import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from app.models import ScanRequest
from app.repo_utils import download_repo, delete_dir
from app.scanner import scan_repo
import aiohttp
import os
import tempfile
import multiprocessing
from typing import Tuple, Optional
import shutil
import random
import string
import subprocess
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import zipfile

# Load environment variables
load_dotenv()
task_queue = asyncio.Queue()

HubType = os.getenv("HubType")

# Thread pool for I/O operations (downloads)
download_executor = ThreadPoolExecutor(max_workers=5)

# Process pool for CPU-intensive operations (model inference)
model_executor = ProcessPoolExecutor(max_workers=multiprocessing.cpu_count())

async def add_to_queue_background(request: ScanRequest, commit: str):
    await task_queue.put((request, commit))
    print(f"📥 Проект {request.ProjectName} поставлен в очередь на сканирование")

async def add_multi_scan_to_queue(multi_scan_items: list, commits: list):
    """Add multi-scan sequence to queue"""
    await task_queue.put(("multi_scan", multi_scan_items, commits))
    print(f"📥 Мультисканирование {len(multi_scan_items)} проектов поставлено в очередь")

async def start_worker():
    """Worker that processes requests concurrently"""
    while True:
        try:
            item = await task_queue.get()
            
            # Check item type
            if isinstance(item, tuple) and len(item) == 3:
                if item[0] == "multi_scan":
                    # Multi-scan processing
                    _, multi_scan_items, commits = item
                    asyncio.create_task(process_multi_scan_sequence(multi_scan_items, commits))
                elif item[0] == "local_scan":
                    # Local scan processing
                    _, request_dict, zip_content = item
                    asyncio.create_task(process_local_scan_async(request_dict, zip_content))
            else:
                # Single scan processing
                request, commit = item
                asyncio.create_task(process_request_async(request, commit))
            
            task_queue.task_done()
        except Exception as e:
            print(f"❌ Worker error: {e}")
            await asyncio.sleep(1)

async def process_local_scan_async(request_dict: dict, zip_content: bytes):
    """Process uploaded zip file locally"""
    temp_dir = tempfile.mkdtemp(dir=os.getenv("TEMP_DIR", "C:\\"))
    
    try:
        project_name = request_dict["ProjectName"]
        callback_url = request_dict["CallbackUrl"]
        commit = request_dict["Ref"]
        
        print(f"🔄 Начинаю локальное сканирование {project_name}")
        
        # Save zip content to file
        zip_path = os.path.join(temp_dir, f"{project_name}.zip")
        with open(zip_path, 'wb') as f:
            f.write(zip_content)
        
        print(f"✅ ZIP файл сохранен: {project_name}")
        
        # Extract zip file
        extracted_path = os.path.join(temp_dir, "extracted")
        os.makedirs(extracted_path, exist_ok=True)
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            download_executor,
            extract_zip_file,
            zip_path,
            extracted_path
        )
        
        print(f"✅ ZIP файл распакован: {project_name}")
        
        # Scan extracted content
        print(f"🔍 Сканирую {project_name}")
        
        results, all_files_count = await loop.run_in_executor(
            model_executor,
            scan_repo_with_model,
            extracted_path,
            project_name,
            request_dict
        )
        
        print(f"✅ Просканировано {project_name}")
        
        # Send results
        payload = {
            "Status": "completed",
            "Message": "Scanned Successfully",
            "ProjectName": project_name,
            "ProjectRepoUrl": request_dict["RepoUrl"],
            "RepoCommit": commit,
            "Results": results,
            "FilesScanned": all_files_count
        }
        
        await send_callback(callback_url, payload)
        print(f"✅ Результаты отправлены для {project_name}")
        
    except Exception as e:
        print(f"❌ Ошибка при локальном сканировании {request_dict.get('ProjectName', 'unknown')}: {e}")
        await send_error_callback(request_dict.get("CallbackUrl", ""), str(e))
    finally:
        # Cleanup
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(download_executor, delete_dir, temp_dir)

def extract_zip_file(zip_path: str, extract_path: str):
    """Extract zip file synchronously"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            zip_file.extractall(extract_path)
        return True
    except Exception as e:
        print(f"❌ Ошибка при распаковке ZIP: {e}")
        raise e

async def process_multi_scan_sequence(multi_scan_items: list, commits: list):
    """Process multi-scan repositories sequentially"""
    print(f"🔄 Начинаю последовательное мультисканирование {len(multi_scan_items)} репозиториев")
    
    for i, (item_dict, commit) in enumerate(zip(multi_scan_items, commits)):
        try:
            # Convert dict back to ScanRequest
            from app.models import ScanRequest
            request = ScanRequest(**item_dict)
            
            print(f"📋 Мультискан [{i+1}/{len(multi_scan_items)}]: {request.ProjectName}")
            
            # Process sequentially (wait for completion)
            await process_request_sequential(request, commit)
            
            print(f"✅ Мультискан [{i+1}/{len(multi_scan_items)}] завершен: {request.ProjectName}")
            
        except Exception as e:
            print(f"❌ Ошибка в мультискане [{i+1}/{len(multi_scan_items)}]: {e}")
            # Continue with next repository even if one fails
            try:
                if 'request' in locals():
                    await send_error_callback(request.CallbackUrl, f"Ошибка мультисканирования: {str(e)}")
            except:
                pass
    
    print(f"🎯 Мультисканирование завершено: {len(multi_scan_items)} репозиториев")

async def process_request_sequential(request: ScanRequest, commit: str):
    """Sequential processing for multi-scan (blocks until complete)"""
    temp_dir = tempfile.mkdtemp(dir=os.getenv("TEMP_DIR", "C:\\"))
    
    try:
        # Step 1: Download repository
        print(f"🔄 Скачиваю {request.ProjectName}")
        loop = asyncio.get_event_loop()
        
        extracted_repo_path, status_message = await loop.run_in_executor(
            download_executor, 
            download_repo_sync, 
            request.RepoUrl, 
            commit, 
            temp_dir
        )
        
        if not extracted_repo_path:
            await send_error_callback(request.CallbackUrl, status_message)
            return
            
        print(f"✅ Скачано {request.ProjectName}")
        
        # Step 2: Scan repository
        print(f"🔍 Сканирую {request.ProjectName}")
        
        request_dict = {
            "ProjectName": request.ProjectName,
            "RepoUrl": request.RepoUrl,
            "RefType": request.RefType,
            "Ref": request.Ref,
            "CallbackUrl": request.CallbackUrl
        }
        
        results, all_files_count = await loop.run_in_executor(
            model_executor,
            scan_repo_with_model,
            extracted_repo_path,
            request.ProjectName,
            request_dict
        )
        
        print(f"✅ Просканировано {request.ProjectName}")
        
        # Step 3: Send results
        payload = {
            "Status": "completed",
            "Message": "Scanned Successfully",
            "ProjectName": request.ProjectName,
            "ProjectRepoUrl": request.RepoUrl,
            "RepoCommit": commit,
            "Results": results,
            "FilesScanned": all_files_count
        }
        
        await send_callback(request.CallbackUrl, payload)
        print(f"✅ Результаты отправлены для {request.ProjectName}")
        
    except Exception as e:
        print(f"❌ Ошибка при обработке {request.ProjectName}: {e}")
        await send_error_callback(request.CallbackUrl, str(e))
    finally:
        # Cleanup
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(download_executor, delete_dir, temp_dir)

def download_repo_sync(repo_url: str, commit: str, temp_dir: str) -> Tuple[str, str]:
    """Synchronous wrapper for download_repo to run in thread pool"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(download_repo(repo_url, commit, temp_dir))
        return result
    finally:
        loop.close()

def scan_repo_with_model(repo_path: str, project_name: str, request_dict: dict) -> Tuple[list, int]:
    """Process scanning and model inference in separate process"""
    import sys
    import os
    import asyncio
    
    # Add the project root to Python path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    try:
        from app.scanner import scan_repo_without_callback
        from app.model_loader import get_model_instance, filter_secrets_in_process
        from app.models import ScanRequest
        
        # Recreate request object from dict
        request = ScanRequest(**request_dict)
        
        # Perform scanning without model (in process)
        results, file_count = asyncio.run(scan_repo_without_callback(request, repo_path, project_name))
        
        # Apply model filtering
        filtered_results = filter_secrets_in_process(results)
        
        return filtered_results, file_count
        
    except Exception as e:
        print(f"❌ Ошибка в процессе сканирования: {e}")
        # Return empty results with error info
        return [{"error": str(e), "path": "process_error", "severity": "High", "Type": "Process Error"}], 0

async def process_request_async(request: ScanRequest, commit: str):
    """Async processing with concurrent download and scanning"""
    temp_dir = tempfile.mkdtemp(dir=os.getenv("TEMP_DIR", "C:\\"))
    
    try:
        # Step 1: Download repository in thread pool (non-blocking)
        print(f"🔄 Начинаю скачивание {request.ProjectName}")
        loop = asyncio.get_event_loop()
        
        extracted_repo_path, status_message = await loop.run_in_executor(
            download_executor, 
            download_repo_sync, 
            request.RepoUrl, 
            commit, 
            temp_dir
        )
        
        if not extracted_repo_path:
            await send_error_callback(request.CallbackUrl, status_message)
            return
            
        print(f"✅ Скачивание завершено {request.ProjectName}")
        
        # Step 2: Scan repository with model in process pool (CPU-intensive)
        print(f"🔍 Начинаю сканирование {request.ProjectName}")
        
        # Convert request to dict for multiprocessing
        request_dict = {
            "ProjectName": request.ProjectName,
            "RepoUrl": request.RepoUrl,
            "RefType": request.RefType,
            "Ref": request.Ref,
            "CallbackUrl": request.CallbackUrl
        }
        
        results, all_files_count = await loop.run_in_executor(
            model_executor,
            scan_repo_with_model,
            extracted_repo_path,
            request.ProjectName,
            request_dict
        )
        
        print(f"✅ Сканирование завершено {request.ProjectName}")
        
        # Step 3: Send results
        payload = {
            "Status": "completed",
            "Message": "Scanned Successfully",
            "ProjectName": request.ProjectName,
            "ProjectRepoUrl": request.RepoUrl,
            "RepoCommit": commit,
            "Results": results,
            "FilesScanned": all_files_count
        }
        
        await send_callback(request.CallbackUrl, payload)
        print(f"✅ Результаты отправлены для {request.ProjectName}")
        
    except Exception as e:
        print(f"❌ Ошибка при обработке {request.ProjectName}: {e}")
        await send_error_callback(request.CallbackUrl, str(e))
    finally:
        # Cleanup in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(download_executor, delete_dir, temp_dir)

async def send_callback(callback_url: str, payload: dict):
    """Send callback with retry logic"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(callback_url, json=payload) as response:
                    if response.status == 200:
                        return
                    print(f"⚠️ Callback failed with status {response.status}, attempt {attempt + 1}")
        except Exception as e:
            print(f"⚠️ Callback error attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

async def send_error_callback(callback_url: str, error_message: str):
    """Send error callback"""
    payload = {
        "Status": "Error",
        "Message": error_message
    }
    await send_callback(callback_url, payload)

# Cleanup function for graceful shutdown
async def cleanup_executors():
    """Cleanup executors on shutdown"""
    try:
        print("🧹 Очистка thread pool...")
        download_executor.shutdown(wait=False)  # Don't wait to avoid hanging
    except Exception as e:
        print(f"⚠️ Ошибка при остановке download_executor: {e}")
    
    try:
        print("🧹 Очистка process pool...")
        model_executor.shutdown(wait=False)  # Don't wait to avoid hanging
    except Exception as e:
        print(f"⚠️ Ошибка при остановке model_executor: {e}")
    
    print("✅ Cleanup завершен")