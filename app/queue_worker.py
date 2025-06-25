import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from app.models import ScanRequest
from app.repo_utils import download_repo, delete_dir
import aiohttp
import os
import tempfile
import multiprocessing
from typing import Tuple
from dotenv import load_dotenv
import zipfile
import time
import gzip
import base64
import logging
import json
import traceback
from logging.handlers import RotatingFileHandler

# Setup logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('secrets_scanner_service.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()  # Также выводить в консоль
    ]
)
logger = logging.getLogger("queue_worker")

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
    logger.info(f"Проект {request.ProjectName} поставлен в очередь на сканирование")

async def add_multi_scan_to_queue(multi_scan_items: list, commits: list):
    """Add multi-scan sequence to queue"""
    await task_queue.put(("multi_scan", multi_scan_items, commits))
    logger.info(f"Мультисканирование {len(multi_scan_items)} проектов поставлено в очередь")

async def start_worker():
    """Worker that processes requests concurrently"""
    while True:
        try:
            # Добавляем timeout для избежания вечного ожидания
            item = await asyncio.wait_for(task_queue.get(), timeout=5.0)
            
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
        except asyncio.TimeoutError:
            # Периодически проверяем, не нужно ли завершиться
            continue
        except asyncio.CancelledError:
            logger.info("Worker получил сигнал отмены")
            break
        except Exception as e:
            logger.error(f"Worker error: {e}")
            await asyncio.sleep(1)

async def process_local_scan_async(request_dict: dict, zip_content: bytes):
    """Process uploaded zip file locally"""
    start_time = time.time()
    temp_dir = tempfile.mkdtemp(dir=os.getenv("TEMP_DIR", "C:\\"))
    
    try:
        project_name = request_dict["ProjectName"]
        callback_url = request_dict["CallbackUrl"]
        commit = request_dict["Ref"]
        
        logger.info(f"Начинаю локальное сканирование {project_name}")
        
        # Save zip content to file
        zip_save_start = time.time()
        zip_path = os.path.join(temp_dir, f"{project_name}.zip")
        with open(zip_path, 'wb') as f:
            f.write(zip_content)
        
        logger.info(f"ZIP файл сохранен: {project_name} (время: {time.time() - zip_save_start:.2f}с)")
        
        # Extract zip file
        extract_start = time.time()
        extracted_path = os.path.join(temp_dir, "extracted")
        os.makedirs(extracted_path, exist_ok=True)
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            download_executor,
            extract_zip_file,
            zip_path,
            extracted_path
        )
        
        logger.info(f"ZIP файл распакован: {project_name} (время: {time.time() - extract_start:.2f}с)")
        
        # Scan extracted content
        scan_start = time.time()
        logger.info(f"Сканирую {project_name}")
        
        results, all_files_count = await loop.run_in_executor(
            model_executor,
            scan_repo_with_model,
            extracted_path,
            project_name,
            request_dict
        )
        
        scan_time = time.time() - scan_start
        logger.info(f"Просканировано {project_name} (время: {scan_time:.2f}с, файлов: {all_files_count})")
        
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
        
        total_time = time.time() - start_time
        logger.info(f"Результаты {project_name} отправлены на CallBack (общее время: {total_time:.2f}с)")
        
    except Exception as e:
        logger.error(f"Ошибка при локальном сканировании {request_dict.get('ProjectName', 'unknown')}: {e}")
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
        logger.error(f"Ошибка при распаковке ZIP: {e}")
        raise e

async def process_multi_scan_sequence(multi_scan_items: list, commits: list):
    """Process multi-scan repositories sequentially"""
    multi_start_time = time.time()
    logger.info(f"Начинаю последовательное мультисканирование {len(multi_scan_items)} репозиториев")
    
    for i, (item_dict, commit) in enumerate(zip(multi_scan_items, commits)):
        try:
            # Convert dict back to ScanRequest
            from app.models import ScanRequest
            request = ScanRequest(**item_dict)
            
            item_start = time.time()
            logger.info(f"Мультискан [{i+1}/{len(multi_scan_items)}]: {request.ProjectName}")
            
            # Process sequentially (wait for completion)
            await process_request_sequential(request, commit)
            
            item_time = time.time() - item_start
            logger.info(f"Мультискан [{i+1}/{len(multi_scan_items)}] завершен: {request.ProjectName} (время: {item_time:.2f}с)")
            
        except Exception as e:
            logger.error(f"Ошибка в мультискане [{i+1}/{len(multi_scan_items)}]: {e}")
            # Continue with next repository even if one fails
            try:
                if 'request' in locals():
                    await send_error_callback(request.CallbackUrl, f"Ошибка мультисканирования: {str(e)}")
            except:
                pass
    
    total_multi_time = time.time() - multi_start_time
    logger.info(f"Мультисканирование завершено: {len(multi_scan_items)} репозиториев (общее время: {total_multi_time:.2f}с)")

async def process_request_sequential(request: ScanRequest, commit: str):
    """Sequential processing for multi-scan (blocks until complete)"""
    temp_dir = tempfile.mkdtemp(dir=os.getenv("TEMP_DIR", "C:\\"))
    
    try:
        # Step 1: Download repository
        download_start = time.time()
        logger.info(f"Скачиваю {request.ProjectName}")
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
            
        download_time = time.time() - download_start
        logger.info(f"Скачано {request.ProjectName} (время: {download_time:.2f}с)")
        
        # Step 2: Scan repository
        scan_start = time.time()
        logger.info(f"Сканирую {request.ProjectName}")
        
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
        
        scan_time = time.time() - scan_start
        logger.info(f"Просканировано {request.ProjectName} (время: {scan_time:.2f}с, файлов: {all_files_count})")
        
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
        logger.info(f"Результаты отправлены для {request.ProjectName}")
        
    except Exception as e:
        logger.error(f"Ошибка при обработке {request.ProjectName}: {e}")
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
        logger.error(f"Ошибка в процессе сканирования: {e}")
        # Return empty results with error info
        return [{"error": str(e), "path": "process_error", "severity": "High", "Type": "Process Error"}], 0

async def process_request_async(request: ScanRequest, commit: str):
    """Async processing with concurrent download and scanning"""
    start_time = time.time()
    temp_dir = tempfile.mkdtemp(dir=os.getenv("TEMP_DIR", "C:\\"))
    
    try:
        # Step 1: Download repository in thread pool (non-blocking)
        download_start = time.time()
        logger.info(f"Начинаю скачивание {request.ProjectName}")
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
            
        download_time = time.time() - download_start
        logger.info(f"Скачивание завершено {request.ProjectName} (время: {download_time:.2f}с)")
        
        # Step 2: Scan repository with model in process pool (CPU-intensive)
        scan_start = time.time()
        logger.info(f"Начинаю сканирование {request.ProjectName}")
        
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
        
        scan_time = time.time() - scan_start
        logger.info(f"Сканирование завершено {request.ProjectName} (время: {scan_time:.2f}с, файлов: {all_files_count})")
        
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
        
        total_time = time.time() - start_time
        logger.info(f"Результаты отправлены для {request.ProjectName} (общее время: {total_time:.2f}с)")
        
    except Exception as e:
        logger.error(f"Ошибка при обработке {request.ProjectName}: {e}")
        await send_error_callback(request.CallbackUrl, str(e))
    finally:
        # Cleanup in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(download_executor, delete_dir, temp_dir)

async def send_callback(callback_url: str, payload: dict):
    """Send callback with compression support"""
    
    project_name = payload.get("ProjectName", "unknown")
    results_count = len(payload.get("Results", []))
    
    # Сериализуем payload
    payload_json = json.dumps(payload, ensure_ascii=False)
    original_size = len(payload_json.encode('utf-8'))
    
    # Сжимаем данные
    compressed_data = gzip.compress(payload_json.encode('utf-8'))
    compressed_size = len(compressed_data)
    
    # Кодируем в base64 для передачи
    compressed_b64 = base64.b64encode(compressed_data).decode('ascii')
    
    # Создаем сжатый payload
    compressed_payload = {
        "compressed": True,
        "data": compressed_b64,
        "original_size": original_size,
        "compressed_size": compressed_size
    }
    
    compressed_json = json.dumps(compressed_payload)
    final_size = len(compressed_json.encode('utf-8'))
    
    compression_ratio = (1 - final_size / original_size) * 100
    
    logger.info(f"📤 Отправляем callback для {project_name}")
    logger.info(f"   URL: {callback_url}")
    logger.info(f"   Оригинал: {original_size / 1024:.2f} KB")
    logger.info(f"   Сжато: {final_size / 1024:.2f} KB")
    logger.info(f"   Экономия: {compression_ratio:.1f}%")
    logger.info(f"   Результатов: {results_count}")
    
    max_retries = 3
    
    for attempt in range(max_retries):
        start_time = time.time()
        logger.info(f"🔄 Попытка {attempt + 1}/{max_retries}")
        
        try:
            timeout = aiohttp.ClientTimeout(
                total=60,
                connect=10,
                sock_read=30
            )
            
            headers = {
                'Content-Type': 'application/json; charset=utf-8',
                'User-Agent': 'SecretsScanner-Service/1.0',
                'X-Compressed': 'gzip-base64'  # Указываем, что данные сжаты
            }
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                logger.info(f"🔗 Устанавливаем соединение с {callback_url}")
                
                async with session.post(
                    callback_url,
                    data=compressed_json,
                    headers=headers
                ) as response:
                    
                    elapsed = time.time() - start_time
                    logger.info(f"📨 Получен ответ за {elapsed:.2f}с")
                    logger.info(f"   Статус: {response.status} {response.reason}")
                    
                    try:
                        response_text = await response.text()
                        response_size = len(response_text)
                        logger.info(f"   Размер ответа: {response_size} bytes")
                        
                        if response_size > 0:
                            preview = response_text[:200].replace('\n', '\\n')
                            logger.info(f"   Начало ответа: {preview}...")
                        
                    except Exception as read_error:
                        logger.error(f"❌ Ошибка чтения тела ответа: {read_error}")
                        response_text = f"ERROR_READING_RESPONSE: {read_error}"
                    
                    if response.status == 200:
                        logger.info(f"✅ Callback успешно отправлен за {elapsed:.2f}с (экономия {compression_ratio:.1f}%)")
                        return
                    else:
                        logger.error(f"❌ HTTP ошибка {response.status}: {response.reason}")
                        
                        if response.status == 413:
                            logger.error("💡 Ошибка 413: Payload слишком большой для сервера")
                        elif response.status == 500:
                            logger.error("💡 Ошибка 500: Внутренняя ошибка сервера при обработке")
                        elif response.status == 502:
                            logger.error("💡 Ошибка 502: Плохой шлюз (проблема с прокси)")
                        elif response.status == 503:
                            logger.error("💡 Ошибка 503: Сервис недоступен")
                        elif response.status == 504:
                            logger.error("💡 Ошибка 504: Таймаут шлюза")
                        else:
                            logger.error(f"💡 Неожиданный HTTP код: {response.status}")
                        
                        logger.error(f"   Полный ответ сервера: {response_text}")
        
        except asyncio.TimeoutError as e:
            elapsed = time.time() - start_time
            logger.error(f"⏰ Таймаут после {elapsed:.2f}с на попытке {attempt + 1}")
            logger.error(f"   💡 Возможно сервер не успевает обработать запрос")
            
        except aiohttp.ClientConnectorError as e:
            elapsed = time.time() - start_time
            logger.error(f"🔌 Ошибка подключения после {elapsed:.2f}с: {e}")
            logger.error(f"   💡 Проверьте доступность {callback_url}")
            
        except aiohttp.ClientOSError as e:
            elapsed = time.time() - start_time
            logger.error(f"💻 Системная ошибка после {elapsed:.2f}с: {e}")
            
        except aiohttp.ClientPayloadError as e:
            elapsed = time.time() - start_time
            logger.error(f"📦 Ошибка передачи данных после {elapsed:.2f}с: {e}")
            
        except aiohttp.ServerDisconnectedError as e:
            elapsed = time.time() - start_time
            logger.error(f"🔌 Сервер разорвал соединение после {elapsed:.2f}с: {e}")
            
        except json.JSONEncodeError as e:
            elapsed = time.time() - start_time
            logger.error(f"📝 Ошибка кодирования JSON: {e}")
            break
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"❓ Неожиданная ошибка после {elapsed:.2f}с: {type(e).__name__}: {e}")
            error_traceback = traceback.format_exc()
            for line in error_traceback.split('\n'):
                if line.strip():
                    logger.error(f"      {line}")
        
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logger.info(f"⏳ Ждем {wait_time}с перед следующей попыткой...")
            await asyncio.sleep(wait_time)
    
    logger.error(f"💥 КРИТИЧНО: Не удалось отправить callback после {max_retries} попыток")
    logger.error(f"   Проект: {project_name}")
    logger.error(f"   URL: {callback_url}")
    logger.error(f"   Размер (сжатый): {final_size / 1024:.2f} KB")

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
        logger.info("Очистка thread pool...")
        download_executor.shutdown(wait=True, cancel_futures=True)
    except Exception as e:
        logger.error(f"Ошибка при остановке download_executor: {e}")
    
    try:
        logger.info("Очистка process pool...")
        # Для Windows - принудительное завершение процессов
        if hasattr(model_executor, '_processes'):
            for p in model_executor._processes.values():
                if p.is_alive():
                    p.terminate()
        model_executor.shutdown(wait=False)
    except Exception as e:
        logger.error(f"Ошибка при остановке model_executor: {e}")
    
    logger.info("Cleanup завершен")