import asyncio
from app.models import ScanRequest
from app.repo_utils import download_repo, delete_dir
from app.scanner import scan_repo
import aiohttp
import os
import tempfile
import random
import string
from dotenv import load_dotenv

load_dotenv()
task_queue = asyncio.Queue()
HubType = os.getenv("HubType")

# Семафор для ограничения одновременных операций скачивания
download_semaphore = asyncio.Semaphore(3)  # Максимум 3 одновременных скачивания

# Семафор для ограничения одновременного использования модели
model_semaphore = asyncio.Semaphore(2)  # Максимум 2 одновременных вызова модели

async def add_to_queue_background(request: ScanRequest, commit: str):
    await task_queue.put((request, commit))
    print(f"📥 Проект {request.ProjectName} поставлен в очередь на сканирование")

async def start_worker():
    """Воркер теперь обрабатывает задачи конкурентно"""
    while True:
        request, commit = await task_queue.get()
        # Запускаем обработку асинхронно без ожидания завершения
        asyncio.create_task(process_request_async(request, commit))
        task_queue.task_done()

async def process_request_async(request: ScanRequest, commit: str):
    """Асинхронная обработка запроса с семафорами для контроля конкурентности"""
    temp_dir = tempfile.mkdtemp(dir="C:\\")
    
    try:
        print(f"🚀 Начинаю обработку {request.ProjectName}")
        
        # Ограничиваем одновременные скачивания
        async with download_semaphore:
            print(f"📥 Скачиваю {request.ProjectName}")
            extracted_repo_path, status_message = await download_repo(request.RepoUrl, commit, temp_dir)
        
        if extracted_repo_path:
            print(f"🔍 Сканирую {request.ProjectName}")
            # Сканирование файлов (быстрая операция)
            results, all_files_count = await scan_repo_concurrent(request, extracted_repo_path, request.ProjectName)

            payload = {
                "Status": "completed",
                "Message": "Scanned Successfully",
                "ProjectName": request.ProjectName,
                "ProjectRepoUrl": request.RepoUrl,
                "RepoCommit": commit,
                "Results": results,
                "FilesScanned": all_files_count
            }

            async with aiohttp.ClientSession() as session:
                await session.post(request.CallbackUrl, json=payload)
            print(f"✅ Результаты сканирования {request.ProjectName} отправлены на CallbackUrl")
        else:
            payload = {
                "Status": "Error",
                "Message": status_message,
                "ProjectName": request.ProjectName
            }
            async with aiohttp.ClientSession() as session:
                await session.post(request.CallbackUrl, json=payload)
                
    except Exception as e:
        print(f"❌ Ошибка при обработке {request.ProjectName}: {e}")
        async with aiohttp.ClientSession() as session:
            payload = {
                "Status": "Error",
                "Message": f"{str(e)}",
                "ProjectName": request.ProjectName
            }
            await session.post(request.CallbackUrl, json=payload)
    finally:
        delete_dir(temp_dir)

async def scan_repo_concurrent(request, repo_path, projectName):
    """Обертка для сканирования с ограничением использования модели"""
    from app.model_loader import get_model_instance
    from app.scanner import scan_directory, load_rules
    
    # Загружаем правила
    rules = load_rules("Settings/rules.yml")
    print(f"🔍 Начинаю сканирование файлов {projectName}")
    
    # Сканирование файлов (без модели)
    results, all_files_count = await scan_directory(request, repo_path, rules)
    
    print(f"🤖 Начинаю валидацию модели для {projectName}")
    
    # Ограничиваем одновременное использование модели
    async with model_semaphore:
        model = get_model_instance()
        sevveritied_secrets = await asyncio.get_event_loop().run_in_executor(
            None, model.filter_secrets, results
        )
    
    print(f"✅ Валидация {projectName} завершена")
    return sevveritied_secrets, all_files_count