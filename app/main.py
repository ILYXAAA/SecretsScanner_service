from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Header, Depends, Query
from fastapi.responses import JSONResponse
from app.models import ScanRequest, PATTokenRequest, RulesContent, MultiScanRequest, MultiScanResponseItem
from app.redis_client import get_redis_client
from app.repo_utils import check_ref_and_resolve_git, check_ref_and_resolve_azure
import asyncio
import os
import yaml
import aiofiles
from app.secure_save import encrypt_and_save, decrypt_from_file
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from contextlib import asynccontextmanager
import secrets
import psutil
import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import base64
from app.admin_routes import admin_router

load_dotenv()
os.system("")  # Нужно для отображение цвета в консоли Windows

logger = logging.getLogger("main")
HubType = os.getenv("HubType")
API_KEY = os.getenv("API_KEY")
VALIDATION_THREADS_NUMBER = int(os.getenv("VALIDATION_THREADS_NUMBER", "5"))

# Thread pool for validation operations
validation_pool = ThreadPoolExecutor(max_workers=VALIDATION_THREADS_NUMBER)

# Background cleanup thread control
cleanup_thread_running = False
cleanup_thread = None

async def validate_api_key(x_api_key: str = Header(None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

def background_maintenance():
    """Background thread for maintenance tasks with improved error handling"""
    global cleanup_thread_running
    
    redis_client = get_redis_client()
    
    # Configuration from environment
    cleanup_interval = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "300"))  # 5 minutes
    timeout_check_interval = int(os.getenv("TIMEOUT_CHECK_INTERVAL", "60"))  # 1 minute
    worker_check_interval = int(os.getenv("WORKER_CHECK_INTERVAL", "120"))  # 2 minutes
    
    last_cleanup = 0
    last_timeout_check = 0
    last_worker_check = 0
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    logger.info(f"'Background maintenance' запущен (cleanup: {cleanup_interval}s, timeout: {timeout_check_interval}s, worker_check: {worker_check_interval}s)")
    
    while cleanup_thread_running:
        try:
            current_time = time.time()
            
            # Check for timed out tasks
            if current_time - last_timeout_check >= timeout_check_interval:
                try:
                    # Get processing tasks and check for timeouts
                    processing_tasks = redis_client.get_tasks(["processing", "downloading", "unpacking", "scanning", "ml_validation"])
                    timeout_count = 0

                    for task in processing_tasks:
                        # ВАЖНО: проверяем что задача действительно в процессе
                        current_status = task.get("status")
                        if current_status not in ["processing", "downloading", "unpacking", "scanning", "ml_validation"]:
                            continue  # Пропускаем уже завершенные задачи
                            
                        timeout_at = task.get("timeout_at", 0)
                        if current_time > timeout_at:
                            task_id = task["task_id"]
                            redis_client.update_task_status(
                                task_id,
                                "failed",
                                error="Task timeout exceeded",
                                worker_id=None
                            )
                            timeout_count += 1
                    
                    if timeout_count > 0:
                        logger.info(f"Обработано '{timeout_count}' задач по таймауту")
                    
                    last_timeout_check = current_time
                    
                except Exception as e:
                    logger.error(f"Ошибка проверки таймаутов: {e}")
            
            # Check worker health
            if current_time - last_worker_check >= worker_check_interval:
                try:
                    from app.admin_routes import cleanup_dead_processes
                    cleaned_processes = cleanup_dead_processes()
                    
                    # Clean up dead workers from Redis
                    cleaned_workers = redis_client.cleanup_dead_workers()
                    
                    if cleaned_processes > 0 or cleaned_workers > 0:
                        logger.info(f"Worker cleanup: '{cleaned_processes}' процессов, '{cleaned_workers}' Redis записей")
                    
                    last_worker_check = current_time
                    
                except Exception as e:
                    logger.error(f"Ошибка проверки воркеров: {e}")
            
            # Periodic cleanup
            if current_time - last_cleanup >= cleanup_interval:
                try:
                    # Clean up old tasks
                    cleaned_tasks = redis_client.cleanup_expired_tasks()
                    
                    # Verify queue consistency
                    redis_client._verify_queue_consistency()
                    
                    if cleaned_tasks > 0:
                        logger.info(f"Periodic cleanup: '{cleaned_tasks}' старых задач")
                    
                    last_cleanup = current_time
                    
                except Exception as e:
                    logger.error(f"Ошибка periodic cleanup: {e}")
            
            # Reset error counter on successful iteration
            consecutive_errors = 0
            
            # Sleep for 10 seconds between checks
            time.sleep(10)
            
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Ошибка в background maintenance (#{consecutive_errors}): {e}")
            
            # If too many consecutive errors, increase sleep time
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Слишком много ошибок в background maintenance, увеличиваю интервал")
                time.sleep(60)  # Sleep for 1 minute
                consecutive_errors = 0  # Reset counter
            else:
                time.sleep(30)  # Longer sleep on error

# === Application Lifecycle ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    global cleanup_thread_running, cleanup_thread
    
    # Startup
    logger.info("Запуск сервиса с Redis-based архитектурой...")
    
    # Set service start time for uptime calculation
    from app.admin_routes import set_service_start_time
    set_service_start_time()
    
    # Initialize Redis client with retry logic
    redis_client = None
    max_redis_retries = 5
    for attempt in range(max_redis_retries):
        try:
            redis_client = get_redis_client()
            # Test connection
            redis_client.redis_client.ping()
            # Clean up old data from previous runs
            redis_client.cleanup_startup()
            logger.info("Redis клиент инициализирован и очищен")
            break
        except Exception as e:
            logger.error(f"Ошибка подключения к Redis (попытка {attempt + 1}/{max_redis_retries}): {e}")
            if attempt < max_redis_retries - 1:
                await asyncio.sleep(5)  # Wait before retry
            else:
                logger.critical("Не удалось подключиться к 'Redis' после всех попыток")
                raise
    
    # Import admin functions
    from app.admin_routes import start_worker_process, worker_processes, set_worker_processes
    
    # Start initial worker processes with error handling
    startup_workers = int(os.getenv("STARTUP_WORKERS", "5"))
    successful_workers = 0
    
    for i in range(startup_workers):
        worker_id = f"worker-{i:02d}"
        try:
            if start_worker_process(worker_id):
                successful_workers += 1
            else:
                logger.error(f"Не удалось запустить worker '{worker_id}'")
        except Exception as e:
            logger.critical(f"Ошибка запуска worker '{worker_id}': {e}")
    
    if successful_workers == 0:
        logger.critical("Не удалось запустить ни одного воркера!")
        raise Exception("Failed to start any workers")
    elif successful_workers < startup_workers:
        logger.warning(f"Запущено '{successful_workers}' из '{startup_workers}' воркеров")
    else:
        logger.info(f"Успешно запущено '{successful_workers}' воркеров")
    
    # Set worker processes reference for admin routes
    set_worker_processes(worker_processes)
    
    # Start background maintenance thread
    cleanup_thread_running = True
    cleanup_thread = threading.Thread(target=background_maintenance, daemon=True, name="MaintenanceThread")
    cleanup_thread.start()
    
    logger.info(f"Сервис готов к обработке запросов. Запущено '{len(worker_processes)}' workers")
    
    yield  # Приложение работает
    
    # Shutdown
    logger.warning("Начинаю остановку сервиса...")
    
    # Stop background thread
    cleanup_thread_running = False
    if cleanup_thread and cleanup_thread.is_alive():
        cleanup_thread.join(timeout=10)
        if cleanup_thread.is_alive():
            logger.warning("Background maintenance thread не завершился gracefully")
    
    try:
        # Send shutdown commands to all workers
        if redis_client:
            shutdown_timeout = 15  # 15 seconds for graceful shutdown
            logger.info("Отправляю команды shutdown воркерам...")
            
            for worker_id in list(worker_processes.keys()):
                try:
                    redis_client.send_worker_command(worker_id, "shutdown")
                except Exception as e:
                    logger.error(f"Ошибка отправки shutdown команды '{worker_id}': {e}")
            
            # Wait for graceful shutdown
            logger.info(f"Ожидаю graceful shutdown воркеров ({shutdown_timeout}с)...")
            start_wait = time.time()
            
            while time.time() - start_wait < shutdown_timeout:
                alive_workers = [wid for wid, proc in worker_processes.items() if proc.is_alive()]
                if not alive_workers:
                    logger.info("Все воркеры завершились gracefully")
                    break
                await asyncio.sleep(1)
            
            # Force terminate remaining processes
            remaining_workers = [wid for wid, proc in worker_processes.items() if proc.is_alive()]
            if remaining_workers:
                logger.warning(f"Принудительно завершаю '{len(remaining_workers)}' воркеров")
                for worker_id in remaining_workers:
                    process = worker_processes[worker_id]
                    try:
                        logger.info(f"Принудительно завершаю worker '{worker_id}'")
                        process.terminate()
                        process.join(timeout=3)
                        if process.is_alive():
                            process.kill()
                            process.join(timeout=1)
                    except Exception as e:
                        logger.error(f"Ошибка принудительного завершения '{worker_id}': {e}")
        
        # Cleanup validation pool
        try:
            validation_pool.shutdown(wait=True)
        except Exception as e:
            logger.error(f"Ошибка завершения validation pool: {e}")
        
    except Exception as e:
        logger.error(f"Ошибка при shutdown: {e}")
    finally:
        logger.info("Сервис остановлен")

app = FastAPI(lifespan=lifespan)
app.include_router(admin_router, prefix="/admin", tags=["admin"])

# Configuration
TOKEN_FILE = "Settings/pat_token.dat"
RULES_PATH = "Settings/rules.yml"
EXCLUDED_EXTENSIONS_PATH = "Settings/excluded_extensions.yml"
EXCLUDED_FILES_PATH = "Settings/excluded_files.yml"
FP_FILE_PATH = "Settings/false-positive.yml"

# === Health Check ===
@app.get("/health", dependencies=[Depends(validate_api_key)])
async def health():
    try:
        from app.admin_routes import worker_processes
        redis_client = get_redis_client()
        queue_stats = redis_client.get_queue_stats()
        
        # Test Redis connectivity
        redis_client.redis_client.ping()
        
        active_workers = len([p for p in worker_processes.values() if p.is_alive()])
        total_workers = len(worker_processes)
        
        health_status = "healthy"
        if active_workers == 0:
            health_status = "critical"
        elif active_workers < total_workers * 0.5:
            health_status = "degraded"
        
        return {
            "status": health_status,
            "queue_size": queue_stats["pending"],
            "max_workers": total_workers,
            "active_workers": active_workers,
            "queue_stats": queue_stats,
            "supports_multi_scan": True,
            "architecture": "redis-workers-v2"
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {e}")

# === Validation Helper ===
async def validate_ref_async(repo_url: str, ref_type: str, ref: str):
    """Async wrapper for ref validation with timeout"""
    loop = asyncio.get_event_loop()
    
    def validate_ref_sync():
        if HubType.lower() == "github":
            return asyncio.run(check_ref_and_resolve_git(repo_url, ref_type, ref))
        else:
            return asyncio.run(check_ref_and_resolve_azure(repo_url, ref_type, ref))
    
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(validation_pool, validate_ref_sync),
            timeout=30  # 30 seconds timeout for validation
        )
    except asyncio.TimeoutError:
        raise ValueError(f"Validation timeout for {ref_type} '{ref}' in repository {repo_url}")

# === Multi-Scanning Endpoint ===
@app.post("/multi_scan", dependencies=[Depends(validate_api_key)])
async def multi_scan(request: MultiScanRequest):
    """Process multiple repositories by creating individual tasks with priority 2"""
    
    try:
        redis_client = get_redis_client()
        queue_stats = redis_client.get_queue_stats()
        
        # Check queue capacity
        max_workers = int(os.getenv("MAX_WORKERS", "10"))
        queue_limit = max_workers * 5  # More permissive for multi-scan
        
        if queue_stats["pending"] >= queue_limit:
            return JSONResponse(status_code=429, content={
                "status": "queue_full",
                "message": f"Очередь переполнена ({queue_stats['pending']} задач). Попробуйте позже.",
                "data": []
            })

        response_data = []
        all_resolved = True
        error_message = ""
        tasks_created = 0

        # Validate all repositories first with improved error handling
        for i, repo in enumerate(request.repositories):
            try:
                logger.info(f"Валидирую репозиторий {i+1}/{len(request.repositories)}: {repo.ProjectName}")
                exists, commit, message = await validate_ref_async(repo.RepoUrl, repo.RefType, repo.Ref)
                
                if exists:
                    response_data.append(MultiScanResponseItem(
                        ProjectName=repo.ProjectName,
                        RefType=repo.RefType,
                        Ref=repo.Ref,
                        commit=commit
                    ))
                    logger.info(f"Resolved '{repo.ProjectName}': '{commit[:8]}'")
                else:
                    all_resolved = False
                    response_data.append(MultiScanResponseItem(
                        ProjectName=repo.ProjectName,
                        RefType=repo.RefType,
                        Ref=repo.Ref,
                        commit="not_found"
                    ))
                    logger.error(f"Failed to resolve '{repo.ProjectName}': '{message}'")
                    if not error_message:
                        error_message = message or f"Не удалось найти '{repo.RefType}' -> '{repo.Ref}'"
                        
            except asyncio.TimeoutError:
                all_resolved = False
                response_data.append(MultiScanResponseItem(
                    ProjectName=repo.ProjectName,
                    RefType=repo.RefType,
                    Ref=repo.Ref,
                    commit="timeout"
                ))
                logger.error(f"Timeout resolving '{repo.ProjectName}'")
                if not error_message:
                    error_message = "Validation timeout"
                    
            except Exception as e:
                all_resolved = False
                response_data.append(MultiScanResponseItem(
                    ProjectName=repo.ProjectName,
                    RefType=repo.RefType,
                    Ref=repo.Ref,
                    commit="error"
                ))
                logger.error(f"Error resolving '{repo.ProjectName}': {e}")
                if not error_message:
                    error_message = str(e)

        # Create individual tasks if all resolved
        if all_resolved:
            logger.info(f"Создаю '{len(request.repositories)}' отдельных задач из multi_scan с приоритетом '2'")
            
            for repo, response_item in zip(request.repositories, response_data):
                # Create individual scan task
                single_task_data = {
                    "type": "scan",
                    "request": repo.dict(),
                    "commit": response_item.commit
                }
                
                # Add to Redis queue with priority 2 (lower priority)
                if redis_client.push_task(single_task_data, priority=2):
                    tasks_created += 1
                else:
                    logger.error(f"Ошибка создания задачи для '{repo.ProjectName}'")
            
            if tasks_created == len(request.repositories):
                return JSONResponse(
                    content={
                        "status": "accepted",
                        "message": f"Мультисканирование разбито на {tasks_created} отдельных задач с приоритетом 2",
                        "data": [item.dict() for item in response_data],
                        "tasks_created": tasks_created,
                        "RepoUrl": request.repositories[0].RepoUrl if request.repositories else ""
                    },
                    status_code=200
                )
            else:
                return JSONResponse(
                    content={
                        "status": "partial_success",
                        "message": f"Создано {tasks_created} из {len(request.repositories)} задач",
                        "data": [item.dict() for item in response_data],
                        "tasks_created": tasks_created
                    },
                    status_code=207
                )
        else:
            return JSONResponse(
                content={
                    "status": "validation_failed",
                    "message": f"Не удалось отрезолвить коммиты: {error_message}",
                    "data": [item.dict() for item in response_data]
                },
                status_code=400
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in multi_scan: {e}")
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")

# === Scanning Endpoint ===
@app.post("/scan", dependencies=[Depends(validate_api_key)])
async def scan(request: ScanRequest):
    try:
        redis_client = get_redis_client()
        queue_stats = redis_client.get_queue_stats()
        
        # Check queue capacity
        max_workers = int(os.getenv("MAX_WORKERS", "10"))
        queue_limit = max_workers * 3  # Allow some queueing
        
        if queue_stats["pending"] >= queue_limit:
            return JSONResponse(status_code=429, content={
                "status": "queue_full",
                "RefType": request.RefType,
                "Ref": request.Ref,
                "message": f"Очередь переполнена ({queue_stats['pending']} задач). Попробуйте позже."
            })

        # Validate reference exists and resolve to commit
        try:
            exists, commit, message = await validate_ref_async(request.RepoUrl, request.RefType, request.Ref)
        except asyncio.TimeoutError:
            return JSONResponse(status_code=408, content={
                "status": "validation_timeout",
                "RefType": request.RefType,
                "Ref": request.Ref,
                "message": "Таймаут валидации репозитория"
            })
        
        if not exists:
            if message:
                return JSONResponse(status_code=400, content={
                    "status": "validation_failed",
                    "RefType": request.RefType,
                    "Ref": request.Ref,
                    "message": message
                })
            else:
                raise ValueError(f"{request.RefType} '{request.Ref}' не найден в репозитории {request.RepoUrl}")
        
        logger.info(f"Commit resolved '{commit[0:8]}'.. для '{request.ProjectName}'")

        # Add to Redis queue with priority 1 (normal priority)
        task_data = {
            "type": "scan",
            "request": request.dict(),
            "commit": commit
        }
        
        if redis_client.push_task(task_data, priority=1):
            response = JSONResponse(
                content={
                    "status": "accepted",
                    "RefType": request.RefType,
                    "Ref": request.Ref,
                    "commit": commit,
                    "queue_position": queue_stats["pending"] + 1,
                    "message": "Сканирование добавлено в очередь"
                },
                status_code=200
            )
            return response
        else:
            raise HTTPException(status_code=500, detail="Ошибка добавления задачи в очередь")
    
    except ValueError as e:
        logger.error(f"Запрос не принят - validation_failed: {e}")
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": str(e)
        })
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}")
        return JSONResponse(status_code=500, content={
            "status": "error",
            "RefType": request.RefType,
            "Ref": request.Ref,
            "message": "Внутренняя ошибка сервера"
        })

@app.post("/local_scan", dependencies=[Depends(validate_api_key)])
async def local_scan(
    ProjectName: str = Form(...),
    RepoUrl: str = Form(...),
    CallbackUrl: str = Form(...),
    RefType: str = Form(...), 
    Ref: str = Form(...), 
    zip_file: UploadFile = File(...)
):
    """Process uploaded zip file locally (no retry support)"""
    
    try:
        logger.info(f"['{ProjectName}'] Получен запрос на локальное сканирование проекта")
        
        redis_client = get_redis_client()
        queue_stats = redis_client.get_queue_stats()
        
        # Check queue capacity
        max_workers = int(os.getenv("MAX_WORKERS", "10"))
        queue_limit = max_workers * 3
        
        if queue_stats["pending"] >= queue_limit:
            return JSONResponse(status_code=429, content={
                "status": "queue_full",
                "message": f"Очередь переполнена ({queue_stats['pending']} задач). Попробуйте позже."
            })

        # Validate file type and size
        if not zip_file.filename.endswith('.zip'):
            logger.error(f"Неверный тип файла: '{zip_file.filename}'")
            return JSONResponse(status_code=400, content={
                "status": "validation_failed",
                "message": "Файл должен быть в формате ZIP"
            })

        # Check file size (limit to 2GB)
        max_file_size = 2 * 1024 * 1024 * 1024  # 2 GB
        zip_file.file.seek(0, 2)  # Seek to end
        file_size = zip_file.file.tell()
        zip_file.file.seek(0)  # Reset position
        
        if file_size > max_file_size:
            return JSONResponse(status_code=400, content={
                "status": "validation_failed",
                "message": f"Файл слишком большой ({file_size // (1024*1024)}MB). Максимум: {max_file_size // (1024*1024)}MB"
            })

        # Create temp directory for uploaded files
        import tempfile
        temp_dir = os.getenv("TEMP_DIR", "/tmp")
        upload_dir = os.path.join(temp_dir, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename for the ZIP
        task_id = f"task-{int(time.time() * 1000)}-{hash(ProjectName) % 10000:04d}"
        zip_filename = f"{task_id}.zip"
        zip_path = os.path.join(upload_dir, zip_filename)
        
        # Save ZIP file to temp location
        logger.info(f"['{ProjectName}'] Сохраняю ZIP файл ('{file_size // 1024}KB') -> '{zip_path}'")
        try:
            with open(zip_path, "wb") as temp_zip:
                zip_file.file.seek(0)  # Reset to beginning
                while True:
                    chunk = zip_file.file.read(8192)  # Read in chunks
                    if not chunk:
                        break
                    temp_zip.write(chunk)
            
            logger.info(f"['{ProjectName}'] ZIP файл сохранен: '{zip_path}'")
            
        except Exception as e:
            logger.error(f"['{ProjectName}'] Ошибка сохранения ZIP файла: {e}")
            # Clean up partial file
            try:
                if os.path.exists(zip_path):
                    os.remove(zip_path)
            except:
                pass
            return JSONResponse(status_code=500, content={
                "status": "error",
                "message": f"Ошибка сохранения файла: {e}"
            })
        
        # Create request object
        request_dict = {
            "ProjectName": ProjectName,
            "RepoUrl": RepoUrl,
            "RefType": RefType,
            "Ref": Ref,
            "CallbackUrl": CallbackUrl
        }

        # Prepare task for Redis with file path instead of content
        task_data = {
            "type": "local_scan",
            "request": request_dict,
            "zip_file_path": zip_path,  # Store path instead of content
            "file_size": file_size
        }
        
        # Add to Redis queue with priority 1 (same as regular scan)
        if redis_client.push_task(task_data, priority=1):
            logger.info(f"['{ProjectName}'] Локальное сканирование поставлено в очередь (файл: '{zip_path}')")
            
            return JSONResponse(
                content={
                    "status": "accepted",
                    "ProjectName": ProjectName,
                    "queue_position": queue_stats["pending"] + 1,
                    "file_size_kb": file_size // 1024,
                    "message": "Локальное сканирование добавлено в очередь"
                },
                status_code=200
            )
        else:
            # Clean up file if task creation failed
            try:
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                    logger.info(f"['{ProjectName}'] Удален ZIP файл после ошибки создания задачи")
            except Exception as cleanup_error:
                logger.error(f"['{ProjectName}'] Ошибка удаления ZIP файла: {cleanup_error}")
            
            raise HTTPException(status_code=500, detail="Ошибка добавления задачи в очередь")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"['{ProjectName}'] Ошибка при добавлении локального сканирования: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={
            "status": "error",
            "message": f"Внутренняя ошибка сервера: {str(e)}"
        })





@app.get("/task_status", dependencies=[Depends(validate_api_key)])
async def get_task_status_by_callback(callback_url: str = Query(..., description="Callback URL задачи")):
    """Получить статус и прогресс задачи по callback URL"""
    try:
        redis_client = get_redis_client()
        
        # Получаем все задачи и ищем по callback_url
        all_tasks = redis_client.get_tasks(status_filter=None, limit=0)  # Получаем все задачи
        
        matching_task = None
        for task in all_tasks:
            if task.get("callback_url") == callback_url:
                matching_task = task
                break
        
        if not matching_task:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "not_found",
                    "message": "Задача с указанным callback URL не найдена"
                }
            )
        
        # Получаем основную информацию о задаче
        task_status = matching_task.get("status", "unknown")
        progress = matching_task.get("progress", 0)
        progress_detail = matching_task.get("progress_detail", "")
        project_name = matching_task.get("project_name", "")
        
        # Человекочитаемые описания статусов
        status_descriptions = {
            "pending": "Ожидает обработки",
            "downloading": "Загрузка репозитория",
            "unpacking": "Распаковка архива", 
            "scanning": "Сканирование файлов",
            "ml_validation": "ML проверка результатов",
            "completed": "Завершено",
            "failed": "Ошибка"
        }
        
        status_description = status_descriptions.get(task_status, task_status)
        
        # Формируем ответ
        response_data = {
            "status": "success",
            "task_id": matching_task.get("task_id"),
            "project_name": project_name,
            "current_status": task_status,
            "status_description": status_description,
            "progress": progress,
            "progress_detail": progress_detail,
            "created_at": matching_task.get("created_at"),
            "started_at": matching_task.get("started_at"),
            "completed_at": matching_task.get("completed_at")
        }
        
        # Добавляем дополнительную информацию в зависимости от статуса
        if task_status == "completed":
            response_data["results_count"] = matching_task.get("results_count", 0)
            if matching_task.get("started_at") and matching_task.get("completed_at"):
                execution_time = matching_task["completed_at"] - matching_task["started_at"]
                response_data["execution_time_seconds"] = round(execution_time, 2)
        
        elif task_status == "failed":
            response_data["error"] = matching_task.get("error", "Неизвестная ошибка")
        
        elif task_status in ["unpacking", "scanning", "ml_validation"]:
            # Для активных задач с прогрессом
            if progress > 0:
                response_data["progress_formatted"] = f"{status_description} ({progress}%)"
            else:
                response_data["progress_formatted"] = status_description
        
        else:
            # Для других статусов (pending, downloading)
            response_data["progress_formatted"] = status_description
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        logger.error(f"Ошибка получения статуса задачи по callback URL '{callback_url}': {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Внутренняя ошибка сервера: {str(e)}"
            }
        )



# === PAT Token Endpoints ===
@app.post("/set-pat", dependencies=[Depends(validate_api_key)])
async def set_pat_token(payload: PATTokenRequest):
    if not payload.token:
        raise HTTPException(status_code=400, detail="Token is required")

    try:
        encrypt_and_save(text=payload.token, filename=TOKEN_FILE, key_name="PAT_KEY")
    except Exception as error:
        return {"status": "failed", "message": f"Error: {str(error)}"}
    
    return {"status": "success", "message": "PAT token saved"}

@app.get("/get-pat", dependencies=[Depends(validate_api_key)])
async def get_pat_token():
    try:
        if not os.path.exists(TOKEN_FILE):
            return {"status": "not_found", "message": "Token not set"}

        token = decrypt_from_file(TOKEN_FILE, key_name="PAT_KEY")

        if len(token) < 4:
            masked = "*" * len(token)
        else:
            masked = token[:4] + "*" * (len(token) - 4)
    except Exception as error:
        return {"status": "failed", "message": f"Error: {str(error)}"}
    return {"status": "success", "token": masked}

# Validator для yml, чтобы не сломать структуру файлов
def validate_yaml_structure(content: str, file_type: str) -> tuple[bool, str]:
    """Валидация YAML структуры для разных типов файлов"""
    
    try:
        data = yaml.safe_load(content)
        if data is None:
            return False, "YAML файл пустой или содержит только комментарии"
        
        # Проверка структуры в зависимости от типа файла
        if file_type == "rules":
            if not isinstance(data, list):
                return False, "Файл rules.yml должен содержать список правил"
            for i, rule in enumerate(data):
                if not isinstance(rule, dict):
                    return False, f"Правило #{i+1} должно быть объектом"
                required_fields = ['id', 'message', 'pattern', 'severity']
                for field in required_fields:
                    if field not in rule:
                        return False, f"Правило #{i+1} должно содержать поле '{field}'"
                    if not isinstance(rule[field], str):
                        return False, f"Поле '{field}' в правиле #{i+1} должно быть строкой"
                        
        elif file_type == "excluded_files":
            if not isinstance(data, dict) or 'excluded_files' not in data:
                return False, "Файл должен содержать ключ 'excluded_files'"
            excluded_files = data['excluded_files']
            if not isinstance(excluded_files, list):
                return False, f"Значение 'excluded_files' должно быть списком, получен {type(excluded_files).__name__}"
                
        elif file_type == "excluded_extensions":
            if not isinstance(data, dict) or 'excluded_extensions' not in data:
                return False, "Файл должен содержать ключ 'excluded_extensions'"
            excluded_extensions = data['excluded_extensions']
            if not isinstance(excluded_extensions, list):
                return False, f"Значение 'excluded_extensions' должно быть списком, получен {type(excluded_extensions).__name__}"
                
        elif file_type == "false_positive":
            if not isinstance(data, dict) or 'false_positive' not in data:
                return False, "Файл должен содержать ключ 'false_positive'"
            false_positive = data['false_positive']
            if not isinstance(false_positive, list):
                return False, f"Значение 'false_positive' должно быть списком, получен {type(false_positive).__name__}"
                
        return True, "Структура YAML корректна"
        
    except yaml.YAMLError as e:
        # Упрощаем сообщение об ошибке YAML
        error_msg = str(e)
        if "expected <block end>" in error_msg:
            return False, "Ошибка структуры YAML: неправильное форматирование списка или объекта"
        elif "found unexpected" in error_msg:
            return False, "Ошибка синтаксиса YAML: неожиданный символ"
        else:
            return False, f"Ошибка синтаксиса YAML: {error_msg}"
    except Exception as e:
        return False, f"Ошибка валидации: {str(e)}"

###########################
# Rules.yml ###############
###########################
@app.get("/rules-info", dependencies=[Depends(validate_api_key)])
async def rules_info():
    if os.path.exists(RULES_PATH):
        stat = os.stat(RULES_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(RULES_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(RULES_PATH)
    }

@app.get("/get-rules", dependencies=[Depends(validate_api_key)])
async def get_rules():
    try:
        if not os.path.exists(RULES_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(RULES_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "rules": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-rules", dependencies=[Depends(validate_api_key)])
async def update_rules(data: RulesContent):
    try:
        info = await update_rules_file(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed", 
            "message": str(e),
            "filename": RULES_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": RULES_PATH,
            "size": 0
        })
    
async def update_rules_file(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "rules")
    if not is_valid:
        raise ValueError(f"Некорректная структура rules.yml: {error_msg}")
    
    # Заменяем \r\n и \r на \n (унифицированный формат)
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(RULES_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(RULES_PATH)
    return {
        "message": f"Файл {RULES_PATH} успешно обновлен",
        "filename": RULES_PATH,
        "size": size
    }

###########################
# excluded_files.yml ######
###########################
@app.get("/excluded-files-info", dependencies=[Depends(validate_api_key)])
async def excluded_files_info():
    if os.path.exists(EXCLUDED_FILES_PATH):
        stat = os.stat(EXCLUDED_FILES_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(EXCLUDED_FILES_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(EXCLUDED_FILES_PATH)
    }

@app.get("/get-excluded-files", dependencies=[Depends(validate_api_key)])
async def get_excluded_files():
    try:
        if not os.path.exists(EXCLUDED_FILES_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(EXCLUDED_FILES_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "excluded_files": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-excluded-files", dependencies=[Depends(validate_api_key)])
async def update_excluded_files(data: RulesContent):
    try:
        info = await do_update_excluded_files(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "message": str(e),
            "filename": EXCLUDED_FILES_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": EXCLUDED_FILES_PATH,
            "size": 0
        })
    
async def do_update_excluded_files(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "excluded_files")
    if not is_valid:
        raise ValueError(f"Некорректная структура excluded_files.yml: {error_msg}")
    
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(EXCLUDED_FILES_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(EXCLUDED_FILES_PATH)
    return {
        "message": f"Файл {EXCLUDED_FILES_PATH} успешно обновлен",
        "filename": EXCLUDED_FILES_PATH,
        "size": size
    }

###########################
# excluded_extensions.yml #
###########################
@app.get("/excluded-extensions-info", dependencies=[Depends(validate_api_key)])
async def excluded_extensions_info():
    if os.path.exists(EXCLUDED_EXTENSIONS_PATH):
        stat = os.stat(EXCLUDED_EXTENSIONS_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(EXCLUDED_EXTENSIONS_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(EXCLUDED_EXTENSIONS_PATH)
    }

@app.get("/get-excluded-extensions", dependencies=[Depends(validate_api_key)])
async def get_excluded_extensions():
    try:
        if not os.path.exists(EXCLUDED_EXTENSIONS_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(EXCLUDED_EXTENSIONS_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "excluded_extensions": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-excluded-extensions", dependencies=[Depends(validate_api_key)])
async def update_excluded_extensions(data: RulesContent):
    try:
        info = await do_update_excluded_extensions(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "message": str(e), 
            "filename": EXCLUDED_EXTENSIONS_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": EXCLUDED_EXTENSIONS_PATH,
            "size": 0
        })
    
async def do_update_excluded_extensions(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "excluded_extensions")
    if not is_valid:
        raise ValueError(f"Некорректная структура excluded_extensions.yml: {error_msg}")
    
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(EXCLUDED_EXTENSIONS_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(EXCLUDED_EXTENSIONS_PATH)
    return {
        "message": f"Файл {EXCLUDED_EXTENSIONS_PATH} успешно обновлен",
        "filename": EXCLUDED_EXTENSIONS_PATH,
        "size": size
    }

##########################################
# False-Positive Rules.yml ###############
##########################################
@app.get("/rules-fp-info", dependencies=[Depends(validate_api_key)])
async def rules_fp_info():
    if os.path.exists(FP_FILE_PATH):
        stat = os.stat(FP_FILE_PATH)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "path": os.path.abspath(FP_FILE_PATH)
        }
    return {
        "exists": False,
        "size": 0,
        "modified": 0.0,
        "path": os.path.abspath(FP_FILE_PATH)
    }

@app.get("/get-fp-rules", dependencies=[Depends(validate_api_key)])
async def get_fp_rules():
    try:
        if not os.path.exists(FP_FILE_PATH):
            return JSONResponse(status_code=404, content={"status": "failed", "message": "Файл не найден"})
        
        async with aiofiles.open(FP_FILE_PATH, mode='r', encoding='utf-8') as f:
            content = await f.read()

        return {"status": "success", "fp_rules": content}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Ошибка при чтении файла: {str(e)}"
        })

@app.post("/update-fp-rules", dependencies=[Depends(validate_api_key)])
async def update_fp_rules(data: RulesContent):
    try:
        info = await update_fp_rules_file(data.content)
        return {"status": "success", **info}
    except ValueError as e:
        return JSONResponse(status_code=400, content={
            "status": "validation_failed",
            "message": str(e),
            "filename": FP_FILE_PATH,
            "size": 0
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "failed",
            "message": f"Произошла ошибка: {e}",
            "filename": FP_FILE_PATH,
            "size": 0
        })
    
async def update_fp_rules_file(content: str):
    # Валидация YAML
    is_valid, error_msg = validate_yaml_structure(content, "false_positive")
    if not is_valid:
        raise ValueError(f"Некорректная структура false-positive.yml: {error_msg}")
    
    # Заменяем \r\n и \r на \n
    normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')

    async with aiofiles.open(FP_FILE_PATH, 'w', encoding='utf-8') as out_file:
        await out_file.write(normalized_content)

    size = os.path.getsize(FP_FILE_PATH)
    return {
        "message": f"Файл {FP_FILE_PATH} успешно обновлен",
        "filename": FP_FILE_PATH,
        "size": size
    }