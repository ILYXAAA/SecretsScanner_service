from fastapi import APIRouter, HTTPException, Header, Depends, Query
from fastapi.responses import JSONResponse
import os
import secrets
import psutil
import uuid
import time
import multiprocessing
import logging
import threading
from dotenv import load_dotenv
from app.redis_client import get_redis_client
from typing import List, Optional

load_dotenv()
logger = logging.getLogger("admin_routes")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

# Global worker processes tracking (shared with main)
worker_processes = {}
service_start_time = time.time()
worker_management_lock = threading.Lock()

def set_service_start_time():
    """Установить время старта сервиса (вызывается из main.py)"""
    global service_start_time
    service_start_time = time.time()

def get_uptime_seconds():
    """Получить время работы сервиса в секундах"""
    return time.time() - service_start_time

def set_worker_processes(processes_dict):
    """Set reference to worker processes dict from main"""
    global worker_processes
    worker_processes = processes_dict

async def validate_admin_api_key(x_api_key: str = Header(None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    return x_api_key

def start_worker_process(worker_id: str) -> bool:
    """Start a new worker process with improved error handling"""
    with worker_management_lock:
        try:
            # Check if worker already exists
            if worker_id in worker_processes:
                existing_process = worker_processes[worker_id]
                if existing_process.is_alive():
                    logger.warning(f"Worker {worker_id} уже существует и работает")
                    return False
                else:
                    # Clean up dead process
                    try:
                        existing_process.join(timeout=1)
                    except:
                        pass
                    del worker_processes[worker_id]
            
            from app.worker import worker_main
            start_time = time.time()
            
            # Create and start process
            process = multiprocessing.Process(
                target=worker_main, 
                args=(worker_id,),
                name=f"Worker-{worker_id}"
            )
            process.daemon = False  # Don't make it daemon to ensure proper cleanup
            process.start()
            
            # Verify process started successfully
            time.sleep(0.5)  # Give process time to start
            if not process.is_alive():
                logger.error(f"Worker '{worker_id}' не запустился успешно")
                try:
                    process.join(timeout=1)
                except:
                    pass
                return False
            
            worker_processes[worker_id] = process
            startup_time = time.time() - start_time
            
            logger.info(f"Worker '{worker_id}' (PID: '{process.pid}') создан (время: {startup_time:.2f}с)")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка запуска worker '{worker_id}': {e}")
            return False

def stop_worker_process(worker_id: str, force: bool = False) -> bool:
    """Stop a worker process with improved cleanup"""
    with worker_management_lock:
        try:
            redis_client = get_redis_client()
            process = worker_processes.get(worker_id)
            success = False
            
            if force:
                # Force kill process
                if process and process.is_alive():
                    try:
                        logger.info(f"Принудительно завершаю процесс worker '{worker_id}' (PID: '{process.pid}')")
                        
                        # Try terminate first
                        process.terminate()
                        process.join(timeout=5)
                        
                        # If still alive, kill
                        if process.is_alive():
                            logger.warning(f"Process '{worker_id}' не завершился, принудительно убиваю")
                            process.kill()
                            process.join(timeout=2)
                        
                        if not process.is_alive():
                            success = True
                            logger.info(f"Процесс worker '{worker_id}' принудительно остановлен")
                        else:
                            logger.error(f"Не удалось остановить процесс worker '{worker_id}'")
                            
                    except Exception as e:
                        logger.error(f"Ошибка принудительной остановки процесса worker '{worker_id}': {e}")
                else:
                    logger.info(f"Worker '{worker_id}' процесс не найден или уже остановлен")
                    success = True
                
                # Always cleanup from Redis and processes dict
                if worker_id in worker_processes:
                    del worker_processes[worker_id]
                
                try:
                    redis_client.unregister_worker(worker_id)
                    logger.warning(f"Worker '{worker_id}' очищен из Redis")
                    success = True
                except Exception as e:
                    logger.critical(f"Ошибка очистки worker {worker_id} из Redis: {e}")
                
                return success
                
            else:
                # Graceful shutdown
                if not process or not process.is_alive():
                    logger.error(f"Worker '{worker_id}' процесс не найден или уже остановлен")
                    # Still try to clean up Redis
                    try:
                        redis_client.unregister_worker(worker_id)
                    except:
                        pass
                    if worker_id in worker_processes:
                        del worker_processes[worker_id]
                    return True
                
                # Send graceful shutdown command
                if redis_client.send_worker_command(worker_id, "shutdown"):
                    logger.info(f"Отправлена команда graceful shutdown для worker '{worker_id}'")
                    
                    # Wait for graceful shutdown
                    shutdown_timeout = 30  # 30 seconds for graceful shutdown
                    start_wait = time.time()
                    
                    while time.time() - start_wait < shutdown_timeout:
                        if not process.is_alive():
                            success = True
                            break
                        time.sleep(1)
                    
                    if success:
                        logger.info(f"Worker '{worker_id}' завершился gracefully")
                        try:
                            process.join(timeout=2)
                        except:
                            pass
                        if worker_id in worker_processes:
                            del worker_processes[worker_id]
                    else:
                        logger.warning(f"Worker '{worker_id}' не завершился gracefully за '{shutdown_timeout}'с, требуется force")
                        
                    return success
                else:
                    logger.critical(f"Ошибка отправки команды shutdown для worker '{worker_id}'")
                    return False
                    
        except Exception as e:
            logger.critical(f"Ошибка остановки worker '{worker_id}': {e}")
            return False

def cleanup_dead_processes():
    """Clean up dead worker processes"""
    with worker_management_lock:
        dead_workers = []
        
        for worker_id, process in list(worker_processes.items()):
            if not process.is_alive():
                dead_workers.append(worker_id)
                try:
                    process.join(timeout=1)
                except:
                    pass
                del worker_processes[worker_id]
                logger.warning(f"Очищен мертвый процесс worker '{worker_id}'")
        
        # Also clean up from Redis
        if dead_workers:
            redis_client = get_redis_client()
            for worker_id in dead_workers:
                try:
                    redis_client.unregister_worker(worker_id)
                except:
                    pass
        
        return len(dead_workers)

def get_worker_process_info(worker_id: str) -> dict:
    """Get detailed process information for a worker"""
    process = worker_processes.get(worker_id)
    if not process:
        return {"exists": False}
    
    try:
        if not process.is_alive():
            return {"exists": True, "alive": False, "pid": None}
        
        # Get process info using psutil
        try:
            p = psutil.Process(process.pid)
            return {
                "exists": True,
                "alive": True,
                "pid": process.pid,
                "cpu_percent": p.cpu_percent(),
                "memory_mb": p.memory_info().rss / 1024 / 1024,
                "status": p.status(),
                "create_time": p.create_time(),
                "num_threads": p.num_threads()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"exists": True, "alive": False, "pid": process.pid}
            
    except Exception as e:
        logger.error(f"Ошибка получения информации о процессе '{worker_id}': {e}")
        return {"exists": True, "alive": False, "error": str(e)}

# Create router
admin_router = APIRouter()

# === Worker Management ===
@admin_router.get("/workers", dependencies=[Depends(validate_admin_api_key)])
async def get_workers():
    """Get all workers with full information including process status and progress"""
    try:
        # Clean up dead processes first
        cleanup_dead_processes()
        
        redis_client = get_redis_client()
        redis_workers = redis_client.get_all_workers()
        
        # Merge with process info
        result = []
        for worker_data in redis_workers:
            worker_id = worker_data["worker_id"]
            process_info = get_worker_process_info(worker_id)
            
            worker_info = {
                **worker_data,
                "process_exists": process_info.get("exists", False),
                "process_alive": process_info.get("alive", False),
                "process_pid": process_info.get("pid"),
                "process_cpu_percent": process_info.get("cpu_percent", 0),
                "process_memory_mb": process_info.get("memory_mb", 0),
                "process_status": process_info.get("status", "unknown"),
                "process_threads": process_info.get("num_threads", 0),
                # Добавляем поля прогресса
                "current_task_progress": worker_data.get("current_task_progress"),
                "current_task_detail": worker_data.get("current_task_detail")
            }
            result.append(worker_info)
        
        # Add workers that exist in processes but not in Redis (startup phase)
        redis_worker_ids = {w["worker_id"] for w in result}
        for worker_id, process in worker_processes.items():
            if worker_id not in redis_worker_ids:
                process_info = get_worker_process_info(worker_id)
                result.append({
                    "worker_id": worker_id,
                    "status": "starting",
                    "pid": process_info.get("pid"),
                    "started_at": process_info.get("create_time"),
                    "last_heartbeat": None,
                    "current_task_id": None,
                    "current_task_progress": None,
                    "current_task_detail": None,
                    "tasks_completed": 0,
                    "tasks_failed": 0,
                    "process_exists": True,
                    "process_alive": process_info.get("alive", False),
                    "process_pid": process_info.get("pid"),
                    "process_cpu_percent": process_info.get("cpu_percent", 0),
                    "process_memory_mb": process_info.get("memory_mb", 0),
                    "process_status": process_info.get("status", "unknown"),
                    "process_threads": process_info.get("num_threads", 0)
                })
        
        return {
            "status": "success",
            "workers": result,
            "total_workers": len(result),
            "active_processes": len([w for w in result if w.get("process_alive", False)])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения списка workers: {e}")

@admin_router.post("/workers/add", dependencies=[Depends(validate_admin_api_key)])
async def add_worker():
    """Add new worker process with MAX_WORKERS limit check"""
    try:
        max_workers = int(os.getenv("MAX_WORKERS", "10"))
        
        # Очищаем мертвые процессы перед проверкой
        cleanup_dead_processes()
        
        # Подсчитываем активные воркеры
        active_workers_count = len([p for p in worker_processes.values() if p.is_alive()])
        
        # Проверяем лимит
        if active_workers_count >= max_workers:
            return JSONResponse(
                status_code=200, 
                content={
                    "status": "limit_exceeded",
                    "message": f"Достигнут максимальный лимит воркеров ({max_workers}). Активных воркеров: {active_workers_count}",
                    "active_workers": active_workers_count,
                    "max_workers": max_workers
                }
            )
        
        # Генерируем ID для нового воркера
        worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        
        # Запускаем воркер
        if start_worker_process(worker_id):
            new_active_count = len([p for p in worker_processes.values() if p.is_alive()])
            return {
                "status": "success",
                "message": f"Worker {worker_id} запущен",
                "worker_id": worker_id,
                "active_workers": new_active_count,
                "max_workers": max_workers,
                "remaining_slots": max_workers - new_active_count
            }
        else:
            raise HTTPException(status_code=500, detail="Не удалось запустить worker")
            
    except ValueError as e:
        # Ошибка парсинга MAX_WORKERS
        logger.error(f"Некорректное значение MAX_WORKERS: {e}")
        raise HTTPException(status_code=500, detail="Некорректная конфигурация MAX_WORKERS")
    except Exception as e:
        logger.error(f"Ошибка запуска worker: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка запуска worker: {e}")

@admin_router.post("/workers/{worker_id}/stop", dependencies=[Depends(validate_admin_api_key)])
async def stop_worker(worker_id: str):
    """Graceful worker shutdown"""
    try:
        if stop_worker_process(worker_id, force=False):
            return {
                "status": "success",
                "message": f"Отправлена команда graceful shutdown для worker {worker_id}"
            }
        else:
            raise HTTPException(status_code=404, detail="Worker не найден или ошибка отправки команды")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка остановки worker: {e}")

@admin_router.post("/workers/{worker_id}/kill", dependencies=[Depends(validate_admin_api_key)])
async def kill_worker(worker_id: str):
    """Force terminate worker"""
    try:
        if stop_worker_process(worker_id, force=True):
            return {
                "status": "success",
                "message": f"Worker {worker_id} принудительно остановлен"
            }
        else:
            raise HTTPException(status_code=404, detail="Worker не найден или уже остановлен")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка принудительной остановки worker: {e}")

@admin_router.post("/workers/{worker_id}/pause", dependencies=[Depends(validate_admin_api_key)])
async def pause_worker(worker_id: str):
    """Pause worker (stop taking new tasks)"""
    try:
        redis_client = get_redis_client()
        if redis_client.send_worker_command(worker_id, "pause"):
            return {
                "status": "success",
                "message": f"Worker {worker_id} приостановлен"
            }
        else:
            raise HTTPException(status_code=404, detail="Worker не найден")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка приостановки worker: {e}")

@admin_router.post("/workers/{worker_id}/resume", dependencies=[Depends(validate_admin_api_key)])
async def resume_worker(worker_id: str):
    """Resume worker (start taking new tasks)"""
    try:
        redis_client = get_redis_client()
        if redis_client.send_worker_command(worker_id, "resume"):
            return {
                "status": "success",
                "message": f"Worker {worker_id} возобновлен"
            }
        else:
            raise HTTPException(status_code=404, detail="Worker не найден")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка возобновления worker: {e}")

@admin_router.post("/workers/{worker_id}/restart", dependencies=[Depends(validate_admin_api_key)])
async def restart_worker(worker_id: str):
    """Restart worker process"""
    try:
        # Stop the worker first
        stop_success = stop_worker_process(worker_id, force=False)
        
        # Wait a bit for cleanup
        time.sleep(2)
        
        # Start new worker
        start_success = start_worker_process(worker_id)
        
        if start_success:
            return {
                "status": "success",
                "message": f"Worker {worker_id} перезапущен",
                "stopped_gracefully": stop_success
            }
        else:
            raise HTTPException(status_code=500, detail="Не удалось перезапустить worker")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка перезапуска worker: {e}")

@admin_router.post("/workers/cleanup", dependencies=[Depends(validate_admin_api_key)])
async def cleanup_workers():
    """Clean up dead worker processes"""
    try:
        cleaned_count = cleanup_dead_processes()
        return {
            "status": "success",
            "message": f"Очищено {cleaned_count} мертвых процессов",
            "cleaned_count": cleaned_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка очистки процессов: {e}")

# === Task Management ===
@admin_router.get("/tasks", dependencies=[Depends(validate_admin_api_key)])
async def get_tasks(
    status: Optional[str] = Query(None, description="Comma-separated list of statuses (pending,processing,completed,failed)"),
    limit: int = Query(100, description="Number of tasks to return (0 = all)")
):
    """Get tasks with optional status filtering and progress information"""
    try:
        redis_client = get_redis_client()
        
        # Parse status filter
        status_filter = None
        if status:
            status_filter = [s.strip() for s in status.split(",") if s.strip()]
            # Validate status values
            valid_statuses = {"pending", "processing", "downloading", "unpacking", "scanning", "ml_validation", "completed", "failed"}
            invalid_statuses = set(status_filter) - valid_statuses
            if invalid_statuses:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid status values: {list(invalid_statuses)}. Valid: {list(valid_statuses)}"
                )
        
        tasks = redis_client.get_tasks(status_filter=status_filter, limit=limit)
        
        # Добавляем человекочитаемые описания статусов
        enhanced_tasks = []
        for task in tasks:
            enhanced_task = task.copy()
            
            status = task.get("status", "")
            progress = task.get("progress", 0)
            progress_detail = task.get("progress_detail", "")
            
            # Добавляем человекочитаемое описание этапа
            status_descriptions = {
                "pending": "Ожидает обработки",
                "downloading": "Загрузка репозитория", 
                "unpacking": "Распаковка архива",
                "scanning": "Сканирование файлов",
                "ml_validation": "ML проверка результатов",
                "completed": "Завершено",
                "failed": "Ошибка"
            }
            enhanced_task["status_description"] = status_descriptions.get(status, status)
            
            # Добавляем время выполнения если задача завершена
            if task.get("completed_at") and task.get("started_at"):
                execution_time = task["completed_at"] - task["started_at"]
                enhanced_task["execution_time_seconds"] = round(execution_time, 2)
                enhanced_task["execution_time_formatted"] = format_duration(execution_time)
            
            # Добавляем время в очереди
            if task.get("started_at") and task.get("created_at"):
                queue_time = task["started_at"] - task["created_at"]
                enhanced_task["queue_time_seconds"] = round(queue_time, 2)
                enhanced_task["queue_time_formatted"] = format_duration(queue_time)
            
            enhanced_tasks.append(enhanced_task)
        
        return {
            "status": "success",
            "tasks": enhanced_tasks,
            "count": len(enhanced_tasks),
            "limit": limit if limit > 0 else "unlimited",
            "status_filter": status_filter
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения задач: {e}")

def format_duration(seconds: float) -> str:
    """Форматирует время в человекочитаемый вид"""
    if seconds < 60:
        return f"{seconds:.1f}с"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}м"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}ч"

@admin_router.post("/tasks/{task_id}/retry", dependencies=[Depends(validate_admin_api_key)])
async def retry_task(task_id: str):
    """Retry failed task"""
    try:
        redis_client = get_redis_client()
        if redis_client.retry_task(task_id):
            return {
                "status": "success",
                "message": f"Задача {task_id} возвращена в очередь"
            }
        else:
            raise HTTPException(status_code=404, detail="Задача не найдена или не может быть повторена")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка повтора задачи: {e}")

@admin_router.get("/tasks/{task_id}", dependencies=[Depends(validate_admin_api_key)])
async def get_task_details(task_id: str):
    """Get detailed information about a specific task"""
    try:
        redis_client = get_redis_client()
        task = redis_client.get_task(task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="Задача не найдена")
        
        # Remove sensitive original_data for response
        task_copy = task.copy()
        task_copy.pop("original_data", None)
        
        return {
            "status": "success",
            "task": task_copy
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения задачи: {e}")

# === Service Statistics ===

@admin_router.get("/service_stats", dependencies=[Depends(validate_admin_api_key)])
async def get_service_stats():
    """Get comprehensive service statistics"""
    try:
        redis_client = get_redis_client()
        
        # Clean up dead processes first
        cleanup_dead_processes()
        
        # System stats
        uptime_seconds = get_uptime_seconds()
        system_cpu_percent = psutil.cpu_percent(interval=0.1)
        system_memory = psutil.virtual_memory()
        system_disk = psutil.disk_usage('/')
        
        # Worker process stats
        worker_stats = []
        total_worker_memory = 0
        total_worker_cpu = 0
        active_workers = 0
        
        for worker_id, process in worker_processes.items():
            if process.is_alive():
                try:
                    p = psutil.Process(process.pid)
                    worker_memory = p.memory_info().rss / 1024 / 1024  # MB
                    worker_cpu = p.cpu_percent()
                    total_worker_memory += worker_memory
                    total_worker_cpu += worker_cpu
                    active_workers += 1
                    
                    worker_stats.append({
                        "worker_id": worker_id,
                        "pid": process.pid,
                        "cpu_percent": round(worker_cpu, 1),
                        "memory_mb": round(worker_memory, 1),
                        "status": p.status(),
                        "threads": p.num_threads()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        # Queue stats
        queue_stats = redis_client.get_queue_stats()
        
        # Worker status distribution from Redis
        redis_workers = redis_client.get_all_workers()
        worker_status_counts = {}
        worker_tasks_total = {"completed": 0, "failed": 0}
        
        for worker in redis_workers:
            status = worker.get("status", "unknown")
            worker_status_counts[status] = worker_status_counts.get(status, 0) + 1
            worker_tasks_total["completed"] += worker.get("tasks_completed", 0)
            worker_tasks_total["failed"] += worker.get("tasks_failed", 0)
        
        return {
            "status": "success",
            "uptime_seconds": round(uptime_seconds, 1),
            "system": {
                "cpu_percent": round(system_cpu_percent, 1),
                "memory_total_gb": round(system_memory.total / 1024 / 1024 / 1024, 1),
                "memory_used_gb": round(system_memory.used / 1024 / 1024 / 1024, 1),
                "memory_percent": round(system_memory.percent, 1),
                "disk_total_gb": round(system_disk.total / 1024 / 1024 / 1024, 1),
                "disk_used_gb": round(system_disk.used / 1024 / 1024 / 1024, 1),
                "disk_percent": round((system_disk.used / system_disk.total) * 100, 1)
            },
            "workers": {
                "total_registered": len(redis_workers),
                "active_processes": active_workers,
                "total_cpu_percent": round(total_worker_cpu, 1),
                "total_memory_mb": round(total_worker_memory, 1),
                "average_cpu_per_worker": round(total_worker_cpu / max(active_workers, 1), 1),
                "average_memory_per_worker": round(total_worker_memory / max(active_workers, 1), 1),
                "status_distribution": worker_status_counts,
                "tasks_completed_total": worker_tasks_total["completed"],
                "tasks_failed_total": worker_tasks_total["failed"],
                "processes": worker_stats
            },
            "queue": queue_stats,
            "generated_at": time.time()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения статистики: {e}")

# === Maintenance Operations ===

@admin_router.post("/maintenance/cleanup_old_tasks", dependencies=[Depends(validate_admin_api_key)])
async def cleanup_old_tasks():
    """Clean up old completed/failed tasks"""
    try:
        redis_client = get_redis_client()
        cleaned_count = redis_client.cleanup_expired_tasks()
        
        return {
            "status": "success",
            "message": f"Очищено {cleaned_count} старых задач",
            "cleaned_count": cleaned_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка очистки старых задач: {e}")

@admin_router.post("/maintenance/verify_queue", dependencies=[Depends(validate_admin_api_key)])
async def verify_queue_consistency():
    """Verify and fix queue consistency"""
    try:
        redis_client = get_redis_client()
        redis_client._verify_queue_consistency()
        
        return {
            "status": "success",
            "message": "Проверка консистентности очереди завершена"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка проверки очереди: {e}")

@admin_router.post("/maintenance/full_cleanup", dependencies=[Depends(validate_admin_api_key)])
async def full_cleanup():
    """Perform full system cleanup"""
    try:
        redis_client = get_redis_client()
        
        # Clean up old tasks
        old_tasks_cleaned = redis_client.cleanup_expired_tasks()
        
        # Clean up dead workers from Redis
        dead_workers_cleaned = redis_client.cleanup_dead_workers()
        
        # Clean up dead processes
        dead_processes_cleaned = cleanup_dead_processes()
        
        # Verify queue consistency
        redis_client._verify_queue_consistency()
        
        return {
            "status": "success",
            "message": "Полная очистка системы завершена",
            "old_tasks_cleaned": old_tasks_cleaned,
            "dead_workers_cleaned": dead_workers_cleaned,
            "dead_processes_cleaned": dead_processes_cleaned
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка полной очистки: {e}")

# === Health Check for Workers ===

@admin_router.get("/workers/health", dependencies=[Depends(validate_admin_api_key)])
async def workers_health():
    """Check health of all workers"""
    try:
        redis_client = get_redis_client()
        redis_workers = redis_client.get_all_workers()
        current_time = time.time()
        
        health_report = {
            "healthy_workers": 0,
            "unhealthy_workers": 0,
            "not_responding_workers": 0,
            "workers": []
        }
        
        for worker in redis_workers:
            worker_id = worker["worker_id"]
            last_heartbeat = worker.get("last_heartbeat", 0)
            heartbeat_age = current_time - last_heartbeat
            
            # Get process info
            process_info = get_worker_process_info(worker_id)
            
            # Determine health status
            if heartbeat_age > 60:  # 1 minute without heartbeat
                health_status = "not_responding"
                health_report["not_responding_workers"] += 1
            elif not process_info.get("alive", False):
                health_status = "unhealthy"
                health_report["unhealthy_workers"] += 1
            else:
                health_status = "healthy"
                health_report["healthy_workers"] += 1
            
            health_report["workers"].append({
                "worker_id": worker_id,
                "health_status": health_status,
                "heartbeat_age_seconds": round(heartbeat_age, 1),
                "process_alive": process_info.get("alive", False),
                "current_status": worker.get("status", "unknown"),
                "current_task": worker.get("current_task_id")
            })
        
        health_report["total_workers"] = len(redis_workers)
        health_report["overall_health"] = "healthy" if health_report["healthy_workers"] == health_report["total_workers"] else "degraded"
        
        return {
            "status": "success",
            "health": health_report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка проверки здоровья воркеров: {e}")