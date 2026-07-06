import redis
import json
import time
import logging
import os
import threading
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv
import uuid

load_dotenv()
logger = logging.getLogger("redis_client")

class RedisClient:
    _instance = None
    _lock = threading.Lock()
    
    def __init__(self):
        if RedisClient._instance is not None:
            raise Exception("Use get_redis_client() to get the singleton instance")
        
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
        
        # Configuration from environment
        self.task_timeout_seconds = int(os.getenv("TASK_TIMEOUT_SECONDS", "1800"))  # 30 minutes
        self.worker_heartbeat_interval = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "20"))  # seconds
        self.task_retention_days = int(os.getenv("TASK_RETENTION_DAYS", "7"))  # days
        
        # Test connection
        try:
            self.redis_client.ping()
            logger.info(f"Подключен к Redis: '{redis_url}'")
        except Exception as e:
            logger.critical(f"Ошибка подключения к Redis: {e}")
            raise
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # === Task Management ===
    
    def push_task(self, task_data: dict, priority: int = 1) -> bool:
        """Add task to priority queue with atomic operations"""
        try:
            # Generate unique task ID
            task_id = f"task-{uuid.uuid4().hex[:8]}" # f"task-{int(time.time() * 1000)}-{hash(str(task_data)) % 10000:04d}"
            
            current_time = time.time()
            timeout_at = current_time + self.task_timeout_seconds
            
            # Extract project name for better logging
            project_name = self._extract_project_name(task_data)
            
            # Create complete task object
            task = {
                "task_id": task_id,
                "status": "pending",
                "project_name": project_name,
                "description": f"Scan {project_name}",
                "repo_url": task_data.get("request", {}).get("RepoUrl", ""),
                "commit": task_data.get("commit", ""),
                "ref": task_data.get("request", {}).get("Ref", ""),
                "ref_type": task_data.get("request", {}).get("RefType", ""),
                "callback_url": task_data.get("request", {}).get("CallbackUrl", ""),
                "task_type": task_data.get("type", "scan"),
                "created_at": current_time,
                "started_at": None,
                "completed_at": None,
                "worker_id": None,
                "error": None,
                "results_count": None,
                "retry_count": 0,
                "timeout_at": timeout_at,
                "priority": priority,
                "progress": 0,
                "progress_detail": None,
                # Store original task data for processing
                "original_data": task_data
            }
            
            # Calculate score for priority queue: priority * 1000000 + timestamp
            # Lower score = higher priority (priority 1 before priority 2)
            score = priority * 1000000 + current_time
            
            # Use atomic transaction
            pipe = self.redis_client.pipeline()
            pipe.multi()
            
            # Add to priority queue
            pipe.zadd("tasks:queue", {task_id: score})
            
            # Store full task data
            pipe.hset("tasks:all", task_id, json.dumps(task, ensure_ascii=False))
            
            # Add to pending index
            pipe.sadd("index:tasks:pending", task_id)
            
            # Execute atomically
            results = pipe.execute()
            
            # Verify all operations succeeded
            if all(results):
                logger.info(f"Задача добавлена в очередь: '{project_name}' (ID: '{task_id}', priority: '{priority}')")
                return True
            else:
                logger.error(f"Не все операции выполнены при создании задачи '{task_id}': {results}")
                # Cleanup partial state
                self._cleanup_partial_task(task_id)
                return False
            
        except Exception as e:
            logger.critical(f"Ошибка добавления задачи: {e}")
            return False

    def _cleanup_partial_task(self, task_id: str):
        """Clean up partially created task"""
        try:
            pipe = self.redis_client.pipeline()
            pipe.zrem("tasks:queue", task_id)
            pipe.hdel("tasks:all", task_id)
            pipe.srem("index:tasks:pending", task_id)
            pipe.execute()
            logger.info(f"Очищена частично созданная задача '{task_id}'")
        except Exception as e:
            logger.error(f"Ошибка очистки частично созданной задачи '{task_id}': {e}")

    def _extract_project_name(self, task_data: dict) -> str:
        """Extract project name from task data"""
        if "request" in task_data and isinstance(task_data["request"], dict):
            return task_data["request"].get("ProjectName", "unknown")
        elif "ProjectName" in task_data:
            return task_data.get("ProjectName", "unknown")
        elif "items" in task_data and task_data["items"]:
            first_item = task_data["items"][0]
            return first_item.get("ProjectName", "multi-scan")
        return "unknown"

    def pop_task(self, worker_id: str, timeout: int = 5) -> Optional[dict]:
        """Get task from priority queue with improved atomicity"""
        try:
            current_time = time.time()
            
            # Use Lua script for atomic pop operation
            lua_script = """
                local current_time = tonumber(ARGV[1])
                local worker_id = ARGV[2]
                
                -- Get highest priority task
                local tasks = redis.call('ZRANGE', 'tasks:queue', 0, 0, 'WITHSCORES')
                if #tasks == 0 then
                    return nil
                end
                
                local task_id = tasks[1]
                local score = tasks[2]
                
                -- Get task data
                local task_json = redis.call('HGET', 'tasks:all', task_id)
                if not task_json then
                    -- Clean up orphaned queue entry
                    redis.call('ZREM', 'tasks:queue', task_id)
                    redis.call('SREM', 'index:tasks:pending', task_id)
                    return 'orphaned'
                end
                
                -- Parse task data (simplified - assume valid JSON)
                local task = cjson.decode(task_json)
                
                -- Check timeout
                if task.timeout_at and task.timeout_at < current_time then
                    -- Mark as failed and remove
                    task.status = 'failed'
                    task.error = 'Task timeout exceeded'
                    task.completed_at = current_time
                    task.worker_id = nil
                    
                    local updated_task_json = cjson.encode(task)
                    redis.call('HSET', 'tasks:all', task_id, updated_task_json)
                    redis.call('ZREM', 'tasks:queue', task_id)
                    redis.call('SREM', 'index:tasks:pending', task_id)
                    redis.call('SADD', 'index:tasks:failed', task_id)
                    return 'timeout'
                end
                
                -- Update task for worker assignment
                task.status = 'downloading'
                task.worker_id = worker_id
                task.started_at = current_time
                local updated_task_json = cjson.encode(task)
                
                -- Atomic assignment
                redis.call('ZREM', 'tasks:queue', task_id)
                redis.call('HSET', 'tasks:all', task_id, updated_task_json)
                redis.call('SREM', 'index:tasks:pending', task_id)
                redis.call('SADD', 'index:tasks:processing', task_id)
                
                return updated_task_json
            """
            
            # Execute Lua script
            try:
                script = self.redis_client.register_script(lua_script)
                result = script(keys=[], args=[current_time, worker_id])
                
                if result is None:
                    return None
                elif result == 'orphaned':
                    logger.debug(f"Найдена задача-сирота, пробуем снова")
                    return self.pop_task(worker_id, timeout)  # Retry once
                elif result == 'timeout':
                    logger.debug(f"Задача с timeout обработана, пробуем снова")
                    return self.pop_task(worker_id, timeout)  # Retry once
                else:
                    # Valid task returned
                    task = json.loads(result)
                    logger.info(f"Воркер '{worker_id}' получил задачу: '{task['project_name']}' (ID: '{task['task_id']}')")
                    return task
                    
            except Exception as lua_error:
                logger.critical(f"Ошибка выполнения Lua скрипта: {lua_error}")
                # Fallback to Python implementation
                return self._pop_task_fallback(worker_id, current_time)
            
        except Exception as e:
            logger.critical(f"Критическая ошибка получения задачи для '{worker_id}': {e}")
            return None

    def _pop_task_fallback(self, worker_id: str, current_time: float) -> Optional[dict]:
        """Fallback implementation using Python with transactions"""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                # Watch the queue for changes
                with self.redis_client.pipeline() as pipe:
                    pipe.watch("tasks:queue")
                    
                    # Get highest priority task
                    tasks = pipe.zrange("tasks:queue", 0, 0, withscores=True)
                    if not tasks:
                        pipe.unwatch()
                        return None
                    
                    task_id, score = tasks[0]
                    
                    # Get task data
                    task_json = self.redis_client.hget("tasks:all", task_id)
                    if not task_json:
                        # Clean up orphaned queue entry
                        pipe.unwatch()
                        self.redis_client.zrem("tasks:queue", task_id)
                        self.redis_client.srem("index:tasks:pending", task_id)
                        logger.warning(f"Очищена задача-сирота '{task_id}' из очереди")
                        continue
                    
                    try:
                        task = json.loads(task_json)
                    except json.JSONDecodeError:
                        # Clean up corrupted task
                        pipe.unwatch()
                        self.redis_client.zrem("tasks:queue", task_id)
                        self.redis_client.hdel("tasks:all", task_id)
                        self.redis_client.srem("index:tasks:pending", task_id)
                        logger.warning(f"Очищена поврежденная задача '{task_id}'")
                        continue
                    
                    # Check timeout
                    if task.get("timeout_at", 0) < current_time:
                        # Mark as failed and remove
                        pipe.unwatch()
                        task["status"] = "failed"
                        task["error"] = "Task timeout exceeded"
                        task["completed_at"] = current_time
                        task["worker_id"] = None
                        
                        self.redis_client.hset("tasks:all", task_id, json.dumps(task, ensure_ascii=False))
                        self.redis_client.zrem("tasks:queue", task_id)
                        self.redis_client.srem("index:tasks:pending", task_id)
                        self.redis_client.sadd("index:tasks:failed", task_id)
                        logger.warning(f"Задача '{task_id}' помечена как failed по таймауту")
                        continue
                    
                    # Update task for worker assignment
                    task["status"] = "downloading"
                    task["worker_id"] = worker_id
                    task["started_at"] = current_time
                    updated_task_json = json.dumps(task, ensure_ascii=False)
                    
                    # Start transaction
                    pipe.multi()
                    
                    # Remove from queue
                    pipe.zrem("tasks:queue", task_id)
                    
                    # Update task data
                    pipe.hset("tasks:all", task_id, updated_task_json)
                    
                    # Update indexes
                    pipe.srem("index:tasks:pending", task_id)
                    pipe.sadd("index:tasks:processing", task_id)
                    
                    # Execute transaction
                    results = pipe.execute()
                    
                    # Verify success
                    if results[0] == 1 and results[2] == 1 and results[3] == 1:  # zrem, srem, sadd success
                        logger.info(f"Воркер '{worker_id}' получил задачу: '{task['project_name']}' (ID: '{task_id}')")
                        return task
                    else:
                        logger.warning(f"Частичный успех транзакции для '{task_id}': {results}")
                        continue
                    
            except redis.WatchError:
                # Queue was modified by another worker, retry
                logger.debug(f"Очередь изменена во время получения задачи, повтор (попытка {attempt + 1})")
                continue
            except Exception as e:
                logger.error(f"Ошибка в pop_task попытка {attempt + 1}: {e}")
                continue
        
        logger.warning(f"Не удалось получить задачу для '{worker_id}' после {max_attempts} попыток")
        return None

    def update_task_status(self, task_id: str, status: str, **kwargs) -> bool:
        """Update task status and additional fields atomically"""
        try:
            lua_script = """
                local task_id = KEYS[1]
                local new_status = ARGV[1]
                local current_time = tonumber(ARGV[2])
                local kwargs_json = ARGV[3]
                
                -- Get current task
                local task_json = redis.call('HGET', 'tasks:all', task_id)
                if not task_json then
                    return nil
                end
                
                local task = cjson.decode(task_json)
                local old_status = task.status
                
                -- Update status
                task.status = new_status
                
                -- ИСПРАВЛЕНИЕ: Сбрасываем прогресс при смене статуса
                if old_status ~= new_status then
                    task.progress = 0
                    task.progress_detail = nil
                end
                
                -- Parse and apply additional fields
                local kwargs = cjson.decode(kwargs_json)
                for key, value in pairs(kwargs) do
                    task[key] = value
                end
                
                -- Update timestamps
                if new_status == 'completed' or new_status == 'failed' then
                    task.completed_at = current_time
                end
                
                -- Update task data
                local updated_task_json = cjson.encode(task)
                redis.call('HSET', 'tasks:all', task_id, updated_task_json)
                
                -- Update indexes
                if old_status ~= new_status then
                    -- Удаляем из всех возможных старых индексов
                    local all_statuses = {'pending', 'processing', 'downloading', 'unpacking', 'scanning', 'ml_validation', 'completed', 'failed'}
                    for _, status in ipairs(all_statuses) do
                        if status ~= new_status then
                            redis.call('SREM', 'index:tasks:' .. status, task_id)
                        end
                    end
                    -- Добавляем в новый индекс
                    redis.call('SADD', 'index:tasks:' .. new_status, task_id)
                end

                return old_status
            """
            
            kwargs_json = json.dumps(kwargs)
            current_time = time.time()
            
            script = self.redis_client.register_script(lua_script)
            old_status = script(keys=[task_id], args=[status, current_time, kwargs_json])
            
            if old_status is not None:
                logger.info(f"Задача '{task_id}' обновлена: '{old_status}' -> '{status}'")
                return True
            else:
                logger.warning(f"Задача '{task_id}' не найдена для обновления статуса")
                return False
            
        except Exception as e:
            logger.error(f"Ошибка обновления статуса задачи '{task_id}': {e}")
            return False

    def get_task(self, task_id: str) -> Optional[dict]:
        """Get task by ID"""
        try:
            task_json = self.redis_client.hget("tasks:all", task_id)
            return json.loads(task_json) if task_json else None
        except Exception as e:
            logger.error(f"Ошибка получения задачи '{task_id}': {e}")
            return None

    def retry_task(self, task_id: str) -> bool:
        """Retry failed task atomically"""
        try:
            lua_script = """
                local task_id = KEYS[1]
                local current_time = tonumber(ARGV[1])
                local task_timeout_seconds = tonumber(ARGV[2])
                
                -- Get current task
                local task_json = redis.call('HGET', 'tasks:all', task_id)
                if not task_json then
                    return 'not_found'
                end
                
                local task = cjson.decode(task_json)
                
                -- Check if can retry
                if task.status ~= 'failed' and task.status ~= 'completed' then
                    return 'invalid_status'
                end
                
                if task.task_type == 'local_scan' or task.task_type == 'local_forbidden_check' then
                    return 'local_scan_no_retry'
                end
                
                -- Reset task for retry
                task.status = 'pending'
                task.worker_id = nil
                task.started_at = nil
                task.completed_at = nil
                task.error = nil
                task.retry_count = (task.retry_count or 0) + 1
                task.timeout_at = current_time + task_timeout_seconds
                
                -- Calculate new score
                local priority = task.priority or 1
                local score = priority * 1000000 + current_time
                
                -- Update task
                local updated_task_json = cjson.encode(task)
                redis.call('HSET', 'tasks:all', task_id, updated_task_json)
                
                -- Add back to queue
                redis.call('ZADD', 'tasks:queue', score, task_id)
                
                -- Update indexes
                redis.call('SREM', 'index:tasks:failed', task_id)
                redis.call('SREM', 'index:tasks:completed', task_id)
                redis.call('SADD', 'index:tasks:pending', task_id)
                
                return tostring(task.retry_count)
            """
            
            current_time = time.time()
            script = self.redis_client.register_script(lua_script)
            result = script(keys=[task_id], args=[current_time, self.task_timeout_seconds])
            
            if result == 'not_found':
                logger.warning(f"Задача '{task_id}' не найдена для retry")
                return False
            elif result == 'invalid_status':
                logger.warning(f"Нельзя повторить задачу '{task_id}' с текущим статусом")
                return False
            elif result == 'local_scan_no_retry':
                logger.warning(f"Повтор local_scan задачи '{task_id}' запрещен")
                return False
            else:
                retry_count = result
                logger.info(f"Задача '{task_id}' возвращена в очередь (попытка #{retry_count})")
                return True
            
        except Exception as e:
            logger.error(f"Ошибка повтора задачи '{task_id}': {e}")
            return False

    # === Worker Management ===
    
    def register_worker(self, worker_id: str, pid: int) -> bool:
        """Register worker atomically"""
        try:
            worker_data = {
                "worker_id": worker_id,
                "status": "starting",
                "pid": pid,
                "started_at": time.time(),
                "last_heartbeat": time.time(),
                "current_task_id": None,
                "tasks_completed": 0,
                "tasks_failed": 0,
                "model_version": None
            }
            
            # Use atomic operation
            result = self.redis_client.hset("workers:all", worker_id, json.dumps(worker_data, ensure_ascii=False))
            logger.info(f"Воркер '{worker_id}' зарегистрирован в 'Redis' (PID: '{pid}')")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка регистрации воркера '{worker_id}': {e}")
            return False

    def update_task_progress(self, task_id: str, progress: int, progress_detail: str = None) -> bool:
        """Update task progress without changing status"""
        try:
            lua_script = """
                local task_id = KEYS[1]
                local progress = tonumber(ARGV[1])
                local progress_detail = ARGV[2]
                if progress_detail == 'nil' then
                    progress_detail = nil
                end
                
                -- Get current task
                local task_json = redis.call('HGET', 'tasks:all', task_id)
                if not task_json then
                    return nil
                end
                
                local task = cjson.decode(task_json)
                
                -- Update progress
                task.progress = progress
                if progress_detail then
                    task.progress_detail = progress_detail
                end
                
                -- Update task data
                local updated_task_json = cjson.encode(task)
                redis.call('HSET', 'tasks:all', task_id, updated_task_json)
                
                return 'ok'
            """
            
            progress_detail_arg = progress_detail if progress_detail else 'nil'
            
            script = self.redis_client.register_script(lua_script)
            result = script(keys=[task_id], args=[progress, progress_detail_arg])
            
            return result == 'ok'
            
        except Exception as e:
            logger.error(f"Ошибка обновления прогресса задачи '{task_id}': {e}")
            return False

    def update_worker_heartbeat(self, worker_id: str, status: str = "free", current_task_id: str = None, task_progress: int = None, task_detail: str = None, model_version: str = None) -> bool:
        """Update worker heartbeat atomically with progress info"""
        try:
            lua_script = """
                local worker_id = KEYS[1]
                local new_status = ARGV[1]
                local current_time = tonumber(ARGV[2])
                local current_task_id = ARGV[3]
                local task_progress = tonumber(ARGV[4])
                local task_detail = ARGV[5]
                local model_version = ARGV[6]
                
                if current_task_id == 'nil' then
                    current_task_id = nil
                end
                if task_progress == 0 then
                    task_progress = nil
                end
                if task_detail == 'nil' then
                    task_detail = nil
                end
                if model_version == 'nil' then
                    model_version = nil
                end
                
                -- Get current worker or create new
                local worker_json = redis.call('HGET', 'workers:all', worker_id)
                local worker
                
                if worker_json then
                    worker = cjson.decode(worker_json)
                else
                    -- Create new worker entry if not exists
                    worker = {
                        worker_id = worker_id,
                        status = 'unknown',
                        pid = 0,
                        started_at = current_time,
                        last_heartbeat = current_time,
                        current_task_id = nil,
                        current_task_progress = nil,
                        current_task_detail = nil,
                        tasks_completed = 0,
                        tasks_failed = 0,
                        model_version = nil
                    }
                end
                
                -- Update heartbeat fields
                worker.status = new_status
                worker.last_heartbeat = current_time
                worker.current_task_id = current_task_id
                
                -- Обновляем last_progress_update только если прогресс действительно изменился
                local old_progress = worker.current_task_progress
                if task_progress ~= nil and task_progress ~= old_progress then
                    worker.last_progress_update = current_time
                elseif worker.last_progress_update == nil and task_progress ~= nil then
                    -- Первое обновление прогресса
                    worker.last_progress_update = current_time
                end
                
                worker.current_task_progress = task_progress
                worker.current_task_detail = task_detail
                if model_version then
                    worker.model_version = model_version
                end
                
                -- Save back
                local updated_worker_json = cjson.encode(worker)
                redis.call('HSET', 'workers:all', worker_id, updated_worker_json)
                
                return 'ok'
            """
            
            current_time = time.time()
            task_id_arg = current_task_id if current_task_id else 'nil'
            progress_arg = task_progress if task_progress is not None else 0
            detail_arg = task_detail if task_detail else 'nil'
            model_version_arg = model_version if model_version else 'nil'
            
            script = self.redis_client.register_script(lua_script)
            script(keys=[worker_id], args=[status, current_time, task_id_arg, progress_arg, detail_arg, model_version_arg])
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка обновления heartbeat воркера '{worker_id}': {e}")
            return False

    def update_worker_model_version(self, worker_id: str, model_version: str) -> bool:
        """Update worker model version"""
        try:
            worker_json = self.redis_client.hget("workers:all", worker_id)
            if worker_json:
                worker = json.loads(worker_json)
                worker["model_version"] = model_version
                self.redis_client.hset("workers:all", worker_id, json.dumps(worker, ensure_ascii=False))
                logger.info(f"Версия модели воркера '{worker_id}' обновлена: {model_version}")
                return True
            else:
                logger.warning(f"Воркер '{worker_id}' не найден для обновления версии модели")
                return False
        except Exception as e:
            logger.error(f"Ошибка обновления версии модели воркера '{worker_id}': {e}")
            return False

    def unregister_worker(self, worker_id: str) -> bool:
        """Unregister worker"""
        try:
            self.redis_client.hdel("workers:all", worker_id)
            logger.warning(f"Воркер '{worker_id}' отписан")
            return True
        except Exception as e:
            logger.error(f"Ошибка отписки воркера '{worker_id}': {e}")
            return False

    def get_all_workers(self) -> List[Dict[str, Any]]:
        """Get all workers"""
        try:
            workers_data = self.redis_client.hgetall("workers:all")
            workers = []
            current_time = time.time()
            
            for worker_id, worker_json in workers_data.items():
                try:
                    worker = json.loads(worker_json)
                    
                    # Determine status based on heartbeat
                    last_heartbeat = worker.get("last_heartbeat", 0)
                    heartbeat_age = current_time - last_heartbeat
                    
                    if heartbeat_age > self.worker_heartbeat_interval * 3:  # 3x heartbeat interval
                        worker["status"] = "not_responding"
                    
                    workers.append(worker)
                except:
                    continue
            
            return workers
        except Exception as e:
            logger.error(f"Ошибка получения списка воркеров: {e}")
            return []

    # === Admin API Helpers ===
    
    def get_tasks(self, status_filter: List[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get tasks with optional status filtering"""
        try:
            if limit == 0:
                limit = None  # No limit
            
            if status_filter:
                # Get task IDs from specific status indexes
                task_ids = set()
                for status in status_filter:
                    ids = self.redis_client.smembers(f"index:tasks:{status}")
                    task_ids.update(ids)
                task_ids = list(task_ids)
            else:
                # Get all task IDs
                task_ids = list(self.redis_client.hkeys("tasks:all"))
            
            # Get task data
            tasks = []
            if task_ids:
                # Apply limit
                if limit:
                    task_ids = task_ids[:limit]
                
                # Get task data in batch
                pipe = self.redis_client.pipeline()
                for task_id in task_ids:
                    pipe.hget("tasks:all", task_id)
                
                task_jsons = pipe.execute()
                
                for task_id, task_json in zip(task_ids, task_jsons):
                    if task_json:
                        try:
                            task = json.loads(task_json)
                            # Remove original_data from response (internal use only)
                            task_copy = task.copy()
                            task_copy.pop("original_data", None)
                            tasks.append(task_copy)
                        except:
                            continue
            
            # Sort by created_at (newest first)
            tasks.sort(key=lambda x: x.get("created_at", 0), reverse=True)
            
            return tasks
            
        except Exception as e:
            logger.error(f"Ошибка получения задач: {e}")
            return []

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        try:
            stats = {}
            
            # Get counts from indexes
            stats["pending"] = self.redis_client.scard("index:tasks:pending")
            stats["processing"] = self.redis_client.scard("index:tasks:processing")
            stats["completed"] = self.redis_client.scard("index:tasks:completed")
            stats["failed"] = self.redis_client.scard("index:tasks:failed")
            
            # Queue length
            stats["queue_length"] = self.redis_client.zcard("tasks:queue")
            
            return stats
            
        except Exception as e:
            logger.error(f"Ошибка получения статистики очереди: {e}")
            return {
                "pending": 0,
                "processing": 0,
                "completed": 0,
                "failed": 0,
                "queue_length": 0
            }

    # === Worker Commands ===
    
    def send_worker_command(self, worker_id: str, command: str) -> bool:
        """Send command to worker"""
        try:
            command_data = {
                "worker_id": worker_id,
                "command": command,
                "timestamp": time.time()
            }
            
            # Store command in worker-specific key with expiration
            command_key = f"worker_commands:{worker_id}"
            self.redis_client.setex(command_key, 300, json.dumps(command_data))  # 5 minutes TTL
            
            logger.info(f"Команда '{command}' отправлена воркеру {worker_id}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка отправки команды воркеру '{worker_id}': {e}")
            return False

    def get_worker_command(self, worker_id: str) -> Optional[str]:
        """Get command for worker"""
        try:
            command_key = f"worker_commands:{worker_id}"
            command_json = self.redis_client.get(command_key)
            
            if command_json:
                # Delete command after reading (one-time use)
                self.redis_client.delete(command_key)
                command_data = json.loads(command_json)
                return command_data.get("command")
            
            return None
            
        except Exception as e:
            logger.error(f"Ошибка получения команды для воркера '{worker_id}': {e}")
            return None

    # === Cleanup and Maintenance ===
    
    def cleanup_expired_tasks(self) -> int:
        """Clean up old completed/failed tasks and fix problematic tasks"""
        try:
            cutoff_time = time.time() - (self.task_retention_days * 24 * 3600)
            current_time = time.time()
            cleaned_count = 0
            fixed_count = 0
            
            # Get all active workers to check for orphaned tasks
            active_workers = set()
            workers_data = self.redis_client.hgetall("workers:all")
            for worker_id, worker_json in workers_data.items():
                try:
                    worker = json.loads(worker_json)
                    last_heartbeat = worker.get("last_heartbeat", 0)
                    # Consider worker active if heartbeat within last 2 minutes
                    if (current_time - last_heartbeat) < 120:
                        active_workers.add(worker_id)
                except:
                    continue
            
            # 1. Clean up old completed/failed tasks (existing logic)
            for status in ["completed", "failed"]:
                task_ids = self.redis_client.smembers(f"index:tasks:{status}")
                
                for task_id in task_ids:
                    task_json = self.redis_client.hget("tasks:all", task_id)
                    if task_json:
                        try:
                            task = json.loads(task_json)
                            completed_at = task.get("completed_at", 0)
                            
                            if completed_at < cutoff_time:
                                # Remove old task atomically
                                pipe = self.redis_client.pipeline()
                                pipe.multi()
                                pipe.hdel("tasks:all", task_id)
                                pipe.srem(f"index:tasks:{status}", task_id)
                                results = pipe.execute()
                                
                                if all(results):
                                    cleaned_count += 1
                                    
                        except:
                            continue
            
            # 2. Fix problematic tasks in processing states
            processing_statuses = ["processing", "downloading", "unpacking", "scanning", "ml_validation"]
            
            for status in processing_statuses:
                task_ids = self.redis_client.smembers(f"index:tasks:{status}")
                
                for task_id in task_ids:
                    task_json = self.redis_client.hget("tasks:all", task_id)
                    if task_json:
                        try:
                            task = json.loads(task_json)
                            worker_id = task.get("worker_id")
                            started_at = task.get("started_at", 0)
                            timeout_at = task.get("timeout_at", 0)
                            
                            # Problem 1: Task has no assigned worker but is in processing state
                            if not worker_id:
                                logger.warning(f"Обнаружена задача '{task_id}' в статусе '{status}' без назначенного воркера")
                                self.update_task_status(
                                    task_id, 
                                    "failed", 
                                    error="Task found in processing state without assigned worker",
                                    worker_id=None
                                )
                                fixed_count += 1
                                continue
                            
                            # Problem 2: Task assigned to inactive worker
                            # Проверяем напрямую данные воркера из Redis для более надежной проверки
                            worker_is_active = False
                            if worker_id in active_workers:
                                worker_is_active = True
                            else:
                                # Дополнительная проверка: получаем данные воркера напрямую
                                worker_json = self.redis_client.hget("workers:all", worker_id)
                                if worker_json:
                                    try:
                                        worker = json.loads(worker_json)
                                        worker_heartbeat = worker.get("last_heartbeat", 0)
                                        worker_task_id = worker.get("current_task_id")
                                        last_progress_update = worker.get("last_progress_update", 0)
                                        
                                        # Воркер активен, если:
                                        # 1. Heartbeat свежий (в пределах 15 минут) И он работает над этой задачей
                                        # 2. ИЛИ прогресс обновлялся недавно (в пределах 20 минут) И он работает над этой задачей
                                        # 3. ИЛИ задача имеет прогресс > 0 (значит воркер работал)
                                        heartbeat_fresh = (current_time - worker_heartbeat) < 900  # 15 минут
                                        progress_recent = last_progress_update > 0 and (current_time - last_progress_update) < 1200  # 20 минут
                                        task_has_progress = task.get("progress", 0) > 0
                                        
                                        if worker_task_id == task_id:
                                            if heartbeat_fresh or progress_recent or task_has_progress:
                                                worker_is_active = True
                                                # Добавляем в active_workers для последующих проверок
                                                active_workers.add(worker_id)
                                    except:
                                        pass
                            
                            if not worker_is_active:
                                logger.warning(f"Обнаружена задача '{task_id}' назначенная неактивному воркеру '{worker_id}'")
                                self.update_task_status(
                                    task_id, 
                                    "failed", 
                                    error=f"Worker '{worker_id}' is not active",
                                    worker_id=None
                                )
                                fixed_count += 1
                                continue
                            
                            # Problem 3: Task timed out
                            if timeout_at > 0 and current_time > timeout_at:
                                logger.warning(f"Обнаружена просроченная задача '{task_id}' (timeout: {timeout_at})")
                                self.update_task_status(
                                    task_id, 
                                    "failed", 
                                    error="Task timeout exceeded during cleanup",
                                    worker_id=None
                                )
                                fixed_count += 1
                                continue
                            
                            # Problem 4: Task running too long without timeout
                            if started_at > 0 and (current_time - started_at) > 3600:  # 1 hour
                                logger.warning(f"Обнаружена задача '{task_id}' выполняющаяся более часа")
                                self.update_task_status(
                                    task_id, 
                                    "failed", 
                                    error="Task running too long (over 1 hour)",
                                    worker_id=None
                                )
                                fixed_count += 1
                                continue
                                
                        except Exception as task_error:
                            logger.error(f"Ошибка обработки проблемной задачи '{task_id}': {task_error}")
                            # Remove corrupted task data
                            try:
                                pipe = self.redis_client.pipeline()
                                pipe.multi()
                                pipe.hdel("tasks:all", task_id)
                                pipe.srem(f"index:tasks:{status}", task_id)
                                pipe.execute()
                                fixed_count += 1
                                logger.warning(f"Удалена поврежденная задача '{task_id}'")
                            except:
                                pass
                            continue
            
            # 3. Fix index consistency issues (like the bug we found earlier)
            orphaned_count = self._fix_index_inconsistencies()
            fixed_count += orphaned_count
            
            if cleaned_count > 0:
                logger.info(f"Очищено '{cleaned_count}' старых задач")
            if fixed_count > 0:
                logger.info(f"Исправлено '{fixed_count}' проблемных задач")
            
            return cleaned_count + fixed_count
            
        except Exception as e:
            logger.error(f"Ошибка очистки задач: {e}")
            return 0

    def _fix_index_inconsistencies(self) -> int:
        """Fix tasks that are in multiple status indexes simultaneously"""
        try:
            fixed_count = 0
            all_statuses = ["pending", "processing", "downloading", "unpacking", "scanning", "ml_validation", "completed", "failed"]
            
            # Get all task IDs from all indexes
            task_status_map = {}
            for status in all_statuses:
                task_ids = self.redis_client.smembers(f"index:tasks:{status}")
                for task_id in task_ids:
                    if task_id not in task_status_map:
                        task_status_map[task_id] = []
                    task_status_map[task_id].append(status)
            
            # Find tasks in multiple indexes
            for task_id, statuses in task_status_map.items():
                if len(statuses) > 1:
                    # Get actual task status
                    task_json = self.redis_client.hget("tasks:all", task_id)
                    if task_json:
                        try:
                            task = json.loads(task_json)
                            actual_status = task.get("status", "unknown")
                            
                            logger.warning(f"Задача '{task_id}' найдена в индексах {statuses}, фактический статус: '{actual_status}'")
                            
                            # Remove from all wrong indexes
                            pipe = self.redis_client.pipeline()
                            pipe.multi()
                            for status in statuses:
                                if status != actual_status:
                                    pipe.srem(f"index:tasks:{status}", task_id)
                            
                            # Ensure it's in correct index
                            if actual_status in all_statuses:
                                pipe.sadd(f"index:tasks:{actual_status}", task_id)
                            
                            pipe.execute()
                            fixed_count += 1
                            
                        except:
                            # Remove corrupted task from all indexes
                            pipe = self.redis_client.pipeline()
                            pipe.multi()
                            pipe.hdel("tasks:all", task_id)
                            for status in statuses:
                                pipe.srem(f"index:tasks:{status}", task_id)
                            pipe.execute()
                            fixed_count += 1
                            logger.warning(f"Удалена поврежденная задача '{task_id}' из всех индексов")
                    else:
                        # Task doesn't exist, remove from all indexes
                        pipe = self.redis_client.pipeline()
                        pipe.multi()
                        for status in statuses:
                            pipe.srem(f"index:tasks:{status}", task_id)
                        pipe.execute()
                        fixed_count += 1
                        logger.warning(f"Удалена несуществующая задача '{task_id}' из индексов {statuses}")
            
            return fixed_count
            
        except Exception as e:
            logger.error(f"Ошибка исправления индексов: {e}")
            return 0

    def cleanup_dead_workers(self) -> int:
        """Remove dead workers and stuck workers"""
        try:
            workers_data = self.redis_client.hgetall("workers:all")
            current_time = time.time()
            cleaned_count = 0
            stuck_timeout = 1200  # 20 минут в секундах
            
            for worker_id, worker_json in workers_data.items():
                try:
                    worker = json.loads(worker_json)
                    last_heartbeat = worker.get("last_heartbeat", 0)
                    current_task_id = worker.get("current_task_id")
                    status = worker.get("status", "")
                    last_progress_update = worker.get("last_progress_update", 0)
                    
                    # Проверка 1: Нет heartbeat более 10 минут
                    if (current_time - last_heartbeat) > 600:
                        logger.warning(f"Воркер {worker_id} отписан: нет heartbeat {int((current_time - last_heartbeat) / 60)} минут")
                        self.unregister_worker(worker_id)
                        cleaned_count += 1
                        continue
                    
                    # Проверка 2: Воркер обрабатывает задачу, но прогресс не меняется более 20 минут
                    if current_task_id and status in ["scanning", "ml_validation", "downloading", "unpacking"]:
                        if last_progress_update > 0:
                            time_since_progress = current_time - last_progress_update
                            if time_since_progress > stuck_timeout:
                                logger.warning(f"Воркер {worker_id} завис на задаче {current_task_id}: прогресс не меняется {int(time_since_progress / 60)} минут")
                                # Помечаем задачу как failed
                                try:
                                    self.update_task_status(
                                        current_task_id,
                                        "failed",
                                        error=f"Worker stuck - no progress for {int(time_since_progress / 60)} minutes",
                                        worker_id=None
                                    )
                                except Exception as task_error:
                                    logger.error(f"Ошибка при пометке задачи {current_task_id} как failed: {task_error}")
                                # Отписываем воркера
                                self.unregister_worker(worker_id)
                                cleaned_count += 1
                        
                except Exception as worker_error:
                    # Invalid worker data, remove it
                    logger.warning(f"Ошибка обработки воркера {worker_id}: {worker_error}")
                    self.unregister_worker(worker_id)
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Очищено {cleaned_count} мертвых/зависших воркеров")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Ошибка очистки мертвых воркеров: {e}")
            return 0

    def cleanup_startup(self) -> bool:
        """Startup cleanup with improved safety"""
        try:
            # Clean dead workers
            self.cleanup_dead_workers()
            
            # Handle stuck processing tasks more carefully
            processing_tasks = self.redis_client.smembers("index:tasks:processing")
            if processing_tasks:
                current_time = time.time()
                recovered_count = 0
                
                for task_id in processing_tasks:
                    task_json = self.redis_client.hget("tasks:all", task_id)
                    if task_json:
                        try:
                            task = json.loads(task_json)
                            started_at = task.get("started_at", 0)
                            status = task.get("status", "")
                            
                            # Only recover tasks that started more than 10 minutes ago
                            # and are NOT already completed
                            if status != "completed" and current_time - started_at > 600:
                                self.update_task_status(
                                    task_id, 
                                    "failed", 
                                    error="Service restart - task was interrupted",
                                    worker_id=None
                                )
                                recovered_count += 1
                        except Exception as ex:
                            logger.warning(f"Не удалось обработать задачу '{task_id}': {ex}")
                            continue
                
                if recovered_count > 0:
                    logger.info(f"Восстановлено '{recovered_count}' прерванных задач")
            
            # Clear old worker commands
            command_keys = self.redis_client.keys("worker_commands:*")
            if command_keys:
                self.redis_client.delete(*command_keys)
                logger.info(f"Очищено '{len(command_keys)}' старых команд")
            
            # Verify queue consistency
            self._verify_queue_consistency()
            
            logger.info("Startup cleanup завершен")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка startup cleanup: {e}")
            return False

    def _verify_queue_consistency(self):
        """Verify and fix queue consistency issues"""
        try:
            # Get all tasks in queue
            queue_task_ids = set(self.redis_client.zrange("tasks:queue", 0, -1))
            
            # Get all pending tasks from index
            pending_task_ids = set(self.redis_client.smembers("index:tasks:pending"))
            
            # Find inconsistencies
            queue_only = queue_task_ids - pending_task_ids
            pending_only = pending_task_ids - queue_task_ids
            
            # Fix tasks in queue but not in pending index
            for task_id in queue_only:
                task = self.get_task(task_id)
                if task and task.get("status") == "pending":
                    self.redis_client.sadd("index:tasks:pending", task_id)
                    logger.info(f"Восстановлен индекс pending для задачи '{task_id}'")
                else:
                    # Remove from queue if task doesn't exist or not pending
                    self.redis_client.zrem("tasks:queue", task_id)
                    logger.info(f"Удалена несуществующая задача '{task_id}' из очереди")
            
            # Fix tasks in pending index but not in queue
            for task_id in pending_only:
                task = self.get_task(task_id)
                if task and task.get("status") == "pending":
                    # Add back to queue
                    priority = task.get("priority", 1)
                    created_at = task.get("created_at", time.time())
                    score = priority * 1000000 + created_at
                    self.redis_client.zadd("tasks:queue", {task_id: score})
                    logger.info(f"Восстановлена задача '{task_id}' в очереди")
                else:
                    # Remove from pending index
                    self.redis_client.srem("index:tasks:pending", task_id)
                    logger.info(f"Удалена несуществующая задача '{task_id}' из индекса pending")
            
            if queue_only or pending_only:
                logger.info(f"Исправлены несоответствия очереди: 'queue_only={len(queue_only)}', 'pending_only={len(pending_only)}'")
                
        except Exception as e:
            logger.error(f"Ошибка проверки консистентности очереди: {e}")


def get_redis_client() -> RedisClient:
    """Get Redis client singleton instance"""
    return RedisClient.get_instance()