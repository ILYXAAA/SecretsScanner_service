import os
import sys
import time
import signal
import logging
import asyncio
import tempfile
import uuid
import multiprocessing
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.redis_client import get_redis_client
from app.repo_utils import download_repo, delete_dir
from app.repo_cache import (
    get_short_commit,
    get_cache_path,
    get_lock_path,
    is_cache_valid,
    touch_cache_used,
    acquire_lock,
    move_extracted_to_cache,
)
from app.scanner import scan_repo_without_callback
from app.model_loader import filter_secrets_in_process
import aiohttp
import json
import gzip
import base64
import zipfile
from app.logging_config import setup_logging

load_dotenv()

class Worker:
    def __init__(self, worker_id: Optional[str] = None):
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.pid = os.getpid()
        self.redis_client = get_redis_client()
        self.running = False
        self.paused = False
        self.current_task = None
        self.model_loaded = False
        self.model_version = None
        self.last_heartbeat_sent = 0
        self.startup_complete = False
        
        # Setup logging with worker ID prefix
        self.logger = setup_logging(self.worker_id)
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Получен сигнал '{signum}', начинаю graceful shutdown")
        self.running = False

    def load_model(self):
        """Load ML model in worker process"""
        try:
            self.logger.info("Загружаю ML модель...")
            start_time = time.time()
            
            from app.model_loader import get_model_instance
            from app.model_version_manager import get_current_model_version
            
            # Получаем версию модели при старте воркера и сохраняем её
            version = get_current_model_version()
            if not version:
                raise ValueError("Не удалось определить версию модели")
            
            self.model_version = version
            self.logger.info(f"Используется версия модели: {version}")
            
            # Загружаем модель с конкретной версией, чтобы воркер всегда использовал ту же версию
            get_model_instance(version=version)
            
            load_time = time.time() - start_time
            self.model_loaded = True
            self.logger.info(f"ML модель загружена за {load_time:.2f}с")
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки ML модели: {e}")
            raise
    
    def should_send_heartbeat(self, force_interval: int = 10) -> bool:
        """Проверяет, нужно ли отправить heartbeat (каждые N секунд)"""
        current_time = time.time()
        return (current_time - self.last_heartbeat_sent) >= force_interval

    def get_current_status(self) -> str:
        """Get current worker status based on state"""
        if not self.startup_complete:
            return "starting"
        elif self.paused:
            return "paused"
        elif self.current_task:
            # Return specific task status if available
            task_status = self.current_task.get("status", "processing")
            if task_status in ["downloading", "unpacking", "scanning", "ml_validation"]:
                return task_status
            return "processing"
        else:
            return "free"

    def update_task_progress(self, progress: int, detail: str = None):
        """Update current task progress"""
        if self.current_task:
            task_id = self.current_task["task_id"]
            redis_client = get_redis_client()
            redis_client.update_task_progress(task_id, progress, detail)

    def send_heartbeat(self, force_status: str = None, force: bool = False, progress: int = None, progress_detail: str = None):
        """Send heartbeat to Redis with proper status management and progress"""
        try:
            current_time = time.time()
            heartbeat_interval = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "20"))
            
            # Rate limit heartbeat unless forced or enough time passed
            if not force and (current_time - self.last_heartbeat_sent) < heartbeat_interval * 0.5:
                return
            
            # Determine status to send
            if force_status:
                status = force_status
            else:
                status = self.get_current_status()
            
            current_task_id = self.current_task["task_id"] if self.current_task else None
            
            # Update both task progress and worker heartbeat
            if self.current_task and progress is not None:
                self.update_task_progress(progress, progress_detail)
            
            success = self.redis_client.update_worker_heartbeat(
                self.worker_id, 
                status, 
                current_task_id, 
                progress, 
                progress_detail,
                self.model_version
            )
            
            if success:
                self.last_heartbeat_sent = current_time
                self.logger.debug(f"Heartbeat отправлен: '{status}'" + (f" (прогресс: {progress}%)" if progress is not None else ""))
            else:
                self.logger.warning(f"Не удалось отправить heartbeat, статус: '{status}'")
                
        except Exception as e:
            self.logger.error(f"Ошибка отправки heartbeat: {e}")

    def send_heartbeat_if_needed(self, status: str = None, force_interval: int = 10, progress: int = None, progress_detail: str = None):
        """Отправляет heartbeat если прошло достаточно времени"""
        if self.should_send_heartbeat(force_interval):
            if status:
                self.send_heartbeat(status, force=True, progress=progress, progress_detail=progress_detail)
            else:
                self.send_heartbeat(force=True, progress=progress, progress_detail=progress_detail)

    def check_commands(self):
        """Check for commands from Redis and handle state changes"""
        try:
            command = self.redis_client.get_worker_command(self.worker_id)
            if command:
                self.logger.warning(f"Получена команда: '{command}'")
                
                if command == "shutdown":
                    self.running = False
                elif command == "pause":
                    if not self.paused:
                        self.paused = True
                        self.logger.warning("Воркер приостановлен")
                        self.send_heartbeat("paused", force=True)
                elif command == "resume":
                    if self.paused:
                        self.paused = False
                        self.logger.warning("Воркер возобновлен")
                        self.send_heartbeat("free", force=True)
                elif command == "restart":
                    self.logger.warning("Перезапуск воркера...")
                    self.running = False
                    
        except Exception as e:
            self.logger.error(f"Ошибка проверки команд: {e}")

    def check_task_timeout(self, task: dict) -> bool:
        """Check if current task has timed out"""
        try:
            current_time = time.time()
            timeout_at = task.get("timeout_at", 0)
            
            if current_time > timeout_at:
                self.logger.warning(f"Задача '{task['task_id']}' превысила таймаут, прерываю обработку")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Ошибка проверки таймаута: {e}")
            return False

    def cleanup_uploaded_zip(self, zip_file_path: str):
        """Clean up uploaded ZIP file"""
        try:
            if zip_file_path and os.path.exists(zip_file_path):
                os.remove(zip_file_path)
                self.logger.info(f"Удален ZIP файл: '{zip_file_path}'")
        except Exception as e:
            self.logger.warning(f"Ошибка удаления ZIP файла '{zip_file_path}': {e}")

    def cleanup_temp_directory(self, temp_dir: str):
        """Safely clean up temp directory for this specific task"""
        try:
            if temp_dir and os.path.exists(temp_dir):
                # Make sure we're only deleting our worker's temp dir
                if f"worker-{self.worker_id}-" in temp_dir:
                    delete_dir(temp_dir)
                    self.logger.info(f"Удалена временная папка: '{temp_dir}'")
                else:
                    self.logger.warning(f"Отказ удаления папки '{temp_dir}' - не принадлежит этому воркеру")
        except Exception as e:
            self.logger.warning(f"Ошибка удаления временной папки '{temp_dir}': {e}")

    async def download_repository(self, task: dict) -> tuple[str, str, str]:
        """Download repository for regular scan. Returns (repo_path, temp_dir, status). Uses repo cache (7 days)."""
        temp_dir = None
        try:
            self.send_heartbeat("downloading", force=True)
            
            repo_url = task["repo_url"]
            commit = task["commit"]
            ref_type = task.get("ref_type")
            ref = task.get("ref")
            
            short_commit = get_short_commit(task)
            cache_path = get_cache_path(short_commit)
            
            # Проверка кэша: если есть актуальная запись — используем её
            if is_cache_valid(cache_path):
                touch_cache_used(cache_path)
                self.logger.info(f"Кэш репозитория (commit {short_commit}), пропуск скачивания ('{task['task_id']}')")
                return cache_path, None, "Success"
            
            is_devzone = "devzone.local" in repo_url.lower()
            if is_devzone:
                self.logger.info(f"Скачиваю DevZone репозиторий '{repo_url}' -> '{ref_type}':'{ref}'... ('{task['task_id']}')")
            else:
                commit_short = commit[:8] if len(commit) >= 8 else commit
                self.logger.info(f"Скачиваю репозиторий '{repo_url}' -> '{commit_short}'... ('{task['task_id']}')")
            
            if self.check_task_timeout(task):
                return "", "", "Task timeout during download"
            
            temp_dir = tempfile.mkdtemp(
                dir=os.getenv("TEMP_DIR", "/tmp"),
                prefix=f"worker-{self.worker_id}-"
            )
            
            try:
                download_timeout = 1800 if is_devzone else 600
                
                if is_devzone:
                    extracted_path, status, scanned_commit = await asyncio.wait_for(
                        download_repo(repo_url, ref or commit, temp_dir, worker_instance=self, ref_type=ref_type),
                        timeout=download_timeout
                    )
                else:
                    extracted_path, status, scanned_commit = await asyncio.wait_for(
                        download_repo(repo_url, commit, temp_dir, worker_instance=self),
                        timeout=download_timeout
                    )
            except asyncio.TimeoutError:
                timeout_msg = f"Download timeout exceeded ({download_timeout // 60} minutes)"
                return "", temp_dir, timeout_msg
            
            if not extracted_path:
                return "", temp_dir, f"Download failed: {status}"
            
            # Обновляем commit в задаче, если получили актуальное значение
            if scanned_commit:
                self.logger.info(f"Обновляю commit в задаче: '{commit[:8]}..' -> '{scanned_commit[:8]}..' ('{task['task_id']}')")
                self.redis_client.update_task_status(
                    task["task_id"],
                    task["status"],
                    commit=scanned_commit
                )
                task["commit"] = scanned_commit
            
            # Кладём в кэш под блокировкой (другой воркер мог уже заполнить)
            try:
                with acquire_lock(get_lock_path(short_commit)):
                    if is_cache_valid(cache_path):
                        self.cleanup_temp_directory(temp_dir)
                        touch_cache_used(cache_path)
                        self.logger.info(f"Кэш репозитория (commit {short_commit}) заполнен другим воркером ('{task['task_id']}')")
                        return cache_path, None, "Success"
                    if move_extracted_to_cache(extracted_path, cache_path):
                        self.cleanup_temp_directory(temp_dir)
                        temp_dir = None
                        self.logger.info(f"Репозиторий сохранён в кэш '{cache_path}' ('{task['task_id']}')")
                        return cache_path, None, "Success"
            except TimeoutError as e:
                self.logger.warning(f"Таймаут блокировки кэша: {e}, используем временную папку")
            
            # Без кэша: возвращаем путь к распакованному репо (temp_dir будет очищен в finally)
            self.logger.info(f"Репозиторий скачан успешно в '{extracted_path}' ('{task['task_id']}')")
            return extracted_path, temp_dir, "Success"
            
        except Exception as e:
            self.logger.error(f"Ошибка скачивания репозитория: {e} ('{task['task_id']}')")
            return "", temp_dir or "", str(e)

    async def extract_zip_file(self, task: dict) -> tuple[str, str, str]:
        """Extract ZIP file for local scan. Returns (repo_path, temp_dir, status)"""
        temp_dir = None
        try:
            self.redis_client.update_task_status(task["task_id"], "unpacking")
            self.send_heartbeat("unpacking", force=True)
            
            project_name = task["project_name"]
            original_data = task["original_data"]
            zip_file_path = original_data.get("zip_file_path")
            
            if not zip_file_path:
                return "", "", "ZIP file path not found in task data"
            
            if not os.path.exists(zip_file_path):
                return "", "", f"ZIP file not found: {zip_file_path}"
            
            self.logger.info(f"Распаковываю ZIP файл для '{project_name}': '{zip_file_path}' ('{task['task_id']}')")
            
            if self.check_task_timeout(task):
                return "", "", "Task timeout during extraction"
            
            # Create temp directory for this specific task
            temp_dir = tempfile.mkdtemp(
                dir=os.getenv("TEMP_DIR", "/tmp"),
                prefix=f"worker-{self.worker_id}-"
            )
            
            repo_path = os.path.join(temp_dir, "extracted")
            os.makedirs(repo_path, exist_ok=True)
            
            # Extract ZIP with size limits
            max_extract_size = 2 * 1024 * 1024 * 1024 * 3  # 6 GB
            extracted_size = 0
            
            try:
                with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
                    # Check total uncompressed size
                    for info in zip_file.infolist():
                        extracted_size += info.file_size
                        if extracted_size > max_extract_size:
                            return "", temp_dir, f"ZIP archive too large (>{max_extract_size // (1024*1024)}MB)"
                    
                    # Извлечение файлов с периодической отправкой heartbeat и прогресса
                    files_list = zip_file.infolist()
                    total_files = len(files_list)
                    
                    self.logger.info(f"Начинаю извлечение {total_files} файлов из ZIP ('{task['task_id']}')")
                    
                    for i, file_info in enumerate(files_list):
                        # Вычисляем прогресс
                        progress = int((i / total_files) * 100) if total_files > 0 else 0
                        progress_detail = f"Извлечено {i} из {total_files} файлов"
                        
                        # Отправляем heartbeat каждые 10 секунд с прогрессом
                        self.send_heartbeat_if_needed("unpacking", 10, progress, progress_detail)
                        
                        # Проверяем timeout задачи
                        if self.check_task_timeout(task):
                            raise Exception("Task timeout during ZIP extraction")
                        
                        # Извлекаем отдельный файл
                        try:
                            zip_file.extract(file_info, repo_path)
                        except Exception as e:
                            self.logger.warning(f"Ошибка извлечения файла '{file_info.filename}': {e} ('{task['task_id']}')")
                            continue
                    
                    # Финальный прогресс
                    self.send_heartbeat("unpacking", force=True, progress=100, progress_detail=f"Извлечено {total_files} файлов")
                    
                    self.logger.info(f"Распаковка завершена: {total_files} файлов ('{task['task_id']}')")
                        
            except zipfile.BadZipFile:
                return "", temp_dir, "Invalid or corrupted ZIP file"
            except Exception as e:
                return "", temp_dir, f"ZIP extraction error: {e}"
            
            # Clean up the original ZIP file after successful extraction
            self.cleanup_uploaded_zip(zip_file_path)
            
            self.logger.info(f"ZIP файл распакован успешно ('{extracted_size // 1024}KB') ('{task['task_id']}')")
            return repo_path, temp_dir, "Success"
            
        except Exception as e:
            self.logger.error(f"Ошибка распаковки ZIP: {e} ('{task['task_id']}')")
            return "", temp_dir or "", str(e)
    
    async def scan_repository(self, task: dict, repo_path: str) -> tuple[list, dict]:
        """Scan repository for secrets"""
        try:
            self.redis_client.update_task_status(task["task_id"], "scanning")
            self.send_heartbeat("scanning", force=True)
            
            project_name = task["project_name"]
            self.logger.info(f"Начинаю сканирование '{project_name}' ('{task['task_id']}')")
            start_time = time.time()
            
            if self.check_task_timeout(task):
                raise Exception("Task timeout during scanning")
            
            # Create request object from original data
            from app.models import ScanRequest
            original_data = task["original_data"]
            request = ScanRequest(**original_data["request"])
            
            # Расширенный контекст для DevZone: 5 строк до и после секрета
            is_devzone = "devzone.local" in (task.get("repo_url") or "").lower()
            CONTEXT_LINES_BEFORE = 7
            CONTEXT_LINES_AFTER = 7
            context_before = CONTEXT_LINES_BEFORE if is_devzone else 0
            context_after = CONTEXT_LINES_AFTER if is_devzone else 0

            # Perform scanning with timeout and worker instance for heartbeat
            try:
                scan_result = await asyncio.wait_for(
                    scan_repo_without_callback(
                        request, repo_path, project_name, 0, [], worker_instance=self,
                        context_lines_before=context_before, context_lines_after=context_after
                    ),
                    timeout=900  # 15 minutes max for scanning
                )
                results, files_excluded, all_files_count, skipped_files, detected_languages, detected_frameworks = scan_result
            except asyncio.TimeoutError:
                raise Exception("Scanning timeout exceeded (15 minutes)")
            
            scan_time = time.time() - start_time
            self.logger.info(f"Сканирование завершено за {scan_time:.2f}с. ID: '{task['task_id']}'. Найдено: '{len(results)}' потенциальных секретов")
            
            if self.check_task_timeout(task):
                raise Exception("Task timeout before ML filtering")
            
            # Apply ML filtering with worker instance for heartbeat
            self.redis_client.update_task_status(task["task_id"], "ml_validation")
            self.send_heartbeat("ml_validation", force=True)
            
            self.logger.info(f"Применяю ML фильтрацию для '{project_name}' ('{task['task_id']}')")
            try:
                filtered_results = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, filter_secrets_in_process, project_name, results, self
                    ),
                    timeout=300  # 5 minutes max for ML filtering
                )
            except asyncio.TimeoutError:
                raise Exception("ML filtering timeout exceeded (5 minutes)")
            
            total_time = time.time() - start_time
            self.logger.info(f"Обработка '{project_name}' завершена за {total_time:.2f}с. Финальных секретов: '{len(filtered_results)}' ('{task['task_id']}')")
            
            scan_data = {
                "results": filtered_results,
                "files_excluded": files_excluded,
                "all_files_count": all_files_count,
                "skipped_files": skipped_files,
                "detected_languages": detected_languages,
                "detected_frameworks": detected_frameworks,
                "scan_time": scan_time,
                "total_time": total_time
            }
            
            return filtered_results, scan_data
            
        except Exception as e:
            self.logger.error(f"Ошибка сканирования: {e} ('{task['task_id']}')")
            raise

    async def send_callback(self, task: dict, payload: dict):
        """Send callback with retry logic"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                project_name = payload.get("ProjectName", "unknown")
                results_count = len(payload.get("Results", []))
                callback_url = task["callback_url"]
                
                # Serialize and compress payload
                payload_json = json.dumps(payload, ensure_ascii=False)
                original_size = len(payload_json.encode('utf-8'))
                
                compressed_data = gzip.compress(payload_json.encode('utf-8'))
                compressed_size = len(compressed_data)
                compressed_b64 = base64.b64encode(compressed_data).decode('ascii')
                
                compressed_payload = {
                    "compressed": True,
                    "data": compressed_b64,
                    "original_size": original_size,
                    "compressed_size": compressed_size
                }
                
                compressed_json = json.dumps(compressed_payload)
                final_size = len(compressed_json.encode('utf-8'))
                compression_ratio = (1 - final_size / original_size) * 100 if original_size > 0 else 0
                
                self.logger.info(f"Отправляю callback для '{project_name}'. Результатов: '{results_count}'. Сжатие: '{compression_ratio:.1f}'% (попытка {attempt + 1}) ('{task['task_id']}')")
                
                headers = {
                    'Content-Type': 'application/json; charset=utf-8',
                    'User-Agent': 'SecretsScanner-Worker/2.0',
                    'X-Compressed': 'gzip-base64'
                }
                
                timeout = aiohttp.ClientTimeout(total=120, connect=30, sock_read=60)
                
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(callback_url, data=compressed_json, headers=headers) as response:
                        if response.status == 200:
                            self.logger.info(f"Callback успешно отправлен для '{project_name}' ('{task['task_id']}')")
                            return
                        else:
                            self.logger.error(f"Callback failed: HTTP '{response.status}' ('{task['task_id']}')")
                            response_text = await response.text()
                            self.logger.error(f"Response: {response_text[:500]} ('{task['task_id']}')")
                            
                            if attempt < max_retries - 1:
                                self.logger.info(f"Retry callback через '{retry_delay}' секунд... ('{task['task_id']}')")
                                await asyncio.sleep(retry_delay)
                                retry_delay *= 2
                            else:
                                raise Exception(f"Callback failed after '{max_retries}' attempts: HTTP '{response.status}' ('{task['task_id']}')")
                
            except asyncio.TimeoutError:
                self.logger.error(f"Callback timeout на попытке '{attempt + 1}' ('{task['task_id']}')")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    raise Exception(f"Callback timeout after '{max_retries}' attempts ('{task['task_id']}')")
            except Exception as e:
                self.logger.error(f"Ошибка отправки callback (попытка '{attempt + 1}'): {e} ('{task['task_id']}')")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    raise

    async def process_task(self, task: dict):
        """Process a single task"""
        temp_dir = None
        task_id = task["task_id"]
        execution_start_time = time.time()
        uploaded_zip_path = None
        
        try:
            self.current_task = task
            task_type = task["task_type"]
            project_name = task["project_name"]
            
            self.logger.info(f"Начинаю обработку задачи: '{project_name}' (тип: {task_type}, ID: '{task_id}')")
            
            # Get repo path based on task type
            if task_type == "scan":
                # Regular repository scan
                repo_path, temp_dir, status = await self.download_repository(task)
                
            elif task_type == "local_scan":
                # Local ZIP scan - store ZIP path for cleanup if needed
                original_data = task["original_data"]
                uploaded_zip_path = original_data.get("zip_file_path")
                
                repo_path, temp_dir, status = await self.extract_zip_file(task)
                
            else:
                raise ValueError(f"Unknown task type: {task_type}")
            
            if not repo_path:
                raise Exception(f"Failed to prepare repository: {status}")
            
            # Scan repository
            if self.check_task_timeout(task):
                raise Exception("Task timeout after preparation")
            
            results, scan_data = await self.scan_repository(task, repo_path)
            
            if self.check_task_timeout(task):
                raise Exception("Task timeout after scanning")
            
            # Prepare callback payload
            original_data = task["original_data"]
            request_data = original_data["request"]
            
            payload = {
                "Status": "completed",
                "Message": "Scanned Successfully",
                "ProjectName": project_name,
                "ProjectRepoUrl": request_data["RepoUrl"],
                "RepoCommit": task.get("commit", request_data.get("Ref", "local")),
                "Results": scan_data["results"],
                "FilesExcluded": scan_data["files_excluded"],
                "AllFiles": scan_data["all_files_count"],
                "SkippedFiles": scan_data["skipped_files"],
                "DetectedLanguages": scan_data["detected_languages"],
                "DetectedFrameworks": scan_data["detected_frameworks"]
            }
            
            # Send callback
            await self.send_callback(task, payload)
            
            # Calculate execution time and mark as completed
            execution_time = time.time() - execution_start_time
            
            self.redis_client.update_task_status(
                task_id,
                "completed",
                results_count=len(scan_data["results"]),
                execution_time=execution_time
            )
            
            # Update worker stats
            self.update_worker_stats(completed=1)
            
            self.logger.info(f"Задача '{task_id}' успешно завершена за {execution_time:.2f}с ('{project_name}')")
            
        except Exception as e:
            error_msg = str(e)
            execution_time = time.time() - execution_start_time
            
            self.logger.error(f"Ошибка обработки задачи: {error_msg} (время: {execution_time:.2f}с) ('{task_id}') ")
            
            # Mark as failed
            self.redis_client.update_task_status(
                task_id,
                "failed",
                error=error_msg,
                worker_id=None,
                execution_time=execution_time
            )
            
            # Update worker stats
            self.update_worker_stats(failed=1)
            
            # Send error callback if possible
            try:
                if self.current_task and "original_data" in self.current_task:
                    original_data = self.current_task["original_data"]
                    request_data = original_data["request"]
                    
                    error_payload = {
                        "Status": "Error",
                        "Message": error_msg,
                        "ProjectName": request_data.get("ProjectName", "unknown")
                    }
                    
                    try:
                        await asyncio.wait_for(
                            self.send_callback(self.current_task, error_payload),
                            timeout=60
                        )
                    except:
                        self.logger.warning(f"Не удалось отправить error callback ('{task_id}')")
                        
            except Exception as callback_error:
                self.logger.error(f"Ошибка отправки error callback: {callback_error} ('{project_name}') ('{task_id}')")
                
        finally:
            # Cleanup resources - only clean up our specific temp dir
            try:
                # Clean up temp directory (only our worker's specific dir)
                if temp_dir:
                    self.cleanup_temp_directory(temp_dir)
                
                # Clean up uploaded ZIP file if it still exists (error case)
                if uploaded_zip_path:
                    self.cleanup_uploaded_zip(uploaded_zip_path)
                    
            except Exception as cleanup_error:
                self.logger.warning(f"Ошибка cleanup: {cleanup_error} ('{project_name}') ('{task_id}')")
            
            # Reset current task and update status appropriately
            self.current_task = None
            # Send status based on current worker state (paused/free)
            self.send_heartbeat(force=True)

    def update_worker_stats(self, completed: int = 0, failed: int = 0):
        """Update worker completion statistics"""
        try:
            worker_json = self.redis_client.redis_client.hget("workers:all", self.worker_id)
            if worker_json:
                worker = json.loads(worker_json)
                worker["tasks_completed"] = worker.get("tasks_completed", 0) + completed
                worker["tasks_failed"] = worker.get("tasks_failed", 0) + failed
                
                self.redis_client.redis_client.hset("workers:all", self.worker_id, json.dumps(worker, ensure_ascii=False))
        except Exception as e:
            self.logger.error(f"Ошибка обновления статистики воркера: {e}")

    async def heartbeat_background_task(self):
        """Фоновая задача для периодической отправки heartbeat независимо от основной работы"""
        heartbeat_interval = 30  # Отправляем heartbeat каждые 30 секунд
        while self.running:
            try:
                await asyncio.sleep(heartbeat_interval)
                if self.running:
                    # Отправляем heartbeat с текущим статусом
                    self.send_heartbeat(force=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Ошибка в heartbeat background task: {e}")
                await asyncio.sleep(10)  # При ошибке ждем меньше перед повтором

    async def run(self):
        """Main worker loop"""
        startup_start = time.time()
        
        try:
            # Register with Redis
            if not self.redis_client.register_worker(self.worker_id, self.pid):
                raise Exception("Failed to register worker with Redis")
            
            # Send initial heartbeat
            self.send_heartbeat("starting", force=True)
            
            # Load ML model
            self.load_model()
            
            # Update worker registration with model version
            if self.model_version:
                self.redis_client.update_worker_model_version(self.worker_id, self.model_version)
            
            # Mark startup as complete
            self.startup_complete = True
            self.running = True
            
            # Send ready heartbeat
            self.send_heartbeat("free", force=True)
            
            startup_time = time.time() - startup_start
            self.logger.info(f"Воркер '{self.worker_id}' готов к работе (запуск за {startup_time:.2f}с)")
            
            # Запускаем фоновую задачу для heartbeat
            heartbeat_task = None
            try:
                heartbeat_task = asyncio.create_task(self.heartbeat_background_task())
            except Exception as e:
                self.logger.error(f"Ошибка создания heartbeat task: {e}")
            
            # Main work loop
            consecutive_errors = 0
            max_consecutive_errors = 5
            
            try:
                while self.running:
                    try:
                        # Send periodic heartbeat (respects pause state)
                        self.send_heartbeat()
                        
                        # Check for commands
                        self.check_commands()
                        if not self.running:
                            break
                        
                        # Skip getting tasks if paused
                        if self.paused:
                            await asyncio.sleep(2)
                            continue
                        
                        # Get task from Redis
                        task_data = self.redis_client.pop_task(self.worker_id, timeout=2)
                        
                        if task_data:
                            # Reset error counter on successful task retrieval
                            consecutive_errors = 0
                            await self.process_task(task_data)
                        else:
                            # No tasks available, short sleep
                            await asyncio.sleep(1)
                        
                        if not self.running:
                            break
                        
                    except KeyboardInterrupt:
                        self.logger.info("Получен 'Ctrl+C', завершаю работу")
                        break
                        
                    except Exception as e:
                        consecutive_errors += 1
                        self.logger.error(f"Ошибка в основном цикле worker (#{consecutive_errors}): {e}")
                        
                        if consecutive_errors >= max_consecutive_errors:
                            self.logger.error(f"Слишком много ошибок подряд ({consecutive_errors}), завершаю работу")
                            break
                        
                        # Progressive backoff on errors
                        await asyncio.sleep(min(consecutive_errors * 2, 30))
                        
                        # Try to send error heartbeat
                        try:
                            self.send_heartbeat("error", force=True)
                        except:
                            pass
                            
                        if not self.running:
                            break
            finally:
                # Останавливаем фоновую задачу heartbeat
                if heartbeat_task:
                    heartbeat_task.cancel()
                    try:
                        await heartbeat_task
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        self.logger.warning(f"Ошибка при остановке heartbeat task: {e}")
            
        except Exception as e:
            self.logger.error(f"Критическая ошибка worker: {e}")
            
            try:
                self.send_heartbeat("crashed", force=True)
            except:
                pass
                
        finally:
            # Cleanup
            try:
                # Mark any current task as failed
                if self.current_task:
                    task_id = self.current_task.get("task_id")
                    if task_id:
                        self.redis_client.update_task_status(
                            task_id,
                            "failed",
                            error="Worker shutdown",
                            worker_id=None
                        )
                
                # Unregister from Redis
                self.redis_client.unregister_worker(self.worker_id)
                self.logger.warning(f"Worker '{self.worker_id}' завершил работу")
                
            except Exception as cleanup_error:
                self.logger.error(f"Ошибка при cleanup: {cleanup_error}")


def worker_main(worker_id: Optional[str] = None):
    """Entry point for worker process"""
    try:
        worker = Worker(worker_id)
        asyncio.run(worker.run())
    except Exception as e:
        print(f"Worker startup error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Allow starting worker standalone
    import argparse
    
    parser = argparse.ArgumentParser(description='Secrets Scanner Worker v2')
    parser.add_argument('--worker-id', help='Worker ID (auto-generated if not provided)')
    args = parser.parse_args()
    
    worker_main(args.worker_id)