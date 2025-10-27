# logging_config.py
import logging
from logging.handlers import RotatingFileHandler
from colorlog import ColoredFormatter
import time
from collections import defaultdict
import re

MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5

class RateLimitFilter(logging.Filter):
    """
    Фильтр для ограничения частоты логов по эндпоинтам.
    Использует regex-паттерны для гибкого поиска.
    """
    def __init__(self, cooldown: int = 10, patterns=None):
        super().__init__()
        self.cooldown = cooldown
        self.patterns = [re.compile(p) for p in (patterns or [])]
        self.last_logged = defaultdict(float)

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()

        for pattern in self.patterns:
            if pattern.search(msg):
                now = time.time()
                key = pattern.pattern
                if now - self.last_logged[key] >= self.cooldown:
                    self.last_logged[key] = now
                    return True   # логируем
                else:
                    return False  # пропускаем

        return True


def setup_logging(worker_id: str = None, log_file: str = "secrets_scanner_service.log"):
    """
    Настройка логирования с поддержкой colorlog для консоли.
    Если worker_id указан, добавляется префикс [WORKER-<id>].
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Удаляем существующие обработчики
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    prefix = f"[WORKER-{worker_id}] " if worker_id else ""

    # -------------------
    # Файл с ротацией
    # -------------------
    file_formatter = logging.Formatter(
        f"%(asctime)s - %(name)s - %(levelname)s - {prefix}%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler = RotatingFileHandler(
        log_file, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # -------------------
    # Консоль с цветами
    # -------------------
    console_formatter = ColoredFormatter(
        fmt=f"[%(log_color)s%(levelname)s%(reset)s] {prefix}%(message)s",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        }
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # -------------------
    # Настройка фильтров для шумных эндпоинтов
    # -------------------
    
    # Эндпоинты которые нужно фильтровать (подстроки для поиска в логах)
    noisy_patterns = [
        r"/secret_scanner/logging/logs",
        r"/secret_scanner/logging/microservice-logs",
        r"/secret_scanner/logging/user-actions-logs",
        r"/secret_scanner/api/admin/service[-_]stats",  # service_stats или service-stats
        r"/secret_scanner/api/admin/tasks",
        r"/secret_scanner/api/admin/workers-status",
        r"/admin/service[-_]stats",
        r"/admin/tasks",        # с любыми query (?limit=50, ?status=...)
        r"/admin/workers",
        r"/task_status"
    ]

    rate_filter = RateLimitFilter(cooldown=20, patterns=noisy_patterns)

    logging.getLogger("uvicorn.access").addFilter(rate_filter)
    logging.getLogger("uvicorn.error").addFilter(rate_filter)
    logging.getLogger("httpx").addFilter(rate_filter)
    logging.getLogger("httpcore").addFilter(rate_filter)
    logging.getLogger("requests").addFilter(rate_filter)
    logging.getLogger("aiohttp").addFilter(rate_filter)

    return logger