"""
Кэш скачанных репозиториев. Хранение 7 дней по short commit.
Используется только для сканов по URL (не для local_scan ZIP).
"""
import os
import re
import time
import shutil
import logging

logger = logging.getLogger("repo_cache")

# Жёстко заданная папка кэша (относительно корня проекта)
_REPO_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "repo_cache"
)
CACHE_RETENTION_DAYS = 7
LAST_USED_FILENAME = ".last_used"
LOCK_SUFFIX = ".lock"


def get_cache_dir():
    """Возвращает путь к корню кэша."""
    return _REPO_CACHE_DIR


def get_short_commit(task: dict) -> str:
    """
    Извлекает short commit из задачи для использования как ключ кэша.
    Для DevZone используется ref или commit, для остальных — commit.
    """
    commit = task.get("commit") or ""
    ref = task.get("ref") or ""
    value = (commit or ref or "unknown").strip()
    if len(value) >= 8:
        value = value[:8]
    # Только буквы, цифры, подчёркивание (безопасно для имени папки)
    value = re.sub(r"[^a-zA-Z0-9_]", "_", value)
    return value or "unknown"


def get_cache_path(short_commit: str) -> str:
    """Путь к папке кэша для данного short commit."""
    return os.path.join(_REPO_CACHE_DIR, short_commit)


def get_lock_path(short_commit: str) -> str:
    """Путь к файлу блокировки для данного short commit."""
    return os.path.join(_REPO_CACHE_DIR, short_commit + LOCK_SUFFIX)


def _last_used_path(cache_path: str) -> str:
    return os.path.join(cache_path, LAST_USED_FILENAME)


def is_cache_valid(cache_path: str) -> bool:
    """
    Проверяет, что кэш существует, в нём есть содержимое и возраст не больше CACHE_RETENTION_DAYS.
    """
    if not os.path.isdir(cache_path):
        return False
    last_used_file = _last_used_path(cache_path)
    if not os.path.isfile(last_used_file):
        return False
    try:
        with open(last_used_file, "r", encoding="utf-8") as f:
            t = float(f.read().strip())
    except (ValueError, OSError):
        return False
    if time.time() - t > CACHE_RETENTION_DAYS * 86400:
        return False
    # Есть ли хотя бы один файл (не только .last_used)
    for name in os.listdir(cache_path):
        if name != LAST_USED_FILENAME:
            return True
    return False


def touch_cache_used(cache_path: str) -> None:
    """Обновляет время последнего использования кэша."""
    try:
        last_used_file = _last_used_path(cache_path)
        with open(last_used_file, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
    except OSError as e:
        logger.warning(f"Не удалось обновить .last_used в {cache_path}: {e}")


def acquire_lock(lock_path: str, timeout_seconds: float = 300.0):
    """
    Контекстный менеджер: блокировка по файлу для создания записи кэша.
    Ждёт до timeout_seconds. На Windows fcntl может быть недоступен — тогда используем только создание файла.
    """
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    fd = None

    class Lock:
        def __enter__(self):
            nonlocal fd
            start = time.time()
            while True:
                try:
                    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                    return self
                except FileExistsError:
                    pass
                if time.time() - start >= timeout_seconds:
                    raise TimeoutError(f"Не удалось захватить lock за {timeout_seconds}с: {lock_path}")
                time.sleep(0.5)

        def __exit__(self, *args):
            nonlocal fd
            if fd is not None:
                try:
                    os.close(fd)
                    os.remove(lock_path)
                except OSError:
                    pass

    return Lock()


def move_extracted_to_cache(extracted_path: str, cache_path: str) -> bool:
    """
    Переносит содержимое extracted_path в cache_path.
    extracted_path — папка с файлами репо (как после download_repo).
    """
    try:
        os.makedirs(cache_path, exist_ok=True)
        for name in os.listdir(extracted_path):
            if name == LAST_USED_FILENAME:
                continue
            src = os.path.join(extracted_path, name)
            dst = os.path.join(cache_path, name)
            if os.path.exists(dst):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                else:
                    os.remove(dst)
            shutil.move(src, dst)
        touch_cache_used(cache_path)
        return True
    except Exception as e:
        logger.error(f"Ошибка переноса в кэш {extracted_path} -> {cache_path}: {e}")
        return False


def cleanup_old_entries() -> int:
    """
    Удаляет из кэша папки старше CACHE_RETENTION_DAYS.
    Возвращает количество удалённых записей.
    """
    if not os.path.isdir(_REPO_CACHE_DIR):
        return 0
    removed = 0
    cutoff = time.time() - CACHE_RETENTION_DAYS * 86400
    for name in os.listdir(_REPO_CACHE_DIR):
        if name.endswith(LOCK_SUFFIX):
            continue
        path = os.path.join(_REPO_CACHE_DIR, name)
        if not os.path.isdir(path):
            continue
        last_used_file = _last_used_path(path)
        try:
            if os.path.isfile(last_used_file):
                with open(last_used_file, "r", encoding="utf-8") as f:
                    t = float(f.read().strip())
            else:
                t = 0
        except (ValueError, OSError):
            t = 0
        if t < cutoff:
            try:
                shutil.rmtree(path)
                removed += 1
                logger.info(f"Удалена устаревшая запись кэша: {path}")
            except OSError as e:
                logger.warning(f"Не удалось удалить {path}: {e}")
    return removed
