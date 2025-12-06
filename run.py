import uvicorn
import os
import sys
import signal
import multiprocessing
import logging
from pathlib import Path
import ipaddress
from cryptography.fernet import Fernet
import secrets
from dotenv import load_dotenv, set_key
import redis
import time
from app.logging_config import setup_logging

os.system("") # Для цветной консоли

# Configure colored logging
class ColoredFormatter(logging.Formatter):
    """Colored log formatter"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        # Применяем стандартное форматирование
        formatted = super().format(record)
        
        # Добавляем цвет к уровню логирования
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset_color = self.COLORS['RESET']
        
        # Заменяем [LEVEL] на цветной вариант
        formatted = formatted.replace(
            f'[{record.levelname}]', 
            f'[{log_color}{record.levelname}{reset_color}]'
        )
        
        return formatted

class SelectiveFormatter(logging.Formatter):
    """Formatter with different formats for different modules"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    # Модули с кратким форматом (без времени и названия модуля)
    SHORT_FORMAT_MODULES = {
        'model_loader', 'redis_client', 'repo_utils'
    }
    
    def format(self, record):
        # Выбираем формат в зависимости от модуля
        if record.name in self.SHORT_FORMAT_MODULES:
            # Краткий формат
            format_str = '[%(levelname)s] %(name)s: %(message)s'
        else:
            # Полный формат с временем и модулем
            format_str = '%(asctime)s - %(name)s - [%(levelname)s] %(message)s'
        
        # Создаем временный форматтер с нужным форматом
        if record.name in self.SHORT_FORMAT_MODULES:
            formatter = logging.Formatter(format_str)
        else:
            formatter = logging.Formatter(format_str, datefmt='%d.%m %H:%M:%S')
        
        # Форматируем сообщение
        formatted = formatter.format(record)
        
        # Добавляем цвет к уровню логирования
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset_color = self.COLORS['RESET']
        
        # Заменяем [LEVEL] на цветной вариант
        formatted = formatted.replace(
            f'[{record.levelname}]', 
            f'[{log_color}{record.levelname}{reset_color}]'
        )
        
        return formatted

def get_accurate_model_memory():
    """Get actual loaded model memory usage"""
    try:
        from app.model_loader import SecretClassifier
        classifier = SecretClassifier()
        return classifier.get_model_memory_usage()
    except Exception as e:
        return {'error': str(e)}

# def setup_logging():
#     from logging.handlers import RotatingFileHandler
#     logging.basicConfig(
#         level=logging.INFO,
#         format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#         handlers=[
#             RotatingFileHandler(
#                 "secrets_scanner_service.log",
#                 maxBytes=10 * 1024 * 1024,
#                 backupCount=5,
#                 encoding="utf-8"
#             ),
#             logging.StreamHandler()
#         ]
#     )
#     return logging.getLogger()

# def setup_logging_v2():
#     logger = logging.getLogger()
#     logger.setLevel(logging.INFO)
    
#     for handler in logger.handlers[:]:
#         logger.removeHandler(handler)
    
#     # Создаем кастомный обработчик с селективным форматированием
#     console_handler = logging.StreamHandler()
#     formatter = SelectiveFormatter()
#     console_handler.setFormatter(formatter)
#     logger.addHandler(console_handler)
    
#     from logging.handlers import RotatingFileHandler
#     file_handler = RotatingFileHandler(
#         'secrets_scanner_service.log', 
#         maxBytes=10*1024*1024, 
#         backupCount=5,
#         encoding='utf-8'
#     )
#     # В файл пишем с полной датой
#     file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     file_handler.setFormatter(file_formatter)
#     logger.addHandler(file_handler)
    
#     return logger

def setup_multiprocessing():
    """Configure multiprocessing for Windows/Linux compatibility"""
    if sys.platform.startswith('win'):
        multiprocessing.set_start_method('spawn', force=True)
    else:
        try:
            multiprocessing.set_start_method('fork', force=True)
        except RuntimeError:
            pass

def setup_host():
    logging.info("Необходимо настроить HOST")
    while True:
        host = input("Введите HOST (в формате 127.0.0.1)\n>")
        try:
            ipaddress.ip_address(host) # Вызовет ValueError если хост некорректный
            set_key(".env", "HOST", host)
            load_dotenv(override=True)
            break
        except ValueError as error:
            print(str(error))
        
def setup_port():
    logging.info("Необходимо настроить PORT")
    while True:
        port = input("Введите PORT (в формате 8001)\n>")
        if port.isdigit() and 1 <= int(port) <= 65535:
            set_key(".env", "PORT", port)
            load_dotenv(override=True)
            break

def setup_login_key():
    logging.info("Необходимо настроить LOGIN_KEY")
    while True:
        try:
            filename = "Settings/login.dat"
            message = input("Введите логин (NTLM Auth)\n>")

            key = Fernet.generate_key().decode()
            fernet = Fernet(key.encode())
            encrypted = fernet.encrypt(message.encode())

            with open(filename, "wb") as file:
                file.write(encrypted)

            input("Нажмите Enter для подтверждения (Консоль будет очищена)")
            set_key(".env", "LOGIN_KEY", key)
            load_dotenv(override=True)
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        except Exception as error:
            print(str(error))

def setup_password_key():
    logging.info("Необходимо настроить PASSWORD_KEY")
    while True:
        try:
            filename = "Settings/password.dat"
            message = input("Введите пароль (NTLM Auth)\n>")

            key = Fernet.generate_key().decode()
            fernet = Fernet(key.encode())
            encrypted = fernet.encrypt(message.encode())

            with open(filename, "wb") as file:
                file.write(encrypted)

            input("Нажмите Enter для подтверждения (Консоль будет очищена)")
            set_key(".env", "PASSWORD_KEY", key)
            load_dotenv(override=True)
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        except Exception as error:
            print(str(error))

def setup_pat_key():
    logging.info("Необходимо настроить PAT токен")
    while True:
        try:
            filename = "Settings/pat_token.dat"
            message = input("Введите PAT токен\n>")

            key = Fernet.generate_key().decode()
            fernet = Fernet(key.encode())
            encrypted = fernet.encrypt(message.encode())

            with open(filename, "wb") as file:
                file.write(encrypted)

            input("Нажмите Enter для подтверждения (Консоль будет очищена)")
            set_key(".env", "PAT_KEY", key)
            load_dotenv(override=True)
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        except Exception as error:
            print(str(error))

def setup_api_key():
    logging.info("Необходимо настроить API_KEY (используется для доступа к данному сервису)")
    answer = input("Хотите сгенерировать токен автоматически? (Y/N)\n>")
    if answer.lower() in ["y", "ye", "yes"]:
        apiKey = secrets.token_urlsafe(32)
        print(f"Сгенерирован API_KEY. Скопируйте его и используйте для доступа к данному сервису")
        print(f"> {apiKey}")
        input("Нажмите Enter для подтверждения (Консоль будет очищена)")
        set_key(".env", "API_KEY", apiKey)
        load_dotenv(override=True)
        os.system('cls' if os.name == 'nt' else 'clear')
    else:
        print("Введите API_TOKEN")
        apiKey = input(">")
        input("Нажмите Enter для подтверждения (Консоль будет очищена)")
        set_key(".env", "API_KEY", apiKey)
        load_dotenv(override=True)
        os.system('cls' if os.name == 'nt' else 'clear')

def setup_admin_api_key():
    logging.info("Необходимо настроить ADMIN_API_KEY (используется для административного доступа)")
    answer = input("Хотите сгенерировать административный токен автоматически? (Y/N)\n>")
    if answer.lower() in ["y", "ye", "yes"]:
        admin_key = secrets.token_urlsafe(32)
        print(f"Сгенерирован ADMIN_API_KEY. Скопируйте его и используйте для административного доступа")
        print(f"> {admin_key}")
        input("Нажмите Enter для подтверждения (Консоль будет очищена)")
        set_key(".env", "ADMIN_API_KEY", admin_key)
        load_dotenv(override=True)
        os.system('cls' if os.name == 'nt' else 'clear')
    else:
        print("Введите ADMIN_API_KEY")
        admin_key = input(">")
        input("Нажмите Enter для подтверждения (Консоль будет очищена)")
        set_key(".env", "ADMIN_API_KEY", admin_key)
        load_dotenv(override=True)
        os.system('cls' if os.name == 'nt' else 'clear')

def setup_redis_url():
    logging.info("Необходимо настроить REDIS_URL")
    default_redis = "redis://localhost:6379/0"
    answer = input(f"Использовать Redis по умолчанию ({default_redis})? (Y/N)\n>")
    if answer.lower() in ["y", "ye", "yes"]:
        redis_url = default_redis
    else:
        redis_url = input("Введите REDIS_URL (например: redis://localhost:6379/0)\n>")
    
    set_key(".env", "REDIS_URL", redis_url)
    load_dotenv(override=True)
    logging.info(f"Redis URL установлен: {redis_url}")

def create_default_env_file():
    """Создает .env файл с базовыми настройками"""
    if not os.path.exists(".env"):
        with open('.env', 'w') as f:
            f.write("")
    
    set_key(".env", "HubType", "Azure")
    set_key(".env", "MAX_WORKERS", "10")
    set_key(".env", "TEMP_DIR", "tmp/")
    set_key(".env", "VALIDATION_THREADS_NUMBER", "5")
    set_key(".env", "TASK_TIMEOUT_SECONDS", "1800")
    load_dotenv(override=True)

    logging.info(".env обновлен базовыми настройками")

def is_first_run():
    """Проверяет, является ли это первым запуском"""
    env_file = Path('.env')
    if not env_file.exists():
        return True
    
    # Проверяем содержимое .env файла
    load_dotenv()
    required_vars = ['HubType', 'MAX_WORKERS', 'HOST', 'PORT', 'LOGIN_KEY', 'PASSWORD_KEY', 'PAT_KEY', 'API_KEY', 'ADMIN_API_KEY', 'REDIS_URL']
    
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            return True
    
    return False

def test_redis_connection():
    """Test Redis connection"""
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        r = redis.from_url(redis_url, decode_responses=True)
        r.ping()
        logging.info(f"✅ Подключение к Redis успешно: {redis_url}")
        return True
    except Exception as e:
        logging.error(f"❌ Ошибка подключения к Redis: {e}")
        logging.error("Убедитесь что Redis сервер запущен и доступен")
        return False

def validate_environment():
    logging.info("Валидация настроек окружения...")
    if is_first_run():
        logging.info("Обнаружен первый запуск. Настройка окружения...")
        create_default_env_file()
    
    if not os.getenv("HOST"):
        setup_host()
    if not os.getenv("PORT"):
        setup_port()
    if not os.getenv("PAT_KEY") or os.getenv("PAT_KEY") == "***":
        setup_pat_key()
    if not os.getenv("LOGIN_KEY") or os.getenv("LOGIN_KEY") == "***":
        setup_login_key()
    if not os.getenv("PASSWORD_KEY") or os.getenv("PASSWORD_KEY") == "***":
        setup_password_key()
    if not os.getenv("API_KEY") or os.getenv("API_KEY") == "***":
        setup_api_key()
    if not os.getenv("ADMIN_API_KEY") or os.getenv("ADMIN_API_KEY") == "***":
        setup_admin_api_key()
    if not os.getenv("REDIS_URL"):
        setup_redis_url()

    # Test Redis connection
    if not test_redis_connection():
        return False

    required_files = ["app/main.py", "app/model_loader.py", "app/models.py", "app/redis_client.py", "app/worker.py", "app/repo_utils.py",
                      "app/scanner.py", "app/secure_save.py",
                      "Settings/excluded_extensions.yml", "Settings/excluded_files.yml", "Settings/false-positive.yml",
                      "Settings/rules.yml", "Settings/login.dat", "Settings/password.dat", "Settings/pat_token.dat"]
    
    validation_result = True
    for file in required_files:
        if not os.path.exists(file):
            logging.error(f"Required файл не найден: {file}")
            validation_result = False
    
    # Проверка наличия датасетов (новая структура с версиями)
    try:
        from app.model_version_manager import get_all_dataset_versions
        dataset_versions = get_all_dataset_versions()
        if not dataset_versions:
            logging.error("Не найдено ни одной версии датасетов в папке Datasets/")
            validation_result = False
        else:
            logging.info(f"Найдено версий датасетов: {len(dataset_versions)}")
    except Exception as e:
        logging.error(f"Ошибка при проверке датасетов: {e}")
        validation_result = False
    
    return validation_result

def check_dependencies():
    """Check if required Python packages are installed"""
    try:
        import uvicorn
        logging.info("uvicorn is installed")
    except ImportError:
        logging.error("uvicorn is not installed")
        return False
    
    try:
        import fastapi
        logging.info("fastapi is installed")
    except ImportError:
        logging.error("fastapi is not installed")
        return False
    
    try:
        import redis
        logging.info("redis is installed")
    except ImportError:
        logging.error("redis is not installed - run: pip install redis>=4.0.0")
        return False
    
    return True

def get_server_config():
    """Get server configuration from environment"""
    host = os.getenv("HOST")
    port = int(os.getenv("PORT"))
    log_level = "info"
    
    return {
        "host": host,
        "port": port,
        "log_level": log_level,
        "access_log": True,
        "use_colors": True,
        "loop": "asyncio"
    }

def setup_signal_handlers():
    """Setup graceful shutdown signal handlers"""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}")
        print("Initiating graceful shutdown...")
        # Позволяем uvicorn обработать shutdown gracefully
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal_handler)

def print_startup_info():
    """Print startup information"""
    config = get_server_config()
    max_workers = os.getenv("MAX_WORKERS", "10")
    hub_type = os.getenv("HubType", "Azure")
    temp_dir = os.getenv("TEMP_DIR", "C:\\")
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    validation_threads = os.getenv("VALIDATION_THREADS_NUMBER", "5")
    task_timeout = os.getenv("TASK_TIMEOUT_SECONDS", "1800")
    
    print("\n" + "=" * 60)
    print("SECRET SCANNER SERVICE (REDIS ARCHITECTURE)")
    print("=" * 60)
    logging.info(f"Server: http://{config['host']}:{config['port']}")
    logging.info(f"Hub Type: {hub_type.upper()}")
    logging.info(f"Max Workers: {max_workers}")
    logging.info(f"Validation Threads: {validation_threads}")
    logging.info(f"Task Timeout: {task_timeout}s")
    logging.info(f"Redis URL: {redis_url}")
    logging.info(f"Log Level: {config['log_level'].upper()}")
    logging.info(f"Temp Directory: {temp_dir}")
    logging.info(f"Platform: {sys.platform}")
    logging.info(f"Python: {sys.version.split()[0]}")
    logging.info(f"CPU Count: {multiprocessing.cpu_count()}")
    print("=" * 60)
    print("")
    
    # Model memory information
    try:
        print("=" * 60)
        print("MODEL MEMORY (ESTIMATED PER WORKER):")
        print("=" * 60)
        model_stats = get_accurate_model_memory()
        if 'error' not in model_stats:
            logging.info(f"Vectorizer: {model_stats.get('vectorizer_mb', 0):.1f} MB")
            logging.info(f"Model: {model_stats.get('model_mb', 0):.1f} MB")
            logging.info(f"Vocabulary: {model_stats.get('vocabulary_size', 0):,} terms")
            logging.info(f"Total per worker: {model_stats.get('total_mb', 0):.1f} MB")
            logging.info(f"Estimated for {max_workers} workers: {model_stats.get('total_mb', 0) * int(max_workers):.1f} MB")
            print("=" * 60)
        else:
            logging.warning("Model not loaded yet - will load in each worker")
    except Exception as e:
        logging.warning(f"Model memory check failed: {e}")

def main():
    """Main startup function"""
    setup_logging()
    print("=" * 60)
    print("Secret Scanner Service Startup (Redis Architecture)")
    print("=" * 60)
    import shutil
    if os.path.exists("tmp"):
        print("Очистка директории tmp/")
        for filename in os.listdir("tmp"):
            file_path = os.path.join("tmp", filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.remove(file_path)  # удаляем файл или ссылку
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)  # удаляем папку со всем содержимым
            except Exception as e:
                print(f"Ошибка при удалении {file_path}: {e}")
    else:
        print("Папка tmp не найдена")
    
    try:
        # Check dependencies
        logging.info("Checking Python dependencies...")
        if not check_dependencies():
            logging.error("Required dependencies not installed")
            logging.info("Please run: pip install -r requirements.txt")
            logging.info("Make sure Redis is installed: pip install redis>=4.0.0")
            sys.exit(1)
        
        setup_multiprocessing()
        
        if not validate_environment():
            print("Произошла ошибка валидации переменных окружения. Завершение программы")
            sys.exit(1)
        logging.info("Валидация переменных окружения прошла успешно")
        
        print_startup_info()
        
        setup_signal_handlers()
        
        config = get_server_config()
        print("")
        print("=" * 60)
        print("Starting HTTP server with Redis-based worker architecture...")
        print("=" * 60)
        
        # Important note about workers
        logging.info("Workers будут запущены автоматически через FastAPI lifespan")
        logging.info("Мониторинг workers доступен через admin API endpoints")
        
        uvicorn.run("app.main:app", **config, log_config=None)
        
    except KeyboardInterrupt:
        print("\nReceived interrupt signal")
    except ImportError as e:
        logging.error(f"Import error: {e}")
        logging.info("Please run: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Critical startup error: {e}")
        sys.exit(1)
    finally:
        print("Service stopped")

if __name__ == "__main__":
    main()