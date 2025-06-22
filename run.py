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
        colored_record = logging.makeLogRecord(record.__dict__)
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        colored_record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(colored_record)

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    console_handler = logging.StreamHandler()
    formatter = ColoredFormatter(fmt='[%(levelname)s] %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    from logging.handlers import RotatingFileHandler
    file_handler = RotatingFileHandler(
        'secrets_scanner_service.log', 
        maxBytes=10*1024*1024, 
        backupCount=5,
        encoding='utf-8'
    )
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

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
    logging.info("Необходимо настроить API_KEY (используется для доступа к данному микросервису)")
    answer = input("Хотите сгенерировать токен автоматически? (Y/N)\n>")
    if answer.lower() in ["y", "ye", "yes"]:
        apiKey = secrets.token_urlsafe(32)
        print(f"Сгенерирован API_KEY. Скопируйте его и используйте для доступа к данному микросервису")
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

def create_default_env_file():
    """Создает .env файл с базовыми настройками"""
    if not os.path.exists(".env"):
        with open('.env', 'w') as f:
            f.write("")
    
    set_key(".env", "HubType", "Azure")
    set_key(".env", "MAX_WORKERS", "10")
    set_key(".env", "TEMP_DIR", "tmp/")
    load_dotenv(override=True)

    logging.info(".env обновлен базовыми настройками")

def is_first_run():
    """Проверяет, является ли это первым запуском"""
    env_file = Path('.env')
    if not env_file.exists():
        return True
    
    # Проверяем содержимое .env файла
    load_dotenv()
    required_vars = ['HubType', 'MAX_WORKERS', 'HOST', 'PORT', 'LOGIN_KEY', 'PASSWORD_KEY', 'PAT_KEY', 'API_KEY']
    
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            return True
    
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

    required_files = ["app/main.py", "app/model_loader.py", "app/models.py", "app/queue_worker.py", "app/repo_utils.py",
                      "app/scanner.py", "app/secure_save.py", "Datasets/Dataset_NonSecrets.txt", "Datasets/Dataset_Secrets.txt",
                      "Settings/excluded_extensions.yml", "Settings/excluded_files.yml", "Settings/false-positive.yml",
                      "Settings/rules.yml", "Settings/login.dat", "Settings/password.dat", "Settings/pat_token.dat"]
    
    validation_result = True
    for file in required_files:
        if not os.path.exists(file):
            logging.error(f"Required файл не найден: {file}")
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
        print(f"\nReceived signal {signum} ({signal.Signals(signum).name})")
        print("Initiating graceful shutdown...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination request
    
    if hasattr(signal, 'SIGHUP'):  # Unix only
        signal.signal(signal.SIGHUP, signal_handler)  # Hangup

def print_startup_info():
    """Print startup information"""
    config = get_server_config()
    max_workers = os.getenv("MAX_WORKERS", "10")
    hub_type = os.getenv("HubType", "Azure")
    temp_dir = os.getenv("TEMP_DIR", "C:\\")
    
    print("\n" + "=" * 60)
    print("SECRET SCANNER SERVICE")
    print("=" * 60)
    logging.info(f"Server: http://{config['host']}:{config['port']}")
    logging.info(f"Hub Type: {hub_type.upper()}")
    logging.info(f"Max Workers: {max_workers}")
    logging.info(f"Log Level: {config['log_level'].upper()}")
    logging.info(f"Temp Directory: {temp_dir}")
    logging.info(f"Platform: {sys.platform}")
    logging.info(f"Python: {sys.version.split()[0]}")
    logging.info(f"CPU Count: {multiprocessing.cpu_count()}")
    print("=" * 60)

def main():
    """Main startup function"""
    setup_logging()
    
    print("Secret Scanner Service Startup")
    print("=" * 40)
    
    try:
        # Check dependencies
        print("\nChecking Python dependencies...")
        if not check_dependencies():
            logging.error("Required dependencies not installed")
            logging.info("Please run: pip install -r requirements.txt")
            sys.exit(1)
        
        setup_multiprocessing()
        
        if not validate_environment():
            print("Произошла ошибка валидации переменных окружения. Завершение программы")
            sys.exit(1)
        logging.info("Валидация переменных окружения прошла успешно")
        
        print_startup_info()
        
        setup_signal_handlers()
        
        config = get_server_config()
        
        print("\nStarting HTTP server...")
        uvicorn.run("app.main:app", **config)
        
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