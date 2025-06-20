#!/usr/bin/env python3
"""
Production startup script for Secret Scanner Service
Supports graceful shutdown and proper resource management
"""

import uvicorn
import os
import sys
import signal
import multiprocessing
import logging
from pathlib import Path
from dotenv import load_dotenv
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
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

def create_env_file():
    """Create .env file from template and run first-time setup"""
    example_file = Path('.env.example')
    if not example_file.exists():
        logging.error(".env.example file not found")
        return False
    
    # Copy example to .env
    with open(example_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    with open('.env', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("\nFirst-time setup detected - running configuration wizard...")
    
    # Run first-time setup from secure_save.py
    try:
        import sys
        sys.path.append('app')
        from secure_save import configure_first_setup
        
        if configure_first_setup():
            logging.info("First-time setup completed successfully")
            return True
        else:
            logging.error("First-time setup failed")
            return False
            
    except ImportError:
        logging.error("Could not import configure_first_setup from app/secure_save.py")
        logging.info("Please run: python app/secure_save.py manually")
        return False
    except Exception as e:
        logging.error(f"Error during first-time setup: {e}")
        return False

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    formatter = ColoredFormatter(fmt='[%(levelname)s] %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
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

def validate_environment():
    """Validate required environment variables and files"""
    # Load environment variables
    env_file = Path('.env')
    if env_file.exists():
        load_dotenv()
        logging.info(".env configuration file found and loaded")
    else:
        logging.warning(".env file not found. Creating from template...")
        create_env_file()
        load_dotenv()
        logging.info(".env file created - configuration required")
    
    # Create required directories
    required_dirs = [
        "Settings",
        "Model", 
        "Datasets",
        "tmp"
    ]
    
    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            logging.info(f"Creating directory: {dir_name}")
            dir_path.mkdir(parents=True, exist_ok=True)
        else:
            logging.info(f"Directory '{dir_name}' found")
    
    # Check dataset files
    secrets_dataset = os.getenv("SECRETS_DATASET", "Datasets/Dataset_Secrets.txt")
    non_secrets_dataset = os.getenv("NOT_SECRETS_DATASET", "Datasets/Dataset_NonSecrets.txt")
    
    if not Path(secrets_dataset).exists():
        logging.warning(f"Dataset file {secrets_dataset} not found")
        logging.info("Create file with secret examples for model training")
    else:
        logging.info(f"Secrets dataset found: {secrets_dataset}")
    
    if not Path(non_secrets_dataset).exists():
        logging.warning(f"Dataset file {non_secrets_dataset} not found")
        logging.info("Create file with non-secret examples for model training")
    else:
        logging.info(f"Non-secrets dataset found: {non_secrets_dataset}")
    
    # Check configuration files
    config_files = {
        "RULES_FILE": "Settings/rules.yml",
        "EXCLUDED_FILES_PATH": "Settings/excluded_files.yml",
        "EXCLUDED_EXTENSIONS_PATH": "Settings/excluded_extensions.yml"
    }
    
    for env_var, default_path in config_files.items():
        file_path = os.getenv(env_var, default_path)
        if not Path(file_path).exists():
            logging.warning(f"Configuration file {file_path} not found")
        else:
            logging.info(f"Configuration file found: {file_path}")
    
    # Check authentication files
    auth_files = {
        "LOGIN_FILE": "Settings/login.dat",
        "PASSWORD_FILE": "Settings/password.dat", 
        "PAT_TOKEN_FILE": "Settings/pat_token.dat"
    }
    
    missing_auth = []
    for env_var, default_path in auth_files.items():
        file_path = os.getenv(env_var, default_path)
        if not Path(file_path).exists():
            missing_auth.append(file_path)
        else:
            logging.info(f"Authentication file found: {file_path}")
    
    if missing_auth:
        logging.error("Missing authentication files:")
        for file in missing_auth:
            logging.error(f"  - {file}")
        logging.info("To configure authentication:")
        logging.info("   Run: python app/secure_save.py")
        return False
    
    # Check required environment variables
    required_env_vars = ["LOGIN_KEY", "PASSWORD_KEY", "PAT_KEY"]
    missing_vars = []
    
    for var in required_env_vars:
        value = os.getenv(var)
        if not value or value == "***":
            missing_vars.append(var)
        else:
            logging.info(f"{var} is configured")
    
    if missing_vars:
        logging.error("Missing required environment variables:")
        for var in missing_vars:
            logging.error(f"  - {var}")
        logging.info("Configure these variables in .env file or run app/secure_save.py")
        return False
    
    logging.info("Environment validation completed successfully")
    return True

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
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8001"))
    workers = int(os.getenv("MAX_WORKERS", "10"))
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    
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
    print(f"Server: http://{config['host']}:{config['port']}")
    print(f"Hub Type: {hub_type.upper()}")
    print(f"Max Workers: {max_workers}")
    print(f"Log Level: {config['log_level'].upper()}")
    print(f"Temp Directory: {temp_dir}")
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"CPU Count: {multiprocessing.cpu_count()}")
    print("=" * 60)

def main():
    """Main startup function"""
    # Setup logging first
    logger = setup_logging()
    
    print("Secret Scanner Service Startup")
    print("=" * 40)
    
    try:
        # Check dependencies
        print("\nChecking Python dependencies...")
        if not check_dependencies():
            logging.error("Required dependencies not installed")
            logging.info("Please run: pip install -r requirements.txt")
            sys.exit(1)
        
        # Setup multiprocessing
        setup_multiprocessing()
        
        # Validate environment
        print("\nValidating environment...")
        if not validate_environment():
            logging.error("Environment validation failed")
            logging.info("Please complete the configuration steps shown above")
            sys.exit(1)
        
        # Print startup info
        print_startup_info()
        
        # Setup signal handlers
        setup_signal_handlers()
        
        # Get server configuration
        config = get_server_config()
        
        # Start the server
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