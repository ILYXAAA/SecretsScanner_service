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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def setup_multiprocessing():
    """Configure multiprocessing for Windows/Linux compatibility"""
    if sys.platform.startswith('win'):
        # Windows requires this for multiprocessing
        multiprocessing.set_start_method('spawn', force=True)
    else:
        # Linux/macOS can use fork (more efficient)
        try:
            multiprocessing.set_start_method('fork', force=True)
        except RuntimeError:
            # Already set
            pass

def validate_environment():
    """Validate required environment variables and files"""
    required_dirs = [
        "Settings",
        "Model", 
        "Datasets",
        "tmp"
    ]
    
    for dir_name in required_dirs:
        if not os.path.exists(dir_name):
            print(f"📁 Создаю директорию: {dir_name}")
            os.makedirs(dir_name, exist_ok=True)
    
    # Check if model training data exists
    secrets_dataset = os.getenv("SECRETS_DATASET", "Datasets/Dataset_Secrets.txt")
    non_secrets_dataset = os.getenv("NOT_SECRETS_DATASET", "Datasets/Dataset_NonSecrets.txt")
    
    if not os.path.exists(secrets_dataset):
        print(f"⚠️  Файл {secrets_dataset} не найден. Создайте файл с примерами секретов для обучения модели.")
    
    if not os.path.exists(non_secrets_dataset):
        print(f"⚠️  Файл {non_secrets_dataset} не найден. Создайте файл с примерами НЕ-секретов для обучения модели.")
    
    # Check configuration files
    rules_file = os.getenv("RULES_FILE", "Settings/rules.yml")
    if not os.path.exists(rules_file):
        print(f"⚠️  Файл правил {rules_file} не найден. Создайте файл с правилами поиска секретов.")
    
    print("✅ Проверка окружения завершена")

def get_server_config():
    """Get server configuration from environment"""
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
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
        print(f"\n🛑 Получен сигнал {signum} ({signal.Signals(signum).name})")
        print("Инициирую graceful shutdown...")
        sys.exit(0)
    
    # Register handlers for common signals
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination request
    
    if hasattr(signal, 'SIGHUP'):  # Unix only
        signal.signal(signal.SIGHUP, signal_handler)  # Hangup

def print_startup_info():
    """Print startup information"""
    config = get_server_config()
    max_workers = os.getenv("MAX_WORKERS", "10")
    hub_type = os.getenv("HubType", "azure")
    
    print("=" * 60)
    print("🔒 SECRET SCANNER SERVICE")
    print("=" * 60)
    print(f"🌐 Server: http://{config['host']}:{config['port']}")
    print(f"🔧 Hub Type: {hub_type.upper()}")
    print(f"👷 Max Workers: {max_workers}")
    print(f"📊 Log Level: {config['log_level'].upper()}")
    print(f"🖥️  Platform: {sys.platform}")
    print(f"🐍 Python: {sys.version.split()[0]}")
    print(f"💾 CPU Count: {multiprocessing.cpu_count()}")
    print("=" * 60)

def main():
    """Main startup function"""
    try:
        print("🚀 Запуск Secret Scanner Service...")
        
        # Setup multiprocessing
        setup_multiprocessing()
        
        # Validate environment
        validate_environment()
        
        # Print startup info (don't setup signal handlers - let uvicorn handle them)
        print_startup_info()
        
        # Get server configuration
        config = get_server_config()
        
        # Start the server
        print("🔄 Запуск HTTP сервера...")
        uvicorn.run("app.main:app", **config)
        
    except KeyboardInterrupt:
        print("\n🛑 Получен сигнал прерывания")
    except Exception as e:
        print(f"❌ Критическая ошибка при запуске: {e}")
        sys.exit(1)
    finally:
        print("👋 Сервис остановлен")

if __name__ == "__main__":
    main()