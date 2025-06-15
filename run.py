#!/usr/bin/env python3
"""
FastAPI application runner script with startup checks
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

def check_files():
    """Check if required files exist"""
    required_files = {
        'app/main.py': 'Main FastAPI application',
        'app/model_loader.py': 'Model loader',
        'app/models.py': 'Pydantic models',
        'app/queue_worker.py': 'Queue workers',
        'app/repo_utils.py': 'Utils for repo interactions',
        'app/scanner.py': 'Scanning utils',
        'app/secure_save.py': 'Saving/Reading Auth data',
        'requirements.txt': 'Python dependencies',
        '.env': 'Environment settings file',
        'Datasets/Dataset_NonSecrets.txt': 'Dataset for FalsePositive secrets',
        'Datasets/Dataset_Secrets.txt': 'Dataset for True secrets'
    }
    
    missing_files = []
    for file, description in required_files.items():
        if not Path(file).exists():
            missing_files.append(f"{file} ({description})")
        else:
            print(f"✅ {file} found")
    
    if missing_files:
        print("\n❌ Missing required files:")
        for file in missing_files:
            print(f"  - {file}")
        return False
    
    return True

def check_env_config():
    """Check environment configuration"""
    load_dotenv()
    
    # Check if .env file exists
    if not Path('.env').exists():
        print("⚠️  .env file not found. Using default configuration.")
        print("   Create a .env file for custom configuration")
    else:
        print("✅ .env configuration file found")
    
    # Check required environment variables
    required_vars = {
        "HubType": "Repository hub type",
        "HOST": "Application host",
        "PORT": "Application port",
        "LOGIN_KEY": "Ключ для шифрования Логина",
        "PASSWORD_KEY": "Ключ для шифрования Пароля",
        "PAT_KEY": "Ключ для шифрования PAT токена"
    }
    
    missing_vars = []
    for var, description in required_vars.items():
        value = os.getenv(var)
        if not value:
            missing_vars.append(f"{var} ({description})")
        else:
            print(f"✅ {var} configured")
    
    if missing_vars:
        print("\n❌ Missing required environment variables:")
        for var in missing_vars:
            if var in ["LOGIN_KEY", "PASSWORD_KEY", "PAT_KEY"]:
                print(f"  - {var} - запустите secure_save.py (мастер настройки Auth данных)")
            else:
                print(f"  - {var}")
        return False
    
    return True

def check_directories():
    """Check if required directories exist"""
    required_dirs = ['Settings', 'app', 'Datasets']
    
    for dir_name in required_dirs:
        if not Path(dir_name).exists():
            print(f"❌ Missing required directory: {dir_name}")
            return False
        else:
            print(f"✅ Directory {dir_name} found")
    
    return True

def main():
    print("🚀 FastAPI Application Startup")
    print("=" * 40)
    
    # Load environment variables
    load_dotenv()
    
    # Check required files
    if not check_files():
        print("\n❌ Please ensure all required files are present before starting.")
        sys.exit(1)
    
    # Check directories
    if not check_directories():
        print("\n❌ Please ensure all required directories are present before starting.")
        sys.exit(1)
    
    # Check environment configuration
    if not check_env_config():
        print("\n❌ Please configure environment variables before starting.")
        sys.exit(1)
    
    print("\n✅ All checks passed!")
    
    # Get configuration from environment
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', '8001'))
    hub_type = os.getenv('HubType', 'Azure')
    
    print(f"\n🌐 Starting FastAPI application...")
    print(f"📍 Application will be available at: http://{host}:{port}")
    print(f"🔧 Repository hub type: {hub_type}")
    print(f"📊 Health check: http://{host}:{port}/health")
    print("\n" + "=" * 40)
    
    # Start the application
    try:
        import uvicorn
        uvicorn.run("app.main:app", host=host, port=port, log_level="info")
    except ImportError as e:
        print(f"❌ Required dependencies not installed: {e}")
        print("Please run: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()