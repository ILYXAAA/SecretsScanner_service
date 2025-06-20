@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: Secret Scanner Service Startup Script
echo ===============================================
echo         Secret Scanner Service
echo ===============================================
echo.

:: Change to script directory
cd /d "%~dp0"

:: Check Python installation
echo [1/7] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo Found: %%i
echo.

:: Check git and update
echo [2/7] Checking for updates...
where git >nul 2>&1
if %errorlevel% equ 0 (
    git fetch --all 2>nul
    git pull 2>nul
    if %errorlevel% equ 0 echo Repository updated
) else (
    echo Git not found, skipping update
)
echo.

:: Create virtual environment
echo [3/7] Setting up virtual environment...
if not exist "venv\" (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created
) else (
    echo Virtual environment exists
)

:: Activate virtual environment
call "venv\Scripts\activate.bat"
if %errorlevel% neq 0 (
    set "PATH=%CD%\venv\Scripts;%PATH%"
    set "VIRTUAL_ENV=%CD%\venv"
)
echo Virtual environment activated
echo.

:: Upgrade pip
echo [4/7] Upgrading pip...
python -m pip install --upgrade pip --index-url http://our.nexus:8080/repository/pypi-all/simple --trusted-host our.nexus --quiet --timeout 60
if %errorlevel% neq 0 (
    python -m pip install --upgrade pip --quiet --timeout 60
)
echo.

:: Install dependencies
echo [5/7] Installing dependencies...
if exist "requirements.txt" (
    pip install -r requirements.txt --index-url http://our.nexus:8080/repository/pypi-all/simple --trusted-host our.nexus --timeout 120
    if %errorlevel% neq 0 (
        pip install -r requirements.txt --timeout 120
        if %errorlevel% neq 0 (
            echo ERROR: Failed to install dependencies
            pause
            exit /b 1
        )
    )
    echo Dependencies installed
) else (
    echo ERROR: requirements.txt not found
    pause
    exit /b 1
)
echo.

:: Create directories
echo [6/7] Creating directories...
for %%d in (Settings Model Datasets tmp app) do (
    if not exist "%%d\" (
        mkdir "%%d" 2>nul
        if exist "%%d\" echo Created %%d
    )
)
echo.

:: Check configuration
echo [7/7] Checking configuration...
if not exist ".env" (
    echo WARNING: .env file not found
    if exist ".env.example" (
        choice /c YN /m "Copy .env.example to .env? (Y/N)"
        if !errorlevel! equ 1 (
            copy ".env.example" ".env" >nul
            echo .env file created - please edit and configure
        )
    )
) else (
    echo Configuration file found
)

:: Check authentication
if not exist "Settings\login.dat" (
    echo WARNING: Authentication not configured
    if exist "app\secure_save.py" (
        choice /c YN /m "Run secure_save.py to configure auth? (Y/N)"
        if !errorlevel! equ 1 (
            python app/secure_save.py
        )
    )
) else (
    echo Authentication configured
)
echo.

:: Start application
echo ===============================================
echo          Starting Service
echo ===============================================
echo.

if not exist "run.py" (
    echo ERROR: run.py not found
    pause
    exit /b 1
)

python run.py

:: Handle exit
if %errorlevel% neq 0 (
    echo.
    echo ===============================================
    echo Service exited with error: %errorlevel%
    echo.
    echo Manual start commands:
    echo   venv\Scripts\activate.bat
    echo   python run.py
    echo ===============================================
    pause
) else (
    echo Service finished successfully
    timeout /t 3 /nobreak >nul
)