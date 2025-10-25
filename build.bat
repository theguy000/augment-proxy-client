@echo off
REM Build script for compiling proxy_client.py with Nuitka
REM This creates a standalone Windows executable

echo ========================================
echo Augment Proxy Client - Nuitka Build
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    exit /b 1
)

REM Check if Nuitka is installed
python -m nuitka --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Nuitka not found, installing...
    pip install nuitka
    if errorlevel 1 (
        echo [ERROR] Failed to install Nuitka
        exit /b 1
    )
)

REM Clean previous build
echo [INFO] Cleaning previous build...
if exist "proxy_client.dist" rmdir /s /q "proxy_client.dist"
if exist "proxy_client.build" rmdir /s /q "proxy_client.build"
if exist "proxy_client.exe" del /f /q "proxy_client.exe"

echo.
echo [INFO] Starting Nuitka compilation...
echo [INFO] This may take several minutes...
echo.

REM Compile with Nuitka
python -m nuitka ^
    --standalone ^
    --onefile ^
    --windows-console-mode=attach ^
    --enable-plugin=no-qt ^
    --assume-yes-for-downloads ^
    --output-dir=. ^
    --output-filename=proxy_client.exe ^
    proxy_client.py

if errorlevel 1 (
    echo.
    echo [ERROR] Nuitka compilation failed
    exit /b 1
)

echo.
echo [SUCCESS] Compilation completed successfully!
echo.

REM Copy to binaries directory
if not exist "binaries\windows" mkdir "binaries\windows"
copy /y "proxy_client.exe" "binaries\windows\proxy_client.exe"

echo [INFO] Binary copied to: binaries\windows\proxy_client.exe
echo.
echo [INFO] Testing the binary...
echo.

REM Test the binary (will show usage)
"binaries\windows\proxy_client.exe"

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Binary location: binaries\windows\proxy_client.exe
echo.
