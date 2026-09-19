@echo off
title TRACE-X Pro One-Click Installer
cls
echo =======================================================
echo          TRACE-X PRO - ONE-CLICK INSTALLER
echo =======================================================
echo.

set ROOT_DIR=%~dp0
cd /d "%ROOT_DIR%"

echo [1/4] Checking Python environment...
set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)

%PYTHON_CMD% --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python not found. Installing Python 3.11 via winget...
    winget install Python.Python.3.11 --scope user --accept-package-agreements --accept-source-agreements
    if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    )
)

echo [2/4] Setting up Python virtual environment...
cd /d "%ROOT_DIR%backend"
if not exist "venv\Scripts\python.exe" (
    %PYTHON_CMD% -m venv venv
)

echo [3/4] Installing Python dependencies...
venv\Scripts\pip.exe install -r requirements.txt

if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
    )
)

echo [4/4] Checking Node.js / Frontend dependencies...
cd /d "%ROOT_DIR%frontend"
if not exist "node_modules" (
    call npm install
)

cd /d "%ROOT_DIR%"
echo.
echo =======================================================
echo           INSTALLATION COMPLETED SUCCESSFULLY!
echo =======================================================
echo.
echo You can now launch TRACE-X Pro by double-clicking:
echo - TRACE-X.exe (Desktop GUI Manager)
echo - START-TRACEX.bat (Command-line Launcher)
echo.
pause
