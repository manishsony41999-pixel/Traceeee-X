@echo off
title TRACE-X Pro Launcher
cls
echo =======================================================
echo          TRACE-X PRO - EMAIL THREAT DETECTOR
echo =======================================================
echo.

set ROOT_DIR=%~dp0
cd /d "%ROOT_DIR%"

if exist "TRACE-X.exe" (
    echo Launching TRACE-X Graphical Manager...
    start "" "TRACE-X.exe"
    exit /b 0
)

echo Starting Backend API...
start "TRACE-X Backend API" /min cmd /c "cd /d %ROOT_DIR%backend && venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

echo Starting Frontend UI...
start "TRACE-X Frontend UI" /min cmd /c "cd /d %ROOT_DIR%frontend && npm run dev"

echo Waiting for services to initialize...
timeout /t 4 /nobreak >nul

echo Opening browser at http://localhost:5173...
start http://localhost:5173

echo.
echo TRACE-X Pro is now running!
echo - Web UI:     http://localhost:5173
echo - API Docs:   http://localhost:8000/docs
echo - Threat WS:  ws://localhost:8000/api/v1/ws/threat-stream
echo.
pause
