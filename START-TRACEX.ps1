# TRACE-X Quick Start Launcher
# This script starts TRACE-X in demo mode (no database/Redis needed)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  TRACE-X Email Threat Analyzer" -ForegroundColor Cyan
Write-Host "  Quick Start Launcher" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
Write-Host "[1/3] Checking Python installation..." -ForegroundColor Yellow
$pythonInstalled = $false
$pythonCmd = "python"

if (Test-Path "$PSScriptRoot\backend\venv\Scripts\python.exe") {
    $pythonCmd = "$PSScriptRoot\backend\venv\Scripts\python.exe"
    $pythonInstalled = $true
    Write-Host "  ✓ Virtual environment Python found." -ForegroundColor Green
} elseif (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe") {
    $pythonCmd = "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
    $pythonInstalled = $true
    Write-Host "  ✓ Python 3.11 found." -ForegroundColor Green
} else {
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python 3") {
            Write-Host "  ✓ Python found: $pythonVersion" -ForegroundColor Green
            $pythonInstalled = $true
        }
    } catch {}
}

if (-not $pythonInstalled) {
    Write-Host "  ✗ Python not found. Installing Python 3.11..." -ForegroundColor Yellow
    winget install Python.Python.3.11 --scope user --accept-package-agreements --accept-source-agreements
}

# Check if Node.js is installed
Write-Host "[2/3] Checking Node.js installation..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    Write-Host "  ✓ Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Node.js not found - Frontend won't start" -ForegroundColor Red
}

Write-Host "[3/3] Starting TRACE-X Services..." -ForegroundColor Yellow
Write-Host ""

# Start Backend API
Write-Host "Starting Backend API (FastAPI)..." -ForegroundColor Cyan
$backendPath = Join-Path $PSScriptRoot "backend"
$backendVenvPy = Join-Path $backendPath "venv\Scripts\python.exe"
if (Test-Path $backendVenvPy) {
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; .\venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000" -WindowStyle Minimized
} else {
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; uvicorn app.main:app --reload --host 127.0.0.1 --port 8000" -WindowStyle Minimized
}

# Start Frontend UI
Write-Host "Starting Frontend UI (Vite)..." -ForegroundColor Cyan
$frontendPath = Join-Path $PSScriptRoot "frontend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; npm run dev" -WindowStyle Minimized

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "  TRACE-X Pro is running!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""
Write-Host "Services:" -ForegroundColor Cyan
Write-Host "  - Frontend UI:  http://localhost:5173" -ForegroundColor White
Write-Host "  - Backend API:  http://localhost:8000" -ForegroundColor White
Write-Host "  - API Docs:     http://localhost:8000/docs" -ForegroundColor White
Write-Host "  - Threat Stream ws://localhost:8000/api/v1/ws/threat-stream" -ForegroundColor White
Write-Host ""

# Wait for services to start then open browser
Start-Sleep -Seconds 4
Start-Process "http://localhost:5173"

