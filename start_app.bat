@echo off
title SentinelTrace V5
color 0b

echo.
echo  ========================================
echo   SENTINELTRACE V5
echo   Universal Log Pre-processing Framework
echo  ========================================
echo.

REM ── Locate repository root relative to this script ──
set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "FRONTEND=%ROOT%frontend"

REM ── Check prerequisites ──────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not on PATH.
    echo          Install Python 3.11 or 3.12 from https://python.org
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Node.js / npm is not installed or not on PATH.
    echo          Install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)

REM ── Check Python virtual environment ─────────────
if not exist "%BACKEND%\.venv\Scripts\activate.bat" (
    echo  [*] Creating Python virtual environment...
    cd /d "%BACKEND%"
    python -m venv .venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [*] Installing backend dependencies...
    .venv\Scripts\pip install -r requirements.txt --quiet
    if errorlevel 1 (
        echo  [ERROR] pip install failed. Check requirements.txt and Python version.
        pause
        exit /b 1
    )
    echo  [OK] Backend dependencies installed.
)

REM ── Check frontend node_modules ───────────────────
if not exist "%FRONTEND%\node_modules" (
    echo  [*] Installing frontend dependencies...
    cd /d "%FRONTEND%"
    npm install --silent
    if errorlevel 1 (
        echo  [ERROR] npm install failed.
        pause
        exit /b 1
    )
    echo  [OK] Frontend dependencies installed.
)

REM ── Start Backend ────────────────────────────────
echo  [*] Starting Backend REST API  ^(port 8000^)...
start "SentinelTrace Backend" cmd /k "cd /d "%BACKEND%" && .venv\Scripts\uvicorn.exe app.main:app --port 8000"

REM ── Start Frontend ───────────────────────────────
echo  [*] Starting Frontend UI       ^(port 5173^)...
start "SentinelTrace Frontend" cmd /k "cd /d "%FRONTEND%" && npm run dev"

REM ── Wait for services ────────────────────────────
echo  [*] Waiting for services to initialize...
timeout /t 5 /nobreak >nul

REM ── Open browser ─────────────────────────────────
start http://localhost:5173

echo.
echo  ========================================
echo   SentinelTrace V5 is running!
echo  ========================================
echo.
echo   Frontend Dashboard : http://localhost:5173
echo   Backend API        : http://localhost:8000
echo   API Documentation  : http://localhost:8000/docs
echo   Health Check       : http://localhost:8000/api/v1/health
echo.
echo   Demo Login:
echo     Username : admin_demo
echo     Password : SentinelDemo!2026
echo.
echo   Run stop_app.bat to shut down all services.
echo  ========================================
echo.
pause
