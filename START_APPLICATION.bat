@echo off
title SentinelTrace V5 - Launcher
color 0b

echo =====================================================================
echo           SENTINELTRACE V5 - PLATFORM LAUNCHER
echo =====================================================================
echo.
echo [*] Starting Backend REST API Server (Port 8000)...
start "SentinelTrace Backend (FastAPI)" cmd /k "cd /d "%~dp0backend" && .venv\Scripts\uvicorn.exe app.main:app --port 8000"

echo [*] Starting Frontend UI Server (Port 5173)...
start "SentinelTrace Frontend (Vite)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo [*] Waiting 4 seconds for services to initialize...
timeout /t 4 /nobreak >nul

echo [*] Launching Dashboard in default browser...
start http://localhost:5173

echo.
echo =====================================================================
echo  [OK] SentinelTrace V5 is now running!
echo.
echo  - Frontend Dashboard : http://localhost:5173
echo  - Backend API Docs   : http://localhost:8000/docs
echo.
echo  LOGIN CREDENTIALS:
echo    Username: admin_demo
echo    Password: SentinelDemo!2026
echo =====================================================================
echo.
pause
