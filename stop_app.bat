@echo off
title SentinelTrace V5 - Stopping
color 0c

echo.
echo  ========================================
echo   SENTINELTRACE V5
echo   Stopping Application
echo  ========================================
echo.

REM ── Stop process on port 8000 (Backend) ──────────
echo  [*] Stopping Backend (port 8000)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
    echo  [OK] Backend stopped (PID: %%a).
)

REM ── Stop process on port 5173 (Frontend) ─────────
echo  [*] Stopping Frontend (port 5173)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
    echo  [OK] Frontend stopped (PID: %%a).
)

echo.
echo  ========================================
echo   Application shutdown complete.
echo  ========================================
echo.
pause
