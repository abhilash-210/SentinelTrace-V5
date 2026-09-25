@echo off
title SentinelTrace V5 - Stopper
color 0c

echo =====================================================================
echo           SENTINELTRACE V5 - STOPPING SERVICES
echo =====================================================================
echo.
echo [*] Terminating servers on ports 8000 (Backend) and 5173 (Frontend)...

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo [*] Killing process on port 8000 (PID: %%a)...
    taskkill /F /PID %%a >nul 2>&1
)

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do (
    echo [*] Killing process on port 5173 (PID: %%a)...
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo =====================================================================
echo  [OK] All SentinelTrace services stopped successfully.
echo =====================================================================
echo.
pause
