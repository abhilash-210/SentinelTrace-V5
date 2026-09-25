@echo off
title SentinelTrace V5 - Database Inspector
color 0a

echo =====================================================================
echo           SENTINELTRACE V5 - DATABASE INSPECTOR
echo =====================================================================
echo.
cd /d "%~dp0"
backend\.venv\Scripts\python.exe scratch\view_database.py
echo.
pause
