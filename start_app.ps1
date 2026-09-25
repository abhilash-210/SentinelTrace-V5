# SentinelTrace V5 — Start Application (PowerShell)
# Universal Log Pre-processing Framework
# SIH 2026 — PS 26156

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"

Write-Host ""
Write-Host " ========================================"
Write-Host "  SENTINELTRACE V5"
Write-Host "  Universal Log Pre-processing Framework"
Write-Host " ========================================"
Write-Host ""

# Check prerequisites
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host " [ERROR] Python not found. Install Python 3.11+ from https://python.org" -ForegroundColor Red
    exit 1
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host " [ERROR] Node.js not found. Install Node.js 18+ from https://nodejs.org" -ForegroundColor Red
    exit 1
}

# Setup Python venv if not present
$VenvPath = Join-Path $Backend ".venv\Scripts\activate.ps1"
if (-not (Test-Path $VenvPath)) {
    Write-Host " [*] Creating Python virtual environment..." -ForegroundColor Cyan
    Set-Location $Backend
    python -m venv .venv
    Write-Host " [*] Installing backend dependencies..." -ForegroundColor Cyan
    & "$Backend\.venv\Scripts\pip.exe" install -r "$Backend\requirements.txt" --quiet
    Write-Host " [OK] Backend dependencies installed." -ForegroundColor Green
}

# Setup npm if not present
if (-not (Test-Path (Join-Path $Frontend "node_modules"))) {
    Write-Host " [*] Installing frontend dependencies..." -ForegroundColor Cyan
    Set-Location $Frontend
    npm install --silent
    Write-Host " [OK] Frontend dependencies installed." -ForegroundColor Green
}

# Start Backend
Write-Host " [*] Starting Backend REST API (port 8000)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Backend'; .venv\Scripts\uvicorn.exe app.main:app --port 8000"

# Start Frontend
Write-Host " [*] Starting Frontend UI (port 5173)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Frontend'; npm run dev"

Start-Sleep -Seconds 5
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host " ========================================"
Write-Host "  SentinelTrace V5 is running!"
Write-Host " ========================================"
Write-Host ""
Write-Host "  Frontend Dashboard : http://localhost:5173"
Write-Host "  Backend API        : http://localhost:8000"
Write-Host "  API Documentation  : http://localhost:8000/docs"
Write-Host ""
Write-Host "  Demo Login:"
Write-Host "    Username : admin_demo"
Write-Host "    Password : SentinelDemo!2026"
Write-Host ""
Write-Host "  Run stop_app.ps1 to shut down all services."
Write-Host " ========================================"
