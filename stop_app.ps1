# SentinelTrace V5 — Stop Application (PowerShell)

Write-Host ""
Write-Host " ========================================"
Write-Host "  SENTINELTRACE V5"
Write-Host "  Stopping Application"
Write-Host " ========================================"
Write-Host ""

function Stop-PortProcess {
    param([int]$Port, [string]$Name)
    $connections = netstat -ano | Select-String ":$Port\s" | Select-String "LISTENING"
    if ($connections) {
        $connections | ForEach-Object {
            $parts = $_ -split '\s+'
            $pid = $parts[-1]
            try {
                Stop-Process -Id $pid -Force -ErrorAction Stop
                Write-Host " [OK] $Name stopped (PID: $pid)." -ForegroundColor Green
            } catch {
                Write-Host " [WARN] Could not stop PID $pid : $_" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host " [INFO] $Name not running on port $Port." -ForegroundColor Gray
    }
}

Stop-PortProcess -Port 8000 -Name "Backend"
Stop-PortProcess -Port 5173 -Name "Frontend"

Write-Host ""
Write-Host " ========================================"
Write-Host "  Application shutdown complete."
Write-Host " ========================================"
Write-Host ""
