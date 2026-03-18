$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = $PSScriptRoot

function Stop-PidFile {
    param([string]$label, [string]$pidFile)
    if (Test-Path $pidFile) {
        $pid = Get-Content $pidFile -Raw
        try {
            Stop-Process -Id $pid -Force
            Write-Host "    [OK] $label parado (PID $pid)" -ForegroundColor Green
        } catch {
            Write-Host "    [!]  $label ja estava parado ou PID invalido." -ForegroundColor Yellow
        }
        Remove-Item $pidFile -Force
    } else {
        Write-Host "    [!]  $label — arquivo .pid nao encontrado." -ForegroundColor Yellow
    }
}

Write-Host "`n[>] Parando Mini SOAR local..." -ForegroundColor Cyan
Stop-PidFile "API"    (Join-Path $ScriptDir ".pid_api")
Stop-PidFile "Worker" (Join-Path $ScriptDir ".pid_worker")
Write-Host ""
Write-Host "Mini SOAR local parado." -ForegroundColor White
