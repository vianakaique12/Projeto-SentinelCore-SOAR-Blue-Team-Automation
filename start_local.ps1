$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot

# ── helpers ────────────────────────────────────────────────────────────────────

function Write-Step { param([string]$msg) Write-Host "`n[>] $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "    [OK] $msg"   -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    [!]  $msg"   -ForegroundColor Yellow }
function Write-Err  { param([string]$msg) Write-Host "    [X]  $msg"   -ForegroundColor Red }

# ── 1. Python ──────────────────────────────────────────────────────────────────

Write-Step "Verificando Python..."
try {
    $pyver = python --version 2>&1
    Write-Ok $pyver
} catch {
    Write-Err "Python nao encontrado. Instale em https://python.org"
    exit 1
}

# ── 2. .env ────────────────────────────────────────────────────────────────────

Write-Step "Carregando variaveis de ambiente..."
$envFile = Join-Path $ScriptDir ".env"
$envExample = Join-Path $ScriptDir ".env.example"

if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Warn ".env criado a partir de .env.example — edite com suas chaves de API antes de usar."
    } else {
        Write-Warn ".env nao encontrado. Continuando sem ele."
    }
}

if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match "^\s*[^#].*=.*" } | ForEach-Object {
        $parts = $_ -split "=", 2
        $name  = $parts[0].Trim()
        $value = if ($parts.Length -gt 1) { $parts[1].Trim() } else { "" }
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
    Write-Ok ".env carregado"
}

# ── 3. Dependencias ────────────────────────────────────────────────────────────

Write-Step "Instalando dependencias Python..."
$reqFile = Join-Path $ScriptDir "requirements.txt"
if (Test-Path $reqFile) {
    python -m pip install -q -r $reqFile
    Write-Ok "Dependencias instaladas"
} else {
    Write-Warn "requirements.txt nao encontrado — pulando."
}

# ── 4. Redis (opcional) ────────────────────────────────────────────────────────

Write-Step "Verificando Redis..."
$redisAvailable = $false

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect("127.0.0.1", 6379)
    $tcpClient.Close()
    $redisAvailable = $true
    Write-Ok "Redis disponivel em 127.0.0.1:6379"
} catch {
    Write-Warn "Redis NAO encontrado em 127.0.0.1:6379"
    Write-Warn "O endpoint /analyze (sincrono) funciona normalmente sem Redis."
    Write-Warn "Para usar /analyze/async, instale Redis via WSL2 ou Memurai (https://www.memurai.com)."
}

# ── 5. API ─────────────────────────────────────────────────────────────────────

Write-Step "Iniciando API (uvicorn)..."
$apiLog = Join-Path $ScriptDir "logs\api.log"
New-Item -ItemType Directory -Force -Path (Join-Path $ScriptDir "logs") | Out-Null

$apiProc = Start-Process python `
    -ArgumentList "-m", "uvicorn", "mini_soar_api:app", "--host", "127.0.0.1", "--port", "8000" `
    -WorkingDirectory $ScriptDir `
    -RedirectStandardOutput $apiLog `
    -RedirectStandardError  $apiLog `
    -PassThru -WindowStyle Hidden

$apiProc.Id | Out-File (Join-Path $ScriptDir ".pid_api") -Encoding utf8
Write-Ok "API iniciada (PID $($apiProc.Id)) — log: logs\api.log"

# ── 6. Worker RQ (so se Redis disponivel) ──────────────────────────────────────

if ($redisAvailable) {
    Write-Step "Iniciando Worker RQ..."
    $workerLog = Join-Path $ScriptDir "logs\worker.log"

    $workerProc = Start-Process python `
        -ArgumentList "mini_soar_worker.py" `
        -WorkingDirectory $ScriptDir `
        -RedirectStandardOutput $workerLog `
        -RedirectStandardError  $workerLog `
        -PassThru -WindowStyle Hidden

    $workerProc.Id | Out-File (Join-Path $ScriptDir ".pid_worker") -Encoding utf8
    Write-Ok "Worker iniciado (PID $($workerProc.Id)) — log: logs\worker.log"
} else {
    Write-Warn "Worker RQ nao iniciado (Redis indisponivel)."
}

# ── 7. Aguarda API subir ───────────────────────────────────────────────────────

Write-Step "Aguardando API ficar pronta..."
$attempts = 0
$ready = $false
while ($attempts -lt 15) {
    Start-Sleep -Seconds 1
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    $attempts++
}

if ($ready) {
    Write-Ok "API respondendo em http://127.0.0.1:8000"
} else {
    Write-Warn "API pode ainda estar subindo. Verifique logs\api.log se houver erro."
}

# ── 8. Resumo ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host " Mini SOAR rodando localmente (sem Docker)"   -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host " API:     http://127.0.0.1:8000"
Write-Host " Swagger: http://127.0.0.1:8000/docs"
Write-Host " Health:  http://127.0.0.1:8000/health"
Write-Host " Logs:    .\logs\"
Write-Host ""
Write-Host " Para parar: .\stop_local.ps1" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
