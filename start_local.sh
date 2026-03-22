#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── helpers ────────────────────────────────────────────────────────────────────

step()  { echo -e "\n\033[36m[>] $*\033[0m"; }
ok()    { echo -e "    \033[32m[OK] $*\033[0m"; }
warn()  { echo -e "    \033[33m[!]  $*\033[0m"; }
err()   { echo -e "    \033[31m[X]  $*\033[0m"; }

# ── 1. Python ──────────────────────────────────────────────────────────────────

step "Verificando Python..."
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    err "Python não encontrado. Instale em https://python.org"
    exit 1
fi
PYTHON=$(command -v python3 || command -v python)
ok "$($PYTHON --version)"

# ── 2. .env ────────────────────────────────────────────────────────────────────

step "Carregando variáveis de ambiente..."
ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        warn ".env criado a partir de .env.example — edite com suas chaves de API antes de usar."
    else
        warn ".env não encontrado. Continuando sem ele."
    fi
fi

if [ -f "$ENV_FILE" ]; then
    set -o allexport
    # shellcheck disable=SC1090
    source <(grep -E '^\s*[^#].*=.*' "$ENV_FILE")
    set +o allexport
    ok ".env carregado"
fi

# ── 3. Dependências ────────────────────────────────────────────────────────────

step "Instalando dependências Python..."
REQ_FILE="$SCRIPT_DIR/requirements.txt"
if [ -f "$REQ_FILE" ]; then
    "$PYTHON" -m pip install -q -r "$REQ_FILE"
    ok "Dependências instaladas"
else
    warn "requirements.txt não encontrado — pulando."
fi

# ── 4. Redis (opcional) ────────────────────────────────────────────────────────

step "Verificando Redis..."
REDIS_AVAILABLE=false

if command -v redis-cli &>/dev/null && redis-cli -h 127.0.0.1 -p 6379 ping &>/dev/null 2>&1; then
    REDIS_AVAILABLE=true
    ok "Redis disponível em 127.0.0.1:6379"
elif (echo > /dev/tcp/127.0.0.1/6379) 2>/dev/null; then
    REDIS_AVAILABLE=true
    ok "Redis disponível em 127.0.0.1:6379"
else
    warn "Redis NÃO encontrado em 127.0.0.1:6379"
    warn "O endpoint /analyze (síncrono) funciona normalmente sem Redis."
    warn "Para usar /analyze/async, instale Redis: sudo apt install redis-server (Linux) ou brew install redis (Mac)."
fi

# ── 5. API ─────────────────────────────────────────────────────────────────────

step "Iniciando API (uvicorn)..."
mkdir -p "$SCRIPT_DIR/logs"
API_LOG="$SCRIPT_DIR/logs/api.log"

"$PYTHON" -m uvicorn mini_soar_api:app --host 127.0.0.1 --port 8000 \
    > "$API_LOG" 2>&1 &
API_PID=$!
echo "$API_PID" > "$SCRIPT_DIR/.pid_api"
ok "API iniciada (PID $API_PID) — log: logs/api.log"

# ── 6. Worker RQ (só se Redis disponível) ─────────────────────────────────────

if [ "$REDIS_AVAILABLE" = true ]; then
    step "Iniciando Worker RQ..."
    WORKER_LOG="$SCRIPT_DIR/logs/worker.log"

    "$PYTHON" "$SCRIPT_DIR/mini_soar_worker.py" \
        > "$WORKER_LOG" 2>&1 &
    WORKER_PID=$!
    echo "$WORKER_PID" > "$SCRIPT_DIR/.pid_worker"
    ok "Worker iniciado (PID $WORKER_PID) — log: logs/worker.log"
else
    warn "Worker RQ não iniciado (Redis indisponível)."
fi

# ── 7. Aguarda API subir ───────────────────────────────────────────────────────

step "Aguardando API ficar pronta..."
READY=false
for i in $(seq 1 15); do
    sleep 1
    if curl -sf http://127.0.0.1:8000/health > /dev/null 2>&1; then
        READY=true
        break
    fi
done

if [ "$READY" = true ]; then
    ok "API respondendo em http://127.0.0.1:8000"
else
    warn "API pode ainda estar subindo. Verifique logs/api.log se houver erro."
fi

# ── 8. Resumo ──────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " SentinelCore SOAR rodando localmente (sem Docker)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " API:       http://127.0.0.1:8000"
echo " Dashboard: http://127.0.0.1:8000"
echo " Swagger:   http://127.0.0.1:8000/docs"
echo " Health:    http://127.0.0.1:8000/health"
echo " Logs:      ./logs/"
echo ""
echo " Para parar: ./stop_local.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
