#!/bin/bash
set -euo pipefail

# ── pré-requisitos ─────────────────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
    echo "[X] Docker não encontrado. Instale em https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker compose version &>/dev/null 2>&1 && ! docker-compose version &>/dev/null 2>&1; then
    echo "[X] docker compose não encontrado. Atualize o Docker Desktop ou instale o plugin."
    exit 1
fi

# Usa 'docker compose' (v2) ou 'docker-compose' (v1) conforme disponível
COMPOSE="docker compose"
if ! docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker-compose"
fi

# ── iniciar stack ──────────────────────────────────────────────────────────────

$COMPOSE up --build -d

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " SentinelCore SOAR stack iniciado (Docker)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " API:       http://127.0.0.1:8000"
echo " Dashboard: http://127.0.0.1:8000"
echo " Swagger:   http://127.0.0.1:8000/docs"
echo " Health:    http://127.0.0.1:8000/health"
echo ""
echo " Para parar: ./stop_stack.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
