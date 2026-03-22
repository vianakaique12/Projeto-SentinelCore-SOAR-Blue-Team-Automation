#!/bin/bash
set -euo pipefail

if ! command -v docker &>/dev/null; then
    echo "[X] Docker não encontrado."
    exit 1
fi

COMPOSE="docker compose"
if ! docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker-compose"
fi

$COMPOSE down

echo "SentinelCore SOAR stack parado."
