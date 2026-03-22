#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok()   { echo -e "    \033[32m[OK] $*\033[0m"; }
warn() { echo -e "    \033[33m[!]  $*\033[0m"; }

stop_pid_file() {
    local label="$1"
    local pid_file="$2"

    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" && ok "$label parado (PID $pid)"
        else
            warn "$label já estava parado ou PID inválido."
        fi
        rm -f "$pid_file"
    else
        warn "$label — arquivo .pid não encontrado."
    fi
}

echo -e "\n\033[36m[>] Parando SentinelCore SOAR local...\033[0m"
stop_pid_file "API"    "$SCRIPT_DIR/.pid_api"
stop_pid_file "Worker" "$SCRIPT_DIR/.pid_worker"
echo ""
echo "SentinelCore SOAR local parado."
