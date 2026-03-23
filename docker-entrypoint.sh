#!/usr/bin/env bash
set -euo pipefail

# Allow running arbitrary commands (e.g. `docker run ... defensia-agent check`)
if [[ "${1:-}" == "defensia-agent" ]]; then
    exec "$@"
fi

CONFIG_DIR="/etc/defensia"
CONFIG_FILE="${CONFIG_DIR}/config.json"
BINARY="/usr/local/bin/defensia-agent"
SERVER_URL="${DEFENSIA_SERVER_URL:-https://defensia.cloud}"
AGENT_NAME="${DEFENSIA_AGENT_NAME:-$(hostname -s)}"

# ── Resolve token (supports Docker secrets via _FILE suffix) ──────────────────
if [[ -z "${DEFENSIA_TOKEN:-}" ]] && [[ -n "${DEFENSIA_TOKEN_FILE:-}" ]] && [[ -f "$DEFENSIA_TOKEN_FILE" ]]; then
    DEFENSIA_TOKEN="$(cat "$DEFENSIA_TOKEN_FILE")"
    export DEFENSIA_TOKEN
fi

# ── Register if not already configured ────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -z "${DEFENSIA_TOKEN:-}" ]]; then
        echo "[defensia] ERROR: DEFENSIA_TOKEN is required for first-time registration."
        echo "[defensia] Set it via: docker run -e DEFENSIA_TOKEN=<your-token> ..."
        echo "[defensia] Or use Docker secrets: DEFENSIA_TOKEN_FILE=/run/secrets/defensia_token"
        exit 1
    fi

    mkdir -p "$CONFIG_DIR"
    echo "[defensia] Registering agent '${AGENT_NAME}' with ${SERVER_URL}..."
    "$BINARY" register "$SERVER_URL" "$AGENT_NAME" "$DEFENSIA_TOKEN"
    echo "[defensia] Registration complete."
fi

# ── Start agent ───────────────────────────────────────────────────────────────
echo "[defensia] Starting agent..."
exec "$BINARY" start
