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

# ── Resolve secrets (supports Docker secrets via _FILE suffix) ────────────────
if [[ -z "${DEFENSIA_TOKEN:-}" ]] && [[ -n "${DEFENSIA_TOKEN_FILE:-}" ]] && [[ -f "$DEFENSIA_TOKEN_FILE" ]]; then
    DEFENSIA_TOKEN="$(cat "$DEFENSIA_TOKEN_FILE")"
    export DEFENSIA_TOKEN
fi

if [[ -z "${DEFENSIA_API_KEY:-}" ]] && [[ -n "${DEFENSIA_API_KEY_FILE:-}" ]] && [[ -f "$DEFENSIA_API_KEY_FILE" ]]; then
    DEFENSIA_API_KEY="$(cat "$DEFENSIA_API_KEY_FILE")"
    export DEFENSIA_API_KEY
fi

# ── Register if not already configured ────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    mkdir -p "$CONFIG_DIR"

    # ── K8s mode: register via API key (multi-use, one key for entire cluster) ──
    if [[ -n "${DEFENSIA_API_KEY:-}" ]]; then
        NODE_NAME="${NODE_NAME:-$(hostname -s)}"
        CLUSTER_NAME="${CLUSTER_NAME:-}"
        OS_INFO="$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2 | tr -d '"' || echo 'Linux')"
        OS_VERSION="$(uname -r)"
        IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '0.0.0.0')"
        AGENT_VERSION="$("$BINARY" version 2>/dev/null || echo 'unknown')"

        echo "[defensia] Registering K8s node '${NODE_NAME}' with ${SERVER_URL}..."

        RESPONSE=$(curl -fsSL -X POST "${SERVER_URL}/api/v1/agents/register-k8s" \
            -H "Content-Type: application/json" \
            -H "User-Agent: DefensiaAgent/${AGENT_VERSION}" \
            -d "{
                \"api_key\": \"${DEFENSIA_API_KEY}\",
                \"name\": \"${NODE_NAME}\",
                \"hostname\": \"${NODE_NAME}\",
                \"ip_address\": \"${IP_ADDR}\",
                \"os\": \"${OS_INFO}\",
                \"os_version\": \"${OS_VERSION}\",
                \"version\": \"${AGENT_VERSION}\",
                \"node_name\": \"${NODE_NAME}\",
                \"cluster_name\": \"${CLUSTER_NAME}\"
            }" 2>&1) || {
            echo "[defensia] ERROR: K8s registration failed."
            echo "[defensia] Response: ${RESPONSE}"
            echo "[defensia] Check: API key is valid, server slots available, server URL reachable."
            exit 1
        }

        # Parse response and write config
        AGENT_TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
        AGENT_ID=$(echo "$RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
        REVERB_URL=$(echo "$RESPONSE" | grep -o '"url":"[^"]*"' | head -1 | cut -d'"' -f4)
        REVERB_KEY=$(echo "$RESPONSE" | grep -o '"app_key":"[^"]*"' | head -1 | cut -d'"' -f4)
        AUTH_ENDPOINT=$(echo "$RESPONSE" | grep -o '"auth_endpoint":"[^"]*"' | head -1 | cut -d'"' -f4)

        if [[ -z "$AGENT_TOKEN" || -z "$AGENT_ID" ]]; then
            echo "[defensia] ERROR: Could not parse registration response."
            echo "[defensia] Response: ${RESPONSE}"
            exit 1
        fi

        cat > "$CONFIG_FILE" << CONF
{
    "server_url": "${SERVER_URL}",
    "agent_token": "${AGENT_TOKEN}",
    "agent_id": ${AGENT_ID},
    "reverb_url": "${REVERB_URL}",
    "reverb_app_key": "${REVERB_KEY}",
    "auth_endpoint": "${AUTH_ENDPOINT}"
}
CONF
        chmod 600 "$CONFIG_FILE"
        echo "[defensia] K8s registration complete (agent_id=${AGENT_ID}, node=${NODE_NAME})."

    # ── Standard mode: register via single-use install token ──────────────────
    elif [[ -n "${DEFENSIA_TOKEN:-}" ]]; then
        echo "[defensia] Registering agent '${AGENT_NAME}' with ${SERVER_URL}..."
        "$BINARY" register "$SERVER_URL" "$AGENT_NAME" "$DEFENSIA_TOKEN"
        echo "[defensia] Registration complete."

    else
        echo "[defensia] ERROR: No credentials provided for registration."
        echo "[defensia]"
        echo "[defensia] For Kubernetes (DaemonSet):"
        echo "[defensia]   Set DEFENSIA_API_KEY (multi-use, one key for the whole cluster)"
        echo "[defensia]   helm install defensia-agent oci://ghcr.io/defensia/charts/defensia-agent --set apiKey=<KEY>"
        echo "[defensia]"
        echo "[defensia] For Docker / bare metal:"
        echo "[defensia]   Set DEFENSIA_TOKEN (single-use install token)"
        echo "[defensia]   docker run -e DEFENSIA_TOKEN=<TOKEN> ghcr.io/defensia/agent"
        echo "[defensia]"
        echo "[defensia] Get credentials at https://defensia.cloud/dashboard"
        exit 1
    fi
fi

# ── Start agent ───────────────────────────────────────────────────────────────
echo "[defensia] Starting agent..."
exec "$BINARY" start
