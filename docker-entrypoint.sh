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

# `defensia-agent register` exits 78 (EX_CONFIG) when the panel rejected the
# token itself (spent, expired, unknown, plan limit). Retrying cannot help.
EXIT_REGISTER_REJECTED=78
IDLE_CHECK_INTERVAL=60
IDLE_REMINDER_INTERVAL=600

# Exit cleanly on `docker stop` even while sleeping (bash as PID 1 ignores
# SIGTERM unless it is trapped).
trap 'echo "[defensia] Stopping."; exit 0' TERM INT

# pause N — sleep that a trapped signal can interrupt.
pause() {
    sleep "$1" &
    wait $! || true
}

warn_if_config_not_persisted() {
    if ! grep -q " ${CONFIG_DIR} " /proc/self/mountinfo 2>/dev/null; then
        echo "[defensia] WARNING: ${CONFIG_DIR} is not a mounted volume, so the agent config is not persisted."
        echo "[defensia]          Install tokens are single-use: recreating this container will need a new token."
        echo "[defensia]          Add -v ${CONFIG_DIR}:${CONFIG_DIR} to docker run (or a volume in compose)."
    fi
}

# Where to remember a token the panel rejected: the config dir when writable,
# otherwise /tmp. Both survive `docker restart`; neither survives a recreate.
rejected_marker_path() {
    if [[ -w "$CONFIG_DIR" ]]; then
        echo "${CONFIG_DIR}/.rejected-token"
    else
        echo "/tmp/.defensia-rejected-token"
    fi
}

print_rejected_help() {
    echo "[defensia] ──────────────────────────────────────────────────────────────"
    echo "[defensia] Registration was rejected: the install token was already used,"
    echo "[defensia] has expired or is invalid (or the plan's server limit is reached)."
    echo "[defensia] Retrying with the same token cannot succeed, so the agent is idle."
    echo "[defensia]"
    echo "[defensia] To fix it:"
    echo "[defensia]   1. Generate a new install token at https://defensia.cloud/account/agents"
    echo "[defensia]   2. Recreate this container with the new DEFENSIA_TOKEN and a persisted"
    echo "[defensia]      config volume:  -v ${CONFIG_DIR}:${CONFIG_DIR}"
    echo "[defensia] ──────────────────────────────────────────────────────────────"
}

# Never returns: the agent either starts (config.json appeared, e.g. via a
# `docker exec ... defensia-agent register`) or stays idle. Exiting would not
# help — with `--restart unless-stopped` Docker restarts even on exit 0.
idle_until_configured() {
    print_rejected_help
    local since_reminder=0
    while :; do
        pause "$IDLE_CHECK_INTERVAL"
        if [[ -f "$CONFIG_FILE" ]]; then
            echo "[defensia] Config found at ${CONFIG_FILE} — starting agent..."
            exec "$BINARY" start
        fi
        since_reminder=$((since_reminder + IDLE_CHECK_INTERVAL))
        if [[ "$since_reminder" -ge "$IDLE_REMINDER_INTERVAL" ]]; then
            print_rejected_help
            since_reminder=0
        fi
    done
}

# ── Register if not already configured ────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    mkdir -p "$CONFIG_DIR"

    # ── K8s mode: register via API key (multi-use, one key for entire cluster) ──
    if [[ -n "${DEFENSIA_API_KEY:-}" ]]; then
        NODE_NAME="${NODE_NAME:-$(hostname -s)}"
        CLUSTER_NAME="${CLUSTER_NAME:-}"
        OS_INFO=$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2 | tr -d '"\n' || echo "Linux")
        OS_VERSION=$(uname -r 2>/dev/null | tr -d '\n' || echo "unknown")
        IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' | tr -d '\n' || echo "0.0.0.0")
        AGENT_VERSION="${DEFENSIA_VERSION:-unknown}"

        echo "[defensia] Registering K8s node '${NODE_NAME}' with ${SERVER_URL}..."

        # Build JSON payload (avoid multiline -d issues in Alpine curl)
        PAYLOAD="{\"api_key\":\"${DEFENSIA_API_KEY}\",\"name\":\"${NODE_NAME}\",\"hostname\":\"${NODE_NAME}\",\"ip_address\":\"${IP_ADDR}\",\"os\":\"${OS_INFO}\",\"os_version\":\"${OS_VERSION}\",\"version\":\"${AGENT_VERSION}\",\"node_name\":\"${NODE_NAME}\",\"cluster_name\":\"${CLUSTER_NAME}\"}"

        # API URL: always use api. subdomain (separable from web server)
        API_BASE="${DEFENSIA_API_URL:-$(echo "$SERVER_URL" | sed 's|://|://api.|')}"

        HTTP_CODE=$(curl -sS -o /tmp/register-response.json -w "%{http_code}" \
            -X POST "${API_BASE}/api/v1/agents/register-k8s" \
            -H "Content-Type: application/json" \
            -H "User-Agent: DefensiaAgent/${AGENT_VERSION}" \
            -L --post301 --post302 --post303 \
            -d "${PAYLOAD}" 2>/tmp/register-error.txt)

        RESPONSE=$(cat /tmp/register-response.json 2>/dev/null)
        CURL_ERR=$(cat /tmp/register-error.txt 2>/dev/null)

        if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
            echo "[defensia] ERROR: K8s registration failed (HTTP ${HTTP_CODE})."
            [[ -n "$CURL_ERR" ]] && echo "[defensia] curl: ${CURL_ERR}"
            [[ -n "$RESPONSE" ]] && echo "[defensia] Response: ${RESPONSE}"
            echo "[defensia] API URL: ${API_BASE}/api/v1/agents/register-k8s"
            echo "[defensia] Check: API key is valid, server slots available, server URL reachable."
            exit 1
        fi

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
        warn_if_config_not_persisted

        TOKEN_HASH="$(printf '%s' "$DEFENSIA_TOKEN" | sha256sum | cut -d' ' -f1)"
        MARKER="$(rejected_marker_path)"

        # A token the panel already refused is not sent again: install tokens
        # are single-use, and replaying a spent one on every container start
        # is exactly the loop this guards against. A different token clears it.
        if [[ -f "$MARKER" ]] && [[ "$(cat "$MARKER" 2>/dev/null)" == "$TOKEN_HASH" ]]; then
            echo "[defensia] This DEFENSIA_TOKEN was already rejected by ${SERVER_URL} — not sending it again."
            idle_until_configured
        fi
        rm -f "$MARKER" 2>/dev/null || true

        BACKOFF=30
        while :; do
            echo "[defensia] Registering agent '${AGENT_NAME}' with ${SERVER_URL}..."
            RC=0
            "$BINARY" register "$SERVER_URL" "$AGENT_NAME" "$DEFENSIA_TOKEN" || RC=$?

            if [[ "$RC" -eq 0 ]]; then
                echo "[defensia] Registration complete."
                break
            fi

            if [[ "$RC" -eq "$EXIT_REGISTER_REJECTED" ]]; then
                printf '%s\n' "$TOKEN_HASH" > "$MARKER" 2>/dev/null || true
                idle_until_configured
            fi

            # Transient (network, 5xx, 429): retry here instead of exiting,
            # so a restart policy does not turn an outage into a tight loop.
            echo "[defensia] Registration failed (exit ${RC}), retrying in ${BACKOFF}s..."
            pause "$BACKOFF"
            BACKOFF=60
        done

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
