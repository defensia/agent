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

# ── Resolve secrets (supports Docker secrets and K8s Secrets via _FILE suffix) ─
# A function rather than a one-off block: on Kubernetes the API key arrives from a
# mounted Secret, which can be created after this pod is already running, so the
# idle loop below re-runs this to notice it.
resolve_credentials() {
    # When a _FILE is given it wins over the variable, and is re-read every time
    # rather than only when the variable is empty. That is what lets a corrected
    # key take effect: the operator edits the Secret, kubelet rewrites the mounted
    # file, and the next pass through the idle loop sees the new value. Reading it
    # once would pin the pod to the first key it ever saw, including a bad one.
    if [[ -n "${DEFENSIA_TOKEN_FILE:-}" ]] && [[ -s "$DEFENSIA_TOKEN_FILE" ]]; then
        DEFENSIA_TOKEN="$(tr -d '[:space:]' < "$DEFENSIA_TOKEN_FILE")"
        export DEFENSIA_TOKEN
    fi

    if [[ -n "${DEFENSIA_API_KEY_FILE:-}" ]] && [[ -s "$DEFENSIA_API_KEY_FILE" ]]; then
        DEFENSIA_API_KEY="$(tr -d '[:space:]' < "$DEFENSIA_API_KEY_FILE")"
        export DEFENSIA_API_KEY
    fi
}

resolve_credentials

have_credentials() {
    [[ -n "${DEFENSIA_API_KEY:-}" ]] || [[ -n "${DEFENSIA_TOKEN:-}" ]]
}

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

# Same idea for the organization API key. Kept in its own file because the two
# credentials are independent: a spent install token says nothing about a key.
apikey_marker_path() {
    if [[ -w "$CONFIG_DIR" ]]; then
        echo "${CONFIG_DIR}/.rejected-apikey"
    else
        echo "/tmp/.defensia-rejected-apikey"
    fi
}

hash_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# True when the key we hold is one the panel has already refused. Used to idle on
# a bad key without hammering the API: the watch loop re-reads the mounted Secret
# every minute, and without this a typo'd key would re-register once a minute
# forever. A corrected key hashes differently and clears the block by itself.
apikey_already_rejected() {
    local marker
    marker="$(apikey_marker_path)"
    [[ -f "$marker" ]] && [[ "$(cat "$marker" 2>/dev/null)" == "$(hash_of "${DEFENSIA_API_KEY:-}")" ]]
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

print_apikey_rejected_help() {
    echo "[defensia] ──────────────────────────────────────────────────────────────"
    echo "[defensia] The organization API key was refused (invalid, revoked, or the"
    echo "[defensia] plan has no free server slots). The agent stays up and idle."
    echo "[defensia]"
    echo "[defensia] Replace the key and it is picked up automatically:"
    echo "[defensia]   kubectl -n ${POD_NAMESPACE:-defensia} create secret generic ${DAEMONSET_NAME:-defensia-agent} \\"
    echo "[defensia]     --from-literal=api-key=<ORG_API_KEY> --dry-run=client -o yaml | kubectl apply -f -"
    echo "[defensia]"
    echo "[defensia] Keys and plan limits: https://defensia.cloud/dashboard"
    echo "[defensia] ──────────────────────────────────────────────────────────────"
}

print_unclaimed_help() {
    echo "[defensia] ──────────────────────────────────────────────────────────────"
    echo "[defensia] Installed, but not connected to an organization yet."
    echo "[defensia]"
    echo "[defensia] This is the expected first state for a marketplace or GitOps"
    echo "[defensia] install, where no credential can be supplied at install time."
    echo "[defensia] Nothing has failed. The agent stays up and connects on its own"
    echo "[defensia] as soon as a key appears — no restart, no reinstall."
    echo "[defensia]"
    echo "[defensia] To connect this cluster, from https://defensia.cloud/dashboard:"
    echo "[defensia]   kubectl -n ${POD_NAMESPACE:-defensia} create secret generic ${DAEMONSET_NAME:-defensia-agent} \\"
    echo "[defensia]     --from-literal=api-key=<ORG_API_KEY> --dry-run=client -o yaml | kubectl apply -f -"
    echo "[defensia]"
    echo "[defensia] For Docker or bare metal, set DEFENSIA_TOKEN instead."
    echo "[defensia] ──────────────────────────────────────────────────────────────"
}

# Never returns: the agent either starts (config.json appeared, e.g. via a
# `docker exec ... defensia-agent register`) or stays idle. Exiting would not
# help — with `--restart unless-stopped` Docker restarts even on exit 0.
#   idle_until_configured <help_fn> [watch-for-credentials]
#
# Pass "watch" only when no credential was supplied. Waiting for one to appear is
# right for a pod installed without a key, and wrong after a rejection: the token
# that was refused is still in the environment, so watching would re-send it on a
# loop — the exact thing the rejection marker exists to prevent.
idle_until_configured() {
    local help_fn="$1"
    local watch_credentials="${2:-}"

    "$help_fn"
    local since_reminder=0
    while :; do
        pause "$IDLE_CHECK_INTERVAL"
        if [[ -f "$CONFIG_FILE" ]]; then
            echo "[defensia] Config found at ${CONFIG_FILE} — starting agent..."
            exec "$BINARY" start
        fi

        # A mounted Secret updates in place, so a key created after this pod
        # started shows up here. Re-exec rather than inlining the registration:
        # it is the same path a normal start takes, so there is only one of it.
        if [[ "$watch_credentials" == "watch" ]]; then
            resolve_credentials
            if have_credentials && ! apikey_already_rejected; then
                echo "[defensia] Credentials appeared — registering."
                exec "$0"
            fi
        fi

        since_reminder=$((since_reminder + IDLE_CHECK_INTERVAL))
        if [[ "$since_reminder" -ge "$IDLE_REMINDER_INTERVAL" ]]; then
            "$help_fn"
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
            echo "[defensia] K8s registration failed (HTTP ${HTTP_CODE})."
            [[ -n "$CURL_ERR" ]] && echo "[defensia] curl: ${CURL_ERR}"
            [[ -n "$RESPONSE" ]] && echo "[defensia] Response: ${RESPONSE}"
            echo "[defensia] API URL: ${API_BASE}/api/v1/agents/register-k8s"

            # Split a refusal from an outage. A 4xx means this key will never be
            # accepted — retrying is just noise — so remember it and wait for a
            # different one. Anything else (5xx, 429, DNS, timeouts: HTTP_CODE is
            # 000 when curl never got a reply) is worth retrying, and a pod that
            # exits on a transient failure turns a brief outage into a crash loop
            # across every node at once.
            case "$HTTP_CODE" in
                4*)
                    printf '%s\n' "$(hash_of "${DEFENSIA_API_KEY:-}")" > "$(apikey_marker_path)" 2>/dev/null || true
                    echo "[defensia] This key will not be accepted; waiting for a corrected one."
                    idle_until_configured print_apikey_rejected_help watch
                    ;;
                *)
                    echo "[defensia] Looks temporary — retrying in ${IDLE_CHECK_INTERVAL}s."
                    pause "$IDLE_CHECK_INTERVAL"
                    exec "$0"
                    ;;
            esac
        fi

        # Parse response and write config
        # Tolerate whitespace after the colon, and never let a missing field end
        # the script under `set -euo pipefail`: a grep with no match used to exit
        # the container silently, before the explicit check below could explain.
        json_str() { echo "$RESPONSE" | grep -oE "\"$1\":[[:space:]]*\"[^\"]*\"" | head -1 | sed -E 's/.*"([^"]*)"$/\1/' || true; }
        json_int() { echo "$RESPONSE" | grep -oE "\"$1\":[[:space:]]*[0-9]+" | head -1 | grep -oE '[0-9]+$' || true; }
        AGENT_TOKEN=$(json_str token)
        AGENT_ID=$(json_int id)
        REVERB_URL=$(json_str url)
        REVERB_KEY=$(json_str app_key)
        AUTH_ENDPOINT=$(json_str auth_endpoint)

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
            idle_until_configured print_rejected_help
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
                idle_until_configured print_rejected_help
            fi

            # Transient (network, 5xx, 429): retry here instead of exiting,
            # so a restart policy does not turn an outage into a tight loop.
            echo "[defensia] Registration failed (exit ${RC}), retrying in ${BACKOFF}s..."
            pause "$BACKOFF"
            BACKOFF=60
        done

    else
        # No credential yet — wait for one instead of exiting.
        #
        # Exiting made the agent uninstallable from any catalogue that cannot ask
        # for a key at install time, which is all of them: DigitalOcean's
        # Marketplace runs `helm upgrade --atomic` with a fixed values file and no
        # way to pass a secret, so the pod crash-looped and the release rolled
        # back. Idling turns "no key" into a state a human can resolve afterwards
        # rather than a failed install, and the loop picks the key up on its own
        # when the Secret lands.
        idle_until_configured print_unclaimed_help watch
    fi
fi

# ── Start agent ───────────────────────────────────────────────────────────────
echo "[defensia] Starting agent..."
exec "$BINARY" start
