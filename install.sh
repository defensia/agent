#!/usr/bin/env bash
# Defensia Agent Installer
# Usage: curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <INSTALL_TOKEN>
# Non-interactive: DEFENSIA_SERVER_URL=https://... DEFENSIA_AGENT_NAME=web-01 curl -fsSL ... | sudo bash -s -- --token <TOKEN>
# Install only (no registration): curl -fsSL ... | sudo bash -s -- --install-only
#
# SSL Error fix (old servers — "Peer's Certificate issuer is not recognized"):
#   This happens on CentOS 7 / RHEL 7 and systems with ca-certificates older than 2024.
#   curl on CentOS 7 links against NSS (not OpenSSL), so update-ca-trust has no effect on it.
#   One-time fix — run these THREE commands, then retry the install:
#     curl -sk https://letsencrypt.org/certs/isrgrootx1.pem -o /tmp/isrg.pem
#     export CURL_CA_BUNDLE=/tmp/isrg.pem
#     curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <TOKEN>

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Config ────────────────────────────────────────────────────────────────────
BINARY_NAME="defensia-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/defensia"
SERVICE_NAME="defensia-agent"
INIT_SYSTEM=""
GITHUB_REPO="${GITHUB_REPO:-defensia/agent}"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/${GITHUB_REPO}/releases/latest/download}"

# ─── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[defensia]${NC} $*"; }
success() { echo -e "${GREEN}[defensia]${NC} ✓ $*"; }
warn()    { echo -e "${YELLOW}[defensia]${NC} ! $*"; }
error()   { echo -e "${RED}[defensia]${NC} ✗ $*" >&2; exit 1; }

# Report install progress to the panel (best-effort, never blocks)
report_status() {
    local step="$1"
    local err="${2:-}"
    [[ -z "${INSTALL_TOKEN:-}" ]] && return 0
    local prefix="${INSTALL_TOKEN:0:16}"
    local os_info
    os_info="$(collect_system_info 2>/dev/null || echo unknown)"
    local arch
    arch="$(uname -m 2>/dev/null || echo unknown)"
    local api_url="${DEFENSIA_SERVER_URL:-https://defensia.cloud}"
    # Escape double quotes in error string for JSON safety
    local err_json="null"
    if [[ -n "$err" ]]; then
        err_json="\"$(echo "$err" | sed 's/"/\\"/g' | head -c 500)\""
    fi
    curl -fsSL --max-time 5 -X POST "${api_url}/api/v1/install/status" \
        -H 'Content-Type: application/json' \
        -d "{\"token_prefix\":\"${prefix}\",\"step\":\"${step}\",\"error\":${err_json},\"os\":\"${os_info}\",\"arch\":\"${arch}\"}" \
        >/dev/null 2>&1 || true
}

# ─── Parse args ───────────────────────────────────────────────────────────────
parse_args() {
    INSTALL_TOKEN=""
    INSTALL_ONLY=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)
                INSTALL_TOKEN="${2:-}"
                [[ -n "$INSTALL_TOKEN" ]] || error "--token requires a value."
                shift 2
                ;;
            --install-only)
                INSTALL_ONLY=true
                shift
                ;;
            --uninstall)
                check_root
                uninstall
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
}

# ─── Checks ────────────────────────────────────────────────────────────────────
check_root() {
    [[ $EUID -eq 0 ]] || error "This script must be run as root. Try: sudo bash"
}

check_os() {
    [[ "$(uname -s)" == "Linux" ]] || error "Defensia Agent only supports Linux."
}

detect_init() {
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif command -v initctl &>/dev/null && initctl --version 2>/dev/null | grep -q upstart; then
        INIT_SYSTEM="upstart"
    elif [[ -d /etc/init.d ]]; then
        INIT_SYSTEM="sysvinit"
    else
        error "No supported init system found (systemd, upstart, or sysvinit)."
    fi
    info "Init system: ${INIT_SYSTEM}"
}

detect_auth_log() {
    if [[ -f /var/log/auth.log ]]; then
        echo "/var/log/auth.log"
    elif [[ -f /var/log/secure ]]; then
        echo "/var/log/secure"
    else
        echo "/var/log/auth.log"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)          echo "amd64" ;;
        aarch64|arm64)   echo "arm64" ;;
        *)               error "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64." ;;
    esac
}

collect_system_info() {
    local os_info=""
    if [[ -f /etc/os-release ]]; then
        os_info="$(. /etc/os-release && echo "${PRETTY_NAME:-${ID} ${VERSION_ID}}")"
    elif [[ -f /etc/lsb-release ]]; then
        os_info="$(. /etc/lsb-release && echo "${DISTRIB_DESCRIPTION:-${DISTRIB_ID} ${DISTRIB_RELEASE}}")"
    else
        os_info="$(uname -sr)"
    fi
    echo "$os_info"
}

dep_install_failed() {
    local err_log="$1"
    local os_info
    os_info="$(collect_system_info)"

    echo ""
    echo -e "${RED}${BOLD}  ✗ Dependency installation failed${NC}"
    echo -e "  ─────────────────────────────────"
    echo ""
    echo -e "  This usually happens on servers with outdated or broken"
    echo -e "  package repositories (e.g. EOL distributions)."
    echo ""
    echo -e "  ${BOLD}You can try manually:${NC}"
    echo -e "    apt-get update --fix-missing && apt-get install -y ca-certificates curl iptables"
    echo -e "    ${CYAN}# Then re-run the installer${NC}"
    echo ""
    echo -e "  ${BOLD}If the problem persists, open a support ticket at:${NC}"
    echo -e "  ${CYAN}https://defensia.cloud/tickets/create${NC}"
    echo ""
    echo -e "  Please include this info:"
    echo -e "  ┌──────────────────────────────────────"
    echo -e "  │ OS:   ${os_info}"
    echo -e "  │ Arch: $(uname -m)"
    echo -e "  │ Kernel: $(uname -r)"
    echo -e "  │ Init: ${INIT_SYSTEM:-unknown}"
    echo -e "  │ Error: ${err_log}"
    echo -e "  └──────────────────────────────────────"
    echo ""
    exit 1
}

check_deps() {
    local missing=()
    for cmd in curl iptables; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    # Only add ca-certificates if not already installed
    if command -v dpkg &>/dev/null; then
        dpkg -s ca-certificates &>/dev/null || missing+=("ca-certificates")
    elif command -v rpm &>/dev/null; then
        rpm -q ca-certificates &>/dev/null || missing+=("ca-certificates")
    else
        missing+=("ca-certificates")
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi

    warn "Installing/updating dependencies: ${missing[*]}"
    local err_output=""
    if command -v apt-get &>/dev/null; then
        # Fix broken packages first (common on old servers)
        dpkg --configure -a --force-confdef &>/dev/null || true
        # apt-get update may fail on servers with broken/EOL repos — try anyway
        err_output="$(apt-get update -qq 2>&1)" || true
        if ! apt-get install -y -qq --fix-broken "${missing[@]}" 2>&1; then
            dep_install_failed "apt-get install failed — $(echo "$err_output" | grep -E '^(E:|W:)' | head -3 | tr '\n' ' ')"
        fi
    elif command -v yum &>/dev/null; then
        if ! yum install -y -q "${missing[@]}" 2>/dev/null; then
            dep_install_failed "yum install failed"
        fi
    elif command -v dnf &>/dev/null; then
        if ! dnf install -y -q "${missing[@]}" 2>/dev/null; then
            dep_install_failed "dnf install failed"
        fi
    else
        dep_install_failed "No package manager found (apt-get, yum, dnf)"
    fi
}

# ─── SSL Bootstrap ─────────────────────────────────────────────────────────────
# On CentOS 7 / RHEL 7, curl is linked against NSS (which already has ISRG Root X1),
# so curl works fine — but the Go agent binary uses the OpenSSL system bundle
# (/etc/pki/tls/certs/ca-bundle.crt) which may be missing ISRG Root X1.
# We detect RHEL/CentOS by the presence of update-ca-trust and always bootstrap there.
# On other distros we only bootstrap when curl itself fails (exit 60).
bootstrap_ssl() {
    # Respect an already-set CA bundle (e.g. user set CURL_CA_BUNDLE manually)
    [[ -n "${CURL_CA_BUNDLE:-}" ]] && return 0

    # Quick SSL test — exit code 60 = CURLE_SSL_CACERT (cert not recognized by curl)
    local curl_exit=0
    curl -fsSL --max-time 10 -o /dev/null "https://defensia.cloud/" 2>/dev/null \
        || curl_exit=$?

    # On non-RHEL systems: only bootstrap if curl itself can't verify the cert
    local is_rhel=false
    command -v update-ca-trust &>/dev/null && is_rhel=true

    if [[ "$is_rhel" == false ]]; then
        [[ $curl_exit -eq 0 ]] && return 0   # curl happy, not RHEL — nothing to do
        [[ $curl_exit -ne 60 ]] && return 0  # different curl error (network, etc.)
    fi
    # On RHEL/CentOS: always inject — curl may use NSS (works) but Go uses OpenSSL bundle (may fail)
    # Skip only if curl returned a non-SSL error (network unreachable, etc.)
    if [[ "$is_rhel" == true ]] && [[ $curl_exit -ne 0 ]] && [[ $curl_exit -ne 60 ]]; then
        return 0
    fi

    warn "Bootstrapping Let's Encrypt root CA (Go agent needs ISRG Root X1 in OpenSSL bundle)..."

    local ca_tmp
    ca_tmp="$(mktemp /tmp/defensia-isrg-XXXXXX.pem 2>/dev/null)" || {
        warn "Could not create temp file — install may fail if SSL issues persist."
        return 0
    }

    # Download ISRG Root X1 using -k (we can't verify LE yet, this is the bootstrap)
    if ! curl -fsSk --max-time 15 \
            "https://letsencrypt.org/certs/isrgrootx1.pem" \
            -o "$ca_tmp" 2>/dev/null \
        || ! grep -q "BEGIN CERTIFICATE" "$ca_tmp" 2>/dev/null; then
        warn "Could not download Let's Encrypt root CA — install may fail. Manual fix:"
        warn "  curl -sk https://letsencrypt.org/certs/isrgrootx1.pem -o /tmp/isrg.pem"
        warn "  export CURL_CA_BUNDLE=/tmp/isrg.pem && re-run installer"
        rm -f "$ca_tmp"
        return 0
    fi

    # Build a permanent merged bundle (system CAs + ISRG Root X1).
    # We save it to CONFIG_DIR so the systemd service can reference it via Environment=SSL_CERT_FILE.
    # Create CONFIG_DIR early — registration will also create it, but we need it now.
    mkdir -p "$CONFIG_DIR" 2>/dev/null || true

    local sys_bundle="" permanent_bundle="${CONFIG_DIR}/ca-bundle.pem"
    for f in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt /etc/ssl/ca-bundle.pem; do
        [[ -f "$f" ]] && sys_bundle="$f" && break
    done
    if [[ -n "$sys_bundle" ]] && cat "$sys_bundle" "$ca_tmp" > "$permanent_bundle" 2>/dev/null; then
        export SSL_CERT_FILE="$permanent_bundle"
        # Signal to install_service_systemd() to add SSL_CERT_FILE to the service environment.
        # systemd services do not inherit shell exports — we must bake it into the unit file.
        _SSL_CA_ENV="Environment=SSL_CERT_FILE=${permanent_bundle}"
    fi

    # Inject into the system bundle so Go binaries trust it too (permanent fix).
    if command -v update-ca-trust &>/dev/null; then
        # RHEL/CentOS: inject via update-ca-trust (also updates NSS for future curl calls)
        cp "$ca_tmp" /etc/pki/ca-trust/source/anchors/isrg-root-x1.crt 2>/dev/null && \
            update-ca-trust extract 2>/dev/null || true
        # DO NOT set CURL_CA_BUNDLE on RHEL/CentOS: curl uses NSS which already has all CAs.
        # Setting CURL_CA_BUNDLE would replace NSS with only ISRG Root X1, breaking github.com etc.
    elif [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
        # Debian/Ubuntu: append to system bundle
        cat "$ca_tmp" >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
        # On non-RHEL that needed bootstrap: use merged bundle for curl (NOT just ISRG alone)
        [[ -n "${SSL_CERT_FILE:-}" ]] && export CURL_CA_BUNDLE="$SSL_CERT_FILE" \
            || export CURL_CA_BUNDLE="$ca_tmp"
    fi

    # shellcheck disable=SC2064
    trap "rm -f '$ca_tmp'" EXIT

    success "Let's Encrypt root CA bootstrapped — HTTPS verification active for this session."
}

# ─── Download ──────────────────────────────────────────────────────────────────
download_binary() {
    local arch="$1"
    local url="${RELEASE_BASE}/${BINARY_NAME}-linux-${arch}"
    local tmp
    tmp="$(mktemp)"

    info "Downloading ${BINARY_NAME} (${arch}) from ${url}..."

    if ! curl -fsSL --progress-bar -o "$tmp" "$url"; then
        rm -f "$tmp"
        local os_info
        os_info="$(collect_system_info)"
        echo ""
        echo -e "${RED}${BOLD}  ✗ Download failed${NC}"
        echo -e "  ──────────────────"
        echo ""
        echo -e "  Could not download the agent binary from:"
        echo -e "  ${url}"
        echo ""
        echo -e "  This may be caused by:"
        echo -e "  • No internet connectivity"
        echo -e "  • Outdated CA certificates (try: apt-get install -y ca-certificates)"
        echo -e "  • Firewall blocking github.com"
        echo ""
        echo -e "  ${BOLD}If the problem persists, open a support ticket at:${NC}"
        echo -e "  ${CYAN}https://defensia.cloud/tickets/create${NC}"
        echo ""
        echo -e "  Please include this info:"
        echo -e "  ┌──────────────────────────────────────"
        echo -e "  │ OS:   ${os_info}"
        echo -e "  │ Arch: $(uname -m)"
        echo -e "  │ Kernel: $(uname -r)"
        echo -e "  │ Error: Download failed from ${url}"
        echo -e "  └──────────────────────────────────────"
        echo ""
        report_status "download_failed" "Download failed from ${url}"
        exit 1
    fi

    # Verify checksum if available
    local checksum_url="${RELEASE_BASE}/${BINARY_NAME}-linux-${arch}.sha256"
    if curl -fsSL -o "${tmp}.sha256" "$checksum_url" 2>/dev/null; then
        local expected actual
        expected="$(awk '{print $1}' "${tmp}.sha256")"
        actual="$(sha256sum "$tmp" | awk '{print $1}')"
        [[ "$expected" == "$actual" ]] || error "Checksum mismatch. Binary may be corrupted."
        success "Checksum verified."
        rm -f "${tmp}.sha256"
    fi

    chmod +x "$tmp"
    mv "$tmp" "${INSTALL_DIR}/${BINARY_NAME}"
    success "Binary installed at ${INSTALL_DIR}/${BINARY_NAME}"
    report_status "download_ok"
}

# ─── Registration ──────────────────────────────────────────────────────────────
prompt_config() {
    local server_url="${DEFENSIA_SERVER_URL:-}"
    local agent_name="${DEFENSIA_AGENT_NAME:-}"

    if [[ -z "$server_url" ]]; then
        echo ""
        read -rp "$(echo -e "${BOLD}Defensia server URL${NC} [e.g. https://panel.example.com]: ")" server_url
    fi

    [[ -n "$server_url" ]] || error "Server URL is required."
    # Strip trailing slash
    server_url="${server_url%/}"

    if [[ -z "$agent_name" ]]; then
        local default_name
        default_name="$(hostname -s)"
        read -rp "$(echo -e "${BOLD}Agent name${NC} [${default_name}]: ")" agent_name
        agent_name="${agent_name:-$default_name}"
    fi

    echo "$server_url"$'\n'"$agent_name"
}

register_agent() {
    local server_url="$1"
    local agent_name="$2"
    local install_token="$3"

    info "Registering agent '${agent_name}' with ${server_url}..."

    if ! DEFENSIA_CONFIG="${CONFIG_DIR}/config.json" \
        "${INSTALL_DIR}/${BINARY_NAME}" register "$server_url" "$agent_name" "$install_token"; then
        local os_info
        os_info="$(collect_system_info)"
        echo ""
        echo -e "${RED}${BOLD}  ✗ Registration failed${NC}"
        echo -e "  ──────────────────────"
        echo ""
        echo -e "  Could not register agent '${agent_name}' with ${server_url}"
        echo ""
        echo -e "  Common causes:"
        echo -e "  • Invalid or expired install token"
        echo -e "  • Server URL is unreachable"
        echo -e "  • Server limit reached for your plan"
        echo ""
        echo -e "  ${BOLD}If the problem persists, open a support ticket at:${NC}"
        echo -e "  ${CYAN}https://defensia.cloud/tickets/create${NC}"
        echo ""
        echo -e "  Please include this info:"
        echo -e "  ┌──────────────────────────────────────"
        echo -e "  │ OS:   ${os_info}"
        echo -e "  │ Arch: $(uname -m)"
        echo -e "  │ Kernel: $(uname -r)"
        echo -e "  │ Server: ${server_url}"
        echo -e "  │ Error: Registration failed"
        echo -e "  └──────────────────────────────────────"
        echo ""
        report_status "register_failed" "Registration failed with ${server_url}"
        exit 1
    fi

    success "Agent registered. Token saved to ${CONFIG_DIR}/config.json"
    report_status "register_ok"
}

# ─── Service install ──────────────────────────────────────────────────────────
install_service() {
    local auth_log
    auth_log="$(detect_auth_log)"

    # Install recovery script for systemd (auto-heals corrupted binaries)
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        install_recovery_script
    fi

    case "$INIT_SYSTEM" in
        systemd)
            install_service_systemd "$auth_log"
            ;;
        upstart)
            install_service_upstart "$auth_log"
            ;;
        sysvinit)
            install_service_sysvinit "$auth_log"
            ;;
    esac
}

install_recovery_script() {
    info "Installing recovery script..."
    cat > "${INSTALL_DIR}/defensia-agent-recover.sh" <<'RECOVEREOF'
#!/usr/bin/env bash
# Defensia Agent Recovery Script
# Called by systemd ExecStartPre to verify the binary before starting.
# If the binary is corrupted or missing, attempts recovery:
#   1. Restore from backup (.bak)
#   2. Download fresh binary from GitHub releases

BINARY="/usr/local/bin/defensia-agent"
BACKUP="/usr/local/bin/defensia-agent.bak"
GITHUB_REPO="defensia/agent"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download"
MARKER="/tmp/defensia-agent-recovered"

log_msg() {
    if command -v systemd-cat >/dev/null 2>&1; then
        echo "[defensia-recover] $*" | systemd-cat -t defensia-agent -p info
    fi
    echo "[defensia-recover] $*"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             echo "amd64" ;;
    esac
}

verify_binary() {
    local bin="$1"
    [[ -f "$bin" ]] || return 1
    [[ -x "$bin" ]] || return 1
    timeout 10 "$bin" check >/dev/null 2>&1
}

restore_from_backup() {
    [[ -f "$BACKUP" ]] || return 1
    if verify_binary "$BACKUP"; then
        log_msg "restoring from backup $BACKUP"
        cp "$BACKUP" "${BINARY}.recover"
        chmod 755 "${BINARY}.recover"
        mv "${BINARY}.recover" "$BINARY"
        if verify_binary "$BINARY"; then
            log_msg "backup restore successful"
            echo "backup" > "$MARKER"
            rm -f /tmp/defensia-agent-crash-count
            return 0
        fi
    fi
    return 1
}

download_fresh() {
    command -v curl >/dev/null 2>&1 || return 1
    local arch
    arch="$(detect_arch)"
    local url="${RELEASE_URL}/defensia-agent-linux-${arch}"
    local checksum_url="${url}.sha256"
    local tmp
    tmp="$(mktemp)"

    log_msg "downloading fresh binary from ${url}"

    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$tmp" "$url" 2>/dev/null; then
        rm -f "$tmp"
        log_msg "download failed"
        return 1
    fi

    # Verify checksum if available
    if curl -fsSL --connect-timeout 10 -o "${tmp}.sha256" "$checksum_url" 2>/dev/null; then
        local expected actual
        expected="$(awk '{print $1}' "${tmp}.sha256")"
        actual="$(sha256sum "$tmp" | awk '{print $1}')"
        rm -f "${tmp}.sha256"
        if [[ "$expected" != "$actual" ]]; then
            log_msg "checksum mismatch — aborting download recovery"
            rm -f "$tmp"
            return 1
        fi
        log_msg "checksum verified"
    fi

    chmod 755 "$tmp"

    if ! verify_binary "$tmp"; then
        rm -f "$tmp"
        log_msg "downloaded binary failed verification"
        return 1
    fi

    mv "$tmp" "$BINARY"
    log_msg "fresh binary installed successfully"
    echo "download" > "$MARKER"
    rm -f /tmp/defensia-agent-crash-count
    return 0
}

# --- Main ---
if verify_binary "$BINARY"; then
    exit 0
fi

log_msg "binary verification failed — attempting recovery"

if restore_from_backup; then
    exit 0
fi

if download_fresh; then
    exit 0
fi

log_msg "all recovery methods failed — manual intervention needed"
# Exit 0 anyway — if we exit 1, systemd won't attempt to start at all.
exit 0
RECOVEREOF

    chmod +x "${INSTALL_DIR}/defensia-agent-recover.sh"
    success "Recovery script installed at ${INSTALL_DIR}/defensia-agent-recover.sh"
}

install_service_systemd() {
    local auth_log="$1"
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    info "Installing systemd service..."

    # If bootstrap_ssl injected a CA bundle (e.g. CentOS 7), bake SSL_CERT_FILE into the unit.
    # systemd services do not inherit shell exports, so we must declare it explicitly.
    local ssl_ca_env="${_SSL_CA_ENV:-}"

    cat > "$service_file" <<EOF
[Unit]
Description=Defensia Security Agent
Documentation=https://defensia.com/docs/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=${INSTALL_DIR}/defensia-agent-recover.sh
ExecStart=${INSTALL_DIR}/${BINARY_NAME} start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
Environment=DEFENSIA_CONFIG=${CONFIG_DIR}/config.json
Environment=AUTH_LOG_PATH=${auth_log}
${ssl_ca_env}

# Security hardening
NoNewPrivileges=no
PrivateTmp=yes
ProtectSystem=false
ProtectHome=no

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"

    if [[ "$INSTALL_ONLY" == true ]]; then
        success "Service installed and enabled (not started — no token configured)."
    else
        systemctl start "${SERVICE_NAME}"
        success "Service enabled and started."
    fi
}

install_service_upstart() {
    local auth_log="$1"
    local conf_file="/etc/init/${SERVICE_NAME}.conf"
    info "Installing Upstart service..."

    cat > "$conf_file" <<EOF
description "Defensia Security Agent"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 30

env DEFENSIA_CONFIG=${CONFIG_DIR}/config.json
env AUTH_LOG_PATH=${auth_log}

exec ${INSTALL_DIR}/${BINARY_NAME} start
EOF

    if [[ "$INSTALL_ONLY" == true ]]; then
        success "Service installed (not started — no token configured)."
    else
        initctl start "${SERVICE_NAME}" || true
        success "Service started."
    fi
}

install_service_sysvinit() {
    local auth_log="$1"
    local init_script="/etc/init.d/${SERVICE_NAME}"
    info "Installing SysVinit service..."

    cat > "$init_script" <<'INITEOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          defensia-agent
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Defensia Security Agent
### END INIT INFO

DAEMON=INSTALL_DIR_PLACEHOLDER/defensia-agent
PIDFILE=/var/run/defensia-agent.pid
export DEFENSIA_CONFIG=CONFIG_DIR_PLACEHOLDER/config.json
export AUTH_LOG_PATH=AUTH_LOG_PLACEHOLDER

case "$1" in
    start)
        echo "Starting defensia-agent..."
        start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" --exec "$DAEMON" -- start
        ;;
    stop)
        echo "Stopping defensia-agent..."
        start-stop-daemon --stop --pidfile "$PIDFILE" --retry 10
        rm -f "$PIDFILE"
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "defensia-agent is running (PID $(cat "$PIDFILE"))"
        else
            echo "defensia-agent is not running"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
INITEOF

    # Replace placeholders
    sed -i "s|INSTALL_DIR_PLACEHOLDER|${INSTALL_DIR}|g" "$init_script"
    sed -i "s|CONFIG_DIR_PLACEHOLDER|${CONFIG_DIR}|g" "$init_script"
    sed -i "s|AUTH_LOG_PLACEHOLDER|${auth_log}|g" "$init_script"

    chmod +x "$init_script"
    update-rc.d "${SERVICE_NAME}" defaults 2>/dev/null || true

    if [[ "$INSTALL_ONLY" == true ]]; then
        success "Service installed (not started — no token configured)."
    else
        "$init_script" start
        success "Service started."
    fi
}

check_service() {
    sleep 2
    case "$INIT_SYSTEM" in
        systemd)
            if systemctl is-active --quiet "${SERVICE_NAME}"; then
                success "Agent is running!"
                report_status "service_started"
                echo ""
                systemctl status "${SERVICE_NAME}" --no-pager -l | head -15
            else
                warn "Service may not have started correctly. Check logs:"
                echo "  journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
                report_status "service_failed" "systemd service not active"
            fi
            ;;
        upstart)
            if initctl status "${SERVICE_NAME}" 2>/dev/null | grep -q "running"; then
                success "Agent is running!"
                report_status "service_started"
                initctl status "${SERVICE_NAME}"
            else
                warn "Service may not have started correctly. Check logs:"
                echo "  cat /var/log/syslog | grep ${SERVICE_NAME}"
                report_status "service_failed" "upstart service not running"
            fi
            ;;
        sysvinit)
            if "/etc/init.d/${SERVICE_NAME}" status 2>/dev/null; then
                success "Agent is running!"
                report_status "service_started"
            else
                warn "Service may not have started correctly. Check logs:"
                echo "  cat /var/log/syslog | grep ${SERVICE_NAME}"
                report_status "service_failed" "sysvinit service not running"
            fi
            ;;
    esac
}

# ─── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    info "Uninstalling Defensia Agent..."

    # Try all init systems — safe even if only one is present
    if command -v systemctl &>/dev/null; then
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload 2>/dev/null || true
    fi
    if command -v initctl &>/dev/null; then
        initctl stop "${SERVICE_NAME}" 2>/dev/null || true
        rm -f "/etc/init/${SERVICE_NAME}.conf"
    fi
    if [[ -f "/etc/init.d/${SERVICE_NAME}" ]]; then
        "/etc/init.d/${SERVICE_NAME}" stop 2>/dev/null || true
        update-rc.d -f "${SERVICE_NAME}" remove 2>/dev/null || true
        rm -f "/etc/init.d/${SERVICE_NAME}"
    fi

    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f "${INSTALL_DIR}/${BINARY_NAME}.bak"
    rm -f "${INSTALL_DIR}/defensia-agent-recover.sh"
    rm -f /tmp/defensia-agent-crash-count
    rm -f /tmp/defensia-agent-recovered
    rm -rf "$CONFIG_DIR"

    success "Defensia Agent uninstalled."
}

# ─── Main ──────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    # Require install token unless --install-only
    if [[ "$INSTALL_ONLY" != true ]] && [[ -z "$INSTALL_TOKEN" ]]; then
        error "Install token is required. Usage: curl -fsSL .../install.sh | sudo bash -s -- --token <TOKEN>"
    fi

    echo ""
    echo -e "${BOLD}  Defensia Agent Installer${NC}"
    echo    "  ─────────────────────────"
    echo ""

    check_root
    check_os
    detect_init
    report_status "started"
    bootstrap_ssl

    local arch
    arch="$(detect_arch)"
    info "Detected: Linux ${arch}"

    check_deps

    # Create config directory
    mkdir -p "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"

    # Download binary
    download_binary "$arch"

    # --install-only: install binary + systemd service, skip registration
    if [[ "$INSTALL_ONLY" == true ]]; then
        install_service
        echo ""
        echo -e "${GREEN}${BOLD}  Defensia Agent installed (binary only).${NC}"
        echo ""
        echo "  To activate, register with your Defensia token:"
        echo "    ${BINARY_NAME} register https://defensia.cloud <AGENT_NAME> <TOKEN>"
        case "$INIT_SYSTEM" in
            systemd)  echo "    systemctl start ${SERVICE_NAME}" ;;
            upstart)  echo "    initctl start ${SERVICE_NAME}" ;;
            sysvinit) echo "    /etc/init.d/${SERVICE_NAME} start" ;;
        esac
        echo ""
        echo "  Get your token at: https://defensia.cloud/dashboard"
        echo ""
        exit 0
    fi

    # Already installed? Re-register?
    if [[ -f "${CONFIG_DIR}/config.json" ]]; then
        warn "Existing config found at ${CONFIG_DIR}/config.json"
        read -rp "Re-register agent? [y/N]: " answer
        if [[ "${answer,,}" != "y" ]]; then
            install_service
            check_service
            exit 0
        fi
    fi

    # Get server URL and agent name
    local config
    config="$(prompt_config)"
    local server_url agent_name
    server_url="$(echo "$config" | head -1)"
    agent_name="$(echo "$config" | tail -1)"

    # Register with install token
    register_agent "$server_url" "$agent_name" "$INSTALL_TOKEN"

    # Install systemd service
    install_service

    # Verify
    check_service

    echo ""
    echo -e "${GREEN}${BOLD}  Defensia Agent installed successfully!${NC}"
    echo ""
    echo "  Useful commands:"
    case "$INIT_SYSTEM" in
        systemd)
            echo "    systemctl status ${SERVICE_NAME}"
            echo "    journalctl -u ${SERVICE_NAME} -f"
            ;;
        upstart)
            echo "    initctl status ${SERVICE_NAME}"
            echo "    tail -f /var/log/syslog | grep ${SERVICE_NAME}"
            ;;
        sysvinit)
            echo "    /etc/init.d/${SERVICE_NAME} status"
            echo "    tail -f /var/log/syslog | grep ${SERVICE_NAME}"
            ;;
    esac
    echo "    ${BINARY_NAME} --help"
    echo ""
}

main "$@"
