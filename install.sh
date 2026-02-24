#!/usr/bin/env bash
# Defensia Agent Installer
# Usage: curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <INSTALL_TOKEN>
# Non-interactive: DEFENSIA_SERVER_URL=https://... DEFENSIA_AGENT_NAME=web-01 curl -fsSL ... | sudo bash -s -- --token <TOKEN>
# Install only (no registration): curl -fsSL ... | sudo bash -s -- --install-only

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
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GITHUB_REPO="${GITHUB_REPO:-defensia/agent}"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/${GITHUB_REPO}/releases/latest/download}"

# ─── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[defensia]${NC} $*"; }
success() { echo -e "${GREEN}[defensia]${NC} ✓ $*"; }
warn()    { echo -e "${YELLOW}[defensia]${NC} ! $*"; }
error()   { echo -e "${RED}[defensia]${NC} ✗ $*" >&2; exit 1; }

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

check_systemd() {
    command -v systemctl &>/dev/null || error "systemd is required. Supported distros: Ubuntu 20+, Debian 11+, CentOS Stream 8+, RHEL 8+, Rocky Linux 8+, AlmaLinux 8+, Fedora 38+, Amazon Linux 2023."
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

check_deps() {
    local missing=()
    for cmd in curl iptables; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Installing missing dependencies: ${missing[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get install -y -qq "${missing[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y -q "${missing[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y -q "${missing[@]}"
        else
            error "Cannot install dependencies automatically. Please install: ${missing[*]}"
        fi
    fi
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
        error "Download failed. Check your internet connection or visit https://defensia.com/docs/agent."
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

    DEFENSIA_CONFIG="${CONFIG_DIR}/config.json" \
        "${INSTALL_DIR}/${BINARY_NAME}" register "$server_url" "$agent_name" "$install_token" \
        || error "Registration failed. Check the server URL, install token, and that the server is reachable."

    success "Agent registered. Token saved to ${CONFIG_DIR}/config.json"
}

# ─── Systemd ───────────────────────────────────────────────────────────────────
install_service() {
    info "Installing systemd service..."

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Defensia Security Agent
Documentation=https://defensia.com/docs/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
Environment=DEFENSIA_CONFIG=${CONFIG_DIR}/config.json
Environment=AUTH_LOG_PATH=$(detect_auth_log)

# Security hardening
NoNewPrivileges=no
PrivateTmp=yes
ProtectSystem=false
ProtectHome=yes

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

check_service() {
    sleep 2
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        success "Agent is running!"
        echo ""
        systemctl status "${SERVICE_NAME}" --no-pager -l | head -15
    else
        warn "Service may not have started correctly. Check logs:"
        echo "  journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    fi
}

# ─── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
    info "Uninstalling Defensia Agent..."

    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
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
    check_systemd

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
        echo "    systemctl start ${SERVICE_NAME}"
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
    echo "    systemctl status ${SERVICE_NAME}"
    echo "    journalctl -u ${SERVICE_NAME} -f"
    echo "    ${BINARY_NAME} --help"
    echo ""
}

main "$@"
