#!/usr/bin/env bash
# Defensia Agent Installer
# Usage: curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <INSTALL_TOKEN> [--name <AGENT_NAME>]
# Non-interactive: DEFENSIA_SERVER_URL=https://... DEFENSIA_AGENT_NAME=web-01 curl -fsSL ... | sudo bash -s -- --token <TOKEN>
# Install only (no registration): curl -fsSL ... | sudo bash -s -- --install-only
# Old servers (SSL error): apt-get update && apt-get install -y ca-certificates && curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <TOKEN>

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
# Where binaries come from, in order. Both are overridable, and the panel
# injects them swapped when it serves this script: there the defensia.cloud
# mirror is primary because agent:mirror-release verifies each checksum before
# publishing, which is why 1cfa1b7 moved away from GitHub as the default. A
# clone of the public repo keeps GitHub first, since that is the source a
# reader of this file can actually verify.
RELEASE_BASE="${RELEASE_BASE:-https://github.com/${GITHUB_REPO}/releases/latest/download}"
RELEASE_FALLBACK="${RELEASE_FALLBACK:-https://defensia.cloud/downloads}"

# ─── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[defensia]${NC} $*"; }
success() { echo -e "${GREEN}[defensia]${NC} ✓ $*"; }
warn()    { echo -e "${YELLOW}[defensia]${NC} ! $*"; }
error()   { LAST_ERROR="$*"; echo -e "${RED}[defensia]${NC} ✗ $*" >&2; exit 1; }

# ─── Parse args ───────────────────────────────────────────────────────────────
# ─── Install telemetry ─────────────────────────────────────────────────────────
# Reports install progress so a failed install is diagnosable instead of
# invisible. Lands in audit_logs as action=install_step, filterable in the admin.
#
# Deliberately minimal: a 16-char token prefix to attribute the install, the
# step, the OS string and the architecture. No hostname, no paths, no config.
# The error string is free-form so it is capped and only sent on failures.
#
# This must never be able to block an install: short timeout, no retries,
# output discarded, and "|| true" so a hung or missing endpoint is a no-op.
# Minimal JSON string escaper. Applied to every interpolated field, not just
# the error: a distro whose PRETTY_NAME contains a double quote produced invalid
# JSON, which the endpoint rejected with a 422 and the report vanished silently.
_json_escape() {
    printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

report_status() {
    local step="$1"
    local err="${2:-}"
    LAST_STEP="$step"
    [[ -z "${INSTALL_TOKEN:-}" ]] && return 0

    local prefix os_info arch api_url err_json="null"
    prefix="$(_json_escape "${INSTALL_TOKEN:0:16}")"
    os_info="$(_json_escape "$(collect_system_info 2>/dev/null || echo unknown)")"
    arch="$(_json_escape "$(uname -m 2>/dev/null || echo unknown)")"
    api_url="${DEFENSIA_SERVER_URL:-https://defensia.cloud}"

    if [[ -n "$err" ]]; then
        # Truncate before escaping: cutting afterwards can sever an escape
        # sequence and leave a trailing backslash, which breaks the JSON.
        err_json="\"$(_json_escape "${err:0:500}")\""
    fi

    curl -fsSL --connect-timeout 3 --max-time 5 -X POST "${api_url}/api/v1/install/status" \
        -H 'Content-Type: application/json' \
        -d "{\"token_prefix\":\"${prefix}\",\"step\":\"${step}\",\"error\":${err_json},\"os\":\"${os_info}\",\"arch\":\"${arch}\"}" \
        >/dev/null 2>&1 || true
}

# ─── Exit handling ─────────────────────────────────────────────────────────────
# One EXIT trap for the whole run. Temp files register here instead of each
# setting its own trap, because a second `trap ... EXIT` silently replaces the
# first.
#
# An install that dies between two reported steps used to vanish: the panel saw
# "download_ok" and then nothing, with no way to tell a crash from a user who
# pressed Ctrl-C at a prompt. Any exit that is not a finished install now reports
# "aborted" with the exit code, the last step reached and the last error.
LAST_STEP=""
LAST_ERROR=""
CLEANUP_FILES=()
INSTALL_FINISHED=false

on_exit() {
    local code=$?
    # A *_failed step already carries its own error; do not report it twice.
    if [[ "$INSTALL_FINISHED" != true ]] && [[ -n "$LAST_STEP" ]] \
       && [[ "$LAST_STEP" != *_failed ]]; then
        report_status "aborted" "exit ${code} after ${LAST_STEP}${LAST_ERROR:+: ${LAST_ERROR}}"
    fi
    if (( ${#CLEANUP_FILES[@]} )); then
        rm -f "${CLEANUP_FILES[@]}"
    fi
}

on_signal() {
    LAST_ERROR="interrupted by SIG$1"
    exit $(( 128 + $2 ))
}

trap on_exit EXIT
trap 'on_signal INT 2' INT
trap 'on_signal TERM 15' TERM
trap 'on_signal HUP 1' HUP

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
            --name)
                DEFENSIA_AGENT_NAME="${2:-}"
                [[ -n "$DEFENSIA_AGENT_NAME" ]] || error "--name requires a value."
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

# install_ipset installs ipset best-effort. ipset is recommended (raises firewall
# capacity from 500 to 65 536 entries) but not required — the agent falls back
# to iptables FIFO rotation if unavailable.
install_ipset() {
    if command -v ipset &>/dev/null; then
        success "ipset already installed — using high-capacity backend (65,536 bans)."
        return 0
    fi

    info "Installing ipset (recommended for high-capacity firewall backend)..."
    local ok=false
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq ipset &>/dev/null && ok=true
    elif command -v dnf &>/dev/null; then
        dnf install -y -q ipset &>/dev/null && ok=true
    elif command -v yum &>/dev/null; then
        yum install -y -q ipset &>/dev/null && ok=true
    elif command -v apk &>/dev/null; then
        apk add --quiet ipset &>/dev/null && ok=true
    fi

    if [[ "$ok" == true ]]; then
        success "ipset installed — firewall capacity raised to 65,536 bans."
    else
        warn "ipset install failed — agent will use iptables backend (500 bans, FIFO)."
        warn "Install manually later for full capacity: apt/dnf/yum install ipset"
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

    CLEANUP_FILES+=("$ca_tmp")

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
        # Fall back to the other source. Which one is primary is configuration,
        # not code: the fallback used to be hardcoded to the same URL as the
        # primary, so an outage had no fallback at all while the warning claimed
        # the other host had been tried.
        local fallback_url="${RELEASE_FALLBACK}/${BINARY_NAME}-linux-${arch}"
        warn "Download from ${RELEASE_BASE} failed — trying ${RELEASE_FALLBACK}..."
        if ! curl -fsSL --progress-bar -o "$tmp" "$fallback_url"; then
            rm -f "$tmp"
            local os_info
            os_info="$(collect_system_info)"
            echo ""
            echo -e "${RED}${BOLD}  ✗ Download failed${NC}"
            echo -e "  ──────────────────"
            echo ""
            echo -e "  Could not download the agent binary from:"
            echo -e "  ${url}"
            echo -e "  ${fallback_url}"
            echo ""
            echo -e "  This may be caused by:"
            echo -e "  • No internet connectivity"
            echo -e "  • Outdated CA certificates (try: apt-get install -y ca-certificates)"
            echo -e "  • Firewall blocking github.com and defensia.cloud"
            echo ""
            echo -e "  ${BOLD}If the problem persists, open a support ticket at:${NC}"
            echo -e "  ${CYAN}https://defensia.cloud/tickets/create${NC}"
            echo ""
            echo -e "  Please include this info:"
            echo -e "  ┌──────────────────────────────────────"
            echo -e "  │ OS:   ${os_info}"
            echo -e "  │ Arch: $(uname -m)"
            echo -e "  │ Kernel: $(uname -r)"
            echo -e "  │ Error: Download failed from both GitHub and mirror"
            echo -e "  └──────────────────────────────────────"
            echo ""
            report_status "download_failed" "Download failed from ${url} and ${fallback_url}"
            exit 1
        fi
        # Take the checksum from wherever the binary actually came from, or the
        # two are compared across sources and mismatch for the wrong reason.
        RELEASE_BASE="$RELEASE_FALLBACK"
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
DEFAULT_SERVER_URL="https://defensia.cloud"

# Read prompts from the controlling TTY so curl|bash installs (where stdin is
# the pipe) still get real input instead of EOF.
read_prompt() {
    local var_name="$1" prompt="$2"
    if [[ -t 0 ]]; then
        read -rp "$prompt" "$var_name"
    elif [[ -r /dev/tty ]]; then
        read -rp "$prompt" "$var_name" </dev/tty
    else
        # No TTY at all (e.g. CI). Caller must rely on defaults or env vars.
        printf '\n'
    fi
}

validate_server_url() {
    local url="$1"
    [[ -n "$url" ]] || return 1
    [[ "$url" =~ ^https?:// ]] || return 1
    return 0
}

prompt_config() {
    local server_url="${DEFENSIA_SERVER_URL:-}"
    local agent_name="${DEFENSIA_AGENT_NAME:-}"

    if [[ -z "$server_url" ]]; then
        echo ""
        read_prompt server_url "$(echo -e "${BOLD}Defensia server URL${NC} [${DEFAULT_SERVER_URL}]: ")"
        # Default to the public instance if the user just hits enter — this
        # mirrors the documented install path and avoids the "unsupported
        # protocol scheme" error that came from passing an empty URL through.
        server_url="${server_url:-$DEFAULT_SERVER_URL}"
    fi

    # Strip trailing slash so callers can concatenate paths cleanly.
    server_url="${server_url%/}"

    if ! validate_server_url "$server_url"; then
        error "Server URL must start with http:// or https:// (got: '${server_url}')"
    fi

    if [[ -z "$agent_name" ]]; then
        local default_name
        default_name="$(hostname -s 2>/dev/null || hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || true)"
        default_name="${default_name%%.*}"
        default_name="${default_name:-server}"
        # The dashboard command always carries --token: that run is meant to be
        # one paste, so take the hostname instead of stopping at a prompt. The
        # prompt was where installs went silent, most of all from phone SSH
        # clients. --name or DEFENSIA_AGENT_NAME still choose a different name.
        if [[ -n "${INSTALL_TOKEN:-}" ]]; then
            agent_name="$default_name"
        else
            read_prompt agent_name "$(echo -e "${BOLD}Agent name${NC} [${default_name}]: ")"
            agent_name="${agent_name:-$default_name}"
        fi
    fi

    echo "$server_url"$'\n'"$agent_name"
}

register_agent() {
    local server_url="$1"
    local agent_name="$2"
    local install_token="$3"

    info "Registering agent '${agent_name}' with ${server_url}..."
    report_status "register_started"

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
        report_status "register_failed" "Registration rejected by ${server_url}"
        exit 1
    fi

    report_status "register_ok"
    success "Agent registered. Token saved to ${CONFIG_DIR}/config.json"
}

# ─── Service install ──────────────────────────────────────────────────────────
install_service() {
    local auth_log
    auth_log="$(detect_auth_log)"

    # Recovery script runs as systemd ExecStartPre and auto-heals a corrupted
    # or missing binary. Only systemd has a pre-start hook to attach it to.
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
DOWNLOAD_STAMP="/var/lib/defensia/recover-download-stamp"

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
    # Fall back to a bare call where coreutils timeout is unavailable: without
    # this, a missing timeout makes every good binary look corrupt and sends the
    # service into permanent recovery.
    if command -v timeout >/dev/null 2>&1; then
        timeout 10 "$bin" check >/dev/null 2>&1
    else
        "$bin" check >/dev/null 2>&1
    fi
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

# Rate-limit the download path. This runs as ExecStartPre under
# Restart=always/RestartSec=10, so a binary that can never pass verification
# would otherwise re-download itself every ten seconds, from every host at once.
#
# Reading an mtime is not portable: "stat -c %Y" is GNU/busybox, "stat -f %m" is
# BSD. When neither answers we must fail CLOSED — assume the stamp is recent and
# skip the download. Failing open would silently void this whole guard and bring
# back the ten-second re-download loop, which is the worse outcome by far.
if [[ -f "$DOWNLOAD_STAMP" ]]; then
    stamp_mtime=""
    for probe in "-c %Y" "-f %m"; do
        # shellcheck disable=SC2086
        candidate="$(stat $probe "$DOWNLOAD_STAMP" 2>/dev/null)" || candidate=""
        if [[ "$candidate" =~ ^[0-9]+$ ]]; then
            stamp_mtime="$candidate"
            break
        fi
    done

    if [[ -z "$stamp_mtime" ]]; then
        log_msg "cannot read stamp mtime (no usable stat) — not retrying the download"
        exit 0
    fi

    if [[ $(( $(date +%s) - stamp_mtime )) -lt 900 ]]; then
        log_msg "download recovery attempted less than 15 min ago — not retrying"
        exit 0
    fi
fi

mkdir -p "$(dirname "$DOWNLOAD_STAMP")" 2>/dev/null || true
date +%s > "$DOWNLOAD_STAMP" 2>/dev/null || true

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

    # If bootstrap_ssl built a merged CA bundle (CentOS 7 and friends), bake
    # SSL_CERT_FILE into the unit: systemd services do not inherit shell exports,
    # so the Go agent would otherwise fail TLS exactly where curl succeeded.
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
                report_status "service_started"
                success "Agent is running!"
                echo ""
                systemctl status "${SERVICE_NAME}" --no-pager -l | head -15
            else
                report_status "service_failed" "systemd unit ${SERVICE_NAME} not active after install"
                warn "Service may not have started correctly. Check logs:"
                echo "  journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
            fi
            ;;
        upstart)
            if initctl status "${SERVICE_NAME}" 2>/dev/null | grep -q "running"; then
                report_status "service_started"
                success "Agent is running!"
                initctl status "${SERVICE_NAME}"
            else
                report_status "service_failed" "upstart job ${SERVICE_NAME} not running after install"
                warn "Service may not have started correctly. Check logs:"
                echo "  cat /var/log/syslog | grep ${SERVICE_NAME}"
            fi
            ;;
        sysvinit)
            if "/etc/init.d/${SERVICE_NAME}" status 2>/dev/null; then
                report_status "service_started"
                success "Agent is running!"
            else
                report_status "service_failed" "sysvinit service ${SERVICE_NAME} not running after install"
                warn "Service may not have started correctly. Check logs:"
                echo "  cat /var/log/syslog | grep ${SERVICE_NAME}"
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
    rm -f /var/lib/defensia/recover-download-stamp

    # Quarantined samples are left in place on purpose: somebody uninstalling
    # after an incident may still need them. Say so, and say where, rather than
    # deleting evidence or leaving unexplained residue behind.
    if [[ -d /var/lib/defensia/quarantine ]] \
       && [[ -n "$(ls -A /var/lib/defensia/quarantine 2>/dev/null)" ]]; then
        warn "Quarantined files kept at /var/lib/defensia/quarantine"
        warn "  Nothing else remains. Delete that directory yourself if you do not need them."
    fi

    # Only if empty, so the quarantine directory above survives.
    rmdir /var/lib/defensia 2>/dev/null || true
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

    local arch
    arch="$(detect_arch)"
    info "Detected: Linux ${arch}"

    check_deps
    install_ipset

    # After check_deps so curl is guaranteed present: on RHEL/CentOS the Go
    # binary reads the OpenSSL bundle, which may lack ISRG Root X1 even when
    # curl (linked against NSS) connects fine.
    bootstrap_ssl

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
        INSTALL_FINISHED=true
        exit 0
    fi

    # Already installed? Re-register?
    if [[ -f "${CONFIG_DIR}/config.json" ]]; then
        warn "Existing config found at ${CONFIG_DIR}/config.json"
        # A fresh install token is an explicit request to register, so do not
        # ask. Asking was also broken under curl | bash: a bare `read` consumes
        # the script itself from stdin instead of the user's answer.
        local answer="y"
        if [[ -z "${INSTALL_TOKEN:-}" ]]; then
            answer=""
            read_prompt answer "Re-register agent? [y/N]: "
        fi
        if [[ "${answer,,}" != "y" ]]; then
            install_service
            check_service
            INSTALL_FINISHED=true
            exit 0
        fi
    fi

    # Get server URL and agent name
    local config
    config="$(prompt_config)"
    local server_url agent_name
    server_url="$(echo "$config" | head -1)"
    agent_name="$(echo "$config" | tail -1)"

    # Re-validate in the parent shell: a failed `error` inside the prompt_config
    # subshell exits with code 1, but assignment from $() does not propagate
    # that to the parent under set -e. Without this guard, empty/invalid values
    # would silently flow into register_agent. (Bug observed via support #5.)
    if ! validate_server_url "$server_url"; then
        error "Server URL must start with http:// or https:// (got: '${server_url}')"
    fi
    [[ -n "$agent_name" ]] || error "Agent name is required."

    # Register with install token
    register_agent "$server_url" "$agent_name" "$INSTALL_TOKEN"

    # Install systemd service
    install_service

    # Verify
    check_service
    INSTALL_FINISHED=true

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
