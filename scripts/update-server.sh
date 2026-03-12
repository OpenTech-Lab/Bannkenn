#!/usr/bin/env bash
# Deployment-mode-preserving update helper for the BannKenn server/dashboard stack.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_SCRIPT="$SCRIPT_DIR/install.sh"
ENV_FILE="${BANNKENN_ENV_FILE:-$REPO_ROOT/.env}"

load_repo_env() {
    local env_file="${1:-$ENV_FILE}"

    if [[ -f "$env_file" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "$env_file"
        set +a
    fi
}

load_repo_env

DEFAULT_TLS_DIR="${BANNKENN_TLS_DIR:-/etc/bannkenn/tls}"
REQUESTED_MODE="${BANNKENN_DEPLOY_MODE:-auto}"

info() {
    printf '[INFO] %s\n' "$*"
}

error() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage:
  sudo bash scripts/update-server.sh [options]

Updates the BannKenn server/dashboard stack while preserving the current
deployment mode. In native TLS mode, this wrapper refuses to regenerate or
replace bannkenn.crt/bannkenn.key during an update.

Options:
  --mode MODE           Force deployment mode: auto, http, native-tls
  --dashboard-url URL   Dashboard upstream URL override
  --no-build            Skip docker compose --build
  --dry-run             Print the resolved mode and delegated command only
  -h, --help            Show this help
EOF
}

normalize_mode() {
    case "${1:-auto}" in
        auto|"") echo "auto" ;;
        http|dashboard) echo "http" ;;
        native-tls|dashboard-native-tls|server-native-tls|tls) echo "native-tls" ;;
        *) return 1 ;;
    esac
}

detect_running_mode() {
    command -v docker >/dev/null 2>&1 || return 1
    docker inspect bannkenn-server >/dev/null 2>&1 || return 1

    local env_dump tls_cert_path local_bind
    env_dump=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' bannkenn-server 2>/dev/null || true)
    tls_cert_path=$(printf '%s\n' "$env_dump" | sed -n 's/^BANNKENN_TLS_CERT_PATH=//p' | tail -n 1)
    local_bind=$(printf '%s\n' "$env_dump" | sed -n 's/^BANNKENN_LOCAL_BIND=//p' | tail -n 1)

    if [[ -n "$tls_cert_path" || -n "$local_bind" ]]; then
        echo "native-tls"
    else
        echo "http"
    fi
}

require_existing_tls_files() {
    local tls_dir="$1"
    local cert_path="$tls_dir/bannkenn.crt"
    local key_path="$tls_dir/bannkenn.key"

    [[ -f "$cert_path" ]] || error "expected existing TLS certificate at $cert_path; refusing to regenerate certificates during update"
    [[ -f "$key_path" ]] || error "expected existing TLS key at $key_path; refusing to regenerate certificates during update"
}

print_command() {
    printf '%q ' "$@"
    printf '\n'
}

forwarded_args=()
dry_run="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            [[ $# -ge 2 ]] || error "--mode requires a value"
            REQUESTED_MODE=$(normalize_mode "$2") || error "unsupported mode: $2"
            shift 2
            ;;
        --dashboard-url)
            [[ $# -ge 2 ]] || error "--dashboard-url requires a value"
            forwarded_args+=("$1" "$2")
            shift 2
            ;;
        --no-build)
            forwarded_args+=("$1")
            shift
            ;;
        --dry-run)
            dry_run="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        dashboard|dashboard-native-tls|server-native-tls|agent)
            error "do not pass an install mode; use --mode http|native-tls if you need an override"
            ;;
        --tls-*|--regenerate-cert|--local-bind)
            error "TLS mutation flags are not allowed in scripts/update-server.sh"
            ;;
        *)
            echo "error: unknown option: $1" >&2
            echo >&2
            usage >&2
            exit 1
            ;;
    esac
done

resolved_mode="$REQUESTED_MODE"
if [[ "$resolved_mode" == "auto" ]]; then
    if running_mode="$(detect_running_mode)"; then
        resolved_mode="$running_mode"
    elif [[ -e "$DEFAULT_TLS_DIR/bannkenn.crt" || -e "$DEFAULT_TLS_DIR/bannkenn.key" ]]; then
        error "could not auto-detect whether the stack should update in HTTP or native TLS mode while TLS files exist; set BANNKENN_DEPLOY_MODE=native-tls in .env or pass --mode native-tls"
    else
        resolved_mode="http"
    fi
fi

install_args=()
case "$resolved_mode" in
    http)
        install_args=("dashboard")
        ;;
    native-tls)
        require_existing_tls_files "$DEFAULT_TLS_DIR"
        install_args=("dashboard-native-tls" "--tls-dir" "$DEFAULT_TLS_DIR")
        ;;
    *)
        error "internal error: unsupported resolved mode '$resolved_mode'"
        ;;
esac

install_args+=("${forwarded_args[@]}")

if [[ "$dry_run" == "true" ]]; then
    info "Resolved deployment mode: $resolved_mode"
    info "Delegated command:"
    print_command bash "$INSTALL_SCRIPT" "${install_args[@]}"
    exit 0
fi

exec bash "$INSTALL_SCRIPT" "${install_args[@]}"
