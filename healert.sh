#!/bin/bash

# Load persisted config — validate ownership and permissions before sourcing
if [[ -f "$HOME/.healert-config" ]]; then
  _config_owner=$(stat -c '%U' "$HOME/.healert-config" 2>/dev/null)
  _config_perms=$(stat -c '%a' "$HOME/.healert-config" 2>/dev/null)
  _config_perms_int=$(( 10#${_config_perms:-0} ))
  if [[ "$_config_owner" != "$(whoami)" ]]; then
    echo "[WARN] ~/.healert-config owned by '$_config_owner' not '$(whoami)' — skipping" >&2
  elif [[ $(( _config_perms_int % 100 / 10 )) -ge 2 ]]     || [[ $(( _config_perms_int % 10  ))       -ge 2 ]]; then
    echo "[WARN] ~/.healert-config is group/world-writable (${_config_perms}) — skipping" >&2
    echo "       Fix: chmod 600 ~/.healert-config" >&2
  else
    # shellcheck source=/dev/null
    source "$HOME/.healert-config"
  fi
fi

# =============================================================================
# healert.sh — Healert Platform Management Script v0.1.1 Coral
# =============================================================================
#
# Copyright 2026 Healert OÜ
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# =============================================================================
# DESCRIPTION
# =============================================================================
#
# Single script for the complete Healert platform lifecycle.
# Manages the backend (FastAPI), local agent (Go binary), and
# Kubernetes DaemonSet deployment.
#
# USAGE:
#   ./healert.sh <command> [options]
#   ./healert.sh help          — show all commands
#
# FIRST TIME:
#   ./healert.sh init          — configure directories
#   ./healert.sh deps          — check dependencies
#   ./healert.sh setup         — generate API key
#   ./healert.sh configure     — set audit log path
#   ./healert.sh start         — start backend + agent
#   ./healert.sh test          — verify pipeline works
#
# ENVIRONMENT VARIABLES:
#   HEALERT_BACKEND_DIR     Backend directory   (default: ~/healert-backend)
#   HEALERT_AGENT_DIR       Agent directory     (default: script directory)
#   HEALERT_HOST            Backend bind host   (default: 127.0.0.1)
#   HEALERT_PORT            Backend bind port   (default: 8000)
#   AUDIT_LOG_PATH          Audit log path      (default: /var/log/k3s-audit.log)
#   ENTITY_NAMESPACE        Backstage namespace (default: default)
#   RULES_PATH              Rules file path     (default: ./rules.yaml)
#   K8S_NAMESPACE           K8s namespace       (default: healert-system)
#
# EXAMPLES:
#   # Backend in /home/user/healert/backend, agent in /home/user/healert/agent
#   export HEALERT_BACKEND_DIR=/home/user/healert/backend
#   export HEALERT_AGENT_DIR=/home/user/healert/agent
#   ./healert.sh setup
#   ./healert.sh start
#
# =============================================================================
#
# Single script for the complete Healert platform lifecycle:
#   - Dependency checking and installation
#   - API key generation and secure storage
#   - Backend and agent startup with full validation
#   - Health monitoring and status reporting
#   - Pipeline testing and verification
#
# USAGE:
#   ./healert.sh <command> [options]
#
# COMMANDS:
#   deps                  Check and install all dependencies
#   setup                 Generate API key, configure both sides
#   setup --rotate        Rotate existing API key
#   start                 Start backend + agent (local mode)
#   start --backend       Start backend only
#   start --agent         Start agent only
#   start --kubernetes    Deploy agent as Kubernetes DaemonSet
#   stop                  Stop all Healert processes
#   restart               Stop then start all
#   status                Show health and running state
#   logs                  Tail live logs from all processes
#   test                  Send test event, verify full pipeline
#   help                  Show this help
#
# DEPLOYMENT MODES:
#   Local       Backend runs on this machine as a uvicorn process.
#               Agent runs as a local binary reading the audit log.
#               Use for: development, single-node clusters, homelab.
#
#   Kubernetes  Backend runs locally. Agent deployed as DaemonSet
#               on every cluster node via kubectl apply.
#               Use for: multi-node clusters, production environments.
#
# FIRST TIME:
#   ./healert.sh deps             # check and install dependencies
#   ./healert.sh setup            # generate API key
#   ./healert.sh start            # start everything
#   ./healert.sh test             # verify pipeline works
#
# ENVIRONMENT VARIABLES:
#   HEALERT_BACKEND_DIR     Backend directory   (default: ~/healert-backend)
#   HEALERT_AGENT_DIR       Agent directory     (default: script directory)
#   HEALERT_HOST            Backend bind host   (default: 127.0.0.1)
#   HEALERT_PORT            Backend bind port   (default: 8000)
#   AUDIT_LOG_PATH          Audit log path      (default: /var/log/k3s-audit.log)
#   ENTITY_NAMESPACE        Backstage namespace (default: default)
#   RULES_PATH              Rules file path     (default: ./rules.yaml)
#   K8S_NAMESPACE           K8s namespace       (default: healert-system)
#
# SECURITY MODEL:
#   - API key stored in .env files with chmod 600
#   - .env added to .gitignore automatically
#   - Key injected via env — never appears in process list (ps aux)
#   - Backend binds to 127.0.0.1 by default — not exposed to network
#   - Kubernetes mode uses Kubernetes Secret — not plain env vars
#   - All secrets cleared from shell variables after use
#   - No secrets written to log files
#
# =============================================================================

# =============================================================================
# SHELL HARDENING
# =============================================================================

# Exit immediately on error (-e), treat unset variables as errors (-u),
# propagate pipe failures (-o pipefail). Together these prevent the script
# from continuing silently after a failure — the most common source of
# security issues in shell scripts.
set -euo pipefail

# Restrict umask — all files created by this script are readable only by owner.
# sensitive output.
umask 077

# Clear dangerous environment variables that could affect child processes.
# PATH is restored to a safe default immediately after.
unset IFS 2>/dev/null || true
# Prepend known safe system paths to prevent PATH injection attacks.
# We preserve the user existing PATH rather than replacing it — this ensures
# user-installed tools (Go, pip packages, custom binaries) remain discoverable.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# =============================================================================
# CONSTANTS — never modified after initialization
# =============================================================================

readonly SCRIPT_VERSION="0.1.1"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_NAME

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Colors — checked for terminal support before use
if [[ -t 1 ]] && command -v tput &>/dev/null && tput colors &>/dev/null; then
  readonly RED='\033[0;31m'
  readonly GREEN='\033[0;32m'
  readonly TEAL='\033[0;36m'
  readonly AMBER='\033[0;33m'
  readonly BOLD='\033[1m'
  readonly DIM='\033[2m'
  readonly RESET='\033[0m'
else
  # No color support — all color codes are empty strings
  readonly RED='' GREEN='' TEAL='' AMBER='' BOLD='' DIM='' RESET=''
fi

# =============================================================================
# CONFIGURATION — resolved once, injected downward
# =============================================================================

# All paths derived from environment variables with safe defaults.
# Readonly after assignment — cannot be accidentally overwritten.
BACKEND_DIR="${HEALERT_BACKEND_DIR:-$HOME/healert-backend}"
AGENT_DIR="${HEALERT_AGENT_DIR:-$SCRIPT_DIR}"
readonly BACKEND_HOST="${HEALERT_HOST:-127.0.0.1}"
readonly BACKEND_PORT="${HEALERT_PORT:-8000}"
readonly BACKEND_URL="http://${BACKEND_HOST}:${BACKEND_PORT}"
# Note: AUDIT_LOG, ENTITY_NS, RULES are NOT readonly — they are resolved
# after _key_load() which loads .agent-config with the correct values.
# Using readonly here would freeze them to defaults before .agent-config loads.
AUDIT_LOG="${AUDIT_LOG_PATH:-/var/log/k3s-audit.log}"
ENTITY_NS="${ENTITY_NAMESPACE:-default}"
RULES="${RULES_PATH:-$AGENT_DIR/rules.yaml}"
readonly K8S_NS="${K8S_NAMESPACE:-healert-system}"

# Runtime directories — writable, created on demand
readonly PID_DIR="$AGENT_DIR/.pids"
readonly LOG_DIR="$AGENT_DIR/.logs"

# Env files — source of truth for API key
readonly BACKEND_ENV="$BACKEND_DIR/.env"
readonly AGENT_ENV="$AGENT_DIR/.env"
# Agent runtime config — separate from .env (which stores the API key).
# Stores agent-specific settings: AUDIT_LOG_PATH, RULES_PATH, ENTITY_NAMESPACE.
# Loaded LAST so backend .env can never overwrite agent settings.
readonly AGENT_CONFIG="$AGENT_DIR/.agent-config"

# PID and log files — one per managed process
readonly BACKEND_PID="$PID_DIR/backend.pid"
readonly AGENT_PID="$PID_DIR/agent.pid"
readonly BACKEND_LOG="$LOG_DIR/backend.log"
readonly AGENT_LOG="$LOG_DIR/agent.log"

# Agent binary and Kubernetes manifest paths
readonly AGENT_BIN="$AGENT_DIR/healert-agent"
readonly DAEMONSET_YAML="$AGENT_DIR/daemonset.yaml"

# =============================================================================
# UI FUNCTIONS
# Single responsibility: output only. No logic, no side effects.
# =============================================================================

# _info prints an informational message to stdout.
_info()  { echo -e "${TEAL}[INFO]${RESET}  $*"; }

# _ok prints a success message to stdout.
_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }

# _warn prints a warning to stdout. Does not exit.
_warn()  { echo -e "${AMBER}[WARN]${RESET}  $*"; }

# _err prints an error message to stderr. Does not exit.
_err()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# _die prints an error and exits with code 1.
_die()   { _err "$*"; exit 1; }

# _dim prints a muted secondary line.
_dim()   { echo -e "        ${DIM}$*${RESET}"; }

# _sep prints a visual separator.
_sep()   { echo -e "  ${TEAL}─────────────────────────────────────────────${RESET}"; }

# _blank prints an empty line.
_blank() { echo ""; }

# _header prints a section header.
_header() { echo -e "  ${BOLD}$*${RESET}"; }

# _banner prints the product logo.
_banner() {
  _blank
  # Healert wordmark + Backstage axolotl logo side by side
  echo -e "  ${BOLD}${TEAL}  ██╗  ██╗███████╗ █████╗ ██╗     ███████╗██████╗ ████████╗${RESET}   ${TEAL}    /\ /\  ${RESET}"
  echo -e "  ${BOLD}${TEAL}  ██║  ██║██╔════╝██╔══██╗██║     ██╔════╝██╔══██╗╚══██╔══╝${RESET}   ${TEAL}  =(  o o)=${RESET}"
  echo -e "  ${BOLD}${TEAL}  ███████║█████╗  ███████║██║     █████╗  ██████╔╝   ██║   ${RESET}   ${TEAL}   (   Y  ) ${RESET}"
  echo -e "  ${BOLD}${TEAL}  ██╔══██║██╔══╝  ██╔══██║██║     ██╔══╝  ██╔══██╗   ██║   ${RESET}   ${TEAL}  /  \ | /\ ${RESET}"
  echo -e "  ${BOLD}${TEAL}  ██║  ██║███████╗██║  ██║███████╗███████╗██║  ██║   ██║   ${RESET}   ${TEAL} (_/ \_|/_) ${RESET}"
  echo -e "  ${BOLD}${TEAL}  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ${RESET}"
  _blank
  echo -e "  ${DIM}Friction Intelligence Platform  v${SCRIPT_VERSION}  Apache-2.0${RESET}"
  echo -e "  ${DIM}Copyright 2026 Healert OÜ ${RESET}"
  _blank
}

# =============================================================================
# SECURITY FUNCTIONS
# Single responsibility: cryptographic key operations only.
# =============================================================================

# _key_generate produces a cryptographically secure 32-byte random key.
# Falls back through available generators — openssl preferred for FIPS compliance.
# The key never appears in the process list or shell history.
_key_generate() {
  if command -v openssl &>/dev/null; then
    # openssl rand -base64 32 produces 44 printable characters
    openssl rand -base64 32
  elif command -v python3 &>/dev/null; then
    # Python secrets module is cryptographically secure
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
  elif [[ -r /dev/urandom ]]; then
    # Last resort — /dev/urandom is always cryptographically secure on Linux
    tr -dc 'A-Za-z0-9+/=' < /dev/urandom | head -c 44
  else
    _die "Cannot generate a secure key — openssl, python3, and /dev/urandom are all unavailable"
  fi
}

# _key_write writes an API key to a single .env file securely.
# Creates the file with 600 permissions before writing —
# prevents a window where the file exists with looser permissions.
_key_write() {
  local env_file="$1"
  local api_key="$2"

  # Validate key is not empty before writing
  [[ -n "$api_key" ]] || _die "_key_write: empty key — refusing to write"

  # Create with secure permissions before any content is written
  install -m 600 /dev/null "$env_file"

  # Remove any existing key line
  if grep -q "^HEALERT_API_KEY=" "$env_file" 2>/dev/null; then
    local tmp
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' RETURN
    grep -v "^HEALERT_API_KEY=" "$env_file" > "$tmp"
    mv "$tmp" "$env_file"
    chmod 600 "$env_file"
  fi

  printf 'HEALERT_API_KEY=%s\n' "$api_key" >> "$env_file"
}

# _key_read reads the API key from a .env file.
# Returns empty string if file does not exist or key is not set.
# Never prints the key — callers must handle it carefully.
_key_read() {
  local env_file="$1"
  [[ -f "$env_file" ]] || { printf ''; return; }
  grep "^HEALERT_API_KEY=" "$env_file" 2>/dev/null \
    | cut -d'=' -f2- \
    | tr -d '\n' \
    || printf ''
}

# _key_load exports HEALERT_API_KEY and agent runtime settings.
# Loading order: backend .env → agent .env → agent config (.agent-config)
# .agent-config is loaded LAST — its values always win over backend .env.
_key_load() {
  # Loading order: backend .env → agent .env → agent config
  # .agent-config is loaded LAST — its values always win

  if [[ -f "$BACKEND_ENV" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$BACKEND_ENV"
    set +a
  fi

  if [[ -f "$AGENT_ENV" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$AGENT_ENV"
    set +a
  fi

  # Agent config loaded last — always overrides backend .env values
  if [[ -f "$AGENT_CONFIG" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$AGENT_CONFIG"
    set +a
  fi
  # Re-resolve agent path variables now that all env files are loaded.
  # AUDIT_LOG was set at script load time before .agent-config was sourced —
  # we must refresh it here so the correct path is used when starting the agent.
  AUDIT_LOG="${AUDIT_LOG_PATH:-$AUDIT_LOG}"
  ENTITY_NS="${ENTITY_NAMESPACE:-$ENTITY_NS}"
  RULES="${RULES_PATH:-$RULES}"
}

# _key_verify checks that two .env files contain the same API key.
# Returns 0 if both files have a non-empty identical key, 1 otherwise.
_key_verify() {
  local file_a="$1" file_b="$2"
  local key_a key_b
  key_a=$(_key_read "$file_a")
  key_b=$(_key_read "$file_b")
  [[ -n "$key_a" ]] && [[ "$key_a" == "$key_b" ]]
}

# _gitignore_add ensures .env is in .gitignore for a directory.
# Only acts if the directory is a git repo — silently skips otherwise.
_gitignore_add() {
  local dir="$1"
  [[ -d "$dir/.git" ]] || return 0
  grep -q "^\.env$" "$dir/.gitignore" 2>/dev/null \
    || { echo ".env" >> "$dir/.gitignore"; _ok "Added .env to $dir/.gitignore"; }
}

# =============================================================================
# PROCESS FUNCTIONS
# Single responsibility: generic process lifecycle management.
# All functions are process-agnostic — they work for backend, agent, or any
# future component. Concrete details are passed as arguments.
# =============================================================================

# _proc_is_running returns 0 if the PID file exists and the process is alive.
# Pure predicate — no output, no side effects.
_proc_is_running() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

# _proc_pid reads the PID from a pid file. Returns empty if not found.
_proc_pid() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] && cat "$pid_file" || printf ''
}

# _proc_stop gracefully stops a process then force-kills if needed.
# Waits up to 5 seconds for graceful shutdown before SIGKILL.
_proc_stop() {
  local name="$1" pid_file="$2"

  if ! _proc_is_running "$pid_file"; then
    _dim "$name is not running"
    return 0
  fi

  local pid
  pid=$(_proc_pid "$pid_file")
  _info "Stopping $name (PID $pid)..."

  # SIGTERM — graceful shutdown request
  kill "$pid" 2>/dev/null || true

  # Wait up to 5 seconds (10 × 0.5s) for graceful exit
  local i=0
  while kill -0 "$pid" 2>/dev/null && [[ $i -lt 10 ]]; do
    sleep 0.5
    ((i++))
  done

  # SIGKILL — force kill if still alive after grace period
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$pid_file"

  _ok "$name stopped"
}

# _proc_start launches a process in the background and records its PID.
# Dependency Inversion: receives the full command as arguments — does not
# know whether it is starting uvicorn, the Go agent, or anything else.
# The log file is created with secure permissions before the process starts.
_proc_start() {
  local name="$1"     # human-readable label for log messages
  local pid_file="$2" # where to write the PID
  local log_file="$3" # where to write stdout + stderr
  shift 3
  # Remaining arguments: the command and its arguments

  # Create directories and log file with secure permissions
  mkdir -p "$(dirname "$pid_file")" "$(dirname "$log_file")"
  install -m 600 /dev/null "$log_file"

  # Launch process — stdout and stderr go to log file
  "$@" >> "$log_file" 2>&1 &

  local pid=$!
  printf '%d\n' "$pid" > "$pid_file"

  _ok "$name started (PID $pid)"
  _dim "Log: $log_file"
}

# _proc_verify waits briefly then confirms the process is still alive.
# Catches immediate exits caused by misconfiguration (bad rules.yaml,
# wrong binary path, missing env vars) before the caller continues.
_proc_verify() {
  local name="$1" pid_file="$2" log_file="$3"
  local delay="${4:-2}" # seconds to wait before checking

  sleep "$delay"

  if ! _proc_is_running "$pid_file"; then
    _err "$name exited immediately — configuration error"
    _err "Last 20 lines of log:"
    _blank
    tail -20 "$log_file" >&2 || true
    _blank
    exit 1
  fi
}

# =============================================================================
# HEALTH FUNCTIONS
# Single responsibility: HTTP health check operations only.
# None of these start, stop, or modify any process or file.
# =============================================================================

# _health_check returns 0 if a URL responds with HTTP 200, 1 otherwise.
_health_check() {
  local url="$1"
  curl --fail --silent --max-time 3 "$url" > /dev/null 2>&1
}

# _health_field fetches one field from a JSON health response.
# Returns "unknown" if the request fails or field is absent.
_health_field() {
  local url="$1" field="$2"
  curl --fail --silent --max-time 3 "$url" 2>/dev/null \
    | python3 -c \
        "import sys,json; print(json.load(sys.stdin).get('$field','unknown'))" \
        2>/dev/null \
    || printf 'unknown'
}

# _health_wait polls a URL until it responds or times out.
# Returns 0 on success, 1 if the timeout is reached.
_health_wait() {
  local url="$1"
  local max_attempts="${2:-20}" # 20 × 0.5s = 10 second timeout

  local i=0
  while [[ $i -lt $max_attempts ]]; do
    _health_check "$url" && return 0
    sleep 0.5
    ((i++))
  done
  return 1
}

# _health_auth_mismatch warns when the backend has auth enabled
# but the agent has no API key configured. Called once after backend starts.
_health_auth_mismatch() {
  local api_key="${1:-}"
  local auth
  auth=$(_health_field "$BACKEND_URL/health" "auth")

  if [[ "$auth" == "enabled" ]] && [[ -z "$api_key" ]]; then
    _warn "Backend auth is ENABLED but HEALERT_API_KEY is not set"
    _warn "All agent events will be rejected with HTTP 401"
    _warn "Fix: ./$SCRIPT_NAME setup"
  fi
}

# =============================================================================
# DEPENDENCY FUNCTIONS
# Single responsibility: check and install runtime dependencies.
# =============================================================================

# _dep_check_one checks a single dependency and prints its status.
# Returns 0 if found, 1 if missing.
# All check_cmd values are hardcoded in cmd_deps — never user-controlled.
_dep_check_one() {
  local name="$1" binary="$2" version_flag="$3" install_hint="$4"

  if command -v "$binary" &>/dev/null; then
    local version
    version=$("$binary" $version_flag 2>/dev/null | head -1 || echo "installed")
    _ok "$name — $version"
    return 0
  else
    _warn "$name — NOT FOUND"
    _dim "Install: $install_hint"
    return 1
  fi
}

# _dep_check_python_pkg checks if a Python package is installed.
_dep_check_python_pkg() {
  local pkg="$1"
  python3 -c "import $pkg" &>/dev/null
}

# =============================================================================
# VALIDATION FUNCTIONS
# Single responsibility: pre-flight validation before starting components.
# Return errors — never start anything.
# =============================================================================

# _validate_backend checks backend prerequisites.
_validate_backend() {
  [[ -d "$BACKEND_DIR" ]] \
    || _die "Backend directory not found: $BACKEND_DIR\n  Set HEALERT_BACKEND_DIR"
  [[ -f "$BACKEND_DIR/main.py" ]] \
    || _die "main.py not found in $BACKEND_DIR"
  _find_uvicorn > /dev/null \
    || _die "uvicorn not found\n  Run: ./$SCRIPT_NAME deps"
  _ok "Backend prerequisites validated"
}

# _validate_agent checks local agent prerequisites.
_validate_agent() {
  [[ -f "$AGENT_BIN" ]] \
    || _die "Agent binary not found: $AGENT_BIN\n  Run: go build -o healert-agent main.go"
  [[ -f "$RULES" ]] \
    || _die "Rules file not found: $RULES\n  Set RULES_PATH or create rules.yaml"
  [[ -f "$AUDIT_LOG" ]] \
    || _warn "Audit log not found: $AUDIT_LOG (agent will retry every 5s)"
  _ok "Agent prerequisites validated"
}

# _validate_kubernetes checks prerequisites for Kubernetes DaemonSet deployment.
# Called only by: ./healert.sh start kubernetes
#
# Automatically detects k3s, kubeadm, and standard Kubernetes clusters.
# Override detection by setting environment variables before running:
#
#   k3s (auto-detected):
#     sudo chmod 644 /etc/rancher/k3s/k3s.yaml
#     export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#     ./healert.sh start kubernetes
#
#   kubeadm / standard:
#     export KUBECONFIG=~/.kube/config
#     ./healert.sh start kubernetes
#
#   Custom kubectl path:
#     export KUBECTL="sudo k3s kubectl"
#     ./healert.sh start kubernetes
_validate_kubernetes() {

  # ── Step 1: Resolve kubectl binary ─────────────────────────────────────────
  # Priority: KUBECTL env var → kubectl in PATH → k3s kubectl → error
  local _kubectl="${KUBECTL:-}"

  if [[ -z "$_kubectl" ]]; then
    if command -v kubectl &>/dev/null; then
      _kubectl="kubectl"
    elif command -v k3s &>/dev/null; then
      _kubectl="k3s kubectl"
      _info "k3s detected — using: k3s kubectl"
    else
      _blank
      _err "kubectl not found"
      _blank
      echo -e "  ${BOLD}Install kubectl:${RESET}"
      echo -e "    https://kubernetes.io/docs/tasks/tools/"
      echo -e ""
      echo -e "  ${BOLD}Or for k3s, install k3s first:${RESET}"
      echo -e "    curl -sfL https://get.k3s.io | sh -"
      echo -e ""
      echo -e "  ${BOLD}Or set a custom path:${RESET}"
      echo -e "    export KUBECTL='sudo k3s kubectl'"
      _blank
      exit 1
    fi
  fi

  # ── Step 2: Resolve kubeconfig ─────────────────────────────────────────────
  # Priority: KUBECONFIG env var → k3s default → standard default
  if [[ -z "${KUBECONFIG:-}" ]]; then
    if [[ -f "/etc/rancher/k3s/k3s.yaml" ]]; then
      # k3s default kubeconfig — make readable first if needed
      if [[ ! -r "/etc/rancher/k3s/k3s.yaml" ]]; then
        _warn "k3s kubeconfig not readable — trying sudo chmod 644"
        # chmod 644 is intentional — kubeconfig must be readable by the
        # current user to run kubectl. The file contains a client certificate
        # and key. In production, create a dedicated kubeconfig for Healert
        # with a scoped service account instead of using the admin kubeconfig.
        sudo chmod 644 /etc/rancher/k3s/k3s.yaml 2>/dev/null || true
      fi
      export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
      _info "Using k3s kubeconfig: $KUBECONFIG"
    elif [[ -f "$HOME/.kube/config" ]]; then
      export KUBECONFIG="$HOME/.kube/config"
      _info "Using kubeconfig: $KUBECONFIG"
    fi
  fi

  # Export _kubectl now so $KUBECTL is available in Step 3 and all k8s functions
  export KUBECTL="$_kubectl"

  # ── Step 3: Verify cluster is reachable ────────────────────────────────────
  if ! $KUBECTL get nodes &>/dev/null 2>&1; then
    _blank
    _err "Cannot reach Kubernetes cluster"
    _blank
    echo -e "  ${BOLD}Current settings:${RESET}"
    echo -e "    kubectl:    ${_kubectl}"
    echo -e "    KUBECONFIG: ${KUBECONFIG:-not set}"
    _blank
    echo -e "  ${BOLD}Fix for k3s:${RESET}"
    echo -e "    sudo chmod 644 /etc/rancher/k3s/k3s.yaml"
    echo -e "    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml"
    echo -e "    ./healert.sh start kubernetes"
    _blank
    echo -e "  ${BOLD}Fix for kubeadm:${RESET}"
    echo -e "    export KUBECONFIG=~/.kube/config"
    echo -e "    ./healert.sh start kubernetes"
    _blank
    exit 1
  fi

  # ── Step 4: Verify daemonset.yaml exists ───────────────────────────────────
  [[ -f "$DAEMONSET_YAML" ]] || _die     "daemonset.yaml not found: $DAEMONSET_YAML
  Download from: github.com/healert/agent/daemonset.yaml
  Or set: export DAEMONSET_YAML=/path/to/daemonset.yaml"

  _ok "Cluster reachable (kubectl: $_kubectl)"
  _ok "daemonset.yaml found: $DAEMONSET_YAML"
}

# _find_uvicorn resolves the uvicorn binary path.
# Checks venv first, then system PATH.
_find_uvicorn() {
  if [[ -f "$BACKEND_DIR/venv/bin/uvicorn" ]]; then
    printf '%s' "$BACKEND_DIR/venv/bin/uvicorn"
  elif command -v uvicorn &>/dev/null; then
    command -v uvicorn
  else
    return 1
  fi
}

# =============================================================================
# KUBERNETES FUNCTIONS
# Single responsibility: Kubernetes-specific operations only.
# =============================================================================

# _k8s_create_namespace creates the healert namespace if it does not exist.
_k8s_create_namespace() {
  if ! $KUBECTL get namespace "$K8S_NS" &>/dev/null; then
    $KUBECTL create namespace "$K8S_NS"
    _ok "Namespace $K8S_NS created"
  else
    _dim "Namespace $K8S_NS already exists"
  fi
}

# _k8s_create_secret creates a Kubernetes Secret for the API key.
# Deletes the existing secret first if rotating.
# The key is passed via stdin to avoid it appearing in the process list.
_k8s_create_secret() {
  local api_key="$1"

  if $KUBECTL get secret healert-api-key -n "$K8S_NS" &>/dev/null; then
    _info "Replacing existing Kubernetes Secret..."
    $KUBECTL delete secret healert-api-key -n "$K8S_NS"
  fi

  # Use --from-literal — key value does not appear in shell history
  # Key name MUST match secretKeyRef.key in daemonset.yaml (HEALERT_API_KEY)
  # Trim whitespace/newlines from key — prevents auth failures from trailing chars
  local _trimmed_key
  _trimmed_key=$(printf '%s' "$api_key" | tr -d '[:space:]')
  $KUBECTL create secret generic healert-api-key \
    --from-literal=HEALERT_API_KEY="$_trimmed_key" \
    -n "$K8S_NS"

  _ok "Kubernetes Secret created: healert-api-key in $K8S_NS"
}

# _k8s_verify_secret reads back the secret and confirms it matches.
_k8s_verify_secret() {
  local expected_key="$1"
  local stored_key
  stored_key=$($KUBECTL get secret healert-api-key \
    -n "$K8S_NS" \
    -o jsonpath='{.data.HEALERT_API_KEY}' \
    | base64 --decode 2>/dev/null)

  [[ "$stored_key" == "$expected_key" ]] \
    || _die "Kubernetes Secret verification failed — stored key does not match"

  _ok "Kubernetes Secret verified"
}

# _k8s_deploy applies the DaemonSet manifest and waits for rollout.
_k8s_deploy() {
  _info "Applying DaemonSet manifest..."
  $KUBECTL apply -f "$DAEMONSET_YAML"

  _info "Waiting for DaemonSet rollout..."
  $KUBECTL rollout status daemonset/healert-agent \
    -n "$K8S_NS" \
    --timeout=120s

  _ok "DaemonSet deployed successfully"
}

# _k8s_undeploy removes the DaemonSet and optionally the namespace.
_k8s_undeploy() {
  if $KUBECTL get daemonset healert-agent -n "$K8S_NS" &>/dev/null; then
    $KUBECTL delete -f "$DAEMONSET_YAML"
    _ok "DaemonSet removed"
  else
    _dim "DaemonSet not found — nothing to remove"
  fi
}

# cmd_stop_kubernetes removes the Healert DaemonSet and its namespace.
# Leaves the backend and local agent untouched.
#
# Usage:
#   ./healert.sh stop kubernetes
cmd_stop_kubernetes() {
  _banner
  _header "Stopping Healert Kubernetes DaemonSet"
  _sep
  _blank

  _validate_kubernetes

  _info "Removing DaemonSet..."
  _k8s_undeploy

  # Remove namespace and all resources inside it
  if $KUBECTL get namespace "$K8S_NS" &>/dev/null; then
    _info "Removing namespace $K8S_NS..."
    $KUBECTL delete namespace "$K8S_NS" --timeout=30s 2>/dev/null || true
    _ok "Namespace $K8S_NS removed"
  else
    _dim "Namespace $K8S_NS not found — nothing to remove"
  fi

  _blank
  _ok "Kubernetes DaemonSet stopped"
  _blank
}

# cmd_update_kubernetes applies the latest daemonset.yaml and rebuilds the
# Kubernetes Secret if the API key has changed. Performs a rolling restart
# so there is no detection gap during the update.
#
# Usage:
#   ./healert.sh update kubernetes
#
# Use after:
#   - Updating daemonset.yaml (new image tag, env vars, resource limits)
#   - Updating rules.yaml (if using ConfigMap mount)
#   - Rotating the API key (./healert.sh setup rotate)
cmd_update_kubernetes() {
  _banner
  _header "Updating Healert Kubernetes DaemonSet"
  _sep
  _blank

  _validate_kubernetes
  _key_load

  # Verify DaemonSet exists — must deploy first
  if ! $KUBECTL get daemonset healert-agent -n "$K8S_NS" &>/dev/null; then
    _die "DaemonSet not found — run ./healert.sh start kubernetes first"
  fi

  # Update API key secret in case it was rotated
  _info "Updating Kubernetes Secret..."
  $KUBECTL create secret generic healert-api-key     --from-literal=HEALERT_API_KEY="$HEALERT_API_KEY"     -n "$K8S_NS"     --dry-run=client -o yaml | $KUBECTL apply -f - > /dev/null
  _ok "Secret updated"

  # Apply updated daemonset.yaml
  _info "Applying updated DaemonSet manifest..."
  $KUBECTL apply -f "$DAEMONSET_YAML" > /dev/null
  _ok "Manifest applied"

  # Rolling restart — replaces pods one at a time, no detection gap
  _info "Rolling restart to apply changes..."
  $KUBECTL rollout restart daemonset/healert-agent -n "$K8S_NS"

  _info "Waiting for rollout to complete..."
  if $KUBECTL rollout status daemonset/healert-agent       -n "$K8S_NS" --timeout=120s; then
    _ok "Rolling restart complete — DaemonSet updated"
  else
    _warn "Rollout timed out — check pod status:"
    _warn "  kubectl get pods -n $K8S_NS"
    _warn "  kubectl describe pod -n $K8S_NS -l app=healert-agent"
  fi

  _blank
  _info "Current pod status:"
  $KUBECTL get pods -n "$K8S_NS" -l app=healert-agent
  _blank
  _ok "Update complete"
  _blank
}

# _agent_config_create writes agent runtime settings to .agent-config.
# Separate from .env (API key storage) so backend settings never overwrite
# agent-specific configuration like AUDIT_LOG_PATH.
# Called automatically by cmd_setup and cmd_configure.
_agent_config_create() {
  local audit_log="$1"
  local rules_path="$2"
  local entity_ns="$3"

  # Create with secure permissions before writing
  # Create file with secure permissions before writing any content
  install -m 600 /dev/null "$AGENT_CONFIG"

  {
    printf '# Healert Agent Runtime Configuration
'
    printf '# Generated by ./%s — edit to change settings
' "$SCRIPT_NAME"
    printf '# Loaded AFTER backend .env — these values always win
'
    printf '
'
    printf 'AUDIT_LOG_PATH=%s
' "$audit_log"
    printf 'RULES_PATH=%s
'     "$rules_path"
    printf 'ENTITY_NAMESPACE=%s
' "$entity_ns"
  } >> "$AGENT_CONFIG"

  _ok "Agent config written: $AGENT_CONFIG"
  _dim "AUDIT_LOG_PATH=$audit_log"
  _dim "RULES_PATH=$rules_path"
  _dim "ENTITY_NAMESPACE=$entity_ns"
}

# cmd_configure updates agent runtime settings interactively or via flags.
# Use after setup to change audit log path, rules file, or namespace.
# Does NOT regenerate the API key.
#
# Usage:
#   ./healert.sh configure
#   ./healert.sh configure --audit-log /var/log/k3s-audit.log
#   ./healert.sh configure --rules /path/to/rules.yaml
#   ./healert.sh configure --namespace production
cmd_configure() {
  local audit_log rules_path entity_ns

  # Load current values as defaults
  _key_load
  audit_log="${AUDIT_LOG_PATH:-$AUDIT_LOG}"
  rules_path="${RULES_PATH:-$RULES}"
  entity_ns="${ENTITY_NAMESPACE:-$ENTITY_NS}"

  # Parse optional flags
  local _has_flags=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --audit-log) audit_log="$2"; shift 2; _has_flags=true ;;
      --rules)     rules_path="$2"; shift 2; _has_flags=true ;;
      --namespace) entity_ns="$2"; shift 2; _has_flags=true ;;
      *) _warn "Unknown option: $1"; shift ;;
    esac
  done

  # Interactive mode when no flags given
  if [[ "$_has_flags" == false ]]; then
    _banner
    _header "Agent Configuration"
    _sep
    _blank
    _info "Press Enter to keep current value"
    _blank

    read -r -p "  Audit log path [$audit_log]: " _in
    if [[ -n "$_in" ]]; then
      [[ "$_in" == /* ]] || _die "Audit log path must be absolute: $_in"
      [[ "$_in" != *..* ]] || _die "Audit log path must not contain ..: $_in"
      audit_log="$_in"
    fi

    read -r -p "  Rules file path [$rules_path]: " _in
    if [[ -n "$_in" ]]; then
      [[ "$_in" == /* ]] || _die "Rules path must be absolute: $_in"
      [[ "$_in" != *..* ]] || _die "Rules path must not contain ..: $_in"
      rules_path="$_in"
    fi

    read -r -p "  Entity namespace [$entity_ns]: " _in
    if [[ -n "$_in" ]]; then
      [[ "$_in" =~ ^[a-zA-Z0-9_-]+$ ]] || _die "Namespace must be alphanumeric/hyphens only: $_in"
      entity_ns="$_in"
    fi
    _blank
  fi

  _agent_config_create "$audit_log" "$rules_path" "$entity_ns"
  _blank
  _info "Restart agent to apply: ./$SCRIPT_NAME restart"
  _blank
}

# cmd_configure_scoring updates the backend scoring parameters.
# Stored in the backend .env file and applied on next backend restart.
#
# SCORING PARAMETERS:
#   SCORE_RETENTION_DAYS      Events older than this have zero weight (default: 30)
#   SCORE_DECAY_HALF_LIFE     Events lose half weight every N days (default: 7)
#   SCORE_CRITICAL_THRESHOLD  Weighted points needed for score=100 (default: 50)
#
# TUNING GUIDE:
#   Strict  (zero tolerance):  threshold=20  half_life=3
#   Default (balanced):        threshold=50  half_life=7
#   Lenient (high volume):     threshold=100 half_life=14
#
# Usage:
#   ./healert.sh configure scoring                           (interactive)
#   ./healert.sh configure scoring --threshold 20            (strict)
#   ./healert.sh configure scoring --threshold 100           (lenient)
#   ./healert.sh configure scoring --half-life 3             (fast decay)
#   ./healert.sh configure scoring --retention 14            (2-week window)
#   ./healert.sh configure scoring --threshold 20 --half-life 3  (strict + fast)
#   ./healert.sh configure scoring --reset                   (restore defaults)
cmd_configure_scoring() {
  local threshold="" half_life="" retention="" do_reset=false _has_flags=false

  # Load current values from backend .env
  _key_load
  local _cur_threshold _cur_half_life _cur_retention
  _cur_threshold=$(grep "^SCORE_CRITICAL_THRESHOLD=" "$BACKEND_ENV" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "50")
  _cur_half_life=$(grep "^SCORE_DECAY_HALF_LIFE="    "$BACKEND_ENV" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "7")
  _cur_retention=$(grep "^SCORE_RETENTION_DAYS="     "$BACKEND_ENV" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "30")
  [[ -z "$_cur_threshold" ]] && _cur_threshold="50"
  [[ -z "$_cur_half_life" ]] && _cur_half_life="7"
  [[ -z "$_cur_retention" ]] && _cur_retention="30"

  # Parse flags
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --threshold) threshold="$2"; shift 2; _has_flags=true ;;
      --half-life) half_life="$2"; shift 2; _has_flags=true ;;
      --retention) retention="$2"; shift 2; _has_flags=true ;;
      --reset)     do_reset=true;  shift;   _has_flags=true ;;
      *) _warn "Unknown option: $1"; shift ;;
    esac
  done

  _banner
  _header "Scoring Configuration"
  _sep
  _blank

  # Reset to defaults
  if [[ "$do_reset" == true ]]; then
    threshold=50; half_life=7; retention=30
    _info "Resetting scoring parameters to defaults"
    _blank
  fi

  # Interactive mode when no flags given
  if [[ "$_has_flags" == false ]]; then
    _info "Press Enter to keep current value"
    _blank

    echo -e "  ${BOLD}SCORE_CRITICAL_THRESHOLD${RESET}"
    echo -e "  ${DIM}Points needed for score=100. Lower = stricter.${RESET}"
    echo -e "  ${DIM}strict=20  balanced=50  lenient=100${RESET}"
    read -r -p "  Value [$_cur_threshold]: " _in
    [[ -n "$_in" ]] && threshold="$_in"
    _blank

    echo -e "  ${BOLD}SCORE_DECAY_HALF_LIFE${RESET}"
    echo -e "  ${DIM}Days for event weight to halve. Lower = faster decay.${RESET}"
    echo -e "  ${DIM}fast=3  balanced=7  slow=14${RESET}"
    read -r -p "  Value [$_cur_half_life]: " _in
    [[ -n "$_in" ]] && half_life="$_in"
    _blank

    echo -e "  ${BOLD}SCORE_RETENTION_DAYS${RESET}"
    echo -e "  ${DIM}Events older than this have zero weight.${RESET}"
    echo -e "  ${DIM}short=7  balanced=30  long=90${RESET}"
    read -r -p "  Value [$_cur_retention]: " _in
    [[ -n "$_in" ]] && retention="$_in"
    _blank
  fi

  # Use current values for unspecified params
  [[ -z "$threshold" ]] && threshold="$_cur_threshold"
  [[ -z "$half_life" ]] && half_life="$_cur_half_life"
  [[ -z "$retention" ]] && retention="$_cur_retention"

  # Validate — must be positive integers
  for _val in "$threshold" "$half_life" "$retention"; do
    [[ "$_val" =~ ^[0-9]+$ ]] && [[ "$_val" -gt 0 ]]       || _die "Value must be a positive integer, got: $_val"
  done

  # Warn about extreme values
  [[ "$threshold" -lt 10 ]] && _warn "threshold=$threshold is very strict — most events will be critical"
  [[ "$threshold" -gt 200 ]] && _warn "threshold=$threshold is very lenient — scores may never reach critical"
  [[ "$half_life" -lt 1 ]] && _warn "half_life=$half_life — events decay within hours"
  [[ "$retention" -lt 7 ]] && _warn "retention=$retention — less than one week of history"

  # Write to backend .env (remove old values first, then append)
  if [[ -f "$BACKEND_ENV" ]]; then
    local _tmp=""
    _tmp=$(mktemp)
    trap 'rm -f "${_tmp:-}" 2>/dev/null || true' RETURN
    grep -v "^SCORE_CRITICAL_THRESHOLD=\|^SCORE_DECAY_HALF_LIFE=\|^SCORE_RETENTION_DAYS="       "$BACKEND_ENV" > "$_tmp" || true
    mv "$_tmp" "$BACKEND_ENV"
    chmod 600 "$BACKEND_ENV"
  fi

  # Append new values
  {
    echo "SCORE_CRITICAL_THRESHOLD=$threshold"
    echo "SCORE_DECAY_HALF_LIFE=$half_life"
    echo "SCORE_RETENTION_DAYS=$retention"
  } >> "$BACKEND_ENV"
  chmod 600 "$BACKEND_ENV"

  _blank
  _sep
  _blank
  _ok "Scoring parameters saved to $BACKEND_ENV"
  _blank

  # Show current configuration in a table
  echo -e "  ${BOLD}Active scoring configuration:${RESET}"
  _blank
  printf "    %-32s %s
" "SCORE_CRITICAL_THRESHOLD" "$threshold"
  printf "    %-32s %s days
" "SCORE_DECAY_HALF_LIFE" "$half_life"
  printf "    %-32s %s days
" "SCORE_RETENTION_DAYS" "$retention"
  _blank

  # Show what scores mean with current settings
  _info "Score reference with current settings:"
  _blank
  python3 - "$threshold" "$half_life" << 'PYEOF'
import sys, math
threshold  = int(sys.argv[1])
half_life  = int(sys.argv[2])
POINTS = {'high': 10, 'medium': 6, 'low': 3}

def score(events_today, sev):
    pts = events_today * POINTS[sev]
    return min(100, round((pts / threshold) * 100))

examples = [
    (1, 'high',   'low',      '1 high event today'),
    (3, 'high',   'high',     '3 high events today'),
    (5, 'high',   'critical', '5 high events today'),
    (1, 'medium', 'low',      '1 medium event today'),
    (5, 'medium', 'high',     '5 medium events today'),
]
for count, sev, _, label in examples:
    s = score(count, sev)
    sev_label = 'critical' if s>=80 else 'high' if s>=60 else 'medium' if s>=40 else 'low'
    print(f'    {label:<35} score={s:<4} ({sev_label})')

print()
decay_7  = round(math.pow(0.5, 7  / half_life), 2)
decay_14 = round(math.pow(0.5, 14 / half_life), 2)
decay_30 = round(math.pow(0.5, 30 / half_life), 2)
print(f'    Event weight after 7 days:  {decay_7}  ({int(decay_7*100)}% of original)')
print(f'    Event weight after 14 days: {decay_14}  ({int(decay_14*100)}% of original)')
print(f'    Event weight after 30 days: {decay_30}  ({int(decay_30*100)}% of original)')
PYEOF

  _blank
  _info "Restart backend to apply: ./$SCRIPT_NAME restart"
  _blank
}

# =============================================================================
# COMMANDS
# Open/Closed: adding a new command requires only a new cmd_* function.
# The dispatcher (main) never changes.
# Each function is self-contained: validates, executes, reports.
# =============================================================================

# _create_default_rules writes the default rules.yaml to the given path.
# Called automatically by cmd_deps when rules.yaml is missing.
# Produces the same 5 built-in rules the Go agent expects.
_create_default_rules() {
  local target="$1"

  # Ensure parent directory exists
  mkdir -p "$(dirname "$target")"

  cat > "$target" << 'RULES_EOF'
# rules.yaml — Healert Agent Detection Rules
#
# Loaded at startup via RULES_PATH environment variable.
# RULES_PATH is required — the agent will not start without this file.
# There are no built-in default rules in the agent binary.
#
# All match fields are optional — omit to match any value.
# All specified fields must match (AND logic).
# ALL rules are evaluated per event — multiple rules can fire.

rules:

  - name: kubectl-exec
    description: "kubectl exec on {resource}/{name} (ns:{namespace}) by {actor} — bypasses GitOps pipeline"
    severity: high
    workflow: deploy
    ignore_system: true
    match:
      resource: pods
      subresource: exec

  - name: pipeline-skip
    description: "Policy gate bypassed on {resource}/{name} (ns:{namespace}) by {actor}"
    severity: high
    workflow: deploy
    ignore_system: true
    match:
      annotation: "policy.admission.k8s.io/bypass=true"

  - name: emergency-access
    description: "Direct secret access {resource}/{name} in namespace {namespace} by {actor}"
    severity: medium
    workflow: incident
    ignore_system: true
    match:
      resource: secrets
      verb: get

  - name: config-drift
    description: "Direct {verb} on {resource}/{name} (ns:{namespace}) by {actor} — bypasses GitOps"
    severity: high
    workflow: deploy
    ignore_system: true
    match:
      resources:
        - pods
        - deployments
        - statefulsets
        - daemonsets
        - replicasets
        - jobs
        - cronjobs
      verbs:
        - create
        - update
        - patch

  - name: port-forward
    description: "kubectl port-forward on {resource}/{name} (ns:{namespace}) by {actor} — direct port access"
    severity: medium
    workflow: debug
    ignore_system: true
    match:
      resource: pods
      subresource: portforward
RULES_EOF
}

# cmd_init — Interactive setup of directory paths.
# Called once before first use to configure where backend, agent, and plugin live.
# Saves paths to .healert-config in home directory so they persist across sessions.
cmd_init() {
  _banner
  _header "Healert Directory Configuration"
  _sep
  _blank

  local config_file="$HOME/.healert-config"
  local backend_dir="$BACKEND_DIR"
  local agent_dir="$AGENT_DIR"

  _info "Where are your Healert components located?"
  _blank

  # Backend directory
  read -r -p "  Backend directory [$backend_dir]: " _in
  if [[ -n "$_in" ]]; then
    [[ "$_in" == /* ]] || _die "Backend directory must be absolute: $_in"
    [[ "$_in" != *..* ]] || _die "Backend directory must not contain ..: $_in"
    backend_dir="$_in"
  fi

  if [[ ! -d "$backend_dir" ]]; then
    _warn "Backend directory does not exist: $backend_dir"
    _dim "Create it now? (mkdir -p $backend_dir)"
    read -r -p "  Create? (y/n): " _create
    if [[ "$_create" == "y" ]]; then
      mkdir -p "$backend_dir"
      _ok "Created: $backend_dir"
    else
      _die "Backend directory required. Aborting."
    fi
  fi

  # Agent directory
  read -r -p "  Agent directory [$agent_dir]: " _in
  if [[ -n "$_in" ]]; then
    [[ "$_in" == /* ]] || _die "Agent directory must be absolute: $_in"
    [[ "$_in" != *..* ]] || _die "Agent directory must not contain ..: $_in"
    agent_dir="$_in"
  fi

  if [[ ! -d "$agent_dir" ]]; then
    _warn "Agent directory does not exist: $agent_dir"
    _dim "Create it now? (mkdir -p $agent_dir)"
    read -r -p "  Create? (y/n): " _create
    if [[ "$_create" == "y" ]]; then
      mkdir -p "$agent_dir"
      _ok "Created: $agent_dir"
    else
      _die "Agent directory required. Aborting."
    fi
  fi

  _blank

  # Save to config file
  cat > "$config_file" << CONFEOF
# Healert Configuration
# Auto-generated by ./healert.sh init
# Edit or delete to reconfigure directories

export HEALERT_BACKEND_DIR="$backend_dir"
export HEALERT_AGENT_DIR="$agent_dir"
CONFEOF

  _blank
  _ok "Export these variables before running setup:"
  echo ""
  printf '    export HEALERT_BACKEND_DIR="%s"
' "$backend_dir"
  printf '    export HEALERT_AGENT_DIR="%s"
'   "$agent_dir"
  echo ""
  _info "Then run:"
  echo "    ./$SCRIPT_NAME setup"
  echo "    ./$SCRIPT_NAME start"
  _blank
}

# cmd_deps checks all runtime dependencies and installs missing ones.
# Covers: bash, curl, python3, Go, uvicorn, kubectl (if Kubernetes mode).
cmd_deps() {
  _banner
  _header "Dependency Check"
  _sep
  _blank

  local missing=0

  # ── System dependencies ────────────────────────────────────────────────────
  _info "Checking system dependencies..."
  _blank

  _dep_check_one "bash 4+" \
    "bash" "--version" \
    "brew install bash  OR  apt install bash" \
    || ((missing++))

  _dep_check_one "curl" \
    "curl" "--version" \
    "apt install curl  OR  brew install curl" \
    || ((missing++))

  _dep_check_one "python3" \
    "python3" "--version" \
    "apt install python3  OR  brew install python3" \
    || ((missing++))

  _dep_check_one "openssl" \
    "openssl" "version" \
    "apt install openssl  OR  brew install openssl" \
    || ((missing++))

  _blank

  # ── Go agent dependencies ──────────────────────────────────────────────────
  _info "Checking Go agent dependencies..."
  _blank

  _dep_check_one "Go 1.22+" \
    "go" "version" \
    "https://go.dev/dl/" \
    || ((missing++))

  if [[ ! -f "$AGENT_BIN" ]]; then
    _warn "Agent binary not built — run: go build -o healert-agent main.go"
    ((missing++))
  else
    _ok "Agent binary — $(stat -c%s "$AGENT_BIN" | numfmt --to=iec 2>/dev/null || stat -c%s "$AGENT_BIN")B"
  fi

  _blank

  # ── Backend Python dependencies ────────────────────────────────────────────
  _info "Checking backend Python dependencies..."
  _blank

  # ── Resolve Python environment ──────────────────────────────────────────────
  # Priority: existing venv > create venv > system pip with --break-system-packages
  # Ubuntu 22.04+ blocks system-wide pip installs (PEP 668) — venv is the correct fix
  local _pip=""
  local _python="python3"

  if [[ -f "$BACKEND_DIR/venv/bin/pip" ]]; then
    # Existing venv — use it
    _pip="$BACKEND_DIR/venv/bin/pip"
    _python="$BACKEND_DIR/venv/bin/python3"
    _dim "Using existing venv: $BACKEND_DIR/venv"
  else
    # No venv — create one in the backend directory
    _info "Creating Python virtual environment in $BACKEND_DIR/venv ..."
    if python3 -m venv "$BACKEND_DIR/venv" 2>/dev/null; then
      _pip="$BACKEND_DIR/venv/bin/pip"
      _python="$BACKEND_DIR/venv/bin/python3"
      # Upgrade pip silently inside venv
      "$_pip" install --upgrade pip --quiet 2>/dev/null || true
      _ok "Virtual environment created: $BACKEND_DIR/venv"
    else
      # venv creation failed — fall back to system pip with --break-system-packages
      _warn "Could not create venv — falling back to system pip"
      if command -v pip3 &>/dev/null; then
        _pip="pip3 --break-system-packages"
      elif command -v pip &>/dev/null; then
        _pip="pip --break-system-packages"
      fi
    fi
  fi

  # Helper: get installed package version
  _pkg_version() {
    "$_python" -c "import importlib.metadata; print(importlib.metadata.version('$1'))" 2>/dev/null       || echo "installed"
  }

  # Helper: check package importable in the resolved Python environment
  _pkg_installed() {
    "$_python" -c "import $1" &>/dev/null
  }

  local python_pkgs=("fastapi" "uvicorn" "pydantic" "slowapi")

  for pkg in "${python_pkgs[@]}"; do
    if _pkg_installed "$pkg"; then
      # Already installed — show version
      _ok "python: $pkg — v$(_pkg_version "$pkg")"
    else
      # Not installed — install now and recheck
      _warn "python: $pkg — not found, installing..."

      if [[ -n "$_pip" ]]; then
        if $_pip install "$pkg" --quiet 2>/dev/null; then
          if _pkg_installed "$pkg"; then
            _ok "python: $pkg — installed v$(_pkg_version "$pkg")"
          else
            _warn "python: $pkg — pip succeeded but import failed"
            _dim "Check: $_python -c "import $pkg""
            ((missing++))
          fi
        else
          _warn "python: $pkg — installation failed"
          _dim "Try manually: cd $BACKEND_DIR && source venv/bin/activate && pip install $pkg"
          ((missing++))
        fi
      else
        _warn "python: $pkg — no pip available"
        _dim "Fix: sudo apt install python3-pip python3-venv"
        ((missing++))
      fi
    fi
  done

  _blank

  # ── Kubernetes dependencies (optional) ────────────────────────────────────
  _info "Checking Kubernetes dependencies (required for --kubernetes mode)..."
  _blank

  _dep_check_one "kubectl" \
    "kubectl" "version --client" \
    "https://kubernetes.io/docs/tasks/tools/" \
    || _dim "Optional — only required for Kubernetes deployment mode"

  _blank

  # ── Configuration files ────────────────────────────────────────────────────
  _info "Checking configuration files..."
  _blank

  if [[ -f "$RULES" ]]; then
    _ok "rules.yaml — $RULES"
  else
    _info "rules.yaml not found at $RULES — creating from built-in defaults..."
    _create_default_rules "$RULES"
    if [[ -f "$RULES" ]]; then
      _ok "rules.yaml — created at $RULES"
    else
      _warn "rules.yaml — could not create at $RULES"
      ((missing++))
    fi
  fi
  if [[ -f "$DAEMONSET_YAML" ]]; then
    _ok  "daemonset.yaml — $DAEMONSET_YAML"
  else
    _dim "daemonset.yaml not found (only needed for Kubernetes mode)"
  fi

  if [[ -f "$BACKEND_ENV" ]]; then
    _ok  "Backend .env — exists ($(stat -c%a "$BACKEND_ENV") permissions)"
  else
    _dim "Backend .env not found — run: ./$SCRIPT_NAME setup"
  fi

  if [[ -f "$AGENT_ENV" ]]; then
    _ok  "Agent .env — exists ($(stat -c%a "$AGENT_ENV") permissions)"
  else
    _dim "Agent .env not found — run: ./$SCRIPT_NAME setup"
  fi

  _blank
  _sep
  _blank

  if [[ $missing -eq 0 ]]; then
    _ok "All dependencies satisfied"
    _blank
    echo -e "  ${BOLD}Next step:${RESET}"
    echo -e "    ./$SCRIPT_NAME setup"
  else
    _warn "$missing dependency/dependencies need attention"
    _blank
    echo -e "  ${BOLD}Next step:${RESET}"
    echo -e "    Fix the issues above then run: ./$SCRIPT_NAME deps"
  fi

  _blank
}

# cmd_setup generates an API key and configures both backend and agent.
# In local mode: writes to .env files.
# In kubernetes mode: also creates a Kubernetes Secret.
cmd_setup() {
  local rotate=false
  # Accept both "rotate" and "--rotate"
  local _arg="${1:-}"
  [[ "$_arg" == "--rotate" || "$_arg" == "rotate" ]] && rotate=true

  _banner
  _header "Setup — API Key Configuration"
  _sep
  _blank

  # Validate required directories exist before generating anything
  [[ -d "$BACKEND_DIR" ]] || _die "Backend directory not found: $BACKEND_DIR\n  Set HEALERT_BACKEND_DIR"
  [[ -d "$AGENT_DIR" ]]   || _die "Agent directory not found: $AGENT_DIR"

  # Warn before overwriting an existing key
  if [[ "$rotate" == false ]] \
     && [[ -f "$BACKEND_ENV" ]] \
     && grep -q "^HEALERT_API_KEY=" "$BACKEND_ENV" 2>/dev/null; then
    _warn "API key already configured in $BACKEND_ENV"
    _blank
    read -r -p "  Overwrite existing key? [y/N] " _confirm
    _blank
    [[ "$_confirm" =~ ^[Yy]$ ]] || { _info "Setup cancelled — key unchanged."; exit 0; }
    unset _confirm
  fi

  [[ "$rotate" == true ]] && _info "Rotating existing API key..."

  # Generate — never echoed to terminal or logs
  _info "Generating cryptographically secure API key..."
  local _api_key
  _api_key=$(_key_generate)
  _ok "API key generated (${#_api_key} chars via openssl)"

  # Write to backend .env with secure permissions
  _info "Writing to backend .env..."
  _key_write "$BACKEND_ENV" "$_api_key"
  _ok "Written to $BACKEND_ENV (permissions: 600)"

  # Write to agent .env with secure permissions
  _info "Writing to agent .env..."
  _key_write "$AGENT_ENV" "$_api_key"
  _ok "Written to $AGENT_ENV (permissions: 600)"

  # Add to .gitignore in both repos
  _gitignore_add "$BACKEND_DIR"
  _gitignore_add "$AGENT_DIR"

  # Write agent runtime config — agent-specific settings separate from API key
  _blank
  _info "Writing agent runtime configuration..."
  _agent_config_create "$AUDIT_LOG" "$RULES" "$ENTITY_NS"

  # Kubernetes mode — also create a K8s Secret if cluster is reachable
  # _validate_kubernetes sets KUBECTL and KUBECONFIG before calling k8s functions
  if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
    _blank
    _info "Kubernetes cluster detected — also creating Kubernetes Secret..."
    _validate_kubernetes
    _k8s_create_namespace
    _k8s_create_secret "$_api_key"
    _k8s_verify_secret "$_api_key"
  elif command -v k3s &>/dev/null && sudo k3s kubectl cluster-info &>/dev/null 2>&1; then
    _blank
    _info "k3s cluster detected — also creating Kubernetes Secret..."
    export KUBECTL="k3s kubectl"
    export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
    _k8s_create_namespace
    _k8s_create_secret "$_api_key"
    _k8s_verify_secret "$_api_key"
  fi

  # Verify keys match between files
  _info "Verifying keys match..."
  _key_verify "$BACKEND_ENV" "$AGENT_ENV" \
    || _die "Key mismatch between .env files — re-run setup"
  _ok "Keys verified — backend and agent have identical key"

  # Clear the key from memory
  unset _api_key

  _blank
  _sep
  _blank

  if [[ "$rotate" == true ]]; then
    echo -e "  ${AMBER}Key rotated. Restart to apply:${RESET}"
    echo -e "    ${BOLD}./$SCRIPT_NAME restart${RESET}"
  else
    echo -e "  ${GREEN}${BOLD}Setup complete.${RESET}"
    echo -e "  Start the platform:  ${BOLD}./$SCRIPT_NAME start${RESET}"
  fi

  _blank
  echo -e "  ${AMBER}Security reminders:${RESET}"
  _dim "Never commit .env to git — add .env to .gitignore"
  _dim "Keys stored with chmod 600 — only you can read them"
  # Show paths relative to HOME to avoid exposing username in output
  local _b_rel="${BACKEND_ENV/#$HOME/~}"
  local _a_rel="${AGENT_ENV/#$HOME/~}"
  _dim "Backend: $_b_rel"
  _dim "Agent:   $_a_rel"
  _blank
}

# cmd_start starts backend and/or agent based on the mode flag.
# Local mode (default): starts backend as uvicorn, agent as binary.
# Kubernetes mode: starts backend locally, deploys agent as DaemonSet.
cmd_start() {
  # Accept both "backend" and "--backend" format for flexibility
  local _raw_target="${1:-both}"
  local target="${_raw_target#--}"  # strip leading -- if present

  _banner
  _header "Starting Healert Platform"
  _sep
  _blank

  # Load API key from .env files — must happen before any process starts
  _key_load

  if [[ -n "${HEALERT_API_KEY:-}" ]]; then
    _ok "API key loaded (${#HEALERT_API_KEY} chars)"
  else
    _warn "HEALERT_API_KEY is not set — run: ./$SCRIPT_NAME setup"
  fi

  _blank

  # ── Backend (always local regardless of mode) ──────────────────────────────
  if [[ "$target" == "both" || "$target" == "backend" ]]; then
    _validate_backend
    _blank

    if _proc_is_running "$BACKEND_PID"; then
      _warn "Backend already running (PID $(_proc_pid "$BACKEND_PID"))"
    else
      local _uvicorn
      _uvicorn=$(_find_uvicorn)

      # passing secrets as command arguments — prevents exposure in ps aux
      export HEALERT_API_KEY="${HEALERT_API_KEY:-}"
      export HEALERT_ALLOWED_ORIGINS="${HEALERT_ALLOWED_ORIGINS:-http://localhost:3000}"
      export HEALERT_RETENTION_DAYS="${HEALERT_RETENTION_DAYS:-30}"
      export HEALERT_DB="${HEALERT_DB:-$BACKEND_DIR/healert.db}"

      _proc_start "Backend" "$BACKEND_PID" "$BACKEND_LOG" \
        "$_uvicorn" main:app \
          --app-dir "$BACKEND_DIR" \
          --host "$BACKEND_HOST" \
          --port "$BACKEND_PORT" \
          --log-level info

      _info "Waiting for backend health check..."
      if _health_wait "$BACKEND_URL/health"; then
        local _version _auth
        _version=$(_health_field "$BACKEND_URL/health" "version")
        _auth=$(_health_field "$BACKEND_URL/health" "auth")
        _ok "Backend healthy — version=$_version auth=$_auth"
        _health_auth_mismatch "${HEALERT_API_KEY:-}"
      else
        _err "Backend did not become healthy within 10 seconds"
        _err "Check log: $BACKEND_LOG"
        tail -10 "$BACKEND_LOG" >&2 || true
        _proc_stop "backend" "$BACKEND_PID"
        exit 1
      fi
    fi

    _blank
  fi

  # ── Agent — local mode ─────────────────────────────────────────────────────
  if [[ "$target" == "both" || "$target" == "agent" ]]; then
    _validate_agent
    _blank

    # When starting agent only, check if backend is running.
    # Warn if it is not — but do NOT exit. The agent will retry
    # sending events when the backend comes back online.
    if [[ "$target" == "agent" ]]; then
      if _health_check "$BACKEND_URL/health"; then
        _ok "Backend reachable at $BACKEND_URL"
      else
        _warn "Backend is not running at $BACKEND_URL"
        _warn "Agent will start and tail the audit log."
        _warn "Events will be sent when backend becomes available."
        _dim  "Start backend: ./$SCRIPT_NAME start backend"
      fi
      _blank
    fi

    if _proc_is_running "$AGENT_PID"; then
      _warn "Agent already running (PID $(_proc_pid "$AGENT_PID"))"
    else
      # Inject env vars — prevents API key from appearing in ps aux output
      export HEALERT_BACKEND_URL="$BACKEND_URL"
      export HEALERT_API_KEY="${HEALERT_API_KEY:-}"
      export AUDIT_LOG_PATH="$AUDIT_LOG"
      export ENTITY_NAMESPACE="$ENTITY_NS"
      export RULES_PATH="$RULES"

      _proc_start "Agent" "$AGENT_PID" "$AGENT_LOG"         "$AGENT_BIN"

      # Wait 2 seconds then verify agent is still alive.
      # This catches hard failures: missing binary, bad rules.yaml, wrong path.
      # It does NOT catch backend-unreachable — that is handled above with a warning.
      _proc_verify "Agent" "$AGENT_PID" "$AGENT_LOG" 2

      _ok "Agent running"
      _dim "Audit: $AUDIT_LOG"
      _dim "Rules: $RULES"
    fi

    _blank
  fi

  # ── Agent — Kubernetes DaemonSet mode ─────────────────────────────────────
  if [[ "$target" == "kubernetes" ]]; then
    _validate_kubernetes
    _blank

    _info "Deploying agent as Kubernetes DaemonSet..."

    # Ensure namespace and secret exist before applying DaemonSet
    _k8s_create_namespace
    _k8s_create_secret "${HEALERT_API_KEY:-}"
    _k8s_verify_secret "${HEALERT_API_KEY:-}"
    _k8s_deploy

    _blank
    _ok "Kubernetes deployment complete"
    _dim "Check pods: $KUBECTL get pods -n $K8S_NS -o wide"
    _dim "Check logs: $KUBECTL logs -n $K8S_NS -l app=healert-agent --tail=20"
    _blank
  fi

  # ── Summary ────────────────────────────────────────────────────────────────
  if [[ "$target" == "both" ]]; then
    _sep
    _blank
    echo -e "  ${BOLD}${GREEN}Platform is running${RESET}"
    _blank
    echo -e "  ${BOLD}Backend:${RESET}  $BACKEND_URL"
    echo -e "  ${BOLD}Agent:${RESET}    tailing $AUDIT_LOG"
    _blank
    echo -e "  ${BOLD}Commands:${RESET}"
    echo -e "    ./$SCRIPT_NAME status   check health"
    echo -e "    ./$SCRIPT_NAME logs     tail live logs"
    echo -e "    ./$SCRIPT_NAME test     verify pipeline"
    echo -e "    ./$SCRIPT_NAME stop     stop everything"
    _blank
  fi
}

# cmd_stop stops all or specific Healert processes.
#
# Usage:
#   ./healert.sh stop              Stop both backend and agent
#   ./healert.sh stop backend      Stop backend only, keep agent running
#   ./healert.sh stop agent        Stop agent only, keep backend running
#
# For Kubernetes DaemonSet: kubectl delete -f daemonset.yaml
cmd_stop() {
  # Accept both "backend" and "--backend" format
  local _raw_target="${1:-both}"
  local target="${_raw_target#--}"

  _banner
  _header "Stopping Healert Platform"
  _sep
  _blank

  case "$target" in
    # ── Stop backend only ────────────────────────────────────────────────────
    backend)
      _proc_stop "Backend" "$BACKEND_PID"
      _blank
      # Report agent status — we are NOT stopping it
      printf "  %-12s" "Agent"
      if _proc_is_running "$AGENT_PID"; then
        echo -e "${GREEN}● still running${RESET}  PID=$(_proc_pid "$AGENT_PID")  (not stopped)"
      else
        echo -e "${DIM}● not running${RESET}"
      fi
      ;;

    # ── Stop agent only ──────────────────────────────────────────────────────
    agent)
      _proc_stop "Agent" "$AGENT_PID"
      _blank
      # Report backend status — we are NOT stopping it
      printf "  %-12s" "Backend"
      if _proc_is_running "$BACKEND_PID"; then
        echo -e "${GREEN}● still running${RESET}  PID=$(_proc_pid "$BACKEND_PID")  $BACKEND_URL  (not stopped)"
      else
        echo -e "${DIM}● not running${RESET}"
      fi
      ;;

    # ── Stop both simultaneously (default) ──────────────────────────────────
    both|*)
      # Send SIGTERM to both processes at the same time — no waiting between them
      local _backend_pid="" _agent_pid=""

      if _proc_is_running "$BACKEND_PID"; then
        _backend_pid=$(_proc_pid "$BACKEND_PID")
        _info "Stopping Backend (PID $_backend_pid)..."
        kill "$_backend_pid" 2>/dev/null || true
      else
        _dim "Backend is not running"
      fi

      if _proc_is_running "$AGENT_PID"; then
        _agent_pid=$(_proc_pid "$AGENT_PID")
        _info "Stopping Agent   (PID $_agent_pid)..."
        kill "$_agent_pid" 2>/dev/null || true
      else
        _dim "Agent is not running"
      fi

      # Wait for both to exit (up to 5 seconds total — not per process)
      local _i=0
      while [[ $_i -lt 10 ]]; do
        local _backend_alive=false _agent_alive=false
        [[ -n "$_backend_pid" ]] && kill -0 "$_backend_pid" 2>/dev/null && _backend_alive=true
        [[ -n "$_agent_pid"   ]] && kill -0 "$_agent_pid"   2>/dev/null && _agent_alive=true
        [[ "$_backend_alive" == false && "$_agent_alive" == false ]] && break
        sleep 0.5
        ((_i++))
      done

      # Force kill anything still alive after 5 seconds
      [[ -n "$_backend_pid" ]] && kill -9 "$_backend_pid" 2>/dev/null || true
      [[ -n "$_agent_pid"   ]] && kill -9 "$_agent_pid"   2>/dev/null || true

      # Clean up PID files
      rm -f "$BACKEND_PID" "$AGENT_PID"

      _ok "Backend stopped"
      _ok "Agent stopped"
      ;;
  esac

  _blank
  _ok "Done"
  _blank
}

# cmd_validate checks rules.yaml for correctness before applying.
# Catches missing required fields, bad annotation format, and duplicate names.
# Called automatically by cmd_restart — safe to call independently.
#
# Usage:
#   ./healert.sh validate
#   ./healert.sh validate --rules /path/to/rules.yaml
cmd_validate() {
  local rules_file="${1:-$RULES}"
  # Strip --rules flag if passed
  [[ "$rules_file" == "--rules" ]] && rules_file="${2:-$RULES}"

  _banner
  _header "Validating rules.yaml"
  _sep
  _blank

  [[ -f "$rules_file" ]] \
    || _die "Rules file not found: $rules_file\n  Set RULES_PATH or run: ./$SCRIPT_NAME configure --rules PATH"

  _info "Validating: $rules_file"
  _blank

  # Python validator — zero external dependencies beyond stdlib
  # Initialise to empty string first — prevents unbound variable error
  # under set -u if mktemp fails or trap fires before assignment.
  local _tmppy=""
  _tmppy=$(mktemp /tmp/healert_validate.XXXXXX.py)
  trap 'rm -f "${_tmppy:-}" 2>/dev/null || true' RETURN

  cat > "$_tmppy" << 'PYEOF'
import sys

rules_path = sys.argv[1]
with open(rules_path) as f:
    lines = f.readlines()

errors   = []
warnings = []
rules    = []
current  = None

VALID_SEVERITIES = {"high", "medium", "low"}
VALID_WORKFLOWS  = {"deploy", "incident", "debug", "rollback", "release"}

for i, raw_line in enumerate(lines, 1):
    stripped = raw_line.strip()
    if not stripped or stripped.startswith("#"):
        continue

    if stripped.startswith("- name:"):
        if current:
            rules.append(current)
        name = stripped.replace("- name:", "").strip().strip('"').strip("'")
        if not name:
            errors.append(f"Line {i}: rule has empty name")
        current = {
            "name": name, "line": i,
            "has_severity": False, "has_workflow": False, "has_match": False,
            "severity": None, "workflow": None,
        }
        continue

    if current is None:
        continue

    if stripped.startswith("severity:"):
        val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        current["has_severity"] = True
        current["severity"] = val
        if val not in VALID_SEVERITIES:
            errors.append(
                f"Rule '{current['name']}' line {i}: "
                f"invalid severity '{val}' — must be: {', '.join(sorted(VALID_SEVERITIES))}"
            )
    elif stripped.startswith("workflow:"):
        val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        current["has_workflow"] = True
        current["workflow"] = val
        if val not in VALID_WORKFLOWS:
            warnings.append(
                f"Rule '{current['name']}' line {i}: "
                f"unknown workflow '{val}' — known: {', '.join(sorted(VALID_WORKFLOWS))}"
            )
    elif stripped.startswith("match:"):
        current["has_match"] = True
    elif stripped.startswith("annotation:"):
        val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        if "=" not in val:
            errors.append(
                f"Rule '{current['name']}' line {i}: "
                f"annotation must be key=value format, got: '{val}'"
            )
    elif stripped.startswith("ignore_system:"):
        val = stripped.split(":", 1)[1].strip().lower()
        if val not in ("true", "false"):
            errors.append(
                f"Rule '{current['name']}' line {i}: "
                f"ignore_system must be true or false, got: '{val}'"
            )

if current:
    rules.append(current)

for rule in rules:
    if not rule["has_severity"]:
        errors.append(f"Rule '{rule['name']}' line {rule['line']}: missing required field: severity")
    if not rule["has_workflow"]:
        errors.append(f"Rule '{rule['name']}' line {rule['line']}: missing required field: workflow")
    if not rule["has_match"]:
        errors.append(f"Rule '{rule['name']}' line {rule['line']}: missing required field: match")

names = [r["name"] for r in rules]
for name in set(names):
    if names.count(name) > 1:
        errors.append(f"Duplicate rule name: '{name}'")

if not rules:
    errors.append("No rules found — file appears empty or has no '- name:' entries")

print(f"RULES={len(rules)}")
for r in rules:
    print(f"RULE {r['name']}|{r['severity'] or '?'}|{r['workflow'] or '?'}|{r['line']}")
for w in warnings:
    print(f"WARN {w}")
for e in errors:
    print(f"ERR  {e}")
print(f"ERRORS={len(errors)}")
print(f"WARNINGS={len(warnings)}")
PYEOF

  local _result
  _result=$(python3 "$_tmppy" "$rules_file" 2>&1)

  local _rule_count=0 _error_count=0 _warn_count=0

  while IFS= read -r line; do
    case "$line" in
      RULES=*)    _rule_count="${line#RULES=}" ;;
      RULE\ *)
        local _rname _rsev _rwf _rline
        local _rdata="${line#RULE }"
        _rname=$(printf '%s' "$_rdata" | cut -d'|' -f1)
        _rsev=$(printf  '%s' "$_rdata" | cut -d'|' -f2)
        _rwf=$(printf   '%s' "$_rdata" | cut -d'|' -f3)
        _rline=$(printf '%s' "$_rdata" | cut -d'|' -f4)
        printf "    ${GREEN}✓${RESET}  %-28s severity=%-8s workflow=%s  (line %s)\n" \
          "$_rname" "$_rsev" "$_rwf" "$_rline"
        ;;
      WARN\ *)
        _warn "${line#WARN }"
        ((_warn_count++)) || true
        ;;
      ERR\ \ *)
        _err "${line#ERR  }"
        ((_error_count++)) || true
        ;;
      ERRORS=*)   _error_count="${line#ERRORS=}" ;;
      WARNINGS=*) _warn_count="${line#WARNINGS=}" ;;
    esac
  done <<< "$_result"

  _blank
  _sep
  _blank

  if [[ "$_error_count" -eq 0 ]]; then
    _ok "$_rule_count rules validated — no errors"
    [[ "$_warn_count" -gt 0 ]] && _warn "$_warn_count warning(s) — review above"
    _blank
    return 0
  else
    _err "$_error_count error(s) found — fix before restarting"
    _blank
    echo -e "  ${BOLD}Fix errors then run:${RESET}"
    echo -e "    ./$SCRIPT_NAME validate"
    echo -e "    ./$SCRIPT_NAME restart"
    _blank
    return 1
  fi
}

# cmd_restart restarts only what is currently running.
# If only backend is running — only backend is restarted.
# If only agent is running — only agent is restarted.
# If neither is running — exits with a clear message.
#
# Validates rules.yaml BEFORE stopping — if validation fails the running
# processes are left untouched so production is not disrupted.
# Reloads the API key from .env files — picks up any key rotations.
#
# Usage:
#   ./healert.sh restart              — restart whatever is currently running
#   ./healert.sh update kubernetes    — rolling restart of DaemonSet (no redeploy)
cmd_restart() {
  _banner
  _header "Restarting Healert Platform"
  _sep
  _blank

  # ── Detect what is currently running ────────────────────────────────────────
  local _backend_running=false _agent_running=false
  _proc_is_running "$BACKEND_PID" && _backend_running=true
  _proc_is_running "$AGENT_PID"   && _agent_running=true

  # Nothing running — nothing to restart
  if [[ "$_backend_running" == false && "$_agent_running" == false ]]; then
    _warn "Nothing is running — nothing to restart"
    _blank
    _dim "Start with: ./$SCRIPT_NAME start"
    _blank
    return 0
  fi

  # Show what will be restarted
  [[ "$_backend_running" == true ]] && _info "Will restart: Backend"
  [[ "$_agent_running"   == true ]] && _info "Will restart: Agent"
  _blank

  # ── Step 1: Validate rules.yaml before touching running processes ───────────
  # Only validate if agent is running — rules only affect the agent.
  # If validation fails — abort immediately, leave everything running as-is.
  if [[ "$_agent_running" == true && -f "$RULES" ]]; then
    _info "Validating rules.yaml before restart..."
    _blank
    if ! cmd_validate "$RULES"; then
      _blank
      _err "Restart aborted — fix rules.yaml errors first"
      _dim "Processes continue running with the previous (working) rules"
      _blank
      exit 1
    fi
    _blank
    _ok "rules.yaml valid — proceeding with restart"
    _blank
  fi

  # ── Step 2: Stop only what is running ───────────────────────────────────────
  local _backend_pid="" _agent_pid=""

  if [[ "$_backend_running" == true ]]; then
    _backend_pid=$(_proc_pid "$BACKEND_PID")
    _info "Stopping Backend (PID $_backend_pid)..."
    kill "$_backend_pid" 2>/dev/null || true
  fi

  if [[ "$_agent_running" == true ]]; then
    _agent_pid=$(_proc_pid "$AGENT_PID")
    _info "Stopping Agent   (PID $_agent_pid)..."
    kill "$_agent_pid" 2>/dev/null || true
  fi

  # ── Step 3: Wait for stopped processes to exit (up to 5 seconds) ───────────
  local _i=0
  while [[ $_i -lt 10 ]]; do
    local _b_alive=false _a_alive=false
    [[ -n "$_backend_pid" ]] && kill -0 "$_backend_pid" 2>/dev/null && _b_alive=true
    [[ -n "$_agent_pid"   ]] && kill -0 "$_agent_pid"   2>/dev/null && _a_alive=true
    [[ "$_b_alive" == false && "$_a_alive" == false ]] && break
    sleep 0.5
    ((_i++)) || true
  done

  # Force kill anything still alive after 5 seconds
  [[ -n "$_backend_pid" ]] && kill -9 "$_backend_pid" 2>/dev/null || true
  [[ -n "$_agent_pid"   ]] && kill -9 "$_agent_pid"   2>/dev/null || true
  [[ -n "$_backend_pid" ]] && rm -f "$BACKEND_PID"
  [[ -n "$_agent_pid"   ]] && rm -f "$AGENT_PID"

  _blank
  _ok "Stopped"
  _blank
  sleep 1
  _key_load

  # ── Step 4: Restart only what was running ───────────────────────────────────

  if [[ "$_backend_running" == true ]]; then
    _info "Starting Backend..."

    export HEALERT_API_KEY="${HEALERT_API_KEY:-}"
    export HEALERT_ALLOWED_ORIGINS="${HEALERT_ALLOWED_ORIGINS:-http://localhost:3000}"
    export HEALERT_RETENTION_DAYS="${HEALERT_RETENTION_DAYS:-30}"
    export HEALERT_DB="${HEALERT_DB:-$BACKEND_DIR/healert.db}"
    local _uv3; _uv3=$(_find_uvicorn)
    _proc_start "Backend" "$BACKEND_PID" "$BACKEND_LOG" \
      "$_uv3" main:app \
        --app-dir "$BACKEND_DIR" \
        --host "$BACKEND_HOST" \
        --port "$BACKEND_PORT" \
        --log-level info

    if _health_wait "$BACKEND_URL/health"; then
      local _ver _auth
      _ver=$(_health_field "$BACKEND_URL/health" "version")
      _auth=$(_health_field "$BACKEND_URL/health" "auth")
      _ok "Backend healthy — version=$_ver auth=$_auth"
    else
      _err "Backend did not become healthy — check log: $BACKEND_LOG"
      tail -5 "$BACKEND_LOG" >&2 || true
      exit 1
    fi
    _blank
  fi

  if [[ "$_agent_running" == true ]]; then
    _info "Starting Agent..."
    _validate_agent

    export HEALERT_BACKEND_URL="$BACKEND_URL"
    export HEALERT_API_KEY="${HEALERT_API_KEY:-}"
    export AUDIT_LOG_PATH="$AUDIT_LOG"
    export ENTITY_NAMESPACE="$ENTITY_NS"
    export RULES_PATH="$RULES"

    _proc_start "Agent" "$AGENT_PID" "$AGENT_LOG" "$AGENT_BIN"
    _proc_verify "Agent" "$AGENT_PID" "$AGENT_LOG" 2
    _blank
  fi

  # ── Summary ─────────────────────────────────────────────────────────────────
  [[ "$_backend_running" == true ]] && _ok "Backend restarted"
  [[ "$_agent_running"   == true ]] && _ok "Agent restarted"
  _blank
  _dim "Run ./$SCRIPT_NAME status to verify"
  _dim "Run ./$SCRIPT_NAME logs to watch live"
  _blank
}

# cmd_reset deletes the SQLite database and creates a fresh empty one.
# All recorded friction events, scores, and history are permanently deleted.
# The backend must be stopped before resetting — the command handles this.
#
# Usage:
#   ./healert.sh reset            — interactive confirmation required
#   ./healert.sh reset --confirm  — skip confirmation (for scripts/CI)
#
# What is deleted:
#   - All friction events
#   - All calculated scores
#   - All actor history
#   - All workflow data
#
# What is NOT deleted:
#   - rules.yaml detection rules
#   - .env API key configuration
#   - .agent-config agent settings
#   - Backstage plugin or catalog data
cmd_reset() {
  local _confirm=false
  [[ "${1:-}" == "--confirm" ]] && _confirm=true

  _banner
  _header "Reset Healert Database"
  _sep
  _blank

  # Resolve database path
  local _db="${HEALERT_DB:-$BACKEND_DIR/healert.db}"

  _warn "This will permanently delete ALL recorded data:"
  _blank
  echo -e "    Database:  $_db"
  echo -e "    Contents:  all friction events, scores, actor history"
  _blank

  if [[ ! -f "$_db" ]]; then
    _info "Database not found: $_db"
    _info "Nothing to reset — database will be created fresh on next start"
    _blank
    return 0
  fi

  # Require explicit confirmation unless --confirm flag is passed
  if [[ "$_confirm" == false ]]; then
    echo -e "  ${BOLD}${RED}WARNING: This cannot be undone.${RESET}"
    _blank
    printf "  Type 'yes' to confirm: "
    local _answer
    read -r _answer
    _blank
    if [[ "$_answer" != "yes" ]]; then
      _info "Reset cancelled"
      _blank
      return 0
    fi
  fi

  # Stop backend if running — cannot reset while backend holds db lock
  local _was_running=false
  if _proc_is_running "$BACKEND_PID"; then
    _was_running=true
    _info "Stopping backend to release database lock..."
    local _bpid
    _bpid=$(_proc_pid "$BACKEND_PID")
    kill "$_bpid" 2>/dev/null || true
    local _i=0
    while kill -0 "$_bpid" 2>/dev/null && [[ $_i -lt 10 ]]; do
      sleep 0.5; ((_i++)) || true
    done
    kill -9 "$_bpid" 2>/dev/null || true
    rm -f "$BACKEND_PID"
    _ok "Backend stopped"
    _blank
  fi

  # Delete database
  _info "Deleting database: $_db"
  rm -f "$_db"
  _ok "Database deleted"

  # Create fresh empty database by starting backend briefly
  _info "Creating fresh database..."
  _key_load

  export HEALERT_DB="$_db"
  local _uv5; _uv5=$(_find_uvicorn)
  _proc_start "Backend" "$BACKEND_PID" "$BACKEND_LOG" "$_uv5" main:app --app-dir "$BACKEND_DIR" --host "$BACKEND_HOST" --port "$BACKEND_PORT" --log-level warning

  # Wait for backend to initialise and create schema
  local _j=0
  while [[ $_j -lt 10 ]]; do
    sleep 0.5
    if _health_check "$BACKEND_URL/health" 2>/dev/null; then
      break
    fi
    ((_j++)) || true
  done

  # Verify fresh database exists
  if [[ -f "$_db" ]]; then
    local _size
    _size=$(du -h "$_db" 2>/dev/null | cut -f1)
    _ok "Fresh database created: $_db ($_size)"
  else
    _warn "Database file not found after init — check backend logs"
  fi

  # Stop backend again if it was not running before reset
  if [[ "$_was_running" == false ]]; then
    local _bpid2
    _bpid2=$(_proc_pid "$BACKEND_PID" 2>/dev/null) || true
    [[ -n "$_bpid2" ]] && kill "$_bpid2" 2>/dev/null || true
    rm -f "$BACKEND_PID"
    _blank
    _ok "Database reset complete"
    _dim "Start backend: ./$SCRIPT_NAME start backend"
  else
    _blank
    _ok "Database reset complete — backend is running with fresh database"
    _dim "Run ./$SCRIPT_NAME status to verify"
  fi

  _blank
}

# cmd_status shows the running state and health of all components.
cmd_status() {
  _key_load
  _banner
  _header "Platform Status"
  _sep
  _blank

  # Backend
  printf "  %-12s" "Backend"
  if _proc_is_running "$BACKEND_PID"; then
    local _pid _version _auth
    _pid=$(_proc_pid "$BACKEND_PID")
    _version=$(_health_field "$BACKEND_URL/health" "version")
    _auth=$(_health_field "$BACKEND_URL/health" "auth")
    echo -e "${GREEN}● running${RESET}  PID=$_pid  $BACKEND_URL"
    _dim "version=$_version  auth=$_auth"
  else
    echo -e "${RED}● stopped${RESET}"
  fi

  _blank

  # Agent — local
  printf "  %-12s" "Agent"
  if _proc_is_running "$AGENT_PID"; then
    local _pid
    _pid=$(_proc_pid "$AGENT_PID")
    echo -e "${GREEN}● running${RESET}  PID=$_pid"
    _dim "audit=$AUDIT_LOG"
    _dim "rules=$RULES"
  else
    echo -e "${RED}● stopped${RESET}"
  fi

  # Agent — Kubernetes
  if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
    _blank
    printf "  %-12s" "K8s Agent"
    if kubectl get daemonset healert-agent -n "$K8S_NS" &>/dev/null; then
      local _desired _ready
      _desired=$(kubectl get daemonset healert-agent -n "$K8S_NS" \
        -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "?")
      _ready=$(kubectl get daemonset healert-agent -n "$K8S_NS" \
        -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "?")
      echo -e "${GREEN}● deployed${RESET}  ready=$_ready/$_desired  ns=$K8S_NS"
    else
      echo -e "${DIM}● not deployed${RESET}"
    fi
  fi

  _blank

  # API Key
  printf "  %-12s" "API Key"
  if [[ -n "${HEALERT_API_KEY:-}" ]]; then
    echo -e "${GREEN}● set${RESET}  ${#HEALERT_API_KEY} chars"
  else
    echo -e "${AMBER}● not set${RESET}"
    _dim "Run: ./$SCRIPT_NAME setup"
  fi

  _blank

  # Agent config
  printf "  %-12s" "Config"
  if [[ -f "$AGENT_CONFIG" ]]; then
    echo -e "${GREEN}● $AGENT_CONFIG${RESET}"
    local _al _rp _ns
    _al=$(grep "^AUDIT_LOG_PATH=" "$AGENT_CONFIG" 2>/dev/null | cut -d= -f2-)
    _rp=$(grep "^RULES_PATH="     "$AGENT_CONFIG" 2>/dev/null | cut -d= -f2-)
    _ns=$(grep "^ENTITY_NAMESPACE=" "$AGENT_CONFIG" 2>/dev/null | cut -d= -f2-)
    _dim "audit=${_al:-not set}"
    _dim "rules=${_rp:-not set}"
    _dim "namespace=${_ns:-not set}"
  else
    echo -e "${AMBER}● not found${RESET}"
    _dim "Run: ./$SCRIPT_NAME configure"
  fi

  _blank

  # Logs
  printf "  %-12s" "Logs"
  echo -e "${DIM}backend=$BACKEND_LOG${RESET}"
  _dim "agent=$AGENT_LOG"

  _blank
}

# cmd_logs tails live log output from all running processes.
cmd_logs() {
  local _files=()
  [[ -f "$BACKEND_LOG" ]] && _files+=("$BACKEND_LOG")
  [[ -f "$AGENT_LOG" ]]   && _files+=("$AGENT_LOG")

  [[ ${#_files[@]} -gt 0 ]] \
    || _die "No log files found. Start the platform first: ./$SCRIPT_NAME start"

  _blank
  _header "Live Logs  (Ctrl+C to stop)"
  _sep
  _blank

  tail -f "${_files[@]}"
}

# cmd_test sends a test event through the full pipeline and verifies it.
# Tests: backend reachable, auth works, event stored, score calculated.
cmd_test() {
  _key_load
  _banner
  _header "Full Pipeline Test"
  _sep
  _blank

  # Backend must be running
  _health_check "$BACKEND_URL/health" \
    || _die "Backend is not running.\n  Start it first: ./$SCRIPT_NAME start"
  _ok "Backend reachable"

  # Send a test friction event
  local _timestamp _http_code
  local _tmpfile
  _tmpfile=""
  _timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  _tmpfile=$(mktemp /tmp/healert_test.XXXXXXXXXX.json)
  # Use || true so trap never fails if file already removed
  # shellcheck disable=SC2064
  trap "rm -f '$_tmpfile' 2>/dev/null || true" RETURN

  _info "Sending test kubectl-exec event..."

  _http_code=$(curl \
    --silent \
    --max-time 10 \
    --output "$_tmpfile" \
    --write-out "%{http_code}" \
    --request POST "$BACKEND_URL/events" \
    ${HEALERT_API_KEY:+--header "Authorization: Bearer $HEALERT_API_KEY"} \
    --header "Content-Type: application/json" \
    --data "{
      \"entity_ref\":  \"component:default/payments-api\",
      \"type\":        \"kubectl-exec\",
      \"severity\":    \"high\",
      \"actor\":       \"test@healert.io\",
      \"workflow\":    \"deploy\",
      \"description\": \"Healert pipeline test $(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"timestamp\":   \"$_timestamp\"
    }" 2>/dev/null)

  # Interpret response — each case is a single responsibility
  case "$_http_code" in
    200|201)
      _ok "Event accepted — HTTP $_http_code"
      _dim "$(cat "$_tmpfile" 2>/dev/null)"
      ;;
    401)
      _die "HTTP 401 Unauthorized\n  API key mismatch between agent and backend\n  Fix: ./$SCRIPT_NAME setup --rotate && ./$SCRIPT_NAME restart"
      ;;
    422)
      _err "HTTP 422 Validation error"
      cat "$_tmpfile" >&2 2>/dev/null || true
      exit 1
      ;;
    429)
      _warn "HTTP 429 Rate limit exceeded — try again in 1 minute"
      ;;
    *)
      _err "HTTP $_http_code — unexpected response"
      cat "$_tmpfile" >&2 2>/dev/null || true
      exit 1
      ;;
  esac

  # Verify the event was stored
  _blank
  _info "Verifying event stored in backend..."
  sleep 1

  local _bypass_count
  _bypass_count=$(curl \
    --fail --silent --max-time 5 \
    "$BACKEND_URL/friction/component:default/payments-api" 2>/dev/null \
    | python3 -c \
        "import sys,json; d=json.load(sys.stdin); \
         print(d.get('frictionScore',{}).get('bypassCount',0))" \
        2>/dev/null \
    || echo "0")

  if [[ "$_bypass_count" -gt 0 ]]; then
    _ok "Event stored — bypass count: $_bypass_count"
  else
    _warn "Could not confirm storage — check: $BACKEND_LOG"
  fi

  _blank
  _sep
  _blank
  _header "Verify manually:"
  _blank
  echo -e "    curl $BACKEND_URL/health"
  echo -e "    curl $BACKEND_URL/events | python3 -m json.tool"
  echo -e "    curl $BACKEND_URL/friction/component:default/payments-api | python3 -m json.tool"
  _blank
  _header "Backstage:"
  _blank
  echo -e "    http://localhost:3000 → Catalog → payments-api → Healert tab"
  _blank
}

# cmd_version prints the script version, copyright, and license.
cmd_version() {
  _banner
  echo -e "  ${BOLD}healert.sh${RESET}  v${SCRIPT_VERSION}"
  _blank
  echo -e "  ${DIM}Copyright 2026 Healert OÜ${RESET}"
  echo -e "  ${DIM}Licensed under the Apache License, Version 2.0${RESET}"
  echo -e "  ${DIM}https://www.apache.org/licenses/LICENSE-2.0${RESET}"
  _blank
  echo -e "  ${DIM}Agent repo:   github.com/healert/agent${RESET}"
  echo -e "  ${DIM}Backend repo: github.com/healert/backend${RESET}"
  echo -e "  ${DIM}Plugin:       @backstage-community/plugin-healert${RESET}"
  _blank
}

# cmd_help prints the full usage information with all commands and notes.
cmd_help() {
  _banner
  echo -e "  ${BOLD}Usage:${RESET} ./$SCRIPT_NAME <command> [options]"
  _blank

  # ── Setup and configuration ───────────────────────────────────────────────
  echo -e "  ${BOLD}${TEAL}Setup & Configuration${RESET}"
  _blank
  printf "    %-36s %s
" "init"                        "Configure backend/agent directories"
  printf "    %-36s %s
" "deps"                        "Check and install all dependencies"
  printf "    %-36s %s
" "setup"                       "Generate API key, configure both sides"
  printf "    %-36s %s
" "setup rotate"                "Rotate existing API key"
  printf "    %-36s %s\n" "configure"                   "Update agent settings interactively"
  printf "    %-36s %s\n" "configure --audit-log PATH"  "Set audit log path"
  printf "    %-36s %s\n" "configure --rules PATH"      "Set rules.yaml file path"
  printf "    %-36s %s\n" "configure --namespace NS"    "Set Backstage entity namespace"
  _blank

  # ── Scoring configuration ─────────────────────────────────────────────────
  echo -e "  ${BOLD}${TEAL}Scoring Configuration${RESET}"
  _blank
  printf "    %-36s %s\n" "configure scoring"              "Update scoring interactively"
  printf "    %-36s %s\n" "configure scoring --threshold N" "Points for score=100  (default: 50)"
  printf "    %-36s %s\n" "configure scoring --half-life N" "Decay half-life days   (default: 7)"
  printf "    %-36s %s\n" "configure scoring --retention N" "Event window days      (default: 30)"
  printf "    %-36s %s\n" "configure scoring --reset"       "Restore all defaults"
  _blank
  echo -e "  ${DIM}  strict:  --threshold 20 --half-life 3${RESET}"
  echo -e "  ${DIM}  default: --threshold 50 --half-life 7${RESET}"
  echo -e "  ${DIM}  lenient: --threshold 100 --half-life 14${RESET}"
  _blank

  # ── Start commands ────────────────────────────────────────────────────────
  echo -e "  ${BOLD}${TEAL}Start${RESET}"
  _blank
  printf "    %-36s %s
" "start"                       "Start backend + agent (local mode)"
  printf "    %-36s %s
" "start backend"               "Start backend only"
  printf "    %-36s %s
" "start agent"                 "Start agent only"
  printf "    %-36s %s
" "start kubernetes"            "Deploy agent as Kubernetes DaemonSet"
  _blank

  # ── Stop commands ─────────────────────────────────────────────────────────
  echo -e "  ${BOLD}${TEAL}Stop${RESET}"
  _blank
  printf "    %-36s %s
" "stop"                        "Stop backend + agent at the same time"
  printf "    %-36s %s
" "stop backend"                "Stop backend only, keep agent running"
  printf "    %-36s %s
" "stop agent"                  "Stop agent only, keep backend running"
  printf "    %-36s %s
" "stop kubernetes"             "Remove DaemonSet and healert-system namespace"
  _blank

  # ── Kubernetes update ─────────────────────────────────────────────────────
  echo -e "  ${BOLD}${TEAL}Kubernetes${RESET}"
  _blank
  printf "    %-36s %s
" "start kubernetes"            "Deploy agent as Kubernetes DaemonSet"
  printf "    %-36s %s
" "stop kubernetes"             "Remove DaemonSet and healert-system namespace"
  printf "    %-36s %s
" "update kubernetes"           "Apply latest daemonset.yaml with rolling restart"
  _blank
  echo -e "  ${DIM}  update kubernetes applies after:${RESET}"
  echo -e "  ${DIM}    - Changing image tag in daemonset.yaml${RESET}"
  echo -e "  ${DIM}    - Updating rules.yaml (if using ConfigMap mount)${RESET}"
  echo -e "  ${DIM}    - Rotating API key via setup rotate${RESET}"
  _blank

  # ── Runtime commands ──────────────────────────────────────────────────────
  echo -e "  ${BOLD}${TEAL}Runtime${RESET}"
  _blank
  printf "    %-36s %s
" "restart"                     "Stop then start backend + agent (one command)"
  printf "    %-36s %s
" "validate"                    "Validate rules.yaml before applying"
  printf "    %-36s %s
" "reset"                       "Delete database and create fresh empty one"
  printf "    %-36s %s
" "reset --confirm"             "Reset without confirmation prompt (for scripts)"
  printf "    %-36s %s
" "status"                      "Show health and running state"
  printf "    %-36s %s
" "logs"                        "Tail live logs from all processes"
  printf "    %-36s %s
" "test"                        "Send test event, verify full pipeline"
  printf "    %-36s %s
" "version"                     "Show script version, copyright, license"
  printf "    %-36s %s
" "help"                        "Show this help"
  _blank

  # ── First time setup ─────────────────────────────────────────────────────
  _sep
  _blank
  echo -e "  ${BOLD}First time setup:${RESET}"
  _blank
  printf "    %-36s %s
" "./$SCRIPT_NAME init"        "Configure directories"
  printf "    %-36s %s
" "./$SCRIPT_NAME deps"        "Check and install dependencies"
  printf "    %-36s %s
" "./$SCRIPT_NAME setup"       "Generate API key"
  printf "    %-36s %s
" "./$SCRIPT_NAME configure"   "Set audit log path and namespace"
  printf "    %-36s %s
" "./$SCRIPT_NAME validate"    "Validate rules.yaml"
  printf "    %-36s %s
" "./$SCRIPT_NAME start"       "Start backend + agent"
  printf "    %-36s %s
" "./$SCRIPT_NAME test"        "Verify pipeline works"
  _blank

  # ── Kubernetes audit log paths ────────────────────────────────────────────
  _sep
  _blank
  echo -e "  ${BOLD}Kubernetes audit log paths:${RESET}"
  _blank
  printf "    %-36s %s
" "k3s:"                       "/var/log/k3s-audit.log"
  printf "    %-36s %s
" "kubeadm:"                   "/var/log/kubernetes/audit/audit.log"
  printf "    %-36s %s
" "Vanilla Kubernetes:"        "/var/log/audit/audit.log"
  printf "    %-36s %s
" "k3s configure example:"     "./$SCRIPT_NAME configure --audit-log /var/log/k3s-audit.log"
  _blank

  # ── Notes ─────────────────────────────────────────────────────────────────
  _sep
  _blank
  echo -e "  ${BOLD}Notes:${RESET}"
  _blank
  echo -e "  ${DIM}• API key stored in .env with chmod 600 — never committed to git${RESET}"
  echo -e "  ${DIM}• Backend binds to 127.0.0.1 by default — not exposed to network${RESET}"
  echo -e "  ${DIM}• Kubernetes mode uses K8s Secret — not plain env vars${RESET}"
  echo -e "  ${DIM}• Production: add healert user to healert group for audit log access${RESET}"
  echo -e "  ${DIM}  sudo groupadd healert && sudo usermod -aG healert \$USER${RESET}"
  echo -e "  ${DIM}  sudo chown root:healert /var/log/k3s-audit.log${RESET}"
  echo -e "  ${DIM}  sudo chmod 640 /var/log/k3s-audit.log${RESET}"
  _blank
  echo -e "  ${DIM}Copyright 2026 Healert OÜ — Apache-2.0${RESET}"
  _blank
}

# =============================================================================
# DISPATCHER
# Routes all commands to their cmd_* functions.
# Handles compound commands: "setup rotate", "stop backend", "start agent".
# To add a new command: create a cmd_newcommand() function above.
# The dispatcher never needs to change for simple commands.
# =============================================================================

main() {
  local _command="${1:-help}"
  shift || true

  # Resolve directories from environment or defaults
  # Set HEALERT_BACKEND_DIR and HEALERT_AGENT_DIR to override
  # Example: export HEALERT_BACKEND_DIR=/home/user/healert/backend
  export BACKEND_DIR="${HEALERT_BACKEND_DIR:-$HOME/healert-backend}"
  export AGENT_DIR="${HEALERT_AGENT_DIR:-$SCRIPT_DIR}"

  # Commands that do not require directories to exist yet
  local _no_dir_needed="init help version deps validate"
  if [[ " $_no_dir_needed " != *" $_command "* ]]; then
    if [[ ! -d "$BACKEND_DIR" ]]; then
      _die "Backend directory not found: $BACKEND_DIR
  Set it: export HEALERT_BACKEND_DIR=/path/to/backend
  Example: export HEALERT_BACKEND_DIR=$HOME/healert/backend
  Then run: ./$SCRIPT_NAME init"
    fi
  fi

  # ── Compound command routing ───────────────────────────────────────────────
  # Handles multi-word commands where the subcommand modifies behavior.
  # Both "--backend" and "backend" formats are accepted.
  case "$_command" in

    # "setup rotate" — rotate the existing API key
    setup)
      local _sub="${1:-}"
      if [[ "$_sub" == "rotate" || "$_sub" == "--rotate" ]]; then
        cmd_setup "--rotate"
      else
        cmd_setup "${1:-}"
      fi
      return
      ;;

    # "start [backend|agent|kubernetes]" — start specific or all components
    start)
      local _sub="${1:-both}"
      _sub="${_sub#--}"   # strip -- prefix: --backend → backend
      cmd_start "$_sub"
      return
      ;;

    # "stop [backend|agent|kubernetes]" — stop specific or all components
    stop)
      local _sub="${1:-both}"
      _sub="${_sub#--}"   # strip -- prefix: --agent → agent
      if [[ "$_sub" == "kubernetes" ]]; then
        cmd_stop_kubernetes
      else
        cmd_stop "$_sub"
      fi
      return
      ;;

    # "update kubernetes" — apply latest daemonset.yaml with rolling restart
    update)
      local _sub="${1:-}"
      _sub="${_sub#--}"
      if [[ "$_sub" == "kubernetes" ]]; then
        cmd_update_kubernetes
      else
        _die "Unknown update target: $_sub — did you mean: update kubernetes"
      fi
      return
      ;;

    # "restart" — stop + start backend + agent
    # For DaemonSet rolling restart use: ./healert.sh update kubernetes
    restart)
      cmd_restart
      return
      ;;

    # "reset [--confirm]" — delete and recreate database
    reset)
      cmd_reset "${1:-}"
      return
      ;;

    # "configure scoring [flags]" — update backend scoring parameters
    # "configure [flags]"         — update agent runtime settings
    configure)
      local _sub="${1:-}"
      if [[ "$_sub" == "scoring" ]]; then
        # Remove "scoring" from args then pass remaining flags
        # Do not use shift here — it does not work reliably in case blocks
        # across all bash versions. Use explicit slice instead.
        local _scoring_args=()
        local _i=0
        for _a in "$@"; do
          [[ $_i -eq 0 ]] && ((_i++)) && continue  # skip first arg ("scoring")
          _scoring_args+=("$_a")
        done
        cmd_configure_scoring "${_scoring_args[@]+"${_scoring_args[@]}"}"
      else
        cmd_configure "$@"
      fi
      return
      ;;

  esac

  # ── Standard command routing ───────────────────────────────────────────────
  # Maps command name to cmd_* function.
  # Hyphens converted to underscores: "my-command" → cmd_my_command()
  local _fn="cmd_${_command//-/_}"

  if declare -f "$_fn" > /dev/null 2>&1; then
    "$_fn" "$@"
  else
    _err "Unknown command: '$_command'"
    _blank
    echo -e "  Run ${BOLD}./$SCRIPT_NAME help${RESET} to see all available commands."
    _blank
    exit 1
  fi
}

main "$@"
