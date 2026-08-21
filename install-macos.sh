#!/bin/bash
# MinBot Selective Proxy macOS installer and launcher

set -euo pipefail

readonly SCRIPT_REPOSITORY="${MINBOT_PROXY_GIT_URL:-https://github.com/MinBotAI/MinBot-Selective-Proxy.git}"
readonly KEYCHAIN_SERVICE="ai.minbot.selective-proxy"
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/minbot-selective-proxy"
readonly USERNAME_FILE="${CONFIG_DIR}/username"
readonly INSTALL_NAME="minbot-proxy"
readonly LAUNCHD_LABEL="ai.minbot.selective-proxy"
readonly DAEMON_DIR="/Library/Application Support/MinBot Selective Proxy"
readonly DAEMON_CONFIG="${DAEMON_DIR}/config.json"
readonly DAEMON_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
readonly DAEMON_LOG="/var/log/minbot-selective-proxy.log"
RUNTIME_CONFIG=""
LAUNCHD_PLIST_TEMP=""

usage() {
  cat <<'EOF'
Usage:
  minbot-proxy install     Install or update the CLI, sing-box, and credentials
  minbot-proxy configure   Change the proxy username or Keychain password
  minbot-proxy check       Validate the generated sing-box configuration
  minbot-proxy run         Run the all-app TUN proxy in the foreground
  minbot-proxy enable      Enable and start automatic background operation
  minbot-proxy disable     Stop and disable automatic background operation
  minbot-proxy status      Show the background service status
  minbot-proxy logs        Show recent important background logs
  minbot-proxy update      Download the latest script from GitHub
EOF
}

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This installer supports macOS only." >&2
    exit 1
  fi
}

require_homebrew() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required. Install it from https://brew.sh/ and retry." >&2
    exit 1
  fi
}

cleanup_runtime_config() {
  if [[ -n "${RUNTIME_CONFIG}" && -f "${RUNTIME_CONFIG}" ]]; then
    rm -f -- "${RUNTIME_CONFIG}"
  fi
  if [[ -n "${LAUNCHD_PLIST_TEMP}" && -f "${LAUNCHD_PLIST_TEMP}" ]]; then
    rm -f -- "${LAUNCHD_PLIST_TEMP}"
  fi
}

emit_launchd_plist() {
  local sing_box_path="$1"
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${sing_box_path}</string>
    <string>run</string>
    <string>-c</string>
    <string>${DAEMON_CONFIG}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${DAEMON_LOG}</string>
  <key>StandardErrorPath</key>
  <string>${DAEMON_LOG}</string>
</dict>
</plist>
EOF
}

emit_sing_box_config() {
  cat <<'JSON'
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "local"
      },
      {
        "type": "fakeip",
        "tag": "minbot-fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      }
    ],
    "rules": [
      {
        "query_type": ["HTTPS", "SVCB"],
        "action": "predefined",
        "rcode": "NOERROR"
      },
      {
        "query_type": ["A", "AAAA"],
        "rule_set": "minbot-domains",
        "action": "route",
        "server": "minbot-fakeip"
      }
    ],
    "final": "local",
    "independent_cache": true
  },
  "outbounds": [
    {
      "type": "http",
      "tag": "minbot-egress",
      "server": "43.156.119.18",
      "server_port": 31528,
      "username": "REPLACE_WITH_USERNAME",
      "password": "REPLACE_WITH_PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "minbot-egress.local",
        "certificate_public_key_sha256": ["GVMj+hTQYmgLDC+XzCL7Sy3MTneSXdqHwUoEcQ9qrXs="]
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "local",
    "rules": [
      {
        "action": "sniff",
        "timeout": "1s"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "network": "udp",
        "port": 443,
        "action": "reject"
      },
      {
        "network": "udp",
        "rule_set": "minbot-domains",
        "action": "reject"
      },
      {
        "network": "udp",
        "action": "route",
        "outbound": "direct"
      },
      {
        "network": "tcp",
        "domain_suffix": ["feishu.cn", "feishucdn.com"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "network": "tcp",
        "port": 443,
        "process_path_regex": ["/(ChatGPT|Codex)\\.app/Contents/"],
        "action": "route",
        "outbound": "minbot-egress"
      },
      {
        "rule_set": "minbot-domains",
        "action": "route",
        "outbound": "minbot-egress"
      }
    ],
    "final": "direct",
    "rule_set": [
      {
        "type": "remote",
        "tag": "minbot-domains",
        "format": "source",
        "url": "http://43.156.119.18:31456/domains.sing-box.json",
        "update_interval": "5m"
      }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  }
}
JSON
}

install_sing_box() {
  require_homebrew
  if command -v sing-box >/dev/null 2>&1; then
    echo "sing-box is already installed: $(sing-box version | head -1)"
    return
  fi
  brew install sing-box
}

install_cli() {
  local mode="${1:-install}"
  require_homebrew
  if ! command -v git >/dev/null 2>&1; then
    brew install git
  fi
  local install_dir install_path current_source download_dir checkout_dir source_path
  install_dir="$(brew --prefix)/bin"
  install_path="${install_dir}/${INSTALL_NAME}"
  current_source="${BASH_SOURCE[0]}"

  if [[ "${mode}" == "install" && -f "${current_source}" ]] &&
    grep -q '^# MinBot Selective Proxy macOS installer and launcher$' "${current_source}"; then
    mkdir -p "${install_dir}"
    if [[ -e "${install_path}" && "${current_source}" -ef "${install_path}" ]]; then
      echo "MinBot CLI is already installed: ${install_path}"
    else
      install -m 0755 "${current_source}" "${install_path}"
      echo "Installed ${install_path} from the current script"
    fi
    return
  fi

  echo "Downloading the latest MinBot CLI from GitHub..."
  download_dir="$(mktemp -d)"
  checkout_dir="${download_dir}/repository"
  if ! GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never git \
    -c credential.interactive=never \
    clone --progress --depth 1 "${SCRIPT_REPOSITORY}" "${checkout_dir}"; then
    find "${download_dir}" -type f -delete
    find "${download_dir}" -type l -delete
    find "${download_dir}" -depth -type d -exec rmdir {} +
    echo "Unable to download the private repository without GitHub access." >&2
    echo "Authenticate Git first, or run a local copy of install-macos.sh." >&2
    exit 1
  fi
  source_path="${checkout_dir}/install-macos.sh"
  if ! grep -q '^# MinBot Selective Proxy macOS installer and launcher$' "${source_path}"; then
    echo "GitHub repository does not contain the expected MinBot installer." >&2
    find "${download_dir}" -type f -delete
    find "${download_dir}" -type l -delete
    find "${download_dir}" -depth -type d -exec rmdir {} +
    exit 1
  fi
  mkdir -p "${install_dir}"
  install -m 0755 "${source_path}" "${install_path}"
  find "${download_dir}" -type f -delete
  find "${download_dir}" -type l -delete
  find "${download_dir}" -depth -type d -exec rmdir {} +
  echo "Installed ${install_path}"
}

configure_credentials() {
  if [[ ! -r /dev/tty ]]; then
    echo "An interactive terminal is required to enter proxy credentials." >&2
    exit 1
  fi
  mkdir -p "${CONFIG_DIR}"
  chmod 700 "${CONFIG_DIR}"

  local default_username username
  default_username=""
  if [[ -f "${USERNAME_FILE}" ]]; then
    default_username="$(<"${USERNAME_FILE}")"
  fi
  if [[ -n "${default_username}" ]]; then
    read -r -p "Proxy username [${default_username}]: " username </dev/tty
    username="${username:-${default_username}}"
  else
    read -r -p "Proxy username: " username </dev/tty
  fi
  if [[ -z "${username}" || "${username}" == *$'\n'* ]]; then
    echo "A valid username is required." >&2
    exit 1
  fi
  printf '%s\n' "${username}" > "${USERNAME_FILE}"
  chmod 600 "${USERNAME_FILE}"

  echo "Enter the proxy password in the secure macOS Keychain prompt:"
  security add-generic-password \
    -U \
    -a "${username}" \
    -s "${KEYCHAIN_SERVICE}" \
    -l "MinBot Selective Proxy" \
    -w </dev/tty
}

render_private_config() {
  require_macos
  if ! command -v sing-box >/dev/null 2>&1; then
    echo "sing-box is not installed. Run: ${INSTALL_NAME} install" >&2
    exit 1
  fi
  if [[ ! -f "${USERNAME_FILE}" ]]; then
    echo "Credentials are not configured. Run: ${INSTALL_NAME} configure" >&2
    exit 1
  fi

  local username password
  username="$(<"${USERNAME_FILE}")"
  password="$(security find-generic-password \
    -a "${username}" \
    -s "${KEYCHAIN_SERVICE}" \
    -w)"
  RUNTIME_CONFIG="$(mktemp "${TMPDIR:-/tmp}/minbot-sing-box.XXXXXX")"
  chmod 600 "${RUNTIME_CONFIG}"
  emit_sing_box_config > "${RUNTIME_CONFIG}"
  /usr/bin/plutil -replace outbounds.0.username -string "${username}" "${RUNTIME_CONFIG}"
  /usr/bin/plutil -replace outbounds.0.password -string "${password}" "${RUNTIME_CONFIG}"
  unset password
}

check_config() {
  render_private_config
  trap cleanup_runtime_config EXIT INT TERM
  sing-box check -c "${RUNTIME_CONFIG}"
  echo "Configuration is valid."
}

run_proxy() {
  render_private_config
  trap cleanup_runtime_config EXIT INT TERM
  sudo sing-box check -c "${RUNTIME_CONFIG}"
  echo "MinBot selective proxy is running. Press Ctrl-C to stop."
  sudo sing-box run -c "${RUNTIME_CONFIG}"
}

enable_daemon() {
  require_macos
  render_private_config
  trap cleanup_runtime_config EXIT INT TERM

  local sing_box_path
  sing_box_path="$(command -v sing-box)"
  sing-box check -c "${RUNTIME_CONFIG}"
  LAUNCHD_PLIST_TEMP="$(mktemp "${TMPDIR:-/tmp}/minbot-launchd.XXXXXX")"
  emit_launchd_plist "${sing_box_path}" > "${LAUNCHD_PLIST_TEMP}"
  /usr/bin/plutil -lint "${LAUNCHD_PLIST_TEMP}" >/dev/null
  sudo install -d -m 0700 "${DAEMON_DIR}"
  sudo install -m 0600 -o root -g wheel "${RUNTIME_CONFIG}" "${DAEMON_CONFIG}"
  sudo install -m 0644 -o root -g wheel "${LAUNCHD_PLIST_TEMP}" "${DAEMON_PLIST}"

  if sudo launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
    sudo launchctl bootout "system/${LAUNCHD_LABEL}"
  fi
  sudo launchctl bootstrap system "${DAEMON_PLIST}"
  sudo launchctl enable "system/${LAUNCHD_LABEL}"
  sudo launchctl kickstart -k "system/${LAUNCHD_LABEL}"
  echo "MinBot selective proxy is enabled and running in the background."
  echo "Check it with: ${INSTALL_NAME} status"
}

disable_daemon() {
  require_macos
  if sudo launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
    sudo launchctl bootout "system/${LAUNCHD_LABEL}"
  fi
  sudo launchctl disable "system/${LAUNCHD_LABEL}"
  echo "MinBot selective proxy background service is disabled."
}

daemon_status() {
  require_macos
  if sudo launchctl print "system/${LAUNCHD_LABEL}"; then
    exit 0
  fi
  echo "MinBot selective proxy background service is not running." >&2
  exit 1
}

daemon_logs() {
  require_macos
  if [[ ! -f "${DAEMON_LOG}" ]]; then
    echo "No background log has been created yet."
    return
  fi
  sudo tail -n 100 "${DAEMON_LOG}"
}

install_all() {
  require_macos
  echo "[1/4] Checking sing-box..."
  install_sing_box
  echo "[2/4] Installing MinBot CLI..."
  install_cli install
  echo "[3/4] Checking proxy credentials..."
  if [[ -s "${USERNAME_FILE}" ]]; then
    echo "Existing proxy username found; keeping the current Keychain credentials."
  else
    configure_credentials
  fi
  echo "[4/4] Validating the generated configuration..."
  check_config
  echo
  echo "Setup complete. Enable automatic background operation with: ${INSTALL_NAME} enable"
}

case "${1:-install}" in
  install)
    install_all
    ;;
  configure)
    require_macos
    configure_credentials
    ;;
  check)
    check_config
    ;;
  run)
    run_proxy
    ;;
  enable)
    enable_daemon
    ;;
  disable)
    disable_daemon
    ;;
  status)
    daemon_status
    ;;
  logs)
    daemon_logs
    ;;
  update)
    require_macos
    install_cli update
    ;;
  _install-cli-current)
    install_cli install
    ;;
  _print-template)
    emit_sing_box_config
    ;;
  _print-launchd-template)
    emit_launchd_plist "/opt/homebrew/bin/sing-box"
    ;;
  *)
    usage
    exit 1
    ;;
esac
