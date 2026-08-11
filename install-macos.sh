#!/bin/bash
# MinBot Selective Proxy macOS installer and launcher

set -euo pipefail

readonly SCRIPT_REPOSITORY="${MINBOT_PROXY_GIT_URL:-https://github.com/MinBotAI/MinBot-Selective-Proxy.git}"
readonly KEYCHAIN_SERVICE="ai.minbot.selective-proxy"
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/minbot-selective-proxy"
readonly USERNAME_FILE="${CONFIG_DIR}/username"
readonly INSTALL_NAME="minbot-proxy"
RUNTIME_CONFIG=""

usage() {
  cat <<'EOF'
Usage:
  minbot-proxy install     Install or update the CLI, sing-box, and credentials
  minbot-proxy configure   Change the proxy username or Keychain password
  minbot-proxy check       Validate the generated sing-box configuration
  minbot-proxy run         Run the all-app TUN proxy in the foreground
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
}

emit_sing_box_config() {
  cat <<'JSON'
{
  "log": {
    "level": "info",
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
  "outbounds": [
    {
      "type": "http",
      "tag": "minbot-egress",
      "server": "43.156.119.18",
      "server_port": 30093,
      "username": "REPLACE_WITH_USERNAME",
      "password": "REPLACE_WITH_PASSWORD"
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "action": "sniff",
        "timeout": "1s"
      },
      {
        "network": "udp",
        "action": "route",
        "outbound": "direct"
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
        "url": "http://43.156.119.18:30093/domains.sing-box.json",
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
  require_homebrew
  if ! command -v git >/dev/null 2>&1; then
    brew install git
  fi
  local install_dir install_path download_dir checkout_dir source_path
  install_dir="$(brew --prefix)/bin"
  install_path="${install_dir}/${INSTALL_NAME}"
  download_dir="$(mktemp -d)"
  checkout_dir="${download_dir}/repository"
  git clone --quiet --depth 1 "${SCRIPT_REPOSITORY}" "${checkout_dir}"
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

install_all() {
  require_macos
  install_sing_box
  install_cli
  configure_credentials
  check_config
  echo
  echo "Setup complete. Start the proxy with: ${INSTALL_NAME} run"
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
  update)
    require_macos
    install_cli
    ;;
  _print-template)
    emit_sing_box_config
    ;;
  *)
    usage
    exit 1
    ;;
esac
