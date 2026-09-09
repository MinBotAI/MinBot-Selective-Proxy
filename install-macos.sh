#!/bin/bash
# MinBot Selective Proxy macOS installer and launcher

set -euo pipefail

readonly SCRIPT_REPOSITORY="${MINBOT_PROXY_GIT_URL:-https://github.com/MinBotAI/MinBot-Selective-Proxy.git}"
readonly VERSION="1.4.0"
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
  minbot-proxy status      Live status monitor (q to quit; refreshes every 2s)
  minbot-proxy status --once  Print one readable status snapshot
  minbot-proxy status --raw   Print the original launchd diagnostic output
  minbot-proxy logs        Show recent important background logs
  minbot-proxy update      Download the latest script from GitHub
  minbot-proxy version     Show the installed CLI version
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
  <key>WorkingDirectory</key>
  <string>${DAEMON_DIR}</string>
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
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:19090",
      "secret": "REPLACE_WITH_RANDOM_STATUS_SECRET"
    }
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
        "type": "https",
        "tag": "alidns-doh",
        "server": "223.5.5.5",
        "server_port": 443,
        "path": "/dns-query",
        "tls": {
          "enabled": true,
          "server_name": "dns.alidns.com"
        }
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
        "action": "route",
        "server": "minbot-fakeip"
      }
    ],
    "final": "alidns-doh",
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
    "default_domain_resolver": "alidns-doh",
    "rules": [
      {
        "network": "tcp",
        "port": 443,
        "action": "sniff",
        "sniffer": ["tls"],
        "timeout": "300ms"
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
        "domain": ["register.appattest.apple.com"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "network": "tcp",
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
  /usr/bin/plutil -replace experimental.clash_api.secret -string "$(openssl rand -hex 32)" "${RUNTIME_CONFIG}"
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
  sudo install -d -m 0700 "${DAEMON_DIR}"
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
  sudo rm -f -- \
    "${DAEMON_DIR}/cache.db" \
    "${DAEMON_DIR}/cache.db-shm" \
    "${DAEMON_DIR}/cache.db-wal"
  sudo install -m 0600 -o root -g wheel /dev/null "${DAEMON_LOG}"
  sudo launchctl enable "system/${LAUNCHD_LABEL}"
  sudo launchctl bootstrap system "${DAEMON_PLIST}"
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
  local mode="${1:-}"
  if [[ "$#" -gt 1 || ( -n "${mode}" && "${mode}" != "--once" && "${mode}" != "--raw" ) ]]; then
    echo "Usage: minbot-proxy status [--once|--raw]" >&2
    return 2
  fi
  if [[ "${mode}" == "--raw" ]]; then
    sudo launchctl print "system/${LAUNCHD_LABEL}"
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Status monitor requires Python 3. Install with: brew install python" >&2
    return 1
  fi
  sudo -v || return
  if [[ "${mode}" == "--once" || ! -t 0 || ! -t 1 || "${TERM:-dumb}" == "dumb" ]]; then
    mode="--once"
  fi
  exec python3 - "${mode}" "${DAEMON_CONFIG}" "${LAUNCHD_LABEL}" 3<&0 <<'PY_STATUS'
import datetime
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import termios
import time
import tty
import urllib.request


def command(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return None


def size(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.1f} {unit}'
        value /= 1024


def clean(value):
    # Remote host/process names must not inject terminal control sequences.
    return ''.join(c for c in str(value) if c.isprintable())


def sample(config_path, label):
    service = command('sudo', '-n', 'launchctl', 'print', 'system/' + label)
    if service is None:
        return {'status': 'UNAVAILABLE', 'hint': '无法读取后台服务状态：minbot-proxy status --raw'}
    if service.returncode:
        missing = 'Could not find service' in service.stderr or 'service not found' in service.stderr
        return {'status': 'STOPPED' if missing else 'UNAVAILABLE',
                'hint': '启动代理：minbot-proxy enable' if missing else '无法读取后台服务状态：minbot-proxy status --raw'}
    match = re.search(r'^\s*pid = (\d+)\s*$', service.stdout, re.M)
    if not match:
        return {'status': 'WAITING', 'hint': '进程尚未运行，检查：minbot-proxy logs'}
    pid = match.group(1)
    process = command('ps', '-p', pid, '-o', 'etime=')
    if process is None or process.returncode or not process.stdout.strip():
        return {'status': 'WAITING', 'hint': '进程已退出，检查：minbot-proxy logs'}
    result = {'status': 'RUNNING', 'pid': pid, 'uptime': process.stdout.strip()}
    config = command('sudo', '-n', 'cat', config_path)
    try:
        api = json.loads(config.stdout)['experimental']['clash_api']
        # Never transmit the API credential to a remote or redirected endpoint.
        address = api['external_controller']
        if not re.fullmatch(r'127\.0\.0\.1:\d+', address) or not api.get('secret'):
            raise ValueError('invalid controller')
    except (AttributeError, KeyError, TypeError, ValueError):
        result['hint'] = '流量统计未启用：运行 minbot-proxy enable 更新配置并重启本机代理。'
        return result
    try:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request('http://' + address + '/connections',
                                         headers={'Authorization': 'Bearer ' + api['secret']})
        with opener.open(request, timeout=1.5) as response:
            data = json.load(response)
        if not isinstance(data.get('connections'), (list, type(None))):
            raise ValueError('invalid connections')
        for field in ('uploadTotal', 'downloadTotal'):
            if not isinstance(data.get(field), (int, float)) or data[field] < 0:
                raise ValueError('invalid counter')
        result.update(data=data, time=time.monotonic())
    except Exception:
        result['hint'] = '统计接口不可用，流量未知。检查：minbot-proxy logs（不会显示为 0）'
    return result


def render(current, previous=None):
    lines = ['MinBot Proxy | ' + datetime.datetime.now().strftime('%H:%M:%S'), '─' * 72]
    labels = {'RUNNING': '运行中', 'STOPPED': '未运行', 'WAITING': '等待启动', 'UNAVAILABLE': '状态不可读'}
    state = current['status']
    lines.append(f"代理服务  {labels[state]}")
    if 'pid' in current:
        lines.append(f"运行时长  {current['uptime']}   PID {current['pid']}")
    if 'data' not in current:
        lines.extend(['流量 / 连接  未知', current['hint']])
        return lines
    data = current['data']
    connections = data.get('connections') or []
    proxy = [c for c in connections if 'minbot-egress' in c.get('chains', [])]
    direct = [c for c in connections if 'direct' in c.get('chains', []) and c not in proxy]
    rates = None
    old_by_id = {}
    if previous and previous.get('pid') == current['pid'] and 'data' in previous:
        elapsed = current['time'] - previous['time']
        old = previous['data']
        if elapsed > 0 and all(data[f] >= old[f] for f in ('uploadTotal', 'downloadTotal')):
            rates = [(data[f] - old[f]) / elapsed for f in ('uploadTotal', 'downloadTotal')]
            old_by_id = {c['id']: c for c in old.get('connections') or []}
    if rates is None:
        speed = '采样中，等待下一次刷新'
    else:
        speed = f'↑ {size(rates[0])}/s   ↓ {size(rates[1])}/s'
    lines.extend([
        f'当前连接  {len(connections)}   代理 {len(proxy)} / 直连 {len(direct)} / 其他 {len(connections)-len(proxy)-len(direct)}',
        '', 'TUN 总流量（包含代理与直连）',
        '实时速率  ' + speed,
        f"累计流量  ↑ {size(data['uploadTotal'])}   ↓ {size(data['downloadTotal'])}（sing-box 本次运行）",
        '', '代理连接（minbot-egress，按本次采样流量排序）',
        '目标                                  上传/s       下载/s       连接累计↓',
    ])
    rows = []
    proxy_up = proxy_down = 0
    matched = 0
    for c in proxy:
        before = old_by_id.get(c.get('id'))
        # A newly observed connection has no complete sampling interval yet.
        up = down = None
        if before is not None and rates is not None:
            up = max(0, c.get('upload', 0) - before.get('upload', 0)) / elapsed
            down = max(0, c.get('download', 0) - before.get('download', 0)) / elapsed
            proxy_up += up
            proxy_down += down
            matched += 1
        metadata = c.get('metadata') or {}
        host = metadata.get('host') or metadata.get('destinationIP') or '?'
        target = clean(f"{host}:{metadata.get('destinationPort', '?')}")[:35]
        rows.append((0 if up is None else up + down,
                     f"{target:<35} {('--' if up is None else size(up)):>11} {('--' if down is None else size(down)):>11} {size(c.get('download', 0)):>13}"))
    if not proxy:
        activity = '空闲（当前没有代理连接）'
    elif not matched:
        activity = '采样中（已有代理连接）'
    else:
        activity = ('正在转发' if proxy_up + proxy_down > 0 else '本次未观测到传输')
        activity += f'   ↑ {size(proxy_up)}/s   ↓ {size(proxy_down)}/s'
    lines.insert(4, '代理转发  ' + activity)
    lines.insert(5, '          速率仅含持续连接，完整总量见下方 TUN 统计。')
    limit = max(1, shutil.get_terminal_size((100, 28)).lines - 20)
    lines.extend(row for _, row in sorted(rows, key=lambda row: row[0], reverse=True)[:limit])
    if not rows:
        lines.append('当前没有代理连接（空闲不代表故障）')
    elif len(rows) > limit:
        lines.append(f'另有 {len(rows) - limit} 条代理连接未显示')
    lines.extend(['', '连接速率仅统计相邻采样均存在的连接；新连接显示 --。',
                  '进程运行与有流量不代表所有目标可达；此面板不主动探测外网。'])
    return lines


def main():
    mode, config_path, label = sys.argv[1:]
    if mode == '--once':
        first = sample(config_path, label)
        if 'data' in first:
            time.sleep(1)
            current = sample(config_path, label)
        else:
            current = first
        print('\n'.join(render(current, first)))
        return 0 if current['status'] == 'RUNNING' else 1
    terminal = os.fdopen(3, 'rb', buffering=0)
    original = termios.tcgetattr(terminal)
    def stop(signum, frame):
        raise SystemExit(128 + signum)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)
    previous = None
    try:
        tty.setcbreak(terminal)
        sys.stdout.write('\033[?1049h\033[?25l')
        while True:
            current = sample(config_path, label)
            lines = render(current, previous)
            lines.append('每 2 秒刷新 | q / Ctrl-C 退出')
            columns, height = shutil.get_terminal_size((100, 28))
            # Keep each frame within the terminal, including when resized.
            import unicodedata
            def fit(line):
                width = 0
                out = ''
                for ch in line:
                    width += 2 if unicodedata.east_asian_width(ch) in 'WF' else 1
                    if width >= columns:
                        break
                    out += ch
                return out
            sys.stdout.write('\033[H\033[J' + '\n'.join(fit(line) for line in lines[:max(1, height-1)]))
            sys.stdout.flush()
            previous = current
            if select.select([terminal], [], [], 2)[0]:
                if terminal.read(1) in (b'q', b'Q', b'\x03', b''):
                    break
    finally:
        termios.tcsetattr(terminal, termios.TCSADRAIN, original)
        sys.stdout.write('\033[?25h\033[?1049l')
        sys.stdout.flush()
    return 0


if __name__ == '__main__':
    sys.exit(main())
PY_STATUS
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
  if ! command -v python3 >/dev/null 2>&1; then
    brew install python
  fi
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
    daemon_status "${@:2}"
    ;;
  logs)
    daemon_logs
    ;;
  update)
    require_macos
    install_cli update
    ;;
  version)
    echo "${INSTALL_NAME} ${VERSION}"
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
