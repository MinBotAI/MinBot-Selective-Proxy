"""Status monitor contract tests with no real launchd or administrator access."""
import os
from pathlib import Path
import select
import signal
import subprocess
import time

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'install-macos.sh'


@pytest.fixture
def cli_env(tmp_path):
    commands = {
        'uname': 'echo Darwin',
        'sudo': '''[ "$1" = "-v" ] && exit 0
[ "$1" = "-n" ] && shift
exec "$@"''',
        'launchctl': '''case "${TEST_STATUS:-running}" in
running) printf 'state = running\\npid = 123\\nlast exit code = 0\\nprivate-field = DO_NOT_DISPLAY\\n';;
stopped) echo 'Could not find service' >&2; exit 113;;
waiting) printf 'state = waiting\\nlast exit code = 1\\n';;
error) echo 'permission denied' >&2; exit 1;;
esac''',
        'ps': "echo '01:23 2.5 20480'",
    }
    for name, body in commands.items():
        path = tmp_path / name
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o755)
    return {'PATH': str(tmp_path) + ':' + os.environ['PATH'], 'HOME': str(tmp_path), 'TERM': 'xterm'}


@pytest.mark.parametrize('state,label,code', [
    ('running', '运行中', 0), ('stopped', '未运行', 1),
    ('waiting', '等待启动', 1), ('error', '状态不可读', 1),
])
def test_snapshot(cli_env, state, label, code):
    result = subprocess.run(['bash', str(SCRIPT), 'status'], env={**cli_env, 'TEST_STATUS': state}, capture_output=True, text=True)
    assert result.returncode == code
    assert label in result.stdout
    assert not any(state in result.stdout for state in ('RUNNING', 'STOPPED', 'WAITING', 'UNAVAILABLE'))
    assert '\x1b' not in result.stdout
    assert 'DO_NOT_DISPLAY' not in result.stdout
    if code == 0:
        assert '流量 / 连接  未知' in result.stdout
        assert 'minbot-proxy enable' in result.stdout


def test_options(cli_env):
    raw = subprocess.run(['bash', str(SCRIPT), 'status', '--raw'], env=cli_env, capture_output=True, text=True)
    assert raw.returncode == 0 and 'DO_NOT_DISPLAY' in raw.stdout
    once = subprocess.run(['bash', str(SCRIPT), 'status', '--once'], env=cli_env, capture_output=True, text=True)
    assert once.returncode == 0 and '运行中' in once.stdout
    invalid = subprocess.run(['bash', str(SCRIPT), 'status', '--oops'], env=cli_env, capture_output=True)
    assert invalid.returncode == 2


@pytest.mark.parametrize('quit_signal', [None, signal.SIGINT, signal.SIGTERM])
def test_monitor_refresh_and_restore(cli_env, quit_signal):
    import pty
    import termios
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(['bash', str(SCRIPT), 'status'], env=cli_env, stdin=slave, stdout=slave, stderr=slave)
    output = b''
    try:
        deadline = time.monotonic() + 8
        while output.count(b'MinBot Proxy |') < 2 and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                output += os.read(master, 65536)
        assert output.count(b'MinBot Proxy |') >= 2
        if quit_signal:
            process.send_signal(quit_signal)
        else:
            os.write(master, b'q')
        process.wait(timeout=5)
        while select.select([master], [], [], 0.1)[0]:
            output += os.read(master, 65536)
        assert b'\x1b[?1049h' in output
        assert b'\x1b[?25h\x1b[?1049l' in output
        after = termios.tcgetattr(slave)
        # macOS sets PENDIN when stty restores flags (pending input retype).
        pending = getattr(termios, 'PENDIN', 0)
        after[3] &= ~pending
        before[3] &= ~pending
        assert after == before
        assert process.returncode == (128 + quit_signal if quit_signal else 0)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


@pytest.fixture
def monitor():
    import types
    module = types.ModuleType('status_monitor')
    source = SCRIPT.read_text().split("<<'PY_STATUS'\n", 1)[1].split('\nPY_STATUS', 1)[0]
    exec(compile(source, str(SCRIPT), 'exec'), module.__dict__)
    return module


def traffic(total_up, total_down, upload=100, download=1000):
    return {'uploadTotal': total_up, 'downloadTotal': total_down, 'connections': [
        {'id': 'proxy1', 'chains': ['minbot-egress'], 'upload': upload, 'download': download,
         'metadata': {'host': 'example.com', 'destinationPort': '443'}},
        {'id': 'direct1', 'chains': ['direct'], 'upload': 50, 'download': 500,
         'metadata': {'host': 'direct.example', 'destinationPort': '443'}},
    ]}


def test_traffic_scope_rates_and_restart(monitor):
    old = {'status': 'RUNNING', 'pid': '123', 'uptime': '01:23', 'time': 10,
           'data': traffic(1024, 4096)}
    current = {**old, 'time': 12, 'data': traffic(3072, 8192, 1124, 3048)}
    rendered = '\n'.join(monitor.render(current, old))
    assert '代理 1 / 直连 1' in rendered
    assert '正在转发   ↑ 512.0 B/s   ↓ 1.0 KiB/s' in rendered
    assert '包含代理与直连' in rendered
    assert '↑ 1.0 KiB/s   ↓ 2.0 KiB/s' in rendered
    assert 'example.com:443' in rendered
    assert 'direct.example' not in rendered
    assert '512.0 B' in rendered  # Per-proxy connection upload rate.
    assert '采样中' in '\n'.join(monitor.render({**current, 'pid': '456'}, old))
    assert '采样中' in '\n'.join(monitor.render({**current, 'data': traffic(0, 0)}, old))


def test_empty_connections_and_terminal_sanitization(monitor):
    current = {'status': 'RUNNING', 'pid': '123', 'uptime': '01:23', 'time': 10,
               'data': {'uploadTotal': 0, 'downloadTotal': 0, 'connections': None}}
    assert '当前没有代理连接' in '\n'.join(monitor.render(current))
    assert '\x1b' not in monitor.clean('evil\x1b[2J\nname')


def test_authenticated_api_and_failure(monitor, monkeypatch):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    payload = traffic(1234, 5678)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path == '/connections'
            assert self.headers['Authorization'] == 'Bearer test-only-token'
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def mock_command(*args):
        if 'launchctl' in args:
            out = 'pid = 123\n'
        elif args[0] == 'ps':
            out = '01:23'
        else:
            out = json.dumps({'experimental': {'clash_api': {
                'external_controller': '127.0.0.1:' + str(server.server_port),
                'secret': 'test-only-token'}}})
        return subprocess.CompletedProcess(args, 0, out, '')
    monkeypatch.setattr(monitor, 'command', mock_command)
    try:
        result = monitor.sample('/unused/config', 'test.service')
        assert result['data'] == payload
        assert 'test-only-token' not in '\n'.join(monitor.render(result))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    result = monitor.sample('/unused/config', 'test.service')
    assert 'data' not in result
    assert '统计接口不可用' in result['hint']
