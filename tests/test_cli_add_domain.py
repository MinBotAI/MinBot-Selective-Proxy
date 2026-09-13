"""Dynamic allowlist CLI contract tests without real Keychain or network access."""

import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "install-macos.sh"


@pytest.fixture
def cli_env(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    username_file = tmp_path / ".config" / "minbot-selective-proxy" / "username"
    username_file.parent.mkdir(parents=True)
    username_file.write_text("alice\n")
    commands = {
        "uname": "echo Darwin",
        "security": "printf 'test-only-password\\n'",
        "curl": """arguments_file="$TEST_ARGUMENTS_FILE"
config_file="$TEST_CONFIG_FILE"
printf '%s\\n' "$@" > "$arguments_file"
cat > "$config_file"
printf '{"domains":["example.com","xn--bcher-kva.example"]}\\n'
""",
    }
    for name, body in commands.items():
        path = fake_bin / name
        path.write_text("#!/bin/bash\n" + body + "\n")
        path.chmod(0o755)
    return {
        "PATH": str(fake_bin) + ":" + os.environ["PATH"],
        "HOME": str(tmp_path),
        "TEST_ARGUMENTS_FILE": str(tmp_path / "curl-arguments"),
        "TEST_CONFIG_FILE": str(tmp_path / "curl-config"),
    }


def test_add_domain_reuses_saved_credentials_over_pinned_tls(cli_env):
    result = subprocess.run(
        ["bash", str(SCRIPT), "add-domain", "Example.COM."],
        env=cli_env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Allowlist updated: example.com" in result.stdout
    arguments = Path(cli_env["TEST_ARGUMENTS_FILE"]).read_text()
    curl_config = Path(cli_env["TEST_CONFIG_FILE"]).read_text()
    assert "https://minbot-egress.local:31528/api/domains" in arguments
    assert "minbot-egress.local:31528:43.156.119.18" in arguments
    assert "sha256//GVMj+hTQYmgLDC+XzCL7Sy3MTneSXdqHwUoEcQ9qrXs=" in arguments
    assert "--disable" in arguments
    assert "--noproxy\n*" in arguments
    assert '{"domain":"example.com"}' in arguments
    assert "test-only-password" not in arguments
    assert curl_config == 'user = "alice:test-only-password"\n'


def test_add_domain_converts_unicode_to_idna(cli_env):
    result = subprocess.run(
        ["bash", str(SCRIPT), "add-domain", "Bücher.example"],
        env=cli_env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Allowlist updated: xn--bcher-kva.example" in result.stdout


@pytest.mark.parametrize("domain", ["https://example.com", "example.com/path", "bad..example"])
def test_add_domain_rejects_invalid_input_without_reading_keychain(cli_env, domain):
    Path(cli_env["TEST_CONFIG_FILE"]).unlink(missing_ok=True)

    result = subprocess.run(
        ["bash", str(SCRIPT), "add-domain", domain],
        env=cli_env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "Invalid domain" in result.stderr
    assert not Path(cli_env["TEST_CONFIG_FILE"]).exists()
