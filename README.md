# MinBot Selective Proxy Client

Free and open-source macOS installer for the authenticated MinBot selective
proxy. It installs sing-box, saves the proxy password in macOS Keychain, and
creates a TUN configuration at runtime so Codex, terminal tools, and desktop
apps can use the same domain allowlist.

## Install

```bash
curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/MinBotAI/MinBot-Selective-Proxy-Client/main/install-macos.sh \
  | bash
```

The installer prompts for an assigned proxy username and then uses the secure
macOS Keychain prompt for the password. It does not send credentials to GitHub
or save the password in the repository or a permanent configuration file.

Start the all-app proxy with:

```bash
minbot-proxy run
```

Other commands:

```bash
minbot-proxy configure
minbot-proxy check
minbot-proxy update
```

The remote proxy remains authenticated and enforces its server-side domain
allowlist. This client cannot add destinations or bypass that boundary.

## Requirements

- macOS
- Homebrew
- An assigned MinBot selective-proxy account

## License

MIT
