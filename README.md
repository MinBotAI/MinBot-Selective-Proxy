# MinBot Selective Proxy

MinBot 的独立认证代理服务。macOS 客户端按 allowlist 选择境外域名，其他流量保持
直连；Codex/ChatGPT 的 TCP 连接统一走代理。通过认证后，服务端允许任意公网目标和
TCP 端口，但始终拒绝私网、回环、链路本地和保留地址。TLS 链路固定服务端公钥。

本仓库包含：

- Python 代理服务与 Docker 镜像
- Chrome 扩展及图形化 allowlist 管理
- macOS 全 App 的 sing-box 一键安装脚本
- iPhone / iPad 的 Karing 配置模板
- 测试、部署、安全与运维文档

代理代码不依赖 SnapCrabBE，也不会访问 SnapCrab 的数据库、Redis 或业务 API。

## 快速使用

### macOS 全 App

以下命令通过 HTTPS 下载固定版本的安装脚本，安装开源 sing-box，并将密码保存到
macOS Keychain：

```bash
curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/MinBotAI/MinBot-Selective-Proxy/v1.3.6/install-macos.sh \
  | bash
```

安装完成后，建议启用 macOS 原生 `launchd` 后台服务：

```bash
minbot-proxy enable
```

服务会立即启动，并在开机后自动运行。TUN 需要系统权限，因此启用时会请求一次
管理员密码；生成的私密配置仅保存为 root 可读（权限 `600`），不会写入仓库。

```bash
minbot-proxy status    # 查看运行状态
minbot-proxy logs      # 最近 100 行重要日志
minbot-proxy disable   # 停止并禁用自动启动
minbot-proxy run       # 需要调试时在前台运行
```

客户端日志默认使用 `warn` 级别，仅保留告警和错误，避免输出每条连接记录。更新脚本或
修改账号后，再执行一次 `minbot-proxy enable`，即可刷新后台配置并重启服务。

### Chrome

在 `chrome://extensions` 开启开发者模式，加载
[`clients/chrome`](clients/chrome) 目录。扩展可配置账号、启停代理，并查看或修改
当前 allowlist。

### iPhone / iPad

使用开源 Karing 导入 [`clients/karing/karing.template.yaml`](clients/karing/karing.template.yaml)
的个人副本。不要把已填写密码的配置上传或提交到仓库。

完整步骤见 [客户端配置](docs/client-setup.md)。

## 本地开发

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest -q
```

本地运行前，至少设置 `PROXY_USERNAME` 和 `PROXY_PASSWORD`：

```bash
set -a
. ./.env.local
set +a
python -m minbot_selective_proxy.server
```

不要把 `.env.local`、真实账号或密码提交到 Git。

## 文档

- [架构与安全边界](docs/architecture-security.md)
- [客户端配置](docs/client-setup.md)
- [Allowlist 管理](docs/allowlist-operations.md)
- [Zeabur 部署](docs/deployment-zeabur.md)
- [版本发布与安装分发](docs/release-distribution.md)
- [故障排查](docs/troubleshooting.md)

## License

MIT
