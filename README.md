# MinBot Selective Proxy

MinBot 的独立选择性代理服务。它只转发 allowlist 中的域名，其他流量保持
直连；macOS TUN 客户端使用 TLS 加密代理链路并固定服务端公钥。

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
  https://raw.githubusercontent.com/MinBotAI/MinBot-Selective-Proxy/v1.3.0/install-macos.sh \
  | bash
```

安装完成后运行：

```bash
minbot-proxy run
```

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
