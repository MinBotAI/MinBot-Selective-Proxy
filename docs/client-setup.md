# 客户端配置

当前公共入口为 `43.156.119.18:30093`。端口由托管平台映射，部署网络配置改变后可能
变化；连接失效时先核对服务的 Public TCP 地址。

| 目标 | 推荐客户端 | 覆盖范围 |
| --- | --- | --- |
| macOS，包含 Codex、终端和桌面 App | sing-box CLI TUN | 整台 Mac 的 TCP 流量 |
| Chrome | 本仓库扩展 | 当前 Chrome Profile |
| iPhone / iPad | Karing | App、Wi-Fi 和蜂窝网络 |
| 不安装客户端 | 系统 PAC | 仅遵循系统代理的 App |

## macOS 全 App

```bash
curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/MinBotAI/MinBot-Selective-Proxy/v1.0.0/install-macos.sh \
  | bash
```

脚本会安装 sing-box 和 `minbot-proxy`，然后在终端提示用户名，并通过 macOS
Keychain 提示录入密码。

```bash
minbot-proxy run        # 前台运行；Ctrl-C 停止
minbot-proxy check      # 检查配置
minbot-proxy configure  # 更换账号
minbot-proxy update     # 从本仓库 main 更新 CLI
```

`run` 需要管理员权限创建 TUN。其他 TCP 与全部 UDP 保持直连，远程 allowlist 每
5 分钟刷新。

## Chrome

安装步骤见 [`clients/chrome/README.md`](../clients/chrome/README.md)。Chrome
扩展会自动响应指定代理主机的认证挑战，适合不希望反复输入账号密码的场景。

## iPhone / iPad

安装 Karing 后，复制并填写
[`clients/karing/karing.template.yaml`](../clients/karing/karing.template.yaml)。详细步骤见
[`clients/karing/README.md`](../clients/karing/README.md)。

iOS 上普通命令行程序不能常驻接管设备网络，因此需要具备 Apple Network Extension
能力的客户端；系统 PAC 只作用于当前 Wi-Fi，不能完整覆盖蜂窝网络和所有 App。

## 系统 PAC 备选

PAC 地址：`http://43.156.119.18:30093/proxy.pac`

macOS：

```bash
networksetup -setautoproxyurl "Wi-Fi" \
  "http://43.156.119.18:30093/proxy.pac"
networksetup -getautoproxyurl "Wi-Fi"
```

关闭：

```bash
networksetup -setautoproxystate "Wi-Fi" off
```

iOS：`设置 → 无线局域网 → 当前网络右侧 ⓘ → 配置代理 → 自动`，填入 PAC 地址。

PAC 不能安全携带密码，部分 App 也会忽略系统代理；全设备使用优先选择 sing-box 或
Karing。全局客户端与 Chrome 扩展不要同时启用。

## 上游项目

- [sing-box Homebrew 安装](https://sing-box.sagernet.org/installation/package-manager/)
- [sing-box TUN 配置](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [sing-box HTTP 出站](https://sing-box.sagernet.org/configuration/outbound/http/)
- [Karing](https://github.com/KaringX/karing)
