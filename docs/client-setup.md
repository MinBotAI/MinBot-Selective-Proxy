# 客户端配置

当前公共入口为 `43.156.119.18:31456`（兼容明文）和
`43.156.119.18:31528`（TLS）。端口由托管平台映射，部署网络配置改变后可能变化；
连接失效时先核对服务的 Public TCP 地址。

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
  https://raw.githubusercontent.com/MinBotAI/MinBot-Selective-Proxy/v1.4.0/install-macos.sh \
  | bash
```

脚本会安装 sing-box 和 `minbot-proxy`，然后在终端提示用户名，并通过 macOS
Keychain 提示录入密码。

```bash
minbot-proxy enable     # 后台运行，并在开机后自动启动
minbot-proxy status     # 每 2 秒刷新状态面板，按 q 或 Ctrl-C 退出
minbot-proxy status --once  # 输出一次可读状态
minbot-proxy status --raw   # 原始 launchd 诊断信息
minbot-proxy logs       # 最近 100 行告警和错误
minbot-proxy disable    # 停止并禁用自动启动
minbot-proxy run        # 仅调试时前台运行；Ctrl-C 停止
minbot-proxy check      # 检查配置
minbot-proxy configure  # 更换账号
minbot-proxy update     # 从本仓库 main 更新 CLI
minbot-proxy version    # 核对实际执行的已安装版本
```

`enable` 使用系统级 `launchd`，因为 TUN 网络接口需要 root 权限。命令会请求一次
管理员密码，将生成后的配置保存到
`/Library/Application Support/MinBot Selective Proxy/config.json`，并限制为仅 root
可读。客户端禁用磁盘 cache-file，远程规则与 DNS 只在内存中缓存，不会产生持续增长的
`cache.db`；升级时会清理旧版本留下的缓存数据库。更新脚本或修改代理账号后，需要再次
执行 `minbot-proxy enable` 刷新配置。

在仓库中执行 `git pull` 只更新工作区，不会替换 Homebrew bin 中的已安装命令。仓库更新
后可执行 `bash ./install-macos.sh _install-cli-current` 安装当前脚本，或直接运行
`minbot-proxy update` 从远端更新。

`status` 优先显示代理是否运行、当前连接数（代理 / 直连 / 其他）、实时上传与下载
速率，以及 sing-box 本次运行的累计流量。顶部单独显示代理持续连接的转发速率，
有增量时显示“正在转发”，没有活跃代理连接时显示“空闲”。总速率与累计量包含 TUN 中的代理和直连流量，
不等于跨境代理流量。下方单独列出 `minbot-egress` 的代理目标、每条连接上传 / 下载速率
与该连接累计下载量，按本次采样流量排序。连接速率只统计连续两次采样都存在的连接；
新连接显示 `--`，短于采样间隔的连接可能不出现在列表中。累计量在 sing-box 重启后重置。

统计通过带随机认证密钥的 `127.0.0.1:19090` Clash API 读取，不监听局域网。
升级旧版后，需要执行一次 `minbot-proxy enable` 生成统计配置并重启本机代理（现有连接
可能短暂中断）；只更新 CLI 不会自动改动运行中的代理。端口已被其他程序占用时，
需先解决冲突。缺少统计配置或接口不可用时显示“未知”及操作提示，不显示虚假的零流量。
监控需要 Python 3，安装命令会在缺少时通过 Homebrew 安装。

“运行中”仅表示本机进程存在；有连接或流量不保证所有目标可达，面板不主动探测外网。
`--once` 会采样约 1 秒后输出速率；管道、重定向和非交互终端自动使用该模式，不输出终端
控制字符。进程未运行或服务状态不可读时返回非零退出码。统计不可用不会改变进程状态。

示例（演示数据，不是当前机器的实测值）：

```text
MinBot Proxy | 14:32:08
代理服务  运行中
运行时长  02:18:36   PID 4281
当前连接  18   代理 6 / 直连 12 / 其他 0
代理转发  正在转发   ↑ 48.0 KiB/s   ↓ 920.0 KiB/s
          速率仅含持续连接，完整总量见下方 TUN 统计。

TUN 总流量（包含代理与直连）
实时速率  ↑ 128.0 KiB/s   ↓ 2.4 MiB/s
累计流量  ↑ 86.2 MiB   ↓ 1.8 GiB（sing-box 本次运行）

代理连接（minbot-egress，按本次采样流量排序）
目标                                  上传/s       下载/s       连接累计↓
chatgpt.com:443                      12.0 KiB    640.0 KiB      28.4 MiB
```

默认日志级别为 `warn`，不会再输出每条连接的 INFO 记录。

所有 A/AAAA 查询会由 sing-box FakeIP DNS 保留原始域名；allowlist 域名通过固定服务端
公钥的 TLS HTTP 代理发送，其他域名仍由 direct 出站使用阿里公共 DNS DoH/443 解析。
这样不会改变选择性分流，但能避免浏览器或 App 把大陆解析得到的单一真实 IP 固定发送
给新加坡出口。allowlist UDP/QUIC 会被拒绝以触发 TCP 回退；其他 TCP 与非 DNS UDP
保持直连，远程 allowlist 每 5 分钟刷新。

对于现代浏览器发出的 HTTPS/SVCB DNS 查询，客户端会统一返回空的成功响应，使其
立即回退到 A/AAAA；既不会把不支持的查询类型送入 FakeIP，也不会因本地 DNS 对这类
扩展查询超时而拖慢页面。

所有 UDP/443 会快速拒绝以强制 App 和浏览器回退到 TCP，包含仍持有旧真实 IP 缓存的
进程；这避免未带域名元数据的 QUIC 流量误走直连并等待超时。

Codex 与 ChatGPT 桌面进程的所有 TCP 连接会始终交给加密代理，包括 App 在代理启动前
缓存的真实 IP 和非标准端口。服务端验证账号后允许任意公网目标，不再做域名、SNI 或
端口 allowlist 校验；私网、回环、链路本地和保留地址仍被拒绝。`feishu.cn` 和
`feishucdn.com` 以及精确的 Apple App Attest 端点会在这条进程规则之前保持大陆直连，
避免不必要的跨境绕行。

客户端只对 TCP/443 执行 TLS 域名识别，最长等待 300ms，用于在 Codex/ChatGPT 进程
规则前识别飞书直连流量。非 443 的 Codex 远程连接不再经过协议嗅探，直接进入代理。

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

PAC 地址：`http://43.156.119.18:31456/proxy.pac`

macOS：

```bash
networksetup -setautoproxyurl "Wi-Fi" \
  "http://43.156.119.18:31456/proxy.pac"
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
