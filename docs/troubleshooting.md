# 故障排查

## 无法连接

1. 核对 Zeabur Service 是否 `RUNNING`。
2. 核对 Public TCP 主机和端口是否改变。
3. 请求 `/healthz`、`/proxy.pac` 和规则集，区分服务故障与客户端故障。
4. 运行 `minbot-proxy check` 检查本地 sing-box 配置。
5. 确认没有同时开启 Chrome 扩展、系统 PAC 和 TUN 客户端。

## 反复提示账号密码

- Chrome：确认扩展启用，代理地址与当前 Public TCP 一致，并重新保存账号。
- macOS CLI：运行 `minbot-proxy configure` 更新 Keychain。
- 系统 PAC：认证保存因 App 而异，优先改用 Chrome 扩展或设备级客户端。

## 域名仍无法访问

1. 在 Chrome 扩展或 `GET /api/domains` 中确认根域名存在。
2. 检查页面是否依赖额外的一方 API 或 CDN 域名。
3. 只添加确认属于目标服务的域名，不添加通用 Cloudflare、Akamai 或 CloudFront
   根域名。
4. sing-box 和 Karing 最长可能等待 5 分钟刷新远程规则。

v1.3.5 起，认证成功后服务端允许任意公网域名、公网 IP 和 TCP 端口。公网目标仍返回
`403 Forbidden` 说明客户端或服务端尚未升级：停止旧进程，执行 `minbot-proxy update`
和 `minbot-proxy enable`，并确认生产代理已部署 v1.3.5。私网、回环、链路本地、保留
和其他非全局地址仍会返回 403，这是保留的 SSRF 防护。

若看到 `read: connection reset by peer`，先确认服务端 `PROXY_MAX_CONNECTIONS` 不低于
`128`。v1.0.2 会在容量耗尽时返回明确的 `503 Service Unavailable`，并并行尝试已经
通过公网校验的 IPv4/IPv6 地址，避免单个不可达地址阻塞 CONNECT。

安装器在“sing-box is already installed”后不应再静默等待。v1.0.2 会显示四阶段进度，
优先安装正在执行的本地脚本，保留已有 Keychain 凭据；从私有 GitHub 仓库更新但未认证
时会立即给出错误。

若中国网络中出现针对 Google 等域名的快速 `connection reset by peer`，确认已升级到
v1.1.0。该版本使用 TLS 加密客户端到代理的 CONNECT 请求，并拒绝 allowlist 的 QUIC
流量以触发 TCP 回退；旧版明文入口会暴露 CONNECT 目标，可能被链路中间设备重置。

若出现 `only IP queries are supported by fakeip`，或 HTTPS 查询本地 DNS 超时，升级
到 v1.1.2。该版本只把 A/AAAA 查询交给 FakeIP，并统一对 HTTPS/SVCB 查询返回空的
成功响应，避免浏览器在 DNS 阶段失败、等待超时或使用 HTTPS 记录中的真实 IP 绕过
域名代理。

若 Codex/ChatGPT 能加载但连接远程任务很慢，升级客户端到 v1.3.6 并重新启用后台
服务。该版本将两个桌面进程的所有 TCP 连接交给代理，不再局限于 443，也不依赖域名
allowlist 或 TLS SNI；大陆飞书域名和 Apple App Attest 端点仍优先直连。协议识别仅
用于 TCP/443，且最长为 300ms，非标准端口不再承担全局 1 秒嗅探开销。

若同一时期出现 `ccm-frontier-hl.feishu.cn:443` 等飞书大陆域名通过
`outbound/http[minbot-egress]`，说明客户端仍是旧版。v1.3.5 会让 `feishu.cn` 与
`feishucdn.com` 在进程规则之前直连，避免失败重试和不必要的跨境绕行。

若日志显示 `dial udp 223.5.5.5:53: i/o timeout`，升级客户端到 v1.3.4 并重新启用
后台服务。该版本将普通域名解析改为阿里公共 DNS 的 DoH/443，避免 UDP/53 丢包阻塞；
allowlist 域名仍由 FakeIP 保留域名信息，不会因此改为直连。

多个国内 IP 的 `:51090` 同时直连超时通常来自测速客户端探测不可用节点。它不是代理
端口限制；不要将这些 IP 加入代理 allowlist。停止测速后日志应自然消失。

## 修改在重建后消失

这是默认临时状态路径的预期行为。为 `PROXY_DOMAINS_STATE_PATH` 挂载独立持久卷，
或把确认后的完整列表同步到 `PROXY_DOMAINS`。

## 安装脚本下载失败

安装器只接受 HTTPS。先检查 GitHub 是否可访问；若已发布官方 HTTPS 镜像，核对版本
和 SHA-256 后使用镜像。不要改用 HTTP 下载并直接执行。
