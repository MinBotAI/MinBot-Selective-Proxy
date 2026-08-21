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

若日志显示 `outbound/http[minbot-egress]` 连接到 IP 地址并返回 `403 Forbidden`，说明
本地仍在使用 v1.0.0 的 TUN 配置。先停止当前进程，运行 `minbot-proxy update`，再重新
执行 `minbot-proxy check` 和 `minbot-proxy run`；v1.1.0 会通过 FakeIP DNS 让 HTTP
代理收到 allowlist 域名，而不是 CDN 的解析后 IP。

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

若 `mtalk.google.com:5228` 返回 `403 Forbidden`，升级到 v1.2.2。服务端默认允许
Google/Firebase 使用的 TCP 5228–5230；客户端同时全局拒绝 UDP/443，让持有旧 IP
缓存的 App 也能快速从 QUIC 回退到 TCP。

若日志中的目标是 `104.16.x.x:443`、`162.125.x.x:443` 等 Cloudflare、Dropbox 或
其他 CDN 实际 IP，并由 `outbound/http[minbot-egress]` 收到 `403 Forbidden`，升级到
v1.3.0。服务端会在认证后的 IP CONNECT 中读取 TLS ClientHello，只在 SNI 命中
allowlist 时按域名连接上游；无需放开任意公网 IP，也不应把 CDN IP 写入 allowlist。

若 `clients2.google.com:80`、`edgedl.me.gvt1.com:80` 等 allowlist 域名返回 403，
升级到 v1.3.1。sing-box 的 HTTP 出站会对 TUN TCP 使用 CONNECT，服务端因此需要允许
经域名 allowlist 校验后的 CONNECT 80；IP 目标的 80 端口仍会被拒绝。

若 Codex/ChatGPT 能加载但连接远程任务很慢，或日志显示 allowlist 服务的真实 IP 仍走
`outbound/direct[direct]`，升级客户端到 v1.3.1 并重启。该版本对 Codex/ChatGPT
进程的 TCP/443 增加代理恢复规则，并在远程规则中覆盖已确认的 Meta IP 段；服务端仍
要求 TLS SNI 命中域名 allowlist。

## 修改在重建后消失

这是默认临时状态路径的预期行为。为 `PROXY_DOMAINS_STATE_PATH` 挂载独立持久卷，
或把确认后的完整列表同步到 `PROXY_DOMAINS`。

## 安装脚本下载失败

安装器只接受 HTTPS。先检查 GitHub 是否可访问；若已发布官方 HTTPS 镜像，核对版本
和 SHA-256 后使用镜像。不要改用 HTTP 下载并直接执行。
