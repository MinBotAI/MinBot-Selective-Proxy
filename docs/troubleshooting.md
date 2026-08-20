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
执行 `minbot-proxy check` 和 `minbot-proxy run`；v1.0.1 会通过 FakeIP DNS 让 HTTP
代理收到 allowlist 域名，而不是 CDN 的解析后 IP。

## 修改在重建后消失

这是默认临时状态路径的预期行为。为 `PROXY_DOMAINS_STATE_PATH` 挂载独立持久卷，
或把确认后的完整列表同步到 `PROXY_DOMAINS`。

## 安装脚本下载失败

安装器只接受 HTTPS。先检查 GitHub 是否可访问；若已发布官方 HTTPS 镜像，核对版本
和 SHA-256 后使用镜像。不要改用 HTTP 下载并直接执行。
