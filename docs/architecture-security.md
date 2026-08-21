# 架构与安全边界

## 请求路径

1. PAC、Chrome、Karing 或 sing-box 使用 allowlist 决定哪些常见境外服务需要代理；
   Codex/ChatGPT 桌面进程的 TCP 连接直接进入代理，大陆飞书域名和精确的 Apple App
   Attest 端点优先直连。
2. 代理请求必须通过 Basic Proxy Authentication，并通过固定公钥的 TLS 入口传输。
3. 认证成功后，服务端允许任意公网域名、公网 IP 和有效 TCP 端口，不再校验域名
   allowlist、TLS SNI 或端口表。
4. 若旧缓存使 HTTPS `CONNECT` 仍携带单一公网 IP，服务端会从 TLS ClientHello 恢复
   SNI 域名并重新解析多个公网地址；该步骤只用于连接容错，不把 SNI 当成授权条件。
5. DNS 结果中的私网、回环、链路本地、保留和其他非全局地址仍被过滤；IP 字面量也
   使用同一规则。这一 SSRF 边界不影响公网访问速度。

allowlist 现在是客户端分流和 PAC 管理机制，不是服务端授权边界。代理账号一旦泄露，
持有者可以消耗出口流量并访问任意公网服务，因此账号必须使用独立高熵密码并及时轮换。

## 公开与受保护入口

无需认证：

- `/healthz`
- `/proxy.pac`、`/wpad.dat`
- `/domains.list`
- `/domains.sing-box.json`

需要代理认证：

- HTTP 请求和 HTTPS `CONNECT`

需要账号认证：

- `GET /api/domains`
- `POST /api/domains`
- `DELETE /api/domains/{domain}`

允许公开读取规则，是为了让系统 PAC 和开源客户端自动更新；写入始终需要认证。

## 凭据

- 主账号放在部署平台 Secret：`PROXY_USERNAME`、`PROXY_PASSWORD`。
- 其他账号放在 Secret：`PROXY_ADDITIONAL_USERS_JSON`。
- 仓库、PAC、规则文件和安装脚本均不包含真实凭据。
- macOS 客户端把密码放入 Keychain；运行时配置权限为 `600`，退出后删除。
- Chrome 凭据只保存在当前 Profile 的 `chrome.storage.local`。

macOS TUN 客户端连接独立 TLS 代理入口，并用仓库内发布的 SHA-256 SPKI 指纹固定
服务端公钥；因此目标域名和代理认证头不会以明文暴露在客户端到代理的链路上。
兼容入口仍是明文 HTTP，只供 PAC、规则下载和暂不支持证书固定的客户端使用。所有
账号仍应使用独立高熵密码，不得复用邮箱、服务器或业务系统密码。

## 数据与日志

服务不访问 SnapCrab 数据库，也不记录目标 URL、查询参数、认证信息或浏览明细。
运行日志只保留必要的启动与错误信息。allowlist 状态默认写入容器临时目录；需要跨
部署保留时必须挂载专用持久卷。

## 容量保护

以下环境变量限制连接资源：

- `PROXY_MAX_CONNECTIONS`，默认 `256`；整机 TUN 客户端会并发建立大量浏览器和 App
  隧道，生产环境不应低于 `128`
- `PROXY_CONNECT_TIMEOUT_SECONDS`，默认 `10`
- `PROXY_IDLE_TIMEOUT_SECONDS`，默认 `120`
- `PROXY_TUNNEL_MAX_SECONDS`，默认 `1800`

认证用户的公网目标和 TCP 端口不设额外限制。以上连接数与超时参数仍用于防止单个
失效目标长期占用服务资源，不属于目标访问控制。

本服务面向少量受信用户，不应作为公开匿名代理。
