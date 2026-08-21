# 架构与安全边界

## 请求路径

1. PAC、Chrome、Karing 或 sing-box 判断目标域名是否在 allowlist。
2. 命中的 TCP 请求通过带 Basic Proxy Authentication 的 HTTP 正向代理发送。
3. 服务端再次校验账号、目标域名、端口和 DNS 解析结果。若 sing-box 保留了 CDN 的
   实际 IP 作为 `IP:443` CONNECT 目标，服务端只在读取到 allowlist 内的 TLS SNI
   后，按该 SNI 域名重新解析并连接上游。
4. 非 allowlist 域名，以及私网、回环、链路本地、保留或非全局 IP 均被拒绝。
   allowlist 域名默认可使用任意有效 TCP 端口，以兼容 TUN CONNECT 和服务自定义端口；
   IP CONNECT 仍仅限 443，并要求 TLS SNI 命中 allowlist。

客户端规则只决定分流体验，不能扩大服务端权限。即使客户端规则被修改，服务端仍
只允许当前 allowlist。IP CONNECT 仅限公网地址和 TCP 443，必须携带合法且命中
allowlist 的 TLS ClientHello；私网 IP、无 SNI、非 TLS 或非 allowlist SNI 都会断开。

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
- `PROXY_ALLOWED_CONNECT_PORTS`，默认 `*`，允许 allowlist 域名使用任意 TCP 端口；
  可配置逗号分隔端口重新收紧，且不会放宽 IP CONNECT 的 443 限制

本服务面向少量受信用户，不应作为公开匿名代理。
