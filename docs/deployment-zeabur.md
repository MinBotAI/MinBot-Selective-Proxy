# Zeabur 部署

本服务应作为独立 Zeabur Service 部署，不与 SnapCrabBE API、worker 或 scheduler
共用源码、运行命令、端口或环境变量。

## 服务配置

| 配置 | 值 |
| --- | --- |
| GitHub 仓库 | `MinBotAI/MinBot-Selective-Proxy` |
| 分支 | `main` |
| Dockerfile | `/Dockerfile` |
| 容器端口 | `8080`（兼容明文）、`8443`（TLS） |
| 网络类型 | Public TCP |
| 健康检查 | `/healthz` |

Zeabur 的 Public TCP 主机和端口是客户端实际连接地址。改变网络配置后，应同步更新
macOS 脚本、Karing 模板、Chrome 默认值和客户端文档。

## main 自动发布

`selective-proxy` 的 Git 触发器绑定 `MinBotAI/MinBot-Selective-Proxy` 的 `main`，
Watch Paths 为 `*`。PR 合并或直接推送到 `main` 后，由 Zeabur 自动构建并发布；
其他分支不会触发该生产服务。包括文档在内的所有 main 提交都触发发布。

`karing-share` 使用部署配置内嵌的服务代码及运行时私有包，不依赖本仓库文件，
因此不绑定 Git 自动触发器。仓库提交不会重建它；需要更新时单独发布该服务。
调整 Git 触发器不会停止当前运行的服务。

不要恢复旧仓库路径 `/Dockerfile.selective-proxy`、`/deploy/selective_proxy`，
它们与本仓库根目录 `Dockerfile`、`src/minbot_selective_proxy/` 不匹配，会漏掉更新。

变更触发配置后，应通过一次真实 PR 合并验证：`selective-proxy` 出现对应 main
提交的新部署并达到 `RUNNING`，`karing-share` 的部署 ID 保持不变，再检查代理健康、
认证、公网请求和私网拦截。不要用手动部署代替自动触发验收。

平台 Watch Paths 语法参见 [Zeabur 官方文档](https://zeabur.com/docs/en-US/deploy/config/watch-paths)。

## Secret

必须通过 Zeabur Secret 设置：

- `PROXY_USERNAME`
- `PROXY_PASSWORD`
- `PROXY_ADDITIONAL_USERS_JSON`，需要其他账号时设置 JSON 对象
- `PROXY_TLS_CERT_PEM`、`PROXY_TLS_KEY_PEM`，必须成对设置且仅保存于 Secret
- `PROXY_TLS_PORT=8443`

可选运行参数见 [`.env.example`](../.env.example)。不要在仓库、构建参数、部署说明
或工单中写入真实账号密码。

## Allowlist 状态

默认 `PROXY_DOMAINS_STATE_PATH=/tmp/selective-proxy/domains.json`，适合无状态部署，
但管理界面的修改会在容器重建后丢失。需要持久化时，为该路径配置独立 Volume，并
确认运行用户具备写权限。

## 部署顺序

1. 从本仓库 `main` 构建镜像。
2. 注入 Secret，保持现有账号值不变。
3. 分别暴露容器 `8080` 和 `8443` 为 Public TCP。
4. 等待部署状态为 `RUNNING`。
5. 检查构建日志、运行日志和健康接口。
6. 用未认证、已认证公网域名、已认证公网 IP 和私网 IP 四类请求完成验收。

## 验收

```bash
export PROXY_ENDPOINT='http://<public-host>:<public-port>'

curl --fail "${PROXY_ENDPOINT}/healthz"
curl --fail "${PROXY_ENDPOINT}/proxy.pac"
curl --fail "${PROXY_ENDPOINT}/domains.sing-box.json"

# 应返回 407
curl --proxy "${PROXY_ENDPOINT}" https://www.google.com/ -I

# curl 会提示密码；任意公网目标应可连接
curl --proxy "${PROXY_ENDPOINT}" \
  --proxy-user '<assigned-username>' \
  https://www.google.com/ -I

# 已认证且不在客户端 allowlist 的公网目标也应可连接
curl --proxy "${PROXY_ENDPOINT}" \
  --proxy-user '<assigned-username>' \
  https://example.com/ -I

# 私网、回环、链路本地和保留目标必须返回 403
curl --proxy "${PROXY_ENDPOINT}" \
  --proxy-user '<assigned-username>' \
  https://127.0.0.1/ -I
```

## 回滚

若新版本异常，将 Service 的 Git source 回退到上一已验证提交并重新部署；不要把
服务重新挂回 SnapCrabBE。代理服务与业务 egress 没有调用关系，回滚不需要修改
SnapCrab API、worker 或数据库。
