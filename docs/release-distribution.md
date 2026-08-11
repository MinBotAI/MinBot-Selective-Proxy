# 版本发布与安装分发

## 决策

macOS 一键安装脚本的权威来源是本公开仓库。README 使用固定版本标签的 GitHub Raw
HTTPS 地址，避免执行会随 `main` 变化的脚本，也避免通过未加密 HTTP 下载可执行
内容。

推荐入口：

```text
https://raw.githubusercontent.com/MinBotAI/MinBot-Selective-Proxy/<tag>/install-macos.sh
```

禁止把 `http://<proxy-host>:<port>/...` 作为 shell 安装源。该端口没有为安装文件
提供 TLS，中间人可替换脚本。

## 发布流程

1. 更新版本、代码、测试和文档。
2. 运行 pytest、shell 语法检查、sing-box 配置检查和 Docker 构建。
3. 提交并推送 `main`。
4. 创建不可移动的语义化版本标签，例如 `v1.0.0`。
5. 从标签地址重新下载脚本，核对 SHA-256 与仓库文件一致。
6. 用全新临时目录验证一键安装流程。
7. 更新 README 中的固定标签，仅在需要更换推荐版本时发布新标签。

## 可选 HTTPS 镜像

若 GitHub 在某些网络中不稳定，可增加以下镜像，但不能替代本仓库作为源码：

| 方案 | 用途 | 要求 |
| --- | --- | --- |
| `minbotai.com` 静态文件 | 中国网络的稳定下载入口 | HTTPS、固定版本路径、发布时校验 SHA-256 |
| 独立 Zeabur 静态 Service | 与官网解耦 | HTTPS 域名、只读构建、固定版本路径 |
| GitHub Release asset | 固定二进制或脚本附件 | 标签、校验和、发布记录 |

任何镜像都必须从已发布标签生成，文件校验和必须一致。不得从 SnapCrabBE 构建目录
复制或维护第二份逻辑源码。

## 更新模型

初次安装使用固定标签；安装后的 `minbot-proxy update` 从本仓库 `main` 获取最新 CLI。
这一区分让首次执行可审计，同时保留主动更新能力。若未来面向更多用户，应把更新也
切换为签名 release，并在安装前验证校验和或签名。
