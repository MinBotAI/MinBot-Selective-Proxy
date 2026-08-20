# Allowlist 管理

## 日常操作

优先使用 Chrome 扩展：登录后会显示当前完整域名列表，可新增或移除根域名。输入
`example.com` 即可，不要输入 `https://`、端口、路径或通配符。

规则入口：

- PAC：`/proxy.pac`
- 文本规则：`/domains.list`
- sing-box source ruleset：`/domains.sing-box.json`

三个入口与管理 API 使用同一份运行时状态。

## API

以下示例不会把密码写入命令；`curl` 会交互提示密码：

```bash
export PROXY_ENDPOINT='http://43.156.119.18:31456'
export PROXY_USERNAME='<assigned-username>'

curl --user "${PROXY_USERNAME}" "${PROXY_ENDPOINT}/api/domains"

curl --user "${PROXY_USERNAME}" \
  --header 'Content-Type: application/json' \
  --data '{"domain":"example.com"}' \
  "${PROXY_ENDPOINT}/api/domains"

curl --user "${PROXY_USERNAME}" \
  --request DELETE \
  "${PROXY_ENDPOINT}/api/domains/example.com"
```

不要把带密码的 `--user username:password` 命令保存到 shell history。

## 持久化

`PROXY_DOMAINS` 是部署时的初始 allowlist；管理 API 的修改写入
`PROXY_DOMAINS_STATE_PATH`。默认路径位于 `/tmp`，容器重建后会恢复初始值。

长期使用应选择一种方式：

1. 为状态路径挂载只供本服务使用的持久卷；或
2. 定期把确认后的列表同步到部署平台的 `PROXY_DOMAINS` Secret。

持久卷不得与 SnapCrabBE 或其他业务服务共享。
