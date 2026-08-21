# Allowlist 管理

## 日常操作

优先使用 Chrome 扩展：登录后会显示当前完整域名列表，可新增或移除根域名。输入
`example.com` 即可，不要输入 `https://`、端口、路径或通配符。

规则入口：

- PAC：`/proxy.pac`
- 文本规则：`/domains.list`
- sing-box source ruleset：`/domains.sing-box.json`

三个入口与管理 API 使用同一份运行时状态。

## 默认覆盖范围

v1.3.6 的默认集合按服务维护，覆盖常见的 AI、Google/YouTube、社交通信、流媒体、
开发协作、海外新闻与知识站点。默认条目必须能在当前大陆代理规则中得到支持，或有
大陆节点的失败实测；根域名会自动覆盖其子域名。

2026-08-21 的审阅后共有 249 个根域名：246 个存在于每日更新的
[`proxy-list.txt`](https://github.com/Loyalsoldier/v2ray-rules-dat)，另外三个
`gamma.app`、`heygen.com`、`pkg.dev` 由大陆节点实测无法建立 HTTPS 连接。未命中规则
且可直连、已失效或无法证明仍有必要的 33 个条目已移除；仅供 Codex/ChatGPT 使用的
Apple App Attest 端点改由进程规则覆盖，不再扩大普通 App 的 allowlist。

“中国大陆不可访问”会随地区、运营商和时间变化，因此默认集合是常用服务基线，不是
对所有受限网站的永久穷举。缺失服务仍应通过管理 API 增加其第一方根域名。共享
基础设施规则会扩大代理流量与带宽消耗，不得仅因某个境外服务使用了某家 CDN、登录、
监控或客服供应商，就把该供应商的整个根域名加入默认集合。

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
