# Chrome 扩展

扩展负责三件事：按 PAC 规则分流、保存当前 Chrome Profile 的代理账号，以及管理
服务端 allowlist。代理服务仍会逐次校验认证、域名、端口和目标 IP，扩展不是安全
边界。

## 安装

1. 打开 `chrome://extensions`，开启“开发者模式”。
2. 点击“加载已解压的扩展程序”，选择本目录。
3. 打开工具栏中的 `MinBot Selective Proxy`。
4. 填写已分配的代理主机、端口、用户名和密码。
5. 保持“启用代理”开启，点击“保存并连接”。

账号只保存在当前 Chrome Profile。每台设备、每个 Profile 都要单独配置。

## Allowlist

登录后扩展会显示完整 allowlist。输入根域名即可，例如 `example.com`，不要输入
协议、端口或路径。所有有效代理账号都可查看、新增和移除域名。

修改会同时影响服务端限制、PAC、Karing 规则和 sing-box 规则。运行时状态是否跨
部署保留取决于服务器是否为 `PROXY_DOMAINS_STATE_PATH` 配置持久卷。

不要同时启用 Chrome 扩展和设备级 TUN 客户端，以免重复代理。
