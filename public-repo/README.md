# FlClash 覆写脚本（Perfect-Rules 二次开发）



## 导入

1. FlClash → 设置 → 进阶配置 → 扩展脚本 → 添加 → **URL 导入**：

    ```
    https://raw.githubusercontent.com/caihongmengya-ai/flclash-/main/public-repo/FlClash.js
    ```

2. 在需要该脚本的配置（Profile）的覆写中**点选启用**该脚本，重新连接生效。

> raw 域名被墙时可改用 jsDelivr 镜像（`@main` 分支缓存最长约 12 小时，
> 更新后可用 `https://purge.jsdelivr.net/gh/caihongmengya-ai/flclash-@main/public-repo/FlClash.js`
> 强制刷新）：
>
> ```
> https://fastly.jsdelivr.net/gh/caihongmengya-ai/flclash-@main/public-repo/FlClash.js
> ```





## 说明与致谢

- 分流架构、地区分组与图标源：[n0de-sudo/Perfect-Rules](https://github.com/n0de-sudo/Perfect-Rules) 二次开发
- 广告规则数据：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（GPL-2.0，仅运行时 URL 引用，不随仓库分发）
- 本仓库只包含脚本本体与其文档，**不含任何订阅链接、节点信息或机场配置**
- 仅供个人配置 FlClash（0.9+）使用；请自行遵守上游许可条款
