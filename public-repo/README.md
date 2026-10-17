# FlClash 覆写脚本（Perfect-Rules 二次开发）

单文件 FlClash 覆写脚本。**脚本固定在仓库根目录 `./FlClash.js`，永不移动、永不重命名**，
目录结构的稳定保证了引用链接的稳定。

## 导入

FlClash → 设置 → 进阶配置 → 扩展脚本 → 添加 → **URL 导入**：

```
https://raw.githubusercontent.com/caihongmengya-ai/<仓库名>/main/FlClash.js
```

> `<仓库名>` 按实际创建的仓库名替换。raw 域名被墙时可改用 jsDelivr 镜像
> （注意其 `@main` 分支缓存最长约 12 小时，更新后可用
> `https://purge.jsdelivr.net/gh/caihongmengya-ai/<仓库名>@main/FlClash.js` 强制刷新）：
>
> ```
> https://fastly.jsdelivr.net/gh/caihongmengya-ai/<仓库名>@main/FlClash.js
> ```

注意：URL 导入是一次性下载。每次脚本更新后，需要在 FlClash 里重新导入一次才会生效。

## 版本

- **v2.6.0**（2026-10-17）：TUN MTU 9000 / fake-ip-filter 补 STUN /
  机场智能组纳入业务组选项
- **v2.5.0**（2026-10-17）：FlClash 0.9 适配，测速地址统一 HTTPS

## 说明与致谢

- 分流架构、地区分组与图标源：[n0de-sudo/Perfect-Rules](https://github.com/n0de-sudo/Perfect-Rules) 二次开发
- 广告规则数据：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（GPL-2.0，仅运行时 URL 引用，不随仓库分发）
- 本仓库只包含脚本本体与其文档，**不含任何订阅链接、节点信息或机场配置**
- 仅供个人配置 FlClash（0.9+）使用；请自行遵守上游许可条款
