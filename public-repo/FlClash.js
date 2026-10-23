// ================================================================
// FlClash / Mihomo Perfect-Rules v2.6.4 (FlClash 0.9 适配)
//
// v2.6.4 Changelog:
//   - [传输] 非 CN 流量禁走 QUIC(UDP 443): 规则
//     AND,((NETWORK,udp),(DST-PORT,443)),REJECT 置于 GEOIP,cn 之后、
//     MATCH 之前。依据: VMess+ws 等常见传输普遍不支持 UDP, YouTube /
//     Google 先抢 QUIC 会干等 1~3s 超时才回落 TCP, 造成每次打开都卡;
//     拒绝后应用立即回落 TCP, 分流结果不变。国内域名的 QUIC(B 站等)
//     已在上方 GEOSITE/GEOIP,cn 直连出隧道, 完全不受影响
//
// v2.6.3 Changelog:
//   - [识别] regionPatterns 补齐常见命名盲区:
//       * emoji 旗帜(🇭🇰 🇹🇼 🇯🇵 🇸🇬 🇰🇷 🇺🇸 🇨🇦 🇬🇧)—— 当前最流行的机场命名风格,
//         此前完全识别不到;
//       * 汉字城市: 东京/大阪/埼玉/首尔/纽约/洛杉矶/伦敦/多伦多/温哥华/狮城;
//       * 三字码 SGP(旧 \bSG(?![A-Za-z]) 遇 "SGP-01" 会失败);
//     效果: 命名混乱(尤其纯 emoji 命名)的订阅节点不再大量沉入
//     "其他地区"混合 url-test 桶, 区域延迟画像恢复可信
//
// v2.6.2 Changelog:
//   - [分流] Windows 更新/微软官方 CDN 直连: windowsupdate.com /
//     delivery.mp.microsoft.com / update.microsoft.com → 国内直连,
//     且置于 RULE-SET,Microsoft 之前防其列表抢跑。实测(2026-10-23)
//     download.windowsupdate.com 在大陆解析为移动机房 CDN(183.204.x),
//     不加规则时 GB 级补丁包会被 Microsoft 业务组(默认地区节点)截走,
//     即白吃节点流量、又丢掉微软国内 CDN 加速
//   - [DNS] fake-ip-filter 补 dns.msftncsi.com: Windows NCSI 在 HTTP
//     探测失败时会退化为 DNS 探测, 拿到 fake-IP 会令系统误判
//     "无 Internet / 正处于门户验证"
//
// v2.6.1 Changelog:
//   - [分流] 显卡驱动/官网大文件进"游戏下载"组(默认国内直连, 需要时可
//     一键临时切代理): nvidia.com / nvidia.cn / geforce.com。
//     实测(2026-10-23) us/cn/international.download.nvidia.com 从大陆
//     一律解析为 Akamai 境外边缘(东京/新加坡), 且 geosite:cn 无 nvidia
//     条目 —— 不加规则时几百 MB~1GB 驱动包会命中 MATCH 吃节点流量
//
// v2.6 Changelog:
//   - [性能] TUN mtu 1280 → 9000(与 FlClash 桌面端默认一致, 官方下限为
//     1280): gvisor 栈本地回环处理的数据包个数与 MTU 成反比, 9000 对
//     大文件下载(如 Steam 游戏本体)吞吐提升明显; 实际外网路径由 MSS
//     端到端协商决定, 不因 TUN MTU 变大而改变
//   - [DNS] fake-ip-filter 补充 STUN 域(+.stun.*.* 系列): 语音/联机
//     (Discord、游戏大厅)的 NAT 类型检测需要拿到真实 IP, 避免被
//     fake-IP 干扰; 条目与 mihomo 官方模板一致
//   - [体验] 机场自带智能组(自动测速/故障转移/全部节点)纳入"一键代理"
//     与业务组可选列表, 不必单独滚动组列表才能用到保留组
//   - [清理] main() 异常日志版本号 v2.4 → v2.6
//
// v2.5 Changelog:
//   - [适配 FlClash 0.9.x] 测速地址统一 HTTPS: 订阅自带的故障转移组/
//     测速组与 proxy-providers 的 health-check.url 常为明文 http://,
//     mihomo 开启 unified-delay 时会对同一连接连发两次 HEAD, 部分机场
//     出口对"明文+重复 HEAD"不兼容(或劫持 80 端口), 第二次请求失败后
//     内核打印 error 日志, FlClash v0.9 起把这类日志弹成红色横幅
//     (形如 "XX failed to get the second response from http://...")。
//     本脚本把所有组与订阅健康检查的测速地址统一改写为
//     https://www.gstatic.com/generate_204, 消除横幅; 链路本身没挂。
//   - [注/DNS] 若新版在 设置→进阶配置→DNS 里遗留了"覆盖项",
//     它们会覆写本脚本的 DNS(逐键生效, 无全局开关), 需在 App 界面
//     清空覆盖项后, 本脚本的 respect-rules + DoH 方案才会生效。
//
// v2.4.1 Changelog:
//   - [修复] 移除 global-client-fingerprint: 新版 mihomo 已废弃该全局
//     字段(启动会弹告警)。按官方建议, TLS 指纹应改为在节点上单独设置
//     client-fingerprint; 脚本不再统一注入, 尊重订阅节点自身配置
//     (如需统一注入, 见第 7 节的注释代码)
//
// v2.4 Changelog:
//   - [修复] 重名去重真正生效: 重建并回写 config.proxies(保留首个同名
//     节点); 区域归类改遍历去重后的列表, 修正原"跳过重名节点"注释
//     与实现不符的问题(此前重名节点既留在配置里, 又会被重复归类)
//   - [修复] 字面量对象当 Map 的原型链隐患: seenProxyNames / proxyNameSet /
//     managedGroups / builtinTargets / originalGroupNameSet / validNames
//     全部改为 Set —— 名为 constructor / toString / __proto__ 的节点或组
//     此前可能被静默丢弃或误当内置目标
//   - [修复] 地区正则误判/漏判:
//       /UK/i 会误伤 Ukraine 这类名字;
//       \bUS\b / \bTW\b 等写法匹配不到 US01(字母与数字之间没有 \b 边界);
//       /SIN/i 会误伤含 "sin" 的普通单词(如 Tsingtao);
//     统一改为 \bXX(?![A-Za-z]) 形态: 兼容 US / US01 / US-01, 又排除
//     词内误匹配。副作用: HKT 这类"HK 后接字母"的命名会被排除, 如遇可另补
//   - [加固] 全脚本 try/catch: 开头备份原配置, 任何异常时整体回滚并返回,
//     避免脚本半途出错导致整个配置加载失败或半成品配置上线
//   - [加固] sanitizeProxyGroups: 固定 5 轮改为 while + guard(最多 10 轮,
//     收敛即退出); 组内去重由 indexOf O(n²) 改为 Set
//   - [清理] 移除冗余正则 /disney\+/(被 /disney/ 覆盖)、/全部节点/
//     (被 /全部/ 覆盖); 移除 finalPreservedGroups 冗余二次过滤;
//     getProxyComposition 去掉未用字段; detectRegion 改 Object.entries
//   - [体验] "一键代理" 移到代理组列表顶部(恢复原顺序见第 20 节注释);
//     fake-ip-filter 补 +.mijia.cloud 与 sniffer.skip-domain 对齐
//     (当时新增的 global-client-fingerprint 见 v2.4.1: 已因内核废弃移除)
//
// v2.3 Changelog:
//   - [关键] 国内 AI 直连规则(Doubao/Kimi/DeepSeek)前置于 RULE-SET,AI,
//     防 AI 规则列表收录这些域名后抢先命中走代理, 导致直连保护失效
//   - tongyi.aliyun.com 调整为国内直连(国内通义入口, 海外出口反而更易
//     触发阿里风控); 如确需强制代理, 恢复 rules 中被注释的那一行
//   - 删除 GEOSITE,cn 之后的死规则段(目标同为国内直连, 永远匹配不到)
//   - TUN: 移除无效字段 disable-icmp-forwarding(非 mihomo 官方字段,
//     会被静默忽略); auto-detect-interface 恢复 true(PC 端防回环/断流)
//   - DNS: listen 收敛为 127.0.0.1:53(TUN dns-hijack 已接管本机流量,
//     0.0.0.0 会向局域网开放查询端口, 与 allow-lan:false 矛盾)
//   - nameserver 改 IP 型 DoH(1.0.0.1), 免去对 cloudflare-dns.com 的
//     明文 bootstrap 解析; AliDNS 家族同步改 IP 型(223.5.5.5)
//   - find-process-mode: strict(脚本无 PROCESS-NAME 规则, always 纯耗 CPU)
//   - 空订阅防御: 无节点时不保留机场基础组, 避免 proxies:[] 非法组
//   - 业务组检测 /ai/i 收紧为 /\bai\b/i, 防误伤英文组名(Taiwan/Main/Chain)
//   - 广告规则集切换 AdvertisingLite 轻量版(手机内存友好, 完整版路径见注释)
//   - 代码: 节点名 Set 化查找 / selectableTargets / attachIcon /
//     applyUrlTestOptions 消除重复
// ================================================================

function transform(config) {

  // ================================================================
  // 1. Basic configuration
  // ================================================================

  config["mixed-port"] = 7890;
  config["mode"] = "rule";
  config["unified-delay"] = true;
  config["tcp-concurrent"] = true;
  config["log-level"] = "error";
  config["ipv6"] = false;
  config["allow-lan"] = false;
  config["find-process-mode"] = "strict"; // 仅规则需要时查询进程, 无 PROCESS 规则则几乎零开销
  config["keep-alive-interval"] = 30;
  config["keep-alive-idle"] = 30;
  config["disable-keep-alive"] = false;

  // ================================================================
  // 2. Profile
  // ================================================================

  config["profile"] = {
    "store-selected": true,
    "store-fake-ip": true
  };

  // ================================================================
  // 3. DNS (单一家族防泄露版)
  //    - 全部采用 IP 型 DoH, 无需明文 bootstrap 域名解析
  //    - respect-rules 需配合 proxy-server-nameserver (已配置)
  // ================================================================

  config["dns"] = {
    "enable": true,
    "listen": "127.0.0.1:53", // TUN dns-hijack 已接管本机 53 端口, 仅保留本机监听
    "prefer-h3": false,
    "ipv6": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "172.19.0.1/16",
    "respect-rules": true,
    "fake-ip-filter": [
      "+.lan", "+.local", "+.localhost", "+.home.arpa",
      "time.*.com", "time.*.gov", "pool.ntp.org",
      "+.push.apple.com", "mesu.apple.com", "swscan.apple.com",
      "captive.apple.com", "connectivitycheck.gstatic.com",
      "connectivitycheck.android.com", "www.msftconnecttest.com", "www.msftncsi.com",
      "dns.msftncsi.com", // v2.6.2: NCSI 的 DNS 探测需真实解析, 防"无 Internet"误判
      "+.mijia.cloud", // v2.4: 与 sniffer.skip-domain 对齐, 米家设备依赖真实 IP
      // v2.6: STUN 直回真实 IP, 保障语音/联机(Discord 等)的 NAT 类型检测
      "+.stun.*.*", "+.stun.*.*.*",
      "+.stun.*.*.*.*", "+.stun.*.*.*.*.*"
    ],
    // 兜底明文引导(当前全部 IP 型 DoH 时实际不参与解析, 保留以防别名写法回退)
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    // 默认解析走 Cloudflare(非国内域名), 尊重规则 → 经一级代理出站, 无泄露
    "nameserver": ["https://1.0.0.1/dns-query"],
    "nameserver-policy": {
      "geosite:cn": ["https://223.5.5.5/dns-query"],
      "geosite:private": ["https://223.5.5.5/dns-query"]
    },
    "proxy-server-nameserver": ["https://223.5.5.5/dns-query"],
    "direct-nameserver": ["https://223.5.5.5/dns-query"]
  };

  // ================================================================
  // 4. TUN
  // ================================================================

  config["tun"] = {
    "enable": true,
    "device": "FlClash",
    "stack": "gvisor",
    "dns-hijack": ["any:53"],
    "auto-route": true,
    "auto-detect-interface": true, // mihomo 默认即 true; PC 端网卡切换时防回环/断流
    "strict-route": true,
    "mtu": 9000, // v2.6: 对齐 FlClash 桌面默认(官方下限 1280); 大文件下载吞吐更好
    "inet4-address": ["172.19.0.1/30"],
    "auto-redirect": false
    // 注: 原配置中的 disable-icmp-forwarding 并非 mihomo TUN 字段(官方字段
    // 清单无此项, 会被静默忽略), v2.3 起移除
  };

  // ================================================================
  // 5. Sniffer
  // ================================================================

  config["sniffer"] = {
    "enable": true,
    "parse-pure-ip": true,
    "force-dns-mapping": true,
    "override-destination": true,
    "sniff": {
      "HTTP": { "ports": [80, "8080-8880"] },
      "TLS": { "ports": [443, 8443] },
      "QUIC": { "ports": [443, 8443] }
    },
    "skip-domain": ["+.push.apple.com", "+.mijia.cloud"]
  };

  // ================================================================
  // 6. NTP (interval 单位为分钟)
  // ================================================================

  config["ntp"] = {
    "enable": true,
    "write-to-system": false,
    "server": "time.apple.com",
    "port": 123,
    "interval": 30
  };

  // ================================================================
  // 7. Original airport proxies
  //    v2.4: 去重真正生效 —— 重建并回写 config.proxies(保留首个同名节点)
  // ================================================================

  const originalProxies = Array.isArray(config["proxies"]) ? config["proxies"] : [];

  const seenProxyNames = new Set();
  const proxies = [];
  originalProxies.forEach((proxy) => {
    if (!proxy || !proxy.name || seenProxyNames.has(proxy.name)) return;
    seenProxyNames.add(proxy.name);
    proxies.push(proxy);
  });
  config["proxies"] = proxies; // 重名/非法节点从配置源头移除

  // 注: 如需统一 TLS 指纹, 新版内核要求在节点上设置 client-fingerprint
  // (全局字段 global-client-fingerprint 已废弃, 会弹告警)。默认不注入,
  // 尊重订阅节点自身配置; 需要统一时可取消下行注释:
  // proxies.forEach((p) => { if (!p["client-fingerprint"]) p["client-fingerprint"] = "chrome"; });

  const proxyNames = proxies.map((proxy) => proxy.name);

  // Set 化查找表: composition / sanitizer 热路径 O(1), 且免疫
  // constructor / toString / __proto__ 等原型链键名
  const proxyNameSet = new Set(proxyNames);

  // ================================================================
  // 8. Original airport proxy groups
  // ================================================================

  const originalGroups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  const originalGroupNameSet = new Set();
  originalGroups.forEach((group) => {
    if (group && group.name) originalGroupNameSet.add(group.name);
  });

  // ================================================================
  // 9. Perfect-Rules icon CDN
  // ================================================================

  const iconBaseURL = "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/icons/";
  const groupIcons = {
    "一键代理": "Proxy.png",
    "国内直连": "China.png",
    "AI": "AI.png",
    "YouTube": "YouTube.png",
    "Google": "Google.png",
    "GitHub": "GitHub.png",
    "网络检测": "Network-test.png",
    "Netflix": "Netflix.png",
    "Spotify": "Spotify.png",
    "Telegram": "Telegram.png",
    "TikTok": "TikTok.png",
    "Apple": "Apple.png",
    "Microsoft": "Microsoft.png",
    "香港": "Hong_Kong.png",
    "台湾": "Taiwan.png",
    "日本": "Japan.png",
    "新加坡": "Singapore.png",
    "韩国": "Korea.png",
    "美国": "United_States.png",
    "加拿大": "Other.png",
    "英国": "Other.png",
    "其他地区": "Other.png",
    "游戏下载": "Steam.png"
    // 注: 如仓库提供 "广告拦截" 图标, 可在此补充对应文件名
  };

  function getGroupIcon(name) {
    if (!groupIcons[name]) return undefined;
    return iconBaseURL + groupIcons[name];
  }

  function attachIcon(group) {
    const icon = getGroupIcon(group.name);
    if (icon) group["icon"] = icon;
    return group;
  }

  // ================================================================
  // 10. Managed groups
  // ================================================================

  const managedGroups = new Set([
    "一键代理", "国内直连",
    "AI", "YouTube", "Google", "GitHub", "网络检测", "Netflix", "Spotify",
    "Telegram", "TikTok", "Apple", "Microsoft",
    "香港", "台湾", "日本", "新加坡", "韩国", "美国", "加拿大", "英国",
    "其他地区", "游戏下载", "广告拦截"
  ]);

  // ================================================================
  // 11. Built-in targets
  // ================================================================

  const builtinTargets = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]);

  // ================================================================
  // 12. Business group detection
  //     注: /ai/ 收紧为 \bai\b, 防止 "Taiwan"/"Main"/"Chain" 等英文组名误伤
  // ================================================================

  function isBusinessGroupName(name) {
    if (!name) return false;
    const text = String(name);
    const patterns = [
      /\bai\b/i, /openai/i, /chatgpt/i, /claude/i, /gemini/i,
      /netflix/i, /disney/i,
      /youtube/i, /google/i, /github/i,
      /spotify/i, /tiktok/i, /telegram/i,
      /twitter/i, /x\.com/i, /facebook/i, /instagram/i,
      /流媒体/i, /媒体/i, /影音/i, /视频/i,
      /游戏/i, /游戏专用/i, /机场专用/i, /节点分流/i, /下载/i,
      /广告/i, /adblock/i, /adguard/i, /\bads?\b/i
    ];
    for (let i = 0; i < patterns.length; i++) {
      if (patterns[i].test(text)) return true;
    }
    return false;
  }

  // ================================================================
  // 13. Auto-select, Failover, All-node detection
  // ================================================================

  function isAutoSelectGroup(name) {
    if (!name) return false;
    return /自动选择/i.test(name) || /auto[\s_-]*select/i.test(name) || /auto[\s_-]*test/i.test(name) || /测速/i.test(name);
  }

  function isFailoverGroup(name) {
    if (!name) return false;
    return /故障转移/i.test(name) || /failover/i.test(name) || /fallback/i.test(name);
  }

  function isAllNodeName(name) {
    if (!name) return false;
    return /所有节点/i.test(name) ||
      /全部/i.test(name) || // 覆盖 "全部节点"/"全部线路" 等, 不再单列
      /\ball\b/i.test(name) ||
      /all[\s_-]*nodes?/i.test(name) ||
      /all[\s_-]*proxies?/i.test(name);
  }

  function getProxyComposition(group) {
    const result = { total: 0, actualNodes: 0, groups: 0 };
    if (!group || !Array.isArray(group.proxies)) return result;
    result.total = group.proxies.length;
    group.proxies.forEach((item) => {
      if (!item) return;
      if (proxyNameSet.has(item)) { result.actualNodes++; return; }
      if (builtinTargets.has(item)) return;
      if (originalGroupNameSet.has(item)) { result.groups++; return; }
    });
    return result;
  }

  function isAllNodesGroup(group) {
    if (!group || !group.name) return false;
    const name = String(group.name);
    if (isAllNodeName(name)) return true;
    if (isBusinessGroupName(name)) return false;
    const composition = getProxyComposition(group);
    if (composition.total === 0) return false;
    if (composition.actualNodes < 2) return false;
    const ratio = composition.actualNodes / composition.total;
    if (ratio < 0.3) return false;
    if (composition.groups > 0) {
      if (composition.actualNodes >= 5) return true;
      return false;
    }
    return true;
  }

  // ================================================================
  // 14. Preserve airport basic groups (v2.1 防御机制)
  //        空订阅防御: 无任何节点时不保留, 避免 proxies:[] 非法组
  // ================================================================

  const hasNodes = proxyNames.length > 0;

  const preservedGroups = [];
  originalGroups.forEach((group) => {
    if (!group || !group.name) return;
    if (managedGroups.has(group.name)) return;
    if (!hasNodes) return;
    const isBasic = isAutoSelectGroup(group.name) || isFailoverGroup(group.name) || isAllNodesGroup(group);
    if (!isBasic) return;
    const copied = JSON.parse(JSON.stringify(group));
    delete copied["hidden"];
    preservedGroups.push(copied);
  });

  function applyUrlTestOptions(group) {
    group.url = "https://www.gstatic.com/generate_204";
    group.interval = 300;
    group.timeout = 5000;
    group.tolerance = 50;
    group.lazy = true;
    group["max-failed-times"] = 3;
    group["expected-status"] = 204;
  }

  preservedGroups.forEach((group) => {
    if (!group || !group.name) return;
    if (!isAutoSelectGroup(group.name)) return;

    if (proxyNames.length < 2) {
      // 单节点降级: select 组比 url-test 更稳
      group.type = "select";
      group.proxies = proxyNames.slice();
      delete group.url;
      delete group.interval;
    } else {
      group.type = "url-test";
      group.proxies = proxyNames.slice();
      applyUrlTestOptions(group);
    }
    delete group["disable-udp"];
    delete group["strategy"];
  });

  // ================================================================
  // 15. Dangling reference sanitizer
  //     v2.4: while + guard 收敛(最多 10 轮, 收敛即退出);
  //           组内去重由 indexOf O(n²) 改为 Set(O(n))
  // ================================================================

  function sanitizeProxyGroups(groups) {
    let current = groups.slice();
    let changed = true;
    let guard = 0;

    while (changed && guard++ < 10) {
      changed = false;

      const validNames = new Set();
      current.forEach((g) => {
        if (g && g.name) validNames.add(g.name);
      });

      const next = [];

      current.forEach((group) => {
        if (!group || !group.name || !Array.isArray(group.proxies)) {
          next.push(group);
          return;
        }

        const isStrictType = ["url-test", "fallback", "load-balance"].indexOf(group.type) !== -1;
        const cleaned = [];
        const seen = new Set();
        const pushUnique = (item) => {
          if (seen.has(item)) return;
          seen.add(item);
          cleaned.push(item);
        };

        group.proxies.forEach((item) => {
          if (!item || item === group.name) return;

          if (proxyNameSet.has(item) || builtinTargets.has(item)) {
            pushUnique(item);
            return;
          }

          if (!isStrictType && validNames.has(item)) {
            pushUnique(item);
            return;
          }

          if (isStrictType) {
            // 严格型组的未知引用一律剔除; 命中"直连"语义时降级为 DIRECT
            if (/直连/.test(item)) pushUnique("DIRECT");
            changed = true;
            return;
          }

          // 宽松型组: 未知引用按语义别名降级, 无法识别则剔除
          let alias;
          if (/直连/.test(item)) alias = "DIRECT";
          else if (/代理|节点选择|手动选择/.test(item)) alias = "一键代理";

          if (alias && alias !== group.name) pushUnique(alias);
          changed = true;
        });

        if (cleaned.length === 0) {
          changed = true;
          return;
        }

        if (cleaned.length !== group.proxies.length) changed = true;
        group.proxies = cleaned;
        next.push(group);
      });

      current = next;
    }
    return current;
  }

  // ================================================================
  // 16. Remote Rule Providers
  //     注: 如所在网络拉取 jsdelivr 经常失败, 可整体改用
  //     fastly.jsdelivr.net 镜像(仅替换 URL 顶部域名)
  // ================================================================

  const ruleBaseURL = "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/rules/";
  function createRuleProvider(filename) {
    return {
      "type": "http",
      "behavior": "classical",
      "format": "yaml",
      "url": ruleBaseURL + filename,
      "path": "./rules/" + filename,
      "interval": 86400
    };
  }

  config["rule-providers"] = {
    "AI": createRuleProvider("ai.yaml"),
    "YouTube": createRuleProvider("youtube.yaml"),
    "Google": createRuleProvider("google.yaml"),
    "GitHub": createRuleProvider("github.yaml"),
    "Netflix": createRuleProvider("netflix.yaml"),
    "Spotify": createRuleProvider("spotify.yaml"),
    "Telegram": createRuleProvider("telegram.yaml"),
    "TikTok": createRuleProvider("tiktok.yaml"),
    "Apple": createRuleProvider("apple.yaml"),
    "Microsoft": createRuleProvider("microsoft.yaml"),
    "NetworkTest": createRuleProvider("network-test.yaml"),
    // AdvertisingLite 轻量版: 规则量约为完整版的 1/3, 手机内存友好
    // 如需换回完整版, 改用:
    //   url:  https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Advertising/Advertising.yaml
    //   path: ./rules/Advertising.yaml
    "Advertising": {
      "type": "http",
      "behavior": "classical",
      "format": "yaml",
      "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdvertisingLite/AdvertisingLite.yaml",
      "path": "./rules/AdvertisingLite.yaml",
      "interval": 86400
    }
  };

  // ================================================================
  // 17. Region detection and grouping
  //     v2.4: 统一 \bXX(?![A-Za-z]) 形态:
  //       - 兼容 US / US01 / US-01(旧 \bUS\b 匹配不到 US01)
  //       - 排除词内误匹配(Ukraine / RUSSIAN / focus01 / Tsingtao)
  // ================================================================

  const regionPatterns = {
    "香港": [/🇭🇰/, /香港/i, /\bHK(?![A-Za-z])/i, /HKG/i, /Hong\s*Kong/i, /HongKong/i],
    "台湾": [/🇹🇼/, /台湾/i, /台灣/i, /\bTW(?![A-Za-z])/i, /TPE/i, /KHH/i, /TSA/i, /Taiwan/i, /Taipei/i],
    "日本": [/🇯🇵/, /日本/i, /\bJP(?![A-Za-z])/i, /NRT/i, /HND/i, /KIX/i, /CTS/i, /FUK/i, /Japan/i, /Tokyo/i, /Osaka/i, /东京/i, /大阪/i, /埼玉/i],
    "新加坡": [/🇸🇬/, /新加坡/i, /\bSG(?![A-Za-z])/i, /\bSGP(?![A-Za-z])/i, /\bSIN(?![A-Za-z])/i, /XSP/i, /Singapore/i, /狮城/i],
    "韩国": [/🇰🇷/, /韩国/i, /韓國/i, /\bKR(?![A-Za-z])/i, /ICN/i, /GMP/i, /PUS/i, /Korea/i, /Seoul/i, /首尔/i],
    "美国": [/🇺🇸/, /美国/i, /\bUS(?![A-Za-z])/i, /\bUSA(?![A-Za-z])/i, /LAX/i, /SFO/i, /JFK/i, /SJC/i, /United\s*States/i, /America/i, /Los\s*Angeles/i, /San\s*Jose/i, /New\s*York/i, /纽约/i, /洛杉矶/i],
    "加拿大": [/🇨🇦/, /加拿大/i, /Canada/i, /Toronto/i, /Vancouver/i, /Montreal/i, /多伦多/i, /温哥华/i],
    "英国": [/🇬🇧/, /英国/i, /\bUK(?![A-Za-z])/i, /United\s*Kingdom/i, /England/i, /London/i, /Manchester/i, /伦敦/i]
  };

  const regionEntries = Object.entries(regionPatterns);

  function detectRegion(proxyName) {
    for (const entry of regionEntries) {
      const region = entry[0];
      const patterns = entry[1];
      for (let i = 0; i < patterns.length; i++) {
        if (patterns[i].test(proxyName)) return region;
      }
    }
    return "其他地区";
  }

  const regionNodes = {
    "香港": [], "台湾": [], "日本": [], "新加坡": [], "韩国": [],
    "美国": [], "加拿大": [], "英国": [], "其他地区": []
  };

  // v2.4: 遍历已去重且均有名字的 proxies, 直接归类, 天然不会重复 push
  proxies.forEach((proxy) => {
    regionNodes[detectRegion(String(proxy.name))].push(proxy.name);
  });

  const regionOrder = ["香港", "台湾", "日本", "新加坡", "韩国", "美国", "加拿大", "英国", "其他地区"];
  const regionGroups = [];

  regionOrder.forEach((region) => {
    const nodes = regionNodes[region];
    if (!nodes || nodes.length === 0) return;

    const groupType = nodes.length > 1 ? "url-test" : "select";

    const group = attachIcon({
      "name": region,
      "type": groupType,
      "proxies": nodes
    });

    if (groupType === "url-test") {
      applyUrlTestOptions(group);
    }
    regionGroups.push(group);
  });

  const availableRegions = regionGroups.map((group) => group.name);

  // ================================================================
  // 18. Domestic Direct & One-click Proxy
  // ================================================================

  // v2.6: 机场自带智能组(自动测速/故障转移/全部节点)也加入可选列表,
  // 业务组可直接引用保留组; 无保留组时 concat([]) 自动退化为原行为
  const preservedGroupNames = preservedGroups.map((group) => group.name);
  const selectableTargets = availableRegions.concat(preservedGroupNames).concat(["国内直连"]);

  const domesticDirectGroup = attachIcon({
    "name": "国内直连",
    "type": "select",
    "proxies": ["DIRECT"]
  });

  const mainSelector = attachIcon({
    "name": "一键代理",
    "type": "select",
    "proxies": selectableTargets
  });

  // ================================================================
  // 19. Service groups, Game Download group & Ad-Block group
  // ================================================================

  function createBusinessGroup(name) {
    return attachIcon({
      "name": name,
      "type": "select",
      "proxies": selectableTargets
    });
  }

  const businessGroups = [
    createBusinessGroup("AI"),
    createBusinessGroup("YouTube"),
    createBusinessGroup("Google"),
    createBusinessGroup("GitHub"),
    createBusinessGroup("Netflix"),
    createBusinessGroup("Spotify"),
    createBusinessGroup("Telegram"),
    createBusinessGroup("TikTok"),
    createBusinessGroup("Apple"),
    createBusinessGroup("Microsoft"),
    createBusinessGroup("网络检测")
  ];

  const gameDownloadGroup = attachIcon({
    "name": "游戏下载",
    "type": "select",
    "proxies": ["国内直连", "一键代理"].concat(availableRegions)
  });
  businessGroups.push(gameDownloadGroup);

  businessGroups.push({
    "name": "广告拦截",
    "type": "select",
    "proxies": ["REJECT-DROP", "DIRECT"]
  });

  // ================================================================
  // 20. Final proxy-group architecture
  //     v2.4: "一键代理" 置顶, 便于在 FlClash 主页快速切换;
  //     想恢复 v2.3 顺序(保留组 → 业务组 → 地区组 → 自有组),
  //     把 [mainSelector] 从最前挪到最后一个 concat 即可
  // ================================================================

  config["proxy-groups"] = sanitizeProxyGroups(
    [mainSelector]
      .concat(preservedGroups)
      .concat(businessGroups)
      .concat(regionGroups)
      .concat([domesticDirectGroup])
  );

  // ================================================================
  // 21. Routing rules (v2.3 AI 分流顺序修正)
  //     原则: 定向覆盖规则(目标不同于后续兜底)必须排在其抢跑者之前
  // ================================================================

  config["rules"] = [
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,localhost,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",

    "DOMAIN-SUFFIX,time.apple.com,国内直连",

    "RULE-SET,NetworkTest,网络检测",
    "RULE-SET,Advertising,广告拦截",

    // --------------------------------------------------------------
    // v2.3 强制修正: qwen 国际版走 AI 策略组 (防国内直连风控)
    // --------------------------------------------------------------
    "DOMAIN-SUFFIX,qwen.ai,AI",
    "DOMAIN-SUFFIX,qwenlm.ai,AI",

    // --------------------------------------------------------------
    // v2.3 关键: 国内 AI 定向直连必须在 RULE-SET,AI 之前。
    // 若 AI 规则列表收录了 DeepSeek/Kimi/豆包域名, 会被 RULE-SET,AI
    // 抢先命中走代理 —— 顺序错误会让 v2.2 的直连保护全部失效。
    // --------------------------------------------------------------
    "DOMAIN-SUFFIX,moonshot.cn,国内直连",
    "DOMAIN-SUFFIX,kimi.com,国内直连",
    "DOMAIN-SUFFIX,doubao.com,国内直连",
    "DOMAIN-SUFFIX,deepseek.com,国内直连",

    // 通义千问国内入口为国内服务: 直连更合理, 海外出口反而更易触发阿里
    // 风控。如确需强制经代理(原 v2.2 行为), 改回下一行即可:
    // "DOMAIN-SUFFIX,tongyi.aliyun.com,AI",
    "DOMAIN-SUFFIX,tongyi.aliyun.com,国内直连",

    "RULE-SET,AI,AI", // ChatGPT / Claude / Gemini 等国外 AI
    "RULE-SET,YouTube,YouTube",
    "RULE-SET,Google,Google",
    "RULE-SET,GitHub,GitHub",
    "RULE-SET,Netflix,Netflix",
    "RULE-SET,Spotify,Spotify",
    "RULE-SET,Telegram,Telegram",
    "RULE-SET,TikTok,TikTok",
    "RULE-SET,Apple,Apple",

    // --------------------------------------------------------------
    // v2.6.2 Windows 更新走微软国内 CDN: 实测 download.windowsupdate.com
    // 在大陆解析为 China Mobile 节点; 置于 RULE-SET,Microsoft 之前,
    // 防其列表抢跑把 GB 级补丁包分流进微软业务组(默认地区节点)
    // --------------------------------------------------------------
    "DOMAIN-SUFFIX,windowsupdate.com,国内直连",
    "DOMAIN-SUFFIX,delivery.mp.microsoft.com,国内直连",
    "DOMAIN-SUFFIX,update.microsoft.com,国内直连",

    "RULE-SET,Microsoft,Microsoft",

    "DOMAIN-KEYWORD,steamcontent,游戏下载",
    "DOMAIN-KEYWORD,steampipe,游戏下载",
    "DOMAIN-SUFFIX,steamserver.net,游戏下载",
    "DOMAIN-KEYWORD,epicgames-download,游戏下载",
    "DOMAIN-SUFFIX,epicgamescdn.com,游戏下载",
    "DOMAIN-SUFFIX,download.epicgames.com,游戏下载",
    "DOMAIN-SUFFIX,download2.epicgames.com,游戏下载",
    "DOMAIN-SUFFIX,download3.epicgames.com,游戏下载",
    "DOMAIN-SUFFIX,download4.epicgames.com,游戏下载",
    "DOMAIN-SUFFIX,fastly-download.epicgames.com,游戏下载",

    // --------------------------------------------------------------
    // v2.6.1 显卡驱动/官网大文件: 默认国内直连(在"游戏下载"组内切换)。
    // 实测 NVIDIA 全部下载源均为 Akamai 境外边缘, 不命中
    // geosite:cn / GEOIP,cn, 不加规则时驱动包会命中 MATCH 走节点
    // --------------------------------------------------------------
    "DOMAIN-SUFFIX,nvidia.com,游戏下载",
    "DOMAIN-SUFFIX,nvidia.cn,游戏下载",
    "DOMAIN-SUFFIX,geforce.com,游戏下载",

    // 国内兜底 (豆包/Kimi/DeepSeek/Baidu 均已被上方定向规则与 geosite:cn
    // 覆盖, 不再重复列出)
    "GEOSITE,private,国内直连",
    "GEOIP,private,国内直连,no-resolve",
    "GEOSITE,cn,国内直连",
    "GEOIP,cn,国内直连,no-resolve",

    // --------------------------------------------------------------
    // v2.6.4 非 CN 流量禁走 QUIC(UDP 443): ws/vmess-ws 类节点普遍
    // 不支持 UDP, YouTube/Google 先抢 QUIC 会干等 1~3s 超时才回落
    // TCP; 在此拒掉非 CN 的 UDP 443, 应用立即回落 TCP(分流不变)。
    // CN 流量已在上方 GEOSITE/GEOIP,cn 直连出隧道, QUIC 不受影响
    // --------------------------------------------------------------
    "AND,((NETWORK,udp),(DST-PORT,443)),REJECT",

    "MATCH,一键代理"
  ];

  // ================================================================
  // 22. Test-URL hygiene (v2.5: FlClash 0.9 适配)
  //     mihomo 开启 unified-delay 时, 延迟测速会先 HEAD 一次建链,
  //     再 HEAD 一次取"纯传输延迟"。订阅自带的故障转移/所有节点组与
  //     proxy-providers 的 health-check.url 常为明文 http:// —— 部分机场
  //     出口对同一连接上的重复 HEAD 兼容性差(或直接劫持 80), 第二次
  //     请求失败后内核打印 error 日志, FlClash 新版把它弹成红色横幅
  //     (形如 "XX failed to get the second response from http://...")。
  //     统一改写为 HTTPS 即可消除; 该报错并不代表节点不能用。
  // ================================================================

  const secureTestURL = "https://www.gstatic.com/generate_204";

  (config["proxy-groups"] || []).forEach((group) => {
    if (
      group &&
      typeof group.url === "string" &&
      group.url.indexOf("http://") === 0
    ) {
      group.url = secureTestURL;
    }
  });

  const providers = config["proxy-providers"];
  if (providers && typeof providers === "object") {
    Object.keys(providers).forEach((name) => {
      const provider = providers[name];
      if (!provider || provider.type === "inline") return;
      const healthCheck = provider["health-check"];
      if (
        healthCheck &&
        typeof healthCheck.url === "string" &&
        healthCheck.url.indexOf("http://") === 0
      ) {
        healthCheck.url = secureTestURL;
      }
    });
  }

  // ================================================================
  // 23. Return generated config
  // ================================================================

  return config;
}

// ================================================================
// 对外入口: 异常防护
//   - 先深度备份原配置; transform 抛错时整体回滚并返回原配置,
//     保证脚本故障不会导致配置加载失败或半成品配置被使用
//   - 备份本身失败(如异常结构)时不做任何修改
// ================================================================

const main = (config) => {
  if (!config || typeof config !== "object") return config;

  let backup;
  try {
    backup = JSON.parse(JSON.stringify(config));
  } catch (e) {
    return config;
  }

  try {
    return transform(config);
  } catch (e) {
    if (typeof console !== "undefined" && console.log) {
      console.log("[Perfect-Rules v2.6] transform 异常, 已回滚原配置: " + e);
    }
    Object.keys(config).forEach((key) => { delete config[key]; });
    Object.keys(backup).forEach((key) => { config[key] = backup[key]; });
    return config;
  }
};
