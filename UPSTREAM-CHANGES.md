# v5.1.3 → v5.3.4 上游变更对照（哪些值得往 Rust 版里加）

上游最新是 **v5.3.4**（2026-01-11 打 tag）。v5.1.3 之后共 **89 个提交**，
其中大部分是 transport/QUIC/pipeline 重构和几个新插件——那些跟当前配置无关。
真正**影响我们这套实现**的只有下面 10 条。

> **状态（2026-10-20 10:04 更新）**：A/B/C/D/E 与 DoQ 已全部实现并上线（md5 `703e71f6…`，3.95 MB）；
> 只剩 EDNS0 转发策略待定（当前保持 v5.1.3 行为）。

## 一、建议移植（性价比高）

### A. forward：坏 rcode 继续等下一个上游 ⭐推荐
- **新版行为**（v5.2.0 起）：收到响应后，
  `if i < concurrent-1 && rcode != NOERROR && rcode != NXDOMAIN { continue }`
  —— 只有 `NOERROR` / `NXDOMAIN` 才立刻返回，**SERVFAIL/REFUSED/其它** 会继续等下一个上游，直到最后一个才认。
- **我们现状**：第一个成功响应直接返回，不看 rcode。本地 DNS 偶发 SERVFAIL 时会直接透给客户端。
- **价值**：`forward_local`（119.29 + 223.5.5.5）里一个上游抽风时，用户少看到 SERVFAIL。
- **改动量**：`Forward::exchange` 里加一个判断，约 10 行。

### B. forward：随机起点选上游 ⭐推荐
- **新版行为**（v5.2.0/v5.3.4）：`r := rand.IntN(len(us)); u := us[(r+i)%len(us)]`
  —— 随机起点 + 不重复；`concurrent=1` 时也不会永远打同一个上游。
- **我们现状**：固定从列表第一个开始（`upstreams.iter().take(n)`）。
  当前配置 `concurrent: 2` 且正好两个上游，影响不大；但只要以后改成 3 个上游 / `concurrent: 1`，
  就会变成「永远只用第一个」。
- **改动量**：5 行（按微秒时间戳取模）。

### C. forward：UDP 上游 1 秒无应答自动重发 ⭐推荐
- **新版行为**（v5.3.4）：`upstream: resend udp package every 1s` —— 丢一个包不再等于一次失败，
  在 5 秒总超时内会重发。
- **我们现状**：单次发送 + 5 秒读超时，UDP 丢包就直接判这个上游失败。
- **价值**：UDP 丢包（尤其 PPPoE/无线链路）是家庭网络最常见的抖动来源。
- **改动量**：`query_udp` 里改成「1 秒没收到就重发同一份报文」，约 15 行。

### D. prefer_ipv4/6：双栈探测结果缓存 ⭐推荐
- **新版行为**（v5.3.0）：`dual_selector: impl cache` —— 把「该域名有没有 A/AAAA」的结果缓存 **1 小时**，
  避免每次 AAAA 查询都发一次参考查询。
- **我们现状**：每条 AAAA 都发一个 A 参考查询（双臂竞速），AAAA 多的时候等于双倍上游查询。
- **价值**：减少上游压力、降低 AAAA 延迟；缓存键是 qname，1 小时过期。
- **改动量**：`PreferIpv4` 加一个 `Mutex<HashMap<String,(bool,Instant)>>`，约 30 行。

## 二、建议顺手改（很小，且与新版对齐）

### E. cache：命中时不再打乱 A/AAAA 顺序 ✅ 已实现
- **新版行为**（v5.2.0）：`cache: don't shuffle ip records` —— **删掉了** v5.1.3 里的 `shuffleIP`。
- **我们现状**：按 v5.1.3 实现了 shuffle（缓存命中时随机打乱尾部 A/AAAA）。
- **影响**：功能无差异（客户端自己会选），只是多一次 RNG + 交换。
- **改动量**：删 20 行。

### F. 根域名 `"."` 的域匹配
- **新版修复**（2023-10-26）：`matcher: fixed domain match doesn't match root "."` ——
  `SubDomainMatcher` 改成从**根节点**取值。
- **我们现状**：**已经是对的**（`DomainSet::matches` 一开始就是 `let mut hit = cur.value`）。
- **改动量**：0，仅记录。

## 三、不建议做（配置用不到，或与我们的模型不符）

| 上游变更 | 为什么不加 |
|---|---|
| ~~DoQ / DoT / DoH 上游~~ | **均已实现**（`quic://` / `tls://` / `https://`，见 README 1.2 节）；QUIC server / H3 入站仍未做 |
| forward pipeline / 连接池自动伸缩（v5.3.0） | 我们已有 idle 复用（55s、池 8），pipeline 只对高 QPS 有意义 |
| v5.3.1 forward 内存泄漏修复 | 修的是 pipeline 路径，我们没走那条路 |
| `ecs_handler` / `forward_edns0opt` / `padding_auth` / `rate_limiter` / `string_exp` | 都是新插件，配置里没有引用 |
| unix abstract socket / SO_REUSEPORT / 限制 SO_RCVBUF | 我们是「单 socket + 线程池」，不靠多进程共享端口 |
| `server: don't exit udp server on temporary read err` | 我们已经是 `continue` |
| `tcp first read timeout 500ms → 2s` | 我们是 10s 空闲超时，比它宽松 |
| `server: log server addr` | 我们已经打了 |

## 四、需要你拍板的一项：EDNS0 转发策略

这是 v5.2.x/v5.3.x 的**破坏性变更**，也是最大的一处语义差异：

| 版本 | 对客户端 EDNS0 option 的处理 |
|---|---|
| v5.1.3（我们在对齐的版本） | 原样转发客户端报文，OPT 里的 ECS/padding/cookie 全部带给上游 |
| v5.2.1 | **只转发 ECS**，其余丢弃；同时过滤掉上游返回的 Padding |
| v5.3.0+ | **默认一个都不转发、也不发送**，由 `forward_edns0opt` / `ecs_handler` 插件显式控制 |

另外 v5.2.0+ 还会给**每个**进来的查询强制补一个 OPT（`query_context: force edns0`），
这样上游能看到 1232 的 UDP 缓冲，减少大应答被截断。

我们现在的行为 = v5.1.3（原样透传、不补 OPT）。家庭场景下：
- 补 OPT 的收益很小（现在的客户端基本都自带 EDNS 1232）；
- 但**原样透传客户端 ECS** 有一点隐私/兼容考量（上游能看到客户端网段），
  新版作者显然认为不该默认透传。

三个选项，请你选：
1. **保持现状**（= v5.1.3 行为，最保守，改动 0）
2. 只剥掉非 ECS 的 OPT option（对齐 v5.2.1，约 20 行）
3. 完全不转发客户端 OPT（对齐 v5.3.x，约 25 行）

## 五、如果全都做，大概是这个量级

A+B+C+D+E ≈ **80 行**，全部集中在 `plugins.rs`（forward / prefer_ipv4 / cache），
不影响配置格式、不影响日志格式，改完可以照旧用
`bash /root/mosdns-rs/status.sh` + 那套基准脚本验证。
