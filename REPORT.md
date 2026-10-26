# 交付报告：mosdns v5.1.3 → Rust 重写（2026-10-19）

## 结果概览

| 项目 | 值 |
|---|---|
| 参考实现 | <target-host> 上 `mosdns v5.1.3-0-gac99eb1`，配置 `/etc/mosdns/config.yaml`（pid 3727980，**全程未改动、未重启**） |
| 重写产物 | `mosdns-rs`，4,643,368 字节，ELF aarch64，md5 `007bc6091cccc34136c598e08fb606a0`（含 mmdb、线程池+弹性溢出、连接复用、DoT/DoH/DoH3/DoQ 上游、v5.3.4 的 forward 语义、netlink ipset、debug 决策轨迹） |
| 构建机 | <build-host>（x86_64 Debian 12，rustc 1.95.0，`aarch64-unknown-linux-gnu` 交叉） |
| 部署位置 | <target-host>: `/root/mosdns-rs/mosdns-rs`，源码 `/root/mosdns-rs`（构建机源码 `<build-dir>`）；运行配置 `/root/mosdns-rs/config.yaml` |
| 上线状态 | **2026-10-20 09:15 起接管生产 :53**（systemd `mosdns-rs.service`）；Go 版二进制保留，可一键回滚 |
| 依赖 | 仅 `regex`（编译期）；运行期无外部 crate、无动态库依赖 |

## 行为一致性验证（同一台机、同一份配置、loopback 客户端）

全部 13 类路径逐条对比 `dig`：只比较 status 与答案集合（忽略 TTL 与记录顺序，这两者受上游轮询与缓存年龄影响）。

| 路径 | 用例 | 结果 |
|---|---|---|
| hosts 内置条目 | `host.lan` | 双方 `NOERROR A <host-ip>` TTL 10 ✅ |
| hosts 文件 | `router.lan` | 双方 `NOERROR A <host-ip>` ✅ |
| redirect | `www.cnbeta.com` | 双方 `CNAME www.cnbeta.com.cdn.cloudflare.net.` TTL 1 + 后续 A 记录 ✅ |
| reject 3（NXDOMAIN） | `ads.raidrive.com`、`mcdn.bilivideo.cn` | 双方 `NXDOMAIN` ✅ |
| regexp 拒绝规则 | `x.pcdn.biliapi.net` | 双方 `NXDOMAIN` ✅ |
| qtype 12/65 → reject 0 | `1.1.1.1.in-addr.arpa PTR`、`www.taobao.com HTTPS` | 双方 `NOERROR` 空答（带 FakeSOA）✅ |
| direct-list → 本地 DNS | `qq.com`、`www.baidu.com` | 答案集合一致 ✅ |
| proxy-list → 远程 DNS + ipset + ttl 钳制 | `proxmox.com`、`cnbeta.com.tw`、`www.google.com` | 答案集合一致；TTL 均落在 [300,3600] 且缓存递减一致（同刻观察到两端都是 193）✅ |
| myproxy-list → 远程 DNS | `github.do`、`proxmox.com` | 双方 NXDOMAIN / 正常答案一致 ✅ |
| unknown_seq（非 CN → drop_resp → 远程） | `example.com`、`one.one.one.one`、`registry.npmjs.org`、`raw.githubusercontent.com`、`pypi.org`… | 28 个域名批量对比，rcode 与答案集合全部一致 ✅ |
| prefer_ipv4（AAAA） | `www.baidu.com`、`www.google.com`、`github.com`、`www.bilibili.com` AAAA | 双方均回 `NOERROR` 空答（A 参考命中即阻断）✅ |
| jump + client_ip + black_hole | 临时副本配置把 `client_ip` 改成 127.0.0.1，跑 :5354 | `app-znds.dangbei.wasu.tv`、`update.biv.sony.tv` → `A 0.0.0.0` TTL 300；同链后续节点（`ads.raidrive.com` NXDOMAIN、`www.baidu.com` 正常解析）证明 jump 会回到外层链 ✅（测试后实例已清） |

其它验证：

- **缓存**：同域名连查三次 0 msec，TTL 207→204→… 逐秒递减；`lazy_cache_ttl: 86400` 生效。
- **TCP 服务**：`dig +tcp -p 5353` 正常（`flags: qr rd ra ad`）。
- **外部可达**：`dig @<target-host> -p 5353` 正常（监听 0.0.0.0）。
- **ipset**：`gfwlist` 条目数 201 → 244，无 ERROR 日志，说明 `ipset add … -exist` 路径生效。
- **压力**：100 次混合查询 ok=100 / fail=0；RSS 稳定在 ~5 MB，无 panic、无内存增长。
- 原版 mosdns 全程 `ELAPSED 02:08` 未变（未被 kill、未被抢占端口）。

## 追加能力：ip_set 直接加载 mmdb（第二轮）

原版 mosdns v5 **不支持 mmdb**（源码里没有任何 mmdb 引用），所以旧做法是把 `Country.mmdb` 转成 `geoip-only-cn.txt`。
现在 `ip_set.files` 可直接写 **本地 mmdb 文件路径**（按内容识别，不看扩展名）。**不支持 URL**（按需求移除）。

| 验证项 | 结果 |
|---|---|
| 用 `/etc/mosdns/Country-lite.mmdb`（旧库 build 1788116813）dump IPv4 | **7274 条**，与现网 `geoip-only-cn.txt` 逐条 diff **0 行差异** |
| 用新库 `/etc/mosdns/Country.mmdb`（build 1792358033）dump | **7455 条 IPv4 + 18050 条 IPv6**（树里 32960 条原始网段，v4 在 `::/96` 与 `::ffff:0:0/96` 各存一份，去重后 7455） |
| 启动加载（本地库作为唯一 CN 源，txt 已从该配置删掉） | `networks=32960 -> v4=14910 v6=18050 (unique v4=7455 v6=18050) filtered_out=0`，`local_ip` 共 25518 条（压缩后） |
| URL 输入 | 直接报错 `URL is not supported ...`，不影响启动其他部分 |
| 行为回归 | 28 域名批量对比 `:53` vs `:5353`，rcode/答案集合一致 |

运行配置 `/root/mosdns-rs/config.yaml` 与生产 `/etc/mosdns/config.yaml` **只差一行**（`local_ip.files` 的 txt → `/etc/mosdns/Country.mmdb`）。
生产配置文件一个字没改——原版 mosdns 一旦重启会把 mmdb 当文本读而启动失败，切到 mosdns-rs 之前不要写进生产配置。

## 性能（第三轮，详见 BENCH.md）

同机（4 核 ARMv8）同配置，Go 用第二个进程跑在 :5354（不动生产 :53），两轮 A/B：

| 场景 | mosdns (Go) | mosdns-rs (Rust) |
|---|---|---|
| 本地作答打满 | 6.6–6.9k qps / 331 µs 每查询 / p50 2.3 ms | **19.1–19.4k qps / 105 µs / p50 0.72 ms** |
| 缓存命中打满 | 5.6–5.7k qps / 443 µs / p50 2.65 ms | **11.6–14.3k qps / 170 µs / p50 0.9 ms** |
| 稳态 2000 qps | 1.2 核 / p99 3.7 ms | **0.5 核 / p99 1.7 ms** |
| 回源（唯一域名） | 4.2–4.6 ms 每查询 / p50 75 ms | 3.8–3.9 ms / p50 78 ms（受上游 RTT 支配） |
| 空闲 RSS / 峰值 RSS / VSZ | 19.2 / 20.7 / 727 MB | **16.5 / 18.3 / 525 MB** |
| 二进制 | 15.1 MB | **2.1 MB** |

期间修掉的三个真问题：「每包一线程」导致单查询 625 µs、吞吐只有 3.9k qps（改 16 线程分片队列后 19k qps）；
上游 TCP 每查询新建连接（改 idle 复用后回源路径 5.7 ms → 3.8 ms CPU/查询）；
固定线程池的队头阻塞（64 个并发回源时本地 p99 24 ms → 2.0 ms，靠 worker 卡顿探测 + 一次性溢出线程）。

## 四、切换前对 Go 版线上日志的审查（2026-10-20）

日志范围 2026-10-13 21:46 → 2026-10-20 09:06，共 30,840 行（30,489 WARN / 351 INFO）。

**结论：没有发现 Go 版的逻辑 BUG。** 所有告警都能归因到「上游网络问题」或「客户端主动放弃」：

| 告警 | 条数 | 归因 |
|---|---|---|
| `forward_local / forward_remote: upstream error` | 19,883 / 7,660 | 上游 EOF、超时、connection reset、8.8.8.8/1.1.1.1:53 被拒 —— 网络侧问题；`concurrent: 2` 时通常另一个上游仍能作答，用户无感 |
| `fallback: primary/secondary error` | 1,448 / 483 | **全部是旧配置时期**（旧配置挂了 doh.pub/dot.pub 并启用了 fallback）；当前配置的 `main_sequence` 并不引用 fallback |
| `udp_server/tcp_server: entry err` | 673 / 34 | `context canceled` —— 客户端在查询完成前关闭了 TCP 连接，属于正常现象 |
| `cache: failed to update lazy cache` | 200 | 惰性回源时上游失败，属预期 |
| `main_sequence.r5: reference query routine err` | 26 | `prefer_ipv4` 的参考分支查询失败，只影响「是否屏蔽 AAAA」的判定 |
| `udp_server: invalid msg` | 13 | 收到非 QUERY opcode 的垃圾包（解码出来是 opcode=4 的随机载荷），疑为探测/串流误投，非程序缺陷 |
| `signal received terminated` | 12 | 有人手工重启进程（包括 10-19 17:25 改配置那次） |

两个值得记录的**运行层面**问题（不是代码 BUG）：

1. **旧配置的 DoH 上游被 429 打爆**：`bad http status codes 429` 出现 **14,642 次**，仅 10-14 一天就 14,008 次
   （`doh.pub` 限流）。这解释了为什么后来把 DoH/DoT 注释掉、换回 `udp://119.29.29.29 + tcp://223.5.5.5`。
2. **失败域名高度集中**：`126.com`(899)、`00006803.com`(794)、`163.com`(442)、`www.baidu.com`(267)。
   前三个都在 `!qname` 免缓存名单里（每条查询都必须回源），上游一抖就成片报错。
   当前配置期（10-19 17:25 起）只剩 314+53 条上游告警，其中「所有上游都失败」只有 **5 次**（约 0.0007%）。

## 五、切换上线（2026-10-20 09:15）

| 项 | 做法 |
|---|---|
| 配置 | **沿用 `/etc/mosdns/config.yaml` 原文件**，只把 `log.level` 改成 `debug`（原文件备份 `config.yaml.bak-20261020091437`） |
| 二进制 | 装到 `/usr/local/bin/mosdns-rs`（`/usr/local/bin/mosdns` 原样保留，用于回滚） |
| 拉起方式 | 新增 systemd 单元 `mosdns-rs.service`（`enabled`，`Restart=always`，`RestartSec=5`）—— 原 Go 进程是无守护地裸跑，崩了没人拉 |
| 日志 | 继续写 `/var/log/mosdns.log`（追加），切换前的历史另存 `/var/log/mosdns-go-20261020.log`；内置轮转 32 MB × 5 |
| 回滚 | `/root/mosdns-rs/rollback-to-go.sh`（停/禁用服务 + 拉起 Go 版 + dig 验证） |

切换后验证（同机 + 跨机）：`www.baidu.com`(3 条 A)、`router.lan`、`host.lan`、`ads.raidrive.com`(NXDOMAIN)、
`www.google.com`(8 条 A)、`www.bilibili.com` AAAA(空)、`www.taobao.com` HTTPS(空)、`PTR`(空)、
`www.cnbeta.com`(CNAME 重定向) 全部符合预期；UDP/TCP 双通；跨机（<build-host> → <target-host>:53）6 种查询正常。
启动 1 分钟内 `NRestarts=0`，RSS 7.4 MB，实测 ~2.5 qps。

debug 日志已经能看到完整决策链，例如：
```
q id=41 udp client=127.0.0.1 qname=www.cnbeta.com.cdn.cloudflare.net. type=1 rcode=0 ans=3 ms=301.51
  path=redirect->www.cnbeta.com.cdn.cloudflare.net.>cache_miss>fwd[udp://119.29.29.29:53]>drop_resp>fwd[tcp://1.1.1.1:53]
```

## 六、对齐上游 v5.3.4 的四项改进 + DoQ（2026-10-20 09:53 上线）

| 项 | 内容 | 验证 |
|---|---|---|
| A | forward：坏 rcode（非 NOERROR/NXDOMAIN）继续等下一个上游 | 用「只回 SERVFAIL 的假上游 + 223.5.5.5」测试：10 次查询全部 NOERROR，日志出现 `upstream udp://127.0.0.1:5355 returned rcode 2 for www.youtube.com., waiting next upstream` |
| B | forward：随机起点选上游（不再永远先打列表第一个） | 代码审查；与 A 同一路径 |
| C | forward：UDP 上游 1 秒无应答自动重发（同 ID） | 代码审查（5s 总超时内重发） |
| D | prefer_ipv4：双栈探测结果缓存 1 小时 | 同一域名连续两次 AAAA：`prefer_v4(block)` → `prefer_v4(block,cached)`（0.03ms，无上游查询） |
| DoQ | `quic://` 上游（RFC 9250，ALPN doq，ID 置 0，2 字节长度分帧，连接复用） | 实测 Quad9 / AdGuard：`fwd[quic://dns.quad9.net:853]` 正常返回，首次 715ms（含握手）→ 后续 170–205ms（复用连接）；主机名懒解析生效 |

**DoQ 延迟实测**（本机，6 个不同域名，单上游无缓存）：

| 上游 | 首查（含主机名解析+握手） | 后续（连接复用） |
|---|---|---|
| 阿里 `quic://dns.alidns.com:853`（解析到 223.5.5.5） | 47.3 ms | 14.1 / 8.4 / 8.8 / 19.7 / 6.8 ms |
| 对照 `udp://223.5.5.5` | 38.6 ms | 38.4 / 2.8 / 3.0 / **1021.7**（上游抖动）/ 5.0 ms |
| 对照 `tcp://223.5.5.5` | 11.0 ms | 12.0 / 6.5 / 16.0 / 5.6 / 14.5 ms |
| 腾讯 `quic://dot.pub:853` | **5035 ms 超时**（`doq handshake timeout 120.53.53.53:853`） | 全部失败 |
| 腾讯 `quic://doh.pub:853` | **5015 ms 超时** | 全部失败 |

结论：**腾讯公共 DNS 不支持 DoQ**（853/UDP 无 QUIC 服务，只提供 doh.pub/dot.pub）；阿里可用，
首次多 ~10 ms 握手开销，复用后与 TCP 相当、略慢于纯 UDP；UDP 那次 1021 ms 抖动正好体现了 C（1 s 重发）的价值。

代价与注意：

- 引入 `quinn`/`rustls`/`webpki-roots`/`tokio`，二进制 2.29 MB → **3.95 MB**；不用 DoQ 时不建 runtime，RSS 无变化（实测 9.9 MB）。
- 交叉编译需要 `CC_aarch64_unknown_linux_gnu` / `AR_aarch64_unknown_linux_gnu`（ring 的 C 后端）。
- 未实现 `insecure_skip_verify` / `bootstrap` / QUIC server（入站 DoQ）；证书校验用内置 webpki 根。

## 七、E 项：cache 命中的 IP 乱序已删除（2026-10-20 10:04）

按 v5.2.0 的变更（`cache: don't shuffle ip records`）删掉了 `shuffle_tail_ip`：
缓存命中时直接返回存储的顺序，不再做一次 RNG + 数组交换。功能无差异，与官方最新行为一致。

## 八、ipset 改走 netlink（2026-10-20 10:19）

原实现用 `ipset add -exist` 外部命令，每次 fork+exec。实测这套 A53 上 **6.1 ms/条**，
一条 8 条 A 记录的响应要 49 ms，确实不如原版（Go 用 `vishvananda/netlink` 直接发 netlink）。

现在改成手写 netlink（`src/ipset.rs`，零依赖），对照内核 UAPI 和 ripset 实现逐字段核对：

- 消息：`type=(6<<8)|9`、`nfgenmsg{family=AF_INET/AF_INET6, version=0, res_id=0}`；
- 属性：`PROTOCOL(1)=7` → `SETNAME(2)` → `DATA(7,nested){ IP(1,nested){ IPADDR_IPV4/6 | NLA_F_NET_BYTEORDER }, CIDR(3), LINENO(9)=0 }`；
- `-exist` 语义用「内核返回 `IPSET_ERR_EXIST`(-4103) 视为成功」，避免猜 flag 位置；
- netlink 失败自动回退外部命令并只警告一次。

踩的坑：第一版漏了 `NLA_F_NET_BYTEORDER`（0x4000）和 `IPSET_ATTR_LINENO`，内核直接回
`IPSET_ERR_PROTOCOL`(4097)。

| 方式 | 单条耗时 | 8 条响应 |
|---|---|---|
| 外部命令 | 6.1 ms | 49 ms |
| netlink | **32.3 µs** | 0.26 ms |

同时修掉一个日志 bug：`ipset(n)` 的 trace 埋点之前因为字符串不匹配没生效（所以早先统计出"0 次触发"是错的）。
现在线上能直接看到：`path=cache_miss>fwd[tcp://1.1.1.1:53]>goto:gfwlist-sequence>ttl>ipset(1)`。

## 九、补齐 DoT / DoH（2026-10-20 10:57）

原版 v5.1.3 有 `tls://` / `https://`，我们之前只做了 udp/tcp/quic。先核对了 v5.3.4 与 v5.1.3 的差异：

- **协议本身没变**：DoT 仍是 TCP+TLS+2 字节分帧；DoH 仍是 HTTP/2 POST `application/dns-message`。
- v5.3.4 的改动集中在连接管理：`bootstrap` 对所有协议生效（v5.1.3 只对 DoH/DoQ）、pipeline 连接泄漏修复（v5.3.1）、
  HTTP/2 的 `MaxHeaderListSize=4K` / `MaxReadFrameSize=16K`、DoH3 改用 `http3.Transport`。
- 所以按协议实现 + 参考最新版参数即可，没有需要"照搬新语义"的地方。

实现：

| 项 | 做法 |
|---|---|
| DoT | `rustls::StreamOwned<ClientConnection, TcpStream>`，阻塞模型，连接池 55s，2 字节长度分帧，响应 ID 校验（丢弃迟到响应） |
| DoH | `h2` 客户端，一条连接多路复用，`POST application/dns-message`，失败重连一次 |
| bootstrap | `src/resolve.rs`：向指定 DNS 服务器发纯 UDP A 查询（避免冷启动时本机就是唯一 DNS），结果缓存 1h；DoT/DoH 都生效 |
| SNI | `server_name` 可覆盖；默认取 addr 里的主机名 |

实测（3 个不同域名、单上游、无缓存）：

| 上游 | 首查 | 后续 |
|---|---|---|
| `tls://dns.alidns.com` | 73.6–171.6 ms | 17.2–61.5 ms |
| `tls://dot.pub` | 297.9–350.5 ms | 139.7–696.8 ms（服务器不回 keep-alive，每查重连） |
| `https://dns.alidns.com/dns-query` | 96.5–320.4 ms | 15.4–84.5 ms |
| `https://doh.pub/dns-query` | 170.9 ms | 42.7–49.5 ms |

代价：新增 `h2`/`http`/`bytes`/`tokio-rustls` 依赖，二进制 3.95 MB → 4.40 MB；不用这些上游时不建立连接，RSS 无变化（10.0 MB）。

顺带把过时的报错文案改了：现在是 `unsupported upstream scheme [x] (supported: udp / tcp / tls / https / quic)`。

`bootstrap` 验证：`tls://dot.pub` + `bootstrap: "119.29.29.29"`，日志可见
`dot resolved dot.pub -> 1.12.12.12:853`（由 119.29 解析得到），随后查询正常返回。

## 十、补齐 DoH3（2026-10-20 11:16）

官方语义：`h3://host/path` == `https://host/path` + `enable_http3: true`（`NewUpstream` 里的 helper protocol）。
两种写法都实现了。

实现：`src/doh3.rs`，`h3` 0.0.8 + `h3-quinn` 0.0.10（对应 quinn 0.11），QUIC ALPN `h3`，POST `application/dns-message`，
一条 QUIC 连接复用，失败重连一次。

踩坑：

- `h3-quinn 0.0.7` 依赖的 quinn 版本里 `StreamId.0` 还是 public，和 quinn 0.11.19 不兼容（编译报 private field），
  必须升到 `h3 0.0.8` + `h3-quinn 0.0.10`。
- `h3::client::SendRequest` 的泛型是 `<连接类型, Buf 类型>`，实际是 `SendRequest<h3_quinn::OpenStreams, Bytes>`。
- 顺手修了超时语义：原来"复用失败→新建重连"两次尝试各用满 timeout，失败要等 10s；现在共享一个 deadline，5s 结束。

实测（3 个域名、单上游）：

| 上游 | 首查 | 后续 |
|---|---|---|
| `h3://dns.alidns.com/dns-query` | 541.6 ms（含 QUIC 握手） | 24.1–67.6 ms |
| `h3://doh.pub/dns-query` | 5s 握手超时 | — |
| `h3://cloudflare-dns.com/dns-query` | 5s 握手超时 | — |

腾讯和 Cloudflare 都是**握手超时**——本机到它们的 UDP/443 出不去（阿里 DoQ/DoH3 都通，说明实现没问题）。
二进制 4.40 MB → **4.64 MB**（+237 KB）。

## 十一、借鉴 smartdns 的重试与 IPv6 策略（2026-10-20 11:42）

对照 smartdns 源码（`src/dns_client`）后做了四件事：

| 改动 | 之前 | 现在 |
|---|---|---|
| 重试方式 | 单次 5s 等待；UDP 每 1s 重发 | **500ms 一轮、最多 4 轮**（≈2s），之后继续等已派发响应到 5s |
| 上游健康 | 无 | **连续失败 2 次 → 禁用 60s**，期间跳过并记 debug 日志，到期自动恢复 |
| 并发上限 | 3（官方值） | **5**（用户要求）；实际派发 = min(concurrent, 5, 上游数) |
| UDP 死上游检测 | `send_to/recv_from`，收不到 ICMP，要等满 5s | 先 `connect()`，端口不可达立刻 `ECONNREFUSED`，**毫秒级判死** |

新增 `only_ipv4`：AAAA 一律 NODATA（NOERROR + 空 answer + SOA，TTL 30，
`a.gtld-servers.net / nstld.verisign-grs.com`），**不查上游**，`ms≈0.01`，日志 `path=ipv4_only(soa)`。
这是照搬 smartdns 的 `force-AAAA-SOA`（用 NOERROR 而非 NXDOMAIN，避免客户端缓存"域名不存在"）。

验证：

- ipv4_only：`dig AAAA` 得到 `status: NOERROR / ANSWER: 0 / AUTHORITY: 1 SOA (TTL 30)`，A 查询正常。
- 健康标记：`udp://127.0.0.1:59999`（死端口）+ `udp://223.5.5.5`，2 次失败后日志出现
  `连续失败 2 次，暂停使用 60s`，后续查询出现 `处于禁用期，本次查询跳过`，业务查询始终由好上游在 3–60ms 内答复。
- 生产回归：部署后 A/AAAA/hosts/reject 全部正常，26525 次查询 0 SERVFAIL 0 err。

顺带发现一个真问题：健康记账最初写在"结果消费端"，导致**竞速失败的上游永远不会被记账**（它的结果没人取）；
已移到查询线程内部，成功/失败都在产生结果的地方结算。

## 十二、`only_ipv4` 更名 + `insecure_skip_verify`（2026-10-20 11:52）

- 屏蔽 IPv6 的写法从 `prefer_ipv4 ipv4_only` 改成独立动作 **`exec: only_ipv4`**（`type: only_ipv4` 也行）；
  `prefer_ipv4` 回归"只做双栈探测、不接受参数"，传参数会报错并提示改用 `only_ipv4`。日志标记 `path=only_ipv4(soa)`。
- 上游新增 **`insecure_skip_verify`**（DoT / DoH / DoH3 / DoQ 都生效）：用 rustls 的
  `ServerCertVerifier` 自定义实现跳过证书链与主机名校验，TLS 签名仍按算法校验；配置时打 WARN 提醒。

验证（同一台服务器 `tls://223.5.5.5:853`，故意给错 SNI）：

| 配置 | 结果 |
|---|---|
| `server_name: wrong.example.com`（默认校验） | `dot handshake ...: invalid peer certificate: certificate not valid for name` → 拒绝 |
| 同上 + `insecure_skip_verify: true` | 握手成功（服务端按应用层回 REFUSED，说明 TLS 已通） |
| `server_name: dns.alidns.com` + `insecure_skip_verify: true` | `rcode=0 ans=3 ms=75.08 path=fwd[tls://223.5.5.5:853]` 正常解析 |

生产回归：27490 次查询 0 SERVFAIL 0 err，A/hosts/reject 全部正常。

## 十三、`idle_timeout` 对齐（2026-10-20 12:11）

每个上游新增 `idle_timeout: <秒>`，语义与 mosdns 一致（缺省用协议默认）：

| 协议 | 默认 | 行为 |
|---|---|---|
| tcp / tls | **10 s**（mosdns `defaultIdleTimeout`） | 池中连接空闲超过该值，下次取用时丢弃重建 |
| https / h3 | **30 s**（mosdns DoH `idleConnTimeout`） | h2/h3 客户端空闲超时后重新建连 |
| quic | **30 s** | 写进 QUIC `max_idle_timeout` |

之前是写死的 55 s（TCP/DoT），DoH 完全没有空闲回收。改动后统一由 UpOpts 传递，
CPU 紧张时可通过调小减少长连接占用。

验证（同一上游，查询间隔 3 s）：

```
idle_timeout: 1   → DEBUG tcp 池中连接空闲 3.084020391s ≥ idle_timeout 1s，丢弃重建（1 次）
idle_timeout: 10  → 0 次（连接照常复用）
```

## 十四、DoQ 补上 `bootstrap`（2026-10-20 12:38）

用户给 `quic://dns.alidns.com:853` 配 `bootstrap` 时发现：之前只给 DoT/DoH 接了 bootstrap，
**DoQ 走的是系统 resolver**，配置里的 bootstrap 被忽略。现已统一到 `resolve::resolve()`。

验证（同一 DoQ 上游）：

| bootstrap | 结果 |
|---|---|
| `223.5.5.5` | `doq resolved dns.alidns.com -> 223.5.5.5:853`，`rcode=0 ms=84.68` |
| `127.0.0.1:59999`（死地址） | 解析失败 → 5s 超时 → 该上游被禁用 60s（证明 bootstrap 真的生效） |

顺带把"全部上游超时且无任何错误信息"时的报错从 `all upstreams failed: []` 改成
`all upstreams failed: no result within 5s`。

另外确认了缩进问题：`bootstrap` 若与 `- addr` 同级顶格，配置会把 plugins 结构打断，
进程直接 `ERROR no server configured` 退出（是硬失败，不会静默忽略）。

## 十五、生产日志审计（2026-10-20 13:38，覆盖 09:34–13:38 / 48,388 次查询）

结论：**没有崩溃、没有内存泄漏迹象、`err` 全为空**；发现 1 个性能缺陷 + 1 个运维风险，均已修/已加护栏。

| 指标 | 值 |
|---|---|
| rcode | NOERROR 48,263 / NXDOMAIN 121 / **SERVFAIL 4** |
| `err` 非空 | **0** |
| 耗时 | p50 0.16 ms、p90 6.63、p95 37.7、p99 121.8、**max 10,000.59** |
| qtype | A 42,672 / **HTTPS 4,494（被 reject 0 挡掉）** / AAAA 1,086 / PTR 58 |
| 路径 | cache_hit 17,772 + cache_lazy 15,984（70%）、cache_miss 7,772、reject(0) 4,552、only_ipv4(soa) 531 |
| 上游胜出 | 119.29.29.29 6,984 / 223.5.5.5 1,372 / 1.1.1.1 1,160 / 8.8.8.8 573 / **DoQ 290** |
| 运维事件 | 连接丢弃重建 801、上游禁用 1（119.29 于 13:32 抖动）、ERROR 5、回退外部命令 0 |

**缺陷①：单条查询最坏 10 s。** 4 条 SERVFAIL 都是同一个域名（`*.xs.alibabachengdun.com`），路径是
`cache_miss > fwd[223.5.5.5] > drop_resp > fwd[8.8.8.8]` —— 链里有两个 forward，各自算 5 s 预算，合计 10 s，
而客户端 5 s 就放弃了。修法：`Forward::exec` 的预算改为 `min(5s, ctx.deadline - now)`，
整条查询被 QCtx 的 5 s 截止时间兜住。

**风险②：配置写错 → DNS 直接中断。** 11:46 把 `only_ipv4` 写成 `ipv4_only`，进程启动即退出，
systemd 每 5 s 重试，连续 7 次、中断约 27 s。新增 `--check`：只加载配置并构建插件链、不监听，
返回 0/1。改配置的标准流程变成 `mosdns-rs --check -c ... && systemctl restart mosdns-rs`。

**发现③（运维，非代码）：日志被清空过。** `/var/log/mosdns.log` 的 birth 是 09:34:36（说明 09:34 发生过一次
正常轮转），但 `.1` 文件不存在，且 Go 期归档 `/var/log/mosdns-go-20261020.log` 变成 0 字节 ——
**09:15–09:34 的日志和整个 Go 期历史都没了**。轮转逻辑本身在受控测试里是正常的（`rot.log.1..5` 齐全），
所以更像是外部清理（含 glob 的 rm）导致，需要留意。

观察项（不算 bug，供决策）：

- DoQ 上游只赢了 290 次：`concurrent: 3` 时 UDP 的 119.29 几乎总是先回，DoQ 等于每查多打一份流量；
  想省流量把 `forward_local` 的 `concurrent` 降到 2。
- 801 次 TCP 连接因 `idle_timeout 10s` 被丢弃重建（与 mosdns 默认一致）；若在意握手开销可设 `idle_timeout: 30`。
- 同一 qname 的重复 `cache_miss`（`dns.alidns.com` 35 次、`www.baidu.com` 29 次）—— 没有 singleflight，
  并发相同查询各自回源，这一点与 mosdns 行为一致，未改。

## 十六、另一台机器 Go 版日志审计（2026-10-20 13:50）

样本：`/tmp/mosdns.log`（另一台机器的 Go 版，10-15 16:19 → 10-20 10:20，63,742 行 / 63,622 WARN）。

**没有 panic / OOM / runtime error**，只有 3 次 signal terminated。问题全部集中在「上游全挂时的行为」：

| 现象 | 数据 |
|---|---|
| 一次出口链路整体中断（10-17 09:00–13:30） | 单小时 17,683 条告警；4 个上游同时超时（119.29 3186 / 223.5.5.5 3144 / 8.8.8.8 2383 / 1.1.1.1 2211） |
| `context deadline exceeded` | 56,260 次 |
| **单查询耗时** | p50 **5.00s**、p95 **139.34s**、p99 **141.60s**、**max 160.74s** |
| 超过 100 s 的查询 | **930 条**（`elapsed: 2m40.714871741s`，客户端早已放弃） |
| 主备都失败 → SERVFAIL | 258 次 `no valid response from both primary and secondary` |
| 惰性缓存更新失败 | 588 次 |
| 死上游不被跳过 | 119.29 在 60 s 内**连续失败 2188 次**、8.8.8.8 1353 次（Go 无健康标记，每查照打） |

另有 6 个被拼坏的 qname（`router.example.com.168.2.1.` 等，共约 300 条，全部来自同一客户端），
后缀统一是 `.168.2.1` —— 不像 mosdns 改名（只有 redirect 会改名），更像那台设备的 DNS search domain 配成了 `168.2.1`。

**对照结论：这些量级的问题在我们这里不会出现。**

| 项 | Go 版 | rs 版 |
|---|---|---|
| 上游全挂时单查询 | max 160.7 s、930 条 >100 s | **硬上限 5 s**（实测 `ms=5000.87`，dig 报 5004 ms） |
| fallback / 二次 forward 叠加 | 5 s → 10 s+ | 预算 = `min(5s, ctx.deadline-now)`，第二段无预算即放弃 |
| 死上游 | 每查都打（2188 次/60 s） | 连续 2 次失败禁用 60 s（部分故障时生效） |
| 长连接阻塞 | 出现分钟级 | TCP/DoT 显式设 read+write timeout；DoH/H3/DoQ 全走 tokio timeout |
| lazy 刷新失败可见性 | WARN 记录 | 之前吞掉，本版补了 debug：`cache failed to update lazy cache for <qname>: <err>` |

诚实补充：**"全部上游都挂"时我们同样要等 5 s**（没有可用上游是物理限制），但不会退化成百秒级，
也不会因为 fallback 串行而翻倍。

## 十七、全上游故障时快速失败 + 半开探测（2026-10-20 13:58）

smartdns 在这个场景的账（源码 `src/dns_client`）：

- `DNS_QUERY_TIMEOUT=500ms`、`DNS_QUERY_RETRY=4` → 首次最多 **2 s**（4 轮 × 500 ms，第 4 次超时即放弃）。
- 但 `prohibit` 只由**发送/连接失败**触发（`client_udp.c` / `client_tcp.c` / `tls` / `http2/3` 各自的 connect/send 失败路径），
  **超时无应答不算**。一旦被 prohibit（60 s），`_dns_client_send_packet` 里 `send_count==0` 会**立即返回失败**，
  并且每 60 s 才探测一次。
- 所以：上游"不回包"→ 每条 **2 s**；上游"发不出去"（断网）→ 首次 2 s，之后 **即时失败**，空窗最长 60 s。

我们的取舍（已上线）：

| 场景 | 改前 | 改后 |
|---|---|---|
| 上游不回包 | 每条查询都等 5 s | 首次 5 s，之后 **立即失败**（实测 76–86 ms） |
| 恢复后第一次成功 | 立即（因为每条都在试） | **≤ 5 s**（半开探测间隔） |
| 探测间隔 | 无 | 5 s（smartdns 是 60 s） |

实测（上游只收不回）：

```
#1 5090ms SERVFAIL   ← 首次等满超时，累计 2 次失败后禁用
#2 80ms / #3 76ms / #4 79ms / #5 86ms / #6 79ms / #7 78ms   ← 全部立即失败
WARN upstream udp://127.0.0.1:5399 连续失败 2 次，暂停使用 60s（每 5s 探测一次）
WARN 所有上游均处于禁用期（未到探测时间），查询立即失败        （120 s 限频一条）
```

实现要点：`Health::acquire(now)` 做半开判定（禁用期内每 `PROBE_INTERVAL_MS=5s` 放行一次并推后时间戳）；
候选为空则直接返回错误，不再派发。恢复后 `on_success` 清空禁用与探测时间。

## 十八、日志补强：C（字段）+ B（失败落盘）（2026-10-21 09:30）

C：单行日志在 `path` 前插入 4 个字段 `ttl= rb= tries= edns=`，仍然只在 debug 下拼串：
`ttl` = 答案最小 TTL；`rb` = 实际发出的响应字节（UDP 截断后）；`tries` = forward 派发轮数；
`edns` = 0 无 EDNS0 / 1 有 / 2 带 DO。

B：新增 `src/faildump.rs`，debug 下若 `err` 非空 / rcode=SERVFAIL / 耗时 ≥ 2s，落一个样本文件：
元信息 + 每轮上游尝试（`up err @501ms: ...`）+ 原始查询报文 hex。默认目录 `<日志目录>/mosdns-fail`，
带三道闸（`fail_per_min=20`、`fail_keep_days=3`、`fail_max_mb=200`，超限从最旧删）。

实现细节：`QCtx` 增加 `tries`（u8）与 `attempts`（Vec<String>，仅 debug 填充）；
`Forward::exchange` 改为写入 `ForwardInfo{winner,waves,attempts}`，`exec` 再把结果记到 ctx。

实测（独立实例）：
- 正常：`ms=2.88 ttl=244 rb=90 tries=1 edns=1 path=fwd[udp://223.5.5.5:53]`
- 死上游：`ms=5000.26 rcode=2 tries=4`，落盘文件 941 B，attempts 依次 `@1ms/@501ms/@1001ms/@1502ms`，
  hex 还原后是完整查询报文。
- 修掉一个自身 bug：最初 ttl/rb 取 `ctx.r`，但 UDP/TCP 在打日志前已 `ctx.r.take()`，导致恒为 0；
  改为把 `&resp` 与已打包长度直接传给 `log_query`。

## 与 Go 原版的已知差异（均不影响当前配置行为）

1. `ipset` 通过调用系统 `ipset` 命令写内核集合，原版用 netlink。集合内容等价，但每次 add 多一次 fork（仅在需要入集合的响应上发生）。
2. 未实现 DoH(`https://`)/DoT(`tls://`)/`api` 指标端点/cache dump 文件（配置里都注释掉了；启动时若出现会告警跳过）。
3. 正则用 Rust `regex`（RE2 语法族），Go 的 `regexp` 同为 RE2，当前 3 条 `regexp:` 规则语义一致。
4. 报文重打包不做逐字节保持（原版 cache 命中也是重新 pack）；字段语义相同，UDP 仍按客户端 EDNS 尺寸截断并置 TC。

## 复现命令

```sh
# 构建（<build-host>）
export PATH=/root/.cargo/bin:$PATH CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
cd <build-dir> && cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.17

# 部署 + 启动（<target-host>）
scp target/aarch64-unknown-linux-gnu/release/mosdns-rs root@<target-host>:/root/mosdns-rs/
ssh root@<target-host> '/root/mosdns-rs/mosdns-rs -c /etc/mosdns/config.yaml -p 5353 --log-file /var/log/mosdns-rs.log'

# 对比
dig @127.0.0.1 -p 53   www.google.com A
dig @127.0.0.1 -p 5353 www.google.com A
```
