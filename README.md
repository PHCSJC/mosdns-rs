# mosdns-rs

**mosdns v5 的 Rust 重写实现** —— 单二进制、无运行时依赖的 DNS 转发 / 分流器。
配置与插件语义沿用 [mosdns](https://github.com/IrineSistiana/mosdns) v5，行为对齐到上游 **v5.3.4**
（含 v5.2/v5.3 期间修正的 forward 语义、坏 rcode 重试、DoH3 等）。

```
config.yaml (mosdns v5 格式) ──► mosdns-rs ──► udp / tcp / tls / https / h3 / quic 上游
                                    │
                                    └─► cache / hosts / redirect / ipset(netlink) / 分流策略
```

## 特性

- **单文件可执行**：x86-64 约 4.6 MB，aarch64 约 3.9 MB，无 Go 运行时、无 cgo
- **六种上游协议**：`udp` `tcp` `tls`(DoT) `https`(DoH/HTTP2) `h3`(DoH3) `quic`(DoQ)
- **每查询一行决策日志**：`path=cache_hit>fwd[quic://…]>goto:tag>ttl>ipset(2)`，排障不用猜
- **ipset 走 netlink**：直接构造 `NFNL_SUBSYS_IPSET` 消息，不 fork 外部命令（实测约 190 倍差距）
- **多地址故障切换**：上游域名有多条 A 记录时逐个尝试，某个地址连不上/反复 5xx 就自动换下一个
- **失败快速返回**：上游连接被拒或重置时立即返回，不空等满超时预算；同批上游都回坏 rcode 时提前放弃
- **配置自检**：`--check` 只构建插件链不监听端口，适合在重启前验证改动
- **低占用**：稳态 2000 qps 约 0.5 核 / 8–10 MB RSS

## 支持的上游

| 形式 | 协议 | 默认端口 | 说明 |
|---|---|---|---|
| `udp://1.1.1.1` | DNS over UDP | 53 | 同 ID 重发，死端口毫秒级判死 |
| `tcp://1.1.1.1` | DNS over TCP | 53 | 2 字节长度分帧，连接池复用 |
| `tls://dns.example.com` | DoT (RFC 7858) | 853 | 证书校验 + 会话恢复 |
| `https://dns.example.com/dns-query` | DoH (RFC 8484) | 443 | HTTP/2 多路复用 |
| `h3://dns.example.com/dns-query` | DoH3 | 443 | HTTP/3 over QUIC，等价 `https://` + `enable_http3: true` |
| `quic://dns.example.com:853` | DoQ (RFC 9250) | 853 | 单流单查询，连接复用 |

每个上游可用的选项：

| 选项 | 说明 |
|---|---|
| `bootstrap` | 解析上游主机名用的 DNS（形如 `223.5.5.5[:53]`），避免自举依赖 |
| `server_name` | `addr` 写 IP 时指定 TLS SNI |
| `enable_http3` | DoH 走 HTTP/3 |
| `insecure_skip_verify` | 跳过证书/主机名校验（自签证书场景，会打 WARN） |
| `idle_timeout` | 长连接空闲上限（秒）。TCP/DoT 默认 10s，DoH/DoH3/DoQ 默认 30s |

## 快速开始

```sh
# 需要 zig + cargo-zigbuild（用于把 glibc 依赖压到 2.17）
cargo install cargo-zigbuild
# zig: https://ziglang.org/download/ 或 pip install ziglang

# 指定链接目标 glibc 版本，产物可运行于 Debian 9+ / CentOS 7+ / Ubuntu 16.04+
export RUSTFLAGS="-C link-arg=-Wl,--build-id=sha1"
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.17
```

依赖：Rust 1.75+；发布产物要求 **glibc ≥ 2.17**，内核 ≥ 3.2。

> 为什么不用 `cargo build`：默认会用构建机的 glibc（如 Debian 12 = 2.36）链接，
> 产物会要求 `GLIBC_2.34`，在 Debian 11 及更老的系统上直接起不来。
> `cargo zigbuild --target …gnu.2.17` 只改变链接时使用的 glibc 桩，代码生成不变，性能一致。

最小可用配置：

```yaml
log:
  level: info
  file: "/var/log/mosdns.log"

plugins:
  - tag: forward_local
    type: forward
    args:
      concurrent: 2
      upstreams:
        - addr: udp://223.5.5.5
        - addr: quic://dns.alidns.com:853
          bootstrap: "223.5.5.5"

  - tag: main
    type: sequence
    args:
      - exec: $forward_local

  - tag: srv
    type: udp_server
    args:
      entry: main
      listen: :53
```

```sh
./mosdns-rs --check -c config.yaml     # 先校验，返回 0 表示可用
./mosdns-rs -c config.yaml             # 启动
dig @127.0.0.1 example.com
```

## 支持的插件

| 类别 | 已实现 |
|---|---|
| 执行器 | `sequence`、`cache`（lazy 命中 + TTL 改写）、`hosts`、`redirect`、`forward`、`fallback`、`ipset`、`ttl`、`reject`、`accept`/`goto`/`jump`/`return`、`prefer_ipv4`、`only_ipv4` |
| 匹配器 | `qname`、`qtype`、`client_ip`、`resp_ip`、`has_resp`（支持 `!` 取反与 `&文件` 形式） |
| 数据源 | `domain_set`、`ip_set`（文本 CIDR / mmdb） |
| 服务端 | `udp_server`、`tcp_server` |

`exec: only_ipv4` 用于整体禁用 IPv6：AAAA 一律返回 **NODATA**（NOERROR + 空 answer + SOA/30s），
语义与 smartdns 的 `force-AAAA-SOA` 一致 —— 客户端看到的是"该域名没有 AAAA"，不会误判成域名不存在。

## 日志

轮转参数：`max_size_mb`（单文件上限）+ `keep_files`（保留几个文件，**不是天数**）。
旧配置里的 `keep` 仍然可用，启动时会提示改名。

debug 级别下每条查询一行（含完整决策链）：

```
q id=1 udp client=192.168.1.10 qname=www.example.com. type=1 rcode=0 ans=3 ms=0.17 ttl=5 rb=90 tries=0 edns=0 path=cache_lazy err=-
```

| 字段 | 含义 |
|---|---|
| `ttl` | 答案里的最小 TTL（lazy 命中会被改写为 5） |
| `rb` | 实际发出的响应字节数（UDP 截断后） |
| `tries` | forward 派发了几轮（1 = 一次成功，>1 = 触发了 500ms 重发） |
| `edns` | `0` 无 EDNS0 / `1` 有 EDNS0 / `2` EDNS0 且带 DO 位 |

**失败样本落盘**（借鉴 smartdns 的 `debug-save-fail-packet`）。
查询最终失败、返回 SERVFAIL，或耗时 ≥ 2000 ms 时，把现场写成一个文件，包含

- 元信息：时间、客户端、qname/qtype、rcode、耗时、决策链、错误
- 每一轮上游尝试的结果与时刻（`tcp://1.1.1.1 err @501ms: ...`）
- 原始查询报文的 hex（`xxd -r -p` 可还原成二进制）

**启用条件（缺一不可）**：

1. `log.level: debug`
2. 配置了 `log.file`（没有文件日志时该功能无意义，直接不生效）
3. **显式配置了 `log.fail_dir`**（没有默认值，不写就等于关闭）

```yaml
log:
  level: debug
  file: "/var/log/mosdns.log"
  max_size_mb: 10     # 可省：默认 64
  keep_files: 5       # 可省：默认 5（保留几个轮转文件）
  fail_dir: "/var/log/mosdns-fail"   # 必填，无默认值
  fail_per_min: 20       # 可省：默认 20（每分钟最多写几个）
  fail_keep_days: 3      # 可省：默认 3（保留天数）
  fail_max_mb: 200       # 可省：默认 200（目录总大小上限，超了从最旧删）
```

`fail_dir` 建不出来（目录不可写 / 挂载点没挂）时只打一条 WARN，功能自动禁用，不影响 DNS 转发。

## 命令行

```
-c, --config <file>          配置文件
-p, --port <port>            覆盖所有 server 的监听端口（调试用）
    --check                  只校验配置并退出（0=OK，1=失败；servers=0 也判失败）
    --version                打印版本
    --log-file <file>        覆盖配置里的日志路径
    --dump-ipset <mmdb>      把 mmdb 转成 CIDR 文本（核对 ip_set 内容）
    --ipset-add <set> <cidr> 通过 netlink 写一条 ipset（自检）
    --ipset-bench <set> <n>  连续写 n 条并统计耗时
```

## 设计要点

**线程模型**：上游查询用阻塞 IO（`TcpStream` / `rustls StreamOwned` / 同步 QUIC 封装）；
UDP 服务端是线程池 + 弹性溢出线程 —— worker 忙超过 10 ms（说明卡在回源）就让新包走一次性线程，
避免回源阻塞造成队头堵塞。异步只用在 HTTP/2、HTTP/3 与 QUIC 客户端内部。

**上游重试**：单条查询总预算 5 s；每 500 ms 再向选中的上游派发一轮（最多 4 轮）。
除最后一个响应外，只有 `NOERROR` / `NXDOMAIN` 会被采用 —— 上游偶发 SERVFAIL 不会直接透给客户端。

**健康隔离**：连续失败 2 次的上游禁用 60 s，期间每 5 s 做一次半开探测；
全部上游都处于禁用期时立即返回失败，而不是让客户端等满 5 s。

**ipset**：`NFNL_SUBSYS_IPSET` 消息直接下发，`-exist` 语义通过把内核的 `IPSET_ERR_EXIST`
视为成功实现；netlink 不可用时自动回退到外部 `ipset` 命令。

**缓存**：LRU + 可选 lazy 窗口。lazy 命中返回陈旧值并把 TTL 改写为 5 s，
同时后台异步刷新，避免客户端长期缓存过期数据。

## 性能

同一台 4 核 ARMv8（Cortex-A53 级，1.8 GB RAM）上与原版对比：

| 指标 | mosdns (Go) v5.1.3 | mosdns-rs |
|---|---|---|
| 本地作答吞吐 | 6.7k qps / 331 µs | **19k qps / 105 µs** |
| 稳态 2000 qps CPU | 1.2 核 | **0.5 核** |
| 内存 RSS | 19–20 MB | **8–10 MB** |
| 二进制体积 | 15.1 MB | 3.9 MB (arm64) / 4.6 MB (x86-64) |

## 与上游 mosdns 的差异

- 只实现了上述插件子集（未实现 `nftset`、`ecs_handler`、`forward_edns0opt`、`rate_limiter`、
  `reverse_lookup`、`arbitrary`、`sleep`、`api` / `metrics`）
- 入站只有 UDP/TCP（没有 DoH / DoQ 服务端）
- EDNS0 保持 v5.1.3 语义（原样透传客户端 option）
- 遇到未实现的插件类型会告警并忽略，不会中断启动

## 致谢

- [mosdns](https://github.com/IrineSistiana/mosdns) —— 配置格式与插件语义的来源
- [smartdns](https://github.com/pymumu/smartdns) —— 上游重试切片、失败隔离、AAAA NODATA 的参考
- [quinn](https://github.com/quinn-rs/quinn) / [rustls](https://github.com/rustls/rustls) /
  [h2](https://github.com/hyperium/h2) / [h3](https://github.com/hyperium/h3) —— 传输层实现
