# 性能对比：mosdns (Go v5.1.3) vs mosdns-rs (Rust)

测试时间 2026-10-19 21:00 左右，同一台机器、同一份配置（仅监听端口不同）。

## 测试环境

| 项 | 值 |
|---|---|
| 机器 | <target-host>，ARMv8 (Cortex-A53 级) **4 核**，1795 MB RAM，Armbian bookworm / kernel 6.1.142 |
| Go 版 | `/usr/local/bin/mosdns` v5.1.3，配置副本 `/root/mosdns-cmp.yaml`（listen `:5354`，日志独立），**临时起的第二个进程，生产 :53 不受影响** |
| Rust 版 | `/root/mosdns-rs/mosdns-rs`（md5 `a8a6f564…`），配置 `/root/mosdns-rs/config.yaml`，listen `:5353`，16 个 UDP 工作线程 |
| 压测器 | 自写 `dnsbench`（Rust，aarch64），同机 loopback、预构建查询报文、按速率/并发发送并统计 |
| CPU 采集 | `/proc/<pid>/stat` 的 `utime+stime`（含全部线程，100 Hz tick），除以实际完成查询数 |
| 内存采集 | `/proc/<pid>/status` 的 `VmRSS` / `VmHWM` / `VmSize` / `Threads` |
| 轮次 | 每项跑 2 轮，下表给两轮区间 |

工作负载：

- **local**：`router.lan`(hosts)、`ads.raidrive.com`/`mcdn.bilivideo.cn`(reject 列表 NXDOMAIN)、`x.pcdn.biliapi.net`(regexp 拒绝)、`www.taobao.com` qtype 65(拒绝) —— 全部本地作答，不碰上游，纯引擎开销。
- **cache**：`www.baidu.com`/`qq.com`/`www.jd.com`/`www.bilibili.com`/`example.com`，先预热，测试期间全部命中缓存。
- **paced**：local 混合但限速 2000 qps（家庭网络的真实量级 ~50-200 qps，这里刻意压高以放大差异）。
- **miss**：400 个随机唯一域名（`.invalid`），必然回源（local DNS → 远程 DNS），用来观察转发路径。

## 结果：吞吐与 CPU

| 场景 | 指标 | mosdns (Go) | mosdns-rs (Rust) | 对比 |
|---|---|---|---|---|
| **local 打满**<br>16 并发 8s | 吞吐 | 6,649 / 6,933 qps | **19,085 / 19,392 qps** | **2.8×** |
| | 单查询 CPU | 331 / 315 µs | **105 / 102 µs** | **1/3（省 3.1×）** |
| | p50 / p99 | 2.30 / 5.78 ms | **0.72 / 3.60 ms** | p50 降到 1/3 |
| **cache 打满**<br>16 并发 8s | 吞吐 | 5,729 / 5,634 qps | **11,641 / 14,342 qps** | **2.1–2.5×** |
| | 单查询 CPU | 443 / 442 µs | **175 / 164 µs** | 省 2.6× |
| | p50 / p99 | 2.65 / 6.90 ms | **0.94 / 5.78 ms** | p50 降到 1/2.9 |
| **稳态 2000 qps**<br>8 并发 10s | CPU 占用 | 116% / 115%（≈1.2 核） | **49.6% / 48.9%（≈0.5 核）** | **约 42%** |
| | 单查询 CPU | 580 / 575 µs | **248 / 244 µs** | 省 2.3× |
| | p50 / p99 | 1.59 / 3.67 ms | **0.69 / 1.72 ms** | p99 一半 |
| **miss 回源**<br>16 并发 400 次 | 吞吐 | 186 / 181 qps | 170 / 177 qps | 持平（受上游 RTT 支配） |
| | 单查询 CPU | 4,250 / 4,625 µs | **3,900 / 3,825 µs** | 省 ~10% |
| | p50 / p99 | 73 / 149 ms | 80 / 173 ms | 相当 |

> 2000 qps 时 Rust 只吃 **0.5 核**，Go 要 **1.2 核**；换成 4 核机器上的可用余量，就是「还能再扛 3 倍流量」。

## 结果：内存

| 指标 | mosdns (Go) | mosdns-rs (Rust) | 说明 |
|---|---|---|---|
| 空闲 RSS | 19.2 MB | **16.5 MB** | -14% |
| 压测后 RSS | 20.0 MB | **17.9 MB** | -10% |
| 峰值 RSS（VmHWM） | 20.7 MB | **18.3 MB** | -12% |
| 虚拟内存（VmSize） | 727.6 MB | **525–538 MB** | -28% |
| 线程数 | 12 | 19–25 | Go 用 goroutine 复用；Rust 16 个工作线程 + 转发临时线程 |
| 二进制大小 | 15.1 MB | **2.1 MB** | 7.2× 小 |
| 生产 Go 实例（真实流量跑 3h46m） | RSS 22.4 MB / VSZ 727 MB / 11 线程 | — | 作为参考：真实负载下 Go 常驻 22 MB |

两者 RSS 都是「十几 MB」量级，差距体现在：Rust 无 GC 堆预留、无 runtime 常驻；Go 的 VSZ 主要来自 runtime 预留地址空间（不是真实占用）。

## 优化过程（Rust 侧，都是这次实测驱动的）

| 阶段 | 饱和吞吐 | 单查询 CPU | p50 |
|---|---|---|---|
| 初版：**每包一线程**（`thread::spawn` / 包） | 3,900 qps | 625 µs | 3.93 ms |
| 改 16 线程池（共享队列） | 17,500 qps | 107 µs | 0.78 ms |
| + 队列分片 / 256KB 线程栈 / glibc `M_ARENA_MAX=8` | 19,100 qps | 103 µs | 0.72 ms |
| + ip_set 排序压缩 + 二分查找 | 同上（resp_ip 命中路径 O(n)→O(log n)） | | |
| + 上游 TCP 连接复用（对齐 Go 的 idle reuse） | miss 路径：5,700 → 3,850 µs/查询，p50 94 → 76 ms | | |
| + 线程池弹性溢出（见下节，解决队头阻塞） | 本地吞吐不变（18.4k），回源并发时本地 p99 24 → 2.0 ms | | |

一句话：**「每包一线程」是初版最大的性能坑**（单查询多花 500 µs、吞吐只有 1/5），换成线程池后 Rust 才真正跑起来。

## 线程模型：Go 的 goroutine vs Rust 的线程池（「为什么是 4×核数」）

### 原版（Go）到底开多少线程

| 观测项 | 值 | 怎么来的 |
|---|---|---|
| `gomaxprocs` | **4** | `/proc/<pid>/environ` 里没有 GOMAXPROCS，Go 默认取 CPU 核数（nproc=4）；`GODEBUG=schedtrace=2000` 打印 `gomaxprocs=4` |
| OS 线程数 | 空闲 7，满载 10，生产实例（跑 3h46m）11 | `/proc/<pid>/status` 的 `Threads:` |
| 逻辑并发单位 | **每个查询一个 goroutine，无上限** | mosdns 的 UDP server 收到包就 `go func(){}` |
| 满载时的调度器 | `SCHED ... gomaxprocs=4 idleprocs=0 threads=10 runqueue=0` | schedtrace |
| 回源阻塞时的调度器 | `SCHED ... gomaxprocs=4 idleprocs=4 threads=10` | 4 个 P 全空闲 —— goroutine 都挂在 syscall 上，**本地查询照样立刻被调度** |

结论：**Go 的"线程数"不是并发上限**。4 个 P 就能挂住几百个阻塞查询而不影响其他请求，代价是每个查询的 goroutine 调度 + GC 开销（单查询 331 µs，是 Rust 的 3 倍）。

### Rust 侧为什么开始取 4×核数（16）

Rust 没有 async，UDP 用固定 worker 池，**一个 worker 在回源时会被整段阻塞（~80 ms）**。所以池子大小同时决定两件事：快路径吞吐、和「同时能挂多少个回源」。

实测（16 客户端打满，400 个必然回源的域名）：

| worker 数 | 本地作答吞吐 | 回源吞吐 | 回源 p50 |
|---|---|---|---|
| 4 | 23.1k qps | **44 qps** | 264 ms（排队） |
| 8 | 20.6–21.8k qps | 96 qps | — |
| 16 | 19.8–20.1k qps（最新一轮 18.4k） | **179 qps**（最新 160） | 80→72 ms |
| 32 | 19.3 kqps | — | — |
| Go（对照） | 6.7k qps | 187 qps | 74 ms |

- 纯吞吐看，4 个 worker 最好（19k→23k），但回源吞吐掉到 44 qps。
- **16 是「回源吞吐追平 Go（179 vs 187）」的最小值**，这就是 4×核数的由来：4 个核 × 每核挂 4 个阻塞查询。
- 代价：本地峰值从 23k 降到 19.8k —— 对家庭场景（~100 qps）毫无意义，所以选 16。

### 但固定池子有个真问题：队头阻塞（已修）

同样是「64 个回源查询 + 持续 500 qps 本地查询」的压力测试：

| 本地作答 p99 | 空载 | 同时 64 个回源 |
|---|---|---|
| Go（goroutine） | 3.91 ms | **4.33 ms**（几乎无感） |
| Rust W=4（改前） | 1.77 ms | **268 ms** ❌ |
| Rust W=4（加溢出线程） | 1.97 ms | **3.87 ms** ✅ |
| Rust W=16（改前） | 1.82 ms | 24 ms |
| Rust W=16（加溢出线程） | 2.06 ms | **1.95 ms** ✅ |

修法是给线程池加**弹性溢出**：worker 开始处理时记录时刻，收包线程探测某个 worker，若它已连续忙 >10 ms（本地查询只要 ~0.1 ms，说明卡在上游 I/O），就把这个包交给一个一次性线程（上限 256 个），处理完即退出。正常负载下永远不触发，所以快路径零开销；一旦出现慢查询，行为就和 Go 的 goroutine 一样，不会拖累其他请求。

于是**池子大小不再关键**：W=4 加溢出后本地 p99 也只有 3.9 ms、回源 110 qps；W=16 是 2.0 ms / 160 qps。默认仍取 4×核数，但可以用 `MOSDNS_RS_UDP_WORKERS` 按需覆盖。

## 怎么解读这些数字

1. **本地作答/缓存命中是日常主路径**（命中率越高越明显），Rust 在这里是 2.5–3× 吞吐、1/3 CPU。
2. **回源路径两边都受上游 RTT 支配**（p50 70–90 ms），差异主要来自「谁先返回」和连接复用；Rust 单查询 CPU 略低，延迟在噪声范围内。
3. 同机压测时压测器和服务器抢同样的 4 个核，**绝对吞吐偏保守**，比例更有意义。
4. 低频稳态（2000 qps）下单查询 CPU 比打满时高（CPU 降频），两边同样受影响，所以只用它比较「谁更省」。

## 复现

```sh
# 1) 起一个 Go 对比实例（不要动生产 :53）
sed -e 's#^      listen: :53$#      listen: :5354#' \
    -e 's#^  file: "/var/log/mosdns.log"#  file: "/var/log/mosdns-cmp.log"#' \
    /etc/mosdns/config.yaml > /root/mosdns-cmp.yaml
setsid nohup /usr/local/bin/mosdns start -c /root/mosdns-cmp.yaml >/var/log/mosdns-cmp.out 2>&1 &

# 2) 压测
/root/mosdns-rs/dnsbench --port 5353 --pid $(pgrep -x mosdns-rs) --mode local --rate 0 --duration 8 --workers 16
/root/mosdns-rs/dnsbench --port 5354 --pid <go-pid>            --mode local --rate 0 --duration 8 --workers 16
/root/mosdns-rs/dnsbench --port 5353 --pid $(pgrep -x mosdns-rs) --mode cache --rate 0 --duration 8 --workers 16
/root/mosdns-rs/dnsbench --port 5353 --pid $(pgrep -x mosdns-rs) --mode local --rate 2000 --duration 10 --workers 8
/root/mosdns-rs/dnsbench --port 5353 --pid $(pgrep -x mosdns-rs) --mode miss --count 400 --workers 16

# 3) 跑全套（两轮 A/B，脚本在机器上）
bash /root/bench_run.sh
```

`dnsbench` 源码在本仓库 `../dnsbench/`。
