mod config;
mod dns;
mod doh;
mod doh3;
mod domain;
mod doq;
mod dot;
mod resolve;
mod engine;
mod faildump;
mod ipset;
mod log;
mod mmdb;
mod plugins;
mod yaml;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use config::{Entry, ServerKind};
use dns::*;
use engine::{Exec, QCtx, Sequence};

fn usage() {
    eprint!(
        r#"mosdns-rs (Rust rewrite of mosdns v5.1.3 core)

Usage:
  mosdns-rs -c <config.yaml> [options]
  mosdns-rs --dump-ipset <file.mmdb> [--country CN] [--ipv4-only]

Options:
  -c, --config <path>      config file (default: /etc/mosdns/config.yaml)
  -p, --port <port>        override all server listen ports
      --log-file <path>    override log file path
      --log-level <lv>     debug|info|warn|error (overrides config; env MOSDNS_RS_LOG_LEVEL)
      --no-stderr          do not log to stderr
      --dump-ipset <spec>  dump mmdb/ip-list as CIDR text and exit
      --country <CC>       mmdb country filter for --dump-ipset (default CN, "all" = no filter)
      --ipv4-only          only emit IPv4 prefixes for --dump-ipset
      --ipset-add <set> <cidr>   (自检) 通过 netlink 往 ipset 写一条，然后退出
      --ipset-bench <set> <n>    (自检) 连写 n 条并统计耗时
      --check                   只校验配置文件能否正确加载，然后退出（0=OK 1=失败）
      --version                 打印版本号后退出
  -h, --help               show this help
"#
    );
}

fn run_dump(spec: &str, country: &str, ipv4_only: bool) -> ! {
    if spec.starts_with("http://") || spec.starts_with("https://") {
        eprintln!("error: URL is not supported, use a local file path");
        std::process::exit(1);
    }
    let path = spec.to_string();
    let cc = if country.is_empty() || country == "*" || country.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(country.to_string())
    };
    if mmdb::is_mmdb_file(&path) {
        let db = match mmdb::Mmdb::open(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        };
        eprintln!(
            "# {} type={} ip_version={} record_size={} nodes={} build_epoch={} country={} ipv4_only={}",
            path,
            db.meta.database_type,
            db.meta.ip_version,
            db.meta.record_size,
            db.meta.node_count,
            db.meta.build_epoch,
            cc.clone().unwrap_or_else(|| "all".to_string()),
            ipv4_only
        );
        match db.dump(cc.as_deref(), ipv4_only) {
            Ok(lines) => {
                use std::io::Write;
                let out = std::io::stdout();
                let mut w = std::io::BufWriter::new(out.lock());
                for l in &lines {
                    let _ = writeln!(w, "{}", l);
                }
                let _ = w.flush();
                eprintln!("# {} prefixes dumped", lines.len());
            }
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match std::fs::read_to_string(&path) {
            Ok(s) => print!("{}", s),
            Err(e) => {
                eprintln!("error: cannot read {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }
    std::process::exit(0);
}

/// glibc 默认给每个线程一个 64MB 的 malloc arena，几十个工作线程会把 VSZ 撑到 2GB+。
/// 这里限制 arena 数量（只影响虚拟地址空间，RSS 不受影响）。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn tune_malloc() {
    const M_ARENA_MAX: i32 = -8;
    extern "C" {
        fn mallopt(param: i32, value: i32) -> i32;
    }
    unsafe {
        mallopt(M_ARENA_MAX, 8);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn tune_malloc() {}

fn main() {
    tune_malloc();
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path = "/etc/mosdns/config.yaml".to_string();
    let mut port_override: Option<u16> = None;
    let mut log_file: Option<String> = None;
    let mut log_level: Option<String> = None;
    let mut to_stderr = true;
    let mut dump_spec: Option<String> = None;
    let mut dump_country = "CN".to_string();
    let mut dump_ipv4_only = false;
    let mut ipset_add: Option<(String, String)> = None;
    let mut ipset_bench: Option<(String, u32)> = None;
    let mut check_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                cfg_path = args[i].clone();
            }
            "-p" | "--port" => {
                i += 1;
                if i >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                port_override = match args[i].parse() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        eprintln!("invalid port: {}", args[i]);
                        std::process::exit(2);
                    }
                };
            }
            "--log-file" => {
                i += 1;
                if i >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                log_file = Some(args[i].clone());
            }
            "--log-level" => {
                i += 1;
                if i >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                log_level = Some(args[i].clone());
            }
            "--check" => check_only = true,
            "--version" | "-V" => {
                println!("mosdns-rs {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--no-stderr" => to_stderr = false,
            "--dump-ipset" => {
                i += 1;
                if i >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                dump_spec = Some(args[i].clone());
            }
            "--country" => {
                i += 1;
                if i >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                dump_country = args[i].clone();
            }
            "--ipv4-only" => dump_ipv4_only = true,
            "--ipset-bench" => {
                if i + 2 >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                ipset_bench = Some((args[i + 1].clone(), args[i + 2].parse().unwrap_or(100)));
                i += 2;
            }
            "--ipset-add" => {
                if i + 2 >= args.len() {
                    usage();
                    std::process::exit(2);
                }
                ipset_add = Some((args[i + 1].clone(), args[i + 2].clone()));
                i += 2;
            }
            "-h" | "--help" => {
                usage();
                return;
            }
            other => {
                eprintln!("unknown argument: {}", other);
                usage();
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if let Some((set, n)) = ipset_bench {
        let t0 = std::time::Instant::now();
        let mut ok = 0u32;
        for i in 0..n {
            let ip: std::net::IpAddr = format!("198.51.100.{}", (i % 250) + 1).parse().unwrap();
            if ipset::add_netlink_only(&set, ip, 32).is_ok() {
                ok += 1;
            }
        }
        let el = t0.elapsed();
        let us = el.as_secs_f64() * 1e6 / n as f64;
        println!(
            "OK {} / {} 条，总耗时 {:.2} ms，平均 {:.1} µs/条",
            ok,
            n,
            el.as_secs_f64() * 1000.0,
            us
        );
        std::process::exit(0);
    }

    if let Some((set, cidr)) = ipset_add {
        let (addr_s, mask_s) = match cidr.split_once('/') {
            Some((a, m)) => (a, m),
            None => (cidr.as_str(), "32"),
        };
        let ip: std::net::IpAddr = match addr_s.parse() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("bad ip {}: {}", addr_s, e);
                std::process::exit(1);
            }
        };
        let mask: u8 = mask_s.parse().unwrap_or(32);
        match ipset::add_netlink_only(&set, ip, mask) {
            Ok(()) => {
                println!("OK netlink add {} {}/{}", set, ip, mask);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("FAIL {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(spec) = dump_spec {
        run_dump(&spec, &dump_country, dump_ipv4_only);
    }

    let text = match std::fs::read_to_string(&cfg_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("failed to read config {}: {}", cfg_path, e);
            std::process::exit(1);
        }
    };
    let root = match yaml::parse(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to parse config: {}", e);
            std::process::exit(1);
        }
    };

    // init logger early using config's log section (may be overridden by CLI)
    let mut lv = "info".to_string();
    let mut lfile = None;
    let mut log_max_mb: Option<u64> = None;
    let mut fail_dir: Option<String> = None;
    let mut fail_keep_days: u64 = 3;
    let mut fail_max_mb: u64 = 200;
    let mut fail_per_min: usize = 20;
    let mut log_keep: Option<usize> = None;
    if let Some(l) = root.get("log") {
        // 可选：日志轮转（原版 mosdns 不认这两个 key，回滚前需摘掉）
        if let Some(v) = l.get("fail_dir").and_then(|v| v.as_str()) {
            fail_dir = Some(v.to_string());
        }
        if let Some(v) = l.get("fail_keep_days").and_then(|v| v.as_int()) {
            fail_keep_days = v as u64;
        }
        if let Some(v) = l.get("fail_max_mb").and_then(|v| v.as_int()) {
            fail_max_mb = v as u64;
        }
        if let Some(v) = l.get("fail_per_min").and_then(|v| v.as_int()) {
            fail_per_min = v as usize;
        }
        if let Some(v) = l.get("max_size_mb").and_then(|v| v.as_int()) {
            if v > 0 {
                log_max_mb = Some(v as u64);
            }
        }
        // keep_files：保留几个轮转文件（只认这个名字）
        if let Some(v) = l.get("keep_files").and_then(|v| v.as_int()) {
            if v > 0 {
                log_keep = Some(v as usize);
            }
        }
        if let Some(v) = l.get("level").and_then(|v| v.as_str()) {
            lv = v.to_string();
        }
        if let Some(v) = l.get("file").and_then(|v| v.as_str()) {
            if !v.is_empty() {
                lfile = Some(v.to_string());
            }
        }
    }
    if let Some(f) = &log_file {
        lfile = Some(f.clone());
    }
    if let Some(l) = std::env::var("MOSDNS_RS_LOG_LEVEL").ok().filter(|v| !v.trim().is_empty()) {
        if log_level.is_none() {
            log_level = Some(l);
        }
    }
    if let Some(l) = &log_level {
        lv = l.clone();
    }
    if let Err(e) = log::init(&lv, lfile.as_deref(), to_stderr, log_max_mb, log_keep) {
        eprintln!("FATAL {}", e);
        std::process::exit(1);
    }

    // 失败查询落盘：必须同时满足 ①debug 级别 ②配置了 log.file ③显式配置了 log.fail_dir。
    // 三个 fail_* 子项不配则用默认值（per_min=20 / keep_days=3 / max=200MB）。
    if log::enabled(log::LV_DEBUG) && lfile.is_some() {
        if let Some(d) = fail_dir {
            let p = std::path::PathBuf::from(&d);
            faildump::init(p.clone(), fail_per_min, fail_keep_days, fail_max_mb);
            if faildump::is_enabled() {
                log::info(format!(
                    "faildump enabled, dir={} per_min={} keep_days={} max={}MB",
                    p.display(),
                    fail_per_min,
                    fail_keep_days,
                    fail_max_mb
                ));
            } else {
                log::error(format!(
                    "faildump 目录 {} 不可用（无法创建/写入），启动中止",
                    p.display()
                ));
                std::process::exit(1);
            }
        }
    }
    log::info(format!(
        "mosdns-rs pid={} version={} log_level={} log_file={} rotate={}MB x {}",
        std::process::id(),
        env!("CARGO_PKG_VERSION"),
        lv,
        lfile.as_deref().unwrap_or("-"),
        log_max_mb.unwrap_or(64),
        log_keep.unwrap_or(5)
    ));

    let built = match config::build(&root) {
        Ok(b) => b,
        Err(e) => {
            log::error(format!("failed to build plugins: {}", e));
            std::process::exit(1);
        }
    };

    if check_only {
        // 配置能解析 ≠ 能提供服务：一个监听器都没有时直接判失败，
        // 否则会出现 "check 通过但进程起来就 exit" 的坑（缩进断了导致 server 段丢失）。
        if built.servers.is_empty() {
            eprintln!(
                "FAIL config={} 解析成功但没有任何 udp_server / tcp_server（servers=0），进程会启动后立即退出",
                cfg_path
            );
            std::process::exit(1);
        }
        println!(
            "OK config={} plugins={} servers={}",
            cfg_path,
            built.reg.len(),
            built.servers.len()
        );
        std::process::exit(0);
    }

    log::info(format!(
        "mosdns-rs starting, config={}, plugins ready, servers={}",
        cfg_path,
        built.servers.len()
    ));

    let mut handles = Vec::new();
    for s in &built.servers {
        let seq: Arc<dyn Exec> = match built.reg.get(&s.entry) {
            Some(Entry::Chain(c)) => Arc::new(Sequence { chain: c.clone() }),
            Some(Entry::Plain(p)) => p.clone(),
            _ => {
                log::error(format!("server entry [{}] is not a sequence", s.entry));
                std::process::exit(1);
            }
        };
        let mut listen = s.listen.clone();
        if let Some(p) = port_override {
            listen = override_port(&listen, p);
        }
        let kind = s.kind;
        let h = std::thread::Builder::new()
            .name(format!("{:?}-{}", kind, listen))
            .spawn(move || match kind {
                ServerKind::Udp => serve_udp(&listen, seq),
                ServerKind::Tcp => serve_tcp(&listen, seq),
            })
            .expect("spawn server thread");
        handles.push(h);
    }

    if handles.is_empty() {
        log::error("no server configured");
        std::process::exit(1);
    }

    for h in handles {
        let _ = h.join();
    }
}

fn override_port(listen: &str, port: u16) -> String {
    if let Some(rest) = listen.strip_prefix(':') {
        let _ = rest;
        return format!(":{}", port);
    }
    if listen.starts_with('[') {
        // [::]:53
        if let Some(idx) = listen.rfind("]:") {
            return format!("{}]:{}", &listen[..idx], port);
        }
    }
    if let Some((host, _)) = listen.rsplit_once(':') {
        if host.parse::<std::net::IpAddr>().is_ok() || host.is_empty() {
            return format!("{}:{}", host, port);
        }
    }
    listen.to_string()
}

fn bind_addr(listen: &str) -> String {
    if let Some(rest) = listen.strip_prefix(':') {
        format!("0.0.0.0:{}", rest)
    } else {
        listen.to_string()
    }
}

fn serve_udp(listen: &str, entry: Arc<dyn Exec>) {
    let addr = bind_addr(listen);
    let sock = match UdpSocket::bind(&addr) {
        Ok(s) => s,
        Err(e) => {
            log::error(format!("udp bind {} failed: {}", addr, e));
            std::process::exit(1);
        }
    };
    match sock.local_addr() {
        Ok(a) => log::info(format!("udp server listening on {}", a)),
        Err(_) => log::info(format!("udp server listening on {}", addr)),
    }
    let sock = Arc::new(sock);
    // 线程池：避免「每包一线程」的 spawn/join 开销（这是最贵的一笔固定成本）。
    // 队列按 worker 分片，避免多线程抢同一把锁（实测共享队列在 16 线程以上会明显掉速）。
    // 每片队列有上限，满载时丢包（客户端会重传），防止被压垮时内存暴涨。
    let workers = udp_workers();
    log::info(format!("udp server workers={}", workers));
    let mut queues = Vec::with_capacity(workers);
    let mut cvs = Vec::with_capacity(workers);
    for _ in 0..workers {
        queues.push(std::sync::Mutex::new(std::collections::VecDeque::with_capacity(
            256,
        )));
        cvs.push(std::sync::Condvar::new());
    }
    let pool = Arc::new(UdpPool {
        queues,
        cvs,
        sock: sock.clone(),
        entry,
        rr: std::sync::atomic::AtomicUsize::new(0),
        busy: std::sync::atomic::AtomicUsize::new(0),
        qlen: std::sync::atomic::AtomicUsize::new(0),
        extra: std::sync::atomic::AtomicUsize::new(0),
        starts: (0..workers)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect(),
    });
    for i in 0..workers {
        let p = pool.clone();
        std::thread::Builder::new()
            .name(format!("udp-w{}", i))
            .stack_size(256 * 1024)
            .spawn(move || udp_worker(p, i))
            .expect("spawn udp worker");
    }

    let mut buf = vec![0u8; 65535];
    let n_workers = workers;
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::warn(format!("udp recv error: {}", e));
                continue;
            }
        };
        // 探一个 worker：如果它已经连续忙了 >10ms，说明卡在上游 I/O 上（本地查询 ~0.1ms）。
        // 此时新包直接交给一次性线程处理，避免本地/缓存命中的请求被慢查询堵在队列里
        // （对齐 Go 的 goroutine 语义；正常负载下不会触发，不产生额外线程开销）。
        let probe = pool.rr.load(Ordering::Relaxed) % n_workers;
        let since = pool.starts[probe].load(Ordering::Relaxed);
        let blocked = since != 0 && epoch_ms().saturating_sub(since) > 10;
        if blocked && pool.extra.load(Ordering::Relaxed) < MAX_EXTRA_THREADS {
            pool.extra.fetch_add(1, Ordering::Relaxed);
            let p = pool.clone();
            let data = buf[..n].to_vec();
            let spawned = std::thread::Builder::new()
                .name("udp-extra".to_string())
                .stack_size(256 * 1024)
                .spawn(move || {
                    handle_udp(p.sock.clone(), data, peer, p.entry.clone());
                    p.extra.fetch_sub(1, Ordering::Relaxed);
                });
            if spawned.is_ok() {
                continue;
            }
            pool.extra.fetch_sub(1, Ordering::Relaxed);
        }

        let idx = pool.rr.fetch_add(1, Ordering::Relaxed) % n_workers;
        let mut q = match pool.queues[idx].lock() {
            Ok(q) => q,
            Err(_) => continue,
        };
        if q.len() >= UDP_QUEUE_MAX {
            continue; // 过载丢包
        }
        q.push_back((buf[..n].to_vec(), peer));
        drop(q);
        pool.qlen.fetch_add(1, Ordering::Relaxed);
        pool.cvs[idx].notify_one();
    }
}

const UDP_QUEUE_MAX: usize = 4096;
/// 溢出线程上限：防止被压垮时线程爆炸（256 × 256KB 栈 ≈ 64MB 虚拟）
const MAX_EXTRA_THREADS: usize = 256;

struct UdpPool {
    queues: Vec<std::sync::Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>>,
    cvs: Vec<std::sync::Condvar>,
    sock: Arc<UdpSocket>,
    entry: Arc<dyn Exec>,
    rr: std::sync::atomic::AtomicUsize,
    /// 正在处理请求的 worker 数
    busy: std::sync::atomic::AtomicUsize,
    /// 全局排队数
    qlen: std::sync::atomic::AtomicUsize,
    /// 当前的溢出线程数
    extra: std::sync::atomic::AtomicUsize,
    /// 每个 worker 开始处理请求的时刻（epoch ms，0 表示空闲）
    starts: Vec<std::sync::atomic::AtomicU64>,
}

#[inline]
fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn udp_workers() -> usize {
    if let Ok(v) = std::env::var("MOSDNS_RS_UDP_WORKERS") {
        if let Ok(n) = v.parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cores * 4).clamp(4, 32)
}

fn udp_worker(pool: Arc<UdpPool>, idx: usize) {
    loop {
        let job = {
            let mut q = match pool.queues[idx].lock() {
                Ok(q) => q,
                Err(_) => return,
            };
            while q.is_empty() {
                q = match pool.cvs[idx].wait(q) {
                    Ok(q) => q,
                    Err(_) => return,
                };
            }
            q.pop_front()
        };
        if let Some((data, peer)) = job {
            pool.qlen.fetch_sub(1, Ordering::Relaxed);
            pool.busy.fetch_add(1, Ordering::Relaxed);
            pool.starts[idx].store(epoch_ms(), Ordering::Relaxed);
            handle_udp(pool.sock.clone(), data, peer, pool.entry.clone());
            pool.starts[idx].store(0, Ordering::Relaxed);
            pool.busy.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// 单条查询的 debug 日志（只在 debug 级别拼字符串）。
#[inline]
fn log_query(ctx: &QCtx, resp: &Msg, proto: &str, wire_len: usize, ms: f64, err: Option<&str>) {
    let rcode = resp.rcode();
    let ans = resp.answer.len();
    if !log::enabled(log::LV_DEBUG) {
        return;
    }
    let (qname, qtype) = ctx
        .q
        .question
        .first()
        .map(|x| (x.name.as_str(), x.qtype))
        .unwrap_or((".", 0));
    // C：补充 ttl / rb（响应字节）/ tries（派发轮次）/ edns 等级
    let ttl = resp
        .answer
        .iter()
        .map(|rr| rr.ttl)
        .min()
        .unwrap_or(0);
    let rb = wire_len;
    let edns = ctx.q.edns_level();

    log::debug(format!(
        "q id={} {} client={} qname={} type={} rcode={} ans={} ms={:.2} ttl={} rb={} tries={} edns={} path={} err={}",
        ctx.qid,
        proto,
        ctx.client
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string()),
        qname,
        qtype,
        rcode,
        ans,
        ms,
        ttl,
        rb,
        ctx.tries,
        edns,
        ctx.trace.as_deref().unwrap_or(""),
        err.unwrap_or("-")
    ));

    // B：失败查询落盘（debug 下才可能启用）
    // 纯缓存回放（cache_hit / cache_lazy）不落盘：那次真实事件在 cache_miss 时已经记过了，
    // 否则 SERVFAIL 缓存 5s 期间每个客户端查询都会再产出一个一模一样的样本。
    let from_cache = ctx
        .trace
        .as_deref()
        .map(|p| p.starts_with("cache_hit") || p.starts_with("cache_lazy"))
        .unwrap_or(false);
    if faildump::is_enabled()
        && !from_cache
        && (err.is_some() || rcode == 2 || ms >= 2000.0)
    {
        let mut hex = String::new();
        for b in ctx.q.pack() {
            hex.push_str(&format!("{:02x}", b));
        }
        let mut header = format!(
            "# {} {} client={} qname={} type={} rcode={} ans={} ms={:.2} ttl={} tries={} edns={}\n# path={}\n# err={}",
            log::now_ms_str(),
            proto,
            ctx.client
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string()),
            qname,
            qtype,
            rcode,
            ans,
            ms,
            ttl,
            ctx.tries,
            edns,
            ctx.trace.as_deref().unwrap_or(""),
            err.unwrap_or("-")
        );
        if !ctx.attempts.is_empty() {
            header.push_str("\n# attempts:");
            for a in ctx.attempts.iter().take(16) {
                header.push_str("\n#   ");
                header.push_str(a);
            }
        }
        faildump::dump(&log::now_ms_str(), qname, qtype, &header, &hex);
    }
}

fn handle_udp(sock: Arc<UdpSocket>, data: Vec<u8>, peer: SocketAddr, entry: Arc<dyn Exec>) {
    let q = match Msg::parse(&data) {
        Ok(q) => q,
        Err(e) => {
            log::warn(format!("invalid query from {}: {}", peer, e));
            return;
        }
    };
    let mut ctx = QCtx::new(q, Some(peer.ip()));
    let t0 = std::time::Instant::now();
    let err = entry.exec(&mut ctx);
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let err_msg = err.as_ref().err().cloned();
    let q = &ctx.q;
    let mut resp = match (err.is_ok(), ctx.r.take()) {
        (true, Some(r)) => r,
        (true, None) => q.set_reply(RCODE_REFUSED),
        (false, _) => {
            log::warn(format!(
                "entry error for {}: {}",
                q.question
                    .first()
                    .map(|x| x.name.clone())
                    .unwrap_or_default(),
                err.err().unwrap_or_default()
            ));
            q.set_reply(RCODE_SERVFAIL)
        }
    };
    resp.flags |= FLAG_RA;
    let size = q.udp_size();
    resp.truncate_to(size);
    let bytes = resp.pack();
    log_query(&ctx, &resp, "udp", bytes.len(), elapsed_ms, err_msg.as_deref());
    if let Err(e) = sock.send_to(&bytes, peer) {
        log::warn(format!("udp send to {} failed: {}", peer, e));
    }
}

fn serve_tcp(listen: &str, entry: Arc<dyn Exec>) {
    let addr = bind_addr(listen);
    let l = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            log::error(format!("tcp bind {} failed: {}", addr, e));
            std::process::exit(1);
        }
    };
    log::info(format!("tcp server listening on {}", addr));
    for c in l.incoming() {
        match c {
            Ok(stream) => {
                let entry2 = entry.clone();
                std::thread::spawn(move || {
                    handle_tcp_conn(stream, entry2);
                });
            }
            Err(e) => log::warn(format!("tcp accept error: {}", e)),
        }
    }
}

fn handle_tcp_conn(mut s: TcpStream, entry: Arc<dyn Exec>) {
    let peer = s.peer_addr().ok();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    loop {
        let mut len_buf = [0u8; 2];
        if s.read_exact(&mut len_buf).is_err() {
            return;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len < 12 {
            return;
        }
        let mut buf = vec![0u8; len];
        if s.read_exact(&mut buf).is_err() {
            return;
        }
        let q = match Msg::parse(&buf) {
            Ok(q) => q,
            Err(e) => {
                log::warn(format!("invalid tcp query: {}", e));
                return;
            }
        };
        let mut ctx = QCtx::new(q, peer.map(|p| p.ip()));
        let t0 = std::time::Instant::now();
        let err = entry.exec(&mut ctx);
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let err_msg = err.as_ref().err().cloned();
        let q = &ctx.q;
        let mut resp = match (err.is_ok(), ctx.r.take()) {
            (true, Some(r)) => r,
            (true, None) => q.set_reply(RCODE_REFUSED),
            (false, _) => q.set_reply(RCODE_SERVFAIL),
        };
        resp.flags |= FLAG_RA;
        let bytes = resp.pack();
        log_query(&ctx, &resp, "tcp", bytes.len(), elapsed_ms, err_msg.as_deref());
        let mut framed = Vec::with_capacity(bytes.len() + 2);
        framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        framed.extend_from_slice(&bytes);
        if s.write_all(&framed).is_err() {
            return;
        }
    }
}
