//! Plugins: cache / hosts / redirect / forward / ipset / ttl / black_hole /
//! prefer_ipv4 / fallback, plus matchers qname / qtype / client_ip / resp_ip.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::dns::*;
use crate::domain::{DomainSet, HostsMap, IpSet, RedirectMap};
use crate::engine::*;
use crate::log;

static RAND_ID: AtomicU16 = AtomicU16::new(0);
static SEQ: AtomicU64 = AtomicU64::new(0);

/// 拆分 "host[:port][/path]"，返回 (host, port, path)
fn split_url_host_path(s: &str, default_port: u16) -> Result<(String, u16, String), String> {
    let (host_port, path) = match s.find('/') {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, "/dns-query"),
    };
    let (host, port) = split_host_port(host_port, default_port)?;
    Ok((host, port, path.to_string()))
}

/// 拆分 "host[:port]" / "[v6][:port]"，没有端口时用默认值。
fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = s.trim().trim_end_matches('/');
    if s.is_empty() {
        return Err("empty upstream host".to_string());
    }
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port 或 [v6]
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid upstream addr [{}]", s))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| format!("invalid port in [{}]", s))?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }
    if s.matches(':').count() == 1 {
        let (host, p) = s.rsplit_once(':').unwrap();
        let port = p
            .parse()
            .map_err(|_| format!("invalid port in [{}]", s))?;
        return Ok((host.to_string(), port));
    }
    // 多个冒号视为裸 IPv6，无端口
    Ok((s.to_string(), default_port))
}

/// 轻量随机（用于上游起点选择），不追求密码学强度。
fn rand_usize(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(1);
    let c = SEQ.fetch_add(1, Ordering::Relaxed);
    ((nanos ^ (c.wrapping_mul(0x9E3779B97F4A7C15))) as usize) % n
}

fn next_id() -> u16 {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(1);
    let v = RAND_ID.fetch_add(1, Ordering::Relaxed);
    seed.wrapping_add(v.wrapping_mul(0x9E37)) | 1
}

// ==================== cache ====================

struct CacheEntry {
    msg: Msg,
    stored: Instant,
    expire: Instant,
    cache_expire: Instant,
    used: u64,
}

pub struct Cache {
    size: usize,
    lazy_ttl: u32,
    inner: Mutex<HashMap<Vec<u8>, CacheEntry>>,
    lazy_inflight: Mutex<HashSet<Vec<u8>>>,
    me: std::sync::Weak<Cache>,
}

fn msg_key(q: &Msg) -> Option<Vec<u8>> {
    if q.is_response() || q.opcode() != 0 || q.question.len() != 1 {
        return None;
    }
    let mut bits = 0u8;
    if q.ad() {
        bits |= 1;
    }
    if q.cd() {
        bits |= 2;
    }
    if q.is_edns0_do() {
        bits |= 4;
    }
    let qq = &q.question[0];
    let mut key = Vec::with_capacity(4 + qq.name.len());
    key.push(bits);
    key.extend_from_slice(&qq.qtype.to_be_bytes());
    key.push(qq.name.len() as u8);
    key.extend_from_slice(qq.name.as_bytes());
    Some(key)
}


impl Cache {
    pub fn new(size: usize, lazy_ttl: u32) -> Arc<Cache> {
        let size = if size == 0 { 1024 } else { size };
        Arc::new_cyclic(|me| Cache {
            size,
            lazy_ttl,
            inner: Mutex::new(HashMap::new()),
            lazy_inflight: Mutex::new(HashSet::new()),
            me: me.clone(),
        })
    }

    fn get(&self, key: &[u8], now: Instant) -> (Option<Msg>, bool) {
        let mut g = self.inner.lock().unwrap();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        if let Some(e) = g.get_mut(key) {
            e.used = seq;
            if now < e.expire {
                return (Some(e.msg.clone()), false);
            }
            if self.lazy_ttl > 0 && now < e.cache_expire {
                return (Some(e.msg.clone()), true);
            }
            g.remove(key);
            return (None, false);
        }
        (None, false)
    }

    fn store(&self, key: Vec<u8>, msg: Msg, msg_ttl: u64, cache_ttl: u64) {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        if g.len() >= self.size && !g.contains_key(&key) {
            // evict least recently used 10% (min 1)
            let mut items: Vec<(Vec<u8>, u64)> = g.iter().map(|(k, v)| (k.clone(), v.used)).collect();
            items.sort_by_key(|(_, u)| *u);
            let n = (self.size / 10).max(1).min(items.len());
            for (k, _) in items.into_iter().take(n) {
                g.remove(&k);
            }
        }
        g.insert(
            key,
            CacheEntry {
                msg,
                stored: now,
                expire: now + Duration::from_secs(msg_ttl),
                cache_expire: now + Duration::from_secs(cache_ttl),
                used: SEQ.fetch_add(1, Ordering::Relaxed),
            },
        );
    }

    fn save(&self, key: &[u8], r: &Msg) {
        if r.flags & FLAG_TC != 0 {
            return;
        }
        let (msg_ttl, cache_ttl) = match r.rcode() {
            RCODE_NXDOMAIN => (30u64, 30u64),
            RCODE_SERVFAIL => (5, 5),
            RCODE_NOERROR => {
                let min_ttl = r.minimal_ttl() as u64;
                if r.answer.is_empty() {
                    let t = min_ttl.min(300);
                    (t, t)
                } else if self.lazy_ttl > 0 {
                    (min_ttl, self.lazy_ttl as u64)
                } else {
                    (min_ttl, min_ttl)
                }
            }
            _ => return,
        };
        if msg_ttl == 0 || cache_ttl == 0 {
            return;
        }
        self.store(key.to_vec(), r.copy_no_opt(), msg_ttl, cache_ttl);
    }
}

impl RExec for Cache {
    fn exec(&self, ctx: &mut QCtx, next: &Walker) -> Res {
        let key = match msg_key(&ctx.q) {
            Some(k) => k,
            None => return next.exec_next(ctx),
        };
        let now = Instant::now();
        let (cached, lazy) = self.get(&key, now);
        let mut hit = false;
        if cached.is_some() {
            ctx.note(if lazy { "cache_lazy" } else { "cache_hit" });
        } else {
            ctx.note("cache_miss");
        }
        if let Some(mut m) = cached {
            if lazy {
                m.set_ttl(5);
            } else {
                let stored = self
                    .inner
                    .lock()
                    .unwrap()
                    .get(&key)
                    .map(|e| e.stored)
                    .unwrap_or(now);
                let elapsed = now.saturating_duration_since(stored).as_secs() as u32;
                m.subtract_ttl(elapsed);
            }
            m.id = ctx.q.id;
            // 与 mosdns v5.2.0+ 对齐：缓存命中时不再打乱 A/AAAA 顺序（v5.1.3 的 shuffleIP 已被上游删除）
            ctx.set_resp(m);
            hit = true;
            if lazy {
                self.spawn_lazy_update(key.clone(), ctx.copy_ctx(), next.clone());
            }
        }

        let gen_before = ctx.resp_gen;
        let r = next.exec_next(ctx);
        if ctx.r.is_some() && (!hit || ctx.resp_gen != gen_before) {
            let resp = ctx.r.as_ref().unwrap().clone();
            self.save(&key, &resp);
        }
        r
    }
}

impl Cache {
    fn spawn_lazy_update(&self, key: Vec<u8>, mut ctx: QCtx, next: Walker) {
        {
            let mut inflight = self.lazy_inflight.lock().unwrap();
            if !inflight.insert(key.clone()) {
                return; // already updating
            }
        }
        let this = match self.me.upgrade() {
            Some(a) => a,
            None => {
                self.lazy_inflight.lock().unwrap().remove(&key);
                return;
            }
        };
        std::thread::spawn(move || {
            ctx.deadline = Instant::now() + Duration::from_secs(5);
            let qname = ctx
                .q
                .question
                .first()
                .map(|x| x.name.clone())
                .unwrap_or_default();
            let r = next.exec_next(&mut ctx);
            match (&r, &ctx.r) {
                (Ok(()), Some(resp)) => this.save(&key, resp),
                (Err(e), _) => {
                    // 对齐 Go 版的 "failed to update lazy cache" 可观测性
                    if crate::log::enabled(crate::log::LV_DEBUG) {
                        crate::log::debug(format!(
                            "cache failed to update lazy cache for {}: {}",
                            qname, e
                        ));
                    }
                }
                _ => {}
            }
            this.lazy_inflight.lock().unwrap().remove(&key);
        });
    }
}

// ==================== hosts ====================

pub struct Hosts {
    pub map: HostsMap,
}

impl Exec for Hosts {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        if ctx.q.question.len() != 1 {
            return Ok(());
        }
        let (name, qtype) = {
            let q = &ctx.q.question[0];
            if q.qclass != CLASS_IN || (q.qtype != TYPE_A && q.qtype != TYPE_AAAA) {
                return Ok(());
            }
            (q.name.clone(), q.qtype)
        };
        let (v4, v6) = match self.map.lookup(&name) {
            Some(e) => e,
            None => return Ok(()),
        };
        let (v4, v6) = (v4.clone(), v6.clone());
        if v4.is_empty() && v6.is_empty() {
            return Ok(());
        }
        ctx.note("hosts");
        let mut r = ctx.q.set_reply(RCODE_NOERROR);
        if qtype == TYPE_A && !v4.is_empty() {
            for ip in &v4 {
                r.answer.push(RR {
                    name: name.clone(),
                    rtype: TYPE_A,
                    class: CLASS_IN,
                    ttl: 10,
                    rdata: RData::A(*ip),
                });
            }
        } else if qtype == TYPE_AAAA && !v6.is_empty() {
            for ip in &v6 {
                r.answer.push(RR {
                    name: name.clone(),
                    rtype: TYPE_AAAA,
                    class: CLASS_IN,
                    ttl: 10,
                    rdata: RData::Aaaa(*ip),
                });
            }
        }
        if r.answer.is_empty() {
            r.ns.push(fake_soa(&name));
        }
        ctx.set_resp(r);
        Ok(())
    }
}

// ==================== redirect ====================

pub struct Redirect {
    pub map: RedirectMap,
}

impl RExec for Redirect {
    fn exec(&self, ctx: &mut QCtx, next: &Walker) -> Res {
        if ctx.q.question.len() != 1 || ctx.q.question[0].qclass != CLASS_IN {
            return next.exec_next(ctx);
        }
        let org_name = ctx.q.question[0].name.clone();
        let target = match self.map.lookup(&org_name) {
            Some(t) => t.clone(),
            None => return next.exec_next(ctx),
        };
        ctx.note_f(|| format!("redirect->{}", target));
        ctx.q.question[0].name = target.clone();
        let r = next.exec_next(ctx);
        if let Some(resp) = ctx.r.as_mut() {
            for q in resp.question.iter_mut() {
                if q.name == target {
                    q.name = org_name.clone();
                }
            }
            let cname = RR {
                name: org_name,
                rtype: TYPE_CNAME,
                class: CLASS_IN,
                ttl: 1,
                rdata: RData::Name(target),
            };
            resp.answer.insert(0, cname);
        }
        r
    }
}

// ==================== forward ====================

/// 每个上游的通用选项（对齐 mosdns 的 UpstreamConfig）
#[derive(Clone, Default)]
pub struct UpOpts {
    pub server_name: Option<String>,
    pub bootstrap: Option<String>,
    pub http3: bool,
    pub insecure: bool,
    /// 空闲多久后丢弃长连接；None = 用协议默认（TCP/DoT 10s，DoH/H3/DoQ 30s）
    pub idle: Option<Duration>,
}

#[derive(Clone)]
pub enum Upstream {
    Udp(SocketAddr),
    Tcp {
        addr: SocketAddr,
        idle: Duration,
        pool: Arc<Mutex<Vec<(TcpStream, Instant)>>>,
    },
    /// DNS over QUIC（RFC 9250）
    Doq(Arc<crate::doq::DoqUpstream>),
    /// DNS over TLS（RFC 7858）
    Tls(Arc<crate::dot::DotUpstream>),
    /// DNS over HTTPS（RFC 8484，HTTP/2）
    Https(Arc<crate::doh::DohUpstream>),
    /// DNS over HTTPS over HTTP/3（DoH3）
    Https3(Arc<crate::doh3::DohH3Upstream>),
}

impl Upstream {
    pub fn parse(addr: &str) -> Result<Upstream, String> {
        Upstream::parse_full(addr, None)
    }

    pub fn parse_full(addr: &str, server_name: Option<&str>) -> Result<Upstream, String> {
        Upstream::parse_ex(
            addr,
            &UpOpts {
                server_name: server_name.map(|s| s.to_string()),
                ..Default::default()
            },
        )
    }

    pub fn parse_ex(addr: &str, opts: &UpOpts) -> Result<Upstream, String> {
        let server_name = opts.server_name.as_deref();
        let bootstrap = opts.bootstrap.as_deref();
        let http3 = opts.http3;
        let insecure = opts.insecure;
        let (scheme, rest) = match addr.split_once("://") {
            Some((s, r)) => (s, r),
            None => ("udp", addr),
        };
        // DoQ：允许写主机名（懒解析），默认端口 853
        if scheme == "quic" || scheme == "doq" {
            let (host, port) = split_host_port(rest, 853)?;
            let idle = opts.idle.unwrap_or(DEFAULT_IDLE_QUIC);
            let u = crate::doq::DoqUpstream::new(&host, port, server_name, insecure, idle, bootstrap)?;
            return Ok(Upstream::Doq(u));
        }
        // DoT：默认端口 853，SNI 默认取 host
        if scheme == "tls" || scheme == "dot" {
            let (host, port) = split_host_port(rest, 853)?;
            let idle = opts.idle.unwrap_or(DEFAULT_IDLE_STREAM);
            let u = crate::dot::DotUpstream::new(&host, port, server_name, bootstrap, insecure, idle)?;
            return Ok(Upstream::Tls(u));
        }
        // DoH3：h3:// 是 https+enable_http3 的简写（对齐官方 helper protocol）
        if scheme == "h3" || (scheme == "https" && http3) {
            let (host, port, path) = split_url_host_path(rest, 443)?;
            let idle = opts.idle.unwrap_or(DEFAULT_IDLE_HTTP);
            let u = crate::doh3::DohH3Upstream::new(&host, port, &path, bootstrap, insecure, idle)?;
            return Ok(Upstream::Https3(u));
        }
        // DoH：默认端口 443，路径取自 URL，HTTP/2
        if scheme == "https" || scheme == "h2" {
            let (host, port, path) = split_url_host_path(rest, 443)?;
            let idle = opts.idle.unwrap_or(DEFAULT_IDLE_HTTP);
            let u = crate::doh::DohUpstream::new(&host, port, &path, bootstrap, insecure, idle)?;
            return Ok(Upstream::Https(u));
        }
        let sa: SocketAddr = match rest.parse() {
            Ok(sa) => sa,
            Err(_) => {
                let host = rest.trim_start_matches('[').trim_end_matches(']');
                let ip: IpAddr = host
                    .parse()
                    .map_err(|_| format!("invalid upstream addr [{}]", addr))?;
                SocketAddr::new(ip, 53)
            }
        };
        match scheme {
            "udp" => Ok(Upstream::Udp(sa)),
            "tcp" => Ok(Upstream::Tcp {
                addr: sa,
                idle: opts.idle.unwrap_or(DEFAULT_IDLE_STREAM),
                pool: Arc::new(Mutex::new(Vec::new())),
            }),
            other => Err(format!(
                "unsupported upstream scheme [{}] (supported: udp / tcp / tls / https / h3 / quic)",
                other
            )),
        }
    }

    /// 用于日志/轨迹的可读名字
    pub fn name(&self) -> String {
        match self {
            Upstream::Udp(sa) => format!("udp://{}", sa),
            Upstream::Tcp { addr, .. } => format!("tcp://{}", addr),
            Upstream::Doq(u) => u.addr_desc(),
            Upstream::Tls(u) => u.addr_desc(),
            Upstream::Https(u) => u.addr_desc(),
            Upstream::Https3(u) => u.addr_desc(),
        }
    }

    fn query(&self, q: &Msg, timeout: Duration) -> Res<Msg> {
        match self {
            Upstream::Udp(sa) => query_udp(*sa, q, timeout),
            Upstream::Tcp { addr, idle, pool } => {
                query_tcp_pooled(*addr, pool, *idle, q, timeout)
            }
            Upstream::Doq(u) => u.query(q, timeout),
            Upstream::Tls(u) => u.query(q, timeout),
            Upstream::Https(u) => u.query(q, timeout),
            Upstream::Https3(u) => u.query(q, timeout),
        }
    }
}

/// TCP 连接空闲超过这个时间就不再复用（原版 mosdns 默认 idle_timeout 60s，这里取 55s 留余量）。
/// mosdns 的 defaultIdleTimeout（TCP/DoT）
pub const DEFAULT_IDLE_STREAM: Duration = Duration::from_secs(10);
/// mosdns 的 DoH idleConnTimeout 默认值（DoH/H3/DoQ 沿用）
pub const DEFAULT_IDLE_HTTP: Duration = Duration::from_secs(30);
pub const DEFAULT_IDLE_QUIC: Duration = Duration::from_secs(30);
const TCP_POOL_MAX: usize = 8;

fn query_udp(addr: SocketAddr, q: &Msg, timeout: Duration) -> Res<Msg> {
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).map_err(|e| format!("udp bind: {}", e))?;
    // connect 一下（不发包）：这样 ICMP 端口不可达会立刻变成 ECONNREFUSED，
    // 死上游能毫秒级判死，而不是干等满超时；内核也会过滤掉其它来源的回包。
    sock.connect(addr)
        .map_err(|e| format!("udp connect {}: {}", addr, e))?;
    let mut q2 = q.clone();
    q2.id = next_id();
    let bytes = q2.pack();
    sock.send(&bytes)
        .map_err(|e| format!("udp send: {}", e))?;

    // 与 smartdns 的 500ms 切片对齐：500ms 没收到应答就重发同一份报文（同一 ID，迟到的应答仍能匹配），
    // 总超时仍然由调用方给出的 timeout 控制。
    const RESEND_EVERY: Duration = Duration::from_millis(500);
    let start = Instant::now();
    let mut last_send = start;
    let mut buf = vec![0u8; 65535];
    loop {
        let now = Instant::now();
        let elapsed = now.duration_since(start);
        if elapsed >= timeout {
            return Err("udp exchange timeout".to_string());
        }
        if now.duration_since(last_send) >= RESEND_EVERY {
            let _ = sock.send(&bytes);
            last_send = now;
        }
        let slice = Duration::from_millis(200).min(timeout - elapsed);
        sock.set_read_timeout(Some(slice)).ok();
        match sock.recv(&mut buf) {
            Ok(n) => {
                if n < 12 {
                    continue;
                }
                if let Ok(mut r) = Msg::parse(&buf[..n]) {
                    if r.id == q2.id {
                        r.id = q.id;
                        return Ok(r);
                    }
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                _ => return Err(format!("udp recv: {}", e)),
            },
        }
    }
}

fn tcp_exchange(stream: &mut TcpStream, q: &Msg, timeout: Duration) -> Res<Msg> {
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut q2 = q.clone();
    q2.id = next_id();
    let bytes = q2.pack();
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(&bytes);
    stream
        .write_all(&framed)
        .map_err(|e| format!("tcp write: {}", e))?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut
        {
            "upstream read timeout".to_string()
        } else {
            format!("tcp read len: {}", e)
        }
    })?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len < 12 {
        return Err("tcp response too short".to_string());
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("tcp read body: {}", e))?;
    let mut r = Msg::parse(&buf)?;
    r.id = q.id;
    Ok(r)
}

/// 复用连接（与原版 mosdns 的 idle reuse 行为对齐）；连接失效时用新连接重试一次。
fn query_tcp_pooled(
    addr: SocketAddr,
    pool: &Arc<Mutex<Vec<(TcpStream, Instant)>>>,
    idle: Duration,
    q: &Msg,
    timeout: Duration,
) -> Res<Msg> {
    for attempt in 0..2 {
        let reused = if attempt == 0 {
            let mut g = match pool.lock() {
                Ok(g) => g,
                Err(_) => return Err("tcp pool poisoned".to_string()),
            };
            let now = Instant::now();
            let mut found = None;
            while let Some((s, idle_since)) = g.pop() {
                let age = now.duration_since(idle_since);
                if age < idle {
                    found = Some(s);
                    break;
                }
                if crate::log::enabled(crate::log::LV_DEBUG) {
                    crate::log::debug(format!(
                        "tcp 池中连接空闲 {:?} ≥ idle_timeout {:?}，丢弃重建",
                        age, idle
                    ));
                }
            }
            found
        } else {
            None
        };

        let (mut stream, was_reused) = match reused {
            Some(s) => (s, true),
            None => (
                TcpStream::connect_timeout(&addr, timeout)
                    .map_err(|e| format!("tcp connect: {}", e))?,
                false,
            ),
        };

        match tcp_exchange(&mut stream, q, timeout) {
            Ok(r) => {
                if let Ok(mut g) = pool.lock() {
                    if g.len() < TCP_POOL_MAX {
                        g.push((stream, Instant::now()));
                    }
                }
                return Ok(r);
            }
            Err(e) => {
                // 复用的连接可能已被上游关掉：换新连接再试一次
                if was_reused && attempt == 0 {
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err("tcp exchange failed".to_string())
}

#[inline]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 同一个上游的失败日志限频（60s 一条），避免坏上游刷爆日志
fn log_upstream_fail(name: &str, msg: &str) {
    if !log::enabled(log::LV_WARN) {
        return;
    }
    static LAST: std::sync::OnceLock<Mutex<HashMap<String, u64>>> = std::sync::OnceLock::new();
    let map = LAST.get_or_init(|| Mutex::new(HashMap::new()));
    let now = now_ms();
    if let Ok(mut g) = map.lock() {
        let last = g.entry(name.to_string()).or_insert(0);
        if now.saturating_sub(*last) < FAIL_LOG_INTERVAL_MS {
            return;
        }
        *last = now;
    }
    log::warn(format!("upstream {} 查询失败：{}", name, msg));
}

#[derive(Clone)]
pub struct UpstreamSlot {
    pub up: Upstream,
}

/// 单个上游的超时（沿用 mosdns 的 queryTimeout）
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// 一轮派发后等待多久再重发（smartdns 的 DNS_QUERY_TIMEOUT = 500ms）
const WAVE_INTERVAL: Duration = Duration::from_millis(500);
/// 最多重发几轮（smartdns 是 4 轮 ≈ 2s，之后仍等已派发的响应直到总超时）
const MAX_WAVES: usize = 4;
/// 上游并发上限（用户要求提到 5；官方是 3）
pub const MAX_CONCURRENT: usize = 5;
/// 同一个上游的失败日志最多每 60s 打一条（免得坏上游把日志刷爆）
const FAIL_LOG_INTERVAL_MS: u64 = 60_000;

pub struct Forward {
    pub upstreams: Vec<UpstreamSlot>,
    pub concurrent: usize,
}

/// 一次 forward 的执行过程（只在 debug 下填充，用于日志与失败落盘）
#[derive(Default)]
pub struct ForwardInfo {
    pub winner: String,
    pub waves: u8,
    pub attempts: Vec<String>,
}

impl Forward {
    fn exchange(&self, q: &Msg, budget: Duration, info: &mut ForwardInfo) -> Res<Msg> {
        let dbg = crate::log::enabled(crate::log::LV_DEBUG);
        let t0 = Instant::now();
        if self.upstreams.is_empty() {
            return Err("no upstream to exchange".to_string());
        }
        let n = self.upstreams.len();
        let mcq = self.concurrent.max(1).min(MAX_CONCURRENT);
        let take = mcq.min(n);
        let deadline = Instant::now() + budget;

        // 不做"临时禁用"：上游失败就失败，反正其它上游会先答；
        // 全部失败时也只是多等一轮预算（deadline），不会静默丢弃查询。
        let mut cand: Vec<usize> = (0..n).collect();
        let _ = now_ms(); // 保持 now_ms 的其他用途不变
        let start = rand_usize(cand.len());
        let picked: Vec<usize> = (0..take.min(cand.len()))
            .map(|k| cand[(start + k) % cand.len()])
            .collect();

        let (tx, rx) = mpsc::channel::<(Res<Msg>, String, usize)>();
        let mut errs: Vec<String> = Vec::new();
        let mut bad: Option<(Msg, String)> = None;
        // 按"不同上游"去重统计坏 rcode：同一上游在后续波次里重复应答不能算
        // （否则一个快速吐 SERVFAIL 的上游会让另外两个还没回话的上游被误判）
        let mut bad_seen = vec![false; n];
        let mut bad_distinct = 0usize;
        // 硬失败（连接拒绝/重置）去重统计：这类错误再重发也没用，全员失败就该立刻返回，
        // 而不是傻等到 5s 预算耗尽（原版 mosdns 也是收满 concurrent 个结果就返回）。
        let mut err_seen = vec![false; n];
        let mut err_distinct = 0usize;
        let mut waves = 0usize;
        let mut next_wave = Instant::now();

        while Instant::now() < deadline {
            // 每 500ms 再派发一轮（对齐 smartdns 的短切片重试）
            if waves < MAX_WAVES && Instant::now() >= next_wave {
                for &i in &picked {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let slot = self.upstreams[i].clone();
                    let nm = slot.up.name();
                    let q2 = q.clone();
                    let tx2 = tx.clone();
                    std::thread::spawn(move || {
                        let r = slot.up.query(&q2, remaining);
                        // 失败日志放在这里：竞速输掉的结果会被丢弃，
                        // 只有在线程里记才看得到"上游为什么坏"。
                        if let Err(e) = &r {
                            log_upstream_fail(&nm, e);
                        }
                        let _ = tx2.send((r, slot.up.name(), i));
                    });
                }
                waves += 1;
                info.waves = waves.min(255) as u8;
                next_wave = Instant::now() + WAVE_INTERVAL;
            }

            let now = Instant::now();
            let until_deadline = deadline.saturating_duration_since(now);
            let wait = if waves >= MAX_WAVES {
                until_deadline
            } else {
                next_wave.saturating_duration_since(now).min(until_deadline)
            };
            if wait.is_zero() {
                continue;
            }

            match rx.recv_timeout(wait) {
                Ok((Ok(m), name, _idx)) => {
                    // 与 mosdns v5.2+ 对齐：只有 NOERROR / NXDOMAIN 立即采用，
                    // 坏 rcode 继续等别的上游；全部都是坏 rcode 时用最后一个兜底。
                    if m.rcode() == RCODE_NOERROR || m.rcode() == RCODE_NXDOMAIN {
                        info.winner = name.clone();
                        if dbg {
                            info.attempts.push(format!(
                                "{} ok rcode={} ans={} @{}ms",
                                name,
                                m.rcode(),
                                m.answer.len(),
                                t0.elapsed().as_millis()
                            ));
                        }
                        return Ok(m);
                    }
                    if crate::log::enabled(crate::log::LV_DEBUG) {
                        let qname = q
                            .question
                            .first()
                            .map(|x| x.name.clone())
                            .unwrap_or_default();
                        crate::log::debug(format!(
                            "upstream {} returned rcode {} for {}, waiting next upstream",
                            name,
                            m.rcode(),
                            qname
                        ));
                    }
                    if dbg {
                        info.attempts.push(format!(
                            "{} bad rcode={} @{}ms",
                            name,
                            m.rcode(),
                            t0.elapsed().as_millis()
                        ));
                    }
                    errs.push(format!("{}: bad rcode {}", name, m.rcode()));
                    if let Some(flag) = bad_seen.get_mut(_idx) {
                        if !*flag {
                            *flag = true;
                            bad_distinct += 1;
                        }
                    }
                    if bad_distinct >= take {
                        // 这一批上游集体给了坏 rcode：直接采用最后一个（与 mosdns 只等
                        // concurrent 个响应的语义一致），别把整条预算耗到 5s
                        if dbg {
                            info.attempts.push(format!(
                                "{} 个不同上游都回了坏 rcode（本次选中 {} 个），提前放弃",
                                bad_distinct, take
                            ));
                        }
                        info.winner = name;
                        return Ok(m);
                    }
                    bad = Some((m, name));
                }
                Ok((Err(e), name, _idx)) => {
                    if dbg {
                        info.attempts.push(format!(
                            "{} err @{}ms: {}",
                            name,
                            t0.elapsed().as_millis(),
                            e
                        ));
                    }
                    errs.push(format!("{}: {}", name, e));
                    if let Some(f) = err_seen.get_mut(_idx) {
                        if !*f {
                            *f = true;
                            err_distinct += 1;
                        }
                    }
                    if err_distinct >= take && bad.is_none() {
                        // 被选中的上游全部硬失败，没有等待的价值
                        if dbg {
                            info.attempts.push(format!(
                                "{} 个不同上游都硬失败，立即返回（不空等预算）",
                                err_distinct
                            ));
                        }
                        return Err(format!("all upstreams failed: {:?}", errs));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        if let Some((m, name)) = bad {
            info.winner = name;
            return Ok(m);
        }
        if errs.is_empty() {
            // 全部上游都在总超时前没回包（解析/握手卡住时常这样），给个可读的原因
            Err(format!(
                "all upstreams failed: no result within {:?}",
                budget
            ))
        } else {
            Err(format!("all upstreams failed: {:?}", errs))
        }
    }
}

impl Exec for Forward {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        // 预算不能超过本次查询的剩余截止时间：一条链里可能有两次 forward
        // （local 被 drop_resp 后再走 remote），各自 5s 会让客户端等到 10s。
        let budget = QUERY_TIMEOUT.min(ctx.deadline.saturating_duration_since(Instant::now()));
        if budget < Duration::from_millis(50) {
            return Err("query deadline exceeded before forward".to_string());
        }
        let q = ctx.q.clone();
        let mut info = ForwardInfo::default();
        let r = self.exchange(&q, budget, &mut info);
        ctx.tries = ctx.tries.saturating_add(info.waves);
        let winner = info.winner.clone();
        if !info.attempts.is_empty() {
            // 累加：一条链上可能有两次 forward（local → remote），不能被后者覆盖
            ctx.attempts.extend(info.attempts);
        }
        let resp = r?;
        ctx.note_f(|| format!("fwd[{}]", winner));
        ctx.set_resp(resp);
        Ok(())
    }
}

// ==================== ipset exec ====================

pub struct IpSetExec {
    pub set4: Option<String>,
    pub mask4: u8,
    pub set6: Option<String>,
    pub mask6: u8,
}

impl IpSetExec {
    /// QuickSetup format: `set_name,{inet|inet6},mask`
    pub fn parse(args: &str) -> Result<IpSetExec, String> {
        let fs: Vec<&str> = args.split_whitespace().collect();
        if fs.len() > 2 {
            return Err(format!("expect no more than 2 fields, got {}", fs.len()));
        }
        let mut e = IpSetExec {
            set4: None,
            mask4: 24,
            set6: None,
            mask6: 32,
        };
        for a in fs {
            let ss: Vec<&str> = a.split(',').collect();
            if ss.len() != 3 {
                return Err(format!("invalid ipset args [{}]", a));
            }
            let mask: u8 = ss[2].parse().map_err(|_| "invalid mask".to_string())?;
            match ss[1] {
                "inet" => {
                    e.set4 = Some(ss[0].to_string());
                    e.mask4 = if mask == 0 { 24 } else { mask };
                }
                "inet6" => {
                    e.set6 = Some(ss[0].to_string());
                    e.mask6 = if mask == 0 { 32 } else { mask };
                }
                other => return Err(format!("invalid set family [{}]", other)),
            }
        }
        Ok(e)
    }

}

impl Exec for IpSetExec {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        let r = match ctx.r.as_ref() {
            Some(r) => r,
            None => return Ok(()),
        };
        let mut jobs: Vec<(String, IpAddr, u8)> = Vec::new();
        for rr in &r.answer {
            match (&rr.rdata, rr.rtype) {
                (RData::A(ip), _) => {
                    if let Some(set) = &self.set4 {
                        jobs.push((set.clone(), IpAddr::V4(*ip), self.mask4));
                    }
                }
                (RData::Aaaa(ip), _) => {
                    if let Some(set) = &self.set6 {
                        jobs.push((set.clone(), IpAddr::V6(*ip), self.mask6));
                    }
                }
                _ => {}
            }
        }
        if !jobs.is_empty() {
            ctx.note_f(|| format!("ipset({})", jobs.len()));
        }
        for (set, ip, mask) in jobs {
            crate::ipset::add(&set, ip, mask)?;
        }
        Ok(())
    }
}

// ==================== ttl ====================

pub struct TtlExec {
    pub fix: u32,
    pub min: u32,
    pub max: u32,
}

impl TtlExec {
    /// QuickSetup format: `{min-max|fix}`
    pub fn parse(s: &str) -> Result<TtlExec, String> {
        let s = s.trim();
        match s.split_once('-') {
            Some((l, u)) => {
                let l: u32 = l.parse().map_err(|_| "invalid lower bound".to_string())?;
                let u: u32 = u.parse().map_err(|_| "invalid upper bound".to_string())?;
                Ok(TtlExec { fix: 0, min: l, max: u })
            }
            None => {
                let f: u32 = s.parse().map_err(|_| "invalid ttl".to_string())?;
                Ok(TtlExec { fix: f, min: 0, max: 0 })
            }
        }
    }
}

impl Exec for TtlExec {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        ctx.note("ttl");
        if let Some(r) = ctx.r.as_mut() {
            if self.fix > 0 {
                r.set_ttl(self.fix);
            } else {
                if self.min > 0 {
                    r.apply_min_ttl(self.min);
                }
                if self.max > 0 {
                    r.apply_max_ttl(self.max);
                }
            }
        }
        Ok(())
    }
}

// ==================== black_hole ====================

pub struct BlackHole {
    v4: Vec<std::net::Ipv4Addr>,
    v6: Vec<std::net::Ipv6Addr>,
}

impl BlackHole {
    pub fn parse(args: &str) -> Result<BlackHole, String> {
        let mut b = BlackHole {
            v4: vec![],
            v6: vec![],
        };
        for s in args.split_whitespace() {
            let a: IpAddr = s.parse().map_err(|_| format!("invalid ip addr [{}]", s))?;
            match a {
                IpAddr::V4(v) => b.v4.push(v),
                IpAddr::V6(v) => b.v6.push(v),
            }
        }
        Ok(b)
    }
}

impl Exec for BlackHole {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        if ctx.q.question.len() != 1 {
            return Ok(());
        }
        let q = &ctx.q.question[0];
        let name = q.name.clone();
        if q.qtype == TYPE_A && !self.v4.is_empty() {
            ctx.note("blackhole");
            let mut r = ctx.q.set_reply(RCODE_NOERROR);
            for ip in &self.v4 {
                r.answer.push(RR {
                    name: name.clone(),
                    rtype: TYPE_A,
                    class: CLASS_IN,
                    ttl: 300,
                    rdata: RData::A(*ip),
                });
            }
            ctx.set_resp(r);
        } else if q.qtype == TYPE_AAAA && !self.v6.is_empty() {
            ctx.note("blackhole");
            let mut r = ctx.q.set_reply(RCODE_NOERROR);
            for ip in &self.v6 {
                r.answer.push(RR {
                    name: name.clone(),
                    rtype: TYPE_AAAA,
                    class: CLASS_IN,
                    ttl: 300,
                    rdata: RData::Aaaa(*ip),
                });
            }
            ctx.set_resp(r);
        }
        Ok(())
    }
}

// ==================== prefer_ipv4 (dual selector) ====================

/// prefer_ipv4：对齐 mosdns v5.3.0 的 dual_selector 缓存
/// key = 归一化 qname，value = (是否应屏蔽 AAAA, 写入时刻)，TTL 1 小时。
const PREFER_CACHE_TTL: Duration = Duration::from_secs(3600);
const PREFER_CACHE_MAX: usize = 8192;

pub struct PreferIpv4 {
    /// `only_ipv4` 模式：AAAA 一律回 NODATA（NOERROR + 空 answer + SOA，smartdns 风格）
    ipv4_only: bool,
    cache: Mutex<HashMap<String, (bool, Instant)>>,
}

impl PreferIpv4 {
    pub fn new(ipv4_only: bool) -> PreferIpv4 {
        PreferIpv4 {
            ipv4_only,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache_get(&self, key: &str) -> Option<bool> {
        let g = self.cache.lock().ok()?;
        match g.get(key) {
            Some((v, t)) if t.elapsed() < PREFER_CACHE_TTL => Some(*v),
            _ => None,
        }
    }

    fn cache_put(&self, key: String, block: bool) {
        if let Ok(mut g) = self.cache.lock() {
            if g.len() >= PREFER_CACHE_MAX {
                g.clear();
            }
            g.insert(key, (block, Instant::now()));
        }
    }
}

impl RExec for PreferIpv4 {
    fn exec(&self, ctx: &mut QCtx, next: &Walker) -> Res {
        if ctx.q.question.len() != 1 {
            return next.exec_next(ctx);
        }
        let qtype = ctx.q.question[0].qtype;
        if qtype != TYPE_AAAA {
            return next.exec_next(ctx);
        }

        // only_ipv4 模式：AAAA 直接返回 NODATA，不查上游
        if self.ipv4_only {
            ctx.note("only_ipv4(soa)");
            let r = crate::dns::no_data_reply(&ctx.q);
            ctx.set_resp(r);
            return Ok(());
        }

        // 命中缓存：直接按上次的双栈探测结果处理，不再发参考查询
        let qname = normalize_domain(&ctx.q.question[0].name);
        if let Some(block) = self.cache_get(&qname) {
            if block {
                ctx.note("prefer_v4(block,cached)");
                let r = gen_empty_reply(&ctx.q, RCODE_NOERROR);
                ctx.set_resp(r);
                return Ok(());
            }
            ctx.note("prefer_v4(pass,cached)");
            return next.exec_next(ctx);
        }

        let mut ref_ctx = ctx.copy_ctx();
        ref_ctx.q.question[0].qtype = TYPE_A;
        let mut org_ctx = ctx.copy_ctx();
        let deadline = ctx.deadline;

        let (tx_ref, rx_ref) = mpsc::channel::<bool>();
        let (tx_org, rx_org) = mpsc::channel::<(Res, Option<Msg>)>();

        {
            let next = next.clone();
            std::thread::spawn(move || {
                let mut c = ref_ctx;
                let e = next.exec_next(&mut c);
                let has = e.is_ok() && c.r.as_ref().map(|m| m.has_rr(TYPE_A)).unwrap_or(false);
                let _ = tx_ref.send(has);
            });
        }
        {
            let next = next.clone();
            std::thread::spawn(move || {
                let mut c = org_ctx;
                let e = next.exec_next(&mut c);
                let _ = tx_org.send((e, c.r));
            });
        }

        let mut ref_state: Option<bool> = None;
        let mut org_res: Option<(Res, Option<Msg>)> = None;
        let mut org_done_at: Option<Instant> = None;

        loop {
            if ref_state.is_none() {
                if let Ok(v) = rx_ref.try_recv() {
                    ref_state = Some(v);
                }
            }
            if org_res.is_none() {
                if let Ok(v) = rx_org.try_recv() {
                    org_res = Some(v);
                    org_done_at = Some(Instant::now());
                }
            }
            // reference says "block AAAA"
            if ref_state == Some(true) {
                ctx.note("prefer_v4(block)");
                self.cache_put(qname.clone(), true);
                let r = gen_empty_reply(&ctx.q, RCODE_NOERROR);
                ctx.set_resp(r);
                return Ok(());
            }
            if org_res.is_some() {
                match ref_state {
                    Some(false) => {
                        ctx.note("prefer_v4(pass)");
                        self.cache_put(qname.clone(), false);
                        let (e, r) = org_res.take().unwrap();
                        apply_branch(ctx, r);
                        return e;
                    }
                    None => {
                        let waited = org_done_at.map(|t| t.elapsed()).unwrap_or_default();
                        if waited >= Duration::from_millis(500) {
                            ctx.note("prefer_v4(pass,no-ref)");
                            let (e, r) = org_res.take().unwrap();
                            apply_branch(ctx, r);
                            return e;
                        }
                    }
                    Some(true) => unreachable!(),
                }
            }
            if Instant::now() >= deadline {
                return Err("prefer_ipv4: deadline exceeded".to_string());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn apply_branch(ctx: &mut QCtx, r: Option<Msg>) {
    ctx.r = r;
    ctx.resp_gen += 1;
}

// ==================== fallback ====================

pub struct Fallback {
    pub primary: Arc<dyn Exec>,
    pub secondary: Arc<dyn Exec>,
    pub threshold: Duration,
    pub always_standby: bool,
}

impl Exec for Fallback {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        let p_ctx = ctx.copy_ctx();
        let s_ctx = ctx.copy_ctx();
        let (tx, rx) = mpsc::channel::<Option<Msg>>();

        let (tx_p, tx_s) = (tx.clone(), tx.clone());
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let (fail_tx, _fail_rx) = mpsc::channel::<()>();
        let prim = self.primary.clone();
        let sec = self.secondary.clone();
        let threshold = self.threshold;
        let always = self.always_standby;

        {
            let mut c = p_ctx;
            std::thread::spawn(move || {
                let e = prim.exec(&mut c);
                match (e, c.r) {
                    (Ok(()), Some(r)) => {
                        let _ = done_tx.send(());
                        let _ = tx_p.send(Some(r));
                    }
                    _ => {
                        let _ = fail_tx.send(());
                        let _ = tx_p.send(None);
                    }
                }
            });
        }
        {
            let mut c = s_ctx;
            std::thread::spawn(move || {
                if !always {
                    match done_rx.recv_timeout(threshold) {
                        Ok(()) => return,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {}
                    }
                }
                let e = sec.exec(&mut c);
                let r = match e {
                    Ok(()) => c.r,
                    Err(_) => None,
                };
                let _ = tx_s.send(r);
            });
        }
        drop(tx);

        for _ in 0..2 {
            if Instant::now() >= ctx.deadline {
                return Err("fallback: deadline exceeded".to_string());
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(r)) => {
                    ctx.note("fallback(ok)");
                    ctx.set_resp(r);
                    return Ok(());
                }
                Ok(None) => continue,
                Err(_) => {
                    if Instant::now() >= ctx.deadline {
                        return Err("fallback: deadline exceeded".to_string());
                    }
                }
            }
        }
        Err("no valid response from both primary and secondary".to_string())
    }
}

// ==================== matchers ====================

pub struct QNameMatcher {
    pub set: DomainSet,
}

impl Matcher for QNameMatcher {
    fn matches(&self, ctx: &QCtx) -> Res<bool> {
        for q in &ctx.q.question {
            if self.set.matches(&q.name) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub struct QTypeMatcher {
    pub types: HashSet<u16>,
}

impl QTypeMatcher {
    pub fn parse(args: &str) -> Result<QTypeMatcher, String> {
        let mut types = HashSet::new();
        for (i, s) in args.split_whitespace().enumerate() {
            let n: u16 = s
                .parse()
                .map_err(|_| format!("arg #{} is not an int", i))?;
            types.insert(n);
        }
        Ok(QTypeMatcher { types })
    }
}

impl Matcher for QTypeMatcher {
    fn matches(&self, ctx: &QCtx) -> Res<bool> {
        for q in &ctx.q.question {
            if self.types.contains(&q.qtype) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub struct ClientIpMatcher {
    pub set: Arc<IpSet>,
}

impl Matcher for ClientIpMatcher {
    fn matches(&self, ctx: &QCtx) -> Res<bool> {
        match ctx.client {
            Some(ip) => Ok(self.set.contains(ip)),
            None => Ok(false),
        }
    }
}

pub struct RespIpMatcher {
    pub set: Arc<IpSet>,
}

impl Matcher for RespIpMatcher {
    fn matches(&self, ctx: &QCtx) -> Res<bool> {
        let r = match ctx.r.as_ref() {
            Some(r) => r,
            None => return Ok(false),
        };
        for rr in &r.answer {
            match rr.rdata {
                RData::A(ip) => {
                    if self.set.contains(IpAddr::V4(ip)) {
                        return Ok(true);
                    }
                }
                RData::Aaaa(ip) => {
                    if self.set.contains(IpAddr::V6(ip)) {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }
}

pub fn log_query_err(tag: &str, e: &str) {
    log::warn(format!("[{}] {}", tag, e));
}
