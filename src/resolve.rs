//! 上游主机名解析（支持 `bootstrap` 指定解析服务器）。
//!
//! 优先级：
//! 1. addr 里直接是 IP → 直接返回；
//! 2. 配置了 `bootstrap: <ip[:port]>` → 用纯 UDP 向它查 A 记录（避免冷启动时本机就是唯一 DNS）；
//! 3. 否则用系统 resolver（`to_socket_addrs`）。
//!
//! 结果由调用方缓存（每个上游自己拿 1 小时）。

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::dns::{Msg, RData, TYPE_A};

/// 用指定 DNS 服务器查全部 A 记录
fn query_a_via(server: SocketAddr, host: &str, timeout: Duration) -> Result<Vec<IpAddr>, String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bootstrap bind: {}", e))?;
    sock.set_read_timeout(Some(timeout)).ok();

    let mut q = Msg::default();
    q.id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1) & 0xffff) as u16;
    q.question.push(crate::dns::Question {
        name: host.trim_end_matches('.').to_string(),
        qtype: TYPE_A,
        qclass: 1,
    });
    let bytes = q.pack();
    sock.send_to(&bytes, server)
        .map_err(|e| format!("bootstrap send {}: {}", server, e))?;

    let mut buf = vec![0u8; 4096];
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return Err(format!("bootstrap query {} via {}: timeout", host, server));
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Ok(r) = Msg::parse(&buf[..n]) {
                    let mut ips: Vec<IpAddr> = Vec::new();
                    for rr in &r.answer {
                        if let RData::A(ip) = rr.rdata {
                            let v = IpAddr::V4(ip);
                            if !ips.contains(&v) {
                                ips.push(v);
                            }
                        }
                    }
                    if ips.is_empty() {
                        return Err(format!(
                            "bootstrap query {} via {}: no A record",
                            host, server
                        ));
                    }
                    return Ok(ips);
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                _ => return Err(format!("bootstrap recv: {}", e)),
            },
        }
    }
}

/// 解析上游地址的**全部**候选（按 DNS 返回顺序）。
///
/// 上游域名常有多条 A 记录（例如 dns.alidns.com → 223.5.5.5 / 223.6.6.6），
/// 而其中某一条可能不提供该协议的服（实测 223.6.6.6:853 不支持 DoQ）。
/// 只取第一条会导致"缓存一个坏地址 1 小时"，所以调用方应该拿全量再逐个试。
pub fn resolve_all(
    host: &str,
    port: u16,
    bootstrap: Option<&str>,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let ips: Vec<IpAddr> = if let Some(bs) = bootstrap.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let sa: SocketAddr = match bs.parse() {
            Ok(sa) => sa,
            Err(_) => {
                let ip: IpAddr = bs
                    .parse()
                    .map_err(|_| format!("invalid bootstrap addr [{}]", bs))?;
                SocketAddr::new(ip, 53)
            }
        };
        query_a_via(sa, host, timeout)?
    } else {
        let mut v: Vec<IpAddr> = Vec::new();
        for sa in (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {}: {}", host, e))?
        {
            if !v.contains(&sa.ip()) {
                v.push(sa.ip());
            }
        }
        if v.is_empty() {
            return Err(format!("resolve {}: no address", host));
        }
        v
    };
    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

/// 解析上游地址。`bootstrap` 形如 `223.5.5.5` 或 `223.5.5.5:53`。
pub fn resolve(
    host: &str,
    port: u16,
    bootstrap: Option<&str>,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(bs) = bootstrap.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let sa: SocketAddr = match bs.parse() {
            Ok(sa) => sa,
            Err(_) => {
                let ip: IpAddr = bs
                    .parse()
                    .map_err(|_| format!("invalid bootstrap addr [{}]", bs))?;
                SocketAddr::new(ip, 53)
            }
        };
        let ips = query_a_via(sa, host, timeout)?;
        return Ok(SocketAddr::new(ips[0], port));
    }
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", host, e))?
        .next()
        .ok_or_else(|| format!("resolve {}: no address", host))
}

/// 上游地址选择器：多地址 + 故障切换 + 1 小时缓存（DoH / DoT / DoH3 / DoQ 共用）。
///
/// 背景：上游域名常有多条 A 记录，其中某一条可能不提供该协议的服务
/// （实测 dns.alidns.com 的 223.6.6.6:853 不支持 DoQ）。只取第一条并缓存 1 小时，
/// 会让该上游整整一小时不可用，所以这里保存全量并按"上次成功的地址"轮转。
pub struct AddrPicker {
    host: String,
    port: u16,
    bootstrap: Option<String>,
    fixed: Option<SocketAddr>,
    state: std::sync::Mutex<Option<(Vec<SocketAddr>, usize, std::time::Instant)>>,
}

const PICKER_TTL: Duration = Duration::from_secs(3600);

impl AddrPicker {
    pub fn new(host: &str, port: u16, bootstrap: Option<&str>) -> AddrPicker {
        let fixed = host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, port));
        AddrPicker {
            host: host.to_string(),
            port,
            bootstrap: bootstrap.map(|s| s.to_string()),
            fixed,
            state: std::sync::Mutex::new(None),
        }
    }

    /// 本次要试的候选列表，按"上次成功的地址优先"轮转；每项是 (缓存下标, 地址)。
    pub fn candidates(&self, timeout: Duration) -> Result<Vec<(usize, SocketAddr)>, String> {
        if let Some(sa) = self.fixed {
            return Ok(vec![(0, sa)]);
        }
        {
            let g = self.state.lock().unwrap();
            if let Some((addrs, cur, t)) = g.as_ref() {
                if t.elapsed() < PICKER_TTL {
                    return Ok(rotate(addrs, *cur));
                }
            }
        }
        let addrs = resolve_all(&self.host, self.port, self.bootstrap.as_deref(), timeout)?;
        crate::log::debug(format!(
            "{} 解析 -> {}",
            self.host,
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
        *self.state.lock().unwrap() = Some((addrs.clone(), 0, std::time::Instant::now()));
        Ok(rotate(&addrs, 0))
    }

    pub fn mark_good(&self, idx: usize) {
        let mut g = self.state.lock().unwrap();
        if let Some((addrs, cur, _)) = g.as_mut() {
            if *cur != idx && idx < addrs.len() {
                *cur = idx;
            }
        }
    }

    pub fn mark_bad(&self, idx: usize) {
        let mut g = self.state.lock().unwrap();
        if let Some((addrs, cur, _)) = g.as_mut() {
            if *cur == idx && addrs.len() > 1 {
                *cur = (idx + 1) % addrs.len();
            }
        }
    }

    /// 全部候选都失败：丢掉缓存，下次重新解析
    pub fn invalidate(&self) {
        if self.fixed.is_none() {
            *self.state.lock().unwrap() = None;
        }
    }
}

fn rotate(addrs: &[SocketAddr], cur: usize) -> Vec<(usize, SocketAddr)> {
    let n = addrs.len();
    (0..n)
        .map(|k| {
            let i = (cur + k) % n;
            (i, addrs[i])
        })
        .collect()
}
