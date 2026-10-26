//! DNS-over-QUIC 上游（RFC 9250）。
//!
//! 用 quinn + rustls。对外是阻塞接口：调用方（forward 的工作线程）直接 `query()`，
//! 内部用 tokio runtime 驱动异步 IO。
//!
//! 要点：
//! - 报文必须把 DNS Message ID 置 0（RFC 9250 §4.2），响应回来后恢复成客户端原始 ID；
//! - 每个查询一条双向流，报文用 2 字节长度前缀分帧（与 TCP 相同）；
//! - 连接复用：一条 QUIC 连接可承载多路流；连接挂了下次查询自动重连；
//! - SNI/证书校验名默认取 addr 里的主机名，可用 `server_name` 覆盖（addr 写 IP 时很有用）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns::Msg;
use crate::log;

const DOQ_ALPN: &[u8] = b"doq";
const RESOLVE_TTL: Duration = Duration::from_secs(3600);

pub struct DoqUpstream {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    bootstrap: Option<String>,
    endpoint: quinn::Endpoint,
    rt: tokio::runtime::Runtime,
    conn: Mutex<Option<quinn::Connection>>,
    /// (候选地址列表, 上次成功的下标, 解析时间)
    resolved: Mutex<Option<(Vec<SocketAddr>, usize, Instant)>>,
}

impl DoqUpstream {
    pub fn new(
        host: &str,
        port: u16,
        server_name: Option<&str>,
        insecure: bool,
        idle: Duration,
        bootstrap: Option<&str>,
    ) -> Result<Arc<DoqUpstream>, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("doq")
            .build()
            .map_err(|e| format!("doq runtime: {}", e))?;

        let sn = server_name
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.to_string());

        let tls_arc = crate::dot::build_client_config(Some(DOQ_ALPN), insecure)?;
        let tls = (*tls_arc).clone();
        // 会话恢复：rustls 的 ClientConfig 默认就是 Resumption::in_memory_sessions(256)，
        // 即重连时用 PSK 恢复握手（省掉证书验证）。这里保持默认，不额外配置。
        // 0-RTT 未启用（需要 enable_early_data = true + quinn 的 into_0rtt()）。

        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| format!("doq quic config: {}", e))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(qcc));
        // QUIC 连接的空闲超时（默认 30s，对齐 mosdns 的 idle_timeout 语义）
        let mut tc = quinn::TransportConfig::default();
        if let Ok(v) = quinn::IdleTimeout::try_from(idle) {
            tc.max_idle_timeout(Some(v));
        }
        client_cfg.transport_config(Arc::new(tc));

        let _guard = rt.enter();
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("doq endpoint: {}", e))?;
        endpoint.set_default_client_config(client_cfg);
        drop(_guard);

        Ok(Arc::new(DoqUpstream {
            host: host.to_string(),
            port,
            server_name: sn,
            bootstrap: bootstrap.map(|s| s.to_string()),
            endpoint,
            rt,
            conn: Mutex::new(None),
            resolved: Mutex::new(None),
        }))
    }

    pub fn addr_desc(&self) -> String {
        format!("quic://{}:{}", self.host, self.port)
    }

    /// 解析上游的**全部**候选地址（带 1 小时缓存）。
    /// 返回 (地址列表, 上次成功的下标)。
    fn resolve(&self, timeout: Duration) -> Result<(Vec<SocketAddr>, usize), String> {
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            return Ok((vec![SocketAddr::new(ip, self.port)], 0));
        }
        {
            let g = self.resolved.lock().unwrap();
            if let Some((addrs, idx, t)) = g.as_ref() {
                if t.elapsed() < RESOLVE_TTL {
                    return Ok((addrs.clone(), *idx));
                }
            }
        }
        let addrs =
            crate::resolve::resolve_all(&self.host, self.port, self.bootstrap.as_deref(), timeout)?;
        log::debug(format!(
            "doq resolved {} -> {}",
            self.host,
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
        *self.resolved.lock().unwrap() = Some((addrs.clone(), 0, Instant::now()));
        Ok((addrs, 0))
    }

    /// 记录"这个下标可用"，下次优先用它
    fn mark_good(&self, idx: usize) {
        let mut g = self.resolved.lock().unwrap();
        if let Some((addrs, cur, _)) = g.as_mut() {
            if *cur != idx && idx < addrs.len() {
                *cur = idx;
            }
        }
    }

    /// 某个地址失败了：如果它正好是"首选"，下次就从下一个开始试（别每次都白等它）
    fn mark_bad(&self, idx: usize) {
        let mut g = self.resolved.lock().unwrap();
        if let Some((addrs, cur, _)) = g.as_mut() {
            if *cur == idx && addrs.len() > 1 {
                *cur = (idx + 1) % addrs.len();
            }
        }
    }

    /// 全部地址都失败 → 丢掉缓存，下次重新解析（DNS 可能已经换序）
    fn invalidate(&self) {
        *self.resolved.lock().unwrap() = None;
    }

    async fn connection(&self, timeout: Duration) -> Result<quinn::Connection, String> {
        if let Some(c) = self.conn.lock().unwrap().as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let (addrs, start) = self.resolve(timeout)?;
        let total = addrs.len();
        let begin = Instant::now();
        let mut last_err = String::from("doq: no address");
        for k in 0..total {
            let i = (start + k) % total;
            let sa = addrs[i];
            // 剩余预算里给每个候选分一份：至少 1s，最多 3s
            let left = timeout.saturating_sub(begin.elapsed());
            if left.is_zero() {
                break;
            }
            let per = (left / (total - k) as u32).clamp(
                Duration::from_secs(1),
                Duration::from_secs(3),
            );
            match self.endpoint.connect(sa, &self.server_name) {
                Ok(connecting) => match tokio::time::timeout(per, connecting).await {
                    Ok(Ok(conn)) => {
                        self.mark_good(i);
                        *self.conn.lock().unwrap() = Some(conn.clone());
                        return Ok(conn);
                    }
                    Ok(Err(e)) => {
                        last_err = format!("doq handshake {} ({}): {}", sa, self.server_name, e)
                    }
                    Err(_) => {
                        last_err =
                            format!("doq handshake timeout {} ({})", sa, self.server_name)
                    }
                },
                Err(e) => last_err = format!("doq connect {}: {}", sa, e),
            }
            self.mark_bad(i);
            if crate::log::enabled(crate::log::LV_DEBUG) {
                log::debug(format!(
                    "doq {} 失败，换下一个地址（{}/{}）",
                    sa,
                    k + 1,
                    total
                ));
            }
        }
        // 全挂了：清缓存，下次重新解析拿新顺序
        self.invalidate();
        Err(last_err)
    }

    pub fn query(&self, q: &Msg, timeout: Duration) -> Result<Msg, String> {
        let mut q2 = q.clone();
        q2.id = 0; // RFC 9250: DoQ 查询的 ID 必须为 0
        let bytes = q2.pack();
        if bytes.len() > 65533 {
            return Err("doq query too large".to_string());
        }
        let resp = self.rt.block_on(async {
            let conn = self.connection(timeout).await?;
            let (mut send, mut recv) = tokio::time::timeout(timeout, conn.open_bi())
                .await
                .map_err(|_| "doq open_bi timeout".to_string())?
                .map_err(|e| format!("doq open_bi: {}", e))?;
            let mut framed = Vec::with_capacity(bytes.len() + 2);
            framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            framed.extend_from_slice(&bytes);
            tokio::time::timeout(timeout, send.write_all(&framed))
                .await
                .map_err(|_| "doq write timeout".to_string())?
                .map_err(|e| format!("doq write: {}", e))?;
            let _ = send.finish();
            let body = tokio::time::timeout(timeout, recv.read_to_end(65535))
                .await
                .map_err(|_| "doq read timeout".to_string())?
                .map_err(|e| format!("doq read: {}", e))?;
            Ok::<Vec<u8>, String>(body)
        })?;

        if resp.len() < 14 {
            return Err(format!("doq response too short: {} bytes", resp.len()));
        }
        let len = u16::from_be_bytes([resp[0], resp[1]]) as usize;
        if len + 2 > resp.len() {
            return Err(format!(
                "doq response truncated: want {} have {}",
                len,
                resp.len() - 2
            ));
        }
        let mut m = Msg::parse(&resp[2..2 + len])?;
        m.id = q.id;
        Ok(m)
    }
}
