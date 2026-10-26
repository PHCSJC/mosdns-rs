//! DoT（DNS over TLS，RFC 7858）上游。
//!
//! 与 udp/tcp 一样是阻塞模型：`rustls::StreamOwned` 包一层 TcpStream，
//! 报文用 2 字节长度前缀（和 TCP 相同），连接池复用。
//! 与原版 mosdns 的 tls:// 行为一致：SNI 取 host、默认端口 853、不设 ALPN。

use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::dns::Msg;
use crate::log;

/// 连接空闲超过这个时间就不再复用（与原版默认 idle_timeout 靠近）
// 空闲超时由 options 传入（默认 10s，对齐 mosdns）
const DOT_POOL_MAX: usize = 8;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// 不做任何证书校验的 verifier（对应 `insecure_skip_verify: true`）。
/// 只跳过"证书链/主机名"校验，签名仍用 rustls 的算法校验，保证握手能正常完成。
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 构造客户端 TLS 配置。`insecure=true` 时跳过证书/主机名校验。
pub fn build_client_config(
    alpn: Option<&[u8]>,
    insecure: bool,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {}", e))?;
    let mut cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    if let Some(a) = alpn {
        cfg.alpn_protocols = vec![a.to_vec()];
    }
    Ok(Arc::new(cfg))
}

fn build_tls_config(alpn: Option<&[u8]>) -> Arc<ClientConfig> {
    {
        {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        // 会话恢复默认开启（Resumption::in_memory_sessions(256)）
        if let Some(a) = alpn {
            cfg.alpn_protocols = vec![a.to_vec()];
        }
        Arc::new(cfg)
        }
    }
}

/// DoT 用：不设 ALPN（与 mosdns 一致）
pub fn tls_config() -> Arc<ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| build_tls_config(None)).clone()
}

/// DoH 用：必须带 ALPN "h2"
pub fn tls_config_h2() -> Arc<ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| build_tls_config(Some(b"h2"))).clone()
}

const RESOLVE_TTL: Duration = Duration::from_secs(3600);

pub struct DotUpstream {
    pub host: String,
    pub port: u16,
    addr: Option<SocketAddr>,
    server_name: String,
    tls: Arc<ClientConfig>,
    idle: Duration,
    bootstrap: Option<String>,
    picker: crate::resolve::AddrPicker,
    pool: Mutex<Vec<(TlsStream, Instant)>>,
}

impl DotUpstream {
    pub fn new(
        host: &str,
        port: u16,
        server_name: Option<&str>,
        bootstrap: Option<&str>,
        insecure: bool,
        idle: Duration,
    ) -> Result<Arc<DotUpstream>, String> {
        let sn = server_name
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.to_string());
        // IP 直接给出时省掉解析
        let addr = host.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, port));
        let tls = if insecure {
            build_client_config(None, true)?
        } else {
            tls_config()
        };
        Ok(Arc::new(DotUpstream {
            host: host.to_string(),
            port,
            addr,
            server_name: sn,
            tls,
            idle,
            bootstrap: bootstrap.map(|s| s.to_string()),
            picker: crate::resolve::AddrPicker::new(&host, port, bootstrap),
            pool: Mutex::new(Vec::new()),
        }))
    }

    pub fn addr_desc(&self) -> String {
        format!("tls://{}:{}", self.host, self.port)
    }

    /// 依次尝试解析出来的每个地址（每个查询最多 2 个），失败就换下一个
    fn connect(&self, timeout: Duration) -> Result<TlsStream, String> {
        let cands = self.picker.candidates(timeout)?;
        let mut last = String::from("dot: no address");
        for (k, (idx, sa)) in cands.iter().enumerate() {
            if k >= 2 {
                break;
            }
            match self.connect_to(*sa, timeout) {
                Ok(st) => {
                    self.picker.mark_good(*idx);
                    return Ok(st);
                }
                Err(e) => {
                    self.picker.mark_bad(*idx);
                    last = e;
                    if log::enabled(log::LV_DEBUG) {
                        log::debug(format!("dot {} 失败，换下一个地址", sa));
                    }
                }
            }
        }
        self.picker.invalidate();
        Err(last)
    }

    fn connect_to(&self, sa: SocketAddr, timeout: Duration) -> Result<TlsStream, String> {
        let tcp = TcpStream::connect_timeout(&sa, timeout)
            .map_err(|e| format!("dot connect {}: {}", sa, e))?;
        tcp.set_read_timeout(Some(timeout)).ok();
        tcp.set_write_timeout(Some(timeout)).ok();
        tcp.set_nodelay(true).ok();

        let name = ServerName::try_from(self.server_name.clone())
            .map_err(|e| format!("dot server name {}: {}", self.server_name, e))?;
        let conn = ClientConnection::new(self.tls.clone(), name)
            .map_err(|e| format!("dot tls init: {}", e))?;
        let mut stream = StreamOwned::new(conn, tcp);
        // 主动握手，失败信息更清晰
        while stream.conn.is_handshaking() {
            if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
                return Err(format!("dot handshake {}: {}", sa, e));
            }
        }
        Ok(stream)
    }

    pub fn query(&self, q: &Msg, timeout: Duration) -> Result<Msg, String> {
        let mut q2 = q.clone();
        q2.id = next_id();
        let bytes = q2.pack();
        let mut framed = Vec::with_capacity(bytes.len() + 2);
        framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        framed.extend_from_slice(&bytes);

        // 先试池子里的连接，失败再用新连接重试一次（对齐 TCP 的做法）；两次共享总超时
        let deadline = Instant::now() + timeout;
        for attempt in 0..2 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("dot timeout".to_string());
            }
            let reused = if attempt == 0 {
                let mut g = match self.pool.lock() {
                    Ok(g) => g,
                    Err(_) => return Err("dot pool poisoned".to_string()),
                };
                let now = Instant::now();
                let mut found = None;
                while let Some((s, since)) = g.pop() {
                    let age = now.duration_since(since);
                    if age < self.idle {
                        found = Some(s);
                        break;
                    }
                    if log::enabled(log::LV_DEBUG) {
                        log::debug(format!(
                            "dot 池中连接空闲 {:?} ≥ idle_timeout {:?}，丢弃重建",
                            age, self.idle
                        ));
                    }
                }
                found
            } else {
                None
            };
            let (mut stream, was_reused) = match reused {
                Some(s) => (s, true),
                None => (self.connect(left)?, false),
            };
            match exchange(&mut stream, &framed, q.id) {
                Ok(r) => {
                    if let Ok(mut g) = self.pool.lock() {
                        if g.len() < DOT_POOL_MAX {
                            g.push((stream, Instant::now()));
                        }
                    }
                    return Ok(r);
                }
                Err(e) => {
                    if was_reused && attempt == 0 {
                        log::debug(format!("dot reused conn failed ({}), retrying fresh", e));
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err("dot exchange failed".to_string())
    }
}

fn exchange(stream: &mut TlsStream, framed: &[u8], orig_id: u16) -> Result<Msg, String> {
    use std::io::{Read, Write};
    stream
        .write_all(framed)
        .map_err(|e| format!("dot write: {}", e))?;
    stream.flush().ok();
    // 读一帧；ID 不匹配说明是上一条查询的迟到响应，继续读（防止错答）
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(5) {
            return Err("dot response timeout".to_string());
        }
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("dot read len: {}", e))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len < 12 {
            return Err("dot response too short".to_string());
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .map_err(|e| format!("dot read body: {}", e))?;
        let Ok(mut m) = Msg::parse(&buf) else {
            continue;
        };
        if u16::from_be_bytes([buf[0], buf[1]]) != sent_id(framed) {
            continue;
        }
        m.id = orig_id;
        return Ok(m);
    }
}

/// 取出我们发出去的报文 ID（framed 前 2 字节是长度，紧跟 2 字节是 ID）
fn sent_id(framed: &[u8]) -> u16 {
    u16::from_be_bytes([framed[2], framed[3]])
}

fn next_id() -> u16 {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    (SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0xffff) as u16
}
