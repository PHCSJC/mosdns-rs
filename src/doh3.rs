//! DoH3（DNS over HTTPS over HTTP/3）上游。
//!
//! 与官方语义一致：`https://... + enable_http3: true` 或 `h3://...`，
//! 用 QUIC（ALPN "h3"）跑 HTTP/3，然后 POST `application/dns-message`。
//! QUIC 连接复用；连接失效自动重连一次。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http::{Method, Request};

use crate::dns::Msg;
use crate::log;
use crate::resolve;

const RESOLVE_TTL: Duration = Duration::from_secs(3600);
const H3_ALPN: &[u8] = b"h3";

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

pub struct DohH3Upstream {
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
    bootstrap: Option<String>,
    idle: Duration,
    rt: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    client: Mutex<Option<(H3SendRequest, Instant)>>,
    picker: resolve::AddrPicker,
}

impl DohH3Upstream {
    pub fn new(
        host: &str,
        port: u16,
        path: &str,
        bootstrap: Option<&str>,
        insecure: bool,
        idle: Duration,
    ) -> Result<Arc<DohH3Upstream>, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("doh3")
            .build()
            .map_err(|e| format!("doh3 runtime: {}", e))?;

        // QUIC 客户端：ALPN 必须是 h3
        let tls_arc = crate::dot::build_client_config(Some(H3_ALPN), insecure)?;
        let tls = (*tls_arc).clone();
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| format!("doh3 quic config: {}", e))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(qcc));

        let _g = rt.enter();
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("doh3 endpoint: {}", e))?;
        endpoint.set_default_client_config(client_cfg);
        drop(_g);

        let authority = if port == 443 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        let path = if path.is_empty() { "/dns-query" } else { path };

        Ok(Arc::new(DohH3Upstream {
            host: host.to_string(),
            port,
            authority,
            path: path.to_string(),
            bootstrap: bootstrap.map(|s| s.to_string()),
            idle,
            rt,
            endpoint,
            client: Mutex::new(None),
            picker: resolve::AddrPicker::new(host, port, bootstrap),
        }))
    }

    pub fn addr_desc(&self) -> String {
        format!("h3://{}{}", self.authority, self.path)
    }

    fn candidates(&self, timeout: Duration) -> Result<Vec<(usize, SocketAddr)>, String> {
        self.picker.candidates(timeout)
    }

    async fn connect(
        &self,
        sa: SocketAddr,
        timeout: Duration,
    ) -> Result<H3SendRequest, String> {
        let connecting = self
            .endpoint
            .connect(sa, &self.host)
            .map_err(|e| format!("doh3 connect {}: {}", sa, e))?;
        let conn = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| format!("doh3 handshake timeout {}", sa))?
            .map_err(|e| format!("doh3 handshake {}: {}", sa, e))?;
        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, send_req) = tokio::time::timeout(timeout, h3::client::new(quinn_conn))
            .await
            .map_err(|_| "doh3 h3 init timeout".to_string())?
            .map_err(|e| format!("doh3 h3 init: {}", e))?;
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(send_req)
    }

    fn send_req(&self, sa: SocketAddr, timeout: Duration) -> Result<H3SendRequest, String> {
        {
            let mut g = self.client.lock().unwrap();
            if let Some((c, last)) = g.as_mut() {
                if last.elapsed() < self.idle {
                    *last = Instant::now();
                    return Ok(c.clone());
                }
                *g = None;
            }
        }
        let c = self.rt.block_on(self.connect(sa, timeout))?;
        *self.client.lock().unwrap() = Some((c.clone(), Instant::now()));
        Ok(c)
    }

    pub fn query(&self, q: &Msg, timeout: Duration) -> Result<Msg, String> {
        let bytes = q.pack();
        // 两次尝试共享同一个总超时，避免"失败要等 2×timeout"
        let deadline = Instant::now() + timeout;
        for attempt in 0..2 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("doh3 timeout".to_string());
            }
            // 逐个地址试（最多 2 个）
            let cands = self.candidates(left)?;
            let mut send_req = None;
            let mut last_err = String::from("doh3: no address");
            for (k, (idx, sa)) in cands.iter().enumerate() {
                if k >= 2 {
                    break;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match self.send_req(*sa, left) {
                    Ok(c) => {
                        self.picker.mark_good(*idx);
                        send_req = Some(c);
                        break;
                    }
                    Err(e) => {
                        self.picker.mark_bad(*idx);
                        last_err = e;
                        if log::enabled(log::LV_DEBUG) {
                            log::debug(format!("doh3 {} 失败，换下一个地址", sa));
                        }
                    }
                }
            }
            let send_req = match send_req {
                Some(c) => c,
                None => {
                    self.picker.invalidate();
                    if attempt == 1 {
                        return Err(last_err);
                    }
                    continue;
                }
            };
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rt.block_on(self.exchange(send_req, bytes.clone(), left)) {
                Ok(resp) => {
                    let mut m = Msg::parse(&resp)?;
                    m.id = q.id;
                    return Ok(m);
                }
                Err(e) => {
                    *self.client.lock().unwrap() = None;
                    if attempt == 1 {
                        return Err(e);
                    }
                    log::debug(format!("doh3 retry after error: {}", e));
                }
            }
        }
        Err("doh3 exchange failed".to_string())
    }

    async fn exchange(
        &self,
        mut send_req: H3SendRequest,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let uri = format!("https://{}{}", self.authority, self.path);
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| format!("doh3 build request: {}", e))?;

        let mut stream = tokio::time::timeout(timeout, send_req.send_request(req))
            .await
            .map_err(|_| "doh3 send_request timeout".to_string())?
            .map_err(|e| format!("doh3 send_request: {}", e))?;
        tokio::time::timeout(timeout, stream.send_data(Bytes::from(body)))
            .await
            .map_err(|_| "doh3 send_data timeout".to_string())?
            .map_err(|e| format!("doh3 send_data: {}", e))?;
        tokio::time::timeout(timeout, stream.finish())
            .await
            .map_err(|_| "doh3 finish timeout".to_string())?
            .map_err(|e| format!("doh3 finish: {}", e))?;

        let resp = tokio::time::timeout(timeout, stream.recv_response())
            .await
            .map_err(|_| "doh3 response timeout".to_string())?
            .map_err(|e| format!("doh3 response: {}", e))?;
        let status = resp.status();
        if status != http::StatusCode::OK {
            return Err(format!("doh3 http status {}", status));
        }
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(timeout, stream.recv_data()).await {
                Ok(Ok(Some(mut chunk))) => {
                    while chunk.has_remaining() {
                        let seg = chunk.chunk();
                        out.extend_from_slice(seg);
                        let n = seg.len();
                        chunk.advance(n);
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(format!("doh3 body: {}", e)),
                Err(_) => return Err("doh3 body timeout".to_string()),
            }
        }
        if out.is_empty() {
            return Err("doh3 empty body".to_string());
        }
        Ok(out)
    }
}
