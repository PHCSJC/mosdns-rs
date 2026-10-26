//! DoH（DNS over HTTPS，RFC 8484）上游：POST `application/dns-message`，走 HTTP/2。
//!
//! 与原版 mosdns 的 https:// 对齐：默认端口 443、路径来自 URL、HTTP/2 多路复用、
//! 连接复用（一条 h2 连接承载多路请求）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request};
use rustls::pki_types::ServerName;

use crate::dns::Msg;
use crate::dot::tls_config_h2;
use crate::log;
use crate::resolve;

const RESOLVE_TTL: Duration = Duration::from_secs(3600);

pub struct DohUpstream {
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
    bootstrap: Option<String>,
    tls: Arc<rustls::ClientConfig>,
    idle: Duration,
    rt: tokio::runtime::Runtime,
    client: Mutex<Option<(SendRequest<Bytes>, Instant)>>,
    picker: resolve::AddrPicker,
    /// (上次出 5xx 的地址下标, 连续次数)：同一地址连续 2 次 5xx 就换下一个地址
    five_xx: Mutex<(usize, u32)>,
}

impl DohUpstream {
    pub fn new(
        host: &str,
        port: u16,
        path: &str,
        bootstrap: Option<&str>,
        insecure: bool,
        idle: Duration,
    ) -> Result<Arc<DohUpstream>, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("doh")
            .build()
            .map_err(|e| format!("doh runtime: {}", e))?;
        let authority = if port == 443 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };
        let path = if path.is_empty() { "/dns-query" } else { path };
        let tls = if insecure {
            crate::dot::build_client_config(Some(b"h2"), true)?
        } else {
            tls_config_h2()
        };
        Ok(Arc::new(DohUpstream {
            host: host.to_string(),
            port,
            authority,
            path: path.to_string(),
            bootstrap: bootstrap.map(|s| s.to_string()),
            tls,
            idle,
            rt,
            client: Mutex::new(None),
            picker: resolve::AddrPicker::new(host, port, bootstrap),
            five_xx: Mutex::new((usize::MAX, 0)),
        }))
    }

    pub fn addr_desc(&self) -> String {
        format!("https://{}{}", self.authority, self.path)
    }

    /// 本次要试的地址候选（多地址故障切换，见 resolve::AddrPicker）
    fn candidates(&self, timeout: Duration) -> Result<Vec<(usize, SocketAddr)>, String> {
        self.picker.candidates(timeout)
    }

    async fn connect(&self, sa: SocketAddr, timeout: Duration) -> Result<SendRequest<Bytes>, String> {
        let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(sa))
            .await
            .map_err(|_| format!("doh tcp connect timeout {}", sa))?
            .map_err(|e| format!("doh tcp connect {}: {}", sa, e))?;
        tcp.set_nodelay(true).ok();

        let name = ServerName::try_from(self.host.clone())
            .map_err(|e| format!("doh server name {}: {}", self.host, e))?;
        let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
        let tls = tokio::time::timeout(timeout, connector.connect(name, tcp))
            .await
            .map_err(|_| format!("doh tls timeout {}", self.host))?
            .map_err(|e| format!("doh tls {}: {}", self.host, e))?;

        let (send_req, conn) = tokio::time::timeout(timeout, h2::client::handshake(tls))
            .await
            .map_err(|_| "doh h2 handshake timeout".to_string())?
            .map_err(|e| format!("doh h2 handshake: {}", e))?;
        // 连接驱动放在 runtime 上跑
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(send_req)
    }

    fn send_req(&self, sa: SocketAddr, timeout: Duration) -> Result<SendRequest<Bytes>, String> {
        // 复用连接；空闲超过 idle_timeout 就丢弃重建（对齐 mosdns 的 idleConnTimeout）
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
        // 两次尝试共享总超时
        let deadline = Instant::now() + timeout;
        for attempt in 0..2 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("doh timeout".to_string());
            }
            // 逐个地址试（每个查询最多换 2 个地址，避免把预算耗光）
            let cands = self.candidates(left)?;
            let mut send_req = None;
            let mut last_err = String::from("doh: no address");
            let mut used: Option<(usize, SocketAddr)> = None;
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
                        used = Some((*idx, *sa));
                        send_req = Some(c);
                        break;
                    }
                    Err(e) => {
                        self.picker.mark_bad(*idx);
                        last_err = e;
                        if log::enabled(log::LV_DEBUG) {
                            log::debug(format!("doh {} 失败，换下一个地址", sa));
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
                    // 成功一次就把"连续 5xx"清零
                    *self.five_xx.lock().unwrap() = (usize::MAX, 0);
                    let mut m = Msg::parse(&resp)?;
                    m.id = q.id;
                    return Ok(m);
                }
                Err(e) => {
                    // 连接可能已失效：清掉缓存重来一次
                    *self.client.lock().unwrap() = None;
                    // HTTP 5xx 是"上游服务出错"，把用的是哪个地址标出来（否则查不出是谁在抽风）；
                    // 同一个地址连续两次 5xx 就换个地址（地址本身可能是坏的）。
                    let is_5xx = e.contains("http status 5");
                    if is_5xx {
                        if let Some((idx, sa)) = used {
                            let mut g = self.five_xx.lock().unwrap();
                            if g.0 == idx {
                                g.1 = g.1.saturating_add(1);
                            } else {
                                g.0 = idx;
                                g.1 = 1;
                            }
                            if g.1 >= 2 && cands.len() > 1 {
                                self.picker.mark_bad(idx);
                                g.1 = 0;
                                if log::enabled(log::LV_DEBUG) {
                                    log::debug(format!(
                                        "doh {} 连续 2 次 5xx，下次换地址",
                                        sa
                                    ));
                                }
                            }
                            let e = format!("{} ({})", e, sa);
                            if attempt == 1 {
                                return Err(e);
                            }
                            log::debug(format!("doh retry after error: {}", e));
                            continue;
                        }
                    }
                    if attempt == 1 {
                        return Err(e);
                    }
                    log::debug(format!("doh retry after error: {}", e));
                }
            }
        }
        Err("doh exchange failed".to_string())
    }

    async fn exchange(
        &self,
        send_req: SendRequest<Bytes>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let uri = format!("https://{}{}", self.authority, self.path);
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("content-length", body.len().to_string())
            .body(())
            .map_err(|e| format!("doh build request: {}", e))?;

        let mut sender = tokio::time::timeout(timeout, send_req.ready())
            .await
            .map_err(|_| "doh ready timeout".to_string())?
            .map_err(|e| format!("doh connection not ready: {}", e))?;

        let (resp, mut send_body) = sender
            .send_request(req, false)
            .map_err(|e| format!("doh send request: {}", e))?;
        send_body
            .send_data(Bytes::from(body), true)
            .map_err(|e| format!("doh send body: {}", e))?;

        let resp = tokio::time::timeout(timeout, resp)
            .await
            .map_err(|_| "doh response timeout".to_string())?
            .map_err(|e| format!("doh response: {}", e))?;
        let status = resp.status();
        if status != http::StatusCode::OK {
            return Err(format!("doh http status {}", status));
        }
        let mut body = resp.into_body();
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(timeout, body.data()).await {
                Ok(Some(Ok(chunk))) => {
                    out.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                Ok(Some(Err(e))) => return Err(format!("doh body: {}", e)),
                Ok(None) => break,
                Err(_) => return Err("doh body timeout".to_string()),
            }
        }
        if out.is_empty() {
            return Err("doh empty body".to_string());
        }
        Ok(out)
    }
}
