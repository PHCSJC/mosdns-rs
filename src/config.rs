//! Config model -> plugin registry builder.

use std::collections::HashMap;
use std::sync::Arc;

use crate::domain::{DomainSet, HostsMap, IpSet, RedirectMap};
use crate::engine::*;
use crate::log;
use crate::mmdb::Mmdb;
use crate::plugins::*;
use crate::yaml::Value;

pub enum Entry {
    Plain(Arc<dyn Exec>),
    Rec(Arc<dyn RExec>),
    Chain(Arc<Chain>),
    IpSet(Arc<IpSet>),
}

#[derive(Default)]
pub struct Registry {
    map: HashMap<String, Entry>,
}

impl Registry {
    /// 已注册的插件数量（--check 里打出来，方便发现"列表被截断"）
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn insert(&mut self, tag: &str, e: Entry) {
        self.map.insert(tag.to_string(), e);
    }

    pub fn get(&self, tag: &str) -> Option<&Entry> {
        self.map.get(tag)
    }
}

/// Adapter: recursive executable used as a plain executable (no continuation).
struct RecAsExec(Arc<dyn RExec>);
impl Exec for RecAsExec {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        let empty = Arc::new(Vec::new());
        let next = Walker::start(empty);
        self.0.exec(ctx, &next)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerKind {
    Udp,
    Tcp,
}

pub struct ServerCfg {
    pub kind: ServerKind,
    pub entry: String,
    pub listen: String,
}

pub struct Built {
    pub reg: Registry,
    pub servers: Vec<ServerCfg>,
    pub log_level: String,
    pub log_file: Option<String>,
}

struct Noop;
impl Exec for Noop {
    fn exec(&self, _ctx: &mut QCtx) -> Res {
        Ok(())
    }
}

/// ip_set 数据源选项：mmdb 国家过滤。
#[derive(Clone)]
pub struct IpSourceOpts {
    /// Some("CN") 只收该国；None 收全部
    pub country: Option<String>,
    pub ipv4_only: bool,
}

impl Default for IpSourceOpts {
    fn default() -> Self {
        IpSourceOpts {
            country: Some("CN".to_string()),
            ipv4_only: false,
        }
    }
}

/// 加载一个 ip_set 数据源：本地 mmdb / 本地文本，按内容自动识别。
pub fn load_ip_source(set: &mut IpSet, spec: &str, opts: &IpSourceOpts) -> Result<(), String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(());
    }
    if spec.starts_with("http://") || spec.starts_with("https://") {
        return Err(format!(
            "ip_set: URL is not supported ({}), put the mmdb file on disk and reference its path",
            spec
        ));
    }
    let path = spec.to_string();
    if crate::mmdb::is_mmdb_file(&path) {
        let db = Mmdb::open(&path)?;
        let st = db.load_into(set, opts.country.as_deref(), opts.ipv4_only)?;
        log::info(format!(
            "ip_set: mmdb {} type={} build={} networks={} -> v4={} v6={} (unique v4={} v6={}) filtered_out={}",
            path,
            if db.meta.database_type.is_empty() { "-" } else { &db.meta.database_type },
            db.meta.build_epoch,
            st.networks,
            st.v4,
            st.v6,
            st.v4_unique,
            st.v6_unique,
            st.filtered_out
        ));
        Ok(())
    } else {
        set.add_file(&path)
    }
}

fn as_tag(v: &Value) -> String {
    v.as_str().unwrap_or("").trim().to_string()
}

pub fn build(root: &Value) -> Result<Built, String> {
    let mut log_level = "info".to_string();
    let mut log_file = None;
    if let Some(l) = root.get("log") {
        if let Some(lv) = l.get("level").and_then(|v| v.as_str()) {
            log_level = lv.to_string();
        }
        if let Some(f) = l.get("file").and_then(|v| v.as_str()) {
            if !f.is_empty() {
                log_file = Some(f.to_string());
            }
        }
    }

    let plugins = root
        .get("plugins")
        .and_then(|v| v.as_list())
        .ok_or("config has no plugins section")?
        .clone();

    let mut reg = Registry::default();
    let mut servers: Vec<ServerCfg> = Vec::new();

    for p in &plugins {
        let tag = p.get("tag").map(as_tag).unwrap_or_default();
        let typ = p.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let args = p.get("args").cloned().unwrap_or(Value::Null);
        if tag.is_empty() {
            return Err(format!("plugin of type [{}] has no tag", typ));
        }

        match typ.as_str() {
            "cache" => {
                let size = args.get("size").and_then(|v| v.as_int()).unwrap_or(1024) as usize;
                let lazy = args
                    .get("lazy_cache_ttl")
                    .and_then(|v| v.as_int())
                    .unwrap_or(0) as u32;
                let c = crate::plugins::Cache::new(size, lazy);
                reg.insert(&tag, Entry::Rec(c));
                log::info(format!("plugin [{}] cache size={} lazy={}", tag, size, lazy));
            }
            "hosts" => {
                let mut map = HostsMap::default();
                if let Some(v) = args.get("entries") {
                    for e in v.as_string_list() {
                        map.add(&e)?;
                    }
                }
                if let Some(v) = args.get("files") {
                    for f in v.as_string_list() {
                        map.add_file(&f)?;
                    }
                }
                reg.insert(&tag, Entry::Plain(Arc::new(Hosts { map })));
                log::info(format!("plugin [{}] hosts loaded", tag));
            }
            "redirect" => {
                let mut map = RedirectMap::default();
                if let Some(v) = args.get("rules") {
                    for e in v.as_string_list() {
                        map.add_rule(&e)?;
                    }
                }
                if let Some(v) = args.get("files") {
                    for f in v.as_string_list() {
                        map.add_file(&f)?;
                    }
                }
                reg.insert(&tag, Entry::Rec(Arc::new(Redirect { map })));
                log::info(format!("plugin [{}] redirect loaded", tag));
            }
            "forward" => {
                let mut ups = Vec::new();
                if let Some(list) = args.get("upstreams").and_then(|v| v.as_list()) {
                    for u in list {
                        let addr = u
                            .get("addr")
                            .and_then(|v| v.as_str())
                            .ok_or("forward upstream missing addr")?;
                        let server_name = u.get("server_name").and_then(|v| v.as_str());
                        let bootstrap = u.get("bootstrap").and_then(|v| v.as_str());
                        let http3 = u.get("enable_http3").and_then(|v| v.as_bool()).unwrap_or(false);
                        let insecure = u
                            .get("insecure_skip_verify")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if insecure {
                            log::warn(format!(
                                "upstream {} 设置了 insecure_skip_verify，将不校验证书",
                                addr
                            ));
                        }
                        // idle_timeout 单位秒；<=0 或缺省表示用协议默认
                        let idle = u
                            .get("idle_timeout")
                            .and_then(|v| v.as_int())
                            .filter(|v| *v > 0)
                            .map(|v| std::time::Duration::from_secs(v as u64));
                        let opts = UpOpts {
                            server_name: server_name.map(|s| s.to_string()),
                            bootstrap: bootstrap.map(|s| s.to_string()),
                            http3,
                            insecure,
                            idle,
                        };
                        ups.push(UpstreamSlot {
                            up: Upstream::parse_ex(addr, &opts)?,
                        });
                    }
                }
                if ups.is_empty() {
                    return Err(format!("plugin [{}] forward has no upstream", tag));
                }
                let concurrent = args
                    .get("concurrent")
                    .and_then(|v| v.as_int())
                    .unwrap_or(1) as usize;
                reg.insert(
                    &tag,
                    Entry::Plain(Arc::new(Forward {
                        upstreams: ups,
                        concurrent,
                    })),
                );
                log::info(format!("plugin [{}] forward ready", tag));
            }
            "ip_set" => {
                let mut set = IpSet::new();
                let mut opts = IpSourceOpts::default();
                if let Some(v) = args.get("mmdb_country") {
                    let s = v.as_str().unwrap_or("").trim().to_string();
                    opts.country = if s.is_empty()
                        || s == "*"
                        || s.eq_ignore_ascii_case("all")
                    {
                        None
                    } else {
                        Some(s)
                    };
                }
                opts.ipv4_only = args
                    .get("mmdb_ipv4_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if let Some(v) = args.get("files") {
                    for f in v.as_string_list() {
                        load_ip_source(&mut set, &f, &opts)?;
                    }
                }
                if let Some(v) = args.get("ips") {
                    for ip in v.as_string_list() {
                        set.add(&ip)?;
                    }
                }
                set.compact();
                log::info(format!("plugin [{}] ip_set entries={}", tag, set.len()));
                reg.insert(&tag, Entry::IpSet(Arc::new(set)));
            }
            "sequence" => {
                let chain = build_chain(&reg, &args)?;
                reg.insert(&tag, Entry::Chain(Arc::new(chain)));
                log::info(format!("plugin [{}] sequence ready", tag));
            }
            "fallback" => {
                let ptag = args
                    .get("primary")
                    .and_then(|v| v.as_str())
                    .ok_or("fallback missing primary")?
                    .to_string();
                let stag = args
                    .get("secondary")
                    .and_then(|v| v.as_str())
                    .ok_or("fallback missing secondary")?
                    .to_string();
                let primary = exec_of(&reg, &ptag)
                    .ok_or_else(|| format!("cannot find primary executable {}", ptag))?;
                let secondary = exec_of(&reg, &stag)
                    .ok_or_else(|| format!("cannot find secondary executable {}", stag))?;
                let threshold = args
                    .get("threshold")
                    .and_then(|v| v.as_int())
                    .unwrap_or(500)
                    .max(1) as u64;
                let always = args
                    .get("always_standby")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                reg.insert(
                    &tag,
                    Entry::Plain(Arc::new(Fallback {
                        primary,
                        secondary,
                        threshold: std::time::Duration::from_millis(threshold),
                        always_standby: always,
                    })),
                );
                log::info(format!("plugin [{}] fallback ready", tag));
            }
            "udp_server" | "tcp_server" => {
                let entry = args
                    .get("entry")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("plugin [{}] missing entry", tag))?
                    .to_string();
                let listen = args
                    .get("listen")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("plugin [{}] missing listen", tag))?
                    .to_string();
                servers.push(ServerCfg {
                    kind: if typ == "udp_server" {
                        ServerKind::Udp
                    } else {
                        ServerKind::Tcp
                    },
                    entry,
                    listen,
                });
            }
            "prefer_ipv4" => {
                reg.insert(&tag, Entry::Rec(Arc::new(PreferIpv4::new(false))));
                log::info(format!("plugin [{}] prefer_ipv4", tag));
            }
            "only_ipv4" => {
                reg.insert(&tag, Entry::Rec(Arc::new(PreferIpv4::new(true))));
                log::info(format!("plugin [{}] only_ipv4 (AAAA -> SOA NODATA)", tag));
            }
            "domain_set" | "api" => {
                log::warn(format!("plugin [{}] type [{}] ignored", tag, typ));
            }
            other => {
                log::warn(format!("plugin [{}] unsupported type [{}], ignored", tag, other));
            }
        }
    }

    Ok(Built {
        reg,
        servers,
        log_level,
        log_file,
    })
}

fn exec_of(reg: &Registry, tag: &str) -> Option<Arc<dyn Exec>> {
    match reg.get(tag)? {
        Entry::Plain(p) => Some(p.clone()),
        Entry::Chain(c) => Some(Arc::new(Sequence { chain: c.clone() })),
        Entry::Rec(r) => Some(Arc::new(RecAsExec(r.clone()))),
        Entry::IpSet(_) => None,
    }
}

fn build_chain(reg: &Registry, args: &Value) -> Result<Chain, String> {
    let list = args
        .as_list()
        .ok_or("sequence args must be a list of rules")?;
    let mut chain: Chain = Vec::with_capacity(list.len());
    for (i, rule) in list.iter().enumerate() {
        let map = rule
            .as_map()
            .ok_or_else(|| format!("sequence rule #{} is not a mapping", i))?;
        let find = |k: &str| -> Option<&Value> {
            map.iter().find(|(mk, _)| mk == k).map(|(_, v)| v)
        };
        let mut matches = Vec::new();
        if let Some(mv) = find("matches") {
            for s in mv.as_string_list() {
                matches.push(build_matcher(reg, &s)?);
            }
        }
        let exec_str = find("exec")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("sequence rule #{} has no exec", i))?
            .to_string();
        let exec = build_exec(reg, &exec_str)
            .map_err(|e| format!("sequence rule #{} (exec: {}): {}", i, exec_str, e))?;
        chain.push(ChainNode { matches, exec });
    }
    Ok(chain)
}

fn build_matcher(reg: &Registry, s: &str) -> Result<Arc<dyn Matcher>, String> {
    let s = s.trim();
    let (reverse, s) = match s.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, s),
    };
    let (kind, args) = match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s, ""),
    };
    let m: Arc<dyn Matcher> = match kind {
        "qname" => {
            let mut set = DomainSet::new();
            for tok in args.split_whitespace() {
                if let Some(path) = tok.strip_prefix('&') {
                    set.add_file(path, "domain")?;
                } else if let Some(tag) = tok.strip_prefix('$') {
                    return Err(format!("domain_set [{}] is not supported", tag));
                } else {
                    set.add(tok, "domain")?;
                }
            }
            Arc::new(QNameMatcher { set })
        }
        "qtype" => Arc::new(QTypeMatcher::parse(args)?),
        "client_ip" => {
            let mut set = IpSet::new();
            for tok in args.split_whitespace() {
                if let Some(path) = tok.strip_prefix('&') {
                    load_ip_source(&mut set, path, &IpSourceOpts::default())?;
                } else if let Some(tag) = tok.strip_prefix('$') {
                    match reg.get(tag) {
                        Some(Entry::IpSet(s)) => set.merge(s),
                        _ => return Err(format!("cannot find ip_set [{}]", tag)),
                    }
                } else {
                    set.add(tok)?;
                }
            }
            set.compact();
            Arc::new(ClientIpMatcher { set: Arc::new(set) })
        }
        "resp_ip" => {
            let mut set = IpSet::new();
            for tok in args.split_whitespace() {
                if let Some(path) = tok.strip_prefix('&') {
                    load_ip_source(&mut set, path, &IpSourceOpts::default())?;
                } else if let Some(tag) = tok.strip_prefix('$') {
                    match reg.get(tag) {
                        Some(Entry::IpSet(s)) => set.merge(s),
                        _ => return Err(format!("cannot find ip_set [{}]", tag)),
                    }
                } else {
                    set.add(tok)?;
                }
            }
            set.compact();
            Arc::new(RespIpMatcher { set: Arc::new(set) })
        }
        "has_resp" => Arc::new(HasResp),
        "_true" => Arc::new(AlwaysTrue),
        "_false" => Arc::new(AlwaysFalse),
        other => return Err(format!("unsupported matcher type [{}]", other)),
    };
    Ok(if reverse {
        Arc::new(Reverse { inner: m })
    } else {
        m
    })
}

fn build_exec(reg: &Registry, s: &str) -> Result<ExecKind, String> {
    let s = s.trim();
    if let Some(tag) = s.strip_prefix('$') {
        let tag = tag.trim();
        return match reg.get(tag) {
            Some(Entry::Plain(p)) => Ok(ExecKind::Plain(p.clone())),
            Some(Entry::Rec(r)) => Ok(ExecKind::Rec(r.clone())),
            Some(Entry::Chain(c)) => Ok(ExecKind::Plain(Arc::new(Sequence { chain: c.clone() }))),
            Some(Entry::IpSet(_)) => Err(format!("plugin [{}] is not executable", tag)),
            None => Err(format!("cannot find executable [{}]", tag)),
        };
    }
    let (kind, args) = match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s, ""),
    };
    match kind {
        "accept" => Ok(ExecKind::Rec(Arc::new(Accept))),
        "return" => Ok(ExecKind::Rec(Arc::new(Return))),
        "reject" => {
            let rcode = if args.is_empty() {
                5u16
            } else {
                args.parse::<u16>()
                    .map_err(|_| format!("invalid rcode [{}]", args))?
            };
            Ok(ExecKind::Rec(Arc::new(Reject { rcode })))
        }
        "drop_resp" => Ok(ExecKind::Plain(Arc::new(DropResp))),
        "ipset" => Ok(ExecKind::Plain(Arc::new(IpSetExec::parse(args)?))),
        "ttl" => Ok(ExecKind::Plain(Arc::new(TtlExec::parse(args)?))),
        "black_hole" => Ok(ExecKind::Plain(Arc::new(BlackHole::parse(args)?))),
        // prefer_ipv4：双栈探测（AAAA 有 A 记录就屏蔽）
        "prefer_ipv4" => {
            if !args.trim().is_empty() {
                return Err(format!(
                    "prefer_ipv4 takes no arguments (got [{}]); use `only_ipv4` to block AAAA entirely",
                    args.trim()
                ));
            }
            Ok(ExecKind::Rec(Arc::new(PreferIpv4::new(false))))
        }
        // only_ipv4：只允许 IPv4，AAAA 一律回 NODATA（NOERROR + SOA）
        "only_ipv4" => Ok(ExecKind::Rec(Arc::new(PreferIpv4::new(true)))),
        "goto" => {
            let tag = args.trim();
            match reg.get(tag) {
                Some(Entry::Chain(c)) => Ok(ExecKind::Rec(Arc::new(Goto {
                    target: c.clone(),
                    name: tag.to_string(),
                }))),
                _ => Err(format!("cannot find goto target [{}]", tag)),
            }
        }
        "jump" => {
            let tag = args.trim();
            match reg.get(tag) {
                Some(Entry::Chain(c)) => Ok(ExecKind::Rec(Arc::new(Jump {
                    target: c.clone(),
                    name: tag.to_string(),
                }))),
                _ => Err(format!("cannot find jump target [{}]", tag)),
            }
        }
        // diagnostics-only execs present in some configs: harmless no-ops
        "debug_print" => Ok(ExecKind::Plain(Arc::new(DebugPrint))),
        "query_summary" | "metrics_collector" => Ok(ExecKind::Plain(Arc::new(Noop))),
        other => Err(format!("unsupported exec type [{}]", other)),
    }
}

struct DebugPrint;
impl Exec for DebugPrint {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        let q = &ctx.q;
        if let Some(qq) = q.question.first() {
            let ans: Vec<String> = ctx
                .r
                .as_ref()
                .map(|r| {
                    r.answer
                        .iter()
                        .map(|rr| match &rr.rdata {
                            crate::dns::RData::A(ip) => format!("A {}", ip),
                            crate::dns::RData::Aaaa(ip) => format!("AAAA {}", ip),
                            _ => format!("type{}", rr.rtype),
                        })
                        .collect()
                })
                .unwrap_or_default();
            log::info(format!(
                "debug_print q={} type={} rcode={} ans=[{}]",
                qq.name,
                qq.qtype,
                ctx.r.as_ref().map(|r| r.rcode()).unwrap_or(999),
                ans.join(", ")
            ));
        }
        Ok(())
    }
}
