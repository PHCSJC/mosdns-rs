//! 失败查询落盘（借鉴 smartdns 的 `debug-save-fail-packet`）。
//!
//! 只在 **debug 日志级别** 下由 `log_query` 调用，触发条件（任一）：
//! - 最终失败（err 非空，例如所有上游都失败 / 上游全被禁用）
//! - 响应 rcode = SERVFAIL
//! - 单条查询耗时 >= 2000 ms
//!
//! 落盘目录默认是 `<日志文件所在目录>/mosdns-fail`，可用 `log.fail_dir` 覆盖。
//! 自带三道闸：每分钟文件数上限、目录总大小上限、按天清理，避免故障时把盘写满。

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

struct State {
    dir: PathBuf,
    per_min: usize,
    keep_days: u64,
    max_total: u64,
    recent: VecDeque<Instant>,
    writes: u64,
    skipped: u64,
}

static ST: OnceLock<Mutex<State>> = OnceLock::new();

/// 初始化（只在 debug 下调用；失败则整个功能自动禁用）
pub fn init(dir: PathBuf, per_min: usize, keep_days: u64, max_total_mb: u64) {
    if per_min == 0 {
        return;
    }
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let max_total = max_total_mb * 1024 * 1024;
    cleanup(&dir, keep_days, max_total);
    let _ = ST.set(Mutex::new(State {
        dir,
        per_min,
        keep_days,
        max_total,
        recent: VecDeque::new(),
        writes: 0,
        skipped: 0,
    }));
}

pub fn is_enabled() -> bool {
    ST.get().is_some()
}

/// 写一个失败样本。`header` 是多行元信息，`raw_hex` 是原始查询报文的十六进制。
/// 返回是否真的落盘（被限流/未启用时为 false）。
pub fn dump(stamp: &str, qname: &str, qtype: u16, header: &str, raw_hex: &str) -> bool {
    let cell = match ST.get() {
        Some(c) => c,
        None => return false,
    };
    let mut st = match cell.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };

    let now = Instant::now();
    while let Some(t) = st.recent.front() {
        if now.duration_since(*t) > Duration::from_secs(60) {
            st.recent.pop_front();
        } else {
            break;
        }
    }
    if st.recent.len() >= st.per_min {
        st.skipped += 1;
        return false;
    }
    st.recent.push_back(now);

    let name = format!(
        "{}-{}-{}.txt",
        compact_stamp(stamp),
        sanitize(qname),
        qtype
    );
    let path = st.dir.join(&name);
    let mut body = String::with_capacity(header.len() + raw_hex.len() + 128);
    body.push_str(header);
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str("# 原始查询报文（xxd -r -p 可还原）:\n");
    for chunk in raw_hex.as_bytes().chunks(64) {
        // hex 全是 ASCII，按字节切安全
        body.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        body.push('\n');
    }
    let ok = fs::write(&path, body.as_bytes()).is_ok();
    st.writes += 1;

    // 每 200 个文件做一次清理
    if st.writes % 200 == 0 {
        let (dir, keep_days, max_total) = (st.dir.clone(), st.keep_days, st.max_total);
        cleanup(&dir, keep_days, max_total);
    }
    if st.skipped > 0 && st.writes % 200 == 0 {
        crate::log::debug(format!(
            "faildump 已写入 {} 个样本，因限流跳过 {} 个（目录 {}）",
            st.writes,
            st.skipped,
            st.dir.display()
        ));
    }
    ok
}

/// "2026-10-21 09:30:12.345" -> "20261021-093012.345"
fn compact_stamp(s: &str) -> String {
    s.replace(['-', ' '], "").replace(':', "")
}

/// 文件名里只留安全字符，并限制长度
fn sanitize(qname: &str) -> String {
    let mut out = String::with_capacity(64);
    for c in qname.trim_end_matches('.').chars() {
        if out.len() >= 60 {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// 按天数 + 总大小清理旧文件
fn cleanup(dir: &Path, keep_days: u64, max_total: u64) {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    let now = SystemTime::now();
    let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let md = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime = md.modified().unwrap_or(now);
        // 超期直接删
        if let Ok(age) = now.duration_since(mtime) {
            if age > Duration::from_secs(keep_days * 86400) {
                let _ = fs::remove_file(&p);
                continue;
            }
        }
        files.push((p, md.len(), mtime));
    }
    // 总大小超限就从最旧开始删
    let mut total: u64 = files.iter().map(|(_, s, _)| *s).sum();
    if total <= max_total {
        return;
    }
    files.sort_by_key(|(_, _, t)| *t);
    for (p, sz, _) in files {
        if total <= max_total {
            break;
        }
        if fs::remove_file(&p).is_ok() {
            total = total.saturating_sub(sz);
        }
    }
}
