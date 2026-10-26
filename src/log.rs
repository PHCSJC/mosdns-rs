//! 分级日志：支持按大小轮转（默认 64MB × 5 份），时间戳带毫秒。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const LV_DEBUG: u8 = 0;
pub const LV_INFO: u8 = 1;
pub const LV_WARN: u8 = 2;
pub const LV_ERROR: u8 = 3;

struct FileState {
    f: File,
    path: PathBuf,
    size: u64,
}

struct Logger {
    level: u8,
    file: Option<Mutex<FileState>>,
    stderr: bool,
    max_size: u64,
    keep: usize,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn parse_level(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "debug" => LV_DEBUG,
        "warn" | "warning" => LV_WARN,
        "error" => LV_ERROR,
        _ => LV_INFO,
    }
}

/// 初始化日志。`path` 为空表示只写 stderr。
/// `max_mb` / `keep` 来自配置文件（`log.max_size_mb` / `log.keep`），
/// 未配置时回退环境变量，再回退内置默认（64MB × 5）。
pub fn init(
    level: &str,
    path: Option<&str>,
    stderr: bool,
    max_mb: Option<u64>,
    keep: Option<usize>,
) -> Result<(), String> {
    let lv = parse_level(level);
    let max_mb = max_mb
        .filter(|v| *v > 0)
        .or_else(|| {
            std::env::var("MOSDNS_RS_LOG_MAX_MB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
        })
        .unwrap_or(64);
    let keep = keep
        .filter(|v| *v > 0)
        .or_else(|| {
            std::env::var("MOSDNS_RS_LOG_KEEP")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0)
        })
        .unwrap_or(5);

    // 日志文件打不开就当成启动失败：宁可起不来，也不要"静默不记日志"
    let file = match path {
        Some(p) => match open_append(p) {
            Ok((f, size)) => Some(Mutex::new(FileState {
                f,
                path: PathBuf::from(p),
                size,
            })),
            Err(e) => return Err(format!("cannot open log file {}: {}", p, e)),
        },
        None => None,
    };

    let _ = LOGGER.set(Logger {
        level: lv,
        file,
        stderr,
        max_size: max_mb * 1024 * 1024,
        keep,
    });
    Ok(())
}

fn open_append(p: &str) -> std::io::Result<(File, u64)> {
    let f = OpenOptions::new().create(true).append(true).open(p)?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((f, size))
}

/// 该级别是否会被输出（调用方可用它跳过昂贵的字符串拼接）。
pub fn enabled(lv: u8) -> bool {
    match LOGGER.get() {
        Some(l) => lv >= l.level,
        None => true,
    }
}

pub fn now_ms_str() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    // 本机时区 UTC+8
    let t = secs + 8 * 3600;
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, dd) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        y,
        m,
        dd,
        h,
        mi,
        s,
        d.subsec_millis()
    )
}

/// Howard Hinnant's days -> (y, m, d)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn rotate(st: &mut FileState, keep: usize) {
    let base = st.path.clone();
    for i in (1..keep).rev() {
        let from = with_suffix(&base, i);
        let to = with_suffix(&base, i + 1);
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    let _ = std::fs::rename(&base, with_suffix(&base, 1));
    if let Ok((f, _)) = open_append(&base.to_string_lossy()) {
        st.f = f;
        st.size = 0;
    }
}

fn with_suffix(p: &Path, i: usize) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(format!(".{}", i));
    PathBuf::from(s)
}

fn write_level(lv: u8, name: &str, msg: &str) {
    let logger = match LOGGER.get() {
        Some(l) => l,
        None => {
            eprintln!("{} {} {}", now_ms_str(), name, msg);
            return;
        }
    };
    if lv < logger.level {
        return;
    }
    let line = format!("{} {} {}\n", now_ms_str(), name, msg);
    if let Some(m) = &logger.file {
        if let Ok(mut st) = m.lock() {
            let need = line.len() as u64;
            if st.size + need > logger.max_size {
                rotate(&mut st, logger.keep);
            }
            if st.f.write_all(line.as_bytes()).is_ok() {
                let _ = st.f.flush();
                st.size += need;
            }
        }
    }
    if logger.stderr {
        eprint!("{}", line);
    }
}

pub fn debug(msg: impl AsRef<str>) {
    write_level(LV_DEBUG, "DEBUG", msg.as_ref());
}
pub fn info(msg: impl AsRef<str>) {
    write_level(LV_INFO, "INFO", msg.as_ref());
}
pub fn warn(msg: impl AsRef<str>) {
    write_level(LV_WARN, "WARN", msg.as_ref());
}
pub fn error(msg: impl AsRef<str>) {
    write_level(LV_ERROR, "ERROR", msg.as_ref());
}
