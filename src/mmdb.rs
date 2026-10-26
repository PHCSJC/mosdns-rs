//! MaxMind DB (MMDB) reader: tree traversal + data-section decoding.
//!
//! 只依赖 std。支持 record_size 24/28/32、IPv4-mapped 前缀（`::ffff:0:0/96` 与 `::/96`）、
//! 按 `country.iso_code` 过滤，用于把 Country.mmdb 直接当作 ip_set 数据源。

use crate::domain::IpSet;

pub const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

#[derive(Debug, Clone)]
pub enum Value {
    Map(Vec<(String, Value)>),
    Array(Vec<Value>),
    Str(String),
    Bytes(Vec<u8>),
    Uint(u128),
    Int(i64),
    Double(f64),
    Float(f32),
    Bool(bool),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => Some(*v as u64),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Meta {
    pub database_type: String,
    pub ip_version: u16,
    pub record_size: u16,
    pub node_count: usize,
    pub build_epoch: u64,
    pub languages: Vec<String>,
    pub description: Vec<String>,
}

pub struct Mmdb {
    buf: Vec<u8>,
    node_count: usize,
    record_size: u16,
    ip_version: u16,
    tree_size: usize,
    data_start: usize,
    meta_start: usize,
    node_bytes: usize,
    pub meta: Meta,
}

impl Mmdb {
    pub fn open(path: &str) -> Result<Mmdb, String> {
        let buf = std::fs::read(path).map_err(|e| format!("failed to read {}: {}", path, e))?;
        Mmdb::from_bytes(buf).map_err(|e| format!("{}: {}", path, e))
    }

    pub fn from_bytes(buf: Vec<u8>) -> Result<Mmdb, String> {
        let marker_pos = find_marker(&buf).ok_or("not an mmdb file (marker not found)")?;
        let meta_start = marker_pos + MARKER.len();
        let mut m = Mmdb {
            node_count: 0,
            record_size: 0,
            ip_version: 0,
            tree_size: 0,
            data_start: 0,
            meta_start,
            node_bytes: 0,
            meta: Meta::default(),
            buf,
        };
        let meta_val = m.decode(meta_start, meta_start)?.0;
        let mt = match &meta_val {
            Value::Map(_) => meta_val.clone(),
            _ => return Err("invalid metadata (not a map)".to_string()),
        };
        m.meta.node_count = mt
            .get("node_count")
            .and_then(|v| v.as_u64())
            .ok_or("metadata: node_count missing")? as usize;
        m.meta.record_size = mt
            .get("record_size")
            .and_then(|v| v.as_u64())
            .ok_or("metadata: record_size missing")? as u16;
        m.meta.ip_version = mt
            .get("ip_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(6) as u16;
        m.meta.database_type = mt
            .get("database_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        m.meta.build_epoch = mt
            .get("build_epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if let Some(Value::Array(a)) = mt.get("languages") {
            m.meta.languages = a
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(Value::Array(a)) = mt.get("description") {
            m.meta.description = a
                .iter()
                .filter_map(|v| match v {
                    Value::Map(_) => Some(
                        v.get("zh-CN")
                            .or_else(|| v.get("en"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    Value::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .filter(|s| !s.is_empty())
                .collect();
        }

        if m.meta.record_size != 24 && m.meta.record_size != 28 && m.meta.record_size != 32 {
            return Err(format!("unsupported record_size {}", m.meta.record_size));
        }
        m.node_count = m.meta.node_count;
        m.record_size = m.meta.record_size;
        m.ip_version = m.meta.ip_version;
        m.node_bytes = (m.record_size as usize) / 4;
        m.tree_size = m.node_count * m.node_bytes;
        // search tree 之后是 16 字节的 data section 分隔符
        m.data_start = m.tree_size + 16;
        if m.data_start > meta_start {
            return Err("corrupted mmdb (data section beyond metadata)".to_string());
        }
        Ok(m)
    }

    pub fn node_count(&self) -> usize {
        self.node_count
    }

    fn byte(&self, off: usize) -> Result<u8, String> {
        self.buf
            .get(off)
            .copied()
            .ok_or_else(|| format!("mmdb read out of range at {}", off))
    }

    fn be(&self, off: usize, n: usize) -> Result<u128, String> {
        let mut v: u128 = 0;
        for i in 0..n {
            v = (v << 8) | self.byte(off + i)? as u128;
        }
        Ok(v)
    }

    /// 返回 (类型, 大小, 下一个字节位置)；指针类型的 size 字段不参与扩展。
    fn ctrl(&self, off: usize) -> Result<(u8, usize, usize), String> {
        let b0 = self.byte(off)?;
        let mut typ = b0 >> 5;
        let mut p = off + 1;
        if typ == 0 {
            typ = self.byte(p)? + 7;
            p += 1;
        }
        let mut size = (b0 & 0x1f) as usize;
        if typ == 1 {
            return Ok((1, size, p)); // 指针：size 位是指针长度编码
        }
        if size == 29 {
            size = 29 + self.byte(p)? as usize;
            p += 1;
        } else if size == 30 {
            size = 285 + self.be(p, 2)? as usize;
            p += 2;
        } else if size == 31 {
            size = 65821 + self.be(p, 3)? as usize;
            p += 3;
        }
        Ok((typ, size, p))
    }

    pub fn decode(&self, off: usize, base: usize) -> Result<(Value, usize), String> {
        let b0 = self.byte(off)?;
        let typ = b0 >> 5;
        if typ == 1 {
            let ps = (b0 >> 3) & 0x3;
            let (ptr, np) = match ps {
                0 => ((((b0 & 0x7) as usize) << 8) | self.byte(off + 1)? as usize, off + 2),
                1 => (
                    (((((b0 & 0x7) as usize) << 16)
                        | ((self.byte(off + 1)? as usize) << 8)
                        | self.byte(off + 2)? as usize)
                        + 2048),
                    off + 3,
                ),
                2 => (
                    (((((b0 & 0x7) as usize) << 24)
                        | ((self.byte(off + 1)? as usize) << 16)
                        | ((self.byte(off + 2)? as usize) << 8)
                        | self.byte(off + 3)? as usize)
                        + 526336),
                    off + 4,
                ),
                _ => (
                    u32::from_be_bytes([
                        self.byte(off + 1)?,
                        self.byte(off + 2)?,
                        self.byte(off + 3)?,
                        self.byte(off + 4)?,
                    ]) as usize,
                    off + 5,
                ),
            };
            let (v, _) = self.decode(base + ptr, base)?;
            return Ok((v, np));
        }

        let (typ, size, mut p) = self.ctrl(off)?;
        let v = match typ {
            2 => {
                let s = String::from_utf8_lossy(&self.buf[p..p + size]).into_owned();
                p += size;
                Value::Str(s)
            }
            3 => {
                let mut b = [0u8; 8];
                for i in 0..size.min(8) {
                    b[i] = self.byte(p + i)?;
                }
                p += size;
                Value::Double(f64::from_be_bytes(b))
            }
            4 => {
                let v = self.buf[p..p + size].to_vec();
                p += size;
                Value::Bytes(v)
            }
            5 | 6 | 9 | 10 => {
                let v = self.be(p, size)?;
                p += size;
                Value::Uint(v)
            }
            7 => {
                let mut m = Vec::with_capacity(size);
                for _ in 0..size {
                    let (k, np) = self.decode(p, base)?;
                    let key = match k {
                        Value::Str(s) => s,
                        other => format!("{:?}", other),
                    };
                    let (val, np2) = self.decode(np, base)?;
                    m.push((key, val));
                    p = np2;
                }
                Value::Map(m)
            }
            8 => {
                let raw = self.be(p, size)? as u64;
                p += size;
                let bits = size * 8;
                let v = if bits < 64 && (raw >> (bits - 1)) & 1 == 1 {
                    ((raw as i64) - (1i64 << bits)) as i64
                } else {
                    raw as i64
                };
                Value::Int(v)
            }
            11 => {
                let mut arr = Vec::with_capacity(size);
                for _ in 0..size {
                    let (v, np) = self.decode(p, base)?;
                    arr.push(v);
                    p = np;
                }
                Value::Array(arr)
            }
            14 => {
                let v = self.byte(p)? != 0;
                p += 1;
                Value::Bool(v)
            }
            15 => {
                let mut b = [0u8; 4];
                for i in 0..size.min(4) {
                    b[i] = self.byte(p + i)?;
                }
                p += size;
                Value::Float(f32::from_be_bytes(b))
            }
            other => return Err(format!("unsupported mmdb data type {}", other)),
        };
        Ok((v, p))
    }

    fn skip(&self, off: usize, base: usize) -> Result<usize, String> {
        let b0 = self.byte(off)?;
        if b0 >> 5 == 1 {
            let ps = (b0 >> 3) & 0x3;
            return Ok(off + 1 + [1usize, 2, 3, 4][ps as usize]);
        }
        let (typ, size, mut p) = self.ctrl(off)?;
        match typ {
            2 | 3 | 4 | 5 | 6 | 9 | 10 | 15 => {
                p += size;
            }
            7 => {
                for _ in 0..size {
                    p = self.skip(p, base)?;
                    p = self.skip(p, base)?;
                }
            }
            11 => {
                for _ in 0..size {
                    p = self.skip(p, base)?;
                }
            }
            14 => {
                p += size;
            }
            other => return Err(format!("unsupported mmdb data type {}", other)),
        }
        Ok(p)
    }

    fn node(&self, n: usize) -> Result<(usize, usize), String> {
        let b = n * self.node_bytes;
        let p = self.tree_size;
        if b + self.node_bytes > p {
            return Err("node index out of tree".to_string());
        }
        match self.record_size {
            24 => Ok((
                self.be(b, 3)? as usize,
                self.be(b + 3, 3)? as usize,
            )),
            28 => {
                let left = ((self.byte(b)? as usize) << 20)
                    | ((self.byte(b + 1)? as usize) << 12)
                    | ((self.byte(b + 2)? as usize) << 4)
                    | ((self.byte(b + 3)? as usize) >> 4);
                let right = (((self.byte(b + 3)? & 0x0F) as usize) << 24)
                    | ((self.byte(b + 4)? as usize) << 16)
                    | ((self.byte(b + 5)? as usize) << 8)
                    | (self.byte(b + 6)? as usize);
                Ok((left, right))
            }
            _ => Ok((
                self.be(b, 4)? as usize,
                self.be(b + 4, 4)? as usize,
            )),
        }
    }

    /// 一次性遍历整棵树，返回 (128bit 前缀, 前缀长度, data section 偏移)。
    pub fn networks(&self) -> Result<Vec<(u128, u8, usize)>, String> {
        let mut out = Vec::new();
        let mut stack: Vec<(usize, u128, u8)> = Vec::with_capacity(1024);
        stack.push((0, 0, 0));
        while let Some((node, prefix, depth)) = stack.pop() {
            if node == self.node_count {
                continue; // 空节点
            }
            if node > self.node_count {
                out.push((prefix, depth, self.data_offset(node)?));
                continue;
            }
            if depth >= 128 {
                continue;
            }
            let (l, r) = self.node(node)?;
            stack.push((r, prefix | (1u128 << (127 - depth as u32)), depth + 1));
            stack.push((l, prefix, depth + 1));
        }
        Ok(out)
    }

    /// 就地查找某个 IP 的记录（用于校验/调试）。
    pub fn lookup(&self, ip: std::net::IpAddr) -> Result<Option<Value>, String> {
        let (mut node, bits, val) = match ip {
            std::net::IpAddr::V4(v4) => {
                // v6 库中 v4 位于 ::ffff:0:0/96 或 ::/96
                let mut n = 0usize;
                for _ in 0..96 {
                    let (l, _r) = self.node(n)?;
                    n = l;
                }
                (n, 32u32, u32::from(v4) as u128)
            }
            std::net::IpAddr::V6(v6) => (0usize, 128u32, u128::from(v6)),
        };
        for i in 0..bits {
            if node >= self.node_count {
                break;
            }
            let bit = (val >> (bits - 1 - i)) & 1;
            let (l, r) = self.node(node)?;
            node = if bit == 1 { r } else { l };
        }
        if node <= self.node_count {
            return Ok(None);
        }
        let off = self.data_offset(node)?;
        Ok(Some(self.decode(off, self.data_start)?.0))
    }

    /// 记录值 > node_count 时指向数据区：偏移需扣掉 node_count 与 16 字节分隔符。
    fn data_offset(&self, record: usize) -> Result<usize, String> {
        let delta = record
            .checked_sub(self.node_count + 16)
            .ok_or("invalid data pointer")?;
        let off = self.data_start + delta;
        if off >= self.meta_start {
            return Err("data pointer beyond data section".to_string());
        }
        Ok(off)
    }

    /// 跟随数据区指针，返回真正的值起始偏移（记录里常直接放指针做去重）。
    fn resolve(&self, off: usize, base: usize) -> Result<usize, String> {
        let mut p = off;
        for _ in 0..8 {
            let b0 = self.byte(p)?;
            if b0 >> 5 != 1 {
                return Ok(p);
            }
            let ps = (b0 >> 3) & 0x3;
            let ptr = match ps {
                0 => (((b0 & 0x7) as usize) << 8) | self.byte(p + 1)? as usize,
                1 => {
                    ((((b0 & 0x7) as usize) << 16)
                        | ((self.byte(p + 1)? as usize) << 8)
                        | self.byte(p + 2)? as usize)
                        + 2048
                }
                2 => {
                    ((((b0 & 0x7) as usize) << 24)
                        | ((self.byte(p + 1)? as usize) << 16)
                        | ((self.byte(p + 2)? as usize) << 8)
                        | self.byte(p + 3)? as usize)
                        + 526336
                }
                _ => {
                    u32::from_be_bytes([
                        self.byte(p + 1)?,
                        self.byte(p + 2)?,
                        self.byte(p + 3)?,
                        self.byte(p + 4)?,
                    ]) as usize
                }
            };
            p = base + ptr;
        }
        Err("too many pointer redirections".to_string())
    }

    /// 读取某条记录的 country.iso_code（优先 country，其次 registered_country）。
    fn iso_code_at(&self, off: usize) -> Result<Option<String>, String> {
        let off = self.resolve(off, self.data_start)?;
        let (typ, size, mut p) = self.ctrl(off)?;
        if typ != 7 {
            return Ok(None);
        }
        let mut country: Option<String> = None;
        let mut registered: Option<String> = None;
        for _ in 0..size {
            let (k, np) = self.decode(p, self.data_start)?;
            let key = k.as_str().unwrap_or("").to_string();
            if key == "country" || key == "registered_country" {
                let iso = self.iso_code_in_map(np)?;
                if key == "country" {
                    country = iso;
                } else {
                    registered = iso;
                }
            }
            p = self.skip(np, self.data_start)?;
        }
        Ok(country.or(registered))
    }

    fn iso_code_in_map(&self, off: usize) -> Result<Option<String>, String> {
        let off = self.resolve(off, self.data_start)?;
        let (typ, size, mut p) = self.ctrl(off)?;
        if typ != 7 {
            return Ok(None);
        }
        for _ in 0..size {
            let (k, np) = self.decode(p, self.data_start)?;
            let key = k.as_str().unwrap_or("").to_string();
            if key == "iso_code" {
                let v = self.resolve(np, self.data_start)?;
                let (v, _) = self.decode(v, self.data_start)?;
                return Ok(v.as_str().map(|s| s.to_ascii_uppercase()));
            }
            p = self.skip(np, self.data_start)?;
        }
        Ok(None)
    }

    /// 把库内容灌进 ip_set。
    /// `country`: Some("CN") 只收该国；None 表示收全部。
    /// `ipv4_only`: 只取 IPv4（等价于旧版 geoip-only-cn.txt 行为）。
    pub fn load_into(
        &self,
        set: &mut IpSet,
        country: Option<&str>,
        ipv4_only: bool,
    ) -> Result<MmdbStats, String> {
        let mut st = MmdbStats::default();
        let nets = self.networks()?;
        st.networks = nets.len();
        let (v4_before, v6_before) = set.counts();
        for (prefix, depth, off) in nets {
            if let Some(cc) = country {
                match self.iso_code_at(off)? {
                    Some(iso) if iso.eq_ignore_ascii_case(cc) => {}
                    _ => {
                        st.filtered_out += 1;
                        continue;
                    }
                }
            }
            if depth >= 96 {
                let top = prefix >> 32; // 高 96 位
                if top == 0xffff || top == 0 {
                    let ip = (prefix & 0xffff_ffff) as u32;
                    let len = depth - 96;
                    set.add_v4_prefix(ip, len);
                    st.v4 += 1;
                    continue;
                }
            }
            if ipv4_only {
                st.v6_skipped += 1;
                continue;
            }
            set.add_v6_prefix(prefix, depth);
            st.v6 += 1;
        }
        // 库里同一份 IPv4 会在 ::/96 和 ::ffff:0:0/96 各出现一次，去重后才是真实条目数
        let (v4_after, v6_after) = set.counts();
        st.v4_unique = v4_after - v4_before;
        st.v6_unique = v6_after - v6_before;
        Ok(st)
    }

    /// 把库内容按 CIDR 文本输出（--dump-ipset 用）。
    pub fn dump(&self, country: Option<&str>, ipv4_only: bool) -> Result<Vec<String>, String> {
        let mut v4: Vec<(u32, u8)> = Vec::new();
        let mut v6: Vec<(u128, u8)> = Vec::new();
        for (prefix, depth, off) in self.networks()? {
            if let Some(cc) = country {
                match self.iso_code_at(off)? {
                    Some(iso) if iso.eq_ignore_ascii_case(cc) => {}
                    _ => continue,
                }
            }
            if depth >= 96 {
                let top = prefix >> 32;
                if top == 0xffff || top == 0 {
                    v4.push(((prefix & 0xffff_ffff) as u32, depth - 96));
                    continue;
                }
            }
            if !ipv4_only {
                v6.push((prefix, depth));
            }
        }
        v4.sort();
        v4.dedup();
        v6.sort();
        v6.dedup();
        let mut out = Vec::with_capacity(v4.len() + v6.len());
        for (ip, len) in v4 {
            out.push(format!("{}/{}", std::net::Ipv4Addr::from(ip), len));
        }
        for (ip, len) in v6 {
            out.push(format!("{}/{}", std::net::Ipv6Addr::from(ip), len));
        }
        Ok(out)
    }
}

#[derive(Debug, Default)]
pub struct MmdbStats {
    pub networks: usize,
    pub filtered_out: usize,
    /// 匹配到的原始记录数（含 v4 两种编码的重复）
    pub v4: usize,
    pub v6: usize,
    /// 去重后实际加入集合的条目数
    pub v4_unique: usize,
    pub v6_unique: usize,
    pub v6_skipped: usize,
}

fn find_marker(buf: &[u8]) -> Option<usize> {
    if buf.len() < MARKER.len() {
        return None;
    }
    // marker 一定在文件末尾 128KB 内
    let start = buf.len().saturating_sub(128 * 1024);
    let mut found = None;
    let mut i = start;
    while i + MARKER.len() <= buf.len() {
        if &buf[i..i + MARKER.len()] == MARKER {
            found = Some(i);
        }
        i += 1;
    }
    found
}

/// 快速判断一个文件是否是 mmdb（只看尾部标记，不解析）。
pub fn is_mmdb_bytes(buf: &[u8]) -> bool {
    find_marker(buf).is_some()
}

pub fn is_mmdb_file(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => {
            if m.len() < MARKER.len() as u64 {
                return false;
            }
            match std::fs::File::open(path) {
                Ok(mut f) => {
                    use std::io::{Read, Seek, SeekFrom};
                    let len = m.len();
                    let start = len.saturating_sub(128 * 1024);
                    if f.seek(SeekFrom::Start(start)).is_err() {
                        return false;
                    }
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_err() {
                        return false;
                    }
                    is_mmdb_bytes(&buf)
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}
