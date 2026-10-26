//! Domain / IP matchers, mirroring mosdns pkg/matcher.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;

use crate::dns::normalize_domain;

// ---------------- domain matcher ----------------

#[derive(Default)]
struct Node {
    children: HashMap<String, Node>,
    value: bool,
}

impl Node {
    fn len(&self) -> usize {
        let mut n = 0;
        for c in self.children.values() {
            n += c.len();
            if c.value {
                n += 1;
            }
        }
        n
    }
}

pub struct DomainSet {
    full: HashSet<String>,
    domain: Node,
    keyword: Vec<String>,
    regex: Vec<Regex>,
    len: usize,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSet {
    pub fn new() -> DomainSet {
        DomainSet {
            full: HashSet::new(),
            domain: Node::default(),
            keyword: Vec::new(),
            regex: Vec::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Add a rule. `default_matcher` is used when the rule has no "type:" prefix.
    pub fn add(&mut self, rule: &str, default_matcher: &str) -> Result<(), String> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(());
        }
        let (typ, pattern) = match rule.split_once(':') {
            Some((t, p))
                if t == "full" || t == "domain" || t == "keyword" || t == "regexp" =>
            {
                (t.to_string(), p.to_string())
            }
            _ => (default_matcher.to_string(), rule.to_string()),
        };
        match typ.as_str() {
            "full" => {
                let n = normalize_domain(&pattern);
                if self.full.insert(n) {
                    self.len += 1;
                }
            }
            "domain" => {
                let n = normalize_domain(&pattern);
                let labels: Vec<&str> = if n.is_empty() {
                    vec![]
                } else {
                    n.split('.').collect()
                };
                let mut cur = &mut self.domain;
                for l in labels.iter().rev() {
                    cur = cur.children.entry(l.to_string()).or_default();
                }
                if !cur.value {
                    cur.value = true;
                    self.len += 1;
                }
            }
            "keyword" => {
                let n = normalize_domain(&pattern);
                if !n.is_empty() {
                    self.keyword.push(n);
                    self.len += 1;
                }
            }
            "regexp" => match Regex::new(&pattern) {
                Ok(re) => {
                    self.regex.push(re);
                    self.len += 1;
                }
                Err(e) => return Err(format!("invalid regexp [{}]: {}", pattern, e)),
            },
            other => return Err(format!("unsupported match type [{}]", other)),
        }
        Ok(())
    }

    pub fn add_file(&mut self, path: &str, default_matcher: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path, e))?;
        for (i, raw) in text.lines().enumerate() {
            let s = raw.split('#').next().unwrap_or("").trim();
            if s.is_empty() {
                continue;
            }
            self.add(s, default_matcher)
                .map_err(|e| format!("{} line {}: {}", path, i + 1, e))?;
        }
        Ok(())
    }

    pub fn matches(&self, name: &str) -> bool {
        let n = normalize_domain(name);
        if self.full.contains(&n) {
            return true;
        }
        // subdomain matcher: walk labels from the right, keep deepest hit
        let mut cur = &self.domain;
        let mut hit = cur.value;
        for label in n.split('.').rev() {
            match cur.children.get(label) {
                Some(c) => {
                    cur = c;
                    if cur.value {
                        hit = true;
                    }
                }
                None => break,
            }
        }
        if hit {
            return true;
        }
        for re in &self.regex {
            if re.is_match(&n) {
                return true;
            }
        }
        for kw in &self.keyword {
            if n.contains(kw.as_str()) {
                return true;
            }
        }
        false
    }
}

// ---------------- ip set ----------------

pub struct IpSet {
    v4: Vec<(u32, u8)>,
    v6: Vec<(u128, u8)>,
    count: usize,
    seen: HashSet<(u8, u128, u8)>,
    sorted: bool,
}

impl IpSet {
    pub fn new() -> IpSet {
        IpSet {
            v4: Vec::new(),
            v6: Vec::new(),
            count: 0,
            seen: HashSet::new(),
            sorted: false,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// (v4 前缀数, v6 前缀数)
    pub fn counts(&self) -> (usize, usize) {
        (self.v4.len(), self.v6.len())
    }

    /// 加入一个 IPv4 前缀（会自动按掩码归一化）。
    pub fn add_v4_prefix(&mut self, ip: u32, len: u8) {
        if len > 32 {
            return;
        }
        let net = if len == 0 { 0 } else { ip & (!0u32 << (32 - len)) };
        if self.seen.insert((4u8, net as u128, len)) {
            self.v4.push((net, len));
            self.count += 1;
            self.sorted = false;
        }
    }

    /// 加入一个 IPv6 前缀（会自动按掩码归一化）。
    pub fn add_v6_prefix(&mut self, ip: u128, len: u8) {
        if len > 128 {
            return;
        }
        let net = if len == 0 { 0 } else { ip & (!0u128 << (128 - len)) };
        if self.seen.insert((6u8, net, len)) {
            self.v6.push((net, len));
            self.count += 1;
            self.sorted = false;
        }
    }

    pub fn add(&mut self, s: &str) -> Result<(), String> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(());
        }
        let (addr_str, prefix) = match s.split_once('/') {
            Some((a, p)) => (
                a,
                p.parse::<u8>()
                    .map_err(|_| format!("invalid prefix length [{}]", s))?,
            ),
            None => (s, 255u8),
        };
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| format!("invalid ip addr [{}]", addr_str))?;
        match addr {
            IpAddr::V4(a) => self.add_v4_prefix(u32::from(a), if prefix == 255 { 32 } else { prefix }),
            IpAddr::V6(a) => self.add_v6_prefix(u128::from(a), if prefix == 255 { 128 } else { prefix }),
        }
        Ok(())
    }

    pub fn add_file(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path, e))?;
        for (i, raw) in text.lines().enumerate() {
            let s = raw.split('#').next().unwrap_or("").trim();
            if s.is_empty() {
                continue;
            }
            self.add(s)
                .map_err(|e| format!("{} line {}: {}", path, i + 1, e))?;
        }
        Ok(())
    }

    /// Merge another set into this one (mosdns uses matcher groups; merging is
    /// semantically identical for membership tests).
    pub fn merge(&mut self, other: &IpSet) {
        for &(net, len) in &other.v4 {
            self.add_v4_prefix(net, len);
        }
        for &(net, len) in &other.v6 {
            self.add_v6_prefix(net, len);
        }
    }

    /// 排序 + 去重 + 去掉被前驱覆盖的前缀，使集合变成互不重叠的有序表
    /// （与 mosdns netlist.List.Sort 的策略一致），之后可用二分查找。
    pub fn compact(&mut self) {
        self.v4.sort_unstable();
        let mut out: Vec<(u32, u8)> = Vec::with_capacity(self.v4.len());
        for &(net, len) in self.v4.iter() {
            if let Some(&(lnet, llen)) = out.last() {
                if lnet == net {
                    continue; // 同地址：保留短前缀（先出现）
                }
                if llen <= len && (net & mask32(llen)) == lnet {
                    continue; // 被前一个前缀覆盖
                }
            }
            out.push((net, len));
        }
        self.v4 = out;

        self.v6.sort_unstable();
        let mut out6: Vec<(u128, u8)> = Vec::with_capacity(self.v6.len());
        for &(net, len) in self.v6.iter() {
            if let Some(&(lnet, llen)) = out6.last() {
                if lnet == net {
                    continue;
                }
                if llen <= len && (net & mask128(llen)) == lnet {
                    continue;
                }
            }
            out6.push((net, len));
        }
        self.v6 = out6;
        self.count = self.v4.len() + self.v6.len();
        self.sorted = true;
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                let v = u32::from(a);
                if self.sorted {
                    let idx = self.v4.partition_point(|&(net, _)| net <= v);
                    if idx == 0 {
                        return false;
                    }
                    let (net, len) = self.v4[idx - 1];
                    return len == 0 || (v & mask32(len)) == net;
                }
                self.v4
                    .iter()
                    .any(|&(net, len)| len == 0 || (v & mask32(len)) == net)
            }
            IpAddr::V6(a) => {
                let v = u128::from(a);
                if self.sorted {
                    let idx = self.v6.partition_point(|&(net, _)| net <= v);
                    if idx == 0 {
                        return false;
                    }
                    let (net, len) = self.v6[idx - 1];
                    return len == 0 || (v & mask128(len)) == net;
                }
                self.v6
                    .iter()
                    .any(|&(net, len)| len == 0 || (v & mask128(len)) == net)
            }
        }
    }
}

// ---------------- hosts / redirect ----------------

#[derive(Default)]
pub struct HostsMap {
    map: HashMap<String, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)>,
}

impl HostsMap {
    pub fn add(&mut self, s: &str) -> Result<(), String> {
        let mut f = s.split_whitespace();
        let pattern = match f.next() {
            Some(p) => p,
            None => return Err("empty entry".to_string()),
        };
        let pattern = pattern
            .strip_prefix("full:")
            .or_else(|| pattern.strip_prefix("domain:"))
            .unwrap_or(pattern);
        let key = normalize_domain(pattern);
        let e = self.map.entry(key).or_default();
        for ip in f {
            let a: IpAddr = ip
                .parse()
                .map_err(|_| format!("invalid ip addr [{}]", ip))?;
            match a {
                IpAddr::V4(v) => e.0.push(v),
                IpAddr::V6(v) => e.1.push(v),
            }
        }
        Ok(())
    }

    pub fn add_file(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path, e))?;
        for (i, raw) in text.lines().enumerate() {
            let s = raw.split('#').next().unwrap_or("").trim();
            if s.is_empty() {
                continue;
            }
            self.add(s)
                .map_err(|e| format!("{} line {}: {}", path, i + 1, e))?;
        }
        Ok(())
    }

    pub fn lookup(&self, name: &str) -> Option<&(Vec<Ipv4Addr>, Vec<Ipv6Addr>)> {
        self.map.get(&normalize_domain(name))
    }
}

#[derive(Default)]
pub struct RedirectMap {
    map: HashMap<String, String>,
}

impl RedirectMap {
    pub fn add_rule(&mut self, s: &str) -> Result<(), String> {
        let f: Vec<&str> = s.split_whitespace().collect();
        if f.len() != 2 {
            return Err(format!(
                "redirect rule must have 2 fields, but got {}",
                f.len()
            ));
        }
        let key = normalize_domain(f[0]);
        self.map.insert(key, crate::dns::fqdn(f[1]));
        Ok(())
    }

    pub fn add_file(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path, e))?;
        for (i, raw) in text.lines().enumerate() {
            let s = raw.split('#').next().unwrap_or("").trim();
            if s.is_empty() {
                continue;
            }
            self.add_rule(s)
                .map_err(|e| format!("{} line {}: {}", path, i + 1, e))?;
        }
        Ok(())
    }

    pub fn lookup(&self, name: &str) -> Option<&String> {
        self.map.get(&normalize_domain(name))
    }
}

#[inline]
fn mask32(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        !0u32 << (32 - len as u32)
    }
}

#[inline]
fn mask128(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        !0u128 << (128 - len as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute_contains(set: &IpSet, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                let v = u32::from(a);
                set.v4
                    .iter()
                    .any(|&(net, len)| len == 0 || (v & mask32(len)) == net)
            }
            IpAddr::V6(a) => {
                let v = u128::from(a);
                set.v6
                    .iter()
                    .any(|&(net, len)| len == 0 || (v & mask128(len)) == net)
            }
        }
    }

    #[test]
    fn compact_matches_bruteforce() {
        let mut set = IpSet::new();
        // 覆盖包含关系、同地址不同长度、重复项
        for s in [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.0.0.0/24",
            "192.168.0.0/16",
            "192.168.1.0/24",
            "1.2.3.4/32",
            "0.0.0.0/0",
            "2408::/22",
            "2408:8000::/32",
            "2001:db8::/32",
        ] {
            set.add(s).unwrap();
        }
        let before_v4 = set.v4.clone();
        let before_v6 = set.v6.clone();
        set.compact();
        let mut set2 = IpSet::new();
        set2.v4 = before_v4;
        set2.v6 = before_v6;
        let probes: Vec<IpAddr> = vec![
            "10.0.0.1".parse().unwrap(),
            "10.2.3.4".parse().unwrap(),
            "11.0.0.1".parse().unwrap(),
            "192.168.1.9".parse().unwrap(),
            "192.169.0.1".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            "1.2.3.5".parse().unwrap(),
            "2408:8000::1".parse().unwrap(),
            "2409::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ];
        for ip in probes {
            assert_eq!(set.contains(ip), brute_contains(&set2, ip), "ip={}", ip);
        }
        assert!(set.sorted);
    }
}
