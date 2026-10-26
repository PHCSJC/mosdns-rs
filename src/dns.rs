//! Minimal DNS wire-format implementation (parse / build / TTL helpers).
//! Semantics follow miekg/dns + mosdns v5 pkg/dnsutils.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_MD: u16 = 3;
pub const TYPE_MF: u16 = 4;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_MB: u16 = 7;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;
pub const CLASS_IN: u16 = 1;

pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;
pub const FLAG_AD: u16 = 0x0020;
pub const FLAG_CD: u16 = 0x0010;

pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;
pub const RCODE_REFUSED: u16 = 5;

#[derive(Clone, Debug)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// domain-name rdata: NS/CNAME/PTR/DNAME/MB/MD/MF
    Name(String),
    Mx(u16, String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv(u16, u16, u16, String),
    Raw(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct RR {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Clone, Debug, Default)]
pub struct Msg {
    pub id: u16,
    pub flags: u16,
    pub question: Vec<Question>,
    pub answer: Vec<RR>,
    pub ns: Vec<RR>,
    pub extra: Vec<RR>,
}

/// Normalize a domain: lowercase, strip trailing dot.
pub fn normalize_domain(s: &str) -> String {
    let s = s.strip_suffix('.').unwrap_or(s);
    s.to_ascii_lowercase()
}

pub fn fqdn(s: &str) -> String {
    if s.ends_with('.') {
        s.to_string()
    } else {
        format!("{}.", s)
    }
}

impl Msg {
    pub fn new() -> Msg {
        Msg::default()
    }

    pub fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0xF
    }

    pub fn rcode(&self) -> u16 {
        self.flags & 0xF
    }

    pub fn set_rcode(&mut self, rc: u16) {
        self.flags = (self.flags & !0x000F) | (rc & 0x000F);
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn ad(&self) -> bool {
        self.flags & FLAG_AD != 0
    }

    pub fn cd(&self) -> bool {
        self.flags & FLAG_CD != 0
    }

    /// miekg/dns Msg.SetReply
    pub fn set_reply(&self, rcode: u16) -> Msg {
        let mut r = Msg::new();
        r.id = self.id;
        r.flags = FLAG_QR;
        // copy opcode
        r.flags |= (self.flags & 0x7800) | (rcode & 0xF);
        if self.opcode() == 0 {
            r.flags |= self.flags & (FLAG_RD | FLAG_CD);
        }
        if let Some(q) = self.question.first() {
            r.question.push(q.clone());
        }
        r
    }

    pub fn opt(&self) -> Option<&RR> {
        self.extra.iter().find(|rr| rr.rtype == TYPE_OPT)
    }

    /// 0 = 无 EDNS0，1 = 有 EDNS0 无 DO 位，2 = EDNS0 且带 DO
    pub fn edns_level(&self) -> u8 {
        if self.is_edns0_do() {
            2
        } else if self.opt().is_some() {
            1
        } else {
            0
        }
    }

    pub fn is_edns0_do(&self) -> bool {
        match self.opt() {
            Some(o) => o.ttl & 0x8000 != 0,
            None => false,
        }
    }

    /// UDP payload size advertised by the query (>= 512).
    pub fn udp_size(&self) -> usize {
        let mut s = 0u16;
        if let Some(o) = self.opt() {
            s = o.class;
        }
        if s < 512 {
            s = 512;
        }
        s as usize
    }

    pub fn has_rr(&self, rtype: u16) -> bool {
        self.answer.iter().any(|rr| rr.rtype == rtype)
    }

    pub fn answer_ips(&self) -> Vec<IpAddrLike> {
        let mut v = Vec::new();
        for rr in &self.answer {
            match rr.rdata {
                RData::A(ip) => v.push(IpAddrLike::V4(ip)),
                RData::Aaaa(ip) => v.push(IpAddrLike::V6(ip)),
                _ => {}
            }
        }
        v
    }

    // ---------- TTL helpers (mosdns pkg/dnsutils) ----------

    pub fn minimal_ttl(&self) -> u32 {
        let mut min = u32::MAX;
        let mut has = false;
        for sec in [&self.answer, &self.ns, &self.extra] {
            for rr in sec.iter() {
                if rr.rtype == TYPE_OPT {
                    continue;
                }
                has = true;
                if rr.ttl < min {
                    min = rr.ttl;
                }
            }
        }
        if !has {
            0
        } else {
            min
        }
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        for sec in [&mut self.answer, &mut self.ns, &mut self.extra] {
            for rr in sec.iter_mut() {
                if rr.rtype == TYPE_OPT {
                    continue;
                }
                rr.ttl = ttl;
            }
        }
    }

    pub fn subtract_ttl(&mut self, delta: u32) {
        for sec in [&mut self.answer, &mut self.ns, &mut self.extra] {
            for rr in sec.iter_mut() {
                if rr.rtype == TYPE_OPT {
                    continue;
                }
                if rr.ttl > delta {
                    rr.ttl -= delta;
                } else {
                    rr.ttl = 1;
                }
            }
        }
    }

    pub fn apply_min_ttl(&mut self, ttl: u32) {
        for sec in [&mut self.answer, &mut self.ns, &mut self.extra] {
            for rr in sec.iter_mut() {
                if rr.rtype == TYPE_OPT {
                    continue;
                }
                if rr.ttl < ttl {
                    rr.ttl = ttl;
                }
            }
        }
    }

    pub fn apply_max_ttl(&mut self, ttl: u32) {
        for sec in [&mut self.answer, &mut self.ns, &mut self.extra] {
            for rr in sec.iter_mut() {
                if rr.rtype == TYPE_OPT {
                    continue;
                }
                if rr.ttl > ttl {
                    rr.ttl = ttl;
                }
            }
        }
    }

    /// Copy without OPT record in additional section (mosdns cache copyNoOpt).
    pub fn copy_no_opt(&self) -> Msg {
        let mut m = self.clone();
        m.extra.retain(|rr| rr.rtype != TYPE_OPT);
        m
    }

    // ---------- wire ----------

    pub fn parse(buf: &[u8]) -> Result<Msg, String> {
        if buf.len() < 12 {
            return Err("msg too short".to_string());
        }
        let mut m = Msg::new();
        m.id = u16::from_be_bytes([buf[0], buf[1]]);
        m.flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;

        let mut pos = 12usize;
        for _ in 0..qd {
            let name = read_name(buf, &mut pos)?;
            if pos + 4 > buf.len() {
                return Err("question truncated".to_string());
            }
            let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            pos += 4;
            m.question.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        for _ in 0..an {
            let rr = read_rr(buf, &mut pos)?;
            m.answer.push(rr);
        }
        for _ in 0..ns {
            let rr = read_rr(buf, &mut pos)?;
            m.ns.push(rr);
        }
        for _ in 0..ar {
            let rr = read_rr(buf, &mut pos)?;
            m.extra.push(rr);
        }
        Ok(m)
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.question.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answer.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.ns.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.extra.len() as u16).to_be_bytes());

        let mut comp: HashMap<String, u16> = HashMap::new();
        for q in &self.question {
            write_name(&mut out, &q.name, &mut comp);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for rr in &self.answer {
            write_rr(&mut out, rr, &mut comp);
        }
        for rr in &self.ns {
            write_rr(&mut out, rr, &mut comp);
        }
        for rr in &self.extra {
            write_rr(&mut out, rr, &mut comp);
        }
        out
    }

    /// miekg/dns Msg.Truncate: drop records until the packed size fits, set TC.
    pub fn truncate_to(&mut self, size: usize) {
        let size = if size < 512 { 512 } else { size };
        if self.pack().len() <= size {
            return;
        }
        self.flags |= FLAG_TC;

        // Keep OPT record (if any) at the head of additional.
        let mut opt: Option<RR> = None;
        let mut idx = None;
        for (i, rr) in self.extra.iter().enumerate() {
            if rr.rtype == TYPE_OPT {
                opt = Some(rr.clone());
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            self.extra.remove(i);
        }

        loop {
            if self.pack().len() <= size {
                break;
            }
            if !self.extra.is_empty() {
                self.extra.pop();
                continue;
            }
            if !self.ns.is_empty() {
                self.ns.pop();
                continue;
            }
            if !self.answer.is_empty() {
                self.answer.pop();
                continue;
            }
            break;
        }
        if let Some(o) = opt {
            self.extra.insert(0, o);
        }
        // Adding OPT back may overflow; drop it if we still don't fit.
        while self.pack().len() > size && !self.extra.is_empty() {
            self.extra.pop();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddrLike {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddrLike {
    pub fn to_ip(self) -> std::net::IpAddr {
        match self {
            IpAddrLike::V4(a) => std::net::IpAddr::V4(a),
            IpAddrLike::V6(a) => std::net::IpAddr::V6(a),
        }
    }
}

/// mosdns dnsutils.FakeSOA
pub fn fake_soa(name: &str) -> RR {
    RR {
        name: fqdn(name),
        rtype: TYPE_SOA,
        class: CLASS_IN,
        ttl: 300,
        rdata: RData::Soa {
            mname: "fake-ns.mosdns.fake.root.".to_string(),
            rname: "fake-mbox.mosdns.fake.root.".to_string(),
            serial: 2021110400,
            refresh: 1800,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        },
    }
}

/// mosdns dnsutils.GenEmptyReply
pub fn gen_empty_reply(q: &Msg, rcode: u16) -> Msg {
    let mut r = q.set_reply(rcode);
    let name = if q.question.len() > 1 {
        q.question[0].name.clone()
    } else {
        ".".to_string()
    };
    r.ns.push(fake_soa(&name));
    r
}

/// smartdns 风格的 SOA（用于 ipv4_only 屏蔽 AAAA）：
/// TTL 30，让策略切换快速生效；mname/rname 取 smartdns 的默认值。
pub fn smartdns_soa(name: &str) -> RR {
    RR {
        name: fqdn(name),
        rtype: TYPE_SOA,
        class: CLASS_IN,
        ttl: 30,
        rdata: RData::Soa {
            mname: "a.gtld-servers.net.".to_string(),
            rname: "nstld.verisign-grs.com.".to_string(),
            serial: 1800,
            refresh: 1800,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        },
    }
}

/// NOERROR + 空 answer + authority SOA（NODATA），用于屏蔽某类型
pub fn no_data_reply(q: &Msg) -> Msg {
    let mut r = q.set_reply(RCODE_NOERROR);
    let name = q
        .question
        .first()
        .map(|x| x.name.clone())
        .unwrap_or_else(|| ".".to_string());
    r.ns.push(smartdns_soa(&name));
    r
}

fn read_name(buf: &[u8], pos: &mut usize) -> Result<String, String> {
    let mut name = String::new();
    let mut p = *pos;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        if p >= buf.len() {
            return Err("name out of range".to_string());
        }
        let len = buf[p];
        if len == 0 {
            p += 1;
            if !jumped {
                *pos = p;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if p + 1 >= buf.len() {
                return Err("bad pointer".to_string());
            }
            let off = (((len & 0x3F) as usize) << 8) | buf[p + 1] as usize;
            if !jumped {
                *pos = p + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > 32 {
                return Err("too many compression jumps".to_string());
            }
            p = off;
            continue;
        }
        if len & 0xC0 != 0 {
            return Err("unsupported label length".to_string());
        }
        let l = len as usize;
        if p + 1 + l > buf.len() {
            return Err("label out of range".to_string());
        }
        let s = String::from_utf8_lossy(&buf[p + 1..p + 1 + l]);
        name.push_str(&s);
        name.push('.');
        p += 1 + l;
    }
    if name.is_empty() {
        name.push('.');
    }
    Ok(name)
}

fn read_rr(buf: &[u8], pos: &mut usize) -> Result<RR, String> {
    let name = read_name(buf, pos)?;
    if *pos + 10 > buf.len() {
        return Err("rr header truncated".to_string());
    }
    let rtype = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    let class = u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]);
    let ttl = u32::from_be_bytes([buf[*pos + 4], buf[*pos + 5], buf[*pos + 6], buf[*pos + 7]]);
    let rdlen = u16::from_be_bytes([buf[*pos + 8], buf[*pos + 9]]) as usize;
    *pos += 10;
    let start = *pos;
    let end = start + rdlen;
    if end > buf.len() {
        return Err("rdata truncated".to_string());
    }

    let rdata = match rtype {
        TYPE_A if rdlen == 4 => {
            *pos = end;
            RData::A(Ipv4Addr::new(
                buf[start],
                buf[start + 1],
                buf[start + 2],
                buf[start + 3],
            ))
        }
        TYPE_AAAA if rdlen == 16 => {
            *pos = end;
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[start..end]);
            RData::Aaaa(Ipv6Addr::from(b))
        }
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME | TYPE_MB | TYPE_MD | TYPE_MF => {
            let mut p = start;
            let n = read_name(buf, &mut p)?;
            *pos = end;
            RData::Name(n)
        }
        TYPE_MX => {
            let mut p = start;
            if p + 2 > end {
                return Err("bad mx".to_string());
            }
            let pref = u16::from_be_bytes([buf[p], buf[p + 1]]);
            p += 2;
            let n = read_name(buf, &mut p)?;
            *pos = end;
            RData::Mx(pref, n)
        }
        TYPE_SOA => {
            let mut p = start;
            let mname = read_name(buf, &mut p)?;
            let rname = read_name(buf, &mut p)?;
            if p + 20 > end {
                return Err("bad soa".to_string());
            }
            let rd = |o: usize| u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
            let soa = RData::Soa {
                mname,
                rname,
                serial: rd(p),
                refresh: rd(p + 4),
                retry: rd(p + 8),
                expire: rd(p + 12),
                minimum: rd(p + 16),
            };
            *pos = end;
            soa
        }
        TYPE_SRV if rdlen >= 7 => {
            let mut p = start;
            let prio = u16::from_be_bytes([buf[p], buf[p + 1]]);
            let weight = u16::from_be_bytes([buf[p + 2], buf[p + 3]]);
            let port = u16::from_be_bytes([buf[p + 4], buf[p + 5]]);
            p += 6;
            let target = read_name(buf, &mut p)?;
            *pos = end;
            RData::Srv(prio, weight, port, target)
        }
        _ => {
            let raw = buf[start..end].to_vec();
            *pos = end;
            RData::Raw(raw)
        }
    };

    Ok(RR {
        name,
        rtype,
        class,
        ttl,
        rdata,
    })
}

fn write_name(out: &mut Vec<u8>, name: &str, comp: &mut HashMap<String, u16>) {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        out.push(0);
        return;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    for i in 0..labels.len() {
        let suffix = labels[i..].join(".").to_ascii_lowercase();
        if let Some(&off) = comp.get(&suffix) {
            if off <= 0x3FFF {
                out.extend_from_slice(&(0xC000u16 | off).to_be_bytes());
                return;
            }
        }
        if out.len() <= 0x3FFF {
            comp.insert(suffix, out.len() as u16);
        }
        let l = labels[i].len();
        if l > 63 {
            // oversize label: write as-is truncated (should not happen in practice)
            out.push(63);
            out.extend_from_slice(&labels[i].as_bytes()[..63]);
        } else {
            out.push(l as u8);
            out.extend_from_slice(labels[i].as_bytes());
        }
    }
    out.push(0);
}

fn write_rr(out: &mut Vec<u8>, rr: &RR, comp: &mut HashMap<String, u16>) {
    write_name(out, &rr.name, comp);
    out.extend_from_slice(&rr.rtype.to_be_bytes());
    out.extend_from_slice(&rr.class.to_be_bytes());
    out.extend_from_slice(&rr.ttl.to_be_bytes());
    let len_pos = out.len();
    out.extend_from_slice(&[0u8, 0u8]);

    match &rr.rdata {
        RData::A(ip) => out.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
        RData::Name(n) => write_name(out, n, comp),
        RData::Mx(pref, n) => {
            out.extend_from_slice(&pref.to_be_bytes());
            write_name(out, n, comp);
        }
        RData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            write_name(out, mname, comp);
            write_name(out, rname, comp);
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        RData::Srv(prio, weight, port, target) => {
            out.extend_from_slice(&prio.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            write_name(out, target, comp);
        }
        RData::Raw(b) => out.extend_from_slice(b),
    }

    let rdlen = out.len() - len_pos - 2;
    out[len_pos] = ((rdlen >> 8) & 0xFF) as u8;
    out[len_pos + 1] = (rdlen & 0xFF) as u8;
}
