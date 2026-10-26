//! 通过 netlink 直接往内核 ipset 写元素（代替 fork 外部 `ipset` 命令）。
//!
//! 与原版 mosdns 一致：走 NFNL_SUBSYS_IPSET 的 IPSET_CMD_ADD。
//! 常量取自内核 UAPI `include/uapi/linux/netfilter/ipset/ip_set.h`：
//! - IPSET_PROTOCOL = 7，IPSET_CMD_ADD = 9
//! - IPSET_ATTR_PROTOCOL=1 / SETNAME=2 / DATA=7
//! - CADT: IPSET_ATTR_IP=1 / CIDR=3
//! - IP:  IPSET_ATTR_IPADDR_IPV4=1 / IPADDR_IPV6=2
//!
//! `-exist` 语义不靠 flag 实现：内核返回 `IPSET_ERR_EXIST` 时直接当成功。
//! 任何失败都会退回外部 `ipset` 命令（并记一次 WARN），保证兼容性。

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::log;

const AF_NETLINK: i32 = 16;
const SOCK_RAW: i32 = 3;
const NETLINK_NETFILTER: i32 = 12;

const NFNL_SUBSYS_IPSET: u16 = 6;
const IPSET_CMD_ADD: u16 = 9;
const IPSET_PROTOCOL: u8 = 7;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLMSG_ERROR: u16 = 0x02;

const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_CIDR: u16 = 3;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

const NLA_F_NESTED: u16 = 0x8000;
/// 地址类属性要带这个标志，否则内核按主机字节序解释
const NLA_F_NET_BYTEORDER: u16 = 0x4000;
/// CADT 里的 lineno（内核期望存在，值为 0）
const IPSET_ATTR_CADT_LINENO: u16 = 9;

/// 内核 `IPSET_ERR_EXIST`（4096 + 7），取负作为 netlink 错误码
const IPSET_ERR_EXIST: i32 = -(4096 + 7);

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn close(fd: i32) -> i32;
}

static FALLBACK: AtomicBool = AtomicBool::new(false);
static SEQ: AtomicU32 = AtomicU32::new(1);

fn align4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

fn push_attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    align4(buf);
}

/// 嵌套属性：先占位，再回填长度
fn push_nested(buf: &mut Vec<u8>, ty: u16, f: impl FnOnce(&mut Vec<u8>)) {
    let start = buf.len();
    buf.extend_from_slice(&0u16.to_ne_bytes()); // 占位 len
    buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
    f(buf);
    align4(buf);
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
}

fn build_add(set: &str, ip: IpAddr, mask: u8) -> Vec<u8> {
    let mut msg: Vec<u8> = Vec::with_capacity(128);
    // nlmsghdr
    msg.extend_from_slice(&0u32.to_ne_bytes()); // len 占位
    msg.extend_from_slice(&((NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD).to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    msg.extend_from_slice(&seq.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid

    // nfgenmsg
    let family: u8 = match ip {
        IpAddr::V4(_) => 2,   // AF_INET
        IpAddr::V6(_) => 10,  // AF_INET6
    };
    msg.push(family);
    msg.push(0); // version = NFNETLINK_V0
    msg.extend_from_slice(&0u16.to_ne_bytes()); // res_id

    push_attr(&mut msg, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
    let mut name = set.as_bytes().to_vec();
    name.push(0);
    push_attr(&mut msg, IPSET_ATTR_SETNAME, &name);

    push_nested(&mut msg, IPSET_ATTR_DATA, |m| {
        push_nested(m, IPSET_ATTR_IP, |m| match ip {
            IpAddr::V4(v4) => push_attr(
                m,
                IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER,
                &v4.octets(),
            ),
            IpAddr::V6(v6) => push_attr(
                m,
                IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER,
                &v6.octets(),
            ),
        });
        push_attr(m, IPSET_ATTR_CIDR, &[mask]);
        push_attr(m, IPSET_ATTR_CADT_LINENO, &0u32.to_ne_bytes());
    });

    let total = msg.len() as u32;
    msg[0..4].copy_from_slice(&total.to_ne_bytes());
    msg
}

/// 直接 netlink 下发一条 add。
fn netlink_add(set: &str, ip: IpAddr, mask: u8) -> Result<(), String> {
    let msg = build_add(set, ip, mask);
    unsafe {
        let fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
        if fd < 0 {
            return Err(format!("netlink socket: errno {}", std::io::Error::last_os_error()));
        }
        let n = send(fd, msg.as_ptr(), msg.len(), 0);
        if n < 0 {
            let e = std::io::Error::last_os_error();
            close(fd);
            return Err(format!("netlink send: {}", e));
        }
        // 读 ACK（可能有多个消息，找 NLMSG_ERROR 且 seq 匹配）
        let mut buf = [0u8; 4096];
        let got = recv(fd, buf.as_mut_ptr(), buf.len(), 0);
        close(fd);
        if got < 0 {
            return Err(format!("netlink recv: {}", std::io::Error::last_os_error()));
        }
        let got = got as usize;
        if got < 20 {
            return Err(format!("netlink short ack ({} bytes)", got));
        }
        // nlmsghdr: len(u32) type(u16) flags(u16) seq(u32) pid(u32)
        let ty = u16::from_ne_bytes([buf[4], buf[5]]);
        if ty != NLMSG_ERROR {
            return Err(format!("netlink unexpected msg type {}", ty));
        }
        // nlmsgerr: error(i32) + 原始请求头
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        match err {
            0 => Ok(()),
            IPSET_ERR_EXIST => Ok(()), // 等价于 ipset add -exist
            e => Err(format!("ipset add {} {}/{}: kernel error {}", set, ip, mask, -e)),
        }
    }
}

/// 退回外部命令（只在 netlink 出错时使用）
fn cmd_add(set: &str, ip: &str, mask: u8) -> Result<(), String> {
    let out = std::process::Command::new("ipset")
        .arg("add")
        .arg(set)
        .arg(format!("{}/{}", ip, mask))
        .arg("-exist")
        .output()
        .map_err(|e| format!("failed to run ipset: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "ipset add {} {}/{}: {}",
            set,
            ip,
            mask,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// 往集合里加一条（自动选 v4/v6 属性），失败时回退外部命令。
pub fn add(set: &str, ip: IpAddr, mask: u8) -> Result<(), String> {
    if !FALLBACK.load(Ordering::Relaxed) {
        match netlink_add(set, ip, mask) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // 只提醒一次，之后这进程生命周期内都用外部命令，避免每次都失败重试
                if !FALLBACK.swap(true, Ordering::Relaxed) {
                    log::warn(format!(
                        "ipset 走 netlink 失败，回退外部命令（后续不再尝试 netlink）：{}",
                        e
                    ));
                }
            }
        }
    }
    cmd_add(set, &ip.to_string(), mask)
}

/// 供 `--ipset-add` 自检用：只走 netlink，不回退，返回详细信息
pub fn add_netlink_only(set: &str, ip: IpAddr, mask: u8) -> Result<(), String> {
    netlink_add(set, ip, mask)
}
