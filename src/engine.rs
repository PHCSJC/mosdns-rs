//! Query context, plugin traits and the sequence chain walker.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::dns::Msg;

pub type Res<T = ()> = Result<T, String>;

static QID: AtomicU32 = AtomicU32::new(0);

pub struct QCtx {
    pub q: Msg,
    pub r: Option<Msg>,
    pub client: Option<IpAddr>,
    pub deadline: Instant,
    pub resp_gen: u64,
    pub qid: u32,
    /// 决策路径（仅 debug 级别时分配；用于事后分析线上问题）
    pub trace: Option<String>,
    /// forward 实际派发了几轮（仅 debug 有价值）
    pub tries: u8,
    /// 各次上游尝试的结果摘要（仅 debug 时记录，供失败落盘）
    pub attempts: Vec<String>,
}

impl QCtx {
    pub fn new(q: Msg, client: Option<IpAddr>) -> QCtx {
        QCtx {
            q,
            r: None,
            client,
            deadline: Instant::now() + std::time::Duration::from_secs(5),
            resp_gen: 0,
            qid: QID.fetch_add(1, Ordering::Relaxed),
            trace: if crate::log::enabled(crate::log::LV_DEBUG) {
                Some(String::with_capacity(64))
            } else {
                None
            },
            tries: 0,
            attempts: Vec::new(),
        }
    }

    /// 记录一步决策：字面量（不分配）。
    pub fn note(&mut self, tag: &str) {
        if let Some(t) = self.trace.as_mut() {
            if !t.is_empty() {
                t.push('>');
            }
            t.push_str(tag);
        }
    }

    /// 记录一步决策：需要格式化时用这个，debug 关闭时连字符串都不会构建。
    pub fn note_f(&mut self, f: impl FnOnce() -> String) {
        if let Some(t) = self.trace.as_mut() {
            if !t.is_empty() {
                t.push('>');
            }
            t.push_str(&f());
        }
    }

    pub fn set_resp(&mut self, r: Msg) {
        self.r = Some(r);
        self.resp_gen += 1;
    }

    pub fn clear_resp(&mut self) {
        self.r = None;
        self.resp_gen += 1;
    }

    pub fn copy_ctx(&self) -> QCtx {
        QCtx {
            q: self.q.clone(),
            r: self.r.clone(),
            client: self.client,
            deadline: self.deadline,
            resp_gen: self.resp_gen,
            qid: self.qid,
            trace: self.trace.clone(),
            tries: self.tries,
            attempts: Vec::new(),
        }
    }
}

pub trait Exec: Send + Sync {
    fn exec(&self, ctx: &mut QCtx) -> Res;
}

pub trait RExec: Send + Sync {
    fn exec(&self, ctx: &mut QCtx, next: &Walker) -> Res;
}

pub trait Matcher: Send + Sync {
    fn matches(&self, ctx: &QCtx) -> Res<bool>;
}

pub enum ExecKind {
    Plain(Arc<dyn Exec>),
    Rec(Arc<dyn RExec>),
}

pub struct ChainNode {
    pub matches: Vec<Arc<dyn Matcher>>,
    pub exec: ExecKind,
}

pub type Chain = Vec<ChainNode>;

#[derive(Clone)]
pub struct Walker {
    pub chain: Arc<Chain>,
    pub p: usize,
    pub jump_back: Option<Box<Walker>>,
}

impl Walker {
    pub fn new(chain: Arc<Chain>, p: usize, jump_back: Option<Box<Walker>>) -> Walker {
        Walker {
            chain,
            p,
            jump_back,
        }
    }

    pub fn start(chain: Arc<Chain>) -> Walker {
        Walker::new(chain, 0, None)
    }

    pub fn exec_next(&self, ctx: &mut QCtx) -> Res {
        let mut p = self.p;
        while p < self.chain.len() {
            let node = &self.chain[p];
            let mut ok = true;
            for m in &node.matches {
                if !m.matches(ctx)? {
                    ok = false;
                    break;
                }
            }
            if !ok {
                p += 1;
                continue;
            }
            match &node.exec {
                ExecKind::Plain(e) => {
                    e.exec(ctx)?;
                    p += 1;
                }
                ExecKind::Rec(re) => {
                    let next = Walker {
                        chain: self.chain.clone(),
                        p: p + 1,
                        jump_back: self.jump_back.clone(),
                    };
                    return re.exec(ctx, &next);
                }
            }
        }
        if let Some(jb) = &self.jump_back {
            return jb.exec_next(ctx);
        }
        Ok(())
    }
}

/// A sequence plugin: plain executable that runs its whole chain.
pub struct Sequence {
    pub chain: Arc<Chain>,
}

impl Exec for Sequence {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        Walker::start(self.chain.clone()).exec_next(ctx)
    }
}

// ---------------- built-in execs ----------------

pub struct Accept;
impl RExec for Accept {
    fn exec(&self, _ctx: &mut QCtx, _next: &Walker) -> Res {
        Ok(())
    }
}

pub struct Return;
impl RExec for Return {
    fn exec(&self, ctx: &mut QCtx, next: &Walker) -> Res {
        if let Some(jb) = &next.jump_back {
            return jb.exec_next(ctx);
        }
        Ok(())
    }
}

pub struct Reject {
    pub rcode: u16,
}
impl RExec for Reject {
    fn exec(&self, ctx: &mut QCtx, _next: &Walker) -> Res {
        ctx.note_f(|| format!("reject({})", self.rcode));
        let r = ctx.q.set_reply(self.rcode);
        ctx.set_resp(r);
        Ok(())
    }
}

pub struct DropResp;
impl Exec for DropResp {
    fn exec(&self, ctx: &mut QCtx) -> Res {
        ctx.note("drop_resp");
        ctx.clear_resp();
        Ok(())
    }
}

pub struct Jump {
    pub target: Arc<Chain>,
    pub name: String,
}
impl RExec for Jump {
    fn exec(&self, ctx: &mut QCtx, next: &Walker) -> Res {
        ctx.note_f(|| format!("jump:{}", self.name));
        let cont = Walker {
            chain: next.chain.clone(),
            p: next.p,
            jump_back: next.jump_back.clone(),
        };
        let w = Walker::new(self.target.clone(), 0, Some(Box::new(cont)));
        w.exec_next(ctx)
    }
}

pub struct Goto {
    pub target: Arc<Chain>,
    pub name: String,
}
impl RExec for Goto {
    fn exec(&self, ctx: &mut QCtx, _next: &Walker) -> Res {
        ctx.note_f(|| format!("goto:{}", self.name));
        Walker::start(self.target.clone()).exec_next(ctx)
    }
}

// ---------------- built-in matchers ----------------

pub struct AlwaysTrue;
impl Matcher for AlwaysTrue {
    fn matches(&self, _ctx: &QCtx) -> Res<bool> {
        Ok(true)
    }
}

pub struct AlwaysFalse;
impl Matcher for AlwaysFalse {
    fn matches(&self, _ctx: &QCtx) -> Res<bool> {
        Ok(false)
    }
}

pub struct Reverse {
    pub inner: Arc<dyn Matcher>,
}
impl Matcher for Reverse {
    fn matches(&self, ctx: &QCtx) -> Res<bool> {
        Ok(!self.inner.matches(ctx)?)
    }
}

pub struct HasResp;
impl Matcher for HasResp {
    fn matches(&self, ctx: &QCtx) -> Res<bool> {
        Ok(ctx.r.is_some())
    }
}
