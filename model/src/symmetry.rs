//! Symmetry reduction.  Clients, memory nodes, scopes and the slabs of one
//! node are interchangeable: every action and every property is invariant
//! under renaming them.  `canonical` maps a state to a representative of its
//! class; the checker then explores the quotient graph.
//!
//! The representative need not be unique per class for soundness (it only has
//! to be a renaming of the input); a tie simply means less reduction.

use crate::model::{Half, Mira, State, MAXC, MAXS, MAXSLAB, NOKEY, NONE};

fn perms(n: usize) -> Vec<Vec<u8>> {
    fn go(n: usize, cur: &mut Vec<u8>, out: &mut Vec<Vec<u8>>) {
        if cur.len() == n {
            out.push(cur.clone());
            return;
        }
        for x in 0..n as u8 {
            if !cur.contains(&x) {
                cur.push(x);
                go(n, cur, out);
                cur.pop();
            }
        }
    }
    let mut out = Vec::new();
    go(n, &mut Vec::new(), &mut out);
    out
}

pub fn canonical(m: &Mira, s: &State) -> State {
    let b = &m.cfg.b;
    let mut best: Option<State> = None;
    for np in perms(b.nodes as usize) {
        for sp in scope_perms(m) {
            let mut t = rename(m, s, &np, &sp);
            sort_slabs(m, &mut t);
            sort_clients(m, &mut t);
            if best.as_ref().is_none_or(|x| t < *x) {
                best = Some(t);
            }
        }
    }
    best.unwrap()
}

/// Permutations of the scope entries that rename the scope_ids of every
/// principal alike (principals and the id bytes they share stay aligned).
fn scope_perms(m: &Mira) -> Vec<Vec<u8>> {
    let b = &m.cfg.b;
    let ids = (b.scopes / b.principals) as usize;
    perms(ids)
        .into_iter()
        .map(|pi| (0..b.scopes as usize).map(|x| (x / ids * ids) as u8 + pi[x % ids]).collect())
        .collect()
}

/// Rename node `n` to `np[n]` and scope `x` to `sp[x]`.
fn rename(m: &Mira, s: &State, np: &[u8], sp: &[u8]) -> State {
    let b = &m.cfg.b;
    let key =
        |k: u8| if k == NOKEY { k } else { sp[m.scope_of(k) as usize] * b.max_pos + m.pos_of(k) };
    let half = |h: Half| match h {
        Half::Tag(k, g) => Half::Tag(key(k), g),
        x => x,
    };
    let mut t = s.clone();
    for e in 0..=s.epoch as usize {
        let mut row = [0u8; MAXS];
        for x in 0..b.scopes as usize {
            row[sp[x] as usize] = (0..b.nodes as usize)
                .filter(|&n| s.owner[e][x] >> n & 1 == 1)
                .fold(0u8, |acc, n| acc | (1 << np[n]));
        }
        t.owner[e] = row;
    }
    for n in 0..b.nodes as usize {
        let d = np[n] as usize;
        t.n_epoch[d] = s.n_epoch[n];
        t.mode[d] = s.mode[n];
        t.up[d] = s.up[n];
        t.ngen[d] = s.ngen[n];
        for x in 0..b.scopes as usize {
            t.scope[d][sp[x] as usize] = s.scope[n][x];
            t.legit[d][sp[x] as usize] = s.legit[n][x];
        }
        let mut row = s.slab[n];
        for x in row.iter_mut().take(b.slabs as usize) {
            x.key = key(x.key);
            x.h1 = half(x.h1);
            x.h2 = half(x.h2);
        }
        t.slab[d] = row;
    }
    for c in 0..b.clients as usize {
        let cl = &mut t.cl[c];
        cl.key = key(cl.key);
        if cl.n != NONE {
            cl.n = np[cl.n as usize];
        }
        cl.d1 = half(cl.d1);
        cl.d2 = half(cl.d2);
    }
    t
}

/// Order the slabs of each node by content (ignoring client references).
fn sort_slabs(m: &Mira, t: &mut State) {
    let b = &m.cfg.b;
    let k = b.slabs as usize;
    for n in 0..b.nodes as usize {
        let row = t.slab[n];
        let mut idx: Vec<usize> = (0..k).collect();
        idx.sort_by_key(|&i| {
            let x = &row[i];
            (x.st, x.key, x.gen, x.h1, x.h2, x.wmr, x.pend1, x.pend2, x.cflight, x.doomed, x.stale)
        });
        if idx.iter().enumerate().all(|(new, &old)| new == old) {
            continue;
        }
        let mut to = [0u8; MAXSLAB];
        for (new, &old) in idx.iter().enumerate() {
            t.slab[n][new] = row[old];
            to[old] = new as u8;
        }
        for c in 0..b.clients as usize {
            let cl = &mut t.cl[c];
            if cl.n as usize == n && cl.slab != NONE {
                cl.slab = to[cl.slab as usize];
            }
        }
    }
}

/// Order the clients of each principal by local state (a client's principal
/// is its index modulo the number of principals, so only same-principal
/// clients can swap).
fn sort_clients(m: &Mira, t: &mut State) {
    let b = &m.cfg.b;
    let k = b.clients as usize;
    let (cl, ce) = (t.cl, t.c_epoch);
    let mut to = [0u8; MAXC];
    for (c, x) in to.iter_mut().enumerate() {
        *x = c as u8;
    }
    for g in 0..b.principals as usize {
        let pos: Vec<usize> = (0..k).filter(|c| c % b.principals as usize == g).collect();
        let mut idx = pos.clone();
        idx.sort_by_key(|&i| (cl[i], ce[i]));
        for (slot, &old) in pos.iter().zip(idx.iter()) {
            t.cl[*slot] = cl[old];
            t.c_epoch[*slot] = ce[old];
            to[old] = *slot as u8;
        }
    }
    if (0..k).all(|c| to[c] as usize == c) {
        return;
    }
    for n in 0..b.nodes as usize {
        for i in 0..b.slabs as usize {
            let x = &mut t.slab[n][i];
            if x.writer != NONE {
                x.writer = to[x.writer as usize];
            }
            if x.lease != 0 {
                x.lease = (0..k).fold(0u8, |acc, c| acc | (((x.lease >> c) & 1) << to[c]));
            }
        }
    }
}
