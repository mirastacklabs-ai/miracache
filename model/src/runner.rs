//! Runs the checker (exhaustive BFS or random simulation) and renders results.

use crate::model::{Action, Bounds, Cfg, Half, Mira, Pc, Sc, St, State, NONE, NOKEY};
use crate::variants::Variant;
use stateright::{Checker, Expectation, HasDiscoveries, Model, UniformChooser};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub struct Outcome {
    pub mode: &'static str,
    /// The whole reachable state space was explored (BFS, no early stop).
    pub complete: bool,
    pub states: usize,
    pub unique: usize,
    pub depth: usize,
    pub elapsed: Duration,
    /// always/eventually properties with a counterexample -> readable trace.
    pub failed: BTreeMap<&'static str, String>,
    /// always/eventually properties without a counterexample.
    pub held: Vec<&'static str>,
    /// Properties that are trivially true in this configuration and must not
    /// be reported as passing (LeaseCoversReader when leases expire).
    pub not_applicable: Vec<&'static str>,
    /// reachability witnesses found / not found.
    pub witnessed: Vec<&'static str>,
    pub unwitnessed: Vec<&'static str>,
}

impl Outcome {
    pub fn failed_names(&self) -> BTreeSet<&'static str> {
        self.failed.keys().copied().collect()
    }
}

fn collect<C: Checker<Mira>>(checker: C, mode: &'static str, complete: bool, t0: Instant) -> Outcome {
    let model = checker.model();
    let disc = checker.discoveries();
    let mut out = Outcome {
        mode,
        complete,
        states: checker.state_count(),
        unique: checker.unique_state_count(),
        depth: checker.max_depth(),
        elapsed: t0.elapsed(),
        failed: BTreeMap::new(),
        held: vec![],
        not_applicable: vec![],
        witnessed: vec![],
        unwitnessed: vec![],
    };
    for p in model.properties() {
        match (p.expectation, disc.get(p.name)) {
            (Expectation::Sometimes, Some(_)) => out.witnessed.push(p.name),
            (Expectation::Sometimes, None) => out.unwitnessed.push(p.name),
            (_, Some(path)) => {
                out.failed.insert(p.name, render_trace(model, path.clone().into_vec()));
            }
            (_, None) if p.name == "LeaseCoversReader" && model.cfg.sw.leases_expire => {
                out.not_applicable.push(p.name)
            }
            (_, None) => out.held.push(p.name),
        }
    }
    out
}

/// Exhaustive breadth-first check.  With `stop_at`, stops as soon as every
/// named property has a counterexample.
pub fn run_bfs(
    cfg: Cfg,
    stop_at: Option<&[&'static str]>,
    threads: usize,
    max_states: Option<usize>,
) -> Outcome {
    let t0 = Instant::now();
    let mut b = Mira::new(cfg).checker().threads(threads);
    if let Some(names) = stop_at {
        b = b.finish_when(HasDiscoveries::AllOf(names.iter().copied().collect()));
    }
    if let Some(n) = max_states {
        b = b.target_state_count(n);
    }
    let checker = b.spawn_bfs().join();
    let early = stop_at.is_some_and(|names| {
        let d = checker.discoveries();
        names.iter().all(|n| d.contains_key(n))
    }) || max_states.is_some_and(|n| checker.state_count() >= n);
    collect(checker, "bfs", !early, t0)
}

/// Check one variant breadth-first at the given bounds.
///
/// A variant that must pass (or is marked exhaustive) is explored completely.
/// Any other teeth variant stops as soon as its expected counterexamples are
/// found.  Counterexamples found under symmetry reduction are re-derived
/// without it, so that the printed trace keeps one name per client/node/slab.
pub fn check_variant(
    v: &Variant,
    bounds: Bounds,
    threads: usize,
    full: bool,
    max_states: Option<usize>,
) -> Outcome {
    let cfg = v.cfg(bounds, full);
    let stop = (!v.explore_all(&bounds, full)).then_some(v.must_fail);
    let mut out = run_bfs(cfg, stop, threads, max_states);
    if cfg.b.symmetry && !out.failed.is_empty() {
        let names: Vec<&'static str> = out.failed.keys().copied().collect();
        let mut plain = cfg;
        plain.b.symmetry = false;
        let again = run_bfs(plain, Some(&names), threads, max_states);
        for (name, trace) in again.failed {
            out.failed.insert(name, trace);
        }
    }
    out
}

/// Random simulation: uniform random walks from the initial states until
/// `budget` states have been visited.
pub fn run_sim(cfg: Cfg, seed: u64, budget: usize, threads: usize) -> Outcome {
    let t0 = Instant::now();
    let mut cfg = cfg;
    cfg.b.symmetry = false;
    let checker = Mira::new(cfg)
        .checker()
        .threads(threads)
        .target_state_count(budget)
        .finish_when(HasDiscoveries::AllFailures)
        .spawn_simulation(seed, UniformChooser)
        .join();
    collect(checker, "simulation", false, t0)
}

// ---------------------------------------------------------------------------
// Rendering

fn half(h: Half) -> String {
    match h {
        Half::None => "-".into(),
        Half::Garbage => "garbage".into(),
        Half::Tag(k, g) => format!("<k{k},g{g}>"),
    }
}

pub fn describe(m: &Mira, a: &Action) -> String {
    let key = |k: u8| {
        format!(
            "k{k} (entry {} = principal {} id {}, pos {})",
            m.scope_of(k),
            m.prin_of(m.scope_of(k)),
            m.scope_of(k) % (m.cfg.b.scopes / m.cfg.b.principals),
            m.pos_of(k) + 1
        )
    };
    match *a {
        Action::ExpireScope { n, s } => format!("n{n}: scope entry {s} expires (reaped)"),
        Action::DropScope { n, s } => format!("n{n}: local drop of scope entry {s}"),
        Action::LookupOpen { c, key: k, n } => format!("c{c}: LOOKUP {} on n{n} OPENS the scope (bug)", key(k)),
        Action::PutBegin { c, key: k, n, slab, victim } => format!(
            "c{c} (principal {}): PUT_BEGIN {} on n{n} -> ACCEPT slab {slab}{}: (WRITING, fresh gen), write MR registered, WRITEs posted",
            m.cprin(c),
            key(k),
            if victim == NONE { String::new() } else { format!(", evicts scope entry {victim}") }
        ),
        Action::Place1 { n, i } => format!("fabric: WRITE of half 1 lands in n{n} slab {i}"),
        Action::Place2 { n, i } => format!("fabric: WRITE of half 2 lands in n{n} slab {i}"),
        Action::PutSendCommit(c) => format!("c{c}: posts PUT_COMMIT (or learns the put was aborted)"),
        Action::PutCommit { n, i } => format!(
            "n{n} slab {i}: PUT_COMMIT arrives -> fence, digest check, commit (abort if doomed or digest mismatch)"
        ),
        Action::PutAbort { n, i } => format!("n{n} slab {i}: server aborts the put (fence, FREE)"),
        Action::ClientPutEnd(c) => format!("c{c}: gets PUT_DONE"),
        Action::PutAbandon(c) => format!("c{c}: abandons its put"),
        Action::RogueWrite { n, i, first, val } => format!(
            "ROGUE: writes {} into half {} of n{n} slab {i}",
            half(val),
            if first { 1 } else { 2 }
        ),
        Action::Invalidate { n, i } => format!("n{n} slab {i}: INVALIDATE -> drop the block and its subtree"),
        Action::GetLookup { c, key: k, n } => format!("c{c}: LOOKUP(LEASE) {} on n{n}", key(k)),
        Action::GetRead1(c) => format!("c{c}: payload READ of half 1 completes"),
        Action::GetRead2(c) => format!("c{c}: payload READ of half 2 completes"),
        Action::GetSeqRead(c) => format!("c{c}: READ of the state_gen word"),
        Action::RailFail { c, h } => format!("c{c}: rail of slice {} turns suspect (no CQE yet)", h + 1),
        Action::RailFlush { c, h } => format!("c{c}: rail QPs ERR, flush CQE of slice {}", h + 1),
        Action::OrigLand { c, h } => format!("c{c}: original READ of slice {} lands now", h + 1),
        Action::GetReissue { c, h } => format!("c{c}: slice {} re-issued", h + 1),
        Action::GetValidate(c) => format!("c{c}: validate (accept or reject), RELEASE"),
        Action::GetCancel(c) => format!("c{c}: fetch deadline"),
        Action::GetDrained(c) => format!("c{c}: QP drained, RELEASE"),
        Action::LeaseExpire { n, i, c } => format!("n{n} slab {i}: lease of c{c} expires"),
        Action::Evict { n, i } => format!("n{n}: evict slab {i}"),
        Action::ZombieReap { n, i } => format!("n{n}: reap zombie slab {i}"),
        Action::Crash { n, warm } => format!("n{n}: CRASH ({})", if warm { "warm" } else { "cold" }),
        Action::Restart(n) => format!("n{n}: restart"),
        Action::ClientCrash(c) => format!("c{c}: CRASH (QPs flush: leases released, puts fenced and freed)"),
        Action::SetMode { n, mode } => format!("controller: n{n} member state -> {mode:?} (same epoch)"),
        Action::EpochChange { owners } => format!(
            "controller: new epoch (bundle reaches live nodes and clients), owner set per scope (bitmask over nodes) = {:?}",
            &owners[..m.cfg.b.scopes as usize]
        ),
    }
}

pub fn describe_state(m: &Mira, s: &State) -> String {
    let b = &m.cfg.b;
    let mut out = String::new();
    out += &format!(
        "    epoch {} owner sets {:?}, modes {:?}\n",
        s.epoch,
        (0..=s.epoch as usize).map(|e| &s.owner[e][..b.scopes as usize]).collect::<Vec<_>>(),
        &s.mode[..b.nodes as usize]
    );
    for n in 0..b.nodes as usize {
        let scopes: Vec<&str> = (0..b.scopes as usize)
            .map(|x| match s.scope[n][x] {
                Sc::None => "none",
                Sc::Open => "open",
            })
            .collect();
        out += &format!(
            "    n{n}: {} epoch {} scopes {:?} generations issued {}\n",
            if s.up[n] { "up" } else { "DOWN" },
            s.n_epoch[n],
            scopes,
            s.ngen[n]
        );
        for i in 0..b.slabs as usize {
            let x = &s.slab[n][i];
            let st = match x.st {
                St::Free => "FREE",
                St::Writing => "WRITING",
                St::Committed => "COMMITTED",
                St::Zombie => "ZOMBIE",
            };
            let k = if x.key == NOKEY { "-".into() } else { format!("k{}", x.key) };
            let mut flags = String::new();
            for (on, name) in [
                (x.wmr, " write-MR"),
                (x.pend1, " write1-in-flight"),
                (x.pend2, " write2-in-flight"),
                (x.cflight, " commit-in-flight"),
                (x.doomed, " DOOMED"),
            ] {
                if on {
                    flags += name;
                }
            }
            out += &format!(
                "      slab {i}: {st} key {k} gen {} halves [{} | {}]{flags} leases {:#b}\n",
                x.gen,
                half(x.h1),
                half(x.h2),
                x.lease
            );
        }
    }
    for c in 0..b.clients as usize {
        let cl = &s.cl[c];
        if cl.pc == Pc::Idle {
            out += &format!("    c{c}: idle, {} ops left\n", cl.ops_left);
        } else {
            out += &format!(
                "    c{c}: {:?} key k{} at n{} slab {} gen {} read [{} | {}] state_gen word {:?}{}\n",
                cl.pc,
                cl.key,
                cl.n,
                if cl.slab == NONE { "-".into() } else { cl.slab.to_string() },
                cl.gen,
                half(cl.d1),
                half(cl.d2),
                cl.sq,
                if m.would_accept(s, c as u8) { "  <-- ACCEPTS" } else { "" }
            );
        }
    }
    out
}

fn render_trace(m: &Mira, steps: Vec<(State, Option<Action>)>) -> String {
    let mut out = String::new();
    let mut last = None;
    for (i, (state, action)) in steps.into_iter().enumerate() {
        if let Some(a) = action {
            out += &format!("  {:>2}. {}\n", i + 1, describe(m, &a));
        }
        last = Some(state);
    }
    if let Some(s) = last {
        out += "  final state:\n";
        out += &describe_state(m, &s);
    }
    out
}
