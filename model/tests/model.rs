//! `cargo test --release`
//!
//! Asserts that the correct protocol passes, that every teeth variant produces
//! its counterexamples, and that every property has teeth.  Checker runs are
//! serialised and use two threads each (they are memory-hungry).

use miracache_model::model::Pc;
use miracache_model::{check_variant, run_sim, variants, Bounds, Mira, Outcome, Variant};
use stateright::Model;
use std::collections::BTreeSet;
use std::sync::Mutex;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
const THREADS: usize = 2;

fn run(v: &Variant, b: Bounds) -> Outcome {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    check_variant(v, b, THREADS, false, None)
}

fn assert_expected(v: &Variant, out: &Outcome) {
    let failed = out.failed_names();
    for must in v.must_fail {
        assert!(
            failed.contains(must),
            "variant {}: expected a counterexample for {must}, the model has lost its teeth",
            v.name
        );
    }
    for name in &failed {
        assert!(
            v.must_fail.contains(name) || v.may_fail.contains(name),
            "variant {}: unexpected counterexample for {name}:\n{}",
            v.name,
            out.failed[name]
        );
    }
}

/// The correct protocol at the bounds of MiracacheProtocol.cfg: every
/// property holds over the whole reachable state space, and the model is not
/// vacuous (every reachability witness is found).
#[test]
fn default_holds_at_small_bounds() {
    let v = miracache_model::variant("default").unwrap();
    let out = run(&v, Bounds::small());
    assert!(out.complete, "the state space was not explored completely");
    assert!(out.failed.is_empty(), "counterexamples: {:?}", out.failed);
    assert!(out.unwitnessed.is_empty(), "not reachable: {:?}", out.unwitnessed);
    assert_eq!(out.not_applicable, vec!["LeaseCoversReader"]);
}

/// Every variant that spec 8.7 expects to pass does, exhaustively.
#[test]
fn passing_variants_hold() {
    for v in variants().iter().filter(|v| v.expect_pass()) {
        let out = run(v, Bounds::ci());
        assert!(out.complete, "{}", v.name);
        assert_expected(v, &out);
        if v.name == "lease-only" {
            // the one configuration where LeaseCoversReader is live
            assert!(out.held.contains(&"LeaseCoversReader"));
        }
    }
}

/// Every teeth variant produces a counterexample for each property it must
/// break, and for nothing outside its declared set.
#[test]
fn every_teeth_variant_fails() {
    for v in variants().iter().filter(|v| !v.expect_pass()) {
        // Variants marked exhaustive are explored completely (single-scope
        // bounds), which also proves what they must NOT break.
        let b = if v.exhaustive { Bounds::ci() } else { Bounds::small() };
        let out = run(v, b);
        assert_eq!(out.complete, v.exhaustive, "{}", v.name);
        assert_expected(v, &out);
    }
}

/// The spec 8.7 "must hold" claims for the teeth variants.
#[test]
fn teeth_variants_keep_the_read_properties_they_should() {
    let reads = ["NoTornRead", "NoWrongKeyRead", "NoForeignScopeRead"];
    for name in ["no-fence", "forging-rogue", "commit-overtakes"] {
        let v = miracache_model::variant(name).unwrap();
        let out = run(&v, Bounds::ci());
        assert!(out.complete);
        for r in reads {
            assert!(out.held.contains(&r), "{name}: {r} should hold");
        }
    }
}

/// Every safety and liveness property is broken by at least one variant.
#[test]
fn every_property_has_teeth() {
    let model = Mira::new(variants()[0].cfg(Bounds::small(), false));
    let broken: BTreeSet<&str> =
        variants().iter().flat_map(|v| v.must_fail.iter().copied()).collect();
    for p in model.properties() {
        if p.name.starts_with("can:") || p.name == "TypeOK" {
            continue; // witnesses; TypeOK is carried by the Rust types
        }
        assert!(broken.contains(p.name), "no teeth variant for {}", p.name);
    }
}

/// The state graph of the correct protocol has no cycle along a path, and
/// every maximal path ends with every client idle.  This is what makes the
/// `eventually` check of OpsTerminate sound (Stateright does not detect
/// cycles for `eventually` properties).
#[test]
fn random_walks_are_acyclic_and_terminate() {
    let mut b = Bounds::small();
    b.symmetry = false;
    b.events = 3;
    let model = Mira::new(variants()[0].cfg(b, false));
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move |n: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % n as u64) as usize
    };
    for _ in 0..3000 {
        let init = model.init_states();
        let mut s = init[rnd(init.len())].clone();
        let mut seen = vec![s.clone()];
        loop {
            let next = model.next_states(&s);
            if next.is_empty() {
                break;
            }
            s = next[rnd(next.len())].clone();
            assert!(!seen.contains(&s), "cycle in the state graph");
            seen.push(s.clone());
            assert!(seen.len() < 1000, "path does not end");
        }
        assert!(
            (0..b.clients as usize).all(|c| s.cl[c].pc == Pc::Idle),
            "an operation is stuck at a terminal state"
        );
    }
}

/// Random simulation at the nightly bounds (a short budget here; the CLI runs
/// the full one).
#[test]
fn nightly_simulation_smoke() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let v = miracache_model::variant("default").unwrap();
    let out = run_sim(v.cfg(Bounds::nightly(), false), 20261109, 300_000, THREADS);
    assert!(out.failed.is_empty(), "counterexamples: {:?}", out.failed);
}

/// three nodes, one scope, R = 2.  The correct protocol holds over the
/// whole space (owner sets, modes), and the two owner-set/mode teeth give
/// their counterexamples.  At two nodes with R = 2 every node is in the owner
/// set, so only this bound makes `RootPutAtReplica` non-vacuous.
#[test]
fn replica3_owner_set_and_modes() {
    let b = Bounds::replica3();
    assert_eq!((b.nodes, b.scopes, b.replicas), (3, 1, 2));
    let v = miracache_model::variant("default").unwrap();
    let out = run(&v, b);
    assert!(out.complete);
    assert!(out.failed.is_empty(), "counterexamples: {:?}", out.failed);
    assert!(out.held.contains(&"RootPutAtReplica") && out.held.contains(&"NoPutOnReadOnly"));
    assert!(out.unwitnessed.is_empty(), "not reachable: {:?}", out.unwitnessed);
    for name in ["no-owner-check", "readonly-accepts-put", "epoch-overshoot"] {
        let v = miracache_model::variant(name).unwrap();
        let out = run(&v, b);
        assert_expected(&v, &out);
    }
}

/// the real drain path.  Two nodes, one scope, one epoch change, two mode
/// changes (Draining, then ReadOnly) and three adverse events, so a mode change
/// combines with an epoch change and a crash.  Every passing variant holds over
/// the whole space.  Trimmed to one operation per client (two operations per
/// client does not finish in 10 min / 3 GB); the CLI runs the same bound with
/// `--bounds drain`, and `--bounds drain --set ops=2 --set clients=1` is the
/// one-client, two-operation variant.
#[test]
fn drain_path_holds() {
    let b = Bounds::drain();
    assert_eq!((b.nodes, b.scopes, b.max_epoch, b.mode_changes, b.events), (2, 1, 1, 2, 3));
    for v in variants().iter().filter(|v| v.expect_pass()) {
        let out = run(v, b);
        assert!(out.complete, "{}: partial", v.name);
        assert_expected(v, &out);
    }
}

/// The two chain witnesses need two blocks on one node (two slabs, a
/// continuation position); below that they are not built, so the default
/// variant has no unreachable sanity witness.
#[test]
fn chain_witnesses_follow_the_bounds() {
    let v = miracache_model::variant("default").unwrap();
    let mut b = Bounds::drain();
    b.slabs = 1;
    let out = run(&v, b);
    assert!(out.complete && out.failed.is_empty());
    assert!(out.unwitnessed.is_empty(), "not reachable: {:?}", out.unwitnessed);
    let m = Mira::new(v.cfg(b, false));
    let names: Vec<_> = m.properties().iter().map(|p| p.name).collect();
    assert!(!names.iter().any(|n| n.contains("chain of two") || n.contains("continuation accepted")));
    let m = Mira::new(v.cfg(Bounds::drain(), false));
    let names: Vec<_> = m.properties().iter().map(|p| p.name).collect();
    assert!(names.iter().any(|n| n.contains("chain of two")) && names.iter().any(|n| n.contains("continuation accepted")));
}
