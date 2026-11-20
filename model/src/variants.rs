//! Named protocol variants: the correct protocol, alternative correct
//! configurations, and the deliberately broken "teeth" variants.
//!
//! The first nine are the variants of design spec section 8.7 (revision 4)
//! and MiracacheProtocol.cfg, with the same names and switches.  The rest
//! inject one bug each, so that every property has a variant that breaks it.

use crate::model::{Bounds, Cfg, Faults, Rogue, Switches};

pub struct Variant {
    pub name: &'static str,
    pub what: &'static str,
    /// Properties that MUST produce a counterexample.  Empty: the variant must pass.
    pub must_fail: &'static [&'static str],
    /// Properties that may also fail as a consequence of the same bug.
    pub may_fail: &'static [&'static str],
    /// Explore the whole state space even after the expected counterexamples
    /// are found, and require that nothing outside must_fail/may_fail fails.
    pub exhaustive: bool,
    pub apply: fn(&mut Switches, &mut Faults),
    /// Adjust the bounds to what the variant needs (teeth: usually fewer
    /// kinds of adverse event, so that the search is quick).
    pub tune: fn(&mut Bounds),
}

impl Variant {
    /// Whether the whole state space is explored at these bounds.  Variants
    /// that must pass always are.  Teeth marked `exhaustive` are explored
    /// completely only at single-scope bounds (`ci`, `tiny`), where that is
    /// cheap; elsewhere they stop at the expected counterexamples.
    pub fn explore_all(&self, b: &Bounds, full: bool) -> bool {
        full || self.expect_pass() || (self.exhaustive && b.scopes == 1 && b.nodes <= 2)
    }
    pub fn cfg(&self, b: Bounds, full: bool) -> Cfg {
        let all = self.explore_all(&b, full);
        let mut sw = Switches::default();
        let mut f = Faults::default();
        (self.apply)(&mut sw, &mut f);
        let mut b = b;
        (self.tune)(&mut b);
        if !all {
            // early-stop searches print traces: keep the original names
            b.symmetry = false;
        }
        Cfg { b, sw, f }
    }
    pub fn expect_pass(&self) -> bool {
        self.must_fail.is_empty()
    }
}

macro_rules! v {
    ($name:expr, $what:expr, [$($must:expr),*], [$($may:expr),*], $ex:expr, $apply:expr) => {
        v!($name, $what, [$($must),*], [$($may),*], $ex, $apply, |_| {})
    };
    ($name:expr, $what:expr, [$($must:expr),*], [$($may:expr),*], $ex:expr, $apply:expr, $tune:expr) => {
        Variant { name: $name, what: $what, must_fail: &[$($must),*], may_fail: &[$($may),*],
                  exhaustive: $ex, apply: $apply, tune: $tune }
    };
}

/// Allow only the listed adverse events: r rogue writes, n node crashes,
/// c client crashes, d drops, l scope lapses, e epoch changes.
fn only(b: &mut Bounds, r: u8, n: u8, c: u8, d: u8, l: u8, e: u8) {
    b.invalidates = 0;
    b.rail_faults = 0;
    b.rogue_writes = r;
    b.node_crashes = n;
    b.client_crashes = c;
    b.drops = d;
    b.lapses = l;
    b.max_epoch = e;
    b.events = r + n + c + d + l + e;
}

pub fn variants() -> Vec<Variant> {
    vec![
        // ---- spec 8.7: must pass --------------------------------------------
        v!("default", "aead + seq, leases expire, blind rogue, fence, commit on the ingest QP, digest",
           [], [], true, |_, _| {}),
        v!("lease-only", "leases never expire, no rogue, both validators off",
           [], ["DropScopeEffective"], true, |sw, _| {
               sw.leases_expire = false; sw.rogue = Rogue::None;
               sw.use_seq = false; sw.use_aead = false;
           }),
        v!("seq-only", "no rogue, AEAD off, seq on, leases expire",
           [], [], true, |sw, _| { sw.rogue = Rogue::None; sw.use_aead = false; }),
        v!("digest-only", "PUT_COMMIT not ordered behind the data, digest on",
           [], [], true, |sw, _| sw.commit_on_ingest_qp = false,
           // Unordered commit keeps stale bytes of freed slabs distinct, which
           // blows the 2-scope space past the 3 GB container limit (OOM kill).
           // Shrunk: no epoch change, no INVALIDATE, no scope lapse.
           |b| { b.max_epoch = 0; b.invalidates = 0; b.lapses = 0; }),
        // ---- spec 8.7: teeth ------------------------------------------------
        v!("no-aead", "AEAD off, forging rogue",
           ["NoTornRead", "NoWrongKeyRead", "NoForeignScopeRead"],
           ["CommittedIntact", "NoStaleGenerationRead", "NoCrossPrincipalRead"], false,
           |sw, _| { sw.use_aead = false; sw.rogue = Rogue::Forging; },
           |b| only(b, 1, 0, 0, 0, 0, 0)),
        v!("no-validation", "AEAD off, seq off, no rogue",
           ["NoTornRead", "NoForeignScopeRead", "NoStaleGenerationRead"],
           ["NoWrongKeyRead", "DropScopeEffective", "NoCrossPrincipalRead"], false,
           |sw, _| { sw.use_aead = false; sw.use_seq = false; sw.rogue = Rogue::None; },
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("no-fence", "write MR not deregistered at commit (blind rogue, two writes)",
           ["WriteMrFenced", "CommittedIntact", "NoStaleGenerationRead"], [], true,
           |sw, _| sw.fence_at_commit = false,
           |b| only(b, 2, 0, 0, 0, 0, 0)),
        v!("commit-overtakes", "PUT_COMMIT not ordered, digest off, no rogue (the revision 3 iWARP bug)",
           ["CommittedIntact"], ["NoStaleGenerationRead"], true,
           |sw, _| { sw.commit_on_ingest_qp = false; sw.digest_at_commit = false; sw.rogue = Rogue::None; }),
        v!("forging-rogue", "forging rogue (two writes)",
           ["CommittedIntact", "NoStaleGenerationRead"], [], true,
           |sw, _| sw.rogue = Rogue::Forging,
           |b| only(b, 2, 0, 0, 0, 0, 0)),
        // ---- one injected bug each -----------------------------------------
        v!("seq-skip-gen", "seq check ignores the generation, no rogue",
           ["NoStaleGenerationRead"], ["DropScopeEffective"], false,
           |sw, f| { sw.rogue = Rogue::None; f.seq_skip_gen = true; },
           // both clients must reach the same keys: one principal, two scope_ids
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.principals = 1; b.scopes = 2; }),
        v!("seq-early", "state_gen READ posted before the payload READs completed; AEAD off, no rogue",
           ["NoTornRead"],
           ["NoForeignScopeRead", "NoWrongKeyRead", "NoStaleGenerationRead", "DropScopeEffective", "NoCrossPrincipalRead"], false,
           |sw, f| { sw.rogue = Rogue::None; sw.use_aead = false; f.seq_early = true; },
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("no-lease", "LOOKUP takes no lease (leases otherwise never expire)",
           ["LeaseCoversReader"], [], false,
           |sw, f| { sw.leases_expire = false; f.no_lease = true; },
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("no-release", "client never sends RELEASE",
           ["NoLeaseLeak"], [], false, |_, f| f.no_release = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("evict-leased", "evictor ignores lease_count",
           ["LeaseSafety"], [], false, |_, f| f.evict_leased = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("no-tail-first", "evictor ignores children",
           ["NoOrphanTail"], [], false, |_, f| f.no_tail_first = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("invalidate-no-subtree", "INVALIDATE drops the block but not its subtree",
           ["NoOrphanTail"], [], false, |_, f| f.invalidate_no_subtree = true,
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.invalidates = 1; b.events = 1; }),
        v!("no-open-check", "PUT_BEGIN does not check that the scope is open",
           ["DenyByDefault"], [], false, |_, f| f.no_open_check = true,
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.preopen = false; }),
        v!("no-exists-check", "PUT_BEGIN does not check for an existing key",
           ["UniqueKey"], [], false, |_, f| f.no_exists_check = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("no-owner-check", "root PUT_BEGIN accepted on any node outside the owner set",
           ["RootPutAtReplica"], [], false, |_, f| f.no_owner_check = true,
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.nodes = b.nodes.max(2); }),
        v!("readonly-accepts-put", "a ReadOnly node accepts PUT_BEGIN as if it were Active",
           ["NoPutOnReadOnly"], [], false, |_, f| f.readonly_accepts_put = true,
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.mode_changes = 1; b.events = 1; }),
        v!("slot-local-gen", "generations are per slot, not node-global",
           ["GenerationsUnique"], ["NoStaleGenerationRead"], false, |_, f| f.slot_local_gen = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("epoch-overshoot", "a node adopts an epoch beyond the controller's",
           ["EpochsBounded"], ["RootPutAtReplica"], false, |_, f| f.epoch_overshoot = true,
           |b| { only(b, 0, 0, 0, 0, 0, 1); b.nodes = b.nodes.max(2); b.max_epoch = 1; }),
        v!("drop-no-state", "drop_scope forgets the scope but leaves its blocks COMMITTED",
           ["DropScopeEffective", "DenyByDefault"], [], false, |_, f| f.drop_no_state = true,
           |b| only(b, 0, 0, 0, 1, 0, 0)),
        v!("no-doom", "drop_scope does not doom the scope's pending puts",
           ["DenyByDefault"], ["DropScopeEffective"], false, |_, f| f.no_doom = true,
           |b| only(b, 0, 0, 0, 1, 0, 0)),
        v!("no-deadline", "no fetch deadline, puts never abandoned",
           ["OpsTerminate"], [], false, |_, f| f.no_deadline = true,
           |b| { only(b, 0, 1, 0, 0, 0, 0); b.clients = 1; b.ops = 1; b.scopes = 1; b.principals = 1; b.max_pos = 1; b.slabs = 1; }),
        v!("put-id-reuse", "a delayed PUT_COMMIT of an aborted put applies to a put re-begun in the same slot; digest off, no rogue",
           ["CommittedIntact"], ["NoStaleGenerationRead", "NoTornRead", "NoWrongKeyRead", "NoForeignScopeRead"], false,
           |sw, f| { sw.digest_at_commit = false; sw.rogue = Rogue::None; f.put_id_reuse = true; },
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        // ---- multi-rail fetch re-issue --------
        v!("reissue-before-flush", "a slice is re-issued while its original READ may still land; AEAD off, no rogue",
           ["NoTornRead"],
           ["NoForeignScopeRead", "NoWrongKeyRead", "NoStaleGenerationRead", "DropScopeEffective", "NoCrossPrincipalRead"], false,
           |sw, f| { sw.rogue = Rogue::None; sw.use_aead = false; f.reissue_early = true; },
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.rail_faults = 1; }),
        v!("seq-before-reissue", "state_gen READ posted while a re-issued slice is still pending; AEAD off, no rogue",
           ["NoTornRead"],
           ["NoForeignScopeRead", "NoWrongKeyRead", "NoStaleGenerationRead", "DropScopeEffective", "NoCrossPrincipalRead"], false,
           |sw, f| { sw.rogue = Rogue::None; sw.use_aead = false; f.seq_before_reissue = true; },
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.rail_faults = 1; }),
        v!("release-outstanding", "the fetch buffer is released while a slice WR is neither completed nor flushed",
           ["NoReleaseWithOutstanding"], [], false,
           |_, f| f.release_outstanding = true,
           |b| { only(b, 0, 0, 0, 0, 0, 0); b.rail_faults = 1; }),
        // ---- revision 5.1: (principal, scope_id) keying, implicit open ----------
        v!("scope-keyed-by-id-only", "scope table and block keys use scope_id alone, not (principal, scope_id)",
           ["NoCrossPrincipalRead"],
           ["DenyByDefault", "DropScopeEffective", "NoWrongKeyRead", "NoForeignScopeRead", "NoStaleGenerationRead"], false,
           |_, f| f.scope_by_id_only = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("lookup-opens-scope", "LOOKUP of an unknown scope opens it",
           ["DenyByDefault"], ["CapEvictsOwnOnly"], false,
           |_, f| f.lookup_opens_scope = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
        v!("cap-evicts-any", "at the cap the node may evict another principal's scope",
           ["CapEvictsOwnOnly"], [], false,
           |_, f| f.cap_evicts_any = true,
           |b| only(b, 0, 0, 0, 0, 0, 0)),
    ]
}

pub fn variant(name: &str) -> Option<Variant> {
    variants().into_iter().find(|v| v.name == name)
}
