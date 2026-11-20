//! The protocol model: state, actions, transition function and properties.
//!
//! A port of the protocol's TLA+ specification (design spec section 8,
//! revision 5.1).  Action and invariant names follow the TLA+ module.  What the
//! model adds to, or bounds differently from, the reference is listed in
//! README.md.

use stateright::{Model, Property};

pub const MAXC: usize = 3; // clients
pub const MAXN: usize = 3; // memory nodes
pub const MAXS: usize = 4; // scope entries: (principal, scope_id) pairs
pub const MAXSLAB: usize = 3; // slabs per node
pub const MAXE: usize = 3; // epochs 0..=2
pub const NOKEY: u8 = 255;
pub const NONE: u8 = 255;

// ---------------------------------------------------------------------------
// Configuration

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub clients: u8,
    pub nodes: u8,
    /// Scope entries, i.e. (principal, scope_id) pairs: `principals` times
    /// `scopes / principals` scope_ids per principal.  Entry x belongs to
    /// principal x / ids; its scope_id bytes are x % ids, so entries of
    /// different principals share scope_id bytes.
    pub scopes: u8,
    /// Principals.  Client c has principal c % principals.
    pub principals: u8,
    /// Per-principal cap on open scopes on a node (R17).
    pub max_scopes: u8,
    /// Chain length (TLA+ MaxPos).  One chain per scope.
    pub max_pos: u8,
    pub slabs: u8,
    /// TLA+ MaxGen: generations a node may issue.
    pub max_gen: u8,
    pub max_epoch: u8,
    /// R: the owner set of a scope has 1..=R nodes (a bitmask over nodes).
    pub replicas: u8,
    /// Controller `SetMode` actions (Active / Draining / ReadOnly per node).
    pub mode_changes: u8,
    /// TLA+ MaxCrashes (memory-node crashes, warm or cold).
    pub node_crashes: u8,
    pub client_crashes: u8,
    /// Scopes the scope provider may drop.
    pub drops: u8,
    /// Scope TTL lapses (SuspendScope).
    pub lapses: u8,
    /// Writes the rogue trust-domain member may issue.
    pub rogue_writes: u8,
    /// INVALIDATE requests.
    pub invalidates: u8,
    /// Rail failures per run (RL0): a fetch half's rail turns suspect and the half is re-issued.
    pub rail_faults: u8,
    /// Total adverse events per run (node crash, client crash, rogue write,
    /// drop_scope, scope lapse, INVALIDATE, epoch change), on top of the per-kind caps.
    pub events: u8,
    /// Operations (get or put) each client may start.
    pub ops: u8,
    /// Every scope starts open on every node (the TLA+ Init has none open).
    pub preopen: bool,
    /// Explore one representative per symmetry class (clients, nodes, scopes
    /// and the slabs of a node are interchangeable).
    pub symmetry: bool,
}

impl Bounds {
    /// One node, one scope: for unit tests and quick experiments.
    pub const fn tiny() -> Self {
        Bounds {
            clients: 2,
            nodes: 1,
            scopes: 1,
            principals: 1,
            max_scopes: 1,
            max_pos: 2,
            slabs: 2,
            max_gen: 3,
            max_epoch: 0,
            replicas: 1,
            mode_changes: 0,
            node_crashes: 1,
            client_crashes: 1,
            drops: 1,
            lapses: 1,
            rogue_writes: 1,
            invalidates: 1,
            rail_faults: 1,
            events: 2,
            ops: 2,
            preopen: false,
            symmetry: true,
        }
    }
    /// `small` with a single scope.  Used by `cargo test` for the variants
    /// that must be explored completely.
    pub const fn ci() -> Self {
        let mut b = Self::small();
        b.scopes = 1;
        b.principals = 1;
        // single scope entry: the two-node, epoch-change space of revision 4
        b.nodes = 2;
        b.max_epoch = 1;
        b
    }
    /// The real drain path: two nodes, one scope, one epoch change, two mode
    /// changes (Active -> Draining -> ReadOnly) and up to three adverse events,
    /// so a mode change combines with an epoch change and a crash.
    pub const fn drain() -> Self {
        let mut b = Self::ci();
        b.mode_changes = 2;
        b.events = 3;
        // two clients doing two operations each does not finish in 10 min / 3 GB
        // (default variant, 2 threads); one operation each takes 2 s and 0.1 GB.
        b.ops = 1;
        b
    }
    /// Three nodes, one scope, R = 2: the smallest space where the owner set
    /// is a proper subset of the nodes, so `RootPutAtReplica` is not vacuous
    /// (at two nodes with R = 2 every node is in the set).  No epoch change
    /// and a single adverse event: the three-node space is large.
    pub const fn replica3() -> Self {
        let mut b = Self::ci();
        b.nodes = 3;
        b.replicas = 2;
        b.max_epoch = 0;
        b
    }
    /// MiracacheProtocol.cfg with revision 5.1 scopes: 2 principals x 2
    /// scope_ids, per-principal cap 1.  One node and no epoch change: the
    /// four-entry, two-node space exceeds the 3 GB container limit; the
    /// two-node epoch space is covered by `ci`.
    pub const fn small() -> Self {
        Bounds {
            clients: 2,
            nodes: 1,
            scopes: 4,
            principals: 2,
            max_scopes: 1,
            max_pos: 2,
            slabs: 2,
            max_gen: 3,
            max_epoch: 0,
            replicas: 1,
            mode_changes: 1,
            node_crashes: 1,
            client_crashes: 1,
            drops: 1,
            lapses: 1,
            rogue_writes: 1,
            invalidates: 1,
            rail_faults: 1,
            events: 1,
            ops: 2,
            preopen: false,
            symmetry: true,
        }
    }
    pub const fn nightly() -> Self {
        Bounds {
            clients: 3,
            nodes: 3,
            scopes: 4,
            principals: 2,
            max_scopes: 2,
            max_pos: 3,
            slabs: 3,
            max_gen: 6,
            max_epoch: 2,
            replicas: 2,
            mode_changes: 2,
            node_crashes: 2,
            client_crashes: 2,
            drops: 2,
            lapses: 2,
            rogue_writes: 3,
            invalidates: 2,
            rail_faults: 2,
            events: 8,
            ops: 4,
            preopen: false,
            symmetry: false,
        }
    }
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "tiny" => Some(Self::tiny()),
            "ci" => Some(Self::ci()),
            "replica3" => Some(Self::replica3()),
            "drain" => Some(Self::drain()),
            "small" => Some(Self::small()),
            "nightly" => Some(Self::nightly()),
            _ => None,
        }
    }
    /// Override one bound by name (CLI `--set name=value`).
    pub fn set(&mut self, name: &str, v: u8) -> bool {
        let f = match name {
            "clients" => &mut self.clients,
            "nodes" => &mut self.nodes,
            "scopes" => &mut self.scopes,
            "principals" => &mut self.principals,
            "max_scopes" => &mut self.max_scopes,
            "max_pos" => &mut self.max_pos,
            "slabs" => &mut self.slabs,
            "max_gen" => &mut self.max_gen,
            "max_epoch" => &mut self.max_epoch,
            "replicas" => &mut self.replicas,
            "mode_changes" => &mut self.mode_changes,
            "node_crashes" => &mut self.node_crashes,
            "client_crashes" => &mut self.client_crashes,
            "drops" => &mut self.drops,
            "lapses" => &mut self.lapses,
            "rogue_writes" => &mut self.rogue_writes,
            "invalidates" => &mut self.invalidates,
            "rail_faults" => &mut self.rail_faults,
            "events" => &mut self.events,
            "ops" => &mut self.ops,
            "preopen" => {
                self.preopen = v != 0;
                return true;
            }
            "symmetry" => {
                self.symmetry = v != 0;
                return true;
            }
            _ => return false,
        };
        *f = v;
        true
    }
    pub fn keys(&self) -> u8 {
        self.scopes * self.max_pos
    }
}

/// TLA+ `Rogue`: a trust-domain member that writes into live write MRs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rogue {
    None,
    /// Cannot make the commit digest match.
    Blind,
    /// Can.
    Forging,
}

/// The seven switches of the TLA+ module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Switches {
    pub leases_expire: bool,
    pub use_seq: bool,
    pub use_aead: bool,
    pub rogue: Rogue,
    pub fence_at_commit: bool,
    /// PUT_COMMIT is delivered only after every WRITE of the put was placed.
    pub commit_on_ingest_qp: bool,
    /// The server commits only if the extent matches the client's digest.
    pub digest_at_commit: bool,
}

impl Default for Switches {
    fn default() -> Self {
        Switches {
            leases_expire: true,
            use_seq: true,
            use_aead: true,
            rogue: Rogue::Blind,
            fence_at_commit: true,
            commit_on_ingest_qp: true,
            digest_at_commit: true,
        }
    }
}

/// Deliberate protocol bugs ("teeth") beyond the TLA+ switches.  All false in
/// a correct model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// The seq check looks at the state byte but not at the generation.
    pub seq_skip_gen: bool,
    /// The state_gen READ may be posted before the payload READs completed.
    pub seq_early: bool,
    /// LOOKUP hits do not take a lease.
    pub no_lease: bool,
    /// The client does not RELEASE when a fetch ends.
    pub no_release: bool,
    /// The evictor ignores lease_count.
    pub evict_leased: bool,
    /// The evictor ignores children (no tail-first rule).
    pub no_tail_first: bool,
    /// INVALIDATE drops the block but not its subtree.
    pub invalidate_no_subtree: bool,
    /// PUT_BEGIN does not check that the scope is open.
    pub no_open_check: bool,
    /// PUT_BEGIN does not check for an existing or pending key.
    pub no_exists_check: bool,
    /// A root PUT_BEGIN is accepted on any node.
    pub no_owner_check: bool,
    /// A ReadOnly node is treated as Active by PUT_BEGIN.
    pub readonly_accepts_put: bool,
    /// Generations are per slot instead of node-global.
    pub slot_local_gen: bool,
    /// A node adopts an epoch beyond the controller's.
    pub epoch_overshoot: bool,
    /// drop_scope forgets the scope but leaves its blocks COMMITTED.
    pub drop_no_state: bool,
    /// drop_scope / lapse does not doom the scope's pending puts.
    pub no_doom: bool,
    /// The scope table is keyed by scope_id alone, not (principal, scope_id):
    /// lookups and the block key derivation ignore the principal.
    pub scope_by_id_only: bool,
    /// LOOKUP of an unknown scope opens it.
    pub lookup_opens_scope: bool,
    /// At the principal's cap the node evicts any principal's scope.
    pub cap_evicts_any: bool,
    /// Clients have no fetch deadline and never abandon a put.
    pub no_deadline: bool,
    /// A delayed PUT_COMMIT of an aborted put applies to a put later begun in
    /// the same slot (no put_id), and is not ordered behind that put's data.
    pub put_id_reuse: bool,
    /// RL0: a slice is re-issued while its original WR may still land (before its CQE).
    pub reissue_early: bool,
    /// RL0: the state_gen READ is posted while a re-issued slice is still pending.
    pub seq_before_reissue: bool,
    /// RL0: the buffer is released while a slice WR is still outstanding.
    pub release_outstanding: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cfg {
    pub b: Bounds,
    pub sw: Switches,
    pub f: Faults,
}

// ---------------------------------------------------------------------------
// State

/// Member state of a node in the bundle (plan decision 8): Active serves
/// everything; Draining refuses root PUT_BEGIN (continuations, reads still
/// served); ReadOnly refuses every PUT_BEGIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mode {
    Active,
    Draining,
    ReadOnly,
}

/// One half of a payload: never written, garbage, or one encryption instance
/// `<<key, gen>>` of a key (TLA+ Halves).  Generation 0 is never issued, so
/// `Tag(k, 0)` stands for "ciphertext of k replayed from an older instance".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Half {
    None,
    Garbage,
    Tag(u8, u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum St {
    Free,
    Writing,
    Committed,
    Zombie,
}

/// Scope state on one node (deny by default).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Sc {
    None,
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slab {
    pub st: St,
    pub key: u8,
    pub gen: u8,
    pub h1: Half,
    pub h2: Half,
    /// Client whose put owns the extent while WRITING.
    pub writer: u8,
    /// A write MR over this extent is registered.
    pub wmr: bool,
    /// WRITE of half 1 / 2 posted, not yet placed.
    pub pend1: bool,
    pub pend2: bool,
    /// PUT_COMMIT sent, not yet delivered.
    pub cflight: bool,
    /// The put will abort at commit (scope gone or ancestor invalidated).
    pub doomed: bool,
    /// Lease set: one bit per client.
    pub lease: u8,
    /// Fault `put_id_reuse` only: a PUT_COMMIT of an aborted put is still in
    /// flight towards this slot.
    pub stale: bool,
}

const FREE_SLAB: Slab = Slab {
    st: St::Free,
    key: NOKEY,
    gen: 0,
    h1: Half::None,
    h2: Half::None,
    writer: NONE,
    wmr: false,
    pend1: false,
    pend2: false,
    cflight: false,
    doomed: false,
    lease: 0,
    stale: false,
};

/// RL0: state of one fetch slice (a half of the payload) over rail failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Hs {
    /// The original READ is posted (or already completed: see `got`).
    Ok,
    /// Its rail is suspect: no CQE yet, the original WR may still land.
    Susp,
    /// Its own CQE arrived (error or flush): it can never land.  May be re-issued.
    Flushed,
    /// Re-issued: the new READ is outstanding.
    Re,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Pc {
    Idle,
    /// LOOKUP sent to a node that is down: only the deadline ends it.
    LookupWait,
    /// TLA+ "rd": payload READs and then the state_gen READ.
    Rd,
    Val,
    Drain,
    /// TLA+ "pw": WRITEs posted, PUT_COMMIT not yet posted.
    Pw,
    /// TLA+ "pwait".
    PutWait,
}

impl Pc {
    /// TLA+ GetStates: the client holds (or should hold) a lease.
    pub fn is_reading(self) -> bool {
        matches!(self, Pc::Rd | Pc::Val | Pc::Drain)
    }
    pub fn is_put(self) -> bool {
        matches!(self, Pc::Pw | Pc::PutWait)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Client {
    pub pc: Pc,
    pub ops_left: u8,
    pub key: u8,
    pub n: u8,
    pub slab: u8,
    pub gen: u8,
    pub d1: Half,
    pub d2: Half,
    pub got1: bool,
    pub got2: bool,
    /// The state_gen word, read last: (state, generation).
    pub sq: Option<(St, u8)>,
    /// Ghost: when the state_gen word was read, the node still knew the scope.
    pub sq_scope_known: bool,
    /// RL0: state of each half's slice (half 1, half 2).
    pub hs: [Hs; 2],
    /// RL0: the half's original READ WR may still land (no CQE yet).
    pub live: [bool; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct State {
    // membership controller
    pub epoch: u8,
    /// owner[e][scope]: bitmask of the nodes in the owner set (1..=R bits).
    pub owner: [[u8; MAXS]; MAXE],
    /// Member state of each node, set by the controller (`SetMode`).
    pub mode: [Mode; MAXN],
    /// Ghost: some PUT_BEGIN was accepted on a node whose mode was ReadOnly.
    pub put_on_ro: bool,
    pub n_epoch: [u8; MAXN],
    pub c_epoch: [u8; MAXC],
    // memory nodes
    pub up: [bool; MAXN],
    pub scope: [[Sc; MAXS]; MAXN],
    /// Ghost: the entry was created by a root PUT_BEGIN (or preopened).
    pub legit: [[bool; MAXS]; MAXN],
    pub ngen: [u8; MAXN],
    pub slab: [[Slab; MAXSLAB]; MAXN],
    // scope provider
    /// Ghost: a cap eviction took another principal's scope.
    pub cross_evicted: bool,
    /// Ghost: a cap eviction took the opening principal's own scope.
    pub evicted_own: bool,
    // clients
    pub cl: [Client; MAXC],
    // budgets
    pub crashes_left: u8,
    pub ccrashes_left: u8,
    pub drops_left: u8,
    pub lapses_left: u8,
    pub rogue_left: u8,
    pub invalidates_left: u8,
    pub rail_left: u8,
    /// Ghost: a fetch released its buffer while a slice WR was still outstanding.
    pub released_outstanding: bool,
    pub events_left: u8,
    pub modes_left: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    // scope provider / controller
    /// TTL expiry (no renewal by activity): the entry is reaped.
    ExpireScope { n: u8, s: u8 },
    DropScope { n: u8, s: u8 },
    // put
    /// `victim`: scope entry evicted by the implicit open (NONE: none).
    PutBegin { c: u8, key: u8, n: u8, slab: u8, victim: u8 },
    /// Fault `lookup_opens_scope` only: a LOOKUP miss that opens the scope.
    LookupOpen { c: u8, key: u8, n: u8 },
    Place1 { n: u8, i: u8 },
    Place2 { n: u8, i: u8 },
    PutSendCommit(u8),
    /// TLA+ CommitDeliver followed by PutCommit.
    PutCommit { n: u8, i: u8 },
    PutAbort { n: u8, i: u8 },
    ClientPutEnd(u8),
    PutAbandon(u8),
    RogueWrite { n: u8, i: u8, first: bool, val: Half },
    Invalidate { n: u8, i: u8 },
    // get
    GetLookup { c: u8, key: u8, n: u8 },
    GetRead1(u8),
    GetRead2(u8),
    GetSeqRead(u8),
    /// RL0: the rail of slice `h` (0 or 1) turns suspect; no CQE yet.
    RailFail { c: u8, h: u8 },
    /// RL0: the rail's QPs are moved to ERR and the slice's flush CQE arrives.
    RailFlush { c: u8, h: u8 },
    /// RL0: the original READ of slice `h` lands (it still could: tooth path).
    OrigLand { c: u8, h: u8 },
    /// RL0: slice `h` is re-issued.
    GetReissue { c: u8, h: u8 },
    GetValidate(u8),
    GetCancel(u8),
    GetDrained(u8),
    LeaseExpire { n: u8, i: u8, c: u8 },
    // eviction
    Evict { n: u8, i: u8 },
    ZombieReap { n: u8, i: u8 },
    // failures
    Crash { n: u8, warm: bool },
    Restart(u8),
    ClientCrash(u8),
    // membership
    EpochChange { owners: [u8; MAXS] },
    /// Controller: node `n` takes the member state `mode` (same epoch).
    SetMode { n: u8, mode: Mode },
}

#[derive(Clone, Debug)]
pub struct Mira {
    pub cfg: Cfg,
}

fn intact(b: &Slab) -> bool {
    b.h1 == Half::Tag(b.key, b.gen) && b.h2 == Half::Tag(b.key, b.gen)
}

/// TLA+ Cleared: fence and release.  No write MR, nothing in flight.
fn clear(b: &mut Slab) {
    b.writer = NONE;
    b.wmr = false;
    b.pend1 = false;
    b.pend2 = false;
    b.cflight = false;
    b.doomed = false;
    b.stale = false;
}

impl Mira {
    pub fn new(cfg: Cfg) -> Self {
        let b = &cfg.b;
        assert!(b.clients as usize <= MAXC && b.nodes as usize <= MAXN);
        assert!(b.scopes as usize <= MAXS && b.slabs as usize <= MAXSLAB);
        assert!((b.max_epoch as usize) < MAXE);
        Mira { cfg }
    }

    // --- keys -------------------------------------------------------------
    pub fn scope_of(&self, key: u8) -> u8 {
        key / self.cfg.b.max_pos
    }
    pub fn pos_of(&self, key: u8) -> u8 {
        key % self.cfg.b.max_pos
    }
    fn child(&self, key: u8) -> Option<u8> {
        (self.pos_of(key) + 1 < self.cfg.b.max_pos).then(|| key + 1)
    }

    // --- principals and scope entries ---------------------------------------
    fn ids(&self) -> u8 {
        self.cfg.b.scopes / self.cfg.b.principals
    }
    pub fn prin_of(&self, entry: u8) -> u8 {
        entry / self.ids()
    }
    fn sid_of(&self, entry: u8) -> u8 {
        entry % self.ids()
    }
    pub fn cprin(&self, c: u8) -> u8 {
        c % self.cfg.b.principals
    }
    /// Key equality as the node's tables see it.
    fn same_key(&self, a: u8, b: u8) -> bool {
        a == b
            || (self.cfg.f.scope_by_id_only
                && a != NOKEY
                && b != NOKEY
                && self.pos_of(a) == self.pos_of(b)
                && self.sid_of(self.scope_of(a)) == self.sid_of(self.scope_of(b)))
    }
    /// Scope open as a LOOKUP sees it (fault: table keyed by scope_id alone).
    fn lookup_open(&self, s: &State, n: u8, entry: u8) -> bool {
        if self.cfg.f.scope_by_id_only {
            (0..self.cfg.b.scopes).any(|x| {
                self.sid_of(x) == self.sid_of(entry) && self.sc(s, n, x) == Sc::Open
            })
        } else {
            self.sc(s, n, entry) == Sc::Open
        }
    }
    fn committed_lookup(&self, s: &State, n: u8, key: u8) -> Option<u8> {
        (0..self.cfg.b.slabs).find(|&i| {
            let b = &s.slab[n as usize][i as usize];
            b.st == St::Committed && self.same_key(b.key, key)
        })
    }
    /// Entries evicted by the implicit open of `scope` by client `c`: `[NONE]`
    /// when none is needed, else one candidate per entry that may be evicted.
    fn victims(&self, s: &State, c: u8, key: u8, n: u8) -> Vec<u8> {
        let (b, f) = (&self.cfg.b, &self.cfg.f);
        let scope = self.scope_of(key);
        if f.no_open_check || self.pos_of(key) != 0 || self.sc(s, n, scope) != Sc::None {
            return vec![NONE];
        }
        let p = self.cprin(c);
        let held =
            (0..b.scopes).filter(|&x| self.prin_of(x) == p && self.sc(s, n, x) != Sc::None).count();
        if held < b.max_scopes as usize {
            return vec![NONE];
        }
        (0..b.scopes)
            .filter(|&x| {
                self.sc(s, n, x) != Sc::None && (f.cap_evicts_any || self.prin_of(x) == p)
            })
            .collect()
    }
    /// The entry leaves the table: its blocks are unlinked (leased ones become
    /// zombies) and its pending puts doomed.
    fn remove_scope(&self, s: &mut State, n: u8, scope: u8, keep_committed: bool) {
        let f = &self.cfg.f;
        s.scope[n as usize][scope as usize] = Sc::None;
        s.legit[n as usize][scope as usize] = false;
        for i in 0..self.cfg.b.slabs as usize {
            let blk = &mut s.slab[n as usize][i];
            if blk.key != NOKEY
                && self.scope_of(blk.key) == scope
                && !(keep_committed && blk.st == St::Committed)
            {
                Self::unlink(blk, !f.no_doom);
            }
        }
    }

    // --- helpers ----------------------------------------------------------
    /// Every owner set: a non-empty bitmask over the nodes with at most R bits.
    fn masks(&self) -> Vec<u8> {
        let b = &self.cfg.b;
        (1u16..1 << b.nodes).filter(|m| m.count_ones() <= b.replicas as u32).map(|m| m as u8).collect()
    }
    /// The owner set (bitmask) of `scope` at epoch `e`.
    fn owner_set_at(&self, s: &State, e: u8, scope: u8) -> u8 {
        s.owner[e.min(s.epoch) as usize][scope as usize]
    }
    pub fn committed(&self, s: &State, n: u8, key: u8) -> Option<u8> {
        (0..self.cfg.b.slabs).find(|&i| {
            let b = &s.slab[n as usize][i as usize];
            b.st == St::Committed && b.key == key
        })
    }
    fn has_key(&self, s: &State, n: u8, key: u8) -> bool {
        (0..self.cfg.b.slabs).any(|i| {
            let b = &s.slab[n as usize][i as usize];
            matches!(b.st, St::Writing | St::Committed) && b.key == key
        })
    }
    pub fn sc(&self, s: &State, n: u8, scope: u8) -> Sc {
        s.scope[n as usize][scope as usize]
    }
    /// The extent of the client's current put still belongs to that put.
    fn still_mine(s: &State, c: u8) -> bool {
        let cl = &s.cl[c as usize];
        let b = &s.slab[cl.n as usize][cl.slab as usize];
        b.st == St::Writing && b.writer == c && b.gen == cl.gen
    }
    /// TLA+ MyExtent.
    fn my_extent(s: &State, c: u8) -> bool {
        let cl = &s.cl[c as usize];
        Self::still_mine(s, c) && s.slab[cl.n as usize][cl.slab as usize].wmr
    }
    /// The guards of TLA+ PutBegin other than "a free slab exists".
    fn put_begin_ok(&self, s: &State, c: u8, key: u8, n: u8) -> bool {
        let f = &self.cfg.f;
        let scope = self.scope_of(key);
        let ne = s.n_epoch[n as usize];
        // fault: a ReadOnly node is treated as Active
        let mode = if f.readonly_accepts_put && s.mode[n as usize] == Mode::ReadOnly {
            Mode::Active
        } else {
            s.mode[n as usize]
        };
        s.up[n as usize]
            && (f.no_open_check
                || self.sc(s, n, scope) == Sc::Open
                // implicit open: only the chain root opens an unknown scope
                || (self.pos_of(key) == 0 && self.sc(s, n, scope) == Sc::None))
            && ne == s.c_epoch[c as usize]
            && if self.pos_of(key) == 0 {
                // root: owner set, and the node must be Active (Draining and
                // ReadOnly refuse it)
                mode == Mode::Active
                    && (f.no_owner_check || self.owner_set_at(s, ne, scope) >> n & 1 == 1)
            } else {
                // continuation: only ReadOnly refuses
                mode != Mode::ReadOnly && self.committed(s, n, key - 1).is_some()
            }
            && (f.no_exists_check || !self.has_key(s, n, key))
            && s.ngen[n as usize] < self.cfg.b.max_gen
    }
    /// What the rogue may write: garbage, or ciphertext replayed from an
    /// older encryption instance (generation 0) of this key, of its sibling
    /// in the same scope, or of a key in another scope.  The TLA+ module
    /// allows every tag; these are one representative per case the
    /// validators and invariants can tell apart.
    fn rogue_values(&self, key: u8) -> Vec<Half> {
        let b = &self.cfg.b;
        let mut v = vec![Half::Garbage];
        if key != NOKEY {
            v.push(Half::Tag(key, 0));
            if b.max_pos > 1 {
                v.push(Half::Tag(if self.pos_of(key) > 0 { key - 1 } else { key + 1 }, 0));
            }
            if b.scopes > 1 {
                v.push(Half::Tag((key + b.max_pos) % b.keys(), 0));
            }
        }
        v
    }

    /// RL0: some slice WR of the client is neither completed nor flushed.
    fn outstanding(cl: &Client) -> bool {
        cl.live[0]
            || cl.live[1]
            || (cl.hs[0] == Hs::Re && !cl.got1)
            || (cl.hs[1] == Hs::Re && !cl.got2)
    }

    fn end_op(&self, s: &mut State, c: u8) {
        let cl = &mut s.cl[c as usize];
        cl.pc = Pc::Idle;
        cl.key = NOKEY;
        cl.n = NONE;
        cl.slab = NONE;
        cl.gen = 0;
        cl.d1 = Half::None;
        cl.d2 = Half::None;
        cl.got1 = false;
        cl.got2 = false;
        cl.sq = None;
        cl.sq_scope_known = false;
        cl.hs = [Hs::Ok; 2];
        cl.live = [false; 2];
    }

    /// TLA+ Unlink: remove a block from view.
    fn unlink(b: &mut Slab, doom: bool) {
        match b.st {
            St::Writing => {
                if doom {
                    b.doomed = true;
                }
            }
            St::Committed => {
                b.st = if b.lease == 0 { St::Free } else { St::Zombie };
            }
            _ => {}
        }
    }

    /// Canonicalise the state so that equivalent states are merged.
    fn normalize(&self, s: &mut State) {
        let b = &self.cfg.b;
        // A FREE slab's key and generation are never read again.  Its stale
        // bytes can be seen only by a client still reading that slab, or by a
        // commit that publishes halves the put never placed; the latter needs
        // PUT_COMMIT to overtake the data, so otherwise forget the bytes too.
        let stale_matters = !self.cfg.sw.commit_on_ingest_qp;
        for n in 0..b.nodes {
            for i in 0..b.slabs {
                let blk = &mut s.slab[n as usize][i as usize];
                if blk.st != St::Free {
                    continue;
                }
                blk.key = NOKEY;
                blk.gen = 0;
                if stale_matters {
                    continue;
                }
                let (mut r1, mut r2) = (false, false);
                for c in 0..b.clients as usize {
                    let cl = &s.cl[c];
                    if cl.pc == Pc::Rd && cl.n == n && cl.slab == i {
                        r1 |= !cl.got1;
                        r2 |= !cl.got2;
                    }
                }
                let blk = &mut s.slab[n as usize][i as usize];
                if !r1 {
                    blk.h1 = Half::None;
                }
                if !r2 {
                    blk.h2 = Half::None;
                }
            }
        }
        if b.symmetry {
            *s = crate::symmetry::canonical(self, s);
        }
    }

    // --- validation (spec 8.1 step 4) ---------------------------------------
    /// The client is at the validation step and would accept the block.
    pub fn would_accept(&self, s: &State, c: u8) -> bool {
        let cl = &s.cl[c as usize];
        if cl.pc != Pc::Val {
            return false;
        }
        // seq: the word read last is still (COMMITTED, leased generation).
        let seq_ok = match cl.sq {
            Some((St::Committed, g)) => g == cl.gen || self.cfg.f.seq_skip_gen,
            _ => false,
        };
        // aead: both halves are ONE encryption instance of the requested key.
        let aead_ok = matches!(cl.d1, Half::Tag(k, _) if self.same_key(k, cl.key)) && cl.d1 == cl.d2;
        (!self.cfg.sw.use_seq || seq_ok) && (!self.cfg.sw.use_aead || aead_ok)
    }

    fn accepting<'a>(&'a self, s: &'a State) -> impl Iterator<Item = &'a Client> + 'a {
        (0..self.cfg.b.clients)
            .filter(move |&c| self.would_accept(s, c))
            .map(move |c| &s.cl[c as usize])
    }

    /// Nothing can happen any more and no operation is left hanging.  On an
    /// acyclic state graph, "eventually quiescent_and_done" says that every
    /// fetch and every put that was started ends (hit, miss, deadline, done or
    /// aborted) on every maximal path.
    pub fn quiescent_and_done(&self, s: &State) -> bool {
        if (0..self.cfg.b.clients as usize).any(|c| s.cl[c].pc != Pc::Idle) {
            return false;
        }
        let mut acts = Vec::new();
        self.actions(s, &mut acts);
        acts.into_iter().all(|a| self.next_state(s, a).is_none())
    }
}

// ---------------------------------------------------------------------------
// Transition system

impl Model for Mira {
    type State = State;
    type Action = Action;

    fn init_states(&self) -> Vec<State> {
        let b = &self.cfg.b;
        let idle = Client {
            pc: Pc::Idle,
            ops_left: b.ops,
            key: NOKEY,
            n: NONE,
            slab: NONE,
            gen: 0,
            d1: Half::None,
            d2: Half::None,
            got1: false,
            got2: false,
            sq: None,
            sq_scope_known: false,
            hs: [Hs::Ok; 2],
            live: [false; 2],
        };
        let mut scope = [[Sc::None; MAXS]; MAXN];
        if b.preopen {
            for row in scope.iter_mut().take(b.nodes as usize) {
                for x in row.iter_mut().take(b.scopes as usize) {
                    *x = Sc::Open;
                }
            }
        }
        let legit = scope.map(|row| row.map(|x| x == Sc::Open));
        let base = State {
            epoch: 0,
            owner: [[0; MAXS]; MAXE],
            mode: [Mode::Active; MAXN],
            put_on_ro: false,
            n_epoch: [0; MAXN],
            c_epoch: [0; MAXC],
            up: [true; MAXN],
            scope,
            legit,
            ngen: [0; MAXN],
            slab: [[FREE_SLAB; MAXSLAB]; MAXN],
            cross_evicted: false,
            evicted_own: false,
            cl: [idle; MAXC],
            crashes_left: b.node_crashes,
            ccrashes_left: b.client_crashes,
            drops_left: b.drops,
            lapses_left: b.lapses,
            rogue_left: b.rogue_writes,
            invalidates_left: b.invalidates,
            rail_left: b.rail_faults,
            released_outstanding: false,
            events_left: b.events,
            modes_left: b.mode_changes,
        };
        // Every placement of the scopes at epoch 0, up to node symmetry: the
        // owner set of scope 0 is the first k nodes (nodes are interchangeable
        // in every action); the other scopes take any set of 1..=R nodes.
        let masks = self.masks();
        let mut out = Vec::new();
        let combos = masks.len().pow(b.scopes.saturating_sub(1) as u32);
        for k in 1..=b.replicas.min(b.nodes) {
            for mut x in 0..combos {
                let mut s = base.clone();
                s.owner[0][0] = ((1u16 << k) - 1) as u8;
                for scope in 1..b.scopes {
                    s.owner[0][scope as usize] = masks[x % masks.len()];
                    x /= masks.len();
                }
                self.normalize(&mut s);
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        out
    }

    fn actions(&self, s: &State, out: &mut Vec<Action>) {
        let b = &self.cfg.b;
        let sw = &self.cfg.sw;
        let f = &self.cfg.f;
        let ev = s.events_left > 0;

        // --- clients ---
        for c in 0..b.clients {
            let cl = &s.cl[c as usize];
            match cl.pc {
                Pc::Idle => {
                    if cl.ops_left > 0 {
                        for key in 0..b.keys() {
                            // a client names only scopes of its own principal
                            if self.prin_of(self.scope_of(key)) != self.cprin(c) {
                                continue;
                            }
                            for n in 0..b.nodes {
                                // A fetch is modelled when it hits (a miss
                                // changes nothing), or when the node is down
                                // and only the deadline can end it.
                                if !s.up[n as usize]
                                    || (self.lookup_open(s, n, self.scope_of(key))
                                        && self.committed_lookup(s, n, key).is_some())
                                {
                                    out.push(Action::GetLookup { c, key, n });
                                }
                                if f.lookup_opens_scope
                                    && s.up[n as usize]
                                    && self.sc(s, n, self.scope_of(key)) == Sc::None
                                {
                                    out.push(Action::LookupOpen { c, key, n });
                                }
                                // A put is modelled when PUT_BEGIN is accepted
                                // (SKIP and REFUSED change nothing).
                                if self.put_begin_ok(s, c, key, n) {
                                    for victim in self.victims(s, c, key, n) {
                                        for i in 0..b.slabs {
                                            if s.slab[n as usize][i as usize].st == St::Free {
                                                out.push(Action::PutBegin { c, key, n, slab: i, victim });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Pc::LookupWait => {}
                Pc::Rd => {
                    if !cl.got1 && matches!(cl.hs[0], Hs::Ok | Hs::Re) {
                        out.push(Action::GetRead1(c));
                    }
                    if !cl.got2 && matches!(cl.hs[1], Hs::Ok | Hs::Re) {
                        out.push(Action::GetRead2(c));
                    }
                    // Seq rule: the state_gen READ only after the CQEs of all
                    // slices, re-issued ones included (`got` is set by the
                    // slice that completes, original or re-issue).
                    let done = |h: usize| {
                        let pending_re = f.seq_before_reissue && cl.hs[h] == Hs::Re;
                        (if h == 0 { cl.got1 } else { cl.got2 }) || pending_re
                    };
                    if cl.sq.is_none() && ((done(0) && done(1)) || f.seq_early) {
                        out.push(Action::GetSeqRead(c));
                    }
                    for h in 0..2u8 {
                        let hu = h as usize;
                        let got = if h == 0 { cl.got1 } else { cl.got2 };
                        if s.rail_left > 0 && cl.hs[hu] == Hs::Ok && !got && !cl.live[hu] {
                            out.push(Action::RailFail { c, h });
                        }
                        // A slice is re-issued only after its own CQE; the
                        // tooth also re-issues while it is merely suspect.
                        if cl.hs[hu] == Hs::Flushed || (f.reissue_early && cl.hs[hu] == Hs::Susp) {
                            out.push(Action::GetReissue { c, h });
                        }
                    }
                }
                Pc::Val => {
                    if f.release_outstanding || !Self::outstanding(&cl) {
                        out.push(Action::GetValidate(c));
                    }
                }
                Pc::Drain => {
                    // No buffer release while a slice WR is neither completed nor flushed.
                    if f.release_outstanding || !Self::outstanding(&cl) {
                        out.push(Action::GetDrained(c));
                    }
                    // a re-issued slice still completes (its CQE) during the drain
                    if !cl.got1 && cl.hs[0] == Hs::Re {
                        out.push(Action::GetRead1(c));
                    }
                    if !cl.got2 && cl.hs[1] == Hs::Re {
                        out.push(Action::GetRead2(c));
                    }
                }
                Pc::Pw => out.push(Action::PutSendCommit(c)),
                Pc::PutWait => {
                    if !Self::still_mine(s, c) {
                        out.push(Action::ClientPutEnd(c));
                    }
                }
            }
            for h in 0..2u8 {
                if cl.live[h as usize] {
                    out.push(Action::OrigLand { c, h });
                    out.push(Action::RailFlush { c, h });
                }
            }
            if !f.no_deadline {
                if matches!(cl.pc, Pc::LookupWait | Pc::Rd | Pc::Val) {
                    out.push(Action::GetCancel(c));
                }
                if cl.pc.is_put() {
                    out.push(Action::PutAbandon(c));
                }
            }
            if s.ccrashes_left > 0 && ev && cl.pc != Pc::Idle {
                out.push(Action::ClientCrash(c));
            }
        }

        // --- memory nodes, fabric, rogue writer, scope provider ---
        for n in 0..b.nodes {
            let nu = n as usize;
            if !s.up[nu] {
                out.push(Action::Restart(n));
                continue;
            }
            for i in 0..b.slabs {
                let blk = &s.slab[nu][i as usize];
                if blk.wmr && blk.pend1 {
                    out.push(Action::Place1 { n, i });
                }
                if blk.wmr && blk.pend2 {
                    out.push(Action::Place2 { n, i });
                }
                match blk.st {
                    St::Writing => {
                        if (blk.cflight && (!sw.commit_on_ingest_qp || (!blk.pend1 && !blk.pend2)))
                            || (f.put_id_reuse && blk.stale)
                        {
                            out.push(Action::PutCommit { n, i });
                        }
                        out.push(Action::PutAbort { n, i });
                    }
                    St::Committed => {
                        let has_child =
                            self.child(blk.key).is_some_and(|ch| self.has_key(s, n, ch));
                        if (blk.lease == 0 || f.evict_leased) && (!has_child || f.no_tail_first) {
                            out.push(Action::Evict { n, i });
                        }
                        if self.sc(s, n, self.scope_of(blk.key)) == Sc::Open
                            && s.invalidates_left > 0
                            && ev
                        {
                            out.push(Action::Invalidate { n, i });
                        }
                    }
                    St::Zombie => {
                        if blk.lease == 0 {
                            out.push(Action::ZombieReap { n, i });
                        }
                    }
                    St::Free => {}
                }
                if sw.leases_expire && blk.lease != 0 {
                    for c in 0..b.clients {
                        if blk.lease & (1 << c) != 0 {
                            out.push(Action::LeaseExpire { n, i, c });
                        }
                    }
                }
                if sw.rogue != Rogue::None && s.rogue_left > 0 && ev && blk.wmr {
                    for first in [true, false] {
                        let cur = if first { blk.h1 } else { blk.h2 };
                        for val in self.rogue_values(blk.key) {
                            if val != cur {
                                out.push(Action::RogueWrite { n, i, first, val });
                            }
                        }
                    }
                }
            }
            for scope in 0..b.scopes {
                // Scopes open only implicitly (PutBegin); no controller.
                let st = self.sc(s, n, scope);
                if st == Sc::Open && s.lapses_left > 0 && ev {
                    out.push(Action::ExpireScope { n, s: scope });
                }
                if st != Sc::None && s.drops_left > 0 && ev {
                    out.push(Action::DropScope { n, s: scope });
                }
            }
            if s.crashes_left > 0 && ev {
                out.push(Action::Crash { n, warm: true });
                out.push(Action::Crash { n, warm: false });
            }
        }

        // --- membership controller: member states ---
        if s.modes_left > 0 && ev {
            for n in 0..b.nodes {
                for mode in [Mode::Active, Mode::Draining, Mode::ReadOnly] {
                    if mode != s.mode[n as usize] {
                        out.push(Action::SetMode { n, mode });
                    }
                }
            }
        }

        // --- membership controller ---
        if s.epoch < b.max_epoch && ev {
            let masks = self.masks();
            let combos = masks.len().pow(b.scopes as u32);
            for mut x in 0..combos {
                let mut owners = [0u8; MAXS];
                for o in owners.iter_mut().take(b.scopes as usize) {
                    *o = masks[x % masks.len()];
                    x /= masks.len();
                }
                out.push(Action::EpochChange { owners });
            }
        }
    }

    fn next_state(&self, last: &State, action: Action) -> Option<State> {
        let b = &self.cfg.b;
        let f = &self.cfg.f;
        let sw = &self.cfg.sw;
        let mut s = last.clone();
        match action {
            // ----------------------------------------------------------- scopes
            Action::ExpireScope { n, s: scope } => {
                s.lapses_left -= 1;
                s.events_left -= 1;
                self.remove_scope(&mut s, n, scope, false);
            }
            Action::DropScope { n, s: scope } => {
                s.drops_left -= 1;
                s.events_left -= 1;
                self.remove_scope(&mut s, n, scope, f.drop_no_state);
            }
            Action::LookupOpen { c, key, n } => {
                s.cl[c as usize].ops_left -= 1;
                s.scope[n as usize][self.scope_of(key) as usize] = Sc::Open;
            }

            // -------------------------------------------------------------- put
            Action::PutBegin { c, key, n, slab, victim } => {
                if s.mode[n as usize] == Mode::ReadOnly {
                    s.put_on_ro = true;
                }
                if victim != NONE {
                    if self.prin_of(victim) == self.cprin(c) {
                        s.evicted_own = true;
                    } else {
                        s.cross_evicted = true;
                    }
                    self.remove_scope(&mut s, n, victim, false);
                }
                let scope = self.scope_of(key) as usize;
                if s.scope[n as usize][scope] == Sc::None && !f.no_open_check {
                    // implicit open by the root PUT_BEGIN
                    s.scope[n as usize][scope] = Sc::Open;
                    s.legit[n as usize][scope] = true;
                }
                // a per-slot counter restarts at 1 in the model's bounds
                let gen = if f.slot_local_gen { 1 } else { s.ngen[n as usize] + 1 };
                s.ngen[n as usize] += 1;
                let blk = &mut s.slab[n as usize][slab as usize];
                // state word first: (WRITING, fresh generation); then the MR
                blk.st = St::Writing;
                blk.key = key;
                blk.gen = gen;
                blk.writer = c;
                blk.wmr = true;
                blk.pend1 = true;
                blk.pend2 = true;
                blk.cflight = false;
                blk.doomed = false;
                let cl = &mut s.cl[c as usize];
                cl.ops_left -= 1;
                cl.pc = Pc::Pw;
                cl.key = key;
                cl.n = n;
                cl.slab = slab;
                cl.gen = gen;
            }
            Action::Place1 { n, i } => {
                let blk = &mut s.slab[n as usize][i as usize];
                blk.h1 = Half::Tag(blk.key, blk.gen);
                blk.pend1 = false;
            }
            Action::Place2 { n, i } => {
                let blk = &mut s.slab[n as usize][i as usize];
                blk.h2 = Half::Tag(blk.key, blk.gen);
                blk.pend2 = false;
            }
            Action::PutSendCommit(c) => {
                if Self::my_extent(&s, c) {
                    let cl = s.cl[c as usize];
                    s.slab[cl.n as usize][cl.slab as usize].cflight = true;
                    s.cl[c as usize].pc = Pc::PutWait;
                } else {
                    // the put was already aborted: the client learns that
                    self.end_op(&mut s, c);
                }
            }
            Action::PutCommit { n, i } => {
                let blk = &mut s.slab[n as usize][i as usize];
                blk.stale = false;
                let digest_ok = !sw.digest_at_commit || sw.rogue == Rogue::Forging || intact(blk);
                if !blk.doomed && digest_ok {
                    if sw.fence_at_commit {
                        clear(blk);
                    } else {
                        blk.writer = NONE;
                        blk.cflight = false;
                    }
                    blk.st = St::Committed;
                } else {
                    clear(blk);
                    blk.st = St::Free;
                }
            }
            Action::PutAbort { n, i } => {
                let blk = &mut s.slab[n as usize][i as usize];
                let in_flight = blk.cflight;
                clear(blk);
                blk.stale = f.put_id_reuse && in_flight;
                blk.st = St::Free;
            }
            Action::ClientPutEnd(c) | Action::PutAbandon(c) => self.end_op(&mut s, c),
            Action::RogueWrite { n, i, first, val } => {
                s.rogue_left -= 1;
                s.events_left -= 1;
                let blk = &mut s.slab[n as usize][i as usize];
                if first {
                    blk.h1 = val;
                } else {
                    blk.h2 = val;
                }
            }
            Action::Invalidate { n, i } => {
                s.invalidates_left -= 1;
                s.events_left -= 1;
                let root = s.slab[n as usize][i as usize].key;
                for j in 0..b.slabs as usize {
                    let blk = &mut s.slab[n as usize][j];
                    let in_subtree = matches!(blk.st, St::Writing | St::Committed)
                        && self.scope_of(blk.key) == self.scope_of(root)
                        && blk.key >= root;
                    if in_subtree && (blk.key == root || !f.invalidate_no_subtree) {
                        Self::unlink(blk, true);
                    }
                }
            }

            // -------------------------------------------------------------- get
            Action::GetLookup { c, key, n } => {
                let cl = &mut s.cl[c as usize];
                cl.ops_left -= 1;
                cl.key = key;
                cl.n = n;
                if !s.up[n as usize] {
                    cl.pc = Pc::LookupWait;
                } else {
                    let i = self.committed_lookup(last, n, key).unwrap();
                    let blk = &mut s.slab[n as usize][i as usize];
                    if !f.no_lease {
                        blk.lease |= 1 << c;
                    }
                    cl.pc = Pc::Rd;
                    cl.slab = i;
                    cl.gen = blk.gen;
                }
            }
            Action::GetRead1(c) => {
                let cl = s.cl[c as usize];
                s.cl[c as usize].d1 = s.slab[cl.n as usize][cl.slab as usize].h1;
                s.cl[c as usize].got1 = true;
                s.cl[c as usize].hs[0] = Hs::Ok;
            }
            Action::GetRead2(c) => {
                let cl = s.cl[c as usize];
                s.cl[c as usize].d2 = s.slab[cl.n as usize][cl.slab as usize].h2;
                s.cl[c as usize].got2 = true;
                s.cl[c as usize].hs[1] = Hs::Ok;
            }
            Action::RailFail { c, h } => {
                s.rail_left -= 1;
                let cl = &mut s.cl[c as usize];
                cl.hs[h as usize] = Hs::Susp;
                cl.live[h as usize] = true;
            }
            Action::RailFlush { c, h } => {
                // ERR the rail's QPs, wait for the flush: the WR can no longer land
                let cl = &mut s.cl[c as usize];
                cl.live[h as usize] = false;
                if cl.hs[h as usize] == Hs::Susp {
                    cl.hs[h as usize] = Hs::Flushed;
                }
            }
            Action::OrigLand { c, h } => {
                // the original READ executes now, reading the block as it is now
                let cl = s.cl[c as usize];
                let blk = s.slab[cl.n as usize][cl.slab as usize];
                let cl = &mut s.cl[c as usize];
                cl.live[h as usize] = false;
                if h == 0 {
                    cl.d1 = blk.h1;
                } else {
                    cl.d2 = blk.h2;
                }
                if cl.hs[h as usize] == Hs::Susp {
                    // completed successfully after all
                    cl.hs[h as usize] = Hs::Ok;
                    if h == 0 {
                        cl.got1 = true;
                    } else {
                        cl.got2 = true;
                    }
                }
            }
            Action::GetReissue { c, h } => {
                s.cl[c as usize].hs[h as usize] = Hs::Re;
            }
            Action::GetSeqRead(c) => {
                let cl = s.cl[c as usize];
                let blk = s.slab[cl.n as usize][cl.slab as usize];
                let known = self.sc(&s, cl.n, self.scope_of(cl.key)) != Sc::None;
                s.cl[c as usize].sq = Some((blk.st, blk.gen));
                s.cl[c as usize].sq_scope_known = known;
            }
            Action::GetValidate(c) | Action::GetDrained(c) => {
                // accept or reject (a state predicate, see would_accept),
                // then RELEASE
                let cl = s.cl[c as usize];
                if Self::outstanding(&cl) {
                    s.released_outstanding = true;
                }
                if !f.no_release {
                    s.slab[cl.n as usize][cl.slab as usize].lease &= !(1 << c);
                }
                self.end_op(&mut s, c);
            }
            Action::GetCancel(c) => {
                if s.cl[c as usize].pc == Pc::LookupWait {
                    self.end_op(&mut s, c);
                } else {
                    s.cl[c as usize].pc = Pc::Drain;
                }
            }
            Action::LeaseExpire { n, i, c } => s.slab[n as usize][i as usize].lease &= !(1 << c),

            // --------------------------------------------------------- eviction
            Action::Evict { n, i } | Action::ZombieReap { n, i } => {
                s.slab[n as usize][i as usize].st = St::Free;
            }

            // --------------------------------------------------------- failures
            Action::Crash { n, warm } => {
                s.crashes_left -= 1;
                s.events_left -= 1;
                s.up[n as usize] = false;
                for i in 0..b.slabs as usize {
                    let blk = &mut s.slab[n as usize][i];
                    blk.lease = 0;
                    clear(blk);
                    if !(warm && blk.st == St::Committed) {
                        blk.st = St::Free;
                    }
                }
                // the scope table is persisted: a warm restart resumes implicit
                // scopes OPEN; a cold one loses them
                if !warm {
                    for scope in 0..b.scopes as usize {
                        s.scope[n as usize][scope] = Sc::None;
                        s.legit[n as usize][scope] = false;
                    }
                }
                // every QP to the node flushes
                for c in 0..b.clients {
                    if s.cl[c as usize].pc != Pc::Idle && s.cl[c as usize].n == n {
                        self.end_op(&mut s, c);
                    }
                }
            }
            Action::Restart(n) => {
                s.up[n as usize] = true;
                s.n_epoch[n as usize] = s.epoch;
            }
            Action::ClientCrash(c) => {
                // Spec 8.6: every QP of the client flushes.  The server
                // releases its leases and fences and frees its puts at once.
                s.ccrashes_left -= 1;
                s.events_left -= 1;
                for n in 0..b.nodes as usize {
                    for i in 0..b.slabs as usize {
                        let blk = &mut s.slab[n][i];
                        blk.lease &= !(1 << c);
                        if blk.st == St::Writing && blk.writer == c {
                            clear(blk);
                            blk.st = St::Free;
                        }
                    }
                }
                self.end_op(&mut s, c);
            }

            // ------------------------------------------------------- membership
            Action::SetMode { n, mode } => {
                s.modes_left -= 1;
                s.events_left -= 1;
                s.mode[n as usize] = mode;
            }
            Action::EpochChange { owners } => {
                s.epoch += 1;
                s.events_left -= 1;
                s.owner[s.epoch as usize] = owners;
                // TLA+ NodeLearn and ClientLearn are taken at once with the
                // epoch change (a node that is down learns at restart).  A
                // stale epoch only ever disables PutBegin (its guard is
                // nEpoch = cEpoch); it enables nothing, so no reachable slab
                // or fetch configuration is lost.  See README.
                for c in 0..b.clients as usize {
                    s.c_epoch[c] = s.epoch;
                }
                for n in 0..b.nodes as usize {
                    if s.up[n] {
                        s.n_epoch[n] = s.epoch + u8::from(f.epoch_overshoot);
                    }
                }
            }
        }
        // The fetch moves on to validation once all three READs completed.
        for c in 0..b.clients as usize {
            let cl = &mut s.cl[c];
            if cl.pc == Pc::Rd && cl.got1 && cl.got2 && cl.sq.is_some() {
                cl.pc = Pc::Val;
            }
        }
        self.normalize(&mut s);
        if s == *last {
            return None;
        }
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mut props = vec![
            Property::always("TypeOK", type_ok),
            Property::always("NoForeignScopeRead", no_foreign_scope_read),
            Property::always("NoTornRead", no_torn_read),
            Property::always("NoWrongKeyRead", no_wrong_key_read),
            Property::always("NoStaleGenerationRead", no_stale_generation_read),
            Property::always("NoOrphanTail", no_orphan_tail),
            Property::always("LeaseSafety", lease_safety),
            Property::always("LeaseCoversReader", lease_covers_reader),
            Property::always("CommittedIntact", committed_intact),
            Property::always("WriteMrFenced", write_mr_fenced),
            Property::always("DenyByDefault", deny_by_default),
            Property::always("NoCrossPrincipalRead", no_cross_principal_read),
            Property::always("CapEvictsOwnOnly", cap_evicts_own_only),
            Property::always("NoLeaseLeak", no_lease_leak),
            Property::always("UniqueKey", unique_key),
            Property::always("GenerationsUnique", generations_unique),
            Property::always("EpochsBounded", epochs_bounded),
            // beyond the TLA+ module
            Property::always("DropScopeEffective", drop_scope_effective),
            Property::always("RootPutAtReplica", root_put_at_replica),
            Property::always("NoPutOnReadOnly", |_: &Mira, s: &State| !s.put_on_ro),
            Property::always("NoReleaseWithOutstanding", |_: &Mira, s: &State| !s.released_outstanding),
            Property::eventually("OpsTerminate", |m: &Mira, s: &State| m.quiescent_and_done(s)),
            // reachability witnesses: the model is not vacuous
            Property::sometimes("can: fetch accepted", |m: &Mira, s: &State| {
                m.accepting(s).next().is_some()
            }),
            Property::sometimes("can: validation rejects", |m: &Mira, s: &State| {
                (0..m.cfg.b.clients).any(|c| s.cl[c as usize].pc == Pc::Val && !m.would_accept(s, c))
            }),
            Property::sometimes("can: slab reused", |m: &Mira, s: &State| {
                slabs(m, s).any(|(_, b)| b.st == St::Committed && b.gen >= 2)
            }),
            Property::sometimes("can: zombie", |m: &Mira, s: &State| {
                slabs(m, s).any(|(_, b)| b.st == St::Zombie)
            }),
            Property::sometimes("can: doomed put", |m: &Mira, s: &State| {
                slabs(m, s).any(|(_, b)| b.st == St::Writing && b.doomed)
            }),
        ];
        if self.cfg.b.rail_faults > 0 {
            props.push(Property::sometimes("can: slice re-issued after its flush", |_: &Mira, s: &State| {
                s.cl.iter().any(|cl| cl.hs.contains(&Hs::Re))
            }));
        }
        if self.cfg.b.max_epoch > 0 {
            props.push(Property::sometimes(
                "can: hit on a node that is not in the current owner set",
                |m: &Mira, s: &State| {
                    (0..m.cfg.b.clients as usize).any(|c| {
                        let cl = &s.cl[c];
                        cl.pc == Pc::Rd
                            && s.owner[s.epoch as usize][m.scope_of(cl.key) as usize] >> cl.n & 1 == 0
                    })
                },
            ));
        }
        if self.cfg.b.slabs >= 2 && self.cfg.b.max_pos >= 2 {
            // a chain needs two blocks on one node, so two slabs and a continuation position
            props.push(Property::sometimes("can: chain of two committed", |m: &Mira, s: &State| {
                (0..m.cfg.b.nodes).any(|n| {
                    (0..m.cfg.b.keys()).any(|k| {
                        m.pos_of(k) > 0
                            && m.committed(s, n, k).is_some()
                            && m.committed(s, n, k - 1).is_some()
                    })
                })
            }));
        }
        if self.cfg.b.scopes >= 2 {
            // these two witnesses need two scope entries (one scope: no cap, no sharing)
            props.push(Property::sometimes("can: two principals hold the same scope_id", |m: &Mira, s: &State| {
                (0..m.cfg.b.nodes).any(|n| {
                    (0..m.cfg.b.scopes).any(|x| {
                        (0..x).any(|y| {
                            m.sid_of(x) == m.sid_of(y)
                                && m.sc(s, n, x) == Sc::Open
                                && m.sc(s, n, y) == Sc::Open
                        })
                    })
                })
            }));
            props.push(Property::sometimes("can: cap evicts the principal's own scope", |_, s: &State| {
                s.evicted_own
            }));
        }
        if self.cfg.b.mode_changes > 0 {
            props.push(Property::sometimes("can: a node is read-only", |m: &Mira, s: &State| {
                (0..m.cfg.b.nodes as usize).any(|n| s.mode[n] == Mode::ReadOnly)
            }));
            if self.cfg.b.slabs >= 2 && self.cfg.b.max_pos >= 2 {
            props.push(Property::sometimes(
                "can: continuation accepted on a draining node",
                |m: &Mira, s: &State| {
                    slabs(m, s).any(|(n, b)| {
                        s.mode[n as usize] == Mode::Draining
                            && b.st == St::Writing
                            && m.pos_of(b.key) > 0
                    })
                },
            ));
            }
        }
        props
    }
}

// ---------------------------------------------------------------------------
// Properties.  Names and meaning follow the TLA+ module.  The TLA+ `accepted`
// history set is replaced by the equivalent state predicate "a client is at
// the validation step and would accept": every accept transition starts in
// such a state, and in every such state the accept transition is enabled.

fn slabs<'a>(m: &'a Mira, s: &'a State) -> impl Iterator<Item = (u8, &'a Slab)> + 'a {
    (0..m.cfg.b.nodes)
        .flat_map(move |n| (0..m.cfg.b.slabs).map(move |i| (n, &s.slab[n as usize][i as usize])))
}

/// Structural well-formedness (the Rust types carry the rest of TLA+ TypeOK).
fn type_ok(m: &Mira, s: &State) -> bool {
    let b = &m.cfg.b;
    s.epoch <= b.max_epoch
        && (0..b.nodes as usize).all(|n| s.ngen[n] <= b.max_gen)
        && slabs(m, s).all(|(_, x)| {
            x.gen <= b.max_gen
                && ((x.writer != NONE) == (x.st == St::Writing))
                && (x.st == St::Writing || (!x.cflight && !x.doomed))
                && ((x.st == St::Free) == (x.key == NOKEY))
                && (x.key == NOKEY || x.key < b.keys())
        })
        && (0..b.clients as usize).all(|c| {
            let cl = &s.cl[c];
            (cl.pc == Pc::Idle) == (cl.key == NOKEY)
                && (cl.pc == Pc::Idle || cl.n < b.nodes)
                && (cl.pc == Pc::Idle || cl.pc == Pc::LookupWait || cl.slab < b.slabs)
        })
}

/// A client never accepts bytes that belong to another scope.
fn no_foreign_scope_read(m: &Mira, s: &State) -> bool {
    m.accepting(s).all(|cl| {
        let ok = |h: Half| matches!(h, Half::Tag(k, _) if m.scope_of(k) == m.scope_of(cl.key));
        ok(cl.d1) && ok(cl.d2)
    })
}

/// A client never accepts a half-written or mixed block.
fn no_torn_read(m: &Mira, s: &State) -> bool {
    m.accepting(s).all(|cl| matches!(cl.d1, Half::Tag(..)) && cl.d1 == cl.d2)
}

/// Accepted bytes are always the requested key.
fn no_wrong_key_read(m: &Mira, s: &State) -> bool {
    m.accepting(s).all(|cl| {
        let ok = |h: Half| matches!(h, Half::Tag(k, _) if k == cl.key);
        ok(cl.d1) && ok(cl.d2)
    })
}

/// Accepted bytes are exactly the leased put.
fn no_stale_generation_read(m: &Mira, s: &State) -> bool {
    m.accepting(s).all(|cl| cl.d1 == Half::Tag(cl.key, cl.gen) && cl.d2 == cl.d1)
}

/// A visible or pending chain block always has its prefix on the same node.
/// (Zombie, free and doomed blocks are unreachable.)
fn no_orphan_tail(m: &Mira, s: &State) -> bool {
    slabs(m, s).all(|(n, b)| {
        !(matches!(b.st, St::Writing | St::Committed) && !b.doomed && m.pos_of(b.key) > 0)
            || m.committed(s, n, b.key - 1).is_some()
    })
}

/// While any lease is held the slab is neither freed nor reused.
fn lease_safety(m: &Mira, s: &State) -> bool {
    slabs(m, s).all(|(_, b)| b.lease == 0 || matches!(b.st, St::Committed | St::Zombie))
}

/// Without lease expiry, a reading client still holds its lease on an
/// unchanged generation.  Not applicable (trivially true) when leases expire.
fn lease_covers_reader(m: &Mira, s: &State) -> bool {
    if m.cfg.sw.leases_expire {
        return true;
    }
    (0..m.cfg.b.clients).all(|c| {
        let cl = &s.cl[c as usize];
        if !cl.pc.is_reading() {
            return true;
        }
        let b = &s.slab[cl.n as usize][cl.slab as usize];
        b.lease & (1 << c) != 0 && b.gen == cl.gen
    })
}

/// A committed (or zombie) block holds exactly one complete encryption
/// instance of its key.
fn committed_intact(m: &Mira, s: &State) -> bool {
    slabs(m, s).all(|(_, b)| !matches!(b.st, St::Committed | St::Zombie) || intact(b))
}

/// A write MR exists only while its extent is being written.
fn write_mr_fenced(m: &Mira, s: &State) -> bool {
    slabs(m, s).all(|(_, b)| !b.wmr || b.st == St::Writing)
}

/// Deny by default: (a) a put that can still commit belongs to an open scope;
/// (b) a visible block belongs to a scope the node knows; (c) every open scope
/// was created by a root PUT_BEGIN (LOOKUP never opens one); (d) a reading
/// client is reading (its slab not yet reused) a block of its own principal.
fn deny_by_default(m: &Mira, s: &State) -> bool {
    let b = &m.cfg.b;
    slabs(m, s).all(|(n, b)| match b.st {
        St::Writing => b.doomed || m.sc(s, n, m.scope_of(b.key)) == Sc::Open,
        St::Committed => m.sc(s, n, m.scope_of(b.key)) != Sc::None,
        _ => true,
    }) && (0..b.nodes).all(|n| {
        (0..b.scopes).all(|x| m.sc(s, n, x) != Sc::Open || s.legit[n as usize][x as usize])
    }) && (0..b.clients).all(|c| {
        let cl = &s.cl[c as usize];
        !cl.pc.is_reading() || {
            let blk = &s.slab[cl.n as usize][cl.slab as usize];
            blk.gen != cl.gen || blk.key == NOKEY || m.prin_of(m.scope_of(blk.key)) == m.cprin(c)
        }
    })
}

/// A principal never reads bytes stored under another principal's scope
/// entry, even when the scope_id bytes are the same.
fn no_cross_principal_read(m: &Mira, s: &State) -> bool {
    (0..m.cfg.b.clients).all(|c| {
        if !m.would_accept(s, c) {
            return true;
        }
        let cl = &s.cl[c as usize];
        let ok = |h: Half| matches!(h, Half::Tag(k, _) if m.prin_of(m.scope_of(k)) == m.cprin(c));
        ok(cl.d1) && ok(cl.d2)
    })
}

/// At the cap the node evicts only the opening principal's own scopes, and
/// no principal holds more open scopes than max_scopes.
fn cap_evicts_own_only(m: &Mira, s: &State) -> bool {
    let b = &m.cfg.b;
    !s.cross_evicted
        && (0..b.nodes).all(|n| {
            (0..b.principals).all(|p| {
                (0..b.scopes).filter(|&x| m.prin_of(x) == p && m.sc(s, n, x) != Sc::None).count()
                    <= b.max_scopes as usize
            })
        })
}

/// An idle client holds no lease anywhere.
fn no_lease_leak(m: &Mira, s: &State) -> bool {
    (0..m.cfg.b.clients).all(|c| {
        s.cl[c as usize].pc != Pc::Idle || slabs(m, s).all(|(_, b)| b.lease & (1 << c) == 0)
    })
}

/// At most one visible or pending block per key per node.
fn unique_key(m: &Mira, s: &State) -> bool {
    let b = &m.cfg.b;
    (0..b.nodes as usize).all(|n| {
        (0..b.slabs as usize).all(|i| {
            (0..i).all(|j| {
                let (x, y) = (&s.slab[n][i], &s.slab[n][j]);
                !(matches!(x.st, St::Writing | St::Committed)
                    && matches!(y.st, St::Writing | St::Committed)
                    && x.key == y.key)
            })
        })
    })
}

/// Node-global generations: no two slots of a node carry the same non-zero
/// generation, and none exceeds the node's counter.
fn generations_unique(m: &Mira, s: &State) -> bool {
    let b = &m.cfg.b;
    (0..b.nodes as usize).all(|n| {
        (0..b.slabs as usize).all(|i| {
            s.slab[n][i].gen <= s.ngen[n]
                && (0..i).all(|j| s.slab[n][i].gen != s.slab[n][j].gen || s.slab[n][i].gen == 0)
        })
    })
}

fn epochs_bounded(m: &Mira, s: &State) -> bool {
    let b = &m.cfg.b;
    (0..b.nodes as usize).all(|n| s.n_epoch[n] <= s.epoch)
        && (0..b.clients as usize).all(|c| s.c_epoch[c] <= s.epoch)
}

/// After a scope is dropped no fetch of it succeeds: a fetch is never
/// accepted if, when it read the state_gen word, the node had already
/// forgotten the scope.
fn drop_scope_effective(m: &Mira, s: &State) -> bool {
    m.accepting(s).all(|cl| cl.sq_scope_known)
}

/// Spec 7.3: a root block is only ever accepted by a node that owned the scope
/// in some epoch the node has seen.
fn root_put_at_replica(m: &Mira, s: &State) -> bool {
    slabs(m, s).all(|(n, b)| {
        if !matches!(b.st, St::Writing | St::Committed) || m.pos_of(b.key) != 0 {
            return true;
        }
        let top = s.n_epoch[n as usize].min(s.epoch);
        (0..=top).any(|e| s.owner[e as usize][m.scope_of(b.key) as usize] >> n & 1 == 1)
    })
}
