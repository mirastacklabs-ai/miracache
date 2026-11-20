# miracache wire protocol and storage formats

This page describes the formats a compatible client must speak: the admin ticket call, the RDMA connection
handshake, the framed control messages, the encrypted block format, key derivation and placement. It is a guide to
the formats, not a byte-level standard: the **exact bytes are pinned by the golden vectors in
[`proto/golden/`](../proto/golden/)**, and the C++ definitions with their `static_assert`s live in
[`core/proto/`](../core/proto/). Where this page and the golden vectors disagree, the golden vectors win.

Versions described here: **wire v0** (frame `ver_major = 0`), **crypto v1** (extent `crypto version = 1`),
**storage layout v0**, **placement v1**, **bundle v1**. These formats are frozen for the alpha; a change needs a design
discussion in an issue first (see `CONTRIBUTING.md`).

For the why behind each step, see [architecture.md](architecture.md); for the threat model, [security.md](security.md).

## 1. Conventions

- All integers are **little-endian**, with one exception: the 32-bit segment counter inside the AES-GCM nonce
  (section 7.4) is big-endian.
- Fields marked `z` are reserved: they must be zero on the wire and are **rejected** otherwise.
- Hashes are SHA-256; HKDF is HKDF-SHA256 with a 32-byte output; HMAC is HMAC-SHA256. `‖` is concatenation.
- Every fixed body size is a multiple of 8 bytes.

## 2. Transport

- Connections: `rdma_cm`, RC queue pairs. Operations: SEND/RECV, RDMA READ, RDMA WRITE. Nothing else: no UD, XRC,
  atomics, on-demand paging, WRITE_WITH_IMM, shared receive queues or memory windows.
- RoCEv2 and iWARP are both supported; a rail pair must use the same protocol.
- Per (client, memory node, rail), the client opens three classes of connection: **control** (class 0, one),
  **fetch** (class 1, a count per rail set by the NIC profile) and **ingest** (class 2, one). All connections are opened by the client.
- The client always sends the first message on every connection (HELLO), as iWARP requires.
- There is no TCP transport and no fallback.

## 3. Tickets: the admin call before connecting

A memory node accepts an RDMA connection only with a live ticket. The client gets tickets from the node's admin API:
HTTP/1.1 over **TLS 1.3 only, with a mandatory client certificate** (mutual TLS). The client's identity is the single
`spiffe://` URI SAN of its certificate, and the node maps it to a principal.

```
POST /v1/tickets
{"classes":["control","fetch","ingest"],"rail":0,"count":4}        (or "class":"fetch"; count 1..64 per class)

200 {"ttl_s":300,"tickets":[{"class":"fetch","rail":0,"id":"<32 hex>"}, ...],"node_id":N,"hostname":"h"}
```

Errors: 400 malformed or unknown field, 403 identity not in the principal table, 413 body over 8 KiB, 429 ticket cap
reached, 503 node draining. Request bodies are parsed strictly (unknown or duplicate fields are errors); clients must
ignore unknown fields in the response.

Each ticket ID is 128 random bits, **single use** (consumed by the first connect that presents it), bound on the node
to {client identity, principal, class, rail, expiry}. Default lifetime 300 s.

### 3.1 Connection private data

The ticket travels in the `rdma_cm` connect request's private data, behind a 5-byte header:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | private-data version, `0x81` |
| 1 | 1 | ticket length (20) |
| 2 | 1 | protocol: 1 RoCE, 2 iWARP |
| 3 | 1 | IRD the sender offers |
| 4 | 1 | ORD the sender offers |
| 5 | 20 | ticket (below) |

The accept reply carries the same 5-byte header with length 0. Both sides take
`ird = min(own IRD, peer ORD)` and `ord = min(own ORD, peer IRD)` from these announced values.

Ticket, 20 bytes (golden: `ticket_v0.hex`):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | ticket version, 0 |
| 1 | 1 | class: 0 control, 1 fetch, 2 ingest |
| 2 | 2 | z |
| 4 | 16 | ticket ID |

### 3.2 Reject reasons

A refused connect carries one byte of reject private data:

| Byte | Meaning | Client action |
|---|---|---|
| 0 | none (also what a host with no memory node listening returns) | treat as link down; back off |
| 1 | RoCE/iWARP mismatch | configuration error |
| 2 | ticket refused | try the next ticket |
| 3 | bad private data | protocol error |
| 4 | out of resources (accept slots, CQ budget, per-principal connection cap) | back off |
| 5 | private-data version not understood | protocol error |
| 6 | busy: node draining; the ticket was **not** consumed | back off |

## 4. Framing

Every control message is one SEND of at most **8192 bytes** (one receive buffer): a 32-byte header, a fixed body per
message type, then optional TLV extensions. Frames have no checksum of their own; the RDMA transport's ICRC (RoCE) or
MPA CRC (iWARP) covers them. Golden: `frame_header_v0.hex`.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `0x4D52414D` (bytes `4d 41 52 4d`) |
| 4 | 1 | `ver_major` (0) |
| 5 | 1 | `ver_minor` (0) |
| 6 | 2 | message type |
| 8 | 2 | flags: `1` RESPONSE, `2` ERROR, `4` MORE, `8` CRITICAL_EXT |
| 10 | 2 | send credits granted to the peer |
| 12 | 4 | body length (at most 8160) |
| 16 | 8 | request ID (per connection; a response echoes it) |
| 24 | 4 | sender's membership epoch |
| 28 | 4 | sender's bundle generation (low 32 bits) |

The epoch and generation on every frame let a peer learn of a newer membership or bundle with no extra traffic.

Credits: a sender never has more SENDs outstanding than the peer has granted, so receiver-not-ready errors cannot
happen by design.

**TLV extensions** follow the fixed body: `u16 tag, u16 len, value`, each padded to 8 bytes with zero bytes. An unknown
tag is skipped, unless bit 15 of the tag is set (critical): then the frame is rejected with UNSUPPORTED.

| Tag | Where | Value |
|---|---|---|
| `0x0001` | any control frame | a lease ID to release (piggybacked RELEASE) |
| `0x0002` | HELLO_ACK | boot nonce, u64: drawn once per memory-node process |
| `0x0003` | HELLO_ACK | largest stored block this node accepts, u64 bytes (its `store.run_bytes`) |
| `0x0004` | HELLO_ACK | the node's hostname, 1..255 printable ASCII bytes (`0x21..0x7e`) |

All four are non-critical. An absent, empty or malformed value means "unknown", so older peers keep working. A client
that sees a different boot nonce on a reconnecting rail knows the node restarted: it discards that session's segment
table and reconnects every rail to the new process.

**Error reply** (any request type, ERROR flag set), 8 bytes: `status u16, z u16, retry_after_ms u32`
(golden: `error_reply_v0.hex`). Status: 1 UNSUPPORTED, 2 MALFORMED, 3 STALE_EPOCH, 4 DRAINING, 5 BUSY. A frame with bad
magic or impossible lengths closes the connection.

## 5. Messages

| Type | Name | Connection, direction | Fixed body | Golden |
|---|---|---|---|---|
| `0x01` | HELLO | every connection, c→s | 48 B | `hello_v0.hex` |
| `0x02` | HELLO_ACK | every connection, s→c | 48 B + TLVs | `hello_ack_v0*.hex` |
| `0x03` | SEG_TABLE | control, s→c | 40 B + n × 40 B | `seg_table_v0*.hex` |
| `0x04` / `0x05` | PING / PONG | control | 8 B | `ping_v0.hex`, `pong_v0.hex` |
| `0x06` | GOAWAY | both | 8 B | `goaway_v0.hex` |
| `0x07` / `0x08` | STATS / STATS_ACK | control | 8 B (+ counter TLVs) | `stats_v0.hex`, `stats_ack_v0.hex` |
| `0x10` / `0x11` | LOOKUP / LOOKUP_ACK | control | 40 B + n × 32 B / 16 B + n × 40 B | `lookup_v0*.hex`, `lookup_ack_v0*.hex` |
| `0x12` / `0x13` | RENEW / RENEW_ACK | control | 8 B / 16 B | `renew_v0.hex`, `renew_ack_v0.hex` |
| `0x14` | RELEASE | control, c→s | 8 B | `release_v0*.hex` |
| `0x15` / `0x16` | INVALIDATE / INVALIDATE_ACK | control | 72 B / 0 B | `invalidate_v0*.hex`, `invalidate_ack_v0.hex` |
| `0x20` / `0x21` | PUT_BEGIN / PUT_BEGIN_ACK | ingest | 40 B + n × 64 B / 112 B + n × 16 B | `put_begin_v0*.hex`, `put_begin_ack_v0*.hex` |
| `0x22` | PUT_COMMIT | ingest, c→s | 16 B + n × 16 B | `put_commit_v0*.hex` |
| `0x23` | PUT_DONE | ingest, s→c | 16 B + n × 4 B (padded to 8 B) | `put_done_v0*.hex` |
| `0x24` | PUT_CANCEL | ingest, c→s | 8 B | `put_cancel_v0.hex` |

Responses (`_ACK`, PONG, PUT_DONE) carry the RESPONSE flag. Batches are bounded so every frame fits in 8 KiB:
**LOOKUP at most 128 keys, PUT_BEGIN at most 64 keys**, SEG_TABLE at most 200 entries per frame (more frames follow with
the MORE flag).

### 5.1 HELLO and HELLO_ACK (48 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | lowest wire major supported |
| 1 | 1 | highest wire major supported |
| 2 | 1 | wire minor |
| 3 | 1 | connection class (0 control, 1 fetch, 2 ingest) |
| 4 | 1 | effective IRD |
| 5 | 1 | effective ORD |
| 6 | 1 | rail index (< 4) |
| 7 | 1 | protocol (1 RoCE, 2 iWARP) |
| 8 | 8 | feature bits (none defined in v0; HELLO_ACK returns the intersection) |
| 16 | 4 | node ID (HELLO_ACK: the memory node's ID) |
| 20 | 4 | MTU |
| 24 | 16 | connection ID (random per client session; not a user session) |
| 40 | 4 | maximum frame size, must be 8192 |
| 44 | 4 | z |

The memory node binds the connection to the identity and class recorded with the ticket. A protocol or MTU mismatch
fails the connection loudly. After HELLO_ACK on the control connection the node sends SEG_TABLE.

### 5.2 SEG_TABLE

Fixed part (40 B): `n u16` entries in this frame, `n_rails u8` (1..4), `local_rail u8`, `table_gen u32`, then the
`state_gen` array: `base u64`, `slots u64`, `rkey u32 × 4` (one per rail). Each entry (40 B): `seg_id u32`,
`flags u32` (bit 0 REMOVED), `base u64`, `len u64`, `rkey u32 × 4`. Memory regions are per device, so **rkeys are per
rail**: a READ sent on rail r uses rkey[r]. The table is sent again when a segment is added or removed. rkeys are not
secrets and stay stable for the life of the node process.

### 5.3 LOOKUP and LOOKUP_ACK

LOOKUP fixed part (40 B): `scope_id[32]`, `flags u16` (bit 0 LEASE; 0 = PROBE), `n u16` (1..128), `z u32`, then n
32-byte key hashes.

LOOKUP_ACK fixed part (16 B): `lease_id u64` (0 = none), `ttl_ms u32`, `n u16`, `z u16`. Then one 40-byte entry per
key, in request order:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | status: 0 MISS, 1 HIT |
| 1 | 3 | z |
| 4 | 4 | segment ID |
| 8 | 8 | offset in the segment |
| 16 | 8 | stored length |
| 24 | 8 | generation (1 .. 2^56 − 1) |
| 32 | 8 | `gen_slot`: index of the block's word in the `state_gen` array |

A MISS entry is all zero. A hit address is turned into (address, rkey) with the cached segment table and the rail the
READ goes on.

### 5.4 Leases

- **RENEW** (8 B): `lease_id u64` (non-zero). **RENEW_ACK** (16 B): `lease_id u64`, `ttl_ms u32` (clamped to the
  node's maximum), `status u8` (0 OK, 1 EXPIRED), `z` 3 B.
- **RELEASE** (8 B): `lease_id u64`; or the `0x0001` TLV on any control frame.
- The client's lease deadline is the LOOKUP's **send** time + ttl − a guard, moved forward by each confirmed RENEW (its
  send time + granted ttl − guard). It never trusts a deadline it cannot prove.

### 5.5 INVALIDATE

INVALIDATE (72 B): `scope_id[32]`, `key_hash[32]`, `gen u64`. The node removes the block, if it still has that
generation, together with its subtree. Sent by a client after a block failed authentication. Rate-limited, and always
answered with an empty INVALIDATE_ACK, whatever happened.

### 5.6 Store: PUT_BEGIN, PUT_COMMIT, PUT_DONE, PUT_CANCEL

PUT_BEGIN fixed part (40 B): `scope_id[32]`, `n u16` (1..64), `z` 6 B. Per key (64 B): `key_hash[32]`,
`parent_hash[16]` (truncated parent key hash; all zero = chain root), `chain_pos u64`, `stored_len u64`.

PUT_BEGIN_ACK fixed part (112 B):

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `put_id` |
| 8 | 1 | status: 0 OK, 1 REFUSED |
| 9 | 1 | number of write regions (≤ 4) |
| 10 | 2 | n |
| 12 | 4 | `retry_after_ms` (REFUSED: 0 = do not retry) |
| 16 | 96 | 4 write regions × {`addr u64`, `len u64`, `rkey u32`, `z u32`}; unused ones zero |

Then per key (16 B): `status u8` (0 SKIP, 1 ACCEPT), `region index u8`, `z` 6 B, `offset u64` within that region.

Rules:
- A key with `parent_hash == 0` on an unknown scope **opens** the scope for the caller's principal. A non-root
  PUT_BEGIN on a scope that is not open for this principal is REFUSED with `retry_after_ms = 0`; the client drops those
  stores, and the chain re-roots at the next root store.
- A key whose `stored_len` exceeds the node's largest block (HELLO_ACK TLV `0x0003`) must not be sent.
- SKIP means any of: exists, pending, quota, no space, busy.

The client then RDMA-WRITEs each accepted extent to its region and offset, and posts **PUT_COMMIT on the same ingest
connection, after the WRITEs**: fixed part (16 B) `put_id u64`, `n u16`, `z` 6 B; per accepted key (16 B)
`key_index u16` (index in the PUT_BEGIN, strictly ascending), `z u16`, `crc32c u32` of the whole client extent,
`stored_len u64` (must equal the PUT_BEGIN value).

The node deregisters the write regions (the fence), checks each CRC32C, and answers **PUT_DONE**: fixed part like
PUT_COMMIT, then per key (4 B) `key_index u16`, `status u8` (0 COMMITTED, 1 ABORTED), `reason u8` (0 none, 1 DIGEST,
2 DOOMED, 3 TIMEOUT, 4 CANCEL), padded to 8 bytes. **PUT_CANCEL** (8 B: `put_id`) aborts a store and is answered by
PUT_DONE(ABORTED). The CRC32C is a second, independent proof that the bytes arrived; it is not a security control (the
AEAD tag is).

### 5.7 PING, GOAWAY, STATS

- **PING / PONG** (8 B): `timestamp_ns u64`; PONG echoes it. Clients ping every second on the control connection;
  three misses mark the rail suspect.
- **GOAWAY** (8 B): `reason u32` (1 shutdown, 2 upgrade, 3 epoch, 4 idle), `drain_ms u32`. The receiver stops
  sending new work on that connection and moves to others.
- **STATS / STATS_ACK** (8 B): `selector u32`, `z u32`; the ack carries counters as TLVs.

### 5.8 No oracles

Answers never reveal more than the caller already knows:
- A miss, an unopened scope and another principal's scope all return the same MISS. Scopes are looked up by
  (principal, `scope_id`), so another principal's scope is never even found.
- REFUSED only says "no scope with this ID is open for your principal here".
- SKIP covers every reason a store is not taken.
- INVALIDATE always answers OK.
- STALE_EPOCH and DRAINING depend only on the node, not on any scope.

## 6. Reading a block: the sequence check

Each block slot has one 8-byte `state_gen` word: low 8 bits = state (0 FREE, 1 WRITING, 2 COMMITTED, 3 ZOMBIE), high
56 bits = generation. The generation is one node-wide counter, taken fresh on every transition into WRITING and
persisted, so a (slot, generation) pair is never reused within one store format. Generation 0 is never valid.

A fetch is: LOOKUP (with LEASE) → RDMA READ of the extent (in slices, on any fetch connections and rails) → after the
completions of **all** slices of the block have arrived, RDMA READ of the 8-byte word at
`state_gen.base + 8 × gen_slot` → the word must equal `(generation << 8) | COMMITTED` → every segment's GCM tag must
verify. Only then is it a hit. Ordering holds only within one connection, which is why the word is read after all
slices complete.

## 7. Block format (crypto v1)

A stored block, the **client extent**, is opaque to the memory node:

```
| crypto header (64 B) | segment 0: ciphertext ‖ tag (16 B) | segment 1 ... | last segment ‖ tag |
```

### 7.1 Crypto header (64 bytes, golden: `extent_header_v0.hex`)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"MIRC"` |
| 4 | 1 | crypto version (1) |
| 5 | 1 | cipher: 1 AES-256-GCM (2 reserved) |
| 6 | 1 | `segment_log2`, 16..20 (64 KiB to 1 MiB segments) |
| 7 | 1 | z |
| 8 | 4 | key version (`kver`) |
| 12 | 4 | z |
| 16 | 16 | block salt: 128 random bits from the OS CSPRNG, fresh for every store |
| 32 | 8 | plaintext length |
| 40 | 24 | z |

The header is not authenticated on its own and is attacker-controlled until a tag verifies: a reader validates its
lengths against the block size before using them.

### 7.2 Sizes

`segments = max(1, ceil(plaintext_len / 2^segment_log2))` and
`stored_len = 64 + plaintext_len + 16 × segments`. Every segment but the last is full.

### 7.3 Keys

All keys come from the deployment secret `S[kver]` (32 bytes, shared by the GPU hosts of one deployment, never sent to
a memory node) and the engine's own block hashes. `raw_key` is the engine's hash of a block, which already chains the
engine's salt (vLLM `cache_salt`, SGLang `extra_key`). `root_key` is the raw key of the chain's first block. `ns` is a
32-byte namespace digest (section 7.6).

```
S_scope  = HKDF(ikm = S[kver], salt = "", info = "mira-sub-scope")
S_key    = HKDF(ikm = S[kver], salt = "", info = "mira-sub-key")
S_dek    = HKDF(ikm = S[kver], salt = "", info = "mira-sub-dek")

scope_id = HKDF(ikm = S_scope, salt = ns, info = "mira-scope-nat-v1" ‖ root_key)     sent to memory nodes
key_hash = HMAC(S_key, "mira-key-v1" ‖ ns ‖ raw_key)                                 sent to memory nodes
DEK      = HKDF(ikm = S_dek,   salt = ns, info = "mira-dek-nat-v1" ‖ raw_key)        never leaves the GPU host
K_block  = HKDF(ikm = DEK,     salt = block salt, info = "mira-blk-v1")              one key per stored block
```

Because every store draws a fresh block salt, no key ever encrypts more than one block, and two hosts storing the same
block use different keys.

### 7.4 Nonces and AAD

- **Nonce** of segment i (12 bytes): seven zero bytes, `u32 i` **big-endian**, then one byte `last` (1 on the final
  segment only, else 0). Golden: `nonce_v0_*.hex`. Reordering, dropping or truncating segments fails the tag.
- **AAD** of every segment (80 bytes, golden: `aad_v0.hex`): `crypto version u8, cipher u8, segment_log2 u8, 0 u8,
  kver u32, scope_id[32], key_hash[32], plaintext_len u64`. A reader builds the AAD from what it **expects** (its own
  scope ID, key hash and length), never from what it read; only the block salt is taken from the block.

### 7.5 Single-fetch decrypt

On iWARP the landing pool must be remotely writable, so a hostile memory node could change ciphertext while it is
being decrypted. A compatible client must load each ciphertext byte from the RDMA buffer exactly once and use that one
value for both authentication and decryption, or first copy the segment to private memory. A block is reported as a
hit only after every tag verified.

### 7.6 Namespace `ns`

`ns = SHA-256("mira-ns-v1\0" ‖ canonical JSON of the namespace fields)`: sorted keys, no whitespace, ASCII only, JSON
values only. The fields describe everything that makes two hosts' KV incompatible: engine and version, model and
weights revision, dtype and KV dtype, KV layout, block or page size, prefix-hash algorithm and seed, and, for SGLang,
the tensor-parallel rank and size and related split settings. Hosts with a different `ns` never share blocks; they miss
silently. The adapters define the field lists (`python/miracache/ns.py` and the two adapters), and their own golden
values pin the bytes.

## 8. Memory-node storage formats (layout v0)

These formats are internal to a memory node (a client never reads them), but they are pinned so that a node can
restart on the store an earlier version wrote. Golden vectors: `superblock_v0.hex`, `segment_meta_v0.hex`,
`run_entry_v0.hex`, `server_header_v0*.hex`, `scope_record_v0.hex`, `scope_region_header_v0.hex`.

- **Superblock** (4 KiB, magic `"MIRASB"`): layout version, store format epoch, node ID, segment table, generation
  high-water mark, highest accepted bundle generation, scope-region descriptor.
- **Segment metadata** (64 B, magic `"MIRM"`) and run entries (8 B): each segment is cut into 256 MiB runs; each run
  holds equal-size block slots of one size class.
- **Server header** (128 B per slot, magic `"MIRH"`, kept outside every RDMA-registered region): generation copy,
  stored length, `scope_id`, `key_hash`, `parent_hash`, chain position, writer ID, format epoch, CRC32C of the client
  extent, CRC32C of the header.
- **Scope records** (72 B each, region magic `"MIRS"`): principal, mode, state, `scope_id` and timestamps.

On restart a node keeps only blocks whose header CRC is valid, whose state is COMMITTED and whose two generation
copies agree, and resumes generations above the persisted high-water mark.

## 9. Placement

Golden: `placement_v1.txt`, `placement_order_v1.txt`, `placement_zones_v1.txt`. For each memory node:

```
x     = first 8 bytes of SHA-256("mira-place-v1" ‖ scope_id[32] ‖ node_id as decimal UTF-8 text), big-endian u64
h     = (x + 0.5) / 2^64          in IEEE-754 double
score = −weight / ln(h)
```

The owner is the highest score; a tie goes to the lexicographically smaller `node_id` string. For
`x ≥ 2^64 − 1024`, `h` rounds to exactly 1.0 and the score is −∞; this is part of the function and must not be
clamped. With replicas, the replica set is the nodes in descending score order (the first is the owner), taking at most
one node per zone when zones are set.

## 10. Versioning

- `ver_major` changes only for incompatible framing. A memory node supports the current and the previous major.
- `ver_minor`, the feature bits and non-critical TLVs extend everything else. A peer skips TLVs it does not know.
- Upgrade memory nodes first, then clients.
- The wire version, the crypto version (in each block) and the storage layout version (in the superblock) are
  independent.
- A change to `ns` or to key derivation is a cold cache by design, never a wrong hit; the golden vectors exist so that
  such a change is always deliberate.

## 11. Cluster bundle (bundle mode)

Bundles carry membership and live configuration, and are accepted only with valid signatures and a higher generation.
The envelope is text (at most 1 MiB), golden: `proto/golden/bundle_v1/` (valid examples and one file per rejection
rule):

```
mira-bundle-v1
key_id: <16 lower-case hex>
sig: <128 lower-case hex>
sec_key_id: <16 lower-case hex>
sec_sig: <128 lower-case hex>
sec_len: <decimal>

<sec: TOML, sec_len bytes><body: TOML>
```

- `sig = Ed25519(publish key, "mira-bundle-v1\0" ‖ u32be(sec_len) ‖ sec ‖ body)`
- `sec_sig = Ed25519(security key, "mira-bundle-sec-v1\0" ‖ sec)`
- `key_id` = the first 8 bytes of SHA-256 of the raw public key. The receiver's trust file lists public keys with their
  roles (`publish`, `security`); a valid signature by a key without the right role is refused.
- `sec` holds principals and role bindings, with its own `sec_generation`; `body` holds the generation, membership
  (epoch, nodes with ID, hostname, admin address, rails, weight, zone, state, and the previous view) and
  `config.cluster.*` tables.

Memory nodes accept bundles on `POST /v1/bundle` (mTLS) and serve them on `GET /v1/bundle?after=G`; clients poll
there. The controller's audit log format is pinned in `proto/golden/audit_v1/`.
