# miracache security model

This page describes what miracache protects, against whom, how, and what it does not protect. To report a
vulnerability, see [SECURITY.md](../SECURITY.md).

> **Status: alpha.** The mechanisms below are implemented and tested on software RDMA, and the cryptographic
> primitives are tested against published NIST and RFC test vectors. miracache has not had an external security
> audit yet.

## 1. Summary

- **Memory nodes are untrusted storage.** They hold only ciphertext and never a key. A compromised memory node can
  delete or withhold cache (the engine then recomputes), but it cannot read KV, and it cannot make a client accept
  altered bytes.
- **Keys never leave the GPU hosts.** Every key is derived on the GPU host from a deployment secret that no memory
  node ever sees.
- **Encryption is always on.** There is no plaintext mode and no integrity-only mode.
- **Isolation equals the engine's own.** miracache never shares KV between two requests that the engine would not
  share in its own GPU prefix cache.
- **Every connection is authenticated.** Mutual TLS 1.3 for every admin and control call; RDMA connections need a
  single-use ticket obtained over mutual TLS.
- **Least privilege.** The memory node runs as an unprivileged user with one capability (`CAP_IPC_LOCK`).
- **Fails safe.** Any failed check is a cache miss and a recompute, never wrong data.

## 2. Why the payload must be encrypted

A memory node exposes its cache memory to RDMA READ. A one-sided READ against a large memory region can address any
offset in it, and RDMA keys (rkeys) are not secrets: anyone who can open a fetch connection and learns an rkey can read
the whole region. Server-side checks can only protect the **index** (which scope answers which lookup), not the bytes.
KV cache is sensitive: published research reconstructs user input from intercepted KV. So confidentiality and
integrity rest on encryption done on the GPU host, before the data leaves it, and on verification after every read.

## 3. Trust boundaries

| Party | Trusted with |
|---|---|
| GPU host (engine + adapter + `libmiracache`) | the deployment secret, plaintext KV |
| Memory node | availability only: never plaintext, never integrity |
| Controller (bundle mode) | membership and configuration (it holds the bundle signing keys) |
| The network between them | nothing: assume the switch is on-path |

## 4. Cryptography

- **Cipher.** AES-256-GCM, applied per segment of a block (64 KiB to 1 MiB segments), each segment with its own
  16-byte tag.
- **Deployment secret.** One 32-byte secret per key version, identical on every GPU host of one deployment, in a file
  that must be mode `0600` (the client refuses to start otherwise). It is never placed in any request and never sent to
  a memory node.
- **Derived keys, not raw secrets.** The secret is never used directly. Three subkeys are derived from it, and from
  them, per block: the scope ID, a keyed key hash, and a per-block data key. The exact derivation is in
  [protocol.md](protocol.md#73-keys).
  - **Keyed key hash.** The memory node sees an HMAC of the engine's block hash, not the engine's hash itself. Engine
    prefix hashes of unsalted prompts can be computed by anyone who knows the text; an unkeyed hash would let a memory
    node confirm guessed prompts offline. The keyed hash closes that.
  - **One data key per block.** Guessing a shared system prompt can at most expose that one block, not the user turns
    after it.
  - **One encryption key per stored copy.** Each store draws a fresh 128-bit random salt, so no key encrypts more than
    one block and the GCM nonce limits never come into play.
- **Bound context.** The tag covers the crypto version, cipher, segment size, key version, scope ID, key hash and
  length. The reader builds this context from what it expects, never from what it read, so a block moved to another
  key, scope or length fails.
- **Segment order.** Each segment's nonce encodes its index and a "last segment" flag: reordering, dropping or
  truncating segments fails the tag.
- **Read once, verify, decrypt.** The decrypt pass reads each ciphertext byte from the RDMA buffer exactly once and
  uses that value for both authentication and decryption, so a memory node rewriting the buffer during decryption gains
  nothing. A block is reported as a hit only after every tag verified; the engine never receives unverified plaintext
  as a success. This is tested with a mutator that flips bytes during decryption.
- **Stable reads.** A separate check (the generation word, see [architecture.md](architecture.md#61-fetch)) detects a
  block that changed during the read. A changed block is a plain miss; a stable block that fails authentication is a
  miss **and a security alert**, and the client tells the node to drop it and its subtree.

## 5. Isolation

miracache follows the engine's own sharing rules (vLLM `cache_salt`, SGLang `extra_key`):

- The engine's block hash already includes the salt, and every miracache key and scope ID is derived from that hash.
  Two requests with different salts can never hit each other's blocks, exactly as in the engine.
- With no salt, prefixes are shared across the deployment, again exactly as in the engine.
- **Per-session isolation** follows when each session gets its own salt, for example when a gateway in front of the
  engine sets an authoritative per-session salt and removes salts sent by clients.
- **Namespace.** Hosts that differ in engine, version, model, weights revision, dtype, block size, hash settings or
  parallel layout compute different keys and never share blocks. `mira-preflight` fails a host whose settings the
  engine does not pass to the tier until the operator mirrors them into the tier configuration.

**On the memory node,** scopes are keyed by (principal, scope ID), where the principal comes from the identity of the
connection's ticket. A scope opened by one principal is invisible to another: the other principal's lookup is a plain
MISS. Only a store of a chain root opens a scope; a lookup never does. At its quota, a principal evicts its own least
recently used scope, never another principal's.

**No oracles.** A miss, an unopened scope and another principal's scope answer identically. A refused or skipped store
gives no reason that depends on other keys. An invalidation always answers OK.

## 6. Authentication and access control

- **Mutual TLS 1.3 only**, with client certificates required, for the memory node admin API, the controller API and
  every client call to them. Identities are `spiffe://` URIs in the certificate SAN; use your own CA. Certificates and
  keys reload without a restart, so short-lived certificates work.
- **Tickets for RDMA.** Before connecting, a client asks the target memory node, over mutual TLS, for single-use random
  128-bit tickets. The node refuses identities outside its principal table and records each ticket with the client's
  identity, class (control, fetch or ingest), rail and a 5-minute expiry. The ticket rides in the RDMA connection
  request and is consumed by the first connect. A ticket seen on the wire is already spent; memory nodes hold no ticket
  signing key, so a compromised node cannot mint tickets that another node accepts.
- **Separate protection domains** per connection class on the memory node: a fetch connection can read only data
  regions and generation words and can never use a write key; a write region exists only from the start of one store
  until its commit fence. On the client, only the landing pool is registered with the NIC, one protection domain per
  memory node, so a memory node can only touch the buffer that receives its own data. Engine memory is never exposed.
- **What a fetch key can read, in full:** ciphertext in the data runs, and the 8-byte state words. Block headers, scope
  IDs, key hashes, chain links and scope records are in memory that is never registered for RDMA.
- **Signed configuration.** In bundle mode, membership and configuration come only in Ed25519-signed bundles with a
  strictly increasing, persisted generation, so an old bundle cannot be replayed. The bundle has two signed parts: a
  security part (principals, role bindings) signed by a key with the `security` role, and the rest signed by a key with
  the `publish` role. Memory nodes hold public keys only.
- **Roles.** `viewer`, `operator`, `security-admin`, `scope-provider`. For example, draining a node needs `operator`,
  and dropping every scope of a principal needs `security-admin`.
- **Audit.** The controller keeps an append-only, hash-chained audit log of publishes and admin calls (`mirctl audit
  verify` checks the chain); each memory node chains its own admin calls.

## 7. Least privilege and hardening

- `mira-memnode` runs as the system user `mira`, with only `CAP_IPC_LOCK` and an unlimited memlock limit (to pin the
  cache for the NIC), `NoNewPrivileges`, a private `/tmp`, a read-only `/usr`, `/boot` and `/etc`, and `UMask=0077`.
  Some systemd sandboxing options are deliberately not set because they would hide the RDMA devices, sysfs or netlink.
- The controller runs as `mira` with no capabilities and a read-only file system except its state directory.
- The Docker images run as uid 10001 with `--cap-drop ALL`, a read-only root file system and `no-new-privileges`;
  no `--privileged`.
- Key files must be `0600`; the memory node and the client refuse to start otherwise. Logs and metrics never carry
  keys, tickets, salts, nonces, payload or rkeys, and no metric label carries a scope or session value.
- The Prometheus endpoint is plain HTTP without authentication: bind it to a scrape network, not to `0.0.0.0`. Open
  the admin port to the GPU hosts and operators only.

## 8. Fails safe

- `mira-preflight` hard-fails engine settings that would break caching or isolation (for example a vLLM failure policy
  that would turn a miss into a request error, a wrong prefix-hash algorithm, or a world-readable secret file).
- The adapters refuse to start on an unsupported configuration or engine version, rather than run with a wrong key
  scheme.
- After start-up, data-path errors never raise into the engine: they are misses.
- There is no TCP fallback: without RDMA, nothing is sent.

## 9. Threat model

| Threat | Protected by | Not protected (residual risk) |
|---|---|---|
| Rogue or compromised memory node | ciphertext only; keyed key hashes; tags checked on every read; no keys; cannot mint tickets for other nodes | traffic analysis (sizes, timing); withholding or deleting data (availability). A scope ID is stable per chain, so the same chain is linkable over time |
| Network attacker reading or injecting RDMA traffic | AEAD on all payload; single-use tickets; mutual TLS on control | injected garbage becomes a miss (denial of service only). RDMA traffic itself is not encrypted beyond the payload: use network isolation (VLAN or VRF per trust domain) |
| Cross-session leakage | keys follow the engine's salted hashes | without salts, prefixes are shared across the deployment, as in the engine. Both engines accept salts from their clients, so an engine exposed directly to clients trusts their salts |
| Prompt-cache timing | a foreign or unopened scope looks exactly like a miss | within one salt, timing reveals hits, as in the engine's own cache |
| Replay of old KV or old configuration | key, scope and length bound into the tag; committed blocks immutable; generations never reused; signed bundles with a persisted generation floor | a node with an empty state directory accepts any validly signed bundle until the next push (optionally pin a minimum security generation in its trust file) |
| Keys leaking through engine logs | no key material in any request field; a logged salt is useless without the secret | none known |
| **Compromised GPU host** | bounded to its own deployment and its principal's quotas | **the major residual risk:** the host holds the secret, so it can decrypt any block of its deployment whose engine hash it can compute (what it served, plus guessable prefixes such as shared system prompts), and can poison not-yet-cached guessable prefixes. Use one secret and one trust domain per deployment |
| Noisy neighbour, flooding | byte and scope caps per principal, store rate limits, fetch deadlines with recompute | fabric-level floods |
| Deletion | idle expiry; per-deployment shred: rotate the secret (`mirctl secret add-kver`), remove the old key version from every host, then drop the principal's scopes created before the rotation | no per-session cryptographic deletion; idle expiry is not provable deletion |
| Online security signing key (bundle mode) | separate role from the publish key | in this version the controller holds the security key online; whoever takes it can publish a new principal table |

## 10. Operator checklist

1. Use your own CA, one SPIFFE identity per host, and short-lived certificates.
2. Create one deployment secret per deployment (`mirctl secret gen`), copy it only to that deployment's GPU hosts,
   mode `0600`, owned by the engine user. Never copy it to a memory node.
3. Back the secret up: a lost secret makes the whole cache unreadable (the engine recomputes).
4. Put memory nodes and GPU hosts of one trust domain on their own VLAN or VRF; restrict the admin and metrics ports.
5. Run `mira-preflight` on every GPU host before launch, and compare host fingerprints.
6. Alert on store checksum mismatches (a shipped alert rule) and on any increase of the client's AEAD failure
   counter `miracache_client_aead_fail_total`.
