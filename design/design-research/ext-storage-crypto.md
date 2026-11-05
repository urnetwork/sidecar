# External state of the art: encrypted versioned storage with MLS (input for PLAN.md "evs")

Fact sheet for the sidecar design writers. Research date: 2026-11-03.

- **Sources:** RFCs, IETF drafts, vendor docs, papers, upstream source read through the GitHub API, and read-only inspection of /Users/brien/urnetwork.
- **Citations:** code facts are `repo/path:LINE`, relative to /Users/brien/urnetwork. `GOROOT/...` means the local Go 1.27.3 at /usr/local/go.
- **Labels:** "inference:" marks my own conclusions. "[search excerpt]" marks a fact seen only in a search summary.
- **Conflicts:** where PLAN.md disagrees with a spec or the code, the spec or code wins.
- **Ignored as instructed:** the message repo and connect/MESSAGEREVIEW.md.

## 1. Summary

- **MLS gives one secret per epoch, and evs needs nothing more from it.** That secret comes from `MLS-Exporter` (RFC 9420 §8.5). MLS also has three limits for storage:
  - new members cannot derive earlier epochs;
  - the exporter is not forward-secure;
  - the Delivery Service (DS) must accept exactly one Commit per epoch.

  Storage therefore needs its own history of epoch keys, a key-regression chain. Keybase, Keyhive, git-remote-e2ee and Grappa (EUROCRYPT 2026) all build one.
- **PLAN.md's claim that client-side lazy re-wrapping with MLS exporters is "almost universal" (sidecar/PLAN.md:47,329,335) is half right.**
  - Forward-only ("lazy") revocation is near universal in deployed E2EE storage: KBFS, Keybase, Tresorit, Dropbox, Apple ADP, git-remote-e2ee.
  - No deployed storage system was found that uses MLS exporters. The only MLS-for-files spec is an individual draft from July 2026, and it does not re-wrap at all.
- **(a) Architecture (inference):**
  - The client runs git. Packs are delta-compressed on plaintext, then encrypted.
  - Each push publishes a signed manifest, and one head moves only by compare-and-swap (CAS).
  - The server is a blind object store plus MLS DS plus notifier.
  - Precedents: Keybase (2017), git-remote-gcrypt, git-remote-e2ee (2026).

  PLAN's git-crypt model works. But it leaks paths and history, it defeats delta compression (hence PLAN's custom diffs), and it blocks crypto-shredding of a single entry.
- **(b) Build vs buy:** no audited Go MLS exists. The MIT candidates are:
  - thomas-vilte/mls-go: interop-tested;
  - tmc/mls: claims all of RFC 9420 and every test vector, but is 6 weeks old;
  - emersion/go-mls: incomplete.

  Go 1.26 added `crypto/hpke` (with X-Wing) to the standard library, so the hard dependency is gone. Fork one candidate into the sidecar repo, or build a narrow subset against the MLS working group (mlswg) test vectors, and budget an audit. Rust over FFI is ruled out, because the sdk's js/wasm build has `CGO_ENABLED=0`.
- **(c) git-crypt-style plaintext paths leak:**
  - names and tree shape;
  - exact sizes (plaintext + 22 B);
  - which contents are equal;
  - commit messages, authors and times;
  - symlink targets;
  - which file changed when.

  For agent records and mail, that is the sensitive data. Encrypt paths.
- **Git protocol and servers:**
  - Smart HTTP v2 defines no push.
  - Custom commands are legal, but stock git never sends them, so any extension needs a custom client anyway.
  - go-git v6 (beta) has a pure-Go server, but no partial clone yet.
  - Gitea and soft-serve run the `git` binary.
  - Netlify (2026) runs git on S3, with ref CAS done by conditional writes.
- **Deltas:** the server cannot delta-compress ciphertext.
  - Content-defined chunking (CDC) leaks chunk sizes, and keyed chunkers were broken in 2025.
  - inference: both products' data is mostly append-only or immutable, so segments plus compaction may beat diffs plus checkpoints.
- **Infrastructure surprises:**
  - upstream MinIO is archived;
  - the deployed MinIO predates a fix for conditional PUTs that ignored their condition when read quorum was lost;
  - the load balancer caps request bodies at 16 MB.
- **(d) Pitfalls:**
  - unauthenticated key-rotation input (Nextcloud);
  - a missing key that defaults to zero (Nextcloud);
  - nonce reuse (Nextcloud, Borg);
  - unauthenticated chunks and metadata (ETH 2024);
  - git-crypt emitting tampered plaintext before it fails;
  - MLS forks, and Welcomes sent before the Commit is accepted;
  - Welcome size linear in the group size;
  - harvest-now-decrypt-later for long-lived data, which calls for a post-quantum MLS suite.

## 2. Facts with citations

### 2.0 Direct answers
**(a) Architecture.** inference, built on §2.5–2.11:
1. **Control plane.**
   - One MLS group per access boundary (open question 3).
   - The server is the DS. It takes the first valid Commit per epoch through an atomic insert, and releases a Welcome only after its Commit is accepted (RFC 9420 §14).
   - It also stores the latest signed GroupInfo and a KeyPackage directory.
2. **Epoch keys.**
   - `K_E = MLS-Exporter("<unique evs label>", repo_id, 32)`, persisted locally in encrypted form.
   - The server stores `Enc(K_E, K_{E-1})`, so any current member can walk back to the first epoch while a removed member never gets `K_{E+1}`. This is the scheme of Keybase PTK seeds and git-remote-e2ee.
   - Delete MLS epoch secrets on the RFC 9420 §9.2 schedule, but keep each `K_E`.
3. **Data plane.**
   - The client runs git: `git` plus a `git-remote-<x>` helper on desktop, and go-git on wasm and mobile, which have no git binary.
   - It deltas on plaintext, encrypts packs as authenticated segments under subkeys of `K_E`, uploads immutable objects, and then moves the head by CAS to a signed manifest. The manifest holds refs, packs, the epoch and the previous manifest's hash.
4. **Server role.**
   - It never parses git. It stores objects (PutIfAbsent), the head (CAS), the MLS log, GroupInfo and KeyPackages.
   - It enforces ACLs as defence in depth, and sends change notifications over connect (sidecar/PLAN.md:55).
5. **Reading the head of one file.** The manifest carries an encrypted path index, mapping each path to segment byte ranges. This replaces PLAN's server-side "checkpoint + diffs" head API (sidecar/PLAN.md:63).
6. **Revocation.**
   - A Remove commit moves new writes to `K_{E+1}`, with no bulk re-encryption.
   - PLAN's "send a new checkpoint" (sidecar/PLAN.md:50) becomes an optional re-key of the head snapshot, and history keeps its old keys.
   - If PLAN's git-crypt model is kept, still encrypt names, commit messages and author fields, and use random per-object keys (DEKs) if erasure is required.

**(b) Build vs buy.** Fork an MIT Go implementation into the sidecar repo, or build a narrow subset in-house. Both run pure Go over `crypto/hpke`, with no cgo (§2.4).

**(c) Paths.** Encrypt them (§2.6).

**(d) Pitfalls.** See §2.12 and §5.

### 2.1 MLS protocol (RFC 9420, July 2023), https://www.rfc-editor.org/rfc/rfc9420.html
- **Scope:** groups "ranging from two to thousands" (abstract).
- **Exporter (§8.5):**
  - `MLS-Exporter(Label, Context, Length) = ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)`.
  - "Applications SHOULD provide a unique label", and §17.8 is the IANA registry of labels.
  - Values "are bound to the group epoch". The RFC recommends refreshing them after every Commit.
- **Derived secrets (§8, Table 4):** `epoch_secret` yields the sender_data, encryption, exporter, external, confirmation, membership and resumption secrets, plus `epoch_authenticator`, which members use to confirm a shared view of the group.
- **Deletion (§9.2):** "As soon as a group member consumes a value, they MUST immediately delete" it. §8.5 gives the exporter no deletion rule.
- **Exporter forward secrecy:**
  - draft-ietf-mls-extensions-11 (2026-11-02, §4.4) says the base exporter "does not provide forward security for exported secrets".
  - It adds `SafeExportSecret(ComponentID)`, built on a 2^16-leaf exporter tree.
  - Working-group state: "Revised I-D Needed – Issue raised by WGLC" (https://datatracker.ietf.org/doc/draft-ietf-mls-extensions/).
- **External joins (§8.3, §12.4.3.2):**
  - `external_pub` is derived from `external_secret` and published in GroupInfo.
  - External Commits "MUST contain a `path` field", may not include proposals by reference, and use sender type `new_member_commit`.
  - A "resync" Commit removes the joiner's own old leaf. Applications may "disallow external commits that contain a Remove".
- **Commit path (§12.4):** a Commit needs a path unless every proposal it covers is Add, PSK or ReInit. Remove, Update, ExternalInit, GroupContextExtensions and empty Commits all require one.
- **Ordering (§12.4.2, §14):**
  - A Commit's epoch must equal the receiver's current epoch.
  - "Applications MUST have an established way to resolve conflicting Commit messages for the same epoch".
  - A Welcome "MUST NOT be delivered to a new joiner until" its Commit is accepted.
- **DS visibility (§16.4.1):** "MLS provides no mechanism to protect the group ID and epoch of a message from the DS". Proposals and Commits sent as PublicMessage are not confidential (§16.4).
- **Credentials (§5.3):**
  - Two credential types are defined. "basic" is "a bare assertion of an identity"; x509 carries DER certificate chains.
  - Every new credential "MUST be validated with the AS" (the Authentication Service).
- **Security (§16.6):**
  - Forward secrecy comes from deleting old tree keys.
  - Post-compromise security comes from regular leaf updates.
  - "Applications SHOULD have mechanisms for evicting group members that are offline for too long".
- **KeyPackages (§16.8):** a "last resort" KeyPackage may be reused; every other KeyPackage is used once.
- **Cipher suites (§17.1):**
  - 0x0001 X25519 / AES-128-GCM / SHA-256 / Ed25519 is mandatory to implement.
  - The others are 0x0002 P-256, 0x0003 X25519 with ChaCha20-Poly1305, 0x0004 and 0x0006 X448/Ed448, 0x0005 P-521 and 0x0007 P-384.
- **Post-quantum suites:**
  - draft-ietf-mls-pq-ciphersuites-07 (2026-11-01, "Publication Requested") defines 0x0010–0x0022.
  - Examples: 0x0010 MLKEM768X25519_AES128GCM_SHA256_Ed25519 (KEM 0x647a), and 0x0020 MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44.
  - Codepoints are requested, not yet assigned (https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/).
- **PLAN.md error (sidecar/PLAN.md:174).** PLAN says external commits and snapshots avoid "replaying every epoch transition".
  - Joiners never replay: the Welcome carries current state.
  - Existing members must process every Commit from their last epoch, because each epoch derives from the previous `init_secret` (§8). The only alternative is an external-Commit resync, which skips the intervening epochs' secrets.
  - Recovery by rejoining gives no access to the gap (RFC 9750 §6.6).

### 2.2 MLS architecture (RFC 9750, Informational, April 2025), https://www.rfc-editor.org/rfc/rfc9750.html
- **One Commit per epoch (§5.2):**
  - "the group must agree on a single MLS Commit message".
  - A strongly consistent DS "is trusted to break ties" (§5.2.1). An eventually consistent DS leaves the tie-break to clients (§5.2.2).
  - Most deployments are expected to use the strongly consistent model.
- **KeyPackages (§5.1):** "intended to be used only once", except one rotated last-resort package. Delete the `init_key` after processing a Welcome.
- **State loss and inactivity:** a client that loses state rejoins and removes its old leaf (§6.6). Idle clients must update keys or be evicted (§8.2.2).
- **Encryption at rest (§8.4.1.2):** "Rely on group secrets exported from the MLS session for server-side encryption at rest", and "update the key after each removal".
- **DS compromise (§8.4.2):** a compromised DS can drop messages and serve stale keys. With `basic` credentials it can also substitute KeyPackages, because nothing binds identity to key. Stronger credentials are recommended.
- **AS compromise (§8.4.3):** "a compromised AS is a serious matter". Mitigations: key transparency, out-of-band checks, and showing membership changes to users.
- **DS metadata (§8.1):** the DS sees the group_id, epoch and content type.

### 2.3 Sizes and scaling
- **Measured Welcome:** XMTP saw a 436,092-byte Welcome for 800 members, about 545 B per member, because "a full copy of the ratchet tree is included in each welcome" (https://github.com/xmtp/libxmtp/issues/812, 2024).
- **Linear tree growth:** draft-mahy-mls-ratchet-tree-options-04 (March 2026) says the tree grows roughly linearly, and defines ways to send it out of band.
- **Measured cost:** Soler et al. (arXiv 2502.18303v2, Feb 2026, built on OpenMLS) found that the logarithmic cost "does not hold in practice", and a Commit took about 0.1 s at 10,000 members.
- **Go timings:** thomas-vilte/mls-go reports, at 500 members, Commit 34.7 ms and JoinFromWelcome 77.7 ms. Message send stays flat at about 50 µs regardless of group size.
- **Post-quantum key sizes:** ML-KEM-768 has a 1184 B public key and a 1088 B ciphertext (FIPS 203, https://csrc.nist.gov/pubs/fips/203/final). X-Wing adds 32 B to each. An ML-DSA-44 signature is 2420 B (FIPS 204).
- **Estimates (inference):** a 0x0001 group with basic credentials needs about 0.27 KB per member for the tree and about 0.1 KB per UpdatePath level. X-Wing raises these to about 2.6 KB and 2.4 KB. A 50-member Welcome grows from about 15 KB to about 130 KB.

### 2.4 Go MLS implementations and build options
- **cisco/go-mls:** archived, BSD-2-Clause, last push 2021. The mlswg list rates it "roughly draft-09" (https://github.com/mlswg/mls-implementations/blob/main/implementation_list.md).
- **emersion/go-mls** (MIT, https://github.com/emersion/go-mls):
  - Last push 2025-12-28. "work-in-progress and has not yet been audited".
  - About 5.4k non-test lines, using CIRCL for HPKE. The exporter is internal only.
  - Open issues include generating update paths (#10), all base proposals in Commits (#8), persistence (#5), PSKs (#2) and an interop server (#12).
- **thomas-vilte/mls-go** (MIT, https://github.com/thomas-vilte/mls-go):
  - Created 2026-03-05; v1.6.0 released 2026-07-10. 413 commits, essentially from one author. Go 1.26, depending only on x/crypto.
  - Interop: 21/21 against mlspp and 12/12 on a subset against OpenMLS, for suites 1–3.
  - Has `Export`, `ExternalJoin`, `GroupInfo` and staged Commits for DS conflicts.
  - Vendors 14 of the 16 vector files, and ships a `GOOS=js` example.
  - Known gaps from its SECURITY.md: ReInit `joiner_secret` derivation needs review; the outer signature on `new_member_proposal` is not verified; padding is 0 by default; zeroing secrets is best effort.
  - `MarshalState` serializes epoch secrets to JSON, so state at rest must be encrypted.
- **tmc/mls** (MIT, https://github.com/tmc/mls):
  - Created 2026-09-18, last push 2026-10-02. 0 stars, 131 commits from one author. Go 1.27, depending only on x/crypto.
  - Claims "Everything RFC 9420 defines is implemented": all 7 suites (X448/Ed448 ported from CIRCL) and all 16 vector suites on every suite.
  - Has wire-format and group fuzzers and an interop-harness server.
  - Unaudited, and does not zero secrets. About 8.2k core lines.
- **Rust and others:**
  - OpenMLS (MIT, v0.9.0 released 2026-08-25) supports `wasm32-unknown-unknown` through its `js` feature.
  - mls-rs (Apache-2.0) supports WASM builds and "has not yet received a full security audit".
  - mlspp is BSD-2-Clause; ts-mls is MIT.
- **FFI conflict, confirmed:**
  - The browser build is `CGO_ENABLED=0 GOOS=js GOARCH=wasm` (sdk/js/Makefile:69). The boundary test pins that build (sdk/dependency_boundary_test.go:84): "A native caller must not add cgo-only dependencies to the shipped browser leg" (sdk/dependency_boundary_test.go:512).
  - "js/wasm doesn't support cgo" (https://github.com/golang/go/issues/40313).
  - The gomobile builds run with cgo on (sdk/dependency_boundary_test.go:88-91), so a Rust static library could link there. inference: that needs per-target Rust builds.
  - inference: in the browser, a Rust-wasm MLS could only reach Go wasm through JavaScript glue.
- **Go standard library:**
  - `crypto/hpke` arrived in Go 1.26 (Feb 2026), "including support for post-quantum hybrid KEMs" (https://go.dev/doc/go1.26).
  - It provides `NewSender`/`NewRecipient`, `Seal`/`Open`, `Export` and `KEM.DeriveKeyPair` (GOROOT/src/crypto/hpke/hpke.go:135,154,197).
  - Its KEM IDs 0x647a, 0x0050, 0x0051, 0x0041 and 0x0042 (GOROOT/src/crypto/hpke/pq.go:21,46,69,361,380) cover every post-quantum MLS draft KEM.
  - `crypto/hkdf` and `crypto/mlkem` date from Go 1.24, and `crypto/mldsa` from Go 1.27 (GOROOT/api/go1.24.txt, go1.27.txt). There is no X448 or Ed448.
  - Go's generic AES, which wasm uses, is table-based (GOROOT/src/crypto/internal/fips140/aes/aes_generic.go:58-74). tmc/mls advises ChaCha20-Poly1305 suites where AES hardware is absent.
- **Cost of an in-house build (inference):**
  - Scope: tree math, codec, key schedule, TreeKEM with parent and tree hashes, transcripts, Welcome/GroupInfo, external Commit, KeyPackage validation and the exporter, for one classical and one post-quantum suite, with PublicMessage handshakes only.
  - Size: about 5–8k lines of Go plus a larger test corpus.
  - Effort: 2–4 engineer-months to pass the 16 vector suites, interop and fuzzing, plus persistence and DS work. The audit is the long pole; its cost was not researched.
  - Forking cuts coding time, but not the review.

### 2.5 MLS and CGKA applied to stored data
- **draft-sullivan-mls-attachments-01** (Sullivan and Robert, 2026-07-21, individual draft, https://datatracker.ietf.org/doc/draft-sullivan-mls-attachments/):
  - Key derivation: `CEK = ExpandWithLabel(SafeExportSecret(ComponentID), …"attachment", object_id, 32)`.
  - Each object needs a fresh 32 B salt. Reusing an (object_id, salt) pair "is a two-time pad".
  - The CEK "is a persistent key for the life of the attachment".
  - Removal does not revoke existing attachments; revocation means re-encryption.
  - After epoch deletion the CEK "cannot be re-derived from MLS".
  - Long-lived data "SHOULD" use a post-quantum suite.
- **Grappa** ("Group Key Progression", Backendal, Balbás and Haller, EUROCRYPT 2026, ePrint 2025/1028):
  - It replaces static folder keys, which survive membership changes, by combining a CGKA with an "interval scheme" (generalized dual key regression), so members can only derive keys within an interval of the sequence.
  - Its artifact reports, for 500 users and 5 admins with the D[H,F] scheme, 4.2 KB of admin state and 5.5 KB of user state (https://github.com/Miro-H/GrappaSimulator).
- **Keyhive BeeKEM** (Ink & Switch, 2025-01-21):
  - It needs only causal order, keeping "conflict keys" for concurrent updates.
  - Keyhive "lacks forward secrecy because decrypting one chunk gives access to the key for the previous chunk". That chain is how history stays readable (https://www.inkandswitch.com/keyhive/notebook/02/).
- **Discord DAVE** (v1.1.4) is a deployed use of the exporter, for media rather than storage:
  - Media keys use `MLS-Exporter("Discord Secure Frames v0", littleEndianSenderID, 16)`.
  - The voice gateway is the DS. It "broadcasts the first commit it receives for a given epoch" and acts as an `external_senders` member proposing Add and Remove (https://daveprotocol.com/).
- **No deployed MLS file-storage system was found** (searches for Wire, Webex, Proton and general terms, 2026-11-03).

### 2.6 git-crypt internals and plaintext-path leakage
- **Construction** (https://github.com/AGWA/git-crypt at 8c7a90ff38fc; v0.8.0 released 2025-09-23):
  - HMAC-SHA1 over the whole file, with a 64 B key (commands.cpp:741; key.hpp:41).
  - Output is `"\0GITCRYPT\0"`, then the first 12 HMAC bytes as nonce, then AES-256-CTR (commands.cpp:800-804; crypto.hpp:71). Overhead is 22 B.
  - Files of 64 GiB or more are refused (crypto.hpp:74).
  - On smudge, an HMAC mismatch prints "tampered with!", but "we've already written the tampered file to stdout" (commands.cpp:858-862).
- **README:**
  - Encryption is deterministic and "provably semantically secure under deterministic chosen-plaintext attack", leaking only equality.
  - It "does not encrypt file names, commit messages, symlink targets, gitlinks, or other metadata".
  - It cannot revoke, and points whole-repo users to git-remote-gcrypt.
  - "Even the smallest change … requires git to store the entire changed file".
  - It needs the whole repository protected against tampering, and `.gitattributes` set before sensitive files are added.
- **What leaks in PLAN's model** (inference):
  - paths, tree shape, counts and exact sizes;
  - equal contents within one key, including reverts;
  - per-commit change sets, times and messages;
  - each writer's client_id (sidecar/PLAN.md:59);
  - repo and branch names (sidecar/PLAN.md:53).
- **Product commitments affected:**
  - "only ciphertext and the metadata listed here" (sidecar/pitch5.html:745).
  - "Publish the list of metadata the servers can see" (sidecar/improve.md:116).
  - The records research treats paths as guessable and metadata as personal data (sidecar/research_notes/Agent work record gaps and features/verifiable_record_tech.md:433-434).
- **How others encrypt names:**
  - gocryptfs: deterministic AES-256-EME per directory, names up to 175 characters (https://nuetzlich.net/gocryptfs/forward_mode_crypto/).
  - Cryptomator: AES-SIV with the parent directory ID as associated data, in a flattened hashed tree; counts stay visible (https://docs.cryptomator.org/security/vault/).
  - Proton Drive: names encrypted with the parent node key (https://proton.me/blog/protondrive-security).
  - KBFS: directory blocks are encrypted.
  - Counterexample: Dropbox E2EE encrypts "file contents rather than metadata" (https://dropbox.tech/security/end-to-end-encryption-for-dropbox-teams, 2024).

### 2.7 Encrypted-git precedents
- **git-remote-gcrypt** (https://github.com/spwhitton/git-remote-gcrypt):
  - The manifest is `EncSign(branches ‖ packs with per-pack keys ‖ repo id)`, and packs are stored under their hash.
  - "Every git push effectively has `--force`".
  - Git and sftp backends upload "the entire repository history with each push".
- **Keybase** (2017, https://keybase.io/blog/encrypted-git-for-everyone):
  - The server sees membership, pushers, devices and repo IDs, but not repo names, branch names or contents. Pushes are signed per device.
  - The code is a go-git helper writing a bare repo into encrypted KBFS under `.kbfs_git` (keybase/client go/kbfs/libgit/repo.go:40).
  - With "no standard remote protocol", a push is implemented as a reverse fetch (go/kbfs/kbfsgit/runner.go:81-94).
  - Delta compression is turned off with `Pack.Window = 0` (runner.go:396-409).
- **git-remote-e2ee** (Rust prototype, 2026, https://github.com/combinatrix-ai/git-remote-e2ee):
  - Each HEAD publication gets a fresh generation key, HPKE-wrapped to each reader. The recipient list is padded to a power of two.
  - A predecessor-key link lets "A current reader … walk to genesis".
  - Packs are encrypted in 1 MiB authenticated segments, and only HEAD moves, by CAS.
  - Revoking a device means "a fresh generation … No historical object changes".
  - A one-line push sends 8.9 KB, against 921 MB with gcrypt.

### 2.8 Git protocol v2, partial clone, promisor remotes, remote helpers
- **Protocol v2** (https://git-scm.com/docs/gitprotocol-v2):
  - Commands: `ls-refs`, `fetch`, `object-info` and `bundle-uri`.
  - Capabilities: `agent`, `server-option`, `object-format`, `session-id` and `promisor-remote`.
  - fetch features: `shallow`, `filter`, `ref-in-want`, `sideband-all`, `packfile-uris` and `wait-for-done`.
  - "Clients must ignore all unknown keys".
  - There is no push command; push stays on receive-pack.
  - The protocol is stateless by default, served at `/info/refs?service=git-upload-pack` with `Git-Protocol: version=2`.
- **Partial-clone filters:** `blob:none`, `blob:limit`, `tree:0`, `object:type` and `sparse:<oid>`, which can be combined (https://git-scm.com/docs/git-pack-objects).
- **Promisor remotes:** Git 2.49 added a "Large-object promisor protocol extension". Git 2.52 lets the server send `partialCloneFilter` and a `token` (git/git Documentation/RelNotes/2.49.0.adoc:100, 2.52.0.adoc:34-36).
- **Bundle URIs:** `--bundle-uri` arrived in Git 2.38.
- **Remote helpers** (https://git-scm.com/docs/gitremote-helpers):
  - A `<transport>://` URL invokes `git remote-<transport>`.
  - Capabilities include `connect`, `stateless-connect`, `fetch`, `push`, `import`, `export` and `option`.
  - gcrypt, Keybase and git-remote-e2ee all add encryption this way.
- **Consequence for PLAN (inference):** PLAN's "own extension" for diffs (sidecar/PLAN.md:63) needs a custom client either way. `packfile-uris` or `bundle-uri` could redirect downloads to presigned object-store URLs.

### 2.9 Go git servers and object-store backends
- **go-git v6** (Apache-2.0; v6.0.0-beta.1 released 2026-10-04; main at 500c64d699c8):
  - Server API: `transport.UploadPack`, `transport.ReceivePack` with `ReceivePackHooks`, and `MapLoader`.
  - The v2 advertisement covers only `agent`, `ls-refs`, `fetch=shallow` and `object-format`.
  - Still TODO: `fetch=filter`, `object-info`, `packfile-uris` and `server-option` (plumbing/transport/serve.go:148-157).
  - `storage.Storer` is pluggable (storage/storer.go:20), and `ReferenceStorer.CheckAndSetReference` is a ref CAS (plumbing/storer/reference.go:24).
  - CI tests `GOOS=js` with memory storage (.github/workflows/test.yml:82-107). A js build regression was fixed on 2026-10-01 (#2417).
- **Servers that need the git binary:**
  - soft-serve runs `exec.CommandContext(ctx, "git")` (pkg/git/service.go:61).
  - Gitea runs `upload-pack --stateless-rpc` (routers/web/repo/githttp.go:359-390).
  - Both need repos on a local filesystem.
- **Netlify (2026,** https://www.netlify.com/blog/how-we-built-git-storage-for-millions**):**
  - A Go service runs git over a local cache. S3 holds packs and loose objects, and refs are JSON objects written with `If-Match`/`If-None-Match: *`.
  - Invariant: "A ref must not get ahead of the objects it points to".
  - Others, not verified: objgit (Go), walgit, rustic-git, Depot Code, awslabs/git-remote-s3 [search excerpt].
- **Conditional writes:**
  - In S3, the first conditional write wins and later ones get 412 (https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).
  - MinIO has supported If-Match and If-None-Match since February 2023, but conditional PUTs "ignore their conditions when read quorum cannot be reached". The fix, PR #21653, was merged on 2025-10-24 (https://github.com/minio/minio/pull/21653).
  - minio/minio is archived: "THIS REPOSITORY IS NO LONGER MAINTAINED" (GitHub API). minio-go is still maintained.

### 2.10 Deltas, checkpoints and chunking under encryption
- **git packs:** the default window is 10 and depth 50, and objects over `core.bigFileThreshold` get no deltas (https://git-scm.com/docs/git-pack-objects). inference: deltas computed before encryption keep gcrypt-style pushes small.
- **Mercurial revlog:** "Whether to store a full version is decided by how much data would be needed to reconstruct the file" (https://wiki.mercurial-scm.org/Revlog). inference: that is a better trigger than PLAN's fixed "every N commits".
- **restic** (https://restic.readthedocs.io/en/latest/100_references.html):
  - Rabin chunking with a random per-repo polynomial; blobs of 512 KiB–8 MiB, averaging 1 MiB.
  - AES-256-CTR with Poly1305-AES; blob IDs are SHA-256 of the plaintext, kept inside encrypted headers.
  - Chunk sizes reveal the polynomial. 0.18.0 mitigated this by placing chunks into pack files at random.
- **borg** (https://borgbackup.readthedocs.io/en/stable/internals/security.html):
  - Keyed-MAC chunk IDs and a secret chunker seed, but it "does not hide the size of the chunks".
  - With several clients "a repository can trick a client into reusing counter values", and then "Borg fails to provide confidentiality".
- **casync:** unkeyed buzhash with SHA512/256 digests (README:63-65).
- **Tarsnap:** the server sees block sizes. Version 1.0.41 mitigated a parameter-extraction attack (https://www.daemonology.net/blog/2025-03.html).
- **2025 attacks:** ePrint 2025/558 (CCS 2025) recovered the keys of the keyed chunkers in Borg, Bupstash, Duplicacy, restic and Tarsnap, and proposed a provably secure construction. ePrint 2025/532 is a second paper on the same problem.
- **Fixed-size blocks** avoid boundary leakage but lose deduplication of shifted content: Proton 4 MB, Dropbox 4 MB, Cryptomator 32 KiB, gocryptfs 4 KiB. The last two bind the block index into the associated data.

### 2.11 Revocation and re-wrap in deployed E2EE storage (claim check)
- **KBFS:** "Don't bother to reencrypt old blocks". Each device's wrapped key is XOR-masked by a server-held half, which is deleted on revocation (https://book.keybase.io/docs/crypto/kbfs).
- **Keybase teams:**
  - Seed `s_i` is encrypted under `c_{i+1}`, so newer keys unlock older ones, and rotation "can happen lazily" (https://book.keybase.io/docs/teams/crypto).
  - The servers delegate rekeying to online admins "one at a time" (https://book.keybase.io/docs/teams/clkr).
- **Tresorit:** removal creates a new folder key, and uploaded content is not re-encrypted [search excerpt of support.tresorit.com/hc/en-us/articles/216114387; fetch 403].
- **Dropbox:** rotation makes leaked keys "obsolete for accessing new or modified encrypted data" [search excerpt of the 2024-06-05 dropbox.tech post].
- **Apple ADP:** "new data written to the service can't be decrypted with the old service key" (https://support.apple.com/guide/security/sec973254c5f/web).
- **Nextcloud:**
  - Each sync re-encrypts the metadata, including all file keys, under the newest metadata key. That is genuine client-side lazy re-wrap.
  - Revocation issues a new metadata key to the remaining users (Albrecht et al. 2024, §1.2).
- **Cryptree and Peergos:** revocation requires re-encryption.
- **git-remote-e2ee:** no historical changes (§2.7).
- **Prior art:** Plutus introduced lazy revocation, and "Key Regression" (Fu, Kamara and Kohno, NDSS 2006, https://eprint.iacr.org/2005/303) formalized it.
- **Verdict:**
  - Forward-only revocation: confirmed as near universal.
  - Client-side re-wrap: one variant (Nextcloud). Rotate-and-chain is more common.
  - MLS exporters in deployed storage: refuted; no example found.
  - PLAN's proxy re-encryption column (sidecar/PLAN.md:284-327) also has no deployed precedent.

### 2.12 Attack literature and pitfalls
- **ETH CCS 2024** (Hofmann and Truong, ePrint 2024/1616, https://brokencloudstorage.info/), covering Sync, pCloud, Icedrive, Seafile and Tresorit:
  - key replacement, because public-key encryption has no origin authentication;
  - key overwrite through malleable CTR;
  - file injection;
  - unauthenticated CBC and chunking (reorder, truncate);
  - tampering with names and metadata;
  - a KDF downgrade;
  - forged shares.
- **Nextcloud, EuroS&P 2024** (ePrint 2024/546; CVE-2023-28997, -28998, -28999):
  - Key insertion: the server plants a chosen key and triggers the client's rotation.
  - Ghost key: an unvalidated index makes the client use an all-zero key.
  - AES-GCM IV reuse on modified files.
- **Formal models:** CRYPTO 2024 (ePrint 2024/989), with an adaptive-corruption follow-up (EUROCRYPT 2026, ePrint 2026/434).
- **Pitfalls for evs** (inference, from the facts above):
  1. Authenticate every rotation and re-wrap input with a member signature.
  2. Reject a missing key or epoch; never default it.
  3. No (key, nonce) reuse across edits or writers. Use XChaCha20 random nonces or salted per-object keys, and never counters coordinated by the server (Borg).
  4. Bind object ID, chunk index and path into the associated data.
  5. Sign manifests and pin the last-seen head against rollback and forks. `epoch_authenticator` can expose a forked group.
  6. git-crypt: files added before `.gitattributes` stay plaintext, and tampered output is written before the error.
  7. MLS: one Commit per epoch; no Welcome before acceptance; republish GroupInfo after each Commit, since `external_pub` changes every epoch (inference from §8.3); evict idle members; use each KeyPackage once.
  8. A server-held handshake log plus long-lived data means harvest-now-decrypt-later exposure. Use a post-quantum suite.

### 2.13 Local code facts that bear on evs
- **PLAN layout:** sidecar imports connect only (sidecar/PLAN.md:7). The Sidecar struct holds the JWT, connect client, API and "encryption key" (sidecar/PLAN.md:14). It runs in the extension as a web worker (sidecar/PLAN.md:28).
- **Toolchain:** Go 1.27.3 (connect/go.mod:3, sdk/go.mod:3) and x/crypto v0.54.0 (connect/go.mod:30).
- **Connect identity:**
  - `ClientKeyManager` holds a long-lived Ed25519 identity whose private half "never leaves" (connect/transfer_key.go:17-68).
  - The platform is "not trusted to honestly distribute" keys (connect/transfer_key.go:30).
  - The key is published as `protocol.ClientKey` (connect/protocol/transfer.proto:780). It is served unauthenticated at `/key/<client_id>` (connect/api.go:540-559), with a signed history at `/key/<client_id>/history` (connect/operator_client_settings.go:147).
- **Key history verification:** `VerifyClientKeyHistory` checks operator-signed, hash-chained records (connect/transfer_key_history.go:422). It "does not stop an operator that is malicious from a client's first contact" (connect/transfer_key_history.go:22-26).
- **Post-quantum transport:** connect's TLS already prefers `X25519MLKEM768` (connect/transfer_encrypt.go:382-385).
- **Server blob store:**
  - MinIO-backed, with "deliberately no Delete" (server/blob.go:155-183).
  - `PutIfAbsent` uses `SetMatchETagExcept("*")` with `DisableMultipart` (server/blob.go:683-697).
  - Dependencies: minio-go v7.2.1 (server/go.mod:29) and pgx v5 (server/go.mod:25).
- **Deployed MinIO:** pinned to RELEASE.2025-10-15T17-29-55Z, commit 9e49d5e (xops/main/ansible/playbook-minio-clusters.yml:36-37). The GitHub compare API shows it is 5 commits behind fix commit 18f97e7, so the fix is absent.
- **Load balancer:** defaults are `client_max_body_size 16m`, request buffering on and 30 s proxy timeouts (warp/warpctl/config.go:1301-1320). The `streamable` mode turns buffering off and allows 60 s (warp/warpctl/config.go:2302-2320; warp/services/services.go:692,922).
- **GKM:** appears only at sidecar/PLAN.md:53, with no definition anywhere in server, connect, sdk or warp.

## 3. Constraints the design must respect
1. MLS and all new evs crypto live in the sidecar repo, which imports connect but not server or sdk (sidecar/PLAN.md:7; owner rule). The DS and storage server side lives in server.
2. Pure Go only, with no cgo, because the browser build has `CGO_ENABLED=0` (sdk/js/Makefile:69; sdk/dependency_boundary_test.go:84,512).
3. There is no git binary in wasm or on mobile, so client-side git there means go-git v6 or no git at all.
4. Exactly one Commit per epoch, and no Welcome before acceptance (RFC 9420 §14). Use an atomic first-writer-wins step: a database unique key, or object-store conditional writes once the MinIO fix is deployed.
5. "signed membership stops a breached server adding a reader" and storage that holds "no key" (sidecar/pitch5.html:745):
   - server ACLs and external-sender proposals cannot be the root of membership;
   - external joins need admin-signed policy;
   - basic credentials need binding through connect's key registry plus pins.
6. Use a unique exporter label, and keep a persistent epoch-key history for new members.
7. Erasure is planned through per-entry DEKs (verifiable_record_tech.md:425-436). Deterministic per-epoch encryption cannot shred one entry.
8. Users must be able to export a plain git repo (sidecar/improve.md:153), and the metadata the servers can see must be published (sidecar/improve.md:116).
9. Choose cipher suites for wasm, where AES is table-based, and post-quantum for long-lived data.
10. Pushes over 16 MB or longer than 30 s fail at the load balancer unless the service is `streamable` with raised limits (warp/warpctl/config.go:1301).
11. BlobStore has no Delete (server/blob.go:158), so GC, repo deletion and erasure need a new capability.

## 4. Reusable pieces (exact names)
- **Go standard library:**
  - `crypto/hpke`: `NewSender`, `NewRecipient`, `Seal`, `Open`, `Sender.Export`, `KEM.DeriveKeyPair`, `DHKEM(ecdh.X25519())`, `MLKEM768X25519()`.
  - `crypto/hkdf`, `crypto/mlkem`, `crypto/mldsa`, `crypto/ed25519`.
  - `golang.org/x/crypto/chacha20poly1305.NewX`.
- **connect identity:**
  - `connect.ClientKeyManager.{PublicKey,Sign,Seed}` (connect/transfer_key.go:197-221).
  - `connect.VerifyClientKeySignature` (connect/transfer_key.go:351).
  - `BringYourApi.GetClientKey` and `GetClientKeySync` (connect/api.go:548,561).
  - `connect.VerifyClientKeyHistory`, `ClientKeyRegistration`, `ClientKeyPin` and `ClientKeyHistoryPolicy` (connect/transfer_key_history.go:200-422).
  - `PeerClientKeyPinStore` and `CheckedPeerClientKeyPinStore` (connect/transfer_key_history_session.go:76,94), for credential binding and pins.
- **Server side:** `server.BlobStore.PutIfAbsent` (server/blob.go:166), `RetainedBlobStore` (:198), `VersionedBlobStore` (:223), and pgx for a unique (group_id, epoch) key.
- **go-git v6:** `transport.UploadPack`, `transport.ReceivePack`, `transport.ReceivePackHooks`, `transport.MapLoader`, `storage.Storer`, `storer.ReferenceStorer.CheckAndSetReference`, `memory.NewStorage` and `memfs.New`.
- **Fork candidates (MIT):**
  - github.com/thomas-vilte/mls-go: `Client.Export`, `ExternalJoin`, `CommitPendingProposalsStaged`/`ConfirmPendingCommit`.
  - github.com/tmc/mls: `NewClient`, `Group.Commit`.
- **Test vectors and specs:** the mlswg vectors (https://github.com/mlswg/mls-implementations), with draft-sullivan-mls-attachments-01 as an exporter-to-CEK recipe.
- **Load balancer:** warp `services.ServiceConfig.Streamable` (warp/services/services.go:692).

## 5. Gaps, risks, surprises
- **PLAN statements to correct:** the "almost universal" claim (sidecar/PLAN.md:47,329,335) and the catch-up text (sidecar/PLAN.md:174) are wrong as written.
- **Key model:** "one session key stored in GKM" (sidecar/PLAN.md:53) conflicts with epoch rotation, and GKM is undefined.
- **MLS candidates:** all Go options are unaudited with a single maintainer, and tmc/mls is 6 weeks old.
- **MinIO:** upstream is archived, and the deployed build lacks the conditional-PUT quorum fix. That breaks CAS-based ordering, and also affects today's `PutIfAbsent` callers.
- **go-git v6 server:** still beta, with no partial clone or `object-info`.
- **Pitch conflict:** plaintext paths conflict with the pitch's "metadata listed here", because every path would be on that list.
- **Welcome size:** about 0.5 KB per member classical and about 2.6 KB per member post-quantum (inference), so large teams need the tree sent out of band.
- **New ground:** no source covers MLS bound to a git DAG. Fork and rollback handling, and the encrypted path index, are new designs that need review.
- **Not verified:** Tresorit's documentation, the full text of Grappa (403), and go-git performance on S3.

## 6. Open questions for the owner
1. Is leaking paths, sizes and commit metadata acceptable for recURd and for burner email? The answer decides between the git-crypt model and opaque packs.
2. Must the storage service speak standard smart HTTP to third-party git clients, or is a sidecar remote helper plus an object API acceptable?
3. Should there be one MLS group per repo, or per team/network with per-repo exporter context? And what is "GKM"?
4. Who authorizes membership: admin-signed policy, a visible audit member or escrow (sidecar/improve.md:106-107), or server ACLs?
5. Which cipher suite: classical 0x0001 or 0x0003, or post-quantum 0x0010 or 0x0020? 0x0020 suits wasm but uses ML-DSA, so it cannot reuse connect's Ed25519 key.
6. Fork thomas-vilte/mls-go or tmc/mls into the sidecar repo, or build a narrow implementation? What audit budget?
7. Is per-entry crypto-shredding required in v1?
8. Keep a self-built MinIO, which is archived and needs a patch, or move to AIStor or another S3 store? Should DS ordering use Postgres?
