# DESIGN review 1 — Astra

**Review date:** 2026-11-04. **Source:** `DESIGN.md`, draft dated 2026-11-03, 9,256 lines / 149,977 words, SHA-256 `12aba8d565bd630e0f8ef6ba2424a9a130d228f9b8f9ee9e99d0fdd1d1b7269c`.

**Status:** Final consolidated REVIEW1. Three independent Astra specialty reviews and an additional runtime/build pass are incorporated. No REVIEW2 or cross-model input was used.

## Assessment

The architecture has a sound organizing principle: customers hold content and policy authority; server services route, order and store encrypted objects; the SDK and daemon adapt that core to different hosts. The document carries this principle unusually far into schemas, metadata disclosures, service boundaries, recovery procedures and release gates. Its owner decisions are sufficiently explicit to review the design without reopening every tradeoff.

The current design nevertheless is **not ready to freeze the M2 authorization, MLS or evs formats**. Several independent counterexamples break core promises: two different authorization histories can look identical to a witness; a completed old rotation can satisfy a new revocation; consistent stale peers can renew a nominal freshness bound indefinitely; disjoint Git pushes cannot acquire the proposed shared-ref semantics without changing their commit identities; and cleanup after an uncertain object-store result can delete a committed push's dependencies. Recovery, path migration and irreversible deletion also need explicit state transitions.

Runtime integration adds two important M3 blockers: whole-tree scans cannot establish ownership of changes for safe run-confined restore, and single-use approval signatures lack a durable consumption protocol across crashes and retries. Host approval availability, SDK token/identity state and browser/wake lifecycle contracts also need correction.

The edge/mail work contains separate feature blockers. A missing ALPN can select the raw path around HTTP audience enforcement; the proposed customer CNAME permits an active operator to supersede the customer's CAA account restriction; the strict direct-MX path does not consistently move DNS authority to the customer; and the outbound SMTP proof omits a server-state precondition that determines whether its purported body is actually parsed as SMTP commands. Revealing the TLS 1.2 server record key creates a separate integrity problem even with a sound client-transcript proof.

These are design findings, **not reports of deployed incidents or failed implementation tests**. DESIGN.md explicitly says the system is unimplemented. Most can be corrected within the existing architecture. The review does not recommend putting plaintext at the edge, replacing the object-store constraint with a database, abandoning in-house MLS, adding an off-site server copy against the owner's decision, or making an external audit a new release gate.

## Method, scope and interpretation

Three Astra reviewers independently examined trust/authorization/key management, storage/protocol/distributed correctness, and DNS/TLS/mail/abuse. The trust reviewer then performed an additional runtime/build pass without reading the other specialist reports or the consolidation. Consolidation followed the completed passes, rechecked concrete candidates against the source, merged duplicates, and distinguished defects from open decisions. No REVIEW2 artifact or Sol review was consulted. The source fingerprint above identifies every line reference in this report. The completed specialist reports are working evidence, not implementation tests.

Coverage spans the owner directive, decision/question registers, §§1–23 and corresponding appendices, with focused depth in each specialist domain. The additional pass covered §§16, 18, 22 and 23 in full and relevant bridge, lifecycle, host and build seams. Primary standards and selected upstream source were checked for the external claims used below; targeted local checks also examined SDK authentication events and release-module rewriting. This is a design review with source checks, not an exhaustive audit of every cited dependency or platform. No benchmark, exhaustive dependency audit, source fix, source edit, commit or Git identity change was performed. The user-supplied AGENTS.md rules were observed; no additional applicable ancestor AGENTS.md was found.

**Priority:** P1 blocks the affected format, invariant or feature claim. P2 is a concrete reliability, interoperability or disclosure issue to resolve before promising that behavior. “Specification blocker” means contradictory or missing normative detail with a concrete unsafe implementation permitted by the text; it is not a claim that unseen code has chosen that implementation. Confidence is stated separately. Every finding includes a deterministic acceptance scenario for eventual implementation. Tests described here are proposals, not invented test results.

## Architectural assessment and strengths

The dependency direction `sidecar → connect`, with `server` and `sdk` importing sidecar, is appropriate. Keeping server engines in child packages and defining host interfaces protects the core from server infrastructure and mobile/worker glue. The explicit Required transport and identity/admission checks are materially stronger than relying on encryption without first-contact key binding. These boundaries should survive the implementation.

Immutable signed pushes plus a conditional ref head are useful building blocks for object-only ordering. They provide a single-key commit point; the missing work is to define how authorization changes, preparations, cleanup, indexes and lifecycle transitions relate to that point. The MinIO conditional-read-quorum fix cited in the design is real, but does not create a transaction across those objects. [MinIO PR #21653](https://github.com/minio/minio/pull/21653).

The MLS design correctly separates encrypted handshake delivery from customer authorization, publishes Welcomes only after the winning epoch, authenticates the historical key ladder, and recognizes that pruning epochs requires resync or recovery. A per-repo group makes the authorization domain understandable. The problems below concern exact state identity and recovery transitions, not the chosen owner-approved group granularity or suite.

On the edge side, per-device TLS keys, customer TLS termination, DANE usage 3 with a pinned SPKI, no plaintext fallback, and a receive-only burner launch provide useful boundaries. The design also handles wildcard-MX/CNAME incompatibility and empty non-terminals explicitly. Its metadata inventory, single-site loss disclosure, offline-grantor limitation and internal review gates are valuable. The remaining claims must be brought into agreement with those mechanisms.

The two-role SDK architecture keeps content/MLS keys out of privileged network processes, and the common outward-action gate is the correct integration point for MCP, CLI, SMTP and SDK callers. The release design also has concrete dependency, protobuf, Cgo and size checks. Its source already supports rewriting development modules into versioned release modules; the apparent unversioned-to-`/v2026` mismatch is not a standalone defect. [Release rewrite implementation](/Users/brien/urnetwork/build/all/run.sh:1899).

The test strategy already chooses appropriate tools: injected clocks, real MinIO and Redis Cluster conformance, crash injection, history checking, a TLA+ model, and a site-loss drill. Those gates need the explicit adversarial schedules below. A model that treats the entire proposed Push as one atomic action would prove the wrong abstraction.

## Findings that block formats or affected security claims

### F01 — Authorization state needs both a delta-prefix commitment and a causal revocation identity

**P1; high confidence.** Evidence: §7.9, lines 2990–2994 and 3019–3021; §6.5, lines 2510–2519; §8.8, lines 3367–3390; §10.4, lines 3907–3913; §10.9, lines 4095–4109; §11.6, line 4333; §11.8, line 4452. [Projection and delta format](/Users/brien/urnetwork/sidecar/DESIGN.md:2990).

There are two distinct failures caused by incomplete identifiers.

First, the projection base is hashed, but `ProjectionDelta` has only base version, sequence and statement; HeadCheck compares the base hash and delta count. A malicious API/store can give two peers the same signed base and equal-length prefixes containing different valid signed scoped statements. Put a socket-grant revoke in one prefix and an unrelated statement in the other, leaving config and MLS epochs unchanged. Direct authenticated HeadCheck reports identical pins and refreshes the witness, although one listener continues honoring the revoked grant. A signature proves who signed a statement; a count does not commit to which statements a peer applied. Conditional writes on an honest store do not constrain the malicious operator in this threat model.

Second, MLS headers and the evs gate retain only `projection_version`. Under base 10, delta 1 removes X and generation 7 rotates while Y remains a reader. Delta 2 then removes Y without advancing the base. Generation 7 already satisfies the specified condition “first rotating generation whose projection version is at least 10,” although Y knows RK_7. A scheduled rotation before either removal can fail similarly. Timed grant expiry can shrink the reader set without changing even the delta count. An up-to-date honest client's own sealing check does not make the server's promised 412 behavior correct for delayed writers or depositors.

**Correction:** Define one canonical authorization-state identifier: base version/hash, applied delta sequence and prefix hash, plus explicit semantics for time-based transitions. Hash each exact signed delta with its predecessor and base identity; make a folded base commit to the exact folded prefix. Carry the same state identity in HeadCheck, MLS authenticated data, generation statements, pushes and gates. Tie the required generation to the specific reader-set shrink, not an older rotation with a numerically adequate base version. Define duplicate, rebase and expiry behavior.

**Acceptance:** Give two peers different valid delta prefixes with equal length and equal config/MLS state; their witness must fail and preserve evidence. Apply two removals under one base and rotate only after the first; a write or deposit at that generation must fail until a rotation covering the second removal is accepted. Repeat with a scheduled rotation before removal and an expired grant. These cases are independent of the pending leaf/wrap and committer choices.

### F02 — v0 witnesses do not exchange ordinary evs ref heads

**P1; high confidence.** Evidence: §6.4–6.5, lines 2472 and 2510–2519; §6.11, lines 2712–2713; §11.8, line 4454; I-16, line 1207. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2472).

Two honest devices can fully replay different valid evs chains for the same ordinary ref while retaining identical config, projection and MLS state. Each locally pins its own `(ref, version, C_v)` and sees no rollback. When they connect directly, v0 HeadCheck exchanges config/projection and MLS epoch information, not those evs ref pins, so it reports consistency. The `EVS_HEAD_CHECK` pair that could perform this comparison is explicitly deferred to v1, while §11 says §6 already compares the pins.

An MLS epoch authenticator authenticates group state, not all writes made during that epoch. Local pins only help if a client is shown conflicting history. This is separate from Q-EVS-6: both clients in this counterexample replay every push.

**Correction:** Include bounded, authenticated comparisons of `(repo_id, ref_id, version, chain)` in v0, with paging if needed. Specify shared-ref discovery, extension proofs when versions differ, and witness scope. A witness for a config head or MLS epoch must not refresh a storage-ref freshness marker it did not check.

**Acceptance:** Serve two valid sibling chains at the same ref version, with all config and MLS bytes identical. Connect peers through the authenticated transport and run the scheduled check; require a fork alarm. Repeat with unequal versions where neither chain extends the other.

### F03 — Mutually stale witnesses cannot establish the claimed 24-hour revocation bound

**P1; high confidence in the counterexample; the correction requires an explicit availability/freshness choice.** Evidence: §2.10, line 1219; D-TRUST-10, line 1257; §6.4/6.6, lines 2472 and 2564–2568; §7.9, line 3021; §22.7, lines 7736–7737. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:1219).

After the administrator removes X, the server withholds the transition from honest writers A and B but permits their direct authenticated communication. Both retain the same old reader set, MLS epoch and encryption generation. Every hourly HeadCheck succeeds against the other and refreshes `witnessed_at`. They can continue publishing material X can decrypt indefinitely; neither forges anything. Sampling four peers changes probability, not a deterministic bound, unless the peer-selection and reachability assumptions force contact with current authority. A removed or colluding reader still present in the withheld view can also act as the consistent witness.

The present timeout detects a lone isolated device, not an isolated cohort. Agreement about old signed state is not evidence of new authorization. MLS itself leaves suppression/loss detection to the application. [RFC 9420 §16.9](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.9).

**Correction:** Either disclose the actual unbounded withholding residual, or introduce expiring, causally fresh authorization attestations from a required customer authority or an explicitly defined intersecting witness quorum. Repeating an old attestation must not renew its expiry. Preserve customer-held authority and ciphertext-only servers; state the resulting offline-write availability cost rather than hiding it in the witness algorithm.

**Acceptance:** With an injected clock, keep A↔B operational while delivering the removal only to the administrator. Run every scheduled witness past 48 hours. To retain the 24-hour claim, A/B must stop new encryption despite matching each other. Otherwise the claim and test must explicitly accept this continued-write behavior.

### F04 — All-devices-lost recovery has both a bootstrap gap and a multi-leaf dead end

**P1 for the advertised recovery flow; high confidence.** Evidence: §5.6/5.9, lines 2254–2262 and 2321; §7.8–7.9, lines 2915–2928 and 3025; §10.6–10.9, lines 3972, 4062, 4074–4077 and 4101–4109; §10.14, lines 4188–4197. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2254).

The code promises to recover a member who has lost every device, but the new device has no specified way to fetch the RecoveryBind, recovery wrap and sealed group information before admission. The declared routes use Client/service authentication and token exchange refuses an unadmitted sidecar. Even normal account login does not itself resolve this admission/key bootstrap. A narrow recovery bootstrap capability may be intended, but is absent from the protocol.

After bootstrap, consider a private group containing lost leaves A and B, with no surviving member state. The specified flow admits recovered device R, revokes A/B and self-joins by external commit. R is not an existing leaf and cannot make an ordinary member Remove commit. An MLS external commit permits at most one Remove, for a qualifying prior appearance of the joiner; it cannot bulk-remove arbitrary lost devices. Leaving either revoked leaf in the resulting tree violates the design's roster-subset requirement. Possession of RK_g and public GroupInfo does not recreate the old leaves' MLS private state. [RFC 9420 §12.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-12.2).

**Correction:** Specify a proof-of-possession recovery fetch/admission protocol, its identifiers and trust anchors, and its veto/revocation behavior. Add an authorized group-reformation path for ordinary all-devices-lost recovery, linked to the old generation commitment and historical ladder, rather than reserving reformation for site loss or a bad commit. Joining first and then removing old leaves may handle one ordered flow, but does not cover a crash after their revocation or a preexisting revoked roster; the recovery state machine must cover those states too. This can preserve one group per repo and the selected MLS subset.

**Acceptance:** Start with an empty device filesystem, only the documented recovery code and permitted account credentials, two lost leaves and no returning device. Record every requested credential. Recover history, reach a writable current group, and prove old keys cannot open new data. Crash after each admission/revocation/reformation step and resume idempotently. Do not count a hidden logged-in old sidecar as successful recovery.

### F05 — Ephemeral-device restrictions conflict with the effective ACL calculation

**P1 specification conflict; high confidence.** Evidence: §7.7–7.8, lines 2899–2902; §8.4–8.6, lines 3219, 3280–3284 and 3292–3324. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2899).

The prose says ephemeral devices deposit only unless explicitly granted read. The effective-policy rules let untagged devices inherit the owner's subject atoms, give member/admin subjects implicit general-repo access, and give an owner's untagged devices vault/mailbox read/write. The final union and hard-deny list has no ephemeral exception, and the schema does not require every ephemeral device to be tagged.

A newly admitted untagged ephemeral sidecar therefore inherits a member's implicit read privileges under the stated calculation; MLS membership/wrap generation then follows those readers. The prose restriction shows the intention, but supplies no precedence or executable predicate that makes the two rules agree. This is a contradiction to fix before implementation, not a claim that code has already chosen the permissive interpretation.

**Correction:** Define device class before subject expansion. Make ephemeral inheritance and the meaning of “explicit grant” normative; exclude implicit owner/member grants when the restriction requires it. Preserve the separate explicit decision that every admitted sidecar can read config. Apply the same calculation in clients, projections, tokens and MLS reader construction.

**Acceptance:** Enroll an untagged ephemeral device under both a Member and an Admin, with no explicit data grant. It must receive only the intended deposit/config capabilities and no data-generation keys. Add and remove an explicit read grant and check the precise transition. Run the same cases with tags and Delegations.

### F06 — Rotating a compromised recovery code does not retire every key it exposed

**P1 for new-name confidentiality; medium confidence for the additional content-chain risk.** Evidence: §5.9, line 2321; §10.5, lines 3954–3966; §10.8, line 4076; §11.6–11.7, lines 4292–4305, 4316–4319 and 4360. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2321).

The recovery code unwraps archive generations. `recovery-rotate` deletes old wraps and asks for a `request` rotation, while path epochs advance for removal/compromise causes, and mandatory fresh full checkpoints are keyed to `remove`. An attacker who already used the leaked code retains the old RK and path key; deleting its wrap cannot make that knowledge disappear. New filenames can continue using the old path key after the advertised code rotation. The permitted reuse of an inline-chain object key also leaves a potential new-content exposure unless every relevant generation transition forces a fresh key; the text does not make that rule explicit.

**Correction:** Treat recovery-key compromise as a confidentiality boundary for all derived domains it exposed. Rotate the path key and require a fresh object key/checkpoint on the first later write to an affected chain, while retaining the owner's lazy treatment of old content. State separately what a code rebind does when no compromise is suspected, and what retained local keychain backups can still reveal.

**Acceptance:** Let an attacker use the old code before rotation and retain every recovered key. Rotate it, create a new filename and append to an existing inline chain. With server-visible metadata and the old keys, the attacker must fail the selected new-name/new-content guarantees. Old history remaining readable is the accepted lazy-rewrap behavior, not a test failure.

### F07 — The proposed Git bridge cannot preserve Git semantics under disjoint or multi-ref pushes

**P1 for single-ref semantics; P2 for the additional receive contract; high confidence.** Evidence: §11.6–11.8, lines 4326–4339, 4358, 4422–4433 and 4454; §11.11, lines 4468–4487; §11.14, line 4553; §22.9, line 7760. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4326).

Start with C0 containing `a=0,b=0`. P and Q both have parent C0; P changes a, Q changes b. P wins the head CAS. The server retries and accepts Q because its changed paths are disjoint. Pointing the ref to Q drops P from the ref's ancestry and restores `a=0`. Combining Q's delta with P yields a tree different from Q's signed Git object. A merge/rebase requires a new client-created commit and ID; a ciphertext-only service cannot manufacture it while preserving the original push. Keeping all objects does not make a non-fast-forward a fast-forward. The later reader OID/descent checks detect the inconsistency after acceptance. [Git push: fast-forward definition](https://git-scm.com/docs/git-push#_note_about_fast_forwards).

There is a second boundary: EvsPush names one ref, but one `git push` may update A and B. A pre-receive hook can commit A remotely and then fail B; returning nonzero rejects all local ref updates even though remote A changed. Returning success cannot faithfully reject only B through that hook. System Git advertises atomic pushes by default, while the design has separate per-ref commit points. A remote-success/local-ref-lock failure also needs reconciliation. [Git pre-receive hook](https://git-scm.com/docs/githooks#pre-receive), [receive.advertiseAtomic](https://git-scm.com/docs/git-config#Documentation/git-config.txt-receiveadvertiseAtomic).

**Correction:** Make a shared Git ref use an expected-ref CAS, returning a conflict for any intervening ref change; any automatic merge must be a new client-authorized commit. Keep independent agent refs for concurrency and specify different semantics for file-update streams if desired. Declare supported receive capabilities. A narrow v0 can disable atomic advertisement and reject unsupported multi-ref combinations before any remote mutation; broader support needs per-command durable outcomes or a real object-only multi-ref transaction. Journal remote/local reconciliation.

**Acceptance:** Race P/Q and compare exported tips, full trees and parent chains, not just `git fsck`. Push A/B together while B conflicts after A's remote success; verify statuses and both copies under the declared contract. Test `--atomic`, local installation failure and daemon restart at that boundary.

### F08 — Ambiguous head-commit outcomes must never enter ordinary cleanup

**P1; high confidence.** Evidence: §11.8, lines 4428–4441; §22.8, lines 7751–7754. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4428).

MinIO accepts a staged push's conditional head PUT, but its response is lost. Step 7 treats “any failure” as permission to remove what step 5 wrote. Deleting the push, index version or key slot now breaks an already committed head, potentially irrecoverably if the slot was the only key copy. Repeating the same If-Match after an accepted but unacknowledged write can return 412; that response does not prove the logical push never committed. A retry that treats its own commit as a conflict has the same problem.

Immutable objects, single-key CAS and invisible-orphan rules do not resolve an uncertain outcome. §22 promises retries adopt their own commit, but §11's failure algorithm does not implement that promise.

**Correction:** Define durable outcomes keyed by `(repo, ref, push_id, statement_hash)`. Resolve an uncertain result against committed history, including retries older than the head window, and return the original success/version for an already committed push. Retain preparations while the outcome is unknown. Fence abort and GC so a delayed request cannot commit reclaimed dependencies; conditional cleanup must preserve other writers' entry versions and directory state.

**Acceptance:** Apply the head PUT, return a synthetic timeout, restart evs, retry on another instance and run GC. Require exactly one version, the same success result and a complete decryptable dependency closure. Repeat while quorum reads are unavailable: uncertainty must prevent cleanup, not trigger it.

### F09 — The revocation gate and the ref commit point are separate, unfenced objects

**Conditional P1 if gate closure must fence commit-time publication; otherwise P2 contract clarification. High confidence in the race.** Evidence: §11.8, lines 4385–4387, 4422–4433 and 4452; §8.12, lines 3432–3434; KF4, lines 4052–4060. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4385).

Writer W validates generation 5 and pauses after its final gate check. Removal closes `repo/<repo>` at generation 6. W resumes its conditional PUT to `head/<repo>/<ref>`, whose ETag has not changed, and succeeds with generation 5. No malicious server or stale cache is required. Rechecking the repo immediately before the PUT merely narrows the window.

A linearizable system may deliberately order an overlapping write before a removal; that is a legitimate contract if stated. Here the document separately names the head PUT as the commit point and says the closed gate returns 412 before accepting the next write. Those claims need a defined answer for the paused request. The client checked before learning the removal, so the primary client rule does not settle it.

**Correction:** Choose and document the removal/write linearization contract. If already authorized in-flight writes may publish, name and bound the exception and adjust claims/tests. If gate closure must fence them, include the minimum authorization/generation in the CAS decision for every ref, with a protocol that also fences new-ref creation, or another explicit object-only barrier. A second GET is not a transaction.

**Acceptance:** Pause after the last gate check, complete gate closure, then resume the head CAS. Require the chosen result; under the current 412 claim the old write must remain uncommitted. Repeat for deposits, new refs and two evs instances.

### F10 — Path-epoch cutover lacks a complete snapshot and overlap protocol

**P1; high confidence.** Evidence: §11.6, lines 4289–4307 and 4342–4352; §11.8, lines 4424–4425 and 4452; §11.9, line 4458; KF4, lines 4052–4060. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4289).

Three related timelines break the transition. First, a removal creates RK_2 and reopens the generation gate, but a desktop may upload the map later. Until PATH_EPOCH commits, new writes still use the ref's old path epoch; a removed member can test those new names with K_path_1. This contradicts immediate token rekeying, independently of the accepted lazy content rewrap.

Second, a map built at head v omits a file created under the old epoch at v+1. PATH_EPOCH contains no ordinary change for that file, the map has no exact source-head binding, and checking only that its parts exist permits a retry at v+2. After copying ends, the omitted file can lose its lookup path. If-None-Match at destination prevents overwrite, not omission.

Third, the specified million-file copy takes about 17 hours. Another compromise can require a new path epoch meanwhile. Reads support “both tokens” and one copy mark, but entries may now physically span three epochs. No composition, serialization or all-live-source rule is defined.

**Correction:** Bind maps to exact source heads and epochs; reject stale publication or incorporate every intervening change before cutover. Define a transition state that uses the new key for new names at the security boundary while preserving old lookups. Compose migrations or serialize cutovers without deferring a required security rotation. Include prefix subscriptions in the transition contract.

**Acceptance:** Snapshot a map, concurrently create and rename files, publish it and finish copying; every committed path/listing must survive. Pause halfway through copying, remove another member and read entries from all three physical epochs. A new filename immediately after the chosen removal boundary must not be derivable with the removed party's retained keys.

### F11 — Restore races irreversible slot deletion

**P1; high confidence.** Evidence: §11.8, lines 4385–4387; §11.12, lines 4505–4515; D-EVS-19, line 4601; §22.5, line 7634. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4385).

Restore reads a restorable `deleted{time,signer}` object. The shred worker deletes slots, leaving the repo object until last. Restore can then CAS that unchanged object back to active, exposing a repo whose keys were irreversibly destroyed. An immediate `--now` shred has the same overlap, and a previously paused worker can continue after restore or a later delete/restore cycle.

Deleting keys first is appropriate for completed erasure; it does not fence a concurrent restore. The legal-hold question is unrelated to this race.

**Correction:** Before deleting any key, CAS `deleted` to a distinct irreversible `shredding{deletion_id,...}` state. Restore competes for that same transition and fails once shredding wins. Fence workers by deletion identity; make restart and duplicate jobs idempotent, and retain a terminal tombstone sufficient to reject stale jobs.

**Acceptance:** Pause restore after its read, let shredding win and delete a slot, then resume restore: reject it. Reverse the order and require the paused worker to delete nothing. Repeat with `--now`, worker restart, duplicate jobs and two lifecycle cycles.

### F12 — ALPN absence selects a raw path without a defined audience check

**P1; high confidence in the dispatch gap, conditional on the unspecified empty-ALPN registration behavior.** Evidence: §9, lines 3609 and 3696; §13.7, lines 5100–5110; §13.10, line 5165. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:3609).

The sidecar TLS front is the component that enforces an HTTP endpoint's audience. The stated dispatcher sends `h2` and `http/1.1` through that front, but sends other declared ALPN values or **no ALPN** to a raw TCP forward. A client can use the correct SNI, omit ALPN and send ordinary HTTP/1.1 bytes to a members-only HTTP backend. Without an additional mode-bound admission rule, this bypasses the cookie/audience gate and its Host checks.

The general sentence that the front enforces audience does not define authentication for the raw branch. If socket discovery is intended to reject an empty ALPN for HTTP registrations, that must be normative and consistent with the explicit no-ALPN dispatch rule. Raw TCP also has no specified members-session mechanism merely because the CLI accepted an audience flag.

**Correction:** Bind the approved registration to HTTP versus raw-TCP mode. For an HTTP registration, no-ALPN clients must go through the HTTP front or be refused; they must never reach the backend directly. For nonpublic TCP, define an independent authenticated admission mechanism or reject unsupported audience combinations at registration. Apply the rule at both lookup and dispatch.

**Acceptance:** Connect to a members-only HTTP endpoint using no ALPN, `http/1.1`, `h2` and arbitrary ALPN values, with and without a session. No unauthenticated variant may reach protected backend content. Repeat for Host/SNI mismatch and explicit TCP registrations. ALPN negotiates a protocol; its absence is not proof that the application is non-HTTP. [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html).

### F13 — The prescribed CNAME defeats the claimed customer CAA exclusion

**P1; high confidence.** Evidence: §2.8 EX1, line 596; §12.8, lines 4854–4858; D-DNS-9, line 4907; §13.8, line 5123; D-TLS-11, line 5197; intended test, line 5236. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:596).

The customer points `app.customer.example` by CNAME at `app.<net>.ur.network`, while its parent CAA pins the customer's ACME account. CAA discovery chases aliases at each queried name and stops when it receives a nonempty relevant RRset. An active URnetwork can add a CAA RRset at the **exact CNAME target** permitting its own account. The CA then uses that RRset instead of climbing the original customer's parent. URnetwork controls routing to the target and can satisfy TLS-ALPN-01; delegated DNS challenges can provide another route. DNSSEC authenticates the operator's target record rather than forbidding it. This is an inference from the specified delegation and the standard CAA lookup algorithm. [RFC 8659 §3](https://www.rfc-editor.org/rfc/rfc8659.html#section-3), [RFC 8657 §3](https://www.rfc-editor.org/rfc/rfc8657.html#section-3).

Precision matters: an empty aliased CAA lookup may still climb the original customer's parent and find its pin. The attack changes the exact target RRset; it does not assert that the honest default always inherits the target parent's policy. A wrong-account test against only honest DNS misses it. CT detection afterward is weaker than the promised exclusion from issuance.

**Correction:** Ensure the RelevantCAASet remains customer-controlled, for example with customer-controlled A/AAAA or an appropriate flattened alias instead of a CNAME into the operator's authority. Otherwise explicitly downgrade this configuration to a detectable issuance risk. Preserve device-held keys and the customer's ACME account.

**Acceptance:** Keep the customer's signed pin unchanged while an adversary controls every URnetwork zone record and edge response. Add target CAA allowing another account and attempt issuance in the ACME fixture. The supported exclusion configuration must reject it. Test both the empty-target and malicious-target cases.

### F14 — Strict direct MX still relies on operator-controlled discovery

**P1 for the strict-mode exclusion; high confidence in the default direct-MX path.** Evidence: §12.8, lines 4852 and 4858; §15.4, lines 5647–5649; D-MAIL strict-mode claim, line 5832; direct-MX API schema, line 4843. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4852).

The direct-MX API installs customer receiver addresses at `mx.<net>.ur.network`; the MX name and TLSA remain in URnetwork's signed zone. Strict mode accepts direct-MX sessions and separately describes customer-zone spliced MX sessions. An active operator can change its own MX/address/TLSA records to an attacker-controlled key and host. A correctly DANE-validating sender then delivers to the attacker before any customer receiver can enforce strictness. Activation-time SPKI probes and DNS/CT watches can detect changes; they do not constrain the authoritative DNS signer. DANE's protection follows authenticated discovery and TLSA authority. [RFC 7672 §§2.2 and 3.1.1](https://www.rfc-editor.org/rfc/rfc7672.html#section-2.2).

If the intention is that the customer-zone requirement covers direct MX too, the direct-MX schema and default naming procedure do not express that. It needs an explicit configuration, not a grammatical implication.

**Correction:** Require customer-controlled signed MX/address/TLSA discovery for every strict path, direct and spliced, including the applicable envelope/bounce-domain setup. Keep the ordinary URnetwork-zone direct MX available with its existing operator-DNS residual; do not label it as excluding that operator.

**Acceptance:** Configure strict direct and spliced receivers, then let an adversary alter all URnetwork-owned DNS and edge routing while customer DNS remains fixed. A validating sender must not deliver plaintext to the substituted host. Test the ordinary direct path separately under its weaker stated guarantee.

### F15 — The outbound proof does not establish that BDAT bytes will be interpreted as data

**P1; high confidence.** Evidence: §14.4, lines 5313–5314; §14.5 E1–E3/Z1–Z6 and the two-proof flow, lines 5364–5383; coverage policy, lines 5391–5394; D-SMTP-16/17, lines 5533–5535. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:5313).

The relation proves the client's EHLO, envelope, `BDAT n LAST`, attribution headers and chunk tail. It does not prove that the actual server's **post-STARTTLS EHLO reply advertised CHUNKING**. In TLS 1.3, the edge has the server handshake secret, not its application secret, so it cannot simply inspect that reply. Honest-client refusal of non-CHUNKING MXs does not constrain a malicious prover.

A modified sidecar connects to an honest STARTTLS server without CHUNKING. The server rejects BDAT and parses subsequent lines as SMTP commands. It can reject the proof-required header lines as unknown commands, then accept commands embedded in the unconstrained purported body: `RSET`, another MAIL transaction, additional RCPTs and a DATA message. The stream can still end with the required tail/QUIT and every client record can be proof-covered. Actual recipients and attribution now differ from the proven fields. The relevant RFC specifically warns that sending BDAT without advertised support makes its data be parsed as commands; STARTTLS also resets prior capability knowledge. [RFC 3030 §2](https://www.rfc-editor.org/rfc/rfc3030.html#section-2), [RFC 3207 §4.2](https://www.rfc-editor.org/rfc/rfc3207.html#section-4.2).

Key binding and record coverage prevent changing proven bytes, but do not establish the receiver's grammar. A CHUNKING census measures coverage, not per-session soundness. A later aggregate-report alarm is not a substitute for the gate.

**Correction:** Include authenticated server capability and transaction-state evidence in the relation/verifier state machine, tied to the same handshake and record sequence without revealing server application keys. Define post-TLS EHLO, PIPELINING negotiation, MAIL/RCPT responses and abort paths before admitting BDAT. Keep the owner-approved BDAT-only gate and receive-only launch sequence.

**Acceptance:** Use a deterministic TLS SMTP fixture that advertises PIPELINING but no CHUNKING and continues after unknown commands. Feed the malicious proven transcript through a modified prover; reject it before body bytes can produce hidden deliveries. Repeat with CHUNKING advertised only before TLS, rejected MAIL/RCPT, a CHUNKING server without PIPELINING, and a valid positive control.

### F16 — Disclosing the TLS 1.2 server record key permits forged delivery outcomes

**P1; high confidence.** Evidence: §14.4, lines 5317–5326; §14.5 E2, line 5365 and lines 5386–5392; metadata smtp-2, line 1047. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:5317).

For TLS 1.2 the edge receives the server write key to verify Finished. That same directional record protection key authenticates later server application records. An active edge can suppress a genuine `451`, withhold the body from the MX, and forge the expected encrypted `250` acknowledgment. The honest sender concludes delivery succeeded and stops retrying. Forged EHLO capability replies are another consequence. Authentication of the original handshake does not prevent a party subsequently given the server record key from impersonating that direction.

The client-transcript proof does not cover truthful server outcomes. This is an integrity failure even if the edge still cannot decrypt the client's message body. TLS 1.2 derives directional record keys used by the record layer; possession allows producing valid authenticated records with the corresponding sequence/nonce. [RFC 5246 §§6.2.3.3 and 6.3](https://www.rfc-editor.org/rfc/rfc5246.html#section-6.2.3.3), [RFC 5288 §3](https://www.rfc-editor.org/rfc/rfc5288.html#section-3).

**Correction:** Prove the server-Finished/key-binding condition inside the relation without disclosing server application record material, or define another mechanism preserving server-record unforgeability. Make bidirectional integrity, not only client-stream soundness and confidentiality, an explicit gate. If TLS 1.2 cannot satisfy it yet, its coverage consequence belongs in the existing outbound launch decision.

**Acceptance:** An honest TLS 1.2 MX returns 451 while a malicious relay tries to substitute 250 using every value the specified protocol gives it. The sender must reject the forgery and retain/retry the message. Include forged EHLO and other transaction-state replies.

### F17 — Pre-approved auth-key bundles need an explicit client-only secret envelope

**P1 specification blocker; medium confidence, not a confirmed implemented leak.** Evidence: §5.6, lines 2256–2261; §7.8, lines 2915 and 2925; §7.9, lines 2978–3002; contrast with invite-fragment treatment at line 2889. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2256).

Pre-approved auth-key bundles include a Delegation private key, but the enrollment sketch sends `{auth_key}` to the API and does not distinguish a server bearer from that client-only bundle. A literal implementation posts admission-signing authority to the server. The operator could then create additional admissions within the Delegation's remaining bounds. The invite flow expressly treats its fragment as client-only; no equivalent split is defined here.

**Correction:** Define a versioned local bundle with separate server bearer, client-only private authority, and trust anchor. Enrollment sends only the bearer plus necessary public claims/signatures; reject a full bundle at the wire boundary. Make diagnostics, SDK/CLI adapters and redaction use the same typed distinction.

**Acceptance:** Put canary bytes in the Delegation private key, exercise CLI/SDK pre-approved enrollment and capture every HTTP request and log. No encoding of the canary may leave the client. The resulting admission must still verify against the intended delegation. This closes a dangerous ambiguity without claiming the designers intended to upload the key.

### F18 — Mirrored recovery and cluster-only slot custody are contradictory

**P1 recovery-format clarification; high confidence in the contradiction, medium confidence about intended mirror contents.** Evidence: §10.5, line 3961; §10.8, lines 4072–4082; §11.8, line 4401; §11.12–11.13, lines 4503–4515 and 4540; §16.8, lines 6136–6142; §19.6, line 6958; §19.10, lines 7015–7020. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:3961).

Record/mailbox object keys live in deletable slots. Operations says slots and wraps exist only in the cluster, while reseeding uploads signed pushes and segments and rebuilds the remainder by replay. A random per-entry key cannot be reconstructed from those ciphertexts or RK_g if its wrapped slot died with the cluster. Conversely, if “mirror in full” includes slots or equivalent keys, those copies exist outside the cluster and erasure/reseed must account for them.

Consider a complete mirror that synced a record but never opened its body or cached its plaintext DEK. Destroy the server buckets. Under cluster-only custody, the mirror cannot recover that record. Under slot-inclusive mirroring, it can, but a stale offline mirror can also reintroduce an erased slot unless erasure reconciliation is defined. This is not a demand for an off-site server backup; device mirrors are already part of the promised recovery.

**Correction:** Enumerate the exact mirrored object/key set and reseed wire format. Distinguish no server backup from no device copy. Define signed erasure tombstones, offline mirror status and reseed reconciliation. Limit erasure claims to the stated cooperative-device/storage assumptions; an authorized or malicious holder cannot be forced to forget a retained key.

**Acceptance:** Recover an unread record body and mailbox message from a fresh complete mirror after bucket loss. Erase one while another mirror is offline, then attempt reseed from that stale mirror. Verify the intended deletion precedence and report unrecoverable/unreconciled states honestly.

### F19 — Whole-tree scans cannot attribute changes safely enough for run-confined restore

**P1; high confidence.** Evidence: §16.7, lines 6047–6059; D-MCP-8, line 6173; R-CTX-16, line 368; M3 exit, line 7887. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6047).

Run A snapshots a shared working tree. Another harness or the person edits file f and creates g. A's unrelated hook triggers a whole-tree scan, which records those differences as A's changes. Nothing changes afterward. `run_restore(A)` then passes the last-scan conflict check, restores f's old bytes and deletes g, undoing work A never performed. This is an ordinary concurrent-use case, not a malicious same-user process or a race after the final conflict check.

Containment checks only the already-misattributed change set. Last-scan hashes detect later edits, not another actor's changes absorbed into the scan. A dry-run helps the person inspect the damage but does not establish the promised run confinement.

There is a related restore-source boundary: content is scrubbed before sealing, and oversized files are captured only by hash/size. Such entries cannot supply byte-exact originals. Without per-path eligibility, restoring from the vault can replace a secret-bearing file with redaction markers or attempt a destructive restoration with no original bytes.

**Correction:** Define exclusive ownership of restorable changes before M3: an exclusive run worktree/capture lease, or operation-level provenance that treats ambiguous modifications as conflicts. Overlapping scans alone cannot prove ownership. Bind execution to previewed before/after hashes and identify non-restorable redacted/hash-only paths. Preserve unrelated work rather than treating it as part of the run.

**Acceptance:** Use two synthetic sessions in one temporary Git worktree. B edits f and creates g between A's start and unrelated scan; restore A without any later writes. B's bytes must survive or the paths must be refused as ambiguous. Add same-file interleavings and manual edits. Capture an original containing a synthetic scrubbed secret and an oversized file; restore must either use an expressly authorized exact local source or refuse mutation, never write redaction markers as original content.

### F20 — Single-use approvals have no durable atomic consumption protocol

**P1 specification blocker; high confidence that the protocol is missing, medium confidence about an implementation's eventual ordering.** Evidence: §5.4, lines 2180–2186, 2226 and 2236; §16.4, line 5941; §16.6, lines 6013–6026; §16.8, lines 6102–6115 and 6135; Appendix G api-10, line 9113. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2180).

A tainted run receives a decision with `uses=1`. The daemon checks its signature, hashes, run, agent and budget, executes an outward action, then dies before appending the approval-use entry or returning a result. The relay reports a retryable failure. After restart the requester presents the same still-valid decision; without durable consumed/reserved state, it can authorize another effect. Two concurrent requests or gate replicas have the analogous check-then-act race. The specified order records use after execution, and records may be batched.

A signed budget does not consume itself; an audit entry written afterward cannot close the crash window. The ten-minute RPC cache is neither durable nor authoritative across sessions/replicas. This finding concerns individual approvals, not a standing grant deliberately authorizing repeated reach over a period.

**Correction:** Give each approval a durable use state machine, keyed by approval/request identity and the existing stable `action_id`. Atomically reserve a use before any effect. Components must execute idempotently under that operation ID or support outcome reconciliation; an uncertain result must not silently free the use for another operation. Burning a use on uncertainty is a defensible explicit policy. Define the shared authority for server-side consumption and the minimal metadata retained, without exposing sealed run/agent/content fields. If approval creates a standing grant, activation must create one stable grant rather than minting a new one on replay.

**Acceptance:** Crash at every reservation/effect/record/response boundary, restart and retry through a fresh session; race two gate replicas. A uses=1 decision authorizes at most one logical action, uses=N at most N. Count effects in a deterministic sink, not merely audit entries. For mail, count stable outbox operations without claiming exactly-once SMTP delivery. A revoked activation must not be recreated by replaying its original decision.

## Additional concrete reliability, interoperability and disclosure findings

### S01 — Four index versions are not tied to committed visibility

**P2; high confidence in the missing invariant; fallback determines severity.** Evidence: §11.7, lines 4364–4377; §11.8, lines 4428–4441; §11.9, line 4458; §11.13, line 4534. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4364).

Four or more staged same-path replacements can evict the only committed entry if “newest four” includes preparations; five can evict a preparation that later wins. Even sequential commits can outrun a reader paused after fetching head H. Old push objects permit reconstruction, so this is **not necessarily permanent data loss**, but no bounded fallback or coherent snapshot retry is specified. An old unchanged file's last push may be arbitrarily far behind the head, outside the advertised window/two pages.

**Correction and acceptance:** Preserve the latest committed value separately from bounded preparations; fence excess/stale preparations, and define read snapshots plus bounded historical locators. Stage five paused replacements, read the committed state, then let the oldest preparation win. Both states must remain readable. Pause a multi-path read, update selected paths five times and require a coherent documented result, never a false absence or mixed snapshot.

### S02 — Repo-wide hint topics use counters that are only monotonic per ref

**P2; high confidence.** Evidence: §6.8, lines 2644–2662; §11.8, lines 4388–4393; §11.10, line 4464; Appendix D, line 8800. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2644).

After processing main=100, a client ignores a valid `evs:<repo>` hint for a new branch at version 1 under the generic topic-version suppression rule. Equal versions on different refs collide, and coalescing can discard the only ref identifier. Hourly resync limits eventual delay but does not meet the live-notification contract. A GKM `pending` event at an unchanged epoch needs similar treatment.

**Correction and acceptance:** Use per-ref topics, a durable repo-wide cursor, or dirty markers that trigger fetching a ref vector without comparing unrelated counters. Make producer updates monotonic under reordered publishers. Publish main=100, B=1, main=101 and B=2 in both orders and through coalescing; every change must be discovered within the live target. A pending removal without an epoch advance must also wake its consumer.

### S03 — Committed-log-only GC cannot find never-committed uploads or reconcile their quota

**P2; high confidence.** Evidence: §11.8, lines 4418–4421 and 4441; §11.13, lines 4534–4538; §20.6, line 7257. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4418).

A client uploads a segment and crashes before submitting a push or flushing buffered usage. No committed log references it. The promised 24-hour orphan collector and nightly quota recount cannot discover it by traversing only those logs, while the design excludes a full scan. Applying age-based deletion to every segment would destroy committed history unless durable adoption is separately represented.

**Correction and acceptance:** Add an object-store allocation/staging journal and durable adoption state, or permit and budget inventory scans. Count the same physical/billable population in GC and quota reconciliation. Upload, crash before push/usage flush, restart with empty memory and advance 24 hours: reclaim or accurately account for the object. Race late adoption with collection and prove no committed head can reference reclaimed data. Coordinate this with F08's uncertain outcomes.

### S04 — A lifetime ref-name key leaks guesses about branches created after removal

**P2; high confidence.** Evidence: §10.5, lines 3954–3964; §11.5–11.6, lines 4281 and 4285. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:3954).

A removed reader retains RK_1/K_ref. Months later it can compute a guessed new branch's ref ID and test its existence with a colluding server, because the key never rotates. The stated name-leak bound to names created before removal is therefore false for branches even after a correct path rotation. Tracking already-known files through a map is a separate, disclosed residual.

**Correction and acceptance:** Publish the permanent branch dictionary-test leakage, or use fresh opaque IDs/current-generation name catalogs or a creation-generation derivation that preserves old physical history paths. Retain all removed-member keys, create a new branch after rotation and test guesses against server-visible metadata. The outcome must match the selected privacy claim.

### S05 — Two-host read availability needs a fully protected-object precondition

**P2; high confidence for the stated degraded-write sequence.** Evidence: §19.6, lines 6935–6956; Q-OPS-1, line 7092; §22.8–22.9, lines 7752–7763. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6935).

On the eight-drive EC:4 metadata set, host A's two drives are offline. A write succeeds on five drives, with one drive of surviving host B failing that write. Before healing, host C fails. Four drives remain online on B/D, but only three hold this object's current shards; four are required. Thus an acknowledged object can be unreadable with only two hosts down. Returning C's original disks may recover it; empty replacements do not recreate absent information.

MinIO permits partial successful writes and schedules repair; the degraded-parity adjustment is already capped at half the set in this layout. The counterexample is an inference from those mechanics and the specified host placement. [Upstream erasure write implementation](https://raw.githubusercontent.com/minio/minio/master/cmd/erasure-object.go), [quorum calculation](https://raw.githubusercontent.com/minio/minio/master/cmd/erasure-metadata.go), [MinIO erasure-coding explanation](https://docs.min.io/aistor/operations/core-concepts/erasure-coding/).

**Correction and acceptance:** Qualify the host-loss promise by healing/protection state and degraded-write acknowledgment policy; expose reduced protection and test spare recovery. Disable A, fail one B drive for a PUT, confirm success, pause healing, then disable C and read it. Repeat for a head, slot and segment. A healthy-object simultaneous-host-loss test is insufficient. The recommendation preserves the selected hardware and single-site decision.

### S06 — Deposit-only principals cannot fetch their required drop key

**P2; high confidence as a scope contradiction.** Evidence: §7.8, line 2928; §8.6, line 3323; §10.6, line 3972; §10.14, lines 4188–4197; §11.12, line 4501. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2928).

A fresh deposit-only receiver needs the current signed DropKeyStatement, but the declared GKM scopes are read/read-write/admin and the route requires a Client/service capability that deposit does not supply. A cached old key does not solve first use or rotation; granting read to fetch a public deposit key defeats the write-only boundary.

**Correction and acceptance:** Provide narrowly scoped access to the public drop statement and necessary generation/gate metadata, while denying reader wraps, group secrets and archive contents. Enroll a deposit-only device with an empty cache, deposit successfully, rotate, refresh and deposit again; every attempted reader-object fetch must remain denied.

### S07 — The 443 split sends custom-domain SNI to the platform terminator

**P2; high confidence.** Evidence: §12.8, line 4858; §13.4, lines 4994–5013; §13.5, line 5054; §19.5, line 6915. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4858).

The documented nginx map sends `*.ur.network` to tlsedge and the default to the platform HTTPS load balancer. A browser following `app.customer.example`'s CNAME still sends `app.customer.example` as SNI. It therefore reaches the default platform certificate/handler rather than tlsedge's custom-host lookup. CNAME resolution changes the destination address, not the requested TLS name.

**Correction and acceptance:** Use an exact platform-name allowlist with an appropriate tlsedge default, or feed a safe custom-host mapping into the split. Test a custom hostname on every load-balancer interface, platform names, unknown/no SNI and removal propagation. The customer must see its device-held certificate. [nginx stream map documentation](https://nginx.org/en/docs/stream/ngx_stream_map_module.html).

### S08 — Parent MTA-STS does not cover burner recipient domains

**P2; high confidence.** Evidence: §12.7, lines 4802–4805; §13.8, line 5119; §15.5, line 5693; §15.9, line 5773. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:4802).

MTA-STS discovery uses the recipient domain. A policy at `_mta-sts.<net>.ur.network` and `mta-sts.<net>.ur.network` is not inherited by `<blabel>.<net>.ur.network`. A wildcard MX does not create per-burner policy TXT/HTTPS endpoints, and the parent's wildcard certificate does not cover `mta-sts.<blabel>.<net>.ur.network`. DANE remains an independent defense, not evidence of MTA-STS coverage. [RFC 8461 §§3.3–3.4](https://www.rfc-editor.org/rfc/rfc8461.html#section-3.3).

**Correction and acceptance:** Narrow advertised MTA-STS coverage or specify per-burner publication, HTTPS names, certificate/CT and quota costs. Policy retrieval must be publicly accessible and compatible with Community endpoint limits. Use an MTA-STS-only sender against both network and burner recipient domains; check exact discovery names, policy retrieval and TLS matching, separately from DANE tests.

### S09 — The report parser excludes the formats carrying its aggregate counters

**P2; high confidence.** Evidence: §14.8, lines 5435–5441, 5459 and 5464; §21, line 7473; metadata, line 1068. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:5435).

The intake expects DMARC RUA and TLS-RPT counts, including a soundness alarm, but limits parsing to ARF `message/feedback-report` and original headers and forbids decoding attachments. DMARC aggregate XML and TLS-RPT JSON, commonly compressed/attached, contain the needed data outside those allowed parts. A valid report can therefore be sealed/discarded without yielding any counters. [RFC 9990 §3.5.2](https://www.rfc-editor.org/rfc/rfc9990.html#section-3.5.2), [RFC 8460 §5.3](https://www.rfc-editor.org/rfc/rfc8460.html#section-5.3).

**Correction and acceptance:** Distinguish bounded machine-readable aggregate attachments from enclosed original-message bodies. Specify dedicated XML/JSON parsers with reporter validation, deduplication, compressed/expanded limits and no external-entity resolution. Keep original body semantics unparsed. Feed plain/compressed fixtures, duplicates, malformed input, expansion bombs and external entities; require exact counter behavior and no body canary in logs or case fields. Define the RUA-count/edge-connection denominator before using the comparison as a soundness alarm.

### S10 — Deferred mail authentication loses reception-time DNS evidence

**P2; high confidence.** Evidence: §15.4, lines 5637–5639; §15.7, lines 5737–5739; §15.9–15.10, lines 5777 and 5793; DKIM selector removal, line 5410; receiver deployment, lines 6591–6598. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:5637).

A receiver durably deposits and acknowledges a message while all reader devices are offline. It records sender IP and TLS metadata, but not the DNS evidence needed later. A valid DKIM selector can be retired or an SPF policy changed before the reader ingests the deposit. The reader then labels a reception-time valid message using future DNS state, affecting spam and forwarding decisions. The design itself deletes some selectors promptly on removal. DKIM verification depends on the selector's published key. [RFC 6376 §§3.5–3.6](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.5).

**Correction and acceptance:** Have the already-plaintext customer receiver capture bounded relevant authentication/DNS evidence at reception and sign/seal it with ingress metadata, or explicitly define the later result as ingestion-time verification with missing-historical-evidence states. Keep current revocation checks distinct from historical authentication. Deposit under a valid selector/SPF policy, remove/change it with a fake clock, then ingest; the recorded result must reflect the chosen semantics. Test tampered evidence and its receiver trust boundary.

### S11 — The absolute no-content-plaintext statement omits report intake

**P2 disclosure contradiction; high confidence.** Evidence: §2.5/§2.8, lines 561 and 592; I-2, line 1193; §14.8, lines 5439 and 5464; §15.4, line 5666; metadata, lines 1068–1105. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:561).

The owner-approved abuse-report host terminates TLS and receives raw reports, potentially including original message bodies, before hashing and HPKE sealing them to a customer. Header-only semantic parsing and immediate sealing do not mean plaintext never existed at the server. This conflicts with absolute statements that URnetwork content handling is ciphertext-only.

**Correction and acceptance:** Preserve the explicitly chosen report flow and disclose the narrow exception: voluntary third-party reports/role mail arrive as transient plaintext; original bodies are not semantically decoded, persisted in plaintext or indexed; encrypted retention and drop rules apply. Reconcile the invariant, public copy and metadata table. Send a report with a body canary and verify both the declared intake exposure and absence from logs, attribution fields, cases and plaintext persistence. Do not “fix” this by silently changing the owner's report-intake decision.

### S12 — A transport-token rejection is mapped to durable identity revocation

**P2; high confidence.** Evidence: §18.7, lines 6698–6702 conflicts with §5.6, line 2262 and §5.8, lines 2287–2292; §22.5, line 7628. Targeted source: [sdk/api.go](/Users/brien/urnetwork/sdk/api.go:303), lines 303–330 and 345–348. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6698).

The SDK table maps a confirmed 401 logout callback to `Revoked`. A child whose parent was removed, or whose transport JWT expired while offline, has not necessarily received a signed SidecarRevoke. The core explicitly requires `Unenrolled`, preserving identity/admission/grants for a new binding generation. The adapter chooses the wrong terminal state. The existing compatibility callback also has no immutable origin; its own source directs callers that can accept another login to the generation-bearing event API. A delayed old rejection must not tear down a new pairing.

**Correction and acceptance:** Consume generation-bearing authentication events, reject only the applicable transport generation and preserve durable identity/pins. Enter Revoked only on verified authoritative revocation. Test expiry, parent removal and generic confirmed 401 separately from a signed SidecarRevoke. Block an old logout event, install a new generation, then release it; the new session must remain enrolled. Run both SDK backends.

### S13 — The keystore API cannot represent its required locked/unavailable result

**P2; high confidence.** Evidence: §18.5, lines 6608–6611 and 6657; §5.9, lines 2318–2329. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6608).

`GetSecret(name) string` reserves the empty string for absence but says it returns `SidecarKeyStoreUnavailable` when locked. There is no error/status channel. A host with an existing inaccessible key must either conflate absence with temporary unavailability or throw across a boundary whose panic can exit the app. Treating the empty result as first use risks provisioning over an existing identity; even a fail-safe implementation has no interoperable representation of Locked.

**Correction and acceptance:** Use a binding-supported result with present, absent, locked/unavailable and permanent-failure states, and corresponding write/delete semantics. Unavailable must cause no creation, overwrite, deletion or identity reset. A fake native store returns each state; assert Locked/retryable with unchanged bytes, then identical identity after unlock. Run the same matrix through generated Swift/Kotlin/C-ABI adapters and require one terminal result without panic.

### S14 — The advertised approval channels are unusable in supported host combinations

**P2; high confidence in the explicit desktop conflict; browser eligibility needs clarification.** Evidence: §16.6, lines 5990–6008; §5.8, lines 2282–2297; §18.4–18.5, lines 6587, 6599, 6624 and 6660; D-SDK-9, line 6793; §18.8, lines 6728–6731; §16/§18 phasing, lines 6217 and 6846. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:5990).

With two CLI daemons and no presence key, harness fallback is forbidden because another device is admitted. §16 promises `ur approve` on that other device using its identity key. Yet the command is a daemon control client, and D-SDK-9 forbids control mode from identity-signing approvals; every remote-mode app decision also requires a presence signer. The promised second-device route is absent. Merely giving the IPC hello a privileged label would contradict the same-user/mode boundary.

Likewise, a one-device user's harness fallback can disappear when a read-only page/quick-burner sidecar is admitted: the literal eligibility rule now sees another admitted device, while that host offers no approval channel. If only approval-capable member devices should count, the predicate must say so and reconcile the owner decision.

**Correction and acceptance:** Freeze a channel-by-host matrix. Define a reviewed other-desktop approval protocol or make presence provisioning a prerequisite before admission disables fallback. Preflight read-only admissions so they preserve a usable authorized channel, or take the required owner decision on eligibility. Test one/two CLIs, remote desktop app, page and quick burner, each with/without a presence key. Admission must preserve a promised route or refuse before committing an unusable configuration; a control caller must not relabel itself as another device/presence evidence.

### S15 — Mandatory author-visible read receipts have no authorized destination

**P2; high confidence.** Evidence: §16.8, lines 6065–6072, 6139 and 6142; §8.5, lines 3280–3286; EvsShare, line 3377; §11.8, line 4413. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6065).

Alice shares her owner-bound vault read-only with unrelated member Bob. Bob must first write a read entry Alice can see, but he has r rather than rw/deposit on that vault. His own vault is not visible to Alice, and the team record does not guarantee author access. A separately sponsored audit reader has the same gap. Enforcing the prerequisite blocks the legitimate share; skipping it breaks the stated disclosure. MLS membership grants decryption, not write permission, and the seven-day server request log is not the specified sealed author-visible channel.

**Correction and acceptance:** Define a receipt-only append/drop capability and destination, restricted payload, quotas and durable-submission/offline behavior, without granting arbitrary vault writes. Share with an ordinary member and a separately sponsored audit reader: both must submit valid author-visible receipts and read under exactly read-only privileges. Reject arbitrary writes and forged readers; test author offline/restart and eventual delivery. Scope the guarantee honestly: cached plaintext cannot be forced to generate a receipt on every offline reuse.

### S16 — HTTPS-only ephemeral hosts have no specified liveness lease

**P2 protocol gap; high confidence in the omission, medium confidence about implementation consequences.** Evidence: §7.7, line 2902; §6.8, line 2648; §18.8–18.9, lines 6720–6739; deferred C4, line 1967. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:2902).

The memory-only quick burner is reaped 30 minutes after page disconnect, but initially uses only HTTPS calls and 25-second polls, with no connect resident or defined liveness registration. Kill it without a final request. There is no specified event/lease from which to measure the 30 minutes. Treating no resident as disconnection can reap an active page; waiting for resident disconnect can leave abandoned admissions indefinitely. A best-effort unload request cannot be the authoritative mechanism, and the generic 30-day reaper is a different promise.

**Correction and acceptance:** Define an authenticated lease from enrollment, refreshed by a designated HTTP heartbeat/poll and bound to client/binding generation. Specify suspend/resume, tab independence and authorized reap after expiry/grace. With a fake clock and no resident, keep a page active beyond 30 minutes, then kill it without unload; require one reap at the stated deadline and correct MLS/gate effects. Test old-generation heartbeats, two tabs and resuming an expired leaf. Inventory any new lease metadata.

### S17 — A stale live marker suppresses the only wake trigger

**P2; high confidence.** Evidence: §18.7, lines 6706–6709; §6.8, lines 2643–2648; §15.6, line 5702. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6706).

At t=0 a publisher refreshes a 90-second live marker and then loses the client. A hint at t=10 sees the marker and queues no wake. No further hint arrives. Marker expiry has no specified action to reconsider that hint, so even a perfectly functioning push vendor receives nothing, and the mail path's 30-second hold expires. Reconnect/hourly resync helps only once the client is already running; TTL bounds stale state but does not schedule the missing action.

**Correction and acceptance:** Keep pending wake eligibility until actual delivery/ack or an explicit bounded deadline, with a delayed fallback independent of the marker. Suppress immediate duplicates without discarding the obligation to reconsider. Use a fake clock, real Redis Cluster fixture and vendor sink: set live, disconnect, emit exactly one hint and nothing later. Require a bounded wake submission compatible with the documented hold, including publisher kills around send/queue steps. Keep vendor failure and cap exhaustion as separate accepted best-effort outcomes.

### S18 — Browser verification is scheduled after the first public browser release

**P2 release-gate contradiction; high confidence.** Evidence: §18.8, line 6728; §18.17, line 6844; §23.4, line 7888; §22.17, line 7848; §22.9, line 7766; T4, line 7607. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:6728).

The HTTPS page Worker decrypts a vault at public RS1/M4, while the test phase puts “the browser worker” under Later. The listed Chrome offscreen/Firefox/native-companion fixtures are different topologies, and wasm-in-Node/size tests do not exercise browser origins, IndexedDB transactions or Worker lifecycle. The generic requirement to test each component at its milestone conflicts with this explicit deferral; an implementation can follow the tables and ship only a happy-path browser demo.

**Correction and acceptance:** Split page, companion and extension test tracks and gate each at first exposure. M4 needs a real-browser HTTPS-only fixture with C4 absent: admission, vault read, termination/restart at key/pin storage boundaries, token refresh, wrong-origin rejection, revocation and read-only outward-call refusal. Map console tests to M6 and quick-burner lifecycle to M8. Mechanically reject a milestone manifest whose artifact precedes its required host tests. Keep the owner's surrogate-only iOS memory gate unchanged.

## Open decisions with technical constraints, and smaller format clarifications

### C01 — Q-MAIL-13 cannot make observed sender metadata a proof of path privacy

**Claim correction before M7; high confidence.** Evidence: I-11, line 1202; §2.8 EX3, line 598; §15.4–15.5, lines 5645–5649 and 5693; §15.7, lines 5737–5739; Q-MAIL-13, line 5860. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:1202).

Q-MAIL-13 is explicitly open, so choosing a label is not reported as a newly discovered unresolved decision. However, its premise that REQUIRETLS alone is “sound” against the active operator is too strong. An operator can intercept an opportunistic sender's first TLS hop, read the message, then originate a genuine TLS connection to the customer receiver with REQUIRETLS and fabricated edge-origin ingress IP/PTR metadata. It can preserve the original aligned DKIM signature. The receiver sees the same label inputs while confidentiality was already lost. DKIM authenticates signed content, not the preceding transport path; a published TLSA does not prove this sender checked it. REQUIRETLS excludes malicious intermediate MTAs from its own threat model. [RFC 8689 §8.3](https://www.rfc-editor.org/rfc/rfc8689.html#section-8.3).

**Recommendation:** Label observable facts separately: TLS on the receiving hop, REQUIRETLS asserted, configured/published authentication policy, and sender-validation status unverified or inferred. A known operator's policy can support a qualified expectation, not cryptographic proof of the particular path. Keep EX3 and the owner-approved strict configuration visible.

**Acceptance:** A two-hop adversarial relay reads a canary, preserves DKIM, adds REQUIRETLS and reproduces permitted ingress metadata. The final UI/API result must not assert that URnetwork could not have read this message. This is a deterministic test of the claim, not a demand to make SMTP provide end-to-end content encryption.

### C02 — Command consent, signature typing and local key isolation need normative schemas

These are specification clarifications rather than demonstrated exploits against nonexistent implementations:

- **Command-bound admin tokens:** §7.8, line 2927 and D-TEAM-7, line 3081 promise one-command tokens, but do not define the canonical command digest, target and use count. DPoP does not bind the request body. Add a digest/target claim and one-use enforcement at the command endpoint; test that a token for one invite cannot change its email/role or repeat it. [RFC 9449 §11.7](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.7).
- **Typed signed records:** §6.9, line 2672 separates signature purposes, but several authority/ACL records share a purpose. Freeze a canonical typed/versioned envelope or equivalent domain separation. A parser-matrix test must reject presenting a signed record as another record type, including wire-compatible protobuf layouts.
- **MLS self-update wording:** §10.4, lines 3898–3901 and 3931–3932, and §10.9, line 4104 should distinguish an Update proposal from a Commit with an UpdatePath. A committer cannot include its own Update proposal. Accept the intended empty-proposal Commit with UpdatePath and reject the invalid self-proposal form. [RFC 9420 §12.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-12.2).
- **Per-network local roots:** §5.8, line 2295 promises no key shared across networks, while §5.9's root-wrap diagram can be read as one root wrapped to each membership recovery key. State that each network has a distinct secret container/root; a shared unlock is not a shared cryptographic root. Test one membership's recovery code against the entire daemon backup and require other memberships' secrets to remain closed. Per-Sidecar keychains can already support the correct implementation, so a proven cross-network leak is not asserted.
- **Packing/read races:** §11.13 writes a pack, publishes its locator, then deletes originals, which is directionally crash-safe. Specify that a missing original invalidates a cached negative pack-index lookup and forces refetch. Test a reader paused between a negative lookup and original deletion.
- **Quota exceptions:** §20.7 correctly keeps reads, deletes and export working at a storage limit. Explicitly classify CONSUME, deletion/tombstone appends, mandatory rotation, path migration, config repair and reseed, including their temporary bytes. A blanket write refusal must not prevent the maintenance operation that restores safety or reduces usage. Test these at the exact quota boundary; no generic quota/deletion deadlock is asserted because the stated exceptions already address it.

### C03 — Native presence approval needs a concrete platform evidence profile

**Integration/specification gap; medium confidence, not a claim of platform impossibility.** Evidence: §16.6, line 5993; §18.5, lines 6613–6615; §6.9, lines 2672–2674; §7.9, lines 2981–2984. [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md:5993).

The design combines an attested Secure Enclave presence key, plain P-256 signing over the sidecar Signed bytes, and a `GetAttestation`/`SignWithPresence` interface without naming a supported evidence profile. Apple's App Attest generates its own Secure Enclave-bound key and returns structured attestations/assertions with authenticator data and counters. Current documentation includes macOS 27 and a key-access-control property; the review does not rely on the outdated assertion that App Attest is unavailable on macOS. These documented properties do not by themselves show that the exact approval key has a remotely verified per-operation human-presence policy or emits the proposed wire signature. [Apple WWDC26 App Attest documentation](https://developer.apple.com/videos/play/wwdc2026/201/).

**Correction and acceptance:** Before claiming the M3 channel, pin the provider/OS support, attestation roots and format, challenge/domain binding, key association, signature encoding and presence semantics. Prototype the public API path. A supported FIDO profile can be the initial channel if native providers are unsupported, but resolve S14's fallback availability first. Verifier fixtures must reject another key's attestation, software-key substitution, app-integrity evidence lacking the required presence property, another action's assertion, replayed challenges/counters and profile substitution. Do not label ordinary app integrity as human approval.

### C04 — Persist run taint and bridge bootstrap authority across restarts

**Specification requirements with deterministic acceptance cases, not additional demonstrated exploits.**

- **Run taint:** §16.4, line 5941 puts run binding/taint in MCP sessions and describes replay of initialization/subscriptions; §16.6, line 6030 and D-MCP-4, line 6165 make taint last the run. Define durable monotonic taint and how a reconnect rejoins that run before an outward call. Read untrusted input, restart daemon and relay, deliver a benign hook and attempt an outward action under a standing grant: fresh approval must still be required. An implementation that treats a coverage gap as taint and restores it before actions can satisfy the invariant; a stored record bit helps only if enforcement reads it.
- **Keyless bridge bootstrap:** D-SDK-13, line 6801 says nothing opens before BridgeState, while §§17.8/18.6, lines 6370 and 6691 use an unverified `has_document` value to choose initial private-destination refusal. Define persistence of the last verified anchor, compiled state and custom block, and the exact pre-state deny rule. Restart an already-enforcing device and present an unsigned response omitting `has_document`; it must not downgrade verified policy. Keep explicitly accepted legacy/no-document LAN behavior separate rather than silently introducing universal deny.

### Recommendations on peer-review questions

These recommendations preserve the owner's decisions and are conditional on resolving the concrete findings above. They are judgments about the design, not substitutes for the measurement gates it already requires.

| Question | Recommendation and acceptance condition |
|---|---|
| Q-CORE-4, line 2388 | Choose **(b)** for ClientKey possession on refresh/token exchange. A copied client bearer alone must not mint service capabilities. Keep transport binding as the separately planned work; this does not replace C02's command-body binding. |
| Q-TEST-6, line 7816 | Choose **(b)**: apply the `oneof` restriction to envelope, stream and push messages, with an explicit descriptor lint allowlist. Keep credential representations compatible with the chosen MLS format rather than extending a transport implementation rule to unrelated schemas. |
| Q-TEST-2, line 7808 | Choose **(a) plus (b)**: the actual pinned MinIO build and a real three-master Redis Cluster, plus cross-slot lint. F08/F09/S05 require applied-but-unacknowledged and degraded-write fault schedules; a fake store or standalone Redis cannot establish those properties. |
| Q-KEYS-11, line 4170 | **(a)** is reasonable only after F04's resync/recovery paths are complete and retention tests show each eligible device can regain current access. Do not call pruning lossless merely because the historical RK ladder exists; MLS state, GroupInfo access and admission are separate prerequisites. |
| Q-EVS-6, line 4615 | Prefer **(c)** for reads presented as fresh/verified: replay from the pin before relying on older index state. If **(a)** is chosen for v0 availability/cost, make old per-file freshness an explicit trust mode and avoid implying the ref pin proves that file is current. Measure phone cost; this review supplies no performance result. F02 remains required under either choice. |
| Q-OPS-2, line 7094 | Retain **(b)** inlining/debouncing initially, with a measured trigger for **(a)** repacking. Treat the stated HDD rates as hypotheses until the selected hardware/workload is measured; reserve versioned locators and safe migration now. Fix S03 before using log reconciliation to validate capacity. |
| Q-CTX-4, line 497 | Choose **(a)**: a socket-served share while `ur share` runs matches the stated blocking CLI contract. Specify link-secret/use-count enforcement and closure semantics; a persistent encrypted-object product would be a different contract. |
| Q-TEST-1, line 7806 | Start with **(a)**, small sidecartest-owned deterministic fixtures. Exercise the production codecs and interfaces rather than reproducing their logic in mocks; move genuinely shared stable helpers into **(b)** if drift appears. Server-only tests are too late to isolate core state-machine failures. |
| Q-BRIDGE-2, line 6499 | Choose **(c)**, preserving the existing per-target client path initially and using a measured memory gate to justify the own-client framing work. The latter needs independent fragmentation/reply-filter and lifecycle tests; no memory savings are assumed here. |
| Q-SDK-5, line 6813 | Keep **(a) only if the required 1 MiB growth gate passes**; otherwise take the explicitly permitted leaf-package split **(b)** before exposing the device role. Test the actual linked artifact and descriptors, not only package source size. |
| Q-OPS-5, line 7100 | Choose **(a)** staged deployment, with mixed-version journal/snapshot compatibility and rollback tests. Rollout staging controls blast radius; it does not replace validation of signed-zone continuity or replica catch-up. |

For **owner** choices, the technical consequences are more important than adding recommendations by vote:

- **Q-ACL-9:** A shared private reader key per Delegation creates a revocation cohort. A reaped agent retaining that key can read new wraps until the cohort key/Delegation is replaced; five holders of one continuing key cannot cryptographically exclude only one. This is explicitly a pending option, not a defect in the adopted all-leaves model. If individual I-15 revocation remains the requirement, choose per-device wraps or a defined cohort-key rotation, and test a removed agent with every old secret and raw store access.
- **Q-KEYS-13:** Option **(b)** cleanly separates authority to approve a change from the writer that packages it into an MLS commit, improving offline-admin availability. Every peer must verify the signed change. It does not by itself solve F01 or the all-leaves-lost recovery in F04; a writer with no current leaf state still cannot issue an ordinary member commit.
- **Q-TEAM-10/11:** Keep the admission and recovery quorum decisions explicit before M2. A 72-hour veto is not equivalent to k-of-n authorization if notices can be withheld. If threshold security is retained, a recovery key should contribute according to that threshold, not silently replace it.
- **Q-TRUST-8:** Use narrower, accurate wording until the relevant internal gates and disclosure corrections pass. The owner declined an external-audit prerequisite; this review does not add one. Even the suggested ciphertext-only alternative must acknowledge S11's report-intake exception and the published EX cases.
- **Q-EVS-7, Q-OPS-8 and remaining operational/legal choices:** They remain explicit owner decisions. The review does not invent legal answers or classify the documented migration-tail question as a new production bug.

## Priorities for implementation, format freeze and launch

The shared M0–M2 work should establish executable contracts before both product tracks build on them. This need not serialize all implementation: interface scaffolding, test fixtures, transport work and the independent mail track can progress while the format blockers are resolved. It does mean a green happy-path prototype is insufficient evidence to freeze a format carrying the wrong state identity.

| Gate | Required decisions/corrections | Evidence required |
|---|---|---|
| Before M1 enrollment/token schemas | F05, F17; C02 typed statements and network key isolation; Q-CORE-4/TEST-6 | Table-driven grant/scope tests, complete enrollment transcript canaries, descriptor checks |
| Before M2 authorization/MLS/evs format freeze | F01–F04, F06–F11, F18; S01–S04/S06; owner leaf/committer/quorum choices and Q-EVS-6 | Concrete state machines and wire fields; deterministic histories below against both a model and the real pinned store; all-devices-lost and unread-slot recovery |
| Before M3 capture/record freeze, pilot and site-loss claims | F19/F20, S14 and C03/C04 run taint; S03/S05/F18; quotas and recovery runbook | Concurrent-worktree restore; redacted/hash-only refusal; approval crash/replay effect counts and host-channel matrix; degraded-write/healing drill, unread-slot mirror reseed and stale-mirror erasure reconciliation |
| Before M4/RS1 public record claims and SDK seams | F01–F03/Q-EVS-6 wording; S12/S13/S18 and C04 bridge bootstrap; C02 maintenance exceptions | Ref witnesses and stale-cohort simulation; generation-bearing token rejection, keystore status adapters, real page-Worker lifecycle/origin/storage tests, accurate metadata and content claims |
| Before M5 public HTTPS/names/report intake | F12; S09/S11 where reports begin at M5 | No-ALPN audience tests, safe aggregate/ARF parsing, accurate report-intake disclosure |
| Before M6 Team/custom domains | F13, S07/S15; owner quorum/reader-wrap choices | Hostile CAA-zone issuance, custom-SNI routing across all interfaces, author-visible receipt submission under read-only permissions |
| Before M7/M8 inbound and burner launch | F14/C01; S06/S08–S11 and S14/S16/S17; app-host contracts | Strict discovery, privacy-label fixture, deposit-only rotation, exact-domain MTA-STS, delayed-ingest evidence, HTTP lease/reap and stale-marker wake fallback; owner acceptance of the planned sender census |
| Before M9 outbound proof gate | F15–F16 and aggregate-alarm semantics | Frozen bidirectional protocol relation, malicious-prover/server-state corpus, TLS 1.2 response-forgery test, the existing non-author reviews and measured performance/coverage gate |

C02's one-command consent binding must gate the command-scoped admin CLI when that feature ships; the narrow v0 login/auth-key flow is not assumed to implement the later admin interface.

The TLA+/history model should represent separate durable objects and processes, not an atomic idealized push. Include the authorization prefix, time-based expiry, required generation, staged push/slot/index objects, head, operation outcomes, abort/GC fences, path-map source head and copy state, and deletion identity. Permit a successful storage operation to lose its response and permit its old process to resume after a retry or timeout. The same schedules should become deterministic regression tests when implementations are written.

The central assertions are:

1. Every accepted authorization state commits to its exact signed inputs, and every required rotation is causally after the reader-set shrink it satisfies.
2. Every committed head's dependency closure remains retrievable and decryptable unless an authorized erasure explicitly changes that contract.
3. Unknown outcome is never equivalent to abort; a reclaimed preparation can never later commit.
4. A successful Git push has the declared ref/tree/ancestry and per-ref outcome semantics.
5. Gate closure has a stated ordering with in-flight writes and new-ref creation; path transitions preserve every committed entry and apply the chosen new-key boundary.
6. Restore and irreversible shred have exactly one winner; stale jobs and stale mirrors cannot silently undo that winner.
7. A witness identifies the actual authority/storage state it checked. Two stale peers cannot manufacture freshness if the design retains a bounded-withholding claim.
8. Routing, protocol negotiation and proof validation preserve the same authorization and grammar assumptions from discovery through the final backend/MX.
9. An approval use is durably reserved before its effect, uncertainty does not reopen its budget, and run taint survives sessions/restarts.
10. Restore modifies only attributable, exactly recoverable content; host failures preserve durable identity and cannot silently downgrade verified policy.

Runtime, storage and mail fixtures should be deterministic independently of load tests. Every eventual bug fix must include the deterministic root-cause regression test required by the user's AGENTS instructions; this review itself makes no fixes. Broad randomized stress is useful after these schedules pass; it is not a substitute for an applied-write/lost-response case, two removals under one base, or a no-CHUNKING server accepting commands from the nominal message body. No new test or benchmark results are claimed by this review.

## Accepted tradeoffs and suspicious candidates ruled out

The review deliberately did not turn the following into findings:

- **Owner-approved in-house MLS, suite 0x0010 and no external audit gate.** The current IETF draft lists the selected X-Wing/AES128GCM/SHA256/Ed25519 suite; the design correctly treats it as a draft. The implementation still needs its planned conformance gates. [IETF MLS PQ ciphersuites draft, version 07](https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-07).
- **Object-store-only ordering.** Single-object conditional writes can be a valid primitive. F08–F11 concern the missing protocols around it, not a requirement for PostgreSQL transactions.
- **Lazy rewrap and historical access.** Former readers retain old content/keys and new readers receive history by design. F01/F06/F10 concern later secrets, writes and names. Seven-day MLS leaf updates are not automatically seven-day archive-generation healing; the stated generation schedule remains the relevant archive boundary.
- **No off-site server copy and unmirrored loss.** These are explicitly accepted. F18 asks whether the already-promised device-mirror recovery contains its indispensable keys. No new server replication requirement is inferred.
- **Missing Welcome after an accepted epoch.** The stated remove/re-add recovery is an acknowledged availability tradeoff. It was not promoted to irreversible content loss.
- **Pruned MLS history.** KF5 already offers re-add/recovery when an old RK cannot open the current GroupInfo. F04 concerns a concrete all-devices-lost path for which those alternatives do not currently complete.
- **Grantor-offline blocking and leaf-cap pressure.** They are documented and assigned to Q-KEYS-13/Q-ACL-9; they are not new hidden failures. The same applies to threshold recovery and self-admission choices.
- **Owner-bound vault grants.** A generic network-admin RepoGrant initially appears to widen access, but §11.12, lines 4493–4499 requires an owner EvsShare or visible audit assignment. No confirmed bypass is claimed. Preserve that condition in executable ACL tests.
- **The ten-minute in-memory peer RPC response cache.** It is not durable exactly-once execution, but the shown v0 peer catalog is mostly read/control operations and service mutations use HTTPS. No specific v0 mutation was found to justify a generic duplicate-side-effect finding. Any new mutating RPC must define method/body binding and restart/expiry semantics.
- **Read-token revocation delay, same-OS-user compromise and web-member impersonation.** These are disclosed boundaries, including EX8 and the remaining service-token lifetime. F12 is an unauthenticated external-visitor path, a different boundary.
- **SNI-only sender coverage, plaintext-mail refusal and iOS foreground-only receipt.** These are owner decisions with an explicit census/launch gate. The review does not invent compatibility measurements or demand a hosted plaintext receiver.
- **URnetwork-zone DNS/issuance authority.** EX1/EX2 accepts it for ordinary operator-hosted names. F13/F14 concern customer configurations that specifically claim to exclude it.
- **Self-signed mail certificates under DANE-EE and multiple receiver SPKIs.** These are compatible with the selected usage; opportunistic non-validating senders remain a disclosed limitation. The DNS wildcard/empty-nonterminal handling and compact-denial approach were not found intrinsically invalid. [RFC 9824 §3.3](https://www.rfc-editor.org/rfc/rfc9824.html#section-3.3).
- **PSL propagation and older receiver behavior.** The draft already identifies this risk. Tests at selected providers cannot prove universal suffix adoption; keep that coverage limitation and the distinction between older PSL and newer DMARC discovery behavior explicit.
- **HTTPS-only browser reads and extension lifetime.** Deferring C4 does not inherently prevent config/storage reads. Chrome's documented WORKERS offscreen reason is real and does not inherit the AUDIO_PLAYBACK-specific idle timeout; no fictitious universal 30-second limit is asserted. S16/S18 concern the specified HTTP lease and page-host tests. [Chrome offscreen API](https://developer.chrome.com/docs/extensions/reference/api/offscreen).
- **Runtime resource/review choices.** Surrogate-only iOS memory testing, no continuous fuzz service, deferred extension Worker, optional native companion and app-host timing are explicit decisions. SDK package placement remains conditional on the real size gate. The P0 credential changes and release-module rewrite are existing, concrete seams rather than reasons to redesign the dependency graph.
- **SMTP proof performance and the final circuit.** `smtpproof/SPEC.md` is a future deliverable. F15/F16 find missing properties in its specified blueprint, not an audited exploit of an existing circuit. The receive-only launch appropriately isolates that work.

## Review closure

All three independent specialty reports and the additional runtime/build pass are incorporated. The source fingerprint was rechecked during consolidation. Findings were merged where they share a root cause, and conditional interpretations, pending owner choices and explicitly accepted residuals remain labeled. The final deliverable is `DESIGN-REVIEW1.md`; DESIGN.md and implementation sources were not modified.

The next design revision should close the state-machine and schema contradictions before M2/M3 freeze, then carry the exact acceptance schedules into implementation. Feature-specific edge/mail and host gates can proceed on their existing tracks, provided their claims and test dates match the actual supported behavior.
