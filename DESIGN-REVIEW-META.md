# Final meta review of DESIGN.md and DESIGN-REVIEW-RESPONSE.md

**Review date:** November 5, 2026, America/Chicago. **Review method:** Astra MAX; three independent specialty reviews, followed by an independent source-only performance supplement from the edge reviewer and critical consolidation. No cross-model input or other current review variant was used.

## Assessment and evidence

**The architecture is substantially improved, but the affected key, storage and format contracts are not ready to freeze.** The response closes many real earlier defects: one authorization prefix, one generation claim, one storage publication point, no cleanup after an uncertain commit, committed-only folds, exact Git tips, typed signatures, owner consent, durable approval consumption, reception-time mail evidence and separate specification/byte freezes. These improvements should be retained.

The remaining problems concentrate at boundaries. A directory reader/writer can destroy another writer's keys before authorization is checked. Shared Delegation keys do not reflect every promised removal event. ReaderKey replacement is not represented in immutable delivery objects or authenticated retirement state. The new search index can lose its diff base or deletion mask and can publish fresh-key copies after an erasure. The refusal fence still relies on an arrival-order assumption. Resource admission contains both an unbounded P0 exception and conflicting P2 accounting rules. Several smaller client workflows have no durable completion or ordering mechanism.

One **already disclosed critical dependency** deserves equal prominence: D-OPS-20's proposed cancellation patch can still let an operation stalled beyond 30 seconds land after a newer same-key operation. This is an unresolved assumption beneath CAS, collection and purge, not just a latency risk. A successful measured-lag gate cannot establish an ordering property the timeout path deliberately releases.

These conclusions do not call for reversing owner decisions about customer-held keys, wrapped readers, ordinary CI reaping, encrypted client-side search, MinIO, single-object publication, versionless content, bounded erasure allowances, endpoint TLS, SNI-only inbound mail, no default indexer, or internal review gates. Where a promise cannot coexist with the chosen mechanism, the report identifies the precise correction or narrower claim required.

The designated inputs were:

| Source | SHA-256 | Lines / words |
|---|---|---|
| DESIGN.md | 41ba66700e65969c4b8ff7a499e9ba6b7f79189a7a903848711a6638a9f73925 | 19,005 / 339,101 |
| DESIGN-REVIEW-RESPONSE.md | 277dd50e6610671205ab2c1650e231a5da340c02a122da231bf89d111fee06e4 | 1,815 / 33,934 |

The reviews used /tmp/sidecar-meta-DESIGN.md, /tmp/sidecar-meta-DESIGN-REVIEW-RESPONSE.md and the manifest. Working sources matched at the final integrity check. All section/line references below identify these exact revisions; links open the corresponding working source at the starting line. “D” means DESIGN.md and “R” means DESIGN-REVIEW-RESPONSE.md.

Independent reading covered architecture/build, authority and keys, protocol/storage/index/GC/recovery, agents/approvals/restore, edges/mail/bridge/mobile, operations/quotas/testing and release gates, including the new appendices and v1 additions. Consolidation rechecked candidate mechanisms against the current source, merged duplicates and retained conditional concerns as conditional. This is a deep design review with targeted primary-source checks, not exhaustive dependency auditing or a claim that every sentence was mechanically proven. The reviewers used arithmetic and isolated scratch traces for selected ordering/rounding counterexamples; no sidecar implementation tests, formal proofs, production benchmarks or load experiments were run. **All acceptance scenarios below are required future regression evidence, not reported passes.** No source, Git identity or commit was changed.

The response itself distinguishes mechanical validation from correctness review and says v1 additions had not been peer reviewed ([R §6.8–6.9, 1749–1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1749)). New v1 findings therefore do not imply that the response falsely claimed they had passed. Conversely, “resolved” on an old issue does not establish every neighboring invariant introduced by its correction.

## Priority map

**High** means a supported schedule breaks an authorization, durable-state, terminal-outcome or completeness guarantee, or a core admission invariant. **Medium** identifies a material claim, resource bound, workflow or format ambiguity with a narrower impact. Confidence is high unless qualified in the finding. “Conditional” means the stated adversary/workload/environment assumption is essential; it is not an assertion that the event has been observed.

| ID | Severity | Issue | Required stage |
|---|---|---|---|
| F01 | High | Directory rw can erase other writers' keys before authorization | Directory authority/reservations; M6 |
| F02 | High | Suspend and individual expiry do not retire a covered Delegation key | M2 specification |
| F03 | High, claim/incident boundary | A copied reusable auth bundle re-admits after the advertised agent-revoke cutoff | M2 semantics and revocation UI |
| F04 | High | Same-generation late wrapping cannot replace an expired recipient-key delivery | M2 object/wire identity |
| F05 | Medium, specification blocker | Late wraps lack their own authorization pin and validation rule | M2 signed format |
| F06 | Medium | Weekly ReaderKeys do not prove the stated 37-day healing bound | M2 claim and adversarial tests |
| F07 | High | A writer-head overwrite can discard its diff base | Index format/reservations; M10 |
| F08 | High | Shards cannot encode the tombstones their reads require | Index format/reservations; M10 |
| F09 | High | Erasure does not fence later fresh-key index publication | Index/erasure protocol |
| F10 | High, arrival assumption | Terminal refusal can precede a later handler's commit of the same push | M2 outcomes |
| F11 | High | LFS force-to-old-tip bypasses upload/touch protection | M10 Git/LFS |
| F12 | High | Aggregate P0 work defeats the hard physical-write budget | Governor specification and M2 gate |
| F13 | High, algorithm ambiguity | Literal allowance split reserves deferred P2 work twice | Governor conservation rule |
| F14 | Medium | Restore hash-check then rename can overwrite a concurrent human edit | Restore/RV gate |
| F15 | Medium | Delayed token projection regresses or resurrects push tokens | M8 wake state |
| F16 | Medium | Directory denial lacks requester notice completion and decision locator | M6/M8 request journey |
| F17 | Medium | Mail authentication's verdict/work count is not bounded by its 8-KiB evidence cap | Inbound mail gate |
| F18 | Medium | 128-KiB rounding does not hide five pages at arbitrary background totals | C19/M10 privacy claim |
| F19 | Medium | One message does not imply one index rekey or next-day erasure | Quota/erasure estimate |
| F20 | Medium | Cross-partition newest mask has no bounded-memory algorithm | Search/M10 |
| F21 | Medium | Cold last-shard matches cannot satisfy the universal first-hit target | Search latency contract |
| F22 | Medium | Directory gate lacks some referenced numerical pass/fail criteria | M6/M10 scale gate |
| K01 | Critical if exercised; known | A >30-second drive operation can defeat cancellation/CAS ordering | Storage adapter before destructive use |
| K02–K05 | Medium; already acknowledged | Custom-ingress readiness, phone revocation, DATA-limit UX, stale Workers | Their feature launch gates |

## Supported findings

### F01 — Directory destruction is authorized after the keys have already been destroyed

**High; high confidence.** Independently found by both trust and edge reviews. This is a new v1 defect with an explicitly acknowledged effect, but the proposed mitigation understates its permanence.

Every admitted non-read-only sidecar, including ordinary agents, gets directory rw. The directory exception admits ERASE/CLOSURE and slot deletion at rw because evs cannot inspect whose copies a slot covers. Only readers check whether the signer is a directory admin or the appropriately scoped announced-repo admin. The text explicitly says a rejected ERASE has already emptied the slots ([D §11.12, 7864–7869](/Users/brien/urnetwork/sidecar/DESIGN.md:7864); [§16.11, 11658–11706, 12091–12102](/Users/brien/urnetwork/sidecar/DESIGN.md:11658)). The normal no-indexer configuration has no directory mirror, while request/decision/coordination streams retain historical records for 400 days.

**Trace:** Bob has an old uncached stream entry in an unmirrored directory. A compromised ordinary agent reads its slot references and submits an identity-signed ERASE naming them. The honest server accepts rw and destroys the random keys. Readers reject the signer and alarm. Revoking the agent or rewriting Bob's next card cannot reconstruct the old entry's lost keys or plaintext. This is permanent loss in a supported configuration, not merely denial “until each writer's next write.” A hold does not prevent the attack because holds deliberately permit key destruction.

**Why current protection fails:** signatures and own-path reader rules detect interference after an irreversible effect; a mirror is optional and no universal repair protocol exists. Even a mirror would turn an ordinary compromised writer into a directory-wide recovery incident. Rate limiting changes speed, not authority. No owner decision requires wildcard destructive capability for every directory writer. [R §6.9, 1762–1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1762) correctly labels this directory material new and unreviewed.

**Correction:** require server-verifiable destructive authority before any key mutation: an opaque slot-scoped erasure capability/customer-signed manifest, or a directory-admin countersignature with scoped delegation for repo-owned announcement copies. Preserve plaintext/path secrecy. If countersigning introduces an offline-admin wait, expose that dependency. A withdrawal may hide an announcement while authorized closure completes. Do not substitute mandatory mirrors for an authorization boundary.

**Acceptance:** create two writers' histories with no mirror and no victim cached key/plaintext. A genuine ordinary agent must be refused before mutating any victim slot. A mixed manifest with one authorized and one unrelated slot must have no destructive partial effect. Repeat under a hold and with a consent-parked device. Positive cases must preserve directory-admin erasure and a repo owner's exact permitted announcement erasure. A fresh authorized reader must still open every unaffected historical entry.

### F02 — Suspend and individual expiry do not remove a Delegation-covered agent's keys

**High; high confidence.** This is distinct from the explicitly accepted ordinary-reap exception.

Suspend is a hard deny, and the primary encryption invariant says a writer must not encrypt to a generation held by a subject it considers a non-reader ([D §8.6, 4973–4987](/Users/brien/urnetwork/sidecar/DESIGN.md:4973); [§8.12, 5187–5189](/Users/brien/urnetwork/sidecar/DESIGN.md:5187)). But KeyHolders includes a Delegation while its tags read the repo; its key drops on Delegation revocation/void/expiry or non-reap SidecarRevoke, not Suspend or an individual agent's earlier admission expiry ([D §10.5, 5922–5938, 5952–5964](/Users/brien/urnetwork/sidecar/DESIGN.md:5922)).

**Trace:** D admits A and B, both holding D's reader seed. Suspend A while D and B remain live. All honest evaluators exclude A from RepoReaders, but KeyHolders still contains D. A later honest rotation wraps the new RK to D. A obtains that valid ciphertext from an untrusted delivery service and decrypts it. The same mismatch occurs when A's SidecarAdmit expires before D, despite the drops table promising a REMOVE generation.

**Why current protection fails:** token denial and contract closure protect honest services; the declared threat model permits delivery of ciphertext by the operator. Witness freshness confirms the suspension but does not change the private key that opens the valid DelegationWrap. D's eventual expiry is not the promised immediate suspension/individual-expiry cutoff. [R T2-03, 380–386](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:380) marks holder exclusion resolved; [T2-04, 388–394](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:388) accepts reaping only.

**Correction:** every non-reap loss of a covered agent's read authority must retire the relevant shared delivery capability, with a positional/time identity in the holder function and gate. Surviving agents can become uncovered and receive individual wraps, as already specified for non-reap revocation. Alternatively narrow Suspend/expiry to an explicitly server-only control, but that is a broader exception requiring correction of the primary invariant and product claim.

**Acceptance:** with fixed keys and fake time, suspend A under a still-live D; separately expire A before D. Disable the server-side gate and deliver every wrap. No post-event RK/new checkpoint may open under A's retained keys; B must continue by its own delivery. Test explicit unsuspension/re-entry and retain the positive no-rotation-on-reap case.

### F03 — Revoking one agent drops the shared reader key but leaves a stolen auth bundle's admission authority

**High claim/incident-response defect; high confidence.** The split capabilities may be intentional, but the stated cutoff for a copy of the entire auth key is false.

A reusable auth-key bundle contains both delegation signing and reader seeds; the daemon uses the signing seed to admit itself. After a non-reap SidecarRevoke, the drops table explicitly says D still admits until revoked. The residual nonetheless says each copy of its auth key stops reading at that agent-revoke cutoff ([D §7.8, 4037, 4050–4067](/Users/brien/urnetwork/sidecar/DESIGN.md:4037); [§10.5, 5955–5957, 5974](/Users/brien/urnetwork/sidecar/DESIGN.md:5955)). [R T2-03/T2-04, 380–394](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:380) repeats the bound.

**Trace:** a thief retains an unexpired reusable bundle with admission uses left. An admin revokes its agent A, and honest writers rotate excluding D's reader key. D itself was signed by an uncompromised admin and remains valid. The thief uses D's retained signing seed to admit fresh identity B. B is now an uncovered authorized agent and receives an individual ReaderWrap of the current generation. The thief reads again after the advertised cutoff.

An honest daemon deleting its signing seed does not erase a stolen original bundle. Invalidating an operator bearer alone does not retire the customer-signed admission authority against the specified colluding-operator threat; that operator can supply a new client/bearer. max_admits and expiry eventually bound repetition, but do not make revocation of A terminate it.

**Correction:** when incident response promises to stop a leaked auth bundle, retire its signed admission capability as well as its shared reader key; already admitted honest agents can remain as individual readers. Or preserve the split explicitly and require signed DelegationRevoke for a leaked bundle, with that distinction shown in the revoke UI and threat table. Preserve ordinary reap behavior.

**Acceptance:** copy the complete bundle, admit A, revoke A non-reap, rotate and submit B signed by the copied seed—first with the old bearer, then with an operator-supplied new client. Under the promised cutoff B must gain neither accepted admission nor a key. Existing honest agents must continue. Keep a separate test for a thief possessing only the reader seed, whose exposure is narrower.

### F04 — Immutable delivery identity does not include the recipient's ReaderKey incarnation

**High; high confidence.** Fresh key rotation has an unresolved delivery lifecycle.

ReaderKeys are genuinely replaced weekly and old private material is deleted at not_after; late wrapping is supposed to restore delivery without changing authorization or the current generation. Yet ReaderWrap objects are create-only at wrap/g/c8/s:sidecar_id, with no key incarnation in path or body ([D §10.5, 5846, 5909, 5932–5936](/Users/brien/urnetwork/sidecar/DESIGN.md:5846); [§10.6, 6027–6037](/Users/brien/urnetwork/sidecar/DESIGN.md:6027)). KF5 explicitly says a lapsed ReaderKey can be republished and receive a late wrap ([D §10.7, 6220](/Users/brien/urnetwork/sidecar/DESIGN.md:6220)).

**Trace:** generation g has a valid wrap for reader A under K0, but A has not received it. A replaces keys for other activity and deletes K0 at expiry. R has no online writer creating another generation. A returns with a fresh K1 and a current reader-holder offers the promised late delivery of the unchanged RK_g. Its If-None-Match targets the already occupied K0 object. Fetching that winner returns ciphertext A can no longer open. A reader-only holder cannot solve this by authorizing a global rotation.

**Why current protection fails:** wrap-pending repeats an impossible write. Keeping K0 indefinitely contradicts the new retention/healing rule. Recovery or waiting for a writer is a new dependency, not the stated late-wrap path. [R WR-N6, 1589](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1589) marks fresh-pair retention fixed, while [T2-22/T2-23, 499–512](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:499) does not supply a new delivery identity.

**Correction:** make immutable delivery identity include the signed recipient-key digest/incarnation, bound into the wrap and authenticated-encryption context. Define lookup, retries and GC. A monotonic, narrowly authorized CAS replacement is another possible design, but an unqualified mutable wrap is not. Check same-generation RecoveryRebind redelivery too.

**Acceptance:** fake-age an occupied K0 delivery beyond its private-key retention, return A with K1, and have a reader-only holder deliver the same RK_g successfully. Race two late wrappers and crash/retry them. The old key must not open K1's ciphertext, and a stale K0 delivery must not block or replace K1.

### F05 — Late deliveries have no signed authorization pin for their required checks

**Medium; high confidence that the wire contract is incomplete.** The exact resulting implementation failure is conditional on how a verifier fills the gap.

ReaderWrap/DelegationWrap bodies name group, generation, recipient and ciphertext. The generic Signed envelope adds no auth pin/time. Verification nevertheless requires each wrap's authorization pin and says every staged or late delivery names a holder, with non-holder delivery poisoning the generation ([D §10.5, 5846–5847](/Users/brien/urnetwork/sidecar/DESIGN.md:5846); [§6.9, 3681–3686](/Users/brien/urnetwork/sidecar/DESIGN.md:3681); [§10.9, 6254, 6305–6316](/Users/brien/urnetwork/sidecar/DESIGN.md:6254)). KF2/KF3 deliberately deliver the unchanged current generation to later admissions/grants.

**Trace:** g is claimed at P0 with holder A. At P1, B is validly admitted/granted without a shrink or new generation. A gives B RK_g. A verifier using g's P0 calls B a non-holder and poisons g; a verifier silently using current P1 accepts. Neither has a signed delivery-time pin to apply the signer/recipient checks after later role changes. The generation identifies the key, not the authority state of a later delivery.

**Correction:** define a typed delivery statement binding generation/full commitment, recipient/key incarnation, AuthPin, time and ciphertext. Separate claim-time holder-set validation from later delivery authorization. Specify first versus replacement delivery signers and treatment of historically valid wraps after revocation. An operator-upload timestamp cannot substitute for customer-signed authority. This complements F04 but addresses a distinct validation requirement. [R T2-02/T2-03, 372–386](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:372) should qualify its closure until these bytes and rules exist.

**Acceptance:** independently implemented verifiers must agree on g-at-P0 delivered to B-at-P1, with no rotation. Negative cases: pre-grant delivery, forged pin, lost signer authority and recipient revoked before delivery. Replaying a historically valid old wrap must not poison history merely because its recipient is now revoked.

### F06 — Weekly replacement does not establish the advertised 37-day content-healing bound

**Medium; high confidence.** The active whole-keychain attacker also needs a stronger qualification than passive snapshot healing.

ReaderKey advertisements are signed and valid up to 30 days; gkm stores one overwriteable current advertisement, with no authenticated replacement position, sequence or retirement proof. The claimed small-group bound assumes the old ReaderKey stops receiving new generations after weekly replacement ([D §10.5, 5851–5858, 5932–5936](/Users/brien/urnetwork/sidecar/DESIGN.md:5851); [§10.6, 6037](/Users/brien/urnetwork/sidecar/DESIGN.md:6037)). [R T2-24, 514–522](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:514) and [WR-N6, 1589](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1589) call the fresh-pair correction fixed.

**Trace without forging anything:** steal K0 on day 0; the honest device performs its path update and publishes K1 on day 7. On day 29, a wrapped writer rotates and receives the authentic still-unexpired K0 advertisement from malicious gkm. Its ReaderWrap opens under stolen K0. The next generation may wait until day 59, so day-40 content remains readable after the stated 37-day bound. Auth/witness pins can be entirely current because they do not authenticate ReaderKey replacement.

Full keychain cloning is stronger still: the copy contains identity and ClientKey authority, enabling impersonation and fresh key advertisements until signed retirement. Fresh encryption material alone does not revoke those credentials. MLS separately discusses signing-key impersonation and fresh-Commit PCS; an application's independent delivery channel must satisfy its own condition ([RFC 9420 §§16.5–16.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.5)).

**Correction:** authenticate key replacement/retirement or limit advertisement validity to the claimed effective cutoff, then derive the actual bound from validity plus generation cadence. Name the attacker assumptions. Require signed revocation and new identity enrollment for an active clone retaining usable credentials, consistent with the existing compromised-backup procedure.

**Acceptance:** run the day-0/7/29/40 stale-advertisement trace with identical current auth/HeadCheck pins. K0 must be rejected or the larger exposure must be documented. Separately clone the full keychain and show exactly which signed retirement prevents later key registration/admission; a path update alone must not be reported as doing so.

### F07 — A head overwrite can destroy the base of its own index diff

**Severity: High; confidence: high.**

**Evidence.** A writer head holds one entry per document key, with a newer entry replacing the older one. The diff encoding includes a base version and added/removed key sets, but neither the base key set nor a locator to a retained base. A writer selects a diff when the previous full set is in the same bucket and the chain remains short. The index files are versionless. Their replaced content is purged, and a new reader downloads the current files. See [D §11.14, 8405–8410](/Users/brien/urnetwork/sidecar/DESIGN.md:8405), [8494–8514](/Users/brien/urnetwork/sidecar/DESIGN.md:8494), [8317–8327](/Users/brien/urnetwork/sidecar/DESIGN.md:8317), [§11.7, 6920–6938](/Users/brien/urnetwork/sidecar/DESIGN.md:6920), and [§11.14, 8571–8588, 8624–8630](/Users/brien/urnetwork/sidecar/DESIGN.md:8571).

**Counterexample.**

1. A writer creates document D in an empty bucket and places its full key set in an unsealed head H.
2. D changes slightly before H fills. The previous full set is in this bucket, the delta is small, and the chain is below both limits. The writer therefore takes the specified diff branch.
3. H's new version contains the single entry for D, now a diff based on D's previous version. The “one entry per doc_key” rule removed the only full entry. No sealed slot or shard ever held it.
4. Older versions of H are purged. A fresh phone downloads the current H. It cannot reconstruct D's unchanged trigrams from the diff or search them correctly.
5. Another small edit can repeat the problem with the first diff as an unavailable predecessor.

This does not require a lost write, malicious writer, unusual merge order or a cache failure. It is an ordinary sequence of edits before a head seals. The same-bucket test establishes where the base was before the overwrite, not that the committed new index still contains it.

**Why the mitigations do not suffice.** The 16-diff and half-size limits bound work only if the chain exists. Versionless retention deliberately removes the old head's bytes. A warm writer retaining its old head in memory is not a recovery format, and phones are explicitly allowed to search without fetching original bodies. The read algorithm requires a “composed diff chain” without specifying how this chain survives the replacing write. FI-18 requires all covered latest documents to remain candidates and sealing/merging to preserve results ([D §22.6, 16136–16141](/Users/brien/urnetwork/sidecar/DESIGN.md:16136)).

**Correction within the chosen design.** Require a diff's entire dependency chain to remain in the newly committed index. The simplest correction is to keep the current head entry self-contained: replace it with a full set, or an explicit base plus composed delta. A smaller alternative is to allow a diff only when its base is in another current, retained slot/shard and bind that base by a stable locator/hash and lifetime rule. Merely saying “same bucket” is insufficient. Specify how repeated edits, slot reuse, merge absorption and erasure affect that dependency.

**Deterministic acceptance.** Create D, edit it twice in the same unsealed head, advance purge/evacuation, discard every client cache, and start a fresh phone with only the current index. Query an unchanged trigram and each added/removed trigram against SearchOracle. Repeat with the base in a sealed slot that is merged and then reused. No query-dependent body fetch may rescue the test.

**Response assessment.** This is part of the new index at [R §6.9, 1766, 1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1766), not an old finding marked resolved. Resolve before the index bytes and relevant format reservations freeze.

### F08 — The canonical shard format cannot retain deletion masks

**Severity: High; confidence: high.**

**Evidence.** Slot entries have explicit full, diff, tombstone and ref-tombstone kinds. A shard doc table instead contains only doc_key, version, time and row. The row's document kinds and flag bits describe files, mail, records, derived documents, trust flags and truncated fields; none denotes a tombstone or ref deletion. No such field exists in IndexFileHeader or IndexManifest either. Meanwhile the newest-version algorithm explicitly needs bucket doc-table tombstones to mask older rows in all. See [D §11.14, 8408–8440](/Users/brien/urnetwork/sidecar/DESIGN.md:8408), [8458–8479](/Users/brien/urnetwork/sidecar/DESIGN.md:8458), [8526–8537](/Users/brien/urnetwork/sidecar/DESIGN.md:8526), and [8631–8638](/Users/brien/urnetwork/sidecar/DESIGN.md:8631).

**Counterexample.**

1. D's old live version resides in all after a completed roll-up.
2. D is removed in a current bucket. Its writer slot contains a tombstone, so searches correctly suppress all's old row.
3. The slot seals and is absorbed into bucket shards. The merge rule says “tombstones applied,” writes the new shards and advances the absorbed watermark.
4. The old slot is reused and its content purged. If “applied” meant dropping the deleted row, the only deletion mask is gone and all's old row reappears. If the merger instead preserves a tombstone, the specified canonical shard encoding cannot distinguish it from a live row.

**Why the mitigations do not suffice.** Applying a deletion within one bucket cannot delete the older row in another partition; all is updated only by the later roll-up. An empty posting list is not a tombstone representation: it also describes a live document with no usable trigrams and does not encode a ref-wide delete. Readers reject non-canonical formats, so implementers cannot safely improvise an undocumented flag. This conflicts directly with FI-18 and the promised newest-version semantics.

**Correction.** Add an explicit canonical deletion representation to shard doc tables or a separately encoded tombstone table. Define document and ref tombstones, their versions, their interpretation across every searched partition, and when roll-up may remove them. Preserve the mask through merge and slot reuse until all's superseded rows are gone. Include the representation in deterministic vectors and format compatibility rules.

**Deterministic acceptance.** Put an old live document in all; delete it in a bucket; seal, merge and reuse every contributing slot; purge all replaced index-file versions; search from a fresh cache. Repeat for rename, conversion to a skipped/binary document, and a Git ref deletion. There must be no old hit before or after the bucket's roll-up, and every file must pass the canonical decoder.

**Response assessment.** New, unreviewed index format ([R §6.9, 1766–1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1766)). Generic merge/delete tests need this exact “all still contains the old row, slot has been reused” schedule.

### F09 — Erasure does not fence publication of new index copies

**Severity: High; confidence: high.**

**Evidence.** ERASE commits on the separate erasure ref after CLOSURE rewrites known copies. Index files in ur/index can be written after the content commit; writers drop pending entries on an ERASE hint. The eraser enumerates current and retained files and, for ten minutes afterward, its device or a designated indexer re-CLOSUREs racing companion copies. No indexer exists by default. FI-19 and I-EVS-13 nevertheless promise that once ERASE commits, no stored/committed index copy remains openable by current reader keys. See [D §11.12, 7799–7814](/Users/brien/urnetwork/sidecar/DESIGN.md:7799), [§11.14, 8312–8327, 8505–8518](/Users/brien/urnetwork/sidecar/DESIGN.md:8312), [8863–8883](/Users/brien/urnetwork/sidecar/DESIGN.md:8863), [§11.8, 7522–7524](/Users/brien/urnetwork/sidecar/DESIGN.md:7522), and [§22.6, 16142–16146](/Users/brien/urnetwork/sidecar/DESIGN.md:16142).

**Counterexample.**

1. Honest writer A extracts document D into a newly created writer-head path or large-entry path, with a fresh key. It pauses before committing the prepared index push. That path is not yet in any committed listing.
2. Eraser B enumerates every committed and historical representation, rewrites those paths, commits ERASE and completes their slot-key deletion.
3. A resumes. Its new path does not conflict with the paths B rewrote. The ordinary ref-head retry can recheck and commit its disjoint creation; there is no erasure epoch or durable erased-document check in the index publication rule.
4. A's newly committed copy is encrypted under a key ERASE never named. An immediate read mask may hide the result in a cooperating UI, but it does not destroy that key or ciphertext.
5. For a permanent case, delay A until after the ten-minute watch, while remaining within the specified 30-minute multipart seal horizon, or crash B's device after ERASE in the default topology with no designated indexer. A lost hint has the same essential effect unless publication consults durable erasure state.

The finding concerns honest delayed work, not a former reader deliberately republishing plaintext it already knew. Explicitly accepted inability to recall an offline reader's knowledge does not authorize the system itself to publish a fresh durable decryptable representation after the erasure cut.

**Why the mitigations do not suffice.** Existing-path CAS protects only paths in the CLOSURE. An unpublished path is absent from that set. A hint is a cache invalidation signal, not a transaction barrier. Ten minutes is shorter than an allowed prepared push's lifetime and provides no crash recovery ownership. Even the ordinary racing case conflicts with the stated invariant: FS-78 allows a racing copy to be reclosed “within 10 min,” while FI-19 says no openable committed version exists once ERASE commits ([D §22.7, 16954–16972](/Users/brien/urnetwork/sidecar/DESIGN.md:16954)). Those are different contracts.

**Correction.** Establish a durable erasure cut for index publication. For example, serialize an opaque erasure epoch/tombstone-set commitment with the index ref's state; every index-producing push names the epoch it used, and a stale prepared push must rebuild after applying the durable erased-document set. The client can keep document identities sealed; the server need only enforce the epoch transition at the same head CAS. Make unfinished closure work durable and reconciled, and include fresh paths, backfills, rebuilds and companion journals. Do not substitute an arbitrary longer watch interval for a barrier. If the intended contract is instead eventual index key destruction, that is an explicit change to FI-19 and the product promise, not a completed fix.

**Deterministic acceptance.** Pause a new-path companion push immediately before publication, erase D, lose all hints, terminate the erasing device, advance more than ten minutes and then seal A's still-valid multipart push. Test with no designated indexer. Enumerate every current-reader-openable index version and verify that none holds D's fields or postings. Repeat for concurrent backfill, a rebuild, old writer-head reuse and held historical versions. A fresh device must observe both the logical mask and the cryptographic deletion contract.

**Response assessment.** [R T1-13, 288–295](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:288) correctly closes the earlier need to enumerate known deposit, index and retained copies. The v1 index introduces new publication paths after that enumeration. Preserve the earlier fix but narrow its “resolved” scope and address this interaction.

### F10 — A handler-arrival fence cannot establish a stable terminal refusal

**Severity: High; confidence: high on the specified protocol gap; transport qualification below.**

**Evidence.** The client reuses one push ID; the load balancer may resend a POST after an error, 503 or 30-second silence. The design allows overlap, asserts that no attempt arrives after its client moves on, and fences an attempt only if fence_ms is later than that attempt's own arrival minus 100 ms. A quota/scope/keying/deleted-state refusal raises a fence after its own arrival and then claims no other attempt of that push can commit. See [D §11.8 Outcomes, 7435–7461](/Users/brien/urnetwork/sidecar/DESIGN.md:7435), [7462–7482](/Users/brien/urnetwork/sidecar/DESIGN.md:7462). [R T1-02, 201–208](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:201) and [R §7, 1790–1793](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1790) say the delayed-first-attempt case is closed.

**Counterexample.**

1. Attempt A for statement P has been sent but is delayed before the receiving evs process records its handler arrival.
2. An allowed retry B reaches a sibling. B's over-limit state refuses P. B raises the head fence and emits terminal 409.
3. A begins handling more than 100 ms after that fence. A's permitted stale below-limit cache passes the external check. Its own later arrival means the existing fence does not stop it.
4. P is still within its signed-time and base windows. No durable record says “P was refused.” A signs no new statement; it performs the ordinary checks and commits the same P.
5. The client treats the 409 as terminal and may rebuild its operation under a different ID. It can therefore observe a refusal followed by the old operation's side effect.

One variant requires no arrival after the client moves on: delay delivery of B's terminal response while A arrives after the fence but before that response reaches the client. “All attempts arrive before the client stops waiting” still does not imply “all attempts arrive before the refusal fence.” Perfectly synchronized clocks do not fix the order.

**Why the mitigations do not suffice.** A ref fence changes the CAS ETag for attempts that have already read the old head; its timestamp ends attempts with an earlier arrival. It records no durable terminal disposition for a future handler of the same P. The original-version lookup finds committed pushes, not refused ones. Transport cancellation could make particular implementations avoid some schedules, but neither client cancellation nor closing an upstream connection supplies a protocol proof that all already-sent attempts have quiesced. Go's cancellation contract expressly does not wait for work to stop; an application must establish the stronger property itself ([Go context documentation](https://pkg.go.dev/context#CancelFunc)).

**Correction.** Bind terminal refusal to P in durable state covered by publication, for at least P's remaining admissible lifetime, with a bounded lookup/compaction scheme; or introduce a stable admission generation that every attempt of P carries and a fence invalidates independently of the new handler's arrival. Retain “unknown/retry” rather than a stable refusal when the server cannot establish that no still-admissible attempt can commit. The correction can preserve one head-CAS commit point and avoid a Postgres transaction. An asserted delivery-time bound is not enough unless the transport, queues and every retry hop actually enforce it.

**Deterministic acceptance.** Add a barrier before A's arrival timestamp is recorded, not just before its head read. Let B fence and return a quota refusal; delay A past the 100 ms margin, then release it with the allowed stale quota state. Run with identical clocks and with B's reply held until A starts. Assert either one original committed result is returned or no attempt of P can ever commit after the terminal refusal. Include multipart seals and the actual proxy resend path. The existing already-arrived-attempt schedule does not exercise this root cause.

**Confidence qualification.** This is a high-confidence gap in the specified protocol. Whether a particular server/proxy implementation accidentally prevents the exact delayed-dispatch schedule is unverified and must not be relied on without an explicit end-to-end guarantee.

### F11 — Stock Git LFS can force a tip back to a pruned object without invoking the upload agent

**Severity: High; confidence: high.**

**Evidence.** ur/lfs prunes objects referenced by no current ref tip, recent commit, upload or touch. The custom transfer agent touches an object only when Git LFS asks it to upload that object. Git-mode refs permit deliberate force updates. Checkout of a pruned object falls back to a pointer file. See [D §11.11, 7717–7760](/Users/brien/urnetwork/sidecar/DESIGN.md:7717) and the stock-client conformance requirement at [§22.9, 17209–17210](/Users/brien/urnetwork/sidecar/DESIGN.md:17209).

**Primary-source check.** The Git LFS pre-push path normally scans the local tip excluding the remote tip's reachable objects. Its implementation excludes remote SHAs and calls ScanMultiRangeToRemote when pushAll is false; it does not enumerate every pointer reachable from the proposed tip. See [Git LFS pre-push source](https://raw.githubusercontent.com/git-lfs/git-lfs/main/commands/command_pre_push.go) and [upload-range implementation](https://raw.githubusercontent.com/git-lfs/git-lfs/main/commands/uploader.go). This source check was performed; a stock Git integration test was not run.

**Counterexample.**

1. Old commit A contains pointer O. Its child B removes O. A and the last upload/touch are older than the retention window; the remote tip is B.
2. The authorized daily prune removes O. No current tip needs it, so this prune is valid.
3. A stock client performs a force-push from B back to A. A is an ancestor of B. The normal pre-push range “A excluding B” is empty.
4. The custom agent receives no upload callback for O and therefore performs neither its existence check nor its touch.
5. The Git TIP update is accepted. The newly current tip references a missing LFS object. Even if the pusher still has O locally, the specified transfer path was never invoked.

**Why the mitigations do not suffice.** Path-level CAS makes a concurrent touch beat pruning only when the touch occurs. This legal push generates no touch. Pointer-file checkout is appropriate for deliberately pruned historical commits, but it does not make a newly acknowledged current tip complete. The accepted retention policy does not require silently accepting a new current tip whose payload is already gone.

**Correction.** Before publishing a proposed Git tip, the daemon/remote helper must establish protection for every LFS object required by that tip, including old ancestors, force pushes, imported commits and new refs. For objects absent from ur/lfs, require a successful upload or refuse the tip with an actionable missing-object result. Preserve the touch-versus-prune CAS protection, and make it cover this tip-validation phase rather than only transfer callbacks. This does not require keeping all historical LFS objects forever.

**Deterministic acceptance.** With an unmodified supported Git/Git LFS client, build A and B, fake-age A and O past N, prune O, and force B back to A without setting any skip-push option. Assert that the tip cannot be acknowledged until O is restored/protected. Repeat with pruning paused between its scan and commit. Verify that ordinary pushes still upload once and retain exact Git pointer bytes/oids.

**Response assessment.** [R T1-05, 224–231](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:224) resolves the earlier Git-tip ordering problem. This is a new retention/transfer interaction added with v1, not a reason to reopen the already-correct TIP-versus-file-mode separation.

### F12 — Unconditional P0 admission defeats the unconditional physical-write bound

**Severity: High; confidence: high.**

**Evidence.** The governor promises a 0.8-DWPD/50%-IOPS physical budget, with 0.768 DWPD refill and one hour of depth. P0 is never queued or refused and includes lifecycle, shreds, slot rewrites, Removes and REMOVE rotations. Its justification is each class's own rate limits, which are per uploader/group or per network. Allowances subtract only the preceding five seconds' measured P0 writes. FI-14 simultaneously requires the daily drive bound and no P0 wait. See [D §11.13, 8003–8047](/Users/brien/urnetwork/sidecar/DESIGN.md:8003), [§10.6, 6062–6064, 6092](/Users/brien/urnetwork/sidecar/DESIGN.md:6062), and [§22.6, 16109–16111](/Users/brien/urnetwork/sidecar/DESIGN.md:16109).

**Quantitative counterexample.** On the specified 1.92-TB drive, 0.8 DWPD is 1.536 TB/day, about 17.8 MB/s; the 0.768 refill is about 17.1 MB/s. One configured upper-end config or directory rotation stages roughly 6,000 objects and writes roughly 50 MiB per drive. The design says directory rotations follow nearly every shrink because writers write often ([D §19.9, 14181–14192](/Users/brien/urnetwork/sidecar/DESIGN.md:14181); [§10.15, 6465](/Users/brien/urnetwork/sidecar/DESIGN.md:6465)).

For an admitted set of 100 large Teams on one metadata cluster, one shrink per Team every five minutes followed by both config and directory rotations is 57,600 rotations/day, approximately 3.0 TB/day per drive at that stated upper-end cost. The shrinking roster reduces the exact total somewhat but does not close a roughly twofold excess. Each group has only 12 rotations/hour, below the 60/uploader/group rate; the Team has 288 revocations/day, below its 20,000 statements/day. No foreground payload flood is needed. Even one rotation per event puts this workload near the entire physical budget before heads, projections, ordinary traffic or other maintenance.

This is a permissible stress shape, not a prediction of the average Year-1 workload. The contract claims a hard bound under admission, and per-tenant rate limits do not give an aggregate bound when the number of tenants/groups and the work per event vary. The same structural issue applies to “every slot rewrite” and bulk shred work.

**Why the mitigations do not suffice.** Subtracting P0's last five seconds can suppress P1/P2 after the writes occur; it cannot undo P0 bytes or stop the next P0 interval. Per-network closure pacing improves fairness and network rate, but does not cap all P0 work on a cluster. The sector-size argument can bound IOPS only after total bytes are bounded. FS-61 floods ordinary pushes and checks that P0 continues; it does not test aggregate P0-only overload ([D §22.7, 16708–16718](/Users/brien/urnetwork/sidecar/DESIGN.md:16708)).

**Correction.** Separate immediate safety transitions from bulk work. Reserve a provable cluster-wide amount for the small revocation/key-invalidation commit; precharge or schedule the larger wrapping, scanning, deletion and slot-rewrite fan-out while preserving the promised security outcome. Alternatively, state a finite admitted P0 workload and enforce its capacity reservation before admitting that liability. If the owner requires arbitrary P0 completion without delay, FI-14 must explicitly exempt those writes; it cannot remain an unconditional wear/IO guarantee. This is a genuine contract choice, not a reason to silently throttle revocations.

**Deterministic acceptance.** Drive a P0-only multi-network schedule in which every uploader/group/network remains below its own cap. Include full-size wrapped rotations, large erasures and shreds, a killed governor and fallback allowances. Over at least 24 hours of fake counters, check both the physical-byte invariant and P0 latency. A test that succeeds only by silently dropping, blocking or exempting P0 must report that changed contract. Add outstanding cleanup liability and P0 bytes by class to operational dashboards.

**Response assessment.** [R §3.6, 1187–1199](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1187) and [ST-N4, 1617](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1617) correctly explain measured pricing and the sector bound. They do not establish the missing aggregate P0 bound. Preserve the model-based fit for its specified mix; qualify the stronger invariant.

### F13 — The literal allowance split reserves deferred P2 work twice

**Severity: High specification ambiguity.** **Classification:** unresolved algorithmic contradiction, rather than an objection to the write governor or owner-selected hardware. **Confidence:** high that the accounting statements conflict; the throughput calculation applies to the literal `A1 + A2 = T` interpretation, which must be distinguished from the apparent intended credit-transfer implementation.

**References.** [D §11.13, 8021–8029](/Users/brien/urnetwork/sidecar/DESIGN.md:8021) says that the next interval's allowance `T` splits into `A1` and `A2`, that P1 admission debits **full** immediate-plus-deferred cost from `A1`, and that P2 spends `A2`. D §19.6 lines 13953–13959 repeats the split and its publication to workers. But D-EVS-33, line 9075, expressly intends prepaid P2 credit and warns that charging it at admission and again at issue would admit approximately 27% fewer pushes. [R §3.6, 1187–1199](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1187) treats the governor and capacity fit as resolved, and R §6.4 lines 1654–1659 says the old P2 cap has been replaced by a “pre-paid, work-conserving floor.” D-TEST-11, line 17331, requires P2 to be charged once and no refusal at 400 pushes/s.

**Deterministic trace.** Ignore P0, calibration error and emergencies, keep the physical bucket full, and let one push cost 100 units: 63 immediate and 37 deferred. Let `T = 100` units per interval. A steady stream of `q` pushes needs `100q` from `A1`, while completing their funded maintenance needs `37q` from `A2`. With the stated split:

```
A1 + A2 <= T
100q + 37q <= 100
q <= 100 / 137 = 0.729927 pushes per interval
```

The disks perform only `100q`, approximately 73 units, of actual work while 100 units were available. The unused physical budget does not enlarge `T`: line 8022 already caps it at one interval's refill whenever the bucket is at least half full. Thus a work-conserving system capable of one complete push per interval rejects or queues about 27% of that workload. A separate P2 credit balance proves who prepaid the work, but does not remove the second reservation while `A2` is also carved out of fresh `T`. The emergency 40% top-up is not needed to exhibit the problem.

This is material at the advertised gate. For the response's illustrative 33.3 KiB/push on 1 KiB XFS (R line 1718), 400 pushes/s physically costs approximately **0.614 DWPD** on a 1.92 TB drive. The literal split needs `0.614 × 1.37 = 0.841` DWPD of interval allowance, above even the test's 0.8 refill. Production's 0.768 refill would admit roughly **365 pushes/s**, versus approximately 500 from physical bytes alone, under these particular costs. These are illustrative accounting results, not replacements for the measured per-cluster model.

**Why the stated mitigations do not close it.** “P2 spends only that credit,” measuring the bucket from actual device writes, and saying “charged once” describe the intended result, but do not define an account transition that makes the concrete split conserve capacity. Calibration cannot repair it when measured and priced bytes already agree. The M2 no-refusal benchmark should catch the problem; leaving two incompatible accounting rules until that gate makes the claimed closure premature.

**Correction within the constraints.** Specify one conservation equation and the account transitions. Either transfer the deferred portion of each full-price P1 debit into a prepaid P2 wallet whose redemption is **not subtracted again from newly issued `T`**, or divide the physical issuance budget into immediate P1 and P2 capacity and debit only immediate bytes from the former while separately reserving the full deferred obligation. Preserve full-cost tenant weighting and admission of future maintenance; specify how actual-versus-priced differences, retries, unreserved maintenance, process death and the emergency floor reconcile. Do not remove prepayment or the physical governor.

**Acceptance.** A fake-clock governor test with exact costs, `T = 1,000`, 63/37 immediate/deferred proportions, a preloaded steady P2 queue and no P0 must admit and complete ten 100-unit pushes per interval after warm-up, with bounded queues and no 100 ms refusal. Repeat with delayed P2 issuance and process restart; all reserved work must still be funded once. Introduce genuinely unfunded P2 backlog and verify that only the additional repair reservation reduces P1 admission. Separately assert the rolling physical-byte bound and the calibrated-cost correction. This deterministic test should precede the hardware gate and directly exercises the root cause.

### F14 — Safe restore still has a hash-check/rename race that can overwrite a new human edit

**Severity: Medium.**

**Confidence: high. Status: related root cause remains after the attribution fix; not the same as the now-fixed missing pre-edit hash.**

**Design:** §16.7, lines 11178–11220, especially apply at 11212–11213 and RV1–RV3 at 11218–11220. [Restore application](/Users/brien/urnetwork/sidecar/DESIGN.md:11206).

**Response:** T3-07, lines 664–672, and §6.1 line 1545 mark the restore fix complete and cite RV1–RV3. [Closure claim](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:664).

The new before/after chain correctly stops a hand edit preceding the agent's edit from being misattributed. However, the application step takes the worktree's apply lock, checks the current hash, then replaces the path by temporary-file rename. Nothing makes an editor, a shell process or a second harness obey that lock.

Schedule: the dry run binds current bytes A; apply locks and verifies A; an editor writes H; apply renames the prepared original B over H. All specified checks passed, yet the human's new content is overwritten. No crash, malicious operator or obscure filesystem is needed. An in-process lock serializes restores, not arbitrary worktree writers. Rechecking after the rename is too late if H was not retained.

The edge reviewer reproduced this as an isolated scratch trace using the specified operation order: hash check, intervening write, replacement. It demonstrates the algorithmic race, not a test of sidecar source, which does not yet implement it. Go's primary documentation confirms that `Rename` replaces an existing non-directory destination and does not supply an expected-content precondition. [Go `os.Rename` source/documentation](https://pkg.go.dev/os#Rename).

**Correction:** distinguish an exclusively controlled worktree from a live, externally writable one. The strong RV guarantees need a conditional replacement primitive or an enforced writer-exclusion mechanism covering all writers. On ordinary shared worktrees, stage restored content and present a conflict/merge instead of promising an unconditional safe overwrite; any overwrite backend must durably preserve the displaced version and expose a detected conflict. A plain advisory lock plus another stat/hash check is not sufficient. Specify the cross-platform behavior, including deleted files and symlink/path replacements.

**Deterministic acceptance:** stop apply at a barrier immediately after its last successful hash check. From a process that does not acquire the daemon's lock, write distinct bytes to the path, then release apply. The human bytes must not be silently lost, and the result must be a conflict or a retained recoverable version, not an RV3-success report. Repeat with atomic editor-save replacement, deletion/recreation, two selected paths with only the second racing, and Windows. Keep the new before-edit regression too; it covers a different failure.

### F15 — Post-commit push-token projections can regress or resurrect a deleted token indefinitely

**Severity: Medium.**

**Confidence: high. Status: regression/gap in the revised recovery mechanism; the old cross-slot bug is fixed.**

**Design:** §18.7, lines 13368–13409, especially 13372–13374 and 13392–13401; §2.8 api-6, lines 785–788. [Token projection and recovery](/Users/brien/urnetwork/sidecar/DESIGN.md:13368).

**Response:** T3-16, lines 732–741, and RT-N5 at line 1597 call token re-projection resolved. [Wake closure claim](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:732).

Normal POST handling commits Postgres and then unconditionally SETs Redis. Delete commits and then DELs Redis. The reconciliation pass holds selected rows `FOR SHARE` while SETting them and asserts that a racing POST/delete's post-commit Redis operation will therefore land later. That assertion does not cover already committed operations whose Redis writes are delayed, and concurrent normal POSTs have the same problem without any Redis loss.

Deterministic schedule:

1. POST A commits token A and pauses before its Redis SET.
2. POST B commits token B and projects B.
3. A resumes and projects A. Postgres now says B; the wake sender uses A.
4. In the deletion variant, the empty POST commits deletion and DELs the key before step 3; the obsolete token reappears despite no database row.

The per-slot sentinel still names the same master run_id, so the 60-second recovery pass has no reason to reconcile this slot. The stale projection can last until another launch/POST or Redis restart. Inserting reconciliation between steps 2 and 3 does not fix it: the delayed SET can overwrite the reconciled value after its lock is released. Row locks end with their transaction and do not order a different system's post-commit operations. [PostgreSQL row-lock semantics](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS).

The user impact is missed wakes for the current phone and potentially topic/version wake metadata sent to a token the user removed. WK2's acknowledged best-effort enqueue losses are a different issue: this is persistent state divergence. Vendor token-error cleanup must also be protected against stale outcomes.

**Correction:** store a monotonically ordered per-client projection revision with each token change, including a durable deletion tombstone. Apply SET/delete/recovery through a slot-local compare-and-set that refuses older revisions, and reconcile against those revisions. Alternatively use an ordered durable projection outbox with equivalent fencing. The reconciliation pass must not erase the tombstone/fence that prevents an old in-flight SET from coming back. Redis supplies atomic conditional update mechanisms; the missing element is the database-to-cache version order. [Redis transaction/CAS semantics](https://redis.io/docs/latest/develop/using-commands/transactions/).

**Deterministic acceptance:** inject barriers after database commit and before projection for two POSTs, POST versus empty POST, client deletion, and vendor rejection. Deliver projections in reverse order and assert that GET tok equals the newest committed database state. Repeat with the per-slot recovery pass before, during and after the delayed projection, including a restart from an older RDB. A deleted token must remain absent without requiring another app launch.

### F16 — Denying a directory request does not complete the notice/wake path used by the requester

**Severity: Medium.**

**Confidence: high for the missing denial transition; medium for the additional missing decision locator. Status: new v1 integration defect.**

**Design:** §16.11, lines 11987–12018; §18.5 lines 13113–13115; directory surfaces 12139–12153; FS-85 lines 17083–17095. [Request lifecycle](/Users/brien/urnetwork/sidecar/DESIGN.md:11995), [SDK denial semantics](/Users/brien/urnetwork/sidecar/DESIGN.md:13113).

**Response:** §6.9 lines 1768–1778 introduces directory requests and states the additions have not been peer reviewed. [Directory addition](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1768).

The requester leases its notices and, when a notice changes to `decided`, reads the decision. Approval writes the grant/decision and rewrites the notice. The denial row writes a denied decision entry with no statement, and the SDK explicitly says “deny the decision entry alone.” Thus a denial changes the approver's stream, not the requester's leased notice. Phones do not follow all directory streams; their bounded view and notice policy is intentional.

A person asks for repo access and leaves the directory screen. The approver denies it. The requester receives neither the notice transition nor the corresponding wake and can continue seeing `pending` until expiry or an unrelated broad synchronization discovers the entry. It also continues occupying the requester's/target's pending-request budget. FS-85 asserts that deny creates no grant, but never asserts that the denied state reaches the requester.

There is a related underspecification even on approval: `DirectoryNotice` has the requester's stream and sequence, but no decision-writer/sequence or decision hash/locator. The decision is in a different writer's stream. A notice-triggered phone needs an explicit bounded lookup, not an implicit scan of 400 days of all members' streams. At M6 there is no search index to rescue that lookup. If an existing lookup is intended, name it and its bounds.

**Correction:** give both approval and denial one durable, resumable completion protocol: append a decision, then CAS the notice to decided with the decision's authenticated locator/hash. Reconciliation must finish a notice after a crash between those steps. The requester follows that locator, verifies the entry/request binding, emits `access_decided`, releases the pending count and acknowledges/removes the notice. Cancellation/expiry semantics should remain distinct from denial.

**Deterministic acceptance:** use a phone surrogate subscribed only to its own notices, with no directory view open, no indexer and no stream-wide sync. Deny a request and assert one wake/hint, bounded fetching of the exact decision, an observed denied state and released pending capacity. Kill the approver after the decision append but before notice CAS, restart it and assert eventual completion without a grant or duplicate decision effect. Run on M6's format 1 as well as format 2.

### F17 — Reception-time authentication has contradictory size/work bounds

**Severity: Medium.**

**Confidence: high for the evidence-size contradiction; medium-high for operational severity pending concrete library configuration. Status: incomplete boundedness in an otherwise correct fix.**

**Design:** §15.5 lines 10463 and 10481–10500; the receiver has 16 streams at 10465. [Authentication evidence contract](/Users/brien/urnetwork/sidecar/DESIGN.md:10481).

**Response:** T4-09 lines 870–873 calls `MailAuthEvidence` bounded and the finding resolved; EM-N1 line 1601 fixes its metadata disclosure. [Response](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:870).

Checking authentication at reception fixes the rotating-DNS problem. However, the receiver is required to verify **every** DKIM and ARC signature before the deposit commits, and the evidence contains a result for each signature. It must stay at most 8 KiB, “past which verdicts stay and records drop.” An SMTP sender can supply enough distinct signatures/selectors that the domain, selector and verdict fields alone exceed 8 KiB. Dropping DNS records does not make this array bounded. No signature-count/header budget or message-wide authentication deadline is specified here.

The same input creates many distinct DoH lookups and signature checks before the receiver can return its deposit-backed 250. A generous message-size limit is not an authentication-work limit. Sixteen concurrent sessions can consume the receiver's work budget with small bodies and many slow, unique selector queries. A library-level limit might prevent one implementation from exhausting resources, but if so it contradicts “every” and must define the missing/unchecked evidence state; it does not implement the specified contract as written.

This is not a claim of a demonstrated mox vulnerability. The cited reusable DKIM API documents one result per signature and leaves policy to its caller. The DKIM standard explicitly permits limiting attempted signatures to prevent denial of service. [mox DKIM API](https://pkg.go.dev/github.com/mjl-/mox%40v0.0.15/dkim#Verify), [RFC 6376 §6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-6.1). ARC additionally has its own bounded-chain validation rules; they should be applied before expensive verification. [RFC 8617 §5.2](https://www.rfc-editor.org/rfc/rfc8617.html#section-5.2).

**Correction:** specify bounded header bytes, signature/set counts, DNS queries/concurrency and a wall/CPU budget for the complete authentication operation, not just individual lookups. Define deterministic selection priority and a compact `incomplete/resource_limit` verdict with counts for omitted signatures. Evidence serialization must have a hard bound even when all result identifiers are maximal. Preserve the accepted policy that an authentication failure does not reject an otherwise acceptable message, and ensure incomplete evidence cannot create a stronger TLS/authentication label.

**Deterministic acceptance:** a syntactically valid message with enough distinct long DKIM identifiers to exceed 8 KiB of verdicts, plus slow and failing resolver answers. Assert bounded queries, goroutines, CPU/time and serialized evidence; the deposit/SMTP result follows the documented incomplete-evidence rule. Repeat on 16 sessions and confirm another normal message makes progress. Include malformed/overlong ARC chains and normal multiple-signature mail whose aligned valid signature occurs after invalid ones.

### F18 — 128-KiB rounding cannot guarantee that up to five search pages look like none

**Severity: Medium.**

**Confidence: high. Status: new v1 privacy/test overclaim; the underlying coarse aggregation is useful.**

**Design:** C19 §4.6 line 2427; §11.14 lines 8813–8836 and 8921–8924; §22 FS-83 lines 17043–17050. [Claim](/Users/brien/urnetwork/sidecar/DESIGN.md:2427), [acceptance assertion](/Users/brien/urnetwork/sidecar/DESIGN.md:17046).

**Response:** §6.9 lines 1765–1770 introduces remote search and owner decisions 175–176, with the peer-review qualification at 1778. [Response scope](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1765).

C19 rounds each marked peer contract's byte count upward to a multiple of 128 KiB. The pair also carries Hello, HeadCheck and other traffic. Rounding is quantization, not an indistinguishability guarantee. With the same 120 KiB of background traffic, no search reports 128 KiB, while one 16 KiB response page reports 256 KiB. Even a single page violates the stated five-page guarantee. Protocol envelopes only strengthen this counterexample. Multiple/successor contracts and a close near an hourly boundary add cases; applying the rule to both directions does not remove them.

The deterministic arithmetic is: `ceil(120 KiB / 128 KiB) = 1`, while `ceil((120+16) KiB / 128 KiB) = 2`. The counterexample does not assert that an observer learns the query or can always separate search from other traffic. The defect is the unconditional privacy claim and an acceptance test that can pass on a specially chosen low-background fixture while the product claim remains false. The metadata list correctly discloses that live relays still observe timing and fixed frame counts.

**Correction:** either state the actual coarse-bucket leakage and explicitly bound the conditions under which five pages remain in the same bucket, or provide a fixed cover/accounting budget for a defined interval that includes the maximum permitted background traffic plus the promised pages. If the five-page requirement is retained, specify interval boundaries, successor contracts, padding/accounting treatment and overflow behavior independent of the query. That is a substantive cost decision, not something that rounding alone can satisfy.

**Deterministic acceptance:** sweep background bytes across every boundary around multiples of 128 KiB, then add zero through five pages with their exact envelope sizes, both directions, existing and successor contracts. For the retained guarantee, reports must be identical for all supported baselines; otherwise the UI, metadata statement, owner-decision interpretation and FS-83 must all state the narrower leakage. Keep separate tests that evs requests do not depend on the remote query.

### F19 — The advertised next-day erasure bound assumes one physical representation per message

**Severity: Medium; confidence: high.**

**Evidence.** Erasure scans every current and historical index file containing the document. Yet the bound says a mail message or record has one version, therefore it sits in at most one shard/large entry, so erasure needs one i/ segment, one index file and small writer slots and finishes by the next UTC day plus two turns at the 4-MiB floor. See [D §11.14, 8863–8879](/Users/brien/urnetwork/sidecar/DESIGN.md:8863), [§11.13, 8259–8273](/Users/brien/urnetwork/sidecar/DESIGN.md:8259), [§15.7, 10586](/Users/brien/urnetwork/sidecar/DESIGN.md:10586), and [§20.7, 14857–14875](/Users/brien/urnetwork/sidecar/DESIGN.md:14857).

**Counterexamples to the premise.**

- One message is not necessarily one index document. Text beyond 1 MiB is explicitly split into one document per chunk; admitted mail can be 25/50 MiB, and the extractor includes MIME-decoded text bodies without a whole-message 1-MiB cap ([D §11.14, 8340–8342, 8370–8373](/Users/brien/urnetwork/sidecar/DESIGN.md:8340); [§15.7, 10586](/Users/brien/urnetwork/sidecar/DESIGN.md:10586)). Several non-skipped chunks can occupy several large entries or shards even though the message has one version.
- Uniqueness is only per bucket's shards and within all. It is not global across buckets, writers' heads, unmerged large entries and retained historical versions. Concurrent backfillers and delayed companion journals can produce more than one physical copy. The erasure enumeration itself correctly accounts for these copies ([D I-EVS-11, 7517–7519](/Users/brien/urnetwork/sidecar/DESIGN.md:7517); [§11.14, 8515–8518, 8870–8872](/Users/brien/urnetwork/sidecar/DESIGN.md:8515)).

An entry with several separately stored chunks can require more than 4 MiB of closure uploads even before its i/ segment and any held copies. The next-day promise then fails under the correctly enforced per-eraser allowance. The file-size cap bounds each upload, not the sum for one user-visible message.

**Why existing tests do not settle it.** FS-78 already uses the more realistic “ceil(rewrite bytes/floor) days” expression, while the product and quota prose promise a fixed next-day bound ([D §22.7, 16954–16961](/Users/brien/urnetwork/sidecar/DESIGN.md:16954)). Testing the former cannot validate the latter. The per-eraser floor does solve starvation by another admin; it does not bound an erasure's own fan-out.

**Correction.** Use the total actual closure bytes and physical representations to state completion time. Define the unit explicitly: message, chunk/document, or rekey object. Either constrain representation fan-out enough to prove the fixed bound or remove that bound and show a progress estimate derived from the eraser's reserved allowance and queued turns. Ensure a multi-day single-message erasure can safely stage/rewrite subsets without letting later work reopen already-erased copies; F09's publication barrier is a prerequisite.

**Deterministic acceptance.** Construct one admitted text-heavy message with multiple non-skipped 1-MiB chunks; distribute them into distinct large entries/shards, add a duplicate backfill and a held older index version. At the exact storage limit, spent and at the 4-MiB floor, count every closure byte and turn. The reported completion estimate and actual key-destruction point must agree with that total. Test one-message UI semantics across a UTC boundary and process restart.

**Response assessment.** [R T1-13, 295](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:295) and [SL-N1, 1566](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1566) support the per-eraser fairness fix. Retain it; the new index invalidates the old fixed work-per-entry inference.

### F20 — The global newest-version mask is outside the claimed search memory bound

**Severity: Medium; confidence: high.**

**Evidence.** Every search builds one mask set of bucket and retained-bucket document keys, including file and derived-document keys whether they match the query or not. It is asserted to stay small because mail and records are single-version. The advertised phone working set is 4 MiB and the page worker/remote-search working sets are 8 MiB. The cache bounds cover decoded dictionaries/doc tables but give no spill or lookup strategy for this set. See [D §11.14, 8631–8638](/Users/brien/urnetwork/sidecar/DESIGN.md:8631), [§5.9, 3146–3152](/Users/brien/urnetwork/sidecar/DESIGN.md:3146), [§18.4, 13000–13004](/Users/brien/urnetwork/sidecar/DESIGN.md:13000), and [§11.14, 8838](/Users/brien/urnetwork/sidecar/DESIGN.md:8838).

**Quantitative bound.** doc_key is 16 bytes. A set of 500,000 recent file keys needs at least 8,000,000 bytes, about 7.63 MiB, just for keys. One million keys needs about 15.26 MiB, before hashing/table overhead, versions, pointers, a query's postings or decrypted frames. The design explicitly admits 1M-file repositories and allows thousands of 1-MiB shard files per partition; it states no smaller cap on distinct recently changed file/derived keys ([D §11.14, 8343–8345, 8445–8446](/Users/brien/urnetwork/sidecar/DESIGN.md:8343); [§22.8, 15936–15938](/Users/brien/urnetwork/sidecar/DESIGN.md:15936)).

**Counterexample.** All contains one old match for D. D's newer version no longer matches, and the recent buckets also contain hundreds of thousands of other nonmatching changed files. Correctly suppressing all's old D is necessary even for a query with one candidate. The specified algorithm builds the entire recent-key mask. The matching-candidate TooBroad limit does not bound these nonmatching keys. Truncating the set would resurrect stale hits; failing every such query would violate the advertised complete covered search.

**Correction.** Specify a bounded-memory algorithm: a persistent sorted mask/index in the encrypted local cache, a merge-join through sorted doc tables, or per-candidate membership/version probes into already-cached doc tables under a fixed LRU. Keep all network fetches query-independent. Account for this structure, concurrent searches and retained buckets in the working-set contract rather than treating it as free cache state.

**Deterministic acceptance.** Create 500,000 and one million recent nonmatching file updates plus one all-partition row that a newer nonmatching version must mask. Search from a fresh phone/page-worker cache and measure peak allocated/resident search state under the defined metric. Results must match SearchOracle within the declared memory cap; repeat with retained expired buckets and concurrent searches. This is a proposed resource test, not a claim that a current implementation was measured to fail.

**Response assessment.** New index algorithm ([R §6.9, 1766–1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1766)). “No decompression bomb” and an LRU do not by themselves bound a separate cross-partition set.

### F21 — Cold-search first-hit latency contradicts fixed-order whole-index downloads

**Severity: Medium.** **Classification:** an unsatisfiable latency target as written, not a defect in the accepted query-private download policy. **Confidence:** high.

**References.** [D §16.10, 11426–11428](/Users/brien/urnetwork/sidecar/DESIGN.md:11426) fetches every missing `all` shard, whole, youngest first in fixed manifest order, and searches each as it arrives. D lines 11632–11633 promises, for a cold 165 MB partition at 10 MB/s, the “first all hit” within three seconds after the first shard lands, with the rest download-bound at about 17 seconds. D §16.12 lines 12162–12164 rejects query-directed fetching and stopping at sufficient hits. [R §6.9, 1762–1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1762) identifies these search additions as new, explicitly not peer reviewed; this is not a previously resolved response finding.

**User journey and lower bound.** A phone with no answering indexer searches for a rare term found only in the oldest shard of its otherwise absent 165 MB `all` partition. Its current buckets have no hit. All earlier shards lack the term. With 1 MiB maximum shards (D §11.14 lines 8419–8433), a fixed-order transfer cannot reach the last shard until approximately `(165,000,000 - 1,048,576) / 10,000,000 = 16.4` seconds. No first hit can be returned within three seconds after the first shard in that valid transfer schedule, even with zero verification or CPU cost. An absent term similarly cannot produce a complete negative result before the scan finishes. Returning an arbitrary early candidate does not solve the case because there is none in the earlier shards.

**Why the mitigations do not close it.** Streaming results and returning `complete=false` with a cursor (D lines 11573–11581) provide a good responsive interface, but cannot make an unavailable matching shard arrive earlier. Local caching and a designated indexer improve other scenarios; the target explicitly says cold and the design deliberately defaults to no indexer.

**Correction.** Keep the private fetch order. Split the target into time to progress/coverage, processing delay after a relevant shard arrives, and completion time as a function of missing bytes and effective throughput. If the three-second target is intended as a percentile over a corpus/query distribution, name that distribution and report late-hit and no-hit completion separately. Also distinguish cold synchronization from the warm-cache query targets rather than implying every search can satisfy both.

**Acceptance.** Construct identical-sized manifests with the sole exact match in the first, middle and last shard, plus a no-match query. At a deterministic throttled 10 MB/s, assert identical fetch order and byte count for all four queries, bounded progress response latency, correct partial/complete status, and result availability only after the necessary data arrives. Repeat across a 1 GiB `MoreByteCount` boundary with cursor continuation and a cache smaller than the index; verify forward progress without restarting the fixed-order scan. This tests the user-visible contract without weakening I-19.

### F22 — Some directory benchmark acceptance criteria are unspecified

**Severity: Medium.** **Classification:** a benchmark/gate specification gap. It is not a claim that the directory cannot scale. **Confidence:** high for the missing daily-GET and explicit directory latency/retry thresholds; medium for the implementation impact until test authors choose them.

**References.** [D §22.7, FS-86, 17096–17100](/Users/brien/urnetwork/sidecar/DESIGN.md:17096) requires commit p99 and 409 retries at 5.8 pushes/s with 3× bursts, and readers' daily download and GETs “within §16.11's figures.” D-TEST-17, line 17343, repeats that comparison. D §16.11 provides useful daily byte estimates at lines 12058–12079 and synchronization rules at 12139–12148, but no per-reader daily-GET acceptance table or directory-specific commit-p99/retry ceiling. The missing criteria should be added to that existing cost table, not treated as though no byte model exists. D §16.12 line 12168 adds an illustrative cold-start comparison (22 MB versus 1.5 MB at 500 members). D §19.6 lines 13849–13851 gives a different peak figure, 6.7 pushes/s including the directory's total workload. [R §6.9, 1762–1778](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1762) correctly leaves the new directory additions unreviewed rather than claiming this test has established capacity.

**Concrete failure of the gate.** One implementation downloads unchanged heads or repeats card/index reads after every conflict. Another coalesces and reproduces them correctly. Both can report p99, retries and GETs, and both may remain below the general drive-write gate, but there is no specified GET/day ceiling for FS-86 to compare against. Similarly, merely recording commit p99 does not say when it must fail. A pass based on lower write amplification can therefore coexist with an unbounded practical reader-transfer regression. Since directory reads debit the team's transfer balance without exemption (D §20.7 lines 14812–14824), this is an operator and user cost concern, not just a test-report presentation issue.

**Correction.** Add the referenced cost/acceptance table: number and mix of members, admissions, active announcing writers and reading devices; active hours; card/entry sizes; renewal, start/end and notice rates; cold versus warm bytes; GETs and bytes per active reader-day and per team-day; commit-p99 and retry ceilings; and phone completion/partial-coverage behavior at the 8 MiB metered-session cap. Explain which part of the 6.7/s total becomes FS-86's 5.8/s shared-ref load. Run physical-time latency/IO measurements for the real-store workload; use the fake clock for reproducible event schedules and long retention periods. Add an M6 entry-carrier case if that feature can launch before M10—the current gate deliberately covers cards only at the later exit (D lines 11870–11874, 17096–17100), so the larger format-1 reader cost otherwise remains a disclosed but unquantified launch limit.

**Acceptance.** A golden deterministic schedule at 500 members and at the maximum admitted configuration must calculate expected reads and ciphertext bytes independently of the sync implementation. Deliberately disable coalescing, head reproduction or unchanged-card suppression one at a time and show that the relevant budget assertion fails. Separately inject commit delays and conflicts above the chosen thresholds and verify gate failure. Include a cold phone whose current-state bytes exceed 8 MiB and assert explicit partial coverage and a usable continuation/consent path, not an apparently complete empty result.

## Acknowledged residuals that still need their feature gates

### K01 — The disclosed late-drive residual remains a storage-correctness dependency

**Status: known, conditional, critical if exercised.** This is not presented as a newly discovered or concealed residual. The response explicitly says a drive operation stalled beyond the 30-second drive timeout can land late ([R §6.8, 1756](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1756)); the current risk table calls its impact critical ([D §19.17, 14566](/Users/brien/urnetwork/sidecar/DESIGN.md:14566)).

The required BlobStore contract is stronger: a cancelled PUT/DELETE lands within measured lag L or never, and before any later request on the key ([D §11.13, 7921–7925](/Users/brien/urnetwork/sidecar/DESIGN.md:7921)). The proposed in-house MinIO patch propagates cancel, checks immediately before commit and keeps the namespace lock until all operations answer **or the 30-second drive timeout**. The conformance suite gates observed lag below 100 ms ([D §19.6, 13908–13935](/Users/brien/urnetwork/sidecar/DESIGN.md:13908); [§22.9, 17211](/Users/brien/urnetwork/sidecar/DESIGN.md:17211)).

**Failure schedule.** An old drive operation passes its final cancel check and is suspended before or during its irreversible filesystem action. Its coordinator eventually reaches the 30-second limit and releases the object's lock. A later request acquires the lock, validates a precondition and publishes a newer value. The old action then resumes and overwrites or deletes that value. Pause enough constituent writes to affect the object quorum for the head-CAS case; for deletion, exercise the same schedule across the relevant replicas and healing. A cancellation check before a syscall and a timeout on waiting for it do not constitute a final-commit fencing token.

This is directly relevant to unconditional marker collection, live versionless content/slot purges, stale folds and head CAS, not merely an extra few milliseconds of latency. Collection waits 15.3 seconds and relies on L below 100 ms ([D §11.7, 7062–7066, 7093–7108](/Users/brien/urnetwork/sidecar/DESIGN.md:7062)). A finite timing experiment cannot turn a timeout that releases an ambiguous operation into an ordering guarantee. The general Go cancellation semantics likewise do not wait for completion ([Go context documentation](https://pkg.go.dev/context#CancelFunc)); the exact custom storage build still needs its own proof and tests.

**Required closure.** Preserve the chosen store, but provide target-side serialization/fencing that remains valid across delayed work and coordinator failure, or keep a key unavailable until every old operation is conclusively quiescent. Do not release an ambiguous lock and then permit later mutations solely because 30 seconds elapsed. If robust deletion fencing is unavailable, retain markers/candidates and fail closed rather than use time as proof that destructive operations cannot arrive. The design may consciously accept an availability outage; it should not describe the resulting storage protocol as unconditionally linearizable while the known late-write schedule remains admissible.

**Deterministic acceptance.** Barrier each remote drive after its last cancel check and before commit, hold it for more than 30 seconds, cancel and kill/restart the coordinator, and attempt a newer same-key mutation. Release the old operation. The newer acknowledged state must remain unchanged, including after healing. Run conditional head PUT, marker DELETE, slot/kind-5 purge and drop-job DELETE variants. Include these schedules in the storage model's environment assumptions, not only the normal-lag benchmark.

The response's update to margins and conformance wording at [1757](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1757) is useful and correctly incorporated. It closes the missing-reference/margin issue, not this explicitly surviving ordering defect.

### K02 — Custom-host readiness still relies on an unacknowledged 15-minute wait

**Confidence: high. Status: known residual in the response; the original missing-map bug is fixed, but the stated activation invariant remains false under ordinary deployment failure.**

**Design:** §13.4 lines 9707–9710, 9735–9741; §19.5 W1 line 13789. [Activation and probes](/Users/brien/urnetwork/sidecar/DESIGN.md:9735).

**Response:** T4-06 lines 851–854 explicitly says the activation barrier is only a fixed wait and probes cover root names, while marking the item resolved. [Acknowledged residual](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:851).

After a custom host's row becomes active, every lb should regenerate its SNI map and reload within 15 minutes. The first TLS-ALPN-01 order waits that interval. If one lb misses the update, cannot reload, or recovers with an old map, it continues sending that custom SNI to the platform HTTP branch. The `probe.edge.<root>` probe still passes because the wildcard route was already present. Platform checks pass as well. The bad interface remains in DNS, so customer requests and CA validation fail intermittently after the declared active time.

The rollout drain/benchmark protects installation of the split itself, not subsequent per-host map updates. Logging hosts added/dropped is not a per-interface applied-version barrier. The standard permits a CA to choose any resolved address and requires port 443 with the requested SNI/ALPN, so this is observable in normal issuance, not merely a hypothetical bespoke client. [RFC 8737 §3](https://www.rfc-editor.org/rfc/rfc8737.html#section-3).

**Correction:** separate validated/desired host state from ingress-ready state. Track a version/digest acknowledged after successful load on every serving interface; gate publication/first order on that readiness or remove an unacknowledged interface from the applicable address set. Include an actual newly added custom hostname in the probe set and restore/rejoin procedure. Bound readiness time as an operational SLO with failure reporting, not an unconditional timer-based guarantee.

**Deterministic acceptance:** add a custom host while one advertised lb drops its update or rejects reload. Advance the clock by more than 15 minutes. The host must remain visibly pending or the bad interface must be drained; a CA connection forced to each advertised address must reach the correct sidecar challenge. Repeat on lb restart with a stale map, add/remove coalescing and a restore that changes custom hosts. Preserve unknown-SNI/platform routing tests.

### K03 — The phone has no API for revoking an ordinary lost device

**Medium; known product/security-operations gap.** RESPONSE §6.9 line 1781 expressly flags this and is correct. DESIGN §5.6 line 3021 promises revocation through an app UI, §5.9 line 3160 describes recovery followed by revoking lost devices, and §18.8 lines 13477–13482 offers revocation of older browser Workers. Yet §18.5's complete bound API at lines 13035–13204 has only alarm-specific revocations inside `SidecarApprovals.Decide`; a normal stolen laptop need not have any such pending approval. `Close` and loss of an access token are not a signed `SidecarRevoke`. [Design promise](/Users/brien/urnetwork/sidecar/DESIGN.md:3021), [response admission](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1781).

Add a core preview/confirm revocation method with a bound SDK surface: enumerate authorized targets, show `lost` versus `compromise`, `since_n` and the cascade, then sign under the existing consent rules. It must remain unavailable to MCP and read-only page Workers. Deterministic acceptance: with only an enrolled phone online and no pending alarm, revoke a lost laptop; assert its verified revoke, connection closure, group rotation and denied future access. Test the same journey for an evicted browser Worker and refusal to revoke an unauthorized member's device. This is necessary at M8's app exit; identifying it in the response is not implementation closure.

### K04 — Outbound DATA size limits need an outbound capability/result journey

**Medium; known disclosure gap.** RESPONSE T4-02 lines 829–831 accurately acknowledges this. DESIGN §14.5 line 10170 defines approximately 600 KiB/1 MiB host-dependent caps for non-CHUNKING destinations; §18.5 lines 13213–13222 puts “large attachments may not reach a minority” on `GetReceiverCoverage`. That does not tell a user composing a normal photo attachment why this recipient fails, which recipients remain deliverable, or whether waiting helps. [Limit](/Users/brien/urnetwork/sidecar/DESIGN.md:10170), [copy](/Users/brien/urnetwork/sidecar/DESIGN.md:13213), [response](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:829).

Keep owner decision 125 and expose an outbound send-capability/result model: measured cap, actual encoded message bytes, recipient-domain mode, expected delay and per-recipient outcome. Show it during composition when known and in a pre-MAIL failure otherwise. Test a message just above the measured DATA cap addressed to one CHUNKING and one non-CHUNKING domain: only the latter receives the precise cap failure; no vague suggestion that an inbound indexer or receiver toggle fixes it. Do not reopen the accepted proof-performance tradeoff itself.

### K05 — Stale Workers can accumulate with self_admit disabled

**Medium; known lifecycle gap.** RESPONSE §6.9 line 1780 notes that an admin admitting a browser Worker does not run the member-consented stale-Worker revocation path. DESIGN §18.8 lines 13477–13486 still says evictions do not pile up. Exercise weekly storage eviction under `self_admit=false` for longer than stale-leaf removal and show bounded admissions, or qualify the claim and surface admin cleanup before quota exhaustion. This is a known lifecycle residual, not evidence that the Web Lock fix failed. [Admission behavior](/Users/brien/urnetwork/sidecar/DESIGN.md:13477), [response residual](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1780).

## Conditional capacity and implementation constraints

### CC-01 — The global path-copy limit is a service-rate constraint

[D §11.6, 6602–6619](/Users/brien/urnetwork/sidecar/DESIGN.md:6602) permits three source epochs, blocks creation when a fourth must wait, and caps copying at 50 operations/s per repo, 150 with multiple sources, and 250 “in all.” Even the optimistic three-operations-per-entry model gives at most:

**250 × 86,400 / 3 = 7.2 million migrated entries/day globally.**

Prefix HEADs, retries, directory translation and shared P2 pressure lower that ceiling. A concrete stress case starts 30 one-million-entry refs together, each making an epoch due once daily: before the fourth daily epoch, every original source must have emptied to avoid a fourth source. Even ignoring all re-copy work, those 30M original entries require at least 90M operations, while 72 hours at the global cap allows only 64.8M. Some refs therefore reach the source-limit block. Per-repo acceleration cannot raise the global cap. Newer maps can supersede older copy jobs, so merely multiplying eight daily epochs by one million entries would not prove an ever-growing backlog; that simpler argument is deliberately not used. This stress shape extends the admitted 1M-file/one-hour-grant fixture, whose current gate records copy operations but does not require a stable backlog ([D §19.9, 14209–14214](/Users/brien/urnetwork/sidecar/DESIGN.md:14209); [§22.8, 15936–15938](/Users/brien/urnetwork/sidecar/DESIGN.md:15936)).

This is a conditional workload limit, not evidence that average launch traffic will reach it. [R T1-07, 240–247](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:240) closes snapshot/tail/starvation protocol issues; it does not eliminate the finite global service rate.

Clarify the scope of “in all,” publish the migration liability per cluster and projected drain time, and add a multi-day fake-clock load gate that requires bounded source age and no sustained EPOCH_SOURCES_FULL at the admitted rotation workload. Capacity planning must multiply *live entries per rotating repo*, not just count rotations. Any increase in copying must remain inside the measured physical-write/P2 budget.

### CC-02 — The HDD model's write floor already consumes its 50% allowance at the optimistic capacity

The design models Year 2 at 400 PUT/s and 1,600 GET/s, approximately 16 drive operations per object operation, against 8,000–12,800 operations/s capacity ([D §19.6, 13862–13878](/Users/brien/urnetwork/sidecar/DESIGN.md:13862)). Admission starts refusing uploads above 50% of measured capacity ([§11.13, 8042–8047](/Users/brien/urnetwork/sidecar/DESIGN.md:8042)).

Under those same constants, PUTs alone require **400 × 16 = 6,400 operations/s**. The 50% allowance is only 4,000–6,400. At the low end, writes alone exceed admission; at the high end they consume all of it before any physical GET, versionless purge, search-index rewrite or drop. The new index adds roughly 650–2,250 modeled operations/s at Year 2. “Cache most GETs” is therefore not a complete Year-2 fit argument.

This is an inference from the stated model, not an independent disk benchmark. Physical writes may coalesce differently, which is precisely why the measured hdd gate must settle it. Require the full mixed workload with **the actual 50% admission policy enabled**, reporting accepted throughput and foreground refusal rate as well as raw capacity. If it cannot pass, segment placement/additional sets must precede that load; lowering the safety threshold or counting rejected traffic as throughput is not a fit. [D §22.8, 15913–15921](/Users/brien/urnetwork/sidecar/DESIGN.md:15913) supplies the measurement hook.

### CC-03 — New-cluster placement does not make old cohorts or the first cluster elastic

[D §19.9, 14247–14255](/Users/brien/urnetwork/sidecar/DESIGN.md:14247) places only new repos on new clusters; existing repositories and groups remain where they are, and placement/projection/revocation/hold/per-sidecar families stay on the first cluster. The old-cohort outgrowth risk is already explicit ([§19.17, 14563–14564](/Users/brien/urnetwork/sidecar/DESIGN.md:14563)). This is an accepted architectural tradeoff, not a hidden design defect.

The operational consequence is that “five to six sets in Year 2” is an aggregate estimate, not a proof every cohort fits. Track each cohort's wear/inodes/space and its own growth slope, and the first cluster's continuing control-plane growth. Tie the later move tool or a stated admission limit to the earliest predicted cohort exhaustion, not the total estate's free space. A launch drill should demonstrate the intended behavior when an old cohort saturates while new sets are mostly empty.

### CC-04 — Redis sequence scripts need explicit lossless 64-bit handling

[D §11.10, 7668–7674](/Users/brien/urnetwork/sidecar/DESIGN.md:7668) initializes the evs sequence from Redis TIME milliseconds × 2^20 and increments it inside one script. [§6.8, 3640–3645](/Users/brien/urnetwork/sidecar/DESIGN.md:3640) compares topic versions and raises only higher values. In 2026 that sequence is about 1.9 × 10^18, far above 2^53.

Redis documents a Lua 5.1 interpreter and conversion of integer replies to Lua numbers; Lua's ordinary number type is double precision ([Redis Lua API](https://redis.io/docs/latest/develop/programmability/lua-api/), [Lua 5.1 manual](https://www.lua.org/manual/5.1/manual.html#2.2)). Thus a natural implementation returning the Lua numeric result of INCR, or comparing these decimal versions through tonumber, loses low bits. The Redis stored integer may be exact while the script's returned/published value repeats or rounds.

This is a conditional implementation trap, not an unavoidable design failure: the script can use exact decimal bulk strings, string-safe comparison and Redis's integer command semantics without converting the sequence through a Lua double. Make that requirement and wire representation explicit. With a fixed 2026 TIME, test at least 1,024 consecutive raises through the actual publisher and client decoder, each exact successor, then test loss/reinitialization and the higher-only comparison. FS-62 currently emphasizes restart ordering rather than adjacent-value precision. [R T1-23, 354–357](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:354) is correct about repo-wide sequencing; this arithmetic detail still needs a deterministic vector.

### CC-05 — Cross-network “intersection” needs an explicit colluding-operator boundary

The source says X's target grant and Y's subject grant intersect at X's provider and Y's routers. Y's current config readers receive the generation's ShareSigner seed; X verifies Y network/share membership, not Y's per-subject grant ([D §8.11, 5157](/Users/brien/urnetwork/sidecar/DESIGN.md:5157); [§17.9, 12637–12710](/Users/brien/urnetwork/sidecar/DESIGN.md:12637)). The shortened certificate/root lifetime fixes removed-reader/static-root exposure, as [R T2-26, 534–541](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:534) and AU-N7 intend.

A narrower conditional trace remains: a modified current Y reader denied by Y policy holds the valid ShareSigner; with a colluding contract service it can obtain a contract and sign a Y delegation that X accepts for an X-approved target. X's own restrictions still hold. This is not a demonstrated bypass against an honest contract service, so it is not promoted to a high-severity defect. State whether “intersection” is promised against both adversaries together. If so, X needs customer-signed per-subject/target authority it verifies. If Y's entire current reader population plus local enforcement is intentionally the trust unit, disclose that beside the claim.

**Acceptance:** a genuine Y reader with no Y grant, its valid current signer and an operator-created contract to an X-approved target. Record which side's policy rejects it; do not credit Y's bypassed local router with enforcement.

### CC-06 — Socket issued-count cap versus eager reports may cap one dialer's throughput

[D §9.7, 5519–5522](/Users/brien/urnetwork/sidecar/DESIGN.md:5519) caps primary tickets since the last report at max(4, 10% of max_streams) per dialer, while eager load reports begin at max(8, 25% of max_streams) moves ([§9.4, 5422](/Users/brien/urnetwork/sidecar/DESIGN.md:5422)). If the former stops issuance, one dialer for a 256-stream listener can issue about 25 tickets and wait for a 15-second heartbeat without reaching the eager threshold. If it only clamps an estimate, say so and define the fairness consequence. [R T4-26, 951–954](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:951) fixes source identity, not this throughput ambiguity.

**Acceptance:** a deterministic one-dialer short-connection workload must establish the exact cap/report interaction and its sustainable issued tickets/s. Do not derive connection throughput from concurrent-stream capacity alone.

### CC-07 — Complete the maintenance and long-lived proof matrices

Two narrower specification checks remain without a demonstrated failure. First, map read-only ReaderKey/KeyPackage uploads, own MLS path commits, resync and acknowledgements to the precise HTTP scopes and signature allowlist; the clear intent to permit maintenance should not be defeated by a generic “only” authority list. Second, an indefinite RepoAnnouncement needs a durable proof of its older authorization pin after ordinary log retention, whereas DirectoryCards use an explicit 4,096-position age check ([D §16.11, 11757–11768, 11844–11860](/Users/brien/urnetwork/sidecar/DESIGN.md:11757)). Name whether that proof travels with the announcement or comes from retained config/access history. Test both through the real retention horizon. Neither is counted as a confirmed defect because the intended existing route/history may already suffice.

## Response closure: what should stay resolved, what must be narrowed

The response is a valuable issue ledger. Its strongest feature is distinguishing accepted limits, fixed text, review closure and future runtime evidence. Keep those categories; do not flatten them into a single “all fixed” count.

| Area / response claim | Current disposition |
|---|---|
| T2-01, one causal authorization prefix ([R 363–370](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:363)) | Substantively repaired: (n, A_n), replay, retention and shrink/expiry identities give consumers one state. F02/F03 concern delivery capabilities left live under that state. |
| T2-02, one generation claim ([R 372–378](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:372)) | Repaired: all writers stage then claim gen/g; MLS commits no longer mint a competing generation. F04/F05 concern late delivery after that claim. |
| T2-03/T2-04, holder exclusion and shared-key residual ([R 380–394](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:380)) | Ordinary reap is an accepted exception. Suspend/individual expiry and the stolen full bundle's continued admission authority are different; F02/F03 require correction or narrower claims. |
| T2-08/T2-09/T2-18 and recovery follow-ups | Proposal time, veto, activation, genesis anchoring, restored-binding ReaderWrap-first order and compromised-backup implications are materially specified ([D §7.9, 4512–4593](/Users/brien/urnetwork/sidecar/DESIGN.md:4512)). Preserve the explicitly disclosed sole-config-writer deadlock at [R 1751–1752](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1751). |
| T2-10/T3-26, typed signatures | Purpose, type and stored body bytes are bound; dispatch checks expected type ([D §6.9, 3677–3698](/Users/brien/urnetwork/sidecar/DESIGN.md:3677)). No need to revive protobuf reinterpretation claims. |
| T2-24/WR-N6, copied-keychain healing ([R 514–522, 1589](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:514)) | Tree/content and passive post-quantum qualifications improved. F06 shows that authenticated ReaderKey retirement and active-clone assumptions still do not support the stated numerical bound. |
| T1-01/T1-03 and ST-N1, head publication and committed folds ([R 195–213, 1614](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:195)) | The mechanism closes pending-version eviction and blind stale removal. Dependence on K01's actual store ordering remains. |
| T1-02, uncertain outcomes ([R 201–208](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:201)) | No answer-time cleanup and bounded committed-P lookup are real fixes. Terminal refusal still needs F10; preserve the correct parts. |
| T1-04, orphan GC ([R 215–222](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:215)) | Receipts, 25-hour age, fences, second checks and batch evacuation address the missing roots. No new direct adoption/GC race was established under the storage contract. |
| T1-05, Git tips ([R 224–231](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:224)) | TIP/file modes and proc-receive journal repair the original issue. F11 is the new LFS retention seam. |
| T1-07, path migration ([R 240–247](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:240)) | Map/tail, creation block, overlap and directory-copy rules address the old traces. CC-01 is workload stability, not the old snapshot bug. |
| T1-12, restore versus shred ([R 281–286](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:281)) | Terminal shredding/deletion ID and per-phase rereads define a winner. No new counterexample apart from K01's environment assumption was found. |
| T1-13/SL-N1, closure and quota starvation ([R 288–295, 1566](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:288)) | Known-copy enumeration and per-eraser allowance fix the old issues. New index publication and representation fan-out require F09/F19. |
| T1-23, repo-wide hints ([R 354–357](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:354)) | Correct scope and explicit hourly recovery. CC-04 is the lossless arithmetic requirement. |
| T3-01/T3-02/T3-08, approvals/taint | Durable reserve-before-effect, unknown uses consumed, action/pin binding and monotone taint address the named restart/late-approval failures ([D §16.6, 10973–11002, 11053–11146](/Users/brien/urnetwork/sidecar/DESIGN.md:10973)). Already-reserved effects may finish by explicit policy. |
| T3-07, restore attribution ([R 664–672](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:664)) | Before/after chaining fixes earlier attribution. F14 is the different live-worktree commit race. |
| T3-09/RT-N1, MCP secret/config access ([R 1593](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1593)) | Explicit resource refusals and person-only authority restrictions now exist; do not report the previous broad tool-access gap again. |
| T3-13/T3-14, keystore state | Present/Absent/Locked/Failed and identity/token separation avoid creating a new identity on an unreadable store ([D §5.9, 3162–3172](/Users/brien/urnetwork/sidecar/DESIGN.md:3162); [§18.5, 13017–13048](/Users/brien/urnetwork/sidecar/DESIGN.md:13017)). |
| T3-16/RT-N4/RT-N5, mobile wake ([R 732–741, 1596–1597](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:732)) | Slot-local script/separate enqueue fixes CROSSSLOT; named losses are honest. F15 remains on ordering the token projection. |
| T3-18/RT-N8, browser concurrency ([R 1600](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1600)) | Separate key origin, exact-origin messaging and per-network Web Lock address the original key/multiple-writer traces. K05 is an already-disclosed enrollment lifecycle gap. |
| T3-19/T3-22, wasm/modules ([R 758–764, 785–791](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:758)) | HTTP-only build leg, narrow device protocol, nested modules and tagged-consumer release fixture are coherent. |
| T4-01/EM-N4, SMTP relation ([R 821–827, 1604](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:821)) | Server state, post-TLS capability checks, successful envelope replies and public handshake inputs now bind the intended relation ([D §14.5, 10117–10176](/Users/brien/urnetwork/sidecar/DESIGN.md:10117)). Circuit, interop and timing remain M9 evidence gates. |
| T4-04/EM-N3, effective CAA ([R 838–844, 1603](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:838)) | A/AAAA-only flattening preserves customer CAA in strong mode; weak CNAME mode and operator-controlled probe limits are disclosed ([D §12.8, 9531–9550](/Users/brien/urnetwork/sidecar/DESIGN.md:9531)). |
| T4-05/T4-10, strict MX and validated labels ([R 846–849, 875–878](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:846)) | Strong claim now requires customer-signed MX selection and TLSA; ordinary URnetwork-zone/direct-MX paths retain EX2. “Validated” is a stated basis/reputation inference, not proof that intermediaries saw no plaintext. |
| T4-06, custom-host route ([R 851–854](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:851)) | Missing SNI map fixed. Its acknowledged no-ack readiness residual is K02. |
| T4-07, ALPN audience bypass ([R 856–861](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:856)) | Signed AppMode selects HTTP authorization; no-ALPN does not bypass it. Raw link audiences use pinned mTLS. |
| T4-08/T4-09, reports and reception evidence ([R 863–873](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:863)) | Bounded aggregate parsing/dedup and reception-time provenance address the old issue. F17 is the separate per-message authentication-work/evidence bound. |
| T4-11, plaintext report exception ([R 880–884](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:880)) | Directive, metadata list and Appendix G now include the limited platform report intake exception; do not repeat an unconditional operator-never-sees-any-plaintext promise. |
| T5-22, format freeze ([R 1109–1114](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1109)) | Specification evidence at entry and executed byte/interop/fault evidence at exit are correctly separated. No production format before final freeze. |

Two response residuals should be updated because the current design has moved further:

- **Versions after collection:** [R 1755](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1755) still says a path may restart at 1. [D §11.7, 7041–7050](/Users/brien/urnetwork/sidecar/DESIGN.md:7041) now uses max(effective base, removal version)+1 and explicitly prevents restart after collection/copy. The current design's fix should receive credit.
- **Closure upload pacing:** [R 1753](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW-RESPONSE.md:1753) says no network-wide closure-upload rate exists. Current §20.7 adds equal-turn four-upload/s pacing. Admissions-times-allowance exposure remains, but absence of pacing is stale. This correction does not close F12's aggregate P0 problem.

## Architecture, efficiency, performance and usability

The service boundaries are sound: shared client/core code owns formats and state machines; server-only engines import it through ServiceHost capabilities; the keyless device imports the narrow bridge protocol; HTTP-only wasm excludes connect/gVisor; CLI/proof/interop modules do not become root dependencies. Cross-repo pins, tagged-consumer builds and pending migrations address practical release hazards ([D §4.4, 2309–2341](/Users/brien/urnetwork/sidecar/DESIGN.md:2309); [§4.7–4.9, 2456–2489](/Users/brien/urnetwork/sidecar/DESIGN.md:2456)). Preserve these choices.

The dominant architectural dependencies are the strong storage-adapter ordering contract, separate content/index/erasure commits, delivery capabilities outside MLS, and the first cluster's permanent control-plane role. The findings identify missing transitions at those boundaries; replacing the whole architecture is unnecessary.

Physical cost accounting is a strength. The design includes the approximately 14-KiB head-overwrite floor, per-process/per-cluster batch occupancy, marker costs, wraps, path copies, staged index heads, purge IO and XFS block size. Format 2 projects roughly 42–45 KiB/push on 4-KiB blocks against the 43-KiB gate, versus 34–37 KiB on 1-KiB blocks ([D §11.13, 8003](/Users/brien/urnetwork/sidecar/DESIGN.md:8003); [§22.12, 17331–17335](/Users/brien/urnetwork/sidecar/DESIGN.md:17331)). These are model inferences, not measured performance from this review. F12/F13 challenge admission invariants, not the decision to meter physical work.

Useful bounds to keep together in operating plans:

| Mechanism | Bound or consequence from the design's constants |
|---|---|
| Physical refill | 0.768 DWPD × 1.92 TB ≈ 17.1 MB/s per busiest non-healing drive |
| Gate versus sustained production | At 43 KiB/push, 400/s ≈ 0.793 DWPD; 0.768 refill permits about 388/s before extra work. At 34–37 KiB, about 490–450/s. The 0.8-refill gate is deliberately different. |
| Global path copying | At 250 operations/s and at least three/entry, no more than 7.2M entries/day before prefix checks/retries/P2 competition |
| HDD write floor | 400 PUT/s × 16 modeled operations = 6,400 operations/s, already all of the optimistic 50% allowance |
| Mutable search mask | 500k 16-byte keys alone are 7.63 MiB; 1M are 15.26 MiB, excluding containers/query work |
| Cold 165-MB search | At 10 MB/s, a last-shard-only match cannot arrive before roughly 16.4 seconds |
| Directory fan-out | The 5,000-member model estimates about 2–2.6 TiB/day across reading daemons, roughly $175–235/month under its tariff; transfer, not NVMe, is the binding modeled term ([D §16.11, 12058–12079](/Users/brien/urnetwork/sidecar/DESIGN.md:12058)). This is a stress model, distinct from the ordinary 5,000-admission/approximately 2,000-member configuration. |

Existing optimizations are well motivated: query-independent whole-file index sync, head reproduction, fixed remote envelopes, no query-time evs/api/gkm reads, bounded remote concurrency/CPU/cursors, cache limits, progress/partial coverage and fair queues. Avoid “fixes” that defeat those constraints—for example, query-directed shard downloads, global directory stream scans for one denial, or mandatory mirrors on every reader.

Operational enablement is also stronger than a feature checklist. The M2 run includes preloaded old batches, restart, P2 completion and no FOLD_BEHIND; purge begins in observe mode for at least 14 days/10,000 candidates; drops require 30 days/200 jobs and an independently implemented retained-version oracle. Format 2's owner-approved computed gate is followed by measured/priced production confirmation inside a restricted rollout ([D §22.12, 17331–17345](/Users/brien/urnetwork/sidecar/DESIGN.md:17331)). Keep those future evidence requirements visible.

Usability must reflect the same states:

- Erasure should show actual representations/bytes remaining, next allowance/turn and whether the durable publication cut is complete. A long wait at quota is different from an unknown operation.
- A retry UI must retain the operation identity while its outcome is unresolved. A terminal refusal must actually be stable.
- A stale push token, denied directory request or lost-device revocation needs a completed durable journey, not merely a present SDK method or logged background task.
- Custom-host setup should report desired versus applied ingress state. Elapsed time is not readiness.
- LFS should reject/repair an incomplete newly current tip before acknowledgment. Pointer-file fallback remains useful for deliberately pruned old history.
- Search should distinguish partial coverage, skipped documents, capacity limits and a real complete zero-result answer. It must not hide an unavailable diff base, truncated mask or not-yet-fetched last shard as “no match.”
- Operators need migration liability/drain time, P0 work liability and per-cohort/first-cluster exhaustion, not only estate-wide free space. Key-incident workflows should show retirement fan-out and the difference between revoking an agent, its shared reader key and the admission capability that could replace it.

## Accepted choices and ruled-out concerns

The following are important limitations, but they are not new undisclosed defects:

- **Ordinary covered reaping** leaves a shared Delegation reader seed live until its documented retirement. F02/F03 concern different events/capabilities.
- **Witnesses are not consensus.** A lone consistent peer, own devices and bounded eight-hop propagation cannot defeat an isolated split with no reachable revocation holder. The numerical bounds and write stops have explicit exceptions.
- **Recovery windows protect admission, not old RecoveryWrap confidentiality.** A stolen code with operator help can read its wraps immediately; old backups already sealed to that code remain exposed. Fresh identity revocation/re-enrollment after compromise is a real burden, now disclosed. The sole-writer restored-binding deadlock is also acknowledged.
- **Same-user code and the sandbox operator** remain inside one device trust boundary. Harness evidence is forgeable there; the owner's tainted-run exceptions and stronger device/presence routes are deliberate. This review does not pretend PID ancestry isolates a shell-capable adversary.
- **Browser limitations** include served-code changes, authorized view access, eviction and re-enrollment. The separate key origin and Web Lock still materially reduce persistent exposure.
- **Current config readers share authority material**, including the certified ShareSigner seed. The seven-day old-certificate limit and long-lived ShareKey dependency are disclosed; CC-05 asks a narrower live-reader/colluding-service question.
- **Single-site durability** loses unmirrored data, including an iOS-only user's unmirrored message bodies. The corrected EC/second-host conditions, customer mirrors and restore drills should be tested, not recast as off-site operator backup.
- **Versionless and drop-history semantics** deliberately permit collected content. Restricted kind-5 reuse, retained statements, promotion to kind 1, same-push adoption/rename rules and separate mark/verify/observe phases close the simple “purge deletes a newly adopted current object” trace under the store contract. No new direct trace was established beyond K01.
- **Hold behavior** retaining dropped history while presenting a completed drop is expressly owner decision 184. The review does not substitute a different legal/product policy.
- **Endpoint TLS, shared addresses, SNI-only mail and inbound-first launch** are owner choices. Shared reputation, unsupported senders and no reliable iOS-only receiver remain meaningful operational costs; changing to operator TLS termination or a warm address pool is not the requested correction.
- **Outbound proof readiness** remains a genuine M9 gate. The revised relation and preamble bind server state and handshake; no circuit/prover audit or deliverability proof was performed here. STARTTLS state reset, effective CAA and TLS-ALPN routing conclusions follow primary protocol rules ([RFC 3207 §4.2](https://www.rfc-editor.org/rfc/rfc3207.html#section-4.2), [RFC 8659 §3](https://www.rfc-editor.org/rfc/rfc8659.html#section-3), [RFC 8737 §3](https://www.rfc-editor.org/rfc/rfc8737.html#section-3)).
- **Reception evidence** is the authorized customer receiver's assertion; it does not prove a compromised receiver honest. “Validated” and final-hop REQUIRETLS should retain their stated basis, rather than imply an intermediate MTA never saw plaintext ([RFC 8689 §8.3](https://www.rfc-editor.org/rfc/rfc8689.html#section-8.3)).
- **Remote search's served record** is deliberately local to the serving owner, replacing a query-time evs receipt. It is not a missing accidental receipt path. Live relays still observe timing and fixed frame counts; F18 concerns the stronger retained-accounting claim.
- **M10's computed gate** and later production confirmation follow owner decision 174. No additional staging hardware or external audit is silently made a new requirement here.

## Implementation, freeze and launch priorities

**Before M2 specification/reservation freeze:** settle the ReaderWrap identity and delivery-authority fields (F04/F05), all promised key-retirement events and threat cutoffs (F02/F03/F06), stable refusal outcomes (F10), the real storage ordering contract (K01), and directory destructive capabilities (F01). Review the index's diff/tombstone/erasure format needs now so format-2 reservations do not encode an impossible transition. Write the governor conservation equation and bounded P0 policy before relying on its sizing.

**Before M2 byte freeze:** run the new pre-arrival retry schedule, >30-second remote-drive/coordinator-death schedule, late-wrap/replayed-ReaderKey fixtures, exact 64-bit sequence vectors and the two governor tests. Keep the existing TLC/Porcupine/interop requirements and the already-correct unknown-outcome, head/idx horizon, marker, receipt and recovery tests. A fake that cancels every operation instantly or starts every retry before its refusal fence cannot validate the real contracts.

**Before M6/M8 feature exits:** enforce directory erasure authority, complete denial notice/decision recovery, provide the phone-only lost-device revoke path, fence token projections and define the directory's actual pass/fail budgets. Custom domains need per-interface readiness evidence; inbound mail needs message-wide authentication limits; restore needs a safe live-worktree commit policy.

**Before M10 byte freeze:** require fresh-cache full→diff recovery; tombstones surviving merge/slot reuse; delayed fresh-path publication after erasure; stock-LFS force-to-ancestor after prune; multi-chunk/held-copy erasure accounting; large mutable-corpus masks; last-shard/no-hit cold queries; and accounting-rounding boundary sweeps. Compare search with the independent oracle after actually purging old versionless bytes. Warm caches and uncollected history can conceal the defects.

**Before general launch or scale expansion:** demonstrate admitted mixed HDD throughput under the real 50% policy, stable multi-day path-copy backlog, per-cohort capacity headroom, recovery/reconcile/host-return drills, and the restricted production confirmation of computed format-2 cost. Show the user-facing failure and repair states in these drills. Every actual implementation fix should include the deterministic root-cause regression required by the user's AGENTS instructions.

The needed changes are mostly precise protocol transitions, wire fields and bounded algorithms. The remaining genuine choices—especially unlimited immediate P0 work versus a hard aggregate budget, or a broader cryptographic cutoff than shared admission capabilities provide—should be made explicitly and reflected consistently in invariants, tests, UI and the response ledger.
