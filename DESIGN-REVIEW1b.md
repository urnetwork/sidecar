# DESIGN-REVIEW1b — independent Astra review of the final draft

Review date: **2026-11-04**. Reviewed source: [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md), the 9,754-line final-draft snapshot with SHA-256 **1f33a2fa817d4c2f1d1066d843398423bf7695a2fb6901341cdc6619cdc168a8**. All DESIGN.md line numbers below refer to that snapshot. A link points to the start of the accompanying exact line range.

## Assessment

The revision materially improves the trust model, recovery ordering, operating constraints and release plan. The architecture is viable enough to implement in vertical slices, but its security-critical formats are **not ready to freeze**. The largest remaining problems occur where one subsystem's authority or commit point is assumed to cover another subsystem: projection deltas versus generations, wrapped rotations versus MLS epochs, revocation gates versus ref CAS, object cleanup versus uncertain outcomes, approval checks versus external effects, and TLS proof bytes versus SMTP server state.

This review identifies **16 high-priority defects or incomplete security contracts**, one additional high-priority conditional TLS boundary, and material secondary issues. Severity is about the affected milestone and promise, not evidence of a deployed exploit. Several findings are contradictions between normative parts of a proposed design: an implementation could choose the safe interpretation, but independent implementers cannot derive that choice from the specified formats and algorithms.

The immediate priority is a small collection of explicit state machines and deterministic schedules, before M2 freezes authority, key and storage formats. Repairing those contracts within the chosen architecture is preferable to adding more service boundaries or replacing the owner's decisions. The mail proof needs its own corrected relation before M9; the custom-domain and strict-mail claims need correct DNS authority chains before the corresponding Team features launch.

## Method and limits

Three independent Astra MAX specialty reviews covered storage/protocol/architecture/operations, trust/identity/ACL/runtime, and DNS/edges/mail/bridge. Their completed reports were then consolidated and checked against the designated final snapshot. The earlier [DESIGN-REVIEW1.md](/Users/brien/urnetwork/sidecar/DESIGN-REVIEW1.md) was used only to assess fixes and unresolved items. No REVIEW2, Sol review or other review variant informed this report. The source changed during the review; conclusions and citations were revalidated against the final fingerprint above, including the last owner-decision citation delta.

This is a design review with targeted source and primary-reference checks, not an implementation audit, cryptographic proof, benchmark, dependency audit or executed regression suite. The acceptance scenarios below are **proposed deterministic tests**, not reported test results. No design/source fixes, commits or Git identity changes were made. Applicable user instructions require deterministic regression coverage for every eventual bug fix; these scenarios identify the root causes that coverage should exercise.

**P1** means resolve before freezing or shipping the affected security/data contract. **P2** means a concrete reliability, interoperability, interface or disclosure defect to resolve before its feature launches. A **conditional** finding names the missing premise explicitly; it is not presented as an established exploit. Confidence describes the finding against the written design, not the likelihood an eventual implementation will make the same mistake. Findings are grouped by dependency rather than a fictitious numerical risk score.

## Architecture, boundaries and strengths

The six-plane split in §3.5, lines 1360–1367, is sound: control and bulk ciphertext use HTTPS, peer streams use Required transport, pushes carry hints, and public edges splice to customer devices. Service ownership in §3.8, lines 1779–1796, is explicit. The sidecar/server package split, generated protocol leaf, injected ServiceHost and separate prover module give maintainers plausible dependency boundaries without moving private keys onto the platform. The mobile and browser constraints are treated as architectural inputs. [Planes and ownership](/Users/brien/urnetwork/sidecar/DESIGN.md:1360), [package boundaries, §4.4–4.6](/Users/brien/urnetwork/sidecar/DESIGN.md:1925).

The weakest architectural seam is **shared durable state**. api, gkm, evs and taskworker each have a locally reasonable operation, but the document repeatedly relies on a cross-object order that no single conditional write enforces. An append-only signed state reference, a generation transition, a ref commit and a maintenance tombstone must each have an identified authority, linearization point, retry identity and recovery procedure. Object-store If-Match is useful; it is not a transaction across repo records, generations, head objects and indexes.

The repository/build plan is substantially more coherent than the earlier draft. It acknowledges that Go replaces are not inherited, explicitly includes sn, pins the source graph, builds releases from main, and freezes applied migration indices. Dark rollout and migration-before-code remain appropriate. Preserve the import and release-leg checks at §4.10, line 2022, and the coordinated merge/migration rules at §23.9, lines 8415–8419. This review found no supported reason to replace the chosen public-repository or milestone-merge policies. [Build checks](/Users/brien/urnetwork/sidecar/DESIGN.md:2022), [release source graph](/Users/brien/urnetwork/sidecar/DESIGN.md:8350), [merges and migrations](/Users/brien/urnetwork/sidecar/DESIGN.md:8415).

Specific strengths worth preserving:

- Owner consent is now distinct from administrative admission. Admin-added devices are parked for owner-bound content until consent, and the config remains readable without granting the member's mailbox or vault (§8.5, lines 3391–3402).
- Signed authority inputs, pinned identities, explicit AdminSet thresholds and client-side roster verification make a malicious server's limits discussable. The new config membership committer exception removes a real operational dependency on admin availability (§10.9, lines 4290–4302).
- Wrapped agents reduce MLS churn and make the no-leaf agent topology explicit. The remaining generation problem is a missing integration protocol, not evidence that wrapped readers are inherently unsound.
- The immutable push chain, stable commit identifiers, multipart manifests and head CAS are a good basis for recoverable storage once uncertainty and cleanup are specified correctly.
- Small groups now publish GroupInfo on every commit, and recovery self-joins before revoking lost leaves. That corrects the previous external-commit ordering dead end (§10.6, line 4156; §10.8, lines 4267–4269).
- TLS 1.2 proof checking now keeps the master secret and server application record keys private. The earlier forged-outcome concern from disclosing the server record key is resolved (§14.5, lines 5678–5680).
- The metadata inventory, retention exclusions for operator backups, privacy canaries, real-browser milestone tests, workload tests and source-graph checks are unusually concrete. They should be used as executable contracts, with fault schedules added where this report identifies gaps.
- The owner explicitly accepts one-site storage, shared edge addresses, iOS foreground receiving, served-page code trust, no-policy LAN behavior and unaudited cryptography disclosures. Those are constraints of this review, not discoveries to relitigate.

## P1 findings: authority, keys and encrypted storage

### F01 — Effective authorization needs a delta-prefix commitment and a causal revocation identity

**P1; high confidence.** Evidence: §6.4 HeadCheck, lines 2531–2533 and 2571–2580; §7.9, lines 3069–3073 and 3106–3120; §8.9, lines 3529–3533 and 3560–3564; §10.5, lines 4102–4106; §11.8, lines 4532–4538 and 4679. [Projection and delta formats](/Users/brien/urnetwork/sidecar/DESIGN.md:3069).

Two different failures arise from representing effective authorization as a base version/hash plus a delta count.

First, an active server gives reader A valid scoped statement X as delta 1 and reader B valid statement Y as delta 1, under the same signed base. Their config head, base hash, delta sequence and MLS epoch can all match while their effective ACLs differ. HeadCheck does not commit to the delta prefix. This survives **actual communication between the readers**; it is separate from the now-disclosed limitation of permanently partitioned witness groups. Statements can be individually authentic while the server substitutes or orders different authentic statements. If a signer is intended to sign the assigned sequence, that still requires a defined predecessor commitment and fork check.

Second, suppose a rotation is committed against base version v. A later reader removal arrives as a delta on that same base. The gate asks for a rotation at or above v, and the prior rotation already qualifies even though it included the removed reader. Comparing integers cannot establish that a particular rotation incorporated a later statement. Increasing generations alone also does not establish which reader set was used.

**Correction.** Give effective authorization a canonical commitment to the base and ordered delta prefix, with explicit signed sequence/predecessor coverage and folding/rebase proofs. Carry that effective-state commitment through HeadCheck, generation transitions, roster validation and the gate. A removal must identify the state that excludes its target; the qualifying rotation must prove descent from or incorporation of that state. Do not silently substitute a server-assigned timestamp for this relation.

**Deterministic acceptance.** Give two peers the same base/hash/count but different valid delta contents, then connect them directly: they must detect disagreement. Repeat with reordered noncommuting statements and a fold/rebase. Separately commit a rotation at v, apply two removals as later deltas without advancing the base, and prove that neither old rotation nor a rotation covering only the first removal reopens the second gate. Test the access log and owner-consent deltas as well as membership removal.

### F02 — Standalone wrapped-reader rotations are not ordered or authenticated with MLS transitions

**P1; high confidence.** Evidence: §10.5, lines 4097–4117; §10.6, lines 4134–4159; §10.8, lines 4245–4257; §10.9, lines 4288–4302; §10.14 routes, lines 4387–4393. [Key hierarchy](/Users/brien/urnetwork/sidecar/DESIGN.md:4097).

The new design permits any wrapped writer to rotate RK when an agent is removed, without an MLS commit. Yet generation authentication is described through ur_group and signed GroupInfo, while gen/g is described as materialized from its epoch. ReaderWrap signs group, generation, recipient and ciphertext, but not the generation's parent commitment, cause or effective authorization state.

Consider an agent writer A producing generation g+1 with key RA while leaf B commits MLS epoch e+1 with generation g+1 and key RB. The two first-writer-wins operations use different keys: gen/g+1 and epoch/e+1. Both can succeed. One set of wraps and the MLS context then disagree on the commitment at the same generation. Even without concurrency, after A's standalone rotation the old MLS context still names g. A returning leaf's ordinary Add or Update is specified to keep its generation; the draft does not say how that transition first adopts g+1 or authenticates the standalone transition. A general instruction to check the key commitment cannot identify the authoritative commitment when the protocols disagree.

There is also a smaller authorization inconsistency: the config admission/revocation signer may rotate even when not a config writer, but the GroupContextExtensions row still permits a writer leaf for generation fields. That exception must survive every verifier and route, not only the high-level committer table.

**Correction.** Specify a first-class, identity-signed generation transition containing parent commitment, generation, cause, effective authorization commitment, new commitment and drop-key binding. Define one serialization point shared by standalone rotations and MLS transitions, with winner adoption, loser retry and completion of missing wraps. Bind MLS epochs to the verified current generation without allowing a returning leaf to regress it. This retains wrapped writers, customer keys, file-cluster storage and the non-admin config committer decision.

**Deterministic acceptance.** Remove an agent while all leaves are offline; let another wrapped writer rotate and write. Reconnect a leaf and perform Add and Update: all readers must converge on one key and no old generation may become current. Race that rotation with a leaf's rotation, kill each participant between generation/epoch/wrap writes, and restart on another service instance. Exercise a consented non-config-writer admission signer through every config rotation check.

### F03 — Ephemeral deposit-only policy conflicts with ordinary member and consent inheritance

**P1 specification conflict; high confidence.** Evidence: §5.6, lines 2281–2284 and 2309–2311; §7.7, line 2971; §8.4–8.6, lines 3321–3344, 3386–3402 and 3409–3439; §18.8, lines 7063–7064. [Effective policy](/Users/brien/urnetwork/sidecar/DESIGN.md:3321).

The prose says an ephemeral sidecar receives only evs deposit unless a grant names it. The executable-style policy model says an untagged subject inherits its owner's user/group/role atoms, grants form a union, and autogroup:member receives general-repo write/admin. The consent predicate has no ephemeral exclusion: a member's consented device signing an ephemeral SidecarAdmit satisfies it, which gives owner-bound vault/mailbox write access through kind defaults.

Admit untagged ephemeral E under member M using M's consented desktop. With no explicit data grant to E, the member defaults can yield general-repo read/write/admin; the consent default can yield M's owner-bound read/write. A quick burner's narrow mailbox EvsShare does not subtract broader union grants. The textual deposit-only rule could be implemented as an overriding ceiling, but hardDeny and grant compilation do not contain that ceiling. This is a conflict to resolve before implementation, not a claim that every possible implementation must leak keys.

**Correction.** Make ephemeral data access an explicit policy operation: exclude ephemeral identities from implicit member/owner data grants or impose a kind-specific ceiling lifted only by a named grant. Retain config readability and the owner's accepted no-policy connectivity behavior; they do not require implicit vault access. Specify whether quick-burner consent authorizes only its EvsShare.

**Deterministic acceptance.** In personal, no-document Pro and Team configurations, admit an untagged ephemeral device and verify deposit succeeds but general-repo reads/writes/admin and owner-bound writes fail without explicit grants. Add one mailbox EvsShare and verify it opens precisely that access. Repeat first-device invitation and quick-burner enrollment paths.

### F04 — The chosen 72-hour recovery veto lacks its signed protocol

**P1 specification blocker; high confidence.** Evidence: owner decision 127; §5.6, lines 2294–2296; §7.9 record/authority formats, lines 3042–3087 and 3125; §7.18, line 3274; §10.8, lines 4267–4269; §18.5, lines 6976–6983; §22, lines 8145–8151. [Authority formats](/Users/brien/urnetwork/sidecar/DESIGN.md:3042).

The revised decision permits recovery-key participation in k-of-n authority and adds a 72-hour administrator veto. The SDK even exposes denial of a recovery window. The signed record grammar does not define a recovery proposal, authenticated start time, veto statement, cancellation or precedence rule. Nor is there a concrete pre-admission route to retrieve and monitor that state using only the recovery capability.

A leaked recovery key can produce a cryptographically valid recovery signature, especially where k=1. Honest devices still need a verifiable answer to whether its proposal has been visible for 72 hours and whether a valid veto won. An untrusted server saying the proposal is old is insufficient. A backdated locally signed field does not prove publication. Conversely, a locally observed valid veto must not be discarded because another response claims the admission completed. The existing admission and recovery signatures do not define those facts.

**Correction.** Freeze signed recovery-intent and veto schemas bound to proposal ID, full requested admission, member RecoveryBind and effective authority state. Define publication/time evidence, the supported time trust assumption, the exact eligibility threshold, pending bootstrap reads, restart behavior, AdminSet/RecoveryRebind changes and the final admission-versus-veto ordering. Preserve the chosen 72-hour window and threshold policy. State the unavoidable withholding limitation instead of implying a server can prove universal absence of vetoes.

**Deterministic acceptance.** With fake time and k=1/k=2 fixtures, exercise backdating, delayed publication, replay, restart, authority change, RecoveryRebind and simultaneous veto/finalization. A device that has verified a valid winning veto must reject that admission. A code-only recovery client must fetch exactly the bootstrap objects it needs without acquiring normal repo access before admission.

### F05 — v0 witnesses do not compare ordinary evs ref heads

**P1 invariant/phase conflict; high confidence.** Evidence: I-16, line 1198; F2, lines 1479–1482; §6.4, lines 2571–2580; §10.4, line 4090; §11.9, line 4681; §11.18–11.21, lines 4930 and 4963. [Invariant](/Users/brien/urnetwork/sidecar/DESIGN.md:1198), [v0/v1 storage verification](/Users/brien/urnetwork/sidecar/DESIGN.md:4681).

The v0 HeadCheck compares config/projection and MLS state. Ordinary ref heads may advance or fork without changing any of them. The storage section explicitly defers EvsHeadCheck to v1 even though I-16 and the flow claim witnessed heads from v0.

An active server gives writers A and B incompatible signed ref histories under the same MLS epoch and effective policy. Both pin their own history and exchange valid v0 HeadChecks; all exchanged fields agree. Local monotonicity catches rollback on one device, but not these incompatible increasing histories. This is also separate from Q-EVS-6's old per-file freshness choice: even fully replaying devices need to compare the refs they replayed.

**Correction.** Include a bounded exchange of repo/ref commitments in v0, with pagination and common-prefix checks, or explicitly narrow I-16, product claims and release tests until that feature exists. Do not count an agreeing MLS/config witness as a witness for an unexchanged ref.

**Deterministic acceptance.** Fork one ref under one unchanged epoch, let two peers fully replay their branches and then communicate. Require a fork alarm or an explicit unwitnessed status; never a storage-witness success. Cover multiple refs, more refs than one message holds and independently advanced non-conflicting histories.

### F06 — Ambiguous head-CAS outcomes enter cleanup that can delete committed dependencies

**P1; very high confidence.** Evidence: §11.8 push steps and cleanup, lines 4637–4668, especially 4647–4648; §22 crash tests, line 8230. [Commit algorithm](/Users/brien/urnetwork/sidecar/DESIGN.md:4637).

The algorithm writes push/slot/index dependencies before the head CAS, then removes step-5 writes on 409 or any failure. A storage request can commit while its response is lost. Apply the head PUT, drop the response, and let evs treat the timeout as failure: cleanup deletes objects that the committed head references. A retried conditional PUT can likewise fail because the original request succeeded. Later advancement by another writer makes a simple current-head equality check insufficient.

The planned crash test that detects an already-committed push is useful but does not establish the required cleanup rule. A 64-version visibility window is not a durable outcome ledger when the retry occurs after that window. Nor does idempotent creation protect dependencies subsequently deleted by cleanup.

**Correction.** Distinguish committed, conclusively uncommitted and unknown outcomes. Give each push one stable operation identity with a durable way to find its outcome after head advancement and restart. Unknown outcomes cannot trigger destructive cleanup. Delete only versions proven to belong to an aborted operation, using conditions that cannot erase a later replacement. Define reconciliation for multipart parts, slots, index staging and log-page rollover.

**Deterministic acceptance.** Apply the head CAS but return timeout; restart evs, advance the ref on another writer, retry on another instance and run GC. Exactly one commit must exist and its complete dependency closure must decrypt. Repeat beyond 64 later commits, at log boundaries and while outcome reads lack quorum. Uncertainty must retain recoverable state, not delete it.

### F07 — The revocation gate is not fenced against a ref commit or its retry

**P1; high confidence.** Evidence: §7.10, lines 3137–3148; §8.9, lines 3560–3564; §11.8, lines 4599–4602, 4637–4648 and 4679; rejected lock explanation at line 4857. [Write checks and CAS](/Users/brien/urnetwork/sidecar/DESIGN.md:4637).

Even after F01 gives the gate a correct causal identity, checking it and later CASing a different head object leaves a race. Writer A checks an open gate at generation g and pauses. A removal closes the gate. Writer B rotates and commits a disjoint change at g+1. A loses its original head CAS, sees no path conflict and follows the specified retry to commit at the new head, still using its old-generation manifest. The retry does not revalidate all authorization, generation and lifecycle predicates. The simpler schedule has A commit after gate closure without any head conflict.

Client EnsureWritable is important but cannot protect an already prepared in-flight write across a later removal. Re-reading the gate immediately before CAS narrows the window but does not close it; the gate and head are different objects. The design itself correctly notes that no store condition spans two objects when rejecting a per-ref lock.

**Correction.** Define a common commit fence that the ref CAS necessarily observes, or a protocol that first advances every affected ref through a revocation barrier and cannot reopen until old writers are fenced. Include effective authorization, current generation, path epoch and lifecycle state in retry eligibility. Specify the linearization point for a successful removal and the treatment of writes already in flight.

**Deterministic acceptance.** Pause A after its last validation; close the gate; rotate and commit B; resume A through both the no-conflict and disjoint-CAS-retry schedules. No post-barrier head may introduce content under an excluded generation. Repeat with multipart seal, repo delete, grant expiry and a process restart between validation and CAS.

### F08 — Path-key migration has no complete snapshot, stale-writer fence or overlapping-rotation rule

**P1; high confidence.** Evidence: §11.6, lines 4489–4507; map format, lines 4554–4560; head copy marker, lines 4603–4608; push/retry/seal, lines 4639–4660. [Path epoch migration](/Users/brien/urnetwork/sidecar/DESIGN.md:4489).

A mapper enumerates the old path tree at head v. Another writer creates path p at v+1. The mapper's PATH_EPOCH push sees disjoint changes and retries at v+2, but its map does not contain p. Once copying completes and the old epoch is retired, the committed path is not reachable through the new token tree. The map does not commit to an exact source snapshot or specify tail catch-up.

A writer that prepared old-epoch tokens before cutover can also retry afterward; the listed multipart seal checks omit a path-epoch fence. Finally, the migration can take many hours, while another removal may require a further path-key rotation. The head has a bounded old/new copy representation, but no specified state machine for three overlapping epochs or a forced completion barrier. Serializing removals themselves would violate their intended prompt effect.

**Correction.** Bind each map to an exact source ref commitment and define either a cutover barrier or authenticated tail maps for intervening writes. Reject stale path epochs at the actual commit point and on every retry/seal. Serialize migration completion while recording subsequent removals safely, or define an explicit multi-epoch chain with bounded reads and retirement. State what happens when the only mapper goes offline; do not claim an exposure cutoff the system cannot enforce.

**Deterministic acceptance.** Insert, delete and rename a path after enumeration but before PATH_EPOCH CAS; force a disjoint retry. Every committed path must remain readable after copy completion. Resume an old-epoch multipart upload after cutover and require safe rejection/rebuild. Trigger two removals during a deliberately paused long copy, crash each copy boundary and verify both revocation and eventual reachability.

### F09 — Path-level disjoint retries and pre-receive publication do not preserve Git ref semantics

**P1; high confidence.** Evidence: §11.7, line 4569; §11.8, line 4647; §11.9–11.11, lines 4681 and 4719–4738; §11.14, line 4850; F2, lines 1468–1482. [Git bridge](/Users/brien/urnetwork/sidecar/DESIGN.md:4719).

From commit O, client A creates commit A changing file a and client B creates sibling B changing file b. A pushes first. The evs algorithm automatically retries B because paths are disjoint. Publishing B as the ref tip loses A's ancestry; applying both trees while keeping B's original object ID does not represent Git object B; manufacturing a merge requires a new commit and client-authorized content/signing. Path compatibility is not Git fast-forward compatibility.

Two other boundaries need explicit treatment. EvsPush updates one ref, while Git can request an atomic multi-ref update. Separately, a pre-receive hook runs before Git updates local refs. If it commits evs successfully and a later ref lock/update fails, or the process dies, local Git and remote evs disagree. Moving the hook later alone trades one inconsistency window for another. These are standard Git semantics, not demands for undocumented extra features. [Git pre-receive contract](https://git-scm.com/docs/githooks#pre-receive), [atomic push contract](https://git-scm.com/docs/git-push#Documentation/git-push.txt---atomic).

**Correction.** Give shared Git refs an expected-old-tip CAS and client-side merge/rebase retry that creates the correct new Git commit. Restrict server path-level merging to operations whose semantics permit it. Either provide a multi-ref transaction committed by one manifest/root CAS or refuse Git's atomic capability before any mutation. Define a durable local/remote publication journal and reconciliation after uncertain hook or ref-update outcomes; never acknowledge success with two unresolved authoritative tips.

**Deterministic acceptance.** Use two stock Git clients making disjoint sibling commits; verify the second non-fast-forward push is rejected or explicitly merged into a new valid commit with both parents/history. Request a two-ref atomic push and force the second ref to conflict: neither may change. Kill the bridge after remote commit and before local update, and force a local ref-lock failure after pre-receive. Restart and verify exact object IDs, reachability, status and retry result.

### F10 — Restore can win after irreversible slot deletion has begun

**P1; high confidence.** Evidence: §11.8 lifecycle states, lines 4599–4602; §11.12, lines 4756–4767; Appendix G evs-1, line 9631. [Delete, restore and shred](/Users/brien/urnetwork/sidecar/DESIGN.md:4756).

The repo record has keying, active and deleted states. A deleted repo can be restored within seven days, while `--now` starts deleting slots immediately. A shred worker can delete the first slots, a concurrent restore can CAS the deleted record back to active, and the worker can continue deleting the remainder. Even if it checks the state between deletes, the first irreversible key loss already happened. The same boundary exists at the grace-period deadline.

The preservation-hold decision is now explicit: it delays ciphertext disposal, not key shredding. That resolves an earlier ambiguity but does not make restore safe. A restored record is not evidence that its key closure still exists.

**Correction.** Add an irreversible SHREDDING transition acquired by CAS before deleting any slot. Restore is legal only from the soft-deleted state; exactly one transition wins. Make the shred job resumable and preserve enough signed deletion state for mirror/reseed reconciliation. Specify when restore stops being offered, including `--now`, without changing the owner's hold policy.

**Deterministic acceptance.** Pause immediately before and after the SHREDDING CAS and before each destructive phase. Race restore against `--now` and grace-period expiry; the winner must be deterministic. A successful restore must retain every key, while a winning shred must never return an active but partially unreadable repo. Repeat after worker restarts and under a preservation hold.

### F11 — Full mirrored recovery and cluster-only slot custody have an unresolved key-closure contract

**P1 recovery/format contract gap; high confidence in the conflict.** Evidence: §10.8, lines 4265–4272; §11.6, lines 4518–4521; §11.12, lines 4754–4767; §11.13, line 4837; §16.8, lines 6463–6464; §19.6, line 7304; §19.10, lines 7390–7411. [Mirror promise](/Users/brien/urnetwork/sidecar/DESIGN.md:4837), [reseed runbook](/Users/brien/urnetwork/sidecar/DESIGN.md:7390).

Record-class bodies use random per-entry keys in deletable slots. RK and the sealed body do not recreate that random key. The design promises a full sealed owner-device mirror and reseed after total site loss, but also describes slots as cluster-only and forbids retained key copies outside the deletion model. The reseed runbook emphasizes pushes and segments without specifying a verified slot/key closure.

Mirror an entry without ever opening it, lose the site and restore from the mirror. If slots were excluded, its body is unrecoverable despite the full-mirror promise. If full mirror implicitly includes them, the cluster-only custody statement is inaccurate and erasure must account for those client copies. A second schedule starts with an old mirror containing a slot, shreds that slot on the cluster, then reseeds from the stale mirror: without durable erasure state, the deleted body becomes decryptable again for legitimate readers who had not retained it.

**Correction.** Define exactly what a full customer mirror contains, distinguishing customer-held encrypted key material from prohibited operator backups. Include verifiable slot coverage and signed erasure tombstones, reconcile those before admitting reseeded keys, and define partial/offline mirror status. Do not promise deletion of plaintext or keys an adversarial former reader already copied; that accepted limitation is different from resurrecting server-accessible slots during routine recovery.

**Deterministic acceptance.** Mirror an entirely unread record-class repo, destroy both clusters and reconstruct every retained body with only the documented recovery material. Then erase an entry after taking a mirror, simulate site loss and attempt reseed from that stale mirror: the erased slot must stay absent. Cover partial slot copies, missing tombstones and crashes during reseed, including the config-first bootstrap.

## P1 findings: approvals and local effects

### F12 — Single-use approvals lack durable atomic consumption before their effects

**P1; high confidence.** Evidence: §5, lines 2208–2209 and 2260; §16.4, line 6261; §16.6, lines 6335–6348; §16.8, lines 6427–6443 and 6461. [Approval execution order](/Users/brien/urnetwork/sidecar/DESIGN.md:6335).

A daemon checks an approval with uses=1, executes an outward operation, and records the use afterward. Records may be batched; restart makes in-flight calls retryable. Crash after a durable mail outbox enqueue but before the use record. The same still-valid decision can authorize another logical enqueue after restart. Concurrent calls can also both observe one available use. This is approval-budget duplication, independent of the unavoidable ambiguity of a remote SMTP server's final acknowledgement.

A stable action_id helps only if all components use it as an idempotency key and the use reservation is durable. A signed count and an eventual audit record do not serialize consumption. Grant activation has the same issue if replay can create multiple grant instances.

**Correction.** Introduce a durable approval-use state machine keyed by decision/request identity and stable action_id. Reserve before any effect; execute each component idempotently or reconcile its outcome. An uncertain effect must not free a use for a new operation. Define cancellation, expiry, multiple uses and the shared authority when server gates participate, retaining only the metadata they are allowed to see. Burning an uncertain use is an acceptable explicit conservative policy.

**Deterministic acceptance.** Release two callers from a barrier against uses=1 and require one logical effect. Kill after reservation, after outbox/component commit and before the completion record; reconnect through a fresh MCP session and retry. Require either the original result or an explicit uncertain/consumed state, never a second effect. Exercise uses=2, cancellation and expiry with fake time.

### F13 — Whole-worktree snapshots cannot safely attribute changes to one run

**P1 data-loss risk; high confidence.** Evidence: R-MCP-4, line 6243; §16.7, lines 6370–6382. [Capture and restore](/Users/brien/urnetwork/sidecar/DESIGN.md:6370).

Runs A and B share a worktree with file x initially x0. B writes xB. An unrelated hook from A triggers A's whole-tree rescan, which records xB as part of A's changes. B does not touch x again. A's restore sees no change since its last scan, so the conflict check passes and restoring A rewrites x to x0, deleting B's work. The same trace applies to a human editor and to files B created that A later deletes as its own.

Requiring a committed restore point fixes missing-data recovery, but not authorship. Hook session binding identifies the event, not which process changed every file since the previous scan. A dry-run previews the error; it does not establish the advertised run-confined invariant.

**Correction.** Use isolated worktrees, a shared durable change ledger with attributable writes, or conservative ambiguity detection that refuses destructive run restore where ownership cannot be established. Record exact before/after hashes and a worktree revision, then validate them at application time. State that a snapshot restores a whole workspace only when the user explicitly chooses that broader operation.

**Deterministic acceptance.** Interleave two runs and a manual editor, triggering A's hooks around B's edits and creations. Restoring A must leave B/manual changes intact or report specific ambiguity conflicts. Repeat across daemon restart, scan gaps, redacted/hash-only content and a change occurring between preview and apply.

## P1 findings: TLS and mail authority

### F14 — The SMTP proof authenticates client bytes but not the server state that interprets them

**P1; high confidence.** Evidence: §14.5, lines 5653 and 5673–5704; E1–E3 and Z1–Z6, lines 5677–5685. [Proof relation and transcript](/Users/brien/urnetwork/sidecar/DESIGN.md:5673).

The updated relation covers all client application records, authenticates the handshake and prevents a premature DATA terminator. It still does not prove the authenticated server's post-TLS EHLO capabilities, accepted envelope or 354 transition. The diagram says the sidecar rechecks CHUNKING and waits for 354; a malicious sidecar is the adversary, so its normal control flow is not evidence.

For BDAT, use an MX that does not advertise CHUNKING after TLS. A malicious sender proves the required outer MAIL/RCPT/BDAT text, followed by a syntactically valid header block. The MX rejects the unrecognized BDAT command and interprets later supposed body lines as SMTP commands. Those bytes can contain RSET and a second MAIL/RCPT/DATA transaction with different attribution. For DATA, cause the outer envelope/DATA to be rejected, then use the alleged body to start the actual transaction. A single terminator at the end can satisfy Z6 while ending the real, different DATA transaction. The circuit's parse and the MX's state machine diverge.

STARTTLS resets capability knowledge; the pre-TLS keyword list cannot establish the later state. BDAT requires negotiated CHUNKING, and server replies affect valid command interpretation. [RFC 3207 §4.2](https://www.rfc-editor.org/rfc/rfc3207.html#section-4.2), [RFC 3030 §2](https://www.rfc-editor.org/rfc/rfc3030.html#section-2).

**Correction.** Bind observed server application records into the public transcript and prove their authenticated decryption and ordered state transitions: post-TLS capabilities, envelope responses, recipient acceptance policy and DATA's 354. Keep application record keys private. Define permitted pipelining and error handling against a precise SMTP state machine. The explicit M9 soundness gate is appropriate, but its adversarial corpus must test this missing relation before proof formats are frozen.

**Deterministic acceptance.** Use a scripted honest MX with no CHUNKING, pre-TLS-only CHUNKING, MAIL/RCPT rejection, absent 354 and mixed recipient outcomes. Put a second valid SMTP transaction in the alleged body. Compare accepted MX envelopes/messages with proved ones; every mismatch must fail before effect. Repeat both TLS versions, both modes, record splits and replayed server replies. Positive cases must remain valid.

### F15 — Custom-domain CNAMEs permit the operator to replace the effective CAA account policy

**P1; high confidence.** Evidence: §2.8 EX1, line 577; §12.8, lines 5160–5164; §13.8, lines 5427–5428. [Custom-domain setup](/Users/brien/urnetwork/sidecar/DESIGN.md:5160).

The customer pins its ACME account in CAA, but points app.customer.example by CNAME to an operator-controlled app.net.ur.network. CAA lookup follows aliases. The active operator can publish a CAA RRset at that exact target authorizing its own account; the CA then uses that nonempty result instead of walking to customer.example's pinned parent policy. The delegated ACME challenge path is also operator-controlled. A customer-held account key is therefore insufficient to establish the stated exclusion of URnetwork issuance.

The counterexample does **not** require claiming that the URnetwork parent's CAA automatically overrides the customer parent. With an empty exact target response, parent traversal can reach the customer policy. The exploit deliberately creates the target RRset. DNSSEC authenticates the operator's authorized zone edit; CT detects issuance afterward. [CAA relevant-RRset algorithm, RFC 8659 §3](https://www.rfc-editor.org/rfc/rfc8659.html#section-3).

**Correction.** For the strong account-pin mode, keep effective CAA discovery under customer authority, for example customer-controlled A/AAAA records or authoritative flattening that returns addresses without an operator CNAME in the CAA lookup. Validate the complete alias chain at setup and renewal. If CNAME operation remains supported, disclose its operator-issuance exception instead of excluding it from EX1.

**Deterministic acceptance.** Resolve a customer parent pin with an empty alias target, then add an operator-account CAA at the exact target. A CA-policy fixture must demonstrate the override. The corrected strong-mode setup must refuse that topology or preserve the customer pin despite the operator's DNS changes; test wildcard and delegated challenge cases too.

### F16 — Strict direct MX still trusts operator-controlled mail discovery

**P1; high confidence.** Evidence: §12.8, lines 5158 and 5164; §15.4, line 5964; D-MAIL-12, line 6147; §2.8 EX2. [Direct-MX and strict-mode rules](/Users/brien/urnetwork/sidecar/DESIGN.md:5964).

Direct MX changes mx.net.ur.network's addresses to customer receivers while retaining its TLSA in the operator's zone. Strict mode accepts direct-MX sessions or splices under customer-signed custom-MX zones. In the direct case, an active operator replaces the relevant MX/address/TLSA records with its own endpoint and certificate. A DANE sender validates the operator's signed DNS and delivers outside the customer receiver; the receiver's strict-session check never runs.

For a customer recipient domain pointing to an operator MX hostname, controlling that hostname's TLSA is already enough. For an operator recipient domain pointing to a customer MX hostname, the operator can instead replace the recipient domain's MX. Both discovery links matter. DANE's authentication is derived from secure MX discovery and each chosen MX's TLSA, not from whether the original customer receiver had a public address. [RFC 7672 §2.2](https://www.rfc-editor.org/rfc/rfc7672.html#section-2.2).

**Correction.** Admit the strong strict-mode claim only when the recipient-domain MX selection and the selected MX's TLSA chain remain under customer authority, with no operator-controlled substitution route. Apply the same rule to direct and spliced delivery, aliases, scopes and alternate MXs. Retain ordinary operator-zone mail with its explicit EX2 limitation.

**Deterministic acceptance.** In a signed-DNS fixture, redirect the existing direct-MX configuration by changing only operator-controlled records. The corrected setup must either reject that configuration as strong mode or prevent the redirected endpoint from authenticating. Repeat with a customer recipient domain/operator MX host and the reverse arrangement; test every alternate MX.

### F17 — Empty ALPN selects raw forwarding without a defined private-audience boundary

**Conditional P1 boundary gap; high confidence in the omission, medium confidence in exploitability.** Evidence: §9 scheduler, line 3837; §13.7, lines 5403–5414. [TLS front dispatch](/Users/brien/urnetwork/sidecar/DESIGN.md:5403).

The TLS front alone enforces audience, but its dispatch table sends no ALPN to decrypted TCP forwarding. Publish an HTTP service with members, members-device or link audience; connect with valid SNI and no ALPN; send ordinary HTTP/1.1. If empty ALPN is treated as compatible with that listener, the connection can bypass the HTTP front and reach the backend without its cookie/device checks. If Find always rejects this combination, the attack is closed, but the registration/matching rules must say so. An optional ALPN filter is not an explicit security invariant.

**Correction.** Bind application mode and audience to the signed registration. For HTTP publishes, no ALPN must still use HTTP audience enforcement or be rejected. Raw protocols need an explicitly defined authentication mode or a deliberately public grant; ALPN omission cannot select a less restrictive path.

**Deterministic acceptance.** For every private audience, test no ALPN, unknown ALPN, HTTP/1.1 and h2, including offered-list/selected-value mismatches. An unauthenticated request must deliver zero application bytes to the backend. Keep positive tests for explicitly public raw services and TLS-ALPN-01.

## P2 findings: reliability, interfaces and disclosure

### S01 — Recovery-code replacement leaves the compromised path key in use

**P2; high confidence, narrow claim.** Evidence: §5 recovery wording, line 2376; §10.5, lines 4101–4117; §10.8, line 4269; §11.6, lines 4481 and 4485–4507; checkpoint rule, line 4571. [Rotation causes](/Users/brien/urnetwork/sidecar/DESIGN.md:4101).

A holder of a leaked old recovery code can save the then-current RK and derive its path keys. RecoveryRebind requests a new generation, but the path-key and checkpoint reset is triggered by removal, not request. A cooperating server can therefore keep exposing new path tokens under a key the old code holder knows, permitting future filename guesses. The new old-code admission test covers identity recovery, not this path-key effect. This does not assert that rotating a code can erase historical plaintext or that every new content key is compromised.

**Correction and acceptance.** Treat a compromised recovery-key replacement as removal of a key holder for the path/checkpoint protections it exposed, or explicitly qualify what replacement revokes. Save old code, wraps and derived keys, rebind, then create guessed-name files and changed inline content after cutover. Old material must not derive new path tokens or open post-cutover content covered by the stated revocation claim. Keep the accepted lifetime ref-name leakage separate.

### S02 — Four index versions can all be pending and evict the visible version

**P2; high confidence.** Evidence: §11.7–11.8, lines 4575–4587, 4615, 4643–4645 and 4668; GC, line 4823. [Index version limits](/Users/brien/urnetwork/sidecar/DESIGN.md:4575).

Five writers can stage versions of one path before any wins the head CAS. Keeping only the newest four can remove the only version referenced by the current visible head. The reader then either fails or searches old signed pushes outside the promised bounded head-read path. Later cleanup cannot repair the missing visible version automatically, and the retained push history does not satisfy the 2–3-object read bound.

**Correction and acceptance.** Separate bounded pending versions from protected committed visibility, or stage versions under push identity and materialize the visible index after commit with a recoverable rule. Pause five writers after index staging, read the unchanged head, then allow one winner and abort the rest. The visible file must remain readable within the documented lookup bound throughout, including restart and cleanup.

### S03 — Log-only GC cannot find uploads that never reached the log

**P2; high confidence.** Evidence: §11.8, lines 4633–4636 and 4668; §11.13, lines 4823–4834; §22, lines 8206 and 8220–8222. [GC and accounting](/Users/brien/urnetwork/sidecar/DESIGN.md:4823).

Upload a segment, then crash before writing any push object or committed log entry that names it. A collector that enumerates only the log cannot discover the orphan, despite the 24-hour orphan cleanup promise. A nightly live-log reconciliation also cannot account for all physical bytes. A blanket age lifecycle on final segment keys would eventually delete live segments as well.

**Correction and acceptance.** Add an upload-intent/staging inventory or a bounded inventory sweep, with a late-seal fence and physical-versus-logical accounting. Kill after segment upload, between multipart parts and before seal; advance fake time beyond the orphan deadline. Every uncommitted object must become reclaimable, while a concurrent successful or uncertain commit remains intact and quota reconciliation converges.

### S04 — The maximum directory cardinality cannot fit the maximum entry size

**P2; very high confidence.** Evidence: §11.7, lines 4582–4584; §11.8, lines 4615 and 4650–4661. [Directory encoding](/Users/brien/urnetwork/sidecar/DESIGN.md:4582).

The format permits 4,096 child names, padded in name fields, while a complete entry is limited to 512 KiB. Even 4,096 valid 255-byte ASCII names padded to 256 bytes require 1 MiB before IDs, tags and framing. Multipart pushes split manifests, not one oversized directory entry. The count limit and byte limit therefore cannot both be advertised as supported.

**Correction and acceptance.** Page directory contents with authenticated continuation/coverage, or define a byte-based capacity and reject oversized trees before any mutation with an explicit Git compatibility limit. Construct the boundary directory, add a child through a concurrent update and verify either a complete readable paged result or a clean pre-mutation refusal.

### S05 — Same-epoch GKM work hints are discarded by the generic version rule

**P2; high confidence.** Evidence: §6.8, lines 2713 and 2728–2729; §10.6, lines 4156–4161; hint kinds at line 4383. [Hint versions](/Users/brien/urnetwork/sidecar/DESIGN.md:2713).

A writer is caught up to epoch e and becomes idle. A reader change closes its gate, or a joiner requests missing GroupInfo. GKM repeatedly hints pending/wrap-pending on gkm:group at version e, but clients ignore versions at or below their own. No MLS epoch changes until a writer acts, so the trigger can be ignored indefinitely until another write or the hourly resync. A standalone wrapped rotation makes epoch-only work versioning still less adequate.

**Correction and acceptance.** Give pending work a durable independent sequence or define authenticated equal-epoch work notifications that force state refresh, including coalesced hints. Keep an idle online writer with no later application writes, request each work type and verify completion within the intended gate target. Repeat after Redis loss and with a standalone generation change that leaves the epoch unchanged.

### S06 — Deposit permission does not consistently authorize fetching the public drop key

**P2 interface conflict; high confidence.** Evidence: §7.8 token scopes, line 2999; §10.6 authorization, line 4132; §10.14 drop-key route, lines 4387–4393; deposit protocol in §11.6. [GKM scope rule](/Users/brien/urnetwork/sidecar/DESIGN.md:4132).

The generic token exchange knows deposit scopes, but GKM's stated accepted scopes are r/rw/admin while depositors need its current public drop-key statement. A genuine deposit-only receiver must either fail or be over-granted. The public key is not a reason to grant repo decryption or general GKM access.

**Correction and acceptance.** Give the exact current public drop-key endpoint explicit deposit authorization, with repo/lifecycle checks and no private wraps or roster access. A deposit-only principal must fetch a new key after rotation and successfully deposit, while being denied every read, ReaderWrap and ordinary MLS route. This finding concerns inconsistent interfaces, not a demonstrated implementation denial.

### S07 — Mandatory author-visible read receipts lack an authorized write path

**P2; high confidence.** Evidence: §8.5–8.8, lines 3384–3404 and 3500–3518; §16.8, lines 6390–6392 and 6468. [Read-receipt requirement](/Users/brien/urnetwork/sidecar/DESIGN.md:6468).

Bob is granted read-only access to Alice's vault, or is the opted-in audit reader. The design requires an author-visible read entry before opening content, but Bob has no general write or deposit right to Alice's owner-bound repo. Alice can be offline. Granting rw merely to write the receipt violates the intended read-only sharing boundary.

**Correction and acceptance.** Define a narrowly authorized receipt append/deposit capability or a recipient-owned stream discoverable and readable by the author, binding receipt author, object and purpose. Test the first shared/auditor read while Alice is offline: the required receipt must be durable under the chosen failure policy, but arbitrary writes/deposits by Bob must still fail.

### S08 — An SDK transport-token rejection is mapped to durable identity revocation

**P2; high confidence.** Evidence: §5 state rules, lines 2316 and 2345; §18.7, lines 7031–7035. [Host logout mapping](/Users/brien/urnetwork/sidecar/DESIGN.md:7031).

The core says token expiry or failed refresh makes the sidecar Unenrolled while retaining its identity. The SDK maps confirmed 401/logout to Revoked. With the newly enforced seven-day strict expiry, this is an ordinary lifecycle, not an edge case. An old API session's delayed callback can also arrive after successful re-pairing to a new client generation.

**Correction and acceptance.** Use a typed, generation-bound transport rejection reason. Expiry/refresh failure requires re-enrollment; signed SidecarRevoke or a separately authenticated permanent identity decision drives Revoked. Expire a child token, re-pair under the same sidecar_id, then deliver the old callback: identity and new enrollment must survive. A real signed revoke must still terminate access.

### S09 — The keystore API cannot express its required unavailable state

**P2; high confidence.** Evidence: §5.9, lines 2361–2377; §18.5, lines 6933–6953 and 6990. [Keystore interface](/Users/brien/urnetwork/sidecar/DESIGN.md:6933).

GetSecret returns a string, with empty meaning absent, but its comment requires SidecarKeyStoreUnavailable while locked. There is no status/error channel. Treating locked as absent risks initializing replacement secrets or taking the wrong recovery path; panicking across the binding is explicitly fatal to the app. Put/Delete's boolean likewise loses useful distinction between refusal, lock and failure.

**Correction and acceptance.** Freeze a binding-compatible result with present/absent/locked/error status and value, or a documented status API with race-safe semantics. Exercise actual Go/mobile/C/JS adapters with locked, absent, corrupted and transient-failure stores. A lock/unlock cycle must preserve the identity and never create a second root or erase stored state.

### S10 — Ineligible devices can disable the only available approval channel

**P2; high confidence.** Evidence: §16.6, lines 6313–6333; §18.5, lines 6992–6993; §18.8, lines 7061–7064; §18.11, line 7125. [Approval eligibility](/Users/brien/urnetwork/sidecar/DESIGN.md:6313).

A desktop without a presence key may use harness evidence while it is the member's only consented device. Adding the read-only page Worker makes that predicate false, yet the Worker is explicitly forbidden to sign approvals. Desktop remote-mode decisions themselves require a presence signer. A second device can therefore remove a working channel without supplying an eligible replacement; two presence-less remote desktop hosts expose a related advertised-channel gap.

**Correction and acceptance.** Define approval-capable devices separately from consented readers, including local/remote mode and presence availability. A read-only Worker must not disable fallback merely by existing. Specify the supported identity-key approval route for another device without opening the same-user self-approval bypass. Test desktop alone, desktop plus Worker, two desktops without presence and a supported presence device; every allowed channel must actually be callable and every prohibited self-approval must fail.

### S11 — Two-host read survival needs a fully protected-object precondition

**P2 conditional durability claim; high confidence in the quorum counterexample.** Evidence: §11.13, line 4837; §19.6, lines 7279–7302; §22.8, lines 8223–8224. [Durability table](/Users/brien/urnetwork/sidecar/DESIGN.md:7296).

For an eight-drive EC4 set distributed across four hosts, a write quorum can succeed on five drives. If three drives fail that write and healing has not completed, losing two hosts can leave fewer than four matching fragments even though two hosts remain online. The table's unconditional second-host RPO 0/read-continuity statement assumes all required fragments of every acknowledged object were present before the later failure. MinIO's write path uses data-drive quorum plus one when data and parity counts are equal; acknowledgement is not proof that every drive completed. [MinIO erasure write implementation](https://raw.githubusercontent.com/minio/minio/master/cmd/erasure-object.go).

**Correction and acceptance.** Qualify the guarantee by object protection/healing state, expose degraded-write debt, and define admission or acknowledgement requirements if the unconditional promise is required. Keep the chosen four-host hardware. Inject a quorum-successful partial write, prevent healing, then lose the two relevant hosts. Exercise metadata and segments; verify the documented read/RPO result and alarms. Do not count a healthy-write-then-two-host-loss test as coverage of this schedule.

### S12 — The outer 443 split never sends custom-domain SNI to tlsedge

**P2; very high confidence.** Evidence: §12.8, lines 5162–5164; §13.4, lines 5299–5316. [Ingress map](/Users/brien/urnetwork/sidecar/DESIGN.md:5299).

The nginx map sends only *.ur.network to tlsedge; other SNI goes to the platform HTTP terminator. A browser connecting to app.customer.example sends that original hostname as SNI even if DNS resolved a CNAME to an operator hostname. Thus the custom-host map inside tlsedge is unreachable from the ordinary shared 443 path. It also prevents the intended custom-host TLS-ALPN-01 flow.

**Correction and acceptance.** Route known platform names explicitly and send other supported SNI to tlsedge for authorized-name checking, or publish the custom-host map to the outer splitter with an activation barrier. Unknown names must still fail safely. An end-to-end ClientHello fixture must reach the customer listener for a registered custom host and preserve the intended handling of platform names, ordinary user names, unknown names, absent SNI and ACME ALPN.

### S13 — Header-only report parsing cannot produce the promised aggregate counts

**P2; very high confidence.** Evidence: §14.8, lines 5747–5753, 5769 and 5774; report inventory, lines 1056–1060 and 9696. [Report intake and halt inputs](/Users/brien/urnetwork/sidecar/DESIGN.md:5747).

The halt rule compares RUA counts with edge connections, and TLS-RPT is promised, but the only allowed parser reads ARF's feedback part and selected enclosed headers. DMARC aggregate records live in XML, commonly a gzip attachment; TLS-RPT records live in JSON or its compressed form. Verifying the enclosing DKIM hash and sealing raw bytes does not extract those counts. [RFC 9990 §3.5.2](https://www.rfc-editor.org/rfc/rfc9990.html#section-3.5.2), [RFC 8460 §5.3](https://www.rfc-editor.org/rfc/rfc8460.html#section-5.3).

**Correction and acceptance.** Specify bounded parsing of aggregate report payloads as distinct from enclosed user-message bodies, with an owner-consistent clarification of the header-only rule; otherwise remove the unsupported counters and halt trigger. Define compressed/decompressed limits, XML external-entity refusal, JSON limits, reporter authentication and report-level deduplication. Valid signed compressed XML/JSON fixtures must produce the exact counts once; duplicates, invalid signatures, untrusted reporters and decompression bombs must not alter them.

### S14 — Deferred mail authentication loses reception-time DNS evidence

**P2; high confidence.** Evidence: §15.4–15.5, lines 5955–5956 and 5985; §15.7, lines 6053–6055; forwarding policy, line 6109. [Receive then ingest](/Users/brien/urnetwork/sidecar/DESIGN.md:5955).

A receiver accepts mail at time T and deposits it while the owner is offline. Before the reader ingests it a week later, the sender removes its DKIM selector or changes SPF/DMARC records. The reader queries current DNS and can no longer establish the reception-time result. The reverse schedule can also change a formerly failing result. Those differences affect labels, receipts and automatic forwarding rules. DKIM's use of selectors permits key lifecycle changes; retaining raw message bytes alone does not retain the DNS evidence used to authenticate them. [RFC 6376 §3.1](https://datatracker.ietf.org/doc/html/rfc6376#section-3.1).

**Correction and acceptance.** Have the approved receiving device capture a bounded authentication result/evidence set at reception, bound to message hash, time and receiver identity, and seal it with the deposit. State the trust in that receiver and distinguish reception-time results from later revalidation. Change DNS between T and T+7 days for valid/invalid messages: deterministic ingestion must preserve the stated original result or explicitly report insufficient historical evidence, not silently rewrite it. Tampered evidence and message/hash substitution must fail.

### S15 — REQUIRETLS is an observed requirement, not exact proof of the message's prior privacy

**P2 claim correction; high confidence.** Evidence: §2.18, line 1293; §15.5, line 6010; §15.16, line 6213; owner decision 135. [Label rule](/Users/brien/urnetwork/sidecar/DESIGN.md:6010).

The owner has chosen the operator-list inference and its disclosed residual. That choice is not reopened here. The remaining exactness claim for REQUIRETLS is stronger than the evidence. An active operator can read an opportunistic first hop, then initiate a genuine TLS session to the customer receiver and add MAIL REQUIRETLS. The received bytes can retain a valid aligned DKIM signature, which does not authenticate the previous SMTP MAIL parameters or transport path. The final receiver sees REQUIRETLS even though confidentiality was already lost. REQUIRETLS expressly excludes malicious intermediate MTAs from its threat model. [RFC 8689 §8.3](https://www.rfc-editor.org/rfc/rfc8689.html#section-8.3).

**Correction and acceptance.** Keep the owner-approved label policy but record its basis as an observed incoming requirement or operator inference, not proof that URnetwork never read the message. Stronger origin/path assertions need evidence beyond these inputs. A two-hop fixture that reads a canary, preserves DKIM and adds REQUIRETLS must not produce an API/UI assertion of exact end-to-end path confidentiality.

### S16 — The global no-content-plaintext promise omits platform report intake

**P2 disclosure inconsistency; very high confidence.** Evidence: §2.8, lines 550 and 573; §14.8, lines 5751 and 5774; §15.4, lines 5958–5959 and 5981; Appendix G smtp-5/mx-4. [Platform report processing](/Users/brien/urnetwork/sidecar/DESIGN.md:5774).

The global statement says URnetwork never has content plaintext in any mode, yet platform mail terminates TLS and receives raw reports that can contain original message bodies. It hashes those bytes for DKIM and HPKE-seals them in server memory. Avoiding MIME decoding does not make already available message bytes cryptographically unavailable. The detailed inventory acknowledges this intake, so this is a disagreement between the global claim and its own exception, not a newly alleged hidden database.

**Correction and acceptance.** State the bounded report/role-mail exception next to the global promise, align I-2 and the inventory, and retain the no-plaintext-persistence rule. Deliver an attributable ARF report with a body canary: it may exist at the documented intake boundary and decrypt from the customer's sealed copy, but must not appear in logs or plaintext durable storage. Unattributable reports must follow the documented drop rule.

### S17 — Wake dispatch has both a Redis Cluster transaction error and a lost-trigger schedule

**P2; very high confidence for cross-slot failure, high confidence for lost trigger.** Evidence: §6.8, lines 2678–2686 and 2713–2716; §15.6, line 6019; §18.7, lines 7039–7047; §19 Redis topology, line 7331; Appendix G, line 9607. [Wake trigger](/Users/brien/urnetwork/sidecar/DESIGN.md:7039).

The hint operation is atomic on keys tagged {scp_C}, but the same MULTI is said to read live and XADD to {wakeq_shard}. Those tags are not generally the same hash slot. Redis Cluster cannot execute that multi-key transaction across slots. In addition, branching on a queued MULTI read needs an explicit conditional mechanism; a transaction block by itself is not a script. [Redis Cluster multi-key and hash-tag rules](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/).

Fixing that operation leaves an independent loss window. At t=0 the publisher refreshes a 90-second live marker and disconnects. One mail hint at t=10 sees live and queues no wake; no later hint arrives. TTL expiry has no specified action to reconsider it. The router's 30-second hold expires even when the push vendor and receiver would have worked. Best-effort vendor delivery is an accepted limit; silently discarding the only local wake trigger is a different preventable failure.

**Correction and acceptance.** Keep client hint state and a pending-wake/outbox obligation in one slot, then drain idempotently to shard queues, or explicitly define recoverable separate writes. Keep a delayed fallback until acknowledgement or bounded deadline instead of deleting the obligation because live is temporarily present. Test real multi-master Redis Cluster with different slots, kill between state and queue operations, and test one hint immediately after a refreshed-live disconnect. With a deterministic vendor sink, a bounded submission must occur within the stated policy; queue failure must never discard durable hint state.

### S18 — HTTPS-only ephemeral hosts still have no authoritative liveness lease

**P2 protocol gap; high confidence in omission, medium confidence about implementation consequences.** Evidence: §7.7, line 2971; §6.8, lines 2712–2716; §18.8, lines 7058–7064. [HTTP-only Worker lifecycle](/Users/brien/urnetwork/sidecar/DESIGN.md:7058).

The quick burner must be reaped 30 minutes after page disconnect, but initially uses HTTPS and 25-second polls without a connect resident. The only live marker specified is maintained by resident publishers. Killing a page without a final unload request produces no defined event from which to measure its 30 minutes. Treating absent resident as disconnect can reap an active page; waiting for a resident disconnect can leave an abandoned admission indefinitely. Seven-day transport expiry is not the promised ephemeral lifetime.

**Correction and acceptance.** Define an authenticated lease beginning at enrollment, refreshed by a designated HTTP heartbeat/poll and bound to client generation. Specify suspended tabs, resumed expired clients and multiple tabs. With a fake clock and no resident, keep a page active past 30 minutes, then kill it without unload: require one reap at the stated deadline and correct generation/gate effects. Old-generation heartbeats must not keep a replacement or revoked client alive.

## Conditional concerns and remaining format contracts

These items are not counted as additional proven bypasses. They are concrete decisions or acceptance obligations that should be settled at the affected freeze.

### C01 — Separate redeemable enrollment credentials from client-only Delegation secrets

**High confidence in the wire ambiguity; conditional leak.** §7.8 sends auth_key to /network/enroll (lines 2984–2986) and says pre-approved keys add Delegation signing and reader private keys (line 2996); §10.5, line 4117 gives that reader key future config/tag access until DelegationRevoke. [Enrollment format](/Users/brien/urnetwork/sidecar/DESIGN.md:2984). A literal whole-bundle POST leaks private keys; a client-side split is safe and plausibly intended. Freeze the bundle and extraction rule, including provisioning/QR paths. Instrument every server-bound request/log with private-key canaries: enrollment must succeed with neither private component reaching any server.

### C02 — Freeze the exact approver signature on GrantActivate

**Conditional authorization concern.** §8.8, lines 3484–3490 describes Signed GrantActivate by approvers via ApprovalDecisions. §16.6, lines 6346–6347 sends the decision/action to the gate, while §16.8, lines 6420–6443 leaves subject/rule bindings inside the opaque request commitment. [Activation](/Users/brien/urnetwork/sidecar/DESIGN.md:3484). An additional approver signature over the full public GrantActivate closes the issue; a gate checking only action payload hash cannot establish the private request's subject. Specify that full transcript or a signed public authorization header. Two eligible subjects with the same sponsor/action must not be able to reuse each other's decision, even before either has spent it.

### C03 — Presence approval needs a concrete platform evidence profile

**Medium-confidence integration obligation, not a claim of platform impossibility.** §6.9, lines 2743–2745; §7.9, lines 3058–3061; §16.6, lines 6315–6319; §18.5, lines 6939–6941 require attested FIDO or Secure Enclave presence. [Presence interface](/Users/brien/urnetwork/sidecar/DESIGN.md:6939). Pin supported provider/OS profiles, roots, challenge binding, key association, signature encoding and evidence of per-operation user presence. An ordinary P-256 signature and self-declared channel are not sufficient by themselves. Positive adapter fixtures and negative vectors must cover wrong key, replayed challenge, software substitution, profile confusion and app-integrity evidence lacking the required presence property. No unsupported assertion about a current Apple API's availability is made here.

### C04 — Small-group GroupInfo publication still needs crash completion

**High-confidence recovery dependency; conditional on the upload failure.** §10.6 stores epoch and GroupInfo separately (lines 4138–4140) and requires current GroupInfo on every commit at at most 16 leaves (line 4156); §10.8 expects code-only self-join (lines 4267–4269). [GroupInfo publication](/Users/brien/urnetwork/sidecar/DESIGN.md:4138). Commit the epoch, crash before current GroupInfo/recovery material publication, then lose all leaf state. The ordinary successful-publication recovery test does not cover this boundary. Define a recoverable publication bundle/completion obligation and when the new state is declared recoverable. Kill after each object boundary and require the documented code-only recovery result. Above 16 leaves, an online leaf dependency is visible and should remain explicit rather than being advertised as universal no-device recovery.

### C05 — Preserve bounded safety maintenance at quota limits

**Specification clarification; existing delete/read exceptions are acknowledged.** §11.13, lines 4832–4834 and §20.7, line 7674 refuse writes while allowing reads, deletes and export. [Quota behavior](/Users/brien/urnetwork/sidecar/DESIGN.md:7670). CONSUME, deletion records, mandatory rotation, PATH_EPOCH/BASE, config repair and reseed may be implemented as pushes and temporarily allocate bytes. Define their bounded exception/charging rules so a full repo can become safe and shrink without admitting arbitrary payload growth. Test each at exact storage and spent-balance boundaries, with concurrent ordinary uploads still refused. This is not a generic claim that deletion is already prohibited; the draft explicitly permits it.

### C06 — Distinguish retained proof records from retained inline payload

**Retention/format clarification.** §11.8 stores inline records in immutable push/part objects (lines 4611–4614); §11.13 preserves statements while collecting content (lines 4823–4826); §16.8 separates deletable body keys (lines 6463–6464). [Immutable payload placement](/Users/brien/urnetwork/sidecar/DESIGN.md:4611). Define whether retention removes ciphertext bytes, shreds keys or retains only a commitment stub, and how immutable packs and Git history reflect it. Test mixed inline/segmented entries across retention, erasure, packing and export, checking both permitted proof verification and forbidden decryption. A Git checkout/history copy already retained by a reader cannot be recalled; do not confuse that accepted fact with server retention obligations.

### C07 — Subscription lease creation and its invalidation counter are not one write

**P2-sized liveness clarification, not content-integrity failure.** §11.10, lines 4692–4702 writes a lease and separately advances repo/<repo>'s counter. [Lease invalidation](/Users/brien/urnetwork/sidecar/DESIGN.md:4692). Crash between them leaves another evs process's cached LIST stale for up to ten minutes. The subscriber's one-second head reread catches earlier commits, not later commits still matched against that stale list. Define repair/outbox ordering or narrow the claim that no notification is missed. Deterministically crash at that boundary, commit after the one-second reread, and verify the documented resync/SLO rather than assuming lossless hints.

### C08 — The edge ticket exception must not waive source identity or private-resource scope

**Conditional boundary concern.** §9.6, lines 3821–3827 can be read as source identity matches and Hello passed, or the dialer is urnetwork-edge. [Socket admission](/Users/brien/urnetwork/sidecar/DESIGN.md:3821). If the second arm also waives source equality and later policy uses a ticket-asserted member identity, a malicious issuer could combine edge labeling with private-member authority. Other namespace checks may already prevent this; the finding is not an established exploit. Make transport-source equality unconditional, waive only the appropriate Hello requirement, and restrict the edge path locally to authorized public TLS/SMTP ingress. Wrong-source edge tickets and member-asserting private-socket tickets must fail before application data; valid splices must work.

### C09 — Bridge-share aliases need capacity preflight

**Capacity contract, not a policy bypass.** §17.9, line 6732 maps a target prefix to an equal-length prefix in one overlay /16. [Share aliases](/Users/brien/urnetwork/sidecar/DESIGN.md:6732). A /8 cannot fit; a /16 conflicts with reserved/existing addresses. Specify maximum prefix size and contiguous free-space requirements, rejecting an unrepresentable share before activation. Deterministically reject oversized/full-block cases and allocate overlapping /24 requests without collisions, including retained aliases during drain. The chosen private-address block need not change.

### C10 — Persist security state across MCP and keyless-device restarts

**Security-state clarification retained from REVIEW1.** MCP sessions hold taint (line 6261), while taint must last the run (line 6353). Bridge startup uses an unverified has_document to choose private-destination refusal (lines 6696 and 7025), while installed state only rises (lines 7012–7018). [Taint](/Users/brien/urnetwork/sidecar/DESIGN.md:6351), [device state](/Users/brien/urnetwork/sidecar/DESIGN.md:7003). Specify durable monotonic run taint and persistence of the last verified bridge anchor/policy. After reading untrusted input, restart and deliver a benign hook: an outward call still needs fresh approval. Restart an already-enforcing device and omit has_document in an unsigned response: it must not downgrade verified policy. Preserve the explicitly accepted legacy/no-document behavior for genuinely new or legacy devices.

### C11 — Close the remaining small wire and lookup ambiguities at freeze

**Format obligations, not separately demonstrated exploits.** One-command admin tokens (§7.8, line 2998) need a canonical command/target/use identity enforced at execution. Shared-purpose Signed records (§6.9, line 2743) need a typed/versioned canonical body, not merely parser convention. Packed-object readers (§11.13, lines 4830–4831) must invalidate a cached negative locator lookup when an original disappears. [Signing](/Users/brien/urnetwork/sidecar/DESIGN.md:2743), [packing](/Users/brien/urnetwork/sidecar/DESIGN.md:4830). Test changed admin-command parameters/replay, cross-type reinterpretation of the same signed bytes, and a reader paused after negative pack lookup while packing publishes then deletes originals. These tests should confirm the intended safe implementation without treating ordinary package choices as bugs.

## Disposition of the earlier Astra review

This is a review of the revised design, not a replay of old line numbers. The mapping below uses the finding IDs in DESIGN-REVIEW1.md. A retained finding has been checked against the current text and may be narrower here.

| Earlier item | Disposition in the final draft |
|---|---|
| F01, authorization deltas and causal rekey | Still open: F01. The revision changes who may commit but does not commit the effective delta prefix or distinguish same-base removals. |
| F02, ordinary-ref witnesses | Still open: F05. EvsHeadCheck is explicitly v1 while the invariant remains broader. |
| F03, mutually stale witness bound | **Resolved as a disclosure objection.** §2.8 line 586 and §6.17 line 2876 explicitly state the unbounded split/own-group residual. Shorter summaries should carry the qualification. F01 is different because even communicating peers can falsely agree. |
| F04, all-devices-lost recovery | **Substantially improved.** Self-join now precedes lost-leaf revocation (4268), avoiding the invalid bulk-Remove external commit; groups up to 16 leaves proactively publish GroupInfo (4156). F04 here covers the new veto protocol/bootstrap, and C04 covers the publication crash boundary. No universal external-commit dead end is repeated. |
| F05, ephemeral ACL inheritance | Still open: F03, including the new consented-device path. |
| F06, compromised recovery-code rotation | Retained narrowly as S01: path/checkpoint retirement. Historical plaintext recall is not claimed. |
| F07, Git semantics | Still open: F09. |
| F08, ambiguous CAS cleanup | Still open: F06; existing crash-test intent needs the safe outcome/cleanup rule. |
| F09, revocation gate versus CAS | Still open: F07, distinct from F01's causal-state problem. |
| F10, path migration | Still open: F08, including overlapping migrations and multipart retry. |
| F11, restore/shred race | Still open: F10. The newly explicit preservation-hold choice does not serialize restore. |
| F12, empty ALPN | Retained as **conditional** F17; exploitability depends on unspecified listener compatibility. |
| F13, customer CAA | Still open: F15, using exact alias-target CAA rather than an incorrect assumption about target-parent inheritance. |
| F14, strict direct MX | Still open: F16, covering both recipient MX discovery and target TLSA authority. |
| F15, SMTP command/data interpretation | Still open and sharpened as F14. DATA support and whole-client-flow proofs do not establish authenticated server state. |
| F16, TLS 1.2 server-key disclosure | **Resolved** by E2/Z1, lines 5678–5680, D-SMTP-21 at 5853 and Appendix G at 9693. Preserve a negative test that the edge cannot read or forge encrypted MX application replies. |
| F17, auth-key private bundle | Retained as conditional C01; safe client-only splitting is possible but unspecified. |
| F18, mirrors versus slots | Still open as the recovery/erasure contract F11. |
| F19, run restore | **Partially fixed:** uncommitted restore points are refused at 6382. Cross-run attribution remains F13. |
| F20, single-use approvals | Still open: F12. |
| S01, four index versions | Still open: S02. |
| S02, per-ref counter on repo hint topic | **Resolved:** lines 2730–2732 and 4703–4709 now define a repo-wide push sequence and skipped-version catch-up. S05 concerns a different GKM topic. |
| S03, orphan GC | Still open: S03. |
| S04, lifetime ref-name key | **Resolved as a hidden-leak objection:** the future branch-name guessing limitation is disclosed at §11.6 line 4481. The lifetime-key choice is accepted. |
| S05, degraded erasure writes | Retained with explicit precondition as S11. |
| S06, drop-key scope | Still open as interface conflict S06. |
| S07, outer custom-SNI routing | Still open: S12. |
| S08, MTA-STS hosting/burner inheritance | **Resolved:** line 6008 specifies the public system publish, certificate readiness and burners relying on DANE. The review does not assume parent MTA-STS covers child burner domains. |
| S09, aggregate parsing | Still open: S13. |
| S10, deferred mail authentication | Still open: S14. |
| S11, report plaintext exception | Still open: S16. |
| S12, SDK auth loss | Still open: S08. |
| S13, keystore unavailable state | Still open: S09. |
| S14, approval availability | **Partially improved:** requiring consent prevents an unconsented admin-injected device from suppressing fallback. Legitimate read-only Workers/remote hosts still produce S10. |
| S15, read receipts | Still open: S07. |
| S16, HTTPS ephemeral liveness | Still open: S18. |
| S17, stale live marker | Still open within S17; the cross-slot queue operation is an additional independently supported issue. |
| S18, browser test phase | **Resolved:** §22.9 line 8244 and §22.17 line 8324 put page-Worker tests at M4, matching first public use. Extension tests may remain Later. |
| C01, inbound privacy labels | Owner decision 135 settles the operator-list policy. Its disclosed inference is accepted; the separate REQUIRETLS exactness claim remains S15. |
| C02–C04, format/presence/persistence clarifications | Relevant unresolved contracts are C03, C05 and C10–C11. They remain acceptance obligations rather than newly asserted implementation exploits. |

Additional resolved or accepted boundaries checked in this revision:

- Config membership execution no longer waits for a config-writing admin: owner decision 128, §7.9 and §10.9 distinguish execution from authority. F02 asks that this change be made consistent with the generation protocol and extension verifier.
- A Delegation's shared private reader key intentionally grants later generations until DelegationRevoke, including to a reaped holder (§2.8 line 560; §10.5 line 4117; tests at 8190–8191). Individual reaping does not promise to revoke that separately held credential. This is not counted as a new agent-removal bug.
- Expiry-only grants are explicitly client-primary because they need not change projection version (§11.8 line 4679). F01 concerns immediate signed deltas and does not conceal that accepted limitation.
- Owner-bound consent now reaches scoped TLS certificates, DNS key records and mail receivers (§12.8, line 5152; §13.8, lines 5423–5427; §15.5, line 5987). Ordinary admin admission alone is no longer reported as owner-vault access.
- The public-repository flip, normal remotes, per-exit merges and immutable applied migrations now agree (§23.9, lines 8417–8419). No private-history rewrite or extra publication approval is recommended.
- Off-loopback Git HTTP, IMAP and submission require TLS under owner decision 130 (I-17, line 1199; D-TRUST-8, line 1243). The previous potential interpretation that Basic/SMTP AUTH crosses the LAN in cleartext is no longer a finding.
- Preservation holds now explicitly permit key shredding while retaining unreadable ciphertext, subject to the chosen counsel condition (§10.8 line 4265; Appendix G line 9631). This review does not impose a different legal retention policy.

## Recommendations on the eleven open peer-review questions

These are engineering recommendations, not owner decisions and not evidence that an already-open question is itself a defect.

| Question and current source | Recommendation and acceptance condition |
|---|---|
| [Q-CTX-4, line 481](/Users/brien/urnetwork/sidecar/DESIGN.md:481), file sharing | Prefer the blocking online socket service (a), consistent with the stated CLI interaction. Bind link secret, resource, expiry and uses; reuse F12's durable consumption semantics where a finite use count is promised. Document loss of availability when the serving sidecar exits. |
| [Q-CORE-4, line 2445](/Users/brien/urnetwork/sidecar/DESIGN.md:2445), ClientKey possession | Support (b), proof on refresh/exchange in v0, with audience and client-generation binding and copied-token negative tests. This does not claim stolen bearer transport tokens become unusable everywhere; (c) remains a later transport decision. |
| [Q-KEYS-11, line 4364](/Users/brien/urnetwork/sidecar/DESIGN.md:4364), epoch retention | Prefer (a) only after code-only/long-offline recovery is demonstrated with current GroupInfo and the generation ladder, including C04's crashes. Retention must preserve verification material needed by the chosen recovery protocol; a calendar cutoff alone is insufficient. |
| [Q-EVS-6, line 4916](/Users/brien/urnetwork/sidecar/DESIGN.md:4916), old per-file freshness | Prefer (c) for clients advertised as verifying freshness: replay from the durable pin before trusting an older file result. If (a) is chosen for v0, label its trust in evs for out-of-window freshness explicitly. It does not resolve ordinary-ref witnessing F05. Do not claim a Merkle-tree cost/performance result without measurement. |
| [Q-BRIDGE-2, line 6825](/Users/brien/urnetwork/sidecar/DESIGN.md:6825), link implementation | Support (c): start with the production multi-client path, then use the own-client framing alternative only where measured memory demands it and fragmentation/reply-filter tests pass. Memory pressure is a reason to prove the alternative, not to inherit fixture-grade assumptions. |
| [Q-SDK-5, line 7145](/Users/brien/urnetwork/sidecar/DESIGN.md:7145), device-role package | Follow the proposed measured choice: root if the actual iOS extension size/init budget passes, otherwise the leaf package. Exercise release tags, generated descriptors and initialization, not only source imports. No package split is justified solely by aesthetics. |
| [Q-OPS-2, line 7487](/Users/brien/urnetwork/sidecar/DESIGN.md:7487), small-object packing | Use inlining/debouncing initially if the measured operation mix passes; reserve authenticated, versioned locator evolution before format freeze. Define generation-ladder packing and its recovery/erasure semantics before Y2 scale. Do not treat the stated IOPS estimates as a benchmark or let a compaction policy erase F11/C06 obligations. |
| [Q-OPS-5, line 7493](/Users/brien/urnetwork/sidecar/DESIGN.md:7493), DNS deployment | Prefer staged dns control-plane rollout, with schema/snapshot compatibility and mixed-version checks. Keep dnsedge's one-host-at-a-time rollout, signed snapshot validation and zone/DS canaries. |
| [Q-TEST-1, line 8284](/Users/brien/urnetwork/sidecar/DESIGN.md:8284), test helpers | Start with narrow sidecartest adapters (a), keeping the boundary contract and vectors synchronized. Promote stable helpers to connect/connecttest only when drift demonstrates the need; avoid broad production exports just for tests. |
| [Q-TEST-2, line 8286](/Users/brien/urnetwork/sidecar/DESIGN.md:8286), local storage/Redis | Choose (a) plus (b): real multi-master Redis Cluster and the pinned MinIO build, supplemented by key-slot lint. S17 is a direct example that a single-node mock cannot reject. Canary-only validation is too late for this correctness class. |
| [Q-TEST-6, line 8294](/Users/brien/urnetwork/sidecar/DESIGN.md:8294), protobuf oneof ban | Prefer the scoped hot-path restriction (b). Make the envelope/stream/push descriptor allowlist explicit and test released descriptors. A universal ban needs measured justification outside those paths. |

## Implementation, format-freeze and launch priorities

The plan's vertical slices and two-track staffing should remain. Tighten entry/exit evidence rather than inserting a new external audit gate the owner rejected. §23.8 already provides internal reviews before M2/M3/M9 freezes. [Existing gates](/Users/brien/urnetwork/sidecar/DESIGN.md:8407).

| Before | Required design closure | Deterministic evidence |
|---|---|---|
| M1 protocol and identity seams | Typed signing/transports, S08/S09 state distinction, S18 HTTP liveness contract, C10 persistent authority | Generation-bound expired-token callbacks; key-store lock/error adapters; HTTP-only enrollment/reap with fake time; restart with stored policy/taint |
| M2 authority and key formats | F01–F05, F02's config committer exception, C01–C04 | Same-base divergent deltas; causal removal; agents-only rotation and returning leaf; veto races; real ref-fork comparison; crash-complete recovery material |
| M2 storage format and concurrency | F06–F10, S02–S06, C05–C07 | Lost CAS response with later commits; gate/head barriers; concurrent path migration; stock-Git ref and multi-ref behavior; shred/restore winner; staged-version pressure; orphan discovery; oversized directories; quota maintenance |
| M3 production storage and capture pilot | F11–F13, S10/S11, C03/C10 | Unread-body mirror reseed plus stale erased-slot refusal; degraded-write then host-loss drill; approval crash/replay effect counts; multi-run/manual-edit restore; usable approval host matrix |
| M4/RS1 browser and reach | F03/F05 disclosure and policy consistency, C08–C10; preserve the newly corrected page-Worker gate | Real browser Worker admission/read/restart/origin/revocation tests; ephemeral grants; authenticated bridge startup; alias capacity; source-bound tickets |
| M5 ingress and public names | F17's dispatch contract and S12 map, privacy inventory consistency | No-ALPN private endpoint negative cases; custom-SNI through the actual splitter; platform-name regressions; CT/zone canaries |
| M6 Team custom domains/strict features | F15/F16, S07, authority/consent acceptance | Exact-target CAA substitution; full recipient-MX/TLSA authority attack; owner-bound read receipts without write privilege; no admin-only owner-vault access |
| M7/M8 inbound and burner release | S06, S13–S18, F16 where strict mode is exposed; sender census remains an explicit gate | Deposit-only rotation; delayed DNS ingestion; aggregate formats; report canary; adversarial REQUIRETLS labeling; real Redis wake fault schedules; HTTP quick-burner reap |
| M9 outbound proof freeze and release | F14; preserve corrected TLS 1.2 secrecy | Authenticated server-state relation; both-mode scripted-MX adversaries; actual accepted-envelope oracle; reply confidentiality; the existing soundness, performance and coverage gates |

The storage tests should check a small set of reusable invariants across every fault schedule:

1. A committed head always has a complete, verifiable, decryptable dependency closure, except an explicitly authorized erasure that is itself durable and visible.
2. Each uncertain operation retains enough identity and state to recover one outcome; cleanup never guesses that a timeout means failure.
3. Every head transition proves the relevant authorization/generation/path/lifecycle state at its commit point, including retries and multipart seals.
4. A generation has exactly one authenticated parent and commitment, whether produced by MLS or a wrapped writer.
5. A successful restore has all required keys; a winning shred cannot later become a normal active repo or be undone by stale reseed.
6. Pending state cannot evict the only committed readable state, and orphan discovery does not depend on the orphan having committed.
7. Approval use is reserved before effect and remains consumed or explicitly uncertain after restart; taint and requester bindings survive session changes.
8. A restore action changes only attributable run-owned state or reports ambiguity; preview is revalidated before mutation.

Use barriers, injected store results, fake clocks, restartable process fixtures and deterministic vendor/MX sinks. Real object-store/Redis conformance belongs alongside those state-machine tests; neither replaces the other. The existing throughput/soak suite remains useful after correctness is established. Tests need not send real external mail, use production credentials or depend on probabilistic sleeps.

Operationally, retain the owner's single-site and staffed-hours decisions, but publish protection state rather than just host counts, mirror completeness rather than a generic mirrored flag, and pending/uncertain maintenance work rather than optimistic completion. Preserve the emergency pager milestone already added for registrar/registry/law-enforcement events. Site loss must be drilled with unread entries and stale erasure state, not just a recently opened demonstration mailbox. Release migrations should be exercised with the previous binary still running and with rollback to that binary before the next format is enabled; the source-graph lock must include every actual consumer, including sn.

## Accepted choices and candidates deliberately not promoted

The following do not justify new findings merely because they have costs:

- The default 72-hour witness bound, configurable to 24–168 hours, cannot make an isolated stale cohort globally fresh. That residual is now disclosed. The review asks for truthful witness coverage and delta commitments, not an impossible partition guarantee.
- History is intentionally available to new readers through the RK ladder. A removed reader keeps material it already held. Ref-name guessing under the lifetime ref key and Delegation-key access until revocation are now stated limitations.
- A preservation hold may retain unreadable ciphertext after keys are shredded. Whether that satisfies a particular legal obligation is outside this technical review and the design already conditions it on counsel.
- Receive-only launch, no-SNI/plaintext refusal, no server mail queue without a key holder, shared-IP reputation risk and iOS foreground-only receiving are explicit owner choices. Their sender census and coverage disclosures remain real gates; the correction is not to terminate customer mail at the platform.
- Served browser code, same-user daemon clients and harness-native egress have explicit trust limits. This review does not pretend that tagging model content or recording a hook cryptographically isolates a compromised local endpoint.
- The corrected TLS 1.2 proof does not disclose the server record key. No claim is made that TLS 1.3 handshake-secret disclosure necessarily exposes later application secrets. F14 is the narrower application-state defect.
- A CNAME's target-parent CAA is not assumed to override the customer parent automatically. F15 uses the exact alias target's nonempty CAA RRset, which is sufficient.
- A healthy fully protected erasure-coded object can meet the stated two-host read case. S11 concerns acknowledged degraded writes before healing, not a claim that parity provides no resilience.
- Hints are intentionally lossy and resync provides eventual state recovery. S05/S17/C07 concern internal trigger/version contradictions and advertised latency, not a demand to turn push into a durable content mailbox.
- Ordinary API/format implementation remains planned work. Absence of code, measurements or production circuits is not itself a bug where the design already specifies an appropriate future gate. The findings identify the concrete contracts that those gates must prove.

## Review closure

Proceed with architectural foundations and nonfreezing implementation work, while treating the affected M2 formats as provisional until the authority/generation/commit/recovery state machines above are specified and their deterministic cases pass. The current revision closes several meaningful earlier issues; it does not yet establish the advertised end-to-end correctness across those boundaries. Mail and Team publication can continue on their planned track with explicit feature gates, but the SMTP relation, effective CAA chain and strict MX authority must be corrected before their associated claims ship.

At report completion, the working DESIGN.md matched the designated 9,754-line source fingerprint. Only this new review artifact was published; the design and earlier reviews were left unchanged.
