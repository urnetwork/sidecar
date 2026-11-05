# DESIGN-REVIEW2 — Independent Sol review

Review date: **2026-11-04**. Design draft: **2026-11-03**.

Source: [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md), **9,256 lines**, SHA-256 **12aba8d565bd630e0f8ef6ba2424a9a130d228f9b8f9ee9e99d0fdd1d1b7269c**. All design line references below refer to that exact source.

## Assessment and method

**Changes are required before G0 approval and the affected format freezes.** The architecture has a sound organizing principle: customer devices hold content keys and authority; infrastructure stores ciphertext, enforces secondary gates, and provides transport. The dependency direction, separation of privileged networking from the full sidecar, explicit metadata inventory, and staged release gates are useful foundations.

Several specified protocols do not yet establish their stated guarantees. The most consequential gaps concern authenticating native IP principals independently of the operator, authorization-state commitments and freshness, blind-deposit keys, destructive storage transitions, and concurrent publication. These are not objections to MLS, shared-IP ingress, object storage, or the owner's other choices. They are missing bindings or state transitions within those choices. Implementing the individual components faithfully would not close the gaps.

This report consolidates **three independent Sol 6.1 max specialty reviews**, an **additional independent Sol runtime/integration pass**, and subsequent Sol validation and consolidation. Their combined scope covers all 23 sections and relevant appendices. Consolidation used only the four completed Sol reports, DESIGN.md, PLAN.md, appropriate adjacent source, and primary technical evidence. **No Astra/REVIEW1 material was consulted.** Duplicates were merged; concerns dependent on an unspecified implementation or unresolved owner choice were separated from defects in the specified protocol.

This is a design review, not a full dependency audit, cryptographic audit, implementation certification, or performance result. The future sidecar services are not implemented. Source and protocol inspection, integrity checks, and an isolated synthetic Go-module parser fixture were performed. The acceptance scenarios below are **proposed deterministic regression tests**, not tests reported as passing. No source fix, commit, Git identity change, or deployment was made. The only repository addition from this synthesis is this review.

**Priority:** P1 means resolve before freezing the affected format or shipping the affected behavior because authorization, confidentiality, durable data, or a required integration can fail. P2 means a concrete functional, lifecycle, enforcement-contract, or disclosure correction. Conditional concerns have their assumptions stated separately. High confidence describes a consequence of the specified mechanism; it does not assert that an unimplemented product has already suffered the failure.

## Ranked findings

| ID | Priority | Finding |
|---|---|---|
| F01 | P1 | Native IP authorization accepts operator-minted subject/network claims without a customer-authenticated session binding |
| F02 | P1 | Unverified bootstrap state can reopen private provider access |
| F03 | P1 | Projection delta pins count operations without committing to their contents |
| F04 | P1 | Blind depositors cannot authenticate drop-key coverage of a known removal |
| F05 | P1 | Matching stale peers do not enforce the promised 24-hour withholding bound |
| F06 | P1 | Recovery and deposit-only key retrieval lack complete authorization bootstraps |
| F07 | P1 | Cleanup after an uncertain head CAS can delete committed data |
| F08 | P1 | Disjoint-path rebase conflicts with exact Git OIDs and non-fast-forward semantics |
| F09 | P1 | Overlapping path epochs lack a complete, fenced migration protocol |
| F10 | P1 | Orphan collection can delete a segment between validation and publication |
| F11 | P1 | Message erasure leaves decryptable deposit and index representations |
| F12 | P1 | Restore can race an unclaimed keys-first shred |
| F13 | P1 | Custom-domain CNAMEs defeat the claimed customer CAA account isolation |
| F14 | P1 | Workspace scans cannot attribute changes sufficiently for run-confined restore |
| F15 | P1 | The prescribed module declaration cannot publish the prescribed v2026 module |
| F16 | P2 | Epoch GC can remove the predecessor needed for the next commit |
| F17 | P2 | Repo-wide EVS hints use incompatible per-ref counters |
| F18 | P2 | Lifetime ref keys disclose future branch-name guesses after removal |
| F19 | P2 | Independent repo-gate checks do not provide the stated commit fence |
| F20 | P2 | The shared 443 SNI map bypasses custom-domain sidecars |
| F21 | P2 | DMARC message counts are compared with SMTP connection counts |
| F22 | P2 | Bridge pin expiry is shorter than live-flow and drain lifetimes |
| F23 | P2 | SDK token rejection is incorrectly classified as terminal identity revocation |
| F24 | P2 | Legacy MCP support conflicts with unconditional newer result types |

### F01 — Authenticate native IP principals independently of the contract signer

**Evidence:** [§17.6, L6295–6339](/Users/brien/urnetwork/sidecar/DESIGN.md:6295); §17.5 L6287; §17.9 L6404–6413; §6.4 L2466–2470; Appendix E C13/C18 L8989–8994. Contradicts I-3/I-4/I-5, L1194–1196. **Confidence: high.**

EgressFlow supplies SourceSubject, SourceNetwork, and Sealed. C13 authenticates those claims with the server's contract signer. It does not bind them to a customer-admitted identity or to a customer-signed delegation to the window client's actual transport key. Required encryption proves possession of a transport key; the design expressly recognizes coherent operator key substitution. Hello closes that gap for sidecar streams/RPC, but native IP does not exercise Hello, and foreign shares explicitly use IP without it.

**Failure trace:** a policy allows S to reach H's LAN database and denies G. The operator creates G with operator-held transport keys and a correctly signed contract claiming SourceSubject=S. G opens a genuinely sealed session. H's hook applies S's grant and dials the database; replies are encrypted to G. A forged SourceNetwork similarly selects another network's share aliases. Substituting a target key can intercept a legitimate sender.

Policy verification, C13's HMAC, Required mode, and a consistent platform key history all pass: the adversary controls their asserted transport identity. The existing contract wire format and signer confirm this boundary: [transfer.proto L562–568](/Users/brien/urnetwork/connect/protocol/transfer.proto:562), [connect_controller.go L1095–1118](/Users/brien/urnetwork/server/controller/connect_controller.go:1095), and [transfer_key_history.go L3–27](/Users/brien/urnetwork/connect/transfer_key_history.go:3).

**Change:** authenticate the native session against customer authority before any upstream flow. Verify scoped delegations binding identity, actual client id/key, network, target and expiry; authenticate target keys too. Share material must carry the foreign authority anchor. Cache an immutable verified principal outside the packet path. Add client_id to the binding at L2197–2203.

**Acceptance:** with server gates disabled, use real sealed sessions and correctly HMACed false subject/network claims. TCP, UDP and ICMP must create zero upstream sockets. Repeat target substitution. Valid scoped window delegations are the positive control; mismatched, expired and cross-target delegations fail.

### F02 — Unknown policy state must not select legacy allow-all

**Evidence:** [§17.8, L6369–6371](/Users/brien/urnetwork/sidecar/DESIGN.md:6369); §18.6 L6690–6693; §17.6 L6333–6344; D-SDK-13 L6801; I-10/I-12 L1201–1203. **Confidence: high.**

Before verified state arrives, the detailed bootstrap installs the block deny and refuses other private destinations only where an **unverified** projection says an ACL document exists. D-SDK-13 instead says the device role opens nothing before state. Unknown policy and a verified absence of policy are materially different states.

**Failure trace:** H has an ACL denying admitted S access to its LAN. H's provider/network process restarts while the full sidecar is disconnected or asleep. BridgeState and projection retrieval are delayed, or the server returns has_document=false. A valid sealed S flow takes the no-document branch and reaches the private destination. The overlay-block deny does not cover arbitrary LAN addresses.

This remains after F01: S can be a genuine member whose access is restricted. Monotonic versions protect installed state, not the initial window. Queuing a later RPC cannot bound suppression by an active server.

**Change:** install an explicit uninitialized deny posture before a provider accepts protected flows, including every client-generation rebuild. Persist the network anchor, policy-presence latch and highest verified state. Only verified state may establish no-document compatibility. Preserve the owner's intentional policy-less allow-all behavior once authenticated.

**Acceptance:** pin a policy denying S→LAN; rebuild the provider and pause all state delivery. Test absent and forged no-document projections with TCP/UDP/ICMP. No private socket opens. Then deliver verified allowed state and verify intended access. Repeat with iOS app suspension, desktop RPC disconnection, and restart followed by a lower/no-document response.

### F03 — Commit to the complete effective authorization state

**Evidence:** [§7.9, L2990–3002](/Users/brien/urnetwork/sidecar/DESIGN.md:2990), L3019–3021; HeadCheck §6.5 L2510–2518; §8.8 L3367–3390; BridgeState L6384–6388. Related consumers: GkmCommitHeader L3910–3913, EvsPush L4333 and gate L4452. **Confidence: high.**

Projection bases are hash-chained, but deltas carry base_version, seq and statement, and peers compare only base version/hash plus delta sequence. A count is not a commitment to the operations counted.

**Failure trace:** independently authorized signers submit reach-grant revocation R and unrelated KeyRegister K at base V. The malicious sequencer presents both as the next delta on separate views. This remains possible if the wrapper is signed: independent signers can receive the same predecessor count, with no predecessor digest specified. A receives R; B receives K. Their config head, MLS epochs, base hash and newest sequence agree. Genuine HeadCheck therefore reports consistency while B continues honoring the revoked reach grant.

Individual signatures authenticate statements, not one common history. Immutable names constrain an honest store; an active operator can equivocate. Eventual folding is not a bound, since deltas intentionally act without a config writer.

**Change:** hash-chain ordered deltas with base commitment, sequence and previous digest; compare the resulting effective-state commitment in gossip and BridgeState. Specify context binding, unique mutation ids, replay protection and rebase rules. Carry the complete authorization commitment into generation/drop attestations, push headers and gate coverage. Base version alone is insufficient when reader changes happen within one base: an earlier rotation at V must not be mistaken for coverage of a later removal delta at V.

**Acceptance:** deliver two valid same-count forks, swapped operations, replayed revocations and a rebase to independent honest devices. Matching counts must not constitute a witness. Also add then remove a reader within one projection base and verify no pre-removal generation satisfies the removal gate or drop-key coverage.

Authenticated log consistency similarly needs a content commitment in addition to size; [RFC 9162 §2.1.4.2](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.4.2) illustrates that distinction.

### F04 — Make drop-key freshness verifiable by a non-reader

**Evidence:** [§10.5, L3939–3956](/Users/brien/urnetwork/sidecar/DESIGN.md:3939), especially DropKeyStatement L3950; deposits §11.12 L4501; gate L4452; malicious-server test L7715–7727. **Confidence: high.**

DropKeyStatement signs repo, generation, public key and expiry. It does not sign a reader-set/projection commitment or proof that this generation covers a known removal. Gen_g contains a projection version, but that field is outside the stated drop-key signature. The MLS GroupContext binding cannot help a deposit-only client that lacks reader secrets.

**Failure trace:** reader A signs an unexpired generation-g drop statement while X is a reader. X retains RK_g and its derived drop private key. X is removed and honest readers rotate. Newly initialized depositor D verifies the current removal, but malicious gkm returns A's older statement. A remains an authorized signer; D has no prior generation pin. The statement passes its explicit checks, D seals a new deposit to g, and X decrypts it if the server gate is bypassed.

This attack does not withhold the removal from D. An honest-server 412 gate and a finite statement expiry cannot supply the missing client-side binding during the replay interval.

**Change:** publicly attest the drop key together with the complete effective authorization commitment from F03 and its generation coverage. A depositor must establish that the key covers every reader-shrinking change it knows, or wait for a fresh authorized attestation. Preserve public-key-only deposits and lazy payload rewrap.

**Acceptance:** initialize D after removal with no old pin; retain X's complete old state; return a correctly signed, unexpired old statement; disable evs's gate. D must reject before sealing/uploading. A current attestation permits a mailbox or record deposit that X cannot decrypt.

### F05 — Arbitrary matching peers do not enforce the 24-hour removal bound

**Evidence:** [§2.10, L1219](/Users/brien/urnetwork/sidecar/DESIGN.md:1219); D-TRUST-10 L1257; §7.9 L3021; §6.4 L2472 and defaults L2569–2571; test L7736–7737. **Confidence: high.**

The stated shared-group bound depends on obtaining a matching peer witness. Matching establishes consistency with that peer, not freshness relative to the authority able to revoke.

**Failure trace:** A revokes X and rotates at V'. The operator withholds V' from B/C but permits their hourly authentic HeadChecks. Both remain at V and continually refresh witnessed_at. After 25 hours or a week they still write under a reader set containing X. A removed X can also be the only responding old-state witness for B.

This is independent of F03: perfectly hash-chained stale histories still agree. More polling, wakes and peers do not solve an adversary-controlled partition. The explicit personal/no-peer exceptions do not cover a shared group with live agreeing stale witnesses.

**Change:** either define expiring customer write authorization whose refresh quorum intersects the revocation authority, including exact intersection/offline rules, or weaken the claimed bound to disclose indefinite exposure in stale partitions and obtain the owner's decision. A bounded customer lease/quorum need not make a server the key authority, but it does impose an availability tradeoff. Resetting a timer after any matching peer cannot supply the guarantee.

**Acceptance:** partition A from B/C after revocation while allowing B↔C hourly checks; advance an injected clock beyond the bound. Shared writes stop at the declared expiry, or the accepted guarantee explicitly permits indefinite staleness. Repeat with X as the sole witness.

[RFC 9750 §8.4.2](https://www.rfc-editor.org/rfc/rfc9750.html#section-8.4.2) identifies selective delivery denial as only partially detectable; gossip alone is not proof that no unseen update exists.

### F06 — Specify recovery and deposit-only key-retrieval authorization

**Evidence:** [§7.8, L2928](/Users/brien/urnetwork/sidecar/DESIGN.md:2928); RecoveryBind/Projection L2978–2994; §5.9 L2321–2322; §10.6 L3972, L3985; recovery L4074–4077; routes L4191–4197; visible-key fields L690–695. **Confidence: medium-high for the recovery gap; high for the literal scope mismatch.**

The code-only recovery flow unwraps RK before obtaining admission. Exchange rejects unadmitted clients, while the wrap route uses ordinary gkm capabilities. The defined RecoveryBind lives inside encrypted config, and the visible registered-key schema specifies presence/SSH keys, not a customer-authenticated recovery-key binding.

**Failure trace:** a member retains recovery words and account login but no files or admitted devices. The new client cannot exchange for gkm access to its wraps; admission-first has no defined public recovery binding to verify. Admin re-add is a separate fallback and cannot satisfy the promised solo recovery case.

A second scope gap affects already admitted depositors: exchange advertises repo:deposit for evs/gkm, but gkm verifies only r/rw/admin, including its drop-key route. A sidecar permitted to deposit but not read cannot literally obtain the public key it needs.

HPKE confidentiality does not make an unauthorized route reachable. Account login cannot substitute for customer recovery authority; an owner threshold choice does not define the bootstrap.

**Change:** define a customer-authenticated public recovery binding/proof and narrow proof-of-possession access to that member's own encrypted wraps/admission workflow, or fully specify authenticated admission before retrieval. Preserve threshold/veto rules. Add a deposit capability limited to public generation/drop attestations, without access to reader state, private wraps or secrets.

**Acceptance:** run actual exchange and gkm handlers from an empty replacement device with only code+login, all other devices offline, and no preauthorized fake client. Correct recovery succeeds within the chosen authority policy; wrong code and another member's wraps fail. A deposit-only principal fetches the public attestation and deposits, but cannot read content or reader/recovery wraps.

### F07 — Unknown CAS outcomes cannot trigger destructive cleanup

**Evidence:** [§11.8, L4428–4441](/Users/brien/urnetwork/sidecar/DESIGN.md:4428); retry expectation L7752. **Confidence: high.**

The head CAS is the commit point. Step 7 nevertheless says that on 409 **or any failure**, the engine removes objects written by step 5.

**Failure trace:** the object store applies the conditional head update, then its response is lost. The engine sees timeout/EOF and deletes the push, entry/slot versions or log material now referenced by the committed head. Another reader observes a valid head whose data is missing. A retry cannot reliably adopt the original commit after cleanup has destroyed it.

A definite conditional rejection and an unknown transport outcome are different. Immutable ids, signatures and later hash checks detect destruction; they do not repair it. The stated retry-adopts-own-commit behavior contradicts cleanup-on-any-failure.

**Change:** make unknown publication outcome an explicit durable/recoverable state. Resolve push_id against head/log ancestry before deleting staged objects. Preserve everything that may have committed until a reachability-safe resolution/GC protocol proves otherwise. A retry on another engine must adopt the same commit/version exactly once, including at log-page boundaries.

**Acceptance:** use a store fake that applies head CAS and then returns an error. Retry through a fresh engine, with intervening valid head advances and page rollover. The original commit remains fully readable and returns its original version once; no referenced object is deleted. Also test a definite 409, which may clean only proven-unreachable objects.

### F08 — Choose Git ref semantics compatible with the committed tree

**Evidence:** [§11.7–11.8, L4358–4433](/Users/brien/urnetwork/sidecar/DESIGN.md:4358); replay L4454; local hook L4487; exact export L4518; D-EVS-8 L4579. **Confidence: high.**

The design combines one EVS push per Git push and preservation of original commit OIDs with automatic rebasing of path-disjoint writes. Those are not generally compatible.

**Failure trace:** G0 contains a0/b0. Independent clients create GA(parent G0, a1/b0) and GB(parent G0, a0/b1). Both disjoint EVS changes succeed through rebase, producing a1/b1. GB's tree is still a0/b1 and GB does not descend from GA. Keeping GB as the accepted final Git commit loses A's tree; inventing a union commit changes the OID and needs client construction/signing. A post-commit hook cannot retroactively repair two acknowledged original pushes.

Git commits bind their tree and parents, and ordinary pushes protect ref ancestry: [Git objects](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects#_git_commit_objects), [fast-forward rules](https://git-scm.com/docs/git-push#_note_about_fast_forwards). Paths being disjoint does not make one independently created commit a descendant of the other.

**Change:** distinguish file-API merge semantics from Git's expected-ref CAS, or require a customer sidecar to create and sign an actual merge/rebased commit before acknowledging the second Git push. Preserve exact export only for the OIDs actually accepted.

**Acceptance:** use two independent daemons from one base. Concurrently push disjoint commits. The second receives a non-fast-forward/conflict or returns a real signed merge result. Final EVS files, exported Git tree, recorded OIDs and ancestry must agree; git fsck alone is insufficient.

### F09 — Fence and compose path-epoch migrations

**Evidence:** [§11.6, L4289–4305](/Users/brien/urnetwork/sidecar/DESIGN.md:4289); EvsPathMap L4343–4349; publication L4423–4433; read resolution L4458. **Confidence: high.**

A million-entry migration can take roughly 17 hours at the stated per-repo rate, but a second member removal must immediately start another path epoch. Reads are described as checking “both” epochs; the map has no committed source-head cut or complete set of source epochs. Worker fencing and map coverage of concurrent changes are unspecified.

**Failure trace:** pause p0→p1 after only some entries move. Remove another member and start p2. An entry still only in p0 is invisible to p1/p2 lookup; a map built only from p0 misses entries already moved into p1. Resuming the old worker can delete a source needed by the newer migration. Separately, a file added after map construction but before the PATH_EPOCH rebase can fall outside the map.

Hash verification reports missing data but cannot supply missing migration coverage. Requiring immediate rotations while assuming the previous copy finished is not an implementable protocol.

**Change:** bind each map to an exact committed snapshot/write barrier; define concurrent create/rename handling; compose mappings or retain all live physical source epochs; fence superseded workers and define subscription/read behavior through completion. Immediate logical revocation need not wait for bulk copying.

**Acceptance:** use barriers for two rapid removals, partial copies and reverse-order worker resumption. Interleave creates, renames, deletes and a head rebase around each snapshot. Every live authorized path resolves exactly once, revoked keys cannot derive new tokens, and no obsolete worker deletes the last current representation.

### F10 — Serialize segment publication with orphan collection

**Evidence:** [§11.8, L4424–4441](/Users/brien/urnetwork/sidecar/DESIGN.md:4424); §11.13 L4534. **Confidence: high.**

A publisher checks that referenced segments exist and later commits the head. GC decides that old unreferenced segments may be deleted. No protection/fence connects those actions.

**Failure trace:** S was uploaded more than 24 hours ago but never committed. A fresh valid push checks S, then pauses. GC sees no committed reference and deletes S. The unchanged head CAS succeeds. The acknowledged push references a missing segment.

A generous grace interval lowers probability; it cannot close this deterministic check/use race. Content hashes detect absence, and single-key CAS does not serialize unrelated segment deletion.

**Change:** define durable publication protections or deletion claims such that an object selected for deletion cannot subsequently become newly reachable without re-protection/re-upload. Include stalled publishers and F07's unresolved commits. GC must participate in the storage model, not sit outside its safety argument.

**Acceptance:** age S with an injected clock; pause after the last existence check; run GC; resume publication. Either S survives or publication fails safely and retries with a protected object. Repeat with unknown head-CAS outcome, engine death and a second publisher using S.

### F11 — Erasure must cover every representation of a message

**Evidence:** [§10.8, L4072](/Users/brien/urnetwork/sidecar/DESIGN.md:4072); drop derivation L3949–3955; slots L4316–4319; deposits/erasure L4501–4503; mailbox layout/ingest L5719–5741. **Confidence: high.**

Two independently specified representations escape per-message slot deletion.

**Deposit trace:** A commits the ingested m/ body and i/ index, then crashes before the separate CONSUME. Another device erases the message slot and clears message-key caches. The original deposit remains live HPKE ciphertext to a drop key derivable from retained RK_g. A newly authorized reader can recover it, including through the backwards generation ladder. This is not an old plaintext cache or forbidden backup. Retained recipient secrets can decrypt past HPKE ciphertexts; see [RFC 9180 §9.7.4](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.4).

**Index trace:** one i/ entry/file contains up to 4,096 messages' sender, subject, snippet, attachment names and one-time codes. Deleting M1's m/ slot leaves the shared index readable for M2, including sensitive M1 fields and potentially retained versions. A fresh reader needs no M1-specific cached key.

Eventual CONSUME/compaction cannot establish erasure at slot deletion. Rewriting only the latest index also leaves retained decryptable history.

**Change:** define an erasure dependency graph covering accepted deposits, ingest/spool copies, bodies and derived index fields. Use destructible per-message/deposit keys from acceptance, with mutable deletable wraps; avoid sensitive shared-index fields outside that boundary. An erasure tombstone must prevent retries from recreating the message. Any alternative transaction must close every representation before acknowledging erasure.

**Acceptance:** crash after ingest commit/before CONSUME; erase M1; retain M2 and legitimate current repo keys, but clear M1 caches. A newly admitted reader must recover neither M1 raw content nor its sensitive index fields from any live/retained artifact. Restarting ingest must not resurrect M1.

### F12 — Claim a terminal shred state before destroying keys

**Evidence:** [§11.12, L4505–4515](/Users/brien/urnetwork/sidecar/DESIGN.md:4505); repo state L4387–4389; D-EVS-19 L4601. **Confidence: high.**

The state machine has keying/active/deleted. Restore changes deleted→active; a scheduled or --now worker deletes slots first, then gkm, objects and repo state last. There is no durable conditional transition claiming the deletion before irreversible work.

**Failure trace:** restore and shred both read deleted. Restore succeeds, returning an active repo. The already selected shred task then deletes its keys and finally repo state. The seven-day boundary and --now both permit this overlap; a retried old job can also attack a later restore/delete incarnation.

Keys-first order is appropriate after irrevocable ownership is established; it does not establish that ownership. Separate tests for successful restore and eventual shred miss the race.

**Change:** require a conditional deleted→terminal-shredding transition, bound to a deletion incarnation, before the first deletion. Restore competes for that transition before the deadline. Once shredding wins, restoration is refused. Persist enough incarnation/terminal state for retries and any allowed identifier reuse.

**Acceptance:** barrier restore against both scheduled and immediate shred; crash/retry at every destructive step; then run another delete cycle. Exactly one result wins: successful restore with all required keys retained, or irrevocable shredding with restore refused. Never return restore success followed by an old task's destruction.

### F13 — Keep effective custom-domain CAA under customer authority

**Evidence:** [§12.8, L4854–4858](/Users/brien/urnetwork/sidecar/DESIGN.md:4854); §13.8 L5123; EX1 L596; D-DNS-9 L4907; D-TLS-11 L5197; test L5236. **Confidence: high.**

The custom-host workflow uses app.customer.example CNAME app.net.ur.network, a parent customer CAA account pin, and a delegated DNS-01 challenge. That CNAME allows the operator to override the effective CAA lookup.

**Failure trace:** the operator adds an exact CAA RRset at app.net.ur.network authorizing operator account U. CAA lookup for the customer host follows the alias and finds that nonempty result before reaching customer.example's account pin. The operator controls the delegated challenge and can validate its order under U. The customer's ACME account key remains secret.

The alias-search rule is specified in [RFC 8659 §3](https://www.rfc-editor.org/rfc/rfc8659.html#section-3); [Let's Encrypt's CAA guidance](https://letsencrypt.org/docs/caa/#where-to-put-the-record) confirms target-side CAA is respected. This is an active-operator modification, not a claim that the honest CNAME always inherits the operator parent's CAA.

Tenant API refusal of CAA does not restrain the authoritative-zone operator. CT monitoring detects issuance afterward; it cannot establish the advertised exclusion.

**Change:** retain customer control over the certificate name's effective address/CAA records, for example customer A/AAAA or customer-side ALIAS flattening that retains the queried name. Do not place a DNS CNAME into the operator namespace for this stronger guarantee. CAA cannot simply coexist alongside that CNAME. Keep the customer account and delegated challenge workflow.

**Acceptance:** test the actual CNAME/challenge topology, not a direct-host simplification. Keep the parent customer pin, inject operator-account CAA at the canonical target, and attempt operator issuance. The adopted topology must refuse it while permitting the customer's order.

### F14 — Run restore needs ownership, not just a before/after diff

**Evidence:** [§16.2, L5923](/Users/brien/urnetwork/sidecar/DESIGN.md:5923); capture L6047–6055; restore L6059; D-MCP-8 L6173; M3 exit L7887. **Confidence: high.**

The daemon serves concurrent harness sessions but records workspace changes through run-start and hook-boundary scans. No exclusive workspace lease, isolated worktree or trustworthy mutation attribution is specified.

**Failure trace:** A/B start from f=original. B edits f. A edits only g, then A's repository scan sees both f/g changed since A's baseline and records both. Nothing changes after that scan. Restoring A therefore passes the “changed since last scan” conflict check and overwrites B's f. A human edit absorbed by the scan has the same problem.

Hashes authenticate the recorded diff, including its wrong attribution. A preview is useful but does not establish the promised confinement, particularly for an untainted W tool.

**Change:** use isolated worktrees, an exclusive capture lease, or reliable per-run mutation attribution. Mark ambiguous changes and refuse destructive automatic restore. Define a run-start baseline barrier: returning a 300 ms hook before a slow baseline completes must not silently absorb the first tool's edits into the baseline.

**Acceptance:** deterministically interleave A/B as above, then restore A. Only g changes, or f is refused as ambiguous. Repeat human edits, shared-file edits, slow baseline capture and overlapping starts. Recheck current bytes immediately before replacement.

### F15 — Align the module path with the calendar major version

**Evidence:** [§4.7, L1986–2000](/Users/brien/urnetwork/sidecar/DESIGN.md:1986); §4.9 L2014; D-REPO-1 L2043; M0 L2096/L7884. **Confidence: high; synthetic parser failure reproduced.**

The literal go.mod declares github.com/urnetwork/sidecar. The prescribed release is github.com/urnetwork/sidecar/v2026 tagged v2026.M.D-code. These are not one publishable Go-module identity. Sibling replacements can hide the mistake locally; they do not fix tagged consumer resolution.

An isolated temporary consumer requiring the unversioned path at v2026.11.3-demo, with networking disabled, failed during go.mod parsing:

    version "v2026.11.3-demo" invalid: should be v0 or v1, not v2026

This was a synthetic fixture, not a sidecar build. [Go's module reference](https://go.dev/ref/mod#major-version-suffixes) requires v2+ major suffixes to agree with module/import paths; the legacy +incompatible exception does not repair a new module with go.mod.

**Change:** adopt the already proposed /v2026 canonical path consistently in module declaration, imports, generated go_package fields, self-imports and consumer require/replace entries before M0's first pin.

**Acceptance:** publish a tagged fixture through a local file proxy. With GOWORK=off, an empty module cache and no sibling replacements, install the CLI and import root/protocol/engine packages. Require one sidecar module identity and one registration of every protobuf descriptor.

### F16 — Retain the current ordering frontier when pruning epochs

**Evidence:** [§10.6, L3977–3996](/Users/brien/urnetwork/sidecar/DESIGN.md:3977); KF5 L4062; ack lifetime L974–979; Q-KEYS-11 L4170. **Confidence: high.**

Creating epoch n+1 requires epoch n to exist. Retention deletes old epochs once every recently acking leaf has passed them, but acks expire after 30 days and no current-tip exception is specified.

**Failure trace:** all devices go offline at epoch n>0 for 31 days. The recent-ack set becomes empty and the retention predicate is vacuously satisfied. GC removes n. Returning devices still have GroupInfo/RK and can construct an update/external resync, but the next epoch is rejected because n no longer exists.

Generation materialization preserves keys, not the predecessor-existence condition. Emergency group re-form is not the stated routine lossless catch-up path.

**Change:** preserve the latest epoch/ordering watermark independently of prunable payloads, or define a durable compaction frontier that safely authorizes n+1. State how external resync verifies it.

**Acceptance:** reach epoch 8, expire all acks, run retention, and return with legitimate local state. Both ordinary update and required resync must produce one canonical epoch 9 without manual re-form or resetting monotonic pins.

### F17 — Scope notification cursors to the same entity as their counters

**Evidence:** [§6.8, L2644–2662](/Users/brien/urnetwork/sidecar/DESIGN.md:2644); per-ref heads L4390–4396; hints L4462–4464; Appendix D L8800. **Confidence: high.**

One evs:repo topic has a monotonic version; consumers drop versions already applied. EVS emits the changed ref's independently numbered head version.

**Failure trace:** after main@100, branch A@1 uses the same topic and is discarded. Its next 99 updates can also be ignored. A reset can appear to roll the durable topic backward. The optional ref body cannot rescue an outer version already discarded, and coalescing may omit it.

Hourly resync does not meet the notification contract or define a valid cursor.

**Change:** use repo+ref topic versions, or introduce an actual durable repo-wide event sequence with recovery semantics. Keep each ref's integrity pin separate; update wildcard subscriptions, resets and metadata together.

**Acceptance:** interleave main@100, A@1, B@1, main@101 and A@2, with coalescing, resident restart and Redis loss. Every subscribed ref change remains discoverable within the claimed target, without lower-version alarms or reliance on unrelated full scans.

### F18 — Narrow or repair the post-removal ref-name leakage claim

**Evidence:** [§11.5–11.6, L4281–4285](/Users/brien/urnetwork/sidecar/DESIGN.md:4281); §10.5 L3964. **Confidence: high.**

The leak bound limits removed-member name guessing to names created before removal, including branch/ref names. K_ref nevertheless derives from RK_1 for the repo's lifetime.

**Failure trace:** after removal and path rotation, an authorized writer creates a new branch with a guessable project/customer name. The removed reader retains RK_1 and can compute candidate ref ids against new head/push object names indefinitely using the raw-store access in the threat model.

Rotating path tokens does not rotate the separate lifetime ref key.

**Change:** preserve existing opaque ids but use fresh-generation derivation/random ids and a sealed catalog for new refs, or explicitly disclose indefinite dictionary testing of future branch names as an owner-accepted consequence. The present bounded claim cannot remain.

**Acceptance:** retain old keys, remove that member, create a new secret-named branch, and expose raw object names. New-ref guesses must fail under the adopted stronger design, or match the explicitly revised leakage statement.

### F19 — Define a commit fence for repo gates and deletion

**Evidence:** [§11.8, L4387–4395](/Users/brien/urnetwork/sidecar/DESIGN.md:4387), L4422–4433/L4452; D-EVS-18 L4599; acceptance L7718–7720. **Confidence: high in the missing fence; impact depends on overlap semantics.**

A push reads/checks repo gate, then commits a different head object. Updating repo gate does not invalidate that head ETag.

**Failure trace:** W passes its final old gate check and pauses. Removal installs a new gate; W resumes and commits the unchanged head under the old generation. There is no CAS failure to trigger another check. Deletion has the same split.

This is a concrete gap in the promised 412 enforcement, but **not independently a demonstrated break of the primary client-side encryption rule**: an already sealed overlapping write may legitimately serialize before removal. The design must say whether that is allowed and when removal completes.

**Change:** order gate/deletion transitions against all affected head commits through a common fence or a specified in-flight completion barrier. A second unfenced GET still races. Preserve client-side generation enforcement regardless.

**Acceptance:** pause push/deposit after its last check, install removal, then resume with no other head writer. Require 412 or documented serialization before completed removal. Repeat deletion and creation of a new ref. Completion must not be reported while later old-state commits remain possible.

### F20 — Route custom SNI names to their sidecars

**Evidence:** [§13.4, L5006–5013](/Users/brien/urnetwork/sidecar/DESIGN.md:5006); downstream lookup L5054; custom names L4856–4858; W1 L6915. **Confidence: high.**

The shared 443 map sends the platform root to platform HTTPS, *.ur.network to tlsedge, and everything else to platform HTTPS. A browser requesting app.customer.example sends that original SNI even when DNS uses a CNAME into ur.network.

**Failure trace:** custom DNS and publish mapping are correct, but the LB chooses platform HTTPS before tlsedge's custom-name lookup. The request receives the wrong service/certificate or refusal. TLS-ALPN-01 validation also cannot reach the intended sidecar.

A downstream map cannot correct an upstream dispatch that never reaches it.

**Change:** propagate active custom-SNI routing into ingress, or explicitly whitelist platform names and route appropriate other registered names to tlsedge, with safe unknown-name handling. Preserve shared-IP/SNI-only constraints.

**Acceptance:** render and run the full LB→tlsedge→sidecar path with a custom host, ordinary platform hosts and unknown SNI on each ingress family. Verify certificate validation, HTTP and challenge reachability; remove the mapping and verify withdrawal.

### F21 — Normalize DMARC anomaly evidence to message evaluations

**Evidence:** [§14.7–14.8, L5423–5459](/Users/brien/urnetwork/sidecar/DESIGN.md:5423), especially L5459. **Confidence: high in the unit mismatch.**

SMTP permits one message to up to 100 recipients on one connection. The anomaly rule suspends when aggregate report counts exceed edge connections by 20%+5. DMARC count concerns messages to which policy evaluation applies, not TCP sessions; see [RFC 9990 §3.1.1.8](https://www.rfc-editor.org/rfc/rfc9990.html#section-3.1.1.8). Recipient-level reporting is a real implementation behavior, illustrated by [Mox's SMTP implementation](https://www.xmox.nl/xr/dev/smtpserver/server.go.html).

**Failure trace:** one legitimate connection delivers to ten recipients at one domain. A report records ten evaluations. Ten exceeds 1×1.2+5, so correct sending trips the purported proof-soundness alarm and suspends the sender. Report overlap/duplicates can inflate comparisons further.

The ZK proof's one-message/recipient restrictions do not make one connection equal one reported evaluation.

**Change:** compare compatible, conservatively bounded quantities with domain/time scope, recipient semantics and report-id deduplication. Treat aggregate excess as an investigation signal unless a true upper bound follows from proved facts; do not label an invalid unit comparison a cryptographic soundness failure.

**Acceptance:** generate one proven message with ten recipients and a valid count-ten report; no false suspension. Add duplicate report ids, overlapping windows, delayed/partial reports and a genuinely impossible count.

### F22 — Keep flow ownership for the complete promised drain

**Evidence:** [§17.5, L6286–6288](/Users/brien/urnetwork/sidecar/DESIGN.md:6286); disposition L6399–6400. Existing timeout context: [connect/ip.go L490–510](/Users/brien/urnetwork/connect/ip.go:490). **Confidence: high.**

Pins retain pairs seen within 120 seconds, while edits promise existing flows stay on their original link for a default 300-second drain, up to 3,600 seconds. The existing NAT timeout can exceed 120 seconds.

**Failure trace:** an established TCP connection is idle for 121 seconds but remains live. An edit changes selected advertiser A→B. The pin has expired; the next packet goes to B instead of draining through A, breaking the connection. A full fixed-size pin table creates the same question for active-flow eviction.

The explicit “TCP cannot change exit mid-flow” rationale requires a lifetime stronger than recent-packet age.

**Change:** retain ownership through actual flow close/timeout and the applicable drain, with explicit admission/overflow policy. Memory pressure may reject new flows; it must not silently migrate an established one.

**Acceptance:** idle a live flow beyond 120 but below NAT/drain expiry, edit routing, then resume. The old flow stays on A and a new flow chooses B. Repeat maximum drain and a full pin table.

### F23 — Separate transport credential loss from authority revocation

**Evidence:** [§18.7, L6700–6702](/Users/brien/urnetwork/sidecar/DESIGN.md:6700); core lifecycle L2151; refresh/revocation L2262–2263; parent loss L2291; identity retention L2248. **Confidence: high.**

The SDK maps AddAuthLogoutListener's confirmed 401 to terminal Revoked. Core rules instead classify refresh refusal/parent transport loss as Unenrolled while retaining stable identity and admission.

**Failure trace:** an admitted phone is offline past seven-day expiry, or loses its parent transport client. A confirmed child-JWT rejection terminally revokes the sidecar despite no SidecarRevoke. Re-pairing no longer follows the ordinary identity-preserving path. A delayed old-session callback can also affect a new generation.

The existing SDK callback reports JWT rejection, not customer authority; its source warns that the compatibility callback lacks immutable event origin: [api.go L303–355](/Users/brien/urnetwork/sdk/api.go:303).

**Change:** map credential rejection to generation-scoped Unenrolled/credential-needed, preserving identity/keys/admission. Only designated authenticated revocation/bind outcomes enter Revoked. Use generation-bearing logout events.

Also explicitly wire the required ClientKey proof into SDK-owned refresh: [api.go L3665–3672](/Users/brien/urnetwork/sdk/api.go:3665) is currently bearer-only. Disabling the core refresher before that integration is defined leaves Q-CORE-4(b) unenforced or breaks refresh.

**Acceptance:** expire tokens with an injected clock, re-pair, and retain sidecar_id/key/admission. Repeat parent loss and an old event delivered after new login. Run the real host adapter against proof-enforcing refresh, and verify genuine SidecarRevoke remains terminal.

### F24 — Render MCP results for the negotiated protocol

**Evidence:** [§16.3–16.4, L5935–5941](/Users/brien/urnetwork/sidecar/DESIGN.md:5935); L6028–6030; D-MCP-1 L6159; conformance L7639. **Confidence: high on large-result incompatibility; ordinary results depend on SDK helper selection.**

The promised range starts at MCP 2024-11-05, but outside content is required only in structuredContent and results above 256 KiB become resource_link. Those features arrived in 2025-06-18: [legacy result types](https://modelcontextprotocol.io/specification/2024-11-05/server/tools#tool-result), [2025 change list](https://modelcontextprotocol.io/specification/2025-06-18/changelog).

**Failure trace:** a strict legacy client initializes successfully, then receives unreadable structured-only output or a resource_link outside its content union. Initialization conformance does not exercise this failure.

The pinned [go-sdk v1.7.0 adapter](https://github.com/modelcontextprotocol/go-sdk/blob/v1.7.0/mcp/server.go#L377-L423) automatically supplies JSON TextContent when Content is nil. That can repair ordinary output, but needs an exception to “only”; an explicitly supplied resource_link is non-nil and is not automatically downgraded.

**Change:** specify version-aware results with the same trust/source tags and untrusted-data delimiters in a legacy text fallback. Below the feature version, use supported references and a defined resources/read path, or raise the minimum supported version. Preserve size limits. The [structured-content guidance](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#structured-content) already describes text compatibility.

**Acceptance:** strict clients for each promised version call small and over-limit evs/mail handlers, validate actual wire schemas, consume output and follow references. Exercise both nil-Content SDK fallback and explicit result content.

## Conditional concerns and guarantees requiring a decision

These are material, but are not additional unconditional exploits. Their assumptions must be settled in the design before implementation can use them as contracts.

### C01 — Does “read-only browser” limit authority or only the UI?

**Evidence:** §18.4 L6593–6602; §18.8 L6728–6731; SidecarAdmit L2974–2976; authority L2996–3005; config writers L3280–3282. **Potential priority: P1; confidence high in role inheritance, medium-high in the intended boundary.**

An Owner/Admin admits a browser with its own identity key. SidecarAdmit has no read-only device capability, so member-derived config-writing and authority-signing rules can authorize that browser key. admin_refused limits platform-admin routes; declares_no_egress limits transport. Neither constrains customer-signed authority.

If “read-only” is a security restriction, an Owner browser at k=1 can bypass its UI and sign a config/admission change; an Admin browser can contribute toward a threshold. EX7 already accepts that served browser code can expose decrypted content, but does not itself decide whether the browser should inherit policy authority.

Define a customer-signed read-only/delegated device capability enforced by writers, admissions, approvals and threshold counting, while allowing necessary MLS maintenance. Alternatively explicitly disclose full member-authority exposure and obtain that product decision. Test direct signed requests from an admitted Owner browser at k=1 and k=2, not only absent UI buttons.

### C02 — Non-public raw TCP has no audience protocol

**Evidence:** §13.7 L5106–5110; flags L5165; HTTP edge login L2945–2958; S5 L7671. **Potential priority: P1; confidence high in the missing contract, conditional on accepted endpoint combinations.**

The ALPN table forwards other declared protocols or no ALPN as decrypted TCP, while members/link authentication is defined through an HTTP front. If HTTP Find accepts no ALPN, a visitor can avoid that front. If it rejects no ALPN, that specific bypass is closed, but a non-public --tcp endpoint still needs an authentication mechanism. ALPN negotiates application protocol, not visitor identity ([RFC 7301 §3](https://www.rfc-editor.org/rfc/rfc7301.html#section-3)).

Bind dispatch to configured protocol. Treat no-ALPN HTTP as authenticated HTTP/1.1 or refuse it; refuse non-public raw publication until its client authentication is specified. Explicitly public raw forwarding is compatible with the constraints. Test each protocol/audience combination and require zero application-upstream bytes before authorization.

### C03 — Define key coverage of a recoverable mirror

**Evidence:** slots §11.6 L4316–4319; cache L3968; erasure L4072; mirrors L4540; “only in the cluster” L6958; reseed L7011–7018. **Potential priority: P1 for the advertised recovery guarantee; confidence high in the unresolved contract.**

A signed-push/ciphertext mirror plus every RK_g cannot reconstruct a lost random entry key if its only wrap was in a destroyed slot. Replaying signed data and reproducing C_v authenticates the ciphertext, not the missing entropy.

“Full mirror” could intend a live customer copy of those erasable keys, but the explicit no-slot/wrap-backup language and reseed inputs do not define that exception. Therefore it would be excessive to conclude every possible full-mirror implementation is broken; it is equally unsafe to claim current reseed guarantees body recovery.

Specify ciphertext coverage and body-key coverage independently. If authorized live mirrors may hold erasable keys, distinguish them from forbidden operator backups and define deletion synchronization/reseed. Otherwise disclose body loss. Do not silently reverse owner decision 90.

Test a declared full mirror after cache eviction and total cluster loss using only permitted artifacts. Every body labeled recoverable must decrypt, and prior erased entries must remain erased.

### C04 — Daily metering needs an uncertainty policy, not an aggregate-receipt assumption

**Evidence:** §20 L7312–7316; usage production L4538/L7252–7257. **Potential priority: P2; confidence medium-high, conditional on Stripe meter mode and producer durability.**

A daily report can be accepted by Stripe while its response is lost. After the guaranteed identifier-deduplication window, an asynchronously delayed aggregate is not proof the event was absent. Retrying into a raw sum meter can double-charge. The current [event API](https://docs.stripe.com/api/billing/meter-event/create) guarantees identifier uniqueness for at least a rolling 24 hours; [summaries](https://docs.stripe.com/api/billing/meter-event-summary/list) are aggregates, not event-id receipts, and [usage processing](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api) is asynchronous.

Freeze the meter mode. A properly configured [daily pre-aggregated replacement meter](https://docs.stripe.com/billing/subscriptions/usage-based/meters/configure) may support the intended canonical daily report; otherwise quarantine/reconcile old uncertain sends instead of treating a temporarily low aggregate as safe to resend.

Separately define durability of the producer's 60-second usage window. A ledger only after receipt cannot recover read-only transfer counters lost in an engine crash; nightly push-log recount does not reconstruct downloads. Choose durable producer identity/snapshots or disclose a bounded loss budget.

Tests must accept then lose a report response, expire deduplication, delay summary visibility and process retries in both orders without double-charge. Crash a read-only transfer producer immediately before report and verify the declared accounting bound. These are contract requirements, not claims that a specific implemented meter already double-bills.

### C05 — Burner subdomains do not inherit network MTA-STS

**Evidence:** DNS L4802–4805; burner addressing L5771–5775; mail coverage claim L5904; certificate scope L5119. **Potential priority: P2 disclosure/coverage correction; confidence high.**

The listed policy exists at the network/alias domain. A burner recipient at label.net.root causes lookup under _mta-sts.label.net.root and policy HTTPS at mta-sts.label.net.root; MTA-STS does not inherit the parent policy. See [RFC 8461 §3.3–3.4](https://www.rfc-editor.org/rfc/rfc8461.html#section-3.4). A network wildcard certificate does not cover that additional two-label policy host.

Shared-MX DANE can still protect DANE-capable senders. Narrow coverage statements to distinguish it from MTA-STS-only senders, or explicitly fund per-burner policy/HTTPS/certificate publication and its metadata/quota consequences. Preserve the owner's fixed address format unless changed explicitly. Test lookup and enforcement for an actual burner domain, not only the network mailbox domain.

### Other contracts to close without promoting assumptions into findings

| Concern and evidence | Required clarification and deterministic check |
|---|---|
| Cross-network keychain separation: L2307–2309/L2374 versus no cross-network key link L2321 | State whether roots, files and recovery wraps are per membership. If one root is wrapped to every membership, code A plus a copied shared keychain can expose B. Test two memberships with distinct codes; common unlock UX must not imply common cryptographic authority. The schema permits a safe per-network interpretation, so this is not a proven cross-network exploit. |
| Socket ticket source binding: L3685 versus D-SOCK-12 L3803 | Require source-id equality for every ticket, then apply only the intended edge Hello exception. Test an unused edge ticket presented by another source. Possession of such a ticket is an additional attack assumption. |
| Flow revocation versus dial completion: L6293/L6399 | Define publication ordering or generation fencing so a pre-check dial cannot appear after CloseFlows. Barrier the hook/dial against revocation. Existing NAT registration may help; inspect actual implementation before declaring a race. |
| Share prefix representation: L6406 | Equal-length aliases inside a /16 cannot represent a /8 or unlimited distinct /16 targets. Validate capacity/prefix feasibility before activation and return an explicit refusal. This is a representation constraint, not a request for a new network quota. |
| Legal-hold kind: L7494 versus L7496 and api-14 | Generic 90+90-day holds cannot represent the design's separate one-year report-preservation period. Define hold kind/deadline and destruction precedence. Test days 180–364 for a year-scoped hold while ordinary holds expire. This is an internal data-model issue; applicability remains counsel's decision. [18 USC 2258A](https://uscode.house.gov/us/usc/119-124/t18/s2258A/) is the primary statutory source. |
| Raw abuse-report privacy: L5464 versus absolute I-2/CC1 wording L1193/L7684–7690 | The approved listener receives raw bytes, including potentially quoted customer content, in memory for DKIM hashing and HPKE sealing. “Unparsed” is not ciphertext. Disclose this narrow intake exception and scope the canary accordingly; do not add prohibited body inspection. |
| Sticky run taint: L5941/L6030/L6165 | Persist/reconstruct taint and approval consumption across daemon death, transport restart and client-generation changes; otherwise resume conservatively tainted. Test an untrusted read followed by crash/reconnect and an attempted outward W action. |
| Protobuf fuzz oracle: L7648 | Define re-marshalling agreement with a reference encoding of the decoded message, not byte identity with arbitrary valid input. Seed reordered/duplicate/unknown fields; protobuf serialization is [not canonical](https://protobuf.dev/programming-guides/encoding/#field-order). |

## Strengths, accepted risks and suspicious issues ruled out

The following boundaries should be retained while correcting the findings:

- **Dependency and privilege separation:** sidecar depends on connect; server/SDK host it through interfaces; server-only engines remain child packages. The iOS tunnel and privileged desktop network process receive compiled state rather than full content keys. F01/F02 require a complete identity/bootstrap contract at that seam, not relocating plaintext there.
- **Customer authority from the first release:** signed admissions, role checks at parent state, complete encrypted config for admitted devices, scoped service audiences, and a distinct platform-admin boundary are the right primitives. F03–F06 concern missing composition/freshness/access protocols around them.
- **A credible storage base:** a fixed quorum-correct single-object conditional PUT is an appropriate primitive. The design already recognizes MinIO's conditional-PUT fix, including [upstream PR 21653](https://github.com/minio/minio/pull/21653); no new claim that this known bug was ignored is made. The defects above concern multi-object publication, cleanup and lifecycle, which single-key correctness does not automatically solve.
- **Explicit key-history semantics:** current generations opening history and removed readers retaining old keys are stated tradeoffs. This review does not demand retroactive confidentiality. It distinguishes those tradeoffs from exposure of newly deposited content after a known removal, or content represented as cryptographically erased.
- **Operational realism:** separating metadata NVMe from segment HDD, requiring measured service budgets, preserving original signed bytes during recovery, and warning about unmirrored/site-lost data are useful. The listed throughput numbers remain hypotheses until measured; no benchmark result is inferred.
- **Useful verification machinery:** injected clocks, fake/real persistence contracts, malicious-server gate-off tests, secret canaries, cross-repo pins, model/history checks, and explicit soundness work before sending are strong foundations. Their adversarial schedules need the additions above.
- **Redis wake handling is not necessarily CROSSSLOT:** L6708 can correctly mean EXEC the same-slot hint/live transaction, inspect the result, then separately enqueue on the wake shard. [Redis Cluster](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/) requires same-slot multi-key operations, but the design permits that valid sequence. Test the chosen sequence on three real masters and inject failure between operations; do not rank an invalid optional interpretation as an existing defect.
- **Browser/mobile feasibility was checked selectively:** Chrome's [offscreen API](https://developer.chrome.com/docs/extensions/reference/api/offscreen) has a real WORKERS reason, and the audio timeout does not apply to every offscreen document. Android's [six-hour foreground-service limit](https://developer.android.com/develop/background-work/services/fgs/timeout) concerns dataSync/mediaProcessing, not all VPN-backed operation. HTTPS-only browser reads do not require peer streams. These are not platform impossibilities.
- **Native networking details:** per-source TransferPath NAT state addresses the alleged cross-network five-tuple collision; [Compact Denial, RFC 9824](https://www.rfc-editor.org/rfc/rfc9824.html), is a real standardized DNS mechanism; the current ACME profile/rate discussion is not dismissed as obsolete. SNI-only ingress necessarily has compatibility/availability limits, already assigned to a census and owner decision.
- **Accepted owner risks remain accepted:** no ACL document preserves legacy untagged LAN behavior; the default listener bind remains all-interface; same-OS-user harnesses are inside the device boundary; harness prompts are an allowed weaker fallback; browser-served code can expose decrypted data; single-site loss and no operator slot/wrap backup remain constraints. None is relabeled as a newly discovered defect.
- **No new external-audit or physical-phone gate:** in-house MLS/proof implementation, deferred external audit, signing rather than reproducible-build gating, and surrogate-only iOS acceptance are owner decisions. The report asks the specified internal gates to test the claimed properties.

## Recommendations on open peer-review and owner questions

These are recommendations, not assertions that the owner has already accepted them.

| Question | Recommendation and qualification |
|---|---|
| Q-CORE-4 | Adopt (b), ClientKey proof on refresh and token exchange. Wire it through the real SDK TokenSource and test it before disabling the core refresher. Issuance proof alone does not solve F01's native peer identity binding or imply every resource request is DPoP-bound. |
| Q-TEST-1 | Start with the proposed sidecartest helpers and shared conformance assertions. If helpers drift, export connect/connecttest rather than maintaining incompatible protocol fakes. Test exported host interfaces and real authorization handlers, not only preauthorized clients. |
| Q-TEST-2 | Adopt the real three-master Redis Cluster plus the final quorum-fixed MinIO at local/release gates, with CROSSSLOT lint as an additional check. One-node Redis and an in-memory CAS fake cannot validate production partition/transaction semantics. |
| Q-TEST-6 | Limit the oneof prohibition to envelope, stream and push messages as proposed; preserve the deliberate MLS credential union. Make descriptor lint target those exact families. |
| Q-KEYS-11 | The 30-day/recent-ack policy is reasonable only after F16 preserves a durable current ordering frontier and generation materialization. Offline duration must not force emergency re-form after routine GC. |
| Q-EVS-6 | Require replay from a trusted pin for security-sensitive config, mail configuration, approvals and restore decisions. General-content head reads can retain the weaker v0 option if per-file freshness limits are explicit and measured. A Merkle-root option changes format/cost and should not be assumed accepted. A valid retained entry is not automatically the latest entry. |
| Q-OPS-2 | Use the proposed inlining/debouncing first, with an explicit measured HDD PUT threshold for repacking. Do not freeze a locator format that precludes repacking before collecting the M2 measurement. No current design arithmetic establishes achieved capacity. |
| Q-BRIDGE-2 / Q-SDK-5 | Use per-target clients only within measured host budgets. Keep iOS links disabled where the surrogate memory cell fails. Use the root device role only if the 1 MiB gate passes; otherwise the named leaf-package exception is the appropriate choice. |
| Q-OPS-5 | Stage DNS API deployment as proposed, with a separate DNSSEC/serial gate for authoritative-edge behavior. Do not conflate API canary rollout with signer/DS safety. |
| Q-CTX-4 | Prefer the proposed online §9 sharer for the blocking CLI. Define its source binding, expiry/count, reconnect, cross-network identity and billing before release. Assign a milestone: the opening table itself says no §23.6 owner is listed. |
| Q-KEYS-13 | Permitting authorized writer leaves to apply customer-signed membership changes helps liveness without giving them authority to invent changes. It does not by itself make config-group updates unattended if only admins are config writers. Test that distinction. |
| Q-ACL-9 | Do not adopt the shared DelegationReaderKey mechanism unchanged: L3957 explicitly lets a reaped agent read until DelegationRevoke, while I-15 requires reaping to revoke future generations. Use individually revocable reader keys/wraps, or obtain an explicit owner change to cohort revocation semantics and its labels. The leaf-per-reader baseline is not accused of this optional flaw. |
| Q-TEAM-10 / Q-TEAM-11 | Prefer non-admin self-admission without an AdminSet bypass, and recovery as one threshold contribution with the veto window. These are already explicit owner questions, not undisclosed vulnerabilities. Whichever choices win still need F06's bootstrap. |
| Q-MAIL-13 | Label facts such as REQUIRETLS asserted separately from proof of active-operator exclusion. [RFC 8689 §8.3](https://www.rfc-editor.org/rfc/rfc8689.html#section-8.3) does not turn a dishonest MTA into a trustworthy delivery attester. DKIM authorship alone does not prove the path used. Keep open-label decisions explicit. |

The owner choices concerning DATA/BDAT coverage, actual inbound SNI census, HE connectivity, reputation ramp, preservation-hold effects on shredding, and SQL merge/deploy timing remain genuine decisions. Do not convert their acknowledged uncertainty into claims of completed compatibility or settled policy. The DMARC standards transition also warrants testing the [current DNS tree-walk](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10) and stale-PSL implementations before making a universal burner-isolation claim; §14.15 L5584 already recognizes stale receiver behavior.

## Implementation, freeze and launch priorities

**Before M0 pins and G0 approval:** fix F15's canonical module identity; assign missing feature owners; record decisions that block M0–M2. Preserve global Git author identity and branch/pin rules. Convert contradictory guarantees into concrete contracts rather than leaving implementation teams to choose different interpretations.

**Before the M2 authority/MLS/storage freeze:** resolve F03–F12 and F16–F19, including recovery/depositor scopes, complete effective-state commitments, erasure dependencies, GC/publication interlocks, Git semantics, path-map composition and deletion incarnations. Decide C03's recoverable-mirror key coverage and the optional Q-ACL-9 consequences. Include GC, uncertain responses, gate transitions and old jobs as actors in the model/history suite; a proof of head CAS alone does not cover them.

The freeze sequence itself needs correction. §22.10 L7773 requires S1/S3a/S4a, model/history checks, fuzzing and twenty agents for the M2 formats, while §23.8 L7934 calls this an **entry** freeze and M2 L7886 assigns the corresponding implementation work. Name a pre-entry executable prototype phase, or separate entry specification approval from an implementation-qualified final freeze at exit. Do not claim unrun implementation evidence at an entry gate. RECORD.md review remains required at the specified storage/record boundary.

**Before M3's concurrent-agent promise:** resolve F14, F24 and sticky run-taint recovery. Test actual harness callbacks and negotiated MCP results. Ensure the P0 credential-stage gates precede the pilot exactly as specified; concurrent scan throughput is not a substitute for ownership-safe restore.

**Before M4/RS1's bridge and page Worker:** resolve F01/F02 and browser capability semantics C01. Test keyless bootstrap with a sleeping/disconnected sidecar and operator-controlled transport claims. Separate the M4 page Worker from later extension-worker work: L6728/L7888 ship the page, while L7848 puts “the browser worker” later and L7766 emphasizes extension paths. Real-page CORS, WebCrypto, IndexedDB recovery, admission and vault reads must gate the page release; Node-only wasm checks do not exercise them. Keep the surrogate iOS budget gate as agreed.

**Before M5 TLS exposure and custom-domain launch:** close C02, F20, and then F13 before the M6 custom-domain promise. Test the complete external-name→LB→sidecar path with actual CAA delegation and all accepted audience/protocol combinations.

**Before M6 billing/team launch:** settle C04's meter mode and uncertain-send handling; use crash-safe usage producers or disclose the precise loss bound. Test authority thresholds/recovery through actual service handlers, not fixtures that assume admission. Preserve the separate escrow review and deterministic ordering gates.

**Before M7–M9 mail claims:** correct F21, decide C05's MTA-STS coverage, distinguish factual validation labels from cryptographic path proof, and reconcile hold kinds and raw-report intake disclosures. Retain receive-only launch until the complete proof statement, TLS-record/message binding, negative vectors, internal soundness arguments and census-driven coverage decisions pass. No external review is added to the owner's gate.

## Verification record and completion criteria

The Go parser fixture above establishes F15's module-version mismatch independently of sibling replacement behavior. Other findings are protocol/state-machine consequences and proposed schedules; no sidecar acceptance suite, load benchmark, ZK circuit, recovery drill or launch audit is represented as completed.

Implementation changes should each carry a deterministic regression for their root cause, in accordance with the user's rule. Prefer barriers, injected clocks, real negotiated schemas, real authorization handlers and isolated fake adversaries to sleeps or broad happy-path suites. A positive control should accompany each refusal test so fail-closed implementations cannot “pass” by disabling the feature.

Before approval, each P1 needs a concrete amended protocol and its acceptance schedule assigned to the affected gate. Each P2 needs either the contract correction or an explicit revised guarantee. Conditional concerns need an unambiguous choice, with resulting metadata/invariant changes propagated through §2.8, wire interfaces and host adapters. Existing open questions and accepted risks should remain visible as such.

The reviewed design's SHA-256 was unchanged at consolidation. The review target was absent before creation; no unrelated existing review content was replaced.

