# Design details

Detailed designs for the hard algorithmic problems that remained in DESIGN.md on 2026-11-09. Each problem's brief is in `.stack/design-problems.md`. The owner directed a fifth agent, on Fable at max effort, to work them out here, and directed that implementation in each problem's area wait until its section is complete.

Where a complete section and DESIGN.md differ, the section governs the tasks it names, until a design-records track folds it into `design/source/`. Each section ends with its proposed DESIGN.md text and its owner questions.

Status values: `pending`, `in progress`, `complete (date)`, or `complete pending owner question <file>` (built on the stated recommendation).

| # | Problem | Tasks held | Status |
|---|---|---|---|
| 1 | Search index merges, roll-ups and the journal (§11.14) | 7 | pending |
| 2 | Storage consistency under stalled writes: segment GC and the MinIO settle rules (§11.13, §19.6) | 4 | pending |
| 3 | Zero-knowledge proofs of TLS delivery for outbound mail (smtpproof; §14.5) | 5 | pending |
| 4 | Forwarding in the apps' VPN component: key, verification and size (owner decision 197) | 40 | pending |
| 5 | Authorization-log verdicts across folds (§7.9) | 13 | complete (2026-11-09) |
| 6 | MLS group key management (§10) | 13 | in progress |
| 7 | Remote search across designated indexers (§11.14, §18.4) | 3 | pending |
| 8 | Git and evs in both directions | 3 | pending |
| 9 | Client path epochs and re-tokenizing | 3 | pending |
| 10 | DROP lists a phone can check (§11.6, §11.7, §11.9) | 5 | pending |
| 11 | Canonical text extraction and exact body sizes for search | 2 | pending |
| 12 | Bridge compiler and NAT engine (§17) | 4 | pending |
| 13 | Smaller scheduling problems: closure pacing, quota leases, socket registration | 4 | pending |

## 1. Search index merges, roll-ups and the journal (§11.14)

Status: pending

Tasks held until complete: SEARCH-M10-10, SEARCH-M10-11, SEARCH-M10-13, SEARCH-M10-14, SEARCH-M10-15, SEARCH-M10-35, TEST-M10-02.

## 2. Storage consistency under stalled writes: segment GC and the MinIO settle rules (§11.13, §19.6)

Status: pending

Tasks held until complete: EVSB-M10-01, EVSB-M10-02, EVSB-M2-12, EVSB-M2-17.

## 3. Zero-knowledge proofs of TLS delivery for outbound mail (smtpproof; §14.5)

Status: pending

Tasks held until complete: SMTP-M9-07, SMTP-M9-08, SMTP-M9-09, SMTP-M9-13, SMTP-M9-32.

## 4. Forwarding in the apps' VPN component: key, verification and size (owner decision 197)

Status: pending

Tasks held until complete: BRIDGE-M2-01, BRIDGE-M4-15, BRIDGE-M4-18, BRIDGE-M4-19, BRIDGE-M4-20, BRIDGE-M4-22, BRIDGE-M6-05, BRIDGE-M6-06, BRIDGE-M6-07, BRIDGE-M6-08, BRIDGE-M8-01, BRIDGE-M8-02, BRIDGE-M8-03, SDK-M10-01, SDK-M10-02, SDK-M10-03, SDK-M10-04, SDK-M10-05, SDK-M10-06, SDK-M3-01, SDK-M4-04, SDK-M4-05, SDK-M4-06, SDK-M4-08, SDK-M4-09, SDK-M6-02, SDK-M6-03, SDK-M8-01, SDK-M8-02, SDK-M8-03, SDK-M8-04, SDK-M8-05, SDK-M8-06, SDK-M8-07, SDK-M8-08, SDK-M8-10, SDK-M8-12, SDK-M8-14, SDK-M8-15, SDK-M9-01.

## 5. Authorization-log verdicts across folds (§7.9)

Status: complete (2026-11-09)

Tasks held until complete: CORE-M3-02, CORE-M3-03, TEAM-M10-01, TEAM-M2-04, TEAM-M2-05, TEAM-M2-06, TEAM-M2-07, TEAM-M2-09, TEAM-M2-10, TEAM-M2-17, TEAM-M2-18, TEAM-M2-19, TEAM-M3-02.

Model: `sidecar/sidecartest/model/details/AuthLog.tla`, its configurations and `run.sh` beside it. Questions filed: `.stack/questions/details-5-settings-in-rows.md`, `.stack/questions/details-5-base-records-in-folds.md`.

### 5.1 The problem

§7.9 defines one state per log position, S(n): the newest base b at or below n gives rows that compile its config head, which holds every statement and tick up to b's `folded_through` (m below); the statements and ticks among m+1..b-1 (the *tail*) re-apply on those rows; then the entries b+1..n apply in order. A statement's *verdict* is judged once, at its own position, against S(n-1), and the BASE row has the tail "keeping the verdict it got at its own position". Three kinds of verifier read the same log: a long-running reader (a device present since the bootstrap base, which judged every entry itself), a new device (one that starts at the newest base, holding rows, the entries from api's retention point r = min(the previous base, m+1), and no state before b), and a rows-only verifier (api, evs, gkm and the other gates, which hold no config key and never open a head). D-TEAM-19 and D-TEAM-20 require that they all hold one S(n) and one verdict per entry ("equal pins give equal verdicts"), because the gates decide reads and writes from S(n) and devices decide keys, commits and alarms from it.

Four places break that today, and the three the brief names are the first three.

**Tail verdicts at a new device (question team-m2-02-new-device-tail-verdicts).** A long-running reader judged a tail statement at position k, m < k < b, against S(k-1), whose head-derived parts (policy, tag owners, ServiceSettings) came from the base current at k-1, and whose retention point was that state's. A new device holds only b's rows, which compile b's head, so it judges the same statement under b's head and under its own first held position. Two concrete runs, with positions:

1. Entry 1: admin device A (member M1, who owns tag `t` in the policy) admits agent D with tag `t`; accepted. Entry 2: a base with `folded_through` 0 whose config head moves `t`'s ownership to M3. A long-running reader keeps entry 1 accepted and D admitted. A new device starting at base 2 judges entry 1 on base 2's rows, where M1 owns no tag: refused, D never admitted. The same shape arises from a `self_admit` edit at the base and a member's self-admission in the tail.
2. Entry 1: a statement signed at pin 0, when the log held no base, so its `at` is 0; accepted at retention point 0. Entry 2: base b1 with `folded_through` 0 (retention point 1). Entry 3: base b2 with the same `folded_through` (retention point min(b1, 1) = 1). A new device at b2 holds entries from 1 on and A_k from 0 on, so it can check entry 1's `at` is on its chain, but the replay row says `at` must not be before "the retention point of the state it lands on", which the new device takes as its own first held position, 1: refused. The long-running reader accepted it. The landed `configTailRetentionPoint` makes exactly this choice.

In both runs the two readers then disagree on every later state, with no FORK: each chains the same A_n.

**Open proposals across a base (question team-m2-02-open-proposals-across-bases).** An AuthorityProposal stays open until its k-th counted cosign or, with a recovery signature, until an ApiTick 72 h after its newest such signature. A writer folds every 1,024 entries or 24 h, so every recovery window and any proposal whose cosigners take a day is folded under a base before it completes. ProjectionRows has no field for an open proposal. §7.9 as written leaves a long-running reader carrying the proposal in its own state and a new device starting without it: entry 1 proposes (k = 2), entry 2 is a base folding through 1, entry 3 cosigns; the long-running reader completes the admission, the new device refuses the cosign as naming no open proposal. The landed `stateFromBase` closes every proposal at a base on every reader instead, which keeps them equal and breaks every recovery window and every slow k-of-n proposal (`TestAProposalABaseFoldsCloses`).

**Self-admission at rows-only verifiers (question team-m2-02-self-admit-at-rows-only-readers).** The scoped row admits a member's untagged device on its consented device's signature "only while self_admit is on", and `self_admit` rides config heads only (plan-TEAM-config-head-format #2). api verifies every statement against S(tip) before it appends one, and api never opens a head (plan-TEAM-api-config-head-reach), so api cannot judge the one statement every personal network's second device needs. The landed code fails closed (`ErrConfigSettingsUnknown`), which means api answers 403 to every self-admission while every device would accept it: the split D-TEAM-19 exists to prevent, at the most common admission there is.

**The replay ring at a new device, found while modelling.** A statement is refused when its id is among the last 4,096 entries' applied ids. A new device holds no verdict for entries the base folded, and the landed `restore` takes every folded statement as applied for the ring. A vetoed recovery proposal, replayed verbatim after a fold, is refused by a long-running reader and accepted by a new device whose rows hold no record of it (the closed proposal left the state, and the id left the ring), so the vetoed window runs again, the hole protos-bridge-statement-id-wrapper's table names. The converse also diverges: a refused statement resubmitted verbatim once its reason has passed.

Two smaller gaps sit beside these. `SidecarRow` keeps only the newest AdmissionConfirm and OwnerConfirm, while the cascade's "a confirmation of a device then unparked and consented on other signatures adding none" and "whose consent rests only on such a sidecar's OwnerConfirm" need every confirmation with its signer and position, so a rows-only verifier computes a different P from a device that kept the entries (ACL-M2-03's note). And a new device's head check has no state to compile against: `CheckConfigBase` refuses a check with no `Previous`, so the anchor a new full device runs on its first base is unbuilt.

The requirement: every verifier reaches the same verdict on every statement and the same S(n) at every position it stands at, whatever base it started from and whatever it can open; a verifier that cannot reach that state forks visibly rather than diverging silently; and the log stays safe through the compromise cascade, recovery, folding and site-loss resumption.

### 5.2 The design

#### 5.2.1 The principle

**A verdict is judged once, at the entry's position, by the verifiers present there, and every later verifier takes it from the next base.** A base carries the verdict of every entry in its tail; its rows carry a complete state at `folded_through` for a verifier that holds nothing else, open proposals, the replay ring, the id-level settings and every confirmation included; no verifier ever re-judges a tail, and every verifier re-applies a tail by its verdicts. A long-running reader checks the base's verdicts against its own and forks on a difference, so a writer cannot split the readers: it can only fork itself off. This keeps §7.9's BASE row ("each keeping the verdict it got at its own position, so a later authority change never undoes an earlier revocation, while effects that depend on rows follow the new rows") and makes it computable from a base alone.

Every change below is additive to the wire, which owner decision 194 leaves unfrozen until M2's Gn-in, and is a format change, so each needs its §2.8 line (I-18) where a server reads it; 5.8 gives the lines.

#### 5.2.2 What a base and its rows carry

```proto
// sidecar/protocol/bridge/auth.proto, additions; numbers follow the order written
message ProjectionHeader {
  // fields 1-9 as today
  bytes  tail_verdicts = 10;         // 2 bits per entry among folded_through+1..version-1, in position order:
                                     //   entry folded_through+1+j is bits 2j and 2j+1 of byte j/4, bit 0 the
                                     //   byte's least significant; 0 refused or a BASE, 1 took effect, 2 took
                                     //   effect and completed a proposal (an AuthorityProposal at k = 1 or the
                                     //   k-th AuthorityCosign only), 3 never; exactly ceil(2*(version-1-
                                     //   folded_through)/8) bytes, padding bits 0; empty when nothing is unfolded
}
message ProjectionRows {
  // fields 1-5 as today; 6 reserved for TeamScopeRow at M6 (protos-bridge-row-fields #3)
  repeated ProposalRow proposals = 7;    // every proposal open at folded_through, by proposal_id
  ProjectionSettings settings = 8;       // the ServiceSettings values a verifier judges by
  repeated RingRow ring = 9;             // the statements that took effect among the 4,096 entries through
                                         //   folded_through, in position order (the replay row)
}
message ProposalRow {
  bytes  proposal_id = 1;                // 32 B
  uint32 statement_type = 2;             // the proposed statement's SignedType
  bytes  statement = 3;                  // AuthorityProposal.statement, verbatim
  uint64 proposed_at = 4;                // o: the AuthorityProposal's entry
  int64  not_after_ms = 5;               // the proposal's own header's
  repeated ProposalSigner signers = 6;   // the proposer, then each counted cosign, in log order
  uint64 window_entry = 7;               // p: the entry of the newest recovery-key signature; 0 with none
  int64  window_time_ms = 8;             // T_p: that entry's time_ms
  uint32 kind = 9;                       // ProposalKind, fixed at the proposal's entry
}
message ProposalSigner {
  bytes  signer = 1;                     // as rows name one: a sidecar_id or a recovery key's hash
  uint64 at = 2;                         // the entry that carried its proposal or cosign
}
enum ProposalKind {
  PROPOSAL_KIND_UNSPECIFIED = 0;
  PROPOSAL_KIND_AUTHORITY = 1;           // k of n (7.9's several row)
  PROPOSAL_KIND_RECOVERY_SCOPED = 2;     // a scoped recovery admission filed with self_admit off: completes on one
                                         //   cosign by an admission signer (7.9's self_admit row)
  PROPOSAL_KIND_RESTORED = 3;            // a restored binding's scoped admission: activates at the window with no
                                         //   counted cosign (owner decision 149)
}
message ProjectionSettings {
  uint32 self_admit = 1;                 // SelfAdmitMode's value: 0 unset (on), 1 on, 2 off (owner decision 112)
  bytes  scim_signer = 2;                // ServiceSettings.scim_signer (7.6), empty for none
}
message RingRow {
  bytes  statement_id = 1;               // the first 16 B of the statement's id (RetainedStatementId)
  uint64 n = 2;                          // the entry that carried it
}
message SidecarRow {
  // fields 1-20 as today; 5-8 stay the newest AdmissionConfirm and OwnerConfirm
  repeated ConfirmationRow confirmations = 21;   // every one that took effect, in position order
}
message ConfirmationRow {
  uint32 kind = 1;                       // 1 AdmissionConfirm, 2 OwnerConfirm
  bytes  signer = 2;                     // the confirm_signer or owner_confirm_signer it set
  uint64 at = 3;                         // its entry
  bool   lifted_park = 4;                // the device was parked when it landed (7.9's lift row)
}
```

```proto
// sidecar/protocol/config.proto: ConfigRecord.kind gains 1 (BASE), its body the Signed ProjectionHeader, so a fold
// holds every entry in (after, folded_through] and a reader recomputes A_k from the genesis through the head alone
```

Encoding and order, which every compiler on every leg must give alike, since `rows_sha256` hashes them: `proposals` sorted by `proposal_id` bytes; `signers` in log order; `ring` in `n` order; `confirmations` in `at` order; `settings` always present, its zero value meaning the defaults; `tail_verdicts` as the comment says, little-endian within a byte, two bits per entry, so a tail of 1,024 entries is 256 B and the cap below bounds it at 1 KiB.

**Compile.** `compile(head, L)` takes the head and L, the *log-derived rows at folded_through*: members, sidecars (confirmations included), Delegations, registered keys, the open proposals, the ring and AclRows' statement-derived rows, exactly `ConfigCompileRows` plus proposals and ring. It writes `settings` from the head's `ServiceSettings` (absent: the zero value), `proposals` from L's open ones, `ring` from L's, and the acl part as ACL's `CompileAcl` does. A proposal is *open at ft* when it took effect, has not completed, been vetoed or voided, and its `not_after_ms` is not below the entry time at ft, T_ft (never a clock; with BASE records in folds every position has a time). A ring entry is kept when its `n` is above ft - 4,096.

L is defined by one recurrence so that the writer and every reader compute it from what they retain. With b' the previous base, ft' its fold and R_b'(k) the state rebuilt from b''s rows by re-applying the entries ft'+1..k by their verdicts (BASEs skipped): L(ft) = LogPart(R_b'(ft)). Since the entries b'+1.. apply by the same re-application rule, R_b'(k) = S(k) for k >= b', so a reader uses `StateAt(ft)` when ft >= b' and b''s retained rows when ft = ft'. Those are the only two cases, by the next rule.

#### 5.2.3 The rules

**folded_through.** A base's `folded_through` is either the previous base's or at least the previous base's position: ft = ft' or ft >= b'. api answers 403 to any other value; a reader forks on it. (A writer never folds part of a previous base's tail: it folds through the tip, or keeps the fold where it was for a policy-only base.)

**Tail cap.** version - 1 - folded_through <= 4,096 (`configTailMax`, a protocol constant beside the 4,096 of the replay row). api answers 403 above it; a reader forks on it. A writer that finds the tail longer, after an outage, folds through the tip first; §7.9's fold row (1,024 entries or 24 h) stays the soft trigger. This bounds every verifier's re-application, the header's bitmap and {acl_}e's needs.

**The base's verdicts.** The writer fills `tail_verdicts` from the verdicts it holds for ft+1..n-1: its own where it judged, the previous base's bits where it took them. Every verifier that holds a verdict for a tail position compares: a differing bit, a 2 on an entry that is no AuthorityProposal or AuthorityCosign, a 3, or a wrong length is a FORK naming the position (the writer lied, or diverged). A verifier that holds none takes the bits.

**Re-application** (`Reapply(state, entry, verdict)`): for each tail entry with verdict 1 or 2, parse the body and apply its effect on the state being built; never verify a signature, a header, a signer's standing or a type rule. An AuthorityProposal with verdict 2 applies the proposed statement with signers [proposer]; with 1 it opens a ProposalRow. An AuthorityCosign with 2 applies the proposed statement with the row's signers plus the cosigner and closes the row; with 1 it appends the cosigner. A TICK applies its reaps and each activation, closing the row and applying its statement with the row's signers. Every other statement applies its effect as its type's `apply` says, an acl effect dropped where the new rows no longer allow it (ACL's `ReapplyStatement`, plan-ACL-folded-grant-state #2). An effect reads only the statement's body and the log-derived state being built, never what the check found on a head at the entry's own position: the row signer, `lifted_park`, `live_since`, `key_dropped_at` and `holders_shrunk_at` are recomputed on the rebuilt state, which every verifier holds alike. The verdict and the completion are never recomputed: they come from the entry's own judgment, or the bits.

**Open proposals.** Rows carry every open proposal; the tail re-opens, advances, completes, vetoes or voids them as its verdicts say; after the base, cosigns, vetoes, rebinds, AdminSet changes, removals and ticks find them in S(n) at every verifier alike. The window's activation reads `window_time_ms` from the row, so T_p is known where the entry p is below the retention point. `kind` is fixed when the proposal takes effect, from the signer's kind, whether the member is in the AdminSet, whether the binding is one a void restored, and `self_admit` then, so the activation rule needs none of those at the tick. Voiding, vetoing and completion delete nothing: the row closes with the position and reason, `OpenProposalIds` filters, and compile drops closed and expired rows.

**Self-admission at rows-only verifiers.** `ProjectionSettings.self_admit` is what every verifier judges the scoped row by; `ConfigState.Settings()` loses `known`, and the head's other values (`team_mail`, `stale_leaf_days`, `witness_bound_hours`, `directory`) stay head-only, read by devices alone. `scim_signer` rides beside it, since the MemberRevoke an admin's indexer signs under 7.6 is judged at api too (M6). A full reader checks `settings` against the head at compile; a rows-only verifier takes it.

**The ring.** `ProjectionRows.ring` holds the ids that took effect among the 4,096 entries through ft; a verifier's ring at n is that, plus the tail's entries with verdict 1 or 2, plus what it judged since, trimmed to the 4,096 before n. The replay row's "before the retention point" clause is what makes this exact without the ring reaching further: a statement applied at m0 carries at <= m0 - 1, so a copy landing after the retention point has passed m0 fails the `at` rule before the ring is asked. The ring is therefore the same set at every verifier for every position it is asked at.

**Confirmations.** `SidecarRow.confirmations` keeps every AdmissionConfirm and OwnerConfirm that took effect, with its signer, entry and whether it lifted a park, for the sidecar's life; fields 5-8 stay the newest of each. The cascade reads the history: "whose park such a sidecar's AdmissionConfirm lifted" is a confirmation with `lifted_park` by a signer then in P from since_n on; "a confirmation of a device then unparked and consented on other signatures adding none" is one with `lifted_park` false whose device's consent (§8.5) also rests on a signature outside P; "whose consent rests only on such a sidecar's OwnerConfirm" is a device every consent basis of which, admission signers, invite, genesis and confirmations alike, lies in P or in a key of a binding P voids. P is a pure function of rows, so api, evs, gkm, a new device and a long-running reader build it alike.

**BASE records in folds.** A fold's `ConfigRecord`s include the BASE entries in (after, ft], kind 1, body the Signed ProjectionHeader, so the head holds every entry's body and a reader holding the genesis recomputes A_1..A_ft from the head alone (A_n = SHA-256(... u64be(n) || A_{n-1} || u32be(kind) || i64be(time_ms) || SHA-256(body))). Compile ignores them; the head check compares them like any record. This closes the far-behind reader's gap (5.5) and gives the new device's anchor a chain it can verify to its first retained entry.

**Owner decision 197's forwarding key.** No proposal file exists yet (`.stack/plan/proposals/od-197-forwarding.md` is unwritten). Whatever statements the design-od197 track gives the forwarding key, the rules above hold for them unchanged if they are ordinary log statements: a `StatementHeader`, a rule in the rule table judged once at the entry's position, a verdict carried in `tail_verdicts`, and a fold into a row that keeps the signer and the carrying position. The natural fit is `KeyRegister` and `KeyRevoke` with a new `KEY_PURPOSE_FORWARDING = 3`, the key's `member_id` its device's member and its `signer` the device's sidecar or its member's consented device, folded to `KeyRow` as presence keys are; then the cascade voids a forwarding key a sidecar in P registered exactly as it voids a presence key, a rows-only verifier (the VPN component itself may be one, since it needs no config key to verify the log) judges its registration by `KeyRow`, and nothing else in this section changes. If the track makes the key a Delegation instead, `DelegationRow` already carries what this section needs.

#### 5.2.4 Algorithms

Notation: `S` a `ConfigState`; `S.rows` its log-derived rows; `V[k]` the verdict held for position k (0, 1, 2); `held` the first position a verifier holds an entry at; `r(b)` the retention point a base sets, min(b', ft+1), or ft+1 for the first base after bootstrap.

```text
Judge(S, entry e at n)                          -- unchanged: §7.9's statement row at S(n-1)
  parse Signed; verify under the signer S names; replay rules at r(S) (at on S's chain, within 4,096,
  not before r(S), unexpired, id not in Ring(S, n)); read_only; presence; the type's rule
  -> 0 refused | 1 effect | 2 effect and completes a proposal

Reapply(S, e at k, v)                            -- never judges
  if v = 0 or e is a BASE: return S
  parse body (no signature check)
  case AuthorityProposal:  if v = 2: apply(proposed, signers=[proposer]) else open ProposalRow(kind fixed now)
  case AuthorityCosign:    row := S.proposals[pid]; if v = 2: apply(row.statement, row.signers + cosigner); close row
                           else row.signers += cosigner
  case TICK:               revoke each reaped id; for each activated pid: close row; apply(row.statement, row.signers)
  otherwise:               rule.apply(S, e) on the rebuilt state (ACL: ReapplyStatement)
  S.ring += (id16(e), k); return S

ApplyBase(V, base e at n)                        -- a verifier already standing at S(n-1)
  h := parse Signed ProjectionHeader
  require h.version = n, h.prev_chain = S.A, signer is a config writer at S, signature verifies  else FORK
  require h.config_version >= prev.config_version, h.folded_through >= prev.folded_through        else FORK
  require h.folded_through = prev.folded_through or h.folded_through >= prev.base                 else FORK
  require n - 1 - h.folded_through <= 4096                                                        else FORK
  rows := fetch(projrows/h.rows_sha256); require sha256(rows) = h.rows_sha256, len = h.rows_byte_count <= 4 MiB
  bits := decode(h.tail_verdicts, n - 1 - h.folded_through)            -- length and padding exact, no 3 else FORK
  for k in ft+1..n-1:
      if e_k is a BASE: require bits[k] = 0                                                       else FORK
      else if V holds V[k]: require bits[k] = V[k]                                                else FORK
      require bits[k] = 2 only on an AuthorityProposal or AuthorityCosign                         else FORK
  if V is a full reader:
      L := LogPart(ft = prev.folded_through ? prev.rows : StateAt(ft))
      require CheckHead(head(h.config_head_sha256), prev, L, rows): genesis, descent, records (BASEs included),
              settings signer, compile(head, L) = rows                                            else FORK
  S' := Load(rows); S'.base := h; S'.previousBase := prev.base; S'.retentionPoint := r
  for k in ft+1..n-1: S' := Reapply(S', e_k, bits[k])
  V[k] := bits[k] for every tail k V did not judge
  retain(S', rows); publish S'

StartAtBase(V, b)                                -- a new device, a cold gate, or a reader that fell behind
  fetch entry 0 (the Signed Genesis; A_0 must equal the invite's or the bundle's), entries r(b)..tip, rows(b)
  chain A_k forward from entry r(b)'s prev_chain; every link must hold                           else FORK
  h := parse base b; require sha256(rows) = h.rows_sha256 and h's signer is a config writer in rows(b)
          whose identity key in rows(b) verifies h's signature; tail cap; ft rule against the previous base if held
  if V is a full reader (anchor):
      head := open(h.config_head_sha256); require head.genesis = A_0; head on the config repo's chain from
              genesis (evs; config_pushes at api); head's fold records equal every held entry in [r(b), ft];
              recompute A_1..A_{r(b)-1} from the genesis through the head's records, BASEs included, and require
              the result to equal entry r(b)'s prev_chain                                         else head_alarm
      settings in rows equal the head's ServiceSettings
  S := Load(rows(b)); S.base := h; bits := decode(h.tail_verdicts)
  for k in ft+1..b-1: S := Reapply(S, e_k, bits[k]); V[k] := bits[k]
  ring := rows.ring + {applied tail ids}; retentionPoint := r(b); held := r(b)
  for k in b+1..tip: Apply(e_k) as a long-running reader (Judge, then effect)

WriterPublishBase(W, head)                       -- a config writer at S(tip), TEAM-M2-09
  ft := tip if folding, else prev.folded_through; require tip - ft <= 4096 (else fold through tip first)
  L := LogPart(ft = prev.folded_through ? prev.rows : StateAt(ft))
  rows := compile(head, L)                       -- settings, proposals open at ft, ring through ft, acl
  bits[k] := V[k] for k in ft+1..tip (0 at a BASE); h := ProjectionHeader{version tip+1, prev_chain A_tip,
      folded_through ft, config_version, config_head_sha256, rows_sha256, rows_byte_count, threshold, tail_verdicts}
  POST /network/config/projection {Signed h, rows, config_pushes}; on 409 re-sign at the new tip (re-compile only
      if the head or the fold moved), extending bits with the new tail's verdicts

ApiAcceptBase(e)                                 -- api, a rows-only verifier at S(tip), TEAM-M2-13
  as ApplyBase without the head check, every FORK a 403 {tip, A_tip} with the reason; then PUT projrows, the entry
```

The equal-verdict argument, in short: a verifier judges an entry only at a state every verifier present holds (S(n-1), by induction from the previous base), so present verifiers agree; a verifier not present takes the bits, which the present verifiers checked, so it agrees with them or they forked; rows at ft equal LogPart(S(ft)) by the full readers' compile check, with every rows-only input a verifier judges by (settings, proposals, ring, confirmations) inside them; and the ring needs no position below the retention point, by the `at` rule. 5.3 states the invariants and checks them.

### 5.3 Invariants and why they hold

```text
Agreement        every verifier that stands on the log, not forked, holds the same state at each position n at or
                 past the base it started at, and the same verdict for each entry both hold a verdict for
                 why: a verdict is judged once, at S(n-1), which present verifiers share by induction; absent ones
                 take the base's bits, which present ones compared; rows carry every rows-only input (5.2.3)
RevocationsStand a revocation that took effect is in effect at every later state
                 why: no verifier re-judges a tail; a base re-applies by verdict, and a revocation's effect depends
                 on no head-derived row
CascadeClosed    a compromise revocation of x from since_n parks every sidecar the design's closure holds, each
                 record counting from its carrying entry, however its signer dated its at
                 why: P is a function of rows (admission signers and positions, every confirmation, bindings,
                 Delegations), the carrying position is api's, and the statement's at is the signer's claim
DelegationEnds   no admission a Delegation's key signs takes effect after the Delegation ended
                 why: DelegationRow.ended_at is in rows and the tail advances it by verdict
ProposalsNeedK   a proposal completes only with k distinct counted members at the completing entry's state
                 why: ProposalRow keeps each signer; completion is judged once, at that entry, and carried as 2
WindowHolds      a recovery proposal activates only at a tick at or after T_p + 72 h with no valid veto between
                 its entry and the tick
                 why: window_entry and window_time_ms are in the row; a veto closes the row at its position
TailBounded      no base leaves more than 4,096 entries unfolded
LiesAreForks     a base whose bits disagree with a present verifier's verdict forks that verifier
ProposalsSurviveFolds
                 a counted member's cosign of a proposal the log itself shows open takes effect, however many bases
                 lie between the proposal and the cosign
```

**The model.** `sidecartest/model/details/AuthLog.tla` keeps the log as its one shared object and three verifiers as variables derived from it: `L`, the long-running full reader and writer; `N[b]`, a new full device started at each base b; and `G`, the rows-only gate cold-started at the newest base, which is what api sequences by. It models admissions with signers, carrying position, the signer's `at`, confirmations, parks and revocations; one Delegation with `max_admits`; recovery bindings, recovery-signed proposals, the 72 h window, vetoes and ticks; AuthorityProposals and cosigns at threshold K; the compromise cascade with consent (§8.5), voids of bindings and Delegations and the parks a Delegation's end makes; the replay ring and the `at` rule with the retention point; and bases with `folded_through`, head-derived rows (`self_admit`, a tag's owner), tail verdict bits and, under `LyingWriter`, a lie; under `Adversary` api sequences refused statements too. It leaves out presence countersignatures, read_only, `not_after` expiries, EvsShares, key registrations, leaf ranks, the head's own chain and api's reap ticks. The clock is the position. `Twin` selects a rule to break: `JudgeTail`, `NoProposalRows` and `NoSettingsRows` are §7.9 as written on 2026-11-09 and `CloseAtBase` the landed code; `ReJudgeTail` (the question's option 2), `NoRingRows`, `CascadeFromAt`, `NoBitsCheck` and `NoTailCap` each break one rule of this design. `Story` fixes a twin's entries so TLC reaches its violation directly; the design runs with none. `run.sh <track>` runs every configuration through `.stack/tools/tlc` and prints a verdict line per run.

Runs, TLC at the owner's jar (master d8fb231), bounded so each finishes; breadth-first over every reachable state at the bounds, but for the deepest design run, which samples:

```text
configuration            Twin           K  bounds (Window 4, TailMax 4, RecoveryWindow 2, Life 5, MaxAdmits 2)
                                           result                                   distinct states  depth  time
AuthLog                  none           2  MaxN 4, MaxBases 2, no story, no adversary
                                           pass, every invariant                      1,725,243      5      1 min 44 s
AuthLog-K1               none           1  the same at k = 1
                                           pass, every invariant                      4,061,811      5      6 min 22 s
AuthLog-Adversary        none           2  MaxN 4, MaxBases 2, LyingWriter: a writer may publish a base with a false
                                           verdict (every honest base has a lying twin beside it)
                                           pass, every invariant                      2,494,475      5      7 min 18 s
AuthLog-Narrow           none           2  MaxN 5, MaxBases 2, Narrow: one at and one since_n a statement; by random
                                           simulation, 200,000 traces of up to 7 steps from seed 1, since its complete
                                           graph passes 20 million states
                                           pass, every invariant on those traces   436,846,285 generated  6  1 h 46 min
Twin-JudgeTail-Head      JudgeTail      2  StoryTailHead, MaxN 2      Agreement violated, 3-state trace    3    3
Twin-JudgeTail-At        JudgeTail      2  StoryTailAt, MaxN 3        Agreement violated, 3-state trace    3    3
Twin-NoProposalRows      NoProposalRows 2  StoryProposals, MaxN 3     Agreement violated, 3-state trace    3    3
Twin-NoSettingsRows      NoSettingsRows 2  StorySettings, MaxN 3      Agreement violated, 4-state trace   11    4
Twin-NoRingRows          NoRingRows     2  StoryRing, MaxN 6          Agreement violated, 7-state trace   75    7
Twin-ReJudgeTail         ReJudgeTail    2  StoryReJudge, MaxN 3       RevocationsStand violated, 4 states  4    4
Twin-CascadeFromAt       CascadeFromAt  1  StoryCascadeAt, MaxN 2     CascadeClosed violated, 3 states     3    3
Twin-NoBitsCheck         NoBitsCheck    2  StoryLie, MaxN 2, LyingWriter Agreement violated, 3 states       3    3
Twin-NoBitsCheck-Forks   NoBitsCheck    2  the same                   LiesAreForks violated, 3 states      3    3
Twin-CloseAtBase         CloseAtBase    2  StoryClose, MaxN 3, Adversary ProposalsSurviveFolds violated   12    4
Twin-NoTailCap           NoTailCap      2  StoryTailCap, MaxN 3, TailMax 1 TailBounded violated, 4 states  6    4
```

Each twin run took under 5 s; a twin's distinct-state count is what TLC had explored when its workers met the violation, so it varies a little between runs (NoRingRows 59 to 75, CloseAtBase 12 to 14) while the trace does not. A depth counts TLC's initial state, so a 3-state trace is two entries. The three breadth-first design runs explore every log the candidate alphabet allows at their depth (about 37 enabled entries a position at MaxN 4); a run one entry deeper multiplies the states by that, so the narrowed depth-5 run, whose complete graph passed 20 million states without finishing in two hours, runs instead by TLC's random simulation, which proves only that the behaviors it drew kept every invariant. Its seed and trace count are fixed in `run.sh`, so the run repeats.

The three divergences appear in the model of §7.9 as written and are gone in the design: `Twin-JudgeTail-Head` and `Twin-JudgeTail-At` violate Agreement at the base (a new device's tail verdict differs from the long-running reader's on a tag owner moved by the head, and on an `at` below the new device's first held position); `Twin-NoProposalRows` at the cosign after the fold; `Twin-NoSettingsRows` at the self-admission the gate refuses; `Twin-NoRingRows` at the vetoed recovery proposal's replay. The design's runs hold every invariant at the same and larger bounds, with Agreement comparing every new device and the gate against the long-running reader at every state.

### 5.4 Cost

Against §8.8's 4 MiB rows, §6.5's 64 KiB `HeadCheckProof` (bases inside it as headers), §18.4's phone budgets and the append limits, which do not change:

```text
header       tail_verdicts: ceil(tail/4) B; 256 B at the 1,024-entry fold trigger, 1 KiB at the 4,096 cap; a proof's
             64 KiB holds about 60 such headers at the cap beside their entries
rows         ProposalRow: about 100 B plus the proposed body (a SidecarAdmit about 150 B, an AdminSet 16 B a
             member) plus 20-40 B a signer; open proposals are few, bounded by their 7-day not_after: under 10 KiB
             RingRow: about 22 B; at most 4,096, so at most 90 KiB; a network at 100 statements a day holds about
             2 KiB, a Team at its 20,000-a-day limit the full 90 KiB
             ConfirmationRow: about 30 B; most devices hold none or one; 5,000 devices at three each, 450 KiB
             ProjectionSettings: under 20 B
             so rows for a 5,000-admission Team grow from about 1.3 MB (protos-bridge-row-fields' 250 B a sidecar)
             toward 1.9 MB at the worst of every column, inside 4 MiB; a personal network's rows stay under 10 KiB
time         re-application on a phone: no signature check, one parse and one effect an entry, 10-30 us each on a
             2020 phone core: under 30 ms at 1,024 entries, under 120 ms at the cap; entries after the base verify
             as today, about 60 us an Ed25519 signature plus the rule, about 100 ms a thousand; the writer's compile
             and a full reader's compile check cost what they cost today plus encoding the three lists
memory       the tail's entries while re-applying, at most 4,096 x about 600 B = 2.4 MB transient, then the
             64 KiB a phone keeps; rows decoded, 2-3x their bytes, so under 6 MB for the Team above and under
             100 KiB for a personal network; the ring as a map, 4,096 x 32 B
wire         a new device fetches what it fetched: rows and the entries from the retention point, about two fold
             spans; plus the ring and confirmations above; a base's header grows by its bitmap; rows re-upload
             only when the head or the fold moves, as before, since content addressing dedups equal rows; the
             bits change the header, never the rows, so a policy-only base at an unchanged fold uploads no rows
api          one bitmap compare and a bounded re-application per base, in place of judging the tail against a
             state it held anyway; FindStatement answers from the ring where it retains A_n, else 403 with the tip
```

### 5.5 Failure modes and recovery

```text
a lying or diverged writer     a base whose bits, rows or fold disagree with a present verifier forks that verifier,
                               which alarms (head_alarm, fork) with both pins, stops sealing in shared groups and
                               keeps the evidence; api, present at every tail, refuses the base with 403 before it
                               is sequenced, so a lie needs a compromised api as well; verifiers that started at the
                               lie agree with each other and with api, and a present verifier's HeadCheck shows the
                               split; recovery is the revocation of the writer for compromise from the base's
                               position, whose cascade parks what it admitted, and a base from another writer, which
                               forked verifiers apply once the log reverses the lie (7.9's precedence row)
a tail over the cap            api refuses the base; a writer folds through the tip and publishes again; a base
                               appended past the cap forks every reader, as a bad base does
a writer with no state at ft   a writer that started at the previous base holds its rows and StateAt from there;
                               ft is either that base's fold or at or past that base, so it always has L(ft)
a verifier that falls far      a reader whose newest pin is below the retention point cannot fetch the entries it
behind (a phone off for weeks) misses; it restarts as StartAtBase at the newest base, keeping its old pin as
                               evidence: if any pin it holds (a base's for 30 days, its last A_k) lies at or above
                               the retention point it checks the fetched chain against it; else a full reader links
                               its last A_k to the first retained entry's prev_chain through the head's records
                               (BASE records in folds), and a rows-only one trusts the base's signer as a cold gate
                               does, with the floor rule refusing any run that ends below its last pin; a mismatch
                               is head_alarm (fork), never a silent restart
a verifier holding an off-log  it forks at the activation as 7.9's precedence row says, so it checks no base's bits;
veto                           once the log reverses the activation it applies the base
site loss (TEAM-M3-02)         devices upload the verbatim entries they keep, the rows of their bases (the new
                               fields included) and pins; api adopts in position order from the oldest two members'
                               devices hold; for the first adopted base api takes its bits as a cold gate does, and
                               for every later one it compares them with the verdicts it judged on the adopted run,
                               refusing a run whose base disagrees, since such a base forked its own readers; the
                               resumed log keeps positions and digests, so no reader forks; an admin's device
                               re-seeds the config repo, whose folds hold BASE records too, and api checks the
                               newest adopted base against it as StartAtBase's anchor does; signers re-submit what
                               no adopted entry holds, open proposals among them if their rows were lost with the
                               run's base, since a proposal below the adopted run's first base survives only in rows
a reader that cannot fetch     withheld, as today: it keeps its pin, retries, and HeadCheck's proof path covers it;
rows or an entry               a rows-only run with a base whose rows the store cannot serve is refused whole
```

### 5.6 The test plan

Unit tests (sidecar root, each a top-level `func TestXxx`, fake clocks and barriers only):

```text
TestANewDeviceTakesItsBasesTailVerdicts        a new device at b holds every tail verdict from the bits and reaches
                                               S(b) byte-equal to a long-running reader's, under a head that moved a
                                               tag owner and toggled self_admit, and with a tail at below its first
                                               held position (5.1's two runs)
TestABaseWhoseBitsDisagreeForks                each of: a flipped bit, a 2 on a SidecarAdmit, a 3, a short or a long
                                               bitmap, a 1 at a BASE position forks a present reader and is 403 at api
TestATailOverTheCapIsRefusedAndForks           4,097 unfolded entries: api 403; appended, a FORK at every reader
TestAFoldedThroughBelowThePreviousBaseForks    ft between ft' and b' refused at api, a FORK if appended
TestAProposalSurvivesAFold                     k = 2: propose, base, cosign completes at a long-running reader, a new
                                               device and a rows-only gate alike; the same with two bases between
TestARecoveryWindowSurvivesAFold               a recovery proposal, a base, a tick at T_p + 72 h activates everywhere;
                                               a veto in the tail closes it everywhere; a rebind in the tail voids it
TestAVetoedProposalsReplayIsRefusedAfterAFold  the replay lands after the fold and is refused by every reader, the
                                               ring taken from rows
TestARefusedStatementResubmittedAfterItsReason a self-admission refused with self_admit off, resubmitted verbatim after
                                               a head turns it on, within 7 days: accepted alike, since the ring holds
                                               only what took effect
TestASelfAdmissionIsJudgedAlikeAtApi           a rows-only log accepts and refuses a member's own admission exactly as
                                               a full reader, under self_admit on and off; scim_signer's MemberRevoke
                                               the same once M6 lands
TestTheCascadeReadsEveryConfirmation           a stolen device's redundant OwnerConfirm of a device consented
                                               otherwise parks nothing at a rows-only gate either; an AdmissionConfirm
                                               that lifted a park pulls the device in; both from rows alone
TestReapplyRecomputesRowSignersOnTheNewRows    live_since, key_dropped_at, holders_shrunk_at and the row signer after
                                               a base equal a long-running reader's
TestAFoldHoldsItsBaseRecords                   a head missing a BASE record or holding a wrong one fails the head
                                               check; the chain recomputed from the genesis through folds equals A_ft
TestAFarBehindReaderLinksThroughTheHead        a reader with a pin below the retention point restarts, links its A_k
                                               through the head's records, and forks on a forged run
TestCompileIsDeterministicWithTheNewLists      rows vectors byte-equal on every leg with proposals, ring, settings and
                                               confirmations populated (testdata/config/rows/)
TestRowsOnlyAndFullReadersAgreeOverGeneratedLogs
                                               the existing property test extended: bases with tails, proposals and a
                                               cascade in every run; a new device started at each base agrees too
```

Schedule rows: FS-14 gains the cases above as named rows (tail verdicts taken, bits disagree, tail cap, fold rule, a vetoed replay after a fold, a self-admission at api, a far-behind reader); FS-16 gains the recovery window across a fold and a veto in a base's tail; FS-18 gains a Delegation's admission count and end carried through a fold to a new device; FS-41 gains a run whose later base's bits disagree with the adopted statements (refused) and a proposal that survives resumption in rows; FS-124 gains a presence-covered statement refused in a tail and carried as 0. §22.7's cascade list gains the confirmation-history case.

Model twins the tasks add to `AuthLog.tla` (new twin values and stories; the file's own tests are the configurations in `run.sh`): TEAM-M2-04 adds `NewestConfirmOnly` (the cascade from the newest confirmation alone, which must break Agreement between a rows-only gate and a full reader) and `DelegationEndIgnored`; TEAM-M2-05 adds `WindowFromProposalEntry` (T_p from o instead of the newest recovery signature, breaking WindowHolds) and `VoidKeepsProposal`; TEAM-M2-09 adds `WriterSkipsBaseBits` as a second lying story; TEAM-M3-02 adds a resumption story under `Adversary` where an adopted base's bits disagree. Each twin names the invariant it breaks, as the configurations here do.

### 5.7 Implementation notes, task by task

Order: the wire and the state first (TEAM-M2-04's rows, with this section's fields), then the reader (TEAM-M2-10), then the writer (TEAM-M2-09), then the rest; TEAM-M2-13 (api's sequencer) and TEAM-M2-11 (rows-only), not held, take the api checks and the bits when they next land.

**Landed code that must change** (all in the sidecar root unless said):

```text
protocol/bridge/auth.proto     ProjectionHeader.tail_verdicts = 10; ProjectionRows.proposals = 7, settings = 8,
                               ring = 9; ProposalRow, ProposalSigner, ProposalKind, ProjectionSettings, RingRow,
                               ConfirmationRow; SidecarRow.confirmations = 21; protocol/design_unfenced_test.go's
                               fence gains them and descriptor_test.go's api-7 guard their lines
protocol/config.proto          ConfigRecord.kind comment: 1 BASE allowed, body the Signed ProjectionHeader
config_state.go                ConfigState holds proposals as rows do (closed ones too, with reason and position),
                               settings from rows (Settings() loses known; SelfAdmit(), ScimSigner()); the ring
                               moves from ConfigLog into the state (a function of the log, so rows can carry it);
                               Rows() encodes the three lists
config_base.go                 applyBase: the ft rule, the tail cap, the bitmap decode and compare, then
                               reapplyTail by bits; stateFromBase keeps rows' proposals instead of emptying them;
                               configLoadRows indexes proposals, ring, settings, confirmations; foldedRecords
                               includes BASE entries; ConfigHeadCheck gains Previous = nil for a new device
config_replay.go               startAtBase: no judgeTailEntry; take the bits; the ring from rows plus the tail;
                               configTailRetentionPoint goes; a far-behind restart links through the head
config_rows_only.go            RestoreConfigLogRowsOnly and ApplyRun: unchanged in shape; the tail by bits
config_authority.go            proposals: a ProposalRow per open proposal with kind, signers (signer, at), window;
                               completion carried as verdict 2; configApplyCosign at re-application reads the row
config_apply.go                ConfigVerdict gains Completed (the 2); reapply recomputes rowSigner and ACL's fold
                               inputs on the rebuilt state; configApplyTick applies activations (TEAM-M2-05)
config_compile.go              ConfigCompileRows gains Proposals, Ring and Settings; CompileProjectionRows encodes
                               them; ConfigCompileRowsOf fills them
config_head.go                 RecordsIn and the fold parser accept kind 1; CheckConfigBase takes a new device's
                               check (Previous nil: genesis, records held, chain recomputation, settings) and the
                               settings-in-rows equality
config_retain.go               retention unchanged; the ring no longer needs its own trim once in the state
acl_statement.go (ACL's)       ReapplyStatement must take only body-derived verdict parts; ConsentedFor reads
                               confirmations; CascadeVoids reads the history (ACL's lane: raise, not edit)
sidecartest/fake_authority.go  PendingProposal(id) beside the rest, for CORE's acts
```

**TEAM-M2-04 (Delegations and the cascade).** Build first. Add `SidecarRow.confirmations` and write every AdmissionConfirm and OwnerConfirm there (kind, signer, at, lifted_park), keeping 5-8 as the newest. `ConfigState.CascadeClosure(x, since)` is 5.2.3's closure over rows: admission signers and `admitted_at`; confirmations with `lifted_park` by a signer then in P; the "adds nothing" clause from the history and §8.5's bases; bindings (`MemberRow.bindings[].signer, at`); Delegations (`DelegationRow.signer, at`, `delegation_id` on each admission, `admitted_at` from since_n for the Delegation that admitted x). Voids set `RecoveryBindingRow`'s void, `DelegationRow.ended_at`, and close recovery proposals signed by a voided binding's key (`ProposalRow` closed, reason void). `DelegationEnded` and `DelegationKeyDropped` read the row. Every effect here must be computable on a re-application from the body and the rebuilt rows (5.2.3's contract): `CascadePlan` is derived, not stored. Tests: the cascade from rows alone equals the cascade from a reader that kept every entry, over generated logs with bases between since_n and the revocation; the redundant-OwnerConfirm case through a fold. Add the `NewestConfirmOnly` and `DelegationEndIgnored` twins.

**TEAM-M2-05 (recovery in the verifier).** Proposals live in rows: `configProposal` becomes `ProposalRow` with `kind` fixed at the proposal's entry (authority; recovery-scoped with self_admit off; restored), `window_entry` and `window_time_ms` moved by each recovery-key signature. A RecoveryVeto closes the row (vetoed) at its position; voiding (a RecoveryRebind of the subject or a signing key's member, an AdminSet change, the subject's removal) closes it (voided); expiry is by the entry time at use. `configCheckTick` judges each activation from the row: open, kind, k satisfied (none needed for restored, one admission signer's cosign for recovery-scoped), `tick.time_ms >= window_time_ms + 72 h`; `configApplyTick` applies it, and `Reapply` applies it by the bits without the window check. `ConfigState.RecoveryWindow` and `PendingProposals` read rows; `HoldVeto` (an off-log veto) stays device state and forks the device at the activation as before. The re-application of a cosign or proposal with verdict 2 applies the proposed statement with the row's signers. Add `WindowFromProposalEntry` and `VoidKeepsProposal` twins.

**TEAM-M2-06 (presence).** Unchanged in substance: a presence-covered statement without its countersignature is refused at its position and carried as 0 in the next base's bits; `KeyRow` is already in rows. If decision 197 lands forwarding keys as `KeyRegister` with a new purpose, `configPresenceCovers` must not count them as presence keys. Add FS-124's "refused in a tail, carried as 0" row.

**TEAM-M2-07 (leaves, sponsors, indexers, settings).** `ConfigState.SelfAdmit()` and `ScimSigner()` read `ProjectionRows.settings`; `StaleLeafDays()` and `WitnessBoundHours()` read the head and answer unknown at a rows-only reader, which no gate rule reads. The compile writes `settings` from the head's `ServiceSettings`, and the head check compares. `live_since` and `LeafRank` are recomputed at re-application (a Suspend lifted in a tail, a device restored by a confirmation), never kept from the original check. FS-72's cases stay.

**TEAM-M2-09 (the writer).** `WriterPublishBase` as 5.2.4: L(ft) from the previous base's rows when the fold is unchanged, else `StateAt(ft)`; `compile` with proposals, ring and settings; the bits from the writer's own verdicts and the previous base's; the ft rule and the tail cap enforced before signing (fold through the tip when the tail passes 4,096, and at the 1,024-or-24 h trigger as today); on a 409, re-sign with the tail's new verdicts appended, re-compiling only when the head or the fold moved. Folds write BASE records (kind 1) in position order with the rest. The bootstrap base (version 1, ft 0) carries an empty bitmap. Tests: FS-14's writer cases plus a base after a tail of 1,024 with mixed verdicts byte-equal to a reader's expectation; a 409 that adds a refused statement to the tail; a fold holding its BASE records.

**TEAM-M2-10 (ConfigClient).** `StartAtBase` and `ApplyBase` as 5.2.4 for a full reader: the anchor on the first base (genesis, head on the repo chain through evs, fold records held, chain recomputation to the first retained entry, settings), then bits, never a judged tail; a far-behind restart as 5.5; `SidecarAuthority` gains `PendingProposal(proposalId) *ProposalRow` for CORE's acts and `Settings()` without `known`; `AddEntryCallback` fires for entries after the starting base only, with `Completed` on the verdict. Retention as today. Tests: restart at a base with a tail, equal to a reader that stayed; the anchor's refusals (another genesis, a head off the chain, a record missing, a chain that does not link).

**TEAM-M2-17 (shrink and expiry).** `holders_shrunk_at` is advanced in `Reapply` as in `Apply`, on the rebuilt rows, so a rows-only gate that started at a base reaches the same value; `ShrunkAt` equal on a new device, a gate and a long-running reader over generated logs with bases; nothing else changes.

**TEAM-M2-18 (CLI plans).** Reads `DelegationRow` and `SidecarRow` as before; the plan's "admissions left" and "ends at" come from rows that now survive any fold, and the agent plan shows a Delegation's parked agents from `parked_at` plus `confirmations` (who lifted what). No new field.

**TEAM-M2-19 (suites).** Add 5.6's unit tests that cross tasks and the FS rows named there to the T2 and T3 runs; run the admission suite with a new device started at every base and a rows-only gate restarted at every base, each compared with the long-running reader after every entry (the property the model checks, on real code).

**TEAM-M10-01 (VersioningRules and search).** No change in scope: `VersioningRules` stays head-only and read by full readers, `IndexerSet` folds to rows as today. It waits only on TEAM-M2-07 and -08.

**TEAM-M3-02 (site loss).** Uploads carry rows with the new fields and bases with bits; `AdoptConfigRun` takes the first adopted base's bits as a cold gate and compares every later base's bits with the verdicts api judges on the adopted run, refusing a run whose base disagrees; the re-seeded config repo's folds hold BASE records; the check of the newest adopted base is `StartAtBase`'s anchor at api's reach (genesis, config_pushes, records equal the adopted entries, chain recomputation); open proposals re-submitted where their rows were lost. Add FS-41's two rows and the resumption story twin.

**CORE-M3-02 (PreviewDeviceRevoke).** `Cascade` through `SidecarAuthority` is unchanged in signature; its items now come from rows' full confirmation history, so the plan lists "confirmed by" items with each confirmation's position; `ProposedSince` from retained entries as before. No scope change.

**CORE-M3-03 (RevokeDevice).** At k > 1 the act's AuthorityProposal is a `ProposalRow` the device watches through `PendingProposal`; `REVOKE_STALE` and the re-derivation are unchanged; the cosign path (`ur approve`, `Decide`) finds the proposal in S(n) after any fold, which is what this section makes true. No scope change.

### 5.8 Proposed DESIGN.md text

For the design-records track, section by section; each replaces the sentence or row named.

**§7.9, the proto block.** Add `tail_verdicts = 10` to `ProjectionHeader` with 5.2.2's comment; add fields 7-9 to `ProjectionRows` and the messages `ProposalRow`, `ProposalSigner`, `ProposalKind`, `ProjectionSettings`, `RingRow` and `ConfirmationRow`; add `repeated ConfirmationRow confirmations = 21` to `SidecarRow`'s comment ("every AdmissionConfirm and OwnerConfirm that took effect, with signer, position and whether it lifted a park, for the sidecar's life; 5-8 the newest"). Replace the ProjectionRows comment's "for the cascade a *_signer names..." with "a rows-only verifier's whole state at folded_through: for the cascade a *_signer names a sidecar_id, a recovery key's hash or a delegation_id, a *_at the position of the entry carrying the record, and confirmations every confirmation; proposals the open AuthorityProposals with their signers and windows; settings the ServiceSettings values a verifier judges by; ring the replay row's applied ids through folded_through".

**§7.9, `state` row.** "S(n) = the newest base b <= n, whose rows compile its config head, plus the STATEMENT and TICK entries among folded_through+1..b-1 re-applied in order by the verdicts b's `tail_verdicts` carries (a BASE there skipped, its rows superseded by b's), and every entry b+1..n, in order; no verifier judges an entry twice: each is judged at its own position by the verifiers then present, and every later one takes the verdict from the base that carries it".

**§7.9, `base` row.** After "config_version and folded_through are each at least the newest base's" add: "folded_through is the newest base's or at least that base's position, version - 1 - folded_through is at most 4,096, and tail_verdicts covers exactly folded_through+1..version-1 and agrees with api's own verdict at each position, a 2 only on an AuthorityProposal or AuthorityCosign; else 403 with the reason".

**§7.9, `fold` row.** Add: "a base may leave at most 4,096 entries unfolded; a writer behind that folds through the tip before it publishes".

**§7.9, `apply(e)` BASE row.** Replace "then the STATEMENT and TICK entries among folded_through+1..n-1 re-apply in order, a BASE among them skipped, its rows superseded by this base's, each keeping the verdict it got at its own position" with "the base's tail_verdicts match this reader's verdict at every tail position it judged, a BASE among them 0, else FORK; then the STATEMENT and TICK entries among folded_through+1..n-1 re-apply in order by those verdicts, a BASE skipped, a 2 applying the proposed statement with its row's signers; an effect reads only the body and the rows being rebuilt". Add to the head's requirements: "holds, as records, exactly the log's entries in (the previous base's folded_through, folded_through], bases included, each by id with its position".

**§7.9, `proposal` and `completion` rows.** Add: "rows carry every open proposal as a ProposalRow, with its signers, its window and its kind, so a cosign, veto, void or activation after a fold finds it at every verifier; a proposal closes in place at completion, veto, void or its not_after, and leaves rows at the next fold".

**§7.9, `self_admit` and ServiceSettings.** Add to ServiceSettings' signer column: "self_admit and scim_signer also compile into ProjectionRows.settings, which api and every gate judge by (§2.8 api-7)".

**§7.9, `retention` row.** Replace "so it judges every at as long-running readers do, and re-applies the statements and ticks among folded_through+1..b-1 as S(b) says" with "takes the verdict of each entry among folded_through+1..b-1 from b's tail_verdicts and re-applies them as S(b) says, judging nothing before b+1; it holds the replay ring from b's rows and the tail; a full reader recomputes A_1..A_{r-1} from the genesis through the head's records, bases included, and requires the result to equal entry r's prev_chain". Add to `retain`: "a reader whose pin falls below the retention point restarts at the newest base and links its last pin to the retained run, through the head where no held pin reaches it".

**§7.9, `cascade` row.** After "rows keep each such record's signer and position" add "and every confirmation with whether it lifted a park".

**§7.9, `site loss` `adopt` row.** Add: "a later adopted base's tail_verdicts must equal api's verdicts on the adopted run, else the run stops before it".

**§7.14.** D-TEAM-19 gains "a base carries the verdict of every entry in its tail, and its rows a rows-only verifier's whole state at its fold, so a new device and a gate reach a long-running reader's S(n) without judging a tail"; D-TEAM-20's "which every reader, a new device included, must judge alike" becomes "which every reader present judges alike and every later one takes from the next base"; D-TEAM-21 gains "open proposals ride ProjectionRows across folds"; D-TEAM-26 gains "rows keep every confirmation".

**§2.8 api-7.** The `sees` text gains: "each base header's tail verdicts (which entries took effect, which api judged itself); open authority proposals with their signers, windows and kinds; the applied-id ring; every confirmation's signer and position; and the id-level settings self_admit and scim_signer". (Pending the owner's answer to details-5-settings-in-rows.)

**§8.8.** AclRows' compile input gains "and §7.9's open proposals and ring", and the Code paragraph: "an acl statement's re-application reads only its body and the rebuilt rows".

**§22.7, §22.5's §7 row and FS-14, FS-16, FS-18, FS-41, FS-124.** The cases 5.6 names.

**§23.8.** No change: the fields freeze with §7.9's records at M2's Gn-in.

**plan-TEAM-config-head-format #1 (RESOLUTIONS).** "records run in n order with no BASE" becomes "records run in n order, BASE entries included as kind 1 with the Signed ProjectionHeader as body" (pending details-5-base-records-in-folds).

### 5.9 Owner questions

**details-5-settings-in-rows** (filed). Should `self_admit` and `scim_signer` compile into ProjectionRows, where api and every gate read them, adding a §2.8 api-7 line (I-18)? Options: (1) yes, the two values a verifier judges by, nothing else of ServiceSettings; (2) every id-level ServiceSettings value, for uniformity; (3) no: api accepts every scoped self-admission and readers refuse the ones self_admit forbids, splitting api from devices. Costs: (1) two small fields and one api-7 line; the server learns a setting whose effect it already sees in which admissions land; (2) the same plus team_mail, stale_leaf_days and witness_bound_hours, which no gate judges by today; (3) a 403 for nothing and a log api sequences but devices refuse, the split D-TEAM-19 forbids. Recommendation: (1). This section is built on it.

**details-5-base-records-in-folds** (filed). Should a fold's records include BASE entries, so the config head holds every entry's body and a reader recomputes the chain from the genesis through the head? Options: (1) yes, kind 1 with the Signed ProjectionHeader; (2) no, as plan-TEAM-config-head-format #1 fills it, and a far-behind reader that holds no pin in the retained run restarts on the base's signer alone, as a cold gate does. Costs: (1) about 400 B a base in the head, one more record kind in `ConfigHead`, `RecordsIn` and `CheckConfigBase`, and a change to a fill the planning track made; (2) a full reader off the network for longer than its base pins' 30 days anchors its restart on the signer named by the rows it is restarting from, which the invite's genesis and the head's repo chain bound but no hash chain does. Recommendation: (1). This section is built on it; with (2), 5.5's far-behind row loses its chain link and nothing else here changes.

Neither question blocks the held tasks: both are additive before M2's freeze, and each task above builds on the recommendation.

## 6. MLS group key management (§10)

Status: in progress

Tasks held until complete: KEYS-M2-19, KEYS-M2-20, KEYS-M2-21, KEYS-M2-22, KEYS-M2-23, KEYS-M2-24, KEYS-M2-25, KEYS-M2-26, KEYS-M2-27, KEYS-M2-28, KEYS-M2-29, KEYS-M2-31, KEYS-M4-01.

Model: `sidecar/sidecartest/model/details/Gkm.tla`, its configurations (`Gkm*.cfg`, `GkmTwin-*.cfg`) and `run-gkm.sh` beside it. Questions filed: `.stack/questions/details-6-last-resort-extension.md`, `.stack/questions/details-6-welcome-pointer-key.md`, `.stack/questions/details-6-group-owner-marker.md`, `.stack/questions/details-6-claim-key-prefix.md`, `.stack/questions/details-6-ladder-aad-widths.md`, `.stack/questions/details-6-reform-epoch-zero-floor.md`.

### 6.1 The problem

§10 keeps one MLS group per repo and, above it, one key generation chain. Three things move it: commits, which make epoch n from epoch n-1 by one If-None-Match create of `epoch/<n>`; rotations, which make generation g+1 from g by one If-None-Match create of `gen/<g+1>` after every delivery of RK_{g+1} is staged; and the authorization log, which every device reads at its own pace and which decides, at each position, who holds the key (`KeyHolders`, D-KEYS-16). Several devices of several members commit and rotate at once; a device's log position (its tip), its MLS epoch and its newest generation each lag the others' by hours or weeks; deliveries are written by whoever is online and read whenever the recipient returns; devices lose their state and come back by resync or by the member's recovery code. The requirement is fourfold: every member device converges on one group state per repo and epoch; no removed member reads a later generation or anything sealed after its removal; no device loses access it is entitled to; and every refusal is safe and recoverable.

The text as written is close, and most of it stands. Four places are wrong or open, each with a scenario, and three choices wait on the owner:

**A last-resort KeyPackage's Welcomes collide (question keys-m2-13-last-resort-welcome-pointer).** `gkm/welcome/<sidecar_id>/<ref>` keys a Welcome pointer by the KeyPackageRef the Add used. A one-time KeyPackage serves one claim, so its ref names one Welcome; the last-resort KeyPackage serves every claim once the one-time ones are gone (§10.6: "never deleted") and is the only one a device with 128 claims outstanding, or a device offline past its refill, has left. Device E, its one-time KeyPackages exhausted, is added to repo B on Monday and to repo A on Tuesday, both through its last-resort KeyPackage, before it comes online. Both Adds write a pointer at `gkm/welcome/E/<lr-ref>`: with If-None-Match the second is refused and A's Welcome is unreachable; with an overwrite B's is. The committer cannot tell, and E never joins that group: §10.6's "a writer leaf removes and re-adds the joiner after 10 minutes" fires only when the uploader crashed before writing the Welcome, and here the Welcome exists. E, an entitled reader, reads nothing of that repo until some unrelated Remove and re-Add happens. The landed `gkmservice/welcomes.go` keeps the standing pointer and alarms, which is the right interim, and the model's `GkmTwin-PointerByRef` reaches the lost Welcome in five steps.

**A GroupForm can name another repo's group (question keys-m2-12-groupform-names-anothers-group).** gkm ties a group to its repo only through `gkm/repo/<repo_id>/<seq>`, and a group route names only the group, which gkm resolves to the repo among the token's scopes whose newest form names it. A member who reads repo A (r) and administers repo B (admin) learns A's group id from A's heads, files a GroupForm for B naming it, and B's `rw` now reaches A's group: it can occupy `gen/<g+1>` with a claim A's members refuse (§10.9), which wedges A's rotations and so its write gate until a re-form, and it can post commits to A's epochs. Nothing leaks (every object there is ciphertext), but a reader holds a write position in another repo's group, and which repo a process resolves depends on which forms it read first. The landed `groups.go` refuses a form naming a group that already has objects, one LIST per form; that still leaves the race between A's form and A's `epoch/0`, in which B's form lands first and the resolver sees two newest forms naming one group. `GkmTwin-FormsUnchecked` shows the claim by a non-writer.

**A commit can carry the REMOVE generation into a tree that still holds the removed leaf.** §10.5 lets a wrapped writer rotate for a removed leaf X "by ReaderWraps to every remaining leaf" while no leaf has committed the Remove, so that no repo stays gated while every leaf is offline; §10.6's epoch PUT check makes every commit carry `GenWrap_n` of gkm's newest generation; and §10.4 has every leaf, read_only ones included, commit a path-only self-update every 7 days (30 above 50 leaves). Put together: agent D rotates to g+1 after member device X is revoked, wrapping RK_{g+1} to leaves A and C; the tree at epoch e still holds X; C, a read_only page Worker whose self-update is due, commits a path-only commit at e+1 carrying GenWrap_{e+1} = seal(KEK_{e+1}, RK_{g+1}). X's leaf is in e+1's tree, so X derives KEK_{e+1} from the commit (which gkm serves to any reader token, and which a copy of the ciphertext serves to anyone) and opens RK_{g+1}: the generation that exists to exclude X. §10.9's roster row ("every commit's roster lies within the key holders at its auth pin") forbids the commit, and §10.6's leaf row forbids C the Remove it would need, but nothing tells C to wait, and the two readings a builder is left with are a leak (C commits, members adopt) or a stall (members refuse C's commit, which then stands at `epoch/<e+1>` as the epoch every later commit must build on). The same shape blocks every resync (an external commit "removes at most its own old leaf") while a dropped leaf stands. `GkmTwin-GenWrapIgnoresRoster` reaches the leak in five steps.

**A re-formed group's epoch 0 has no auth pin (question keys-wire-reform-epoch-zero).** A re-form's generations arrive after its form, through the ladder, so `POST /gkm/repos/<id>/forms` has no GenRotate to read epoch 0's pin from, and the landed `epochs.go` refuses every commit onto a pinless epoch. A re-formed group takes no commit at all until this is settled, which blocks KEYS-M2-25 and FS-6's re-seed.

The three choices the brief names are settled in 6.2.2: which extension marks a last-resort KeyPackage (keys-m2-07-last-resort), which Welcome a device gets when two share a last-resort KeyPackage's pointer key (the first failure above), and group-id uniqueness across repos (the second). Beside them, 6.2.2 fixes what else the tasks would otherwise have to decide: the ladder's AAD widths and generation 1's cause (keys-ladder-aad-widths), the claim key's prefix (keys-m2-13-claim-key-prefix), the data each flow persists and the names of every new object, field and setting.

Three further rules that the text states but spreads over four places, each of which the model shows a violation without, are gathered in 6.2.3: a claim's auth pin never falls below its parent's (§10.6's claim checks), a LATE delivery is signed at a state at or past its generation's pin (§10.9's late row), and a leaf_wrap uses only an epoch whose tree holds holders alone (§10.5's remove row). `GkmTwin-ClaimBelowParent`, `GkmTwin-LateBelowClaimPin` and `GkmTwin-LeafWrapDirtyTree` each break one and reach a removed leaf reading the generation that excludes it; `GkmTwin-NoGate` seals past a shrink; `GkmTwin-SelfJoinCarriesGenWrap` lets a recovered device's self-join hand the lost device's leaf the next generation.

### 6.2 The design

#### 6.2.1 The principle

**Every secret of a generation reaches a party by exactly one of four paths, and each path is fenced by one object that a verifier can judge at its own pin.** RK_g reaches a leaf through a GenWrap in an epoch object, through a leaf_wrap in `gen/<g>`, through a STAGED delivery written before `gen/<g>`'s claim, or through a LATE delivery written after it; a non-leaf only through the last two, and a member's recovery code through its RecoveryWraps. The four fences are: (1) *the roster rule*, that every commit's new tree lies within `KeyHolders` at the commit's auth pin, which the committer checks before it commits and every member checks before it adopts, so that no epoch object ever wraps a generation to a tree holding a party that generation excludes; (2) *the claim chain*, that `gen/<g+1>`'s auth pin and time are at or past `gen/<g>`'s, so that holders only ever shrink along the chain; (3) *the delivery pin*, that a STAGED delivery is judged at its claim's holder set and a LATE one at its signer's state, which is at or past the claim's; and (4) *the leaf_wrap condition*, that a leaf_wrap's epoch holds holders alone. With these, "removed reads nothing new" is a property of the store, whatever any honest device's timing, and the model's `RemovedReadsNothingNew` checks exactly that over the reach a removed party has when it fetches everything.

Two consequences shape the flows. A leaf that may not commit a Remove (a read_only leaf; any external commit) **waits** while its tree holds a dropped leaf, and a hint keeps writer leaves awake until one commits it. And every refusal a member makes of a commit is a refusal to *adopt*, never a fork: the object stands at gkm, members alarm, and the group is repaired by a Remove of the committer and a rotation, or by a re-form, as §10.9 says; so the committer-side check must be the one that normally runs, and the member-side one the backstop.

Convergence needs no new mechanism: `epoch/<n>` and `gen/<g>` are each one If-None-Match create chained on its predecessor, every member adopts its own commit only on gkm's 200 and another's only from the stored object, and the generation pin and epoch pin never fall at any device. What this section adds is the set of preconditions under which a device *makes* each object, so that honest devices never write one that others must refuse.

#### 6.2.2 Formats settled

Each is a format change before M2's freeze (owner decision 194), with its §2.8 line where a server reads it; 6.8 gives the lines and 6.9 the questions.

**Last-resort KeyPackages** carry draft-ietf-mls-extensions' `last_resort` extension, type 0x000A, empty `extension_data`, in `KeyPackage.extensions` only, and every leaf lists 0x000A and 0xF553 (`ur_group`) in `capabilities.extensions`. gkm reads the flag from the KeyPackage it stores (`MlsKeyPackageInfo.LastResort`), never from the route. Two rules RFC 9420 §16.8 implies become ours: a device that joined through its last-resort KeyPackage commits a path-only self-update at its first opportunity after the join (the leaf's HPKE key is shared with every other Welcome that package serves until then), and replaces the last-resort KeyPackage at its next upkeep pass; and a device takes its last-resort KeyPackage's Welcomes under I-16's rule alone (no join at or below the newest epoch it reached of the group), which `mls_engine.go` already keeps. As built in `mls_extension.go` (keys-m2-07-last-resort option 1; question details-6-last-resort-extension).

**Welcome pointers** are keyed by group and epoch, never by ref: `gkm/welcome/<sidecar_id>/<group_id>/<n>`, n 20 digits as every epoch number, group_id 32 lowercase hex (QD-442). `GkmWelcomePointer` gains `bytes key_package_ref = 3`, the ref the Add used, so a joiner opens the Welcome with the KeyPackage that ref names and the reader needs no other lookup. One Welcome, one key, whatever KeyPackage it used. `GET /gkm/welcomes` lists the prefix `gkm/welcome/<sidecar_id>/` as it does now and answers each pointer with its Welcome; a device holding several pointers for one group takes the one with the highest n above the newest epoch it reached and skips the rest, since a lower one names a leaf a later Remove took out (the 10-minute re-add) or an epoch below its pin. The reconciler deletes a pointer at its recipient's first ack past n, at most 90 days, as it does today. (keys-m2-13-last-resort-welcome-pointer option 1; question details-6-welcome-pointer-key.)

**A group belongs to one repo from its first byte.** The first write of a creation or a re-form is the group's owner marker, `gkm/<group_id>/owner`, created If-None-Match, holding `GkmGroupOwner{bytes repo_id = 1; bytes network_id = 2}`, written by gkm from the token; a marker that exists with other bytes answers 409 and nothing else of the request is written; equal bytes resume a crashed request. Only then come the form, `epoch/0` and, for a creation, `gen/1`. gkm resolves every group route through the marker: `GET gkm/<group_id>/owner` (immutable, cached for the process's life), the repo it names must be among the token's scopes, and that repo's newest form must name the group; a token naming no such repo is refused whatever its other scopes. The shred deletes the marker with the group's other objects, and a re-seed's form in §19.10's deleted mode writes it again. The LIST the landed `groups.go` makes before a form goes. Group ids stay 16 random bytes (plan-KEYS-reform-ladder's rule 1 stands). gkm-1's §2.8 row, which already shows (repo_id, group_id) pairs, gains the marker in words; it discloses nothing new. (keys-m2-12 option 1's intent, made race-free; question details-6-group-owner-marker.)

**The ladder's AAD widths** are as built: `u64be(g)` and `u64be(e)` wherever §10.5 writes g or e, one byte for `cause`, so GenLink's AAD is `repo_id || u64be(g) || u8(cause)` (25 B), GenWrap's and LeafWrap's `group_id || u64be(e) || u64be(g)` (32 B) and GroupInfo's `group_id || u64be(e)` (24 B); `gen/1` carries cause REQUEST (2), and a reader refuses REMOVE there. `testdata/gkm/ladder.json` pins the bytes. (keys-ladder-aad-widths option 1; question details-6-ladder-aad-widths.)

**The claim key** `gkm/kp/<sidecar_id>/<ref>.claim` stands, and §11.8's "no key prefixes another" means a *path* prefix (an existing key followed by `/` at the new key's next byte, or the reverse), MinIO's real constraint; `sidecartest/fake_blobs.go` checks that, and KEYS-M2-13's filter of the one byte-prefix report goes once it does. (keys-m2-13-claim-key-prefix option 1; question details-6-claim-key-prefix.)

**A re-form's epoch 0 carries no auth pin**, as `GkmGroupReformRequest` landed; gkm gives epoch 1's pin its floor from `gen/<form.generation>`'s auth, which the ladder must have written before the group takes any commit (plan-KEYS-reform-ladder rule 5), so the epoch PUT check reads "never below the previous epoch's pin, or, for epoch 1 of a re-formed group, below gen/<the form's generation>'s". (keys-wire-reform-epoch-zero option 1; question details-6-reform-epoch-zero-floor.)

**Names.** New settings in `GkmSettings` (client): `PendingCommitDelay` (15 s plus jitter, KF2/KF3's other writers), `WelcomeTimeout` (10 min, the re-add), `LateAskInterval` (1 min), `LateDeliverJitter` (0-15 s), `SelfUpdateInterval` (7 d) and `SelfUpdateIntervalLarge` (30 d, above `LargeGroupLeafCount` 50), `ScheduleInterval` (30 d), `ResyncReplayMax` (100 epochs), `RotateBatchSize` (256) and `RotateBatchConcurrency` (4), `SeatCount` (1,000). In `GkmServiceSettings`: `PendingHintInterval` (60 s), `DroppedLeafHintInterval` (60 s, 6.2.3's hint), `GroupInfoPointerLagCount` (16). Keychain items in `keychain.ur` (§5.9): `gkm/<repo_id>/gen/<g>` (RK_g and the Signed GenRotate, per plan-KEYS-reform-ladder rule 2), `gkm/<repo_id>/draft` (a rotation's RK' and GenRotate draft), `gkm/<repo_id>/pins` (6.2.6), `gkm/<repo_id>/pending` (6.2.4's pending-change record), and the MLS state files KEYS-M2-09 keeps.
#### 6.2.3 The rules

Notation: `S` this device's newest verified state at tip `n`; `H(n, t) = KeyHolders(R, S(n), t)`; `tree(e)` the leaves of epoch e; `g*` gkm's newest generation and `gen/<g>.auth`, `.time` its claim's pin and time; `shrunk(n)` = `holders_shrunk_at` at `S(n)`; `expiry(t)` the newest holder expiry at or before `t`; `covers(g, n, t)` = `gen/<g>.auth.version >= shrunk(n)` with the pin on my chain and `gen/<g>.time >= expiry(t)` (§7.9's coverage, as `GkmGenerationCovers` has it).

```text
R1 judged pins    a device judges a commit at its header's auth, a claim at its auth and a STAGED delivery at
                  its claim's, a LATE one at its own auth (§10.9's judged row); one above n waits (never a
                  refusal), one off the chain is a fork alarm, one before my previous base is not judged
                  and counts against no one; a device builds nothing on an object it has not judged: it
                  commits only at the newest epoch it adopted, rotates only from a generation it holds and
                  judged, and delivers only a generation it holds and judged
R2 pin floors     a commit's auth is at or past the previous epoch's and the carried generation's; a claim's
                  auth and time are at or past its parent's; a LATE delivery's auth is at or past its
                  generation's; gkm refuses what it can see of these (the epoch PUT and claim checks, the
                  wrap checks' late row), members refuse the rest; so holders only shrink along each chain
R3 roster         every commit's new tree lies within H(auth, time) at its own header, but a recovery self-join
                  with generation 0, which may leave the lost devices' leaves; the committer checks this
                  before it commits, and carries every Remove it may commit that the rule needs (the pending
                  engine, 6.2.4); a member refuses a commit whose tree breaks it and never adopts or
                  encrypts to its epoch, raising refused (plan reading 7), and the group repairs as §10.9's
                  "a bad commit can stall" says; a leaf that may not commit a Remove (read_only; an external
                  commit, which removes only its own old leaf) waits while its tree holds a dropped leaf,
                  self-updates and resyncs included, and hint H1 keeps a writer leaf awake until it commits
                  the Remove
R4 GenWrap        a commit's GenWrap wraps g*, which the committer holds and judged, under the new epoch's
                  KEK; with R3 that epoch's tree holds holders of g* alone (g*'s holders are H at its claim,
                  and the commit's auth is at or past it by R2); the one exception is the generation-0
                  self-join, which carries none
R5 leaf_wrap      a rotator uses a leaf_wrap under KEK_e only if it is a leaf of e and tree(e) ⊆ H at its
                  state; else every leaf of e in H gets a ReaderWrap, as every agent does; an epoch whose
                  tree holds a dropped leaf never carries a leaf_wrap, and no later epoch wraps g+1 into
                  that tree (R3, R4)
R6 delivery       a STAGED delivery's recipient is in the claim's holder set, and a LATE one's in H at the
                  signer's auth and time, the signer a holder that is not read_only and whose auth is at or
                  past gen/<g*>'s; a LATE delivery names a key the recipient published and gkm serves; a
                  delivery valid at its own state stays valid (§10.9's history row)
R7 gate           a writer seals to the newest generation it holds only while that generation covers
                  shrunk(n) and expiry(now) at its state, and evs passes the push only while it covers them
                  at evs's state (§10.6, §11.8); EnsureWritable rotates first when it does not; a depositor
                  seals to a drop key under the same coverage (D-KEYS-17)
R8 one tree       a device adopts its own commit only on gkm's 200 and another's only from epoch/<n> as
                  stored; its epoch pin (group_id, n, epoch_authenticator) and generation pin (g, C_g) never
                  fall, and no join, Welcome or external, takes it to an epoch at or below the newest it
                  reached (I-16); HeadCheck compares both pins (6.2.6)
```

Why R3 is checked by the committer and not only by members: a bad commit leaks the moment it stands at `epoch/<n>`, since the removed leaf, or anyone holding the ciphertext, derives KEK_n from it whatever honest members do; a member's refusal contains the damage (it treats the carried generation as poisoned: never seals to it again, rotates at once with cause REMOVE, and the next leaf commit removes the committer, §10.9's poisoned row) but cannot undo it. Every honest leaf therefore runs the same check before it commits, and the model's twin shows what the text's self-update interval alone would do.

Hints (§10.6's duties, extended):

```text
H1 dropped leaf   the reconciler hints pending every DroppedLeafHintInterval to a repo's writers while gkm's
                  newest verified state shows a holder dropped since the newest epoch's auth pin and time, as
                  it already does while the gate is closed; gkm cannot see whether the dropped holder was a
                  leaf, so the hint is sent either way and costs one wake a minute per affected group; it
                  stops at the first epoch whose pin passes the drop
H2 waiting leaf   a leaf that waits under R3 asks GET .../group-info?want=<e+1> at most once a LateAskInterval,
                  which hints wrap-pending to the writers as an older want does (KF5); a writer so hinted
                  runs EnsureWritable's commit step
H3 pending        as today: pending to the writers, the statement's signer first, at each holder change,
                  every PendingHintInterval while the gate is closed; in the directory group to the signer
                  and the config writers only (D-KEYS-23)
```

#### 6.2.4 The flows as state machines

Each flow is a machine per (device, repo); every transition names the object it writes and the check that fences it. `persist` means a keychain write under §5.9's AEAD before the next step, so a kill resumes from it. Pseudocode is the implementer's: Go names from the plan (`gkm_*.go`), fields from `protocol/gkm.proto`.

**The pending engine** (KEYS-M2-21), one per group, single-flight, drives every membership change. Its input is the log applier's `AuthAdvanced(S)` and gkm's hints; its state is derived, never stored but for the Welcomes it owes:

```text
Pending(S, e) for a leaf of epoch e, tree(e), H = H(n, now):
  removes   = tree(e) \ H                                    (every dropped leaf; R3)
            ∪ {x ∈ tree(e) : x not leaf-entitled at S}        (config and directory groups: §7.9's move)
            ∪ {x ∈ tree(e) : stale(x)}                        (§10.9's stale row, KEYS-M2-19's one function)
  adds      = {d ∈ H ∩ member devices : d ∉ tree(e), d leaf-entitled (config, directory) or seated
              (data: earliest-admitted first up to SeatCount), d has a KeyPackage gkm serves, d consented
              where the kind is owner-bound (§8.5), d anchored if a restored binding admitted it (§10.8)}
  welcomes  = Welcomes this device committed whose pointer it has not yet written
  rotate    = ¬covers(g*, n, now) ∨ gen/<g*>.time + ScheduleInterval < now ∨ a request is pending

may(c)      c commits removes and adds iff c is a writer leaf (not read_only, not wrapped); the admission's or
            revocation's signer may in the config and directory groups (owner decisions 128, 182); the
            granting device first, other writer leaves after PendingCommitDelay; a wrapped writer commits
            nothing and rotates (6.2.4's Rotate) or writes first wraps (KF2)

Run(c):     while Pending ≠ ∅ and may(c):
  1  if removes ∪ adds ≠ ∅: Commit(removes, adds)             one commit carries all of them (R3)
  2  write each owed Welcome and pointer                       welcome/<n>, then welcome/<d>/<group>/<n>
  3  if rotate: Rotate()                                       6.2.4's Rotate
  4  refetch S and gkm's newest epoch and generation; loop
```

**Commit** (any leaf; the engine's step 1, a self-update, a resync's or self-join's external commit):

```text
states   Idle → Staged(commit, e+1) → Uploading → Adopted | Discarded
pre      at the newest epoch e I adopted; tip n ≥ epoch/<e>.auth and ≥ gen/<g*>.auth; I hold RK_{g*} (R1);
         new tree ⊆ H(n, now) (R3), or the self-join exception; path = true for every commit but an Add-only
         one; read_only: path only, no proposal; an external commit: ExternalInit, my old leaf's Remove, a path
stage    engine.Commit(args) → staged; header {generation g*, auth (n, A_n)} in authenticated_data; seal
         GenWrap_{e+1} = seal(KEK_{e+1}, RK_{g*}; group_id || u64be(e+1) || u64be(g*)) and, at ≤ 16 leaves,
         GroupInfo_{e+1} under K_groupinfo of g*, group_info_generation = g*; persist nothing (a staged commit
         that dies is remade)
upload   POST epochs/<e+1> {commit, gen_wrap, sealed_group_info, group_info_generation}
         200   Adopt; pins ← (e+1, epoch_authenticator), (g*, C_{g*}); if Adds: owe the Welcome (persist
               welcomes owed with the Welcome bytes and recipients, keyed by (group, e+1)); hint commit rides
         409   Discard; Process(winner) as any received commit; rerun Pending (KF6)
         403   refused by gkm's checks (rate, pin, header): alarm refused if my checks passed; wait for S
         unknown  GET epoch/<e+1>: mine (same commit bytes) = 200; another = 409; 404 = repeat the POST
welcome  POST welcome/<e+1> {welcome, recipients [(sidecar_id, ref)]}; gkm writes welcome/<n> If-None-Match,
         then a pointer per recipient If-None-Match, equal bytes answering success; a crash before this step
         leaves joiners waiting: a writer leaf that sees no welcome/<e+1> after WelcomeTimeout removes and
         re-adds them (the engine's removes gain "added at e+1 with no Welcome after WelcomeTimeout")
```

**Process** (a received commit, from `GET epochs?after=` or a commit hint):

```text
pre      epoch/<e+1> stored; tip n ≥ its header's auth (else wait: R1)
check    engine.Process(bytes) stages it (signature, proposals, path, confirmation tag: mls_group.go); then
         §10.9's committer and check rows at the header's auth: the committer may make it (Add: a writer leaf
         or the signer; Remove: a writer leaf or the signer, never the target; path-only: any leaf; external:
         the sidecar itself, resync or self-join); each Add's credential admitted, pinned, consented, seated
         or entitled; each Remove's input (a revocation, park, Suspend, grant end, entitlement loss, or a
         stale leaf by the credential's not_after rule); the new tree ⊆ H at the header (R3) but a
         generation-0 self-join; header.generation = the previous epoch's or newer, and its GenWrap opens to
         RK matching gen/<g>'s C_g (or none at generation 0)
adopt    Adopt(); pins forward; if removed: leave the group (at ← none), keep every RK_g held, read on by
         wraps if still a holder (a stale-removed or wrapped device), else by nothing new
refuse   alarm refused naming the committer and epoch; never adopt; keep processing nothing of this group
         until a later epoch's chain shows the group repaired (a Remove of the committer and a rotation, or a
         GroupForm); seal nothing to the generation its GenWrap carried (poisoned, §10.9)
```

**Rotate** (KEYS-M2-20; §10.5's five steps, with every fence named):

```text
states   Idle → Drafted(RK', GenRotate) → Staging(k of W) → Claiming → Done | Lost(winner)
pre      I am a writer (or the statement's signer, config group), a holder or covered at S; I hold RK_{g*} and
         judged gen/<g*> (tip n ≥ its auth); GET gen/<g*+1> → 404
1 draft  H = H(n, now); RK' random; C' = SHA-256("UR evs 1.0 commit" || repo_id || u64be(g*+1) || RK');
         GenLink = seal(K_link', RK_{g*}; repo_id || u64be(g*+1) || u8(cause)); cause = REMOVE iff
         GkmRotationRemoveRequired (a shrink, expiry or compromise retirement since gen/<g*>'s pin and time,
         or a poisoned parent), else REQUEST or SCHEDULE; holders_sha256 over H's identities; drop key if the
         kind takes deposits (drop_not_after_ms = time_ms + DropKeyLifetime); persist draft {RK', GenRotate}
2 set    W = deliveries:
           leaves      if I am a leaf of my epoch e and tree(e) ⊆ H: leaf_wrap {e, seal(KEK_e, RK')} in the
                       GenRotate (R5); else a ReaderWrap to each leaf of e in H, to the ReaderKey gkm serves
                       for it if 10.5's readerkey check passes (time_ms < not_after ≤ time_ms + 7 d + 10 min)
           wrapped     config and directory groups: each member device in H outside tree(e): a ReaderWrap
           agents      each agent in H not covered by a live Delegation in H: a ReaderWrap
           delegations each live Delegation in H: a DelegationWrap to its reader key
           recovery    each member reading R with a current binding: a RecoveryWrap at its b8
         wrap_count = |W|; every delivery STAGED at wrap/<g*+1>/<c8>/<recipient>/<k8> and recovery/.., in
         batches of RotateBatchSize, RotateBatchConcurrency at once (QD-066); a 412 with equal bytes is
         success, with other bytes an alarm (another rotator with my C', impossible unless RK' leaked); a 0
         item is sent again; persist nothing between batches: a restart re-stages (If-None-Match makes it
         safe) and stale staged objects of a lost claim are GC'd after 24 h
3 claim  POST gen/<g*+1> (the Signed GenRotate), the linearization point; testHookBarrier around it
         201   Done; keychain gen/<g*+1> ← {RK', bytes}; pin (g*+1, C') forward; delete the draft; seal to
               g*+1 from now
         412   winner = the stored GenRotate: judge it (§10.9's rotation checks at its auth: signer, chain,
               holders recomputed at its pin and time, each STAGED delivery I can read, cause, time);
               if it passes and covers(g*+1, n, now) and I have a delivery or leaf_wrap to open: adopt it
               (keychain, pin), delete the draft, Done; if it passes but does not cover what I rotate for:
               fetch my key of it (a late ask if none), then go to 1 at g*+2; if it fails: poisoned (alarm,
               never seal to it, rotate at g*+2 at once with cause REMOVE, and the admins revoke its signer)
         403   my state is behind gkm's (signer, auth or time check): refetch S and retry at 1; a time
               refusal waits for my clock
         unknown  GET gen/<g*+1>: my C' = 201; another = 412; 404 = repeat the POST with the same bytes
```

**Late delivery** (KEYS-M2-20, the deliverer; KEYS-M2-22, the asker):

```text
asker    a holder whose GET wraps/<g*>?recipient=&want=<my k8> finds no delivery of g* to a key it holds: ask
         with since = first ask, at most once a LateAskInterval; a device none of whose keys opens anything
         publishes a fresh ReaderKey first (upkeep); meanwhile it reads with what it holds, and a leaf keeps
         processing epochs (a GenWrap of g* in any epoch it adopts also serves)
deliver  on wrap-pending naming recipient x: wait LateDeliverJitter; require: I am a holder (or covered), not
         read_only, hold RK_{g*} and judged gen/<g*>, tip n ≥ gen/<g*>.auth (R2), x ∈ H(n, now) (R6); GET
         reader-key/<x> (or the Delegation's key): 10.5's readerkey check; PUT one LATE KeyDelivery at
         wrap/<g*>/<c8>/<x>/<k8> with auth (n, A_n) and time_ms = max(now, gen/<g*>.time_ms); 201 done; 412:
         judge the winner (delivery checks); 409 (not newest, or a key gkm no longer serves): refetch and
         retry once; unknown: repeat the PUT (If-None-Match)
```

**KF1, create** (KEYS-M2-21):

```text
states   Filed(RepoCreate) → Placed(keying) → Owner → Form → Epoch0 → Gen1 → Staged(k of W) → Active → FirstAdd
1        file RepoCreate (§8.8); evs creates repo/<id> keying and place/<id> (§11.8); persist nothing yet
2        draw group_id (16 random bytes), RK_1, GenRotate_1 {generation 1, no parent, cause REQUEST, auth (n,
         A_n), holders_sha256 over H(n, now), wrap_count}; engine.CreateGroup(group_id, ur_group {network,
         repo, kind, owner}); seal GenWrap_0 and GroupInfo_0 under RK_1; persist draft {group_id, RK_1,
         GenRotate_1, MLS state}
3        POST /gkm/groups {form, gen_rotate, gen_wrap, sealed_group_info, cipher_suite}: gkm writes owner,
         form, epoch/0, gen/1 in that order, each If-None-Match, equal bytes resuming (QD-464); 409 on
         other bytes at the owner marker: the id is taken, draw another at 2
4        stage generation 1's deliveries as Rotate's step 2 (ReaderWraps to agents and, in the config and
         directory groups, to member devices in H; DelegationWraps; RecoveryWraps); while the repo is keying
         gkm accepts STAGED deliveries of generation 1 by gen/1's signer (§10.6's wrap checks)
5        POST /evs/v1/repos/<id>/activate (RESOLUTIONS plan-EVS1-repo-activate-route): only after 4, so no
         content predates its recovery wraps (D-KEYS-18); then delete the draft, keep gen/1 in the keychain
6        the engine's first run adds every pending member device in one Add commit (KF2)
crash    before 3: resume from the draft (same bytes); between 3 and 5: resume at 4 (the repo is still
         keying, the group exists); the creator's only device lost before 5: the repo stays keying forever
         (FS-20), and a repo admin's device may re-form it or delete it
```

**KF2, add a device D; KF3, add a member** (the engine's adds):

```text
D        enrolls; SidecarAdmit lands at n_a; uploads ReaderKey and, as a member device, KeyPackages (a device
         a restored binding admitted: ReaderKey only until anchored); gkm hints pending at its first upload
         and at each state that lists D as a reader
leaf     a writer leaf (the granting device first; the signer in the config and directory groups) claims a
         KeyPackage (POST key-packages/claim; 404: D has none yet, D reads by first wrap where the group
         wraps, else waits) and commits the Add with every other pending change; the Welcome and pointer
         follow; D joins: JoinWelcome, open GenWrap_n for RK_{g*} against gen/<g*>'s C_g, open GroupInfo_n
         under K_groupinfo of group_info_generation, Complete; walk the ladder down to generation 1; pins
         start at (n, epoch_authenticator) and (g*, C_{g*}); D acks
wrapped  an agent, or in the config and directory groups a member device that is wrapped or has no
         KeyPackage: a LATE ReaderWrap of g* from any holder but a read_only one, hinted writers first, signed
         at a state listing D (R6); a covered agent reads at once through its Delegation's wrap
seat     data repos: at most SeatCount leaves; the engine fills a free seat with the earliest-admitted waiting
         device that has a KeyPackage (§8.12); the 1,001st waits keyless, named in the writer's preview
consent  owner-bound kinds: an unconsented D is parked (no Add, no wrap) and raises approval_pending (§8.5)
member N a grant or EvsShare for N lands; KF2 runs for each of N's devices
```

**KF4, remove X** (the engine's removes, then Rotate):

```text
1  entry n' revokes X (or a grant ends, a park, a Suspend, an expiry at T_e): holders_shrunk_at = n' (or
   expiry(T_e)); evs refuses pushes whose generation does not cover it (412 GATE_CLOSED), gkm hints pending
2  a writer leaf, the revoking device first, commits Remove(X) with a path (R3) at auth ≥ n'; a wrapped
   revoker (config, directory) skips to 3 and the next leaf commit removes X (H1 keeps leaves awake)
3  any writer rotates: a leaf whose tree is clean by leaf_wrap under KEK_{e+1}; a wrapped writer, or a leaf
   whose tree still holds X, by ReaderWraps to every remaining leaf and agent (R5); cause REMOVE
4  the gate reopens for writes declaring g+1 (R7); EnsureWritable runs 2 and 3 for a writer before its next
   write, so reaps and expiries batch (D-KEYS-6)
5  §11.7's next write of each file is a full checkpoint, and a path epoch is due (§11.6)
```

**KF5, catch-up and resync** (KEYS-M2-23):

```text
behind   ≤ ResyncReplayMax epochs: Process each in order (the Adopt chain)
resync   further behind, or commits pruned, processing failed, or my leaf was removed as stale: open the
         current sealed GroupInfo (inline at ≤ 16 leaves, probing epoch/<pointer+1>.. to a 404; above, the
         group-info object, a ?want= hinting a leaf to write it) with K_groupinfo of the generation it names,
         which I hold or ask for late; then an external commit at g* (R1-R4: tip ≥ epoch/<e>.auth and ≥
         gen/<g*>.auth; tree(e) \ {my old leaf} ⊆ H, else wait under R3 and ask H2); else await a re-add or
         use the recovery code
```

**KF6, concurrent commits:** the 409 loser discards its staged commit, having written no Welcome, processes the winner (Process) and reruns Pending; two rotations race only at `gen/<g+1>` (Rotate's 412). **KF7, gkm unavailable:** `CurrentRepoKey` and `RepoKey` answer from the keychain, `DropKey` from the newest GenRotate held if it still covers at my state (R7), writes continue while every shrink is covered (evs checks the gate from the log) and stop at the first uncovered one until gkm returns; joins, catch-up, rotations and deliveries wait and retry on the hint intake's resync.

**Recovery** (KEYS-M2-24; §10.8 with its order made explicit):

```text
states   Fetching → Admitted → Anchored → SelfJoined(config) → Joined(others) → Revoking → Rotated
1        under recovery:<member_id>, GET recovery/<member_id>/wraps: the newest per group whose b8 is my
         binding's; open each RecoveryWrap against gen/<g>'s C_g; walk the ladder; read the log and these
         wraps only
2        admitted (§7.9's table); §7.9's anchor on the config group's RecoveryWrap: head_alarm (fork) and stop
         on failure
3        self-join the config group and every group M writes by external commit: if tree(e) ⊆ H at my tip,
         generation g* with its GenWrap (an ordinary resync); else generation 0 with no GenWrap (R4's
         exception), the lost devices' leaves staying; join the others through KF2 (upload KeyPackages)
4        revoke M's lost devices (§5.6's calls); then, as a writer leaf, the engine's next Commit removes
         every dropped leaf (R3), then Rotate (cause REMOVE); the self-join's epoch gave them nothing, and no
         generation after their revocation is wrapped into a tree holding them
restored a binding a void restored: ReaderKey, no KeyPackage, the late ReaderWrap of the config group's
         current generation (KF2's wrapped row), the anchor on its RK_g, only then 3 and 4 (§7.9's restored)
rebind   ur keychain recovery-rotate: re-wrap each group's current generation to the new binding at its own b8,
         delete the old binding's wraps only once every new one exists, request a REQUEST rotation, or REMOVE
         for a compromise, which also starts a path epoch at once
```

**Drop** (a holder leaving: §10.5's table): a shrink (revocation, park, Suspend, grant end, Delegation end or key drop, compromise retirement) closes the gate at its entry; an expiry closes it at T_e with no entry; the reconciler hints pending; the engine's next run removes the leaf (if any) and rotates with cause REMOVE; a Delegation's key drop excludes the Delegation's wrap and every parked agent; an unsuspended agent returns by a late ReaderWrap of its own. A ReaderKey lapse or replacement, a move between leaf and wrap, a covered agent's reap and a newer forwarding Delegation drop nothing and rotate nothing (§10.6's never list).

**Re-form** (KEYS-M2-25; plan-KEYS-reform-ladder's rules 1-9): owner marker (6.2.2), form naming previous_group_id and the newest generation held, epoch/0 with no pin, the ladder route in ascending batches of 64, then the group takes commits from epoch 1 with its pin floor at gen/<form.generation>'s auth; readers re-add by KF2 and late wraps; members check the form's signer by §10.6's rule, each C_k against their cache, and judge each GenRotate's signature only where their retained log reaches.

#### 6.2.5 Key access (KEYS-M2-22)

```text
CurrentRepoKey(repo)  the newest generation held and judged: EvsRepoKey{RK_g, C_g, cause, auth, time};
                      ErrGkmUnavailable with none; a stale newest is still answered (reads never wait on a
                      rotation), and §11.7 reads its cause for the checkpoint rule
RepoKey(repo, g)      from the keychain, or the ladder walked down from the newest held through the Signed
                      GenRotates (GET gen?since= for any missing; each verified at its pin where my log
                      reaches, by C_g chain always); a key that is not there is refused, never defaulted
EnsureWritable(repo)  1 require writer at S (ErrGkmNotWriter); 2 Run(c) the pending engine for the changes
                      this device may commit (as a leaf: removes and adds; as a wrapped writer: nothing but
                      first wraps); 3 if ¬covers(g*, n, now) or SCHEDULE due: Rotate (6.2.4), a wrapped
                      writer or a dirty tree by ReaderWraps (R5); 4 refuse (ErrGkmWait) while the newest
                      generation still does not cover at S, even with evs's gate off (the writers' own rule,
                      §8.12), and while a non-holder leaf stands in a tree that wrapped it (R3's poisoned
                      case); 5 return CurrentRepoKey; the witness stop never holds 2 or 3 (owner decision 129)
DropKey(repo)         §10.5's depositor rule: the newest GenRotate gkm serves (GET repos/<id>/drop-key?since=),
                      verified; covers(g, n, now) at my state; now < drop_not_after_ms ≤ time_ms +
                      DropKeyLifetime + 10 min; g not below my pin, which then rises; else ErrGkmWait, and a
                      writer rotates on the renewal hint (plan-KEYS-drop-key-lifetime)
RotateRepo(repo)      ur keys rotate: Rotate with cause REQUEST (never REMOVE unless one is due)
ForgetRepo(repo)      §11.12's shred: drop RK_g, GenRotates, MLS state, pins and pending records
```

#### 6.2.6 Group sync, pins and HeadCheck (KEYS-M2-23)

Each device keeps, per repo, `pins{epoch: (group_id, e, epoch_authenticator), gen: (group_id, g, C_g)}` in the keychain, advanced only forward: a commit adopted, a Welcome completed, a generation claimed, opened or adopted. A lower or conflicting value from any source (a push's sealed epoch pin, a head's generation pin, a GenRotate, a HeadCheck peer) is `head_alarm` (fork) with both values; the device stops sealing in that repo until the chain extends its pin. `GroupHead` and `GenHead` for §6's HeadCheck are these pins, GroupHeads only for groups both peers are leaves of, GenHeads for repos both read, 16 of each a round, rotating by group id. §6.4's rules apply: same epoch, same epoch_authenticator else FORK; same g, same C_g else FORK; the lower side reads `gen?since=` or `epochs?after=` up to the higher, checking the chain, and a chain that does not extend its pin is a FORK. After a re-form, a GenHead's group_id differs: the lower side resolves the repo's newest GroupForm (plan-KEYS-reform-ladder rule 8) and compares (g, C_g) along the form chain. Self-updates: a leaf that committed no path for `SelfUpdateInterval` (`SelfUpdateIntervalLarge` above `LargeGroupLeafCount` leaves) commits a path-only commit under R1-R4, read_only leaves included (D-KEYS-26), and defers it under R3 while its tree holds a dropped leaf. Acks: daily, the newest adopted epoch, per group.
### 6.3 Invariants and why they hold

```text
RemovedReadsNothingNew  for every generation g and party s outside gen/<g>'s holder set (its recovery code
                        aside), s opens nothing at or above g, however much of the store s fetches
                        why: s reaches RK_g only by a GenWrap in an epoch whose tree holds s (R3, R4 keep
                        every epoch wrapping g within g's holders), a leaf_wrap under an epoch whose tree
                        holds s (R5), a STAGED delivery (gen/<g>'s holders) or a LATE one (R6: at a state
                        at or past g's pin, where s is a holder only if it was at g's pin, since holders
                        shrink along the chain by R2); the ladder opens downward only
NoContentToDropped      no content sealed at state n opens to a party dropped at n
                        why: R7 seals only to a generation covering shrunk(n) and expiry(now), whose holder
                        set excludes the dropped party, and RemovedReadsNothingNew keeps it there
RosterWithinHolders     every epoch's tree lies within the holders at its commit's pin, but a generation-0
                        self-join's; why: R3 at the committer, backed by every member's refusal
GenerationsFromWriters  every gen/<g> is claimed by a writer of the repo that holds the key at its pin
                        why: §10.6's claim checks (scope, signer) resolved through the owner marker (6.2.2),
                        so no other repo's scope reaches the group
WelcomesReachable       every Welcome has a pointer its recipient can read; why: one pointer key per (device,
                        group, epoch), created If-None-Match, never shared by two Welcomes
ChainsMonotone          auth pins never fall along the epoch chain or the generation chain; why: R2 at gkm
                        (the epoch PUT and claim checks) and at every member
Convergence             every member at epoch n holds the same tree and epoch_authenticator, and every holder
                        of generation g the same RK_g; why: one If-None-Match object per index, R8's adopt
                        rule, MLS's confirmation tag and C_g; the model keeps the store as the one copy, so
                        this is R8's action structure rather than a checked formula
HoldersReach (liveness) once the log and the rotations stop, every holder of the newest generation holds
                        it; why: a leaf through its epoch's GenWrap or a leaf_wrap, an agent through its
                        staged delivery, a holder whose key lapsed or who joined after the claim through a
                        LATE delivery by any holder that is not read_only (fair), a member device not yet
                        in a data repo's tree through its Add (fair at a writer leaf)
```

**The model.** `sidecartest/model/details/Gkm.tla` keeps one repo A's store as the shared state: the epoch chain (committer, tree, carried generation, pin, time, kind), the generation chain (rotator, holders, pin, time, staged recipients, leaf_wrap epoch), LATE deliveries, Welcomes with their pointer keys, each member device's one-time KeyPackage count, the content sealed (generation, state) and repo B's Welcomes. Each sidecar keeps its tip, the epoch it adopted and the newest it ever reached (I-16). The log is a sequence of admissions, a recovery admission, revocations and an agent's grant expiry; its position is the clock, and an expiry is seen by clock while a revocation is seen by tip, which is how a device with a stale state but a current clock behaves. What a party can open, `Reach`, is derived from the store alone: every GenWrap of an epoch whose tree holds its leaf, every leaf_wrap under such an epoch, every delivery to it, its recovery wraps, and the ladder below; so a removed device that fetches the whole store, or colludes with the server, is the adversary. Five sidecars: a the creator and a writer leaf, b a writer leaf, c a read_only leaf, d an agent that rotates and delivers but never commits, e the device a member's recovery code admits, which the squat twin casts as a reader of A and admin of B. Actions: an entry, a device's advance, a member's processing of the next epoch, a leaf's commit (Add, Remove, path-only, a stale Remove) carrying every pending Remove it may, a Welcome join, an Add in B, a rotation, a LATE delivery, a resync by external commit, the recovered device's self-join, a lost state, a content seal under the gate, and under the squat twin the form and claim. It leaves out ReaderKey lapses and replacements (a delivery to a holder is a delivery to a key it holds), Delegations and their covered agents (an agent holds its own wrap), the leaf rank of the config group, GroupInfo availability, the 412 loser's adoption (two rotations are two claims), gkm's rate limits and the write budget, and the server's forks (HeadCheck's domain, §6). `Twin` selects a rule to break; `Story` fixes each twin's actions so TLC reaches its violation directly; the design runs with no story. `run-gkm.sh <track>` runs every configuration through `.stack/tools/tlc` and prints a verdict line per run.

Runs, TLC at the owner's jar (master d8fb231), breadth-first over every reachable state at the bounds:

RUNS_TABLE

Each twin run took under 10 s. A twin's distinct-state count is what TLC had explored when its workers met the violation, so it varies a little between runs while the trace does not; a depth counts TLC's initial state. The three failures of §10 as written (6.1) appear in `GkmTwin-PointerByRef` (the second Welcome of a last-resort KeyPackage has no pointer), `GkmTwin-FormsUnchecked` (a reader of A claims A's next generation under B's scope) and `GkmTwin-GenWrapIgnoresRoster` (the read_only leaf's self-update hands the removed leaf the REMOVE generation), and are gone in the design: the design runs hold every invariant at the same and larger bounds, with the same log alphabet, devices at every combination of tips, concurrent commits and rotations from every leaf and the agent, deliveries in every order, lost state, resyncs and the recovery self-join. The five design-rule twins show what each fence is for: without R2 at the claim (`ClaimBelowParent`), R6's pin (`LateBelowClaimPin`), R5 (`LeafWrapDirtyTree`), R4's exception (`SelfJoinCarriesGenWrap`) or R7 (`NoGate`), a removed leaf reads what the design keeps from it.

### 6.4 Cost

Against D-KEYS-14's table, which §22.8's `groups` benchmark (KEYS-M2-31) measures; RFC 9420's structures on suite 0x0010, X-Wing public key 1,216 B and ciphertext 1,120 B, Ed25519 32 B and 64 B, credential 207 B:

```text
tree          leaf 1.54-1.57 KB (X-Wing encryption key 1,216, signature key 32, credential 207, capabilities
              and extensions ~50, signature 64); parent 1.25 KB plus 4 B an unmerged leaf; so 10 leaves
              16-27 KB, 100 leaves 158-282 KB, 1,000 leaves 1.58-2.83 MB (parents blank .. full), which is
              D-KEYS-14's 2.83 MB and stands: nothing here adds a node
commit        a path commit updates log2(leaves) levels, each a new X-Wing key and one ciphertext (1,120 B
              plus a 48 B sealed path secret) per node of its copath resolution: every parent full, ~2.4 KB
              a level, 26 KB at 1,000 leaves; every parent blank, the top level's resolution is ~500 leaves,
              1.18 MB; an Add-only commit 0.2 KB plus 2.85 KB a joiner; a PrivateMessage adds ~100 B of
              framing; the GkmCommitHeader 50 B; GenWrap 72 B; the inline GroupInfo at ≤ 16 leaves under
              50 KB
Welcome       0.4 KB plus 1.2 KB a joiner (one X-Wing ciphertext each), no tree: the joiner takes the tree
              from the sealed GroupInfo (0.7 MB at 1,000 leaves, one GET)
pointer       GkmWelcomePointer grows by the 32 B ref; one object per (recipient, group, epoch) as before
owner marker  one 40 B object per group, written once; one GET per group per gkm process, then cached
rotation      GenRotate ~0.5 KB (1.7 KB with a drop key); ReaderWrap ~1.37 KB staged, ~1.42 KB late;
              RecoveryWrap 1.17 KB; a leaf rotator with a clean tree stages one 72 B leaf_wrap for every leaf
              and a wrap per agent, Delegation and recovery binding; a wrapped rotator, or a leaf whose tree
              holds a dropped leaf, a ReaderWrap per leaf: 1,000 leaves cost ~1.37 MB of staged objects,
              ~45 batched requests (QD-066) and ~9 KiB a drive per object (§11.13); the config and directory
              groups at a 5,000-admission Team: ~6,000 objects, ~7.5 MB, as §10.15 sizes it
memory        one tree loaded at a time (§10.5): 2.83 MB at 1,000 leaves; a path commit clones the tree and
              the key schedule before it stages (mls_group.go), ~6 MB transient, plus ~1.2 MB of path
              material in the blank-parent case; a Welcome join holds the sealed GroupInfo (0.7 MB) and the
              tree it decodes (2.83 MB); so a 1,000-leaf group peaks under ~10 MB on a phone, within §18.4's
              budgets, and KEYS-M2-09 logs the allocation totals KEYS-M2-31 turns into a sampled peak;
              the pending engine's record and pins are under 1 KB a repo; a 1,000-generation ladder is
              ~0.5 MB of Signed GenRotates beside 32 KB of keys
store         per §10.6's table, unchanged for commits (4 GETs and a PUT), rotations (1 GET, W PUTs, 1
requests      claim), Adds (claim, delete, Welcome, pointer, group-info) and late wraps; plus: creation and
              re-form +1 PUT (the marker); group resolution +1 GET per group per process (was a form read
              per 5 s); H1 adds at most one hint a minute per group with a dropped holder, on Redis only;
              H2 one GET a minute per waiting leaf; a self-update after a last-resort join is one commit
              more per such join
time          a 1,000-leaf path commit: ~10 X-Wing encapsulations and ~10 decapsulations a member in the
              full-parent case (under 1 ms each on a 2020 phone core), ~500 at the top level in the blank
              case (~0.5 s, which the js/wasm leg yields across, KEYS-M4-01); a 1,000-leaf tree hash ~1 ms
```

### 6.5 Failure modes and recovery

```text
a commit a member refuses   the object stands; the member alarms (refused, naming committer and epoch), adopts
                            nothing, seals nothing to the generation it carried; honest committers never make
                            one (R3 at the committer), so this is a bug or a compromised leaf; repair: a writer
                            leaf's Remove of the committer, a REMOVE rotation (6.2.4), and the refusing
                            members process on from the repaired chain, or an admin re-forms the group
                            (KEYS-M2-25); content sealed to the poisoned generation re-checkpoints at its
                            next write (§11.7)
a dropped leaf stands       (a wrapped writer rotated; every leaf offline or read_only) reads continue, the
                            gate is open, read_only self-updates and every resync wait (R3); H1 hints the
                            writer leaves each minute until one commits the Remove; a read_only leaf whose
                            self-update waits past stale_leaf_days is removed as stale and returns by resync,
                            which waits on the same Remove; no leak, since no epoch wraps the new generation
                            into that tree
a lost Welcome              the uploader crashed between epoch/<n> and welcome/<n>: a writer leaf sees no
                            Welcome after WelcomeTimeout, removes and re-adds the joiner; a slow uploader's
                            late Welcome lands at its own pointer key and the joiner takes the newer one
a lost claim                staged objects with no gen/<g>: GC after 24 h; the rotator resumes from its draft
                            with the same bytes, or finds another's claim and judges it
a 412 that does not cover   the loser fetches its delivery of the winner (a late ask if it has none), then
                            rotates again at g+2 for what the winner left uncovered
a rotator ahead of gkm      403 at the claim (auth gkm's state has not reached): retry when gkm's state
                            arrives (§8.9's 5 s), a time refusal when the clock moves
a generation no holder can  every delivery to a lapsed key: the holder publishes a new ReaderKey and asks; any
open                        holder but a read_only one delivers (15 min, then 64 others); a leaf also takes
                            the next GenWrap; nothing is lost, since the ladder opens downward from any later
                            generation it gets
gkm down (KF7)              reads and deposits from the keychain; writes while covered; joins, rotations,
                            deliveries wait on the hint intake's resync
a device far behind         KF5's resync from the newest GroupInfo under the generation it names, which a late
                            delivery gives; above 16 leaves, one leaf online writes the GroupInfo on the ?want=
                            hint
a device with lost state    resync (its leaf stands) or, with the keychain gone, the member's recovery code
                            (6.2.4's Recovery), or an admin's re-add after revocation
a group-id collision        409 at the owner marker: the creator draws another id; a re-form naming a taken id
                            is refused and the admin re-forms with a fresh one
a squatting form            refused at the marker (409); nothing written
a re-formed group's first   refused until gen/<form.generation> exists (plan-KEYS-reform-ladder rule 5); the
commit                      re-former uploads the ladder first, then commits
site loss                   D-KEYS-13: a repo admin's device re-forms from its keychain (RK_g and the Signed
                            GenRotates), the marker and form first; readers re-add by KF2 and late wraps
a fork at any pin           head_alarm (fork) with both values; sealing stops in that repo until the chain
                            extends the pin; §6.4's HeadCheck relays it
```
### 6.6 The test plan

Unit tests (sidecar root, each a top-level `func TestXxx`, on `FakeMls` then the real subset, fake clocks and barriers only, `testHookSecret` at every key and `testHookBarrier` at every claim and epoch PUT):

```text
TestACommitCarriesEveryPendingRemove             a writer leaf at a state past two revocations commits one Remove of
                                                 both with its Add; a member refuses the same commit made without
                                                 them (R3) and alarms refused naming the committer
TestAReadOnlyLeafWaitsWhileADroppedLeafStands    after a wrapped rotation the read_only leaf's due self-update
                                                 waits, asks H2, and commits once a writer leaf's Remove lands; the
                                                 twin's commit, injected, is refused by every member
TestAResyncWaitsWhileADroppedLeafStands          KF5's external commit waits under R3 and lands after the Remove
TestNoEpochWrapsAGenerationToANonHolder          over generated runs (revocations, rotations by leaves and the agent,
                                                 commits from every leaf, resyncs, the self-join), every stored
                                                 epoch's tree lies within the holders of the generation its GenWrap
                                                 carries, and Reach of each removed device, computed as the model
                                                 does from the fake store, stays below the first generation after
                                                 its drop
TestARotationsClaimNeverFallsBelowItsParent      a rotator at a stale tip refuses to claim (ErrGkmAuthAhead) and
                                                 gkm refuses a claim whose auth is below gen/<g>'s
TestALateDeliveryIsSignedAtOrPastTheClaimsPin    a holder behind the claim does not deliver; one at the pin does; a
                                                 LATE delivery below the pin, injected, is refused by gkm and
                                                 judged invalid by members
TestALeafWrapNeedsACleanTree                     a leaf whose tree holds a dropped leaf rotates by ReaderWraps to
                                                 every leaf; with a clean tree one leaf_wrap; the removed leaf opens
                                                 neither
TestARecoverySelfJoinCarriesNoGenWrapOverLostLeaves
                                                 generation 0 while the lost devices' leaves stand, generation g*
                                                 with a clean tree; the recovered device's next commit removes them
                                                 and the rotation after is the first new generation (FS-20)
TestAWelcomePointerIsKeyedByGroupAndEpoch        a device whose last-resort KeyPackage served two Adds in two groups
                                                 holds two pointers and joins both; two Adds of one device in one
                                                 group (the 10-minute re-add) leave two pointers and it joins the
                                                 newer; a pointer at or below its reached epoch is skipped
TestALastResortJoinSelfUpdatesAtOnce             the joiner's first commit after a last-resort join is a path-only
                                                 commit, and its next upkeep pass replaces the last-resort
                                                 KeyPackage
TestAGroupBelongsToOneRepo                       a form for B naming A's group answers 409 at the marker and writes
                                                 nothing; a B-scoped token reaches none of A's routes; equal bytes
                                                 resume a crashed creation; the shred deletes the marker and a
                                                 re-seed's form writes it again
TestAReformsFirstCommitFloorsAtTheFormsGeneration
                                                 epoch 1 of a re-formed group is refused below gen/<form.generation>'s
                                                 auth and before the ladder reaches that generation
TestEnsureWritableCommitsThenRotatesThenRefuses  the four steps in order on a fake clock: pending changes committed,
                                                 a REMOVE rotation when uncovered, SCHEDULE at 30 days, ErrGkmWait
                                                 while uncovered at my state with evs's gate off
TestKeyAccessWalksTheLadderFromAnyHeldGeneration RepoKey(g) from a newest held generation through cached and fetched
                                                 GenRotates; a wrong C_g, GenLink, AAD width or cause refused; gen/1
                                                 with cause REMOVE refused
TestPinsNeverFall                                a lower or conflicting epoch or generation pin from a push, a head,
                                                 a GenRotate or a HeadCheck peer raises head_alarm (fork) and stops
                                                 sealing; the chain extending the pin resumes it
TestDropKeyFollowsTheDepositorRule               FS-23's M2 half as a unit: an older unexpired GenRotate after a
                                                 removal refused with evs's gate off; a lapsed drop key waits
TestTheLadderAadWidthsArePinned                  testdata/gkm/ladder.json byte-equal on every leg (exists; gains the
                                                 gen/1 cause row)
```

Schedule rows (KEYS-M2-27 to -29, KEYS-M4-01), each with its success twin and `ApplyThenDrop` where a write is involved: FS-15 gains "a wrapped rotation while a leaf stands, then the read_only leaf's self-update waits under R3, the writer leaf's Remove releases it, and the removed leaf opens nothing of g+1", "a resync waiting on the same Remove", "a claim at a stale tip refused" and "two Adds of one device through its last-resort KeyPackage in two groups, both joined"; FS-20 gains "the self-join's generation 0 only while the lost leaves stand" and "a kill between the owner marker and the form, then the form and epoch/0, resumed with equal bytes"; FS-24 gains "H1's pending hint while a dropped holder precedes the newest epoch's pin, stopping at the first commit past it" and "H2's want from a waiting leaf"; FS-103 gains "a LATE delivery whose signer's state trails the claim refused, and one at the pin accepted"; FS-104 gains the twin's injected commit "refused by every member and the oracle, the carried generation poisoned"; FS-6 and FS-41 gain the marker (deleted at a shred, written by a re-seed's form, refused for another repo); FS-97's leaf legs gain "a stale Remove of a page Worker whose tree holds a dropped leaf carries that Remove too". §22.7's committers block gains "a squatting form refused" and "a last-resort join's immediate self-update".

Model twins the tasks add to `Gkm.tla` (new twin values and stories; the file's own tests are the configurations in `run-gkm.sh`): KEYS-M2-19 adds `MembersSkipRosterCheck` (members adopt a commit whose tree breaks R3, which must break `RemovedReadsNothingNew` as `GenWrapIgnoresRoster` does, reached from an injected commit rather than a read_only leaf's); KEYS-M2-20 adds `StagedToNonHolder` (a rotation stages a delivery to a party outside its holder set, `RemovedReadsNothingNew`) and `AdoptNonCoveringWinner` (the 412 loser adopts and seals to a winner that does not cover its shrink, `NoContentToDropped`); KEYS-M2-21 adds `AddWithoutRemove` (an Add commit that leaves a dropped leaf, `RosterWithinHolders`); KEYS-M2-24 adds `RecoverBeforeAnchor` as a story under a lying-store flag if one is added, else a unit test; KEYS-M2-25 adds `FormWithoutMarker` (`GenerationsFromWriters`). Each twin names the invariant it breaks, as the configurations here do.

mlsinterop vectors (KEYS-M2-11's artifact, §22.10's ladder row): `ladder_test.go` gains the gen/1 cause byte (REQUEST, 0x02) in GenLink's AAD and a GenWrap of a generation-0 self-join's epoch (none: the row records that epoch's GenWrap is empty and its GroupInfo seals under `group_info_generation`); `testdata/gkm/wrap_paths.json` gains `gkm/welcome/<sidecar_id>/<group_id>/<n>` and `gkm/<group_id>/owner`; the stacks row's lifecycle gains a join through a last-resort KeyPackage (tmc/mls sends `last_resort` 0x000A) followed by the joiner's path commit, so both stacks agree on the extension's number and placement; and a GroupInfo with `ratchet_tree` from a tree holding a last-resort leaf.

### 6.7 Implementation notes, task by task

Order: the formats first (KEYS-M2-19's branch carries the proto and path changes, since every later task reads them), then member checks (-19), rotation and deliveries (-20), the engine and flows (-21), key access (-22), sync and pins (-23), recovery (-24), re-form (-25), the commands (-26), then the schedules (-27 to -29), sizes (-31) and the page Worker (M4-01).

**Landed code that must change** (sidecar root unless said):

```text
protocol/gkm.proto             GkmWelcomePointer.key_package_ref = 3; new GkmGroupOwner{repo_id = 1; network_id = 2};
                               the GkmEpochObject comment at epoch 0 of a re-form: "no auth; epoch 1's floor is
                               gen/<form.generation>'s"; testdata/gkm/metadata_rows.yml rows for both (gkm-1, gkm-5)
gkm_paths.go                   GkmWelcomePointerPath(sidecarId, groupId, epoch), GkmGroupOwnerPath(groupId); the
                               wrap_paths.json vectors gain both
gkmservice/welcomes.go         pointers at the new key; the collision count and alarm go; the Welcomes listing reads
                               the ref from the pointer
gkmservice/groups.go           the owner marker as the first write of a creation and a re-form, 409 on other bytes;
                               the LIST goes; GET /gkm/groups/<id> and every group route resolve through the marker
                               (a new gkmGroupOwners cache, immutable entries); the re-form's epoch 0 unchanged
gkmservice/epochs.go           the epoch PUT check's floor for epoch 1 of a re-formed group: gen/<form.generation>'s
                               auth, read through generations.go's accessor; the fail-closed refusal of a pinless
                               previous epoch narrows to that case
gkmservice/reconciler.go       H1: pending hints while a holder dropped since the newest epoch's pin and time, from
                               the same state watch; H2's want is groupinfo.go's existing hint
gkmservice/shred.go            deletes gkm/<group_id>/owner with the group's objects
gkmservice/objects.go          the owner family in the key inventory
sidecartest/fake_blobs.go      path-prefix rule (EVSB's file: raise with the question, not an edit; until then
                               KEYS-M2-13's filter stays)
sidecartest/fake_gkm.go        FakeGkm gains the roster rule's effect for FakeMls trees: a client's rotation uses a
                               leaf_wrap only on a clean tree, and EnsureWritable's step 2 runs the pending engine
                               (KEYS-M2-21's seam) before it rotates
gkm_upkeep.go                  after a last-resort join: replace the last-resort KeyPackage at the next pass
                               (KEYS-M2-23 reports the join to upkeep through GkmUpkeepRole)
mls_extension.go, gkm_keys.go  unchanged: 0x000A and the widths stand as built
```

**KEYS-M2-19 (member checks).** Build first, with the format changes above on its branch. `CheckCommit(view, group, staged, header)` runs §10.9's committer and check rows at `header.auth` (`GkmAuthView.At`, waiting with `ErrGkmAuthAhead`, fork on `ErrGkmAuthOffChain`), then R3: `staged.Added()`, `Removed()` and the new roster against `KeyHolders(view.At(header.auth), repo, header.time)`, the generation-0 external-commit exception for a recovery-admitted uploader only; then R4: `header.generation` at or past the previous epoch's and its GenWrap opening to `gen/<g>`'s `C_g`. Stale Removes by the owner's rule (`UrMlsCredential.not_after - 90 d + stale_leaf_days <= my clock + 60 s`, read from the prior epoch's tree), in one function `gkmStaleRemoveValid`. `CheckRotation` is §10.9's rotation checks with R2 (auth and time at or past the parent's); `CheckDelivery` the delivery checks with R6, judged at the delivery's own state. The poison verdict: a type `GkmVerdict{Refused bool; Poisoned uint64 (generation); Reason}` the engine and sync read. Tests: one refusal and one success per row, the R3 cases above, S3's forged admission, KeyPackage and ReaderKey; the oracle (KEYS-M2-29) stays separate code.

**KEYS-M2-20 (Rotate and late deliveries).** 6.2.4's Rotate as one code path for every cause and rotator, `persist draft` through the keychain's `gkm/<repo_id>/draft` item, batched staging through `GkmApi.UploadWraps` and `UploadRecoveryWraps`, the claim through `ClaimGeneration` with `testHookBarrier` around it, and the 412 branch with `CheckRotation` and the cover test (`GkmGenerationCovers` against what this rotation rotates for). R5's leaf case from `MlsGroup.Roster()` against H. `drop_public_key` and `drop_not_after_ms` for kinds that take deposits or an inbox (RESOLUTIONS plan-KEYS-drop-key-lifetime and plan-MAIL-group-inbox). Late deliveries as 6.2.4's deliver, with R2's `tip >= gen/<g*>.auth` precondition and the readerkey check; `dwraps` for a Delegation's signer. Tests: KEYS.md's list plus 6.6's rotation rows; a kill before and after each step resuming from the draft.

**KEYS-M2-21 (membership flows).** The pending engine as 6.2.4 (one `gkmGroupManager` per group, single-flight, inputs `AuthAdvanced` and the hint intake's `pending`, `welcome` and `wrap-pending` handlers), with `Pending(S, e)` as a pure function (`gkm_members.go`) the tests and the oracle can call, `may(c)` from §10.9's committers, seats from §8.12 (`gkm_seats.go`, reusing §7.9's leaves rule for the config and directory groups), KF1 as the state machine with its keychain draft and the `activate` call after the deliveries, KF2/KF3 through the engine, KF4 through the engine then `Rotate`, KF6's loser path, the `WelcomeTimeout` re-add, and the owed-Welcome record. `GkmClient.CreateGroup` and `AuthAdvanced` land here; `EnsureWritable`'s step 2 calls `Run(c)`. Tests: §22.5's KF1 to KF4 and KF6 on `FakeMls` then the real subset, the engine's R3 cases, a kill at each KF1 step, a repo never activated before its recovery wraps exist, the two-group last-resort join.

**KEYS-M2-22 (key access).** 6.2.5 as written, over the keychain's `gkm/<repo_id>/gen/<g>` items (RK_g with the Signed GenRotate bytes, plan-KEYS-reform-ladder rule 2), `gkm_ladder.go` walking down through cached or fetched GenRotates with `OpenGkmLadder`, `EnsureWritable`'s four steps, `DropKey` over `GkmApi.DropKeys`, `ForgetRepo`, and the late ask (`GkmLateAsks`, landed in gkm_api.go) driven from a `wraps` fetch that finds nothing for a held key. The checkpoint signal is `EvsRepoKey.Cause()` (landed). Tests: 6.6's key-access rows; FS-23's half; a pin that never falls.

**KEYS-M2-23 (sync, pins, HeadCheck).** 6.2.6: KF5 with R1-R4's preconditions and the R3 wait with H2; self-updates with the wait; `gkm_pins.go` keeping `gkm/<repo_id>/pins` and answering `GroupHead` and `GenHead` to PROTO-M2-02's HeadCheck (its `SealAllowed` and `ReportFork` seams, PROTO-M2-04); the commit-hint handler (fetch `epochs?after=`, Process each); acks through upkeep's `AckGroups`; the last-resort join's immediate self-update and its report to upkeep. Tests: KEYS.md's list plus 6.6's pin and wait rows; replay at 100 and 101 epochs; a fork at one epoch alarming.

**KEYS-M2-24 (recovery).** 6.2.4's Recovery with its states persisted (`gkm/<repo_id>/pending` carries the recovery phase), the generation-0 self-join exactly when the tree holds a non-holder at the device's tip, the ordinary external join otherwise, the next commit's removes through the engine, then `Rotate`; the restored order; the rebind's re-wrap and delete order. Tests: §22.7's recovery rows and 6.6's self-join row; FS-20's and FS-22's cases run in -27 and -28.

**KEYS-M2-25 (re-form and re-seed).** No longer blocked: plan-KEYS-reform-ladder is decided and 6.2.2 settles epoch 0's floor and the marker. Build `gkm_reform.go` (the re-former's form, marker, epoch 0, ladder upload in ascending batches of 64, re-adds and wraps) and `gkmservice/reform.go`'s ladder route (QD-074's checks) and the floor rule. Tests: FS-6's gkm legs, a re-form refused from a non-admin device, a member refusing a mismatched C_g, a re-form naming a taken group id refused at the marker, FS-41's group legs on T3.

**KEYS-M2-26 (`ur keys rotate`, `ur evs rekey`).** Unchanged in scope; `RotateRepo` is `Rotate` with cause REQUEST, REMOVE only if one is due (`GkmRotationRemoveRequired`).

**KEYS-M2-27, -28, -29 (schedules).** As the plan has them, plus 6.6's added rows; -29's `DeliveryOracle` judges from the log and the fake store alone and, for FS-104's new case, computes `Reach` as the model does; FS-15's wrapped-rotation-then-read_only-self-update case is the schedule that shows the leak twin refused on real code.

**KEYS-M2-31 (sizes).** As the plan has it; the table gains the owner marker and the new pointer, and the memory row measures the join and path-commit peaks 6.4 estimates (a sampled peak on the ios32 surrogate, not allocation totals).

**KEYS-M4-01 (page Worker and stale leaves).** The group view §7.10's stale row needs (`SidecarStaleGroupView`'s real implementation over the engine's `Pending` and the credential `not_after` rule), the yield points, and the read_only leaf's R3 wait: a Worker whose self-update or resync waits must not count as stale for that reason alone (its leaf's credential is what the stale rule reads, so a Worker that cannot commit because a dropped leaf stands is removed only after stale_leaf_days, as any quiet leaf, and returns by resync once the Remove lands). FS-97's leaf legs as 6.6 adds them.

Scope changes: KEYS-M2-25 loses its "blocked on the question" clause; KEYS-M2-19 gains the proto and path changes; KEYS-M2-21 gains the pending engine's R3 and the WelcomeTimeout re-add as named parts; KEYS-M2-23 gains the R3 wait and H2; no held task loses scope.
### 6.8 Proposed DESIGN.md text

For the design-records track, section by section; each replaces the sentence or row named.

**§10.4, the credential block.** Add: "A last-resort KeyPackage carries draft-ietf-mls-extensions' `last_resort` extension, type 0x000A with empty extension_data, in its own extensions, and every leaf lists 0x000A and 0xF553 in its capabilities; a device that joined through it commits a path-only self-update at its first opportunity and replaces it at its next upkeep pass."

**§10.5, the hierarchy block.** After `GroupInfo_e` add the widths: "GenLink's AAD is repo_id || u64be(g) || u8(cause_g), GenWrap's and LeafWrap's group_id || u64be(e) || u64be(g), GroupInfo's group_id || u64be(e); gen/1 carries cause REQUEST." In Rotate's step 3 `leaves` row, after "else a ReaderWrap to each leaf's ReaderKey" add "(a leaf_wrap never uses an epoch whose tree holds a non-holder)".

**§10.6, the object table.** Replace the `gkm/welcome/<sidecar_id>/<ref>` row with `gkm/welcome/<sidecar_id>/<group_id>/<n>`, "with the Welcome; pointer {group_id, n, key_package_ref}; one per Welcome, so a last-resort KeyPackage's Welcomes never share a key; a device holding several for one group takes the highest n above the newest epoch it reached". Add a row `gkm/<group_id>/owner`, "If-None-Match, the first write of a creation or re-form; {repo_id, network_id}, written by gkm from the token; the only binding of a group to its repo, through which every group route resolves; deleted by the shred". In the checks row replace "whose newest GroupForm names the group" with "which gkm/<group_id>/owner names, among the token's scopes, and whose newest GroupForm names the group". In the Welcomes row replace "joiners get a pointer and a welcome hint" with "joiners get a pointer, keyed by group and epoch, and a welcome hint". In the epoch PUT check add: "never below the previous epoch's, or, for epoch 1 of a re-formed group, below gen/<the form's generation>'s auth, since a re-form's epoch 0 carries none". Add to the pending changes row: "and every 60 s while its newest verified state shows a holder dropped since the group's newest epoch's auth pin and time, so a leaf commits the Remove a wrapped rotation left".

**§10.6, the keys rule.** In the object table's note add: "§11.8's 'no key prefixes another' is a path prefix, so `<ref>` beside `<ref>.claim` stands."

**§10.7, KF2.** After "a committer per 10.9 claims a KeyPackage and commits the Add with other pending changes" add "(every Remove it may commit among them, so the new tree lies within the key holders at its pin)". KF5: after "resyncs by external commit" add "once its tree holds no dropped leaf but its own old one, waiting otherwise for a writer leaf's Remove, which gkm hints".

**§10.9, the roster row.** Replace with: "roster: every commit's new tree lies within the key holders at its auth pin, and in the config and directory groups within the leaf-entitled devices (§7.9), except a recovery self-join's revoked leaves (10.8), whose generation-0 epoch has no GenWrap; a committer checks this before it commits and carries every Remove it may, a leaf that may not commit one (read_only; an external commit) waits while its tree holds a dropped leaf, and a member refuses a commit that breaks it, never adopting its epoch and treating the generation its GenWrap carried as poisoned; so no epoch wraps a generation to a tree holding a party that generation excludes, and no leaf wrap uses such an epoch". Self-update row: add "deferred while the leaf's tree holds a dropped leaf it may not remove". External commit row: add "and waits under the roster row while its tree holds another dropped leaf".

**§10.11.** D-KEYS-18 gains "KF1 writes the group's owner marker before its form"; D-KEYS-24 gains "a Welcome pointer is keyed by (recipient, group, epoch)"; new **D-KEYS-27 (proposed):** "Every commit's new tree lies within the key holders at its pin, checked by the committer, which carries every Remove it may, and by every member; a leaf that may not commit a Remove waits while its tree holds a dropped leaf, and gkm hints writer leaves meanwhile. *Why:* an epoch that wraps a generation to a tree holding a removed leaf hands it the generation that excludes it, whatever honest members then do." New **D-KEYS-28 (proposed):** "A group belongs to one repo from its first byte: gkm/<group_id>/owner, created If-None-Match before the GroupForm, names the repo through which alone gkm resolves the group. *Why:* a form naming another repo's group would give a reader a write position there."

**§10.14, routes.** `POST /gkm/groups` and `/forms` gain "writes the owner marker first; 409 when it names a taken group id". The object list in Provides gains the marker and the pointer's key.

**§2.8.** gkm-1's `sees` gains "and each group's owner marker (repo_id, network_id)"; gkm-5's gains "pointers keyed by recipient, group and epoch, naming the KeyPackageRef the Add used".

**§22.7 and the FS rows.** The cases 6.6 names: FS-15, FS-20, FS-24, FS-103, FS-104, FS-6, FS-41, FS-97 and the committers block.

**§23.8.** No change: the fields freeze with the gkm wire at M2's exit (D-KEYS-10), these among them.

### 6.9 Owner questions

Each is filed under `.stack/questions/` in the brief's format; the section is built on the recommendation in every case.

**details-6-last-resort-extension** (keys-m2-07-last-resort restated). Which extension marks a last-resort KeyPackage? Options: (1) draft-ietf-mls-extensions' `last_resort`, 0x000A, empty, as built; (2) a private-use type beside ur_group, 0xF554; (3) no extension, the route or key says. Costs: (1) a draft's number, moved by D-KEYS-12's migration if IANA changes it, and the one value OpenMLS sends; (2) stable, read by no other stack; (3) changes QD-526's accepted request and gkm-4. Recommendation: (1).

**details-6-welcome-pointer-key** (keys-m2-13-last-resort-welcome-pointer restated). Options: (1) key pointers by group and epoch, `gkm/welcome/<sidecar_id>/<group_id>/<n>`, the ref inside the pointer; (2) `<ref>` for one-time and `<ref>/<group_id>` for last-resort KeyPackages; (3) keep the key, overwrite, and re-add after 10 minutes. Costs: (1) one key-form change, one proto field, gkm-5's wording; (2) two key forms and a path-prefix pair; (3) a lost Welcome per collision and a 10-minute delay. Recommendation: (1).

**details-6-group-owner-marker** (keys-m2-12-groupform-names-anothers-group, widened). Options: (1) an owner marker `gkm/<group_id>/owner` written If-None-Match before the form, the only binding gkm resolves by; (2) the question's option 1, a LIST before the form; (3) accept the reach. Costs: (1) one 40 B object per group, a §2.8 line under gkm-1 (no new value: the pair is already shown), one GET per group per process, and the landed LIST goes; (2) a LIST per form and a race between a repo's form and its epoch/0 in which two newest forms name one group and the resolver must refuse both; (3) any reader can wedge another repo's rotations. Recommendation: (1).

**details-6-claim-key-prefix** (keys-m2-13-claim-key-prefix restated). Options: (1) §11.8's rule means a path prefix and `sidecartest/fake_blobs.go` checks that; (2) move claims to `gkm/kpc/`; (3) exempt `.claim` in the fake. Costs: (1) one change in EVSB's file and a sentence in §11.8; (2) a key-form change and QD-442; (3) a special case. Recommendation: (1); until answered KEYS-M2-13's filter of the one report stays.

**details-6-ladder-aad-widths** (keys-ladder-aad-widths restated). Options: (1) as built, u64be for g and e, u8 for cause, gen/1 REQUEST; (2) u32be for cause; (3) gen/1's cause free. Costs: (1) text only; (2) one line and regenerated vectors; (3) a reader rule for two shapes. Recommendation: (1).

**details-6-reform-epoch-zero-floor** (keys-wire-reform-epoch-zero restated). Options: (1) as landed, no auth at a re-form's epoch 0, epoch 1's floor from gen/<form.generation>'s auth; (2) a Signed GenRotate in the reform request; (3) epoch 0 through the epochs route after the ladder. Costs: (1) one sentence in the epoch PUT check; (2) the same bytes twice and a ladder check; (3) a special case on the epochs route and a third route in deleted mode. Recommendation: (1).

None blocks the held tasks: every one is additive before M2's freeze, and each task above builds on the recommendation.

## 7. Remote search across designated indexers (§11.14, §18.4)

Status: pending

Tasks held until complete: SEARCH-M10-19, SEARCH-M10-32, SEARCH-M10-33.

## 8. Git and evs in both directions

Status: pending

Tasks held until complete: EVS1-M2-34, EVS1-M2-35, EVS1-M2-36.

## 9. Client path epochs and re-tokenizing

Status: pending

Tasks held until complete: EVS1-M2-28, EVS1-M2-29, EVS1-M2-30.

## 10. DROP lists a phone can check (§11.6, §11.7, §11.9)

Status: pending

Tasks held until complete: EVS2-M10-09, EVS2-M10-10, EVS2-M10-22, EVSB-M10-03, EVSB-M10-04.

## 11. Canonical text extraction and exact body sizes for search

Status: pending

Tasks held until complete: SEARCH-M10-31, SEARCH-M10-36.

## 12. Bridge compiler and NAT engine (§17)

Status: pending

Tasks held until complete: BRIDGE-M4-16, BRIDGE-M4-17, BRIDGE-M6-03, BRIDGE-M6-04.

## 13. Smaller scheduling problems: closure pacing, quota leases, socket registration

Status: pending

Tasks held until complete: QUOTA-M2-07, SOCK-M5-05, SOCK-M5-06, SOCK-M5-07.
