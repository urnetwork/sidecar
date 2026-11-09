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
| 5 | Authorization-log verdicts across folds (§7.9) | 13 | in progress |
| 6 | MLS group key management (§10) | 13 | pending |
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

Status: in progress

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

**The model.** `sidecartest/model/details/AuthLog.tla` keeps the log as its one shared object and three verifiers as variables derived from it: `L`, the long-running full reader and writer; `N[b]`, a new full device started at each base b; and `G`, the rows-only gate cold-started at the newest base, which is what api sequences by. It models admissions with signers, carrying position, the signer's `at`, confirmations, parks and revocations; one Delegation with `max_admits`; recovery bindings, recovery-signed proposals, the 72 h window, vetoes and ticks; AuthorityProposals and cosigns at threshold K; the compromise cascade with consent (§8.5), voids of bindings and Delegations and the parks a Delegation's end makes; the replay ring and the `at` rule with the retention point; and bases with `folded_through`, head-derived rows (`self_admit`, a tag's owner), tail verdict bits and, under `Adversary`, a lie. It leaves out presence countersignatures, read_only, `not_after` expiries, EvsShares, key registrations, leaf ranks, the head's own chain and api's reap ticks. The clock is the position. `Twin` selects a rule to break: `JudgeTail`, `NoProposalRows` and `NoSettingsRows` are §7.9 as written on 2026-11-09 and `CloseAtBase` the landed code; `ReJudgeTail` (the question's option 2), `NoRingRows`, `CascadeFromAt`, `NoBitsCheck` and `NoTailCap` each break one rule of this design. `Story` fixes a twin's entries so TLC reaches its violation directly; the design runs with none. `run.sh <track>` runs every configuration through `.stack/tools/tlc` and prints a verdict line per run.

Runs, TLC at the owner's jar (master d8fb231), bounded so each finishes; breadth-first, every reachable state at the bounds:

```text
configuration            Twin           K  bounds (Window 4, TailMax 4, RecoveryWindow 2, Life 5, MaxAdmits 2)
                                           result                                   distinct states  depth  time
AuthLog                  none           2  MaxN 4, MaxBases 2, no story, no adversary
                                           pass, every invariant                      1,725,243      5      1 min 44 s
AuthLog-K1               none           1  the same at k = 1
                                           pass, every invariant                      4,061,811      5      6 min 22 s
AuthLog-Adversary        none           2  MaxN 4, MaxBases 2, Adversary: api sequences refused statements and a
                                           writer may lie in a base
                                           ADVERSARY-ROW
AuthLog-Narrow           none           2  MaxN 5, MaxBases 2, Narrow: one at and one since_n a statement
                                           NARROW-ROW
Twin-JudgeTail-Head      JudgeTail      2  StoryTailHead, MaxN 2      Agreement violated, 3-state trace    3    3
Twin-JudgeTail-At        JudgeTail      2  StoryTailAt, MaxN 3        Agreement violated, 3-state trace    3    3
Twin-NoProposalRows      NoProposalRows 2  StoryProposals, MaxN 3     Agreement violated, 3-state trace    3    3
Twin-NoSettingsRows      NoSettingsRows 2  StorySettings, MaxN 3      Agreement violated, 4-state trace   11    4
Twin-NoRingRows          NoRingRows     2  StoryRing, MaxN 6          Agreement violated, 7-state trace   75    7
Twin-ReJudgeTail         ReJudgeTail    2  StoryReJudge, MaxN 3       RevocationsStand violated, 4 states  4    4
Twin-CascadeFromAt       CascadeFromAt  1  StoryCascadeAt, MaxN 2     CascadeClosed violated, 3 states     3    3
Twin-NoBitsCheck         NoBitsCheck    2  StoryLie, MaxN 2, Adversary Agreement violated, 3 states         3    3
Twin-NoBitsCheck-Forks   NoBitsCheck    2  the same                   LiesAreForks violated, 3 states      3    3
Twin-CloseAtBase         CloseAtBase    2  StoryClose, MaxN 3, Adversary ProposalsSurviveFolds violated   14    4
Twin-NoTailCap           NoTailCap      2  StoryTailCap, MaxN 3, TailMax 1 TailBounded violated, 4 states  6    4
```

Each twin run took under 5 s. A twin's depth counts TLC's initial state, so a 3-state trace is two entries. The design runs explore every log the candidate alphabet allows at their depth (about 37 enabled entries a position at MaxN 4); a run one entry deeper multiplies the states by that, which is why the deeper run narrows the alphabet instead.

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

Status: pending

Tasks held until complete: KEYS-M2-19, KEYS-M2-20, KEYS-M2-21, KEYS-M2-22, KEYS-M2-23, KEYS-M2-24, KEYS-M2-25, KEYS-M2-26, KEYS-M2-27, KEYS-M2-28, KEYS-M2-29, KEYS-M2-31, KEYS-M4-01.

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
