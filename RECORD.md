# RECORD.md: recURd's record semantics

*Draft for review by M2's entry. 2026-11-06. Nothing here is implemented, and nothing here is frozen.*

DESIGN.md §16.8 provides the record's primitives (X20): signed, chained, sealed entries; per-entry keys; approval and reach receipts; run coverage; retention; erasure. This document is owner decision 25's RECORD.md. It holds what sits above them (Q-MCP-1): record semantics, the v1 kind registry with each kind's search text, exports, the verifiable log, disclosure, model receipts (D-CTX-5) and cost. It is reviewed by M2's entry, before format 1 freezes (G0; §23.8). `record.proto` is specified from it at M3's entry, and its bytes freeze at M3's exit (D-MCP-6; §23.8).

**What this document may not change.** §16.8's `semantics` row binds it: the logs' reader and writer matrix (§8.5's kind defaults), per-entry key slots, the source and tainted labels, and approvals bound by `request_sha256` and `payload_sha256`. It cites those and restates none. Where it and DESIGN.md disagree, DESIGN.md wins. Section 16 lists each place this draft found DESIGN.md silent or inconsistent, as a question raised to the owner or a reading taken.

**Reading it.** `§n` cites DESIGN.md, and "section n" this document. Ids take DESIGN.md's forms: `R-RECORD-n`, `D-RECORD-n`, `Q-RECORD-n`. P5, PM, MK2 and REC are DESIGN.md's source keys: design/pitch5.html, design/product.md, design/market2.md and design/reports/Agent work record gaps and features.md. A figure marked "by inference" is an estimate until §22.8 measures it. A passage marked *Pending Q-RECORD-n* states the recommended answer to an open question, and that feature stays off until the owner answers.

## Contents

1. [Purpose and scope](#1-purpose-and-scope)
2. [Requirements](#2-requirements)
3. [What exists today](#3-what-exists-today)
4. [The record model](#4-the-record-model)
5. [Entries](#5-entries)
6. [The v1 kind registry](#6-the-v1-kind-registry)
7. [Search text](#7-search-text)
8. [Retention and erasure](#8-retention-and-erasure)
9. [Exports](#9-exports)
10. [The verifiable log](#10-the-verifiable-log)
11. [Disclosure](#11-disclosure)
12. [Model receipts](#12-model-receipts)
13. [Cost](#13-cost)
14. [Alternatives considered](#14-alternatives-considered)
15. [Decisions proposed](#15-decisions-proposed)
16. [Open questions and readings](#16-open-questions-and-readings)
17. [Departures from the product sources](#17-departures-from-the-product-sources)
18. [Interfaces](#18-interfaces)
19. [Risks](#19-risks)
20. [Phasing and tests](#20-phasing-and-tests)

## 1. Purpose and scope

This document owns the meaning of an entry: which kinds exist, when each is written and by whom, what its body holds, how it reads in search, how long it lasts, and what leaves a log through an export or a packet. It owns no storage, key, tool or policy mechanism.

| Owner | Owns | This document adds |
|---|---|---|
| §16.8 | the envelope, the logs' matrix, chains, erasure, retention, read receipts | kind numbers, bodies, named hashed bytes, class numbers |
| §16.5, §16.6 | the tool catalog, approvals, taint, the use ledger | filters for `record_query`, `run_coverage` and `approval_status`; no new tool |
| §16.7 | capture, redaction, restore | which entries a capture yields |
| §16.10, §11.14 | the search surface, header fields, run cards, the index format | each kind's title, text and claim state |
| §16.11 | the team directory, `directory.proto`, its retention and erasure | numbers for its entry kinds, and their search text |
| §11 | streams, deposits, slots, ERASE, BASE, `ur evs export` | what a deposit carries, and how a record repo exports |
| §20 | quotas and metering | run cost, and the record's own cost in those terms |

Not here: an eval or trace product (PM:47); compliance mappings and a team's own legal holds (RS3; §23.4); the instruction-file writer (§1.7); the feedback service (D-CTX-4).

## 2. Requirements

| Id | Requirement | Source |
|---|---|---|
| R-RECORD-1 | Each action is captured once: the raw session goes to the author's vault, a signed entry to the team's ledger | P5:486; MK2:686-695 |
| R-RECORD-2 | Session contents stay with their author unless shared; admins see actions and approvals, not transcripts; in teams, run titles reach teammates by default; every admin read is visible to the author | P5:579, :640; R-CTX-17; I-20 |
| R-RECORD-3 | Every changed file, by any tool path, is in the run's change set; restore is recorded | P5:622; R-MCP-4 |
| R-RECORD-4 | Each run states what the record could not see | P5:481, :941 |
| R-RECORD-5 | One action id from proposal to execution; high-risk approvals carry an SSH signature | P5:727; R-MCP-6, R-MCP-7 |
| R-RECORD-6 | Admins can answer which agents, harnesses and models touched which repos, for which sponsor | P5:726, :893 |
| R-RECORD-7 | Handoffs, claims and commit-to-run links; handoff notes record decisions, not transcripts | P5:626, :635, :893 |
| R-RECORD-8 | Proof for a client that a person approved a change, without the code | P5:728 |
| R-RECORD-9 | SIEM export, retention, the verifiable log and client packets | P5:898 |
| R-RECORD-10 | A record of the weight digest, quantization and engine, each labeled by evidence level; a hosted model's record stops at harness and model name | P5:766, :779, :781; D-CTX-5 |
| R-RECORD-11 | Per-client cost; agents are never metered, storage and traffic are | P5:845, :849 |
| R-RECORD-12 | The entry format is open, and a person can leave with a clone | P5:576, :662 |
| R-RECORD-13 | An open kind registry that gives each kind's search text and claim state, and a run's context entry the agent label and session ids | §16.8; §16.10; §16.16 |

## 3. What exists today

Nothing is built. The sidecar repo holds documents only. DESIGN.md leaves these hooks here:

| Hook | Where DESIGN.md leaves it | Section |
|---|---|---|
| `RecordHeader.kind` numbers and the open registry | §16.8; `SearchFilters.kinds` (§11.14) | 6 |
| The bytes each hash covers, named at M3's entry | §23.8's `record.proto` row | 5.1 |
| Each kind's text and claim state; the context entry's label and session ids | §16.10; §16.16's assumptions | 7 |
| The body of `announce`, `read` and the other kinds with no message of their own | §16.8; §16.11's M6 carrier | 6.4 |
| `RetentionPolicy.class` | §16.8 | 8 |
| The verifiable log, over §16.8's leaf hashes and order | §16.8; §16.18 | 10 |
| The client disclosure packet | §16.8; §16.18 | 11 |
| Exports; `ur evs export` of a record repo | Q-MCP-1; §11.12 | 9 |
| Model receipts and run cost | Q-MCP-1; §1.7; D-CTX-5 | 12, 13 |

## 4. The record model

### 4.1 Logs

A log is a repo holding `RecordEntry` files, and `log_id` is its `repo_id`. §16.8's table gives the four logs and their readers, writers and mirrors. This document names them V (the author's vault), D (the team directory), T (the team record) and R (a `record` repo). A log holds per-writer streams, deposit refs, its `erasure` ref and `ur/index` (§11.8, §11.14). A `mailbox` or `secret` repo is a log only for the `read` entries its readers deposit (§11.12).

### 4.2 Modes and routing

```text
team mode   a network is in team mode for a kind once the config head this sidecar holds names a live repo of
            the kind's log: team_record for T's kinds, directory for D's (§8.8's access log: a RepoCreate and no
            later RepoDelete); readers cannot see the tier (§20.5), so routing reads the config, not the plan
personal    otherwise; every kind goes to the author's vault (§16.8)
author      the member a sidecar's admission names, or a tagged or ephemeral sidecar's sponsor (§7.10); a tagged
            sidecar whose sponsor is gone has no author until a SponsorSet
vault path  a consented device writes its own stream; the author's other sidecars deposit (§8.5, §16.8)
no author   raw capture stays in the spool (§16.7), each cut a coverage gap, and approvals take §16.8's route
twice       a kind that section 6.3 sends to V and T is two entries, each with its own chain position, key and
            commitment: the vault entry holds everything, and T's projection holds only section 6.4's unmarked
            fields, with one ContentRef to the vault entry (ContentRef, section 5.1); the vault entry is sealed first
copies      every entry a sidecar deposits to T also lands in its author's vault, in a copy entry (§16.8's "authors
            keep copies"; section 6.4); a team-record erasure does not reach it (section 8)
```

The projection rule keeps R-RECORD-2 and I-20: T holds no title, prompt, path, branch, tool name or argument, and neither does a body in D, beyond §16.11's fields. *Pending Q-RECORD-3:* who files the team record's `RepoCreate`. *Pending Q-RECORD-4:* how entries reach an R log.

### 4.3 Runs

```text
run         one harness session's work, or a person's declared task (harness none, §16.11)
run_id      16 random bytes, drawn when the daemon first binds a (harness, session_id) (§16.7)
sessions    a harness's resume of a session this daemon holds joins its run, up to 4 session ids (§16.10); a fifth
            session starts a new run, whose context names the old one in continues_run_id
start       the first bound event: the run file (§16.6), then the context entry
restate     a change of model or permission mode writes another context entry with stage 2
end         SessionEnd, or 10 min idle without one (§16.8): a coverage entry, then a cost entry (section 13)
re-open     a later event on the same (harness, session_id) binds the same run while its run file lasts, and its next
            end writes a newer coverage entry, which supersedes the last; a run is ended only while its newest
            coverage entry is newer than its last event; idling never clears taint (D-MCP-16)
continue    the first handoff entry a run reads, if it names this run's member or agent label, sets
            continues_run_id and continues_entry_id in a stage 2 context entry; a continuing run starts untainted
            (§16.6's monotone row), and reading the handoff follows §16.10's trust rule
```

### 4.4 Actions

`action_id` is 32 bytes, one value from proposal to result (R-RECORD-5):

```text
O action    §16.6's formula, which approval, approval_decision, approval_use, tool_call, route and publish all carry
tool call   SHA-256("urnetwork-sidecar-v1/action-tool" || run_id || u16be(len(tool_use_id)) || tool_use_id), the
            id the harness gives the call; a harness or event with none takes 32 random bytes, linking nothing, and
            the run's coverage names the gap (Claude Code's PermissionRequest omits the id, REC:179)
empty       entries about no action: context, coverage, membership and the like
```

| Stage | Tool call | O action |
|---|---|---|
| Proposal | `hook_event` (PreToolUse) | `approval` |
| Decision | `permission` | `approval_decision`, `approval_cancel` |
| Execution | `tool_call` | `approval_use` |
| Result | `tool_call` | `approval_use`, then `route`, `publish` or `reach` |

### 4.5 One run, worked through

```text
a team-mode run, with one O tool (M6); V vault, T team record, D team directory
SessionStart       V context   T context, content -> V context   D announce (a card from format 2)
each tool call     V hook_event, tool_call; transcript chunks every 30 s
PermissionRequest  V permission, hook_event                      T permission, content -> V permission
hook-boundary scan V change, blob per changed file               T change, content -> V change
O tool             V approval (the member's vault, §16.8)        T approval, the same ApprovalRequest bytes
decision           V approval_decision, by the approver's device T approval_decision, the same Signed bytes
effect             V approval_use                                T approval_use; T route
forward in use     the provider's T reach, per (grant, peer) per 5 min
SessionEnd         V coverage, cost                              T coverage   D ended
throughout         V copy, holding each entry the daemon deposited to T
```

### 4.6 What the record claims

A record can claim four things (REC:187): integrity (entries are signed and unaltered), custody (the team holds the keys), time (checkpoints countersigned by witnesses, from M6) and observed effects (what changed on disk). It cannot claim completeness, the truth of what a harness reported, or independence from the team that runs it. `source` says how far each entry goes: `observed` is what the daemon did or saw, and `hook` is what any same-user process could have said (§16.8). Coverage states the rest. Copy that claims more than this section is wrong (D-CTX-3).

## 5. Entries

### 5.1 Hashed bytes

§23.8 requires these named at M3's entry. Every value covers stored bytes, never a re-encoding (§16.8).

```text
leaf(E)            SHA-256(0x00 || E.header.body), E.header being the entry's Signed (§16.8; RFC 9162 §2.1.1)
prev_sha256        leaf of the writer's previous entry in this log; 32 zero bytes at seq 1
body               the kind's body message, marshaled once at sealing with Deterministic: true, then only stored
body_commitment    SHA-256("urnetwork-sidecar-v1/record-body" || salt || body) (§16.8), salt 32 bytes
ContentRef         repo_id the named entry's log; object_id its entry_id; commitment its body_commitment, whose salt
                   is in that entry's slot row (§16.8's "salt in the object's slot")
header_sha256,     SHA-256 of the bytes of RecordEntry.header, the whole Signed (§16.11's DecisionRef and
request_entry_     DirectoryDecision)
  sha256
payload_sha256,    §16.6 and §16.8, unchanged
request_sha256,
action_id,
effect_key
evidence_sha256    channel harness: leaf of the matched hook_event entry, so an erased event still answers and no
                   unsalted hash of its body exists; channel presence: empty, the assertion riding in Signed.webauthn
                   (Pending Q-RECORD-2); channel device: empty
sshsig             PROTOCOL.sshsig over the bytes below, namespace urnetwork-sidecar-approval, by the member's key of
                   KeyRegister purpose sshsig (§7.9); the field cannot cover itself, so it covers these, never the
                   decision's own encoding:
                   "urnetwork-sidecar-v1/approval-sshsig" || 0x00 || u16be(len) || approval_id || request_sha256 ||
                   payload_sha256 || u32be(decision) || u32be(uses) || i64be(not_after_millis) ||
                   u16be(len) || requester_sidecar_id || u16be(len) || approver_member_id
```

### 5.2 Sealing

```text
key, salt     32 random bytes each, per entry, never reused (owner decision 61); testHookSecret at each creation and
              unwrap
sealed_body   24 random nonce bytes || XChaCha20-Poly1305(key, nonce, body, aad), §11.6's AEAD, one shot; the largest
              body is a blob's, 8 MiB (§16.7's limit)
aad           "urnetwork-sidecar-v1/record-seal" || log_id || entry_id
slot row      key || salt, 64 bytes, wrapped under fek_g in a slot object of up to 64 rows (§11.6, §16.8): 104 bytes a
              row with its nonce and tag, so a full slot object stays inside 8 KiB; key_slot_id and key_index name
              the row and lie outside the signed header
entry file    the RecordEntry bytes, sealed as any record-class file (§11.6), under a key an ERASE of the row does
              not touch, so headers and chains still verify after erasure (§16.8)
stream path   e/<n div 2048>/<n>, n a stream's own counter from 1, in decimal, sealed and tokenized like any path
              (§11.6, §16.8); in a stream that holds no ingested entry, every directory stream among them, n equals
              the header's seq, which is how §16.11's DecisionRef names a path
```

### 5.3 Writing

Each entry is built in one order: redact (§16.7), marshal the body, draw key and salt, commit, take the next (seq, prev_sha256), sign, journal, push.

```text
chain       per (log_id, writer_sidecar_id): seq from 1, no gaps; the head {seq, leaf} sits in the component
            state <state>/net/<network_id>/record/<log_id> (§5.9), fsynced before a signed entry leaves the daemon
signed      the identity key signs Signed.body, purpose record-entry, type SIGNED_RECORD_HEADER (§6.9, §16.8);
            agent ids stay sealed; from M6 an agent subkey signs inside the body by RecordEntry.version 2 (below)
labels      source by section 6.3; tainted is the run's bit at sealing, so a run's entries turn tainted at the fsync
            §16.6 requires and never back; entries in no run take false; agent_source by §5.5; policy_version is
            the writer's AuthPin version; grant_id the grant the action ran under, else empty
time        time_millis is the capture time on the writer's clock: for spooled capture, when it was captured, not
            when it was signed; a reader shows a time over 10 min from its push's time_ms as skewed, and order
            never rests on it
batch       up to 64 entries or 1 s of them a push, in one part, 64 keys to a slot object (§16.8); a tree's change
            and blob entries go in one push, multi-part when large (§16.7, §11.8), each 64 keys to a slot object
position    a push's entries are ordered by (writer_sidecar_id bytes, seq) (§16.8), whatever the order of the
            statement's changes, which sort by token path (§11.6)
deposits    to T: coalesced for DepositInterval (5 min; owner decision 172's cadence), flushed at once for the
            approval family and at run end, sleep and exit
spool       a locked daemon spools (§16.7) and signs at unlock, in capture order
retry       a signed entry whose push outcome is unknown is re-pushed verbatim, never re-signed (D-MCP-10)
restart     a direct writer takes the higher of its local head and its stream's newest entry of this chain; a
            depositor reads no log, so a device restored from an old backup forks its chain, which readers alarm on
agent key   RecordEntry.version 2 (M6, agent subkeys, §5.5): the sealed plaintext is AgentSignedBody {body, agent_id,
            key_id, signature}, the signature by the agent's subkey over "urnetwork-sidecar-v1/record-agent" ||
            0x00 || log_id || entry_id || body, and body_commitment covers that message; a version-1 reader keeps
            the entry, verifies its header and shows the body generically
```

### 5.4 Deposits and ingest

A deposit file holds one `RecordDepositBatch`, sealed under its one object key (§11.12). A read receipt holds one entry and stays within 4 KiB (§16.8).

```proto
message RecordDepositBatch { repeated RecordDeposit entries = 1; }   // <= 64 entries, <= 1 MiB
message RecordDeposit {
  bytes entry = 1;                          // RecordEntry bytes; key_slot_id empty, key_index 0
  bytes key = 2; bytes salt = 3;            // the body key and salt, which the ingester re-slots
}
```

```text
ingester    a device with rw on the log: T's admins' devices, an author's consented devices (§11.12), a designated
            indexer that writes the log first; several may run
stream      an ingested entry sits in the ingester's own stream, since an owned stream takes only its sidecar's
            pushes (§11.8); its bytes and its writer's chain stay as written (§16.8), and only key_slot_id and
            key_index change
order       per deposit ref, in version order (§11.12); per entry:
  1 parse   a batch or entry that does not parse: consume unrecorded, alarm
  2 signer  VerifySigned as section 5.5; writer_sidecar_id equals the deposit ref's sidecar; log_id is this repo
  3 body    open with the deposit's key, recompute body_commitment; a mismatch: consume unrecorded, alarm
  4 class   a receipt-only depositor: only kind read with source observed, else consume unrecorded, alarm (§11.12)
  5 chain   as section 5.5's step 4: a gap or fork is kept and alarmed, never dropped
  6 write   a new slot row, then the entry in the ingester's next push; once it commits, CONSUME (§11.12)
twice       two ingesters may hold one entry; readers keep one by leaf; a crash between steps 6 and CONSUME leaves
            the deposit, and a re-run finds the leaf in its stream and only consumes
index       the ingester is the log's writer for the run card (§16.10) and journals its index entries
```

### 5.5 Reading

```text
verify      per entry, in stream order, on every reader:
  1 push    the statement carrying it verifies (§11.8's replay)
  2 header  VerifySigned(header, "record-entry", SIGNED_RECORD_HEADER, Ed25519, the writer's identity key);
            signer_id equals writer_sidecar_id; log_id is this repo; any failure: ignore and alarm
  3 right   the writer could write here at the push's auth pin: §16.8's matrix, §16.11's path rules in D
  4 chain   seq is the pinned head's + 1 and prev_sha256 its leaf, then pin (I-16); a higher seq is a gap, and a seq
            at or below the head with another leaf a fork: keep both, alarm (§16.8), showing a fork's later branch
            as forked; a gap is expired only if a committed BASE dropped those seqs and each lies past its class's
            keep_days (section 8)
  5 body    with its key: open, recompute body_commitment, a mismatch alarming and showing the body as invalid;
            without its key: the states below
  6 kind    known: parse as the kind's one message, keeping the stored bytes; unknown: keep, verify steps 1-5, show
            generically (§16.8); a known kind from a writer section 6.3 does not admit: ignore and alarm
states      live; erased (an ERASE named its key; header kept); expired (past keep_days and erased; after BASE and
            GC only its push statement and any checkpoint leaf remain); archived (section 8); forked; lost (a
            checkpoint leaf with no entry, after a site loss)
flagged     an entry is flagged, for §16.6 and I-9, when its header's tainted is true; §16.10's trust rule reads
            this, so reading a flagged entry's text taints the reader's run first
```

### 5.6 Projections

§16.5 lists three R tools with `(filters) -> rows` and leaves the filters here. None adds a tool, and each row carries §16.6's `trust` and `source`. `ur://record/{log}` streams the same rows.

```text
record_query(log?, run?, agent?, kind?, action?, entry?, since?, until?, untrusted?, cursor?) -> rows
  log       vault (the default), directory, team, or an R log's id; only logs this sidecar reads by §8's local
            evaluation, narrowed per agent (§5.5, §8.4)
  rows      entry_id, log, kind, time, writer, agent_id, agent_label, run_id, action_id, source, tainted, trust,
            state, and the body by field name, or stub true
  stubs     an untrusted row, and D's announcements, requests and decisions, return as stubs unless
            untrusted: include, which taints the run first (§16.10, §16.11); raw kinds (48-53) return bodies only
            when entry names one, over 256 KiB as §16.4's resource_link; copy entries return stubs
run_coverage(run?, since?, gaps_only?, cursor?) -> rows
  rows      run_id, harness, version, sources, gaps, first_seq, last_seq, ended: the newest coverage entry of each
            run in the logs this sidecar reads, with its log; a run with none shows open
approval_status(approval?, run?, state?, cursor?) -> rows
  rows      approval_id, action_id, run_id, state (pending, approved, denied, cancelled, expired, spent), uses
            reserved of uses, channel, approver_member_id, not_after, from this daemon's ledger (§16.6) and the
            approval family in the logs it reads; no stored hash or signature
```

### 5.7 What format 1 must carry

M2's review of this document exists to catch what format 1 cannot hold. The answer in this draft is that format 1 needs no change. It rests on four checks:

- A slot row of 64 bytes fits §11.6's slot object at 64 rows (section 5.2).
- A read receipt of 64 object ids, each 16 or 32 bytes, stays under §11.12's 4 KiB with its header, nonce, keys and file overhead.
- Streams take creates only, so nothing here needs a rewrite: re-slotting touches no signed byte (§16.8).
- `BASE` keeps every push statement, so a checkpoint batch's stream versions stay checkable after expiry (section 10).

## 6. The v1 kind registry

### 6.1 Rules

```text
numbers     a kind's number and name are permanent once released, and never reused; 0 is never written; 1-1,023 are
            this registry's, in the blocks below; 1,024 and up are for private use, which v1 readers show generically
blocks      1-15 coordination and directory entries; 16-47 actions, accounting and log upkeep; 48-63 raw capture;
            64-79 derived names, which appear only in search (field 6, SearchFilters.kinds), never in a header
one body    each kind has one body message and is parsed only as it; versions add fields (§16.8); a hash or signature
            over a body covers its stored bytes, so readers keep unknown fields by keeping the bytes
unknown     an unknown kind is kept, verified and shown generically, never refused (§16.8): its number, time, writer,
            source, tainted and state, and no body
adding      a new kind is a row here and, where it has one, a new message; nothing in the envelope changes
```

### 6.2 Enumerations

```text
RecordHeader.source         1 observed, 2 hook, 3 agent, 4 approver (meanings: §16.8)
RecordHeader.agent_source   0 no agent, 1 agent_asserted, 2 isolated (§5.5)
ApprovalDecision.decision   1 approve, 2 deny
ApprovalDecision.channel    1 device, 2 presence, 3 harness (§16.6)
ReachReceipt.kind           1 listen, 2 publish, 3 forward, 4 route, 5 send, 6 receive (§16.8's four endpoints)
RetentionPolicy.class       section 8
zero                        as §6.11's edge codes: no writer sets 0 where this table lists no 0, and a reader takes it
                            as unknown
```

§5.4's `SidecarActionKind` and `SidecarRisk`, which `CanonicalAction.kind` and `ApprovalRequest.risk` carry, have names and no numbers yet. Their numbers are §5.4's to set before M3's entry.

### 6.3 The registry

Personal and Team give the log an entry lands in, by mode (section 4.2). "Route" is §16.8's approval route: the log the approver reads, copied to any team record. Class is section 8's.

| No. | Kind | Class | Personal | Team | Writer | Source | Since |
|---|---|---|---|---|---|---|---|
| 1 | `claim` | coordination | V | none: state of the run's announcement (§16.11) | the daemon, for `record_append` | agent | M3 |
| 2 | `handoff` | coordination | V | none: as `claim` | the daemon, for `record_append` | agent | M3 |
| 3 | `ask` | coordination | V | D | the daemon, for `record_append` | agent | M3; D at M6 |
| 4 | `answer` | coordination | V | D | as `ask` | agent | M3; D at M6 |
| 5 | `check` | coordination | V | D | as `ask` | agent | M3; D at M6 |
| 6 | `note` | coordination | V | D | as `ask` | agent | M3; D at M6 |
| 7 | `announce` | announce | none | D | §16.11's filers | hook for a run item; agent for a version `record_append` raised; else observed | M6 |
| 8 | `request` | request | none | D | the requester's daemon | agent for `filed_by` 2 and 3; else observed | M6 |
| 9 | `decision` | request | none | D | the decider's device | approver | M6 |
| 10 | `erasure_request` | request | none | D | the revoking device | approver | M6 |
| 16 | `context` | action | V | V, T | the daemon | hook | M3 |
| 17 | `change` | action | V | V, T | the daemon, at a scan | observed | M3 |
| 18 | `permission` | action | V | V, T | the daemon | hook | M3 |
| 19 | `approval` | action | V | route | the daemon, in `Authorize` | observed | M3 |
| 20 | `approval_decision` | action | V | route | the approver's device; the daemon for channel harness | approver; hook for channel harness (FS-28) | M3 |
| 21 | `approval_cancel` | action | V | route | the approver's device | approver | M3 |
| 22 | `approval_use` | action | V | route | the spending daemon | observed | M3 |
| 23 | `route` | action | V | T | the sidecar that files the grant or rule | observed | M4 |
| 24 | `publish` | action | V | T | the publishing sidecar | observed | M5 |
| 25 | `reach` | action | V | T | the enforcing endpoint (§16.8) | observed | M6 |
| 26 | `restore` | action | V | V, T | the daemon | observed | M3 |
| 27 | `model` | action | V | T | the model host's daemon | observed | M6 |
| 28 | `cost` | action | V | V; T *pending Q-RECORD-6* | the daemon | hook | M6 |
| 29 | `attestation` | action | none | V, T *pending Q-RECORD-7* | a person's device | approver | M6 |
| 32 | `membership` | accounting | V | T, and each affected vault | the statement's signer; each alarming device for `admission_alarm` | observed | M3 |
| 33 | `key` | accounting | V | T, and each affected vault | the rotator or registrar | observed | M3 |
| 34 | `coverage` | accounting | V | V, T | the daemon | observed | M3 |
| 35 | `read` | accounting | V, by deposit (§16.8) | V by deposit; T for the audit reader | the reader | observed | M3; T at M6 |
| 36 | `erasure` | accounting | the erased log | the erased log | the eraser (§16.8) | observed | M3 |
| 37 | `inventory` | accounting | none | T | the daemon | observed | M6 |
| 38 | `disclosure` | accounting | V | the log disclosed or exported | the discloser's device | approver | M6 |
| 39 | `copy` | accounting | none | V | the depositing daemon | observed | M6 |
| 40 | `retention` | log | the log it governs | the log it governs | a log admin's device | approver | M6 |
| 41 | `log_settings` | log | none | T, R | a log admin's device | approver | M6 |
| 42 | `checkpoint` | log | none | T, R | the log's checkpointer | observed | M6 |
| 43 | `ledger_scope` | log | none | R *pending Q-RECORD-4* | a log admin's device | approver | M6 |
| 48 | `transcript` | capture | V | V | the daemon | hook | M3 |
| 49 | `tool_call` | capture | V | V | the daemon | hook; observed for its own MCP calls | M3 |
| 50 | `hook_event` | capture | V | V | the daemon | hook | M3 |
| 51 | `file_event` | capture | V | V | the daemon | observed | M6 |
| 52 | `blob` | capture | V | V | the daemon | observed | M3 |
| 53 | `model_call` | capture | V | V | the daemon | hook | M6 |
| 64 | `run` | derived | run card, and D's run announcement | as personal | section 7.4 | none | M10 |
| 65 | `worker` | derived | none | D's worker announcement | §16.11 | none | M10 |
| 66 | `repo` | derived | none | D's repo announcement | §16.11 | none | M10 |

Source `approver` means a person's act at a device: a decision, or a command confirmed on /dev/tty or in an app's UI (§5.8). A sponsorless tagged sidecar's run kinds go to T alone, as §16.8 routes its approvals.

### 6.4 Bodies

These kinds' bodies are messages DESIGN.md already holds, whose stored bytes are the whole body:

```text
approval             ApprovalRequest (§16.8)              announce          Announcement (§16.11)
approval_decision    Signed ApprovalDecision (§16.8)      request           DirectoryRequest (§16.11)
approval_cancel      Signed ApprovalCancel (§16.8)        decision          DirectoryDecision (§16.11)
reach                ReachReceipt (§16.8)                 erasure_request   DirectoryErasureRequest (§16.11)
coverage             Coverage (§16.8)                     retention         Signed RetentionPolicy (§16.8)
```

`Coverage.first_seq` and `last_seq` are the writer's chain in the log that holds the entry, so the V and T entries of one run differ there, and with several runs on a sidecar the range brackets the run without being exclusive to it. `sources` are `mcp`, `hooks`, `transcript`, `scan`, `telemetry` and `file_events`. `gaps` are `code` or `code:count` strings, codes `hook_failure`, `missed_event`, `config_changed`, `downtime`, `truncation`, `oversize`, `bypass_mode`, `redaction`, `no_tool_id` and `no_vault`, with no path or text in them, so T's copy is V's.

The rest are new, in `record.proto`, and sealed like every body, so §2.8's evs rows stand. Sections 10-13 hold their own sections' messages. A comment starting `V:` marks a field that T's projection leaves empty. Every cap is the writer's: it refuses an overrun, and a reader ignores a version past one and alarms (§16.11's caps row). Prose and identifier fields follow §16.11's classes, and the daemon redacts them before it signs.

```proto
// sidecar/protocol/record.proto, beside §16.8's messages (M3 unless a comment says otherwise)
message CoordinationBody {                  // claim, handoff, ask, answer, check, note
  string text = 1;                          // prose: claim and handoff <= 512 B, the others <= 1,024 B
  repeated string targets = 2;              // <= 16; grammar below
  int64 expires_millis = 3;                 // claim, ask; else 0
  bytes claim_id = 4;                       // claim: 16 random bytes, or the claim this entry restates
  uint32 claim_state = 5;                   // claim: 1 active, 2 released (§16.11's Claim.state)
  uint32 result = 6;                        // check: 1 pass, 2 fail, 3 objection (a person's "no")
}
message ContextBody {                       // context
  uint32 stage = 1;                         // 1 start, 2 restatement (section 4.3)
  string harness = 2; string harness_version = 3;
  string agent_label = 4;                   // [a-z0-9-]{1,64}, as §16.11's AnnounceWho
  repeated string session_ids = 5;          // <= 4, each <= 64 B
  string model = 6;                         // an identifier <= 64 B, or empty
  string permission_mode = 7;               // the harness's own string, <= 32 B
  bytes repo_id = 8;                        // the run's evs repo, else empty
  string project = 9;                       // §16.11's project key rule, <= 128 B; empty when the repo is private
  string branch = 10;                       // V: a git ref name <= 128 B
  string title = 11;                        // V: §16.10's run title, <= 120 B after redaction
  repeated InstructionFile instruction_files = 12;  // <= 64
  repeated string truncations = 13;         // <= 16 warnings, each <= 128 B, naming a file and its cut
  bytes config_sha256 = 14;                 // the harness config hash §16.6 checks
  bytes continues_run_id = 15; bytes continues_entry_id = 16;
}
message InstructionFile {
  uint32 scope = 1;                         // 1 managed, 2 user, 3 project
  string name = 2;                          // the file's base name, <= 128 B
  bytes sha256 = 3; uint64 size = 4;
}
message ChangeBody {                        // change: one scan's changes (§16.7), the tree's manifest
  bytes repo_id = 1; string project = 2;    // as ContextBody
  string base_commit = 3;                   // the git oid the interval started from
  repeated string commits = 4;              // <= 64 commits the run made in the interval: commit-to-run links
  uint32 path_count = 5;                    // changed paths in all
  uint32 edit_count = 6; uint32 shell_count = 7; uint32 foreign_count = 8;  // by §16.7's attribution
  uint32 capture = 9;                       // bits: 1 hooks, 2 scan, 4 file events
  repeated ChangedPath paths = 10;          // V: <= 4,096; past it path_count stands, and coverage has truncation
}
message ChangedPath {
  string path = 1;                          // relative to the worktree
  bytes before_sha256 = 2; bytes after_sha256 = 3;  // §16.7's ledger; empty when absent or unknown
  uint32 mode = 4;                          // git's file mode
  uint32 attribution = 5;                   // 1 edit, 2 shell, 3 foreign (§16.7)
  bytes blob_entry_id = 6;                  // the blob with the after bytes; empty past §16.7's 8 MiB
}
message PermissionBody {                    // permission: a harness's own step, never an I-8 decision
  uint32 decision = 1;                      // 0 unknown, 1 asked, 2 allowed, 3 denied
  uint32 decided_by = 2;                    // 0 unknown, 1 user, 2 config, 3 hook, 4 classifier
  string permission_mode = 3;
  uint32 tool_class = 4;                    // 1 shell, 2 edit, 3 mcp, 4 web, 5 other
  string tool_name = 5;                     // V: <= 64 B
  bytes arguments_sha256 = 6;               // V: §16.6's hash of the arguments
}
message ApprovalUseBody {                   // approval_use: §16.6's "an approval entry per use"
  bytes approval_id = 1; uint32 use_index = 2; bytes payload_sha256 = 3; bytes effect_key = 4;
  uint32 state = 5;                         // §16.6's Outcome: 1 done, 2 not_done, 3 uncertain
  bytes effect_ref = 6; int64 reserved_millis = 7; int64 outcome_millis = 8;
}
message RouteBody {                         // route (M4)
  uint32 event = 1;                         // 1 opened, 2 closed
  uint32 kind = 2;                          // 1 forward, 2 expose, 3 route, 4 map (§17.8)
  bytes rule_id = 3;                        // bridge rules; a forward's grant is the header's grant_id
  bytes target_sidecar_id = 4; uint32 target_port = 5; repeated string cidrs = 6;
  int64 expires_millis = 7; bytes approval_id = 8;
  uint32 reason = 9;                        // closed: 1 expired, 2 revoked, 3 withdrawn, 4 suspended
}
message PublishBody {                       // publish (M5)
  uint32 event = 1;                         // 1 opened, 2 closed
  string host = 2; uint32 port = 3; uint32 audience = 4; uint32 app_mode = 5;
  int64 expires_millis = 6; bytes approval_id = 7; uint32 reason = 8;  // reason as RouteBody
}
message RestoreBody {                       // restore: one apply of run_restore (§16.7)
  bytes restored_run_id = 1; bytes preview_id = 2;
  bytes approval_id = 3;                    // a tainted run's, or shell paths', else empty
  uint32 restored_count = 4; uint32 conflict_count = 5;
  repeated RestoredPath paths = 6;          // V: <= 4,096
}
message RestoredPath {
  string path = 1;
  string result = 2;                        // restored, or §16.7's conflict name
  repeated string copies = 3;               // <= 2: §16.7's copies beside the path
}
message MembershipBody {                    // membership: §16.8's mirror of §5's SidecarEvents
  uint32 event = 1;                         // 1 member_added, 2 member_removed, 3 sidecar_admitted, 4 sidecar_revoked,
                                            // 5 suspended, 6 unsuspended, 7 owner_confirmed, 8 admission_alarm
  bytes member_id = 2; bytes sidecar_id = 3; bytes group_id = 4;
  uint64 auth_position = 5;                 // the statement's log position; 0 for an alarm
  bytes statement_sha256 = 6;               // the statement's Signed as stored
  uint32 evidence = 7;                      // a member's own device revocation (§5.6): 1 presence, 2 confirmation
  bytes assertion = 8;                      // evidence 1: the WebAuthnEvidence as stored (§6.9)
  uint32 reason = 9;                        // the revocation's reason, as its statement gives it
}
message KeyBody {                           // key: the rest of §5's SidecarEvents
  uint32 event = 1;                         // 1 generation_rotated, 2 key_registered, 3 key_revoked, 4 recovery_changed
  bytes group_id = 2; uint64 generation = 3; uint32 cause = 4;  // §10.5's GenRotate cause
  bytes key_id = 5; uint64 auth_position = 6; bytes statement_sha256 = 7;
}
message ReadBody {                          // read: §16.8's read receipt
  repeated bytes object_ids = 1;            // <= 64: a 16 B entry_id, or a 32 B index file's content_sha256 (§11.14)
  uint32 purpose = 2;                       // 1 read, 2 search, 3 export, 4 disclosure
  bytes read_log_id = 3;                    // in T: the log read; else empty
}
message ErasureBody {                       // erasure: §16.8's entry in the eraser's stream
  bytes erasure_id = 1;                     // §11.12's id; its ERASE and CLOSURE notes name it
  repeated bytes entry_ids = 2;             // <= 1,024; a larger erasure writes several
  uint32 reason = 3;                        // 1 person, 2 retention, 3 moderation, 4 revocation
  bytes request_id = 4;                     // reason 4: the DirectoryErasureRequest
}
message InventoryBody {                     // inventory (M6): one a sidecar a UTC day it ran anything
  bytes sponsor_member_id = 1;              // the member, or a tagged sidecar's sponsor
  uint32 day = 2;                           // days since 1970-01-01, UTC
  bytes credential_ref = 3;                 // a delegation_id or auth key id; never a value (I-7)
  repeated InventoryAgent agents = 4;       // <= 64
}
message InventoryAgent {
  bytes agent_id = 1; string agent_label = 2; uint32 agent_source = 3;
  repeated string harnesses = 4;            // <= 8, each name/version
  repeated string models = 5;               // <= 16
  repeated bytes repo_ids = 6; repeated string projects = 7;  // <= 64 each; a private repo's id, with no project
  uint32 runs = 8; int64 first_seen_millis = 9; int64 last_seen_millis = 10;
}
message Opening {                           // an entry with what opens it
  bytes header = 1;                         // RecordEntry.header, the whole Signed, as stored
  bytes salt = 2; bytes body = 3;           // both empty: the header alone
}
message CopyBody { repeated Opening entries = 1; }  // copy (M6): <= 64 entries the daemon deposited to T
message TranscriptBody {                    // transcript: a chunk of §16.7's tail
  uint64 first_line = 1; uint32 line_count = 2;
  bytes lines = 3;                          // the harness's JSONL lines after redaction, <= 1 MiB
  bool truncated = 4;
}
message ToolCallBody {                      // tool_call: §16.7's PostToolUse family and the daemon's MCP calls
  string tool_name = 1; string tool_use_id = 2; uint32 tool_class = 3;  // tool_class as PermissionBody
  bytes input = 4; bytes output = 5;        // after redaction, <= 1 MiB together (§16.7)
  int64 started_millis = 6; int64 ended_millis = 7; int32 exit_code = 8;
  repeated string paths = 9;                // <= 256: the paths the call names
  bool truncated = 10;
}
message HookEventBody {                     // hook_event: the payload ur hook passed, after redaction, <= 1 MiB
  string event = 1;                         // the harness's event name
  bytes payload = 2;
  bytes arguments_sha256 = 3;               // §16.6's hash, for harness_ok's match
}
message FileEventBody {                     // file_event (M6)
  string path = 1; uint32 op = 2;           // 1 create, 2 write, 3 delete, 4 rename
  bytes after_sha256 = 3; int64 millis = 4;
}
message BlobBody {                          // blob: one changed file's after bytes
  string path = 1; bytes content = 2;       // after redaction, <= 8 MiB (§16.7)
  bytes sha256 = 3;                         // the bytes as captured, before redaction: the ledger's after_sha256
  bool redacted = 4; uint64 size = 5;
}
```

```text
targets     claim    path prefixes under §16.11's Claim.targets rules; or, to release a claim, exactly one
                     claim:<id hex> with expires <= now (section 7.3)
            handoff  claim:<id hex> for each claim it hands off, and at most one member:<id hex> and one agent:<label>
            ask      any of member:<id hex>, agent:<label>, project:<label>
            answer   entry:<id hex> first, the ask it answers; then as ask
            check    entry:<id hex>, action:<id hex> or path prefixes
            note     any of these
            the daemon refuses another form (INVALID_ARGUMENT); a target is an identifier, not prose
```

### 6.5 R logs

*Pending Q-RECORD-4.* §16.8's matrix gives R logs writers, but `record_append` names no log and §16.5's catalog is static, so no agent can write one today. Until the owner answers, an R log holds only what a log admin writes there. The recommended answer needs no tool change: a log admin writes a `ledger_scope` entry naming the projects the ledger covers, and a sidecar with write on that log adds a copy of each T-bound run entry to it.

```proto
message LedgerScopeBody {                   // ledger_scope (M6)
  repeated bytes repo_ids = 1;              // <= 256
  repeated string projects = 2;             // <= 256, §16.11's project keys
  repeated uint32 kinds = 3;                // the kinds copied here, from context, change, the approval family,
                                            // restore, coverage and cost; empty: all of them
}
```

The newest `ledger_scope` by (writer, seq) from a repo admin at its push's pin governs. A sidecar applies it from its next run, and each copy is an ordinary entry of that log: T's projection, its own chain position, key and commitment. This is MK2:797's per-client partition, under its own keys, and per-client erasure is that repo's erasure or shred (§11.12).

## 7. Search text

### 7.1 Rules

```text
documents   V: one run card per run; in personal mode each claim, handoff, ask, answer, check and note entry
            D: §16.11's announcements, announce entries folding into them, and one document per other stream entry
            T: one run card per run, and nothing else (§16.10)
            R: each entry except class log
            never: raw kinds (§16.12's "Later", once §22.8 measures it), copy, class log
row         §11.14's row: doc kind record for an entry, derived for a run card; flag bit 0 the header's tainted;
            time the header's time_millis in seconds; started and expires 0 for an entry; locator the stream path
fields      4 title, 5 text; 6 the kind's registry name, or for an unknown kind kind-<number>; 7 writer sidecar_id,
            8 agent_id and 10 run_id in lowercase hex; 9 agent label and 11 session ids (space-joined) from the
            run's first context entry in this log, empty if none; 12-14 by section 7.3 and 7.4; 15 empty
            D's documents use §16.11's registry instead: 7-10 as above; 11 member_id (the writer's member or
            sponsor), 12 project, 13 branch and 14 repo_id from the run's announcement at writing; 15 state
times       a time in a field is RFC 3339 UTC to the second
title       first(s): s up to its first U+000A, trailing spaces dropped, cut to 120 B on a code point
caps        each display field <= 256 B cut on a code point, its flag bit set, a row <= 2 KiB (§11.14); field 5 is
            indexed whole, up to the body's own cap, and displays its first 256 B
filters     SearchFilters.kinds carries numbers; a reader maps them to field 6's names, and a number it does not
            know matches nothing and is named in coverage
determinism a row and its text are functions of the entry and its run's first context entry, so a rebuild writes
            the same bytes (§11.14); this section is record extractor 1, named in each index file's header, and
            any change to it is a new extractor id and a rebuild
trust       §16.10's rule, from the row's writer and tainted bit; §16.11 narrows it in D
```

### 7.2 Title and text by kind

Text is the listed values in the listed order, one a line. Numbered enumerations appear by their names in sections 6.2 and 6.4. D's rows show field 15 in their notes.

| Kind | 4 title | 5 text | Logs indexed; notes |
|---|---|---|---|
| `claim` | first(text) | text; each target | V; 13 and 14 by section 7.3 |
| `handoff` | first(text) | text; each target | V; 14 `handed_off` |
| `ask`, `answer`, `note` | first(text) | text; each target | V in personal mode; D |
| `check` | first(text) | text; result; each target | V in personal mode; D |
| `announce` | §16.11 | §16.11 | D: its document is the announcement's, kind `run`, `worker` or `repo` |
| `request` | empty | reason; target as hex | D; 15 `pending`; 14 the repo, if a repo |
| `decision` | empty | note | D; 15 `approved`, `denied` or `cancelled` |
| `erasure_request` | empty | empty | D; 14 repo_id |
| `context` | harness and agent label | model; project; permission mode; each instruction file's name | R |
| `change` | "change" and project | each commit | R |
| `permission` | permission mode | tool class; decided_by | R |
| `approval` | the action kind's name | the CanonicalAction's string fields in field order; never `summary` or `preview` | R |
| `approval_decision` | decision and channel | approval_id | R |
| `approval_cancel` | "cancel" | approval_id | R |
| `approval_use` | state | approval_id | R |
| `route` | event and kind | target_sidecar_id; target_port; each cidr | R |
| `publish` | event and host | host; audience | R |
| `reach` | kind | each relay; stream_count; byte_count | R |
| `restore` | "restore" | restored_run_id | R |
| `model` | served name | engine; quantization; weights digest | R |
| `cost` | "cost" | each model | R |
| `attestation` | statement | each commit; note | R |
| `membership`, `key` | event | member_id; sidecar_id; group_id | R |
| `coverage` | "coverage" | harness; version; each source; each gap | R |
| `read` | "read" | purpose | R |
| `erasure` | "erasure" | erasure_id; reason | R |
| `inventory` | "inventory" | each agent label, harness, model and project | R |
| `disclosure` | act | recipient; purpose | R |

### 7.3 Claim state

Entries never change, and a row is encoded from its own document (§11.14), so a claim's state is folded when read.

```text
field 13    claim: expires
field 14    claim: active or released, its claim_state; handoff: handed_off; run card: section 7.4
release     record_append(kind: claim, targets: [claim:<id>], expires <= now) writes a claim entry with claim_state 2;
            in team mode it sets that Claim's state to 2, raising the item's version (§16.11)
fold        per claim_id, the newest entry by (writer, seq) wins: a claim entry restating it, or a handoff naming it;
            no claim_id entry after a claim means active until its run ends, then released, or past expires,
            expired, which is computed and never stored
read        a claim hit's fold reads the doc table's rows by field 10 in the partitions this device holds, never evs;
            a device holding only part of them shows the state it can see, and claims stay advisory (MK2:714)
group       §16.10's claims rows carry the folded state, and its active rule reads it
team mode   claims and handoffs live in the run's announcement (§16.11), so no claim entry exists and D's field 15 and
            Claim.state carry state
```

### 7.4 Run cards

§16.10 gives the card's contents, name (`run/` || run_id), caps and cadence. Its version is the highest seq, in the run's writer's chain in this log, of the entries folded (§11.14's "its writer's sequence"), so two ingesters agree. Here is the mapping, so that a rebuild reproduces it:

```text
                 V's card                                     T's card
4 title          the newest context's title, else             empty: T holds no title (§16.10)
                 first(the run's first user prompt)
6 kind           run                                          run
7-11             as section 7.1, from the context entry       the same
12 tools         name:count, by count then name, <= 32        empty
13, 14           personal mode: the newest claim's expires    empty
                 and folded state
row started      the first entry's time                       the same
row expires      the newest coverage's time while the run is  the same
                 ended, else 0
row time         the run's last event                         the same
5 text, in       harness and version; model; project and      harness and version; model; project;
order, one       branch; every tool name:count; each commit;  each commit; each approved action kind:count;
a line           up to 256 touched paths, byte order; user    each published host; each route target;
                 prompts in order, cut at 2 KiB               each coverage gap code
                 at most 16 KiB, cut on a code point          at most 16 KiB
sources          context, tool_call, change, transcript       context, change, approval, publish, route, reach,
                                                              coverage (§16.10)
```

An erasure re-projects the card without the erased entry (§16.8). A card's `active` reading is §16.10's, with "no Coverage entry" read as section 4.3's "not ended". `search_agents` asks for `kind [claim, handoff, ask, note, run]` (§16.10).

## 8. Retention and erasure

§16.8 gives the mechanism, and §11.12 and §11.13 the pushes. This section gives `RetentionPolicy.class`, what each field means, and how an erasure reads.

```text
class         1 capture        transcript, tool_call, hook_event, file_event, blob, model_call
              2 action         context, change, permission, the approval family, route, publish, reach, restore,
                               model, cost, attestation
              3 coordination   claim, handoff, ask, answer, check, note
              4 announce       announce (§16.11's keep_days 30, from a newer entry or file or the item's expiry)
              5 request        request, decision, erasure_request
              6 accounting     membership, key, coverage, read, erasure, inventory, disclosure, copy
              7 log            retention, log_settings, checkpoint, ledger_scope: no policy applies, and they last
                               as long as the log, or a tree could no longer be rebuilt (section 10)
              an unknown kind takes class 2
defaults      T and R: every class keep_days 400, searchable_days 90 (§16.8; R-MCP-8)
              D: §16.11's retention row and settings
              V: keep_days 0 and searchable_days 0 until its owner sets them (§16.8)
keep_days     0 keeps entries until a person erases them; else entries of the class expire that many days after
              the time_ms of the push that holds them, which evs bounds (§11.14's entry row), never time_millis,
              which a writer asserts
searchable    0 is no limit; else §16.10 masks older documents at query time, and they stay readable by id (FS-76);
              at most keep_days
archive       true: past keep_days an entry is archived, not expired: its key stays, default views and search leave
              it out, and record_query reads it by entry or with archived true; false: it expires
newest        a log's policy for a class is the newest retention entry for it, by (writer, seq), from a repo admin
              of the log at its push's pin (owner-bound: a consented device of its owner)
change        a policy takes effect at the next expiry pass, on existing entries too; it is forward-only for
              entries already erased
expiry        once a UTC day, on the log's admin device (D: §16.11's runner): ERASE the expired entries (§16.8), write
              one erasure entry per batch with reason 2, then weekly an admin BASE re-listing the live set, which
              lists every class 7 entry; a device that finds a class 7 entry unlisted alarms; a preservation hold
              pauses only §11.13's GC (§21.9)
floor         ur record retention warns below 365 days on T, which R-MCP-8 sets as the default's floor; it refuses
              nothing, since a shorter term can be the customer's duty
```

```text
ur record retention show [--log l]
ur record retention set --log l --class c --keep d [--searchable d] [--archive]    (a log admin; /dev/tty or an app)
```

**What an erasure leaves.** The header stays: kind, ids, time, source, tainted and the commitment, readable by the log's readers (§16.8). A leaf and any `checkpoint` naming it stay. A commitment whose salt is gone links to nothing (REC:219-223). Expiry adds BASE and GC, after which the entry file is gone as well, and its push statement and leaf remain.

**Who erases.** Only `admin` on the log (§11.12): V's owner, T's and R's repo admins, D's admins and runner (§16.11). An author cannot erase a T entry. A member asks an admin, and keeps the `copy` in the vault, which no T erasure reaches. That copy, and the T copies of a vault entry's facts, are the author's to erase: an erasure names one entry in one log, and §11.12's closure covers that entry's own representations, never its twin in another log. `ur record erase` runs §16.8's erasure and writes the `erasure` entry.

**Run cards and packets.** An erased entry leaves its run card at the next re-projection (§16.8). A packet can no longer open it (§16.8's `disclosure` row), though a packet already sent stays out of reach, as every copy does.

## 9. Exports

Exports run on a reader's device, from what it decrypts. No server takes part, and no server route, webhook or queue carries an entry (the directive). §7.11's SIEM webhooks carry only api's `network_admin_event`, which is a different log.

```text
ur record export --log l [--since t] [--until t] [--run id] [--kind k,...] [--bodies] [--format jsonl|ocsf|otel]
                 [--out path] [--follow]
```

```text
who         a reader of the log, a person's command; no MCP tool exports, and §16.5's catalog is unchanged
confirm     --bodies and --follow only for a command confirmed on /dev/tty or in an app's UI (§5.8); a command with a
            harness process as its ancestor first taints each such run, as §16.10's cli rule does
receipt     a reader that is not a writer of an owner-bound log deposits read receipts first, purpose 3, under
            D-MCP-18's budget; a receipt that cannot land stops the export
record      write-ahead: a disclosure entry with act 3 (section 11), naming the range and format, commits in the log
            before the first line is written, so other readers see who exported what; if it cannot land the export
            is refused
target      a file or stdout, never a network address: a customer's own forwarder ships it, so the export adds no
            egress path for an agent to reach
follow      a local job in the daemon, confirmed once, resumed from a cursor in the record component's state; a line
            per entry as it verifies; the job ends with the sidecar's read of the log
cost        reads debit the transfer balance as any read does (owner decision 10)
copies      an exported line is a copy beyond recall (§11.12's residual); a later erasure does not reach it
```

**Canonical lines.** `jsonl` is the format every other format maps from. A line is one JSON object: keys sorted, no insignificant whitespace, ids in lowercase hex, `header`, `salt` and `body` in standard base64, times in RFC 3339 UTC with milliseconds.

```json
{"action":"","agent":"7c1e...","agent_label":"limiter-fix","agent_source":1,"body":"CgV...","content":[{"commitment":"a590...","object":"4b7e...","repo":"e3f1..."}],"entry":"9a0c...","fields":{"path_count":3},"grant":"","header":"Cgh...","kind":"change","kind_no":17,"leaf":"1b80...","log":"aaaa...","policy_version":412,"prev":"124c...","run":"4b7e...","salt":"ERE...","seq":12,"source":1,"state":"live","tainted":false,"time":"2026-11-05T07:12:09.123Z","v":1,"writer":"d0c4..."}
```

`header`, `salt` and `body` verify a line with no other file, and `salt`, `body` and `fields` appear only with `--bodies`. `fields` is the body by proto field name, a convenience: repeated fields as arrays, bytes as lowercase hex, enumerations as numbers, unknown fields left out and kept in `body`. An erased or expired entry is §11.12's stub: `state`, `token_path` and `entry_hash`, plus the header fields while the header is held.

**`ur evs export`** of a log keeps §11.12's plain-git form. This document fixes only the blob: each entry's file holds its canonical line with bodies, so a clone reads without a sidecar (R-RECORD-12). An erased entry's file holds the stub. Slot rows are never exported. `ur evs export` of a vault follows the `confirm` and `receipt` rows above.

**`ocsf`** is for SIEMs: OCSF 1.3.0, one event a line, pinned again at M6's entry. Every event sets `metadata.uid` to the entry id, `metadata.version` to `1.3.0`, `metadata.product` to name `recURd` and vendor `URnetwork`, `time`, `severity_id` 1 (3 for `admission_alarm` and a `coverage` with gaps), `cloud.provider` `urnetwork`, `osint` empty, and `type_uid` as class_uid × 100 + activity_id. `actor.user.uid` is the member or sponsor, `actor.session.uid` the run, and `src_endpoint.uid` the writer's `sidecar_id`. No IP address appears (I-13). `unmapped` carries `kind`, `source`, `tainted`, `action`, `leaf` and the body's `fields`.

| Kind | OCSF class (category) | activity_id |
|---|---|---|
| `membership` | Account Change 3001 (3): `user.uid` the subject | `member_added`, `sidecar_admitted` 1 Create; `member_removed`, `sidecar_revoked` 6 Delete; `unsuspended` 2 Enable; `suspended` 5 Disable; others 99 |
| `route`, `publish` | Network Activity 4001 (4): `action_id` 1, `dst_endpoint.uid` the target or host | opened 1 Open, or 7 Listen for `publish`; closed 2 Close |
| `reach` | Network Activity 4001 (4): `action_id` 1, `dst_endpoint.uid` the peer | 6 Traffic |
| every other kind | API Activity 6003 (6): `api.operation` `recurd.<kind>`, `api.service.name` the log | 1 Create; 3 Update for `coverage`, `retention` and a stage 2 `context`; 4 Delete for `erasure`; 2 Read for `read` and `disclosure` |

**`otel`** is for telemetry stacks: OTLP JSON log records under the GenAI semantic conventions. On 2026-11-06 opentelemetry.io says those moved to their own repository, and REC:235 found them still "Development", so names are pinned again at M6's entry. `context` and `model_call` map `model` to `gen_ai.request.model`, `input_tokens` and `output_tokens` to `gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens`, `provider` to `gen_ai.provider.name`, `run_id` to `gen_ai.conversation.id`, `agent_label` to `gen_ai.agent.name` and `agent_id` to `gen_ai.agent.id`. `tool_call` adds `gen_ai.tool.name` and `gen_ai.tool.call.id`. Other kinds go out as plain log records with `recurd.*` attributes.

**Not in v1:** in-toto statements, SCITT and COSE envelopes (MK2:799). REC:243 and the IETF's AUDIT BoF of 2026-11-17 make the format a moving target, so M6's entry review picks one against whatever the BoF yields, as a further `--format`. Nothing here blocks it: an envelope wraps the leaf and the packet's proofs.

## 10. The verifiable log

From M6, a log's admin may turn on a tamper-evident log over T, and once Q-RECORD-4 is answered over an R log (R-RECORD-9; §16.18). V and D take none. It is an RFC 9162 Merkle tree over §16.8's leaves, held in the log's own `checkpoint` entries and summarized by C2SP checkpoints that witnesses countersign. No URnetwork server takes part, and nothing here adds a server-visible value.

### 10.1 The tree

```text
leaf        §16.8's SHA-256(0x00 || Signed.body); node SHA-256(0x01 || left || right); root RFC 9162's MTH
batch       the unit of growth: one checkpoint entry appends one batch of leaves, then signs the new tree
frontier    the rows (ref_id, version, C_v) of each stream that moved: the batch takes every push after the last
            batch's version of that stream, through this one
order       batch by batch; in a batch, streams by ref_id bytes; in a stream, §16.8's order: (evs push version,
            position in the push), position by (writer, seq) (section 5.3); a leaf already in the tree is skipped, so a
            second ingester's copy adds nothing, and a fork's two leaves both stay, as evidence
covers      every entry of the log, every kind, checkpoint entries included: batch k's own entry falls in batch k + 1
index       a leaf's position in the tree; a derived number that no header or envelope carries
```

*Pending Q-RECORD-1.* §16.8's `order` row gives "a log's total order" as (evs push version, position), but a push version counts one ref, and a log has a stream per writer and per ingester. Its order cannot be append-only across streams: a new stream's version 1 would sort before an older stream's version 100. The batch order above keeps the row exactly within each stream, reduces to it on a log with one stream, and adds no field. Until the owner answers, the verifiable log stays off on any log with more than one stream.

The tree needs no separate store. A `checkpoint` body lists its batch's leaves, so a reader rebuilds the tree from `checkpoint` entries alone, and a leaf outlives its entry's expiry. This is why class 7 never expires (section 8).

```proto
message LogSettingsBody {                   // log_settings
  string origin = 1;                        // ur.io/recurd/log/<log_id hex>: a name, never dialed
  bytes checkpointer_sidecar_id = 2;        // a device with rw on the log: an admin's device or indexer
  bytes note_public_key = 3;                // its Ed25519 log key, 32 B
  uint32 interval_seconds = 4;              // 3,600 by default; 300 to 86,400; 0 turns the log off
  repeated LogWitness witnesses = 5;        // <= 8
  uint64 from_batch = 6;                    // the first batch this entry governs
}
message LogWitness {
  string name = 1;                          // its cosigner name
  string url = 2;                           // its submission prefix, https only (c2sp.org/tlog-witness)
  string vkey = 3;                          // its verifier key
}
message LogCheckpointBody {                 // checkpoint
  uint64 batch = 1;                         // from 1, +1 each
  uint64 first_index = 2;                   // the tree index of this batch's first leaf
  repeated LogFrontier frontier = 3;        // sorted by ref_id
  bytes leaves = 4;                         // this batch's leaves, 32 B each, in order
  bytes note = 5;                           // the signed checkpoint, with every cosignature got
}
message LogFrontier { bytes ref_id = 1; uint64 version = 2; bytes chain = 3; }  // chain is C_v (§11.8)
```

### 10.2 Checkpoints

```text
note        c2sp.org/tlog-checkpoint: origin, tree size in decimal, root in standard base64, no extension lines
log key     an Ed25519 log signature (c2sp.org/signed-note, type 0x01), key name the origin, key id
            SHA-256(origin || 0x0A || 0x01 || public key)[:4]; a key of its own, never the identity key, which signs
            only §6.9's Signed; drawn on the checkpointer, kept in the record component's state, testHookSecret at its
            creation, in no slot, export or packet
who         the checkpointer the newest log_settings names, from a repo admin at its push's pin; readers accept
            batch k only from the settings whose from_batch governs k; a successor replays every batch first
when        every interval_seconds while new entries wait; at once when 32,768 leaves wait, a batch ending at a push
            boundary; and, with witnesses, every 24 h at the same size, so their times stay fresh
steps
  1 read    each stream to its head, verifying as section 5.5
  2 batch   the frontier, then the leaves in order
  3 sign    the root over all leaves, then the note
  4 journal the batch and note in the record component's state, fsynced, before any witness sees the note
  5 witness each witness: POST add-checkpoint with `old <its last size>` and a consistency proof
            (c2sp.org/tlog-witness), at most 60 s in all; a 409 names its size and the proof is rebuilt once; a witness
            still failing is left out of this note, and alarms past three misses
  6 entry   the checkpoint entry, holding the note and every cosignature got, then the journal's row goes
resume      after a crash, step 5 re-sends the journaled note unchanged; a witness already there answers 200 with old
            equal to size; a log never signs two roots at one size (c2sp.org/tlog-checkpoint), so step 3 never
            re-runs for a journaled batch
monitor     every reader of the log, at each sync: batch is the last + 1; first_index the tree's size; the signer is
            the governing checkpointer; the note's size and root match the leaves; its signature verifies; versions
            only rise; and, for streams it reads, its own derivation gives the same leaves; a miss alarms, naming
            the batch; an entry older than a frontier and not in the tree alarms too
lost        after a site loss, checkpoint entries re-seed verbatim (D-MCP-10), and a leaf with no entry shows as lost
```

**What a witness learns.** The origin, the tree size and its times, so how many entries a log holds and when it grew (REC:241). It reads no entry. A customer or auditor runs it: the public witness network was not in production when REC read it (REC:203). Without a witness a checkpoint is the team's own statement, and a verifier should say so.

**What it stops.** A server cannot forge or reorder a leaf, which §16.8's signatures and chains already stop. The tree adds that a team cannot quietly rewrite its own past after a witness has cosigned it: a different root at an old size has no consistency proof. It does not show that every action was written (section 4.6), and an admin can always refuse to write.

Limits: a Team of 2,000 members adds about 12 MiB of leaves a working day to T, by inference (section 13).

```text
ur record log on --log l [--interval d] [--witness name,url,vkey]...     a log admin; /dev/tty or an app
ur record log off --log l        ur record log status [--log l]          ur record log checkpoint [--log l]
```

## 11. Disclosure

A disclosure is a person giving someone outside the log proof of some entries (R-RECORD-8, R-RECORD-9). §16.8 fixes its base: `body_commitment` opens with (salt, body), which only key holders have until erasure, and a packet carries both. Erasure makes later disclosure impossible, by design. Packets arrive with the verifiable log, at M6.

```proto
message DisclosurePacket {                  // one file; the verifier needs no other
  uint32 version = 1;                       // 1
  bytes log_id = 2; string origin = 3; int64 created_millis = 4;
  repeated DisclosedEntry entries = 5;      // <= 1,024
  repeated bytes checkpoints = 6;           // signed notes with their cosignatures, as stored
  repeated DisclosedKey keys = 7;
  string purpose = 8;                       // <= 512 B, as the person typed it
}
message DisclosedEntry {
  Opening opening = 1;                      // section 6.4; salt and body empty for a header alone
  uint64 leaf_index = 2; uint32 checkpoint = 3;  // checkpoint: an index into checkpoints
  repeated bytes inclusion_path = 4;        // RFC 9162 §2.1.3, <= 63 hashes
  repeated Opening content = 5;             // the author's openings of its ContentRefs, if given
}
message DisclosedKey {
  bytes key_id = 1; bytes sidecar_id = 2; uint32 alg = 3; bytes public_key = 4;
  string label = 5;                         // the person or device, as the team states it
}
message DisclosureBody {                    // disclosure: the log's own record of the act
  uint32 act = 1;                           // 1 packet, 2 opening, 3 export
  bytes packet_sha256 = 2;                  // acts 1, 2: the file's SHA-256
  repeated bytes entry_ids = 3;             // acts 1, 2: <= 1,024
  string recipient = 4;                     // <= 128 B (prose), as typed
  string purpose = 5;                       // <= 512 B (prose)
  int64 since_millis = 6; int64 until_millis = 7; uint32 format = 8;  // act 3: 1 jsonl, 2 ocsf, 3 otel
}
```

```text
ur record disclose --log l (--entry id... | --approval id | --run id) [--profile p] [--recipient r] [--purpose t]
                   [--content file]... [--dry-run] --out file
ur record open --entry id... [--recipient r] [--purpose t] --out file      the author's vault openings
ur record verify <packet> --log-key vkey [--witness vkey]... [--quorum n] [--ssh-key allowed_signers] [--format f]
```

```text
who         a person, on /dev/tty or in an app's UI, on a device that reads the log; no MCP tool; a command with a harness
            process as its ancestor is refused, so a prompt-injected agent's shell cannot build one
profiles    approval: approval, approval_decision and approval_use opened, and the run's coverage entry's header
            decision: approval_decision opened, approval as a header alone: a person decided on a hash, and no more
            run: context and coverage opened, each change opened, approval family as approval
            entries: exactly the ids named, opened
show        the confirmation and --dry-run list every field the packet opens; approval opens ApprovalRequest whole,
            summary and preview included, since request_sha256 and payload_sha256 hash them (§16.8), so a person who
            will not show them sends the decision profile
checkpoint  a packet needs a checkpoint covering each entry; disclose asks for one and waits, or says when it will come
content     a T entry's ContentRef opens only with an Opening from the author: ur record open on the author's consented
            device, which writes its own disclosure entry in the vault; admins cannot make one (§8.5)
record      write-ahead: the disclosure entry commits in the log before the file is written, and an act that cannot
            land is refused; a reader that is not a writer of an owner-bound log deposits a read receipt, purpose 4
erased      an erased entry goes as a header alone, showing it existed and is gone
no keys     a packet holds salts and bodies of what it opens, never an entry key, slot row or log key
```

**Verifying** needs no daemon, network or keychain, and `ur record verify` is the open offline verifier (MK2:796). Exit 0 means every check passed, 1 that one failed, 2 that the file cannot be read.

```text
1 note       each checkpoint parses; its signature by --log-key verifies; at least --quorum cosignatures by --witness keys
             verify, every --witness given by default; each cosignature's time is reported
2 inclusion  leaf(opening.header) reaches the note's root at its size by the path (RFC 9162 §2.1.3.2)
3 header     VerifySigned(record-entry) under a key in keys; log_id equals the packet's
4 body       where opened, body_commitment recomputes
5 content    each content Opening's own header verifies, and its entry_id and body_commitment equal a ContentRef's
6 approval   approval_decision: VerifySigned(approval, SIGNED_APPROVAL_DECISION) under a key in keys; beside its
             approval entry, request_sha256 is SHA-256 of that body and payload_sha256 SHA-256 of its canonical_action
7 ssh        with --ssh-key: sshsig verifies under namespace urnetwork-sidecar-approval over section 5.1's bytes
8 report     for each entry what passed, each key's label marked team-stated unless step 7 passed for it
```

| A packet shows | It does not show |
|---|---|
| The entry was in the team's log before the witnesses' times | That the log holds every action (section 4.6) |
| Its writer sidecar's key signed the header | That the writer told the truth, where `source` is `hook` or `agent` |
| A body, by commitment | Anything else in that run, or anything erased |
| A key approved one exact CanonicalAction, by channel | That the key is a named person, unless the verifier holds that person's SSH key: a device or presence key's owner is the team's statement, since the config repo stays sealed |
| No code: T's bodies hold no paths or text (section 4.2), and a packet opens only what it names | That no sensitive text was opened: `summary` and `preview` are agent text, shown before sending |

**Scope of "approved".** §16.8's approvals bind O actions. A merge or a commit is no O action, so no `approval` entry names one. P5:728's "a person approved a change" has no entry today beyond an O-tier `evs_write`, and copy must not claim more than this table.

*Pending Q-RECORD-7.* The recommended answer is an `attestation` entry: a person's signed statement about commits, outside the I-8 gate and never called an approval.

```proto
message AttestationBody {                   // attestation (M6), by a person's device
  uint32 statement = 1;                     // 1 reviewed, 2 tested, 3 approved
  repeated string commits = 2;              // <= 64 git oids
  bytes repo_id = 3; string note = 4;       // note <= 512 B (prose)
  bytes sshsig = 5;                         // over "urnetwork-sidecar-v1/attestation-sshsig" || 0x00 ||
                                            // u32be(statement) || each commit's oid bytes, in order, each
                                            // u16be-length-prefixed, || u16be(len) || member_id
}
```

**Client partitions.** A per-client ledger with its own keys is an R log (section 6.5). A packet from it reveals no other client's tree. Field-by-field disclosure is not offered (section 17).

## 12. Model receipts

D-CTX-5 keeps per-request signing out of scope, because it needs an HTTP proxy that PLAN.md lacks, and this document adds no proxy. So a model receipt is not a signature on each request. It is three records that need no proxy, joined by run, grant and time (*Pending Q-RECORD-5*, on what product copy may say):

```text
manifest    a model entry: what a model host states it serves on a port, each field labeled by evidence
receipt     that host's reach entry for a forward to that port, per (grant, peer) per 5 min (§16.8), whose header content
            names the manifest in force: the provider, which enforces the grant, signs it (§16.8; §17.9)
call        a model_call entry per call the harness reports (§16.18), in the author's vault (I-20), source hook
```

```proto
message ModelManifest {                     // model (M6), by the model host's daemon
  uint32 port = 1;                          // the local port: a forward's target_port
  ModelField served_name = 2;               // the name clients ask for
  ModelField engine = 3;                    // vllm, sglang, ollama, llama.cpp or other
  ModelField engine_version = 4;
  ModelField quantization = 5;
  ModelField weights_digest = 6;            // the lowercase hex digest below
  uint64 weights_bytes = 7;
}
message ModelField {
  string value = 1;                         // an identifier <= 128 B
  uint32 evidence = 2;                      // below
}
message ModelCallBody {                     // model_call (M6)
  string model = 1; string provider = 2; string request_id = 3;  // each <= 128 B, as the harness reports them
  uint64 input_tokens = 4; uint64 output_tokens = 5;
  uint64 cache_read_tokens = 6; uint64 cache_write_tokens = 7;
  uint64 reported_micro_usd = 8;            // the harness's own amount, else 0
  int64 started_millis = 9; uint32 duration_millis = 10;
}
```

```text
evidence    1 declared   a person typed it (ur record model set): an operator's statement
            2 reported   the engine said so over loopback on the host, by its model listing; adapters fixed at M6's entry
            3 measured   the host's daemon hashed the files a person named: SHA-256 over the sorted (relative path,
                         file SHA-256) pairs; it shows the bytes on disk at hashing, not what the engine loaded
            4 attested   reserved for hardware attestation; a v1 writer never sets it, and software evidence is never
                         presented as it (D-RECORD-11)
change      the daemon reads the listing at most once a window while the grant has flows, and rehashes a named file when
            its size or mtime changes; a change writes a new model entry, and later receipts name it; a port that
            needs a credential is not probed, its reported fields staying empty (I-7)
join        a reader joins a run to a manifest by the run's sidecar in peers, the grant and the window; this is an
            inference, since no byte ties one request to one window, and it is labeled so
hosted      a hosted model has no manifest: the record stops at harness and model name (P5:766)
```

```text
ur record model set --port p [--engine e] [--engine-version v] [--quantization q] [--weights path]...   a person
ur record model show [--port p]
```

A port serving many models (Ollama) has one manifest naming none of them singly, so D-CTX-5's per-model grant holds only where each model has its own port, and the manifest says what the host states. Weight digests stay in the host's author's log and T (section 6.3), and reach no server.

## 13. Cost

"Cost" is two things: what a run cost its owner (§1.7 leaves this here), and what the record costs to keep.

### 13.1 Run cost

```proto
message RunCostBody {                       // cost (M6): written with each coverage entry, which supersedes as it does
  repeated ModelUsage usage = 1;            // <= 16, by model
  uint64 metered_bytes = 2;                 // the sum of the run's tool results' metered_bytes (§16.6)
}
message ModelUsage {
  string model = 1;
  uint64 input_tokens = 2; uint64 output_tokens = 3;
  uint64 cache_read_tokens = 4; uint64 cache_write_tokens = 5;
  uint64 calls = 6;
  uint64 reported_micro_usd = 7;            // the sum of what the harness reported, else 0
  bool complete = 8;                        // false where coverage has a gap that may hide calls
}
```

```text
sources     model_call entries, from Codex's PostModelRequest and harness OpenTelemetry (§16.18); a run with neither has
            no cost entry and coverage says so; source hook throughout
amounts     only what a harness reports: no price table ships, since a price the sidecar computed would be a claim it
            cannot back; a self-hosted model reports none, and tokens stand
not a bill  §20 owns billing; a cost entry is a harness's report
T           Pending Q-RECORD-6: I-20 keeps model calls in the vault, while P5:845 sells per-client cost and MK2:688 puts cost
            in the ledger; until the owner answers, cost entries stay in V, the failing-closed reading; the recommended
            answer sends per-run totals to T, never a model_call
```

```text
ur record cost [--log l] [--since t] [--until t] [--by project|model|month] [--map file] [--format text|csv|jsonl]
```

`ur record cost` sums `cost` entries the device reads. `--map` is a local file of `project,client` lines, which gives P5:845's per-client view with nothing new in any log. There is no `--by member` and no ranking of people (MK2:774). With the recommended answer to Q-RECORD-6, a group holding fewer than 5 members shows as `other`, a minimum group size that REC:259 says may narrow works-council exposure and that needs legal review. Admins hold the entries regardless, so this shapes the tool and is no privacy control.

### 13.2 What the record costs

Record bytes count toward `storage` and reads toward the transfer balance (§20.6; §16.7), and agents themselves are never metered (P5:849). All figures are by inference, on §16.11's model of 10 agent runs a member-day and 5 working days in 7, until §22.8 measures them. A run writes about 20 T entries (a context, 6 changes, 8 permissions, 3 of the approval family, a coverage and a restore or route) of about 1 KiB each, Padmé included.

```text
                                    5 members   150         500         2,000 (Team limit)
T entries a working day             1,000       30,000      100,000     400,000
T kept at 400 days                  0.3 GiB     8.2 GiB     27 GiB      109 GiB
leaves a working day                31 KiB      0.9 MiB     3.1 MiB     12 MiB
a T reader's sync a working day     1 MiB       29 MiB      98 MiB      391 MiB
deposit, ingest, CONSUME pushes     850         25,500      85,000      340,000
```

- **Pushes.** About 170 a member-day (80 deposits at the 5 min cadence, 80 CONSUMEs, 10 ingests) beside the ~2,400 a member's runs already make (§16.11): about 7%, or ~7 MiB a member-day a drive at ~43 KiB a push (§11.13).
- **Storage.** A 2,000-member Team's T alone takes about half of Team's included 200 GiB by 400 days, before any vault (§20.4). Vault copies add T's size again, across its members' vaults.
- **`reach`.** Adds up to 288 entries a day per (grant, peer) in constant use, on top of the table.
- **Checkpoints.** 24 pushes a day a log, and 32 B a leaf, about 3% of T's bytes.
