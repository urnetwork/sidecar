### mcp-team-legal-holds: A team's own legal holds
Stage: Later, with RS3's assurance stage
- **Deferred:** A hold that a team places on its own records, which suspends retention's expiry (§16.8, §16.18; §23.4's RS3).
- **Why:** It belongs to RS3, recURd's assurance stage, which ships whole once its assurance items land (R-PHASE-4).
- **Launch instead:** Retention expires entries as its policy says. The only hold is §21.9's preservation hold, which URnetwork places on legal process and which pauses server-side GC.
- **Lost:** A team under a hold of its own cannot suspend its record's expiry.
- **Dark in code:** Nothing is built. §21.9's preservation holds are a separate, in-scope mechanism.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design: who places and lifts a team hold, a signed statement for it in the config repo, how every eraser's device honors it, and its FS row.

### mcp-regex-queries: Regex queries
Stage: Later
- **Deferred:** Regular-expression queries in `ur search` and the search tools, planned as codesearch's planner does over trigrams (§16.10's query row; §16.18).
- **Why:** §16.10: "no regex in v1". DESIGN.md gives no further reason.
- **Launch instead:** Each word or quoted phrase is a required substring term, with OR, exclusion, `field:text` and `fuzzy` (§16.10).
- **Lost:** No pattern search over indexed text.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A regex-to-trigram planner on the device, limits on what a pattern may cost, and a `search_version` step for remote search.

### mcp-semantic-search: Semantic search and embedding
Stage: Later
- **Deferred:** Semantic search on desktops and indexers, and embedding as an indexer service (owner decision 150; R-CTX-33; §3.4, §16.18, §23.4).
- **Why:** Owner decision 150 names embedding as future work for an indexer. DESIGN.md gives no design for it.
- **Launch instead:** §11.14's trigram index and §16.10's substring search, with fuzzy near hits.
- **Lost:** Search by meaning.
- **Dark in code:** Nothing is built. `IndexerSet`'s readers ignore a service value they do not know (the plan's TEAM-M2-07), so a later `embedding` service does not break an older device.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design: where the model runs, what an embedding reveals if it is stored, where vectors live in evs, and a new `IndexerSet` service.

### mcp-transcript-text-index: Transcript text in the vault's index
Stage: Later, once §22.8 measures it
- **Deferred:** Indexing every capture entry of a run, tool calls and transcripts included (§16.12's alternatives row; §16.18).
- **Why:** §16.12: it indexes tool output, much of it outside text, at near the runs' own size.
- **Launch instead:** The vault's index holds run cards: title, prompts, tool names, touched paths and times (§16.7, §16.10).
- **Lost:** A search does not find a run by text that appears only inside its transcript or a tool's output.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §22.8's measurement of the index's size and write cost with transcripts in it, then a document class for capture entries.

### mcp-worker-task-delegation: Delegating tasks to a worker's agent and sharing its run sessions
Stage: Later
- **Deferred:** Handing a task to another member's worker agent, and sharing that worker's run sessions (owner decision 179; Q-MCP-8; §16.18, §23.4).
- **Why:** Owner decision 179: in v1, access to a worker means reaching the services it announces; delegating tasks and sharing sessions are later items, each with a design of its own.
- **Launch instead:** An approved request through the directory becomes a grant to dial the ports, sockets and published names the worker announces, under the access policy, with an approver, an expiry and receipts (§16.11).
- **Lost:** One member's agent cannot ask another's to do work, or watch its session, through the directory.
- **Dark in code:** Nothing is built. The plan keeps the worker items of the directory's access requests (RECORD-M6-17) as the seam.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Two designs, one each: what a delegated task may do and under whose approvals, and who may read a shared session.

### mcp-sealed-requests: Directory requests sealed to their approvers
Stage: Later
- **Deferred:** Sealing a directory request to its approvers, so other members see no request and there is no per-target prefix (§16.11's cost paragraph; §16.12's alternatives row; §16.18).
- **Why:** §16.12: it needs per-approver HPKE, fixes the approver set at filing, and makes audit harder.
- **Launch instead:** Requests are entries in the team directory, which every admitted sidecar of the team reads.
- **Lost:** Every member, and every agent of the team, can see who asked for access to what.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for sealing to a set of approvers that changes after filing, and for the audit reader's view.

### mcp-directory-guest-view: A guest view of the directory for cross-network shares
Stage: Later
- **Deferred:** Letting a guest from another network see a team's directory (§16.12's alternatives row; §16.18; QD-268).
- **Why:** §16.12: no cross-network evs read exists in v1. Cross-network shares are §17.9's IP path, for which evs builds nothing.
- **Launch instead:** A guest reaches what a share grants over §17.9's IP path. The directory is read by the team's own sidecars only.
- **Lost:** No discovery across networks.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A cross-network evs read first, which is a design of its own, then a view limited to what the guest was granted.

### mcp-member-prose-setting: A per-team setting for prose at member trust
Stage: Later
- **Deferred:** A per-team setting that would give agents the prose of directory announcements, requests and decisions at `member` trust (§16.12's alternatives row; D-MCP-29).
- **Why:** D-MCP-29 rejects it as the default: auto-filed text would be broadcast to every agent with no person reading it (I-9; owner decision 142). The setting is left for later.
- **Launch instead:** Directory prose is untrusted. Agents get stubs of attested and identifier fields, and prose only with `untrusted: include`, which taints the run first.
- **Lost:** Richer coordination between agents through free text.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for who may turn it on and what an injection then costs, and an owner decision against I-9's rule.

### mcp-harness-config-keys: The harness config's waiting keys
Stage: Later
- **Deferred:** Three keys of the global harness config: `record.capture` as a narrowing control, and `reach` and `identity`; with them §8.5's harness `reach:` block as a filer of access requests (owner decision 452; QD-116; §1's source row; §8.5, §16.7). The fourth, `models`, is designed and acts since owner decision 743, written only by the person's own act (DESIGN-COMPUTE.md section 16.4).
- **Why:** Owner decision 452: a narrowing control on capture weakens R-MCP-4 and needs a person-only surface first. `reach` and `identity` wait for a later design.
- **Launch instead:** Two keys act: `record.redact.pii` from M3 and `claims` from M6, with `agents.<label>` overriding those two only. Capture stays §16.7's fixed set.
- **Lost:** A person cannot narrow what is captured, and a harness config cannot file reach requests or set identity.
- **Dark in code:** The keys are kept in the format: `record.capture` is read and ignored, and `reach` and `identity` are ignored and warned about, so a `reach:` block files no request; `models` too, until the compute tracks build owner decision 743's reader.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for each key. For capture: a person-only path and a Team refusal. For `reach`: how a block becomes requests under §8.5.

### mcp-sshsig-approvals: SSH-signed approvals for high-risk actions
Stage: Later, until a customer asks
- **Deferred:** The member's SSHSIG on a high-risk approval, and with it a second risk level: a classifier or a policy field that marks an action high risk, and SSH-signed receipts (R-MCP-7; §16.6's approval channels; owner decision 279, which declined the build's recommendation of two risk levels; ledger id QD-014; the plan's MCP-M4-03).
- **Why:** §16.6 added the SSHSIG to a high-risk approval, and nothing said what makes an action high risk or who computes it. The owner dropped it from v0 and every milestone until a customer asks (owner decision 279).
- **Launch instead:** Every action's risk is normal. A decision carries its evidence channel, device, presence or harness, and a network's `requests` rules and `evidenceDefault` say which channels it accepts (§16.6, §8.5).
- **Lost:** No second factor separates a public publish or a wide mailing from any other approved action.
- **Dark in code:** `ApprovalDecision.sshsig` stays a reserved field, ignored wherever it is presented and never trusted; `SidecarRisk` keeps its two values, every action normal, and no policy field or classifier raises one (§16.8, §5.4). `KeyRegister` still takes a key of purpose `KEY_PURPOSE_SSHSIG` (§7.9), which nothing verifies a decision under.
- **Held:** MCP-M4-03, the plan's task for the SSHSIG on high-risk decisions, is void while this stands.
- **To bring back:** A customer asks. Then an owner decision on what makes an action high risk, a fixed classifier, a policy field on request rules or both, as owner decision 279's options not taken describe; `AclRequestRule` gains its risk field, and verifiers check the SSHSIG under the member's registered key.

### mcp-card-closure-replay-check: The fresh-reader check on a directory admin's CLOSURE of a card or repo file
Stage: Review phase
- **Deferred:** A reader-side check that holds a directory admin's push at a `d/` or `r/` path to the `cards` ref's own log: evs marks a CLOSURE's path versions, and a reader accepts an admin's push there only where the log shows a CLOSURE at that version whose content hash equals the version before it (§16.11's closure row; owner decision 636; ledger id QD-1100; the plan's RECORD-M10-05).
- **Why:** The owner accepted the draft's rule for an erasure's CLOSURE and left this check to the review phase: it is a reader-side check, with no format change if the cards read already exposes a push's kind.
- **Launch instead:** A reader accepts a directory admin's push at a `d/` or `r/` path only when its bytes are the very bytes its copy already accepted there, or else verify as the rightful writer's own Signed under every other rule, whose seq must rise (§16.11's closure row).
- **Lost:** Until the check lands, a reader that has accepted nothing at a path, a fresh device or one whose copy was reset, has no seq to hold a rewrite to: a directory admin that kept the bytes of a writer's earlier Signed file could push them as a CLOSURE, and such a reader would show them as the writer's, a card within the 4,096-position bound of its `at`, a repo file at whatever position its signer named, until the writer's next write or its repair replaces them.
- **Dark in code:** Nothing is built. The reader rule above is drafted and held by its tests.
- **Held:** The review phase's work on the directory's erasure. An admin-signed eraser card, option 2 of the question, is the one to design if the owner later wants moderation to keep a writer's other runs, or a revoked run gone before its daemon wakes.
- **To bring back:** evs marks the path versions a CLOSURE writes; the cards read exposes each push's kind; readers apply the check; and a test replays an earlier Signed card to a fresh reader and sees it refused.

### mcp-v1: §16's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §16.18's v1 rows. At M6: the team record and the team directory as the coordination log, mirrored on admins' indexers (owner decisions 102, 150, 171, 177); reach receipts; agent subkeys; filesystem events; model calls (owner decision 463); retention policies; the `audit` reader (owner decision 63); RECORD.md's verifiable log and client disclosure packets. At M10 (owner decisions 163, 169): the evs tools' versioning argument; `ur search`, `ur agents`, `search`, `search_agents` and `search_status`; run cards; the directory's cards and index; `evs_drop_preview` and the drop states; remote serving on indexers.
- **Why:** Team ships at M6 and format 2 with search at M10.
- **Launch instead:** v0 at M3: the in-daemon MCP server and `.ur`, R and W tools with restore, harness hooks, transcript tails and the redactor, the vault record, approvals and the use ledger; O tools with their components through M4-M9.
- **Lost:** Until M6: the team record and directory. Until M10: search and drops in the tools.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
