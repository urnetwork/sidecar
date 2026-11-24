# Second review of the compute design

**Recommendation.** Keep the local-first release in §19.3. Before freezing its formats, settle how a reader verifies deferred history, how older devices interpret new authorization rules, and how an approved calendar write survives a partial batch. Before opening compute purchases, settle which durable record proves a debit and which identifier makes it unique. Each affects data that later software must still interpret.

Reviewed on November 23, 2026 by GPT-6.2 Astra at maximum reasoning effort. Section and line references refer to the 7,464-line plan, Git blob `e9f480118d5d5c3ede515ecffa694ee29b60b650`, in sidecar at `8b286a54`. CO-1 through CO-44 are the owner's decisions for this review. The revised plan already moves the first release ahead of external provider commitments, keeps purchases closed until credit can be spent, and specifies the sponsor access an agents' enclave receives. The findings below concern what it takes to deliver those decisions. [Reviewed plan](DESIGN-COMPUTE.md) · [First review](REVIEW-COMPUTE-REVIEW1.md)

## First release and shared formats

### R2-01 · High · Deferred history breaks verification of the ordinary record

§24.5 (line 5280) puts session entries under `s/` in the same signed writer chain as ordinary `e/` entries. Consider four successive entries, ordinary 1, session 2, session 3, ordinary 4. Reading 4 gives the expected leaf of 3. It supplies neither 3's signed predecessor nor the link from 2 to 1. A deferred entry at the tip has no successor at all. §24.10 (5414–5421) also permits a full vault to withhold session entries, eventually evicting some locally, while approvals and other ordinary entries still publish. The current reader will correctly report an unexplained gap in that ordinary history. [Record writing rules](RECORD.md#53-writing) · [Record reading rules](RECORD.md#55-reading) · [Current chain reader](record_reader.go#L730) · [Deferred reading in §24.5](DESIGN-COMPUTE.md#245-how-it-is-stored)

Publish enough authenticated information for every sequence number before allowing a later ordinary entry to advance the reader. One option is a compact, independently retrievable signed header with the predecessor and body commitment, even when the body stays in the spool. Another is a separately versioned session chain with signed checkpoints in the ordinary log. Specify how a reader distinguishes a deferred body, a permanent drop, and a missing or conflicting header. Carry the choice into Appendix D and the reader upgrade rule.

**Acceptance.** On a cold device, verify an approval after two consecutive deferred entries and verify a deferred suffix up to its published head. Repeat across a writer restart, a storage cap and permanent spool eviction. A matching body completes its entry. A body that fails an authentic header’s commitment raises an integrity error, a second signed header with another leaf at the same sequence raises a fork, and a missing required header still raises a gap.

### R2-02 · High · A software release cannot activate new authorization rules for a whole network

§20.4 (4030–4032) assumes that shipping M11 before the first new `agents` or `agent` repo creation makes all readers compatible. An offline phone can return later. M14 changes an even more consequential rule. §11.4 (2614–2624) admits an agents' enclave with both a member and tags plus capability bit 3. Today's validator rejects that shape and the unknown bit. On refusal it still advances to the record's position, so two implementations can agree on a config-log position and disagree on who is admitted. Today's `ApprovalCapable` also inherits the exclusion of tags from the shared consent predicate. Relaxing that predicate alone could grant personal approval authority to the enclave. The blanket approval refusal in §18 (3763) also needs the narrow local `auto` exception in §27.9 (6540–6555). [Admission validator](config_admit.go#L351) · [Refusal and log advancement](config_apply.go#L554) · [Consent and approval predicates](acl_consent.go#L209) · [Enclave admission in §11.4](DESIGN-COMPUTE.md#114-what-an-enclave-is)

Specify a per-network activation point for each incompatible format, which gates and key distributors must understand it, and what an old device sees when it returns. Upgrading after a refused entry needs a defined replay or verified checkpoint. Give sponsor EVS access, network tag rights, configuration signing, human approval and automatic approval separate predicates. Preserve CO-43's full sponsor data access for an agents' enclave and the indexer's narrower mailbox grants.

**Acceptance.** Replay one log through old and new readers, with an offline member returning across activation, a folded config base and a revocation. Before resuming writes or handing out new keys, upgraded readers must agree on the admission, repo kinds and recipients. Exercise sponsor vault access, absence of human signing rights, the allowed auto cases and an indexer with one member grant.

### R2-03 · High · Calendar approval and crash recovery need the exact destination and operation

§23.6–§23.9 (4903–4905, 4935–4938, 4974–5005) store a provider account and calendar ID or CalDAV collection, while kind 25 signs a display label, host, audience and event fields. A person can replace a link between approval and execution. Two calendars on the same host can have identical display labels and sharing descriptions. The authorization then permits a different destination with the same visible fields. Kind 26 already carries the connection repo ID and account (5838). [Calendar approval fields in §23.9](DESIGN-COMPUTE.md#239-approvals-and-taint)

There is a second gap after execution. The lookup in §16.3 (3598–3601) and Appendix D (7234) derives an event UID from the effect key and index. That works for creates. An update or cancellation acts on an existing UID. Seeing that an event exists, changed, or disappeared cannot establish which request caused the change or which attendee notices the provider sent. Graph documents its `transactionId` for retried creates. [Microsoft Graph event resource](https://learn.microsoft.com/en-us/graph/api/resources/event?view=graph-rest-1.0)

Bind the approval to the link's stable identity, the provider account and the selected calendar or collection. Recheck destination, audience and applicable revision preconditions at dispatch. Persist a receipt per original selected index with its operation, original UID or occurrence and expected revision. Specify what outcome each provider can establish. Where it cannot distinguish an applied write from a lost reply, return an explicit uncertain outcome and require reconciliation before another send.

**Acceptance.** Change a link to a second calendar with the same host and label while approval is pending. No write may reach it. In a three-event update select indexes 0 and 2, then stop after the first provider change and before its local receipt. Repeat with an attendee cancellation. Recovery must account for each selected index, leave the unselected event untouched and send no second notice for an uncertain write.

### R2-04 · High for restricted data · The gateway needs a run identity before routing or replay

§8.5 (1890) coalesces requests by grant, body hash and an optional caller request ID. Two independent runs on one grant can make byte-identical calls and legitimately expect two answers. The second can instead receive the first run's response and tool-call IDs, with no new session entry under §24.8 (5352–5355). Conversely, the crash rule permits a second upstream charge for a genuine retry. The resulting promise depends on the identity the client actually supplies. [Gateway recording and run binding in §24.8](DESIGN-COMPUTE.md#248-external-harnesses-and-the-gateway)

The same ambiguity matters for connected-service data. §8.9 and §24.8 (1959, 5334–5336) allow a time-based guess and OR the live runs' taint into the stored entries. `limited_use` is a distinct mark (5249–5250). §§6.4 and 25.10 (1231, 5834–5837) require that mark to constrain the model **before** dispatch. Choosing which run to record afterward cannot enforce that check.

Give supported clients a daemon-bound run handle and a retry identifier scoped to one operation. Verify the body on reuse. For callers without a stable retry ID, document the uncertainty and preserve distinct calls. For callers without a reliable run binding, either apply the union of all applicable restrictions before route selection and replay, or refuse to release restricted results through that session. Define the disposition of an in-flight call across a crash.

**Acceptance.** Run two sessions on one grant with identical request bytes, then retry just one identified operation. Check upstream call counts, independent audit entries and replay ownership. Mark one run through a synthetic service read, delay its hook and interleave both sessions' calls. A disallowed model must receive zero marked input, including on replay and after restart.

### R2-05 · Medium · Concurrent inbox writers can create the same message path

§20.7 (4095–4127) builds a create-only filename from one plus the largest sequence seen and the sender's display name. Two devices of one member both write as `me`. Team agent names are unique only within a member (§20.5, 4051). Concurrent replies from either pair can choose the same path. A directed reply naming a Team agent by label alone can also wake the wrong agent. [Thread format in §20.7](DESIGN-COMPUTE.md#207-inboxes-and-conversations)

Give each logical message an immutable ID created before its first write, carry that ID across retries, and use it in the filename. Keep the sequence for presentation, with a deterministic tie-break. Address directed Team messages by stable member and agent identity or an authenticated recipient repo, and use the label for display. Validate identity from the existing push provenance.

**Acceptance.** Let two disconnected devices reply as `me` to one thread and let two Team members with the same agent label answer a broadcast. Synchronize their writes in opposite orders, then repeat delivery. Both messages must remain addressable in each case, and only the intended recipient may wake for a directed reply.

### R2-06 · Medium · Some classifier evidence deliberately disappears

§27.6 (6486) rebuilds in-memory scores from the journal. §27.9 (6608) promises a reviewer can open exactly what the classifier read. §24.9 (5379–5384) deliberately keeps only a stub for search results and can omit oversized parts. A hash can identify the omitted input, but cannot reproduce it. This affects M13a wherever journal exceptions apply and M13b for search. [Journal exceptions in §24.9](DESIGN-COMPUTE.md#249-the-exceptions)

Use the existing `inputs_unknown` rule (§27.7, 6526) when a needed input is unavailable after restart or continuation. Define which input span, digest, classifier version and score survive for a prior decision. The digest UI should identify any unavailable input and distinguish a recorded verdict from a reproducible one. Preserve the owner's search retention rule.

**Acceptance.** Classify a synthetic result whose journal representation is a stub, and interrupt the run before its next decision. The recovered run asks a person. When the original decision completed before the interruption, the digest shows the recorded verdict and identifies the unavailable source.

## Before opening purchases or enabling a paid route

### R2-07 · High · Releasing a hold and publishing its charge lack a recoverable handoff

§9.7 (2167–2168, 2189–2202) releases a hold and appends a charge for asynchronous SQL settlement. §14.4 (3207–3209) puts the hold and budget in one Redis Cluster slot and the settlement stream in another. Those keys cannot share an atomic Redis operation. A crash after release can restore spending room before the debit reaches the stream. Losing Redis after enqueue and before PostgreSQL commit can erase the only queued liability. Rebuilding from committed charges then misses work already served. The sibling subscription implementation explicitly retains durable debit authority and uses SQL-fenced recovery for pending reservations. [Redis Cluster hash tags](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/#hash-tags) · [Subscription admission implementation](../server/model/subscription_redis_admission.go#L19) · [Settlement flow in §9.7](DESIGN-COMPUTE.md#97-holds-and-settlement)

Specify the durable record for each ordinary billable operation before a provider liability can become unrecoverable. A durable intent and settlement outbox keyed by operation, or an independently recoverable provider receipt plus a durable lookup key, can support this. Keep pending spend reserved until that handoff is recoverable. Define when admission resumes after a cache rebuild. The deliberately ephemeral search attribution maps in §21.5 need their own loss accounting (R2-09).

**Acceptance.** Stop the producer on each side of release, enqueue and SQL commit. Drop the cache, restart the worker and redeliver a signed receipt or an enclave interval. Compare the balance, lot draws, subject budgets, day and lifetime totals against an uninterrupted run. A concurrent admission must see the pending liability, and duplicate delivery must add one debit in total.

### R2-08 · High · The same idempotency rule can refund twice and omit a paid search

The day-partitioned charge table uses `PRIMARY KEY (start_time, charge_id)` (§9.4, 2092). A refund reuses an ID derived from the original charge, but §9.6 (2148) gives it the time when it is written. A worker retry or concurrent dispute and operator refund can insert a second pair with the same ID and another timestamp, drawing the lots in reverse twice. §9.7 (2191–2196) assumes the pair is stable. [Charge table in §9.4](DESIGN-COMPUTE.md#94-the-ledger)

For search the failure goes the other way. §§21.5 and 21.8 (4384–4386, 4420, 4507–4511) authorize up to three separately payable attempts under one request ID. §9.7 derives the charge from the request ID and hold time, and §9.6 plus compute-10 (2146, 3249) retain times only to the minute. Two settled attempts in one minute can collide. Persisting a more precise timestamp as a workaround would change the privacy contract.

Give the ledger a durable uniqueness rule for each logical operation across partitions. A refund can claim the original charge ID once and retain its first booking time. A search can derive a broker-local charge key from network, request ID and attempt, with minute precision for time and no signer ticket, nonce or payee. Commit the claim, charge, lot changes and rollups together. Bound the search settlement replay window so per-request deduplication records can expire by the 72-hour privacy deadline.

**Acceptance.** Race manual and dispute refunds, then retry across UTC midnight. One refund restores the eligible draws once. Settle attempts 2 and 1 in reverse order in the same minute, duplicate both reports and let attempt 3 lapse. Exactly two charges must appear in the correct day's and lifetime totals.

### R2-09 · High for reconciliation · A settled search can have no attributable charge

§21.5 (4419–4423) explicitly accepts loss of the volatile ticket map. The signer still knows which nonces it issued, and a transfer can finalize after that loss, but the broker releases the customer's hold when no report arrives. §21.8 (4520) requires monthly Base settlements to match customer charges to the search. Both outcomes can occur on the same day. The loss is the value of all affected outstanding authorizations that settle, which can exceed the price of one search. [Search settlement in §21.5](DESIGN-COMPUTE.md#215-how-a-search-is-made-and-paid)

Define an aggregate operator-funded expense for finalized issued authorizations that remain unattributable. Reconcile finalized provider costs to customer-funded costs plus these expenses, separating retail markup and refunds. Specify the finality cursor, reporting window, maximum unsettled value and who owns a difference. This can preserve the separation of signer and broker without persisting their join keys. Also align compute-10's 72-hour row lifetime (3249) with the daily deletion at 02:00 UTC (3216), which can retain a row almost a day longer.

**Acceptance.** Finalize a fixed set of synthetic transfers around midnight while losing each volatile map in turn. Replay the block notifications. Every settled unit is counted once, only attributable units reach customer statements and both sides balance at month end. Ordinary unflagged transfers must leave no persistent payee-to-customer link. Keep the separately specified sanctions records subject to compute-10’s own rule. Check deletion immediately on either side of the stated retention deadline.

### R2-10 · High · A network exposure limit does not enforce a member's hard budget

§6.6 (1356–1361) and §9.7 (2170–2177) hold the declared model's worst case against the balance and budgets. The provider's signed actual charge can be higher. The additional test allows exposure against the **network's** available balance and floor. Engy's gate makes provider enforcement of model and cost optional (§4.7, 842). With ample network credit, an agent at $4.90 of its $5 daily budget could reserve $0.05 and receive a $2 receipt. Charging in full takes that agent to $6.90 before the mismatch alarm fires. §§16.4–16.5 (3627, 3652) promise enforcement at agent, device and configured subject scopes. [Budget enforcement in §16.4](DESIGN-COMPUTE.md#164-budgets-models-and-the-floor)

Preserve CO-42's declared-model hold against the customer's balance. Separately define how each hard budget bounds the authorized liability, using a provider-enforced maximum or a conservative maximum against the remaining room in every applicable budget. If URnetwork absorbs a difference, specify its maximum, how it is booked and what is shown to the member. A provider's new price or alias needs a safe effective point in the same check.

**Acceptance.** With a funded network, exercise the remaining cents of independent agent, device and member caps against a fake adapter that returns a higher-priced receipt. Parallel calls must neither spend the same room twice nor charge a person beyond their authorized cap. The ordinary small-balance call under CO-42 should still succeed when every applicable cap has room.

## Before enabling the affected integration

### R2-11 · High · Freshness-ticket expiry exceeds the stated revocation horizon

IC-9 (§2.4, 306), D-ATTEST-5 (§5.10, 1095) and Q-ATTEST-5 promise at most 14 days if unreleased tickets escape. §5.4 (1021) pre-signs daily tickets up to 14 days ahead and accepts each until 72 hours past its day. The last ticket can therefore keep the previous policy usable beyond day 14, roughly to day 16 or 17 depending on the day boundary. A newer policy can exist while a device still has only the old policy and the final signed ticket. [Policy and freshness tickets in §5.4](DESIGN-COMPUTE.md#54-the-policy)

Sign explicit UTC validity bounds and enforce an absolute batch expiry at most 14 days after signing. Clip each ticket's grace period at that boundary. Define how a verifier handles future tickets, policy expiry and a newer policy version it has already observed.

**Acceptance.** With a fixed clock, issue the full batch, revoke immediately and withhold the new policy. Check an ordinary released ticket against the 72-hour bound, an unreleased ticket before its start, and the final ticket immediately before and at the absolute horizon. Exercise each remote operation IC-9 covers.

### R2-12 · High for Team privacy · The proposed cache prefix is computable by other members

§2.5 (332) says every admitted sidecar can read `K_sock`. §6.6 (1318) derives the TEE cache prefix from that network-wide key, a constant and the member ID. All of those inputs are available within the Team. The construction distinguishes the default prefixes honest clients send, but cannot support the cross-member privacy assurance in §2.7 (375) and Q-INFER-3. The sidecar implementation likewise treats `K_sock` as a network key. [Socket key derivation](socket_name.go#L223) · [Provider cache prefixes in §6.6](DESIGN-COMPUTE.md#66-the-remote-paths)

Use a random member secret distributed only to that member's authorized devices, including authorized sponsor enclaves under CO-43. Specify the namespace for a tagged device without that secret and how rotation works when a device loses access. State the provider's role in cache separation and the linkage the provider can still observe.

**Acceptance.** Two authorized devices of one member share the intended namespace. A different member with the same network key and directory data does not have the inputs to derive it. A tagged device receives its specified isolated namespace. After revocation a former device cannot derive the new one.

### R2-13 · High for strict providers · A refresh lease cannot recover a consumed token

§25.6 (5735) promises a crash loses no grant. §25.7 (5749) takes a 30-second EVS lease, calls the provider and saves the replacement token. A strict provider can consume the old token before the response or the EVS write is durable. A second device sees an expired lease and the old token. Resubmitting it can revoke the active grant. An ordinary delayed response can also outlive the lease. §19.7 (3906) includes user-supplied strict definitions in M13b even though the initial Google and Microsoft definitions use other behavior. [OAuth Security BCP, §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) · [Refresh rules in §25.7](DESIGN-COMPUTE.md#257-tokens-in-use-rotation-revocation-and-loss)

Persist the in-flight attempt and token generation. Fence late completions and define how to recover an uncertain result if the provider supports idempotent refresh or retrieval. Otherwise move the connection to a reconnect-required state and tell the person why. Lease expiry alone cannot authorize another submission of a possibly consumed token.

**Acceptance.** Use a clock-controlled strict provider that consumes the token and drops its reply. Advance past 30 seconds and bring a second device online. No device resubmits the old token. Complete the recoverable and reconnect-required cases, and ensure a late response cannot overwrite a newer grant.

### R2-14 · Medium · The indexer has conflicting conditions for billable running

§11.6 (2648) requires SSH and the Harness to be up for any enclave to enter `running`. Steps 8–9 in §11.7 (2686–2689) start the Harness and take over agent cards, then mark the enclave running after checking its SSH key registration. §11.10 (2748–2754) specifies a mail indexer with no Harness or agent container and with all SSH logins refused. Following the common lifecycle can leave a healthy indexer in `joining`. Following step 9 can start billing after a key appears while its mail service is still down. [Indexer role in §11.10](DESIGN-COMPUTE.md#1110-what-runs-in-it)

Give each role its own readiness check. For the indexer, distinguish an admitted, healthy mail and search daemon from the point when its mail-host key and listen grant make it eligible to receive. Name the state that starts billing and the condition that retires the prior receiver during the two-TTL handoff.

**Acceptance.** Start a reference indexer with no Harness and no possible SSH login. Independently delay the daemon, listen grant and publication of the new mail key. The state and charge boundary must match the documented readiness rule. A healthy old receiver must stay in service through the planned handoff.

## Two discrepancies in operating instructions

| Decision to carry through | Passages to reconcile | Observable check |
| --- | --- | --- |
| Q-GAMMA-4 (2546) selects weekly USD funding and just-in-time TAO purchases with a one- to two-day float. | §§10.4–10.6 (2426, 2449–2453, 2477) and Appendix F's CO-10 row (7330) still describe weekly TAO purchases or model their exposure. Update the job, custody instructions and cost example together. | A sample week of mint demand yields the approved transfer, conversion and float schedule. |
| The SSH-setup provider gate and its test in §§11.7 and 18 (2696, 3760) require a reachable setup port from 1024 upward. | §19.7 (3921) promises the broker tunnel for a setup provider offering only port 22. Give the adapter contract, tunnel allowlist and gate test one disposition for this case. | A reference provider offering only port 22 gets the same outcome in the gate and the orchestrator. |

## Verification

The review compared the plan's contracts with the existing record, authorization and subscription admission implementations, their checked-in fixtures, the first review and the primary protocol references cited above. The 194 body decision IDs and 185 body question IDs each match their respective register without duplicates. The conflicts here concern the meaning of those entries. [Record reader fixtures](record_reader_test.go#L242) · [Admission fixtures](config_admit_test.go#L156)

An attempt to run the existing admission-shape and record-reader tests stopped during package setup because the local replacement for `../operator-core` is missing. The source checks above are static. The acceptance cases describe deterministic tests for the proposed designs. Live provider behavior, commercial commitments and production pricing were outside this verification. [Local module replacement](go.mod#L79)
