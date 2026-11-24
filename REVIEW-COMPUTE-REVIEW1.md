# Review 1 of DESIGN-COMPUTE.md

Reviewed: DESIGN-COMPUTE.md as it stood on 2026-11-23 (6,317 lines), against DESIGN.md at commit 5fb94cae and RECORD.md. Line numbers are that file's. Every body section was read in full. Each finding was checked against the rest of the document, DESIGN.md, the code in the urnetwork checkout and, where possible, primary sources; the last section says what was and was not verified. Quotes are verbatim.

The owner's statements CO-1 to CO-39 are taken as decided. Where a finding touches one, it names a consequence or a risk the document does not state, and leaves the decision alone.

## Summary verdict

The design is careful, and honest about what it cannot promise. I found no place where it has a URnetwork server read plaintext by design. The registers are clean: 146 decisions and 151 questions, no duplicate or missing ids, every question with an answer and a decider. Most obvious attacks are already answered somewhere in the text.

It is not ready to build from as written, for four reasons.

1. **Launch depends on other companies.** Remote inference, TEE inference, enclaves, web search and Google or Microsoft calendars each wait on a gate that an outside party must pass, and most gates need a feature that party has not built. The build order spends most of M12 and M14 on those paths (R1-60, R1-63).
2. **The trust model has gaps at its edges.** Taint has doors beside kind 24. Three of the four enclave provisioning forms can let a breached broker into the enclave. The listeners rule delivers connections as localhost. The search payer signs transfers to any address. Each has a contained fix.
3. **The money mechanics fail on small balances.** At launch every remote call holds roughly $2.60 to $3 of balance whatever it costs, and holds drive auto-renew and suspension (R1-32, R1-33).
4. **The scope is larger than its estimate.** The document plans 55 to 65 engineer-months after M10 with no staffing plan, and several lines look low by a factor of two or three (R1-64).

M11 (the Harness, local models, the skill, context history) is close. It needs R1-2, R1-35, R1-36, R1-37 and R1-38 fixed first. M12 to M14 need the high findings fixed, a new build order and the cuts in R1-69.

There are 20 high findings. Eighteen are in the top 10 below; the other two are R1-35 (the macOS engine cannot load as designed) and R1-64 (effort and staffing).

## Top 10 issues, ranked

1. **Nothing that spends the balance can reach a user until an outside party ships a feature, and the build puts that work first.** At today's gate status a person gets local models, the skill, context history, web fetch, CalDAV calendars and listeners. Everything paid waits. M12 still builds the Chutes TEE path, which CO-32 drops from launch, and M14 builds enclaves that no provider can host. See R1-60 and R1-63.
2. **Taint has open doors beside kind 24.** The Harness's own `git` and file tools do not taint. A tainted run's EVS writes reach enclaves that are on the internet, and every enclave holds the member's whole `agents` repo. An egress-`none` enclave still reaches every listed service. A tainted run can stop and start enclaves. See R1-2, R1-3, R1-4 and R1-5.
3. **A breached broker can become an enclave, or aim a physical attack at one.** Three of EPC-1's four forms do not bind the keys a device admits to the VM it checked. The broker also chooses placement and retries, so the "$1,000 attack by a miner" becomes a targeted attack. Enclave tags are not unique or tied to a sponsor. See R1-6, R1-7 and R1-8.
4. **The indexer enclave is never argued against the directive, and "always on" does not hold.** It reads every member's incoming mail on a VM that URnetwork's broker creates, and it replaces owner decision 12 in one table cell. It stops an hour after the balance reaches zero and needs a person at most restarts. See R1-9 and R1-40.
5. **A listed service is delivered as a localhost connection.** That skips the host firewall, passes "allow from localhost" checks, and can reach a loopback-only service that shares a port. The rule also opens for tagged sidecars at the M13 upgrade with no person's act. See R1-10 and R1-11.
6. **The search payer signs a transfer to any address a device names.** CO-29 accepted cash-out. It did not cover a member making URnetwork's key pay a sanctioned address, or the lack of any cap a fraudster cannot raise. See R1-1 and R1-23.
7. **Holds make a $5 balance barely usable, and can charge cards during a provider outage.** Each direct call holds the provider's costliest worst case. Auto-renew and suspension read a balance that includes those holds, and an unanswered hold becomes a charge. See R1-32, R1-33 and R1-34.
8. **Revocation and policy signing rest on custody the design does not state.** The 72-hour bound fails if the host that releases tickets also holds the unreleased ones. The offline release key becomes a routine key. See R1-12, R1-13 and R1-65.
9. **Private data travels further than the texts say.** The rule that keeps Google data from training has no defined mechanism and no enforcement over MCP. Sign-in codes and reset links in unread mail go to `none` providers behind one skill instruction. See R1-15 and R1-16.
10. **Context history is lossy where it matters and unbudgeted where it costs.** A resumed run reads a record with every email address and phone number hashed out. Per-call pushes are not counted against EVS's push budget, and an enclave's history stalls without a member's device online. See R1-37 and R1-38.

## Findings by area

### 1. Security and privacy

**R1-1. The search payer signs a transfer to any address, a sanctioned one included (high)**
- **Where:** §21.5, line 3879, "it signs to the address the device sends"; §10.8, line 2292, "Sanctions. Stripe's screening at checkout".
- **Problem:** CO-29 accepts cash-out on economic grounds. It does not cover this case. A member with a few cents of balance names a sanctioned address as `pay_to`, gets the authorization, and submits it to Base itself. EIP-3009 lets anyone submit, so Coinbase's screening never runs. URnetwork's payer has then paid a sanctioned address on a public chain. The broker drops the nonce after about 30 minutes, so URnetwork cannot say which network did it. The facilitator may then decline the payer, which stops search for everyone.
- **Recommendation:** Before signing, the broker screens `pay_to` against the published sanctions address list, and requires a fresh address (no code, no history) if the gate test shows Stripe's deposit addresses are fresh. While the mapping still exists, the settlement watcher flags a network whose authorization was not submitted by the facilitator. Add payee-side sanctions to counsel's reading.

**R1-2. The Harness's `git` and file tools are not taint triggers (high)**
- **Where:** §7.8, line 1477, "`evs_read` of versions whose provenance is untrusted"; §13.6, line 2816, "Its writes are W-tier (DESIGN §16.5)". §13 has no taint rule.
- **Problem:** §7.8 lets a tainted run or an enclave agent write a file to a repo because "every reader takes as untrusted". But the list of taint triggers names `evs_read`, not the bundled git's clone, fetch, pull, show or diff, nor a later `read` of a checked-out file. The person's untainted local bot runs `git pull` and reads `notes.md`. The injected text is now in an untainted context, so `agent_prompt` into an enclave, `calendar_add`, `service_call` writes and `mail_send` run with no approval. In the enclave profile, `bash` output taints but `read`, `grep` and `find` do not.
- **Recommendation:** A git operation taints the run when any fetched push has untrusted or unreadable provenance, before the worktree is written. Treat every tool result in the enclave profile as untrusted. Add both to §7.8, §13.6 and §18.

**R1-3. Kind 24 leaves the EVS door open, and every enclave holds the member's whole `agents` repo (high)**
- **Where:** §7.8, line 1478, "What a tainted run writes into EVS otherwise"; §20.4, line 3525, "Each enclave is given EvsShares on its member's `agents` repo".
- **Problem:** Kind 24 exists because, in an enclave on the internet, "a receiver's taint stops nothing its `bash` sends". The same reasoning applies to anything that enclave reads from EVS, yet a tainted run's write needs no approval. A local agent that has read mail writes a summary. An injected enclave agent calls `agent_list` with `untrusted: include`, or reads a shared repo, and sends the text out as root. The local Harness has no storage but EVS (CO-6), so this is the common path, not a corner. The share is also write access, and the document notes that EVS does not stop one writer rewriting another's path.
- **Recommendation:** Give enclaves write access only to their own card, status and summaries, and read access to cards and status stubs; summaries by the sponsor's grant. Have the enclave's daemon hold back versions a tainted run wrote from an enclave whose egress is not `none`, until the sponsor releases them. State the remaining residual in the `enclave:<provider>` disclosure.

**R1-4. The egress-`none` exemption ignores the listeners rule (medium)**
- **Where:** §7.10, line 1597, "An enclave whose egress is `none` sends nothing to the internet itself"; §26.7's implicit rule for `autogroup:tagged`.
- **Problem:** A tainted run may prompt an egress-`none` enclave without approval. That enclave can still dial every listed service on the member's devices, and §26.7 itself names "a development server, a database with no password" among them. A web page injects the local bot, the bot prompts the enclave, and the enclave's agent posts what it was given to a Jupyter or Docker API on the laptop.
- **Recommendation:** Apply the exemption only to an enclave that has egress `none` and no `listener:` grant, or leave egress-`none` enclaves out of the default listeners rule.

**R1-5. `enclave_stop` and `enclave_start` are W tools in any run (high)**
- **Where:** §7.5, line 1416, "W for stop and start"; §15.2, line 3037.
- **Problem:** A stop destroys the VM and its scratch disk. A prompt-injected run, local or through MCP, can stop every enclave the person sponsors. If one is the network's indexer, inbound mail waits, and §9.9 says "an enclave its person stopped stays stopped", so no keeper restarts it. `enclave_start` lets the same run resume per-second charges that no budget stops, and causes an admission by a tool, which §11.4 says never happens. The design already gates a tainted run's `agent_stop` for this reason.
- **Recommendation:** Make start the person's act. Make stop an outward action when the run is tainted. No agent tool stops or starts the indexer enclave. Record whether a stop was the person's or a run's, so a keeper may restart a run's stop.

**R1-6. Three of EPC-1's four forms do not bind the admitted keys to the VM that was checked (high)**
- **Where:** §11.7, line 2476, "steps 5-9 follow, step 6 checking the provider image's profile in place of ur-enclave's"; §5.5, line 937.
- **Problem:** In setup over SSH, the device verifies its session into VM1. The payload then stops SSH and makes keys, and step 5's nonce and evidence travel through the broker. The measurement is the provider's stock image. A breached broker answers step 5 from VM3, another VM of the same image where it holds root. Step 6 passes, and the device seals the auth key to the broker's key and admits it. A URnetwork server is then the enclave. In the second and third forms, EPC-1 does not require that the provider image take no other input: Hippius' documented boot configuration carries SSH keys, so a broker that adds its own gets root with the report unchanged.
- **Recommendation:** In the fourth form, send step 5's nonce over the verified session, or mix a session secret into the report data. In the second and third, add to EPC-1 that the measured init runs the bootstrap before any access service and binds or refuses every key and boot input. Add both negative tests to §18 and to G-PROV-hippius. This is the first thing the enclave audit should examine.

**R1-7. The broker can aim the physical attack, and key extraction is not "per machine" (high)**
- **Where:** §11.6, line 2441, "never retried on the same machine; the orchestrator asks the provider for another"; §5.12, line 1022, "low per machine, real across many miners"; §6.6, line 1174, "pick one by its load hint"; §5.6, line 949, "the broker may fetch, per instance per 2-minute window".
- **Problem:** §2.7 treats the physical attacker as a random miner. Three facts change that. The broker decides when a VM is lost and how often to retry, so an attacker with the broker and one rigged machine can discard VMs until a chosen network's indexer lands on it. For inference, the device can use only instances whose key the broker returns. And tee.fail states that one extracted key lets an attacker forge quotes on other hardware, so one extraction serves every node that miner registers. In M15's beacon mode the broker fetches the evidence itself, and Chutes' evidence carries no chute id, so the broker can hand over its own chute's instance.
- **Recommendation:** Add the §2.7 row. Change the disclosure wording to "a holder who has done this once can fake the check on every machine they run". Make each create authorization good for one VM, with retries counted and shown. Require A2 or a provider-signed placement for the indexer role. Have devices pick at random among verified instances. Have URnetwork watch for one chip identity behind more instances than a machine can host. In beacon mode, keep the device's own fetch.

**R1-8. Enclave tags are neither unique nor bound to a sponsor (high in Teams)**
- **Where:** §11.4, line 2408, "Grants are written to the enclave's tags"; §16.5, line 3316, the `tag:enclave-*` owners row, `autogroup:member`.
- **Problem:** Shares, `ssh` and `dial` rules and the indexer's listen grant all name `tag:enclave-<name>`. Nothing makes names unique in a network or ties a tag to its sponsor. Two members each create `build1`, and one's shares seat the other's enclave. A member can also admit a sidecar they control under another enclave's tag and inherit its grants. I found no uniqueness or ownership rule in either document; DESIGN's tag matching may scope by sponsor somewhere I did not find.
- **Recommendation:** Put the enclave id in the tag and keep the name as a label. Write a `tagOwners` row per enclave at create. State that a tag grant reaches only incarnations its owner admitted.

**R1-9. The indexer enclave is never argued against the directive (high)**
- **Where:** §11.10, line 2528, "This supersedes owner decision 12's"; the directive's inbound-mail clause, DESIGN.md line 18, "a device or a customer-run sidecar".
- **Problem:** CO-19 and CO-20 ask for this enclave, and I do not reopen them. But the document never says why a VM that URnetwork's broker creates, pays for and can destroy, running URnetwork's image under URnetwork's provider account, counts as customer-run. With R1-6 open, a breached broker can be that VM. The change to owner decision 12 sits in one table cell and one Appendix D row, with no Q- item. Every member's incoming mail is read there on one admin's choice, and a member who grants nothing never acknowledges the provider's disclosure.
- **Recommendation:** Add a Q-ENC item that states the argument and its conditions: the binding fix of R1-6, no console or key injection in any form, and no shell on any console. In a Team, notify every member before the enclave becomes the receiver.

**R1-10. A listed service is delivered as a loopback connection (high)**
- **Where:** §26.4, line 5529, "which the host's bridge maps to `127.0.0.1:<port>` (rule 3)"; §26.7, line 5676.
- **Problem:** The rule admits by port, then the host's daemon dials 127.0.0.1. Three things follow that neither design discusses.
  - The service sees its peer as localhost. Redis in protected mode refuses LAN clients but answers these, and so does any "allow from localhost" admin panel.
  - Loopback traffic is not filtered by the usual host firewall rules. A bind on every interface that the firewall keeps off the LAN, such as SMB on a Windows laptop, opens to every member device and enclave agent.
  - A loopback-only socket can share a port with an all-interface one. This review bound both on macOS: a dial to 127.0.0.1 reached the loopback-only socket. So Docker's published `*:5432` being listed can expose a private Postgres on `127.0.0.1:5432`, which the disclosure says cannot happen. Linux is stricter about such binds and was not tested.
- **Recommendation:** For flows the listeners rule admits, deliver through the tun with the peer's overlay address where `ur tun` runs, and elsewhere to a non-loopback local address. Refuse a port that also has a loopback-specific bind. Apply removals to the hook at discovery, not at the next publish. Put what remains in `listeners:publish`.

**R1-11. Listener reach opens by an upgrade and by one remote tap (medium)**
- **Where:** §26.7, line 5670, "the implicit document, from the version M13 ships"; §26.6, line 5626, "first open and at the first start after the feature ships".
- **Problem:** Before M13 a tagged source in a network with no document could dial only its own subject on tcp:443. After the upgrade a CI runner, a cloud agent or an enclave's root agent reaches every all-interface socket of every tagged host, and no one is shown a disclosure, since servers publish without asking. Separately, one acknowledgment on a phone starts the person's work laptop publishing and hosting, without the person seeing a single entry.
- **Recommendation:** Make the implicit rule and tagged publishing take effect only once the network's Owner has acknowledged `listeners:publish`, recorded as a signed statement. Have each desktop show its own first list and take a local confirmation once.

**R1-12. The 72-hour revocation bound depends on who holds the unreleased tickets (high)**
- **Where:** §5.4, line 926, "the tickets are released one a day"; IC-9, line 279.
- **Problem:** The signers pre-sign 90 daily tickets in one sitting. If the host that releases them also holds the unreleased ones, the adversary this mechanism targets, a server withholding policy N+1, holds up to 90 days of valid tickets for policy N. It serves them, and every device keeps accepting a revoked profile or chip. The DNSSEC precedent does not carry over: pre-signed key sets are harmless if leaked, and these tickets are the capability the revocation must defeat. The text also does not say whether a lapsed ticket stops only TEE calls or all remote work, since the direct, search and services lines live in the same policy.
- **Recommendation:** Keep unreleased tickets offline or on a host apart from ur.io's serving path and the broker. Sign at most 14 days ahead. Restate IC-9 as "72 hours, or the pre-signed horizon if the ticket store is taken too". Scope the lapse. Let tickets travel by any path, since they are signed.

**R1-13. Stale vendor collateral widens what passes for about 30 days (medium)**
- **Where:** §5.7, line 955, "the cache can withhold or serve a stale item but not forge one".
- **Problem:** TCB info and certificate revocation lists stay valid for about 30 days. A breached cache that serves last month's items keeps a downgraded TCB at UpToDate and a revoked key acceptable. That revocation is the vendor's only answer to key extraction, and tickets do not cover it. Separately, §5.3 verifies NVIDIA's token "under NVIDIA's key", but the policy's roots pin only the device root, so a relaying broker could substitute the signing keys. The 30-day figure is from memory.
- **Recommendation:** The policy carries a minimum TCB evaluation number, a maximum collateral age of about 7 days, and the NRAS root. Let devices fetch collateral through the egress as a cross-check.

**R1-14. For direct providers, an unsigned catalog decides who reads the prompt (medium)**
- **Where:** §5.4's `direct` line, lines 902-906; Q-PROV-6, line 809, "the catalog marks the one model without ZDR workers".
- **Problem:** The policy pins a TEE model to its chute id. A direct model's provider-side id, its zero-retention flag and SayGM's upstream come from `GET /v1/catalog`, which is unsigned. A breached broker remaps `engy-<model>-<effort>` to the model without zero retention, or to an upstream that trains. The device sends plaintext there under an unchanged name and an acknowledged disclosure. §2.7's broker row covers only the TEE case.
- **Recommendation:** Put the direct model map in the signed policy: canonical name, provider id, zero retention required, allowed upstreams. Have the device check `served.zdr` on every engy receipt.

**R1-15. Google's data rule is narrower than Google's policy, and is not enforceable where the text promises it (high)**
- **Where:** §25.10, line 5293, "carried as the mail mark is"; §6.4, line 1118; the `connect:google` text, lines 5350-5351.
- **Problem:** "The mail mark" appears nowhere else in the document. How `no_training` travels to a child agent, a thread, a summary in EVS, a fork or a context pack is undefined, and a tainted parent can launch a child on a `saygm-*` model with the events in its instructions. Over MCP, a harness on its own provider gets `calendar_list` and `service_call` results with no router in the path, while the signed text promises Google's data goes only to models that do not train. TEE models are exempt, yet at AP the provider reads plaintext. And Google's Limited Use rules cover more than training: transfers need a user-facing feature and consent, and no human may read the data. A reviewer who finds Calendar data at an unvetted model can refuse or pull verification, which stops every user's Google connection.
- **Recommendation:** Rename the rule `limited_use`. Each provider's gate records no training, no retention past the request, no human access and written terms, AP providers included. Define the mark as a property of journal nodes, inherited as taint is and checked at `agent_launch` and `agent_send`. Over MCP, serve such a service only to runs whose model the router routes. Fix the disclosure sentence.

**R1-16. Sign-in codes and reset links in unread mail go to `none` providers (high)**
- **Where:** §23.4, line 4318, "the skill names a one-time code, password reset or sign-in link".
- **Problem:** `mail_list` returns each snippet and `mail_read` the first text part, unredacted. Burner mail is largely codes and magic links. The only control is an instruction to the model. On SayGM a call reaches the miner and the upstream it calls, both anonymous. A miner scans prompts for reset links and uses one while it is valid. CO-34 says mail follows the provider's disclosure; this is a consequence it does not state, with a cheap fix.
- **Recommendation:** In the daemon, withhold the body and snippet of mail the mail component already classes as code or sign-in mail from any model that is not local, A1 or A2. Return "a sign-in code from X (withheld)". Add a per-person switch, and name it in the `inference:*` texts.

**R1-17. Token readership is wider than use requires (medium)**
- **Where:** §25.6, line 5203, "the audit reader holds connections as it holds any secret"; §16.4, line 3282, "never lets an admin read a member's connection".
- **Problem:** Every consented device can decrypt every platform's refresh token, so the per-platform split protects nothing on a lost phone. A Team that names `kind:secret` in its audit block, perhaps for ACME keys, hands the audit device live credentials that act as each member, iCloud app passwords among them. Line 3282 reads as a contradiction beside that. A member who leaves has no device left to run Disconnect, so a personal Google token stays live for months.
- **Recommendation:** Seal each token entry, and a link's secret, to the member's devices of the platform that uses it. Add a leave flow that revokes at the provider. Reword line 3282.

**R1-18. `service_call` reads bypass the calendar's limits and switches (medium)**
- **Where:** §25.4, line 5097, "a GET or HEAD no rule names is read"; line 5123.
- **Problem:** Typed tools own only writes. A `GET` of the same events returns raw JSON with attendee addresses, conference passcodes and full descriptions, which `calendar_list` withholds. It works when the network turns the calendar tools off. Rule matching has no stated path canonicalization. Google's `watch` endpoint takes any HTTPS address and a 256-character token, so it is an exfiltration channel guarded only by a raw-body approval.
- **Recommendation:** A typed tool owns its paths for every method. Canonicalize before matching. Mark `watch`, `subscriptions` and sharing endpoints refused in both launch definitions. Make the calendar switch govern `service_call` on calendar paths.

**R1-19. Over MCP, "untainted" is weaker than the W tier assumes (medium)**
- **Where:** §25.16, line 5454; §23.9, line 4441, "A run that has read nothing untrusted writes only what the person asked for".
- **Problem:** That holds for the local Harness, which has no shell. An external harness is tainted only by reads through `ur` and by hooks on its web tools. A cloned repo's files and package READMEs do not taint. An injected coding agent can write 20 calendar events a call into a shared calendar with no card.
- **Recommendation:** For MCP sessions, make calendar writes and `service_call` writes outward always, or whenever the calendar reports an audience. Keep W for the local Harness.

**R1-20. Free text from other writers reaches untainted runs (medium)**
- **Where:** §7.10, line 1586, "and do not taint"; §26.9, line 5709; §15.1, line 3019.
- **Problem:** Agent names, unsigned model names and listener descriptions come from writers that include enclave agents and other members. Listener descriptions are free text, 64 characters by 512 entries a device, about 32 KiB that another member's laptop can place in any member's untainted run. `ur listeners label` is not refused to a harness process, so an injected coding agent can write a label that a later Harness run reads as trusted.
- **Recommendation:** Restrict these fields to a token charset and cap the untrusted bytes per result. Return free text only under `untrusted: include`, which taints. Refuse `label` to harness ancestors and never treat a label as trusted.

**R1-21. The gateway's port can be taken while the daemon is down (medium)**
- **Where:** §8.4, line 1703, "the port chosen at install and kept in the daemon's settings".
- **Problem:** The gateway authenticates callers, but harnesses never authenticate the gateway. The daemon idles out. On a shared Linux host another user binds the port, and Codex posts the full prompt and a live token to that user, who can answer with tool calls Codex runs as the victim. Separately, nothing keeps the daemon up between a harness's calls.
- **Recommendation:** Hold the listener for as long as any grant exists, by socket activation or no idle exit. Have `ur gateway token` and `ur gateway run` refuse when the daemon is not the port's listener.

**R1-22. Search unlinkability rests on perfect non-retention of a join key, and is overstated at launch volume (medium)**
- **Where:** §21.5, line 3882, "what remains is time, kept to the minute"; §14.6's compute-10 row; §14.4's `{cmpa}` key.
- **Problem:** The broker must see each search's payee and nonce to sign. Parallel ties both to the query, and the chain keeps both for good. So the only thing between a query and a network is that the broker forgets. The text covers logs, but not Redis snapshots, append-only files or backups of `{cmpa}`. Also, the charge row keeps the network, agent and minute for 90 days. At a few searches a minute, one row matches one transfer. The `inference:engy` text states this kind of join; `search:parallel` does not.
- **Recommendation:** Put the signer in a separate small service that never sees the network, so a join needs two systems. State that persistence is off for these keys. Keep minute rows 72 hours, then daily counts. Add the join sentence to the search disclosure.

**R1-23. Search cash-out and purchase limits are keyed to things the fraudster controls (medium)**
- **Where:** §21.9, line 3983, "which the network's policy may raise"; §9.11, line 2087, the new account purchase row.
- **Problem:** A fraudster administers their own network, so `day_max` is self-set, and new agent ids escape per-agent budgets. Search is the only path from a stolen card to bearer USDC, yet enclaves have a new-account rule and search has none. Purchase limits are per network, and networks are free: one stolen card works across many fresh networks. After day 7 nothing bounds a day's purchases but the $10,000 cap. When the card is charged back, URnetwork has lost the USDC, so CO-29's premise of taking a percentage does not hold for these calls.
- **Recommendation:** A broker cap on searches that policy cannot raise, scaled to the age of settled purchases. Velocity limits keyed to the payer as well as the network: card fingerprint, store account hash. A daily limit after day 7.

**R1-24. Uncharged enclave states before `running` have no timeout or cap (medium)**
- **Where:** §11.6, line 2428, "no (absorbed by URnetwork if it fails)".
- **Problem:** `creating` through `joining` are free to the user, and limits count running enclaves. A modified client with a small purchase history creates whole-GPU machines and never verifies, or always fails step 6, which asks the provider for another. URnetwork pays for every minute. Steps 2 to 9 also run on the approving device, often a phone that the OS suspends, and no resumption is specified.
- **Recommendation:** Timeouts per state. Count pre-running VMs against the limits. Cap failed creates per network per day. Take the first hold at `requested`. Make steps 2 to 9 resumable by any consented device of the sponsor.

**R1-25. Any tagged sidecar can wake every agent in a Team (medium)**
- **Where:** §16.5, line 3315, "`autogroup:member` and tagged subjects of the network".
- **Problem:** A compromised CI runner or enclave deposits into any agent's inbox directly, which skips kind 24. Each agent wakes up to 20 times an hour for a paid turn and stays tainted. No limit is per sender.
- **Recommendation:** Default deposit to `autogroup:member`. Add per-sender wake limits. Queue untrusted cross-member messages for the next turn a person drives.

**R1-26. "Never the person, the device or the network" overstates what a provider cannot learn (medium)**
- **Where:** §6.6, line 1239, "nothing links one run to the next"; the "Private" lists of the `inference:*` texts in §2.8.
- **Problem:** The Harness puts identifiers in every context: `ur://<net>/<repo>` URLs, agent names, enclave names. `<net>` is the network's label or chosen alias. A direct provider can link a network's runs and may read its name. On the TEE path the per-member cache salt is a stable pseudonym in every request, readable by Chutes' serving code, which AP puts inside the boundary.
- **Recommendation:** Keep network ids out of what the model reads, or change the texts to say the conversation itself may carry the network's and agents' names. Make the TEE salt per run, or disclose the linkage.

**R1-27. The agents' container assumes URnetwork's kernel, and nothing patches a running enclave (medium)**
- **Where:** §11.10, line 2518, "kept current answer the kernel attack surface".
- **Problem:** Under EPC-1's second to fourth forms the kernel and its patch cadence are the provider's, and EPC-1 to EPC-8 ask nothing of them. There is no maximum incarnation age. Root in a user namespace with `CAP_NET_ADMIN` is a well-used path to kernel privilege escalation, and an escape yields the incarnation's keys and firewall. §11.17 has no row for it.
- **Recommendation:** Add an EPC item for the kernel. Add a maximum incarnation age tied to the profile's expiry. Add the risk row. Evaluate gVisor for the container.

**R1-28. Two paths lead from an agent to the person's desktop (medium)**
- **Where:** §12.2, line 2627, "Standard SSH, so OpenSSH, VS Code and sftp work"; §13.4, line 2781.
- **Problem:** VS Code Remote-SSH into the agents' container trusts the remote, and its publisher warns that a compromised remote can run code locally. Enclave agents are root there and reach the internet. Separately, the local agent's file tools can write inside the worktree's `.git`. An injected agent sets `core.fsmonitor` in `.git/config`, and the person's shell prompt or IDE then runs a host command. That defeats IC-7.
- **Recommendation:** Have `ur ssh config` print the warning and offer a person-only container as the editors' target. Refuse any `.git` path to the file tools, or keep the git directory outside the workspace.

**R1-29. The dispute rule lets one network remove a provider (medium)**
- **Where:** §6.7, line 1247, "is taken out of the catalog until reviewed".
- **Problem:** On the TEE path a dispute is a claim only the device can check. At launch volumes a few modified clients disputing 0.5% of a day's requests remove the only remote provider for everyone. The check also compares two numbers from the same provider, so it catches a broker that inflates and not a provider that overcounts.
- **Recommendation:** Count disputes by distinct networks, with a cap per network. Page a person instead of delisting. Run canary calls with known token counts.

**R1-30. The tainted-run fetch rule protects less, and allows less, than stated (medium)**
- **Where:** §22.5, line 4194, "at most about 45 bits a tainted run"; line 4193, "a run's fetches without approval stop at 10".
- **Problem:** A tainted run still composes search queries, and the query picks which pages become listed. An attacker with many indexed pages gets far more bits per fetch than the estimate. On the other side, the first search taints the run, so a bot-tab conversation gets 10 pages for its life and then an approval per page. Whether Parallel fetches a URL named in an objective on demand is not established; if it does, search is a channel to an attacker's host.
- **Recommendation:** Restate the residual. Count the allowance per person turn. Keep the person's own URLs listed and uncounted. Settle the on-demand fetch question at G-SRCH-parallel.

**R1-31. A saved card belongs to the network, not the payer (low)**
- **Where:** §9.5, line 1969, "`setup_future_usage=off_session`".
- **Problem:** A member with `compute:buy` pays $5 with a personal card. A Billing admin later turns on threshold top-ups, and that card is charged $20 up to three times a day.
- **Recommendation:** Save a card for off-session use only when its holder turns on auto-renew. Bind the mandate to the network and the payer.

### 2. Correctness and feasibility

**R1-32. Every direct call holds the provider's costliest worst case, which strands small balances (high)**
- **Where:** §6.6, line 1236, "the hold the floor counts is the worst case of the costliest model the provider serves"; §9.7, line 2033, "so a $5 balance runs two such calls at once".
- **Problem:** Under CO-32 the direct path is the only remote path at launch. Each call holds the provider's costliest model at full context, whatever model it names. The example's $2.15 uses provider prices; charges are at catalog prices, so with the 1.20 markup the hold is about $2.58, and two exceed $5. On engy's costliest model this review estimates about $3. A person buys the 5-credit pack and runs Codex through the gateway. The second concurrent call is refused for balance while the session has cost cents. Once available falls under one hold, no direct call starts, which strands roughly half the smallest pack. A pricier model that engy lists tomorrow raises every network's hold. "A cheap model hundreds" is true only on the TEE path.
- **Recommendation:** Make a bound the broker can sign and the provider enforces a condition of G-PROV-engy and G-PROV-saygm: a per-hotkey model allowlist, or a model and cost cap in the signed target. Until then, hold the declared model's worst case and carry a capped exposure per network. Add a refusal reason `held` with a retry time, so the Harness does not ask for money the person already has. Fix the example.

**R1-33. States and auto-renew run on a balance that includes holds, and an unanswered hold becomes a charge (high)**
- **Where:** §9.7, line 2029, "available = settled - unsettled charges - open holds"; §9.8, line 2040; §9.7, line 2015, "with no answer from the provider in 10 minutes, the hold is charged".
- **Problem:** A network with $7.50 and threshold top-up on makes one engy call. Available drops under $5 and the card is charged $20 for a call that cost a cent. Low-balance notices flap the same way. If engy is down, each retry takes a new hold, and after 10 minutes each is charged at its hold. A $20 balance settles to zero, the threshold fires up to three times a day, grace starts, and after an hour enclaves stop, the mail indexer among them. The charges are refunded later; the card charges and the stopped enclaves are real.
- **Recommendation:** Drive §9.9's states and auto-renew from the settled balance less accrued enclave time, and use `available` for admission only. Never settle an unanswered hold as a charge: keep it pending, capped per network. Reserve the overdraft floor for enclave intervals.

**R1-34. The direct path's hold lifecycle has three holes (medium)**
- **Where:** §6.6, line 1235, "a retry takes a new signature over the same hash, under the same hold"; §14.5's `compute_direct_settle` row, "a lookup that finds no request served under the nonce".
- **Problem:** Line 1235 says one hold covers a retry; line 1243 releases "the unused authorization's hold", one per authorization. If it is one hold, a modified client collects several signatures, is served several times against one hold, and overdraws. If it is one each, an honest retry needs double the hold. Second, a long generation is still running one minute after its nonce; if the provider records usage at completion, the hold is released mid-call. Third, a call longer than 10 minutes is charged after its hash is dropped, so its receipt cannot be checked.
- **Recommendation:** One hold per authorization. Sign a retry only after the lookup shows the earlier nonce unused. Require a three-state lookup from the provider: unknown, in progress, finished. Set a maximum call duration.

**R1-35. On macOS the engine cannot load LiteRT-LM as written without weakening the process that holds the keys (high)**
- **Where:** §6.5, line 1128, "the same `ur` binary in engine mode, loading the C library with purego".
- **Problem:** DESIGN.md line 3473 makes `ur` a hardened-runtime, notarized Developer ID bundle that claims the app groups. Under the hardened runtime, library validation loads only libraries signed by Apple or the same team. Google's libraries and GPU plugins, downloaded at first use, are neither. Either the load fails or `ur` takes the entitlement that disables library validation, and since the engine is the same binary, the daemon gets it too. The document never mentions notarization or library validation. The engine child also parses model files and attacker-influenced text in C++ with the user's network and file access, which is outside what IC-7 promises.
- **Recommendation:** A separate helper executable with its own bundle id and no keychain or app group, carrying that entitlement or libraries re-signed by URnetwork. Sandbox it: no network, read-only on model files. Add a library-load test on a notarized build to M11's exit.

**R1-36. The Harness loop does not fit the default local models, and phones are under-specified (medium)**
- **Where:** §7.4, line 1383, "keeps the last 20,000 tokens"; §6.5, line 1130, "a Play Feature Delivery module"; §20.7, line 3618, "its agents answering only in the foreground".
- **Problem:** The default phone model's window is 32k tokens at most. Compaction fires at the window less 16,384 and keeps 20,000, so it removes nothing. The local profile carries about fifty tool schemas and the skill before the first user word. Nothing says how eight local agents share one engine. Android's default build flavor is `github`, the build without Play (android/app/app/build.gradle), which has no Play Feature Delivery. And no section says what happens to a phone-hosted run when the app leaves the foreground: a remote stream is cut while the provider keeps generating and charging.
- **Recommendation:** Scale compaction to the window. Give each model a tool budget and the local profile a reduced tool set. Say per build flavor how the engine ships. Specify backgrounding per platform: cancel or finish under a background task, journal, pause at an item boundary. Add to M11's exit a tool-using turn on the default phone model.

**R1-37. Resume and continue read a record that is redacted by default (high for phones)**
- **Where:** §24.9, line 4883, "apply to every node, blob and transcript line before it is sealed"; DESIGN.md line 16032, `record.redact.pii` "default `hash`".
- **Problem:** The journal holds only sealed, redacted entries, and §24 names no unredacted local source. After any daemon restart or app death, which is routine on phones, the resumed context has a marker where the person typed "invite bob@example.com", markers for every attendee in calendar results, and stubs where search results were. §24.1's "rebuilt exactly" holds only for calls with no match. Q-CTXH-10 weighs secrets, not the default PII rule, and an agent cannot read again an address the person typed.
- **Recommendation:** Exempt kinds 54 and 55 from PII hashing and keep the secret rules; they are vault-only and never indexed. Apply PII hashing where history leaves the owner's devices: exports, disclosures and, by choice, packs. State that a continued run must search, and pay, again.

**R1-38. Per-call pushes are not budgeted, and an enclave's history needs a member's device (medium)**
- **Where:** §24.5, line 4712, "pushes them in its batches of 64 entries or 1 s" and "past 3,000 it pauses its runs' new calls"; §14.8.
- **Problem:** DESIGN's binding storage limit is drive writes per push, and §24.10 counts only bytes. Each call now makes at least two pushes. By this review's estimate that adds 60% to 90% to a working member's daily pushes. An enclave agent at 80 calls an hour reaches 1,000 unconsumed deposits in about 12 hours, and 3,000 about a week later. A phone-only person, or anyone whose laptop is shut for ten days, finds every enclave run paused. The text does not say whether phones ingest.
- **Recommendation:** IC-19 needs only the local write, so push session entries every 30 to 60 seconds or at turn end. Coalesce enclave deposits from the first call. Give session deposits their own prefix and let devices ingest lazily. Add a pushes-per-member-day row to §24.10 and §14.8. Add "needs a device of the member online within about a week, or a keeper" to Appendix F.

**R1-39. At the storage cap the newest history goes first, and the numbers do not hold together (medium)**
- **Where:** §24.10, line 4907, "history writes stop at 90%"; line 4902, "holds 2-5 months of it".
- **Problem:** "Writes stop" conflicts with IC-19 unless nodes keep writing and only parts drop, which makes the cap soft. The default member share of half gives a one-person Community network 512 MiB, about one to two and a half months at the document's own rates, not two to five. After the cap, old runs stay whole and every new run loses its large parts.
- **Recommendation:** State what continues and what stops. Correct the estimate. Derive the default share from the member count. Have the warning offer one-tap expiry of the oldest `bulk` entries.

**R1-40. The "always-on" indexer is not always on (high for CO-19 (1) and CO-20)**
- **Where:** §9.9, line 2060, "grace older than 1 h"; §11.7, line 2480, "only on a machine whose chip identity"; §11.11, line 2539, "or silent for 5 minutes, is `failed`".
- **Problem:** Three separate rules stop it.
  - It stops one hour after the balance reaches zero. A person who buys in the App Store has no threshold top-up. Their agents spend the balance, the indexer stops, and mail bounces at senders with short retry windows. One disputed lot suspends the whole network's compute.
  - A keeper restarts it alone only on a machine it used before. The providers describe no machine pinning, so most restarts page a person. Each new incarnation needs a new mail-host key and certificate, live two TTLs later, so every restart is a mail gap.
  - A broker or relay incident longer than five minutes marks every enclave failed at once.
- **Recommendation:** At setup, move about 7 days of the indexer's cost into a reserve only its charges draw, and give that role a 72-hour grace. Allow unattended restart on any attested machine, with a notice and a rate limit. Design a make-before-break restart. Mark an enclave failed only on the provider's report. Say all of this on the setup sheet.

**R1-41. `auto` egress drops TCP 22 and every other privileged port (medium)**
- **Where:** §11.7, line 2476, "The device dials the VM's SSH port through `auto` egress"; §11.8.
- **Problem:** Verified in code: connect/ip_security_cfaa.go drops destination ports below 1024 other than a short list (80, 443 and the secure mail and DNS ports) for non-Network sources. Setup over SSH therefore fails wherever the provider's SSH is on port 22. Under the default mode an enclave's agents cannot `git clone` over ssh, scp or rsync outward, while the disclosure says they act as root on the internet. §22.4 knows this for fetch; §11 does not.
- **Recommendation:** For the fourth form, require a port at or above 1024 or relay the session through the broker. State the port limits in §11.8, the enclave disclosure and the skill.

**R1-42. The reference provider cannot exercise the SEV-SNP paths the first two enclave providers need (medium)**
- **Where:** §11.3, line 2391, "where URnetwork boots its own image and binds its own launch data".
- **Problem:** Google's attestation documentation says that on SEV-SNP the launch measurement covers firmware only, with the rest in a vTPM Google controls, and documents no customer-set HOST_DATA. Only TDX measures the image into hardware registers there. Hippius and Cathedral are both SEV-SNP. M14's exit on the reference provider proves little about them.
- **Recommendation:** Add a self-hosted SEV-SNP host as a second reference, for development and CI only. Correct §11.3's sentence.

**R1-43. Store purchases have four correctness gaps and three policy assumptions (medium)**
- **Where:** §9.5, line 1970, "auto-renewing subscriptions granting 10, 25, 50 or 100 credits a month"; §14.3, line 2907, "a purchase naming no live network credits none"; Q-BAL-3.
- **Problem:**
  - Apple upgrades take effect at once with a prorated refund. Stepping through four plans in one sitting appears to grant 185 credits for about the price of 100; which notification Apple sends was not tested.
  - Play keeps one purchase token across renewals. A unique key on the token credits a Play subscription once, ever.
  - Consumables are new to the server. The checkout finds no consumable or consume handling, and Play refunds an unacknowledged purchase after three days.
  - A purchase with no account token "credits none", though the store took the money.
  - The 15% commission applies only in the small-business programs or after a subscriber's first year. Play's payments policy says in-app virtual currency "must only be used within the app or game title for which they were purchased", and these credits are spent by the CLI and enclaves. Stripe flows inside a store build are steering outside the US storefront.
- **Recommendation:** One subscription group per credit plan, or grant only the difference on upgrade. Define the market reference per product type. Design the consumable flow. Reuse Pro's binding rules. Add the store rules to §19.2's counsel gate, which now covers only cryptocurrency.

**R1-44. "Covers these with room" and "no exchange-rate risk" are not supported (medium)**
- **Where:** §10.6, line 2271, "covers these with room"; D-BAL-2, line 2141, "so a USD balance carries no exchange-rate risk".
- **Problem:** Weekly TAO buys and a 7-day float mean TAO is minted about 10 days after purchase. The document's own readings show a 12.5% fall in under two weeks, which turns a 1.20 markup into about 1.05. Stripe's fee on the $5 pack is 8.9%. At a 30% store commission, a 5-credit pack priced for 15% about breaks even against provider cost.
- **Recommendation:** A margin table per pack and market. A weekly realized-margin alarm per provider. Keep CO-35's weekly rhythm as a USD transfer to the exchange, and convert and mint just in time with a hot float of one to two days. Make $10 the smallest Stripe pack.

**R1-45. The closed-loop argument cites a limit the design does not have (medium)**
- **Where:** §10.8, line 2291, "under $2,000 a day per account"; §9.11, line 2086, the balance cap of $10,000.
- **Problem:** §9.11 has no $2,000-a-day limit. After a network's first week, twenty $500 packs in a day pass. The prepaid-access exclusion the section leans on is worded on the value associated with a device on any day. I am not counsel; the finding is that the text cites a limit it does not design. Credits that never expire (CO-35) also raise unclaimed-property rules, which the document does not mention.
- **Recommendation:** Add a daily load limit under $2,000 per network and per payer to §9.11. Have counsel read this before the store products are submitted, not at M12's exit.

**R1-46. "A network never owes more than $5" does not hold, and "forecast" is never defined (medium)**
- **Where:** §9.9, line 2065, "so a network never owes more than $5"; line 2060; §10.4, line 2238, "holds under 1 day of P's forecast cost".
- **Problem:** No state covers an interval hold refused while available is still positive. A large GPU shape costs about $19 per 10-minute interval by this review's estimate, so one refused hold can end near -$9. Line 2060 says "available <= floor" where every other line uses the negative floor; read literally it suspends any network holding $5 or less. Separately, deposits and caps are sized by a forecast that is zero at launch. One GPU enclave can exceed a provider's whole forecast, and the broker never refuses a hold because the provider's prepaid balance cannot cover it.
- **Recommendation:** On a refused interval hold, schedule that enclave's stop from what is left. Fix the sign. Define forecast as the largest of the trailing mean, the committed rate of running enclaves, and a floor per provider. Refuse new holds with `capacity` when the provider's balance is short.

**R1-47. The gateway: a 4 MiB cap, retries billed twice in flight, and Claude Code settings (medium)**
- **Where:** §8.7, line 1763, "4 MiB request body"; §8.5, line 1737, "keeps each completed response for 10 minutes"; §8.8.
- **Problem:** Codex and Claude Code resend full history each turn. A session with two or three screenshots passes 4 MiB, and every later request fails, compaction included. The retry cache covers only completed responses, so a retry that arrives mid-call starts a second paid call; Codex retries streams several times by default. The cache is memory only, and a daemon restart is the likeliest cause of a cut stream. Claude Code prepends an attribution block with a conversation fingerprint that reaches a `none` provider in plaintext, takes one context-window value for three model slots, and stops compacting when a gateway rewords an overflow error. The last three come from Claude Code's gateway documentation as this review read it.
- **Recommendation:** Decouple the direct path's nonce window from body upload and accept at least 32 MiB. Join identical in-flight requests. Strip or disable the attribution block. Map overflow errors to each API's own wording. Add each to the per-release suite.

**R1-48. G-SRCH-parallel's one paid call cannot settle its open items (medium)**
- **Where:** §19.2, line 3450, "one paid test call from staging"; Appendix F, line 6307, "the gateway settles each payment before it searches".
- **Problem:** Whether the gateway's instances share the payee cache, whether a payee outlives the broker's round trip from slow exits, and whether unpaid requests count toward the rate limit show only under load. The x402 specification's default flow is verify, serve, settle, which points the other way from Appendix F's sentence; §21.3 only says Parallel's wording "suggests" settlement first. A search is two requests against a limit of 60 a minute per address, and changing exit after a `429` reads as the circumvention Parallel's policy bars. Pending authorizations live only in Redis, so a failover makes in-flight nonces look like key theft and stops the signer for everyone.
- **Recommendation:** A load test of several hundred paid calls from many exits, with pass thresholds. Reword the tool, the card and Appendix F as conditional. Back off on the same exit. Keep the pending set durably and name two Base data sources.

**R1-49. Two assumptions about provider edges carry both remote paths, and no gate tests them (medium)**
- **Where:** §6.6, line 1219, "a nonce at most 10 s old when the body has arrived"; §5.7.
- **Problem:** Direct calls go to a provider behind Cloudflare, through a different exit each time, with a body of up to 4 MiB that must land inside a 10-second signature window. Edge bot rules commonly challenge VPN addresses, and an API client cannot answer a challenge. The TEE path relies on Chutes' evidence endpoint staying anonymous, and every device arrives from the broker's address, so one rate limit serves all users.
- **Recommendation:** G-PROV-engy measures success and latency across a sample of exits and obtains an edge exemption for signed routes. The agreement with Chutes fixes anonymous evidence access and a rate. Limit the tunnel per sidecar.

**R1-50. Connections through exits: the pin is unspecified, and Microsoft work accounts are thinner than stated (medium)**
- **Where:** §25.8, line 5224, "a connection keeps one exit, chosen at its code exchange"; §25.17.
- **Problem:** Under `auto` the exit is a public provider of the network. The text does not say what is recorded, how long such an exit lives, or how several devices pin it. Each change is a new address at the next refresh, and the document's own stated impact is a work account's sessions revoked. The privacy bought is small: the provider knows the account and sees the person's address at sign-in. Tenants with Conditional Access judge the token request's address, and tenants that require admin consent or device compliance refuse a public-client flow whatever the publisher's status.
- **Recommendation:** Specify the pin. Add `direct` as a choice for connections and CalDAV links; no URnetwork server is involved either way. Run a test account through exit changes for 30 days at each gate. State the expected Microsoft coverage and map its error codes to texts that name the fix.

**R1-51. URnetwork's OAuth clients share one fate, and two claims about them are doubtful (medium)**
- **Where:** §25.5, line 5146, "no client secret for URnetwork's clients"; §25.4.
- **Problem:** Google's Desktop client type has long issued a client secret that its token endpoint expects, though Google says it is not confidential. The Desktop definition will most likely need one, and it would then sit in a public signed policy, against Google's rule on committing credentials. The Calendar API's quota is per project across all users, and no URnetwork server sees a call, so the only caps are a device's. If Google suspends the client, every Google connection fails at once and rotation means every user reconnects.
- **Recommendation:** Settle the Desktop secret at the gate and say where it lives. Request quota headroom and watch the console's aggregates. Write the rotation and suspension runbook. Use a separate project for staging.

**R1-52. The bundled git's stock-git claim is wrong, and basic semantics are unspecified (low)**
- **Where:** §13.4, line 2781, "stock git can open it on a desktop for debugging".
- **Problem:** Index version 2 has no skip-worktree bit, so stock git would read a sparse clone as mass deletions. `.gitignore` is never mentioned. Rename detection, file modes and case-folding collisions on macOS and Windows are unspecified, though §18 promises conformance with stock git.
- **Recommendation:** Drop the claim or limit it to full clones. Specify ignore rules, renames, modes and collisions.

**R1-53. Smaller correctness points (low)**

| Where | Problem | Fix |
|---|---|---|
| §11.10, line 2512, `ptrace_scope` = 3 | the setting is global and blocks gdb and strace in the container, though the image ships debugging tools; the user namespace already protects the daemon | drop it; list what "full tools" excludes |
| §11.9, line 2501, "makes reads fail, not lie" | authenticated disk encryption does not detect replay of an older sector | state the limit |
| §6.3, line 1079; §9.6 | nothing bounds how old a catalog version a request may name, so a modified client keeps old prices; SayGM prices per request below its list | accept the current and previous version for 24 to 48 hours; price dynamic providers at their ceiling |
| §23.4, line 4313, "the first text part" | much commercial and burner mail is HTML-only, so summaries rest on snippets | render the HTML part with §22's extractor |
| §25.6, line 5182 | scopes are kept per connection, but Google's tokens are per platform, so a feature shows on while one platform's token lacks it | record scopes per token entry |
| §23.8, line 4416, "without it the write takes the series" | a model that omits `occurrence` removes years of a recurring event | require an explicit scope |
| §20.5, line 3550, "creates the agent repo" | every registration creates a repo, cards retire only by revocation, and `agent_list` reads every card | create the repo at the first deposit; retire idle cards |
| §20.7, lines 3594-3614 | a recipient cannot read another member's card, and `from` carries no repo id, so a cross-member reply has no stated address | carry the sender's repo id |
| §21.6, line 3905 | the query check refuses a person's own "who owns support@acme.com" with no override | in an attached run, turn a personal-data match into a confirmation |
| §24.9, line 4882 | search stubs are matched by whole-result hash; a harness that truncates or saves a large result to a file defeats it | stub by tool-call identity first |
| §25.6, line 5200 | Microsoft tokens are written back at every refresh, though old ones stay valid; hourly writes show storage when agents are active | write back when the stored token is about a week old; make every write a compare-and-swap |
| §9.7, line 2004; §14.4 | the "one script" for holds, budgets and rates spans Redis hash slots, which production's cluster rejects | key budgets and rates under the network's tag |

### 3. Coherence

**R1-54. The per-device spending ceiling exists only as a question's answer (medium)**
- **Where:** §16.4, line 3282, "so no local grant, harness or process spends past them"; Q-CACL-4, line 3353.
- **Problem:** §16.5 bounds each agent id at $5 a day, and the device figure covers only calls that name no agent. Q-CACL-4 itself says a process that mints agent ids is "bounded only by the balance and auto-renew's limits". Its answer, $50 a day per device, appears in no D- line and not in §16.5 or §8.6. So §16.4's sentence is false as the tables stand, and the fix changes CO-35's defaults in effect without saying so.
- **Recommendation:** Make it a D-CACL decision, put it in §16.5 and §8.6, add a broker test, and flag it to the owner.

**R1-55. `inference:local` says use is private, and context history pushes at every call (medium)**
- **Where:** §2.8, line 407, "That you used it: a local call sends no request and makes no charge"; §24.5, line 4712; M11's exit, "no request to a server".
- **Problem:** The same disclosure lists, under what could be exposed, that storage "sees its sizes and when it is written and read". Session entries push within a second of each call, so URnetwork's storage learns that a device ran a model call, when, and roughly how large. IC-5 is true of the inference and not of the run. M11's exit criterion cannot be met as worded.
- **Recommendation:** Reword the Private line to "what you and the model said". Reword IC-5 and M11's exit to "no request for the inference". R1-38's slower push cadence also blurs the timing.

**R1-56. Canonical names mislead where no badge shows (low)**
- **Where:** §6.3, lines 1053-1063, "a provider's own marks stay, as Chutes' "-tee""; §16.2, line 3175, `model:*-tee-*`.
- **Problem:** SayGM's `-tee` models are labeled `none` yet keep `-tee` in the name, and in Codex's picker the name is all a person sees. §16.2's own example glob would admit them. `none` means a label, an effort (`local-gemma-4-e4b-none`), a floor and an egress mode. Dropping the organization prefix collides ids that differ only by organization.
- **Recommendation:** Strip or rewrite a provider's `-tee` mark when the label is `none`. Remove the glob example and point to `assurance_floor`. Rename the effort or the label. Refuse a catalog whose normalized names collide.

**R1-57. Any change of a disclosure's text asks everyone again and stops work (low)**
- **Where:** §2.8's Text row, "raised at any change of text"; §26.6, line 5626, "at a new version it stops publishing until the person acknowledges again".
- **Problem:** A typo fix is a new version. It stops unattended runs and gateway calls on `none` providers in every network, and empties every person's listeners list, until each person acknowledges. Running enclaves keep on at a new version (Q-ENC-8), so the rules disagree. The texts have no translations, though the apps are localized.
- **Recommendation:** Separate a material version, which asks again, from an editorial revision, which does not. Give a material change a grace period of about 14 days with a "changed" mark. Say how translations are signed.

**R1-58. Contradictions and slips (low)**

| Where | Conflict |
|---|---|
| §2.7, line 348, "up to a day's deposit" and §10.9, line 2300, "at most 2 days' deposit" | the loss bound for a dissolved subnet |
| §10.2, line 2210, "(PR #3300, release 487)" and mmm/BTCPAY.md §18.1 | BTCPAY says runtime 488 |
| §10.6, line 2266 | mint impact is given for three subnets that are not launch providers |
| §9.9's `low` row and §9.8 | whether threshold renew fires on entering `low` or only below T |
| §23.7, line 4373, and §25.13, line 5385 | which egress key governs a Microsoft calendar's calls |
| §25.4, line 5131, and §25.8, line 5226 | a private-name issuer is reached over the overlay, yet every call refuses the overlay |
| §7.8, line 1477, "on another device" and I-9 | the presence key is dropped, though Appendix F's CO-24 row relies on it |
| §7.4's `HarnessBudget`, line 1363, and §16.4 | day and run against day, month and run |
| §20.5, line 3550, and §20.14, line 3745 | every registration creates an agent repo; ephemeral agents "use only the agents repo" |
| §3.3, line 581, and owner rule 2 | `computeservice/gamma_*.go` sits "over the server's chain reader", which sidecar may not import |
| §21.3, line 3789, and Parallel's terms | "a customer keeps the version in force when it joined" against the clause that makes continued use acceptance; the paraphrase of the restrictions drops "sell, resell", which a 1.20 markup is on its face |
| §19.1's M12 row, "(from M15, for the apps' bot tab, CO-19)" | reads as "from M15 on"; it means "moved in from M15" |

**R1-59. Mechanisms that could be one (low)**
- **Where:** §5.7's evidence tunnel and §6.6's egress; §7.10's management link and §20.7's threads; §23.8's calendar tools and §25.9's `service_call`; §21.8's outcome reports.
- **Problem:** Each pair does nearly the same job with its own rules and tests. The direct path already trusts the network's egress to carry a device's TLS to a provider, yet evidence gets its own tunnel through the broker. A management prompt is both an RPC and a thread message. Calendar reads have two paths with different limits (R1-18). Search outcome counts add a route, a job, a table and a metadata row, where a staging canary that searches every few minutes would measure the failure rate with nothing new from users' devices.
- **Recommendation:** Fetch evidence through the egress. Consider threads alone for management in M14, with the live link later. Let typed tools own their paths. Replace compute-11 with the canary.

### 4. Completeness against the use cases

**R1-60. "Supported once G-…" hides what a person can use at launch (high)**
- **Where:** Appendix F, lines 6272-6317; §19.2.
- **Problem:** Most rows end "supported once" a gate passes, and §19.2 shows that most gates need an outside party to build something first. engy must sign receipts on signed requests, answer usage by nonce and give written terms. SayGM must add two features. Chutes takes no gamma and is dropped (CO-32). No enclave provider meets EPC-1. Search waits on a paid test, counsel and an external review. Google and Microsoft calendars wait on app verification. So on the day M13 exits, at today's status, a person has local models, the skill and threads, context history, web fetch, CalDAV calendars, listeners and git on EVS. They have no remote model, no TEE inference, no enclave, no web search and no Google calendar writes, and the balance has nothing to spend on. The design is complete on URnetwork's side, which is what CO-39 can ask of it. The owner cannot see from Appendix F how much rests on others.
- **Recommendation:** Add a status table to §19: one row per use case, with what works with no gate, what it waits on, what the outside party must build, and the dates asked and committed. Update it at each milestone's entry.

**R1-61. Tagged sidecars have no remote inference at launch (medium)**
- **Where:** Q-CTRUST-3, line 524, "(a) at launch, enclaves aside"; CO-32.
- **Problem:** A tagged or cloud sidecar cannot acknowledge a disclosure, so it gets `disclosure_required` for every `none` provider. Under CO-32 the only launch providers are `none`. A cloud agent, a CI runner or a development server then has local models only, on hardware where the local engine is slow or has no build. The answer says such a sidecar "still uses local and TEE models", which at launch means local.
- **Recommendation:** For tagged subjects at launch, take option (c): an Owner's or Admin's acknowledgment per provider in the `compute` block, shown in the network's settings. Or say plainly that these sidecars wait for Chutes.

**R1-62. Use cases that hold only under conditions Appendix F does not state (medium)**

| Statement | Condition not stated | See |
|---|---|---|
| CO-1, the phone example | the default phone model must fit the loop and the tool set; Android needs a Play build | R1-36 |
| CO-5 | "full tools" excludes outbound ssh and scp under `auto` egress, debuggers as written, and nested containers | R1-41, R1-53 |
| CO-17 | the first search taints the run, which then gets 10 fetches and an approval per page after; a static `GET` from an exit's address fails on many sites, and M13's exit sets no success rate | R1-30 |
| CO-19 (1), CO-20 | a funded balance at all times, and a person at most restarts | R1-40 |
| CO-23 | once the bot reads a report it is tainted, and it "still asks at its next such prompt" (§7.10, line 1597). A verbatim relay would fix this: the tool names the person's own message, and the Harness sends those exact words under the person's origin | |
| CO-24 | "my unread mail" is UR mail only; until G-CONN-google a Google calendar is read-only and each event is one add sheet; many Microsoft work tenants refuse | R1-50 |
| CO-25 | a resumed or continued run loses addresses, numbers and search results; an enclave's history needs a device of the member online within about a week | R1-37, R1-38 |
| CO-38 | `ur daemon` on the desktop, since an app-only desktop lists as a phone; descriptions will often read "another user's program" or `docker-proxy`; WireGuard's default port is above the server threshold, so Q-LSTN-6's own example is never listed | |

### 5. Architecture and scope

**R1-63. The build order spends most of its effort on paths no user can reach (high)**
- **Where:** §19.1's M12 exit, "a TEE model answers through the Harness and Codex"; the M14 row; §19.2.
- **Problem:** M12's exit needs a TEE call through Chutes, which CO-32 drops from launch. The tunnel, the encrypted envelope and the GPU verification serve no user until Chutes' subnet enables gamma. M14 is 13.5 to 15.5 engineer-months, and none of it reaches a user until a provider ships a launch binding that does not exist today. M13 ships an SSH client with nothing to connect to. The engy and SayGM adapters are built against features those providers have not committed to. If one declines, the work is stranded.
- **Recommendation:**
  - Build in this order: M11; the gate-free parts of M13 (fetch, CalDAV, listeners, git); the balance and the direct path once engy commits in writing; the Chutes path when gamma on its subnet is real; the enclave adapters when a provider commits to EPC-1.
  - Build no adapter before its provider's written commitment to the gate's asks. Send the asks now.
  - Before M12's entry, run a paid spike against engy: signed requests through exits, receipts, the lookup's states, the edge's behaviour. Before M14's, measure VM lifetimes and restarts on Hippius.
  - Keep the policy pipeline and the CPU verifier, which enclaves and the direct line need anyway.

**R1-64. Effort is under-counted, and there is no staffing plan (high)**
- **Where:** §19.4, line 3463, "connected services 1".
- **Problem:** The total is 55 to 65 engineer-months, about five times DESIGN's M10, for which DESIGN plans three engineers. §19 names no team or track, where DESIGN §23.5 does for M0 to M10. Several lines look low by two or three times:
  - connected services, 1 month: an OAuth client on five platforms, a credential store with write-back, a rule engine, kind 26 and two provider reviews;
  - mail and calendar, 2 months: four calendar clients with recurrence, and kind 25;
  - context history, about 2.5 months over four milestones: two record kinds, a change to how readers verify, three gateway matchers and packs;
  - listeners, 2 months: discovery on three operating systems, a repo kind, an ACL resource through compiler, gates and hook, and a peer RPC;
  - store purchases, counted as a product family on existing routes (R1-43).
  M13 alone holds nine features.
- **Recommendation:** Re-estimate after the cuts in R1-69, with a named team per milestone. Split M13 in two. Give listeners its own track, since it depends only on the bridge, EVS and the ACL.

**R1-65. The offline release key becomes a routine key, and the operating load is not counted (medium)**
- **Where:** §5.4, line 890, "the offline two-person key that signs `SHA256SUMS`".
- **Problem:** That key must now sign every Chutes measurement profile, every model's chute id, every disclosure wording, every direct, search and services line, revocations, 90 tickets a run, and a staging policy each week. DESIGN.md line 3498 rejected an offline two-person signature for a pipeline that runs almost daily. If the signers lag a provider's image roll, TEE inference fails closed for everyone. Beyond the key, URnetwork takes on weekly treasury buys that need two of three owners' hardware wallets, a hot payer float on Base, six provider adapters, 90-day re-checks of every provider and disclosure text, conformance runs per Codex and Claude Code release, and OAuth app verification. No section totals this or says who does it.
- **Recommendation:** A compute-policy key that the release key certifies, and a separate staging key. State the expected signing cadence. Add an operations section with a rota and runbooks for a signer who is away, a provider or OAuth client suspended, and a stopped payer key.

**R1-66. Web search carries a lot of machinery for one tool on a young dependency (medium)**
- **Where:** §21.5; §21.12.
- **Problem:** One tool needs a hot signer, a chain watcher, a float refill, policy pins, a legal gate and an outcome pipeline. Parallel's own post describes the gateway's payee cache as in-memory on a Stripe preview API, and no capacity is published. All of URnetwork's users share one payer address and shared exits against a per-address rate limit. There is no ready replacement.
- **Recommendation:** Run R1-48's load test before building the signer. Tell Parallel the payer address and expected volume; a notice is not an agreement. Name the fallback provider and what a switch would cost.

**R1-67. The credential store reaches users before its security review (medium)**
- **Where:** §19.1's M16 row, "§25's credential store and sign-in flows"; the G-CONN row, line 3451.
- **Problem:** G-CONN asks for the provider's own review and "a second person's review" of the rules and the text. The red team on the store is M16, after users hold live Google and Microsoft tokens in it. The verifier and enclaves get an external audit before first use.
- **Recommendation:** Add a security review of the OAuth client, the store and kinds 25 and 26 to G-CONN-<service>.

**R1-68. The outside facts will be stale before M11 starts (medium)**
- **Where:** §4.4, §8.3, §21.3, §25.3 and the texts of §2.8.
- **Problem:** All the research is dated 2026-11-23, and M11 starts after M10's exit. By the document's own count Gamma's calls changed four times in a month. Parallel's gateway is months old, and Codex and Claude Code ship new releases every few weeks. Prices, model lists, harness versions and terms are written into normative sections and into signed texts.
- **Recommendation:** Move provider facts to dated appendices. Give each milestone an entry check that re-verifies the facts it builds on. Keep the body to what URnetwork requires of a provider.

**R1-69. What can be cut or deferred without losing a use case (medium)**

| Cut or defer | Why it is safe |
|---|---|
| PiG in the measured enclave image (§7.3, line 1349) | CO-1 says "look at" PiG, which D-HARN-1 does; a person can install it in the container; §7.3's own table counts about a million lines from one main author |
| EPC-1's fourth form, setup over SSH | a second provisioning protocol with R1-6's gap and R1-41's port problem, and it still needs a provider feature |
| The Chutes path, beacon nonces, GPU verification and A2 lists, until their gates | R1-63 |
| `calendar_update`, `calendar_delete` and Undo | CO-24 asks only to add |
| `service_call` writes with kind 26, custom definitions, the strict rotation lease | Q-CONN-3 says the tool "adds little on Google and Microsoft" at launch; no launch definition rotates strictly |
| The Android App Link and `oauth.ur.io` | Chrome's Auth Tab captures a custom-scheme redirect; this removes the one path by which a code could be asked of a URnetwork host |
| The M13 SSH client | nothing to connect to until M14 |
| Merge, stash, tag and grep in the bundled git | the local Harness has no shell; agents push to their own branch after a fast-forward pull |
| The Team inbox and cross-member deposits | until a Team asks |
| The Stripe monthly plan, promotion lots, self-serve refunds | threshold covers the web; support credits cover refunds |
| UDP listing and the live ask for other people's devices | CO-38's list holds without them |
| compute-11's outcome pipeline | a staging canary measures the same rate |
| `ur gateway run` and the long tail of Chat Completions harnesses | until asked for |

### 6. Readability for the owner

**R1-70. 116 questions name the owner as decider, in no order (medium)**
- **Where:** Appendix B; the front matter's CO-14 paragraph.
- **Problem:** There are 151 questions, 116 for the owner, and 146 proposed decisions that stand unless overridden. Nothing separates the dozen that cost money or are hard to undo from the rest. An owner who skims the register accepts by default things like setup over SSH, PiG in the image and a $50 device ceiling.
- **Recommendation:** Put a two-page decision brief ahead of §1: the 12 to 15 decisions that cost money, bind commercially or are hard to reverse, each with its options and its price. Mark everything else "stands unless you say otherwise".

**R1-71. Changes to the owner's earlier positions sit in table cells (medium)**
- **Where:** §11.10, line 2528 (owner decision 12); Q-CACL-4 (CO-35's budgets); Appendix D, line 6179 (DESIGN §1.7's promise that agents "reach only granted ranges"); Q-CTRUST-3.
- **Problem:** Each of these changes something the owner decided or promised in public. Each follows from a CO statement, but the owner would find none of them without reading the cell.
- **Recommendation:** List them in the decision brief under "this changes what you decided before".

**R1-72. The residuals the design accepts are scattered (low)**
- **Where:** §2.7's Residual column; §7.8; §21.5; §24.9.
- **Problem:** The design accepts many residuals in good faith: the EVS door, same-user processes, AP, time correlation, CO-29's cash-out. They sit across a dozen sections, and the owner accepts them as a set by approving the document.
- **Recommendation:** One table of accepted residuals, each with who can use it, what it costs them and what it yields.

**R1-73. Structure and prose (low)**
- **Where:** the contents; §19.1's M13 row; §19.4.
- **Problem:** §20 to §26 follow testing and phasing, so a reader meets the milestones before the designs they schedule. The M13 scope is one table cell of about 3,500 characters, too long to check a build against. Many paragraphs are single sentences of 150 words or more. Revision history leaks into normative text: "move in", "adds 1", "the reviews' … fixes".
- **Recommendation:** Move §20 to §26 ahead of §14. Break milestone scopes into lists. Keep history in a changelog.

## Questions for the owner

Each has a recommended answer.

1. **If no inference provider has passed its gate when M12 would start, what gets built?** Recommended: M11 and the gate-free parts of M13 first, and no adapter before its provider commits in writing. Keep CO-28's choice of providers, and revisit it only if one declines.
2. **Should Chutes' TEE path stay in M12, though CO-32 drops Chutes from launch?** Recommended: no. Keep the policy pipeline and the CPU verifier. Start the tunnel, the envelope and the GPU work when gamma on Chutes' subnet is real. M12's exit then needs no TEE call.
3. **Does M14 start before a provider commits to EPC-1?** Recommended: build the image, the measurement pipeline, the verifier and the SSH server on a SEV-SNP host the team controls. Hold the adapters, the indexer enclave and the management link until a commitment exists.
4. **Does the indexer enclave satisfy the directive, and does it replace owner decision 12?** Recommended: yes for personal networks. In a Team, only with a notice to every member and only on a provider that passes by EPC-1's first form or at A2. Record it as its own Q-ENC item.
5. **Should the indexer enclave have its own reserve and a longer grace, and may a keeper restart it on a new machine with no person?** Recommended: yes to both. Seven days reserved at setup and 72 hours of grace; unattended restart with a notice and a limit of two new machines a week.
6. **Should the broker screen each search payee before signing, and cap searches by a limit a network's policy cannot raise?** Recommended: yes to both. CO-29 accepted cash-out, not sanctions exposure or an uncapped path from a stolen card to USDC.
7. **May a tainted run's EVS writes reach an enclave that is on the internet with no person's act, and should an enclave read every summary of its member's agents?** Recommended: no to both. Enclaves read cards and status stubs; summaries by the sponsor's grant; a tainted run's versions wait for release.
8. **Should an agent's `enclave_stop` and `enclave_start` need the person in a tainted run, with the indexer enclave outside agent tools?** Recommended: yes.
9. **Does CO-38's "any client" include agents' containers by default: enclave agents, cloud agents, CI?** Recommended: they see the list and reach an entry by the sponsor's or an admin's one-line grant. If the answer stays yes, gate it on the Owner's acknowledgment (R1-11). Either way, each desktop confirms its own first list.
10. **Should a listed service be delivered as a localhost connection, which skips the host firewall?** Recommended: no for flows the listeners rule admits (R1-10).
11. **At launch, do you accept that each remote call locks roughly $2.60 to $3 of balance?** Recommended: no. Hold the declared model's worst case, let URnetwork carry up to $5 of exposure per network, and make $10 the smallest pack offered beside a remote model.
12. **Who holds the unreleased freshness tickets, how far ahead are they signed, and may a delegated key sign the compute policy?** Recommended: sign 14 days ahead; keep unreleased tickets off the serving hosts and the broker; a compute-policy key that the release key certifies.
13. **Do you confirm Q-CACL-4's $50 a day per device across all its agents?** Recommended: yes, as a D- line. It bounds what CO-35's per-agent figures cannot.
14. **May a tagged sidecar use a `none` provider on an Owner's or Admin's acknowledgment?** Recommended: yes at launch, since `none` providers are the only remote ones then.
15. **Should sign-in codes and reset links be withheld from models outside the device or an A1 or A2 TEE?** Recommended: yes by default, in the daemon, with a per-person switch.
16. **Should session history be exempt from default PII hashing, so a run resumes with the addresses the person typed?** Recommended: yes for kinds 54 and 55, keeping the secret rules, with hashing at export, disclosure and packs.
17. **Does "my unread mail" in CO-24 mean UR mail only at launch?** Recommended: yes, and §23.1 should say so. Gmail and Outlook mail need restricted scopes, a yearly security assessment and their own design.
18. **Should a Team's audit reader, or a device of another platform, ever hold a member's live tokens?** Recommended: no. Seal credentials per platform to the member's own devices, and revoke at the provider when a member leaves.
19. **May a connected service's calls, and a CalDAV link's, leave by the device's own route where the person or network chooses?** Recommended: yes, as `direct`, with `auto` the default until the gate's 30-day exit test says otherwise.
20. **Do you accept cost swings of about 15% a fortnight from weekly TAO buys, and purchases with no daily limit after a network's first week?** Recommended: no to both. Send USD weekly and convert just in time; add a daily load limit under $2,000 per network and per payer.
21. **Which of R1-69's cuts do you take?** Recommended: all of them, with PiG in the image and setup over SSH first, since they also shrink the enclave audit.

## Checks behind this review

**Verified in the checkout.**
- DESIGN.md's hash and commit match the front matter. Ids are unique and unbroken; the registers hold 146 decisions and 151 questions.
- connect/ip_security_cfaa.go drops privileged destination ports outside its short list (R1-41).
- android/app/app/build.gradle makes `github`, the build without Play, the default flavor (R1-36).
- DESIGN.md line 3473 (the hardened-runtime bundle) and line 16032 (`record.redact.pii` default `hash`).
- server/controller/gamma_chain.go:95-97 and server/model/subscription_model.go:167-175 match the document's notation.
- Every quote in this review was matched against the file.

**Tested.** On macOS: a wildcard and a loopback-only socket bound to one port, with a dial to 127.0.0.1 reaching the loopback-only one; and listeners with their process ids listed without privilege.

**Confirmed at primary sources.** Parallel's gateway (endpoints, $0.01 a search, 60 requests a minute per address, "All payments are final") and its engineering post; EIP-3009; the x402 v2 flow; the btauth/1 guide; tee.fail; LiteRT-LM's releases and the Gemma 4 E2B card's 32k context; Codex's config reference; Claude Code's gateway pages; Google's OAuth guide for native apps, Workspace API user data policy and Calendar quota; Android's `AuthorizationClient`; Microsoft's refresh-token and publisher-verification pages; Chrome's Auth Tab guide; Apple's subscription upgrade rules and guideline 3.1.1; Play's payments policy; 31 CFR 1010.100(ff)(4)(iii)(A); Redis protected mode; the kernel's Yama documentation; engy's signed-receipt documentation.

**Not verified.** Chutes' live endpoints. SayGM's facts. Cathedral, for which no public source was found. How Hippius places and restarts VMs. Coinbase's screening rules and how it would treat the payer. That Google's token endpoint requires the Desktop client's secret (from long-standing behaviour and developer reports, not Google's page). Which notification an Apple upgrade sends. Co-binding on Linux and Windows. The token cost of the local tool set. The 30-day validity of vendor collateral (from memory). Whether Parallel fetches a URL named in an objective on demand. The dollar estimates marked as this review's.

**Not reviewed in depth.** Appendices A and B, which are generated from the body. App screens, which the document leaves to the apps.
