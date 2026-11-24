# Compute design amendments

This file holds the answers DESIGN-COMPUTE.md does not yet carry, for the owner to fold when they revise it.

The compute planner raised 151 questions about DESIGN-COMPUTE.md on 2026-11-24 (`.stack/questions/compute-plan-*.md`, listed in `.stack/plan/COMPUTE-PLAN.md`), and the owner answered all of them the same day, QD-1233 to QD-1383, each with the recommended option, under the owner's standing acceptance of recommended options (2026-11-16, restated 2026-11-19). The run's question ledger (`.stack/decisions/LEDGER.json`), `.stack/decisions/RESOLUTIONS.md` and `.stack/decisions/later-pending.md` record them outside git; this file is their durable copy in the sidecar repo, each answer stated as the rule it makes. Track dr17-compute-answers wrote it on 2026-11-24. One answer recorded after them that amends DESIGN-COMPUTE.md alone, QD-1386, the catalog's tie rule, which the build raised while implementing §6.3 (INFER-M11-01) and the owner answered the same day, is filed under §6 by track dr17-late-fold, which folded the rest of that day's later answers into DESIGN.md. Five more the build raised while implementing the compute policy (CACL-M11-01, CACL-M11-04, CACL-M11-05 and CACL-M12-01), QD-1388 to QD-1392, which the owner answered the same day, each with the recommended option, are filed under §14 and §16 by track dr19-support-fold; what they change in DESIGN.md it already carries, QD-1388's words in §2.8's compute-4 since metadata_list.yml v69, and QD-1389's to QD-1391's in §8.4 and §16.8 since the tenth fold. The owner folded four of the plan's readings into DESIGN-COMPUTE.md §26 on 2026-11-24, aligning its listeners with DESIGN.md's service discovery (owner decision 778; commit e9478d45): QD-1248 (`Deliver` on app hosts), QD-1249 (the listeners file's `desc_by` and `v4_uncertain` and the `LISTENERS` bodies), QD-1250 (`BridgeListenerReach` in `device/`) and QD-1251 (a labeled UDP socket above the ephemeral threshold), so they left this file, as its folding rule has a folded item do; track dr18-compute-fences took them out.

The answers are of two kinds:

- **Appendix answers**, QD-1258 to QD-1365, 108 in all, below by the DESIGN-COMPUTE.md section that asks them. Each answers a question of DESIGN-COMPUTE.md's question register (Appendix B): the 101 open owner questions of Appendix G.2, whose recommended answers the owner let stand with CO-44 ("Let recommendations stand", 2026-11-23), and 7 more that a compute task's plan cites, whose decider Appendix B gives as peer review (Q-CTRUST-2, Q-INFER-7, Q-HARN-6, Q-GW-7, Q-ENC-7, Q-ENC-14, Q-GIT-1) and whose answers stood as the design (CO-14). Every one takes the answer DESIGN-COMPUTE.md already gives, so the rule is the design's own; what the document does not carry yet is that the owner has decided it. One, QD-1260 (Q-BAL-16), is also the G.1 decision Appendix G calls still open, which the second review added after CO-42 and CO-44.
- **The plan's own readings**, QD-1233 to QD-1257 and QD-1366 to QD-1383, 43 in all, 39 left here, in a section of their own after the appendix answers. The planners raised them where DESIGN-COMPUTE.md leaves a format, a route, a module or a name open, or disagrees with itself or with the code (COMPUTE-PLAN.md's "What the design leaves contradictory or unbuildable"): command names that already exist, modules the design does not name, routes and bytes it gives no form. Each is a rule DESIGN-COMPUTE.md does not state, and some change DESIGN.md or RECORD.md through Appendix D as well, which the item's first line says.

**Precedence.** Where an item here and DESIGN-COMPUTE.md differ, the item governs until it is folded, as sidecar/DESIGN-AMENDMENTS.md's items govern DESIGN.md's text. The compute tasks build to these items, and to DESIGN-COMPUTE.md where they are silent. DESIGN-COMPUTE.md governs the points it owns over DESIGN.md until a design-records track folds its Appendix D (its front matter); an item that changes what Appendix D carries changes what that fold takes into DESIGN.md.

**Folding.** The owner writes DESIGN-COMPUTE.md and its review files (DESIGN-COMPUTE-REVIEW2.md, REVIEW-COMPUTE-REVIEW1.md) and pushes them to origin; no track edits them. When the owner revises DESIGN-COMPUTE.md, each item folds into the sections its first line names. An appendix answer folds by marking its question decided where its section asks it and in Appendix B, as the questions CO-35 and CO-41 settled are ("*Decider:* owner, confirmed (CO-35)"), and by dropping it from Appendix G.2's open list, QD-1260 also from G.1's note that it is the one G.1 decision still open. A reading folds by writing its rule into the sections it amends, and into Appendix D where it changes DESIGN.md or RECORD.md. A folded item leaves this file in the same change, and once none is left the file is deleted. An answer to a compute question given after these joins the section it amends, or the readings, the same way.

Each item gives the question as asked; a line naming where it folds and the option taken; the rule, with why where the answer gives a reason; the compute tasks that build to it (`.stack/plan/<AREA>.md`); and the question's file in `.stack/questions/`.

## Index

A reading appears in every row whose section it amends, and is written once, below, in the place of the section it mainly amends. §14.6's rows reach DESIGN.md through Appendix D's row for DESIGN §2.8's list, so a reading that amends one is listed under Appendix D too.

| DESIGN-COMPUTE.md section | Appendix answers | The plan's readings that amend it |
|---|---|---|
| §1 Context, scope and requirements | | QD-1253 |
| §2 Trust model and invariants | QD-1276, QD-1277 | QD-1242 |
| §3 Architecture and flows | | QD-1244 |
| §4 Providers | QD-1344 | QD-1247, QD-1257 |
| §5 Attestation and the policy | | QD-1242, QD-1243, QD-1254, QD-1256, QD-1379 |
| §6 Inference | QD-1324, QD-1325, QD-1326; QD-1386, the build's | QD-1237, QD-1241, QD-1246, QD-1247, QD-1370 |
| §7 The Harness | QD-1313 to QD-1323 | QD-1255 |
| §8 The local gateway | QD-1306 to QD-1312 | QD-1254 |
| §9 The compute balance | QD-1258 to QD-1262 | QD-1238, QD-1247, QD-1252, QD-1376 |
| §10 Paying providers in Gamma | | QD-1244, QD-1245, QD-1257 |
| §11 Secure enclaves | QD-1289 to QD-1298 | QD-1243, QD-1254, QD-1255 |
| §12 The bundled SSH | QD-1364, QD-1365 | QD-1243 |
| §13 The bundled git | QD-1304, QD-1305 | |
| §14 Server services, routes, tables and metadata | QD-1388, the build's | QD-1237, QD-1239, QD-1241, QD-1243, QD-1245, QD-1246, QD-1252, QD-1367, QD-1374, QD-1375, QD-1377 |
| §15 CLI, MCP, sdk and app surfaces | | QD-1247, QD-1253, QD-1380, QD-1381, QD-1382 |
| §16 Policy, budgets and approvals | QD-1263, QD-1264; QD-1389 to QD-1392, the build's | |
| §17 Abuse, safety and legal process | | QD-1382 |
| §19 Phasing and milestones | QD-1274, QD-1275 | QD-1233, QD-1255 |
| §20 The recURd skill | QD-1351 to QD-1355 | QD-1378, QD-1380 |
| §21 Web search | QD-1356 to QD-1363 | QD-1246, QD-1374, QD-1377, QD-1382, QD-1383 |
| §22 Web fetch | QD-1299 to QD-1303 | |
| §23 Mail and calendar for agents | QD-1335 to QD-1343 | QD-1235, QD-1236 |
| §24 Context history in EVS | QD-1278 to QD-1288 | QD-1234, QD-1240, QD-1366 |
| §25 Connected services | QD-1265 to QD-1273 | QD-1381 |
| §26 Listeners | QD-1327 to QD-1334 | |
| §27 Automatic approvals and the safety classifier | QD-1345 to QD-1350 | QD-1366, QD-1368 to QD-1373 |
| Appendix B, question register; Appendix G, open decisions | every appendix answer | |
| Appendix D, amendments to DESIGN.md | QD-1388 and QD-1390, the build's, which DESIGN.md already carries | QD-1234, QD-1237, QD-1238, QD-1240, QD-1243, QD-1252, QD-1254, QD-1255, QD-1366, QD-1367, QD-1374, QD-1378 |
| Appendix F, use-case coverage | | QD-1382 |

## §2 Trust model and invariants

### QD-1276 (Q-CTRUST-1): Is an acknowledgment kept per network or once per person?
*§2.10. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

A disclosure's acknowledgment is kept per network, in that network's vault; a person in two networks acknowledges in each. Why: the vault and its harness config are per network and DESIGN keeps no store across a person's networks; CO-26 treats each network as one person or entity, whose policy may allow different providers, so its member reads and acknowledges there.

Builds: INFER-M11-03, CTRUST-M12-01, CTRUST-M12-02. Question: `compute-plan-q-ctrust-1-acknowledgment-kept-per-network-once.md`.

### QD-1277 (Q-CTRUST-2): Should the broker refuse a call or a search whose disclosure the person has not acknowledged?
*§2.10. Appendix B, decided by peer review; not in G.2. The design's answer, (a).*

No: the device checks the acknowledgment, and the broker refuses nothing for want of one. Why: the acknowledgments are sealed in the person's vault, which no server reads, so the broker could check only a flag the device sets, which a modified client sets as easily as it skips the prompt; the check protects the person from surprise, which only the person's own device can do, and does not protect URnetwork from the device.

Builds: CTRUST-M12-01, CTRUST-M12-02. Question: `compute-plan-q-ctrust-2-broker-refuse-call-search-whose.md`.

## §4 Providers

### QD-1344 (Q-PROV-9): Until SayGM signs usage per request, should URnetwork use it through one hotkey per network, billing each network from its hotkey's `/balance`?
*§4.10. In Appendix G.2's open list, blocking M12b's entry. The design's answer, (a).*

No: SayGM waits for its gate, G-PROV-saygm, and is not used through per-network hotkeys meanwhile. Why: every mint and spend is a chain event under its hotkey, so per-network hotkeys would publish each network's spending as a series anyone can read, undoing the pooling behind URnetwork's hotkey (§10); each would cost a mint; and a modified client could still buy models URnetwork excludes (Q-PROV-7), since nothing bounds the model a body names.

Builds: PROV-M12-03. Question: `compute-plan-q-prov-9-until-saygm-signs-usage-per.md`.

## §6 Inference: the catalog, the router, the local engine and the remote path

### QD-1324 (Q-INFER-1): Does a local model that fails or lacks memory fall back to a remote one?
*§6.11. In Appendix G.2's open list, blocking M11's entry. The design's answer, (a).*

Never on its own: the Harness offers the switch to a remote model, and the person chooses (CO-9, CO-11). Why: local is free and private; remote costs money and leaves the device.

Builds: INFER-M11-02. Question: `compute-plan-q-infer-1-local-model-fails-lacks-memory.md`.

### QD-1325 (Q-INFER-6): Should a name let URnetwork pick the provider, as `any-<model>-<effort>` routed to the cheapest allowed one?
*§6.11. In Appendix G.2's open list, blocking nothing at launch. The design's answer.*

Not at launch: CO-18 puts the provider in the name, so the person always knows who serves a model. An `any` provider is Later, and would choose only among providers the person's floor and list allow.

Builds: nothing yet. Question: `compute-plan-q-infer-6-name-let-urnetwork-pick-provider.md`.

### QD-1326 (Q-INFER-7): One disclosure per provider, or one per model?
*§6.11. Appendix B, decided by peer review; not in G.2. The design's answer, (a).*

One disclosure per provider, its text naming any model whose exposure differs; a provider whose models differ more gets a disclosure id per group of models. engy's text names its one model without zero-retention workers, and SayGM's points to the upstream the signed policy names for each model. Why: the exposure follows the provider and its label, who reads a request and under which terms, and one acknowledgment per provider keeps the prompts few.

Builds: CTRUST-M11-01. Question: `compute-plan-q-infer-7-disclosure-per-provider-per-model.md`.

### QD-1386: When an alias's requested effort lies equally near two efforts its model lists, which does the call run at?
*§6.3. A question the build raised (infer-m11-01), answered by the owner on 2026-11-24, one at a time. Option 1, the recommendation.*

The lower of the two, on the order off < minimal < low < medium < high < xhigh < max: medium against a model listing low and high runs at low, xhigh against high and max at high, minimal against off and low at off. Why: an alias then never runs a model harder, slower or dearer than its request asked, the conservative choice for the person's balance and budgets and what most providers' own tables do for medium; a person who wants a particular effort names the full name, which Q-INFER-5 already leaves them. §6.3 gave no tie rule.

Builds: INFER-M11-01 (`inferNearestEffort`, held by `TestInferNearestEffort` and `TestInferAliasMapsToNearestEffort`), already built. Question: `infer-m11-01-alias-effort-tie.md`.

## §7 The Harness

### QD-1313 (Q-HARN-1): Fork PiG or reimplement?
*§7.14. In Appendix G.2's open list, blocking M11's entry. The design's answer, (b).*

The Harness reimplements on Pi's formats, for §7.3's reasons, rather than vendoring PiG or importing its `agent` and `ai` packages. PiG stays a pinned source for the goldens and the enclave image (QD-1255).

Builds: HARN-M11-01, HARN-M11-04. Question: `compute-plan-q-harn-1-fork-pig-reimplement.md`.

### QD-1316 (Q-HARN-2): Does the local Harness get web access?
*§7.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

Yes: the local profile gets `web_fetch` (§22) and web search (§21), through URnetwork's network, under the listed-URL rule and taint. Why: CO-17 asks for a core fetch tool and CO-16 for search.

Builds: HARN-M11-03. Question: `compute-plan-q-harn-2-local-harness-get-web-access.md`.

### QD-1317 (Q-HARN-3): May a local Harness run on the page Worker or the extension?
*§7.14. In Appendix G.2's open list, blocking nothing at launch. The design's answer.*

Not at launch: the extension's Worker is Later in DESIGN, and the page Worker has no compute surface. A remote-only Harness in the browser follows the Worker.

Builds: nothing yet. Question: `compute-plan-q-harn-3-local-harness-run-page-worker.md`.

### QD-1318 (Q-HARN-4): What runs by default in an enclave?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (a).*

The Harness runs by default in an enclave; PiG is one flag away for people who want Pi's extensions and TUI. Why: the Harness records natively, and its tool and approval rules are sidecar's.

Builds: HARN-M14-05, HARN-M14-07. Question: `compute-plan-q-harn-4-runs-default-enclave.md`.

### QD-1319 (Q-HARN-5): How does a local Harness reach several agents in one enclave?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

By one management link per device and enclave, reaching every agent of that enclave's Harness, with inbox threads beside it for work that outlives the link: the link carries control and the live view, and each prompt's thread carries the answer, which survives a dropped link or a sleeping phone. Why: a session attach per agent spends an SSH session per agent against §12.4's 16 a client, and can neither list agents nor launch one; threads alone cannot steer, abort or show a run as it happens.

Builds: HARN-M14-02, HARN-M14-03. Question: `compute-plan-q-harn-5-local-harness-reach-several-agents.md`.

### QD-1320 (Q-HARN-6): How does the remote side know whether a command on the link is trusted?
*§7.14. Appendix B, decided by peer review; not in G.2. The design's answer, (b).*

By an origin the caller's sidecar signs over the session, naming the person or a run with its taint bit, trusted only from an untagged device of the enclave's sponsor. It is D-SKILL-4's rule for messages applied to the link, so since CO-43 an untainted run in another of the sponsor's enclaves counts as one on their device (IC-12). The origin is signed over the session's exchange hash, so it cannot move to another session or be chosen by a line's writer, and OpenSSH sessions, which `ur ssh agent` lets any same-user process open, carry none. A same-user process that detaches from its harness and drives a pty can still pass as the person: DESIGN's TB1 residual (owner decision 47), which §2.7 discloses. Why: trusting every command from a device the `ssh` rule admits would let a tainted run on the person's own device carry injected text into an enclave agent's trusted context, past I-9; trusting none would taint every run the person drives by hand and cost it its outward actions, though the person typed the prompt.

Builds: HARN-M14-02, SSH-M14-04, SSH-M14-06. Question: `compute-plan-q-harn-6-remote-side-know-command-link.md`.

### QD-1321 (Q-HARN-7): Is a tainted run's prompt into an enclave an outward action?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

Yes, when the enclave's egress is not `none`, as `ssh_exec` is (§7.8): it is kind 24, `tainted_send`, for every tool that carries text there, `agent_send` and `agent_broadcast` included. With one kind for every tool and command that messages, runs a command or moves a context, and no evs or git write into an inbox, a tainted run has no messaging door. An enclave whose egress is `none` still counts as reaching out when a rule lets it dial another device's services, which can act on the internet for it (§7.8, §26.7). Otherwise a `none` enclave's runs that took the prompt are tainted, so their sends onward pass the same gate, kept by a Harness outside its agents' container (§11.10), and what they write into the network (deposits, the agents repo, the repos it syncs) waits behind §7.8's hold before an enclave that reaches the internet reads it. Why: a receiver's taint stops nothing in an enclave whose `bash` reaches the internet outside the gate (DESIGN §16.6), so the gate must be the sender's; asking always would cost approvals for nothing the hold does not already cover.

Builds: HARN-M11-02, HARN-M14-04. Question: `compute-plan-q-harn-7-tainted-run-s-prompt-enclave.md`.

### QD-1322 (Q-HARN-8): Does a remote agent's answer taint the local run that reads it, even from an untainted run in an enclave whose egress is `none`?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer: (b) for the member's own enclave, (a) for another member's.*

From the member's own enclave, an answer taints the local run that reads it only when the remote run says it is tainted, as CO-43 has it. From another member's enclave it always taints, as any other member's runs do (IC-12). A managing agent stays useful because it need not read: `harness_list`'s stubs do not taint, events go to the person's view rather than its context, threads bring the answer when it is needed, and the person's own prompts never wait for approval. Why: the member's enclave is one of their devices, whose Harness keeps each run's taint in the daemon's namespaces, outside the agents' container, where no agent can clear it (§11.10), so its untainted runs are trusted as a desktop's are; most of its runs are tainted anyway, since every tool that touches the container taints its run (§7.8), and their answers taint the reader.

Builds: HARN-M14-04. Question: `compute-plan-q-harn-8-remote-agent-s-answer-taint.md`.

### QD-1323 (Q-HARN-9): May an enclave's agent manage another enclave's Harness, and a member another member's?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

As the `ssh` rule allows: within a member, and another member's enclave only with its sponsor's consent, every such command arriving untrusted to its receiver (QD-1320). Within a member, managing is the `ssh` action (§16.2): the default rule reaches a member's enclaves from that member's untagged devices and the agents on them (§16.5), so one enclave reaches another only by a rule naming both (`tag:enclave-<a>` to `tag:enclave-<b>`). Another member's enclave holds its sponsor's owner-bound agent record, its agents' status, summaries and conversations (owner decision 126), so a rule an admin writes is not enough: the sponsor's consented device approves a requested `ssh` grant naming the other member (`autogroup:dst-owner`, DESIGN §8.8), which the enclave's SSH server checks. With it the other member may list, prompt, steer, wait on and stop the enclave's agents but never launch one, since `ur_launch_agent` takes only the sponsor's origins, and its prompts, steers and stops spend the sponsor's budget. From a tainted run into an enclave that reaches the internet, such commands wait for approval (QD-1321), and a report back to another member's agent is kind 24 from the enclave's run, so the skill has such agents report once, at the end. Since CO-43 the enclave holds what its sponsor's devices hold, so such a grant never reaches `root` (§12.5), and what another member's command has a run there read of the sponsor's reaches that member only by the sponsor's kind 24, which the classifier never decides for another member (§7.8, §27.7).

Builds: SKILL-M11-01, SKILL-M11-06, SKILL-M13-01, CTXH-M14-01, HARN-M14-02, HARN-M14-04, SKILL-M14-01, SSH-M14-02. Question: `compute-plan-q-harn-9-enclave-s-agent-manage-another.md`.

### QD-1314 (Q-HARN-10): May a tainted run's EVS writes reach an enclave that reaches the internet with no person's act, and should an enclave's agents read every summary of their member's agents?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer: (b) for the first; for the second, CO-43's reading.*

A tainted run's EVS versions reach no enclave that reaches the internet without a person's act: the enclave's daemon holds them until the sponsor releases them by kind 24. Since CO-43 makes the enclave one of its sponsor's devices, its agents read the agents repo, summaries included, as the member's other agents do (§20.4), a summary a tainted run wrote waiting behind the hold like any other version. Why: kind 24 exists because a receiver's taint stops nothing in an enclave that reaches the internet, and the same holds for what it reads from EVS; the local Harness keeps everything in EVS (CO-6), so a summary a mail-reading run wrote is the common path, not a corner. Holding only tainted runs' versions leaves untainted work flowing, while keeping every enclave from its member's repos would break the agent graph and the management of CO-19 and CO-23.

Builds: HARN-M14-06, SKILL-M14-01. Question: `compute-plan-q-harn-10-tainted-run-s-evs-writes.md`.

### QD-1315 (Q-HARN-11): Once an enclave holds its sponsor's data (CO-43), may one run there both read it and use the agents' container, whose `bash` reaches the internet?
*§7.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

Only in an enclave that does not reach out. In one that does, a run holds the sponsor's private data (mail, calendars, connected services, the vault, the mailbox) or the agents' container, not both: mail and accounts work in runs that never touch the container, under the local profile's gates (§7.8), and builds, root and the internet in runs that never read them, as before CO-43. A run that needs both asks the person once, by kind 24, and the crossing's card shows what the run holds. Repos other than the vault and the mailbox stay readable by the container's runs, as CO-43's full access has it for the initial version, which the enclave's disclosure says (§2.8). Why: in an enclave that reaches out, a prompt-injected agent's `bash` sends whatever its run holds outside every gate, so one injected message could otherwise send the person's mail, accounts and record anywhere, past every approval; taking mail, calendar and connection tools from such an enclave would take away what CO-42 shares with it.

Builds: HARN-M14-06. Question: `compute-plan-q-harn-11-once-enclave-holds-sponsor-s.md`.

## §8 The local gateway

### QD-1306 (Q-GW-1): CO-4 says "responses api"; is that the only API?
*§8.12. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (b).*

No: the gateway serves the OpenAI Responses API, with Chat Completions and Anthropic Messages beside it. Why: as §8.3 shows, Claude Code speaks only Messages, and most open harnesses speak Chat Completions.

Builds: GW-M12-03. Question: `compute-plan-q-gw-1-co-4-says-responses-api.md`.

### QD-1307 (Q-GW-2): Cursor?
*§8.12. In Appendix G.2's open list, blocking nothing at launch. The design's answer, (a).*

Cursor is unsupported; the gateway is not published for it. Why: Cursor's custom endpoints are called from Cursor's servers, which would see every prompt, and the gateway would have to be public.

Builds: GW-M12-07. Question: `compute-plan-q-gw-2-cursor.md`.

### QD-1308 (Q-GW-3): Gemini CLI?
*§8.12. In Appendix G.2's open list, blocking nothing at launch. The design's answer, (a).*

Later: a fourth translation for one harness waits for demand.

Builds: nothing yet. Question: `compute-plan-q-gw-3-gemini-cli.md`.

### QD-1309 (Q-GW-4): May the gateway forward to the person's own API keys for OpenAI, Anthropic or Google?
*§8.12. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

Never. A harness that wants the person's own keys keeps its own provider settings beside the gateway's profile. Why: CO-18 brings every provider URnetwork can reach into its catalog, paid from the compute balance under one namespace; a person's own keys are a separate matter.

Builds: GW-M12-03. Question: `compute-plan-q-gw-4-gateway-forward-person-s-own.md`.

### QD-1310 (Q-GW-5): Does the gateway run in the apps?
*§8.12. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

No: the gateway runs in desktop daemons and enclaves only. Phones run no external harness, and the apps' Harness calls the router in-process; an enclave runs the gateway so Codex, Claude Code or PiG inside it use the catalog (§11.10).

Builds: GW-M12-01. Question: `compute-plan-q-gw-5-gateway-run-apps.md`.

### QD-1311 (Q-GW-6): How does a harness that takes its API key from a file or its environment, with no credential command to renew it (most Chat Completions harnesses, [Rpt:bb] gateway_harness_compat.md), keep working past a token's hour?
*§8.12. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (b).*

Through `ur gateway run <h> -- <command>`, which starts the harness with its base URL on a loopback port of its own and a session key that lives only in that process's environment and the runner's memory, and relays each call to the gateway under an hour-long token it renews; `ur gateway config <h>` prints this form for such a harness. No credential reaches a file, the runner keeps §8.7's loopback, Host and Origin checks, its key ends with the process, and the grant, budget and recording are the harness's own, as for Codex and Claude Code. Why: a token that lives as long as its grant, written into the harness's settings, leaves a long-lived credential on disk past IC-11's hour; restarting such a harness each hour breaks every session at the hour.

Builds: GW-M12-08. Question: `compute-plan-q-gw-6-harness-takes-api-key-file.md`.

### QD-1312 (Q-GW-7): When a harness supplies no retry id, which repeated request is a retry?
*§8.12. Appendix B, decided by peer review; not in G.2. The design's answer, (b).*

A request with the same run handle and bytes as a call whose answer never reached its caller whole is a retry of that call, and a retry of an undelivered call costs nothing. A client that sends `Idempotency-Key` gets exact answers. The cases this misreads are recorded as what was assumed: a new request repeating an abandoned call's bytes gets that call's answer, and a retry of an answer that arrived whole is charged again, shown as a second call on the same context. Why: Codex and Claude Code send no id for one operation (§8.5), so treating every request as its own call would charge the person again for every dropped stream's re-run; matching any request with the same grant and bytes within 10 minutes would hand one run another's answer and tool-call ids whenever two sessions send the same bytes, and let marked data cross runs.

Builds: GW-M12-05. Question: `compute-plan-q-gw-7-harness-supplies-retry-id-repeated.md`.

## §9 The compute balance

### QD-1261 (Q-BAL-7): What happens to a running enclave when the balance runs out?
*§9.16. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

It runs on through §9.9's grace, to the floor and one hour, then stops; its work is in EVS, and it starts again as a new incarnation once the balance allows.

Builds: BAL-M12-12, BAL-M14-01, BAL-M14-02, ENC-M14-06. Question: `compute-plan-q-bal-7-happens-running-enclave-balance-runs.md`.

### QD-1262 (Q-BAL-8): Which days are the spend view's "last 7 days", and in which time zone?
*§9.16. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

Seven UTC days, today so far included. The view says "UTC", and the apps show the window's bounds in the person's local time beside it. Why: `compute_charge_day`, the statements and DESIGN's daily quotas (DESIGN §20.4) all count UTC days, so the view and a statement agree; a time zone the network sets would be one more fact on the server that hints where its people are, and a Team's members span zones; a rolling 168 hours would read the per-request rows on every view.

Builds: BAL-M12-04, BAL-M12-15, BAL-M12-17. Question: `compute-plan-q-bal-8-days-spend-view-s-last.md`.

### QD-1258 (Q-BAL-10): Where are lifetime totals kept, for how long, and at what grain?
*§9.16. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

On the server, for the account's life, and deleted with the network: what was spent by kind, member, model or shape, provider and enclave, with no day, sidecar or agent, and one date, the network's first charge, which is all the view shows. By agent, the view covers the last 7 days and statements their months. Why: CO-22 asks for a total, which 400 days of day rows cannot give; keeping the day rows' grain for the account's life would keep when each sidecar used which model, which §9.4 bounds at 400 days on purpose; a fold kept on devices would have each viewer's devices keep their own without a gap, a member's unable to read an admin's, for figures the server derives from charges it holds anyway. An agent's id names one device's agent (DESIGN §5.5), so a lifetime row by agent would be a device's lifetime spend, and agent ids churn with every sub-agent and enclave incarnation, so such rows would grow without end.

Builds: BAL-M12-01, BAL-M12-04, BAL-M12-15. Question: `compute-plan-q-bal-10-where-lifetime-totals-kept-long.md`.

### QD-1259 (Q-BAL-11): May the person's own bot read the spend view?
*§9.16. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (b).*

Yes, through `compute_spend`, within the person's role, and only on the person's consented device: untagged and neither ephemeral nor Delegation-admitted, not merely untagged. No agent on a tagged sidecar, which acts for no one person, or in an enclave, which runs on a machine others hold (§2.6), reads it, and an untagged CI runner or server enrolled by an auth key that acts as its creator (DESIGN §7.8) is such a machine too. Charge rows, lots and payment methods stay out of every agent's reach. Why: "Where did my credits go?" is a question for the bot tab (CO-19); the view holds figures and the device's labels, never content (R-BAL-6), less than the mail and vault the same agent may already read, and the sidecar calls the route, so no credential enters the agent's context (I-7).

Builds: BAL-M12-15, BAL-M12-20. Question: `compute-plan-q-bal-11-person-s-own-bot-read.md`.

### QD-1260 (Q-BAL-16): When a direct call's provider charges more than the call's budget reservation, as when it serves a costlier model than the device declared, who pays the rest?
*§9.16. In Appendix G.2's open list, blocking M12b's entry, and in G.1 as the one G.1 decision the design left open, which the second review added (R2-10) after CO-42 and CO-44. The design's answer, (b).*

URnetwork pays the rest, with §9.7's reservation, at most $5 across a network's open direct calls; the network is charged the reservation and flagged. Why: charging the network past its budgets breaks the caps §16.4 promises (an agent at $4.90 of its $5 could reserve $0.05 and be charged $2); refusing a direct call without a bound the provider enforces unless every applicable budget has room for the provider's costliest worst case would strand up to that worst case, about $3, of every $5 agent budget, as Q-BAL-14 found for balances. This answer keeps every cap, still charges a lying device in full wherever its budgets have room, and costs URnetwork at most $5 a network at once, and $10 in the 30 days before a second mismatch ends its direct calls (§9.11), nothing where a provider enforces a signed bound (§6.6).

Builds: BAL-M12-21, INFER-M12-04, INFER-M12-05. Question: `compute-plan-q-bal-16-direct-call-s-provider-charges.md`.

## §11 Secure enclaves

### QD-1289 (Q-ENC-1): Which providers do we support for enclaves?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer.*

None today without a change on the provider's side (§11.3's table). The three CO-28 chose are supported each after its gate: Hippius first, for CPU, once it binds launch data, or adds the one feature setup over SSH needs (Q-ENC-7, QD-1297), and documents guest reports (G-PROV-hippius); Cathedral, for CPU, once it is generally available and passes the same (G-PROV-cathedral); Lium, for GPU, once it measures the renter's image (G-PROV-lium). Chutes' TDX VMs and Targon are not chosen (CO-28). Development runs on the reference provider, never a user (CO-21).

Builds: ENC-M14-22, ENC-M14-23, ENC-M15-01, ENC-M15-02. Question: `compute-plan-q-enc-1-providers-we-support-enclaves.md`.

### QD-1293 (Q-ENC-2): What is the default egress?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer.*

`auto`, as for any sidecar whose network sets no egress mode (DESIGN §17.11: default egress on, mode `auto`): it keeps destinations from the miner and attributes traffic to URnetwork's network. A network that writes a policy sets `exits` or `none` for `tag:enclave`.

Builds: ENC-M14-12. Question: `compute-plan-q-enc-2-default-egress.md`.

### QD-1294 (Q-ENC-3): Root for agents?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer, (c).*

Agents get root by default inside their own Debian container, its user and network namespaces apart from the daemon's: root for everything Debian offers, `apt`, services and low ports included, as CO-19 asks, while the incarnation's keys and the egress rules CO-7 has sidecar run stay outside their namespaces (§11.10). The enclave's real root stays with the person's own SSH session. Why: an agent with the real root could read the incarnation's keys from the daemon's memory or flush the firewall, making the enclave only as trusted as its least careful agent.

Builds: ENC-M14-13. Question: `compute-plan-q-enc-3-root-agents.md`.

### QD-1295 (Q-ENC-5): Until a Bittensor provider passes the enclave contract, may the indexer enclave run on a cloud's confidential VMs (the reference provider, 11.3), paid in USD?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer, (a).*

No: as the owner decided (CO-21), enclaves run only on Bittensor providers, so the indexer enclave, like every user-facing enclave, waits for G-PROV-hippius or the next provider to pass; until then a network's indexer is a member's always-on device, as DESIGN has it.

Builds: ENC-M14-20, ENC-M14-21, ENC-M14-25. Question: `compute-plan-q-enc-5-until-bittensor-provider-passes-enclave.md`.

### QD-1296 (Q-ENC-6): May a member's grant to the indexer enclave reach beyond the mailbox, to the vault or other repos?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer.*

No: a member's grant to the indexer enclave covers the mailbox alone (CO-20), and the member's other repos are indexed by their own devices. A member who wants an enclave to hold their vault and repos runs their own, which CO-43 makes one of their devices (§11.4, Q-ENC-13). Why: the indexer serves the whole network under its Owners' and Admins' sponsorship.

Builds: ENC-M14-26. Question: `compute-plan-q-enc-6-member-s-grant-indexer-enclave.md`.

### QD-1297 (Q-ENC-7): Instead of the provider binding the bootstrap, can URnetwork set an enclave up by SSH into the provider's VM?
*§11.16. Appendix B, decided by peer review; not in G.2. The design's answer, (c).*

Yes, where the provider's measured image takes nothing from the miner's host, installs keys only once and gives its customer no later way in, and has its SSH server bind the installed keys, the enclave id and its own session into a report. The provider offers no key, console or command after the report, and the payload closes the provider's own access before it makes keys (§11.7). With all of them, setup reaches only the VM made for this enclave, which only the device's key can enter; it needs one small provider feature, a report the SSH server binds, not a new register, which SEV-SNP lacks without an SVSM vTPM. Why: four dangers need these conditions. An image that reads start-up data or SSH keys from the host lets the miner plant its own key or a boot script, and a backdoor planted at boot leaves the attestation unchanged. A report proves only the image, so without the installed keys and the enclave id bound into it, a breached broker, or a miner who is also the provider's customer, could present a genuine VM of the same image on which it holds root. Without the server's own binding, a relay could splice a genuine guest's report into another session. And a key, console or command the provider's API adds after the report would let that broker, which drives URnetwork's account, or a miner with an impostor VM in its own account, take root after the check.

Builds: ENC-M14-18, ENC-M14-23. Question: `compute-plan-q-enc-7-instead-provider-binding-bootstrap-urnetwork.md`.

### QD-1298 (Q-ENC-8): Does a new version of an enclave provider's disclosure stop the sponsor's running enclaves there?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer, (a).*

No: running enclaves go on. The next kind 19 there, a creation or a move, asks, and each card shows the new line at once, marking the change until the sponsor opens it. Why: the enclave and what it holds are already there, and stopping it would stop agents' work, and a network's indexer enclave its mail, for a change of text.

Builds: ENC-M14-08, ENC-M14-24. Question: `compute-plan-q-enc-8-new-version-enclave-provider-s.md`.

### QD-1290 (Q-ENC-12): Should an agent's `enclave_stop` and `enclave_start` need the person in a tainted run, with the network's indexer enclave outside agent tools?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

Yes: a start through a tool is a kind 19, a tainted run's stop waits for the person's confirmation, and no tool stops, starts or removes the network's indexer enclave. Why: a stop destroys the VM and its scratch disk, so a prompt-injected run, local or through MCP, could otherwise stop every enclave the person sponsors, the network's mail with them, and a start would resume per-second charges no budget stops and admit an incarnation by a tool, which §11.4 forbids; a tainted run's `agent_stop` already waits for the person (§7.10).

Builds: ENC-M14-24, ENC-M14-29. Question: `compute-plan-q-enc-12-agent-s-enclave-stop-enclave.md`.

### QD-1291 (Q-ENC-13): Does CO-43's full access extend to the network's indexer enclave?
*§11.16. In Appendix G.2's open list, blocking M14's entry. The design's answer, (a).*

No: the indexer enclave stays a tagged sidecar its Owners and Admins sponsor, receiving the network's mail and reading only the mailboxes members grant it, and it keeps its measured role, with no Harness, no agents and no login (§11.10). Why: it serves the whole network, holding every member's incoming mail and the mailboxes members grant it, and any of its sponsors may admit its incarnations (§11.4), so its access is not one member's; with an admin's full access, every member's mail would sit beside that admin's vault, mail and accounts on one machine, a breach exposing them together, while members' grants (CO-20) already give it what it needs.

Builds: CACL-M14-01, ENC-M14-03, ENC-M14-09, ENC-M14-25. Question: `compute-plan-q-enc-13-co-43-s-full-access.md`.

### QD-1292 (Q-ENC-14): How is an agents' enclave given its sponsor's access (CO-43)?
*§11.16. Appendix B, decided by peer review; not in G.2. The design's answer, (b).*

For the initial version, by a tagged admission that also names its sponsor, capability bit 3: consented for the sponsor, holding none of their authority. It rests on DESIGN's own consent (§8.5's `scoped` clause) and key delivery, so the enclave reads what the sponsor's devices read with no share to keep current, and it keeps `tag:enclave-<id>`, on which its claim, its network reach, its egress default and its listeners rest (§11.8, §16.5, §26). The bit also keeps the enclave from the sponsor's authority and from writing their settings (§11.4). Why: admitting it as an untagged device of the sponsor would drop the tag and give a machine a miner holds the sponsor's authority to admit devices, consent and share, which would outlast the incarnation's revocation; a share or grant of each repo, link and connection to its tag is what CO-43 replaced, and reaches no new repo by itself.

Builds: CACL-M14-01, ENC-M14-03, ENC-M14-09. Question: `compute-plan-q-enc-14-agents-enclave-given-sponsor-s.md`.

## §12 The bundled SSH

### QD-1364 (Q-SSH-1): Should desktops and other sidecars run the SSH server too?
*§12.12. In Appendix G.2's open list, blocking nothing at launch. The design's answer.*

Not at launch; CO-5 is about enclaves. `ur ssh serve` for a person's own machines is Later, behind the same rule.

Builds: ENC-M14-03. Question: `compute-plan-q-ssh-1-desktops-other-sidecars-run-ssh.md`.

### QD-1365 (Q-SSH-2): Should person sessions be recorded?
*§12.12. In Appendix G.2's open list, blocking nothing at launch. The design's answer.*

Receipts only (§12.7). Full recordings are Later, to the person's vault, by a Team policy.

Builds: SSH-M14-02. Question: `compute-plan-q-ssh-2-person-sessions-recorded.md`.

## §13 The bundled git

### QD-1304 (Q-GIT-1): Rebase?
*§13.11. Appendix B, decided by peer review; not in G.2. The design's answer, (a).*

No rebase at launch: merge covers the agent's need to integrate, and coding agents' own instructions avoid rewriting history. A linear `rebase` of unpushed commits is the first addition if agents trip over its absence.

Builds: GIT-M13-07. Question: `compute-plan-q-git-1-rebase.md`.

### QD-1305 (Q-GIT-2): Other remotes (GitHub) from the local Harness?
*§13.11. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer.*

No: CO-6 gives the local Harness EVS for storage, and a GitHub remote would be network access by another name. Enclaves use the system git for GitHub, through their egress.

Builds: GIT-M13-02. Question: `compute-plan-q-git-2-other-remotes-github-local-harness.md`.

## §14 Server services, routes, tables and metadata

### QD-1388: Should §2.8's compute-4 name the provider's label and the price per hour that kind 19's action shows the broker?
*§14.6's compute-4, and through Appendix D's row for DESIGN §2.8's list. A question the build raised (CACL-M11-04), answered by the owner on 2026-11-24, one at a time. Option 1, the recommendation.*

compute-4's sees gains "and the label and price per hour its create's action shows, the catalog's own values for its shape and provider", and kind 19's action stays as §16.3 writes it, field 42's `EnclaveFields` carrying both to the broker. Why: the values add nothing a server does not hold, and the broker comparing the approved price with its catalog's is worth keeping. DESIGN.md's §2.8 carries the words since metadata_list.yml v69 (track dr19-support-fold), so only §14.6's row waits for the owner's revision.

Builds: CACL-M11-04 (testdata/approval_compute/metadata_rows.yml's `EnclaveFields.label` and `EnclaveFields.price_per_hour`, which quote compute-4 since v69), already built. Question: `cacl-m11-04-compute4-create-label-price.md`.

## §16 Policy, budgets and approvals

### QD-1263 (Q-CACL-1): Is each remote inference call an outward action?
*§16.8. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (b).*

No: budgets bound it, with model rules and taint, and the record holds every call. Why: an approval per call would make agents unusable.

Builds: INFER-M11-03, CACL-M12-05. Question: `compute-plan-q-cacl-1-remote-inference-call-outward-action.md`.

### QD-1264 (Q-CACL-3): What may a new network use?
*§16.8. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

Every provider and label, with TEE-only one setting away, as CO-18 says. Every model carries its label in the catalog and on every message, and the apps put the TEE-only switch beside the model picker.

Builds: CACL-M11-01, INFER-M11-03, CACL-M12-03. Question: `compute-plan-q-cacl-3-new-network-use.md`.

### QD-1389: What action word does a rule on `compute:buy` take, which §16.2 names none for?
*§16.2, and §16.5's defaults for `compute:buy`. A question the build raised (CACL-M11-05), answered by the owner on 2026-11-24, one at a time. Option 1, the recommendation.*

`buy`, as acl.proto declares it (`ACL_ACTION_BUY` = 12): `{"src": [...], "dst": ["compute:buy"], "allow": ["buy"]}`, one word for buying credits, redeeming a code and setting auto-renew. Why: one word covers §16.2's one row, and the value is already numbered in its place. DESIGN.md's §8.4 names it since the tenth fold (track dr18-compute-fences).

Builds: CACL-M11-05 (the value, declared), CACL-M12-04 (the parse). Question: `cacl-m11-05-compute-buy-action-word.md`.

### QD-1390: Does version 5's sealed detail ride kinds 19 and 21 alone, as field 38's row says, or kinds 19 to 24, as §16.3's prose and Appendix D say?
*§16.3 (field 38's row and its prose), §16.7's D-CACL-5 and Appendix D's §16.8 row. A question the build raised (CACL-M12-01), answered by the owner on 2026-11-24, one at a time. Option 1, the recommendation.*

Kinds 19 and 21 alone, as field 38's row says; §16.3's prose and Appendix D's "19-24" read as "the kinds 19-24 that a gate sees". No change to the code. Why: the detail exists to keep a name and a grant from the broker's gates, and only kinds 19 and 21 reach one. DESIGN.md's §16.8 names kinds 19 and 21 since the tenth fold (track dr18-compute-fences).

Builds: CACL-M11-04, CACL-M12-01 (built for 19 and 21; a kind that seals is a row change). Question: `cacl-m12-01-sealed-detail-kinds.md`.

### QD-1391: How does a version-5 action's field 39 name an enclave whose default egress is off (§11.8's `direct`), which `BridgeEgressMode` has no value for?
*§16.3 (field 39 on kinds 19 and 24) and §11.8. A question the build raised (CACL-M12-01), answered by the owner on 2026-11-24, one at a time. Option 1, the recommendation.*

Field 39 at version 5 alone takes a fourth value, 4 `direct`, documented in record.proto's comment and read only by version 5's rules and render, `BridgeEgressMode` unchanged, so no wire changes outside version 5: the rules accept 1 to 4 at version 5 and the render names 4 `direct`. Why: it keeps the forwarding role's enum as it is, binds the mode in the action the approval signs, and touches only version 5's rules and render. DESIGN.md's §16.8 carries it since the tenth fold (track dr18-compute-fences), as CACL-M12-01 built it, 4 on kind 24.

Builds: CACL-M12-01 (the rules and render); kind 24's card into a direct-egress enclave naming its mode (HARN, SKILL and SSH). Question: `cacl-m12-01-version5-direct-egress-mode.md`.

### QD-1392: Is a harness config version's writer judged at the newest verified state or at its push's own pin?
*§16.6 (the reading row), §16.4 and IC-23. A question the build raised (CACL-M11-01), answered by the owner on 2026-11-24, one at a time. Option 1, the recommendation, as built.*

At the newest verified state, not at its push's own pin: a stolen device's last change to `tee_only`, `allow` or `approvals` is dropped the moment the device is revoked, with no compromise cascade, and IC-23's enclave rule still holds, bit 3 refused whatever the time. Cost: a lost device's legitimate last change is dropped too, the file reading as the version before it, which can be wider (`tee_only` back off, say) until the person sets it again with `ur models set`, each such version raising one `record_alarm` `path_rule`. Why: it is the closed reading and needs nothing of evs, where judging at the push's pin would need the push's authorization pin on `EvsHistoryVersion`, the state at that pin and a compromise cascade that voids the versions it parks.

Builds: CACL-M11-01 (models_member_config.go), already built. Question: `cacl-m11-01-harness-config-writer-when.md`.

## §19 Phasing and milestones

### QD-1274 (Q-CPHASE-2): Should Chutes' TEE path stay in M12, though CO-32 drops Chutes from launch?
*§19.10. In Appendix G.2's open list, blocking M11's entry. The design's answer, (b).*

No: the policy pipeline stays in M12a, the CPU verifier moves to M14, and the E2E client and the GPU work start in M15, once SN64 takes gamma and Chutes signs. Until then no user can reach the path, and M12's exits then need no TEE call. QD-1233 lets the draft build provider work ahead of this order, against fakes and off until each gate passes.

Builds: nothing yet; it shapes M11's entry. Question: `compute-plan-q-cphase-2-chutes-tee-path-stay-m12.md`.

### QD-1275 (Q-CPHASE-3): Does M14 start before a provider commits to EPC-1?
*§19.10. In Appendix G.2's open list, blocking M11's entry. The design's answer, (c).*

Its platform only: the image, the measurement pipeline, the CPU verifier and the SSH server start before a commitment, on hosts URnetwork controls, while the adapters, the indexer enclave and the management link wait for a written commitment. QD-1233 lets the draft build the adapters ahead of a commitment, against fakes and off until each gate passes. Why: the platform is most of M14 and no provider's choice changes it, while an adapter, the indexer enclave or the management link built before a commitment is work no user reaches if the provider declines.

Builds: nothing yet; it shapes M11's entry. Question: `compute-plan-q-cphase-3-m14-start-before-provider-commits.md`.

## §20 The recURd skill: agent names, status, and inboxes

### QD-1351 (Q-SKILL-1): Are names unique per member or per network?
*§20.13. In Appendix G.2's open list, blocking M11's entry. The design's answer, (a).*

Agent names are unique per member. A personal network has one member, so the two agree there; in a Team, other members address an agent as `<name>` with its member shown, which `agent_find` and the directory resolve, and no member's agents can squat another's names.

Builds: SKILL-M11-02. Question: `compute-plan-q-skill-1-names-unique-per-member-per.md`.

### QD-1352 (Q-SKILL-2): Is there one shared repo for a whole Team's agents?
*§20.13. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (b).*

A Team inbox for messages, with status staying per member: the Team inbox gives every agent one place to be reached, while summaries, which say more than owner decision 170's titles, projects and branches, stay in each member's agents repo. Every Team inbox message taints its readers. Why: CO-15 asks for "a general repo and inbox shared by all agents", and in a Team "all agents" includes other members'.

Builds: SKILL-M13-02. Question: `compute-plan-q-skill-2-there-shared-repo-whole-team.md`.

### QD-1353 (Q-SKILL-3): How often are summaries written?
*§20.13. In Appendix G.2's open list, blocking M11's entry. The design's answer.*

Every 15 minutes of active work, settable from 5 to 60, plus at task end and session end. Why: fifteen minutes keeps "what is it doing" current enough without spending many model turns.

Builds: SKILL-M11-03. Question: `compute-plan-q-skill-3-often-summaries-written.md`.

### QD-1354 (Q-SKILL-4): Can agents in different networks message each other?
*§20.13. In Appendix G.2's open list, blocking nothing at launch. The design's answer, (a).*

Not at launch: cross-network shares (DESIGN §17.9, v1) carry ports and subnets, not EVS deposits, so messaging across networks waits for a design of its own (Later).

Builds: nothing yet. Question: `compute-plan-q-skill-4-agents-different-networks-message-other.md`.

### QD-1355 (Q-SKILL-5): Does the skill write to the team directory too?
*§20.13. In Appendix G.2's open list, blocking M11's entry. The design's answer, (a).*

No: the directory's own announcements of title, project and branch stay (owner decision 170), and summaries, which hold more, stay with the member.

Builds: SKILL-M11-06. Question: `compute-plan-q-skill-5-skill-write-team-directory-too.md`.

## §21 Web search

### QD-1358 (Q-SRCH-2): How is Parallel paid, given CO-10?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer.*

Per search, in USDC on Base, from URnetwork's payer address to the payee each challenge names, which the treasury funds in USD. CO-10 sets how Bittensor providers are paid; Parallel is not one and takes no gamma, and CO-28 names it. Users still pay only fiat, into the compute balance; the apps give no user USDC to hold or move, though a modified client can direct an authorization to itself (CO-29, Q-SRCH-13).

Builds: SRCH-M13-02. Question: `compute-plan-q-srch-2-parallel-paid-given-co-10.md`.

### QD-1359 (Q-SRCH-3): Which of Parallel's paths?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

The keyless gateway over x402. Why: it needs no agreement (CO-27) and puts no key on a device or a server. An account with short-lived tokens minted per device would bring zero data retention on Scale and no public payments, but its tokens can only be scoped `*` and spend until they expire, so it waits for narrower scopes (§21.12); the free keyless MCP tier is no basis for a metered product.

Builds: SRCH-M13-02. Question: `compute-plan-q-srch-3-parallel-s-paths.md`.

### QD-1360 (Q-SRCH-4): Is search on by default?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

On, for every network with a compute balance, under the web search clause the network accepted with its compute terms (§21.9). Each person still acknowledges the disclosure before their first search (§21.6), each search's card names Parallel and its price, and a network's policy can turn search off. Why: CO-16 makes search built in.

Builds: SRCH-M13-07, SRCH-M13-10. Question: `compute-plan-q-srch-4-search-default.md`.

### QD-1361 (Q-SRCH-6): Should the local Harness also fetch the pages it finds?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer.*

Yes: CO-17 asks for it, and §22 designs `web_fetch` on every leg. Parallel's excerpts already carry the relevant text of each result, so an agent fetches when it needs a whole page, its links or its tables.

Builds: FETCH-M13-04. Question: `compute-plan-q-srch-6-local-harness-also-fetch-pages.md`.

### QD-1362 (Q-SRCH-7): May external harnesses keep `web_search` as an MCP tool, now that the gateway serves no hosted search?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

Yes: `web_search` stays an MCP tool for external harnesses, tier R, its results untrusted, each search charged to the session's agent. Why: the MCP tool is URnetwork's own tool and result format, used by the network's own harness on its member's device, an integration of the Services into URnetwork's application, which Parallel's §2(b) allows. The gateway's case differs: there the gateway would answer the harness's own built-in tool, in the harness vendor's shape, inside the vendor's product, which is why CO-26 turns it off. DESIGN §16.5 already gives external harnesses the Harness's tools by the same names.

Builds: SRCH-M12-01, SRCH-M13-11. Question: `compute-plan-q-srch-7-external-harnesses-keep-web-search.md`.

### QD-1363 (Q-SRCH-9): Are results kept in the record?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

No: the record keeps a stub, as §21.6 says, and the agent's own prose, which cites what it used. QD-1285 answers the same for context history. Why: CO-26 rests the reading of Parallel's §2(c)(xi) on not storing results; a sealed copy in the person's own record would fit §2(b)'s one End Customer, but a kept result invites answering a later query from it, which §2(c)(xi) bars.

Builds: SRCH-M13-10. Question: `compute-plan-q-srch-9-results-kept-record.md`.

### QD-1356 (Q-SRCH-11): Should URnetwork keep which network each payment belonged to, so that Parallel's complaints can be traced?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

No: the ticket joining a network to its nonce and payee is dropped at settlement, and a complaint is traced by time alone. Per-network budgets, caps and rates and time-based tracing carry the duty instead, at the risk that one network's abuse stops search for all until it is found. The sanctions records of §21.5 join no search: they keep a network only for a payee the screen refused, never paid, or an authorization settled outside the gateway, which bought none. Why: a sealed escrow of nonce to network would be the one record joining Parallel's log to a network, against R-SRCH-4.

Builds: SRCH-M13-03, SRCH-M13-07, SRCH-M13-08. Question: `compute-plan-q-srch-11-urnetwork-keep-network-payment-belonged.md`.

### QD-1357 (Q-SRCH-12): Which search provider?
*§21.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

Parallel, as CO-28 decides; Brave is dropped (§21.12). The client is one adapter, so the owner's review of alternatives under CO-30 can switch it with a release. Why: Parallel needs no enterprise agreement and lets each device call it directly, unintercepted (CO-27).

Builds: SRCH-M13-02. Question: `compute-plan-q-srch-12-search-provider.md`.

## §22 Web fetch

### QD-1299 (Q-FETCH-2): Through which egress?
*§22.11. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer.*

`auto` by default, so sites see an exit's address; `exits` by the network's policy; never `direct` from a device, which would expose its address and bypass the sidecar's own transports (IC-7).

Builds: FETCH-M13-01. Question: `compute-plan-q-fetch-2-through-egress.md`.

### QD-1300 (Q-FETCH-3): Does it obey `robots.txt`?
*§22.11. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

It obeys rules naming `ur-fetch` only, not rules for `*`; its `User-Agent` names it and links a page saying so. Why: it fetches a page when a person's agent asks, as a browser does, so crawler rules for `*` do not describe it, but a site can still refuse it by name.

Builds: FETCH-M13-03. Question: `compute-plan-q-fetch-3-obey-robots-txt.md`.

### QD-1301 (Q-FETCH-4): May an agent fetch a URL it composed?
*§22.11. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer.*

Yes while its run is untainted. Once the run is tainted, only with an approval: the device's safety classifier's in auto mode on a site the member has used (§27.4), else a person's; and even listed URLs are narrowed (§22.5). Why: agents compose URLs often, from documentation patterns, so a blanket refusal would hobble them, and an untainted run has read nothing that could compose one for an attacker.

Builds: FETCH-M13-04. Question: `compute-plan-q-fetch-4-agent-fetch-url-composed.md`.

### QD-1302 (Q-FETCH-5): An MCP `web_fetch` for external harnesses?
*§22.11. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer.*

No: external harnesses have their own fetch tools, and §22.5's rule needs the run's context, which an MCP call does not carry. The gateway fetches nothing either, since it serves no hosted search (§21.7).

Builds: CSURF-M11-02, FETCH-M13-03, FETCH-M13-04. Question: `compute-plan-q-fetch-5-mcp-web-fetch-external-harnesses.md`.

### QD-1303 (Q-FETCH-7): A page that builds its content with script comes back nearly empty on devices (22.6): should `web_fetch` render script at launch?
*§22.11. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

Not at launch: the result says `render: "static"` and suggests `web_search`, whose excerpts come from Parallel's index of the page, and an enclave's agent renders such a page with a browser it installs as root in its container (§11.10). Why: a browser on devices is tens of MB and a large attack surface, against DESIGN §18.10's size budgets; a provider's rendering API on devices shows a third party every URL and page (§22.9); in an enclave `apt` already brings a browser under the enclave's egress, so bundling one adds image size for what an agent can do itself; and static fetch covers the documentation, articles and references agents read most.

Builds: FETCH-M13-02. Question: `compute-plan-q-fetch-7-page-builds-content-script-comes.md`.

## §23 Mail and calendar for agents

### QD-1335 (Q-MAILCAL-1): What is the "calendar edit link" CO-24 names?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

A link with the credential that writes it, or a read-only address; not a URL that alone lets its holder add events, which none of the six providers read offers: Google's, iCloud's, Fastmail's, Proton's, Outlook's and Nextcloud's links all only read, and writing takes a CalDAV app password or an OAuth grant (§23.3). The app's calendar settings say so in one line and ask each provider for the right thing.

Builds: MAILCAL-M13-01, MAILCAL-M13-04. Question: `compute-plan-q-mailcal-1-calendar-edit-link-co-24.md`.

### QD-1340 (Q-MAILCAL-2): How do Google and Microsoft calendars, which write only through OAuth, get in?
*§23.15. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (b), with (a) until each gate passes.*

By OAuth on the device, the grant kept as the link: built in M13 and offered as each provider passes its gate (G-CONN-google, G-CONN-microsoft), and until then through their read-only addresses and the phone's add sheet. OAuth with PKCE runs on the device, its code never reaching a URnetwork server, with one Google client per platform and none of Google's refresh tokens on Android devices (Q-MAILCAL-13). Why: most people's calendars are Google's or Microsoft's; tokens held by a URnetwork server would be a server reading calendars, which the directive rules out.

Builds: CONN-M13-05, MAILCAL-M13-12. Question: `compute-plan-q-mailcal-2-google-microsoft-calendars-write-only.md`.

### QD-1341 (Q-MAILCAL-3): Does an agent's read mark mail read?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

No: the person marks it read from the summary card. Why: a summary the person has not read would otherwise empty their unread list, and a tainted run could hide mail from them by reading it.

Builds: MAILCAL-M13-08. Question: `compute-plan-q-mailcal-3-agent-s-read-mark-mail.md`.

### QD-1342 (Q-MAILCAL-4): May an agent flag, file or delete mail?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

Not at launch. CO-24 asks for summaries; a `mail_flag` tool, W for flags and labels in an untainted run, is a small later step, and deletion stays the person's, since an erasure cannot be undone (DESIGN §15.7).

Builds: MAILCAL-M13-08. Question: `compute-plan-q-mailcal-4-agent-flag-file-delete-mail.md`.

### QD-1343 (Q-MAILCAL-7): Is a calendar write from an untainted run W or O?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

W, with attendees always O. Why: an untainted run carries out only what the person asked for, as §7.8 reasons for `agent_send` and `ssh_exec`; invitations are mail to other people, so they always wait.

Builds: MAILCAL-M13-05. Question: `compute-plan-q-mailcal-7-calendar-write-untainted-run-w.md`.

### QD-1336 (Q-MAILCAL-11): Do external harnesses get the calendar tools?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

Yes, through MCP with the same tiers, but with writes counting as a tainted run's (Q-CONN-14, QD-1268); the link stays in the daemon either way. Why: DESIGN §16.5 already gives them `mail_list` and `mail_read`, and a harness's taint is kept by DESIGN §16.6's hooks for what it reads through `ur` and its web tools, though not for what it reads by itself, so its writes count as a tainted run's (§23.9).

Builds: MAILCAL-M13-11. Question: `compute-plan-q-mailcal-11-external-harnesses-get-calendar-tools.md`.

### QD-1337 (Q-MAILCAL-12): Should a summary run on its own, as a morning digest?
*§23.15. In Appendix G.2's open list, blocking nothing at launch. The design's answer, (a).*

On request only at launch; the digest follows the design of scheduling agents (Later). Why: a scheduled run has no person at hand to acknowledge a disclosure (§2.8) or approve a batch, and scheduling agents is not yet designed.

Builds: nothing yet. Question: `compute-plan-q-mailcal-12-summary-run-own-morning-digest.md`.

### QD-1338 (Q-MAILCAL-14): May `mail_read` give an agent an invitation's `text/calendar` part, the event a meeting invitation carries?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

Yes: sidecar parses the part on the device with the calendar's iCalendar parser (§23.7) and returns its events' fields, never its bytes, as untrusted text between the untrusted-data markers, as the body is; the duplicate check (§23.8) keeps an invitation the provider already placed from being added twice. Opening any attachment stays Later, with attachments. Why: invitations are the commonest mail that carries an event, and their part states the time, zone and recurrence exactly where the text may not; the parser is the one the calendar tools already run on providers' answers, vendored, fuzzed and capped (§23.7).

Builds: MAILCAL-M13-02, MAILCAL-M13-08. Question: `compute-plan-q-mailcal-14-mail-read-give-agent-invitation.md`.

### QD-1339 (Q-MAILCAL-15): Should sign-in codes and reset links be withheld from models outside the device or an A1 or A2 TEE?
*§23.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

Yes by default: a deterministic filter in the daemon withholds them from models outside the device or an A1 or A2 TEE, AP's included, and the person can allow them. Why: burner mail is largely codes and magic links, and a call to a `none` provider reaches its gateway and the machine that serves it, at SayGM a miner and the upstream it calls, any of which could use a password-reset link while it is valid; the skill's instruction binds only the model, after the provider has the text; and at AP the provider's own code reads the request. The filter takes nothing a summary needs, since a summary names codes without copying them and the apps show codes themselves (DESIGN §15.9), and CO-34's disclosure still covers the rest of the mail. The switch leaves the last word to the person.

Builds: MAILCAL-M13-09. Question: `compute-plan-q-mailcal-15-sign-codes-reset-links-withheld.md`.

## §24 Context history in EVS

### QD-1278 (Q-CTXH-1): Where is the history kept?
*§24.14. In Appendix G.2's open list, blocking M11's entry. The design's answer, (a).*

In the author's vault, as record entries: it is the record. The vault already holds Harness runs (§7.7) under the record's chains, erasure, retention, disclosure and I-20's line, and an agents' enclave reads the vault as its sponsor's device (§24.7). Why: one copy is cheaper and simpler than two; the agent repo is readable by the member's other agents (§20.4), and a new repo kind would rebuild what the vault has.

Builds: CTXH-M11-01, CTXH-M11-03. Question: `compute-plan-q-ctxh-1-where-history-kept.md`.

### QD-1284 (Q-CTXH-2): Does CO-25 lift §22.7's 64 KiB cap on a fetched page's text?
*§24.14. In Appendix G.2's open list, blocking M11's entry. The design's answer, (b).*

Yes: the history keeps the whole `FetchedPage`, up to the part cap. Why: the record is the person's own and the page their own visit (§22.7), and the cap was a storage choice, not a term anyone set; an agent that continues a run, or a person reviewing it, gets the page that was read, not its first 64 KiB.

Builds: CTXH-M11-03. Question: `compute-plan-q-ctxh-2-co-25-lift-22-7.md`.

### QD-1285 (Q-CTXH-3): Does CO-25 override CO-26 on keeping search results?
*§24.14. In Appendix G.2's open list, blocking M11's entry. The design's answer, (b).*

No: search results are kept as stubs, and the agent's prose, citing what it used, is kept. If the owner ever allows storage, results become blobs like any part, with no format change. Why: CO-26 answers Parallel's §2(c)(xi) by not storing results, and a sealed copy in the vault is storage that invites answering a later query from it (§21.11, Q-SRCH-9).

Builds: CTXH-M11-03. Question: `compute-plan-q-ctxh-3-co-25-override-co-26.md`.

### QD-1286 (Q-CTXH-4): How does an enclave read a run?
*§24.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (d).*

From the vault, as one of its sponsor's devices, which CO-43 makes an agents' enclave (§11.4): it reads every run as the member's other devices do. That puts every run on a machine a miner holds (§2.6), which the owner accepted for the initial version and the enclave's disclosure says (§2.8). Why: context packs sealed to the incarnation are gone with their builds, seals and confirmations (§24.7), and an `EvsShare` of the vault, or the runs kept a second time in the agent repo, would add a share or a copy for what the enclave reads already.

Builds: CTXH-M14-01. Question: `compute-plan-q-ctxh-4-enclave-read-run.md`.

### QD-1287 (Q-CTXH-6): With the gateway recording each call, should the transcript tail stop for runs it covers?
*§24.14. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

No: both are kept. DESIGN §16.7 keeps capture fixed, `record.capture` ignored until a person-only surface exists. The overlap roughly doubles an external run's record (§24.10). Why: the two say different things: the transcript is the harness's own word, its local commands and its view after its own edits included, and the gateway's entries are what the model received; they differ exactly where the harness rewrote its context, which a reviewer wants to see.

Builds: CTXH-M12-01, GW-M12-06. Question: `compute-plan-q-ctxh-6-gateway-recording-call-transcript-tail.md`.

### QD-1288 (Q-CTXH-9): Should the gateway now serve `previous_response_id` from the record?
*§24.14. In Appendix G.2's open list, blocking M12a's entry. The design's answer, (a).*

No: the gateway stays stateless to its callers, and serving `previous_response_id` stays Later (§19.5), its data now kept. Why: Codex and Claude Code send full history and need no stored state; serving from the record would make the vault's sync a dependency of every call and the record a cache.

Builds: CTXH-M12-01, GW-M12-03. Question: `compute-plan-q-ctxh-9-gateway-now-serve-previous-response.md`.

### QD-1279 (Q-CTXH-10): Is redaction applied though it makes rebuilds inexact?
*§24.14. In Appendix G.2's open list, blocking M11's entry. The design's answer, (a).*

Yes, as for every entry: DESIGN §16.7 redacts before every seal. A rebuild marks each redaction, and a continued agent that needs the secret reads it again where it lives. Email addresses and phone numbers are not secrets of that kind, and `record.redact.pii`'s hashing spares kinds 54 and 55 (Q-CTXH-15, QD-1282). Why: a secret in the record is a secret on every device that opens the run and in every export.

Builds: CTXH-M11-03. Question: `compute-plan-q-ctxh-10-redaction-applied-though-makes-rebuilds.md`.

### QD-1280 (Q-CTXH-11): Who may move a run into an enclave?
*§24.14. In Appendix G.2's open list, blocking M14's entry. The design's answer, (b).*

Only these: the person's act on an untagged consented device, `ur harness continue --enclave` or the app, each confirmed on /dev/tty or in the app's UI, never by an RPC `ui_response`, which a process could answer; an agent's `harness_continue`, which sends only after that confirmation; and, after a loss, the next incarnation, for the runs the last one held open. From a tainted run, or with a continued node flagged or untrusted, into an enclave that reaches out, the move waits instead for kind 24's approval on another device, which shows the taint, the egress and `ContextFields` (D-HARN-7, §16.3), since the enclave's daemon would otherwise hold those nodes from its container (§7.8). A shell is no way around it: `ur harness continue --enclave` refuses a caller with a harness ancestor (§24.7). Why: since CO-43 the enclave reads every run from the vault, so a move carries no data there that it lacks, but it starts work the person pays for, in an enclave whose agents may reach the internet, and a prompt-injected agent that could move any run would do both unasked; leaving agents no path would cost the person who asks their own bot to move a run the same confirmation with an extra step.

Builds: CTXH-M14-01. Question: `compute-plan-q-ctxh-11-move-run-enclave.md`.

### QD-1281 (Q-CTXH-14): Does CO-25 reach a harness that calls its own provider rather than the gateway, such as Claude Code on the person's own Anthropic account?
*§24.14. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

As far as DESIGN §16.7's capture reaches: its transcript and hooks, the run marked `context_partial`, and `ur status` naming the harness with the command that sets it to the gateway. The Harness's runs, and every call of a harness set to the gateway, which one command does, are kept whole; a harness that keeps its own provider keeps what its transcript shows, and its record says so. Why: only a call that passes through sidecar can be kept as the model received it. Forwarding to the person's own provider keys would reverse Q-GW-4 (QD-1309), putting providers outside the catalog's labels, disclosures and budgets behind the gateway and another company's API keys in the daemon; a local TLS-intercepting proxy would put a certificate authority into the person's trust store to read their traffic to another company.

Builds: CTXH-M13-01. Question: `compute-plan-q-ctxh-14-co-25-reach-harness-calls.md`.

### QD-1282 (Q-CTXH-15): Should session history be exempt from `record.redact.pii`'s default hashing, so a run resumes with the addresses the person typed?
*§24.14, and DESIGN §16.7 through Appendix D. In Appendix G.2's open list, blocking M11's entry. The design's answer, (b).*

Yes, for kinds 54 and 55, with DESIGN §16.7's secret rules kept and the hashing applied where history leaves the member's devices: `ur harness export` and `ur record export --bodies` hash them in what they write. A disclosure packet proves each body by its commitment, so it cannot hash without breaking the proof: it carries them as sealed, and its confirmation counts them, so the person chooses. This narrows owner decision 452's default for two new kinds. Why: hashing before seal makes every resumed or continued run lose each address and number the person typed or a tool read ("invite bob@example.com" becomes a marker, and so does every attendee a calendar read returned), which a phone meets at every app death, while the vault already keeps them owner-bound, sealed and out of every index; secrets stay redacted, since a secret in the record is on every device that opens the run.

Builds: CTXH-M11-03, CTXH-M11-05. Question: `compute-plan-q-ctxh-15-session-history-exempt-record-redact.md`.

### QD-1283 (Q-CTXH-16): What is a member's default share of the network's storage for history?
*§24.14. In Appendix G.2's open list, blocking M11's entry. The design's answer, (b).*

All of it in a network of one member, and 2/n of it in a network of n, which a Team's Owner or Admin may set from 0.05 to 1. Q-CTXH-13's caps stand as confirmed (CO-35); only the share's default changes. Why: half, whatever the network's size, would keep a one-person network's history to 512 MiB of Community's 1 GiB, one to two and a half months at §24.10's rates, though the 90% cap already keeps room for its mail, and would let one member of a Team of 20 take 100 GiB of its 200; 2/n lets each member use twice an even split, the 90% cap still keeping mail and repos writing.

Builds: CTXH-M11-06, CACL-M12-03. Question: `compute-plan-q-ctxh-16-member-s-default-share-network.md`.

## §25 Connected services

### QD-1265 (Q-CONN-1): Where do service definitions live, and how is a service added?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (b).*

In the signed compute policy, a service added by a policy update. The policy is signed by the two-person compute-policy key the release key certifies (§5.4), moves only forward and cannot be widened by a server (IC-9), and each release carries the newest one. Typed tools still ship in releases, and `service_call` serves a new service until they do (Q-CONN-3). Why: definitions compiled into the release would make a new or narrowed service wait for every platform's release and store review; a list a URnetwork server serves would let a breached server point people's tokens at its own hosts.

Builds: CONN-M13-03. Question: `compute-plan-q-conn-1-where-service-definitions-live-service.md`.

### QD-1272 (Q-CONN-4): Do access tokens stay in memory only, or are they also cached, sealed, in the connection's repo so the member's devices do not each refresh?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

In memory only, each device refreshing for itself. CO-37 holds either way: what is long-lived is in EVS, and an access token is derived from it and dies within the hour. Why: the refresh token in EVS already lets every device mint an access token, so a cache adds no reach and saves at most one token request per device an hour; it would write the repo at every refresh, telling URnetwork's servers when a member's agents use a service, which for Google, whose refresh tokens do not rotate, they otherwise never see; Google's tokens are bound per platform client, so a shared cache would need an entry per platform, and an Android device's come from Play services and stay there; and every refresh leaves through the connection's one exit, so separate refreshes look like one client to the provider.

Builds: CONN-M13-04, CONN-M13-06. Question: `compute-plan-q-conn-4-access-tokens-stay-memory-only.md`.

### QD-1273 (Q-CONN-9): May a connected service's data reach a model without a TEE?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (b).*

Yes, as any context does, once the person acknowledges that provider's disclosure (CO-34); and a service definition may limit its data, and what is derived from it, to models whose providers' written terms bar training on it, keeping it past the request and any person reading it. Google's definition is `limited_use`: a read marks the run, the mark follows what the run writes, launches and sends, and the run's context goes only to local models and to models of any label, AP included, whose provider's gate recorded such terms (§25.10, §4.7). A harness whose model calls do not pass the gateway gets no such data over MCP. Why: CO-18 makes the model the person's choice, and the provider's disclosure already informs it (CO-34); but Google's Limited Use rules confine its data, and data derived from it, to the user-facing feature the user consented to and bar people reading it, and its Workspace API policy forbids training a model beyond the user's own (§25.3), so a provider that trained on it, kept it or let staff read it would put URnetwork's verification, and every user's Google connection, at risk. Local and TEE models only would refuse providers whose terms meet the rule, and admit an AP provider whose terms do not, though at AP the provider reads plaintext.

Builds: CONN-M13-07. Question: `compute-plan-q-conn-9-connected-service-s-data-reach.md`.

### QD-1266 (Q-CONN-10): Should the person's sign-in at the provider also go through the egress?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

No: the sign-in runs in the person's own system browser, from their own address. Everything after the sign-in, the code exchange included, leaves through the connection's exit. Why: the provider already knows the person's address from their everyday use; their browser holds their session and passkeys; a sign-in from an exit's address could be flagged as an anonymous one; and sidecar does not control the system browser's routes.

Builds: CONN-M13-05. Question: `compute-plan-q-conn-10-person-s-sign-provider-also.md`.

### QD-1267 (Q-CONN-12): Do external harnesses get the connection tools?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

Yes: `connections_list` and `service_call` through MCP, with the same tiers, but with writes and sends counting as a tainted run's (Q-CONN-14, QD-1268). `connection_request` stays out, since only a person in the apps or at the terminal can answer it. Why: DESIGN §16.6's hooks keep a harness's taint for what it reads through `ur` and its web tools, the token stays in the daemon either way, and the calendar's tools are already there (Q-MAILCAL-11, QD-1336).

Builds: CSURF-M11-02, CONN-M13-10. Question: `compute-plan-q-conn-12-external-harnesses-get-connection-tools.md`.

### QD-1268 (Q-CONN-14): Does CO-40's rule for a run that has read nothing untrusted reach an MCP session, whose taint misses what its harness reads by itself?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (b).*

No, at launch: for calendar writes and for `service_call`'s writes and sends, an MCP session's run counts as tainted, so they are kinds 25 and 26, decided as a tainted run's are under §27, which asks the person, since the daemon never saw what the harness read (§27.4). The Harness keeps CO-40's rule whole, since every input of its runs passes its tools (§7.8). Why: an external harness is tainted only by what it reads through `ur` and by hooks on its web tools (DESIGN §16.6): a cloned repo's files, a package's README or its own shell's output taint nothing, so its untainted run has not shown that it read nothing untrusted, which is what CO-40's rule rests on; otherwise an injected coding agent could write 20 events a call into a shared calendar, or send mail through a connection, with no card. Letting the classifier decide such a write from its text spares taps but judges an action whose cause it never read, which §27.4 refuses elsewhere; the bench can measure that for a later release.

Builds: CONN-M13-08, MAILCAL-M13-05, MAILCAL-M13-11, SAFE-M13-15. Question: `compute-plan-q-conn-14-co-40-s-rule-run.md`.

### QD-1269 (Q-CONN-15): Should a Team's audit reader, or a device of another platform, ever hold a member's live tokens?
*§25.16. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (b).*

No: each token, and a calendar link's secret, is sealed inside the repo to the member's devices that use it, a Google token to its platform's devices, and the member's devices revoke at the provider when the member leaves. The cost is a re-seal a device does as it opens its entry, and a device of a platform with no entry yet waiting for another to seal it one. Why: an audit reader that holds live tokens acts as each member at their provider, an iCloud app password opening their mail too, which no audit needs, and it still sees each connection's record; if every reader held them, a lost phone would hold the desktops' Google token as well, so Replace would have to revoke both; and a member who leaves has no device left to run Disconnect, so a personal Google token would stay live for months.

Builds: CONN-M13-01, CONN-M13-04, CONN-M13-09. Question: `compute-plan-q-conn-15-team-s-audit-reader-device.md`.

### QD-1270 (Q-CONN-16): May a connected service's calls, and a calendar link's, leave by the device's own route where the person or the network chooses?
*§25.16. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

Yes, as `direct`, chosen per connection or link by the person, or for all by the network's policy. `auto` stays the default unless a definition's gate, by its 30-day exit test (§19.2), shows that exit changes cost sessions. Why: the privacy exits buy here is small, since the provider knows the account and sees the person's own address at every sign-in (Q-CONN-10) and no URnetwork server takes part either way; while each exit change is a new address at the next refresh, which Entra ID Protection may read as a stolen token and answer by revoking a work account's sessions, and a Conditional Access policy that judges the token request's address refuses an exit it does not trust.

Builds: CONN-M13-02, CONN-M13-10, MAILCAL-M13-03, MAILCAL-M13-04. Question: `compute-plan-q-conn-16-connected-service-s-calls-calendar.md`.

### QD-1271 (Q-CONN-17): Should an enclave hold an OAuth grant of its own, so that revoking it when an incarnation ends touches no other device?
*§25.16. In Appendix G.2's open list, blocking nothing at launch. The design's answer: (a) at launch, (b) Later.*

Not at launch: an enclave reads the member's tokens as any device does. A stop or a loss asks no one to replace them, since they lived only in the incarnation's memory, and a compromise revocation offers Replace as for any device (§25.7). A grant per enclave, made by the person's sign-in when the enclave is created, sealed only to its incarnations and revoked at the provider at its removal or a compromise, is Later. Why: clean revocation does not need it, since a stop ends the VM, its memory and its ReaderKey, and the tokens it held go with them; only a breach, which the owner accepted for the initial version (CO-43), could have kept a copy. A grant per enclave would narrow Replace to the enclave's own grant at Google, but Microsoft revokes no single token, so it gains nothing there, and it asks the person to sign in again for each enclave; a grant per incarnation would ask at every incarnation, which unattended restarts cannot do (§11.7).

Builds: CONN-M14-01. Question: `compute-plan-q-conn-17-enclave-hold-oauth-grant-own.md`.

## §26 Listeners

### QD-1327 (Q-LSTN-1): Who sees whose listeners?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

Every device's list goes to every admitted sidecar of the network. A person keeps a service or a device to themselves by hiding it, after reading `listeners:publish`, which their devices wait for; admins may narrow who publishes with the document's `listeners` block, never widen past the default. Why: CO-38 decided it ("any client on the network"), and CO-39 confirms that the design supports the use case whole; the earlier default kept most people's services off the list until they opted in.

Builds: LSTN-M13-05, LSTN-M13-10. Question: `compute-plan-q-lstn-1-sees-whose-listeners.md`.

### QD-1329 (Q-LSTN-2): Who may reach a listed entry by default?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

Every client of the network, tagged sidecars and enclaves included: DESIGN's allow-all where there is no document, and the listeners rule, which the implicit document carries for tagged sources and every new document for all. So every service a device serves on every interface, a development server or a database with no password among them, is open to every device and every enclave agent of the network, a prompt-injected one included, unless its person hides it or an admin narrows the rule; what is open is exactly what is listed, so the person sees it, and `listeners:publish` and §26.15 say so. Reach opens only by people's acts: a person's devices once that person acknowledges the text and confirms each desktop's first list on it; tagged sidecars' entries and the implicit document's rule once an Owner or Admin acknowledges it for the network (Q-LSTN-8, Q-LSTN-9). An enclave whose egress is `none` reaches listed services too, and so counts as reaching out (§7.8); and a flow the rule admits reaches the service as the network's, never as localhost (Q-LSTN-11). Why: as CO-38 says, "any client on the network" sends to `ip:port` and reaches the service, and CO-39 asks for the whole use case.

Builds: LSTN-M13-06. Question: `compute-plan-q-lstn-2-reach-listed-entry-default.md`.

### QD-1330 (Q-LSTN-4): Does the listeners rule open forwards too?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

No: a forward is listed with who may use it and until when, and its target is listed by its own host, where the listeners rule opens it to every client once that host publishes (§26.6), delivered there as the network's traffic (Q-LSTN-11). Why: a forward is a grant to one sidecar for its own use (R-BRIDGE-6); opening its local port to every client would let each reach the target through that grant, past whatever the target's own rules say.

Builds: LSTN-M13-07. Question: `compute-plan-q-lstn-4-listeners-rule-open-forwards-too.md`.

### QD-1331 (Q-LSTN-5): Are sockets bound to loopback alone listed?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

No: they stay in the person's own view, with "map it", and the listeners rule never delivers to loopback (Q-LSTN-11). A person who wants to offer one maps it (`ur bridge expose :<port>=127.0.0.1:<port>`, or "map it" in the apps), an approved act of theirs whose map is then listed, and opened, as any. Why: a loopback bind is a program's or a person's choice to serve this machine alone: a browser's debugging port, which runs any script it is sent, a local admin panel, a database set to `localhost`; listing them would open them to every client and, delivered at `127.0.0.1`, skip the host's firewall and pass their "allow from localhost" checks.

Builds: LSTN-M13-04, LSTN-M13-07. Question: `compute-plan-q-lstn-5-sockets-bound-loopback-alone-listed.md`.

### QD-1332 (Q-LSTN-7): May the local Harness open a listed service, as `web_fetch` of an http entry?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

No: the local profile lists, and the person opens an entry in their browser. An enclave's agents, which run programs, dial as any program there, within the enclave's reach. No new outward kind is needed. Why: the local profile reaches the network only through sidecar's own transports and `web_fetch` only public addresses (IC-7, IC-16), so a prompt-injected run cannot send requests into the person's network.

Builds: LSTN-M13-15. Question: `compute-plan-q-lstn-7-local-harness-open-listed-service.md`.

### QD-1333 (Q-LSTN-8): Does the release open the listeners rule anywhere by itself?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

No. A network's existing document gains the rule only by its admins' save, which the apps offer. In a network with no document, the implicit document's rule for tagged sources admits only once an Owner or Admin has acknowledged `listeners:publish` for the network (§26.6), as tagged sidecars' publishing does (Q-LSTN-9). Team's starting document and every new document carry the rule, opening what people's acts have listed. Until the acts, such a network's entries show `blocked` or `waiting` with the fix, so the list stays honest. Why: a document is its admins' signed statement (I-4), which no release rewrites; a network with no document takes its rules from the release, so a rule it gained at an upgrade would open services to every CI runner, cloud agent and enclave's root agent of the network with no one who may decide for the network having acted.

Builds: LSTN-M13-06. Question: `compute-plan-q-lstn-8-release-open-listeners-rule-anywhere.md`.

### QD-1334 (Q-LSTN-9): Must someone acknowledge `listeners:publish` before a tagged sidecar publishes?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (c).*

Yes: an Owner or Admin, for the network, by §2.8's `disclosure-ack` in the `compute` block (§26.6), as CO-41 settled for tagged sidecars' disclosures (Q-CTRUST-3). In a network with no document, the `compute` block sits in a config record that sets no reach, which keeps it under DESIGN's allow-all. Why: no person sits at a server, a CI runner or an enclave, so one who may decide for the network reads the text for them; publishing with no acknowledgment would open every tagged host's services to every client at the upgrade with no one having read anything, and a sponsor's act per machine fails where an admin's servers have no sponsor who reads.

Builds: LSTN-M13-06, LSTN-M13-10. Question: `compute-plan-q-lstn-9-must-someone-acknowledge-listeners-publish.md`.

### QD-1328 (Q-LSTN-10): Is a new entry open at once, or only once its person has seen it?
*§26.14. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

At once, as the bridge lists it: the person reads `listeners:publish` once and confirms each desktop's first list on it (§26.6), then sees each new entry with its program's name and hides what should stay theirs. Why: CO-38 asks the bridge to keep the list current, and a confirmation for every development server started would leave the list behind the machine.

Builds: LSTN-M13-10. Question: `compute-plan-q-lstn-10-new-entry-open-once-only.md`.

## §27 Automatic approvals and the safety classifier

### QD-1345 (Q-SAFE-1): Which model?
*§27.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

Llama Prompt Guard 2: the 22M on phones and the 86M elsewhere. The Llama 4 Community License asks for its copy and "Built with Llama", both in the release's notices, and "Llama" first in a derived model's name, which the exports' names keep. The bench can swap in PIGuard by release if it serves better. Why: it has the best published detection of the small classifiers, 81.2% of AgentDojo's attacks prevented at a 3% utility cost for the 86M against 22.2% for Protect AI's, by Meta's measure; a tokenizer refined against the spacing attacks that broke its predecessor; a multilingual 86M; and a 22M that fits a phone. Protect AI's model is English only, archived and nearly three times the 22M's size; PIGuard resisted adaptive search better (71% against more than 90%) but is 0.2B on an English base; Llama Guard 3 1B classifies hazards, not injection; and the agent's own local model is open to the same text.

Builds: SAFE-M13-05, SAFE-M13-13. Question: `compute-plan-q-safe-1-model.md`.

### QD-1346 (Q-SAFE-3): Should the classifier also decide DESIGN's own taint-driven refusals, such as `mail_send` from a tainted run to recipients already approved, which would amend I-8 and I-9 through Appendix D?
*§27.15. In Appendix G.2's open list, blocking nothing at launch. The design's answer, (c), which is (a) at launch.*

Not at launch: the classifier decides this document's kinds 23 to 26 only, and the question returns once M13's records show what it allows and what it misses, when an owner decision beside owner decision 142 can extend it. Why: CO-40 answers Q-CONN-7, a question about this document's kinds; DESIGN's outward actions mostly reach other people or the network (mail, publishes, grants, DNS), which §27.7 would send to the person anyway, so deciding them buys little now while amending invariants frozen with `record.proto` at M3 (owner decision 142).

Builds: nothing yet. Question: `compute-plan-q-safe-3-classifier-also-decide-design-s.md`.

### QD-1347 (Q-SAFE-4): Does CO-40's rule for clean runs reach the calendar's invitations, which §23.9 sends to the person in any run?
*§27.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (a).*

No: an event with attendees waits for the person, on every link. Under this answer a clean run's raw `service_call` send goes without a tap while a typed invitation asks, which the owner may settle otherwise later. Why: CO-40 answers Q-CONN-7, which asked about `service_call` and set it against the calendar's own rule; an invitation is mail the provider sends from the person's account to other people, which DESIGN asks about in any run for a first recipient (R-CTX-26); one rule for a tool across its links is what a person can learn; and one tap approves a whole batch.

Builds: SAFE-M13-06, SAFE-M13-15. Question: `compute-plan-q-safe-4-co-40-s-rule-clean.md`.

### QD-1348 (Q-SAFE-5): Does auto mode wait for the person's acknowledgment of `approvals:auto`?
*§27.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

Yes: the first taint-driven approval goes to the person with the `approvals:auto` text and an offer to let the check decide, and auto starts once the person acknowledges it. The setting's default stays `auto` (CO-40). Why: CO-33 asks that the person read what could be exposed, and that an automatic check may let an injection act is such a fact; the person is at that first card anyway.

Builds: SAFE-M13-06, SAFE-M13-10. Question: `compute-plan-q-safe-5-auto-mode-wait-person-s.md`.

### QD-1349 (Q-SAFE-8): How many automatic approvals, and does one ask end them for the run?
*§27.15. In Appendix G.2's open list, blocking M13a's entry and the listeners track. The design's answer, (b).*

At most 10 a run, 3 a minute and 50 a day on a device, the minute's 3 counted per device (QD-1372); one ask or decline ends auto for the run. Why: a miss should cost little and be seen: 10 covers a run's ordinary fetches and writes, and 50 a busy person's day; ending auto after an ask stops a run from trying phrasings until one passes, at the price of a tap for each later action in a run already suspect.

Builds: SAFE-M13-06. Question: `compute-plan-q-safe-8-many-automatic-approvals-ask-end.md`.

### QD-1350 (Q-SAFE-9): May the classifier decide a tainted run's `send` through `service_call`, as CO-40's "if the classifer approves, go ahead" could be read?
*§27.15. In Appendix G.2's open list, blocking M13b's entry. The design's answer, (a).*

Never: a tainted run's send goes to the person. Writes, to the person's own data, are where the classifier spares taps; deciding sends to recipients the member has written to before can follow once typed tools name their recipients. Why: a send reaches other people, whom the daemon cannot read from an arbitrary API body, so it cannot tell a first recipient (§27.7), and an injected send harms them, not only the person; DESIGN asks even a clean run before mail to a new recipient (R-CTX-26).

Builds: SAFE-M13-15. Question: `compute-plan-q-safe-9-classifier-decide-tainted-run-s.md`.

## The plan's own readings

The 43 rules the planners read where DESIGN-COMPUTE.md leaves a format, a route, a module or a name open, each the option the question recommended. They are in the order of the section each mainly amends, Appendix D's last; the index lists every section each one touches.

### QD-1242: From what instant does a new disclosure version's grace run, which neither §2.8 nor §5.4 gives?
*Amends §2.8 and §5.4. Option 1.*

From the version's effective instant: each disclosure entry of §5.4's signed policy gains `since_ms`, that instant, signed with the policy, and the grace runs from it, exact and the same on every device. Why: running it from when each device first sees the version would have devices disagree, and one long offline would see a fresh grace.

Builds: ATTEST-M11-01, CTRUST-M12-01. Question: `compute-plan-disclosure-grace-start.md`.

### QD-1257: How does reconciliation read what each provider billed for a day, which §10.7 compares and §4.6's adapter interface cannot supply?
*Amends §4.6 and §10.7. Option 1.*

§4.6's adapter interface gains an optional `BilledUsage(ctx, day)`, implemented where a provider exposes its billed usage; elsewhere reconciliation reads balance deltas, and its report says which it compared. Why: complete where possible; balance deltas alone would never compare a provider's own bill.

Builds: GAMMA-M12-06. Question: `compute-plan-provider-billing-export.md`.

### QD-1256: What is the compute policy's signature container, its certificate's form, and is "two of four holders sign" one signature under two-person custody or two signatures?
*Amends §5.4. Option 1.*

Each policy version is signed by one SSHSIG over `<version>.json`, detached as `<version>.json.sig`, under the namespace `ur-compute-policy`, by the compute-policy key, whose OpenSSH certificate the release key signs, valid for at most a year. "Two of four holders sign" is two-person custody of that one key, a ceremony as the release key's is, not two signatures. The ceremony that creates the key and its certificate is External. Why: one verifier path, the SSHSIG code the repository already has; two signatures by the holders' own certified keys would have devices verify two signatures and pin four keys.

Builds: ATTEST-M11-01, ATTEST-M12-01, ATTEST-M12-02. Question: `compute-plan-policy-signature-format.md`.

### QD-1379: How are freshness tickets encoded and served, and may a device take a ticket from another device of its network?
*Amends §5.4 and §5.6. Option 1, the device relay included.*

Freshness tickets are deterministic protobuf, in attest.proto, served with the policy at `ur.io/compute/policy/<version>/tickets/<day>.bin`, the ticket host posting them through the same publishing path. A device may relay its newest verified ticket to its network's devices over EVS, in the vault, which §5.4 allows when ur.io is unreachable. Why: complete; without the relay, a device that cannot reach ur.io stops remote work after 72 hours. For the fold: §5.4 serves the policy itself at `https://ur.io/compute/policy/v1/<version>.json`, with a `v1` segment the reading's tickets path lacks.

Builds: ATTEST-M12-01, ATTEST-M12-02. Question: `compute-plan-ticket-distribution.md`.

### QD-1237: Where does the broker keep catalog versions, which §6.3's 24-hour rule needs across stateless broker instances?
*Amends §6.3, §14.4, and §14.6's compute-7, which Appendix D's row for DESIGN §2.8's list carries into DESIGN.md. Option 1.*

In a `compute_catalog_version` table of MG-C2: each version, its published time, and its entries and prices as published, compute-7's row naming it. Stateless broker instances read from it which versions still admit a call (one for 24 hours after a newer one, §6.3) and the prices a call was admitted under (§9.7). Why: durable and auditable; versions kept in Redis only would lose, with Redis, the prices calls were admitted under.

Builds: INFER-M12-01. Question: `compute-plan-catalog-versions.md`.

### QD-1241: Which route carries a direct call's receipt from the device to the broker, which §6.6's step 4 forwards and §14.3 does not list?
*Amends §6.6 and §14.3. Option 1.*

`POST compute/v1/infer/settle`, with sidecar auth, carrying the provider's signed receipt (or its usage record) and the call's nonce, idempotent by nonce, beside its sibling routes. Why: carrying the receipt on the next `infer/authorize` instead would leave a device that stops calling never settling its last call except by the broker's lookup.

Builds: INFER-M12-05. Question: `compute-plan-direct-settle-route.md`.

### QD-1247: May the inference plan's five small readings stand: fixed provider codes, the helper's location, the direct call's label, `models_list` as a Harness tool only, and `ComputeInferHeader` in infer.proto?
*Amends §4.6, §6.5, §6.6, §6.8, §9.4 and §15.2. Option 1.*

All five stand:

1. Each provider slug of §4.6 has a fixed smallint code, an identifier, both kept in `compute_provider`; `compute_charge.provider` (§9.4) holds the code.
2. The `ur-engine` helper's main lives in `cli/ur-engine/` (§6.5).
3. A direct call's `none` label on its `model_call` (§6.8) is read from the route the router took, not from the catalog entry.
4. `models_list` is a Harness tool only (§7.5), not an MCP tool (§15.2).
5. `ComputeInferHeader` lives in protocol/infer.proto, not compute.proto as §6.6 places it, with the same name and fields, so no wire byte changes.

Builds: INFER-M11-04, INFER-M11-07, INFER-M11-09, PROV-M12-01, BAL-M13-01, INFER-M15-02. Question: `compute-plan-inference-small-readings.md`.

### QD-1252: May the ledger add the columns, and the metadata rows, the money plan found missing from §9.4's SQL and §14.6?
*Amends §9.4, §9.9, §9.11, §9.12, §14.4, and §14.6's compute-2 and compute-7, which Appendix D's row for DESIGN §2.8's list carries into DESIGN.md. Option 1.*

MG-C1 gains the three columns the design describes without a place in §9.4's SQL: §9.9's `indexer_reserve`, §9.11's per-network search-cap override, and a self-serve refund's amount on `compute_lot` (§9.12). Three server-visible stores gain their metadata rows (I-18) by amended rows: `compute_terms`, which stores the accepting user, and `{cmpk_<network_id>}`, a network's failed promotion code redemptions today, under compute-2; and GAMMA's provider-capacity key `{cmpv_<provider_id>}` under compute-7. CARCH-M11-03 carries the rows' text. Why: what the design describes, made storable and listed; leaving each out until a fold would run the indexer with no reserve, and leave no search-cap override, no self-serve refund and no terms route.

Builds: CARCH-M11-03, BAL-M12-01, BAL-M12-07, BAL-M12-13, BAL-M12-14, GAMMA-M12-05, BAL-M13-02, BAL-M13-03, BAL-M14-02. Question: `compute-plan-money-schema-gaps.md`.

### QD-1376: How does §9.7's settlement fence work under PgBouncer's transaction pooling, which forbids the session lock it describes?
*Amends §9.7. Option 1.*

The fence takes a transaction-scoped advisory lock in each of the booking's and the drop's transactions, and the drop script carries a version guard: it drops only the unsettled charge whose booked version matches. The guard carries the ordering the session lock gave, so a settlement's drop still never races its booking (IC-6, R2-07). Why: production's Postgres runs behind PgBouncer in transaction pooling, which forbids session-level locks (server/model/approval_use_model.go does without them); a non-pooled connection for the settle worker alone would keep the lock as written, at the cost of one more connection class to provision.

Builds: BAL-M12-04. Question: `compute-plan-settle-fence-pooling.md`.

### QD-1238: How does `compute_low` reach every member device, since §6.8's push topic registry has no compute topic?
*Amends §9.9, and DESIGN §6.8's push topic registry, which Appendix D does not list yet. Option 1.*

By a `compute` clock topic in the push topic registry (sidecar/push_topic.go), hinted through `Push.HintSidecars` when a network's balance state changes; each device then reads the balance route and raises `compute_low` (§9.9). Why: the existing push path; devices polling the balance route would have a phone learn late.

Builds: BAL-M12-12, BAL-M12-17. Question: `compute-plan-compute-low-delivery.md`.

### QD-1244: May the compute treasury copy server's chain reader (`controller/gamma_chain.go`), which exists only on server's main branch, onto server's sidecar branch?
*Amends §10.2 and §3.3. Option 1.*

Yes: GAMMA-M12-02 copies `server/controller/gamma_chain.go`, its test and its testdata unchanged from server's main branch (commit 5ca596d12) onto server's sidecar branch, then extends them with what GAMMA adds (`mint_gamma`, the cap and the move calls). The copy diverges from main until the branches merge. Why: merging server's main into its sidecar branch first, a 2,679-commit merge mid-draft, would touch every lane.

Builds: GAMMA-M12-02. Question: `compute-plan-gamma-chain-on-sidecar.md`.

### QD-1245: Which route carries a spend from taskworker's `compute_gamma_spend` job to K_P's signer on the computeservice hosts?
*Amends §10.5, §14.3 and §14.5. Option 1.*

An internal `POST compute/v1/gamma/sign`, reachable only from taskworker's hosts and refused to every sidecar, which signs only spends that match the job's committed operation rows. K_P stays on the computeservice hosts, where §10.5 puts it. Why: running the spend job on the computeservice hosts instead would move a job off taskworker.

Builds: GAMMA-M12-03. Question: `compute-plan-gamma-signer-route.md`.

### QD-1243: May the enclave plan's format readings stand where §11 and §12 name a thing without its bytes or channel?
*Amends §5.8, §11.4, §11.6, §11.7, §11.11, §11.12, §12.5, §12.7 and §14.6's compute-5, and, through Appendix D, DESIGN §7.9's `KeyRegister`, DESIGN §3.6's `IndexerSet` and RECORD.md's kinds. Option 1.*

All seven stand, each a format change the enclave tasks land under the `enclaves` feature, before any reader judges it:

1. `KeyRegister` (DESIGN §7.9) gains the purpose `ssh`, which a sidecar registers for itself under the `enclaves` feature, for the sidecar's own SSH key §12.5 and §11.7 need; DESIGN's purposes are presence and sshsig, and only an approval-capable device may register (config_keys.go).
2. §11.12's `enclave` record entries take a record kind of their own; kind 29 is code review's.
3. §12.7's per-session receipt is an SSH session receipt of its own, not `ReachReceipt`, which is coalesced per grant and peer.
4. `IndexerSet` gains `enclave_id` (field 6), so it can name an enclave.
5. compute-5 lists, in transit and never stored, the bootstrap B the broker carries to the VM (§11.7's create request carries only SHA-256(B), and the VM reads B from the host) and the per-VM token the VM uses from the host (§14.3), a second host input §11.5 does not mention.
6. §5.8's `AttestationResult` gains the chip identity, which §11's keeper rule and the indexer's Where row check.
7. Liveness ("silent for 5 minutes") and the stop signal go through the incarnation's own row, and agents' readiness through the evidence's health bits.

Builds: CARCH-M11-05, CTXH-M11-08. Question: `compute-plan-enc-readings.md`.

### QD-1239: Does `computeservice` check a DPoP proof on every request, as §14.2 says, or the exchange-minted bearer service token, as DESIGN §7.8's services do?
*Amends §14.2. Option 1, for the draft.*

`computeservice` verifies the exchange-minted bearer service token, as evs, gkm and dns do, the token's `cnf` left for a later per-request proof; a stolen token is good for its 15 minutes. A per-request DPoP proof bound by `cnf.jkt`, with a jti replay family `{cmpj_<sidecar>}` and its §14.6 row, is a hardening the review phase may add with that row. Why: it matches every other service, whose bearer tokens the exchange mints after checking the ClientKey's DPoP proof once (DESIGN §7.8).

Builds: CSRV-M12-01. Question: `compute-plan-compute-token-dpop.md`.

### QD-1246: What encoding do the compute routes' bodies take: protobuf, JSON, or both?
*Amends §14.3, beside §6.6 and §21.5. Option 1.*

Every `compute/v1/*` body is protobuf, from protocol/infer.proto, websearch.proto, enclave.proto and compute.proto, and every `api/compute/*` body is JSON, as the api's other routes are: one convention per host. The sdk mirrors the JSON as it does today. Why: JSON everywhere would need a canonical JSON form for sealed envelopes and hashes.

Builds: INFER-M12-01, INFER-M12-04, INFER-M12-05, INFER-M12-06, INFER-M15-02. Question: `compute-plan-infer-wire-format.md`.

### QD-1367: Which §14.6 rows cover the compute state the servers hold that no row names outright: `{cmpk_<network_id>}`, the budget counters, `{cmpr_<network_id>}`, the projection's compute fields and the per-sidecar features?
*Amends §14.4 and §14.6's compute-2, compute-6, compute-10 and api-7, which Appendix D's row for DESIGN §2.8's list carries into DESIGN.md. Option 1, which agrees with QD-1252 on `{cmpk_}`.*

Each maps explicitly to an existing row, in CARCH-M11-03's rows and fields.yml: `{cmpk_<network_id>}` under compute-2, amended to "failed redemptions a network a UTC day, a day"; the budget counters under `{cmp_<network_id>}:b:<subject_id>` under compute-6; `{cmpr_<network_id>}`, a network's search rate and its searches today, under compute-10; the signed projection's compute fields (assurance floors, allowed providers, enclave shapes, the search day cap, §16.4) and `ProjectionSettings.auth_features` (§16.6) under api-7, the projection's row; and the core state's per-sidecar features, the proposed Redis hash `{scf_<network_id>}`, under api-7 as the core state's features. Why: the rows' content, stated where I-18's check reads it; new rows from compute-12 on would describe what the existing ones already do.

Builds: CARCH-M11-03, CSRV-M12-01. Question: `compute-plan-redis-family-rows.md`.

### QD-1375: How is MG-S1 applied to `searchsigner`'s own database, which server's migration runner cannot reach?
*Amends §14.4's MG-S1 and §14.2. Option 1.*

MG-S1 is a migration list of its own, `server/db_migrations_searchsigner.go`, applied by a new `sidecarctl searchsigner migrate` against the signer's database; the signer stays unready until its database is at that list's head. Why: the separation §21.5 wants, kept in operations; server's migration runner applies one list to one database (db_migrations.go), and a signer that created its tables at start would be a service with DDL rights on its own database.

Builds: CSRV-M13-01. Question: `compute-plan-searchsigner-migrations.md`.

### QD-1382: `ur search` already runs DESIGN §16.10's encrypted index search: what command does DESIGN-COMPUTE's web search take?
*Amends §15.1, §17.2, §21.6, §21.9 and Appendix F. Option 1.*

A command of its own, `ur web-search "<query>"…` with §21.6's flags (`[--objective <text>] [--mode <m>] [--json]`), in the CLI's hyphenated style (`ur install-harness`, `ur native-host`); `ur search` stays DESIGN §16.10's index search (owner decision 166), and the MCP tool keeps its name `web_search`. The fold changes "`ur search`" to "`ur web-search`" in §15.1, §17.2, §21.6, §21.9 and Appendix F. Why: a web search is charged and leaves the device, while the index search is free and stays in the network, so they share neither a verb nor a file; as written, the index search's pattern `ur search <query>` already matches the web form, and a person meaning to search their own mail could pay for, and send to Parallel, a web search instead.

Builds: SRCH-M13-11. Question: `compute-plan-ur-search-collision.md`.

### QD-1380: `ur agents [<task>]` already searches agents' work: may DESIGN-COMPUTE's `ur agents [ls]` take bare `ur agents`?
*Amends §15.1 and §20.8. Option 1.*

Yes: bare `ur agents` lists agents with their newest summaries (§15.1), `ur agents <task>` keeps DESIGN §16.11's search of what agents did, and `ls`, `send`, `broadcast`, `inbox` and `reply` are reserved words a task argument cannot take. A script that ran bare `ur agents` for the search gets the list. Why: the list is what a person typing `ur agents` asks for, and the search keeps its argument form.

Builds: SKILL-M11-08. Question: `compute-plan-ur-agents-ls.md`.

### QD-1381: `ur connect` already enrolls a device with an auth key: may DESIGN-COMPUTE's `ur connect <service>` share the command?
*Amends §15.1 and §25.5. Option 1.*

Yes: one `ur connect` carries both sets of usages, its help naming both, and dispatches by their arguments: `--token` or `--token-file` enrolls the device (DESIGN §5.6, R-CORE-9), and a positional service or label, or `--issuer`, makes or changes a connection. A service form on a device that is not enrolled is refused with a message naming `ur connect --token`. Both designs' texts and the landed command stand. Why: the argument shapes cannot collide, and the refusal on an unenrolled device covers the one confusing case.

Builds: CONN-M13-10. Question: `compute-plan-ur-connect-collision.md`.

### QD-1253: Does `ur native-host`, the browser extension's relay to `ur daemon`, carry §15.3's compute methods at launch?
*Amends §15.4, beside §1.2. Option 1.*

No: `ur native-host` refuses compute methods at launch, with the same refusal the page Worker gives, and the extension has no compute until its Worker returns from Later. Why: consistent with §15.4, which gives the page Worker no compute surface, and with §1.2, which gives the browser the Harness with remote inference only once the extension's Worker returns; relaying the Harness and models through `ur native-host` (DESIGN §18.8's meanwhile path) would be an early browser surface the design does not plan.

Builds: CSURF-M11-02. Question: `compute-plan-native-host-compute.md`.

### QD-1233: May the draft build each provider's adapter, and the search signer, before the provider commits in writing and before G-SRCH-parallel's load test?
*Amends §19.3's D-CPHASE-2 and D-CPHASE-9. Option 1.*

Yes: each provider's adapter (engy, SayGM and Chutes for inference; Hippius, Lium and Cathedral for enclaves) and `searchsigner` are built now, as drafts against fakes and the providers' documented APIs, each kept out of the catalog and the production policy, and the signer's signing switched off in production (`SearchSignerSettings.Enabled`), until its gate passes; nothing calls a live provider, Parallel or Base. Each such task's draft note says it is unverified against the live provider or gateway. D-CPHASE-2's and D-CPHASE-9's order binds what reaches a user, not what the draft builds: every gate of §19.2 still binds each user's use. Why: the owner's instruction of 2026-11-24 is newer and asks for the whole design as a draft; a draft against fakes binds URnetwork to no provider, and the catalog, the policy and the signer's switch keep each provider and every payment out until its gate passes, which is what D-CPHASE-2 and D-CPHASE-9 protect. An adapter whose provider declines or changes its API is rework.

Builds: CTEST-M12-07, PROV-M12-01, PROV-M12-02, PROV-M12-03, CSRV-M13-01, CTEST-M13-06, SRCH-M13-03, SRCH-M13-04, SRCH-M13-05, SRCH-M13-06, ENC-M14-19, ENC-M14-20, ENC-M14-21, ENC-M14-22, ENC-M14-23, ATTEST-M15-01, CTEST-M15-01, ENC-M15-02, INFER-M15-01, INFER-M15-02, PROV-M15-01. Question: `compute-plan-adapters-before-commitment.md`.

### QD-1378: How does a reader verify the agent name an `agent` repo carries, which §20.4 and §20.7 check through a label no format records?
*Amends §20.4 and §20.7, and, through Appendix D's row for DESIGN §8.5's kinds, DESIGN's `RepoCreate` (protocol/acl.proto). Option 1.*

`RepoCreate` gains a label for the owner-bound agent kinds, written under the `agent_repos` feature, which lands at M11, before any reader judges it, so §20.7's check of a message's `to.repo` and `from.repo` against the member's agent repo labeled `agent/<name>` works as written across members. Within one member the agent card's `agent_repo` gives the binding. Why: §20.7 relies on it, and it can land with the feature at M11; without it another member's agent name would stay unverified for good, the repo id alone addressing and waking.

Builds: SKILL-M11-01, SKILL-M13-01. Question: `compute-plan-skill-agent-repo-label.md`.

### QD-1374: How is a network's web search suspension cleared after review, which §21.5 and §21.10 describe and no command, act or column carries?
*Amends §21.5, §21.10, §14.4's `compute_search_flag`, and §14.6's compute-10, which Appendix D's row for DESIGN §2.8's list carries into DESIGN.md. Option 1.*

`sidecarctl compute resume <network> --search --review <reference>` clears it, an operator act on the record, as CARCH-M12-01's other compute controls are. `compute_search_flag` gains `reviewed_time` and `review_reference`, and compute-10's row is amended to name them. Why: clearing by a database edit under the legal process runbook would leave no record of who cleared what.

Builds: nothing yet; until a task takes it, a suspended network stays suspended. Question: `compute-plan-search-suspension-clear.md`.

### QD-1377: How does `searchsigner` report each final authorization to the broker, when only the broker may reach the signer and §14.3 lists no route for it?
*Amends §21.5, §14.2, §14.3 and §14.5. Option 1.*

The broker pulls: it polls the signer's report queue over the same mTLS link, acknowledging each report by ticket, so a report waits up to a poll interval. Why: it keeps §14.2's one direction and the separation §21.5 is built on; a signer pushing to an internal broker route, mTLS both ways, would add a second direction of trust between the two systems.

Builds: CSRV-M13-01. Question: `compute-plan-signer-report-path.md`.

### QD-1383: What HPKE suite, info string, AAD and answer sealing does a search's payee and nonce take between the device and `searchsigner`?
*Amends §21.5. Option 1.*

The repository's suite, X-Wing with HKDF-SHA256 and AES-128-GCM; the info strings `ur websearch payee v1` and `ur websearch authorization v1`, for the device's sealed payee and nonce and the signer's sealed authorization; the broker's ticket as the AAD; and the answer sealed to a fresh key the device sends in its request. Why: one suite across the code.

Builds: SRCH-M13-01. Question: `compute-plan-websearch-seal-format.md`.

### QD-1236: What are the bytes of a calendar link's target and of an event UID, which §23.6 and §23.8 give only by their inputs?
*Amends §23.6 and §23.8. Option 1.*

Each is its fields, u16be length-prefixed, in the order §23.6 and §23.8 list them (a target's stable identity, provider account and selected calendar or collection, after the second review's R2-03; a UID's effect key and index), hashed with SHA-256 where a fixed size is needed. Why: deterministic and unambiguous.

Builds: MAILCAL-M13-01, MAILCAL-M13-05. Question: `compute-plan-calendar-target-bytes.md`.

### QD-1235: May a calendar write's record keep the provider's href relative to the collection, since §23.11 forbids any entry holding a link's address or user name?
*Amends §23.11. Option 1.*

Yes: a calendar write's record keeps the provider's href relative to the collection, the event's own segment, never the collection URL, which often carries the user name; so §23.11's href and IC-18's "no entry holds a link's address, user name" both hold. Why: a hash of the full href would hold no address at all, but recovery after a lost reply could not find the event by it.

Builds: MAILCAL-M13-10. Question: `compute-plan-calendar-record-href.md`.

### QD-1234: What are the bytes and the ref of owner decision 573's per-request approval notice `a/<approval_id>`, which phones lease from M11 in place of the whole approval log?
*Amends §24.7, and Appendix D's row for DESIGN §16.8's approvals (owner decision 573). Option 1.*

A versionless sealed notice per request on the approvals ref, shaped as DESIGN §16.11's `DirectoryNotice`: the request id, its kind, its state and the request's record position, written with the request and rewritten at its decision. Phones lease those notices and the inbox prefixes, not the approval log's prefix whole. Why: it mirrors an existing format; leasing the approval log's prefix whole, as before owner decision 573's change, would wake a phone at every session push.

Builds: CTXH-M11-01, CTXH-M11-07. Question: `compute-plan-approval-notice-bytes.md`.

### QD-1240: Which route reports "the network's stored bytes as api reports them", which §24.10's storage caps read?
*Amends §24.10, and DESIGN's `GET /sidecar/limits`, beside Appendix D's row for DESIGN §20.7. Option 1.*

`GET /sidecar/limits` also answers the network's stored bytes and the time they were counted. It needs no new metadata row, since the count is already server-visible under DESIGN §20's rows. Why: one field on an existing route; a route of its own would be a separate surface for one number, and the device's own estimate from its own pushes would drift on a network of several devices.

Builds: CTXH-M11-06. Question: `compute-plan-ctxh-stored-count.md`.

### QD-1370: Does the safety classifier run as `ur __engine classify` inside `ur` (§27.5) or in the separate `ur-engine` helper (§6.5)?
*Amends §27.5, beside §6.5. Option 1.*

In `ur-engine`, beside LiteRT-LM, through the helper's method registry (`registerInferEngineMethod`): one helper, confined as §6.5 confines it and holding no keys (D-INFER-2). The fold changes §27.5's `ur __engine classify` to name it. Why: building `ur __engine classify` in `ur` as §27.5 says would make a second engine process without §6.5's confinement.

Builds: SAFE-M13-03. Question: `compute-plan-safe-engine-binary.md`.

### QD-1368: Where does the classifier's Unicode confusables table (UTS #39 skeletons, §27.6) come from, which no module here carries?
*Amends §27.6. Option 1.*

From Unicode's own confusables.txt, for the release's Unicode version, pinned in the signed release manifest beside the exported models and loaded at start; until it loads, the classifier answers `unavailable`, so each automatic approval asks. Why: the table's authoritative source, versioned with the models; a Go table generated into the source tree would change only with a code change.

Builds: SAFE-M13-02. Question: `compute-plan-safe-confusables-table.md`.

### QD-1369: What is the shortest span of the person's own words an action may copy without the classifier scoring it?
*Amends §27.6. Option 1.*

A settings field, by default 32 normalized characters: a copied span shorter than that is scored as any other text. Why: a span that long is the person's sentence, not a word; with no minimum, one copied word would exempt any text.

Builds: SAFE-M13-06. Question: `compute-plan-safe-copied-span.md`.

### QD-1373: Does §27.6's 512-token window include the model's two special tokens?
*Amends §27.6. Option 1.*

Yes: a window is 512 tokens with the two special tokens, so 510 of text, the models' maximum input as exported. Why: 512 of text plus the two would pass the models' maximum.

Builds: SAFE-M13-01. Question: `compute-plan-safe-window-specials.md`.

### QD-1371: What numbers do the classifier's verdict reasons and §27.7's always-ask rules take, which `AutoVerdict.reason`, `AutoVerdictBody.rules` and field 70 carry?
*Amends §27.6, §27.7 and §27.9. Option 1.*

They are numbered in the order §27.6 and §27.7 list them, zero being UNSPECIFIED, in record.proto beside `AutoVerdict`; `AutoVerdict.reason`, `AutoVerdictBody.rules` and CanonicalAction field 70's rules carry those numbers, and CACL-M12-01 validates field 70 against them. Why: deterministic, and the order is the design's.

Builds: SAFE-M13-06, SAFE-M13-08. Question: `compute-plan-safe-enum-numbers.md`.

### QD-1372: Is §27.8's limit of 3 automatic approvals a minute per device or per run?
*Amends §27.8. Option 1, the narrower reading.*

Per device, as the day's limit is: one burst limit across a device's runs. Why: per run, a device running many tainted runs would approve more.

Builds: SAFE-M13-06. Question: `compute-plan-safe-minute-limit.md`.

### QD-1254: Which modules may the compute tasks add that DESIGN-COMPUTE.md does not name: a BLS12-381 verifier, an XML-signature verifier, go-tpm, gorilla/websocket and x/image?
*Amends Appendix D's row for DESIGN §4.5 and §4.7, the dependency allowlist, for §5.3, §5.6, §5.7, §8.5 and §11.7. Option 1.*

All five, added at M11 in one change, CARCH-M11-02, each with its dependencies.yml row and its license read from its own files, so go.mod is edited once and the M15 tasks only import: github.com/cloudflare/circl for drand's BLS12-381 beacon signatures (§5.6; BSD-3, maintained, used by drand's own clients); github.com/russellhaering/goxmldsig for NVIDIA's XML-signed RIMs (§5.3; Apache-2.0); github.com/google/go-tpm for SVSM's vTPM quote check and credential activation (§11.7; Apache-2.0); gorilla/websocket, today an indirect requirement of sidecar, as a direct one for the evidence tunnel (§5.7); and golang.org/x/image, which server and sdk already require, for the gateway's WebP re-encoding (§8.5); the last two at the versions the other modules already select. Why: writing the BLS12-381 and XML-signature checks in-tree would mean owning a pairing implementation and an XML canonicalizer, large and subtle code; adding the M15 verifiers at M15 would edit go.mod again later.

Builds: CARCH-M11-02, ENC-M14-07. Question: `compute-plan-new-modules.md`.

### QD-1255: May the build take PiG (github.com/MichaelKinsy/PiG), which CO-1 names but no dependency list carries, as a pinned source for the Harness's goldens and the enclave image?
*Amends Appendix D's row for DESIGN §4.5 and §4.7, with §7.3, §7.10, §11.5 and §19.7. Option 1.*

Yes, at a pinned version through the module proxy, checked against the checksum database: the newest version the proxy serves (40b509fb or its tagged successor), since one PiG release was retracted for passing Go's module size limit. Its MIT license goes in NOTICE, and its dependencies.yml row marks it never linked: it is never linked into `ur`, and serves as the source of the Pi 1.5.0 goldens (§7.3, §7.10) and as the enclave image's pinned binary for attach's `--harness pig` (§11.5, §19.7). CARCH-M11-02 adds it. Why: the design's intent; writing the goldens by hand from Pi's documentation and building the image without PiG would drop §19.7's `--harness pig`.

Builds: CARCH-M11-02, HARN-M11-01, HARN-M14-07. Question: `compute-plan-pig-module.md`.

### QD-1366: Must Appendix D's RECORD.md rows (record kinds 54 to 56, class 8, `body_apart`, Coverage's field 8) be folded into RECORD.md before the code that adds them lands, or may the tests that hold the code to RECORD.md take an additions list?
*Amends how Appendix D's RECORD.md rows land, for §24.5 and §27.9. Option 1.*

The tests that hold the record's code to RECORD.md and DESIGN.md, record_kind_test.go and protocol/design_fence_test.go, take an additions list, each entry naming DESIGN-COMPUTE.md's section and the compute planner's amendment entry (`.stack/plan/COMPUTE-AMENDMENTS.md`, CA-69 to CA-85), which the design-records fold deletes as it writes the text into RECORD.md, as design_unfenced_test.go's testFenceAdditions and metadata_list_test.go's metadataListAdditions already work. So record kinds 54 (`session_entry`) and 55 (`session_blob`), class 8 `bulk`, `body_apart` and Coverage's field 8 (CTXH-M11-01), kind 56 (`auto_verdict`, SAFE-M13-08) and `ModelCallBody` fields 11 to 14 (INFER-M11-07) land without waiting for the fold. Why: the pattern the repository already uses for its other additions; folding first would make M11's first tasks wait for a fold that is paused.

Builds: CTXH-M11-01, CTXH-M11-02, CTXH-M11-08, SAFE-M13-08. Question: `compute-plan-record-registry-fold.md`.
