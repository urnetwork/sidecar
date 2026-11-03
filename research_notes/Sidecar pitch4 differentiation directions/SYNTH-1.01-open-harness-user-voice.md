# Branch 1.01 synthesis: what developers using open-source harnesses and local models need (SYNTH-1.01)

Synthesized 1 November 2026. This file draws only on the branch's five notes and adds no new research. Findings and figures come from the notes, cited with the URLs the notes give, followed by the note they came from in parentheses. The directions, tests and cost judgments are this synthesis's inferences from those notes.

**Notes in this branch**
- (1.01) level 1: `L1-1.01-open-harness-user-voice.md`. What developers using open-source harnesses and local models need.
- (2.07) level 2, opened by 1.1 and 1.5: `L2-2.07-without-patching-them-what-can-a-sidecar-beside.md`. What a sidecar beside the model server can learn without patching vLLM, SGLang, llama.cpp, Ollama or LM Studio.
- (2.11) level 2, opened by 1.1, 1.4 and 1.5: `L2-2.11-how-much-coding-agent-work-runs-on-open-weight-m.md`. How much coding-agent work runs on open weights, where it runs, who runs it, and which hosts prove what they served.
- (2.14) level 2, opened by 1.1: `L2-2.14-would-local-model-developers-and-their-security.md`. Local-only proof versus OS firewalls and sandboxes.
- (3.11) level 3, opened by 2.11 and 2.04: `L3-3.11-are-gateways-hosts-and-model-providers-starting.md`. Whether gateways, hosts and providers give per-request proof of what served a call.

**Pitch4 pages named below** ([pitch4.html](/Users/brien/urnetwork/sidecar/pitch4.html)): 1 the idea ("One write, three readers"), 2 for developers ("Never lose a session or an edit"), 3 for security buyers ("Govern every way out"), 4 open source and open weights ("Open all the way down"), 5 market and pricing ("What's ours, and who pays"), 6 the plan ("Proof before scale").

---

## Summary

- **What these developers ask for.** They want local models that work with their harness, sessions they cannot lose, and proof of what leaves the machine. The leak is the harness, not the model. All nine harnesses whose source was read contact other hosts by default when pointed at a local model, and in at least four an opt-out failed on some path (2.14).
- **What they rarely ask for.** Approval and audit logs come from 19 people, with 0 votes, outside Codex (1.01). Direct demand for an exportable "what left this machine" report is thin (2.14). The only requests for signed model-call records at LiteLLM came from three people, two of whom sell signing products (3.11).
- **Who runs open weights, and where.** Open-weight-only teams are about 2–5% of agent users, and mixed fleets are the norm (2.11). Most developer open-weight coding tokens run on third-party hosts, so pitch4's "nothing has to leave your control" is false for most open-weight coding (2.11).
- **What a model-server sidecar can prove.** Beside vLLM, SGLang, llama.cpp, Ollama or LM Studio, it can recover nearly the whole serving identity without patches. The exception is a content digest of the weights, which it must compute once per model version (2.07). No host's per-request receipt binds the weights today, and the open ACI receipt format has an empty slot for exactly that claim (3.11).
- **Who keeps receipts.** Attested hosts keep their receipts for an hour or less. Phala's own client keeps them, but only on one developer's laptop. Nobody offers a team-keyed archive across hosts, linked to sessions and changes (3.11).
- **Net effect of the deeper levels on level 1.** Local-only proof, level 1's lead idea, becomes a strong first-release feature rather than the product's lead. The weights claim becomes exact and narrower. The "organizations that run open weights" segment gives way to mixed fleets. A tension appears: egress enforcement can stay out of the model path, but verifiable receipts cannot.

---

## 1. What the branch found

### 1.1 What open-harness and local-model users ask for (1.01)

Counts are distinct GitHub accounts across 12 harness repos, excluding Codex, from title searches run on 1 Nov 2026. They are lower bounds, because each query kept only its top 50 results ([GitHub search API](https://docs.github.com/en/graphql/reference/queries#search)) (1.01).

| Theme | People (excl. Codex) | Votes (excl. Codex) |
|---|---|---|
| Offline, privacy, telemetry | 284 | 489 |
| Undo and checkpoints | 246 | 293 |
| Sessions lost, hidden, or stranded | 191 | 71 |
| Export of sessions | 130 | 137 |
| Sharing sessions | 120 | 71 |
| Search across sessions | 110 | 124 |
| Model provenance and attribution | 93 | 115 |
| Approval, permission, or audit logs | 19 | 0 |
| Sync or move across machines | 13 | 32 |

- **Local models fail on compatibility, not reach.**
  - The largest single request is model discovery: [OpenCode #6231](https://github.com/anomalyco/opencode/issues/6231), 248 thumbs-up.
  - Tool-call failures come next, with 109 items and 435 people across 12 repos, for example [OpenCode #20995](https://github.com/anomalyco/opencode/issues/20995).
  - Timeouts on slow local generations follow ([Kilo #1681](https://github.com/Kilo-Org/kilocode/issues/1681)) (1.01).
- **Reach is solved for individuals; teams still have gaps.** Tailscale and LM Studio's LM Link already let one person reach a home GPU box ([Tailscale blog](https://tailscale.com/blog/lm-link-remote-llm-access)). The open problems are at team level (1.01):
  - Ollama has no native authentication ([#1053](https://github.com/ollama/ollama/issues/1053), [#14003](https://github.com/ollama/ollama/issues/14003)).
  - vLLM had an `--api-key` bypass ([#64391](https://github.com/vllm-project/vllm/issues/64391)).
  - Request logs are scarce ([vLLM #64654](https://github.com/vllm-project/vllm/issues/64654)).
- **Users want to know which model and checkpoint served them.**
  - Users of hosted open-weight plans ask which checkpoint served them ([OpenCode #41969](https://github.com/anomalyco/opencode/issues/41969); [#24649](https://github.com/anomalyco/opencode/issues/24649), 34 thumbs-up).
  - On HN, users say providers "can pull a switcheroo on weights or quantization at any moment" ([HN 49792371](https://news.ycombinator.com/item?id=49792371)).
  - Harnesses do not record which model produced a step ([OpenCode #40544](https://github.com/anomalyco/opencode/issues/40544)), and models write false attribution into commits ([OpenCode #52445](https://github.com/anomalyco/opencode/issues/52445)) (1.01).
- **Session tools are crowded, and harnesses are dropping features.**
  - The note lists seven cross-harness session tools launched on HN between August and October 2026.
  - Vibivibi already sells end-to-end encrypted session sharing at $8 Pro and $15 per member Team ([vibivibi.com](https://vibivibi.com/)).
  - OpenCode retired session sharing on 15 Oct 2026 ([PR #55716](https://github.com/anomalyco/opencode/pull/55716)), and Roo Code shut down on 15 May 2026 ([Roo Code README](https://github.com/RooCodeInc/Roo-Code)) (1.01).
- **Trust events set the adoption bar.**
  - OpenCode leaked stored provider keys ([HN 50133401](https://news.ycombinator.com/item?id=50133401), 977 points).
  - Codex installed a self-updating daemon ([HN 50060694](https://news.ycombinator.com/item?id=50060694), 193 commenters).
  - ZCode silently uploaded git history ([HN 49750694](https://news.ycombinator.com/item?id=49750694)).
  - LiteLLM was compromised on PyPI ([HN 47501426](https://news.ycombinator.com/item?id=47501426), 290 commenters).
  - Users object to in-path proxies as "a single point of failure direct in the line of your productivity" ([HN 50151130](https://news.ycombinator.com/item?id=50151130)) (1.01).

### 1.2 What a harness sends when pointed at a local model, and what breaks when it is blocked (2.14)

- **Every harness phones out.** The note read the source of nine harnesses: OpenCode, Crush, Pi, Aider, Goose, Qwen Code, Cline, Continue and Kilo. Each contacts hosts other than the model server by default, for telemetry, model catalogs, update checks, binary and plugin downloads, and vendor cloud features. Eight of the nine have a telemetry client, and six of those use PostHog (2.14).
- **Offline switches.** Pi has one documented switch, `PI_OFFLINE` ([cli.md](https://github.com/earendil-works/pi/blob/b556cfe5b0/packages/coding-agent/docs/cli.md)). Crush has two flags that cover its two hosts ([#453](https://github.com/charmbracelet/crush/issues/453)). OpenCode has about six separate flags and no single offline mode (2.14):
  - its maintainers closed two offline-mode PRs unmerged ([PR #18235](https://github.com/anomalyco/opencode/pull/18235), [PR #8130](https://github.com/anomalyco/opencode/pull/8130));
  - they closed [#2224](https://github.com/anomalyco/opencode/issues/2224), [#10416](https://github.com/anomalyco/opencode/issues/10416) and [#18233](https://github.com/anomalyco/opencode/issues/18233) as not planned.
- **Opt-outs fail** (2.14):
  - Cline: SDK events "ignore the level and report usage events anyway" ([PR #14905](https://github.com/cline/cline/pull/14905)).
  - Kilo: the JetBrains plugin "turns CLI telemetry back on after the user opts out" ([PR #15201](https://github.com/Kilo-Org/kilocode/pull/15201)).
  - Qwen Code: the privacy notice contradicted the default, and the triage bot replied "the report is accurate on every point" ([#15478](https://github.com/QwenLM/qwen-code/issues/15478)).
  - Continue: telemetry was sent with `allowAnonymousTelemetry: false` ([#2082](https://github.com/continuedev/continue/issues/2082)).
- **Blocking without stubs breaks work.** Most breakage comes from downloads and catalogs; very little comes from blocking telemetry (2.14):
  - OpenCode's `grep`, `glob` and `skill` tools fail without ripgrep ([#34442](https://github.com/anomalyco/opencode/issues/34442)).
  - Kilo hangs downloading an "agent" component ([#10580](https://github.com/Kilo-Org/kilocode/issues/10580)).
  - Cline's MCP configuration breaks in an air-gapped environment ([#7245](https://github.com/cline/cline/issues/7245)).
- **OS firewalls are rare here, and single-machine tools are free** (2.14):
  - About 11 people on HN in 22 months describe running Little Snitch, OpenSnitch or LuLu with an AI tool or local model ([HN Algolia API](https://hn.algolia.com/api)).
  - nono records every session's network events by default and lists them as JSON ([audit.mdx](https://github.com/nolabs-ai/nono/blob/f9f58b77ad/docs/cli/features/audit.mdx)).
  - Greywall and Watch.ly are building "Little Snitch for agents" ([greywall.io](https://greywall.io/), [watch.ly](https://watch.ly/)).
- **The single-point-of-failure objection depends on placement.** It holds for a proxy on the model path; Cowork's allowlist bugs are the example ([#30112](https://github.com/anthropics/claude-code/issues/30112)). It does not hold for a split design that leaves model traffic on a direct OS-level allow rule (2.14).

### 1.3 What a sidecar beside the model server can learn without patches (2.07)

- **Field coverage.** Every field pitch4 names can be obtained without a patch on at least four of the five servers, except a content hash of the loaded weights, which no server serves by default (2.07):
  - Ollama's manifest digest comes closest to a weights hash.
  - SGLang exposes the most over its API, and vLLM the least by default.
  - LM Studio, which is closed source, leaves the chat template, tool-call parser and KV-cache type out of its API.
- **`system_fingerprint` means three different things** (2.07):
  - vLLM: a 32-bit config hash ([fingerprint.py](https://github.com/vllm-project/vllm/blob/8530a778f78dc7cd9a31e108ebc035c4b27ceb3c/vllm/entrypoints/serve/utils/fingerprint.py)) that leaves out the tool-call and reasoning parsers, chat template, tokenizer and loaded LoRA adapters ([config/vllm.py](https://github.com/vllm-project/vllm/blob/8530a778f78dc7cd9a31e108ebc035c4b27ceb3c/vllm/config/vllm.py)).
  - llama.cpp: a build ID.
  - Ollama: the constant `fp_ollama` ([openai.go](https://github.com/ollama/ollama/blob/c1db5f9ef203b2e946161bf4c6bd4f2ec7f123b3/openai/openai.go)).
- **Cost of hashing the weights** (2.07):
  - SHA-256 ran at about 2.27 GB/s on one core of an M1 Max in the note's measurement. A 500 GB checkpoint is therefore about 3.7 CPU-minutes, once per file version.
  - Storage is the real bound. A vLLM user measured about 32 s per restart for a header-only scan on a network filesystem ([vLLM #60944](https://github.com/vllm-project/vllm/issues/60944)).
  - Content-addressed stores, a hash cache keyed by inode, or fs-verity make restarts nearly free.
- **Binding the hash to the running server** (2.07):
  - It needs `/proc` access. In Kubernetes that means `shareProcessNamespace`, which exposes "passwords that were passed as arguments or environment variables" ([Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)).
  - The hash proves what is on disk, not what is in GPU memory.
  - Linking a hash to each request needs a sidecar in the request path, or polling with a race window.
- **Upstream and discovery** (2.07):
  - No maintainer has been asked for a signed manifest. Upstream does accept identity fields; vLLM's fingerprint is the example ([PR #40537](https://github.com/vllm-project/vllm/pull/40537)).
  - OpenCode 2.0 already discovers local models through per-server plugins ([PR #8359](https://github.com/anomalyco/opencode/pull/8359)). A manifest would replace those plugins rather than unblock discovery.

### 1.4 How much coding work runs on open weights, and where (2.11)

- **By people.** Stack Overflow 2026 raw data ([archive](https://github.com/StackExchange/Survey/tree/main/packages/archive/2026)) (2.11):
  - 20.3% of 6,827 agent-model respondents named an open-weight-family vendor for agents; 2.4% named no closed vendor.
  - Among open-harness users the shares are 44.0% and 4.9%.
  - Respondents who used both an open harness and an open-weight-family vendor number 735.
- **By tokens and spend on OpenRouter** (2.11):
  - Open weights rose from 30.6% to 72.7% of weekly tokens between the week of 3 Nov 2025 and the week of 19 Oct 2026 ([open-closed API](https://openrouter.ai/api/frontend/v1/rankings/open-closed)).
  - In coding tasks they carry about 80% of tokens but 33% of spend among the models OpenRouter lists ([task-spend API](https://openrouter.ai/api/frontend/v1/rankings/task-spend)).
- **Where it runs.** No source measures self-hosted coding volume (2.11):
  - The note estimates that 80–90% or more of developer open-weight coding tokens run on third-party hosts.
  - Enterprises with open weights in production mostly run them on infrastructure they control: self-managed cloud 46%, on-premises 42% ([Futurum](https://futurumgroup.com/wp-content/uploads/2026/10/Enterprises-Embrace-Open-Weights-but-Infrastructure-Sellers-Profit-Most_AIONP202610.pdf)).
- **Host disclosure is uneven.** Across 238 endpoints for 12 open coding models, 31% state no quantization and 13% no headquarters. Of 48 GLM 5.3 endpoints, 8 declare that they retain prompts ([OpenRouter endpoints](https://openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints)) (2.11).
- **Named deployments.** Pegatron remains the only named organization running an open harness on self-hosted weights in production. Cline's named enterprise users route to Bedrock, Vertex and Azure ([Cline blog](https://cline.bot/blog/introducing-cline-for-enterprise)) (2.11).

### 1.5 Who already proves what served a model call (2.11, 3.11)

- **Per-request proof is rare.** Only two small attested hosts offer it: Phala, with signed ACI receipts, and NEAR AI, with response signatures. No gateway gives customers per-request cryptographic proof: not OpenRouter, Kilo Gateway, OpenCode Zen and Go, Cline Enterprise, LiteLLM, Coder or Prisma AIRS. Anthropic does not either (3.11).
- **OpenRouter is adding declarations, not proof.** Between 21 Sep and 29 Oct 2026 it added declared ZDR, private endpoints, declared region and declared quantization. It "records it and routes on it, and does not independently verify" these ([OpenRouter docs](https://openrouter.ai/docs/llms-full.txt), [changelog](https://openrouter.ai/docs/changelog)) (3.11).
- **No receipt binds the weights.** ACI defines a `model_weights_provenance` claim, and its reference gateway leaves it "Unknown" ([claims.rs](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/src/aggregator/service/claims.rs)). Tinfoil binds weights per deployment, not per request (3.11).
- **Receipts are short-lived, and only one laptop keeps them** (3.11):
  - The ACI reference gateway keeps receipts for 3,600 s in memory, and they are lost on restart ([conformance gaps](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/docs/reviews/aci-spec-conformance-gaps.md)).
  - Since 28 Sep 2026, Phala's Private AI Proxy and `pap` CLI keep receipts in a local database for Claude Code, Codex, OpenCode, Pi and Hermes ([CHANGELOG](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/apps/desktop/CHANGELOG.md)).
- **A verifier already exists.** teep verifies six attested providers and fails closed, but keeps no receipts ([teep](https://pkg.go.dev/github.com/13rac1/teep)) (2.11, 3.11).
- **Attested hosting is small.** It is about 0.1% of OpenRouter tokens, a figure computed from a Phala claim (2.11).

---

## 2. Directions for pitch4

| # | Direction | Pitch4 pages | Effect | Confidence |
|---|---|---|---|---|
| 1 | Correct the claims that fail a check | 1, 3, 4 | differentiation | high |
| 2 | Lead with mixed fleets; aim each tier at the buyers who fit it | 1, 4, 5, 6 | both | high |
| 3 | Offline and air-gapped single-user operation in the first release, with strict trust hygiene | 1, 6 | differentiation | high |
| 4 | Treat the vault as table stakes; add harness exit and private sharing | 2, 5 | offering | high |
| 5 | Name the open harnesses people use; lead the open side with OpenCode and Pi | 1, 2, 4 | offering | high |
| 6 | Model manifest at the model server, signed per request in the open ACI receipt shape | 2, 3, 4, 6 | both | medium |
| 7 | Widen model access to "only approved inference, wherever it runs" | 3, 4, 6 | offering | medium |
| 8 | Keep every host's receipts under the team's keys; partner rather than build a verifier | 4, 5 | both | medium |
| 9 | Local-only proof as a first-release feature, not the lead | 1, 4, 5, 6 | both | medium |
| 10 | Keep the sidecar off the model path, and state what happens when it fails | 4, 6 | differentiation | medium |
| 11 | Guard the team's inference server: identity, per-agent grants, content-free receipts | 3, 4 | offering | medium |

Taken together, the directions describe one pattern. The free, single-person tools earn adoption from this audience because they can be checked: offline operation, a run report of what left the machine, and the vault. The money is in team-level records across machines and hosts: cross-machine egress records, route policy, an archive of host receipts, and a ledger stamped with the model manifest (2.14, 2.11, 3.11).

### Direction 1. Correct the claims that fail a check

**Change.**
- **Page 1, The problem.** Replace "Local models leave no log. No vendor keeps one." with "Local-model sessions leave no record your team controls." (2.14)
- **Page 4, subtitle.** Replace "With open-weight models, nothing has to leave your control." with a claim that can be checked and is scoped to self-hosting: "Nothing leaves except what your run report lists" (2.14). This holds only when the team runs the model server (2.11).
- **Page 4, "What changes when the model is yours".** The cell "Who sees prompts and code: Only your team" holds only for servers the team runs. Add a column for open weights on a third-party host, where the answer is the host (2.11).
- **Page 4, Model access "Proves" row, and page 3, "What admins can answer" ("down to the weights").** Replace "signs which weights it serves" with 3.11's wording: "For each request, the sidecar beside your model server signs the weight-file digests, quantization and engine that served it. Today no host's per-request receipt names the weights." Add 2.07's qualifiers:
  - digests are computed "once per model version; near-zero per restart", not re-verified per request;
  - the signature attests what the sidecar saw on the host, not what is in GPU memory;
  - LM Studio exposes less than the other servers.
  - Also concede that Tinfoil proves weights per deployment with hardware roots (2.07, 3.11).
- **Before citing OpenCode's title-generation leak as current, check it at runtime.** OpenCode 2's code limits the small model to the same provider, so the September 2026 reports may describe version 1 ([model.ts](https://github.com/anomalyco/opencode/blob/97a71f0cc6/packages/core/src/model.ts)) (2.14).

**Why it helps.** This audience treats open source as "necessary but not enough" and asks to see what leaves the machine (1.01). A reviewer can test each of these lines, and today three of them would fail. Once corrected, they become claims the product can demonstrate.

**Evidence.**
- **"No vendor keeps one" is untrue.** Harnesses report to their vendors even with local models: eight of nine have telemetry clients, and Qwen Code sends usage statistics to Alibaba Cloud RUM by default ([qwen-logger.ts](https://github.com/QwenLM/qwen-code/blob/87c1918a6a/packages/core/src/telemetry/qwen-logger/qwen-logger.ts), [#15478](https://github.com/QwenLM/qwen-code/issues/15478)) (2.14).
- **"Leave no log" is untrue too.** Single-machine tools already keep local logs: nono by default ([audit.mdx](https://github.com/nolabs-ai/nono/blob/f9f58b77ad/docs/cli/features/audit.mdx)), and Greywall and Watch.ly ([greywall.io](https://greywall.io/), [watch.ly](https://watch.ly/)) (2.14).
- **The host sees the code in most open-weight coding.** Most developer open-weight coding runs on third-party hosts (estimated at 80–90% or more), and 8 of 48 GLM 5.3 endpoints retain prompts ([OpenRouter catalog](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=z-ai/glm-5.3-20260816)) (2.11).
- **The weights claim needs qualifiers.** No server serves a content digest of the weights. Binding is by path and inode, and linking a digest to each request needs an in-path position or polling (2.07). No host's per-request receipt binds the weights, while Tinfoil binds them per deployment ([teep, Tinfoil support](https://github.com/13rac1/teep/blob/HEAD/docs/providers/tinfoil/tinfoil_support.md); [claims.rs](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/src/aggregator/service/claims.rs)) (3.11).

**Counter-evidence.**
- The narrower lines read as weaker.
- Page 3 already concedes that "a hosted model sees what the harness sends, unless you run the model" ([pitch4.html](/Users/brien/urnetwork/sidecar/pitch4.html)), so part of this fix is making page 4 consistent with page 3 rather than new information.
- "Nothing leaves except what your run report lists" is only as strong as the local-only feature behind it (direction 9), and direct demand for that report is thin (2.14).

**Cost and risk.** Text only. The risk is losing a vivid anecdote, OpenCode's title leak, if a runtime check shows it is fixed.

**Test.** Before publishing, ask a security reviewer at two or three design partners to check each line against a live run. Run OpenCode 2 against a local model and record whether session titles leave the machine.

**Effect:** differentiation. **Confidence:** high.

### Direction 2. Lead with mixed fleets, and aim each tier at the buyers who fit it

**Change.**
- **Page 4, "Who it's for".** Replace the row "Organizations that run open weights so no vendor reads their code: The best fit … 11% of enterprise LLM spend" with mixed fleets, in 2.11's wording: "one in five agent users already mixes in open-weight models; open weights carry most gateway coding tokens but a third of the spend." Sell one record that covers hosted closed models (observed tier) and open models wherever they run (2.11).
- **Page 1, The problem.** "some on open-weight models they run themselves" becomes: most teams mix closed and open models, on their own servers and on third-party hosts (2.11).
- **Page 5, "Where we start", and page 6, design partners.** Aim each tier at the buyers who fit it (2.11):
  - The self-serve segment skews to small firms, IT services and systems integrators, and Europe, and holds more purchase authority than the base. It fits the free and Team plans.
  - Enterprise buyers of open harnesses are platform and DevX teams and CIOs, and they route to Bedrock, Vertex and Azure. Support those routes as approved routes.
  - Reserve the self-hosted model-server sidecar and the signed tier for defense, EU banks, integrators and manufacturers.
- **Page 6, design-partner table.** The row "Do open-weight teams adopt it, and pay?" becomes a mixed-fleet question: what share of model calls goes over each route type.

**Why it helps.** It removes the "segment is small" objection, because the record no longer depends on the team being open-weight-only. A record that covered only open-weight calls "would miss most of the spend and most of the hard decisions" (2.11).

**Evidence.**
- **Survey shares.** Stack Overflow 2026 raw data: 20.3% use an open-weight family in agents and 2.4% use only that; among open-harness users, 44.0% and 4.9%. The "any" rate by harness is 46–56% ([archive](https://github.com/StackExchange/Survey/tree/main/packages/archive/2026)) (2.11).
- **Gateway tokens and spend.** On OpenRouter, open weights were 70.8% of weekly tokens in the week of 26 Oct 2026; in coding tasks they carry 80% of tokens and 33% of spend among listed models ([open-closed](https://openrouter.ai/api/frontend/v1/rankings/open-closed), [task-spend](https://openrouter.ai/api/frontend/v1/rankings/task-spend)) (2.11).
- **Who the segment is.** Among the 735 respondents in the segment, against the base (2.11):
  - IT services and systems integrators: 21.0% against 16.5%.
  - Freelancers: 11.8% against 7.6%.
  - Germany: 10.2%.
  - Making the final purchase decision: 21.6% against 15.7%.
  - AI use "mostly optional and left up to individuals": 33.2% against 24.9%.
- **Named deployments.** Only Pegatron is named running an open harness on self-hosted weights. Cline's named enterprises use hyperscaler inference ([Cline blog](https://cline.bot/blog/introducing-cline-for-enterprise)). Kilo's comparison page reportedly concedes fully air-gapped deployments to Tabnine (search summary; [kilo.ai](https://kilo.ai/enterprise/vs/tabnine)) (2.11).

**Counter-evidence.**
- **The survey cannot isolate self-hosting.** Vendor is not weights, and weights are not self-hosting: DeepSeek through DeepSeek's API counts the same as a self-hosted DeepSeek. The sample is volunteer, unweighted, and smaller than 2025's (2.11).
- **Gateway data is not market share.** Futurum says gateway data "describes developer behavior rather than market share", and open weights take 5% of enterprise metered AI spend (2.11).
- **Vendors are widening their own records.** A record of hosted closed-model calls is observed-tier only, and it meets the vendors' own records. Anthropic's Compliance API now takes Claude Code transcripts from users' machines (beta from 11 Aug 2026; [release notes](https://platform.claude.com/docs/en/release-notes/overview.md)) (3.11).
- **Origin screens.** China and Russia are over-represented in the segment (3.1% each, against about 1% in the base), so origin screens may apply to part of it (2.11).

**Cost and risk.** Positioning only, so low cost. Covering closed-model calls widens the competition to include the vendors' compliance feeds.

**Test.** At design-partner intake, record each team's model mix. In pilots, measure the share of model calls by route: self-hosted, attested host, declared gateway route, or closed vendor. If self-hosted calls are rare outside defense, EU banks, integrators and manufacturers, sell the signed tier as a premium.

**Effect:** both. **Confidence:** high.

### Direction 3. Ship offline and air-gapped single-user operation in the first release, with strict trust hygiene

**Change.**
- **Page 6, "What ships, in order".** Move "an air-gapped install" from "Last: inbox and assurance" into the first release for single users.
- **Page 6, "Trust documents first".** Add signed, pinned releases; no auto-updating background daemon; no phone-home by default.
- **Page 1, "Open source".** It already says "air-gapped if needed"; page 6 should match it.
- **Design rules from 1.01:**
  - the sidecar works fully offline;
  - capture fails open and is never a required hop for model traffic;
  - hosted parts hold only ciphertext;
  - the vendor stores no long-lived provider keys.

**Why it helps.** These are this audience's stated conditions for adoption, drawn from the year's trust events (1.01). Meeting them in the first release shows the sidecar is not the "cloud stuff" that users cite when leaving OpenCode ([HN 50134766](https://news.ycombinator.com/item?id=50134766)) (1.01).

**Evidence.**
- **Demand for offline and air-gapped use.**
  - OpenCode [#2224](https://github.com/anomalyco/opencode/issues/2224) (48 thumbs-up, 15 people) and [#16117](https://github.com/anomalyco/opencode/issues/16117) (24); Crush [#453](https://github.com/charmbracelet/crush/issues/453) (28) (1.01).
  - Issues with "offline", "air-gapped" or "airgapped" in the title: in OpenCode, 49 issues by 36 authors with 135 reactions ([GitHub search](https://github.com/search?q=repo%3Aanomalyco%2Fopencode+air-gapped+OR+airgapped+OR+offline+in%3Atitle&type=issues)) (2.14).
  - Goose serves air-gapped users with a docs bundle ([#10042](https://github.com/aaif-goose/goose/issues/10042)) (2.14).
- **The trust events behind the bar.**
  - Codex daemon ([HN 50060694](https://news.ycombinator.com/item?id=50060694), 610 points); OpenCode key leak ([HN 50133401](https://news.ycombinator.com/item?id=50133401), 977 points); LiteLLM compromise ([HN 47501426](https://news.ycombinator.com/item?id=47501426), 938 points) (1.01).
  - A second LiteLLM compromise on 21 Oct 2026: "The payload is NOT in the `v1.107.0` git tag; it was injected into the build tree before the wheels were built" ([#47826](https://github.com/BerriAI/litellm/issues/47826)) (3.11). Reproducible builds are designed to catch exactly this.
- **Domain reputation can block a tool.** Several security vendors flagged opencode.ai, so corporate users may be unable to reach it ([#40822](https://github.com/anomalyco/opencode/issues/40822)) (2.14). By inference, a sidecar that depends on no vendor domain avoids this, which matters given URnetwork's own trust gaps.

**Counter-evidence.**
- Offline single users are early adopters and evangelists, not a revenue segment (2.14). The air-gapped buyers with budgets buy through GitLab, Coder or Mistral (2.11).
- Pi and Crush already ship offline modes, so the sidecar running offline is expected, not distinctive. What is distinctive is keeping other harnesses working offline (direction 9).
- Relays, hosted storage and the edge need a network by definition.

**Cost and risk.** Release engineering (reproducible builds, signing, pinned updates) and an offline path for every first-release feature. Low product risk.

**Test.**
- Install the first release on a machine that can reach only the model endpoint, under an OS firewall. It should make no other connection.
- Have an outside party reproduce a release build.
- Count installs among the authors of the offline issues above.

**Effect:** differentiation. **Confidence:** high.

### Direction 4. Treat the vault as table stakes, and add harness exit and private sharing

**Change.**
- **Page 5, "Where we stand, piece by piece".** In the row "Sessions and actions under separate keys … Ours", claim the combination instead: sessions plus the signed action ledger plus governed reach plus model provenance (1.01).
- **Page 2, Session vault card.** Add, from 1.01:
  - full-content search;
  - export that survives compaction;
  - sessions that survive path moves, upgrades and store migrations, by copying them out of the harness's store, append-only;
  - import from retired harnesses (Roo Code, OpenCode share links);
  - sharing that is end-to-end encrypted, revocable, expiring and team-scoped, never public by default.
- **Page 2, stats.** It could cite the open-harness counts in section 1.1 beside its existing figures, labelled as lower bounds from title searches.
- **Page 5, pricing.** Price against Vibivibi ($8 Pro, $15 per member Team), which sits inside the inferred $8–25 Team band (1.01).

**Why it helps.** Session loss, export, search and sharing are the largest session themes (110 to 191 people each, excluding Codex), so the vault is why developers install (1.01). Competitors already sell parts of it, so its credibility comes from what it is attached to.

**Evidence.**
- **Harness stores are fragile** (1.01):
  - moving a project folder loses its history ([#29703](https://github.com/anomalyco/opencode/issues/29703), 27 thumbs-up);
  - upgrades hide sessions ([#49412](https://github.com/anomalyco/opencode/issues/49412));
  - SQLite stores corrupt under concurrent agents ([#14970](https://github.com/anomalyco/opencode/issues/14970), [#56282](https://github.com/anomalyco/opencode/issues/56282));
  - VS Code globalState resets wipe Roo Code's history ([#11994](https://github.com/RooCodeInc/Roo-Code/issues/11994)).
- **Harnesses die or drop features** (1.01): Roo Code shut down ([README](https://github.com/RooCodeInc/Roo-Code)); OpenCode retired sharing ([PR #55716](https://github.com/anomalyco/opencode/pull/55716)); Kilo's shares are public links ([#4540](https://github.com/Kilo-Org/kilocode/discussions/4540)).
- **Competitors:**
  - Vibivibi sells end-to-end encrypted sharing for four harnesses ([vibivibi.com](https://vibivibi.com/)); Skillsync (YC W26, [HN 49743049](https://news.ycombinator.com/item?id=49743049)); Pond ([HN 49376500](https://news.ycombinator.com/item?id=49376500)); cass, SpecStory and memex (1.01).
  - agentsview, a local-first session search tool with 6,322 stars ([agentsview](https://github.com/kenn-io/agentsview)) (2.14).
  - Cline Enterprise copies conversation files to the customer's S3 or R2 bucket ([Prompt Storage](https://docs.cline.bot/enterprise-solutions/monitoring/prompt-storage)) (3.11).

**Counter-evidence.**
- There is no usage or revenue data for Vibivibi, Supafork, Skillsync, Ocean or Pond, and why OpenCode retired sharing is unknown (1.01).
- Single-harness save, resume and export are now built in: Gemini CLI, Qwen Code, Goose, OpenCode (1.01).
- Sync across machines is weak among open-harness users (13 people), and one HN user says a markdown work journal solves it ([HN 49744147](https://news.ycombinator.com/item?id=49744147)) (1.01).
- Levels 2 and 3 did not test this direction.

**Cost and risk.** Importers for each retired format, plus sharing infrastructure. Little differentiation on its own.

**Test.** Use pitch4's own measure, daily use of the vault and restore per developer, plus the number of imports from retired harnesses and paid conversions at Vibivibi-level prices.

**Effect:** offering. **Confidence:** high.

### Direction 5. Name the open harnesses people use; lead the open side with OpenCode and Pi

**Change.**
- **Page 1, The problem, and the harness lists elsewhere.** "from Claude Code and Codex to open-source OpenCode and Goose" becomes a list that leads the open side with OpenCode and Pi, then names Cline, Kilo and Continue, then Crush, Aider, Qwen Code and Gemini CLI (1.01).
- **Goose.** Keep it, recorded like any harness, as pitch4's partner stance toward Block's Buzz requires.
- **Hermes Agent.** Look into it. It is the top coding app by OpenRouter tokens, and Phala's client and Tinfoil's tutorials support it (2.11, 3.11).
- **Page 2.** Use Roo Code's shutdown as proof that "the record must outlive any one harness" (1.01).

**Why it helps.** It matches where open-harness use is, and where local-model users are. Pi has the cleanest offline switch (2.14) and among the highest rates of open-model use (2.11).

**Evidence.**
- **Adoption** (1.01): OpenCode has 223,765 stars and 12.93M npm downloads a month ([GitHub API](https://github.com/anomalyco/opencode); [npm API](https://api.npmjs.org/downloads/point/last-month/opencode-ai)); Pi 119,311 stars; Cline 5.80M VS Code installs; Continue 4.47M; Kilo 1.69M.
- **Survey shares** (2.11): Stack Overflow 2026 coding-agent use is Open Code 14.2%, Cline 4.7%, Pi 4.6%, Continue 4.0%, Kilo Code 3.3%, Aider 2.2%. Use of any open-weight family is Pi 55%, Continue 56%, Kilo 54%, Open Code 48%.
- **Gateway tokens** (2.11): OpenRouter coding apps over 30 days were Hermes Agent 54.0T, Kilo Code 25.0T, pi 16.7T and Cline 13.0T tokens ([apps API](https://openrouter.ai/api/frontend/v1/rankings/apps)).
- **Shared code.** Kilo v2 is built on an OpenCode fork (`packages/opencode` in [kilocode](https://github.com/Kilo-Org/kilocode/blob/dd35e09db9/packages/opencode/src/share/share-next.ts)), so capture built for OpenCode may carry over (2.14).
- **Existing tool support.** Phala's client supports Claude Code, Codex, OpenCode, Pi and Hermes ([CHANGELOG](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/apps/desktop/CHANGELOG.md)); teep lists Aider, Cline and OpenCode ([teep](https://pkg.go.dev/github.com/13rac1/teep)) (3.11, 2.11).

**Counter-evidence.**
- Downloads are not users.
- Pi's download figures conflict between notes: 1.72M a month for `@mariozechner/pi-coding-agent` (1.01) against 17.47M for `@earendil-works/pi-coding-agent`, which is also used as a library (2.14).
- OpenCode is missing from OpenRouter's app data, so that ranking cannot place it (2.11).
- The notes do not say whether Hermes Agent is open source.

**Cost and risk.** A capture adapter per harness, plus upkeep as session stores change, as with OpenCode's V1-to-V2 migration (1.01).

**Test.** At design-partner intake, list the harnesses each team uses. Ship the OpenCode and Pi adapters first, and in pilots measure the share of sessions by harness.

**Effect:** offering. **Confidence:** high.

### Direction 6. Ship a model manifest at the model server, signed per request in the open ACI receipt shape

**Change.** Define what the model-server sidecar captures, publishes and signs.
- **Fields:** weight-file digests; weight and KV-cache quantization; engine version or commit and launch flags; chat-template hash; tool-call and reasoning parsers; LoRA adapters; draft model (2.07).
- **Capture** (2.07):
  - API-only by default; a "host mode" that reads process arguments and binds through `/proc` is opt-in.
  - Digests are computed once per model version. Reuse Hugging Face blob names or Ollama digests where possible, cache by inode, or read fs-verity digests.
  - Strip secrets before signing anything. SGLang's `/server_info`, for example, returns the full launch command.
- **Normalize `system_fingerprint`** across servers (2.07).
- **Receipts.** Emit per-request receipts in the `aci/1` shape. Fill `model_weights_provenance` with `operator_asserted`, or `hardware_proven` under a TEE, so `pap` and teep users can verify self-hosted servers with tools they already run (3.11).
- **Daily use.** Publish the manifest at a GET endpoint any harness can read, and stamp each ledger entry with its digest. Attribution then sits outside the commit, and Assisted-by trailers are generated on request from observed facts, never from the model's self-report (1.01).
- **Upstream asks: fields, not signatures** (2.07):
  - vLLM: parsers, template hash and loaded adapters in a non-dev view.
  - llama.cpp: `general.file_type` and the KV-cache types in `/props`.
  - Ollama: KV-cache type and flash attention in `/api/ps`.
  - LM Studio: the v0 `runtime` block back in the v1 API.
  - Across servers: a convention that `system_fingerprint` is the digest of a published runtime manifest.
- **Pitch4 pages:** page 4, Model access card and "Where open tools already stand" (add a row for served-model identity); page 2, Change set and restore (model and weights per change); page 3, "What admins can answer"; page 6, first-release list.

**Why it helps.** It gives provenance a daily use. The parser, template and `--jinja` state explain tool-call failures, the top class of local-model complaint (1.01, 2.07). It fills a slot in an existing open format instead of inventing one, and 3.11 infers URnetwork would be the first implementation to fill it.

**Evidence.**
- **What each server exposes.** See the 2.07 field-by-server matrix ([vLLM protocol.py](https://github.com/vllm-project/vllm/blob/8530a778f78dc7cd9a31e108ebc035c4b27ceb3c/vllm/entrypoints/serve/engine/protocol.py); [SGLang http_server.py](https://github.com/sgl-project/sglang/blob/0f93be7b654d6a208676d060deb995af5df8f7c1/python/sglang/srt/entrypoints/http_server.py); [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/785322d17f2d51e5185cf996a1f4e46d87640841/tools/server/README.md); [Ollama types.go](https://github.com/ollama/ollama/blob/c1db5f9ef203b2e946161bf4c6bd4f2ec7f123b3/api/types.go); [LM Studio list.md](https://github.com/lmstudio-ai/docs/blob/8c7159be3ffe364af10aa8ae6f5a7570e9402089/1_developer/2_rest/list.md)).
- **Existing identifiers fall short** (2.07):
  - vLLM's fingerprint is a compile-graph key. It leaves out parsers, template, tokenizer and loaded adapters, hashes the model path string rather than the bytes, is 32 bits, and is computed with `usedforsecurity=False` ([config/vllm.py](https://github.com/vllm-project/vllm/blob/8530a778f78dc7cd9a31e108ebc035c4b27ceb3c/vllm/config/vllm.py)).
  - SGLang's served model name is "an API alias, not a robust model/layout identity" ([#24758](https://github.com/sgl-project/sglang/issues/24758)).
- **User demand** (1.01): checkpoint and provenance requests ([#41969](https://github.com/anomalyco/opencode/issues/41969), [#56362](https://github.com/anomalyco/opencode/issues/56362), [#40544](https://github.com/anomalyco/opencode/issues/40544), [HN 49796399](https://news.ycombinator.com/item?id=49796399)); tool calls failing on local models ([#20995](https://github.com/anomalyco/opencode/issues/20995), 48 thumbs-up; [Cline #1418](https://github.com/cline/cline/issues/1418)).
- **The empty slot.** ACI's `model_weights_provenance` "stays Unknown" in the reference gateway ([claims.rs](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/src/aggregator/service/claims.rs); [aci.md](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/spec/aci.md)). NEAR binds compose and image digests, not weights ([image provenance](https://docs.near.ai/cloud/verification/cloud-api/image-provenance.md)) (3.11).
- **No schema covers runtime identity.** models.dev has no quantization, revision or digest field ([README](https://github.com/sst/models.dev/blob/eeda3233fe1df6446c381163c8fcf10910fbd1a4/README.md)), and ModelPack covers static identity only ([config.md](https://github.com/modelpack/model-spec/blob/d7a6481cddb3bd30d646dd5ea5e700171baaeadb/docs/config.md)) (2.07).
- **Attribution in commits is contested** (1.01). Crush adds Assisted-by trailers by default ([README](https://github.com/charmbracelet/crush/blob/main/README.md)), the Linux kernel requires Assisted-by ([kernel docs](https://docs.kernel.org/process/coding-assistants.html)), and users reject forced trailers ([Qwen Code #1379](https://github.com/QwenLM/qwen-code/issues/1379)).

**Counter-evidence.**
- **Discovery is mostly solved.** OpenCode 2.0 already discovers vLLM, LM Studio and Ollama models and needs only tools, vision and context ([PR #8359](https://github.com/anomalyco/opencode/pull/8359); [vllm.ts](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/plugin/provider/vllm.ts)). The manifest "helps but does not 'fix' #6231" (2.07).
- **Maintainer acceptance is unknown.** No maintainer of the five servers or of OpenCode has been asked. OpenCode's maintainers have not answered checkpoint-disclosure requests even for their own Go service ([#41969](https://github.com/anomalyco/opencode/issues/41969)) (2.07).
- **Coverage has holes.** Self-hosters already know their weights (1.01). LM Studio is closed source and leaves out template, parser and KV-cache type, and macOS and Windows were not researched (2.07).
- **The evidence is weaker than hardware proof.** The signature is operator-asserted evidence of what was on disk, weaker than Tinfoil's hardware-rooted proof per deployment. Per-request LoRA scales (llama.cpp) and per-request draft models (LM Studio) are visible only to a sidecar in the request path (2.07, 3.11).
- **Buyers may not need it.** The auditor texts 3.11 cites accept self-produced tamper-evident logs, so signed per-request receipts may be more than buyers need (3.11).

**Cost and risk.**
- Adapters for five servers.
- Hashing takes minutes per model version, slower on network filesystems ([vLLM #60944](https://github.com/vllm-project/vllm/issues/60944)).
- Host mode carries permission and secret-exposure risk ([Kubernetes docs](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)).
- Normalization must keep up as the engines change.

**Test.**
- Build the API-only manifest reader for vLLM, SGLang, llama.cpp and Ollama.
- Open the small upstream field PRs and record the maintainers' responses.
- Ask the OpenCode, Pi and Kilo maintainers whether they would read a manifest endpoint.
- Check that `pap audit` or teep verifies a receipt from a self-hosted server.
- In pilots, count how often developers use the manifest to diagnose a tool-call failure.

**Effect:** both. **Confidence:** medium.

### Direction 7. Widen model access to "only approved inference, wherever it runs"

**Change.**
- **Scope** (page 4, Model access card: "Agents reach the inference servers you run … and nothing else"; page 3, since model access is a way out; page 6, first release). Model access covers self-hosted servers, attested hosts, declared gateway routes and closed vendors.
- **The record.** Every call records host, headquarters, datacenter, declared quantization, retention and ZDR flag, labelled with its evidence tier: observed, declared, signed or attested (2.11, 3.11).
- **Route policy.** Teams set it per repository, for example "this repository's code may reach only our vLLM cluster or attested hosts in the EU at fp8 or better" (2.11) or "only declared-ZDR EU routes for this repo" (3.11). The sidecar enforces it and keeps it on the ledger.
- **Page 3, "What admins can answer".** Add "which host saw this repository's code, and on what evidence".

**Why it helps.** Most open-weight coding tokens go to third-party hosts that disclose unevenly, and no harness records the host per step (2.11, 1.01). Gateways compete on curation and declared privacy, each inside its own service. Nobody offers one record across gateways and harnesses, under team keys (3.11). The fit is best for integrators doing client work, who are over-represented in the segment (2.11).

**Evidence.**
- **Disclosure is uneven** (2.11): 31% of endpoints give no quantization; every sampled endpoint from Together, Fireworks, Bedrock and Google shows quantization "unknown"; 8 of 48 GLM 5.3 endpoints retain prompts ([OpenRouter providers](https://openrouter.ai/api/v1/providers); [model endpoints](https://openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints)).
- **OpenRouter's declarations are unverified.** The fields dated 21 Sep to 29 Oct 2026 work as routing policy and audit-trail entries, and OpenRouter does not verify them ([private endpoints](https://openrouter.ai/docs/guides/routing/private-endpoints); [ZDR](https://openrouter.ai/docs/guides/features/zdr); [changelog](https://openrouter.ai/docs/changelog)) (3.11).
- **Harness gateways stay inside their own service** (3.11): Kilo Gateway's audit log covers seat management only ([Kilo docs](https://kilo.ai/docs/llms.txt)); OpenCode Go blocks endpoints that train on request data and allows only Europe and the US by default ([Go](https://opencode.ai/docs/go/)).
- **Harnesses do not record the model per step** ([OpenCode #40544](https://github.com/anomalyco/opencode/issues/40544); [Kilo #6930](https://github.com/Kilo-Org/kilocode/issues/6930)) (1.01).

**Counter-evidence.**
- **Gateways already enforce route policy in their own scope.** Kilo's org owners control "which models and provider routes" members use, with region and training-data filters. OpenRouter routes on declarations and logs the model and "final provider" for each generation ([Logs](https://openrouter.ai/docs/guides/features/logs)) (3.11).
- **Others sell routing to the team's own gateway.** OpenCode Enterprise sells "use only your internal AI gateway" per seat ([enterprise.mdx](https://github.com/anomalyco/opencode/blob/dev/packages/web/src/content/docs/enterprise.mdx)), and Pi's Radius is building a gateway with organization-level controls ([radius.earendil.com](https://radius.earendil.com/)) (1.01).
- **Private endpoints overlap pitch4.** OpenRouter's private endpoints (28 Sep 2026) overlap "agents reach only your own servers" for teams whose deployments sit in a provider account (3.11).
- **Declared means unverified.** The declared tier is only as good as the host's word, and there is no buyer evidence of willingness to pay for host policy (2.11).

**Cost and risk.** The metadata is cheap to collect (2.11). Enforcing policy on model calls puts the sidecar on that path, which needs the failure design in direction 10. Unlabelled tiers would overclaim.

**Test.** Offer per-repository route policies to the design partners that do client work. Count how many set one, and whether a client or a security review asks for the host record.

**Effect:** offering. **Confidence:** medium.

### Direction 8. Keep every host's receipts under the team's keys; partner rather than build a verifier

**Change.**
- **The archive.** The sidecar fetches each attested host's receipt within the host's window. It stores, in the team-keyed ledger:
  - the receipt;
  - the session and attestation report the receipt cites;
  - hashes of the raw request and response bytes, including SSE framing;
  - links to the agent session, change set and approval.
- **Verification.** Customers can re-verify offline later. Build on the ACI verifiers (`@phala/aci-verifier`, `pap audit`) and teep rather than writing a new verifier (3.11).
- **Tier.** Sell it as a premium tier (2.11).
- **Pitch4 pages.** Page 4, "Where open tools already stand": add a row in 3.11's wording, "Phala's client keeps its own receipts on one laptop. The sidecar keeps every host's receipts, and its own, under the team's keys", with "partner first", as pitch4 already says about Block's Buzz. Also page 5, "Where we stand, piece by piece", and the Assured tier.

**Why it helps.**
- Hosts forget receipts within about an hour, and only one developer's laptop keeps them, for Phala's service only (3.11).
- Gateway logs are "operator-controlled", and gateway processes can be compromised ([#29895](https://github.com/BerriAI/litellm/issues/29895), [#47826](https://github.com/BerriAI/litellm/issues/47826)) (3.11).
- Coding agents stream, and NEAR signs streamed completions at the gateway by default. A gateway signature "binds the response to the gateway, not to a model report" ([NEAR](https://docs.near.ai/cloud/verification/cloud-api/response-signatures.md)) (3.11).

**Evidence.**
- **The spec expects clients to keep receipts.** ACI says "Clients SHOULD fetch receipts promptly", and a receipt is "one self-contained file a client can archive and re-verify offline" ([aci.md](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/spec/aci.md)) (3.11).
- **Hosts keep them briefly.** The reference gateway keeps them 3,600 s in memory ([configuration reference](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/docs/configuration-reference.md)). Phala says audit evidence "can be retained by the customer" ([Phala compliance](https://docs.phala.com/phala-cloud/confidential-ai/confidential-model/compliance-and-open-source)) (3.11).
- **Existing clients keep them locally or not at all.** `pap` keeps receipts in local SQLite, and `usage clear` deletes them ([cli.md](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/apps/desktop/docs/cli.md)). teep never fetches receipts ([capture.go](https://github.com/13rac1/teep/blob/HEAD/internal/capture/capture.go)) (3.11).

**Counter-evidence.**
- **The market is tiny.** Attested hosting is about 0.1% of OpenRouter tokens, computed from a Phala claim (2.11).
- **Demand is vendor-led.** The LiteLLM requests for tamper-evident or served-model records came from three people, two of whom wrote the signing products they propose ([#29895](https://github.com/BerriAI/litellm/issues/29895); [#38383](https://github.com/BerriAI/litellm/issues/38383)) (3.11).
- **Phala may move.** Its plans for team modes in `pap` are unknown (3.11).
- **The watch list could commoditize parts of it** (3.11): OpenRouter filling `required_attestation_types` or relaying receipts ([orca field notes](https://github.com/deankerr/orca/blob/HEAD/docs/openrouter/models.md)); LiteLLM landing #29895; Coder storing responses ([audit](https://coder.com/docs/ai-coder/ai-gateway/audit)); Anthropic's 1 July 2027 target becoming customer-visible ([roadmap](https://www.anthropic.com/responsible-scaling-policy/roadmap)).
- **It needs the request path.** Capture must sit in the request path, which brings back the single-point-of-failure objection (3.11, 2.14).
- **Auditors may not require it.** They may accept self-produced logs (3.11).

**Cost and risk.**
- In-path capture of exact bytes, including SSE.
- A receipt fetcher per host.
- Dependence on Phala's and NEAR's formats.
- teep is AGPL-3.0, with dual licensing "available for commercial use" (2.11).

**Test.** Prototype receipt capture for Phala and NEAR, and verify offline with `pap audit`. Ask Phala whether it would partner on team retention. Ask the auditors of regulated design partners whether host receipts would change what they sample.

**Effect:** both. **Confidence:** medium.

### Direction 9. Make local-only proof a first-release feature, not the lead

**Change.**
- **Egress manifests.** For each harness and version, publish what the harness contacts: the model server, catalogs, binaries and plugins, update checks, telemetry, vendor cloud features, and agent-initiated tools (2.14).
- **Enforcement with stubs.** Enforce "model server only" for local-model setups, and stub what breaks (2.14):
  - pinned catalog snapshots (`OPENCODE_MODELS_PATH`, a catwalk URL override, `PI_OFFLINE`);
  - ripgrep and LSP servers provisioned in advance;
  - a local npm mirror;
  - a local default model.
- **Opt-out verification.** Check that each configured opt-out held, by comparing settings with observed egress (2.14).
- **The run report.** Write a signed "what left this machine" report for each run, listing allowed connections and denied attempts against the manifest for that harness version (2.14).
- **Reuse.** Read nono's JSON audit and srt's violation events instead of rebuilding single-machine capture (2.14).
- **Pricing (page 5, "Who pays").** Single-machine enforcement and reports are free. The cross-machine team ledger, client-facing egress packets and central policy are paid (2.14).
- **Pitch4 pages:** page 1, The problem (a line that harnesses phone home even with local models); page 4, subtitle (the checkable claim in direction 1); page 5, "Who pays"; page 6, first release.

**Why it helps.**
- It turns the privacy promise into something the people most likely to evangelize it can check (2.14).
- The largest harness's maintainers have twice declined a single offline switch, which leaves a role for a harness-independent layer (2.14).
- Settings alone cannot be trusted, since opt-outs failed in at least four harnesses (2.14).

**Evidence.**
- **Host inventory by harness** (2.14): OpenCode ([models-dev.ts](https://github.com/anomalyco/opencode/blob/97a71f0cc6/packages/core/src/models-dev.ts)), Crush ([event.go](https://github.com/charmbracelet/crush/blob/ef4993a390/internal/event/event.go)), Pi ([version-check.ts](https://github.com/earendil-works/pi/blob/b556cfe5b0/packages/coding-agent/src/utils/version-check.ts)), Cline ([posthog-config.ts](https://github.com/cline/cline/blob/a6507a62a1/apps/vscode/src/shared/services/config/posthog-config.ts)), Continue ([load.ts](https://github.com/continuedev/continue/blob/5522c6f44c/core/config/load.ts)), Kilo ([client.ts](https://github.com/Kilo-Org/kilocode/blob/dd35e09db9/packages/kilo-telemetry/src/client.ts)).
- **Opt-out failures** (2.14): [PR #14905](https://github.com/cline/cline/pull/14905), [PR #15201](https://github.com/Kilo-Org/kilocode/pull/15201), [#15478](https://github.com/QwenLM/qwen-code/issues/15478), [#2082](https://github.com/continuedev/continue/issues/2082).
- **Breakage when blocked** (2.14): [#34442](https://github.com/anomalyco/opencode/issues/34442), [#11320](https://github.com/Kilo-Org/kilocode/issues/11320), [#10580](https://github.com/Kilo-Org/kilocode/issues/10580), [#7245](https://github.com/cline/cline/issues/7245).
- **Requests that point at this need** (2.14): documentation of outbound connections for compliance ([#12770](https://github.com/anomalyco/opencode/issues/12770)); a switch "without resorting to OS-level firewall rules or environment-variable guesswork" ([#18233](https://github.com/anomalyco/opencode/issues/18233)).
- **Closed vendors publish lists; open harnesses do not.** Claude Code publishes an 18-host allowlist for security teams ([network-config](https://code.claude.com/docs/en/network-config)), and none of the open harnesses publishes one (2.14).
- **Level-1 privacy complaints** (1.01): [#10416](https://github.com/anomalyco/opencode/issues/10416) (65 thumbs-up), [#5554](https://github.com/anomalyco/opencode/issues/5554), [HN 44841060](https://news.ycombinator.com/item?id=44841060); and "you only see what these harnesses are willing to show you" ([HN 50153072](https://news.ycombinator.com/item?id=50153072)).

**Counter-evidence.**
- **Demand for the report is thin.** No developer or security team was found asking for a per-run egress report for clients, and "egress log" has zero HN hits since January 2025 (2.14).
- **OS-firewall users are few**: about 11 people on HN in 22 months, and LuLu had 17,931 Homebrew installs in a year ([HN Algolia API](https://hn.algolia.com/api); [LuLu cask](https://formulae.brew.sh/api/cask/lulu.json)) (2.14).
- **Single-machine enforce-and-record is free.** nono (4,793 stars), Greywall, srt, LuLu and OpenSnitch cost nothing; Watch.ly charges $6.99 a month for three machines (2.14).
- **Some harnesses already have offline modes.** Pi and Crush offer them.
- **The host list is unverified at runtime.** It came from grepping source, so hosts built at runtime may be missing, and no harness was actually run (2.14).

**Cost and risk.**
- One manifest per harness per version, maintained as nine harnesses ship releases.
- OS-level enforcement on three platforms.
- Stubs that track each harness's catalog and download paths.
- Enforcement per process tree without root, and whether it survives auto-updaters and daemons, are untested (2.14).

**Test.**
- Run each harness against a local model under the sidecar, and compare observed egress with the manifest.
- Release the free single-machine mode to OS-firewall users and count installs.
- With design partners, check whether the report replaces a security-questionnaire answer and whether any client asks for an egress packet.
- Until then, pitch4 should label client-facing reports as a hypothesis (2.14).

**Effect:** both. **Confidence:** medium.

### Direction 10. Keep the sidecar off the model path, and state what happens when it fails

**Change** (page 6, "Risks we manage", the Completeness line; page 4, Model access card).
- **Adopt 2.14's split design:**
  1. Model traffic goes directly to the model server under an OS-level allow rule.
  2. All other egress from the harness's process tree is denied at the kernel or sandbox layer.
  3. The sidecar sets the rules, records denials and writes the report.
  - If the sidecar dies, inference continues, leaks stay blocked, and the next run states the gap (2.14).
- **Failure behavior by location.** Same-host and LAN model servers get the direct allow by default. Remote forwards state their failure behavior: high availability, or a policy that permits a direct fallback (2.14).
- **Receipts that need the request path.** For attested hosts and per-request weight linkage, capture should not block the response. Phala's client says its receipt audits "report after delivery and never block a response" ([CHANGELOG](https://github.com/Dstack-TEE/private-ai-gateway/blob/HEAD/apps/desktop/CHANGELOG.md)) (3.11).

**Why it helps.** It answers the most specific architectural objection this audience raised ([HN 50151130](https://news.ycombinator.com/item?id=50151130)) (1.01, 2.14). In-path egress proxies have broken work; the example is Cowork's allowlist bugs ([#30112](https://github.com/anthropics/claude-code/issues/30112), 59 reactions, 76 comments) (2.14).

**Evidence.**
- **The HN debate split.** OTEL-only advocates argued against proxies. Others argued that "a key place for proxies is resource access where the client is not fully trusted … AI agents seem like a pretty clear case of this" ([HN 50156389](https://news.ycombinator.com/item?id=50156389)) (2.14).
- **Shipped tools make explicit fail-open and fail-closed choices**: Claude Code's `sandbox.failIfUnavailable` ([sandboxing](https://code.claude.com/docs/en/sandboxing)) and LiteLLM's `allow_requests_on_db_unavailable` ([LiteLLM production docs](https://docs.litellm.ai/docs/proxy/prod)) (2.14).

**Counter-evidence.**
- **Some proxy remains.** Domain filtering for non-model traffic still needs a local proxy, because kernel rules cannot see hostnames (2.14).
- **Receipts and per-request linkage need the request path.** Verifiable host receipts need the exact request and response bytes (3.11), and per-request weight linkage needs an in-path sidecar or polling with a race window (2.07). So some in-path component remains.
- **No precedent from the closest vendors.** No agent-egress vendor (nono, Greywall, Watch.ly) publishes what happens when its proxy crashes (2.14).

**Cost and risk.** Enforcement differs by platform: seatbelt, bwrap or a network namespace with nftables, and WFP. Remote forwards need high availability. Enforcement without root on macOS, Linux and Windows is untested (2.14).

**Test.** In pilots, kill the sidecar mid-run. Inference must continue, blocked hosts must stay blocked, and the next run must report the gap. Also measure the latency any in-path receipt capture adds.

**Effect:** differentiation. **Confidence:** medium.

### Direction 11. Guard the team's inference server: identity, per-agent grants, content-free receipts

**Change** (page 4, Model access "Grant" row; page 3, "Easy exposure has already gone wrong").
- **Make the guard role explicit.** The model-server sidecar puts identity in front of Ollama, vLLM and llama.cpp, issues per-agent grants, writes content-free receipts that correlate request IDs, and shows queue position (1.01).
- **Do not add exposure.** It should not widen network exposure of the identity endpoints (2.07).
- **Position against Tailscale.** Stand apart from Tailscale Aperture and LM Link through per-agent grants, receipts and the manifest, and run over Tailscale where possible (1.01).
- **Page 3's exposure box.** It can add the 175,108 exposed Ollama hosts that SentinelLABS and Censys counted. 1.01 saw this figure only in search snippets ([SentinelLABS](https://www.sentinelone.com/labs/silent-brothers-ollama-hosts-form-anonymous-ai-network-beyond-platform-guardrails); [SecurityWeek](https://www.securityweek.com/175000-exposed-ollama-hosts-could-enable-llm-abuse/)).

**Why it helps.** Reach is already solved for individuals, so the model-server value is at team level, where authentication and logs are missing (1.01).

**Evidence.**
- **Missing authentication** (1.01):
  - Ollama has no native authentication ([#1053](https://github.com/ollama/ollama/issues/1053), 75 thumbs-up; [#14003](https://github.com/ollama/ollama/issues/14003)).
  - vLLM's `/invocations` route ignored `--api-key` ([#64391](https://github.com/vllm-project/vllm/issues/64391)).
  - llama.cpp's router does not forward `--api-key` to child instances ([#28820](https://github.com/ggml-org/llama.cpp/issues/28820)).
- **Missing logs** (1.01): users want request-ID correlation without logging content ([vLLM #64654](https://github.com/vllm-project/vllm/issues/64654)), and logging for EU AI Act Article 12 ([vLLM #34947](https://github.com/vllm-project/vllm/issues/34947)).
- **A team's need, in its own words.** One wanted "something simple and secure to not leak data from one session to another" ([Ask HN 47293590](https://news.ycombinator.com/item?id=47293590)) (1.01).
- **Disclosure risk.** SGLang's `/server_info` returns the launch command with only watermark secrets redacted, a risk if the port is reachable ([http_server.py](https://github.com/sgl-project/sglang/blob/0f93be7b654d6a208676d060deb995af5df8f7c1/python/sglang/srt/entrypoints/http_server.py)) (2.07).
- **Gateways are not a safe substitute.** LiteLLM was compromised again in October, and it hides the served model on the endpoint Claude Code uses ([#47826](https://github.com/BerriAI/litellm/issues/47826); [#35246](https://github.com/BerriAI/litellm/issues/35246)) (3.11).

**Counter-evidence.**
- **Tailscale and LiteLLM cover much of this** (1.01):
  - Aperture logs each request "with the identity of the caller, the model called, the provider, the timestamp, and the token count" and proxies self-hosted LLMs ([Aperture](https://tailscale.com/aperture)).
  - LM Link shares GPU-backed models across machines ([LM Link](https://tailscale.com/blog/lm-link-remote-llm-access)).
  - LiteLLM issues virtual keys ([HN 50147059](https://news.ycombinator.com/item?id=50147059)).
- **OpenRouter routes to team-operated deployments** through its private endpoints (3.11).
- **Levels 2 and 3 did not test this direction.** Level 1's question about what teams sharing a GPU server use, and would pay for, was not pursued. Level 1 also found no first-person report of a cloud agent reaching a self-hosted model (1.01).

**Cost and risk.** The guard sits in front of the model server, so it needs the failure design in direction 10, and it competes with free gateways.

**Test.** Interview teams that share a GPU server about identity, quotas and logs. In pilots, count agents granted per model and how often receipts are read.

**Effect:** offering. **Confidence:** medium.

---

## 3. How the deeper levels changed or qualified the level-1 findings

| Level-1 finding or direction (level-1 confidence) | What levels 2 and 3 found | Net effect |
|---|---|---|
| Local-only proof and a "what left this machine" report (medium) | 2.14 confirmed the premise from source: all nine harnesses contact other hosts by default, and opt-outs failed in at least four. But blocking breaks harnesses unless their downloads and catalogs are stubbed, OS-firewall users are few (about 11 on HN in 22 months), single-machine enforce-and-record is free (nono, Greywall, srt), and direct demand for a report is thin. | **Narrowed.** A first-release feature, not the lead. The difference shifts to per-harness manifests, stubs, opt-out verification, and a team-readable record across machines. |
| OpenCode sends session titles to a cloud model (evidence) | 2.14: OpenCode 2's code limits the small model to the same provider; the HN reports probably describe version 1. | **Corrected.** Check at runtime before pitch4 cites it. |
| Signed model manifest that also fixes discovery (medium) | 2.07: the fields can be recovered without patches; the weights digest needs one-time hashing; LM Studio is weakest; macOS and Windows are unresearched. OpenCode 2.0 already discovers models through per-server plugins. Ask upstream for fields, not signatures. 3.11: no per-request receipt binds weights anywhere, and ACI has an empty slot for it. | **Provenance half strengthened** and made exact: an ACI-compatible receipt with an `operator_asserted` weights claim. **Discovery half weakened.** |
| "Signs which weights it serves": demand is strongest where users do not control serving (inference) | 2.11: that describes most developer open-weight coding (estimated at 80–90% or more on third-party hosts), where no model-server sidecar can be installed. 3.11: gateways offer declarations, not proofs; attested hosts are about 0.1% of volume. | **Re-scoped.** Hosted open weights need a declared tier and a receipt archive (directions 7 and 8). Self-hosted signing serves the enterprise minority (direction 6). |
| "Best fit" segment unsized beyond Menlo's 11% (gap) | 2.11 sized it: 20.3% of agent users use an open-weight family, 2.4% use only that; open-harness users 44.0% and 4.9%; the segment is 735 people; Pegatron is the only named self-hosted deployment. | **Answered.** Open-weight-only teams are about 2–5% of agent users; mixed fleets are the market (direction 2). |
| "Nobody can show which weights or quantization served a request" (takeaway) | 2.11 and 3.11: Phala issues signed receipts and NEAR signs responses; Tinfoil binds weights per deployment; teep verifies six providers; Phala's `pap` keeps receipts locally since 28 Sep 2026. | **Narrowed.** What remains open is per-request weights binding, and retention across hosts under team keys, linked to sessions. |
| The in-path proxy as a single point of failure (rejection risk) | 2.14: a split design answers it for egress enforcement, but the model-access forward stays in path for remote servers. 2.07: linking weights to each request needs an in-path sidecar or polling. 3.11: verifiable host receipts need exact bytes captured in path. | **Partly answered, with a new tension.** Enforcement can stay out of the model path; receipts and per-request linkage cannot (direction 10). |
| Supply-chain bar set by LiteLLM's March compromise | 3.11 and 2.14: a second compromise (1.107.0, 21 Oct 2026), with the payload injected into the build tree and absent from the git tag. | **Strengthened.** Reproducible builds and signed, pinned releases belong in the first release (direction 3). |
| Offline single-user mode in the first release (high) | 2.14: offline use needs stubs, not just blocking; Pi and Crush accepted offline modes; OpenCode declined a single switch twice. | **Strengthened** and made concrete. |
| Harness coverage led by OpenCode and Pi (high) | 2.11: Stack Overflow shares and OpenRouter app tokens (Hermes Agent first; OpenCode missing from the data). 2.14: Pi's single offline switch; Kilo v2 built on an OpenCode fork. 3.11: the client lists of `pap` and teep. | **Strengthened.** Adds Hermes Agent as a candidate. Pi's download figures conflict between notes. |
| Inference-server guard for teams (medium) | Not tested deeper. 3.11 adds OpenRouter's private endpoints as overlap, and LiteLLM's second compromise and served-model gap. 2.07 adds SGLang's disclosure risk. | **Unchanged.** More competition, and more reason not to trust gateways. |
| Vault as table stakes, plus harness exit (high) | Not tested deeper. 2.14 adds agentsview; 3.11 adds Cline's prompt storage to the customer's bucket. | **Unchanged**, and slightly more crowded. |
| Attribution recorded outside the commit (medium) | Not tested deeper. 2.07 supplies the observed facts (the manifest digest) to stamp on each change. | **Unchanged**, now with a concrete data source (folded into direction 6). |
| Audit and approval demand is thin (19 people, 0 votes) | 2.14: no one asks for per-run egress reports for clients. 3.11: the LiteLLM requests for signed records were vendor-led. | **Consistent.** Record and proof features are bought, if at all, by admins and security buyers. Willingness to pay is still untested. |

Across levels the emphasis moved. Level 1 led with local-only proof and a signed manifest as the open-weight user's reasons to adopt. Levels 2 and 3 kept both but changed what makes them distinctive:
- for local-only proof, verification and stubs across harnesses rather than blocking, which free tools already do (2.14);
- for the manifest, an exact claim inside an existing receipt format rather than a new signing scheme (2.07, 3.11);
- for the market, a record that covers mixed fleets and third-party hosts rather than open-weight-only teams (2.11).

The deeper levels also surfaced one architectural tension that pitch4 has to resolve. Egress enforcement works best off the model path, while verifiable receipts and per-request weight linkage need to sit on it (2.14, 2.07, 3.11).

---

## 4. What remains open

- **Willingness to pay** is untested for local-only proof, the model manifest, host-route policy and the cross-host receipt archive. Every note in the branch flags it (1.01, 2.11, 2.14, 3.11).
- **Maintainer acceptance is unknown:**
  - whether harness maintainers (OpenCode, Pi, Kilo) would read a manifest endpoint or cooperate on egress manifests (1.01, 2.07, 2.14);
  - whether vLLM, SGLang, llama.cpp and Ollama would add identity fields, given that none has been asked and LM Studio is closed source (2.07);
  - whether ACI's maintainers would accept `operator_asserted` weights claims from servers without a TEE in verifiers' default policies (3.11).
- **Self-hosted coding volume is unmeasured.** Stack Overflow has no deployment-mode question and OpenRouter sees only hosted traffic. Beyond Pegatron, no named company runs an open harness on self-hosted weights in production (2.11).
- **Platform reach is unresearched:**
  - capture at the model server on macOS and Windows, which have no `/proc`, although LM Studio and Ollama are common on Macs (2.07);
  - whether vLLM and SGLang keep weight files memory-mapped, which decides whether `/proc` binding works (2.07);
  - enforcement per harness process tree without root on macOS, Linux and Windows, and whether it survives auto-updaters and daemons (2.14).
- **Nothing was run.** The harness egress inventory and the server field matrix come from source and docs. Runtime-built hosts, OpenCode 2's title behavior, and the cause of Cline's reported failure when blocked are unconfirmed (2.07, 2.14).
- **Host retention and plans are unpublished:** Phala's production receipt retention and any team modes for `pap`; NEAR's signature window; OpenRouter's log retention; whether OpenRouter passes upstream receipt headers (3.11).
- **Watch list.** Any of these would commoditize verification and shrink direction 8 to collection and retention (3.11):
  - OpenRouter populating `required_attestation_types` or relaying receipts;
  - LiteLLM landing #29895 or asqav;
  - Coder storing responses;
  - Anthropic's 1 July 2027 target becoming customer-visible.
- **Auditor requirements.** It is unknown whether auditors need per-request host receipts or accept self-produced tamper-evident logs. The texts 3.11 cites (AIUC-1 E015.4; HITRUST "version of the model used") suggest the latter, which would make host receipts a premium need (3.11).
- **Client-facing egress reports** are a hypothesis with no observed request; test them with design partners (2.14).
- **Level-1 questions this branch did not pursue** (1.01; [L1-results.json](L1-results.json)):
  - session-sharing traction (Vibivibi, Supafork, Skillsync, Ocean, Pond) and why OpenCode retired `/share`;
  - each open harness's capture surface for sessions, permission decisions, edits and model IDs;
  - what teams sharing a GPU server use for identity, quotas and logs, and whether cloud agents need to reach private model servers (no first-person evidence found).
- **Reddit was not reached** in either 1.01 or 2.14, so r/LocalLLaMA voices are missing.
- **Conflicts to reconcile:**
  - Pi's npm downloads: 1.72M a month for `@mariozechner/pi-coding-agent` (1.01) against 17.47M for `@earendil-works/pi-coding-agent` (2.14).
  - Tailscale Aperture's status: 1.01 quotes its page as having "no published pricing during the current Alpha and Beta period", while the earlier `market2.md` dates its general availability to 26 August 2026.
- **Hermes Agent.** The notes show it is the top coding app by OpenRouter tokens and is supported by Phala's client and Tinfoil's tutorials, but not whether it is open source or fits pitch4's harness definition (2.11, 3.11).
