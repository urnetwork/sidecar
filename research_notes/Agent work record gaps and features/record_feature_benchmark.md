# Agent work record tools: feature benchmark and gaps (state as of 31 October 2026)

## 1. What each tool records, where the record lives, who can read it, and its integrity, harness coverage, export, lifecycle, price and traction

### Takeaway
Every tool records some mix of prompts, tool calls, and model, token and cost metadata. The records fall into five silos:
1. Harness-local transcripts and telemetry (Claude Code, Codex, Copilot CLI, Cursor): plaintext, and each covers one harness.
2. Vendor-held compliance and audit feeds (Anthropic, OpenAI, GitHub, Cursor, Amp): these see only what reaches the vendor.
3. Git- or file-stored provenance (Entire, git-ai, Agent Trace, SpecStory, AgentFS): anyone with access to the repo or file can read it.
4. Gateways (Aperture, Coder, Cloudflare) and observability backends (Langfuse, LangSmith, Braintrust, Arize, Datadog and others): these see LLM and MCP traffic, or whatever hooks export.
5. Security-vendor verdict logs held in vendor SaaS.

No agent-work record is vendor-blind or verifiable by a third party. The only signed Merkle log in the set, Anthropic's Access Transparency log, records Anthropic staff access to customer content, not agent work.

### Cited Findings

#### Method and source notes
- **Date and sources.** Researched on 31 Oct 2026 in six parallel threads (provenance; Claude Code; Codex and Cursor; GitHub and Amp; observability; security vendors) plus direct research on the gateways and on signed-record projects. GitHub star counts and release dates come from the GitHub API on 31 Oct 2026.
- **Labels.** "(search summary)" or "(search excerpt)" marks a fact taken from a search-result digest when the page itself was not opened. "(vendor claim)", "(press)", "(analyst)" and "(third-party)" label the source type. Failed pages are listed under Gaps.
- **Scope of the earlier rounds.** They described Entire, git-ai, Agent Trace, AgentFS, the Compliance API, GitHub's control plane, Cursor's audit log, Aperture, Coder and Cloudflare portals. This round adds feature-level detail and corrects several earlier points:
  - Entire has removed file rewind.
  - Cloudflare's "prompt activity" means MCP prompt-template names, not user prompts.
  - Aperture's six-user free tier is unconfirmed.
  - git-ai's team has joined OpenAI.


#### Feature matrix
Legend: ● documented, ◐ partial / opt-in / limited, ○ not offered or not documented, ? unclear in the sources read. Each cell summarises a sourced finding in the per-tool notes below. Rows are features where a vendor ships several record surfaces.

**Matrix 1. What each tool records**

| Tool / feature | Prompts | Responses | Tool calls | Shell cmds | File diffs | Network reach | Approvals / denials | Model, tokens, cost |
|---|---|---|---|---|---|---|---|---|
| Entire checkpoints + forge | ● | ● | ● | ● | ● files touched, line attribution | ○ (PII pass strips IPs) | ○ | ◐ tokens; no model field shown |
| git-ai notes / Teams | ◐ local SQLite or Teams store | ◐ Teams | ◐ Teams | ◐ bash-written lines attributed | ● line attribution | ○ | ○ | ● model; Teams cost per PR |
| Agent Trace (spec) | ○ conversation URL only | ○ | ○ | ○ | ● line ranges + content_hash | ○ | ○ | ◐ model_id |
| SpecStory | ● | ● | ◐ truncated for some agents | ● | ◐ | ○ | ○ | ? |
| Turso AgentFS | ○ | ○ | ● name, params, result | ? | ● overlay diff | ○ | ○ | ◐ optional extension |
| Tapes (proxy) | ● | ● | ◐ as seen by the LLM | ○ | ○ | ○ | ○ | ● |
| Claude Code checkpoints | ○ | ○ | ○ | ○ (Bash edits untracked) | ● edit-tool files only | ○ | ○ | ○ |
| Claude Code session JSONL | ● | ● | ● | ● | ● via tool results | ○ | ? format undocumented | ◐ request params |
| Claude Code OTel | ◐ redacted by default | ◐ opt-in | ◐ opt-in | ◐ opt-in `bash_command` | ○ (line counts) | ◐ refusal counts only; event withdrawn v2.1.312 | ● `tool_decision` with source | ● |
| Claude Code hooks | ● | ◐ via transcript_path | ● | ● | ● tool_input | ○ | ◐ PermissionRequest/Denied; no event for the human answer | ○ |
| Claude Code Analytics API | ○ | ○ | ◐ counts | ○ | ◐ line counts | ○ | ◐ accept/reject counts | ● |
| Anthropic Compliance API | ● | ● | ● truncated 10 KB | ◐ as API-visible tool calls | ◐ | ○ | ○ | ? |
| Claude Code cloud sessions | ● | ● | ● | ● | ● | ◐ proxy audit, vendor-only | ? | ? |
| Codex rollouts (local) | ● | ● | ● | ● (64 KiB cap) | ◐ TurnDiff not persisted | ○ | ○ approvals "transient" | ● tokens |
| Codex OTel + network proxy | ◐ length only by default | ◐ | ◐ output snippet | ◐ | ○ | ● host, port, allow/deny/ask (managed runtime) | ● `tool_decision` | ● |
| Codex hooks | ● | ◐ | ● | ● | ● apply_patch | ○ | ◐ PermissionRequest | ● model field |
| OpenAI Compliance Logs (`codex_log`) | ● | ● | ● args + results | ? | ? | ○ | ? | ● tokens |
| Cursor checkpoints | ○ | ○ | ○ | ○ | ● | ○ | ○ | ○ |
| Cursor hooks | ● | ● afterAgentResponse | ● | ● | ● old/new strings | ◐ MCP server URL | ◐ allow/deny/ask outputs | ● model field |
| Cursor Enterprise audit log | ○ | ○ | ○ | ○ | ○ | ◐ admin IPs only | ○ | ○ (admin changes only) |
| Cursor OTel export | ◐ cloud agents only, opt-in | ◐ | ◐ cloud tool I/O | ◐ cloud | ◐ | ◐ Grok Bot browsing metadata | ○ | ● |
| Cursor AI Code Tracking / Blame | ○ | ○ | ○ | ○ | ● AI lines per commit | ○ | ○ | ● model |
| Cursor shared transcripts / cloud agents | ● | ● | ● | ● | ● | ○ allowlist only | ○ | ? |
| GitHub cloud-agent session logs | ● | ● | ● | ● | ● | ◐ blocked requests only | ○ | ◐ tokens |
| GitHub audit log + session streaming | ● (preview) | ● | ● | ? | ? | ○ | ○ | ? |
| GitHub Copilot usage metrics | ○ | ○ | ○ | ○ | ◐ line counts | ○ | ◐ acceptance rate | ● model breakdown |
| Copilot CLI local sessions | ● | ● | ◐ | ? | ? | ○ | ○ | ? |
| Amp threads | ● | ● | ● | ● | ● | ○ | ? | ● |
| Tailscale Aperture | ● full bodies | ● | ◐ parsed from LLM bodies | ◐ | ○ | ◐ LLM traffic only; connectors not recorded | ○ | ● |
| Coder AI Gateway + Agent Firewall | ◐ last prompt only | ○ discarded | ◐ requests only | ◐ | ○ | ● method, URL, allow/deny (HTTP, Coder workspaces) | ◐ firewall policy decisions | ● |
| Cloudflare MCP portals | ○ | ○ | ◐ tool name only | ○ | ○ | ◐ ClientIP, ServerURL | ◐ success/error | ○ |
| Cloudflare AI Gateway | ● default on | ● | ◐ inside bodies | ○ | ○ | ○ | ◐ DLP FLAG/BLOCK | ● |
| LangSmith plugin (hooks) | ● | ● | ? | ? | ◐ file contents | ○ | ○ | ? |
| Langfuse (Stop-hook shipper) | ● | ● | ● tool I/O | ● Tool: Bash | ? | ○ | ○ | ● model, tokens |
| Braintrust plugin / OTLP | ● | ● | ● | ◐ | ? | ○ | ◐ "approval state" on tool spans | ● |
| Arize Phoenix / AX plugins | ● on by default | ● | ● | ● | ◐ Edit tool | ○ | ○ | ● |
| AgentOps | ○ no coding-agent integration | ○ | ○ | ○ | ○ | ○ | ○ | ○ |
| Laminar plugins | ● | ● | ● | ? | ? | ○ | ○ | ◐ SDK path |
| Datadog Agent Console | ◐ via Claude Code OTel logs | ○ | ○ | ○ | ◐ lines, commits | ○ | ○ | ● spend |
| Honeycomb / Grafana (native OTel) | ◐ as exported | ◐ | ◐ | ◐ | ○ | ○ | ◐ if exported | ● |
| Opik | ● plugin, full content | ● | ● | ? | ? | ◐ local proxy and network extension, metadata only | ○ | ● |
| Lasso | ? | ? | ● inspected | ? | ? | ○ | ◐ block verdicts | ? |
| Zenity | ● | ? | ● | ● | ◐ "code it touches" | ○ | ◐ block/modify | ? |
| Noma (Claude Code plugin) | ● | ? | ● shell, MCP, file reads | ● | ? | ○ | ◐ allow/block events | ? |
| Prompt Security (SentinelOne) | ● | ? | ◐ | ? | ? | ○ | ◐ | ? |
| Pillar | ◐ context window | ? | ● | ● sequences | ◐ file access | ◐ "network communications" (vendor claim) | ◐ | ? |
| Cato (Aim) | ● | ● | ● | ? | ? | ○ | ◐ policy | ? |
| Palo Alto Prisma AIRS + Cortex AES | ● | ● | ◐ MCP, WebFetch/WebSearch | ○ | ○ | ◐ web tools only | ◐ verdicts | ? |
| CrowdStrike AIDR / Guardian | ● | ○ excluded | ● | ● via tool calls | ? | ◐ Windows inspection of AI apps | ◐ block | ○ excluded |
| Microsoft Defender for Endpoint | ? | ? | ◐ runtime subset | ? | ? | ◐ LLM inference traffic only | ◐ audit/block | ? |
| Obsigna / Agent Receipts (OSS) | ○ | ○ | ● each call signed; params hashed | ◐ | ○ | ○ | ◐ names the authorizing human | ○ |

**Matrix 2. Where it lives, who reads it, integrity, coverage, export**

| Tool / feature | Storage | Readers | Tamper-evident? | Harnesses | Export / standards |
|---|---|---|---|---|---|
| Entire | git refs in repo; Entire forge clusters | anyone with repo access; public if repo public | ◐ best-effort GPG/SSH-signed checkpoint commits | 8 (Claude Code, Codex, Cursor, Copilot CLI, OpenCode, Antigravity, Droid, Pi) | JSON/JSONL in git; no OTel, no Agent Trace |
| git-ai | git notes; local SQLite; Teams cloud or self-host | repo members (notes); Teams store write-only | ○ | ~10 agents + background agents | git notes, stats JSON |
| Agent Trace | storage-agnostic | n/a | ○ (hash for tracking only) | VT Code verified; partners unverified | JSON record format, CC BY 4.0 |
| SpecStory | local markdown; optional cloud sync | user; public links | ○ | 13+ (broadest found) | markdown, cloud API |
| Turso AgentFS | local SQLite; optional Turso sync | file holder | ○ ("insert-only" rule only) | `agentfs run` wraps any program | SQL, timeline JSON |
| Claude Code local (checkpoints, JSONL) | local plaintext | OS user | ○ | Claude Code only | `/export` text |
| Claude Code OTel / hooks | customer collector or hook target | customer | ○ | Claude Code only | OTLP; partial GenAI semconv (`gen_ai.*` attributes) |
| Anthropic Compliance API | Anthropic cloud | Enterprise compliance key holders | ○ (staff-access log only: ● signed Merkle) | Anthropic surfaces, API-visible only | REST pull; 100+ partner integrations (vendor claim) |
| Codex local (rollouts, OTel, hooks) | local JSONL; customer collector | OS user; customer | ○ | Codex only | JSONL; OTLP with `codex.*` names |
| OpenAI Compliance Logs | OpenAI cloud | compliance admins | ○ | Codex activity reaching OpenAI | log files via API; Elastic integration |
| Cursor hooks / audit / OTel | customer targets; Cursor cloud (audit) | customer; Enterprise admins | ○ | Cursor only | JSON hooks; CSV/API; Splunk, Sumo, webhook, S3; OTLP `cursor.*` |
| Cursor shared transcripts | Cursor AWS | team or anyone with link | ○ | Cursor | links |
| GitHub agent logs / audit / streaming | GitHub cloud; customer SIEM | repo readers; AI admins | ○ ("Verified" commits link to logs) | Copilot surfaces; Claude/Codex on GitHub cloud | 7 streaming targets, compressed JSON; NDJSON metrics |
| Copilot CLI local | local plus optional sync | user (private by default) | ○ | Copilot CLI/app | md, html, gist |
| Amp | GCP US multi-tenant | workspace or group members; admins (passkey, logged) | ○ | Amp clients only | md/JSON export, API |
| Tailscale Aperture | Tailscale-managed gateway node; S3 export | admins; users see their own | ○ | any base-URL-configurable agent | S3; hooks (Cerbos, Oso, Highflame) |
| Coder AI Gateway + Firewall | self-hosted Coder DB | owner/auditor (unofficial source) | ○ | 11+ clients; not Cursor, Amp, Gemini CLI | Prometheus, OTLP traces, structured logs, REST |
| Cloudflare portals / AI Gateway | Cloudflare | account admins | ○ | any remote-MCP client; any base-URL client | Logpush (Enterprise for portals); RSA-encrypted Logpush for AI Gateway |
| LangSmith | LangChain cloud US/EU; hybrid or self-host (Enterprise) | workspace; public links | ○ | Claude Code, Cursor, Codex plugins | no export documented on plugin page |
| Langfuse | cloud (EU, US, JP, HIPAA) or MIT self-host | project members; public links | ○ | Claude Code, Codex, Copilot, Cursor, Kiro, OpenCode, Augment | OTLP ingest; webhooks |
| Braintrust | US/EU or self-hosted data plane | org members | ○ | Claude Code, Codex, Cursor, OpenCode, SDKs | OTLP mapping of Claude spans; MCP server |
| Arize Phoenix / AX | self-host (ELv2) or cloud | project users | ○ | Claude Code, Codex, Copilot, Gemini CLI, Cursor | OpenInference (OTel-based) |
| Laminar | cloud or self-host | org | ○ | Claude Code, Codex, OpenCode, Pi | ? |
| Datadog Agent Console | Datadog SaaS | Datadog users | ○ | broadest roster (plus Trajectory for others) | OTLP; GenAI semconv (search snippet) |
| Honeycomb / Grafana | SaaS | team or stack users | ○ | Claude Code | OTLP |
| Opik | cloud or self-host | org; shared sessions | ○ | Claude Code, Copilot, Codex, Cursor | OTel; plugin |
| Security vendors (Lasso … Defender) | vendor SaaS consoles; Defender XDR | security team | ○ (none documented) | 1–6 named harnesses; Defender discovers ~60 | SIEM (CrowdStrike NG-SIEM, Defender KQL); mostly undocumented |
| Obsigna (OSS) | local receipt DB | operator | ● Ed25519, hash-chained | Claude Code hook; MCP proxy for Claude Desktop, Claude Code, Codex | W3C VC receipts |

**Matrix 3. Lifecycle and use**

| Tool / feature | Retention / deletion | Redaction | Search | Replay / rewind | Sharing | Alerting | Price | Traction (dated) |
|---|---|---|---|---|---|---|---|---|
| Entire | delete "is not a full purge" | ● 7 secret passes; opt-in PII | ● semantic + keyword | ○ file rewind removed; log resume | repo access | ◐ Trails watch | free tier + per-token | 5,282★; forge GA 26 Oct 2026; $60M seed (Feb 2026) |
| git-ai | ? | ◐ Teams best-effort | ◐ blame/stats | ○ | Teams dashboards | ○ | OSS free; Teams by demo | 2,917★; team joined OpenAI 11 Sep 2026 |
| SpecStory | soft-delete local; cloud ? | ● Betterleaks default | ● | ◐ cross-agent resume | ● public link, exchange-level | ○ | free; Pro $25 (aggregator) | 1,365★; 233,573 installs (vendor badge) |
| Turso AgentFS | manual archival | ○ | ◐ timeline | ◐ overlay diff | ○ | ○ | OSS | 3,500★; no release since Mar 2026 |
| Claude Code local | 30 days (`cleanupPeriodDays`) | ○ local | ◐ history | ● rewind (edit tools) | ○ (`/share` sends to Anthropic, kept 5 yrs) | ○ | all plans | Claude Code run-rate >$2.5B (Feb 2026, vendor) |
| Claude Code OTel/hooks | customer | ● prompts redacted by default | customer SIEM | ○ | ○ | customer | all plans | — |
| Anthropic Compliance API | 6 yrs (custom; HIPAA 30 days); read-only | ○ "Nothing masks" | time filters | ○ | ○ | ○ | Enterprise | 100+ partners (vendor) |
| Codex local | history cap; rollouts until deleted | ○ (OTel prompt off by default) | ◐ local index | ◐ resume, fork, rollback | ○ | ○ | all plans | 132,467★ |
| OpenAI Compliance Logs | up to 30 days | ○ | SIEM | ○ | ○ | SIEM | Enterprise/Edu | 3–4M weekly users (Apr 2026, third-party) |
| Cursor | cloud history indefinite (Ent 90-day option); audit API 30-day window | ◐ best-effort secrets | ◐ | ◐ checkpoints (local) | ● team or public links (50/day) | SIEM | Teams $30+/user; Enterprise | SpaceX deal ~$60B agreed 16 Jun 2026 (press) |
| GitHub | cloud sessions archive-only; audit 180 days; streaming buffered 7 days | ○ (1 MB truncation) | ◐ actor filter; CLI /chronicle | ○ | repo access; `/share` | SIEM | Pro $10 to Max $100; EMU for streaming | 4.7M paid subs (Jan 2026, press) |
| Amp | delete within 30 days; Enterprise kept to contract end | ● `[REDACTED:amp]` best-effort | ● feed + CLI | ○ | workspace, group, unlisted link | ○ | free BYOK; $20/mo; Teams no extra charge | spun out 2 Dec 2025; "profitable" (vendor) |
| Tailscale Aperture | configurable; zero-retention mode | ◐ auth headers only | ◐ by session/user | ○ | ○ | ○ | unpublished (sales/self-serve) | GA blog 26 Aug 2026 |
| Coder | 60 days default; 0 = forever | ◐ `disable_content_recording` | ● prompt, tool, destination search | ○ | ○ | Prometheus | Premium (AI Governance) | GA 3 Feb 2026 |
| Cloudflare | Workers Logs plan-based; legacy 10M logs per gateway | ◐ DLP masks; payload logs encrypted to customer key | ◐ | ○ | ○ | ◐ DLP block | Logpush on Enterprise (portals) | portals GA 24 Sep 2026 |
| LangSmith | base traces 14 days | ● local secret redaction (a "safety net") | ● | ◐ thread view | ● public links (admins can disable) | ? | Plus $39/seat + ~$5/1k traces | plugin 73★; $125M Series B (Oct 2025, press) |
| Langfuse | 30 days (Hobby), 90 (Core), 3 yrs (top) | ○ for Claude Code integration | ● | ◐ sessions | ● public links | ◐ webhooks and Slack | Core $29/mo | 36,806★; ClickHouse acquisition 16 Jan 2026 |
| Braintrust | 14 days (Starter); 30–180 days (Pro); per-project (Enterprise) | ◐ SDK masking | ● | ◐ span tree | ? | ? | Pro $249/mo | $80M Series B 17 Feb 2026 (press) |
| Arize | 15 days (Free), 30 (Pro) | ○ content on by default | ● | ◐ | ? | ? | AX Pro $50/mo | Phoenix 12,083★ |
| Laminar | 7 days / 30 days / 6 months | ? | ? | ◐ | ? | ? | $30 / $150 per mo | 3,465★ |
| Datadog | ? | ? | ● | ○ | ○ | ● cost alerts | ? (14-day trial) | — |
| Honeycomb / Grafana | 60 days (Honeycomb); 14 days free, 30 days logs paid (Grafana) | ? | ● | ○ | ? | ? | Honeycomb Pro from $150 per 50M events | — |
| Opik | ? | ◐ content capture can be pinned off | ● | ◐ | ● share a session | ? | ? | 23,068★ |
| Security vendors | mostly undocumented | ◐ DLP masking (Prisma, Noma, Prompt) | ◐ "searchable audit log" | ○ | ○ | ● real-time block/alert | contact sales | M&A: PANW–Protect AI $634.5M; S1–Prompt ~$133.6M cash + stock; CrowdStrike–Pangea $212.1M; Zenity $125M C (Aug 2026); Lasso $30M (Sep 2026) |
| Obsigna (OSS) | local | ◐ params hashed | CLI | ○ | ○ | ○ | free | 20★ (created 2 Apr 2026) |


#### Session and provenance tools
Star counts and release dates come from the GitHub API and were checked 31 Oct 2026. Pages that failed: `https://specstory.com/pricing` (404) and `github.com/cursor/agent-trace` (404).

##### Entire — CLI checkpoints and the entire.com forge
- **Records.** A checkpoint holds "the prompts, transcript, and files touched", linked to a commit — [README](https://github.com/entireio/cli/blob/HEAD/README.md). The committed tree has a root `metadata.json` (`checkpoint_id`, `branch`, `files_touched`, `linked_commits` `{sha, repo}`, and `token_usage` with input, cache and output tokens and `api_call_count`). Each session has a `metadata.json` (with redaction counts), `full.jsonl` ("Agent transcript, sanitized + redacted"), `transcript.jsonl`, `prompt.txt` and `content_hash.txt` ("sha256 of full.jsonl (dedup short-circuit)") — [Sessions and checkpoints](https://github.com/entireio/cli/blob/HEAD/docs/architecture/sessions-and-checkpoints.md). Transcripts "capture all tool interactions — including file contents, MCP server calls, and other data exchanged during the session" — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md). The docs also list "tool calls, shell commands, and file operations" and agent-vs-human line attribution — [docs.entire.com](https://docs.entire.com/guides/sessions/overview). Not documented: approval decisions, network hosts, and a model field.
- **Storage and readers.** Data goes to "your own git repository" as `refs/entire/checkpoints/<shard>/<id>`. "Anyone with access to your repository can read committed checkpoint data"; for a public repo it is "visible to the entire internet". Mitigations are a private `--checkpoint-remote` or `--skip-push-sessions` — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md). Forge repos live on Entire clusters (e.g., `aws-eu-central-1.entire.io`) — [README](https://github.com/entireio/cli/blob/HEAD/README.md). Residency at launch was US, EU, India and Australia — [launch post](https://entire.com/news/entire-launches-an-independent-git-forge-for-agent-human-collaboration.md). UK, Singapore and Brazil were added 28–30 Oct 2026 — [Entire news](https://entire.com/news). No encryption claim was found.
- **Integrity.** Checkpoint commits can be signed with the user's GPG or SSH key (`sign_checkpoint_commits`, default on, requires `commit.gpgsign`). Signing is "best-effort": if the signer fails, "the commit is created unsigned and a warning is logged" — [Checkpoint signing](https://github.com/entireio/cli/blob/HEAD/docs/architecture/checkpoint-signing.md). "anyone who can push checkpoints can name any commit". The server verifies a link "only when the authenticated checkpoint pusher is the commit's author"; otherwise it is an "unverified attachment" — [Sessions and checkpoints](https://github.com/entireio/cli/blob/HEAD/docs/architecture/sessions-and-checkpoints.md). There is no hash chain or transparency log, and refs can be deleted.
- **Harnesses.** Claude Code, Codex, Antigravity, OpenCode, Cursor, Factory Droid, Copilot CLI and Pi, plus external `entire-agent-*` plugins. Capture is local, through hooks and agent transcripts — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md)
- **Export.** JSON/JSONL in git, plus `entire search --json`. Logging is only "inspired by OpenTelemetry concepts" — [Logging](https://github.com/entireio/cli/blob/HEAD/docs/architecture/logging.md). A code search for Agent Trace in `entireio/cli` returned 0 hits.
- **Retention and deletion.** `entire checkpoint delete <id>` removes a checkpoint locally and on remotes, but "Deleting a checkpoint is not a full purge": legacy-branch history and sibling checkpoints keep transcripts, and unreachable objects stay until `git gc` — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md)
- **Redaction.** Seven secret passes, six always on: entropy, Betterleaks or goredact, provider token shapes, credentialed URIs, DB strings, shell-stdin literals and credential values. Custom rules and PII redaction (email, phone, address, IP) are opt-in. Gaps it states itself: "There is no OCR pass", Claude Code images are "Stored unredacted", and path fields "are not scanned" — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md)
- **Search, replay, sharing.** Hybrid semantic and keyword `entire search` (`--all-repos`), and a web viewer for "timelines, transcripts, files, and attribution" — [docs.entire.com](https://docs.entire.com/guides/sessions/overview). **File rewind was removed**: "the file-restoring path (`Rewind`, `PreviewRewind`, `CanRewind`) was removed along with the `rewind` commands", and `entire resume` restores only session logs — [Sessions and checkpoints](https://github.com/entireio/cli/blob/HEAD/docs/architecture/sessions-and-checkpoints.md). Trails offer `trail watch`, `trail approve` and `trail resume` — [README](https://github.com/entireio/cli/blob/HEAD/README.md). "Live-streamed sessions" are on the roadmap — [launch post](https://entire.com/news/entire-launches-an-independent-git-forge-for-agent-human-collaboration.md). Sharing is by repo access only.
- **Pricing and traction.** The forge launched 26 Oct 2026 ("Available to every developer today"), with Trails, distributed Git hosting and Continuous Memory; CI partners are Buildkite and Depot; no customers are named — [launch post](https://entire.com/news/entire-launches-an-independent-git-forge-for-agent-human-collaboration.md). The distributed Git network launched 8 Jul 2026 — [Entire news](https://entire.com/news/entire-launches-distributed-git-network-for-the-agent-era.md). The free tier covers "Code Hosting, Trails, Session Storage, Continuous Memory, Agentic Search". Agent usage is pay-as-you-go per token with no seat fee, and Enterprise is custom — [Pricing](https://entire.com/pricing). The $60M seed was announced 10 Feb 2026 (prior round). The CLI had 5,282 stars, with v0.12.2 on 26 Oct 2026 — [repo](https://github.com/entireio/cli)
- **Counter-evidence on approvals.** `entire review` spawns agents with approval checks disabled (`bypassPermissions`, `--dangerously-bypass-approvals-and-sandbox`) — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md)

##### git-ai — line attribution in Git Notes; Git AI for Teams
- **Records.** `refs/notes/ai` holds at most one authorship log per commit. It maps file, then session/turn (`s_…::t_…`) or human (`h_…`), then line ranges. Metadata: `schema_version` `authorship/3.0.0`, `sessions{agent_id{tool,id,model}, human_author}` and `humans{author}`. The transcript "`messages` array field was removed as of v1.3.4". The spec covers rebase (squash, split, drop), merge `--squash`, reset and cherry-pick. The `agent_id.tool` values are cursor, claude, windsurf, copilot, gemini, codex, amp, droid, pi and opencode — [Git AI standard v3.0.0](https://github.com/git-ai-project/git-ai/blob/HEAD/specs/git_ai_standard_v3.0.0.md)
- **Storage and readers.** Notes are "readable by anyone with repo access", including the steering person's name and email. Open-source prompts stay in a "local SQLite", "never shared with teammates or Git AI". The Teams store keeps "every tool use, MCP call, skill invocation, interruption, error, and token-usage event" and "Full prompts", and is "Write-only: ... developers cannot read unless explicitly granted permission". "PR diffs — processed ... but not stored". It does "Best-effort stripping of secrets and PII by default" — [Data privacy](https://github.com/git-ai-project/git-ai/blob/HEAD/data-privacy.md). Teams comes as managed cloud or self-hosted, with no list price ("Book demo call") — [Pricing](https://usegitai.com/pricing)
- **Integrity.** The v3.0.0 standard defines no signing or hashing, and notes are mutable refs — [standard](https://github.com/git-ai-project/git-ai/blob/HEAD/specs/git_ai_standard_v3.0.0.md). No Agent Trace export was found in code.
- **Traction and corporate.** 2,917 stars, v1.7.5 on 9 Sep 2026 — [repo](https://github.com/git-ai-project/git-ai). "Git AI is joining the Codex team at OpenAI" (11 Sep 2026). The post says "we'll keep investing in open source" and does not mention the Teams product — [Git AI blog](https://usegitai.com/blog/git-ai-is-joining-openai); [The New Stack](https://thenewstack.io/openai-hires-git-ai/) (press)

##### Agent Trace — spec and adopters
- **Spec.** v0.1.0, RFC, January 2026, and still the only version. Required fields: `version`, `id`, `timestamp` and `files[]`. Optional: `vcs{type,revision}`, `tool`, `metadata`. Each file has `conversations[]` with `url`, `contributor{type,model_id}` and `ranges[]` (`start_line`, `end_line`, `content_hash`). `content_hash` is for "position-independent tracking" (murmur3 in the examples), and there is no signature field. "This spec intentionally does not define how traces are stored." Licence CC BY 4.0 — [agent-trace.dev](https://agent-trace.dev/)
- **Governance.** The linked repo `github.com/cursor/agent-trace` returned 404 on 31 Oct 2026. An Agentic AI Foundation (AAIF) working-group doc recorded "744 stars, 54 forks, 19 open issues, and no published GitHub release" as of 16 Jun 2026, and the repo as "quiet since Feb 2026" — [AAIF WG prior-work doc](https://github.com/aaif/wg-observability-and-traceability/blob/HEAD/working-documents/PRIOR-WORK.md)
- **Adopters.** The ten listed partners are thanked "for helping shape Agent Trace", not labelled as adopters — [agent-trace.dev](https://agent-trace.dev/). Code evidence of emitting it: **VT Code** (895 stars: "Agent Trace storage layer for VT Code", `.vtcode/traces/`) — [source](https://github.com/vinhnx/VTCode/blob/HEAD/crates/codegen/vtcode-core/src/trace/mod.rs) — and git-atrace (11 stars) — [repo](https://github.com/tnm/git-atrace). Code search found no emitter in cline, opencode, entireio/cli, tapes or git-ai. No evidence was found that Cursor or Amp emit it (see the Cursor and Amp sections).
- **Tapes (Paper Compute).** A "Transparent telemetry collector for hi-fidelity agent traces". It is a proxy: "every intercepted LLM interaction is persisted to an immutable `raw_turns` log" in PostgreSQL, with OTel instrumentation. Its "merkle node layer is retained **internally**". 334 stars, v0.52.0 on 23 Oct 2026 — [repo](https://github.com/papercomputeco/tapes)

##### SpecStory — local markdown history, CLI and Cloud
- **Records.** One markdown file per session in `.specstory/history/` — [CLI README](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/README.md). Codex tool output is "truncated after 5000 characters". Cursor Cloud transcripts are copied locally because Cursor's API serves them "for only 24 hours" — [changelog](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/changelog.md). No approvals, network or integrity data.
- **Harnesses.** Claude Code, Cursor CLI, Codex CLI, Gemini CLI, Droid, Antigravity, Muse Code, OpenCode, Qwen Code, Pi, Cursor IDE, Cursor Cloud Agents and VS Code Copilot, read from the agents' local stores — [CLI README](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/README.md). This is the broadest harness coverage found in any tool.
- **Storage and sharing.** "Everything is local-first" — [README](https://github.com/specstoryai/getspecstory/blob/HEAD/README.md). Cloud sync runs when the user is logged in and can be turned off with `--no-cloud-sync` — [CLI README](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/README.md). "Synced sessions remain private unless you enable sharing". You can "Share a session with a public link and control which exchanges are visible". There is an API "to retrieve or search your history". Retention and encryption are not mentioned — [SpecStory Cloud](https://docs.specstory.com/cloud/overview)
- **Redaction.** Betterleaks secret redaction is on by default and "also covers all the data synced to SpecStory Cloud" — [changelog](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/changelog.md)
- **Integrity research.** A Feb 2026 research doc recommends Git-Notes provenance and to "Keep trust/signing optional but supported via attestations". I found no evidence it shipped — [recommendations](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/docs/git-provenance/RECOMMENDATIONS.md)
- **Pricing and traction.** Cloud has a free plan — [docs](https://docs.specstory.com/). The pricing page returned 404. An aggregator lists Pro at $25/mo and Team at $300/mo (unverified) — [aisotools](https://aisotools.com/pricing/specstory). 1,365 stars, v2.16.0 on 18 Oct 2026 — [repo](https://github.com/specstoryai/getspecstory). The vendor badge API reports 233,573 installs and 11,396 active users on 31 Oct 2026 — [badge](https://specstory.com/api/badge?stat=installs). Funding not found.

##### Turso AgentFS
- **Records.** The `tool_calls` table holds `id`, `name`, `parameters`, `result`, `error`, `started_at`, `completed_at` and `duration_ms`. `session_id`, `user_id`, cost and tokens are optional "extension points" only. "Records MUST NOT be updated or deleted (insert-only audit log)" is a spec rule, with no hash or signature behind it — [SPEC](https://github.com/tursodatabase/agentfs/blob/HEAD/SPEC.md)
- **Encryption.** Optional local at-rest encryption via libSQL with a user-supplied key (AES-256-GCM, AEGIS), but "Local encryption and cloud sync cannot be used together". There are `agentfs timeline --format json`, `agentfs sync push/pull` and `agentfs serve mcp` — [MANUAL](https://github.com/tursodatabase/agentfs/blob/HEAD/MANUAL.md)
- **Status.** BETA — [README](https://github.com/tursodatabase/agentfs/blob/HEAD/README.md). No release since v0.6.4 (25 Mar 2026) — [CHANGELOG](https://github.com/tursodatabase/agentfs/blob/HEAD/CHANGELOG.md). 3,500 stars. No automatic Claude Code or Codex capture into `tool_calls` was found (unverified).

##### Smaller attribution entrants and standards work
- **Agent Blame (Mesa).** Git Notes attribution showing "the tool, model, and prompt". 102 stars, created 8 Jan 2026 — [repo](https://github.com/mesa-dot-dev/agentblame)
- **AIttributor (Block).** A `prepare-commit-msg` co-author trailer; "Only one agent is attributed per commit". 6 stars — [repo](https://github.com/block/aittributor)
- **AAIF Observability & Traceability WG.** Created 12 Feb 2026. Its survey notes that OCSF 1.9 includes "Record Integrity structures" and "attested security ev[idence]" for agent operations — [AAIF WG doc](https://github.com/aaif/wg-observability-and-traceability/blob/HEAD/working-documents/PRIOR-WORK.md) (second-hand; I did not check the OCSF schema itself).


#### Claude Code and Anthropic admin APIs
Claude Code versions are dated by npm publish time; the latest is v2.1.316, published 31 Oct 2026 — [npm registry](https://registry.npmjs.org/@anthropic-ai/claude-code). One doc page has moved: `build-with-claude/claude-code-analytics-api` now serves `/docs/en/manage-claude/claude-code-analytics-api`.

##### Claude Code — checkpoints and /rewind
- **Records.** Snapshots are taken "before each prompt you send that starts a turn", and only for "changes made by its file editing tools". "A file that only Bash commands changed isn't tracked". Subagent edits (except foreground forked skills), manual edits, edits from concurrent sessions, and symlinked or hard-linked files are not captured — [Checkpointing](https://code.claude.com/docs/en/checkpointing). Since v2.1.309 (22 Oct 2026), `sed -i` is "no longer restored by `/rewind`" — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
- **Storage and readers.** Local `~/.claude/file-history/<session>/`. "OS file permissions are the only protection" — [.claude directory](https://code.claude.com/docs/en/claude-directory)
- **Integrity, retention, sharing.** None for integrity: "Not a replacement for version control". It keeps "the 100 most recent checkpoints in a session" and sweeps them about 30 days after the last save (`cleanupPeriodDays`). It can restore code, the conversation or both, and can "Summarize from here" — [Checkpointing](https://code.claude.com/docs/en/checkpointing). `/rewind` shipped in v2.0.0 on 29 Sep 2025 — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md). There is no sharing and no alerting.

##### Claude Code — session transcripts (JSONL), resume/fork, /export, /share
- **Records.** The `.jsonl` holds "messages, tool calls, and tool results, plus the system prompt, tool definitions, and parameters of the requests Claude Code sent the model". "Anything that passes through a tool is written to a transcript on disk: file contents, command output, pasted text." `history.jsonl` holds typed prompts with timestamps — [.claude directory](https://code.claude.com/docs/en/claude-directory). "The entry format is internal to Claude Code and changes between versions" — [Sessions](https://code.claude.com/docs/en/sessions). Whether permission decisions are recorded is undocumented.
- **Storage.** `~/.claude/projects/<project>/<session-id>.jsonl` — [Sessions](https://code.claude.com/docs/en/sessions). "Transcripts and history are not encrypted at rest" — [.claude directory](https://code.claude.com/docs/en/claude-directory). They are stored "locally in plaintext under `~/.claude/projects/` for 30 days by default" — [Data usage](https://code.claude.com/docs/en/data-usage)
- **Integrity.** None documented. Resuming in two terminals without forking means "messages from both interleave into one transcript" — [Sessions](https://code.claude.com/docs/en/sessions). For hooks, the file "is written asynchronously and may lag" — [Hooks](https://code.claude.com/docs/en/hooks)
- **Redaction.** None locally: "If a tool reads a `.env` file or a command prints a credential, that value is written" — [.claude directory](https://code.claude.com/docs/en/claude-directory)
- **Resume, export, retention.** `--continue`, `--resume`, `/branch`, `--fork-session` and `/fork` exist. `/export` writes plain text — [Sessions](https://code.claude.com/docs/en/sessions). `cleanupPeriodDays` defaults to 30 days with a minimum of 1. Desktop and Cowork transcripts are exempt by default — [.claude directory](https://code.claude.com/docs/en/claude-directory)
- **Naming trap: `/share` is not teammate sharing.** "Transcripts shared via `/feedback`, or via `/bug` and `/share`, which report through the same path, are retained for 5 years". Optional survey transcript uploads are kept "up to 6 months", with "Known API key and token patterns" redacted — [Data usage](https://code.claude.com/docs/en/data-usage)

##### Claude Code — OpenTelemetry monitoring
- **Metrics.** `session.count`, `lines_of_code.count`, `pull_request.count`, `commit.count`, `cost.usage`, `token.usage`, `code_edit_tool.decision` and `active_time.total` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage)
- **Events.** `user_prompt`, `assistant_response`, `tool_result` (with gated `tool_parameters`, including `bash_command`), `api_request` (model, tokens, `cost_usd`), `api_error`, `api_refusal`, raw request and response bodies, `permission_mode_changed`, `auth`, `mcp_server_connection`, hook events, `compaction`, `subagent_completed`, `retention_sweep` and `managed_settings_resolved` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage)
- **Approvals.** `tool_decision` carries the `decision` (accept/reject) and its `source` (`config`, `hook`, `user_permanent`, `user_temporary`, `user_abort`, `user_reject`), plus `classifier_verdict`, `permission_mode` and `tool_parameters`. It shares `tool_use_id` with `tool_result` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage). `tool_parameters` was added in v2.1.157 (29 May 2026) and classifier/mode in v2.1.301 (15 Oct 2026). Since v2.1.288 (2 Oct 2026), unanswered asks also emit the event — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
- **Traces (beta).** Enabled with `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`. Spans: `interaction`, `llm_request`, `tool` (`blocked_on_user`, `execution`) and `hook`. `TRACEPARENT` is propagated to Bash subprocesses — [Monitoring](https://code.claude.com/docs/en/monitoring-usage)
- **Docs and changelog conflict.** The monitoring doc describes `safety_event`, including sandbox proxy refusals as `sandbox_violation_count` with "no command text, file paths, host names". It was added in v2.1.307 (21 Oct 2026), but v2.1.312 (27 Oct 2026) says "stop sending the `claude_code.safety_event`" — [Monitoring](https://code.claude.com/docs/en/monitoring-usage); [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
- **Storage and standards.** Data goes to the customer's own OTLP collector or SIEM. Anthropic's operational telemetry "never include[s] your code, prompts, or file paths" — [Data usage](https://code.claude.com/docs/en/data-usage). GenAI semantic conventions are partial: some attributes are labelled "OpenTelemetry GenAI semantic convention" (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.tool.call.id`) — [Monitoring](https://code.claude.com/docs/en/monitoring-usage). More were added in v2.1.300 (14 Oct 2026): `gen_ai.provider.name`, `gen_ai.conversation.id` and `gen_ai.tool.name` — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
- **Redaction.** The prompt is "Redacted by default". Responses are `<REDACTED>` unless `OTEL_LOG_ASSISTANT_RESPONSES=1`. Tool details need `OTEL_LOG_TOOL_DETAILS=1`. Raw bodies (which "include the entire conversation history") need `OTEL_LOG_RAW_API_BODIES` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage)
- **Identity attributes.** `session.id`, `organization.id`, `user.account_uuid`, `user.email` and `prompt.id` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage)
- **Admin forcing.** Managed settings can force telemetry on, and managed endpoints remove "conflicting developer-set variables" — [Monitoring](https://code.claude.com/docs/en/monitoring-usage). Since v2.1.282 (24 Sep 2026), project and local settings ignore the enable and content-capture variables — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md). The docs do not say whether developers are told when content capture is forced on.
- **Network reach.** The documented route for logging hosts is to "replace the built-in sandbox proxy with a proxy you run" — [Sandboxing](https://code.claude.com/docs/en/sandboxing)
- **Self-hosted Claude apps gateway.** "You control where telemetry, audit logs ... go, and the gateway sends none of them to Anthropic" — [Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway)

##### Claude Code — analytics (dashboard, Claude Code Analytics API, Enterprise Analytics API, Usage & Cost API)
- **Records.** The dashboard shows lines accepted, accept rate, DAU and sessions, a leaderboard, a CSV export and spend "per user and per model". GitHub contribution metrics (beta) label PRs `claude-code-assisted` — [Analytics](https://code.claude.com/docs/en/analytics). `GET /v1/organizations/usage_report/claude_code` returns per-user, per-day sessions, lines, commits, PRs, Edit/Write accept and reject counts, and tokens and estimated cost by model. It covers the Claude API only (Bedrock, Foundry, Google and subscription users are excluded). It is "free to use", has "up to a 1-hour delay", and "There is no specified deletion period" — [Claude Code Analytics API](https://platform.claude.com/docs/en/manage-claude/claude-code-analytics-api)
- **Readers and limits.** The dashboard is for "Admins and Owners". The Enterprise Analytics API is "not available on the Teams plan" — [Analytics](https://code.claude.com/docs/en/analytics). The Usage & Cost API has a "365-day lookback and 31-day span" — [Usage & Cost API](https://platform.claude.com/docs/en/manage-claude/usage-cost-analytics-api). No prompts, code or commands are included, and there is no developer opt-out.

##### Claude Code — hooks as an audit mechanism
- **Events (33).** SessionStart, Setup, InstructionsLoaded, UserPromptSubmit, UserPromptExpansion, MessageDisplay, PreToolUse, **PermissionRequest**, PostToolUse, PostToolUseFailure, PostToolBatch, **PermissionDenied**, Notification, SubagentStart/Stop, TaskCreated/Completed, Stop, StopFailure, TeammateIdle, ConfigChange, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate/Remove, Pre/PostCompact, Pre/PostModelSwitch, SessionEnd, Elicitation and ElicitationResult. Payloads include `session_id`, `prompt_id`, `transcript_path`, `cwd`, `permission_mode` and `agent_id`. PermissionRequest carries `tool_input` "but without `tool_use_id`". PostToolUse carries `tool_input`, `tool_response` and `tool_use_id`. **No event fires on the human's answer to a prompt** (OTel `tool_decision` carries it) — [Hooks](https://code.claude.com/docs/en/hooks)
- **Enforcement.** Managed `allowManagedHooksOnly` exists, and `disableAllHooks` set outside managed settings "can't disable managed hooks". `allowedHttpHookUrls` restricts HTTP hook targets — [Settings reference](https://code.claude.com/docs/en/settings-reference); [Hooks](https://code.claude.com/docs/en/hooks). Server-managed hooks trigger a user "security approval dialog" — [Server-managed settings](https://code.claude.com/docs/en/server-managed-settings)
- **Limits.** "PostToolUse hooks can't undo actions". `@`-referenced files bypass PreToolUse. SessionEnd shares a "1.5-second budget". Stop hooks don't fire on user interrupts — [Hooks guide](https://code.claude.com/docs/en/hooks-guide); [Hooks](https://code.claude.com/docs/en/hooks)
- **Inference hooks (server-side, Enterprise).** Anthropic "sends the conversation transcript to your AI security server" before inference, and an optional `tool_call` event fires before tools run. They are configured by an Owner or Primary Owner — [Inference hooks](https://platform.claude.com/docs/en/manage-claude/inference-hooks)

##### Anthropic — Compliance API, audit-log export, Access Transparency
- **Records.** The Activity Feed (`GET /v1/compliance/activities`) covers auth, admin, chat, file and project activity, with `ip_address` and `user_agent` — [Activity Feed](https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed). Local session transcripts (`/v1/compliance/apps/sessions/local`, surface `claude_code`) hold prompts, assistant text, tool calls and tool-result text. Tool inputs are "Truncated to 10,000 bytes ... up to about 1 MiB on request". They "show what Claude was asked to do and what it returned, not what occurred on the device". Excluded: Console API keys, Bedrock/Google/Foundry, cloud sessions and routines, and ZDR sessions (which return 404). "Nothing masks URLs, credentials, or personal data" — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions)
- **Integrity.** None for the feed or transcripts. Customers are told to store exports with "a content hash of each record" — [Integration patterns](https://platform.claude.com/docs/en/manage-claude/compliance-integration-patterns). Some Anthropic-run processes "can currently appear as `user_actor`", and retention-policy deletions log no `*_deleted` event — [Activity Feed](https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed)
- **Retention.** The Activity Feed is kept 6 years — [Compliance FAQ](https://platform.claude.com/docs/en/manage-claude/compliance-faq). Local sessions are kept 6 years or a custom period (30 days for HIPAA orgs), and the session endpoints are read-only — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions). Turning the API off loses activity that "cannot be recovered later" — [Compliance FAQ](https://platform.claude.com/docs/en/manage-claude/compliance-faq)
- **Export and partners.** REST pull only, with no webhooks — [Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api). The partner blog (21 May 2026) lists "28 integrations" at launch, later "over 100+", including Splunk, CrowdStrike, Datadog, Purview and Netskope (vendor claim) — [Claude blog](https://claude.com/blog/compliance-api-security-partners). The audit-log CSV export is for Enterprise Owners, covers the past 180 days, and is unavailable with CMEK — [Support](https://support.claude.com/en/articles/9970975-how-to-access-audit-logs)
- **Access Transparency transparency log (beta; on request, not self-serve).** It is "an append-only, cryptographically signed record of Access Transparency events (`anthropic_access` and `cmek_preserve`)". It is a Merkle tree with signed checkpoints (ECDSA P-256) in "the C2SP tlog-tiles wire format exactly", with inclusion and consistency proofs and an `axt-verify` tool. "Every proof is also computable from tiles, so you never have to trust a proof endpoint's output." Caveat: "It does not prove that every access was recorded… It proves only that what Anthropic committed to the log has not changed since." — [Access Transparency log](https://platform.claude.com/docs/en/manage-claude/access-transparency-log). Each human view of customer content by Anthropic staff, including "Claude Code sessions", writes an event; "Per-workspace enrollment is not currently available" — [Access Transparency](https://platform.claude.com/docs/en/manage-claude/access-transparency)
- **CMEK.** Transcripts are "encrypted under your customer-managed key", and the endpoint returns 503 while the key is unusable — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions). "If your key is deleted, Anthropic can't recover the data it protects" — [CMEK](https://platform.claude.com/docs/en/manage-claude/cmek). CMEK covers "Claude Code on the CLI, including message content" — [CMEK coverage](https://platform.claude.com/docs/en/manage-claude/cmek-coverage-claude-enterprise)

##### Claude Code — cloud sessions (Claude Code on the web)
- **Records.** "Anthropic stores the session transcript". "All outbound traffic goes through a security proxy for audit logging and abuse prevention" — [Data usage](https://code.claude.com/docs/en/data-usage). "All operations in cloud sessions are logged for compliance and audit purposes" — [Security](https://code.claude.com/docs/en/security). No customer API is documented for these proxy logs, and cloud sessions are excluded from the Compliance API — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions)
- **Sharing.** Team/Enterprise sessions can be Private or Team. On Pro/Max/Ultra, Public means "any user logged into claude.ai", and recipients see a non-live snapshot. Delete "permanently removes the session and its data". Cloud sessions are blocked under ZDR, HIPAA or CMEK — [Claude Code on the web](https://code.claude.com/docs/en/claude-code-on-the-web)

##### Retention, ZDR and traction
- **Retention.** Consumer data is kept 5 years with training on and 30 days with it off. Commercial data is kept 30 days with no training. Anthropic API encryption at rest is "Infrastructure-level disk encryption (AES-256)" — [Data usage](https://code.claude.com/docs/en/data-usage)
- **ZDR.** Enterprise, for "qualified accounts". It disables cloud sessions, Remote Control and `/feedback`/`/share`, and keeps "productivity metadata such as account emails" — [ZDR](https://code.claude.com/docs/en/zero-data-retention)
- **Traction.** On 12 Feb 2026, Claude Code run-rate was "over $2.5 billion" and enterprise was "over half of all Claude Code revenue" (vendor claim) — [Anthropic Series G](https://www.anthropic.com/news/anthropic-raises-30-billion-series-g-funding-380-billion-post-money-valuation). On 28 May 2026, company run-rate had "crossed $47 billion" (vendor claim) — [Anthropic Series H](https://www.anthropic.com/news/series-h)
- **Agent-team messages.** Mailboxes are plain JSON files that are validated for format only; no sender authentication is documented — [Agent teams](https://code.claude.com/docs/en/agent-teams)


#### OpenAI Codex
`developers.openai.com/codex/config-advanced` and `/codex/hooks` now redirect (308) to `learn.chatgpt.com/docs/...`.

##### Codex — local rollouts, history.jsonl, rollout-trace bundles
- **Records (source on `main`).** User and assistant messages, `Reasoning`, `LocalShellCall`, `FunctionCall`/`FunctionCallOutput`, `CustomToolCall`, `WebSearchCall`, `SessionMeta`, `TurnContext`, `TokenUsageRecord`, `WorldState`, `SecurityRiskScore`, `InterAgentCommunication(+Metadata)` and `ThreadRolledBack`. Command output is capped at `64 * 1024` bytes. These are labelled "Transient, non-durable" and **not** persisted: `ExecApprovalRequest`, `ApplyPatchApprovalRequest`, `RequestPermissions`, `NetworkApprovalResolved`, `GuardianAssessment`, `TurnDiff` and `ExecCommandBegin/End` — [policy.rs](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/policy.rs). Files are named `rollout-{timestamp}-{thread_id}.jsonl` — [rollout_file_name.rs](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/rollout_file_name.rs)
- **Storage.** "Codex saves local session transcripts under `CODEX_HOME`" (`~/.codex`) — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced). Opt-in rollout-trace bundles (`CODEX_ROLLOUT_TRACE_ROOT`) "can contain prompts, responses, tool inputs/outputs, terminal output, and paths", and "Codex does **not** upload or report these traces" — [rollout-trace README](https://github.com/openai/codex/blob/main/codex-rs/rollout-trace/README.md)
- **Integrity and redaction.** None documented; the files are plain JSONL, and the crate has no signing or chaining module — [rollout src](https://github.com/openai/codex/tree/main/codex-rs/rollout/src)
- **Retention.** `history.max_bytes` "drops the oldest entries", and `persistence = "none"` disables history — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced). The CLI has `resume`, `fork`, `archive` and `delete` subcommands — [cli main.rs](https://github.com/openai/codex/blob/main/codex-rs/cli/src/main.rs). The local logs DB is swept after 10 days — [logs_maintenance.rs](https://github.com/openai/codex/blob/main/codex-rs/state/src/runtime/logs_maintenance.rs)
- **Resume and fork.** `codex resume`, `codex fork` ("the original transcript" is kept), `/fork`, Esc-Esc edit-and-fork, `codex exec resume --last`, and App Server rollback of the last N turns with a marker (search summary) — [CLI reference](https://learn.chatgpt.com/docs/cli/reference); [App Server](https://learn.chatgpt.com/docs/app-server). No file-level checkpoint or undo was found.
- **Traction.** Apache-2.0. 132,467 stars on 31 Oct 2026 (created 13 Apr 2025). Latest release `rust-v0.166.0` on 29 Oct 2026 — [openai/codex](https://github.com/openai/codex). About 3M+ weekly users (about 8 Apr 2026) and 4M+ (about 21 Apr 2026), per a third-party site that I did not confirm against a primary source — [danielvaughan](https://codex.danielvaughan.com/2026/04/29/codex-four-million-users-growth-gpt-5-2-codex-aws-partnership/)

##### Codex — OpenTelemetry and the network-proxy audit events
- **Events.** OTel is "Disabled by default; opt in via `[otel]`". Events: `codex.conversation_starts` (model, sandbox and approval policy), `codex.api_request`, `codex.sse_event` (token counts), `codex.user_prompt` ("content redacted unless explicitly enabled"), `codex.tool_decision` ("approved/denied, and whether the decision came from config or the user") and `codex.tool_result` ("output snippet"). `otel` "cannot be set in project-local `.codex/config.toml`". Exporters: `none`, `otlp-http` and `otlp-grpc` — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced)
- **Network proxy.** `codex.network_proxy.policy_decision` carries `server.address`, `server.port`, `network.policy.decision` (allow/deny/ask), `network.policy.source`, `http.request.method`, `conversation.id` and `user.account_id`. "Audit events intentionally avoid logging full URL/path/query data", and the event fires only when the proxy is "embedded in managed Codex runtime" — [network-proxy README](https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md). This is the most complete per-host network-reach record found in any harness.
- **Standards.** Events use a `codex.*` namespace; the docs do not mention GenAI semantic conventions — [otel README](https://github.com/openai/codex/blob/main/codex-rs/otel/README.md). OpenAI says local OTel can be collected "by configuring an OTel collector endpoint" — [Governance](https://learn.chatgpt.com/docs/enterprise/governance)

##### Codex — hooks and managed config (`requirements.toml`)
- **Events (12).** `SessionStart`, `SessionEnd`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop` and `Interrupt`, with `session_id`, `transcript_path`, `model`, `tool_use_id` and `tool_input`. On PreToolUse, `"ask"` is "parsed but not supported yet". For PermissionRequest, "any `deny` wins". Managed hooks are "trusted by policy, and can't be disabled from the user hook browser", and `allow_managed_hooks_only = true` is available. Command and local hooks are "not supported with cloud orchestration, even when tools execute locally". "MCP hooks do not provide a complete Compliance API audit trail" — [Hooks](https://learn.chatgpt.com/docs/hooks); [config.md](https://github.com/openai/codex/blob/main/docs/config.md)

##### Codex — cloud tasks
- **Records and controls.** Users can "Inspect changed files and check results" and open a PR. "Each task has its own workspace". There are domain allowlists, but no egress log is documented. Task retention and sharing are undocumented — [Codex cloud](https://learn.chatgpt.com/docs/cloud)

##### OpenAI — Compliance Logs Platform (Codex coverage), Analytics, pricing
- **Records.** Coverage is "with records under `conversation_message` and `codex_log`", and the platform is "not an adoption or productivity dashboard". "Conversation visibility alone does not establish a complete record of local actions." "Check these records separately from Compliance API coverage" — [Governance](https://learn.chatgpt.com/docs/enterprise/governance). `CODEX_LOG` covers "tool calls, prompts and responses, plugins, environments, and access tokens", with `prompt_text`, `response_text`, tool-call arguments and results, and token usage. Other streams: `CONVERSATION_MESSAGE`, `AUDIT_LOG`, `AUTH_LOG`, "Codex Security Log" and "Custom Agents Log". "OpenAI retains compliance logs for a limited window (up to 30 days)" — [Elastic integration](https://www.elastic.co/docs/reference/integrations/openai_chatgpt_enterprise). OpenAI help article 9261474 returned HTTP 403: https://help.openai.com/en/articles/9261474-openai-compliance-platform-for-enterprise-customers
- **Pricing.** Free $0, Go $8, Plus $20, Pro $100/$200/$500, Business $20/user/mo (annual), and Enterprise/Edu by sales ("SCIM, EKM, user analytics", Compliance API, Analytics API, `requirements.toml`) — [Codex pricing](https://learn.chatgpt.com/docs/pricing). The prior round's point that API-key usage is excluded from the Compliance API was **not re-confirmed** on the current governance page.

#### Cursor (Anysphere)
##### Cursor — checkpoints
- Agent takes checkpoints "before making significant changes, capturing the state of all modified files". They are "stored locally and separate from Git". Restoring "does not remove messages from the conversation". Retention is not documented — [Checkpoints](https://cursor.com/docs/agent/chat/checkpoints)

##### Cursor — hooks
- **Events (21).** `sessionStart/End`, `preToolUse`, `postToolUse(+Failure)`, `subagentStart/Stop`, `before/afterShellExecution`, `before/afterMCPExecution`, `beforeReadFile`, `afterFileEdit`, `beforeSubmitPrompt`, `preCompact`, `stop`, `afterAgentResponse`, `afterAgentThought`, `beforeTabFileRead`, `afterTabFileEdit` and `workspaceOpen`. Common fields: `conversation_id`, `generation_id`, `model`, `user_email` and `transcript_path`. Shell, MCP and file-edit payloads carry commands, MCP URLs and old/new strings. "any `deny` wins over `ask`, and `ask` wins over `allow`" — [Cursor hooks](https://cursor.com/docs/agent/hooks)
- **Distribution.** Enterprise MDM, then Team ("cloud-distributed, Enterprise"), then project, then user. Cloud agents skip some events and "read-only exploratory turns". Named partners: MintMCP, Oasis Security, Runlayer, Corridor, Semgrep, Endor Labs, Snyk and 1Password — [Cursor hooks](https://cursor.com/docs/agent/hooks). Cursor's guidance is to log "metadata (who, when, what file) rather than content when possible" — [Compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring). Cursor also loads Claude Code hooks, but it does not map `PermissionRequest`, and "Other non-zero exit codes fail open" — [Third-party hooks](https://cursor.com/docs/reference/third-party-hooks)
- **User demand.** A forum thread asks for a "Platform-level audit trail for agent tool call proposals and user approval decisions" (title only) — [Cursor forum](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247)

##### Cursor — Enterprise audit log
- **Records.** "Audit logs record who changed what in your team and organization": sign-ins, membership, roles, API keys, settings, integrations, Cloud Agent environments, Grok Bot configuration and Origin repositories. "Payloads carry identifiers, names, and changed settings, never prompts, agent output, generated code, or credentials." Fields: `event_id`, `timestamp`, `team_id`, `ip_address`, `user_email`, `user_id`, `event_type` and `event_data`. "Privacy Mode doesn't suppress audit events" — [Compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring)
- **Export.** CSV, plus `GET /teams/audit-logs` and `/organizations/audit-logs` (7-day default, 30-day maximum window). Streaming goes to Splunk HEC, Sumo Logic, an HTTPS webhook or S3, set up through hi@cursor.com. Retention is not stated — [Compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring). It is Enterprise-only — [Pricing](https://cursor.com/pricing)

##### Cursor — OpenTelemetry export (Enterprise)
- **Records.** Metrics for tokens, tool calls and cost ("best-effort USD estimate, not an invoice"). Logs for `cursor.api.request`, hooks, Cloud Agent lifecycle and Grok Bot actions. Opt-in content covers Cloud Agent and Grok Bot prompts and responses and Cloud Agent tool I/O. "IDE, CLI, and desktop conversations are not exported by this family yet." "Cursor doesn't send traces". It uses the `cursor.*` namespace, not `gen_ai.*`. Content is "off by default", and "Pattern matching can't recognize every secret or every piece of personal data" — [OpenTelemetry export](https://cursor.com/docs/enterprise/opentelemetry-export)

##### Cursor — AI Code Tracking API, Cursor Blame, Agent Trace
- **Records.** Per-commit hash, user email, repo, `commitSource`, and TAB/Composer/non-AI lines. "Commit Details" (limited alpha) gives blame annotations linking line ranges to conversation IDs and models. "Commit hashes are not unique or unchangeable" — [AI Code Tracking API](https://cursor.com/docs/account/teams/ai-code-tracking-api)
- **Cursor Blame.** It labels lines Tab, Agent or Human, with the model and a conversation summary. Data is "fetched from Cursor's servers" — [Cursor Blame](https://cursor.com/docs/integrations/cursor-blame). It shipped in Cursor 2.4 on 22 Jan 2026 (search summary) — [Changelog 2.4](https://cursor.com/changelog/2-4)
- **Agent Trace.** No evidence that Cursor emits it. `github.com/cursor/agent-trace` returned 404 on 31 Oct 2026.

##### Cursor — cloud agents and shared transcripts
- **Sharing.** Shared transcripts contain "The full conversation history … including code snippets, tool calls, and their results". Links are "Team (only signed-in team members) or Public (anyone with the link)", with "50 shares per day". Redaction of secret patterns is best-effort, and admins can delete transcripts — [Shared transcripts](https://cursor.com/help/ai-features/shared-transcripts)
- **Storage and retention.** Cloud agents run "inside our AWS infrastructure in isolated VMs". "Conversation history is kept indefinitely by default", with an Enterprise 90-day option. Secrets are "redacted from the agent's tool call results, chat transcript, commits" but remain visible "via the Terminal". "Cloud Agents can only reach the domains you explicitly add to your allowlist", but no egress log is documented — [Cloud agent security](https://cursor.com/docs/cloud-agent/security-network)

##### Cursor — Privacy Mode, pricing, traction
- **Privacy Mode.** "When enabled, we will not train on your data". The security page links to a "Data Encryption and CMEK" doc, which I did not open — [Security](https://cursor.com/security)
- **Pricing.** Free, Plus $8, Premium $30, Super $100, Ultra $200, Teams "$30+/user/month", and Enterprise custom (audit logs, SCIM) — [Pricing](https://cursor.com/pricing)
- **Corporate.** SpaceX agreed on 16 Jun 2026 to acquire Anysphere in an all-stock deal valued at about $60B (press) — [Techzine](https://www.techzine.eu/news/devops/142197/spacex-acquires-cursor-for-60-billion/); [Quartz](https://qz.com/spacex-buying-cursor-anysphere-60-billion-deal-061626). Closing was expected in Q3 2026. A 15 Aug 2026 closing is reported only by minor outlets and is unconfirmed — [search results](https://pasqualepillitteri.it/en/news/11391/spacex-buys-cursor-anysphere-60-billion). The docs now include "Grok Bot" and "Origin" repository hosting.


#### GitHub Copilot
Not opened: the content-exclusion docs and the artifact-attestation (Sigstore) docs.

##### GitHub — Copilot cloud agent ("coding agent") session logs
- **Records.** Logs show "Copilot's internal reasoning and the tools it used to explore the repository, make changes, and validate its work", plus token usage and session length — [Managing agent sessions](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions). They contain "prompts and responses, tools used, and changes made to files" — [Session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data). When the firewall blocks a request, the PR shows the blocked address and the command that made it. The firewall "does not apply directly to Model Context Protocol (MCP) server processes", and "Sophisticated attacks may bypass the firewall" — [Agent firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall). No log of allowed hosts or per-call approvals is documented.
- **Readers.** Actions-based sessions are "Shared by default" with "anyone with access to the repository"; sandbox sessions are "unshared by default" — [Session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data)
- **Integrity.** Agent commits are "Verified", and each commit message "includes a link to the session logs" — [Managing agent sessions](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions). Since 20 Mar 2026, an `Agent-Logs-Url` trailer gives "a permanent link from agent-authored commits back to the full session logs". Commits are "authored by Copilot, with the human who gave Copilot the task marked as the co-author" — [GitHub changelog](https://github.blog/changelog/2026-03-20-trace-any-copilot-coding-agent-commit-to-its-session-logs/). The signature protects the link, not the log content (inference).
- **Retention.** Cloud agent sessions "can be archived but not deleted"; no retention period is stated — [Managing agent sessions](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions)
- **Plans.** Included in Pro, Pro+ and Max, not Free — [Plans](https://github.com/features/copilot/plans)

##### GitHub — agent control plane, Enterprise AI Controls, audit log and session streaming
- **Audit fields.** `actor_is_agent` ("This will always be `true` for agentic audit log events"), `agent_session_id` and `user`. The `actor:Copilot` filter shows "the last 180 days" — [Agentic audit log events](https://docs.github.com/en/copilot/reference/agentic-audit-log-events). The control plane went GA on 26 Feb 2026, adding `user_id`, an `agent_session.task` event (start, finish, fail), an "AI administrator" role, the AI Controls tab, and a 24-hour session view filterable by agent. Future work listed then: "more comprehensive session activity coverage to Copilot clients such as VS Code and Copilot CLI" — [GA changelog](https://github.blog/changelog/2026-02-26-enterprise-ai-controls-agent-control-plane-now-generally-available/)
- **Session streaming (public preview, 2 Jul 2026).** Streams "prompts, responses, and tool calls" from the cloud agent, Copilot CLI, VS Code, Visual Studio and JetBrains/Eclipse to the customer's SIEM. A REST API returns "the last 48 hours of session data". It requires "GitHub Enterprise Cloud customers with enterprise managed users" — [Streaming changelog](https://github.blog/changelog/2026-07-02-copilot-agent-session-streaming-is-now-in-public-preview/). Usage records carry `body` (JSON string), `user_id`, `endpoint` and `truncated` (cut at 1 MB) — [Agentic audit log events](https://docs.github.com/en/copilot/reference/agentic-audit-log-events)
- **Export and integrity.** Destinations: S3, Azure Blob, Azure Event Hubs, Datadog, GCS, Microsoft Purview and Splunk, as "compressed JSON files". "GitHub uses an at-least-once delivery method", "some events may be duplicated", and streams are "encrypted" in transit only. No signing, hash chain or WORM — [Audit-log streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise). No OTel or Agent Trace.

##### GitHub — Copilot usage metrics
- **Records.** Counts only: DAU, agent mode, cloud agent and CLI usage, breakdowns "by feature, IDE, language, model, and user", lines added and deleted, acceptance rate and PR merge times. Data is available "at the enterprise, organization, repository, and user levels" and exported as NDJSON. It needs "telemetry enabled in their IDE". Dashboards show "28-day usage trends", with data "within two full UTC days" — [Copilot usage metrics](https://docs.github.com/en/copilot/concepts/copilot-usage-metrics/copilot-metrics)
- **Undercount.** A 6 Oct 2026 changelog says agent activity was undercounted until IDEs are updated (search summary) — [changelog](https://github.blog/changelog/2026-10-06-update-your-ide-to-restore-agent-activity-in-copilot-usage-metrics/)

##### GitHub — third-party agents (Agent HQ)
- Claude (Claude Agent SDK) and Codex (Codex SDK) run in preview as GitHub Apps. Their actions "will be visible in your audit log". These policies "do not apply to local agents in VS Code". Sessions consume "GitHub Actions minutes and AI credits". The page does not describe session logs for these agents — [Third-party agents](https://docs.github.com/en/copilot/concepts/agents/about-third-party-agents)

##### GitHub — Copilot CLI local sessions, /chronicle, /share
- **Local record.** The "complete record of each session" is kept under `~/.copilot/session-state/`, with a SQLite session store. For Business and Enterprise, if the "Store local sessions in the Cloud" policy is "disabled or unconfigured, sessions are stored locally only". Synced data is "accessible only to you by default" — [Session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data)
- **Commands.** `/chronicle search` "searches all of your session content". `/share link`, `/share gist` (private gist), `/share file` (markdown) and `/share html` exist, as do `/session delete`, `delete-all` and `prune --older-than DAYS` — [Copilot CLI chronicle](https://docs.github.com/en/copilot/how-tos/copilot-cli/chronicle). /chronicle launched 2 Jun 2026 (search summary) — [changelog](https://github.blog/changelog/2026-06-02-gain-insights-across-your-agent-sessions-with-chronicle/)

##### GitHub — pricing and traction
- **Pricing.** Free $0, Pro $10, Pro+ $39, Max $100. "1 AI credit = $0.01 USD". "GitHub Enterprise now includes access to GitHub Copilot" — [Plans](https://github.com/features/copilot/plans)
- **Traction.** 4.7M paid subscribers, up 75% year on year (29 Jan 2026) — [TechCrunch](https://techcrunch.com/2026/01/29/satya-nadella-insists-people-are-using-microsofts-copilot-ai-a-lot) (press)
- **Prompt retention.** No official retention page was retrieved. A Microsoft Learn module says IDE prompts are discarded after the suggestion is returned, and other Chat surfaces are kept for 28 days (search summary) — [MS Learn](https://learn.microsoft.com/en-gb/training/modules/introduction-prompt-engineering-with-github-copilot/4-github-copilot-data)

#### Amp (Amp Frontier Corporation; spun out of Sourcegraph)
##### Amp — threads
- **Records.** A thread holds "your prompts, the agent's replies, every tool call it made, and the files it changed", plus diffs, commits and cost. Agent commits carry an `Amp-Thread-ID` trailer — [Threads](https://ampcode.com/docs/threads)
- **Storage.** "Our primary infrastructure is hosted on Google Cloud Platform in the US", in "a multi-tenant Google Cloud Platform project". Data is "encrypted at the volume level using AES-256". Local CLI threads connect through `tunnel.ampcode.com` — [Security](https://ampcode.com/security)
- **Visibility.** Private ("You. In a workspace, workspace admins can also see it."), Workspace, Group (Enterprise) and Unlisted ("Anyone on the internet who has the link.") — [Threads](https://ampcode.com/docs/threads). Public threads ended 2 Jun 2026 because it was "too hard to review a thread to ensure it doesn't contain any snippets of sensitive files" — [End of Public Threads](https://ampcode.com/news/end-of-public-threads)
- **Export, search, redaction, deletion.** Markdown export (`.md` URL suffix), JSON "for the thread's creator", `amp threads export` and `amp threads search`, and an Activity feed — [Threads](https://ampcode.com/docs/threads). Secrets become `[REDACTED:amp]` (best-effort; launched 30 May 2025) — [Security](https://ampcode.com/security); [news](https://ampcode.com/news/secret-redaction). Deleted data is "removed within 30 days". "We only delete workspace threads and associated user data when the enterprise's contract with us ends" — [Security](https://ampcode.com/security)

##### Amp — enterprise controls
- **Audit logs.** Application audit logs are "not currently exposed to Workspace Admins" and "can be provided... upon request". "All workspace admin access to private threads is audit-logged", with a passkey required. "Audit logs are retained for a minimum of 30 days" — [Security](https://ampcode.com/security). The pricing page lists "Audit logs and network/MCP access controls" for Enterprise (vendor claim; at odds with the security page) — [Pricing](https://ampcode.com/pricing)
- **Data retention and training.** Minimal Data Retention "limits how long third-party model providers retain prompts and responses" and "does not control how Amp stores thread data" — [Minimal data retention](https://ampcode.com/docs/enterprise/minimal-data-retention). "Neither Amp nor our subprocessors train models on your data, unless you have explicitly opted into training" — [Security](https://ampcode.com/security)
- **Usage and admin.** Usage CSVs (spend and tokens per member) and Enterprise roles including Auditor — [Workspaces](https://ampcode.com/docs/collaborate/workspaces). Admins can disable external sharing and make threads private by default — [Visibility controls](https://ampcode.com/docs/enterprise/workspace-thread-visibility-controls). The API `GET /threads` returns threads "from your workspace, including private and group-shared threads" — [Amp API](https://ampcode.com/api/external)

##### Amp — corporate, pricing, Agent Trace
- **Corporate.** On 2 Dec 2025: "Amp is becoming a separate company. We're spinning out of Sourcegraph to become an independent research lab." "Amp is profitable" (vendor claim) — [Amp Frontier Corporation](https://ampcode.com/news/amp-frontier-corporation). The editor extension was killed 19 Feb 2026 — [news](https://ampcode.com/news/the-coding-agent-is-dead)
- **Pricing.** Hobby is free (bring your own key), Individual $20/mo, Teams at "No extra charge", and Enterprise custom ("Pooled credits only, no paid user seats") — [Pricing](https://ampcode.com/pricing)
- **Agent Trace.** No Amp source shows Agent Trace emission; its attribution mechanism is the `Amp-Thread-ID` trailer.


#### Observability products for coding agents
Some pages were only partly read or did not load. Of the Claude Code monitoring page, only the first 100k of 172k characters were read. The Datadog LLM Observability instrumentation page did not load. The AgentOps pricing page did not render.

##### LangSmith (LangChain) — `langsmith-tracing` plugin for Claude Code (hooks); Cursor and Codex plugins
- **Records.** "Each message becomes a trace, and a session's messages are grouped into a thread". A redacted trace "still holds your prompts and file contents". It is hook-based (log at `~/.claude/state/hook.log`). The page does not list tool I/O, cost or permission decisions — [LangSmith, trace Claude Code](https://docs.langchain.com/langsmith/trace-claude-code)
- **Storage and readers.** LangChain cloud (US/EU). Enterprise offers "Hybrid: SaaS control plane, Self-hosted data plane" and "Self-Hosted: Fully self-managed" — [Pricing](https://www.langchain.com/pricing). Public links: "Shared traces will be accessible to anyone with the link, even if they don't have a LangSmith account". Admins can "Disable Public Sharing" — [Share trace](https://docs.langchain.com/langsmith/share-trace); [KB](https://support.langchain.com/articles/5345880639-how-do-i-disable-public-sharing-for-traces-in-langsmith)
- **Redaction and privacy.** Local secret redaction is on by default, before upload (`[SECRET_DETECTED]`), and is called "a safety net rather than a guarantee". Mute controls exist. The page warns: "Project-level config files can turn tracing on and redirect traces" — [LangSmith, trace Claude Code](https://docs.langchain.com/langsmith/trace-claude-code)
- **Retention and price.** "Base traces have a shorter retention period of 14 days". Plus is "$39 / seat / mo · includes 10K traces total", with extra traces at about $5 per 1k — [Pricing](https://www.langchain.com/pricing)
- **Traction.** `langsmith-claude-code-plugins` had 73 stars (created 1 Apr 2026) — [repo](https://github.com/langchain-ai/langsmith-claude-code-plugins). LangChain's Series B was $125M at $1.25B (Oct 2025, press; sources disagree on figures) — [press](https://siliconvalleyinvestclub.beehiiv.com/p/langchain-raises-125-million-at-a-1-25-billion-valuation)

##### Langfuse (ClickHouse) — Stop-hook transcript shipper and plugin; Codex, Copilot, Cursor, Kiro, OpenCode, Augment
- **Records.** User prompt, assistant text, tool spans ("Tool: Read", "Tool: Bash") with inputs, outputs and duration, model, tokens, session ID and `transcript_path`. Text over `CC_LANGFUSE_MAX_CHARS` (20,000) is truncated, keeping "a hash of the original". Mechanism: "The hook reads Claude Code's generated conversation transcripts". Tracing is opt-in per project (`TRACE_TO_LANGFUSE`). No redaction is described for this integration — [Langfuse, Claude Code](https://langfuse.com/integrations/other/claude-code). The plugin repo had 29 stars (created 26 May 2026) — [repo](https://github.com/langfuse/claude-observability-plugin)
- **Harnesses.** "Langfuse traces all major coding agents today" (vendor claim). Codex uses "Plugin hooks (Stop hook per turn)", Copilot uses "Native OpenTelemetry export", and Cursor, Kiro, OpenCode and Augment are also covered — [Coding-agent tracing](https://langfuse.com/resources/engineering/coding-agent-tracing)
- **Storage, sharing, retention.** Cloud (EU, US, Japan, HIPAA) or self-hosted — [Langfuse, Claude Code](https://langfuse.com/integrations/other/claude-code). Public trace links date from 14 Sep 2023 — [changelog](https://langfuse.com/changelog/2023-09-14-public-link-sharing). Hobby gives "30 days data access", Core ($29/mo) "90 days", and the top tier "3 years data access", "Audit Logs" and "Project-level RBAC". Overage is $8 per 100k units — [Pricing](https://langfuse.com/pricing)
- **Traction.** 36,806 stars, MIT outside `ee/` — [repo](https://github.com/langfuse/langfuse). Acquired by ClickHouse, announced 16 Jan 2026, terms undisclosed — [Langfuse blog](https://langfuse.com/blog/joining-clickhouse); [ClickHouse blog](https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability); [SiliconANGLE](https://siliconangle.com/2026/01/16/database-maker-clickhouse-raises-400m-acquires-ai-observability-startup-langfuse/) (press)

##### Braintrust — `trace-claude-code` plugin or Claude Code native OTel; Codex, Cursor and OpenCode plugins; Agent SDK wrappers
- **Records.** Session spans (hostname, username, OS, model, Git metadata); turn spans (prompts, responses, permission mode); model-call spans (tokens); tool spans with "inputs, outputs, approval state, and tool names"; subagents. `bt trace import` loads local transcripts. On the OTLP path it maps `claude_code.interaction`, `llm_request`, `tool` and `hook` spans. US/EU or self-hosted data plane — [Braintrust, Claude Code](https://docs.braintrust.dev/integrations/developer-tools/claude-code.md)
- **Retention and price.** Starter keeps 14 days. Pro ($249/mo) keeps "30-day retention then $0.50 per GB per month", "Up to 180-day". Enterprise can "Define per-project retention" — [Pricing](https://www.braintrust.dev/pricing). SDK masking runs "before upload" — [Redact sensitive data](https://docs.braintrust.dev/sdks/python/redact-sensitive-data.md). A KB article is titled "Claude Agent SDK API keys recorded in trace metadata" — [KB](https://docs.braintrust.dev/kb/claude-agent-sdk-api-keys-recorded-in-trace-metadata.md)
- **Traction.** An $80M Series B on 17 Feb 2026 led by ICONIQ, at $800M post-money (press) — [SiliconANGLE](https://siliconangle.com/2026/02/17/braintrust-breaks-80m-series-b-funding-round-become-observability-layer-ai/); [Axios](https://www.axios.com/pro/enterprise-software-deals/2026/02/17/ai-observability-braintrust-80-million-800-million)

##### Arize (Phoenix OSS and AX) — `coding-harness-tracing` hook plugins (OpenInference spans)
- **Records.** One trace per turn, LLM spans (model, tokens) and tool spans ("inputs, outputs, and duration": Bash, Read, Edit…). `ARIZE_LOG_PROMPTS`, `ARIZE_LOG_TOOL_DETAILS` and `ARIZE_LOG_TOOL_CONTENT` all default to `"true"`, so content capture is on by default. The Python Agent SDK lacks `PermissionRequest` and other hooks — [Arize, Claude Code](https://arize.com/docs/phoenix/integrations/coding-agents/claude-code)
- **Harnesses.** Claude Code, Codex, Copilot, Gemini CLI (Phoenix) and Cursor (AX) — [Phoenix docs index](https://arize.com/docs/phoenix/llms.txt); [AX docs index](https://arize.com/docs/llms.txt). "Install Phoenix as a Claude Code, Cursor, or Codex plugin" (14 Sep 2026) — [release notes](https://arize.com/docs/phoenix/release-notes/09-2026/09-14-2026-coding-agent-plugins-and-error-analysis)
- **Retention and price.** AX Free keeps 15 days and AX Pro ($50/mo) 30 days — [Pricing](https://arize.com/pricing). Phoenix had 12,083 stars (Elastic License 2.0) — [repo](https://github.com/Arize-ai/phoenix). A $70M Series C (20 Feb 2025, press) — [TechCrunch](https://techcrunch.com/2025/02/20/arize-ai-hopes-it-has-first-mover-advantage-in-ai-observability/)

##### AgentOps
- No coding-agent integration was found. The docs index lists an Anthropic API integration only — [docs index](https://docs.agentops.ai/llms.txt). 5,933 stars, last push 25 Jun 2026 (GitHub API).

##### Laminar (lmnr) — Claude Code and Codex plugins
- "each turn becomes a full trace with its LLM calls, tool executions, and subagents", attributed to the `lmnr-cli login` identity — [Laminar, Claude Code](https://laminar.sh/docs/integrations/claude-code.md). Harnesses: Claude Code, Codex, OpenCode, Pi and the Claude Agent SDK. Self-hosting via Docker Compose or Helm — [Self-hosting](https://laminar.sh/docs/self-hosting/overview.md). Retention: Free 7 days, Starter ($30/mo) 30 days, Pro ($150/mo) 6 months — [Pricing](https://laminar.sh/pricing). 3,465 stars, Apache-2.0.

##### Datadog — Agent Console (Preview)
- Claude Code arrives through the Anthropic Usage and Costs integration ("daily spend and user analytics") or native OTel. Codex arrives as "Daily usage, credits, code attribution, and review analytics", and Cursor and Copilot as daily spend. Claude Desktop, Codex CLI, Cline, Windsurf and Zed come through "Trajectory, an open source tool, installed per user or via MDM"; what Trajectory sends is undocumented — [Datadog Agent Console setup](https://docs.datadoghq.com/ai_agents_console/setup/). The 9 Jun 2026 blog covers spend, sessions, lines, commits, PRs, behaviour patterns and "set a per-team cost alert" — [Datadog blog](https://www.datadoghq.com/blog/claude-code-monitoring/). A search snippet says LLM Observability "natively supports OpenTelemetry GenAI Semantic Conventions"; the page itself did not load — [Datadog LLM Obs](https://docs.datadoghq.com/llm_observability/instrumentation/)

##### Honeycomb and Grafana Cloud — dashboards on Claude Code's native OTel
- **Honeycomb.** Board templates; it recommends "an ingest key with create datasets turned off" — [Honeycomb blog](https://www.honeycomb.io/blog/measuring-claude-code-roi-adoption-honeycomb). Data is kept "60 days"; Pro "Starting at $150 / 50M events" — [Pricing](https://www.honeycomb.io/pricing)
- **Grafana Cloud.** The official "Claude Code" integration will "Track Claude Code usage, costs, and tool activity". It sends metrics and logs over OTLP with no traces exporter, and can be rolled out with managed settings — [Grafana integration](https://grafana.com/docs/grafana-cloud/monitor-infrastructure/integrations/integration-reference/integration-claude-code.md). Free keeps 14 days; paid keeps 13 months of metrics and 30 days of logs — [Pricing](https://grafana.com/pricing/)

##### Opik (Comet), Helicone, Sentry (dedicated pages only)
- **Opik.** The Claude Code plugin captures "every turn with full content". For Codex native OTel, "Prompt text and tokens go to the logs signal, which Opik does not ingest". Teammates can "share a session" — [Opik coding agents](https://www.comet.com/docs/opik/integrations/coding-agents.md). Cost Intelligence "runs a local proxy on each developer machine", and "Only counts, costs, and structural metadata are reported" — [Opik Cost Intelligence](https://www.comet.com/docs/opik/cost-intelligence/install/overview.md). There is also a "macOS menu-bar app and network extension for transparent capture" — [Opik docs index](https://www.comet.com/docs/opik/llms.txt). 23,068 stars.
- **Helicone.** A base-URL proxy for Claude Code, "maintained but no longer actively developed" — [Helicone, Claude Code](https://docs.helicone.ai/integrations/anthropic/claude-code.md). Retention tiers run "7 days, 1 month, 3 months, Forever" — [Pricing](https://www.helicone.ai/pricing)
- **Sentry.** The cookbook uses a personal-namespace hooks plugin. "Each Claude Code session appears as an invoke_agent root span" — [Sentry cookbook](https://sentry.io/cookbook/monitor-claude-code-with-sentry)

##### OpenTelemetry GenAI semantic conventions — status on 31 Oct 2026
- GenAI conventions moved to their own repo on 5 May 2026 ("Move GenAI semantic conventions to its own dedicated repository (#3696)") — [semantic-conventions](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/README.md). `open-telemetry/semantic-conventions-genai` has no releases or tags, and its README says "Schema URL: TODO". It is active (commits on 30 Oct 2026) — [repo](https://github.com/open-telemetry/semantic-conventions-genai)
- Every GenAI doc (spans, agent spans, events, MCP, A2A) is "**Status**: [Development]". Agent operations are `create_agent`, `invoke_agent`, `invoke_workflow` and `execute_tool` — [agent spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md); [registry](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/registry/attributes/gen-ai.md). The MCP conventions define `mcp.method.name`, `mcp.session.id` and `mcp.resource.uri`, and for `tools/call`, `gen_ai.operation.name` "SHOULD be set to `execute_tool`" — [MCP conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md)
- Nothing covers approvals, hooks, file edits, shell commands or network destinations, and there are no coding-agent conventions (repo tree reviewed).

##### Native OTel emitters among coding agents
- **Claude Code.** Mostly `claude_code.*` names, plus some `gen_ai.*` attributes; content is redacted by default — [Monitoring](https://code.claude.com/docs/en/monitoring-usage)
- **Codex.** `codex.*` names; disabled by default; prompts redacted unless enabled — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced)
- **Gemini CLI.** Telemetry is off by default, but **`logPrompts` defaults to `true`**. It emits `gemini_cli.*` events plus `gen_ai.client.inference.operation.details` — [Gemini CLI telemetry](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md)
- **GitHub Copilot (VS Code, CLI).** Spans `invoke_agent`, `chat`, `execute_tool` and `execute_hook`. "All signal names and attributes follow the OTel GenAI Semantic Conventions" (vendor claim). "By default, no prompt content, responses, or tool arguments are captured" — [VS Code, monitoring agents](https://code.visualstudio.com/docs/agents/guides/monitoring-agents)
- **Cursor.** No client-side native OTel; Enterprise OTel is server-side and has no traces — [Cursor OTel export](https://cursor.com/docs/enterprise/opentelemetry-export)


#### Agent runtime security and endpoint vendors
Most of these pages are marketing pages; treat their claims as vendor claims unless labelled otherwise. "(search excerpt)" marks a fact taken from a search-result excerpt rather than a page I opened. Not loaded: the Cato AI Endpoint blog (empty content: https://www.catonetworks.com/blog/cato-ai-endpoint-secures-browser-ai-desktop-ai-and-coding-agents-on-every-endpoint/) and the Cato support doc (HTTP 403: https://support.catonetworks.com/hc/en-us/articles/35507937898141-What-is-Local-AI-Agents-Security). Island and Jamf were not researched.

##### Lasso Security — AI Coding Assistants (hooks-based)
- **Coverage.** "Secure any coding assistant your developers use, including Claude Code, Cursor, Codex, and OpenCode, and more" (vendor claim). For Claude Code it "connects directly to Claude Code's lifecycle hooks via the enterprise management platform"; "there is no agent to install". Lasso "ships as both an open source tool and an enterprise deployment". The page does not say how Cursor, Codex or OpenCode are hooked — [Lasso](https://www.lasso.security/use-cases/ai-coding-assistants). The open-source `lasso-security/claude-hooks` shows 222 stars and a last push on 8 Jan 2026, per a third-party tracker — [gittrend](https://gittrend.io/repo/lasso-security/claude-hooks) (search excerpt)
- **Records.** "Lasso inspects every tool call before it is executed", along with "which MCPs are connected, what tools are being called" and ingested files, web responses and MCP outputs. "Every interaction is monitored and saved." Shell commands, hosts, model, tokens and identity fields are not documented — [Lasso](https://www.lasso.security/use-cases/ai-coding-assistants)
- **Storage, integrity, export, retention.** Not documented, apart from a "full exportable audit trail for compliance"; there is no integrity mechanism, format or SIEM connector — [Lasso](https://www.lasso.security/use-cases/ai-coding-assistants)
- **Pricing and traction.** No public pricing. A $30M round led by ClearSky (about 2 Sep 2026; Lasso claims "500%+" revenue growth) — [SiliconANGLE](https://siliconangle.com/2026/09/02/lasso-security-launches-cpu-only-ai-guardrail-raises-30m/) (press, search excerpt). A $6M seed (Nov 2023) — [Help Net Security](https://www.helpnetsecurity.com/2023/11/21/lasso-security-llm-cybersecurity/)

##### Zenity — device-based agents
- **Coverage.** It names "ChatGPT Codex", "Claude Enterprise (Chat, Cowork, and Code)", "Cursor" and "GitHub Copilot". It gets visibility through "native hooks" and "OpenTelemetry" and blocks through "native agent hooks and the Zenity MCP gateway". It argues that EDR/XDR "only see a trusted process" (vendor claim) — [Zenity](https://www.zenity.io/use-cases/agent-type/device-based)
- **Records.** "the prompts, tool calls, commands, memory, and data an agent uses", "the MCP servers and tools it invokes", and "the code and data it touches". Zenity "can block or modify a dangerous tool call before it executes". Storage, retention, export and integrity are not documented; "audit trails" is mentioned only under "Prove governance" — [Zenity](https://www.zenity.io/use-cases/agent-type/device-based)
- **Traction.** A $125M Series C on 3 Aug 2026, led by Norwest, bringing the total to about $180M — [SecurityWeek](https://www.securityweek.com/zenity-raises-125-million-in-series-c-funding/) (press, search excerpt); about $185M per [Dealroom](https://dealroom.co/news/142790-zenity-raises-125m-to-secure-enterprises-ai-agents). A $38M Series B in Oct 2024 — [Zenity newsroom](https://zenity.io/company-overview/newsroom/company-news/zenity-raises-38m-series-b-funding-round-to-secure-agentic-ai)

##### Noma Security — Claude Code Hooks Plugin (Beta)
- **Coverage.** "Runtime Protection for Claude Code Agents" that "sits between your AI agents and their intended actions" to "evaluate, allow, or block high-risk activities in real-time". It covers "Shell execution", "MCP tool execution", "File reads" and "User prompt submission". The plugin "is currently in **Beta** status", and Noma "may decide to suspend further work on this feature". The README does not mention Cursor — [Noma README](https://github.com/Noma-Security/claude-marketplace)
- **Records and storage.** "real-time allow/block events" appear in the Noma Console under "Runtime Protection → Inferences", filtered by application ID. Payload fields are not specified. The API key is issued by a Noma TAM — [Noma README](https://github.com/Noma-Security/claude-marketplace)
- **Redaction.** It "Scans and filters sensitive data, PCI, PII, PHI before it leaves your local environment" and blocks ".env files, SSH keys" — [Noma README](https://github.com/Noma-Security/claude-marketplace)
- **Traction.** A $100M Series B on 31 Jul 2025, led by Evolution Equity, for $132M total — [SiliconANGLE](https://siliconangle.com/2025/07/31/ai-security-startup-noma-security-closes-100m-funding-round/) (press, search excerpt)

##### Prompt Security (SentinelOne)
- **Coverage.** It names GitHub Copilot, Cursor and Claude Code ("without exposing IP or secrets"), and offers to "Map every agent and MCP server in your environment". Policies are "enforced at the point of interaction", but the delivery mechanism is unspecified — [SentinelOne](https://www.sentinelone.com/platform/securing-ai-prompt/). A Claude Compliance API integration scans prompts and responses "without requiring a browser extension or endpoint agent" — [SentinelOne blog](https://www.sentinelone.com/blog/sentinelone-and-claude-integrations-for-ai-visibility-governance-and-defense/) (search excerpt)
- **Records and redaction.** "a searchable audit log of every agent action, decision, and enterprise system interaction". It can "Redact sensitive data and enforce policies across 15,000+ AI services in real time". Storage, export, retention and integrity are not documented — [SentinelOne](https://www.sentinelone.com/platform/securing-ai-prompt/)
- **Traction.** The acquisition was announced 5 Aug 2025 — [SentinelOne press](https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security-to-advance-genai-security/). It closed 5 Sep 2025 for "approximately $133.6 million in cash, 1,555,099 shares… and 415,109 assumed options" (fair value about $159.3M) — [SentinelOne 10-Q](https://www.sec.gov/Archives/edgar/data/1583708/000158370825000159/s-20251031.htm) (search excerpt). Named customers are 10x Banking and Carnival — [SentinelOne](https://www.sentinelone.com/platform/securing-ai-prompt/)

##### Pillar Security — Pillar for AI Coding Agents (launched 5 Feb 2026)
- **Coverage.** Claude Code, Cursor, Codex, Antigravity, GitHub Copilot and OpenClaw. "Pillar scans every workstation", including the `.cursor`, `.claude` and `.continue` directories. It does "Monitor agent actions during execution", but the mechanism is not described — [Pillar blog](https://www.pillar.security/blog/introducing-pillar-for-ai-coding-agents)
- **Records.** Behavioural baselines of "file access, command execution sequences, network communications, and tool invocations"; context-window injection monitoring; and tracking of credentials or PII sent to external endpoints. It can "terminate compromised sessions, or block specific operations". Storage is not documented; a navigation label reads "Cloud, Self-Hosted & Hybrid" — [Pillar blog](https://www.pillar.security/blog/introducing-pillar-for-ai-coding-agents)
- **Traction.** A $9M seed on 16 Apr 2025, led by Shield Capital — [Shield Capital](https://shieldcap.com/newsroom/pillar-security-raises-9m-in-seed-funding-to-tackle-ai-specific-cyber-threats)

##### Aim Security (Cato Networks)
- **Coverage (all search excerpts).** Cato says it enforces policy on tool calls from Claude Code, Cursor and Codex, and inspects prompts, responses and tool calls — [Cato AI Security](https://www.catonetworks.com/solutions/ai-security/). It uses Anthropic "Inference Hooks" across Claude Chat, Claude Code and Cowork "with no endpoint agent or inline network access". Audit records are tied to users and devices through a Scout client installed as a Claude Code plugin — [Cato blog](https://www.catonetworks.com/blog/how-cato-ai-security-keeps-up-with-claude/). It also ingests the Claude Compliance API — [Cato blog](https://www.catonetworks.com/blog/cato-integration-claude-compliance-api/)
- **Traction.** The acquisition was announced 3 Sep 2025 with undisclosed terms. Cato reported more than $300M ARR — [Cato press](https://www.catonetworks.com/?p=134806) (search excerpt); [Help Net Security](https://www.helpnetsecurity.com/2025/09/04/cato-networks-aim-security/) (press)

##### Protect AI (Palo Alto Networks) — Prisma AIRS with Cortex Agentic Endpoint Security (AES)
- **Coverage.** "Claude Code, Cursor, Codex, GitHub Copilot, and Antigravity" on developer endpoints. AES "deploys and manages the AIRS hooks on each device", and rules are pushed from Strata Cloud Manager — [PANW docs](https://docs.paloaltonetworks.com/prisma-airs/ai-runtime-security/airs-api/prisma-airs-integration-with-cortex-aes)
- **Records.** It inspects prompts before and after the LLM, external MCP tool calls before execution, and WebFetch/WebSearch calls. AES "records every verdict in the AES portal", attributed to device, agent, session and policy. Shell and file activity are not mentioned. It "returns masked text in place of the original content", and AES "informs the developer inside the agent's chat" — [PANW docs](https://docs.paloaltonetworks.com/prisma-airs/ai-runtime-security/airs-api/prisma-airs-integration-with-cortex-aes)
- **Traction.** The acquisition completed 22 Jul 2025 — [PANW press](https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-protect-ai/). Total consideration was $634.5M — [PANW 10-K](https://www.sec.gov/Archives/edgar/data/1327567/000132756725000027/panw-20250731.htm) (search excerpt)

##### CrowdStrike — Falcon AIDR (from Pangea), now Falcon Guardian
- **Coverage.** AIDR "connects to Claude Code's own hook event system" by "adding a block of JSON in the Claude Code settings file", and it "coexists with any hooks a team already runs" — [CrowdStrike blog, 30 Jul 2026](https://www.crowdstrike.com/en-us/blog/falcon-aidr-protects-copilot-studio-agents-and-claude-code/). Collectors: Claude Code, an MCP Proxy ("Claude Desktop, VS Code, Cursor, custom agents"), browser extensions, Windows Network Inspection, LLM gateways (LiteLLM, Portkey, Kong), an OTel Collector and Bedrock logs. AIDR "reaches end of support on November 30, 2026" — [AIDR docs](https://aidr-docs.crowdstrike.com/docs/aidr/collectors). Falcon Guardian covers Codex agents under the OpenAI partnership — [CrowdStrike press](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-and-openai-expand-partnership-to-secure-the-agentic-era/) (search excerpt)
- **Records.** The Claude Code collector takes "User prompts and tool calls" and "captures only data that passes through Claude Code hook events". It does not capture LLM responses, model configuration or token usage. Redaction applies to tool inputs and outputs, not to user prompts — [AIDR docs](https://aidr-docs.crowdstrike.com/docs/aidr/collectors). Events "can be tied back to a specific Claude Code session and user in Falcon Next-Gen SIEM" — [CrowdStrike blog](https://www.crowdstrike.com/en-us/blog/falcon-aidr-protects-copilot-studio-agents-and-claude-code/)
- **Traction.** The Pangea deal was announced 16 Sep 2025 — [CrowdStrike IR](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-pangea-secure-every-layer-enterprise-ai) — and closed 26 Sep 2025 for $212.1M cash plus awards — [CrowdStrike 10-Q](https://www.sec.gov/Archives/edgar/data/1535527/000153552725000033/crwd-20251031.htm) (search excerpt). A conflicting $252.7M excerpt may belong to the Seraphic deal.

##### Microsoft Defender for Endpoint — local AI agent discovery and runtime protection (preview)
- **Coverage.** Discovery "identifies local AI agents and their configured Model Context Protocol (MCP) servers on onboarded devices" and is "activity based". About 60 Windows agents are listed, including Claude Code, Codex CLI, Cursor, Gemini CLI, Copilot CLI, Windsurf and OpenCode; macOS and WSL are in preview. Runtime protection (preview) uses "Agent-native event inspection" for Claude Code, Copilot CLI and the VS Code extensions, in audit or block mode. Cursor, Codex and Gemini CLI are discovery-only. "Network inspection covers agents that communicate with LLMs through well-known inference services. It doesn't cover agents that use certificate pinning or HTTP/3." Data lands in the `AgentsInfo` advanced-hunting table (KQL) — [MS Learn, AI agent support matrix (ms.date 7 Oct 2026)](https://learn.microsoft.com/defender-endpoint/ai-agent-support-matrix)

##### Netskope and Zscaler (brief; search excerpts, vendor claims)
- **Netskope.** Client AI Discovery scans for agents, local MCP servers and IDE extensions — [docs](https://docs.netskope.com/en/netskope-client-ai-discovery). Agent Action Control blocks, allows or alerts per agent action — [product](https://www.netskope.com/products/agent-action-control). The Claude Compliance API integration is visibility-only, and a pre-inference hook covers Claude Code — [Netskope community](https://community.netskope.com/blogs-21/securing-anthropic-s-claude-at-enterprise-scale-netskope-one-ai-security-for-claude-enterprise-and-claude-platform-8716)
- **Zscaler.** AI Endpoint Security covers VS Code, Cursor and Windsurf, monitoring "tool and function calls" — [Zscaler blog](https://www.zscaler.com/blogs/product-insights/ai-endpoint-security-closes-zero-trust-gap)

##### Hook-mechanism caveats that affect every hook-based vendor
- Cursor's mapping of Claude Code hooks does not carry over `PermissionRequest` or `Notification` events, and "Other non-zero exit codes fail open" — [Cursor, third-party hooks](https://cursor.com/docs/reference/third-party-hooks)
- Code already running inside the agent process can likely sidestep userspace hooks (vendor analysis) — [Endor Labs](https://www.endorlabs.com/learn/when-the-guardrails-slip-the-case-for-hook-based-governance-across-agent-platforms) (search excerpt)


#### Gateways (researched directly, 31 Oct 2026)

##### Tailscale Aperture (AI gateway; GA blog dated 26 Aug 2026)
- **Records.** Request capture includes the "full body" and headers; response capture includes the "full response body", status and headers; token counts by type (input, output, cached, reasoning); model name; duration; tool-use count. Each metric record includes "the login name and device ID"; tagged devices get a synthetic identity built from sorted tags. Sessions are grouped by a session ID found in the Claude Code request body or the Codex HTTP header. OpenAI Chat sessions are fingerprinted from content, and other clients get a random ID per request, so their requests "cannot be grouped". Tool extraction can be turned off with `purge: ["captures", "tools"]` — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md)
- "Aperture records token counts, model names, sessions, and tool use for LLM requests". Captured bodies include `tool_use` and `tool_result` blocks from MCP tool calls. "Aperture does not record connector requests, errors, latency, tokens, or cost" for HTTP connector proxy traffic — [Observe and export](https://tailscale.com/docs/aperture/observe-and-export)
- **Storage and readers.** Users see only their own sessions and usage. Admins filter organization-wide views by user and inspect captured content under Security > Logs. Roles are granted by Tailscale identity — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md); [Observe and export](https://tailscale.com/docs/aperture/observe-and-export). The privacy page describes a "managed" gateway that is a node on the customer's tailnet. It mentions database backups, and Tailscale support can restore a decommissioned gateway during a 7-day grace period, which implies Tailscale operates the storage. It does not say whether Tailscale staff can read captures — [Privacy and data retention](https://tailscale.com/docs/aperture/privacy-and-data-retention). The product page says "We're currently experimenting with multiple deployment options" — [Aperture](https://tailscale.com/aperture)
- **Integrity.** Traffic is encrypted in transit (Tailscale, then TLS upstream), and identity comes from the Tailscale control plane. No encryption at rest, signing or tamper evidence is documented — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md)
- **Harnesses.** Claude Code, Codex, Gemini CLI, Roo Code, Cline and "any coding agent that allows the end user to replace the base URL" — [Aperture](https://tailscale.com/aperture). It sees only LLM and MCP traffic routed through it. Local tool calls are reconstructed from LLM request bodies ("Extracts MCP and local tool calls from popular agents") — [Aperture](https://tailscale.com/aperture)
- **Export.** S3 export of "LLM usage data". Integrations reach "external services such as log aggregators and authorization engines", but no SIEM or OTel target is named — [Observe and export](https://tailscale.com/docs/aperture/observe-and-export). Guardrails are synchronous pre-request hooks: beta, with no post-response guardrails and no coverage of MCP or connector traffic. Cerbos and Oso integration hooks run asynchronously after responses, and Highflame combines both modes — [Aperture guardrails](https://tailscale.com/docs/aperture/guardrails) (search summary); [Cerbos Synapse for Aperture](https://docs.cerbos.dev/synapse/latest/usecases/aperture) (search summary). `tailscale.com/docs/aperture/integrations` returned HTTP 404.
- **Retention and deletion.** Duration, `purge` and `require_export` are configurable, and export to S3 can be required before purge. Zero retention keeps no bodies or headers, but usage metrics remain. It "does not delete Chat conversation history" and does not stop most hooks from sending content. After decommission and a 7-day grace period, "All request and response bodies, headers, tool-call details, and database backups are destroyed." — [Privacy and data retention](https://tailscale.com/docs/aperture/privacy-and-data-retention); [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md)
- **Redaction.** Upstream auth header values and `add_headers` are redacted. "Other headers… stay in plaintext". No PII redaction is described — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md)
- **Search, replay, sharing, alerting.** The Logs page groups requests by session, and admins can filter by user. Rate limits and spend caps can be set per agent, team or org. No alerting or sharing is described — [Aperture](https://tailscale.com/aperture)
- **Pricing and traction.** The GA post gives no price: each instance has "some initial tokens included" — [Tailscale blog](https://tailscale.com/blog/aperture-ga). The product page fetched on 31 Oct 2026 still says "We do not have published pricing during the current Alpha and Beta period" and "Aperture is available via self-serve now!" — [Aperture](https://tailscale.com/aperture). The pricing page lists Aperture under "Platform extensions", available "by reaching out to our sales team" — [Tailscale pricing](https://tailscale.com/pricing). The prior round's "six-user free tier" came from a search summary and is **not confirmed** on these pages. Vendor-shown logos are Perplexity, Microsoft and Instacart (vendor claim) — [Aperture](https://tailscale.com/aperture)

##### Coder AI Gateway (formerly AI Bridge) and Agent Firewall (formerly Agent Boundaries)
- **Records (gateway).** Stored: the "last user prompt" (only the last prompt from a block of `role="user"` messages), token usage, "Tool calls (requests only, not responses)", and model reasoning when available, plus Agent Firewall counts (total, blocked, top domains). Not stored: "Model-produced inference text is discarded, as generated text alone cannot affect external systems". Tool responses are also dropped. "AI Gateway cannot declare with certainty whether a request was human- or agent-initiated." — [Coder, Audit AI sessions](https://coder.com/docs/ai-coder/ai-gateway/audit)
- **Records (firewall).** Agent Firewall is "a process-level firewall that restricts and audits what autonomous programs, such as AI agents, can access and use". Each HTTP request logs the allow/deny decision, method, full URL, workspace ID, name and owner, template, time, and the matched allow rule. HTTP status is not tracked. It covers HTTP only, and in landjail mode "data can leak over UDP". Logs are "emitted as structured log entries from the Coder server" — [Coder, Agent Firewall](https://coder.com/docs/ai-coder/agent-firewall)
- **Storage and readers.** Records are written to the self-hosted Coder deployment's database — [Setup](https://coder.com/docs/ai-coder/ai-gateway/setup). The gateway runs in `coderd` or standalone and "supports clients running inside or outside Coder workspaces" — [AI Gateway](https://coder.com/docs/ai-coder/ai-gateway). A commit in an unofficial mirror of Coder's source says only `owner` or site-wide `auditor` roles can read interceptions, and members cannot read back even their own. This is not confirmed in the official docs — [mirror](https://git.dragonfruit.dev/mirror/coder/src/branch/main/coderd/rbac) (search summary)
- **Integrity.** None documented.
- **Harnesses.** Supported: Claude Code, Codex CLI, OpenCode, Factory, Cline, Kilo Code, VS Code 1.122+, JetBrains (chat only), Junie, Zed, and GitHub Copilot (through AI Gateway Proxy with per-user GitHub tokens). Unsupported: Cursor (base-URL override "broken"), Amp, Kiro, Antigravity and "Devin Desktop (formerly Windsurf)" ("No option to override base URL"), and Gemini CLI ("No Gemini API support") — [Clients](https://coder.com/docs/ai-coder/ai-gateway/clients)
- **Export.** Prometheus `coder_ai_gateway_*` metrics, OTLP/gRPC trace spans (`Intercept`, `Intercept.ProcessRequest.ToolCall`, `Intercept.RecordTokenUsage`, …), structured interception logs that "can emit a structured log for every interception record to an external SIEM or observability platform", and a REST API at `GET /api/v2/ai-gateway/sessions` with filters by client, initiator, provider, model and time — [Monitoring](https://coder.com/docs/ai-coder/ai-gateway/monitoring). The span names are Coder-specific, not GenAI semantic-convention names (inference from the names).
- **Retention.** "By default, this data is retained for 60 days". It is configurable, and "Set to `0` to retain data indefinitely" — [Setup](https://coder.com/docs/ai-coder/ai-gateway/setup)
- **Redaction.** `disable_content_recording` stops storing prompts, tool inputs and reasoning, while token and interception records remain. "Sensitive headers are redacted before dumps are written". Forwarding user email to providers is off by default — [Setup](https://coder.com/docs/ai-coder/ai-gateway/setup)
- **Search.** Sessions can be filtered by user, time and client. Session detail can be searched across "prompt text, tool names, tool inputs, and network call destinations" — [Audit](https://coder.com/docs/ai-coder/ai-gateway/audit)
- **Pricing.** "AI Gateway is part of AI Governance, which is included with a Premium license" — [AI Gateway](https://coder.com/docs/ai-coder/ai-gateway). The Agent Firewall page says the same — [Agent Firewall](https://coder.com/docs/ai-coder/agent-firewall). GA was 3 Feb 2026 (v2.30), as an add-on — [Coder blog](https://coder.com/blog/secure-agentic-ai-now-production-ready) (prior round). The Premium list price was not checked.

##### Cloudflare MCP server portals, AI Gateway and Zero Trust DLP logging
- **MCP portal log fields.** ClientCountry, ClientIP, ColoCode, Datetime, Error, Method (JSON-RPC, e.g., `tools/call`, `prompts/get`, `resources/read`), PortalAUD/ID, PromptGetName, ResourceReadURI, ServerAUD/ID/URL, ServerResponseDurationMs, SessionID, Success, ToolCallName, UserEmail and UserID. There are **no tool arguments, no results and no prompt text**: the "prompt activity" is the *name* of an MCP prompt template fetched — [Cloudflare, mcp_portal_logs dataset](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/index.md)
- **MCP portal features.** The dashboard shows Time, Status, Server, Capability and Duration. Logpush export of `mcp_portal_logs` is Enterprise-only. With Gateway routing on, "Gateway inspects the traffic and applies any matching HTTP policies, including DLP scanning" of tool requests and responses, but "AI prompt DLP profiles do not apply to portal traffic". Clients named are Claude Desktop, Workers AI Playground, OpenCode, Windsurf and MCP Inspector (page last updated 28 Oct 2026) — [MCP portals docs](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals). Logpush for portals was announced 27 Feb 2026 — [changelog](https://developers.cloudflare.com/changelog/post/2026-02-27-mcp-portal-logpush/) — and the dataset was added 9 Mar 2026 — [changelog](https://developers.cloudflare.com/changelog/post/2026-03-09-log-fields-updated/)
- **AI Gateway logs.** "Each log can include the prompt, response, provider, timestamp, status, token usage, cost, duration, and user agent." "Logs are enabled by default". A per-request `cf-aig-collect-log` header and `cf-aig-collect-log-payload: false` (keep metadata, drop bodies) control collection. DLP fields record FLAG/BLOCK and the policies matched. Gateways created on or after 24 Sep 2026 follow Workers Logs pricing and retention — [AI Gateway logging](https://developers.cloudflare.com/ai-gateway/observability/logging/). Legacy limits are 100,000 logs per account (free) and 10M per gateway (paid) — [limits](https://developers.cloudflare.com/ai-gateway/reference/limits) (search summary)
- **Encryption to customer keys (a partial positive for vendor-blind storage).** AI Gateway Logpush encrypts each log with an AES key wrapped in the customer's RSA public key: "only someone with the corresponding RSA private key can decrypt". The page does not explicitly say that Cloudflare cannot — [AI Gateway Logpush](https://developers.cloudflare.com/ai-gateway/observability/logging/logpush/). Zero Trust DLP payload logs are encrypted with a customer public key: "Cloudflare does not have access to your private key and cannot decrypt your logs". They store "a redacted version of the match" plus "75 bytes of additional context on both sides". AI prompt logging captures "the user prompt and AI model's raw response if available" for supported apps such as ChatGPT. By contrast, Logpush "forensic copies" are "encrypted in transit only" (Enterprise) — [DLP logging options](https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/dlp-policies/logging-options/)
- **Integrity.** No signing or hash chaining of logs is documented on these pages.

#### Signed or hash-chained agent records outside commercial products
- **Agent Receipts / Obsigna.** An "open protocol for producing cryptographically signed, tamper-evident records of AI agent actions". Components: `obsigna-mcp` ("MCP stdio proxy — signs every tool call, adds policy hooks"), `obsigna-daemon` ("Out-of-process signing daemon — holds the key, owns the audit chain") and `obsigna-hook` ("PostToolUse hook for Claude Code and other runtimes"). It uses Ed25519 and offers proxy setup for Claude Desktop, Claude Code and Codex. Its chain invariants are model-checked with Alloy. Its own caveat: with an in-process key, "anyone with code execution in the agent can forge receipts" — [README](https://github.com/agent-receipts/obsigna). It was created 2 Apr 2026, had 20 stars on 31 Oct 2026, and is Apache-2.0 (GitHub API).
- **Smaller projects.** `webaesbyamin/agent-receipts` (1 star, created 8 Feb 2026: "Signed receipts… Verify offline. Local-first"), `chintanonweb/veritrace` (0 stars, created 29 Jun 2026: Ed25519, Merkle proofs, Arweave anchoring) and `joy7758/verify-agent-receipt-action` (0 stars) — GitHub API, 31 Oct 2026.
- **IETF drafts (individual, not WG-adopted).** `draft-sharif-agent-audit-trail-09` (26 Oct 2026) chains records with SHA-256 over JCS-canonical JSON, with optional ECDSA signatures, hashed inputs and outputs, and tombstone erasure that "keep[s] the chain verifiable"; it is "not endorsed by the IETF" — [datatracker](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/). `draft-stone-aivs-00` (Mar 2026) describes a SHA-256 row-chained session log with Ed25519 and proof bundles. Per a search summary, it notes that OTel, LangSmith and Langfuse provide no cryptographic guarantees — [datatracker](https://datatracker.ietf.org/doc/html/draft-stone-aivs). `draft-ruvalcaba-nhe-audit-00` (Aug 2026) — [IETF mirror](https://ftp.kaist.ac.kr/ietf/draft-ruvalcaba-nhe-audit-00.html) (search summary).
- **Academic work (search summaries only).** Agent Flight Recorder (arXiv 2609.01931): tamper-evident trails with on-chain anchoring; it guarantees integrity of recorded events, "not that all events reach the recorder". NovaFabric (arXiv 2609.12582). aiAuthZ (arXiv 2607.05518) clears encrypted payloads while keeping hashes, so erasure and verifiability coexist — [search results](https://arxiv.org/pdf/2609.01931)



### Inferences
- **Five silos, and no product spans them.** Local transcripts know what happened on the device but cover one harness and are plaintext. Vendor feeds are team-readable but miss on-device actions: Anthropic's sessions "show what Claude was asked to do and what it returned, not what occurred on the device", and OpenAI says "Conversation visibility alone does not establish a complete record of local actions". Gateways see only traffic that passes through them. Git-stored records are readable by everyone with repo access. Security logs are verdicts held in the security vendor's SaaS.
- **Harness vendors are extending their own records to local sessions.**
  - GitHub's session streaming (preview, 2 Jul 2026) covers the CLI, VS Code and JetBrains.
  - Anthropic's Compliance API returns local Claude Code transcripts.
  - Claude Code added `tool_decision` sources (Oct 2026) and beta traces.

  Each vendor builds a better record of its own harness. That makes neutrality across harnesses the defensible position, not record-keeping as such.
- **Consolidation is removing the independent record vendors.**
  - git-ai's team joined OpenAI Codex (11 Sep 2026).
  - SpaceX agreed to buy Cursor (16 Jun 2026; press).
  - ClickHouse acquired Langfuse (16 Jan 2026).
  - Palo Alto, SentinelOne, Cato and CrowdStrike absorbed the 2025 agent-security startups. CrowdStrike's AIDR reaches end of support on 30 Nov 2026.
  - Entire pivoted to a forge and dropped rewind.
  - Agent Trace stalled at v0.1.0 and its repo returns 404.

  A neutral, cross-harness record is now under-supplied.
- **Signing alone is not a moat.** Anthropic already runs C2SP tlog-tiles infrastructure, Entire signs checkpoint commits, and GitHub signs agent commits. The combination nobody offers is signing, customer-held keys and cross-harness coverage together.
- **There is room to define record types.** Formats are vendor-specific (`claude_code.*`, `codex.*`, `cursor.*`, `gemini_cli.*`, `github.copilot.*`). The GenAI semantic conventions are Development-only and say nothing about approvals, file edits, shell commands or network destinations. A sidecar could define record types and map them to `invoke_agent`, `execute_tool` and the MCP conventions.
- **"Rewind" is narrow and fading.** Claude Code and Cursor restore files edited through their own tools only. Codex rollback is context-only, and Entire removed file restore. "What it left for the next run" fits handoff and resume better: Amp handoff, SpecStory's cross-agent `resume` and Entire's continuous memory are the nearest analogs.

### Gaps
- **Pages that failed:**
  - `https://specstory.com/pricing` (404)
  - `https://github.com/cursor/agent-trace` (404, on the web and via the API)
  - `https://tailscale.com/docs/aperture/integrations` (404)
  - Cato AI Endpoint blog (empty) and Cato support doc (403)
  - `https://help.openai.com/en/articles/9261474-openai-compliance-platform-for-enterprise-customers` (403)
  - Datadog LLM Observability instrumentation page (did not load)
  - AgentOps pricing (did not render)
- **Pages not opened (budget):** GitHub artifact-attestation (Sigstore) docs and content-exclusion docs; Cursor's "Data Encryption and CMEK" and Analytics API docs; Amp's Streaming JSON, Egress IPs and MCP allowlist pages; the Arize AX audit-log page; Laminar's PII redaction page; the Codex App Server rollback method.
- **Unverified points:**
  - Aperture's hosting model and Tailscale staff access to captures.
  - Aperture pricing: the "six-user free tier" from the prior round conflicts with the product page ("We do not have published pricing") and the pricing page ("reaching out to our sales team").
  - Coder roles: who can read AI Gateway sessions comes from an unofficial source mirror.
  - Whether Codex API-key usage is excluded from the Compliance API, and the full `codex_log` schema.
  - Whether Claude Code JSONL stores approval entries, and whether `claude_code.safety_event` returns.
  - Whether GitHub session streaming includes tool arguments and model.
  - Entire forge RBAC/SSO, and whether Entire records the model.
  - Funding for SpecStory, AgentOps and Laminar; Datadog pricing and retention; Cursor ARR (aggregator only).
  - Whether the SpaceX–Anysphere deal has closed.
  - OCSF 1.9 "Record Integrity structures", seen only second-hand via the AAIF working group.
- **Not researched:** Island and Jamf. W&B Weave was excluded because it has no coding-agent page.



## 2. Which features are table stakes, and which are absent everywhere?

### Takeaway
**Table stakes** (offered by most tools): prompt and tool-call capture, model, token and cost metadata, per-user identity, export to OTel, SIEM or JSON, content capture that is off or redacted by default, best-effort secret redaction in shared stores, session search and resume, whole-session sharing, and pre-execution allow/deny hooks.

**Absent from every commercial agent-work record:**
- vendor-blind encryption;
- approvals cryptographically bound to the executed action;
- third-party verifiability;
- cryptographic selective disclosure;
- per-record or per-client crypto-erasure;
- per-client keyed partitions;
- message and inbox provenance.

**Present only in single-vendor silos:** cross-harness capture with local actions, and network-reach records.

### Cited Findings

#### Table stakes (offered by most tools)
- **Prompt and tool-call capture in some form.**
  - Harness records: Claude Code JSONL ("messages, tool calls, and tool results") — [.claude directory](https://code.claude.com/docs/en/claude-directory); Codex rollouts (`LocalShellCall`, `FunctionCall`/`Output`) — [policy.rs](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/policy.rs); GitHub cloud-agent logs ("prompts and responses, tools used, and changes made to files") — [Session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data); Amp threads — [Threads](https://ampcode.com/docs/threads).
  - Provenance and observability: Entire — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md); Langfuse — [Langfuse](https://langfuse.com/integrations/other/claude-code).
  - Gateways: Aperture's "full body" captures — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md).
  - Exceptions are attribution-only or metrics-only products: git-ai notes, Agent Trace, Cursor Blame, usage-metrics APIs, Cursor's audit log ("never prompts, agent output") — [Cursor compliance](https://cursor.com/docs/enterprise/compliance-and-monitoring) — and MCP portal logs, which hold names only — [mcp_portal_logs](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/index.md).
- **Model, token and cost metadata.**
  - Harness telemetry: Claude Code `cost.usage` and `token.usage` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage); Codex `codex.sse_event` token counts — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced); Cursor's OTel cost ("best-effort USD estimate") — [Cursor OTel](https://cursor.com/docs/enterprise/opentelemetry-export).
  - Records and gateways: Entire `token_usage` — [Sessions and checkpoints](https://github.com/entireio/cli/blob/HEAD/docs/architecture/sessions-and-checkpoints.md); Aperture token counts by type — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md); Cloudflare AI Gateway cost — [AI Gateway logging](https://developers.cloudflare.com/ai-gateway/observability/logging/).
- **Per-user identity on records.**
  - Claude Code `user.email` — [Monitoring](https://code.claude.com/docs/en/monitoring-usage).
  - GitHub `actor_is_agent` plus `user` — [Agentic audit events](https://docs.github.com/en/copilot/reference/agentic-audit-log-events).
  - Cloudflare `UserEmail` — [mcp_portal_logs](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/index.md).
  - Aperture "login name and device ID" — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md).
  - Cursor hook `user_email` — [Cursor hooks](https://cursor.com/docs/agent/hooks).
- **Export to SIEM, OTel or JSON. Formats are vendor-specific.**
  - SIEM: GitHub streams to 7 destinations — [Audit-log streaming](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise); Cursor to Splunk, Sumo, webhook or S3 — [Cursor compliance](https://cursor.com/docs/enterprise/compliance-and-monitoring); Anthropic claims "over 100+" partners (vendor claim) — [Claude blog](https://claude.com/blog/compliance-api-security-partners); Coder emits structured logs — [Coder monitoring](https://coder.com/docs/ai-coder/ai-gateway/monitoring); Cloudflare has Logpush — [MCP portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals).
  - Semantic-convention adoption is partial. Claude Code has some `gen_ai.*` attributes — [Monitoring](https://code.claude.com/docs/en/monitoring-usage). Copilot claims full adoption (vendor claim) — [VS Code monitoring](https://code.visualstudio.com/docs/agents/guides/monitoring-agents). Codex and Cursor use `codex.*` and `cursor.*` — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced); [Cursor OTel](https://cursor.com/docs/enterprise/opentelemetry-export). The conventions themselves are all "Development" — [semconv-genai](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md).
- **Content capture off or redacted by default.**
  - Harness telemetry: Claude Code prompts are "Redacted by default" — [Monitoring](https://code.claude.com/docs/en/monitoring-usage). Codex prompt content is "redacted unless explicitly enabled" — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced). Cursor content is "off by default" — [Cursor OTel](https://cursor.com/docs/enterprise/opentelemetry-export). Copilot: "By default, no prompt content, responses, or tool arguments are captured" — [VS Code monitoring](https://code.visualstudio.com/docs/agents/guides/monitoring-agents).
  - Gateways: Coder `disable_content_recording` — [Coder setup](https://coder.com/docs/ai-coder/ai-gateway/setup); Cloudflare `cf-aig-collect-log-payload` — [AI Gateway logging](https://developers.cloudflare.com/ai-gateway/observability/logging/).
  - Exceptions: Gemini CLI's `logPrompts` defaults to `true` — [Gemini CLI telemetry](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md). Arize's `ARIZE_LOG_PROMPTS` defaults to `"true"` — [Arize](https://arize.com/docs/phoenix/integrations/coding-agents/claude-code).
- **Best-effort secret redaction where records are shared or synced.**
  - Entire runs seven passes — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md). SpecStory uses Betterleaks by default — [changelog](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/changelog.md). Amp uses `[REDACTED:amp]` — [Amp security](https://ampcode.com/security). Cursor redacts cloud-agent transcripts — [Cloud agent security](https://cursor.com/docs/cloud-agent/security-network). LangSmith's plugin uses `[SECRET_DETECTED]` — [LangSmith](https://docs.langchain.com/langsmith/trace-claude-code).
  - Not in local harness transcripts: "If a tool reads a `.env` file … that value is written" — [.claude directory](https://code.claude.com/docs/en/claude-directory).
  - Not in Anthropic's Compliance API: "Nothing masks URLs, credentials, or personal data" — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions).
- **Search and resume.**
  - Search: Entire semantic search — [README](https://github.com/entireio/cli/blob/HEAD/README.md); Copilot `/chronicle search` — [Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/chronicle); Coder search across prompts, tools and "network call destinations" — [Coder audit](https://coder.com/docs/ai-coder/ai-gateway/audit); Amp `amp threads search` — [Threads](https://ampcode.com/docs/threads).
  - Resume: Claude Code `--resume` and `/fork` — [Sessions](https://code.claude.com/docs/en/sessions); Codex `resume` and `fork` — [cli main.rs](https://github.com/openai/codex/blob/main/codex-rs/cli/src/main.rs).
- **Whole-session sharing.**
  - Claude cloud sessions, Team or Public — [Claude Code on the web](https://code.claude.com/docs/en/claude-code-on-the-web).
  - Cursor "Team … or Public (anyone with the link)" — [Shared transcripts](https://cursor.com/help/ai-features/shared-transcripts).
  - Amp Unlisted ("Anyone on the internet who has the link") — [Threads](https://ampcode.com/docs/threads).
  - LangSmith public traces — [Share trace](https://docs.langchain.com/langsmith/share-trace); Langfuse public links — [changelog](https://langfuse.com/changelog/2023-09-14-public-link-sharing).
  - Copilot `/share` — [Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/chronicle).
- **Pre-execution allow/deny hooks, which the security vendors build on.**
  - Hook surfaces: Claude Code has 33 events — [Hooks](https://code.claude.com/docs/en/hooks), Codex 12 — [Codex hooks](https://learn.chatgpt.com/docs/hooks), Cursor 21 — [Cursor hooks](https://cursor.com/docs/agent/hooks).
  - Vendors on top of them: Lasso — [Lasso](https://www.lasso.security/use-cases/ai-coding-assistants); Noma — [Noma](https://github.com/Noma-Security/claude-marketplace); Palo Alto AES — [PANW](https://docs.paloaltonetworks.com/prisma-airs/ai-runtime-security/airs-api/prisma-airs-integration-with-cortex-aes); CrowdStrike — [CrowdStrike blog](https://www.crowdstrike.com/en-us/blog/falcon-aidr-protects-copilot-studio-agents-and-claude-code/).

#### Features present in a minority of tools
- **File rewind or checkpoints.**
  - Claude Code restores edit-tool files only — [Checkpointing](https://code.claude.com/docs/en/checkpointing).
  - Cursor's checkpoints are local — [Cursor checkpoints](https://cursor.com/docs/agent/chat/checkpoints).
  - Entire removed its file restore — [Sessions and checkpoints](https://github.com/entireio/cli/blob/HEAD/docs/architecture/sessions-and-checkpoints.md).
- **Line-level AI attribution.**
  - git-ai — [standard v3.0.0](https://github.com/git-ai-project/git-ai/blob/HEAD/specs/git_ai_standard_v3.0.0.md).
  - Cursor Blame — [Cursor Blame](https://cursor.com/docs/integrations/cursor-blame).
  - Agent Trace — [agent-trace.dev](https://agent-trace.dev/).
  - Agent Blame — [repo](https://github.com/mesa-dot-dev/agentblame).
- **Signed artifacts.**
  - Entire's best-effort GPG/SSH checkpoint commits — [Checkpoint signing](https://github.com/entireio/cli/blob/HEAD/docs/architecture/checkpoint-signing.md).
  - GitHub's "Verified" agent commits — [Managing sessions](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions).
  - Anthropic's staff-access transparency log — [Access Transparency log](https://platform.claude.com/docs/en/manage-claude/access-transparency-log).

#### Gap candidates: status across all tools
- **(a) Vendor-blind encryption: absent.**
  - **Cloudflare is the nearest commercial instance.**
    - DLP payload logs are encrypted to a customer public key: "Cloudflare does not have access to your private key and cannot decrypt your logs" — [DLP logging options](https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/dlp-policies/logging-options/).
    - AI Gateway Logpush wraps per-log AES keys in the customer's RSA key — [AI Gateway Logpush](https://developers.cloudflare.com/ai-gateway/observability/logging/logpush/).
    - Both cover exported or matched snippets only, and Cloudflare inspects the traffic in plaintext inline.
  - **AgentFS** encrypts locally with a user key, but "Local encryption and cloud sync cannot be used together" — [AgentFS manual](https://github.com/tursodatabase/agentfs/blob/HEAD/MANUAL.md).
  - **CMEK and EKM** still let the vendor decrypt. Anthropic's transcripts are "encrypted under your customer-managed key" yet served by Anthropic — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions). OpenAI lists EKM for Codex — [Codex pricing](https://learn.chatgpt.com/docs/pricing).
  - **Self-hosting** is custody, not cryptography: Coder — [Coder setup](https://coder.com/docs/ai-coder/ai-gateway/setup); Langfuse — [Langfuse](https://langfuse.com/integrations/other/claude-code); Braintrust's data plane — [Braintrust](https://docs.braintrust.dev/integrations/developer-tools/claude-code.md). The self-hosted Claude apps gateway "sends none of them to Anthropic" — [Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway).
- **(b) Cross-harness coverage plus a record of local actions: partial, siloed.**
  - **Broadest local capture:**
    - SpecStory (13+ harnesses, read from the agents' local stores) — [CLI README](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/README.md).
    - Entire (8 harnesses, via hooks) — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md).
    - git-ai (about 10 agents, attribution only) — [standard](https://github.com/git-ai-project/git-ai/blob/HEAD/specs/git_ai_standard_v3.0.0.md).
  - **Observability plugins** cover many harnesses but only what the harness exposes: Langfuse — [Coding-agent tracing](https://langfuse.com/resources/engineering/coding-agent-tracing); Arize — [Arize](https://arize.com/docs/phoenix/release-notes/09-2026/09-14-2026-coding-agent-plugins-and-error-analysis).
  - **Microsoft Defender** discovers about 60 agents, but runtime coverage is a subset — [MS Learn](https://learn.microsoft.com/defender-endpoint/ai-agent-support-matrix).
  - **Opik** observes the device independently through a local proxy, metadata only — [Opik Cost Intelligence](https://www.comet.com/docs/opik/cost-intelligence/install/overview.md).
  - **No evidence found** that any product records sidecar-type actions (store writes and merges, forwards, published names, messages). Membership changes are logged only for the vendor's own admin plane, e.g., Cursor's audit log — [Cursor compliance](https://cursor.com/docs/enterprise/compliance-and-monitoring).
- **(c) Approvals bound to executed actions: absent.**
  - **Correlation without binding:**
    - Claude Code's `tool_decision` shares `tool_use_id` with `tool_result`, and the decision `source` distinguishes `config`, `hook` and user choices — [Monitoring](https://code.claude.com/docs/en/monitoring-usage).
    - Claude Code's PermissionRequest hook lacks `tool_use_id`, and "No event fires on the human's answer" — [Hooks](https://code.claude.com/docs/en/hooks).
    - Codex classes approval events as "Transient, non-durable" in rollouts — [policy.rs](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/policy.rs) — while OTel `codex.tool_decision` is a separate stream — [Config advanced](https://learn.chatgpt.com/docs/config-file/config-advanced).
    - Braintrust records "approval state" — [Braintrust](https://docs.braintrust.dev/integrations/developer-tools/claude-code.md).
  - **Users are asking for it:** Cursor's forum has a request for a "Platform-level audit trail for agent tool call proposals and user approval decisions" — [forum](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247).
  - **GitHub's approval is the PR review:** a co-author trailer for the human who assigned the task — [GitHub changelog](https://github.blog/changelog/2026-03-20-trace-any-copilot-coding-agent-commit-to-its-session-logs/).
  - **Counter-example:** Entire's own review agents run with approvals bypassed — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md).
  - **Outside commercial products:** the open-source Agent Receipts protocol names "the human who authorized it" on each signed receipt — [agentreceipts.ai](https://agentreceipts.ai). The individual IETF draft `draft-sharif-agent-audit-trail-09` has an authorizing-principal field — [datatracker](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/).
- **(d) Third-party verifiability: absent for agent-work records.**
  - **Anthropic's Access Transparency log is a verifier-grade design** ("append-only, cryptographically signed", Merkle tree, C2SP tlog-tiles, inclusion and consistency proofs, `axt-verify`). It covers only `anthropic_access` and `cmek_preserve` events, is beta and on request, and "does not prove that every access was recorded" — [Access Transparency log](https://platform.claude.com/docs/en/manage-claude/access-transparency-log).
  - **Entire's GPG/SSH-signed checkpoint commits** let outsiders verify transcript content with the developer's key. Signing is best-effort, and when it fails "the commit is created unsigned" — [Checkpoint signing](https://github.com/entireio/cli/blob/HEAD/docs/architecture/checkpoint-signing.md).
  - **GitHub's signed agent commits** carry an `Agent-Logs-Url`. The signature covers the commit, not the log — [GitHub changelog](https://github.blog/changelog/2026-03-20-trace-any-copilot-coding-agent-commit-to-its-session-logs/).
  - **Open-source and standards work only:**
    - Obsigna (20 stars) — [README](https://github.com/agent-receipts/obsigna).
    - IETF individual drafts — [datatracker](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/).
    - Tapes keeps its Merkle layer "internally" — [Tapes](https://github.com/papercomputeco/tapes).
- **(e) Selective disclosure to clients: absent as a cryptographic feature.**
  - SpecStory lets you "Share a session with a public link and control which exchanges are visible" — [SpecStory Cloud](https://docs.specstory.com/cloud/overview).
  - Amp has groups and unlisted links — [Threads](https://ampcode.com/docs/threads).
  - Everything else shares whole sessions.
  - Agent Receipts hashes parameters, and "The operator controls what is disclosed" — [agentreceipts.ai](https://agentreceipts.ai).
- **(f) Crypto-erasure: absent per record or per client.**
  - **Org-wide key deletion:** Anthropic CMEK: "If your key is deleted, Anthropic can't recover the data it protects" — [CMEK](https://platform.claude.com/docs/en/manage-claude/cmek).
  - **Key rotation:** Cloudflare's DLP key rotation leaves older payload logs "permanently unreadable" — [DLP payload logging](https://developers.cloudflare.com/cloudflare-one/policies/data-loss-prevention/dlp-policies/payload-logging) (search summary).
  - **Deletion is weak or absent elsewhere:**
    - GitHub cloud sessions "can be archived but not deleted" — [Managing sessions](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions).
    - Entire: "Deleting a checkpoint is not a full purge" — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md).
    - Amp keeps Enterprise threads until the contract ends — [Amp security](https://ampcode.com/security).
  - **Erasure that keeps the chain verifiable** exists only in drafts: `draft-sharif-agent-audit-trail` tombstones — [datatracker](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/).
- **(g) Per-client partitions with separate keys: absent.**
  - Only access partitions exist: Amp groups and projects — [Threads](https://ampcode.com/docs/threads); Entire's per-repo checkpoint remote — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md); Langfuse project RBAC — [Pricing](https://langfuse.com/pricing); Braintrust per-project retention — [Pricing](https://www.braintrust.dev/pricing).
  - Anthropic: "Per-workspace enrollment is not currently available" for Access Transparency — [Access Transparency](https://platform.claude.com/docs/en/manage-claude/access-transparency).
- **(h) Network-reach records: partial, siloed, mostly egress.**
  - **Codex's network proxy** logs `server.address`, `server.port` and allow/deny/ask. It works only in the managed runtime, and "intentionally avoid[s] logging full URL/path/query data" — [network-proxy README](https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md).
  - **Coder Agent Firewall** logs method, URL and decision. It is HTTP only; in landjail mode "data can leak over UDP" — [Agent Firewall](https://coder.com/docs/ai-coder/agent-firewall).
  - **Claude cloud sessions** route outbound traffic through a security proxy "for audit logging". The logs are held by Anthropic — [Data usage](https://code.claude.com/docs/en/data-usage).
  - **GitHub** shows blocked requests only, and its firewall excludes MCP — [Agent firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall).
  - **Cloudflare portal logs** carry `ClientIP` and `ServerURL` — [mcp_portal_logs](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/index.md).
  - **Microsoft Defender** inspects LLM inference traffic only — [MS Learn](https://learn.microsoft.com/defender-endpoint/ai-agent-support-matrix).
  - **Claude Code's sandbox refusal counts** carry no hosts, and the event was withdrawn in v2.1.312 — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md).
  - **No evidence found** that any researched tool records inbound reach (ports exposed, names published).
- **(i) Inbox and message provenance: absent.**
  - Codex persists `InterAgentCommunication(+Metadata)` — [policy.rs](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/policy.rs).
  - Cursor `subagentStart` carries `parent_conversation_id` — [Cursor hooks](https://cursor.com/docs/agent/hooks).
  - Claude agent-team mailboxes are plain JSON validated for format only — [Agent teams](https://code.claude.com/docs/en/agent-teams).
  - Compliance transcripts show CLAUDE.md as "ordinary user-role content" — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions).
  - Security vendors flag injected content without recording its source: Lasso — [Lasso](https://www.lasso.security/use-cases/ai-coding-assistants); Pillar — [Pillar](https://www.pillar.security/blog/introducing-pillar-for-ai-coding-agents).

### Inferences
- **What the sidecar can own.** The positioning ("tamper-evident, team-keyed, cross-harness") maps onto gaps no commercial product fills: (a), (c), (d), (e), (f), (g) and (i). For (h), it can own its own forwards and published names, which is inbound reach that nobody records.
- **What it must match.** To pass procurement it still needs:
  - per-user identity on records;
  - OTel/SIEM export mapped to `invoke_agent` and `execute_tool`;
  - redaction;
  - search;
  - resume and handoff;
  - whole-session sharing;
  - hook ingestion from Claude Code, Codex and Cursor.
- **Approval binding is feasible because harnesses already expose the pieces:**
  - Claude Code's `tool_use_id` and `tool_decision.source`;
  - Codex's `PermissionRequest` with exact `tool_input`;
  - Cursor's `before*` hooks.

  A sidecar that signs the hook's approval payload together with the later PostToolUse result would be the first such binding. That is an inference; hook fail-open and bypass limit completeness — [Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks).
- **Completeness is the shared weak point.** Anthropic's log "does not prove that every access was recorded". Agent Flight Recorder (search summary) guarantees integrity of what reaches the recorder, "not that all events reach the recorder". A sidecar record can prove integrity and customer custody, not completeness. Marketing should claim the former only.
- **Incumbents could close (d) quickly.** Anthropic already ships tlog-tiles for staff access and could apply them to Compliance API transcripts. They are unlikely to close (a), because their compliance, DLP and analytics products depend on reading content.

### Gaps
- I did not verify the GitHub artifact-attestation (Sigstore) docs, so I cannot rule out an agent-provenance attestation there.
- I did not open Cursor's CMEK doc, so its key-revocation semantics (crypto-erasure) are unknown.
- I did not check the OCSF 1.9 "Record Integrity structures" against the OCSF schema.
- The verification model of the open-source Agent Receipts protocol (shared vs per-operator keys) was not fully clear from its homepage.
- "Table stakes" is judged from documentation coverage, not from usage data.



## 3. Where do these tools conflict with developer privacy, and how do they handle it?

### Takeaway
Every shared record is plaintext to someone other than the developer:
- the vendor (gateways, compliance feeds, cloud sessions, observability SaaS);
- the employer's admins and security team (session streaming, compliance keys, admin reads of private threads);
- everyone with repo access (git-stored records).

Vendors mitigate this with content-off defaults, role gating, logging of admin or staff access, self-hosting, zero data retention and local-only modes. None of these mitigations is cryptography the vendor cannot bypass. The exception is Cloudflare's customer-key encryption of DLP payload logs.

### Cited Findings
- **Gateways read prompts.**
  - **Tailscale Aperture** captures full request and response bodies. Admins "inspect captured content" under Security > Logs, and users see only their own sessions — [Observe and export](https://tailscale.com/docs/aperture/observe-and-export). The docs describe a "managed" gateway with Tailscale-held backups and do not say whether Tailscale staff can read captures — [Privacy and data retention](https://tailscale.com/docs/aperture/privacy-and-data-retention). Its mitigation is zero retention, which still keeps usage metrics and "does not delete Chat conversation history" — [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md).
  - **Coder** is self-hosted, so Coder the vendor does not hold the data, but deployment admins do. It stores the "last user prompt", tool inputs and reasoning, with `disable_content_recording` as an opt-out — [Coder audit](https://coder.com/docs/ai-coder/ai-gateway/audit); [Coder setup](https://coder.com/docs/ai-coder/ai-gateway/setup).
  - **Cloudflare AI Gateway** "Logs are enabled by default" and include prompt and response. There is a per-request opt-out header — [AI Gateway logging](https://developers.cloudflare.com/ai-gateway/observability/logging/). DLP payloads can be encrypted so Cloudflare "cannot decrypt" them — [DLP logging options](https://developers.cloudflare.com/cloudflare-one/data-loss-prevention/dlp-policies/logging-options/).
- **Harness vendors give the employer content access.**
  - **Anthropic:** compliance reviewers can read Enterprise developers' Claude Code prompts, tool calls and file text, and "Nothing masks URLs, credentials, or personal data". No developer opt-out is documented — [Compliance sessions](https://platform.claude.com/docs/en/manage-claude/compliance-sessions).
  - **Anthropic's own staff access** is disclosed through Access Transparency events and its signed log, on request — [Access Transparency](https://platform.claude.com/docs/en/manage-claude/access-transparency).
  - **GitHub:** synced local sessions are "accessible only to you by default" — [Session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data). Yet enterprise session streaming sends "prompts, responses, and tool calls" from CLI and IDE sessions to the employer's SIEM — [Streaming changelog](https://github.blog/changelog/2026-07-02-copilot-agent-session-streaming-is-now-in-public-preview/).
  - **Cursor:** "Privacy Mode doesn't suppress audit events" — [Cursor compliance](https://cursor.com/docs/enterprise/compliance-and-monitoring). Content export requires a team-level "Allow conversation content export" switch — [Cursor OTel](https://cursor.com/docs/enterprise/opentelemetry-export). Enterprise hooks receive prompt text and the transcript path, and Cursor advises logging "metadata (who, when, what file) rather than content when possible" — [Cursor hooks](https://cursor.com/docs/agent/hooks); [Cursor compliance](https://cursor.com/docs/enterprise/compliance-and-monitoring).
  - **Amp:** "In a workspace, workspace admins can also see" private threads — [Threads](https://ampcode.com/docs/threads). It mitigates this with "All workspace admin access to private threads is audit-logged" and a passkey requirement — [Amp security](https://ampcode.com/security).
  - **OpenAI:** compliance logs export `prompt_text` and `response_text`, retained "up to 30 days" — [Elastic integration](https://www.elastic.co/docs/reference/integrations/openai_chatgpt_enterprise).
- **Admins can switch telemetry content on.**
  - **Claude Code** managed settings can force telemetry on and remove "conflicting developer-set variables" — [Monitoring](https://code.claude.com/docs/en/monitoring-usage). Since v2.1.282, project and local settings ignore the content-capture variables — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md). The docs do not say whether developers are notified.
  - **Copilot:** a managed telemetry value "overrides user settings" — [VS Code monitoring](https://code.visualstudio.com/docs/agents/guides/monitoring-agents).
- **Productivity analytics are per developer.**
  - Claude's dashboard and API show per-user lines, PRs and spend — [Analytics](https://code.claude.com/docs/en/analytics); [Claude Code Analytics API](https://platform.claude.com/docs/en/manage-claude/claude-code-analytics-api).
  - GitHub metrics are available "at the … user levels" — [Copilot metrics](https://docs.github.com/en/copilot/concepts/copilot-usage-metrics/copilot-metrics).
  - Datadog maps identity through `email` and `github_login` — [Datadog setup](https://docs.datadoghq.com/ai_agents_console/setup/).
  - Under zero data retention, Anthropic still keeps "productivity metadata such as account emails" — [ZDR](https://code.claude.com/docs/en/zero-data-retention).
- **Git-stored records expose prompts to the whole repo.**
  - Entire: "Anyone with access to your repository can read committed checkpoint data". The mitigations are `--checkpoint-remote` and `--skip-push-sessions` — [Security and privacy](https://github.com/entireio/cli/blob/HEAD/docs/security-and-privacy.md).
  - git-ai notes show the steering person's name and email to repo readers. Its Teams prompt store is "Write-only: ... developers cannot read unless explicitly granted permission" — [git-ai data privacy](https://github.com/git-ai-project/git-ai/blob/HEAD/data-privacy.md).
  - Amp ended public threads because it was "too hard to review a thread to ensure it doesn't contain any snippets of sensitive files" — [End of Public Threads](https://ampcode.com/news/end-of-public-threads).
- **Security vendors inspect prompts and code without addressing employee monitoring.**
  - None of the fetched pages from Lasso, Zenity, Noma, Pillar, SentinelOne, Palo Alto, CrowdStrike or Microsoft discusses consent or monitoring. Minimisation appears only as DLP, e.g., Noma's "before it leaves your local environment" — [Noma](https://github.com/Noma-Security/claude-marketplace) — and Palo Alto's masked text — [PANW](https://docs.paloaltonetworks.com/prisma-airs/ai-runtime-security/airs-api/prisma-airs-integration-with-cortex-aes).
  - CrowdStrike's Claude Code collector excludes LLM responses, and its redaction "applies to tool inputs and outputs but not to user prompts" — [AIDR collectors](https://aidr-docs.crowdstrike.com/docs/aidr/collectors).
- **Naming traps send data to the vendor.**
  - Claude Code's `/share` reports through the `/feedback` path, and those transcripts "are retained for 5 years" — [Data usage](https://code.claude.com/docs/en/data-usage).
  - LangSmith warns "Project-level config files can turn tracing on and redirect traces" — [LangSmith](https://docs.langchain.com/langsmith/trace-claude-code).
- **Local-only modes are the developer-side mitigation.**
  - Copilot CLI sessions are "stored locally only" when the cloud policy is unset — [Session data](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/session-data).
  - Codex says it "does **not** upload or report these traces" for rollout traces — [rollout-trace README](https://github.com/openai/codex/blob/main/codex-rs/rollout-trace/README.md).
  - SpecStory has `--no-cloud-sync` — [CLI README](https://github.com/specstoryai/getspecstory/blob/HEAD/specstory-cli/README.md).
  - Opik's Cost Intelligence reports "Only counts, costs, and structural metadata", and orgs "can pin" content off — [Opik](https://www.comet.com/docs/opik/cost-intelligence/install/overview.md).

### Inferences
- **The common trade.** Teams get a shared, searchable record only by giving a vendor or an admin plaintext. The privacy-preserving options (local-only modes, zero data retention, content-off telemetry) lose the shared record. A vendor-blind record held under team keys would remove that trade for the vendor, but not for the team: the team still reads its members' work. So the sidecar's privacy claim should be scoped as "the vendor (URnetwork) cannot read it", not "no one can read it".
- **Per-developer disclosure is missing.** No product lets a developer show a client or auditor a subset of the record without exposing the rest. Combined with selective disclosure (gap e), this is the clearest privacy-positive feature no one offers.
- **Gateway vendors are the sharpest conflict.** Aperture and Cloudflare AI Gateway hold full prompt bodies by default, and their docs are silent or limited on staff access. The sidecar's network-forwarding role could log reach metadata without content, the inverse of the gateway pattern.
- **Admin forcing without notice is a trust gap.** Claude Code and Copilot let admins enforce content capture, and neither documents telling the developer. A record that is visible to its subjects, where developers can see what was recorded about them and who read it, would be a differentiator. This is an inference; I found no product doing it, except Amp's audit logging of admin reads and Anthropic's staff-access log.

### Gaps
- I found no user-sentiment data in this round (e.g., developer complaints about streaming or forced telemetry). Evidence is limited to documentation.
- Tailscale and Cursor staff-access policies were not documented on the pages read.
- Whether GitHub notifies developers when session streaming is enabled was not checked.
- Employment-law constraints on monitoring developers (e.g., EU works councils) were out of scope.


