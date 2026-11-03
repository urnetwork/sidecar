# Measuring the impact, quality and cost of AI coding agents: market state and gaps (as of 31 October 2026)

Retrieval notes. All pages below were retrieved on 31 Oct 2026 unless marked otherwise. Several primary pages would not load: the Business Wire release for the Span round (HTTP 403), the Gartner newsroom release (403), Visual Studio Magazine (403), LeadDev's report pre-registration page (404), and one Span help article (404). LeadDev's full 2026 report sits behind a login, and only its headline statistics were visible. For each of these, the notes say where the figure came from instead (a secondary outlet or a search-result summary). Every vendor figure is vendor-reported unless stated otherwise. Survey figures come from different populations and question wordings, so they must not be averaged or combined.

---

## 1. Engineering-intelligence products: what they offer for AI and agent impact; pricing, traction and funding

### Takeaway
By late 2026 every major engineering-intelligence (EI) platform has an "AI impact" module. The common pattern is adoption metrics from vendor APIs, AI-labelled PRs set against DORA and cycle-time metrics, and, since mid-2026, AI spend tied to output. The newest moves are toward per-session agent traces and token cost per outcome: Faros "Token Engineering" (Sept 2026), Swarmia AI cost (2026), Span agent traces (2026) and Waydev "AI Spend Hub". Revert- and survival-based metrics for agent changes are still rare. Money is flowing to the category: Atlassian agreed to buy DX for roughly US$1B in Sept 2025, Span raised $25M in Nov 2025 and Swarmia raised €10M in Jun 2025. Faros and Jellyfish show no new rounds in 2025–26.

### Cited Findings

#### DX (getdx.com, now part of Atlassian)
- The DX AI Measurement Framework has three dimensions. **Utilization**: DAU/WAU, % of PRs that are AI-assisted, % of committed code that is AI-generated, and tasks assigned to agents. **Impact**: AI-driven time savings (hours/week), developer satisfaction, and "human-equivalent hours" (HEH) of work done by agents. Indirectly, it also tracks PR throughput, perceived rate of delivery, DXI, code maintainability, change confidence and change fail percentage, all analysed longitudinally against DX Core 4. **Cost**: AI spend (total and per developer), net time gain per developer (time savings minus AI spend), and "agent hourly rate" (HEH divided by AI spend). The page lists no rework or revert metric. Page last updated 20 May 2026. — [DX AI measurement framework guide](https://getdx.com/blog/ai-measurement-framework-guide/)
- The same page cites vendor data, dated as Q1 2026: 93% of developers use AI coding tools at least monthly; 3.9 h/week saved (4.72 h/week for daily users); about 28% of committed code is AI-authored (27.4% of merged code); daily AI users merge a median 2.4 PRs/week against 1.5 for non-users; change failure rates swing by up to 2 percentage points. Undated figures on the page: leading organisations reach about 60% active usage; a longitudinal study found a 10–15% PR-throughput increase over more than a year; Booking.com saw a 16% throughput increase across 3,500+ engineers. — [DX guide](https://getdx.com/blog/ai-measurement-framework-guide/)
- DX advises against using these metrics for individual performance evaluation, and recommends telling teams so. It also recommends treating agents as extensions of the developers and teams that oversee them, so agent PRs count toward team throughput. — [DX guide](https://getdx.com/blog/ai-measurement-framework-guide/)
- Data sources: DX ingests vendor APIs. Its Codex Enterprise connector pulls per-user, per-day token and credit metrics and states that "DX does not read or access your source code" ([DX Codex connector](https://docs.getdx.com/connectors/codex-enterprise.md)). Its Cursor connector uses Cursor's AI Code Tracking API; a search-result summary of that page says privacy mode must be disabled to track code change files ([DX Cursor connector](https://docs.getdx.com/connectors/cursor.md), page not opened directly).
- Acquisition: Atlassian announced a definitive agreement to acquire DX on 18 Sept 2025. Atlassian's post gives no price, says DX serves "more than 350 enterprises" (naming Pfizer, Pinterest and Xero), and says DX will join Rovo Dev, Jira, Bitbucket and Compass. The post's framing question is "how do we measure the ROI of AI investments?" — [Atlassian blog, 18 Sept 2025](https://www.atlassian.com/blog/announcements/atlassian-acquires-dx). Press coverage puts the price at about US$1B in cash and restricted stock (about A$1.5B in Australian outlets) — [BNN Bloomberg/Reuters, 18 Sept 2025](https://www.bnnbloomberg.ca/business/2025/09/18/atlassian-to-acquire-developer-productivity-platform-dx-for-us1-billion) (search result, not opened). Completion was announced around 10 Nov 2025 — [Business Wire](https://www.businesswire.com/news/home/20251110683591/en/Atlassian-Completes-Acquisition-of-DX-Advancing-Engineering-Intelligence-for-Enterprises) (search-result title only).
- Pricing: no public DX price found (see Gaps).

#### Jellyfish (AI Impact)
- AI Impact added **Autonomous Agent Insights**, which tracks agent-generated code, agent PRs, AI contribution ratios and merge rates. Named agents are Devin, Factory, Codegen, "Claude Agent", "Copilot Agent" and Google Jules. The release also added **Developer Insights**, which are pre-built developer-experience surveys on AI enablement, productivity and suggestion quality, and **Executive Reporting** workflows aimed at demonstrating ROI. The post says AI Impact unifies "adoption, usage, spend, and outcome data" but names no data sources. Posted 18 Nov 2025. — [Jellyfish, "New in AI Impact"](https://jellyfish.co/?p=29717)
- The H1 2026 "State of AI in Software Engineering" report is vendor platform telemetry, not a survey. Its figures:
  - Cost per AI user at the median company rose from about $5/month (Aug 2025) to $81/month (May 2026), a 16x increase. At the P75 company it went from $10 to $170. In May 2026 the mean was $248/month and the P99 user spent $2,452/month.
  - Returns diminish past about 2M tokens per user per month. The first million tokens yields about 11 merged PRs.
  - The same workload cost about 40% more on Opus 4.7 than on Opus 4.6 at the same list price.
  - Autonomous-agent PR share is about 2% at the median company. At the P90 company it rose from 10% (Jan 2026) to 35% (Apr 2026).
  - 84% of active users run one or two agents at once.
  - The page reports no bug, revert, rework or review-time findings. Cost figures are derived from API list prices.
  — [Jellyfish State of AI in Software Engineering H1 2026](https://jellyfish.co/state-of-ai-software-engineering/)
- Jellyfish names "AI Token Cost Management" as a product area and runs a site banner reading "AI spend per engineer tripled in six months" (undated, no methodology). — [Jellyfish](https://jellyfish.co/?p=29717); [Jellyfish H1 2026](https://jellyfish.co/state-of-ai-software-engineering/)
- Funding: the last round found is a $71M Series C (Feb 2022, led by Accel, Insight Partners and Tiger Global). No 2025–26 round or acquisition was found. — [Insight Partners](https://www.insightpartners.com/?p=6928) (search result)

#### LinearB (AI Insights)
- AI Insights identifies AI-assisted work from four signals: commit co-author trailers naming AI agents, AI-agent comments in PRs, PRs opened by known AI agents, and provider APIs for adoption and usage. Named provider integrations are GitHub Copilot, Claude and Codex.
- Metrics: acceptance rate; AI-co-authored PR labels; and Cycle Time, Deployment Frequency, CFR and MTTR compared against AI-assisted work. On the Essentials plan only cycle time and deployment frequency are available; all four DORA metrics need Enterprise.
- Team and individual views are both offered, and individual visibility can be restricted with RBAC. The FAQ does not say whether AI Insights costs extra.
- — [LinearB AI Insights FAQ](https://linearb.helpdocs.io/article/ww1ciql9uw-linear-b-ai-insights-faq)
- The AI Insights dashboard launched in beta in Sept 2025 — [LinearB release notes, Sept 2025](https://linearb.helpdocs.io/article/echp7pv043-release-notes-september-2025) (search snippet).
- Funding: $50M Series B (2022) is well documented — [Built In LA](https://www.builtinla.com/articles/linearb-raises-50m-series-b-hiring). CB Insights lists an $11.31M "Series C" on 20 Jan 2026, which I could not corroborate — [CB Insights](https://www.cbinsights.com/company/linear-b/financials) (search result).

#### Faros AI
- The "AI Coding ROI" page defines **cost per outcome**: AI spend divided by a unit of shipped work (merged PR, resolved ticket or released feature), sliceable by team, model and tool. It says Faros "connects agent sessions to the pull requests, tickets, and releases they produced". Named data sources are coding agents, AI gateways, source control, ticketing, CI/CD and incident systems. It explicitly calls seat counts, token volume and acceptance rates poor proxies for impact. Named tools: Claude Code, OpenAI Codex, Cursor and GitHub Copilot. No public pricing beyond a free self-service trial environment. — [Faros AI Coding ROI](https://www.faros.ai/solutions/ai-coding-roi)
- Faros launched a "Token Engineering" platform in Sept 2026 (Observe / Optimize / Govern), including model routing enforced at the gateway. — [Faros AI Coding ROI](https://www.faros.ai/solutions/ai-coding-roi) (the Sept 2026 date comes from a search-result summary of Faros pages)
- The "AI Engineering Report 2026: The Acceleration Whiplash" is vendor telemetry covering 22K developers and 4K teams over two years, comparing high with low AI adoption inside the same organisations.
  - Quality and review: PR size +51%; bugs/PR +28%; median review time 5x; incidents/PR about 3x (+242.7%); code churn about 10x (+861%); monthly incidents +57.9%; bugs/developer +54%.
  - Throughput: epics +66.2%; task throughput +33.7%; PR merge rate +16.2%; deployments/week −11.7%.
  - The page does not define the adoption cut-offs.
  — [Faros research page](https://faros.ai/research/ai-acceleration-whiplash)
  - A search summary of the PDF adds "31% more PRs merge with no review" — [Faros PDF](https://pages.faros.ai/hubfs/AI_Engineering_Report_2026_The_Acceleration_Whiplash_Faros.pdf) (not opened). Secondary write-ups give the review-time rise both as +441.5% and as +156.6% time-to-first-review, which are different metrics.
- Funding: the last round found is a $20M Series A (June 2023). No 2025–26 round found. — [Faros blog](https://www.faros.ai/blog/announcing-our-20m-series-a-funding)

#### Swarmia
- The "Coding agents" view (changelog, 2 Feb 2026) shows PRs from GitHub Copilot, Cursor and Claude Code across teams and repos. It covers merged versus closed agent PRs, the share of PRs created entirely by agents ("how often engineers intervene"), batch-size distribution, trends, team comparisons and PR drill-downs. It does not say how agent PRs are detected. — [Swarmia changelog](https://www.swarmia.com/changelog/2026-02-02-ai-agent-metrics/)
- **AI cost** feature:
  - Sources: Copilot AI-credit usage (data from 19 Jun 2026); Cursor usage (list price plus Cursor fee, no discounts); Claude Code "estimated cost" via OTel, the Claude Code Analytics API or the Enterprise Analytics API; Codex "estimated cost" via the Codex Enterprise Analytics API, or token counts times list price via OTel; custom tools via an API.
  - Attribution: each person's daily AI usage is spread across the issues and PRs they touched that day, in proportion to effort.
  - Views: per team (token usage, AI-assisted PRs merged), per person and per issue. No cost-per-PR ratio is computed.
  - Caveats: costs are list price, not invoice; seat licences are excluded; data can lag up to a day.
  — [Swarmia AI cost docs](https://help.swarmia.com/features/ai-tools/ai-cost)
- Funding: €10M (about $11.5M Series A), June 2025, Helsinki — [BeBeez, 18 Jun 2025](https://bebeez.eu/2025/06/18/finnish-saas-startup-swarmia-secures-e10-million-to-power-engineering-productivity/) (search result). Sources disagree on the lead investor.
- Pricing (buyer data, not vendor): from $179/developer/year for single modules; $286–$433/developer/year for the full Standard suite at 50 developers — [Vendr](https://www.vendr.com/marketplace/swarmia) (search result). Other listings range from $10 to $45 per developer per month, so the sources conflict.

#### Span (span.app)
- Positioning (Oct 2026 homepage): a "developer intelligence platform" that links **agent traces** to code, PRs and downstream outcomes ("prompt-to-prod").
  - Traces capture prompts, tool calls, model choices, file edits and token spend, with related sessions linked, including dead ends.
  - Traces show $ cost per session, and Span reports ROI with each number "mapped to its supporting evidence". It also ranks harness and workflow improvements.
  - Privacy: sessions are private by default and "belong to the engineer"; reporting is at repo and team level, "never people". Secrets and PII are stripped before storage.
  - Capture: the recorder runs on developer machines via MDM, not as a proxy.
  - Named customers: Ramp, Writer, Carvana and Fin. Benchmarks are "from 103 teams".
  — [Span homepage](https://www.span.app/)
- Security overview (updated 20 May 2026):
  - Hosting is AWS, US only. Data is encrypted with TLS 1.2+ in transit and AES-256 at rest, with master keys rotated at least annually. **Customer-managed keys are not mentioned.**
  - Trace retention defaults to 90 days and can be set as low as 30. Secret and PII redaction happens on device and again at ingestion.
  - "Prompts and full trace details are accessible only for the authors of a given trace."
  - A "Pause Collection" control is listed as "coming soon".
  — [Span security overview](https://span-knowledge-base.help.usepylon.com/articles/8922907265-span-agent-trace-analytics-security-overview)
  - A search summary of another Span help article, dated June 2026, says prompt and file capture "can be turned off by org policy" and that Span runs "agent evals" over traces. The article itself returned 404. This conflicts with the security overview, which describes no such toggle. — [Span help (404)](https://span-knowledge-base.help.usepylon.com/articles/5451555629-understanding-agent-traces-in-span)
- Earlier product (2025): an "AI Code Detector" (span-detect-1) that classifies code text as human or AI-assisted, with a claimed 95% accuracy — [Show HN](https://hn.svelte.dev/item/45265831) (search result). The current homepage no longer lists it.
- Funding: $25M seed plus Series A, announced 5 Nov 2025. Search coverage names Alt Capital, Craft Ventures, SV Angel, BoxGroup and Bling Capital. — [Business Wire (403)](https://www.businesswire.com/news/home/20251105703479/en/Span-Raises-%2425M-to-Bring-Clarity-to-Engineering-Teams-Navigating-AI-Transformation); [AI Journal reprint](https://aijourn.com/span-raises-25m-to-bring-clarity-to-engineering-teams-navigating-ai-transformation/) (search result)

#### Waydev
- The Oct 2026 homepage markets "AI Adoption", "AI Impact", "AI ROI", "AI Agent Observability" ("what each AI agent does across the SDLC"), "AI Governance" (guardrails and limits), "Human and Agent Spend", "AI FinOps", "AI Spend Hub" ("what AI tools cost and what they shipped") and "AI Feature Spend". It has tool pages for Claude Code and Cursor.
- Named data sources are git, ticketing, CI/CD and calendars; AI vendor APIs are not named. Waydev claims "300+ companies" and is listed as a Niche Player in Gartner's Magic Quadrant for Developer Productivity Insight Platforms. No prices are listed.
- — [Waydev homepage](https://waydev.co/)
- A "Waydev Agent" launched in May 2026 — [Product Hunt](https://www.producthunt.com/products/waydev/launches/waydev-agent) (search result).
- According to a competitor's pricing guide, AI adoption and impact features are gated to higher tiers and AI actions consume per-contributor credits — [Pensero (competitor-authored)](https://pensero.ai/blog/waydev-pricing) (search result).

#### Haystack (usehaystack.io)
- Buyer data puts the median contract at $12,000/year (range $4,800–$19,140) — [Vendr](https://www.vendr.com/marketplace/haystack) (search result). A competitor's guide says measuring the impact of Copilot, Cursor or Claude Code is outside what Haystack's pricing buys — [Pensero (competitor-authored)](https://pensero.ai/blog/haystack-pricing) (search result). I found no first-party Haystack page on AI or agent metrics (see Gaps).

#### Uplevel
- The Oct 2026 homepage positions Uplevel as "Engineering intelligence to surface your bottlenecks. Human intelligence to fix what it finds", with products "AI Impact and ROI", "AI Gap Analysis" and "AI Capability Building". It warns that code generation may improve "while review or validation absorbs the extra load". It offers a free "StackUp" session on six AI cost drivers. It lists no agent-specific measurement and no named data sources. The only pricing statement is that customers "pay less over time". Customer-reported claims: 12x deployment frequency (Avalara) and +17% capacity (Xactly). — [Uplevel homepage](https://uplevelteam.com/)
- Starting price $25,000, "priced by transformation scope, not headcount" — [Capterra](https://www.capterra.com.sg/software/198866/uplevel) (search result).

#### Metric coverage matrix (what each product's own pages show; "—" means not found on the pages reviewed, not proven absent)

| Product | AI-authored share | Acceptance | PR throughput | Cycle time | Rework/churn | Revert | Review time | Cost per PR/dev | Agent-specific |
|---|---|---|---|---|---|---|---|---|---|
| DX | Yes (% committed code AI) | — | Yes | — | — (maintainability, CFR) | — | — | Per dev; "agent hourly rate" | Tasks to agents, HEH |
| Jellyfish | "AI contribution ratio" | — | Yes (2x for top adopters) | — | — | — | — | Spend analytics, token cost | Agent PRs, merge rate |
| LinearB | AI-co-authored PR labels | Yes | — | Yes | — | — | — | — | Agent-opened PRs |
| Faros | — | Called a poor proxy | Yes | — | Yes (rework rate) | — | Yes | Cost per outcome by team/model/tool | Agent sessions to PRs |
| Swarmia | — | — | AI-assisted PRs merged | — | — | — | — | Per team, person and issue (list price) | Agent PRs; human-intervention share |
| Span | — (2025 detector) | — | — | — | — | — | — | $ per session | Full agent traces |
| Waydev | — | — | — | Yes | — | — | — | "AI Spend Hub", "Feature Spend" | "Agent Observability" |
| Uplevel | — | — | — | Yes (general) | — | — | — | — | — |

Sources: as cited in the product subsections above.

### Inferences
- The category has converged on three layers: (1) adoption from vendor APIs, (2) outcomes from git, ticketing and CI/CD joined to AI labels, and (3) since mid-2026, spend per outcome. "Cost per merged PR by tool" is already offered, or at least claimed, by Faros, Swarmia, Span, Waydev and Git AI Teams (see §6), so it is not a differentiator by itself.
- Span (local recorder via MDM, agent traces, author-only prompts, aggregate-only reporting) is the closest existing product to a "private record of agent work". The differences that remain are key custody (Span's data sits on Span-operated AWS in the US with no customer-managed keys mentioned), tamper-evidence, and capture of approvals (not described).
- Atlassian's roughly $1B purchase of DX shows that strategic buyers value AI-ROI measurement. It also means the leading measurement vendor is now owned by a company that also sells an agent (Rovo Dev), which could create neutrality concerns for buyers who use other agents. That last point is my inference.

### Gaps
- Public list pricing for DX, Jellyfish, LinearB, Faros, Span and Waydev was not found. LinearB "from $29/month" appears only on a third-party tracker and was not verified.
- Jellyfish's customer count ("700+ companies", May 2026) appeared only in a search summary and could not be confirmed on a primary page.
- How Swarmia, Jellyfish and LinearB detect agent PRs from harnesses whose commits are authored by the human (local CLI runs) is not documented on the pages reviewed.
- A "LinearB 16M ARR" headline appeared as a Smartkarma search-result title. It is unverified and not used.
- No first-party Haystack documentation on AI metrics was retrieved.

---

## 2. Vendor analytics: what GitHub, Cursor, Anthropic, OpenAI and Windsurf/Devin expose; per-user versus aggregated

### Takeaway
All five vendors now expose **per-user** data to admins: emails or logins, daily activity, lines, tokens and cost or credits. Each sees only its own harness. Outcome data is thin and vendor-specific. GitHub reports Copilot-created PRs merged and time to merge. Anthropic attributes merged-PR lines to Claude Code by text matching. Cursor reports AI lines per commit. Codex reports usage and code-review activity. None reports whether agent code was later reverted or survived, and none attributes work across harnesses, apart from GitHub's new, best-effort `totals_by_client` field, which covers only traffic that uses Copilot models.

### Cited Findings

#### GitHub Copilot usage metrics (dashboard and API)
- History: the new usage-metrics dashboard and API went to public preview on 28 Oct 2025 ([changelog](https://github.blog/changelog/2025-10-28-copilot-usage-metrics-dashboard-and-api-in-public-preview/)) and reached GA on 27 Feb 2026 ([changelog](https://github.blog/changelog/2026-02-27-copilot-metrics-is-now-generally-available)). A closing-down notice for the legacy metrics APIs was posted on 29 Jan 2026 ([changelog](https://github.blog/changelog/2026-01-29-closing-down-notice-of-legacy-copilot-metrics-apis/)). These dates come from changelog titles in search results; the pages were not opened.
- **Per-user reports** (1-day and 28-day) contain `user_id`/`user_login`, `ai_credits_used`, `used_agent`, `used_chat`, `used_cli` and `used_copilot_coding_agent` (same value as `used_copilot_cloud_agent`), plus `ai_adoption_phase`, activity counts and LoC added/deleted.
- **Aggregated enterprise/org reports** contain DAU/WAU/MAU and a `pull_requests` object with `total_created`, `total_reviewed`, `total_merged`, `median_minutes_to_merge`, `total_created_by_copilot`, `total_merged_created_by_copilot`, `median_minutes_to_merge_copilot_authored`, `total_reviewed_by_copilot`, and Copilot review suggestions applied versus generated by comment type (for example `security` and `bug_risk`).
- **Repository-level reports** split review time into three stages, each with median and P90. Coverage starts with PRs that became ready on or after 21 Sept 2026, with no backfill. Bot-created PRs, **including Copilot cloud-agent PRs, are excluded from review timing**. `authored_by` is currently always "human".
- Team reports exclude teams with fewer than 5 seated users on a given day.
- `totals_by_3rd_party_agent` counts only job starts for recognised partner agent apps, with no token or model data. CLI usage sits in `totals_by_cli`, and the dashboard charts exclude CLI.
- Telemetry can undercount when clients are outdated or telemetry is blocked.
- — [GitHub Docs: Copilot usage metrics reference](https://docs.github.com/en/copilot/reference/copilot-usage-metrics/copilot-usage-metrics)
- Changelog additions in 2026 (search results, not opened):
  - Per-user identification of coding-agent users (assigning Copilot to an issue or tagging @copilot), 25 Mar 2026 — [changelog](https://github.blog/changelog/2026-03-25-copilot-usage-metrics-now-identify-active-copilot-coding-agent-users/)
  - PR throughput and time-to-merge in the API, 19 Feb 2026 — [changelog](https://github.blog/changelog/2026-02-19-pull-request-throughput-and-time-to-merge-available-in-copilot-usage-metrics-api/)
  - Repository-level metrics GA, 17 Jul 2026 — [changelog](https://github.blog/changelog/2026-07-17-repository-level-github-copilot-usage-metrics-generally-available/)
  - "Copilot CLI activity now included in usage metrics totals and feature breakdowns", 10 Apr 2026 — [changelog](https://github.blog/changelog/2026-04-10-copilot-cli-activity-now-included-in-usage-metrics-totals-and-feature-breakdowns). This **conflicts** with the current reference doc, which says CLI is not reflected in `totals_by_ide` or `totals_by_feature` and is excluded from dashboard charts.
- On 23 Oct 2026 GitHub added `totals_by_client`: requests, sessions and tokens per client, covering model traffic from tools such as OpenCode that send no editor telemetry. It appears in enterprise, org and per-user reports. Unrecognised clients are grouped as "other". — [GitHub changelog, 23 Oct 2026](https://github.blog/changelog/2026-10-23-usage-metrics-api-adds-usage-from-tools-like-opencode) (search summary; the page was not opened). Visual Studio Magazine reports that client labels are "best-effort groupings rather than verified identities" — [VSM, 27 Oct 2026](https://visualstudiomagazine.com/articles/2026/10/27/github-tracks-copilot-model-usage-from-opencode-and-other-clients.aspx) (403, from a search summary).

#### Cursor AI Code Tracking API
- Enterprise only, **alpha** ("response shapes and fields may change").
- Endpoints: `/analytics/ai-code/commits` (per commit: total lines, lines from TAB, lines from COMPOSER/agent, non-AI lines, `userEmail`, `repoName`, `branchName`, `isPrimaryBranch`, and `commitSource` = ide/cli/cloud) and `/analytics/ai-code/changes` (accepted AI changes, model, per-file lines). A blame endpoint, `/commits/:commitHash`, maps line ranges to conversation, model and operation, and is limited to select users.
- Limitations: only the git repo at the top level of the workspace root is tracked (multi-root workspaces unsupported); privacy mode omits fields such as `fileName`; commit hashes "are not unique or immutable", because amending produces duplicates. Squash merges, rebases and later human edits are not addressed.
- — [Cursor docs](https://cursor.com/docs/account/teams/ai-code-tracking-api)

#### Anthropic: Claude Code Analytics API, claude.ai analytics and OpenTelemetry
- **Claude Code Analytics Admin API** (`/v1/organizations/usage_report/claude_code`):
  - Returns daily records **per user**: actor email or API-key name, `terminal_type`, sessions, LoC added/removed, commits and PRs created via Claude Code, Edit/MultiEdit/Write/NotebookEdit accept/reject counts, and per-model tokens with estimated cost in cents.
  - Up to 1 h delay. Free of charge.
  - Coverage: Claude API (Console) usage only. Subscription plans (Pro/Max/Team/Enterprise) are excluded, as are Bedrock, Microsoft Foundry, Google Cloud and "Claude Platform on AWS".
  — [Claude Code Analytics API docs](https://platform.claude.com/docs/en/build-with-claude/claude-code-analytics-api)
- **claude.ai Team/Enterprise dashboard**:
  - Usage metrics, plus "contribution metrics" (public beta) via a GitHub app: "PRs with CC", "Lines of code with CC" and % of merged PRs with Claude Code.
  - A **leaderboard** of the top 10 users, and a CSV export of every user.
  - Attribution matches Claude Code session output against added lines in merged PRs, using sessions from 21 days before to 2 days after the merge, after normalisation. Code rewritten by more than 20% is not attributed, and source and destination branches are ignored. Merged PRs are labelled `claude-code-assisted`.
  - Anthropic calls the metrics "deliberately conservative ... an underestimate".
  - "Lines of code accepted ... does not track subsequent deletions."
  - Not available with Zero Data Retention or for GitHub Enterprise Server repos. Console API users and third-party integrations are excluded.
  - The Enterprise Analytics API returns per-user engagement, usage and cost across Claude surfaces; it is not available on the Teams plan.
  — [Claude Code analytics docs](https://code.claude.com/docs/en/analytics)
- **OpenTelemetry export** (any plan, sent to the customer's own OTLP collector; "doesn't send data to Anthropic"):
  - Metrics for sessions, LoC, PRs, commits, cost and tokens.
  - A `claude_code.code_edit_tool.decision` metric.
  - A `claude_code.tool_decision` event per tool call, with `decision` (accept/reject) and `source`: `config` (settings rules, permission mode, classifier), `hook`, `user_permanent`, `user_temporary`, `user_abort` or `user_reject`.
  - `tool_result` events and per-request `api_request` cost events.
  - Identity: `user.email` is "always included when available". Prompt and response text, and tool parameters, are redacted or omitted by default.
  — [Claude Code monitoring docs](https://code.claude.com/docs/en/monitoring-usage)

#### OpenAI Codex
- The governance page describes the Codex analytics dashboard and the Analytics API as "interactive reporting surfaces, not raw audit logs". The Compliance API records local-access activity under `conversation_message` and `codex_log`. Local execution emits separate OpenTelemetry events, which the customer must collect. Hook-based auditing works through admin-defined MCP hooks. The page warns: **"Conversation visibility alone does not establish a complete record of local actions."** It lists no fields and no dates. — [Codex governance (redirected from developers.openai.com to learn.chatgpt.com)](https://learn.chatgpt.com/docs/enterprise/governance)
- Analytics API: omitting `group` returns **per-user rows**, while `group=workspace` returns workspace totals. Data comes in daily or weekly UTC buckets, with token fields for text input, cached input and output, and there is a code-review endpoint (`/workspaces/{workspace_id}/code_reviews`). — [OpenAI analytics API docs (localized)](https://developers.openai.com/es-419/docs/enterprise/analytics-api) (search summary; full field schema not retrieved)
- Per DX's connector documentation, data is per user per day (tokens and credits). It needs an admin key with `codex.enterprise.analytics.read` on an Enterprise plan, and "OpenAI provides no direct dollar mapping for Codex credits". — [DX Codex connector](https://docs.getdx.com/connectors/codex-enterprise.md)

#### Windsurf / Devin (Cognition)
- On 31 Oct 2026, docs.windsurf.com analytics pages redirected (HTTP 307) to docs.devin.ai/desktop. The page there covers only Devin **Personal Analytics**: users see their own ACU consumption ("only ever see their own consumption, not anyone else's"), and the feature is off by default and enabled by admins. — [Devin docs](https://docs.devin.ai/desktop/accounts/analytics)
- A search snippet of the Windsurf analytics page (Japanese locale) says team leads and managers can see aggregated team analytics, including "Percent of Code Written (PCW)" by AI. The page itself was not opened. — [Windsurf docs (ja)](https://docs.windsurf.com/ja/windsurf/accounts/analytics). The Windsurf homepage carries a marketing figure of "94%" of code written by AI, with no methodology — [windsurf.com](https://windsurf.com/) (search snippet).
- Devin CLI usage counts against legacy Windsurf Enterprise allocations, and admins can pull usage analytics through an Analytics API. The search summary describes this as usage and spend data, not authorship. — [Devin docs (ja)](https://docs.devin.ai/ja/cli/enterprise/windsurf-auth) (search snippet)

### Inferences
- The vendors' per-user data, including emails, a top-10 leaderboard (Claude), per-user rows by default (Codex) and per-user AI credits (GitHub), is exactly the kind of data that triggers works-council co-determination in Germany (§5). EI vendors inherit this exposure when they ingest it.
- Each vendor's attribution method is specific to that vendor: Claude uses post-merge text matching with a 21-day window, Cursor uses client-side line accounting per commit, and GitHub counts PRs authored by the Copilot agent. Counts from different vendors therefore cannot be summed into a cross-harness "AI share" without double-counting or gaps, for example when one PR touched both Cursor and Claude Code. This is an inference; no vendor documents cross-vendor reconciliation.
- Approvals are visible in vendor data only at the level of individual tool calls, and only for Claude Code through customer-run OTel (`tool_decision.source`). Code review appears only at the PR level (GitHub). No vendor joins the two.

### Gaps
- The full Codex Analytics API field list (threads, turns, surfaces, code-review fields) was not retrieved.
- The definition and computation of Windsurf PCW, and whether it is exposed per user via API, were not confirmed. Whether Windsurf has been formally renamed (for example to "Devin Desktop") was not confirmed; only the docs redirect was observed.
- Cursor's own Analytics dashboard (as distinct from the API) was not reviewed.

---

## 3. Data sources and blind spots

### Takeaway
EI products assemble AI impact from four inputs: (a) vendor admin APIs (adoption, lines, tokens, cost, all per harness); (b) git and PR heuristics (co-author trailers, bot or agent PR authors, labels such as `claude-code-assisted`, text classifiers); (c) surveys (DX and Jellyfish Developer Insights); and, newest, (d) local capture on developer machines (Span's recorder via MDM, Git AI's agent-reported line attribution, Claude/Codex OTel to a customer collector). Blind spots that persist across all four: local CLI agent work committed under a human identity; consistent cross-harness attribution; per-action approvals; provenance that survives hosted squash and rebase merges; and whether agent code is still there N weeks later.

### Cited Findings
- **Vendor-API dependence.** Swarmia's AI cost pulls Copilot AI credits, Cursor usage, Claude Code estimated cost and Codex estimated cost, each on a different basis: list price, an estimate, or "no discounts" ([Swarmia AI cost](https://help.swarmia.com/features/ai-tools/ai-cost)). DX pulls Codex per-user token and credit data and notes there is no dollar mapping for credits ([DX Codex connector](https://docs.getdx.com/connectors/codex-enterprise.md)). LinearB uses provider APIs for adoption and usage ([LinearB FAQ](https://linearb.helpdocs.io/article/ww1ciql9uw-linear-b-ai-insights-faq)).
- **Git heuristics.** LinearB detects AI work from co-author trailers, agent PR comments and PRs opened by known agents ([LinearB FAQ](https://linearb.helpdocs.io/article/ww1ciql9uw-linear-b-ai-insights-faq)). Claude's contribution metrics label merged PRs `claude-code-assisted` after text matching ([Claude Code analytics](https://code.claude.com/docs/en/analytics)). Span's 2025 detector classified code text, with a claimed 95% accuracy ([Show HN](https://hn.svelte.dev/item/45265831), search result).
- **Surveys.** DX's framework relies on time savings and satisfaction as "direct" impact measures ([DX guide](https://getdx.com/blog/ai-measurement-framework-guide/)). Jellyfish Developer Insights are survey-based ([Jellyfish](https://jellyfish.co/?p=29717)).
- **Local capture.** Span's recorder runs on developer machines via MDM ([Span](https://www.span.app/)). Git AI says it uses "no hooks and no wrappers", with "agents report[ing] the lines they write" ([Git AI](https://usegitai.com/)). Claude Code OTel requires the customer's own collector ([Claude monitoring](https://code.claude.com/docs/en/monitoring-usage)). Codex local execution emits separate OTel events ([Codex governance](https://learn.chatgpt.com/docs/enterprise/governance)).
- **Blind spot: local CLI agents and coverage holes.**
  - GitHub dashboard charts exclude CLI, and the docs and changelog conflict on whether CLI is in totals ([GitHub docs](https://docs.github.com/en/copilot/reference/copilot-usage-metrics/copilot-usage-metrics); [changelog, 10 Apr 2026](https://github.blog/changelog/2026-04-10-copilot-cli-activity-now-included-in-usage-metrics-totals-and-feature-breakdowns)).
  - The Claude Code Analytics API excludes subscription seats and Bedrock, Foundry and Google Cloud usage; contribution metrics exclude Console API users, ZDR orgs and GHES ([Claude analytics API](https://platform.claude.com/docs/en/build-with-claude/claude-code-analytics-api); [Claude analytics](https://code.claude.com/docs/en/analytics)).
  - Codex: "Conversation visibility alone does not establish a complete record of local actions" ([Codex governance](https://learn.chatgpt.com/docs/enterprise/governance)).
  - Jellyfish's agent tracking lists PR-opening cloud agents (Devin, Factory, Codegen, Jules, and others) ([Jellyfish](https://jellyfish.co/?p=29717)).
- **Blind spot: cross-harness attribution.** GitHub's `totals_by_client` (23 Oct 2026) covers only traffic that uses Copilot models, with "best-effort" labels ([changelog](https://github.blog/changelog/2026-10-23-usage-metrics-api-adds-usage-from-tools-like-opencode), search summary; [VSM](https://visualstudiomagazine.com/articles/2026/10/27/github-tracks-copilot-model-usage-from-opencode-and-other-clients.aspx), search summary). `totals_by_3rd_party_agent` counts only job starts ([GitHub docs](https://docs.github.com/en/copilot/reference/copilot-usage-metrics/copilot-usage-metrics)).
- **Blind spot: the agent's actual actions and approvals.** Only Claude Code's OTel exposes per-tool-call decision provenance (config, hook or user), and only to a customer-run collector ([Claude monitoring](https://code.claude.com/docs/en/monitoring-usage)). Span traces capture "prompts, tool calls, model choices, file edits, and token spend" but do not mention approvals ([Span](https://www.span.app/)). GitHub excludes bot-created PRs, including Copilot cloud-agent PRs, from review-time metrics ([GitHub docs](https://docs.github.com/en/copilot/reference/copilot-usage-metrics/copilot-usage-metrics)).
- **Blind spot: provenance through rebases and squash merges.**
  - Cursor: commit hashes "are not unique or immutable"; amending produces duplicates; squash and rebase are not addressed ([Cursor docs](https://cursor.com/docs/account/teams/ai-code-tracking-api)).
  - Claude: attribution "does not consider the PR source or destination branch" and drops code rewritten by more than 20% ([Claude analytics](https://code.claude.com/docs/en/analytics)).
  - Git AI (git notes): hosted web-UI squash and rebase merges do not preserve authorship because "SCM tools aren't running Git AI on their servers"; a GitHub Actions workflow is offered to rewrite authorship. The main docs page still lists rebase as a limitation, while a July 2026 changelog describes a rewrite of rebase, squash, amend and cherry-pick handling. — [Git AI "How it works"](https://usegitai.com/docs/how-git-ai-works) (search summary); [Git AI changelog, 6 Jul 2026](https://usegitai.com/changelog/2026-07-06) (search result)
  - Agent Trace leaves rebases and merge commits "open for implementations to explore" ([agent-trace.dev](https://agent-trace.dev/)).
- **Blind spot: is agent code still there after N weeks.** Claude's "Lines of code accepted ... does not track subsequent deletions" ([Claude analytics](https://code.claude.com/docs/en/analytics)). No survival or durability metric appears in the GitHub, Cursor or Codex docs reviewed. Durability is offered only by specialist and vendor-research tools (§6).

### Inferences
- The structural gap is where the data sits. Harness vendors see the session but not what happened to the change after merge. EI platforms see git, PRs and incidents but not the session. Local recorders (Span, Git AI) see both, but store records on the vendor's cloud or in git notes that hosted squash merges break. A record kept with each run that is also reconciled with hosted merges, for example by a CI or bot step, is the missing join. This is an inference.
- Any squash-merge-heavy organisation (common on GitHub) will see line-level AI attribution degrade unless the attribution tool runs server-side or in CI. This is inferred from the Git AI and Cursor documentation.

### Gaps
- I found no published accuracy comparison across attribution methods (text matching, co-author trailers, classifiers, agent-reported lines).
- How Faros "connects agent sessions" to PRs (the matching method) is undocumented on its page.
- Whether Span ingests approval or permission events was not documented on the pages retrieved.

---

## 4. What engineering leaders and finance say they need (2025–2026)

### Takeaway
Leaders' language moved from "adoption" (2025) to "accountability" (2026). They want proof that AI spend produces shipped, stable outcomes, because usage metrics are widely distrusted: 58% of LeadDev's 2026 respondents call token-usage metrics ineffective. They want cost governance under usage billing: per-user spend rose roughly 16x in ten months in Jellyfish data, Uber capped spend per tool, and Gartner warns that AI coding costs could exceed developer salaries by 2028. And they are watching quality and stability (DORA 2025 found AI still negatively related to stability; Faros finds review time up 5x) and a review bottleneck. Figures below come from different populations and must not be combined.

### Cited Findings
- **DORA 2025** (Google Cloud-run survey of nearly 5,000 technology professionals, plus 100+ hours of qualitative data; published 23 Sept 2025):
  - 90% use AI at work; more than 80% believe it increased their productivity; 30% report little or no trust in AI-generated code.
  - AI adoption is now *positively* related to throughput but still *negatively* related to delivery stability.
  - "AI doesn't fix a team; it amplifies what's already there."
  - Seven team archetypes and a seven-capability AI model.
  — [Google Cloud blog](https://cloud.google.com/blog/products/ai-machine-learning/announcing-the-2025-dora-report)
- DORA now lists five delivery metrics. **Deployment rework rate** ("unplanned [deployments] ... as a result of an incident in production") joins change fail rate under "instability". DORA also warns against using metrics as goals or for cross-team competition. — [dora.dev metrics guide](https://dora.dev/guides/dora-metrics/)
- **DX budget research** (vendor-run; 50 engineering budget holders plus a 275-leader poll; page updated 15 Oct 2025):
  - Nearly half allocate 1–3% of total engineering budget to AI tools.
  - 2025 per-developer spend: 38.4% spent $101–500/year; 10.5% spent $501–1,000; 10.5% spent over $1,000.
  - $1,000/developer/year is a common 2026 target, with $500 to $3,000+ expected.
  - 86% are uncertain which tools deliver most benefit; 40% lack the data to build an ROI case.
  - Leaders want to **cap spend by team or job title, but "most usage-based enterprise plans lack that granularity"**.
  — [DX blog](https://getdx.com/blog/how-are-engineering-leaders-approaching-2026-ai-tooling-budget/)
- **Jellyfish 2026 State of Engineering Management** (vendor-run; 600+ respondents; article dated 12 May 2026):
  - 64% report at least a 25% velocity gain from AI; 42% cite rising AI tool costs as a challenge; 60% need better data to understand productivity.
  - Only 10% report strong enablement and high adoption across the organisation.
  — [Jellyfish SEMR blog](https://jellyfish.co/blog/the-state-of-engineering-management-in-2026/)
  - A follow-up post (11 Jun 2026) adds that 46% actively track AI-specific metrics (adoption, acceptance, model usage) and that 42% named rising AI tool expense as their *primary* adoption challenge, ahead of security and quality. Boards ask "how much is spent on AI, which teams generate the most value, whether productivity gains offset costs". One platform leader describes leadership cutting access to a coding assistant over token costs. — [Jellyfish, "AI Adoption to AI Accountability"](https://jellyfish.co/blog/2026-engineering-leaders-shifting-from-ai-adoption-to-ai-accountability/)
- **LeadDev AI Impact Report 2026** (591 engineering leaders, per LeadDev's search listing; full report behind login):
  - 70% have adopted AI developer tools "widely or completely".
  - 26% report "major productivity gains", but only 31% measure them.
  - **58% say token usage metrics are ineffective.**
  - 62% expect fewer junior hires.
  — [LeadDev AI Impact Report 2026](https://leaddev.com/the-ai-impact-report-2026/)
  - Panel and event pages, seen only in search summaries, say 68% cite "lack of clear metrics" as their top AI challenge and that concern about AI tool costs rose from 35% to 62% in a year. Not verified. — [LeadDev event page](https://leaddev.com/event/how-ai-is-changing-engineering) (search result)
- **Gartner** (Nitish Tyagi; release dated 24 Jun 2026, reported by CFOtech on 25 Jun 2026; the Gartner page itself returned 403):
  - AI coding costs are predicted to surpass the average developer's salary by 2028.
  - Budgets "often running out earlier than planned".
  - Vendors lack mature built-in cost-optimisation features.
  - "Most organisations still lack the maturity and frameworks to effectively measure cost versus business impact."
  - Recommendations: token thresholds, escalation policies, automated monitoring, classifying work as developer-led, shared with agents, or mainly agent-led, and matching model size to the task.
  — [CFOtech UK](https://cfotech.co.uk/story/gartner-warns-ai-coding-costs-may-top-developer-pay-by-2028); [Gartner release (403)](https://gartner.com/en/newsroom/press-releases/2026-06-24-gartner-predicts-ai-coding-costs-will-surpass-average-developer-salary-by-2028-as-token-consumption-surges)
- **Budget caps, real cases.**
  - Uber reportedly capped AI coding-tool spend at $1,500 per employee per month *per tool* (Claude Code, Cursor and others) after exhausting its 2026 AI coding budget within about four months. The CTO disclosed the overrun in April. Usage is tracked on an internal dashboard and exceptions can be approved. — Bloomberg, 2 Jun 2026, via [Simon Willison, 3 Jun 2026](https://simonwillison.net/2026/Jun/3/uber-caps-usage/) and [Let's Data Science](https://letsdatascience.com/news/uber-caps-employee-ai-coding-tool-spending-8d1bc22d) (search results; Bloomberg not opened). Secondary reports say Claude Code adoption at Uber rose from 32% (Feb) to 84% (Mar) of a 5,000-person engineering organisation (unverified).
  - Meta: internal AI use is reportedly heading toward "billions" in costs in 2026, with budgets and a central dashboard from 2027 — [The Decoder, 8 Sept 2026](https://the-decoder.com/meta-drops-ai-usage-from-engineer-performance-reviews-after-tokenmaxxing-backfires/) (citing The Information).
- **Quality, stability and the review bottleneck.**
  - Faros 2026 telemetry (vendor), high versus low adoption: median review time 5x, incidents/PR 3x, bugs/PR +28%, churn about 10x, deployments/week −11.7% — [Faros](https://faros.ai/research/ai-acceleration-whiplash).
  - Claude Code PRs waited longest for first human review, a 12.6 h median across 37,623 agent PRs. This is independent academic work (single author, arXiv, 12 Sept 2026) — [arXiv 2609.17598](https://arxiv.org/abs/2609.17598).
  - Jellyfish: agentic PRs merged more slowly than unassisted PRs in Q1 2026, and the gap later closed — [Jellyfish H1 2026](https://jellyfish.co/state-of-ai-software-engineering/).
  - Uplevel warns that review and validation "absorbs the extra load" — [Uplevel](https://uplevelteam.com/).
- **GitClear** (vendor code-analysis research):
  - The 2025 report (211M changed lines, Jan 2020–Dec 2024) found copy/pasted lines rose from 8.3% (2021) to 12.3% (2024) while moved (refactored) lines fell from 25% to under 10%. For the first time, copy/paste exceeded moved code. — [GitClear 2025 research](https://www.gitclear.com/ai_assistant_code_quality_2025_research)
  - A 2026 "Maintainability Gap" report (623M changes, 2023–2026) is cited only by secondary blogs. They report block duplication up 81% (from 40.3 to 73.0 duplicated lines per million changed lines). These figures were not verified on a GitClear page, and the blogs disagree on baselines. — [Refonte Learning (secondary)](https://www.refontelearning.com/blog/ai-generated-code-technical-debt) (search result)

### Inferences
- The needs cluster into three buyer questions. (1) Did spend produce merged, kept work? This is the ROI question finance asks. (2) Can spend be capped and allocated by team, person or tool? DX says vendor plans lack this granularity; Uber and Meta built their own caps and dashboards. (3) Is the extra volume degrading stability and review? DORA, Faros and arXiv all point to stability and review costs. All three require joining per-run cost to post-merge fate, which (§3) no single data source does.
- Caps are being set per tool (Uber), so organisations need spend per person and per harness under one roof. That favours a harness-neutral meter. This is an inference.

### Gaps
- The LeadDev 2026 report's sample, fieldwork dates and cost and quality figures were behind a login. A figure of 18% measuring AI impact, attributed to LeadDev's 2025 edition (880+ leaders, run with DX), appeared only in a search summary and is unverified.
- No primary CFO-authored commentary (as opposed to vendor blogs) was found. The Pragmatic Engineer piece on how 18 companies measure AI impact was not fetched; only DX's teaser was seen ([DX newsletter, 17 Sept 2025](https://newsletter.getdx.com/p/how-18-companies-measure-ai-impact-in-engineering)).
- The DORA 2025 report's numeric stability or rework results were not retrieved; only the direction of the relationships was.

---

## 5. Privacy backlash against measuring individual developers

### Takeaway
2026 brought visible backlash. Meta dropped AI-usage and token metrics from engineer reviews after "tokenmaxxing" (Sept 2026). Duolingo's CEO backtracked on AI-usage requirements. A Harness-commissioned survey found 54% of developers fear AI-data-based evaluations. Vendors respond unevenly. DX, Span and Devin explicitly aggregate or restrict; GitHub suppresses teams under 5 users. But Claude's dashboard ships a top-10 leaderboard, and Codex and Cursor default to per-user rows. In Germany, monitoring-capable tools need works-council agreement under §87(1) No. 6 BetrVG before rollout.

### Cited Findings
- **Meta** (8 Sept 2026): Meta told employees that AI tool usage will no longer count in engineer performance reviews, after staff used large token volumes to climb internal leaderboards ("tokenmaxxing"). Reviews now weigh "quality, speed, and complexity of the work". The source is an internal memo reported by The Information. — [The Decoder](https://the-decoder.com/meta-drops-ai-usage-from-engineer-performance-reviews-after-tokenmaxxing-backfires/)
- **Duolingo** (around 13 Apr 2026): CEO Luis von Ahn said the company "backtracked" on evaluating employees on AI usage after backlash — [Fortune](https://dc.fortune.com/2026/04/13/duolingo-ceo-luis-von-ahn-ai-usage-requirement-employee-performance-evaluations) (search result, not opened).
- **Developer sentiment** (Harness-commissioned survey, vendor-commissioned; 700 practitioners and managers in the US, UK, FR, DE and IN; reported 15 May 2026):
  - 54% fear performance evaluations tied to their AI use.
  - 55% want reviews to separate improvement data from performance data.
  - 49% want to help define the AI metrics.
  - Harness's SVP: leaders can now see "how code is written, not just the final pull request".
  — [IT Brew](https://www.itbrew.com/stories/developers-fear-performance-evaluations-based-on-ai-data-survey)
- Reports also claim Google factors AI use into some engineer reviews and that JPMorgan classifies 65,000 engineers as light, heavy or non-users. These come from aggregator outlets in a search summary and are unverified. — [ai2.work](https://ai2.work/blog/jpmorgan-now-tracks-employee-ai-usage-in-performance-reviews) (search result, low reliability)
- **How vendors handle it.**
  - DX: do not use the metrics for individual evaluation, and tell teams so ([DX](https://getdx.com/blog/ai-measurement-framework-guide/)).
  - Span: sessions "belong to the engineer"; reports are "never people"; prompts and full traces are visible only to the trace's author ([Span](https://www.span.app/); [Span security](https://span-knowledge-base.help.usepylon.com/articles/8922907265-span-agent-trace-analytics-security-overview)).
  - Devin Personal Analytics: users see only their own consumption ([Devin docs](https://docs.devin.ai/desktop/accounts/analytics)).
  - LinearB: individual views can be restricted by RBAC ([LinearB](https://linearb.helpdocs.io/article/ww1ciql9uw-linear-b-ai-insights-faq)).
  - GitHub: excludes teams with fewer than 5 seated users from team reports ([GitHub docs](https://docs.github.com/en/copilot/reference/copilot-usage-metrics/copilot-usage-metrics)).
  - By contrast, Claude's Team/Enterprise dashboard has a top-10 **leaderboard** and an all-user CSV export, and Anthropic suggests using it to "identify power users" ([Claude analytics](https://code.claude.com/docs/en/analytics)).
  - Codex's Analytics API returns per-user rows by default ([OpenAI analytics API](https://developers.openai.com/es-419/docs/enterprise/analytics-api), search summary).
  - Swarmia shows per-person AI cost and day-by-day usage ([Swarmia](https://help.swarmia.com/features/ai-tools/ai-cost)).
  - DORA warns against using metrics as goals or for competition ([dora.dev](https://dora.dev/guides/dora-metrics/)).
- **EU and Germany works councils** (Covington overview, "as of July 2026"):
  - §87(1) No. 6 BetrVG (technical monitoring) requires the employer to "reach agreement before introducing monitoring-capable AI". The overview rates this high risk, with possible injunctions and suspension of the tool, including where the works council is formed after deployment.
  - §94(2) applies to AI-based assessment principles. Art. 26(7) of the EU AI Act requires informing the works council before deploying a high-risk AI system.
  - Measures implemented without the required consent may be "legally ineffective".
  - A general-purpose assistant such as Microsoft Copilot typically does not by itself trigger §95.
  - Reforms to ease AI introduction are being discussed.
  — [Covington PDF](https://www.cov.com/-/media/files/corporate/publications/2026/07/works-council-rights-in-ai-implementation-projects.pdf)
  - CMS reports a German labour-court decision finding no co-determination where employees used their own ChatGPT accounts and the employer had no access to usage data — [CMS](https://cms.law/de/deu/legal-updates/kein-mitbestimmungsrecht-des-betriebsrats-bei-chatgpt-amp-co) (search summary, not opened).

### Inferences
- The legal trigger in Germany is whether the employer *can* monitor performance or behaviour, not whether it intends to. A record "held under the team's own keys" is still employer-accessible and would likely need a works-council agreement. A design that keeps per-person detail under per-developer keys and exports only thresholded aggregates (as GitHub's 5-user floor does) may reduce that exposure. Legal review is needed. This is an inference from the Covington and CMS material.
- Gaming risk is now proven at scale (Meta's tokenmaxxing). Metrics based on outcomes and survival are harder to game than token or usage counts, which is a market argument for outcome metrics. This is an inference.

### Gaps
- No works-council agreement specific to developer-AI telemetry (for example covering Copilot or Claude Code metrics) was found.
- No EI vendor documentation describing EU works-council templates was found.
- No independent (non-vendor) survey of developer attitudes to AI telemetry was found for 2026.

---

## 6. The opportunity: outcome-based agent measurement and a harness-neutral, private record

### Takeaway
Demand for outcome measurement over usage measurement is well evidenced. LeadDev reports that 58% call token metrics ineffective. Faros calls acceptance and token volume poor proxies. Meta moved reviews to quality of work. Gartner says organisations lack frameworks to measure cost against impact. Two of the three proposed metrics already exist in partial form: cost per merged change by tool (Faros, Swarmia, Span, Waydev, Git AI) and code survival or durability (Git AI, Greptile, Larridin, GitClear, academic studies). **No product found joins per-action approval provenance to later reverts.** "Approval-to-revert ratio", and survival measured per agent run across harnesses and through squash merges, are where a private, neutral record could offer something new. Standards (Cursor's Agent Trace) and harness owners (OpenAI hiring the Git AI team; Anthropic's contribution metrics) are converging on attribution, so the defensible position is the neutral, customer-keyed, tamper-evident record and the approval layer, not the dashboard.

### Cited Findings
- **Demand for outcome over usage.**
  - LeadDev 2026: 58% say token usage metrics are ineffective; only 31% measure productivity gains ([LeadDev](https://leaddev.com/the-ai-impact-report-2026/)).
  - Faros: seat counts, token volume and acceptance rates are "poor proxies"; it defines cost per merged PR, ticket or feature ([Faros](https://www.faros.ai/solutions/ai-coding-roi)).
  - Jellyfish: leaders must show "the return on every token they spend" ([Jellyfish, 11 Jun 2026](https://jellyfish.co/blog/2026-engineering-leaders-shifting-from-ai-adoption-to-ai-accountability/)).
  - Meta now reviews on quality, speed and complexity of work rather than AI usage ([The Decoder](https://the-decoder.com/meta-drops-ai-usage-from-engineer-performance-reviews-after-tokenmaxxing-backfires/)).
  - Gartner: organisations lack frameworks "to effectively measure cost versus business impact" ([CFOtech](https://cfotech.co.uk/story/gartner-warns-ai-coding-costs-may-top-developer-pay-by-2028)).
- **Survival and durability evidence and products.**
  - Rahman & Shihab (arXiv, 23 Jan 2026; 200,000+ code units, 201 OSS projects): agent-authored code "survives significantly longer". Its line-level modification rate is 15.8 percentage points lower (HR 0.842), with slightly higher corrective-change rates (26.3% vs 23.0%). The effect is small, and "per-agent variation exceeds the agent-human gap". — [arXiv 2601.16809](https://arxiv.org/abs/2601.16809)
  - Kraishan (arXiv, 12 Sept 2026; 37,623 PRs from Codex, Devin, Copilot, Cursor and Claude Code, Dec 2024–Jul 2025): revert rates differ by vendor (Codex 6.1% vs human 11.5%; Devin 14.5%), and "quality differences are vendor-specific". — [arXiv 2609.17598](https://arxiv.org/abs/2609.17598)
  - Greptile agent leaderboard (vendor; April 2026): reverts per 1,000 merged PRs were Codex 1.19, Claude 1.80, human 2.72, Cursor BG 3.41 and Devin 3.50. 7-day file churn was 5.7%, 8.1%, 10.0%, 8.8% and 13.5% respectively. The detection method is not documented. — [Greptile leaderboard](https://www.greptile.com/agent-leaderboard)
  - The arXiv and Greptile revert figures use different definitions and populations and must not be compared or combined.
  - Larridin defines a "Code Turnover Rate": the share of merged code reverted, deleted or substantially rewritten within 30 or 90 days, split by AI and human code ([Larridin (vendor)](https://larridin.com/developer-productivity-hub/code-turnover-rate-ai-quality-metric), search summary).
- **Git AI** (open source; 1.0 announced 8 Nov 2025):
  - Line-level authorship stored in git notes, linked to agent, model and prompt.
  - Supported agents: Cursor, Codex, Claude Code, Copilot, Gemini, OpenCode, Junie, Droid, Windsurf and Amp.
  - The Teams tier adds a "secure prompt store", token-to-PR linking, % AI by PR, team and repo, rework tracking ("20% reworked within a week of shipping" in its sample dashboard) and incident linking.
  - About 2.9k GitHub stars; claims "hundreds of engineering teams".
  — [Git AI homepage](https://usegitai.com/); [Git AI 1.0 post](https://usegitai.com/blog/introducing-git-ai)
  - Its founders joined OpenAI's Codex team, reported around 12 Sept 2026, to work on "better data on how coding agents perform and the returns they generate". Reports say it is not a formal acquisition and that the open-source project continues. — [The New Stack](https://thenewstack.io/openai-hires-git-ai/) (search summary)
- **Agent Trace** (Cursor; v0.1.0 RFC, Jan 2026):
  - A vendor-neutral JSON trace record that maps file line ranges (with optional `content_hash`) to contributor type (human/ai/mixed/unknown), model, conversation URL, tool name and version, and VCS revision.
  - Storage is "implementation-defined" (local files, git notes or databases).
  - Partners listed: Amp, Amplitude, Cline, Cloudflare, Cognition, git-ai, Jules, OpenCode, Tapes and Vercel.
  - Non-goals include "quality assessment of AI contributions". Approvals, cost and outcomes are not in the schema.
  — [agent-trace.dev](https://agent-trace.dev/)
- **Cost per merged change by tool already exists in some form.** Faros cost per outcome by team, model and tool ([Faros](https://www.faros.ai/solutions/ai-coding-roi)); Swarmia per-issue and per-PR allocation by tool at list price ([Swarmia](https://help.swarmia.com/features/ai-tools/ai-cost)); Span $ per session ([Span](https://www.span.app/)); Waydev "AI Spend Hub" ([Waydev](https://waydev.co/)); Git AI Teams token-to-PR linking ([Git AI](https://usegitai.com/)). Inputs are inconsistent: estimates, list prices, and Codex credits with "no direct dollar mapping" ([DX Codex connector](https://docs.getdx.com/connectors/codex-enterprise.md)). Coverage is also incomplete: the Claude API excludes Bedrock, Vertex and Foundry ([Claude analytics API](https://platform.claude.com/docs/en/build-with-claude/claude-code-analytics-api)).
- **Approval data exists only in fragments.** Claude Code's OTel `tool_decision.source` (config, hook or user) ([Claude monitoring](https://code.claude.com/docs/en/monitoring-usage)); Codex hook-based auditing and Compliance API logs ([Codex governance](https://learn.chatgpt.com/docs/enterprise/governance)); GitHub PR review data ([GitHub docs](https://docs.github.com/en/copilot/reference/copilot-usage-metrics/copilot-usage-metrics)). No EI product page reviewed describes joining these to reverts or incidents.
- **Ability to pay** (market signals):
  - Atlassian–DX at about US$1B (Sept 2025) ([BNN Bloomberg](https://www.bnnbloomberg.ca/business/2025/09/18/atlassian-to-acquire-developer-productivity-platform-dx-for-us1-billion), search result).
  - Span $25M (Nov 2025) and Swarmia €10M (Jun 2025) (sources in §1).
  - EI contracts of about $179–$433/developer/year (Swarmia, Vendr), a median $12K/year (Haystack, Vendr) and from $25K (Uplevel, Capterra) (sources in §1).
  - DX advises budgeting for measurement as part of AI tooling spend ([DX](https://getdx.com/blog/how-are-engineering-leaders-approaching-2026-ai-tooling-budget/)).

### Inferences
- **Agent change survival rate.** This would be novel only if it is (a) per agent run and per harness, (b) consistent across harnesses, and (c) robust to hosted squash and rebase merges. Today: Claude matches text post-merge but "does not track subsequent deletions"; Cursor's commit hashes are mutable; Git AI's git-notes approach breaks on hosted squash merges without a CI step; Greptile and arXiv measure per vendor, not per run. A sidecar record keyed by content hashes (compatible with Agent Trace's `content_hash`), plus a post-merge reconciler running in CI or as a repo bot, could produce it. A local sidecar alone cannot see hosted merges.
- **Cost per merged change by harness.** Already offered in rough form by four or five vendors, so not novel as a metric. A sidecar could still make it more accurate: per-run actual tokens across harnesses, including local CLI and bring-your-own-key, Bedrock or Vertex usage that vendor APIs miss, and attribution per run instead of Swarmia-style daily allocation. The pitch would be "the only cost-per-change figure you can audit", not a new metric.
- **Approval-to-revert ratio.** I found it nowhere. Variants it could support: reverts or incidents per 100 human-approved actions versus config- or hook-auto-approved actions, per approver role, per harness and per permission mode. It speaks to the review bottleneck and stability concerns (Faros 5x review time; DORA's negative stability link; GitHub excluding bot PRs from review timing). But I found **no direct survey evidence** that leaders ask for approval-quality metrics. Demand is inferred, not observed. It also carries the highest privacy risk, because approvers are individuals, so it would need aggregation by role or team to avoid the backlash in §5.
- **Would buyers pay, or is it a feature?** EI platforms are adding cost-per-outcome and agent views quickly, and harness owners are moving into attribution (OpenAI and Git AI; Cursor's Agent Trace; Anthropic contribution metrics; GitHub `totals_by_client`). A standalone metrics dashboard would probably become a feature within 12 to 18 months. The parts that are hard to copy are structural:
  - neutrality (harness vendors measure themselves; Anthropic labels its own metrics "deliberately conservative");
  - customer-held keys and tamper-evidence (Span stores on its own AWS; Git AI notes are mutable git data);
  - approval provenance across harnesses.
  The likely business is a data layer that EI platforms ingest (an Agent Trace-compatible export plus approvals and fate), with governance and audit buyers (security, legal, works councils) as a second paying constituency alongside engineering and finance. This is an inference; no buyer survey tests willingness to pay for it.
- Competitive risk to watch: Span already combines a local recorder, traces, cost per session and engineer-private sessions. If Span adds customer-managed keys and approval capture, the differentiation narrows to tamper-evidence and the open, cross-harness format.

### Gaps
- No survey asks leaders directly about willingness to pay for per-run provenance, approval audit or survival metrics.
- No product was found offering approval-to-revert or similar metrics. Absence is based on the pages reviewed, not an exhaustive search.
- Git AI's 30/60/90-day durability figures (about 30% to 85% by team) appeared only in a search summary and not on its homepage.
- Whether Agent Trace has actual adopters beyond its listed partners, and whether it will add approval or outcome fields, is unknown.
- Span pricing, and whether Span captures approval or permission events, are unknown.
