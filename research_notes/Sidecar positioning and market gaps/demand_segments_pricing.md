# Demand signals, buyer segments, and pricing benchmarks for agent infrastructure near an AI-agent sidecar (as of 31 October 2026)

Scope: this round covers new evidence only. It does not repeat the earlier rounds' per-tool shares from JetBrains and Stack Overflow, the ngrok, AgentMail and Resend price lists, Mem0's PyPI numbers, ngrok's signup claim, or the NANDA, METR and Stanford findings. Pages were fetched on 31 Oct 2026 unless a different date is given. "Vendor claim" marks figures a company reports about itself.

## (a) How many developers use more than one agent harness, or run agents in parallel?

### Takeaway
Roughly one-third of developers who use agents at work run more than one agent (Stack Overflow pulse, Apr 2026). These multi-agent users are the heaviest users. About two-thirds of Stack Overflow 2026 respondents switched AI tools in the past year. No primary 2026 survey reports the share of developers using two or more distinct harnesses, and none measures how many agents run at the same moment.

### Cited Findings
**Stack Overflow AI-agent pulse survey (published 27 May 2026; about 1,100 developers and tech professionals; fielded late April 2026)**
- 59% use AI agents at work at any frequency, up from 31% in the 2025 Developer Survey. Daily use is 37%, up from 14% — [Stack Overflow blog](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)
- How respondents set up agents: 69% use a "single agent", 17% use "multiple specialized agents", and 16% use "multiple overlapping or coordinated agents". The three figures sum to 102%, and the post does not say whether the question allowed several answers — [Stack Overflow blog](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)
- Daily use by setup: 54% of single-agent users, 85% of users with multiple specialized agents, and 77% of users with coordinated agents — [Stack Overflow blog](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)
- 68% prefer predictable single-agent setups to multi-agent configurations. 63% rarely or never let agents run fully on autopilot, and 60% block agents from making unapproved system changes — [Stack Overflow blog](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)
- Most-used code assistants in the previous six months: GitHub Copilot 61% and Claude Code 51% — [Stack Overflow blog](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)

**Stack Overflow 2026 Developer Survey (results published 6 Oct 2026; "more than 30,000" people took it)**
- Tools in use include Claude Code at 66% and GitHub Copilot at 59%. The AI page does not state the base for these figures — [SO 2026 AI results](https://survey.stackoverflow.co/2026/ai); [SO blog](https://stackoverflow.blog/2026/10/06/the-results-of-the-2026-developer-survey-are-here/)
- Switching AI tools in the past year (n=13,144):
  - "No": 33.7%
  - Yes, for better output quality: 25.1%
  - Yes, because the organization required or recommended a different tool: 10.6%
  - Yes, for better workflow or IDE integration: 7.4%
  - Yes, for lower cost: 6.4%
  - Yes, for better support for agents, automation, or coding workflows: 3.7%
  - Yes, because the previous tool became too expensive, limited, or unavailable: 3.3%
  - Yes, for better security, privacy, or compliance: 2.2%
  - Yes, for access to a preferred model: 2.1%
  - Yes, for a specific feature: 1.4%
  - Yes, another reason: 3.6%
  - Do not use AI at work: 0.6%
  - Source: [SO 2026 AI results](https://survey.stackoverflow.co/2026/ai)
- Time spent with AI (n=10,926): 31% use it 4+ hours a day, 24% 2–4 hours and 25% 1–2 hours. The blog gives 26% for 1–2 hours — [SO 2026 AI results](https://survey.stackoverflow.co/2026/ai)

**Temporal "State of Development 2026" (published 25 Aug 2026; vendor-sponsored)**
- Method: Qualtrics fieldwork ran 29 Apr–25 May 2026. All respondents were current AI-agent users: 650 were solicited and 554 kept after quality checks. About two-thirds were in the US and one-third in the UK/EMEA. The report defines an agent as "An LLM instance capable of taking multi-step actions on its own" — [Temporal](https://temporal.io/reports/state-of-development-2026)
- Agents per respondent: median 5.0, mean 10.7, maximum 256. 2.2% run 51 or more — [Temporal](https://temporal.io/reports/state-of-development-2026)
- The average team uses 3.5 of the listed AI tools. "Successful" teams use 3.6, other teams 2.7, and Temporal users 5.0 — [Temporal](https://temporal.io/reports/state-of-development-2026)

**GitHub Octoverse 2026 (published 28 Oct 2026; data from 1 Oct 2025 to 30 Sep 2026)**
- Agents started more than 40% of pull requests in Sep 2026, up from 17% in March. They started 110M pull requests in September, about 6x the March volume. GitHub says its agent detection is "a floor" — [GitHub Octoverse](https://github.blog/news-insights/octoverse/octoverse-commits-pushes-reach-new-highs-in-2026-as-developers-build-with-agents/)
- 55% of Copilot monthly active users use agentic features, up from 35% a year earlier. Copilot cloud agent usage grew 230% year over year — [GitHub Octoverse](https://github.blog/news-insights/octoverse/octoverse-commits-pushes-reach-new-highs-in-2026-as-developers-build-with-agents/)
- In Sep 2026, 61% of Copilot users who chose their own model used more than one model, up from 50% four months earlier. Paying users used 47 distinct models in September, and no model exceeded 25% of requests. This measures multi-model use, not multi-harness use — [GitHub Octoverse](https://github.blog/news-insights/octoverse/octoverse-commits-pushes-reach-new-highs-in-2026-as-developers-build-with-agents/)
- By contributor growth among product-led repos, anthropics/claude-code ranks #1, openai/codex #2, anomalyco/opencode #3, github/copilot-cli #5 and google-gemini/gemini-cli #7. Octoverse gives no figures for agents per developer or for cloud versus local execution — [GitHub Octoverse](https://github.blog/news-insights/octoverse/octoverse-commits-pushes-reach-new-highs-in-2026-as-developers-build-with-agents/)

**JetBrains Developer Ecosystem Survey 2026 (fielded May–July 2026; >15,000 professional developers)**
- 90% use AI coding agents at work at least weekly, and 68% use them daily. Awareness of Copilot and Claude Code is 79% each. Codex awareness rose from 27% in Jan 2026 to 65% in May–Jul 2026. These figures come from GIGAZINE (24 Aug 2026) because the JetBrains blog returned HTTP 403 — [GIGAZINE](https://gigazine.net/gsc_news/en/20260824-ai-coding-agent-adoption-trends/); primary: [JetBrains blog](https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/) (not loadable)

**Vendor features built for multi-harness and parallel use (vendor docs, 31 Oct 2026)**
- Copilot Pro+ and Max include delegating tasks to third-party agents (Claude and OpenAI Codex, in preview) — [GitHub Copilot plans](https://github.com/features/copilot/plans)
- Claude Code docs: "each `--cloud` command creates its own cloud session … they'll all run simultaneously". "Running multiple tasks in parallel consumes more rate limits proportionately" — [Claude Code docs](https://code.claude.com/docs/en/claude-code-on-the-web)

**Weak or dated figures (not usable as 2026 evidence)**
- "59% running three or more AI tools in parallel" appears in a compiled-statistics blog. It seems to trace back to Q1 2025 data and is unverified — [Uvik](https://uvik.net/blog/ai-coding-assistant-statistics/)
- "74% of developers now run multiple AI agents" (Apr 2026) is an adoption statistic, not a measure of parallel use — [agentmarketcap.ai](https://agentmarketcap.ai/blog/2026/04/05/dual-tool-developer-stack-cursor-claude-code-multi-agent-workflows)

### Inferences
- **Lower bounds on dual use.** If the SO 2026 shares for Claude Code (66%) and Copilot (59%) come from one multi-select base, at least about 25% of those respondents use both. The same arithmetic on the pulse survey (Copilot 61%, Claude Code 51%) gives at least about 12%. These are minimums from pigeonhole arithmetic, not estimates, and the two surveys have different bases, so they should not be combined.
- **Tool churn.** In SO 2026, the "Yes" answers on switching sum to about 65.8%. Harness loyalty is weak, which supports a harness-neutral sidecar whose memory and context survive a tool switch. 10.6% switched because their employer told them to, so the organization chooses the harness for a meaningful minority.
- **Who runs several agents.** Multi-agent users are a minority (about one-third of agent users), but they use agents far more: 77–85% use them daily, against 54% of single-agent users. That makes them a plausible first segment for coordination features such as shared memory and a group inbox.
- **Temporal's "5 agents".** Temporal's median counts agent instances or apps per respondent, not coding harnesses, so it cannot be compared with the SO figures.
- **Platforms are going multi-harness.** GitHub's delegation to Claude and Codex and its multi-model routing show the platforms becoming multi-harness themselves. This supports the premise behind a neutral sidecar but also means GitHub is a direct competitor for the coordination layer.

### Gaps
- No primary JetBrains figure for the share of developers using two or more agents. Both JetBrains research posts (Aug 2026 and Apr 2026) returned HTTP 403, and secondary coverage reports no multi-tool share or local-versus-cloud split.
- No credible 2026 survey measures concurrent sessions, meaning the share of developers running two or more agents at the same moment. The results of Nikolas Burk's "State of Agentic Coders (Q1 2026)" survey ([form](https://tally.so/r/WORrLJ)) were not found.
- I did not check the SO 2026 raw data at /2026/ai/data for a "number of AI tools used" variable or organization-size crosstabs.
- Octoverse 2026 gives no figures for agents per developer or for cloud versus local execution.

## (b) Do cloud/background agents need, and lack, reach into private networks and local machines?

### Takeaway
The need is real: every major cloud-agent vendor now documents some route to private resources. Most of those routes are restricted in at least one way:
- available only on Enterprise plans or through sales (Cursor PrivateLink, Devin dedicated deployments)
- tied to a single provider (Codex supports only Tailscale)
- limited to some protocols (Codex: HTTP/HTTPS, plus TCP through a CONNECT proxy)
- dependent on the customer running its own compute (Copilot self-hosted runners, Claude self-hosted environments)

No vendor documents letting a cloud agent reach a developer's own laptop or localhost. Direct user complaints exist but are few and anecdotal.

### Cited Findings
**OpenAI Codex cloud**
- Docs: "Give cloud tasks access to services on your private network through a VPN connection." "Tailscale is currently the supported VPN provider", with more providers planned. Private IPv4 subnet routes are supported. TCP services "such as databases or SSH" are reached through the environment's HTTP CONNECT proxy at `proxy:8088`. The page is undated — [OpenAI Codex docs](https://learn.chatgpt.com/docs/environments/cloud-environments)
- For public services that filter by source IP, OpenAI publishes an agent egress IP feed (openai.com/chatgpt-agents.json). The ranges are shared across customers, and OpenAI advises checking the feed daily. Listed limitations include no support for GitLab or self-hosted GitHub Enterprise Server — [OpenAI Codex docs](https://learn.chatgpt.com/docs/environments/cloud-environments)
- Tailscale blog (6 Oct 2026): "Codex Cloud shipped with Tailscale support. Nobody told us." "There was no partnership agreement, custom API, or integration project." It also warns, "By default, Codex could reach nearly everything in your tailnet." The feature is rolling out to paid ChatGPT accounts (Plus and higher) — [Tailscale blog](https://tailscale.com/blog/codex-cloud-tailscale)
- **Conflict:** Tailscale's post lists MagicDNS, split DNS, UDP, ICMP, inbound connections to the Codex node, and SSH as unsupported. OpenAI's docs say tasks "can use Tailscale split DNS and MagicDNS" and can reach SSH through the proxy — [Tailscale blog](https://tailscale.com/blog/codex-cloud-tailscale); contradicted by [OpenAI Codex docs](https://learn.chatgpt.com/docs/environments/cloud-environments)

**Cursor Cloud Agents**
- Cloud Agents "do not need to run on your hardware to reach private resources". The docs describe two routes: Tailscale userspace networking and Cloudflare Tunnel. For TCP targets such as databases, "the agent connects to `localhost`" and the tunnel forwards the traffic to the private origin. Cursor publishes egress CIDR ranges but changes them, and it does not recommend IP allowlisting as the main control. Locking the network policy is Enterprise-only — [Cursor docs: security & network](https://cursor.com/docs/cloud-agent/security-network)
- "Cursor supports private network connectivity for Enterprise teams" through AWS PrivateLink (preferred for GitHub Enterprise Server and GitLab Enterprise) or Cloudflare Tunnel, arranged through sales. It does not support self-signed certificates, unencrypted connections, SSH, custom ports or IPv6-only endpoints. The scope is source control and package registries — [Cursor docs: private connectivity](https://cursor.com/docs/cloud-agent/private-connectivity)
- An older Cursor network-configuration page says Cloud Agents run on Cursor infrastructure and cannot reach internal resources. It looks stale next to the pages above (seen in a search snippet, undated) — [Cursor network config](https://prod.cursor.com/docs/enterprise/network-configuration)
- A Cursor docs changelog from July 2026 says the self-hosted runtime docs were removed. The security docs no longer recommend "My Machines" or the "Self-Hosted Pool" for private network access (secondary changelog mirror) — [techdevnotes](https://techdevnotes.com/releases/cursor-docs/20260717-062020Z-09f6be259344)
- **User complaint (forum, 31 Jan 2026):** "We have an app that relies on a VPN connection." The user wanted agents to run scripts, codegen and tests against internal APIs. Cursor staff replied on 9 Feb 2026: "while in theory nothing should stop you from configuring your VPN on the cloud agent host … it might be simpler to put the cloud agent IPs on an allow list" — [Cursor forum](https://forum.cursor.com/t/cursor-agents-with-access-to-our-vpn-or-environment-variables/150497)
- **User complaint (forum, date not captured):** a background agent could not authenticate to a private GitHub Packages npm registry before install. The search result showed no accepted answer — [Cursor forum](https://forum.cursor.com/t/background-agents-private-npm-dependencies/129792)

**Claude Code cloud sessions (claude.ai/code, `claude --cloud`)**
- Sessions run on Anthropic-managed VMs, or on the organization's "self-hosted environment" when routed there — [Claude Code docs](https://code.claude.com/docs/en/claude-code-on-the-web)
- Network access has four levels: None, Trusted (the default: package registries, GitHub, cloud SDKs), Full, and Custom (a domain allowlist such as `*.internal.example.com`). All outbound traffic from Anthropic-hosted sessions passes through an HTTP/HTTPS security proxy. The docs describe no VPN or Tailscale option. In self-hosted environments, traffic "leaves through your own network boundary". For heavy workloads the docs point to "Remote Control to run Claude Code on your own hardware" — [Claude Code docs: cloud environments](https://code.claude.com/docs/en/cloud-environments)
- If an organization has IP allowlisting enabled, "every Anthropic-hosted cloud session fails with an authentication error" until support grants an exemption. Organizations with zero data retention, the HIPAA configuration or customer-managed encryption keys cannot use cloud sessions — [Claude Code docs](https://code.claude.com/docs/en/claude-code-on-the-web)

**GitHub Copilot cloud (coding) agent**
- Self-hosted runners let you "give Copilot access to internal resources on your network." The built-in firewall "is not compatible with self-hosted runners" and must be disabled. GitHub recommends ARC and "ephemeral, single-use runners". Only Ubuntu x64 and Windows 64-bit runners work. Larger GitHub-hosted runners offer "Azure private networking". Without these, Copilot may be "completely unable to download these dependencies" when they are private — [GitHub docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment)
- **User report (date not captured):** a team ran ARC runners behind a Squid proxy with default-deny iptables. The agent's `fetch()` calls bypassed `HTTPS_PROXY`, and the workaround was allowlisting GitHub's endpoints — [GitHub community discussion #198103](https://github.com/orgs/community/discussions/198103)

**Devin (Cognition)**
- "Devin can connect to a VPN from inside its workspace" to reach internal package registries, databases and Git hosts. Only non-MFA OpenVPN and WireGuard are covered: "Client VPNs that require interactive MFA sign-in are not supported by this setup." Enterprise private networks are referred to the dedicated deployment docs — [Devin docs: VPN](https://docs.devin.ai/onboard-devin/vpn)
- Devin Connect, a gateway deployed inside the customer's network and reached by an outbound-only tunnel or AWS PrivateLink, is in early access. The dedicated deployment connects through PrivateLink or IPSec, and MFA VPNs do not work with Enterprise Cloud. This comes from search summaries of the docs; I did not fetch these pages — [Devin Connect](https://docs.devin.ai/enterprise/deployment/devin-connect); [Devin deployment overview (zh mirror)](https://docs.devin.ai/zh/enterprise/deployment/overview.md)
- The Enterprise plan lists "VPC deployment" — [Devin pricing](https://devin.ai/pricing)

**Google Jules**
- The environment docs describe a "secure, short-lived virtual machine" and say nothing about network access, private networks or VPNs — [Jules docs](https://jules.google/docs/environment/)

**Third-party bridge products (vendor docs, via search)**
- Tembo connects agent sandboxes to corporate VPNs through OpenConnect "so they can reach internal databases and services" — [Tembo docs](https://docs.tembo.io/integrations/openconnect.md)
- Smooth's cloud browser routes traffic "through your machine by default", so localhost URLs work — [Smooth docs](https://docs.smooth.sh/cli/features/localhost)
- Coder's AI Premium tier lists "network-isolated agent workspaces" — [Coder pricing](https://coder.com/pricing)

**Indirect survey signal**
- "Poor integrations with existing systems" blocks 22.6% of non-Temporal respondents and 15.2% of Temporal users (Apr–May 2026, n=554). This is broader than network reach — [Temporal](https://temporal.io/reports/state-of-development-2026)

### Inferences
- **Vendors are building private reach.** OpenAI, Cursor, GitHub and Cognition all shipped or documented private-network paths in 2025–26, and Anthropic sends private access to self-hosted environments. Vendors would not build this without customer pull.
- **The gaps match the sidecar's design.** Today's routes have four problems:
  - They are gated by plan or sales.
  - Most depend on one provider. Tailscale is the only VPN Codex supports and one of two routes in Cursor's docs.
  - They are limited by protocol: HTTP plus CONNECT, with no UDP or inbound connections.
  - None reaches a developer's own machine.

  A userspace subprocess that forwards ports and IPs (features 2–3) and works under any harness targets those four problems directly.
- **The design pattern is already standard.** Cursor's documented pattern, a tunnel client inside the agent that exposes a `localhost` listener and forwards to a private origin, is the same mechanism the sidecar proposes.
- **Tailscale is the incumbent to beat.** It became Codex's VPN without any partnership. Its pricing page also lists "Aperture … Unified AI governance for AI agents and users".
- **Security is a second opening.** Tailscale's own warning that agents "could reach nearly everything" by default, and Cursor's advice against relying on IP allowlists, point to demand for per-agent scoped access and audit trails (features 5–6).
- **Regulated organizations may be underserved.** Claude's Anthropic-hosted sessions shut out zero-data-retention, HIPAA and customer-managed-key organizations, and Devin's VPN setup rules out MFA VPNs. These are signs that regulated or security-heavy organizations lack a sanctioned path.

### Gaps
- No survey quantifies how often cloud agents fail or are rejected because they cannot reach private services. The complaint evidence is a handful of forum and discussion posts. I did not search HN or Reddit systematically.
- Jules's network behavior is undocumented. Copilot's default cloud-sandbox mode, as opposed to Actions runners, is not described in terms of private reach.
- The Devin Connect and dedicated-deployment details rest on search summaries, not fetched pages.
- No vendor documents reaching a developer laptop's localhost from a cloud agent. That is absence of evidence, not proof that no vendor supports it.

## (c) Where are investors funding adjacent agent infrastructure (2025–2026), and what analyst sizing exists?

### Takeaway
The large rounds went to agent compute and sandboxes. Modal raised $355M in May 2026 and $750M in Oct 2026, and Daytona went from a $24M Series A to a $60M Series B at a $1B valuation in 2026. Rounds in categories closer to the sidecar were seed to Series A: memory (Mem0 $24M), email (AgentMail $6M), identity (Keycard $38M), MCP gateways (Runlayer $11M) and agent context/record (Entire's $60M seed). I found no new ngrok round. Gartner's "agent" spending forecasts are broad, inconsistent from one release to the next, and not usable as a market size for agent infrastructure.

### Cited Findings
**Agent memory**
- **Mem0:** $24M announced 28 Oct 2025. This combined a $3.9M seed led by Kindred Ventures and a $20M Series A led by Basis Set Ventures, with Peak XV, GitHub Fund and YC participating. CB Insights dates the Series A to 24 Jul 2025, which conflicts with the announcement date — [Built In SF](https://www.builtinsf.com/articles/mem0-raises-24m-ai-memory-infrastructure-20251103); [Mem0](https://mem0.ai/series-a); [CB Insights](https://www.cbinsights.com/company/mem0/financials)
- **Supermemory:** about $3M, labeled "PRE-SEED $3M" and led by Susa Ventures with Browder Capital and SF1, dated about 1–6 Oct 2025. One aggregator claims about $29M in total funding, which I could not verify — [Supermemory blog](https://supermemory.ai/blog/supermemory-raises-3-million-and-building-the-best-memory-engine-for-llms); [StartupIntros](https://startupintros.com/news/2025-10-06-supermemory-seed); conflicting: [oreateai](https://discover.oreateai.com/discover/supermemory-secures-29-million-to-build-the-persistent-memory-layer-for-ai-agents)
- **Letta:** the only round found is a $10M seed led by Felicis in Sep 2024, outside the 2025–26 window. I found no 2025–26 round — [VCA Online](https://www.vcaonline.com/news/2024092404/berkeley-ai-research-lab-spinout-letta-raises-10m-seed-financing-led-by-felicis-to-build-ai-with-memory/)
- **Zep:** no 2025–26 round found. One aggregator lists only a $500K pre-seed from Mar 2024, which is weak evidence — [vcbacked](https://www.vcbacked.co/company/zep-ai)

**Agent email**
- **AgentMail:** $6M seed on 10 Mar 2026, led by General Catalyst with YC and Phosphor Capital. It launched an API that lets an agent sign itself up and create an inbox — [TechCrunch](https://techcrunch.com/2026/03/10/agentmail-raises-6m-to-build-an-email-service-for-ai-agents/); [AgentMail](https://www.agentmail.to/blog/agentmail-seed-launch)

**Sandboxes and compute**
- **Modal Series C:** $355M on 21 May 2026 at a $4.65B post-money valuation, led by General Catalyst and Redpoint. Modal said it had passed $300M in annualized revenue (vendor claim) — [Dealroom](https://dealroom.co/news/129203-modal-raises-355m-series-c-at-4-65b-valuation/); [Pulse 2.0](https://pulse2.com/modal-labs-355-million-raised-at-4-65-billion-valuation-for-ai-infrastructure-platform/)
- **Modal Series D:** $750M on 14 Oct 2026 at a $15.75B post-money valuation, led by Accel with Kleiner Perkins. Modal reports more than $1B in annualized run rate, about $300M of it from Sandboxes (vendor claims, via secondary coverage). The valuation path was $1.1B (Series B, Sep 2025), then $4.65B, then $15.75B — [RuntimeWire](https://runtimewire.com/article/modal-750m-series-d-1b-run-rate); [AI Weekly](https://aiweekly.co/alerts/modal-closes-750m-series-d-led-by-accel-at-1575b-valuation-crosses-1b-arr)
- **Daytona Series A:** $24M in Feb 2026, led by FirstMark with Pace, Upfront, E2VC and Darkmode — [Polsinelli](https://www.polsinelli.com/news/polsinelli-represents-daytona-24-million-series-a-financing)
- **Daytona Series B:** $60M announced 20 Oct 2026 at a $1B valuation, led by FirstMark Growth. Strategic investors include Okta Ventures, Qualcomm Ventures and Samsung Next, and total funding is $91M. Vendor claims: run-rate up "about 25-fold since January", and it supplies Anthropic, OpenAI, NVIDIA, Cursor and Cognition. CB Insights instead shows a $48.27M raise on 17 Aug 2026 (conflict) — [Tech Funding News](https://techfundingnews.com/daytona-raises-60m-at-1b-valuation-to-build-a-cloud-for-ai-agents/); [CB Insights](https://www.cbinsights.com/compare/daytona-vs-e2b)
- **E2B:** a $21M Series A in Jul 2025 led by Insight Partners, from secondary sources only. I found no 2026 round — [StartupIntros](https://startupintros.com/orgs/e2b); [bex.co](https://bex.co/blog/2026/09/11/ai-sandbox-funding-modal-daytona-e2b)

**Browser infrastructure**
- **Browserbase:** $40M Series B on 17 Jun 2025 at a $300M post-money valuation, led by Notable Capital with CRV and Kleiner Perkins. I found no 2026 round — [SiliconANGLE](https://siliconangle.com/2025/06/17/browserbase-reels-40m-browser-automation-tools/); [VCA Online](https://www.vcaonline.com/news/2025061702/browserbase-launches-director-to-automate-the-web-for-everyone-announces-40m-series-b/)

**Agent identity and MCP gateways**
- **Keycard:** $38M on 21 Oct 2025. An $8M seed was co-led by a16z and Boldstart, and a $30M Series A was led by Acrew. The product issues identity-bound, task-scoped tokens for agents — [SiliconANGLE](https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/); [SecurityWeek](https://www.securityweek.com/keycard-emerges-from-stealth-mode-with-38-million-in-funding/)
- **Runlayer (MCP security gateway):** $11M seed on 17 Nov 2025 from Keith Rabois (Khosla) and Felicis — [TechCrunch](https://techcrunch.com/2025/11/17/mcp-ai-agent-security-startup-runlayer-launches-with-8-unicorns-11m-from-khoslas-keith-rabois-and-felicis)
- **Manufact (formerly mcp-use):** $6.3M seed on 12 Feb 2026, led by Liquid 2 Ventures (aggregator source) — [Seedtable](https://seedtable.com/companies/manufact/funding-rounds/seed-2026-02)

**Agent record and coordination**
- **Entire (Thomas Dohmke):** $60M seed on 10 Feb 2026 at a $300M valuation, led by Felicis with Madrona, M12 and Basis Set. Its first product is "Checkpoints", an open-source CLI that captures AI-agent context and syncs it into git repositories — [Axios](https://www.axios.com/2026/02/10/former-github-ceo-ai-coding-startup); [GeekWire](https://www.geekwire.com/2026/former-github-ceo-launches-new-developer-platform-with-huge-60m-seed-round/)

**Tunnels**
- **ngrok:** the latest confirmed round is still the $50M Series A led by Lightspeed with Coatue (Dec 2022). ngrok's 2025–26 news is product news: its AI Gateway entered early access on 15 Dec 2025, and its dashboard moved to app.ngrok.ai on 1 Jul 2026 — [ngrok press release](https://ngrok.com/press-releases/reverse-proxy-startup-ngrok-raises-50m-in-funding); [ngrok AI Gateway changelog](https://ngrok.com/docs/ai-gateway/changelog.md); [ngrok blog](https://ngrok.com/blog/new-ngrok-ai)

**Analyst sizing (Gartner primary pages returned HTTP 403; figures come from titles and secondary coverage)**
- 15 Jan 2026 release: worldwide AI spending "will total $2.5 trillion in 2026" — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-1-15-gartner-says-worldwide-ai-spending-will-total-2-point-5-trillion-dollars-in-2026)
- 19 May 2026 release ("AI spending to grow 47% in 2026"): secondary coverage reports AI agent software spending of $206.5B in 2026 (from $86.4B in 2025) and $376.3B in 2027. One summary ties these figures to a 5 May release instead, so the attribution is uncertain — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-05-19-gartner-forecasts-worldwide-ai-spending-to-grow-47-percent-in-2026); [dev.to](https://dev.to/docdavkitty/ai-agent-market-spending-2026-the-2065-billion-inflection-point-3ae0); [Enterprise DNA](https://enterprisedna.co/resources/news/gartner-worldwide-ai-spending-2-59-trillion-2026/)
- 16 Sep 2026 release ("grow 49.5% in 2026"): reports a narrower "AI Agents and Assistants" category of about $29.2B in 2026 and $65.5B in 2027, after redefining categories. Per search snippets, this is not comparable with the $206.5B figure — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-09-16-gartner-forecasts-worldwide-ai-spending-to-grow-49-point-5-percent-in-2026)
- Feb 2026 forecast analysis: agentic AI software spending of $985B by 2030, a 62.7% CAGR over 2025–2030 (from a snippet) — [Gartner document](https://www.gartner.com/en/documents/7455226)
- 1 Jul 2026 release title: "$234 billion in enterprise application software spend is at risk from agentic AI" — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-07-01-gartner-says-us-dollars-234-billion-in-enterprise-application-software-spend-is-at-risk-from-agentic-artificial-intelligence)
- Gartner has also predicted that more than 40% of agentic AI projects will be canceled by the end of 2027 (secondary roundup, Feb 2026) — [Software Strategies Blog](https://softwarestrategiesblog.com/2026/02/26/roundup-of-agentic-ai-forecasts-and-market-estimates-2026/)

### Inferences
- **Money follows execution.** Sandboxes and compute (Modal, Daytona) absorbed most 2026 capital and show real revenue claims, such as about $300M run-rate for Modal Sandboxes. The sidecar's adjacent categories (memory, email, identity, context) are still seed or Series A, with no clear leader.
- **Entire validates the sidecar's memory feature.** Entire's $60M seed for capturing agent context into git is the round closest to the sidecar's feature 1 (encrypted storage with a git front end). It is both validation and a direct competitor.
- **Repeat investors in adjacent bets:**
  - Felicis: Letta (2024), Runlayer, Entire
  - Basis Set: Mem0, Entire
  - General Catalyst: AgentMail, Modal
  - FirstMark: Daytona
- **Identity is converging with agent infrastructure.** Okta Ventures invested in Daytona.
- **Gartner's agent numbers are not a market size.** They count agentic features embedded across enterprise software, and Gartner itself redefined the categories between May and September. They should not be presented as the sidecar's addressable market.

### Gaps
- Letta and Zep have no verified 2025–26 rounds. E2B's Series A rests on secondary sources.
- Daytona's Series B conflicts with CB Insights.
- I found no analyst sizing specific to agent infrastructure (sandboxes, memory, identity, tunnels).
- Gartner's primary pages returned 403.
- Tailscale and Cloudflare funding were not researched.
- I did not verify the Runlayer–Rippling lawsuit report ([mezha.net](https://mezha.net/eng/bukvy/ed926ce3_runlayer_and_rippling/)).

## (d) How do adjacent products price: per seat, per agent, or by usage?

### Takeaway
The dominant pattern is a per-human-seat price plus metered usage. Coding harnesses (Copilot, Claude, Devin, Cursor) moved toward token or usage billing in 2026. Memory products bill by usage (requests, credits or episodes). Network and identity products bill per human user, and non-human resources are either included or cheap. Separate per-agent charges are rare: Letta charges $0.10 per active agent per month on its API plan, and Coder caps active agents by tier. Microsoft says outright that "Agents do not require their own licenses."

### Cited Findings
**Tailscale (pricing page, no effective date)**
- Plans: Personal is free (up to 6 users, non-commercial). Standard is $8 per user per month and Premium $18 per user per month. Enterprise is custom.
- User devices are free and unlimited.
- "Tagged resources" (non-human nodes): 50 included, then $1 per month each.
- Ephemeral nodes draw on a pool of 1,000 minutes a month (Standard) or 10,000 (Premium). A node that stays longer than 4 hours counts as a tagged resource.
- Aperture ("Unified AI governance for AI agents and users") is listed with no price.
- Source: [Tailscale pricing](https://tailscale.com/pricing)

**GitHub Copilot**
- Copilot Business costs "$19 USD per granted seat per month" and includes 1,900 GitHub AI Credits per user per month. Enterprise costs "$39 USD per granted seat per month" and includes 3,900 credits. "Copilot access" is $0 for licensed GitHub Enterprise Cloud users, or $10 per user per month standalone, with no included allowance — [GitHub docs](https://docs.github.com/en/copilot/get-started/plans)
- **Billing change:** from 1 Jun 2026 all plans moved from premium requests to token-based AI Credits at published API rates, and credits can be pooled across an organization. Business and Enterprise got promotional credits of $30 and $70 for June–August. The stated rationale: "Agentic usage is becoming the default … the current premium request model is no longer sustainable." The post is dated 27 Apr 2026 although its URL says 05-01 — [GitHub blog](https://github.blog/2026-05-01-github-copilot-is-moving-to-usage-based-billing/)
- Individual plans: Pro $10, Pro+ $39 and Max $100 a month, priced as credit bundles. 1 credit equals $0.01 — [GitHub Copilot plans](https://github.com/features/copilot/plans)
- The cloud agent consumes AI Credits plus Actions minutes when it runs on GitHub-hosted runners. This comes from secondary sources; the official post confirms the double billing only for code review — [SmartScope](https://smartscope.blog/en/generative-ai/github-copilot/github-copilot-ai-credits-usage-billing-2026/)

**Claude (pricing page, no effective date)**
- Team plan (2–150 seats): a Standard seat costs $20 per month billed annually or $25 monthly. A Premium seat costs $100 annually or $125 monthly and includes 5x the usage.
- Enterprise: $20 per seat per month billed annually, with a 20-seat minimum, plus usage billed at API rates.
- Managed Agents are billed at "standard token rates", with no per-agent price listed.
- Source: [Claude pricing](https://claude.com/pricing)

**Cursor (pricing page, no effective date)**
- Individual plans: Free, Plus $8 ("Plus includes Grok models only"), Premium $30, Super $100 and Ultra $200 a month.
- Teams costs "$30+/user/month". Enterprise is custom and includes service accounts and audit logs.
- Cloud agents are included from Premium up and draw from a shared usage pool. Third-party models are billed at API list price. No per-agent fee is listed.
- The page links to x.ai and "SpaceXSI Subscription Terms". I did not research the corporate relationship behind this.
- Source: [Cursor pricing](https://cursor.com/pricing)

**Devin (pricing page, no effective date)**
- Plans: Free, Pro $20 a month, and Max $200 a month.
- Teams costs "$80/month" plus "$40/month per full dev seat", for up to 200 users. Enterprise is custom and includes VPC deployment.
- Usage beyond the quota is billed at API pricing. The page no longer mentions ACUs.
- Source: [Devin pricing](https://devin.ai/pricing)

**Coder (pricing page, no prices published)**
- Community is free with up to 5 active Coder Agents. Premium is billed "annually per user" at an unpublished price. AI Premium is custom-priced with unlimited active Coder Agents and "network-isolated agent workspaces".
- Source: [Coder pricing](https://coder.com/pricing)

**Mem0 (page dated 26 Oct 2026)**
- The free tier includes 10,000 add requests and 1,000 retrieval requests a month for the first 30 days without your own LLM key. With your own key it includes 50,000 and 10,000.
- End users are unlimited. Custom (enterprise) pricing is negotiated, and enterprise features include SSO, audit logs and on-prem deployment.
- There is no per-seat or per-agent pricing.
- Source: [Mem0 pricing](https://mem0.ai/pricing)

**Letta (pricing page, no date)**
- Plans: Free $0 (3 stateful agents) and Pro $20 a month (up to 20 stateful agents).
- The API Plan costs $20 a month plus **$0.10 per active agent per month**, plus $0.00015 per second of tool execution.
- Teams Pro costs $20 per seat per month. Enterprise is custom.
- Source: [Letta pricing](https://docs.letta.com/letta-code/pricing)

**Zep (pricing page, no date)**
- Plans: Free (10,000 credits a month), Flex at $125 a month (50,000 credits; $25 per extra 10,000) and Flex Plus at $375 a month (200,000 credits).
- 1 credit covers one "Episode" of up to 350 bytes. Retrieval, storage and users cost nothing.
- Enterprise is custom and offers bring-your-own-cloud deployment.
- There is no per-seat or per-agent pricing; MCP server seats are a plan quota.
- Source: [Zep pricing](https://www.getzep.com/pricing)

**Microsoft Agent 365 (generally available 1 May 2026)**
- "Agent 365 is licensed per user." "Agents do not require their own licenses." "Blueprints, agents, and agent instances are not licensed separately." "There are no consumption-based costs for Agent 365 yet."
- It costs $15 per user per month standalone, or comes inside Microsoft 365 E7 at $99 per user per month.
- Windows 365 for Agents is billed separately at $0.40 per VM per hour.
- Sources: [Microsoft licensing FAQ](https://www.microsoft.com/licensing/faqs/122); [Microsoft Security blog](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/); [Microsoft 365 blog](https://techcommunity.microsoft.com/blog/microsoft_365blog/microsoft-365-e7-and-agent-365-are-now-generally-available/4516295)

**Okta**
- Okta prices agentic identity as an uplift on per-user pricing "rather than by the number or type of agents, to reduce buying friction" (secondary summary of a Goldman Sachs Communacopia 2026 talk) — [Quartr](https://quartr.com/events/okta-okta-goldman-sachs-communacopia-technology-conference-2026_3eA3BLSd)
- On the Q4 FY2026 earnings call, Okta described two models: a multiplier on a person-based license, or a price based on the number of agent connections to systems — [AOL/Motley Fool transcript](https://www.aol.com/finance/okta-okta-q4-2026-earnings-000230368.html)
- Okta for AI Agents is listed as "Contact for pricing" — [beri.net](https://www.beri.net/tools/okta-for-ai-agents)

**Cost-pressure signal**
- A Gartner release (24 Jun 2026; title only, page returned 403) is headed "AI Coding Costs Will Surpass Average Developer's Salary by 2028 as Token Consumption Surges" — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-06-24-gartner-predicts-ai-coding-costs-will-surpass-average-developer-salary-by-2028-as-token-consumption-surges)

**Prior round**
- The ngrok, AgentMail and Resend price lists were covered earlier and were not re-fetched.

### Inferences
- **Charge per human, meter the rest.** Large vendors that price agent identity (Microsoft, Okta) deliberately avoid per-agent fees. The per-agent prices that do exist are tiny (Letta's $0.10) or work as tier caps (Coder). Tailscale's $1 per month per tagged resource is the closest network-infrastructure analogue to a per-agent node price.
- **Implied sidecar pricing.** The sidecar would fit the market with per-human-seat pricing for team, auth and audit (features 5–6), plus usage pricing for storage, egress and tunnels, inboxes and TLS edge traffic. Generous agent counts per seat would remove any reason to meter agents.
- **Agents push spend into usage billing.** Copilot's move to token billing and Claude Enterprise's "$20 seat + API-rate usage" show agent workloads pushing harness spending toward usage. Buyers already expect agent-related costs to be metered, but Gartner's prediction on AI coding costs suggests cost governance (budgets, caps) will be a buying criterion.

### Gaps
- Keycard and Auth0-for-AI-Agents pricing is not published.
- Cursor's Teams and Enterprise usage terms are not detailed on the page.
- Copilot cloud-agent billing in Actions minutes is confirmed only by secondary sources.
- Coder's Premium price is not published.
- None of the pricing pages state effective dates.

## (e) Which segments adopt agent infrastructure first?

### Takeaway
The earliest and most intense adopters are:
- AI-native startups and AI platform builders. Startups' deployments are more often "true agents", and sandbox vendors name AI labs and coding-agent companies as customers.
- Tech, finance and media industries. Fintech and media/advertising lead daily agent use.
- Individual developers buying bottom-up. Product-led and shadow-AI spending make up 27% to about 40% of AI application spend, and solo "organizations of one" rose to 10% of SO respondents.

Large firms lead in paid AI adoption but trail startups in deploying agents. Regulated sectors such as healthcare and government lag. I found no data on agencies or OSS maintainers specifically.

### Cited Findings
**Menlo Ventures, "2025: The State of Generative AI in the Enterprise" (published 9 Dec 2025; 495 US enterprise AI decision-makers surveyed 7–25 Nov 2025)**
- Startups hold 63% of the AI application market, up from 36%. Incumbents hold 56% of AI infrastructure.
- 76% of AI use cases are bought rather than built, up from 53% in 2024.
- Only 16% of enterprise deployments and 27% of startup deployments qualify as true agents.
- Product-led growth accounts for 27% of AI application spend, against 7% in traditional software. Including shadow AI, it may be "close to 40%".
- Coding reached $4.0B, 55% of departmental AI spend, up from about $550M.
- 47% of AI deals reach production, against 25% for traditional SaaS.
- Source: [Menlo Ventures](https://menlovc.com/perspective/2025-the-state-of-generative-ai-in-the-enterprise/)

**Ramp AI Index (data through Sep 2026; paid AI transactions at more than 85,000 US businesses)**
- 55.9% of businesses pay for AI. By size: large 65.7%, medium 62.5%, small 50.0%.
- By industry: Information 79.9%, Finance & Insurance 73.7%, Manufacturing 60.9%, Retail 49.9%, Construction 43.2%, Healthcare 42.5%, Accommodation & Food 33.0%.
- Vendor adoption: Anthropic 43.8%, OpenAI 40.6%.
- Token-spend share for the week ending 23 Oct 2026: Anthropic 60.5%, OpenAI 35.1%, Cursor 0.1%.
- The index excludes free tools and personal accounts.
- Source: [Ramp AI Index](https://ramp.com/data/ai-index)

**Stack Overflow pulse survey (27 May 2026; about 1,100 respondents)**
- Daily agent use by industry: Fintech 55%, Media & Advertising 50%, Software Development 44%, Transportation/Supply Chain 41%, Manufacturing 38%, Healthcare 36%, Government 35%, Banking/Financial Services 31%, Higher Education 26%, Energy 17%.
- By role: software architects 52%, senior executives 50%, full-stack developers 40%.
- No company-size split is given.
- Source: [Stack Overflow blog](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)

**Stack Overflow 2026 Developer Survey (6 Oct 2026)**
- The share working in an "organization of one" rose from 4% to 10%. Employer size: 17% under 20 employees, 17% at 20–99, and 16% at 100–499. I found no agent-use split by organization size — [SO blog](https://stackoverflow.blog/2026/10/06/the-results-of-the-2026-developer-survey-are-here/)

**GitHub Octoverse 2026 (28 Oct 2026)**
- In administrative and support services, mining, health care and agriculture, fewer than 3% of repositories had agent-opened PRs. Construction was highest at about 9%, with manufacturing next — [GitHub Octoverse](https://github.blog/news-insights/octoverse/octoverse-commits-pushes-reach-new-highs-in-2026-as-developers-build-with-agents/)

**Temporal (25 Aug 2026; n=554 agent users)**
- Respondents' company sizes: 29.2% at 251–1,000 employees, 22.7% at 51–250, and 18.8% at 1,001–5,000.
- In the 5,001+ cohort, about one-fifth say moving from prototype to production takes "months", against 5.5% of everyone else.
- Source: [Temporal](https://temporal.io/reports/state-of-development-2026)

**a16z CIO survey (2025 edition; no 2026 edition found)**
- Innovation budgets fell to 7% of LLM spend.
- 65% of enterprises prefer incumbent solutions when one is available.
- In a follow-up piece, 81% use three or more model families.
- The sample is CIOs at Global 2000-scale companies.
- Sources: [a16z](https://a16z.com/ai-enterprise-2025/); [a16z follow-up](https://a16z.com/leaders-gainers-and-unexpected-winners-in-the-enterprise-ai-arms-race/)

**First buyers of agent infrastructure (vendor claims)**
- Daytona says it supplies Anthropic, OpenAI, NVIDIA, Cursor and Cognition (Oct 2026) — [Tech Funding News](https://techfundingnews.com/daytona-raises-60m-at-1b-valuation-to-build-a-cloud-for-ai-agents/)
- Modal reports about $300M of its run-rate from Sandboxes (Oct 2026) — [RuntimeWire](https://runtimewire.com/article/modal-750m-series-d-1b-run-rate)

**Shadow AI and bring-your-own agents (vendor-sponsored surveys with different denominators; do not combine)**
- PagerDuty and Wakefield (2026; 1,250 office professionals): 66% used an AI tool at work despite believing it was not permitted, and 88% shared work data with a public AI tool — [PagerDuty](https://www.pagerduty.com/newsroom/shadow-ai-workplace-survey-2026)
- Cloud Security Alliance research note (5 Jun 2026; 445 security and IT professionals): 54% of organizations host 1–100 unsanctioned AI agents and 47% host more than 100. The figures sum to 101%, which may be rounding — [CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_Shadow_AI_Agents_Systemic_Risk_20260605-csa-styled.pdf)
- Verizon 2026 DBIR, measured from network traffic: 67% of AI users reach AI through personal, unsanctioned accounts on corporate devices. Okta's "AI Agents at Work 2026" (492 knowledge workers in 7 countries) found 68% used AI agents. Both come via secondary coverage; I did not load the primary reports — [Forkast](https://forkast.news/the-shadow-agent-gap-67-of-workers-use-unapproved-ai-while-enterprises-ship-governance-infrastructure/)
- Menlo (Dec 2025): employees often pay for tools on personal cards. Menlo cites an NBER finding that "roughly 27%" of ChatGPT Plus usage is work-related — [Menlo Ventures](https://menlovc.com/perspective/2025-the-state-of-generative-ai-in-the-enterprise/)

**Enterprise deployment readiness (secondary, unverified)**
- A Gartner 2026 CIO survey reportedly found 17% of organizations have deployed AI agents and 64% plan to — [agentmarketcap.ai](https://agentmarketcap.ai/blog/2026/07/13/gartner-2026-cio-survey-17-deployed-64-percent-forward-plan)
- Mayfield's 2026 CXO research says 91% of enterprises are increasing spend on agents and 56% are shifting budget toward AI-native startups — [Mayfield](https://www.mayfield.com/mayfield-cxo-research-2019-2026/)

### Inferences
- **Two plausible beachheads:**
  1. Small, AI-native teams and solo builders, who adopt bottom-up, use the most agents and switch tools often.
  2. Platforms that build agents for others, which are the buyers already paying sandbox vendors.

  Large enterprises pay for AI more often but deploy "true agents" less and buy through incumbents (a16z 65%), which favors later, sales-led entry.
- **Agencies and fintech.** Fintech (55% daily) and media/advertising (50% daily, the closest proxy for agencies) are the most agent-intensive industries in the SO pulse. Their mix of client confidentiality, shared inboxes and multi-party collaboration matches features 4–6.
- **Regulated SMBs need a sanctioned path.** Healthcare and government lag in daily agent use, healthcare is low in Ramp and Octoverse, and Claude cloud sessions exclude zero-data-retention, HIPAA and customer-managed-key organizations. Regulated buyers lack sanctioned agent infrastructure. That is an opening for a privacy-first, auditable sidecar, though their adoption is slower.
- **Shadow AI is large but hard to size.** The figures range from 66% of office workers to 67% of AI users, with different denominators. Bring-your-own agents imply that a sidecar a developer can start personally, without IT, can grow from the bottom up into team features (auth, audit). That mirrors Menlo's 27%–40% product-led and shadow share of AI application spend.

### Gaps
- I found no a16z 2026 CIO survey, only the 2025 edition and a follow-up piece.
- I found no organization-size split for agent use in SO 2026 (I did not check the raw data). The SO pulse survey has no company-size split.
- I found no data specific to agencies, OSS maintainers or regulated SMBs. The industry figures are only proxies.
- The shadow-AI figures are vendor-sponsored and have incompatible bases. The Verizon and Okta figures were not verified against the primary reports.
- Search summaries mentioned a figure attributed to Gartner (88% of employees with an employer-provided AI tool also use a personal one) that I could not tie to a source I could load, so I excluded it.
