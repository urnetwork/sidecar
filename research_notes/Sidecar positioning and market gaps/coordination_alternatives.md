# Closest competitive alternatives to the URnetwork agent sidecar: agent coordination, agent messaging, and agent-run records (state of the market on 31 Oct 2026)

Reading key: **J1** = real-time encrypted storage with a git front end (shared context, project memory). **J2** = IP/port forwarding for local services. **J3** = public TLS edge. **J4** = email inbox plus group inbox/messaging shared by people and agents. **J5** = easy auth and team management. **J6** = admin audit trail. **J7** = runs in userspace as a subprocess of any harness, driven by a text protocol. "Stars" are GitHub stargazer counts I read from the GitHub REST API on 31 Oct 2026. "npm last-month" is the npm downloads API window 30 Sep to 29 Oct 2026. "PyPI last-month" is pypistats' "recent" endpoint, read on 31 Oct 2026. HN points and comment counts come from the HN Algolia API, read on 31 Oct 2026. Several repos have moved: Beads and Gas Town to `gastownhall/`, Cipher to `campfirein/byterover-cli`, and Crystal is now Nimbalyst.

## 1. What each alternative does, which jobs it covers, and its deployment, encryption, harness reach, pricing, launch, and traction

### Takeaway
No product or project reviewed covers more than about five of the seven jobs, even partially. None ships port forwarding (J2) or a public TLS edge (J3). Agent-to-agent mail with file leases and a git-backed ledger now exists in open source (MCP Agent Mail, Gas Town plus Beads) and inside Claude Code (agent teams, cross-session messaging). Agent-run records exist as git-native session capture (Entire, git-ai, the Agent Trace spec) and as an SQLite audit log (AgentFS). The only end-to-end encryption claim found is Happy's device-to-device transport. The only storage encryption found is MCP Agent Mail's age-encrypted export bundles, which apply to exports, not the live store.

### Cited Findings

#### A. Agent-mail and coordination layers

**MCP Agent Mail (Python original, now deprecated; Rust rewrite maintained)**
- The project describes itself as "A mail-like coordination layer for AI coding agents, exposed as an MCP server with 45 tools and 25 resources, Git-backed archive, SQLite indexing, an interactive 16-screen TUI, a server-rendered web UI, and an agent-first robot CLI." — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- It gives each agent "a persistent identity (e.g., `GreenCastle`), an inbox/outbox, searchable threaded conversations, and advisory file reservations (leases) to signal editing intent." Reservations are "advisory leases, not hard locks", expire automatically, and are "enforce[d]... at commit time" by a pre-commit guard. — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- Storage design: "SQLite for live state, Git for the durable ledger." "Every message, reservation, and agent profile [is] stored as files in per-project Git repos." Vendor claim: it "Provides full audit trails: Every instruction, lease, message, and attachment is in Git for human review." — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- Cross-repo coordination: "Frontend and backend agents in different repos coordinate through the product bus and contact system." Cross-project delivery requires a contact approval ("Check AgentLink Approval → Deliver"). — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust); [Python README](https://github.com/Dicklesworthstone/mcp_agent_mail)
- Human access: a web UI at `/mail/` provides a unified inbox, search, a reservations view, and `/overseer/compose`, a "Human compose form for pushing high-priority instructions to agents". In the Python version, overseer messages carry a "MESSAGE FROM HUMAN OVERSEER" preamble. — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust); [Python README](https://github.com/Dicklesworthstone/mcp_agent_mail)
- Deployment and auth: a local HTTP server on `127.0.0.1:8765` (MCP at `/mcp/`), plus a GHCR Docker image configured with `HTTP_BEARER_TOKEN`. "Bearer/JWT authorization is still checked on every request." The Python version documented JWT+JWKS and RBAC middleware. — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust); [Python README](https://github.com/Dicklesworthstone/mcp_agent_mail)
- Encryption: the Rust README has no encryption mention (keyword search). The Python version could export static archive bundles "optionally encrypt[ed]... with age", and the README includes nginx/Let's Encrypt hosting examples. This applies to exports, not the live mailbox. — [Python README](https://github.com/Dicklesworthstone/mcp_agent_mail)
- Supported harnesses: "Claude Code, Codex CLI, Gemini CLI, Oh My Pi (OMP), GitHub Copilot CLI, and any MCP-compatible client". The installer auto-configures detected agents. — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- License: "MIT License (with OpenAI/Anthropic Rider)". The GitHub API reports NOASSERTION; I did not review the rider text. — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- There is a commercial add-on: "the commercial Companion app's Message Stacks", an iOS app plus host automation to "provision, pair, and steer heterogeneous fleets (Claude Code, Codex, Gemini CLI, Factory Droid, etc.) from your phone". I found no price. — [Python README](https://github.com/Dicklesworthstone/mcp_agent_mail)
- Launch and traction: "Agent Mail has been available since October 2025." The Python repo was created 23 Oct 2025 and had 2,227 stars on 31 Oct 2026; its last release was v0.3.2 (16 Apr 2026), and its description reads "Deprecated: superseded by mcp_agent_mail_rust". The Rust repo was created 5 Feb 2026 and had 225 stars on 31 Oct 2026; its latest release is v0.3.39 (13 Oct 2026). — [Python repo](https://github.com/Dicklesworthstone/mcp_agent_mail); [Rust repo](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- Its Show HN posts drew little attention: 4 points (27 Oct 2025) and 14 points with 2 comments (2 Nov 2025). — [HN 45720416](https://news.ycombinator.com/item?id=45720416); [HN 45793684](https://news.ycombinator.com/item?id=45793684)
- The README publishes stress tests (vendor benchmark), for example a "30-agent message pipeline... 150/150 success, p99=6.8s". It says the Python version had "Git lock file contention... SQLite pool exhaustion... cascading failures". — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)

**Claude Code agent teams (Anthropic)**
- Anthropic's description: "Coordinate multiple Claude Code instances working together as a team, with shared tasks, inter-agent messaging, and centralized management." One session is the lead; teammates "communicate directly with each other", and the user can message any teammate. — [Claude Code docs: agent teams](https://code.claude.com/docs/en/agent-teams)
- Mechanics: "Each agent's mailbox is a JSON file at `~/.claude/teams/{team-name}/inboxes/{agent-name}.json`." The task list lives at `~/.claude/tasks/{team-name}/`. "Task claiming uses file locking to prevent race conditions." Tasks support dependencies and are pending, in progress, or completed. Hooks: `TeammateIdle`, `TaskCreated`, `TaskCompleted`. — [agent teams docs](https://code.claude.com/docs/en/agent-teams)
- Status as of 31 Oct 2026: "Agent teams are experimental and disabled by default" and require `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`. They also need an interactive session; `-p` and Agent SDK sessions do not spawn teammates. — [agent teams docs](https://code.claude.com/docs/en/agent-teams)
- Launch: v2.1.32 added a "research preview agent teams feature for multi-agent collaboration (token-intensive...)" alongside "Claude now automatically records and recalls memories as it works". npm published 2.1.32 on 5 Feb 2026, the day Opus 4.6 launched; that HN thread drew 2,346 points and 1,031 comments. — [Claude Code CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md); [npm registry time field](https://registry.npmjs.org/@anthropic-ai/claude-code); [HN 46902223](https://news.ycombinator.com/item?id=46902223)
- Documented limitations, verbatim: "One team per session... You can't create additional named teams or share a team across sessions"; "No nested teams"; "Lead is fixed"; "No session resumption with in-process teammates"; "Task status can lag"; "Split panes require tmux or iTerm2". Also: "Two teammates editing the same file leads to overwrites." — [agent teams docs](https://code.claude.com/docs/en/agent-teams)
- Scope: Claude Code only, on one machine, with storage under `~/.claude`. The page does not mention encryption. Teams are part of Claude plans and use "significantly more tokens than a single session". — [agent teams docs](https://code.claude.com/docs/en/agent-teams)

**Beads (Steve Yegge; repo now `gastownhall/beads`)**
- Beads is a "Distributed graph issue tracker for AI agents, powered by Dolt". It "provides a persistent, structured memory for coding agents... a dependency-aware graph". `bd remember "insight"` stores "durable project facts". — [Beads README](https://github.com/gastownhall/beads)
- Storage: Dolt, a "Version-controlled SQL database with cell-level merge, native branching, and built-in sync". It runs embedded by default (single writer) or as a server for concurrent writers. "Cross-machine sync uses `bd dolt push` / `bd dolt pull` against `refs/dolt/data` on your git remote." Hash-based IDs "prevent merge collisions in multi-agent/multi-branch workflows." — [Beads README](https://github.com/gastownhall/beads)
- Remote mode: a workspace "can also talk to a remote `bd serve` over HTTP" with bearer credentials. Plain `http://` to a non-loopback server "is refused by default (a bearer credential would cross the network unencrypted)". The README says nothing about at-rest encryption. — [Beads README](https://github.com/gastownhall/beads)
- Harnesses: `bd init` "installs the project Claude Code, Codex, and Cursor integrations" and writes AGENTS.md. `bd setup codex` and `bd setup claude` are also available. Distributed via brew, npm, and PyPI (`beads-mcp`). — [Beads README](https://github.com/gastownhall/beads)
- Launch and traction: repo created 12 Oct 2025; 28,326 stars and 1,911 forks on 31 Oct 2026; v1.3.2 released 24 Oct 2026; MIT. npm `@beads/bd` had 34,611 downloads last month and PyPI `beads-mcp` had 5,690. — [repo](https://github.com/gastownhall/beads); [npm API](https://api.npmjs.org/downloads/point/last-month/@beads/bd); [pypistats](https://pypistats.org/packages/beads-mcp)
- Direction: the issue "Proposal: Memory Beads" (opened 20 Aug 2026) has 131 comments, and "[Memory] Implementation Status" was opened 17 Oct 2026. — [issue #5877](https://github.com/gastownhall/beads/issues/5877); [issue #7656](https://github.com/gastownhall/beads/issues/7656)

**Gas Town (Steve Yegge's multi-agent orchestrator; repo now `gastownhall/gastown`)**
- Gas Town is "a workspace manager that lets you coordinate multiple AI coding agents (Claude Code, GitHub Copilot, Codex, Gemini, and others)". It advertises "Built-in mailboxes, identities, and handoffs". The "Mayor" is "a Claude Code instance with full context about your workspace"; "Hooks" are "Git worktree-based persistent storage for agent work". — [Gas Town README](https://github.com/gastownhall/gastown)
- Built-in runtime presets: `claude`, `gemini`, `codex`, `kiro`, `cursor`, `auggie`, `amp`, `opencode`, `copilot`, `pi`, `omp`. tmux 3.0+ is "Required for `gt up` and the tmux-backed roles", and Windows needs WSL. — [Gas Town README](https://github.com/gastownhall/gastown)
- Mail: "Gas Town agents coordinate via mail messages routed through the beads system. Mail uses `type=message` beads with routing handled by `gt mail`." Typed messages include POLECAT_DONE, MERGE_READY, MERGED, MERGE_FAILED, REWORK_REQUEST, HELP, and HANDOFF. "Every `gt mail send` creates a wisp bead in Dolt -- a permanent record with its own commit." `gt nudge` is ephemeral, and "if the target session is dead, the nudge is lost". — [mail-protocol.md](https://github.com/gastownhall/gastown/blob/main/docs/design/mail-protocol.md)
- Federation: "Wasteland" is a "Federated work coordination network linking Gas Towns through DoltHub". Separately, Gas City is an "Orchestration-builder SDK for multi-agent coding workflows" (repo created 22 Feb 2026, 1,470 stars on 31 Oct 2026). — [Gas Town README](https://github.com/gastownhall/gastown); [gascity repo](https://github.com/gastownhall/gascity)
- Launch and traction: Yegge launched it on 1 Jan 2026 with "Welcome to Gas Town"; the HN thread drew 354 points and 224 comments. A follow-up analysis by Maggie Appleton (23 Jan 2026) drew 403 points and 433 comments. The repo was created 16 Dec 2025 and had 18,641 stars on 31 Oct 2026; v1.2.1 was released 6 Jun 2026; MIT. — [Medium post](https://steve-yegge.medium.com/welcome-to-gas-town-4f25ee16dd04); [HN 46458936](https://news.ycombinator.com/item?id=46458936); [HN 46734302](https://news.ycombinator.com/item?id=46734302); [repo](https://github.com/gastownhall/gastown)
- Hosted variant: SD Times reports "Gas Town by Kilo", a cloud-hosted version. I did not verify the date. — [SD Times](https://sdtimes.com/softwaredev/gas-town-by-kilo-multi-agent-orchestrator-now-available/)
- gastown.dev failed DNS resolution (ENOTFOUND) when I fetched it on 31 Oct 2026, so I read the mail protocol from the repo copy instead.

#### B. Agent-run records

**Entire (Thomas Dohmke): Checkpoints, now part of an "agent–human" Git forge**
- Funding: a $60M seed at a $300M valuation, announced 10 Feb 2026 and led by Felicis. Other investors include Madrona, M12, Basis Set, 20VC, Cherry Ventures, Picus Capital, and Global Founders Capital. The first product was the open-source Checkpoints CLI, which pairs each agent-generated commit with "the full session, including transcripts and prompts" stored in Git. It launched with support for Claude Code and Gemini CLI. The stated vision is "a git-compatible database, a semantic reasoning layer for multi-agent coordination, and an AI-native user interface." — [Entire news](https://entire.com/news/former-github-ceo-thomas-dohmke-raises-60-million-seed-round); [TechCrunch, 10 Feb 2026](https://techcrunch.com/2026/02/10/former-github-ceo-raises-record-60m-dev-tool-seed-round-at-300m-valuation/)
- Current scope per the README (31 Oct 2026): "Entire is a Git forge built for agent–human collaboration." It offers "Distributed Git hosting" with regional replicas and GitHub mirrors, "Trails" (review with eval "project agents"), and "Continuous memory" (checkpoints plus `entire-brain` and `entire-graph`). It works with "Claude Code, Codex, Cursor, Copilot CLI, OpenCode, Antigravity, Factory AI Droid, Pi". — [entireio/cli README](https://github.com/entireio/cli)
- Privacy: "Session transcripts are pushed to your Git remote — as checkpoint refs, not commits on your branch. If that repository is public, anyone can read them. Entire redacts detected secrets... but redaction is best effort." Users can redirect checkpoints to a separate private repo. The README does not mention encryption. — [entireio/cli README](https://github.com/entireio/cli)
- Traction: `entireio/cli` was created 2 Jan 2026 and had 5,282 stars on 31 Oct 2026; v0.12.2 was released 26 Oct 2026; MIT. Related repos on 31 Oct 2026: `entireio/git-sync` (517 stars), `entireio/skills` (236), `entireio/entire-brain` (86, created 25 May 2026). The HN submissions of the funding news drew 3 points each, so I found no substantive HN discussion. — [entireio org](https://github.com/entireio); [HN 46961115](https://news.ycombinator.com/item?id=46961115)
- Pricing: the CLI is open source. I did not find hosted forge pricing.

**Agent Trace (open spec for AI attribution in version control)**
- It is an "open specification for tracking AI-generated code", v0.1.0, RFC status, dated January 2026, with Cursor branding. A trace record maps files and line ranges to conversations, with contributor type `human`, `ai`, `mixed`, or `unknown` and an optional model ID. It covers git, jj, hg, and svn, and "intentionally does not define how traces are stored". Listed partners: Amp, Amplitude, Cline, Cloudflare, Cognition, git-ai, Jules, OpenCode, Tapes, Vercel. — [agent-trace.dev](https://agent-trace.dev)
- Thoughtworks Technology Radar placed it in "Assess" (April 2026). — [Thoughtworks Radar](https://www.thoughtworks.com/radar/platforms/agent-trace)
- The canonical repo listed by agent-trace.dev, `github.com/cursor/agent-trace`, returned HTTP 404 on 31 Oct 2026, both on the web and through the API. I could not determine why. — [github.com/cursor/agent-trace](https://github.com/cursor/agent-trace)

**git-ai**
- git-ai is an "open source git extension that tracks the AI-generated code in your repositories... every line of AI code is linked to the agent, model, and prompts". It stores line-level attribution in Git Notes and syncs it on push/fetch. Prompts are "scanned and redacted, and saved outside of Git". — [git-ai README](https://github.com/git-ai-project/git-ai)
- Supported agents: Claude Code, Codex, Cursor, GitHub Copilot, OpenCode, Windsurf, Amp, and Gemini, plus background agents (Claude Web, Codex Cloud, Cursor Agent, Devin). The CLI is free, works locally, and needs no login. "Git AI for Teams" adds a prompt store and "% AI and token cost by Pull Request, Repo, Team, and Contributor"; access is by booked meeting, with no public price found. Vendor claim: "Hundreds of engineering teams (including many in the Fortune 100)". — [git-ai README](https://github.com/git-ai-project/git-ai)
- Traction: created 2 Jul 2025; 2,917 stars on 31 Oct 2026; v1.7.5 released 9 Sep 2026; Apache-2.0. — [repo](https://github.com/git-ai-project/git-ai)

**Turso AgentFS**
- Launched 13 Nov 2025 (Pekka Enberg and Glauber Costa). It is an SQLite/Turso-based agent filesystem with "a POSIX-like filesystem, a key-value store, and a toolcall audit trail". The post claims "Every file operation, tool call, and state change is recorded in SQLite", and the toolcall log is append-only. The post does not mention encryption or sync. — [Turso blog](https://turso.tech/blog/agentfs)
- The README says "This software is in BETA". It supports FUSE (Linux) and NFS (macOS) mounts and `agentfs run <program>` in an "experimental sandbox", which can wrap any program. Examples include the Claude Agent SDK, Firecracker, and Cloudflare Workers. It is "a single SQLite file" that you can "check into version control", but it is not git-backed. — [AgentFS README](https://github.com/tursodatabase/agentfs)
- Traction: repo created 24 Oct 2025; 3,500 stars on 31 Oct 2026; latest release v0.6.4 (25 Mar 2026). npm `agentfs-sdk` had 100,178 downloads last month. — [repo](https://github.com/tursodatabase/agentfs); [npm API](https://api.npmjs.org/downloads/point/last-month/agentfs-sdk)

#### C. Remote and direct-to-agent clients

**Happy (happy.engineering, `slopus/happy`)**
- The current README pitch is "Orchestrate Claude, Codex and Grok in one app". Claims: "OpenCode or any Agent Client Protocol agent plugs in as a harness"; "Reuse your subscriptions"; "End-to-end encrypted mobile app... what moves between your devices is encrypted"; "Natively multiplayer. Invite a colleague... either of you can steer it." The repo contains the mobile/web app, the original CLI (`happy claude`, `happy codex`), and "the relay server for encrypted sync". — [Happy README](https://github.com/slopus/happy)
- The site says it is "Free and open source" (MIT). For teams: "Deploy a team server... Everyone signs in as themselves and shares the same projects and sessions." It does not say where keys live. Store ratings shown on the site (vendor claim): Mac App Store 4.9 from "1,000+ ratings" and Google Play 5.0 from "3.1k+ reviews". — [happy.engineering](https://happy.engineering/)
- Traction: repo created 18 Jul 2025; 24,436 stars on 31 Oct 2026. The Show HN on 14 Aug 2025 drew 30 points. npm `happy` had 22,237 downloads last month and `happy-coder` 2,066. — [repo](https://github.com/slopus/happy); [HN 44904039](https://news.ycombinator.com/item?id=44904039); [npm API](https://api.npmjs.org/downloads/point/last-month/happy)

**Omnara (YC S25)**
- History: the Show HN "Omnara – Run Claude Code from anywhere" (12 Aug 2025) drew 310 points and 168 comments. The Launch HN "Run Claude Code and Codex from anywhere" (12 Feb 2026) drew 147 points and 161 comments. There the founder said the "Free tier gives you 10 sessions/month". — [HN 44878650](https://news.ycombinator.com/item?id=44878650); [HN 46991591](https://news.ycombinator.com/item?id=46991591)
- Pivot: on 21 Oct 2026 it relaunched as "The open-source managed agent platform. A self-hostable alternative to Claude Managed Agents and OpenAI's Agents API" (Show HN: 114 points, 35 comments). — [README](https://github.com/omnara-ai/omnara); [HN 50183892](https://news.ycombinator.com/item?id=50183892)
- Current features per the README (vendor claims):
  - Memory stores "shared with other agents, with read or read-write access per agent".
  - An `omnarad` daemon "connects out to Omnara, so agents can run commands there without any inbound ports".
  - Slack, Discord, and GitHub triggers; streaming and webhooks.
  - "Role-based access control" with org and project roles and a secrets store; multi-tenant.
  - Self-hosted history kept "in your own Postgres".
  - Pricing: "Free to self-host. On Omnara Cloud, free with your own keys and machines, or pay as you go."
  - It runs its own agent loop rather than wrapping Claude Code or Codex.
  — [Omnara README](https://github.com/omnara-ai/omnara)
- Traction: 3,331 stars on 31 Oct 2026 (repo created 9 Jul 2025); Apache-2.0. npm `omnara` had 3,185 downloads last month. — [repo](https://github.com/omnara-ai/omnara)

**Claude Code Remote Control (Anthropic)**
- Remote Control "connects claude.ai/code or the Claude app for iOS and Android to a Claude Code session running on your machine". It is "available on Pro, Max, Ultra, Team, and Enterprise plans. API keys are not supported." — [Remote Control docs](https://code.claude.com/docs/en/remote-control)
- Transport: the local process "makes outbound HTTPS requests only and never opens inbound ports"; "All traffic travels through the Anthropic API over TLS"; "the session transcript... is stored on Anthropic servers." Server mode runs up to 32 concurrent sessions by default (`--capacity`), with an optional worktree per session. — [Remote Control docs](https://code.claude.com/docs/en/remote-control)
- Limits (verbatim): "One remote session per interactive process" outside server mode, and "Local process must keep running". — [Remote Control docs](https://code.claude.com/docs/en/remote-control)
- Launch: the `claude remote-control` subcommand arrived in v2.1.51 (npm, 23 Feb 2026), and v2.1.58 (25 Feb 2026) expanded it to more users. The HN thread on 25 Feb 2026 drew 544 points and 313 comments. — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md); [HN 47148454](https://news.ycombinator.com/item?id=47148454)

#### D. Parallel-agent managers (none documents inter-agent messaging, shared memory, or network reach to local services)

**Conductor (Melty Labs)**
- The docs say "Conductor lets you run Claude Code, Codex, Cursor, and OpenCode in parallel", on a Mac. Each task gets an isolated workspace with its own branch, terminal, and diff, followed by review, PR, and merge. The intro page does not mention messaging, shared memory, or port handling. — [Conductor docs](https://www.conductor.build/docs/); [conductor.build](https://www.conductor.build)
- Funding: a $22M Series A from Spark and Matrix, announced 30 Mar 2026. Vendor claims: "10x [user growth] since January" and use by engineers at "Google, Meta, Hubspot, Chime, Intercom, Ramp, Datadog, Block, Flexport, Rippling, Amazon, and Spotify". It aims to be "available everywhere from your phone to your VPC". — [Conductor blog](https://www.conductor.build/blog/series-a)
- Conductor Cloud launched 30 Jul 2026, per a report based on Conductor's X post and changelog (vendor-sourced). It added shared cloud workspaces that keep running after the laptop closes, microVM sandboxes, an API, and an iPhone beta. — [Runtimewire](https://runtimewire.com/article/conductor-launches-multiplayer-cloud-workspaces-coding-agents)
- Pricing is unverified from primary pages. Secondary directories say the Mac app is free and disagree about paid tiers. — [codepick.dev](https://codepick.dev/en/tool/conductor/)
- The YC company page returned only a title when fetched.

**Vibe Kanban (bloop)**
- It is a kanban board plus agent workspaces for "10+ coding agents — Claude Code, Codex, Gemini CLI, GitHub Copilot, Amp, Cursor, OpenCode, Droid, CCR, and Qwen Code". It had a self-hostable cloud and a relay/tunnel mode. Its remote-deployment docs tell users to "Use Cloudflare Tunnel, ngrok, or similar to expose the web UI". — [README](https://github.com/BloopAI/vibe-kanban)
- Shutdown announced 10 Apr 2026: bloop "couldn't find a business model that we could get excited about", and "the vast majority are free users". Remote services ended after 30 days; kanban issues, comments, projects, and organisations were removed, and the product moved to "a fully local architecture" under community maintenance. Vendor claim: "Thousands of software engineers use Vibe Kanban every day." — [Vibe Kanban blog](https://www.vibekanban.com/blog/shutdown)
- Traction: the Show HN on 11 Jul 2025 drew 195 points and 132 comments. The repo had 28,536 stars on 31 Oct 2026, and npm `vibe-kanban` had 11,133 downloads last month. — [HN 44533004](https://news.ycombinator.com/item?id=44533004); [repo](https://github.com/BloopAI/vibe-kanban); [npm API](https://api.npmjs.org/downloads/point/last-month/vibe-kanban)

**Claude Squad**
- A terminal app to "Manage multiple AI terminal agents like Claude Code, Codex, OpenCode, and Amp", using tmux and git worktrees, with an experimental auto-accept mode. A README keyword search found no messaging, memory, or network features. AGPL-3.0. Repo created 9 Mar 2025; 8,711 stars on 31 Oct 2026; v1.0.20 released 20 Aug 2026. — [repo](https://github.com/smtg-ai/claude-squad)

**Imbue Sculptor**
- A "desktop app for running coding agents in parallel" in isolated workspaces. It has "integrated support for the Pi agentic harness in addition to Claude Code" and can "run and manage _any_ terminal-based agents". An experimental container backend can run "in Docker or on a remote". — [README](https://github.com/imbue-ai/sculptor)
- The Show HN "Sculptor – A UI for Claude Code" (30 Sep 2025) drew 176 points and 85 comments. MIT; 242 stars on 31 Oct 2026; v0.49.0 released 21 Oct 2026. — [HN 45427697](https://news.ycombinator.com/item?id=45427697); [repo](https://github.com/imbue-ai/sculptor)

**Crystal, now Nimbalyst**
- Crystal's repo description reads "(Crystal is now Nimbalyst) Run multiple Codex and Claude Code AI sessions in parallel git worktrees". Its last release was v0.3.5 (26 Feb 2026), with 3,131 stars on 31 Oct 2026. — [stravu/crystal](https://github.com/stravu/crystal)
- Nimbalyst describes itself as an "open-source visual workspace for Claude Code, Codex, and OpenCode... track tasks... mobile companion for iOS and Android". MIT; created 30 Oct 2025; 2,008 stars on 31 Oct 2026; Show HN on 30 Apr 2026 drew 8 points. A `nimbalyst-wiki` plugin ("A local wiki your agents write for you") was created 13 Oct 2026. — [nimbalyst repo](https://github.com/nimbalyst/nimbalyst); [HN 47962230](https://news.ycombinator.com/item?id=47962230)

#### E. Cross-harness memory servers (cross-harness use and team sharing)

**Basic Memory (Basic Machines)**
- Local-first Markdown memory over MCP: "Pick up right where you left off — in Claude, Codex, Cursor, ChatGPT". The cloud version connects Claude Desktop, Claude Code, Codex, Cursor, ChatGPT (Custom GPTs), and VS Code. Local cross-device sync is "Manual (Git, Syncthing, etc.)". The README does not mention encryption. — [README](https://github.com/basicmachines-co/basic-memory)
- Teams: "Basic Memory Teams is now available! Give your team a single, shared cloud workspace... Edit a note together in real time, hand work off between humans and agents." Pricing: cloud is "$15.00/mo locked in for life" during beta (regular $19), with a 7-day trial; Teams has the "Same pricing - start with one user and add more". — [README](https://github.com/basicmachines-co/basic-memory)
- Traction: repo created 2 Dec 2024; 4,427 stars on 31 Oct 2026; v1.0.0 released 29 Oct 2026; AGPL-3.0. PyPI had 27,770 downloads last month. — [repo](https://github.com/basicmachines-co/basic-memory); [pypistats](https://pypistats.org/packages/basic-memory)

**Supermemory**
- A "Memory and context engine + app... can be run fully locally". It has a hosted MCP endpoint (`https://mcp.supermemory.ai/mcp`) and plugins "for Claude Code, Muse Code, Cursor, Codex, OpenCode, OpenClaw, and Hermes". Memory is "scoped with projects (container tags)", and self-hosting is documented. The README does not mention team sharing or encryption. — [README](https://github.com/supermemoryai/supermemory)
- Traction: MIT; 31,482 stars on 31 Oct 2026. npm `supermemory` (the SDK, not only the MCP) had 497,320 downloads last month. — [repo](https://github.com/supermemoryai/supermemory); [npm API](https://api.npmjs.org/downloads/point/last-month/supermemory)
- Funding reports conflict. TechCrunch (6 Oct 2025) reported a seed of $2.6M; several later outlets report $3M. — [TechCrunch](https://techcrunch.com/2025/10/06/a-19-year-old-nabs-backing-from-google-execs-for-his-ai-memory-startup-supermemory/); [Let's Data Science ($3M)](https://letsdatascience.com/news/dhravya-shah-raises-3m-for-supermemory-9b29cd09)

**OpenMemory (Mem0)**
- The current `mem0ai/openmemory` repo (created 6 Jul 2026, 100 stars on 31 Oct 2026) is an "Open-source CLI & TUI to port AI coding sessions across Claude Code, Codex, and OpenCode". "Autosync keeps them all in sync, all the time (coming soon)". It criticizes "Codex's 'Import from Claude Code'" as "uni-directional". — [mem0ai/openmemory](https://github.com/mem0ai/openmemory)
- The Mem0 docs page at `/openmemory/overview` did not mention OpenMemory when fetched on 31 Oct 2026. Mem0 lists coding-agent guides for Claude Code, Cursor, Codex, Kimi Code, OpenCode, OpenClaw, Pi Agent, DeepSeek Harness, and Antigravity. — [Mem0 docs](https://docs.mem0.ai/openmemory/overview)
- Mem0 traction: 68,163 stars on 31 Oct 2026; PyPI `mem0ai` had 2,020,516 downloads last month. — [mem0 repo](https://github.com/mem0ai/mem0); [pypistats](https://pypistats.org/packages/mem0ai)

**ByteRover (formerly Cipher)**
- "ByteRover CLI (`brv`) gives AI coding agents persistent, structured memory... sync it to the cloud, and share it across tools and teammates." It offers "Git-like version control for the context tree (branch, commit, merge, push/pull)" and "Works with 22+ AI coding agents". ByteRover Cloud adds "Team context sync", "Shared spaces", and "Team management — manage members, spaces, and permissions"; the cloud is labeled "Free" with limited hosted-LLM usage. — [README](https://github.com/campfirein/byterover-cli)
- Status: `campfirein/cipher` redirects to `campfirein/byterover-cli`, which the GitHub API reported as archived on 31 Oct 2026. It had 4,948 stars; last push 25 Jun 2026; last release v3.16.1 (27 May 2026). npm `byterover-cli` had 4,828 downloads last month. — [repo](https://github.com/campfirein/byterover-cli); [npm API](https://api.npmjs.org/downloads/point/last-month/byterover-cli)

**claude-mem**
- Description: "Persistent Context Across Sessions for Every Agent – Captures everything your agent does during sessions, compresses it with AI, and injects relevant context back into future sessions. Works with Claude Code, OpenClaw, Codex, Gemini, Hermes, Copilot, OpenCode + More." Storage is SQLite (FTS5) plus a Chroma vector database. — [README](https://github.com/thedotmack/claude-mem)
- Team and cloud: "CMEM Pro, the hosted memory"; "Cloud Sync" to cmem.ai; and "TeamBrain - An optional shared workspace... with real team work lists, member attribution and linked findings. Each person chooses what to share". `<private>` tags exclude content. I found no CMEM Pro price. — [README](https://github.com/thedotmack/claude-mem)
- Traction: repo created 31 Aug 2025; 107,507 stars on 31 Oct 2026, the most of any item here; v15.7.0 released 30 Oct 2026; Apache-2.0. npm `claude-mem` had 78,676 downloads last month, though the README says npm installs only the SDK. — [repo](https://github.com/thedotmack/claude-mem); [npm API](https://api.npmjs.org/downloads/point/last-month/claude-mem)

### Inferences
- On stars (31 Oct 2026), the "memory" and "orchestration" categories dwarf "agent mail": claude-mem (107.5k), Supermemory (31.5k), Vibe Kanban (28.5k), Beads (28.3k), Happy (24.4k), and Gas Town (18.6k) far exceed MCP Agent Mail (2.2k Python plus 0.2k Rust). Stand-alone coordination servers have not won mindshare by themselves. They spread when bundled into an orchestrator (Gas Town) or into the harness (Claude Code agent teams).
- Every item that covers J4 does so agent-to-agent inside one project or town, with humans as "overseers" through a web UI or phone. None uses standard email addresses or groups shared by people and agents. The `name@you.ur.network` design has no direct equivalent in this set; AgentMail and Resend were covered in an earlier round.
- Git-native records are converging. Entire uses checkpoint refs, git-ai uses Git Notes, Agent Trace is a storage-agnostic spec, and MCP Agent Mail and Beads keep git or Dolt ledgers. None of them encrypts the record, and Entire explicitly warns that transcripts in a public repo are readable. Privacy of the record is therefore an open gap.
- The parallel-agent manager category is consolidating or retreating. Vibe Kanban shut down, Crystal was renamed, and Conductor moved to cloud and mobile. These managers sit above the harness: they launch it. The URnetwork sidecar is designed to sit below or alongside it, as the harness's subprocess.

### Gaps
- I found no HN or GitHub discussion of Happy's key management. Its homepage does not say whether the relay sees only ciphertext.
- Still unverified: Conductor pricing from a primary page, Omnara's funding amount, CMEM Pro pricing, Entire hosted pricing, and the MCP Agent Mail Companion price.
- I could not determine why `campfirein/byterover-cli` is archived or why `cursor/agent-trace` returns 404.
- The status of Mem0's original OpenMemory MCP server, the local one with a dashboard, could not be confirmed. The docs URL no longer describes it.
- Gas Town's "Kilo" hosted version: date and details unverified.
- Download counts cover npm and PyPI only. Homebrew counts and app-store install counts were not available.

## 2. Which alternatives combine two or more jobs, and which is closest to the full bundle (store + inbox + reach + auth + audit + harness-neutral protocol)?

### Takeaway
Several products combine three to five jobs, but none comes close to all seven. On the coordination, record, and harness-neutral core, the closest is MCP Agent Mail (Rust): identities and inboxes, threads, file leases, a git ledger, bearer/JWT auth, and MCP access for five named harnesses. Gas Town plus Beads is the closest integrated stack. Omnara's October 2026 relaunch is the closest on auth, team, and memory, but it replaces the harness instead of riding alongside it. Claude Code's built-ins are the closest on reach and messaging, but only for Claude. All of them lack J2 and J3, and none offers an encrypted, git-fronted shared store.

### Cited Findings
- MCP Agent Mail combines identities, inboxes, threads, contacts, advisory leases, a git plus SQLite archive ("full audit trails"), a human overseer web UI, bearer/JWT auth, and MCP access from Claude Code, Codex CLI, Gemini CLI, OMP, and Copilot CLI. It runs as a local HTTP server or a Docker container. — [Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)
- Gas Town combines "Built-in mailboxes, identities, and handoffs" with Dolt-backed mail ("permanent record with its own commit"), Beads task memory, and 11 runtime presets. It needs tmux. — [Gas Town README](https://github.com/gastownhall/gastown); [mail-protocol.md](https://github.com/gastownhall/gastown/blob/main/docs/design/mail-protocol.md)
- Omnara (21 Oct 2026) combines shared memory stores, RBAC, orgs, and secrets, outbound-only machine connectivity, Slack, Discord, and GitHub channels, durable step history in Postgres, and webhooks. It brings its own agent loop. — [Omnara README](https://github.com/omnara-ai/omnara)
- Claude Code combines agent-team mailboxes and a locked task list (Feb 2026), Remote Control over outbound HTTPS through Anthropic (Feb 2026), and cross-session messaging "on any of your machines" (Aug 2026). All of it is Claude-only, and cross-machine traffic passes "Through Anthropic servers". — [agent teams docs](https://code.claude.com/docs/en/agent-teams); [Remote Control docs](https://code.claude.com/docs/en/remote-control); [cross-session messaging docs](https://code.claude.com/docs/en/cross-session-messaging)
- Entire combines git-stored session checkpoints, hosted Git with regional replicas, login and projects, search, and hooks for eight harnesses. — [entireio/cli README](https://github.com/entireio/cli)
- Happy combines multi-harness wrapping (Claude Code, Codex, ACP agents), an end-to-end encrypted relay (vendor claim), multiplayer sessions, and a team server. — [Happy README](https://github.com/slopus/happy); [happy.engineering](https://happy.engineering/)
- claude-mem, ByteRover, and Basic Memory each combine cross-harness memory with some team sharing: TeamBrain, ByteRover's "members, spaces, and permissions", and Basic Memory Teams. — [claude-mem README](https://github.com/thedotmack/claude-mem); [ByteRover README](https://github.com/campfirein/byterover-cli); [Basic Memory README](https://github.com/basicmachines-co/basic-memory)
- AgentFS combines a single-file store (filesystem plus KV) with an append-only toolcall audit trail. — [Turso blog](https://turso.tech/blog/agentfs)
- The only network-exposure guidance found was external. Vibe Kanban's docs say "Use Cloudflare Tunnel, ngrok, or similar". An Omnara founder said running `opencode serve` means you must "expose it via tailscale or something like that" (HN, 12 Feb 2026). — [Vibe Kanban README](https://github.com/BloopAI/vibe-kanban); [HN 46991591](https://news.ycombinator.com/item?id=46991591)

### Inferences
Coverage matrix. This is my mapping from the cited docs. Y = covered per docs; P = partial; - = not found in docs; Inv. = the product launches harnesses (it is above the harness, not a subprocess of it).

| Alternative | J1 store | J2 forward | J3 TLS edge | J4 inbox | J5 auth/team | J6 audit | J7 sidecar for any harness | Jobs touched |
|---|---|---|---|---|---|---|---|---|
| MCP Agent Mail (Rust) | P: git+SQLite message ledger, no at-rest encryption found | - | - (DIY nginx examples in Python docs) | Y for agents, P for humans (web overseer) | P: bearer/JWT | P: git ledger | P: MCP over HTTP, 5 named harnesses, robot CLI; a server, not a subprocess | 5 |
| Gas Town + Beads | P: Dolt, git-remote sync | - | - | Y for agents (Dolt mail) | P: `bd serve` bearer | P: Dolt commits, event stream | Inv. for Gas Town; Y for the Beads CLI | 4-5 |
| Omnara (Oct 2026) | P: shared memory stores, Postgres | - (outbound daemon reaches machines; no service exposure documented) | - | P: Slack/Discord/GitHub threads | Y: RBAC, orgs, secrets | P: durable steps, events | - (own agent loop) | 4 |
| Entire | P: checkpoints in git refs, hosted forge | - | - | - | P: login, projects | Y/P: per-commit session record | P: hooks for 8 agents | 4 |
| claude-mem | P: SQLite/Chroma, Cloud Sync | - | - | - | P: TeamBrain | P: compressed activity capture | P: 10+ harnesses | 4 |
| Claude Code built-ins | - (local JSON) | - | - | P: Claude-only mailboxes, cross-machine through Anthropic | Y: plan admin, Trusted Devices | (covered in earlier round) | - (Claude-only) | 2-3 |
| Happy | - | - | - | P: human-to-agent from phone, multiplayer | P: team server | - | P: wraps Claude Code and Codex, ACP | 3 (plus E2E transport) |
| ByteRover | P: context tree with git-like VC | - | - | - | Y: members, spaces, permissions | - | P: 22+ agents | 3 (repo archived) |
| Basic Memory | P: Markdown, Teams real-time | - | - | - | P: Teams | - | P: MCP, 6 clients | 3 |
| AgentFS | P: SQLite FS+KV, not git, no encryption found | - | - | - | - | Y: append-only toolcall log | P: `agentfs run` wraps any program | 3 |
| git-ai / Agent Trace | - | - | - | - | P: Teams / - | Y: line attribution / P: spec | P: 8+ agents / partners | 2-3 / 1-2 |
| Supermemory | P: hosted or self-hosted memory | - | - | - | not documented | - | P: 7 plugins + MCP | 2 |
| Conductor | - | - | - | - | P: Cloud multiplayer (Jul 2026) | - | Inv. (4 harnesses) | 1-2 |
| Vibe Kanban / Claude Squad / Sculptor / Nimbalyst | - | - | - | - | VK orgs removed | - | Inv. | 0-1 |

- **Closest to the whole bundle on the coordination core: MCP Agent Mail (Rust).** Gaps against the sidecar: no encryption of the live store; no real-time multi-machine sync (a single server); no J2 or J3; no human email identities or groups (users asked for "project-addressed shared mailboxes", issue #263); no team or user management beyond tokens; it runs as an HTTP server rather than a harness subprocess (users asked for "stdio transport", issue #41); small traction; and a custom license rider.
- **Closest integrated stack: Gas Town plus Beads.** Gaps: single host with tmux; no encryption; no J2, J3, or J5; it is an orchestrator that owns the harnesses, the opposite of a sidecar; and trust friction (see question 3).
- **Closest on auth, team, and memory: Omnara.** Gaps: it is not a sidecar for Claude Code or Codex; no git front end; no encryption claim; no email; no public TLS edge or service forwarding.
- **Closest on reach and messaging: Claude Code built-ins.** Gaps: Claude-only; traffic relayed through and stored on Anthropic servers; no service forwarding; no git store; teams are single-session and single-machine.
- **Only privacy-first item: Happy** (E2E transport, self-hostable relay). Gaps: no store, no inbox, no audit trail, no service forwarding.
- The sidecar's distinctive combination (private, encrypted, git-fronted store; network reach for local services plus a public TLS edge; one inbox namespace shared by people and agents; harness-neutral subprocess) appears in none of these products. The parts most at risk of commoditization are agent mailboxes, task lists, and leases, now in Claude Code and Codex (see question 4). The parts least covered are J2, J3, encrypted J1, and human-plus-agent J4.

### Gaps
- I did not test any product hands-on. Coverage reflects docs and READMEs as of 31 Oct 2026.
- J6 for Claude Code, Cursor, Copilot, and others was covered in an earlier round and is not re-evaluated here.
- I could not confirm whether Omnara Cloud or Conductor Cloud expose preview URLs or ports. An Omnara founder mentioned "preview urls" as a goal in Feb 2026 ([HN 46991591](https://news.ycombinator.com/item?id=46991591)), but the current README documents only that "Sandboxes also work once your instance has a public URL".

## 3. What users say about the limits (GitHub issues, Hacker News)

### Takeaway
Complaints cluster around six themes:
- **Vendor lock-in and Claude-only reach.** Remote Control has no API-key support, Entire users asked for Codex the day after launch, and Happy users asked for OpenCode.
- **Single-machine and platform constraints.** Gas Town requires tmux, and Windows is "not viable".
- **Reliability under swarm load.** MCP Agent Mail's Rust version has had SQLite corruption, and Gas Town spawns many git processes.
- **Storage migrations.** Beads' move to Dolt broke it for some users.
- **Demand for shared or group mailboxes and team use.**
- **Privacy and trust in central relays.** This includes the Gas Town credits controversy.

### Cited Findings
- **Claude-only and lock-in:** "Would be great if it supported API keys. I'm getting by with slack threads of all things for work." (squirrellous, 25 Feb 2026). A sub-thread argues tmux/mosh avoids "vendor lock in" (samusiam, pshirshov). — [HN 47148454](https://news.ycombinator.com/item?id=47148454)
- **Entire:** the "Codex support" issue was opened 11 Feb 2026, the day after launch, and drew 18 comments. — [entireio/cli #245](https://github.com/entireio/cli/issues/245)
- **Happy:** "OpenCode Support" (opened 5 Dec 2025, 17 comments) and "Still maintained ?" (opened 4 Nov 2025, 24 comments). — [slopus/happy #265](https://github.com/slopus/happy/issues/265); [#223](https://github.com/slopus/happy/issues/223)
- **Platform:** "Windows is not a viable platform: tmux hard dependency, build failures, and no viable workaround" (Gas Town, opened 6 Apr 2026). "Support local and remote execution sandboxes for polecats" (opened 1 Mar 2026). — [gastown #3538](https://github.com/gastownhall/gastown/issues/3538); [gastown #2229](https://github.com/gastownhall/gastown/issues/2229)
- **Agent teams:** split panes "require tmux or iTerm2" and are "not supported in VS Code's integrated terminal, Windows Terminal, or Ghostty". One user wrote: "Agent teams nuke your tmux layout" (anupamchugh, 6 Feb 2026). — [agent teams docs](https://code.claude.com/docs/en/agent-teams); [HN 46902223](https://news.ycombinator.com/item?id=46902223)
- **Scale and reliability:**
  - A user quoting a Gas Town bug: "With 17+ concurrent sessions each running gt commands... Each bd version spawns 5-7 git processes - This creates 85-120+ git pro[cesses]" (msp26, 23 Jan 2026). — [HN 46734302](https://news.ycombinator.com/item?id=46734302)
  - MCP Agent Mail Rust: "0.3.30 / fsqlite 0.3.8 repeatedly corrupts SQLite after parallel-WAL snapshot conflicts under agent-swarm load" (opened 30 Aug 2026, still open); "send_message panics serve-http" (21 comments). — [mcp_agent_mail_rust #278](https://github.com/Dicklesworthstone/mcp_agent_mail_rust/issues/278); [#118](https://github.com/Dicklesworthstone/mcp_agent_mail_rust/issues/118)
  - Entire: "Orphaned sessions cause 3GB+ RAM usage and 2m44s commit times" (opened 3 Mar 2026). — [entireio/cli #591](https://github.com/entireio/cli/issues/591)
- **Storage migration:** "Moving to dolt pretty much made beads unusable for me" (opened 13 Mar 2026, 23 comments). — [beads #2573](https://github.com/gastownhall/beads/issues/2573)
- **Demand for group mailboxes and subprocess transport:** "Feature: add project-addressed shared mailboxes" (opened 20 Aug 2026) and "Support project-local installation and stdio transport" (opened 20 Dec 2025). — [mcp_agent_mail #263](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/263); [#41](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/41)
- **Team collaboration demand:** "Are you thinking of doing a hosted version so I can have my team collab on it?" (lharries on Vibe Kanban, 11 Jul 2025). The same thread reported parallel agents that "clash while editing files simultaneously... It's chaos" (deepdarkforest). — [HN 44533004](https://news.ycombinator.com/item?id=44533004)
- **Central relay and privacy:**
  - "Also see solutions which don't require a central server like Vibetunnel" (_1tem, Omnara Show HN, 13 Aug 2025). — [HN 44878650](https://news.ycombinator.com/item?id=44878650)
  - One user runs "the Happy server on my home Mac to skip the cloud relay" (faramarz, 12 Feb 2026). — [HN 46991591](https://news.ycombinator.com/item?id=46991591)
  - Anthropic's own docs state that Remote Control transcripts are "stored on Anthropic servers". — [Remote Control docs](https://code.claude.com/docs/en/remote-control)
  - Entire warns that public-repo transcripts are readable. — [entireio/cli README](https://github.com/entireio/cli)
- **Network reach is do-it-yourself:** an Omnara founder said self-run `opencode serve` means you must "expose it via tailscale or something like that" (cmsparks, 12 Feb 2026). Another user said "I can't sit back down at my computer and cd/ssh/tmux into that same environment" (fragmede). — [HN 46991591](https://news.ycombinator.com/item?id=46991591)
- **Trust:** an issue alleged that Gas Town's release formulas make local installs work Gas Town's own GitHub issues using "Your Claude credits / usage" and "your GitHub account". It was opened 14 Apr 2026 and closed 1 May 2026; I did not review the resolution. The HN thread drew 253 points and 127 comments (15 Apr 2026). — [gastown #3649](https://github.com/gastownhall/gastown/issues/3649); [HN 47785053](https://news.ycombinator.com/item?id=47785053)
- **Cost:** "'agent teams' while a cool concept, it largely constrained by the economics of running multiple LLM agents" (Someone1234, 5 Feb 2026). On Gas Town: "spend tokens until your wallet bleeds dry" (WesolyKubeczek, 5 Jan 2026). — [HN 46902223](https://news.ycombinator.com/item?id=46902223); [HN 46458936](https://news.ycombinator.com/item?id=46458936)
- **Third parties filling built-in gaps:** "Show HN: Real-time dashboard for Claude Code agent teams" (1 Apr 2026, 77 points, 28 comments) and "Show HN: Claude Code agent teams with real time shared local memory" (6 Feb 2026). — [HN 47602986](https://news.ycombinator.com/item?id=47602986); [HN 46913360](https://news.ycombinator.com/item?id=46913360)

### Inferences
- The complaints line up with the sidecar's design jobs:
  - Users ask for group mailboxes (J4), stdio or subprocess transport (J7), cross-harness support (J7), and remote reach without tmux, SSH, or Tailscale (J2/J3).
  - They also want privacy from central relays (encrypted J1/J4), and observability and shared memory for agent teams (J1/J6).
- Reliability under concurrent agents is the main technical failure mode of the open-source coordination layers: git lock contention, SQLite corruption, and process explosions. A sidecar that writes a git-fronted store under many agents will face the same failure mode. This is my inference from the cited issues.

### Gaps
- The MCP Agent Mail Show HN threads had almost no comments, so there is little public user feedback beyond GitHub issues.
- I found no substantive HN discussion of Entire, Conductor, Basic Memory, or ByteRover; their launch submissions drew 0 to 8 points.
- I did not mine Reddit or Discord.

## 4. Are coordination primitives (agent mail, file leases or locks, shared task lists) moving into the harnesses in 2026, and which harness shipped what, when?

### Takeaway
Yes. Through 2026 the two largest coding harnesses absorbed the primitives that MCP Agent Mail and Gas Town pioneered in late 2025:
- **Claude Code:** agent-team mailboxes, a file-locked shared task list, and task hooks (Feb 2026); Remote Control (Feb 2026); agent view (May 2026); cross-session messaging across a user's machines (Aug 2026).
- **Codex:** collab and agent roles (Jan 2026), a mailbox (Apr 2026), and a shared agent message board (Sep 2026, shipping in Codex CLI 0.165 on 27 Oct 2026).

Copilot CLI (/fleet, Apr 2026) and Gemini CLI (subagents, Apr 2026) added parallel subagents without documented messaging or locking. Each implementation is vendor-specific, and cross-machine traffic goes through the vendor.

### Cited Findings
- **Claude Code, v2.1.32 (npm 5 Feb 2026):** "Added research preview agent teams feature for multi-agent collaboration" and "Claude now automatically records and recalls memories as it works". — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md); [npm registry](https://registry.npmjs.org/@anthropic-ai/claude-code)
- **Claude Code, v2.1.33 (6 Feb 2026):** "Added `TeammateIdle` and `TaskCompleted` hook events for multi-agent workflows". Teams use per-agent JSON mailboxes and "file locking" for task claims. — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md); [agent teams docs](https://code.claude.com/docs/en/agent-teams)
- An HN user's view on 6 Feb 2026: "Agent teams in this release is mcp-agent-mail built into the runtime. Mailbox, task list, file locking — zero config, just works." (anupamchugh, user opinion). — [HN 46902223](https://news.ycombinator.com/item?id=46902223)
- **Claude Code Remote Control:** subcommand in v2.1.51 (23 Feb 2026), expanded in v2.1.58 (25 Feb 2026); HN on 25 Feb 2026 drew 544 points. — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md); [HN 47148454](https://news.ycombinator.com/item?id=47148454)
- **Claude Code agent view, v2.1.139 (11 May 2026):** "a single list of every Claude Code session — running, blocked on you, or done." — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
- **Claude Code, v2.1.224 (7 Aug 2026):** "Added cross-session `SendMessage`: Claude Code sessions can now message each other, on any of your machines, with `ListAgents` to discover them". The same release added `claude self-hosted-runner` for Team and Enterprise. v2.1.225 (7 Aug 2026) lets SendMessage "start a conversation with your Remote Control sessions on other machines by name". — [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
- **How cross-session messaging works and its limits:**
  - Same-machine delivery uses "a per-session socket... never through Anthropic servers". Other machines are reached "Through Anthropic servers, arriving over that machine's Remote Control connection".
  - It requires a claude.ai sign-in for cross-machine use and does not work with API keys, Bedrock, Vertex, or Foundry.
  - "Plain text only".
  - "A session inside a container and a session on the host can't reach each other".
  - The receiver "queues at most 50 accepted messages".
  — [cross-session messaging docs](https://code.claude.com/docs/en/cross-session-messaging)
- **OpenAI Codex (dates are when merged PRs were opened in `openai/codex`):**
  - "feat: add agent roles to collab tools" (#9275, 15 Jan 2026). — [PR #9275](https://github.com/openai/codex/pull/9275)
  - "Preempt mailbox mail after reasoning/commentary items" (#16725, 3 Apr 2026). — [PR #16725](https://github.com/openai/codex/pull/16725)
  - "Add shared agent message-board extension interfaces" (#46959) and "Add collaboration tools for the agent message board" (#46985), both 21 Sep 2026. — [PR #46959](https://github.com/openai/codex/pull/46959); [PR #46985](https://github.com/openai/codex/pull/46985)
- **Codex CLI changelog:**
  - 0.165.0 (27 Oct 2026): "Deferred agent mail after empty final answers"; "Made agent-message wakes respect interrupts and Plan mode"; "Added silent append support to message boards".
  - 0.166.0 (29 Oct 2026): "Routed state-changing multi-agent calls through Guardian review"; "Enabled agents navigation for remote App Server sessions".
  — [Codex changelog](https://learn.chatgpt.com/docs/changelog) (developers.openai.com/codex/changelog redirects here)
- **Codex subagents GA:** a secondary source says Codex announced general availability of subagents and custom agents on 16 Mar 2026, after a feature-flag preview. Not verified against OpenAI's own post. — [Let's Data Science](https://letsdatascience.com/news/openai-codex-adds-subagents-and-custom-agents-c3e4196e)
- **Codex import:** Codex has an "Import from Claude Code" feature, described by Mem0 as "uni-directional". This is a vendor claim from a competitor. — [mem0ai/openmemory README](https://github.com/mem0ai/openmemory)
- **GitHub Copilot:**
  - Agent HQ and "mission control" for assigning and tracking multiple agents (including third-party agents) were announced at GitHub Universe on 28 Oct 2025. — [GitHub blog](https://github.blog/news-insights/company-news/welcome-home-agents/); [Visual Studio Magazine, 28 Oct 2025](https://visualstudiomagazine.com/Articles/2025/10/28/GitHub-Introduces-Agent-HQ-to-Orchestrate-Any-Agent-Any-Way-You-Work.aspx)
  - Copilot CLI `/fleet` (1 Apr 2026) splits work into parallel subagents. A secondary source reports "no file locking between subagents... the last one wins, silently"; not verified against GitHub docs. — [GitHub blog, 1 Apr 2026](https://github.blog/2026/04/01/run-multiple-agents-at-once-with-fleet-in-copilot-cli/); [GitHub docs](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/fleet); [lilting.ch (secondary)](https://lilting.ch/en/articles/github-copilot-cli-fleet-parallel-agents)
- **Gemini CLI:** subagents with parallel execution, announced April 2026 (15 Apr 2026 per secondary coverage). Google warns that parallel subagents doing heavy code edits can overwrite each other. — [Google Developers Blog](https://developers.googleblog.com/en/subagents-have-arrived-in-gemini-cli/); [InfoQ](https://infoq.com/news/2026/04/subagents-gemini-cli)
- **Cursor:**
  - Cursor 3's "Agents Window" for multiple local, cloud, worktree, and SSH agents (2 Apr 2026, secondary source). — [DataCamp](https://www.datacamp.com/blog/cursor-3)
  - `/multitask` async subagents in Cursor 3.2 (24 Apr 2026, secondary source). — [AI Catchup](https://aicatchup.com/news/cursor-3-2-multitask-multi-root)
  - I found no agent-to-agent messaging in these sources.
- **Third-party consolidation in the same period:**
  - Vibe Kanban shut down (10 Apr 2026). — [Vibe Kanban blog](https://www.vibekanban.com/blog/shutdown)
  - MCP Agent Mail's Python version was deprecated in favor of Rust. — [repo](https://github.com/Dicklesworthstone/mcp_agent_mail)
  - The ByteRover CLI repo was archived (seen 31 Oct 2026). — [repo](https://github.com/campfirein/byterover-cli)
  - Omnara pivoted to managed agents (21 Oct 2026). — [HN 50183892](https://news.ycombinator.com/item?id=50183892)
  - Conductor moved to cloud and mobile (30 Jul 2026). — [Runtimewire](https://runtimewire.com/article/conductor-launches-multiplayer-cloud-workspaces-coding-agents)
  - Entire grew from session capture into a Git forge. — [entireio/cli README](https://github.com/entireio/cli)

### Inferences
- Within a single vendor, mailboxes, task lists with locking, and session-to-session messaging are now harness features. A sidecar positioned as "agent mail for coding agents" competes directly with free built-ins in Claude Code and Codex.
- The remaining whitespace is what vendors structurally avoid or relay through their own clouds:
  - **Cross-vendor coordination:** Claude to Codex to Gemini to humans.
  - **Private, end-to-end encrypted transport and storage:** Anthropic stores Remote Control transcripts and relays cross-machine messages.
  - **Network reach for local services:** port forwarding and a public TLS edge.
  - **One identity and inbox namespace shared by people and agents.**
  - **A durable, harness-neutral record that admins can audit.**
- Codex's late-October 2026 "message boards" and Claude Code's August 2026 cross-machine `SendMessage` suggest the next move is group and broadcast channels inside each harness. That would erode a generic group-inbox pitch unless the pitch stresses cross-harness reach, human participation, and privacy.

### Gaps
- I read Codex dates from merged-PR open dates and the CLI changelog. The GitHub releases API timed out, and I did not find an official OpenAI launch post for agent mail or message boards. User-facing defaults (on by default or feature-flagged) for Codex message boards are unconfirmed.
- Cursor and Gemini dates come from secondary coverage; I did not read cursor.com/changelog or the Google post directly.
- The Copilot "no file locking" claim is secondary.
- I found no evidence of Cursor, Copilot, or Gemini shipping agent-to-agent mail or file leases as of 31 Oct 2026, but I did not exhaustively review their changelogs.
