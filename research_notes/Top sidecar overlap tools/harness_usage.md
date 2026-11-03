# Harness and protocol usage, late 2026

Scope is interfaces a coding-agent harness can drive, plus the harnesses people actually run. Overlap with jobs 1–6 is scored only from pages opened below. No adoption percentage below was inferred from marketing copy. Download counts are install events, not people.

Rank, by how well public usage evidence matches “a userspace subprocess any harness can drive over a text protocol,” as of 2026-10-31:

1. MCP over stdio. Strongest match to the shape, and the only one with both a current spec and very large SDK install volume plus named clients in Claude, Cursor, VS Code Copilot, ChatGPT, and Codex.
2. Agent Client Protocol (ACP) over stdio. Same subprocess shape, but the host is an editor, and no developer-survey penetration number was found.
3. Vendor CLIs spawned as subprocesses (Claude Code `-p` JSON, Codex `exec`). These are the most-used harnesses, but each speaks its own CLI, not a protocol other harnesses implement.
4. In-process libraries (OpenAI Agents SDK, LangGraph, Google ADK, and the Claude Agent SDK as a library). Real products. Not a text protocol a foreign harness drives.
5. A2A. A real agent-to-agent spec (released 1.0.0) over HTTP, gRPC, and JSON-RPC. Not a local subprocess of a coding harness. No survey penetration number was found.

Among harnesses, Stack Overflow’s 2026 “used in the past year” table and JetBrains’ May–July 2026 “use at work” figures agree on the top cluster (Claude Code, GitHub Copilot, Codex, Cursor) and disagree on the gaps between them. Neither survey shows any of those four also shipping real-time encrypted git storage, port forwarding, a public TLS edge, and an email inbox.

## How widely used is MCP, and which clients speak it?

### Takeaway

MCP is the default text protocol for attaching tools to coding agents in late 2026. The current spec is dated 2026-07-28 and still defines a newline-delimited stdio binding for a client-launched subprocess. There is no developer-survey percentage for “uses MCP” in the Stack Overflow pages opened here. The usage evidence that does exist is SDK install volume and named clients, not a share of developers.

### Cited Findings

- The specification page labels 2026-07-28 as the latest version. MCP is an open protocol between hosts, clients, and servers, carried as JSON-RPC 2.0. Servers expose resources, prompts, and tools. — [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- The transports page for that revision defines two standard bindings. stdio is “newline-delimited messages over the standard streams of a client-launched subprocess.” Streamable HTTP is an HTTP POST per message, with the reply as a JSON object or a request-scoped SSE stream. Custom transports are allowed. The same page says earlier revisions used a connection-scoped `initialize` handshake and allowed servers to start JSON-RPC requests; 2026-07-28 clients and servers detect that era and fall back. — [MCP transports, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- The npm registry page for `@modelcontextprotocol/sdk` 1.32.2 says this package is the v1 maintenance line and implements the spec only through 2025-11-25. Support for 2026-07-28 is not planned on v1. v2, called the current stable release and dated there as released 2026-07-27, ships as separate packages `@modelcontextprotocol/server` and `@modelcontextprotocol/client`. The same README lists stdio “for local, process-spawned integrations” and Streamable HTTP for remote servers. — [npm @modelcontextprotocol/sdk](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
- The npm downloads API, window 2026-10-23 through 2026-10-29, reports 87,026,138 downloads of `@modelcontextprotocol/sdk` and 21,176,440 downloads of `@modelcontextprotocol/server`. These are package downloads, not unique developers or running servers, and the two packages are not interchangeable versions of one install. — [npm downloads API, sdk](https://api.npmjs.org/downloads/point/last-week/@modelcontextprotocol/sdk); [npm downloads API, server](https://api.npmjs.org/downloads/point/last-week/@modelcontextprotocol/server)
- The PyPI stats API for the package named `mcp`, retrieved 2026-10-31, reports `last_day` 10,739,255, `last_week` 70,537,448, and `last_month` 235,193,557. The JSON does not name an end date. The project homepage on pypi.org was not opened, so this is the download count for that package name, not a confirmed unique-user count. — [pypistats recent, package mcp](https://pypistats.org/api/packages/mcp/recent)
- The community extension-support matrix names these as MCP clients: Claude (web), Claude Desktop, Claude Code, VS Code GitHub Copilot, Microsoft 365 Copilot, Goose, Postman, MCPJam, ChatGPT, Cursor, Archestra.AI, PostHog Code, Kiro Crew, fast-agent, MCP Inspector, and mcpc. The page says the list is community-maintained. Checkmarks did not render in the fetched text, so extension-by-extension support is not cited here. The rendered example-clients page at modelcontextprotocol.io/clients did not return a readable client list. — [MCP extension client matrix](https://modelcontextprotocol.io/extensions/client-matrix)
- Codex CLI documents `codex mcp` as the way to “add local or remote MCP servers” and inspect the tools available to the session. Codex is therefore an MCP client, even though it is not a row on the extension matrix above. — [Codex CLI](https://learn.chatgpt.com/docs/codex/cli)
- Cursor’s enterprise audit-log docs include the event `mcp_server_config` with `server_type` values `HTTP` and `STDIO`, scoped to user or team. That is product evidence that Cursor configures both MCP transports, including a local subprocess. — [Cursor compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring)
- The Claude Agent SDK overview lists MCP as a capability: “Connect external tools and data sources via the Model Context Protocol.” — [Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- The OpenAI Agents SDK documents “MCP server tool calling” as a built-in integration that exposes remote MCP tools beside function tools. The page describes remote tools, not a stdio subprocess. — [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)

### Inferences

- MCP is widely installed and is spoken by the harnesses that lead the 2026 usage surveys (Claude Code, VS Code Copilot, Cursor, Codex, plus ChatGPT). That is adoption evidence. It is not a percentage of developers.
- The stdio binding is the piece that matches “userspace subprocess of any harness, text protocol.” Streamable HTTP is the other production binding and is not a local subprocess.
- v1 and v2 TypeScript packages both move tens of millions of downloads a week. Adding those figures, or treating them as users, would overstate adoption. CI and dependency installs dominate this kind of count.
- A survey rank of protocols is not possible from the pages opened. MCP ranks first on qualitative evidence (spec liveness, client list, download magnitude), not on a published share of developers.

### Gaps

- No Stack Overflow or JetBrains question opened here asks whether the respondent uses MCP. A penetration rate is missing.
- The official example-clients page did not render, and the extension matrix is community-maintained with unreadable cells. Codex and Gemini CLI are not established by that matrix. Gemini CLI was not opened.
- An official count of public MCP servers was not opened from a primary page. Secondary claims of “10,000 servers” were not used.
- The PyPI project page for `mcp` was not opened, so the package’s maintainer description was not confirmed in this pass.
- `@modelcontextprotocol/client` weekly downloads were not fetched. v2 client volume is unknown here.

## What other text or subprocess interfaces are in real use?

### Takeaway

Two open protocols actually spawn a local process and talk text on its stdio: MCP and ACP. Claude Code and Codex can also be spawned as subprocesses, but only by something that speaks that vendor’s CLI. OpenAI Agents SDK, LangGraph, and Google ADK are libraries inside an application. A2A is a network protocol between agents. No separate, widely measured “line-oriented local memory server” protocol turned up.

### Cited Findings

- ACP’s introduction says local agents “run as sub-processes of the code editor, communicating via JSON-RPC over stdio,” and remote agents can use HTTP or WebSocket. It also says full remote-agent support is still a work in progress. User-readable text defaults to Markdown. The protocol reuses MCP’s JSON shapes where it can. — [ACP introduction](https://agentclientprotocol.com/get-started/introduction)
- JetBrains’ May–July 2026 adoption write-up says Claude Agent, Codex, GitHub Copilot, and OpenCode are integrated into the JetBrains AI chat, and that “dozens of other agents, including Cursor, can be added via the Agent Client Protocol (ACP).” That is a vendor stating ACP is how extra agents enter its IDE. It is not a count of ACP users. — [JetBrains, AI coding agent adoption, 2026-08-18](https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/)
- Cursor’s docs navigation, on pages opened for teams and audit logs, includes a CLI entry titled ACP and a Headless / CI entry. Those ACP and headless pages were not opened, so Cursor’s ACP behavior is not described here. The nav item is evidence the docs treat ACP as a CLI surface. — [Cursor teams setup](https://cursor.com/docs/account/teams/setup); [Cursor compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring)
- Claude Agent SDK: a Python/TypeScript library “that runs the Claude Code binary,” with Claude Code’s tools, permissions, sessions, and hooks. For any other language, the docs say to run the CLI as a subprocess with `-p` and `--output-format json`. The interactive product is the Claude Code CLI. A separate Client SDK calls the Claude API directly. Managed Agents are hosted by Anthropic, or in a self-hosted sandbox, and are reached via an SDK, the `ant` CLI, or REST. This is Anthropic’s harness, embeddable as a library or a CLI subprocess. It is not a protocol an arbitrary third-party harness implements. — [Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- Codex CLI is a terminal agent: inspect, edit, and run commands in a local repo; `codex exec` for scripts and CI; `codex mcp` for MCP servers; `codex cloud` to hand work to a cloud environment and apply the result locally. Sign-in is “Sign in with ChatGPT” or another method. Git checkpoints are described as local revert points around a task, not as a storage service. The CLI is OpenAI’s harness. A pipeline can spawn it. Other harnesses do not speak a Codex protocol to gain its tools; Codex speaks MCP to reach tools. — [Codex CLI](https://learn.chatgpt.com/docs/codex/cli)
- OpenAI Agents SDK is installed with `pip install openai-agents` and used in-process (`Agent`, `Runner.run_sync`). It has handoffs, guardrails, sessions, tracing, sandbox agents, and remote MCP tool calling. It is a library inside the caller’s process, not a subprocess protocol. — [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)
- LangGraph is installed with `pip install -U langgraph` and used in-process as a graph runtime (`StateGraph`, `invoke`). The overview calls it a low-level orchestration framework for durable, stateful agents, with persistence, human-in-the-loop, and memory. Deployment is a separate LangSmith product. Not a text protocol a foreign harness spawns. — [LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview)
- Google ADK’s site (the google.github.io docs URL resolved here) describes an open-source framework in Python, TypeScript, Go, Java, and Kotlin, installed in Python with `pip install google-adk`. Agents are constructed in code. Production deployment is “containerize and run on your own infrastructure” or Google Cloud (Agent Runtime, Cloud Run, or GKE). That is a library plus a deploy target, not a subprocess protocol any coding harness speaks. This page does not mention MCP or A2A. — [Agent Development Kit](https://adk.dev/)
- A2A’s spec page says the latest released version is 1.0.0. It is an open standard for independent agents to discover each other, negotiate modalities, and exchange tasks without sharing internal state, memory, or tools. Bindings named on that page are JSON-RPC, gRPC, and HTTP+JSON/REST. Transport is network RPC, not a client-launched local subprocess. The page gives no adoption count. — [A2A specification](https://a2a-protocol.org/latest/specification/)

### Inferences

- If the requirement is “any harness, one text protocol, local subprocess,” MCP stdio is the interface those harnesses already implement. ACP is the same shape aimed the other direction: an editor spawning an agent, not an agent spawning a tool. A sidecar that wanted to be driven by Cursor, Claude Code, Codex, and VS Code would implement MCP. A sidecar that wanted to be the agent inside Zed or a JetBrains IDE would implement ACP.
- Claude Code’s `-p` JSON mode and Codex `exec` are real subprocess interfaces with wide harness usage behind them, but a third-party tool cannot be added to “any harness” by speaking those CLIs. The harness would have to be Claude or Codex.
- OpenAI Agents SDK, LangGraph, and ADK do not meet job 7. They are how a developer writes an agent, not how an existing harness drives a local tool.
- A2A does not meet job 7 either. It is how two agents call each other across a network. Nothing opened here shows coding-agent users driving a local sidecar with A2A.
- No line-oriented local memory server, distinct from MCP’s newline-delimited stdio, was found with usage evidence. MCP stdio is itself newline-delimited JSON-RPC. A memory server on that transport would be an MCP server, not a second protocol.

### Gaps

- No survey, registry count, or download figure for ACP was opened. “Dozens of other agents” is JetBrains’ wording, not a census. Zed’s ACP registry page was not opened.
- No download or survey figures were opened for the OpenAI Agents SDK, LangGraph, or Google ADK, so they cannot be ranked against each other by use.
- A primary announcement of A2A’s move under the Agentic AI Foundation, and any “150 organizations” claim, was not opened. Organizational support is therefore unknown here.
- The ADK page opened does not say whether current ADK speaks MCP or A2A. Secondary news claims were not used.
- Claude Code’s headless-mode page was not opened; the subprocess claim rests on the Agent SDK overview’s explicit `-p` / `--output-format json` instruction.
- No widely used product documented as a “line-oriented local memory server” was opened. Absence from this pass is not proof none exists.

## Which coding agents have the best public usage evidence in 2025–2026?

### Takeaway

The best public evidence is the Stack Overflow Developer Survey 2026 tool table, with JetBrains’ reweighted Developer Ecosystem Survey 2026 as a second, conflicting measure of “use at work.” Claude Code and GitHub Copilot lead both. Codex and Cursor are the next tier. Windsurf and Devin are still measured and are far behind. The two surveys do not support a single percentage ranking, because they ask different questions of different bases.

### Cited Findings

- Stack Overflow’s 2026 survey homepage says it collected 30,903 responses from 169 countries. — [Stack Overflow Developer Survey 2026](https://survey.stackoverflow.co/2026)
- The AI coding-agents data page asks: “Have you used any of the following coding agents or assistants in the past year? Do you want to use any of the following in the next 6 months?” The chart is labeled “Used · n = 12,255.” The page’s own analysis rounds the leaders to “Claude Code (66%) and GitHub Copilot (59%).” The table, which is multi-select so shares sum past 100%, is:

  | Tool | Respondents | Percent of n=12,255 |
  | --- | ---: | ---: |
  | Claude Code | 8,030 | 65.5% |
  | GitHub Copilot | 7,196 | 58.7% |
  | OpenAI Codex | 3,620 | 29.5% |
  | Cursor | 3,127 | 25.5% |
  | Google Antigravity | 1,956 | 16.0% |
  | Gemini Code Assist | 1,789 | 14.6% |
  | Open Code | 1,662 | 13.6% |
  | JetBrains AI | 1,569 | 12.8% |
  | Windsurf | 796 | 6.5% |
  | Devin | 360 | 2.9% |

  Warp, Cline, Amazon Q, Continue, Replit Agent, Aider, and others are on the same table below Windsurf or between Windsurf and Devin. The question is optional, so 12,255 is not 30,903. — [Stack Overflow 2026, AI coding agents](https://survey.stackoverflow.co/2026/ai/data/ai-code-agent)
- JetBrains, writing up the Developer Ecosystem Survey 2026: more than 15,000 professional developers, fielded so that May–July 2026 is the current wave, statistically reweighted by region, employment, language, and familiarity with JetBrains products. “90% of professional developers were using AI coding agents at work at least weekly” and “68% using them daily.” Tool figures they state as use at work: Claude Code about 39% (18% in January 2026; 47% in the United States; the single most-used tool for 31%); GitHub Copilot 21% (29% a year earlier); Codex 16% (3% in January 2026); Cursor 12% (18% in January; in China, 28% in January to 16% in May–July); OpenCode 7%; Google Antigravity 6%; JetBrains AI in IDEs and/or Junie about 9%. Awareness, not use: Copilot 79% (86–90% in Europe, the UK, and the US); Codex awareness from 27% in January to 65%; Cursor mind share from 69% to 75%; Antigravity awareness from 29% to 47%; OpenCode mind share 42%. — [JetBrains, AI coding agent adoption, 2026-08-18](https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/)
- Windsurf is a response option in the Stack Overflow 2026 instrument at 6.5% of people who answered the used question (796 people). That is evidence it was still a recognized product when the survey ran. A vendor page confirming it still ships on 2026-10-31 was not opened. — [Stack Overflow 2026, AI coding agents](https://survey.stackoverflow.co/2026/ai/data/ai-code-agent)
- Devin is on the same table at 2.9% (360 people). — [Stack Overflow 2026, AI coding agents](https://survey.stackoverflow.co/2026/ai/data/ai-code-agent)

### Inferences

- Best-evidence order for “developers who used this coding agent,” past year, among people who answered Stack Overflow’s optional question: Claude Code, GitHub Copilot, OpenAI Codex, Cursor, then a gap, then Google Antigravity, Gemini Code Assist, OpenCode, and JetBrains AI. Windsurf and Devin are real but small on that instrument.
- Best-evidence order for “using it at work” in JetBrains’ reweighted mid-2026 wave: Claude Code, GitHub Copilot, Codex, Cursor. The same four names, with Claude further ahead and Copilot and Cursor lower than a past-year-ever-used question would suggest.
- Do not average 65.5% and 39%. Stack Overflow’s denominator is people who answered an optional multi-select about the past year. JetBrains’ denominator is professional developers, reweighted, and the metric is current use at work. Stack Overflow is also a self-selected community survey. JetBrains sells a competing assistant, which is a reason to treat its levels as a second source rather than the tie-breaker, even though the write-up documents weighting.
- Copilot’s Stack Overflow share is still second, while JetBrains shows it losing share of “use at work” (29% to 21%). Both can be true: many people used it in the past year, and fewer name it as what they use at work now.
- Stars, vendor “most loved” claims, and install-from-a-marketplace slogans were not used. None of those were needed once these two surveys were open.
- Google Antigravity and OpenCode outrank Windsurf and Devin on the Stack Overflow table. They were not in the suggested list, but the table puts them in the second tier.

### Gaps

- The survey wave’s exact field dates are not on the Stack Overflow pages opened. Secondary write-ups said June–August 2026. That field window was not confirmed from Stack Overflow itself.
- No page opened here gives GitHub’s own Copilot seat count, Cursor’s user count, Anthropic’s Claude Code user count, or Cognition/Devin’s customer count. Those vendor totals are missing, so the ranking is survey ranking only.
- JetBrains does not publish Windsurf or Devin in the 2026-08-18 post, so there is no second-source check on those two.
- Whether Windsurf still exists as a shipping product on 2026-10-31 was not checked on a vendor page.
- A 2025 JetBrains figure (85% regularly using AI tools) appeared in search snippets and was not taken from a page opened in full, so it is not used.

## For the leaders, which of jobs 1–6 do they also do?

### Takeaway

On the pages opened, none of Claude Code, GitHub Copilot, Codex, or Cursor is a real-time encrypted store with a git front end, an IP and port forwarder for local services, a public TLS edge, and an email or group inbox. The overlap that is documented is administrative: Cursor Teams and Enterprise cover sign-in, membership, and an audit log; GitHub Copilot Business and Enterprise cover license and policy changes plus agent activity on github.com, in an audit log that excludes local prompts. Cloud agents and “Origin” repositories are not those network jobs.

Jobs, as scored: (1) real-time encrypted storage with a git front end, (2) IP and port forwarding for local services, (3) a public TLS edge, (4) email inbox and group inbox, (5) easy auth and team management, (6) an audit trail for an admin view.

### Cited Findings

- Claude Code, via the Agent SDK overview, reads, writes, and edits files, runs commands, searches the web, loads skills and memory from `.claude/` and `~/.claude/` and from `CLAUDE.md`, and connects MCP servers. Sessions can be resumed. Nothing on that page describes encrypted storage, a git hosting front end, port forwarding, a TLS edge, an inbox, team SSO, or an admin audit log. — [Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- GitHub’s Copilot audit-log docs: enterprise owners, or a custom role that can read enterprise audit logs, on Copilot Business or Copilot Enterprise, can review “changes to your Copilot plan, such as changes to settings and policies or a user losing or receiving a license” and “agent activity on the GitHub website.” The log “does not include client session data, such as the prompts a user sends to Copilot locally.” Search `action:copilot` for plan events and `actor:Copilot` for agent activity. Events are kept 180 days; the docs recommend streaming to a SIEM. Seat-assignment event names such as `copilot.cfb_seat_assignment_created` are on this page, which shows license administration exists. The page does not describe SSO setup, an inbox, port forwarding, a TLS edge, or encrypted git storage. — [Reviewing audit logs for GitHub Copilot](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/review-audit-logs)
- Codex CLI works on the local repository, can create git checkpoints before and after a task so the user can revert, can run non-interactively as `codex exec`, can attach MCP servers, and can move work to “Codex cloud” and apply the result locally. The page does not describe a hosted git service, encryption at rest, port forwarding, a public TLS endpoint for the user’s services, an inbox, team administration, or an admin audit trail. — [Codex CLI](https://learn.chatgpt.com/docs/codex/cli)
- Cursor Teams: “The Teams plan provides tools for organizations: SSO, team management, access controls, and usage analytics.” Admins invite members, can opt into domain matching, can set an unpaid admin, and bill per active user. An Enterprise organization can hold multiple teams. That is job 5, on the Teams plan, not a claim about the individual editor. — [Get Started with Teams](https://cursor.com/docs/account/teams/setup)
- Cursor Enterprise audit logs “record who changed what in your team and organization: sign-ins, membership, roles, API keys, settings, integrations, Cloud Agent environments, Grok Bot configuration, and Origin repositories.” Each event has a time and, when the request carried them, actor, client IP, and product surface. “Payloads carry identifiers, names, and changed settings, never prompts, agent output, generated code, or credentials.” Explicitly not logged: agent responses, prompts, and generated code; Grok Bot shell and browser actions (those go to a separate action-recording stream); failed sign-ins; secret values. Audit logs are Enterprise-only. The same page documents `mcp_server_config` events for HTTP and STDIO MCP servers. This is job 6 for administrative changes, not a transcript of agent work. — [Cursor compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring)
- The same Cursor pages’ navigation lists an “Origin” section (create a repository, mirror GitHub, clone, push, pull, pull requests) and a Tailscale integration, and the audit-log setting names include `origin_disabled`, network allowlists, and cloud-agent egress controls. The Origin product page, the Tailscale integration page, and the Private Connectivity page were not opened. Those nav labels are not evidence of encrypted storage, port forwarding, or a public TLS edge. — [Cursor compliance and monitoring](https://cursor.com/docs/enterprise/compliance-and-monitoring)

### Inferences

- Job 7 is the only job the leading harnesses clearly share with a local sidecar, and they share it as clients of MCP (Claude Code, Cursor, VS Code Copilot, Codex), not by being the sidecar.
- Job 5 is documented for Cursor Teams (SSO, invites, roles, domain join) and, more narrowly, for Copilot Business/Enterprise as administered licenses and policies. It was not documented on the Claude Code or Codex pages opened.
- Job 6 is documented for Cursor Enterprise and for GitHub Copilot on github.com. Both vendors say the admin log is not the local prompt stream. A sidecar whose audit trail included what the agent saw and did would be ahead of these logs, not matched by them.
- Jobs 1, 2, 3, and 4 were not found for any of the four leaders on a page that describes the product. Local git checkpoints, cloud agent VMs, Slack or Teams notification integrations, and enterprise network allowlists are different products from encrypted realtime git, a forwarded port, a public TLS edge, and an inbox. They should not be counted as overlap.
- Devin, Windsurf, Antigravity, and OpenCode were not scored for jobs 1–6. No product page for those jobs was opened.

### Gaps

- Cursor Origin’s storage model was not opened. It may or may not be encrypted, realtime, or a general git remote. The audit log only shows that Origin repositories are an audited object.
- Cursor Private Connectivity, network allowlists, and the Tailscale integration were not opened. They might be private networking for cloud agents. They were not read, so they are not scored as job 2 or job 3.
- Claude Code team and enterprise admin docs were not opened. Job 5 or 6 might exist on a page this pass did not fetch. The Agent SDK overview does not describe them.
- Codex enterprise admin, audit, and cloud-environment networking docs were not opened. The CLI page is silent on them. The learn.chatgpt.com chrome linked enterprise identity pages that were not fetched.
- GitHub Copilot’s SSO story was not opened. Seat events show licensing administration, not the identity-provider flow.
- No leader’s page was opened that inventories “we do not offer encrypted git, port forwarding, a TLS edge, or email.” The negative findings are “not described on the pages opened,” which is the evidence available, not a proof of absence across the whole product line.
