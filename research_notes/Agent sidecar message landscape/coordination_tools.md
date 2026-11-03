# Developer tools for agent coordination, memory, messaging, and local reachability (late 2026)

Research date: 2026-10-31. Claims below are limited to primary pages opened on that date (vendor docs, homepages, or GitHub READMEs). Secondary articles were used only to discover names and are not cited as facts. Anything whose primary page predates 2025 is marked historical only if it was opened; older announcement posts were not used as current product descriptions.

Jobs used throughout:

- (a) shared or persistent agent memory / project context
- (b) real-time or git-backed storage of that context
- (c) encryption or privacy of agent data
- (d) agent-to-agent or human-to-agent messaging, including email inboxes for agents
- (e) exposing local services (forwarding, tunnels, public TLS edge)
- (f) auth and team management
- (g) admin audit trails
- (h) running beside a harness as a local subprocess or text/CLI protocol, rather than only as a cloud platform

## Which products are the closest tools in each job, and what do their own pages say?

### Takeaway

As of late 2026 the work is split across separate product categories: memory/context APIs, git- or file-backed project instructions, agent harness SDKs, agent-to-tool and agent-to-agent protocols, email inboxes for agents, and general developer tunnels. No page opened describes one product that performs all eight jobs.

### Cited Findings

- **Mem0** (mem0.ai). Tagline from the docs intro: "Mem0 gives your AI agents long-term memory that persists across sessions, tools, and runs." The same page offers a managed platform and "The open-source version. Run it as a library or a Docker stack, with your data on your infrastructure." Docs also point at coding-agent guides for Claude Code, Cursor, Codex, Kimi Code, OpenCode, OpenClaw, Pi Agent, DeepSeek Harness, and Antigravity, and at framework guides including LangChain, CrewAI, LlamaIndex, and the Vercel AI SDK. — [Mem0 introduction](https://docs.mem0.ai/introduction)
- **Mem0 Platform** calls itself "the fully managed memory layer for your AI apps and agents" and says "Audit logs and workspace governance ship by default." It stores extracted facts, not a requirement that the caller run a vector database. — [Mem0 Platform overview](https://docs.mem0.ai/platform/overview)
- **Mem0 Open Source** is "the same memory engine as the Platform, running on your own infrastructure." It runs as a library (`Memory()`) or as a Docker server "with a dashboard, per-user API keys, and a request audit log." Library defaults named on that page: OpenAI `gpt-5-mini`, OpenAI embeddings, local Qdrant at `/tmp/qdrant`, and SQLite history at `~/.mem0/history.db`. The server default vector store is Postgres with pgvector. — [Mem0 Open Source overview](https://docs.mem0.ai/open-source/overview)
- **Letta** (Letta, an AI lab; product page says it was "Born from MemGPT at UC Berkeley's Sky Computing Lab"). Homepage line: "Stateful agents for your team that get better as you work with them. Run locally or on the cloud." It says all context "is git-tracked through MemFS," and that users can "Communicate with agents through Slack, Discord, Telegram, or custom channels." The CLI install shown is `npm i -g @letta-ai/letta-code`, then `letta`. — [Letta Agent](https://www.letta.com/agent)
- **Letta MemFS** "is how a Letta agent works with its long-term memory." Memory "is part of the agent's state, held in a git repository that belongs to the agent — hosted by Letta for cloud agents." MemFS projects that repo onto the machine as files the agent edits; "Edits are local until committed and pushed." "Local-only agents commit to a repository on the current machine." "Each agent has its own MemFS." Shared memory is described as a separate feature "when multiple cloud-hosted agents need access to the same Git-backed files." MemFS "does not include a semantic or vector index by default." — [MemFS](https://docs.letta.com/concepts/memfs)
- **Letta memory operations** (page reached from the Letta Agent memory docs): `/init`, `/remember`, and `/memory`; dreaming via background subagents; Free plan "5 MiB per memory repository" and Pro "50 MiB per memory repository," counting files in the latest snapshot, not Git history. — [Memory & dreaming](https://docs.letta.com/configuration/memory)
- **Zep** (getzep.com docs). "Zep is the unified context layer for enterprise data." Listed uses: enterprise context graphs, agent memory, and customer or account context. A Context Graph "represents facts, their relationships, and changes over time." "Audit Logs record dashboard activity, and API Logs record supported API request activity." — [Zep concepts](https://help.getzep.com/concepts)
- **LangGraph** (documented on docs.langchain.com). "AI applications need memory to share context across multiple interactions." Short-term memory is a checkpointer scoped by `thread_id`. Production examples on that page use Postgres, and the page also documents MongoDB, Redis, and Oracle checkpointers, plus a Postgres store for long-term cross-thread memory. In-memory savers are shown for non-production use. — [LangGraph memory](https://docs.langchain.com/oss/python/langgraph/add-memory)
- **Claude Code memory** (Anthropic). "Each Claude Code session begins with a fresh context window." Persistence is `CLAUDE.md` / `AGENTS.md` files the user writes, plus auto memory Claude writes. Project `CLAUDE.md` is "shared with your team through version control." Auto memory is per repository, and only the first 200 lines or 25KB of the index load each session. Managed-policy `CLAUDE.md` paths are given for macOS, Linux/WSL, and Windows. — [How Claude remembers your project](https://code.claude.com/docs/en/memory)
- **Cursor Rules** (Cursor). "Large language models don't retain memory between completions. Rules provide persistent, reusable context at the prompt level." Project Rules live in `.cursor/rules` as version-controlled `.mdc` files. User Rules are global. Team Rules are "managed from the dashboard" on Team and Enterprise plans. `AGENTS.md` is supported as plain markdown. Precedence stated: Team Rules, then Project Rules, then User Rules. — [Cursor Rules](https://cursor.com/docs/rules)
- **AgentMemory** (GitHub project `jayzeng/agentmemory`, MIT). "AgentMemory is a local-first, MIT-licensed memory layer for coding agents. It stores durable memory as plain Markdown files." Default directory `~/.agent-memory/`. It "does not require an account, remote service, payment flow, or proprietary runtime." It can run as an MCP server over stdio: `agent-memory serve --mcp`, "one message per line on stdin/stdout." README says common credential shapes "are redacted before AgentMemory writes or injects memory content." — [agentmemory README](https://github.com/jayzeng/agentmemory)
- **Model Context Protocol** (modelcontextprotocol.io, spec revision 2026-07-28). "Model Context Protocol (MCP) is an open protocol that enables seamless integration between LLM applications and external data sources and tools." It uses JSON-RPC 2.0 among hosts, clients, and servers. Server features named on the spec page: resources, prompts, and tools. Optional extensions named there include Tasks, Skills over MCP, and MCP Apps. The security section says hosts must get explicit user consent before exposing user data or invoking tools, and that the protocol itself cannot enforce those principles. — [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- **Agent2Agent (A2A)** (originally developed by Google, donated to the Linux Foundation; TSC named as AWS, Cisco, Google, IBM Research, Microsoft, Salesforce, SAP, and ServiceNow). Tagline: "An open protocol enabling communication and interoperability between opaque agentic applications." The same page says MCP is for agent-to-tool communication and A2A is for agent-to-agent communication. It also says A2A is "Not an interactive messaging app like Slack, Discord, WhatsApp, or Telegram" and "Not an agent development kit." Agents "interact without needing to share internal memory, tools, or proprietary logic." Apache License 2.0. A CLI and SDKs for Python, JavaScript, Java, C#/.NET, Go, and Rust are linked. — [A2A Protocol](https://a2a-protocol.org/latest/)
- **Claude Agent SDK** (Anthropic). "Build production AI agents with Claude Code as a library." The SDK "runs the Claude Code binary" inside "a process you operate," in Python or TypeScript. For other languages the docs say to "run the CLI as a subprocess" with `-p` and `--output-format json`. Capabilities listed include subagents, MCP, permissions, sessions, and skills/commands/memory loaded from the project's `.claude/` and from `~/.claude/`. A separate "Managed Agents" option is Anthropic-hosted, with an optional self-hosted sandbox. — [Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- **OpenAI Agents SDK** (OpenAI; TypeScript docs). "Build text, sandbox, and voice agents with a small set of primitives." Primitives include agents, sandbox agents, voice agents, handoffs, guardrails, function tools, "MCP server tool calling," and "Sessions: A persistent memory layer for maintaining working context within an agent loop." A sandbox example uses `UnixLocalSandboxClient` inside the application. The page says the SDK is also available in Python and is a successor to the earlier Swarm experiments. — [OpenAI Agents SDK (TypeScript)](https://openai.github.io/openai-agents-js/)
- **Google Agent Development Kit (ADK)** (Google). "Build production agents, not prototypes." "ADK is the open-source agent development framework that lets you build, debug, and deploy reliable AI agents at enterprise scale. Available in Python, TypeScript, Go, Java, and Kotlin." The same page says you can containerize and run ADK on your own infrastructure, or deploy to Google Cloud (Agent Runtime, Cloud Run, or GKE), where agents "inherit managed infrastructure, built-in authentication, Cloud Trace observability, and enterprise-grade security." It describes multi-agent orchestration and graph workflows as of ADK 2.0. — [ADK](https://adk.dev/)
- **AgentMail** (agentmail.to). "AgentMail is the first email provider built for AI agents. It gives agents their own inboxes to send, receive, and act upon emails." "This allows agents to assume their own identity and communicate via the universal protocol of email with services, people, and other agents." Free tier on that page: "3 inboxes and 100 emails per day, no credit card required." — [AgentMail welcome](https://www.agentmail.to/docs/welcome)
- **Resend Inboxes** (Resend), announced on the Resend blog dated 2026-10-22. "The inbox for agents. Create shared inboxes, connect your own agents, and build workflows around email." An inbox sends and receives on the customer's domain. "The same inbox can be worked by people and agents side by side." The post says agents such as Claude Code, Cursor, Codex, Grok, or Gemini connect "through MCP or skills," and that the product is usable via API, CLI, or MCP server. "You can start for free with up to 3 inboxes today. Additional inboxes are available on paid plans on a pay-as-you-go basis ($1/inbox)." — [Announcing Inboxes](https://resend.com/blog/announcing-inboxes)
- **ngrok.** "ngrok is developer infrastructure that routes and secures traffic to your apps, APIs, and AI models." Core products named: Gateway, AI Gateway, and Share Localhost. Share Localhost: "Expose a service running on `localhost` to the internet, even from behind a NAT or firewall." The same page lists "Connect local MCP servers: Let ChatGPT and Claude reach tools on your machine" and an "Identity and access" primitive for "credentials for human users and automated processes." — [What is ngrok?](https://ngrok.com/docs/about)
- **Cloudflare Tunnel** (Cloudflare). Public-app docs: "Securely connect your origin servers, APIs, and services to Cloudflare with post-quantum encrypted tunnels — no public IPs required." `cloudflared` makes outbound connections; hostnames map to local services, "for example, `app.example.com` to `http://localhost:8080`." "Available on all plans." Protocols named include HTTP, HTTPS, TCP, SSH, and RDP. A separate Cloudflare One page covers private networking and Zero Trust rather than public publishing. — [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/); [Cloudflare One Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
- **Tailscale Funnel** (Tailscale). "Tailscale Funnel lets you route traffic from the broader internet to a local service running on a device in your Tailscale network (known as a tailnet)." The page, last validated 2026-01-20, says Funnel "is currently in beta" and "is available for all plans." Example command `tailscale funnel 3000` publishes `https://<machine>.<tailnet>.ts.net` and proxies to `http://127.0.0.1:3000`. Public ports are limited to 443, 8443, and 10000. The page says the Funnel relay "cannot decrypt" the proxied traffic. Tailscale Serve is the alternative "only with other devices in your tailnet." — [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)

Job coverage that is directly stated on those pages, not inferred:

| Product | a memory | b git or realtime store | c encryption or privacy control | d messaging | e local reachability | f auth/teams | g audit | h local process beside a harness |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Mem0 Platform | yes | no git stated; managed store | vendor-hosted | no | no | workspace governance stated | audit logs stated | guides for coding agents; mechanism not opened |
| Mem0 OSS | yes | local Qdrant/SQLite or Postgres, not git | "your own infrastructure" | no | no | per-user API keys on the server | request audit log on the server | library or Docker server |
| Letta / MemFS | yes | git commits; cloud-hosted or local repo | local-only option stated; encryption of the repo not stated | Slack, Discord, Telegram, custom channels | no | "for your team"; shared cloud memory | not stated on pages opened | Letta's own CLI/agent, local or cloud |
| Zep | yes | temporal graph, not git | BYOK, BYOC, SOC 2, HIPAA | no inbox | no | RBAC, SSO, ABAC | Audit Logs and API Logs | not a local sidecar; cloud or BYOC |
| LangGraph | yes, thread and store | DB checkpointers, not git | depends on the database you run; not a product encryption claim | graph/multi-agent runtime, not an inbox | no | not on the memory page | not on the memory page | library inside the app |
| Claude Code memory | yes, files plus auto memory | project files can be in git; auto memory is local files | not stated on the memory page | no | no | managed policy file for an org | not an admin audit log | files loaded by Claude Code |
| Cursor Rules | instructions, not chat memory | project rules are version-controlled | not stated | no | no | Team and Enterprise Team Rules | not stated | rules inside Cursor |
| AgentMemory | yes, local markdown | files on disk; git commits not stated | local-only; credential redaction | no | no | no account | no | stdio MCP subprocess |
| MCP | context and tools, not a memory product | no | consent rules; not an encrypted store | tool protocol, not agent chat | no | spec does not define a team product | no | protocol; stdio vs HTTP not in the spec page opened |
| A2A | explicitly does not share internal memory | no | opaque agents, no shared internal state | agent-to-agent tasks, not a chat app | no | not a team admin product | no | protocol plus CLI/SDKs |
| Claude Agent SDK | loads Claude Code memory files | same as Claude Code | not stated | subagents; not an inbox | no | permissions inside the SDK | not stated | runs the Claude Code binary in your process, or the CLI as a subprocess |
| OpenAI Agents SDK | sessions inside the agent loop | not git | sandbox is isolated workspace, not a private memory store | handoffs between agents | no | not on the page opened | tracing, not an admin audit log | SDK inside the application |
| Google ADK | context management described; dedicated memory product page not opened | no | Google Cloud deploy mentions enterprise security | multi-agent and graphs | no | "built-in authentication" on Google Cloud deploy | Cloud Trace on Google Cloud deploy, not described as an admin audit trail | local framework or container; also Google Cloud |
| AgentMail | stores email threads for the agent | no | not stated on the welcome page | email inboxes | no | not on the welcome page | not on the welcome page | API; not shown as a local subprocess |
| Resend Inboxes | email threads, not project memory | no | not stated | shared email inbox for people and agents | no | share with a team, assign threads | not stated on the announcement | API, CLI, or MCP; the inbox itself is Resend-hosted |
| ngrok | no | no | encrypted tunnels stated | no | yes, including localhost and local MCP | identity and access stated; SSO details not on the page opened | not on the page opened | local agent |
| Cloudflare Tunnel | no | no | post-quantum encrypted outbound tunnels | no | yes, public hostname to a local port | not on the tunnel overview | not on the tunnel overview | `cloudflared` daemon |
| Tailscale Funnel | no | no | encrypted tunnel; relay cannot decrypt | no | yes, public HTTPS to a local port | tailnet policy controls who may enable Funnel | not stated | Tailscale client already on the device |

### Inferences

- The practical late-2026 catalog is a set of adjacent categories, not one competitive set. A buyer comparing Mem0 with ngrok, or AgentMail with Tailscale, is comparing different jobs.
- "Persistent project context" in coding tools (Claude Code, Cursor) is mostly instructions in files. "Memory" in Mem0, Zep, Letta, and LangGraph is a runtime store the agent reads and writes. Those are different mechanisms even though both are marketed around remembering.
- Protocols (MCP, A2A) are not substitutes for the products. MCP standardizes tool and context access. A2A standardizes task exchange between agents that stay opaque. Neither page describes storage, tunnels, or an admin console.

### Gaps

- Legal entity names were not on most product pages. "Mem0," "Zep," and "AgentMail" are used here as the names on their sites, not as verified corporate registrations.
- Cursor staff posts and third-party writeups say Cursor removed an automatic Memories feature in version 2.1 (November 2025). Those pages were not opened. The opened Cursor Rules page does not mention Memories. Current Cursor behavior beyond Rules, User Rules, Team Rules, and `AGENTS.md` is unverified here.
- Mem0, Letta, LangGraph, Claude Code, and Cursor encryption-at-rest details were not on the pages opened.
- ngrok SSO, RBAC, SOC 2, and SIEM claims appeared in search snippets of ngrok marketing pages that were not opened. They are not treated as findings.
- No primary page was opened for Honcho, cognee, Supermemory, Basic Memory, Graphiti as a standalone product, Microsoft Dev Tunnels, or localhost.run. Graphiti is named only as the engine Zep's docs say Zep uses.

## What do memory and context products actually store, and which are cloud versus local?

### Takeaway

Mem0, Letta, and Zep are all shipping memory products in October 2026, with different shapes: extracted facts, a git repo of markdown, and a temporal context graph. Local-first options that were verified are Mem0's library/server, Letta's local-only git repo, Claude Code and Cursor instruction files, and AgentMemory's markdown directory. Git history of memory was verified for Letta and for instruction files the user commits, not for Mem0 or Zep.

### Cited Findings

- Mem0 Platform is fully managed. The open-source engine is the same engine "running on your own infrastructure," as a library or a Docker server. The intro page says platform data can stay off the caller's vector database; the OSS page says the caller owns the stack and the data. — [Mem0 introduction](https://docs.mem0.ai/introduction); [Open Source overview](https://docs.mem0.ai/open-source/overview)
- Mem0 Platform overview says memories persist "across users and agents" and that Mem0 "distills them into facts." It does not describe git commits or a file checkout. — [Platform overview](https://docs.mem0.ai/platform/overview)
- Letta memory is a git repository. Cloud agents use a repo hosted by Letta and projected locally. Local-only agents commit on the current machine and the user is responsible for backup. Root markdown files are loaded into the system prompt every turn. Subdirectories with their own `MEMORY.md` stay out of context until read. Dreaming and memory-doctor subagents use git worktrees. — [MemFS](https://docs.letta.com/concepts/memfs); [Memory & dreaming](https://docs.letta.com/configuration/memory)
- Zep stores a temporal Context Graph of facts, relationships, source episodes, and changes over time, served through a Context Lake. Retrieval returns selected context; "The application decides how to place that context in a model request." This is a Zep service (cloud, cloud with the customer's AWS KMS key, or bring-your-own-cloud in the customer's VPC). It is not described as a local library or a git repo. — [Concepts](https://help.getzep.com/concepts); [Security & Compliance](https://help.getzep.com/security-compliance)
- LangGraph short-term memory is checkpoints of graph state for one thread. Long-term memory is an application-defined store across threads. The documented production backing stores are databases the application connects to (Postgres is the primary example). `InMemorySaver` is in-process. Nothing on that page says git. — [LangGraph memory](https://docs.langchain.com/oss/python/langgraph/add-memory)
- Claude Code: user-written `CLAUDE.md` at managed, user, project, and local scopes, plus auto memory under the project. Project instructions are shared by committing them. `CLAUDE.local.md` is the personal, gitignored file. Auto memory is "Per repository, shared across worktrees" and is loaded only up to 200 lines or 25KB. Claude "treats them as context, not enforced configuration." — [Claude Code memory](https://code.claude.com/docs/en/memory)
- Cursor: rules are prompt context, not retained model memory. Project rules are git-versioned `.mdc` files. Team Rules are dashboard-managed and are not files in the repo. — [Cursor Rules](https://cursor.com/docs/rules)
- AgentMemory stores markdown on the machine (`MEMORY.md`, `SCRATCHPAD.md`, `daily/`, `topics/`). Search can use local qmd, but "basic read/write behavior works without it." The README does not say writes create git commits. — [agentmemory README](https://github.com/jayzeng/agentmemory)
- OpenAI Agents SDK sessions are "for maintaining working context within an agent loop." The page does not describe a shared project memory repository. — [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/)
- ADK's homepage says ADK "manages" context, including sessions, memory, tool outputs, and artifacts, and that it filters events and summarizes older turns. A dedicated memory-product page was not opened, so this is a framework behavior claim, not evidence of a standalone memory service. — [ADK](https://adk.dev/)

### Inferences

- "Git-backed agent memory" is verified for Letta MemFS. Claude Code and Cursor give git-backed *instructions* only if the team commits the files. Those instruction files are not described as an agent-owned memory database.
- Self-hosting is not the same as local-first. Mem0 OSS can be a library on one machine or a Docker server. Zep BYOC is still Zep deployed in the customer's VPC, not a userspace subprocess on a laptop.

### Gaps

- The Letta docs page `https://docs.letta.com/concepts/shared-memory` was linked but not opened, so the exact sharing model beyond the MemFS summary is unverified.
- Mem0's fact-extraction pipeline page was not opened. The platform overview's "distills them into facts" is the claim used here.
- Whether AgentMemory or Claude auto-memory directories are commonly committed to git is not stated.
- A git-native memory engine whose README says every write is a git commit (`agentage/memory-core`) showed up in search and was not opened. It is not included as a verified product.

## How do coordination and messaging products differ?

### Takeaway

MCP connects an agent to tools and context. A2A connects opaque agents to each other for tasks. Harness SDKs (Claude Agent SDK, OpenAI Agents SDK, LangGraph, ADK) coordinate agents inside one runtime. AgentMail and Resend Inboxes, both verified in October 2026, give agents real email addresses and threads. Letta adds team chat channels. These are different layers.

### Cited Findings

- MCP spec 2026-07-28: applications share contextual information, expose tools, and build composable workflows. Parties are hosts, clients, and servers. Server features are resources, prompts, and tools. Clients may offer elicitation. Optional extensions include asynchronous Tasks, Skills over MCP, and MCP Apps (inline UI). — [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28)
- A2A: "MCP is for agent-to-tool communication" and "A2A is for agent-to-agent communication." Agents can delegate sub-tasks "without needing to share internal memory, tools, or proprietary logic." A2A "does not specify how an agent talks to its own sub-agents." It is "Not an interactive messaging app." — [A2A Protocol](https://a2a-protocol.org/latest/)
- Claude Agent SDK subagents "Spawn specialized agents for focused subtasks." MCP is how that SDK connects external tools. The SDK is Python and TypeScript and runs the Claude Code binary; other languages use the CLI as a subprocess. Managed Agents are the hosted alternative. — [Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- OpenAI Agents SDK: "Agents as tools and handoffs, which allow agents to delegate to other agents for specific tasks," plus built-in MCP server tool calling. — [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/)
- LangGraph models multi-step and multi-agent work as a graph with checkpointed state. The memory page shows parent graphs and subgraphs sharing a checkpointer. It does not describe an inbox or a wire protocol between separately owned agents. — [LangGraph memory](https://docs.langchain.com/oss/python/langgraph/add-memory)
- ADK: "grow to multi-agent orchestration, graph-based workflows." The homepage does not say ADK implements A2A; that link was not opened. — [ADK](https://adk.dev/)
- AgentMail: each agent gets an inbox so it can "communicate via the universal protocol of email with services, people, and other agents." — [AgentMail welcome](https://www.agentmail.to/docs/welcome)
- Resend, 2026-10-22: inboxes on the customer's domain, threads available to "your app, your team, and your agents," assignment and notes, and a built-in agent whose allowed actions are configurable (`draft_reply`, `add_labels`, and others listed). External agents attach through MCP or skills. — [Announcing Inboxes](https://resend.com/blog/announcing-inboxes)
- Letta: "Communicate with agents through Slack, Discord, Telegram, or custom channels." That is Letta's channel list, not a claim that Letta provides email. — [Letta Agent](https://www.letta.com/agent)
- ngrok's docs list a use case to "Connect local MCP servers" so ChatGPT and Claude can reach tools on the machine. That is reachability for MCP servers, not an agent mailbox. — [What is ngrok?](https://ngrok.com/docs/about)

### Inferences

- "Agent-to-agent communication" in A2A and in the SDKs is task delegation inside or between agent runtimes. "Agent inbox" in AgentMail and Resend is ordinary email that people and agents can both open. A team can use both and they do not replace each other.
- A local MCP server is the verified pattern for "any harness that speaks MCP" (AgentMemory documents this explicitly). The harness SDKs are not harness-agnostic: Claude's SDK runs Claude Code, OpenAI's SDK runs inside the caller's app, ADK is its own framework.

### Gaps

- MCP transport details (stdio, Streamable HTTP, and auth schemes) are not in the specification overview page that was opened. Stdio is verified only for AgentMemory's server, which says it speaks MCP over stdin/stdout.
- AgentMail's API surface beyond the welcome page (IMAP, SMTP, webhooks, custom domains, pods) was not opened. The welcome page is the source for the product description and free-tier numbers.
- Whether Resend's MCP server is local or remote was not opened; the announcement only says agents connect through MCP or skills.
- No primary page was opened for CrewAI, Microsoft Agent Framework, Pydantic AI, or Mastra. They are not described here.
- Google's A2A-versus-ADK integration page was not opened, so ADK's A2A support is unverified.

## What do developers use so a remote agent can reach a port on a laptop or private network?

### Takeaway

The verified tools are ngrok Share Localhost, Cloudflare Tunnel via `cloudflared`, and Tailscale Funnel. All three put a public HTTPS name in front of a local port using an outbound agent. Tailscale also documents a private alternative, Tailscale Serve, that stays inside the tailnet. None of these pages is an agent-memory or agent-inbox product. ngrok additionally documents using the same tunnel so a remote assistant can call a local MCP server.

### Cited Findings

- ngrok Share Localhost exposes a service on `localhost` "even from behind a NAT or firewall," skipping port forwarding, DNS changes, and firewall rules. The agent creates encrypted tunnels. Listed alongside that: local webhook testing, and connecting local MCP servers to ChatGPT and Claude. Gateway also claims private connectivity "without public URLs, open ports, or VPNs," which is a different product surface from public localhost sharing. — [What is ngrok?](https://ngrok.com/docs/about)
- Cloudflare Tunnel for public apps uses `cloudflared` outbound, post-quantum encrypted, with no public origin IP. A public hostname is mapped to a local service such as `http://localhost:8080`. CDN, WAF, Bot Management, and DDoS protection are applied on Cloudflare's side. "Available on all plans." The Zero Trust docs use the same daemon for private networking and say public publishing lives in the other doc set. — [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/); [Cloudflare One Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
- Tailscale Funnel publishes one local service, file, or directory on a `ts.net` HTTPS name. The relay hides the device IP and, per the docs, does not decrypt the proxied bytes. Funnel is beta, off by default, requires Tailscale v1.38.3 or later, MagicDNS, HTTPS certificates, and a `funnel` node attribute. Listen ports are only 443, 8443, and 10000. On macOS, Funnel requires an open-source variant of the client. Serve is the tailnet-only counterpart. — [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)

### Inferences

- For a coding agent on another host that must call a laptop port, the verified choices are a public URL (ngrok, Cloudflare published hostname, or Funnel) or a private tailnet (Tailscale Serve, and ngrok's internal-endpoint claim). The pages do not rank them.
- Putting an agent tool on a public URL is an exposure decision. Tailscale's Funnel page warns that anyone with the URL can access it. ngrok's identity-and-access primitive and Cloudflare's separate Zero Trust doc are the documented places to add access control; those access-control procedures were not opened in full.

### Gaps

- Microsoft Dev Tunnels, localhost.run, Pinggy, and localtunnel were not opened.
- Pricing, custom-domain limits, and who can see request bodies were not opened for ngrok or Cloudflare. Tailscale's bandwidth limits are "non-configurable" on the Funnel page, but the numbers are not stated there.
- ngrok's claim that traffic is encrypted is the docs' phrase "encrypted tunnels." Certificate ownership and whether ngrok terminates TLS were not opened.

## Which agent platforms emphasize admin audit logs, SSO, and team controls?

### Takeaway

Zep's own governance and security pages are the clearest agent-context product for RBAC, enterprise SSO, per-agent ABAC, audit logs, and API logs. Mem0 states audit logs and workspace governance on the managed platform, and a request audit log on the self-hosted server, without an SSO page opened here. Cursor documents Team Rules for Team and Enterprise. ADK documents built-in authentication and Cloud Trace only when deployed on Google Cloud. Claude Code documents an org-managed instruction file, which is policy text, not an audit log.

### Cited Findings

- Zep governance separates human access from agent access. Dashboard teammates use RBAC "and, for how those teammates authenticate, enterprise SSO." Agents and Context MCP users use ABAC policies on API keys and UserGroups. Enterprise content policies are in beta and "audit what Zep repaired or dropped." Audit logging covers "member, API key, project, access-control, settings, and data-operation events." API logging covers SDK and API requests. Zep says its policies do not authorize actions in external systems. — [Governance](https://help.getzep.com/governance)
- Zep security: "SOC 2 Type II Certified," HIPAA BAAs for Enterprise, BYOK with the customer's AWS KMS CMK "including revocation," BYOM for OpenAI, Anthropic, Google, AWS Bedrock, or Azure, and deployment choices of managed cloud, cloud plus BYOK, or BYOC "inside your own VPC." The page points at governance for RBAC, ABAC, audit logs, and API logs. — [Security & Compliance](https://help.getzep.com/security-compliance)
- Mem0 Platform: "Enterprise-ready. Audit logs and workspace governance ship by default." The feature table repeats "Audit logs, workspace governance, and dedicated support." No SSO or encryption-key page was opened. — [Platform overview](https://docs.mem0.ai/platform/overview)
- Mem0 self-hosted server includes "per-user API keys, and a request audit log." That is an operator log on the caller's server, not a vendor admin console. — [Open Source overview](https://docs.mem0.ai/open-source/overview)
- Cursor Team Rules exist on Team and Enterprise plans, are managed in the dashboard, and can be enforced so members cannot disable them. The page says some teams use enforced rules for compliance workflows and that "AI guidance should not be your only security control." No audit-log page was opened. — [Cursor Rules](https://cursor.com/docs/rules)
- Claude Code managed `CLAUDE.md` is "Organization-wide instructions managed by IT/DevOps," deployed to a system path or via the `claudeMd` key in managed settings. The same page says settings, not `CLAUDE.md`, are how an org blocks tools. It does not describe an audit trail of agent actions. — [Claude Code memory](https://code.claude.com/docs/en/memory)
- ADK on Google Cloud: deploying via Agent Runtime, Cloud Run, or GKE gives "built-in authentication, Cloud Trace observability, and enterprise-grade security" without code changes. The page does not call Cloud Trace an admin audit log. Self-hosted ADK is a container the user runs. — [ADK](https://adk.dev/)
- Letta's product page addresses teams ("Stateful agents for your team") and shared work in Slack, Discord, and Telegram. The MemFS page says shared git-backed files are for multiple cloud-hosted agents. Neither page states SSO or an admin audit log. — [Letta Agent](https://www.letta.com/agent); [MemFS](https://docs.letta.com/concepts/memfs)
- Resend Inboxes: "Share an inbox with your team, assign conversations, leave notes." That is inbox collaboration, not an org-wide SSO or audit claim. — [Announcing Inboxes](https://resend.com/blog/announcing-inboxes)
- OpenAI Agents SDK documents tracing "for visualizing, debugging, and monitoring workflows." That is developer tracing, and the page does not describe org admin audit logs or SSO. — [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/)
- Tailscale Funnel is gated by tailnet policy: a `funnel` node attribute, and only Owners, Admins, or Network admins can edit that policy. That is access control for who may publish, not an audit log of agent actions. — [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)

### Inferences

- Among the memory products opened, Zep is the one whose docs put team SSO, agent-scoped authorization, and audit/API logs in one governance section. Mem0 asserts audit logs exist but the detailed event list was not opened.
- Coding-agent "admin" controls that were verified are instruction and rule distribution (Claude managed `CLAUDE.md`, Cursor enforced Team Rules), not immutable audit trails of what the agent did.

### Gaps

- Anthropic Console, Claude Enterprise, OpenAI organization audit logs, LangSmith, and Cursor admin audit logs were not opened. Absence from this note is not evidence those products lack audit logs.
- Mem0's audit-log event schema, retention, and whether logs are exportable were not opened.
- Letta enterprise SSO, if it exists, was not found on the pages opened.
- ngrok identity-and-access is named on the product overview; the IAM document itself was not opened.

## Where do the verified tools leave a combined gap?

### Takeaway

The pages support a gap of composition, not a gap inside any single job. Memory, git-shaped context, encrypted hosting, agent email, local port publishing, team auth, and admin audit are each offered by at least one verified product. No opened page describes one private system that is a local userspace subprocess, stores context as encrypted git, and also provides an inbox, port forwarding, and an admin audit trail.

### Cited Findings

- Local subprocess or text protocol beside a harness: AgentMemory's MCP server is a stdio process any MCP client can spawn, and memory "still never leaves your machine except as the direct result of a call you authorized" when a separate relay is used. The Claude Agent SDK runs a specific binary, Claude Code, in the caller's process, or the Claude CLI as a subprocess. OpenAI's SDK and LangGraph are libraries inside the application. ADK can run locally or as a container. Mem0 OSS is a library or a Docker server. None of those pages also describes a public tunnel or an email inbox. — [agentmemory README](https://github.com/jayzeng/agentmemory); [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview); [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/); [LangGraph memory](https://docs.langchain.com/oss/python/langgraph/add-memory); [ADK](https://adk.dev/); [Mem0 OSS](https://docs.mem0.ai/open-source/overview)
- Encrypted git-shaped storage: Letta is the verified git-shaped agent memory, including a local-only repo, and its MemFS page does not mention encryption of that repo, an audit log, email, or port forwarding. Zep is the verified product with customer-managed encryption (AWS KMS BYOK) and VPC deployment, and its security page describes a context graph service, not git. AgentMemory is local plaintext markdown with credential redaction, not described as encrypted or as git. — [MemFS](https://docs.letta.com/concepts/memfs); [Zep security](https://help.getzep.com/security-compliance); [agentmemory README](https://github.com/jayzeng/agentmemory)
- Inbox plus forwarding plus audit: AgentMail and Resend describe email inboxes for agents. Their opened pages do not describe git memory, local port forwarding, or admin audit trails. ngrok, Cloudflare Tunnel, and Tailscale Funnel describe local reachability and, for Tailscale and Cloudflare, encryption of the tunnel. Their opened pages do not describe agent memory or an inbox. Zep describes audit logs and does not describe an inbox or a tunnel. — [AgentMail](https://www.agentmail.to/docs/welcome); [Resend Inboxes](https://resend.com/blog/announcing-inboxes); [ngrok](https://ngrok.com/docs/about); [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/); [Tailscale Funnel](https://tailscale.com/kb/1223/funnel); [Zep governance](https://help.getzep.com/governance)
- A2A's own page limits the protocol: it is not a messaging app, not a memory store, and not a development kit. MCP's spec page limits that protocol to context and tools between hosts and servers, with consent left to implementors. — [A2A](https://a2a-protocol.org/latest/); [MCP](https://modelcontextprotocol.io/specification/2026-07-28)

### Inferences

- A developer who wants every job in the list today assembles at least three systems: a memory or instruction store, a tunnel if a remote caller must hit a laptop port, and a separate inbox if the agent must send and receive email. Audit and SSO, where required, are currently documented as features of the memory vendor (Zep, and Mem0's audit-log claim) or of the coding-tool admin (Cursor Team Rules), not of the tunnel or the inbox pages that were opened.
- Letta is the closest single product to "local plus git plus team channels," and Zep is the closest to "shared context plus encryption keys plus audit." Neither page set claims the other jobs. That is a boundary in the docs, not a claim that no vendor could add the missing pieces later.

### Gaps

- This note cannot say the combination is absent from the market. It can say the combination is not described on the primary pages opened for the products above. Products not opened might bundle more.
- "Real-time" sync of git memory, beyond Letta's commit-and-push model and LangGraph's synchronous checkpoint modes, was not specified on the pages opened. LangGraph's durability modes (`exit`, `async`, `sync`) were seen in search snippets of a durable-execution page that was not opened, so they are not cited as findings.
- Whether any tunnel vendor stores an admin-visible audit trail of each forwarded request was not opened.
