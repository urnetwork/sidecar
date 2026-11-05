# Where the used tools leave a gap

As of 31 October 2026, the tools with the best usage evidence overlap the seven sidecar jobs one or two at a time. No opened source shows one widely used product doing the set. The seven jobs are: real-time encrypted storage with a git front end, port forwarding for local services, a public TLS edge, email and group inbox, team auth, an admin audit trail, and a userspace subprocess any harness drives over a text protocol.

Survey shares below are not averaged. JetBrains asked about use at work. Stack Overflow asked about use in the past year.

## Harnesses

Two 2026 surveys both put Claude Code first and GitHub Copilot second, then OpenAI Codex and Cursor.

JetBrains, May–July 2026, professional developers, use at work: Claude Code about 39%, GitHub Copilot 21%, Codex 16%, Cursor 12%.

Stack Overflow’s past-year coding-agent table, n=12,255: Claude Code 65.5%, GitHub Copilot 58.7%, Codex 29.5%, Cursor 25.5%. Windsurf is 6.5% and Devin 2.9% on that table only.

Those shares measure agents, not memory files, tunnels, or inboxes. Claude Code loads `CLAUDE.md` and keeps auto memory locally. Copilot Memory became generally available on paid plans on 28 October 2026, after the JetBrains wave, and it is hosted facts, not a git front end. Cursor’s enterprise log records who changed a setting and omits prompts and agent output. None of the four does encrypted real-time git storage, port forwarding, a public TLS edge, and an inbox.

## Memory

Mem0 leads products whose job is memory: about 2.6 million PyPI downloads in 30 days, CI included. LangGraph’s roughly 56 million downloads in the same window are the whole framework, not memory use.

Letta MemFS is the only opened git filesystem for agent memory. The agent’s memory is a git repo of Markdown. The opened docs do not show encryption or real-time multi-writer sync, and there is no download or user count.

Nothing opened is real-time, encrypted, and git-fronted together.

## Reach

ngrok is the only tunnel with a large signup number: an undated vendor claim of 15.3 million developers. It does local forwarding and a public TLS edge. Team SSO and account audit logs are paid add-ons. Request history is 24 hours on the free plan and 72 hours on paid plans.

Microsoft dev tunnels are the port forwarder inside VS Code, private by default, still a public preview, with no user count. Limits on the opened page are 5 GB and 10 tunnels per user per month.

Cloudflare Tunnel and Tailscale Funnel have no feature-level user counts. Funnel was still marked beta on a page last validated 20 January 2026. Agent docs that name a tunnel name ngrok and Cloudflare.

None of these is a git store, an inbox, or a text protocol for any harness.

## Inbox, auth, and audit

Slack is the channel product docs actually attach an agent to. Claude’s Slack doc and Cursor’s enterprise log show the link. Neither gives an install count.

AgentMail is the agent-email product with a price list and named customer stories, all vendor claims. Free is 3 inboxes, 3,000 emails a month, and 100 a day. No product-wide usage total was opened. Resend Inboxes launched 22 October 2026, with no volume.

GitHub’s enterprise log is the clearest widely used record of agent actions, kept 180 days, with an agent session id. It excludes prompts a user sends to Copilot locally. Dust and Devin log agent actions more explicitly, and nothing opened shows they are as widely administered. Claude’s enterprise export keeps conversation identifiers and drops chat content.

## Protocol

MCP over stdio, spec 28 July 2026, is the text protocol Claude Code, VS Code Copilot, Cursor, ChatGPT, and Codex already speak. In the week of 23–29 October 2026, `@modelcontextprotocol/sdk` had 87.0 million npm downloads. That is installs, not people. No opened survey asks whether developers use MCP.

MCP does not store memory, forward a port, terminate public TLS for the user’s service, provide an inbox, or record an admin audit trail.

## The coverage gap

A team covering the seven jobs with the best-evidenced tools would still be on Claude Code or Copilot, ordinary git, ngrok or dev tunnels, Slack plus AgentMail if the channel is email, GitHub’s admin log, and MCP.

The jobs that stay split are the encrypted git store, the human-and-agent thread, and a record of what the agent actually did. Letta is the closer git match and has no usage figure. Mem0 is the download leader and is not git. AgentMail and Resend are the email match and have no market total. Devin and Dust have the clearer agent-action log and no people denominator.

The tools with the best overlap on a single job are the ones with the worst usage evidence. The tools with the best usage evidence each miss most of the seven jobs.

## What users report

User evidence is a person’s own words on a page that was opened: a GitHub issue, a forum thread, or a Hacker News comment. A vendor limit is labeled as a vendor limit. Reddit threads that looked relevant did not render, so they are not counted. One thread is one thread.

Users describe a saved rule, a saved note, an approval, a port, or a login that the product then drops. On the pages that opened, they do not ask for real-time encrypted storage, a new email inbox, team single sign-on, or a text protocol any harness can spawn.

### A committed rules file does not govern the run

This is the complaint on all four leading agents. The mechanisms differ.

Claude Code issue #6354 is still open, with 30 thumbs-up on the issue and eight people from August 2025 through September 2026. After compaction, `CLAUDE.md` is dropped or outranked. flux627, 22 August 2025: “I have to tell it to re-read this every time it compacts, otherwise it starts doing things in ‘common sense’ ways.” tatyree, 24 November 2025, 4 thumbs-up: “It just wiped out a running production project because it carried on making changes after compaction.” John-Rood, 27 September 2026: “The rules text surviving is mostly handled now. What still fails is rank.” The compacted summary “is the live frame, so anything re-injected reads as background and gets outranked.”

Cursor’s opened thread is three people and no vote count. Kinland, 31 October 2025: rules are followed in a new chat and forgotten “after a few messages, making rules more or less useless.” Staff the same week called it model non-determinism and told people to keep threads and rules short.

GitHub Copilot’s opened complaint is code review, not Copilot Memory. Discussion #187926 opened with 15 votes. Szer, 24 February 2026: “Custom instructions have no observable effect on Copilot Code Review on GitHub.com,” and the reviewer comments on “exactly what the instructions tell it not to do.” davideoliveri, 19 October 2026, 2 votes: “A few months in, the issue is still there.” A second thread is one person, 2 votes: an organization repo’s cloud agent never fetched `.github/copilot-instructions.md` while the same file loaded in VS Code and on a personal repo. No opened user post after Copilot Memory’s 28 October 2026 general availability judges that product.

Codex issue #13386 has 12 thumbs-up and was still discussed on 24 October 2026. guidedways, 3 March 2026: Codex “silently truncates `AGENTS.md` at `32 KB`” and “any instructions past that limit are dropped and never sent to the model — with no warning.” jdanbrown, 14 July 2026, said his 40 KB file was cut to 32 KB, “silently omitting 20% of my instructions.” An earlier “forgets after `/compact`” issue, 9 thumbs-up, was closed as stale on 25 December 2025. No later user on that thread confirmed a fix.

These users asked the loader to honor, or at least show, the file they already wrote. Nothing opened shows a chat correction becoming a teammate’s rule through the product’s own memory store.

### The next run cannot see what was stored

Each of these is one opened thread.

The reference MCP memory server, 12 thumbs-up on the opening post, four people: the JSON file did not stick because the path sat in the npx cache. Closed 12 March 2025.

Mem0: one user, 7 March 2025, said the next run forgot a name. A maintainer said short-term memory is a platform feature, and the issue was closed. A second user, 5 November 2025, lost history because the history database lived in the container. A third thread, two people, still open on 17 October 2026, is a lock on a local Qdrant folder the user never configured. That is a lock, not a request to share memory with a team.

Letta Code already stores one agent’s memory as git. tcwillis2-max, 2 June 2026: the previous agent had “6 memory files, 23 git commits,” and the new session had a default `persona.md` and “1 git commit.” Recovery “required manual file copying.”

Claude Code across machines, one person, 30 May 2026: “Memory written on device A is invisible on device B.” A desktop-app report, one person, 25 October 2026: memory “lands under the scratch path and is deleted together with the session,” and project `CLAUDE.md` files “are never loaded.”

One Hacker News item, 2 points, names the cross-tool version: “memory is locked to one tool on one machine. Switch from Claude Code to Cursor, or from your laptop to your desktop, and everything is gone.” A commenter on the same item switches between Claude Code, Gemini CLI, and OpenCode and says `CLAUDE.md` only works in Claude Code, on one machine. Nobody on these pages asked for a userspace subprocess or a text protocol.

Wrong notes treated as current are a Claude complaint. One essayist turned auto-memory off because the tool fetched “delusional or obsolete facts or conclusions that you fetch from notes I never sanctioned.” One claude-mem report, 19 May 2026, closed as not planned: the summarizer “fabricated a git commit hash that does not exist,” and a later session described features that “have never existed in the codebase.” No opened Mem0 or Letta issue asks for encryption, team sharing, or a reviewable diff of a wrong fact.

Two local-process reports are one thread each. A stdio child in the TypeScript SDK “exits almost immediately” and can take down the host process. In Cursor, custom stdio servers “all work” in editor chat and are “none available” in Projects, because the Project coordinator “always runs as a Cloud Agent” and cannot start servers that need the user’s machine. The reporter did not ask for port forwarding.

### Cursor is where the audit complaint repeats

Four people on one Cursor forum thread want the proposal, the human decision, and the command that ran. Ville Pispa, 30 March 2026: “None of these proposals or decisions are persisted in any queryable, exportable form.” An organization cannot answer “what did the AI agent do, and did a human authorize it?” He asked for that record in the Enterprise stream and in a local file beside the transcript. He did not ask for the chat text. Aleksey Safonov, 23 June 2026: without a shared action id it “may still be impossible to prove that the executed action was precisely the action the user approved.” znuttyone, 9 October 2026: “a request against my own machine can’t be traced to its source.”

A separate Cursor report, two people in late October 2026, says the change list omits files the agent wrote, including edits made from the terminal and edits in chats that used subagents. One admin, 6 May 2026, asked for employees’ prompt and response data. Staff called content an intentional privacy boundary and pointed at a per-machine hook.

GitHub’s opened comments do not match that theme and do not agree with each other. One person asked for an API to track Copilot prompts. Another asked whether admins can view prompts, and community replies said admins see usage and not content. The vendor page says the Copilot audit log omits local prompts, records agent activity on the GitHub website, and keeps 180 days. No opened Claude Code or Copilot post asks for an admin export of what the agent read or changed. Claude’s export omits chat title and content. That is a vendor limit, and no user complaint page about it loaded. Dust and Devin had no opened user discussion.

### Tunnel users ask for a session that lasts and a port that works

Cloudflare quick tunnels, one open issue, five people, 6 thumbs-up, October 2026. After a one-time PIN, “the authenticated session expires roughly 5 seconds,” and “the protected site cannot be used.” One of the five asked for a log of “only the authentication outcome without exposing sensitive request data.” They asked for a login that stays logged in. The vendor limit beside that bug is that quick-tunnel email authentication does not support non-interactive clients, the hostname changes each time the process starts, and tunnel audit logs record connector and DNS events, not the HTTP request.

Tailscale Funnel, five people across two still-open threads, want more than ports 443, 8443, and 10000, or at least an error when another port is accepted and then times out. Funnel is still documented as beta, public to anyone with the URL, and limited to those three ports. That port list is the vendor’s. The user sentence is the timeout and the missing error. A separate outage on 4 August 2026 had seven reporters: the public path was dead while `funnel status` still said on. Tailscale shipped a fix the same day.

ngrok’s opened 2026 user evidence is one report, 3 thumbs-up, closed as not planned. Free-plan HTTP hit an interstitial page unless the client sent `ngrok-skip-browser-warning`, and an agent iframe received that HTML instead of its assets. The interstitial, a 3-user cap on visitor OAuth, and 24-hour request history on the free plan are vendor limits. No opened user said a webhook body was missing from the inspector.

Dev tunnels have no opened user thread. The limits are the vendor’s: public preview, no SLA, a public port is anyone with the link, client tokens last 24 hours, and a tunnel created only by `host` is deleted when the connection closes.

### What users did not ask for

No opened user asked for encryption at rest, for Mem0 or Letta to be the store Codex or Cursor reads, or for a diff of a wrong Mem0 or Letta fact. No opened user, after 28 October 2026, judged Copilot Memory. No opened user asked for one record that holds a Slack or email thread and the agent’s tool log. Cursor’s three Slack reports are an install error, a private-DM limitation, and a lossy copy of a thread. AgentMail’s opened friction is a create-then-send race of one to two seconds, a request for more inboxes, and deliverability. Resend Inboxes, announced 22 October 2026, has no opened user report.

The coverage gap and the user gap are different sentences. The coverage gap is that no widely used product does the seven jobs together. The user gap is that the tools people already use drop the rules file, the memory note, the approval, or the login they already accepted.

---

## Addendum, 31 October 2026: which gaps are worth taking

The sections above separate two gaps:
- **The coverage gap:** no widely used product does all seven jobs.
- **The user gap:** the tools people already use drop what those users saved.

This addendum adds a third test: does a gap stay open, given how the companies that could close it make money? It then ranks the gaps by opportunity. Facts carry links; the rankings are inference.

The underlying notes are in `research_notes/Sidecar positioning and market gaps/`. The full argument is in `reports/Sidecar positioning and market gaps.md`, which also has a table of eight earlier conclusions it revises.

### Corrections to the sections above

**Claude's audit export.** The section above says it "keeps conversation identifiers and drops chat content." That is still true of the audit-log export. But Anthropic's Compliance API now returns Claude Code and Cowork session transcripts for Enterprise customers ([Compliance API FAQ](https://platform.claude.com/docs/en/manage-claude/compliance-faq)). It still misses:
- cloud sessions and scheduled routines;
- Claude Code used with an API key;
- Claude Code on Bedrock, Google Cloud, or Foundry;
- anything that never reaches Anthropic's API.

**Inboxes in the four harnesses.** The section above says none of the four leading harnesses offers an inbox. Agent-to-agent mail inside one vendor now exists:
- Claude Code shipped agent teams with mailboxes (February 2026) and cross-session messaging (August 2026) ([agent teams](https://code.claude.com/docs/en/agent-teams), [cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging)).
- Codex had agent mail by April 2026 and added an agent message board in September. The board appears in the CLI 0.165 changelog of 27 October.

There is still no email, no namespace that people share with agents, and nothing that works across vendors.

**Letta MemFS is no longer the only git filesystem for agent memory.**
- Cloudflare Artifacts, in private beta since 16 April 2026, is versioned storage that "speaks Git" to any git client ([Artifacts](https://blog.cloudflare.com/artifacts-git-for-agents-beta)).
- Entire stores agent sessions in git ([entireio/cli](https://github.com/entireio/cli)).
- Dolt now calls itself "the Database for Agents" ([DoltHub](https://www.dolthub.com/blog/2026-06-05-our-ai-policy/)).

None of them is end-to-end encrypted. Entire warns that transcripts pushed to a public repository can be read by anyone.

**"Nothing opened is real-time, encrypted, and git-fronted together" still holds after a wider search:**
- Keybase's encrypted git (2017) is encrypted and git, but not real-time ([Keybase](https://keybase.io/blog/encrypted-git-for-everyone)).
- Automerge's encrypted layer is real-time, but not git, and is still alpha.
- Radicle says its private repositories are "not encrypted at rest."

**Users did not ask for the sidecar's shape: that is now one issue per ask, not none.** Single issues have now asked for the subprocess transport, shared mailboxes, and relay-free operation:
- MCP Agent Mail users asked for "stdio transport" ([#41](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/41)) and for "project-addressed shared mailboxes" ([#263](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/263)).
- Happy users run their own server "to skip the cloud relay" ([HN](https://news.ycombinator.com/item?id=46991591)).

Encryption at rest is still not a user request.

### Gaps that closed or narrowed in 2026

**Coordination inside one harness.** The built-ins listed above now cover it. Copilot CLI added `/fleet` (1 April 2026) and Gemini CLI added subagents (April 2026) for parallel work, though neither documents messaging or locking ([GitHub](https://github.blog/2026/04/01/run-multiple-agents-at-once-with-fleet-in-copilot-cli/)).

**Git-shaped memory as a primitive.** Cloudflare Artifacts and Agent Memory now offer it, and so does Entire, which raised a $60 million seed on 10 February 2026. Star counts on 31 October 2026 show where developer attention went:

| Project | GitHub stars |
|---|---|
| claude-mem | 107.5k |
| Supermemory | 31.5k |
| Beads | 28.3k |
| MCP Agent Mail (both repos combined) | about 2.5k |

**Records that include content, for one vendor's agents.** Anthropic's Compliance API covers this, and so does GitHub's agent control plane, generally available since 26 February 2026 with `actor_is_agent` and agent session events ([GitHub changelog](https://github.blog/changelog/2026-02-26-enterprise-ai-controls-agent-control-plane-now-generally-available/)).

**Agent identity.** The basic layer is now free inside the big identity providers, and the specialists are being acquired:
- Entra Agent ID is available to all Entra customers.
- Okta added agent SSO to core SSO "at no additional cost" in August 2026.
- Microsoft's Agent 365, generally available since 1 May 2026, is licensed per human user. Microsoft's licensing FAQ says "Agents do not require their own licenses" ([Microsoft](https://www.microsoft.com/licensing/faqs/122)).
- Palo Alto Networks closed its roughly $25 billion CyberArk purchase on 11 February 2026.
- CrowdStrike, Cisco, SailPoint, Cyera, and Okta each bought, or agreed to buy, an agent- or machine-identity company in 2026.

**Private routes for cloud agents.** Every major vendor now documents one, and every route has a limit:
- Codex supports only Tailscale ([Tailscale](https://tailscale.com/blog/codex-cloud-tailscale)).
- Cursor supports Tailscale or Cloudflare Tunnel, with PrivateLink on Enterprise arranged through sales ([Cursor](https://cursor.com/docs/cloud-agent/private-connectivity)).
- Copilot needs self-hosted or Azure-private runners.
- Devin's VPN support excludes VPNs that require MFA ([Devin](https://docs.devin.ai/onboard-devin/vpn)).
- Anthropic-hosted Claude sessions document no VPN option.

**Gateways that log agent traffic.** Four vendors now sell this:
- Tailscale Aperture, generally available since 26 August 2026 ([Aperture GA](https://tailscale.com/blog/aperture-ga)).
- ngrok's MCP gateway ([ngrok](https://ngrok.com/docs/gateway/api-gateway/mcp-gateway)).
- NetFoundry's MCP and LLM gateways, launched June 2026 ([NetFoundry](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/)).
- Coder's AI Gateway and Agent Firewall, generally available since 3 February 2026.

**Parallel-agent managers are consolidating, not closing a gap.** They sit above the harness, not beside it.
- Vibe Kanban shut down its hosted service in April 2026. Its post says the team "couldn't find a business model that we could get excited about" and that "the vast majority are free users" ([Vibe Kanban](https://www.vibekanban.com/blog/shutdown)).
- Conductor raised $22 million and moved to cloud workspaces ([Conductor](https://www.conductor.build/blog/series-a)).

### Gaps that stay open because of how the closers make money

**1. Coordination across rival harnesses at runtime.** Model vendors and the forge earn when the work runs on their own agent and API.
- Anthropic's docs say "the workers are Claude sessions."
- Claude Code's Remote Control switches off behind a third-party LLM gateway, and on Bedrock, Google Cloud, or Foundry ([Remote Control](https://code.claude.com/docs/en/remote-control)).
- GitHub's neutrality means choosing which agent runs, on GitHub's runtime, bill, and audit.

**2. Content the operator cannot read, with a record the customer's admin can.** Every incumbent's audit depends on content the incumbent holds or inspects:
- Anthropic's transcripts and OpenAI's compliance logs;
- Cloudflare's MCP portal activity logs and data-loss scanning;
- Coder's prompt audit;
- Tailscale's Aperture, which says it logs "all of your agent's actions."

Anthropic already turns away organizations on zero data retention, HIPAA, or customer-managed keys.

**3. Audit of local actions at the source.** Each of the three agent vendors documents the hole:
- OpenAI says "Conversation visibility alone does not establish a complete record of local actions" ([OpenAI governance](https://learn.chatgpt.com/docs/enterprise/governance)).
- Anthropic's Compliance API does not capture on-device activity that never reaches the API.
- GitHub lists local session activity as future work.

**4. One address space for people and agents across organizations.**
- Microsoft offers this only inside Microsoft 365 tenants, through a preview program.
- Cloudflare offers the parts. Its open-source "Agentic Inbox" reference app also lowers the bar for everyone else ([Cloudflare](https://blog.cloudflare.com/email-for-agents/)).
- The harness vendors keep people in Slack, GitHub, or Teams.

**5. Reach and memory together for agents on developer machines, including reach into the laptop itself.**
- No vendor documents a cloud agent reaching a developer's own laptop or localhost.
- Cloudflare offers both reach and memory, but only for agents hosted on Workers.

### Ranked opportunities

The ranking follows the report. Each gap was scored on four tests together:
- how well the need is documented;
- whether incumbents' business models keep them out;
- how much of the gap URnetwork's assets already cover;
- whether anyone in the beachhead will pay.

| Rank | Gap | Strongest evidence | Why it stays open | URnetwork fit today | Verdict |
|---|---|---|---|---|---|
| 1 | A source-level record of what agents did through the sidecar, across harnesses, bound to the human who approved it | 68% of organizations cannot tell agent activity from human activity, and 43% run agents on shared service accounts (CSA/Aembit, March 2026, n=228) ([CSA](https://cloudsecurityalliance.org/articles/more-than-two-thirds-of-organizations-cannot-clearly-distinguish-ai-agent-from-human-actions)). The Cursor audit thread above asks for this exact object. NCCoE, the Five Eyes guidance, and OWASP MCP08 all describe it | Each vendor logs only its own runtime and API path | Low: no customer-facing audit product exists | Take it. This is the layer someone pays for. It sees only what crosses it and what the harness's hooks report, so say that |
| 2 | Shared context and records the operator cannot read | Anthropic excludes zero-retention, HIPAA, and customer-managed-key orgs. Entire warns its public transcripts are readable. Users route around central relays | Incumbents' compliance value rests on content they hold | Medium: URmessage is an early messenger built on MLS | Take it as the property that makes the record distinctive. No developer has asked for it, so it is not a headline |
| 3 | Coordination between rival harnesses and the people running them | A third of agent users run several agents and use them most. Two-thirds switched AI tools in a year ([Stack Overflow pulse](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)) | Model vendors earn when work stays on their runtime | Medium: recipes for 21 harnesses and an OAuth MCP server already exist | Take it as the reason developers install. On its own, nobody pays for it |
| 4 | Governed reach from cloud and local agents to private services | Every vendor built a route, and none reaches a laptop | Only partly open: Tailscale is neutral, strong, and already Codex's VPN | High: the operator relay, permanent client addresses, userspace WireGuard, and the gVisor netstack | Build it as a scoped grant that appears in the record, not as a tunnel product |
| 5 | One identity and inbox for people and agents across organizations | Microsoft offers agent mailboxes only in preview tenants. MCP Agent Mail users asked for shared mailboxes | Microsoft stays inside its tenant; the others prefer Slack and issues | Low: email is entirely new | Narrow it to the channel where a person approves or corrects a run. Ship it after the record and the store |

**Why that order is right, and what it costs.**
- **The paid gap leads.** Developer pull comes from gaps 3 and 2. If the product ships only what developers will install for free, it repeats Keybase, which gave encrypted git and teams away and ended as Zoom's acqui-hire in 2020, and Vibe Kanban, whose post says "the vast majority are free users." The day-one product therefore has to deliver the record and continuity together. That means one object that the next run reads and that the lead shows the client.
- **The order runs opposite to URnetwork's strengths.** Its production networking maps onto gap 4. Gap 1 rests on an audit product the company has not built, and on an encryption claim it has not had audited. Reach is still the enabling layer, because it is what lets the record and the store follow a run from a laptop into a cloud agent and back. It should be built well and sold as a line in the record.

**Two opportunities that are not gaps on their own.**
- **Defaults that break the lethal trifecta.** An inbox that agents read, next to a private store and a way to send data out, puts all three of Simon Willison's ingredients in one process ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). Each point tool sees only one leg. A product that holds the store, the inbox, and the routes is the only place that can stop one run from holding all three. The incidents show what is at stake:
  - Email has delivered zero-click prompt injection (EchoLeak).
  - The squatted `postmark-mcp` package silently BCC'd every outgoing message to an attacker ([Koi](https://koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)).
  - Knostic found 1,862 exposed MCP servers, and none of the 119 it checked by hand required authentication ([Knostic](https://www.knostic.ai/blog/mapping-mcp-servers-study)).
  
  Bundling the legs is the biggest security objection to this product. It is also the reason bundling can be safer than buying the legs separately. The defaults are in `improve.md`.
- **Agents that sign themselves up.** Ten percent of Stack Overflow 2026 respondents now work in an "organization of one." URnetwork already runs an OAuth MCP server and quotes x402 prices. That is cheap distribution for the free tier, not a market.

**Not worth chasing:**
- agent mail inside one vendor's harness;
- standalone memory;
- becoming an agent identity provider. Accept OIDC, Okta's Cross App Access, or SPIFFE identities from the customer's own provider instead;
- a standalone tunnel;
- a gateway that inspects content;
- evaluation, for the reasons in `market.md`.

### The first gap a buyer will find is URnetwork's own

The table ranks the market, but a security reviewer will rank the company first. On 31 October 2026, the reviewer would find the following.

**Trust artifacts are missing or stale.**
- The warrant canary, the transparency report, and the trust-and-safety policy all returned 404 at their public URLs.
- The latest transparency entry, even in the local copy, covers April to June 2024.

**URnetwork looks like proxyware.**
- In January 2026, Google took down the IPIDEA residential proxy network. Google said it found 550+ threat groups using IPIDEA's exit nodes within seven days, and told consumers to be "extremely wary" of apps that pay for unused bandwidth ([Google](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)).
- The FBI seized NetNut-linked domains on 2 July 2026 ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-residential-proxy-economy-systemic-risk-20/)).
- URnetwork matches the visible pattern:
  - paid bandwidth sharing;
  - an embeddable provider SDK that pays out to a wallet;
  - residential exits;
  - a published skill recipe for "many distinct egress IPs (distributed scraping)";
  - a homepage testimonial that reads "Passes Proxy/VPN detection."

**Member egress would break agents, not just the brand.** Okta and Entra flag or block anonymizing IP addresses, and a DISA STIG for Okta counts a missing anonymous-proxy block as a finding ([Okta](https://sec.okta.com/blockanonymizers), [STIG V-279692](https://www.stigviewer.com/stigs/okta_identity_as_a_service_idaas/2025-11-19/finding/V-279692)). If sidecar traffic left through members' devices, enterprise SaaS would flag the agents' sign-ins. The sidecar's routes must not use member egress.

**The claims run ahead of the evidence.**
- The homepage says "No logs stored," "Tor-like," and "100% open source."
- The public threat model says "There is no independent audit of the protocol, the connect engine, or the operator's server code." It also says the fail-closed toggle "still ships off in all five native apps" ([threat model](https://ur.io/docs/threat-model)).
- The agent docs say x402 is "not switched on," but the live endpoint returned a price list.

**The counterparty is unclear.** BringYour, Inc. operates the network, while a token-governed UR Foundation presents it as Bittensor subnet SN25 ([ur.xyz](https://ur.xyz/)). Procurement will ask who signs the contract, and whether fees flow into token incentives.

**There is no traction proof.**
- The skill repository has zero stars, and the only Show HN got 17 points.
- The company's own stats feed shows daily providers falling from about 105,000 in August to about 84,000 in October ([stats](https://api.bringyour.com/stats/last-90)).

None of this changes the market ranking. It decides whether the company can take what the ranking offers.

### Conclusion to the addendum

The coverage gap and the user gap both still stand. The opportunity gap is narrower: what the harness vendors, the network vendors, and the identity suites will not build, because it cuts against how they earn. That gap is a record that is neutral across harnesses, unreadable by the operator, complete for the team's admin, and kept at the source.

Everything else in the seven jobs is now a free built-in or a commodity. Offer those as parts of the record, not as products.

Close the company's own trust gap first. The security reviewer who pays for the record will check the company before the product.
