# Position the sidecar as the private record of agent work

As of 31 October 2026, the strongest position for URnetwork's agent sidecar is **the private record of agent work across harnesses**. That means one record, unreadable by the vendor, that every Claude Code, Codex, Cursor, or Copilot run writes to through one local process. Sessions and change sets stay under each developer's keys, and actions and approvals sit in a ledger under the team's. Together they show what each run changed, what it reached, who approved it, and what it left for the next run.

Each of the seven designed jobs is now either a free harness built-in or a commodity, so the bundle can be defended only when one object ties it together. Three things remain open because incumbents' business models push against them:
- coordination across rival vendors' agents;
- content the operator cannot read;
- a record of the actions taken on the machine. OpenAI, Anthropic, and GitHub each document that their own logs miss these.

The beachhead is engineering teams of roughly 5 to 150 people that run two or more harnesses and have to answer a client or auditor for what their agents did.

The binding constraint is URnetwork itself. The gaps worth owning sit where the company is weakest today. The reputation of its egress network will reach a security reviewer before the sidecar does.

The package that follows from this is one write with three readers. Each action is captured once and lands in two key domains: the developer's encrypted session vault holds the raw content, and the team's ledger holds the signed entry. Three readers use them:
- agents coordinate through the ledger;
- the developer and the next run continue from the vault and the ledger;
- the admin answers for what the ledger shows.

The vault is free for individuals. The team ledger arrives with the second person, because shared entries need team keys and team keys need an admin. Proof for outsiders is the top tier. The order of value comes from the newest research: developers' lost sessions and invisible edits affect far more people than clients' questions, and those questions harden only from December 2027.

**Sources and conventions.** This document is analysis. It builds on six research notes in `research_notes/Sidecar positioning and market gaps/` and on their synthesis, `reports/Sidecar positioning and market gaps.md` ("Sell the record, not the tunnel"), which holds the full argument and 155 sources. It also builds on, and corrects, the earlier research in `market.md`, `gap.md`, and `improve.md`. Each of those files now ends with a 31 October 2026 addendum that carries this same analysis, split by topic.

Sentences that state a fact carry a link. Sentences that recommend are inference. Survey figures come from studies run or sponsored by vendors.

## The competitive set moved during 2026

**Coordination became a harness feature.**
- Claude Code shipped agent teams on 5 February 2026, experimental and off by default. Agents get JSON mailboxes and a task list they claim under a file lock.
- Claude Code v2.1.224, on 7 August 2026, added messaging between sessions "on any of your machines". Messages that cross machines go through Anthropic's servers ([agent teams](https://code.claude.com/docs/en/agent-teams), [cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging)).
- Codex had agent mail by April. It added a shared agent message board in September, which appears in the CLI 0.165 changelog of 27 October ([Codex changelog](https://learn.chatgpt.com/docs/changelog), [PR #46985](https://github.com/openai/codex/pull/46985)).
- Copilot CLI added `/fleet` on 1 April 2026, and Gemini CLI added subagents in April, for parallel work. Neither documents messaging or locking ([GitHub](https://github.blog/2026/04/01/run-multiple-agents-at-once-with-fleet-in-copilot-cli/)).

On Claude Code's launch day, a Hacker News commenter named the pattern: "Agent teams in this release is mcp-agent-mail built into the runtime" ([HN](https://news.ycombinator.com/item?id=46902223)).

**Cloudflare assembled six of the seven jobs as cloud parts:**
- Artifacts, its "git for agents", in private beta since 16 April 2026;
- Agent Memory, in private beta;
- Email Service, with an `onEmail` hook that routes mail to agents;
- Tunnel and the Workers edge;
- Access;
- MCP server portals, generally available since 24 September 2026. These log "tool, prompt, and resource activity", where "prompt" means MCP prompt templates rather than users' prompts, and run data-loss scanning on it ([Artifacts](https://blog.cloudflare.com/artifacts-git-for-agents-beta), [Email for agents](https://blog.cloudflare.com/email-for-agents/)).

The parts serve agents built on Workers. None of them is a process that Claude Code or Codex starts, and the portals get their value from inspecting traffic.

**Teams that use a single vendor can now get a record that includes content.**
- Anthropic's Compliance API returns Claude Code and Cowork session transcripts for Enterprise customers ([Compliance API FAQ](https://platform.claude.com/docs/en/manage-claude/compliance-faq)).
- GitHub's agent control plane became generally available on 26 February 2026. It has an `actor_is_agent` flag and session events in the audit log ([GitHub changelog](https://github.blog/changelog/2026-02-26-enterprise-ai-controls-agent-control-plane-now-generally-available/)).

Both stop at the vendor's own runtime, and the vendors say so in writing:
- OpenAI writes that "Conversation visibility alone does not establish a complete record of local actions" ([OpenAI governance](https://learn.chatgpt.com/docs/enterprise/governance)).
- Anthropic's Compliance API does not capture on-device activity that never reaches the API.
- GitHub listed local VS Code and CLI session activity as future work.

**Each half of the earlier recommended line now has a funded owner.** The line was "Keep what the last run changed, and let the next one reach the machine."
- "Keep what the last run changed" is Entire's pitch. Thomas Dohmke's company raised a $60 million seed on 10 February 2026 to store agent sessions in git ([Entire](https://entire.com/news/former-github-ceo-thomas-dohmke-raises-60-million-seed-round)).
- "Let the next one reach the machine" belongs to Tailscale:
  - Codex cloud shipped with Tailscale as its only supported VPN, and Tailscale wrote: "Nobody told us."
  - Tailscale now calls itself "the missing network identity layer for AI agents".
  - Its Aperture gateway became generally available on 26 August 2026 ([Tailscale on Codex](https://tailscale.com/blog/codex-cloud-tailscale), [Aperture GA](https://tailscale.com/blog/aperture-ga)).

**Agent identity is now free inside the identity provider, and the specialists are being bought.**
- Entra Agent ID is available to all Entra customers.
- Okta added agent SSO to core SSO "at no additional cost" in August.
- Microsoft's Agent 365, generally available since 1 May 2026, is licensed per human user. Microsoft's licensing FAQ says "Agents do not require their own licenses" ([Microsoft](https://www.microsoft.com/licensing/faqs/122)).
- Palo Alto Networks closed its roughly $25 billion CyberArk purchase on 11 February 2026.
- CrowdStrike, Cisco, SailPoint, Cyera, and Okta each bought, or agreed to buy, an agent- or machine-identity company during 2026.

**Every major cloud-agent vendor now documents a private route, and each route has a limit:**
- Codex supports only Tailscale.
- Cursor supports Tailscale or Cloudflare Tunnel. PrivateLink is Enterprise-only and arranged through sales ([Cursor](https://cursor.com/docs/cloud-agent/private-connectivity)).
- Copilot needs self-hosted or Azure-private runners.
- Devin's VPN setup excludes VPNs that require MFA ([Devin](https://docs.devin.ai/onboard-devin/vpn)).
- Anthropic-hosted Claude sessions document no VPN option.
- No vendor documents a cloud agent reaching a developer's own laptop.

**Gateways that log agent traffic are a crowded field.**
- Tailscale Aperture.
- ngrok's MCP gateway ([ngrok](https://ngrok.com/docs/gateway/api-gateway/mcp-gateway)).
- NetFoundry's MCP and LLM gateways, launched in June 2026 ([NetFoundry](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/)).
- Coder's AI Gateway and Agent Firewall, generally available since 3 February 2026.

**Parallel-agent managers, which sit above the harness rather than beside it, are consolidating.**
- Vibe Kanban shut down its hosted service in April 2026. It said the team "couldn't find a business model that we could get excited about" and that "the vast majority are free users" ([Vibe Kanban](https://www.vibekanban.com/blog/shutdown)).
- Conductor raised $22 million and moved to cloud workspaces ([Conductor](https://www.conductor.build/blog/series-a)).

**Developer attention went to memory, not mail.** GitHub stars on 31 October 2026:

| Project | Stars |
|---|---|
| claude-mem | 107.5k |
| Supermemory | 31.5k |
| Beads | 28.3k |
| MCP Agent Mail (both repos combined) | about 2.5k |

### Corrections to the earlier research

**Claude's audit export.** `gap.md` says it "keeps conversation identifiers and drops chat content." That is still true of the audit-log export. But the Compliance API now returns transcripts. It still misses:
- cloud sessions and scheduled routines;
- Claude Code used with an API key;
- Claude Code on Bedrock, Google Cloud, or Foundry;
- anything that never reaches Anthropic's API.

**Inboxes in the leading harnesses.** `gap.md` says none of the four leading harnesses offers an inbox. Agent-to-agent mail inside one vendor's harness now exists, as described above. There is still no email, no namespace that people share with agents, and nothing that works across vendors.

**Git-shaped agent storage.** Letta MemFS is no longer the only git filesystem for agent memory. Others now exist:
- Cloudflare Artifacts "speaks Git" to any git client.
- Entire stores agent sessions in git ([entireio/cli](https://github.com/entireio/cli)).
- Dolt now calls itself "the Database for Agents" ([DoltHub](https://www.dolthub.com/blog/2026-06-05-our-ai-policy/)).

None of these is end-to-end encrypted. Entire warns that transcripts pushed to a public repository can be read by anyone.

**Real-time, encrypted, and git-fronted together.** The earlier finding that no opened product is all three still holds after a wider search:
- Keybase's encrypted git (2017) is encrypted and git, but not real-time ([Keybase](https://keybase.io/blog/encrypted-git-for-everyone)).
- Automerge's encrypted layer is real-time, but not git, and is still alpha.
- Radicle says its private repositories are "not encrypted at rest."

**User asks for the design's shape.** Single issues now ask for things the design includes:
- MCP Agent Mail users asked for "stdio transport" ([#41](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/41)) and for "project-addressed shared mailboxes" ([#263](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/263)).
- A Happy user runs a self-hosted server "to skip the cloud relay" ([HN](https://news.ycombinator.com/item?id=46991591)).

Encryption at rest is still not a user request.

## What a buyer would use instead

A team that runs agents today has four alternatives.

**Stay inside one vendor.** This could be Claude Code's agent teams, Remote Control, Claude Tag, and Compliance API. Or it could be GitHub's Agent HQ, Copilot Memory, and agent control plane.
- The buyer gets coordination, memory, and a record that includes content, for that vendor's agents.
- The cost is that the vendor holds the content, and everything stops at the vendor's edge.
- Remote Control switches off behind a third-party LLM gateway and on Bedrock, Google Cloud, and Foundry ([Remote Control](https://code.claude.com/docs/en/remote-control)).
- Organizations on zero data retention, HIPAA, or customer-managed keys are excluded from most of Anthropic's reach features.

**Stitch point tools together.** A typical stack:
- a committed `AGENTS.md` or `CLAUDE.md`;
- Entire or claude-mem for continuity;
- Tailscale or ngrok for reach;
- Slack or AgentMail for messages;
- the forge's audit log.

Every piece is good, but nothing joins them. The Slack user, the git author, the tunnel credential, and the memory key are four separate identities. No record says which agent did what, for whom, or who approved it.

**Build on a cloud platform.** Cloudflare's parts cover most of the jobs, but only for agents a team writes itself on Workers. They do not wrap the harnesses developers already run.

**Do nothing.** The team re-explains context every session, copies corrections by hand, and approves in whichever terminal someone happens to be sitting at. This is the world of the NANDA lawyer quoted in `market.md`. It is the default the other three alternatives compete against.

## What stays open, and why the incumbents leave it

The report's attribute table marks six designed attributes as commoditized or contested:
- agent mailboxes;
- git-backed memory;
- port forwarding and a public TLS edge;
- base agent identity;
- gateway audit;
- agent email.

None of them is worth selling alone. What remains open is what the companies that could close it are paid not to build.

**1. Coordination across rival harnesses at runtime.** Model vendors and the forge earn when the work runs on their own agent and API.
- Anthropic's docs say "the workers are Claude sessions."
- GitHub's neutrality means choosing which agent runs, but on GitHub's runtime, bill, and audit.

**2. Content the operator cannot read, with a record the customer's admin can.** Every incumbent's audit depends on content it holds or inspects:
- Anthropic's transcripts and OpenAI's compliance logs;
- Cloudflare's MCP portal activity logs and data-loss scanning;
- Coder's prompt audit;
- Tailscale's Aperture, which says it logs "all of your agent's actions."

The organizations that most want blindness are the ones Anthropic already turns away.

**3. A record of local actions at the source.** All three agent vendors document this hole in their own logs. OWASP's Q3 2026 roundup tells defenders to log what agents actually did: network, tool, and credential events by run ID, not the model's own account of them ([OWASP](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)).

**4. One address space for people and agents across organizations.**
- Microsoft offers this only inside Microsoft 365 tenants, through a preview program.
- Cloudflare offers the parts, and its open-source "Agentic Inbox" reference app lowers the bar for everyone else ([Cloudflare](https://blog.cloudflare.com/email-for-agents/)).
- The harness vendors keep people inside Slack, GitHub, or Teams.

**5. Reach and memory together for agents on developer machines, including reach into the laptop itself.** Cloudflare spans both, but only for agents hosted on Workers.

**The object that ties these together is the record.** Every action through the sidecar writes to one record held under the team's keys:
- a commit or merge;
- a forward opened;
- a name published;
- a message read or sent;
- a member added.

The next run, in any harness, opens that record, and the admin reads it. A store, a tunnel, and an inbox sold side by side are three commodities. The same three, each writing into one record the customer holds the keys to, is a product no incumbent sells.

**The principal is what makes the record attributable.** Each agent and each person is one principal. That principal is at once:
- the mail address;
- the signer of git commits;
- the owner of a hostname;
- the actor in the record.

In the design sketch these are `name@you.ur.network` and `hostname.you.ur.network`. A stitched stack cannot join its four identities after the fact.

The need is measurable. In a CSA survey sponsored by Aembit (March 2026, 228 respondents), 68% of organizations could not clearly distinguish agent activity from human activity, and 43% ran agents on shared service accounts ([CSA](https://cloudsecurityalliance.org/articles/more-than-two-thirds-of-organizations-cannot-clearly-distinguish-ai-agent-from-human-actions)).

## Gaps ranked by opportunity

The ranking follows the report. It scores each gap on four tests together:
- how well the need is documented;
- whether incumbents' business models keep them out;
- how much of the gap URnetwork's assets already cover;
- whether anyone in the beachhead will pay.

| Rank | Gap | Strongest evidence | Why it stays open | URnetwork fit today | Verdict |
|---|---|---|---|---|---|
| 1 | A source-level record of what agents did through the sidecar, across harnesses, tied to the human who approved it | 68% cannot tell agent activity from human, and 43% run agents on shared service accounts (CSA/Aembit). Cursor users ask for this exact object ([Cursor forum](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247)). NCCoE, the Five Eyes guidance, and OWASP MCP08 all describe it | Each vendor logs only its own runtime and API path | Low: no customer-facing audit product exists | Take it. This is the layer someone pays for. It sees only what crosses it plus what harness hooks report, and the pitch should say so |
| 2 | Shared context and records the operator cannot read | Anthropic excludes orgs on zero data retention, HIPAA, or customer-managed keys. Entire warns its public transcripts are readable. Users route around central relays | Incumbents' compliance value rests on content they hold | Medium: URmessage is an early MLS messenger | Take it as the property that makes the record distinctive. No developer asked for it, so it is not a headline |
| 3 | Coordination between rival harnesses and the people running them | A third of agent users run several agents and use them the most. Two-thirds switched AI tools in a year ([Stack Overflow pulse](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)) | Model vendors earn when work stays on their runtime | Medium: recipes for 21 harnesses and an OAuth MCP server | Take it as the reason developers install. Nobody pays for it alone |
| 4 | Governed reach from cloud and local agents to private services | Every vendor built a route; none reaches a laptop | Only partly open: Tailscale is neutral, strong, and already Codex's VPN | High: operator relay, permanent client addresses, userspace WireGuard, gVisor netstack | Build it as a scoped grant shown in the record, not as a tunnel product |
| 5 | One identity and inbox for people and agents across organizations | Microsoft has agent mailboxes only in preview tenants. MCP Agent Mail users asked for shared mailboxes | Microsoft stays in its tenant; the others prefer Slack and issues | Low: email is entirely new | Narrow it to the channel where a person approves or corrects a run. Ship it after the record and the store |

**Why the paid gap leads.** Developer pull comes from gaps 3 and 2. A product that ships only what developers will install for free repeats two failures:
- Keybase gave away encrypted git and teams, and ended as Zoom's acquisition in 2020.
- Vibe Kanban's users were overwhelmingly on the free tier.

The day-one product therefore has to deliver the record and continuity together. The newest research sharpens this: the developer's session vault and change set are why the product gets installed, and the signed approval ledger is why a lead pays (see the package below).

**The order runs opposite to URnetwork's strengths.** Its production networking maps onto gap 4. Gap 1 rests on an audit product the company has not built, and on an encryption claim it has not had audited. Reach is still the enabling layer, because it lets the record and the store follow a run from a laptop into a cloud agent and back. It should be built well and sold as a line in the record.

**Two opportunities that are not gaps on their own.**
- **Defaults that break the lethal trifecta.** An inbox that agents read, next to a private store and a way to send data out, puts all three of Simon Willison's ingredients in one process ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). Each point tool sees only one leg. A product that holds the store, the inbox, and the routes is the one place that can stop a run from holding all three. The risk is real:
  - Email has delivered zero-click prompt injection (EchoLeak).
  - The squatted `postmark-mcp` package silently BCC'd every outgoing message to an attacker ([Koi](https://koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)).
  - Knostic found 1,862 exposed MCP servers, and none of the 119 it checked by hand required authentication ([Knostic](https://www.knostic.ai/blog/mapping-mcp-servers-study)).
  
  Bundling the legs is the biggest security objection to the product. It is also why bundling can be safer than buying the legs separately.
- **Agents that sign themselves up.** Ten percent of Stack Overflow 2026 respondents now work in an "organization of one". URnetwork already runs an OAuth MCP server and quotes x402 prices. This is cheap distribution for the free tier, not a market.

**Not worth chasing:**
- agent mail inside one vendor's harness;
- standalone memory;
- becoming an agent identity provider. Accept OIDC, Okta's Cross App Access, or SPIFFE identities from the customer's own provider instead;
- a standalone tunnel;
- a gateway that inspects content;
- evaluation, for the reasons in `market.md`.

## The frame: the private record of agent work

Most of the available categories lose:
- **Memory** faces Copilot Memory, Claude's auto memory, Mem0, and claude-mem.
- **Agent mail** faces free mailboxes built into the harnesses.
- **Tunnel** faces ngrok and Tailscale, with a residential-proxy company's name attached.
- **Gateway** faces vendors whose model is inspection.
- **Agent identity** faces identity providers that give the base layer away.

"Sidecar" is the right architecture word and the wrong product name. Microsoft's Entra Agent ID docs already describe an "Auth SDK (sidecar)" for agent authentication ([Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id)).

**The frame with room is the agent-work record.** Investors and standards writers have validated this emerging category:
- Entire raised $60 million to keep agent sessions in git.
- git-ai links every AI-written line to its agent, model, and prompt.
- The Agent Trace spec sits in the "Assess" ring of Thoughtworks' Technology Radar.
- Turso's AgentFS keeps an append-only tool-call log.

None of them encrypts the record, and the category is consolidating into harness owners and forges:
- git-ai's team joined OpenAI's Codex on 11 September 2026;
- Agent Trace has stalled at v0.1.0, and its repository is gone;
- Entire removed restore when it launched its forge on 26 October 2026.

That strengthens the case for a neutral record. URnetwork's version differs on three counts:
- it keeps sessions and change sets under each developer's keys, and actions and approvals under the team's, rather than code lines in git notes or transcripts in the repository;
- it covers reach and messages as well as storage;
- its vendor cannot read it.

The sidecar would be the private member of a category that already has momentum, not the founder of a new one it would have to explain. That is the cheaper position to hold. It is not an evaluation product: it can hold a failed check or a person's "no" for the next run, but it does not grade the run.

**A second frame was considered and placed second: "accounts for agents."** That means what a company gives a new teammate on day one: an address, a mailbox, access to the shared repo, a way onto the network, and an admin who can see what they did. Microsoft's mailbox-holding agents prove the idea inside Microsoft 365. It ranks second for three reasons:
- "Account" reads as identity, which is now free.
- It puts the inbox first, and the inbox is the riskiest, lowest-ranked job.
- No developer asks for accounts.

The account survives as the mechanism, the principal described above, not as the category.

**One earlier caution needs revising.** `market.md` found no buyer saying agents need "an inbox of their own, or a colleague identity", and it advised against such lines. That still holds for the economic buyers in the NANDA interviews. It no longer holds for the security buyer. These terms recur across NIST's NCCoE, OWASP, the Five Eyes guidance, Microsoft, and Okta:
- "non-human identity";
- "sponsor";
- "registry of authorized agents";
- "immutable audit trail";
- "kill switch".

The homepage and the admin page therefore have different readers and need different words.

## Who to win first

**The beachhead** is engineering teams of roughly 5 to 150 people that run two or more harnesses and have to answer a client or an auditor for what their agents did. Typical examples are B2B software companies, fintech, and consultancies.

Three conditions meet in this group:
- a developer can install a subprocess without asking anyone;
- a team lead can pay without a procurement department;
- an outside party creates the reason to keep a record.

**The trigger is narrower than the first questionnaire.** Today's questionnaires and auditors ask which AI a team uses and whether a human reviews it, not what the agents touched ([Vanta](https://www.vanta.com/resources/introducing-vantas-ai-security-assessment)). Proof is already demanded in five situations:
- a Microsoft supplier completing Section K of DPR v12, whose requirement 33 asks for change logs naming the approver, kept 90 days ([Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf));
- a consultancy, agency, or legal-services team bound by client AI-disclosure terms;
- a team that wants to remove human approval from low-risk changes and needs evidence an auditor will accept;
- a fintech or health vendor whose agents act with admin access on in-scope systems;
- a team that ships agents and faces AIUC-1-style questions.

"What did the agents touch" hardens from December 2027, with the AICPA's draft SOC 2 criteria, the EU AI Act's high-risk logging, and most Cyber Resilience Act duties.

**Why this group fits.**
- They already tolerate tunnel and VPN vendors, so URnetwork's reputational exposure here is moderate rather than fatal.
- The record's two benefits meet in one person: the lead who wants the next run to start from the last one is also the person who answers the client's question.
- The size band is an inference. It matches the 2-to-150-seat range Claude sells as its Team plan, and it sits below the enterprises that buy through incumbents.

**The evidence for multi-harness use.**
- In Stack Overflow's pulse survey published 27 May 2026, 17% of agent users ran multiple specialized agents and 16% ran coordinated ones. Those users worked with agents daily at 85% and 77%, against 54% of single-agent users ([Stack Overflow pulse](https://stackoverflow.blog/2026/05/27/agents-on-a-leash-agentic-ai-remains-mostly-monitored-at-work)).
- In the same pulse survey, fintech (55% daily use) and media and advertising (50%) led the industries.
- Only 33.7% of Stack Overflow 2026 respondents had not switched AI tools in the past year ([Stack Overflow survey](https://survey.stackoverflow.co/2026/ai)).
- Buying starts from the bottom up. Menlo counted product-led buying at 27% of AI application spend, possibly about 40% including shadow use ([Menlo](https://menlovc.com/perspective/2025-the-state-of-generative-ai-in-the-enterprise/)).

**The other segments, in order.**
1. **Solo developers** are the free funnel, not revenue.
2. **Security and IAM teams at larger firms** come second, but only once a published audit, SOC 2, and a cleaned-up agent surface exist.
3. **Regulated organizations that Anthropic excludes** (zero data retention, HIPAA, customer-managed keys) are the largest prize for operator blindness, and the least forgiving of URnetwork's history. They come last.

**Not targets.** Enterprises standardized on GitHub Enterprise or Microsoft E5/E7, and builders of agent platforms, are the incumbents' and Cloudflare's to lose.

## Positioning statement and message order

**Statement.** For engineering teams that run more than one coding agent and have to answer for what those agents did, [product] is the private record of agent work. Every harness writes to it through one local process. The next run in any harness starts from it. Only the team and its developers hold the keys: sessions stay with their author, and actions and approvals belong to the team.
- Unlike the logs inside Claude, Codex, Copilot, or Cursor, it covers every harness and the actions that never reach a vendor's API.
- Unlike gateways from Tailscale, Coder, or Cloudflare, it keeps the record without the vendor being able to read it.

**Headline: "The private record of agent work."** The subhead lists what goes in and who holds it: every Claude Code, Codex, Cursor, and Copilot run writes to one record that you and your team hold the keys to. It shows what each run changed, what it reached, who approved it, and what it left for the next run. We can't read it.

**The privacy line under it: "Private from us. Actions and approvals complete for your admins. Sessions stay with their author unless shared."** The shorter "private from us, complete for your admins" covered the vendor boundary and missed the one inside the team. Under §87(1) No. 6 of Germany's Works Constitution Act, a record the employer can read is monitoring-capable and likely needs a works-council agreement ([Covington](https://www.cov.com/-/media/files/corporate/publications/2026/07/works-council-rights-in-ai-implementation-projects.pdf)), and developers object to colleagues reading raw sessions. The longer line reconciles URnetwork's privacy brand with what security reviewers want. Two kinds of competitor cannot copy it without undercutting how they make money: model vendors, which hold transcripts, and gateway vendors, which inspect traffic.

**Developer line: "Never lose an agent session or an edit, whichever harness made it."** Review, rewind, and lost history involve more people than handoff: about 280 and about 200, against 139. Continuity comes second: "The next run starts from what the last one did, whichever harness runs it." That is the earlier "keep what the last run changed" in narrower form. "Whichever harness" is what separates it from Copilot Memory and Claude's auto memory. The reach half becomes a benefit inside the record: "the route that worked, granted to the next run, with the approval on file."

**Security line, on the page a reviewer reads: "Know which agent did what, in any harness, and who allowed it, without handing the record to another vendor."** Use their words: agent identity, sponsor, delegation, tamper-evident audit trail, registry, kill switch.

**Where these lines fail.**
- **Developers may hear "record" as surveillance.** The developer page has to lead with continuity, and the record has to be useful to the next run before it is useful to the admin. If the admin is its only reader, developers will route around it.
- **Buyers may mistake it for Entire.** The subhead carries the difference: actions and approvals rather than transcripts; reach and messages, not just storage; a vendor that cannot read it.
- **The lines fail with any security reviewer whose first search result is the consumer network's pages.** See the URnetwork section below.
- **"Private from us" fails the first time the product ships something the vendor can read without saying so,** such as a terminating TLS edge or server-side search.

### What the positioning needs before it is said in public

**A demo that starts with the developer's bad day:**
1. Claude Code, in auto mode, edits through Bash. No harness checkpoint sees it, but the record shows every file and can restore it.
2. Codex, in another terminal or in the cloud, starts from the handoff note and calls the same local service through a scoped grant.
3. A database migration waits for an approval, which the lead signs with an SSH key from a phone.
4. The lead sends the client a packet that proves the approval without the code.
5. A packet capture shows that URnetwork's servers saw only ciphertext.
6. The developer can see that the admin opened only the approval entries.

The demo does not need email. The approval can travel through the team's own encrypted messages first (see the sequencing below).

**Four artifacts:**
- an open-source client;
- a sidecar threat model that lists what the servers can see;
- an independent audit before any encryption claim;
- a separation from the consumer egress network that a security reviewer can verify.

## What not to say

| Drop this | Why | Say this instead |
|---|---|---|
| "Zero-knowledge" | A USENIX Security 2026 paper titled "Zero Knowledge (About) Encryption" attacked that claim in three password managers. A CCS 2024 paper found severe flaws in four of five end-to-end-encrypted cloud-storage services when the server is malicious ([USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata), [ePrint 2024/1616](https://eprint.iacr.org/2024/1616)) | "We cannot read your store or your record. Here is the metadata we can see." |
| "End-to-end encrypted," unscoped | The model provider sees whatever the harness sends. A terminating TLS edge sees that traffic. Inbound mail arrives as plaintext SMTP | "Encrypted on members' devices under keys your team holds." Then list what is outside that boundary |
| "Private audit trail" | It reads to a CISO as unauditable | "Private from us. Actions and approvals complete for your admins. Sessions stay with their author unless shared." |
| "Tamper-evident" as the differentiator | Open-source signed logs, dozens of IETF receipt drafts, and Anthropic's signed transparency log already exist ([Obsigna](https://github.com/agent-receipts/obsigna)) | Customer-held keys, capture from outside any one harness, approvals signed by humans, and selective disclosure |
| "Records everything your agents do" | The sidecar sees only what crosses it and what hooks report | "Records every action through the sidecar, and every harness event you connect, bound to the person who approved it" |
| "Works with any harness" | Cursor's Projects coordinator "always runs as a Cloud Agent" and cannot launch a local process | "Works in any harness that runs a local MCP server, and in cloud-agent environments that install it" |
| "Easy" public exposure of local services | Exposed MCP servers and OpenClaw gateways | "Private by default; public when you publish, and every publish is on the record" |
| Sidecar, agent mail, memory, tunnel, or identity layer as the category | Each word now belongs to someone else | "The private record of agent work" |

Keep the consumer network's lines away from anything this buyer reads: "No logs stored," "Tor-like," "100% open source," and the agent skill's "distributed scraping."
- URnetwork's own public threat model describes retention windows and lists no defenses against traffic analysis. That sits badly with the first two.
- "Distributed scraping" is the pattern proxyware enforcement now targets.

Also keep the stock lines `market.md` already rules out: "get more value from AI," "10x," "AI workforce," and replacement of headcount.

## The first gap a buyer will find is URnetwork's own

The table above ranks the market. A security reviewer will rank the company first. On 31 October 2026, that reviewer finds the following.

**Missing or stale trust artifacts.** The warrant canary, transparency report, and trust-and-safety policy returned 404 at their public URLs. The last transparency entry, even in the local copy, covers April to June 2024.

**A visible match to proxyware.**
- Google took down the IPIDEA residential proxy network in January 2026. It said it found 550+ threat groups using IPIDEA's exit nodes within seven days, and told consumers to be "extremely wary" of apps that pay for unused bandwidth ([Google](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)).
- The FBI seized NetNut-linked domains on 2 July 2026 ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-residential-proxy-economy-systemic-risk-20/)).
- URnetwork matches the visible pattern on five counts:
  - paid bandwidth sharing;
  - an embeddable provider SDK that pays out to a wallet;
  - residential exits;
  - a published skill recipe for "many distinct egress IPs (distributed scraping)";
  - a homepage testimonial reading "Passes Proxy/VPN detection."

**A functional problem, not only a reputational one.** Okta and Entra flag or block anonymizing IP addresses, and a DISA STIG for Okta counts a missing anonymous-proxy block as a finding ([Okta](https://sec.okta.com/blockanonymizers), [STIG V-279692](https://www.stigviewer.com/stigs/okta_identity_as_a_service_idaas/2025-11-19/finding/V-279692)). If sidecar traffic left through members' devices, enterprise SaaS would flag the agents' sign-ins. The sidecar uses the network for encrypted reach between its own endpoints; its routes to the internet must not use member egress.

**Claims ahead of evidence.**
- The homepage says "No logs stored," "Tor-like," and "100% open source."
- The public threat model says "There is no independent audit of the protocol, the connect engine, or the operator's server code," and that the fail-closed toggle "still ships off in all five native apps" ([threat model](https://ur.io/docs/threat-model)).
- The agent docs say x402 is "not switched on," while the live endpoint returned a price list.

**An unclear counterparty.** BringYour, Inc. operates the network. A token-governed UR Foundation presents the network as Bittensor subnet SN25 ([ur.xyz](https://ur.xyz/)). Procurement will ask who signs the contract, and whether fees flow into token incentives. The sidecar itself is not tokenized.

**No traction proof.**
- The skill repository has zero stars, and the only Show HN got 17 points.
- The company's own stats feed shows daily providers falling from about 105,000 in August to about 84,000 in October ([stats](https://api.bringyour.com/stats/last-90)).

**What does and doesn't transfer to the sidecar.**
- **Transfers:**
  - the OAuth MCP server, already on the stateless 2026-07-28 spec;
  - recipes for 21 harnesses;
  - account and API-key plumbing;
  - URmessage, an MLS (RFC 9420) messenger whose server stores what it cannot decrypt, though it is in early development.
- **Does not transfer: the VPN's privacy argument.** The split-knowledge design protects egress. But live routing goes through an operator hop, and the sidecar's storage, inbox, forwarding, and audit would all be operator-hosted. The sidecar's privacy has to rest on keys customers hold, not on network topology.

None of this changes the market ranking. It decides whether the company can take what the ranking offers.

## Moves that make the positioning true

`improve.md` was right that the run record is the thing to sell. The research promotes it to the headline. It also changes three things about the record:
- whose identity sits at its center;
- who must be unable to read it;
- which defaults make it safe to put an inbox, a repo, and a route in one process.

### Put one principal at the center of every entry

Every agent instance and every person is a principal with a sponsor: the human or team the agent acts for. The same principal is:
- the mail address;
- the signer of git commits;
- the owner of a TLS name;
- the actor in the record.

**Share links are bearer capabilities.** The count-limited share links in the design sketch work for anyone who holds them.
- Each redemption should bind to a device or agent key and enter the team through a signed membership change.
- Removing a member should start a new key epoch, which MLS supports. The docs should concede that a removed member keeps whatever they already read.
- Key recovery should be a disclosed choice, made per member.

**Consume identity; don't issue it.** "Easy auth" should mean:
- OIDC and SAML sign-in, plus SCIM;
- Okta's Cross App Access (now the Enterprise-Managed Authorization extension for MCP);
- SPIFFE where it exists.

Agents should run on short-lived per-run tokens instead of the long-lived `urn_` keys URnetwork issues today. They should be registered under a sponsor where admins already look, and be reachable by a kill switch in Agent 365 or Okta.

Microsoft says its discovery of local CLI agents is only "expanding soon." A process the harness starts is the natural place to attach a sponsor to an agent that would otherwise be invisible. It also has to be discoverable and killable by enterprise controls, or it will be blocked as shadow infrastructure.

### Write the record the frameworks describe

Every action that crosses the sidecar should emit one signed, hash-chained entry:
- a store write or merge;
- a forward opened or closed;
- a name published;
- a message read or sent;
- a member or key added or removed.

Each entry should carry:
- the actor: agent and sponsor, harness and version, device;
- a reference to the credential used, never its value;
- the action and target, such as a commit hash, a port with its hostname and exposure, or every mail recipient including BCC;
- the policy decision and the identity of whoever approved it;
- the provenance of the triggering input, as a hash plus a pointer into the encrypted store;
- writes to memory, agent configuration, and MCP tool definitions, recorded by hash;
- a run ID and the outcome.

**One action, one ID.** The sidecar should ingest harness hooks and telemetry, and mint the shared action ID Cursor users asked for. A proposal, the person's approval, and the command that ran then become one entry.

**Retention and export.**
- The team record keeps at least 12 months, with 90 days immediately searchable. That covers PCI DSS 10.5.1 and Microsoft's requirement 33, and exceeds the AI Act's six-month floor. Each developer's vault follows a policy its owner sets, and archives instead of deleting.
- Exports should go to the SIEMs that Entra, Okta, Splunk, and CrowdStrike customers already run.
- Every read of the record should itself be recorded.

**No secrets and no plaintext content.** Keeping content out means the record is never a second, weaker copy of the private data, and erasing content does not break the hash chain.

No standard supplies this schema yet. It combines four sources:
- OWASP's MCP08 call for "immutable audit trails";
- OWASP's Q3 2026 advice to log actual actions by run ID;
- NCCoE's questions on delegation and non-repudiation ([NCCoE](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf));
- the EU AI Act's six months of logs "under their control" for high-risk deployers. The Digital Omnibus moved that obligation to 2 December 2027 ([Lewis Silkin](https://www.lewissilkin.com/insights/2026/07/27/the-digital-omnibus-on-ai-enters-into-force-today)).

Mail recipients matter in particular. The hidden BCC that `postmark-mcp` added was invisible to mail gateways, and it would be obvious in a per-send record.

### Say out loud who can read what

"Private" should mean three things: private from URnetwork, complete for the team's admins on actions and approvals, and private to each developer for raw sessions. Use two key domains:
- **The developer's domain** holds raw transcripts, prompts, replies, and files read, under that developer's keys. The developer discloses them one run or one subset at a time.
- **The team's domain** holds actions, approvals, change-set hashes, the inventory, cost, and coverage. Admins can read it. Its pointers to content resolve only when the developer discloses that content.

Every admin read becomes an entry the developer can see. For teams that must retain content, pick the patterns credible encrypted products use, and name them:
- **By default:** a metadata-only record that the clients sign, so the server cannot forge it.
- **For content access:** either a visible audit member every participant can see, or disclosed key escrow with a private-member option.
  - Element's AuditBot "is visible to your users" and "cannot be hidden."
  - Proton for Business escrows keys under an organization key, with a per-member "private" setting ([Element](https://ems-docs.element.io/books/element-cloud-documentation/page/audit-bot), [Proton](https://proton.me/support/private-users)).
- **Never:** a silent plaintext archive. TeleMessage sold end-to-end encryption "through to the corporate archive," shipped plaintext to its own archive, and was breached in May 2025 ([Micah Lee](https://micahflee.com/despite-misleading-marketing-israeli-company-telemessage-used-by-trump-officials-can-access-plaintext-chat-logs/)).

Then scope every claim in writing:
- The model provider sees whatever the harness sends.
- The edge defaults to TLS passthrough, routing on SNI to a sidecar that holds the key. Any mode that terminates TLS is labeled as one URnetwork can read.
- Inbound mail arrives as plaintext SMTP and is encrypted on receipt.
- Search and summarization run on members' machines.

Publish the list of metadata the servers can see, as Keybase did for its encrypted git.

### Break the lethal trifecta by default

Because the sidecar mediates all three legs, it can keep them apart:
- **Untrusted mail cuts off the way out.** Mail from outside the team is marked untrusted. A run that has read untrusted content loses send, forward, and publish until a person approves.
- **New recipients wait for approval.** The first message to a new recipient is held until someone approves it.
- **Public names are explicit and guarded.** Publishing a public TLS name is an explicit act. The name has authentication on by default and is short-lived. The sidecar refuses known agent control endpoints, such as MCP Inspector or an OpenClaw control UI.
- **Agent configuration goes to review.** Writes to executable agent configuration go to review rather than straight into the shared branch. This covers `CLAUDE.md`, `AGENTS.md`, hooks, editor tasks, and `.mcp.json`. In May and June 2026, Mini Shai-Hulud planted a Claude Code hook, and Miasma planted configuration files that run when a repo is opened.
- **Shared writes are scanned for secrets.** Writes to the repo and to group threads are scanned, because evaluation agents at OpenAI passed credentials to each other through whatever channel they shared.
- **The sidecar holds no long-lived secrets.** It keeps no long-lived plaintext secrets, because s1ngularity and Shai-Hulud harvested tokens from the same developer userspace the sidecar will run in.

This is close to what the company already does. Its network's trust and safety is built on defaults that keep strangers' traffic from becoming a member's problem, and its deck prepared for IETF 124 is titled "Default Safe." Saying the same about agents is credible only if the defaults ship switched on.

### Make git semantics survive twenty agents

Syncing git objects in real time is easy, because they are content-addressed and only ever added. Branch pointers are the hard part. Keybase did not keep a bare repo on its real-time encrypted filesystem, because concurrent writes could conflict, and used locking instead.

The design that follows:
- Give each agent and person a branch namespace that syncs in real time.
- Merge into shared branches as explicit, reviewable steps. Ink & Switch reached the same design after finding that real-time co-editing creates a "fishbowl effect."
- Serialize shared refs with compare-and-swap.

Fixing a wrong memory then becomes a revert rather than an argument.

**Publish a load test.** Reliability under load is where the open-source coordination layers break:
- MCP Agent Mail's Rust version "repeatedly corrupts SQLite" under swarm load.
- Gas Town spawns large numbers of git processes.
- One Beads user wrote that "Moving to dolt pretty much made beads unusable for me."

"Twenty agents writing at once" should be a published test, not an adjective.

**Plan for erasure and exit.** A signed, append-only history cannot remove a leaked secret or personal data without tools that rewrite and re-encrypt it. The store should always clone as plain git, with a documented export. Notion shut Skiff down within months of buying it, and Keybase's future has been in Zoom's hands since 2020.

### Meet each harness where it already reads

**Speak MCP over stdio.** The text protocol should be MCP over stdio, the subprocess binding the leading harnesses already launch.

**Install in cloud environments too.** The sidecar should also install inside cloud-agent environments, so that "any harness" includes the Codex and Cursor cloud agents that need private reach today.

**Write each harness's own context files.** The sidecar should write the team's context into the files each harness already loads: `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, and `.github/copilot-instructions.md`. It should record what each run was given, and warn before a harness truncates it. Codex silently cuts `AGENTS.md` at 32 KB, and a user on that issue asked for "an inspectable assembled-instructions path." This can ship before anything else, and it answers the most repeated complaint in `gap.md`.

**Bridge the built-ins instead of replacing them.** Claude Code's team mailboxes and Codex's message board are where each vendor's agents already talk. The sidecar should carry those messages into the shared record, and on to people and agents outside that vendor.

### Use the network for reach, and nothing else

*Updated 1 November 2026: the sidecar is not tokenized, and it uses URnetwork's network for worldwide reach and nothing else.*

**Architecture.** Traffic between sidecars is end-to-end encrypted, so the network carries only ciphertext. Agents reach the internet only through exits the customer runs, never through member egress (see the Okta and Entra finding above). The sidecar threat model should name the network hops that carry its traffic and the metadata each one sees.

**Infrastructure.** Storage and mail run outside the network. Mail has to, because the provider network blocks port 25 by default.

**Trust and safety.** It must cover hosted endpoints and outbound mail. The current egress process does not.

**Domains.** The inbox and the edge default to the customer's own domain, as Resend's agent inboxes do, rather than to `you.ur.network`. Two reasons:
- nobody has checked how secure web gateways categorize URnetwork's domains;
- deliverability follows the domain.

### Price per person and include the agents

**The structure.** Charge per human seat for the record, the keys, and team management. Meter storage, edge traffic, and mail. Leave agents unmetered.

**Precedents.**
- Microsoft licenses Agent 365 per user.
- Okta prices agent identity as a per-user add-on.
- Per-agent prices are rare. Letta's $0.10 per active agent is one exception.

**Seat price.** Beachhead teams already pay per-person prices from Tailscale's $8 to Copilot Business's $19 and a Claude Team seat's $20–25. That suggests a seat in that band. The band is an inference.

**Free tier.** It has to allow many concurrent agents. URnetwork's current Free plan allows two concurrent clients.

**x402.** Keep it for autonomous agents topping up usage. Enterprise procurement will not pay in stablecoins.

### Ship the trust artifacts with the product

Before the first use of "end-to-end encrypted":
- Open-source the sidecar client.
- Complete an independent audit of the client and protocol, and extend the Cure53 scope to the sidecar. The threat model says the 2025 assessments did not examine "logging, retention, the data path, or the protocol."
- Publish a sidecar threat model that assumes a malicious server, with the metadata list.
- Restore a dated warrant canary and current transparency reports.
- Name the contracting entity, BringYour, Inc. State that the sidecar is not tokenized and uses the network only for worldwide reach, and explain the operator's relation to the UR Foundation.
- Take the "distributed scraping" recipe, and the evasion and Iran testimonials, off anything an agent buyer sees.
- Fix the x402 docs.
- Define "users," "networks," and "devices."
- Publish sanctions controls.
- Document the IETF talk or stop citing it.
- Map the record to the AICPA's draft 2027 SOC 2 points of focus first, and to ISO/IEC 42001's event-log control (A.6.2.8) second. Only 271 ISO 42001 certificates existed worldwide at the end of 2025.
- Give the product a name that does not lean on "sidecar."

### Sequence the bundle, and charge for the team layer from the start

**First release, sharing one capture engine and one entry format:**
- the cross-harness session vault, under each developer's keys;
- each run's change set with a restore point, covering every tool path;
- approval receipts, carried by the team's own encrypted messages (on the URmessage base) or by signed links. No email is needed;
- the run inventory and agent identities;
- handoff notes and private links from commits to runs;
- the instruction-file writer.

**Then the paid team layer:**
- SSO and SCIM;
- SIEM export;
- retention controls;
- public TLS publishing;
- approval by email reply, limited to team members with DKIM-verified senders.

**Then the inbox proper:**
- external mail on the customer's domain;
- group inboxes;
- the visible audit member;
- key-escrow options;
- certifications for the regulated tier.

Email comes last because it is the heaviest new build serving the lowest-ranked gap.

**Charge for the team layer from the first release.** Keybase built almost exactly this bundle in 2017: encrypted git, teams that rotated keys, chat, and an encrypted filesystem. It gave it away to a reported 200,000 to 400,000 users and deferred charging to "someday." Zoom bought it in May 2020, mainly for its encryption team, and it has been in maintenance mode since ([Keybase](https://keybase.io/blog/keybase-joins-zoom)).

The team layer is what an admin pays for. It is also the part no incumbent will give away across vendors.

### Still out of scope

- An eval product.
- A harness.
- An identity provider.
- Agent mail that works only inside one vendor's harness.
- A gateway whose value is reading the traffic it passes.

## What the record must do, by evidence

The research on the record changes the order in which it earns its keep (`reports/Agent work record gaps and features.md`, "Keep the session, sign the approval"). The developer's bad day comes first, and it reaches far more people than the client's question does.

### User pains, by people affected

The table counts distinct non-staff accounts across GitHub issues, Hacker News, and forum threads read on 31 October 2026. The counts are floors, because Reddit could not be searched.

| Pain | People | What breaks today |
|---|---|---|
| Reviewing and undoing what a run changed | About 280 | Edits made through Bash, subagents, or reverts escape every harness's checkpoints. Claude Code's auto mode routed edits through Bash, which silently disabled checkpoints, diffs, and edit hooks ([#87575](https://github.com/anthropics/claude-code/issues/87575)) |
| Sessions deleted or hidden | About 200 | Claude Code silently deletes transcripts after 30 days ([#62476](https://github.com/anthropics/claude-code/issues/62476)). Simon Willison: "Most of my work is captured in them now" ([HN 48921792](https://news.ycombinator.com/item?id=48921792)) |
| Handoff across surfaces, machines, and teammates | 139 | Resume works inside one harness, on one machine |
| Approvals not recorded or silently overridden | 86 | Claude Code keeps no log of "Allow" decisions ([#32904](https://github.com/anthropics/claude-code/issues/32904)). A hook's "ask" is auto-approved in bypass mode yet logged as success ([#51255](https://github.com/anthropics/claude-code/issues/51255)) |

These pains yield four promises, in order of evidence:
1. Nothing a run changed is invisible or irreversible, whatever tool made the change.
2. Nothing a run did is lost. Retention is the owner's policy, and archiving replaces deletion.
3. Any run can be picked up in another harness, on another machine, or by a teammate, through a summary of its decisions rather than its full transcript.
4. Every approval is on file and bound to what ran, whatever the permission mode.

### What already exists, and what no product offers

Agent records sit in five silos:
- harness-local transcripts;
- vendor compliance feeds;
- provenance kept in the repository;
- gateways and observability backends;
- security vendors' verdict logs.

No commercial record of agent work does any of the following:
- stays unreadable by its own vendor;
- lets a third party verify it;
- binds an approval to the action that ran. Claude Code only correlates the two by `tool_use_id`, and Codex keeps approvals as transient events;
- discloses part of itself cryptographically to a client;
- keys data per client;
- erases a single record;
- traces which message triggered which action;
- records inbound reach, such as forwarded ports and published names.

Three features do not set the record apart:
- **Tamper-evidence.** Open-source signed logs such as [Obsigna](https://github.com/agent-receipts/obsigna) already exist, along with dozens of IETF receipt drafts and Anthropic's own signed transparency log.
- **Cost per shipped change.** Five measurement platforms already sell it.
- **Public provenance.** Linux dropped its `Assisted-by` tag, and developers strip vendor trailers.

### When buyers ask

Today's questionnaires, contracts, and auditors ask which AI a team uses, and whether a human reviews it. The question "what did the agents touch" hardens from December 2027:
- the AICPA's draft SOC 2 criteria would apply to engagements beginning on or after 31 December 2027;
- the EU AI Act's high-risk logging applies from 2 December 2027;
- most Cyber Resilience Act duties apply from 11 December 2027.

So the record's first job is to rescue the developer when a session or an edit goes missing. Meanwhile, it builds the agent inventory and approver change log that the later demands will want.

## The complete package: trails, coordination, and the record

Two facts set the shape of the package:
- Coordination alone does not sell. Vibe Kanban closed its hosted service, saying "the vast majority are free users" ([Vibe Kanban](https://www.vibekanban.com/blog/shutdown)). MCP Agent Mail has about 2.5k GitHub stars, against claude-mem's 107.5k.
- An admin record alone is something no developer installs.

The package resolves both with **one write and three readers**. Each action is captured once, by one engine, and the capture lands in two key domains:
- **The developer's session vault**, under that developer's keys. It holds raw transcripts, prompts, replies, files read, and each run's change set with a restore point.
- **The team's ledger**, under team keys. It holds actions, approvals, change-set hashes, the agent inventory, cost, and coverage. It also holds the coordination entries that agents read: claims, handoffs, questions, and routes.

Three readers use these domains:
- **Agents** coordinate through the ledger.
- **The developer and the next run** continue from the vault and the ledger.
- **The admin** answers for what the ledger shows, and sees raw content only when its author discloses it.

The vault is free for individuals. The team ledger arrives with the second person, because shared entries need team keys, and team keys need an admin. "The private record of agent work" stays the category; "trails" is the word for the entries agents and developers touch.

### One write, three readers, two key domains

| Reader | Reads | Gets | Who sells this face today, and where it stops |
|---|---|---|---|
| Agents (coordination) | The ledger: claims, handoffs, open questions, routes, who is working where | Agents find each other through the work they touch, across harnesses | Claude Code agent teams and Codex message boards: one vendor, with cross-machine traffic through the vendor. MCP Agent Mail and Gas Town: one host, unencrypted |
| Developer and next run (continuity) | Their own vault, plus the ledger | Sessions never lost, every change reviewable and restorable, handoff in any harness, approvals from a phone, cost per run | Entire, SpecStory, and git-ai: readable from the repo or synced to the vendor's cloud, and they miss edits made through the shell. Harness resume: one harness only, and Claude Code deletes after 30 days |
| Admin (accountability) | The ledger only | An inventory from real runs, approvals bound to actions, exposure, policy, and export | Anthropic's Compliance API, GitHub's control plane, Agent 365: held by the vendor, limited to its own runtime. Span's local recorder: sessions kept private to engineers by access control on Span's servers, with no customer keys or approval capture. Aperture and Coder: inspection at a gateway |

### The trail entry

Every ledger entry has three properties:
- **It is signed** by the principal that wrote it. High-risk approvals are also signed by the human, with their own SSH key.
- **It points to content in the developer's vault through a salted hash.** Salts have to be in the entry format from day one, because they cannot be added to entries already logged.
- **It carries a trust flag** saying whether the run that wrote it had read untrusted content.

| Entry | Written when | Main readers |
|---|---|---|
| `claim` | An agent takes files, a task, or a service, with an expiry. Leases are advisory and enforced at commit, the way MCP Agent Mail's pre-commit guard does it ([Rust README](https://github.com/Dicklesworthstone/mcp_agent_mail_rust)) | Agents, plus admin metadata |
| `change` | A run changes files by any tool path. The entry records its capture source (tool call, hook, telemetry, or filesystem watcher) and a restore point | Developer, next run, admin (hashes) |
| `handoff` | A run ends or pauses. It records the goal, what was done, what was tried and failed, decisions, and the next step. In one commenter's words: "store CHOICES… not the whole session" ([HN 48846415](https://news.ycombinator.com/item?id=48846415)) | Agents, next run, teammates |
| `ask` / `answer` | A question is addressed to a person, role, or project | Agents, people |
| `approval` | A person or a policy decides on a proposal. One action ID binds the proposal, the decision, the execution, and the result. The entry records the permission mode, and session grants can be listed and revoked. It stays complete in auto and bypass modes | Admin, auditors |
| `route` | A scoped grant to reach a service is used or approved, with its approver and expiry | Agents, admin |
| `publish` | A public TLS name opens or closes | Admin |
| `context` | A run starts. The entry is a manifest of what the run was given: instruction files and their hashes, files read, model, harness version, and permission mode, plus any truncation warnings | Developer, admin |
| `check` | A test fails, or a person says "no" for the next run | Next run |
| `membership` / `key` | Someone joins or leaves, or a key epoch changes | Admin |

### Agents find each other through the work

When an agent starts on a file, a task, or a service, it asks the trail what is already there. It might find:
- a live claim by an agent in another harness;
- a handoff with open questions;
- a question addressed to its project;
- a route that worked last time, with its approval.

It can then wait, answer, take over after the claim expires, or follow the route under the same grant.

With mailboxes, agents have to know whom to address. With trails, they find each other by what they touch. That is the difference from the built-in versions, which coordinate one vendor's agents inside one team or session.

The need shows up as collisions and lost handoffs. One HN user said parallel agents "clash while editing files simultaneously... It's chaos" ([HN 44533004](https://news.ycombinator.com/item?id=44533004)). Handoff drew 139 people across 14 threads.

That this kind of indirect coordination improves outcomes for LLM agents is a hypothesis. Pilots should measure duplicate work, conflicting edits, and time to hand off before the product claims it.

### Rules that keep the readers from colliding

**Write once.** The admin view reads the same entries that agents coordinate through, and there is no separate audit pipeline. In audit-only systems, logging is overhead, and it gets bypassed when hooks fail open or auto modes skip them. Here, an agent that does not write its claims and handoffs cannot coordinate. Coordination makes the record fuller, though it never proves it complete.

**Capture from four sources:**
- the sidecar's own MCP traffic;
- harness hooks;
- harness telemetry;
- watching the filesystem and git.

Recorders that rely on the repo alone miss work. One Entire user found that 26 of 29 commits had no checkpoint ([Entire #529](https://github.com/entireio/cli/issues/529)). Another wrote that "the actual capture boundary is the agent process, not the working tree" ([Entire #1098](https://github.com/entireio/cli/issues/1098)). Watching the filesystem shows the effects of shell commands even when the commands themselves are invisible. The record can claim integrity, custody, time, and observed effects, but never completeness. Each run should state what the record could not see.

**Durable by default.** Archive instead of deleting, and make retention the owner's setting. Demands that vendors delete sessions drew more reactions than worries about teammates: a request to delete web and desktop sessions got 96 +1s ([#13514](https://github.com/anthropics/claude-code/issues/13514)). A Codex user insisted that "Archiving is not deletion" ([Codex #24610](https://github.com/openai/codex/issues/24610)). The team ledger keeps at least 12 months, with 90 days immediately searchable.

**Two key domains inside the team.**

| Who | What they see |
|---|---|
| The author | Their own raw sessions and change sets, under their own keys |
| Teammates and agents | Claims, handoffs, decisions, and questions. A session only when its author shares it |
| Admins | Actions, approvals, hashes, inventory, cost, and coverage. Every admin read becomes an entry the author can see |

Some teams must retain content; FINRA-supervised firms, for example, keep prompt and output logs. For them there is one visible access path: either an audit member that users can see, or disclosed key escrow with a private option for each member.

The legal trigger is capability, not intent. Under §87(1) No. 6 of Germany's Works Constitution Act, a record the employer can read is monitoring-capable and likely needs a works-council agreement ([Covington](https://www.cov.com/-/media/files/corporate/publications/2026/07/works-council-rights-in-ai-implementation-projects.pdf)). Keeping each person's content under their own keys, and exporting only aggregates above a minimum group size, may narrow that exposure. This needs legal review.

The Team tier therefore ships with a works-council packet:
- a data inventory;
- the purposes of processing;
- retention periods;
- an access log;
- a clause ruling out use in individual performance reviews.

There are no leaderboards. Meta dropped AI usage from engineer reviews after "tokenmaxxing" ([The Decoder](https://the-decoder.com/meta-drops-ai-usage-from-engineer-performance-reviews-after-tokenmaxxing-backfires/)). In a survey commissioned by Harness, 54% of developers feared evaluations based on their AI data.

Developers object to colleagues reading raw sessions. One said: "I am not willing to share my sheepish prompts with my team" ([HN 46966815](https://news.ycombinator.com/item?id=46966815); [Entire #340](https://github.com/entireio/cli/issues/340)). Admins say they have "gone completely blind" ([#27780](https://github.com/anthropics/claude-code/issues/27780)). The two key domains give each side what it asked for.

**Trust-weighted reading.** Each entry carries the provenance of the run that wrote it, including whether that run had read untrusted content. Agents treat entries from tainted runs as untrusted input, and secrets are blocked when entries are written.

**Private provenance, disclosed by choice.** Nothing goes into public commit history by default; links from commits to runs stay private.
- The Linux kernel added an `Assisted-by` tag in December 2025, and decided on 8 October 2026 to remove it ([commit 1e035297ffda](https://github.com/torvalds/linux/commit/1e035297ffda)).
- VS Code reverted a Copilot co-author default after 244 thumbs-down.

Disclosure to a client, auditor, or maintainer is a proof pack the team chooses to send. It can be an SD-JWT-style disclosure (RFC 9901) of a human-signed approval, plus an inclusion proof, without the transcript ([RFC 9901](https://datatracker.ietf.org/doc/rfc9901/)).

### What ships, and in which tier

| # | Feature | Evidence it answers | Tier | Stage |
|---|---|---|---|---|
| 1 | Session vault: every session under the developer's keys, a per-run context manifest, secrets redacted before saving, search, and archiving instead of deletion | Lost and hidden sessions (about 200 people); the privacy and secrets themes | Solo | First release |
| 2 | Run change set and restore point: every file changed by any tool path; restore stays inside the run's own changes, is previewed first, and is recorded | Review and rewind (about 280 people) | Solo | First release |
| 3 | Approval receipts: one action ID, the permission mode, revocable grants, an SSH signature for high-risk tiers, and complete records in auto and bypass modes | The approvals theme; Cursor users' request ([Cursor forum](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247)); Microsoft DPR requirement 33 | Solo for a developer's own history; Team for the shared signed ledger | First release |
| 4 | Run inventory and agent identity: harness, version, model, sponsoring human, a credential reference, and an agent identity distinct from the human's token | Vanta's "built with AI" questions; the AICPA draft's "unsanctioned AI tools" | Team | First release |
| 5 | Handoff notes and private links from commits to runs, with an optional brand-neutral disclosure for code review | Handoff (139 people); open-source disclosure norms | Solo | First release |
| 6 | Coordination entries: claims and leases across harnesses, live presence, and threads addressed to projects and roles | Collisions ("It's chaos"); handoff | Solo among a developer's own agents; Team across people | First (own agents), next (across people) |
| 7 | Verifiable team log: Tessera, C2SP checkpoints, witnesses run by customers or auditors, and an open-source offline verifier | NCCoE's call for logs kept "in a tamper-proof and verifiable manner"; DORA's tamper protection | Team | Next |
| 8 | Client disclosure packet: a partition with its own keys for each client, field-by-field SD-JWT disclosure with inclusion proofs, and erasure per client | Outside-counsel terms; Microsoft DPR; consultancies in the beachhead | Team | Next |
| 9 | Reach receipts: each forward and published name, with its owner, approver, scope, duration, and who connected | No tool records inbound reach | Team | Next |
| 10 | Exports and retention: OTel GenAI mapping, SIEM, SCITT/COSE and in-toto statements, attribution compatible with Agent Trace; 12 months kept, 90 days searchable | PCI 10.5.1; Microsoft DPR requirement 33 | Team | Next |
| 11 | Per-run cost across harnesses, as a line item and an export to the measurement platforms teams already use | The cost theme; DX's "lack that granularity" | Team | Next |
| 12 | Fate reconciler: a CI or bot step that follows each run's content hashes through squash and rebase merges, measuring survival per run and approval-to-revert ratios by role or team, never by person | DORA's stability finding; no product joins approvals to reverts | Team | Later |
| 13 | Message provenance: which inbound message triggered which action; untrusted input removes send and publish until a human approves | The lethal trifecta ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)) | Team | With the inbox |
| 14 | Assured controls: SCIM; a kill switch through Agent 365 or Okta; content retention through a visible audit member; legal hold; policy on publish and egress; compliance mappings (the AICPA draft SOC 2 points of focus first, then ISO 42001, Microsoft DPR Section K, PCI, and AIUC-1 for agent vendors) | Regulated systems, Microsoft suppliers, agent vendors | Assured | Next |

| | Solo | Team | Assured |
|---|---|---|---|
| For | One person, any number of agents and harnesses | Two or more people, roughly 2 to 150 | Regulated systems, Microsoft suppliers, agent vendors, and teams that must retain content |
| Includes | Features 1, 2, 5; the developer's own approval history; coordination among their own agents; the instruction-file writer | Everything in Solo, plus features 3 (shared ledger), 4, 6 (across people), 7 to 13, the works-council packet, and SSO | Everything in Team, plus feature 14 |
| Price (inference) | Free | A seat in the $8–25 band. Anchors: Tailscale $8, Agent 365 $15, Copilot Business $19, a Claude Team seat at $20–25 | About a Copilot Enterprise seat ($39) |

Storage, edge traffic, and mail are metered. Agents are never metered. Autonomous agents can top up usage through x402.

**Solo is free** because the vault is why a developer installs the sidecar, and the change set is why it keeps running every day: it works where the harness's own checkpoints fail. Coordination brings installs, not seats.

**Team starts at the second person**, because shared entries need team keys. The first admin job is the one buyers ask about today: which agents, harnesses, and models touched which repos, and whether a human approved. That is the inventory and approver change log that Vanta's AI Security Assessment asks about ([Vanta](https://www.vanta.com/resources/introducing-vantas-ai-security-assessment)), answered with evidence from real runs instead of a policy document. The client packet sits in Team rather than Assured, because the beachhead's consultancies and agencies need it.

**Assured covers the buyers whose demand for proof already exists or hardens in 2027–28:**
- **Microsoft suppliers.** Change logs must name the approver and be available for 90 days ([Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf)).
- **Teams that ship agents.** AIUC-1 requires activity and tool-call logs, and has had requirements for coding agents since July 2026 ([Drata](https://drata.com/blog/introducing-aiuc-1)).
- **PCI environments.** Administrative actions are logged and kept for 12 months.
- **SOC 2 engagements from the end of 2027.** The AICPA's draft 2027 criteria add AI points of focus; comments close on 15 January 2027 ([AICPA](https://www.aicpa-cima.com/news/article/aicpa-proposes-update-of-soc-2-r-trust-services-criteria-to-enhance-the-relevance-usability-and-value-of-cpas-reports)).

### The flywheel

1. Developers install the vault for their own bad days: the lost session, the edit no checkpoint saw.
2. The same capture writes the team ledger once a second person joins.
3. Agents coordinate through the ledger, which makes it fuller.
4. The admin sets policy on the same entries: what agents may publish, send, and reach.
5. The signed approvals answer the client's questionnaire.
6. The team adds people and clients, and more agents coordinate.

The moat is time. A team that turns on the ledger in 2026 will hold a year of signed, witnessed approvals when the 2027 criteria arrive. A latecomer cannot recreate that history, even though the underlying data exports as plain git.

### Why the package is harder to copy than any one face

Each competitor owns one reader, and is one step away from more:
- **The agent face:** Claude Code's agent teams and cross-session messaging, Codex's message boards, MCP Agent Mail, and Gas Town. Each covers one vendor or one host.
- **The developer face:** Entire (which removed restore and launched a forge on 26 October 2026) and SpecStory are each one encryption feature away from the vault. git-ai's team joined OpenAI's Codex on 11 September 2026.
- **The admin face:** Anthropic's Compliance API returns local transcripts. GitHub streams prompts, responses, and tool calls from Copilot CLI and IDE sessions to the employer's SIEM. Span's local recorder already keeps sessions private to engineers, but through access control on its own servers ([Span](https://www.span.app/)). Its documentation mentions no customer-held keys, tamper-evidence, or approval capture.

Copying the package means serving all three readers from one capture, across rival harnesses, with two key domains that the vendor cannot open. The structural obstacles:
- Harness owners cannot be neutral.
- Gateway and recorder vendors would have to give up reading the data their products are built on.
- Span would have to replace access control with keys.

The key split, more than encryption alone, is the clearest line between this package and the Span recorder on nearby ground.

### Risks of the merge

- **Scope.** Three surfaces is a lot for a company of one to ten people. The first release shares one capture engine and one entry format, and each tier should ship whole before the next.
- **Restore can destroy work.** Cursor's revert crossed workspace boundaries and deleted files without a preview ([Cursor forum](https://forum.cursor.com/t/cursor-ide-revert-to-message-operation-crosses-workspace-boundaries-and-silently-targets-ignored-files/176032)). Restore must show a preview, stay inside the run's own change set, and record itself.
- **The free line.** Solo must be generous enough to win heavy users without replacing Team. The second person is that line; crippling Solo is not.
- **Unproven coordination value.** Measure it before claiming it.
- **Completeness.** Hooks fail open, auto modes bypass them, and a harness can act outside the sidecar. State what each run could not see.
- **Not every developer wants a record.** The Hacker News thread on Entire's launch was mostly skeptical. That is why the vault leads with recovery, not with sharing.

### How to say it

- **The package:** "Every agent leaves a trail. Only your team can read it, and your sessions stay yours."
- **Developers:** "Never lose an agent session or an edit, whichever harness made it." Then: "Your agents find each other's work, and the next run starts where the last one stopped."
- **Admins:** "Know which agent did what, in any harness, and who approved it. Signed, and without handing it to another vendor."
- **Privacy:** "Private from us. Actions and approvals complete for your admins. Sessions stay with their author unless shared."
- **Category:** still "the private record of agent work".

## Conclusion

The crack the earlier research described is real, and the record is how to occupy it. The jobs a buyer can already get elsewhere become benefits of one record no incumbent can sell: continuity, reach, messages, and team auth. Model vendors can't sell it because it is neutral across their harnesses. Gateway vendors can't because the operator cannot read it. And none of them can match a record of what happened on the machine, which each of them admits its own logs miss.

The coverage gap in `gap.md` and the user gap still stand. The opportunity gap is narrower: what the harness vendors, the network vendors, and the identity suites will not build, because it cuts against how they earn.

The report names the inversion this creates:
- **Defensible ground** is where URnetwork is weakest today: a customer-facing record, keys the company cannot read, and an audited encryption claim.
- **Commodity ground** is where it is strongest: relays and reach.

Positioning cannot paper over that. It can only pick the ground worth building toward, and say why nobody else will occupy it: in the developer's words on the homepage, and in the security team's words on the admin page. The window is set by events, not a date:
- GitHub shipping the local session activity it listed as future work;
- Microsoft extending discovery to CLI agents;
- Anthropic or OpenAI offering records across rival harnesses, held under customer keys;
- Cloudflare turning its storage, email, and tunnel parts into a process that runs beside the harness.

Any one of these would shrink the first two gaps to a feature. That argues for building the record and the store before the inbox, and for closing the company's own trust gap first: the reviewer who pays for the record will check the company before the product.

The complete package makes that ground buildable in order:
1. a free session vault and change set that developers install for their own bad days;
2. a team ledger of signed approvals and coordination entries that arrives with the second person;
3. assurance for the outsiders who must be convinced.

One write feeds both key domains, so neither face has to be built twice. And the moat is time. A team that turns on the ledger in 2026 will hold a year of signed approvals when the new SOC 2 criteria and EU dates arrive. A latecomer cannot recreate a log's unbroken, witnessed history.
