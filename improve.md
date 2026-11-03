# Strengthen the offer

The offer is built only from the brief: a userspace sidecar any harness drives over a text protocol, with real-time encrypted git storage, port forwarding, a public TLS edge, email and group inbox, team auth, and an admin audit trail.

The line stays “Keep what the last run changed, and let the next one reach the machine.” It gets stronger when those two verbs are one record. Git storage and a tunnel, sold side by side, are jobs buyers can already buy separately.

## The thing you sell is the run record

A run ends as one commit in the encrypted store. That commit holds the context diff, the route that was used, and the inbox message that caused the change. The next harness opens that commit through the text protocol. The admin view is the same commit: what changed, what was reached, and who was allowed. The sentence under the line is: “The correction, the route, and the admin record are one commit any harness can open.”

## The protocol writes the record

The text interface should treat “end of run” as a write. The harness sends the delta, the service it called, and the principal it used. The sidecar commits that and syncs it. The next subprocess, in a different harness, reads it back. A person does not have to copy a correction into a prompt, and the model is not the place the correction lives. Real-time sync is what makes “already in the repo” true for a teammate’s harness before they start, which is the part a local git commit on one laptop does not do.

## Reach is a grant recorded in that commit

Port forwarding and the public TLS edge stay in the product. The default a buyer should see is narrower: the next run on this team can call the service the last run used, under team auth, and the call lands on the audit trail beside the diff. Publishing a public TLS name is an explicit step, because a URL anyone can open is a different product. For a company whose systems are not a port on a laptop, the service on the machine is the adapter. The sidecar keeps the route that worked and who may use it, so the next run does not rediscover the endpoint.

## The inbox is how the correction gets into the commit

A reply in the group inbox becomes the next commit before the next run starts. That is the feature that makes “keep what the last run changed” survive a team that will not hand-edit a repo. Direct agent messaging belongs here too: an agent’s message into the group is the same kind of write, with the same auth and the same admin view.

## One session is the whole offer

Harness A changes context and calls a local service. The subprocess writes one commit. Harness B starts, reads the diff, and calls the same service under the same team. The admin view shows the diff and the call. Encryption is the sentence you can say about that record: the team holds the key, and the record stays in the userspace process they run. The harness still sends the model whatever working set it chooses to send.

## Leave a file for the loop you do not grade

A failed check or a human “no” from the inbox is a file in that same commit, which the next run opens. That is as far as the sidecar goes toward a feedback loop. Scoring, datasets, and CI gates stay outside it.

Real-time sync, userspace, and the text protocol are how the record stays one process any current harness can drive. They sit under the line, not in it.

---

## Addendum, 31 October 2026: moves that make the positioning true

This file was right that the run record is the thing to sell. The October 2026 research promotes it from the core of the offer to the headline. The report's title is "Sell the record, not the tunnel." The line above, "Keep what the last run changed, and let the next one reach the machine," keeps both of its pains but stops being the headline:
- Continuity becomes what the next run reads from the record.
- Reach becomes a grant the record shows someone approved.

The research also changes three things about the record itself:
- whose identity sits at its center;
- who must be unable to read it;
- which defaults make it safe to put an inbox, a repo, and a route in one process.

Each move below is a recommendation, with the evidence that drives it. The notes are in `research_notes/Sidecar positioning and market gaps/`. The positioning these moves support is in the addendum to `market.md`.

### Put one principal at the center of every entry

Every agent instance and every person is a principal with a sponsor: the human or team the agent acts for. One principal does four jobs:
- it is the mail address (`name@you.ur.network`);
- it is the signer of its git commits;
- it owns its TLS name;
- it is the actor in the record.

A stitched-together stack cannot join its four separate identities after the fact. This is the attribution gap in concrete form. In a CSA survey sponsored by Aembit, 68% of organizations could not tell agent activity from human activity, and 43% ran agents on shared service accounts ([CSA](https://cloudsecurityalliance.org/articles/more-than-two-thirds-of-organizations-cannot-clearly-distinguish-ai-agent-from-human-actions)).

**Treat share links as bearer capabilities.** The count-limited share links in the design sketch work for whoever holds them. Each redemption should bind to a device or agent key and enter the team through a signed membership change. Removing a member should start a new key epoch. URmessage already uses MLS (RFC 9420), which was built for this. Like every comparable system, MLS cuts a removed member off from new content only, and the docs should say so. Key recovery should be a disclosed choice, made per member.

**Consume identity; do not issue it.** "Easy auth" should mean:
- OIDC and SAML sign-in, and SCIM;
- Okta's Cross App Access, now the Enterprise-Managed Authorization extension for MCP;
- SPIFFE where it exists.

Agents should run on short-lived per-run tokens instead of the long-lived `urn_` keys URnetwork issues today. They should be registered under a sponsor where admins already look, and be reachable by a kill switch in Agent 365 or Okta. Microsoft says its discovery of local CLI agents is only "expanding soon." A process the harness starts is the natural place to attach a sponsor to an agent that would otherwise be invisible. It also has to be discoverable and killable by enterprise controls, or it will be blocked as shadow infrastructure.

### Write the record the frameworks describe

Every action that crosses the sidecar should emit one signed, hash-chained entry. The actions are:
- a store write or merge;
- a forward opened or closed;
- a name published;
- a message read or sent;
- a member or key added or removed.

Each entry should carry:
- the actor: agent and sponsor, harness and version, device;
- a reference to the credential used, never its value;
- the action and its target, such as a commit hash, a port, hostname, and exposure, or every mail recipient including BCC;
- the policy decision and the identity of whoever approved it;
- the provenance of the input that triggered it, as a hash plus a pointer into the encrypted store;
- writes to memory, agent configuration, and MCP tool definitions, recorded by hash;
- a run ID and the outcome.

**Join proposals, approvals, and commands.** The sidecar should ingest the harness's hooks and telemetry. It should also mint the shared action ID that Cursor users asked for, so that a proposal, the person's approval, and the command that ran become one entry. One user wrote that without that ID "it may still be impossible to prove that the executed action was precisely the action the user approved."

**Handle retention and export.** Retention should be configurable to at least six months. Exports should go to the SIEMs that Entra, Okta, Splunk, and CrowdStrike customers already run. Every read of the record should itself be recorded.

**Keep content out.** No secrets and no plaintext content go in the record. That way the record never becomes a second, weaker copy of the private data, and erasing content from the store does not break the hash chain.

No standard supplies this schema yet. It is the union of four sources:
- OWASP's MCP08 call for "immutable audit trails";
- OWASP's Q3 2026 advice to log what agents actually did, by run ID ([OWASP](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/));
- NCCoE's questions about delegation and non-repudiation ([NCCoE](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf));
- the EU AI Act's six months of logs "under their control," which applies to deployers of high-risk systems from 2 December 2027.

Mail recipients matter in particular. The squatted `postmark-mcp` package quietly added a BCC to every message ([Koi](https://koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)). Mail gateways could not see it. A per-send record would have shown it plainly.

**Say what the record cannot see.** It sees what crosses the sidecar and what the harness reports through hooks. It does not see a shell command the harness runs on its own. The right claim is "every action through the sidecar, and every harness event you connect."

### Say out loud who can read what

"Private" should mean private from URnetwork and complete for the team's admins. Pick the patterns that credible encrypted products use, and name them:
- **By default**, the record is metadata-only and signed by the clients, so the server cannot forge it.
- **For content access**, use either:
  - a visible audit member that every participant can see, as Element's AuditBot does: it "is visible to your users" and "cannot be hidden"; or
  - disclosed escrow of keys under an organization key, with a per-member "private" setting, as Proton for Business does ([Element](https://ems-docs.element.io/books/element-cloud-documentation/page/audit-bot), [Proton](https://proton.me/support/private-users)).
- **Never** use a silent plaintext archive. TeleMessage sold end-to-end encryption "through to the corporate archive," shipped plaintext to its own archive, and was breached in May 2025 ([Micah Lee](https://micahflee.com/despite-misleading-marketing-israeli-company-telemessage-used-by-trump-officials-can-access-plaintext-chat-logs/)).

Then put the scope of every claim in writing:
- The model provider sees whatever the harness sends.
- The edge should default to TLS passthrough, routing on SNI to a sidecar that holds the key. Any terminating mode should be labeled as one URnetwork can read.
- Inbound mail arrives as plaintext SMTP and is encrypted on receipt.
- Search and summarization run on members' machines, not on a server.

Publish the list of metadata the servers can see, as Keybase did for its encrypted git. Never say "zero-knowledge."

### Break the lethal trifecta by default

The sidecar puts all three of Simon Willison's ingredients in one process ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)):
- private data, in the shared repo;
- untrusted content, in the inbox;
- a way out, through outbound mail, forwards, and the public edge.

That is the strongest argument against the product. Because the sidecar mediates all three legs, it is also the one place that can keep them apart:
- **Untrusted mail cuts off the way out.** Mail from outside the team is marked untrusted. A run that has read untrusted content loses send, forward, and publish until a person approves.
- **New recipients need approval.** The first message to a new recipient waits for approval.
- **Publishing is explicit and guarded.** Publishing a public TLS name is an explicit act. The name has authentication on by default and is short-lived. The sidecar refuses to publish known agent control endpoints, such as MCP Inspector or an OpenClaw control UI. Knostic found 1,862 exposed MCP servers, and none of the 119 it checked by hand required authentication ([Knostic](https://www.knostic.ai/blog/mapping-mcp-servers-study)).
- **Agent configuration goes to review.** Writes to executable agent configuration go to review instead of straight into the shared branch. That covers `CLAUDE.md`, `AGENTS.md`, hooks, editor tasks, and `.mcp.json`. In May and June 2026, Mini Shai-Hulud planted a Claude Code hook, and Miasma planted configuration files that run when a repo is opened.
- **Shared writes are scanned for secrets.** Writes to the repo and to group threads are scanned, because evaluation agents at OpenAI passed credentials to each other through whatever channel they shared.
- **No long-lived secrets in the sidecar.** It keeps no long-lived plaintext secrets, because s1ngularity and Shai-Hulud harvested tokens from the same developer userspace the sidecar will run in.

This is close to what the company already does. Its network's trust and safety is built on defaults that keep strangers' traffic from becoming a member's problem, and its deck prepared for IETF 124 is titled "Default Safe." Saying the same thing about agents is credible only if the defaults ship on.

### Make git semantics survive twenty agents

Syncing git objects in real time is the easy part, because they are content-addressed and only ever added. Branch pointers are the hard part. Keybase did not keep a bare repo on its real-time encrypted filesystem, because concurrent writes could conflict. It used locking instead.

The design follows from that:
- Give each agent and person a branch namespace that syncs in real time.
- Merge into shared branches as explicit, reviewable steps. This is the design Ink & Switch reached after finding that real-time co-editing creates a "fishbowl effect."
- Serialize shared refs with compare-and-swap.

The merge log then is the record of the store, and a wrong memory is a revert instead of an argument.

**Make reliability under load a published test.** This is where the open-source coordination layers break:
- MCP Agent Mail's Rust version "repeatedly corrupts SQLite" under swarm load.
- Gas Town spawns large numbers of git processes.
- One Beads user wrote that "Moving to dolt pretty much made beads unusable for me."

"Twenty agents writing at once" should be a published test, not an adjective.

**Plan for erasure and exit.** Append-only signed history cannot remove a leaked secret or personal data without rewrite and re-encryption tools. The store should also always clone as plain git, with a documented export. Notion shut Skiff down within months of buying it, and Keybase's future has been in Zoom's hands since 2020.

### Meet each harness where it already reads

**Speak MCP over stdio.** The text protocol should be MCP over stdio. That is the subprocess binding the leading harnesses already launch, and it is what MCP Agent Mail users asked for when that tool was only an HTTP server ([#41](https://github.com/Dicklesworthstone/mcp_agent_mail/issues/41)).

**Say "any harness" precisely.** Cursor's Projects coordinator "always runs as a Cloud Agent" and cannot start a local server. The sidecar should therefore also install inside cloud-agent environments. That brings in the Codex and Cursor cloud agents that need private reach today.

**Write the files each harness already loads.** The sidecar should write the team's context into each harness's own files: `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, and `.github/copilot-instructions.md`. It should also record what each run was given, and warn before a harness truncates it. Codex silently cuts `AGENTS.md` at 32 KB, and a user on that issue asked for "an inspectable assembled-instructions path." This can ship before anything else, and it answers the most repeated complaint in `gap.md`.

**Bridge the built-ins instead of replacing them.** Claude Code's team mailboxes and Codex's message board are where each vendor's agents already talk to each other. The sidecar should carry those messages into the shared record, and on to the people and agents outside that vendor.

### Use the network for reach, and nothing else

*Updated 1 November 2026: the sidecar is not tokenized, and it uses URnetwork's network for worldwide reach and nothing else.*

That boundary has to show in the architecture, the contract, and the claims:
- **Architecture.** Traffic between sidecars is end-to-end encrypted, so the network carries only ciphertext. Agents reach the internet only through exits the customer runs, never through members' devices.
- **Infrastructure.** Storage and mail run outside the network. Mail has to, because the provider network blocks port 25 by default.
- **Trust and safety.** The process covers hosted endpoints and outbound mail, which the current egress process does not.

Either of two reasons is enough to keep agents' internet traffic off members' devices:
- **Agents would fail to sign in.** Okta and Entra flag or block anonymizing IP addresses, so agents whose traffic left through members' devices would fail to sign in to the customer's own SaaS ([Okta](https://sec.okta.com/blockanonymizers)).
- **Reviewers would stop reading.** After Google's IPIDEA takedown and the NetNut seizure, a reviewer who finds residential egress in the data path will go no further.

Default the inbox and the edge to the customer's own domain, as Resend's agent inboxes do, rather than to `you.ur.network`. Nobody has checked how secure web gateways categorize URnetwork's domains, and deliverability follows the domain.

Keep the privacy argument honest about the topology. The live network relays through an operator hop. So the sidecar's privacy rests on keys customers hold, not on the egress network's split between operator and provider.

### Price per person and include the agents

**Charge per human seat** for the record, the keys, and team management. **Meter** storage, edge traffic, and mail. **Leave agents unmetered.** The market supports this:
- Microsoft's Agent 365 licensing FAQ says "Agents do not require their own licenses" ([Microsoft](https://www.microsoft.com/licensing/faqs/122)).
- Okta prices agent identity as a per-user add-on.
- Per-agent prices are rare: Letta's $0.10 per active agent is one exception.
- The seats a beachhead team already pays for run from Tailscale's $8 to Copilot Business's $19 and a Claude Team seat's $20–25. A team seat somewhere in that band is an inference from those anchors.

**The free tier has to allow many concurrent agents.** URnetwork's current Free plan allows two concurrent clients, which would stop one developer from running three agents.

**Keep x402 for autonomous agents topping up usage.** It has no place in the team sale; enterprise procurement will not pay in stablecoins.

### Ship the trust artifacts with the product

Before the first use of "end-to-end encrypted":
- Open-source the sidecar client, because it is the endpoint.
- Complete an independent audit of the client and protocol, and extend the Cure53 scope to the sidecar. The threat model says the 2025 assessments did not examine "logging, retention, the data path, or the protocol."
- Publish a sidecar threat model that assumes a malicious server, with the metadata list.
- Restore a dated warrant canary and current transparency reports. Both returned 404 on 31 October 2026, and the last entry covers April to June 2024.
- Name the contracting entity, BringYour, Inc. State that sidecar fees carry no token economics, and explain how the operator relates to the UR Foundation.
- Take the skill's "distributed scraping" recipe and the evasion and Iran testimonials off anything an agent buyer will read.
- Fix the x402 docs, and define "users," "networks," and "devices."
- Publish sanctions controls.
- Document the IETF talk or stop citing it.
- Start a SOC 2 path, and map the record to ISO/IEC 42001's event-log control (A.6.2.8). Before December 2027, security questionnaires, not statutes, will ask for the record.
- Give the product a name that does not lean on "sidecar."

### Sequence the bundle, and charge for the team layer from the start

**First release, for teams on more than one harness:**
- principals;
- the record, with hook ingestion and action IDs;
- the encrypted store, with provenance on every write;
- the instruction-file writer;
- scoped reach grants;
- approvals.

Approvals in this release travel through the team's own encrypted messages, on the URmessage base, or through signed approval links. This release needs no email.

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

**Charge for the team layer from the first release.** Two precedents show what happens otherwise:
- Keybase built almost exactly this bundle in 2017: encrypted git, teams that rotated keys, chat, and an encrypted filesystem. It gave it away to a reported 200,000 to 400,000 users and deferred charging to "someday." It was bought by Zoom in May 2020, mainly for its encryption team, and has been in maintenance mode since ([Keybase](https://keybase.io/blog/keybase-joins-zoom)).
- Vibe Kanban shut down its hosted service in April 2026 because "the vast majority are free users" ([Vibe Kanban](https://www.vibekanban.com/blog/shutdown)).

The team layer is what an admin pays for, and it is the part no incumbent will give away across vendors.

### Still out of scope

Five things stay out of scope:
- **An eval product.** The sidecar can hold a failed check or a person's "no" for the next run, as above, but it does not grade the run.
- **A harness.**
- **An identity provider.**
- **Agent mail that works only inside one vendor.**
- **A gateway whose value is reading the traffic it passes.**
