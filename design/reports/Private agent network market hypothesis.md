# Win privacy-first agent users, then their teams

URnetwork's strongest market hypothesis is not an encrypted agent network sold at once to developers, product leaders, IT and security buyers. It is a narrower bet that can be tested. **The first buyers are privacy-first people already on URnetwork's list: developers, founders and consultants on desktop clients and Pro plans who have started letting AI agents act for them, and who won't hand those agents, or any company in the middle, their keys, mail and history.** They will adopt the CLI, Bot and Burner free on their own machines, and those who work in small groups will turn the habit into a three-seat Team. The raw material leaves no doubt about the gap. All six latest earnings calls treat seeing the content as the security model, and Palo Alto Networks' CEO calls the alternative "insane". A full-text search of the transcripts found no executive mention of encryption or privacy. On 42 vendors' sites, no networking, agent-infrastructure or observability product offers a hosted mode its operator can't read, and the confidential-AI vendors that promise one decrypt inside enclaves they or their suppliers run. So "no URnetwork server can read it, even in an enclave" has the field above the transport layer to itself. The 284 reviews and about 110 community threads, however, place the demand for that rule with self-hosters and privacy consumers, not with CISOs. Privacy decides whether people trust a product, not why they adopt it, and trust follows plain admissions and good conduct, not slogans. Nine complaints recur without a fix: a middle nobody can verify, secrets leaking into agents, self-hosting that breaks, private AI that forgets, alias addresses that get blocked, and lockouts with no human to appeal to, among others. URnetwork's design answers most of them, which is why the job, not the encryption, should lead. The evidence makes me confident about the gap, moderately confident that the segment exists, and doubtful about its size on a list where 94.9% of networks have no email login and sign-up farms have made most email sign-ups since 9 November. Twenty-four to 28 conversations recruited from the product, plus a launch question that asks what readers would run rather than what title they hold, should settle it before the campaign scales. For the campaigns, that means:
- leading with the job;
- telling developers that agents take no seat;
- scoping the security email's "whole list" of what the servers see, since URnetwork's support team reads support conversations in full;
- asking non-leading questions.

For ur.io, it means replacing "Period," "fully private" and unscoped "end-to-end encrypted" with claims that the pages' own tables support, and treating the trust page as the main asset.

## Every incumbent agrees that securing agents means reading them

The six latest earnings calls of the big networking, security, identity and observability vendors tell one demand story:
- **Cloudflare.** Matthew Prince expects agents to outnumber humans online "1,000 to 1" within five years, and would now bet on it happening sooner ([Cloudflare Q3 call](https://www.fool.com/earnings/call-transcripts/2026/11/06/cloudflare-net-q3-2026-earnings-call-transcript/)).
- **Palo Alto Networks.** Agentic traffic on its SASE network is "up approximately 9x year-over-year", all of which, it says, "require real-time inspection" ([PANW Q1 FY27 call](https://www.tradingkey.com/news/transcripts/262311927-)).
- **Datadog.** MCP tool calls are "up by a factor of 50 so far this year" ([Datadog Q3 call](https://www.fool.com/earnings/call-transcripts/2026/11/04/datadog-ddog-q3-2026-earnings-call-transcript/)).
- **Microsoft.** It has "over 50 million agents" in its registry, up more than 30% in a quarter ([Microsoft FY27 Q1 call](https://www.microsoft.com/en-us/investor/events/fy-2027/earnings-fy-2027-q1)).

Each vendor describes the buyer's job the same way: find the agents, limit what they reach, watch what they do, and pay by volume. Each assumes the watcher must see the content. Nikesh Arora calls the alternative a fantasy: a security product for an AI "I have no visibility into", which can somehow stop it, "is insane. It's not going to happen." He adds that "Cortex wins because we ingest it" ([PANW](https://www.tradingkey.com/news/transcripts/262311927-)). Zscaler presents "more than 750 billion transactions per day" of telemetry as its moat, and Datadog guards agents "on the same real-time data we collect to observe them" ([Zscaler Q4 FY26 call](https://www.tradingkey.com/news/transcripts/262150882-tradingkey); [Datadog](https://www.fool.com/earnings/call-transcripts/2026/11/04/datadog-ddog-q3-2026-earnings-call-transcript/)).

The money follows the reading:
- Prisma AIRS reached **nearly $170M in ARR in five quarters across more than 1,000 customers** ([PANW](https://www.tradingkey.com/news/transcripts/262311927-)).
- Arora expects "a 3% to 5% security spend associated with the tokens" ([PANW](https://www.tradingkey.com/news/transcripts/262311927-)).
- Zscaler's AI products are priced on consumption "linked to queries, essentially transferred to token consumption" ([Zscaler](https://www.tradingkey.com/news/transcripts/262150882-tradingkey)).

**A full-text search of all six transcripts found no executive statement on encryption, end-to-end protection, privacy, confidential computing or zero-knowledge. No analyst questioned the inspection model** ([earnings-call notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/earnings_calls.md)).

The vendors' own sites repeat the consensus. Across the 20 networking and agent-infrastructure companies, "identity" appears on 18 sites, "audit" on 19 and "MCP" on 16 ([vendor-site notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/sites_network_agent_infra.md)).

Only two kinds of vendor say they can't read anything:
- **The mesh vendors, about packets.** Tailscale says it "sees your metadata, not your data" ([Tailscale security](https://tailscale.com/security)).
- **doxx.net:** "Nothing to log. Nothing to know." ([doxx.net](https://www.doxx.net/)).

Among the networking, agent-infrastructure and observability vendors, every product above the transport layer is sold on seeing more:
- Tailscale's Aperture offers "full LLM session recordings" ([Tailscale pricing](https://tailscale.com/pricing)).
- Cloudflare's Gateway "will decrypt all traffic sent over HTTPS" ([Cloudflare](https://developers.cloudflare.com/cloudflare-one/traffic-controls/http-policies/tls-decryption/)).
- Composio's firewall "reads every tool result before your agent does" ([Composio](https://composio.dev/firewall)).
- Sentry records "both the inputs and outputs" of AI calls by default ([Sentry docs](https://docs.sentry.io/platforms/python/data-management/data-collected/)).

Elsewhere, privacy is sold as a place or a policy rather than as cryptography: self-hosting, your own cloud, a zero-retention setting. At Composio, zero data retention is "Not included" on the free plan ([Composio pricing](https://composio.dev/pricing)). Among the private-AI vendors, "verify, don't trust" through hardware enclaves (TEEs) has become a slogan shared by at least six companies ([observability and privacy notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/sites_observability_privacy.md)).

Three blind spots follow from the consensus:

1. **No one offers operator blindness above the transport layer, except by decrypting inside an enclave the vendor runs.** "No competitor in this corpus says 'end-to-end encrypted' about agent traces or observability data." NEAR AI's comparison row "Private observability" is the only place the two ideas meet ([observability and privacy notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/sites_observability_privacy.md); [NEAR AI](https://near.ai/)).
2. **The buyer on every call is an enterprise, but adoption is personal.** Okta watched one prospect go from 50 Claude agents to 1,500 in a few weeks ([Okta Q2 FY27 call](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf)). The only vendor pricing agents for individuals, doxx.net, charges $6 a month for one "AI agent seat" and $16 for five, and has no team tier ([doxx.net pricing](https://www.doxx.net/pricing/)).
3. **No analyst asks whether the inspector is itself an exposure.** Meanwhile, the community's loudest agent threads are about middlemen that read: xAI's Grok CLI uploading whole repositories (539 points), and Claude Code sending background agents' transcripts to its model (591 points) ([HN](https://news.ycombinator.com/item?id=48877371); [HN](https://news.ycombinator.com/item?id=50284255)).

One more pattern belongs here, as data rather than instruction: vendors now market to AI agents directly. Examples include Composio's hidden "For AI agents" block on every page, doxx.net's "Ask your agent to read config.doxx.net", NetBird's pre-filled assistant prompts and Langfuse's install-by-agent prompt ([vendor-site notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/sites_network_agent_infra.md); [Langfuse](https://langfuse.com/)). This report treats all such text as quoted material.

The biggest opportunities sit where those blind spots meet complaints that keep coming back.

| What everyone assumes | What the raw material shows | The opening |
|---|---|---|
| Securing agents means reading them | Users doubt the middle in five forms, and self-hosting is the only fix they name | A middle that can't read, and that customers can check |
| Agents belong to the enterprise | Agents spread one person at a time (50 to 1,500 Claude agents in weeks); OpenClaw sells "Your machines. Your data." | Sell to the person who runs agents, and let the team inherit it |
| Agents will be metered by traffic or tokens | Buyers "like the predictability" (Okta); reviewers resent hidden costs and credits spent on failed work | One price per person, with agents included |
| Private AI has to be weaker | Users leave over lost memory; the one paid choice in the threads turned on synced history | Private AI that remembers across devices |
| Privacy means where the data sits | Merck and Gumloop self-host to get it; a German doctors' association (HÄVG) can't use cloud AI at all | Self-hosting's guarantee without running the server |

## Winners sell to a person, stay switched on and admit what they see

Four things separate the products customers praise from those they leave. In each case the nearest competitors miss it.

**The buyer is a person before it is a company.**
- **Tailscale.** Its pricing page is headed "Plans that work for engineers, IT, security, and home users," and its free plan covers six users ([Tailscale pricing](https://tailscale.com/pricing)). Reviewers praise exactly that: getting past "the CGNAT imposed by my ISP" (the carrier-grade NAT that blocks incoming connections), not having "to open any firewall ports", and a free tier that "is perfect for me" ([Tailscale on Trustpilot](https://www.trustpilot.com/review/tailscale.com)).
- **The path from home to work.** One comment on Tailscale's Pricing v4 shows it: "I'm personally thrilled that the free plan now includes 6 seats, which is perfect for my home setup [...] it likely means I'll lose the ability to use Tailscale at work" ([HN](https://news.ycombinator.com/item?id=47692071)).
- **Team buyers object to packaging, not price.** They accept $6 to $18 a user, but not tiers where using ACLs (access control lists) "jumps 3x to $18/u/m" ([HN](https://news.ycombinator.com/item?id=43627559)).
- **Cloudflare.** Its developer platform carries "significantly lower cost to book" than its Zero Trust products, and it added 158,000 paying customers in the quarter ([Cloudflare](https://www.fool.com/earnings/call-transcripts/2026/11/06/cloudflare-net-q3-2026-earnings-call-transcript/)).
- **Inside companies too.** Datadog calls the explosion of coding agents "not planned largely" ([Datadog](https://www.tradingkey.com/news/transcripts/262275046-)).

The enterprise vendors miss this because their sales run the other way. Okta's CEO describes buyers "hesitant enough about buying a small vendor" who sit through "17 vendor meetings" ([Okta](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf)). The agent platforms address "technical teams" and "enterprise agents" ([Google](https://cloud.google.com/products/gemini-enterprise-agent-platform); [Microsoft](https://azure.microsoft.com/en-us/products/ai-foundry/agent-service/)).

**The secure product is the one people leave on.** Prince put it in one line: "the most secure Zero Trust platform inherently is the one people actually leave on." An incumbent's latency had become so bad "that many simply turned it off" ([Cloudflare](https://www.fool.com/earnings/call-transcripts/2026/11/06/cloudflare-net-q3-2026-earnings-call-transcript/)). Reviews show where products get turned off: on the phone.
- **Battery drain** appears in **11% of Tailscale's** 2025–26 App Store reviews in the sample and **18% of NetBird's**.
- **Disconnects** appear in **14% of Proton VPN's** and **17% of Mullvad's** ([review notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/customer_reviews.md)).
- **Reviewers separate the product from the app.** One review is titled "Tailscale is awesome. This app isn't." A Mullvad customer of nearly ten years quits because of "having to constantly disable the VPN just to be able to use your devices reliably" ([Tailscale reviews](https://itunes.apple.com/us/rss/customerreviews/page=1/id=1470499037/sortby=mostrecent/json); [Mullvad reviews](https://itunes.apple.com/us/rss/customerreviews/page=1/id=1488466513/sortby=mosthelpful/json)).
- **The requests repeat across apps:** widgets, state indicators, automations, and a warning when the tunnel drops, so the garage door doesn't silently fail to open ([Cloudflare One Agent reviews](https://itunes.apple.com/us/rss/customerreviews/page=1/id=6443476492/sortby=mostrecent/json); [Twingate reviews](https://itunes.apple.com/us/rss/customerreviews/page=1/id=1501686317/sortby=mostrecent/json)).

None of this reaches the homepages, which lead with replacing "your legacy VPN, SASE, and PAM" ([Tailscale](https://tailscale.com/)). URnetwork is exposed here. **The two largest themes in its own support inbox are disconnects and reconnects (556 mentions) and connection failures (484)** ([re-engagement research](file:///Users/brien/urnetwork/mmm/reengagement/RESEARCH.md)).

**Trust is conduct that customers check.**
- **What reviewers praise is honesty.** The privacy brands with the warmest reviews are praised for it rather than for features. Mullvad earns "Perfect honesty" and credit for "not being treated like a marketing funnel." Tailscale is credited for its exact admission about metadata ([Mullvad on Trustpilot](https://www.trustpilot.com/review/mullvad.net); [Tailscale security](https://tailscale.com/security)).
- **Careful vendors publish their limits:**
  - Venice: its anonymous mode's minus sign reads "Provider sees and likely saves your prompt" ([Venice](https://venice.ai/privacy)).
  - Tinfoil: a list of the network and billing metadata it keeps ([Tinfoil](https://tinfoil.sh/security-and-privacy-faq)).
  - NEAR AI: an incident report admitting that requests "running in confidential mode" could have been observed ([NEAR AI](https://near.ai/blog/security-incident-report-sglang-vulnerability)).
- **One shock drains the balance.** In the sample of Proton Mail App Store reviews dated 20 October or later, 13 of 77 cite the controversy over its CEO, one titled "No longer a trustworthy product." Proton holds a Trustpilot score of 2.0 from 1,838 reviews, against 4.75 in the App Store ([Proton Mail reviews](https://itunes.apple.com/us/rss/customerreviews/page=2/id=979659905/sortby=mostrecent/json); [Trustpilot](https://www.trustpilot.com/review/proton.me?sort=recency)).
- **Willingness to pay attaches to guarantees, not features.** In the threads, people offer:
  - $125 a person for a team password manager "without creating a single point of failure in a SaaS company" ([HN](https://news.ycombinator.com/item?id=50646212));
  - $10 a month for a mail provider "who would go to jail for me" ([HN](https://news.ycombinator.com/item?id=47268464));
  - a fee to Tailscale "if they could review thr code" ([HN](https://news.ycombinator.com/item?id=50265512)).

**Customers want to read their agents' record; vendors bundle that with their own reading.** Observability buyers value seeing the whole run: being able to "trace problems through the entire prompt path", or else "flying blind" ([LangSmith reviews](https://www.producthunt.com/products/langsmith/reviews); [Langfuse reviews](https://www.producthunt.com/products/langfuse/reviews)). Case studies use the same picture:
- Twine: "black box of logic" ([Datadog](https://www.datadoghq.com/case-studies/twine/));
- PagerDuty: "Agents are a black box." ([Arize](https://arize.com/customers/pagerduty-ai-agent-quality-monitoring/));
- Merck: "see what's happening under the hood" ([Langfuse](https://langfuse.com/users/merckgroup)).

Okta sells the same need to regulated buyers as "a verifiable record that can satisfy client and regulator requirements" ([Okta](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf)). Every hosted vendor delivers it by holding the record. Only buyers who self-host escape: Merck kept pharmaceutical data "within their own infrastructure", and Gumloop self-hosts for "data residency" ([Merck](https://langfuse.com/users/merckgroup); [Gumloop](https://e2b.dev/customers/gumloop-case-study)). **No observability vendor in either corpus offers a hosted record its operator can't read.** The nearest thing is a comparison row labelled "Private observability" on a confidential-AI vendor's page ([NEAR AI](https://near.ai/)).

## Four assumptions the industry never tests

**Assumption 1: securing agents requires the vendor to read them.** It is the premise of every enterprise call and every agent-layer product, and it pays, because inspection is priced by the token ([PANW](https://www.tradingkey.com/news/transcripts/262311927-); [Zscaler](https://www.tradingkey.com/news/transcripts/262150882-tradingkey)). Arora's argument deserves its strongest form: a guard that can't see a prompt can't stop a prompt injection. That is why Composio inspects every tool result ([Composio](https://composio.dev/firewall)).

If the assumption is wrong, it will be because the inspector becomes the exposure, and the strain already shows:
- **Controls that need no content.** The vendors' own frameworks lean that way: Microsoft's "separate intelligence from authority", Okta's tokens and delegation, and enforcement "outside the model where a prompt can't undo it" from Arcade, Pomerium and AWS ([Microsoft](https://www.microsoft.com/en-us/investor/events/fy-2027/earnings-fy-2027-q1); [Arcade](https://www.arcade.dev/); [Pomerium](https://www.pomerium.com/); [AgentCore](https://aws.amazon.com/bedrock/agentcore/faqs/)).
- **Sovereignty answered by yet another vendor.** Enterprises want their data "inside their own 4 walls" and ask "Can I own the weights?" ([PANW](https://www.tradingkey.com/news/transcripts/262311927-); [Microsoft](https://www.microsoft.com/en-us/investor/events/fy-2027/earnings-fy-2027-q1)). The vendors answer by putting one more trusted party in the path.
- **Doubt about the middle, in five forms.** They run from key negotiation that "there's no way to verify" to TLS that Cloudflare will "strip and optionally re-add" ([HN](https://news.ycombinator.com/item?id=43631012); [HN](https://news.ycombinator.com/item?id=45948083)).

If the premise fails, revenue tied to a share of token spend becomes a liability. Enforcement then moves to the device and the authorization layer, where a network that can't read can still decide who reaches what and hold each outward action for approval. URnetwork's design does this with device admissions that only an admin's device signs, and approvals for an agent's outward actions ([DESIGN-COMPUTE.md](file:///Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md); [DESIGN-UI.md](file:///Users/brien/urnetwork/sidecar/DESIGN-UI.md)).

**Assumption 2: agents belong to the enterprise.** On the calls they are delegated identities of employees, governed by IT and wrapped in "a kill switch" ([Okta](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf)). The opposite view has a large following:
- OpenClaw sells "Your memories. Your skills. Your models. Your machines. Your data." and counts 3,606 contributors and 83,000 forks ([OpenClaw](https://openclaw.ai/); [OpenClaw blog](https://openclaw.ai/blog/openclaw-isnt-free)).
- An HN thread arguing that CLI agents make running a home server easier drew 775 points ([HN](https://news.ycombinator.com/item?id=46580326)).

If agents are personal tools first, the first purchase is a person's. Agent security is then bought like a developer tool: self-serve, free to start, judged by trying. OpenClaw's own admission that it is "not a hostile multi-tenant security boundary" marks the gap such a buyer feels ([OpenClaw docs](https://docs.openclaw.ai/gateway/security.md)).

**Assumption 3: buyers will accept metering by traffic or tokens.** Okta keeps per-user pricing because customers "like the predictability" "for now" ([Okta](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf)). Elsewhere, metered bills draw complaints:
- Datadog reviewers who score it 8 or 9 out of 10 still ask for pricing that is "more predictable" and warn of "hidden costs" ([PeerSpot](https://www.peerspot.com/products/datadog-reviews)).
- Manus customers watch credits "decreasing even when I am not receiving the results I actually paid for" ([Trustpilot](https://www.trustpilot.com/review/manus.im)).
- A Venice user "wasted over 24,900 credits for failed work using Agent AI" ([Trustpilot](https://www.trustpilot.com/review/venice.ai)).

If buyers keep preferring predictable bills, a per-person price with agents included wins small teams. The margin risk is the one Arora names: more traffic "increases COGS" ([PANW](https://www.tradingkey.com/news/transcripts/262311927-)).

**Assumption 4: private AI must be weaker.** In consumer AI, everyone accepts that privacy costs capability:
- Lumo is "far less capable" ([Lumo reviews](https://itunes.apple.com/us/rss/customerreviews/page=2/id=6746714949/sortby=mostrecent/json)).
- Venice has "no real memory or recall" ([Venice reviews](https://itunes.apple.com/us/rss/customerreviews/page=6/id=6742061900/sortby=mostrecent/json)).
- Venice's own end-to-end mode has "No web search or memory" ([Venice](https://venice.ai/privacy)).
- Local models are "5 to 10 years away" for the people who want them ([HN](https://news.ycombinator.com/item?id=46606965)).

Users accept the trade as the price of privacy: "I understand that the privacy helps but having to start over each and every time [...] is rather annoying" ([Venice reviews](https://itunes.apple.com/us/rss/customerreviews/page=2/id=6742061900/sortby=mostrecent/json)). Then they leave over it. If the assumption is wrong, the main reason to leave disappears. The one paid choice in the threads already turned on it: "I chose Lumo+ because chat history is stored with my Proton data and is available in all my devices" ([HN](https://news.ycombinator.com/item?id=47165755)).

## Nine complaints recur everywhere and still lack a fix

The complaints below repeat across review sites, Hacker News, the Privacy Guides forum and GitHub trackers. People keep naming partial fixes, and each fix comes back with a "but" in the same threads.

| Complaint | How often and how loudly | What people use now, and its "but" | What URnetwork's design offers |
|---|---|---|---|
| The middle can't be verified, only trusted | Networking alone has five forms: unverifiable key negotiation, unsigned policy files, closed clients, logs uploaded by default, TLS stripped at the edge ([HN](https://news.ycombinator.com/item?id=44152846); [HN](https://news.ycombinator.com/item?id=50105362)). The same doubt reaches Lumo, Confer, 1Password and Proton ([HN](https://news.ycombinator.com/item?id=44664851); [Privacy Guides](https://discuss.privacyguides.net/t/thoughts-on-confer-to-ai-by-the-creator-of-signal/41574/4)) | Tailnet Lock (Tailscale's node signing); Headscale, which is still not "security audited" ([HN](https://news.ycombinator.com/item?id=43564441)); TEEs, where "a compromise of the TEE would mean your data is exposed" ([HN](https://news.ycombinator.com/item?id=46606289)) | Only an admin's device can sign a new device in. Roles are compiled into a signed policy. The TLS edge holds no key. All of it stays a promise until audited |
| Secrets leak into agents | 474 reactions for a way to stop Codex reading `.env` and key files ([GitHub](https://github.com/openai/codex/issues/2847)); 216 for secrets in Claude Code on the web ([GitHub](https://github.com/anthropics/claude-code/issues/32733)); "commit secrets or don't share" ([GitHub](https://github.com/anthropics/claude-code/issues/28942)) | Credential proxies, which still leave "a confused-deputy boundary" ([HN](https://news.ycombinator.com/item?id=49366194)); builders say "nothing like this exists" ([HN](https://news.ycombinator.com/item?id=47890495)) | OAuth tokens sealed in encrypted storage and used only through tools; agents never see a token ([DESIGN-COMPUTE.md](file:///Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)) |
| Harnesses ship work upstream | Grok's CLI uploading whole repositories, 539 points; Claude Code's background transcripts, 591 points ([HN](https://news.ycombinator.com/item?id=48877371); [HN](https://news.ycombinator.com/item?id=50284255)) | Sandboxes, and "separate the coding tools from LLM providers" ([HN](https://news.ycombinator.com/item?id=48878024)) | A local harness and a model router that routes without reading. The model's provider still reads whatever it is sent |
| Self-hosting is the fix, and it breaks | Self-hosted NetBird failed for "10-15% of users" ([HN](https://news.ycombinator.com/item?id=46846275)); self-hosting is "a very demanding hobby" ([HN](https://news.ycombinator.com/item?id=46582112)); "afraid of the self-hosting (of something this critical)" ([HN](https://news.ycombinator.com/item?id=49546970)) | Headscale, NetBird, Vaultwarden, KeePass, local models | The core offer: a managed service whose operator can't read |
| Mobile clients drain batteries and drop silently | Battery in 11% of Tailscale's and 18% of NetBird's recent App Store reviews; disconnects in 14% of Proton VPN's and 17% of Mullvad's ([review notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/customer_reviews.md)) | Shortcuts that toggle the tunnel; turning it off | Also URnetwork's own top support theme: a weakness to fix, not a selling point |
| Automated lockouts with no human to appeal to | Paying SimpleLogin users banned with no path back; a Proton user who "lost 8 years of photos"; encrypted medical data made "inaccessible" ([SimpleLogin on Trustpilot](https://www.trustpilot.com/review/simplelogin.io); [Proton on Trustpilot](https://www.trustpilot.com/review/proton.me?sort=recency)) | Regular encrypted exports "in case of a more catastrophic bug" ([Bitwarden reviews](https://itunes.apple.com/us/rss/customerreviews/page=1/id=1137397744/sortby=mosthelpful/json)) | A human support conversation in the app. Device-held keys make recovery design decisive |
| Billing traps, and credits spent on failed work | 94 of 284 review excerpts are tagged price; a bill of "~10x" the plan's price; 31,132 credits that expired ([Datadog on Trustpilot](https://www.trustpilot.com/review/datadoghq.com); [Manus on Trustpilot](https://www.trustpilot.com/review/manus.im)) | Leaving | A flat Team price, with each new seat approved by an admin. Bot's compute balance is itself a credit model and must avoid the same surprises |
| Alias addresses get blocked | 529 and 607 points on Apple's Hide My Email ([HN](https://news.ycombinator.com/item?id=48559935); [HN](https://news.ycombinator.com/item?id=49426564)); a 2026 Privacy Guides thread asks whether to give up on email privacy ([Privacy Guides](https://discuss.privacyguides.net/t/do-i-step-back-from-email-privacy/35019/1)) | Custom domains: "the only lasting solution is to put them on the same domain as [...] non-private email addresses" ([HN](https://news.ycombinator.com/item?id=49428288)) | Burner's per-use addresses sit on `ur.network` subdomains, the shape that gets blocked. Custom domains are a Team feature |
| Private AI forgets | "no real memory or recall"; "start over each and every time" ([Venice reviews](https://itunes.apple.com/us/rss/customerreviews/page=6/id=6742061900/sortby=mostrecent/json)) | Paying for the one service whose history syncs ([HN](https://news.ycombinator.com/item?id=47165755)) | Bot's sessions live in encrypted storage and follow the person across devices and harnesses ([DESIGN-UI.md](file:///Users/brien/urnetwork/sidecar/DESIGN-UI.md)) |

URnetwork's design answers four of these directly: the unverifiable middle, secrets in agents, self-hosting that breaks and forgetful private AI. It answers harnesses that ship work upstream only up to the model's provider. It shares three of the industry's weaknesses: mobile reliability, lockouts and credit billing. It is exposed on blocked aliases. None of the complaints asks for a bundle. The research found no thread asking for a VPN, alias email, password manager and private AI in one product ([community notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/community_complaints.md)). That warns against selling the bundle as the idea.

## Four rounds narrow "an encrypted agent network" to "the person who runs agents"

The strongest hypothesis that follows from the gap is the one URnetwork's campaign plan already holds. **Round 1's hypothesis:** teams adopting agents will choose an end-to-end encrypted network and toolkit, with:
- private addresses;
- a TLS edge that holds no keys;
- encrypted storage and mail;
- a model router that doesn't read;
- a record that only the team can read.

They will choose it because every incumbent reads their agents' content, and URnetwork can reach developers, product leaders, IT and security buyers through its product-update list ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)). Each round below states the hypothesis, makes the strongest case an investor would make for it, shows where it breaks, and revises it.

| Round | Hypothesis | Strongest case | Where it breaks | Revision |
|---|---|---|---|---|
| 1 | An encrypted network and toolkit for teams adopting agents, sold to four buyer types on the list | Incumbents earn by reading, so they can't follow; the position is uncontested | Mainstream buyers equate security with seeing; the list holds few such buyers | Aim at people who already demand a middle that can't read |
| 2 | Self-hosting's guarantee as a managed service for privacy-first technical people | A named workaround with known costs, and feature requests that match the design | Self-hosters want verification, not promises; small teams get a mesh network free; transport encryption is standard | Move above the transport layer, and make verification part of the product |
| 3 | A workspace for agents on your own machines that no operator can read | Stated demand for an agent workspace; secrets and harness uploads are the loudest pains | A crowded "the agent never sees the secret" field; the model's provider still reads; demand for agent networking comes from vendors | Anchor on the audience's revealed preference, lead with jobs, narrow the claim |
| 4 | Privacy-first agent users first, their teams second | Fits the winners' patterns, the audience and the unfixed complaints | Segment size, the trust deficit, reliability | Final, conditional on the tests below |

### Round 1: an encrypted agent network for four kinds of buyer

**The case for it.** A top-tier investor would call this the cleanest innovator's dilemma in security:
- **Agents are a new user population:** 1,000 to 1, 9x, 50x, 50 million.
- **The budget is flowing.** Zscaler's security-for-AI bookings rose more than 50% in a quarter with "no budget constraints", and PANW's AI security product reached $170M in ARR in five quarters ([Zscaler](https://www.tradingkey.com/news/transcripts/262150882-tradingkey); [PANW](https://www.tradingkey.com/news/transcripts/262311927-)).
- **The incumbents can't follow.** Their revenue is tied to reading, so they can't sell "we can't see it" without cutting their own meter.
- **The position is uncontested** on the calls, and on the sites only the enclave vendors come close.
- **The fears are real.** 81% of the CISOs Okta talks to know they are exposed, Prince describes them as panicking, and buyers ask for sovereignty ([Okta](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf); [Cloudflare](https://www.fool.com/earnings/call-transcripts/2026/11/06/cloudflare-net-q3-2026-earnings-call-transcript/)).
- **URnetwork brings distribution and price:** a base of people who already bought "they shouldn't see my traffic", and a price of $10 for three seats with the team's own identity provider ([DESIGN-UI.md](file:///Users/brien/urnetwork/sidecar/DESIGN-UI.md)).

**Where it breaks: the buyer.**
1. **The people who hold enterprise security budgets equate security with seeing.** Arora calls blindness "insane", Zscaler says "identity is only the starting point", Microsoft deploys "guardian agents", and no analyst asked about vendor access.
2. **Customers buy simplicity, speed and scale, not confidentiality.**
   - In case studies they cite deployment that's "easier to deploy, setup, and maintain", "up and running in two hours", and capacity, almost never confidentiality ([Kooapps](https://www.twingate.com/customers/kooapps); [Turo](https://goteleport.com/case-study/turo/); [Lovable](https://modal.com/blog/lovable-case-study)).
   - Reviews of LangSmith and Langfuse never mention who reads traces ([review notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/customer_reviews.md)).
   - In Stack Overflow's 2026 survey, **only 2.2% of developers who switched AI tools did so for security, privacy or compliance** ([Stack Overflow 2026](https://survey.stackoverflow.co/2026/ai)).
3. **Enterprises reject small vendors and buy platforms.** Okta describes the reluctance, and Prince says customers are "buying the overall platform of Cloudflare" ([Okta](https://s205.q4cdn.com/566291348/files/doc_financials/2027/q2/Okta-Q2-FY27-Earnings-Call_Transcript.pdf); [Cloudflare](https://www.fool.com/earnings/call-transcripts/2026/11/06/cloudflare-net-q3-2026-earnings-call-transcript/)).
4. **URnetwork's list can't deliver these buyers.**
   - **94.9% of its 128,653 networks are seed-phrase accounts with no email, and 4.0% have an email login** ([re-engagement plan](file:///Users/brien/urnetwork/mmm/reengagement/PLAN.md)).
   - Sign-up farms have made most email sign-ups since 9 November ([onboarding README](file:///Users/brien/urnetwork/mmm/onboarding/README.md)).
   - The support inbox is dominated by consumer VPN problems: disconnects, connection failures, payouts and subscription payments ([re-engagement research](file:///Users/brien/urnetwork/mmm/reengagement/RESEARCH.md)).

**Revision:** aim at people who already demand that the middle be blind, and who pay for it today with their own time by self-hosting.

### Round 2: self-hosting's guarantee, sold as a service

**Hypothesis.** Privacy-first technical people who self-host to keep the middle blind (Headscale, self-hosted NetBird, Vaultwarden or KeePass, local models) will move to URnetwork. It gives them self-hosting's guarantee as a managed service that just works, free for one person and $10 for three.

**The case for it.** This is a wedge with a named workaround and a known cost, which is the best kind:
- **The workaround is everywhere.** "I self-host a tailnet with Headscale and could not be happier" ([HN](https://news.ycombinator.com/item?id=50265373)).
- **Its costs are well documented.** Headscale has no audit, self-hosted NetBird failed for 10 to 15% of one organization's users, and a demanding hobby is only fun until "critical problems hit" ([HN](https://news.ycombinator.com/item?id=43564441); [HN](https://news.ycombinator.com/item?id=46846275); [HN](https://news.ycombinator.com/item?id=46582112)).
- **The requests match URnetwork's design almost line by line:**

  | What users ask for | URnetwork's design |
  |---|---|
  | To sign the tailnet policy file ([HN](https://news.ycombinator.com/item?id=44152846)) | Roles written into a signed policy |
  | To verify who negotiates keys | Admissions only an admin's device can sign |
  | TLS not stripped at the edge | An edge that routes by name and holds no key |
  | Enrollment keys that aren't "way over powered" ([HN](https://news.ycombinator.com/item?id=49130351)) | Auth keys limited by role, uses and expiry ([DESIGN-UI.md](file:///Users/brien/urnetwork/sidecar/DESIGN-UI.md)) |

- **The incumbent is giving cause.**
  - Tailscale's Pricing v4 put tagged and ephemeral devices (how servers and agents join a network) behind "Contact Sales", which one user called "a classic bait-and-switch" ([HN](https://news.ycombinator.com/item?id=47692253)).
  - Its users worry about "a rug pull" (22 replies) ([HN](https://news.ycombinator.com/item?id=47063593)).
  - Its October SSH incident sent commenters back to stock OpenSSH ([HN](https://news.ycombinator.com/item?id=50266168)).
- **The audience is already adjacent.** VPN users already pair a privacy VPN with a mesh network: "paired with a mullvad exit node this service is incredible" ([Tailscale reviews](https://itunes.apple.com/us/rss/customerreviews/page=2/id=1470499037/sortby=mostrecent/json)).

**Where it breaks.**
1. **Self-hosters are the hardest people to sell a managed service to.** What they want is not a better promise but no promise to rely on. "Can't verify the middle" applies to URnetwork the moment it becomes the middle, and the pay signal is literally for code review.
2. **URnetwork can't meet that bar yet.** It has no independent audit, and as of 31 October its site claimed "100% open source and reproducible" while its client repository called itself "Open core" ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)). This segment is the one most likely to notice.
3. **At two to six people, the competition is free.** Tailscale's Personal plan covers six users, and homelab reviewers praise its free tier first ([Tailscale pricing](https://tailscale.com/pricing); [Tailscale on Trustpilot](https://www.trustpilot.com/review/tailscale.com)).
4. **A network-first wedge fights where URnetwork is weakest.** Every mesh network already says it can't read packets. Tailscale has an App Store average of 4.39 from 808 ratings and "60,000 businesses", while URnetwork's own support inbox leads with disconnects ([Apple lookup](https://itunes.apple.com/lookup?id=6443490629,979659905,1437005085,6746714949,1494359858,1511601750,1137397744,663592361,1488466513,1470499037,1423538627,6443476492,1084101492,1501686317,6469329339,6742061900,1391380318&country=us); [Tailscale](https://tailscale.com/)).

**Revision:** move the wedge above the transport layer, to the agent layer where no one offers blindness, and make verification part of the product.

### Round 3: a workspace for agents on your own machines

**Hypothesis.** People who run agents on their own machines need a workspace for them:
- an address;
- HTTPS on their own domain;
- a mailbox;
- credentials the agent never sees;
- a router to any model;
- a record of what each agent did.

URnetwork is the only place where no operator can read any of it.

**The case for it.** The demand is stated in users' own words:
- **A thread asks for exactly this.** It wants an agent that "just works as software with its own email, calendaring", describes "a common workspace for me and my agent", and puts a price on it: "Hiring a part time admin is a couple thousand a month. I would pay half that" ([HN](https://news.ycombinator.com/item?id=50392586); [HN](https://news.ycombinator.com/item?id=50412683); [HN](https://news.ycombinator.com/item?id=50394143)).
- **Secrets are the most-voted complaint, and the design answers it.** Tokens stay sealed and agents act through tools.
- **The answer users adopt for harness uploads is this design's shape.** The two biggest agent-privacy threads of the half-year are about harnesses shipping work upstream, and people's answer, "separate the coding tools from LLM providers", is a local harness plus a router.
- **The record has buyer language behind it, and no observability vendor offers it unreadable to the vendor.**
- **The demand for agents on one's own machines is proven.** OpenClaw's 83,000 forks show it, and its admitted lack of isolation shows the gap.
- **The incumbents can't follow without giving up the meter.** The pricing contrast is sharp:
  - Tailscale charges for the devices agents join as ([Tailscale pricing](https://tailscale.com/pricing)).
  - doxx.net sells "AI agent seats" ([doxx.net pricing](https://www.doxx.net/pricing/)).
  - In URnetwork's seat model, agents take no seat ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)).

**Where it breaks: three cracks.**

1. **The workspace is filling fast with companies promising that the agent never sees the secret.** Sealed credentials are no longer unique; only the combination is, and buyers buy jobs, not combinations. Okta's CEO says "we're competing against confusion".
   - 1Password for Agents "is included in all Individual and Family plans" ([1Password](https://1password.com/personal-ai-agent-integrations)).
   - Bitwarden has its Agent Access SDK ([Bitwarden](https://bitwarden.com/blog/introducing-agent-access-sdk/)).
   - Tinfoil's Bunkers keep "everyone else out, including us" ([Tinfoil](https://tinfoil.sh/bunkers)).
   - Confer has confidential workers ([Confer](https://confer.to/blog/2026/09/confidential-workers-for-private-ai/)).
   - Open-source credential gateways keep launching ([HN](https://news.ycombinator.com/item?id=47890495)).
2. **The largest reader stays in place.** Whatever an agent sends a remote model, that model's provider reads.
   - URnetwork's own Bot page says a TEE provider "is trusted not to attack it" ([ui-site mockup](file:///Users/brien/urnetwork/sidecar/design/mocks/ui-site.html)).
   - NEAR AI's incident showed confidential-mode requests could be observed through software running inside the enclave ([NEAR AI](https://near.ai/blog/security-incident-report-sglang-vulnerability)).
   - Local models are the only fully private path, and reviewers find private assistants weaker: Lumo "complements ChatGPT [...] but certainly doesn't replace it" ([Lumo reviews](https://itunes.apple.com/us/rss/customerreviews/page=3/id=6746714949/sortby=mostrecent/json)).

   So "nobody can read your agents' work" is false. The honest claim is "no URnetwork server can", with every other reader labelled.
3. **The demand for agents inside private networks has so far come from vendors.** Tailscale's Aperture launch was met with "a random grasp at 'build something, anything, AI related'" (12 replies) and "I certainly don't trust them to manage my secrets" ([HN](https://news.ycombinator.com/item?id=46783825); [HN](https://news.ycombinator.com/item?id=46789115)). The workspace thread had 4 points and 20 comments. Whether URnetwork's list holds people who run agents at all is unknown.

**Revision:** anchor on the audience URnetwork actually has and what it already pays for. Lead each product with its job, narrow the claim, and make verification and conduct part of the product.

### Round 4: the person who runs agents, then the team

**Hypothesis.** The final version, stated in full in the next section: privacy-first people who run agents adopt a private workspace for themselves and their agents on their own machines, and a subset bring it to work as Team.

**The case for it.**
- **It fits all four things winners understand:** sell to the person first, build the product that stays on, admit what you see, and let the customer read its own record.
- **It fits what the audience already pays for.** They pay a VPN to "transfer the trust of your internet activity" away from their ISP ([HN](https://news.ycombinator.com/item?id=48144195)).
- **It answers the unfixed complaints URnetwork can answer:**
  - secrets kept from agents;
  - private AI that forgets;
  - a login and address for every site, at a time of password-manager price rises, 1Password's $35.88 to $47.88 and Bitwarden Premium's $10 to $19.80 ([HN](https://news.ycombinator.com/item?id=47140589); [Bitwarden forum](https://community.bitwarden.com/t/bitwarden-launches-enhanced-premium-plan/93006/8));
  - self-hosting that breaks.
- **The timing is good.**
  - The privacy audience's largest brand is shaken.
  - The 1Password security incident drew 1,695 points and talk of moving ([HN](https://news.ycombinator.com/item?id=50644817)).
  - The incumbents' business models discourage copying.
- **Acquisition is cheap.** Bot and Burner are tabs in an app the audience already has, and the owner has already chosen the product, content and an opt-in list over bought lists ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)).

**What could still break it.**
- **The segment may be small.** The audience leans consumer, and many of its users live in countries URnetwork does not market to ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md); [re-engagement research](file:///Users/brien/urnetwork/mmm/reengagement/RESEARCH.md)).
- **The trust deficit hits hardest here.** This segment is the most likely to read the exit network's history.
- **Reliability.** URnetwork's own support inbox leads with disconnects.
- **Bundle overreach has punished others.** Proton's reviewers call its suite's bugs "overreach" ([Proton VPN reviews](https://itunes.apple.com/us/rss/customerreviews/page=2/id=1437005085/sortby=mosthelpful/json)).
- **Prices are anchored at zero.** One user writes "Apple Passwords for $0 is a pretty easy switch" ([1Password Community](https://www.1password.community/1password-at-home-31/what-justifies-the-huge-subscription-price-increase-24103)).

These become the conditions and falsifiers below.

## The final bet, how sure to be, and what would kill it

**Final hypothesis:**
- **Who.** Among URnetwork's privacy-first users, the people who already let AI agents act for them, chiefly developers, founders and consultants on desktop clients and Pro plans.
- **What they adopt.** A private workspace for themselves and their agents, on their own machines.
- **Why: the job.** It does jobs they now patch together:
  - reach their machines and agents from anywhere;
  - publish on their own domain with the key on their own machine;
  - keep tokens out of agents' hands;
  - keep an address and a login for every site;
  - keep an AI history that follows them across devices.
- **Why: the rule.** No URnetwork server can read any of it. Privacy decides whether they trust it; the job decides whether they adopt it.
- **What makes them believe it.** Only checkable admissions (what URnetwork's servers see, who else reads what) and visible separation from the VPN's exit network.
- **Team is the second sale.** Those who work with others bring the workspace to work as a three-seat Team, because agents take no seat and only their admins' devices can let a device in.

| Part of the hypothesis | Confidence | Why |
|---|---|---|
| No product offers operator blindness above transport without decrypting in an enclave the vendor runs, and incumbents are discouraged from building one | High | Six calls, 42 vendor sites, pricing tied to reading, and no executive mention of encryption |
| Privacy works as the gate, and the job as the reason to adopt | High | Privacy is why reviewers try private AI and capability is why they leave; case studies cite speed and simplicity; 2.2% switched AI tools for security |
| Privacy-first technical people want this and will pay something | Moderate | Repeated high-scoring threads, but the pay signals are individual comments, not surveys ([community notes](file:///Users/brien/urnetwork/sidecar/research_notes/Private%20agent%20network%20market%20hypothesis/community_complaints.md)) |
| URnetwork's app and list hold enough of them | Low | No data on agent use; 4.0% have an email login; sign-up farms; consumer-heavy support themes |
| They will believe URnetwork's claim | Low to moderate | Depends on the footprint fixes the owner has already ordered; this audience punishes trust shocks |
| One person pulls a team onto three seats for $10 | Low | No direct evidence, and free tiers cover small teams |

Taken together, the evidence makes the gap close to certain, and makes the market roughly a coin flip that leans slightly against. My judgment is that the chance the conversations confirm a reachable segment is about 40%. The hypothesis is wrong if most of the following happen:

| Signal that would prove it wrong | Threshold | Where it shows up |
|---|---|---|
| Few agent users | Fewer than 1 in 5 desktop or Pro interviewees let an AI tool act on their files, accounts or servers in the past month; under 10% of launch answers pick agents | Conversations; the launch email's one-tap answers |
| Privacy is not even a gate | Fewer than 1 in 3 raise exposure without being asked, and none has a workaround (a sandbox, a separate provider, self-hosting, refusing to connect accounts) | Conversations |
| The person can't bring it to work | Most who work with others name an approver who requires an audit or SOC 2 report, or a free mesh network already in place | Conversations; reply emails |
| Trust breaks on the exit network | More than 1 in 4 raise scraping, proxies or the exit network as a reason not to believe the claim | Conversations; reply emails |
| The jobs don't stick | The CLI stays on one device; Bot users never start an agent or a remote harness; per-site addresses are abandoned after sites refuse them | Product data after launch |
| Team doesn't follow | Teams created within 21 days don't beat the 10% holdout; invited teammates average under one per team | Campaign readout ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)) |

## Twenty-four conversations, recruited in the product, before the first send

The email list is a weak tool for finding these people. Only 4.0% of networks can be emailed, recent email sign-ups are mostly farms, and the house rules exclude experiment holdouts and networks without consent evidence ([re-engagement plan](file:///Users/brien/urnetwork/mmm/reengagement/PLAN.md); [PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)). The product is better. The server knows each network's platform, plan, country, last connection and the bot-or-human label, and the app reaches the 94.9% who have no email. Recruit from those signals, invite seed-phrase users in the app, and email only readers the campaign rules already allow. Offer a thank-you that does not depend on what anyone says.

| Group | Who | Where to find them | Count | What it tests |
|---|---|---|---|---|
| 1 | Pro subscribers on desktop or CLI clients, active in the last 30 days | Plan, platform and last connection on the server; an in-app invitation for seed-phrase accounts | 8 | Agent use, the jobs, unprompted privacy behaviour, pull toward a team |
| 2 | Human email-login readers at company domains | The Team launch's "likely at work" filter, minus bot-labelled sign-ups and holdouts | 6 | Who approves tools, the trust bar, price, team size |
| 3 | People who use URnetwork's agent or API access for personal use | Accounts that use the API or the agent skill, where the server records it | 4 | Whether they run agents of their own or use the exits to scrape, which is the footprint risk |
| 4 | Privacy consumers, lapsed and active, on phones | The Burner and Bot re-engagement audience; in-app for the rest | 4 | Burner (aliases, switching password managers, blocking) and Bot (private AI, memory) |
| 5 | Non-users who opt in, likely self-hosters | The "Tell me when Team launches" box and readers of the launch post | 2 to 4 | Whether a managed service that can't read beats self-hosting |

The numbers follow two classic studies. In one, interviews in a fairly uniform group reached saturation by about 12, with the basic themes in place by 6 ([Guest, Bunce and Johnson, 2006](https://doi.org/10.1177/1525822X05279903)). In the other, 20 to 30 interviews found 90 to 95% of customer needs ([Griffin and Hauser, 1993](https://doi.org/10.1287/mksc.12.1.1)). Neither study is part of the research notes. Run two waves of 12:
- **Wave 1:** groups 1 and 2, before the Team email goes out.
- **Wave 2:** the remaining groups, plus people whose launch answer was "My AI agents" or "Something else".

The role page the answer links to can carry the invitation. Stop a group when two interviews in a row add no new job, workaround or objection.

The guide follows one rule: ask about what people did, never about what they would do. Don't name encryption, privacy or agents until the interviewee does, and count how often they raise them unprompted.

| Part | Ask, in these words | What it tests | Avoid |
|---|---|---|---|
| Context | "What do you use URnetwork for, and when did you last connect?" | Whether they use the VPN, provide bandwidth or use the proxies | Mentioning Team |
| Machines | "Walk me through the machines and services you look after, for yourself or for work. What's the last thing you had to reach from somewhere else, and how did you do it?" | The network job and the current tool | Naming any product |
| AI that acts | "Tell me about the last time an AI tool did something for you rather than just answering. What did it touch?" | Agent use, in their words | The word "agent" before they use it |
| Access | "What did you have to give it to do that, and how did you give it? Is there anything you didn't let it touch? Why?" | Secrets, workarounds, unprompted privacy concerns | Suggesting risks |
| The record | "Afterwards, how did you find out what it actually did? Who else could see that?" | The value of the record; whether the vendor seeing it matters | "Would you want..." |
| Workarounds | "What have you set up or self-hosted yourself because you didn't want a company in the middle? How's that going?" | How painful self-hosting is | Agreeing with complaints |
| Switching | "What's the last tool you stopped using, and why?" | Switching triggers: price, trust shocks, reliability | Leading options |
| Money | "What do you pay for today for this: VPN, passwords, email, AI, hosting? Which would you cut first?" | Price anchors | Quoting URnetwork's prices |
| Team | "Who else would need these machines or agents? Who decides what your team uses, and what did they ask the last time you brought in a tool?" | Whether the person can pull a team in, and who approves | Assuming they are the buyer |
| Trust | "When a company says it can't read your data, what do you check before you believe it?" Then, last: "Some people know URnetwork for its exit network. Does that change how you'd judge that claim?" | The trust bar and the footprint risk | Defending URnetwork |
| Burner and Bot (group 4) | "When did you last sign up with an address you didn't want to give? Has a site ever refused an alias? What would make you move your passwords? Do you use an AI chat you consider private, and what made you start or stop?" | Alias blocking, switching password managers, why people leave private AI | Describing Burner or Bot first |
| Close | Show the product only now: "Would you install it on two machines this week and tell me what broke? Can you introduce me to whoever approves tools?" | Commitment, the strongest signal | Counting compliments |

These answers would change the plan:

| If the conversations show | Then |
|---|---|
| Fewer than 1 in 5 in groups 1 and 2 have an AI acting on their files, accounts or servers | Lead Team with machines, files and the own-domain job. Drop the agent record from the launch. Pitch Bot as a private chat that remembers |
| Privacy comes up unprompted for fewer than 1 in 3 | Keep privacy to the one keys sentence. Send the security follow-up only to readers who pick it, and lead on the job and price |
| More than 1 in 4 distrust URnetwork because of the exit network | Turn the separation the owner ordered (Q-OB-1) into a separate domain or brand for Team before launch |
| Most small-company interviewees name an approver who needs an audit | Hold Team outbound to company domains until the trust page shows a dated audit plan; promote personal CLI and Bot use meanwhile |
| Burner interviewees report sites refusing their aliases | State the limit in the Burner email, and make addresses that look ordinary, on a custom domain, a product priority |
| Interviewees left a private AI over memory, or over capability | Lead the Bot email with remembered sessions (memory), or with model choice and per-model labels (capability) |
| Interviewees are anxious about credits | State per-use costs plainly. Don't lead the Bot email with remote models |
| Fewer than 1 in 4 accept the two-machine install | The job isn't compelling as framed; revise it before any send |

## Rewrite the emails around the job and the site around proof

The owner's rule that copy is product-forward and names no rival fits the evidence well. The winners' praise is for honesty and the product itself, never for attacks on rivals. The security follow-up's opening, "Everything our servers can see", is the Tailscale-style admission this audience rewards. Fixing the footprint before any send (Q-OB-1) is the right precondition, because privacy audiences punish a trust shock harder than a missing feature ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)).

The changes the hypothesis calls for are narrow. Where a change touches something the owner decided, the table marks it as a question for the owner.

| Email | Now | Change | Why |
|---|---|---|---|
| Launch (`team_1`), one-tap answers | Five job titles: "I build software", "I lead a product", "I run IT or operations", "I work in security", "Something else" | Owner question, since Q-OB-4 decided the role taps: ask what the reader would put on it first: "My machines", "A service on my own domain", "My AI agents", "Files we share", "Checking it for security", "Something else". Each maps to today's follow-ups | The list holds few product, IT or security buyers. A job question routes the same follow-ups and measures the hypothesis on every answer |
| Launch, first line | "Today URnetwork works for teams." ([string](file:///Users/brien/urnetwork/mmm/outbound/strings/email_ob_team1_p1.yaml)) | Person first: "Your machines, files and agents can now be one private network. Start alone, and invite your team when you're ready." | Winners sell to the person; the general follow-up already says people can invite their team when ready |
| Developer follow-up | Own domain, key on the machine; addresses, ports, storage; public source | Once these ship, add the agent job: each agent gets an address, HTTPS on your domain and a mailbox, and never sees your tokens. Fold in the record line from the product version | The most-voted agent complaints; the person who runs agents is the one who reads the record |
| Price line, all follow-ups | "Team is $10 a month for your first three seats." ([string](file:///Users/brien/urnetwork/mmm/outbound/strings/email_ob_team_price.yaml)) | Owner question, since the line was decided word for word: "...and agents don't take a seat." | Okta's buyers "like the predictability"; rivals charge for agent devices or sell agent seats |
| Security follow-up, first line | "Here's the whole list of what URnetwork's servers see: sizes, timing and a few routing values" ([string](file:///Users/brien/urnetwork/mmm/outbound/strings/email_ob_team2_sec_p1.yaml)) | Scope it: "Here's what URnetwork's servers see of your team's traffic, files and mail." Link the full list, which must also name account and billing data, support conversations (which URnetwork reads in full), and what the model, search and enclave providers read | As written, "whole list" is untrue: the design has support read the whole conversation ([DESIGN-COMPUTE.md](file:///Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)). This audience reads fine print: Confident Security's "Zero logging*" ([Confident Security](https://confident.security/)) |
| Product, and IT and operations follow-ups | The agent feed; identity provider, SCIM, admin-signed devices | Keep both, sent by the launch answer; expect few readers | List composition |
| Reply email (`team_3`) | "Is it the price, something missing, or the way your team works?" ([string](file:///Users/brien/urnetwork/mmm/outbound/strings/email_ob_team3_p2.yaml)) | "What are you using instead, and what made you pick it?" | Offered options steer replies; switching stories are the data the hypothesis needs |
| Burner (`relaunch_1`) | An address per site with its login; mail server on the device; free; two limits | Keep the hook. Add the limit people hit most: "A few sites refuse addresses like these." If importing from another password manager ships, add one line about it | Blocked aliases are the top alias complaint; people switch when migrating is cheap ([Bitwarden reviews](https://itunes.apple.com/us/rss/customerreviews/page=3/id=1137397744/sortby=mostrecent/json)) |
| Bot (`relaunch_2`) | Six paragraphs: local models, enclave, TEE models, search, record ([string](file:///Users/brien/urnetwork/mmm/outbound/strings/email_ob_rl2_p1.yaml)) | One idea that keeps the owner's rule of naming the enclave first: "Bot remembers your chats and your agents' work across your phone, your computer and your own encrypted enclave, and only your devices can read it." Keep "local models are free". Add one line that Bot labels every model with who can read it before you send. Move TEE and search details to the page, keeping the search disclosure if search stays in the email | Memory is what private-AI users give up, and synced history is the one paid choice in the threads; the house rule is one idea per email |

**Measurement.** Teams created within 21 days against the 10% holdout stay the primary measure. Add:
- the share of launch answers picking agents;
- CLI installs on two or more devices;
- teammates invited;
- replies coded for privacy raised unprompted.

Use the staggered sending days the plan already requires as waves, and read the one-tap answers from the first days before mailing the rest.

**The site.** The same reasoning applies to ur.io. The pages should lead with jobs, make claims that their own tables support, and carry the proof on two pages that can name things: the trust page and the comparison page.

| Page | Now | Change | Why |
|---|---|---|---|
| Home | "off our servers and off the record. Period." and "100% open source and reproducible." ([SITEMAP.md](file:///Users/brien/urnetwork/mmm/ur.io/SITEMAP.md)) | A scoped promise with a link: "Our servers carry what they can't read. Here's everything they can see." Route by job: browse privately, inbox and passwords, AI and agents, your machines and team. Add one line on how Team and the apps relate to the VPN's exits, worded so it mentions neither providers nor earning, as the sitemap requires | Absolute claims fail with careful readers; the separation is Q-OB-1 |
| Products | "Build on transparent, end-to-end encrypted infrastructure." ([ui-site mockup](file:///Users/brien/urnetwork/sidecar/design/mocks/ui-site.html)) | Keep "Every plan gets every privacy feature." Say where keys live instead of an unscoped "end-to-end". Add "Agents don't take a seat" and the rule that an admin approves each new seat. Say how the compute balance is spent and whether it expires | Elsewhere privacy is a paid tier (Composio); reviewers resent credits that expire ([Manus on Trustpilot](https://www.trustpilot.com/review/manus.im)) |
| CLI | Six features; "encrypted end to end"; "Give your team the CLI" | Lead with the developer email's job line. Add "Give your agents a place to work" once it ships. Make "no server, ours included, can add a member or a device" prominent. Add a section on what self-hosting gives you, without the server | It answers the signed-policy and key-negotiation complaints; self-hosting is fragile |
| Burner | "Email only you can read", four points, a flow diagram | Keep. Add sections on what happens "if you lose your phone" (recovery and a human to ask), the limit that some sites refuse aliases, and moving from another password manager. Put "as many addresses as you want, on every plan" near the top | Lockouts are the most damaging complaint; password-manager prices rose up to 98% |
| Bot | "A fully private bot" and "remote ones sealed inside TEEs", above a table whose TEE row reads "Only the provider" ([ui-site mockup](file:///Users/brien/urnetwork/sidecar/design/mocks/ui-site.html)) | Owner question, since "fully private bot" is the owner's phrase (UI-1): a headline the table supports, such as "A private bot that remembers", with "Private on your device. Labeled everywhere else." Move "your agents and chats follow you between them" from the bottom to the top. Retitle "Private web search" (for example "Web search without an account"). Keep the "Where your words go" table | The headline contradicts the page's own disclosures; published limits build trust (Venice, Tinfoil) |
| Trust (`ur.io/security`) | Planned: the trust statement, the canary, what servers see, "not yet audited" ([PLAN.md](file:///Users/brien/urnetwork/mmm/outbound/PLAN.md)) | Make it the main asset. Cover: what the servers see, by data class (edge, account, billing, support); what URnetwork can't do and how to check it (client source, signed releases, admissions visible in the app); a dated audit plan; subprocessors; legal requests; recovery and human appeal; a commitment to publish incident reports; separation from the exit network | Willingness to pay follows guarantees; NEAR AI's incident report shows how candor reads |
| Comparison | Planned from `matrix.json` | Title it "Who can read what", by category and dated. Include URnetwork's own readers (model providers, search, support) and self-hosting as a column, and credit rivals' accurate claims. This stays the only page that names companies | Information, not attack, as the owner's rule requires; self-hosting is the real alternative for this audience |

One more surface carries claims: the text written for AI agents. The sitemap's Agents section is meant to address an AI agent directly ([SITEMAP.md](file:///Users/brien/urnetwork/mmm/ur.io/SITEMAP.md)), and the agent skill is what agents read about URnetwork. Agents repeat what they read to the people they work for, and competitors now write for exactly that reader. So the skill and every page aimed at agents need the same scoped claims, without "distributed scraping" (Q-OB-1), and with a link to the trust page.

## Conclusion

The market's blind spot and URnetwork's audience meet in one person, not in an org chart. The incumbents' consensus that securing agents means reading them is defensible for the enterprise. It fails for the person who runs agents on their own machines and already pays to keep the middle blind, and that person is URnetwork's natural first customer. Team is the second sale. The launch question and the 24 conversations should decide whether Team leads the next campaign or follows Bot and Burner. That makes the launch both a campaign and an experiment, and the plan should treat it that way.

For URnetwork, "can't read" is necessary but not enough. The scarce asset in this market is conduct: published admissions, clear separation from the exit network, and a human path through recovery. Incumbents can't adopt it cheaply because they earn by reading, and privacy brands keep losing it in single shocks. URnetwork's own footprint is therefore both its largest risk and its cheapest advantage. The trust page, not the email, is the first feature to ship.
