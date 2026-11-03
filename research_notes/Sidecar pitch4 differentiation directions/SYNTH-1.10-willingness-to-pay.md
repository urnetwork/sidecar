# Branch 1.10 synthesis: willingness to pay for agent records, governance and team features (as of 1 November 2026)

## About this synthesis

- **What the branch contains.** Two notes files, both read in full:
  - **Level 1, node 1.10:** [`L1-1.10-willingness-to-pay.md`](L1-1.10-willingness-to-pay.md). It asks four questions:
    1. What do agent observability, governance, session and audit products charge in late 2026, and per what unit: seat, agent or event?
    2. Which budget and buyer pays, and what deal sizes and sales motions are reported?
    3. Is there evidence of paid adoption for audit or record products specifically, as opposed to free use?
    4. What price and packaging would best convert free solo use into a paid team record?
  - **Level 2, node 2.08,** opened jointly by 1.10, 1.8 and 1.3: [`L2-2.08-in-companies-with-5-150-engineers-below-the-ente.md`](L2-2.08-in-companies-with-5-150-engineers-below-the-ente.md). For companies with 5–150 engineers, below the Enterprise plans of Cursor, Claude and Copilot, it asks:
    1. Is there public demand for evidence of what agents did and reached? How much, and of what kind?
    2. Do customers' questionnaires or auditors ask for it?
    3. Would these companies pay a Team price for a signed export that covers every harness?
    4. Who signs: the engineering leader from the AI-tools budget, or security?
    5. What does this mean for pitch4?
  - 2.08's coverage: 22 Cursor forum queries (554 topics, 24 opened in full); 18 searches of anthropics/claude-code (417 issues, 16 opened in full, reactions read on 26); 18 GitHub Community searches; 14 Hacker News comment queries since 1 Jan 2025 (139 comments); 10 GitHub repository searches.
- **Depth.**
  - Level 2 merged two of level 1's six open questions: whether teams below the Enterprise line seek audit evidence and would pay for a signed export across harnesses, and who signs. It also carried 1.8's question about questionnaires and auditors, and 1.3's question about tying each connection to a run rather than to a device or tag.
  - Level 1's other four open questions were not followed up in this branch:
    - what security buyers pay per developer, and what a "resource" is;
    - whether any standalone record product earns revenue;
    - conversion at the "second person joins" trigger;
    - whether agent pricing will converge on per-agent metering.

    They remain open (section 4).
  - Level-3 note 3.06 (clients' AI terms at 5–150-engineer suppliers) was opened jointly by 2.08 and 2.01, and level-4 note 4.04 follows it. The workflow placed both in branch 1.8, and [`SYNTH-1.08-buyer-evidence-artifacts.md`](SYNTH-1.08-buyer-evidence-artifacts.md) covers them. Their findings are not used here, so for this synthesis the branch ends at level 2.
- **Conventions.**
  - Every factual claim below comes from the two notes files, and every link is one the notes use.
  - Labels carried over from the notes:
    - "(vendor claim)": a company's statement about itself, or data it collected about itself.
    - "(search excerpt)" or "(search summary)": the notes saw the claim only in a search engine's summary of a page that did not load. Treat it as unverified.
    - "(secondary)": press or another third party reporting someone else's data.
  - **Counting people.** Counts follow 2.08's rule:
    - a "person" is a distinct non-staff username or GitHub login whose own words were read;
    - a "+1" reply counts;
    - likes, thumbs-up and views do not;
    - vendor founders pitching a product are not counted.

    Counts are lower bounds for the queries the notes ran.
  - Annual costs and seat equivalents are the notes' own arithmetic from list prices.
  - "[inference]" marks reasoning by the notes rather than a sourced fact. "[inference, this synthesis]" marks reasoning added here.
- **Relation to earlier research.**
  - `market2.md` and pitch4's page-5 footnote set the Team band at $8–25 a seat from per-person anchors: Tailscale $8, Agent 365 $15, Copilot Business $19, and a Claude Team seat at $20–25. They set Assured at about a Copilot Enterprise seat ($39). Both called the band an inference.
  - `sentiment2.md` listed "whether teams will pay the inferred $8–25 a seat" as untested, and called paying demand "narrow".
  - **What this branch adds:**
    - the first survey of what governance, audit and observability products charge;
    - the first evidence on which budget pays and who signs;
    - the first count of demand below the Enterprise line.
  - It still does not measure willingness to pay directly. It found no price-sensitivity data and ran no interviews.

## 1. What the branch found

### Short version

1. **Pitch4's Team price is low for the market, not high** (level 1).
   - Comparable team plans cost $20–50 a seat. The cheapest configurations that include SSO cost about $500 a month flat.
   - At 20 engineers, Team costs $1,920–$6,000 a year. That is the same order as the cheapest SSO tiers of Langfuse and Keycard (about $6,000). Assured at $39 equals a Copilot Enterprise seat.
   - The risk is under-pricing a tier that includes SSO and exports.
   - The footnote's anchors are weak. Copilot's seat now sits beside credit billing, and a Claude Team seat bundles model usage.
2. **Audit is the Enterprise lever almost everywhere** (level 1, confirmed at level 2).
   - Cursor, Claude, Graphite, Langfuse, Factory, Keycard and Teleport keep audit logs, the compliance API, SIEM export or SCIM for their top tier. Span is the exception.
   - Pitch4's Team tier, with SSO, exports and a signed ledger, is a real packaging difference.
3. **Three budgets pay, and they buy differently** (level 1).
   - **Security** buys sales-led annual commitments ($10,000 to about $200,000 on AWS Marketplace), or pays per agent or per resource. Only 24% of security teams track AI as its own budget line.
   - **Engineering** buys self-serve: per-seat plans capped at 10–25 seats, or flat fees a manager puts on a card.
   - **Developer-productivity measurement** is a proven purse: Atlassian paid about $1B for DX.
4. **No standalone agent-record product shows revenue** (level 1).
   - Money goes to security control, to measurement, and to audit bundled into enterprise plans.
   - Prompt Security was acquired for $159.3M with "immaterial ARR".
5. **Below the Enterprise line, demand is for attribution, not audit** (level 2).
   - 2.08 counted 58 people on the Cursor forum and in Claude Code issues. Of them, 43 ask who used what, on which project or client, at what cost, and how much code AI wrote. At least 14 of the 43 say they are on a Team plan.
   - Only 3 ask for approval or audit records. None asks for per-connection reach receipts.
   - The strongest voices tie the data to proving ROI to management or passing AI costs on to clients.
   - Audit workaround tools have almost no adoption: at most 2 GitHub stars, and 0 forum likes. Usage trackers have thousands of stars (ccusage: 19,286).
6. **What auditors ask small companies for today can be answered without agent records** (level 2).
   - Auditors and consultants treat AI-written code as ordinary SOC 2 change management. They ask for an inventory of AI tools, an approval process, and evidence of human review.
   - Protected branches and PR approvals supply most of that.
   - Agent-run records appear only in stronger, vendor-adjacent asks.
   - 139 HN comments yielded no first-hand report of a customer or auditor asking a team for coding-agent records.
7. **In 5–150-engineer companies the engineering leader signs, by card** (level 2).
   - Team plans are card purchases, and invoicing is an Enterprise feature.
   - Security, IT and legal appear at purchase as approvers, reviewing the vendor's SOC 2 report or DPA.
   - Assured is a different sale.
8. **"Audit without Enterprise" is a smaller wedge than level 1 assumed** (level 2).
   - Claude's self-serve Enterprise is a card purchase from 20 seats.
   - Copilot Business logs GitHub-side agent activity with session IDs.
   - The gap bites mainly for Claude teams under 20 seats, Cursor and Devin Teams orgs, and agencies and outsourcers.
9. **Coverage across harnesses is the most defensible part of the offer** (level 2).
   - Small teams mix Claude Code and Cursor.
   - Each vendor's analytics stop at its own harness and break at plan or surface boundaries.
   - Team-plan orgs build their own OTel pipelines and still hit identity gaps: 54% of one Team org's Cowork rows were unattributed.
10. **Developers resist attribution stamped into commits they did not choose** (level 2). Twenty Claude Code issues (68 thumbs-up) ask it to stop writing attribution trailers. One issue asking for a more accurate "Assisted-by" trailer has 52 thumbs-up.

### 1.1 What comparable products charge, and per what unit (level 1, with level-2 additions)

**Three pricing logics, each tied to a buyer:**

| Logic | Buyer | Examples (list prices, fetched 1 Nov 2026 unless noted) |
|---|---|---|
| Per human seat | Developers and engineering | Graphite $20 or $40 a user a month, billed annually ([Graphite](https://graphite.com/pricing)); Factory Teams "$60/mo" per team "plus $40/mo per seat", up to 10 seats ([Factory](https://factory.com/pricing)); Warp Business "$50/user /month" ($45 annual), up to 25 seats ([Warp](https://www.warp.dev/pricing)) |
| Flat org fee plus events | AI engineering or platform | Langfuse $29–$2,499 a month, with unlimited users from Core ([Langfuse](https://langfuse.com/pricing)); Datadog Agent Observability from $160 a month for 100K LLM spans ([Datadog](https://www.datadoghq.com/pricing/?product=llm-observability)); Keycard Team "$500 /mo" for 100,000 transactions ([Keycard](https://www.keycard.ai/pricing)) |
| Per agent, per resource, or annual commitment | Security | Aembit Teams "$20/agent/mo" ([Aembit](https://aembit.io/pricing/)); Noma and Zenity $130 per resource a month on AWS Security Hub ([AWS Security Hub pricing](https://aws.amazon.com/security-hub/pricing/)); annual AWS Marketplace listings of $200,000 for Noma, $20,000 and $50,000 for Lasso, and $10,000 per Prompt Security option (search excerpts) ([Noma](https://aws.amazon.com/marketplace/pp/prodview-kd2qklag2zzym); [Lasso for Employees](https://aws.amazon.com/marketplace/pp/prodview-7ygm7pa3k5agg); [Lasso gateway](https://aws.amazon.com/marketplace/pp/prodview-noabqkrq6zbq4); [Prompt Security](https://aws.amazon.com/marketplace/pp/prodview-lzvx5ody7qffw)) |

**Where audit sits.** In the top tier almost everywhere:
- **Langfuse.** "The SCIM API and audit logs are Enterprise-only", at $2,499 a month. SSO is a "$300/month" Teams add-on to the $199 Pro tier ([Langfuse](https://langfuse.com/pricing)).
- **Graphite.** Enterprise adds SAML, ACLs and "audit log (SIEM)" ([Graphite](https://graphite.com/pricing)).
- **Factory.** The unpriced Business tier adds SSO, SAML/SCIM provisioning, ZDR and "Audit logging and activity trails" ([Factory](https://factory.com/pricing)).
- **Cursor.** Audit logs are "available on Enterprise plans" (search excerpt) ([Cursor docs](https://cursor.com/docs/enterprise/compliance-and-monitoring)).
- **Claude.** The Compliance API is "available to Enterprise plan organizations" ([Claude Help Center](https://support.claude.com/en/articles/13015708-access-the-compliance-api)).
- **Keycard.** Enterprise adds SCIM, customer-managed KMS and "Continuous export (OCSF)". Its comparison table conflicts with its plan bullets on whether export and provisioning are in Team ([Keycard](https://www.keycard.ai/pricing)).
- **Teleport.** The Enterprise Edition lists "Session recordings and structured audit logs for every session and request" and audit data "exportable to SIEMs". It bills by monthly active users and protected resources, and the guide gives no dollar prices ([Teleport pricing guide](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_Jan_6_2026_c706e2abf0.pdf)).

**The exception: Span** ([Span pricing](https://www.span.app/pricing)).
- It is "Priced per code contributor".
- Its base tier includes audit logs, RBAC, SSO and SCIM.
- Dashboard-only viewers are free.
- It shows no price: "Request pricing".

**The SSO tax.** sso.tax lists markups from base price to SSO price ranging from +50% (Linear, Bitwarden) to +425% (GitHub) and +613% (JFrog) ([sso.tax](https://sso.tax/)).

**Annual cost for a 20-engineer team** (level 1's arithmetic, annual list rates, ignoring usage; the Copilot and Claude figures are prior-round anchors that were not re-fetched):

| Product | Annual cost |
|---|---|
| Pitch4 Team | $1,920–$6,000 |
| Pitch4 Assured | $9,360 |
| Copilot Business / Copilot Enterprise | $4,560 / $9,360 |
| Claude Team Standard | $4,800 |
| Graphite Team | $9,600 |
| Warp Business | $10,800 |
| Langfuse Pro plus Teams add-on (cheapest with SSO) | $5,988 |
| Langfuse Enterprise (first tier with audit logs) | $29,988 |
| Keycard Team | $6,000 |
| Aembit Teams, 20 or 60 agents | $4,800 or $14,400 |
| Prompt Security option / Lasso for Employees | $10,000 / $20,000 |
| Noma | ~$195,000–200,000 |

**What level 1 concluded:**
- **The footnote anchors are weaker than they look.** [inference]
  - From 28 Oct 2026, GitHub Enterprise customers can use Copilot features without a separate Copilot seat and pay for the AI credits they use ([GitHub Blog](https://github.blog/news-insights/company-news/github-universe-2026-evolving-every-layer-of-the-stack/)).
  - A Claude Team seat bundles model usage ([Claude pricing](https://claude.com/pricing)).
  - Closer anchors for a team record with SSO are Span (per contributor, price unknown), Langfuse Pro plus Teams ($499 a month) and Keycard Team ($500 a month).
- **Pitch4's Team band sits at or below comparable team plans.** [inference]
- **"Agents are never metered" contrasts with the security side; it is not a market norm.** [inference]
  - Harness vendors, Microsoft and Okta avoid per-agent fees. Agent 365 says: "Agents do not require their own licenses" ([Microsoft licensing FAQ](https://microsoft.com/licensing/faqs/122)).
  - Aembit, Noma, Zenity and Teleport meter non-human identities. Teleport counts any "MCP server, git repository, or a machine or workload identity" as a protected resource.
- **The paid cross-harness slot is getting crowded.**
  - Warp Enterprise lists cross-harness agent memory as a Research Preview. Warp Factories runs Claude Code and Codex harnesses, with transcripts and conversation data at Enterprise ([Warp](https://www.warp.dev/pricing)).
  - Entire calls itself "a new distributed Git forge that stores your intent alongside your code". It offers shared team agent memory and shows no prices ([Entire](https://entire.com/)).

**What level 2 added:**
- **Cursor.**
  - The pricing page lists Teams at "$30+/user/month" with SSO, usage analytics and team privacy settings. Enterprise adds "Invoice/PO billing", SCIM, "audit logs and service accounts", and access controls for repositories, models and MCP ([Cursor pricing](https://cursor.com/pricing)).
  - Cursor staff told an evaluating company in January 2026 that Team was "$40/user/mo", which conflicts with the page ([Cursor forum 149536](https://forum.cursor.com/t/what-features-are-included-in-team-vs-enterprise/149536)).
- **Devin.** Windsurf's pricing page now redirects to Devin's. Devin charges "$80/month for team plan + $40/mo per full dev seat", "Up to 200 users". "SAML/OIDC SSO" is Enterprise-only, and the pricing page does not mention audit logs ([Devin pricing](https://devin.ai/pricing); [Windsurf redirect](https://windsurf.com/pricing)).
- **What Cursor buyers pay.**
  - Vendr's Cursor page reports a median buyer at "$116,734" a year from "97 purchases" (range $29,520–$513,000). It gives Business list as "$40–$50/user/month", with volume discounts starting around 20–25 users (vendor-collected data) ([Vendr](https://www.vendr.com/marketplace/cursor)).
  - SpendHound reports an average of $171,086 a year across 160 Cursor customers (search summary) ([SpendHound](https://www.spendhound.com/marketplace/cursor-pricing)).
  - At $40 a seat, Vendr's $29,520 minimum is about 61 seats. 2.08 inferred that companies of 5–60 engineers mostly buy self-serve. [inference]

### 1.2 Which budget pays, and who signs (level 1 Q2; level 2 Q4)

**The security purse (level 1).**
- **IANS and Artico, 2026 Security Budget report** (500+ security executives; reported by CSO Online on 17 Sep 2026; [CSO Online](https://www.csoonline.com/article/4223455/)):
  - How AI security is funded:
    - 24% track AI as "a separate security-budget line or subcategory";
    - 38% embed it in the security budget;
    - 38% fund it from IT, data or innovation budgets.
  - 69% named AI their top net-new priority.
  - Budgets grew 5% on average, but "median budget growth remained at 0%".
  - 70% of "aggressive AI spenders" have "clearly defined AI governance ownership", against 34% of organizations with no AI-specific spending plans.
- **Felicis** (45 enterprise security leaders, spring 2026; [Felicis](https://felicis.com/blog/cisos-have-budget-for-ai-security-the-missing-layer-is-the-control-loop)):
  - 78% have a dedicated "security for AI" budget, mostly $100K–$1M.
  - Felicis invests in adjacent companies.
  - Its 78% conflicts with IANS's 24%. The questions and samples differ, and level 1 gave IANS more weight.
- **Gartner** puts spending on AI governance platforms at $492M in 2026, passing $1B by 2030. That figure is secondary: the release itself returned HTTP 403 ([Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms); [Signisys](https://www.signisys.com/blog/ai-governance-spending-will-hit-492-million-in-2026-and-surpass-1-billion-by-2030/)).
- **How security buys.** Sales-led annual commitments, often through AWS Marketplace. Zenity and Noma also sell inside AWS Security Hub Extended, on one AWS bill ([AWS Security Hub pricing](https://aws.amazon.com/security-hub/pricing/)).

**The engineering purse (level 1).**
- Tailscale's free users are "bringing it to work, where a dev manager or TLM pays us on a corporate credit card" ([Tailscale blog](https://tailscale.com/blog/free-plan)).
- Self-serve has caps: Warp Business up to 25 seats, Factory Teams up to 10 seats.
- Langfuse, Datadog and Keycard sell monthly plans with no commitment.

**The measurement purse (level 1).**
- Atlassian agreed to buy DX for about US$1B. DX's tools "track the adoption and impact of AI tools" ([BNN Bloomberg / Reuters](https://www.bnnbloomberg.ca/business/2025/09/18/atlassian-to-acquire-developer-productivity-platform-dx-for-us1-billion)).
- Span raised $25M (Nov 2025) and bills per contributor ([Business Wire](https://www.businesswire.com/news/home/20251105703479/en/Span-Raises-%2425M-to-Bring-Clarity-to-Engineering-Teams-Navigating-AI-Transformation); [Span pricing](https://www.span.app/pricing)).

**Compliance and privacy (level 1).** These teams often own AI governance but have thin tooling budgets. "The privacy function often bears primary responsibility for AI governance" (secondary) ([Let's Data Science](https://letsdatascience.com/news/iapp-executive-describes-who-owns-ai-governance-64324c43)).

**Who signs in 5–150-engineer companies (level 2).**
- **Card versus invoice:**
  - Cursor staff: choose Enterprise when "You need invoicing instead of a card" ([Cursor forum 149536](https://forum.cursor.com/t/what-features-are-included-in-team-vs-enterprise/149536)). "Invoice/PO billing" is Enterprise-only ([Cursor pricing](https://cursor.com/pricing)).
  - Claude: "Organizations upgrading from a Team plan pay by credit card during the upgrade." Self-serve Enterprise (20-seat minimum) accepts "Credit card, ACH". Invoicing is only for sales-assisted deals of 50+ seats ([Claude help center](https://support.claude.com/en/articles/9797531/what-is-the-enterprise-plan)).
- **Where the budget sits.** Nearly half of 50 engineering budget holders set aside "between 1-3% of their total engineering budgets for AI tools" ([DX](https://getdx.com/blog/how-are-engineering-leaders-approaching-2026-ai-tooling-budget/)).
- **Procurement by company size.** "It seems like enterprise procurement, not individual preference, is behind this divergence" ([Pragmatic Engineer](https://newsletter.pragmaticengineer.com/p/ai-tooling-2026)).
- **Gartner** addressed "Best Practices to Mitigate Security Risks With Agentic Coding Tools" (24 Mar 2026) to software engineering leaders. This is from a search summary; the page returned 403 ([Gartner](https://www.gartner.com/en/documents/7633033)).
- **Role signals on the forums:**
  - an engineering admin with 75+ members;
  - an org of 100+ reporting ROI "to our management";
  - a Team plan Owner;
  - the dashboard builder at a 123-person org;
  - BizOps provisioning licenses for SOC 2;
  - an IT department reviewing Cursor's SOC 2 report;
  - a legal team in procurement.
  - Sources: [138430](https://forum.cursor.com/t/any-plans-to-make-ai-code-tracking-api-available-for-teams-plan/138430); [#67772](https://github.com/anthropics/claude-code/issues/67772); [#27780](https://github.com/anthropics/claude-code/issues/27780); [111148](https://forum.cursor.com/t/integrate-with-rippling-hris/111148); [67361](https://forum.cursor.com/t/can-anyone-share-me-a-soc2-report/67361); [1339](https://forum.cursor.com/t/document-q-a-for-security-compliance-concerns-for-business-use-cases/1339).
- **Security-side signals** (all search summaries):
  - An IANS session says security leaders play "a pivotal role in the governance of these emerging technologies" (AI generally) ([IANS](https://www.iansresearch.com/what-we-do/events/vendor-event/details/2026/04/23/2026-insight-exchange/april-23-insight-exchange-put-ai-governance-into-action)).
  - Salt Security reports that "nine in ten security leaders are concerned" about AI-generated code (vendor) ([IT Security Guru](https://www.itsecurityguru.org/2026/06/01/nine-in-ten-security-leaders-concerned-about-ai-generated-code-risks-as-salt-security-launches-new-governance-tool/)).
  - Checkmarx data puts the share with policies for AI coding assistants at 18% (vendor, via Encore) ([Encore](https://encore.dev/guides/ai-code-compliance)).
- **Security ownership in small companies** (weak, secondary):
  - A dedicated security hire becomes worthwhile "above roughly 150 employees or when enterprise customers require SOC 2" ([Decryption Digest](https://www.decryptiondigest.com/blog/startup-security-foundation-series-a-first-priorities-budget-constraints)).
  - An AI-generated summary says the SOC 2 trigger has moved to as early as 10–20 employees ([Sacra summary](https://sacra.com/chat/h/6440134e-3007-49cf-845d-b5ee25f50ebb/)).
- **Level 2's conclusion** [inference]:
  - For a Team tier, the engineering leader (VP Engineering, CTO or engineering manager) buys and signs, by card, from the AI-tools line.
  - Security approves. Below about 150 people, security is often the CTO wearing a second hat, and needs a short vendor-review packet.
  - Assured is a separate sale: annual, possibly through a marketplace, and signed by security or compliance at regulated buyers or firms nearing 150 or more engineers.

### 1.3 Paid adoption of audit and record products (level 1)

- **Security platforms.**
  - SentinelOne paid $159.3M for Prompt Security, closing on 5 Sep 2025 ([SEC 10-Q](https://www.sec.gov/Archives/edgar/data/1583708/000158370825000159/s-20251031.htm)). Earnings-call coverage says the impact is "expected to be minimal in fiscal year '26 with immaterial ARR and revenue contribution" ([Nasdaq](https://www.nasdaq.com/articles/sentinelone-arr-tops-1-billion-q2)). Both are search excerpts.
  - Noma ("ARR more than 1,300%") and Lasso ("500%+") report growth only as percentages (vendor claims) ([ARR Club](https://www.arr.club/noma-security/noma-security-grows-at-1300-year-over-year-with-dozens-of-enterprise-customers-); [SiliconANGLE](https://siliconangle.com/2026/09/02/lasso-security-launches-cpu-only-ai-guardrail-raises-30m/)).
- **Observability.** Braintrust's ARR of roughly $36M in 2025 is an unverified third-party estimate ([Ecosistema Startup](https://ecosistemastartup.com/7-herramientas-de-observabilidad-ia-2026-braintrust-36m-arr-langsmith-100k-devs/)).
- **Measurement.** Span's AWS Marketplace listing names Ramp, Vanta, Duolingo and Fin (search excerpt, vendor claim) ([AWS Marketplace, Span](https://aws.amazon.com/marketplace/pp/prodview-rie6wmj5drsui)).
- **Record products.** Entire publishes no price. Teleport sells session recordings in its commercial edition but publishes no revenue.
- **Demand below the Enterprise line.** One practitioner wrote guides for Cursor Teams and Claude Team on getting audit logs "without upgrading to Enterprise" ([codenote, Cursor](https://codenote.net/en/posts/cursor-teams-audit-log-workarounds/); [codenote, Claude](https://codenote.net/en/posts/claude-team-audit-log-workarounds/)). The Cursor guide notes that "Enterprise audit logs only record management events, not prompt content."
- **Free users do not fund hosting.** Vibe Kanban closed its hosted service because "the vast majority are free users" ([Vibe Kanban](https://www.vibekanban.com/blog/shutdown)).
- **Level 1's conclusion** [inference]:
  - Audit is sold as part of something else: security control, measurement, or compliance checkboxes bundled into Enterprise plans.
  - Funding rounds in agent security are not evidence of willingness to pay.

### 1.4 Demand below the Enterprise line (level 2)

**Counts** (distinct people on pages opened; lower bounds):

| Kind of request | People | Notes |
|---|---|---|
| Attribution of usage, identity or AI-written code | 43 | 11 on two Cursor threads, 32 on Claude Code issues; at least 14 say they are on a Team plan |
| Compliance documents or controls below Enterprise | 6 | A DPA, governance admin, GxP, a client AI policy |
| Actor attribution (which human or agent acted) | 6 | |
| Approval or audit records | 3 | Plan unstated |
| Per-connection reach receipts | 0 | |

**The strongest voices.**
- **"Any Plans to Make AI Code Tracking API Available for Teams Plan?"** (5 people) ([Cursor forum 138430](https://forum.cursor.com/t/any-plans-to-make-ai-code-tracking-api-available-for-teams-plan/138430)):
  - songcj (on Teams, 75+ members) cites "Visibility Governance: It would help us track AI-generated code across the team, ensuring alignment with internal coding standards and compliance requirements". He adds that "for growing teams that need robust oversight without Enterprise-scale budgets, having it in the Teams plan would be a game-changer."
  - T.H (100+ engineers): "This exact data allowed us to prove the clear ROI of Cursor to our management. It was the key justification that enabled us to successfully roll out Cursor licenses to our entire engineering organization (100+ members)."
- **"Chat/Agent Session Metadata for Client, Task, and Cost Attribution"** (6 people). Staff replied: "We've captured this as a feature request internally." ([Cursor forum 160895](https://forum.cursor.com/t/chat-agent-session-metadata-for-client-task-and-cost-attribution/160895)):
  - Gyurmatag: "We are on Team plan with 40 developers and would like to exactly monitor the cost of each project."
  - Andrey_Eroftiev: "As a software development outsourcing company we would like to have per-task token spending attribution feature on our Team plan to be able to pass through these expenses to our clients".
- **Claude Code #27780**, on the Analytics Admin API not returning subscription users (19 people, 26 thumbs-up) ([issue #27780](https://github.com/anthropics/claude-code/issues/27780)):
  - kohapple: "Team plan admins are hit harder than Enterprise, because we don't have access to the Admin API at all."
  - 0xDEnYO: "+1 from a 123-person org on the Team plan. We're building an internal AI-spend dashboard and want per-developer Claude Code metrics (sessions, LoC, commits, PRs, tokens)".
- **Team-plan orgs building their own pipelines:**
  - #88490: cloud Cowork sessions exported OTLP "with no identity attributes". 7 people, including an org with "~70 developers" and one running a "Self-hosted OTel Collector → ClickHouse". The opener reported a fix in v2.1.259 ([issue #88490](https://github.com/anthropics/claude-code/issues/88490)).
  - #90288: "The result is unattributable spend … Over the last 14 days that bucket is 54% of all Cowork rows." ([issue #90288](https://github.com/anthropics/claude-code/issues/90288)).
  - #71312: a broken OTLP export "removes the only supported mechanism for Claude Code usage observability on the Team plan". The telemetry backend is Jellyfish ([issue #71312](https://github.com/anthropics/claude-code/issues/71312)).
- **A reseller buying Team where Enterprise is unavailable.** A software vendor in China says it has "facilitated cumulative payments totaling several million USD for Cursor on behalf of our clients", buying Team subscriptions ([Cursor forum 166137](https://forum.cursor.com/t/cursor-enterprise-plan/166137)).

**Where vendors draw the line**, besides Cursor and Claude (section 1.2):
- **GitHub Copilot's audit log** records "Agent activity on the GitHub website" and keeps events for 180 days. But it "does not include client session data, such as the prompts a user sends to Copilot locally" ([GitHub docs](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-for-organization/review-activity/review-audit-logs)).
- **GitHub's agentic events** carry `actor_is_agent`, `agent_session_id` and `user`. The page points to "your enterprise audit log" and does not say whether Copilot Business organization owners see these events ([GitHub docs](https://docs.github.com/en/copilot/reference/enterprise-administrators/agentic-audit-log-events)).
- **Cursor service accounts** are Enterprise-only ([Cursor forum 168503](https://forum.cursor.com/t/cloud-agent-pr-attribution-gh-account-wide-app-vs-personal-oauth-confusion/168503)).

**Workaround tools versus usage trackers.**
- **Audit tools get almost no adoption.**
  - Four Cursor forum posts for audit tools drew 0 likes in total. One is Agentmetry, which "records each tool call Cursors agent makes, in a hash-chained trail" (29 views) ([Cursor forum 175129](https://forum.cursor.com/t/a-local-record-of-the-tool-calls-cursors-agent-made/175129)).
  - Five agent-audit repositories have at most 2 stars each.
- **Usage trackers draw thousands of stars** (GitHub API, 1 Nov 2026):
  - [ccusage](https://github.com/ccusage/ccusage): 19,286
  - [Claude-Code-Usage-Monitor](https://github.com/Maciek-roboblog/Claude-Code-Usage-Monitor): 8,788
  - [claude-code-otel](https://github.com/ColeMurray/claude-code-otel): 520
  - [anthropics/claude-code-monitoring-guide](https://github.com/anthropics/claude-code-monitoring-guide): 386

**Paid analytics that span harnesses.**
- Jellyfish's "AI Impact" release (October 2026) tracks "GitHub Copilot, Cursor, and Claude Code" and adds an AI spend view (vendor claim; search summary) ([SD Times](https://sdtimes.com/software-intelligence-platform/jellyfish-advances-developer-and-agent-productivity-insights-for-the-ai-native-sdlc/)).
- A third-party analysis says Jellyfish's data comes from Git, Jira, tool usage and spend, "not deep code attribution" (search summary) ([Sacra](https://sacra.com/chat/h/3d690886-e4a6-49e6-8e75-4fb7bcb094e2/)).

**Small teams use several harnesses.** "Huge companies (10K+) more likely to use Copilot (56%), tiny startups mostly go with Claude Code (75%) and Cursor (42%)" (906 responses) ([Pragmatic Engineer](https://newsletter.pragmaticengineer.com/p/ai-tooling-2026)).

**Actor-attribution failures.**
- **Cursor Team Followups.** "User B [can] submit followup prompts that the agent executes as user A". Staff: "This is actually documented and intentional behavior of the Team Followups feature." ([Cursor forum 158866](https://forum.cursor.com/t/cursor-cloud-agent-sessions-are-shared-across-users-act-on-behalf/158866)).
- **Cursor PR authorship.** Cursor attributes an agent's PR to the user who started the agent: "If the PR were authorized by the bot, you could approve your own PR" ([Cursor forum 168503](https://forum.cursor.com/t/cloud-agent-pr-attribution-gh-account-wide-app-vs-personal-oauth-confusion/168503)).
- **GitHub Community.** "When an agent comments on a PR or opens a commit under my name and avatar, attribution is broken". The thread asks for:
  - agent sub-identities linked to the owner, with "no self-approval";
  - for each action, "a scoped delegation grant", "tool/runtime version" and "an outcome receipt".
  - Source: [discussion #203213](https://github.com/orgs/community/discussions/203213).
- **Claude's gateway to Bedrock** (Enterprise context; NERC CIP). "CloudTrail logs show the task role ARN for all `InvokeModelWithResponseStream` calls — no per-user attribution" ([issue #84504](https://github.com/anthropics/claude-code/issues/84504)).
- **Network logs.** Tailscale flow logs and Devin Connect gateway logs attribute traffic to a device, a tag or a "client address". This is 1.3's finding, cited in 2.08 ([Tailscale](https://tailscale.com/blog/codex-cloud-tailscale); [Devin Connect](https://docs.devin.ai/enterprise/deployment/devin-connect)).

**Approval and audit records (3 people).**
- #40634: the approval method "is not captured anywhere in the audit log" ([#40634](https://github.com/anthropics/claude-code/issues/40634)).
- #32904: "You cannot answer the question: 'What have I authorized Claude to do in this session?'" ([#32904](https://github.com/anthropics/claude-code/issues/32904)).
- #97908: "A team wants a durable record of its Claude Code sessions … it should not double as a log of anyone's working hours." ([#97908](https://github.com/anthropics/claude-code/issues/97908)).

**Counter-signal on commit attribution.**
- 20 issues by 20 authors (68 thumbs-up in total) ask Claude Code to stop adding Co-Authored-By or Claude-Session trailers, or to obey the opt-out. One is titled "Attribution is opt-out advertising" ([#4287](https://github.com/anthropics/claude-code/issues/4287); [#7543](https://github.com/anthropics/claude-code/issues/7543); [#83813](https://github.com/anthropics/claude-code/issues/83813); [#103691](https://github.com/anthropics/claude-code/issues/103691)).
- #36105, "Use `Assisted-by` git commit trailer instead of `Co-authored-by`", has 52 thumbs-up ([#36105](https://github.com/anthropics/claude-code/issues/36105)).

### 1.5 What auditors, questionnaires and clients ask small companies for (level 2)

**Auditor and consultant guides.**
- **CrashOverride** (vendor; 8 May 2026) ([CrashOverride](https://crashoverride.com/resources/knowledge-base/compliance/soc-2-ai-coding-tools)):
  - It lists two auditor questions: "Do your developers use AI tools? Which ones?" and "How is AI-generated code reviewed and tested differently from human code?"
  - For Type 2, it calls for records of "AI agent version, reviewer name, review date, approval" over 6–12 months.
  - "To pass SOC 2, you need machine-generated evidence showing every agent-generated code change was reviewed."
  - It recommends commit trailers such as "AI-Generated: copilot/coding-agent/2026-q1-v4".
- **Accorp Partners** (a CPA-led firm marketing its services) ([Accorp Partners](https://accorppartners.com/blogs/soc-2/soc-2-for-ai-companies-in-2026-what-auditors-test-that-didnt-exist-two-years-ago)):
  - Auditors want "a list of approved AI tools, a process for requesting approval for new ones".
  - For agents, they want "audit logs that attribute each agent action to the session, user, and workflow that initiated it".
  - "There is no AICPA-specific AI edition of SOC 2 as of 2026."
  - The guide targets companies with LLM features and agents, not coding agents specifically.
- **Linford & Co** (Tim Nackos, CPA; 18 Mar 2026). It says "auditors are asking about them now", and ties shadow AI to CC6, CC7.1 and CC9.1. It lists no specific AI evidence request ([Linford & Co](https://linfordco.com/blog/shadow-ai-soc-2/)).
- **Vanta, Drata and Secureframe.** The notes found no guidance from any of them on evidence for coding agents. Each ships an MCP server that lets coding agents *read* compliance data (search summary) ([Vanta MCP](https://help.vanta.com/en/articles/14094979-connecting-to-vanta-mcp); [Drata MCP](https://help.drata.com/en/articles/13379899-drata-mcp-setup-usage-guide); [Secureframe MCP](https://secureframe.com/blog/secureframe-mcp-server)).

**Controls teams use.** One team describes its setup: "master branch is protected, no one can push directly to it (including AI agents) PRs require human review/approval before merging". Cursor staff endorsed controlling "the environment, not the agent" ([Cursor forum 158756](https://forum.cursor.com/t/how-are-we-supposed-to-prevent-catastrophic-mistakes/158756)).

**Client asks.**
- An agency whose clients "contractually prohibit AI code generation" ([136492](https://forum.cursor.com/t/repository-level-ai-policy-file-ai-policy-txt-for-client-compliance/136492)).
- An outsourcer whose clients "are interested in per-task cost logging" ([160895](https://forum.cursor.com/t/chat-agent-session-metadata-for-client-task-and-cost-attribution/160895)).
- Startups whose finance and legal customers "require strict security compliance from their vendors" ([74447](https://forum.cursor.com/t/important-does-cursor-generate-copyrighted-code/74447)).

**Reviews target the tool itself, at purchase.**
- "Our Information Technology department intends to review the SOC2 report to determine whether we can procure Cursor." ([67361](https://forum.cursor.com/t/can-anyone-share-me-a-soc2-report/67361)).
- "I cannot point the legal team to a forum answer" ([1339](https://forum.cursor.com/t/document-q-a-for-security-compliance-concerns-for-business-use-cases/1339)).
- A request for a self-service DPA on Pro and Business. Without one, smaller teams are "forced to either: Upgrade to Enterprise (which may not be practical for smaller teams)…" ([152255](https://forum.cursor.com/t/feature-request-self-service-dpa-for-pro-business-plans/152255)).

**Hacker News.** 14 queries returned 139 comments since 1 Jan 2025, with 0 first-hand reports of a customer or auditor asking for coding-agent records ([HN Algolia API](https://hn.algolia.com/api/v1/search_by_date?query=SOC%202%20cursor&tags=comment)).

**Level 2's conclusion** [inference]:
- A PR-approval trail and a policy satisfy most of today's asks.
- Agent records become necessary in three cases:
  1. an auditor samples AI-authored changes;
  2. agents act without a human gate;
  3. a client contract restricts AI, or prices it per engagement.
- Agencies and outsourcers are the clearest small-company segment with a need driven by clients.
- The consultant guides are vendor-adjacent. Treat them as the high end of what auditors may ask, not as observed practice.

### 1.6 Converting free use into a paid team (level 1)

- **Tailscale's model.** "Increased word-of-mouth from free plans sells the more valuable corporate plans". And: "Willingness to pay for these controls is how we make more than enough money to cover all our costs" ([Tailscale blog](https://tailscale.com/blog/free-plan)).
- **Upgrade triggers in comparable products:**
  - Langfuse's free Hobby tier caps at 2 users and 30 days of data.
  - Keycard's free tier has a 5,000-transaction "hard cap", with unlimited users and agents.
  - Aembit is free for 3 agents.
  - Factory and Devin charge a team fee plus a seat price.
  - Span lets dashboard viewers in free.
- **Pricing-model benchmarks** (secondary coverage of a paywalled survey of about 230 companies) ([Growth Unhinged](https://www.growthunhinged.com/p/the-state-of-b2b-monetization-in-2026); [Enterprise DNA](https://enterprisedna.co/resources/ai-pulse/ai-pulse-2026-08-12-ai-saas-pricing-keeps-fragmenting-away-from-pure-per-seat); [Growth Unhinged 2025](https://www.growthunhinged.com/p/2025-state-of-b2b-monetization)):
  - 37% use hybrid pricing.
  - Investors prefer hybrid (35%), outcome-based (26%) and usage-based (24%) pricing over flat fees (10%) and seats (5%).
  - "Not enough expansion revenue" is the top challenge, especially for flat-fee and seat-based companies.
  - The 2025 edition's figures conflict with these.
- **Conversion.** ChartMogul's median free-to-paid conversion is 8%, and a quarter of freemium products convert below 2.5% (search excerpt) ([ChartMogul](https://chartmogul.com/reports/saas-conversion-report/)).
- **Level 1's proposals** [inference; untested]:
  - Keep the solo tier free, with unlimited agents.
  - Start Team at the second person, payable by card.
  - Price Team as a small team fee plus a low seat price, or as flat bundles with unlimited members.
  - Put SSO and a signed export in Team, and add free read-only seats for reviewers, auditors and executives.
  - Sell Assured as an annual commitment with a floor, through AWS Marketplace private offers.
  - Measure conversion at the second-person trigger.

### 1.7 Pitch4 claims the branch contradicts or weakens

| Pitch4 says (page) | What the branch found | Safer wording |
|---|---|---|
| "*Inferred from Tailscale ($8), Agent 365 ($15), Copilot Business ($19), and Claude Team ($20–25)." (5) | Copilot seats now sit beside credit billing. GitHub Enterprise customers can skip the Copilot seat from 28 Oct 2026 ([GitHub Blog](https://github.blog/news-insights/company-news/github-universe-2026-evolving-every-layer-of-the-stack/)). A Claude Team seat bundles model usage. Team plans for comparable tools cost $20–50 a seat, and the cheapest configurations with SSO are about $500 a month flat ([Langfuse](https://langfuse.com/pricing); [Keycard](https://www.keycard.ai/pricing)) | "Inferred from governance and team-tool prices: the cheapest SSO configurations at Langfuse ($499 a month) and Keycard ($500 a month); Graphite Team ($40 a seat); Factory Teams ($60 plus $40 a seat); Aembit ($20 per agent)." (level 1) |
| "Team $8–25 / seat*" (5) | At or below comparable team plans. The risk is under-pricing a tier that includes SSO and exports (level 1) | Keep the band as a test range, and add a test point above $25 (D5) |
| "Agents are never metered" (5) | Not a market norm. Agent-security tools charge per agent or per resource ([Aembit](https://aembit.io/pricing/); [AWS Security Hub pricing](https://aws.amazon.com/security-hub/pricing/); [Teleport](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_Jan_6_2026_c706e2abf0.pdf)) | "Agents are never metered, unlike agent-security tools that charge per agent or per resource." (D7) |
| "Coordination across agents … Ahead across harnesses." (5) | Warp Enterprise lists cross-harness agent memory, and Warp Factories runs Claude Code and Codex with transcripts. Entire sells shared team agent memory ([Warp](https://www.warp.dev/pricing); [Entire](https://entire.com/)) | Claim the lead only for attribution and records across vendors and their surfaces (D2) |
| "Money is moving into this space" (5) | Funding is not evidence of willingness to pay. Prompt Security sold for $159.3M with "immaterial ARR" ([SEC 10-Q](https://www.sec.gov/Archives/edgar/data/1583708/000158370825000159/s-20251031.htm); [Nasdaq](https://www.nasdaq.com/articles/sentinelone-arr-tops-1-billion-q2)) | Show where buyers pay today: measurement (DX at about $1B; Span per contributor), security control (annual commitments), and audit inside Enterprise plans (D6) |
| "Teams of 5 to 150 engineers on two or more harnesses, where proof is already demanded" (5) | Below Enterprise, 43 people ask for attribution and 3 for approval or audit records. HN yielded no first-hand report of a customer or auditor asking for agent records (2.08) | "…where the vendors' own analytics and audit stop: Team plans, mixed harnesses, and client work." (D1, D4) |
| "Now: Questionnaires ask which AI a team uses and whether a human reviews its work." (5) | Confirmed. Protected branches and PR approvals already answer most of it ([CrashOverride](https://crashoverride.com/resources/knowledge-base/compliance/soc-2-ai-coding-tools); [Accorp Partners](https://accorppartners.com/blogs/soc-2/soc-2-for-ai-companies-in-2026-what-auditors-test-that-didnt-exist-two-years-ago); [Linford & Co](https://linfordco.com/blog/shadow-ai-soc-2/); [Cursor forum 158756](https://forum.cursor.com/t/how-are-we-supposed-to-prevent-catastrophic-mistakes/158756)) | Keep it, and add the three cases where records become necessary (D4) |
| "Agents coordinate, developers continue, and admins answer" (1); "What admins can answer" (3) | Below Enterprise, the reader who asks is the engineering leader, and the questions are about usage, cost and AI-written code (2.08) | "…and leads answer: who ran which agent on what, at what cost, and who approved." (D1) |
| "What was reachable, by whom, and who connected." (3) | 0 people below Enterprise asked for per-connection receipts. Network logs attribute to a device, a tag or a role (2.08) | "Each connection names the run, the repo, whose credential it used, and who approved it." (D10) |
| "Will teams pay? Paid conversions at $8–25 a seat" (6) | No price-sensitivity data exists for agent record or governance tools. The 8% conversion median counts individual signups (level 1) | Test the price shape and a point above $25, at the second-person trigger (D5) |

## 2. Directions for pitch4

Summary (details follow):

| # | Direction | Pitch4 pages it changes | Effect | Confidence |
|---|---|---|---|---|
| D1 | Sell Team to the engineering leader as attribution across harnesses; make audit evidence the by-product | 1, 3, 5 | Both | Medium |
| D2 | Make coverage of every harness and surface the paid core; sharpen "ahead across harnesses" | 5, 1 | Differentiation | Medium |
| D3 | Export into the tools Team buyers already pay for | 5, 6 | Offering | Medium |
| D4 | Narrow "audit without Enterprise" to a packaging difference, named segments and named cases | 5, 3 | Differentiation | Medium on packaging; low as a wedge |
| D5 | Price Team as a card purchase by the engineering leader, and test above $25 | 5, 6 | Offering | Medium |
| D6 | Rebuild page 5's price evidence: governance anchors, a 20-engineer cost line, and where buyers pay today | 5 | Offering | High on anchors; medium on the paid-adoption box |
| D7 | Keep agents unmetered, stated as a contrast with agent-security pricing | 5 | Differentiation | Medium |
| D8 | Make Assured a separate annual sale for security and compliance signers; do not lead with it | 5, 6 | Offering | Medium on not leading; low on the marketplace motion |
| D9 | Ship a vendor-review packet, with a self-service DPA at Team, before asking security to approve | 6, 5 | Offering | Medium |
| D10 | Put actor attribution in every reach receipt; sell receipts as part of Team attribution | 3, 5 | Differentiation | Medium on the difference; low on willingness to pay |
| D11 | Keep attribution in the record; write commit trailers only on request | 6, 2 | Offering | Medium |
| D12 | Rewrite the agency segment as per-client policy, record and cost | 5, 3 | Both | Medium |

**Where to start** (synthesis judgment):
- D6 and the claims table (section 1.7) are cheap, and the evidence for them is firm.
- D1 and D4 together change pitch4's paid story, from audit for security buyers to attribution for engineering leaders, with audit as a by-product.
- D5 decides what the design-partner pilot tests.

### D1. Sell Team to the engineering leader as attribution across harnesses; make audit evidence the by-product

- **Pitch4 change.**
  - Page 1 (the idea): the third reader, "admins answer", in "How it works" and in the diagram.
  - Page 3: the "What admins can answer" list.
  - Page 5: the Team row in "Who pays", and the subhead "The tools are table stakes. The record under your keys is the product."
- **What to change.**
  - Recast the third reader. Today's version is admins answering auditors. The new version is engineering leaders answering:
    - who or which agent;
    - which repo, client or task;
    - which model;
    - what it cost;
    - how much AI-written code was merged;
    - who approved.
  - Lead the Team row with that attribution. List "records an auditor can check" after it, as coming from the same write.
  - On page 3, put the leader's questions (cost and merged AI-written code, by repo or client) first in the admin list, with the auditor's questions below them.
  - [inference, this synthesis] By default, attribute by run, repository, client and team. Make per-person views a team policy that developers can see, consistent with page 2's "Yours unless you share".
- **Why it helps.**
  - It matches what people below the Enterprise line ask for: 43 of the 58 counted.
  - It sells into a purse that already pays (measurement). Audit, by contrast, is a need these companies mostly do not yet voice.
  - It keeps "one write, three readers": the auditor's answer comes from the same record.
- **Evidence.**
  - 43 requests for attribution, against 3 for approval or audit records and 0 for reach receipts (2.08's table).
  - Forum voices: T.H's ROI quote; songcj's "without Enterprise-scale budgets", which also cites "compliance requirements"; Gyurmatag's cost per project; Andrey_Eroftiev's cost pass-through; 0xDEnYO's AI-spend dashboard ([Cursor forum 138430](https://forum.cursor.com/t/any-plans-to-make-ai-code-tracking-api-available-for-teams-plan/138430); [Cursor forum 160895](https://forum.cursor.com/t/chat-agent-session-metadata-for-client-task-and-cost-attribution/160895); [issue #27780](https://github.com/anthropics/claude-code/issues/27780)).
  - Team orgs pipe telemetry into Jellyfish, ClickHouse and Azure Monitor ([issue #71312](https://github.com/anthropics/claude-code/issues/71312); [issue #88490](https://github.com/anthropics/claude-code/issues/88490)).
  - The measurement purse pays: Atlassian–DX at about $1B; Span per contributor ([BNN Bloomberg / Reuters](https://www.bnnbloomberg.ca/business/2025/09/18/atlassian-to-acquire-developer-productivity-platform-dx-for-us1-billion); [Span pricing](https://www.span.app/pricing)).
  - LeadDev (591 leaders; search summary): concern about AI tool cost "nearly doubled", and only 31% measure impact effectively ([LeadDev](https://leaddev.com/the-ai-impact-report-2026/)).
  - Usage trackers draw thousands of stars, and audit tools almost none ([ccusage](https://github.com/ccusage/ccusage)).
- **Counter-evidence.**
  - Paid incumbents already sell to this leader. Jellyfish tracks adoption and spend for Copilot, Cursor and Claude Code (vendor claim) ([SD Times](https://sdtimes.com/software-intelligence-platform/jellyfish-advances-developer-and-agent-productivity-insights-for-the-ai-native-sdlc/)), and DX and Span sell to the same leader. They are top-down, and Jellyfish's data is "not deep code attribution" ([Sacra](https://sacra.com/chat/h/3d690886-e4a6-49e6-8e75-4fb7bcb094e2/)). Both are search summaries.
  - Vendors are closing some gaps. Cursor has "captured this as a feature request internally" ([Cursor forum 160895](https://forum.cursor.com/t/chat-agent-session-metadata-for-client-task-and-cost-attribution/160895)). Anthropic fixed identity in cloud Cowork exports in v2.1.259 ([issue #88490](https://github.com/anthropics/claude-code/issues/88490)).
  - Developers resist being logged: "it should not double as a log of anyone's working hours" ([#97908](https://github.com/anthropics/claude-code/issues/97908)). 0xDEnYO wants per-developer metrics, which sits uneasily with page 2's privacy promise.
  - No one has measured willingness to pay for cross-harness attribution against Jellyfish, DX or Span (2.08 gap).
- **Cost and risk.**
  - The copy changes on pages 1, 3 and 5 are small.
  - Cost and AI-code attribution need model and token data from each harness, plus the link to merged code. Pitch4's first release already lists "run inventory and agent identity" and "commit-to-run links".
  - [inference, this synthesis] Risk: the positioning drifts toward an analytics product, where the sidecar would be a newcomer against funded incumbents.
- **Test.**
  - In design-partner calls, show two versions of the Team page. One leads with attribution: cost per repo or client, merged AI-written code, approver. The other leads with audit evidence.
  - Ask the engineering leader which version they would put on a card, and at what price.
  - Record whether they name Jellyfish, DX, Span or a home-built OTel dashboard as the alternative.
- **Effect and confidence.** Both. Medium. This is the branch's largest demand count, but payment is untested.

### D2. Make coverage of every harness and surface the paid core, and sharpen "ahead across harnesses"

- **Pitch4 change.**
  - Page 5: the "Coordination across agents" row ("Ahead across harnesses") and the two record rows in "Where we stand, piece by piece".
  - Page 1: "The problem" ("Each harness keeps a partial record").
- **What to change.**
  - State the specific difference. The sidecar keeps one attribution record:
    - across vendors: Claude Code, Cursor, Codex, Copilot and the open harnesses;
    - across each vendor's own surfaces;
    - signed, and under the customer's keys;
    - with identity filled in where a vendor's export drops it.
  - Name the nearest paid alternatives and what they lack:
    - Warp: cross-harness memory as a Research Preview, transcripts at Enterprise;
    - Entire: a hosted forge with shared team agent memory;
    - Jellyfish: adoption and spend across three tools, not at run level.
  - On page 1, add to "The problem": each vendor's analytics stop at its own harness and break between its own surfaces.
- **Why it helps.**
  - 2.08 calls this "the part of pitch4 no single vendor will build". [inference]
  - It answers level 1's warning that the paid cross-harness slot is getting crowded.
- **Evidence.**
  - Mixed use in small companies: "tiny startups mostly go with Claude Code (75%) and Cursor (42%)" ([Pragmatic Engineer](https://newsletter.pragmaticengineer.com/p/ai-tooling-2026)).
  - Breaks at surface boundaries:
    - cloud Cowork sessions exported "with no identity attributes" ([issue #88490](https://github.com/anthropics/claude-code/issues/88490));
    - "54% of all Cowork rows" unattributed ([issue #90288](https://github.com/anthropics/claude-code/issues/90288));
    - the Team plan's "only supported mechanism" for usage observability broke ([issue #71312](https://github.com/anthropics/claude-code/issues/71312));
    - OTel for Claude Code on the Web has 37 thumbs-up ([issue #32364](https://github.com/anthropics/claude-code/issues/32364)).
  - Vendor analytics stop at the vendor and sit behind Enterprise:
    - Cursor's "AI Code Tracking API + Conversation Insights" is Enterprise-only ([Cursor forum 149536](https://forum.cursor.com/t/what-features-are-included-in-team-vs-enterprise/149536));
    - a user reports that Claude's Analytics API is Enterprise-only ([issue #67772](https://github.com/anthropics/claude-code/issues/67772)).
  - The crowding: [Warp](https://www.warp.dev/pricing); [Entire](https://entire.com/).
- **Counter-evidence.**
  - Jellyfish already spans three harnesses for adoption and spend (vendor claim; search summary) ([SD Times](https://sdtimes.com/software-intelligence-platform/jellyfish-advances-developer-and-agent-productivity-insights-for-the-ai-native-sdlc/)).
  - Warp Factories hosts Claude Code and Codex harnesses and keeps transcripts at Enterprise ([Warp](https://www.warp.dev/pricing)).
  - Each vendor fix narrows the gap. #88490 was fixed in v2.1.259.
  - This branch did not test which surfaces the sidecar can observe.
- **Cost and risk.**
  - The copy change is small.
  - Delivering the coverage is the capture engine itself.
  - [inference, this synthesis] Risk: claiming coverage of surfaces the sidecar cannot see.
- **Test.**
  - Ask each design partner to list every harness and surface its team used in the past month.
  - Check which of them the first release records with identity.
  - Count how many rows the vendors' own exports leave unattributed.
- **Effect and confidence.** Differentiation. Medium.

### D3. Export into the tools Team buyers already pay for, instead of asking them to adopt a new console

- **Pitch4 change.**
  - Page 5: the Team row's "exports".
  - Page 6: "Next: the team layer", which lists "SIEM export".
- **What to change.**
  - Name the targets:
    - OTLP, with identity filled in across harnesses;
    - engineering-intelligence tools (Jellyfish, DX, Span);
    - SIEMs;
    - GRC platforms (Vanta, Drata).
  - Present the sidecar's admin app as the place to verify and drill down, not a console the leader must live in.
- **Why it helps.**
  - Team buyers already build these pipelines, and still hit identity gaps.
  - 2.08 judged this a cheaper route to market than asking a 5–150-engineer company to buy a new audit console. [inference]
  - It fits level 1's finding that money goes to purchases buyers already make.
- **Evidence.**
  - Self-built pipelines on Team plans: an OTel collector into ClickHouse, Azure Monitor, and Jellyfish ([issue #88490](https://github.com/anthropics/claude-code/issues/88490); [issue #71312](https://github.com/anthropics/claude-code/issues/71312)).
  - The codenote guide for Claude Team calls OTel "the most practical way to secure audit trails on the Team plan" ([codenote](https://codenote.net/en/posts/claude-team-audit-log-workarounds/)).
  - An HN commenter refers to "observability tools that we already pay for" ([HN 47413654](https://news.ycombinator.com/item?id=47413654)).
  - Level 1 found no standalone record product with revenue; money goes to measurement, security control and bundled audit.
- **Counter-evidence.**
  - [inference, this synthesis] Exporting identity-rich records into third-party analytics takes them outside the encrypted boundary that pages 1, 3 and 4 promise. Each export has to be the customer's choice, and the pitch should say so.
  - [inference, this synthesis] Feeding Jellyfish or DX could make the sidecar a data source for the incumbents that hold the budget.
  - This branch did not test whether GRC platforms accept such evidence. 2.08 found only MCP servers that let agents read compliance data ([Vanta MCP](https://help.vanta.com/en/articles/14094979-connecting-to-vanta-mcp)). Branch 1.8 covers that question (`SYNTH-1.08-buyer-evidence-artifacts.md`).
- **Cost and risk.**
  - Each target is one export to build.
  - Integrations with partners need those partners' cooperation.
- **Test.**
  - Record where each design partner's AI-tool usage data goes today.
  - Ship the OTLP export first, and measure whether the partner's existing dashboards fill their unattributed rows.
- **Effect and confidence.** Offering. Medium.

### D4. Narrow "audit without Enterprise" to a packaging difference, named segments and named cases

- **Pitch4 change.**
  - Page 5: the Team row in "Who pays", "Where we start", and the "Now" and "December 2027" box.
  - Page 3: "What admins can answer".
- **What to change.**
  - In the Team row, say what the category holds back: "SSO and a signed audit export in Team, where Cursor, Claude, Graphite, Langfuse and Factory keep audit logs above their team plans."
  - In "Where we start", name where the gap bites:
    - Claude teams under 20 seats;
    - Cursor and Devin Teams orgs (Devin's Teams plan goes up to 200 users);
    - agencies and outsourcers with client AI terms.
  - In the "Now" box, keep today's asks, and add the three cases that make agent records necessary:
    1. an auditor samples AI-authored changes;
    2. agents act without a human gate;
    3. a client contract restricts AI, or prices it per engagement.
  - On page 3, say what vendor audit logs leave out even at Enterprise:
    - Cursor's audit logs "only record management events, not prompt content";
    - Copilot's audit log "does not include client session data".
- **Why it helps.** It keeps a real packaging contrast without claiming a wedge the evidence does not show.
- **Evidence.**
  - Audit held for the top tier: section 1.1 ([Langfuse](https://langfuse.com/pricing); [Graphite](https://graphite.com/pricing); [Factory](https://factory.com/pricing); [Cursor pricing](https://cursor.com/pricing); [Claude help center](https://support.claude.com/en/articles/9797531/what-is-the-enterprise-plan)).
  - The SSO tax runs from +50% to +425% ([sso.tax](https://sso.tax/)).
  - The walls are lower than they look:
    - Claude's self-serve Enterprise starts at 20 seats, paid by card ([Claude help center](https://support.claude.com/en/articles/9797531/what-is-the-enterprise-plan));
    - Copilot's audit log includes "Agent activity on the GitHub website" ([GitHub docs](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-for-organization/review-activity/review-audit-logs)).
  - Where vendor audit ends ([codenote](https://codenote.net/en/posts/cursor-teams-audit-log-workarounds/); [GitHub docs](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-for-organization/review-activity/review-audit-logs)).
  - The three cases:
    - CrashOverride's list of Type 2 records ([CrashOverride](https://crashoverride.com/resources/knowledge-base/compliance/soc-2-ai-coding-tools));
    - Accorp's attribution of each agent action ([Accorp Partners](https://accorppartners.com/blogs/soc-2/soc-2-for-ai-companies-in-2026-what-auditors-test-that-didnt-exist-two-years-ago));
    - client terms ([136492](https://forum.cursor.com/t/repository-level-ai-policy-file-ai-policy-txt-for-client-compliance/136492); [160895](https://forum.cursor.com/t/chat-agent-session-metadata-for-client-task-and-cost-attribution/160895)).
- **Counter-evidence.**
  - The demand is thin (2.08):
    - only 3 people asked for approval or audit records;
    - audit workaround tools have at most 2 stars and 0 forum likes;
    - HN yielded 0 first-hand asks from customers or auditors.
  - The consultant guides are vendor-adjacent. CrashOverride sells "continuous evidence", and Accorp sells audits.
  - Level 1 found no evidence on whether putting SSO in a low tier eats into upgrades.
  - Keycard's comparison table may include export in Team, a possible exception besides Span ([Keycard](https://www.keycard.ai/pricing)).
- **Cost and risk.**
  - It is a copy change.
  - Risk: with SSO and export in Team, there is less left to sell in Assured (see D8).
- **Test.**
  - Count how many design partners fall in the three named segments.
  - Count how many have met one of the three cases in the past year.
  - Read both counts against conversion to Team.
- **Effect and confidence.** Differentiation. Medium on the packaging contrast; low on audit as a wedge.

### D5. Price Team as a card purchase by the engineering leader, and test above $25

- **Pitch4 change.**
  - Page 5: the "Who pays" table and the price footnote.
  - Page 6: the pilot rows "Does the ledger sell?" and "Will teams pay?".
- **What to change.**
  - **Shape.** Either a small team fee plus a low seat price (the Factory and Devin pattern), or flat team bundles with unlimited members (the Langfuse and Keycard pattern).
  - **Payment.** Self-serve by card up to about 25 seats, and invoices above that.
  - **Viewers.** Free read-only seats for reviewers, auditors and executives, following Span. This delivers part of pitch4's "visible audit member" before Assured.
  - **Pilot.**
    - Keep measuring conversion when a second person joins; pitch4 already does.
    - Test two price shapes.
    - Test at least one price above $25, since level 1 found the risk is under-pricing.
- **Why it helps.**
  - It matches how the signer pays: by card.
  - It keeps the free-to-team trigger where pitch4 already puts it.
  - It avoids pure seat pricing, which the 2026 survey data disfavor.
- **Evidence.**
  - Card versus invoice: section 1.2 ([Cursor forum 149536](https://forum.cursor.com/t/what-features-are-included-in-team-vs-enterprise/149536); [Cursor pricing](https://cursor.com/pricing); [Claude help center](https://support.claude.com/en/articles/9797531/what-is-the-enterprise-plan)).
  - Tailscale: "a dev manager or TLM pays us on a corporate credit card" ([Tailscale blog](https://tailscale.com/blog/free-plan)).
  - Self-serve caps and team-fee shapes: [Warp](https://www.warp.dev/pricing); [Factory](https://factory.com/pricing); [Devin pricing](https://devin.ai/pricing).
  - Flat bundles: [Langfuse](https://langfuse.com/pricing); [Keycard](https://www.keycard.ai/pricing).
  - Free viewers: [Span pricing](https://www.span.app/pricing).
  - Vendr's figures suggest that Cursor purchases managed by procurement are mostly above about 60 seats ([Vendr](https://www.vendr.com/marketplace/cursor)).
  - Price level: the 20-engineer table in section 1.1.
  - Investors' preference against seats: [Growth Unhinged](https://www.growthunhinged.com/p/the-state-of-b2b-monetization-in-2026).
- **Counter-evidence.**
  - The branch found no price-sensitivity data, and no conversion data for "second person joins" triggers (level 1 gaps).
  - The Growth Unhinged and ChartMogul figures come from secondary coverage or search excerpts, and the 2025 and 2026 editions conflict.
  - Free users do not fund hosting ([Vibe Kanban](https://www.vibekanban.com/blog/shutdown)). Pitch4 makes self-hosting free, so a card buyer can choose not to pay.
  - A flat bundle gives up growth per seat. "Not enough expansion revenue" is the top challenge for flat-fee and seat-based companies ([Growth Unhinged](https://www.growthunhinged.com/p/the-state-of-b2b-monetization-in-2026)).
- **Cost and risk.**
  - Changing the page costs little.
  - [inference, this synthesis] Risk: a higher test price slows adoption during the pilot.
- **Test.**
  - Split the design partners across two price pages. For example: team fee plus seat versus a flat bundle, and $15 versus $30 a seat.
  - Record conversions when a second person joins, who paid, and how they paid.
- **Effect and confidence.** Offering. Medium.

### D6. Rebuild page 5's price evidence: governance anchors, a 20-engineer cost line, and where buyers pay today

- **Pitch4 change.** Page 5: the price footnote and the "Money is moving into this space" box.
- **What to change.**
  - Replace the harness-seat anchors (Tailscale, Agent 365, Copilot Business, Claude Team) with governance anchors:
    - the cheapest Langfuse configuration with SSO ($499 a month);
    - Keycard Team ($500 a month);
    - Aembit ($20 per agent a month);
    - Span (per contributor).
  - Add one line of cost: for 20 engineers, Team costs $1,920–$6,000 a year and Assured $9,360.
  - Replace the funding box, or pair it with where buyers pay today:
    - measurement: Atlassian–DX at about $1B, and Span per contributor;
    - security control: annual commitments of $10,000–200,000;
    - audit inside Enterprise plans.
- **Why it helps.**
  - The current anchors compare the sidecar with harness seats that bundle model usage and are turning into credits.
  - Funding is not evidence of willingness to pay.
- **Evidence.** [GitHub Blog](https://github.blog/news-insights/company-news/github-universe-2026-evolving-every-layer-of-the-stack/); [Claude pricing](https://claude.com/pricing); [Langfuse](https://langfuse.com/pricing); [Keycard](https://www.keycard.ai/pricing); [Aembit](https://aembit.io/pricing/); [Span pricing](https://www.span.app/pricing); Prompt's "immaterial ARR" ([Nasdaq](https://www.nasdaq.com/articles/sentinelone-arr-tops-1-billion-q2)); [BNN Bloomberg / Reuters](https://www.bnnbloomberg.ca/business/2025/09/18/atlassian-to-acquire-developer-productivity-platform-dx-for-us1-billion).
- **Counter-evidence.**
  - Several security figures are search excerpts or placeholders. Zenity's marketplace entry shows $1.00, and Aembit's shows $200.
  - Span's price is not public.
  - Langfuse and Keycard are not coding-agent tools, so buyers may not see them as comparable.
- **Cost and risk.** Low.
- **Test.** Ask leaders at design partners which products they would compare the Team price with. Record whether they name harness seats or governance tools.
- **Effect and confidence.** Offering. High on correcting the anchors; medium on the box of paid adoption.

### D7. Keep agents unmetered, and say it is a deliberate contrast with agent-security pricing

- **Pitch4 change.** Page 5: the footnote, "Agents are never metered".
- **What to change.** "Agents are never metered, unlike agent-security tools that charge $20 per agent or $130 per resource a month. Teams that run many parallel agents pay for people, not agents."
- **Why it helps.** It turns a footnote into a selling point for the beachhead's heaviest users.
- **Evidence.**
  - Agent-security tools meter agents and resources: [Aembit](https://aembit.io/pricing/); [AWS Security Hub pricing](https://aws.amazon.com/security-hub/pricing/); [Teleport](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_Jan_6_2026_c706e2abf0.pdf).
  - Harness vendors and Microsoft do not ([Microsoft licensing FAQ](https://microsoft.com/licensing/faqs/122)).
- **Counter-evidence.**
  - Not metering agents gives up the unit security buyers already accept (level 1).
  - Open, and not followed up: do security buyers read unmetered agents as a sign of a developer tool rather than a control?
- **Cost and risk.**
  - Low.
  - Hosted storage, edge traffic and mail stay metered, as pitch4 already says.
- **Test.** In Assured conversations, ask security buyers whether they expect to count governed agents, and whether unmetered agents changes how they see the product.
- **Effect and confidence.** Differentiation. Medium.

### D8. Make Assured a separate annual sale for security and compliance signers; do not lead the 5–150 pitch with it

- **Pitch4 change.**
  - Page 5: the Assured row and "Where we start".
  - Page 6: "Last: inbox and assurance".
- **What to change.**
  - Keep about $39 a seat as the list price. Sell Assured as an annual commitment with a floor, through marketplace private offers where security already buys.
  - Name the signer: security or compliance.
  - Name the buyers:
    - regulated teams;
    - firms nearing 150 or more engineers;
    - teams facing a binding client or audit case.
  - Lead "Where we start" with the Team buyer, and put the segments that start from assurance after it.
- **Why it helps.**
  - Team's signer is the engineering leader, paying by card. Assured's buyer buys differently.
  - At 20 seats, $39 comes to $9,360 a year, below Lasso's $20,000 commitment. A floor brings Assured closer to the size of a security deal.
- **Evidence.**
  - Security deal sizes and motions: [AWS Security Hub pricing](https://aws.amazon.com/security-hub/pricing/); [Noma](https://aws.amazon.com/marketplace/pp/prodview-kd2qklag2zzym); [Lasso for Employees](https://aws.amazon.com/marketplace/pp/prodview-7ygm7pa3k5agg); [Prompt Security](https://aws.amazon.com/marketplace/pp/prodview-lzvx5ody7qffw).
  - The budget split: 24% / 38% / 38% ([CSO Online](https://www.csoonline.com/article/4223455/)).
  - Who signs: section 1.2 (2.08).
- **Counter-evidence.**
  - The deal figures are weak (level 1):
    - marketplace figures are search excerpts, and some are placeholders;
    - none are for 5–150-engineer companies;
    - no deal for an Assured-like product was found.
  - 38% fund AI security from IT, data or innovation budgets, so security may approve rather than pay (level 1).
  - Level 1 inferred that engineering is Assured's likely champion. Level 2 points to security or compliance as the signer. Both are inferences, not survey results.
  - The figure of about 150 employees for a security hire comes from a search summary.
- **Cost and risk.**
  - Marketplace listings take setup work, which the notes do not cost.
  - [inference, this synthesis] An annual floor could price out small regulated teams.
- **Test.** Ask design partners in regulated segments who would sign an Assured order, from which budget, and whether a marketplace private offer would help.
- **Effect and confidence.** Offering. Medium that Assured should not lead; low on the marketplace motion and the floor.

### D9. Ship a vendor-review packet, with a self-service DPA at Team, before asking security to approve

- **Pitch4 change.**
  - Page 6: "Trust documents first".
  - Page 5: the Team row.
- **What to change.**
  - Add three items to "Trust documents first":
    - the sidecar's own SOC 2 plan;
    - a data-flow diagram;
    - a self-service DPA available at Team.
  - Say in the Team row that the DPA does not require an Enterprise upgrade.
- **Why it helps.**
  - In small companies, security, IT and legal appear at purchase to review the vendor itself.
  - Cursor reserves "MSA & DPA instead of the standard Terms" for Enterprise.
  - One user says that without a self-service DPA, smaller teams are "forced to either: Upgrade to Enterprise…".
- **Evidence.**
  - [Cursor forum 149536](https://forum.cursor.com/t/what-features-are-included-in-team-vs-enterprise/149536); [152255](https://forum.cursor.com/t/feature-request-self-service-dpa-for-pro-business-plans/152255); [67361](https://forum.cursor.com/t/can-anyone-share-me-a-soc2-report/67361); [1339](https://forum.cursor.com/t/document-q-a-for-security-compliance-concerns-for-business-use-cases/1339); [13979](https://forum.cursor.com/t/security-and-data-management-questions-for-cursor/13979); [165666](https://forum.cursor.com/t/request-for-documentation-bugbot-repository-isolation-boundaries-for-gitlab/165666); [111148](https://forum.cursor.com/t/integrate-with-rippling-hris/111148).
  - 2.08 also cites 1.9's finding that the sidecar will be reviewed as a top-tier vendor.
- **Counter-evidence.**
  - The figures on security ownership in small companies are weak and secondary ([Decryption Digest](https://www.decryptiondigest.com/blog/startup-security-foundation-series-a-first-priorities-budget-constraints); [Sacra summary](https://sacra.com/chat/h/6440134e-3007-49cf-845d-b5ee25f50ebb/)).
  - The notes do not say what a SOC 2 costs or how long it takes.
  - The requests above ask for the vendor's reports and terms. Open source alone does not answer them.
- **Cost and risk.**
  - A DPA template is cheap. A SOC 2 is not, and these notes do not cost it.
  - [inference, this synthesis] A company still in design has no SOC 2 report to show yet.
- **Test.** For each design partner, record which documents its IT, security or legal reviewer asked for before approving the install, and how long approval took.
- **Effect and confidence.** Offering. Medium.

### D10. Put actor attribution in every reach receipt; sell receipts as part of Team attribution, not on their own

- **Pitch4 change.**
  - Page 3: the "Records" line on each reach card, and "What was reachable, by whom, and who connected."
  - Page 5: "reach receipts" in the Team row.
- **What to change.**
  - Each receipt names:
    - who initiated the run;
    - whose credential was used;
    - who approved;
    - the run and the repo;
    - the model.
  - Present receipts as part of the Team attribution record, not as a separate line item.
- **Why it helps.**
  - Device, tag and role logs cannot say which run or person a connection served.
  - That gap is what the identity failures show. No one below Enterprise asks for network logs as such.
- **Evidence.** [Tailscale](https://tailscale.com/blog/codex-cloud-tailscale); [Devin Connect](https://docs.devin.ai/enterprise/deployment/devin-connect); [issue #84504](https://github.com/anthropics/claude-code/issues/84504); [Cursor forum 158866](https://forum.cursor.com/t/cursor-cloud-agent-sessions-are-shared-across-users-act-on-behalf/158866); [Cursor forum 168503](https://forum.cursor.com/t/cloud-agent-pr-attribution-gh-account-wide-app-vs-personal-oauth-confusion/168503); [discussion #203213](https://github.com/orgs/community/discussions/203213); [issue #90288](https://github.com/anthropics/claude-code/issues/90288).
- **Counter-evidence.**
  - 0 people below Enterprise asked for per-connection receipts.
  - The NERC CIP need in #84504 comes from an Enterprise context.
  - There is no evidence that buyers below Enterprise will pay extra for receipts (2.08 gaps).
- **Cost and risk.**
  - The receipt needs harness context (the run and the approver) joined to the network grant.
  - Pitch4 already promises that each grant is approved by a person and recorded (page 3), and it schedules reach receipts for the team layer (page 6).
- **Test.**
  - In pilots with cloud-agent reach, ask the reviewer: "Which run, and which person, used this connection?"
  - Have them answer once from Tailscale or CloudTrail logs and once from the sidecar's receipt.
  - Record which answer they trust.
- **Effect and confidence.** Differentiation. Medium on the difference; low on willingness to pay.

### D11. Keep attribution in the record; write commit trailers only on request

- **Pitch4 change.**
  - Page 6: "commit-to-run links" in the first release.
  - Page 2: "Yours unless you share".
- **What to change.**
  - Keep the link from commit to run in the record.
  - Generate trailers or notes, such as "Assisted-by", only when a team or developer turns them on.
  - Offer a verified trailer for teams whose auditors ask for one.
- **Why it helps.** Developers push back on attribution stamped into commits they did not choose, but they accept accurate attribution.
- **Evidence.**
  - 20 issues with 68 thumbs-up oppose default trailers ([#4287](https://github.com/anthropics/claude-code/issues/4287); [#7543](https://github.com/anthropics/claude-code/issues/7543); [#83813](https://github.com/anthropics/claude-code/issues/83813); [#103691](https://github.com/anthropics/claude-code/issues/103691)).
  - The issue asking for "Assisted-by" has 52 thumbs-up ([#36105](https://github.com/anthropics/claude-code/issues/36105)).
  - #104719 asks for "verified commit attribution" parity. Only its title was seen ([#104719](https://github.com/anthropics/claude-code/issues/104719)).
- **Counter-evidence.**
  - CrashOverride recommends commit trailers as SOC 2 evidence ([CrashOverride](https://crashoverride.com/resources/knowledge-base/compliance/soc-2-ai-coding-tools)).
  - Cursor attributes agent PRs to the user to prevent self-approval ([Cursor forum 168503](https://forum.cursor.com/t/cloud-agent-pr-attribution-gh-account-wide-app-vs-personal-oauth-confusion/168503)). So choices about attribution touch review governance.
- **Cost and risk.** Low.
- **Test.** Turn trailers off by default in the pilots. Count how many teams turn them on, and why.
- **Effect and confidence.** Offering. Medium.

### D12. Rewrite the agency segment as per-client policy, record and cost

- **Pitch4 change.**
  - Page 5: the first "Where we start" bullet, "Consultancies and agencies under client AI-disclosure terms".
  - Page 3: "Proof for a client that a person approved a change, without the code."
- **What to change.**
  - Name the two client asks the notes found:
    - clients that restrict AI by contract, which calls for policy enforced per client;
    - clients that want the AI cost of each task passed through, which calls for a cost record per client.
  - Add cost and AI use to the proof a client receives.
- **Why it helps.**
  - Agencies and outsourcers are the clearest small-company segment whose need is driven by clients.
  - Their need maps to per-client policy plus a per-client record, more than to SOC 2 (2.08). [inference]
- **Evidence.**
  - DC_9000: "We run a dev agency working with 15+ clients simultaneously … some clients contractually prohibit AI code generation" ([136492](https://forum.cursor.com/t/repository-level-ai-policy-file-ai-policy-txt-for-client-compliance/136492)).
  - In the cost-attribution thread ([160895](https://forum.cursor.com/t/chat-agent-session-metadata-for-client-task-and-cost-attribution/160895)):
    - Andrey_Eroftiev wants per-task cost attribution for pass-through;
    - Adam_Bercovich wants "enterprise cost attribution for teams working across multiple clients, projects, ERP tasks, Jira tickets, GitHub issues, and parallel Cursor chats".
  - Startups whose finance and legal customers require compliance from their vendors ([74447](https://forum.cursor.com/t/important-does-cursor-generate-copyrighted-code/74447)).
- **Counter-evidence.**
  - Only a handful of people.
  - 2.08 found no data on how many agencies and outsourcers face client AI clauses.
  - Branch 1.8 (notes 3.06 and 4.04) studied client terms at these suppliers in depth. Read `SYNTH-1.08-buyer-evidence-artifacts.md` before acting on this direction.
- **Cost and risk.**
  - The copy change is small.
  - Policy per client adds product scope: the sidecar must map repos to clients.
- **Test.**
  - Recruit two or three agencies or outsourcers among the design partners.
  - Record whether their clients' terms mention AI.
  - Ask whether they would pass a per-client report on to the client.
- **Effect and confidence.** Both. Medium.

## 3. How level 2 changed or qualified level 1

| Level-1 finding or direction | What level 2 found | Net effect |
|---|---|---|
| "Enterprise gating leaves a wedge"; the direction to offer "audit without Enterprise" in Team (differentiation, medium) | 3 people asked for approval or audit records, against 43 for attribution. Audit workaround tools have at most 2 stars. HN yielded 0 first-hand asks. Claude's self-serve Enterprise is a card purchase from 20 seats, and Copilot Business logs GitHub-side agent activity. The gap bites for Claude teams under 20 seats, Cursor and Devin Teams orgs, and agencies and outsourcers | **Narrowed.** A stated packaging difference and a proof point inside Team, not the wedge (D4) |
| "Measurement has a proven buyer", and the direction to present the paid record as evidence for purchases buyers already make (both, medium) | 43 of 58 people ask for attribution of usage, cost and AI-written code, tied to ROI and to passing costs to clients. Team orgs pipe telemetry into Jellyfish, ClickHouse and Azure Monitor | **Strengthened** into the lead: attribution for the engineering leader (D1), delivered through exports to the tools buyers use (D3) |
| "Engineering is the likely champion for Assured … with security as approver" (inference, not survey-tested) | For Team, the engineering leader signs, by card. Assured is a different sale: annual, signed by security or compliance at regulated buyers or firms nearing 150 or more engineers | **Split.** Confirmed for Team. For Assured, the signer probably shifts to security or compliance. Both remain inferences (D8) |
| The direction to make Team payable on a manager's card (offering, medium), with "distinct motions per tier" | Cursor reserves invoicing for Enterprise. Claude's Team-to-Enterprise upgrades are paid by card. Vendr's minimum (about 61 seats at $40) suggests that companies with 5–60 engineers mostly buy self-serve | **Confirmed** (D5) |
| "The paid cross-harness slot is getting crowded" (Warp, Entire) | Each vendor's analytics, AI-code tracking and OTel stop at its own harness and break at surface boundaries. Small teams mix Claude Code and Cursor. Jellyfish spans three tools, but not at run level | **Qualified.** Crowded for memory and transcripts; open for attribution across vendors and surfaces (D2) |
| "Audit is the Enterprise lever across the category" | Confirmed for Cursor (audit logs, service accounts, invoicing, the AI Code Tracking API), Claude (audit logs, SCIM, the Compliance API) and Devin (SSO; the audit API sits under `/enterprise/`). Copilot's audit log shows GitHub-side agent activity, but whether Business plans see it is unconfirmed | **Confirmed**, with Copilot Business still to check (D4) |
| Pitch4's Team band sits "at or below" comparable plans; the risk is under-pricing | Cursor Team is "$30+" on the page and "$40" according to staff. Devin Teams costs $80 plus $40 a seat. Vendr lists Cursor Business at $40–50 | **Unchanged**, with more anchors at $30–50 (D5, D6) |
| Not in level 1: what auditors and questionnaires ask small companies for | An inventory of AI tools, an approval process, human review, and the vendor's own SOC 2 report or DPA. PR approvals answer most of it. Agent records appear only in stronger, vendor-adjacent asks | **New.** Today's asks do not require the sidecar, and three cases do (D4). Security needs a vendor-review packet (D9) |
| Not in level 1 (raised by 1.3): reach receipts versus device and tag logs | 0 people asked for reach receipts. The visible demand is in identity failures | **New.** Receipts differ only if they carry actor attribution (D10) |
| Not in level 1: how developers view attribution | 20 issues (68 thumbs-up) oppose default commit trailers, and 52 thumbs-up back "Assisted-by" | **New.** Attribution belongs in the record, with trailers on request (D11) |
| Level 1 found little user voice on paying for a record (three HN usernames) | 58 people counted on the Cursor forum and in Claude Code issues | **Evidence base strengthened**, but for attribution rather than audit |
| Directions on unmetered agents (medium), the Assured marketplace motion (low), free viewer seats, and measuring conversion at the team trigger | Not tested at level 2 | **Unchanged** (D7, D8, D5) |
| Level 1's other open questions: the security purse's unit, standalone record revenue, conversion when a second person joins, per-agent metering | Not followed up | **Open** (section 4) |

## 4. What remains open

1. **Direct willingness to pay.**
   - No price-sensitivity data (Van Westendorp or Gabor-Granger) exists for agent record or governance tools, or for attribution and audit exports at Team.
   - No one has measured willingness to pay for cross-harness attribution against Jellyfish, DX or Span. None of the three publishes prices, and the notes found no Tropic data for Cursor, Claude or Copilot.
   - Only pricing tests with design partners can settle this.
2. **Conversion when a second person joins.** No rates are published for open-source developer tools with hosted team tiers. It is also unknown whether a flat team fee beats per-seat pricing at that step (level-1 open question c2-1.10-5).
3. **Cannibalization.** Does putting SSO and a signed export in Team reduce upgrades to Assured?
4. **The security purse's unit** (c2-1.10-3).
   - What do security buyers pay per developer for coding-assistant security? The term of SHI's $300 "per developer" Prompt Security SKU is unknown.
   - What counts as a "resource" in Noma's and Zenity's $130 pricing?
   - Marketplace figures remain search excerpts, and some are placeholders.
5. **Revenue from standalone records** (c2-1.10-4).
   - Entire's forge pricing and Span's price per contributor are unpublished.
   - No revenue was found for Teleport, Zenity or Keycard.
   - No case study names an agent record as the reason for a purchase.
6. **Per-agent metering** (c2-1.10-6). Will agent-governance pricing converge on per-agent or per-resource units? Do security buyers read "agents never metered" as a sign of a developer tool rather than a control?
7. **Who signs, measured.**
   - No survey breaks out ownership of coding-agent governance by company size.
   - The full LeadDev 2026 and Pragmatic Engineer reports are gated, and the Gartner note returned 403.
   - No Vendr or Tropic data exists by buyer department, and no platform-engineering budget data was found.
   - The conflict between Felicis (78% with a dedicated budget) and IANS (24% with a separate line) is unresolved.
8. **Auditor practice.**
   - A-LIGN, Prescient, Schellman, Johanson, Drata, Secureframe and Vanta have no SOC 2 publication specific to coding agents.
   - No GRC-vendor dataset gives the share of 2026 questionnaires with AI or coding-agent questions.
   - Without interviews, what audit firms actually do is unknown.
9. **Channels that may undercount demand.**
   - Reddit (r/cursor, r/ClaudeAI, r/sysadmin, r/grc) was unreachable.
   - The Claude Developers Discord is not searchable.
   - Windsurf and Devin have no public forum.
   - GitHub Community search was unreliable, so demand from Copilot Business users may be undercounted.
   - It is unconfirmed whether Copilot Business organization owners can see `actor:Copilot` agent events.
10. **How fast the vendors close the gap.**
    - How many Team-plan companies run their own OTel pipeline?
    - How quickly will vendors bring analytics, identity and audit down to Team plans? Cursor has "captured this as a feature request", and Anthropic fixed one export in v2.1.259.
11. **Receipts.** Would buyers below Enterprise pay extra for per-connection reach receipts?
12. **Agencies and outsourcers.** How many face client AI clauses? Branch 1.8's notes 3.06 and 4.04 address this; see `SYNTH-1.08-buyer-evidence-artifacts.md`.
13. **An unattributed claim.** A search summary said Anthropic calls OTel "not a replacement for audit logs". The notes could not tie it to a page, so it is not used here.
