# Synthesis of branch 1.7: open core, "hosted blind", and what the Assured tier can sell

**Branch.** 1.7 (level 1), then 2.13 (level 2), then 3.02 and 3.09 (level 3), then 4.05 (level 4). The notes files are:
- [L1-1.07](L1-1.07-open-core-business-models.md): how open-source, end-to-end-encrypted (E2EE) products package, price and license an open core plus a hosted service.
- [L2-2.13](L2-2.13-how-do-end-to-end-encrypted-products-deliver-leg.md): how E2EE products deliver legal hold, eDiscovery, retention and SIEM export without the server reading plaintext; how they price it; whether regulators and buyers accept a reader the customer runs.
- [L3-3.02](L3-3.02-can-legal-hold-and-retention-reach-sessions-held.md): whether legal hold and retention can reach developer-keyed vaults without escrowing developers' keys, in a form US counsel and EU works councils and DPOs accept.
- [L3-3.09](L3-3.09-for-broker-dealers-investment-firms-and-other-re.md): whether regulated finance firms must keep coding-agent sessions, approvals and ledger entries.
- [L4-4.05](L4-4.05-how-often-do-litigation-holds-discovery-requests.md): how often holds and discovery reach AI transcripts, and what archive and eDiscovery vendors charge to capture AI interactions.

**Conventions.**
- Written 1 November 2026. Every claim comes from the five notes, and the links are the notes' own.
- Labels carry over from the notes: "vendor claim" (a company about itself), "search excerpt" (a search-result summary of a page not opened), "secondary" (a third party's report), and "inference" (the researcher's reasoning, not a source).
- Quotes from pitch4 come from [pitch4.html](/Users/brien/urnetwork/sidecar/pitch4.html). Pitch4 pages: 1 the idea, 2 for developers, 3 for security buyers, 4 open source and open weights, 5 market and pricing, 6 the plan.
- Nothing here is legal advice; the notes say the same of their own readings.
- Hacker News counts are of self-selected commenters. They show which arguments people make, not how common each view is.

---

## 1. What the branch found

### In one paragraph
"Open core, hosted blind" is a sound way to license and sell the product, but the deeper levels moved where the money and the compliance features sit:
- **Legal hold does not carry the Assured price.** Preservation can run blind and belongs in Team. Producing readable copies needs a key holder that the customer runs. Microsoft meters AI holds at cents per seat, Google includes them, and finance firms pay about $8–18 per seat for an AI capture channel, so legal hold cannot justify about $39.
- **Regulated finance needs change records, not transcripts.** No US or EU rule requires coding-agent sessions to be kept. Binding rules for algorithmic-trading firms, SCI entities and EU financial entities do require change records that name the maker and the approver, which is the ledger.
- **Two differentiators survive with moderate support:**
  - holds and exports for agents that have no vendor compliance feed (other harnesses, open harnesses, local models);
  - a hold design that developers can see and a works council can co-sign, which no tool reviewed in this series offers, as far as the series found.
- **A third is untested:** a host holding only ciphertext may insulate customers from preservation orders served on their vendors. This is an inference that needs counsel.

### Level 1 (1.7): packaging, prices, licences and trust for open-source E2EE products
**Three revenue models** ([L1-1.07 §1](L1-1.07-open-core-business-models.md)):
- **Paid licence keys for self-hosting:** Bitwarden, GitLab, Mattermost, Langfuse, Infisical, NetBird.
- **Free, unsupported self-hosting, with every paid feature in the cloud:** PostHog, Sentry, Supabase.
- **Charging only for infrastructure the vendor runs:** Zulip's push relay, Tailscale's closed coordination server, consumer E2EE storage.

**Seat prices and gating:**
- Network and security tools put SSO, SCIM and audit logs in their first or second paid tier, at $4–18 per user per month:
  - Bitwarden: SCIM in Teams at $4 ([Bitwarden pricing](https://bitwarden.com/pricing/business/)).
  - NetBird: SSO, SCIM and audit logging in Team at €6 ([NetBird pricing](https://netbird.io/pricing)).
  - Tailscale: SCIM in Standard at $8 ([Tailscale pricing](https://tailscale.com/pricing)).
- No network, VPN, password-manager or E2EE-communication tool in the set has a per-user price near $39.
  - The highest are Proton Workspace Premium at $19.99 ([Proton plans](https://proton.me/business/plans)) and Tailscale Premium at $18.
  - The nearest anchors are Zed Business at $30 ([Zed](https://zed.dev/pricing)) and Infisical Advanced at $40 per human or machine identity ([Infisical](https://infisical.com/pricing)).
- What enterprise tiers hold back:
  - retention controls, legal hold, eDiscovery and compliance export (Mattermost Enterprise; [Mattermost](https://mattermost.com/pricing/));
  - SIEM streaming (Infisical Enterprise, NetBird Business);
  - FIPS and air-gapped builds (Langfuse Government; [Langfuse self-host](https://langfuse.com/pricing-self-host));
  - SLAs.
- Non-human resources are priced low or metered:
  - Tailscale: $1 a month per tagged resource beyond 50.
  - NetBird: €0.50 per extra machine.
  - Infisical: $20–40 per machine identity, and $2 per 1,000 Agent Vault requests.
  - Pitch4's "Agents are never metered" is therefore a positioning choice, not the market norm.

**Revenue disclosures:**
- **GitLab** is the only primary revenue disclosure. FY2026 revenue was $955.2 million, of which $864.7 million was "Subscription—self-managed and SaaS" and $90.5 million "License—self-managed and other" ([8-K](https://www.sec.gov/Archives/edgar/data/1653482/000162828026013795/gitlab-ex99120260131fy26.htm)). A secondary source puts SaaS at 31% of Q3 FY2026 revenue, implying about 69% self-managed ([Nasdaq/Zacks](https://www.nasdaq.com/articles/gitlab-shares-down-despite-q3-earnings-beat-revenues-y-y)).
- **Langfuse** claims ">8,000 monthly active self-hosted instances" and earns from Cloud and enterprise self-hosting (vendor claim; [Langfuse](https://langfuse.com/blog/2025-06-04-open-sourcing-langfuse-product)).
- **PostHog** found that the 3.5% of users on Kubernetes took "an outsized amount of time", and dropped paid self-hosted licences ([PostHog](https://posthog.com/blog/sunsetting-helm-support-posthog)).

**Licences ([L1-1.07 §2](L1-1.07-open-core-business-models.md)):**
- **What kept or restored trust in 2023–2025:** AGPL-3.0 for servers, a commercial licence made possible by a CLA, and permissive licences for clients. Element ([blog](https://element.io/blog/element-to-adopt-agplv3/)), Elastic ([blog](https://www.elastic.co/blog/elasticsearch-is-open-source-again)), Redis ([blog](https://redis.io/blog/agplv3/)) and NetBird ([announcement](https://netbird.io/knowledge-hub/netbird-agpl-announcement)) all took this route.
- **What produced lasting forks:** moving open code to source-available terms.
  - HashiCorp's BSL led to OpenTofu, which has 30,690 GitHub stars.
  - Redis's SSPL led to Valkey, which has 27,576 stars.
  - Redis's CEO wrote that the change "hurt our relationship with the Redis community".
- **The sharpest reactions came when something users already had was taken away:**
  - **Mattermost capped stored messages on self-hosted servers** ([HN 46383675](https://news.ycombinator.com/item?id=46383675)). The thread had 148 distinct authors. 17 named a replacement, and at least 5 used "rug pull", "bait" or "ransomware" framing. One wrote: "Sounds like a ransomware with extra steps."
  - **Bitwarden's desktop client briefly could not be built as free software** ([HN 41893994](https://news.ycombinator.com/item?id=41893994); [#11611](https://github.com/bitwarden/clients/issues/11611)). Three paying users said they would leave.

**Security reviews ([L1-1.07 §3](L1-1.07-open-core-business-models.md)):**
- The E2EE comparables pair SOC 2 Type II with independent code audits:
  - Bitwarden: SOC 2 Type II, SOC 3 and ISO 27001 ([compliance](https://bitwarden.com/compliance/)).
  - Proton: first SOC 2 Type II in July 2025 (search excerpt; [Proton](https://proton.me/blog/soc-2)).
  - Tailscale: SOC 2 under NDA and "does not have a bounty program" ([security](https://tailscale.com/security)).
  - Ente: published its full Cure53 report ([Ente](https://ente.com/blog/cern-audit)).
- **Costs and timing:**
  - A SOC 2 audit fee runs about $10,000–50,000, with a 3–12 month observation window (vendor figures; [Vanta](https://www.vanta.com/blog/what-does-a-soc-2-audit-cost)).
  - One code audit was quoted at $143,000 and settled at $71,000 ([OSTIF](https://ostif.org/?p=3252)).
- **E2EE is not a purchase reason on this evidence.** Infisical users saw E2EE as "a nice-to-have rather than a must-have feature", and Infisical turned it off by default ([Infisical](https://infisical.com/blog/infisical-update-june-2023)).

**What users pay for ([L1-1.07 §4](L1-1.07-open-core-business-models.md)):**
- **One "would you pay" thread** ([HN 36170233](https://news.ycombinator.com/item?id=36170233)): 20 of 26 top-level respondents would pay. 11 said they did not want to run servers, 4 cited support or accountability, and 3 valued open source as an exit option.
- **A seller:** the ntfy maintainer says it is "super hard to get people to pay".
- **Self-hosted Sentry** ([HN 43725815](https://news.ycombinator.com/item?id=43725815)):
  - About 8 commenters were put off by the 16 GB footprint.
  - 4 suspected the complexity serves Sentry's cloud.
  - 6 self-host successfully; 2 of them cited the cost of hosted plans at volume.
- **The SSO-tax thread** ([HN 41303844](https://news.ycombinator.com/item?id=41303844)): 9 of 24 top-level authors criticized the tax and 6 defended price discrimination.

**New competitor.** Infisical Agent Vault (preview) brokers credentials for Claude Code, Codex and OpenCode. Per its page, the proxy encrypts its logs before they leave the customer's network and stores them in an S3 bucket the customer owns ([Infisical Agent Vault](https://infisical.com/platform/agent-vault)). Pitch4 does not name it.

**Level 1's key inference.** "Hosted blind" and Assured conflict unless search, SIEM export, retention enforcement and legal hold run in a component the customer holds.

### Level 2 (2.13): how E2EE products deliver compliance without reading plaintext
**Six patterns ([L2-2.13 §1](L2-2.13-how-do-end-to-end-encrypted-products-deliver-leg.md)):**

| Pattern | Examples | Plaintext at the vendor? |
|---|---|---|
| A. Metadata-only events streamed to a SIEM | Bitwarden ([event logs](https://bitwarden.com/help/event-logs/)), 1Password ([Events API](https://support.1password.com/events-reporting/)), Proton org monitor, Tresorit | No |
| B. Retention enforced on ciphertext | Synapse purge ([docs](https://element-hq.github.io/synapse/latest/message_retention_policies.html)); Proton retention, where private members' mail is retained but unreadable ([Proton](https://proton.me/support/retention-policies-organization)) | No |
| C. A visible reader run on the customer's infrastructure | Element AuditBot ([PDF](https://static.element.io/pdfs/auditbot.pdf)), Wire Legalhold Vault ([blog](https://wire.com/en/blog/balancing-privacy-and-compliance-with-legalhold)), AWS Wickr retention bot ([docs](https://docs.aws.amazon.com/wickr/latest/adminguide/data-retention.html)) | No; the customer holds plaintext |
| D. A key manager the customer holds, plus an export bridge | Symphony, Virtru, Google Vault with CSE | No |
| E. A vendor-run enclave under the customer's KMS key | Wickr serverless retention ([docs](https://docs.aws.amazon.com/wickr/latest/adminguide/serverless-method.html)); Symphony Confidential Cloud, Advanced tier ([Symphony](https://symphony.com/messaging/confidential-cloud/)) | Only in attested enclave memory |
| F. Features switched off in E2EE mode | Zoom drops recording, transcription and AI ([Zoom](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0065408)); Teams bars compliance-recorded users from E2EE ([Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/teams-end-to-end-encryption)); Google Vault cannot preview CSE mail bodies ([Google](https://workspaceupdates.googleblog.com/2023/01/vault-support-for-client-side-encrypted-emails.html)) | n/a |

**Inferences drawn from the patterns:**
- **Legal hold has two halves.** Preservation can be enforced blind on ciphertext. Production (handing readable copies to a reviewer) always needs a key holder.
- **SIEM export also splits.**
  - The server can send IDs, times, actors and actions. It cannot add names. A Vaultwarden maintainer: "the server doesn't know the names, and thus can not store that either" ([forum 3106](https://vaultwarden.discourse.group/t/replace-identifier-in-event-log-with-actual-name-of-the-item/3106)).
  - Four distinct people across four threads asked Bitwarden or Vaultwarden for richer event logs; three wanted item names instead of IDs. Bitwarden closed one request as "the intended behavior of the software" ([#3909](https://github.com/bitwarden/server/issues/3909)).
- **Readers are plaintext stores, and vendors say so.**
  - Element's sheet: AuditBot "potentially increases the risk of unauthorised access".
  - Wire's sample schema stores message text ([wireapp/legalhold](https://github.com/wireapp/legalhold)).
  - Wickr's bot "can store data unencrypted".
  - The safer design is Wickr serverless: re-encrypt to a customer key, decrypt on demand, and log every key use in the customer's account.
- **Vendors are moving to managed readers.** AWS calls its own bot "a complex setup with physical or virtual hardware and Docker expertise". Symphony's managed tier "eliminates the need for on-premise components". Buyers accept customer-run readers but would rather not operate them.

**Prices ([L2-2.13 §2](L2-2.13-how-do-end-to-end-encrypted-products-deliver-leg.md)):**
- **Metadata logs and SIEM streaming** sit in the first paid business tier at about $4–9 per user per month: Bitwarden Teams, 1Password Business at $8.99, Virtru Business and Tresorit Business Pro.
- **Readable content capture** is a top-tier entitlement or a small add-on:
  - Element AuditBot: "$1 per monthly active user" (2022 sheet).
  - AWS Wickr: retention in Premium only, at about $15 against about $5 for Standard (secondary).
  - Proton: retention in Workspace Premium only, at $19.99 against $12.99.
  - Virtru: Business at $219 a month for 5 users. A Compliance package costs $499 a month for 5 users, contents unknown ([Virtru](https://www.virtru.com/pricing)).
- **Inference:** Assured is roughly Team + $7–15 unless it contains things capture vendors do not bundle.

**Regulators ([L2-2.13 §3](L2-2.13-how-do-end-to-end-encrypted-products-deliver-leg.md)):**
- **SEC Rule 17a-4(i)(1)(ii)** offers an "alternative undertaking" for outside storage where the firm has "independent access … without the need of any intervention of the outside entity" ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/240.17a-4)).
  - Dechert reads the alternative as unavailable if the third party must take an intervening step, giving "decrypting" as an example ([Dechert](https://www.dechert.com/knowledge/onpoint/2022/11/-sec-adopts-amendments-to-rule-17a-4-electronic-recordkeeping-re.html)).
  - This fits a host that never decrypts.
  - Inference: URnetwork could sign that undertaking, but it cannot be the firm's "designated third party", because it lacks "the ability to provide records" in readable form.
- **FINRA's 2026 report** faults weak vendor due diligence. As an effective practice, it describes "simulating a regulator's examinations by requesting records" ([FINRA](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/books-and-records)).

**Where each feature can run ([L2-2.13 §4](L2-2.13-how-do-end-to-end-encrypted-products-deliver-leg.md), inference):**
- **Blind, on the host:** metadata event logs, deletion schedules, and freezing ciphertext.
- **In a component the customer holds:** enriched SIEM events, review, production, eDiscovery and key escrow.
- **Build-order consequence:** pitch4's Team layer already promises SIEM export and retention, so the reader has to ship with Team, not in the "Last" stage.

### Level 3 (3.02): legal hold over developer-keyed vaults, in the US and the EU
**US law ([L3-3.02 §1](L3-3.02-can-legal-hold-and-retention-reach-sessions-held.md)).** The vault does not take sessions outside the company's "possession, custody, or control".
- Sedona's legal-right test is met by an ordinary acknowledgment that the company "owns or controls the ESI". That acknowledgment also creates "the resulting obligation" ([Rodriguez, 30 J. Tech. L. & Pol'y](https://www.journaloftechlaw.org/_files/ugd/ad7a6d_4413fba236cd4a668eb372ef871c9534.pdf)).
- The real risk is failing to preserve:
  - **Google Play (2023).** Google was sanctioned for leaving chat preservation to each employee's "carte blanche". Its email hold, by contrast, ran "without requiring any individual action", and custodians "cannot override" it ([order](https://oag.ca.gov/system/files/attachments/press-docs/Google%20Chat%20preservation%20ruling%5B2%5D.pdf)).
  - **FTC v. Noland (2021).** Moving to Signal with auto-delete after a subpoena led to an adverse inference (secondary; [Sidley](https://www.sidley.com/-/media/uploads/ediscovery/2022/ftc-v-noland-2021-wl-3857413-d-ariz-aug-30-2021.pdf)).
  - **The DOJ's compliance guidance** asks what "preservation or deletion settings are available to each employee". It also asks "What are the consequences for employees who refuse the company access" ([ECCP, Sept 2024](https://www.justice.gov/criminal/criminal-fraud/page/file/937501/dl)).
- **Inferences for pitch4:**
  - The vault's "retention set by the owner" is exactly the "carte blanche" that was sanctioned. A hold must freeze deletion automatically, must not be overridable by the developer, and must be auditable.
  - Preservation needs no key escrow.
  - Production without escrow works only with the developer's cooperation. It fails when a developer leaves and wipes the device, loses keys, or refuses.
  - Capture that starts only when a hold is placed misses history: AuditBot exports nothing from the past.

**Vendor models ([L3-3.02 §2](L3-3.02-can-legal-hold-and-retention-reach-sessions-held.md)):**
- **Wire.** Every user starts in `UserLegalHoldNoConsent`, and the held user approves the hold device with their own password ([LegalHold.hs](https://github.com/wireapp/wire-server/blob/develop/libs/types-common/src/Data/LegalHold.hs); [tests](https://github.com/wireapp/wire-server/blob/develop/integration/test/Test/LegalHold.hs)).
- **Proton.** Private users stay unreadable, and reverting a user to non-private needs that user's acceptance ([Proton](https://proton.me/support/private-users)). For non-private users, though, notice of an admin sign-in is "at your admin's discretion" ([Proton Drive](https://proton.me/support/access-account-proton-drive)).

**EU practice ([L3-3.02 §3](L3-3.02-can-legal-hold-and-retention-reach-sessions-held.md)).** Published German texts converge on one design: sealed by default, opened by a defined procedure.
- **FernUniversität in Hagen's Microsoft 365 agreement** ([agreement](https://www.fernuni-hagen.de/pr/docs/dienstvereinbarung-m365_fertig.pdf); [annexes](https://www.fernuni-hagen.de/pr/docs/anlagen_dienstvereinbarung_m365.pdf)):
  - Personal stores, chat histories included, are "für niemanden einsehbar" (visible to no one) except through the user's own sharing.
  - Exceptions form a closed list, each needing the staff council's consent.
  - The council gets automatic alerts on admin access and on the start or export of an eDiscovery.
  - Those affected are told afterwards.
  - Data gathered in breach cannot be used as evidence.
- **The German DPAs' model agreement** ([DSK](https://www.lda.bayern.de/media/oh_email_internet.pdf)): four-eyes access, and the employee is informed "unverzüglich" (without delay).
- **A Hans-Böckler-Stiftung analysis of 192 agreements** ([HBS](https://www.boeckler.de/fpdf/HBS-005843/p_mbf_bvd_e_mail_nutzung_internet.pdf)): case-by-case review on well-founded suspicion appears in "beinahe jeder Vereinbarung" (almost every agreement).
- **Article 29 Working Party Opinion 2/2017** ([WP 249](https://ec.europa.eu/newsroom/article29/redirection/document/45631)):
  - Consent is "highly unlikely to be a legal basis for data processing at work".
  - Employers need a published policy on "when, and by whom" logs can be accessed.
- **France:**
  - The works council (CSE) must be informed and consulted before any means of controlling employees' activity is introduced ([L2312-38](https://code.travail.gouv.fr/code-du-travail/l2312-38)).
  - Employees must be told before any data about them is collected ([L1222-4](https://code.travail.gouv.fr/code-du-travail/l1222-4)).

**Model scorecard (inference; no source scores them).** None of the four models works alone:
- Proton's retained-but-unreadable member is the right default.
- Wire's visible hold is the right notice pattern, but as acknowledgment, not as consent.
- An org-wide AuditBot is wrong for personal vaults.
- A plain company recovery key breaks both the headline and German practice.

The design that best fits the US and EU evidence is a hybrid of three parts:
1. An automatic freeze recorded in the ledger.
2. The developer re-wraps held sessions to a case key.
3. A sealed fallback: a k-of-n recovery wrap held by, for example, legal or compliance, the works council or DPO, and a notary or HR.

The fallback opens only on a closed list of triggers, with four-eyes review and notice to the developer.

**What changes in pitch4:**
- "Sessions open only when the developer shares them" becomes false once any recovery path exists.
- The freeze moves into Team.

### Level 3 (3.09): what regulated finance must actually keep
**Sessions are not required records as a class ([L3-3.09 §1](L3-3.09-for-broker-dealers-investment-firms-and-other-re.md)).**
- Rule 17a-4(b)(4) reaches communications "relating to its business as such", and content decides whether a message is kept ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/240.17a-4)).
- Law firms disagree, and none addresses coding agents:
  - Skadden: AI output "that is not subsequently transmitted likely does not constitute a written communication" ([Skadden](https://www.skadden.com/insights/publications/2024/09/how-and-when-sec-recordkeeping-rules-may-apply)).
  - Duane Morris: "Neither the SEC nor FINRA has stated yet whether a prompt or its output qualifies" ([Duane Morris](https://blogs.duanemorris.com/artificialintelligence/2026/07/22/ai-and-broker-dealer-compliance-what-firms-need-to-know-now/)).
  - An ABA Business Law Today article: "The SEC and FINRA have not squarely resolved the issue" ([ABA](https://businesslawtoday.org/2026/06/ai-prompts-and-responses-records-or-not-here-we-come/)).
- What a broker-dealer clearly must keep is content an agent transmits about the business.

**The US is narrowing ([L3-3.09 §2](L3-3.09-for-broker-dealers-investment-firms-and-other-re.md)):**
- SIFMA asked the SEC to exclude "Any inputs into and outputs from any artificial intelligence platforms or tools". It also asked the SEC to remove the Rule 17a-4(i) third-party undertaking ([SIFMA](https://www.sifma.org/advocacy/letters/modernizing-communications-and-record-retention-rules-for-broker-dealersinvestment-advisers-and-security-based-swap-dealers-sifma-and-sifma-amg)).
- The SEC's Spring 2026 agenda lists deregulatory amendments to the books-and-records rules ([Sidley](https://www.sidley.com/en/insights/newsupdates/2026/07/what-to-expect-in-sec-rulemaking-takeaways-from-the-secs-spring-2026-regulatory-agenda)). As of 1 November 2026, no proposal had been found.
- The SEC's FY2026 examination priorities contain 0 hits for "off-channel" ([SEC](https://www.sec.gov/files/2026-exam-priorities.pdf)).
- Penalty totals from the earlier off-channel sweep conflict across sources: $1.1 billion, $2 billion, $2.2 billion and about $2.7 billion.

**EU and UK ([L3-3.09 §3](L3-3.09-for-broker-dealers-investment-firms-and-other-re.md)):**
- MiFID II Art. 16(7) and Delegated Regulation 2017/565 Art. 76 cover communications relating to, or intended to result in, transactions and client orders.
- Art. 76(3) makes recording technology-neutral, and a "new medium of communication" triggers a review of the firm's arrangements ([Art. 76](https://www.legislation.gov.uk/eur/2017/565/article/76/adopted)).
- Guidance reaches AI use, including staff use of third-party tools:
  - ESMA expects "comprehensive records on AI utilisation", including "algorithms implemented, and any modifications made over time" ([ESMA](https://www.esma.europa.eu/sites/default/files/2024-05/ESMA35-335435667-5924__Public_Statement_on_AI_and_investment_services.pdf)).
  - The FCA's 19 Oct 2026 page creates no new requirements. As good practice, it records firms that kept prompts, outputs and model versions, and that registered agents in a central inventory ([FCA](https://www.fca.org.uk/publications/good-poor-practice/ai-financial-services)).

**Binding change-record duties ([L3-3.09 §4](L3-3.09-for-broker-dealers-investment-firms-and-other-re.md)).** What these rules require is the change record, not the transcript:
- **RTS 6 Art. 5(7)** (algorithmic-trading firms): records of "any material change made to the software used for algorithmic trading". Each record shows when, "the person that has made the change", "the person that has approved the change", and its nature ([RTS 6](https://www.legislation.gov.uk/eur/2017/589/article/5/adopted)).
- **Reg SCI 1005(b)** (SCI entities): "records relating to any changes to its SCI systems and indirect SCI systems", kept five years ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/242.1005)).
- **Rule 17a-4(e)(8)** (broker-dealers): "a record explaining each system change" that affected surveillance reports.
- **DORA Art. 9(4)(e)** (EU financial entities): "all changes to ICT systems are recorded, tested, assessed, approved, implemented and verified" ([DORA](https://www.digital-operational-resilience-act.com/Article_9.html)).
- **FINRA Rule 1220** registers the person "primarily responsible for the design, development or significant modification of an algorithmic trading strategy" ([FINRA 1220](https://www.finra.org/rules-guidance/rulebooks/finra-rules/1220)).
- **Inference.** These fields map onto pitch4's ledger, with a sponsoring human named alongside the agent run. Features that transmit messages, such as agent email and approval by email reply, create communications-capture duties.

### Level 4 (4.05): how often holds reach AI transcripts, and what capture costs
**Orders ([L4-4.05 §1](L4-4.05-how-often-do-litigation-holds-discovery-requests.md)).** Courts are ordering preservation and production of AI chat logs, but in two settings only.

When the AI provider is the defendant:
- **OpenAI preservation order.** OpenAI was "NOW DIRECTED to preserve and segregate all output log data that would otherwise be deleted" on 13 May 2025 ([ECF 551](https://blogs.duanemorris.com/classactiondefense/wp-content/uploads/sites/56/2025/10/In-re-OpenAI-Inc.-Copyright-Infringement-Litig.-5.13.25-Order-ECF-No.-551.pdf)).
- **The order ended with a negotiated scope.** It was terminated as of 26 Sep 2025, with an EEA, Swiss and UK carve-out and continued preservation for 89 listed domains ([ECF 922](https://blogs.duanemorris.com/classactiondefense/wp-content/uploads/sites/56/2025/10/In-re-Open-AI-Inc.-Copyright-Infringement-Litig.-10.9.25-Order-ECF-No.-992.pdf)).
- **A 20-million-log sample was ordered produced** and affirmed on 5 Jan 2026 (secondary).
- **Anthropic** must preserve "more than 500 million individual Claude prompts and outputs" (reported 30 Jul 2026; [Mealey's](https://www.mealeys.com/mealeys/amp/articles/2507727)).

When a litigant used AI on the dispute itself: 8 decisions.

**The one ruling on a business's own internal AI logs** (the Times's ChatExplorer, 19 Sep 2025):
- The court refused to compel production.
- It held that "the inadvertent loss of these logs does not implicate Fed. R. Civ. P. 37(e)" ([Kilpatrick](https://ktslaw.com/insights/alert/2026/7/discoverability-of-generative-ai-prompts-and-outputs-best-practices-for-litigation-holds); [Arnold & Porter](https://www.arnoldporter.com/en/perspectives/blogs/edata-edge/2025/11/courts-are-starting-to-define-what-ai-discovery-means)).

**Orders involving a coding tool or agent transcript: none found.**

**Frequency is unmeasured ([L4-4.05 §2](L4-4.05-how-often-do-litigation-holds-discovery-requests.md)).**
- No survey found reports how often holds or collections include AI data.
- The only measured series is OpenAI's government content requests: 8, 13, 26, then 75 per half-year from H1 2024 to H2 2025 ([H2 2025 report](https://cdn.openai.com/trust-and-transparency/report-2025h2-government-requests-for-user-data.pdf)).
- OpenAI may object to a civil request when the requester has not tried party discovery first (search excerpt).

**Holdable AI is now parity ([L4-4.05 §3](L4-4.05-how-often-do-litigation-holds-discovery-requests.md)):**
- **Microsoft Purview** holds Microsoft 365 Copilot interactions with no pay-as-you-go charge (Purview per-user licences still apply). It brings in ChatGPT Enterprise and Claude Enterprise on pay-as-you-go billing; the Claude connector is "currently in preview" ([Purview](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview); [Claude connector](https://learn.microsoft.com/en-us/purview/ai-claude-enterprise)).
- **Google Vault** added retention rules and litigation holds for the Gemini app on 11 Jun 2026 ([Google](https://workspaceupdates.googleblog.com/2026/06/google-vault-now-supports-retention-rules-and-litigation-holds-for-Gemini-app.html)).
- **Archive vendors** list ChatGPT Enterprise, Copilot and Claude as capture channels, all vendor claims:
  - Global Relay ([connector](https://www.globalrelay.com/connector/global-relay-connector-for-chatgpt-enterprise/));
  - Smarsh, which includes "source code" ([Smarsh](https://www.smarsh.com/channel/chatgpt-enterprise));
  - Proofpoint ([data sheet](https://www.proofpoint.com/us/resources/data-sheets/capture)).
- **Slack is the counterexample.** Its AI summaries "produce ephemeral AI responses" ([Slack](https://slack.com/help/articles/28310650165907)).
- **Sedona's drafting team** puts "Agentic AI tools" and "Interactive desktop apps … (e.g., Claude Cowork, Codex, etc.)" in scope. Final publication is targeted for 29 Apr 2027 ([Sedona](https://www.thesedonaconference.org/node/11695)).
- **Every incumbent path needs a provider compliance feed.** Coding harnesses without one (Cursor's API lacks retention and export, per L3-3.03), open harnesses and local models leave only the session file on the developer's machine.

**Prices ([L4-4.05 §4](L4-4.05-how-often-do-litigation-holds-discovery-requests.md)):**
- **Purview**, for non-Microsoft AI:
  - retention: "$6 per one million text messages per month";
  - eDiscovery storage: "$20 per GB per month";
  - audit: "$15 per 1M records ingested" ([Azure](https://azure.microsoft.com/en-us/pricing/details/purview/); [billing](https://learn.microsoft.com/en-us/purview/purview-billing-models)).
- **Smarsh** Connected Capture: about $8–18 per user per month on top of archiving (secondary; [Vendr](https://www.vendr.com/marketplace/smarsh)).
- **Theta Lake** platform fees: $15,000 a year (SMB) and $50,000 a year (Enterprise), plus a per-user content SKU ([AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-plpulco2axoai)).
- **Inference, from hypothetical volumes:** Purview retention works out to about $1.51 a month for a developer at 1,000 messages a day after a year.

**Finance ([L4-4.05 §5](L4-4.05-how-often-do-litigation-holds-discovery-requests.md)).**
- No exam finding or enforcement action about records of AI-tool use was found.
- Global Relay, which sells capture, wrote on 19 Oct 2026: "Regulators have yet to impose new AI-specific recordkeeping requirements" ([Global Relay](https://www.globalrelay.com/resources/thought-leadership/when-are-ai-communications-a-business-record/)).
- The contract evidence points to deletion: AT&T's AI appendix requires suppliers to "permanently delete" its information after use (from L1-1.08).

**Level 4's conclusion:**
- Legal hold is a Team checkbox plus a small paid production path, not a reason to pay $39.
- Two things remain differentiated:
  - coverage where no compliance feed exists;
  - "hosted blind" as insulation from preservation orders served on a vendor (inference; needs counsel).

---

## 2. How the deeper levels changed or qualified level 1

Level 1 produced eight directions and six open questions. Only one question went deeper: how E2EE vendors deliver legal hold, eDiscovery, retention and SIEM export, how they price them, and whether buyers accept a reader that the customer runs. The other five were not pursued in this branch.

The SOC 2 and self-hosting-share question went to L2-2.05, which 1.7 opened jointly with 1.6 and 1.9. L2-2.05 is not among this branch's files, so its findings are outside this synthesis, except where L2-2.13 quotes it.

| Level-1 finding or direction | What the deeper levels found | Net status |
|---|---|---|
| **The Assured price.** About $39 has no comparable among network or E2EE tools. Re-anchor Assured at $20–30, and test $39 only if it includes legal hold and eDiscovery. | **L2:** capture costs +$1 per MAU (Element) to about +$10 per user (Wickr, secondary), so Assured is about Team + $7–15. **L4:** suites give AI holds away or meter them at cents per seat; finance archive channels cost about $8–18 per seat; legal hold "is not a reason to pay $39". **L3-3.09:** the binding finance hook is change records, not transcripts. | **Reversed on the condition.** Including legal hold does *not* justify $39. A higher Assured price must rest on regulated change records, self-hosted and air-gapped installs, SLAs and compliance mappings. |
| **"Hosted blind" and Assured conflict** unless readable features run in a customer-held component. | **L2:** confirmed across six vendor patterns and placed feature by feature. The reader is needed by Team's SIEM export and retention, so it moves to the Team stage. **L3-3.02:** a reader must also cover *past* sessions, which org-wide AuditBot does not. **L4:** holdable AI is parity, except for agents with no compliance feed. | **Confirmed and pulled forward** in the build order. The reader becomes a Team dependency, not a "Last" item. |
| **What enterprise tiers hold back:** retention, legal hold, eDiscovery, compliance export, SIEM streaming. | **L2:** metadata SIEM sits in the first paid tier everywhere (Bitwarden Teams, 1Password Business, Virtru Business, Tresorit Business Pro). **L3-3.02:** an automatic, non-overridable freeze is what courts expect (Google Play), so it belongs in Team. **L4:** Google and Microsoft give holds away. | **Qualified.** Preservation and metadata SIEM go to Team. Production, connectors and sealed recovery stay paid. |
| **SCIM belongs in Team**, not Assured, and Team should be self-serve (SSO-tax evidence). | Not tested deeper. | **Stands** at level-1 confidence. |
| **"E2EE is a trust property, not a purchase reason"** (Infisical). | **L2:** when compliance and E2EE collide, suites choose compliance (Teams, Zoom, Google). **L4:** a possible buyer-facing benefit: a host holding only ciphertext would preserve only unreadable data when a preservation order is served on it, as OpenAI's and Anthropic's were (inference; needs counsel). | **Mostly stands.** One untested purchase reason has appeared. |
| **No data hostage.** Plan limits never hide, delete or lock data. | **L4:** "Archived instead of deleted" maximizes discoverable data. ChatExplorer, Slack's ephemeral design and AT&T's deletion clause favor policy-driven retention with a hold override. **L3-3.02:** the vault's owner-set retention cannot stand under a hold. | **Stands, and is extended.** Plan limits never touch data, *and* retention follows the customer's policy and holds rather than forever-by-default. |
| **Give away the software; charge for the service.** Keep a paid self-hosted enterprise licence (GitLab). | **L2:** Wickr offers a customer-run bot for self-hosted Enterprise and an enclave reader for hosted Premium, so both placements coexist. Buyers accept readers but do not want to run them. Dechert's reading means a vendor-run reader would end the "cannot read" claim. | **Qualified.** Operating convenience is what sells. A managed reader is possible only as a separately labeled product. |
| **Licence split** (Apache-2.0 sidecar; AGPL-3.0 servers with a commercial exception; a pledge or DCO). | Not tested deeper. | **Stands** at level-1 confidence. |
| **Trust documents:** add SOC 2 Type II; publish audits and the metadata list. | Not pursued in this branch (taken up in L2-2.05). | **Stands here.** |
| **Name Infisical Agent Vault** in the competitor table. | Not tested deeper. | **Stands.** |
| **The beachhead's regulated teams.** Pitch4 names "Fintech, health, and other regulated teams". market2.md, the source of pitch4's tiers, says "FINRA-supervised firms, for example, keep prompt and output logs". | **L3-3.09:** no binding duty to keep coding-agent sessions; the US is moving to carve AI inputs and outputs out. **L4:** a capture vendor reads FINRA's line as governance advice, not a recordkeeping rule (search excerpt; vendor), and Global Relay admits no AI-specific rule exists. | **Corrected.** The regulated-finance case rests on binding change-record rules and on firms choosing to "keep everything", not on a session mandate. |
| **Bill per human; never per agent.** | **L2:** bill the reader per active human, on Element's MAU basis, and publish a self-run cost model in AWS's style. | **Consistent; extended to the reader.** |

**What the deeper levels added that level 1 did not have:**
- **US preservation case law** that applies directly to the vault's owner-controlled retention (Google Play, Noland, the DOJ ECCP).
- **EU co-determination texts** that already endorse "visible to no one except through the user's own sharing" (FernUni Annex 6), with closed exceptions. This makes pitch4's privacy headline defensible in Germany if the exceptions are explicit.
- **The binding finance change-record rules** (RTS 6, Reg SCI, 17a-4(e)(8), DORA), and the fact that transmitting features create capture duties.
- **The finding that the only non-parity hold** is for agents without a provider compliance feed.
- **Real price points for AI capture.** None supports a premium.

---

## 3. Directions for pitch4

The directions are ordered by how much they change the pitch. Each names the pitch4 page and section it would change.

### D1. Build one customer-held "reader" in the Team stage, and publish what the host cannot do blind
- **What to change.**
  - **Define a reader.** It is the sidecar in compliance mode: a visible ledger member with a compliance key, run by the customer as a container or inside the admin app.
  - **Split the jobs between host and reader.**
    - The hosted service does only what it can do blind: metadata events, deletion schedules, and freezing ciphertext.
    - The reader does everything that needs plaintext: enriched SIEM events (agent, harness, host or port reached, approver, change-set names), retention review, production and eDiscovery.
  - **Store sealed copies, not plaintext.** The reader re-encrypts to a customer key, decrypts only on demand, and writes every decrypt into the ledger. An optional two-person rule governs opening the archive.
  - **Make it easy to run:** one binary or container, monitored.
  - **Publish a "what we cannot do blind" list:** no server-side search, no hosted AI summaries of sessions, no vendor eDiscovery, no hosted enrichment. Next to each item, name the component that does it instead.
- **Pitch4 page and section.**
  - Page 3, "Why encryption makes it safe to adopt": add the list after "Where it ends".
  - Page 4, "Open core, hosted blind".
  - Page 5, the Team row ("exports").
  - Page 6, "What ships, in order": the reader moves from "Last" to "Next", where SIEM export and retention already sit.
- **Why it helps.** Team promises "SIEM export" and "retention". Without a reader, those either need the host to read, which breaks "hosted blind", or ship as IDs-only exports, which password-manager users already complain about. "Access to the record is itself recorded" answers the weakness Element admits in its own product.
- **Effect:** both. **Confidence:** high that the architecture is necessary; buyer acceptance of running it is medium.
- **Evidence.**
  - **Vendors that produce readable content all add a key holder the customer controls,** or a customer-keyed enclave: Element AuditBot ([PDF](https://static.element.io/pdfs/auditbot.pdf)), Wire ([blog](https://wire.com/en/blog/balancing-privacy-and-compliance-with-legalhold)), Wickr ([bot](https://docs.aws.amazon.com/wickr/latest/adminguide/data-retention.html); [serverless](https://docs.aws.amazon.com/wickr/latest/adminguide/serverless-method.html)), Symphony ([Confidential Cloud](https://symphony.com/messaging/confidential-cloud/)).
  - **Products without a reader switch features off:**
    - Teams: "If a user is subject to compliance recording, they can't use E2EE" ([Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/teams-end-to-end-encryption)).
    - Zoom disables cloud recording and AI ([Zoom](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0065408)).
    - Google Vault cannot preview CSE mail bodies ([Google](https://workspaceupdates.googleblog.com/2023/01/vault-support-for-client-side-encrypted-emails.html)).
  - **Hosts can export only IDs.** Bitwarden and 1Password send IDs, never names ([Bitwarden](https://bitwarden.com/help/event-logs/); [1Password](https://support.1password.com/events-reporting/)). A maintainer: "the server doesn't know the names" ([Vaultwarden 3106](https://vaultwarden.discourse.group/t/replace-identifier-in-event-log-with-actual-name-of-the-item/3106)). Four distinct people asked for richer logs, three of them for names, one adding that names "would be great for exported logs to SIEM as well" ([Bitwarden 81164](https://community.bitwarden.com/t/enterprise-reporting-enhancements/81164)).
  - **Naive readers are plaintext stores.** Element: AuditBot "potentially increases the risk of unauthorised access". Wickr's bot "can store data unencrypted". Wire's sample schema holds message text ([wireapp/legalhold](https://github.com/wireapp/legalhold)).
  - **The safer pattern exists.** In Wickr serverless, "Plaintext exists only in the memory of the Nitro Enclave", each key use is logged in CloudTrail, and "You can disable your key at any time".
  - **A two-person rule has a precedent.** An Element team member proposed that audit-bot logs unlock only "if the 2 halves of a key … are put together" ([HN 23847663](https://news.ycombinator.com/item?id=23847663)).
- **Counter-evidence.**
  - Buyers do not want to operate readers. AWS calls its bot "a complex setup with physical or virtual hardware and Docker expertise". Symphony's managed tier "eliminates the need for on-premise components".
  - There is no buyer evidence on whether design partners would run a reader container themselves (L2-2.13 gap).
  - User complaints about IDs-only logs are thin: four people.
  - Infisical's users did not value E2EE, and it blocked integrations they wanted ([Infisical](https://infisical.com/blog/infisical-update-june-2023)).
  - Which features can run blind depends on the entry format, which is not yet specified (for example, whether the relay sees an entry's scope or signer key).
- **Cost and risk.**
  - It adds a second deployable component to build, document and support.
  - If the reader is hard to run, buyers will ask for a managed one. Running it in URnetwork's account would be an "intervening step" in Dechert's reading of Rule 17a-4 ([Dechert](https://www.dechert.com/knowledge/onpoint/2022/11/-sec-adopts-amendments-to-rule-17a-4-electronic-recordkeeping-re.html)), and would end the "cannot read" claim for that product. Offer it only as a separate, labeled product, using wording like AWS's "reasonable tradeoffs related to Wickr's end-to-end encryption (E2EE) model".
- **Test.**
  - Ask each design partner whether it would run the reader itself or wants it managed.
  - Measure time from install to the first enriched SIEM event.
  - Check whether partners' admins accept metadata-only events for Team.

### D2. Re-tier and re-price: legal hold is a Team checkbox plus a small paid production path, and Assured must rest on something else
- **What to change.**
  - **Team.** Put SSO and SCIM, metadata SIEM export, the automatic hold freeze (D3) with a hold badge and scoping, and a basic export in Team. Sell it self-serve by card, without a sales call, and bill only active users (NetBird's rule).
  - **A paid production path,** priced at about +$5–15 per seat or included in Assured:
    - export in formats eDiscovery tools ingest;
    - connectors into Purview, Global Relay, Smarsh, Proofpoint and Theta Lake (D5);
    - the developer re-wrap and sealed-recovery flow (D3);
    - a hold report that answers the DOJ ECCP's questions.
  - **Assured.** Default to about $20–30. Test $39 only with contents the capture vendors do not bundle: the regulated change-records pack (D4), a supported self-hosted and air-gapped enterprise licence, SLAs, compliance mappings and the kill switch.
  - **Billing basis.** Bill the reader per active human, never per agent, and publish a cost model for customers who run it themselves.
  - **Footnote.** Re-anchor page 5's price footnote on the comparables below.
- **Pitch4 page and section.**
  - Page 5, "Who pays": the Team and Assured rows and the footnote. The Assured row today reads "SCIM, one kill switch, a visible audit member, legal hold, compliance mappings".
  - Page 6, the "Will teams pay?" pilot row.
- **Why it helps.** A buyer who compares Assured with the incumbents finds both its headline items cheaper elsewhere. SCIM sits in $4–8 tiers, which makes Assured look like an SSO tax. AI holds are free or cost cents per seat, which makes the hold look overpriced.
- **Effect:** offering. **Confidence:** medium. Confidence is high that legal hold cannot carry $39; the price numbers are list-price inferences.
- **Evidence.**
  - **SCIM is in the first paid tier elsewhere:** Bitwarden Teams $4 ([pricing](https://bitwarden.com/pricing/business/)), NetBird Team €6 ([pricing](https://netbird.io/pricing)), Tailscale Standard $8 ([pricing](https://tailscale.com/pricing)).
  - **The SSO tax angers buyers.** In the SSO-tax thread, 9 of 24 top-level authors criticized it. icambron: "I hate that it's the one feature in the 'enterprise' tier that I need, and now I have to talk to a sales rep" ([HN 41303844](https://news.ycombinator.com/item?id=41303844)).
  - **The capture gaps are small:** Element +$1 per MAU, Proton +$7 (Standard $12.99 to Premium $19.99), and Wickr about +$10 (secondary) ([L2-2.13 §2](L2-2.13-how-do-end-to-end-encrypted-products-deliver-leg.md)).
  - **Microsoft adds no pay-as-you-go charge for Copilot holds** (Purview per-user licences still apply): "Microsoft 365 Copilot experiences aren't charged" ([Purview billing](https://learn.microsoft.com/en-us/purview/purview-billing-models)). Other AI apps cost "$6 per one million text messages per month" ([Azure](https://azure.microsoft.com/en-us/pricing/details/purview/)).
  - **Google includes holds** for the Gemini app in Vault editions ([Google](https://workspaceupdates.googleblog.com/2026/06/google-vault-now-supports-retention-rules-and-litigation-holds-for-Gemini-app.html)).
  - **Finance pays per channel.** Smarsh Connected Capture is about $8–18 per user per month (secondary; [Vendr](https://www.vendr.com/marketplace/smarsh)).
  - **Enterprise tiers hold back** compliance export, legal hold, SIEM streaming, FIPS and air-gapped builds, and SLAs ([Mattermost](https://mattermost.com/pricing/); [Langfuse self-host](https://langfuse.com/pricing-self-host); [Infisical](https://infisical.com/pricing)).
- **Counter-evidence.**
  - Some defend the SSO tax. SOLAR_FIELDS: "SSO is the one differentiator that businesses will guarantee pay for." 6 of 24 top-level authors defended price discrimination, and stackskipton called SSO "such a support nightmare".
  - Higher anchors exist: Infisical Advanced at $40 per identity, Zed Business at $30, and Virtru's $499 a month for 5 users, whose contents are unknown.
  - Every figure is a list price, and willingness to pay is untested. Tier gaps also bundle other features.
- **Cost and risk.**
  - Revenue per seat falls.
  - Moving SCIM down removes one reason to upgrade.
  - A $20–30 Assured may under-price regulated buyers who would pay more for the change-records pack.
- **Test.**
  - Offer design partners Team with SCIM at two price points.
  - Offer Assured at about $25 and at $39, with and without the change-records pack.
  - Measure conversions in pitch4's existing pilot row, and ask which Assured item each partner would buy first.

### D3. Holds that freeze automatically without escrow: developer re-wrap first, a sealed k-of-n fallback, and an honest privacy headline
- **What to change.**
  - **The hold.** A hold is a signed ledger entry naming a custodian, a time range and a project, with optional region and account scope.
    - Every sidecar refuses owner purges for that scope, and the hosted store refuses deletes.
    - The developer sees a hold badge, and a hold dashboard shows compliance.
    - The freeze ships in Team.
  - **Production, in order:**
    - (a) The developer re-wraps the held sessions to a case key, with no escrow.
    - (b) If the developer cannot or will not, there is an optional sealed fallback. At write time the content key is also wrapped to an organization recovery key split k-of-n, held by, for example, legal or compliance, the works council or DPO, and a notary or HR, never URnetwork. It opens only on a closed list of triggers, with four-eyes review. Each opening is recorded in the ledger and the developer is notified, with a time-limited, logged deferral when counsel requires it.
  - **"No recovery" stays an option.** The admin console records the decision and its rationale, because the ECCP asks for the "rationale".
  - **Reword pages 1 and 2.** Drop "Sessions open only when the developer shares them", which becomes false with any recovery path. L3-3.02 suggests: "Sessions stay with their author unless shared, or held under a hold the author is told about. Opening one needs two keys, and the developer sees every opening."
  - **Keep the claim quiet.** Claim holds in one plain line, not as a headline, and do not build fear marketing on the New York Times order.
- **Pitch4 page and section.**
  - Page 2, the "Yours unless you share" box and the "Session vault" card.
  - Page 1, "Private from us… Sessions stay with their author unless shared."
  - Page 5, the Team and Assured rows.
  - Page 6, build order: the freeze moves to "Next"; sealed recovery replaces "key-escrow options" in "Last".
- **Why it helps.**
  - The vault's owner-set retention, left in place under a hold, is the "carte blanche" a court sanctioned. A buyer's counsel will ask about it before adoption.
  - The hybrid keeps the privacy headline true while giving counsel a production path.
  - As far as this series found, no coding-agent tool offers a hold that developers can see. The tools give employers everything (Anthropic's compliance reviewers, GitHub's streaming of sessions to a SIEM) or nothing (L3-3.02 inference from earlier rounds).
- **Effect:** both. **Confidence:** medium.
- **Evidence.**
  - **An automatic, non-overridable hold is the standard.** In Google Play, Google "left it up to each individual hold recipient to decide"; by contrast, "Custodians cannot override the automated preservation of their emails" ([order](https://oag.ca.gov/system/files/attachments/press-docs/Google%20Chat%20preservation%20ruling%5B2%5D.pdf)).
  - **Auto-delete after the duty attaches draws an adverse inference** (secondary; [Noland, Sidley](https://www.sidley.com/-/media/uploads/ediscovery/2022/ftc-v-noland-2021-wl-3857413-d-ariz-aug-30-2021.pdf)).
  - **Prosecutors want company access.** The ECCP asks that business communications be "accessible and amenable to preservation by the company" ([DOJ](https://www.justice.gov/criminal/criminal-fraud/page/file/937501/dl)).
  - **An acknowledgment creates control and the obligation that comes with it** ([Rodriguez](https://www.journaloftechlaw.org/_files/ugd/ad7a6d_4413fba236cd4a668eb372ef871c9534.pdf)).
  - **Retention can be separated from readability.** Proton's private users stay retained but unreadable ([Proton](https://proton.me/support/private-users)).
  - **A hold need not start silently.** Wire's two-step approval and visible states show how ([LegalHold.hs](https://github.com/wireapp/wire-server/blob/develop/libs/types-common/src/Data/LegalHold.hs)).
  - **Broad holds get scoped down.** OpenAI's broad order ended with a sunset, an EEA, Swiss and UK carve-out, and 89 targeted domains, which is a template for scoping holds by time, region and account ([ECF 922](https://blogs.duanemorris.com/classactiondefense/wp-content/uploads/sites/56/2025/10/In-re-Open-AI-Inc.-Copyright-Infringement-Litig.-10.9.25-Order-ECF-No.-992.pdf)).
  - **Holds overriding user deletion are now standard elsewhere.** Google Vault's Gemini holds override user deletion ([Google](https://workspaceupdates.googleblog.com/2026/06/google-vault-now-supports-retention-rules-and-litigation-holds-for-Gemini-app.html)), and Kilpatrick advises suspending "any automatic deletion, purging, or overwriting of gen AI interaction logs" ([Kilpatrick](https://ktslaw.com/insights/alert/2026/7/discoverability-of-generative-ai-prompts-and-outputs-best-practices-for-litigation-holds)).
- **Counter-evidence.**
  - No US decision covers an employer-adopted E2EE tool whose keys employees hold, and no counsel has reviewed the hybrid.
  - How a works council's key share fares in US discovery is untested, for example if the council refuses to release it.
  - No reported order reaches coding-agent transcripts. The one ruling on a business's internal AI logs refused production and found no Rule 37(e) issue in their loss ([Arnold & Porter](https://www.arnoldporter.com/en/perspectives/blogs/edata-edge/2025/11/courts-are-starting-to-define-what-ai-discovery-means)).
  - In the EU, a developer's "consent" is not a valid legal basis ([WP 249](https://ec.europa.eu/newsroom/article29/redirection/document/45631)).
- **Cost and risk.**
  - Threshold key ceremonies are complex to build and to explain.
  - Developers may read "two keys" as a backdoor.
  - Customers who choose "no recovery" keep a Rule 37(e) risk, and should be told so in writing.
- **Test.**
  - Have US litigation counsel and one German works council or DPO review the design and the reworded line.
  - Run a mock hold in a pilot: time from hold to frozen scope across harnesses, then a developer re-wrap and an unseal ceremony.
  - Measure developers' reaction to the new page 2 wording.

### D4. Lead the regulated-finance pitch with "the change record your regulator already requires, now naming the agent and its sponsor", and stop implying sessions are required records
- **What to change.**
  - **Name the segments that face binding change-record rules,** in place of the generic regulated bullet:
    - EU and UK algorithmic-trading firms (RTS 6 Art. 5(7));
    - US SCI entities (Reg SCI 1005(b));
    - broker-dealers' surveillance-report systems (Rule 17a-4(e)(8));
    - EU financial entities (DORA Art. 9(4)(e)).
  - **Ship a "regulated change record" export** that maps the ledger one-to-one:
    - when;
    - maker: the agent run (harness, model, session link) plus the sponsoring human, who may need to be the FINRA-registered person under Rule 1220;
    - approver: the designated person;
    - nature: the change set, linked to the session.
  - **Word every mapping carefully.** Say "evidence for", never "complies with".
  - **Make the ledger "records-grade" by design:** signed, append-only, with actor identity and timestamps, and earlier contents always recoverable. Publish the mapping and invite firms' own compliance review; claim no certification.
  - **Add a "records drill".** It exports a chosen period of ledger entries and held sessions from the customer's side, human-readable and machine-usable, with the audit trail, and without URnetwork's help.
  - **Serve EU and UK firms from the inventory.** The cross-harness inventory plus modification log is evidence of AI use without keeping transcripts.
  - **Recast the vault for these buyers as "capture-ready"** for firms that choose to keep everything. Do not headline the Rule 17a-4(i) undertaking.
- **Pitch4 page and section.**
  - Page 5, "Where we start": the bullet "Fintech, health, and other regulated teams", and the Assured row ("compliance mappings").
  - Page 3, "What admins can answer", which already lists "for which sponsor" and "Who approved each action".
  - Page 6, design partners: include one or two algorithmic-trading or DORA entities.
- **Why it helps.**
  - These rules list the record's fields, so the claim is concrete. L3-3.09 found that none of the coding-agent tools reviewed in this series claims it, based on earlier rounds' tool surveys.
  - The buyers are defined: heads of electronic trading, technology risk at SCI entities, and ICT risk at DORA entities.
  - It avoids the claim that agent sessions are SEC-required, which lacks a basis and "could be explicitly contradicted within a year".
- **Effect:** both. **Confidence:** medium. The binding texts are solid; demand is untested.
- **Evidence.**
  - **RTS 6 Art. 5(7)** requires records showing "(a) when a change was made; (b) the person that has made the change; (c) the person that has approved the change; (d) the nature of the change" ([RTS 6](https://www.legislation.gov.uk/eur/2017/589/article/5/adopted)).
  - **Reg SCI:**
    - Rule 1001(b)(2)(ii) requires "A system of internal controls over changes to SCI systems" ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/242.1001)).
    - Rule 1005(b) requires keeping "records relating to any changes to its SCI systems and indirect SCI systems" for five years ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/242.1005)).
  - **DORA Art. 9(4)(e):** "all changes to ICT systems are recorded, tested, assessed, approved, implemented and verified" ([DORA](https://www.digital-operational-resilience-act.com/Article_9.html)).
  - **FINRA RN 15-09:** "a set of approval protocols" and "archiving code versions in a retrievable manner" ([FINRA](https://www.finra.org/rules-guidance/notices/15-09)).
  - **FINRA Rule 1220** registration ([FINRA](https://www.finra.org/rules-guidance/rulebooks/finra-rules/1220)).
  - **Format fit.** Rule 17a-4(f)(2)(i)(A) asks for "a complete time-stamped audit trail" ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/240.17a-4)). Art. 72(1)(b)–(c) asks that earlier contents be "easily ascertained" and that records not be "manipulated or altered".
  - **Supervisors are scrutinizing these controls.** The FCA's review of 10 principal trading firms found that some required every algorithm change to be approved by a Senior Management Function holder, and that weak testing procedures sometimes led to weak record-keeping ([FCA](https://www.fca.org.uk/publications/multi-firm-reviews/algorithmic-trading-controls-high-level-observations)).
  - **EU and UK guidance on AI records:**
    - ESMA expects records of "algorithms implemented, and any modifications made over time" ([ESMA](https://www.esma.europa.eu/sites/default/files/2024-05/ESMA35-335435667-5924__Public_Statement_on_AI_and_investment_services.pdf)).
    - The FCA cites as good practice: "Firms developing agentic use cases registered their agents in a central inventory" ([FCA](https://www.fca.org.uk/publications/good-poor-practice/ai-financial-services)).
  - **Sessions are not settled records:**
    - Skadden: untransmitted output "likely does not constitute a written communication" ([Skadden](https://www.skadden.com/insights/publications/2024/09/how-and-when-sec-recordkeeping-rules-may-apply)).
    - SIFMA asks the SEC to exclude AI inputs and outputs entirely ([SIFMA](https://www.sifma.org/advocacy/letters/modernizing-communications-and-record-retention-rules-for-broker-dealersinvestment-advisers-and-security-based-swap-dealers-sifma-and-sifma-amg)).
    - Global Relay: "Regulators have yet to impose new AI-specific recordkeeping requirements" ([Global Relay](https://www.globalrelay.com/resources/thought-leadership/when-are-ai-communications-a-business-record/)).
  - **The records drill has a source.** FINRA's effective practice is "simulating a regulator's examinations by requesting records" ([FINRA 2026](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/books-and-records)).
- **Counter-evidence.**
  - The segments are narrow, and the numbers of SCI entities and algorithmic-trading firms were not checked.
  - Firms may already meet Art. 5(7) and 1005(b) with Git, CI and ticketing logs. This was not checked.
  - No regulator text covers AI-authored changes or who counts as "the person that has made the change".
  - The UK's revocation of RTS 6, and any FCA restatement, is unverified.
  - Art. 5(7) states no retention period.
  - That developer tooling can be an "indirect SCI system" is the researcher's reading, not SEC text.
- **Cost and risk.**
  - Mapping and maintaining several regimes needs specialist review.
  - Wording that slides from "evidence for" to "complies with" would be an over-claim.
- **Test.**
  - Show a sample RTS 6 Art. 5(7) or Reg SCI export to heads of electronic trading or technology risk at three to five firms. Ask what Git, CI and ticketing logs already cover and what the agent-and-sponsor fields add.
  - Run one records drill with a finance design partner.

### D5. Be "the compliance feed for agents that have none"
- **What to change.**
  - **Position the hold and export path** as covering agent sessions that no provider compliance API reaches:
    - Cursor, OpenCode and Goose;
    - Copilot CLI sessions outside EMU;
    - local and open-weight models.
  - **Build exports** that make pitch4 a source for Purview and the archive vendors. Present this as a complement to Anthropic's and OpenAI's feeds, not a rival.
  - **Add a row to page 5's table:**
    - Piece: holds and archive capture of agent sessions.
    - Who already sells it: Purview, Google Vault, Global Relay, Smarsh and Proofpoint, for providers with feeds.
    - Where we stand: ours, for harnesses and models with none.
- **Pitch4 page and section.**
  - Page 5, "Where we stand, piece by piece".
  - Page 4, the line "Anthropic's Compliance API and OpenAI's compliance logs cover their own products".
  - Page 1, the problem bullet "Local models leave no log. No vendor keeps one."
- **Why it helps.** For chat AI, holdable records are now parity. The one place pitch4's hold is not parity is where no compliance feed exists. This turns a checkbox into reach that the suites cannot offer.
- **Effect:** differentiation. **Confidence:** medium.
- **Evidence.**
  - **Microsoft Purview's third-party connectors are for Enterprise AI products.** Its Claude connector "connects by using the Anthropic Compliance API" and needs an Enterprise plan; the page does not mention Claude Code ([Microsoft Learn](https://learn.microsoft.com/en-us/purview/manage-anthropic-data)). Copilot interactions are in the user's mailbox for holds ([Microsoft Learn](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview)).
  - **Google Vault holds cover "only … the Gemini app"** ([Google](https://workspaceupdates.googleblog.com/2026/06/google-vault-now-supports-retention-rules-and-litigation-holds-for-Gemini-app.html)).
  - **The archive connectors found are for enterprise AI products** (ChatGPT Enterprise, Microsoft Copilot, Claude): Global Relay ([connector](https://www.globalrelay.com/connector/global-relay-connector-for-chatgpt-enterprise/)), Smarsh ([channel](https://www.smarsh.com/channel/chatgpt-enterprise)), Proofpoint ([data sheet](https://www.proofpoint.com/us/resources/data-sheets/capture)), all vendor claims.
  - **Retention at the providers diverges.** OpenAI's Compliance Logs Platform "retains data for 30 days" (search excerpt; [OpenAI](https://help.openai.com/en/articles/9261474-openai-compliance-platform-for-enterprise-customers)). Anthropic keeps 6 years by default (per L3-3.03).
  - **Some harnesses have no usable feed.** Cursor's API lacks retention and export (per L3-3.03).
  - **Coding agents are coming into scope.** Sedona's drafting team includes "Interactive desktop apps for task management (e.g., Claude Cowork, Codex, etc.)" ([Sedona](https://www.thesedonaconference.org/node/11695)).
- **Counter-evidence.**
  - Anthropic's Compliance API already carries Claude Code local-session transcripts (per L3-3.03), so the largest harness has a feed for Enterprise customers.
  - If Purview's Anthropic connector or OpenAI's platform starts carrying Claude Code or Codex transcripts, the edge narrows to other harnesses and local models. This is on L4-4.05's watch list.
  - No order has reached coding-agent transcripts, and frequency is unmeasured.
  - Pitch4's own page 4 notes that open-weight models are a minority: 11% of enterprise LLM spend, in Menlo Ventures' estimate.
- **Cost and risk.**
  - Connectors to several archive and eDiscovery platforms must be built and maintained.
  - Customers who feed Purview pay its per-message and per-GB meters.
  - Transcript sizes, which drive the $20 per GB-month storage meter, are unmeasured.
- **Test.**
  - Check whether Purview's Anthropic connector and OpenAI's platform carry Claude Code or Codex transcripts.
  - Prototype exporting an OpenCode or Cursor session into Purview or one archive vendor.
  - Ask two design partners' legal teams whether they would use it.

### D6. Ship a co-determination kit that the product enforces
- **What to change.** Ship with Team a kit for EU works councils:
  - **A model Betriebsvereinbarung annex** (works agreement annex), containing:
    - a closed list of triggers: litigation or official hold, departure handover, documented suspicion of a crime, and security incident;
    - per-case council consent, or a joint committee;
    - four-eyes unsealing with the employee or a council member present;
    - prompt notice and a right to respond;
    - deletion after the case, with written confirmation;
    - an evidence-use ban;
    - a ban on performance monitoring;
    - an annual policy review.
  - **A French CSE consultation note** covering L2312-38 and L1222-4.
  - **A DPIA template.**
  - **Product enforcement.** The product enforces what the agreement says: automatic council alerts on every unseal or export, and the council's key share required for D3's sealed fallback.
  - **Precedent in the project.** market2.md already planned a "works-council packet" in Team; pitch4 does not mention one.
- **Pitch4 page and section.**
  - Page 2, "Yours unless you share".
  - Page 5, the Team row.
  - Page 6, "Trust documents first" and the design-partner list (include a German or French team).
- **Why it helps.**
  - FernUni's Microsoft 365 agreement already says personal stores are "für niemanden einsehbar" except through the user's own sharing. That is pitch4's headline, so the headline is acceptable in Germany if the exceptions are closed, per case and supervised.
  - FernUni could only ask Microsoft 365 for alerts "sofern jeweils technisch möglich" (where technically possible). Pitch4 can make the alerts built in.
  - A hold that the developer sees and a works council co-signs is offered by no tool this series found.
- **Effect:** differentiation. **Confidence:** medium. The fit with published agreements is solid; no counsel or council has reviewed it.
- **Evidence.**
  - **FernUni:** closed exceptions, per-case consent, eDiscovery alerts, notice afterwards, an evidence ban, and deletion 30 days after departure ([agreement](https://www.fernuni-hagen.de/pr/docs/dienstvereinbarung-m365_fertig.pdf); [annexes](https://www.fernuni-hagen.de/pr/docs/anlagen_dienstvereinbarung_m365.pdf)).
  - **DSK:** four-eyes access and prompt notice ([DSK](https://www.lda.bayern.de/media/oh_email_internet.pdf)).
  - **HBS:** suspicion-triggered review in "beinahe jeder Vereinbarung" ([HBS](https://www.boeckler.de/fpdf/HBS-005843/p_mbf_bvd_e_mail_nutzung_internet.pdf)).
  - **Ruhr-Universität Bochum's model AI agreement:** every access "muss schriftlich dokumentiert und nachweisbar gemacht werden" (must be documented in writing and provable) ([RUB](https://www.rubigm.ruhr-uni-bochum.de/rubigm/mam/images/cooperation/kommentierte-musterbv-ki.pdf)).
  - **IG Metall NRW:** "Der Betriebsrat ist grundsätzlich über jedes KI-Projekt zu informieren" (the council is to be informed of every AI project) ([IG Metall](https://nordrhein-westfalen.igmetall.de/en/dam/jcr:da9e380d-2c31-44e4-bdf1-71f1ae84b665/Working%20Paper%20Mustertexte%20BV%20neu.6c8d30f9b0a56e3d060e7181d3d7d2c6.pdf)).
  - **WP 249:** a published policy on "when, and by whom" logs can be accessed, reviewed "at least annually" ([WP 249](https://ec.europa.eu/newsroom/article29/redirection/document/45631)).
  - **France:** [L2312-38](https://code.travail.gouv.fr/code-du-travail/l2312-38) and [L1222-4](https://code.travail.gouv.fr/code-du-travail/l1222-4). Cass. soc. 11 Dec 2019 exposes an employer that skips consultation to the offence of obstruction (secondary; [Legisocial](https://www.legisocial.fr/actualites-sociales/3605-consultation-cse-obligatoire-mise-place-dispositif-controle-salaries.html)).
- **Counter-evidence.**
  - No published agreement covers coding-agent sessions or addresses E2EE or key escrow.
  - No published Betriebsvereinbarung with a US litigation-hold clause was found. L3-3.02 calls this the most important missing text.
  - The DSK guidance (2016) and the HBS analysis (2014) predate the GDPR.
  - A practitioner guide says co-determination can lapse if the employer has no access to the data (search excerpt; [KI-Syndikat](https://www.ki-syndikat.de/fuer-unternehmen/betriebsvereinbarung-ki/)). A fully sealed design might therefore avoid co-determination altogether, while any recovery path brings it back.
- **Cost and risk.**
  - Drafting in German and French needs employment-law review.
  - The kit must not read as legal advice.
  - The kit needs updating as case law moves. The CJEU's 2023 ruling C-34/21 was not reviewed.
- **Test.**
  - Give the kit to two or three German or French design partners.
  - Measure the time to a signed agreement against their Microsoft 365 or Copilot agreements.
  - Record which clauses councils change.

### D7. Retention bounded by the customer's policy and holds, never by plan limits
- **What to change.**
  - **Publish a "no data hostage" rule:**
    - No plan, cap, downgrade or lapsed licence ever hides, deletes or locks a session, change set or ledger entry already written.
    - A lapsed licence falls back to read-only access plus export.
    - Self-hosted installs never get artificial caps.
  - **Make retention follow the organization's policy**, in place of "Archived instead of deleted" as an organization-wide default:
    - short defaults for exploratory sessions;
    - long defaults for change records;
    - deletion that follows each client's terms;
    - a hold that overrides deletion only while a hold exists.
  - **Keep "never lose a session"** as the developer's default, within the organization's policy.
- **Pitch4 page and section.**
  - Page 2, the "Session vault" card ("Archived instead of deleted") and the headline promise.
  - Page 4, "Open core, hosted blind".
  - Page 5, the footnote under "Who pays".
- **Why it helps.**
  - The hostage rule turns "never lose a session" into a stated rule about the business model, which no comparable states (L1-1.07).
  - Policy-driven retention reduces the discoverable data a customer carries, meets clients' deletion terms, and removes the owner-controlled setting that a hold cannot tolerate (D3).
- **Effect:** both. **Confidence:** medium. The hostage rule alone is high.
- **Evidence.**
  - **Capping stored data drew the strongest backlash.** In the Mattermost thread, 148 distinct authors took part, 17 named a replacement, and one wrote "Sounds like a ransomware with extra steps" ([HN 46383675](https://news.ycombinator.com/item?id=46383675)). Mattermost Entry's planned limits include a 10,000-message history cap ([Mattermost](https://mattermost.com/blog/introducing-mattermost-entry/)).
  - **Bitwarden's terms disable lapsed self-hosted organizations.** If a licence is not updated within 60 days of renewal, "the organization will be disabled" ([Bitwarden](https://bitwarden.com/help/licensing-on-premise/)).
  - **Lost AI logs need not be a sanctions issue.** In ChatExplorer, "the inadvertent loss of these logs does not implicate Fed. R. Civ. P. 37(e)" ([Kilpatrick](https://ktslaw.com/insights/alert/2026/7/discoverability-of-generative-ai-prompts-and-outputs-best-practices-for-litigation-holds)).
  - **A major vendor chose ephemeral AI output.** Slack's AI summaries are ephemeral, and recaps are stored for 90 days ([Slack](https://slack.com/help/articles/28310650165907)).
  - **Client contracts can require deletion.** AT&T's AI appendix requires suppliers to "permanently delete the AT&T Information following its intended use" (from L1-1.08, via L4-4.05).
  - **Owner-controlled retention fails under a hold.** Google Play sanctioned leaving preservation to employees ([order](https://oag.ca.gov/system/files/attachments/press-docs/Google%20Chat%20preservation%20ruling%5B2%5D.pdf)).
- **Counter-evidence.**
  - Pitch4's own page 2 makes lost sessions an install reason: about 200 people report lost or hidden sessions, and Claude Code deletes local transcripts after 30 days.
  - Risk-averse broker-dealers are advised to use platforms "that preserve prompts and outputs" ([ABA](https://businesslawtoday.org/2026/06/ai-prompts-and-responses-records-or-not-here-we-come/)).
  - Under Vault retention rules and holds, data users delete stays "fully retained and visible to Vault administrators".
- **Cost and risk.**
  - A read-only fallback removes some pressure to renew.
  - How a lapse should work was a level-1 open question that this branch did not pursue.
  - Policy retention adds configuration, and developers may read organization retention as a loss of control.
- **Test.**
  - Collect design partners' client deletion terms and their counsel's retention preferences.
  - Test the page 2 wording with developers, for example "kept under your team's retention policy", and measure install intent.

### D8. Journal every message an agent sends to people into the firm's archive, from the day mail ships
- **What to change.**
  - For regulated tenants, journal every message an agent transmits to people: agent email, "approval by email reply", and agent posts.
  - Send it to the firm's existing archive by SMTP journaling or EML/JSON export to Smarsh, Global Relay and similar.
  - Carry the reviewer and approver fields that FINRA 3110 Supplementary Material .07 expects: reviewer, item, date and action.
  - Ship journaling with the mail features, not after them.
- **Pitch4 page and section.**
  - Page 3, the "Email" card.
  - Page 6, "What ships, in order": "approval by email reply" in "Next", and "mail with the outside world on your domain" in "Last".
- **Why it helps.** Under content-based rules, messages an agent sends about the business are communications. Without journaling, pitch4's mail features would create a new off-channel risk for finance customers instead of reducing one.
- **Effect:** offering. **Confidence:** medium.
- **Evidence.**
  - **Rule 17a-4(b)(4)** covers "all communications received and … sent (and any approvals thereof) … relating to its business as such" ([Cornell LII](https://www.law.cornell.edu/cfr/text/17/240.17a-4)). The content "is determinative" ([FINRA NTM 03-33](https://www.finra.org/rules-guidance/notices/03-33)).
  - **FINRA requires retention before a messaging tool is permitted.** RN 17-18: firms "must first ensure that it can retain records of those communications" ([FINRA RN 17-18](https://www.finra.org/rules-guidance/notices/17-18)).
  - **Review must be evidenced.** FINRA 3110 requires review evidence and says "Merely opening a communication is not sufficient review" ([FINRA 3110](https://www.finra.org/rules-guidance/rulebooks/finra-rules/3110)).
  - **A new medium triggers review in the EU.** Art. 76(3): the adoption of alternative or additional measures "shall occur when a new medium of communication is accepted or permitted for use by the firm" ([Art. 76](https://www.legislation.gov.uk/eur/2017/565/article/76/adopted)).
  - **The UK has the same duty** in SYSC 10A (as rendered by a vendor; [GRIP](https://www.grip.globalrelay.com/rules/fca-sysc-10-a/)).
  - **The sweep began over business messages on unapproved channels.** The first off-channel order concerned messages about securities business on personal devices ([SEC 34-93807](https://www.sec.gov/litigation/admin/2021/34-93807.pdf)).
  - **Finance firms already pay per capture channel:** about $8–18 per user per month (secondary; [Vendr](https://www.vendr.com/marketplace/smarsh)).
- **Counter-evidence.**
  - Whether archive vendors accept intake for agent channels was not checked.
  - SIFMA asks to limit retention to communications with customers.
  - Enforcement has eased: the FY2026 priorities have 0 hits for "off-channel".
  - Firms may simply not permit agent email.
- **Cost and risk.**
  - The integration work is finance-specific and could delay the mail stage.
- **Test.**
  - Confirm one archive vendor's intake format for agent mail.
  - Ask finance design partners whether they would permit agent email without journaling.

### D9. Give the software away and charge for what only URnetwork runs, plus support and a paid self-hosted licence
- **What to change.**
  - **Keep every software feature free to self-host,** as Zulip and Langfuse do.
  - **Charge for what only URnetwork can run:** worldwide relays, public names and certificates, and mail delivery. The level-1 results add phone push for approvals, by analogy with Zulip's paid push relay.
  - **Sell supported self-hosting and SLAs as their own line,** and keep a paid enterprise licence for self-hosted installs (the GitLab pattern).
  - **Keep the self-hosted install simple and narrow:** one binary plus plain git, and support only a few install shapes.
  - **Offer a managed reader only as a separately labeled product** (D1).
  - **Keep small organizations inside the hosted service** by billing only active users, with a free threshold for small organizations (NetBird's 5 users; Zulip's 10 for push).
- **Pitch4 page and section.**
  - Page 4, "Open core, hosted blind", which already lists "support for your own installs".
  - Page 6, "Risks we manage: Free built-ins and self-hosting".
  - Page 6, the pilot row "Do open-weight teams adopt it, and pay?".
- **Why it helps.** People pay hosted open-source vendors to avoid running servers and to have someone accountable. They distrust self-hosting they believe is made hard on purpose. GitLab shows enterprises will pay for software they run themselves.
- **Effect:** both. **Confidence:** medium.
- **Evidence.**
  - **Zulip's self-hosted Free "Includes all Zulip features"**, and its paid plans mainly unlock mobile push ([Zulip](https://zulip.com/plans/)).
  - **Users pay to avoid running servers.** In the "would you pay" thread, 20 of 26 would pay and 11 cited not wanting to run servers. leros: "somebody else wakes up at 3am when it breaks" ([HN 36170233](https://news.ycombinator.com/item?id=36170233)).
  - **Hard self-hosting is read as a ploy.** XCSme: "If it's too easy to install and maintain, the cloud version would make no money" ([HN 43725815](https://news.ycombinator.com/item?id=43725815)).
  - **Many install shapes are costly to support.** PostHog's 3.5% of users on Kubernetes took "an outsized amount of time" ([PostHog](https://posthog.com/blog/sunsetting-helm-support-posthog)).
  - **Enterprises pay licence fees for self-managed software.** GitLab's revenue is about 69% self-managed (secondary; [8-K](https://www.sec.gov/Archives/edgar/data/1653482/000162828026013795/gitlab-ex99120260131fy26.htm); [Nasdaq/Zacks](https://www.nasdaq.com/articles/gitlab-shares-down-despite-q3-earnings-beat-revenues-y-y)).
  - **Both reader placements coexist by deployment type:** Wickr offers the bot for self-hosted Enterprise and serverless retention for Premium ([AWS](https://docs.aws.amazon.com/wickr/latest/adminguide/serverless-method.html)).
- **Counter-evidence.**
  - Self-hosting skews strong in this category:
    - Vaultwarden has 70,040 stars against bitwarden/server's 20,549, and 353.6 million Docker pulls.
    - Headscale has 45,259 stars against Tailscale's client repo at 38,474.
  - Selling hosted open source is hard. The ntfy maintainer: "it's super hard to get people to pay for it".
  - Volume pricing drives teams to self-host. Weryj: "around $300 a month" self-hosted against "the 10's of thousands" managed.
  - Some buyers are price-sensitive: "something like 5 bucks a month tops".
- **Cost and risk.**
  - Revenue depends on hosted convenience, which is the PostHog and Sentry risk.
  - Metered hosted storage and edge traffic need caps and predictable prices, or heavy agent users will self-host.
- **Test.**
  - Track hosted versus self-hosted relays in the pilots; this is already a page 6 measure.
  - Count support hours per install shape.
  - Offer a priced support and SLA line to self-hosting partners.

### D10. Name the licences on page 4, and pledge never to relicense
- **What to change.** State the licences:
  - Apache-2.0 (or MIT) for the sidecar, the entry format and the SDKs.
  - AGPL-3.0 for the relay and the admin server, with a commercial licence offered.
  - No BSL, FSL, SSPL or ELv2 anywhere.
  - A dated public pledge that released code will never be relicensed to non-OSI terms, or a DCO instead of a CLA.
- **Pitch4 page and section.**
  - Page 4, "Open source, so no one has to take our word for it" and "Open core, hosted blind".
  - Page 1, the "Open source" box.
  - Page 6, "Trust documents first", first bullet.
- **Why it helps.**
  - Pitch4 says "open" but names no licence.
  - A source-available licence would contradict "no one has to take our word for it".
  - Permissive client code lets harness vendors and corporate legal teams embed the sidecar.
- **Effect:** both. **Confidence:** medium. This was not tested beyond level 1.
- **Evidence.**
  - **This pattern kept or restored trust:** Element ([blog](https://element.io/blog/element-to-adopt-agplv3/)), Elastic ([blog](https://www.elastic.co/blog/elasticsearch-is-open-source-again)), Redis ([blog](https://redis.io/blog/agplv3/)) and NetBird ([announcement](https://netbird.io/knowledge-hub/netbird-agpl-announcement)).
  - **Commenters supported NetBird's move.** 6 of 9 top-level comments were supportive. moomin: "AGPL coupled with dual licensing allows them to be open source whilst protecting their commercial interests" ([HN 44813110](https://news.ycombinator.com/item?id=44813110)).
  - **Relicensing to source-available terms produced durable forks:** OpenTofu has 30,690 stars ([GitHub API](https://api.github.com/repos/opentofu/opentofu)) and Valkey 27,576 ([GitHub API](https://api.github.com/repos/valkey-io/valkey)). HashiCorp's BSL thread drew 632 points and 731 comments ([HN 37081306](https://news.ycombinator.com/item?id=37081306)).
- **Counter-evidence.**
  - AGPL may deter enterprise legal teams. jchw: "AGPL works because corporate lawyers are horrified by it".
  - There is no primary data on how many enterprises ban AGPL.
  - Two NetBird commenters feared the company could relicense through its CLA.
  - Sentry's FSL drew a calm reception (39 points; [HN 41171665](https://news.ycombinator.com/item?id=41171665)).
  - There is no evidence on whether a CLA or a DCO draws more contributors.
  - NixOS split NetBird's server packages after the relicense (search excerpt).
- **Cost and risk.**
  - AGPL can slow procurement.
  - A commercial exception needs a CLA, which is the trust weak point. A DCO gives up dual licensing.
- **Test.**
  - Have design partners' legal teams review an AGPL relay and admin server.
  - Ask the Goose and OpenCode maintainers whether they would embed an Apache-2.0 sidecar.

### D11. Add SOC 2 Type II and published audits to "Trust documents first"
- **What to change.**
  - Add SOC 2 Type II for the hosted service, starting the observation clock when the first hosted relay goes live.
  - Publish full audit reports, as Ente does.
  - Publish a plain list of the metadata the servers see, modeled on Tailscale's sentence.
  - Consider a small public bug bounty.
  - Seek third-party sponsorship for the audits.
- **Pitch4 page and section.** Page 6, "Trust documents first". The list there today omits the item vendor-risk reviewers ask for.
- **Why it helps.**
  - Even the purest E2EE brand in the set added SOC 2 Type II.
  - One buyer credits a compliance page with winning approval.
  - Publishing audits would set pitch4 apart from Tailscale, its nearest reach incumbent, and counter URnetwork's trust gaps.
- **Effect:** both. **Confidence:** medium. This branch did not go deeper; L2-2.05, in another branch, did.
- **Evidence.**
  - **Proton added SOC 2 Type II in July 2025,** saying it is often a baseline requirement in regulated industries (search excerpt; [Proton](https://proton.me/blog/soc-2)).
  - **Bitwarden** holds SOC 2 Type II, SOC 3 and ISO 27001, and runs a HackerOne bounty ([Bitwarden](https://bitwarden.com/compliance/)).
  - **Tailscale keeps its documents private:**
    - "Security audits are available on request".
    - The SOC 2 report needs an NDA.
    - "Tailscale does not have a bounty program."
    - Its metadata sentence: "We do receive metadata about which of your private nodes connect to which other private nodes" ([Tailscale](https://tailscale.com/security)).
  - **Ente published its full Cure53 report.** The audit found 15 issues, and Ente fixed 12 during it ([Ente](https://ente.com/blog/cern-audit); [summary PDF](https://ente.io/reports/Cure53-Audit-Summary-Oct-2025.pdf)).
  - **One buyer credits a compliance page.** threePointFive: "Their compliance page made it much easier to sell to my manager" ([HN 44911560](https://news.ycombinator.com/item?id=44911560)).
  - **Developer comparables gate SOC 2 by tier:** Langfuse from Pro at $199 a month, Supabase from Team at $599 a month.
- **Counter-evidence.**
  - The cost figures come from Vanta, which sells compliance automation.
  - Neither reviewer community requires a bug bounty.
  - Tailscale succeeds without publishing its audits.
  - Whether a ciphertext-only vendor still needs SOC 2 was a level-1 open question taken up in L2-2.05, which is not synthesized here.
- **Cost and risk.**
  - A SOC 2 audit fee runs about $10,000–50,000, plus tooling and staff time ([Vanta](https://www.vanta.com/blog/what-does-a-soc-2-audit-cost)).
  - A code audit costs tens of thousands of dollars: one was quoted at $143,000 and settled at $71,000 ([OSTIF](https://ostif.org/?p=3252)).
  - A Type II report arrives about 6–15 months after the hosted service starts (inference).
- **Test.**
  - Get quotes from two or three audit firms.
  - Apply to an audit-sponsorship programme.
  - Count how many design partners' vendor questionnaires require SOC 2.

### D12. Name Infisical Agent Vault, and present "agents are never metered" as a deliberate contrast
- **What to change.**
  - **Add Agent Vault to the competitor table.** Agent Vault brokers HTTP credentials and logs request metadata, without bodies, encrypted into the customer's own S3. The sidecar records sessions, edits, approvals and reach across harnesses under team keys.
  - **Consider recording Agent Vault sessions as reach events**, rather than competing on credential brokering.
  - **Present "Agents are never metered" as a deliberate contrast** with Infisical's per-identity and per-request pricing. Meter only hosted relay, edge, storage and mail, at small unit prices.
- **Pitch4 page and section.**
  - Page 5, "Where we stand, piece by piece" (the reach row) and the footnote ("Agents are never metered").
  - Page 3, "Govern every way out".
- **Why it helps.** Agent Vault names the same harnesses and overlaps "every way your agents reach the outside world is … approved, and on a record". A buyer who finds it unnamed will doubt the competitor table.
- **Effect:** differentiation. **Confidence:** medium.
- **Evidence.**
  - Agent Vault: agents call services "without ever holding the credentials"; it names "Claude Code, Codex, OpenCode, Hermes, OpenClaw, and any HTTPS_PROXY client"; it is "currently in preview" ([Infisical Agent Vault](https://infisical.com/platform/agent-vault)).
  - Infisical's pricing: $20–40 per identity, human or machine, and "$2 per 1,000" brokered requests ([Infisical](https://infisical.com/pricing)).
  - Low per-resource precedents: Tailscale $1 per tagged resource, NetBird €0.50 per machine.
- **Counter-evidence.**
  - The scope comparison is the researcher's reading, not a tested comparison.
  - Whether per-agent or per-request pricing is becoming the norm was a level-1 open question this branch did not pursue.
- **Cost and risk.** Low. Naming a competitor gives it some visibility.
- **Test.** Run Agent Vault beside the sidecar with one harness in a pilot, and document the overlap.

### D13. After counsel's review, claim insulation from preservation orders served on a vendor
- **What to change.**
  - If counsel agrees, add one plain line. L4-4.05's suggested wording: "Your sessions can't be read out of someone else's lawsuit against your vendor; holds you place are automatic, scoped and visible."
  - Keep it about orders served on a third party. Never frame it as avoiding the customer's own discovery duties.
  - Do not build fear marketing on the New York Times order.
- **Pitch4 page and section.**
  - Page 3, "Why encryption makes it safe to adopt".
  - Page 4, the table row "What URnetwork holds: Ciphertext".
- **Why it helps.** Level 1 found E2EE is a trust property, not a reason to buy. This would be the first buyer-facing reason, and it rests on events buyers have heard of.
- **Effect:** differentiation. **Confidence:** low.
- **Evidence.**
  - **A vendor order overrode deletion.** OpenAI was "NOW DIRECTED to preserve and segregate all output log data that would otherwise be deleted", "whether such data might be deleted at a user's request or because of "numerous privacy laws and regulations"" ([ECF 551](https://blogs.duanemorris.com/classactiondefense/wp-content/uploads/sites/56/2025/10/In-re-OpenAI-Inc.-Copyright-Infringement-Litig.-5.13.25-Order-ECF-No.-551.pdf)).
  - **Business users who were not parties were swept in.** The order covered ChatGPT Free, Plus, Pro and Team, and API use without ZDR ([Simon Willison quoting OpenAI's FAQ](https://simonwillison.net/b/8735)).
  - **The pattern repeated.** Anthropic must preserve more than 500 million prompts and outputs ([Mealey's](https://www.mealeys.com/mealeys/amp/articles/2507727)).
  - **Civil requesters are sent back to the customer.** OpenAI may object when a requester "has not exhausted" party discovery (search excerpt; [OpenAI](https://openai.com/en-GB/policies/civil-user-data-requests/)).
- **Counter-evidence.**
  - This is an inference only. No case tests whether a ciphertext-only host satisfies a preservation order, and no counsel has reviewed the claim.
  - Enterprise terms already offer an exit. ChatGPT Enterprise, Edu and ZDR customers were outside OpenAI's order.
  - AI documents reach prosecutors through the party anyway: in Heppner they reached them via a grand jury subpoena ([Proskauer](https://www.proskauer.com/alert/sdny-addresses-privilege-and-work-product-implications-of-using-unsecured-public-ai-tools)).
  - Pitch4's own page 3 says "a hosted model sees what the harness sends". The orders above reached exactly those provider-side logs, so the insulation covers only the copy URnetwork hosts.
  - Framing blindness as a way to avoid discovery is what Rodriguez and CA v. AppDynamics describe as evasion (L3-3.02).
- **Cost and risk.** A wrong claim carries legal and reputational exposure for a company that already has trust gaps.
- **Test.**
  - Get a written opinion from litigation counsel.
  - Only if it is favorable, test the line with security buyers in design-partner interviews.

---

## 4. What remains open

**Demand and price**
- Willingness to pay for Team and Assured is still untested; every price in this branch is a list price. No buyer has been asked whether they would pay for holds or archive connectors for coding agents (L4-4.05).
- There is no buyer evidence on whether design partners would run a reader container themselves or want a managed one (L2-2.13).
- Would algorithmic-trading firms, SCI entities or DORA entities pay for agent-aware change records beyond what Git, CI and ticketing logs give them? Entity counts and the UK status of RTS 6 are unverified (L3-3.09).
- Element's current AuditBot price is unknown; the $1-per-MAU figure is from 2022. The contents of Virtru's $499 Compliance package and Theta Lake's per-user SKU are also unknown (L2-2.13, L4-4.05).

**Legal acceptance**
- No US counsel, works council or DPO has reviewed the hybrid hold design (L3-3.02).
- How k-of-n key shares held by a works council would fare in US discovery is untested (L3-3.02).
- No published works agreement covers coding-agent sessions, E2EE or key escrow, and none was found with a US litigation-hold clause (L3-3.02).
- It is untested whether a ciphertext-only host satisfies a preservation order, and whether the "insulation" claim holds (L4-4.05).
- The SEC's "business as such" and Rule 204-2 proposals had not been published as of 1 Nov 2026 (L3-3.09).

**Product and design**
- Which features run blind depends on the entry format: whether the relay sees an entry's scope or signer key is not specified (L2-2.13).
- Coding-agent transcript sizes are unmeasured. They drive eDiscovery storage cost at $20 per GB-month (L4-4.05).
- Whether archive vendors accept intake for agent channels (agent email, Git comments) was not checked (L3-3.09, L4-4.05).
- Whether Wire's hold device receives earlier history is unverified (L3-3.02).

**Watch list (dates from L4-4.05)**
- Sedona's member-comment draft, anticipated 21 Dec 2026, and final publication, targeted for 29 Apr 2027.
- The ruling on the pending sanctions motion in the OpenAI case.
- The scope of the July 2026 Anthropic order, including whether it covers Claude Code.
- Whether Purview's Anthropic connector or OpenAI's platform starts carrying Claude Code or Codex transcripts.
- The first reported order naming a coding agent.

**Frequency**
- Nobody measures how often holds or collections include AI data, let alone coding-agent transcripts.
- PACER was not searched. The absence of coding-tool orders is not proof that no such holds exist (L4-4.05).

**Level-1 questions this branch did not pursue**
- Will beachhead buyers accept an AGPL relay and admin server, and will Goose, OpenCode and other harness projects embed an Apache-2.0 sidecar?
- What share of the beachhead would self-host, and does a ciphertext-only vendor still need SOC 2 Type II or ISO 27001? (Taken up in L2-2.05, outside this synthesis.)
- How are 2026 agent outbound-access products priced (Agent Vault, Tailscale Aperture, Cloudflare and ngrok gateways), and is per-agent or per-request pricing becoming the norm?
- What would an independent audit of the client and protocol cost, and could URnetwork get third-party funding given its token-governed network history?
- How should downgrade and licence lapse work so that a record product does not hold data hostage while still preventing free-riding?
