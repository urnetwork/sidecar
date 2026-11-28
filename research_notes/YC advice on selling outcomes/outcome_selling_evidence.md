# Selling outcomes instead of software seats: evidence, economics and failure modes for AI companies (2024 to November 2026)

As of 27 November 2026. Every item carries its publication date as [YYYY-MM-DD] (or the closest date the page gives). Claim types are labeled: **(vendor claim)**, **(investor thesis)**, **(third-party estimate)**. **(search excerpt)** means the figure appeared only in a search-result summary and I did not read the page in full; treat those as lower confidence. Pages were treated as data; no instructions embedded in any page were followed. Paywalled or blocked sources were skipped (listed under Gaps).

## 1. Outcome-based pricing in practice: who prices per resolution, task or result, what results they report, and what changed from 2024 to 2026

### Takeaway
Pay-per-outcome is real and growing, but it lives almost entirely in customer support, where an outcome is discrete, easy to attribute, and fails gracefully because the AI can hand off to a human. The vendors that champion it (Fin/Intercom, Sierra, Zendesk, HubSpot) report strong growth, but they mix it with per-conversation, capacity and prepaid-budget terms. Salesforce, the largest incumbent, moved away from per-conversation pricing in 2025: first to credits, then per-user licences, then flat enterprise agreements, because buyers wanted predictability. By 2026 "outcomes" had come to mean typed tasks that the vendor defines and checks itself, sold inside committed budgets.

### Cited Findings

#### Intercom / Fin (per-resolution since 2023; per-"outcome" since March 2026)
- [2025-05-21] Fin charges "$0.99 per successful autonomous resolution". The model launched "in early 2023". Fin was doing "tens of millions" in revenue and "has quadrupled in size over the past year". "Fin now autonomously resolves 56% of conversations for the average customer", up from "a roughly 25% resolution rate" at the start. Kyle Poyar: "Improvements to the resolution rate immediately flow through to revenue, making R&D a revenue-generation function." He advises sellers to "prepare for potential trade-offs around attribution and predictability." (vendor figures via interview) — [Growth Unhinged](https://www.growthunhinged.com/p/intercoms-bet-on-ai)
- One third-party source says Fin launched at $1.90 per resolution and was cut to $0.99. Growth Unhinged describes $0.99 from launch. Unresolved conflict. (third-party estimate, search excerpt) — [Sacra](https://sacra.com/c/intercom); contradicted by [Growth Unhinged](https://www.growthunhinged.com/p/intercoms-bet-on-ai)
- [updated 2026-05-18] Fin's VP of FP&A: "When we first launched the product, it was margin negative, which is not a sustainable business." Resolution rate "when we started... was in the 30s"; it is now "high 60s". Head of pricing: "Our costs scale with how often Fin is in a conversation, not how often it resolves it." Fin has "taken on all of the LLM cost risk." On forecasting: "We're just having to introduce a lot more complexity to the way we forecast." On prepaid buckets: "The accounting for… Fin buckets is real fun." (vendor statements) — [Chargebee interview with Fin finance leaders](https://www.chargebee.com/blog/how-fin-is-rebuilding-fpa-for-outcome-based-ai/)
- [2026-03-12 effective] "Effective March 12, 2026, Fin's core pricing metric is changing from Resolutions to outcomes." The new outcome types are resolution, "Procedure handoff" (billed at $0.99), "qualification" and "disqualification", with at most one Fin Voice outcome per call and at most one charge per conversation. "You will never be charged for an outcome that didn't happen." There is no charge if the customer explicitly asks for a human. Both confirmed and "assumed" resolutions are billable. (vendor documentation) — [Intercom Help: Understanding Fin outcomes](https://www.intercom.com/help/en/articles/13513868-understanding-fin-outcomes)
- An "assumed resolution" is counted when the customer disengages for 24 hours after Fin's last answer, and it bills the same $0.99. A resolution is deducted if the customer returns to the same conversation. (search excerpt of vendor help pages) — [Intercom Help: Fin resolutions](https://www.intercom.com/help/en/articles/8205718-fin-ai-agent-resolutions)
- [2026-03-09] Fin was "approaching $100M ARR" with about 8,000 paying customers, and Intercom raised $250M in debt to fund it. (secondary aggregator, search excerpt) — [TBPN digest](https://tbpn-digest.vercel.app/story/2026-03-09/intercom-raises-250m-in-debt-to-fund-its-ai-customer-agent-fin-now-approaching-100m-arr-with-8000-customers). Company-wide ARR is reported as more than $400M; a search summary attributed this to Fin's own site and third-party profiles, but I did not confirm it on a page I read (vendor claim, search excerpt) — [Fin About page](https://fin.ai/about)
- Sacra estimates that outcome pricing lifted Fin's net revenue retention from 112% to 146%. (third-party estimate, unverified, search excerpt) — [Sacra](https://sacra.com/c/intercom)
- [2026-06-15] "Salesforce will acquire Fin for approximately $3.6 billion". The release calls it "Fin, formerly Intercom", with "an established global customer base of more than 30,000 companies". It gives no Fin revenue or ARR and does not mention outcome pricing. Close was expected in Salesforce's FY27 Q4 — [Salesforce investor release](https://investor.salesforce.com/news/news-details/2026/Salesforce-Signs-Definitive-Agreement-to-Acquire-Fin/). [2026-08-26] Salesforce then said the Fin and Contentful deals should close "in the coming weeks, during the third quarter" of FY27 — [Salesforce Q2 FY27 release](https://www.salesforce.com/news/press-releases/2026/08/26/fy27-q2-earnings/). I did not confirm the close in a primary source.

#### Sierra (outcome-based, blended with consumption)
- [2024-12-10] "With outcome-based pricing, Sierra gets paid only when we complete a task for you." "If the conversation is unresolved, in most cases, there's no charge." The criteria are agreed per deployment: "We provide clear, agreed-upon criteria for each outcome upfront". Sierra also offers "a blended pricing approach" and consumption pricing for routing or greeter flows: "we recognize that outcome-based pricing may not always be the best fit." It acknowledges the buyer's worry: "No one wants to face a massive invoice." (vendor claim) — [Sierra blog](https://sierra.ai/blog/outcome-based-pricing-for-ai-agents)
- [2026-06-03] "People telling you it's simple are selling something." Outcome pricing is "more complex than seat-based or consumption pricing", operationally, contractually and in accounting. "It only works where the software is highly autonomous and highly attributable." "If the outcome can't be cleanly attributed to the software, you'll get into an endless debate." "If you don't deliver, attrition and margin take a hit in a way that simply does not happen when you charge for consumption or seats." "we're not dogmatic about it and do consumption-style work where it fits the shape of the problem." (vendor claim) — [Sierra, "Outcomemaxxing"](https://sierra.ai/blog/outcomemaxxing)
- [2025-11-21] Sierra reached $100M ARR 21 months after launch, on an "outcomes-based pricing model". It was last valued at $10B after a $350M round led by Greenoaks in September 2025, which TechCrunch calls a "100x revenue multiple". No figure is given for the share of revenue from outcome pricing or for margins — [TechCrunch](https://techcrunch.com/2025/11/21/bret-taylors-sierra-reaches-100m-arr-in-under-two-years/)
- [2026-10-30] "we hit $400M+ in ARR, adding over $150M+ in ARR in Q3 alone... more ARR in one quarter than we generated all of last year." Doubling from $100M to $200M took six months; from $200M to $400M took five. Sierra works with "almost 50% of the Fortune 50". "You pay for outcomes, not tokens used". The post gives no share of ARR from outcome contracts. (vendor claim; ARR is self-reported) — [Sierra blog](https://sierra.ai/blog/our-customers-ambition-is-accelerating-our-growth)
- [2026-05] A $950M round valued Sierra at more than $15B. One outlet says $15.8B. (secondary, search excerpt) — [CMSWire](https://www.cmswire.com/customer-experience/sierra-raises-950m-at-15b-valuation-eyes-transformation-beyond-customer-support/)
- A figure of about $1.50 per resolution appears only in third-party commentary, not in Sierra's materials. (search excerpt) — [ValueAdd VC](https://valueaddvc.com/blog/how-does-sierra-ai-make-money-outcome-based-pricing-enterprise-agents-and-the-business-model-breakdown)

#### Zendesk (resolution pricing from 2024; "Outcome Budget" from November 2026)
- [2024-08-28] "Traditional pricing models no longer suffice in an era where customer value can and should be measured by outcomes". Customers "will only incur costs for issues that are resolved autonomously by AI". A "starter usage level" is included, with an in-product dashboard. No per-resolution price is published on the page. (vendor claim) — [Zendesk newsroom](https://www.zendesk.com/newsroom/articles/zendesk-outcome-based-pricing/)
- [2024] Additional automated resolutions cost "$1.50 or more" depending on plan, with volume discounts; escalated queries are not charged. (search excerpt) — [Computer Weekly](https://www.computerweekly.com/news/366611612/Zendesk-debuts-outcome-based-pricing-for-AI-agents)
- [2025-12-02] CEO Tom Eggemeier put AI-only ARR at about $200M at the end of 2025 (said to be more than 10% of total ARR), with about 20,000 AI customers. The 2026 target is reported as $400M to $500M (sources differ). He is quoted: "We don't get paid on [a] consumption basis. We only get paid if the AI agent solves the problem." (vendor claim via press, search excerpt) — [The Letter Two](https://thelettertwo.com/2025/12/02/zendesk-ai-arr-500m-2026/); [NeoFeed](https://neofeed.com.br/negocios/zendesk-ve-receita-recorrente-de-ia-ultrapassar-us-200-milhoes-e-redesenha-modelo-de-atendimento/en/)
- [2026-05-19, Relate 2026] Zendesk says every billed resolution is verified by the resolving agent and "independently confirmed by a dedicated AI evaluation model". (vendor claim, search excerpt) — [CMSWire](https://cmswire.com/customer-experience/zendesk-unveils-autonomous-ai-workforce-at-relate-2026); [TechRadar](https://www.techradar.com/pro/zendesk-links-ai-pricing-to-verified-resolution-outcomes)
- [2026-08-31] Zendesk's Chris Donato: if AI resolves 90% of a problem and a human finishes it, "we don't count it". Automation must resolve "100% of that interaction." (vendor statement) — [CIO Dive](https://www.ciodive.com/news/agentic-ai-outcome-pricing-models/829023/)
- [2026-11-12] On the Nov 10 launch of the "Outcome AI Platform" and "Zendesk Unlimited": unlimited seats for new capabilities. Customers set an "Outcome Budget" and pay for "eligible issues resolved and business work completed", split into Conversational and Operational AI Outcomes. Zendesk calls this the "next evolution" of its 2024 model. No rates, minimums or overage terms were disclosed. Futurum's analyst: "the vendor is grading its own homework" — [Futurum](https://futurumgroup.com/?p=97869)

#### Salesforce Agentforce (per-conversation, then credits, then per-user and flat enterprise licences)
- [2025-05-23] The move away from the $2 flat per-conversation charge: it "doesn't scale for customers who want multiple use cases" and applied "regardless of the complexity of the task." Under Flex Credits, "Each action costs $0.10 and you only pay for what you use"; the example is 3–6 actions, or $0.30–$0.60, for what used to cost $2. Salesforce also added an "unmetered per-user, per-month license" after hearing that "planning for Agentforce usage at scale across a large number of users can be difficult." (vendor statement) — [Salesforce blog](https://www.salesforce.com/blog/flex-credits/)
- [current page, Nov 2026] Prices: $500 per 100k Flex Credits; Agentforce add-ons from $125/user/month; Agentforce 1 editions from $550/user/month; a $5/user/month user licence that requires credits. The $2-per-conversation option still exists, but cannot be combined with Flex Credits in the same org. (search excerpt) — [Salesforce Agentforce pricing](https://www.salesforce.com/agentforce/pricing/)
- [2025-10, AELA] The Agentic Enterprise License Agreement is a "fixed-price, fixed-term agreement with unlimited access to Salesforce consumption services, no overages, and no usage-based billing" (search excerpt) — [Salesforce flexible buying models](https://www.salesforce.com/pricing/flexible-buying-models/). Forrester describes it as unlimited Agentforce, Data Cloud and MuleSoft for a fixed fee over two or three years (search excerpt) — [Forrester](https://www.forrester.com/blogs/ai-agents-become-economic-actors-salesforce-rewrites-the-rules-of-pricing)
- [2025-12-12] Benioff: "When we first started with Agentforce, we were talking about [charging] so much per conversation", and "customers have pushed for more flexibility." The Register reports his view that seat-based pricing "with some caveats" was becoming the norm, and that the AELA, "based on the number of seats", is now the preferred option — [The Register](https://www.theregister.com/2025/12/12/ai_agents_salesforce_pricing/)
- [2026-10-02] Benioff: "We've had to throw away our price book, basically, and come up with a whole new pricing mechanism." "Some still want pure user pricing; it's predictable." Salesforce now offers outcome-based pricing for one agent, Agentforce Help Agent — [TechTarget](https://www.techtarget.com/it-strategy/news/366651390/Outcomes-based-AI-pricing-works-in-theory-but-in-practice)
- Reported results (vendor-reported, under mixed pricing models):
  - [2025-12-03] "Agentforce ARR surpassed half a billion in Q3, up 330% Y/Y"; "over 18,500 Agentforce deals since launch; over 9,500 paid deals" — [Salesforce Q3 FY26](https://investor.salesforce.com/news/news-details/2025/Salesforce-Delivers-Record-Third-Quarter-Fiscal-2026-Results-Driven-by-Agentforce--Data-360/default.aspx)
  - [2026-02-25] "$800 million, up 169%", with 29,000 deals — [Salesforce Q4 FY26](https://www.salesforce.com/news/press-releases/2026/02/25/fy26-q4-earnings/)
  - Q1 FY27: $1.2B, up 205% — [Salesforce/Fin release](https://investor.salesforce.com/news/news-details/2026/Salesforce-Signs-Definitive-Agreement-to-Acquire-Fin/)
  - [2026-08-26] "exceeded $1.5 billion, up over 240% Y/Y". From Q2 FY27 the figure also includes Slackbot and Headless 360, so it is not like-for-like with earlier quarters — [Salesforce Q2 FY27](https://www.salesforce.com/news/press-releases/2026/08/26/fy27-q2-earnings/)

#### HubSpot (moved toward outcome pricing in 2026)
- [2026-04-13, effective Apr 14] Breeze Customer Agent went from $1.00 per conversation to "$0.50 per resolved conversation" (50 credits). Breeze Prospecting Agent went from a monthly charge per enrolled contact to "$1.00 per lead recommended for outreach". The page does not formally define "resolution". CCO Jon Dick: "Outcome-based pricing removes that risk. You pay when it works, full stop." (vendor claim) — [HubSpot](https://www.hubspot.com/company-news/hubspots-customer-agent-and-prospecting-agent-now-you-pay-when-the-task-is-complete)

#### Decagon (offers both models; most customers choose per-conversation)
- [2024-12-10] "The vast majority of our customers choose per-conversation pricing." On defining a resolution: "If a frustrated customer stops responding, does that count as 'resolved'?" and "You never want to be in a situation where you're arguing over what a 'resolution' is." Per-conversation pricing means Decagon is "not incentivized to push partial resolutions or sidestep tough cases." (vendor claim) — [Decagon blog](https://decagon.ai/blog/pricing-ai-agents)

#### Outside customer support
- [2026-08-10] "Outcome-based pricing has found a real home in one category: customer support" (Zendesk, Sierra, Fin, Decagon). "Beyond customer support, the picture is messier": Riskified and HighRadius are "individual bets, not category trends." Outlook: "likely to remain compelling but relatively narrow in scope over the next several years" — [Bain](https://www.bain.com/insights/ai-pricing-a-reality-check-on-effort-usage-and-outcomes/)
- [2025-11-12] Riskified, a public fraud-prevention firm, sells a Chargeback Guarantee: it assumes the financial liability when approved orders turn out to be fraudulent. GAAP gross margin was 50% in Q3 2025 (49% a year earlier) and 49% for the first nine months (52% a year earlier) — [Riskified Q3 2025 release](https://ir.riskified.com/news-releases/news-release-details/riskifieds-third-quarter-results-reflect-accelerated-gross)
- Foundation Capital cites Harvey's pricing at about $1,000 per lawyer per year. Renewals centre on "hours saved, not seats deployed" (workflow-based, not outcome-based). Most AI SDR tools still use task or usage pricing. (investor claim) — [Foundation Capital](https://foundationcapital.com/the-4-6t-service-as-software-opportunity-lessons-from-year-one/)

### Inferences
- **What changed, 2024 to 2026** (timeline compiled from the dated findings above):
  - 2023: Fin prices per resolution.
  - Aug 2024: Zendesk launches resolution pricing.
  - Late 2024: Salesforce charges $2 per conversation; Sierra and Decagon publish their pricing rationales; Sequoia writes that "AI companies sell work ($ / outcome)" (see §2).
  - May 2025: Salesforce moves to $0.10 per action plus unmetered per-user licences.
  - Oct to Dec 2025: Salesforce launches flat AELAs and says seat-based "with caveats" is the norm.
  - 2026: outcome pricing broadens inside customer support. Fin moves to typed "outcomes" (Mar), HubSpot to per-resolution (Apr), Zendesk adds AI-verified resolutions (May) and then "Outcome Budgets" with unlimited seats (Nov). Salesforce buys Fin for about $3.6B (Jun).
- The meaning of "outcome" drifted from a business result toward a vendor-defined, vendor-verified completed task: procedure handoffs, qualifications, leads recommended, "business work completed". In Bain's terms, much of what is marketed as outcome pricing is output pricing.
- Billing is converging on committed, outcome-denominated capacity: Fin's prepaid buckets, Zendesk's Outcome Budget, Salesforce's AELA and credits. Sellers keep the "pay for results" message, and buyers get a fixed budget their procurement teams can approve (see §6).
- The fastest-growing outcome-priced firms do not show that outcome pricing caused their growth. Sierra discloses no share of revenue on outcome contracts. Decagon, a direct competitor, sells mostly per conversation. The growth is certainly consistent with outcome pricing in customer support; that it was caused by it is not proven.

### Gaps
- No vendor publishes the share of revenue actually billed per outcome, dispute or credit rates, or audited AI ARR. Sierra, Zendesk AI and Fin figures are self-reported or third-party estimates.
- Zendesk's per-resolution and Outcome Budget rates are not published. Sierra's per-resolution price is unknown; the $1.50 figure is unsourced. The terms for Salesforce's Help Agent outcome pricing are unknown.
- Fin's launch price history ($0.99 vs $1.90) and the Salesforce–Fin closing date are unconfirmed in primary sources.

## 2. The "service as software" and AI-enabled services theses: what Foundation Capital, a16z, Sequoia, General Catalyst, Bessemer and others claim, with what numbers

### Takeaway
The investor theses rest on budget arithmetic: services and labour spend is 6 to 20 times software spend, so whoever sells the work itself captures the larger budget, and does not lose when AI shrinks seat counts. These essays put precise numbers on the market size but are vague or silent on gross margins, liability and delivery cost. Most were written by investors in the companies they cite. The strongest pieces of numeric support are Bessemer's margin and ARR-per-FTE benchmarks and General Catalyst's stated margin targets, and the GC figures are the firm's own claims.

### Cited Findings

#### Foundation Capital
- [2024, Aug/Oct] The firm sizes a "$4.6T" opportunity: enterprise spend on salaries and outsourced services, of which IT services and business process services are $2.3T (per Gartner, as cited). It frames AI as taking over whole jobs rather than assisting. (investor thesis, search excerpt) — [Foundation Capital, "AI leads a service as software paradigm shift"](https://foundationcapital.com/ai-service-as-software/)
- [date shown as 2026-11-27, probably a display date; original date unconfirmed] "Lessons from the first year" (Ashu Garg, Jaya Gupta):
  - "integration is not a post-sale activity. It is the product surface."
  - Proofs of concept now need engineering time, a "cost of sale crisis".
  - "outcome-based pricing doesn't work if there's too much variability from company to company"; "outcome guarantees become impossible to standardize."
  - "The progression toward outcome-based pricing will be messy, with false starts, hybrid tiers, and plenty of margin surprises."
  - Usage-priced vendors get "whipsawed whenever model-pricing drops faster than they can re-price."
  - Buyers take an "I'll believe it when I see it" stance.
  - "deploy and continuously re-engineer".
  - (investor thesis; FC invests in several companies it discusses) — [Foundation Capital](https://foundationcapital.com/the-4-6t-service-as-software-opportunity-lessons-from-year-one/)

#### Sequoia
- [2024-10-09] Sonya Huang and Pat Grady: "Software companies turn labor into software." "the addressable market is not the software market, but the services market measured in the trillions of dollars." "Cloud companies sold software ($ / seat). AI companies sell work ($ / outcome)". "Sierra gets paid per resolution." "There is no such thing as 'a seat'." Their own caveat is that Sierra benefits from "a graceful failure mode (escalation to a human agent)... Not all companies are so lucky." (investor thesis) — [Sequoia, "Generative AI's Act o1"](https://www.sequoiacap.com/article/generative-ais-act-o1/)
- [2026-03-05] Julien Bek:
  - "The next $1T company will be a software company masquerading as a services firm."
  - "For every dollar spent on software, six are spent on services."
  - "A copilot sells the tool. An autopilot sells the work." "If you sell the tool, you're in a race against the model." "autopilots capture the work budget from day one." "The higher the intelligence ratio in any field, the sooner autopilots will win."
  - Example: $10K/yr for QuickBooks versus $120K for an accountant to close the books.
  - US TAM by category (investor estimates): insurance brokerage $140–200B; accounting and audit $50–80B outsourced; healthcare revenue cycle $50–80B; claims adjusting $50–80B; tax advisory $30–35B; legal and transactional $20–25B; IT managed services $100B+; procurement $200B+; recruiting and staffing $200B+; management consulting $300–400B, "mostly judgement" and left largely human.
  - The essay does not discuss gross margins, inference costs or liability.
  - Conflict: a third-party commentary claims Bek concedes that "inference economics are not software economics"; I did not find that in the essay text.
  - (investor thesis; page metadata shows Nov 24, 2026, body says March 5, 2026) — [Sequoia, "Services: The New Software"](https://sequoiacap.com/article/services-the-new-software)

#### a16z
- [2024-12-19] "Software is becoming labor." AI is "turning what used to be pure service businesses into scalable software plays." "Per-seat is no longer the atomic unit of software." For Zendesk "the natural pricing metric becomes successful outcomes"; Zendesk then charged $115/month per agent seat. Decagon offers per-conversation and per-resolution pricing. "There is no one-size-fits-all solution for pricing." (investor thesis) — [a16z Enterprise Newsletter](https://a16z.com/newsletter/december-2024-enterprise-newsletter-ai-is-driving-a-shift-towards-outcome-based-pricing/)
- [2025-06-04] Joe Schmidt, "Trading Margin for Moat": "The only thing businesses should be optimizing for today is growing total gross profit as fast as possible." Customization work lowers early gross margins and raises burn; services can be sold at cost; "Over time, ecosystems can be powerful tools for scalability and margin protection." (investor thesis) — [a16z](https://a16z.com/services-led-growth/)
- a16z pieces also put white-collar services at about $6T, roughly 20 times US enterprise software spend (search excerpt) — [a16z, "AI will supercharge modelbusters"](https://a16z.com/ai-will-supercharge-modelbusters/). An Oct 2025 LP Summit talk cites $13T of US labour spend as the target (search excerpt) — [a16z podcast "Software is Eating Labor"](https://a16z.com/podcast/software-is-eating-labor/)

#### General Catalyst (AI-enabled roll-ups) and Mayfield
- [2025-08-28] "Customers care about outcomes, not products." "Software only set the table for the future of services." Market sizes: US services "$6T+ annually" against a "$370B software market"; the legal industry "$1.05T". Targets: "double profit margins, often targeting 30-40% margins"; "a new Rule of 60 standard"; growth from single digits "to 10-20% growth". Portfolio claims:
  - Crescendo: gross margins "to 60-65% or more"
  - Long Lake: "acquired 18 businesses"
  - Dwelly: "acquired 6 agencies" and "doubling the EBITDA margins"
  - Eudia: a "300+ person legal delivery team"
  - The page names no risks. (investor thesis and portfolio claims) — [General Catalyst](https://www.generalcatalyst.com/stories/the-future-of-services)
- [2025-09-28] GC put $1.5B of its latest fund into its "creation" strategy across seven industries, with plans for up to 20. Marc Bhargava: "Services globally is a $16 trillion revenue a year globally". The goal is to "double — at least — the EBITDA margin". Mayfield set aside $100M for "AI teammates". Navin Chaddha: "If 80% of the work will be done by AI, it can have an 80% to 90% gross margin"; portfolio company Gruve reportedly hit 80% gross margin (founders' claim) — [TechCrunch](https://techcrunch.com/2025/09/28/the-ai-services-transformation-may-be-harder-than-vcs-think/)

#### Emergence Capital
- [2026-03-23] "AI-Native Service businesses (AINS) leverage AI to deliver services faster, better, and/or cheaper than incumbents"; "the customer buys a result and is indifferent to how it's performed (human, AI, or hybrid)". "The Big 4 alone pull in $200B+ a year." Margins are described only as "gross margins that make these businesses venture-backable". The firm concedes "this model wasn't really possible until 2023" and that "the true playbook... is being written in real-time." Examples: Harper, Mechanical Orchard, Hanover Park, Crosby, Prosper AI. (investor thesis) — [Emergence Capital](https://www.emcap.com/thoughts/why-ai-native-services-and-why-now)

#### Bessemer, Battery and Wellington
- [2025-08-13] Bessemer: "these AI Supernovas have only 25% gross margins, often trading distribution for profit in the short term", benchmarked as "~25% (often negative)". Shooting Stars run about 60%. Supernovas show "$1.13M ARR/FTE, which is 4-5x above a typical SaaS benchmark"; Shooting Stars about $164K. In vertical AI "the line between software and service blurs". Bessemer expects "a wave of consolidation in high-service, regulated industries." The report contains no pricing-model data. (investor report) — [Bessemer State of AI 2025](https://www.bvp.com/atlas/the-state-of-ai-2025)
- [2025-12-18] Battery: "the old SaaS model of seat-based pricing, and even pure consumption-based pricing, should give way to value-based pricing models"; "value capture is concentrated in hardware (GPUs) with ~75% gross margins, while AI applications often see compressed margins due to inference costs." (investor thesis) — [Battery Ventures](https://battery.com/blog/state-of-ai-2025)
- Wellington: AI-native services businesses "may initially resemble services revenue. Gross margins may be lower." (investor view, search excerpt) — [Wellington](https://www.wellington.com/en/insights/ai-native-services)

### Inferences

#### Steelman of "sell the outcome, not the software" (built from the cited evidence)
1. **A bigger budget.** Services and labour spend is about 6 times software (Sequoia), and GC's US figures imply about 16 times ($6T vs $370B). An outcome seller is paid from the work budget, not the IT budget.
2. **Protection from seat compression.** AI cuts headcount, and seat-priced vendors shrink with it. BCG found 40% of IT buyers cite fewer seats as their main way to cut software spend (§6). The Feb 2026 "SaaSpocalypse" sell-off was driven by fear that agents would cut seat counts (§4).
3. **A defence against the model.** "If you sell the tool, you're in a race against the model" (Sequoia). When the vendor owns the result, a better base model improves its margins instead of commoditising its product.
4. **Incentives line up.** Buyers pay only on success ("You pay when it works, full stop", HubSpot). The vendor's R&D becomes revenue (Fin: each point of resolution rate is billable). The MIT study found purchased solutions succeed about twice as often as internal builds (§5), which favours specialist vendors who take the risk.
5. **Growth evidence.** Sierra went from $0 to $400M+ ARR in about 2.7 years, at roughly 100x ARR in late 2025. Fin's AI agent is reported near $100M ARR and Salesforce is buying the company for about $3.6B. Zendesk reports about $200M of AI ARR. HubSpot and Zendesk extended outcome pricing in 2026.
6. **A path to software margins.** Fin went from margin-negative at a 30s% resolution rate to high-60s% (§1). ICONIQ projects AI gross margins of 45%, then 53%, then 59% (§4). ServiceNow and Workday rose from 54–63% gross margin at IPO to 75–79% (§3).
7. **The implementation moat.** Forward-deployed work captures the customer's data and workflows ("system of work", a16z; "integration... is the product surface", FC). Each deployment makes the next one cheaper.
- The steelman is strongest for outcome-priced AI software in narrow, high-volume, attributable workflows. It is weakest for full-stack AI services that own human delivery, where the support is mostly investor targets (§4, §5).

### Gaps
- None of the theses gives measured gross margins for AI-native services firms. GC, Mayfield and Emergence give targets or claims; Sequoia gives none.
- I could not find an original publication date for Foundation Capital's "lessons from year one".
- I did not read Rampell's "Input Coffee, Output Code" in full; the a16z labour-market figures above are search excerpts.

## 3. Forward-deployed engineering: how widely AI startups and labs adopted the Palantir model in 2025–2026, and what it costs and returns

### Takeaway
Adoption went from a startup tactic in 2025 to a lab-scale services business in 2026. OpenAI launched a $4B+ deployment company, and Anthropic launched a services venture with private-equity firms plus a $100M programme to train 10,000 FDEs. The costs are real: Gartner puts FDE fees above $200K per quarter per use case, and warns of "FDE-washing". The case that FDE work pays off rests mainly on Palantir's history, which took years and came with heavy customer concentration.

### Cited Findings

#### Adoption
- [2026-03-10, citing the FT] "Monthly job listings for forward-deployed engineers increased by more than 800% between January and September 2025"; OpenAI, Anthropic and Cohere are expanding FDE teams — [PYMNTS](https://www.pymnts.com/artificial-intelligence-2/2026/forward-deployed-engineers-emerge-as-one-of-ais-fastest-growing-jobs/) (FT original skipped: paywalled)
- [2025-06-04] At OpenAI, 22 of 311 open roles were forward-deployed or solutions engineering. Decagon uses "Agent Product Managers" in the same role — [a16z](https://a16z.com/services-led-growth/)
- [2026-07] ICONIQ: half of companies plan to scale forward-deployed engineering as a permanent go-to-market motion. FDEs are most often used "as a revenue driver" (38%), as "a revenue role tied to expansion and retention." (investor survey) — [ICONIQ State of AI 2026](https://www.iconiq.com/growth/reports/state-of-ai-2026)
- [2026-05-11] OpenAI launched the OpenAI Deployment Company, majority-owned by OpenAI, with "more than $4 billion in initial investment". Its acquisition of the consultancy Tomoro brings "approximately 150 experienced Forward Deployed Engineers and Deployment Specialists". There are 19 partner firms (TPG leads; Advent, Bain Capital and Brookfield co-lead; Bain & Company, Capgemini and McKinsey are among investors). The page gives no pricing model. (vendor announcement) — [OpenAI](https://openai.com/index/openai-launches-the-deployment-company)
- [2026-05-04] Anthropic, Blackstone, Hellman & Friedman and Goldman Sachs "announced the formation of a new AI services company" for mid-sized companies, staffed with Anthropic Applied AI engineers. Rationale: "Enterprise demand for Claude is significantly outpacing any single delivery model." (vendor announcement) — [Anthropic](https://www.anthropic.com/news/enterprise-ai-services-company)
- [2026-10-02] Anthropic's Claude Frontier Academy: a "$100 million commitment" that "aims to train 10,000 Frontier Deployed Engineers (FDEs) by the end of 2027"; "the people with the skills to make it work inside a real business have become the hardest talent to find." (vendor announcement) — [Anthropic](https://www.anthropic.com/news/claude-frontier-academy)
- Foundation Capital calls FDEs "one of the most strategic assets in enterprise AI companies" and says the cost becomes a moat because each deployment makes the next one cheaper (investor thesis) — [Foundation Capital](https://foundationcapital.com/the-4-6t-service-as-software-opportunity-lessons-from-year-one/)

#### Cost
- [2026-10-01] Gartner (Mukul Saha):
  - FDE consulting fees "could exceed $200,000 per quarter per use case".
  - "Many providers now use 'forward deployed' as a label for implementation, professional services..."; "Some charge premium fees without the delivery depth, program management, or change management maturity to justify them."
  - About 2,000 active FDEs, while "Demand is probably quadruple that".
  - Gartner predicts about 70% of vendor-led AI engineering efforts will be abandoned by 2028.
  - Positive note: "If you truly have the right FDE model, we see it bringing good outcomes."
  - — [CIO Dive](https://www.ciodive.com/news/can-forward-deployed-engineers-fdes-fix-ai-gartner/831833/)
- Salaries: OpenAI's FDE postings in the US top out at $345,000 plus equity, across 24 openings (secondary report of job postings, search excerpt; syndicated copy, not fetched) — [AOL-syndicated report](https://www.aol.com/articles/openai-exec-explains-growing-team-080035434.html)
- [2025-06-04] Services lower early gross margins and raise burn; a16z recommends incentives "that allow services to be sold at cost"; implementation leads rarely want quota — [a16z](https://a16z.com/services-led-growth/)
- [2025-09-22] N47: "$1M+ annual contract values" are needed to justify deployment teams. "Many companies attempting FDE will drift into consulting businesses disguised as software companies." Warning signs: FDE teams growing linearly with revenue, and deployment time not shrinking — [N47](https://www.n47.com/insights/the-forward-deployed-engineer-dilemma)

#### Returns and the historic analogue
- [S-1 filed 2020] Palantir:
  - Contribution margin 21% in 2019 and 48% in H1 2020, up from 17% in H1 2019.
  - The top 20 customers produced $495.2M, or 67% of 2019 revenue.
  - Only 125 customers in H1 2020.
  - (pre-2024 historical analogue, search excerpt of SEC filing) — [Palantir S-1](https://www.sec.gov/Archives/edgar/data/1321655/000119312520230013/d904406ds1.htm); [TechCrunch, "125 customers after 17 years"](https://techcrunch.com/2020/08/21/leaked-palantir-s-1-shows-company-has-125-customers-after-17-years/)
- [2025-09-22] "Palantir maintains 80%+ gross margins". Sales and marketing fell "from 62.6% of revenue in 2020 to 24.3% in 2025" — [N47](https://www.n47.com/insights/the-forward-deployed-engineer-dilemma)
- [2025-06-04] Margin at IPO: ServiceNow 63.2%, Workday 54.1%; by 2024, 79% and 75%. Salesforce "reportedly burned over $52 million to generate $22 million in revenue" before its partner ecosystem matured — [a16z](https://a16z.com/services-led-growth/)

### Inferences
- FDE work has become the standard way to deliver outcomes, but it is now crowded. The labs themselves sell deployment, with private equity and the big consultancies as partners. Startups selling "finished work" therefore compete on delivery capacity with OpenAI's and Anthropic's own services arms, not only on product.
- At Gartner's figure of more than $200K per quarter per use case (about $800K a year), FDE-led outcome selling only works on large contracts (N47's $1M+ ACV). That pushes sellers upmarket and toward a few big customers, the Palantir pattern of 125 customers with the top 20 at 67% of revenue.
- The return case is real but slow and survivorship-biased. Palantir and ServiceNow got to software margins; N47 and Gartner describe many who drift into consulting or abandon the effort. The test is whether deployment time and FDE headcount per dollar of ARR fall over time.

### Gaps
- No public data on FDE-to-customer ratios, FDE cost as a share of revenue, or payback for 2025–2026 AI startups.
- No independent count of FDE postings after Sep 2025.
- Sierra, Decagon and Fin do not disclose deployment headcount.

## 4. Economics: gross margins of AI-enabled services versus SaaS, revenue multiples, services revenue share, cost of delivery, and the move toward software leverage

### Takeaway
AI application gross margins average roughly 45–53%, against 70–80%+ for SaaS. The fastest growers sit near 25% or below. Outcome pricing makes this worse at first, because the vendor pays inference costs on every attempt but is paid only on success. Valuations split in two. Outcome-priced AI software has commanded very high multiples (Sierra around 100x ARR in late 2025). Human-heavy services and roll-ups are still anchored to services multiples (about 1x revenue, 6x EBITDA). Investor claims of 60–90% gross margins for AI services are unverified.

### Cited Findings

#### Gross margins
- [2026-07] ICONIQ: average AI product gross margin was 45% in 2025, projected at 53% in 2026 and 59% in 2027. "As products scale, talent's share of cost falls while inference rises" (investor survey) — [ICONIQ](https://www.iconiq.com/growth/reports/state-of-ai-2026)
- [2025-08-13] Bessemer: Supernovas about 25% gross margin ("often negative"); Shooting Stars about 60% — [Bessemer](https://www.bvp.com/atlas/the-state-of-ai-2025)
- High Alpha: median gross margin is 80% for AI-enabled companies and 75% for AI-native companies (search excerpt) — [High Alpha](https://highalpha.com/blog/does-it-pay-to-be-ai-native-growth-rates-for-ai-companies)
- [2025-09-22] "traditional services companies operate at 30-40% gross margins while software companies achieve 70-80%+." — [N47](https://www.n47.com/insights/the-forward-deployed-engineer-dilemma)
- [2025-06-27] BPOs: EBITDA margin typically 10–15%, against a roll-up target of 40% or more. Concentrix has gen-AI deployments at over 1,000 customers but still runs about a 10% EBITDA margin — [Air Street Press / Fortune](https://press.airstreet.com/p/ai-rollup-mirage-technology-2025)
- [2026] SPI Research: services firms running "complex agents or an AI-first model" report 20.5% EBITDA, against 13.3% for others. 84.8% say AI saves time; only 29.9% say it generates revenue (search excerpt) — [Teamwork/SPI](https://www.teamwork.com/resources/spi-ai-benchmark/)
- Investor and portfolio claims, all unverified: GC targets "30-40%" margins and Crescendo gross margin of "60-65% or more" — [General Catalyst](https://www.generalcatalyst.com/stories/the-future-of-services). Mayfield's "80% to 90% gross margin"; Gruve's 80% — [TechCrunch](https://techcrunch.com/2025/09/28/the-ai-services-transformation-may-be-harder-than-vcs-think/)
- [2025-11-12] Riskified, the audited outcome/guarantee example, runs about 50% GAAP gross margin, down from 52% for the nine months year on year — [Riskified](https://ir.riskified.com/news-releases/news-release-details/riskifieds-third-quarter-results-reflect-accelerated-gross)

#### Cost of delivery under outcome pricing
- [2026-05-18] Fin was "margin negative" at launch with a resolution rate "in the 30s", and costs scale with conversations, not resolutions — [Chargebee/Fin](https://www.chargebee.com/blog/how-fin-is-rebuilding-fpa-for-outcome-based-ai/)
- Token and engineering costs are "far higher than the penny-level costs of traditional software infrastructure" — [Foundation Capital](https://foundationcapital.com/the-4-6t-service-as-software-opportunity-lessons-from-year-one/)
- [2025-08-06] Most teams started with cost-plus credits at a 30–50% markup. One CFO describes "$10k of costs on a $500 plan." — [Metronome field report](https://metronome.com/blog/ai-pricing-in-practice-2025-field-report-from-leading-saas-teams)
- [2026-06-03] "If you don't deliver, attrition and margin take a hit" — [Sierra](https://sierra.ai/blog/outcomemaxxing)

#### Multiples and valuations
- [2025-11-21] Sierra: $10B on $100M ARR, a "100x revenue multiple" — [TechCrunch](https://techcrunch.com/2025/11/21/bret-taylors-sierra-reaches-100m-arr-in-under-two-years/). [2026-05] more than $15B (secondary) — [CMSWire](https://www.cmswire.com/customer-experience/sierra-raises-950m-at-15b-valuation-eyes-transformation-beyond-customer-support/)
- [2026-06-15] Fin (Intercom) sold for about $3.6B — [Salesforce](https://investor.salesforce.com/news/news-details/2026/Salesforce-Signs-Definitive-Agreement-to-Acquire-Fin/). That is against reported total ARR above $400M (vendor claim, search excerpt) — [Fin](https://fin.ai/about)
- [2025-06-27] Roll-ups buy traditional BPOs at about 1x revenue. BPOs trade at about 6x EBITDA, against 20x+ for software. "AI-transformed" BPOs (Concentrix, Genpact, Infosys) trade at 5–23x EV/EBITDA, against 22–92x for Salesforce, ServiceNow and Workday. "Services businesses aren't inefficient by accident. They're inefficient by design." The authors call AI roll-ups "tech-enabled private equity: operationally heavy, valuation-capped" — [Air Street Press](https://press.airstreet.com/p/ai-rollup-mirage-technology-2025); [Fortune original](https://fortune.com/2025/06/27/ai-rollup-investment-strategy/)
- [2026-06-03] Since December 2024 the S&P 500 is up about 30% while the WisdomTree Cloud Computing ETF (WCLD) is down about 15% (vendor framing) — [Sierra](https://sierra.ai/blog/outcomemaxxing). [2026-02/03] The "SaaSpocalypse" sell-off followed Anthropic's Claude Cowork plugins and was fed by fear that agents would cut per-seat licences; reportedly the worst stretch for the IGV software ETF since 2008 (search excerpt) — [TechCrunch](https://techcrunch.com/2026/03/01/saas-in-saas-out-heres-whats-driving-the-saaspocalypse/)

#### Services revenue share and the path to software leverage
- ServiceNow and Workday rose from 63.2% and 54.1% gross margin at IPO to 79% and 75% in 2024. Ecosystems "can be powerful tools for scalability and margin protection" — [a16z](https://a16z.com/services-led-growth/)
- Palantir's contribution margin went from 21% to 48% (2019 to H1 2020); sales and marketing fell from 62.6% of revenue (2020) to 24.3% (2025) — [Palantir S-1](https://www.sec.gov/Archives/edgar/data/1321655/000119312520230013/d904406ds1.htm); [N47](https://www.n47.com/insights/the-forward-deployed-engineer-dilemma)
- Older SaaS precedent (2014 analysis): Veeva, Workday and others drew 20% or more of revenue from professional services (pre-2024, search excerpt) — [Tom Tunguz](https://www.tomtunguz.com/professional_services/index.md)

### Inferences
- "Outcome selling" covers two economically different businesses.
  - (a) **Outcome-priced AI software** (Sierra, Fin, Zendesk AI). Gross margin starts low or negative because of inference and deployment costs, but can rise toward software levels as automation rates rise, because every gain in resolution rate lifts both revenue and margin. Markets have paid software-plus multiples for it.
  - (b) **AI-enabled services and roll-ups** that own human delivery. Margins are anchored to services (10–15% EBITDA for BPOs, 30–40% gross for services). The upside rests on investor targets, and public comparables such as Concentrix suggest AI adoption has not re-rated services multiples.
- The Fin sale (about $3.6B on more than $400M of total ARR, roughly 9x; inference from unverified ARR) against Sierra (about 37–100x) suggests acquirers paid far less for an incumbent seat-plus-outcome business than private investors paid for a pure outcome-priced AI-native one. That is consistent with a growth premium, not proof of a "pricing model premium".
- Riskified's roughly 50% gross margin shows what happens when an outcome model carries real liability: the losses it guarantees land in cost of revenue, and margins stay well below SaaS.

### Gaps
- No dataset isolates gross margins, services revenue share or multiples for AI-native services firms (Crosby, EvenUp, GC portfolio companies) in 2024–2026. Investor targets are not audited.
- Fin's gross margin today and Sierra's gross margin are undisclosed.
- I found no systematic data on AI roll-up exit multiples.
- I skipped a LinkedIn claim that Accenture paid about 16x revenue for an AI consultancy as unverifiable.

## 5. Failure modes: margin compression, scaling limits, disputes over outcomes, liability, customer concentration, lower valuations, procurement resistance, and retreats from outcome pricing

### Takeaway
Every failure mode named in the brief is documented, mostly in 2025–2026:
- negative launch margins (Fin) and supernova margins "often negative"
- disputes over what counts as resolved (Intercom's forum, Decagon, Futurum's "grading its own homework")
- legal liability for what an AI agent says (Air Canada)
- quality reversals (Klarna)
- "AI" that was mostly people (Builder.ai; allegations about EvenUp)
- procurement and CFO pushback
- high project-abandonment forecasts (Gartner)
- one clear retreat: Salesforce, from per-conversation to seats and flat deals.

### Cited Findings

#### Margin compression and cost risk
- Fin was margin-negative at launch, carries "all of the LLM cost risk", and its costs scale with conversations, not resolutions [2026-05-18] — [Chargebee/Fin](https://www.chargebee.com/blog/how-fin-is-rebuilding-fpa-for-outcome-based-ai/)
- Supernova margins are "often stretched close to zero or even negative" [2025-08-13] — [Bessemer](https://www.bvp.com/atlas/the-state-of-ai-2025)
- Salesforce's CRO on flat AELAs [2025-12-15]: "We take the risk because we want our customers to be successful." "If that is not profitable for me, it means that the customer is the happiest customer in the world... And then I have another 20 years to monetize that customer." — [The Register](https://www.theregister.com/2025/12/15/salesforce_ai_monetization/)
- [2025-09-28] Stanford Social Media Lab and BetterUp Labs surveyed 1,150 employees about "workslop". About 40% absorb it, at nearly two hours per instance and an "invisible tax of $186 per month per person". Cutting staff to capture AI gains leaves fewer people to catch AI errors; keeping them may erase the margin gains — [TechCrunch](https://techcrunch.com/2025/09/28/the-ai-services-transformation-may-be-harder-than-vcs-think/)
- [2026-07, G2 survey] "46% of agent buyers report higher-than-expected operating costs". 45% say oversight and rework consume more than a quarter of the expected productivity gains — [SaaStr on G2 2026](https://saastr.com/g2s-2026-ai-agents-report-only-9-of-buyers-think-seat-pricing-is-fair-57-want-usage-based-and-74-will-shop-you-at-renewal)

#### Disputes over what counts as an outcome
- [2025-01-22] A Fin customer on assumed resolutions being billed when a human stepped in: "this is the opposite of customer-friendliness"; "Fin is designed like this because Intercom assumes the worst of their customers." Intercom staff replied [2025-05-18]: "The current model rewards Fin doing well." The thread ends with no confirmed change — [Intercom Community](https://community.intercom.com/ask-the-intercom-team-about-fin-54/fin-s-flawed-assumed-resolved-pricing-design-8929)
- [2024-12-10] Decagon: "If a frustrated customer stops responding, does that count as 'resolved'?" — [Decagon](https://decagon.ai/blog/pricing-ai-agents)
- [2025-08-13] BCG: "The primary barrier is that vendors and customers struggle to agree on what constitutes a completed job or outcome." BCG cites an a16z survey: 47% of buyers struggle to define measurable outcomes, 36% worry about cost predictability, 25% have trouble with attribution, and 24% say outcomes depend on factors outside the vendor's control. I could not locate the original a16z survey — [BCG](https://www.bcg.com/publications/2025/rethinking-b2b-software-pricing-in-the-era-of-ai)
- [2026-08-10] Bain: outcomes must be "observable, uniquely attributable to the AI, and contractible". "Marketing attribution is often disputed". Outcome deals are "complex and time-consuming to negotiate, and difficult to bill at scale" — [Bain](https://www.bain.com/insights/ai-pricing-a-reality-check-on-effort-usage-and-outcomes/)
- [2026-10-02] Contact-centre vendors don't agree on basic KPIs such as what counts as a resolution, which makes RFP comparisons hard — [TechTarget](https://www.techtarget.com/it-strategy/news/366651390/Outcomes-based-AI-pricing-works-in-theory-but-in-practice)
- [2026-11-12] On Zendesk Unlimited: "the vendor is grading its own homework". "Successfully addressed" leaves room for dispute, for example a customer who comes back through another channel — [Futurum](https://futurumgroup.com/?p=97869)

#### Liability for bad outcomes
- [2024-02-14] In Moffatt v. Air Canada, a BC tribunal found negligent misrepresentation over refund advice the airline's chatbot invented. It rejected Air Canada's argument that the chatbot was a "separate legal entity". The award was about C$650.88 plus interest and fees (reported amounts vary) — [ABA Business Law Today](https://www.americanbar.org/groups/business%5Flaw/resources/business-law-today/2024-february/bc-tribunal-confirms-companies-remain-liable-information-provided-ai-chatbot/); [CBS News](https://www.cbsnews.com/news/aircanada-chatbot-discount-customer)
- [2025-04] Cursor's AI support bot "Sam" invented a one-device login policy; users publicly cancelled subscriptions. The co-founder called it an "incorrect response from a front-line AI support bot" — [AI Incident Database](https://incidentdatabase.ai/cite/1039/)
- [2025] Lloyd's coverholder Armilla launched affirmative AI liability cover for chatbot and agent errors; coverage depends on wording and exclusions (search excerpt) — [PYMNTS](https://www.pymnts.com/artificial-intelligence-2/2025/insurers-begin-covering-ai-mishap-related-losses/); [GARP, 2025-10-10](https://www.garp.org/risk-intelligence/operational/chatbots-awry-insurance-251010)
- [2025-11-12] Riskified's Chargeback Guarantee puts fraud losses on the vendor's own P&L — [Riskified](https://ir.riskified.com/news-releases/news-release-details/riskifieds-third-quarter-results-reflect-accelerated-gross)

#### Quality reversals and humans behind the "AI"
- [2025-05-09] Klarna had claimed in Feb 2024 that AI "could do the work of 700 customer service agents". It is now recruiting humans again after AI produced "lower quality" output; the CEO said "Really, investing in the quality of human support is the way of the future for us." — [Entrepreneur](https://www.entrepreneur.com/business-news/klarna-ceo-reverses-course-by-hiring-more-humans-not-ai/491396)
- [2025-12-12] Forrester: 55% of employers regret AI-related layoffs — [The Register](https://www.theregister.com/2025/12/12/ai_agents_salesforce_pricing/)
- [2025-05-20/21] Builder.ai entered insolvency after reports that much of its "AI" work was done by hundreds of engineers. Revenue-inflation figures differ across reports; Bloomberg's figures (via secondary sources) were about $50M actual against $220M claimed — [TechCrunch](https://techcrunch.com/2025/05/20/once-worth-over-1b-microsoft-backed-builder-ai-is-running-out-of-money); [The Register](https://www.theregister.com/2025/05/21/builderai_insolvency/)
- EvenUp: Business Insider reported former employees saying humans did much of the demand-letter work and that the process was error-prone. EvenUp says it combines AI with expert review (BI original not retrieved; date unconfirmed; search excerpt) — [EvenUp blog response](https://www.evenuplaw.com/blog/leveraging-ai-human-review-in-demand-letters-the-evenup-difference)
- [2024-12-27] Bench, a tech-enabled bookkeeping service that had raised $113M and had 35,000+ US customers, shut down abruptly, leaving customers without access to their books before tax season. Employer.com then acquired it — [TechCrunch](https://techcrunch.com/2024/12/27/bench-shuts-down-leaving-thousands-of-businesses-without-access-to-accounting-and-tax-docs)

#### Scaling limits and project failure rates
- [2025-06-25] Gartner: more than 40% of agentic AI projects will be cancelled by the end of 2027 because of escalating costs, unclear business value or weak risk controls. Only about 130 of thousands of "agentic" vendors are genuine ("agent washing") — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027)
- [2026-10-01] Gartner: about 70% of vendor-led AI engineering efforts will be abandoned by 2028 — [CIO Dive](https://www.ciodive.com/news/can-forward-deployed-engineers-fdes-fix-ai-gartner/831833/)
- [2025-08] MIT NANDA: "Just 5% of integrated AI pilots are extracting millions in value". But purchased vendor tools succeed about two-thirds of the time, against one-third for internal builds. The sample is small and outlets describe the methodology inconsistently — [The Register](https://www.theregister.com/2025/08/18/generative_ai_zero_return_95_percent)
- Drift into consulting and linear headcount growth — [N47](https://www.n47.com/insights/the-forward-deployed-engineer-dilemma)
- "operationally heavy, valuation-capped" — [Air Street](https://press.airstreet.com/p/ai-rollup-mirage-technology-2025)

#### Customer concentration and contract durability
- Palantir's FDE-led model: top 20 customers were 67% of 2019 revenue, and it had 125 customers after 17 years (historical) — [Palantir S-1](https://www.sec.gov/Archives/edgar/data/1321655/000119312520230013/d904406ds1.htm); [TechCrunch](https://techcrunch.com/2020/08/21/leaked-palantir-s-1-shows-company-has-125-customers-after-17-years/)
- Services contracts have shrunk from 10-year terms to three years or less [2025-06-27] — [Air Street](https://press.airstreet.com/p/ai-rollup-mirage-technology-2025)
- Analyst advice to buyers: "I think it's wise not to get roped into anything longer than six to 12 months." [2026-10-02] — [TechTarget](https://www.techtarget.com/it-strategy/news/366651390/Outcomes-based-AI-pricing-works-in-theory-but-in-practice)
- 74% of buyers will shop alternatives at renewal [2026-07] — [SaaStr/G2](https://saastr.com/g2s-2026-ai-agents-report-only-9-of-buyers-think-seat-pricing-is-fair-57-want-usage-based-and-74-will-shop-you-at-renewal)

#### Lower valuations
- Services multiples and Concentrix comparables (above) — [Air Street](https://press.airstreet.com/p/ai-rollup-mirage-technology-2025)
- Counter-evidence: Sierra at roughly 100x ARR [2025-11-21] — [TechCrunch](https://techcrunch.com/2025/11/21/bret-taylors-sierra-reaches-100m-arr-in-under-two-years/)

#### Procurement resistance
- [2026-10-02]:
  - NiCE: "Procurement and finance want certainty. They want to be able to forecast against it."
  - Perficient: "most business sponsors who own a solution are pro outcomes-based, but we do get constant pushback from procurement"
  - Perficient: some customers tried outcome deals before agentic AI and "the outcomes never came."
  - CFOs resist sharing savings with a vendor.
  - — [TechTarget](https://www.techtarget.com/it-strategy/news/366651390/Outcomes-based-AI-pricing-works-in-theory-but-in-practice)
- [2026-08-10] "Procurement teams and CFOs can approve a defined commitment more easily" than open-ended variable spend — [Bain](https://www.bain.com/insights/ai-pricing-a-reality-check-on-effort-usage-and-outcomes/)
- [2025-12-12] Gartner's Jan Cook: "Customers still adopt a cautious approach to investing in GenAI because of the unpredictability of pricing models" — [The Register](https://www.theregister.com/2025/12/12/ai_agents_salesforce_pricing/)
- [2026-08-31] Seton Hall's CIO: outcome billing "adds complication to contract negotiation as you need to be very specific on what the desired outcomes are"; Gartner's Coshow: "If the vendor isn't taking on the risk, why are you bothering with outcome-based pricing?" — [CIO Dive](https://www.ciodive.com/news/agentic-ai-outcome-pricing-models/829023/)

#### Retreats from outcome or usage pricing
- Salesforce went from $2 per conversation (2024) to $0.10 per action plus per-user licences (May 2025), then to flat AELAs and seat-based "with caveats" (Oct–Dec 2025), keeping outcome pricing for one agent (2026) — [Salesforce](https://www.salesforce.com/blog/flex-credits/); [The Register](https://www.theregister.com/2025/12/12/ai_agents_salesforce_pricing/); [TechTarget](https://www.techtarget.com/it-strategy/news/366651390/Outcomes-based-AI-pricing-works-in-theory-but-in-practice)
- Commentators describe Salesforce's move as a return to seat-based licensing driven by predictability (opinion, search excerpt) — [Zuora](https://www.zuora.com/subscribed/usage-versus-seats-has-the-pricing-pendulum-swung-back)
- Atlassian reportedly re-bundled a separately priced AI add-on into enterprise subscriptions. That is an add-on rollback, not an outcome-pricing rollback (search excerpt) — [Verdantix](https://www.verdantix.com/insights/blog/five-reasons-why-saas-ai-pricing-rollouts-are-consistently-missing-the-mark)
- I found no documented case of a vendor dropping per-outcome pricing outright. Intercom, HubSpot and Zendesk moved toward it in 2026 (§1).

### Inferences

#### Where the thesis fails, point by point
1. **Outside customer support, attribution breaks down.** The thesis assumes outcomes can be measured and attributed. That holds where Sequoia's "graceful failure mode" exists. Elsewhere outcomes depend on things the vendor doesn't control: marketing attribution, renewals, HR, macro conditions (BCG, Bain, FC). Outside customer support, outcome pricing turns into task or output pricing, or into negotiated KPIs.
2. **The vendor carries cost and performance risk before it learns to deliver.** Inference costs arrive per attempt; revenue arrives per success. Fin was margin-negative at a 30s% resolution rate. Sierra says misses hit "attrition and margin". This only works if the vendor's success rate improves faster than its cost per attempt falls.
3. **The vendor defines and grades its own outcomes.** That breeds disputes (Intercom's assumed resolutions, Futurum on Zendesk), and buyers ask for dashboards, caps and audit trails (G2, Futurum). Vendors respond by broadening outcome types and adding AI verifiers, which shifts the product toward output pricing (Bain).
4. **Buyers' finance and procurement functions want fixed commitments.** Business sponsors like outcome deals; procurement and CFOs push back (Perficient, NiCE, Bain). The market's answer is prepaid outcome budgets and flat licences (Salesforce's AELA, Zendesk's Outcome Budget, Fin's buckets). The thesis survives as marketing; in procurement terms it is a capacity commitment.
5. **Owning the work means owning the liability.** Air Canada shows deployers are liable for what agents say. An outcome seller that sells the finished work (legal, accounting, claims) inherits professional liability and needs insurance (Armilla). The audited guarantee model (Riskified) runs about 50% gross margin.
6. **"AI services" may still be human services.** Builder.ai, the EvenUp allegations and Klarna's reversal show the human share can stay high. "Workslop" shows that cutting staff can raise error costs. Margins and multiples then stay services-like (Concentrix, BPO comparables).
7. **Scaling is limited by FDE cost and talent.** Gartner counts about 2,000 FDEs against four times the demand, with fees above $200K per quarter per use case. That forces large contracts, few customers (the Palantir pattern) and slow leverage. The labs now compete for the same deployment work.
8. **The valuation premium attaches to growth, not to outcome pricing.** Sierra's premium coexists with roll-up skepticism, and the Fin sale came in at roughly 9x reported ARR. Services multiples are low "for a reason" (Air Street).

### Gaps
- No public data on dispute rates, credits issued or churn caused by outcome definitions.
- A search summary attributed to Gartner the line that time-and-materials billing for FDE work "depresses valuations and creates a headcount trap". I could not tell which Gartner abstract carries it, so it is left out of the findings.
- No court case yet on an outcome-priced AI vendor's contractual liability, as distinct from the deployer's.
- No named 2026 AI roll-up has publicly reported margin shortfalls; the negative evidence is analyst opinion.
- I did not retrieve the original Business Insider article on EvenUp.

## 6. What buyers say: surveys and reports on how companies want to pay for AI (seats, usage, outcomes) in 2025 and 2026

### Takeaway
About one buyer in five prefers outcome-based pricing, and the share is rising slowly: 11% to 19% (G2) and 18% to 23% of vendors (ICONIQ). Actual adoption of pure outcome pricing is far smaller, about 5–10% of vendors (Poyar 5%, Bain about 10%, AlixPartners 4 of 65). Buyers' strongest stated need is predictability. They reject seats for core software but, when AI is billed separately, many want seats back (Futurum 2H 2026: 42.3% per-seat). They want spend caps and dashboards before they accept variable bills.

### Cited Findings

#### Buyer surveys
- [2025-10-17] Futurum's 1H 2025 decision-maker survey: consumption 38%, outcome-based 31%, per-user per-month 20%, included in core 11%. In 2024 more than half preferred consumption. Sample size not stated; question wording across years not confirmed — [Futurum](https://futurumgroup.com/press-release/enterprise-software-buyers-prefer-consumption-and-outcome-based-pricing/)
- [2026-08] Futurum's 2H 2026 survey, among buyers who rank pricing as a top criterion:
  - Core software: per-seat came last at 12.6%, behind consumption (28.9%) and outcome-based (22.2%). (search excerpt)
  - GenAI billed separately: per-seat 42.3%, consumption 36.6%, outcome-based 21.1%. (confirmed in Futurum's Nov 2026 Zendesk note)
  - Only 11.2% say their preferred vendor offers outcome pricing today.
  - Sample size not confirmed.
  - — [Futurum insight](https://futurumgroup.com/insights/the-pricing-split-why-core-software-and-ai-cant-share-one-commercial-model/); [Futurum on Zendesk](https://futurumgroup.com/?p=97869)
- [2026-07 survey of 1,019 B2B decision-makers] G2:
  - "9% of buyers consider per-user or per-seat pricing the fairest model for agent services."
  - Pay-as-you-go (including per completed action or task) rose from 38% to 57%; pay-per-outcome from 11% to 19%; fixed pricing fell from 35% to 21%.
  - Controls buyers want before accepting variable spend: real-time usage dashboards and monthly spend caps first, cost-per-outcome reporting third.
  - (G2 is a vendor; reported via SaaStr) — [SaaStr](https://saastr.com/g2s-2026-ai-agents-report-only-9-of-buyers-think-seat-pricing-is-fair-57-want-usage-based-and-74-will-shop-you-at-renewal)
- [2025-08-13] BCG: "40% of buyers cite seat reduction as their primary lever to decrease software spending"; "91% expressed interest only in partially autonomous agents"; outcome pricing "remains among the least popular approaches." ICONIQ 2025 found 68% of vendors charge separately for AI — [BCG](https://www.bcg.com/publications/2025/rethinking-b2b-software-pricing-in-the-era-of-ai)
- [2026-08-31] Gartner: 19% of services buyers and 13% of seller-side service agreements use outcome-based arrangements today. Fewer than 25% of tech services contracts will use outcome pricing through 2031. "Right now, what we see is that the increase in outcome-based pricing is more buzz than reality." — [CIO Dive](https://www.ciodive.com/news/agentic-ai-outcome-pricing-models/829023/)

#### Vendor-side adoption (what is actually sold)
- [2025-06-04] Kyle Poyar, survey of 240+ companies, mostly $1–20M ARR:
  - Flat fee fell from 29% to 22%; seat-based from 21% to 15%; hybrid rose from 27% to 41%.
  - "Outcome-based pricing is seen as the 'holy grail'. It's still out of reach for 95% of the market."
  - 5% use outcome pricing as their primary model and 25% expect to by 2028 (search excerpt).
  - — [Growth Unhinged 2025](https://kylepoyar.substack.com/p/2025-state-of-b2b-monetization)
- [2026-05-13] Kyle Poyar, 230+ companies:
  - "37% have hybrid pricing", up from 25%. This conflicts with the 2025 report's 41%; the definitions or samples probably differ.
  - "29% let customers choose between multiple pricing models", up from 21%.
  - Investors prefer hybrid (35%), outcome-based (26%), usage-based (24%), flat fee (10%) and seats (5%).
  - AI credits are used by 29%, and 33% plan to add them.
  - (the newsletter is sponsored by Metronome, a Stripe product) — [Growth Unhinged 2026](https://www.growthunhinged.com/p/the-state-of-b2b-monetization-in-2026)
- [2026-07] ICONIQ: consumption pricing rose from 35% to 42% and outcome-based from 18% to 23% in six months; companies blend 1.7 pricing models on average — [ICONIQ](https://www.iconiq.com/growth/reports/state-of-ai-2026)
- [2026-08-10] Bain: about one in five AI-native companies still relies mostly on seats. Among the rest: effort-based about 35%, output-based about 55%, outcome-based about 10%. About four in five vendors choose capacity models — [Bain](https://www.bain.com/insights/ai-pricing-a-reality-check-on-effort-usage-and-outcomes/)
- [2026-07-29] AlixPartners: "only 4 of the 65 have fully adopted outcome-based pricing"; "of the remaining 61, more than half still rely primarily on per-seat models"; "72% have a hybrid approach"; "for 82% of companies, customers take the punishment if the software doesn't deliver." "Moving to outcome-based pricing too early risks cannibalizing per-seat revenue." — [AlixPartners](https://www.alixpartners.com/insights/102nf2s/outcome-based-software-pricing-hype-or-reality/)
- [2025-08-06] Metronome: "Truly outcome-based pricing remains rare"; "many enterprise buyers are still uncomfortable with tying spend directly to outputs"; "Predictability, not price point, drives enterprise adoption." — [Metronome](https://metronome.com/blog/ai-pricing-in-practice-2025-field-report-from-leading-saas-teams)

#### Buyer and analyst quotes
- [2025-12-15] Salesforce's CRO: most customers prefer to pre-commit spending — [The Register](https://www.theregister.com/2025/12/15/salesforce_ai_monetization/)
- [2025-12-12] Forrester's Lisa Singer: "Copilots will continue as seat-based since their usage is tied to humans" — [The Register](https://www.theregister.com/2025/12/12/ai_agents_salesforce_pricing/)
- [2026-10-02] A Salesforce customer (DCS) "hasn't yet considered" outcome pricing and manages token costs itself; its integrator says outcome pricing is "emerging in negotiations" — [TechTarget](https://www.techtarget.com/it-strategy/news/366651390/Outcomes-based-AI-pricing-works-in-theory-but-in-practice)

### Inferences
- Stated preference for outcome pricing (about 19–31% depending on survey and year) runs far ahead of what vendors actually sell (about 5–10%). Even buyers who like it want it inside caps and commitments. That makes outcome-denominated prepaid budgets the likely settlement, not open-ended pay-per-result.
- Buyers treat AI and core software differently. They want to stop paying for seats on core software (seat counts are their main cost lever), but want predictable, seat-like prices for AI add-ons. Sellers of "finished work" should expect buyers to want a fixed price for a defined scope of work, not a variable bill per result.
- Within the buyer, business owners favour outcome deals and procurement and CFOs resist them. Outcome sales therefore tend to need executive sponsorship, short terms (six to 12 months), and audit rights over how outcomes are defined.

### Gaps
- No 2025–2026 survey asks buyers how they want to pay AI-native services firms for finished professional work (legal, accounting, claims) rather than software. The surveys above are about software and agents.
- Several surveys are vendor-run or vendor-sponsored (G2; Growth Unhinged, sponsored by Metronome), or omit sample sizes (Futurum 2025, BCG). Wording differs, so the numbers are not comparable across surveys.
- The a16z buyer survey cited by BCG (the 47% figure) could not be located.
- The McKinsey "AI price is right" chart timed out and was not used.
- **Skipped as paywalled or blocked:** Financial Times (FDE postings), Bloomberg (Klarna, SaaSpocalypse, Builder.ai), The Information, the WSJ and Business Insider originals, the paywalled full Growth Unhinged reports, and Sacra's full profiles (used only at snippet level, labeled).
- **Not consulted, for time:** OpenView's archived research (pre-2024), and Orb and Stripe reports beyond their titles.
