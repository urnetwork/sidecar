# Agent and LLM observability platforms: who can read the traces (state as of 26 November 2026)

Scope note: covers tracing, evaluation and monitoring platforms for LLM apps and agents. Coding-harness built-ins, GitHub Agent HQ, Microsoft Agent 365 and agent work-record tools (Entire, git-ai, SpecStory) were covered on 31 Oct 2026 and are not repeated. Pages without their own date are marked "fetched 26 Nov 2026". GitHub star counts were read from the GitHub API on 26 Nov 2026. Encryption terms are kept apart: **TLS + at-rest with vendor-held keys** / **customer-managed keys (CMK)** / **self-hosted, BYOC or hybrid deployment** / **TEE** / **client-side or end-to-end encryption (E2EE)**. "BYOK" in this market often means *bring your own LLM API key* for evals, not encryption keys, and is flagged where that applies.

## 1. Which platforms lead in late 2026, and what adoption evidence exists?

### Takeaway
2026 was a year of consolidation. Six of the platforms in scope now belong to larger companies: Langfuse (ClickHouse, Jan 2026), Traceloop (ServiceNow, Mar 2026), Helicone (Mintlify, Mar 2026, then in maintenance mode; its site now says "part of Experiential Labs"), Galileo (Cisco/Splunk, closed May 2026), Arize (Dynatrace, about $915M, announced Aug 2026, closed by Oct 2026) and Weights & Biases Weave (CoreWeave, now sold inside "CoreWeave Forge"). The independent leaders are LangChain/LangSmith (raised $300M at a $3B valuation on 13 Nov 2026 and says more than 7,000 organizations use LangSmith) and Braintrust ($80M Series B at $800M, Feb 2026). Langfuse is the open-source adoption leader (37.9k GitHub stars; it claims 21 of the Fortune 50 as users).

### Cited Findings
**Independent leaders**
- LangChain (LangSmith) announced a $300M Series C at a $3B valuation on 13 Nov 2026, led by existing investor CapitalG: "More than 7,000 organizations already rely on LangSmith". Named customers include Harvey, Rippling, Listen Labs, NVIDIA, Toyota, Salesforce, Clay and Workday — [LangChain Series C post](https://www.langchain.com/blog/series-c)
- Earlier rounds: a $125M Series B at a $1.25B valuation led by IVP (20 Oct 2025) — [SiliconANGLE](https://siliconangle.com/2025/10/20/ai-agent-tooling-provider-langchain-raises-125m-1-25b-valuation). Annual recurring revenue (ARR) was reported at $12–16M in mid-2025, citing four sources (older figure) — [TechCrunch, 8 Jul 2025](https://techcrunch.com/2025/07/08/langchain-is-about-to-become-a-unicorn-sources-say)
- The LangSmith page's logo wall (fetched 26 Nov 2026) shows Vanta, Clay, Rippling, Lyft, Harvey, Abridge, Expedia, Autodesk, Bristol Myers Squibb, Workday, Cisco, Mercor, "NU", monday.com, Nvidia, Bridgewater, ServiceNow, Coinbase, Rakuten, Elastic, Uber and others — [LangSmith page](https://www.langchain.com/langsmith)
- Braintrust raised an $80M Series B at an $800M post-money valuation (17 Feb 2026), led by ICONIQ with a16z, Greylock, basecase and Elad Gil — [SiliconANGLE](https://siliconangle.com/2026/02/17/braintrust-lands-80m-series-b-funding-round-become-observability-layer-ai); [Axios Pro](https://www.axios.com/pro/enterprise-software-deals/2026/02/17/ai-observability-braintrust-80-million-800-million). Customers named on its homepage (fetched 26 Nov 2026): Notion, Replit, Cloudflare, Box, Retool, Graphite, Pylon, Coursera — [braintrust.dev](https://www.braintrust.dev/)

**Acquired in 2025–2026**
- ClickHouse announced it was acquiring Langfuse on 16 Jan 2026, alongside a $400M ClickHouse funding round. Langfuse "remains 100% open-source under its existing MIT license for core features", and Langfuse Cloud keeps running as a standalone service — [Langfuse blog](https://langfuse.com/blog/joining-clickhouse); [SiliconANGLE](https://siliconangle.com/?p=728064); [Orrick](https://www.orrick.com/en/news/2026/01/open-source-llm-observability-langfuse-acquired-by-clickhouse-inc). One outlet gives a $15B valuation; I found that figure in only one source — [WebProNews](https://www.webpronews.com/clickhouse-acquires-langfuse-raises-400m-at-15b-valuation-for-ai-push)
- Langfuse's self-reported adoption (fetched 26 Nov 2026): "21 of the Fortune 50", "65M+ SDK installs per month", "50,000+ companies", more than 100,000 engineers, and over 110 billion observations a month — [langfuse.com](https://langfuse.com/). The GitHub repo has 37,898 stars — [GitHub](https://github.com/langfuse/langfuse)
- Dynatrace agreed to buy Arize for about $915M: roughly $815M in cash plus replacement equity awards. The deal was announced 13 Aug 2026 — [Dynatrace press release](https://www.dynatrace.com/news/press-release/dynatrace-to-acquire-arize/); [HPCwire](https://www.hpcwire.com/bigdatawire/this-just-in/dynatrace-to-acquire-ai-observability-leader-arize/). A Dynatrace post dated 1 Oct 2026 says the acquisition is complete: "Phoenix remains available as an open-source project", and Arize AX continues as a standalone offering — [Dynatrace blog](https://dynatrace.com/news/blog/dynatrace-completes-acquisition-of-arize)
- Arize's previous round was a $70M Series C in Feb 2025 — [TechCrunch](https://techcrunch.com/2025/02/20/arize-ai-hopes-it-has-first-mover-advantage-in-ai-observability). Named customers include Booking.com (case study 17 Aug 2026), Tripadvisor, LG Uplus and Handshake — [Arize customers](https://arize.com/customers). Phoenix has 12,446 GitHub stars — [GitHub](https://github.com/Arize-ai/phoenix)
- Cisco announced its intent to acquire Galileo on 9 Apr 2026. An update dated 22 May 2026 says the deal is complete; no price was disclosed. Galileo will feed "AI Agent Monitoring capabilities in Splunk Observability Cloud" — [Cisco blog](https://blogs.cisco.com/news/cisco-announces-the-intent-to-acquire-galileo). galileo.ai/pricing now redirects (301) to Splunk's pricing page — [Splunk pricing](https://www.splunk.com/en_us/products/pricing.html#agent-observability); [Splunk Galileo page](https://www.splunk.com/en_us/about-splunk/acquisitions/galileo.html)
- ServiceNow acquired Traceloop, the company behind OpenLLMetry. CB Insights dates the deal 2 Mar 2026 — [CB Insights](https://www.cbinsights.com/company/servicenow/financials). The price was reported, not disclosed, at $60–80M — [AI Market Watch](https://www.ai-market-watch.com/news/servicenow-buys-traceloop-in-60-80-million-deal-it); [Calcalist](https://www.calcalistech.com/ctechnews/article/sjghwiqf11e). Traceloop's site now carries the banner "Traceloop is joining Service now!", and its demo and contact links go to servicenow.com — [Traceloop pricing](https://www.traceloop.com/pricing). OpenLLMetry has 7,557 stars and an Apache-2.0 license — [GitHub](https://github.com/traceloop/openllmetry)
- Mintlify announced on 3 Mar 2026 that it was acquiring Helicone: "Helicone will continue operating in maintenance mode—security updates, bug fixes, and new models will keep shipping." Mintlify will help customers migrate "to another platform" — [Mintlify](https://www.mintlify.com/blog/mintlify-acquires-helicone). On 26 Nov 2026 helicone.ai said "Helicone is now part of Experiential Labs… Details to come soon," with no date — [helicone.ai](https://www.helicone.ai/). Experiential Labs is a YC Summer 2026 company. Per a search summary of its YC profile, it has a 2-person team — [YC](https://www.ycombinator.com/companies/experiential-labs). Helicone has 6,293 GitHub stars — [GitHub](https://github.com/Helicone/helicone)
- Weights & Biases is now "a CoreWeave company" — [CoreWeave](https://www.coreweave.com/companies/weights-and-biases). wandb.ai/site/pricing redirects to "CoreWeave Forge Pricing", which lists Weave as a feature — [CoreWeave Forge pricing](https://www.coreweave.com/forge-pricing). Forge combines W&B Models, OpenPipe post-training and marimo — [CoreWeave news](https://coreweave.com/news/coreweave-forge-launches-turning-the-ai-loop-production-run-into-a-better-model-and-agent). The weave repo has 1,151 stars — [GitHub](https://github.com/wandb/weave)
- In Aug 2025 Anthropic hired the Humanloop team, an earlier prompt and eval platform (older event) — [TechCrunch](https://techcrunch.com/2025/08/13/anthropic-nabs-humanloop-team-as-competition-for-enterprise-ai-talent-heats-up)

**Other platforms in scope**
- Comet Opik has 23,517 stars (Apache-2.0); MLflow, which includes GenAI tracing, has 28,985 stars — [Opik](https://github.com/comet-ml/opik); [MLflow](https://github.com/mlflow/mlflow)
- Pydantic Logfire's SDK has 4,570 stars (MIT) — [GitHub](https://github.com/pydantic/logfire). Pydantic's latest disclosed round is a $12.5M Series A led by Sequoia (Oct 2024, older) — [Pydantic](https://pydantic.dev/articles/logfire-announcement)
- Laminar raised a $3M seed (17 Mar 2026). Its Agent Debugger reruns an agent from any step — [Tech.eu](https://tech.eu/2026/03/17/agent-debugging-startup-laminar-raises-3m-seed-to-tackle-the-observability-gap-in-ai-agents/). It has 3,526 stars (Apache-2.0) — [GitHub](https://github.com/lmnr-ai/lmnr). Browser Use is its named customer ("We run millions of agent sessions in our cloud") — [laminar.sh](https://laminar.sh/)
- AgentOps has 5,976 stars (MIT); its last push was 25 Jun 2026 — [GitHub](https://github.com/AgentOps-AI/agentops). Its homepage shows logos including Microsoft, Samsung, Google, Meta, Deloitte and Fidelity, without saying whether they are paying customers. The footer reads "2025", and the only funding item is a $2.6M round (2024) — [agentops.ai](https://www.agentops.ai/)
- HoneyHive names Commonwealth Bank of Australia: 17M retail consumers and 55K internal users served by agents in production — [honeyhive.ai](https://www.honeyhive.ai/)
- OpenAI's Agents SDK docs list 31 external tracing processors, including W&B, Phoenix, MLflow, Braintrust, Logfire, AgentOps, LangSmith, Opik, Langfuse, Galileo, Portkey, HoneyHive, Datadog and Laminar. This is a rough proxy for which vendors matter — [OpenAI Agents SDK tracing](https://openai.github.io/openai-agents-python/tracing/)

**Entrants and adjacent 2026 rounds that matter**
- Raindrop ("Sentry for AI agents") raised a Series A led by CRV, bringing total funding to $50M. Reported round sizes vary between $22.6M and $35M — [The Next Web](https://thenextweb.com/news/raindrop-series-a-50m-crv-agent-failures-simulations); [Lightspeed](https://lsvp.com/stories/production-monitoring-for-an-increasingly-agentic-world-announcing-raindrops-series-a/)
- Tsuga raised a $35M Series A (23 Jun 2026) for observability that "deploys inside the customer's environment"; the article says "the data never leaves the customer's perimeter" — [The Next Web](https://thenextweb.com/news/tsuga-35-million-series-a-observability)
- Fiddler raised a $30M Series C in Jan 2026 — [IT Brief](https://itbrief.news/story/fiddler-raises-30m-series-c-to-power-the-control-plane-for-ai-agents). Dash0 raised $110M at a $1B valuation in Mar 2026 — [SiliconANGLE](https://siliconangle.com/2026/03/23/dash0-raises-110m-1b-valuation-change-cloud-observability-ai-agents). Respan (formerly Keywords AI) raised a $5M seed — [Pulse 2.0](https://pulse2.com/respan-5-million-raised-for-ai-observability-platform-to-improve-agent-performance/amp/)
- Other open-source eval and tracing repos, by GitHub stars: DeepEval (Confident AI) 19,694; Portkey gateway 13,455; LangWatch 5,055; Agenta 4,941; OpenLIT 3,105 — [DeepEval](https://github.com/confident-ai/deepeval); [Portkey](https://github.com/Portkey-AI/gateway); [LangWatch](https://github.com/langwatch/langwatch); [Agenta](https://github.com/Agenta-AI/agenta); [OpenLIT](https://github.com/openlit/openlit)
- Cloud-native option: since 23 Jul 2026, all of an AWS Bedrock AgentCore agent's telemetry, including traces and prompts, goes to one per-agent CloudWatch log group in the customer's own AWS account — [AWS What's New](https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-bedrock-agentcore-unified-observability-single-log-group/)

### Inferences
- Buyers increasingly get agent observability as a feature of a larger platform: an APM suite (Datadog, Dynatrace/Arize, Splunk/Galileo, Sentry), a data platform (ClickHouse/Langfuse, Databricks/MLflow) or an ITSM/governance suite (ServiceNow/Traceloop). That widens the set of companies, and staff, who sit in the data path of trace content.
- LangSmith (closed source, best funded, 7,000+ organizations) and Langfuse (open source, most stars, a self-reported 50,000+ companies) are the two names a buyer will compare a new entrant against. The two counts are self-reported and probably measured differently, so they are not directly comparable. Braintrust is the eval-centric challenger with the most explicit "data plane in your cloud" architecture.
- Helicone (maintenance mode, then an unexplained move to a 2-person YC company) and AgentOps (stale footer, slowing commits) look like weakening options. Teams leaving them are a reachable segment.

### Gaps
- No current ARR, customer counts or user numbers for Datadog Agent Observability, Sentry AI monitoring, Opik, Logfire, Laminar or HoneyHive.
- Date and terms of Helicone's move from Mintlify to Experiential Labs: not found.
- Download figures (PyPI/npm) were not collected beyond Langfuse's self-reported claim.
- Galileo's pricing before the acquisition was not recovered, since its site now redirects to Splunk.

## 2. Current pricing, and where SSO, SCIM, RBAC, audit logs, retention controls and self-hosting are gated

### Takeaway
Entry-level paid tiers cost $19–$250 a month and are mostly priced by usage (traces, spans, GB or units), not seats. LangSmith ($39/seat) and Logfire (5 seats included, $25 per extra seat) are the main per-seat exceptions. Across nearly every vendor, SAML SSO, SCIM, audit logs, custom RBAC, customer-managed keys and self-hosting or hybrid deployment are reserved for Enterprise or a costly add-on. A 3–10 person team that wants SSO plus control over where traces live usually faces a sales call or a $500–$2,500+ monthly price. The exceptions are Sentry Business ($80/month annual), which includes SAML2 and SCIM; Langfuse's $300/month Teams add-on, which brings SSO; and self-hosting open source (Langfuse, Phoenix, Opik, Laminar, Helicone), which costs ops effort.

### Cited Findings
Prices are as listed on each vendor's page, fetched 26 Nov 2026. No page carried an effective date unless one is shown.

| Platform | Free tier | Team-ish paid tier | Where SSO / SCIM / RBAC / audit / retention control / self-host sit | Source |
|---|---|---|---|---|
| LangSmith | Developer $0: 1 seat, 5k base traces/mo | Plus **$39/seat/mo**, 10k base traces/mo, then pay-as-you-go | Custom SSO, ABAC and RBAC on Enterprise; self-hosted and hybrid on Enterprise only; Google/GitHub SSO not plan-gated. Base traces kept 14 days, extended traces 180 days. Per-1k trace prices not shown on the page | [LangChain pricing](https://www.langchain.com/pricing) |
| Langfuse Cloud | Hobby $0: 50k units/mo, 30-day data access, 2 users | Core **$29/mo** (90 days); Pro **$199/mo** (3 years); overage $8 per 100k units, falling to $6 | SSO and SSO enforcement need the **Teams add-on, $300/mo on Pro**, or Enterprise **$2,499/mo**. SCIM and audit logs on Enterprise only. Retention management on Pro and up. HIPAA/BAA on Pro and up. Regions US/EU/JP, plus a HIPAA region on Enterprise. Client-side masking on all plans. Self-hosting OSS is free | [Langfuse pricing](https://langfuse.com/pricing) |
| Langfuse self-hosted | MIT OSS, free | Enterprise license (price not on page) | Server-side ingestion masking needs the Enterprise license | [Langfuse data masking](https://langfuse.com/self-hosting/security/data-masking) |
| Braintrust | Starter $0: 1 GB processed data, 10K scores, 14-day retention | Pro **$249/mo**: 5 GB, $3/GB overage, 30-day retention, extended up to 180 days at $0.50/GB/mo; unlimited users | SAML SSO not on Starter or Pro. RBAC "Basic roles" on Pro, "Custom" on Enterprise. BAA on Enterprise. On-prem or hosted deployment on Enterprise | [Braintrust pricing](https://www.braintrust.dev/pricing) |
| Helicone (maintenance mode) | Hobby $0: 10k requests, 7 days, 1 seat | Pro **$79/mo**, 1 month retention; Team **$799/mo**, 3 months | SOC 2 and HIPAA on Team. SAML SSO and on-prem on Enterprise | [Helicone pricing](https://www.helicone.ai/pricing) |
| Arize AX | $0: 25k spans/mo, 1 GB, 15 days | Pro **$50/mo**: 50k spans, 10 GB, 30 days | Enterprise SSO not on Free or Pro. Self-hosting on Enterprise only. Regions US/EU/CA on all plans. "BYOK" here means AI-provider keys, on Enterprise | [Arize pricing](https://arize.com/pricing/) |
| Phoenix (Arize) | Open source, self-hosted | — | Authentication is off on default installs (see Q5) | [OSV](https://osv.dev/vulnerability/CVE-2026-53998) |
| Splunk Agent Observability (Galileo) | Free edition, up to 15 hosts | "Starting at just $100 per month per 1.2 million spans annually"; the same page also lists $8.50 per 10k spans/mo | "Available in Observability Cloud and self-hosted deployments"; 500M Eval-G1 ("Luna") tokens a year | [Splunk pricing](https://www.splunk.com/en_us/products/pricing.html#agent-observability) |
| HoneyHive | Free: 10k events/mo, 30 days, up to 5 users, AWS us-west-2 only | Enterprise only (custom) | SAML and custom SSO, custom roles, single-tenant, hybrid and self-hosted, custom DPA and BAA all on Enterprise | [HoneyHive pricing](https://www.honeyhive.ai/pricing) |
| Laminar | Free: 1 GB, 7 days, 1 seat | Pro **$30/mo**: 3 GB, $2/GB, 3 months, unlimited seats; Scale **$250/mo**: 100 GB, 1 year | Trace-level RBAC, audit logs, SOC 2 Type II and HIPAA on Scale. On-prem on Enterprise | [Laminar pricing](https://laminar.sh/pricing) |
| Comet Opik | Free Cloud: 25k spans, 60 days, up to 10 members; OSS self-host unlimited | Pro Cloud **$19/mo** (not per seat): 100k spans, $5 per 100k extra; 400-day retention +$29 per 100k spans | RBAC, enterprise SSO (SAML/LDAP), SSO enforcement, the SOC 2/ISO 27001/HIPAA listing and flexible deployments on Enterprise only. Region US on Free and Pro | [Comet pricing](https://www.comet.com/site/pricing/) |
| Pydantic Logfire | Personal $0: 10M records, 30 days, 1 seat | Team **$49/mo**: 5 seats, **$25 per extra seat** up to 12; Growth **$249/mo**: unlimited seats, up to 90 days | SSO, SAML, SCIM, RBAC, audit-log API and self-hosting on Enterprise only. HIPAA BAA "boilerplate" on Growth, custom on Enterprise. US/EU regions and SOC 2 Type 2 on all plans | [Pydantic pricing](https://pydantic.dev/pricing) |
| CoreWeave Forge (W&B Weave) | $0: up to 5 seats, 1 GB/mo Weave ingestion | Pro from **$60/mo**: up to 10 seats, 1.5 GB/mo, $0.10/MB extra; only for companies under 50 employees | SSO, SCIM, custom roles, audit logs, HIPAA ("Possible with BYOB"), CMK ("Available with private hosting", AWS/GCP), bring-your-own-bucket and dedicated deployment all on Enterprise | [CoreWeave Forge pricing](https://www.coreweave.com/forge-pricing) |
| Datadog Agent (LLM) Observability | Free $0: 40K LLM spans/mo, 15-day retention | Pro **$160/mo** annual, $200 month-to-month, $240 on-demand, each with 100K LLM spans; then $3.50, $4.20 or $5 per 10K | Only LLM spans are billed (not tool, retrieval or workflow spans). Retention add-ons of $6.50, $8 or $9 per 10K spans buy 30, 60 or 90 days. Sensitive Data Scanner included (1 GB per 10K spans) | [Datadog pricing](https://www.datadoghq.com/pricing/?product=llm-observability) |
| Sentry | Developer $0: 5k errors, 5M spans, 1 user, 30-day lookback | Team **$26/mo** annual ($29 monthly); Business **$80/mo** annual ($89 monthly) | Google/GitHub SSO from Team. SAML2 and SCIM from Business. BAA from Business. "Agent tracing" and "MCP monitoring" on all plans. Data residency on all plans | [Sentry pricing](https://sentry.io/pricing/) |
| Traceloop (ServiceNow) | Free Forever: 50K spans/mo, 5 seats, **24-hour retention** | Enterprise only | SOC 2 and on-prem on Enterprise | [Traceloop pricing](https://www.traceloop.com/pricing) |
| AgentOps | Basic $0: 5,000 events | Pro from **$40/mo**: unlimited events and retention, role-based permissions | Custom SSO, on-prem and self-hosting (AWS/GCP/Azure), custom retention, SOC-2, HIPAA and NIST AI RMF on Enterprise | [agentops.ai](https://www.agentops.ai/) |

- Other pricing notes: Logfire's paid plans offer a price cap, and once it is reached new telemetry is hidden — [Pydantic pricing](https://pydantic.dev/pricing). Braintrust Pro is free for 6–12 months for qualifying startups — [Braintrust pricing](https://www.braintrust.dev/pricing). Helicone gave startups 50% off their first year — [Helicone pricing](https://www.helicone.ai/pricing)
- LangSmith adds metered charges beyond traces. The Agent Server, Fleet, Engine and Sandboxes are billed in LSUs ($1 each); for example, Engine uses about 7–45 LSUs per run — [LangChain pricing](https://www.langchain.com/pricing)
- Retention has changed: an Apr 2026 article citing LangSmith docs gave 400 days for extended traces, against 180 days on the Nov 2026 pricing page — [Tian Pan, 23 Apr 2026](https://tianpan.co/blog/2026-04-23-ai-observability-tracing-data-exfiltration-leak); [LangChain pricing](https://www.langchain.com/pricing)

### Inferences
- The "Team" price point in this market is about $30–$250 a month flat plus usage. SSO, audit logs and control over where data lives are the levers used to push teams to Enterprise.
- A Team plan that includes end-to-end privacy, audit-ready records and SSO-like control would undercut the usual gate, where buyers pay Enterprise prices for "data stays in your environment".
- Short default retention (24 hours at Traceloop Free, 7 days at Helicone Hobby and Laminar Free, 14–15 days at LangSmith, Braintrust, Arize and Datadog) is common, because storing traces costs vendors money and carries liability. Longer retention is sold per GB or per span.

### Gaps
- LangSmith's per-1k base and extended trace prices were not on the fetched page.
- Sentry's page does not say how AI-agent spans are metered.
- Self-hosted Enterprise prices for Langfuse, LangSmith, Arize, Braintrust and HoneyHive are not published.
- Logfire's pricing change of 1 Jan 2026 was mentioned only in aggregator results, so it is unverified.

## 3. Data visibility: who can read the traces, under which keys

### Takeaway
On every SaaS tier in this market the vendor holds the keys. Traces get TLS in transit, AES-256 (or "encrypted") at rest, and vendor staff, support sub-processors and the vendor's own AI features can reach plaintext. Customer control comes in three forms:
- **Client-side masking or omission**, which every major SDK offers. Masked content is then unreadable to the team as well.
- **Deployment moves**: self-hosted, BYOC, or hybrid where the browser talks straight to a data plane in the customer's cloud (Braintrust, HoneyHive, LangSmith Enterprise).
- **CMK**, offered for traces only by CoreWeave Forge/W&B (Enterprise with private hosting) and by self-hosted or BYOC setups that use the customer's own KMS.

Application-level encryption, where it exists, covers credentials (LLM API keys) and, for LangGraph, agent checkpoints. It never covers trace contents. Vendor AI features send trace text to LLM sub-processors, with zero data retention (ZDR) as the stated safeguard: LangSmith Engine uses OpenAI, Anthropic, Fireworks and Baseten; Braintrust Topics uses Baseten; Langfuse AI features use AWS Bedrock; Arize Alyx uses Arize-managed providers.

### Cited Findings
**LangSmith (LangChain)**
- Hosted data: "When using LangSmith hosted at smith.langchain.com, data is stored in GCP us-central-1." Self-hosted and BYOC options exist "for teams with data residency requirements". "Self-host SmithDB inside your VPC so sensitive traces never leave your infrastructure." "We will not train on your data, and you own all rights to your data." — [LangSmith page](https://www.langchain.com/langsmith)
- Regions: GCP US, GCP EU, GCP APAC, AWS US and Azure US, on all plans including free. No EU legal entity for contracting — [LangSmith regions FAQ](https://docs.langchain.com/langsmith/regions-faq)
- Ambiguity: the pricing page says "Cloud and Hybrid data live in LangChain's Cloud (US or EU). Self-Hosted data lives in your VPC", yet it also describes Hybrid as a SaaS control plane with a self-hosted data plane. For trace storage, only Self-Hosted clearly keeps data out of LangChain's cloud — [LangChain pricing](https://www.langchain.com/pricing)
- Masking runs client-side: `LANGSMITH_HIDE_INPUTS`/`LANGSMITH_HIDE_OUTPUTS`, anonymizers and regex/Presidio/Comprehend all mask data "before they are serialized and sent to the API". The docs warn the regex examples are "not exhaustive", and that conditional tracing suits data that must never be traced — [LangSmith masking](https://docs.langchain.com/langsmith/mask-inputs-outputs)
- Agent Server: checkpoints can be AES-encrypted with an optional, customer-set `LANGGRAPH_AES_KEY`, which covers checkpoints only. The self-hosted server makes API calls to "confirm that the server has a valid license" and "track the number of executed runs and tasks" — [LangSmith data storage](https://docs.langchain.com/langsmith/data-storage-and-privacy)
- LangSmith Engine, an AI that analyzes traces, sends trace data to sub-processors "OpenAI, Anthropic, Fireworks, and Baseten". Each provider is configured for zero data retention and contractually barred from training. Engine is off by default and only an org admin can enable it. Self-hosted users can use their own Anthropic, OpenAI, Bedrock, Vertex or Foundry credentials (page reviewed 16 Sep 2026) — [Engine security](https://docs.langchain.com/langsmith/engine-security)
- Compliance: a LangChain changelog entry announces SOC 2 Type II — [LangChain changelog](https://changelog.langchain.com/announcements/langsmith-is-now-soc-2-type-ii-compliant). A third-party review says a HIPAA BAA is available on Enterprise, unverified — [search summary of the regions FAQ and Trust Center](https://docs.langchain.com/langsmith/regions-faq)

**Langfuse (ClickHouse)**
- Cloud: "runs on AWS and ClickHouse Cloud in isolated regional environments". US and HIPAA regions are in us-west-2, EU in eu-west-1, JP in ap-northeast-1. Annual SOC 2 Type 2 and ISO 27001 audits; ClickHouse holds ISO/IEC 27701:2025; the HIPAA claim is a "HIPAA-ready region" — [Langfuse security](https://langfuse.com/security)
- Sub-processors (effective 10 Aug 2026): AWS for hosting. AWS Bedrock only "if the customer uses AI Features". Support tools Salesforce, Pylon, Google Workspace, Waypoint, GitHub and kapa.ai (an AI support tool). Nine ClickHouse entities (US, Australia, Netherlands, Germany, India, Japan, Singapore, UK, plus Langfuse GmbH) "provide technical and support services" — [ClickHouse Langfuse sub-processors](https://clickhouse.com/legal/agreements/langfuse-subprocessors)
- Encryption: Langfuse Cloud uses "AES-256 across all databases". Self-hosters rely on storage-layer encryption (managed Postgres, Redis and S3; an encrypted ClickHouse disk). `ENCRYPTION_KEY` covers only LLM API credentials and integration secrets, not trace inputs or outputs — [Langfuse encryption](https://langfuse.com/self-hosting/configuration/encryption)
- Masking: an SDK mask (`mask_otel_spans` in Python, `mask` in JS) runs in the application before export — [Langfuse masking](https://langfuse.com/docs/observability/features/masking). Self-hosted Enterprise adds server-side ingestion masking through a customer-hosted callback. It fails open by default (`…FAIL_CLOSED=false`), data is briefly stored unmasked in blob storage, and the legacy ingestion endpoint is not covered — [Langfuse server-side masking](https://langfuse.com/self-hosting/security/data-masking)
- Self-hosted Langfuse "can be run fully offline/air-gapped" — [Langfuse security](https://langfuse.com/security)

**Braintrust**
- Deployment: SaaS, or BYOC, where "Braintrust operates the data plane in your own cloud account". "no customer data flows through Braintrust's control plane". All data "encrypted at rest and in transit". Provider secrets are "encrypted using AES-256 with unique 256-bit keys and nonces". Retention policies are configurable. SOC 2 Type II, BAAs and DPAs available — [Braintrust security docs](https://docs.braintrust.dev/security)
- Topics feature: "the trace text it summarizes is sent to Braintrust-served Baseten endpoints for inference", with "Zero Data Retention (ZDR) for every organization" on by default — [Braintrust security docs](https://docs.braintrust.dev/security)
- What each plane holds: the data plane stores logs, traces, spans, datasets, prompts and completions, and project-level provider secrets. The control plane holds org-level provider secrets (encrypted), hashed API keys, experiment, dataset and project names, project settings, git metadata, org and login info (authentication via Clerk). "Your browser communicates directly with your data plane via CORS"; BYOC data planes still send "operational telemetry" — [Braintrust architecture](https://docs.braintrust.dev/admin/self-hosting/architecture)
- The 21 Jan 2026 blog says the control plane "doesn't store or process the contents of your data-plane records". Under BYOC the customer controls "the account, network, encryption keys, audit logs". "no models are trained on your data" — [Braintrust blog](https://www.braintrust.dev/blog/security-data-control)

**Arize (AX and Phoenix, now Dynatrace)**
- AX Enterprise offers self-hosting "in the customer's cloud of choice", with data inside the customer's private VPC; an air-gapped option is mentioned — [Arize on-prem](https://arize.com/self-hosted/) (search summary)
- Certifications: SOC 2 Type II, PCI DSS 4.0, HIPAA, CSA STAR Level 1 and ISO 27001 — [Arize compliance](https://www.arize.com/docs/ax/security-and-settings/compliance) (search summary)
- Alyx, the AI assistant, uses "Arize-managed providers" on Free and Pro; Enterprise can bring its own AI-provider key. Data regions US, EU and CA — [Arize pricing](https://arize.com/pricing/)
- Phoenix at-rest encryption is storage-layer only. The maintainer said field-level application encryption "would have large performance ramifications and would likely not work for most" (27 Jul 2026) — [Phoenix issue #14707](https://github.com/Arize-ai/phoenix/issues/14707)

**Datadog Agent (LLM) Observability**
- Redaction runs through Sensitive Data Scanner. Access control uses Data Access Control scoped by `ml_app`. SDK span processors can modify inputs and outputs or drop spans. Traces are kept 15 days by default, add-ons extend to 30, 60 or 90 days, and datasets and prompts are kept 3 years. Not available on US-FED sites. Neither this page nor a web search turned up any CMK or BYOK encryption option — [Datadog data security & RBAC](https://docs.datadoghq.com/llm_observability/data_security_and_rbac/)
- LLM-as-judge evaluations run through the customer's own connected OpenAI, Anthropic or Azure OpenAI account. The integration toggle reads "Use this API key to evaluate your LLM applications", so trace content goes to that provider under the customer's account — [Datadog connect account](https://docs.datadoghq.com/llm_observability/investigate/evaluations/llm_as_a_judge_evaluations/connect_to_account/) (search summary)

**Sentry**
- "By default, Sentry agent integrations collect this content": prompts, system instructions, responses, tool definitions, and tool arguments and results. Opt out with `recordInputs`/`recordOutputs` (`dataCollection`). Server-side default scrubbers mask emails, card numbers, IBANs, US SSNs and bearer tokens inside `gen_ai.*` attributes — [Sentry AI agents privacy](https://docs.sentry.io/product/insights/ai/agents/privacy/)
- Region: US (Iowa) or EU (Frankfurt), chosen when the org is created and fixed afterwards. Some account metadata and support data stays in the US — [Sentry data storage location](https://docs.sentry.io/organization/data-storage-location/)

**W&B Weave (CoreWeave)**
- Two redaction modes. Server-side, an org admin setting "Redact PII in Weave traces" redacts emails, phones, SSNs and card numbers before storage, so the server receives plaintext. Client-side, Presidio redaction runs in the Python SDK only. Keys such as `api_key`, `auth_headers` and `authorization` are always redacted — [Weave redaction](https://docs.coreweave.com/weave/guides/tracking/redact-pii)
- CMK on AWS/GCP "Available with private hosting" (Enterprise). Bring-your-own-bucket on Enterprise. SOC 2 Type II on all tiers — [CoreWeave Forge pricing](https://www.coreweave.com/forge-pricing)

**Pydantic Logfire**
- SDK scrubbing is on by default, but it matches field names such as `password`, `api_key` and `jwt`, not prose. For `gen_ai.input.messages` and `gen_ai.output.messages` only nested field names are checked, and the docs advise `include_content=False` to drop content. "Logfire doesn't scrub exception messages" — [Logfire scrubbing](https://pydantic.dev/docs/logfire/instrument/scrubbing/)
- US and EU regions. Self-hosting and dedicated deployment (any GCP region) on Enterprise — [Pydantic pricing](https://pydantic.dev/pricing)

**Traceloop / OpenLLMetry**
- "By default, OpenLLMetry logs prompts, completions, and embeddings to span attributes"; set `TRACELOOP_TRACE_CONTENT=false` to stop. Content can be switched per workflow or per user — [Traceloop privacy](https://www.traceloop.com/docs/openllmetry/privacy/traces)
- On-prem deployment "in any environment", including air-gapped — [Traceloop pricing](https://www.traceloop.com/pricing)

**HoneyHive**
- Three models: fully managed SaaS, hybrid ("Sensitive data never leaves your environment") and self-hosted ("Nothing leaves your network"). SOC 2 Type II, GDPR with EU residency, HIPAA BAA — [honeyhive.ai](https://www.honeyhive.ai/)
- Self-hosted security uses a federated design with separate control and data planes: no trace data, eval results or PII leaves the data plane. AWS KMS at rest, with customer keys for self-hosted. SDK-level PII redaction — [HoneyHive self-hosted security](https://docs.honeyhive.ai/v2/setup/self-hosted/security) (search summary)

**Laminar, Opik, AgentOps, Helicone, Splunk/Galileo, Raindrop**
- Laminar redacts PII "on Laminar's own infrastructure before storage", which is server-side. Apache-2.0 self-hosting via Docker or Helm; "HIPAA & SOC 2 Type II Compliant" badge — [laminar.sh](https://laminar.sh/). Its Signals feature analyzes traces and bills by the tokens used — [Laminar pricing](https://laminar.sh/pricing)
- Opik: Apache-2.0 self-host. Cloud data region US on Free and Pro. Compliance listing (SOC 2, ISO 27001, HIPAA) on Enterprise — [Comet pricing](https://www.comet.com/site/pricing/)
- AgentOps: self-hosting (AWS, GCP, Azure) and SOC-2/HIPAA on Enterprise; no PII redaction mentioned — [agentops.ai](https://www.agentops.ai/)
- Helicone offers "Omit logs" headers instead of prompt encryption — [Helicone issue #35](https://github.com/Helicone/helicone/issues/35)
- Splunk Agent Observability (Galileo) can deploy on-premises, "so the evaluation and enforcement layers run inside your boundary rather than behind a hosted API". Luna evaluation models can be self-hosted — [Splunk blog](https://www.splunk.com/en_us/blog/observability/ai-on-premises.html) (search summary)
- Raindrop: client-side SDK redaction is regex-only. Server-side "PII Guard" costs from $80/mo — [Raindrop PII redaction](https://www.raindrop.ai/docs/security/pii-redaction) (search summary)

**Built-in and cloud-native comparators**
- OpenAI Agents SDK "exports the spans and traces to the OpenAI backend" by default, with `trace_include_sensitive_data` defaulting to True. "Tracing is unavailable for organizations that use OpenAI's APIs under a Zero Data Retention (ZDR) policy." — [OpenAI Agents SDK tracing](https://openai.github.io/openai-agents-python/tracing/)
- AWS AgentCore writes traces and prompts to a CloudWatch log group in the customer's account — [AWS](https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-bedrock-agentcore-unified-observability-single-log-group/). The AgentCore encryption docs list CMK for memories and gateways; I found no explicit observability CMK — [AgentCore data encryption](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html)

**Data-visibility tiers for the matrix (each tier drawn from the vendors above)**

| Tier | Who can read trace content | Examples |
|---|---|---|
| A. SaaS, vendor-held keys (TLS + AES-256 at rest) | Vendor operators, support sub-processors, vendor AI features and their LLM sub-processors | All hosted tiers above |
| B. A + client-side masking or content off | Vendor reads what isn't masked; masked content is readable by no one, the team included | LangSmith hide/anonymizers, Langfuse mask, Weave Presidio, Logfire `include_content=False`, `TRACELOOP_TRACE_CONTENT=false`, Sentry `recordInputs` |
| C. A + server-side redaction | Vendor receives plaintext, then redacts | Weave org setting, Laminar, Raindrop PII Guard, Datadog SDS, Sentry scrubbers, Langfuse EE callback |
| D. BYOC with vendor-operated data plane, customer KMS | Customer account and keys; vendor operates the plane | Braintrust BYOC, CoreWeave Forge private hosting + CMK |
| E. Hybrid, browser-direct to customer data plane | Vendor sees metadata and serves the UI code | Braintrust, HoneyHive hybrid |
| F. Fully self-hosted or air-gapped | Customer's own operators; vendor sees licence and usage pings only | Langfuse, Phoenix, Opik, Laminar, Helicone, LangSmith EE, Arize AX EE, Splunk on-prem |
| G. Client-side encryption, customer-held keys, vendor stores ciphertext | Only key holders | Honeycomb Secure Tenancy (2020, general observability); Volidator (unaudited) — see Q4 |

### Inferences
- In this market "BYOK" mostly means bringing your own LLM API key so that evals or AI features run on the customer's provider account (Arize Enterprise, Datadog evals, LangSmith self-hosted Engine). Only W&B/CoreWeave (Enterprise) and BYOC or self-hosted KMS setups give customer-managed encryption keys over trace storage. A matrix should not conflate the two.
- Client-side masking is the only control that keeps content from the vendor on SaaS, and it destroys the content for the team too. No vendor offers "the team can read it, the vendor cannot" on SaaS. That gap is exactly where an E2EE team feed sits.
- "ZDR" claims cover the LLM sub-processors behind a vendor's AI features, not the observability vendor's own storage, which keeps traces for 14 days to 3 years.
- Self-hosting moves trust rather than removing it. Plaintext then sits with whoever operates the database, and defaults can be weak: Phoenix ships without authentication, and Langfuse's server-side masking fails open.
- Even in browser-direct hybrid, the vendor serves the JavaScript that decrypts and renders data. A compromised control plane could therefore ship code that exfiltrates it. That is my own threat-model reading; no vendor source says so.

### Gaps
- Datadog: no public statement found on CMK, employee access or whether AI features (Bits AI) process LLM traces.
- Opik/Comet: hosting provider, encryption and employee-access details beyond the pricing page.
- LangSmith: HIPAA/BAA terms and CMK availability are unverified. The Trust Center was not fetched.
- Arize: whether SOC 2 and HIPAA cover customer-hosted deployments; whether Dynatrace will change data handling ("We will share updates").
- Microsoft Foundry and Google Vertex agent tracing data handling were not researched.
- Training-use statements were found only for LangSmith, Braintrust and LangSmith Engine. Other vendors' DPAs were not checked.

## 4. Does any vendor claim E2EE, zero-knowledge or operator blindness for traces? What is the nearest thing?

### Takeaway
No agent or LLM observability vendor claims end-to-end encryption or zero-knowledge storage of traces; an extended web search found no such product. Vendors' strongest claims are deployment claims: "sensitive traces never leave your infrastructure" (LangSmith self-host), "no customer data flows through Braintrust's control plane" (Braintrust hybrid and BYOC), "Sensitive data never leaves your environment" (HoneyHive hybrid). These keep the vendor's cloud out of the data path, but the vendor's code, or the customer's own operators, still see plaintext.

The nearest thing to E2EE observability is **Honeycomb's Secure Tenancy**, announced in **2020** for general observability, not agents. An on-premises proxy encrypts data with customer-held keys, and the browser decrypts through that proxy, so "Honeycomb never has access to the data or the security keys". Its availability in 2026 is unconfirmed. **Volidator**, a small and unaudited startup, claims zero-knowledge audit logs for AI agents. A June 2026 arXiv proposal, "Notarized Agents", argues current agent observability is "structurally compromised". No observability product runs trace storage in a TEE.

### Cited Findings
- Honeycomb Secure Tenancy, announced 16 Jun 2020 (older): "This patented technology allows Honeycomb to offer its enterprise customers broader security protection when observing production data which is encrypted with the keys maintained onsite via a Secure Proxy. When a user logs-in to Honeycomb, their browser connects to the Secure Proxy where the data is decrypted and Honeycomb never has access to the data or the security keys." The deploying team controls key rotation. Enterprise plan only. The post does not say which fields are encrypted, or whether column names or numeric values stay visible to Honeycomb — [Honeycomb blog](https://www.honeycomb.io/blog/honeycomb-io-granted-patent-to-securely-manage-control-sensitive-data)
- Honeycomb's current security documentation says only "All data is encrypted at rest and in transit" and does not mention Secure Tenancy — [Honeycomb docs](https://docs.honeycomb.io/getting-data-in/datasets/secure-manage/)
- Braintrust's claims: "All data requests from the Braintrust UI go directly from your browser to your self-hosted data plane (via CORS), bypassing our servers". The data plane "sends metrics and status telemetry to the control plane, but not logs, traces, or customer data" — [Braintrust self-hosting advanced](https://braintrust.dev/docs/guides/self-hosting/advanced) (search summary). "no customer data flows through Braintrust's control plane" — [Braintrust security](https://docs.braintrust.dev/security). The same docs say "Braintrust operates the data plane in your own cloud account" under BYOC. A KB article covers CORS and "unable to connect to data plane" errors in hybrid setups — [Braintrust KB](https://kb.braintrust.dev/articles/1232375066-cors-errors-and-unable-to-connect-to-data-plane-in-hybrid-self-hosted-deployments)
- LangSmith: "Self-host SmithDB inside your VPC so sensitive traces never leave your infrastructure." — [LangSmith](https://www.langchain.com/langsmith)
- HoneyHive: "Sensitive data never leaves your environment" (hybrid); "Fully self-hosted. Nothing leaves your network." — [HoneyHive](https://www.honeyhive.ai/)
- Arize's own article (11 Aug 2026) warns that "Local storage does not guarantee local processing". A vendor can truthfully say raw traces stay in your VPC while exporting sensitive derived data, and control-plane and data-plane terms "are not standardized" — [Arize](https://arize.com/?p=30898)
- Volidator: its SDK README says each entry is encrypted on the customer's server before it is sent, and "the backend stores only ciphertext and blind indexes" — [Volidator README v1.0.6](https://jsr.io/@volidator/node/1.0.6/README.md). It names AES-256-GCM and HMAC-SHA-256 blind indexing — [README v1.0.5](https://jsr.io/@volidator/node/1.0.5/README.md). The promotional articles are written by the same author and describe key handling inconsistently (a URL-fragment key versus an environment variable) — [dev.to](https://dev.to/ankreations/why-your-ai-agent-needs-an-audit-trail-and-how-to-build-one-51d6). No independent audit was found.
- "Notarized Agents: Receiver-Attested Confidential Receipts for AI Agent Actions" (Juan Figuera, arXiv, submitted 2 Jun 2026): "Current AI agent observability is structurally compromised… the entity producing the activity log is the same entity whose activity is being logged." It proposes that the receiving service "signs a receipt… encrypts the receipt to the agent's owner, and publishes it to a public transparency log" (HPKE to an owner public key) — [arXiv 2606.04193](https://arxiv.org/abs/2606.04193)
- TEE: I found no observability vendor that stores or processes traces inside TEEs. Available guidance comes from vendors with a commercial interest and recommends sending only metadata out of an enclave; it warns that cloud evaluators which receive raw content "defeat the purpose" — [FutureAGI glossary](https://futureagi.com/glossary/confidential-computing/); [Gravitee](https://www.gravitee.io/corpus/gen-2069/encryption-software/confidential-computing-for-llms.html)
- Inside the OTel standard, the nearest building block is a reference pattern. The GenAI conventions recommend production apps "Store content externally and record references on the spans", using `gen_ai.input.messages_ref`, `gen_ai.output.messages_ref` and similar attributes (URIs to external storage), because it "enables separate access controls" — [OTel GenAI spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md); [client-inference attributes](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/client-inference.md)
- Application-level encryption that does exist covers only credentials or agent state: Langfuse `ENCRYPTION_KEY` for LLM keys, Braintrust AES-256 provider secrets, LangGraph optional `LANGGRAPH_AES_KEY` for checkpoints — [Langfuse](https://langfuse.com/self-hosting/configuration/encryption); [Braintrust](https://docs.braintrust.dev/security); [LangSmith](https://docs.langchain.com/langsmith/data-storage-and-privacy)

### Inferences
- What each claim really protects:
  - "Never leaves your infrastructure" or "never leaves your environment": the vendor's cloud is out of the data path. The customer's own operators and admins, and the vendor-supplied UI code, still see plaintext.
  - Braintrust BYOC: the vendor operates the data plane in your account, so vendor engineers keep an operational path to the data.
  - Honeycomb Secure Tenancy: close to "vendor stores only what it can't read". Even so, decryption happens at a customer-hosted proxy, not on each user's device, and the 2020 post does not say whether metadata or structure stays visible.
- The market therefore has no product where content is encrypted on the user's devices, the operator stores only ciphertext, and the team still reads and searches a shared record. An operator-blind, team-readable encrypted agent feed has no direct analogue among observability vendors. The nearest analogues are Honeycomb's 2020 design and the 2026 "Notarized Agents" research proposal.
- Rivals will raise one predictable objection: E2EE gives up vendor-side LLM-as-judge evals, cross-trace analytics and AI assistants, which all read plaintext on vendor or sub-processor servers. Phoenix's maintainer already calls field-level encryption likely unworkable "for most". The answer has to be on-device or team-key evaluation, or a deliberate scope of audit record over analytics platform.
- The OTel "store content externally, keep references on spans" pattern lets an E2EE content store coexist with standard tracing back ends. Metadata could go to any OTel vendor while the content stays team-encrypted.

### Gaps
- Whether Honeycomb Secure Tenancy is still sold in 2026, and exactly what it leaves in plaintext, could not be confirmed.
- No technical audit of Volidator; its customer count, funding and status are unknown.
- No vendor claim was found using "operator blindness" or "zero-knowledge" for LLM traces. That absence comes from searches, not from an exhaustive list.

## 5. 2025–2026 events: acquisitions, funding, pricing, outages, security advisories, OTel GenAI status, multi-agent tracing

### Takeaway
Besides the consolidation in Q1, the period brought several serious security advisories in this tooling:
- LangSmith's "AgentSmith" proxy flaw (CVSS 8.8, disclosed Jun 2025).
- Two Langfuse CVEs in 2026, including members being able to read stored LLM API keys.
- A CVSS 10.0 Phoenix flaw (CVE-2026-53998) reachable without authentication on default installs, with a public proof of concept in Nov 2026.

The OpenTelemetry GenAI semantic conventions moved to their own repository and cut a first standalone release, v0.1.0, on 21 Nov 2026. They are still at "Development" status and still say content should *not* be captured by default. The OpenAI–Mixpanel breach (Nov 2025) is the reference case buyers cite for the risk of sending data to third-party analytics vendors.

### Cited Findings
**Security advisories and incidents**
- AgentSmith (LangSmith Prompt Hub), CVSS 8.8, disclosed by Noma Security in Jun 2025. An attacker could publish a public agent with a malicious proxy configuration; anyone who adopted and ran it had their communications ("OpenAI API keys, uploaded files, and even voice inputs") routed through the attacker's server. It was reported on 29 Oct 2024 and fixed on 6 Nov 2024, with no evidence of exploitation — [The Hacker News](https://thehackernews.com/2025/06/langchain-langsmith-bug-let-hackers.html); [Hackread](https://hackread.com/agentsmith-flaw-langsmith-prompt-hub-api-keys-data/)
- Langfuse CVE-2026-41487 (published 8 May 2026): "Improper role-based-access control in Langfuse LLM connection management allowed users of role 'member' to retrieve stored LLM provider API keys" in versions 3.68.0 to before 3.167.0 — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-41487)
- Langfuse CVE-2026-24055 (Jan 2026): an unauthenticated Slack OAuth flaw let an attacker link a Slack workspace to any project (versions 3.89.0–3.146.0, fixed in 3.147.0). No exploitation was found on Langfuse Cloud — [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-24055)
- Arize Phoenix CVE-2026-53998 (OSV published 16 Nov 2026), CVSS 10.0, "Format String Injection in applyChatTemplate". "The endpoint is unauthenticated on default installations, and any account can reach it when authentication is enabled." Fixed in 15.7.0 — [OSV](https://osv.dev/vulnerability/CVE-2026-53998). A separate write-up says it can expose secrets such as `PHOENIX_SECRET`, that the fix landed on 13 May 2026, and that a proof of concept went public on 9 Nov — [Corgea](https://corgea.com/research/cve-2026-53998-arize-phoenix-applychattemplate-fstring-secret-disclosure/)
- Phoenix CVE-2026-32689 is an unauthenticated denial of service in the long-poll transport, CVSS 8.7 — [Eventus](https://advisory.eventussecurity.com/advisory/phoenix-vulnerability-causes-unauthenticated-denial-of-service/). MLflow CVE-2026-2635 is a default-password authentication bypass — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-2635)
- OpenAI–Mixpanel (disclosed 26 Nov 2025, older than the 2026 window): an SMS-phishing compromise at Mixpanel, the analytics vendor behind platform.openai.com, exposed API users' names, emails and locations, but no prompts or keys. OpenAI ended its use of Mixpanel and announced "expanded security reviews across our vendor ecosystem" — [OpenAI](https://openai.com/index/mixpanel-incident/); [The Register](https://www.theregister.com/2025/11/27/openai_mixpanel_api/); [SiliconANGLE](https://siliconangle.com/2025/11/27/mixpanel-breach-compromises-openai-api-users-account-data/)

**Outages**
- LangSmith US had a trace-ingestion incident on 12 Jul 2026 (about 37 minutes) and trace visualization was unavailable on 30 Apr 2026 (about 4 hours), per third-party status aggregators — [IsDown, 12 Jul](https://isdown.app/status/langsmith-us/incidents/621418-ingestion-is-delayed); [IsDown, 30 Apr](https://isdown.app/status/langsmith-us/incidents/579390-langsmith-ui-ongoing-incident-trace-visualization-unavailable)

**Pricing and packaging changes**
- Datadog now has a free Agent (LLM) Observability tier (40K LLM spans) and bills only LLM spans. The product is labeled "Agent Observability" in the pricing nav and in docs ("Agent Observability > Settings > Integrations") — [Datadog pricing](https://www.datadoghq.com/pricing/?product=llm-observability); [Datadog docs](https://docs.datadoghq.com/llm_observability/investigate/evaluations/llm_as_a_judge_evaluations/connect_to_account/)
- LangSmith extended-trace retention appears as 180 days in Nov 2026, against 400 days cited in Apr 2026 — [LangChain pricing](https://www.langchain.com/pricing); [Tian Pan](https://tianpan.co/blog/2026-04-23-ai-observability-tracing-data-exfiltration-leak)
- Helicone moved to $79 Pro and $799 Team flat tiers, then went into maintenance mode — [Helicone pricing](https://www.helicone.ai/pricing); [Mintlify](https://www.mintlify.com/blog/mintlify-acquires-helicone)
- Sentry's Seer moves to credit-based pricing from 8 Dec — [Sentry pricing](https://sentry.io/pricing/)

**OpenTelemetry GenAI semantic conventions**
- The GenAI conventions "have moved to the OpenTelemetry GenAI semantic conventions repository"; the opentelemetry.io page is no longer maintained — [opentelemetry.io](https://opentelemetry.io/docs/specs/semconv/gen-ai/). The new repo was created 5 May 2026 — [GitHub](https://github.com/open-telemetry/semantic-conventions-genai)
- v0.1.0, published 21 Nov 2026, is the "First standalone release of the GenAI semantic conventions". It depends on semantic-conventions v1.45.0 and follows v1.41.0, the last release before the move. Breaking changes include merging `invoke_workflow` into `gen_ai.invoke_agent.internal` and replacing the token-usage histogram — [v0.1.0 release](https://github.com/open-telemetry/semantic-conventions-genai/releases/tag/v0.1.0)
- Status is still "**Development**". Coverage includes client inference, embeddings, execute-tool, retrieval, client agent invocations, agent spans, events, metrics and realtime. It has provider pages for Anthropic, Azure AI Inference, AWS Bedrock and OpenAI, plus A2A and MCP conventions — [GenAI README](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/README.md)
- Content guidance: "Model instructions, user messages, and model outputs are considered sensitive… OpenTelemetry instrumentations SHOULD NOT capture them by default, but SHOULD provide an option for users to opt in." The default is "Don't record". External storage with references is "recommended in production environments where… sensitive data needs to be handled securely" — [GenAI spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md). `gen_ai.input.messages` and `gen_ai.output.messages` are Opt-In attributes carrying the warning "likely to contain sensitive information including user/PII data" — [client inference](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/client-inference.md)
- Vendor defaults diverge from that guidance. Sentry ("By default, Sentry agent integrations collect this content"), OpenLLMetry ("By default… logs prompts, completions") and the OpenAI Agents SDK (`trace_include_sensitive_data` True) all capture content by default — [Sentry](https://docs.sentry.io/product/insights/ai/agents/privacy/); [Traceloop](https://www.traceloop.com/docs/openllmetry/privacy/traces); [OpenAI](https://openai.github.io/openai-agents-python/tracing/)

**Multi-agent tracing features**
- In OTel, agent spans (`gen_ai.invoke_agent`) and `execute_tool` were aligned across spans and metrics in v0.1.0, and A2A and MCP each have conventions — [v0.1.0 release](https://github.com/open-telemetry/semantic-conventions-genai/releases/tag/v0.1.0); [README](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/README.md)
- Sentry lists "Agent tracing" and "MCP monitoring" on all plans — [Sentry pricing](https://sentry.io/pricing/). LangSmith offers "Tool and agent trajectory monitoring" and message threading — [LangSmith](https://www.langchain.com/langsmith). Laminar's Agent Debugger reruns from any step — [Tech.eu](https://tech.eu/2026/03/17/agent-debugging-startup-laminar-raises-3m-seed-to-tackle-the-observability-gap-in-ai-agents/). AgentCore puts per-agent traces and logs in one log group (Jul 2026) — [AWS](https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-bedrock-agentcore-unified-observability-single-log-group/)

### Inferences
- The advisories show that trace stores hold secrets as well as prompts: LLM provider keys (Langfuse), environment secrets (Phoenix) and proxied API keys (AgentSmith). The more an observability tool acts like an agent platform (playgrounds, stored keys, hubs, AI features), the bigger its blast radius.
- The standards body's own position (sensitive content off by default; external storage with separate access controls in production) is citable support for operator-blind designs. Vendor defaults that capture everything contradict it.
- Every acquisition changes who processes the data (new affiliates, parent-company sub-processors) and how long a product will be maintained (Helicone). Buyers who fear vendor lock-in or loss of control over their traces have a concrete 2026 story to point to.

### Gaps
- No public breach of trace content at any observability vendor was found for 2025–2026. The incidents found are vulnerabilities and outages.
- No official status-page history for Datadog, Braintrust, Langfuse Cloud or Arize was gathered.
- There is no date for OTel GenAI moving to Stable; no roadmap was found.

## 6. How each platform markets itself, and the weaknesses users report about sensitive data in traces

### Takeaway
Taglines sell reliability and visibility ("Know what your agents are really doing", "Ship reliable agents", "The observability agent"). Privacy talk falls into four patterns:
- Compliance badges: SOC 2 Type II, HIPAA, ISO 27001.
- "We don't train on your data".
- Regions.
- "Never leaves your environment", which always means self-hosted, BYOC or hybrid, never encryption.

Users and critics raise recurring complaints:
- Full prompt and tool capture is the default.
- Regex redaction is brittle and misses prose.
- Self-hosting is the only way to keep content from the vendor.
- Long vendor retention cancels zero-retention deals made with model providers.
- Anyone with dashboard access can read prompts. Requests to encrypt prompts or span attributes have been closed or redirected to "omit logs" or storage-level encryption.

### Cited Findings
**Taglines and privacy messaging (fetched 26 Nov 2026 unless dated)**
- LangSmith: "Know what your agents are really doing"; "Keep sensitive data in your environment"; "We will not train on your data, and you own all rights to your data." — [LangSmith](https://www.langchain.com/langsmith)
- Langfuse: "Open Source Agent Evals & Observability"; "one open platform for every AI call your company makes and every agent your teams build". It promotes SOC 2 Type II and ISO 27001, a "HIPAA-ready region", GDPR, an MIT license, and self-hosting with "data masking and your own encryption keys" — [langfuse.com](https://langfuse.com/)
- Braintrust: "The observability agent"; "Find issues and opportunities in your agent traces and app logs". Claims "SOC 2 Type II certified", "GDPR and HIPAA compliant" — [braintrust.dev](https://www.braintrust.dev/)
- Laminar: "Ship reliable agents"; "Open source from day zero"; "HIPAA & SOC 2 Type II Compliant" — [laminar.sh](https://laminar.sh/)
- HoneyHive: "Production AI starts with observability." — [honeyhive.ai](https://www.honeyhive.ai/)
- AgentOps: "Trace, Debug, & Deploy Reliable AI Agents." — [agentops.ai](https://www.agentops.ai/)
- Helicone: "Build Reliable AI Apps" — [helicone.ai](https://www.helicone.ai/)
- Splunk Agent Observability (Galileo): evaluation and guardrails on every interaction, not a sample, plus an on-prem story for regulated buyers — [Splunk blog](https://www.splunk.com/en_us/blog/observability/ai-on-premises.html) (search summary)
- Tsuga (deploys inside the customer's environment; the article doesn't use the word "BYOC"): "the data never leaves the customer's perimeter" — [The Next Web](https://thenextweb.com/news/tsuga-35-million-series-a-observability)

**User-reported weaknesses and critiques**
- Helicone issue #35 (Feb 2023, older): a user wanted encrypted prompts because "if someone were to access my Helicone account they would be able to see the data through the prompts". The maintainer pointed to "Omit logs" and closed it — [GitHub](https://github.com/Helicone/helicone/issues/35)
- Phoenix issue #14707 (24 Jul 2026, open): "Protected env and zero trust policy requires encryption at rest of traces… Without that in some environments it won't be possible to deploy phoenix to prod". The maintainer replied that storage-layer encryption meets the usual control, and that stronger "unreadable even to someone with a valid DB connection" protection would be application-layer work with "large performance ramifications" — [GitHub](https://github.com/Arize-ai/phoenix/issues/14707)
- Phoenix issue #9325 (Aug 2025): a user trying to encrypt span attributes client-side broke the trace structure — [GitHub](https://github.com/Arize-ai/phoenix/issues/9325)
- Langfuse issue #3518 (Sep 2024, older), a PII-masking request: "regex… is very brittle. IMHO, Brittle doesn't work for PII." — [GitHub](https://github.com/langfuse/langfuse/issues/3518)
- Critique by Tian Pan, "Your Tracing Stack Is a Data Exfiltration Surface" (23 Apr 2026). It criticizes capture-everything defaults and treating "does the vendor train on my data?" as the main risk, when retention, breach surface and subpoena matter more. It says vendor-side redaction acts only after data has left the trust boundary, and that "Zero-retention agreements with model providers" are undone by tracing vendors that store the same data for much longer. It recommends fail-closed field classification and self-hosting or a hybrid. Its opening scenario, medical summaries, Stripe keys and an acquisition memo shipped to a SaaS backend with 400-day retention, is anecdotal and unsourced — [tianpan.co](https://tianpan.co/blog/2026-04-23-ai-observability-tracing-data-exfiltration-leak)
- SDK redaction has a known blind spot: if a model emits sensitive data in its response, that content reaches the application and its traces unmodified — [Grafana Cloud AI Observability docs](https://grafana.com/docs/grafana-cloud/machine-learning/ai-observability/privacy-and-security/pii-and-secrets-redaction/) (search summary)
- Vendor docs admit the same limits: Logfire does not scrub prose or exception messages ([Logfire](https://pydantic.dev/docs/logfire/instrument/scrubbing/)), LangSmith's regex "may miss some formats" ([LangSmith](https://docs.langchain.com/langsmith/mask-inputs-outputs)), Raindrop's client-side redaction is regex-only ([Raindrop](https://www.raindrop.ai/docs/security/pii-redaction)), and Langfuse's server-side masking fails open by default ([Langfuse](https://langfuse.com/self-hosting/security/data-masking))
- Non-air-gapped LangSmith self-hosting still needs outbound connections for license checks and usage reporting — [groundcover guide](https://www.groundcover.com/guides/self-hosted-llm-observability-security) (vendor-authored); consistent with the license and usage calls in [LangSmith docs](https://docs.langchain.com/langsmith/data-storage-and-privacy)
- Community requests for self-hosted alternatives to LangSmith, "to avoid cloud-based options", get Langfuse as the usual recommendation — [Latenode community](https://community.latenode.com/t/self-hosted-alternatives-to-langsmith-for-llm-monitoring/32654)
- OpenAI's own tracing is unavailable to Zero Data Retention organizations. That shows the trade-off buyers face today: either the platform keeps their traces, or they get no hosted tracing — [OpenAI](https://openai.github.io/openai-agents-python/tracing/)

### Inferences
- "Privacy" in this category means compliance badges and deployment location, never cryptography. An operator-blind claim stands out, but buyers are used to "never leaves your environment" meaning self-hosted. The pitch has to state precisely who holds keys, where decryption happens (on the user's devices), and what metadata the operator still sees.
- The pain points are concrete and citable:
  - Anyone with dashboard access can read prompts (Helicone #35).
  - Zero-trust deployments need trace encryption that goes beyond storage-level encryption (Phoenix #14707).
  - Redaction is brittle (Langfuse #3518 and vendors' own docs).
  - Long retention cancels zero-retention deals with model providers (Tian Pan).
  - Self-hosting means running ClickHouse, Postgres, Redis and S3, and patching CVEs such as Phoenix's CVSS 10.
- Against a Team plan whose agent-action feed only the team can read, observability vendors will argue richer analytics, evals and OTel coverage. The planned Team plan should answer on trust: a SaaS vendor, its acquirer's affiliates and its LLM sub-processors can all read the traces, while the team-keyed feed cannot be read by the operator.

### Gaps
- Searches did not surface Reddit or Hacker News threads about sensitive data in traces; the forum evidence comes from GitHub issues and one community forum. A targeted search of r/LocalLLaMA and r/LangChain is still needed.
- Arize AX, Datadog, Opik and Sentry homepage taglines and privacy copy were not captured verbatim.
