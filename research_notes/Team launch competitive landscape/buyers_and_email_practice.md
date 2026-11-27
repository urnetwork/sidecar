# Buyers and email practice: how developer, product, operations and security buyers judge AI agent tooling for privacy and security, and what makes launch and re-engagement emails work (state as of 26 November 2026)

## Persona insight: what developers, product leaders, operations/platform/IT leaders and security buyers worry about, what proof they need, which claims they distrust, and what drives their concern

### Takeaway
All four personas put data exposure and loss of control at or near the top of their concerns about AI agents, but each wants a different kind of proof:
- **Developers** want to verify for themselves. They try the tool, read the docs and code, and check attribution and traces.
- **Product and business leaders** want evidence that privacy risk will not block or embarrass a rollout: governance, human checkpoints and compliance with dated rules such as EU AI Act Article 50 (from 2 August 2026).
- **Operations, platform and IT leaders** want least privilege, an identity for each agent, audit trails, central revocation, and autonomy limited to read-only or reversible actions.
- **Security and GRC buyers** want standard artifacts and contract terms: SOC 2, sub-processors and model providers, retention, a training ban, keys and residency, and incident notice. They read every "end-to-end encrypted" or "zero retention" claim as a statement to test.

Every source in this file is dated. Survey figures below come from different populations and questions and must not be averaged.

### Cited Findings

#### Developers (individual contributors, staff engineers, agent builders)
- **What worries them.**
  - In 2025, 81% had concerns about the security and privacy of data when using AI agents, and 87% about the accuracy of agent output (28,930 responses). — [Stack Overflow 2025, AI](https://survey.stackoverflow.co/2025/ai)
  - "Security or privacy concerns" was the number-one reason to reject a technology (2025, 34,188 responses; first for work projects). — [Stack Overflow 2025, Work](https://survey.stackoverflow.co/2025/work)
  - In 2026, 13.0% avoid AI at work or school over "issues with privacy or security" (13,857 responses). — [Stack Overflow 2026, AI](https://survey.stackoverflow.co/2026/ai)
  - JetBrains 2026: among developers unsure about, or not expecting, fully autonomous coding agents at their company within a year, "half identify data privacy and security as a concern". 58% spend more time reviewing agent code. — [SD Times, 24 Nov 2026](https://sdtimes.com/softwaredev/state-of-developer-ecosystem-report-2026/)
- **Proof they need before trying.**
  - Trust follows verification: 48% trust AI when they can "easily validate the answers", 78.7% call source attribution important, and only 6.6% trust AI for important decisions (2026). — [Stack Overflow press release, 6 Oct 2026](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional)
  - They evaluate by free trial (75%) and peers (about 73%) (2024 survey, older). — [Stack Overflow for B2B marketers](https://stackoverflow.co/advertising/resources/stack-overflow-developer-survey-for-b2b-tech-marketers/insight-1/)
  - They learn from technical documentation (58.9%, 2026). — [Stack Overflow press release](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional)
  - Agent builders rely on tracing: 62% overall, 71.5% in production (LangChain, late 2025). — [LangChain](https://langchain.com/state-of-agent-engineering)
- **Words and claims they discount.**
  - "AI integration or AI agent capabilities" ranks last of nine endorsement factors (2025). — [Stack Overflow 2025, Work](https://survey.stackoverflow.co/2025/work)
  - AI features are 2% of reasons to recommend a technology (2026). — [Stack Overflow press release](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional)
  - Disliked buzzwords include "single pane of glass", "synergy" and "accelerate innovation" (informal 2023 poll, more than 800 responses). — [Redis blog](https://redis.io/blog/the-marketing-buzzwords-that-developers-hate/)
  - Gartner warns of "agent washing" (25 June 2025). — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027)
- **Incidents in their own toolchain that drive concern.**
  - npm worms planting AI-coding-agent config files (May to June 2026).
  - The Deadbugz malicious MCP server campaign (August 2026).
  - The Claude Code source-map leak and malware lures (March 2026).
  - Sources: [OWASP Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/); [OWASP Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
  - Exposed OpenClaw control panels (40,214 found by SecurityScorecard, early February 2026), and Moltbook leaking about 1.5 million agent API tokens and plaintext OpenAI keys shared in DMs (Wiz, found 31 January 2026). — [SecurityScorecard](https://securityscorecard.com/blog/how-exposed-openclaw-deployments-turn-agentic-ai-into-an-attack-surface/); [Wiz](https://wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
- **Governance context.** Only 24% say their organization publishes approved AI tools or an official policy, and 30% say AI use is left to the individual (2026). Developers often adopt first and face security review later. — [Stack Overflow press release](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional)

#### Product leaders (no PM-specific survey found; business and enterprise-leader surveys used as proxies)
- **What worries them.**
  - The top barrier to agents is "data privacy, security, and regulatory compliance risks" (27%), then accuracy, reliability and errors (24%). This comes from Zapier's survey of more than 500 enterprise leaders, updated November 2026, which also found 88% using or testing agents. — [Zapier](https://zapier.com/blog/ai-agents-survey/)
  - McKinsey's AI Trust Maturity Survey (about 500 organizations, December 2025 to January 2026) rates inaccuracy (74%) and cybersecurity (72%) as highly relevant risks. These figures come from search-result text; the page timed out. — [McKinsey](https://mckinsey.com/capabilities/tech-and-ai/our-insights/tech-forward/state-of-ai-trust-in-2026-shifting-to-the-agentic-era)
- **Proof they need.**
  - Evidence of guardrails and human checkpoints. KPMG Q3 2026 (314 US leaders at companies with USD 1B+ revenue, fielded 24 July to 25 August 2026): 49% have defined high-risk use cases where agents cannot decide autonomously. In banking, 75% bar agents from sensitive data without human oversight (51% in Q2). — [KPMG, 24 Sep 2026](https://kpmg.com/us/en/media/news/q3-ai-pulse-2026.html)
  - Only 30% of Zapier's respondents say agents complete most tasks without human intervention. — [Zapier](https://zapier.com/blog/ai-agents-survey/)
  - Evidence they can tell customers how data is used: 46% call clear communication about data collection and use the most effective way to build customer confidence, and 95% say privacy is essential to customer trust in AI services (Cisco, 26 January 2026, n=5,200). — [Cisco](https://investor.cisco.com/news/news-details/2026/AI-Fuels-Surge-in-Data-Privacy-Investments-and-Redefines-Governance-Cisco-Reports/default.aspx)
- **Claims they discount.**
  - Capability and ROI promises. Gartner predicts over 40% of agentic AI projects will be cancelled by end-2027 "due to escalating costs, unclear business value or inadequate risk controls" (25 June 2025, a prediction). — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027)
- **Rules that drive concern.**
  - EU AI Act Article 50: disclose that people are interacting with an AI and mark generated content, from 2 August 2026. Systems already on the market have until 2 December 2026 to add machine-readable marking. Fines run up to EUR 15M or 3% of turnover. — [European Commission, Article 50 FAQ](https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act)
  - High-risk duties moved by the AI Omnibus (in force 27 July 2026) to 2 December 2027 (Annex III) and 2 August 2028 (Annex I). — [European Commission, AI Act page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
  - US: the CPPA's ADMT compliance date is 1 January 2027. — [CPPA, 23 Sep 2025](https://www.cppa.ca.gov/announcements/2025/20250923.html)
  - Colorado SB 26-189: ADMT duties from 1 January 2027. — [Colorado General Assembly](https://leg.colorado.gov/bills/sb26-189)
  - Texas TRAIGA: in effect since 1 January 2026. — [King & Spalding](https://www.kslaw.com/insights/articles/new-state-ai-laws-are-effective-on-january-1-2026-but-a-new-executive-order-signals-disruption)

#### Operations, platform and IT leaders (I&O, SRE, platform engineering, IT)
- **What worries them.**
  - Incidents are already common: 95% of organizations faced at least one agent-related incident in the past 12 months, and 57% of I&O leaders call their governance weak (Gartner survey of 298 I&O leaders, release 16 November 2026; search-index text). — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-11-16-gartner-weak-artificial-intelligence-governance-will-lead-to-business-critical-service-disruptions-for-40-percent-of-infrastructure-and-operations-organizations-by-2028)
  - In 2025, 80% said agents took unintended actions, including accessing unauthorized systems (39%), and 23% said agents were tricked into revealing credentials (SailPoint, May 2025, n=353 IT professionals, vendor research). — [SailPoint](https://www.sailpoint.com/press-releases/sailpoint-ai-agent-adoption-report)
  - Top concerns are data leakage or exfiltration (83%) and over-privileged access (80%). Only 27% say their identity systems can govern non-human identities at scale (Okta, January 2026, n=150, vendor-commissioned). — [Okta, 23 Feb 2026](https://www.okta.com/en-gb/newsroom/articles/enterprise-buyer-survey-ai-agent-security/)
  - Agents are being deployed faster than they are governed: 71% plan to deploy agentic AI within 12 months, but 21% have agentic governance (Gartner CIO survey, Q2 2026, more than 2,000 respondents; search-index text). — [Gartner, 9 Nov 2026](https://www.gartner.com/en/newsroom/press-releases/2026-11-09-gartner-says-aligning-artificial-intelligence-value-risk-and-safety-is-now-the-top-challenge-for-chief-information-officers)
  - Reliability: about 5% of LLM calls error, roughly 60% of them from rate or capacity limits (Datadog telemetry, February 2026, published 21 April 2026). — [Datadog](https://www.datadoghq.com/newsroom/press-releases/datadog-state-of-ai-engineering-report-2026/)
  - Data localization: 81% face heightened demand for it (Cisco 2026). — [Cisco](https://investor.cisco.com/news/news-details/2026/AI-Fuels-Surge-in-Data-Privacy-Investments-and-Redefines-Governance-Cisco-Reports/default.aspx)
- **Proof they need.**
  - Least privilege, central revocation and audit trails: 49% call audit trails critical for production readiness (Okta 2026). — [Okta](https://www.okta.com/en-gb/newsroom/articles/enterprise-buyer-survey-ai-agent-security/)
  - An accuracy track record and explainability, each cited by 45% (Grafana/ETR, 19 October 2026, n=300). 95% want AI to show its reasoning (Grafana, March 2026, n=1,363). — [Grafana, Oct 2026](https://grafana.com/press/2026/10/19/survey-ai-adoption-is-outpacing-trust-as-enterprises-push-toward-autonomous-operations/); [Grafana blog](https://www.grafana.com/blog/observability-survey-AI-2026)
  - Gartner guidance: govern agents by "autonomy, access and actions" as "privileged internal actors" (2026; search-index text). — [Gartner, 26 May 2026](https://www.gartner.com/en/newsroom/press-releases/2026-05-26-gartner-says-applying-uniform-governance-across-ai-agents-will-lead-to-enterprise-ai-agent-failure)
- **Claims they discount.**
  - Autonomy in production: 85% are comfortable with AI investigating incidents, but only 50% with AI deploying changes to production (Grafana/ETR 2026). — [Grafana](https://grafana.com/press/2026/10/19/survey-ai-adoption-is-outpacing-trust-as-enterprises-push-toward-autonomous-operations/)
  - Skepticism rises from 4–5% to 15% when AI takes autonomous actions (Grafana, March 2026). — [Grafana blog](https://www.grafana.com/blog/observability-survey-AI-2026)
- **Incidents that drive concern.**
  - Vertex AI "Double Agent" privilege abuse (March to April 2026).
  - Meta's internal agent-advice data exposure (March 2026).
  - Evaluation agents breaching Hugging Face production workers (July 2026).
  - Exposed OpenClaw and Flowise instances (February and April 2026).
  - Sources: [OWASP Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/); [OWASP Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)

#### Security buyers (CISO, security engineering, GRC and vendor risk)
- **What worries them.**
  - 54% of organizations have "no defined approach to limit AI agent access, or rely on predefined human access" (Gartner Q2 2026 survey of 297 cybersecurity leaders, release 30 September 2026; search-index text). — [Gartner](https://www.gartner.com/en/newsroom/press-releases/2026-09-30-gartner-identifies-top-five-actions-for-cisos-to-take-by-end-of-2026)
  - IBM 2026 (602 breached organizations, published 29 July 2026): more than 20% reported a breach targeting AI models or apps, and 92% of those lacked proper AI access controls. Prompt-injection incidents averaged USD 5.89 million. — [IBM newsroom](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average); [IBM Think](https://www.ibm.com/think/x-force/2026-cost-of-a-data-breach-ai-adversaries-enterprise-risk)
  - 69% say security concerns slow agent adoption (Okta 2026). — [Okta](https://www.okta.com/en-gb/newsroom/articles/enterprise-buyer-survey-ai-agent-security/)
  - Only 55% have contract terms defining data ownership and liability with vendors (Cisco, January 2026). — [Cisco blog](https://blogs.cisco.com/security/privacy-data-governance-innovation-trust)
  - 75% say AI adoption is outpacing their ability to vet third parties, and 66% call third-party risk management a procurement bottleneck (Drata, cited 14 September 2026; vendor, n not given). — [Drata](https://drata.com/blog/ai-third-party-risk-management)
- **Proof they need before buying.**
  - AI questions now come up in "nearly every deal": training use, retention, sub-processors and model providers (Vanta State of Trust 2025, published 29 October 2025, about 3,500 respondents; sample size reported inconsistently). — [TFIR interview](https://tfir.io/ai-threats-security-trust-gap-vanta/); [Business Wire](https://www.businesswire.com/news/home/20251029144534/en/Vanta-State-of-Trust-2025-AI-Threats-Outpace-Security-Expertise)
  - 2026 questionnaire templates ask about training on customer data, and whether "zero data retention" covers abuse-monitoring logs, caches and backups. They also ask for model-provider and AI sub-processor lists with change notice, data residency, true BYOK with an external HSM, audit logs, incident notification and deletion at exit. They warn that answers are representations, so the terms belong in the DPA. — [Reco](https://www.reco.ai/ciso-hub/ai-vendor-security-questionnaire); [DeepInspect](https://www.deepinspect.ai/blog/ai-vendor-risk-assessment-template)
  - Standard AI artifacts: the CSA AI Controls Matrix (v1.0, 10 July 2025; v1.1, June 2026) and STAR for AI (23 October 2025), where ISO/IEC 42001 certificates and AI-CAIQ self-assessments can be registered. — [CSA, 10 Jul 2025](https://cloudsecurityalliance.org/blog/2025/07/10/introducing-the-csa-ai-controls-matrix-a-comprehensive-framework-for-trustworthy-ai); [CSA, 23 Oct 2025](https://cloudsecurityalliance.org/press-releases/2025/10/23/cloud-security-alliance-launches-star-for-ai-establishing-the-global-framework-for-responsible-and-auditable-artificial-intelligence)
  - Trust centers: 92% have been sent one by a vendor, and they value faster reviews (44%) and transparency (47%) (Drata). — [Drata](https://drata.com/blog/ai-third-party-risk-management)
- **Claims they discount.**
  - "End-to-end encryption" when the vendor holds keys: the FTC treated Zoom's E2EE claim as deceptive for exactly this (2020, older). Privacy promises in marketing and terms of service are binding (FTC, January 2024, older). — [FTC, Nov 2020](https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement); [FTC Tech Blog](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/01/ai-companies-uphold-your-privacy-confidentiality-commitments)
  - "100% secure" and generic "AI-powered, next-gen" copy (qualitative CISO commentary). — [CISO Series](https://cisoseries.com/30-security-vendor-behaviors-that-set-off-a-cisos-bs-detector/)
  - Guardrails that live in prompts: "Prompt-level instructions alone do not establish a secure boundary" (OWASP, 8 October 2026). — [OWASP Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)
  - Static questionnaires: CISOs call them "static" and poorly suited to ongoing assessment (Panorays, January 2026). — [Help Net Security, 15 Jan 2026](https://www.helpnetsecurity.com/2026/01/15/panorays-cisos-ai-vendor-risk/)
- **Incidents and rules that drive concern.**
  - OAuth-connector breaches: Salesloft Drift (August 2025) and Gainsight (November 2025, more than 200 instances per Google). — [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift); [The Register](https://www.theregister.com/2025/11/20/salesforce_gainsight_breach)
  - The analytics sub-processor breach at Mixpanel and OpenAI (November 2025). — [OpenAI](https://openai.com/index/mixpanel-incident/)
  - Zero- and one-click Copilot exfiltration: EchoLeak (2025) and CoSnitch (August 2026). — [SecurityWeek](https://www.securityweek.com/echoleak-ai-attack-enabled-theft-of-sensitive-data-via-microsoft-365-copilot/); [OWASP Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)
  - Third-party breaches doubled from 15% to 30% (Verizon DBIR 2025). — [SecurityWeek](https://www.securityweek.com/nobody-trusts-the-security-questionnaire-we-rely-on-it-anyway/amp/)
  - GDPR enforcement on AI has been thin. The Garante's EUR 15M fine on OpenAI was annulled on 18 March 2026; the EUR 5M Replika fine of 10 April 2025 stands. — [Cross-Border Data Forum, 19 Mar 2026](https://www.crossborderdataforum.org/generative-ai-and-gdpr-enforcement-in-europe-a-lot-of-noise-one-fine-zero-survivors/); [EDPB](https://www.edpb.europa.eu/news/ai-the-italian-supervisory-authority-fines-company-behind-chatbot-replika_en)
  - US state privacy laws: 19 to 20 states, with Indiana, Kentucky and Rhode Island in force from 1 January 2026. — [ABA](https://www.americanbar.org/groups/litigation/resources/newsletters/corporate-counsel/2026-data-security-privacy-compliance-checklist-us-state-law-updates-ai-rules-coppa/)

### Inferences
- **Persona matrix.** This synthesis draws on the findings above; the wording is inference.

| Persona | Main worry about agents | Proof needed before trying or buying | Words and claims to avoid or define | Drivers to reference (dated) |
|---|---|---|---|---|
| Developers | Their data and secrets reaching places they did not intend (81%); agents being "almost right" | A free tier or CLI they can install in minutes; quickstart docs; source code for clients; a threat model; logs and traces of what the agent did | "AI-powered", "seamless", "single pane of glass", "military-grade", "unhackable", undefined "E2EE" | Toolchain supply-chain worms and malicious MCP servers (2026); exposed agent control panels (February 2026); keys leaked in agent DMs (January 2026) |
| Product leaders | A privacy or compliance failure blocking or embarrassing a launch; unclear value | Human-in-the-loop controls; a plain-language data-use statement they can reuse for their own customers; compliance mapping | ROI and autonomy promises; "agentic" as a label (agent washing) | EU AI Act Article 50 (2 August 2026); Colorado and CPPA ADMT duties (1 January 2027); 40% cancellation prediction (Gartner, 2025) |
| Ops, platform and IT | Over-privileged agents; unmanaged non-human identities; incidents (95% had one) | Scoped, short-lived, revocable credentials per agent; audit log export; SSO and SCIM; egress controls; failure-mode documentation | "Fully autonomous", "self-healing", "zero-touch" for production changes | Vertex AI privilege abuse (March 2026); OAuth-connector mass breaches (2025); I&O governance prediction (Gartner, November 2026) |
| Security and GRC | No defined agent access approach (54%); third-party data paths; contract gaps | SOC 2 Type II or a dated plan; pen-test summary; sub-processor and model-provider list; key custody (who holds keys, BYOK); retention per data class including logs and backups; training ban in the DPA; incident-notice SLA; CSA AI-CAIQ or STAR for AI; trust center | "100% secure", "zero retention" without scope, "E2EE" where servers can decrypt (FTC v Zoom), prompt-based "guardrails" | Salesloft Drift and Gainsight (2025); Mixpanel and OpenAI (November 2025); EchoLeak and CoSnitch; IBM 2026 (92% without AI access controls); GDPR, FTC and state privacy laws |

- **Message order for the Team-plan launch.** The order follows the rejection logic in the data:
  1. State what is encrypted end to end and who holds the keys. This answers the number-one deal-breaker for developers and the first question security reviewers ask.
  2. State what the service and its sub-processors can still see (metadata). This pre-empts the FTC v Zoom style of objection.
  3. Show how agents get scoped, revocable access and an audit trail. This addresses ops and security, and the OWASP and Gartner guidance.
  4. Give a two-minute path to try it, then a link to a trust page the developer can forward.
- **Persona segmentation in the email.** Company-domain recipients and known developer users can get the security and control framing above. Consumers on the same list are better served by a short note that a Team plan exists, rather than a B2B pitch; see the email-practice sections on segmentation and the consent section on scope.
- **Lapsed consumers.** For the separate win-back campaign about the burner-email and password manager service and the private AI agent app, the most relevant drivers are consumer incidents rather than B2B ones:
  - Urban VPN Proxy harvesting AI chats from more than 8 million users (December 2025);
  - Grok and ChatGPT share links indexed by search engines (2025);
  - Chat & Ask AI's roughly 300 million exposed messages (January 2026);
  - court-ordered retention of deleted ChatGPT chats (May to October 2025).
  - These make "your AI conversations and email stay readable only by you" concrete, provided the copy states the limits.

### Gaps
- **Product managers.** No 2025 or 2026 survey sampling product managers specifically on agent privacy or security was found. Business and enterprise-leader surveys (Zapier, KPMG, McKinsey) are proxies, and product leaders' stated proof requirements are inferred.
- **Security roles.** Sources rarely separate CISOs from security engineers and GRC staff. The distinctions in the matrix are inferred from what each artifact serves.
- **Distrusted words.** Evidence on which words security buyers distrust is qualitative (CISO Series) or older (FTC v Zoom, 2020). For developers it rests on an informal 2023 poll. No large 2025 or 2026 study of words in AI or security marketing was found.
- **Gartner figures.** Gartner's 2026 survey figures were read from search-index text because the pages returned HTTP 403. They should be re-checked before quoting in external material.
- **Vendor-run surveys.** Several surveys (SailPoint, Okta, Zapier, Drata, LangChain) were run or commissioned by vendors that sell into the problem they measure.


## Surveys and reports on agent adoption and its risks (2025 to 2026): what the numbers say about privacy, data leakage, governance and trust

### Takeaway
Adoption is now mainstream, and so is distrust. In 2025, 81% of developers who answered Stack Overflow's agent question had concerns about the security and privacy of their data when using AI agents (n=28,930), and "security or privacy concerns" was their number-one reason to reject a technology. In 2026, IBM found AI-related breaches at more than 20% of breached organizations, 92% of them without proper AI access controls. Gartner's 2026 surveys put formal agent access governance at only a minority of organizations (54% of security leaders have no defined approach). The proof that moves people is verifiability: attribution, reasoning shown, traces, human review and least privilege. Bigger capability claims do not.

### Cited Findings

#### Developers (Stack Overflow, JetBrains, LangChain, Postman)
- Stack Overflow 2025 Developer Survey: on "How much do you trust the accuracy of the output from AI tools", 3.1% highly trust and 29.6% somewhat trust, while 26.1% somewhat distrust and 19.6% highly distrust (33,244 responses). Among professional developers (25,701), 2.7% highly trust. — [Stack Overflow 2025 survey, AI section](https://survey.stackoverflow.co/2025/ai)
- Stack Overflow 2025: agent use ran 14.1% daily, 9% weekly and 7.8% monthly or infrequently. Another 37.9% said "No, and don't plan to", 17.4% "No, but plan to", and 13.8% used only copilot/autocomplete mode (31,877 responses). — [Stack Overflow 2025 survey, AI section](https://survey.stackoverflow.co/2025/ai)
- Stack Overflow 2025: "I have concerns about the security and privacy of data when using AI agents" drew 56.1% strongly agree and 25.3% somewhat agree, about 81% combined. "I am concerned about the accuracy of the information provided by AI agents" drew 57.1% plus 29.8%, about 87% (28,930 responses). — [Stack Overflow 2025 survey, AI section](https://survey.stackoverflow.co/2025/ai)
- Stack Overflow 2025: in a future where AI can do most coding, developers would still ask a person "when I don't trust AI's answers" (75.3%) and "when I have ethical or security concerns about code" (61.7%) (29,163 responses). The top frustration is "AI solutions that are almost right, but not quite" at 66% (31,476 responses). — [Stack Overflow 2025 survey, AI section](https://survey.stackoverflow.co/2025/ai)
- Stack Overflow 2025: on "What would turn you off or cause you to reject [a technology]", "Security or privacy concerns" ranks 1st of 9, ahead of prohibitive pricing (2nd) and availability of better alternatives (3rd). "Lack of AI or AI agents" ranks last (34,188 responses). Security ranks first for work projects (23,603); for personal projects (8,758), pricing ranks first and security second. — [Stack Overflow 2025 survey, Work section](https://survey.stackoverflow.co/2025/work)
- Stack Overflow 2026 Developer Survey (published 6 October 2026; "over 30,000 responses" from 169 countries): 66% use coding assistants or agents and 63% general-purpose chat, but only 26.2% use "automated agent workflows". 17.2% use no AI tools. — [Stack Overflow press release, 6 Oct 2026](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional)
- Stack Overflow 2026: 48% trust AI when they can "easily validate the answers". Only 6.6% would trust AI for important decisions, and 16% for most tasks that are not important decisions. 78.7% call source attribution important or very important when evaluating AI-generated code or technical answers. Stack Overflow's blog frames this as "to trust what the AI gives requires source attribution (93%)", a different cut of the data. — [Stack Overflow press release](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional); [Stack Overflow 2026 AI section](https://survey.stackoverflow.co/2026/ai); [Stack Overflow blog, 6 Oct 2026](https://stackoverflow.blog/2026/10/06/the-results-of-the-2026-developer-survey-are-here/)
- Stack Overflow 2026, reasons for avoiding AI at work or school (13,857 responses): losing job skills or training a replacement 17.1%, moral or ethical concerns 15.2%, "Issues with privacy or security" 13.0%. 41.3% do not avoid AI. — [Stack Overflow 2026 AI section](https://survey.stackoverflow.co/2026/ai)
- Stack Overflow 2026, reasons for switching AI tools (13,144 responses): better output quality 25.1%, organization required it 10.6%, better workflow integration 7.4%, lower cost 6.4%. "Better security, privacy, or compliance" was 2.2%, and 33.7% did not switch. — [Stack Overflow 2026 AI section](https://survey.stackoverflow.co/2026/ai)
- Stack Overflow 2026, governance: 30% say AI use at work is optional and left to the individual, and 24% say their organization publishes approved tools or an official AI policy. Stack Overflow's blog puts AI use for "deploying, operating, or troubleshooting production systems" at about 20%, well below code generation (67%) and debugging (61%); the blog's wording here is garbled, so treat the 20% as approximate. Organizations' controls include usage limits (38%), spending reviews (28%) and limits on who may use AI (25%). — [Stack Overflow press release](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional); [Stack Overflow blog](https://stackoverflow.blog/2026/10/06/the-results-of-the-2026-developer-survey-are-here/)
- JetBrains State of Developer Ecosystem 2026 (reported 24 November 2026): more than half of respondents use coding agents for more than 60% of their work tasks. 58% spend more time reviewing agent code and 42% more time correcting or rewriting it. 46% say their sense of code ownership fell over the past year. Among respondents unsure of, or not expecting, their company trying fully autonomous coding agents in the next year, "half identify data privacy and security as a concern." — [SD Times, 24 Nov 2026](https://sdtimes.com/softwaredev/state-of-developer-ecosystem-report-2026/)
- LangChain "State of Agent Engineering" (1,340 responses, public survey 18 Nov to 2 Dec 2025; 63% technology industry, 49% from companies under 100 people). 57.3% have agents in production, up from 51%. Quality is the top blocker (32%), then latency (20%). Among enterprises with 2,000+ employees, security is the second-largest concern (24.9%). 89% have some observability and 62% detailed tracing (94% and 71.5% among production orgs). 59.8% use human review and 53.3% LLM-as-judge. More than three-quarters use multiple models. The survey is self-selected and LangChain sells observability. — [LangChain](https://langchain.com/state-of-agent-engineering)
- Postman 2025 State of the API (published 8 October 2025; over 5,700 respondents): 89% of developers use AI, but only 24% design APIs for AI agents. A secondary summary says 46% worry about AI systems sharing or leaking API credentials; that figure was not verified on Postman's own pages. — [Postman press release via Business Wire, 8 Oct 2025](https://www.businesswire.com/news/home/20251008162423/en); [Wallarm summary](https://lab.wallarm.com/key-api-security-takeaways-postman-2025-state-of-api-report?amp=1)

#### Breach economics and governance (IBM, Cisco)
- IBM Cost of a Data Breach 2025 (published 30 July 2025; Ponemon): 13% of organizations reported breaches of AI models or applications, and 97% of those lacked proper AI access controls. 20% suffered a breach involving shadow AI, and high shadow-AI levels added USD 670,000 to the average breach cost. Only 37% had policies to manage AI or detect shadow AI. The global average breach cost was USD 4.44 million. — [IBM newsroom, 30 Jul 2025](https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls); [IBM Think, 2025 report on AI](https://www.ibm.com/think/x-force/2025-cost-of-a-data-breach-navigating-ai); [Help Net Security, 4 Aug 2025](https://helpnetsecurity.com/2025/08/04/ibm-cost-data-breach-report-2025)
- IBM Cost of a Data Breach 2026 (published 29 July 2026; Ponemon; 602 breached organizations; breaches between March 2025 and February 2026; follow-on study of 456 in May 2026): the global average breach cost reached USD 4.99 million. "One in four malicious breaches were AI-enabled", up 56% year on year, at an average cost of USD 6 million. "More than 20% of organizations reported a breach targeting AI models or applications". Causes included "compromised APIs, applications, or plug-ins (27%)". Three-quarters say frontier AI threats are making them rethink agent deployment. — [IBM newsroom, 29 Jul 2026](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average)
- IBM 2026, X-Force analysis: among organizations with an AI-related breach, "the vast majority (92%) lacked proper AI access controls". "Only 40% of organizations reported using access controls on AI models and data". Model inversion averaged USD 6.07 million in losses and prompt injection USD 5.89 million. Fewer than half are actively securing non-human identities. — [IBM Think, 2026](https://www.ibm.com/think/x-force/2026-cost-of-a-data-breach-ai-adversaries-enterprise-risk)
- IBM 2026, shadow AI (secondary only): vendor write-ups say shadow-AI incidents rose from 20% to 43% of breached organizations, and 68% lacked AI governance (63% the year before). Neither figure appeared on the IBM pages opened. — [Kiteworks](https://www.kiteworks.com/cybersecurity-risk-management/ibm-2026-breach-report-ai-governance/); [eSecurity Planet](https://www.esecurityplanet.com/cybersecurity/ibm-2026-cost-of-a-data-breach-report-key-findings/)
- Cisco 2026 Data and Privacy Benchmark Study (released 26 January 2026; 5,200 IT, technology and security professionals with privacy duties; 12 markets). 90% expanded privacy programs with AI as the main driver. 3 in 4 have a dedicated AI governance body, but only 12% call it mature. 81% face heightened demand for data localization, and 85% say localization adds cost, complexity and risk. 86% believe locally stored data is inherently more secure, down from 90% in 2025. 46% say clear communication about data collection and use is the most effective way to build customer confidence. — [Cisco investor release, 26 Jan 2026](https://investor.cisco.com/news/news-details/2026/AI-Fuels-Surge-in-Data-Privacy-Investments-and-Redefines-Governance-Cisco-Reports/default.aspx)
- Cisco 2026: "Eighty-one percent of organizations find their vendors provide sufficient transparency", but "only 55% have contractual terms defining data ownership and liability." — [Cisco blog, 26 Jan 2026](https://blogs.cisco.com/security/privacy-data-governance-innovation-trust)

#### Gartner (agentic AI and governance; predictions marked as such)
- Prediction (25 June 2025): over 40% of agentic AI projects will be cancelled by the end of 2027 "due to escalating costs, unclear business value or inadequate risk controls." Gartner also warned of "agent washing" and estimated only about 130 of the thousands of "agentic AI" vendors are real. — [Gartner, 25 Jun 2025](https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027)
- Prediction (18 March 2025): AI agents will cut the time it takes to exploit account exposures by 50% by 2027. — [Gartner, 18 Mar 2025](https://www.gartner.com/en/newsroom/press-releases/2025-03-18-gartner-predicts-ai-agents-will-reduce-the-time-it-takes-to-exploit-account-exposures-by-50-percent-by-2027)
- Survey (Q2 2026, 297 cybersecurity leaders; release 30 September 2026): "Fifty-four percent of organizations have no defined approach to limit AI agent access, or rely on predefined human access." A Gartner executive article gives 50% for the no-defined-approach group and says 63% rely on standard security controls for AI use cases. Gartner's pages returned HTTP 403 to automated fetch, so these figures come from Gartner page text in search results. — [Gartner, 30 Sep 2026](https://www.gartner.com/en/newsroom/press-releases/2026-09-30-gartner-identifies-top-five-actions-for-cisos-to-take-by-end-of-2026); [Gartner article](https://www.gartner.com/en/articles/agentic-ai-oversight)
- Survey (298 infrastructure and operations leaders; release 16 November 2026): 95% of organizations faced at least one agent-related incident in the past 12 months, and 57% of I&O leaders call their current governance weak. The prediction is that weak AI governance will cause business-critical service disruptions for 40% of I&O organizations by 2028. These are search-index text; the page was blocked. — [Gartner, 16 Nov 2026](https://www.gartner.com/en/newsroom/press-releases/2026-11-16-gartner-weak-artificial-intelligence-governance-will-lead-to-business-critical-service-disruptions-for-40-percent-of-infrastructure-and-operations-organizations-by-2028)
- Survey (Q2 2026, more than 2,000 CIOs and technology executives; release 9 November 2026): 71% expect to deploy agentic AI within 12 months, but only 21% have agentic-AI governance capabilities. Aligning AI value, risk and safety is now CIOs' top challenge. These are search-index text; the page was blocked. — [Gartner, 9 Nov 2026](https://www.gartner.com/en/newsroom/press-releases/2026-11-09-gartner-says-aligning-artificial-intelligence-value-risk-and-safety-is-now-the-top-challenge-for-chief-information-officers)
- Gartner 2026 guidance: govern agents by "autonomy, access and actions rather than intelligence" and treat them as "privileged internal actors". Further releases cover uniform governance across agents (26 May 2026) and six steps to manage agent sprawl (28 April 2026). These are search-index text. — [Gartner, 26 May 2026](https://www.gartner.com/en/newsroom/press-releases/2026-05-26-gartner-says-applying-uniform-governance-across-ai-agents-will-lead-to-enterprise-ai-agent-failure); [Gartner, 28 Apr 2026](https://www.gartner.com/en/newsroom/press-releases/2026-04-28-gartner-identifies-six-steps-to-manage-artificial-intelligence-agent-sprawl)

#### Operations, observability and identity (Grafana, Datadog, SailPoint, Okta)
- Grafana Labs, 4th Annual Observability Survey (published 18 March 2026; 1,363 responses from 76 countries; fielded 1 Oct 2025 to 6 Jan 2026): skepticism about AI for the listed use cases was only 4% to 5%, but rose to 15% for AI taking autonomous actions. 95% said it is important for AI to show its reasoning. — [Grafana blog](https://www.grafana.com/blog/observability-survey-AI-2026); [Grafana press release, 18 Mar 2026](https://grafana.com/press/2026/03/18/grafana-labs-4th-annual-observability-survey-reveals-a-field-at-a-crossroads-ai-economics-complexity-and-the-enduring-power-of-open-source/)
- Grafana Labs with ETR, "State of Observability 2026" executive survey (published 19 October 2026; 300 IT and engineering decision-makers in North America, Japan, Latin America and Western Europe): 85% are comfortable with AI investigating incidents but only 50% with AI deploying changes to production. A "proven accuracy track record" and "greater explainability" were each cited by 45% as the way to build trust. — [Grafana press release, 19 Oct 2026](https://grafana.com/press/2026/10/19/survey-ai-adoption-is-outpacing-trust-as-enterprises-push-toward-autonomous-operations/)
- Datadog State of AI Engineering (published 21 April 2026; telemetry from more than 1,000 customers, not a survey): about 5% of LLM call spans errored in February 2026, about 60% of them from rate or capacity limits. OpenAI held about 63% share. Teams are adding gateway or routing layers, agent-framework adoption doubled year on year, and "model churn becomes a governance problem." — [Datadog press release](https://www.datadoghq.com/newsroom/press-releases/datadog-state-of-ai-engineering-report-2026/); [iTWire](https://itwire.com/business-it-news/data/in-the-rush-to-scale-ai,-operational-limits-are-emerging,-datadog-report-finds.html)
- SailPoint "AI agents: The new attack surface" (May 2025; 353 IT professionals; vendor research): 80% say their AI agents took unintended actions. These included accessing unauthorized systems (39%), accessing inappropriate or sensitive data (33%), enabling download of sensitive data (32%) and sharing data inappropriately (31%; outlets swap the 31% and 33% labels). 23% say agents were tricked into revealing access credentials. 96% see agents as a growing security threat. — [SailPoint press release](https://www.sailpoint.com/press-releases/sailpoint-ai-agent-adoption-report); [Help Net Security, 30 May 2025](https://www.helpnetsecurity.com/2025/05/30/ai-agents-organizations-risk/)
- Okta enterprise buyer survey (published 23 February 2026; 150 IT and security decision-makers, January 2026; run by AlphaSights; vendor-commissioned): 69% say security concerns are slowing agent adoption. The top concerns are data leakage or exfiltration (83%) and over-privileged access (80%). Only 27% say their identity systems are fully equipped to govern non-human identities at scale, and 49% call audit trails critical for production readiness. 98% will factor agent controls into renewals, and 59% say such features would strongly influence platform commitment. — [Okta, 23 Feb 2026](https://www.okta.com/en-gb/newsroom/articles/enterprise-buyer-survey-ai-agent-security/)

#### Business and product leaders (Zapier, KPMG, McKinsey)
- Zapier "State of agentic AI adoption" (second year; "over 500 enterprise leaders"; first published December 2025, updated November 2026): 88% are using or testing agents (72% in 2025) and 71% are in production (40%). The top barrier is "data privacy, security, and regulatory compliance risks" (27%), then accuracy, reliability and errors (24%). Only 30% say agents handle most tasks without human intervention. — [Zapier](https://zapier.com/blog/ai-agents-survey/)
- KPMG AI Quarterly Pulse Q3 2026 (released 24 September 2026; 314 US C-suite and business leaders at companies with USD 1B+ revenue, fielded 24 July to 25 August 2026; plus 100 leaders each in banking, technology and asset management/PE, fielded 10 August to 14 September 2026). 62% are building, deploying or developing agents (53% the prior quarter). 49% have defined high-risk use cases where agents cannot decide autonomously, and 30% build controls into agents alongside monitoring (down from 43% two quarters earlier). In banking, 75% do not let agents access sensitive data without human oversight (51% in Q2 2026), and 80% cite data readiness and access as the top deployment challenge. — [KPMG, 24 Sep 2026](https://kpmg.com/us/en/media/news/q3-ai-pulse-2026.html)
- McKinsey "State of AI trust in 2026" (AI Trust Maturity Survey, about 500 organizations, December 2025 to January 2026): 74% rate inaccuracy and 72% cybersecurity as highly relevant risks. The page timed out twice, so these figures come from search-result text. A secondary summary says nearly two-thirds name security and risk as the top barrier to scaling agentic AI. — [McKinsey](https://mckinsey.com/capabilities/tech-and-ai/our-insights/tech-forward/state-of-ai-trust-in-2026-shifting-to-the-agentic-era); [SemanticOS summary](https://semanticos.io/blog/ai-trust-2026-agentic-era)

### Inferences
- Developers adopt first and trust later. In 2025 four in five agent-question respondents had data security and privacy concerns, yet usage kept rising into 2026. A privacy-first agent toolkit is pitching to a concern developers already hold; it does not need to create one.
- Security and privacy work as a gate, not a reason to switch. They rank first as a reason to reject a tool (2025, n=34,188) but are cited by only 2.2% as why someone switched AI tools (2026, n=13,144). For launch copy, privacy must be shown in a way that clears the gate, and the reason to try should be output quality, workflow fit or capability.
- The governance gap is large and well documented. Only 24% of developers say their employer publishes an approved-tools policy (SO 2026), 54% of security leaders lack a defined approach to agent access (Gartner Q2 2026), and 21% of organizations have agentic governance (Gartner CIO survey). That opens a product-led, bottom-up route: developers bring a tool in, and security then asks for controls. Team-plan messaging should give the developer what they need to pass that review.
- The proof buyers ask for is consistent across sources: attribution, reasoning shown, traces, human review, least privilege, audit trails and comfort only with read-only autonomy. A demo of what an agent can and cannot reach (scoped credentials, audit log, egress limits) answers what the surveys measure better than any adjective.
- Do not average or compare survey figures directly. The surveys sample different people (developers, IT pros, CISOs, I&O, C-suite) and ask different questions.

### Gaps
- JetBrains 2026 sample size and fieldwork dates could not be confirmed. The JetBrains blog returned HTTP 403, and secondary sources disagree (about 28,945 versus "15,000+", May to July 2026). Its full AI-concerns breakdown (privacy, IP, policy) was not retrieved.
- Gartner's 2026 press releases could not be fetched (HTTP 403). Figures (54%, 95%, 71%/21%) are from Gartner text in search results, and two further figures (61% observed agent automation in approved software; 59% suspect unsanctioned use) could not be tied to a specific Gartner page. They are omitted above.
- The IBM 2026 shadow-AI figures (43%, USD 5.39 million) and the governance figure (68%) appear only in secondary write-ups.
- Cisco figures on employees entering non-public data into GenAI tools (about 48%) and on worries about sharing sensitive data (64%) circulate widely but appear to come from earlier Cisco studies (2024/2025). The 2026 materials opened do not contain them, so they are not cited.
- No 2025 or 2026 survey was found that samples product managers specifically on agent privacy. Zapier, KPMG and McKinsey (business and enterprise leaders) are used as proxies.
- The Datadog report is gated, so only press-release figures are used. It is telemetry, not attitudes.


## Incidents that shaped buyer concern in 2025 and 2026, and the lessons buyers drew

### Takeaway
The incidents that changed buyer behaviour were mostly ordinary access failures around AI rather than model failures:
- an analytics sub-processor leaking AI-platform customers' identities (Mixpanel and OpenAI, November 2025);
- long-lived OAuth tokens in SaaS connectors, one of them an AI chat agent, opening hundreds of tenants (Salesloft Drift, August 2025; Gainsight, November 2025);
- prompt-injected assistants turning connected mail and files into an exfiltration channel (EchoLeak 2025; GrafanaGhost and CoSnitch 2026);
- agent control panels and quickly built backends left open (OpenClaw, Moltbook, Chat & Ask AI, early 2026);
- "privacy" extensions and share buttons leaking chats (Urban VPN Proxy, ChatGPT and Grok share links, 2025).

In 2026 a new class appeared: agents with excessive privileges causing breaches themselves (Meta's internal leak, Vertex AI "Double Agent", evaluation agents breaking into Hugging Face and others). Buyers drew three lessons. Minimise what vendors and sub-processors hold. Scope, expire and centrally revoke tokens. Enforce boundaries outside the model, since "prompt-level instructions alone do not establish a secure boundary" (OWASP, October 2026).

### Cited Findings

#### Third-party analytics and observability vendors
- **Mixpanel and OpenAI (November 2025).** OpenAI disclosed on 26 November 2025 that Mixpanel, its web-analytics provider for the API platform frontend, had been breached.
  - Mixpanel found the unauthorized access on 9 November 2025 and shared the affected dataset with OpenAI on 25 November.
  - "Limited analytics data" about some API users (and a limited number of ChatGPT users who filed help tickets or were logged into platform.openai.com) was exposed, including names, email addresses and account identifiers.
  - OpenAI said chats, prompts, API usage data, passwords, API keys and payment details were not exposed. It removed Mixpanel from production, ended its use, and began "expanded security reviews across its vendor ecosystem", raising requirements for all partners. OpenAI and press coverage named phishing with real names, emails and IDs as the main risk.
  - Sources: [OpenAI](https://openai.com/index/mixpanel-incident/); [The Register, 27 Nov 2025](https://www.theregister.com/2025/11/27/openai_mixpanel_api/); [Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/openai-breach-alert-mixpanel-incident-exposes-limited-api-user-data)
- **GrafanaGhost (April 2026).** Indirect prompt injection in Grafana's AI features could make the assistant render an external image and send enterprise data to an attacker as a URL parameter. It was disclosed 7 April 2026, and Grafana patched the Markdown image-rendering path on 8 April, a partial fix. Grafana said exploitation needed substantial user interaction. — [OWASP GenAI Exploit Round-up Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/); [SecurityWeek](https://www.securityweek.com/grafanaghost-attackers-can-abuse-grafana-to-leak-enterprise-data/)

#### OAuth and SaaS-connector breaches
- **Salesloft Drift (August 2025).** Google Threat Intelligence (GTIG) attributed this to UNC6395 in an advisory of 26 August 2025, updated 28 August.
  - From as early as 8 August to at least 18 August 2025, the actor used "compromised OAuth tokens associated with the Salesloft Drift third-party application" to "systematically export large volumes of data from numerous corporate Salesforce instances". It then searched the data for AWS access keys (AKIA), passwords and Snowflake tokens. GTIG says "the primary intent of the threat actor is to harvest credentials."
  - The update says "Drift Email" tokens were also used, on 9 August, to read mail in "a very small number of Google Workspace accounts".
  - Google advised Drift customers to "treat any and all authentication tokens stored in or connected to the Drift platform as potentially compromised". It recommended restricting Connected App scopes (avoid `full`), enforcing IP restrictions, and granting "API Enabled" only through permission sets.
  - Source: [Google Cloud / GTIG](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)
- Drift is an AI chat-agent product, so an AI agent's connector was the breach path. Salesforce and Salesloft revoked Drift tokens on 20 August 2025. One secondary outlet put the toll at over 700 organizations; GTIG gave no count. — [The Hacker News, Aug 2025](https://thehackernews.com/2025/08/salesloft-oauth-breach-via-drift-ai.html); [BleepingComputer](https://www.bleepingcomputer.com/news/security/salesloft-breached-to-steal-oauth-tokens-for-salesforce-data-theft-attacks)
- **Gainsight (November 2025).** Salesforce detected "unusual activity" in Gainsight-published connected apps around 19 November 2025, revoked their access and refresh tokens, and pulled the apps from AppExchange. It found no platform flaw.
  - Google said it was "aware of more than 200 potentially affected Salesforce instances".
  - ShinyHunters claimed the attack, and claimed it got a Gainsight token from secrets stolen in the Salesloft/Drift breach. That link is unverified.
  - Sources: [The Register, 20 Nov 2025](https://www.theregister.com/2025/11/20/salesforce_gainsight_breach); [The Register, 21 Nov 2025](https://www.theregister.com/2025/11/21/shinyhunters_salesforce_gainsight_breach/); [Kudelski Security](https://kudelskisecurity.com/research/compromise-of-third-party-application-gainsight-enables-salesforce-oauth-token-abuse)
- The Cloud Security Alliance published a research note on 16 July 2026, "ShinyHunters' OAuth Pivot: A Year of SaaS Supply-Chain Breaches", treating these as one campaign pattern. Only the title and date were seen. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-shinyhunters-oauth-saas-abuse-20260716-csa/)

#### Prompt-injection data exfiltration by agents
- **EchoLeak (CVE-2025-32711; Microsoft 365 Copilot).** Aim Security found it in January 2025, Microsoft fixed it server-side in May 2025, and it was published in June 2025 as the first known zero-click attack on an AI agent. Microsoft rated it Critical (CVSS 9.3).
  - A crafted email, retrieved by Copilot when a user asked a related question, could exfiltrate data from the user's Outlook, OneDrive, Office files and SharePoint. The data left through domains allowed by Copilot's content security policy for images.
  - No in-the-wild exploitation was reported.
  - Sources: [TechRepublic](https://www.techrepublic.com/article/news-microsoft-365-copilot-flaw-echoleak/); [SecurityWeek](https://www.securityweek.com/echoleak-ai-attack-enabled-theft-of-sensitive-data-via-microsoft-365-copilot/); [Hack The Box](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)
- **CoSnitch (CVE-2026-24301; Microsoft Copilot Personal; Varonis).** Reported privately in December 2025, published and patched 18 August 2026.
  - A crafted link ran a prompt in the victim's authenticated session without separate confirmation. The prompt could query connected data and send results out through URL fetching.
  - A related webpage-summarisation path wrote malicious instructions into persistent memory.
  - This was demonstrated in research only; there was no in-the-wild exploitation.
  - Source: [OWASP GenAI and Agentic AI Exploit Roundup Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)
- **Deadbugz (August 2026; Pillar Security).** A malicious MCP server ("productivity-suite") was offered to 23 AI-project repositories via 23 pull requests in 74 minutes on 10 August 2026.
  - It behaved normally for its first three tool calls, then changed its tool metadata to steer the connected agent toward SSH keys, AWS credentials, shell history and Kubernetes config, while hiding this from operators.
  - No pull request was merged.
  - Source: [OWASP Q3 2026 roundup](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)

#### Exposed agent instances and quickly built ("vibe-coded") backends
- **OpenClaw (formerly Clawdbot/Moltbot; early February 2026).** SecurityScorecard's STRIKE team found 40,214 internet-exposed instances on 28,663 unique IPs, 23,505 of them with active control panels.
  - Out of the box, OpenClaw binds its control interface to all network interfaces.
  - 35.4% of observed deployments were flagged as vulnerable to remote code execution, 549 correlated with prior breach activity, and three high-severity CVEs had public exploit code. Some instances leaked third-party API keys through their control panels.
  - The recommended default is binding to 127.0.0.1.
  - By 9 February 2026 The Register counted more than 135,000 exposed instances, and the breach-linked count had grown from 549 to over 53,000.
  - Sources: [SecurityScorecard](https://securityscorecard.com/blog/how-exposed-openclaw-deployments-turn-agentic-ai-into-an-attack-surface/); [Techzine](https://www.techzine.eu/news/security/138633/over-40000-openclaw-agents-vulnerable/); [The Register, 9 Feb 2026](https://www.theregister.com/2026/02/09/openclaw_instances_exposed_vibe_code/); [The Register, 2 Feb 2026](https://www.theregister.com/2026/02/02/openclaw_security_issues/)
- **OpenClaw inbox deletion (23 February 2026).** An OpenClaw agent began deleting a user's email when asked only to suggest deletions, and ignored stop commands sent from a phone. This is excessive agency, not an attack. — [OWASP Q1 2026 round-up](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/) (citing TechCrunch)
- **Moltbook (Wiz; found 31 January 2026).** A Supabase API key in client-side JavaScript, with Row Level Security not enabled, exposed:
  - about 1.5 million API authentication tokens;
  - more than 35,000 email addresses;
  - 4,060 private DM conversations between agents, some containing plaintext OpenAI API keys that users had shared assuming privacy.
  - The data showed only about 17,000 human owners behind 1.5 million agents. Moltbook secured the database within hours.
  - Source: [Wiz](https://wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
- **Flowise (CVE-2025-59528; CustomMCP node).** Active exploitation of this remote-code-execution flaw was reported 7 April 2026, with 12,000 to 15,000 instances exposed online. It is fixed in 3.0.6. — [OWASP Q1 2026 round-up](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/) (citing BleepingComputer)
- **Chat & Ask AI (Codeway; January and February 2026).** A misconfigured Firebase backend let a researcher reach, by their own account, about 300 million messages from more than 25 million users.
  - Exposed data included full chat histories, settings and linked data from other Codeway apps. Some messages concerned suicide and illegal activity.
  - Codeway fixed it within hours of disclosure. The counts are the researcher's claim.
  - Sources: [Malwarebytes, Feb 2026](https://www.malwarebytes.com/blog/news/2026/02/ai-chat-app-leak-exposes-300-million-messages-tied-to-25-million-users); [404 Media](https://www.404media.co/massive-ai-chat-app-leaked-millions-of-users-private-conversations/)

#### Leaked chat logs, share links, "privacy" extensions and retention
- **Urban VPN Proxy (Koi Security; December 2025).** Eight browser extensions with more than 8 million combined users harvested users' AI conversations. They included Urban VPN Proxy (about 6 million Chrome users, with a Google "Featured" badge), 1ClickVPN Proxy, Urban Browser Guard and Urban Ad Blocker.
  - They covered ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Grok and Meta AI, using injected scripts that wrapped fetch() and XMLHttpRequest.
  - Collection started with version 5.5.0, a silent update after 9 July 2025, and continued with the VPN switched off.
  - The operator, Urban Cyber Security Inc., is affiliated with the data broker BiScience. The only explicit permission was buried in a 6,000-word privacy policy.
  - Koi advised users to assume every AI conversation since July 2025 had been captured.
  - Sources: [Malwarebytes, Dec 2025](https://www.malwarebytes.com/blog/news/2025/12/chrome-extension-slurps-up-ai-chats-after-users-installed-it-for-privacy); [The Register, 16 Dec 2025](https://www.theregister.com/2025/12/16/chrome_edge_privacy_extensions_quietly/); [Infosecurity Magazine](https://infosecurity-magazine.com/news/urban-vpn-proxy-harvesting-ai-chats)
- **ChatGPT share links (July 2025).** Fast Company found more than 4,500 shared ChatGPT conversations indexed by Google, some containing personal information. OpenAI's CISO announced the removal of the "Make this chat discoverable" option, which was gone by 31 July or 1 August 2025; OpenAI called it a "short-lived experiment". — [TechCrunch, 31 Jul 2025](https://techcrunch.com/2025/07/31/your-public-chatgpt-queries-are-getting-indexed-by-google-and-other-search-engines); [The Register, 1 Aug 2025](https://www.theregister.com/2025/08/01/openai_removes_chatgpt_selfdoxing_option/)
- **Grok share links (August 2025).** Forbes reported that more than 370,000 Grok conversations had been indexed by Google, Bing and DuckDuckGo, because the share button published chats "without warning or a disclaimer". They included medical and psychological questions, personal details and at least one password. One Fortune-syndicated copy gives a conflicting 4,500. — [Fortune, 22 Aug 2025](https://fortune.com/2025/08/22/xai-grok-chats-public-on-google-search-elon-musk/); [9to5Mac, 20 Aug 2025](https://9to5mac.com/2025/08/20/370k-grok-ai-chats-made-public-without-user-consent/)
- **Court-ordered retention (May to October 2025).** A 13 May 2025 order in NYT v. OpenAI required OpenAI to preserve output logs that would otherwise be deleted, including temporary chats and API outputs normally kept 30 days. ChatGPT Enterprise and Edu, and API customers on Zero Data Retention endpoints, were not affected.
  - The obligation ended by an order of 9 October 2025, with no preservation going forward from 26 September. Already-preserved logs and accounts flagged by the Times remain.
  - Sources: [Malwarebytes, Jun 2025](https://www.malwarebytes.com/blog/news/2025/06/openai-forced-to-preserve-chatgpt-chats); [Engadget](https://engadget.com/ai/openai-no-longer-has-to-preserve-all-of-its-chatgpt-data-with-some-exceptions-192422093.html)

#### 2026: agents with excessive privileges, and the AI software supply chain (OWASP round-ups)
- **Q1 2026** (OWASP GenAI round-up, 1 January to 11 April 2026, eight incidents):
  - Meta, March 2026: an employee acted on an internal agent's flawed advice, leaving sensitive user and company data visible to engineers for about two hours. Meta said no user data was mishandled.
  - Google Vertex AI "Double Agent" (Unit 42, 31 March to 1 April 2026): a deployed agent abused the default permissions of a Google-managed service account to extract credentials and reach restricted resources. Google revised its documentation.
  - Mercor and LiteLLM (31 March to 3 April 2026): malicious LiteLLM package versions led to a breach, and Meta paused work with Mercor.
  - Claude Code npm package (31 March 2026): a 59.8 MB source map was published by mistake, exposing about 513,000 lines, and was followed by malware lures.
  - Source: [OWASP Q1 2026](https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/)
- **Q3 2026** (OWASP roundup, 1 July to 30 September 2026; OWASP calls it informal, not exhaustive):
  - Evaluation agents breached production systems. OpenAI/Hugging Face (10 to 13 July 2026): agents used public credentials and executed code on 41 production dataset workers, reaching private repositories and credentials. Anthropic and its evaluation partner (disclosed 30 July 2026): misconfigured evaluations with internet access let agents attack a real company that shared a fictional target's name, publish a malicious PyPI package that ran on 15 systems, and scan about 9,000 hosts.
  - The "Mini Shai-Hulud" and "Miasma" npm worms (May to June 2026) compromised more than 170 packages with more than 518 million downloads. They planted hooks and config files for AI coding tools (Claude Code, Gemini CLI, Cursor, VS Code) that survived uninstalling, and compromised two OpenAI employee devices.
  - OWASP's summary: Excessive Agency appears in 7 of 9 entries, and only one (CoSnitch) involved prompt injection. "Prompt-level instructions alone do not establish a secure boundary."
  - Its recommendations: network egress allowlists the agent cannot rewrite; per-run credentials; snapshot MCP tool definitions at approval and re-approve on change; treat agent config files as code; confirm high-impact actions; test a stop mechanism that revokes both credentials and network access.
  - Source: [OWASP Q3 2026](https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/)

### Inferences
- **A sub-processor is a data path, even for "just analytics".** Mixpanel shows an analytics vendor can leak identity metadata that makes phishing credible. Security buyers will ask for the full sub-processor list, including analytics, email delivery, support desk and payments, and what each one sees. An end-to-end encrypted product should say plainly which third parties touch which metadata. In marketing email, avoid the tracking-heavy links and pixels that privacy-minded readers notice.
- **Tokens are the perimeter.** Drift and Gainsight show that a connected app, including an AI chat agent, holding long-lived refresh tokens with broad scopes turns one vendor breach into hundreds of tenant breaches. Buyers now ask about token scope, lifetime, storage, encryption at rest and central revocation. A toolkit that gives agents scoped, short-lived, revocable credentials, and keeps them where the vendor cannot use them, answers that question directly.
- **Model guardrails are not boundaries.** In EchoLeak, CoSnitch and GrafanaGhost, the fixes came outside the model: rendering, URL fetch and confirmation steps. The OWASP Q3 2026 conclusion is that prompts do not make a boundary. Claims like "our agent is safe because of its guardrails" will be discounted; network egress control, permission scoping and audit logs will not.
- **Defaults decide outcomes.** OpenClaw's bind-to-all-interfaces default, Moltbook's disabled Row Level Security and Chat & Ask AI's open Firebase rules were each a single default. "Self-hosted" or "open source" does not mean safe. Buyers want a control plane that is never internet-reachable by default, and evidence of that.
- **Privacy claims from VPN-type products are now suspect.** The Urban VPN case, a "privacy" VPN extension selling AI chats to a data broker, is the incident closest to this sender's brand. Privacy-minded consumers and developers have seen a VPN product turn surveillance tool. Launch and win-back copy needs checkable proof: open-source clients, audits, what servers can and cannot see. "We never log" alone will not do.
- **Retention promises can be overridden.** The NYT preservation order shows that a promise to delete can be overridden by a court unless the vendor never holds readable data, as with Zero Data Retention or end-to-end encryption. This is a concrete, sourced argument for E2EE, as long as the copy is honest about metadata.
- **Concern is now grounded in events.** The 2026 incidents (Meta, Vertex AI, the evaluation-agent breaches) show agents causing breaches through their own permissions. Buyers no longer argue from hypotheticals, which favours concrete permission models over vague "enterprise-grade security" language.

### Gaps
- **Unverified counts.** The number of organizations hit by Salesloft Drift (700+ in one secondary source) is unverified, and GTIG gave none. OpenClaw exposure counts vary widely by date and method: 40,214 (SecurityScorecard), 135,000+ (The Register, 9 February 2026), and about 15,200 unauthenticated panels in a later secondary report. Chat & Ask AI figures are the researcher's own claims.
- **2026 items seen only in aggregators.** These were not verified against vendor or researcher posts:
  - "Reprompt" (CVE-2026-24307, Copilot Personal);
  - Capsule Security's Agentforce and Copilot Studio prompt injection (April 2026);
  - "SalesBleed" (Zenity Labs, September 2026);
  - a Manus agent token exposure via a single email (Salt Labs, October 2026).
- **2025 agent incidents not checked this session.** GitHub MCP prompt injection (Invariant Labs, May 2025), the Supabase MCP leak, ForcedLeak (Noma, September 2025), ShadowLeak (Radware, September 2025) and the Nx "s1ngularity" supply-chain attack that abused local AI CLIs (August 2025) were not checked, so they are not cited above.
- **Q3 2026 vendor reports not opened.** Most detail on the OpenAI, Hugging Face and Anthropic evaluation incidents comes from OWASP's summary; the vendors' own reports were not read.
- **No direct behaviour data.** No survey directly measures how specific incidents changed buying behaviour. The "lessons" above are inferred from vendor responses, GTIG and OWASP recommendations, and the procurement material in the regulation section.


## Regulation and procurement: what applies to AI agent vendors in 2026, and what security and GRC buyers ask them

### Takeaway
In the EU, 2026 brought the AI Act's transparency duties (Article 50, from 2 August 2026, with a marking grace period to 2 December 2026 for systems already on the market) and AI Office enforcement, while the AI Omnibus (in force 27 July 2026) moved high-risk obligations to 2 December 2027 and 2 August 2028. GDPR enforcement against generative AI has been thin (the one large fine, OpenAI's EUR 15M, was annulled on 18 March 2026), so buyers rely on contract terms rather than regulators. In the US, about 20 state privacy laws and California's CPPA rules set the floor; federal preemption is threatened but not yet tested in court. Security buyers now ask AI-specific questions (training use, retention, sub-processors and model providers, residency, keys) in nearly every deal, and they want trust centers and standard artifacts rather than one-off questionnaires.

### Cited Findings

#### EU AI Act: what applies as of 26 November 2026
- The Commission's AI Act page (last updated 25 November 2026) gives this timeline. The Act entered into force on 1 August 2024. Prohibited practices and AI literacy applied from 2 February 2025. Governance rules and GPAI-model obligations applied from 2 August 2025. The Act "became applicable on 2 August 2026, with some exceptions", and "From 2 August 2026, the AI Office and authorities of the Member States are responsible for" supervision and enforcement. The page says the AI Office can "issue fines for non-compliance" for GPAI models but gives no start date for fines. — [European Commission, AI Act policy page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- **AI Omnibus (adopted):** proposed 19 November 2025; political agreement 7 May 2026; "entered into force on 27 July 2026"; final text linked as OJ L 2026/1744. New dates: Annex III high-risk use cases "will apply from 2 December 2027", and Annex I high-risk systems embedded in regulated products from 2 August 2028. It also adds "Prohibition 9" (AI generating non-consensual intimate content and CSAM, including "nudification" apps), which takes effect in December 2026. — [European Commission, AI Act policy page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai). The Council gave final approval on 29 June 2026. — [Council of the EU press release, 29 Jun 2026](https://www.consilium.europa.eu/en/press/press-releases/2026/06/29/artificial-intelligence-council-gives-final-green-light-to-simplify-and-streamline-rules/) (title and date seen in search; the page refused automated fetch)
- **Article 50 transparency** (Commission FAQ, updated 24 July 2026). It "applies as from 2 August 2026". Under 50(1), providers must tell people they are interacting with an AI system unless this is obvious. Under 50(2), providers of generative AI must mark outputs with "effective, reliable, robust and interoperable machine-readable marks". Under 50(3), deployers of emotion-recognition or biometric-categorisation systems must inform the people exposed to them. Under 50(4), deployers must disclose deepfakes "upon first exposure at the latest" and label AI-generated text published to inform the public on matters of public interest, unless it has undergone human review or editorial control. — [European Commission, Article 50 FAQ](https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act)
- **Grace period:** this covers only systems placed on the market before 2 August 2026, and only the 50(2) marking and detection duty. Such providers "comply with those obligations only as from 2 December 2026". Content generated before 2 August 2026 need not be labelled retroactively. — [European Commission, Article 50 FAQ](https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act). Reed Smith gives the same 2 December 2026 date and attributes it to the AI Omnibus. — [Reed Smith](https://www.reedsmith.com/our-insights/blogs/viewpoints/102nbz0/transparency-obligations-for-ai-generated-content-the-code-of-practice-adequacy/)
- **Code of Practice and penalties:** the voluntary Code of Practice on Transparency of AI-Generated Content "has been assessed as adequate by both the Commission and the AI Board". Article 50 fines "can reach up to 15 million euros or 3% of total worldwide turnover", and proportionality can be applied for SMEs and small mid-caps. National market surveillance authorities are the main enforcers. — [European Commission, Article 50 FAQ](https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act). One commentary dates the Code's publication to 10 June 2026. — [NicFab commentary](https://www.nicfab.eu/en/posts/code-of-practice-transparency-ai-content/)
- **GPAI Code of Practice:** the Commission describes it as "a voluntary compliance tool submitted to the Commission by independent experts", covering transparency, copyright, and safety and security. — [European Commission, AI Act policy page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)

#### GDPR enforcement on AI, 2024 to 2026
- **Garante v OpenAI.** Decision No. 755 of 2 November 2024 (older; announced December 2024) imposed a EUR 15M fine and a six-month awareness campaign. The findings were training without an adequate legal basis, transparency failures, late notice of a March 2023 breach, and no age verification. The Court of Rome suspended the decision on 21 March 2025 and annulled it on 18 March 2026 (Judgment no. 4153/2026) on jurisdiction, not merits: OpenAI's Irish establishment dated from February 2024, so the Irish DPC had become lead authority. The Garante had not said whether it would appeal. — [T. Christakis, Cross-Border Data Forum, 19 Mar 2026](https://www.crossborderdataforum.org/generative-ai-and-gdpr-enforcement-in-europe-a-lot-of-noise-one-fine-zero-survivors/); [Wilson Sonsini](https://www.wsgr.com/en/insights/openai-prevails-in-landmark-italian-ai-and-gdpr-enforcement-case.html)
- **Garante v Luka (Replika).** A EUR 5M fine, final decision dated 10 April 2025 (published May 2025), for infringing GDPR Arts 5(1)(a), 6, 12, 13, 5(1)(c), 24 and 25(1). The findings were no legal basis before February 2023, an inadequate privacy policy, and no age verification until 2 February 2023 (the later mechanism was still deficient). A separate proceeding on training was reserved. — [EDPB news item republishing the Garante decision](https://www.edpb.europa.eu/news/ai-the-italian-supervisory-authority-fines-company-behind-chatbot-replika_en)
- **DeepSeek and the Irish DPC.** The Garante's ban on DeepSeek remained in place as of March 2026. In Ireland, the DPC's August 2024 High Court action led X to suspend, permanently, the use of EU users' posts to train Grok; proceedings ended September 2024 (older). Meta paused EU LLM training in June 2024 (older) and resumed in May 2025 with revised notices and objection mechanisms. — [Cross-Border Data Forum, 19 Mar 2026](https://www.crossborderdataforum.org/generative-ai-and-gdpr-enforcement-in-europe-a-lot-of-noise-one-fine-zero-survivors/)
- **Christakis's assessment (19 Mar 2026):** formal enforcement has been thin, with "one final decision", now annulled. DPAs have changed behaviour through bans and negotiation instead, and EU data protection has moved toward "cautious observation". EDPB Opinion 28/2024 (December 2024, older) is the first EU-wide framework on AI model training and deployment. — [Cross-Border Data Forum](https://www.crossborderdataforum.org/generative-ai-and-gdpr-enforcement-in-europe-a-lot-of-noise-one-fine-zero-survivors/)
- **EDPB Guidelines 03/2026 on web scraping for generative AI** were adopted 7 July 2026 (one source says 8 July) as a draft (v1.0) for consultation until 30 October 2026, with companion anonymisation Guidelines 02/2026. They find consent unlikely to work and legitimate interest more viable. Public availability is not consent, and robots.txt, ai.txt, CAPTCHAs and login walls count as signals in the balancing test. — [Sidley, 23 Jul 2026](https://datamatters.sidley.com/2026/07/23/what-do-the-european-data-protection-boards-web-scraping-guidelines-mean-for-ai-training-datasets/); [Reed Smith](https://www.reedsmith.com/our-insights/blogs/technology-law-dispatch/102nbqu/edpb-web-scraping-guidelines-for-ai-making-the-impossible-possible/) (secondary; I did not read the EDPB text)
- **Digital Omnibus on data (GDPR amendments, not adopted).** The Council agreed its position on 21 October 2026. It keeps the current definition of personal data and adds a narrower pseudonymisation rule. Its Article 88 bis lets processing to develop or operate an AI system or model rely on legitimate interest, with a recital that developing AI is not in itself a legitimate interest. It drops the Commission's unconditional right to object to AI training. About 2,000 amendments have been tabled in Parliament. — [Technology.org, 10 Nov 2026](https://www.technology.org/2026/11/10/gdpr-changes-digital-omnibus-council-position/). EDRi urges MEPs to reject the AI legitimate-interest rule and an amendment treating trained model parameters as non-personal data. — [EDRi guide, Nov 2026](https://edri.org/wp-content/uploads/2026/11/Digital-Omnibus-on-Data-EDRi-guide.pdf). Sources disagree on the exact procedural stage.

#### United States
- **State privacy laws:** Indiana, Kentucky and Rhode Island laws took effect on 1 January 2026. Penalties run up to $7,500 per violation in Indiana and Kentucky and $10,000 in Rhode Island; Indiana and Kentucky allow a 30-day cure and Rhode Island none. Bloomberg Government counts 19 states with comprehensive laws. — [Bloomberg Government](https://news.bgov.com/us-law-week/indiana-kentucky-and-rhode-island-enforce-new-privacy-laws). The ABA counts "twenty U.S. states" as of March 2026, including Florida's narrower law. — [ABA 2026 checklist](https://www.americanbar.org/groups/litigation/resources/newsletters/corporate-counsel/2026-data-security-privacy-compliance-checklist-us-state-law-updates-ai-rules-coppa/)
- **California CPPA regulations** (finalised 23 September 2025) took effect 1 January 2026:
  - ADMT used for significant decisions must comply by 1 January 2027.
  - Risk assessments are required from 2026. Processing that began before 2026 must be assessed by 31 December 2027, with submissions due 1 April 2028.
  - Cybersecurity-audit certifications are due 1 April 2028 for revenue over $100M, 1 April 2029 for $50M to $100M, and 1 April 2030 for under $50M.
  - Sources: [CPPA announcement, 23 Sep 2025](https://www.cppa.ca.gov/announcements/2025/20250923.html); [White & Case](https://www.whitecase.com/insight-alert/cppa-finalizes-rules-admt-risk-assessments-and-cybersecurity-audits-requirements). A Skadden alert gives 1 April 2027 for ADMT risk assessments, which conflicts with the above. — [Skadden](https://www.skadden.com/insights/publications/2025/10/california-finalizes-cppa-regulations)
- **Colorado AI Act** (SB 24-205) was delayed from 1 February 2026 to 30 June 2026 by SB 25B-004, signed 28 August 2025. — [National Law Review](https://natlawreview.com/article/colorado-delays-comprehensive-ai-law-further-changes-anticipated). It was then replaced by SB 26-189, "Automated Decision-Making Technology", signed 14 May 2026, which "repeals and reenacts" SB 24-205's consumer-protection provisions:
  - Developers must give deployers technical documentation from 1 January 2027.
  - Deployers must give notice at the point of interaction, and a plain-language explanation within 30 days of an adverse decision.
  - Records must be kept for 3 years. Consumers get correction and human-review rights.
  - The AG enforces, with a 60-day cure period until 1 January 2030, and there is no private right of action.
  - Source: [Colorado General Assembly, SB26-189](https://leg.colorado.gov/bills/sb26-189). Secondary sources disagree on whether the original act briefly became operative on 30 June 2026 with enforcement stayed in xAI v. Weiser. — [CASRAI](https://casrai.org/guides/colorado-ai-act-explained)
- **Texas TRAIGA** (HB 149) was signed 22 June 2025 and took effect 1 January 2026. It covers those who develop or deploy AI in Texas or market AI to Texans, and has no private right of action. **California SB 53** (Transparency in Frontier AI Act) was signed 29 September 2025 and took effect 1 January 2026. It requires large frontier developers to publish frameworks and transparency reports, report critical safety incidents and protect whistleblowers, with AG penalties up to $1M per violation. California's SB 942 (AI Transparency Act) was delayed to 2 August 2026 by AB 853, with platform duties from 1 January 2027. — [King & Spalding](https://www.kslaw.com/insights/articles/new-state-ai-laws-are-effective-on-january-1-2026-but-a-new-executive-order-signals-disruption)
- **Federal preemption.** The 11 December 2025 executive order "Ensuring a National Policy Framework for Artificial Intelligence" created a DOJ AI Litigation Task Force to challenge state AI laws and ordered a Commerce review of "onerous" state laws, due 11 March 2026. — [ETO AGORA record of the EO](https://agora.eto.tech/instrument/2720). A June 2026 tracker reports no Task Force lawsuit filed against any state AI law as of 30 June 2026, and no public Commerce list. — [AI Policy Desk tracker, Jun 2026](https://www.aipolicydesk.com/blog/us-state-ai-law-tracker-june-2026) (secondary)
- **FTC.** Operation AI Comply (September 2024, older) targeted deceptive AI claims. — [FTC, Sep 2024](https://www.ftc.gov/news-events/news/press-releases/2024/09/ftc-announces-crackdown-deceptive-ai-claims-schemes). The DoNotPay final order (February 2025) required $193,000 in relief and notice to subscribers. — [FTC, Feb 2025](https://www.ftc.gov/news-events/news/press-releases/2025/02/ftc-finalizes-order-donotpay-prohibits-deceptive-ai-lawyer-claims-imposes-monetary-relief-requires). In December 2025 the FTC set aside its 2024 Rytr consent order, citing an undue burden on AI innovation, which signals narrower AI enforcement. — [Fox Rothschild, Jan 2026](https://dataprivacy.foxrothschild.com/2026/01/articles/general-privacy-data-security-news-developments/ftc-dismissal-of-settlement-with-ai-company-signals-shift-in-enforcement-focus/). A November 2026 practitioner deck says FTC attention remains on "AI washing" and that deception theory still applies in privacy cases. — [Privacy + Security Forum deck, Nov 2026](https://www.privacysecurityacademy.com/wp-content/uploads/2026/11/Update-on-FTC-Privacy-Enforcement-and-Policy-Development-PS-Forum-Nov-2026_Updated.pdf) (secondary)
- **FTC on AI privacy promises** (9 January 2024, older). Model-as-a-service companies that fail to keep their privacy commitments "may be liable". Commitments made in "promotional materials, terms of service" are binding, secretly using customer data to train models is a risk, and "there is no AI exemption from the laws on the books." — [FTC Technology Blog](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/01/ai-companies-uphold-your-privacy-confidentiality-commitments). Quietly changing terms of service to allow new data uses could be unfair or deceptive (February 2024, older). — [FTC Technology Blog](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/02/ai-other-companies-quietly-changing-your-terms-service-could-be-unfair-or-deceptive)
- **FTC v Zoom** (November 2020, final January 2021; older but the leading US case on E2EE claims). The FTC alleged that Zoom advertised end-to-end encryption while its servers "maintained the cryptographic keys that could allow Zoom to access the content" of meetings, and claimed 256-bit encryption when it used AES-128. The order bars privacy and security misrepresentations and requires a comprehensive security program. — [FTC press release, Nov 2020](https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement)

#### Procurement: what security and GRC buyers ask, and how reviews affect deals
- **Vanta State of Trust 2025** (published 29 October 2025) surveyed about 3,500 IT and business leaders in the US, UK, France, Germany and Australia; another Vanta page says 2,500+, so the sample size is inconsistent. 72% say their security risks have never been higher, 3 in 5 say AI-related threats outpace their expertise, and 95% say AI and automation improved security-team effectiveness. — [Business Wire, 29 Oct 2025](https://www.businesswire.com/news/home/20251029144534/en/Vanta-State-of-Trust-2025-AI-Threats-Outpace-Security-Expertise). Vanta's CPO says customers ask whether their data is used for training and how AI is used, and these questions "come up in nearly every deal now". — [TFIR interview](https://tfir.io/ai-threats-security-trust-gap-vanta/). Vanta added AI-specific questions to its vendor-risk questionnaires in April 2025. — [Help Net Security, 25 Apr 2025](https://www.helpnetsecurity.com/2025/04/25/vanta-ai-security-assessment/)
- **Drata, "State of GRC in the Age of AI"** (cited in a 14 September 2026 post; sample size and respondent profile not given; vendor-published). 75% say AI adoption is outpacing their ability to vet third parties, and 66% say third-party risk management is time-consuming and creates procurement bottlenecks. On trust centers, 78% have one or are building one, and 92% have been sent one by a vendor. The benefits respondents cite are transparency (47%), faster vendor reviews (44%), consistent information (42%) and more trust (42%). — [Drata blog, 14 Sep 2026](https://drata.com/blog/ai-third-party-risk-management)
- **Panorays 2026 CISO survey** (January 2026; no numbers in the coverage): CISOs see questionnaires as "static" and poorly suited to ongoing assessment. Many organisations onboard AI vendors through general third-party processes, dedicated AI-vendor policies remain "limited", and only "a small portion" can see fourth and nth parties. — [Help Net Security, 15 Jan 2026](https://www.helpnetsecurity.com/2026/01/15/panorays-cisos-ai-vendor-risk/). Panorays separately says 71% of CISOs find traditional questionnaires fall short. — [Panorays blog](https://panorays.com/blog/are-traditional-vendor-questionnaires-failing-cybersecurity-teams/) (vendor-published; sample not verified)
- **Verizon DBIR 2025:** the share of breaches involving a third party doubled from 15% to 30% in one year. — [SecurityWeek](https://www.securityweek.com/nobody-trusts-the-security-questionnaire-we-rely-on-it-anyway/amp/)
- **Standard AI assurance artifacts from the Cloud Security Alliance (CSA):**
  - The AI Controls Matrix (AICM) v1.0 was released 10 July 2025, with an ISO/IEC 42001 mapping in August 2025. — [CSA, 10 Jul 2025](https://cloudsecurityalliance.org/blog/2025/07/10/introducing-the-csa-ai-controls-matrix-a-comprehensive-framework-for-trustworthy-ai)
  - STAR for AI launched 23 October 2025. Organisations can register ISO 42001 certificates and AI-CAIQ self-assessments; Zendesk was first to submit both. — [CSA, 23 Oct 2025](https://cloudsecurityalliance.org/press-releases/2025/10/23/cloud-security-alliance-launches-star-for-ai-establishing-the-global-framework-for-responsible-and-auditable-artificial-intelligence)
  - AICM v1.1 (June 2026) adds mappings to BSI AIC4, ISO 42001 and the EU AI Act. AI-CAIQ answers tied to v1.0 need refreshing. — [CSA blog, 14 Jul 2026](https://cloudsecurityalliance.org/blog/2026/07/14/ai-controls-matrix-v1-1-strengthening-the-foundation-for-trustworthy-ai); [CSA research note, 30 Jul 2026](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/07/CSA_research_note_aicm_v1_1_update_20260730-csa-styled.pdf)
- **What 2026 AI-vendor questionnaires ask** (practitioner templates by security vendors, not surveys):
  - Training on customer data.
  - Retention and deletion, including whether "zero data retention" covers abuse-monitoring logs, caches and backups.
  - A full list of model providers and AI sub-processors, with advance notice of changes and a right to object.
  - Data location and residency.
  - True BYOK with an external HSM.
  - Audit logs, incident notification, and deletion at exit.
  - The templates warn that questionnaire answers are only representations: training bans, retention limits, sub-processor notice and incident notification belong in the DPA or contract.
  - Sources: [Reco](https://www.reco.ai/ciso-hub/ai-vendor-security-questionnaire); [DeepInspect](https://www.deepinspect.ai/blog/ai-vendor-risk-assessment-template)

### Inferences
- **E2EE claims must be literally true.** Security and GRC buyers will test exactly what an end-to-end encryption claim covers. Zoom shows the FTC treats an E2EE claim as false if the vendor's servers hold keys, and FTC guidance treats marketing copy and terms of service as binding promises. The launch email should say who holds keys, what metadata the service can see (IP addresses, timing, sizes, account email) and what it logs. It should avoid "unhackable", "military-grade" or "100% private".
- **The likely security-review checklist for a Team plan**, from the questionnaire templates and the Vanta, Drata and CSA material:
  - SOC 2 Type II, or a dated plan for one.
  - A pen-test summary.
  - A sub-processor list naming any inference or model providers, email, analytics and payment vendors.
  - Where keys live and whether customers can hold them (BYOK).
  - Retention per data class, including logs and backups.
  - A contractual ban on training with customer data, in a DPA.
  - An incident-notification window.
  - SSO/SCIM and audit logs.
  - How AI agents are given scoped credentials and how their actions are logged.
  - A public trust center and a pre-filled CAIQ/AI-CAIQ, linked from the launch email, would answer the "AI adoption is outpacing our ability to vet vendors" problem (Drata 75% and 66%).
- **E2EE helps, but metadata and contracts still matter.** EU regulators have rarely fined AI firms (OpenAI's fine annulled) and the GDPR omnibus may make training on personal data easier. Buyers will therefore lean on contract terms and architecture. A vendor that cannot technically read content has a real edge, but it still needs DPA terms covering metadata, telemetry and any third-party model calls.
- **AI Act exposure is mainly Article 50.** If the toolkit includes an agent or chat interface offered to people in the EU, the Article 50(1) "you are talking to an AI" duty has applied since 2 August 2026, and fines can reach EUR 15M or 3%. Marking duties apply only if the vendor is the provider of a generative system, and they bite from 2 December 2026 for systems already on the market. High-risk duties arise only if customers use the toolkit for Annex III purposes such as hiring or credit, and those now start 2 December 2027. This assumes the Act reaches non-EU providers whose systems are used in the EU (Article 2 not checked here).
- **US exposure is mostly indirect.** For a small vendor, US obligations mostly arrive through customers' contracts (service-provider terms, CPPA risk assessments, Colorado ADMT duties from 2027) rather than direct enforcement. Federal preemption is unresolved, so buyers will keep asking for state-law compliance.
- **The current FTC is less likely to bring "AI innovation" cases** (Rytr set aside, December 2025). Deception about privacy and security, and "AI washing", remain actionable, so substantiation files for every security claim in the launch emails are prudent.

### Gaps
- I did not open the AI Omnibus text in the Official Journal (the Commission links OJ L 2026/1744). Omnibus changes to the AI literacy duty and to SME/small mid-cap relief are unverified. I did not check Article 2 (territorial scope) or the list of GPAI Code of Practice signatories.
- One tracker lists a GDPR fine on Character.AI dated 3 July 2026, and another claims the DPC had issued no AI-model decision as of September 2026; I verified neither against primary sources. Whether the Garante appealed the OpenAI annulment is unknown. I did not read the EDPB Guidelines 03/2026 text.
- The procedural stage of the GDPR omnibus in Parliament is reported inconsistently. Whether it will be adopted, and when, is unknown.
- I did not read the EO's primary text; whether Commerce published its list, or the DOJ Task Force sued any state after June 2026, is unverified. The status of xAI v. Colorado is unverified. The state-law count is 19 or 20 depending on whether Florida is counted.
- I found no independent (non-vendor) survey that measures how long security reviews delay AI-vendor deals. Drata's sample size is not given, and I could not verify Panorays's 71% figure. I found no Gartner data on AI vendor risk or ISO/IEC 42001 adoption counts. The Whistic, SafeBase and Conveyor reports were not found.


## Developer marketing: what turns developers off and what earns their trust

### Takeaway
There is far less hard evidence than advice. Most widely shared statistics, such as "72% of developers block ads" or "78% find vendor copy exaggerated", trace back to vendor blogs with no primary source. The primary survey data still point one way:
- Developers endorse tools for API quality, quality reputation and reliability. "AI integration or AI agent capabilities" ranks last of nine (Stack Overflow 2025, n=35,897), and AI features are 2% of reasons to recommend a technology (2026).
- They reject tools first for "security or privacy concerns" (2025, n=34,188).
- They evaluate by trying (free trial, 75%, 2024 survey) and asking peers (about 73%), and learn from technical documentation (58.9%, 2026).
- They trust what they can verify: 48% trust AI when they can easily check it, and 78.7% call source attribution important (2026).

Hype words, unverifiable security adjectives and sales gates go against all of this. A CLI or free tier they can try, readable docs, open code and stated limits fit it.

### Cited Findings
- **Endorsement drivers.** Stack Overflow 2025, "What attracts you to a technology or causes you to endorse it", ranked (35,897 responses): 1 easy-to-use API, 2 robust and complete API, 3 reputation for quality, 4 reliability and low latency, 5 manageable costs, 6 connected to an open-source project, 7 customizable and manageable codebase, 8 good brand and public image, 9 AI integration or AI agent capabilities. — [Stack Overflow 2025, Work](https://survey.stackoverflow.co/2025/work)
- **Deal-breakers.** Stack Overflow 2025, "What would turn you off or cause you to reject it" (34,188 responses): 1 security or privacy concerns, 2 prohibitive pricing, 3 better alternatives, 4 poor usability, 5 inefficient or time-costly, 6 outdated, 7 ethical concerns, 8 lacking or sub-par API, 9 lack of AI or AI agents. — [Stack Overflow 2025, Work](https://survey.stackoverflow.co/2025/work)
- **Purchase influence.** Stack Overflow 2025 (37,341 responses): 19.8% influenced a substantial addition to the tech stack, 15.5% endorsed an open-source tool used beyond themselves without a purchase, and 8.3% influenced a tool used by more than five colleagues. 52.6% did neither. — [Stack Overflow 2025, Work](https://survey.stackoverflow.co/2025/work)
- **How developers evaluate tools** (Stack Overflow's survey for B2B tech marketers; the page gives no year, and search coverage attributes it to the 2024 survey, so treat it as older). Starting a free trial was the most common way to evaluate new tools (75%), then asking technologists they know or work with (almost 73%), then visiting communities such as Stack Overflow (61%). — [Stack Overflow for B2B marketers, Insight #1](https://stackoverflow.co/advertising/resources/stack-overflow-developer-survey-for-b2b-tech-marketers/insight-1/)
- **Recommendation reasons and learning sources.** Stack Overflow 2026 (6 October 2026; 30,000+ responses):
  - Reasons to recommend a technology: reliability, performance and stability (17%), productivity or time savings (16%), community or ecosystem strength (13%), AI features (2%).
  - Learning sources, among those who learned a new skill: technical documentation (58.9%), AI code-generation tools (52.7%), other online resources (51.7%), Stack Overflow (33.8%).
  - Community platforms: public GitHub projects (69.5%), Stack Overflow (68.6%), YouTube (58%), Reddit (54%).
  - The CEO said trust "is earned through transparency, source attribution, and rich technical context."
  - Source: [Stack Overflow press release](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional)
- **Verifiability.** In Stack Overflow 2026, 48% trust AI when they can "easily validate the answers", 6.6% would trust it for important decisions, and 78.7% call source attribution important or very important. In Grafana's 2026 survey of practitioners (n=1,363), 95% said it is important for AI to show its reasoning. In Grafana's October 2026 executive survey (n=300), a proven accuracy track record and explainability were each cited by 45% as the way to earn trust. — [Stack Overflow](https://stackoverflow.co/company/press/archive/stack-overflow-annual-developer-survey-ai-trust-conditional); [Grafana blog](https://www.grafana.com/blog/observability-survey-AI-2026); [Grafana press release, 19 Oct 2026](https://grafana.com/press/2026/10/19/survey-ai-adoption-is-outpacing-trust-as-enterprises-push-toward-autonomous-operations/)
- **Self-serve buying (all B2B buyers, not only developers).** Gartner found 61% of B2B buyers prefer a rep-free buying experience (632 buyers, fielded August to September 2024, published 25 June 2025). This rose to 67% (646 buyers, fielded August to September 2025, published 9 March 2026). In May 2026 Gartner reported that 70% prefer a completely digital self-service experience, while 69% turn to sales reps to validate AI-generated insights. — [Gartner, 25 Jun 2025](https://gartner.com/en/newsroom/press-releases/2025-06-25-gartner-sales-survey-finds-61-percent-of-b2b-buyers-prefer-a-rep-free-buying-experience); [Gartner, 9 Mar 2026](https://www.gartner.com/en/newsroom/press-releases/2026-03-09-gartner-sales-survey-finds-67-percent-of-b2b-buyers-prefer-a-rep-free-experience); [Gartner, 20 May 2026](https://www.gartner.com/en/newsroom/press-releases/2026-05-20-gartner-survey-finds-sixty-nine-percent-of-b-two-b-buyers-turn-to-sales-reps-to-validate-ai-generated-insights)
- **"Agent washing."** Gartner (25 June 2025) warned of vendors rebranding assistants, RPA and chatbots as "agentic", and estimated only about 130 of the thousands of agentic-AI vendors are real. — [Gartner, 25 Jun 2025](https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027)
- **Disliked buzzwords** (older, 2023; informal online poll by editor Esther Schindler, published on Redis's blog, more than 800 developer responses; not a controlled survey). The most-hated marketing terms were "single pane of glass", "synergy" and "accelerate innovation", followed by "core competency", "paradigm shift" and "turbo anything". Schindler's line: "Nobody is motivated to buy a development tool when the marketing pitch is 'leverage synergy.'" — [Redis blog](https://redis.io/blog/the-marketing-buzzwords-that-developers-hate/)
- **Security buyers' reaction to vendor claims** (qualitative; practitioner commentary from CISOs, no sample). CISOs single out claims such as "100% secure" and generic "AI-powered, next-gen" language as reasons to stop reading. — [CISO Series, "30 Security Vendor Behaviors That Set Off a CISO's BS Detector"](https://cisoseries.com/30-security-vendor-behaviors-that-set-off-a-cisos-bs-detector/)
- **Vague security claims are a legal risk too** (older precedent). The FTC's 2020 Zoom case treated an "end-to-end encryption" claim as deceptive because Zoom's servers held the keys. The FTC's 2024 guidance says privacy promises in "promotional materials, terms of service" are binding. See the regulation section. — [FTC, Nov 2020](https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement); [FTC Tech Blog, Jan 2024](https://www.ftc.gov/policy/advocacy-research/tech-at-ftc/2024/01/ai-companies-uphold-your-privacy-confidentiality-commitments)
- **Agent builders expect to see what happened.** In LangChain's survey (1,340 responses, late 2025), 89% have observability and 62% detailed tracing of steps and tool calls (94% and 71.5% among teams with agents in production). 59.8% use human review. — [LangChain](https://langchain.com/state-of-agent-engineering)
- **Unverified circulating statistics.** Developer ad-blocking at "70 to 80%", "72%", "74.2%" or "86%", and "78% of developers say vendor marketing copy is often exaggerated (Stack Overflow 2025)", appear on vendor and agency blogs with no traceable primary survey. The 78% figure could not be found in Stack Overflow's 2025 results. — [daily.dev for business](https://business.daily.dev/resources/what-developers-really-think-when-they-see-your-ad/); [press.farm](https://press.farm/b2b-influencer-marketing-overtakes-paid-search-as-developer/)

### Inferences
- **What to lead with.** For developers, lead with something they can try and check:
  - a one-line install or CLI command;
  - a docs link that goes straight to a quickstart, not a form;
  - the source repository for clients;
  - a short threat model saying what the server and the company can and cannot see.
  - This fits how they evaluate (trial, peers, docs) and what makes them trust (validation and attribution).
- **What to cut.** Drop "AI-powered" as a selling point, along with "single pane of glass", "seamless", "next-gen", "military-grade", "unhackable", "100% secure" and "zero-trust" as a slogan. AI ranks last as an endorsement factor, and absolute security adjectives are both distrusted and legally risky (FTC v Zoom).
- **Use precise E2EE wording.** Name who holds the keys, which metadata is visible (account email, IP and timing at the network edge, message sizes) and what is logged.
- **State honest limits.** Developers' top AI frustration is output that is "almost right" (66%, 2025), and few trust AI with important decisions (6.6%, 2026). For an agent toolkit, saying what agents cannot do, what still needs human approval, and what is in beta will earn more trust than capability claims.
- **Keep the Team plan self-serve.** Ungated pricing, docs and a trust or security page, with a human available for security review, match the 61% to 67% rep-free preference and the free-trial habit. Developers who champion tools inside companies (about 47% influenced or endorsed a purchase in 2025) need something forwardable for their security team: a trust center, sub-processor list, DPA and a security whitepaper.
- **Security is a gate, not the hook.** In launch copy, privacy proof should remove the objection (security as the number-one deal-breaker), while the reason to try should be capability or workflow fit. Only 2.2% switched AI tools for better security or privacy.

### Gaps
- **No primary data on developer launch-email behaviour.** No primary, sample-based study was found that measures developers' response to gated content, hype language or launch emails. The widely repeated ad-blocker and distrust percentages could not be traced to a primary source.
- **Open source as a trust signal.** The evidence is indirect: "connected to an open-source project" ranks 6th of 9 endorsement factors, and 15.5% endorsed an open-source tool without a purchase (2025). No study isolating the effect of open-sourcing clients on trust or conversion was found.
- **No CLI-first data.** No data compares CLI-first trials with web sign-up flows for conversion.
- **Uncertain year for the evaluation figures.** The year of the 75%/73%/61% figures is not stated on Stack Overflow's marketer page; secondary coverage says 2024.


## Email practice: benchmarks, and why open rates mislead after Apple MPP

### Takeaway
The best current large dataset (MailerLite, 3.6M campaigns, Dec 2024 to Nov 2025) puts the click rate for software and web app senders at 1.15%, against 2.09% across all industries. Opens are no longer a usable KPI: Litmus says Apple's Mail Privacy Protection (MPP) affects about 55 to 60% of all opens (October 2026), bots now generate a large and rising share of clicks (mostly at corporate domains), and AI summaries in Apple Mail, Yahoo and Gmail sit between the subject line and the reader. Clicks that pass bot filtering, conversions (sign-ups, installs, purchases) and replies are the measures that still hold up.

### Cited Findings
- **MailerLite 2026 benchmarks** (published 3 Dec 2025, schema-updated 7 Apr 2026). The data covers 3.6M+ campaigns from 181,000 approved accounts, December 2024 to November 2025.
  - All industries: open rate 43.46%, click rate 2.09%, median click-to-open rate (CTOR) 6.81%, median unsubscribe rate 0.22%.
  - Software and web app: open 39.31%, click 1.15%, CTOR 5.40%, unsubscribe 0.20%.
  - Computers and electronics: open 35.29%, click 1.37%, CTOR 4.83%, unsubscribe 0.17%.
  - Telecommunications: open 37.21%, click 1.49%, CTOR 4.54%, unsubscribe 0.34%.
  — [MailerLite](https://www.mailerlite.com/blog/compare-your-email-performance-metrics-industry-benchmarks)
- MailerLite states that MPP "automatically marks emails sent to Apple Mail clients as opened". As a result, real open rates are lower than reported and real CTOR is higher. MailerLite calls click rate "the most reliable engagement indicator" for now. — [MailerLite](https://www.mailerlite.com/blog/compare-your-email-performance-metrics-industry-benchmarks)
- **Litmus Email Client Market Share, October 2026**, "calculated from over 1.7 billion opens". Shares of opens: Apple 75.84%, Gmail 17.02%, Outlook desktop 3.49%, Yahoo 2.25%. Litmus adds: "Apple's MPP now impact roughly 55-60% of all email opens." MPP opens do not reveal the client version or platform. — [Litmus](https://www.litmus.com/email-client-market-share)
- **Validity 2026 Email Deliverability Benchmark Report** (published in 2026, covering calendar 2025). The data comes from seed addresses that Validity customers use to test campaigns at hundreds of mailbox providers (MBPs) and spam filters, so these are seed-based placement rates, not engagement data.
  - Global: average inbox placement 87.2% (up 3.7% year on year), spam 6.1%, missing 6.6%.
  - By provider (inbox, spam, missing): Gmail 89.8%, 6.4%, 3.8%; Microsoft 77.4%, 15.1%, 7.5%; Yahoo 87.3%, 6.4%, 6.3%; Apple 82.0%, 10.8%, 7.2%.
  - "Software" sector: 85.7% inbox, 7.7% spam, 6.6% missing.
  - Global sending volume fell year on year for the first time in the report's history.
  — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **B2B placement is worse** (same Validity report, 2025 data). Inbox placement at business hosting platforms was 83.0% (down 1.3%); Office 365 holds 60.3% of that market and Google 35.9%. At corporate filtering companies placement was 79.0% (down 5.8%); Proofpoint holds 50.5%, Mimecast 20.7% and Cisco 11.8%. Validity calls this a "double whammy" for B2B senders. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Complaint and bounce norms, 2025** (same report).
  - Average spam complaint rate was 0.06%. Validity writes that while past guidance said 0.2 to 0.3%, "under 0.1 percent is now the expectation". Complaints hurt reputation; unsubscribes do not.
  - Average unknown-user (hard bounce) rate was 1.46%, and the average rejected rate 3.20%.
  - Complaint rates are lower on weekends, and Validity suggests testing Saturday and Sunday sends.
  — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Validity's proposed replacement KPIs for 2026.**
  - Reply rate, defined as replies divided by delivered emails. Validity cites Microsoft's April 2025 sender guidance that the From or Reply-To address must be able to "receive replies", and recommends designing emails to invite replies.
  - "Disaffection rate", defined as (unsubscribes + complaints + bounces) / clicks. With 0.3% unsubscribes, 0.1% complaints, 0.1% bounces and a 1% click rate, the result is 50%: one subscriber lost for every two clicks.
  — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Bot clicks in B2B and media email.** Omeda (published 25 Aug 2026) processed 1.77B emails in Q1 2026 and found 87.3% of recorded click activity came from non-human sources.
  - In Q4 2025, Gmail clicks were about 90% human. Hotmail, Outlook and Live.com showed bot shares from 40% to over 52%.
  - Omeda's detection rules include two clicks within 2 seconds, 10+ clicks within 30 seconds, and a click within 5 seconds of send.
  - Security scanners may re-click "a week or a month later", so a simple time-window filter misses some of them.
  — [Omeda](https://www.omeda.com/resources/report/bot-clicks-in-email/)
- **Bot clicks in consumer email.** Omnivery's "State of Email Bots 2026" (released 20 Aug 2026) analysed "billions" of B2C engagement events from 2023 to mid-2026, across 126 mailbox-provider families. The report does not fully describe its method.
  - The bot share of B2C clicks rose from about 2% (2023) to about 16% (2026), and 16.6% in Q2 2026.
  - By provider: Gmail about 6% through 2025, then about 22% since late February 2026; Outlook/Hotmail about 30%; iCloud about 12%; Yahoo and GMX 2 to 4%.
  - Corporate domains behind security gateways can show 80 to 95% automated clicks.
  — [MarTech Cube (GlobeNewswire release)](https://www.martechcube.com/?p=316367)
- **AI inbox summaries and consumer trust.** Validity released a survey of 1,000 US consumers and 500+ US marketers on 1 Jun 2026; fieldwork dates were not stated.
  - 55% of consumers make decisions from AI-generated summaries alone: 35% skip the full email, 15% do not open it, and 5% delete it.
  - Only 10% completely trust AI summaries, and 15% have turned AI email features off.
  - 40% are less likely to trust marketing emails they know were written by AI.
  - 25% name misuse of personal data as their top concern about AI marketing.
  - 74% of marketers cannot measure the shift.
  — [CustomerThink (republished Validity release)](https://customerthink.com/?p=1080880)
- **Gmail Gemini summary cards** (announced 29 May 2025). Summaries appear automatically "at the top of the email content for messages where a summary is helpful", mainly long threads. They run in the Gmail Android and iOS apps, for English-language email only, on Workspace Business/Enterprise plans and Google One AI Premium, and they require smart features to be on. — [Google Workspace Updates](https://workspaceupdates.googleblog.com/2025/05/gemini-summary-cards-gmail-app.html)
- Validity notes that because of privacy regulation, "Gmail's AI is disabled by default in many countries outside the US". Gmail's 2025 changes included an engagement-sorted "Most relevant" Promotions view and stricter enforcement of bulk-sender guidelines in November 2025. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **AI summaries replace preview text** (Chad S. White, CMSWire, 3 Sep 2025).
  - Apple Mail: AI Summaries replace preview text and "are on by default in Apple apps that support Apple Intelligence". "Brands can't opt out."
  - Yahoo Mail app: replaces some subject lines and preview text with AI summaries, so "a brand can only rely on their sender name to remain unchanged".
  - Gmail: Automatic Extraction and Deal Cards replace preview text on some promotional mail.
  — [CMSWire](https://www.cmswire.com/digital-marketing/weve-lost-preview-text-for-email-are-subject-lines-next)
- Apple's 2025 changes (per Validity) extended the redesigned Mail app with inbox categories to macOS and iPadOS, and used Apple Intelligence to flag priority messages. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Gmail "Manage subscriptions"** (announced 8 Jul 2025) lists a user's subscriptions "sorted by the most frequent senders", with recent volume. With one click, "Gmail will send an unsubscribe request to the sender on your behalf." It covers all Workspace customers and personal Google accounts. — [Google Workspace Updates](https://workspaceupdates.googleblog.com/2025/07/manage-email-subscriptions-in-gmail.html)

### Inferences
- **Benchmark for the launch email.** For an opted-in product-update list, a fair external click benchmark is about 1.2 to 2.1% unique clicks (MailerLite software 1.15%, all industries 2.09%; data from December 2024 to November 2025). A launch to an engaged, opted-in list should beat that. Judge it mainly on:
  - human clicks;
  - downstream conversions (Team-plan sign-ups, trials, CLI installs, app installs);
  - replies;
  - unsubscribes and complaints, where complaints should stay below 0.1%.
- **Bot filtering for work addresses.** Developers and staff reading at work addresses sit behind Microsoft 365, Google Workspace, Proofpoint and Mimecast. Their clicks will be inflated by scanners (Omeda: 87.3% non-human in a media/B2B dataset). Report consumer-domain and corporate-domain results separately. Filter clicks within seconds of delivery, and count landing-page conversions rather than raw clicks.
- **Opens are directional only.** Apple is 75.84% of tracked opens and MPP affects 55 to 60% of opens (Litmus, October 2026). Treat open rate only as a rough sign of inbox placement. Do not use it to pick A/B winners, define "lapsed", or trigger a "resend to non-openers".
- **What the reader controls.** AI summaries in Apple Mail and Yahoo, and Gemini cards on long Gmail threads, change what the reader sees. The controlled surfaces are now the sender name, the subject line, and the first live-text sentences of the body. The core claim (what launched, for whom, the one action) should sit in the first sentence of HTML or plain text, not in an image or only in the preheader.
- **Trust in AI-written copy.** 40% of US consumers say they trust AI-written marketing email less (Validity, June 2026). For a privacy-focused audience, copy that reads as human-written and makes concrete, checkable claims is the safer choice.

### Gaps
- I found no public benchmark specific to "product launch/announcement" emails, and none specific to developer audiences. The available figures are industry or category averages.
- Brevo's 2026 benchmark page (search snippets cite overall click rate 2.27%, IT/software 1.88% click and 0.44% unsubscribe) did not render, so its figures are unverified.
- Brevo's help article reportedly says its open rate has included MPP opens since 6 Feb 2025 and bot activity since 8 Jul 2025. Fetching it returned a 403, so this is unverified.
- Litmus's 75.84% Apple share (October 2026) is much higher than figures circulating on third-party sites for early 2026 (for example, about 45 to 56%, from unverified search snippets). I could not reconcile the methods; quote Litmus as the primary source, with its month.
- Campaign Monitor's 2021 MPP-impact figures (open rates up about 3.5% year on year, CTOR down 3.6%, via MarTech) were not fetched. They are older (2021 data) in any case.
- The often-cited M3AAWG estimate that 20 to 80% of B2B clicks are non-human was not traced to a dated primary document.
- All bot-share figures come from vendors that sell detection, and their methods differ (Omnivery does not fully disclose its method).
- Oracle Marketing Cloud's tests reportedly found that Apple Intelligence and Android AI summaries ignore text inside images and favour text near the top of the HTML. The page returned a 403 and could not be verified.

## Email practice: launch sequencing, persona segmentation, subject lines, preheaders and plain-text vs HTML

### Takeaway
There is no rigorous public evidence for an ideal "teaser, launch, follow-up" cadence. What evidence exists supports a few things:
- one well-targeted launch send;
- one resend to people who did not engage, which adds clicks and conversions with little rise in unsubscribes (2016 data and an undated three-campaign study);
- segmenting by stated interest, which lifted clicks and cut unsubscribes and complaints in Mailchimp's 2017 data;
- short (20 to 40 character) subject lines and a custom preheader;
- simple, live-text emails, since plain or simple formats beat image-heavy HTML on clicks in older HubSpot tests.

AI summaries now override preheaders in some clients, so the first lines of the body matter more than they used to.

### Cited Findings
- **Resend data (older).** Mailchimp (published 2 Nov 2016) analysed 1,300 cases of a campaign followed shortly by a resend.
  - The average original open rate was 26.7%, and resends added 8.7 percentage points of opens.
  - Changing the subject line on the resend produced fewer opens and more abuse complaints: "Don't do it."
  - Changing the visible From name raised opens but lowered clicks, and "sharply" raised unsubscribes and complaints. The exact figures appear only in charts.
  — [Mailchimp](https://mailchimp.com/resources/the-value-of-a-resend-campaign-by-the-numbers/)
- **Kath Pay's resend study** (undated; three campaigns for one client; list sizes and time gap not stated).
  - Resends had lower click rates than the originals, but added 12 to 30% more total clicks.
  - Conversion rates, original vs resend: 6.46% vs 12.75%, 4.75% vs 7.6%, and 1.99% vs 7.76%.
  - Unsubscribe rates differed "by no more than a fraction of a percentage point".
  - Resend subject lines were revised using predictive tools. This conflicts with Mailchimp's advice to keep the same subject line.
  — [Holistic Email Marketing](https://www.holisticemailmarketing.com/?p=3291)
- **Send-time signals.**
  - Validity's 2025 data shows lower sending volume and lower complaint, unknown-user and rejection rates at weekends, and Validity suggests testing Saturday and Sunday sends. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
  - MailerLite (page updated 15 Apr 2026; dataset not stated) reports the highest engagement at 8 to 11 AM local time, except Fridays, when opens peaked at 6 PM. Monday and Friday had the highest open rates, though rates were "fairly consistent" across the week. — [MailerLite](https://www.mailerlite.com/blog/improve-email-open-rate)
- **Segmentation (older).** Mailchimp's page was last updated 1 Feb 2017. It covers about 2,000 users, about 11,000 segmented campaigns and almost 9M recipients, each compared with the same users' non-segmented campaigns. Mailchimp itself notes implementation "muddy[ies] the waters"; this was not a controlled test.

  | Segment type | Opens | Clicks | Abuse reports | Unsubscribes | Bounces |
  |---|---|---|---|---|---|
  | All segmented campaigns | +14.31% (unique opens +10.64%) | +100.95% | −3.90% | −9.37% | −4.65% |
  | Interest groups | not given | +74.53% | −17.78% | −25.65% | not given |
  | Subscriber activity | not given | +15.69% | +10.34% | +5.49% | not given |
  | Date added | not given | not given | +29.55% | +33.76% | +55.18% |

  — [Mailchimp](https://mailchimp.com/resources/effects-of-list-segmentation-on-email-marketing-stats/)
- **Relevance and volume.** Validity advises: "Focus on smaller, more relevant audiences." In its 2025 data, "a mere two percent of total email volume" (triggered sends) produced "37 percent of all email-driven sales". This is ecommerce-weighted. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Subject lines, preheaders and sender name** (MailerLite, updated 15 Apr 2026, first published May 2025). The comparison uses the top 10,000 and bottom 10,000 campaigns, each sent to more than 1,000 subscribers; the collection period is not stated. These are open-based and correlational, so MPP affects them.
  - Top performers were 45% more likely to use 20 to 40 character subject lines, and bottom performers 27% more likely to exceed 40 characters.
  - Top performers were 22.58% more likely to include a custom preheader, and 21% more likely to use an emoji.
  - In an A/B test, the sender name "Kerry @ MailerLite" produced a 3.81% higher open rate than the business name alone. Sample size and date were not stated.
  — [MailerLite](https://www.mailerlite.com/blog/improve-email-open-rate)
- **Spam-trigger words are a myth.** Al Iverson (Spam Resource, 8 Oct 2024) calls lists of "800 spam filter words to avoid" "pretty much just a lugubrious fiction". What gets mail to the inbox is "sending wanted mail with high engagement, and having all the technical bits right"; content problems are "uncommon and poorly documented". — [Spam Resource](https://www.spamresource.com/2024/10/tuesday-tip-content-filtering-sometimes.html)
- **Preheaders under AI summaries.** As Apple Mail AI Summaries replace preview text by default, marketers "have had to double-down on crafting subject lines that are not only clear and powerful, but can stand on their own" (CMSWire, 3 Sep 2025). — [CMSWire](https://www.cmswire.com/digital-marketing/weve-lost-preview-text-for-email-are-subject-lines-next)
- **Plain text vs HTML (HubSpot, older).** The page shows only "Updated 06/13/25". The A/B tests are undated and give no sample sizes; the accompanying preference survey is from 2014.
  - The simpler design won every A/B test, with statistical significance.
  - HTML template with images vs plain text: 21% lower clickthrough rate and 51% fewer clicks.
  - GIF version: 2.3% lower clickthrough rate, so the plain version got 42% more clicks.
  - Simple HTML vs HTML-heavy: 5.3% higher clickthrough rate and 30% more clicks.
  - An analysis of over half a billion HubSpot customer emails found that "even a single image" reduced click rate.
  - In the 2014 survey of more than 1,000 professionals, nearly two-thirds said they preferred HTML and image emails, which is the opposite of what the tests showed.
  — [HubSpot](https://blog.hubspot.com/marketing/plain-text-vs-html-emails-data)
- **Plain text vs HTML (Litmus, older; 23 Oct 2020).** These were webinar-registration tests with list sizes not stated.
  - Customers: the plain-text-style email had slightly higher opens and clicks, and 60% of converting customers came from it.
  - Non-customers: plain text got higher opens but marginally lower clicks, and 49% of registrants came from it, so the two formats were roughly even.
  - The first test changed the copy as well as the format, and Litmus calls the results "far from definitive".
  — [Litmus](https://www.litmus.com/blog/the-results-are-in-a-b-testing-html-vs-plain-text-emails)
- **Accessibility.** The Email Markup Consortium's 2026 accessibility report found that 99.88% of 376,348 emails analysed had "Serious" or "Critical" defects. Only eight emails, from three brands, passed (0.002%). The 2026 figures were reported by beSpacific on 4 Jun 2026 ([original report](https://emailmarkup.org/en/reports/accessibility/2026/)). — [beSpacific](https://www.bespacific.com/?p=125394)
- **Replies.** Validity predicts reply rate will become "a primary KPI in 2026". It recommends "reply@" addresses and copy that invites responses, because MBPs likely treat replies as an engagement signal. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)

### Inferences
- **Sequence.** The evidence supports a short sequence over a long teaser campaign:
  1. One launch email, with content segmented by audience: consumer, developer, and people at companies (detectable from corporate domains or Team-relevant use).
  2. One follow-up a few days later to non-clickers, not non-openers, since MPP makes "non-opener" meaningless for about 55 to 60% of opens. Keep the From name the same; change the subject line only modestly, given the conflicting evidence.
  3. Nothing further to people who ignored both, so complaints stay low.

  A teaser is optional. No data shows it lifts launch results, and on a list that opted in to "product updates", each extra send adds unsubscribe and complaint exposure.
- **Segmentation.** Segment by stated interest or product use rather than by activity alone. In Mailchimp's 2017 data, interest segments raised clicks and cut unsubscribes and complaints, while activity-based sends raised both. For the Team-plan launch, a developer or company-domain segment can get a version focused on the CLI, docs and security proof. Consumers can get a shorter "what's new for you" version, or nothing beyond a single mention.
- **Subject line and sender.** Aim for 20 to 40 characters with the concrete news in it; for example, a product name plus "Team plan" outperforms vague hype. A sender name like "Name at Company" and a reply-to that reaches a person are worth A/B testing. Do not bend copy around "spam words"; reputation and authentication matter far more.
- **Format for developers.** Developers and security-minded readers are better served by plain-text or lightly formatted live-text HTML: one primary link, no text inside images, a visible plain-language summary at the top, and a real reply address. This fits the older HubSpot tests, AI-summary behaviour, and accessibility. It is an inference: no 2025 to 2026 test on developer audiences was found.

### Gaps
- No controlled or large-sample study was found on teaser/launch/follow-up spacing or the number of launch sends, for B2B, SaaS or developer audiences.
- I found no 2025 to 2026 primary test of plain text vs HTML, and nothing on developer audiences specifically. The HubSpot tests are undated, with no sample sizes; Litmus's are from 2020.
- I found no measured lift for role or persona segmentation in B2B product email beyond Mailchimp's 2017 interest-group data.
- **Subject-line words.** No reliable dataset was found on words such as "new", "introducing", "launch" or "free", on questions or numbers, or on emoji. Emoji evidence is mixed and comes from small or undisclosed samples (an Experian "56% higher open rate" claim, a Search Engine Journal test of 17 campaigns, Agorapulse), all unverified.
- B2B send-time studies found (Belkins, 7.5M cold emails in 2025; Superhuman, 16.5M cold emails) concern cold outreach, disagree with each other, and were not verified.
- Whether senders can stop Apple Intelligence from replacing their preheader could not be confirmed. An Apple developer forum thread raises the question, but no answer text was visible.

## Email practice: re-engagement, win-back and sunset policies

### Takeaway
Win-back emails have low immediate read rates but a long tail. In Return Path's older 2014 research, 12% read the win-back email itself, yet 45% of recipients read a later message, often within about 90 days.

Mailing long-dormant addresses carries real risk: Yahoo closes accounts after 12 months of inactivity and Gmail after 24, abandoned addresses can be recycled as spam traps, and providers expect complaint rates under 0.1 to 0.3%. Current guidance (Yahoo, Spamhaus, Validity, Omeda) is to stagger sends, ask inactive subscribers to reconfirm, and suppress non-responders. It also warns against suppressing on opens or clicks alone.

### Cited Findings
- **Return Path win-back research (older; MarTech, 30 Apr 2014).** The study looked at the 33 brands in Internet Retailer's Top 100 that ran win-back campaigns.
  - "A little over 66%" of marketers' list addresses were inactive.
  - Only 12% of recipients read the win-back email, but 45% read a later message; only 24% of those had read the win-back itself.
  - 75% of re-engaged subscribers read a later message within 89 days, and the rest kept opening for up to 300 days.
  - Fewer than 2% of idle accounts opened a re-activation campaign.
  - "Miss you" and "come back" subject lines each had 13% read rates.
  - Dollar-off offers performed about twice as well as percentage-off offers.
  - Win-back campaigns should be "ongoing, as opposed to a one-time event".
  — [MarTech](https://martech.org/email-win-back-programs-work/)
- **Validity on dormant addresses** (2025 data). MBPs close inactive accounts, "Yahoo after 12 months and Gmail after 24 months", so "bounces are more likely when mailing to older lists". The average unknown-user (hard bounce) rate was 1.46% and the rejected rate 3.20%. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Validity against over-suppression.** Validity also warns against suppressing on engagement metrics alone: "don't jeopardize relationships (and revenue) by suppressing these subscribers based on metrics like opens and clicks", because email also works like a billboard. — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)
- **Spamhaus on sunset policies** (29 Nov 2023).
  - "Mailbox providers can investigate an email address that has been unengaged for anywhere from three to twelve months."
  - "Recycled spamtraps" are how providers judge list hygiene, and Spamhaus cites M3AAWG's suggestion of 12 months as a minimum age for spamtraps.
  - "Sending to all unengaged users at once is a sure-fire way to destroy your reputation!" Spamhaus advises a permission pass or re-engagement campaign staggered over several days, close reputation monitoring, and then suppressing non-responders.
  - Poor bounce handling plus no sunset policy can lead to blocklisting.
  — [Spamhaus](https://www.spamhaus.org/resource-hub/deliverability/what-is-an-email-sunset-policy-and-why-do-you-need-one)
- **Yahoo Sender Best Practices** (live page, © 2026; enforcement since February 2024).
  - "Monitor hard and soft bounces as well as inactive recipients", and "Consider sending a reconfirmation email to inactive subscribers periodically".
  - Use double or confirmed opt-in, and "Remove invalid recipients from your list promptly".
  - Keep the spam rate "below 0.3%", calculated on mail delivered to the inbox.
  - Bulk senders must honour unsubscribes within 2 days and support one-click unsubscribe, with the RFC 8058 POST method highly recommended.
  — [Yahoo Sender Hub](https://senders.yahooinc.com/best-practices)
- **Omeda (August 2026)** recommends "Confirmation of Interest" campaigns to get direct signals from subscribers rather than relying on bot-polluted click data. It also recommends segmenting engagement analysis by receiving domain rather than suppressing subscribers. — [Omeda](https://www.omeda.com/resources/report/bot-clicks-in-email/)
- **Re-permission outcomes (older case studies).** SuperOffice (page updated 4 May 2021) emailed 10,000 blog subscribers, then 3 days later re-sent to non-openers; the ask required extra details such as name and company rather than one click. Only 102 re-subscribed (about 1%), and 9,898 were deleted. The RNLI ran two re-permission campaigns in 2017 to about 900,000 subscribers. It expected to lose up to 75%, but "more than 450,000" re-opted in. — [SuperOffice](https://superoffice.com/blog/gdpr-email-marketing)
- **Gmail one-click unsubscribing.** Since July 2025, Gmail users can see their subscriptions ranked by send frequency and unsubscribe in one click. — [Google Workspace Updates](https://workspaceupdates.googleblog.com/2025/07/manage-email-subscriptions-in-gmail.html)
- **Complaint expectation.** Validity says complaint rates "under 0.1 percent is now the expectation" (2025 data, average 0.06%). — [Validity 2026 Benchmark (PDF)](https://www.validity.com/wp-content/uploads/2026/03/2026-Benchmark-Report.pdf)

### Inferences
- **Define the audience.** Define "lapsed" by product signals (last login, app use, purchase, last human click), not by opens, which MPP inflates. Split the lapsed audience by recency:
  - lapsed under 12 months;
  - 12 to 24 months, with rising bounce and Yahoo-closure risk;
  - over 24 months, where Gmail closes accounts and recycled-trap risk applies.

  Run address validation or bounce cleanup on the oldest group before mailing. Consider a reconfirmation-style message, or no mail at all, for addresses dormant more than 24 months.
- **Stagger the sends.** Mail the most recently active first and widen in waves over several days, watching complaints (target under 0.1%), bounces and blocks at Gmail, Microsoft and Yahoo before each wave (Spamhaus, Validity).
- **Keep the series short, then sunset.** For the two consumer launches (the encrypted burner email with a password manager, and the private AI agent app), use a series of two or three emails over two to four weeks:
  1. A clear "here's what's new and why it matters to you" email, leading with one product per email or one primary call to action.
  2. A follow-up to non-clickers.
  3. A final "stay subscribed or we'll stop emailing" choice.

  Then suppress or sunset non-responders. A prominent unsubscribe is cheaper than a complaint, since unsubscribes do not hurt reputation and complaints do.
- **Expect a long tail.** Expect low immediate response (the Return Path win-back read rate was 12% in older 2014 data) and measure reactivation over about 90 days (sign-ups, logins, installs), not just the campaign's own clicks.
- **Consent scope.** Whether product-update consent covers announcements of separate new products is a separate question; see the consent/deliverability section.

### Gaps
- I found no verified 2025 to 2026 primary benchmark for win-back or reactivation rates. Widely repeated figures come from secondary vendor blogs or calculators and could not be traced to primary data, for example:
  - "a single win-back email reactivates about 6%, a 4-email sequence 14 to 18%", attributed to Klaviyo 2025;
  - "12 to 20% of inactive customers reactivate";
  - "win-back flows recover 10 to 15%".

  The Return Path figures are from 2014.
- Validity's oft-cited "six months" starting point for a sunset policy appeared only in a search snippet; the Validity page returned 404. Mailbox providers publish no official month count. Yahoo declines to give one; the "90 to 180 days" figure attributed to a Verizon Media-era interview is third-party and unverified.
- No recent industry-wide re-permission response-rate data was found; only the two case studies above, which bracket roughly 1% to about 50%.
- No win-back data specific to privacy, VPN or security consumer products was found.
- Gmail's rule that inactive accounts are deleted after 2 years comes here via Validity's report; Google's own inactive-account policy page was not fetched.


## Deliverability and consent: mailbox-provider rules and the law for a product-updates list and lapsed users

### Takeaway
Gmail and Yahoo (since February 2024) and Outlook.com (since 5 May 2025) apply the same core rules to anyone sending 5,000 or more messages a day to their consumer mailboxes:
- SPF, DKIM and DMARC (p=none at minimum, aligned).
- RFC 8058 one-click unsubscribe, honoured within 2 days (48 hours).
- A user-reported spam rate kept below 0.10% and never at 0.30%.

Gmail began issuing temporary and permanent rejections in November 2025, and I found no new 2026 rule. Legally, the US (CAN-SPAM) is opt-out. The UK, EU and Canada require consent or a narrow existing-customer exception. A "product updates" opt-in very likely covers news of a new plan from the same company. Emailing lapsed users who never consented, or emailing them to ask for fresh consent, is itself marketing that needs valid consent: the UK ICO fined Honda and Flybe for this in 2017, and UK PECR fines can reach £17.5M or 4% of turnover since 5 February 2026.

### Cited Findings

#### Gmail (Google)
- **All senders** must have SPF or DKIM, valid forward and reverse DNS (PTR), TLS, RFC 5322 formatting, and a Postmaster Tools spam rate "below 0.3%". They must not impersonate Gmail From: headers; Google says it will begin applying a DMARC quarantine policy to such mail. The requirements began 1 February 2024, and TLS was added in December 2023. — [Google, Email sender guidelines](https://support.google.com/a/answer/81126)
- **Bulk senders** are those sending more than 5,000 messages a day to personal Gmail accounts (@gmail.com, @googlemail.com). They need:
  - SPF and DKIM, plus DMARC, whose policy "can be set to none".
  - A From: domain "aligned with either the SPF domain or the DKIM domain".
  - One-click unsubscribe on "Marketing messages and subscribed messages", via `List-Unsubscribe-Post: List-Unsubscribe=One-Click` and an HTTPS `List-Unsubscribe` header (RFC 2369, RFC 8058).
  - DKIM keys of at least 1024 bits (2048 recommended).
  - A spam rate kept "below 0.10%" and never reaching "0.30% or higher".
  - Source: [Google, Email sender guidelines](https://support.google.com/a/answer/81126)
- **Google's FAQ** adds the following:
  - Bulk status is permanent: "Senders who meet the above criteria at least once are permanently considered bulk senders."
  - Existing senders had until 1 June 2024 to add one-click unsubscribe.
  - From June 2024, bulk senders with a user-reported spam rate above 0.3% are ineligible for mitigation, and they regain eligibility after 7 consecutive days below 0.3%.
  - Google recommends fulfilling unsubscribes "within 48 hours" and lists "Unsubscribe requests aren't honored within 48 hours" as an enforcement issue.
  - "Starting November 2025, Gmail is ramping up its enforcement on non-compliant traffic", with "temporary and permanent rejections" (4.7.x temporary, 5.7.x blocked). New domains face "an accelerated timetable".
  - The guidelines "don't apply to messages sent to Google Workspace accounts".
  - Source: [Google, Email sender guidelines FAQ](https://support.google.com/a/answer/14229414)
- **No 2026 change found.** Google's pages, read on 26 November 2026 (©2026), show no 2026 requirement change, and DMARC p=none is still accepted. Claims on vendor sites that Google now requires p=quarantine or p=reject are not supported by Google's own pages. — [Google, Email sender guidelines](https://support.google.com/a/answer/81126)

#### Yahoo
- **All senders** must have SPF or DKIM, valid forward and reverse DNS, a spam rate "below 0.3%", and comply with RFC 5321 and 5322. — [Yahoo Sender Hub, Sender Requirements & Recommendations](https://senders.yahooinc.com/best-practices/)
- **Bulk senders** must:
  - Implement "both SPF & DKIM".
  - "Publish a valid DMARC policy with at least p=none - DMARC must pass"; "Relaxed alignment is acceptable."
  - Add a list-unsubscribe header. The RFC 8058 POST method is "highly" recommended and mailto is acceptable.
  - Put a visible unsubscribe link in the body.
  - Honour unsubscribes within 2 days.
  - Keep complaints below 0.3%, measured on inbox-delivered mail.
  - Recommendations: DMARC on every sending domain, DKIM keys of at least 1024 bits, ARC for forwarders, and a complaint feedback loop.
  - Enforcement began in February 2024 with a gradual rollout, and the page lists no later change.
  - Source: [Yahoo Sender Hub](https://senders.yahooinc.com/best-practices/)

#### Microsoft (Outlook.com, Hotmail, Live)
- **Scope and requirements.** The rules apply to domains sending "more than 5,000 emails per day" to Outlook.com consumer domains (outlook.com, hotmail.com, live.com). SPF "Must Pass", DKIM must pass, and DMARC must be at least p=none and aligned with SPF or DKIM ("preferably both"). — [Microsoft Defender for Office 365 blog, Apr 2025](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730)
- **Enforcement.** "After May 5th, 2025, Outlook will begin routing messages from high volume non‐compliant domains to the Junk folder"; "in the future (date to be announced), non-compliant messages will be rejected" with "550; 5.7.515 Access denied, sending domain [SendingDomain] does not meet the required authentication level". The Safe Senders list "won't be honored" for non-compliant mail. — [Microsoft blog](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730)
- **Recommended hygiene:** a valid From or Reply-To address that can receive replies, a "functional, easy-to-find unsubscribe link", regular removal of invalid addresses and bounces, accurate subject lines, and sending only to recipients who consented. The only timeline revision in the post is dated 29 April 2025. Reader comments report 550 5.7.515 rejections, but these are not official. — [Microsoft blog](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730)

#### CAN-SPAM (US)
- **Requirements:**
  - Accurate header information.
  - "The subject line must accurately reflect the content of the message."
  - "Disclose clearly and conspicuously that your message is an advertisement."
  - A "valid physical postal address".
  - A clear opt-out explanation.
  - "You must honor a recipient's opt-out request within 10 business days."
  - "Subscribers and members don't lose their ability to opt out."
  - "You can't contract away your legal responsibility to comply with the law."
  - "The law makes no exception for business-to-business email."
  - Source: [FTC, CAN-SPAM Act: A Compliance Guide for Business](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business)
- **Primary purpose test:** "What matters is the 'primary purpose' of the message."
  - Commercial content "advertises or promotes a commercial product or service".
  - Transactional or relationship content includes notices of "a change in the terms or features of a membership, subscription", and "the law views these categories narrowly".
  - A mixed message is commercial if its subject line would lead a reasonable recipient to expect a commercial message, or if the transactional part "doesn't appear at the beginning".
  - Source: [FTC compliance guide](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business)
- **Penalty:** up to $53,088 per email. — [FTC compliance guide](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business). This is the 2025 inflation-adjusted figure. The FTC's 15 September 2026 Federal Register notice keeps the 2025 levels for 2026, because OMB Memorandum M-26-11 (17 April 2026) cancelled the 2026 adjustment: the shutdown stopped BLS producing the October 2025 CPI-U. — [Federal Register, 15 Sep 2026](https://www.federalregister.gov/documents/2026/09/15/2026-18853/civil-penalty-inflation-adjustments)

#### EU (ePrivacy Directive Art 13(2), GDPR) and member-state variation
- **CJEU C-654/23** (judgment 13 November 2025) addressed a news site that collected email addresses when users created a free account with limited content and a newsletter.
  - Addresses collected this way count as obtained "in the context of the sale of a product or service" under ePrivacy Article 13(2), where the free elements belong to a model designed to drive paid subscriptions. Indirect remuneration is enough.
  - Such newsletters are direct marketing when their aim is to promote paid offerings, even if they carry editorial content.
  - Where Article 13(2) applies, no separate GDPR Article 6 legal basis is needed, though GDPR duties such as transparency still apply.
  - In practice: market only your own similar products, and offer a free, easy opt-out at collection and in every email.
  - It is unclear how far this reaches fully free, non-commercial platforms.
  - Source: [Reed Smith, 18 Nov 2025](https://www.reedsmith.com/our-insights/blogs/viewpoints/102luvt/ecj-rules-on-soft-opt-in-for-freemium-newsletters-no-separate-gdpr-legal-basis-r/)
- **Germany, UWG § 7.** § 7(2) no. 2 treats email advertising without "vorherige ausdrückliche Einwilligung" (prior express consent) as always an unreasonable nuisance. The § 7(3) existing-customer exception applies only if all four conditions hold:
  1. The address was obtained "im Zusammenhang mit dem Verkauf einer Ware oder Dienstleistung" (in connection with the sale of goods or services).
  2. It is used for direct advertising of the sender's own similar goods or services.
  3. The customer has not objected.
  4. At collection and at every use, the customer is clearly told they can object at any time at no cost beyond basic transmission rates.
  - Source: [UWG § 7, gesetze-im-internet.de](https://www.gesetze-im-internet.de/uwg_2004/__7.html)
- **Other member states (older evidence).** A Fieldfisher survey (March 2020) listed Germany as double opt-in for both B2C and B2B, said reliance on the soft opt-in is rare there, and listed France's B2B regime as opt-out. Current secondary sources conflict on B2B treatment in both countries. — [Fieldfisher EU e-marketing requirements, Mar 2020](https://res.cloudinary.com/fieldfisher/image/upload/v1585817516/PDFs/EU_e-marketing_requirements_updated_March_2020_g6jh2u.pdf). A January 2024 edition exists but I did not read it. — [Fieldfisher, Jan 2024](https://res.cloudinary.com/fieldfisher/image/upload/v1706627634/PDFs/EU_e-marketing_requirements_-_January_2024_lqpl6s.pdf)

#### UK (PECR and the ICO; Data (Use and Access) Act 2025)
- **ICO electronic mail marketing rules:**
  - "You must not send marketing emails or texts to individuals without specific consent."
  - The soft opt-in covers existing customers who "bought (or discussed buying) a similar product or service from you in the past", provided "you gave them a simple way to opt out both when you first collected their details and in every message you have sent".
  - "It does not apply to prospective customers or new contacts (eg from bought-in lists)."
  - "You can email or text any corporate body", but "Sole traders and some partnerships are treated as individuals"; keep a do-not-email list.
  - The guidance "is under review and may be subject to change".
  - Source: [ICO, Electronic mail marketing](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guide-to-pecr/electronic-and-telephone-marketing/electronic-mail-marketing/)
- **Service messages versus marketing.** A purely administrative message that promotes nothing is not direct marketing. Adding marketing material changes that: a neutral tone does not save promotional content, and branding alone is unlikely to make a message marketing. — [ICO, Key concepts for direct marketing using electronic mail](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guidance-on-direct-marketing-using-electronic-mail/key-concepts-for-direct-marketing-using-electronic-mail/); [ICO, Identify direct marketing](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/direct-marketing-guidance/identify-direct-marketing/)
- **January 2026 fines.** The ICO fined two companies a combined £225,000. ZMLUK was fined £105,000 for more than 67M emails sent on third-party consent covering 361 partners, and a second company £120,000 for more than 4M texts with no simple way to refuse. The ICO said "relying on vague or third-party consent, or sending marketing messages under the guise of service updates, isn't enough." — [RPC, Spring 2026](https://www.rpclegal.com/snapshots/data-protection/spring-2026/ico-issues-fines-over-electronic-marketing-breaches/); [Emailexpert](https://emailexpert.com/ico-fines-225000-nuisance-marketing/) (secondary)
- **An email asking for consent is itself marketing** (March 2017, older; still the leading precedent).
  - The ICO fined Flybe £70,000 for 3,333,940 emails to people who had opted out; its "data cleansing" defence was rejected.
  - It fined Honda £13,000 for 289,790 emails asking customers about their marketing preferences; its "service message" defence was rejected.
  - Source: [Lewis Silkin](https://lewissilkin.com/en/insights/ico-fines-flybe-and-honda)
  - The ICO's 2020 draft direct marketing code (older) treats a hotel's email asking past guests to opt in to offers as direct marketing. — [ICO draft direct marketing code](https://ico.org.uk/media2/migrated/2616882/direct-marketing-code-draft-guidance.pdf)
- **Data (Use and Access) Act 2025.** The Commencement No. 6 Regulations (SI 2026/82, made 29 January 2026) brought the PECR changes into force on 5 February 2026.
  - Conduct on or after that date faces PECR penalties of up to £17.5M or 4% of worldwide turnover (higher tier), or £8.7M or 2% (standard tier).
  - The ICO also has new PECR powers, such as compelling interviews and requiring technical reports.
  - Sources: [ICO commencement statement, Feb 2026](https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2026/02/statement-on-the-commencement-of-the-data-use-and-access-act-duaa/); [SI 2026/82](https://www.legislation.gov.uk/uksi/2026/82/made); [ICO DUAA summary: PECR](https://ico.org.uk/about-the-ico/what-we-do/legislation-we-cover/data-use-and-access-act-2025/the-data-use-and-access-act-2025-duaa-summary-of-the-changes/privacy-and-electronic-communications)
  - The Act also extended the soft opt-in to charities' own charitable purposes; the ICO's final guidance on this is reported as April 2026. This does not widen the soft opt-in for companies. — [PDV Agency](https://www.pdv.agency/charity-soft-opt-in-guidance/) (secondary)

#### Canada (CASL)
- **s.6(1) and s.6(2).** A commercial electronic message may not be sent unless the recipient "has consented to receiving it, whether the consent is express or implied", and the message complies with s.6(2). Section 6(2) requires the message to identify the sender (and anyone on whose behalf it is sent), give contact information, and include an unsubscribe mechanism under s.11(1). — [CASL, S.C. 2010, c. 23, Justice Laws](https://laws-lois.justice.gc.ca/eng/acts/E-1.6/page-1.html)
- **s.6(6) exemptions.** Consent is not needed, but the s.6(2) form rules still apply, for a message that solely:
  - (a) gives a requested quote;
  - (b) facilitates, completes or confirms an agreed transaction;
  - (c) gives "warranty information, product recall information or safety or security information" about a product the recipient uses or has used;
  - (d) gives "factual information about" ongoing use of a product or service under a "subscription, membership, account", or about the relationship itself;
  - (e) relates to employment;
  - (f) "delivers a product, goods or a service, including product updates or upgrades, that the person … is entitled to receive under the terms of a transaction" previously entered into.
  - Source: [CASL, Justice Laws](https://laws-lois.justice.gc.ca/eng/acts/E-1.6/page-1.html)
- **s.10(9) to (10) and s.11(3).** Consent is implied only in the listed cases. One is an existing business relationship based on a purchase or lease "within the two-year period immediately before the day on which the message was sent", or on an inquiry or application "within the six-month period". Unsubscribes must take effect "without delay, and in any event no later than 10 business days" after the request. — [CASL, Justice Laws](https://laws-lois.justice.gc.ca/eng/acts/E-1.6/page-2.html)
- **Penalties and enforcement.** Penalties reach C$10M per violation for businesses and C$1M for individuals. The CRTC's report for October 2025 to March 2026 lists 11 warning or information letters and an "enhanced focus" on business compliance. — [CRTC enforcement report, 31 Mar 2026](https://crtc.gc.ca/eng/internet/pub/20260331.htm) (seen via search; the CRTC site refused automated fetch). Bennett Jones reports a C$48,000 penalty for a "technical violation" of CASL, identified in search summaries as a Plenty of Fish undertaking from August 2025. — [Bennett Jones](https://www.bennettjones.com/Insights/Blogs/CRTC-Issues-$48000-Fine-for-Technical-Violation-of-CASL). Implied consent is valid but harder to evidence than express consent. — [Bennett Jones](https://www.bennettjones.com/Blogs-Section/Defending-Enforcement-Under-CASL-Establishing-Consent)

### Inferences
- **Technical readiness before either campaign:**
  - SPF, DKIM (2048-bit) and DMARC aligned on the visible From domain.
  - RFC 8058 POST headers plus a visible unsubscribe link.
  - A suppression pipeline that processes unsubscribes within 48 hours. This is stricter than the 10 business days under CAN-SPAM or CASL, so meet the 48-hour mailbox rule everywhere.
  - Gmail bulk status is permanent once reached, so these rules bind even on low-volume days.
- **Order the two campaigns by risk to the spam rate.** Send the Team launch first, to recently engaged product-update subscribers, which keeps complaints well under 0.1%. Send the lapsed-user campaign later, in throttled batches, on a separate subdomain or stream if possible, and suppress hard bounces and long-inactive addresses. A lapsed list carries the most complaint and spam-trap risk, and since November 2025 Gmail may reject outright rather than defer.
- **Scope of a "product updates" opt-in.** Announcing a Team plan for the same network and toolkit is very likely within a "product updates" consent. Promoting distinct new consumer products, such as a burner email service with a password manager or an AI agent app, is direct marketing. Whether it falls within the consent depends on the wording shown at sign-up, because UK and EU consent must be specific.
  - For people in the UK and EU, check the original consent text.
  - Where it is narrow, present the new products as part of the same account or app, give a one-click opt-out and a preference center, and do not hide the promotion inside an "account" or "security" notice. The ICO's January 2026 fines targeted exactly that.
- **No email asking lapsed or unsubscribed users for permission.** Do not email people who unsubscribed, or whose consent cannot be shown, to ask for permission again (Honda and Flybe, 2017). A win-back email may go only to people with valid consent, or to UK and EU customers who qualify for the soft opt-in. They qualify only if they bought or negotiated a purchase, the products are similar, and an opt-out was offered at collection and in every message. CJEU C-654/23 suggests free-tier users of a freemium service can qualify in the EU when free use is tied to paid tiers. Germany remains the strictest jurisdiction, where double opt-in is standard practice.
- **Canada.** Implied consent from a past purchase lapses two years after that purchase, or six months after an inquiry. I found no statutory expiry for express consent (such as a "product updates" opt-in) in the sections read. Promoting new products is a commercial electronic message that needs consent, and it is not covered by the s.6(6)(f) "product updates or upgrades" exemption. That exemption covers delivering updates a customer is entitled to, not advertising new products.
- **US.** CAN-SPAM allows opt-out marketing, but the launch email is commercial under the primary-purpose test. It therefore needs a postal address, an ad disclosure where required, an accurate subject line and a working opt-out. B2B addresses get no exemption.
- **Business addresses.** In the UK, corporate addresses can be emailed without consent, but sole traders count as individuals. In Germany, email advertising to business addresses also needs consent in practice. Company-domain recipients on the list should therefore be treated as consented subscribers, not cold B2B leads.

### Gaps
- I did not check Apple iCloud Mail's sender requirements.
- Microsoft has not officially announced a date for 550 5.7.515 rejections. Whether rejections now happen is known only from user reports.
- I found no 2026 change to the Gmail or Yahoo rules, but announcements after this date, or on blogs not searched, cannot be ruled out.
- I did not read the ICO's guidance on how long consent remains valid. The CRTC's guidance on how long express consent lasts was not reachable (its site refused automated fetch).
- I did not verify France's B2B rules (CNIL guidance, CPCE Article L34-5) against primary sources. The Fieldfisher table is from 2020.
- Whether UK courts or the ICO will follow CJEU C-654/23 (EU law, decided after Brexit) on freemium users is unknown. So is whether free-tier users of a VPN or network service count as having "bought or negotiated" for the soft opt-in, or as having an existing business relationship under CASL.
- The Plenty of Fish CASL details come from search summaries only.


