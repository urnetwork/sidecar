# Synthesis of branch 1.8: what reviewers, auditors, regulators and clients ask teams to prove about AI coding agents and the models behind them

State as of 1 November 2026. This synthesizes the eleven notes files of branch 1.8 (levels 1 to 4) in this folder. It adds no new research: every finding comes from those notes and carries the URL the notes give. Where I combine notes into a judgment of my own, I mark it **synthesis judgment**.

**The branch:**
- **L1 1.08**, buyer evidence artifacts.
  - **L2 2.01**, AT&T-style supplier AI terms → **L3 3.05**, defense and federal rules (also opened by 2.03 and 2.09), and **L3 3.06**, clients' AI terms for 5–150-engineer suppliers (also opened by 2.08) → **L4 4.04**, AI mandates and savings pass-through in services contracts.
  - **L2 2.09**, rules on which models and model origins touch code → **L3 3.05** and **L3 3.12**, demand for per-repository route policy (also opened by 2.11) → **L4 4.08**, harness vendors' own models on Chinese-lab bases.
  - **L2 2.10**, SOC 2 and assessor evidence → **L3 3.10**, Vanta, Drata and Secureframe push interfaces → **L4 4.03**, Drata's AI Agent Governance.

**Labels kept from the notes:**
- "[search summary]": the notes saw the claim only in search results.
- "vendor claim" or "vendor data": a company describing itself or its own users.
- "inference": the notes' author reasoned it rather than read it.
- A number such as "(2.10)" names the note a claim comes from.

---

## 1. What the branch found

### The answer in brief
1. **Questionnaires still ask what AI a team uses, whether client data trains it, and whether a human reviews it. None found asks which agent, which weights or which host.** (L1, 4.08)
2. **The binding asks come from client contracts, and they mostly gate use rather than ask for artifacts:** default deny, no training, human review, and records of AI use on request. AT&T's per-release AI SBOM and its delete-after-use term are outliers. (2.01, 3.06)
3. **Federal and defense rules bar the *use* of named models in contract performance,** keyed to the vendor (Anthropic), the lineage (DeepSeek) or the controller (L3Harris's U.S.-control rule). The rules require only a reasonable inquiry into records the supplier already holds. Counterparties demand self-certifications. Nobody asks for cryptographic proof. (2.09, 3.05)
4. **Auditors will meet agent-written code in the change-management sample.** The live test is segregation of duties: was the approver someone other than the person who directed the agent? No source accepts a model as the approver. (2.10)
5. **GRC platforms can carry pushed evidence, but they cannot see who directed an agent, which harness or model ran, or which run produced which commit.** For coding-agent sessions, the nearest bundling threat is Vanta's Claude-only AI Inventory, not Drata. (3.10, 4.03)
6. **Org-level model allowlists are table stakes. Per-repository or per-contract policy with proof of the route is unclaimed.** Its demand comes from rules (DoW work, French State work) and from Congress, not from questionnaires or developers. Lineage now hides inside harness vendors' own models. (2.09, 3.12, 4.08)
7. **What binds a small supplier is who its clients are, not its size.** Clients pull both ways, and more of them encourage AI and want its savings than ban it. (3.06, 4.04)
8. **First-hand voice is thin at every level.** The demand evidence is binding text, counsel's advice and congressional letters. (all notes)

### 1.1 Client and supplier terms (L1, 2.01, 3.06, 4.04)
- **Prevalence among large buyers, public documents only.**
  - Of 43 large buyers searched, 13 have public terms that reach a supplier's *use* of AI to deliver work: AT&T, BT, Citi, HSBC, Barclays, Lockheed Martin, Northrop Grumman, L3Harris, Google, Gallagher, Cigna, Cushman & Wakefield and BCG. 2.01 calls this "a floor for *public* terms, not a prevalence estimate".
  - 3.06 adds four buyers whose terms bind suppliers of any size: Cisco (Oct 2026), Carrier (May 2025), Zuellig Pharma (Dec 2025) and Raiffeisen Informatik (Jun 2026). It also adds two sets of government standard terms: California's General Terms (GTC 02/2025) and New York's ITS Appendix C-AI (Apr 2025).
- **What is common across the 13 (2.01's coding):**
  - permission before AI use, or before client data enters AI: 8 of 13;
  - no training on client data: 11 of 13;
  - human review of AI output: 7 of 13;
  - disclosing or keeping records of which AI tools were used, on request: 7 of 13;
  - "no input without authorization" or "no merging" clauses that reach context use in practice: 7 of 13.
- **What is rare:**
  - a per-release SBOM naming the AI tool: AT&T only, 1 of 13 ([AT&T SAIR](https://attsuppliers.com/downloads/ATT-Supplier-Artificial-Intelligence-Requirements-V1.pdf));
  - deletion after use, keeping only pseudonymized audit metadata: AT&T only, 1 of 13;
  - named AI subcontractors: 3 of 13;
  - labels on AI-generated deliverables: 3 of 13.
- **The terms are tightening:**
  - Citi moved from notification (May 2025) to "shall not use … unless such use has been agreed to … in the applicable Schedule or Work Order" (Sep 2026) ([Citi](https://www.citigroup.com/rcs/citigpa/storage/public/Citi-Requirements-for-Suppliers-English.pdf)).
  - AT&T added a default-deny rule in SISR v8.0 §3.6 ([AT&T SISR](https://globalsupplychain.att.com/misc/ATT_SISR_Appx.pdf)).
  - Barclays issued a dedicated AI SCO, v16.0, with agentic safeguards ([Barclays](https://home.barclays/content/dam/home-barclays/documents/who-we-are/our-suppliers/English/v16/Artificial%20Intelligence%20SCO%20v16.0%20-%20English.pdf)).
  - L3Harris's 2026 terms add a full Article 17, "AI USE AND COMPLIANCE" (3.05).
- **Coding agents are explicitly in scope:**
  - at Barclays, AT&T, L3Harris, BT and Citi (2.01);
  - at Zuellig, which covers "indirect use of AI (e.g., using AI internally to support development, coding …)" ([Zuellig](https://edge.sitecorecloud.io/zuelligphar3c90-zpcms-prod-4532/media/Project/Corporate/Policy/Zuellig-Pharma--AI-Policy-for-Service-Providers-Consultants---25022026.pdf));
  - in California, whose SAM §4986.2 gives "Using GenAI to write source code" as a material impact that needs notice ([SAM 4986.2](https://www.dgs.ca.gov/Resources/SAM/TOC/4900/4986-2)) (3.06).
- **How compliance runs today: "contractual and manual" (2.01).**
  - The routes are authorization written into the SOW, Work Order or Call-Off; email approval per use case (Gallagher's `AIUseCases@ajg.com`); the buyer's own provisioned tools (BT); and "records on request".
  - 2.01 found no product that turns a client's AI clause into enforcement or evidence.
  - Clients approve tools, providers, use cases and data inputs, not runs. Notice clocks run from 2 weeks (Zuellig) to 90 days (New York) (3.06).
  - The evidence accepted is mostly documents and attestations. Logs are asked for only in narrow cases: Zuellig when client data trains AI, California's GenAI Special Provisions §3, and New York audit reports (3.06).
- **The most visible challenge to a small supplier is "prove the tool kept nothing".** One client was not satisfied by the vendor's privacy page: "your privacy page alone doesn't convince my client enough" ([Cursor 5418](https://forum.cursor.com/t/concerns-about-privacy-mode-and-data-storage/5418)) (3.06).
- **Across small-supplier contracts generally, explicit AI terms are a minority:**
  - about 8% of independent-contractor agreements carry them ([Spellbook](https://spellbook.com/blog/2026-state-of-contracts-report), vendor data);
  - they appear "rarely" in 670+ filed tech-services agreements ([Bloomberg Law](https://news.bgov.com/bloomberg-law-analysis/analysis-ais-risks-fly-under-contract-drafters-radar));
  - 39% of ad-agency contracts don't address AI at all ([Adweek](https://www.adweek.com/agencies/ai-is-moving-faster-than-agency-contracts/));
  - 14% of freelance-platform clients discourage AI entirely ([CHI '26](https://arxiv.org/pdf/2603.07459)).
  - Even so, 3.06's illustrative arithmetic, assuming independent clients, gives an agency with 15 clients a 71% chance of at least one restrictive client at an 8% rate, and about 90% at 14%.
- **Microsoft is a moving target.**
  - SSPA program guide v11 let suppliers that only *use* Copilot or third-party AI answer "no" to the AI profile ([SSPA v11](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY25-Program-Guide-v11_en-US.pdf)) (2.01).
  - v12 no longer contains that sentence, and it adds a "Deployer" profile ([SSPA v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-SSPA-Program-Guide-v12_en-US.pdf)) (3.06).
  - The notes do not establish whether pure tool users are now in scope.

### 1.2 Federal and defense rules and prime terms (2.09, 3.05)
- **Use of named models in contract performance is barred.**
  - NDAA §1532 bars DoD contractors from using "covered artificial intelligence with respect to the performance of a contract". Today that means DeepSeek and High Flyer AI ([ETO AGORA](https://agora.eto.tech/instrument/2694)) (2.09).
  - The DoW's Anthropic designation (March 2026) was upheld by the D.C. Circuit on 25 Sep 2026; Anthropic petitioned for en banc rehearing on 14 Oct 2026. Anthropic's own reading is that it "applies to the use of Claude as a direct part of DoW contracts and subcontracts" ([Anthropic](https://claude.com/solutions/government)) (2.09, 3.05).
  - In the signed DHS DeepSeek order, the footnote on the *exclusion* leg reads "To include third party implementations of DeepSeek used to provide products and services to civilian agencies" ([DHS order](https://downloads.regulations.gov/DHS-2026-0628-0002/content.pdf)). The phrase "developed using" sits in the separate removal leg and is still undefined (3.05).
  - GSA's Schedules and GWACs select all three FASCSA order types: DHS, DoD and DNI ([GSA](https://origin-www.gsa.gov/system/files/AA%20FASCSA%20Orders%20-%20Message%20Sent%20to%20GSA%20Industry%20Partners.pdf)) (3.05).
  - Harvard's own §1532 guidance lists "Generating code, models, algorithms, or design recommendations using a prohibited AI tool" as prohibited ([Harvard OVPR](https://bpb-us-e1.wpmucdn.com/websites.harvard.edu/dist/f/106/files/2026/01/NDAA-2026-Guidance-and-Prohibition-on-use-of-certain-Artificial-Intelligence.pdf)) (3.05).
- **What the rules require as proof is little.**
  - FAR 52.204-29/30 require a representation, a "reasonable inquiry" into "information in the entity's possession" with no audit, and a report within 3 business days ([FAR 52.204-30](https://www.acquisition.gov/far/52.204-30)).
  - The FAR Council glosses the inquiry as "primarily documentation or other records" ([85 FR 42665](https://www.govinfo.gov/content/pkg/FR-2020-07-14/pdf/2020-15293.pdf)) (2.09, 3.05).
- **What counterparties demand is a ladder of self-certifications (3.05):**
  1. the representation made by submitting an offer;
  2. checkbox forms and 18 U.S.C. §1001-backed questionnaires;
  3. prime-drafted "verified absence" forms ([Mayer Brown](https://www.mayerbrown.com/en/insights/publications/2026/07/dows-anthropic-ban-goes-live-a-confusing-patchwork-of-certification-demands-for-contractors));
  4. per-person signed attestations (Harvard);
  5. at the top, L3Harris's 2026 Article 17: written approval naming "the specific AI systems, providers, and use cases", API endpoints included; a U.S.-control rule; a human operator who approves before any AI action affects L3Harris environments; an inventory; change notices; a 72-hour notice of "unauthorized AI use"; and audit rights ([L3Harris 2026](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf)).
  - Nobody asks for publisher signatures or cryptographic proof. Logs are asked for only after a breach (3.05).
- **Counsel advise documented diligence, not per-repository logs.**
  - "should be prepared to document that separation" ([Holland & Knight](https://www.hklaw.com/en/insights/publications/2026/09/dc-circuit-upholds-exclusion-of-anthropic-from-dow-supply-chain)); "avoid certifying more than the company has actually verified" (Mayer Brown).
  - Four firms advise inventories or documented diligence. None advises per-repository logs of model and harness, and none warns against keeping them (3.05).
  - False Claims Act knowledge includes "reckless disregard" ([Holland & Knight](https://www.hklaw.com/en/insights/publications/2026/01/cmmc-affirmation-trap-fca-exposure)).
- **On their text, prime terms reach the harness's own transcript store.**
  - Northrop bars buyer information being "stored, logged, cached, or otherwise retained by the AI System", or being "accessible to any third party, including the AI System Provider" ([Northrop R05_26](https://cdn.northropgrumman.com/-/media/Supplier-Documents/Terms-and-Conditions/CTM-P-ST-003USGTMOrderNotforCommercialProductsServices_R05_26.pdf)).
  - L3Harris bars an AI system that "will maintain any persistent copy" (3.05).
  - The reading that this covers a harness's local transcripts is the researcher's own. No prime or counsel has stated it (3.05).
- **Zero data retention (ZDR) alone does not clear Northrop's access test on the text.** Every hosted provider keeps exceptions: flagged content, legal requirements. Self-hosted inference is the only path that clears the test without interpretation (3.05).
- **Encrypted CUI is still CUI.** A cloud that stores it must meet the FedRAMP Moderate baseline. Networking components that carry only ciphertext out of an enclave are out of scope ([AWS CMMC FAQ](https://docs.aws.amazon.com/prescriptive-guidance/latest/cmmc-level-2-compliance-on-aws/faq.md)) (3.05).
- **GSA's final LLM clause does not reach a supplier's internal coding agents.** GSAR 552.239-7001, effective 19 Oct 2026, turns itself off for LLM use in a contractor's "internal business, back-office, operational, or performance-support systems", and the "American AI" rule was dropped in June ([Crowell](https://www.governmentcontractslegalforum.com/2026/10/articles/government-contracts/gsa-issues-final-rule-on-large-language-model-procurements/)) (3.05).

### 1.3 Auditors, assessors and supervisors (L1, 2.10)
- **The SOC 2 2027 draft.**
  - Two secondary readings agree on three points of focus, though neither quotes the draft: access control "considers robotic process automation and AI agents" (draft CC5.1); controls "detect unsanctioned AI platforms and unauthorized AI tools and models" (CC5.3); "Third-party AI models, APIs and plugins are evaluated before use and as they change" (CC8.1) ([Noru](https://noru.tech/resources/soc2-2027-trust-services-criteria); [Elevate](https://elevateconsult.com/insights/soc-2-trust-services-criteria-2027/)).
  - The criteria "would be effective for engagements beginning on or after Dec. 31, 2027, with early adoption permitted"; comments close 15 Jan 2027 ([AICPA](https://www.aicpa-cima.com/news/article/aicpa-proposes-update-of-soc-2-r-trust-services-criteria-to-enhance-the-relevance-usability-and-value-of-cpas-reports)).
  - "no point of focus requires a specific control" (Noru).
  - The draft renumbers: change management moves to CC7.1–CC7.3, and CC8 becomes vendor management (2.10).
  - No source says the draft names coding agents or AI-written code.
- **How CPA firms test.**
  - Populations come from the system of record, and the auditor tests them for completeness and accuracy (IPE). A change list that "was manually prepared" is a known deficiency ([Linford IPE](https://linfordco.com/blog/iuc-ipe-audit-procedures-for-soc-audits/)).
  - Samples start at 25 and expand to 40 after one deviation ([Linford sampling](https://linfordco.com/blog/audit-sampling/)).
  - Automated controls can be tested once when IT general controls are effective. This comes from secondary sources and a SOX analogy (2.10).
- **The live hook is segregation of duties.**
  - Noru, on draft CC7.2–7.3: "the evidence that a separate person approved it has to come from somewhere".
  - BrightByte: the approver must be "not the same person who wrote the prompt" ([BrightByte](https://thebrightbyte.com/playbook/expertise/ai-coding-agents-soc2), vendor).
  - Binding on EU financial entities, DORA RTS Art. 17(1)(b) requires "independence of the functions that approve changes and the functions responsible for requesting and implementing those changes" ([Springlex](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-17/)).
  - PCI DSS 6.2.3.1: if review is manual, someone other than the author does it, and management approves ([Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/06/02/03/)).
- **No source accepts a second model as the approver.** AI review is accepted as an extra control (A-LIGN, second-hand) (2.10).
- **Supervisors:**
  - NYDFS, 21 May 2026, an advisory: "additional testing and validation procedures, including human oversight," "for AI-generated code prior to deployment in production environments" ([NYDFS](https://www.dfs.ny.gov/industry-guidance/industry-letters/20260521-heightened-cybersecurity-risks-assoc-with-frontier-ai-models)).
  - MAS AI Risk Management Guidelines, 7 Oct 2026. Sections 3–4 apply from 7 Oct 2027 and Sections 5–6 by 7 Oct 2028. They ask for "an approved list of AI tools", "network monitoring" to "detect unauthorised use of AI", agent-specific inventory attributes, and review of oversight "decisions and interventions (including incidents as well as near misses)", while weighing "automation bias and decision fatigue" ([MAS PDF](https://www.mas.gov.sg/-/media/mas-media-library/regulation/guidelines/bd/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions/guidelines-on-artificial-intelligence-risk-management.pdf)) (2.10).
- **AIUC-1:**
  - E015.2 asks for agent provenance fields, tool calls, sub-agent delegations, and approvals linked to execution ([AIUC-1 E015](https://standard.aiuc-1.com/accountability/log-model-activity)) (L1).
  - D003.4, "Requiring human approval for sensitive tool operations", became a core control on 15 Oct 2026 ([changelog](https://standard.aiuc-1.com/changelog)) (2.10).
- **Human review degrades.** Among 400 repeat reviewers over seven months, approval of agent PRs rose "from 30.1% to 36.8%" and inline comments fell 22% ([arXiv 2606.22721](https://arxiv.org/abs/2606.22721)) (2.10).
- **After the Delve allegations, the credibility of evidence is the audible pain.** IANS: "Pick 5–10 controls at random and verify that the underlying evidence actually exists and is current" ([IANS](https://www.ians.com/news/delve-allegations-expose-weak-points-in-modern-compliance)). No major audit firm has published on AI-written code (L1, 2.10).
- **Federal software-assurance standards give no tailwind.** SP 800-218A does "not distinguish between human-written and AI-generated source code" ([NIST SP 800-218A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf)). NIST's agent overlays are unpublished, and the project was renamed COSIS on 20 Oct 2026 ([NIST](https://csrc.nist.gov/projects/cosais)) (L1).

### 1.4 GRC platforms (3.10, 4.03)
- **All three accept pushed records and files, with limits:**
  - **Vanta:** custom resources and Custom Tests work only in a customer's own private integration. Fields must be flat scalars. Each type takes at most 10,000 records and 10 MB per request, and each sync replaces the whole set. Custom Tests can be created only in the dashboard and "may require a plan upgrade or add-on" ([Vanta](https://developer.vanta.com/reference/build-integrations/overview.md); [Vanta tests](https://developer.vanta.com/docs/concepts/tests.md)).
  - **Drata:** custom connections need the Advanced or Enterprise plan ([Drata](https://help.drata.com/en/articles/11117161-custom-connections-and-tests)).
  - **Secureframe:** custom integrations need the Complete plan ([Secureframe](https://support.secureframe.com/en/articles/15111548-create-custom-integrations)).
  - None has fields for an audit period, record counts, a reconciliation or a signature, and none verifies signatures (3.10).
- **Their native change evidence misses agents.**
  - Vanta's auditor-facing code-change population has eight fields and no author, reviewer, approver or AI field ([CodeChange model](https://github.com/VantaInc/vanta-auditor-api-sdk-typescript/blob/main/docs/models/components/codechange.md)).
  - Vanta's PR test passes when the approver is not the author, and treats bot-authored PRs like human ones ([Vanta GitHub guide](https://help.vanta.com/en/articles/14845240-github-integration-guide)).
  - Drata's code-review test reads branch settings, not pull requests ([Drata Test 8](https://help.drata.com/en/articles/4776886-test-formal-code-review-process)).
  - No platform ships a test or template for AI-authored changes (3.10).
- **Drata's AI Agent Governance is not a coding-agent product.**
  - It has been in Limited Availability since 4 Aug 2026, "to qualified enterprises running agents on Anthropic" ([Drata release](https://drata.com/about/news/drata-extends-trust-management-platform-to-continuously-monitor-and-govern-ai-agents)).
  - It governs agents that call SaaS through MCP proxies. No public source names a coding harness, links agent activity to commits or PRs, or documents how its "tamper-evident" record is built.
  - It is Drata-hosted, with no self-hosting, and its price is undisclosed (4.03).
- **Vanta is now nearer for coding-agent sessions.** As a Claude Compliance API partner, its AI Inventory pulls Claude Code and Cowork sessions "Every four hours by default", reading the previous seven days. It is in beta for select Claude Enterprise customers, with general availability planned for January 2027 ([Claude Help Center](https://support.claude.com/en/articles/15167101-get-started-with-claude-compliance-api-integrations); [Vanta](https://www.vanta.com/integrations/claudes-compliance-api)) (4.03).

### 1.5 Model route, origin and lineage (2.09, 3.12, 4.08)
- **Org-level allowlists are everywhere; repository scope is nowhere.**
  - At least 10 of the 12 harness and gateway vendors 3.12 could read offer an org-level model or provider allowlist. About 7 add a host or region control. Three add a lab-origin control: Amp's "Chinese Labs" switch, Anaconda's "Country of Origin" field and Prisma AIRS's publisher block.
  - None scopes policy to a repository or a contract, and none gives per-request proof of host or jurisdiction (3.12).
  - 2.09 found the same for Copilot, Cursor, GitLab Duo Self-Hosted (which "does not capture which model or model provider the customer uses") and LiteLLM.
- **Gateways cannot prove the route either.** TrueFoundry: "AWS does not report the destination region back" ([TrueFoundry](https://www.truefoundry.com/docs/ai-gateway/aws-bedrock)). Databricks: a caller-supplied project tag "doesn't establish the caller's permission" ([Databricks](https://docs.databricks.com/aws/en/data-governance/unity-catalog/service-policies/policy-examples)) (3.12).
- **France routes per client by rule.** SREN Art. 31 and Decree 2026-272 require SecNumCloud for sensitive State data. "En production, votre solution utilise le compte Albert API de l'administration cliente." Albert's default code model is Alibaba's Qwen3-Coder-30B, with DeepSeek V4 Flash on trial ([DINUM suppliers page](https://guides.ia.numerique.gouv.fr/albert-api/guides/entreprises-se-connecter-a-albert-api); [DINUM models](https://guides.ia.numerique.gouv.fr/albert-api/modeles/available-models)). In EU procurement, "sovereign" means host and operator, not lab origin (3.12 inference). No tender notice found requires proof.
- **Lineage hides inside vendor models (4.08):**
  - Cursor's Composer 2 and 2.5 are built on Moonshot's Kimi K2.5 ([Cursor](https://cursor.com/blog/composer-2-5)), but the docs say "Provider: Cursor" ([Cursor docs](https://cursor.com/docs/models/cursor-composer-2-5)).
  - Cognition's SWE-1.7 is built on Kimi K2.7 Code, and SWE-2 on Kimi K3 ([Cognition](https://cognition.com/blog/swe-2)).
  - "SWE 1.6 Federal", listed for FedRAMP High, ITAR and IL4, has a base Cognition calls only "open-source" ([Devin federal](https://docs.devin.ai/federal/compliance)).
  - The served model is often hidden: Cursor Router hides it by default ([Cursor Router](https://cursor.com/docs/cursor-router)); Cursor's subagents use Composer by default ([Cursor 159047](https://forum.cursor.com/t/159047)); Devin's recommended Fusion pairing hands the coding to SWE-2 ([Fusion](https://docs.devin.ai/cli/fusion)).
- **Congress wrote the first public schema for route evidence (4.08).**
  - The April letters ask Anysphere for "real-time, affirmative disclosure of the identity and country of origin of every model processing their data at the time of processing", and ask both Anysphere and Airbnb for server locations and PRC jurisdiction for every entity in the processing chain ([Anysphere letter](https://homeland.house.gov/wp-content/uploads/2026/04/2026.04.29-Homeland-China-Select-Letter-to-Anysphere-Inc.pdf); [Airbnb letter](https://homeland.house.gov/wp-content/uploads/2026/04/2026.04.29-Homeland-China-Select-Letter-to-Airbnb-re-PRC-AI.pdf)).
  - The July letter asks DoorDash for an inventory with checkpoint, quantization, hosting environment, "the cryptographic hash or other identifier used to verify the deployed artifacts", and monthly request and token volumes by function ([DoorDash letter](https://homeland.house.gov/wp-content/uploads/2026/07/2026.07.31-Homeland-China-Select-Letter-to-DoorDash.pdf)).
  - The responses are not public.
- **Users and questionnaires barely ask.**
  - On the Cursor forum, 6 people raised lineage or host, 3 were explicitly indifferent, and none asked for per-session records.
  - One state-agency buyer, "restricted from using Chinese models by decree", asked to use "only Cursor models" ([Cursor 168923](https://forum.cursor.com/t/168923)).
  - Shared Assessments' August 2026 questions for a vendor that codes with AI ask what is AI-generated, what human review happens and whether there is an SBOM, but not which model, lab or host ([Shared Assessments](https://sharedassessments.org/blog/evaluating-third-party-ai-use-how-to-address-three-real-world-scenarios/)) (4.08).
- **Mixed fleets are where a route rule would bite.** In the 2026 Stack Overflow survey (computed in 3.12), 16.9% of agent-model users name a Chinese-lab vendor, but only 1.9% use no US closed vendor. Among EU users of open harnesses the share is 35.8% (225 people), and 88% of them also use a US closed vendor ([Stack Overflow data](https://github.com/StackExchange/Survey/tree/main/packages/archive/2026)).

### 1.6 Clients who want AI used, and its savings shared (3.06, 4.04)
- **Large IT-services clients contract for productivity, not tools.**
  - Infosys has reported since its FY2024 20-F that "clients have started demanding higher commitments around productivity improvements" ([Infosys 20-F FY2025](https://www.sec.gov/Archives/edgar/data/1067491/000095017025091925/infy-20250331.htm)).
  - On its October 2026 call: "across the client base, there is demand or request requirement, which is focused on productivity benefits from the AI that are getting passed on" ([Infosys Q2 FY27](https://www.sec.gov/Archives/edgar/data/1067491/000106749126000044/exv99w05.htm)).
  - No contract text found mandates particular AI tools.
  - The evidence asks are coarse: a "detailed proposal" before each AI use ([Talcott–Cognizant MSA](https://www.sec.gov/Archives/edgar/data/45947/000004594726000027/ex27i-talcottcognizantms.htm)); proof of "how and when" savings arrive ([ISG](https://isg-one.com/articles/index-insider---ai-savings-commitments-are-only-the-beginning)); and gainshare that settles "how it will be verified" ([Pinsent Masons](https://www.pinsentmasons.com/out-law/news/gainshare-clauses-incentivise-ai-related-savings-financial-services)) (4.04).
- **For small suppliers the pressure is informal.**
  - About a third of agencies have been asked for an AI discount, and the rate of asking had not risen by March 2026 ([Productive](https://productive.io/blog/agencies-in-the-ai-era/); [Productive pulse](https://productive.io/reports/agencies-in-the-ai-era-pulse-report/); vendor data).
  - Among small and mid-sized clients, 45% suspect agencies save with AI without passing it on, while 19% expect fee cuts ([AMI](https://businessofstory.com/wp-content/uploads/2025/11/2025AgencyEdge.pdf)).
  - 81% of freelance-platform clients encourage AI in some capacity ([CHI '26](https://arxiv.org/pdf/2603.07459)) (3.06, 4.04).
- **The documented per-client evidence need is the supplier's own.** Six new people ask for AI usage and cost by client or repository. Cursor's staff: "usage is attributed by user, model, and day, not by a specific repo or workspace. A per-repo breakdown isn't available on any plan yet" ([Cursor 164650](https://forum.cursor.com/t/164650)) (4.04).

### 1.7 How much first-hand voice the branch found (counts as the notes report them)
- **L1:** 7 distinct people on opened pages spoke to AI-evidence asks. 4 were vendor- or consultancy-affiliated, and 0 reported a first-hand customer or auditor request for agent-run records.
- **2.01:** 0 first-hand supplier voices described complying with a client AI clause.
- **2.10:** 4 practitioners were counted, and none reported an auditor ruling on AI-written code.
- **3.06:** 4 first-hand restriction voices with client context, 3 weaker ones, and 1 client mandating AI. The strongest: "most of our projects NDA for gov & defense clients absolutely forbid us to use any cloud based IDE tools … Would love … Bring Your Own Inference Endpoint" ([HN 44565144](https://news.ycombinator.com/item?id=44565144)).
- **3.10:** one Vanta Community member filed a request "to be able to pull in claude code reviews", with no staff reply ([Vanta Community](https://community.vanta.com/x/grc/nwnr9uwkwu1y/ai-only-code-reviews-and-soc-2-change-management-e)).
- **4.03:** 1 named user of Drata's product, in a vendor-selected quote.
- **4.04:** 0 new client-originated demands for per-task evidence, and 6 supplier-side attribution needs.
- **4.08:** 6 forum users raised lineage, 3 were indifferent, and 0 asked for per-session records.
- **Reddit** was unreachable throughout.

---

## 2. How the deeper levels changed the level-1 findings

Level 1 proposed eight directions. The deeper levels confirmed some, narrowed others, and added new ones.

| Level-1 finding or direction | What the deeper levels found | Net effect |
|---|---|---|
| AT&T's SAIR "reads like a specification for sidecar's ledger"; lead the client packet with a per-release AI SBOM (L1, medium) | Of 13 buyers, only AT&T asks for a per-release SBOM (1/13) or deletion with pseudonymized metadata (1/13). The pattern is gates (8/13 default deny; 11/13 no training; 7/13 human review) plus records on request (7/13) (2.01). Clients approve per engagement, tool or use case, and accept documents; logs only in narrow cases (3.06). | **Narrowed.** Lead with enforced per-engagement policy and generated documents. The SBOM becomes one export. |
| Client-matter retention mode (L1, high) | Clients split between "keep records of AI use" and "don't retain client data in the AI tool" (2.01). On their text, Northrop's and L3Harris's clauses reach a harness's own local transcripts; encrypted CUI is still CUI; discovery counsel favor deliberate retention (3.05). New York's terms bar the vendor from storing or retaining State data beyond the contracted services (3.06). | **Strengthened and widened.** Also suppress harness stores, govern replay into agents, and keep CUI out of hosted storage. |
| The DHS order's "developed using" might make serving receipts a compliance artifact (L1) | "Developed using" probably does not reach written code; the "use" route through FAR 52.204-30 does, and the live case for coding agents is the hosted Anthropic designation (2.09). The signed order ties "used to provide" to the exclusion leg; GSA vehicles carry DoD and DNI orders; GSA's final clause excludes internal use (3.05). | **Re-pointed.** The hook is use in contract performance, keyed to vendor, lineage and controller. The record must cover hosted endpoints and the harness, not only self-hosted weights. |
| Signed serving receipts with OMS verification, marketed as proof of origin and integrity (L1, medium) | No contracting officer or prime asks for publisher signatures or cryptographic proof (3.05). No procurement document asks for per-request proof (3.12). The House letter to DoorDash asks for an artifact hash, and lineage hides inside vendor models (4.08). | **Narrowed.** A headline only for public-sector, defense and letter-risk buyers; "evidence for" a representation, not a requested artifact. The record must be per step and two-axis, with "lineage undisclosed" as a value. |
| Auditor-sampling export plus a verifier that runs without URnetwork (L1, medium) | Method confirmed: system-generated populations, IPE completeness, 25–40 samples; the sponsor field settles segregation of duties (2.10). GRC change populations lack author, approver and AI fields, and the platforms neither keep history nor verify signatures (3.10). "Tamper-evident" is now Drata's vocabulary, with no published mechanism (4.03). | **Strengthened and sharpened** to sponsor ≠ approver. The integrity claim must name its mechanism. |
| Compliance mappings early, published as a reference evidence spec (L1, medium) | The 2027 draft renumbers criteria, so one ID means different things from 2027 to 2029, and AIUC-1's crosswalk uses 2017 IDs. MAS maps almost one to one and applies from Oct 2027 (2.10). | **Qualified.** Mappings must carry the criteria version, and should add MAS, DORA Art. 17, NYDFS and PCI 6.2.3. |
| Re-sequence the assurance story: regulation does not require agent records; add large-enterprise suppliers to the beachhead (L1, high) | Banks, defense primes and services firms impose binding gates (2.01); defense primes' 2026 clauses are the most specific (3.05). SSPA v11 exempted tool users, but v12 dropped that sentence (2.01, 3.06). Pitch4's "December 2027" line overstates the draft (2.10). Questionnaires still don't ask about model, lab or host (4.08). | **Confirmed.** The beachhead changes; the Microsoft line needs re-verification. |
| Export into GRC platforms rather than compete (L1, medium) | Feasible but narrower: private integrations only, plan-gated, no partner path for change records (3.10). Drata's agent governance does not target coding harnesses or small buyers; Vanta's AI Inventory ingests Claude Code sessions, in beta (4.03). | **Confirmed with constraints.** The bundling watch shifts to Vanta. |
| A client data boundary for context and memory (L1, medium) | No-input and no-merge clauses reach context use at 7 of 13 buyers (2.01). L3Harris requires "segregation of Buyer Data from other data sets" (3.05). Zuellig bars client data in "shared AI environments" (3.06). | **Strengthened.** |
| Practitioner voice is thin; the credibility of evidence is the audible pain (L1) | Still thin at every level (§1.7). | **Unchanged.** Demand evidence is textual, not voiced. |
| Not considered at level 1 | Clients who want AI used and its savings shared (3.06, 4.04); per-client attribution (4.04); per-repository route policy and the two axes of lab and host (2.09, 3.12, 4.08); per-step recording, because routers and subagents hide the served model (4.08); a human-in-the-loop clause for client environments (3.05); CUI and hosted storage (3.05); review depth and habituation (2.10); MAS, NYDFS and DORA texts (2.10); licence duties (4.08). | **New directions** (D5, D9–D13). |

**Corrections between the notes** (use the later reading):
- **GSA.** 4.04 cites GSA's March 2026 draft clause, under which contractors would "disclose all AI systems used in performance of the contract". 3.05 found that the final clause (effective 19 Oct 2026) applies only when the government buys an LLM system, turns itself off for a contractor's internal use, and describes no disclosure, inventory, logging or certification duty. Drop GSA as a driver.
- **Vanta.** 3.10 concluded that Vanta lacked "anything from inside the session". 4.03 found that Vanta's AI Inventory pulls Claude Code sessions through Anthropic's Compliance API, in beta.
- **Microsoft SSPA.** 2.01, reading v11, treated tool users as exempt. 3.06 found the exemption sentence absent from v12 and a new "Deployer" profile. Whether pure tool users are now in scope is open.
- **DHS order.** 2.09's "use" route rested on CSA's reading. 3.05 verified it from footnote 10 of the signed order.
- **Devin federal.** 3.12 read Devin's federal table as listing no open-weight or Chinese-lab models. 4.08 refined this: it lists SWE 1.6 Federal, whose base Cognition calls only "open-source".
- **SOC 2 numbering.** L1 and 4.03 use "CC8.1" for change management, which is the 2017 numbering. In the 2027 draft, CC8.1 is vendor management and change management is CC7.1–CC7.3 (2.10).
- **Bundling ranking.** 3.10 ranked Drata as the highest bundling risk. 4.03 revised this: Vanta is nearer for coding-agent sessions, and Drata nearer only for inline enforcement over business agents.
- **Route policy as a release item.** 2.09 proposed contract-scoped model policy as a first-release model-access item. 3.12 advised keeping it as configuration behind the record, not as the headline, because no procurement document asks for proof.

---

## 3. Directions for pitch4

Pitch4's pages: 1 the idea; 2 for developers; 3 for security buyers; 4 open source and open weights; 5 market and pricing; 6 the plan. Section names below are pitch4's own headings.

| # | Direction | Pitch4 pages | Effect | Confidence | Main notes |
|---|---|---|---|---|---|
| D1 | Keep the record, not the content, for client and contract work | 1, 2, 3, 4, 5, 6 | offering | high | L1, 2.01, 3.05, 3.06 |
| D2 | Bind AI policy to the client engagement, enforced per repository across harnesses | 3, 5, 6 | both | medium | 2.01, 2.09, 3.05, 3.06, 3.12 |
| D3 | Generate the documents clients already ask for (the client packet) | 3, 5, 6 | offering | medium | L1, 2.01, 3.05, 3.06, 4.04 |
| D4 | Keep each client's context, memory and handoffs separate | 2, 3 | offering | medium | L1, 2.01, 3.05, 3.06 |
| D5 | Mediate agent actions in client environments; bind approvals to the exact action | 3 | differentiation | medium | 2.01, 2.10, 3.05, 4.03 |
| D6 | Lead with sponsor ≠ approver; export auditor-ready populations | 3, 5, 6 | differentiation | medium | L1, 2.10, 3.10, 4.03 |
| D7 | Make "verifiable without trusting us" the claim, and name the mechanism | 1, 3, 5 | differentiation | medium | L1, 2.10, 3.10, 4.03 |
| D8 | Feed Vanta, Drata and Secureframe through an open bridge, with version-aware mappings | 5, 6 | offering | medium | L1, 2.10, 3.10, 4.03 |
| D9 | Widen model access to approved hosted endpoints; record the provider path | 3, 4, 6 | both | medium | 2.09, 3.05, 3.12 |
| D10 | Record the route per model call, with lineage and host as separate, tiered fields | 3, 4 | differentiation | high | L1, 2.09, 3.12, 4.08 |
| D11 | A provenance-inquiry export and an open lineage map | 4, 5 | both | medium | 3.12, 4.08 |
| D12 | A defense and federal deployment mode | 3, 4, 6 | offering | medium | 2.09, 3.05, 3.06 |
| D13 | One per-client record for clients who encourage AI and expect its savings | 3, 5 | offering | medium | 3.06, 4.04 |
| D14 | Re-target "Where we start" to the binding triggers | 5, 6 | differentiation | medium | 2.01, 2.09, 2.10, 3.05, 3.06, 3.12, 4.08 |
| D15 | Correct the assurance timeline and tighten the claims | 3, 4, 5 | differentiation | high | all notes |

**If pitch4 can absorb only five changes (synthesis judgment):**
- D15, because it is cheap and each correction rests on a primary text;
- D1, because pitch4's vault promise conflicts with binding client clauses;
- D10, because a per-session record would misstate which models touched the code;
- D6, because it is the clearest verified gap in every compliance tool checked;
- D2 together with D3, because policy per engagement is where four notes converge.

---

### D1. Keep the record, not the content, for client and contract work
- **Pitch4 pages and sections:**
  - Page 1, "For developers" box, and page 2's headline "Never lose a session or an edit";
  - page 2, "Session vault" ("Archived instead of deleted");
  - page 3, "What admins can answer";
  - page 4, "Open core, hosted blind";
  - page 5, "Who pays", Assured row (legal hold);
  - page 6, "Next: the team layer" (retention).
- **What to change:**
  - Make retention a per-engagement setting. For repositories tagged to a client or contract under a no-retention clause, the default is not to persist session content, or to purge it when the engagement closes.
  - Keep the signed, pseudonymized metadata record in the ledger, with the mapping key held by the team. This follows AT&T C.1.d's escrow pattern.
  - Suppress the harness's own transcript store for that work, and record the suppression and each purge as evidence. Claude Code documents `CLAUDE_CODE_SKIP_PROMPT_HISTORY`, which works "in any mode", and `claude purge`.
  - Keep any retained content inside the customer's own boundary, treated as client information. Re-feeding it into an agent (resume, handoff, context) becomes an approved action.
  - Never hold CUI in URnetwork-hosted storage. Legal hold overrides disposal.
  - Reword: "never lose a session" for your own work; "never lose the record" for client work.
- **Why it helps:**
  - Pitch4's vault promise breaches binding clauses for client work, while its split between the developer's vault and the team's ledger already matches AT&T's carve-out for "metadata or audit logs … for traceability" (L1).
  - It turns a liability into a feature: "delete what the client requires, prove what happened" (L1).
  - It matches counsel's pattern as 3.05 synthesizes it: a narrow signed metadata record per contract, and short, per-contract content retention with documented disposal and a litigation-hold override.
- **Evidence:**
  - AT&T C.1.c: "will permanently delete the AT&T Information following its intended use. However, metadata or audit logs … may be retained solely for traceability purposes" ([AT&T SAIR](https://attsuppliers.com/downloads/ATT-Supplier-Artificial-Intelligence-Requirements-V1.pdf)) (L1, 2.01).
  - No retention inside the AI tool:
    - Northrop: "not stored, logged, cached, or otherwise retained by the AI System" ([Northrop R05_26](https://cdn.northropgrumman.com/-/media/Supplier-Documents/Terms-and-Conditions/CTM-P-ST-003USGTMOrderNotforCommercialProductsServices_R05_26.pdf));
    - L3Harris: no AI system that "will maintain any persistent copy" ([L3Harris 2025](https://www.l3harris.com/sites/default/files/2025-07/LGL-50.F1-Rev-July-2025.pdf)), and an approved system "does not retain, reuse, validate, test, improve, fine tune, or train on such data" ([L3Harris 2026](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf));
    - Google: "turn off any AI features that store (even temporarily)" ([Google](https://support.google.com/legal/answer/16117094)) (2.01, 3.05).
  - New York: "The Vendor shall not store, retain, or repurpose the State's data for any purpose other than providing the contracted services" ([NY ITS](https://its.ny.gov/system/files/documents/2025/04/appendix-c-ai-april-2025_1.pdf)) (3.06).
  - Harnesses keep local stores, and some can switch them off: [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference). Claude for Government "keeps conversation history on each user's device" ([Anthropic](https://claude.com/solutions/government)). AWS: "Claude Code runs on local developer machines and requires separate evaluation" ([AWS](https://aws.amazon.com/blogs/machine-learning/supercharge-regulated-workloads-with-claude-code-and-amazon-bedrock/)) (3.05).
  - "Encrypted CUI data retains the control designation", and a cloud storing it must meet FedRAMP Moderate ([AWS CMMC FAQ](https://docs.aws.amazon.com/prescriptive-guidance/latest/cmmc-level-2-compliance-on-aws/faq.md)) (3.05).
  - 2026 discovery commentary favors "deliberate retention"; "Exploratory prompts and draft outputs … may be subject to defensible disposition practices" ([K&L Gates](https://www.klgates.com/Litigation-Minute-Preserving-AI-Generated-ESI-in-Anticipation-of-Litigation-5-20-2026); [Kilpatrick](https://ktslaw.com/insights/alert/2026/7/discoverability-of-generative-ai-prompts-and-outputs-best-practices-for-litigation-holds); search summary) (3.05).
- **Counter-evidence:**
  - Other clients require records to be kept: BT, C&W, Northrop 22(M)(3), Lockheed and Barclays, 5 of 13 (2.01). So the record must stay, and only content can go.
  - The reading that a harness's transcripts are "retained by the AI System" is the researcher's own; no prime or counsel has stated it (3.05).
  - Persistence switches in Codex, Cursor, Copilot, OpenCode and Goose were not checked (3.05).
  - Replaying stored sessions into agents may be read as "reuse", or as the "feed" barred by L3Harris's 2025 Art. 26(d) (3.05).
  - Pitch4 says the vault "is why a developer installs the sidecar", so narrowing it touches the adoption wedge (synthesis judgment).
- **Cost and risk (synthesis judgment):**
  - **Build:** per-engagement retention modes, purge jobs with signed purge receipts, and suppression of each harness's own store.
  - **Risks:** the developer promise becomes conditional, and pseudonymized metadata may still count as client information unless built to C.1.d.
- **Test:**
  - Map 3–5 design partners' actual client clauses onto the retention modes.
  - Ask a prime's supplier-compliance contact, or government-contracts counsel, whether harness transcripts fall under Northrop 22(M)(2)(c)(ii) or L3Harris 9(iii).
  - On page 6's "Do developers keep it running?" measure, compare daily use under content-off defaults.
- **Confidence:** high. Binding text at several buyers conflicts with "Archived instead of deleted". The harness-store reading is medium.

### D2. Bind AI policy to the client engagement, and enforce it per repository across every harness
- **Pitch4 pages and sections:**
  - Page 3's headline promise ("private, approved, and on a record") and "What admins can answer";
  - page 5, "Where we stand, piece by piece" (a new row) and "Who pays", Team row;
  - page 6, "What ships, in order".
- **What to change:**
  - Add engagement profiles bound to sets of repositories. Each profile holds:
    - a mode: "no AI", "approved tools and providers only", or "private models only, no content kept";
    - the approved harnesses, models, providers and endpoints, use cases, allowed data classes and retention mode, and whether human-in-the-loop is required;
    - the authority for each entry: an SOW clause, a Work Order, an email approval ID or a notice date.
  - The sidecar enforces the mode at model access and reach, denies by default, writes an exception log, and travels with the repository to freelancers and subcontractors.
  - Read and respect the harness's or gateway's own org allowlist rather than building another (3.12).
  - Say what the binding cannot prove: a developer with local admin rights can misreport the repository. So pitch it as protection against *accidental* misrouting and as evidence for clients, with stronger assurance only on managed devices or hosted agents (3.12).
- **Why it helps:**
  - Default deny is the pattern (8 of 13), and 2.01 found no product that turns a client clause into enforcement or evidence.
  - Every vendor scopes policy to people or features, never to the code being worked on. Group semantics widen access ("Grants only add access", [Amp](https://ampcode.com/docs/markdown/enterprise/allowed-models); "The union gotcha", [Devin federal](https://docs.devin.ai/federal/model-provisioning)), so a contract rule that must *restrict* is poorly served by groups (3.12).
  - Under prohibitions, workers "interpreted prohibition as a reason to remain silent" ([CHI '26](https://arxiv.org/pdf/2603.07459)). So enforcement plus an exception log is more credible than self-reporting (3.06).
- **Evidence:**
  - The default-deny clauses (2.01): Citi; [AT&T SISR](https://globalsupplychain.att.com/misc/ATT_SISR_Appx.pdf) §3.6; HSBC; Lockheed; Gallagher; C&W; BCG.
  - L3Harris 17(b)(i) requires written approval after the supplier "has disclosed the specific AI systems, providers, and use cases involved" ([L3Harris 2026](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf)) (3.05).
  - Agencies ask for per-client rules:
    - DC_9000's three clients, "no AI code generation whatsoever", "Use AI tools, go fast!" and "Case-by-case approval required" ([Cursor 136492](https://forum.cursor.com/t/repository-level-ai-policy-file-ai-policy-txt-for-client-compliance/136492); [claude-code #9070](https://github.com/anthropics/claude-code/issues/9070));
    - Agile Collective's per-client "AI Policy" document ([handbook](https://handbook.docs.agile.coop/13-artificial-intelligence/policy/));
    - BuiltByGo's SOW-level "no AI" option ([BuiltByGo](https://builtbygo.com/ai-usage));
    - JetBrains' `.noai` file covers only JetBrains' own assistant ([JetBrains](https://jetbrains.com/help/rider/Disable_AI_Assistant.html), search summary) (3.06).
  - Endava's 20-F: "some clients prohibit autonomous code generation or require explicit disclosure of agentic methods" ([Endava](https://www.sec.gov/Archives/edgar/data/1656081/000165608125000039/dava-20250630.htm)) (3.06).
  - No vendor scopes policy to repositories:
    - Copilot ([GitHub](https://github.blog/changelog/2026-08-27-global-model-policy-generally-available/)), Cursor ([Cursor](https://cursor.com/docs/enterprise/model-and-integration-management)) and GitLab ([GitLab](https://docs.gitlab.com/administration/gitlab_duo_self_hosted/)) (2.09);
    - Devin applies org overrides by the user's "primary billing org" ([Devin](https://docs.devin.ai/enterprise/local/controls)) (3.12).
- **Counter-evidence:**
  - Clients approve per engagement and accept documents; "records exist as a backstop, not as the routine proof" (3.06).
  - Per-instance approval is "neither realistic nor operationally practical" ([Davis+Gilbert](https://www.dglaw.com/wp-content/uploads/2026/09/AI-Is-Reshaping-Agency-Work-Are-Your-Contracts-Keeping-Up.pdf)).
  - Only 4 first-hand voices are on record (3.06), and the one public allowlist request 2.09 found was per user, not per repository ([Cursor forum](https://forum.cursor.com/t/model-allow-list-per-team-member/121588)).
  - Browser chats and personal devices bypass the sidecar (3.06).
  - Configuration sits with platform admins, and sign-off with contracts, delivery or compliance, so the sale needs two buyers (3.12).
  - 3.12 advises presenting route policy as configuration behind the record, not as a headline.
  - Some buyers do not gate at all: Cisco accepts agentic AI without prior approval ([Cisco](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/docs/Supplier-AI-Policy.pdf)) (3.06).
  - Willingness to pay is untested.
- **Pitch4 change:**
  - Page 3, "What admins can answer": add "Which client's AI rules applied to each repository, and every exception."
  - Page 5, "Where we stand": add a row, "Client AI terms enforced per repository, across harnesses: No one; vendors scope policy to users, groups and features."
  - Page 5, Team row: add "per-client AI policy".
  - Page 6: list engagement profiles beside approval receipts and run inventory.
- **Cost and risk (synthesis judgment):**
  - **Build:** repository binding at call time (remote URL, commit), enforcement that differs per harness, and the exception log.
  - **Risk:** false assurance outside the sidecar's view, and a slower two-buyer sale.
- **Test:**
  - With design partners, count client engagements with distinct AI terms, repositories tagged, and exceptions caught per month.
  - Ask one bank or defense supplier's delivery lead whether a profile plus an exception log would replace email approvals.
  - Add the row "Do clients accept enforced profiles?" to page 6's design-partner table.
- **Confidence:** medium. The need is binding for defense, bank and government suppliers; differentiation and willingness to pay are untested.

### D3. Generate the documents clients already ask for, with the runs as backing
- **Pitch4 pages and sections:**
  - Page 3, "What admins can answer" ("Proof for a client that a person approved a change, without the code");
  - page 5, "Who pays", Team row ("client packets");
  - page 6, "Next: the team layer" ("client packets").
- **What to change:** define the client packet as generated documents, not a dump of runs.
  - A per-engagement inventory of tools, models and providers, shaped as a sub-processor list with first-use, notice and objection dates.
  - Each provider's training and retention terms, checked against a list such as Cisco §2.3.
  - Approvals, each with its authority.
  - Human-review evidence: pull-request approvals.
  - "No-AI repositories stayed clean" exception reports, with the coverage boundary stated.
  - Ready-made notices: California GTC and SAM 4986.2, New York Appendix C-AI, 30-day notices like Raiffeisen Informatik's, and UK PPN 02/24 Q3 and PPN 017.
  - For defense primes: the L3Harris 17(h)(i) inventory, drafts of 17(h)(ii) change notices and 17(i) 72-hour notices, and Northrop 22(M)(3) documentation.
  - Run-level records available on request.
  - The AT&T-style per-release AI SBOM stays as one export, built on CycloneDX `formulation` plus an ML-model component and an "AI Generated" property, or SPDX 3 `Tool`/`usesTool`/`generates` (L1).
  - Price the packet inside Team, not as a separate audit product (3.06).
- **Why it helps:**
  - The evidence clients accept is documents and attestations (3.06), and "records on request" is the common form (2.01). Suppliers answer such requests today from memory, invoices and commit trailers (2.01).
  - The packet earns its place when it "generates the documents clients already ask for and keeps the runs as backing" (3.06).
  - Notice clocks of 2 to 90 days and assessments of about four months (ProcessUnity, vendor claim) mean a complete first submission shortens the cycle (3.06 inference).
- **Evidence:**
  - Records on request: Northrop 22(M)(3); BT; Lockheed; the DTA template ("promptly provide these records to the Buyer if asked") ([DTA](https://www.hoganlovells.com/-/media/8ceddfbb6c67472c86078098acd7e853.ashx)) (2.01).
  - What buyers ask for (3.06):
    - descriptions and notices: [NY ITS](https://its.ny.gov/system/files/documents/2025/04/appendix-c-ai-april-2025_1.pdf), [Raiffeisen Informatik](https://www.raiffeiseninformatik.at/wp-content/uploads/2026/06/R-IT_SRS_Stand_20260615.pdf), [Carrier](https://www.corporate.carrier.com/Images/Standard-Terms-Conditions-Purchase-Attachment%20E-0625_tcm558-273921.pdf), [PPN 02/24](https://www.gov.uk/government/publications/ppn-0224-improving-transparency-of-ai-use-in-procurement/ppn-0224-improving-transparency-of-ai-use-in-procurement-html);
    - provider contracts that "prohibit the storage of Protected Data" ([Cisco](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/docs/Supplier-AI-Policy.pdf));
    - documentation on request ([Zuellig](https://edge.sitecorecloud.io/zuelligphar3c90-zpcms-prod-4532/media/Project/Corporate/Policy/Zuellig-Pharma--AI-Policy-for-Service-Providers-Consultants---25022026.pdf));
    - logs only under California's Special Provisions ([CDT](https://www.cdt.ca.gov/wp-content/uploads/2025/02/GenAI-Special-Provisions-January-2025.pdf)).
  - Small suppliers already keep registers by hand: Geeks' "AI Register" records client, project, sign-off, tool and purpose ([Geeks](https://www.geeks.ltd/ai-use-policy)) (3.06).
  - Disclosure clauses are spreading: Talcott–Cognizant §6.03 ([MSA](https://www.sec.gov/Archives/edgar/data/45947/000004594726000027/ex27i-talcottcognizantms.htm)); OMB M-25-22 §3(h) ([OMB](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf)); [PPN 017](https://www.gov.uk/government/publications/ppn-017-improving-transparency-of-ai-use-in-procurement) (4.04).
  - Neither CycloneDX nor SPDX has an agreed field for AI-authored code ([aiprov](https://github.com/TrueHorison/aiprov)) (L1).
- **Counter-evidence:**
  - It is untested whether clients prefer a generated packet to "a blanket SOW clause plus a tool list, which costs suppliers nothing today" (3.06).
  - No buyer has said a signed export would replace email approvals (2.01).
  - Only AT&T asks for the SBOM (2.01).
  - GSA's draft disclosure duty did not survive into the final clause (3.05, correcting 4.04).
  - An "attestation of non-use" proves only what passed through the sidecar (3.06).
- **Pitch4 change:**
  - Page 5, Team row: spell out the packet's contents.
  - Page 3: "Proof for a client that a person approved a change" becomes "A client's AI disclosure, generated: tools, providers, approvals, review and exceptions."
  - Page 6: list the notice templates.
- **Cost and risk (synthesis judgment):**
  - **Build:** templates per client type, kept current as terms change.
  - **Risk:** a wrong generated notice is the supplier's liability.
- **Test:**
  - Give 3–5 agency or outsourcer partners a generated packet for one real client.
  - Record whether the client accepts it in place of a questionnaire or email thread, and how long the first approval takes.
- **Confidence:** medium. The document asks are well evidenced; client acceptance is untested.

### D4. Keep each client's context, memory and handoffs separate
- **Pitch4 pages and sections:**
  - Page 2: "Context that loads", "Pick up anywhere" (handoff notes), "Agents that find each other's work" and "Yours unless you share";
  - page 3, "What admins can answer".
- **What to change:**
  - Tag every context artifact with its client engagement: handoff notes, agent memory, team context files, embeddings and indexes.
  - Block retrieval across engagements.
  - Record in the ledger that the scoping held, and export that as evidence that clients were kept separate.
- **Why it helps:**
  - Pitch4's page 2 features move context between runs, harnesses and teammates. For a supplier with several clients, that is a contract risk unless it is scoped.
  - Coordination tools do not offer this scoping (2.01 inference).
- **Evidence:**
  - AT&T defines "Model" to include "prompt/context learning, RAG or vector storage" and "data embedding" ([AT&T SAIR](https://attsuppliers.com/downloads/ATT-Supplier-Artificial-Intelligence-Requirements-V1.pdf)) (L1).
  - Citi: "shall not merge Content or Citi Information with Supplier or any third-party data" ([Citi](https://www.citigroup.com/rcs/citigpa/storage/public/Citi-Requirements-for-Suppliers-English.pdf)).
  - Gallagher: models "logically segmented, not commingled … encrypted using a unique encryption key" ([Gallagher](https://www.ajg.com/br/-/media/files/gallagher/br/privacy-policy/ggb-br-global-online-ai-addendum-en.pdf)).
  - Such clauses reach context use, in effect, at 7 of 13 buyers (2.01).
  - L3Harris 2026: "Maintain segregation of Buyer Data from other data sets" ([L3Harris 2026](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf)) (3.05).
  - Zuellig: "no Client Data is used in publicly accessible or shared AI environments" ([Zuellig](https://edge.sitecorecloud.io/zuelligphar3c90-zpcms-prod-4532/media/Project/Corporate/Policy/Zuellig-Pharma--AI-Policy-for-Service-Providers-Consultants---25022026.pdf)) (3.06).
- **Counter-evidence:**
  - Only AT&T bans RAG explicitly (1 of 13).
  - No first-hand report of a breach claim over shared context was found. A tool builder's remark that cloud vector databases "breaks NDA on client code" was not counted as demand ([Cursor 168479](https://forum.cursor.com/t/168479)) (3.06).
  - Scoping may cut into the coordination value that pitch4 still calls "A hypothesis until the pilots measure it".
- **Pitch4 change:**
  - Page 2: add "scoped to the client engagement; nothing crosses clients" to the context, handoff and claims features.
  - Page 3: add "evidence that each client's context stayed separate".
- **Cost and risk (synthesis judgment):**
  - **Build:** tags and retrieval filters; per-engagement keys would mirror Gallagher's unique-key wording.
  - **Risk:** more friction for developers working across clients.
- **Test:** in agency pilots, count cross-client context loads blocked, and ask whether scoping broke real workflows.
- **Confidence:** medium.

### D5. Mediate agent actions in client environments, and bind each approval to the exact action
- **Pitch4 pages and sections:** page 3, the "Port forwarding" and "IP addresses" grant rows, "What admins can answer" ("Who approved each action: one action ID, SSH-signed for high-risk steps") and "Safe by default".
- **What to change:**
  - Let a team tag a client's networks and systems as "mediated". Every agent action that reaches them through a forward or private address then waits for a recorded human approval.
  - Bind each approval to the exact command, diff or commit hash.
  - Present Barclays-style safeguards as existing pieces (2.01):
    - kill switch → lease revocation, pitch4's "One switch";
    - containment across steps → claims, leases and approved reach;
    - post-action review → ledger replay.
- **Why it helps:**
  - A prime now states this as a contract term, and pitch4's reach grants and per-action receipts already have its shape (3.05).
  - Drata records approvals as "who approved it, when, and against which policy". It does not say they are bound to a diff or command ([Drata](https://drata.com/learn/agent-gov/human-in-the-loop-for-ai-agents)) (4.03). Binding approvals to the exact action is where pitch4 can be specific.
- **Evidence:**
  - L3Harris 2026, Art. 17(d)(i): no AI system with "unmediated read, write, deployment, or execution access to any Buyer networks, systems, databases, or APIs", and every interaction subject to a human "who maintains the ability to review, approve, reject, or modify any action before it is executed" ([L3Harris 2026](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf)) (3.05).
  - Barclays: "a kill switch or equivalent mechanism"; controls to "contain autonomous decision-making or action execution, including where actions are taken across multiple steps"; "transparent post-action review" ([Barclays AI SCO](https://home.barclays/content/dam/home-barclays/documents/who-we-are/our-suppliers/English/v16/Artificial%20Intelligence%20SCO%20v16.0%20-%20English.pdf)) (2.01).
  - AIUC-1 D003.4, "Requiring human approval for sensitive tool operations", has been a core control since 15 Oct 2026 ([AIUC-1 changelog](https://standard.aiuc-1.com/changelog)) (2.10).
  - BuiltByGo gives AI tools connected to production "Read-only credentials by default" ([BuiltByGo](https://builtbygo.com/ai-usage)) (3.06).
- **Counter-evidence:**
  - The per-action clause rests on one prime's text (3.05).
  - Drata already ships approvals, so "approvals" alone are not distinctive (4.03).
  - Human approvals degrade with habituation: approval rates rise and comments fall ([arXiv 2606.22721](https://arxiv.org/abs/2606.22721)). MAS warns of "automation bias and decision fatigue" (2.10).
  - Approval of every AI use is impractical ([Davis+Gilbert](https://www.dglaw.com/wp-content/uploads/2026/09/AI-Is-Reshaping-Agency-Work-Are-Your-Contracts-Keeping-Up.pdf)), so mediation should cover only client environments.
- **Pitch4 change:**
  - Page 3 grant rows: add a "mediated" mode for client environments.
  - "What admins can answer": approvals "bound to the exact command or diff".
  - "Safe by default": add "client environments are mediated by default".
- **Cost and risk (synthesis judgment):** builds on the planned approval receipts. The risks are approval latency and rubber-stamping.
- **Test:**
  - With one defense or bank supplier, tag one client environment as mediated for a month.
  - Measure approvals per day, waiting time and review depth.
  - Ask whether the prime's supplier manager accepts the receipts as evidence under 17(d).
- **Confidence:** medium.

### D6. Lead the compliance story with sponsor ≠ approver, and export auditor-ready populations
- **Pitch4 pages and sections:**
  - Page 3, "What admins can answer";
  - page 5, "Who pays", Team row ("exports");
  - page 6, "First release" (beside "commit-to-run links").
- **What to change:**
  - Make the sponsor a first-class field: the human who started or directed each agent run.
  - Ship an enforced segregation-of-duties control. It blocks or flags merges where approver = sponsor or approver = deployer, and agent identities that hold merge rights.
  - Rename "exports" as auditor-ready populations (2.10):
    - **changes:** enriching the forge's own change population, including changes with no agent run, flagged;
    - **agent identities and grants;**
    - **approved versus observed AI:** with detections and a coverage statement;
    - **model change events;**
    - **oversight events:** with review-depth metrics.
  - Every export carries an envelope: period, query parameters, record count, reconciliation to the forge's merged-change count, checkpoint ID and signature, export hash, and an open verifier command.
  - Pitch line from 3.10: "Vanta sees the pull request. The sidecar says which agent wrote it, for whom, and who approved it."
- **Why it helps:**
  - This is the one segregation-of-duties check that every platform's native test misses for agent-opened PRs. Forge data cannot answer it; a sponsor field can (2.10, 3.10).
  - Populations generated from the system of record pass completeness testing better than hand-built lists (2.10).
  - An enforced control may be tested once instead of sampling 25–40 changes. This rests on secondary sources (2.10).
- **Evidence:**
  - Linford: an insufficient population was one that "was not systematically generated"; the preferred population is one "directly obtained from the source code library" ([Linford IPE](https://linfordco.com/blog/iuc-ipe-audit-procedures-for-soc-audits/)). Samples start at 25 and expand to 40 ([Linford sampling](https://linfordco.com/blog/audit-sampling/)).
  - Noru on draft CC7.2–7.3: "the evidence that a separate person approved it has to come from somewhere" ([Noru](https://noru.tech/resources/soc2-2027-trust-services-criteria)).
  - BrightByte, a vendor, reports that auditors ask: "Pull a sample of 10 production commits and identify which were AI-assisted" ([BrightByte](https://thebrightbyte.com/playbook/expertise/ai-coding-agents-soc2)).
  - Binding independence rules: DORA RTS Art. 17(1)(b) ([Springlex](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-17/)); PCI DSS 6.2.3.1 ([Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/06/02/03/)).
  - Supervisors' oversight asks: NYDFS ([NYDFS](https://www.dfs.ny.gov/industry-guidance/industry-letters/20260521-heightened-cybersecurity-risks-assoc-with-frontier-ai-models)); MAS ¶5.9 on oversight interventions and near misses ([MAS](https://www.mas.gov.sg/-/media/mas-media-library/regulation/guidelines/bd/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions/guidelines-on-artificial-intelligence-risk-management.pdf)) (2.10).
  - The gap in GRC tools (3.10, 4.03):
    - Vanta's `CodeChange` record has no author, approver or AI field ([Vanta SDK](https://github.com/VantaInc/vanta-auditor-api-sdk-typescript/blob/main/docs/models/components/codechange.md)).
    - Vanta's PR test treats bot-authored PRs like human ones ([Vanta](https://help.vanta.com/en/articles/14845240-github-integration-guide)).
    - Drata's Test 8 reads branch settings ([Drata](https://help.drata.com/en/articles/4776886-test-formal-code-review-process)).
    - Drata's agent governance links nothing to commits, PRs or change-management controls.
  - Wallfacer: AI authorship should be "distinguishable in the record, by identity, not by a trailer policy engineers can strip" ([Wallfacer](https://www.wallfacer.ai/guide/reference/security-questionnaire)) (L1).
- **Counter-evidence:**
  - Points of focus require no specific control, and most 2027 reports will use the 2017 criteria. 2.10 infers that the first mandatory Type 2 reports under the 2027 criteria arrive in late 2028–2029.
  - No CPA firm has published on the draft, on stratifying changes by AI authorship, or on treating prompter = approver as an exception (2.10).
  - "Tested once" rests on secondary sources and a SOX analogy.
  - Inside one company, auditors accept forge approval logs (2.10).
  - A customer's auditor may treat a hosted ledger as a subservice organization needing URnetwork's own SOC 2 report (2.10 inference).
  - The sidecar sees only agents that route through it.
  - BrightByte's auditor requests are vendor-reported.
- **Pitch4 change:**
  - Page 3: add "Whether the person who directed each agent also approved its change."
  - Page 5, Team row: "exports" becomes "auditor-ready populations, reconciled to your forge".
  - Page 6, first release: the sponsor field and the segregation-of-duties check.
- **Cost and risk (synthesis judgment):**
  - **Build:** forge reconciliation for each forge.
  - **Risks:** the sponsor field is only as accurate as each harness's hooks, and the value depends on auditors' appetite.
- **Test:**
  - Show a sample export to 3–5 SOC 2 firms, as 2.10 recommends.
  - Ask whether they would test the enforced block once, and whether approver = sponsor counts as an exception.
  - Track sample sizes in one partner's next audit.
- **Confidence:** medium. The gap is verified in vendor documentation; auditor appetite is untested.

### D7. Make "verifiable without trusting us" the claim, and name the mechanism
- **Pitch4 pages and sections:**
  - Page 1's tagline ("Only your team can read it, and anyone can read the code");
  - page 3, "Why encryption makes it safe to adopt";
  - page 5, "Where we stand", the row "A record of agent work you can read and we cannot" (now "No one"), and "Who pays", Assured row.
- **What to change:**
  - Keep "No one", but say what makes it true: signed checkpoints, an open verifier any reviewer can run, keys only the team holds, and self-hosting.
  - Stop using "tamper-evident" and "auditor-grade" as differentiators.
  - Add "anyone can check the evidence" to the tagline (L1).
  - Put signatures, the verifier, a read-only auditor seat and signed, client-verifiable review attestations per release in Assured. That is where evidence crosses an organizational boundary or faces doubt about its authenticity (2.10).
- **Why it helps:**
  - After the Delve allegations, the audible pain is whether evidence is real (L1).
  - IPE testing asks that report logic and source data cannot be changed without authorization (2.10).
  - GRC platforms store values the sidecar asserts but cannot check them, so proof of completeness and integrity has to come from the sidecar's own signed export (3.10).
  - Drata uses "tamper-evident" in every asset, with no published mechanism, no customer-held keys and no self-hosting (4.03).
- **Evidence:**
  - IANS's advice to spot-check underlying evidence ([IANS](https://www.ians.com/news/delve-allegations-expose-weak-points-in-modern-compliance)). The Delve allegations themselves are contested ([Lorikeet](https://lorikeetsecurity.com/blog/delve-fake-compliance-scandal), search summary) (L1).
  - AIUC-1 E015.4, log integrity ([AIUC-1](https://standard.aiuc-1.com/accountability/log-model-activity)); Workstreet on append-only storage ([Workstreet](https://www.workstreet.com/blog/soc-2-type-2-for-ai-companies)) (L1).
  - Drata's record is described only as "tamper-evident" ([Drata data sheet](https://tfm5idqp2axdd32z.public.blob.vercel-storage.com/AI%20Agent%20Governance%20-%20Why%20Drata.pdf); [Drata](https://drata.com/products/agent-governance)), and activity is reduced and masked on the device before transfer (4.03).
  - A verifiable design exists to point to: Anthropic's Access Transparency log, with a Merkle tree, signed checkpoints and `axt-verify` ([Anthropic](https://platform.claude.com/docs/en/manage-claude/access-transparency-log)) (4.03).
  - A client found a vendor's privacy page insufficient ([Cursor 5418](https://forum.cursor.com/t/concerns-about-privacy-mode-and-data-storage/5418)) (3.06).
- **Counter-evidence:**
  - There is no buyer evidence that anyone will pay for independent verifiability (4.03).
  - Inside one company, signatures are not required (2.10).
  - Auditors' reliance on a third-party export is untested (2.10, 3.10).
  - Page 6 puts trust documents (an independent audit and a threat model) before public claims, so this claim must wait for them.
- **Pitch4 change:** the tagline, the competitor-table cell and the Assured row, as above.
- **Cost and risk (synthesis judgment):**
  - **Build:** the verifier and checkpoint publication.
  - **Risk:** claiming verifiability before the independent audit is done.
- **Test:** give one auditor or client reviewer an export and the verifier. Record whether they run it, and whether follow-up questions fall.
- **Confidence:** medium.

### D8. Feed Vanta, Drata and Secureframe through an open bridge, with version-aware mappings
- **Pitch4 pages and sections:**
  - Page 5, "Who pays" (Team "exports"; Assured "compliance mappings");
  - page 5, "Where we stand" (a GRC row);
  - page 6, "Last: inbox and assurance" (where compliance mappings sit now).
- **What to change:**
  - **Ship an open-source "GRC bridge" in Team** that runs under the customer's own credentials:
    - a Vanta private integration, with custom resources split to stay under 10,000 records per type;
    - Drata custom connections using sessions;
    - Secureframe custom integrations;
    - documented test recipes: `approver_is_sponsor == false`, `unmatched_count == 0`, `agent_identity_has_merge_rights == false`;
    - a quarterly signed export uploaded as file evidence, for customers on entry plans.
  - **List a Vanta marketplace app only for what fits Vanta's built-in types:** agent identities as user accounts, so they enter access reviews, and signed exports as documents (3.10).
  - **Make compliance mappings version-aware:** SOC 2 2017 and 2027 IDs side by side; AIUC-1, whose crosswalk uses 2017 IDs; MAS; DORA RTS Art. 17; NYDFS; PCI 6.2.3. Phrase each as "evidence for", and move mappings from "Last" to "Next: the team layer" (L1, 2.10).
  - **Reword the claim:** "Feeds Vanta, Drata and Secureframe through your own integration. Your auditor reviews the agent-change tests across the audit window, and can verify the signed export themselves" (3.10).
  - **Position against Drata:** "Drata governs the agents that call your SaaS; the sidecar records the agents that change your code, in every harness" (4.03).
- **Why it helps:**
  - Buyers already gather evidence in these platforms (L1), and the platforms cannot see harness, model, sponsor or run-to-commit links (3.10).
  - Vanta says most partner builds take "about 1 week of engineering time" ([Vanta](https://developer.vanta.com/docs/guides/become-partner.md)).
  - No platform has a test for AI-authored changes, and a customer's request to "pull in claude code reviews" went unanswered (3.10).
  - The renumbering will cause confusion from 2027 to 2029 (2.10).
- **Evidence:**
  - Push interfaces: [Vanta](https://developer.vanta.com/reference/build-integrations/overview.md), [Vanta resources](https://developer.vanta.com/docs/concepts/resources.md), [Drata](https://developers.drata.com/openapi/reference/v2/tag/Custom-Data-Records/), [Secureframe MCP](https://mcp.secureframe.com/mcp_docs) (3.10).
  - The unanswered request: [Vanta Community](https://community.vanta.com/x/grc/nwnr9uwkwu1y/ai-only-code-reviews-and-soc-2-change-management-e) (3.10).
  - The 2017-numbered crosswalk: [AIUC-1 D003](https://standard.aiuc-1.com/reliability/restrict-unsafe-tool-calls.md) (2.10).
  - Vanta's AI Inventory, in beta: [Vanta](https://www.vanta.com/integrations/claudes-compliance-api) (4.03).
- **Counter-evidence:**
  - Plan gating narrows the Team route: Drata needs Advanced or Enterprise, Secureframe the Complete plan, and Vanta "may require a plan upgrade or add-on" (3.10).
  - Vanta has no partner path for change records (3.10).
  - No auditor has said whether a GRC custom test over pushed records counts as system-generated evidence (3.10).
  - Vanta could add an "AI-assisted" column from forge metadata as "a small step" (3.10), and its Claude Code ingestion reaches GA in January 2027 (4.03).
  - If Drata folds its agent governance into Advanced or Enterprise at GA, 50–150-engineer customers would get an agent inventory inside contracts worth about $25k–$50k a year ([Vendr](https://www.vendr.com/marketplace/drata)). So Team must stand on developer continuity and cross-harness coordination, not on compliance alone (4.03).
- **Pitch4 change:**
  - Page 5, Team row: "exports" becomes "an open GRC bridge for Vanta, Drata and Secureframe".
  - Page 5, Assured row: list the version-aware mappings.
  - Page 5, "Where we stand": add a row naming Vanta's AI Inventory and Drata's AI Agent Governance, with what each misses.
  - Page 6: move mappings to the team layer.
- **Cost and risk (synthesis judgment):**
  - **Build:** small, per Vanta's own estimate; maintenance across three APIs.
  - **Risk:** the platforms may build their own ingestion.
- **Test:**
  - Build the Vanta recipe with one partner whose plan includes Custom Tests.
  - Check whether their auditor uses the test snapshots, and time the setup.
- **Confidence:** medium.

### D9. Widen model access to approved hosted endpoints, and record the provider path
- **Pitch4 pages and sections:**
  - Page 4, the "Model access" box ("Agents reach the inference servers you run … and nothing else"), and the table "What changes when the model is yours" (row "What the record can prove");
  - page 3, "What admins can answer" (first bullet) and "Why encryption makes it safe to adopt";
  - page 6, "First release" (model access).
- **What to change:**
  - Agents reach only the model endpoints approved for each repository. These include the team's own servers and any hosted or government-cloud endpoint a client or prime approves, such as Bedrock GovCloud, Azure Government or Vertex Assured Workloads (3.05).
  - Each call is recorded with:
    - the harness;
    - the provider path and endpoint;
    - the region or inference-profile geography;
    - the retention or review mode, where it can be read (for example Azure's `ContentLogging=false`);
    - the approval reference.
  - Support contract-scoped rules:
    - no Anthropic models on DoW-tagged repositories, and optionally no Claude Code harness there until that question is settled;
    - no DeepSeek lineage on DoD and GSA-vehicle repositories;
    - per-client keys, such as each French ministry's own Albert account.
  - Export, per contract:
    - the FAR 52.204-30 report fields;
    - answers to Mayer Brown-style questionnaires;
    - "verified absence for contract X, for work through the sidecar".
  - Message it as "the records your reasonable inquiry will search" and "evidence for your FASCSA and §1532 representations", never "compliant" (2.09, 3.05).
- **Why it helps:**
  - The live federal exclusion for coding agents is a hosted US vendor, keyed to vendor and use. A record limited to self-hosted servers "misses half the compliance question" (2.09).
  - DORA's location clause bites hardest on hosted APIs (2.09).
  - Defense suppliers will route to government clouds under prime approval (3.05). French suppliers must route per client (3.12).
  - Without a record, the honest answer to a certification is often "we don't know", and counsel warn against certifying beyond what was verified (3.05).
  - CSA rates the detectability of AI-assisted code "Very low unless development tooling is logged" ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-dhs-deepseek-fascsa-order-20261021-csa-sty/)) (2.09).
- **Evidence:**
  - The exclusions:
    - Anthropic's own statement ([Anthropic](https://claude.com/solutions/government));
    - Holland & Knight: "should be prepared to document that separation" ([H&K](https://www.hklaw.com/en/insights/publications/2026/09/dc-circuit-upholds-exclusion-of-anthropic-from-dow-supply-chain));
    - A&O Shearman: §4713 may capture "the use of Claude Code under a general license to write software that ends up in a DoW system" ([A&O Shearman](https://www.aoshearman.com/en/insights/ao-shearman-on-tech/dow-and-anthropic-showdown-continues-navigating-the-anthropic-supply-chain-risk-designations));
    - the DHS footnote ([DHS order](https://downloads.regulations.gov/DHS-2026-0628-0002/content.pdf));
    - the GSA vehicles ([GSA](https://origin-www.gsa.gov/system/files/AA%20FASCSA%20Orders%20-%20Message%20Sent%20to%20GSA%20Industry%20Partners.pdf)) (2.09, 3.05).
  - The certification practice: Mayer Brown's survey of forms ([Mayer Brown](https://www.mayerbrown.com/en/insights/publications/2026/07/dows-anthropic-ban-goes-live-a-confusing-patchwork-of-certification-demands-for-contractors)), and Frazee's advice to "inventory, are you using Claude?" and build "a good factual record" ([FNN](https://federalnewsnetwork.com/contracting/2026/08/contractors-trying-to-comply-with-the-pentagons-anthropic-restrictions-are-running-into-an-unexpected-problem/)) (3.05).
  - What the inquiry searches: [FAR 52.204-30](https://www.acquisition.gov/far/52.204-30); [85 FR 42665](https://www.govinfo.gov/content/pkg/FR-2020-07-14/pdf/2020-15293.pdf).
  - Hosted retention exceptions: [Anthropic privacy](https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data), [Claude Code ZDR](https://code.claude.com/docs/en/zero-data-retention), [OpenAI](https://developers.openai.com/api/docs/guides/your-data), [Azure](https://learn.microsoft.com/en-us/azure/foundry/responsible-ai/openai/data-privacy). Bedrock's claim that model providers "don't have access to … customer prompts and completions" ([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/data-protection.html)) is a vendor claim (3.05).
  - Locations and per-client keys: [DORA Art. 30](https://www.digital-operational-resilience-act.com/Article_30.html); [DINUM](https://guides.ia.numerique.gouv.fr/albert-api/guides/entreprises-se-connecter-a-albert-api).
  - A reported failure mode, contested by Accenture: a contractor "connected a sensitive Pentagon system to their personal Claude Code account" ([TNW](https://thenextweb.com/news/accenture-contractor-claude-agent-pentagon-network-wired)) (2.09).
- **Counter-evidence:**
  - No lawyer advises per-repository records of model and harness. The record is a product inference from their advice (3.05).
  - No contracting officer or prime has said what evidence is accepted. Nobody asks for cryptographic proof, and the FAR inquiry needs no audit (3.05).
  - There is a double edge: a detailed record puts more "in possession", and that can make covered use reportable within 3 business days. 3.05 judges the edge narrow and mainly about content (2.09, 3.05).
  - The Anthropic designation could change; the en banc petition is pending (3.05).
  - Two questions are unanswered: whether the Claude Code harness counts as "use of Claude" when it calls another vendor's model, and whether Claude via Bedrock or Vertex is excluded on DoW work (3.05).
  - Hosted calls show only a declared route: "AWS does not report the destination region back" ([TrueFoundry](https://www.truefoundry.com/docs/ai-gateway/aws-bedrock)) (3.12).
  - Widening model access dilutes page 4's thesis that "nothing has to leave your control".
  - 3.12 advises keeping route policy as configuration behind the record, not as a headline.
- **Pitch4 change:**
  - Page 4's "Model access" box: replace "and nothing else" with "only the endpoints approved for each repository, your servers or hosted ones, each recorded".
  - Page 4 table, hosted column: "Which harness and which model name" becomes "Which harness, provider path, region and model name".
  - Page 3's first bullet: add the provider path.
  - Page 6: define first-release model access to include hosted endpoints.
- **Cost and risk (synthesis judgment):**
  - **Build:** recording hosted calls for each harness.
  - **Risks:** legal positioning, and weakening the privacy thesis.
- **Test:**
  - Ask 2–3 dual-use suppliers, or their counsel, to answer a real certification form from a sample per-contract export.
  - Record whether counsel would rely on it.
- **Confidence:** medium.

### D10. Record the route per model call, with lineage and host as separate, tiered fields
- **Pitch4 pages and sections:**
  - Page 3, "What admins can answer" ("Which agents, harnesses, and models, down to the weights, touched which repos, for which sponsor");
  - page 4, the table row "What the record can prove", and the "Model access" box's "Proves" row ("The sidecar beside the model server signs which weights it serves").
- **What to change:**
  - **One entry per model call, not per session,** carrying:
    - the role: lead, subagent, sidekick or router choice;
    - the model identifier as the harness reports it;
    - the host, at one of three tiers: declared (provider, `eu.` or `us.` profile, retention terms), observed (what the sidecar saw on the wire), or signed or attested (self-hosted or attested hosts);
    - the lineage, at one of four tiers: verified (a digest matches a published checkpoint), publisher-declared (Hugging Face `base_model` or `base_model_relation`, or a manifest revision), vendor-stated (a prose statement, with URL and date), or undisclosed (3.12, 4.08).
  - **For self-hosted serving receipts, add what L1 called for:** the digest of the exact quantized file, its quantization recipe and imatrix hash, the runtime version, and an OMS verification result.
  - **State the limits:** the sidecar cannot see lineage inside vendor models or block them inside the harness. Say "as disclosed by the vendor" or "undisclosed" (4.08).
- **Why it helps:**
  - Routers, subagents and sidekicks switch the served model without the user choosing, so a per-session record misstates which models touched the code (4.08).
  - Buyers argue on two separate axes. Airbnb argues host, Congress argues lab, DINUM chose a Chinese lab on a sovereign host, and AWS's sovereign cloud offers no Chinese-lab models. No product records both per session (3.12).
  - CSA rates fine-tunes and quantizations "Likely covered", so origin rules must key on lineage and digests, not names (2.09).
  - None of 198 popular GGUF repositories can be independently re-derived, so a bare operator signature over full-precision weights says little about the quantized file actually run (L1).
- **Evidence:**
  - Lineage behind vendor labels (4.08):
    - [Cursor Composer 2.5](https://cursor.com/blog/composer-2-5) and its docs ("Provider: Cursor") ([Cursor docs](https://cursor.com/docs/models/cursor-composer-2-5));
    - [Cognition SWE-1.7](https://cognition.com/blog/swe-1-7) and [SWE-2](https://cognition.com/blog/swe-2);
    - [Devin federal](https://docs.devin.ai/federal/compliance) (SWE 1.6 Federal, base unnamed).
  - Hidden or switched served models: [Cursor Router](https://cursor.com/docs/cursor-router); [Cursor 159047](https://forum.cursor.com/t/159047); [Devin Fusion](https://docs.devin.ai/cli/fusion); [Kilo](https://kilo.ai/docs/llms.txt); [Amp modes](https://ampcode.com/modes) (4.08).
  - Good practice to reuse:
    - JetBrains' Hugging Face card with a merge manifest pinning exact source revisions ([JetBrains](https://huggingface.co/JetBrains/Qwen3.8-3.6-27B-blend));
    - GitHub's separate statements of developer, host and data flow: "Kimi K3 is hosted by GitHub on Fireworks AI … prompts and completions are not sent to Moonshot AI" ([GitHub](https://docs.github.com/en/copilot/reference/ai-models/model-hosting)) (4.08).
  - The two axes in products: [Amp](https://ampcode.com/docs/markdown/enterprise/allowed-models) and [Anaconda](https://anaconda.com/docs/platform/guides/governance/model-governance) key on lab; [Augment](https://docs.augmentcode.com/cosmos/guides/admin-checklist) keys on region (3.12).
  - Airbnb's host-based defence: "We are not providing data to any Chinese companies" ([Chesky](https://www.dailygazette.com/tribune/airbnb-s-chesky-says-us-misunderstanding-use-of-chinese-open-source-ai-models/article_6cfb9935-51e5-5908-8646-efc0061ab4e4.html)) (3.12).
  - The quantization gap and signing status: [arXiv 2610.19498](https://arxiv.org/abs/2610.19498); the eight-nation guidance via [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-nsa-allied-ai-supply-chain-security-guidan/); [SP 800-218A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf) PW.4.4 (L1).
- **Counter-evidence:**
  - Per-step capture depends on what each harness exposes. Whether harness APIs or admin exports carry a per-request model ID was not checked (4.08).
  - Vendors are already answering disclosure in prose: GitHub, Augment and Cognition's neutrality evaluation (4.08).
  - Serving-time signature enforcement is immature: KServe's design is under review, and Ollama's signing PR has been open since July 2025 ([Ollama PR](https://github.com/ollama/ollama/pull/11573)) (L1).
  - An operator-signed receipt is still the operator's own claim (L1).
  - Individual developers are often indifferent: 3 explicitly, against 1 objection (4.08).
- **Pitch4 change:**
  - Page 3: replace "down to the weights" with "per model call, with lab lineage and host recorded separately, at a stated level of evidence".
  - Page 4 table: hosted column, "model as reported, lineage as disclosed or 'undisclosed', host as declared"; open-weights column, add "checked against the published checkpoint where possible".
  - Page 4, "Proves" row: add OMS verification and the quantization recipe and imatrix hashes.
- **Cost and risk (synthesis judgment):**
  - **Build:** per-harness capture of routing decisions, which may not always be visible.
  - **Risk:** a wrong lineage label damages credibility, so every label needs its source.
- **Test:**
  - Run Cursor and Devin sessions through the sidecar and check how many steps carry a model identity.
  - Compare the result with the vendors' published lineage.
- **Confidence:** high, as the design the record needs in order to be accurate. Demand for it as a headline is narrower; see D11.

### D11. Offer a provenance-inquiry export, and maintain an open lineage map
- **Pitch4 pages and sections:** page 5, "Who pays", Assured row; page 4, "Where open tools already stand".
- **What to change:**
  - **(a) An export shaped like the House letters.** Generate from the ledger the inventory and volume tables the committees asked for:
    - developer and nationality;
    - model, checkpoint and version; quantization;
    - first use and purpose;
    - hosted versus self-deployed; host and region;
    - the artifact hash, where self-hosted;
    - request and token volume by month and by repository or business function;
    - the policy owner.
    Sell it in Assured to US companies that mix Chinese open weights with US frontier models (the DoorDash pattern), and to public-sector and defense suppliers (4.08).
  - **(b) An open lineage map.** Publish a small, signed, open data file that maps harness model names to their stated bases, with source URL, date and confidence. For example: `composer-2.5 → moonshotai/Kimi-K2.5 (vendor-stated, 18 May 2026)`; `swe-1.6 → undisclosed`. Add licence duties and known hosts, and reuse Hugging Face's `base_model` vocabulary.
  - **(c) Flags and warnings.** Flag sessions that touched models with display or use restrictions. Warn before a session when a harness's own model has undisclosed or Chinese-lab lineage.
- **Why it helps:**
  - The letters are the first public schema for route evidence. The committees asked DoorDash for artifact hashes because open weights "can be obtained and deployed on infrastructure selected by the user" (4.08).
  - The pitch is "answer a provenance inquiry from your records, not from memory" (4.08).
  - Vendors' docs omit lineage, so the map fills a public gap, suits the open-source posture, and keeps every change reviewable in git (4.08).
  - A buyer under an origin decree asked for "only Cursor models", and one of those is Kimi-based ([Cursor 168923](https://forum.cursor.com/t/168923)).
- **Evidence:**
  - The letters: [Anysphere](https://homeland.house.gov/wp-content/uploads/2026/04/2026.04.29-Homeland-China-Select-Letter-to-Anysphere-Inc.pdf), [Airbnb](https://homeland.house.gov/wp-content/uploads/2026/04/2026.04.29-Homeland-China-Select-Letter-to-Airbnb-re-PRC-AI.pdf), [DoorDash](https://homeland.house.gov/wp-content/uploads/2026/07/2026.07.31-Homeland-China-Select-Letter-to-DoorDash.pdf). HaystackID reads the April letters as asking for "the records a well-governed AI program would generate along the way" ([HaystackID](https://newsline.haystackid.com/doordash-ai-inquiry-turns-model-selection-into-a-governance-test/)) (4.08).
  - Licence duties: Kimi K3 exempts use "accessed through Moonshot AI's official products or certified inference partners" ([Kimi K3 licence](https://huggingface.co/moonshotai/Kimi-K3/raw/main/LICENSE)). MiniMax M3 prohibits uses that "Assist with, engage in or otherwise support any military purpose" ([MiniMax M3 licence](https://huggingface.co/MiniMaxAI/MiniMax-M3/raw/main/LICENSE)) (4.08).
  - Mixed fleets: 225 EU open-harness users name a Chinese-lab vendor, and 88% of them also use a US closed vendor ([Stack Overflow data](https://github.com/StackExchange/Survey/tree/main/packages/archive/2026)) (3.12).
- **Counter-evidence:**
  - These are letters to three companies, not a rule. They ask for documents "sufficient to show", which spreadsheets could satisfy, and the answers are not public (4.08).
  - Questionnaires do not ask:
    - Shared Assessments' AI-coding questions ([Shared Assessments](https://sharedassessments.org/blog/evaluating-third-party-ai-use-how-to-address-three-real-world-scenarios/));
    - its Product Release 2027 note ([Shared Assessments](https://sharedassessments.org/blog/coming-soon-product-release-2027/));
    - CSA's AICM v1.1 ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-aicm-v1-1-update-20260730-csa-styled/)) (4.08).
  - Cisco's Amy Chang argues that country of origin is a poor proxy for model risk ([Techstrong](https://techstrong.tv/episodes/2026-09-03), search summary).
  - Whether decrees and orders reach derivative vendor models is untested (4.08).
  - 4.08 rates licence flags low-medium.
- **Pitch4 change:**
  - Page 5, Assured row: add "provenance inquiry export".
  - Page 4, "Where open tools already stand": add the open lineage map as an open part.
- **Cost and risk (synthesis judgment):**
  - **Build:** little code; ongoing curation of the map.
  - **Risk:** labelling vendors' models carries reputational and legal sensitivity.
- **Test:**
  - For 2–3 partners with mixed fleets, generate one month's inventory and ask their compliance lead whether it would replace their spreadsheet.
  - Track outside contributions to the map.
- **Confidence:** medium.

### D12. A defense and federal deployment mode: self-hosted, U.S.-only, no CUI at URnetwork
- **Pitch4 pages and sections:**
  - Page 4, "Open core, hosted blind";
  - page 3, "Why encryption makes it safe to adopt";
  - page 6, "Trust documents first" and "Ten to fifteen design partners".
- **What to change:** for defense and federal work, the defaults are:
  - the vault and ledger self-hosted inside the customer's enclave;
  - no CUI in URnetwork-hosted storage;
  - relays that carry only ciphertext between enclave sidecars;
  - relays and exits that can be pinned to U.S. infrastructure the customer runs or approves;
  - published relay locations.
  - Revenue in this segment is support and self-hosted licences, not hosting (3.05).
- **Why it helps:**
  - Encrypted CUI stays CUI, so a URnetwork-hosted vault holding it would need FedRAMP Moderate equivalence. Ciphertext leaving an enclave over outside networking components is out of scope (3.05).
  - L3Harris bars "non-U.S. persons or non-U.S. assets" without prior written approval, and requires U.S. control of any AI system used (3.05).
  - The strongest first-hand restriction voice asks to "Bring Your Own Inference Endpoint" under government and defense NDAs (3.06).
  - It also answers part of URnetwork's trust gap: no residential or foreign hops for this segment (3.05 inference).
- **Evidence:**
  - The CUI position: [AWS CMMC FAQ](https://docs.aws.amazon.com/prescriptive-guidance/latest/cmmc-level-2-compliance-on-aws/faq.md). Bochner: "encrypting CUI doesn't remove the FedRAMP requirement" ([Bochner](https://www.bochner.law/news/publications/2026-10-07-using-ai-on-dow-work-technical-data-dfars-data-rights-and-cui-safeguards)).
  - L3Harris Art. 29(c) and 17(c) ([L3Harris 2026](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf)); Northrop's clause 57 on DFARS 252.204-7012 ([Northrop R05_26](https://cdn.northropgrumman.com/-/media/Supplier-Documents/Terms-and-Conditions/CTM-P-ST-003USGTMOrderNotforCommercialProductsServices_R05_26.pdf)) (3.05).
  - The first-hand voice: [HN 44565144](https://news.ycombinator.com/item?id=44565144) (3.06).
- **Counter-evidence:**
  - The relay-scope reading is an inference that a CMMC assessor would have to confirm (3.05).
  - The segment's size, and its willingness to pay for a self-hosted tool, are unmeasured (3.05).
  - Bochner's report that CMMC Phase 2 third-party certification was suspended is unverified, and it bears on urgency (3.05).
  - FedRAMP and IL5 remain the gate for anything running *inside* DoD systems (2.09).
- **Pitch4 change:**
  - Page 4: add "For defense work: no CUI in URnetwork storage; self-host the vault and ledger; relays and exits pinned to U.S. infrastructure you run or approve."
  - Page 3: add that encryption does not take CUI out of scope.
  - Page 6: publish where relays run, and include defense subcontractors among the design partners.
- **Cost and risk (synthesis judgment):**
  - **Build:** pitch4 already plans a supported self-hosted install. U.S. pinning of relays and exits is new.
  - **Risk:** a small, slow segment.
- **Test:** review the mode with one defense subcontractor's compliance lead, or a CMMC assessor, against their System Security Plan.
- **Confidence:** medium. Medium-high on the CUI point; medium on the relay-scope inference.

### D13. One per-client record for clients who encourage AI and expect its savings
- **Pitch4 pages and sections:**
  - Page 5, "Where we start" (the line "Consultancies and agencies under client AI-disclosure terms") and "Who pays", Team row;
  - page 3, "What admins can answer".
- **What to change:**
  - For each client engagement, record and export:
    - which harnesses and models ran;
    - tokens and cost;
    - AI-assisted versus human-only changes;
    - merged lines from AI-assisted changes;
    - the human approver.
  - Deliver it as CSV and as a monthly statement.
  - The same statement serves both kinds of client:
    - a restrictive one gets the enforcement and exception log (D2);
    - an encouraging one gets a disclosure of the AI systems used, plus pass-through lines for model cost (4.04).
  - A possible Assured upsell, at low confidence: a signed baseline-and-verification pack for 50–150-engineer outsourcers in enterprise gainshare deals, covering cycle time, the share of merged changes that were AI-assisted, and cost per change (4.04).
- **Why it helps:**
  - Clients encourage AI far more often than they ban it: 81% against 14% (3.06).
  - Large clients contract for productivity pass-through (Infosys). Small suppliers face a renewal question and a trust gap: 45% of small and mid-sized clients suspect savings are not passed on (4.04).
  - The documented need is the supplier's own per-client attribution, and no harness vendor provides it across repositories or harnesses (4.04).
  - The record already exists, so the marginal cost is low (4.04 inference).
  - Gainshare needs agreement on "how it will be verified" (4.04).
- **Evidence:**
  - The vendor gap: Cursor staff ([Cursor 164650](https://forum.cursor.com/t/164650)).
  - Supplier asks: [Cursor 154687](https://forum.cursor.com/t/154687), [159552](https://forum.cursor.com/t/159552), [36465](https://forum.cursor.com/t/36465).
  - Small-client sentiment: [AMI](https://businessofstory.com/wp-content/uploads/2025/11/2025AgencyEdge.pdf); [Productive](https://productive.io/blog/agencies-in-the-ai-era/).
  - Large-firm pass-through: [Infosys Q2 FY27](https://www.sec.gov/Archives/edgar/data/1067491/000106749126000044/exv99w05.htm); [Pinsent Masons](https://www.pinsentmasons.com/out-law/news/gainshare-clauses-incentivise-ai-related-savings-financial-services); [Implement](https://implementconsultinggroup.com/article/contracting-for-ai-impact) ("quarterly automation metrics, baseline tracking, independent verification") (4.04).
  - Client attitudes: [CHI '26](https://arxiv.org/pdf/2603.07459) (3.06).
- **Counter-evidence:**
  - Small clients' demand for evidence is weak and informal. Requests for discounts are not rising ([Productive pulse](https://productive.io/reports/agencies-in-the-ai-era-pulse-report/), vendor data), and no client-originated per-task demand was found (4.04).
  - Cursor staff once called time tracking "somewhat niche, and would not be of use to 99% of our users" (4.04).
  - Large firms build this in-house: Infosys tracks it "at a child / subproject level" (4.04).
  - No public SOW has AI-adjusted rate cards, so pitch4 should not claim to support one (4.04).
  - The baseline pack is evidenced only for large deals.
- **Pitch4 change:**
  - Page 5: reword the agency line to "Agencies and outsourcers that must answer each client for AI: whether the client restricts it or expects its savings" (4.04).
  - Page 5, Team row: add "per-client attribution and monthly statements".
  - Page 3: add "what AI did and cost for each client".
- **Cost and risk (synthesis judgment):**
  - **Build:** cost data per harness varies in what it exposes.
  - **Risk:** clients may use the statements to press for discounts.
- **Test:** produce per-client monthly statements for 3–5 agencies for one quarter. Record whether they send them to clients or use them in billing and renewals.
- **Confidence:** medium for attribution; low for the baseline pack.

### D14. Re-target "Where we start" to the binding triggers
- **Pitch4 pages and sections:** page 5, "Where we start"; page 6, "Ten to fifteen design partners".
- **What to change:**
  - **Add:**
    - subcontractors to defense primes and dual-use software suppliers, including GSA Schedule and GWAC holders. They work under L3Harris, Northrop and Lockheed terms and the Anthropic and DeepSeek exclusions;
    - suppliers to banks under default-deny AI terms (Citi, HSBC, Barclays) and to services firms (Gallagher, C&W), plus consultancies that pass terms down (BCG);
    - optionally, French public-sector integrators (SREN and Albert) and Singapore financial institutions (MAS, from 7 Oct 2027).
  - **Reword** the agency line (D13).
  - **Re-verify** "Microsoft suppliers, whose change logs must name the approver" against SSPA v12 before keeping it.
  - **Keep** "Agent vendors facing AIUC-1 reviews".
  - **Make the route record (D10–D11) a headline** only for public-sector, defense and "letter-risk" buyers, and a supporting claim for security buyers in general (4.08).
- **Why it helps:**
  - These segments have dated, binding, specific texts (2.01, 3.05).
  - What binds a small supplier is who its clients are (3.06).
  - Coding agents are explicitly in scope at Barclays, AT&T, L3Harris, BT and Citi (2.01).
  - For dual-use firms, whose DoW work may now exclude Claude Code, the sidecar's neutrality across harnesses becomes a selling point (2.09).
  - The Microsoft trigger was weaker than assumed under v11 (2.01).
- **Evidence:**
  - Buyer terms: [Citi](https://www.citigroup.com/rcs/citigpa/storage/public/Citi-Requirements-for-Suppliers-English.pdf); [HSBC](https://www.hsbc.com/-/files/hsbc/who-we-are/esg-and-responsible-business/working-with-suppliers/pdfs/240930-general-terms-and-conditions.pdf); [Barclays](https://home.barclays/content/dam/home-barclays/documents/who-we-are/our-suppliers/English/v16/Artificial%20Intelligence%20SCO%20v16.0%20-%20English.pdf); [Lockheed](https://www.lockheedmartin.com/content/dam/lockheed-martin/eo/documents/suppliers/corpdocs/2026/2026corpdoc01.pdf); [Northrop](https://cdn.northropgrumman.com/-/media/Supplier-Documents/Terms-and-Conditions/CTM-P-ST-003USGTMOrderNotforCommercialProductsServices_R05_26.pdf); [L3Harris](https://www.l3harris.com/sites/default/files/2026-07/LGL-50.F1-v9.3-07.09.2026.pdf); [Gallagher](https://www.ajg.com/br/-/media/files/gallagher/br/privacy-policy/ggb-br-global-online-ai-addendum-en.pdf); [C&W](https://www.cushmanwakefield.com/en/supplier-use-of-ai); [BCG](https://www.bcg.com/assets/2025/supplier-code-of-conduct.pdf) (2.01, 3.05).
  - Microsoft: [SSPA v11](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY25-Program-Guide-v11_en-US.pdf); [SSPA v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-SSPA-Program-Guide-v12_en-US.pdf).
  - France: [DINUM](https://guides.ia.numerique.gouv.fr/albert-api/guides/entreprises-se-connecter-a-albert-api). Singapore: [MAS](https://www.mas.gov.sg/regulation/guidelines/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions).
- **Counter-evidence:**
  - Segment sizes and willingness to pay are unmeasured.
  - The defense segment pays for support, not hosting (3.05).
  - No first-hand supplier voice describes complying with these clauses (2.01).
  - The demand is legally driven and largely unvoiced by developers (2.09).
  - The French segment is inferred from rules, not interviews (3.12).
  - Open-weight teams remain a minority segment: Menlo puts open models at 11% of spend (2.09).
- **Pitch4 change:** page 5's list and page 6's design-partner mix, as above. Recruit at least two partners from the defense and bank-supplier segments.
- **Cost and risk (synthesis judgment):**
  - **Cost:** regulated segments have long sales cycles.
  - **Dependency:** the defense segment needs D12's mode.
- **Test:** compare conversion and depth of use between the new segments and agencies across the pilot.
- **Confidence:** medium.

### D15. Correct the assurance timeline and tighten the claims
- **Pitch4 pages and sections:**
  - Page 5's timeline ("Now"; "December 2027"; "The moat is time and service");
  - claims on pages 3 and 4.
- **What to change:**
  1. **The SOC 2 part of "December 2027 Draft SOC 2 criteria … apply".** Use 2.10's wording: "From 31 Dec 2027, if the AICPA finalizes them, SOC 2 engagements move to the 2027 criteria (early adoption allowed). Their AI points of focus ask about agent accounts, unapproved AI and third-party models. They prompt the auditor's questions; they are not required controls."
     - Consider adding MAS, whose Sections 3–4 apply from 7 Oct 2027, and NYDFS, which already asks for human oversight of AI-generated code.
     - The EU AI Act and Cyber Resilience Act parts of that line were not checked in this branch.
  2. **"The moat is time and service".** A year of signed approvals before the audit period is not what a Type 2 samples. What counts is a record complete from day one of the first period under the 2027 criteria. Earlier history still helps with client questionnaires and incident reconstruction (2.10).
  3. **Say "evidence for" and "the records your reasonable inquiry will search", never "compliant"** (2.09, 3.05).
  4. **Drop GSA's "American AI Systems" as a driver** (3.05).
  5. **Pitch enforcement plus an exception log, not an "attestation of non-use", as proof** (3.06).
  6. **Do not claim SIG or CAIQ require route records.** Say "the questions Congress asked Anysphere, Airbnb and DoorDash" (4.08).
  7. **Separate lab from host in every claim, and do not equate "sovereign" with "self-hosted" or "non-Chinese"** (3.12, 4.08).
  8. **Do not say clients demand per-task AI evidence** (4.04).
  9. **Do not suggest model review can replace human approval.** Offer "independent model review, recorded" as extra evidence (2.10).
  10. **Test before claiming that MCP proxies miss built-in tool actions.** Claude Code names MCP tools `mcp__<server>__<tool>`, separate from built-ins such as `Bash` and `Edit` ([Claude Code hooks](https://code.claude.com/docs/en/hooks)). The claim that a proxy sees only MCP traffic is 4.03's inference, so test it against real Claude Code, Codex and Cursor sessions first.
  11. **Keep page 5's "Now: Questionnaires ask which AI a team uses and whether a human reviews its work".** It matches what the branch found (L1, 4.08).
- **Why it helps:** reviewers after Delve spot-check claims (L1); claims built on regulation would overreach (L1); and each correction rests on a primary text read in the branch.
- **Evidence:**
  - The SOC 2 timing: [AICPA](https://www.aicpa-cima.com/news/article/aicpa-proposes-update-of-soc-2-r-trust-services-criteria-to-enhance-the-relevance-usability-and-value-of-cpas-reports); [Noru](https://noru.tech/resources/soc2-2027-trust-services-criteria); [Elevate](https://elevateconsult.com/insights/soc-2-trust-services-criteria-2027/).
  - GSA: [Crowell on GSA](https://www.governmentcontractslegalforum.com/2026/10/articles/government-contracts/gsa-issues-final-rule-on-large-language-model-procurements/).
  - Certifications: [Mayer Brown](https://www.mayerbrown.com/en/insights/publications/2026/07/dows-anthropic-ban-goes-live-a-confusing-patchwork-of-certification-demands-for-contractors).
  - Silence under prohibition: [CHI '26](https://arxiv.org/pdf/2603.07459).
  - Questionnaires: [Shared Assessments](https://sharedassessments.org/blog/evaluating-third-party-ai-use-how-to-address-three-real-world-scenarios/).
  - Sovereignty and hosts: [DINUM models](https://guides.ia.numerique.gouv.fr/albert-api/modeles/available-models); [GitHub hosting](https://docs.github.com/en/copilot/reference/ai-models/model-hosting).
- **Counter-evidence:**
  - Softer claims reduce urgency.
  - The AICPA draft may change before it is final.
  - MAS's dates are guidance, not law.
- **Pitch4 change:** the timeline and moat lines on page 5, and the claims on pages 3 and 4, as above.
- **Cost and risk (synthesis judgment):** near-zero cost. The risk is a less urgent page 5.
- **Test:** have a SOC 2 auditor and a government-contracts lawyer read the revised lines before publication.
- **Confidence:** high.

---

## 4. What remains open

1. **Acceptance.** Would a client, prime, contracting officer or auditor accept a contractor-run signed export in place of email approvals, checkbox certifications, "verified absence" forms or "records on request"? No buyer was interviewed at any level (2.01, 2.10, 3.05, 3.06).
2. **Harness stores under prime clauses.** Does a harness's local transcript store, or a separate session vault, fall under Northrop 22(M)(2)(c)(ii) or L3Harris 9(iii) and 17(d)(ii)? Do Codex, Cursor, Copilot, OpenCode and Goose offer switches that disable local persistence? (3.05)
3. **Hosted providers under prime clauses.** Does ZDR, Azure's modified abuse monitoring, or Bedrock's "Zero Operator Access" satisfy Northrop's "not … accessible to … the AI System Provider" or L3Harris's "accessible to any person other than Buyer and Seller"? (2.01, 3.05)
4. **The edges of the DoW exclusion.** Does the Claude Code harness count as "use of Claude" when it calls a non-Anthropic model? Is Claude through Bedrock or Vertex excluded on DoW work? How will Anthropic's en banc petition of 14 Oct 2026 be decided? (3.05)
5. **The DeepSeek orders.** The texts of the DoW and DNI orders were not read. There is no CISA or FASC guidance on "developed using". Will §1532(a)(2) guidance name other Chinese labs, such as Qwen, Kimi, GLM or MiniMax? (2.09, 3.05)
6. **SOC 2 specifics.** The AICPA draft's verbatim text sits behind a free account and was not read. Does it name coding agents? Will CPA firms treat prompter = approver as an exception, and test an enforced segregation-of-duties control once? Would customers' auditors need URnetwork's own SOC 2 report for a hosted ledger? (2.10)
7. **GRC visibility.** Do Vanta's Custom Test results on custom resources appear in its Controlled Audit View, and which plans include them? Can Drata's Audit Hub sample custom-connection records? Does Vanta's AI Inventory keep session content, and does it link sessions to code changes? When does Drata's AI Agent Governance reach GA, at what price and with what packaging? (3.10, 4.03)
8. **Prevalence among 5–150-engineer suppliers.** How many software agencies and outsourcers hold at least one client contract that restricts AI coding tools, or one with productivity commitments? No dev-shop survey was found (3.06, 4.04).
9. **Willingness to pay.** It is untested for every direction: per-client policy, packets, the GRC bridge, the inquiry export, independent verifiability, attribution and the defense mode.
10. **Ownership.** Who owns and signs a per-repository or per-contract model policy? Platform admins configure; contracts, delivery and compliance sign off. No source names an owner (3.12).
11. **Derivative vendor models.** Do origin decrees and orders reach derivative vendor models such as Composer 2.5 and SWE-2? Will harness vendors expose the served model per request in admin APIs or logs? (4.08)
12. **The congressional letters.** What did Anysphere, Airbnb and DoorDash produce, and will the committees issue a report or legislation? (4.08)
13. **Licensed question sets.** The SIG 2026 and 2027 texts and the AI-CAIQ v1.1 workbook were not read. An origin or route question could sit there unseen (L1, 4.08).
14. **MCP proxies.** Does an MCP proxy really miss a coding harness's built-in tool actions in practice? This needs a test against real sessions (4.03).
15. **CMMC scope of relays.** Do ciphertext-only relays between enclave sidecars sit outside CMMC scope? An assessor would have to confirm it (3.05).
16. **Questions routed outside this branch.** Level 1 also asked:
    - what proof of which weights ran reviewers will accept: an operator signature, OMS plus reproducible quantization, or hardware attestation;
    - which format will become the convention for "produced by tool X running model Y, approved by Z": CycloneDX, SPDX 3, in-toto predicates or an IETF draft.
    No note in this branch settles either.

---

## 5. Notes synthesized

All in `/Users/brien/urnetwork/sidecar/research_notes/Sidecar pitch4 differentiation directions/`:
- `L1-1.08-buyer-evidence-artifacts.md`
- `L2-2.01-how-common-are-at-t-style-supplier-ai-terms-amon.md`
- `L2-2.09-do-current-rules-or-client-terms-require-supplie.md`
- `L2-2.10-what-will-soc-2-auditors-and-other-assessors-req.md`
- `L3-3.05-what-do-us-defense-and-federal-rules-and-defense.md`
- `L3-3.06-how-common-are-clients-ai-use-terms-in-the-contr.md`
- `L3-3.10-do-vanta-drata-and-secureframe-accept-custom-evi.md`
- `L3-3.12-is-there-buyer-demand-beyond-lawyers-advice-for.md`
- `L4-4.03-does-drata-s-ai-agent-governance-a-device-sensor.md`
- `L4-4.04-are-clients-writing-ai-use-mandates-and-producti.md`
- `L4-4.08-which-harness-vendors-own-coding-models-are-buil.md`

Pitch4's section names and quoted lines come from `/Users/brien/urnetwork/sidecar/pitch4.html`, read on 1 Nov 2026.
