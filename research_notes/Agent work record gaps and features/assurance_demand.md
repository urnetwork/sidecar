# Assurance demand: what customers, auditors, insurers, regulators and client contracts ask teams to prove about AI agents and AI-generated work (state as of 31 October 2026)

Source labels used below:
- **[opened]**: the page or document was fetched and read in this round.
- **[search summary]**: the claim was seen only in search-engine result summaries, not on the page itself.
- **Binding**: law, regulation, or a signed contract or supplier requirement.
- **Guidance**: non-binding material from a regulator or standards body.
- **Vendor**: vendor marketing, or data a vendor ran itself.

Prior-round findings are not repeated unless new evidence changes them:
- EU AI Act logging and the Digital Omnibus delay.
- The SOC 2 AI gap.
- ISO 42001 control A.6.2.8.
- Colorado SB 26-189.

## 1. Security questionnaires and frameworks: which added AI or agent questions in 2025–2026, what they ask, and how often AI questions appear

### Takeaway
Every major standardized questionnaire family now carries AI content:
- CSA's AI Controls Matrix and AI-CAIQ.
- The SIG 2026 AI domain.
- HECVAT 4's AI worksheet.
- Vanta's tiered AI Security Assessment. Its basic tier covers any company whose "software [is] built with AI", so it reaches teams that build with coding agents.

The public material centers on AI *use and data flow*: which tools and models, training on customer data, subprocessors, output monitoring, and human oversight. It does not ask for records of what agents did. I found **no independent measure** of how often AI questions appear in vendor reviews. The numbers that exist are vendor-run figures or template estimates.

### Cited Findings
- **CSA AI Controls Matrix (AICM) v1.0:**
  - CSA's AICM page lists a release date of 9 Jul 2025, and the press release is dated 10 Jul 2025. — [CSA AICM page](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix/), [CSA press release](https://cloudsecurityalliance.org/press-releases/2025/07/10/cloud-security-alliance-delivers-the-ai-guardrails-you-ve-been-looking-for) [search summary]
  - CSA launched STAR for AI in October 2025. — [CSA SOC 2 research note, 30 Aug 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/) [opened]
  - The AI-CAIQ supports a STAR Level 1 self-assessment for AI. — [Tripwire](https://www.tripwire.com/state-of-security/csa-ai-controls-matrix-framework-trustworthy-ai) [search summary]
- **AICM v1.1 and AI-CAIQ v1.1** (CSA blog 14 Jul 2026; CSA research note 30 Jul 2026) — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-aicm-v1-1-update-20260730-csa-styled/) [opened]; [CSA blog](https://cloudsecurityalliance.org/blog/2026/07/14/ai-controls-matrix-v1-1-strengthening-the-foundation-for-trustworthy-ai) [search summary]
  - **Size:** 247 control objectives (up from 243) across 18 domains. The AI-CAIQ has **320 questions**.
  - **What changed:** the four added controls are refinements synchronized with CCM v4.1, not new AI-specific requirements. The Model Security domain (MDS-01 to MDS-13) is unchanged since v1.0.
  - **Agent content:** the note lists **no new controls on logging, audit trails, event logs, provenance or human oversight**. Agentic AI appears only through the first mapping to **AIUC-1**.
  - **Use:** the AI-CAIQ is meant for "self-assessment and third-party evaluation".
  - **Release-date conflict:** CSA's publications page reportedly lists 22 Jun 2026. — [search summary]
- **Shared Assessments SIG 2026:**
  - It has 21 risk domains, including a dedicated Artificial Intelligence domain. ISO/IEC 42001:2023 has been mapped alongside NIST AI RMF 1.0, and Vorp Labs gives the release date as 19 Sep 2025. — [Vorp Labs SIG tracker](https://vorplabs.com/security-framework-changes/sig) [search summary]
  - Mitratech says SIG 2026 covers the AI lifecycle "from data collection and model training to deployment and bias monitoring". — [Mitratech](https://mitratech.com/resource-hub/blog/sig-2026-key-updates-and-considerations/) [search summary]
  - The SIG is licensed (Vorp Labs cites a $7,000 one-year corporate license), and Shared Assessments does not publish the AI domain's question text. — [Aliteq](https://aliteq.com/ai-security-questionnaire-answers-2026) [search summary]
  - The Shared Assessments "2026 SIG workbook updates" blog returned only a sign-in holding page. — [Shared Assessments](https://sharedassessments.org/blog/2026-sig-workbook-updates) [did not load]
- **Vanta AI Security Assessment (24 Apr 2025)** — [Vanta blog](https://www.vanta.com/resources/introducing-vantas-ai-security-assessment) [opened]; [BusinessWire](https://secure.businesswire.com/news/home/20250424580132/en/Setting-the-Standard-for-AI-Compliance-Vanta-Introduces-AI-Security-Assessment) [search summary]
  - **Tiers:**
    - **"Companies using AI** (such as AI software products or software built with AI)" get a basic evaluation.
    - **Companies building with AI** get added questions on AI supply chain risk, cross-functional review, model training, and drift.
    - **Companies developing models** get questions on access controls, issue reporting, risk classification, and procurement.
  - **Framework alignment:** NIST AI RMF, the EU AI Act, and ISO 42001.
  - **Delivery:** the questions sit inside Vanta's Vendor Risk Management questionnaires, which Vanta customers send to their vendors.
  - **Question text:** the blog publishes no sample question wording.
- **Drata / SafeBase:**
  - Drata acquired SafeBase in February 2025 (reported at $250M), and sells its AI Questionnaire Assistance product. — [soc2auditors.org](https://soc2auditors.org/software/safebase/), [Drata](https://drata.com/blog/acquiring-safebase) [search summary]
  - On 16 Jul 2026 Drata announced native support for **AIUC-1** (requirements, controls, policy templates, continuous evidence) — [Drata blog](https://drata.com/blog/introducing-aiuc-1) [opened]:
    - It says "Security reviews stall. Legal teams pump the brakes" and that "procurement stalls when buyers cannot validate that an agent is safe and reliably governed".
    - It cites **no statistics** and does not mention agent logging (vendor).
- **Whistic, OneTrust, Secureframe, Conveyor:**
  - Whistic's AI features (Assessment Copilot, Smart Response, SOC 2 summaries) automate assessments. No public AI question set was found. — [FitGap](https://us.fitgap.com/products/012928/whistic) [search summary]
  - No official OneTrust AI vendor-assessment template was found. — [search summary]
  - Conveyor's "AI predictions" page analyzes 300,000+ questionnaire questions, but its statistic labels are jumbled and none measures AI-question prevalence. — [Conveyor](https://www.conveyor.com/ai-predictions-2024) [search summary]
  - Secureframe was not covered by any result.
- **HECVAT 4 (EDUCAUSE), used by vendors selling to higher education:**
  - It added AI-specific questions written by community volunteers. — [EDUCAUSE Review, Feb 2025](https://er.educause.edu/articles/2025/2/hecvat-4-better-than-ever) [search summary; page returned 403]
  - A third-party guide describes a conditional AI domain of **32 questions** with machine-learning and LLM sub-sections. This count is unverified. — [SaltyCloud](https://www.saltycloud.com/blog/hecvat-v3-05-whats-changed) [search summary]
- **Prevalence statistics (all vendor-run or analyst predictions relayed by vendors):**
  - **Vanta State of Trust 2025 (vendor-run):** vendor security reviews and risk assessments take **9 working weeks a year** (7 the year before). — [BusinessWire, 29 Oct 2025](https://www.businesswire.com/news/home/20251029144534/en/Vanta-State-of-Trust-2025-AI-Threats-Outpace-Security-Expertise) [search summary; page returned 403]
  - **Vanta's April 2025 release (vendor-run):** cites its research that only **36%** of organizations have, or are putting in place, a company AI policy. — [BusinessWire](https://secure.businesswire.com/news/home/20250424580132/en/Setting-the-Standard-for-AI-Compliance-Vanta-Introduces-AI-Security-Assessment) [search summary]
  - **Gartner Predicts 2026 (relayed by RiskRecon, a vendor):**
    - **62%** of organizations "overly trust" due-diligence questionnaire answers, which are increasingly AI-generated.
    - By 2028, **70%** of organizations and their vendors will use GenAI on both sides of the questionnaire.
    - Source: [RiskRecon](https://blog.riskrecon.com/5-key-takeaways-from-gartner-predicts-2026), [SRM Today](https://www.srmtoday.com/gartner-warns-ai-driven-questionnaires-may-undermine-third-party-cyber-risk-accuracy/) [search summary]
  - **Template estimate:** one template author says ~35% of the questions in its own template target AI-specific risk. This is not a measure of prevalence. — [Glacis](https://www.glacis.io/guide-ai-security-questionnaire) [search summary]
- **What the questions ask (vendor and consultant sources only; no primary standardized question text was accessible):**
  - Aetos (a consultancy) says vendor assessments now ask:
    - "how AI outputs are monitored, how the model was selected";
    - "whether that model was trained on their data";
    - "where that data goes after the API call returns";
    - "what happens when it produces outputs that are wrong".
  - It says buyers want "ninety days of documented evidence" of output controls. The article is unsourced and promotional. — [Aetos](https://www.aetos-data.com/answers-insights/enterprise-security-ai-questionnaires) [opened]
  - A vendor guide on AI coding tools under SOC 2 frames the questions as: "For AI agents and AI coding assistants: what guardrails prevent unauthorized actions? Is there human review?" — [Augment Code](https://www.augmentcode.com/guides/ai-coding-tools-soc2-compliance-enterprise-security-guide) [search summary]
  - Buyer-side templates are split into tiers. For example, Safe Security's LLM questionnaire has 46 questions across 12 domains (20 Core, 26 Enhanced). — [Safe Security](https://safe.security/resources/templates/ai-llm-vendor-risk-questionnaire/) [search summary]

### Inferences
- Vanta explicitly puts "software built with AI" in the basic tier of its AI assessment. A team using Claude Code, Cursor or Copilot to build its product is therefore in scope when any Vanta-using customer runs vendor risk management on it. This is the most concrete documented path by which AI-coding-tool use reaches small vendors through questionnaires.
- The example questions in the brief match the themes in the sources: which tools are used, whether customer data goes to them, and whether AI output is reviewed. I could not find them **verbatim** in a primary standardized questionnaire, because the SIG and AI-CAIQ question text is licensed or download-gated.
- CSA's own control set added no logging or agent controls in v1.1. Agent-specific control content is entering the questionnaire ecosystem through the AIUC-1 mapping and through GRC vendors adopting AIUC-1, not through the CAIQ.
- Gartner expects AI-written answers to be reviewed by AI. If that holds, buyers will put more weight on evidence they can verify than on narrative answers. That favors exportable records over prose. This is a forecast, not observed behavior.

### Gaps
- The SIG 2026 AI-domain questions and the AI-CAIQ v1.1 questions were not accessed (licensed or download-gated).
- No public question lists were found for the AI modules of Whistic, OneTrust, Secureframe or Conveyor, and Vanta's question text is behind a form.
- No Vendor Security Alliance (VSA) AI module was found.
- I found **no independent statistic** on the share of vendor reviews that contain AI questions, and no GRC vendor dataset on AI-question frequency.

## 2. Auditors and certification: what AI evidence SOC 2 auditors request, ISO/IEC 42001 certification counts, and what 42001 audits ask for on logs

### Takeaway
SOC 2 still runs on the 2017 Trust Services Criteria. On **28 Oct 2026** the AICPA released an exposure draft of **2027 criteria** with AI points of focus, open for comment until 15 Jan 2027. If adopted, it applies to engagements beginning on or after 31 Dec 2027. Until then, auditors improvise:
- **AI products:** CSA reports requests for per-inference logs (model version, redacted prompt or prompt hash, tool calls, outcome), model lineage, LLM subprocessor risk, and drift dashboards tied to change tickets.
- **AI-written code:** the audit question is change management. A-LIGN reportedly does not accept fully AI-only code review as standard and expects a human at the approval or push-to-production step.

ISO/IEC 42001 is still rare: **271** accredited certificates worldwide at 31 Dec 2025 (ISO Survey 2025).

### Cited Findings
- **AICPA exposure draft (28 Oct 2026)** — [AICPA news](https://www.aicpa-cima.com/news/article/aicpa-proposes-update-of-soc-2-r-trust-services-criteria-to-enhance-the-relevance-usability-and-value-of-cpas-reports) [opened]; [Journal of Accountancy, 28 Oct 2026](https://www.journalofaccountancy.com/news/2026/oct/aicpa-proposes-improvements-to-soc-2-trust-services-criteria/) [opened]
  - The SOC 2 Working Group seeks comment "through Jan. 15, 2027".
  - If approved, the criteria apply to engagements beginning on or after **31 Dec 2027**, with early adoption permitted.
  - New points of focus cover "AI governance, model monitoring, prompt manipulation, data poisoning", transparency of AI-generated outputs, training-data management, and the risks of automated decision-making.
  - Neither article says how many criteria are affected, and neither mentions agentic AI, logging or human oversight.
- **Elevate Consult's reading of the draft (27 Oct 2026; a consultancy's analysis that does not quote the draft)** — [Elevate Consult](https://elevateconsult.com/insights/soc-2-trust-services-criteria-2027/) [opened]
  - **Structure:** common criteria fall from 33 to 20, and vendor management becomes its own series (CC8).
  - **Reach:** AI-related points of focus appear in **17 criteria**, 12 of them common criteria.
  - **Examples:**
    - access reviews that include AI and other technology accounts;
    - **controls against unsanctioned AI tools**;
    - monitoring AI components for drift and anomalous outputs;
    - informing users when outputs are AI-generated;
    - evaluating vendor-supplied AI components before use and after updates.
  - **Not listed** as draft points of focus: an AI inventory, logging, or human oversight.
- **Before the draft:**
  - As of 13 Oct 2026, the AICPA's SOC page still listed the 2017 TSC with the 2022 points of focus. — [search summary]
- **CSA research note "The SOC 2 AI Gap" (30 Aug 2026)** — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/) [opened]
  - **What "security-focused SOC 2 auditors" request:**
    - **training lineage:** dataset snapshot, code commit, hyperparameters, and the approval that promoted the model;
    - **per-inference logging:** model version, "a redacted prompt or prompt hash", tool calls, and outcome;
    - **LLM subprocessor risk:** the provider's SOC 2 or ISO 27001 status and its retention configuration;
    - **drift dashboards** paired with change tickets showing each deployment was approved, tested, and reversible.
  - **How it maps to the criteria:** the note gives no criteria IDs. Baker Tilly treats model development, validation and monitoring as extensions of processing integrity and security.
  - **Agents:** auditors report an "accountability gap" when agents act without a preceding human request. Advisory guidance recommends allowlisted connectors, endpoint detection, and structured logging.
  - **Shadow AI** can make an otherwise accurate report silent about AI that is actually in use.
  - **The note does not mention AI coding tools.**
  - **AICPA context:**
    - the ASEC SOC 2 Working Group warned of "templated, look-alike reports" (Journal of Accountancy, 1 Feb 2026);
    - the AICPA Peer Review Board added scrutiny of high-volume SOC 2 practices from 1 Jun 2026.
  - **Advice to buyers:** ask for AICM-aligned evidence or an AI-CAIQ self-assessment.
- **Practitioner evidence on AI-written code and SOC 2 change management** — [Vanta Community thread, 3 Jun 2026](https://community.vanta.com/x/grc/nwnr9uwkwu1y/ai-only-code-reviews-and-soc-2-change-management-e) [opened]
  - A member exploring "AI-driven code reviews with no human approvers for certain tiers of changes" asked how auditors react.
  - A respondent relayed his auditor's (A-LIGN's) view:
    - A-LIGN is "not seeing fully AI-only code review (no human) accepted as standard".
    - "Most clients keep a human at the approval/push-to-prod step".
    - Core evidence is unchanged: PR records, review comments, approvals, CI results, branch protection, audit logs.
    - AI review adds evidence on **logical access to agents**, drift and hallucination monitoring, CI/CD integration configuration, and CI/CD security thresholds.
  - Another member has asked Vanta for a feature that pulls Claude Code reviews in as evidence.
  - No one reported clearing an audit with AI-only review. The auditor's view is second-hand.
- **SOC 2 change management is technology-neutral:**
  - CC8.1 treats an AI-initiated change like a human one: it needs the same authorization, testing and approval evidence. — [Scalr](https://scalr.com/learning-center/can-ai-agents-change-infrastructure-and-stay-compliant) [search summary; vendor]
  - Guides note that an AI coding tool's own SOC 2 report does not cover the customer's change-management controls. — [search summary; vendor blogs]
- **ISO/IEC 42001 certificate count:**
  - The ISO Survey 2025 includes ISO/IEC 42001 for the first time: **271** valid accredited certificates worldwide, counted at **31 Dec 2025**. Spain shows 0. The survey's total across all standards is 3,287,917 certificates (+11%). — [DQS summary of the ISO Survey 2025, 8 Oct 2026](https://www.dqsglobal.com/es/acerca-de/sala-de-prensa/iso-survey-2025-las-certificaciones-iso-crecen-un-11-en-el-mundo-y-un-28-en-espana) [opened]
  - The survey is now compiled from IAF CertSearch data and counts only accredited certificates. — [ISO Survey page](https://www.iso.org/the-iso-survey.html) [search summary]
  - A vendor blog said fewer than 500 organizations held 42001 certification in early 2026. — [search summary; unverified]
- **Accreditation capacity is new:**
  - **BSI:** a BSI press release (URL dated November 2025) says it was the first certification body accredited by UKAS and RvA for 42001, while Vorp Labs dates UKAS's accreditation of BSI to 15 Jan 2026. These conflict. — [BSI](https://fcms.bsigroup.com/en/insights-and-media/media-centre/press-releases/2025/november/bsi-becomes-the-first-certification-body-accredited-by-ukas-and-rva-to-deliver-certification-for-isoiec-42001/), [Vorp Labs](https://vorplabs.com/security-framework-changes/iso-iec-42001) [search summary]
  - **Palindrome Technologies** announced accreditation in April 2026. — [Technijian](https://technijian.com/ai/iso-42001-certification-surge-hits-this-week-ibex-and-palindrome-announcements-signal-ai-governance/) [search summary]
  - **ANAB** accreditation covers Armanino Certified and ControlCase. — [Bright Defense](https://brightdefense.com/news/iso-42006-raises-the-bar-for-iso-42001-certifiers) [search summary]
- **ISO 42001 A.6.2.8 wording and retention:**
  - Aviso Consultancy renders the control as: "The organization shall determine at which phases of the AI system life cycle, record keeping of event logs should be enabled, but at the minimum when the AI system is in use." — [Aviso](https://www.avisoconsultancy.co.uk/iso-42001-annex-a/06-2-8-ai-system-recording-of-event-logs) [search summary]
  - ISMS.online quotes shorter wording without "at the minimum". — [ISMS.online](https://www.isms.online/iso-42001/annex-a-controls/a-6-ai-system-life-cycle/a-6-2-8-ai-system-recording-of-event-logs/) [search summary]
  - Freshfields notes that ISO 42001 sets no minimum retention, whereas the AI Act requires at least six months. — [Freshfields](https://technologyquotient.freshfields.com/post/102jcog/eu-ai-act-unpacked-10-iso-42001-a-tool-to-achieve-ai-act-compliance) [search summary]
- **What 42001 auditors ask for** — [Teleport blog, 3 Sep 2026; vendor; the author says he is a certified 42001/27001 auditor](https://goteleport.com/blog/iso-42001-audit-evidence/) [opened]
  - **A.6.2.8 event logs:**
    - Logs must "contain enough context to connect an action to a specific actor, resource, time, and activity".
    - Activity should be attributable to an engineer, service account, workload, pipeline, or **agent**.
    - Typical sources are cloud and Kubernetes audit events, authentication logs, and CI/CD activity.
  - **A.9.3 human oversight:**
    - a review record of who checked the AI output and when;
    - sign-off before release;
    - logs showing someone "paused, stopped, rejected, or overrode an AI action".
  - **A.4.5:** AI systems and resources are documented, with dated access reviews.
  - **Not covered:** the post gives no retention period and does not address tamper-evidence.

### Inferences
- For a team that uses coding agents, the auditor's question today is **who approved the change**. A human PR approval satisfies it, so agent records are not yet required.
- Agent records become necessary when a team removes the human approver for some change tiers, or when agents act without a preceding human request (CSA's "accountability gap"). Then the evidence shifts to the agent's access, its configuration, and its outputs.
- The draft 2027 criteria (as Elevate reads them) include "controls against unsanctioned AI tools" and access reviews covering AI accounts. Both are inventory and identity questions. A cross-harness record of which agents ran, under whose identity, is evidence for both, from the first examination period that adopts the 2027 criteria (late 2027 to 2028, or earlier under early adoption).
- CSA reports that auditors accept "a redacted prompt or prompt hash". Auditors therefore do not demand plaintext prompts, which supports a record that stores hashes or redacted content.
- With 271 certificates worldwide at the end of 2025, ISO 42001 is not yet a mass-market trigger for 5–150-person teams. It matters mainly where a customer program accepts it in place of an assessment (Microsoft SSPA; see §3).

### Gaps
- The exposure draft itself was not opened. The count of 17 criteria and the example points of focus are Elevate's reading.
- No audit-firm publication (Schellman, A-LIGN, Linford, etc.) on AI coding tools was found; the A-LIGN view is second-hand from a forum.
- The normative ISO/IEC 42001 text (paywalled) and IAF CertSearch were not accessed.
- No information was found on how many SMBs hold 42001, or on certification-body checklists for A.6.2.8.

## 3. Client contracts: clauses and guidelines that restrict or require disclosure of AI use

### Takeaway
Contract-level AI terms exist but are uneven:
- **Strongest primary example:** Microsoft's Supplier Data Protection Requirements v12 (March 2026). They apply to any supplier that "use[s] AI Systems in connection with" its performance, and add AI training, Section K requirements, and change logs that name the approver, with 90 days available on request.
- **Law firms:** only **2% of 1,054 public outside-counsel guidelines** mention AI. Those that do require disclosure (often in the time entry), human review, and keeping client data out of open AI tools.
- **Agencies:** the ANA media-buying template requires prior consent for any AI application used in delivering services.
- **Software-development and AI addenda:** these add disclosure, consent, no-training, inventory and advance-notice, IP warranty and indemnity terms, though the evidence is mostly templates and commentary.
- **US federal:**
  - M-25-22 excludes contractor-optional AI but tells agencies to consider AI-use disclosure clauses.
  - GSA's LLM clause (effective 19 Oct 2026) reaches contractors whose LLMs process Government Data.
  - The FY2026 NDAA bans "covered AI" (DeepSeek and covered-nation AI) for DoD contractors.

### Cited Findings
- **Microsoft Supplier Data Protection Requirements (DPR) v12, March 2026 (binding on Microsoft suppliers through the SSPA program)** — [Microsoft DPR v12 PDF](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
  - **Applicability:** the DPR applies to suppliers that process Microsoft personal or confidential data "and/or use AI Systems in connection with that supplier's performance (e.g., provision of services, software licenses, cloud services)". Section K "is only applicable to suppliers providing services to Microsoft involving AI Systems".
  - **"AI Systems" definition** (broad): "an engineered system that applies an optimized model so that the system can, for a given set of human-defined objectives, make predictions, recommendations, or decisions…".
  - **Req. 3 (AI training):** anyone who will "Process data within AI Systems in connection with Supplier's engagement for Microsoft" must complete AI training relevant to their role.
  - **Req. 33 (change logs):** "The required change logs must track changes, provide information regarding the reason for the change, and include the name and title of the designated approver. Records for past 90 days available upon request."
  - **Section K (Reqs. 51–63):**
    - **Contract terms and intended uses:** AI Systems terms must be in the contract. Any change to Intended Uses "must be disclosed without undue delay".
    - **Prohibited Practices** are banned.
    - **AI incident response plan:** Microsoft must be notified "without undue delay" or sooner. The plan must include rollback times and the ability to turn features off.
    - **Governance documents:** transparency disclosures, a document defining accountability, and risk assessments.
    - **Logging:** the supplier is "to log all system failure reports, corruption, hallucinations, or reported misuse … and provide evidence of steps taken to resolve the issues".
    - **Health-monitoring SOP:** it must include "Processes for reproducing system failures".
    - **Human Oversight** is defined as human-in-the-loop, human-on-the-loop, or human-in-command.
  - **Assessment route:** an independent assessment becomes mandatory when Section K is in scope, and Microsoft accepts ISO 42001 certification as an alternative pathway. — [CSA blog, 16 Oct 2024](https://cloudsecurityalliance.org/blog/2024/10/16/an-overview-of-microsoft-dpr-its-new-ai-requirements-and-iso-42001-s-potential-role), [Microsoft SSPA](https://www.microsoft.com/procurement/sspa) [search summary]
- **Outside-counsel guidelines (OCGs):**
  - **Fulkerson Advisors study** (Cambridge, MA; documents collected 15–16 Sep 2026) — [Fulkerson Advisors](https://www.fulkersonadvisors.com/research/ai-in-outside-counsel-guidelines) [opened]
    - **Sample:** 1,054 OCGs dated December 2022 or later.
    - **Results:**
      - **20 mention AI (2%)**, and no guideline dated before 2024 does.
      - **12** require disclosure, **1** bans AI outright, and **9** keep client information out of public AI tools.
      - **8** require lawyer review of AI output, and **9** change billing (2 refuse to pay for AI time).
      - **1** limits firms to approved tools, and **3** require the firm to have its own AI policy.
    - **Examples:**
      - Zscaler: "If a timekeeper uses generative AI for a discrete task, they should note that in their time entry"; "Any work product created by a Large Language Model (LLM) or other generative AI tool must be reviewed by a human attorney."
      - FDIC: "Never enter Sensitive Information or FDIC work product into a GenAI tool that operates in an 'open environment.'"
      - UBS, Microsoft and the University of California are also named.
    - **Limitations:**
      - 86% of the sample are public bodies, and only 24 are companies.
      - Most corporate OCGs are delivered through portals and never published.
      - The rubric did **not** code logging or audit rights.
  - **ACC template:** the Association of Corporate Counsel publishes a sample set of AI guidelines for outside counsel, covering disclosure, data security, accuracy and performance (members only). Its full text was not accessed. — [ACC](https://www.acc.com/resource-library/sample-artificial-intelligence-ai-guidelines-outside-counsel) [search summary]
  - **Thomson Reuters 2025 GenAI in Professional Services report** — [Law Gazette](https://www.lawgazette.co.uk/news/corporate-clients-demanding-firms-use-ai/5123087.article), [LawCareers](https://www.lawcareers.net/Explore/News/Corporate-clients-push-for-AI-adoption-in-law-firms-25042025) [search summary]
    - **59%** of corporate legal respondents want their firms to use AI.
    - **8%** of clients request GenAI use in tender documents.
    - **71%** of corporate clients do not know whether their outside firms use GenAI.
  - **Unverified figure:** Sartori attributes "14% of GCs mandate disclosure, 30% consider it" to a Thomson Reuters survey, which I could not verify. — [Sartori](https://sartoriglobal.com/insights/market/ai-driven-panel-selection-are-clients-changing-how-they/) [search summary]
  - **Older reporting (29 Nov 2023):**
    - Paul Weiss said some clients asked it not to use GenAI without first telling them.
    - Salesforce's chief legal officer expected firms to disclose GenAI use.
    - A Florida Bar draft opinion recommended informed consent where AI use would disclose confidential information.
    - Source: [Bloomberg Law](https://news.bloomberglaw.com/business-and-practice/law-firms-wrestle-with-how-much-to-tell-clients-about-ai-use) [opened]
- **Agency and consultancy agreements:**
  - The ANA Master Media Buying Services Template (June 2023) says "an agency must obtain the advertiser's prior consent to use any artificial intelligence applications in the delivery of services". — [MediaPost](https://www.mediapost.com/publications/article/386043/ana-revises-media-agency-contracts-requires-prior.html), [CLL advertising-law alert](https://www.cll.com/media/news/829_Print_Pilot_-_Advertising_Law_Alert_--_How_Brands_Can_Identify_and_Mitigate_AI-Related_Risks_in_Advertising_Campaigns.pdf) [search summary]
  - The ANA and Venable published an "AI Rider" template in 2025 (members only). — [ANA](https://www.ana.net/miccontent/show/id/pulse-2025-06-gen-ai-use-in-ad-contracts) [search summary]
  - The 4A's has a template for agency AI policies, and ISBA has Generative AI contract terms for UK advertisers. — [ISBA](https://www.isba.org.uk/event/generative-ai-advertiser-guidance-and-contract-terms-agency-use) [search summary]
  - A WFA survey found only **29%** have reviewed media and creative contracts to add AI clauses (survey date not given). — [search summary]
  - The 4A's article "Brands add AI restrictions to agency contracts" returned 404. — [4A's](https://aaaa.org/brands-add-ai-restrictions-to-agency-contracts-behind-the-growing-trend/) [did not load]
  - **Deloitte Australia** agreed to repay the final instalment of an A$440,000 government report after it was found to contain AI-generated errors (fabricated references and a fabricated legal quote) — [ACS Information Age](https://ia.acs.org.au/article/2025/deloitte-to-refund-government-over-ai-errors.html), [TechSpot](https://www.techspot.com/news/109758-deloitte-admits-ai-hallucinated-quotes-government-report-offers.html) [search summary]:
    - Its AI use (Azure OpenAI GPT-4o) was disclosed only in the updated version of the report.
    - Reports said stricter AI rules for government contracts would follow. I could not confirm any binding rule.
- **Software-development contracts and AI addenda (templates and commentary; few true law-firm alerts were accessible):**
  - **Warranties and indemnity:**
    - Recommended terms include warranting that deliverables, "including any AI-generated components", do not infringe, and indemnifying third-party IP claims related to AI-generated code. Finberg Firm calls that indemnity "non-negotiable" (April 2026). — [Finberg Firm](https://finbergfirm.com/2026/04/01/key-clauses-in-software-master-services-agreements-msa-2026/), [Gravitee explainer](https://www.gravitee.io/corpus/gen-1991/commercial-law/indemnification-for-ai-outputs.html) [search summary]
    - Coding-tool vendors' own terms disclaim non-infringement; Tabnine is an example. — [ConductAtlas on Tabnine terms](https://conductatlas.com/platform/tabnine/tabnine-terms-of-use/warranty-disclaimer/) [search summary]
  - **Disclosure and prohibition:**
    - Templates recommend an AI-generated-code disclosure clause. — [Layer3 Labs template](https://www.layer3labs.io/contracts/software-development-contract-template) [search summary]
    - Client MSAs may warrant that deliverables are original and ban GenAI without written consent. — [search summary]
    - A freelancer guide describes "full prohibition" clauses that, read literally, cover VS Code with Copilot. It says code clients mostly worry about licence-tainted output and the confidentiality of their code in cloud AI services, and suggests satisfying them with **"a tool log plus assurances about the tool's data-retention controls"**. — [Delivvo](https://delivvo.io/blog/anti-ai-contract-clauses-freelancers-2026), [FixMyContract](https://www.fixmycontract.com/guides/what-is-an-ai-clause-in-a-contract) [search summary]
  - **AI-addendum clauses:**
    - prior written consent before "incorporating, using or making AI features available in the performance of the services or in deliverables";
    - no training on customer inputs or outputs;
    - customer ownership of outputs;
    - flowdown to model-provider subprocessors;
    - a list of AI systems in use, with **60 days' advance notice** of any new AI system that will process Customer Data.
    - Sources: [No Jitter](https://www.nojitter.com/data-governance/have-a-saas-contract-in-place-you-may-need-an-ai-addendum), [AI Governance Library](https://www.aigl.blog/key-terms-for-ai-addendums-six-clauses-to-include-in-your-ai-addendum/), [Axiom](https://www.axiomlaw.com/blog/ai-addendums-contract-clauses-to-negotiate-with-ai-vendors) [search summary]
  - The ABA Business Law Today article "Vendor AI legal considerations" (October 2026) and the GFR Law article on AI deliverables clauses both returned 403. — [ABA](https://www.americanbar.org/groups/business_law/resources/business-law-today/2026-october/vendor-ai-legal-considerations), [GFR Law](https://www.gfrlaw.com/what-we-do/insights/ai-deliverables-clauses-providers-need-assurances-clients-should-seek) [did not load]
- **US federal acquisition:**
  - **OMB M-25-22 (3 Apr 2025; rescinds M-24-18)** — [OMB M-25-22](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf) [opened]
    - **Exclusion:** the memo excludes "AI used incidentally by a contractor during performance of a contract (e.g., AI used at the option of a contractor when not directed or required to fulfill requirements)".
    - **Applicability:** it applies to contracts awarded under solicitations issued 180 days or more after issuance (about 30 Sep 2025), and to options exercised after that date.
    - **§3(h):** "Agencies must be cognizant of the risks posed by the unsolicited use of AI systems by vendors and determine whether there are circumstances that merit including a provision in a solicitation requiring disclosure of AI use as part of any given contract's performance."
    - **Acquired AI systems:**
      - Contracts must let agencies "regularly monitor and evaluate (e.g., on a quarterly or biannual basis)".
      - Vendor testing must be detailed enough to be "independently verified or reproduced, if practicable".
    - **M-25-21:** the memo cross-references M-25-21's minimum practices for high-impact uses. M-25-21 itself was not opened.
  - **GSA clause GSAR 552.239-7001, "Basic Safeguarding of Data within Large Language Model Artificial Intelligence Systems"** — [Crowell & Moring, 2 Oct 2026](https://www.crowell.com/en/insights/client-alerts/gsa-issues-final-rule-on-large-language-model-procurements) [opened]; [Winvale](https://info.winvale.com/blog/gsas-new-ai-clause-is-here-heres-what-mas-contractors-should-know), [Jenner](https://www.jenner.com/en/news-insights/client-alerts/gsa-issues-a-revised-proposed-clause-governing-ai-data-safeguarding-requirements) [search summary]
    - **History:** drafted 6 Mar 2026, revised 17 Jun 2026, issued **28 Sep 2026** as a GSA deviation, and **effective 19 Oct 2026**.
    - **Scope:** it applies where LLM functionality is a "material feature" and Government Data is "submitted directly to or produced by the LLM". It self-deletes where LLM use is internal "back-office" or "incidental or ancillary".
    - **Incident notice:** the trigger is an incident "affecting an LLM used in the performance of the contract". The June draft required notice within 72 hours; the final timeline is not given in the alert.
    - **Flowdown:** it flows down to subcontractors that "collect[], process[], store[], retain[], train[] on, fine-tune[] on, or otherwise handle[] Government Data", tied to the NIST AI RMF task categories.
    - **Government rights:** the Government may suspend LLM use "at any time".
    - **Data definitions:** logs and metadata are excluded from "Data Outputs".
  - **FY2026 NDAA §1532 (P.L. 119-60, signed 18 Dec 2025):**
    - Bars DoD contractors from using "covered AI" in contract performance. Covered AI means DeepSeek, High Flyer, and AI from covered nations. The bar took effect around 17 Jan 2026, with waivers possible.
    - A King & Spalding alert (relayed second-hand) says contractors "will need to audit [their] use of any covered AI".
    - Sources: [CRS In Focus IF13197](https://www.everycrsreport.com/reports/IF13197.html), [Digital Policy Alert](https://digitalpolicyalert.org/event/42290-prohibition-on-use-of-deepseek-and-related-artificial-intelligence-in-national-defense-authorization-act-for-fiscal-year-2026-public-law-119-60-entered-into-force-for-department-of-defense-and-its-contractors), [Petronella](https://petronellatech.com/blog/deepseek-and-the-fy2026-ndaa-what-dod-contractors-need-to-know/) [search summary]
- **News of AI coding-tool bans:**
  - One blog reports that Alibaba banned Claude Code company-wide from 10 Jul 2026. It was an internal ban, not a client clause, and it comes from a single source. — [BERI](https://www.beri.net/article/alibaba-bans-claude-code-hidden-tracking-enterprise-ai-tool-trust-sovereignty-crisis-2026) [search summary; unverified]

### Inferences
- **Microsoft DPR:** it is the clearest primary evidence that a large client asks suppliers, including agencies and consultancies, to *prove* things about their AI use: training, incident plans, logs of failures, change logs with approvers, and disclosure of changes in use. Its definition of "AI Systems" is broad enough that coding agents used to build deliverables for Microsoft plausibly bring the supplier under DPR applicability. Whether that triggers full Section K is ambiguous and decided through the SSPA profile.
- **OCGs:** they show the *shape* of a per-task disclosure duty ("note that in their time entry"). A per-run record that attaches to a client matter or ticket would satisfy that duty. But 98% of public OCGs say nothing about AI, and published OCGs skew to the public sector.
- **Federal:** contractor-optional coding agents are **outside** M-25-22, and GSA's clause self-deletes for incidental LLM use. Federal reach to coding agents therefore comes from agency-specific disclosure clauses (§3(h)), from NDAA §1532 bans on specific models, and from the GSA clause when the deliverable is itself an LLM system processing Government Data. A per-run record of which harness and model ran, and on what data, answers the §1532 "audit your use" question.
- **Agent-record service under the GSA clause:** a vendor-readable record service that stored prompts containing Government Data could plausibly count as a subcontractor that "stores" or "retains" Government Data under GSA's flowdown. A design where the vendor holds only ciphertext under the team's keys weakens that argument, but I found no guidance on whether encrypted storage counts as "handling".
- **Data restrictions:** OCG and FDIC-style rules ("never enter … into a GenAI tool … in an open environment") cut both ways. A record of agent work that contains client work product must itself satisfy client data-handling terms. That favors customer-held keys and redaction.

### Gaps
- Full texts of the ACC sample, the ANA AI Rider, the 4A's template, and the ABA and GFR articles were not accessed.
- I found no corporate (non-public-sector) OCG corpus, and no statistic on AI clauses in software-development MSAs.
- I found no named news report of a client banning its software vendor's or agency's use of AI coding tools.
- I could not confirm any binding Australian rule on consultant AI disclosure after the Deloitte refund.
- M-25-21 was not opened.
- The final GSA clause text (acquisition.gov) was not opened, so the incident-notice timeline is unknown.

## 4. Sector rules that imply records of automated actions, and which reach coding agents as opposed to business agents

### Takeaway
No sector rule names coding agents. The rules reach a coding agent only where the agent **acts inside the regulated system**:
- **HIPAA audit controls:** systems that contain or use ePHI.
- **PCI DSS 10.2.1.2 and 10.5.1:** administrative actions on cardholder-data components, with 12 months of retention.
- **PCI DSS 6.2.3:** pre-release review of bespoke code.
- **DORA RTS Art. 12:** change and access events, protection against tampering, and a retention period the entity sets.

FINRA's 2026 report is the only regulator text found that tells firms to consider "how to track agent actions and decisions". It is guidance aimed at business uses. The banking agencies' SR 26-2 (April 2026) puts generative and **agentic AI outside** model-risk guidance. The EU CRA adds SBOM, third-party-component due diligence, and 10-year documentation duties, but no rule on AI provenance.

### Cited Findings
- **HIPAA (binding):**
  - 45 CFR 164.312(b): "Standard: Audit controls. Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information." — [Cornell LII](https://www.law.cornell.edu/cfr/text/45/164.312) [opened]
  - The Security Rule overhaul (the January 2025 proposed rule) slipped from May 2026 to **July 2027** and moved to "long-term actions" in the July 2026 regulatory agenda. The current rule stays in force. — [Fierce Healthcare](https://www.fiercehealthcare.com/health-tech/feds-push-back-hipaa-security-rule-overhaul-july-2027), [DWT](https://www.dwt.com/blogs/privacy--security-law-blog/2026/07/hhs-updates-hipaa-rulemaking-timeframes) [search summary]
- **PCI DSS v4.0.1** (standard text as reproduced by Cloudaware):
  - **10.2.1.2:** "Audit logs capture all actions taken by any individual with administrative access, including any interactive use of application or system accounts." — [Cloudaware 10.2.1.2](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/02/01/02/) [opened]
  - **10.5.1:** "Retain audit log history for at least 12 months, with at least the most recent three months immediately available for analysis." — [Cloudaware 10.5.1](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/05/01/) [opened]
  - **6.2.3 and 6.2.3.1:** bespoke and custom software is reviewed before release. Manual reviews must be done by someone other than the originating author and approved by management. — [Cloudaware 6.2.3](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/06/02/03/) [search summary]
  - No QSA guidance was found on whether an AI tool counts as the "originating author".
- **PCI SSC guidance (non-binding):**
  - "Integrating Artificial Intelligence in PCI Assessments – Guidelines v1.0" (spring 2025) covers *assessors'* use of AI. — [PCI SSC blog](https://blog.pcisecuritystandards.org/new-guidance-integrating-artificial-intelligence-into-pci-assessments) [search summary]
  - An AI system inside the PCI scope must meet the applicable requirements. — [Barr Advisory](https://www.barradvisory.com/resource/ai-scope-pci-dss/) [search summary]
  - On **7 Oct 2026** the PCI SSC published "additional guidance on securing AI in payment environments" (the URL slug suggests "Security Considerations for AI Systems") — [PCI SSC press release](https://www.pcisecuritystandards.org/about_us/press_releases/pci-ssc-publishes-additional-guidance-on-securing-ai-in-payment-environments/) [opened]:
    - It covers access management for AI systems that act with limited human involvement, and where responsibility sits.
    - It "is not to be considered as mandatory requirements".
    - The release itself says nothing about logging or about Requirement 10.
- **FINRA (guidance):**
  - **Regulatory Notice 24-09 (27 Jun 2024):** existing rules apply to GenAI as to any technology, whether the tools are built in-house or supplied by a third party. It creates no new requirements. — [FINRA RN 24-09](https://www.finra.org/rules-guidance/notices/24-09) [search summary]
  - **2026 Annual Regulatory Oversight Report (released December 2025)**, GenAI section — [FINRA](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) [opened]:
    - **Definition:** AI agents are "systems or programs that are capable of autonomously performing and completing tasks on behalf of a user".
    - **Risks named:** autonomy, scope and authority, and auditability.
    - **Considerations for firms:**
      - "how to monitor agent system access and data handling;"
      - "where to have 'human in the loop' agent oversight protocols or practices;"
      - "how to track agent actions and decisions;"
      - guardrails to limit agent behavior.
    - **GenAI monitoring:** firms may keep "prompt and output logs for accountability and troubleshooting" and track "which model version was used and when".
    - **Code generation and software-development uses are not mentioned.**
    - **Recordkeeping:** GenAI "can implicate rules regarding supervision, communications, recordkeeping and fair dealing", including supervision under Rule 3110.
  - Debevoise's summary says the report recommends vendor contracts that, for example, prohibit ingesting sensitive data into open-source GenAI tools. The GenAI page I opened did not discuss contract terms, so the two may conflict. — [Debevoise](https://www.debevoise.com/insights/publications/2025/12/finras-2026-regulatory-oversight-report-continued) [search summary]
- **SEC (exam priorities, not rules):**
  - The 2026 examination priorities (Foley dates the release to 17 Nov 2025; another source says January 2026) cover:
    - firms' use of automated tools, AI and algorithms;
    - the accuracy of AI-related representations;
    - governance, controls and human oversight;
    - compliance with the 2024 amendments to Regulation S-P.
  - Sources: [Foley](https://www.foley.com/insights/publications/2025/12/sec-releases-its-2026-examination-priorities/), [Sia Partners](https://www.sia-partners.com/en/insights/publications/sec-division-examinations-releases-2026-priorities) [search summary]
- **Banking model risk (guidance):**
  - **SR 26-2** (17 Apr 2026; Federal Reserve, OCC, FDIC) supersedes SR 11-7 and SR 21-8. It is most relevant to Fed-supervised organizations with more than $30 billion in assets. — [SR 26-2 letter](https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm) [opened]
  - Footnote 3 reads: "Generative AI and agentic AI models are novel and rapidly evolving. As such, they are not within the scope of this guidance. Nonetheless, a banking organization's risk management and governance practices should guide the determination of appropriate governance and controls for any tools, processes, or systems not covered in this document." — [SR 26-2 attachment](https://www.federalreserve.gov/supervisionreg/srletters/SR2602a1.pdf) [opened]
  - The OCC's version is Bulletin 2026-13. The agencies said they plan a request for information on AI. — [search summary]
- **EU DORA (binding on EU financial entities):**
  - Delegated Regulation (EU) 2024/1774, Art. 12 — [Springlex reproduction of OJ text](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-12/) [opened]:
    - Entities must "develop, document, and implement logging procedures, protocols and tools".
    - **Events to log** cover access control and identity management, capacity, **change**, ICT operations, and network traffic.
    - **Protection:** logs are protected against "tampering, deletion, and unauthorised access", and logging failures must be detected.
    - **Clocks** must be synchronized.
    - **Retention** is set by the entity, "taking into account the business and information security objectives", the reason for logging, and the ICT risk assessment.
  - A vendor blog's claim of a five-year minimum is contradicted by the text above. — [DeepInspect](https://www.deepinspect.ai/blog/ai-audit-log-retention-period) [search summary]
- **EU NIS2:**
  - Implementing Regulation (EU) 2024/2690 sets security measures, including monitoring and logging, for cloud providers, managed service providers, managed security service providers, and other digital providers. — [Hunton](https://www.hunton.com/privacy-and-cybersecurity-law-blog/implementing-regulation-developing-nis2-rules-for-certain-digital-service-providers-enters-into-force) [search summary]
  - The Annex §3.2 text did not load from EUR-Lex.
- **EU Cyber Resilience Act (binding):**
  - **Dates:** reporting obligations apply from **11 Sep 2026**, with 24-hour reporting of actively exploited vulnerabilities and severe incidents to ENISA/CSIRTs. Most other obligations apply from **11 Dec 2027**. — [Jones Day](https://www.jonesday.com/en/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026), [McCann FitzGerald](https://www.mccannfitzgerald.com/knowledge/data-privacy-and-cyber-risk/cyber-resilience-act-reporting-obligations-apply-from-11-september-2026) [search summary]
  - **Art. 13 duties** — [Springlex Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/) [opened]:
    - **Art. 13(5):** manufacturers "shall exercise due diligence when integrating components sourced from third parties".
    - **Art. 13(13):** technical documentation and the EU declaration of conformity are kept for at least **10 years** or the support period, whichever is longer.
    - **Art. 13(24):** the SBOM format is left to an implementing act. The SBOM requirement itself sits in Annex I, Part II(1).

### Inferences
- **Business agents** (agents that process patient data, card data, customer communications or trading workflows) are the main target of HIPAA, PCI, FINRA and SEC expectations.
- **Coding agents** are reached in three ways:
  - when they operate with administrative access on in-scope systems (PCI 10.2.1.2's "interactive use of application or system accounts" covers an agent running under an engineer's admin credentials; HIPAA audit controls cover any activity in systems that hold ePHI);
  - when they author code that must pass the pre-release review in PCI 6.2.3;
  - when they make changes in a financial entity's ICT systems (DORA "change" events).
  - A coding agent confined to a repository with no production data is largely outside these rules. Only change management applies to it, through SOC 2 and DORA.
- FINRA's "track agent actions and decisions" and "which model version was used and when" are the closest regulator statements to "a record of what every agent run did". Fintech vendors meet them second-hand, through broker-dealers' vendor oversight, not directly.
- SR 26-2 removes the most obvious banking hook for agent governance. Banks' asks of vendors about agents will come from general third-party risk management, not model-risk management.
- The CRA's 24-hour reporting from September 2026, together with its due-diligence duty, implies that manufacturers must be able to reconstruct how a component or change entered a product. A record of agent work helps with that. The CRA itself does not require it.

### Gaps
- I did not verify HIPAA's documentation-retention rule (45 CFR 164.316(b)(2)), the record-retention periods under FINRA and SEC 17a-4, or the detail of the Regulation S-P amendments.
- DORA's contractual requirements for ICT third parties (Arts. 28–30) were not opened.
- The NIS2 CIR Annex §3.2 logging and retention text did not load.
- The PCI SSC October 2026 AI guidance document itself was not opened, and no QSA position on AI-authored code under 6.2.3.1 was found.
- No 2025–2026 SEC rule specific to AI was identified.

## 5. Cyber insurance: AI questions on applications, AI exclusions and endorsements

### Takeaway
Insurers are changing **policy wording** faster than **applications**:
- **Affirmative cover:** Coalition writes affirmative AI coverage into its base cyber policy.
- **Exclusions:**
  - Verisk/ISO has offered optional generative-AI exclusions for general liability (CGL) policies since January 2026, and they are spreading.
  - W.R. Berkley reportedly uses an absolute AI exclusion in its D&O and E&O lines.
- **Applications:** a September 2026 read of seven forms found **no AI question** on the Beazley, Chubb and Apogee cyber applications. The one AI question found was on AmTrust's lawyers' professional-liability forms.
- **Agent-specific underwriting** runs through **AIUC-1**, which certifies *agent vendors*, not teams that use agents. It requires activity logging and tool-call logging, and since July 2026 has requirements for coding agents. Certification unlocks affirmative AI liability cover.

### Cited Findings
- **Coalition (affirmative cover):**
  - On 26 Mar 2024 it added an Affirmative AI Endorsement, which counts an "AI security event" as a security failure and covers deepfake-induced funds-transfer fraud.
  - In April 2025 the endorsement was folded into the Active Cyber Policy.
  - A 18 Mar 2026 blog says Coalition "enhanced our policy language" on prompt injection and the "gray area of model hallucinations", and attaches a Deepfake Response Endorsement automatically.
  - Sources: [Coalition announcement](https://www.coalitioninc.com/announcements/coalition-adds-new-affirmative-ai-endorsement-to-cyber-policies), [Coalition blog](https://www.coalitioninc.com/blog/cyber-insurance/active-insurance-ai-risk-landscape) [search summary]
- **Exclusions:**
  - **Verisk/ISO forms:** optional GenAI exclusions for CGL policies have been available since 1 Jan 2026. The forms are CG 40 47 (broad), CG 40 48 (narrower) and CG 35 08 (products and completed operations); sources describe their scope differently. — [Big I](https://www.independentagent.com/vu_resource/verisk-to-roll-out-new-general-liability-exclusions-for-generative-ai-exposures/), [MoneyGeek](https://www.moneygeek.com/insurance/business/general-liability/generative-ai-exclusion/) [search summary]
  - **Adoption:** a trade article reports **2,369** GenAI-exclusion filings in force across 49 states by mid-2026. Carriers named include Berkley, Chubb, Travelers, Berkshire Hathaway and AIG, using ISO forms or their own equivalents. This is a single source. — [Insurance Business](https://www.insurancebusinessmag.com/us/news/cyber/isos-generative-ai-exclusion-is-already-on-thousands-of-cgl-policies-589971.aspx) [search summary]
  - **W.R. Berkley:** results report an absolute AI exclusion across its D&O, E&O and fiduciary products. — [Insurance Business](https://www.insurancebusinessmag.com/us/news/cyber/isos-generative-ai-exclusion-is-already-on-thousands-of-cgl-policies-589971.aspx), [Beancount guide](https://beancount.io/blog/2026/08/13/iso-generative-ai-exclusion-cgl-2026-guide) [search summary; which page states it is unclear]
- **Applications** — [Nonimo guide, 16 Sep 2026, updated 28 Sep 2026](https://nonimo.ai/resources/guides/cyber-insurance-questionnaire-ai-questions/) [opened; vendor (redaction software); page footer marks it "TEST SITE"; small sample the author chose]
  - Of 7 insurer and broker forms opened on 16 Sep 2026, only 2 asked about AI. Both were AmTrust lawyers' professional-liability forms dated May 2023:
    - "Allow the use of Artificial Intelligence software to draft documents. If checked, please attach description."
    - "Does the firm allow for the use of Artificial Intelligence software to draft documents?"
  - The five cyber forms (Beazley, three Chubb forms, Apogee) contained **no AI question**.
  - The page cites Aon's estimate that over 90% of cover for AI perils sits in policies that do not mention AI ("silent AI").
- **At-Bay:** a gated "2026 Guide to AI Risk" covers topics from securing AI agent access to auditing policies for AI exclusions. — [At-Bay](https://www.at-bay.com/?p=18170) [search summary]
- **AIUC-1 (the agent standard tied to insurance)** — [NYU Shanghai RITS article](https://rits.shanghai.nyu.edu/ai/aiuc-1-the-ai-agent-certification-turns-to-coding-agents/) [opened; secondary]
  - **Who runs it:** the Artificial Intelligence Underwriting Company writes the standard, runs the evaluations, issues certificates, and sells insurance. Critics flag this as a conflict of interest.
  - **Insurance:** certified vendors can bind affirmative AI liability cover marketed at up to **$50M**.
  - **Q3-2026 revision (15 Jul 2026):** changed 8 requirements and 41 controls, and added two **mandatory requirements for code-generating agents**:
    - **A008**, preventing leakage of secrets "in AI system inputs, outputs, logs, and credential storage";
    - **B010**, promoting secure patterns in generated code, including "safe dependency specification".
    - B006.3 adds sandboxed execution for code that agents execute.
  - **Re-certification** requires quarterly red-teaming and annual validation.
  - **Certified so far:** ElevenLabs, Intercom Fin (December 2025), UiPath (March 2026) and Fieldguide (May 2026). Lovable is pursuing certification, with a Schellman audit planned.
- **AIUC-1 logging controls:**
  - **E015** asks organizations to maintain logs of AI system processes, actions and model outputs "where permitted". **E015.2** requires storage with appropriate retention, access controls and data sanitation. Auditors may look for WORM storage, hashing or append-only settings. — [myctrl.tools](https://myctrl.tools/frameworks/aiuc-1/e015) [search summary; third-party summary]
  - **Q2-2026 refresh (effective 15 Apr 2026):** modified 14 requirements and added 23 controls for MCP and agent-to-agent security. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-aiuc1-owasp-agentic-crosswalk-20260804-csa/) [search summary]
  - **Tool-call controls:** 2026 updates reportedly added approved-MCP-server rules, sandboxing, and "authorizing and logging each tool call, including the MCP tool name and its inputs". — [Morphisec](https://www.morphisec.com/?p=11269), [Pomerium](https://www.pomerium.com/blog/the-aiuc-1-compliance-checklist-5-layers-every-enterprise-needs-before-deploying-ai-agents) [search summary; vendor]

### Inferences
- **Applications:** I found no evidence that cyber insurance applications ask SMB engineering teams what their agents did. The application-side trigger is weak today.
- **Claims side:** the insurance effect runs through claims. Exclusions such as CG 40 47 apply where AI is merely a contributing factor, and "silent AI" wording is being tightened. If a loss is linked to agent activity, an insured with a record of what the agent did, and who approved it, is better placed to contest whether an exclusion applies. This is an inference; I found no claim case.
- **AIUC-1:** it is the clearest market signal that tool-call and activity logs are becoming certifiable evidence *for agent products*. Teams that ship agents may face AIUC-1-style questions from customers. Teams that only use coding agents mostly will not.

### Gaps
- No primary Marsh guidance from 2026 on AI agents was found. No Beazley or Chubb AI wording or endorsements were found beyond Nonimo's form check, and the actual AI questions on At-Bay's and Coalition's applications were not found.
- Several claims surfaced in search summaries but could not be traced to an identifiable page:
  - that 81% of cyber insurers include AI governance questions in 2026 renewals;
  - that only Arch's Australian questionnaire asks about staff use of AI;
  - Acrisure London Wholesale's "nine governance questions";
  - a sample question set ("Does your organization permit the use of generative AI tools? Which ones? …");
  - HSB's AI liability product for small businesses.
- The primary AIUC-1 standard text (control IDs, retention) was not accessed.

## 6. Software supply chain: do SSDF 800-218A, the CISA attestation form, the CRA, SBOM/AI-BOM formats, or customers ask for the provenance of AI-generated code?

### Takeaway
As of October 2026, **no binding supply-chain rule asks for the provenance of AI-generated code**:
- **US federal:**
  - The CISA secure-software attestation became optional for agencies (OMB M-26-05, 23 Jan 2026).
  - SP 800-218A covers *developing* generative AI models, not using coding assistants.
  - SSDF v1.2 (SP 800-218 Rev. 1) is still a draft.
- **EU CRA:** requires SBOMs (at least top-level dependencies), due diligence on third-party components, and 10-year technical documentation, but nothing specific to AI.
- **AI-BOM formats** (the SPDX 3.0 AI and Dataset profiles; CycloneDX ML-BOM) describe models and datasets, not code an AI wrote.

The only explicit provenance demands found come from open-source projects (the Linux kernel's "Assisted-by" tag, which is now contested) and from AIUC-1's coding-agent controls for agent vendors. Customer demand for code provenance is asserted only in vendor marketing.

### Cited Findings
- **NIST SP 800-218A (final, 26 Jul 2024):**
  - It is an "SSDF Community Profile" for generative AI and dual-use foundation models, adding practices "specific to AI model development". Its audience is producers of AI models, producers of AI systems that use them, and acquirers, and it is used alongside SP 800-218. — [NIST CSRC](https://csrc.nist.gov/pubs/sp/800/218/a/final), [NIST news](https://csrc.nist.gov/news/2024/nist-publishes-sp-800-218a) [search summary]
  - The nist.gov page shows an update on 25 Jun 2025. — [search summary]
- **SSDF v1.2 draft (SP 800-218 Rev. 1 initial public draft, 17 Dec 2025, in response to EO 14306):**
  - A third-party blog says it borrows tasks from 800-218A. v1.1 remains the final version. — [NIST CSRC draft](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd), [NIST news](https://csrc.nist.gov/News/2025/draft-ssdf-version-1-2) [search summary]
- **OMB M-26-05 (23 Jan 2026):**
  - It rescinded M-22-18 and M-23-16. Agencies "are no longer required" to use the Common Form (the attestation form). They may use it, require an SBOM, or rely on other guidance such as SP 800-218.
  - OMB called the old regime "unproven and burdensome software accounting processes".
  - Sources: [Wiley](https://www.wiley.law/alert-OMB-Rescinds-Secure-Software-Development-Mandate-in-Favor-of-a-Risk-Based-Approach), [Mayer Brown](https://www.mayerbrown.com/en/insights/publications/2026/02/omb-rescinds-biden-era-software-security-memoranda), [Inside Government Contracts](https://www.insidegovernmentcontracts.com/2026/02/omb-rescinds-the-common-form-secure-software-attestation-requirement/) [search summary]
- **EU CRA:** Art. 13(5) due diligence on third-party components, Art. 13(13) 10-year documentation, and Art. 13(24) SBOM format by implementing act. — [Springlex Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/) [opened]
- **AI-BOM formats:**
  - **SPDX 3.0** (released 16 Apr 2024) added AI and Dataset profiles, reportedly with 36 new fields (20 AI, 18 Dataset). — [arXiv 2510.07070](https://arxiv.org/pdf/2510.07070), [Linux Foundation AI-BOM guide](https://www.linuxfoundation.org/hubfs/LF%20Research/lfr_spdx_aibom_102524a.pdf) [search summary]
  - **CycloneDX:** the cdxgen `aibom` command generates CycloneDX AI/ML BOMs (spec versions 1.5–1.7) from source, Hugging Face references, Modelfiles or GGUF files. — [cdxgen](https://github.com/cdxgen/cdxgen) [search summary]
  - **Research proposal:** a 2026 paper proposes extending CycloneDX with "AI-specific provenance, model lineage, and disclosure metadata". — [arXiv 2605.19755](https://arxiv.org/pdf/2605.19755) [search summary]
- **Open-source provenance rules:**
  - In spring 2026 the Linux kernel added `coding-assistants.rst` — [It's FOSS](https://itsfoss.com/news/linux-ai-coding-assistants-policy/), [Gigazine](https://gigazine.net/gsc_news/en/20260413-linux-a-generated-code-assisted-by/) [search summary]:
    - AI agents may not add Signed-off-by tags.
    - AI-assisted patches carry an "Assisted-by: AGENT_NAME:MODEL_VERSION" tag.
  - The Register later reported Maintainers Summit "consensus to deprecate the Assisted-by Tag", over objections. Whether that change has been merged is unconfirmed, so sources conflict. — [The Register](https://www.theregister.com/a/5303140) [search summary]
- **Agent-vendor certification:** AIUC-1's mandatory B010 (secure patterns in generated code, including dependency specification) and A008 (secrets kept out of generated code and logs) apply to code-generating agents. — [NYU Shanghai RITS](https://rits.shanghai.nyu.edu/ai/aiuc-1-the-ai-agent-certification-turns-to-coding-agents/) [opened]

### Inferences
- **US federal:** provenance asks for AI-written code weakened in 2026, because the attestation is now optional. Agencies that still want assurance will choose their own instruments (SBOMs, SSDF evidence). A per-change record of which agent and model wrote what, and who approved it, is SSDF-style evidence that a team can hand over on request. No rule requires it.
- **CRA:** neither the 10-year documentation duty nor the due-diligence duty mentions AI. But AI-generated code and agent-added dependencies are product content subject to those duties. Agent-proposed dependencies are where B010's "safe dependency specification" and the CRA's SBOM overlap.
- **Coding-agent provenance:** the AI-BOM formats would record a coding agent's model as a *tool*, not as a component. Provenance for coding agents is therefore likelier to live in commit trailers and change records than in an SBOM.

### Gaps
- No customer contract or procurement document was found that requires AI-authorship marking of code.
- No CycloneDX or SPDX field for "AI-generated code" was confirmed.
- The SSDF v1.2 draft's AI tasks were not read.
- Other open-source policies (Fedora, Gentoo, NetBSD, QEMU) were not verified this round.
- CISA AI-SBOM work was not researched.

## 7. What evidence satisfies these asks, and what retention they imply

### Takeaway
Most asks are satisfied today by **documents**:
- an AI use policy;
- an inventory of AI tools and models, with their data-handling terms;
- AI training records;
- human approval on PRs.

**Records of agent runs** are requested in narrower but growing cases:
- per-inference logs with tool calls (SOC 2 auditors of AI products);
- change logs with the reason and the approver (Microsoft, 90 days);
- tool-call and activity logs (AIUC-1);
- tracking of agent actions (FINRA guidance);
- administrative-action logs (PCI, 12 months);
- the ability to reconstruct failures for incident duties (Microsoft, GSA, CRA).

Retention runs from **90 days to 12 months** for operational logs, **at least 6 months** for EU AI Act high-risk logs from December 2027 (prior round), and **10 years** for CRA technical documentation. DORA and ISO 42001 leave the period to the organization.

### Cited Findings
- **Policies:**
  - 3 of 20 AI-mentioning OCGs require the firm's own AI policy. — [Fulkerson](https://www.fulkersonadvisors.com/research/ai-in-outside-counsel-guidelines) [opened]
  - Microsoft requires a document describing the Responsible AI program and who is accountable (Req. 56). — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
  - Vanta says only 36% of organizations have, or are putting in place, an AI policy (vendor-run). — [BusinessWire](https://secure.businesswire.com/news/home/20250424580132/en/Setting-the-Standard-for-AI-Compliance-Vanta-Introduces-AI-Security-Assessment) [search summary]
- **Tool inventories and disclosure:**
  - AI addenda ask for a list of AI systems in use and 60 days' notice of new ones. — [No Jitter](https://www.nojitter.com/data-governance/have-a-saas-contract-in-place-you-may-need-an-ai-addendum) [search summary]
  - Microsoft requires transparency disclosures and notice when Intended Uses change (Reqs. 51, 54, 61). — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
  - DoD contractors must "audit [their] use of any covered AI" (second-hand). — [Petronella](https://petronellatech.com/blog/deepseek-and-the-fy2026-ndaa-what-dod-contractors-need-to-know/) [search summary]
  - The draft SOC 2 points of focus include controls against unsanctioned AI tools. — [Elevate Consult](https://elevateconsult.com/insights/soc-2-trust-services-criteria-2027/) [opened]
  - A freelancer guide proposes "a tool log plus assurances about the tool's data-retention controls" to satisfy code clients. — [Delivvo](https://delivvo.io/blog/anti-ai-contract-clauses-freelancers-2026) [search summary]
- **Logs of agent activity:**
  - **SOC 2 (CSA note):** model version, a redacted prompt or prompt hash, tool calls, and outcome. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/) [opened]
  - **FINRA:** prompt and output logs, model version, and tracking of agent actions and decisions. — [FINRA](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) [opened]
  - **ISO 42001 audits:** logs that connect an action to an actor, resource, time and activity, with actors that include agents. — [Teleport](https://goteleport.com/blog/iso-42001-audit-evidence/) [opened]
  - **AIUC-1 E015:** activity logs, plus tool-call logging that includes the MCP tool name and inputs. — [myctrl.tools](https://myctrl.tools/frameworks/aiuc-1/e015), [Morphisec](https://www.morphisec.com/?p=11269) [search summary]
  - **PCI 10.2.1.2:** all administrative actions, including interactive use of system accounts. — [Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/02/01/02/) [opened]
  - **DORA:** change and access events, protected against tampering. — [Springlex](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-12/) [opened]
  - **HIPAA:** mechanisms that "record and examine activity". — [Cornell LII](https://www.law.cornell.edu/cfr/text/45/164.312) [opened]
- **Approvals and human review:**
  - **SOC 2 change management:** PR approvals, CI results and branch protection, with a human kept at push-to-production (A-LIGN, relayed second-hand). — [Vanta Community](https://community.vanta.com/x/grc/nwnr9uwkwu1y/ai-only-code-reviews-and-soc-2-change-management-e) [opened]
  - **Microsoft change logs:** must name the approver's name and title. — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
  - **Zscaler's OCG:** a human attorney reviews AI work product. — [Fulkerson](https://www.fulkersonadvisors.com/research/ai-in-outside-counsel-guidelines) [opened]
  - **PCI 6.2.3.1:** an independent reviewer plus management approval. — [Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/06/02/03/) [search summary]
  - **ISO 42001 A.9.3:** sign-off, plus records of overrides and stops. — [Teleport](https://goteleport.com/blog/iso-42001-audit-evidence/) [opened]
- **Attestations and certifications:**
  - A SOC 2 report whose system description includes AI. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/) [opened]
  - An AI-CAIQ self-assessment or STAR for AI. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-aicm-v1-1-update-20260730-csa-styled/) [opened]
  - ISO 42001 certification (271 certificates worldwide). — [DQS](https://www.dqsglobal.com/es/acerca-de/sala-de-prensa/iso-survey-2025-las-certificaciones-iso-crecen-un-11-en-el-mundo-y-un-28-en-espana) [opened]
  - Microsoft SSPA independent assessment, or ISO 42001 in its place. — [CSA blog](https://cloudsecurityalliance.org/blog/2024/10/16/an-overview-of-microsoft-dpr-its-new-ai-requirements-and-iso-42001-s-potential-role) [search summary]
  - AIUC-1 certification. — [NYU Shanghai RITS](https://rits.shanghai.nyu.edu/ai/aiuc-1-the-ai-agent-certification-turns-to-coding-agents/) [opened]
  - The CISA attestation form, now optional. — [Inside Government Contracts](https://www.insidegovernmentcontracts.com/2026/02/omb-rescinds-the-common-form-secure-software-attestation-requirement/) [search summary]
- **Exportable reports and incident evidence:**
  - **Microsoft:** an AI incident plan with rollback and feature-off times, logs of failures, hallucinations and misuse, and "processes for reproducing system failures". — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
  - **GSA:** incident notice can be met by FedRAMP or CISA reports that contain substantially the same information. — [Crowell](https://www.crowell.com/en/insights/client-alerts/gsa-issues-final-rule-on-large-language-model-procurements) [opened]
  - **Drata Trust Center:** used to share AI governance documentation with buyers. — [Drata](https://drata.com/blog/introducing-aiuc-1) [opened]
- **Retention:**
  - **PCI DSS 10.5.1:** at least 12 months, with the most recent 3 months immediately available. — [Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/05/01/) [opened]
  - **Microsoft change logs:** the past 90 days available on request. — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
  - **DORA:** the entity sets the period. — [Springlex](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-12/) [opened]
  - **ISO 42001:** no minimum. — [Freshfields](https://technologyquotient.freshfields.com/post/102jcog/eu-ai-act-unpacked-10-iso-42001-a-tool-to-achieve-ai-act-compliance) [search summary]
  - **AIUC-1 E015.2:** "appropriate retention periods", with no number. — [myctrl.tools](https://myctrl.tools/frameworks/aiuc-1/e015) [search summary]
  - **CRA:** technical documentation kept 10 years or the support period, whichever is longer. — [Springlex](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/) [opened]
  - **CRA reporting:** within 24 hours from 11 Sep 2026. — [Jones Day](https://www.jonesday.com/en/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026) [search summary]
  - **Buyer expectations (vendor claim, unsourced):** "ninety days of documented evidence" of output controls. — [Aetos](https://www.aetos-data.com/answers-insights/enterprise-security-ai-questionnaires) [opened]

### Inferences
- **What a record of agent work can and cannot do:** it cannot replace policies, training records, contracts or risk assessments. It can be the single source for:
  - the **inventory** (which harnesses and models actually ran, under which identity);
  - the **change log** (what changed, why, and who approved it, which matches Microsoft Req. 33 field for field);
  - **per-run activity logs** (tool calls and outcomes, hashed or redacted prompts);
  - **incident reconstruction** (Microsoft's "reproducing system failures", the GSA notice, CRA reporting);
  - **per-matter disclosure** (OCG time-entry notes).
- **Retention:** a default of **at least 12 months, with 90 days hot**, covers PCI 10.5.1 and Microsoft Req. 33, and exceeds the EU AI Act floor for high-risk systems. It also matches the observation window of a SOC 2 Type II report (assumed, not sourced). Longer, configurable retention is needed for CRA-style product documentation (10 years), which points to exportable summaries rather than raw logs.
- **Content:** asks consistently favor attribution (actor, agent, approver, time, resource, tool) over raw content, and accept hashed or redacted prompts. A metadata-first, tamper-evident record under customer keys fits the evidence better than a transcript archive, which would itself become client-confidential data subject to OCG, FDIC-style and GSA handling terms.

### Gaps
- Not verified: the typical SOC 2 Type II observation period, HIPAA's six-year documentation retention, FINRA and SEC books-and-records periods, and NIS2 CIR log retention.
- No source specifies a minimum *field set* for an agent-run record beyond the CSA, Microsoft and AIUC-1 items listed above.

## 8. The trigger: are small and mid-size engineering teams actually being asked, and how strong is the evidence for "a client or auditor asks what agents touched"?

### Takeaway
The evidence supports a **softer and later** trigger than the hypothesis:
- **Today:** small and mid-size vendors are being asked *whether and how* they use AI: which tools, whether data flows to them, and whether AI output gets human review. SOC 2 auditors are starting to ask how AI-authored changes are approved.
- **Missing:** I found almost no evidence that clients or auditors yet ask for a **record of what agents touched**. Those asks exist mainly for AI products and business agents (per-inference logs, FINRA agent tracking, AIUC-1), in Microsoft's supplier program, and when teams try to remove human code approvers.
- **When it hardens:** in 2027–2028:
  - AICPA criteria for engagements from 31 Dec 2027;
  - EU AI Act high-risk logging from December 2027;
  - most CRA obligations from December 2027.
- **SMB prevalence:** there is no data on prevalence for SMBs, and no Hacker News thread or founder post describing the trigger was found.

### Cited Findings
- **Evidence for an AI-use trigger reaching SMB vendors:**
  - Vanta's AI assessment, sent through customers' vendor risk management, covers vendors with "software built with AI". — [Vanta](https://www.vanta.com/resources/introducing-vantas-ai-security-assessment) [opened]
  - SIG 2026 has an AI domain. — [Vorp Labs](https://vorplabs.com/security-framework-changes/sig) [search summary]
  - HECVAT 4 has an AI worksheet. — [SaltyCloud](https://www.saltycloud.com/blog/hecvat-v3-05-whats-changed) [search summary]
  - The AI-CAIQ has 320 questions. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-aicm-v1-1-update-20260730-csa-styled/) [opened]
  - GRC vendors market AI-questionnaire answering as the remedy for stalled reviews ("Security reviews stall"; vendor). — [Drata](https://drata.com/blog/introducing-aiuc-1) [opened]
  - Microsoft's DPR applies to any supplier that uses AI Systems in performance. — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
- **Evidence for an auditor trigger on agent-authored change:**
  - A June 2026 practitioner thread asks how to evidence AI-only review. A-LIGN reportedly expects a human at push-to-production, plus evidence on agent access, drift monitoring and CI/CD configuration. — [Vanta Community](https://community.vanta.com/x/grc/nwnr9uwkwu1y/ai-only-code-reviews-and-soc-2-change-management-e) [opened]
  - CSA documents auditors improvising, and an "accountability gap" when agents act without a human request. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/) [opened]
  - The AICPA draft adds AI points of focus. — [AICPA](https://www.aicpa-cima.com/news/article/aicpa-proposes-update-of-soc-2-r-trust-services-criteria-to-enhance-the-relevance-usability-and-value-of-cpas-reports) [opened]
- **Evidence for an asset or log trigger in regulated and agent-vendor contexts:**
  - FINRA: "how to track agent actions and decisions". — [FINRA](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) [opened]
  - AIUC-1: logging of tool calls, and coding-agent requirements. — [NYU Shanghai RITS](https://rits.shanghai.nyu.edu/ai/aiuc-1-the-ai-agent-certification-turns-to-coding-agents/) [opened]
  - Microsoft: change logs with approver, retained 90 days. — [Microsoft DPR v12](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/accex/documents/presentations/FY26-Microsoft-Supplier-Data-Protection-Requirements-v12_en-US.pdf) [opened]
- **Evidence against, or limits:**
  - 98% of public outside-counsel guidelines say nothing about AI. — [Fulkerson](https://www.fulkersonadvisors.com/research/ai-in-outside-counsel-guidelines) [opened]
  - The cyber forms checked contain no AI questions. — [Nonimo](https://nonimo.ai/resources/guides/cyber-insurance-questionnaire-ai-questions/) [opened]
  - Generative and agentic AI are outside SR 26-2. — [SR 26-2 attachment](https://www.federalreserve.gov/supervisionreg/srletters/SR2602a1.pdf) [opened]
  - Contractor-optional AI is outside M-25-22. — [OMB M-25-22](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf) [opened]
  - GSA's clause self-deletes for incidental LLM use. — [Crowell](https://www.crowell.com/en/insights/client-alerts/gsa-issues-final-rule-on-large-language-model-procurements) [opened]
  - CSA's SOC 2 note does not mention AI coding tools at all. — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/) [opened]
  - No independent statistic on how often AI questions appear exists. Vanta's figures are vendor-run, and Gartner's are predictions. — [RiskRecon](https://blog.riskrecon.com/5-key-takeaways-from-gartner-predicts-2026) [search summary]
- **Hacker News and founders:**
  - Searches restricted to news.ycombinator.com found general threads about security questionnaires and AI code-review tools, but **no thread about customers asking about AI or agent use in security reviews**. — [HN: AI-assisted code review tools](https://news.ycombinator.com/item?id=48587808), [HN: SOC 2 as a solo founder](https://news.ycombinator.com/item?id=48145524) [search summary]
  - The HN search summary attributed the remark that without SOC 2 "you will be asked to fill out an insane 200+ questionnaire" to a SOC 2 thread; the attribution to the solo-founder thread above is my guess.
  - The search tool could not reach Reddit.

### Inferences
- **Strength of evidence:**
  - **"Clients ask whether and how you use AI":** moderate to strong. It is built into the standard questionnaires (SIG, AI-CAIQ, HECVAT, Vanta) and into at least one major supplier program (Microsoft). How often SMBs actually receive these questions is unmeasured.
  - **"Auditors ask how AI-authored changes are approved":** moderate. It is documented for teams pushing toward AI-only review, and is about to be codified (the AICPA draft, effective late 2027 or earlier by choice).
  - **"Clients or auditors ask what agents touched":** weak today for teams that only use coding agents. It is stronger for teams that ship agents (AIUC-1, per-inference logs), sell to Microsoft (DPR change logs and failure logs), or work in PCI, HIPAA or DORA environments where agents hold administrative access.
- **A sharper beachhead than "the first questionnaire"** would be any of:
  - a team whose first SOC 2 Type II under the 2027 criteria includes AI points of focus;
  - a Microsoft supplier filling in DPR Section K;
  - a team removing human approval for some change tiers;
  - a fintech or health vendor whose agents act on in-scope production systems.
- **Hypothesis versus evidence:** the hypothesis holds that a questionnaire or SOC 2 request asks "what did agents touch". The evidence says the first ask is usually "what AI do you use, and does a human review it". A tool inventory and approval record compiled from real agent runs would answer that first ask, and the same data would grow into the "what did agents touch" ask as it hardens in 2027–2028.

### Gaps
- No GRC-vendor dataset (Vanta, Drata, Conveyor, Whistic, SafeBase) on how often AI or agent questions appear in inbound questionnaires was found. This is the single most useful missing data point.
- No primary founder posts or HN or Reddit threads describing the trigger were found; Reddit was unreachable.
- No buyer-side policy (bank, insurer, enterprise TPRM) was found that asks vendors for agent-run records.
