# Branch 1.06 synthesis: competitive moves since September 2026, open standards for agent activity records, and how security reviewers treat host-blind hosting (as of 1 November 2026)

## About this synthesis

- **What the branch contains.** Two notes files, both read in full:
  - **Level 1, node 1.6:** [`L1-1.06-competitive-refresh-and-standards.md`](L1-1.06-competitive-refresh-and-standards.md). It asks four questions:
    1. Which competitor moves between September and November 2026 overlap pitch4?
    2. Does any product combine customer-held keys, capture across harnesses, and signed records?
    3. Where do open standards for agent activity records stand?
    4. What would make the sidecar clearly different from the three strongest threats?
  - **Level 2, node 2.05,** opened jointly by 1.6, 1.9 and 1.7: [`L2-2.05-how-do-security-reviews-and-third-party-risk-pro.md`](L2-2.05-how-do-security-reviews-and-third-party-risk-pro.md). It covers:
    - how third-party-risk programs tier a vendor that holds only ciphertext, or that ships software the customer self-hosts;
    - which attestations close deals;
    - whether reviewers tell host-blind encryption apart from vendor-held CMEK;
    - how often comparable buyers self-host.
- **Depth.** No level-3 or level-4 note in this folder names 2.05 as its parent, so the branch ends at level 2.
  - Level 2 followed up one of level 1's six open questions: host-blind versus CMEK.
  - This branch did not follow up the other five: the IETF AUDIT outcome, the AAIF route, Block's plans, Tailscale's plans, and what SIEMs and auditors ingest. They remain open (section 4).
- **Conventions.**
  - Every factual claim below comes from the two notes files, and every link is one the notes use.
  - Labels carried over from the notes:
    - "(vendor claim)": a company's statement about itself.
    - "(secondary)": press or another third party.
    - "(search summary)": the page was seen only in a search engine's summary.
    - "(GitHub API, 1 Nov 2026)": stars and dates pulled that day. Stars measure attention, not use.
  - "[inference]" marks reasoning, by the notes or by this synthesis, rather than a sourced fact.
  - Hacker News (HN) counts are counts of distinct commenters. They show which claims people make, not how common each view is.
- **Relation to earlier research.**
  - `market2.md` already argued that tamper-evidence alone cannot differentiate the sidecar, citing Obsigna and "dozens of IETF receipt drafts". It also already listed OTel, SIEM and SCITT/COSE exports.
  - This branch adds dated evidence that settles the first point.
  - It gives the exports a concrete route through named standards bodies.
  - It adds the first evidence in this effort on how security reviewers treat host-blind hosting.

## 1. What the branch found

### Short version

1. **Three moves press hardest on pitch4:**
   - Block's open-source Buzz, now a signed workspace that runs several harnesses;
   - Tailscale's push into agent reach and private model access;
   - the harness vendors' own records, led by Anthropic: Compliance API coverage of Claude Code is generally available, CMEK covers its transcripts, and there is a self-hosted gateway.

   Each covers one layer of what pitch4 promises. None ties the layers together.
2. **No product combines all three properties.** The branch found none with host-blind keys, capture across harnesses, and signed records together.
   - Signing alone is now a commodity.
   - CMEK lets the vendor read the data while the key is enabled.
3. **No standard for agent activity records exists.**
   - The AAIF's Observability & Traceability working group names the exact profile that is missing.
   - OTel has ruled integrity out of its GenAI conventions.
   - OCSF 1.9 already carries signed, chained AI-agent events for SIEMs.
   - The IETF AUDIT BoF meets on 17 Nov 2026, with about two dozen competing drafts and none adopted.

   The opening is for a profile that composes these standards and has real users behind it, not for a new format.
4. **Level 2: blind hosting shortens the review but does not lower the tier.**
   - Hosted blind does not lower the sidecar's vendor-risk tier. Tiers follow the vendor's worst attribute, and the sidecar's worst is system access: a process on endpoints, network paths per agent, and a gate on model access.
   - It does shorten the data-handling part of a review.
   - It is a recognized EU transfer safeguard, which vendor-held CMEK is not.
   - Reviewers can tell blind hosting from CMEK when the question is put in the terms used by the Cloud Security Alliance (CSA) and the EDPB.
   - No evidence was found that buyers pay more for blindness alone. Key control is sold inside top-tier bundles.
   - Every end-to-end-encrypted vendor checked still holds SOC 2 or ISO 27001.
   - A SOC 2 Type 1, or a contract promise of one, opens first deals. Larger buyers expect Type II.
5. **The defensible core**, as the branch states it, is one record per run that:
   - binds the person's approval, the action, the file change set, the network grant, and the model that served the call;
   - is captured outside any single harness;
   - is held under keys the host never holds;
   - states what it could not see;
   - exports in standard formats.

### 1.1 Competitive moves, September to November 2026 (level 1)

**Block's Buzz is now the nearest open rival on the ledger, not only on coordination.**
- What Buzz does:
  - Its README says: "It's a Nostr relay: every message, reaction, workflow step, review approval, and git event is a signed event in one log", and "Agents have their own keys, their own channel memberships, and their own audit trail." — [block/buzz README](https://github.com/block/buzz)
  - Working today: the "ACP harness (Goose, Codex, Claude Code)". Still being wired: "Workflow approval gates (infra exists, glue still drying)". — same source
  - For telemetry, memory and cost records, the server "sees routing metadata, not those payloads". — [Block engineering blog](https://engineering.block.xyz/blog/buzz) (vendor claims)
- Momentum:
  - 36,652 stars, Apache-2.0. Desktop v0.5.28 (9 Oct 2026) raised the hosted community limit to fifty and added an Admin Console. — [Buzz releases](https://github.com/block/buzz/releases/tag/desktop-v0.5.28) (GitHub API, 1 Nov 2026)
  - goose, now at `aaif-goose/goose`, has 56,074 stars and has shipped weekly since September. — [goose releases](https://github.com/aaif-goose/goose/releases)
- Limits Block itself documents in [ARCHITECTURE.md](https://github.com/block/buzz/blob/main/ARCHITECTURE.md):
  - "The relay is the single source of truth", with Postgres full-text search over stored events.
  - The audit hash chain records 10 workspace actions (events, channels, members, auth, rate limits). It does not record tool calls, file changes or network use.
  - Runs that hit an approval gate "are marked as failed" (WF-08).
  - No pull request merged since 1 Sep 2026 adds content encryption. — [GitHub search](https://github.com/block/buzz/pulls?q=is%3Apr+is%3Amerged+approval)
- [inference, level 1] Sessions a developer runs in their own terminal or IDE, outside Buzz, are not captured.
- Pitch4 misdescribes Buzz as "over iroh". Buzz is a Nostr relay; iroh carries only its pooled-compute feature, MeshLLM. — [iroh blog](https://www.iroh.computer/blog/buzz-agent-workspaces)

**Tailscale moved into agent reach and private model access.**
- Meta's Muse agent — [Tailscale, Muse](https://tailscale.com/blog/meta-muse-ai-agent-tailscale):
  - It joins the tailnet as its own node, so grants and tags apply.
  - It "requires explicit confirmation the first time it connects to any tailnet device", and access can be standing or one-time.
  - The post restates that Aperture is generally available and that Tailscale and Tailscale SSH can be MCP endpoints.
  - It does not mention logging.
- Sovereign AI — [Tailscale, sovereign AI](https://tailscale.com/blog/sovereign-ai-patricia-prewitt) (vendor claims):
  - "Tailscale is making a multi-million-dollar, multi-year investment in sovereign AI", and has named a General Manager of Sovereign AI.
  - "Tailscale isn't going to build models, GPUs, or datacenters."
  - The post makes no logging or audit claims.
- Tailscale PAM (beta) records sessions — [Tailscale, PAM](https://tailscale.com/blog/what-is-tailscale-pam):
  - Recordings are "generally saved and stored in Tailscale-managed storage", or in S3 on Premium.
  - The post says nothing about encryption keys, AI agents or human approval.
- Also in the window: "Codex Cloud shipped with Tailscale support. Nobody told us." (6 Oct). — [Tailscale blog RSS](https://tailscale.com/blog/index.xml)

**Harness vendors hardened their own records.**
- **Anthropic:**
  - Compliance API coverage of Claude Code (CLI and desktop) is generally available. It excludes Claude Code on the web, Claude Code through the Claude Platform, and sessions on Bedrock, Vertex AI and Foundry. — [Claude blog](https://claude.com/blog/compliance-api-cowork-and-claude-code)
  - CMEK covers "Claude Code on the CLI, including message content" and Compliance API local session transcripts. — [CMEK coverage](https://platform.claude.com/docs/en/manage-claude/cmek-coverage-claude-enterprise)
  - Turning CMEK on turns off Claude Code on the web ("New sessions can't be started"), Claude in Slack, Claude Security (beta) and routines. — same source
  - The vendor uses the key: "Anthropic uses it to encrypt certain data at rest", and "While the key is disabled, Claude can't read that data". — [CMEK](https://platform.claude.com/docs/en/manage-claude/cmek)
  - The self-hosted Claude apps gateway connects only to Claude providers: Bedrock, Claude Platform on AWS, Google Cloud's Agent Platform, Microsoft Foundry and the Anthropic API. — [Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway)
- **Claude Code approval telemetry grew** — [Claude Code changelog](https://code.claude.com/docs/en/changelog) (only 15–31 Oct was read):
  - 2.1.301 (15 Oct): `classifier_verdict` and `permission_mode` added to OTel `tool_decision` events.
  - 2.1.304 (19 Oct): `decider: "person"`, so "only the permission dialog or a host's callback can approve the ask".
  - 2.1.309–2.1.310 (22–23 Oct): fixes for Windows `PreToolUse` and `PermissionRequest` hooks "failing open".
- **Cursor**, owned by SpaceX since 14 Aug 2026 per [Wikipedia](https://en.wikipedia.org/wiki/Cursor_(company)) (secondary) — [Cursor Docs](https://cursor.com/docs/cloud-agent/security):
  - CMEK/BYOK for Cloud Agent server-side encryption;
  - audit logs that can stream to a SIEM, a webhook or S3;
  - conversation state "Kept indefinitely by default".
- **GitHub** (Universe, 28 Oct):
  - Copilot Memory is generally available. It is built partly from agent conversations and works on Copilot surfaces only. — [GitHub Changelog](https://github.blog/changelog/2026-10-28-github-intelligence-puts-your-code-context-and-history-to-work)
  - Local models are an "opt-in experimental preview", and routing decisions are still made in the cloud. — [GitHub Changelog](https://github.blog/changelog/2026-10-28-github-copilot-fusion-now-supports-selection-of-local-models)

**Smaller moves that overlap specific pitch4 pieces.**
- **nono** (4,791 stars, Apache-2.0):
  - Offers "Cryptographic audit", rollback and egress control across eight named agents. — [nolabs-ai/nono](https://github.com/nolabs-ai/nono)
  - Keeps a Merkle root per session with an optional DSSE signature, and audit entries from its network proxy. — [nono audit docs](https://nono.sh/docs/cli/features/audit)
  - Records stay on the host, and no encryption is described.
  - Without an external anchor, the attestation "remains host-local attestation material".
- **Agent Receipts / Obsigna:**
  - Signs Claude Code `Edit` and `Bash` calls through a PostToolUse hook, and can seal disclosures with HPKE to a "forensic key". — [Agent Receipts blog](https://agentreceipts.ai/blog/attribution-over-undo/)
  - 20 stars. — [obsigna](https://github.com/agent-receipts/obsigna)
- **Priced receipt products** — [provenant #168](https://github.com/JaredKlopstein/provenant/issues/168) (secondary; an AI-generated map, unverified):
  - Asqav Pro $39 a month;
  - AI Identity Pro $79 a month;
  - agent-custody $50 a month for 1M appends;
  - Pipelock Enterprise $25,000 a year.
- **JetBrains Air Governance:**
  - Sets organization policy on "allowed MCP servers, agents, and LLMs", plus spending limits and adoption analytics. — [JetBrains docs](https://www.jetbrains.com/help/air/air-governance.html.md)
  - Mentions no audit logs, session records or approvals.
  - Works with ACP agents, per [Techzine](https://www.techzine.eu/news/devops/145229/jetbrains-releases-air-governance-for-ai-management/) (search summary).
- **Keycard for Code** — [Keycard](https://keycard.ai/keycard-for-code/) (vendor claim):
  - Wraps any harness (`keycard run -- claude`), with 15-minute credentials and a per-session allow/deny event log.
  - Does not say where the logs live or whether they are signed.
- **Span** — [Span](https://www.span.app/) (vendor claims):
  - Audits "every read of trace content".
  - Installs its recorder through MDM, and holds SOC 2 Type II.
  - Mentions no customer-managed keys, no self-hosting and no approval capture.
- **Cloudflare Artifacts** (open beta) persists "the code and context from agent sessions". Cloudflare makes no statement about encryption, customer keys, signing or provenance. — [Cloudflare blog](https://blog.cloudflare.com/next-git-platform-on-cloudflare/)
- **Model custody:**
  - OPAQUE's Weight Custody Manifest (WCM) keeps weights encrypted until the receiving infrastructure proves agreed conditions, with keys sealed to an attested workload. — [Help Net Security](https://www.helpnetsecurity.com/2026/09/10/weight-custody-manifest-open-standard/) (secondary)
  - The AAIF blog calls WCM "one proposed approach, published as an open, pre-1.0 specification" that "remains a design under review". — [AAIF blog](https://aaif.io/blog/before-an-agent-uses-a-model-verifying-model-custody-on-customer-infrastructure)
  - The WCM repo has 7 stars. — [repo](https://github.com/agentrust-io/weight-custody-manifest)
  - Tinfoil binds a public commitment to the weights to an enclave's signed boot measurement. — [Tinfoil](https://tinfoil.sh/blog/2026-02-03-proving-model-identity) (search summary, vendor claim)
- **Money:**
  - Factory raised $200M at a $5B valuation (about 15 Sep). — [AIwire](https://www.hpcwire.com/aiwire/2026/09/15/factory-raises-200m-at-5b-valuation-to-scale-enterprise-software-platform/) (search summary, secondary)
  - No September–October rounds were found for Mem0, Letta, Zep, Keycard or Aembit. — [mnemoverse](https://mnemoverse.com/docs/library/ai-memory-solutions-2026-q3) (secondary); [CB Insights](https://www.cbinsights.com/company/keycard) (search summary)
  - On 4 May 2026, Cisco announced its intent to acquire Astrix "for approximately $400 million". — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons/)

### 1.2 Who combines customer-held keys, capture across harnesses, and signed records (level 1)

| Property | Who has it now | What is missing |
|---|---|---|
| Customer-managed keys | Anthropic (Claude Code CLI transcripts), Cursor (Cloud Agent) | The vendor decrypts while the key is enabled ([CMEK](https://platform.claude.com/docs/en/manage-claude/cmek); [Cursor](https://cursor.com/docs/cloud-agent/security)) |
| Payloads encrypted from the relay | Buzz, for memory, cost and telemetry | The relay stores and indexes channel content ([ARCHITECTURE.md](https://github.com/block/buzz/blob/main/ARCHITECTURE.md)) |
| End-to-end-encrypted sync across harnesses | claude-mem (108,816 stars), as a PR still unmerged on 1 Nov | Unsigned ([PR #4259](https://github.com/thedotmack/claude-mem/pull/4259)) |
| Signed records | Buzz, nono, Obsigna, priced receipt startups | Each covers one layer or one machine |
| Capture across harnesses | Span, Entire, claude-mem, LoongSuite Pilot, Keycard, nono, Buzz through ACP | Readable by the operator, or limited to one machine |

- Level 1's verdict: "No product found offers all three together", and "Nothing hosted that the operator cannot read was found."
- The closest combinations:
  - Self-hosted Buzz: signed, runs several harnesses, partly encrypted. But it covers workspace events, not harness actions.
  - claude-mem, if its encrypted-sync PR merges.
- [inference, level 1] Signing alone "cannot carry pitch4's differentiation". The combination nobody offers is "hosted, cross-harness, host-blind, and binding approvals to actions, file changes and reach in one record".

### 1.3 Open standards for agent activity records (level 1)

- **OpenTelemetry.**
  - The GenAI conventions have no release. — [semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai)
  - Integrity was ruled out of GenAI scope: "not necessarily in the scope of GenAI semantic conventions, but it is in scope of OpenTelemetry in general". — [#438](https://github.com/open-telemetry/semantic-conventions-genai/issues/438)
  - Authorization moved to the core conventions. — [#461](https://github.com/open-telemetry/semantic-conventions-genai/issues/461)
  - A maintainer asked that a proposal "be supported by some commonly used frameworks", and called the cited implementations closed-source, dead or "pet projects". — [#470](https://github.com/open-telemetry/semantic-conventions-genai/issues/470)
  - Approval capture is still open. Ten distinct people are converging on approval as "a pre-execution control state, not a tool execution result", recorded with an opaque actor field (`decision_actor_ref` or `approval_actor_ref`). — [#95](https://github.com/open-telemetry/semantic-conventions-genai/issues/95)
  - The Audit Logging SIG has been only a proposal since 24 Oct 2024. — [community PR #2409](https://github.com/open-telemetry/community/pull/2409)
- **AAIF (Linux Foundation).**
  - The foundation has 10 hosted projects after 22 Oct 2026, and none is an activity-record format. — [LF press release](https://www.linuxfoundation.org/press/agentic-ai-foundation-announces-four-new-projects-agent-skills-open-responses-openenv-and-opensandbox)
  - The Observability & Traceability working group: chair from Cisco, vice chair from Datadog, 254 active members, weekly meetings, no deliverables listed. — [WG page](https://aaif.io/working-groups/observability-traceability)
  - Its execution plan — [execution plan](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/AGENT-BEHAVIOR-TRACE-MODEL-EXECUTION-PLAN.md):
    - "Implement it in Goose and one independent agent or SDK."
    - "missing observations mean unknown, not zero or success. Observed approval is not proof of enforcement; a service-side receipt is not cryptographic attestation."
  - Its use cases name the gap — [USE-CASES.md](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/USE-CASES.md):
    - Missing: "a broadly adopted profile that combines complete agent-action coverage, approvals, trustworthy collection, retention, and trace correlation for audit use".
    - Use case E4 wants a record "resistant to modification (by the vendor, the operator, or the agent itself), independently verifiable, and time-bound".
    - Telemetry "should identify its producer and observation point".
  - An interim attestation working group is on a 90-day trial. — [minutes, 28 Oct](https://github.com/aaif/wg-observability-and-traceability/blob/main/meeting-minutes/2026-10-28.md) (machine-generated minutes)
- **IETF.**
  - The AUDIT BoF request was approved; an earlier request was declined in July. — [approved request](https://datatracker.ietf.org/doc/bofreq-kuhlewind-audit-agent-use-of-delegation-and-interaction-traceability/)
  - The session is scheduled at IETF 127 for 17 Nov 2026, 17:00 UTC. — [agenda](https://datatracker.ietf.org/meeting/127/agenda)
  - Between 1 Sep and 1 Nov 2026, 157 drafts with "agent" in the name changed. 25 match record-related keywords (a few of those are identity or terminology drafts), and none is adopted by a working group. — [datatracker query](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=agent&type=draft&time__gte=2026-09-01)
  - draft-gilda-audit-agent-audit-record-03 carries "the decision and the observed effect with a derived agreement between them" in a DSSE envelope. — [gilda](https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/)
  - draft-rampertab is "an append-only, signed record of who granted what to whom". — [rampertab](https://datatracker.ietf.org/doc/draft-rampertab-audit-agent-authority-history/)
- **OCSF 1.9.0** (3 Aug 2026) added — [OCSF 1.9.0](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0):
  - a `record_integrity` profile;
  - an `attestation` object with signatures and optional chain attributes;
  - an `ai_agent` object;
  - an optional `delegation` on the `ai_operation` profile, "linking data-plane actions to the delegated authority under which they were performed".
- **Others.**
  - W3C's agentic-integrity community group has 20 participants and one post. — [W3C AIVS CG](https://www.w3.org/community/aivs/)
  - CycloneDX's behavior-evidence issue is open, and v2.1 has been "briefly discussed". — [#1015](https://github.com/CycloneDX/specification/issues/1015)
  - SPDX 3.1 is at RC1. — [spdx-spec](https://github.com/spdx/spdx-spec/releases)
  - The ACP registry is live, and no foundation governs ACP. — [Zed](https://zed.dev/blog/acp-registry) (search summary)
- [inference, level 1] There is an opening, "but for a profile that composes these standards and ships with real adoption, not for a new format". Level 1 recommends a home for each piece:

  | Piece | Home |
  |---|---|
  | Semantics | AAIF working group |
  | Attribute names | OTel GenAI SIG, through the working group |
  | Signed envelope | IETF AUDIT if it is chartered; until then, receipts compatible with COSE/SCITT (RFC 9942/9943) |
  | SIEM export | OCSF 1.9 |
  | Model identity | CycloneDX, WCM or OpenSSF Model Signing |

### 1.4 How security reviews treat a host-blind or self-hosted vendor (level 2)

**Tiering follows the worst attribute.** None of the methods found has an attribute for "the vendor holds no keys".
- UpGuard tiers on "data access, operational continuity, regulatory mandates, strategic exposure, and security resiliency", and advises: "Score what the vendor can touch and how badly operations fail if it drops." — [UpGuard](https://www.upguard.com/blog/what-is-vendor-tiering.md) (vendor content)
- Vanta's inherent risk uses "data sensitivity, access level, and business criticality". — [Vanta Help](https://help.vanta.com/en/articles/11345560-configuring-inherent-risk-scoring)
- Vanta's own vendor program counts "Integration with production environments". — [Vanta, Security](https://www.vanta.com/company/security)
- ProcessUnity scores the vendor's importance and the data shared. — [ProcessUnity](https://www.processunity.com/third-party-risk-management-platform/inherent-risk/)
- NIST groups suppliers by importance, not by data. — [NIST SP 800-161r1-upd1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-161r1-upd1.pdf)

**Regulators keep a host without keys in scope, with lighter duties.**
- HHS — [HHS via Wayback](https://web.archive.org/web/20251231073222/https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html):
  - "Lacking an encryption key does not exempt a CSP from business associate status".
  - Duties are "flexible and scalable" for "no-view services".
  - A breach of encrypted data falls in the safe harbor.
- EDPB — [EDPB Recommendations 01/2020](https://www.edpb.europa.eu/system/files/2021-06/edpb_recommendations_202001vo.2.0_supplementarymeasurestransferstools_en.pdf):
  - Encryption is an effective transfer safeguard when "the keys are retained solely under the control of the data exporter" (Use Case 1).
  - Transport and at-rest encryption "do not constitute a supplementary measure ... if the data importer is in possession of the cryptographic keys" (para. 95).
- DORA's register covers "software licences" as well as cloud services. — [BAHR](https://bahr.no/newsletter/asset-management-compliance-dora-norwegian-asset-managers-must-report-their-ict-register-by-13-march-2026) (secondary)

**[inference, level 2] Verdict.**
- Hosted blind does not change the sidecar's inherent tier, because "the endpoint process and network grants score high".
- What it does do:
  - lowers residual risk;
  - shortens the data-handling part of the review;
  - counts as a recognized EU transfer safeguard, which vendor-held CMEK does not;
  - lightens HIPAA duties, though a BAA is still needed.
- The lever that could lower the hosted part's tier is to split the engagement in two:
  1. endpoint software, reviewed as a software supplier;
  2. a hosted relay that holds only ciphertext.

  UpGuard demotes a relationship that "loses privileged access".

**End-to-end-encrypted vendors pair "we can't read it" with full attestations.**
- Tailscale: "Tailscale cannot read your traffic", plus SOC 2 Type II, and "Tailscale sees your metadata, not your data". — [Tailscale Security](https://tailscale.com/security)
- 1Password: SOC 2 Type 2, four ISO certifications, and penetration-test reports in its trust center. — [1Password](https://support.1password.com/security-assessments/)
- Bitwarden: SOC 2 Type II, SOC 3, ISO 27001, HIPAA, and FedRAMP in progress. — [Bitwarden](https://bitwarden.com/compliance/)
- Tresorit: ISO 27001, and it signs BAAs. — [Tresorit](https://tresorit.com/security)
- All four are vendor claims.
- GitLab's SOC 2 and ISO 27001 cover only GitLab.com and GitLab Dedicated, not self-managed installs. — [GitLab](https://about.gitlab.com/security/)
- On HN, no commenter said self-hosting or E2EE removed the need for SOC 2. Eight vendor-side accounts presented them together (for example [HN 10509942](https://news.ycombinator.com/item?id=10509942)).

**Attestations that close deals.** 11 distinct HN practitioners said what buyers accept:
- 5 say a Type 1, a contract promise of one within about six months, or proof of being "in process" closes first deals.
  - tptacek: "Assume your SOC2 Type I report will suffice as a first attestation". — [HN 47482097](https://news.ycombinator.com/item?id=47482097)
  - Also mikeocool. — [HN 43338240](https://news.ycombinator.com/item?id=43338240)
- 7 say larger buyers expect Type II.
  - flippy_flops: "once you have SOC 2 type 2, the IT approval process is far more streamlined". — [HN 48165463](https://news.ycombinator.com/item?id=48165463)
- One person said both.
- ISO 27001 is rarely required first in North America.
- Questionnaires continue after attestation. — [HN 29099905](https://news.ycombinator.com/item?id=29099905)
- ISC2 survey (n=1,062) — [ISC2](https://www.isc2.org/insights/2025/11/2025-isc2-supply-chain-risk-survey):
  - 77% cite standards compliance as their top vendor requirement; 84% in financial services.
  - 82% of enterprise respondents are highly concerned about supply-chain risk, against 57% in small and medium organizations.

**Host-blind versus CMEK.**
- CSA (Jan 2026) — [CSA blog](https://cloudsecurityalliance.org/blog/2026/01/05/choosing-the-right-key-responsibility-model):
  - Bring-your-own-key "Does not mean the CSP cannot access your data".
  - Hold-your-own-key gives "High assurance that your CSP cannot decrypt certain data".
  - But "terms like BYOK, HYOK, and CMK do not have an agreed-upon meaning throughout the industry".
- Vendors sell the two as different products:
  - Microsoft Customer Key lets Microsoft 365 use the keys for "eDiscovery, anti-malware, anti-spam, and search indexing". — [Microsoft Learn](https://learn.microsoft.com/en-us/purview/customer-key-overview)
  - Slack EKM is an add-on for Enterprise Grid and Enterprise+, and "Org members can use Slack as normal". — [Slack Help](https://slack.com/help/articles/360019110974-Slack-Enterprise-Key-Management)
  - Google's client-side encryption is limited to top editions. — [Google](https://support.google.com/a/answer/10741897)
  - Microsoft's Double Key Encryption (DKE) targets the "Highly sensitive (about 5% of data)" class, breaks coauthoring, eDiscovery, DLP and search, and comes in E5-class licenses. — [Microsoft Learn, DKE](https://learn.microsoft.com/en-us/purview/double-key-encryption); [service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description)
- No HN comment, questionnaire or survey was found in which a buyer chose host-blind over CMEK, or paid more for it.

**Self-hosting share.** At developer-infrastructure vendors that sell both models, self-managed is still about half of revenue or more:
- GitLab: SaaS was 34% of Q2 FY2027 revenue, up 36%. — [MarketBeat](https://www.marketbeat.com/instant-alerts/transcript-gitlab-q2-earnings-call-highlights-2026-09-01/) (search summary, secondary)
- JFrog: cloud was 53% of Q2 2026 revenue and grew 53%; self-managed grew 9%. — [Nasdaq](https://www.nasdaq.com/articles/jfrog-q2-earnings-call-highlights) (search summary, secondary)
- Atlassian ends most Data Center products on 28 Mar 2029, but keeps Bitbucket and Bamboo. — [Atlassian](https://www.atlassian.com/licensing/data-center-end-of-life)
- GitLab Dedicated passed $70M ARR. (search summary, secondary)

### 1.5 Pitch4 claims the branch contradicts or weakens

| Pitch4 says (page) | What the branch found | Safer wording |
|---|---|---|
| "Approvals go dark. Nothing records who clicked 'Allow.'" (1) | Claude Code's OTel `tool_decision` events carry `classifier_verdict` and `permission_mode`. `decider: "person"` lets an organization require a person to approve ([changelog](https://code.claude.com/docs/en/changelog)) | "Approvals are recorded only as optional, unsigned, per-vendor telemetry." (level 1) |
| "Sessions vanish. Claude Code deletes them after 30 days." (1, and page 2's stat) | Compliance API coverage of Claude Code CLI and desktop transcripts is generally available, and CMEK covers those transcripts. Excluded: Claude Code on the web, through the Claude Platform, and on Bedrock, Vertex AI and Foundry ([Claude blog](https://claude.com/blog/compliance-api-cowork-and-claude-code); [CMEK coverage](https://platform.claude.com/docs/en/manage-claude/cmek-coverage-claude-enterprise)) | [inference, from level 1] Keep the 30-day local default. Add that each vendor keeps sessions only for its own product and some of its surfaces, and that the vendor can read them |
| "Reach is all or nothing today." (3) | Tailscale's Muse agent is its own tailnet node. It "requires explicit confirmation the first time it connects to any tailnet device", with standing or one-time access ([Muse](https://tailscale.com/blog/meta-muse-ai-agent-tailscale)) | [inference] Keep the Codex default quote as an example, but drop "all or nothing" as a general claim. The gap that remains: no reach product ties a connection to the harness approval and the run that used it (level 1, Tailscale limits) |
| "Block's Buzz: ... pooled spare compute, over iroh." (4) | Buzz "is a Nostr relay", and every message and approval is a signed event. iroh carries MeshLLM ([README](https://github.com/block/buzz); [iroh blog](https://www.iroh.computer/blog/buzz-agent-workspaces)) | "Block's Buzz: a self-hostable Nostr relay where every message and approval is a signed event, running Claude Code, Codex and goose through ACP; pooled compute over iroh." |
| "Agent Receipts signs tool calls, but not sessions, edits, or reach." (4) | Obsigna signs Claude Code `Edit` and `Bash` calls ([Agent Receipts](https://agentreceipts.ai/blog/attribution-over-undo/)). nono signs a per-session audit that includes network proxy events ([nono docs](https://nono.sh/docs/cli/features/audit)) | "No one signs one record across harnesses that binds approvals, file changes and network grants under keys the customer holds." (level 1) |
| "... an individual IETF draft for agent audit trails." (4) | 25 record-related agent drafts changed in two months, none adopted. The AUDIT BoF meets on 17 Nov 2026. OCSF 1.9 defines signed AI-agent events ([datatracker query](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=agent&type=draft&time__gte=2026-09-01); [agenda](https://datatracker.ietf.org/meeting/127/agenda); [OCSF 1.9.0](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0)) | "About two dozen competing IETF drafts and an approved AUDIT BoF; OCSF 1.9 for signed agent events in SIEMs." |
| "The sidecar beside the model server signs which weights it serves." (4) | WCM and Tinfoil bind weights to attested hardware ([Help Net Security](https://www.helpnetsecurity.com/2026/09/10/weight-custody-manifest-open-standard/); [Tinfoil](https://tinfoil.sh/blog/2026-02-03-proving-model-identity)) | "The record names the attested weights that served each call", with a fallback labeled as weaker (level 1) |
| "Adopting it adds no vendor that can read your agents' work" (3) | Hosted blind does not lower the vendor's inherent tier, and a host without keys is still a HIPAA business associate ([UpGuard](https://www.upguard.com/blog/what-is-vendor-tiering.md); [HHS via Wayback](https://web.archive.org/web/20251231073222/https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html)) | Say that blindness shortens the data-handling part of the review, and that the sidecar is still reviewed as software on the buyer's machines and network (level 2) |
| "Coordination across agents: ... Block's Buzz: one vendor each", and "Ahead across harnesses" (5) | Buzz runs Claude Code, Codex and goose through its ACP harness ([README](https://github.com/block/buzz)). JetBrains Air Governance sets policy over ACP agents ([Techzine](https://www.techzine.eu/news/devops/145229/jetbrains-releases-air-governance-for-ai-management/), search summary) | [inference] Buzz is not tied to one harness. Claim a lead only for runs outside Buzz, and for the record |
| "A record of agent work you can read and we cannot: No one." (5) | Self-hosted Buzz and nono already mean "only the team can read". Anthropic and Cursor sell CMEK (level 1) | "No hosted, host-blind record across harnesses." (level 1) |
| "Span keeps sessions private by access control, not keys." (5), and "every admin read is visible to the developer" (2) | The keys contrast is still accurate. But Span's audit logs include "every read of trace content" ([Span](https://www.span.app/)) | Keep the keys contrast. Drop audited reads as a point of difference |
| "Tailscale's and Cloudflare's roadmaps are the first to watch." (5) | In the window, Anthropic moved most on the record. Tailscale added reach, model access and recording, but said nothing about logs under customer keys. Cloudflare Artifacts stated no encryption model | Add the harness vendors' own records and Block's Buzz to the watch list |
| "Money is moving into this space ... Keycard ($38M), Mem0 ($24M)" (5) | No September–October rounds were found for Mem0, Letta, Zep, Keycard or Aembit. Factory raised $200M at $5B. SpaceX's acquisition of Anysphere closed. Cisco intends to buy Astrix for about $400M | Show that recent money went to harnesses and to consolidation in agent identity (level 1) |

## 2. Directions for pitch4

Summary (details follow):

| # | Direction | Pitch4 pages it changes | Effect | Confidence |
|---|---|---|---|---|
| D1 | Lead with "bound and blind", not "signed" | 1, 4, 5 | Differentiation | High (on differentiation; demand untested) |
| D2 | Answer "can the vendor decrypt?" in CSA and EDPB terms | 3, 1, 4, 5, 6 | Differentiation | Medium |
| D3 | Charge for what is hard to do blind, not for blindness | 5, 4, 6 | Offering | Medium |
| D4 | Sell the security review in two parts, with a dated attestation ladder | 6, 3, 5 | Offering | Medium |
| D5 | Publish the entry format as a profile of existing standards; offer the sidecar to the AAIF working group as its independent implementation | 4, 1, 5, 6 | Both | Medium |
| D6 | Make coverage a first-class field and a selling point | 3, 1, 6 | Offering | Medium |
| D7 | Run reach over transports teams already use; sell the grant receipt | 3, 4, 5, 6 | Both | Medium |
| D8 | Name the attested weights per call | 4, 3 | Offering | Medium |
| D9 | Target what vendor records exclude, and buyers for whom blindness decides | 5, 4, 1, 2 | Differentiation | Medium |
| D10 | Make "partner first" with Buzz concrete | 4, 5, 6 | Both | Low |
| D11 | Correct the competitive claims | 1, 3, 4, 5 | Offering | High |

### D1. Lead with "bound and blind", not "signed"

- **Pitch4 change.**
  - Page 1 (the idea): the subtitle; "How it works" ("a signed entry to the team's ledger"); and the diagram's "each way out is a scoped grant: approved, encrypted, and recorded".
  - Page 4: the "A signed record of agent work" row.
  - Page 5: the headline "The record under your keys is the product", and "The moat is time and service" ("holds a year of signed approvals").
- **What to change.**
  - Make the binding for each run the headline property. One entry ties together:
    - the person's approval;
    - the action;
    - the files it changed;
    - the network grant it used;
    - the model that served it.
  - The entry is written from outside any single harness, under keys the host never holds, and says what it could not see.
  - Keep "signed" as a property of the entry, not the selling point.
  - Restate the moat as a year of approvals bound to what they allowed, rather than a year of signed approvals.
- **Why it helps.**
  - Signing is now free in open projects and costs from $39 a month in paid ones.
  - Each strong rival covers one layer.
  - The binding is the one property that no threat offers and that the standards groups are still looking for.
- **Evidence.**
  - Signing is common:
    - every Buzz event is signed ([README](https://github.com/block/buzz));
    - nono signs a per-session audit that includes network proxy entries ([nono docs](https://nono.sh/docs/cli/features/audit));
    - Obsigna signs Claude Code `Edit` and `Bash` calls ([Agent Receipts](https://agentreceipts.ai/blog/attribution-over-undo/));
    - priced receipt products start at $39–$79 a month ([provenant #168](https://github.com/JaredKlopstein/provenant/issues/168); secondary, unverified).
  - Each threat covers one layer:
    - Buzz's audit chain covers 10 workspace actions, not tool calls, file changes or network use ([ARCHITECTURE.md](https://github.com/block/buzz/blob/main/ARCHITECTURE.md));
    - Tailscale records connections in Tailscale-managed storage, with no link to a harness approval ([PAM](https://tailscale.com/blog/what-is-tailscale-pam));
    - Anthropic's record covers Claude surfaces only, with exclusions ([Claude blog](https://claude.com/blog/compliance-api-cowork-and-claude-code));
    - nono has "a local binding without a team record" (level 1 inference).
  - The standards groups are looking for the binding:
    - the AAIF plan asks "Approvals: Which decision concerned an action, and did that action execute?" and "Effects: Which external change can be connected to that execution?" ([execution plan](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/AGENT-BEHAVIOR-TRACE-MODEL-EXECUTION-PLAN.md));
    - the AAIF's use case E3 names the gap ([USE-CASES.md](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/USE-CASES.md));
    - draft-gilda records "the decision and the observed effect" ([gilda](https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/)).
- **Counter-evidence.**
  - Self-hosted Buzz and nono already mean "only the team can read" for what they capture (level 1).
  - Level 2 found no buyer who paid more for blindness, and showed that blindness does not lower the sidecar's vendor tier. So the "blind" half earns a shorter review, not a price ([CSA](https://cloudsecurityalliance.org/blog/2026/01/05/choosing-the-right-key-responsibility-model); [UpGuard](https://www.upguard.com/blog/what-is-vendor-tiering.md)).
  - No buyer evidence was gathered on whether the binding itself sells. Level 1 called this "the largest open risk to the differentiation".
  - [inference, this synthesis] If the AAIF or the IETF standardizes the binding, others can implement it too. D5 makes that an advantage only if the sidecar is the reference implementation.
- **Cost and risk.**
  - The copy change is small.
  - Delivering the binding is the whole first release: capture from hooks, the filesystem and the sidecar's own traffic, plus grants and model identity, in one entry.
  - Block could wire its approval gates (WF-08) and add harness capture. Level 1 found no statement of Block's plans either way.
- **Test.**
  - In design-partner security reviews, show one sample entry for a run and ask the reviewer which existing tool gives the same record.
  - Record whether they name Buzz, nono, the Compliance API, or nothing.
  - Record whether their questions are about the binding or about the signature.
  - Pair this with pitch4's own pilot question, "Does the ledger sell?"
- **Effect and confidence.** Differentiation. High that "bound" is more differentiated than "signed"; demand is untested.

### D2. Answer "can the vendor decrypt?" in the CSA's and the EDPB's words

- **Pitch4 change.**
  - Page 3: "Why encryption makes it safe to adopt".
  - Page 1: "Private from us".
  - Pages 4 and 5: "Open core, hosted blind", and "Paid: relays, storage, and an edge we run and cannot read".
  - Page 6: "Trust documents first".
- **What to change.**
  1. Add one testable line that separates host-blind from vendor-held CMEK, in third-party terms. Level 2's draft: "Our relay and storage never hold a key; with CMEK the vendor decrypts whenever the key is enabled (CSA); with us, neither a subpoena nor a breach of our servers yields plaintext."
  2. Rewrite "Adopting it adds no vendor that can read your agents' work" so it says what blindness does in a review.
     - It removes the data-handling questions: who can read, subprocessors with plaintext access, breach notification, and transfer analysis.
     - The sidecar is still reviewed as software on developer machines and on the network.
  3. Use Tailscale's sentence, "Tailscale sees your metadata, not your data", as the template for the promised list of metadata.
  4. Back the claim with:
     - open relay code;
     - reproducible builds;
     - a key-transparency or verifier tool;
     - the published protocol audit.
- **Why it helps.** A reviewer can now tick "customer-managed keys" for Claude Code and Cursor, so pitch4 has to answer a different question. Authorities the reviewer already trusts draw the line for it.
- **Evidence.**
  - CSA (Jan 2026) — [CSA blog](https://cloudsecurityalliance.org/blog/2026/01/05/choosing-the-right-key-responsibility-model):
    - Bring-your-own-key "Does not mean the CSP cannot access your data—as long as you use keys within the CSP's KMS/HSM, the CSP can decrypt data".
    - Hold-your-own-key gives "High assurance that your CSP cannot decrypt certain data".
    - CSA tells teams to ask, "do we require a model where the provider cannot technically decrypt data?"
  - CSA (2022): a customer-controlled key store means "Elimination of a cloud service provider's ability to process customer data in plaintext". — [CSA, 2022](https://cloudsecurityalliance.org/press-releases/2022/09/27/cloud-security-alliance-offers-recommendations-for-using-customer-controlled-key-store)
  - EDPB: Use Case 1 versus Use Case 6 and para. 95. — [EDPB](https://www.edpb.europa.eu/system/files/2021-06/edpb_recommendations_202001vo.2.0_supplementarymeasurestransferstools_en.pdf)
  - HHS: "no-view services" and the breach safe harbor. — [HHS via Wayback](https://web.archive.org/web/20251231073222/https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html)
  - The vendors' own wording:
    - "Anthropic uses it to encrypt certain data at rest" ([CMEK](https://platform.claude.com/docs/en/manage-claude/cmek));
    - Cursor's CMEK is "for Cloud Agent server-side encryption" ([Cursor](https://cursor.com/docs/cloud-agent/security));
    - Microsoft Customer Key is used for "eDiscovery, anti-malware, anti-spam, and search indexing" ([Microsoft Learn](https://learn.microsoft.com/en-us/purview/customer-key-overview));
    - with Slack EKM, "Org members can use Slack as normal" ([Slack](https://slack.com/help/articles/360019110974-Slack-Enterprise-Key-Management)).
- **Counter-evidence.**
  - CSA says the terms "do not have an agreed-upon meaning". A form asking "Do you support customer-managed keys?" therefore gets a yes from Anthropic and Cursor too (level 2 inference).
  - No buyer was found who chose host-blind over CMEK, or paid more for it.
  - Blindness costs features: Microsoft frames DKE for "about 5% of data", because coauthoring, eDiscovery, DLP and search stop working ([DKE](https://learn.microsoft.com/en-us/purview/double-key-encryption)).
  - Blindness does not take the vendor out of scope. A host without keys is still a HIPAA business associate, and the tier stays at the sidecar's highest attribute.
- **Cost and risk.**
  - The line is cheap to write. The backing artifacts cost the most, and pitch4 already plans most of them before "end-to-end encrypted" appears in public.
  - The risk is overclaiming. Metadata stays visible, so pitch4's own "Where it ends" list must stay next to the line.
- **Test.**
  - Put the line into design partners' questionnaire answers.
  - Record whether the reviewer marks the hosted part as having no plaintext access.
  - Record which sections shrink: DPA, subprocessors, breach notification, transfer assessment.
  - Record whether EU partners cite EDPB Use Case 1.
  - Compare with how the same reviewer handled Anthropic's or Cursor's CMEK.
- **Effect and confidence.** Differentiation. Medium: the authorities support the distinction, but buyer behavior is untested.

### D3. Do not charge for blindness; charge for what is hard to do blind

- **Pitch4 change.**
  - Page 5: "Who pays" (what Team and Assured contain), and the headline "The tools are table stakes. The record under your keys is the product."
  - Page 4: the paid list in "Open core, hosted blind".
  - Page 6: "What ships, in order". Legal hold and key escrow currently come last.
- **What to change.**
  - State blindness as the default architecture in every tier, including free.
  - Put in the paid tiers the things blind systems make hard. Microsoft's list of what DKE breaks maps them out:
    - a customer-run reader for search, eDiscovery and legal hold;
    - SIEM export from the admin side;
    - key escrow and recovery;
    - a dedicated region or tenant that stays blind (the GitLab Dedicated analog).
- **Why it helps.** Key control is sold inside top-tier bundles, not as a separate premium for blindness. The features vendors keep under CMEK, such as search and eDiscovery, are exactly what a blind design has to rebuild on the customer's side. They are what a buyer will miss.
- **Evidence.**
  - Google's client-side encryption comes only in "Frontline Plus; Enterprise Plus; Education Standard and Education Plus". — [Google](https://support.google.com/a/answer/10741897)
  - DKE comes in E5-class licenses. — [service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description)
  - Slack EKM is "available as a security add-on for the Enterprise Grid and Enterprise+ plans". — [Slack](https://slack.com/help/articles/360019110974-Slack-Enterprise-Key-Management)
  - The features DKE loses. — [DKE](https://learn.microsoft.com/en-us/purview/double-key-encryption)
  - GitLab Dedicated passed $70M ARR. — [MarketBeat](https://www.marketbeat.com/instant-alerts/transcript-gitlab-q2-earnings-call-highlights-2026-09-01/) (search summary, secondary)
  - Level 2 found no price list from any one vendor that charges more for blind than for CMEK.
- **Counter-evidence.**
  - The finding rests on absence. No buyer survey or analyst note on willingness to pay for HYOK or E2EE over CMEK was found, and Gartner and Forrester were not searched.
  - Pitch4's tier prices are inferred and untested.
  - GitLab Dedicated is single-tenant and run by the vendor; it is not blind.
- **Cost and risk.**
  - These are large builds. Moving legal hold and key recovery earlier enlarges the first paid release, against pitch4's own "Scope" risk.
  - Nothing in this branch shows whether buyers with 5–150 engineers want eDiscovery or legal hold early.
- **Test.**
  - In pilots, offer Team and Assured with and without each of these features.
  - Record which features buyers ask for before they pay.
  - Record conversion at $8–25 and at about $39 a seat (pitch4's "Will teams pay?" row).
- **Effect and confidence.** Offering. Medium.

### D4. Sell the security review in two parts, with a dated attestation ladder

- **Pitch4 change.**
  - Page 6: "Trust documents first" and "Risks we manage".
  - Page 3: a short note on how the sidecar is reviewed.
  - Page 5: Assured's "on your servers too".
- **What to change.**
  1. Present the sidecar to third-party-risk teams as two engagements:
     - **Open-source software on endpoints**, reviewed as a software supplier: an SBOM, signed reproducible builds, vulnerability disclosure, an SSDF-style attestation, and the buyer's own scan of the product.
     - **A hosted relay and storage that hold only ciphertext**, scored low on data access.
  2. Add level 2's attestation ladder:
     - design partners sign with a "SOC 2 Type 1 (Security) within six months" clause;
     - an auditor is engaged at the beta of the hosted team layer, with the Type 1 scoped to the hosted relay, ledger and storage, and no consumer network in scope;
     - the Type II window opens right after the Type 1 report and runs 3–6 months;
     - ISO 27001 waits until EU enterprise deals require it;
     - the self-hosted Assured install ships with an SSDF-style attestation, an SBOM, signed reproducible builds, a penetration-test letter and the published protocol audit.
  3. Use a dated auditor engagement letter, not sign-up with a compliance platform, as the interim proof.
  4. Offer a no-view BAA template for health buyers.
- **Why it helps.**
  - The sidecar's tier is set by system access, not data, so blindness alone cannot lower it. Separating the hosted part might.
  - The vendors pitch4 resembles all pair "we can't read it" with SOC 2 or ISO.
  - First deals open on a Type 1 or a contract promise of one.
- **Evidence.**
  - The tiering rubrics and UpGuard's demotion rule: [UpGuard](https://www.upguard.com/blog/what-is-vendor-tiering.md); [Vanta Help](https://help.vanta.com/en/articles/11345560-configuring-inherent-risk-scoring); the [Vanta API](https://developer.vanta.com/api-reference/vendor-risk-attributes/list-vendor-risk-attributes.md) attribute "Read internal systems" (search summary).
  - The E2EE vendors' attestations: [Tailscale](https://tailscale.com/security), [1Password](https://support.1password.com/security-assessments/), [Bitwarden](https://bitwarden.com/compliance/), [Tresorit](https://tresorit.com/security). GitLab's attestations cover only its SaaS ([GitLab](https://about.gitlab.com/security/)).
  - The 5 versus 7 split among 11 HN practitioners: [HN 29099232](https://news.ycombinator.com/item?id=29099232), [HN 43338240](https://news.ycombinator.com/item?id=43338240), [HN 47482479](https://news.ycombinator.com/item?id=47482479), [HN 29103457](https://news.ycombinator.com/item?id=29103457), [HN 25810851](https://news.ycombinator.com/item?id=25810851), [HN 29100011](https://news.ycombinator.com/item?id=29100011).
  - tptacek on scoping the report to Security: "having a security SOC2 ends the vendorsec process it any enterprise buyer [sic]". — [HN 48999265](https://news.ycombinator.com/item?id=48999265)
  - ISC2's 77% and 84%. — [ISC2](https://www.isc2.org/insights/2025/11/2025-isc2-supply-chain-risk-survey)
  - Buyers of self-hosted software still scan it: "Our security team scanned it with our chosen tools and you have to fix these things before we will deploy it." — [HN 38536864](https://news.ycombinator.com/item?id=38536864)
  - The SSDF attestation form. — [CISA](https://www.cisa.gov/secure-software-attestation-form)
- **Counter-evidence.**
  - The HN accounts come from sellers and are self-selected. No evidence from buyers at companies with 5–150 engineers was found.
  - No rubric item that scores "vendor holds no keys" was found. The two-engagement idea is an untested inference.
  - Some practitioners dismiss Type 1: "roughly logo-ware" ([HN 48997698](https://news.ycombinator.com/item?id=48997698)); "has no weight" ([HN 21605056](https://news.ycombinator.com/item?id=21605056)).
  - DORA's register still lists a license with ongoing support, and HIPAA still requires a BAA.
  - Level 2 warns that the way an endpoint process with network reach gets approved (by IT, the endpoint or MDM team, or third-party risk) "may gate the first release more than SOC 2 does". This was not researched.
- **Cost and risk.**
  - One 2021 data point: "$40k in year one and $30k/year in subsequent years" for "Vanta, pen test, vulnerability monitoring and audit fees". — [HN 25810851](https://news.ycombinator.com/item?id=25810851)
  - Type II needs months of observed operation.
  - The Delve allegations weaken "in process" proof from compliance platforms (level 2, citing `L1-1.08`).
- **Test.**
  - For each design partner, log:
    - who approved the install (IT, MDM, security, or third-party risk);
    - which artifacts they asked for;
    - how long the review took;
    - whether the hosted relay was tiered separately, and lower.
  - If endpoint approval turns out to be the blocker rather than SOC 2, reorder the trust work.
- **Effect and confidence.** Offering. Medium.

### D5. Publish the entry format as a profile of existing standards, and offer the sidecar to the AAIF working group as its independent implementation

- **Pitch4 change.**
  - Page 4: the "A signed record of agent work" row. Its phrase "an individual IETF draft for agent audit trails" is out of date.
  - Page 1: "the sidecar, relay, and entry format are open".
  - Page 5: "The format is open, so teams stay because the service is good".
  - Page 6: the team layer's "SIEM export" and "the verifiable log".
- **What to change.**
  - Describe the entry format as a profile:
    - OTel GenAI attribute names (turn, approval as in #95, tool call ID);
    - an OCSF 1.9 export for SIEMs (`ai_operation` with `delegation` and `record_integrity`);
    - receipts compatible with COSE/SCITT (RFC 9942/9943) that track IETF AUDIT;
    - model identity that points to WCM, OpenSSF Model Signing or CycloneDX rather than a new format.
  - Offer the open-source sidecar to the AAIF Observability & Traceability working group as the "one independent agent or SDK" beside goose.
  - Contribute the four things level 1 names:
    - coverage fields;
    - approval records with an opaque approver reference that the team can resolve;
    - the binding of grant, action, effect and model for each run;
    - test fixtures from real harnesses.
- **Why it helps.**
  - "Open format" becomes checkable and portable.
  - The security buyer gets an export that their SIEM's schema already defines.
  - The sidecar gets a credible route into the standard, instead of competing with about two dozen drafts.
- **Evidence.**
  - The AAIF's 10 projects include no record project. — [LF press release](https://www.linuxfoundation.org/press/agentic-ai-foundation-announces-four-new-projects-agent-skills-open-responses-openenv-and-opensandbox)
  - The working group names the E3 gap and plans to implement in goose plus one independent agent. — [USE-CASES.md](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/USE-CASES.md); [execution plan](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/AGENT-BEHAVIOR-TRACE-MODEL-EXECUTION-PLAN.md)
  - OTel handed integrity and authorization to other groups. — [#438](https://github.com/open-telemetry/semantic-conventions-genai/issues/438); [#461](https://github.com/open-telemetry/semantic-conventions-genai/issues/461)
  - #95's opaque actor field fits pitch4's split, where admins see approvals but not transcripts. — [#95](https://github.com/open-telemetry/semantic-conventions-genai/issues/95)
  - OCSF 1.9 has `record_integrity` and `delegation`. — [OCSF 1.9.0](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0)
  - The AUDIT BoF meets on 17 Nov. — [agenda](https://datatracker.ietf.org/meeting/127/agenda)
- **Counter-evidence.**
  - Standards follow adoption. OTel maintainers reject proposals that are not "supported by some commonly used frameworks". — [#470](https://github.com/open-telemetry/semantic-conventions-genai/issues/470)
  - The field is crowded:
    - 25 record-related IETF drafts in two months, none adopted ([datatracker query](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=agent&type=draft&time__gte=2026-09-01));
    - receipt startups;
    - Action State's capsule format, pushed through both the IETF and the AAIF, including a working-group demo anchored on Hedera ([minutes, 14 Oct](https://github.com/aaif/wg-observability-and-traceability/blob/main/meeting-minutes/2026-10-14.md)).
  - The plan itself says "recording this plan does not make those semantics an adopted standard".
  - Still unknown: the AUDIT outcome, the working group's contribution process, and the AAIF's admission rules.
  - Whether SIEMs support OCSF 1.9's new fields is unverified.
- **Cost and risk.**
  - Three mappings (OTel, OCSF, COSE) and harness test fixtures to build and maintain, plus weekly working-group time.
  - The envelope format (COSE/CBOR or JSON/DSSE) may change after the BoF.
- **Test.**
  - After 17 Nov, check the datatracker for an AUDIT charter and which envelope it picks.
  - Open an issue in the working group's repo offering the sidecar as the independent implementation, and record the answer.
  - Build the OCSF 1.9 export and test ingest in one SIEM (AWS Security Lake, Splunk or Sentinel).
  - Track whether #95 merges an approval convention that the sidecar's entry maps to.
- **Effect and confidence.** Both. Medium.

### D6. Make coverage a first-class field and a selling point

- **Pitch4 change.**
  - Page 6, "Risks we manage" ("Completeness. Hooks fail open, so each run states what the record could not see"), moves forward.
  - It goes to page 3, "What admins can answer", and page 1, "How it works".
- **What to change.**
  - Each entry names:
    - its observer: harness hook, filesystem, the sidecar's own traffic, or the sidecar beside the model server;
    - its observation point;
    - its assurance level.
  - Missing data reads "unknown", never "none" or "success".
  - Each run carries a coverage summary.
  - Contribute the fields through D5.
- **Why it helps.** Every rival record is silent about what it missed. A record that states its own blind spots meets a working group's stated requirement and makes an audit answer defensible.
- **Evidence.**
  - The AAIF's cross-cutting requirement: telemetry "should identify its producer and observation point, distinguishing agent self-reporting from framework, gateway, identity-provider, sandbox, operating-system, network, or security-sensor evidence". — [USE-CASES.md](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/USE-CASES.md)
  - Use case E1: "agent-produced telemetry may not be sufficient". — same source
  - "missing observations mean unknown, not zero or success". — [execution plan](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/AGENT-BEHAVIOR-TRACE-MODEL-EXECUTION-PLAN.md)
  - The working group's CLI analysis found that "Agent policy decisions lack a portable observation model". — [deep-dive](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/agent-tool-cli-boundary-deep-dive.md)
  - Claude Code's Windows hooks were "failing open" until 22–23 Oct 2026. — [changelog](https://code.claude.com/docs/en/changelog)
  - Alibaba's LoongSuite Pilot recorder covers main-agent `Bash` calls "but not subagent, PowerShell, MCP or non-Bash tools". — [deep-dive](https://github.com/aaif/wg-observability-and-traceability/blob/main/working-documents/agent-tool-cli-boundary-deep-dive.md)
  - The Compliance API's exclusions. — [Claude blog](https://claude.com/blog/compliance-api-cowork-and-claude-code)
- **Counter-evidence.** The demand comes from a working group, not from buyers. This branch has no buyer evidence that a coverage statement changes a purchase.
- **Cost and risk.**
  - Moderate: the sidecar has to detect failed hooks and uncaptured tool paths in each run.
  - [inference, this synthesis] On harnesses with few hooks, the record may show many unknowns.
- **Test.**
  - In pilots, count runs where the record marks something unknown: a failed hook, an uncaptured tool path, or a surface it cannot see.
  - Ask admins whether the coverage summary changed what they would sign off.
  - Watch whether the working group adopts observer and assurance fields.
- **Effect and confidence.** Offering. Medium.

### D7. Run reach over the transports teams already use, and sell the grant receipt

- **Pitch4 change.**
  - Page 3: "Govern every way out" (port forwarding, IP addresses), and "Reach is all or nothing today".
  - Page 4: the "Reach" row.
  - Page 5: the reach row ("At par ... We add per-agent grants and receipts").
  - Page 6: reach in the first release, and the pilot question "Is reach a wedge?"
- **What to change.**
  - Treat Tailscale (tsnet, Aperture), iroh and zrok as transports where a team already runs them, next to URnetwork's own.
  - Sell the receipt that ties each connection to the approving person, the run, and its change set, under customer keys.
  - Explore Tailscale's sovereign-AI push as a sales channel.
  - Replace "Reach is all or nothing today" with the gap that remains (section 1.5).
- **Why it helps.** Tailscale is now a funded, neutral incumbent for agent reach and private model access, aimed at the same self-hosted-model buyers pitch4 targets. On tunnels the sidecar is only at par. The receipt is what Tailscale does not offer.
- **Evidence.**
  - Agents are tailnet nodes, with confirmation at first connect and standing or one-time access. — [Muse](https://tailscale.com/blog/meta-muse-ai-agent-tailscale)
  - The sovereign-AI post — [sovereign AI](https://tailscale.com/blog/sovereign-ai-patricia-prewitt):
    - "You can host your own AI infrastructure using Tailscale and Aperture today";
    - "Tailscale isn't going to build models, GPUs, or datacenters";
    - no logging claims.
  - Recordings sit in "Tailscale-managed storage", with nothing said about keys or approvals. — [PAM](https://tailscale.com/blog/what-is-tailscale-pam)
  - Codex Cloud ships with Tailscale. — [RSS](https://tailscale.com/blog/index.xml)
  - Level 1 found "no harness-level action record, no binding of a connection to a harness approval, and no attestation of which weights served a call".
- **Counter-evidence.**
  - Tailscale may add per-action records or logs under customer keys. Level 1 found no statement either way, and did not re-check Aperture's current logging and retention.
  - Whether Tailscale is open to partners that build on tsnet is unknown.
  - Level 2 adds a counterweight. The per-agent network paths and the model-access gate are what put the sidecar in a high tier ("system access") in every rubric. Shipping reach first raises the review the sidecar faces, whatever the transport.
- **Cost and risk.** Several transports widen the test matrix and tie part of the product to a rival's roadmap.
- **Test.**
  - Prototype the grant receipt over tsnet, and over iroh or zrok.
  - Measure pitch4's own "cloud-agent grants approved and used each week".
  - Ask Tailscale's sovereign-AI team or partner program whether they would work with a partner that builds on tsnet, and record the answer.
- **Effect and confidence.** Both. Medium.

### D8. Name the attested weights that served each call, instead of having the sidecar sign them

- **Pitch4 change.**
  - Page 4: "Model access — Proves: The sidecar beside the model server signs which weights it serves", and the table row "What the record can prove ... Also which weights, quantization, and runtime".
  - Page 3: "down to the weights".
- **What to change.**
  - Claim: "The record names the attested weights that served each call."
  - Use WCM, enclave attestations or OpenSSF Model Signing where they exist.
  - Fall back to a hash signed by the sidecar, labeled as weaker.
- **Why it helps.** A reviewer who knows hardware-attested custody will discount a software signature from the sidecar. Claiming more than the sidecar can prove costs credibility.
- **Evidence.**
  - WCM keeps weights encrypted until the receiving infrastructure proves agreed conditions, with keys sealed to an attested workload (CPU attestation, and GPU attestation where required). — [Help Net Security](https://www.helpnetsecurity.com/2026/09/10/weight-custody-manifest-open-standard/) (secondary)
  - WCM can optionally link to OpenSSF Model Signing. — [AAIF blog](https://aaif.io/blog/before-an-agent-uses-a-model-verifying-model-custody-on-customer-infrastructure)
  - Tinfoil uses dm-verity to check weight reads against a Merkle root. — [Tinfoil](https://tinfoil.sh/blog/2026-02-03-proving-model-identity) (search summary)
- **Counter-evidence.**
  - WCM is pre-1.0 and "a design under review", has 7 stars, and is not stated to be an AAIF project. — [repo](https://github.com/agentrust-io/weight-custody-manifest)
  - The Tinfoil description comes only from a search summary.
  - Open weights are a minority of enterprise LLM spend (pitch4's own Menlo figure, 11%), so this proof matters to a small segment.
- **Cost and risk.** One integration per attestation scheme, and the risk of backing a scheme that does not become the standard.
- **Test.**
  - With the two or three design partners on open weights, check whether their servers can produce WCM, enclave or Model Signing evidence.
  - Measure the share of model calls with attested identity versus a sidecar hash.
  - Ask their reviewers whether the labeled fallback is acceptable.
- **Effect and confidence.** Offering. Medium.

### D9. Aim at what the vendors' own records leave out, and at buyers for whom blindness changes the decision

- **Pitch4 change.**
  - Page 5: "Where we start".
  - Page 4: "Who it's for".
  - Page 1: the problem bullets "Sessions vanish" and "Approvals go dark".
  - Page 2: the line "Claude Code deletes local transcripts after 30 days".
- **What to change.**
  - Name the segments the vendors' own documents exclude:
    - teams on several harnesses;
    - Claude Code on Bedrock, Vertex or Foundry;
    - teams on open weights;
    - CMEK organizations that lose Claude Code on the web;
    - buyers who need keys the vendor cannot use, rather than keys the vendor manages.
  - Add level 2's segments, where blindness changes a decision rather than a review answer:
    - EU buyers transferring data to a host with US ties (EDPB Use Case 1);
    - EU sovereignty tenders that score key control;
    - health buyers (HIPAA "no-view" duties and the breach safe harbor, with a BAA).
  - Rewrite the problem bullets to describe the gap that remains for Claude Enterprise buyers.
- **Why it helps.** Pitch4's problem statements are now weaker for Claude Enterprise buyers. But the vendors document their own exclusions, so the remaining gap can be stated precisely.
- **Evidence.**
  - Compliance API exclusions. — [Claude blog](https://claude.com/blog/compliance-api-cowork-and-claude-code)
  - Features CMEK turns off. — [CMEK coverage](https://platform.claude.com/docs/en/manage-claude/cmek-coverage-claude-enterprise)
  - The gateway connects only to Claude providers. — [gateway](https://code.claude.com/docs/en/claude-apps-gateway)
  - Copilot Memory works on Copilot surfaces only. — [GitHub](https://github.blog/changelog/2026-10-28-github-intelligence-puts-your-code-context-and-history-to-work)
  - EDPB Use Case 1. — [EDPB](https://www.edpb.europa.eu/system/files/2021-06/edpb_recommendations_202001vo.2.0_supplementarymeasurestransferstools_en.pdf)
  - The EU Cloud Sovereignty Framework assesses "where providers store encryption keys". — [heise](https://www.heise.de/en/news/Cloud-Sovereignty-Framework-How-the-EU-will-assess-cloud-sovereignty-10922224.html) (secondary)
  - HHS no-view duties and safe harbor. — [HHS via Wayback](https://web.archive.org/web/20251231073222/https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html)
  - Atlassian keeps Bitbucket and Bamboo on Data Center. Level 2 reads this as self-hosting lasting longest where code lives. — [Atlassian](https://www.atlassian.com/licensing/data-center-end-of-life)
- **Counter-evidence.**
  - Anthropic could extend the Compliance API or the gateway. Level 1 found nothing either way.
  - The sovereignty framework's details rest on vendor blogs whose SEAL scale and award dates conflict, and the Commission PDF was not read.
  - Regulated buyers need Type II, BAAs and DORA register entries, which is a longer path.
  - Teams of 5–50 engineers mostly lack a third-party-risk function. For them, blindness mainly answers "can the vendor read our code?" in the developer's own evaluation (level 2 matrix).
- **Cost and risk.** The copy is cheap. Narrowing toward regulated segments lengthens sales cycles.
- **Test.** Recruit design partners deliberately across these segments. Compare conversion and review length with partners already covered by a vendor record, such as Claude Enterprise on the Anthropic API.
- **Effect and confidence.** Differentiation. Medium.

### D10. Make "partner first" with Buzz concrete

- **Pitch4 change.**
  - Page 4: the "Agents and shared models" row.
  - Page 5: the "Coordination across agents" row.
  - Page 6: "Risks we manage: Open rivals".
- **What to change.**
  - Describe Buzz correctly: a self-hostable Nostr relay with signed events and an ACP harness; iroh carries MeshLLM.
  - Name the integration:
    - post sidecar entries and approval requests into Buzz channels as signed events;
    - accept a Buzz reaction as an approval source;
    - position the sidecar as the capture layer for harnesses running outside Buzz, with content kept encrypted from any relay.
- **Why it helps.**
  - Buzz has the audience and the signed workspace.
  - Its documented gaps are exactly what the sidecar adds: approval gates not wired, audit limited to workspace actions, and a relay that stores and indexes channel content.
  - "Partner first" with a named integration is believable. Without one, it reads as a hope.
- **Evidence.** [README](https://github.com/block/buzz); [ARCHITECTURE.md](https://github.com/block/buzz/blob/main/ARCHITECTURE.md); [Buzz releases](https://github.com/block/buzz/releases/tag/desktop-v0.5.28); [Block engineering blog](https://engineering.block.xyz/blog/buzz); [iroh blog](https://www.iroh.computer/blog/buzz-agent-workspaces).
- **Counter-evidence.**
  - Block could close the gaps itself. Level 1 found no statement of plans for channel-content encryption or harness-level capture. If Block does close them, the sidecar's open-source position "narrows to a capture plug-in for Buzz" (level 1).
  - Posting entries into a relay that indexes channel content would break blindness, unless only encrypted entries go in.
  - There is no evidence that Buzz's maintainers would accept an external entry format.
- **Cost and risk.** A bridge to build and maintain, plus a dependency on Buzz's approval work (WF-08).
- **Test.**
  - Build a minimal bridge.
  - Ask Buzz's maintainers, in an issue, whether they would accept an external approval source or entry format.
  - Measure use among design partners that already run Buzz.
- **Effect and confidence.** Both. Low.

### D11. Correct the competitive claims before pitch4 is shown again

- **Pitch4 change.** Pages 1, 3, 4 and 5, as listed in section 1.5.
- **What to change.** Apply the table in section 1.5.
- **Why it helps.** Vendor documents now contradict several statements. Level 1's own rationale was that accuracy is part of the offering, given URnetwork's trust gaps.
- **Evidence.** As cited in section 1.5.
- **Counter-evidence.** Some corrections rest on secondary or search-summary sources, such as the SpaceX–Cursor close (via Wikipedia) and Factory's round. Some apply only to Claude Enterprise buyers.
- **Cost and risk.** Low.
- **Test.** Re-check each cited page the day before publishing. Ask a reviewer at a design partner to mark any claim they can contradict.
- **Effect and confidence.** Offering. High.

## 3. How level 2 changed or qualified level 1

| Level-1 finding or direction | What level 2 found | Net effect |
|---|---|---|
| CMEK "changes the buyer conversation", so pitch4 needs "a one-line, testable distinction" (1.6, Q2) | The CSA, the EDPB and HHS each draw the line between a provider that can decrypt and one that cannot. Large vendors sell CMEK and client-side encryption as different products | **Confirmed and strengthened.** The line can be written in words reviewers already trust (D2) |
| "No buyer evidence was gathered on whether host-blind encryption beats CMEK in purchase decisions; this is the largest open risk" (1.6, Q4 gap) | No buyer was found who chose or paid more for host-blind. Key control is sold inside top-tier bundles. Microsoft limits its hold-your-own-key product to about 5% of data because it breaks search, eDiscovery and DLP | **Qualified.** Blindness shortens reviews and decides specific regulated cases, but carries no premium on its own. More of the weight moves to "bound" (D1), and paid tiers carry what is hard to do blind (D3) |
| "Hosted blind" as the core paid differentiation (1.6's open question on CMEK) | Tiering takes the worst attribute, and the sidecar's worst is system access. HHS keeps a host without keys in scope. DORA lists software licenses | **Qualified.** Hosted blind does not lower the inherent tier. New lever: a review in two parts (D4). Page 3's adoption claim must be narrowed (section 1.5) |
| Segments that the harness vendors' records exclude (1.6, Q4) | Blindness changes decisions for EU transfers (Use Case 1), sovereignty tenders that score key control, and health buyers. Teams of 5–50 engineers mostly lack a third-party-risk function | **Extended** with regulatory segments. For small teams, blindness matters in the developer's own evaluation (D9) |
| Open source and self-hosting as the answer to "you don't have to trust us" (pitch4 pages 1 and 4) | Every E2EE vendor checked still holds SOC 2 or ISO 27001. Self-managed software is reviewed as supply chain. Self-managed is about half or more of comparable spend, but shrinking. GitLab Dedicated passed $70M ARR | **Qualified.** Open source and self-hosting change the review rather than removing it. This supports "Assured, on your servers too" and a dedicated blind tenant (D3, D4) |
| Reach first, treated as transports (1.6, Q4; pitch4 page 6 order) | The endpoint process, per-agent network paths and the model-access gate score high on system access in every rubric | **Qualified.** Reach in the first release raises the review. How endpoint installs get approved is now a first-release question (D4, D7) |
| (Not in level 1) Which attestations close deals | Of 11 HN practitioners, 5 say Type 1 or a contract promise opens first deals and 7 say larger buyers expect Type II. ISO 27001 comes later. Questionnaires continue | **New.** An attestation ladder for page 6 (D4) |
| Standards route, Block's and Tailscale's plans, SIEM ingest, attestation of weights (1.6's other open questions) | Not followed up in this branch | **Unchanged** and still open (section 4) |

## 4. What remains open

1. **IETF AUDIT outcome.** Will the BoF on 17 Nov 2026 lead to a working-group charter? Which envelope would it adopt:
   - VACR (CDDL with COSE);
   - in-toto/DSSE, as in draft-gilda;
   - SCITT receipt profiles?

   The answer sets the entry format's encoding, and whether pitch4 can claim to be "standard-compatible".
2. **AAIF route.**
   - Would the AAIF working group and the goose maintainers accept a capture tool that spans harnesses as the "independent agent or SDK"?
   - How does the AAIF take in outside formats? The trace-model proposal (in Google Docs) and the Discord were not read.
   - What will the interim attestation working group recommend after its 90-day trial?
3. **Buyer evidence on host-blind versus CMEK.** Do security reviewers at companies with 5–150 engineers treat host-blind differently from vendor CMEK in practice, and will any pay more? No buyer-side accounts, buyer surveys or analyst notes were found.
4. **Endpoint approval.** Who approves an endpoint process with network reach: IT, the endpoint or MDM team, security, or third-party risk? Does that gate the first release more than SOC 2 does?
5. **Two-part review.** Does presenting the sidecar as two engagements actually lower the hosted part's tier in Vanta, Drata, OneTrust or ProcessUnity intake?
   - No rubric item that scores "vendor holds no keys" was found.
   - SIG 2026 scoping, CAIQ v4's key-management items and HECVAT 4 could not be read.
6. **Block's plans.**
   - Is Block wiring Buzz's approval gates (WF-08)?
   - Is it adding harness-level capture, or encrypting channel content? Whether NIP-17 or NIP-44 is used in production is unconfirmed.
   - Would it adopt an external entry format?
7. **Tailscale's plans.**
   - Will Tailscale add per-action records bound to approvals, or log encryption under customer keys, across Aperture, PAM and MCP endpoints?
   - Is it open to partners that build on tsnet for its sovereign-AI customers?
   - Aperture's current logging and retention were not re-checked.
8. **What SIEMs and auditors ingest.**
   - Do AWS Security Lake, Splunk or Sentinel support OCSF 1.9's `ai_operation` and `record_integrity`?
   - Do SCITT/COSE receipts count as evidence for SOC 2 or the EU AI Act?
9. **Anthropic.**
   - Will it extend the Compliance API to sessions on Bedrock, Vertex and Foundry, or the gateway to non-Claude upstreams?
   - Is Claude Code's local session storage encrypted with an organization recovery key? This was claimed only on DEV Community and is unverified.
10. **Regulatory texts not read:**
    - the EU Cloud Sovereignty Framework PDF (SOV-3 criteria);
    - the DORA ITS annex, and the ESAs' Q&A on software licenses;
    - GDPR Art. 34(3)(a);
    - HITRUST expectations;
    - FedRAMP scope for self-hosted software.
11. **Competitor items still unverified or unchecked:**
    - Cognition's September agreement with AWS;
    - Cursor's October Agent SDK;
    - Action State's "EvidenceBook" launch;
    - the September Claude Code changelog;
    - moves by Datadog, Sentry, Grafana, Okta and Coder;
    - customer-managed keys at SpecStory, git-ai Teams and Entire's enterprise tier;
    - OpenAI's own Codex governance page, which returned HTTP 403.
12. **Self-hosting details.**
    - What share of companies with 5–150 engineers self-host?
    - How do GitLab's self-managed customers review GitLab?
    - Do 1Password's and Bitwarden's SOC 2 scopes cover self-hosted deployments?
