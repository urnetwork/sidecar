# Privacy-preserving and confidential AI: who claims operator blindness, what it covers, and where it breaks (state as of 26 November 2026)

*Notes for the report writer. Every bullet carries the date of the claim or event. Items dated before 2026 are marked "(older)". Quoted text is verbatim from the cited page as retrieved on 26 Nov 2026. Unquoted text is a paraphrase. These trust classes are used throughout and kept distinct, as the brief requires:*
- ***V*** *vendor-held keys: TLS plus at-rest encryption, and the operator can decrypt.*
- ***Z*** *contractual minimization: zero data retention, no-training terms or an anonymizing proxy. The operator still sees plaintext.*
- ***C*** *customer-managed keys: the operator processes plaintext, but the customer controls the keys for stored data.*
- ***S*** *self-hosting or local models.*
- ***T*** *confidential computing: a hardware TEE plus remote attestation. The operator is excluded by design, but the chip vendor, firmware, physical access and the software inside the enclave stay in the trust base.*
- ***T+*** *"device-to-enclave" encryption that vendors market as end-to-end encryption. The client encrypts to a key held only by an attested TEE that the provider runs, so compute is still class T.*
- ***E*** *true end-to-end encryption: only users' devices hold keys, and servers see only ciphertext.*

*Bittensor subnets appear only in the matrix in section 5, cited from the earlier report of 23 Nov 2026.*

## 1. Platform-scale private AI: what do Apple Private Cloud Compute, Google Private AI Compute, Meta Private Processing, Azure confidential AI, NVIDIA confidential computing and AWS Nitro promise, and to whom?

### Takeaway
Apple, Google and Meta all promise their own consumers "not even us" using the same pattern: device-encrypted requests sent to attested, stateless enclaves, with transparency logs and third-party IP relays. All three remain class T, because the operator owns the hardware and the data centres, and Apple and Meta both concede physical or insider attacks in their threat models. Two shifts in 2026 matter most:
- **Google memory (23 Sep 2026):** Google added persistent server-side memory sealed under keys held on the user's devices. This is the first platform-scale claim of encrypted AI memory.
- **Apple and Gemini (Jun 2026):** Apple's Gemini-based Siri reportedly sends its heaviest requests to Google Cloud B200 servers, and no audit of that tier has been published.

Microsoft, NVIDIA and AWS sell confidential-computing building blocks to enterprises, clouds and model builders. They do not sell operator-blind consumer assistants.

### Cited Findings

#### Apple Private Cloud Compute (PCC): for Apple Intelligence users
- (Jun 2024, older) Apple's founding claim is "making sure that personal user data sent to PCC isn't accessible to anyone other than the user — not even to Apple." PCC runs on "custom-built server hardware that brings the power and security of Apple silicon to the data center." — [Apple Security Research, 10 Jun 2024](https://security.apple.com/blog/private-cloud-compute/)
- (Jun 2024, older) Apple sets five requirements — [Apple, 10 Jun 2024](https://security.apple.com/blog/private-cloud-compute/):
  - stateless computation: "personal data leaves no trace in the PCC system"
  - enforceable guarantees: "Security and privacy guarantees are strongest when they are entirely technically enforceable"
  - no privileged runtime access: PCC "must not contain privileged interfaces that would enable Apple's site reliability staff to bypass PCC privacy guarantees"
  - non-targetability: "targeting users should require a wide attack that's likely to be detected"
  - verifiable transparency: "security researchers must be able to verify the security and privacy guarantees of Private Cloud Compute"
- (Jun 2024, older) Apple's threat model includes "an attacker with physical access to a compute node and a high level of sophistication". Apple says such an attacker might subvert some hardware protections and potentially extract data while it is being processed. Its mitigations are supply-chain hardening and non-targetability. — [Apple, 10 Jun 2024](https://security.apple.com/blog/private-cloud-compute/)
- (Oct 2024, older) For verification, Apple published a PCC Security Guide and a Virtual Research Environment that lets researchers "Verify the consistency of the transparency log" and "Download the binaries corresponding to each release". It also released source for some components "under a limited-use license agreement". — [Apple, 24 Oct 2024](https://security.apple.com/blog/pcc-security-research/)
- (Oct 2024, older) Apple's PCC bounties — [Apple, 24 Oct 2024](https://security.apple.com/blog/pcc-security-research/):
  - $1,000,000 for "Remote attack on request data"
  - $250,000 for access to request data outside the trust boundary
  - $150,000 for "Attack on request data from a privileged network position"
  - $100,000 for "Ability to execute unattested code"
  - $50,000 for "Accidental or unexpected data disclosure due to deployment or configuration issue"
- (29 Jan 2026) Tim Cook on the Google deal: "The personalized version of Siri is a collaboration with Google". He added "We'll continue to run on the device and run in Private Cloud Compute" and that Apple will "maintain our industry-leading privacy standards in doing so." Apple did not disclose the deal's terms. — [9to5Mac, 29 Jan 2026](https://9to5mac.com/2026/01/29/apple-confirms-gemini-powered-siri-will-use-private-cloud-compute/)
- (2 Mar 2026) Press reported that Apple asked Google about running Siri on Google's own servers. — [MacRumors, 2 Mar 2026](https://macrumors.com/2026/03/02/apple-asks-google-to-run-siri)
- (9 Jun 2026, WWDC) The Next Web reported a three-tier design: simple tasks stay on the device, moderate requests go to PCC, and the heaviest reasoning goes to a custom 1.2-trillion-parameter model hosted on Google Cloud servers with "Nvidia Blackwell B200 GPUs." — [The Next Web, 9 Jun 2026](https://thenextweb.com/news/apple-siri-google-gemini-nvidia-privacy-wwdc)
  - Craig Federighi: "We use none of the models that Google deploys to its customers," and "Your requests are completely private to you. They're never stored. They're never accessible to anyone."
  - The Next Web noted that no independent audit of the Google Cloud tier has been published. It also reported that the contract bars Google from training on Apple user data.
  - **Conflict:** Cook's January framing (on device and in PCC) differs from the WWDC reporting of a Google Cloud tier. Most hosting details come from press reports, not from Apple documentation.

#### Google Private AI Compute: for Pixel and Gemini users
- (11 Nov 2025, older) At launch, Google said personal data stays "private to you and is not accessible to anyone else, not even Google." The service runs on Google TPUs with Titanium Intelligence Enclaves (TIE), and devices connect through remote attestation and encryption. The first features were Magic Cue on Pixel 10 and Recorder summaries. — [Google blog, 11 Nov 2025](https://blog.google/technology/ai/google-private-ai-compute/)
- (Nov 2025, older) NCC Group reviewed parts of the system between April and September 2025. — [NCC Group public report](https://www.nccgroup.com/research/public-report-google-private-ai-compute-review/); [The Hacker News, Nov 2025](https://thehackernews.com/2025/11/google-launches-private-ai-compute.html); [The Register, 12 Nov 2025](https://www.theregister.com/2025/11/12/google_touts_private_ai_compute/)
  - **Findings:** a timing side channel in the IP-blinding relay that could help unmask users, and some denial-of-service weaknesses.
  - **Google's response:** it is addressing items including unbounded session message queues and no limit on attestation data requests.
  - **Overall verdict:** The Register summarized the audit as finding that the system mostly keeps session data safe from everyone except Google.
- (Nov 2025, older) eWEEK reported that privacy advocates point out that Google ultimately controls the infrastructure. — [eWEEK](https://www.eweek.com/fr/news/google-private-ai-compute/)
- (23 Sep 2026) Google added persistent server-side memory that replaces the earlier "stateless" tasks. — [Google DeepMind blog, 23 Sep 2026](https://deepmind.google/blog/advancing-private-ai-compute-with-secure-server-side-memory/)
  - Memory is "sealed within dedicated, encrypted storage", and the keys stay on the user's devices.
  - The design uses "Per-user databases shielded by device-derived encryption keys". Data is decrypted only temporarily, in isolated memory, to serve a request.
  - Google says the data is "inaccessible to anyone else, even Google."
  - Devices connect to the enclave over authenticated, end-to-end encrypted channels.
  - Google publishes a "tamper-proof public record of our server software", and cites "an independent audit by a leading cybersecurity firm" without naming the firm.
  - Google's examples include picking up work between a laptop and smart glasses.
  - TechRepublic's headline: "Google Is Building AI Memory Designed to Stay Locked Even From Google." — [TechRepublic](https://www.techrepublic.com/article/news-google-private-ai-memory/)

#### Meta Private Processing and Incognito Chat: for WhatsApp and Meta AI users
- (29 Apr 2025, older) Meta's design — [Engineering at Meta, 29 Apr 2025](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/):
  - **Promise:** "no one except you and the people you're talking to can access or share your personal messages, not even Meta or WhatsApp."
  - **Hardware:** "CPU-based confidential virtualization technologies, along with Confidential Compute mode GPUs."
  - **Relay:** requests travel "via a third-party relay which hides requester IP from Meta and WhatsApp".
  - **Attestation:** "The attestation verification step cross-checks the measurements against a third-party ledger." Meta also commits to "publishing a third-party log of CVM binary digests and CVM binary images."
  - **First uses:** summaries of unread messages and writing suggestions.
- (29 Apr 2025, older) Meta's threat model names "Insiders with physical or remote access to Private Processing hosts" and concedes that "physical attacks on Private Processing hosts may be used to defeat TEE guarantees". Its mitigations are encrypted DRAM, physical data-centre security and host monitoring. — [Engineering at Meta](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/)
- (13 May 2026) Meta launched Incognito Chat with Meta AI, "Built on top of our Private Processing technology". The post cites no independent audit. — [WhatsApp blog, 13 May 2026](https://blog.whatsapp.com/introducing-incognito-chat-with-meta-ai-a-completely-private-way-to-chat-with-ai)
  - **Claims:** "Incognito Chat with Meta AI is truly private — no one can read your conversation, not even us"; "Your messages are processed in a secure environment that even Meta cannot access"; "Your conversations are not saved and by default, your messages disappear".
  - **Rollout:** "over the coming months".
  - **Planned:** "Side Chat with Meta AI will give you private help with any chat".
- (2025–2026) The technical whitepaper has three versions: V1 (10 Jun 2025), V2 (16 Mar 2026) and V3 (20 Oct 2026). — [Meta Private Processing whitepaper](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)

#### Microsoft Azure: for enterprises
- (Sep 2024, older) Two launches — [Microsoft Tech Community: H100 CVM GA](https://techcommunity.microsoft.com/t5/azure-confidential-computing/general-availability-azure-confidential-vms-with-nvidia-h100/ba-p/4242644); [Azure AI Confidential Inferencing preview](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-preview/4248181):
  - Azure confidential VMs with NVIDIA H100 (NCCadsH100v5) became generally available.
  - Azure AI Confidential Inferencing entered preview, starting with the Azure OpenAI Whisper model. Prompts are encrypted so that they can be decrypted only inside TEEs that span the CPU and GPU.
- (current docs) Microsoft's product overview still lists confidential inferencing only for the Whisper model. — [Microsoft Learn](https://learn.microsoft.com/azure/confidential-computing/overview-azure-products)

#### NVIDIA confidential computing: for model builders and clouds
- (2025–2026) NVIDIA's R580 release notes put Blackwell single-GPU passthrough with a bounce buffer (SPT CC mode) at general availability. The R590 notes list the RTX PRO 6000 Blackwell Server Edition and HGX B200. — [NVIDIA R580 notes](https://docs.nvidia.com/confidential-computing/release-notes/r580-trd1.md); [R590 notes](https://docs.nvidia.com/confidential-computing/release-notes/r590-trd1.md)
- (21 Oct 2026) NVIDIA expanded "Confidential Bare Metal" to Grace Blackwell NVL72, to GB300 NVL72 (for Google Cloud's A4X Max) and to HGX/DGX Rubin NVL8. The protections cover model IP as much as user data. — [NVIDIA blog, 21 Oct 2026](https://blogs.nvidia.com/blog/confidential-computing-model-builders-infrastructure/)
  - **Cloud partners:** CoreWeave, Firmus, GMI Cloud, Google Cloud, IREN, Lambda, Microsoft Azure Infrastructure, Nebius, Nscale and Vultr.
  - **Cohere** "plans to integrate Confidential Bare Metal into Cohere Model Vault", "protecting models and data in memory and across interconnects during execution".
  - **Google Cloud's quote** mentions "cryptographic protection for training data and model intellectual property".
- NVIDIA's threat-model documentation says the protections depend on the GPU architecture, security mode, firmware and driver versions. — [NVIDIA CC threat model](https://docs.nvidia.com/confidential-computing/virtual-machines/threat-model.md)

#### AWS Nitro: for EC2 customers
- AWS states that "there is no mechanism for any AWS operator to access an Amazon EC2 instance based on the Nitro System or to access data that customers send to a machine learning (ML) accelerator or GPU". — [AWS Confidential Computing](https://aws.amazon.com/confidential-computing/)
- AWS says Nitro Enclaves "operate only in the CPU, limiting the potential for larger generative AI models". — [AWS Compute Blog](https://aws.amazon.com/blogs/compute/building-zero-trust-generative-ai-applications-in-healthcare-with-aws-nitro-enclaves)
- (Sep 2025, older) EC2 instance attestation uses NitroTPM and Attestable AMIs, which carry a hash over the AMI's full contents. It works with KMS and covers instances with AI chips and GPUs. AWS says these are building blocks that customers must configure. — [AWS What's New, Sep 2025](https://aws.amazon.com/about-aws/whats-new/2025/09/aws-announces-ec2-instance-attestation); [AWS docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html); [Attestable AMIs](https://docs.aws.amazon.com/en_en/AWSEC2/latest/UserGuide/attestable-ami.html)

### Inferences
- **Same pattern, same trust class.** Apple, Google and Meta converge on device-encrypted requests to attested, stateless or now sealed enclaves, a public software log and a third-party relay. Each promise is class T made by the hardware owner, and two of the three write physical or insider attacks into their own threat models. None of them is E2EE in the brief's strict sense.
- **Google's memory overlaps "private agent memory".** Persistent memory under device-held keys is the most direct platform-scale overlap with a private agent-memory feature. It still decrypts inside Google's enclaves, on Google's hardware, inside Google's ecosystem.
- **Apple's Google tier is the weakest link.** Apple's strongest asset is verifiable transparency (a log, binaries and a $1M bounty). The reported Google Cloud tier for heavy Siri requests is the weakest link in Apple's 2026 claim until Apple publishes how that tier is attested and audited.
- **The B2B side sells building blocks.** Azure, NVIDIA and AWS are maturing their offerings (Hopper to Blackwell to Rubin, bare metal and rack scale, instance attestation). The buyers are model builders protecting weights and enterprises protecting data, not end users who verify anything themselves.

### Gaps
- No Microsoft Ignite 2026 announcement was found that extends confidential inferencing beyond Whisper to GPT-family models in Azure OpenAI or Foundry.
- No source says whether Apple's Google Cloud tier runs PCC's software, publishes to Apple's transparency log or is covered by the PCC bounty.
- No adoption figures (users or requests) were found for PCC, Private AI Compute or Private Processing.
- What changed in Meta's V3 whitepaper (20 Oct 2026) was not reviewed. No independent audit of Incognito Chat was found.
- Google did not name the firm that audited server-side memory, or say which products use it.
- AWS: no AWS-run, operator-blind inference service (for example in Bedrock) with customer-verifiable attestation was found. Bedrock was not researched.

## 2. Confidential inference vendors (Tinfoil, Confident Security, Phala/RedPill, NEAR AI, OpenSecret/Maple, Privatemode, Opaque, Fortanix, Chutes, zero-retention clouds): what do they charge, how is attestation done, and who can still read data?

### Takeaway
TEE inference on open-weight models is now crowded and cheap. Tinfoil, NEAR AI, Privatemode and Chutes (see the matrix) list per-token prices at or near ordinary hosting rates. Phala/RedPill (priced per hour), Maple (subscriptions), Confident Security and Cocoon (no prices found) sell the same class of service. Verification lags well behind:
- An independent tracker (snapshot of 26 Nov 2026) finds open gaps at every provider it covers.
- NEAR AI's breach on 8 Nov 2026, through a remote-code-execution flaw in SGLang, showed that an exploitable inference engine inside the TEE can expose "confidential-mode" requests.

In every case the vendor still builds the images, runs the gateway or proxy, or releases the keys. The honest claim is "the operator cannot read it by design" (class T). These offerings are not E2EE, even where they are marketed that way.

### Cited Findings

#### Independent verification: the "Is private inference real yet?" tracker
- (snapshot 26 Nov 2026) The tracker re-verifies attestation bundles across 9 providers and 19 paths, and states "Dated assessments; no stages awarded." — [awesome-private-inference tracker](https://amiller.github.io/awesome-private-inference)
- (Nov 2026) Its main cautions — [tracker](https://amiller.github.io/awesome-private-inference):
  - "A genuine enclave can still run operator-controlled code that logs prompts."
  - "a valid gateway quote is not a model attestation."
  - "Collection counts do not measure privacy."
- (Nov 2026) Findings by provider — [tracker](https://amiller.github.io/awesome-private-inference):
  - **RedPill/Phala (ACI gateway):** the TEE path has the strongest evidence. For the ordinary RedPill path the tracker says "This hostname does not enforce TEE-only serving."
  - **NEAR AI:** marked "Stale / mixed". RTMR0 cannot be pinned, and a client "cannot tell which of the three composes served a request."
  - **Tinfoil:** the TCB is below AMD's fix level on live reads.
  - **Chutes:** "The reviewed Chutes base-TD measurements do not commit to serve.py or model weights."
  - **Venice via Phala:** the inference host's CPU evidence is unattested.
  - **Maple and Privatemode:** "Not assessed", with only a dated source review.

#### Tinfoil: for developers and apps, plus a consumer chat
- (2026) Tinfoil's core claim: "Every request is encrypted directly to an attested secure enclave, verified client-side." — [Tinfoil Inference](https://tinfoil.sh/inference)
  - A testimonial from MZLA Technologies, the company behind Thunderbird, promises "a hardware guarantee that nobody, including us, can see what you send."
  - A DuckDuckGo executive's testimonial says Tinfoil's hardware attestation enforces Duck.ai's zero-retention policy.
- (Nov 2026) Pricing — [Tinfoil pricing](https://tinfoil.sh/pricing):
  - **Chat:** $20 a month.
  - **API, per million tokens (input/output):** GPT-OSS $0.15/$0.60; DeepSeek V4.1 Flash $0.60/$1.45; GLM-5.3 $1.80/$5.75; Kimi K3.1 Pro $4.00/$20.00.
  - **Enclave GPUs** (monthly commitment): H200 $5.90/h, B200 $8.12/h, B300 $9.23/h.
  - **"Bunkers"** ("A dedicated secure enclave", "Encrypted, persistent workspace", "Credential isolation"): $0.32/h.
  - **Enterprise:** custom pricing with an SLA, SSO and audit logs.
- (2026) Recent milestones:
  - Blog posts on "proving model identity" (3 Feb 2026) and Tinfoil Containers (Mar 2026), which run "any containerized workload in a secure enclave". — [Tinfoil blog: model identity](https://tinfoil.sh/blog/2026-02-03-proving-model-identity); [Tinfoil Containers](https://tinfoil.sh/blog/2026-03-06-tinfoil-containers)
  - A Product Hunt launch on 30 Apr 2026. — [Product Hunt](https://www.producthunt.com/products/tinfoil-private-ai-chat)
  - Tinfoil is backed by Y Combinator. — [YC](https://ycombinator.com/companies/tinfoil)
- (2026) Caveats in Tinfoil's own privacy policy: some prompt-prefix state may be cached in encrypted enclave memory, and its web-search MCP servers may send data to third parties. — [Tinfoil privacy policy](https://tinfoil.sh/privacy)

#### NEAR AI Cloud: for developers, and a supplier to Brave and Venice
- (page updated 16 Nov 2026) Claims — [near.ai](https://near.ai/):
  - "We never see plaintext, and there is no operator backdoor, by construction."
  - "Keys never touch our infrastructure."
  - "Memory is sealed from the host and operators."
  - "Every response is signed inside the enclave and backed by a hardware attestation."
  - "Prompts are sent over TLS and only decrypted inside the enclave."
  - "No logs of prompts or responses".
  - Hardware: "Intel TDX + NVIDIA GPU TEE".
- (Nov 2026) Pricing per million tokens (input/output): Qwen 3.8 27B $0.04/$1.35; GLM 5.3 Flash $0.08/$0.50; GLM 5.3 $1.80/$5.75; Kimi K3 $3.30/$16.50. — [near.ai](https://near.ai/)
- (Nov 2026) Adoption: 65 models, of which 11 are "private, in TEEs". Named customers are Brave ("Brave Leo now runs private inference on NEAR AI Cloud, verified by Brave"), Venice, the Government of Bermuda and Abound. — [near.ai](https://near.ai/)
- (8–10 Nov 2026) **Incident.** An attacker exploited a remote-code-execution flaw in SGLang to run code on one inference server, then moved into other infrastructure. — [The Block, 10 Nov 2026](https://www.theblock.co/news/defi/2026-11-10-near-ai-security-breach-437002); [NEAR AI on X](https://x.com/near_ai/status/2120043366444601458)
  - **Exposure:** requests processed on that server on 8 November, including confidential-mode requests, "could have been observed".
  - **Data taken:** account details of about 100 users; chat histories, settings and logs of 18 agents on a legacy deployment outside the TEE; and API keys of two Cloud customers, which had been written to logs.
  - **NEAR AI's statements:** "The SGLang vulnerability let the party run code inside one inference server"; "Confidential computing protects data from the operator and the host"; "It does not protect against a vulnerability in the software running inside the environment".
  - **Response:** Private Chat was taken offline, and NEAR AI Cloud was paused during the investigation and has since been restored.
- (Nov 2026) The Cloud Security Alliance's analysis says the TEE "does nothing against an exploitable inference engine running inside the confidential VM". — [CSA research note, Nov 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-confidential-ai-inference-tee-limits-20261/)

#### Phala Cloud and RedPill: for developers and agent builders
- (2026) Pricing — [Phala pricing](https://phala.network/pricing):
  - Confidential VMs from $0.06/h (Intel TDX).
  - GPU TEE from $4.40/h.
  - RedPill, a serverless inference service, offers "Intel TDX and NVIDIA remote attestation".
  - An unofficial Phala learn page lists H100 TEE at $4.50/GPU/h and H200 at $6.00. — [Phala learn page](https://phala.com/learn/Private-Compute-Cloud-Guide)
- (2026) Phala reports 12,783 cumulative agent CVM deployments (a vendor figure). — [Phala AI agents](https://phala.com/de/solutions/ai-agents)
- (Mar 2026) Phala partnered with Venice to serve Venice's TEE models. — [Phala post](https://phala.com/posts/venice-ai-phala-tee-verifiable-private-ai)
- (Oct 2025, older) TEE.fail showed that a malicious provider could run Phala's dstack workloads in a non-confidential VM while forging attestation. — [TEE.fail](https://tee.fail/)

#### Edgeless Systems Privatemode: for regulated EU organizations and the public sector
- (Nov 2026) Claims — [privatemode.ai](https://www.privatemode.ai/):
  - Privatemode "encrypts your data before it leaves your device and keeps it protected even during AI processing".
  - It describes itself as "Cloud-grade AI with end-to-end encryption and confidential computing".
  - "Compliance enforced by technology, not contracts."
- (Nov 2026) Assurance — [privatemode.ai](https://www.privatemode.ai/):
  - Meets BSI C5:2026 for "very strong attestation".
  - ISO 27001 certified.
  - Two independent evaluations (penetration test and architecture review), with reports available only to Enterprise customers.
  - First place in the Deutscher IT-Sicherheitspreis 2026.
- (Nov 2026) Named "Partners and customers": Airbus, Munich city IT, Capgemini, Nvidia, GitLab, Bechtle and Maple. — [privatemode.ai](https://www.privatemode.ai/)
- (Nov 2026) Pricing — [Privatemode pricing](https://www.privatemode.ai/pricing):
  - Free trial of 5M tokens.
  - Pay-as-you-go from €0.65 per million output tokens.
  - Business plan from €250 a month.
  - Per million tokens (input/output): GLM-5.3 €1.55/€5.74; gpt-oss-120b €0.20/€0.65.
- (2025–2026) Edgeless calls Privatemode the first end-to-end encrypted AI inference service. A March 2026 release says it uses Blackwell GPUs with remote attestation. An Edgeless page says the service runs on Azure, but its architecture means "neither Microsoft nor Edgeless Systems" can access data. — [Edgeless Privatemode product page](https://edgeless.systems/products/privatemode); [Edgeless press](https://www.edgeless.systems/press)

#### OpenSecret and Maple: for privacy-minded consumers, and developers via Maple Proxy
- (2025, older) Maple runs its app code in AWS Nitro enclaves and runs models on NVIDIA GPU TEEs at confidential-computing hosts. Its team says it cannot read chats. — [Stacker News](https://stacker.news/items/972845); [TFTC](https://www.tftc.io/maple-ai-private-encrypted-ai-secure-enclaves-bitcoin)
- (2026) Maple Proxy (v0.2.0) is an open-source, OpenAI-compatible proxy to Maple's TEE backend (enclave.trymaple.ai), suitable for developers and agents. — [docs.rs maple-proxy](https://docs.rs/crate/maple-proxy/0.2.0)
- (2025, older) Launch pricing: a free tier of 10 chats a week, Starter at $5.99 a month and Pro at $20 a month. — [Nostr launch note](https://nostr.at/note1temewxuyydrjakgfudwdnqp6rk9zcp5jfd8rq5axucds8ngh6c8suh4f0s); [AlternativeTo](https://alternativeto.net/software/maple-ai/about)
  - AlternativeTo lists plans up to $100 a month.

#### Confident Security: CONFSEC and the OpenPCC standard, for enterprises
- (5 Nov 2025, older) "Confident Security today released OpenPCC, the first open-source standard that allows companies to use large language models (LLMS) without exposing sensitive data." — [Business Wire, 5 Nov 2025](https://www.businesswire.com/news/home/20251105013372/en); [Axios, 5 Nov 2025](https://axios.com/2025/11/05/openpcc-encryption-ai-mcp-data); [GitHub openpcc](https://github.com/openpcc/openpcc)
  - OpenPCC is modelled on Apple's PCC and uses Oblivious HTTP with a third-party relay.
  - CONFSEC is the managed service: "an enterprise-grade implementation of Apple's Private Cloud Compute (PCC) architecture".
- (2025, older) Funding: a $4.2M seed announced in July 2025, while the November release cites $5M. The figures conflict. The company joined the Confidential Computing Consortium in November 2025. — [Business Wire, 17 Jul 2025](https://www.businesswire.com/news/home/20250717403863/en); [CCC](https://confidentialcomputing.io/?p=3791)
- (9 Jun 2026) **Name clash.** A separate academic "OpenPcc" for commodity TEEs comes from authors at Ohio State and is unrelated to Confident Security. — [arXiv 2606.11145](https://arxiv.org/abs/2606.11145)

#### Opaque Systems: for enterprises
- (12 Feb 2026) Opaque raised a $24M Series B at about a $300M valuation, led by Walden Catalyst with Intel Capital, for $55.5M raised in total. It sells OPAQUE Studio for building "Confidential AI agents" with runtime-verifiable privacy and auditability. — [SiliconANGLE, 12 Feb 2026](https://siliconangle.com/2026/02/12/opaque-raises-24m-300m-valuation-confidential-ai-platform/); [Intel Capital](https://www.intelcapital.com/opaque-raises-24m-series-b-at-300m-valuation-to-advance-confidential-ai-for-the-enterprise/)
- (May 2026) Opaque bought cryptographic AI technology from Abu Dhabi's Technology Innovation Institute (TII). — [SiliconANGLE, May 2026](https://siliconangle.com/2026/05/05/opaque-buys-post-quantum-cryptographic-ai-tech-abu-dhabis-tii/)
- (13 Oct 2026) Anthropic licensed Opaque's technology and hired part of its team; the CEO and CTO are reported to be joining. Opaque continues as a company. Its Confidential MCP project is MIT-licensed. — [Constellation Research](https://constellationr.com/insights/news/anthropic-licenses-releases-opaque-acquihire); [Crypto Briefing](https://cryptobriefing.com/anthropic-licenses-opaque-systems-confidential-ai/)

#### Fortanix
- (Jul 2026) Fortanix's Confidential Computing Manager runs "composite CPU and GPU attestation to verify the integrity of both environments before releasing encrypted assets". Fortanix positions it for agentic systems and sovereign deployments. — [Fortanix blog](https://www.fortanix.com/blog/confidential-ai-the-security-foundation-for-enterprise-ai)

#### Telegram Cocoon (Confidential Compute Open Network): for Telegram and developers
- (Nov–Dec 2025, older) Cocoon went live around 30 November 2025 on the TON blockchain and pays GPU owners in Toncoin. Its developers say requests and responses stay confidential and are known only to the client. Telegram is the anchor customer, and one source names Intel TDX. — [Decrypt](https://decrypt.co/346645/telegram-launches-cocoon-decentralized-ai-network-pays-gpu-owners-crypto); [Cointelegraph](https://cointelegraph.com/news/pavel-durov-cocoon-decentralized-ai-privacy); [AlternativeTo, Dec 2025](https://alternativeto.net/news/2025/12/telegram-launches-cocoon-a-decentralized-confidential-ai-network-on-ton-blockchain)

#### Zero-retention clouds without TEEs (class Z)
- (2026) **Fireworks:** "Fireworks has Zero Data Retention by default. It does not log or store prompt or generation data for any open models, without explicit user opt-in." The Responses API is the exception: with `store=True` (the default), conversation data is kept and deleted after 30 days. — [Fireworks data handling](https://docs.fireworks.ai/guides/security_compliance/data_handling)
- (2026) **Together:** zero data retention is not on by default. An organization admin enables it by setting "Store prompts and model responses" to No. Doing so also disables passthrough models. — [Together ZDR docs](https://docs.together.ai/docs/zero-data-retention)

### Inferences
- **Price is no longer the barrier; proof is.** Attested inference on open-weight models costs about the same as ordinary hosting (for example GPT-OSS at Tinfoil, $0.15/$0.60 per million tokens, or Qwen 3.8 27B at NEAR, $0.04/$1.35). The tracker and the NEAR breach show the hard parts:
  - measuring the serving code and model weights, not just the base image;
  - enforcing a minimum TCB;
  - binding the model's identity to the quote;
  - keeping inference engines such as SGLang patched.
- **Concentration risk.** A few TEE operators sit under many consumer brands: NEAR under Brave and Venice, Phala under Venice and RedPill, and Privatemode listing Maple. One supplier's breach, like NEAR's, can therefore touch several "verifiably private" brands.
- **Vendors still operate the trust chain.** In every case, the vendor writes or chooses the image, operates the gateway that checks attestation (Brave's gateway, Venice's proxy, the RedPill gateway) or releases the keys. This is class T: only the attestation (and client-side checks, where they exist) keeps the vendor honest.
- **Market consolidation.** Anthropic's licensing of Opaque is the clearest sign yet that frontier labs may absorb confidential-inference technology rather than leave the category to startups.

### Gaps
- Confident Security: CONFSEC pricing, customers and production status were not found.
- Fortanix: Armet AI pricing and status were not verified.
- Anyscale: no zero-retention or confidential offering was researched or found.
- Maple: current (2026) pricing could not be retrieved (trymaple.ai returned HTTP 403).
- Cocoon: no 2026 figures on usage or on the number of GPU providers were found.
- The tracker did not assess Privatemode, Maple or Confident Security, so no independent check of their attestation exists in this research.
- NEAR AI did not say whether Brave's or Venice's traffic was among the requests that could have been observed on 8 November.

## 3. Private assistants (Proton Lumo, Venice, Brave Leo, Duck.ai, Kagi Assistant, Moxie Marlinspike's Confer, and other "end-to-end encrypted AI"): what is encrypted end to end, and where is plaintext exposed?

### Takeaway
Consumer "private AI" falls into three tiers:
- **Anonymizing proxies with contractual retention limits (class Z):** Duck.ai, Kagi, and Venice's and Leo's standard modes.
- **Zero-access (E) storage of chat history, with plaintext inference on servers the vendor controls:** Proton Lumo.
- **Device-to-TEE encryption (T+), marketed as "end-to-end encryption", often with E2EE history:** Confer, Maple, Tinfoil Chat, Privatemode, Venice's E2EE models, Brave Leo's E2EE beta (Oct 2026) and Meta's Incognito Chat.

No assistant reviewed keeps plaintext off every server it runs. In each top-tier product, the endpoint that decrypts is a TEE the provider or its supplier operates. Turning on E2EE modes also switches off server features such as web search, file upload and memory.

### Cited Findings

#### Proton Lumo: for consumers (launched 23 Jul 2025)
- (2026 page) Storage and logging — [Proton Lumo privacy](https://proton.me/support/lumo-privacy):
  - Chat histories are "stored on your device and synced to Proton servers using zero-access encryption."
  - "Our no-logs policy ensures we keep no logs of what you ask, or what Lumo replies."
  - Lumo does not store metadata such as timestamps or IP addresses.
- (2026 page) Inference — [Proton Lumo privacy](https://proton.me/support/lumo-privacy):
  - Proton encrypts prompts asymmetrically "so only the Lumo GPU servers are able to decrypt them."
  - Models (Qwen 3.5, GLM 5.3 and Apertus 1.5, among others) "run exclusively on servers Proton controls".
  - The page does not claim a TEE.
- (2026 page) Open source: "Lumo's code is open source, meaning anyone can see it's secure and does what it claims to." — [Proton Lumo privacy](https://proton.me/support/lumo-privacy)
  - A Privacy Guides thread reports that Proton support called open source a "long-term intention, not the instantaneous state". — [Privacy Guides forum](https://discuss.privacyguides.net/t/proton-markets-lumo-as-open-source-but-support-calls-it-a-long-term-intention-not-the-instantaneous-state/30004?page=2)
- (Jul 2025, older) Critics argue that data must exist in cleartext on Proton's servers before it is stored as zero-access history. — [Privacy Guides forum](https://discuss.privacyguides.net/t/proton-markets-lumo-as-open-source-but-support-calls-it-a-long-term-intention-not-the-instantaneous-state/30004?page=2)
- (Jul 2025, older) Launch price: Lumo Plus at $12.99 a month or $119.88 a year. — [TechNave, Jul 2025](https://technave.com/gadget/Proton-Lumo-AI-launches-at-RM59-month--Privacy-focused-AI-Assistant-now-available-on-Web-and-Mobile-43528.html)

#### Venice: for consumers and developers
- (2026 docs) Privacy modes — [Venice privacy docs](https://docs.venice.ai/overview/privacy.md):
  - **Standard:** "Requests pass through Venice over HTTPS/TLS and are relayed without Venice storing prompt or response content"; "Venice does not store or log prompt and response content for normal inference."
  - **Anonymized:** "Prompt content is still visible to that provider."
  - **E2EE:** "Venice relays ciphertext, and only the verified TEE decrypts it."
- (2026 docs) TEE and E2EE models — [Venice TEE/E2EE guide](https://docs.venice.ai/guides/features/tee-e2ee-models.md):
  - "TEE models run inside hardware-secured enclaves (Intel TDX, NVIDIA Confidential Computing)." Even so, "A TEE-only request still reaches the Venice API as plaintext".
  - In E2EE mode, "Your prompts are encrypted before leaving your device, and only the TEE can decrypt them". The scheme uses ECDH on secp256k1, HKDF-SHA256 and AES-256-GCM.
  - E2EE disables web search ("would leak content") and the Venice system prompt, and does not support file uploads. Tool definitions are not encrypted.
- (Mar 2026; one source says Jun 2026) Venice launched E2EE modes on NEAR AI Cloud and Phala, for Pro subscribers. The sources conflict on the launch date. — [Crypto Briefing](https://cryptobriefing.com/encrypted-ai-inference-venice-release); [Phala post](https://phala.com/posts/venice-ai-phala-tee-verifiable-private-ai)

#### Brave Leo: for Brave browser users
- (Nov 2025, older) First phase: TEE inference through NEAR AI (DeepSeek V3.1, on Nightly). Brave verifies the attestation itself and shows users a "Verifiably Private with NEAR AI TEE" label. — [Brave blog: TEE](https://brave.com/blog/browser-ai-tee/); [Privacy Guides news, 20 Nov 2025](https://www.privacyguides.org/news/2025/11/20/brave-announces-verifiable-and-transparent-tee-support-in-leo/)
- (15 Oct 2026) Second phase — [Brave blog, 15 Oct 2026](https://brave.com/blog/browser-ai-e2ee/):
  - **Claim:** Leo chats with GLM 5.3 Flash (which "is in beta") are "protected by end-to-end encryption and hardware-backed confidential computing".
  - **Transport:** Oblivious HTTP with HPKE. Brave's relay "relays the encrypted message without needing to read it"; "Neither Brave, NEAR AI, nor the cloud host can read it"; "Neither the TEE nor Brave Search ever sees your IP."
  - **Who verifies:** "Today, your browser relies on the gateway for this check"; "Next, your browser will check each key against a signed list of the oracle's approvals itself".
  - **Limits Brave states:** the third-party runtime is pinned by an attested deployment log rather than rebuilt from source, and "Every verification chain ends in something you have to trust."

#### Duck.ai: for consumers
- (last updated 16 Nov 2026) Duck.ai's privacy terms — [Duck.ai privacy terms](https://duckduckgo.com/duckai/privacy-terms):
  - Providers named: "Anthropic, Azure OpenAI, OpenAI, together.ai."
  - Providers delete data "(at most within 30 days, with limited exceptions for safety and legal compliance)". They may not use prompts or outputs to improve their models.
  - "All metadata that contains personal information (for example, your IP address) is removed."
  - Recent chats are saved locally. Optional Sync & Backup is stored encrypted, and "the decryption key is only stored on your devices, so only you can decrypt this information." Synced chats are deleted after 18 months without access.
- (2026) Duck.ai's help page states plainly that "Model providers need to see your prompts in order for their models to provide responses." — [DuckDuckGo help](https://duckduckgo.com/duckduckgo-help-pages/privacy-pro/duck-ai/do-any-of-these-providers-see-my-prompts)
  - **Conflict:** another help page describes providers deleting prompts and responses immediately after replying. The terms say at most 30 days.

#### Kagi Assistant: for Kagi subscribers
- (2025–2026) Kagi sends API requests to third-party model providers. — [Kagi LLM privacy](https://help.kagi.com/kagi/ai/llms-privacy.html); [Kagi Assistant docs](https://help.kagi.com/kagi/ai/assistant.html); [Kagi blog](https://blog.kagi.com/assistant-for-all)
  - It publishes each provider's retention; for example, the Anthropic API keeps data 30 days and flagged prompts for 2 years.
  - Kagi says contracts keep providers from training on assistant data.
  - Temporary threads expire 24 hours after the last message.

#### Confer (Moxie Marlinspike): for consumers (launched Dec 2025)
- (5 Jan 2026) Design, from Confer's "Private inference" post — [Confer blog, 5 Jan 2026](https://hn.jakechampion.name/reader/https://confer.to/blog/2026/01/private-inference):
  - The client runs a Noise handshake, and the TEE's attestation quote is returned inside it, which "binds the encrypted channel to the TEE".
  - dm-verity covers the root filesystem, so "any change to any file changes the attestation".
  - nix and mkosi builds give "bit-for-bit reproducible outputs", and releases go to a transparency log: "The log is append-only and publicly auditable."
  - "Confer combines confidential computing with passkey-derived encryption to ensure your data remains private."
  - Sessions use "ephemeral session keys that provide forward secrecy."
  - The post names no TEE vendor and states no threat-model exclusions.
- (Jan 2026) Coverage — [Gizmodo](https://gizmodo.com/signals-founder-turns-his-attention-to-ais-privacy-problem-2000709897); [TechCrunch, 18 Jan 2026](https://techcrunch.com/2026/01/18/moxie-marlinspike-has-a-privacy-conscious-alternative-to-chatgpt); [heise](https://heise.de/-11143673); [Habr](https://habr.com/en/articles/988874):
  - Chat-history keys come from passkeys through WebAuthn PRF and stay on users' devices.
  - Confer uses several open-source models for different tasks without naming them.
  - heise notes that inference still runs on GPU servers.
  - Habr notes that TEE.fail-class attacks undermine the model if an attacker obtains attestation keys.

#### Other TEE chat apps
- (2026) Tinfoil Chat costs $20 a month. — [Tinfoil pricing](https://tinfoil.sh/pricing)
- (2026) Privatemode runs a web chat at chat.privatemode.ai and offers Office and coding integrations. — [privatemode.ai](https://www.privatemode.ai/)
- (Nov 2026) NEAR AI Private Chat was taken offline after the 8 Nov breach. — [The Block](https://www.theblock.co/news/defi/2026-11-10-near-ai-security-breach-437002)
- Meta's Incognito Chat is covered in section 1.

#### OpenAI's stated plans for ChatGPT encryption
- (Aug 2025, older) Sam Altman said OpenAI was "strongly considering" encryption, likely starting with temporary chats. — [Axios, 18 Aug 2025](https://www.axios.com/2025/08/18/altman-openai-chatgpt-encrypted-chats)
- (Nov 2025, older) OpenAI named "client-side encryption" for ChatGPT as a long-term roadmap item. — [OpenAI: fighting NYT privacy invasion](https://openai.com/index/fighting-nyt-user-privacy-invasion/); [Privacy Guides, 15 Nov 2025](https://www.privacyguides.org/news/2025/11/15/openai-announces-plans-for-client-side-encryption-for-chatgpt/)
- (Aug 2025, older) Tinfoil argued that this does not stop OpenAI from seeing conversations unless processing happens without OpenAI holding the key. — [Tinfoil blog](https://tinfoil.sh/blog/2025-08-22-openai-encrypted-chatgpt)

### Inferences
- **"End-to-end encryption" now means something weaker in AI products.** Brave, Venice, Confer coverage, Privatemode, Edgeless and Google's memory post all use the phrase to mean "device to a provider-run, attested enclave". Under the brief's strict definition (only user devices hold keys), none of them is E2EE for compute. The only true E2EE pieces in this set are stored chat history: Lumo's zero-access history, Duck.ai's Sync & Backup and Confer's passkey-encrypted history.
- **E2EE modes strip agent features.** Venice's E2EE mode turns off web search, memory and file upload and leaves tool definitions unencrypted, and Brave's covers one beta model. Agent features (tools, search, memory) are exactly what E2EE modes give up today.
- **Verification is mostly done by a gateway.** In Brave's design the gateway checks attestation on the user's behalf, and in Venice's TEE-only mode the proxy sees plaintext. Client-side verification exists only at Confer and Tinfoil.

### Gaps
- Confer's price was not verified. A figure of $34.99 a month appears only in a copied chat transcript on GitHub Gist, so it is unreliable.
- Not found: Venice Pro and Leo Premium prices, Kagi's subscription price, and the current (2026) Lumo Plus price (only the launch price was found).
- No independent audit was found for Lumo, Confer, Venice's E2EE mode or Brave's E2EE mode.
- No adoption numbers were found for any private assistant.
- Which Duck.ai models, if any, run on Tinfoil is unknown; only a testimonial was found.

## 4. Model labs' privacy modes: what do OpenAI, Anthropic and Google offer (zero data retention, enterprise no-training terms), what do they still log, and what court orders or policy changes affected retention in 2025–2026?

### Takeaway
All three labs offer no-training enterprise terms and approval-gated zero data retention (ZDR). The 2026 trend runs against operator blindness for frontier models, and the labs then answered with "safety without plaintext retention":
- **Anthropic** began requiring 30-day retention of prompts and outputs for its most capable "covered" models, even for ZDR customers, from 9 Jun 2026.
- **OpenAI** responded on 19 Aug 2026 with "Private Safety Processing" and customer-held keys.
- **Anthropic** added "Enterprise Frontier Safeguards" and customer-managed keys.
- **The NYT v. OpenAI litigation** showed that legal holds can override deletion. Deleted consumer chats were preserved from May to September 2025, and a production of 20 million de-identified logs was affirmed on 5 Jan 2026.

All of these are class Z or C. None is TEE-verified (class T) or E2EE (class E).

### Cited Findings

#### OpenAI
- (2026 docs) Default API logging and ZDR — [OpenAI: your data](https://developers.openai.com/api/docs/guides/your-data):
  - Abuse-monitoring logs are kept for up to 30 days.
  - ZDR and Modified Abuse Monitoring are "subject to prior approval by OpenAI and acceptance of additional requirements".
  - "Zero Data Retention ineligible endpoints or capabilities may retain application state when used, even if you have Zero Data Retention enabled."
- (19 Aug 2026; rollout update 22 Sep 2026) Private Safety Processing is "designed to identify patterns across related interactions" while keeping ZDR. — [OpenAI, 19 Aug 2026](https://openai.com/index/offering-zero-data-retention-for-frontier-models/); [Axios, 19 Aug 2026](https://axios.com/2026/08/19/openai-previews-zero-retention-safety-system-as-anthropic-requires-data-logs)
  - In ZDR deployments, customer content stays on infrastructure the customer controls.
  - OpenAI is developing an option to store content on OpenAI infrastructure under customer-controlled keys, where OpenAI personnel "do not have a copy of those keys."
  - Images flagged for potential CSAM "will continue to be retained for manual review and reporting purposes, even in Zero Data Retention deployments."
  - OpenAI does not mention TEEs.
  - **Wording conflict:** earlier descriptions said content would sit in encrypted abuse-monitoring logs on OpenAI-managed infrastructure, excluded from human review unless the law requires it.

#### Anthropic
- (Aug 2025, older) Consumer terms change: users choose whether their chats train models, and Anthropic is "extending data retention to five years, if you allow us to use your data for model training". — [Anthropic, Aug 2025](https://anthropic.com/news/updates-to-our-consumer-terms); [TechCrunch, 28 Aug 2025](https://www.techcrunch.com/2025/08/28/anthropic-users-face-a-new-choice-opt-out-or-share-your-data-for-ai-training/)
- (Jun 2025, older) Anthropic and Pattern Labs (now Irregular) published "Confidential Inference via Trusted Virtual Machines", which protects both model weights and user data inside TEEs. — [Anthropic research](https://www.anthropic.com/research/confidential-inference-trusted-vms); [Irregular](https://www.irregular.com/research/confidential-inference-systems)
- (effective 9 Jun 2026; page current) Covered-model retention — [Claude privacy center](https://privacy.claude.com/en/articles/15425996-data-retention-practices-for-covered-models):
  - **Which models:** "Mythos-class models and future models with similar capabilities that we designate as covered models".
  - **Rule:** "Prompts submitted to, and outputs generated by, covered models are retained for 30 days".
  - **Who it applies to:** ZDR workspaces in Claude Console, Claude Code with ZDR, and ZDR access through AWS Bedrock, Google Cloud Agent Platform and Microsoft Foundry. Consumer plans are not affected.
  - **Rationale:** "Some attacks only become visible across multiple requests."
  - **Human review:** "Human review can occur only through a controlled access path." Every access is recorded in a tamper-proof log.
  - **Options:** eligible organizations can add "customer-managed encryption keys" and access-transparency audit logs, and some organizations may use Fable with ZDR under "Enterprise Frontier Safeguards".
- (Aug–Sep 2026) After customer pushback, reports said Anthropic would still require 30 days of retention but would let business customers keep the data on their own cloud. Customer-controlled monitoring is planned for a phased rollout in fall 2026. — [The Star (Reuters), 21 Aug 2026](https://www.thestar.com.my/tech/tech-news/2026/08/21/anthropic-plans-to-change-enterprise-data-retention-policy-source-says); [WinBuzzer, 3 Sep 2026](https://winbuzzer.com/2026/09/03/anthropic-plans-customer-controlled-ai-monitoring-after-data-retention-pushback-xcxwbn/); [CX Today](https://www.cxtoday.com/security-privacy-compliance/anthropic-zero-data-retention-enterprise-ai/)
- (13 Oct 2026) Anthropic licensed Opaque's confidential-AI technology and hired part of its team. — [Constellation Research](https://constellationr.com/insights/news/anthropic-licenses-releases-opaque-acquihire)

#### Google
- (2026 docs) Gemini Developer API: on paid services, Google logs prompts and responses "for a limited period of time solely for detecting violations of the Prohibited Use Policy". — [Gemini API ZDR](https://ai.google.dev/gemini-api/docs/zdr?hl=en)
  - Implicit caching "is strictly in RAM (not at-rest), isolated at the project level, and has a 24-hour TTL. This does not violate Zero Data Retention."
  - Files uploaded through the File API persist until deleted.
  - For guaranteed ZDR, Google points customers to Vertex AI.
- (2026 docs) Vertex AI, now under the "Gemini Enterprise Agent Platform" name — [Vertex/Agent Platform ZDR](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/data-governance):
  - Abuse-monitoring prompt logging applies to customers under the Google Cloud Platform terms who lack invoiced billing, and they can request an exception.
  - ZDR requires `store=false` (the default is true) and disabled caching.
  - "There is no way to disable the storage of this information if you use Grounding with Google Search."
- (support page updated May 2026) Gemini Apps: "Chats reviewed by human reviewers ... are not deleted when you delete your activity. Instead, they are retained for up to three years." Gemini Apps Activity is on by default. — [Gemini Apps Privacy Hub](https://support.google.com/gemini/answer/13594961?hl=en)

#### Court orders and legal compulsion
- (13 May 2025, older) In NYT v. OpenAI, Magistrate Judge Ona Wang ordered OpenAI to "preserve and segregate all output log data that would otherwise be deleted", including chats users had deleted. One source says the duty ran from 13 May to 26 September 2025. — [llms-for-lawyers](https://www.llms-for-lawyers.com/confidentiality/nyt-v-openai-deleted-chatgpt-chats-lawyers/); [AI Lawsuit Tracker](https://ailawsuittracker.com/cases/new-york-times-v-openai/)
- (Nov 2025, older) Wang ordered OpenAI to produce 20 million de-identified ChatGPT logs, finding the sample "proportional to the needs of the case". — [The Decoder, Nov 2025](https://the-decoder.com/openai-ordered-to-turn-over-20-million-chatgpt-chats-to-the-new-york-times/); [ABA Journal](https://www.abajournal.com/news/article/chatgpt-creator-must-turn-over-20m-chat-logs-in-copyright-litigation-federal-judge-says)
- (5 Jan 2026) District Judge Sidney Stein affirmed the order. — [Yahoo News](https://www.yahoo.com/news/articles/openai-ordered-hand-over-20m-035748762.html); [eWEEK](https://www.eweek.com/news/openai-chatgpt-logs-new-york-times-copyright-mdl/)
- (Nov 2025, older) OpenAI said the preservation order did not affect ChatGPT Enterprise, Edu, Business or API customers. — [OpenAI](https://openai.com/index/fighting-nyt-user-privacy-invasion/)

### Inferences
- **2026 took frontier models further from operator blindness, not closer.** The labs now treat cross-request safety monitoring as a reason to retain data. The privacy answers on offer are customer-held keys, controlled-access human review and customer-side storage (classes C and Z), not attestation or E2EE. Anthropic's licensing of Opaque and its 2025 confidential-inference paper suggest a future TEE path, but nothing has shipped as of 26 Nov 2026.
- **What a direct-to-lab disclosure must cover.** If remote models are reached "direct with a disclosure", it should cover:
  - OpenAI's default 30-day abuse logs and its CSAM carve-out;
  - Anthropic's 30-day retention for covered models (even under ZDR);
  - Google's search-grounding storage and up-to-three-year human-review retention in Gemini Apps;
  - court preservation orders, which can reach data a user deleted.
- **Contracts can change.** Anthropic's June 2026 change, made mid-contract for ZDR customers, shows that contractual privacy is revocable in a way an architecture is not.

### Gaps
- OpenAI's promised September 2026 technical white paper on Private Safety Processing was not found or reviewed.
- Whether Anthropic's "Enterprise Frontier Safeguards" are generally available as of November 2026 is unclear.
- Whether the NYT case has a trial date, or brought any 2026 change to preservation duties, was not established.
- Court orders in 2026 affecting Anthropic or Google retention were not found. None may exist, or they may not have surfaced.

## 5. Does anyone offer end-to-end encryption for agent activity, agent memory or agent networking (not just one chat)? Who are the nearest competitors?

### Takeaway
No product found encrypts agent actions, memory, messaging and files together under keys only users hold. The nearest competitors each cover one surface:
- **Agent messaging, true E2EE:** XMTP's MLS network, and Microsoft's draft AgentMesh WIRE 1.0 protocol.
- **Agent memory:** Google Private AI Compute's server-side memory (23 Sep 2026), which uses device-held keys but decrypts inside Google's TEEs.
- **Agent runtimes in TEEs:** Tinfoil Bunkers and Containers, Phala's agent CVMs, NEAR AI agents, and Opaque Studio (now licensed to Anthropic).
- **E2EE chat history only:** Confer, Duck.ai Sync and Lumo.

The research literature still treats private AI memory as an open problem. NEAR AI's breach exposed exactly the agent state that sat outside the encryption boundary.

### Cited Findings

#### Agent messaging and networking
- (2026) XMTP is open source and offers E2EE DMs and groups for people and AI agents. — [xmtp.org](https://xmtp.org/); [XMTP agent docs](https://docs.xmtp.org/agents/get-started/intro); [Hashgraph Online](https://hol.org/docs/registry-broker/xmtp/)
  - It uses MLS with forward secrecy and post-compromise recovery, plus a hybrid post-quantum key exchange for welcome messages.
  - NCC Group assessed the MLS implementation in 2024.
  - Agents get their own identities and keys. The SDK "provides the messaging rails", while the agent's logic runs separately and sees plaintext.
  - Backend operators can still see metadata, timing and message sizes.
  - Adoption: "Billions of messages sent since 2022."
- (2026, status unclear) An XMTP docs file dated March 2026 expected the decentralized mainnet to launch in "early 2026". — [XMTP llms.txt](https://docs.xmtp.org/llms.txt)
- (draft, 21 Apr 2026) Microsoft's AgentMesh WIRE 1.0 — [AgentMesh WIRE 1.0](https://microsoft.github.io/agent-governance-toolkit/specs/AGENTMESH-WIRE-1.0/):
  - "This specification defines the wire protocol for E2E encrypted agent-to-agent messaging in the Agent Governance Toolkit."
  - It uses X3DH and the Double Ratchet. The relay "sees only ciphertext" but can see sender and recipient DIDs, timestamps and sizes.
  - The spec warns that "a compromised registry can perform MitM by substituting pre-keys".
  - It covers one-to-one messaging only.
- (Aug 2026) An individual IETF draft proposes MLS for agent-to-agent (A2A) messaging. It is experimental, not a standard. — [draft-chapman-a2a-mls](https://datatracker.ietf.org/doc/draft-chapman-a2a-mls/)

#### Agent memory
- (23 Sep 2026) Google's server-side memory uses "Per-user databases shielded by device-derived encryption keys" and promises data "inaccessible to anyone else, even Google". It is processed in Google's enclaves. — [Google DeepMind](https://deepmind.google/blog/advancing-private-ai-compute-with-secure-server-side-memory/)
- (2 Apr 2026) The Opal paper (Kaviani, Ozdarendeli, Zhu, Ding and Popa) — [arXiv 2604.02522](https://arxiv.org/abs/2604.02522):
  - "Trusted hardware can keep this data private, but struggles to scale with a growing datastore."
  - It confines reasoning to an enclave and uses ORAM so that "Untrusted disk then sees only fixed, oblivious memory accesses."
  - "Opal is under consideration for deployment to millions of users at a major AI provider."
- (2026) Small open-source libraries such as VaultMem and Engram, and the MemTrust paper, claim encrypted agent memory. Many similar pages describe only at-rest encryption with server-held keys. — [MemTrust, arXiv Jan 2026](https://arxiv.org/html/2601.07004v1); [VaultMem on PyPI](https://pypi.org/project/vaultmem/0.1.1/)

#### Agent runtimes in TEEs
- (Nov 2026) Tinfoil Bunkers ("A dedicated secure enclave", "Encrypted, persistent workspace", "Credential isolation", $0.32/h) and Tinfoil Containers ("Run any containerized workload in a secure enclave"). — [Tinfoil pricing](https://tinfoil.sh/pricing)
- (2026) Phala reports 12,783 agent CVM deployments, and its templates include the Agno framework. — [Phala AI agents](https://phala.com/de/solutions/ai-agents); [DEV Community](https://dev.to/soulman_250/your-ai-agents-are-leaking-deploy-agno-on-phala-cloud-and-fix-that-today-1mm8)
- (Feb 2026) Opaque Studio builds "Confidential AI agents" with runtime-verifiable privacy, policy compliance and auditability. Its Confidential MCP project continues under the MIT licence after Anthropic's October 2026 deal. — [SiliconANGLE](https://siliconangle.com/2026/02/12/opaque-raises-24m-300m-valuation-confidential-ai-platform/); [Constellation Research](https://constellationr.com/insights/news/anthropic-licenses-releases-opaque-acquihire)
- (2026) NVIDIA's Secure Agent Workspace is an enterprise reference design for governed agent VMs. It is about isolation and governance, not encryption against the operator. — [NVIDIA SAW](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)
- (2026) A Confidential Computing Summit 2026 talk: "The TEE protects bytes, not meaning". In other words, TEEs do not stop prompt injection. — [CC Summit 2026 slides](https://hosted-files.sched.co/ccsummit2026/7a/Confidential%20Computing%20Summit%202026.pdf)

#### Incident: agents outside the enclave
- (8–10 Nov 2026) NEAR AI's breach exposed chat histories, settings and logs of 18 agents on a legacy deployment that did not run in the TEE. — [The Block](https://www.theblock.co/news/defi/2026-11-10-near-ai-security-breach-437002); [Bonfy blog](https://blog.bonfy.ai/near-ai-agent-data-breach-lessons)

#### Trust-model matrix (all products in this file; facts sourced in the bullets above)
| Product (audience) | Class | Who can still read plaintext | Verifiability | Price found | Main limit | Sources |
|---|---|---|---|---|---|---|
| Apple PCC (Apple Intelligence users) | T | Apple only via the physical or supply-chain attack its own threat model admits | Transparency log, research environment, binaries, $1M bounty | Bundled | Heavy Gemini Siri tier on Google Cloud, unaudited (Jun 2026) | [Apple](https://security.apple.com/blog/private-cloud-compute/); [TNW](https://thenextweb.com/news/apple-siri-google-gemini-nvidia-privacy-wwdc) |
| Google Private AI Compute + memory (Pixel/Gemini users) | T; memory keys held on devices | Google via hardware; NCC found a timing side channel in the relay | Attestation, public software record, NCC 2025, unnamed 2026 audit | Bundled | Google controls the infrastructure | [Google](https://blog.google/technology/ai/google-private-ai-compute/); [DeepMind](https://deepmind.google/blog/advancing-private-ai-compute-with-secure-server-side-memory/) |
| Meta Private Processing / Incognito Chat (WhatsApp) | T + third-party relay | Insiders with physical access (Meta's own threat model) | Third-party ledger; whitepaper V3 | Free | No audit cited for Incognito Chat | [Meta](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/) |
| Azure confidential GPU VMs / inferencing (enterprises) | T | Customer's own code; Microsoft excluded by design | Attestation | Not found | Inferencing listed for Whisper only | [Microsoft Learn](https://learn.microsoft.com/azure/confidential-computing/overview-azure-products) |
| NVIDIA confidential computing (model builders, clouds) | T building block | Relies on the CPU CVM; attestations can be "borrowed" | NVIDIA attestation | n/a | No NVIDIA-side fix for interposers | [NVIDIA](https://blogs.nvidia.com/blog/confidential-computing-model-builders-infrastructure/); [TEE.fail](https://tee.fail/) |
| AWS Nitro / EC2 attestation (EC2 customers) | Operator excluded by Nitro design | AWS hardware and design | NitroTPM, Attestable AMIs | EC2 rates | Building blocks; Nitro Enclaves are CPU-only | [AWS](https://aws.amazon.com/confidential-computing/) |
| Tinfoil (developers; chat) | T+ | Only via a TEE break or code Tinfoil ships; web-search MCP sends to third parties | Client-side attestation, open source | Chat $20/mo; GPT-OSS $0.15/$0.60 | TCB below AMD fix level (tracker) | [Tinfoil](https://tinfoil.sh/pricing); [tracker](https://amiller.github.io/awesome-private-inference) |
| NEAR AI Cloud (developers; supplies Brave, Venice) | T+ | An attacker with RCE in the engine (8 Nov 2026) | Signed attestation per response; public stack | Qwen 3.8 27B $0.04/$1.35 | Breach; RTMR0 can't be pinned; 3 compose hashes | [near.ai](https://near.ai/); [The Block](https://www.theblock.co/news/defi/2026-11-10-near-ai-security-breach-437002) |
| Phala Cloud / RedPill (developers, agents) | T (dstack) | Non-TEE backends on the ordinary RedPill path | TDX + NVIDIA attestation | GPU TEE from $4.40/h | TEE.fail forged dstack attestation | [Phala](https://phala.network/pricing); [tracker](https://amiller.github.io/awesome-private-inference) |
| Privatemode (EU regulated, public sector) | T+ (sold as E2EE) | Edgeless and Azure excluded by design | Attestation; BSI C5:2026; ISO 27001; pen tests | From €0.65/M output tokens; from €250/mo | Not independently assessed by the tracker | [Privatemode](https://www.privatemode.ai/pricing) |
| Maple / OpenSecret (consumers; developers via proxy) | T (Nitro + GPU TEE); E history | Only via a TEE break | Open source | $5.99–$20/mo (2025) | 2026 status and pricing unverified | [Stacker News](https://stacker.news/items/972845) |
| Confident Security CONFSEC / OpenPCC (enterprises) | T + OHTTP relay | Not specified | Open standard | Not found | Little public production evidence | [Business Wire](https://www.businesswire.com/news/home/20251105013372/en) |
| Opaque (enterprises; licensed to Anthropic) | T | Not specified | "Runtime-verifiable" claims | Not found | Future unclear after the Anthropic deal | [Constellation](https://constellationr.com/insights/news/anthropic-licenses-releases-opaque-acquihire) |
| Chutes SN64 (developers) | T+ via `/e2e/invoke` | Miners with physical access; serving code and weights unmeasured | TDX + NVIDIA evidence | From $0.039/M input tokens | Code and weights unmeasured | [Earlier report](<../../design/reports/Bittensor TEE inference and enclaves.md>); [tracker](https://amiller.github.io/awesome-private-inference) |
| Targon SN4, Lium SN51, Hippius SN75, Cathedral SN94 | T rentals | Operator builds the images or holds the disk keys | Partial or none | Varies | Beta or preview | [Earlier report](<../../design/reports/Bittensor TEE inference and enclaves.md>) |
| Telegram Cocoon (Telegram, developers) | T on GPU owners' machines | GPU owners with physical access | Not assessed | Paid in TON | Hardware held by decentralized operators | [Decrypt](https://decrypt.co/346645/telegram-launches-cocoon-decentralized-ai-network-pays-gpu-owners-crypto) |
| Fireworks / Together (developers) | Z | Provider | Contract | Standard rates | ZDR is default only at Fireworks, for open models | [Fireworks](https://docs.fireworks.ai/guides/security_compliance/data_handling); [Together](https://docs.together.ai/docs/zero-data-retention) |
| Proton Lumo (consumers) | E history; plaintext inference | Proton's GPU servers | Code "open source" (disputed) | $12.99/mo (2025) | Cleartext at Proton during inference | [Proton](https://proton.me/support/lumo-privacy) |
| Venice (consumers, developers) | Z / T / T+ | Model provider (standard); Venice API (TEE-only mode) | Attestation via NEAR and Phala | Pro (price not found) | E2EE disables search, files and memory | [Venice](https://docs.venice.ai/guides/features/tee-e2ee-models.md) |
| Brave Leo (browser users) | Z standard; T+ beta | NEAR's stack if compromised | Brave's gateway and open-source oracle | Not found | Browser trusts the gateway | [Brave](https://brave.com/blog/browser-ai-e2ee/) |
| Duck.ai (consumers) | Z proxy; E sync | OpenAI, Anthropic, Azure OpenAI, together.ai | Contract | Not found | Providers keep data up to 30 days | [DDG](https://duckduckgo.com/duckai/privacy-terms) |
| Kagi Assistant (subscribers) | Z | Model providers | Contract | Not found | Retention depends on the provider | [Kagi](https://help.kagi.com/kagi/ai/llms-privacy.html) |
| Confer (consumers) | T+ inference; E history | Only via a TEE break | Reproducible builds, transparency log, attestation bound to the channel | Unverified | No physical-attack exclusions stated | [Confer](https://hn.jakechampion.name/reader/https://confer.to/blog/2026/01/private-inference) |
| OpenAI API (ZDR, Private Safety Processing) | Z / C | OpenAI during processing; CSAM retained | Contract | Standard rates | Approval-gated; legal holds | [OpenAI](https://openai.com/index/offering-zero-data-retention-for-frontier-models/) |
| Anthropic API (ZDR, covered models) | Z / C | Anthropic (30 days for covered models) | Contract; tamper-proof access log | Standard rates | Retention for Mythos-class models | [Claude privacy](https://privacy.claude.com/en/articles/15425996-data-retention-practices-for-covered-models) |
| Google Gemini API / Vertex ZDR | Z | Google | Contract | Standard rates | Search-grounding storage; 3-year human-review retention in Gemini Apps | [Google](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/data-governance) |
| XMTP (apps, agents) | E (messaging only) | Node operators see metadata; agents see plaintext | NCC 2024 MLS review; open source | Not found | Covers messaging, not compute | [XMTP](https://xmtp.org/) |
| Microsoft AgentMesh WIRE 1.0 (draft) | E (one-to-one messaging) | Relay sees metadata; registry MitM risk | Spec only | Open | Draft; no groups | [Spec](https://microsoft.github.io/agent-governance-toolkit/specs/AGENTMESH-WIRE-1.0/) |

### Inferences
- **Where an E2EE network for people and agents stands apart:**
  - **Scope.** It would cover several surfaces at once: agent actions, memory, messaging and files. Each competitor covers one (XMTP messaging, Google memory, Tinfoil, Phala or NEAR runtimes, Confer, Duck.ai or Lumo history).
  - **A stricter server rule.** Every assistant and inference vendor reviewed lets a provider-run TEE see plaintext. A rule that no server the company runs sees plaintext, even inside a TEE, holds only for pure E2EE storage and messaging (XMTP, Duck.ai Sync, Lumo history). No AI agent product found holds to it.
  - **Labelled compute.** Per-model labels (local, attested TEE with what the attestation proves, or direct with a disclosure) match what the independent tracker and the CSA say claims should state. The only consumer precedent found is Brave's "Verifiably Private with NEAR AI TEE" label.
  - **A team-only action feed.** No competitor offers an encrypted feed of agent actions that only the team can read. Enterprise "auditability" (Opaque Studio, Anthropic's access-transparency logs) is visible to the provider or records the provider's own access.
- **Threats to that position:**
  - Platforms can ship "private memory" and "private side chats" to billions of users (Google's memory, Meta's planned Side Chat).
  - XMTP already runs an E2EE network that includes agents.
  - "End-to-end encrypted" is being diluted into "encrypted to our enclave", so a stricter claim needs explicit wording to register with users.
  - Any remote TEE inference the network uses inherits every limit in section 6.
- **The NEAR breach supports E2EE-by-default agent state.** NEAR's 18 leaked agents ran outside the TEE, so a design where agent memory and logs are encrypted under users' keys from the start addresses a failure that has already happened.

### Gaps
- XMTP's current mainnet status, fees and agent-specific adoption figures were not established.
- The "major AI provider" considering Opal is unnamed, and no link to Google's memory feature is established.
- No product was found offering E2EE agent action logs. This is absence of evidence from search, not proof that none exists.
- Microsoft's AgentMesh WIRE 1.0 revision history is unclear: it cites an audit document dated after the spec itself.

## 6. What do published attacks on TEEs and confidential GPUs in 2024–2026 (TEE.fail, Battering RAM, WireTap and others) mean for "the provider can't read it" claims?

### Takeaway
Between 2025 and 2026, researchers showed four ways past TEE protections:
- **Physical memory-bus interposers costing $50 to under $1,000** that break Intel SGX, Intel TDX and AMD SEV-SNP, including SEV-SNP with Ciphertext Hiding. They can forge attestations, including NVIDIA GPU attestations "borrowed" across machines.
- **Firmware and host attacks** that forge SEV-SNP attestation (Mior, 2026).
- **Side channels and audit findings** against TDX (TDXRay; the Google–Intel audit of TDX 1.5).
- **Ordinary software bugs inside the enclave**, such as SGLang remote code execution (NEAR AI, Nov 2026).

Intel, AMD and NVIDIA treat physical attacks as outside their threat models. A TEE claim therefore protects against remote attackers and host software, not against whoever has physical access, and never against bugs in the code inside. The weakest case is hardware held by anonymous operators: miners, GPU owners and decentralized nodes.

### Cited Findings

#### Physical memory-bus attacks
- (Sep–Oct 2025, older) Two DDR4 attacks — [Kaspersky blog](https://www.kaspersky.com/blog/wiretap-battering-ram-tee-attacks/54598/); [TechRadar](https://www.techradar.com/pro/security/battering-down-the-doors-usd50-hacking-kit-is-enough-to-break-intel-and-amds-toughest-chip-defenses); [TechSpot](https://www.techspot.com/news/109712-trusted-enclaves-intel-amd-shown-vulnerable-physical-attacks.html):
  - **Battering RAM** (KU Leuven and the University of Birmingham) uses an interposer under $50 to alias memory at runtime. It gives arbitrary plaintext reads and writes of SGX enclave memory and falsifies AMD SEV-SNP attestation. Sources disagree on the full extent of the SEV-SNP impact.
  - **WireTap** passively captures DDR4 traffic to break SGX, with a rig costing under $1,000.
  - Both were limited to DDR4, so DDR5-only TDX was then unaffected.
- (Oct 2025, older; IEEE S&P '26) TEE.fail — [TEE.fail](https://tee.fail/):
  - **Scope:** it can "extract cryptographic keys from Intel TDX and AMD SEV-SNP with Ciphertext Hiding", and "we can forge attestations from both TDX and SGX."
  - **NVIDIA:** "extracted attestation keys can be used to compromise Nvidia's GPU Confidential Computing". NVIDIA attestation reports "are not bound to the identity of a specific CVM", so they can be "borrowed".
  - **Cost:** "under $1000 to build a setup similar to ours". The DDR5 interposer kit fits in a briefcase.
  - **Demonstrations:** a malicious provider could run Phala's dstack workloads in a non-confidential VM while forging attestation. The team also extracted Secret Network's consensus seed.
  - **Vendor responses:** Intel says "interposer attacks are considered out of the threat model for Intel SGX and TDX". AMD has no plan for SEV-SNP firmware updates. "there are no mitigations from the Nvidia CC side".
  - **Authors:** Georgia Tech, Purdue and van Schaik, LLC.
- (Oct 2026) DDRop manipulates DDR5 traffic so that an attacker with physical access can force confidential VMs into debug mode and extract memory. KU Leuven, ETH Zurich, Google and Durham researchers published proof-of-concept code. Intel says the attack is outside its cloud threat model. This is from secondary coverage; the primary paper was not reviewed. — [GBHackers, Oct 2026](https://gbhackers.com/intel-tdx-under-attack/); [Cybersecurity News](https://cybersecuritynews.com/new-ddrop-attack/)

#### Firmware, host-software and side-channel attacks in 2026
- (Feb 2026) A joint Google–Intel review of TDX 1.5 (including live migration) found one flaw that lets a VMM fully compromise a trust domain, plus four that leak confidential memory. Another report counts ten defects, nine of them fixed in TDX code. — [SecurityWeek](https://www.securityweek.com/google-intel-security-audit-reveals-severe-tdx-vulnerability-allowing-full-compromise/); [SecurityWeek audit summary](https://www.securityweek.com/google-audit-finds-vulnerabilities-in-intel-tdx/amp/)
- (Apr 2026) TDXRay (UC San Diego, CISPA and Google): a malicious host can infer data from confidential VMs. Intel's mitigation guidance relies on side-channel-safe software inside the trust domain. — [Intel security announcement 2026-04-02-001](https://www.intel.com/content/www/us/en/security-center/announcement/security-announcement-2026-04-02-001.html)
- (published 10 Nov 2026) Two AMD SEV-SNP flaws — [CSA research note, Nov 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-confidential-ai-inference-tee-limits-20261/):
  - **Mior (CVE-2026-0462):** a host with hypervisor and BIOS control can read and write guest memory and forge attestation reports, on EPYC 7003 through 9005. ETH Zurich reported success in all 1,000 attempts on a Zen 5 EPYC 9135. SEV firmware mitigations shipped 12 Aug 2026, but the platform-firmware fix for OEM BIOS is targeted for December 2026.
  - **Skyfall (CVE-2026-40671):** leaks guest register state through a transient-scheduler side channel on Zen 3 and Zen 4.

#### Software inside the TEE
- (30 Jul 2026) CERT/CC VU#281278 lists six SGLang vulnerabilities, including unauthenticated RCE through pickle deserialization (CVE-2026-15969). No patches existed at publication, and as of 16 Nov 2026 no fixed release was reported. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-confidential-ai-inference-tee-limits-20261/)
- (8 Nov 2026) NEAR AI's SGLang breach: confidential-mode requests on the compromised server could have been observed (see section 2). The CSA's lesson: a TEE "does not protect a workload from its own software", and confidential computing "should be positioned as one layer of defense, not as a guarantee." — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-confidential-ai-inference-tee-limits-20261/)
- (Nov 2026) The tracker's equivalent point: "A genuine enclave can still run operator-controlled code that logs prompts." — [tracker](https://amiller.github.io/awesome-private-inference)

#### GPU-specific findings
- (Apr 2026) GPUBreach is a GDDR6 RowHammer attack that reaches full system compromise. NVIDIA was investigating a fix. It is not tied to GPU confidential-computing attestation. — [CSA research note, Apr 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-gpubreach-gddr6-rowhammer-20260408-csa-sty/)
- (Nov 2026) The CSA says no attack on GPU confidential computing itself has been demonstrated, but that it likely inherits CPU TEE weaknesses because it is built on SEV-SNP or TDX confidential VMs. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-confidential-ai-inference-tee-limits-20261/)
- (2026) IBM Research published an MLSys 2026 security analysis, "Blueprint, Bootstrap, and Bridge", of NVIDIA GPU confidential computing. Its findings were not retrieved. — [MLSys 2026](https://mlsys.org/virtual/2026/oral/3741); [IBM Research](https://research.ibm.com/publications/blueprint-bootstrap-and-bridge-a-security-look-at-nvidia-gpu-confidential-computing)

#### What the platforms themselves concede
- (2024–2025, older) Apple's threat model includes a sophisticated attacker with physical access who could extract data being processed. Meta says "physical attacks on Private Processing hosts may be used to defeat TEE guarantees". — [Apple](https://security.apple.com/blog/private-cloud-compute/); [Meta](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/)
- (15 Oct 2026) Brave: "Every verification chain ends in something you have to trust" (Intel, NVIDIA, dstack, Sigstore, GitHub, Hugging Face, DNS). — [Brave](https://brave.com/blog/browser-ai-e2ee/)

### Inferences
- **What "the provider can't read it" honestly means.** As of 26 Nov 2026 the defensible version is: "the provider can't read it remotely, through host software, as long as firmware is current and the code inside the enclave is sound and measured." It does not hold against anyone with physical access to the server (all three chip vendors exclude interposers) or against a compromised inference engine.
- **GPU attestation inherits the CPU's weaknesses.** TEE.fail and the CSA can be reconciled: no one has broken the GPU's own memory protection, but GPU attestation can be subverted through the CPU TEE and unbound reports. A GPU attestation therefore proves less than it appears to.
- **Who holds the hardware matters.** Claims are strongest at large clouds with physical controls (Apple, Google, Meta, Azure). They are weakest on networks where anonymous operators own the machines (Cocoon GPU owners, Chutes miners, Phala nodes), which is exactly the scenario the interposer papers model.
- **What a trustworthy label should state.** A label for remote TEE inference should state the minimum TCB and firmware level, whether serving code and model weights are measured, and the physical-access caveat. These are the CSA's recommendations: minimum TCB checks, reproducible builds, patch cadence and incident disclosure.

### Gaps
- Older attacks were not re-verified in this session: BadRAM (Dec 2024, SEV-SNP via the memory module's SPD chip), Heracles, RMPocalypse and similar 2025 SEV-SNP papers.
- The primary DDRop paper and its affected TDX versions were not reviewed.
- The MLSys 2026 NVIDIA paper's specific findings are unknown.
- No published attack on Apple PCC or Google TIE hardware was found. That may reflect the proprietary hardware and the research access it allows, not robustness.

## 7. Demand signals: what do enterprises and consumers say about private AI (surveys and reports from Cisco, IBM, Gartner, Pew, KPMG and others), and what regulation drives it (EU AI Act 2026 obligations, GDPR enforcement on AI, HIPAA)?

### Takeaway
Enterprise worry about AI data leakage is high and rising, and governance lags behind:
- **IBM (Jul 2026):** shadow AI was involved at 43% of breached organizations (up from 20%), and 68% lack AI governance.
- **Netskope (Jan 2026):** the average organization logs 223 incidents a month of sensitive data sent to AI apps.
- **Gartner (2025):** 69% of organizations suspect or have evidence of prohibited GenAI use.

Consumers distrust AI with their data: 71% of US adults say AI will make their personal information less secure (Pew, 2026). Gartner made confidential computing a 2026 top technology trend. Regulatory deadlines slipped in 2026, though:
- the EU AI Act's high-risk obligations moved to December 2027 and August 2028;
- the HIPAA Security Rule overhaul moved to July 2027.

GDPR enforcement against AI chatbots continues. Litigation (NYT v. OpenAI) has taught the public that AI chats can become evidence.

### Cited Findings

#### Enterprise: data leakage and shadow AI
- (29–30 Jul 2026) IBM Cost of a Data Breach 2026 — [IBM newsroom, 29 Jul 2026](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average?lnk=hpln1id); [Help Net Security, 30 Jul 2026](https://www.helpnetsecurity.com/2026/07/30/ibm-cost-of-a-data-breach-2026/); [Kiteworks summary](https://www.kiteworks.com/cybersecurity-risk-management/ibm-2026-breach-report-ai-governance/):
  - Shadow AI was involved at 43% of breached organizations, up from 20%. Breaches involving shadow AI cost $5.39M on average, up from $4.63M.
  - 68% of organizations lack AI governance, up from 63% in 2025. 92% of organizations with an AI-related breach lacked proper AI access controls.
  - The global average breach cost a record $4.99M, up 12%.
  - IBM's headline: one in four malicious breaches is AI-enabled, at about $6M each.
- (Jan 2026) Netskope Cloud and Threat Report 2026 — [TechRadar](https://www.techradar.com/pro/security/average-organization-now-reporting-over-200-genai-related-data-policy-violations-each-month); [BetaNews, 6 Jan 2026](https://betanews.com/2026/01/06/genai-data-policy-violations-more-than-doubled-in-2025/); [Netskope](https://www.netskope.com/resources/cloud-and-threat-reports/cloud-and-threat-report-2026):
  - The average organization logs 223 incidents a month of sensitive data sent to AI apps, and the top quartile about 2,100.
  - Regulated data makes up 54% of GenAI policy violations.
  - 47% of GenAI users still use personal accounts, down from 78%.
  - Prompts per organization rose from 3,000 to 18,000 a month.
- (Jul 2026) Netskope's AI Report adds "downstream" violations: 924 per 10,000 AI alerts, against 8,752 upstream. — [IT Brief](https://itbrief.com.au/story/netskope-says-downstream-ai-data-breaches-are-surging)
- (Mar–May 2025 fieldwork, older) Gartner's survey of 302 cybersecurity leaders — [ITPro](https://www.itpro.com/technology/artificial-intelligence/gartner-says-40-percent-of-enterprises-will-experience-shadow-ai-breaches-by-2030-educating-staff-is-the-key-to-avoiding-disaster); [Infosecurity Magazine](https://infosecurity-magazine.com/news/gartner-40-firms-hit-shadow-ai):
  - 69% suspect or have evidence that staff use prohibited public GenAI, and 79% report misuse of approved tools.
  - Gartner predicts that by 2030 more than 40% of enterprises will have incidents from unauthorized shadow AI.
- (20 Oct 2025, older) Gartner named confidential computing a top strategic technology trend for 2026: "By 2029, more than 75% of operations processed in untrusted infrastructure will be secured in-use by confidential computing". — [Gartner press release, 20 Oct 2025](https://www.gartner.com/en/newsroom/press-releases/2025-10-20-gartner-identifies-the-top-strategic-technology-trends-for-2026)
- (26 Jan 2026) Cisco 2026 Data and Privacy Benchmark, a survey of more than 5,200 professionals in 12 markets — [Cisco newsroom, Jan 2026](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m01/ai-data-privacy-investments-governance-cisco-report.html); [Cisco study](https://www.cisco.com/c/en/us/about/trust-center/data-privacy-benchmark-study.html):
  - AI is the primary catalyst for 90% of companies expanding their privacy programs, and 93% plan further investment.
  - 23% lack a dedicated AI governance committee.
  - 95% see privacy as essential to customer trust in AI services.
  - 81% face heightened demand for data localization.
- (Nov 2024–Jan 2025 fieldwork, older) KPMG and the University of Melbourne surveyed more than 48,000 people in 47 countries. — [KPMG press release](https://kpmg.com/mt/en/home/media/press-releases/2025/05/global-study-reveals-tension-between-ai-benefits-and-risks-and-highlights-a-governance-gap.html); [University of Melbourne](https://fbe.unimelb.edu.au/newsroom/media-release-global-study-reveals-trust-of-ai-remains-a-critical-challenge-reflecting-tension-between-benefits-and-risks); [KPMG UK](https://kpmg.com/uk/en/insights/ai/uk-attitudes-to-ai.html)
  - Almost half of employees admit to using AI against company policy, including uploading sensitive company information to free public AI tools.
  - Only 46% are willing to trust AI, and only 40% say their workplace has a GenAI policy.
  - In the UK, 39% have uploaded company information to a public AI tool.

#### Consumers
- (survey 17–23 Feb 2026; chart published 17 Jun 2026) Pew: "Americans largely think AI will make their personal information less secure". 71% say less secure, 10% not much difference, 3% more secure and 16% not sure. — [Pew Research](https://www.pewresearch.org/chart/americans-largely-think-ai-will-make-their-personal-information-less-secure/)
- (Jun 2026) Pew: privacy concerns are among the main reasons non-users give for avoiding chatbots. — [Pew: why don't people use chatbots](https://www.pewresearch.org/internet/2026/06/17/why-dont-people-use-chatbots/)
- (Aug 2026) Pew: concern about AI is rising, including among adults under 30. — [Pew short read, 18 Aug 2026](https://www.pewresearch.org/short-reads/2026/08/18/young-adults-in-the-us-are-increasingly-wary-of-ai/)
- (Nov 2025–Jan 2026) Coverage of the NYT case framed AI chats as legal evidence. — [AI Weekly](https://aiweekly.co/issues/your-ai-chats-are-evidence-court-orders-leaks-what-stays)

#### Regulation and legal drivers
- (in force 27 Jul 2026) The EU's Digital Omnibus on AI, Regulation (EU) 2026/1744, delays the AI Act's high-risk obligations. Sources are law-firm and compliance summaries; the Official Journal text was not reviewed. — [Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/); [Orrick, Jul 2026](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes); [Usercentrics](https://usercentrics.com/knowledge-hub/eu-ai-act-high-risk-delay-article-50-transparency-consent/)
  - Stand-alone Annex III systems now face obligations from 2 Dec 2027 instead of 2 Aug 2026; systems embedded in Annex I products from 2 Aug 2028.
  - Article 50 transparency duties are not amended.
- (GDPR enforcement by Italy's Garante):
  - OpenAI fined €15M (Dec 2024, older). — [SecurityWeek](https://www.securityweek.com/italys-privacy-watchdog-fines-openai-for-chatgpts-violations-in-collecting-users-personal-data/amp/)
  - Replika's maker fined €5M, decision of 10 Apr 2025 (older). — [EDPB](https://www.edpb.europa.eu/news/ai-the-italian-supervisory-authority-fines-company-behind-chatbot-replika_en)
  - Character.AI fined €158,000 in July 2026 over age checks and safeguards for minors. — [OECD AI incidents](https://oecd.ai/en/incidents/2026-07-09-06ea); [PYMNTS](https://www.pymnts.com/cpi-posts/italy-penalizes-character-ai-owner-over-child-safety-and-privacy-controls/)
- (Jul 2026) The HIPAA Security Rule overhaul, proposed in January 2025 and covering ePHI in AI training data and algorithms, was pushed to July 2027. — [Fierce Healthcare](https://www.fiercehealthcare.com/health-tech/feds-push-back-hipaa-security-rule-overhaul-july-2027); [Holland & Knight, 6 Jul 2026](https://hklaw.com/en/insights/publications/2026/07/hipaa-security-rule-amendments-now-projected-for-july-2027); [Alston & Bird, 10 Jul 2026](https://www.alston.com/en/insights/publications/2026/07/hhs-delays-hipaa-security-rule-2027)
- (Apr 2026) OCR Director Paula Stannard said the Security Rule should apply to AI as to any other technology. — [Morgan Lewis, Apr 2026](https://www.morganlewis.com/pubs/2026/04/key-takeaways-from-the-43rd-national-hipaa-summit-what-healthcare-industry-stakeholders-should-know)

### Inferences
- **Enterprise demand is framed as governance.** Buyers frame the need as leakage and governance (shadow AI, data-policy violations, missing access controls), not as operator blindness. Products that let staff use strong AI without sending plaintext to an unmanaged third party speak to the IBM, Netskope and Gartner numbers directly.
- **Consumer demand is general distrust.** The 71% figure and privacy-driven non-use are a broad market. The visible winners so far are bundled platform features (Apple, Google, Meta) and browser or search add-ons (Brave, Duck.ai), not paid stand-alone apps.
- **Regulation pushes indirectly.** Delays in the AI Act and HIPAA reduce near-term compliance pressure. GDPR fines, data-localization demand (81% in Cisco's study) and legal discovery of chat logs keep pressure on data minimization. Architectures where the vendor holds no plaintext are the clearest answer to discovery and localization demands.

### Gaps
- No 2026 Gartner survey repeating the 69% shadow-AI question was found.
- Deloitte's 2025–2026 surveys on GenAI privacy concerns were not researched.
- Cisco's study has generative-AI-specific figures in its PDF that were not extracted.
- No survey was found that measures willingness to pay specifically for end-to-end encrypted or TEE-verified AI.
- 2026 GDPR actions beyond Italy (for example by the Irish DPC against X/Grok or Meta AI) were not researched.
