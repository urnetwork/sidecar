# Bittensor subnets other than Chutes (SN64) and Targon (SN4): inference and compute offerings and their TEE status (survey dated 2026-11-23)

## 1. Which subnets sell GPU/CPU rental or VMs, and does any offer a confidential (TEE) machine the customer can attest, with SSH, root, a public IP or ports, and egress the customer controls?

### Takeaway
On 2026-11-23, two subnets besides Targon sell a confidential machine that a customer can rent and attest today, and neither is a clean "customer-imaged TEE VM".
- **Lium (SN51)** rents GPU pods on Intel TDX + NVIDIA CC nodes. The pod is a container inside a CVM whose measured software Lium controls. The measurements cover the node, not the renter's image, and Lium itself stays in the trust base.
- **Hippius (SN75)** sells CPU-only AMD SEV-SNP VMs with Debian/Ubuntu, sudo, SSH, an optional public IPv4 and open egress (port 25 blocked). It runs on miner hardware, and the disk keys are released by a key service Hippius manages.

Two more are not usable yet:
- **Cathedral (SN94):** SEV-SNP sandboxes, still in "live testing, not general availability". SSH into confidential sandboxes is not live.
- **Nodexo (SN106):** claims optional TEE execution, but the claim is unverified and the project has been dormant since July 2026.

Every other compute subnet has no TEE. The previously named compute subnets (Basilica SN39, NI Compute SN27, Polaris SN49) no longer hold those netuids.

### Cited Findings

#### Registry snapshot and method (all as of 2026-11-23)
- SubnetRadar counts 128 registered subnets and puts 11 in "Compute": SN51 lium.io (17.67% of emission, $152.5M market cap), SN64 Chutes, SN4 Targon, SN110 Green Compute (0%, $19.0M), SN12 Compute Horde (0%, $6.0M), SN90 KubeTEE (0.64%, $3.2M), SN94 Cathedral (<0.01%, $2.5M), SN128 ByteLeap (0.01%, $2.4M), SN106 Nodexo (<0.01%, $2.3M), SN100 Cortex (0%, $1.7M) and SN36 Weir (0.79%, $413K). Snapshot 2026-11-23 07:22 UTC. — [SubnetRadar Compute category](https://subnetradar.com/subnets/compute)
- SubnetRadar's "Infra" category is SN19 blockmachine, SN114 SOMA, SN25 UR, SN105 Beam, SN27 Komms and SN122 CookingTAO. None of them sells compute. — [SubnetRadar Infra](https://subnetradar.com/subnets/infra)
- Method: I took the SubnetRadar Compute, Inference, Infra, Agents and Security categories, opened each candidate's SubnetRadar dossier, and checked its own docs or site where one exists. I also checked the netuids the brief named (12, 27, 39, 49, 51, 75). SubnetRadar is a third-party aggregator. Its TEE claims were corroborated for some subnets (Hippius, Cathedral, KubeTEE, SayGM) but not for others (Nodexo, see below). I did not query taostats directly.

#### Master table: compute, rental and VM candidates (current state, 2026-11-23)
| SN | Name (team) | What a customer can buy | Access | TEE | Verdict | Maturity signals | Sources |
|---|---|---|---|---|---|---|---|
| 51 | Lium, formerly Celium (Datura) | Hourly GPU pods. Confidential Computing (CVM) nodes are a labeled subset | Web console, REST API (OpenAPI), CLI, SDK; SSH into the pod | Intel TDX CVM with NVIDIA CC on H100/H200/B200/GB200/B300. The pod runs inside a dstack-based CVM | **TEE enclave usable**, with caveats (container in a Lium-measured VM; Lium in the trust base) | Largest subnet by emission (17.67%). 2,477 GPUs listed, 1,818 rented, 165 providers, 30-day GMV $3.14M (2026-11-23) | [CVM guide](https://docs.lium.io/providers/nodes/cvm), [Pod security](https://docs.lium.io/pod-users/security.md), [Private models](https://docs.lium.io/pod-users/private-models.md), [stats feed](https://lium.io/api/public/v1/stats) |
| 75 | Hippius (The Nerve Lab, thenervelab) | Confidential VMs (CPU only), managed PostgreSQL, managed Kubernetes, GitHub Actions runners, plus storage, S3 and CDN | Console, Management/Compute API (OpenAPI), browser console, SSH | AMD SEV-SNP. The disk unlocks only after attestation | **TEE enclave usable** (CPU only; Hippius-managed key service) | 2.68% emission, $23.4M market cap, 421 commits in 30 days. Confidential VMs announced 2026-10-27 | [Hippius Confidential Compute](https://hippius.com/confidential-compute), [docs/use/compute](https://docs.hippius.com/use/compute), [SubnetRadar SN75](https://subnetradar.com/subnet/75), [TAO Outsider](https://www.taooutsider.com/subnet-research/) |
| 94 | Cathedral (founder Fred Esere) | Confidential CPU sandboxes (1–8 vCPU), agent sessions, CI jobs, CPU models | `ctcli`, HTTPS API (OpenAPI), web console | AMD SEV-SNP sandboxes. One-shot runs on fresh Intel TDX machines. Ed25519 receipts | **TEE announced but not available** ("Live testing, not general availability"; SSH into confidential sandboxes not live) | <0.01% emission (gated), $2.5M market cap, 512 commits in 30 days | [cathedral.computer](https://cathedral.computer), [SubnetRadar SN94](https://subnetradar.com/subnet/94) |
| 106 | Nodexo (nodexo-ai; earlier presented as a Neural Internet product) | Hourly GPU rentals | CLI, then SSH (root per SubnetRadar) | SubnetRadar claims optional TDX / SEV-SNP / NVIDIA CC "confidential execution". The README says nothing about TEE | **TEE announced but not available** (unverified) | <0.01% emission (gated). Repo inactive since 2026-07-23. Over 50 GPUs in Aug 2026 | [SubnetRadar SN106](https://subnetradar.com/subnet/106), [HackerNoon 2026-08-07](https://hackernoon.com/nodexo-crosses-50-verified-gpus-on-bittensor), [GitHub](https://github.com/nodexo-ai/nodexo) |
| 90 | KubeTEE AI (KubeTEE AI LTD, "Pierre") | Confidential *inference* only (see section 2). No rentable VMs or clusters | LiteLLM gateway llm.kubetee.ai, or via SayGM | Kata + Confidential Containers, Intel TDX, NVIDIA CC (Blackwell) | TEE inference (section 2). Not an enclave product | 0.64% emission, $3.1M market cap, 2 contributors | [README](https://github.com/KubeTEE-AI/kubetee-subnet), [SubnetRadar SN90](https://subnetradar.com/subnet/90) |
| 12 | ComputeHorde (Backend Developers LTD) | GPU jobs for *other subnets' validators* through a Python SDK and a "Facilitator". Not sold to outside buyers | SDK | None. Its "Trusted Miner" is a validator-linked GPU for cross-checks, not a TEE | **no TEE** | 0% emission; supported class A6000 | [GitHub README](https://github.com/backend-developers-ltd/ComputeHorde), [SubnetRadar SN12](https://subnetradar.com/subnet/12) |
| 110 | Green Compute | RTX 4090/5090 rental and inference on verified renewable power | Not stated | None mentioned | **no TEE** | Emissions switched off by root governance (0%). No public repo | [SubnetRadar SN110](https://subnetradar.com/subnet/110) |
| 36 | Weir (Weir Compute) | Whole GPU machines with root SSH, booked on weircompute.com | Web, SSH | None mentioned | **no TEE** | 0.79% emission, $412K market cap. Ownership changed 2026-11-02 | [SubnetRadar SN36](https://subnetradar.com/subnet/36) |
| 128 | ByteLeap (byteleapai) | Leased machines (libvirt VMs behind a VM gateway) | Not stated | None mentioned | **no TEE** | 0.01% emission. "Inactive" (last activity 8/11/2026) | [SubnetRadar SN128](https://subnetradar.com/subnet/128) |
| 74 | Gittensor (Entrius) | A compute pool of verified NVIDIA GPU boxes that customers can rent (purchase path not described) | Not stated | None mentioned | **no TEE** | 0% emission. Dev "Inactive" since 2026-10-12 | [SubnetRadar SN74](https://subnetradar.com/subnet/74) |
| 100 | Cortex (Cortex Foundation; repo formerly PlatformNetwork/platform) | Nothing for compute buyers; research challenges | n/a | Firecracker guests that sign execution receipts. Not called a TEE | **no TEE** | 0% emission; "experimental" | [GitHub](https://github.com/PlatformNetwork/platform), [SubnetRadar SN100](https://subnetradar.com/subnet/100) |

#### Lium (SN51): main facts on renting a confidential machine (details in section 4)
- Lium's renter overview says a pod is "a container on a provider's machine, with its own GPUs and SSH access", billed per second. CVM machines "encrypt your pod's memory in hardware, and you can verify the VM's attestation yourself". On non-CVM machines the provider "may let the provider access your pod… Never put secrets on them". Page has no date; fetched 2026-11-23. — [Lium pod overview](https://docs.lium.io/pod-users/overview.md)
- CVM nodes are "labeled CVM-enabled in the UI and CLI", and "If a node is not labeled, assume the provider can access your pod." — [Lium Pod Security](https://docs.lium.io/pod-users/security.md)
- Egress: a rule in force and enforced since 2026-08-19 says providers may block outbound port 25 and access to their own LAN. They "must not add other outbound filters". Breaking the privacy rule means a permanent ban matched by hotkey, coldkey or GPU UUID. — [Lium Rental Workload Privacy](https://docs.lium.io/providers/rental-privacy.md)
- The pod exposes provider-mapped ports. A CVM node is configured with `SSH_PORT=2200`, `EXTERNAL_PORT=8001` and `RENTING_PORT_RANGE` (for example 19001–19003). Renter root access and a renter-facing public IP are not described. — [Lium CVM guide, updated 2026-11-17](https://docs.lium.io/providers/nodes/cvm)

#### Hippius (SN75): main facts (details in section 4)
- Images include Ubuntu, Debian, Fedora and others. "Your VM has no password login": you sign in by SSH key as the image's default user, "not `root`", and that user can use `sudo`. — [Hippius: create a VM](https://docs.hippius.com/use/virtual-machines)
- Networking:
  - Inbound is blocked by default. Allow rules can be TCP, UDP or ICMP (50 rules per VM).
  - An optional public IPv4 costs $0.005/h and "is not on the VM's network interface". You find it through a metadata URL.
  - Outbound is open except SMTP port 25, which support can unblock for a VM with a public IPv4.
  - Bandwidth is capped at 100 / 250 / 500 Mbit/s by VM size, and a public IPv4 is capped at 250 Mbit/s.
  - The edge terminates TLS for published HTTPS ports ("Don't publish anything only you should be able to read").
  - Source: [Hippius networking](https://docs.hippius.com/use/compute/networking)
- "Every VM runs inside an AMD SEV-SNP enclave". The VM proves itself to a key service with a signed hardware report before its disk key is released. — [Hippius Confidential Compute docs](https://docs.hippius.com/use/compute)

#### Non-TEE and former compute subnets
- ComputeHorde's README describes a Facilitator as "a gateway for organic requests (from other subnets' validators)", lists "Fallback to other clouds like RunPod via SkyPilot", and mentions no TEE. — [ComputeHorde README](https://github.com/backend-developers-ltd/ComputeHorde)
- Basilica (SN39, Covenant AI) lost its footing when Covenant AI announced its exit from Bittensor on 2026-04-09. Covenant alleged that its subnets' emissions were suspended and their infrastructure "deprecated". — [The Block, 2026-04-09](https://www.theblock.co/news/ecosystems/2026-04-09-covenant-ai-exits-bittensor-tao-396959). SN39 is now "Kokoah", a Hyperliquid trading subnet "renamed from Cathedral on Nov 20". — [SubnetRadar SN39](https://subnetradar.com/subnet/39)
- Polaris (SN49) was deregistered after its immunity period. SN49 is now Nepher Robotics. — [TAO Daily, 2025-11-01](https://taodaily.io/bittensor-subnet-49-takeover-polaris-deregistered-nepher-ai-assumes-ownership); [SubnetRadar SN49](https://subnetradar.com/subnet/49)
- NI Compute (SN27, Neural Internet) is gone from SN27. TAO Daily lists "Quasar Acquires SN27 and Rebrands It Orion" (Jul 13; the year is inferred as 2026 from the page ordering). SN27 today is "Komms", an encrypted messaging layer. — [TAO Daily SN27 tag](https://taodaily.io/tag/sn27); [SubnetRadar SN27](https://subnetradar.com/subnet/27)

### Inferences
- **Fit for URnetwork "secure enclaves" (TEE Debian VM with SSH, an IP, and networking URnetwork controls):**
  - **Hippius** is the only non-Targon subnet offering a general-purpose confidential *VM*, with Debian, sudo, SSH, a public IPv4, UDP/TCP inbound rules and open egress.
  - Limits on Hippius: CPU only. The public IPv4 is a 1:1 mapping at the edge, not on the interface. Bandwidth is capped at 250–500 Mbit/s. Most importantly, the disk-key release is run by Hippius, and its measurement policy is undocumented. Hippius is therefore in the trust base unless the customer can pin the SEV-SNP launch measurement of an image it controls, which the docs do not show.
  - **Lium** gives a confidential *GPU container*, not a customer-imaged VM. The quote covers "the node, not your image". Lium's own software runs inside the VM, so "The VM keeps the provider out, not Lium". To keep other pods off the same CVM, the renter must rent every GPU, and nodes are 1–8 datacenter GPUs at roughly $3.7–$12 per GPU-hour.
  - So Lium suits "run our own attested GPU workload". It does not meet "TEE Debian VM with our own image".
- Cathedral's design (SEV-SNP sandboxes, None / Allowlist / Internet egress modes, signed receipts) is close to an agent-enclave product. Until it is GA with SSH it is a watch item, not a supplier.
- Every other rental subnet (Weir, Green Compute, ByteLeap, Gittensor's pool, ComputeHorde) exposes the workload to the host, so none meets the TEE rule.

### Gaps
- Lium does not publish how many CVM nodes exist. The public nodes feed has no CVM field, only `tier` = secure/spot ([nodes feed doc](https://docs.lium.io/developers/public-nodes-feed.md)), and no CVM price premium is documented ([billing](https://docs.lium.io/pod-users/billing.md)). CVM availability could not be counted.
- Not documented for Hippius:
  - whether a customer can supply their own image and pin its SEV-SNP measurement;
  - who operates the key service and what policy it enforces;
  - whether all hosts are Bittensor miners. TAO Outsider says "miner hardware"; the docs only say "verified server".
- Nodexo's TEE claim comes only from SubnetRadar. The HackerNoon article says only "confidential execution options", and the README is silent.
- I could not confirm whether Basilica still runs as an off-chain service. basilica.ai shows only "Summon compute" and a CLI installer ([basilica.ai](https://www.basilica.ai)), and docs.basilica.ai returned no content.

## 2. Which subnets offer inference APIs, and do any offer TEE-backed inference?

### Takeaway
Two non-Chutes/Targon subnets offer TEE-backed inference today, and both are small or partial:
- **KubeTEE (SN90)** runs open-weight models in Kata/CoCo TDX pods on NVIDIA CC GPUs. It exposes a nonce-bound TDX quote endpoint (live since 2026-09-18), but sells mainly through SayGM. Its own billing is not live.
- **SayGM (SN28)**, a 74-model gateway, runs its gateway in Intel TDX and serves an open-weight "confidential" tier inside TEEs. Its Claude, GPT and Gemini routes run on the providers' own hardware, so they are **not** TEE inference.

The other inference subnets have no TEE:
- engy (SN53, the largest by emission) explicitly says "No TEEs" and relies on TOPLOC proofs.
- Verathos (SN96) lists TEE as "not yet enabled on mainnet" and has pivoted to decision models.
- SN2 moved from Inference Labs' zkML (DSperse) to DaniLabs in October 2026.
- Nineteen (SN19) and Apex (SN1) no longer sell inference.

### Cited Findings

#### Master table: inference candidates (2026-11-23)
| SN | Name (team) | What a customer can buy / access | TEE | Verdict | Maturity | Sources |
|---|---|---|---|---|---|---|
| 28 | SayGM / "gm" (T34 Corporation FZCO, Dubai; code in the taostat GitHub org) | OpenAI-, Anthropic- and Gemini-compatible gateway to 74 models (Claude, GPT, Gemini, open models), priced "≤ List" | Gateway in an Intel TDX enclave. Open-weight "confidential" models are served in a TEE. Miners run a TDX CVM on Phala Cloud (aggregator claim) | **TEE inference usable**, for the open-weight confidential tier only. Frontier-model routes are not TEE inference | 4.49% emission, $40.5M market cap, 245 miners | [saygm.com](https://saygm.com), [SubnetRadar SN28](https://subnetradar.com/subnet/28) |
| 90 | KubeTEE AI | OpenAI-compatible LiteLLM gateway llm.kubetee.ai (`/v1/chat/completions`, `/mcp`, `/a2a`). The models (GLM-5.2, GLM-5.3, GLM-5.3-Flash, Ornith-1.5-397B) are "available to buyers on sayGM" | Kata + CoCo, Intel TDX, NVIDIA CC (Blackwell); nonce-bound quote endpoint | **TEE inference usable** (early; direct billing not live) | 0.64% emission, $3.1M market cap | [README](https://github.com/KubeTEE-AI/kubetee-subnet), [kubetee.ai](https://kubetee.ai/) |
| 53 | engy (hanlin.ai) | OpenAI/Anthropic-compatible API, "zero data retention" | "No TEEs, no trusted hardware" | **no TEE**; *verifiable inference (TOPLOC fingerprints)* | 5.49% emission, $48.3M market cap | [GitHub engy](https://github.com/hanlinai/engy), [SubnetRadar SN53](https://subnetradar.com/subnet/53) |
| 96 | Verathos (verathos-ai) | Was an OpenAI-compatible API ($0.08–$1.20 per 1M tokens, TAO / USDC via x402). Since 2026-10-15 it is "Verathos Decide" (decision models) | "TEE Verification (complementary, not yet enabled on mainnet)" | **TEE announced but not available**; *verifiable inference (Gleipnir sampling proofs)* | <0.01% emission (gated); inactive since 2026-10-14 | [docs intro](https://raw.githubusercontent.com/verathos-ai/verathos/main/docs/intro.md), [SubnetRadar SN96](https://subnetradar.com/subnet/96) |
| 2 | DaniLabs, formerly DSperse / Omron (Inference Labs) | "Privacy-focused" no-retention inference, "still in early development" | None. The former owner's zkML proofs were verifiable inference, not TEE | **no TEE** | 0% emission, $4.0M market cap | [TAO Daily 2026-10-17](https://taodaily.io/daniLabs-takes-over-dsperse-sn2-with-plans-for-faster-cheaper-ai-inference), [SubnetRadar SN2](https://subnetradar.com/subnet/2) |
| 95 | Actual (Actual Computer Inc.) | Private API and relay to models on the customer's own machines | None mentioned | **no TEE** | 0% emission, $20.6M market cap | [SubnetRadar SN95](https://subnetradar.com/subnet/95) |
| 34 | Yugos, formerly BitMind (renamed 2026-10-27) | OpenAI-compatible routing ("System One" decision model) | None mentioned | **no TEE** | 1.33% emission | [SubnetRadar SN34](https://subnetradar.com/subnet/34) |
| 14 | Cacheon (latent-to) | Hosted open-model inference and serving-stack optimization | None mentioned | **no TEE** | 0.71% emission | [SubnetRadar SN14](https://subnetradar.com/subnet/14) |
| 46 | Instant | Uncensored GLM-5.3-Flash through the instantnetwork.ai portal, with bit-exact validator checks | None mentioned | **no TEE**; *output re-verification* | <0.01% emission (gated) | [SubnetRadar SN46](https://subnetradar.com/subnet/46) |
| 92 | REAX (reaxlabs) | Decision-model API through decisionmodels.io, billed in euros. EU-tier requests "never use the network" | None mentioned | **no TEE**; *validator recompute* | 0.95% emission | [SubnetRadar SN92](https://subnetradar.com/subnet/92) |
| 31 | rec4ll | RAG / memory API ("encrypted vector databases") | None mentioned | **no TEE** | 0.14% emission | [SubnetRadar SN31](https://subnetradar.com/subnet/31) |
| 103 | Terza Inference, formerly Consted (renamed 2026-10-27) | One API key for chat, image, speech and video models | None mentioned | **no TEE** | 0.02% emission; inactive | [SubnetRadar SN103](https://subnetradar.com/subnet/103) |
| 10 | Pareton | Serving-optimization campaigns; no customer purchase path | None mentioned | **no TEE** (no product) | <0.01% emission | [SubnetRadar SN10](https://subnetradar.com/subnet/10) |
| 29 | hoτfloaτ (coldint) | Fork of Cacheon; no customer product | None mentioned | **no TEE** (no product) | Inactive since 2026-01-28 | [SubnetRadar SN29](https://subnetradar.com/subnet/29) |
| 1 | Apex (Macrocosmos) | Optimization *competitions*, not an inference API | None mentioned | **no TEE** (no inference product) | <0.01% emission | [SubnetRadar SN1](https://subnetradar.com/subnet/1) |
| 19 | blockmachine (formerly Nineteen) | Multi-chain RPC, not inference | None mentioned | n/a | 0.57% emission | [SubnetRadar SN19](https://subnetradar.com/subnet/19) |

- The SubnetRadar Inference category (2026-11-23 07:25 UTC) lists SN53 engy, SN28 SayGM, SN95 Actual, SN34 Yugos, SN14 Cacheon, SN10 Pareton, SN2 DaniLabs, SN46 Instant, SN29 hoτfloaτ, SN92 REAX, SN31 rec4ll, SN96 Verathos and SN103 Terza Inference. — [SubnetRadar Inference](https://subnetradar.com/subnets/inference)

#### SayGM (SN28)
- From saygm.com (fetched 2026-11-23):
  - "The gateway runs in an Intel TDX enclave."
  - "Open-weight models served inside a TEE, so your prompt is decrypted only within the enclave that runs the model."
  - Frontier models "run on their provider's hardware, under its API terms".
  - The page shows an attestation panel: gateway `gw-mainnet-2`, TCB "UpToDate", quote signature "verified", last verified 2026-11-23 07:27:53 UTC. It states "A verifier outside the gateway checks hardware-signed evidence." No public evidence endpoint or downloadable quote is documented.
  - Source: [saygm.com](https://saygm.com)
- SubnetRadar says miners run the gm miner image "as an Intel TDX confidential VM on Phala Cloud, where upstream keys stay inside the enclave", and that the registry checks the image against approved versions. — [SubnetRadar SN28](https://subnetradar.com/subnet/28). A Yellow.com explainer says the same and is likewise secondary: [Yellow SN28](https://yellow.com/asset/sn28)
- History: in June 2026 the TEE gateway was "on testnet". "Attested Logs", BYOK, Teams and "Pay with Alpha" were roadmap items. — [TAO Daily, 2026-06-13](https://taodaily.io/gm-wants-to-be-bittensors-private-door-to-every-frontier-model/) (possibly superseded by the November mainnet attestation panel)
- A May 2026 report calls SN28 "gm" a "confidential routing layer" alongside OpenRouter. The same report says 20–25% of Chutes' traffic goes through OpenRouter. These are unsourced secondary claims. — [KuCoin/CryptoBriefing, 2026-05-30](https://www.kucoin.com/news/flash/bittensor-integrates-confidential-routing-layer-with-openrouter-processes-up-to-120-billion-tokens-daily)

#### KubeTEE (SN90)
- From the README:
  - Kata runtimes `kata-qemu-nvidia-gpu-tdx-runtime-rs` (GPU) and `kata-qemu-tdx-runtime-rs` (CPU), Kata 4.3.1.
  - CoCo Trustee/KBS handles attestation and secret release, with guest debug off.
  - "A confidential pod is a virtual machine with an encrypted, attested memory boundary."
  - `GET /v1/attestation?nonce=…` returns a fresh TDX quote with the nonce bound into REPORTDATA, live since 2026-09-18. It can be verified with Intel Trust Authority or local DCAP.
  - RA-TLS with the quote in the handshake is "a later hardening step".
  - Source: [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)
- kubetee.ai says confidential inference is "served inside TEE-isolated pods and available to buyers on sayGM", and lists USDC/TAO billing as "Coming". — [kubetee.ai](https://kubetee.ai/)

#### Verifiable / zero-knowledge inference (does not meet the TEE rule; noted as asked)
- **engy SN53:** "Every response carries a TOPLOC activation fingerprint", "the check enforced today", and "No TEEs, no trusted hardware. The proof pins the math, not the machine." — [engy README](https://github.com/hanlinai/engy)
- **Verathos SN96:** Gleipnir v3 probabilistic proofs ("not a full transformer SNARK"); TEE verification "not yet enabled on mainnet". — [Verathos docs](https://raw.githubusercontent.com/verathos-ai/verathos/main/docs/intro.md)
- **SN2 under Inference Labs (DSperse/Omron):** zkML verifiable inference. "More than 6 billion cryptographic proofs" had been produced before the October 2026 handover to DaniLabs. — [TAO Daily, 2026-10-17](https://taodaily.io/daniLabs-takes-over-dsperse-sn2-with-plans-for-faster-cheaper-ai-inference). JSTprove went live on DSperse on 2026-01-16. — [TAO Daily SN2 tag](https://taodaily.io/tag/sn2/)
- **Instant SN46** (bit-exact checks) and **REAX SN92** (validator recompute) also verify outputs without TEEs. — [SubnetRadar SN46](https://subnetradar.com/subnet/46), [SubnetRadar SN92](https://subnetradar.com/subnet/92)

### Inferences
- If the design requires inference *always* in a TEE, the only non-Chutes/Targon routes are:
  1. **KubeTEE**: direct, with a per-request nonce-bound TDX quote. It is tiny (2 contributors, $3.1M market cap), its model list keeps changing (several models are "withdrawn or retired"), and it has no live self-serve billing.
  2. **SayGM's confidential tier**: the client must pin model IDs to that tier and refuse frontier models. SayGM publishes no machine-readable evidence chain from gateway to model enclave.
  3. **Self-hosting on Lium CVM nodes**: URnetwork would run its own inference server inside a Lium TDX pod and verify the TDX quote plus NVIDIA GPU attestation itself, with Lium in the trust base.
- The largest non-TEE inference subnet (engy) and the zk/verification subnets offer integrity (right model, right weights) but no confidentiality. They fail the rule.

### Gaps
- SayGM's "Technical details" docs were not reachable (saygm.com/docs returned 404). Still unknown:
  - which hosts serve the confidential tier (KubeTEE, Phala-hosted miners, or others);
  - whether the gateway refuses (fails closed on) unattested backends;
  - which payment methods "wallet payments" covers.
- KubeTEE: whether outside integrators can get llm.kubetee.ai keys today, and at what price. The README says demand-side billing is Phase 1 work in progress. It also says "no attestation means no emissions" while its Evidence Feeds section says attestation is "not yet in the weight path"; the two statements conflict.
- I found no source on what DaniLabs' SN2 will use for privacy beyond "without storing them afterward".

## 3. Do any subnets run on Phala's dstack or other confidential-container frameworks, or partner with Chutes or Targon for TEE capacity? Is there any Bittensor-wide (protocol-level) TEE initiative?

### Takeaway
Three subnets use confidential-VM or container frameworks:
- **Lium** builds its CVMs on dstack components (dstack OS measurements, dstack QEMU, the dstack guest socket).
- **SayGM** miners reportedly run on Phala Cloud TDX CVMs.
- **KubeTEE** uses Kata Containers with Confidential Containers (CoCo) and lists Phala, Chutes and NEAR AI as planned TEE fallbacks.

Several other subnets use TEEs *internally* for miners or validators rather than selling them: Fugal (TDX benchmarks), Cathedral (miners run SEV-SNP/TDX machines) and Kokoah ("sealed machines"). Lium's idle-GPU incentive also rewards attested CVMs.

Dependencies on Chutes/Targon:
- KubeTEE uses Targon, Lium and Chutes price feeds, and Chutes as a planned fallback.
- Affine (SN120) hosts its miners' models on Chutes.

I found no Opentensor or subtensor protocol-level TEE program. Phala's dstack had a guest-agent data leak between 2026-10-08 and 2026-10-12. That matters to any dstack- or Phala-based subnet.

### Cited Findings
- **Lium and dstack:**
  - Lium's CVM guide requires "dstack QEMU 9.2.1".
  - Renters fetch quotes through `/var/run/dstack.sock`. Only `GetQuote`, `Info` and `Version` work; key-derivation calls return 403. Verification uses "the dstack verifier or any Intel DCAP quote verifier".
  - Measurements "MRTD and RTMR0–2 match the dstack OS release" and RTMR3 the executor release.
  - Sources: [Lium CVM guide](https://docs.lium.io/providers/nodes/cvm), [Lium Pod Security](https://docs.lium.io/pod-users/security.md), [Lium Private models](https://docs.lium.io/pod-users/private-models.md)
- **SayGM and Phala Cloud:** SubnetRadar says SayGM miners run "as an Intel TDX confidential VM on Phala Cloud". — [SubnetRadar SN28](https://subnetradar.com/subnet/28)
- **KubeTEE:** Kata/CoCo/Trustee stack. Chutes (SN64), Phala and NEAR AI are "planned LiteLLM router fallbacks (Phase 2)". Targon, Lium and Chutes price feeds set pricing, and "the Targon snapshot API drives a live supply-side clamp". — [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)
- **KubeTEE and SayGM:** KubeTEE's confidential models are "available to buyers on sayGM". The README dates the SN28 channel to 2026-08-19 and the first Ornith-1.5-397B delivery to 2026-08-20. — [kubetee.ai](https://kubetee.ai/), [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)
- **Fugal (SN70):**
  - "Miners run the benchmark inside an Intel TDX confidential VM and produce hardware-attested proofs."
  - It is a router-training subnet with no customer product.
  - It was re-registered by a new owner on 2026-10-26 and renamed from "Consted 2.0" on 2026-11-03.
  - Sources: [SubnetRadar SN70](https://subnetradar.com/subnet/70). On 2026-09-06 it reported "closing five TEE verifier exploit classes" in a pre-Finney release — [TAO Outsider](https://www.taooutsider.com/subnet-research/)
- **Cathedral (SN94) miners** run "AMD SEV-SNP or Intel TDX confidential machines". — [SubnetRadar SN94](https://subnetradar.com/subnet/94)
- **Kokoah (SN39):** verified agents run in "sealed machines" and receive extra skill weight. The technology is not explained. — [SubnetRadar SN39](https://subnetradar.com/subnet/39)
- **Lium's idle-GPU incentive:** "An 8× H200, B200 or B300 node earns the unrented incentive while idle only with GPU Profiling, GPU splitting or a CVM whose TDX quote the validator verifies." — [Lium CVM guide](https://docs.lium.io/providers/nodes/cvm)
- **Affine and Chutes:** Affine (SN120) "leverages Bittensor's Subnet-64 (Chutes) as a model hosting and inference subnet". This comes from a search excerpt and was not fully verified. — [SubnetAlpha Affine](https://subnetalpha.ai/subnet/affine/)
- **Phala incident, 2026-10-08 to 10-12:**
  - The `guest-agent` in dstack OS images v0.3.1 through v0.6.0 let an attacker read container logs and `Config.Env` environment variables for "a small set of customer applications".
  - Phala says no enclave, sealing or KMS keys were affected.
  - The fix is in v0.6.1 and v0.5.12, with an upgrade deadline of 2026-11-19 and forced upgrades from 2026-11-20.
  - The report does not say whether self-hosted dstack deployments were affected.
  - Sources: [Phala post-mortem, 2026-10-19](https://phala.com/posts/2026-10-post-mortem-dstack-guest-agent-vulnerability); [Own Your Mind newsletter, 2026-10-29](https://buttondown.com/ownyourmind/archive/bittensor-changed-its-code-five-times-in-eight/)
- **Earlier Phala and dstack security items** (from search snippets only; not fetched):
  - A Phala Cloud API authorization flaw (2026-05-31 to 06-01) let an attacker modify CVMs they did not own. — [Phala status incidents](https://status.phala.network/incidents)
  - A February 2026 hardening of the attestation pipeline included a "critical QE identity verification issue" and asked users to upgrade to v0.5.6. — [Phala dstack security update](https://phala.com/posts/dstack-security-update-attestation-pipeline-hardening)
- **No protocol-level TEE program found:** searches did not surface any Opentensor-authored TEE proposal for subtensor or validators. On the night of Covenant's exit, Steeves said instead that "Bittensor will invent lock-based subnet ownership" (governance, not TEE). — [The Block, 2026-04-09](https://www.theblock.co/news/ecosystems/2026-04-09-covenant-ai-exits-bittensor-tao-396959)
- **Gamma, a protocol-level payment rail (not TEE) several subnets accept:**
  - Lium accepts "SN51 gamma". — [Lium billing](https://docs.lium.io/pod-users/billing.md)
  - Cathedral offers "Pay with Gamma, no account". — [cathedral.computer](https://cathedral.computer)
  - Hippius lists "Pay with Gamma… not yet live". — [Hippius llms.txt](https://docs.hippius.com/llms.txt)
  - TAO Daily: "What the Chain Says About Gamma: $47.7K Spent…" (2026-11-22; title only). — [TAO Daily SN2 tag](https://taodaily.io/tag/sn2/)
- **Context (not about a subnet):** an August 2026 audit of Venice's end-to-end-encrypted path through a Phala-operated dstack gateway found:
  - "the serving software and model weights remain outside the measured claims";
  - "a root SSH key may be injected into the enclave, and the attestation does not tell you whether one was";
  - the gateway ran a development dstack image that builds code at boot.
  - Source: [Juraj Bednar, 2026-08-11](https://juraj.bednar.io/en/blog-en/2026/08/11/hardware-attestation-for-private-ai-inference/)

### Inferences
- A TDX quote from dstack proves the dstack OS and compose. It does not prove the workload image (Lium says so explicitly) or the absence of debug or SSH paths (the Venice audit). Any URnetwork verifier for Lium or SayGM therefore needs its own allow-list of RTMR values and its own nonce binding, as Lium's private-models flow already does.
- SayGM miners keep upstream provider keys in Phala Cloud CVMs. If they hold those keys in environment variables, the Phala guest-agent leak (v0.3.1–v0.6.0) is the kind of exposure that could have hit them. This is an inference; no source says SayGM was affected.
- The "partner with Chutes/Targon for TEE capacity" pattern exists only as KubeTEE's planned fallback and price benchmarking, plus Affine's dependency on Chutes. No non-Chutes/Targon subnet resells Targon TVM capacity, as far as I found.

### Gaps
- I found no primary document on Opentensor-level TEE plans (validator TEEs, confidential weights). I could not query the Bittensor Discord or forum.
- Whether Lium's dstack OS guest agent fell in the vulnerable v0.3.1–v0.6.0 range is not stated. Lium production CVMs have "no live-logs page", which may reduce exposure; this is inference.
- An older PlatformNetwork/platform description (search snippet only) said challenges ran "in TDX-secured VMs via dstack". The current README (now Cortex, SN100) mentions only Firecracker receipts. When and why it changed is unknown.

## 4. For each subnet with a TEE offering: exact hardware, attestation flow, who can see plaintext, API, pricing, payment (fiat vs TAO vs alpha), and terms for business integrators

### Takeaway
Of the six subnets with TEE claims, Lium and Hippius have the most complete renter-side documentation. In both, the operator (Lium or Hippius), not the miner, remains trusted:
- Lium is trusted because its software sits inside the measured VM.
- Hippius is trusted because its key service releases disk keys.

KubeTEE has the best client-facing attestation for inference (a nonce-bound quote endpoint), but no live self-serve billing. SayGM shows attestation status but publishes no verifiable evidence format. Cathedral's receipt model is well designed but in preview. Nodexo's claim is unverified. None publishes enterprise terms or SLAs that I could find.

### Cited Findings

#### Lium (SN51): Datura team; formerly Celium ([CoinMarketCap "What is lium (SN51)"](https://coinmarketcap.com/cmc-ai/celium/what-is/); [Datura-ai/lium-io](https://github.com/Datura-ai/lium-io/wiki))
- **Hardware** (CVM guide updated 2026-11-17):
  - CPU TEE: Intel TDX, plus SGX for the key provider, on 4th/5th Gen Xeon Scalable or Xeon 6.
  - GPU: NVIDIA CC on Hopper (H100, H200) or Blackwell (B200, GB200; B300 is also covered).
  - Hopper 8-GPU HGX nodes run in Protected PCIe mode.
  - Host: Ubuntu 25.04, TDX module ≥ 2.0.08, kernel `6.14.0-1009-intel`.
  - AMD SEV-SNP is not mentioned.
  - Source: [Lium CVM guide](https://docs.lium.io/providers/nodes/cvm)
- **Validator attestation:**
  - Validators verify each node's TDX quote.
  - The executor runner image digest is written into the CVM compose file, whose hash the validator checks. "Changing flags such as `--enable-logs`… changes the hash, and validators then reject the node."
  - A key provider supplies sealing keys, and the data disk is encrypted.
  - Source: [Lium CVM guide](https://docs.lium.io/providers/nodes/cvm)
- **Renter attestation flow** (renter brings their own key broker):
  1. Inside the pod, create an X25519 key and get a nonce from the broker.
  2. Bind `sha256(public_key + nonce)` into `report_data` through the dstack SDK.
  3. The broker checks the DCAP/dstack signature and TCB, the binding, and the measurements (MRTD and RTMR0–2 against the dstack OS release, RTMR3 against the executor release). Only then does it release the data key.
  - Source: [Lium Private models](https://docs.lium.io/pod-users/private-models.md)
- **Who sees plaintext:**
  - "The provider cannot read the VM's memory or disk." But "The VM keeps the provider out, not Lium."
  - "GPU memory and the CPU-GPU link are not covered by the CPU quote"; renters should use NVIDIA's attestation tools inside the pod.
  - "The quote does not identify the renter's image or pod, so renters should rent every GPU on the machine."
  - Source: [Lium Private models](https://docs.lium.io/pod-users/private-models.md)
- **API:** REST API (OpenAPI), CLI, SDK, Workspaces API, account audit log and a Provider API. The docs index also lists Partners, Invoices and Statements pages. — [Lium llms.txt](https://docs.lium.io/llms.txt)
- **Pricing** (2026-11-23 07:30 UTC, USD per GPU-hour, reference / min–max):
  - H200: 3.65 / 3.70–6.00
  - B200: 5.60 / 3.70–6.71
  - B300 SXM6 AC: 8.00 / 4.70–11.90
  - H100 80GB: 1.39 / 2.88–5.00 (the reference is below the minimum, which looks like a data inconsistency)
  - Source: [lium.io/pricing.json](https://lium.io/pricing.json). B300 "from $4 per GPU-hour" was advertised on 2026-10-28: [TAO Outsider](https://www.taooutsider.com/subnet-research/)
- **Scale** (2026-11-23):
  - 2,477 GPUs listed and 1,818 rented, 30-day utilization 80.2%.
  - 165 providers in 43 countries.
  - 30-day GMV $3,144,096.
  - CVM-capable models listed: H200 209, B200 151, B300 326 (212 SXM6 AC + 114 SXM6 PC), H100 111. How many of these run as CVMs is not reported.
  - Source: [Lium stats feed](https://lium.io/api/public/v1/stats)
- **Payment and billing:** "Pay by card, crypto, TAO, alpha or SN51 gamma". Billing is per second with no minimum. No CVM premium or enterprise terms are documented. — [Lium billing](https://docs.lium.io/pod-users/billing.md)

#### Hippius (SN75): thenervelab; co-founder @mast3rdubs per SubnetRadar
- **Hardware and attestation:**
  - "Every VM runs inside an AMD SEV-SNP enclave". CPU models are not named, and there are no GPUs.
  - Before the disk is unlocked, the VM proves itself to a key service with a signed hardware report.
  - Each VM's Confidential Computing panel shows the attestation result and the raw SEV-SNP report.
  - Source: [Hippius docs/use/compute](https://docs.hippius.com/use/compute)
  - The marketing page says "Check AMD's signature yourself". No verifier tool or measurement list is published. — [Hippius Confidential Compute](https://hippius.com/confidential-compute)
- **Who hosts and holds keys:** the 2026-10-27 announcement says the VMs run "on miner hardware with attestation and Hippius-managed disk keys". — [TAO Outsider](https://www.taooutsider.com/subnet-research/). A GitHub release tagged "hippius-cvm" v2026.10.09 exists. — [SubnetRadar SN75](https://subnetradar.com/subnet/75)
- **Plaintext:**
  - Memory is encrypted "with a key the host operating system never holds".
  - The browser terminal does the SSH handshake, so the private key never reaches Hippius.
  - The Kubernetes cluster key is generated in the browser.
  - The edge terminates TLS for published ports.
  - Sources: [Hippius docs/use/compute](https://docs.hippius.com/use/compute); [Hippius networking](https://docs.hippius.com/use/compute/networking)
- **API:** Management API with a Compute API section and a full OpenAPI spec at api.hippius.com/swagger.json. — [Hippius llms.txt](https://docs.hippius.com/llms.txt)
- **Pricing:**
  - VMs cost $18 per vCPU, $2.50 per GB RAM and $0.10 per GB disk per month. Small (1 vCPU, 4 GB, 40 GB) is about $32/month ($0.0438/h); 4X-Large (32 vCPU, 128 GB) is about $1,024/month.
  - Public IPv4: $0.005/h. Outbound bandwidth: "not charged today".
  - Billing is per second with a one-minute minimum, and stopped VMs still bill.
  - Sources: [Hippius Confidential Compute](https://hippius.com/confidential-compute); [Hippius docs/use/compute](https://docs.hippius.com/use/compute)
- **Payment:** "Top up on Billing in one of five ways": card, Bitcoin, USDC on Base, TAO and hAlpha. "Pay with Gamma" is not yet live. Balances are in USD. — [Hippius llms.txt](https://docs.hippius.com/llms.txt)
- **Regions:** pin by ISO country code. Only countries with verified server capacity are listed; France, the Netherlands and Australia are named. — [Hippius docs/use/compute](https://docs.hippius.com/use/compute); [Hippius Confidential Compute](https://hippius.com/confidential-compute)

#### KubeTEE (SN90)
- **Hardware:**
  - Intel TDX on Granite Rapids. AMD SEV-SNP is "from Phase 1".
  - NVIDIA CC on Blackwell (B200, B300, RTX PRO 6000). Hopper is deprecated for new onboarding, with a target of November 2026.
  - Source: [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)
- **Attestation flow:**
  - Client side: `GET /v1/attestation?nonce=…` returns a TDX quote with the nonce bound into REPORTDATA. Evidence can also ride in response headers. Verification uses Intel Trust Authority or DCAP.
  - Validators challenge miners, who sign with their Bittensor hotkey.
  - Source: [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)
- **Plaintext path:** Traefik TLS passthrough into an in-guest terminator, then attestation-gated TLS to model backends. — [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)
- **Pricing and terms:**
  - The per-GPU-hour card (H100 $4, H200 $5.50, B200 $8, B300 $10, RTX6000 $2.50) is used for *miner* compensation.
  - Customers pay Alpha or TAO at a "resources price per hour", with "no discounts and no referrer or reseller program".
  - Demand-side billing is Phase 1 work in progress. USDC/TAO on Base is planned.
  - Source: [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet)

#### SayGM (SN28)
- **Hardware:** an Intel TDX gateway (saygm.com). Miners on Phala Cloud TDX CVMs (SubnetRadar). Which GPUs or GPU-TEE mode serve the "confidential" open-weight tier is unknown. — [saygm.com](https://saygm.com), [SubnetRadar SN28](https://subnetradar.com/subnet/28)
- **Attestation:** a public panel (TCB UpToDate, quote verified, timestamp). "A verifier outside the gateway checks hardware-signed evidence." — [saygm.com](https://saygm.com)
- **Plaintext:** for frontier models the provider sees the prompt "under its API terms". For confidential models the prompt is "decrypted only within the enclave that runs the model". Optional guardrails swap out personal data on the way and restore it in the reply. — [saygm.com](https://saygm.com)
- **API:** point existing OpenAI, Anthropic or Gemini SDKs (and Cursor, Cline, Claude Code) at one base URL. — [SubnetRadar SN28](https://subnetradar.com/subnet/28)
- **Pricing and payment:** "≤ List", "Up to 70% cheaper" (39% average discount shown), "wallet payments" and "Pay as you go". — [saygm.com](https://saygm.com)

#### Cathedral (SN94)
- **Hardware:** SEV-SNP sandboxes; one-shot runs on "its own fresh Intel TDX machine".
- **Attestation (receipts):** Ed25519 receipts signed by a key in the machine's attestation, with an offline Node.js verifier. "A key fetched from the same API is not independent." A receipt "says nothing about the run's egress policy".
- **Plaintext:** typed input "passes Cathedral's API as plain text" in "Send unencrypted" mode.
- **Egress:** network off by default; None / Allowlist (up to 32 hosts) / Internet.
- **Pricing:** $0.005/h (1 vCPU, 2 GiB) and $0.01/h (2 vCPU, 4 GiB).
- **Payment:** $20 minimum top-up by card (Stripe), USDC (Coinbase) or TAO ("not available for this billing context right now").
- **Status:** "Live testing, not general availability"; sign-in unavailable in preview.
- Source for all of the above: [cathedral.computer](https://cathedral.computer)

#### Nodexo (SN106)
- **Payment:** hourly in USDC; "accountless rentals available through agent-compatible interfaces". — [HackerNoon, 2026-08-07](https://hackernoon.com/nodexo-crosses-50-verified-gpus-on-bittensor). SubnetRadar adds x402 (USDC) or account credits. — [SubnetRadar SN106](https://subnetradar.com/subnet/106)
- **TEE:** no hardware, attestation or verifier details found in primary sources. The README covers operator setup only. — [Nodexo README](https://github.com/nodexo-ai/nodexo)

### Inferences
- Trust model compared with URnetwork's E2EE posture: in every usable offering here, one central party besides the hardware vendor is still trusted.
  - Lium is trusted because its software is inside the measured VM.
  - Hippius is trusted because of its key service and edge TLS for published ports.
  - SayGM is trusted because of its gateway and its unpublished evidence chain.
  - KubeTEE is trusted because the owner runs the control plane.
- Only KubeTEE's nonce-bound quote endpoint and Lium's broker flow let a customer pin evidence to its own nonce without trusting the operator's verifier.
- On payments, all of these accept TAO or crypto, and Lium and Hippius also accept cards. Payment is not a blocker. Contractual terms (SLA, DPA, liability) are not published by any of them.

### Gaps
- No subnet publishes an SLA, DPA or enterprise agreement for its TEE product. Lium has Partners, Invoices and Workspaces pages that I did not read.
- Hippius' SEV-SNP measurement contents, guest image provenance, and whether customers can bring their own image are undocumented.
- SayGM's evidence format and GPU-TEE details are unknown.
- KubeTEE's actual buyer pricing is unknown.

## 5. Which subnets were TEE-related (or the inference and compute subnets named in the brief) and have since 2025 shut down, deregistered, pivoted or lost emissions?

### Takeaway
TEE-related subnets that changed:
- **SN2 (Inference Labs):** its SGX TEE-inference prototype was archived on 2026-01-02, and the subnet passed to DaniLabs on 2026-10-16/17.
- **SN42 (Masa / Gopher, SGX tee-worker for data scraping):** renamed CADmind on 2026-11-12.
- **SN96 Verathos:** TEE was "not yet enabled on mainnet" before the 2026-10-15 pivot to decision models; it is now inactive and gated.
- **SN106 Nodexo:** claimed TEE, dormant since July 2026, emission gated.
- **SN94 Cathedral:** TEE preview, emission gated.
- **SN100 (Platform, now Cortex):** reportedly dropped dstack/TDX (low confidence).

Named compute and inference subnets that are gone:
- Basilica SN39 (Covenant exit, 2026-04-09);
- Polaris SN49 (deregistered by November 2025);
- NI Compute SN27 (SN27 acquired by Quasar, 2026-07-13);
- Nineteen SN19 (blockmachine since January 2026);
- Apex SN1 (no longer an inference API).

### Cited Findings
- **Inference Labs SGX prototype:** `subnet-2-tee` is "Trusted Execution Environment Inference" using Intel SGX/TDX. It was a hackathon project (Brussels, 2024-07-05 to 07) that targeted a local chain, and it was "archived by the owner on Jan 2, 2026". — [GitHub subnet-2-tee](https://github.com/inference-labs-inc/subnet-2-tee)
- **SN2 handover:** "DaniLabs will take over DSperse (SN2)" (announced 2026-10-16, article 2026-10-17). The service is "still in early development". — [TAO Daily](https://taodaily.io/daniLabs-takes-over-dsperse-sn2-with-plans-for-faster-cheaper-ai-inference). SN2 now receives 0% emission. — [SubnetRadar SN2](https://subnetradar.com/subnet/2)
- **Masa SN42:** Masa's `tee-worker` scraped data "from a secure TEE enclave", using the ego Go SDK with Intel SGX (search excerpt). — [gopher-lab/tee-worker](https://github.com/gopher-lab/tee-worker). SN42 was "renamed from Gopher to CADmind on 12 Nov 2026" and is now a prompt-to-3D-print subnet. — [SubnetRadar SN42](https://subnetradar.com/subnet/42)
- **Verathos SN96:** "TEE Verification (complementary, not yet enabled on mainnet)" (undated docs). — [Verathos docs](https://raw.githubusercontent.com/verathos-ai/verathos/main/docs/intro.md). Since 2026-10-15 it runs "Verathos Decide". It is inactive since 2026-10-14 and gated below the emission bar. — [SubnetRadar SN96](https://subnetradar.com/subnet/96)
- **Nodexo SN106:** dev status "Inactive", last activity 2026-07-23. Gated, keeping about 2% of its demand-implied emission. — [SubnetRadar SN106](https://subnetradar.com/subnet/106)
- **Cathedral SN94:** gated, keeping "roughly 0%" of its demand-implied emission. — [SubnetRadar SN94](https://subnetradar.com/subnet/94). SN39's dossier says Kokoah was "renamed from Cathedral on Nov 20". — [SubnetRadar SN39](https://subnetradar.com/subnet/39) How Cathedral relates to SN39 is unclear.
- **SN70:** its previous identity ("Centralised Entity", "Consted 2.0") was replaced. The subnet was re-registered by a new owner on 2026-10-26 and is now Fugal, which uses TEE internally. — [SubnetRadar SN70](https://subnetradar.com/subnet/70)
- **Basilica SN39 (Covenant AI):** on 2026-04-09 Covenant said Steeves had "Suspended emissions to Covenant's subnets… unilaterally deprecated its subnet infrastructure". I found no evidence that Basilica ever had a TEE. — [The Block](https://www.theblock.co/news/ecosystems/2026-04-09-covenant-ai-exits-bittensor-tao-396959)
- **Polaris SN49:** "deregistered after its four-month immunity period expired… after failing to maintain competitive emissions"; it was a GPU marketplace for the Solana ecosystem. — [TAO Daily, 2025-11-01](https://taodaily.io/bittensor-subnet-49-takeover-polaris-deregistered-nepher-ai-assumes-ownership)
- **NI Compute SN27:**
  - As of 2025-10-22 (possibly superseded) it was a GPU marketplace verified by "benchmark proofs", from "$0.01 per hour", paid via Stripe, USDC or alpha. No TEE. — [TAO Daily, 2025-10-22](https://taodaily.io/how-neural-internet-is-building-verifiable-compute-network-on-tao)
  - Later: "Quasar Acquires SN27 and Rebrands It Orion" (Jul 13, year inferred 2026). — [TAO Daily SN27 tag](https://taodaily.io/tag/sn27). SN27 is now Komms. — [SubnetRadar SN27](https://subnetradar.com/subnet/27)
- **Nineteen SN19 (Rayon Labs):** SN19 is now blockmachine, an RPC marketplace. A search excerpt says it launched in January 2026. — [SubnetRadar SN19](https://subnetradar.com/subnet/19); [TAO Daily blockmachine](https://taodaily.io/blockmachine-sn19turns-blockchain-infrastructure-into-a-competitive-marketplace)
- **Apex SN1 (Macrocosmos):** now "an open competition platform for measurable optimization problems", with no inference API. — [SubnetRadar SN1](https://subnetradar.com/subnet/1)
- **Other emission losses among compute subnets (none had a TEE):**
  - Green Compute SN110: "Root governance switched this subnet's emissions off". — [SubnetRadar SN110](https://subnetradar.com/subnet/110)
  - ComputeHorde SN12: 0% emission. — [SubnetRadar SN12](https://subnetradar.com/subnet/12)
  - Weir SN36: ownership changed on 2026-11-02 after an on-chain "critique of Bittensor's governance" on 2026-10-27. — [SubnetRadar SN36](https://subnetradar.com/subnet/36)
  - Instant SN46: a 2026-09-25 dispute described a possible exit or real-estate pivot. — [TAO Outsider](https://www.taooutsider.com/subnet-research/)
- **Older reference (low confidence):** a search excerpt of PlatformNetwork/platform described challenges "in TDX-secured VMs via dstack, with TDX/SGX/SEV-SNP attestation verification". The current repo (Cortex, SN100) says nothing about TEEs. — [GitHub PlatformNetwork/platform](https://github.com/PlatformNetwork/platform)

### Inferences
- Netuid churn in October and November 2026 was heavy: SN2, SN27, SN34, SN36, SN39, SN42, SN70 and SN103 all changed identity or owner. Netuid alone is not a stable reference. A URnetwork integration should pin on team and product endpoints and recheck the registry before trusting any netuid.
- None of the subnets that left was a *shipped* TEE compute or inference product. The TEE losses are prototypes (SN2), data-scraping enclaves (SN42), or never-enabled roadmap items (Verathos).

### Gaps
- Exact dates are unknown for:
  - Polaris' on-chain deregistration (the article is dated 2025-11-01);
  - the end of Nineteen's inference service;
  - the year of Quasar's acquisition of SN27, and when SN27 went from Orion to Komms;
  - what happened to SN39 between Basilica and Kokoah, including the "Cathedral" rename.
- Whether Basilica (basilica.ai) still operates as an off-chain compute product is unclear.
- Masa's tee-worker deployment status in 2026, and whether SN42's change was a sale or a re-registration, could not be confirmed.
