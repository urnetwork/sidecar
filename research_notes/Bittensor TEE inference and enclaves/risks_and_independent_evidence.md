# Risks, critiques and independent evidence: relying on Bittensor TEE subnets (Chutes SN64, Targon SN4) for confidential inference and TEE VMs

Research date: 2026-11-23. Every claim is dated. Items dated before about mid-2026 are marked "possibly superseded". "Documented" means a primary source (code, ToS, provider page, API output, or a dated hands-on audit) shows it. "Inference" and "speculation" are my own reasoning and are labelled. API snapshots I pulled myself (OpenRouter, CoinGecko, GitHub) are dated 2026-11-23.

## Has any TEE claim by Chutes or Targon been shown false, weakened, or unverifiable? Has anyone independently verified an attestation end to end and published how?

### Takeaway
Yes, the claims are weakened, though not shown false at the hardware layer. Independent audits in 2026 found real Intel TDX and NVIDIA confidential-computing hardware behind both subnets. For Chutes, however, three things are documented: the default API path is plaintext at Chutes' control plane; the in-enclave serving code and the model weights are not measured; and an operator-capability demo pulled prompts out of a `verified=True` enclave. Both fixes are still open issues as of November 2026. Targon gives the renter no quote and no end-to-end encryption, and its attestation verdict is a closed boolean returned by Manifold's own "Tower" service. Chutes attestation has been verified end to end by third parties, who published code; I found no published independent client-side verification of Targon. Separately, the TEE.fail attack (October 2025) shows that anyone with physical access (which Bittensor miners have) can forge TDX quotes and borrow NVIDIA attestations for under $1,000 of hardware. Intel and AMD treat this as out of scope.

### Cited Findings
**Chutes: independent audits and verification**
- DevProof case study of Chutes `-TEE` confidential compute (live tests 2026-06-16/17; commits 2026-06-17). The headline: "The cryptographic core is sound and hardware-rooted — verified live. But the chute's **application code and model run unmeasured inside the enclave**, so a verified quote proves 'genuine TDX+GPU running *a* Chutes-blessed base image,' not '*this* model on *this* code.'" The miner/host is assessed as contained by a measured admission controller; the remaining trust sits with Chutes (control plane, server-side build and signing) and with the chute operator. — [DevProof Chutes README](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/README.md)
- Documented demo (2026-06-16/17, on the author's own chute, `verified=True`, 1×RTX PRO 6000). Operator-added middleware collected two "victim" callers' decrypted prompts in process RAM and returned them verbatim to a third caller through the normal encrypted completion channel: "No network egress, no logs." The authors frame it as "a verifiability gap, not a remote exploit" and an operator-capability test, not a breach of production users. The exposure applies where a chute is offered as private inference to users who did not deploy it, including "the models on `llm.chutes.ai`" and "a third party reselling a chute as confidential." — [DevProof OPERATOR-EXFIL-POC](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/OPERATOR-EXFIL-POC.md)
- Finding I1 (June 2026), "The default path is plaintext at the control plane": the OpenAI-compatible path (`llm.chutes.ai`) parses the JSON body, rewrites the model alias, iterates the messages and hashes prompt prefixes for cache routing before forwarding. Verdict: "For the path the vast majority of API users hit, Chutes **does** see prompts." The "not even we can see your data" claim holds only on the explicit `/e2e/invoke` path with a verifying client. — [DevProof REPORT-inference](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/REPORT-inference.md)
- Finding I2 (June 2026): E2E key discovery (`GET /e2e/instances/{chute_id}`) returns a miner-supplied `e2e_pubkey` with no quote, and Chutes' own example client encrypts without fetching evidence. A non-verifying client can therefore be MITM'd by the control plane. Issue chutesai/e2ee-proxy#3, "Validate the e2ee public key against TDX attestation", opened 2026-06-18, was still **open** on 2026-11-23 (last updated 2026-11-18). — [DevProof REPORT-inference](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/REPORT-inference.md); [GitHub issue e2ee-proxy#3](https://github.com/chutesai/e2ee-proxy/issues/3)
- Reseller view (June 2026), directly relevant to an integrator. A Chutes customer "cannot pass a confidentiality guarantee through" to its own users, because the tenant image is "built+signed by Chutes server-side and bound to no measured register" (R1, High). Production RTMR3 = 0, and the tenant can't compute its own image digest. Tenant data is confidential from the miner (✅) but not from Chutes (❌, R3: Chutes builds the image and holds the cosign and LUKS keys). "TEE VMs have no SSH" except the `@chute.job` path, which was quota-gated to 0 and therefore unaudited (R4). — [DevProof REPORT-reseller](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/REPORT-reseller.md)
- Lower-tier finding (June 2026; possibly superseded): boot attestation releases "one static `LUKS_PASSPHRASE` identical for every node" (F5). GPU verdict is obtained only via NVIDIA NRAS (F4). — [DevProof PLATFORM.md](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/PLATFORM.md)
- chutesai/chutes#75, "Make the per-chute serving code verifiable in the attestation": opened 2026-06-18, **still open** on 2026-11-23 with no maintainer reply. The 2026-11-17 follow-up checked 176 production quotes from 19 chutes across 5 accounts. All verified against Intel PCS, but "the quote still tells a client which base VM is running and nothing about the serving code or weights." It also found that "VMs were shared across accounts", so one chute per VM is not guaranteed and tenants co-reside inside one TD. — [GitHub issue chutes#75](https://github.com/chutesai/chutes/issues/75)
- Independent operator review dated 2026-11-15: all gaps "unchanged". chutesai/chutes had no commits on main since 2026-05-25. **chutesai/chutes-api (the control plane) is archived**, last commit 2026-09-03, "so the control plane that receives default-path prompts no longer has current public source." The review also flags that Chutes both publishes the reference measurements and releases disk keys against a ConfigMap it edits. — [awesome-private-inference operator review 2026-11-15](https://github.com/amiller/awesome-private-inference/blob/main/research/operator-review-2026-11-15/chutes.md). I confirmed via the GitHub API on 2026-11-23: `archived: true`, `pushed_at 2026-09-03`. — [chutesai/chutes-api](https://github.com/chutesai/chutes-api)
- Unpublished-image case (documented 2026-10-12, write-up 2026-11-15). Instance `912aec3d` served `Qwen3-32B-TEE` with a quote that verified as UpToDate and was nonce-bound, but its MRTD `ddc6efcd…` matched none of the 55 published rows, all of which carried MRTD `261CE538…`. The MRTD had been in the published set from 2026-06-18 to 2026-09-02 and then withdrawn, so a withdrawn image was still serving. The quote was not retained, so the case cannot be replayed. — [chutes-912aec3d evidence gap](https://github.com/amiller/awesome-private-inference/blob/main/research/chutes-912aec3d-evidence-gap-2026-11-15.md); [abalone PR #13](https://github.com/amiller/abalone/pull/13)
- **End-to-end verification published, with method** (draft PR, 2026-10-12, GitHub user amiller). The client:
  - lists a chute's instances and their ML-KEM-768 keys;
  - fetches fresh evidence for each instance;
  - verifies the TDX DCAP quote against Intel PCS, requiring TCB `UpToDate`;
  - checks that `report_data` binds the nonce, the E2E key and the evidence certificate's SPKI;
  - matches MRTD and RTMR0-3 against a 55-row snapshot of Chutes' published measurements;
  - verifies GPU evidence through NVIDIA NRAS;
  - seals the whole request (ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305) to `/e2e/invoke`, unstreamed, because "Chutes' streamed frames lack sequence numbers."

  Caveats stated in the PR: the measurement anchor is "a copy of Chutes' own unsigned feed", "Nothing in the quote binds which model answers", and live evidence carries `instance_id: null`. — [abalone PR #13](https://github.com/amiller/abalone/pull/13)
- A runnable reproducer, `verify_chutes.py` (~115 lines, June 2026), checks five crypto-core properties plus model substitution ("two different `-TEE` models, byte-identical quote"). — [DevProof Chutes README](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/chutes-confidential-inference/README.md)
- A third production verifier: taostat/gm-miner PR #271 (merged 2026-09-23) routes `-TEE` Chutes models through a local proxy that "admits instances on verified evidence and encrypts each request end to end." Non-TEE Chutes selectors go directly to llm.chutes.ai. — [taostat/gm-miner PR #271](https://github.com/taostat/gm-miner/pull/271)
- AnonRouter (undated docs, read 2026-11-23) caps Chutes at `provider-attested` because "The missing complete Intel/NVIDIA vendor chain keeps the result at `provider-attested`." It reports "Chutes has no callable route; its rows below are a protocol reference." This cap partly reflects AnonRouter's own unwired vendor-chain port, which applies to every provider it lists. — [AnonRouter TEE verification](https://docs.anonrouter.ai/tee-verification)
- Chutes' own TEE page (checked 2026-11-23):
  - "11 of 20 models report confidential_compute: true" (14 were reported on 2026-10-17, per search-indexed Chutes pages);
  - recommends filtering on the flag rather than the `-TEE` suffix;
  - "Evidence that parses is not the same as a passed cryptographic (DCAP) verification";
  - "The hypervisor is outside the trust boundary";
  - no third-party audit is mentioned.

  — [Chutes TEE page](https://chutes.ai/tee)
- Chutes' own legal documents (2026-11-01) concede limits: the TEE "reduces risk but does not eliminate it"; "the measures in items 2 through 5 apply in full only to Confidential Compute Models." — [Chutes Privacy Policy](https://chutes.ai/privacy); [Chutes DPA](https://chutes.ai/dpa)
- New Chutes repositories created 2026-11-20 suggest a coming "bring-your-own Intel TDX VM" product on **Google Cloud**. `chutes-tdx-measure`: "Predict, capture, sign and verify the TDX measurements of a customer-built VM image, as the Chutes gateway checks them". `chutes-tdx-image`: "Reference Intel TDX guest image template for Google Cloud (mkosi, UKI, dm-verity…)". `chutes-tdx-gate`: attestation route plus E2E front end. The product's launch status, pricing and terms are not documented. — [chutes-tdx-measure](https://github.com/chutesai/chutes-tdx-measure); [chutes-tdx-image](https://github.com/chutesai/chutes-tdx-image); [chutes-tdx-gate](https://github.com/chutesai/chutes-tdx-gate)

**Targon: independent audit**
- DevProof audit of Targon SN4 (2026-05-25) concluded: "Targon's **hardware root is real**", but "it fails at every layer" of external verifiability. Main findings:
  - **F1 (Critical):** validators forward an opaque quote to `tower.targon.com` and trust `{valid: bool}`. There is "**zero** local quote crypto in the entire Go tree". Intel Trust Authority's signed JWT is discarded.
  - **F2 (High):** "the user is never in the attestation loop, and there is no E2E channel."
  - **F3:** no workload or model identity is measured.
  - **F4 (High):** the CVM image is a "Manifold-built encrypted qcow2", the attestation agent is in no public repo, and no golden MRTD/RTMR set is published.
  - **F5:** provisioning is gated on "a self-reported host-posture report."
  - **F7:** auction prices and burn are set by Tower.
  - Credited: per-VM disk keys in ITA-KBS ("strictly better than Chutes' single static fleet-wide `LUKS_PASSPHRASE`") and IP-bound anti-cloning.

  — [DevProof Targon report](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/targon-confidential-compute/DEVPROOF-REPORT.md)
- The same audit noted that the older Targon inference product repo (`Manifold-Archive/targon-hub-api`) had been deleted, and "There is no inference path in this repo." — [DevProof Targon report](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/targon-confidential-compute/DEVPROOF-REPORT.md)
- A secondary review (2026-04-10, updated 2026-10-06) says the subnet incentive code is MIT-licensed but the orchestration layer (TVM) is closed, and "attestation only means something if the attested code can be reviewed." It cites the Intel co-authored paper (2026-03-23): "Decentralization does not eliminate the trust problem, it redistributes it." — [Own Your Mind, Targon review](https://ownyourmind.ai/tokenomics/targon-bittensor-confidential-compute/)
- A third-party profile (2026-08-09, updated 2026-11-17) says Targon bare-metal servers "are not confidential", and that the team sets auction targets, price caps and the burn. — [TaoScale, Targon SN4](https://taoscale.com/blog/subnets/targon-sn4)

**Physical-access attacks on TDX and NVIDIA CC (applies to both subnets)**
- TEE.fail (Georgia Tech and Purdue; IEEE S&P 2026; Intel advisory dated 2025-10-28, possibly superseded by later mitigations I did not find):
  - a DDR5 memory interposer that "should cost you under $1000" extracted Intel PCE attestation keys;
  - "A forged quote with invalid measurements passed Intel's DCAP verification at the highest trust level of UpToDate";
  - NVIDIA attestation reports "are not bound to a specific CVM or CPU" and can be "borrowed";
  - against Phala's dstack, a malicious provider could run workloads outside a CVM while forging attestation.
  - Intel: "there is no current mitigation besides separately ensuring physical security"; AMD considers interposers out of scope. Recommended practice is to know "which servers you trust and where they are located."

  — [TEE.fail](https://tee.fail/); [BleepingComputer](https://www.bleepingcomputer.com/news/security/teefail-attack-breaks-confidential-computing-on-intel-amd-nvidia-cpus/amp/); [Schneier on Security](https://schneier.com/blog/archives/2025/11/new-attacks-against-secure-enclaves.html)

### Inferences
- (Inference) For sidecar's design: a "TEE-backed" Chutes route only means "not even Chutes can see it" if sidecar does all of the following itself:
  1. uses `/e2e/invoke`, not the OpenAI-compatible default path;
  2. verifies each instance's quote and NVIDIA evidence and the `report_data` key binding before encrypting (Chutes' own clients don't);
  3. keeps its own history of reference measurements, because the published feed is unsigned and has changed;
  4. accepts that the serving code and weights are unmeasured. That means trusting Chutes (or whoever deployed the chute) not to read prompts and to serve the claimed model, until #75 is fixed.

  The default OpenAI-compatible path protects only against the miner.
- (Inference) Reselling a Chutes chute "as confidential" is the exact case the DevProof reseller report says can't be made provable to end users today. Marketing copy must not promise that "nobody, including the provider, can read prompts."
- (Inference) Targon's confidential VMs protect a renter from the GPU host only if the renter trusts Manifold's closed Tower, image builder and key broker. The renter gets no artifact to check. This is the opposite of what a "verifiable" product claim needs.
- (Speculation) Because Bittensor miners are anonymous operators with physical access, TEE.fail-class attacks fall squarely inside the realistic threat model. A well-resourced miner could in principle pass attestation while reading memory. No in-the-wild exploitation is reported.

### Gaps
- No response from Chutes maintainers to #75 or e2ee-proxy#3 was visible, and I found no public statement from Chutes or Manifold on TEE.fail.
- Whether the new BYO-TDX/Google Cloud tooling, or any unreleased Chutes change, closes the unmeasured-code gap is unknown. The repos appeared on 2026-11-20.
- I found no independent, published client-side verification of a Targon renter session. Per the May 2026 audit, the renter receives no quote at all. Whether Targon has since added renter-facing attestation is undocumented in what I found.
- I found no formal third-party security audit (e.g. a paid audit firm) of either subnet's TEE stack.

## What failures or incidents (outages, data leaks, model substitution, quantization substitution, miners serving wrong models) have been reported in 2025-2026, and how were they handled?

### Takeaway
I found no publicly reported data breach at Chutes or Targon in 2025-2026. The documented problems are of other kinds:
- Chutes: a withdrawn enclave image still serving (October 2026); intermittent per-model errors and capacity refusals; lower tool-call fidelity than official APIs in a November 2025 benchmark; a sharp drop in OpenRouter volume; catalog churn.
- Targon: it quietly retired its inference API and is no longer an OpenRouter provider.
- Bittensor platform: emissions were halted for 57 subnets by founder announcement, a major team left the network in a public dispute, and a fraud case surfaced.
- Nearby, a TEE-branded inference provider (Phala) disclosed an inference-server compromise in November 2026.

Chutes' status page shows "no incidents" for September to November 2026 and lists no monitored components, so it is a weak signal.

### Cited Findings
**Chutes reliability and fidelity**
- OpenRouter endpoint stats, pulled 2026-11-23. Chutes serves 8 models on OpenRouter; quantizations are as tagged by OpenRouter.

  | Model | Chutes quant | Chutes 1-day uptime | Peers |
  |---|---|---|---|
  | kimi-k2.6 | int4 | 99.67% | — |
  | kimi-k3 | mxfp4 | 94.44% | most at 100% |
  | glm-5.1 | fp8 | 99.67% | — |
  | deepseek-v4-flash-0731 | fp8 | 100% | — |
  | qwen3.6-27b | fp8 | 98.62% | — |
  | gemma-4-31b-it | fp4 | 98.24% | — |

  Chutes serves gemma-4-31b-it with a 131,072 context versus 262,144 at most peers. The API returned no latency or throughput values (null). — [OpenRouter endpoints API, kimi-k2.6](https://openrouter.ai/api/v1/models/moonshotai/kimi-k2.6/endpoints); [kimi-k3](https://openrouter.ai/api/v1/models/moonshotai/kimi-k3/endpoints); [glm-5.1](https://openrouter.ai/api/v1/models/z-ai/glm-5.1/endpoints); [gemma-4-31b-it](https://openrouter.ai/api/v1/models/google/gemma-4-31b-it/endpoints); [OpenRouter Chutes provider page](https://openrouter.ai/provider/chutes)
- Chutes' OpenRouter volume, per a secondary analysis of OpenRouter data: ~42B tokens/day peak on 2026-02-07, 8–12B/day by late March 2026, ~6.8B/day in April 2026, and a 7.7B/day average over the latest 89 days. Rayon Labs self-reports 160B tokens/day across all channels. — [Own Your Mind, Chutes review (updated 2026-10-06)](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
- Live failures in one all-model run (2026-10-12):
  - Qwen3-235B: HTTP 400 requiring `chutes_version >= 0.6.0`;
  - Nemotron: evidence returned 502;
  - Mistral: 404;
  - GLM-5.2: "429 at capacity";
  - one Qwen3-32B instance refused for an unpublished measurement.

  — [abalone PR #13](https://github.com/amiller/abalone/pull/13)
- Chutes' own 2026-02-27 announcement: the big models are "exceptionally resource-intensive" and frequently overloaded, and a "global GPU shortage" limits added inventory. — [Chutes community announcement, Feb 27 2026](https://chutes.ai/news/community-announcement-february)
- Status page (read 2026-11-23): "No incidents reported" for September, October and November 2026; no components listed. — [Chutes status, previous incidents](https://status.chutes.ai/incidents)
- OpenRouter lists no status page for Chutes (`status_page_url: null`). — [OpenRouter providers API](https://openrouter.ai/api/v1/providers)
- Tool-calling fidelity (Moonshot K2 Vendor Verifier, test date 2025-11-15; possibly superseded). On kimi-k2-thinking, Chutes (via OpenRouter) had the lowest trigger similarity (68.10%, below the 73% acceptance line) and the lowest schema accuracy (83.05%) of listed providers; Moonshot official scored 100% schema accuracy. On K2-0905, Chutes scored 96.70% schema accuracy. — [MoonshotAI K2-Vendor-Verifier](https://github.com/MoonshotAI/K2-Vendor-Verifier)
- Model and catalog churn:
  - TEE-flagged models: 14 (reported for 2026-10-17), 11 of 19 (2026-11-12), 11 of 20 (2026-11-23). — [Chutes TEE page](https://chutes.ai/tee)
  - GLM-5, Kimi K2.5, Qwen 3.5 and MiniMax M2.5 were pulled from the Base tier (announced 2026-02-27). — [Chutes announcement](https://chutes.ai/news/community-announcement-february)
- Chutes added **non-TEE "Standard Models" served by third-party Model Providers**, alongside TEE models. An X post says "Starting today, alongside our confidential TEE models, Chutes now offers a set of non-TEE model…"; the 2026-10-27 date comes from search-indexed Chutes pages and was not confirmed on the post. The ToS confirm that Standard Models "may run on infrastructure in the US or elsewhere, including Asia." — [Chutes on X](https://x.com/chutes_ai/status/2115081018512183733); [Chutes Terms §4.2–4.3](https://chutes.ai/terms)
- Model-substitution controls are vendor-documented only. Chutes describes `cllmv` per-token hashes tied to a Hugging Face model and revision, and a "watchtower" that hashes random slices of weights. I found no independent report of a miner caught substituting models. The independent audits say model identity is not in the attestation. — [Chutes security architecture docs](https://chutes.ai/docs/core-concepts/security-architecture); [GitHub issue chutes#75](https://github.com/chutesai/chutes/issues/75)

**Targon**
- Targon is absent from OpenRouter's provider list (API pulled 2026-11-23: 123 providers, no Targon; `openrouter.ai/provider/targon` returns 404). A bug report from about late September 2026 lists Targon among 11 slugs "OpenRouter no longer serves." — [OpenRouter providers API](https://openrouter.ai/api/v1/providers); [pydantic-ai issue #8885](https://github.com/pydantic/pydantic-ai/issues/8885)
- The Targon inference hub repo was deleted by 2026-05-25. The subnet is now a GPU/CVM rental auction. — [DevProof Targon report](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/targon-confidential-compute/DEVPROOF-REPORT.md)
- Targon's landing page (as of April 2026) claimed "99% uptime, sub-50ms latency." No independent measurement was found, and GPU counts were inconsistent (H100 vs H200 claims). — [Own Your Mind, Targon review](https://ownyourmind.ai/tokenomics/targon-bittensor-confidential-compute/)
- I found no Targon outage or security incident reports for 2026.

**Bittensor platform incidents**
- 2026-06-22: emissions were halted for 57 of 128 subnets, announced by co-founder Const (Jacob Steeves) on Discord. The mechanism was undisclosed. Owners of some working subnets said they were caught without prior contact. SN4 and SN64 were not affected. — [OurCryptoTalk](https://ourcryptotalk.com/news/bittensor-subnet-emissions-halted-57-subnets); [TAO Media](https://www.tao.media/bittensor-to-begin-blocking-emissions-to-inactive-and-exploitative-subnets/)
- About 2026-04-09: Covenant AI (Templar SN3, Basilica SN39, Grail SN81) left Bittensor, calling it "decentralization theatre". It alleged the founder suspended emissions and deprecated its infrastructure; Steeves denied he can suspend emissions. TAO fell 15–18% (sources differ). — [The Block](https://www.theblock.co/post/396959/covenant-ai-exits-bittensor-tao); [The Block, denial](https://theblock.co/post/397028/bittensor-co-founder-denies-suspending-subnet-emissions-after-covenant-ai-exit)
- August 2026: the "Quasar" fraud, a subnet whose weights were about 95% copied and then obfuscated. Single newsletter source. — [TAO Daily](https://taodaily.io/a-fraud-a-major-upgrade-and-a-new-direction-for-bittensor/)
- July 2024 (older; possibly superseded): a ~$8M wallet drain from a malicious PyPI package put the chain in "safe mode" (blocks produced, no transactions). — [The Block post-mortem](https://www.theblock.co/post/303547/bittensor-exploit); [Cointelegraph](https://cointelegraph.com/news/bittensor-network-halt-8m-theft)

**Inference-provider breaches in the same market (context)**
- Dragos canary research (published 2026-11-19) seeded about 2M prompts from July to November 2026 and found three breached inference providers. The earliest breach began in mid-July. On 2026-11-22 OpenRouter removed three providers and stripped 125 endpoints of ZDR eligibility. Neither Chutes nor Targon was named or cleared. — [The Hacker News](https://thehackernews.com/2026/11/openrouter-drops-3-providers-after.html); [Unite.AI](https://www.unite.ai/openrouter-cuts-three-providers-after-ai-prompt-exposure-findings/)

### Inferences
- (Inference) OpenRouter's 1-day uptime for Chutes is usually high-90s, but individual models dip to about 94%, and peers often sit at 99.9–100%. Sidecar should plan for per-model failover. Chutes' TEE catalog is small (11 models), so there may be no TEE fallback for a given model. Falling back to a non-TEE provider would break the product promise.
- (Inference) Chutes now mixes TEE and non-TEE models under one API, and its control plane remaps model aliases (DevProof I1). Sidecar must therefore pin exact `-TEE` chute IDs and check `confidential_compute` and the attestation on every request. Silent routing to a Standard Model (third-party provider, possibly in Asia, up to 30 days' retention) is a real failure mode.
- (Inference) For Targon, "TEE inference" isn't an off-the-shelf product. Sidecar would rent a CVM and run its own serving stack, inheriting all reliability work.

### Gaps
- I found no latency or throughput numbers for Chutes: OpenRouter's public API returned nulls, and I found no Artificial Analysis page for Chutes. I also found no independent per-request TEE-path latency measurements (attestation plus ML-KEM overhead).
- I could not establish whether OpenRouter-routed Chutes traffic uses TEE instances. OpenRouter tags show only quantization.
- No Chutes or Targon postmortems are published for the per-model failures above, and Chutes' status page shows nothing before September 2026 in the view I fetched.

## How exposed are customers to TAO price swings and emission changes; what do the teams say about sustainability; have prices or free tiers changed abruptly?

### Takeaway
Exposure is high and structural. Chutes' low prices have been largely funded by TAO emissions, estimated at 22–40× external revenue in March 2026. Emissions follow staking flows (Taoflow: subnets with negative net flows get zero) and governance decisions. Chutes' emission share fell from about 14.4% (March 2026) to about 5.8% (September 2026). TAO itself traded between $146 and $346 over the past year. Chutes has repeatedly tightened its free and subscription terms with short notice:
- August 2025: free allowance ended (secondary sources);
- February 2026: TEE access cut for Early Access users the same day it was announced; 5× usage caps added; models pulled from Base;
- March 2026: Early Access fully retired; OpenRouter sponsored free tier ended (secondary).

Its ToS lets PAYGO prices change on posting. Targon's miner economics are set centrally by Manifold's auction targets and burn.

### Cited Findings
- TAO/USD (CoinGecko, pulled 2026-11-23): $191.94. Over 365 days: $297.20 (2025-11-24), low $146.06 (2026-02-12), high $345.70 (2026-03-26), a +137% swing in about six weeks. — [CoinGecko API, TAO 365-day](https://api.coingecko.com/api/v3/coins/bittensor/market_chart?vs_currency=usd&days=365&interval=daily); [CoinGecko TAO](https://www.coingecko.com/en/coins/bittensor)
- Subsidy estimate (Pine Analytics, 2026-03-23; possibly superseded). Chutes received 14.4% of emissions (~518 TAO/day, ~$52M/yr at ~$275) against $1.3–2.4M/yr of external revenue, or 22–40×. The implied unsubsidized price is about $1.41 per million tokens, "1.6–3.5x" centralized rates. It argues there is no customer lock-in, and that if emissions fall, "prices would roughly double, miners would leave, or the subsidy gap would widen." The $10.4M Targon ARR figure "is a projection… not an audited number." — [Pine Analytics, Bear Case for Bittensor](https://pineanalytics.substack.com/p/the-bear-case-for-bittensor-tao)
- Emission shares are falling (chain reads cited by Own Your Mind):
  - Chutes: 14.39% (March 2026), 6.55% (2026-08-15), 5.82% (2026-09-22).
  - Rayon Labs' three subnets combined: ~23.7% (early 2026), 7.97% (2026-09-22).
  - Targon: ~5.73% (April 2026), 4.63% (2026-09-22).
  - An undated TaoScope page shows Chutes at 5.08%. One search snippet claimed Targon "is not currently capturing protocol emissions under Taoflow", which conflicts with the September read and is unverified.

  — [Own Your Mind, Chutes](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/); [Own Your Mind, Targon](https://ownyourmind.ai/tokenomics/targon-bittensor-confidential-compute/); [TaoScope SN64](https://www.taoscope.org/subnets/64)
- Revenue transparency at Chutes: its daily revenue series was withdrawn in mid-2026. Rebuilt from the Wayback Machine, it averaged $15.6K/day over its last 90 published days and peaked at $22.5K on 2026-03-25; part of February revenue was sponsored hosting. The "approaching $10M ARR" claim traced to an Altcoin Buzz post, not Rayon Labs. — [Own Your Mind, Chutes](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
- Emission mechanics:
  - dTAO launched in February 2025.
  - Since November 2025, "Taoflow" allocates emissions by an EMA of net TAO staking flows (~30-day half-life); "negative-flow subnets receive zero."
  - The first halving was 2025-12-14 (7,200 to 3,600 TAO/day); the next is estimated around December 2029.
  - Stress scenario: an exit by the Rayon trio could hit TAO 30–45%. Low-margin subnets "Chutes in particular" would face "raising prices… or exiting."

  — [Sawinyh, TAO tokenomics under stress (2026-04-23)](https://sawinyh.com/blog/bittensor-tao-tokenomics/)
- Deregistration: with 128 subnet slots full, a new registration deregisters the non-immune subnet with the lowest EMA alpha price. The immunity period is about 4 months. Emission halts can also come by announcement, as on 2026-06-22. — [Bittensor docs, subnet deregistration](https://docs.learnbittensor.org/subnets/subnet-deregistration); [OurCryptoTalk](https://ourcryptotalk.com/news/bittensor-subnet-emissions-halted-57-subnets)
- Chutes pricing and free-tier timeline:
  - **August 2025** (secondary; possibly superseded): free allowance cut; $5 one-time deposit perk replaced by $3/$10/$20 monthly plans; existing depositors kept 200 requests/day. — [RP With AI](https://rpwithai.com/chutes-is-no-longer-free/); [free-llm-api-resources issue #217](https://github.com/cheahjs/free-llm-api-resources/issues/217)
  - **2026-02-27** (primary): "Effective February 27, TEE model access is removed for Early Access users." The 200/day quota stayed for non-TEE models "until March 15", then the plan was fully retired. Each subscription was capped at "5× the equivalent Pay-As-You-Go value", possibly enforced over a "rolling 4-hour period". The top-5 users per tier had used 56× to 324× their subscription price in PAYGO-equivalent value; about 15% of accounts were affected. Chutes says it "is often the lowest-cost option of any Pay-As-You-Go provider" and intends to keep it that way. — [Chutes announcement, Feb 27 2026](https://chutes.ai/news/community-announcement-february)
  - **2026-03-20** (secondary): Chutes' sponsored free tier on OpenRouter ended. — [Activepieces, Chutes pricing 2026](https://www.activepieces.com/blog/chutes-ai-pricing-plans-limits-and-costs-2026)
  - **Current ToS** (2026-11-01): price changes take effect "at the next billing cycle, or when posted for PAYGO" (§12.7); subscriptions are for interactive or low-volume use, and production workloads require PAYGO (§5.4). — [Chutes Terms](https://chutes.ai/terms)
- Targon economics: miner rewards run as per-hardware auctions with USD target prices per card-hour and maximum prices. Unallocated emissions are burned, and "the team sets auction targets, price caps, and the burn, so miner economics can change quickly." — [TaoScale](https://taoscale.com/blog/subnets/targon-sn4); [DevProof Targon F7](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/targon-confidential-compute/DEVPROOF-REPORT.md)

### Inferences
- (Inference, rough arithmetic; alpha-vs-TAO valuation ignored) At 5.82% × 3,600 TAO/day × $191.94, Chutes' emissions are about $40K/day (~$14.7M/yr). Against Chutes' last published ~$15.6K/day revenue, the subsidy ratio is about 2.6×. Against Pine's $1.3–2.4M/yr it is about 6–11×. Either way the subsidy has shrunk a lot since March 2026, which is consistent with the February 2026 tightening. Targon: 4.63% × 3,600 × $191.94 ≈ $32K/day (~$11.7M/yr), roughly equal to its unaudited ~$10.4M ARR claim.
- (Inference) A prepaid, auto-renewing user "compute balance" priced off Chutes' PAYGO rates carries repricing risk: Chutes can change PAYGO prices on posting, while sidecar's users have prepaid. Sidecar needs its own margin buffer, the right to reprice its credits, and per-model price monitoring.
- (Speculation) If Taoflow turns SN64's net flows negative, or governance halts its emissions, miner capacity for TEE models (which need scarce TDX+H100/H200/B200-class hardware) would likely shrink before prices rise. Chutes' October 2026 move to third-party Standard Models and the Google Cloud TDX tooling could be read as hedging away from miner supply.

### Gaps
- I found no live, dated November 2026 emission-share read for SN64 or SN4; the latest dated reads are from 2026-09-22. I also have no current audited revenue for either team.
- I found no Chutes or Manifold statement on what customers get if emissions stop, and no published price-protection or notice-period commitments beyond the ToS clauses above.
- Targon's current price list and any price-change history were not found.

## Can a business get a contract, DPA, SLA, invoicing and fiat billing; are reselling and embedding allowed; what jurisdictions are the operating companies in? (Also covers privacy and data handling, OpenRouter labels, miner location, sanctions and acceptable use.)

### Takeaway
**Chutes** (as of 2026-11-01) has a real paper trail:
- operating company: Chutes Global Corp., a Delaware corporation;
- a self-executing DPA with SCCs and a 72-hour breach-notice target;
- Stripe (fiat) or crypto payment;
- embedding in your own product allowed, but white-label or standalone resale needs a separate written agreement;
- no uptime guarantee unless separately agreed;
- liability capped at the greater of $10K or 30 days' fees;
- you answer for your end users' acts as if they were your own.

Its "Network Operators" (miners) are worldwide, have no contract with Chutes, and are not disclosed in advance. **Targon** (Manifold Labs, Inc., Texas) has thin terms: ToS and privacy policy last updated 2025-07-10, a "personal or internal business purposes" licence, no SLA, no DPA, no stated payment terms, suspension "without notice", and a list of prohibited content that includes sensitive personal, financial and medical data. On OpenRouter, Chutes endpoints are **not** ZDR-eligible as of 2026-11-23.

### Cited Findings
**Chutes contract terms (ToS last updated 2026-11-01)**
- Entity and law: "Chutes Global Corp., a Delaware corporation." Delaware law; individual AAA arbitration with a class-action waiver (30-day opt-out). — [Chutes Terms](https://chutes.ai/terms)
- This conflicts with a secondary review (2026-10-06) that "found no registered entity: no Delaware, Cayman, or UK filing" and described the team only as "independent teams collaborating" (founder Jon Durbin; co-founder known by handle). The named entity appears in documents dated 2026-11-01. — [Own Your Mind, Chutes](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
- SLA: Chutes "does not guarantee any uptime, capacity, latency, or performance level" unless a separate written agreement says so; operators may change or end capacity at any time (§18.3). — [Chutes Terms](https://chutes.ai/terms)
- Embedding and resale:
  - You may "integrate the Platform into your own products" (§9.1), but must not give end users "direct or unrestricted access to the Platform" (§9.2).
  - Keys may not be sold or sublicensed (§3.3).
  - "Reselling or white-labeling as a standalone inference service requires a separate written agreement" (§9.3).
  - You remain "responsible for the acts and omissions of your End Users as if they were your own" (§9.2), plus indemnity (§17).

  — [Chutes Terms](https://chutes.ai/terms)
- Acceptable-use enforcement: remedies include removing content, restricting a model, suspending an API key, or suspending or terminating the account (§11.2). Repeat violators are terminated (§11.3). Suspension can be immediate "where reasonably necessary" (§16.2). — [Chutes Terms](https://chutes.ai/terms)
- Billing:
  - Stripe and blockchain deposits, including TAO (§12.2).
  - "Cryptocurrency payments are final and nonrefundable" (§12.3); Stripe refunds are discretionary (§12.4); taxes are extra (§12.5).
  - Prepaid balances are not redeemable for cash and are forfeited on termination, except where law requires or Chutes terminates for convenience and the balance was paid in fiat (§12.6, §16.3).
  - Liability cap: greater of US$10,000 or fees paid in the prior 30 days (§19.2).
  - Invoicing mechanics are not described.

  — [Chutes Terms](https://chutes.ai/terms)
- DPA (2026-11-01):
  - Incorporated by reference and self-executing ("Customer does not need to sign it").
  - Chutes acts as processor.
  - SCCs 2021/914 Modules 2/3 with Irish law and courts, plus UK and Swiss addenda.
  - 72-hour breach-notice target, including incidents at subprocessors.
  - One audit per 12 months at the customer's cost.
  - Model Providers (Standard Models) are listed on request, with 15 days' notice of new ones.
  - Network Operators "supply compute… without a bilateral contract" and Chutes "cannot give advance notice" of them.
  - Network Operators are "worldwide"; there is no EU-only residency commitment.

  — [Chutes DPA](https://chutes.ai/dpa)
- Sanctions and export: no access from comprehensively sanctioned regions or by restricted-list persons; EAR compliance; Chutes screens accounts (§14). — [Chutes Terms](https://chutes.ai/terms)
- Sensitive data: health information and government IDs may not be sent to Standard Models without a separate agreement (§7.5). — [Chutes Terms](https://chutes.ai/terms)

**Chutes privacy and data handling (Privacy Policy, 2026-11-01)**
- "Chutes does not log, store, or persist the content of your API requests or responses on Chutes systems", subject to §6.3 exceptions: transient buffers (≤24h), abuse investigations, legal holds, and debugging on request.
- Metadata logged includes timestamps, token counts, model and instance, and latency. It is kept 24 months for operations and 7 years for accounting. Security and IP logs are kept 90 days.
- Prompt-prefix hashes are kept ≤24h.
- "Chutes does not train on your content."
- For Standard Models, "a Model Provider's own staff and systems can access content while they process it". Standard retention is "generally up to 30 days", and flagged content can be kept "up to two years".
- Model Providers operate in the US and "other countries, including countries in Asia."
- No EU representative is named.

— [Chutes Privacy Policy](https://chutes.ai/privacy); [Chutes DPA](https://chutes.ai/dpa)

**Targon (Manifold Labs) terms and privacy**
- Terms (last updated 2025-07-10; possibly superseded, but this is the live page):
  - "Manifold Labs, Inc., a Texas Corporation", Texas law.
  - Services "as is" and "as available"; no SLA.
  - Licence "for personal or internal business purposes"; resale is not addressed.
  - Prohibited content includes pornographic or obscene material and "sensitive personal/financial/medical data."
  - Targon may "suspend or terminate your access… at our discretion, without notice."
  - "We will not use any data you submit… to train."
  - Customers represent they are not OFAC-sanctioned.
  - No payment terms appear on the page, and there is no DPA or GDPR text.

  — [Targon Terms](https://targon.com/terms)
- Privacy policy (2025-07-10): Austin, TX address; it doesn't address workload or prompt data, operator access, processing location, transfer mechanisms or a DPA. Rights requests go via Discord. — [Targon Privacy](https://targon.com/privacy)
- Miner location: per the May 2026 audit, Targon's key broker records each provider's IP (anti-clone), but I found no public location disclosure or region selection. — [DevProof Targon](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/targon-confidential-compute/DEVPROOF-REPORT.md); [Targon Terms](https://targon.com/terms)

**OpenRouter labels and listings (pulled 2026-11-23)**
- Providers API: Chutes has headquarters "US", datacenters null, no status page. Phala has headquarters "US" with status.phala.network. Near AI has headquarters null. Venice is US. Targon is absent. — [OpenRouter providers API](https://openrouter.ai/api/v1/providers)
- The ZDR-eligible endpoint list has 934 endpoints. It includes Venice and Near AI but **no Chutes and no Phala** endpoints. — [OpenRouter ZDR endpoints API](https://openrouter.ai/api/v1/endpoints/zdr)
- OpenRouter shows retention "as reflected in each provider's terms." On training it says only that it works with providers to ensure prompts aren't trained on, "but there are exceptions". The per-provider table did not render in my fetch. — [OpenRouter provider logging docs](https://openrouter.ai/docs/guides/privacy/provider-logging)
- One third-party page claims OpenRouter's table lists Chutes as "retaining prompts for an unknown period and possibly training". I could not confirm this on OpenRouter, so treat it as unverified.

### Inferences
- (Inference) A US business can sign up for Chutes self-serve, pay in fiat, and rely on a click-through DPA. Sidecar's model (prepaid credits, users never touch Chutes keys, inference embedded in sidecar) fits §9.1/§9.2. If the product is effectively "private inference as a service", §9.3 white-label/standalone resale could apply, so a separate written agreement, plus any SLA, should be negotiated.
- (Inference) Because sidecar is liable for its users' acts (§9.2) and Chutes can suspend the whole account immediately (§16.2), one abusive user could take down inference for all sidecar users. Mitigations: per-user abuse controls, possibly per-cohort Chutes accounts, and a contractual notice-and-cure clause.
- (Inference) Under GDPR, subprocessors with "no bilateral contract" who are not notified in advance (Chutes Network Operators) are hard to pass through in sidecar's own DPA. The defence rests entirely on the TEE. That defence is weakened by the unmeasured-code gap and by TEE.fail-class physical attacks on anonymous operators.
- (Inference) Targon's licence scope and its ban on sensitive data conflict with reselling confidential VMs to end users, and there is no DPA. A written agreement with Manifold Labs would be needed before using Targon commercially.
- (Speculation) Neither provider lets a customer pin miner location. For a US integrator, sanctions exposure is mostly mediated: sidecar pays a US corporation, which pays miners in emissions. But physical-attack risk and data-location promises can't be scoped to known jurisdictions.

### Gaps
- I found no evidence of negotiated enterprise contracts, SLAs, invoice formats or volume pricing for either provider.
- I couldn't establish whether a Chutes TEE customer can restrict processing to specific countries. The DPA says operators are worldwide.
- OpenRouter's per-provider retention and training labels for Chutes could not be read directly; the table is dynamic.
- Targon's payment, refund and credit terms were not found.

## Which baselines outside Bittensor offer verifiable TEE inference or confidential VMs today, and how do their guarantees compare?

### Takeaway
Independent reviewers (AnonRouter docs; the GitHub-hosted "awesome-private-inference" registry and DevProof case studies, 2026) rate every confidential-inference provider as having gaps. Of those reviewed, Tinfoil comes closest to client-side verifiability: an open-source, Sigstore-logged, SDK-verified stack, with SOC 2 Type I claimed. It still has open findings (router TCB below an AMD fix level, prompt rewriting in the control plane). Phala/RedPill, NEAR AI and Venice verify gateways or sessions rather than the model machine end to end. Phala disclosed an inference-server compromise in November 2026 and is no longer ZDR-eligible on OpenRouter. Relative to these baselines, Chutes is notable for a client-reachable quote with ML-KEM end-to-end encryption, but weaker on measured serving code and default-path plaintext. Targon gives renters no attestation artifact at all.

### Cited Findings
- **AnonRouter classification** (undated docs, read 2026-11-23):
  - **Tinfoil**: `sdk-verified`, the strongest tier listed, via the official `tinfoil@1.2.1` verifier. It is not advertised as E2EE because "the model selector is encrypted and not bound to an AnonRouter ticket."
  - **Phala**: gateway reaches `hardware-verified`, but "Prompts are decrypted inside the verified gateway… so these routes are not client-opaque E2EE"; model-machine CPU attestation is "enforced by the verified gateway, not checked by AnonRouter."
  - **NEAR AI**: `provider-attested`; "Current evidence does not independently prove the model-weight digest or complete silicon chain."
  - **Venice**: `provider-attested`, E2EE, but "Venice's own `verified` boolean is not accepted as proof," and on some routes "that enclave is a verified gateway rather than the machine running the model."
  - **Chutes**: `provider-attested`; no callable route.

  — [AnonRouter TEE verification](https://docs.anonrouter.ai/tee-verification)
- **Registry comparison** (snapshot 2026-11-22):
  - Chutes: "Serving code unmeasured," "Model not committed," "Code can change unmeasured."
  - RedPill/Phala: "a valid gateway quote is not a model attestation" (2026-08-18); api.redpill.ai is marked "Non-TEE backend allowed."
  - NEAR AI: "Gateway picks among 3 composes," "App-wide key, unlogged env."
  - Tinfoil: "TCB below AMD fix level" on live routers; "Control-plane prompt rewriting" in source; Sigstore and measurement checks pass but the verifier "does not reproduce the build."
  - Venice: depends on route ("Inference CPU unattested" via Phala).
  - Privatemode, Maple and others: "Not assessed."
  - Targon is not listed.

  — [awesome-private-inference comparison](https://amiller.github.io/awesome-private-inference/)
- **DevProof case-study index:** Phala verifier is "Stage 0" ("'verified' is not confidentiality"). RedPill/Phala gateway chain is "sound and reproducible", but a legacy attestation endpoint ignores its `model` parameter. NEAR AI is "Stage 0" (inner compose not in RTMR3, model weights unverified, operator log access). Tinfoil is "~Stage 1" ("Closes the Phala/NEAR compose-hash gap"). — [DevProof audits guide](https://github.com/amiller/devproof-audits-guide)
- **Phala incident** (preliminary report 2026-11-10): "An attacker took control of an inference server at Phala and could view request data while it was being processed." DeepSeek V4 Flash 0731 requests via OpenRouter from 2026-10-21 00:00 UTC to 2026-11-08 05:35 UTC are to be treated as exposed. The VM was serving "without our full production security hardening." Phala has not said whether the server was one of its attested CVMs. This was reportedly its second break-in in a month. — [The Hacker News](https://thehackernews.com/2026/11/openrouter-drops-3-providers-after.html); [Transclew](https://transclew.com/tech/phala-openrouter-ai-requests-exposed/)
- **Physical attacks on dstack:** TEE.fail showed Phala's dstack could be fooled by a malicious provider forging TDX attestation and relaying NVIDIA attestations (disclosed October 2025). — [TEE.fail](https://tee.fail/)
- **Tinfoil commercial:** the homepage lists "SOC 2 Type I Compliant." Enterprise is custom-priced, and the security-critical infrastructure is open source with transparency logs. No DPA found. — [Tinfoil](https://www.tinfoil.sh)
- **Privatemode (Edgeless Systems, Germany):** runs on Microsoft Azure; claims neither Microsoft nor Edgeless can access data; source available on GitHub. GDPR/HIPAA "by design" is a vendor claim on Product Hunt. DPA and SLA terms were not found in my search. — [Edgeless Privatemode](https://edgeless.systems/products/privatemode); [Product Hunt](https://www.producthunt.com/products/privatemode-ai-by-edgeless-systems)
- **OpenRouter ZDR status** (2026-11-23): Venice and Near AI endpoints are ZDR-eligible; Phala and Chutes are not. — [OpenRouter ZDR endpoints API](https://openrouter.ai/api/v1/endpoints/zdr)

### Inferences
- (Inference) No provider, inside or outside Bittensor, currently offers a third-party-verifiable chain covering hardware, measured serving code, model identity and E2E key binding with a contractually backed operator. Sidecar should treat "verifiable" as a per-route property it checks itself, using its own verifier and pinned references, not as a vendor label.
- (Inference) Compared with Chutes on confidential *inference*, Tinfoil currently has the stronger code-transparency story, and Venice and NEAR have OpenRouter ZDR eligibility. Chutes' advantages are price and a client-reachable quote with ML-KEM E2E.
- (Inference) For confidential *VMs*, Targon's renter has less verifiability than the inference baselines (no quote at all). Hyperscaler confidential VMs, or Chutes' new BYO-TDX-on-Google-Cloud tooling, would at least put hardware in known, physically secured data centres, the mitigation TEE.fail recommends. Their terms and pricing were not researched here.

### Gaps
- I didn't research hyperscaler confidential GPU VMs (Azure/GCP H100 CC) or Apple/Google private compute in depth, and have no side-by-side price comparison for any baseline.
- Privatemode, Maple and other providers have no independent hands-on assessment in the sources found.
- Whether Phala's compromised server was a TEE/CVM, and the full root cause, were pending as of 2026-11-23.
