# Chutes (Bittensor SN64) as a TEE inference and TEE compute provider: notes as of 2026-11-23

Method note: Where a fact says "observed 2026-11-23", this researcher fetched the public endpoint or read the code that day; the link is that endpoint or file. Chutes' own claims (blog, marketing pages) are labeled **[claim]**. Code, live API responses and third-party verifier output are labeled **[verified]**. Anything dated before mid-2026 is marked **(pre-mid-2026: may be superseded)**. The contracting entity is "Chutes Global Corp., a Delaware corporation", 2810 N Church St., Suite 89723, Wilmington, DE 19802 ([Terms](https://chutes.ai/terms), last updated 2026-11-01).

## 1. What is Chutes' TEE offering (names, since when, hardware, models), how does a client tell TEE from non-TEE, and can a client require TEE?

### Takeaway
As of 2026-11-23, Chutes serves 11 open-weight LLMs as "Confidential Compute Models" (`-TEE` ids, `confidential_compute: true`). They run on miner-operated Intel TDX VMs ("sek8s") with NVIDIA GPUs in confidential-computing mode: H200, B200, B300 or RTX Pro 6000. Since 2026-11-04 the same API also serves 9 non-TEE "Standard Models", which third-party Model Providers serve in plaintext. Clients tell them apart only by the catalog flag and model id. No request flag forces TEE. The only cryptographic hard fail is E2EE to an attested instance key, and only if the client checks the attestation itself. Chutes' own E2EE clients do not.

### Cited Findings
#### Product names and timeline
- Names in use: "TEE chutes", "Confidential Compute Models", "sek8s" (the TDX/k3s guest stack), model-id suffix `-TEE`, and the catalog field `confidential_compute`. The privacy policy separates "Confidential Compute Models", served by "Network Operators" (miners) "inside a TEE", from "Standard Models", which "may be served by a Model Provider" **[claim]**. — [Chutes Privacy Policy, last updated 2026-11-01](https://chutes.ai/privacy)
- sek8s repo created 2025-07-30 **[verified]**. — [chutesai/sek8s](https://github.com/chutesai/sek8s)
- First TEE launch post: "Confidential Compute for AI Inference: How Chutes Delivers Verifiable Privacy with Trusted Execution Environments", dated 2025-12-23 (pre-mid-2026: may be superseded). — [Chutes blog index](https://chutes.ai/news)
- Share of LLM tokens on `-TEE`-named chutes, computed by this researcher from Chutes' public stats on 2026-11-23 **[verified]**: 0% through Nov 2025; 17.8% in Dec 2025; 39.7% Jan 2026; 46.4% Feb; 67.5% Mar; 81.3% Apr; 96.2% May; ≥99.9% Jun–Sep 2026; 99.4% Oct; 97.8% Nov 1–23. — [api.chutes.ai/invocations/stats/llm](https://api.chutes.ai/invocations/stats/llm)
- Agent toolkit hosted in the chutesai org (community-originated; its badges point to Veightor/chutes-agent-toolkit), live-verified 2026-06-11: "Catalog collapsed to TEE-only: 13 models, every one `-TEE` / `confidential_compute: true`. The entire non-TEE tier (including all Llama models) is gone." It also says `PUT /chutes/{id}/teeify` is gone from the API; the deploy-side switch is now the SDK's `tee=True`. — [chutesai/chutes-agent-toolkit README](https://github.com/chutesai/chutes-agent-toolkit)
- Miner README, added in commit #144 on 2026-07-31: "The chutes network is now TEE-exclusive. All GPU worker nodes run inside Intel TDX confidential VMs… a node without the `chutes/tee=true` label will be rejected during `add-node`." Legacy GraVal verification is "deprecated and blocked" **[verified, code/docs]**. — [chutesai/chutes-miner README](https://github.com/chutesai/chutes-miner); [README commit history](https://github.com/chutesai/chutes-miner/commits/main/README.md)
- 2026-06-15 post **[claim]**: the platform and all active chutes are being migrated to be "fully TEE"; the validator stack is "protected via TEE (AMD SEV-SNP)"; Blackwell B200/B300 nodes were onboarded "in TEE". — [Please excuse our absence from Proof of Talk in Paris (2026-06-15)](https://chutes.ai/news/please-excuse-our-absence-from-proof-of-talk-in-paris)
- On 2026-11-04 Chutes added seven models that "use standard inference and do not run inside a trusted execution environment": GLM-5.3, DeepSeek V4.1 Flash 1017, GLM-5.2 Fast, Qwen3.8 Max 0902, DeepSeek V4 Pro 0813, Kimi K2.7 Code and Qwen3.8 2.4T A95B. The post tells users to "Select an available model from the catalog with `confidential_compute: true`" for confidential workloads. — [We're expanding our model catalog… (2026-11-04)](https://chutes.ai/news/were-expanding-our-model-catalog-with-glm-deepseek-qwen-and-kimi)
- The live OpenAPI has an "External" backend family: `POST /external/accounts` takes `adapter`, `base_url`, `credentials` and `auth_header_templates`, alongside `/external/chutes` and `/external/bindings`. This is the mechanism for chutes served by an upstream provider rather than by miners **[verified]**. — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)

#### Hardware
- **[claim]** TEE chutes run on sek8s inside Intel TDX confidential VMs. GPUs such as the H100 run in NVIDIA Confidential Computing mode with Protected PCIe. The hypervisor is outside the trust boundary. — [chutes.ai/tee (catalog check dated 2026-11-23)](https://chutes.ai/tee); [Security architecture docs](https://chutes.ai/docs/core-concepts/security-architecture)
- 2026-05-11 post **[claim]** (pre-mid-2026: may be superseded):
  - Hopper uses single-GPU passthrough (SPT CC) or PPCIe, which "passes all 8 GPUs on an HGX baseboard into one confidential VM".
  - "On Blackwell, MPT CC closes even this gap": NVLink traffic is encrypted.
  - On Hopper PPCIe, NVLink data is unencrypted on the wire; physical interposers are "out of scope".
  - RTX PRO 6000 multi-GPU has no NVLink, so GPU-to-GPU traffic goes through bounce buffers and tensor parallelism is "unusable".

  — [I built an open-source TEE stack… (2026-05-11)](https://chutes.ai/news/i-built-an-open-source-tee-stack-for-confidential-gpu-compute)
- Published accepted measurements, observed 2026-11-23 **[verified]**: 60 profiles, all with one MRTD (one TDVF firmware build). Guest versions 1.3.1 (19), 1.4.0 (5), 1.4.1 (15) and 1.5.0 (21). Expected GPUs: `h200` (19 profiles), `pro_6000` (18), `b200` (10), `b300` (13). Every profile is an 8-GPU host layout. There is **no H100 profile**, although the marketing page still names H100. — [api.chutes.ai/servers/tdx/measurements](https://api.chutes.ai/servers/tdx/measurements); [deprecated /servers/tee/measurements (63 profiles)](https://api.chutes.ai/servers/tee/measurements)
- sek8s commits added a B200 profile on 2026-09-03 and a B300 profile on 2026-09-14, and fixed "Keep B300 GPUs off PXB bridges so all 8 attach" on 2026-10-01. — [sek8s commits](https://github.com/chutesai/sek8s/commits/main)
- AMD SEV-SNP is being rolled in **[verified, API docs]**. The evidence endpoints take `include_amd`: "Include AMD SEV-SNP instances (tee_type snp…). The default becomes true on the date in the Sunset header." `GET /servers/snp/measurements` returned `[]` on 2026-11-23. — [OpenAPI](https://api.chutes.ai/openapi.json); [api.chutes.ai/servers/snp/measurements](https://api.chutes.ai/servers/snp/measurements)
- Independent run on 2026-11-13 (teep) **[verified, third party]**: `Qwen/Qwen3.6-27B-TEE` ran on Intel TDX with 1 GPU, arch BLACKWELL, SPDM GPU evidence. — [teep recorded Chutes report](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/report.txt)

#### Models served in TEE today (catalog fetched 2026-11-23; USD per 1M tokens: input / output / cached input; context length)
Source for every row: [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models) **[verified]**, matching [chutes.ai/pricing](https://chutes.ai/pricing). The /tee page also says "11 of 20 models reported `confidential_compute: true`" on 2026-11-23 ([chutes.ai/tee](https://chutes.ai/tee)).

| Model id (`confidential_compute: true`) | Price | Context / max output | Quant / engine |
|---|---|---|---|
| `Qwen/Qwen3.8-27B-TEE` | 0.039 / 1.25 / 0.0039 | 262,144 / 65,536 | fp8 / sglang |
| `google/gemma-4-31B-turbo-TEE` | 0.12 / 0.37 / 0.012 | 131,072 / 65,536 | fp4 (NVFP4) / sglang |
| `Qwen/Qwen3.5-27B-TEE` | 0.20 / 1.75 / 0.02 | 262,144 / 262,144 | fp8 / sglang |
| `Qwen/Qwen3.6-27B-TEE` | 0.25 / 2.00 / 0.025 | 262,144 / 65,536 | fp8 / sglang |
| `moonshotai/Kimi-K2.6-TEE` | 0.39 / 1.80 / 0.039 | 262,144 / 65,535 | int4 / vllm |
| `deepseek-ai/DeepSeek-V4-Flash-0731-TEE` | 0.44 / 1.32 / 0.044 | 1,048,576 / 131,072 | fp8 / sglang |
| `Qwen/Qwen3.5-397B-A17B-TEE` | 0.45 / 3.00 / 0.045 | 262,144 / 65,536 | fp8 / sglang |
| `zai-org/GLM-5.1-TEE` | 0.90 / 2.90 / 0.09 | 202,752 / 65,535 | fp8 / sglang |
| `deepseek-ai/DeepSeek-V3.2-TEE` | 1.00 / 1.00 / 0.10 | 131,072 / 65,536 | fp8 / sglang |
| `zai-org/GLM-5.2-TEE` | 1.25 / 3.95 / 0.125 | 1,048,576 / 65,535 | fp4 (NVFP4) / sglang |
| `moonshotai/Kimi-K3-TEE` | 1.85 / 9.50 / 0.185 | 1,048,576 / 65,535 | mxfp4 / sglang |

- The 9 **non-TEE** catalog entries (`confidential_compute: false`, `owned_by: "chutes"`, `quantization: null`) are: `deepseek-ai/DeepSeek-V4-Pro-0813` (0.85/2.65), `deepseek-ai/DeepSeek-V4.1-Flash-1017` (0.195/0.78), `zai-org/GLM-5.3` (0.80/2.50), `Qwen/Qwen4-Max` (1.50/4.50), `zai-org/GLM-5.2-Fast` (2.45/7.70), `Qwen/Qwen3.8-Max-0902` (2.00/6.00), `Qwen/Qwen3.8-2.4T-A95B` (2.00/6.00), `moonshotai/Kimi-K2.7-Code` (0.832/3.50) and `tencent/Hy4` (0.525/1.5625). — [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models)

#### Telling TEE from non-TEE; requiring TEE
- **[claim]** "Filter on that flag [`confidential_compute: true`] rather than the `-TEE` name suffix"; "Evidence that parses is not the same as a passed cryptographic (DCAP) verification." — [chutes.ai/tee](https://chutes.ai/tee)
- Chutes' local E2EE proxy rejects non-TEE models by default **[verified]**. The check reads `confidential_compute` from `/v1/models`; it is a catalog check, not an attestation check. The error reads: "model 'Qwen/Qwen3-32B' is not running in confidential compute (TEE)… Set ALLOW_NON_CONFIDENTIAL=true to override." — [chutesai/e2ee-proxy README](https://github.com/chutesai/e2ee-proxy); [lua/e2ee_discovery.lua](https://github.com/chutesai/e2ee-proxy/blob/main/lua/e2ee_discovery.lua)
- The E2EE invoke call pins a specific attested instance: `POST /e2e/invoke` requires headers `X-Chute-Id`, `X-Instance-Id` and `X-E2E-Nonce`. — [OpenAPI](https://api.chutes.ai/openapi.json)
- Routing aliases exist: `GET/POST /model_aliases/`, plus "`default:latency` / `default:throughput` routing alias after configuring a pool once at chutes.ai/app → Model Routing" (toolkit, June 2026). — [OpenAPI](https://api.chutes.ai/openapi.json); [chutes-agent-toolkit](https://github.com/chutesai/chutes-agent-toolkit)
- Privacy policy **[claim]**: "Every model page shows whether a model runs in a trusted execution environment". — [Privacy Policy](https://chutes.ai/privacy)

### Inferences
- A "TEE only" rule cannot rest on Chutes' plain OpenAI-compatible path. The Chutes API receives the plaintext and chooses the backend. A non-TEE "Standard Model" is now one model-id typo or one alias away, and it goes to a third-party Model Provider. Enforcing TEE needs three things together: (a) an allowlist of concrete `-TEE` ids, re-checked against `confidential_compute`; (b) E2EE to an instance key; (c) client-side attestation checks that fail closed.
- Hardware actually used today is TDX plus H200, B200, B300 or RTX Pro 6000 (per published measurements). The marketing pages' "H100" is out of date. GPU evidence seen by teep on a small model was a single Blackwell GPU.

### Gaps
- I did not fetch the 2025-12-23 launch post. The exact public-launch date for "-TEE" models is inferred from the token stats (first TEE usage in December 2025).
- No document says which specific third-party Model Providers serve the 9 Standard Models. The privacy policy §4.6 says the list is available "on request to customers that have a Data Processing Agreement" ([Privacy](https://chutes.ai/privacy)).
- No documented per-request "require TEE" header, and no documented guarantee that a `-TEE` id never falls back.

## 2. What can a remote client verify by itself, and who sees plaintext at each hop?

### Takeaway
A client can independently fetch, anonymously, a fresh TDX quote plus NVIDIA SPDM GPU evidence for every instance of a TEE chute. It can check these against Intel PCS and NVIDIA NRAS, and match MRTD/RTMRs against Chutes' published measurement list. The quote's REPORTDATA binds both the client nonce plus the instance's ML-KEM-768 E2EE public key, and the per-VM proxy TLS key. So E2EE (ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305) can keep the Chutes gateway blind, but only if the client verifies before encrypting. Chutes' own E2EE clients skip that step.

What the quote does not prove:
- which serving code (`/app/chute.py`) or which model weights run;
- that VMs are single-tenant (they are shared across accounts);
- anything about the API gateway.

The prompt cache is also shared across accounts (open issue, 2026-11-19).

### Cited Findings
#### Attestation and verification endpoints (all observed 2026-11-23 unless stated)
- `GET https://api.chutes.ai/chutes/{chute_id_or_name}/evidence?nonce=<64 hex>` (optional `include_amd`) returns "TEE evidence for all instances of a chute (quote, GPU evidence, certificate per instance)". It is rate-limited "per caller, or per client IP when anonymous". It works without an API key: an anonymous call returned 200 on 2026-11-23, although chutes.ai/tee says to pass your API key. `GET /instances/{instance_id}/evidence?nonce=…` is the per-instance form; it returns 409 if the instance is stale and 502 if its attestation proxy is unreachable **[verified]**. — [OpenAPI](https://api.chutes.ai/openapi.json); [chutes.ai/tee](https://chutes.ai/tee)
- Response shape, observed for `deepseek-ai/DeepSeek-V4-Flash-0731-TEE` (chute `b4d58772-…`) on 2026-11-23 **[verified]**:
  - Top-level keys: `evidence[]`, `failed_instance_ids`, `excluded_instance_ids`.
  - Per-instance keys: `tee_type` ("tdx"), `quote`, `gpu_evidence` (NVIDIA cert chains and evidence), `instance_id`, `certificate`, `signature` (256-byte RSA), and `attested_body` (base64 JSON `{evidence:{tdx_quote, nvtrust_evidence}, nonce}` carrying the caller's nonce).
  - Only 1 instance was returned.
  - The quote was TDX v4 (TEE type 0x81) with debug bit 0. MRTD and RTMR0–2 matched a published profile.
  - The `certificate` is X.509 with CN=attestation-service, issued by `O=chutes, OU=sek8s, CN=sek8s-vm-root-ca`, valid 2026-09-21 to 2027-09-21.

  — [api.chutes.ai/chutes/b4d58772-e72b-55d1-9d73-d30dff6d2ed8/evidence?nonce=…](https://api.chutes.ai/chutes/b4d58772-e72b-55d1-9d73-d30dff6d2ed8/evidence?nonce=0000000000000000000000000000000000000000000000000000000000000000)
- **REPORTDATA layout [verified]:**
  - `REPORTDATA[0:32] = SHA256(nonce_hex + e2e_pubkey_base64)` — [teep report 2026-11-13: "REPORTDATA binds SHA256(nonce_hex + e2e_pubkey_base64)"](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/report.txt); [teep NanoGPT/Chutes gap note](https://github.com/amiller/teep/blob/main/docs/attestation_gaps/nanogpt_chutes_evidence.md)
  - `REPORTDATA[32:64] = SHA-256(DER SubjectPublicKeyInfo of the per-VM proxy TLS cert)`. The code says "the 64-char nonce followed by the 64-char cert hash". This researcher recomputed it on 2026-11-23: SHA-256 of the returned certificate's SPKI equals `report_data[32:64]`. The first half is not the raw client nonce, consistent with the SHA256(nonce_hex + e2e_pubkey) binding above. — [sek8s providers/base.py](https://github.com/chutesai/sek8s/blob/main/src/sek8s/sek8s/providers/base.py); [sek8s nonce.py](https://github.com/chutesai/sek8s/blob/main/src/sek8s/sek8s/nonce.py)
- The `signature` / X-Signature is an RSA-PKCS1v15-SHA256 signature over the proxied response body, made with the host TLS private key. Its purpose: "signature proves key possession -> cert hash in TDX report data matches cert -> TDX quote is hardware-attested" (spec dated 2026-04-30). — [sek8s docs/specs/x-signature-header.md](https://github.com/chutesai/sek8s/blob/main/docs/specs/x-signature-header.md); [attestation-proxy CHANGELOG](https://github.com/chutesai/sek8s/blob/main/changelogs/attestation-proxy/CHANGELOG.md)
- Public transparency endpoints (no auth) **[verified]**:
  - `GET /servers/tdx/measurements`: accepted MRTD and RTMR0–3 per host profile and guest version.
  - `GET /servers/tee/measurements`: deprecated; boot and runtime RTMR sets; "No authentication required — public transparency endpoint".
  - `GET /servers/snp/measurements`: empty.
  - `GET /servers/signing-keys`: cosign public keys (`cosign/chutes.pub`, `cosign/dockerhub.pub`) and the Helm GPG key.

  — [OpenAPI](https://api.chutes.ai/openapi.json); [/servers/signing-keys](https://api.chutes.ai/servers/signing-keys)
- Independent verifier result (teep, 2026-11-13, `Qwen/Qwen3.6-27B-TEE`) **[verified, third party]**: "Score: 19/25 passed, 1 skipped, 5 failed (0 enforced, 5 allowed)".
  - Passed:
    - DCAP chain and signature;
    - debug off;
    - MRTD/MRSEAM policy;
    - REPORTDATA binding;
    - Intel PCS TCB "UpToDate";
    - NVIDIA SPDM signatures (Blackwell) and nonce binding ("answers the requester nonce derived from the client nonce and the instance key");
    - NRAS verified;
    - ML-KEM-768 E2EE round trip.
  - Failed:
    - `nonce_match` ("no echoed nonce; freshness rests on tee_reportdata_binding");
    - `tee_boot_config` ("RTMR[2] not in policy allowlist");
    - `cpu_gpu_chain` ("CPU-GPU attestation not bound");
    - `measured_model_weights`;
    - `cpu_id_registry` (not in the Proof of Cloud registry).
  - Not applicable: "Chutes supply chain verification is validator-side only" and "event log not exposed".

  — [teep report.txt](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/report.txt)
- Per-chute serving code is not measured **[verified, open issue]**. Issue #75 (opened 2026-06-18, still OPEN) says: "A verified quote proves you are talking to a genuine TDX enclave running a Chutes base image. It does not measure the per-chute serving code that decrypts and handles the prompt (`/app/chute.py`)… Chutes could substitute its own `serve.py` for a first-party model — the attestation is identical either way."

  The 2026-11-17 follow-up reports:
  - "176 quotes from 19 chutes and 5 accounts… all verify against Intel PCS… same MRTD. The RTMRs come in only three sets" (base-VM versions 1.4.0, 1.4.1, 1.5.0).
  - The author's private Llama 3.3 70B finetune chute "has the same RTMR1–3 as `Qwen/Qwen3.8-27B-TEE`".
  - Multi-tenancy: "my instance shared a VM with four instances of first-party Qwen chutes, and 5–6 VMs per snapshot held chutes from two or more accounts."
  - "The leaf cosign keys are still fetched at boot rather than measured."

  — [chutesai/chutes issue #75](https://github.com/chutesai/chutes/issues/75)
- Cross-tenant prompt-cache leak **[verified by reporter, open issue]**. Issue #78 (2026-11-19, OPEN): "the prompt cache behind each chute is shared across **all accounts**… Client-supplied `cache_salt` is ignored by the public API". The reporter tested all 11 `confidential_compute: true` models; "on all 8 where the warm-up gate succeeded… account B's first request hit account A's entry". Responses expose `usage.prompt_tokens_details.cached_tokens`. — [chutesai/chutes issue #78](https://github.com/chutesai/chutes/issues/78)
- Chutes' own verification tooling stops at "shape-valid" **[claim / blog]**. The 2026-09-15 post's attestation script printed "cryptographic validation: not run. Install Intel DCAP and run it against the saved envelope." The toolkit README (June 2026) says `shape-valid` "remains the practical verdict ceiling". — [I let Hermes write its own Chutes config (2026-09-15)](https://chutes.ai/news/open-agent-open-weights-open-enclave); [chutes-agent-toolkit](https://github.com/chutesai/chutes-agent-toolkit)
- Reproducible builds: the 2026-05-11 post said "we are actively working on providing them". sek8s now documents `docs/specs/tdx-measurement-verification.md`, covering how measurements are "structured, reproduced, and independently verified (on-host capture…; offline replay/generation in `chutes_cvm.measurement`)". No transparency log or Sigstore check is client-visible (teep: "Chutes cosign verification is validator-side only"). — [TEE stack post (2026-05-11)](https://chutes.ai/news/i-built-an-open-source-tee-stack-for-confidential-gpu-compute); [sek8s README](https://github.com/chutesai/sek8s); [teep report](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/report.txt)
- Boot and runtime protections **[claim]**:
  - The guest root disk is LUKS-encrypted; "Only the Chutes attestation/key service… can decrypt it after verifying Intel TDX measurements".
  - "TEE VMs have no SSH access".
  - An admission controller admits only cosign-signed images.
  - The 2026-05-11 post says the initramfs decrypts the root volume only after attestation against the platform API over mTLS, and that the platform API holds the volume passphrase (paraphrase). So Chutes, not the miner, controls disk-key release.

  — [sek8s README](https://github.com/chutesai/sek8s); [chutes.ai/tee](https://chutes.ai/tee); [TEE stack post](https://chutes.ai/news/i-built-an-open-source-tee-stack-for-confidential-gpu-compute)

#### End-to-end encryption (E2EE v1, GPU chutes)
- Protocol (2026-03-26 post; pre-mid-2026: may be superseded):
  - Key exchange and ciphers: ML-KEM-768 encapsulation, HKDF-SHA256 (info labels `e2e-req-v1`, `e2e-resp-v1`, `e2e-stream-v1`), ChaCha20-Poly1305 with a random 12-byte nonce, gzip before encryption, and a fresh ephemeral keypair per request.
  - Instance keys and single-use nonces come from `GET /e2e/instances/{chute_id}` (API key required; an anonymous call returned 401 on 2026-11-23). Nonces live 75 s server-side and 60 s client-side.
  - Invoke is `POST /e2e/invoke` with an `application/octet-stream` body. Streaming uses an `e2e_init` SSE event, then `e2e` chunks.
  - The relay "sees only ciphertext… The API does see usage metadata (token counts) for billing purposes."
  - Attestation verification is labeled "(Optional)".

  — [E2EE post (2026-03-26)](https://chutes.ai/news/end-to-end-encrypted-ai-inference-with-post-quantum-cryptography); [OpenAPI](https://api.chutes.ai/openapi.json)
- The live `/e2e/invoke` also takes optional headers `X-E2E-Stream`, `X-E2E-Path` and `X-E2EE-Usage-Passthrough`; the semantics of the last are undocumented. — [OpenAPI](https://api.chutes.ai/openapi.json)
- Official clients **do not verify attestation** **[verified, code]**:
  - `chutes-e2ee` (PyPI 0.1.0; repo last pushed 2026-03-11): `discovery.py` holds `instance_id`, `e2e_pubkey`, `nonces` and has no quote, evidence or attestation logic.
  - `e2ee-proxy` (Docker `parachutes/e2ee-proxy`) checks only the catalog flag.
  - Both encrypt to whatever `e2e_pubkey` the API returns.

  — [chutes-e2ee-transport discovery.py](https://github.com/chutesai/chutes-e2ee-transport/blob/main/src/chutes_e2ee/discovery.py); [e2ee-proxy](https://github.com/chutesai/e2ee-proxy)
- Third-party fail-closed verifiers exist **[verified, code]**:
  - **teep**: Go, AGPL-3.0; upstream 13rac1/teep created 2026-03-20; fork amiller/teep. It verifies the evidence and then does ML-KEM E2EE "with multi-instance failover".
  - **NioZow/chutes-litellm-proxy**: Python, no license; updated 2026-11-21. Before encrypting it "verifies the RSA signature over the evidence body, runs Intel DCAP on the TDX quote, binds `report_data` to the instance key and certificate, matches MRTD + RTMR0-3 against a published Chutes measurement, verifies NVIDIA NRAS GPU evidence… Any failure refuses the request (fail closed)".

  — [13rac1/teep](https://github.com/13rac1/teep); [amiller/teep README](https://github.com/amiller/teep); [NioZow/chutes-litellm-proxy](https://github.com/NioZow/chutes-litellm-proxy)
- Relay pitfall documented by teep: NanoGPT relays Chutes evidence but not the instance E2E keys. "Without these keys a client cannot check that any of the evidence was made for its request, and nothing tells the client which machine answers the request." — [teep: NanoGPT Chutes Evidence](https://github.com/amiller/teep/blob/main/docs/attestation_gaps/nanogpt_chutes_evidence.md)

#### TLS termination and gateway
- Responses from `api.chutes.ai` carry `server: nginx` and `via: 1.1 google` (observed 2026-11-23). teep's 2026-11-13 E2EE capture also shows `Via: 1.1 google` plus `X-Chutes-Quota-*` and `X-Chutes-Rl-User: 60` headers. — [teep manifest](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/manifest.json); [api.chutes.ai evidence endpoint](https://api.chutes.ai/chutes/b4d58772-e72b-55d1-9d73-d30dff6d2ed8/evidence?nonce=0000000000000000000000000000000000000000000000000000000000000000)
- For the validator-to-instance hop **[claim]**: "The TLS session for communication is terminated inside the confidential VM." — [Security architecture docs](https://chutes.ai/docs/core-concepts/security-architecture)
- The archived validator README (repo archived after 2026-09-03) recommends staking to Chutes' child hotkey `5Dt7HZ7Zpw4DppPxFM7Ke3Cm7sDAWhsZXmM5ZAmE7dSVJbcQ` rather than running a validator. Validators must run Postgres, Kubernetes and more, and "The CLI/SDK/etc., point to the `chutes.ai` subdomains by default". In practice the API gateway is the Chutes-operated validator. — [chutesai/chutes-api README](https://github.com/chutesai/chutes-api)
- No client-verifiable attestation of the API gateway exists. teep has no Chutes gateway tier, and the "validator stack… AMD SEV-SNP" statement is a blog claim only. — [teep report](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/report.txt); [2026-06-15 post](https://chutes.ai/news/please-excuse-our-absence-from-proof-of-talk-in-paris)

#### Hop-by-hop: who can see plaintext (TEE model, 2026-11-23)
| Hop | Plain HTTPS to `llm.chutes.ai` | E2EE (`/e2e/invoke`), client verified attestation first | Standard (non-TEE) model |
|---|---|---|---|
| Client device | Plaintext | Plaintext | Plaintext |
| Cloud ingress (`via: 1.1 google`) | TLS ends at Chutes' cloud ingress; plaintext from there (inferred from headers above) | Ciphertext inside TLS | As plain HTTPS |
| Chutes API / validator (Chutes Global Corp.) | **Plaintext.** Policy: not logged or stored, except §6.3 (transient buffers ≤24 h, abuse investigations, legal, debug) ([Privacy](https://chutes.ai/privacy)) | Ciphertext plus chute id, instance id, nonce, token counts, sizes and timing ([E2EE post](https://chutes.ai/news/end-to-end-encrypted-ai-inference-with-post-quantum-cryptography)); §6.3 exceptions "None of these exceptions applies to requests in end-to-end encryption mode" ([Privacy](https://chutes.ai/privacy)) | Plaintext |
| Validator to miner network | TLS terminating inside the CVM; cert key bound in REPORTDATA[32:64] ([sek8s base.py](https://github.com/chutesai/sek8s/blob/main/src/sek8s/sek8s/providers/base.py)) | Ciphertext | Goes to a third-party Model Provider. "a Model Provider's own staff and systems can access content"; retention "Generally up to 30 days"; flagged content "Up to two years" ([Privacy](https://chutes.ai/privacy)) |
| Miner host (hypervisor, host OS, NIC, disks) | Ciphertext / TDX-encrypted memory; LUKS disks ([chutes.ai/tee](https://chutes.ai/tee)) **[claim + hardware model]** | Same | n/a |
| Inside the TEE VM (k3s, attestation proxy, chute pod) | Plaintext to the chute's serving code, which is unmeasured ([#75](https://github.com/chutesai/chutes/issues/75)). VMs are shared across accounts; the KV cache is shared across accounts ([#78](https://github.com/chutesai/chutes/issues/78)) | Plaintext after in-VM decryption; same caveats | n/a |
| GPU | Plaintext in GPU memory (CC mode); CPU↔GPU bounce buffers encrypted; Hopper PPCIe NVLink unencrypted on the wire ([TEE stack post](https://chutes.ai/news/i-built-an-open-source-tee-stack-for-confidential-gpu-compute)) | Same | n/a |

- Via OpenRouter: Chutes serves `deepseek/deepseek-v4-flash-0731`, `google/gemma-4-31b-it`, `moonshotai/kimi-k2.6`, `moonshotai/kimi-k3`, `qwen/qwen3.5-27b`, `qwen/qwen3.6-27b`, `qwen/qwen3.8-27b` and `z-ai/glm-5.1` there. OpenRouter lists Chutes with "headquarters": "US", "datacenters": null. None of OpenRouter's 934 zero-data-retention endpoints are Chutes (observed 2026-11-23). — [openrouter.ai/provider/chutes](https://openrouter.ai/provider/chutes); [OpenRouter providers API](https://openrouter.ai/api/v1/providers); [OpenRouter ZDR endpoints API](https://openrouter.ai/api/v1/endpoints/zdr)

### Inferences
- E2EE plus client-side checks closes the gateway hop. The checks are: DCAP; debug off; MRTD/RTMR0–3 ∈ `/servers/tdx/measurements`; `REPORTDATA[0:32] == SHA256(nonce_hex ‖ e2e_pubkey_b64)`; NVIDIA SPDM/NRAS; and pinning the instance id plus key.
- It does **not** close the "operator of the image / serving code" hop. Chutes builds and signs the images, and the serving code is unmeasured. Chutes can, by design, change what runs inside the TEE without changing the quote (issue #75).
- The shared KV cache is an active cross-tenant side channel even for TEE models (issue #78). A per-user cache salt has to be injected server-side; client `cache_salt` is ignored.
- If URnetwork relays traffic through its own servers (e.g., to hold the Chutes API key), the device must get the raw `e2e_pubkey` list plus evidence and do the verification and encryption itself. Otherwise URnetwork's relay becomes the NanoGPT-style gap teep documents.
- Miners physically control the hosts. That is the physical-attacker model which interposer attacks of the TEE.fail type target, and which Intel and NVIDIA treat as out of scope. teep's `cpu_id_registry` check failed: there is no independent check of where the CPU sits. — [TEE.fail](https://tee.fail/); [teep report](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/report.txt)

### Gaps
- I did not obtain an `e2e_pubkey` (needs an API key), so I could not recompute `REPORTDATA[0:32]` myself; the binding relies on teep and NioZow code and outputs.
- teep's RTMR2 mismatch may be teep's own stale allowlist rather than an unpublished Chutes measurement. Not resolved.
- No public spec for `X-E2EE-Usage-Passthrough`; no documentation of the plaintext "usage summary" format.
- No primary detail on the "validator stack protected via TEE (AMD SEV-SNP)" claim, and no attestation of it.

## 3. API surface (OpenAI compatibility, streaming, tools, auth, keys, rate limits, context lengths)

### Takeaway
Chutes offers an OpenAI-compatible Chat Completions API at `https://llm.chutes.ai/v1` with streaming. Every current model advertises tools, JSON mode, structured outputs and reasoning. The management and E2EE APIs are at `https://api.chutes.ai`. Anthropic Messages and OpenAI Responses are provided by Chutes-published translation proxies, not natively by the E2EE path. Auth is `cpk_…` API keys (Bearer), which can be scoped, plus an OAuth2/OIDC "Sign in with Chutes" IdP. No numeric rate limits are published.

### Cited Findings
- Base URLs: `https://llm.chutes.ai/v1` (`/v1/chat/completions`, `/v1/completions`, `/v1/models`) and `https://api.chutes.ai` (`/e2e/*`, evidence, management). — [chutes-e2ee-transport README](https://github.com/chutesai/chutes-e2ee-transport); [e2ee-proxy README](https://github.com/chutesai/e2ee-proxy); [2026-11-04 post: "OpenAI-compatible API… `https://llm.chutes.ai/v1`"](https://chutes.ai/news/were-expanding-our-model-catalog-with-glm-deepseek-qwen-and-kimi)
- Per-model `supported_features` is `["json_mode","tools","structured_outputs","reasoning"]` for all 20 catalog models (2026-11-23) **[verified]**. — [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models)
- OpenRouter's view of Chutes' `deepseek/deepseek-v4-flash-0731` endpoint (2026-11-23): supported parameters include `reasoning`, `include_reasoning`, `reasoning_effort`, `tools`, `tool_choice`, `response_format`, `structured_outputs`, `seed`, `top_k` and `repetition_penalty`. Chutes' endpoints for `qwen/qwen3.8-27b`, `z-ai/glm-5.1` and `moonshotai/kimi-k2.6` show `supports_implicit_caching: true`. — [OpenRouter endpoints API (DeepSeek V4 Flash)](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash-0731/endpoints); [qwen3.8-27b](https://openrouter.ai/api/v1/models/qwen/qwen3.8-27b/endpoints); [glm-5.1](https://openrouter.ai/api/v1/models/z-ai/glm-5.1/endpoints)
- Anthropic Messages and OpenAI Responses:
  - `e2ee-proxy` exposes `POST /v1/messages` and `POST /v1/responses`, which are "translated to chat completions before encryption".
  - `claude-proxy` (Rust; hosted at `https://claude.chutes.ai` per its installer) translates the Claude Messages API onto `/v1/chat/completions`.
  - `responses-proxy` (Rust) translates the Responses API into Chat Completions.

  — [e2ee-proxy](https://github.com/chutesai/e2ee-proxy); [claude-proxy](https://github.com/chutesai/claude-proxy); [responses-proxy](https://github.com/chutesai/responses-proxy)
- Embeddings: no embedding model is in the public `/v1/models` catalog (20 LLMs, 2026-11-23). The SDK has embedding templates for custom chutes ("vllm, sglang, and embedding templates"). — [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models); [chutes SDK README](https://github.com/chutesai/chutes)
- Auth and keys:
  - `POST /api_keys/` takes `{admin, name, scopes:[{object_type, object_id, action}]}`. "OAuth access tokens and existing API keys cannot mint credentials."
  - The OAuth2/OIDC IdP lives at `/idp/*` (authorize, token, introspect, revoke, userinfo, apps).
  - Public scope list (`GET /idp/scopes`): `admin`, `profile`, `balance:read`, `billing:read`, `quota:read`, `usage:read`, `account:read/write`, `secrets:read/write`, `chutes:read/write/delete/invoke`, `images:read/write/delete`, `invocations:read`.

  — [OpenAPI](https://api.chutes.ai/openapi.json); [api.chutes.ai/idp/scopes](https://api.chutes.ai/idp/scopes)
- "Sign in with Chutes" is an OAuth 2.0 + OIDC + PKCE relying-party kit. — [Sign-in-with-Chutes repo](https://github.com/chutesai/Sign-in-with-Chutes); [chutes-agent-toolkit](https://github.com/chutesai/chutes-agent-toolkit)
- Sub-account style funding: `POST /users/balance_transfer` "Transfer balance from the authenticated user to a target user" (hotkey auth, admin API key, or fingerprint). — [OpenAPI](https://api.chutes.ai/openapi.json)
- Rate limits:
  - No published numeric limits. Quotas are visible per user (`GET /users/me/quotas`, `/users/me/quota_usage/{chute_id}`).
  - The evidence endpoints document 429s.
  - Observed headers: `X-Chutes-Quota-Remaining/Total/Used`, `X-Chutes-Rl-User: 60` (2026-11-13).

  — [OpenAPI](https://api.chutes.ai/openapi.json); [teep manifest](https://github.com/amiller/teep/blob/main/internal/integration/testdata/current/chutes_chutes/manifest.json)
- Context lengths of the TEE models are in the section 1 table: 131K to 1M tokens. — [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models)

### Inferences
- A Go client (the sidecar) would call `llm.chutes.ai/v1/chat/completions` for plain use. For TEE-only use it would implement `/e2e/instances` + `/e2e/invoke` itself; there is no official Go E2EE client. Anthropic/Responses-format callers would need local translation.
- Scoped API keys exist, but the terms bar handing keys to end users (section 4). Per-device keys are not a compliant integration pattern without a separate agreement.

### Gaps
- Whether `llm.chutes.ai` natively serves `/v1/responses` or `/v1/messages` (outside the proxies) was not verified.
- No published per-key or per-account RPM/TPM limits; the meaning of `X-Chutes-Rl-User: 60` is unconfirmed.

## 4. Pricing, payment (incl. Gamma), funding mechanics, refunds, usage reports, and terms

### Takeaway
Pricing is pay-as-you-go per token. TEE models are not priced at a premium; they cost $0.039–$1.85 per 1M input tokens. Monthly plans are no longer sold. Payment is by Stripe (card, bank, crypto), TAO or Bittensor alpha deposits, or enterprise invoicing.

Gamma: **no evidence that Chutes accepts it as of 2026-11-23**. Chutes was named in September 2026 as one of seven "initial Gamma issuers", but its pricing page, ToS and live API show no Gamma path.

Terms allow embedding in your own product. They forbid reselling it as a standalone inference service without a written agreement, and forbid giving API keys to end users. Crypto payments are final.

### Cited Findings
#### Prices and plans
- Per-token TEE and Standard prices are in section 1 (catalog 2026-11-23). OpenRouter shows the same prices for Chutes' endpoints. — [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models); [OpenRouter endpoints API](https://openrouter.ai/api/v1/models/qwen/qwen3.8-27b/endpoints)
- Pricing page FAQ (fetched 2026-11-23): "Monthly plans are no longer sold on chutes.ai"; existing plans run to the end of their billing period and do not renew. Pay-as-you-go has "no minimum commitment"; there is no free tier, no stated minimum top-up, and no crypto discount. Volume discounts are via enterprise sales. — [chutes.ai/pricing](https://chutes.ai/pricing)
- Earlier history (pre-mid-2026: may be superseded): the 2026-02-27 announcement capped subscriptions at a PAYG-equivalent ceiling and removed GLM-5, Kimi K2.5, Qwen 3.5 and MiniMax M2.5 from the Base tier. A secondary source says the free tier (200 requests/day) was eliminated and quotes "heavy users were extracting 56x to 324x their subscription value". — [Community Announcement 2026-02-27](https://chutes.ai/news/community-announcement-february); [ownyourmind.ai (2026-04-10, updated 2026-10-06)](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
- Dedicated TEE GPU ("Private Chutes"), from the pricing page on 2026-11-23: RTX Pro 6000 at $2.25/hour, billed per second, plus a one-time deployment fee of 3× the hourly rate ($6.75). The June 2026 toolkit noted $1.80/hr. Public GPU price estimates (2026-11-23) for the GPU types that have TEE profiles: `pro_6000` $2.25/h, `h200` $5.00/h, `b200` $7.75/h, `b300` $8.75/h. `tao_usd` was 191.2386. — [chutes.ai/pricing](https://chutes.ai/pricing); [api.chutes.ai/pricing](https://api.chutes.ai/pricing); [chutes-agent-toolkit](https://github.com/chutesai/chutes-agent-toolkit)

#### Payment methods and funding mechanics
- Pricing page (2026-11-23): "Card, crypto, and bank transfer, among 25+ methods via Stripe"; "TAO and Bittensor alpha tokens"; "Enterprise custom terms, including invoicing". The page does not mention Gamma. — [chutes.ai/pricing](https://chutes.ai/pricing)
- ToS (2026-11-01):
  - §12.2 accepts Stripe and "supported blockchain deposits, including Bittensor (TAO)".
  - §12.3 "Cryptocurrency payments are final and nonrefundable."
  - §12.4 "Payments made through Stripe may be refundable in limited circumstances".
  - §12.6 "Prepaid balances are not redeemable for cash, except where the law requires otherwise."
  - §16.3 "Any unused prepaid balance is forfeited, except where the law requires a refund".
  - §12.7 "We may change prices with reasonable notice."

  — [Terms](https://chutes.ai/terms)
- Deposit mechanics, from validator code that was archived after its last commit on 2026-09-03 (may differ from production now) **[verified, code]**:
  - Each registered user gets "a unique bittensor coldkey address for payments and another for developer deposits".
  - The payment watcher follows the chain head. It credits `Balances.Transfer` events to a user's `payment_address` as `amount_rao × FMV / 1e9` USD and queues the TAO for autostaking.
  - It also credits `SubtensorModule.StakeTransferred`, meaning alpha stake moved to the user's coldkey on any netuid, at "market value only - no bonus". It ignores amounts below a dust threshold and queues the alpha for "stake move and burn".

  — [chutes-api README](https://github.com/chutesai/chutes-api); [api/payment/watcher.py](https://github.com/chutesai/chutes-api/blob/main/api/payment/watcher.py)
- Live API (2026-11-23):
  - Payments and pricing: `GET /payments`, `GET /payments/summary/tao`, `GET /fmv` ("current FMV for tao"), `POST /return_developer_deposit`, `GET /users/me/discounts`, `GET /users/me/price_overrides`.
  - Admin only: `POST /users/{user_id}/enable_invoicing`, `GET /users/invoiced_user_list`.
  - No Gamma, Stripe or alpha-specific paths are exposed.

  — [OpenAPI](https://api.chutes.ai/openapi.json)

#### Gamma (Chutes' side only)
- Const (Jacob Steeves) "named seven subnets as the initial Gamma issuers: Chutes, Engy, GM, Lium, Targon, Hippius, and Affine". This was at a keynote at Bittensor's Exploit Summit on 2026-09-28, as reported second-hand on 2026-10-03 via CryptoBriefing/KuCoin. The same article says "the standard is slated to go live in early 2027". — [Startup Fortune (2026-10-03)](https://startupfortune.com/bittensor-unveils-gamma-tokens-to-let-ai-subnets-pay-each-other/)
- Conflicting dates for network launch:
  - "Gamma shipped on 5 November and was switched on network-wide on 9 November". — [Asymmetric Jump (2026-11-20)](https://asymmetricjump.substack.com/p/tao-is-down-75-the-network-isnt)
  - KuCoin (2026-11-11) says OTF "has launched Gamma Tokens" but names no adopting subnet. — [KuCoin flash (2026-11-11)](https://www.kucoin.com/news/flash/opentensor-foundation-launches-native-payment-mechanism-gamma-tokens)
  - A search snippet of a Mentat X post says Gamma is opt-in per subnet. I did not fetch it. — [Mentat on X](https://x.com/mentatminds/status/2118370933345792319)
- No Chutes statement, blog post, docs page, ToS clause or API path about accepting Gamma was found as of 2026-11-23. The blog index has no Gamma post; ToS §12.2 lists only Stripe and blockchain deposits incl. TAO; the OpenAPI has no Gamma paths. — [Chutes blog index](https://chutes.ai/news); [Terms](https://chutes.ai/terms); [OpenAPI](https://api.chutes.ai/openapi.json)

#### Usage reports
- `GET /invocations/exports/{year}/{month}/{day}/{hour_format}` and `/invocations/exports/recent` (exports), `GET /users/{user_id}/usage`, `GET /users/me/subscription_usage`, `GET /instances/compute_history_csv`, and OAuth scopes `billing:read`, `usage:read` and `invocations:read`. — [OpenAPI](https://api.chutes.ai/openapi.json); [api.chutes.ai/idp/scopes](https://api.chutes.ai/idp/scopes)
- Retention of usage and billing metadata: "24 months for operations, and 7 years for accounting, tax, and audit records". — [Privacy](https://chutes.ai/privacy)

#### Terms relevant to an integrator (ToS 2026-11-01; Privacy 2026-11-01)
- §9.1 "You may integrate the Platform into your own products and offer them to your own users"; §9.2 you must bind End Users to terms at least as protective. — [Terms](https://chutes.ai/terms)
- §9.3 "You may not resell, white label, or redistribute access to the Platform as a standalone inference service" without a separate written agreement. — [Terms](https://chutes.ai/terms)
- §3.3 you "may not give any third party, including your own end users, direct access to your API keys". — [Terms](https://chutes.ai/terms)
- Training: §7.3 "Chutes does not use your Content to train, fine tune, distill, evaluate, or otherwise improve any model." Model Providers are not permitted to train on Inputs or Outputs (Privacy §4.2). — [Terms](https://chutes.ai/terms); [Privacy](https://chutes.ai/privacy)
- Logging: "Chutes does not log, store, or persist the content of your API requests or responses on Chutes systems". The §6.3 exceptions cover transient buffers "never longer than 24 hours", abuse investigations, legal duties and debug requests, and "None of these exceptions applies to requests in end-to-end encryption mode".
  - Prompt-prefix hashes and routing caches: "Generally no longer than 24 hours".
  - Security logs including IP: 90 days.
  - IPs are not sent to Network Operators or Model Providers.

  — [Privacy](https://chutes.ai/privacy)
- ToS §6.4: Model Providers "may briefly cache Content, may retain Content that its safety systems flag". — [Terms](https://chutes.ai/terms)
- AUP: §5.1 lawful use only; §5.2 prohibited uses (malware, harassment, impersonation…); Schedule 1 adds Standard-Model limits. — [Terms](https://chutes.ai/terms)
- No SLA: §18.3 "Chutes does not guarantee any uptime, capacity, latency, or performance level unless a separate written agreement says so"; §4.5 "We do not promise that any Model will remain available." — [Terms](https://chutes.ai/terms)
- Liability cap §19.2: the greater of fees paid in the prior 30 days or US$10,000. Governing law §22: Delaware. A DPA exists at `/dpa`. — [Terms](https://chutes.ai/terms); [chutes.ai/tee links](https://chutes.ai/tee)

### Inferences
- URnetwork's model has users paying URnetwork in fiat and URnetwork paying the provider. That fits §9.1 (embedding) if Chutes access is a feature of URnetwork's product rather than a pass-through API, but needs care under §9.3.
- Under §3.3 the sidecar cannot ship a URnetwork Chutes API key to user devices. A URnetwork-side relay holding the key, forwarding E2EE ciphertext, is the compliant shape. The other route is per-user Chutes accounts via "Sign in with Chutes" OAuth, where users pay Chutes directly.
- Paying Chutes in Gamma is not currently possible as far as public evidence shows. Today's on-chain route is TAO, or alpha stake transfers to URnetwork's account coldkey, credited at market value. Crypto payments are final, and the prepaid balance is forfeitable under §16.3. A Gamma arrangement would need direct confirmation or negotiation with Chutes; an enterprise invoicing agreement could also cover §9.3.
- There is no TEE surcharge. No model is sold in both TEE and non-TEE form, so a like-for-like premium cannot be measured. The cheapest catalog models are TEE models ($0.039–$0.45/M input), and most Standard models are priced higher ($0.195–$2.45/M input). TEE is Chutes' default tier, not a premium add-on.

### Gaps
- I found no Stripe minimum top-up, Stripe fee pass-through, invoice terms, current TAO deposit confirmation policy, or dust threshold value. The watcher code reads the chain head; the finality and confirmation wait in current production is unknown.
- No Chutes statement on Gamma adoption or timing; no reseller-program terms.
- The date monthly plans stopped being sold is unknown; the FAQ was observed on 2026-11-23.

## 5. Custom deployments and "enclave" fit: can Chutes host an arbitrary long-running Debian TEE VM with SSH, a public IP and customer-controlled networking?

### Takeaway
Not as of 2026-11-23. Three things come closest, and none meets URnetwork's requirement:
- **Private TEE chutes:** customer container images on TEE GPUs, HTTP "cords" invoked via the Chutes API, scale-to-zero, $2.25/h on an RTX Pro 6000.
- **"Bring-your-own Intel TDX VM endpoints":** kit published 2026-11-20. These are CPU-only GCE `c3` TDX VMs in Chutes' Google Cloud project. They serve only declared JSON POST routes through a Chutes relay; the reference image has no sshd, no public ingress and an isolated network. No public docs or pricing yet.
- **SDK "jobs / server rentals":** these have SSH and ports, but run at container level; they are not documented for TEE and the SSH host key is not attested.

A CPU-only TEE VM product for "sandboxes, agent runners" was "in development" as of June 2026.

### Cited Findings
#### Private / custom TEE chutes
- Deployment: `chutes deploy <module:chute> [--accept-fee] [--public]`; private by default. Scaling knobs are `max_instances`, `scaling_threshold`, `shutdown_after_seconds` (scale-to-zero; recommend longer in production "to avoid cold starts") and `concurrency`. Networking flag `allow_external_egress` defaults to true for custom chutes and false for vLLM/SGLang templates. The deploy docs do not cover TEE, SSH, persistent storage or inbound ports. — [Deploy docs](https://chutes.ai/docs/cli/deploy)
- The TEE switch is the SDK's `tee=True` (the old `PUT /chutes/{id}/teeify` was removed by 2026-06-11). The pricing page example pins `NodeSelector(gpu_count=1, include=["pro_6000"])`. — [chutes-agent-toolkit](https://github.com/chutesai/chutes-agent-toolkit); [chutes.ai/pricing](https://chutes.ai/pricing)
- Billing: you pay the hourly GPU rate while any instance is hot, "through last request timestamp + `shutdown_after_seconds`", and cold starts are not charged. `allow_external_egress=False` blocks outbound connections "after the chute has finished running all on_startup(..) hooks". — [chutes SDK README](https://github.com/chutesai/chutes)
- In TEE nodes, "chutes-net-nanny blocks outbound traffic by default, except to the validator proxy". Management is only through the locked-down Kubernetes API, with no SSH **[claim]**. — [Security architecture docs](https://chutes.ai/docs/core-concepts/security-architecture)
- Images: built by Chutes' "forge", signed with cosign and admitted only if signed. Remote builds run via depot.dev (2026-06-15). Private chutes share TEE VMs with other accounts' chutes and share the base-VM measurement (issue #75, 2026-11-17). Owner-only encrypted log sessions are available at `/encrypted_logs/{chute_id}/sessions`. — [Security architecture docs](https://chutes.ai/docs/core-concepts/security-architecture); [2026-06-15 post](https://chutes.ai/news/please-excuse-our-absence-from-proof-of-talk-in-paris); [issue #75](https://github.com/chutesai/chutes/issues/75); [OpenAPI](https://api.chutes.ai/openapi.json)

#### SDK jobs / "server rentals" (container level; status unclear)
- `chutes/chute/job.py`, last changed 2025-08-03 (pre-mid-2026: may be superseded), describes "Jobs (or server rentals, or anything really that isn't an API)":
  - `ports: list[Port]` with proto "tcp", "udp" or "http"; port 2202 or 8002–65535.
  - `timeout` of None "for server rental", or up to one day.
  - `ssh=True` adds SSH on port 2202, set up from the job's `_ssh_public_key` with `PasswordAuthentication no`.
  - The API exposes `/jobs/{chute_id}/{method}` and related job endpoints.

  — [job.py](https://github.com/chutesai/chutes/blob/main/chutes/chute/job.py); [ssh.py](https://github.com/chutesai/chutes/blob/main/chutes/entrypoint/ssh.py); [run.py](https://github.com/chutesai/chutes/blob/main/chutes/entrypoint/run.py); [OpenAPI](https://api.chutes.ai/openapi.json)
- 2026-06-15 **[claim]**, on the planned CPU/RAM-only TEE VMs ("sandboxes, agent runners, etc."): "More work to be done here". A miner could "proxy network traffic through a transparent gateway, perform the real attestation, then intercept and redirect SSH traffic"; the fix requires "the VM SSH host key to be part of the attestation". Also "sensitive data could theoretically leak into system logs visible from the host". — [2026-06-15 post](https://chutes.ai/news/please-excuse-our-absence-from-proof-of-talk-in-paris)

#### Bring-your-own Intel TDX VM endpoints (repos created 2026-11-20; MIT) **[verified, code/docs]**
- Kit: `chutes-tdx-image` (template), `chutes-tdx-gate` (front end in the VM) and `chutes-tdx-measure` (measurement prediction, signing and quote verification, "as the Chutes gateway checks them").
  - Template: Ubuntu 26.04 LTS guest (a 24.04 branch also exists) booting one UKI on a **GCE `c3` TDX machine**.
  - Root: read-only erofs plus dm-verity.
  - App partition: encrypted `aes-xts-plain64` with dm-verity over the ciphertext, unlocked with a key fetched from **your own key service** through "Chutes' key window".
  - Runtime: "no Google guest agent, cloud-init, sshd or getty"; `/tmp` and `/var` in memory; root locked.

  — [chutes-tdx-image](https://github.com/chutesai/chutes-tdx-image)
- Networking: the VM serves on port 8080 only through `tdx-gate`. The relay's requests come "from the validator's internal address" with fixed headers; the app sees only `Host`, `Content-Type: application/json` and `Content-Length` on `POST <app_path>`. The answer is limited to the sealed status plus body, and "none of its headers reach the caller". A `probe` image variant "tries every path out of the VM… to test the VM's network isolation". — [chutes-tdx-gate README](https://github.com/chutesai/chutes-tdx-gate); [SPEC.md §4.3](https://github.com/chutesai/chutes-tdx-gate/blob/main/spec/SPEC.md); [chutes-tdx-image](https://github.com/chutesai/chutes-tdx-image)
- Attestation and E2E v2:
  - The VM attests with `GET /attest?nonce=<64 hex>`, where `REPORTDATA = SHA-512("chutes-tdx-endpoint-attest-v1" ‖ 0x00 ‖ nonce ‖ ML-KEM-768 public key)`.
  - The client's E2E v2 envelope binds `endpoint_id`, `instance_id`, `path`, `stream`, `nonce` and `ts` (120 s behind, 60 s ahead), and carries an `e2e_response_pk`. Answers are sealed to that key.
  - The gate "logs no body, no envelope field and no decrypted byte".

  — [SPEC.md](https://github.com/chutesai/chutes-tdx-gate/blob/main/spec/SPEC.md)
- Measurement: the owner signs `chutes.tdx-measurements.v1` documents with an Ed25519 key registered with Chutes, in "exact" or "firmware-following" form. The gateway's `verify-quote` rows are: Intel DCAP (via dcap-qvl 0.5.3 / chutes-attest 0.9.0), the binding, the pinned GCP project and zone, the signed measurements, and `provider_root` (MR_OWNER = the instance's PZID; the host is in Google's registry). — [chutes-tdx-measure](https://github.com/chutesai/chutes-tdx-measure)
- Hosting and lifecycle: the reference key service checks "the instance's project is Chutes' customer-VM project". The key window allows four connection attempts, "after four the VM waits for its deadline and is replaced". `/health` gates readiness. — [chutes-tdx-image](https://github.com/chutesai/chutes-tdx-image)
- None of `docs`, `pricing` or the live OpenAPI (2026-11-23) mentions BYO TDX VM endpoints. — [chutes.ai/pricing](https://chutes.ai/pricing); [OpenAPI](https://api.chutes.ai/openapi.json); [Chutes blog index](https://chutes.ai/news)

### Inferences
- URnetwork's enclave requirement is a TEE Debian VM with SSH and an IP address whose networking URnetwork controls. It is unmet by every Chutes option as of 2026-11-23:
  - BYO TDX endpoints are request-driven JSON-over-HTTP functions behind Chutes' relay. There is no inbound port or public IP for the customer, and the network is isolated. They run on Google Cloud rather than on Bittensor miners, and are CPU-only.
  - Private TEE chutes are request-driven containers on shared multi-tenant TEE VMs, with egress limited.
  - SDK job/rental SSH is container-level on miner hosts, with no attested host key; that is exactly the attack Chutes itself described.
- The BYO-TDX kit (Go, MIT, with test vectors) is still a useful reference for attested ML-KEM E2E v2 and customer-held key release, even though it is not a VM-rental product.
- Watch for the CPU-only TEE VM ("sandboxes, agent runners") work announced as in progress in June 2026; it is the item most likely to evolve toward SSH-able enclaves.

### Gaps
- No public price, availability date, region list, CPU/RAM sizes or SLA for BYO TDX endpoints; whether this is GA, beta or internal is unknown.
- Whether `tee=True` chutes can use jobs, ports or SSH is undocumented, as are their egress policy specifics and persistent storage (sek8s has cache/storage volumes for miners, but nothing customer-facing was found).
- No CPU-only TEE VM launch announcement found after 2026-06-15.

## 6. Reliability and scale (OpenRouter share, volume, incidents, cold starts, churn, miner locations, cheating)

### Takeaway
Chutes' own public stats show LLM traffic falling from about 104–108B tokens/day (Nov 2025–Jan 2026) to about 17.7B/day in November 2026, roughly −84%. TEE capacity is thin for large models: 1–7 instances each, and `GLM-5.2-TEE` had 52% of requests rate-limited in the last hour of a 2026-11-23 snapshot. OpenRouter uptime for Chutes endpoints is about 99–100% per day. The model catalog churns and no SLA is offered. No documented miner TEE cheating was found, but two open security issues (#75, #78) are material.

### Cited Findings
- Daily LLM tokens, computed by this researcher from Chutes' public per-chute/day stats on 2026-11-23 **[verified]**:

  | Period | Avg tokens/day |
  |---|---|
  | Jun 2025 | 136.8B |
  | Jan 2026 | 107.8B |
  | Feb 2026 | 99.5B |
  | Mar 2026 | 67.1B |
  | Apr 2026 | 73.4B |
  | May 2026 | 53.3B |
  | Jun 2026 | 44.7B |
  | Jul 2026 | 43.3B |
  | Aug 2026 | 44.5B |
  | Sep 2026 | 29.6B |
  | Oct 2026 | 21.1B |
  | Nov 1–23, 2026 | 17.7B |

  Peak day: 159.5B on 2025-06-20. 2026-11-16 to 11-22 ran 15.7–20.0B per day. November token mix: Qwen3.8-27B-TEE 31.6%, GLM-5.2-TEE 14.5%, gemma-4-31B-turbo-TEE 10.6%, GLM-5.1-TEE 10.5%, Kimi-K2.6-TEE 9.4%. — [api.chutes.ai/invocations/stats/llm](https://api.chutes.ai/invocations/stats/llm)
- A third party independently reports "108B tokens a day in January 2026 and 18.5B so far in November, down about 83%". — [Asymmetric Jump (2026-11-20)](https://asymmetricjump.substack.com/p/tao-is-down-75-the-network-isnt)
- Capacity snapshot, 2026-11-23 07:31 UTC **[verified]** (active instances per TEE chute):
  - Qwen3.8-27B-TEE 65; gemma-4-31B-turbo-TEE 49; GLM-5.1-TEE 7; Kimi-K2.6-TEE 6; DeepSeek-V3.2-TEE 6; Kimi-K3-TEE 6; GLM-5.2-TEE 4; Qwen3.5-27B-TEE 2; Qwen3.6-27B-TEE 2; DeepSeek-V4-Flash-0731-TEE 1 (of 2); Qwen3.5-397B-A17B-TEE 1.
  - GLM-5.2-TEE: `utilization_1h` 0.97, `rate_limit_ratio_1h` 0.52.
  - 221 active instances across all chutes.

  — [api.chutes.ai/chutes/utilization](https://api.chutes.ai/chutes/utilization)
- OpenRouter, observed 2026-11-23: Chutes' `uptime_last_1d` was 100% for deepseek-v4-flash-0731, 99.7% for kimi-k2.6, 99.4% for qwen3.8-27b and 99.7% for glm-5.1. — [OpenRouter endpoints API (DeepSeek V4 Flash)](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash-0731/endpoints); [kimi-k2.6](https://openrouter.ai/api/v1/models/moonshotai/kimi-k2.6/endpoints); [qwen3.8-27b](https://openrouter.ai/api/v1/models/qwen/qwen3.8-27b/endpoints); [glm-5.1](https://openrouter.ai/api/v1/models/z-ai/glm-5.1/endpoints)
- OpenRouter volume (pre-mid-2026 / secondary: may be superseded): Chutes' OpenRouter throughput "peaked on 7 February 2026 at roughly 42 billion tokens per day", fell to 8–12B in late March, and was about 6.8B/day in April. Rayon Labs' self-reported "160 billion tokens per day" is "not verifiable against OpenRouter data". — [ownyourmind.ai (2026-04-10, updated 2026-10-06)](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
- A search snippet attributes "about 5.7B tokens a day, down 33% over the prior 30 days… blended price of $0.21 per million" to Blockworks Advisory; I did not fetch it and its date is unknown. — [Blockworks Advisory on X](https://x.com/BlockworksAdv/status/2110415412580020472)
- Model churn:
  - June 2026 TEE flagships included Kimi-K2.5, MiniMax-M2.5, Nemotron-3-Ultra, `Qwen/Qwen3-32B-TEE` and `unsloth/Mistral-Nemo-Instruct-2407-TEE`. None are in the 2026-11-23 catalog.
  - teep's example id `deepseek-ai/DeepSeek-V3-0324-TEE` is also gone.
  - ToS §4.5 makes no availability promise.

  — [chutes-agent-toolkit](https://github.com/chutesai/chutes-agent-toolkit); [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models); [Terms](https://chutes.ai/terms)
- Cold starts: not charged; scale-to-zero via `shutdown_after_seconds`. Capacity issues seen by others: "the other 3 hit replica churn/capacity" (issue #78, 2026-11-19); a quota error in Chutes' own 2026-09-15 test. — [chutes SDK README](https://github.com/chutesai/chutes); [issue #78](https://github.com/chutesai/chutes/issues/78); [2026-09-15 post](https://chutes.ai/news/open-agent-open-weights-open-enclave)
- The status page `status.chutes.ai` is hosted on Better Stack; server-rendered content showed no incident history (2026-11-23). — [status.chutes.ai](https://status.chutes.ai)
- Miner hardware requirements: bare metal or VM ("will not work on Runpod, Vast, etc."), "unique, static" IPs with 1:1 port mapping, and TDX-capable CPUs with supported GPUs. — [chutes-miner README](https://github.com/chutesai/chutes-miner)
- Miner locations are not published. OpenRouter shows Chutes "headquarters": "US", "datacenters": null. — [OpenRouter providers API](https://openrouter.ai/api/v1/providers)
- Cheating and security history:
  - No public report of a miner defeating TEE attestation was found.
  - Issue #36 (2025-12-02, closed 2025-12-03; pre-mid-2026) reported "7 Critical Security Vulnerabilities in Validator/Miner Code", e.g., a 540-second nonce replay window.
  - Design-level risks are described above: SSH redirect (Chutes, 2026-06-15), unmeasured serving code (#75) and the cross-tenant KV cache (#78).

  — [issue #36](https://github.com/chutesai/chutes/issues/36); [issue #75](https://github.com/chutesai/chutes/issues/75); [issue #78](https://github.com/chutesai/chutes/issues/78)
- Economics context (secondary): SubConnect's late-August index put Chutes' revenue at "$4M–$5M a year". SN64's pool held about 192,400 TAO, 9.8% of the total. — [Asymmetric Jump (2026-11-20)](https://asymmetricjump.substack.com/p/tao-is-down-75-the-network-isnt)

### Inferences
- For URnetwork, Chutes' TEE capacity on large models is shallow (single-digit instances). Expect 429s at peak, and plan multi-provider fallback that is also TEE-only, since there is no SLA.
- Falling volume plus frequent model replacement means model ids must be discovered dynamically (`/v1/models` filtered on `confidential_compute`), not hard-coded.

### Gaps
- No authoritative current OpenRouter market-share figure for Chutes; no incident or post-mortem history found.
- No data on miner geography or the number of distinct miners hosting TEE nodes.

## 7. Open-source repositories (names, languages, licenses, activity as of 2026-11-23)

### Takeaway
The TEE guest stack, the miner control plane, the SDK, the E2EE clients and the new BYO-TDX kit are public, mostly MIT. The validator/API repo (`chutes-api`) was archived after its last commit on 2026-09-03, so current gateway code is no longer public. The miner repo has no license file. Independent verification code exists in Go (teep, AGPL-3.0) and Python (NioZow proxy, no license).

### Cited Findings
All rows from GitHub metadata fetched 2026-11-23 **[verified]**: [github.com/chutesai](https://github.com/chutesai).

| Repo | Purpose | Language / license / stars / last push |
|---|---|---|
| [chutesai/sek8s](https://github.com/chutesai/sek8s) | TDX guest image (LUKS, k3s, attestation services, `nvevidence`), host tools (`chutes-cvm`), measurement specs | Python / MIT / 9 / 2026-10-15 (created 2025-07-30) |
| [chutesai/chutes-miner](https://github.com/chutesai/chutes-miner) | Miner control plane; TEE-exclusive since 2026-07-31 | Python / **no license** / 39 / 2026-10-10 |
| [chutesai/chutes-api](https://github.com/chutesai/chutes-api) | Validator/API, payments watcher, attestation verification (**archived**) | Python / MIT / 27 / 2026-09-03 |
| [chutesai/chutes](https://github.com/chutesai/chutes) | CLI/SDK (`tee=True`, jobs, TEE evidence server); PyPI `chutes` 0.6.9 (2026-05-17), 0.6.11rc2 (2026-06-10) | Python / MIT / 88 / 2026-07-23 |
| [chutesai/chutes-e2ee-transport](https://github.com/chutesai/chutes-e2ee-transport) | httpx transport for OpenAI SDK E2EE (PyPI `chutes-e2ee` 0.1.0) | Python / MIT / 9 / 2026-03-11 |
| [chutesai/e2ee-proxy](https://github.com/chutesai/e2ee-proxy) | OpenResty local E2EE proxy (OpenAI, Anthropic, Responses) | Lua / MIT / 12 / 2026-08-07 |
| [chutesai/e2ee-test](https://github.com/chutesai/e2ee-test) | TypeScript plus Rust→wasm `build_e2ee_request` | TypeScript / no license / 0 / 2026-05-17 |
| [chutesai/chutes-tdx-gate](https://github.com/chutesai/chutes-tdx-gate) | BYO TDX VM front end, E2E v2 spec + vectors | Go / MIT / 0 / created 2026-11-20 |
| [chutesai/chutes-tdx-image](https://github.com/chutesai/chutes-tdx-image) | BYO TDX VM image template + reference key service | Go / MIT / 0 / 2026-11-22 |
| [chutesai/chutes-tdx-measure](https://github.com/chutesai/chutes-tdx-measure) | Predict, capture, sign and verify TDX measurements | Python / MIT / 0 / 2026-11-23 |
| [chutesai/tdx-measure](https://github.com/chutesai/tdx-measure) | Rust CLI/library that precomputes TDX measurements, validated for Canonical TDX boot chains | Rust / Apache-2.0 / 0 / 2026-09-22 |
| [chutesai/chutes-audit](https://github.com/chutesai/chutes-audit) | Auditor for fairness of request distribution | Python / MIT / 4 / 2026-09-14 |
| [chutesai/claude-proxy](https://github.com/chutesai/claude-proxy), [chutesai/responses-proxy](https://github.com/chutesai/responses-proxy) | API-format translators | Rust / no license / 11 and 3 / 2026-05-29 and 2026-08-06 |
| [13rac1/teep](https://github.com/13rac1/teep) (fork [amiller/teep](https://github.com/amiller/teep)) | Independent multi-provider TEE verifier + E2EE proxy (Chutes supported) | Go / AGPL-3.0 / 32 / 2026-11-14 (fork 2026-11-22) |
| [NioZow/chutes-litellm-proxy](https://github.com/NioZow/chutes-litellm-proxy) | LiteLLM proxy with fail-closed Chutes attestation + E2EE | Python / no license / 0 / 2026-11-21 |

### Inferences
- For a Go sidecar (CLI, mobile, wasm), the reusable pieces are:
  - `chutes-tdx-gate`'s MIT Go code and normative vectors (E2E v2);
  - the E2EE v1 wire format documented in the Python and Lua MIT clients;
  - teep's Chutes verifier, which is Go but AGPL-3.0, so a dual license or clean-room work would likely be needed for embedding.

  There is no official Go client.
- Archiving `chutes-api` removes public visibility into gateway and validator behaviour (logging, routing, key handling) after 2026-09-03.

### Gaps
- Why `chutes-api` was archived, and whether a successor repo exists (private or renamed), was not found.
- No third-party security audit report of sek8s or the E2EE implementation was found.
