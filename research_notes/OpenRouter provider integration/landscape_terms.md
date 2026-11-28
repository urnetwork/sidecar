> **Unfinished (2026-11-24).** This research stopped when the owner dropped the OpenRouter plan ("If openrouter can read every prompt, that isn't for us"). Its author had flagged four places where the wording goes beyond what the sources support, and did not correct them; check a claim against its source before relying on it.

# OpenRouter: the privacy-provider landscape and the resale terms that constrain a URnetwork listing (as of 2026-11-24)

Method note. "Observed 2026-11-24" means this researcher pulled the public endpoint that day (about 17:12–17:30 UTC) without an account: OpenRouter's providers, ZDR and endpoints APIs, its provider pages, and its frontend catalog (`/api/frontend/v1/catalog/model-endpoints`). Facts carried over from the earlier notes in `research_notes/Bittensor TEE inference and enclaves/` are marked **[earlier notes]**, with their original sources. Third-party traffic estimates (routers.vantage.sh) are labeled as estimates. Vendor claims are labeled **[claim]**. Inferences appear only under "Inferences". No sign-ups or paid calls were made.

## 1. Which privacy-oriented (TEE, confidential, no-log) providers are on OpenRouter today: their models, prices, throughput, uptime, privacy presentation and traffic share?

### Takeaway
As of 2026-11-24, five OpenRouter providers market privacy:
- **Venice:** no-log policy, ZDR-eligible, and the largest of the five at about 58.9B tokens/day.
- **NEAR AI:** TEE hardware, but behind a gateway NEAR itself calls "not attested"; ZDR-eligible.
- **Chutes:** TEE chutes reached over a plaintext gateway. OpenRouter labels it as retaining prompts, and none of its endpoints is ZDR-eligible.
- **Darkbloom:** attested Apple-silicon Macs whose owners can still read prompts. Labeled as retaining; not ZDR.
- **Phala:** still configured, but serving no models since its October–November breach.

OpenRouter has **no TEE badge, flag, filter or attestation link**. Privacy shows only as per-provider data-policy flags, ZDR eligibility, and links to each provider's terms and privacy policy.

Together these providers carry under 0.5% of OpenRouter's estimated ~31.8T tokens/day. None of the following is an OpenRouter provider: Tinfoil, Privatemode, Maple, Atoma, Secret Network, Targon, engy or SayGM.

### Cited Findings
**Census and schema (observed 2026-11-24)**
- OpenRouter's providers API lists **124 providers**. The earlier notes counted 123 on 2026-11-23.
  - No provider is named Tinfoil, Privatemode, Maple, Atoma, Secret, Nillion, RedPill, Targon, engy, SayGM/gm or Nineteen.
  - Phala's terms and privacy links point to redpill.ai.

  — [OpenRouter providers API](https://openrouter.ai/api/v1/providers)
- OpenRouter's provider object has these fields:
  - `dataPolicy`: `{training, trainingOpenRouter, retainsPrompts, canPublish, safetyRetention, requiresUserIDs}`, plus terms and privacy URLs;
  - `baseUrl`, `headquarters`, `datacenters`, `byokEnabled`, `requiredAttestationTypes`, `isProvisional`, `sendClientIp` and `description`.

  There is no TEE or confidential-computing field. The frontend catalog's endpoint object adds `provider_model_id`, `is_hipaa_eligible`, `declared_region`, `provider_region` and `required_attestation_types`.

  `requiredAttestationTypes` is `[]` and `is_hipaa_eligible` is `false` for every privacy provider checked. `description` is `null` for Phala, NEAR AI, Chutes and Venice. — [openrouter.ai/provider/near-ai](https://openrouter.ai/provider/near-ai); [openrouter.ai/provider/chutes](https://openrouter.ai/provider/chutes); [OpenRouter catalog, qwen3.8-27b](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=qwen/qwen3.8-27b-20260814)
- The ZDR endpoint list has **937 endpoints** (934 on 2026-11-23 [earlier notes]).
  - Privacy-branded providers: Venice 37, NEAR AI 4, Chutes 0, Phala 0, Darkbloom 0.
  - For comparison: DeepInfra 172, Google 66, Azure 63, Parasail 48.

  — [OpenRouter ZDR endpoints API](https://openrouter.ai/api/v1/endpoints/zdr)

**The privacy-positioned providers on OpenRouter (observed 2026-11-24 unless noted)**

| Provider | OpenRouter `baseUrl` | OR data policy (training / retainsPrompts) | ZDR endpoints | Models live on OR | HQ / datacenters | TEE on the OR route? |
|---|---|---|---|---|---|---|
| Venice | `https://api.venice.ai/api/v1` | false / **false** | 37 | ≥30 linked on its page | US / [US] | No evidence: OR sends standard Venice ids (e.g. `kimi-k2-6`), not Venice's `e2ee-` ids |
| NEAR AI | `https://openrouter.cloud.near.ai/v1` (dedicated host) | false / **false** | 4 | 4 | null / [] | TEE hardware behind an unattested gateway (NEAR, below) |
| Chutes | `https://llm.chutes.ai/v1` | false / **true** | 0 | 8 | US / null | TEE chutes, plaintext gateway (Section 2) |
| Darkbloom | `https://api.darkbloom.dev/v1` | false / **true** | 0 | 12 | null / [] | Attested Macs; not a TEE; owner can read prompts |
| Phala | `https://openrouter.phala.com/v1` (dedicated host) | false / false | 0 | **0** | US / null | n/a: no live models |

Sources for the table:
- [providers API](https://openrouter.ai/api/v1/providers) and the provider pages for [Venice](https://openrouter.ai/provider/venice), [NEAR AI](https://openrouter.ai/provider/near-ai), [Chutes](https://openrouter.ai/provider/chutes), [Darkbloom](https://openrouter.ai/provider/darkbloom) and [Phala](https://openrouter.ai/provider/phala) (embedded `provider` JSON);
- [ZDR API](https://openrouter.ai/api/v1/endpoints/zdr);
- OR catalog `provider_model_id` for [kimi-k2.6](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=moonshotai/kimi-k2.6-20260420) and [glm-5.3-flash](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=z-ai/glm-5.3-flash-20260826).

The same data policies appear per endpoint in the catalog.
- Other search-cached copies of Phala's page showed 17–21 models, but they are undated. On 2026-11-24 Phala was also absent from the 25 endpoints serving `deepseek/deepseek-v4-flash-0731`, the model named in its incident. — [search results for openrouter.ai/provider/phala](https://openrouter.ai/provider/phala); [endpoints API, deepseek-v4-flash-0731](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash-0731/endpoints)

**Prices and 1-day uptime on shared models (USD per 1M input / output; observed 2026-11-24)**

| Model (endpoints on OR) | Chutes | NEAR AI | Venice | Darkbloom | Cheapest other seen |
|---|---|---|---|---|---|
| qwen/qwen3.8-27b (22) | 0.039 / 1.25, fp8, 100% | 0.04 / 1.35, fp8, 99.86% | — | 0.035 / 1.50, fp4, 100% | AkashML 0.225 / 1.98 |
| z-ai/glm-5.3-flash (42) | — | 0.08 / 0.50, fp8, 99.86% | 0.15 / 0.50, 100% | 0.065 / 0.18, fp4, **32K ctx**, 99.68% | InferenceNet 0.108 / 0.35 |
| deepseek/deepseek-v4.1-flash-1017 (53) | — | 0.30 / 1.20, 100% | 0.30 / 1.20, 100% | — | Ambient 0.045 / 0.25 |
| openai/gpt-oss-120b (23) | — | 0.03 / 0.15, fp4, 99.86% | 0.03 / 0.15, int4, 99.93% | — | AkashML 0.03 / 0.187 |
| moonshotai/kimi-k2.6 (14) | 0.39 / 1.80, int4, 100% | — | 0.75 / 3.50, int4, 100% | — | — |
| deepseek/deepseek-v4-flash-0731 (25) | 0.44 / 1.32, fp8, 100% | — | 0.13 / 0.26, 98.1% | — | — |
| google/gemma-4-31b-it (18) | 0.12 / 0.37, fp4, 131K ctx, 99.51% | — | 0.12 / 0.36, fp4, 256K ctx, 100% | — | — |
| qwen/qwen3.6-27b (8) | 0.25 / 2.00, fp8, 99.44% | — | 0.325 / 3.25, fp8, 99.26% | — | — |

Sources: endpoints API for [qwen3.8-27b](https://openrouter.ai/api/v1/models/qwen/qwen3.8-27b/endpoints), [glm-5.3-flash](https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flash/endpoints), [deepseek-v4.1-flash-1017](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4.1-flash-1017/endpoints), [gpt-oss-120b](https://openrouter.ai/api/v1/models/openai/gpt-oss-120b/endpoints), [kimi-k2.6](https://openrouter.ai/api/v1/models/moonshotai/kimi-k2.6/endpoints), [deepseek-v4-flash-0731](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash-0731/endpoints), [gemma-4-31b-it](https://openrouter.ai/api/v1/models/google/gemma-4-31b-it/endpoints) and [qwen3.6-27b](https://openrouter.ai/api/v1/models/qwen/qwen3.6-27b/endpoints).
- **Throughput and latency:** `throughput_last_30m` and `latency_last_30m` were `null` for every endpoint checked, as the earlier notes also found on 2026-11-23. — [endpoints API](https://openrouter.ai/api/v1/models/qwen/qwen3.8-27b/endpoints)

**Traffic share (third-party estimate; OpenRouter publishes no provider share)**
- OpenRouter's rankings page has "Market Share", "Top Models" and "Top Apps" sections, organised by model and model author. "Chutes", "Near AI", "NEAR AI" and "Phala" do not appear anywhere in its HTML (observed 2026-11-24). — [openrouter.ai/rankings](https://openrouter.ai/rankings)
- Vantage's "OpenRouter Provider Economics" tracker, as of **2026-11-22**: total OpenRouter traffic **31.83T tokens/day**.
  - Its method label is "observed_tokens_calibrated_model_mix_observed_pricing".
  - Billings are estimates of OpenRouter-attributable revenue, not reported figures.

  | Provider | Rank | Tokens/day | Token share | Revenue share | Est. billings/day |
  |---|---|---|---|---|---|
  | Venice | 49 | 58.9B | 0.2% | 0.1% | $22.4K |
  | Darkbloom | 61 | 29.8B | 0.1% | 0.0% | $2.1K |
  | Ambient (verified inference, not privacy) | 62 | 27.4B | 0.1% | 0.0% | $1.5K |
  | NEAR AI | 64 | 26.4B | 0.1% | 0.0% | $2.3K |
  | Chutes | 73 | 8.3B | 0.0% | 0.0% | $1.4K |
  | Phala | 120 | 0 | 0.0% | 0.0% | $0 |
  | InferenceNet (decentralized, ZDR) | 10 | 729.6B | 2.3% | 2.7% | $507.4K |
  | PrimeIntellect (decentralized, ZDR) | 22 | 427.1B | 1.3% | 0.3% | $49.5K |
  | Top provider: Tencent | 1 | 6.94T | 21.8% | 2.2% | $410.7K |

  — [routers.vantage.sh/providers](https://routers.vantage.sh/providers); [routers.vantage.sh/providers/chutes](https://routers.vantage.sh/providers/chutes)

**How each presents privacy (mostly off OpenRouter)**
- **NEAR AI** (blog, 2026-09-28; at that time only GLM 5.3 Flash was listed):
  - "The model runs on the same TEE hardware our direct API uses", but "the gateway in front of this route is not attested."
  - "Your request travels through OpenRouter's infrastructure and then through a gateway outside our confidential environment."
  - "When you need confidentiality, skip the router."
  - On OpenRouter, "Inference carries no markup".
  - Verification docs are at docs.near.ai/cloud/verification.

  — [NEAR AI Cloud Is Now a Provider on OpenRouter](https://near.ai/blog/near-ai-cloud-on-openrouter)

  By 2026-11-24 NEAR lists 4 models, all ZDR. — [ZDR API](https://openrouter.ai/api/v1/endpoints/zdr)
- **Venice** docs (undated):
  - "A TEE-only request still reaches the Venice API as plaintext, the same as a request to any other model."
  - Use E2EE "if Venice should relay only ciphertext". This needs client-side ECDH, HKDF and AES-256-GCM on `e2ee-` model ids.
  - Attestation is at `GET /api/v1/tee/attestation?model=&nonce=`; signatures are at `GET /api/v1/tee/signature`.
  - The page does not mention OpenRouter.

  — [Venice TEE & E2EE models](https://docs.venice.ai/guides/features/tee-e2ee-models.md)

  A secondary source says the March 2026 launch ran on NEAR AI Cloud and Phala and was Pro-only. — [search-result summary of Delphi Digital via AICoin](https://www.aicoin.com/en/news-flash/2803218)
- **Darkbloom** ("How Darkbloom protects your prompts", undated):
  - "The provider process decrypts it because it runs the model, so it sees the prompt and completion in plaintext."
  - "Attestation and routing gates reduce that risk but do not make the Mac owner cryptographically unable to read the process."
  - "This is not end-to-end encryption between you and the provider."
  - The coordinator runs in a GCP Confidential VM (AMD SEV) and "is still a trust boundary, not a blind relay."

  — [Darkbloom security overview](https://docs.darkbloom.dev/security/overview.md)

  Darkbloom is labeled a research preview with keys prefixed `eigeninference-` ([Darkbloom docs via search](https://docs.darkbloom.dev/)). Its OR `provider_model_id` is `EigenLabs/Qwen3.8-27B-4bit-mtp` ([OR catalog](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=qwen/qwen3.8-27b-20260814)).
- **Phala**, as of its 2025-04-21 post (pre-mid-2026: may be superseded):
  - On the OpenRouter/RedPill route, the TEE service packaged an Intel TDX quote, NVIDIA attestation and an in-enclave signing key, available at `/attestation/report?model=<model_name>`.
  - "Openrouter / Redpill will process this request by forwarding it to the DeepSeek model running inside the enclave."

  — [Phala: GPU TEEs is Alive on OpenRouter](https://phala.com/posts/GPU-TEEs-is-Alive-on-OpenRouter)
- **Phala's breach** (preliminary report dated 2026-11-10):
  - An attacker "took control of a newly deployed GPU inference server 'serving production traffic without our full production security hardening'". Separately, an attacker used a legacy internet-facing service to create unauthorized CVMs.
  - DeepSeek V4 Flash 0731 requests via OpenRouter from 2026-10-21 00:00 UTC to 2026-11-08 05:35 UTC are to be treated as exposed.

  — [CSA research note (2026-11-23)](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/); [The Hacker News (2026-11-22)](https://thehackernews.com/2026/11/openrouter-drops-3-providers-after.html)
- **Independent monitor**, data "partially refreshed at Nov 24, 2026, 07:17 UTC":
  - Of 13 confidential providers tracked (Maple, Privatemode, Redpill, Confidential AI, NanoGPT, Tinfoil, NEAR AI, Venice, Chutes, PPQ.AI, Prem, Enclave42, Cohere Model Vault), "None is currently verified by the independent attestation monitor."
  - It lists none of them as available on OpenRouter.
  - The site is sponsored by Enclava.

  — [Confidential Inference Directory](https://confidentialinference.net/)
- **Earlier independent ratings [earlier notes]:**
  - AnonRouter rates NEAR AI and Venice `provider-attested`, Phala's gateway `hardware-verified` but not client-opaque, and Chutes `provider-attested`.
  - The awesome-private-inference registry (2026-11-22) records gaps for every provider.

  — [AnonRouter TEE verification](https://docs.anonrouter.ai/tee-verification); [awesome-private-inference](https://amiller.github.io/awesome-private-inference/)

### Inferences
- **The listing that is actually TEE-adjacent is NEAR AI's.** It combines TEE hardware, ZDR and a dedicated OpenRouter host, and NEAR says openly that the route is not confidential end to end. It is the closest competitor to a "most private" URnetwork listing.
- **Venice wins traffic on a no-log policy brand alone.** Its OpenRouter route shows no TEE path, yet it carries about 2–7× the traffic of NEAR AI, Darkbloom or Chutes. Privacy as a label has not, by itself, won share on OpenRouter.
- **Privacy-branded providers are small.** Summing the Vantage estimates: Venice, NEAR AI, Darkbloom, Chutes and Phala together ≈ 123B tokens/day, ≈ 0.39% of 31.83T. Decentralized but non-privacy-branded ZDR providers do far better: InferenceNet alone is 729.6B.
- **Chutes is both upstream and competitor.** It already sells the same TEE models on OpenRouter at its own list prices (Section 2).
- **A Phala return looks gated.** Its dedicated endpoint (`openrouter.phala.com`) is still configured with no live models. Returning would plausibly need the "assurances and validation" OpenRouter now requires (Section 3).

### Gaps
- No per-provider throughput or latency: the public API returns nulls, and the frontend catalog's `stats` object was empty.
- The meaning of `requiredAttestationTypes` / `required_attestation_types` is undocumented in the pages read. It may be a user-side requirement, not TEE attestation.
- Which three providers OpenRouter "off-boarded" on 2026-11-22 is unnamed in every source; whether Phala is one of them is unknown.
- Venice's exact live model count is unclear: its page links 30 models, while the ZDR API has 37 Venice endpoints.
- Vantage's figures are modelled estimates by an operator not named on the page. They are the only provider-level share data found.
- Privacy routers outside OpenRouter (AnonRouter, TrustedRouter) were not assessed as alternative channels. A search summary said TrustedRouter marks OpenRouter's confidential inference "Not verified"; unconfirmed. — [trustedrouter.com/providers](https://trustedrouter.com/providers)

## 2. Chutes' own OpenRouter listing: which models, what data policy, does the traffic use the TEE path, and what does Chutes say?

### Takeaway
Chutes is an OpenRouter provider with **8 models**. OpenRouter's catalog shows that every one is sent to a Chutes **`-TEE` chute** (for example `Qwen/Qwen3.8-27B-TEE`), so the models run on TDX with confidential GPUs. But OpenRouter calls Chutes' plain OpenAI-compatible endpoint `https://llm.chutes.ai/v1`, not the end-to-end-encrypted `/e2e/invoke` path. OpenRouter and Chutes' gateway therefore both see plaintext.

OpenRouter labels Chutes `retainsPrompts: true`, and none of Chutes' endpoints is ZDR-eligible. Chutes publishes no OpenRouter-specific privacy statement, and its OpenRouter description is empty.

Volume is about 8.3B tokens/day (estimate for 2026-11-22), with 84.6% of it on Qwen3.8-27B.

### Cited Findings
- **The listing (observed 2026-11-24):**
  - `baseUrl` `https://llm.chutes.ai/v1`, adapter `ChutesAdapter`.
  - `dataPolicy`: `training: false`, `trainingOpenRouter: false`, `retainsPrompts: true`, `safetyRetention: false`.
  - headquarters "US", datacenters `null`, `statusPageUrl: null`, `byokEnabled: true`, `description: null`, terms URL `https://chutes.ai/tos`.

  — [openrouter.ai/provider/chutes](https://openrouter.ai/provider/chutes) (embedded provider JSON); [providers API](https://openrouter.ai/api/v1/providers)
- **Models and the upstream model ids OpenRouter sends (`provider_model_id`; observed 2026-11-24):**

  | OR model | Upstream id at Chutes | Endpoint created | Price in / out | Quant, context | 1-day uptime |
  |---|---|---|---|---|---|
  | qwen/qwen3.8-27b | `Qwen/Qwen3.8-27B-TEE` | 2026-08-16 | 0.039 / 1.25 | fp8, 262,144 | 100% |
  | google/gemma-4-31b-it | `google/gemma-4-31B-turbo-TEE` | 2026-04-24 | 0.12 / 0.37 | fp4, 131,072 | 99.51% |
  | moonshotai/kimi-k2.6 | `moonshotai/Kimi-K2.6-TEE` | 2026-04-21 | 0.39 / 1.80 | int4, 262,144 | 100% |
  | moonshotai/kimi-k3 | `moonshotai/Kimi-K3-TEE` | 2026-07-29 | 1.85 / 9.50 | mxfp4, 1,048,576 | 100% |
  | qwen/qwen3.5-27b | `Qwen/Qwen3.5-27B-TEE` | 2026-11-09 | 0.20 / 1.75 | fp8, 262,144 | 98.7% (status −2) |
  | qwen/qwen3.6-27b | `Qwen/Qwen3.6-27B-TEE` | 2026-04-27 | 0.25 / 2.00 | fp8, 262,144 | 99.44% |
  | z-ai/glm-5.1 | `zai-org/GLM-5.1-TEE` | 2026-04-07 | 0.90 / 2.90 | fp8, 202,752 | 100% |
  | deepseek/deepseek-v4-flash-0731 | `deepseek-ai/DeepSeek-V4-Flash-0731-TEE` | 2026-11-01 | 0.44 / 1.32 | fp8, 1,048,576 | 100% |

  — OR catalog for [qwen3.8-27b](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=qwen/qwen3.8-27b-20260814), [gemma-4-31b-it](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=google/gemma-4-31b-it-20260402), [kimi-k2.6](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=moonshotai/kimi-k2.6-20260420), [kimi-k3](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=moonshotai/kimi-k3-20260715), [qwen3.5-27b](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=qwen/qwen3.5-27b-20260224), [qwen3.6-27b](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=qwen/qwen3.6-27b-20260422), [glm-5.1](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=z-ai/glm-5.1-20260406) and [deepseek-v4-flash-0731](https://openrouter.ai/api/frontend/v1/catalog/model-endpoints?permaslug=deepseek/deepseek-v4-flash-20260731). Prices and uptime are from the [endpoints API](https://openrouter.ai/api/v1/models/qwen/qwen3.8-27b/endpoints).
- These prices equal Chutes' own catalog list prices for the same `-TEE` ids, and all 8 ids have `confidential_compute: true` in Chutes' catalog **[earlier notes, 2026-11-23]**. — [llm.chutes.ai/v1/models](https://llm.chutes.ai/v1/models)
- **ZDR:** none of the 937 ZDR endpoints is Chutes'. — [ZDR API](https://openrouter.ai/api/v1/endpoints/zdr)
- **Chutes' encrypted path is a different API [earlier notes]:**
  - `POST /e2e/invoke` on `api.chutes.ai` takes an `application/octet-stream` body encrypted with ML-KEM-768, HKDF-SHA256 and ChaCha20-Poly1305 to an attested instance key.
  - The relay then "sees only ciphertext… The API does see usage metadata (token counts)".

  — [Chutes E2EE post (2026-03-26)](https://chutes.ai/news/end-to-end-encrypted-ai-inference-with-post-quantum-cryptography); [OpenAPI](https://api.chutes.ai/openapi.json)

  Chutes' privacy policy exceptions cover transient buffers of up to 24 h, abuse investigations, legal duties and debug requests. "None of these exceptions applies to requests in end-to-end encryption mode." — [Chutes Privacy](https://chutes.ai/privacy)
- **Chutes Terms (last updated 2026-11-01, read 2026-11-24):**
  - §4.2: "We designed Confidential Compute Models so that the Network Operator that supplies the hardware cannot read your Content while it is being processed… Hardware isolation reduces risk but does not eliminate it."
  - §4.3: "A Standard Model does not run inside a Chutes trusted execution environment."
  - §4.4: "If you use an automatic, aggregate, or fallback routing option, the Platform may select a Standard Model."

  — [Chutes Terms](https://chutes.ai/terms)
- **What Chutes says.**
  - No Chutes post or doc about its OpenRouter listing's privacy was found (searches 2026-11-24).
  - Its 2026-10-28 SayGM post claimed "all of the models we currently serve run inside hardware-attested TEEs with end-to-end encryption". On 2026-11-04 Chutes added non-TEE Standard models [earlier notes].

  — [Chutes models are now on SayGM (2026-10-28)](https://chutes.ai/news/chutes-models-are-now-on-saygm); [Chutes catalog expansion (2026-11-04)](https://chutes.ai/news/were-expanding-our-model-catalog-with-glm-deepseek-qwen-and-kimi)
- **Volume on OpenRouter (estimate, as of 2026-11-22):**
  - 8.3B tokens/day (7-day average 8.9B, 30-day 8.2B), rank 73, "Declining share".
  - Estimated billings $1.4K/day, with 30-day trailing revenue of about $50.4K.
  - Daily share never exceeded 0.2% from Jul 1 to Nov 22, 2026.
  - Token mix: qwen3.8-27b 84.6% of tokens (52.8% of revenue), gemma-4-31b-it 5.1%, qwen3.5-27b 3.0%, kimi-k2.6 2.8%, qwen3.6-27b 2.7%, glm-5.1 1.2%.

  — [routers.vantage.sh/providers/chutes](https://routers.vantage.sh/providers/chutes)
- **Earlier volume (secondary, pre-mid-2026: may be superseded):**
  - Chutes' OpenRouter throughput "peaked on 7 February 2026 at roughly 42 billion tokens per day", and was about 6.8B/day in April. — [Own Your Mind (updated 2026-10-06)](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
  - An unsourced May 2026 report said "Between 20% and 25%" of Chutes' traffic goes through OpenRouter. — [KuCoin/CryptoBriefing (2026-05-30)](https://www.kucoin.com/news/flash/bittensor-integrates-confidential-routing-layer-with-openrouter-processes-up-to-120-billion-tokens-daily)
- Chutes' own stats show 17.7B LLM tokens/day for Nov 1–23, 2026 **[earlier notes]**. — [api.chutes.ai/invocations/stats/llm](https://api.chutes.ai/invocations/stats/llm)
- **Quality signals:**
  - **[earlier notes]** In Moonshot's K2 Vendor Verifier (test date 2025-11-15), Chutes via OpenRouter had the lowest schema accuracy on kimi-k2-thinking (83.05%). — [K2-Vendor-Verifier](https://github.com/MoonshotAI/K2-Vendor-Verifier)
  - OpenRouter's routing weighs "tool-call quality" and 429s (Section 3).

### Inferences
- **"TEE yes, E2EE no."** OpenRouter-routed Chutes traffic runs on Chutes' TEE chutes, so miners cannot read it per Chutes' design. But it crosses OpenRouter and Chutes' API gateway in plaintext. It is also exposed to the open TEE issues recorded in the earlier notes: unmeasured serving code (chutes#75) and a prompt cache shared across accounts (chutes#78).
- **The route fails URnetwork's own TEE rule.** R-PROV-3 requires that "For a TEE label, no hop outside the TEE, the provider's own gateway included, sees plaintext". Chutes' OpenRouter route breaks that at two hops. — [DESIGN-COMPUTE.md R-PROV-3](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)
- **Why `retainsPrompts: true`, probably.** The label most plausibly reflects the privacy-policy exceptions that apply to non-E2EE traffic: transient buffers of up to 24 h and abuse investigations. Without ZDR, Chutes gets no traffic from users who set `zdr: true` or ZDR-only privacy settings.
- **OpenRouter may now be about half of Chutes' LLM traffic.** 8.3B ÷ 17.7B ≈ 47% in November 2026, against the claimed 20–25% in May. The two methods differ, so treat the ratio as indicative only.
- **No room to undercut.** Chutes' OpenRouter prices are its own list prices. A reseller of the same Chutes TEE models could not undercut Chutes' own listing.

### Gaps
- Whether OpenRouter's Chutes account uses any routing alias or fallback option (§4.4) was not visible. Only the pinned `-TEE` ids are.
- The commercial terms between Chutes and OpenRouter (invoicing, any written agreement) are not public.
- No Chutes statement explains the `retainsPrompts` label, or why Chutes has not sought ZDR on OpenRouter.

## 3. Differentiation: what would make a new provider "the most private" on OpenRouter, and is there demand?

### Takeaway
On OpenRouter, "private" is expressed only as ZDR eligibility and data-policy flags. There is no TEE filter, badge or attestation link, and OpenRouter itself handles every prompt in plaintext. No current provider's OpenRouter route is attested end to end:
- NEAR's gateway is unattested;
- Chutes' gateway sees plaintext;
- Venice's TEE and E2EE modes are not on its OpenRouter route;
- Darkbloom's Mac owners can read prompts.

A credible "most private" listing would pair ZDR with:
- TLS from OpenRouter terminating inside an attested TEE, bound to the TLS key;
- measured serving code, with no cross-tenant cache;
- every hop and jurisdiction disclosed;
- continuous independent verification.

Demand is now highly salient. Dragos' canary research (2026-11-19) found prompt theft at three hosting providers, and on 2026-11-22 OpenRouter removed three providers and 125 ZDR labels. But OpenRouter publishes no demand numbers, and privacy-branded providers carry under 0.5% of tokens.

### Cited Findings
**What OpenRouter lets users select (docs read 2026-11-24, undated)**
- **Routing.** OpenRouter "picks a provider by comparing what a good response would actually cost you at each one, not by list price alone… Providers close to the best share most of the traffic". Throughput, time to first token, rate limits and "tool-call quality" also count. "A provider whose errors or 429s are far worse than the model's other providers gets no traffic until it recovers."
- **Privacy parameters.** `data_collection: "deny"` means "use only providers which do not collect user data". `zdr`: "Restrict routing to only ZDR (Zero Data Retention) endpoints".
- **No TEE control.** There is no parameter for TEE, confidential computing or attestation.
- **Pinning.** Users can pin with `only`, `order`, `ignore` and `allow_fallbacks`.
- **Region.** Residency (Business and Enterprise plans) works by sending to `https://eu.openrouter.ai` or `https://us.openrouter.ai`.

— [OpenRouter provider routing docs](https://openrouter.ai/docs/guides/routing/provider-selection.md)
- **OpenRouter's own handling:**
  - "OpenRouter does not store your prompts or responses, *unless* you opt in".
  - It "does store metadata (e.g. number of prompt and completion tokens, latency, etc) for each request".
  - Users who opt in to product-improvement use get "a 1% discount on all model usage".

  — [OpenRouter data collection](https://openrouter.ai/docs/guides/privacy/data-collection)
- **ZDR blog** (2026-09-11, updated 2026-10-27):
  - "We evaluate data policies at the endpoint level".
  - An endpoint whose policy OpenRouter cannot confirm is classified "as retaining and training on data".
  - No TEE mention and no demand statistics.

  — [OpenRouter: Zero Data Retention](https://openrouter.ai/blog/insights/zero-data-retention/)

  The ZDR docs treat in-memory prompt caching as not "retaining". — [search-result summary of OpenRouter ZDR docs](https://openrouter.ai/docs/guides/features/zdr)
- **Private endpoints.** For a customer's own private endpoints, the customer's declaration is "your attestation," which OpenRouter "does not independently verify". — [CSA research note (2026-11-23)](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/)

**The November 2026 trust shock**
- **Dragos canary research** (HD Moore; published 2026-11-19):
  - About 2M prompts carrying unique canary URLs and credentials were seeded from July to November 2026.
  - It found "three different hosting providers" being robbed, the earliest from mid-July; two breaches included ZDR-flagged requests.
  - An unnamed Chinese lab fetched secret links from "about two-thirds" of "no data collection" or ZDR requests.
  - Route tracing found "several hundred" unidentified systems, and one router quietly forwarded traffic into a marketplace.
  - Moore: "a privacy flag only binds the first hop" and "A privacy flag doesn't help when the attacker is already inside."

  — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/); [TheNextWeb (2026-11-23)](https://thenextweb.com/news/openrouter-drops-providers-dragos-ai-prompt-theft-canaries); [Dragos blog (search-result excerpt; not fetched)](https://www.dragos.com/blog/ai-supply-chain-security-canary-tokens)
- **OpenRouter's response** (2026-11-22):
  - It "off-boarded three providers" and "removed 125 endpoints from Zero Data Retention (ZDR) eligibility".
  - It is "adapting the researchers' testing approach so we can run these checks on an ongoing basis" and "conducting technical verification of network paths".
  - "Any endpoint removed during the review will require assurances and validation before its status is returned."
  - It found no breach of OpenRouter itself, and the removed providers are unnamed.

  — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/); [The Hacker News](https://thehackernews.com/2026/11/openrouter-drops-3-providers-after.html)
- **Named in that coverage:**
  - Together AI's stored prompt samples leaked after "An AI coding agent committed a credential". Together then made ZDR the default for new accounts.
  - Novita forwarded some MiniMax requests "to MiniMax's official API rather than processed on Novita-hosted infrastructure" (May 28 – Nov 11, 2026).
  - Atlas Cloud removed its models from OpenRouter.

  — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/); [The Hacker News](https://thehackernews.com/2026/11/openrouter-drops-3-providers-after.html)

  AtlasCloud's OpenRouter page lists no models (observed 2026-11-24). — [openrouter.ai/provider/atlas-cloud](https://openrouter.ai/provider/atlas-cloud)
- **CSA on TEEs:**
  - Confidential computing and hardware attestation "can strengthen assurance" only if attestation covers the actual serving path and is checked continuously.
  - In procurement, buyers should require disclosure of every hop that receives plaintext and notice of routing changes.

  — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/)

**Mechanisms a provider could use**
- **Binding TLS to the TEE [earlier notes].** Chutes' TEE instances already put the SHA-256 of the per-VM TLS certificate's SPKI into TDX `REPORTDATA[32:64]`. That binds a TLS endpoint to the quote, though today only on the validator-to-instance hop. — [sek8s providers/base.py](https://github.com/chutesai/sek8s/blob/main/src/sek8s/sek8s/providers/base.py)
- **Per-model attestation reports.** Phala's 2025 OpenRouter route published them at `/attestation/report?model=`. — [Phala post](https://phala.com/posts/GPU-TEEs-is-Alive-on-OpenRouter)
- **Declaring location.** OpenRouter asks providers to "Declare where each endpoint physically serves from" (`datacenters`, `deployment_region`). — [OpenRouter for-providers docs](https://openrouter.ai/docs/guides/community/for-providers.md)

  Chutes' DPA says its Network Operators are "worldwide" **[earlier notes]**. — [Chutes DPA](https://chutes.ai/dpa)

**Demand evidence**
- OpenRouter publishes no statistic on privacy or ZDR demand in the pages read (ZDR blog, data-collection, routing and provider docs).
- OpenRouter now offers:
  - per-request `zdr` and `data_collection` filters;
  - 937 ZDR endpoints;
  - EU and US residency endpoints for Business and Enterprise plans;
  - Guardrails with model, provider, ZDR and region rules (per the earlier pitch notes; not re-read).

  — [provider routing docs](https://openrouter.ai/docs/guides/routing/provider-selection.md); [ZDR API](https://openrouter.ai/api/v1/endpoints/zdr); [OpenRouter Guardrails](https://openrouter.ai/docs/guides/features/guardrails)
- After 2026-11-22, a wave of user-facing explainers appeared ("Is OpenRouter private?", "Is OpenRouter Safe? Privacy, Logging and ZDR in 2026"). — [toolscout](https://toolscout.ai/news/is-openrouter-private-logging-and-zdr); [getaiperks](https://www.getaiperks.com/en/ai/is-openrouter-safe); [Brandefense provider checklist](https://brandefense.io/security-news/openrouter-prompt-exposure-provider-checklist/)
- **User voice: Privacy Guides forum** thread "Chutes.ai security/privacy questions", started 2026-02-16:
  - "The question however is if they really implement it the way they say."
  - "Chutes is the cheapest and has the largest model catalogue by far."
  - "None uses any metadata reduction techniques. Consider using Tor/VPNs."
  - One user found Chutes listed on OpenRouter.

  — [Privacy Guides forum](https://discuss.privacyguides.net/t/chutes-ai-security-privacy-questions/35540)
- **Revealed preference (estimate):** Venice, the largest privacy-branded provider, has 0.2% of tokens and 0.1% of revenue. — [routers.vantage.sh/providers](https://routers.vantage.sh/providers)
- **Expert advice that cuts against routers:**
  - Moore advises self-hosting or going direct to first-tier providers, and choosing upstreams yourself. — [TheNextWeb](https://thenextweb.com/news/openrouter-drops-providers-dragos-ai-prompt-theft-canaries)
  - NEAR: "When you need confidentiality, skip the router." — [NEAR blog](https://near.ai/blog/near-ai-cloud-on-openrouter)

**URnetwork's own design rules (repo, read 2026-11-24)**
- DESIGN.md §0: "A server component that would see plaintext content is a design error and is never offered as an option." — [DESIGN.md](</Users/brien/urnetwork/sidecar/DESIGN.md>)
- DESIGN-COMPUTE.md applies it to a relay: "A relay URnetwork ran inside a TEE would still be one". — [DESIGN-COMPUTE.md](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)
- R-PROV-3: "For a TEE label, no hop outside the TEE, the provider's own gateway included, sees plaintext; for any label, no URnetwork server does". — [DESIGN-COMPUTE.md](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)

### Inferences
- **The ceiling on OpenRouter.** OpenRouter terminates the user's TLS and forwards OpenAI-format JSON to the provider's `baseUrl`, so OpenRouter always sees plaintext. Its docs offer no end-to-end path and NEAR confirms the gateway hop. "Most private on OpenRouter" therefore means "most private after OpenRouter". No listing can match URnetwork's own device-direct E2EE path to Chutes, so an OpenRouter listing would be a funnel, not the flagship.
- **A checklist that would beat today's field.** Each item is something a competitor lacks:
  1. **ZDR eligibility** (`training: false`, `retainsPrompts: false`), the table stakes for ZDR-filtered traffic. Chutes and Darkbloom fail it.
  2. **TLS from OpenRouter ending inside an attested TEE**, with the TLS key bound in the quote and a public, nonce-fresh evidence endpoint. NEAR's gateway is unattested, and Chutes' and Venice's APIs see plaintext.
  3. **Measured serving code and weights**, against Chutes #75 and NEAR's compose gaps [earlier notes].
  4. **Per-tenant cache isolation**, against Chutes #78.
  5. **Declared datacenters and jurisdiction.** Chutes declares `null`.
  6. **Continuous third-party verification**: confidentialinference.net's monitor, teep, and OpenRouter's own canary and network-path checks.
  7. **A DPA plus disclosure of every plaintext hop**, as the CSA asks.
- **URnetwork cannot meet item 2 when reselling Chutes.** Chutes exposes no OpenAI-compatible endpoint whose TLS ends inside the TEE: `llm.chutes.ai` is the plaintext gateway, and E2EE needs client-side ML-KEM encryption, which OpenRouter will not do. So a URnetwork listing would need a URnetwork-run relay that accepts plaintext from OpenRouter and re-encrypts to Chutes instance keys. DESIGN.md §0 and R-PROV-3 rule that out, even inside a TEE. Listing on OpenRouter as a provider therefore needs either an owner exception to the directive for this product, or a third-party-operated attested TLS terminator. (Owner decision, not a research finding.)
- **Where the demand is.** It concentrates among buyers that the Dragos and CSA advice pushes *away* from routers. The OpenRouter-side opportunity is buyers who need OpenRouter's one API and still want the strongest available route. The `provider.only` pin makes that a deliberate, per-request choice, not default traffic.

### Gaps
- What "assurances and validation" OpenRouter will require to restore or grant ZDR, and whether it will ever expose a TEE or attestation attribute, are unknown.
- No Hacker News or Reddit threads specifically about OpenRouter TEE providers were found. Demand evidence is press, explainers and one forum thread.
- No OpenRouter figure on how many requests use `zdr: true` or `data_collection: deny`.

## 4. Resale terms: do Chutes', engy's and SayGM's terms let URnetwork resell their inference via OpenRouter, and does OpenRouter bar providers that resell other providers?

### Takeaway
- **Chutes.** An OpenRouter listing of Chutes inference falls within §9.3 on its plain words: "redistribute access to the Platform as a standalone inference service". That needs "a separate written agreement". §9.4 shows Chutes runs an authorized-reseller channel. Its public line that "an SN28 inference router is a Chutes customer and simply pays for what it uses" is friendly, but it is not that agreement.
- **engy.** The terms (effective 2026-11-20) say nothing about resale, end users or routers. Nothing bars it, but the terms also name no contracting entity and no governing law.
- **SayGM.** The terms (19 November 2026) bar resale only "in a way that circumvents our limits or provider policies". That imports every upstream's restrictions: Chutes §9.3, DeepInfra, Moonshot and Z.ai, and the frontier labs' bans.
- **OpenRouter.** It publishes no rule against providers that resell other providers. Its provider terms are accepted online after an NDA and are not public. But since 2026-11-22 it verifies network paths for hidden forwarding. It also prioritises providers that "fill gaps", and holds frontier-lab models for manual review.

### Cited Findings
**Chutes Terms ("Last updated: November 01, 2026"; read 2026-11-24)** — [Chutes Terms](https://chutes.ai/terms)
- §3.3: "You may not sell, transfer, share, or sublicense your account or API keys, and you may not give any third party, including your own end users, direct access to your API keys."
- §9.1: "You may integrate the Platform into your own products and offer them to your own users (your "End Users"), subject to these Terms."
- §9.2: "If you offer the Platform or any Output to End Users, you must do all of the following:
  - bind each End User to terms that are at least as protective of Chutes and our Model Providers as these Terms, including Sections 5, 7.4, and 8, Schedule 1, and a waiver by the End User of any claim directly against Chutes or any Model Provider;
  - tell End Users that Outputs are generated by artificial intelligence;
  - provide End Users a privacy notice… that tells them their content may be processed by Chutes and by Model Providers…;
  - obtain every consent the law requires from End Users;
  - keep your API keys under your control and not give End Users direct or unrestricted access to the Platform or to any Model Provider's interfaces;
  - act promptly on any notice from Chutes about an End User's violation…; and
  - remain responsible for the acts and omissions of your End Users as if they were your own."
- §9.3 "Resellers": "You may not resell, white label, or redistribute access to the Platform as a standalone inference service without a separate written agreement with Chutes."
- §9.4 "Access through an authorized reseller": "If you buy access to the Platform from a reseller that Chutes has authorized, your agreement with that reseller governs your purchase, billing, and support. Sections 5, 6, 7, 8, 10, 11, 14, and 18 of these Terms and Schedule 1 still govern your use of the Platform. Chutes has no contract with you for that purchase…"
- The terms never mention aggregators, marketplaces, routers or OpenRouter. §4.4 covers Chutes' own "automatic, aggregate, or fallback routing option".
- §18.3: "Chutes does not guarantee any uptime, capacity, latency, or performance level unless a separate written agreement says so."
- Chutes on SayGM routers (2026-10-28): "From where we sit, an SN28 inference router is a Chutes customer and simply pays for what it uses". Each SayGM provider "holds its own Chutes API key". The post mentions no written agreement, and no aggregator other than SayGM. — [Chutes blog](https://chutes.ai/news/chutes-models-are-now-on-saygm)

**engy Terms ("Effective 2026-11-20"; read 2026-11-24)** — [engy terms](https://engy.ai/terms)
- On acceptance: "Using the API or the dashboard means you accept these terms." "If you use engy on behalf of an organization, you accept them for that organization."
- On keys and suspension: "You are responsible for all usage under your API keys." "Keep them secret; rotate or revoke a key immediately if you suspect it leaked." "We may suspend keys or accounts that violate these terms or generate abusive traffic."
- On use: "Do not use the service for unlawful activity, to infringe the rights of others, or to attack, probe, or overload the service itself." "You are responsible for complying with the license terms of the models you invoke."
- On data:
  - "Requests are served on GPU infrastructure we operate or by independent operators on the engy network".
  - "without confidential computing non-retention is a policy and contractual commitment rather than something engy can technically guarantee".
  - A ZDR-flagged request "is served only by ZDR-certified workers".
- On resale: the terms say nothing about resale, sublicensing, white-labelling, redistribution, competing services, routers, marketplaces or OpenRouter. They name no contracting entity or governing law; the only contact is support@engy.ai.
- **[earlier notes]** engy's API is OpenAI- and Anthropic-compatible and takes `sk-engy-` keys or btauth/1. It has no client-visible attestation, and Cloudflare plus engy's gateway see plaintext. — [engy API overview](https://engy.ai/docs/api-reference/inference-api/overview); [engy privacy](https://engy.ai/privacy)

**SayGM Terms ("Last updated: 19 November 2026") [earlier notes, read 2026-11-23]** — [SayGM terms](https://saygm.com/terms)
- Acceptable use: "You must not use the Service to… resell or provide access in a way that circumvents our limits or provider policies." "We may suspend or restrict access where reasonably necessary to address these risks."
- "SayGM routes inference requests to third-party model and infrastructure providers… Provider-specific terms or usage policies may also apply to a request routed to that provider."
- "If you use the Service for an organisation, you confirm that you have authority to bind it."
- Business customers are governed by UAE law as applied in Dubai. The operator is T34 Corporation FZCO.
- SayGM's miner terms say: "gm does not represent that supplying capacity through gm is permitted under any particular provider's terms — that judgement is yours." — [gm-miner miner-terms.md](https://github.com/taostat/gm-miner/blob/main/docs/miner-terms.md)
- **Upstream clauses that flow through [earlier notes]:**
  - DeepInfra §11(a)(viii): may not "resell, sublicense, rent, distribute, or otherwise make the Services available to any third party except as expressly permitted". — [DeepInfra terms](https://deepinfra.com/terms)
  - Moonshot: may not "buy, sell, or transfer API keys from, to or with a third party". — [Moonshot terms](https://platform.moonshot.ai/docs/agreement/modeluse)
  - Z.ai: "You cannot transfer, assign, sublicense, or subcontract your rights… without our prior written consent". — [Z.ai terms](https://docs.z.ai/legal-agreement/terms-of-use)
  - Anthropic D.4: may not "resell the Services except as expressly approved by Anthropic". — [Anthropic Commercial Terms](https://www.anthropic.com/legal/commercial-terms)
  - OpenAI 3.1: "Customer may not resell or lease access to its Account or any End User Account." — [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
  - Google APIs Terms: may not "Sublicense an API for use by a third party". — [Google APIs Terms](https://developers.google.com/terms)

**OpenRouter's provider rules (read 2026-11-24)**
- **For-providers docs** (undated):
  - "If you'd like to be a model provider and sell inference on OpenRouter, fill out our form".
  - "For OpenRouter to use the provider we must be able to pay for inference automatically. This can be done via auto top up or invoicing."
  - Providers need a models endpoint whose `id` "should be the exact model identifier that OpenRouter will use when calling your API".
  - "Return early 429s if under load, rather than queueing requests".
  - Uptime routing bands: 95%+ normal, 80–94% lower priority, below 80% fallback only.
  - Declared slugs for `anthropic`, `google`, `openai` and `x-ai` models are held for manual review. Endpoints can stay hidden for "a small list of models whose authors restrict distribution."
  - Nothing on resellers, aggregators or proxying other providers.

  — [OpenRouter for providers](https://openrouter.ai/docs/guides/community/for-providers.md)
- **Application page** (© 2026):
  - "You invoice OpenRouter monthly for inference. We don't onboard providers on other payment terms."
  - "We review providers with proprietary models first." "We give priority to providers that fill gaps in our network." "We can't accept every provider."
  - Required: "A published privacy and data policy", which "says whether you log prompts, how long you keep data, and whether you train on it". "SOC 2 and zero data retention help, but neither is required."
  - Steps: a mutual NDA and call, then "You answer the security questionnaire, upload your security documents and accept the provider terms online."
  - Also required: a `/chat/completions` endpoint that "supports streaming and returns usage tokens", and no personal email addresses.
  - Nothing on resellers or aggregators.

  — [openrouter.ai/providers/apply](https://openrouter.ai/providers/apply)
- **Conflict:** the docs allow "auto top up or invoicing", while the application page accepts only monthly invoicing. — [for-providers docs](https://openrouter.ai/docs/guides/community/for-providers.md); [apply page](https://openrouter.ai/providers/apply)
- **Post-incident enforcement against hidden hops (2026-11-22):** OpenRouter is "conducting technical verification of network paths". Coverage describes this as checking for "hidden forwarding to third parties". — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/); [TheNextWeb](https://thenextweb.com/news/openrouter-drops-providers-dragos-ai-prompt-theft-canaries)
- **Precedents of OpenRouter providers relaying to another provider's API:**
  - Novita's misconfiguration sent MiniMax requests to MiniMax's official API.
  - Prompts "sent through Atlas Cloud" reached MiniMax's official API, and Atlas Cloud then left OpenRouter.

  — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/)
- **Observed provider configs that point at another company's infrastructure (2026-11-24):**
  - Arcee AI's `baseUrl` is `https://api.clarifai.com/v2/ext/openai/v1`;
  - Recursive's is a `modal.direct` host.

  Several providers use dedicated OpenRouter hosts: `openrouter.cloud.near.ai`, `openrouter.phala.com`, `openrouter.inference.crusoecloud.com`, `api.akashml.com/integrations/openrouter`, `api.intelligence.io.solutions/api/openrouter`. — provider pages for [Arcee AI](https://openrouter.ai/provider/arcee-ai), [Recursive](https://openrouter.ai/provider/recursive), [NEAR AI](https://openrouter.ai/provider/near-ai) and [Crusoe](https://openrouter.ai/provider/crusoe)

### Inferences
These are contract-risk readings, not legal advice.
- **Chutes: §9.3 is the controlling clause.** An OpenRouter endpoint serving Chutes models is a standalone inference service that redistributes Platform access. §9.1 embedding covers URnetwork's own product, not a public API listing. So URnetwork needs a written §9.3 agreement, or authorized-reseller status under §9.4.
- **That agreement should also replace §9.2's flow-down.** OpenRouter's users contract with OpenRouter, not URnetwork. URnetwork could not "bind each End User" to Chutes-protective terms and a claim waiver, or "act promptly" against a specific end user. It could also be argued to give them "unrestricted access to the Platform".
- **§3.3 is met in that setup.** URnetwork's relay keeps the Chutes key; OpenRouter holds a URnetwork key.
- **Chutes' incentive is mixed.** Its SayGM stance suggests it welcomes router customers. But a URnetwork listing would compete with Chutes' own OpenRouter listing for the same `-TEE` models at a higher price.
- **engy: permitted on the face, but thin footing.** Nothing forbids resale via OpenRouter. With no named entity or governing law, URnetwork should get written confirmation and an entity name before relying on it. Qualifying for OpenRouter ZDR would require sending engy every request with `provider.zdr: true`. Even then, Cloudflare and engy's gateway see plaintext, so engy routes can never back a TEE-labelled listing under R-PROV-3.
- **SayGM: allowed only where every upstream allows it.**
  - Chutes-sibling routes need Chutes' consent.
  - DeepInfra, Moonshot and Z.ai routes are restricted.
  - Frontier models are effectively unlistable: lab terms, OpenRouter's manual review of `anthropic`, `openai`, `google` and `x-ai` slugs, and its distribution-restricted list.
  - Miners and their accounts are anonymous, so URnetwork cannot audit compliance.
- **OpenRouter: an aggregator-of-aggregators is not barred on paper, but it is disadvantaged in practice.**
  1. The upstream hop must be disclosed in the data policy and security questionnaire. After 2026-11-22, an undisclosed hop is exactly what network-path checks look for.
  2. "Priority to providers that fill gaps" counts against reselling models Chutes already serves there.
  3. Margin over Chutes' list price makes URnetwork the costlier route under cost-weighted routing.

  The only gap URnetwork could plausibly claim is an attested, gateway-blind TEE route. Reselling Chutes cannot deliver that (Section 3).
- **Lower-friction alternative.** OpenRouter's Private Providers feature lets a customer register its own endpoint behind OpenRouter policies, on the customer's own unverified "attestation". It avoids the public-listing backlog and has existed as an API since at least 2026. A URnetwork-served private provider still runs into §9.3 and the plaintext directive. — [OpenRouter API: create a private provider](https://openrouter.ai/docs/api/api-reference/private-providers/create-a-private-provider.md); [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-inference-provider-prompt-theft-zdr-canary/)

### Gaps
- OpenRouter's provider terms and security questionnaire are not public. Whether they restrict subcontracting, require named subprocessors or forbid reselling a provider already on the platform could not be checked.
- No public Chutes reseller or partner programme terms were found, despite §9.4 referring to authorized resellers.
- engy's legal entity and governing law are unknown. SayGM's DPA is unknown.
- Whether OpenRouter has ever onboarded a pure reseller of another OpenRouter provider's models is not documented.

## 5. Earning in reverse: can Bittensor providers sell to OpenRouter directly, and what do the Chutes and Targon listings teach?

### Takeaway
Only one Bittensor subnet sells on OpenRouter today: Chutes (SN64). Targon (SN4) used to, and was gone by about late September 2026 when it retired its inference API. engy (SN53) and SayGM (SN28) are not listed, and a May 2026 claim that SN28 "integrates" with OpenRouter is unsupported.

OpenRouter's documents set no bar against subnets. But OpenRouter pays providers by **monthly USD invoice**, so every listing earns dollars, not gamma. A URnetwork listing that buys from engy or SayGM would have to convert fiat into gamma.

The precedents show three things:
- OpenRouter volume follows price and free tiers;
- the data-policy label decides whether ZDR traffic is reachable at all;
- a subnet's change of strategy can end a listing.

### Cited Findings
- **Who is listed.** On 2026-11-24 the providers API has Chutes, and no Targon, engy, SayGM, gm or Nineteen. — [providers API](https://openrouter.ai/api/v1/providers)
- **Targon's exit [earlier notes]:**
  - `openrouter.ai/provider/targon` returned 404 on 2026-11-23.
  - A bug report from about late September 2026 lists Targon among 11 slugs "OpenRouter no longer serves".
  - `api.targon.com/v1/*` returns 410 Gone.
  - The Targon inference hub repo was deleted by 2026-05-25, and the subnet is now a GPU/CVM rental auction.

  — [pydantic-ai issue #8885](https://github.com/pydantic/pydantic-ai/issues/8885); [targon_sn4.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/targon_sn4.md>); [DevProof Targon report](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/targon-confidential-compute/DEVPROOF-REPORT.md)
- **An unverified May 2026 claim:** "Targon and Nineteen" were "operational on OpenRouter", and SN28 gm was the core of a "confidential routing" integration. No mechanism is given. Its source is CryptoBriefing. — [KuCoin (2026-05-30)](https://www.kucoin.com/news/flash/bittensor-integrates-confidential-routing-layer-with-openrouter-processes-up-to-120-billion-tokens-daily)
- **Chutes' OpenRouter arc:**
  - **[earlier notes]** OpenRouter peak of about 42B tokens/day on 2026-02-07. — [Own Your Mind](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
  - **[earlier notes]** The sponsored free tier on OpenRouter ended on 2026-03-20 (secondary). — [Activepieces](https://www.activepieces.com/blog/chutes-ai-pricing-plans-limits-and-costs-2026)
  - About 8.3B tokens/day and rank 73 on 2026-11-22 (estimate), with 84.6% of tokens on its cheapest model, Qwen3.8-27B at $0.039/M input. — [Vantage](https://routers.vantage.sh/providers/chutes)
  - Labeled `retainsPrompts: true`, with no ZDR endpoints. — [providers page](https://openrouter.ai/provider/chutes); [ZDR API](https://openrouter.ai/api/v1/endpoints/zdr)
- **How OpenRouter pays and admits providers:**
  - "OpenRouter pays providers through monthly invoicing." "You invoice OpenRouter monthly for inference."
  - It has a "large backlog of applications", with priority to "proprietary models" and to "providers that fill gaps".

  — [openrouter.ai/providers/apply](https://openrouter.ai/providers/apply)
- **Payment rails of the gamma providers [earlier notes]:**
  - engy takes card, USDC, TAO, alpha (SN53) and gamma (SN53). "One Gamma adds $1 of engy credit, plus a 5% bonus". — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments)
  - SayGM credits "$1 per gamma spent", and "Gamma credit is non-refundable". — [SayGM terms](https://saygm.com/terms)
  - Chutes shows no evidence of accepting gamma (Stripe, TAO and alpha only, as of 2026-11-23). — [chutes.ai/pricing](https://chutes.ai/pricing)
- **Decentralized supply can win on OpenRouter** when priced low and ZDR-labelled (Vantage estimates, 2026-11-22):
  - InferenceNet: rank 10, 729.6B tokens/day, 22 ZDR endpoints.
  - PrimeIntellect: rank 22, 427.1B tokens/day, 30 ZDR endpoints.
  - AkashML and Io Net: ZDR, ranks 66 and 72.

  — [routers.vantage.sh/providers](https://routers.vantage.sh/providers); [ZDR API](https://openrouter.ai/api/v1/endpoints/zdr)
- **Routing penalties.** OpenRouter gives no traffic to providers whose errors or 429s are far worse than peers'. **[earlier notes]** Chutes' GLM-5.2-TEE was rate-limiting 52% of requests in the last hour of a 2026-11-23 snapshot. — [provider routing docs](https://openrouter.ai/docs/guides/routing/provider-selection.md); [api.chutes.ai/chutes/utilization](https://api.chutes.ai/chutes/utilization)
- **Design context.** DESIGN-COMPUTE.md Q-PROV-5 decided that the catalog does not take OpenRouter as an *upstream* at launch (owner-confirmed, CO-42). Listing URnetwork *on* OpenRouter is the reverse direction and is not covered there. — [DESIGN-COMPUTE.md](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)

### Inferences
- **engy and SayGM face no evident bar.** Both run OpenAI-compatible, streaming APIs and could apply as providers themselves, subject to the backlog and "fill gaps" test.
  - engy's catalog overlaps heavily with models that 14–53 endpoints already serve on OpenRouter.
  - SayGM's frontier models are blocked by lab terms and manual review.
  - If either lists directly, URnetwork's resale of them on OpenRouter becomes redundant.
- **Money flow for a URnetwork listing.** OpenRouter would pay URnetwork USD monthly, in arrears. URnetwork would prepay Chutes (fiat or TAO; crypto is final under §12.3), engy (gamma +5%) and SayGM (gamma, non-refundable). That is a working-capital gap of about one month plus the fiat-to-gamma conversion cost, carried by URnetwork's treasury. See the earlier gamma treasury notes (not re-read here).
- **Lessons from the precedents:**
  1. **Free and sponsored tiers buy volume that does not persist.** Chutes went from about 42B/day to about 8B/day after its subsidy ended.
  2. **Price sets the traffic.** Chutes' traffic sits almost entirely on its cheapest model, so a reseller priced above its upstream's own listing will get only pinned traffic.
  3. **The data-policy label gates privacy-minded traffic.** Chutes' `retainsPrompts: true` excludes it from every ZDR-filtered request.
  4. **Listings die with strategy changes.** Targon's pivot removed it.
  5. **Capacity matters.** Thin TEE capacity turns into 429s, which OpenRouter's router punishes.

### Gaps
- OpenRouter's provider payout terms, take rate, payment timing and any minimums are not public. The application page says only "monthly invoicing".
- The exact date of and reason for Targon's delisting, and whether Nineteen (SN19) was ever a provider, were not established.
- No evidence was found that engy or SayGM has applied to OpenRouter, or plans to.
