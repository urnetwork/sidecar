# SayGM (SN28) as a gamma-paid inference provider for URnetwork: gamma, btauth/1, billing verification, model allowlists, terms and upstreams (state as of 2026-11-23)

Conventions:
- Pages were fetched on 2026-11-23 between about 17:59 and 18:20 UTC unless another date is given.
- **[chain 2026-11-23]**: read by this researcher from Finney storage over public JSON-RPC ([entrypoint RPC](https://entrypoint-finney.opentensor.ai), [archive RPC](https://archive.chain.opentensor.ai)).
  - Current values are at finalized block 9,571,070 (2026-11-23 18:01:48 UTC, runtime spec 494).
  - "First block" dates come from binary searches between block 9,520,000 and head 9,571,079 (18:03:36 UTC). A binary search assumes a value stayed set once set. For the SN28 flag, toggling was checked separately with 61 evenly spaced samples.
  - Storage layouts (`SubnetGammaEnabled`, `Services`, `GammaDeposits`, `GammaSpent`) are from [subtensor lib.rs](https://github.com/RaoFoundation/subtensor/blob/main/pallets/subtensor/src/lib.rs).
- **[live call]**: a free, unauthenticated GET made by this researcher. No signed, paid or authenticated request was sent to SayGM or any provider.
- **[earlier notes]**: from this folder's [all_inference_providers.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/all_inference_providers.md>), [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>) or [chutes_sn64.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/chutes_sn64.md>). Those files cite their own primary sources.
- **[computed]**: computed by this researcher from the cited data.

## 0. Verdict: can SayGM meet N1–N5 and the per-hotkey model allowlist, and on what terms?

### Takeaway
SayGM meets three of the five requirements as of 2026-11-23:
- **N1** (direct btauth/1 calls): every paid route accepts btauth/1, and no API key is used.
- **N3** (gamma): SN28 gamma has been on since 2026-11-18 09:36 UTC, at $1 per gamma, usable on any model including frontier.
- **N5** (compatible API): OpenAI Chat Completions and Responses, Anthropic Messages, and Gemini.

It fails **N2** and the **model-allowlist requirement**:
- No response carries a signed receipt.
- The public per-request settlement records hold no hotkey, btauth nonce, body hash or signature.
- `/balance` is a cumulative per-hotkey total.
- Neither hotkeys nor API keys can be restricted to models or providers. The only restriction is the per-request, unsigned `X-GM-Providers` header, which the device controls.

**N4** is partly met:
- The terms do not forbid serving one's own end users; they forbid resale only "in a way that circumvents our limits or provider policies".
- SayGM's own record retention is stated.
- But SayGM makes no training statement about itself, offers no DPA and no zero-retention flag, and leaves upstream retention and training to each provider. Moonshot's default terms let it use content to improve its services.
- Every upstream named in the open tier, except engy, restricts passing its service on to third parties. SayGM's miner terms put that compliance on anonymous miners.

On today's terms, SayGM is usable for URnetwork only with compensating controls (Section 3 Inferences). Otherwise SayGM would need to add hotkey-bound signed usage (keyed by btauth nonce or body hash) and a per-hotkey model allowlist.

### Cited Findings
- **N1, met.** Every paid path in the gamma OpenAPI lists only `security: [{btauth: []}]`, and its scheme text ends "Send no API key headers with a signed request." — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json). Its `info` says: "The first credited spend creates the hotkey's balance; no sign-up or API key is needed." — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- **N2, not met.** Production settlement records have no signature and no buyer, hotkey, nonce or body-hash field (Section 3). `/balance` returns only `credited_usd`, `used_usd` and `remaining_usd` (Section 3). — [epoch 26511 raw.jsonl.zst](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/raw.jsonl.zst); [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- **N3, met.** `SubnetGammaEnabled(28)` is true. It first read true at block 9,532,572 (2026-11-18 09:36:48 UTC) [chain 2026-11-23]. "SayGM credits $1 per gamma… Gamma credit is usable for any gateway model." — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- **N4, partly met.**
  - The terms (19 November 2026) and privacy policy (2 October 2026) are quoted in Section 4.
  - Upstream clauses are in Section 5.
  - "SayGM does not make retention or training claims about upstream providers." — [SayGM llms.txt](https://saygm.com/llms.txt)
- **N5, met.** The service exposes `/v1/chat/completions`, `/v1/responses`, `/v1/messages` and `/v1beta/models/{model}:generateContent`, among others. — [SayGM llms.txt](https://saygm.com/llms.txt)
- **Allowlist, not met.**
  - The Account API's `POST /keys` takes only `name` and `tool`; `PATCH /keys/{id}` takes only `name`. — [SayGM Account API OpenAPI](https://account.saygm.com/v1/openapi.json)
  - Provider restriction exists only as the request header `X-GM-Providers`. — [SayGM docs: routing](https://docs.saygm.com/api/routing/)

### Inferences
- **What to ask SayGM for**, so that URnetwork can verify usage and constrain spend under btauth (these are recommendations, not SayGM commitments):
  - (1) A signed per-response receipt, or a hotkey-filtered usage listing, that carries the btauth `X-Bittensor-Nonce` or the SHA-256 body hash next to `request_id`, model, tokens and charged nano-USD. SayGM already has the material for this: its gateway sees the btauth headers and has an attested `gateway_pubkey` (Section 3).
  - (2) A per-hotkey policy that SayGM enforces: a model allowlist, a provider allowlist, and per-request or daily caps.
  - (3) A written data-processing commitment that states SayGM's own no-training and no-retention position, and that pins providers which do not train.
- **Until then:**
  - Treat SayGM as a provider whose per-request charges URnetwork can only reconcile statistically.
  - Bound exposure with small balances per hotkey and the deposit's daily spend cap.
  - Do not bill users from device-reported cost alone.

### Gaps
- Whether SayGM would add hotkey policies or signed receipts was not asked; no sign-up or contact was made.

## 1. Gamma now: SN28's flag, SayGM's service document, rate, balance endpoint, and what "turned on gamma" changed

### Takeaway
SN28 gamma has been on since 2026-11-18 09:36:48 UTC, with no toggling seen since. SayGM published its service at the subnet-owner hotkey 36 seconds earlier. The service document has one payment entry (`gamma`, `btauth/1`, balance `https://api.saygm.com/balance`). Credit is $1 per gamma with no bonus, and it is usable on any model, frontier included.

No announcement was found. The visible changes are:
- the chain switch on 11-18;
- a terms update on 19 November whose only change is a gamma paragraph;
- new gamma docs and a hotkey OpenAPI;
- a btauth-signed `GET /balance`.

The existing inference routes simply accept btauth. Prices did not change.

On-chain use is tiny: exactly one SN28 deposit exists, and the only spend at SayGM, 0.1 gamma, was made at 02:01 UTC on 2026-11-23. That spend may be what prompted "just turned on gamma".

### Cited Findings
**Chain state [chain 2026-11-23]**
- `GammaEnabled` = true; `SubnetGammaEnabled(28)` = true at finalized block 9,571,070 (2026-11-23 18:01:48 UTC). — [Finney entrypoint RPC](https://entrypoint-finney.opentensor.ai)
- **When it switched on.** `SubnetGammaEnabled(28)` first reads true at block **9,532,572 (2026-11-18 09:36:48 UTC)**. All 61 evenly spaced samples from then to the head read true, so no toggle-off was seen at about 2-hour resolution. The 2026-11-18 09:36 date matches the earlier notes [earlier notes]. — [Finney archive RPC](https://archive.chain.opentensor.ai)
- **The service entry.**
  - `Services(28, 5Evgh9QTXJLxYLusVy3tcY5S6Z3GgRSNDb9AzXUchX5dco3P)` first exists at block **9,532,569 (2026-11-18 09:36:12 UTC)**.
  - Its URL is `https://saygm.com/services.json`, both at block 9,567,893 (07:26 UTC) and at the head.
  - That hotkey is `SubnetOwnerHotkey(28)`. `SubnetOwner(28)` is coldkey `5CA6rwAytZvvyZhLYEzo79627QEV422Q8kD51DEnTaRQxm45`.

  — [Finney archive RPC](https://archive.chain.opentensor.ai)
- **Deposits.** SN28 has **exactly one gamma deposit**:
  - hotkey `5DV2YvVaDhR6PErvbYViDAWQGahScahKLfkr6Hfxks83YtM5`, coldkey `5CwBNV18DA9RUgyZ2wTPwR1F9LnhQEFVo4AxE6w811FZXRvp` (not the owner coldkey);
  - balance 0.272932423 gamma, with no daily cap;
  - first present at block 9,566,266 (2026-11-23 02:01:00 UTC).

  — [Finney archive RPC](https://archive.chain.opentensor.ai)
- **Spends.** `GammaSpent(28, SayGM publisher, 5DV2Yv…)` = **0.1 gamma**, first non-zero at block 9,566,269 (2026-11-23 02:01:36 UTC). It is the only `GammaSpent` entry on SN28, so total gamma spent at SayGM is 0.1 (about $0.10). — [Finney entrypoint RPC](https://entrypoint-finney.opentensor.ai)
- **Pool depth.** `SubnetTAO(28)` = 28,831.34 TAO; `SubnetAlphaIn(28)` = 935,019.39 alpha; spot price 0.03084 TAO per alpha. The earlier notes had about 29,578 TAO [earlier notes]. — [Finney entrypoint RPC](https://entrypoint-finney.opentensor.ai)
- **Runtime 494** went live at block **9,570,596 (2026-11-23 16:27:00 UTC)** [chain 2026-11-23].
  - Its release summary lists commitments, weight delegation, basket trade bands and an Etao owner-update limit. It lists no gamma or btauth change.
  - It says "Runtime spec version 494 and transaction version 2 require signers and indexers to regenerate metadata."

  — [494 release notes JSON](https://github.com/RaoFoundation/subtensor/blob/main/.github/release-notes/runtime/494.json)
- The signed-requests guide last changed in Release 489 (2026-11-10), and the services guide on 2026-11-19 ("Document the gamma balance url and http services"). — GitHub commit history of [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx) and [services.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/services.mdx)

**Service document [live call]**
- `https://saygm.com/services.json`, byte-identical to `https://saygm.com/gamma/services.json`:
  - `"description":"SayGM provides prepaid access to AI models through an API, with gamma as a payment method."`
  - `"publishers":[{"netuid":28,"hotkey":"5Evgh9QTXJLxYLusVy3tcY5S6Z3GgRSNDb9AzXUchX5dco3P"}]`
  - `"services":[{"type":"http","endpoint":"https://api.saygm.com","spec":"https://saygm.com/gamma/openapi.json"}]`
  - `"payments":[{"type":"gamma","signature":"btauth/1","balance":"https://api.saygm.com/balance"}]`
  - `"pricing":"https://api.saygm.com/v1/models"`, `"terms":"https://saygm.com/terms"`, `"docs":"https://saygm.com/gamma/guide.md"`

  There is no `max_spend`, no `x402` entry, and no rate field. The `pricing`, `terms` and `docs` fields are new relative to the earlier notes' description. — [SayGM services.json](https://saygm.com/services.json); [gamma/services.json](https://saygm.com/gamma/services.json)

**Rate and scope**
- "Spend gamma from a hotkey deposit at one of SayGM's publisher hotkeys. Each hotkey has its own SayGM balance. That balance belongs to the spending hotkey. Gamma credit is usable for any gateway model." — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- "A few minutes after each spend finalizes, SayGM credits $1 per gamma to the balance for the spending hotkey." — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- "Minimum spend is 0.1 gamma; the remaining deposit can be spent in full. Each spend is limited by the deposit balance and available daily spend cap. One spend can be pending per hotkey per subnet at a time." "Gamma credit is non-refundable." The guide requires `pip install "bittensor>=11.3.5" httpx`. — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- Prices are the general catalog's ("Prices are in `GET /v1/models`"). — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- Gamma pricing compared with others: engy credits $1 + 5% per gamma; Lium, Hippius and EveryFrame credit $1 [earlier notes].

**Balance endpoint**
- `GET https://api.saygm.com/balance?hotkey=<ss58>`, btauth-signed over an empty body. — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- Its OpenAPI text: "Returns the signing hotkey's spendable USD balance. A hotkey with no credited spend returns zeros. Sign the path including its query string." Other responses: 403 "The hotkey parameter is not the signing hotkey"; 503 "The balance is unavailable. Retry shortly." — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- [live call] An unsigned `GET https://api.saygm.com/balance?hotkey=…` returned **401** with `{"error":"unauthorized"}` and an `x-gm-request-id`. `GET https://api.saygm.com/v1/balance` returned **404** "Unknown endpoint". The gamma OpenAPI's `servers` value (`https://api.saygm.com/v1`) is therefore wrong for `/balance`, and also for `/v1beta/...`. The service document's URL is the right one. — [api.saygm.com/balance](https://api.saygm.com/balance); [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)

**What "turned on gamma" changed**
- **Terms.** The current terms are "Last updated: 19 November 2026". The archived 2026-10-21 copy read "Last updated: 17 August 2026". Diffing the two texts, **the only change is one added paragraph**:

  > "Spending gamma at SayGM means you accept these terms. Calling the API with a signed request also means you accept these terms. A few minutes after each spend finalizes, SayGM adds $1 per gamma spent to the balance for the spending hotkey. That balance belongs to that hotkey. Gamma credit is non-refundable."

  The resale clause predates gamma. — [SayGM terms](https://saygm.com/terms); [Wayback capture 2026-10-21](https://web.archive.org/web/20261021064951/https://saygm.com/terms)
- **Docs.** There is a hotkey OpenAPI titled "SayGM Gateway API for Bittensor hotkeys". llms.txt has a "Hotkey auth" bullet. top-up.md has a Gamma section. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json); [SayGM llms.txt](https://saygm.com/llms.txt); [SayGM top-up guide](https://saygm.com/topup.md)
- **Routes.** No new inference route was added. The btauth paths are the existing chat completions, responses, messages, Gemini, images and videos routes, plus the btauth-only `GET /balance`. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- **Not changed:**
  - The docs site (docs.saygm.com, pages "Last updated: Oct 29, 2026") has no gamma or btauth page; its sitemap lists none. — [docs.saygm.com sitemap](https://docs.saygm.com/sitemap-0.xml)
  - The blog index (latest posts 2026-11-20) and the site sitemap have no gamma post. — [SayGM blog](https://saygm.com/blog); [saygm.com sitemap](https://saygm.com/sitemap.xml)
  - Web searches for a SayGM gamma announcement found none.
  - A 2026-11-23 gamma-spending tracker repost (311 mints, $49,657.80; 207 spends, $47,735 through Nov 22; Lium about 87%) does not mention SayGM. — [KuCoin insight, 2026-11-23](https://www.kucoin.com/news/insight/TAO/6b03d69e9278e40007d921f1)
  - SubnetRadar's SN28 chart has a "Gamma switched on" marker type, but its date could not be read. — [SubnetRadar SN28](https://subnetradar.com/subnet/28)
- **Unrelated to gamma.** SayGM's "Buybacks" page (cycle 03, 16 Oct–16 Nov 2026) reports 22,915 alpha burned against 91,045 alpha emitted to miners (25.2%). These are monthly treasury burns with `burnAlpha`, not gamma. — [SayGM buybacks](https://saygm.com/buybacks)

### Inferences
- **What "just turned on gamma" probably refers to:**
  - SayGM enabled gamma on 11-18 and updated its terms on 11-19, without a blog post.
  - The first and only customer spend happened at 02:01 UTC on 11-23.
- **No frontier tier is specific to gamma**: gamma credit buys the same catalog at the same prices as card or crypto credit.
- **The pool is deep enough.** At about 28.8k TAO, a $10k mint (about 51 TAO at $192–196) would move the pool's price by roughly 0.18% [computed].
- **Runtime 494 does not change gamma semantics.** URnetwork's own mint and spend tooling must still regenerate metadata for transaction version 2 [inference from the release summary].

### Gaps
- No SayGM announcement (X, Discord, Medium) could be read. SayGM's X account was not fetched.
- The SubnetRadar marker's date could not be read; the chart loads by script.
- Whether `SubnetGammaEnabled(28)` was ever toggled between samples (about 640 blocks apart) is unknown.
- Spends under runtimes 488–492 (before `GammaSpent` existed) were not scanned from events. SN28 enabled gamma under runtime 491, so a pre-v493 spend at SayGM is possible, though no SN28 deposit existed before 11-23 under the binary-search assumption.

## 2. btauth/1 details at SayGM: freshness window, rate limits, and whether keys or hotkeys can be restricted to models or providers with spending caps

### Takeaway
SayGM publishes **no freshness window and no rate-limit numbers** for btauth.
- Its 401 covers signatures that are "missing, invalid, expired or replayed".
- Its 429s give a `Retry-After` but no limits.

**No allowlist exists for hotkeys or API keys:**
- A hotkey has no account record or settings at all.
- The Account API can create a key (`name`, `tool`), rename it, revoke it, and weight its share of a shared balance; that is all.
- Model and provider choice is per request: the body's `model` and the unsigned `X-GM-Providers` header, both of which the device controls.

**Spending caps:**
- At SayGM, the only per-key limit is balance allocation (weights 1–100).
- Hotkeys have none. A hotkey's whole credited balance is spendable by any validly signed request.
- The only hotkey-side brake is the on-chain daily spend cap on the gamma deposit, which limits refills, not spending.

### Cited Findings
**Freshness window and replay**
- The gamma OpenAPI's 401 on every paid route reads "The btauth/1 signature is missing, invalid, expired or replayed." No window is given. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- The guide: "Signed requests may use sr25519 (the default) or ed25519. Generate fresh signed headers for every request attempt, including retries." Hashed schemes are not offered. — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- The scheme text says to sign "over the method, the full request path with its query string (for example `/v1/chat/completions`) and the exact body bytes", and to send all six `X-Bittensor-*` headers. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- The SDK's defaults are a 10 s maximum age and 2 s future skew, with one acceptance per (hotkey, nonce) [earlier notes]. — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)

**Rate limits**
- Every btauth inference path lists a bare 429 with no description. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- The general OpenAPI's inference 429: "Account, model, or upstream request limit. OpenAI-shaped account-limit errors use `rate_limit_exceeded`", with `Retry-After`: "Seconds before retrying, when a delay is available." The videos 429: "The account has reached a video job or upload concurrency limit." — [SayGM OpenAPI](https://saygm.com/openapi.json)
- The terms: "We may apply reasonable rate, usage, or security limits to protect the Service and other users." — [SayGM terms](https://saygm.com/terms)
- [live call] No rate-limit headers appeared on unauthenticated responses. The exposed headers were `x-gm-request-id`, `x-gm-surface-translated`, `x-gm-response-losses`, `x-request-id` and `request-id`. — [api.saygm.com/v1/models](https://api.saygm.com/v1/models)
- "When every matching route is rate-limited, you get HTTP 429 with Retry-After." — [SayGM docs: errors](https://docs.saygm.com/api/errors/)

**Keys and the Account API (`account.saygm.com/v1`)**
- The Account API's description: "Account state for SayGM customers. Sign in with the device grant under `/oauth`, then send the access token as `Authorization: Bearer <access_token>`. `GET /usage/self` instead accepts an inference API key and returns only that key's history." — [SayGM Account API OpenAPI](https://account.saygm.com/v1/openapi.json)
- What the key endpoints accept, per the same OpenAPI:
  - `POST /keys` takes `{"name": string (required), "tool": "claude-code"|"codex"|"hermes"|"openclaw"}`.
  - `PATCH /keys/{id}` takes `{"name"}` only.
  - `PUT /keys/allocations` takes `{"allocations":[{"id", "weight": 1–100}]}`.
  - `PUT /keys/allocation-mode` ("Share the whole balance across keys, or split it by weight").

  — [SayGM Account API OpenAPI](https://account.saygm.com/v1/openapi.json)
- The Key schema has `id`, `name`, `prefix`, `status`, `created_at`, `last_used_at`, `created_via`, `weight`, `share_percent` and `spendable`.
  - A listing schema elsewhere also shows `rate_limit_rpm`, `cu_limit` and `expires_at` (integer or null).
  - No endpoint sets those three.
  - Searches of the whole Account API for `allowed_models`, `model_allowlist`, `allowed_providers`, `spend_limit` and `monthly_limit` returned 0 hits. Its only "allowlisted" text concerns integration pages.

  — [SayGM Account API OpenAPI](https://account.saygm.com/v1/openapi.json)
- Keys are minted with an account access token obtained through a coldkey-signature OAuth grant (`POST https://account.saygm.com/v1/keys`). — [SayGM top-up guide](https://saygm.com/topup.md)
- Balance sharing: "When shared balance is on, every key can spend your entire prepaid balance — there is no per-key cap. With shared balance off, each key spends its configured allocation; the remainder is split across your other keys by their current shares." — [SayGM llms.txt](https://saygm.com/llms.txt)
- Guardrails are "Optional, per-API-key processors that run inside the enclave… PII redaction, secret/credential redaction, custom regex, and blocked-word filters… Configured per key in the dashboard". They act on content, not on model choice. — [SayGM llms.txt](https://saygm.com/llms.txt)
- The only customer-set spending limit found is on "Sign in with SayGM" partner keys, where the customer picks a monthly limit or "unlimited". These are API keys, not hotkeys [earlier notes]. — [SayGM docs: OAuth](https://docs.saygm.com/api/oauth/)

**Hotkeys**
- A hotkey needs no account: "The first credited spend creates the hotkey's balance; no sign-up or API key is needed." No endpoint configures a hotkey. The gamma OpenAPI's only non-inference btauth route is `GET /balance`. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- Per-request provider restriction (header `X-GM-Providers`): "Comma-separated allowlist of provider identifiers that may serve the request. Use 1 to 16 distinct case-insensitive names". "If none of your chosen providers can serve the request, SayGM returns an error." — [SayGM OpenAPI](https://saygm.com/openapi.json); [SayGM docs: routing](https://docs.saygm.com/api/routing/)
- btauth/1 signs only eight lines: method, target, body hash, nonce, sender, receiver, scheme and version. Headers such as `X-GM-Providers` and `X-GM-Routing` are unsigned [earlier notes]. — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- Admission: "For token-metered requests it may lower the output limit, such as max_tokens, to fit what the balance can cover. When the balance falls short of the estimated input plus a minimum usable output, the request stops there with HTTP 402, before anything is sent upstream". — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- On-chain brake: a deposit's daily spend cap "refill[s] linearly over 7,200 blocks"; a cap of 0 pauses the deposit [earlier notes]. — [gamma guide](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/gamma.mdx)

### Inferences
- **A modified client can spend the hotkey's whole SayGM balance on any catalog model and route**, including frontier models such as `claude-fable-5-2` or `gpt-5.5-pro`. It can also choose `X-GM-Providers`, pick `X-GM-Routing`, and call video and image routes. Per-request exposure is bounded only by the remaining hotkey balance, because the gateway shrinks `max_tokens` to fit it.
- **One exception: the Gemini surface.** There the model id is in the request target, `/v1beta/models/{model}:generateContent`, which btauth signs. On that surface only, the broker can bind the model without reading the body. On Chat Completions, Responses, Messages, images and videos, the model is in the body.
- **Compensating controls available today:**
  - Many hotkeys, each holding a small SayGM balance. The chain allows at most 64 deposits per coldkey per subnet [earlier notes], but more coldkeys can be used.
  - Frequent small top-ups, with the deposit's daily cap limiting how fast any one hotkey can be refilled.
  - Each refill posts "a few minutes after" the spend finalizes, which adds latency to top-ups.
- **Retries.** The freshness window is unstated, so URnetwork should assume the SDK default (10 s / 2 s) and test it. This is unverified.

### Gaps
- SayGM's actual btauth window and nonce-store design, and its rate limits per hotkey and per account, are undocumented. Measuring them would need signed calls, which were out of scope.
- Whether SayGM applies `rate_limit_rpm` or `cu_limit` to hotkeys, and who sets these fields on keys, is unknown.

## 3. Per-request usage that URnetwork can check: settlement data, nonce or body-hash listings, signed receipts, and `/balance`

### Takeaway
SayGM's "published" settlement data has been found: a public-read OVH S3 bucket, `gm-mainnet`, with a folder per finalized 361-block epoch (about 72 minutes).
- Each folder holds `raw.jsonl.zst` with **one record per serving attempt**, keyed by the gateway's ULID `request_id` (the `x-gm-request-id`). Records carry tokens, model, miner, route and the miner's effective price.
- Records appear about 10 minutes after the epoch ends.
- The records carry **no hotkey, btauth nonce, body hash, buyer id or signature**.

Nothing else is keyed by nonce or body hash:
- Responses carry `usage.cost` and `cost_nano_usd`, unsigned.
- `/balance` gives cumulative `credited_usd`, `used_usd` and `remaining_usd` for a hotkey.
- `/v1/usage/self` exists only for API keys.

URnetwork can therefore confirm that a device-reported `request_id` exists, and recompute its charge as the miner price plus 3%. It cannot prove that the record belongs to its own signed request.

### Cited Findings
**Where the public data lives**
- SayGM's privacy policy: "Once the network epoch it belongs to closes, this record is written to object storage as public, permanently readable data — that is by design, not a mistake: it is how the subnet proves its own accounting." — [SayGM privacy policy](https://saygm.com/privacy-policy)
- The validator's mainnet config:

  > `# --- finalized artifacts: public-read OVH bucket, NO credentials required ---`

  It sets `S3_BUCKET=gm-mainnet`, `S3_ENDPOINT_URL=https://s3.gra.io.cloud.ovh.net` and `GM_VALIDATOR_S3_ANONYMOUS=1`. — [gm-validator .env.mainnet](https://github.com/taostat/gm-validator/blob/main/.env.mainnet)
- Object keys are `{prefix}/finalized/epoch={N}/` with `_FINALIZED`, `aggregated.jsonl` and `epoch_summary.json`. The prefix defaults to `v1`. `BLOCKS_PER_EPOCH` is `361`: "the chain head divided by this gives the open epoch id". — [gm-validator s3_mirror.py](https://github.com/taostat/gm-validator/blob/main/validator/src/gm_validator/s3_mirror.py); [gm-validator CLAUDE.md](https://github.com/taostat/gm-validator/blob/main/CLAUDE.md)
- The validator's test fixture also writes `raw.jsonl.zst` per epoch. Its fixture records include a `"signature"` field. — [gm-validator test_validator_integration.py](https://github.com/taostat/gm-validator/blob/main/validator/tests/test_validator_integration.py)
- The validator "treats the published artifact set as authoritative and does not re-derive cost or re-verify hashes or signatures." — [gm-validator README](https://github.com/taostat/gm-validator/blob/main/README.md)

**What the live bucket held [live call]**
- Bucket listing is denied (403 AccessDenied). Path-style URLs return "Not S3 request". Virtual-hosted object GETs work. — [gm-mainnet bucket](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/_FINALIZED)
- Epoch 26511:
  - `_FINALIZED` was last modified 2026-11-23 17:25:50 GMT.
  - `epoch_summary.json` has `"finalized_at":"2026-11-23T17:25:21Z"`, `tao_price_usd` 195.55 (source "taostats"), `alpha_price_usd` 6.0493, `emissions_alpha` 360 and `finalizer_version` 0.3.0.

  — [epoch_summary.json](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/epoch_summary.json)
- `raw.jsonl.zst` (499,477 bytes) holds **14,470 records**:
  - Record timestamps run from 16:02:24 to 17:14:55 UTC. That matches blocks 9,570,471–9,570,831 (26511 × 361 onward); `epoch_summary.json`'s `price_block_height` is 9,570,831. The data was public about 10 minutes after the epoch ended.
  - Each record has the fields `schema_version` ("1"), `request_id`, `timestamp`, `epoch_id`, `gateway_id`, `miner_id`, `worker_id`, `route_id`, `product{provider, model}`, `miner_discount_bp`, `effective_price_ndollars` (rate card), `usage` (input, output, cache, image and reasoning tokens, `long_context_tier`), `surcharges` and `success`.
  - **None has a `signature`, hotkey, nonce, body hash, account or IP field.**
  - Gateways: `gw-mainnet-1` 14,467, `gw-mainnet-2` 3. There were 109 miners, 59 route ids and 435 failures.

  — [raw.jsonl.zst](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/raw.jsonl.zst) [computed]
- Example record:

  ```
  {"request_id":"01M84J9NNT2QG04T2JXMMNNAY4","timestamp":"2026-11-23T16:02:24.833Z","gateway_id":"gw-mainnet-1","miner_id":"5CJHeo…","route_id":38,"product":{"provider":"openai","model":"gpt-5.6-luna"},"miner_discount_bp":1600,"effective_price_ndollars":{"input_per_mtok_ndollars":168000000,"output_per_mtok_ndollars":1008000000,…},"usage":{"input_tokens":600,"output_tokens":522},"surcharges":{},"success":true}
  ```

  `product.provider` names the model maker (anthropic, openai, deepseek, zai, moonshot, qwen, gemini, google, xiaomi), not the upstream host. — [raw.jsonl.zst](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/raw.jsonl.zst)
- `aggregated.jsonl` holds 603 rows per (miner, product) with `totals`, `earnings_ndollars`, `raw_record_count` and a `raw_hash`. — [aggregated.jsonl](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/aggregated.jsonl)
- **Timing [computed].** Record `timestamp` minus the ULID's embedded time is 0 ms minimum, 7.2 s median, 291 s at p99 and 853 s maximum. The ULID marks arrival and the timestamp marks completion. Traffic averaged about 3.0 requests per second.
- **Price check [computed].** In every model checked, the catalog buyer price equals the cheapest record's effective price × 1.03:
  - claude-opus-5-5: $2.000 → $2.060/M input;
  - gpt-5.6-luna: $0.100 → $0.103;
  - kimi-k3: $1.800 → $1.854;
  - deepseek-v4.1-flash: $0.075 → $0.07725;
  - qwen3.8-27b: $0.060 → $0.0618;
  - glm-5.3-flash: $0.1245 → $0.128235.

  Within one epoch, the effective prices of different miners for the same model varied widely. claude-opus-5-5 ranged from 50% to 3% below list. — [raw.jsonl.zst](https://gm-mainnet.s3.gra.io.cloud.ovh.net/v1/finalized/epoch=26511/raw.jsonl.zst); [api.saygm.com/v1/models](https://api.saygm.com/v1/models?include_unavailable=true)
- The buyer charge "is the charge after miner pricing, buyer markup, the retail clamp and any surcharge, computed from the usage the provider reported". — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- **Retries.** "If a request is retried against another miner, it can produce more than one pair; every attempt shares the same request id so the sequence can be audited". All 14,470 request ids in epoch 26511 were unique. — [SayGM privacy policy](https://saygm.com/privacy-policy) [computed]

**Per-response data, receipts and listings**
- "Every successful response carries settled cost inside usage… `cost`… `cost_nano_usd`". On Gemini the fields are `usageMetadata.cost` and `costNanoUsd`. "Error responses carry neither." — [SayGM docs: OpenAI](https://docs.saygm.com/api/openai/); [SayGM docs: Gemini](https://docs.saygm.com/api/gemini/)
- "Each buyer request has one gateway-generated ULID, exposed as x-gm-request-id… the charge for that ID is processed at most once. Sending a new API request creates a new ID and a separate settlement." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- Neither OpenAPI mentions a receipt, a response signature or `x-gm-request-id` (0 hits). [live call] The exposed response headers include no signature header. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json); [SayGM OpenAPI](https://saygm.com/openapi.json)
- The gateway's TDX attestation binds a `gateway_pubkey` (`report_data = SHA‑512(gateway_pubkey ‖ nonce)`), but nothing is signed with it for buyers [earlier notes]. — [SayGM privacy page](https://saygm.com/privacy)
- **`/balance`.** The schema `HotkeyBalance` has `hotkey`, `credited_usd` ("Total USD credited, as a decimal string."), `used_usd` ("Total USD spent, as a decimal string.") and `remaining_usd` ("Spendable USD balance, as a decimal string."). — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- "In a stream the cost fields arrive before the charge posts to the billing service, so the balance may catch up a moment later." "Credit stays available to your other requests until a charge settles." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- **API-key-only history.** `GET https://account.saygm.com/v1/usage/self` "returns only the presented key's usage… requests, errors, and spent", by model or day, over at most 90 days. `GET /v1/credits` is also API-key based. Neither is offered for hotkeys. — [SayGM docs: usage](https://docs.saygm.com/platform/usage/); [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)

### Inferences
- **What URnetwork can verify today:**
  - (a) That a device-reported `x-gm-request-id` exists in the public records.
  - (b) Its model, tokens and miner rate. The buyer charge can be recomputed as rate × 1.03, clamped at retail, plus surcharges. The 3% markup is an inference from the data, not a documented constant.
  - (c) That the ULID's time falls within the btauth window after the broker's nonce.
- **What it cannot do: bind the record to its own signed request.** A modified client could report the id of another customer's cheaper request from the same seconds. At about 3 requests per second there are about 30 candidates in a 10 s window. It could also report nothing for an aborted stream.
- **Per-hotkey `/balance` deltas are exact only with one request in flight per hotkey.** Settlement also lags behind streams. At URnetwork's concurrency this gives reconciliation in aggregate, not per-request verification.
- **N2 is not met.** The smallest change SayGM could make is to put the btauth `(hotkey, nonce)`, or the body SHA-256, into a signed response header or into a hotkey-filtered usage listing, signed with the attested `gateway_pubkey`. Publishing a keyed hash of the hotkey in the public records would also work.
- **Privacy cost of the public records.** They are permanent and public. They reveal timing, model and token counts of every request, which URnetwork's privacy story should take into account.

### Gaps
- How SayGM's billing service keys btauth charges internally (by hotkey, nonce or ULID) is not published.
- Whether failed attempts in the public data carry usage, and how the 3% markup applies to surcharges, was not checked.
- The aggregated `raw_hash` construction was not reproduced.

## 4. SayGM's terms: resale and serving end users, logging and retention, training, zero retention, DPA, suspension and notice

### Takeaway
**Terms of service (19 November 2026):**
- They neither permit nor forbid serving one's own end users expressly.
- Acceptable use forbids resale only "in a way that circumvents our limits or provider policies".
- Provider-specific terms "may also apply".
- SayGM may suspend "where reasonably necessary", or terminate for material breach, with notice only "where reasonably practicable" and only for material adverse changes.

**Privacy policy (2 October 2026; it predates gamma and never mentions hotkeys):**
- Content stays inside the TDX gateway.
- Public settlement records are permanent.
- Diagnostic records are kept 30 days.
- Account and usage data have no fixed deletion period.
- SayGM may act as a processor for business customers.

**What is missing:**
- No SayGM training clause exists. The terms' use grant is limited to providing the service.
- No DPA was found.
- No zero-retention flag exists.
- Upstream retention and training are expressly left to providers.

### Cited Findings
**Terms of service ("Last updated: 19 November 2026")** — [SayGM terms](https://saygm.com/terms)
- Operator: "T34 Corporation FZCO, Dubai World Trade Centre Authority trade licence L-3102, Dubai Unified Licence CN9173".
- Binding organisations: "If you use the Service for an organisation, you confirm that you have authority to bind it." Gamma: "Spending gamma at SayGM means you accept these terms. Calling the API with a signed request also means you accept these terms."
- **Accounts and keys:** "You are responsible for activity carried out through your account or keys… We may apply reasonable rate, usage, or security limits to protect the Service and other users."
- **Providers:** "SayGM routes inference requests to third-party model and infrastructure providers. Models, routes, prices, limits, and features may change as those providers and the network change. Provider-specific terms or usage policies may also apply to a request routed to that provider."
- **Acceptable use** ("You must not use the Service to:"):
  - "submit content you do not have the right or lawful basis to process";
  - "misrepresent AI output as human-generated where the law requires disclosure";
  - "resell or provide access in a way that circumvents our limits or provider policies."
  - Then: "We may suspend or restrict access where reasonably necessary to address these risks."
- **Content:** "You grant us the limited rights needed to transmit and process that content to provide, secure, support, and account for the Service." "rights in output may depend on applicable law and the relevant model provider's terms."
- **Charges:** "Gamma credit is non-refundable." "If you believe a charge or usage record is wrong, contact us promptly. Refund and correction requests are handled under applicable law."
- **Sensitive data:** "You should not submit regulated, confidential, or sensitive data unless you have assessed the Service and relevant provider terms as suitable for that data and implemented any required agreement or safeguards."
- **Changes and suspension:**
  - "We may change, suspend, or discontinue features, routes, or models. Where reasonably practicable, we will give notice of a material change that adversely affects paid use."
  - "We may suspend or terminate access for a material breach, unlawful or harmful use, non-payment, or a security risk."
  - "We may update these terms and will change the date above; material changes will apply prospectively after reasonable notice where required."
- **Law:** "For business customers, these terms are governed by the laws of the United Arab Emirates as applied in Dubai, and the courts of Dubai have non-exclusive jurisdiction." Contact: hi@saygm.com (decoded from the page's obfuscated address).
- The resale and acceptable-use text was identical in the 17 August 2026 version. — [Wayback capture 2026-10-21](https://web.archive.org/web/20261021064951/https://saygm.com/terms)

**Privacy policy ("Last updated: 2 October 2026")** — [SayGM privacy policy](https://saygm.com/privacy-policy)
- **Content:** "The gateway's design is meant to keep request and response content decrypted only inside that enclave, so it is not visible in plaintext to SayGM or to the miner operators whose machines forward it."
- **Providers:** "After any guardrail step, your request content is sent to the model and infrastructure providers selected for that route. These currently include Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot, DeepInfra, and KubeTEE. Depending on the route, a provider may process content on SayGM's instructions or under terms that apply directly to its service."
- **Settlement record:** "It carries no buyer identity at all — no account id, no API key id, no IP address… Once the network epoch it belongs to closes, this record is written to object storage as public, permanently readable data".
- **Diagnostic record:** "kept for 30 days in storage SayGM controls (not public)… never your prompt, completion, or provider-supplied error text."
- **Scope of the TEE claim:** "The TEE description above does not extend to a provider's handling after content reaches it, anything logged by your own client before it reaches SayGM, or the metadata itself".
- **Retention:** "Account, usage, and billing data does not currently have a fixed automatic deletion period."
- **Processor role:** "When a business customer submits personal data through the API for us to process on its instructions, that customer may be the controller and SayGM may act as its processor or service provider."
- **Transfers:** "providers may process data in the United States and other countries outside your own… Contact us for current information about a route's processing locations and any transfer protections relevant to your data."
- **Deletion:** "There is not currently a self-serve account-deletion flow."
- The policy has no word on training by SayGM, and none on gamma, hotkeys or btauth.

**Other statements**
- "The enclave seals each request in-transit and in-use; SayGM does not make retention or training claims about upstream providers." — [SayGM llms.txt](https://saygm.com/llms.txt)
- On frontier routes: "On a Claude model, the provider serving the request still receives your prompt and processes it under its API terms. If you need a data-handling contract of your own with Anthropic, sign it directly." [earlier notes] — [SayGM vs Anthropic](https://saygm.com/vs/anthropic)
- **Zero retention:** there is no ZDR flag. The privacy page offers per-key guardrails and the confidential (`-tee`) tier as its privacy options [earlier notes]. — [SayGM privacy page](https://saygm.com/privacy)
- **DPA:** none found on saygm.com. The sitemap's legal pages are `/terms`, `/privacy-policy`, `/bot-terms` and `/bot-privacy`. — [saygm.com sitemap](https://saygm.com/sitemap.xml)

### Inferences
- **Serving URnetwork's users does not, on its face, breach SayGM's own terms:**
  - URnetwork would be "an organisation" responsible for its keys and hotkeys.
  - The resale clause targets circumventing limits and provider policies.
  - Because the clause also names "provider policies", the upstream restrictions in Section 5 flow through to URnetwork.
- **Training.** The terms' content grant ("to provide, secure, support, and account for the Service") reads as excluding training by SayGM itself, but no clause says so expressly.
- **N4 gaps** URnetwork would want closed in writing: an express no-training and no-retention clause for SayGM, a DPA, named providers with their retention terms, and longer notice before suspension. The suspension standard ("where reasonably necessary") gives no cure period.

### Gaps
- Whether SayGM offers a DPA or enterprise terms on request is unknown. Its contact is hi@saygm.com and Discord.
- The Discord bot terms (`/bot-terms`) were not read; they cover a separate product.

## 5. The upstreams behind the `open` (non-TEE) tier, and whether their terms permit this resale chain

### Takeaway
The open tier has 13 products, 12 of them available. They are served by SN28 miners' own accounts at:
- DeepInfra, Z.ai, Moonshot, engy and Moonmath ZRO;
- Chutes and KubeTEE, through "TEE sibling" routes.

`gateway_provider` and the public records name only the model maker, so a buyer cannot tell which host served a request.

SayGM's miner terms disclaim the question entirely: "gm does not represent that supplying capacity through gm is permitted under any particular provider's terms — that judgement is yours."

The upstream terms:
- **DeepInfra** forbids making the Services available to any third party except as expressly permitted.
- **Moonshot** forbids leasing account access and trading API keys, and by default may use content to improve its services.
- **Z.ai** permits serving end users of your own applications, but bars sublicensing without written consent.
- **Chutes** bars standalone resale without a written agreement, but has publicly endorsed SN28 routing.
- **engy's** terms are silent on resale.

The chain URnetwork → SayGM → anonymous miner → upstream account is therefore not clearly permitted by most of these terms. Only Chutes has given anything like approval.

### Cited Findings
**Open-tier catalog [live call]**
- The open tier (`tier: "open"`; 13 entries with `include_unavailable=true`), by `gateway_provider`:
  - deepseek: `deepseek-v4-flash-0731`, `deepseek-v4.1-flash`, `deepseek-v4.1-flash-1017`;
  - zai: `glm-5.2`, `glm-5.3`, `glm-5.3-flash`;
  - moonshot: `kimi-k3`, `kimi-k3.1-pro`;
  - qwen: `qwen3.6-35b-a3b`, `qwen3.8-27b`;
  - openai: `gpt-oss-20b`;
  - bfl: `flux.2-klein-4b` (images);
  - xiaomi: `mimo-v2.6-pro-ultraspeed`, unavailable at `published_retail`.
- The whole catalog has 74 entries (67 available): frontier 45, confidential 16, open 13. — [api.saygm.com/v1/models?include_unavailable=true](https://api.saygm.com/v1/models?include_unavailable=true)
- "Open-weight models in the open tier take the frontier route: sealed through the gateway, then served by the named provider under its terms." — [SayGM privacy page](https://saygm.com/privacy)

**Which hosts serve which open models** (gm-miner sourcing matrix, "Snapshot date: **2026-11-04**", described as "a miner setup matrix, not a buyer product catalog") — [gm-miner provider-model-support.md](https://github.com/taostat/gm-miner/blob/main/docs/provider-model-support.md)

| Open product | Sources |
|---|---|
| DeepSeek V4 Flash 0731 | Engy; DeepInfra; Chutes (TEE sibling) |
| DeepSeek V4.1 Flash | DeepInfra; Engy; KubeTEE (TEE sibling) |
| DeepSeek V4.1 Flash 1017 | KubeTEE (TEE sibling) only |
| GLM-5.2 | Z.ai API; DeepInfra; Engy; Moonmath ZRO; Chutes (TEE sibling); KubeTEE (TEE sibling) |
| GLM-5.3 | Z.ai API; Engy; DeepInfra; KubeTEE (TEE sibling) |
| GLM-5.3-Flash | Z.ai API; Engy; DeepInfra; KubeTEE (TEE sibling) |
| gpt-oss-20b | DeepInfra only |
| Kimi K3 | Moonshot API; DeepInfra; Engy; Moonmath ZRO; Chutes (TEE sibling); KubeTEE (TEE sibling) |
| Kimi K3.1 Pro | Moonshot API; Engy; KubeTEE (TEE sibling) |
| Qwen3.6 35B A3B | Engy; DeepInfra |
| Qwen3.8 27B | Engy; DeepInfra |
| FLUX.2 klein 4B | DeepInfra (NEAR and KubeTEE "disabled in catalog") |
| MiMo V2.6 Pro Ultraspeed | KubeTEE (TEE sibling) |

- The matrix explains: "Routes marked `TEE sibling` are shared through the catalog's explicit link from a TEE buyer product to its ordinary sibling." — [gm-miner provider-model-support.md](https://github.com/taostat/gm-miner/blob/main/docs/provider-model-support.md)
- The miner README lists provider keys for "Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot, DeepInfra, KubeTEE, Engy, Moonmath, NEAR AI Cloud, or Bedrock/Foundry/Azure transport backends" [earlier notes]. — [taostat/gm-miner](https://github.com/taostat/gm-miner)
- The privacy policy's provider list (2 Oct) omits Engy, Moonmath and NEAR. — [SayGM privacy policy](https://saygm.com/privacy-policy)
- Buyers can name hosts per request (`bedrock`, `azure`, `foundry`, `anthropic`, `openai`, `google`, `kubetee`, `chutes`, `near`, `deepinfra`). — [SayGM docs: routing](https://docs.saygm.com/api/routing/)

**SayGM's miner terms** ("gm miner terms (acceptable use)", last changed 2026-06-19) — [gm-miner miner-terms.md](https://github.com/taostat/gm-miner/blob/main/docs/miner-terms.md)
- "By proceeding you confirm that your provider accounts and API keys permit you to supply capacity through gm, and that doing so does not breach the provider's terms. You are solely responsible for your accounts' compliance; gm is not liable for any action a provider takes against your account."
- "You — not gm — hold the commercial relationship with each provider."
- "Supply only capacity you are authorised to supply under your own provider agreements."
- "gm does not represent that supplying capacity through gm is permitted under any particular provider's terms — that judgement is yours. gm is not a party to your provider agreements and is not liable for a provider suspending, rate-limiting, or closing your account."

**DeepInfra** ("Last modified: October 15th, 2026") — [DeepInfra terms](https://deepinfra.com/terms)
- §11(a), Restrictions on Use: "Customer shall not, and shall not permit or enable any User or other third party to:… (viii) resell, sublicense, rent, distribute, or otherwise make the Services available to any third party except as expressly permitted under this Agreement or the applicable Service Order, or exceed or circumvent any usage limits or quotas set forth in the applicable Service Order, or sell, transfer, or share any account or access credentials."
- "Users" are "all individuals accessing and using the Services under Customer's account". Customer "is solely responsible for its own products, services, and end-user relationships".
- §7(b): "Provider will not sell Customer Data, and will not use Customer Data to train, fine-tune, or otherwise improve any model, except as necessary to provide the Services… Provider will not retain, store, or log any Customer Data submitted to or generated by the Services beyond the period strictly necessary to process and return the applicable request".
- DeepInfra's data page: "We do not log the content of your requests. We log only metadata useful for debugging: request ID, cost, sampling parameters." — [DeepInfra data privacy](https://deepinfra.com/docs/data)

**Moonshot (Kimi OpenPlatform), "Last Updated: July 30th, 2026"** — [Moonshot terms of service](https://platform.moonshot.ai/docs/agreement/modeluse)
- §1: the licence "allows you to use Moonshot AI's application programming interfaces ("APIs") to integrate the Services into your own applications, products, or Services (each referred to as a "Customer Application") and to offer those Customer Applications to End Users."
- "You must not share your account credentials or make your account accessible to others, including not transferring, lending, leasing, or providing it to anyone for use in any form without authorization."
- Prohibited use (9): "buy, sell, or transfer API keys from, to or with a third party."
- §4: "We may use Content to provide, maintain, develop, support, and improve the Services… Customer who requires restrictions on the use of Customer Content for training or improving Moonshot AI models may contact Moonshot AI to discuss available enterprise arrangements or separate written agreements. Unless otherwise expressly agreed in writing, Customer Content may be used for the foregoing purposes." Governing law: Singapore.

**Z.ai (JINGSHENG HENGXING TECHNOLOGY PTE.LTD), "Last Update: April 14, 2026"** — [Z.ai terms of use](https://docs.z.ai/legal-agreement/terms-of-use)
- Scope: the terms govern "access and use of Z.ai for services or tools for your own purposes, internal organizational use, or for the benefit of end users".
- Additional Terms for API Services 1(a): "the right to use Z.ai's API to integrate the Services into your applications or to develop downstream systems, applications or functions to your end users ("End Users")."
- 1(f)(vii) bars "Any exploitation of our intellectual property through use, lease, lending, copying, modification, linking, reposting, compilation, publication, or establishment of mirror sites".
- "No assignment without consent. You cannot transfer, assign, sublicense, or subcontract your rights or obligations under these Terms to anyone else without our prior written consent."
- §3(b): "We will only use End User Content as necessary to provide you with the API Services, comply with applicable law, enforce our policies, and prevent abuse. [We will not use End User Content to develop or improve Services, unless you explicitly agree to such use.]" The brackets are in the original.
- Data protection is under a "Data Processing Addendum for API Services". Arbitration is at SIAC.

**Chutes** [earlier notes] — [Chutes terms](https://chutes.ai/terms)
- §9.1: "You may integrate the Platform into your own products and offer them to your own users".
- §9.3: "You may not resell, white label, or redistribute access to the Platform as a standalone inference service without a separate written agreement with Chutes."
- §3.3: you "may not give any third party, including your own end users, direct access to your API keys".
- §7.3: no training on Content.
- **Chutes' public stance on SN28**: "an SN28 inference router is a Chutes customer and simply pays for what it uses". — [Chutes blog, 2026-10-28](https://chutes.ai/news/chutes-models-are-now-on-saygm)

**engy** [earlier notes]: the terms "contain no clause on resale, sublicensing, white-labelling or serving one's own end users", and engy offers ZDR. — [engy terms](https://engy.ai/terms)

**KubeTEE, Moonmath ZRO, NEAR AI**
- KubeTEE: no terms page was found; only its GitHub README. — [KubeTEE subnet README](https://github.com/KubeTEE-AI/kubetee-subnet)
- Moonmath ZRO: only third-party listings, seen through a search summary and not opened, describe no-retention and no-training claims and EU hosting. Its own terms were not found. — [free-llm.com Zro listing](https://free-llm.com/provider/zro)
- NEAR AI serves only TEE (confidential) products in the matrix. — [gm-miner provider-model-support.md](https://github.com/taostat/gm-miner/blob/main/docs/provider-model-support.md)

### Inferences
- **The resale chain under each upstream:**
  - **DeepInfra:** a miner serving SayGM buyers is "mak[ing] the Services available to any third party", which §11(a)(viii) allows only "as expressly permitted". A SayGM-to-URnetwork-user chain is a further hop.
  - **Moonshot:** a miner's account serving unknown buyers resembles "providing it to anyone for use", unless SayGM's gateway counts as the miner's "Customer Application". That reading is arguable at best.
  - **Z.ai:** the "downstream systems… to your end users" grant is the most permissive. The sublicensing ban and the "lease" or "mirror sites" language still cut against raw API resale.
  - **Chutes:** the clearest case. Its public statement treats SN28 routers as ordinary customers. It covers only Chutes-hosted TEE-sibling routes.
  - This is a contract-risk inference, not legal advice.
- **Training under N4.** On `kimi-k3` and `kimi-k3.1-pro`, a request routed to Moonshot's API can, by default, be used by Moonshot "to… improve the Services".
  - Pinning hosts with `X-GM-Providers` (for example `deepinfra,chutes,kubetee`) would avoid Moonshot. The header is unsigned, though, so URnetwork cannot enforce it on a device it does not trust.
  - A body-blind broker cannot guarantee "no training" for the open tier.
- **Practical upshot.** SayGM's open tier inherits upstream-terms risk that URnetwork cannot audit, because miners are anonymous and records name only makers. That risk is milder than the frontier routes' (Anthropic D.4, OpenAI 3.1 and 3.3(g), Google sublicensing [earlier notes]), but it is not cleared.

### Gaps
- The matrix is a 2026-11-04 snapshot of what miners can declare, not live routing shares. Which hosts actually serve open-tier traffic cannot be read from the public records (`route_id` is not mapped to a host).
- KubeTEE's and Moonmath ZRO's terms, AWS Bedrock, Azure OpenAI and Microsoft Foundry resale terms, and engy's current terms text were not read.

## 6. Reasoning parameters on the OpenAI and Gemini surfaces, and abort and disconnect billing rules

### Takeaway
**Reasoning:**
- Only the **Anthropic** surface documents reasoning pass-through (`thinking`, `output_config.effort`; dropped controls are named in `x-gm-params-dropped`).
- On **Chat Completions**, the schema accepts any extra field (`additionalProperties: true`). Only two catalog models declare `reasoning_efforts`, with aliases.
- **Responses** bodies "match the OpenAI Responses schema".
- **Gemini** bodies are forwarded by miners unchanged.
- No doc states that `reasoning_effort`, `reasoning` or Gemini `thinkingConfig` reach the upstream.
- The catalog now lists 11 Claude models on `chat.completions`. Undocumented headers (`x-gm-surface-translated`, `x-gm-response-losses`) suggest a translation that can lose fields.

**Billing on aborts:**
- A client disconnect is charged in full: the gateway reads the upstream to the end and settles what the provider reports.
- A stream ending in error, timeout or truncation, or before a usage frame, costs nothing.
- A 402 is refused before dispatch, at no charge.
- Videos are charged when complete.

### Cited Findings
**Reasoning**
- Anthropic: "`thinking` and `output_config.effort` pass through unchanged. Which values a model accepts is the model's own rule." "A route drops the controls its provider rejects and names them in the `x-gm-params-dropped` response header." [earlier notes] — [SayGM docs: Anthropic](https://docs.saygm.com/api/anthropic/)
- Messages request schema: "The gateway requires model and messages. Additional provider fields are forwarded unchanged." — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- Chat Completions request schema: `"additionalProperties": true`, listing only `model`, `messages`, `stream`, `temperature` and `max_tokens`. The Responses endpoint: "the request and response bodies match the OpenAI Responses schema". — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- The routing docs mention Responses follow-ups carrying "`previous_response_id` or encrypted reasoning" that belong to one provider. — [SayGM docs: routing](https://docs.saygm.com/api/routing/)
- Catalog fields: `reasoning_efforts` ("Reasoning effort values supported by this model") and `reasoning_effort_aliases` ("Accepted reasoning effort aliases and their native values"). Only 2 of 74 entries carry them: `glm-5.3-flash` and its `-tee`, with `["low","high","max"]`; the earlier notes record aliases medium→low, minimal→low, xhigh→max. — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json); [api.saygm.com/v1/models](https://api.saygm.com/v1/models?include_unavailable=true) [earlier notes]
- The OpenAI and Gemini docs pages ("Last updated: Oct 29, 2026") do not mention reasoning. — [SayGM docs: OpenAI](https://docs.saygm.com/api/openai/); [SayGM docs: Gemini](https://docs.saygm.com/api/gemini/)
- SayGM's blog line that "Gemini's reasoning controls map onto OpenAI's `reasoning_effort` parameter" describes **Google's own** OpenAI-compatible shim (`generativelanguage.googleapis.com/v1beta/openai/`), not SayGM. — [SayGM blog: Claude, GPT and Gemini via one OpenAI-compatible API](https://saygm.com/blog/claude-gpt-and-gemini-via-one-openai-compatible-api)
- Miner side:
  - "Azure OpenAI chat completions and Microsoft Foundry Messages forward request bodies unchanged through Envoy."
  - The Bedrock adapter "rewrites only `model` and leaves every other body field and content block to Bedrock's validation".
  - For Gemini, "Envoy forwards that path and body unchanged to Google's Gemini API".

  — [gm-miner provider-model-support.md](https://github.com/taostat/gm-miner/blob/main/docs/provider-model-support.md)
- The Codex integration uses `wire_api = "responses"`. Its troubleshooting entry: "Tools or reasoning behave oddly on a model. Codex tunes itself from its own list of OpenAI model ids. Use a real OpenAI id such as gpt-6-luna." — [SayGM Codex integration](https://saygm.com/integrations/codex)
- [live call] The catalog lists 11 of 12 Anthropic models with `api_shapes: ["messages","chat.completions"]`, and every response exposes `x-gm-surface-translated` and `x-gm-response-losses`. Neither header appears in either OpenAPI or the docs pages. llms.txt still says "Claude uses `/v1/messages`". — [api.saygm.com/v1/models](https://api.saygm.com/v1/models?include_unavailable=true); [SayGM llms.txt](https://saygm.com/llms.txt)

**Abort, disconnect and failure billing**
- Disconnect: "If you disconnect during a stream, the gateway stops forwarding frames and keeps reading the upstream to the end, then settles the usage the provider reports, including output generated after you left and any surcharge. The usage frame is what gets charged: a stream that ends before one arrives costs nothing." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- Failed streams: "A stream that ends in an error, timeout, or truncation bills zero and carries no cost fields; on the Anthropic surface, message_delta itself is withheld after a provider error terminal." "If the connection breaks after output has started, retrying may create a second billable request." — [SayGM docs: streaming](https://docs.saygm.com/api/streaming/)
- Where cost arrives in a stream: on Chat Completions "a final chunk with "choices": [] carries the cumulative usage plus the cost fields, delivered ahead of data: [DONE] for every request, whether or not stream_options.include_usage was set". On Responses, in `response.completed` or `response.incomplete`. — [SayGM docs: streaming](https://docs.saygm.com/api/streaming/)
- 402 admission: the request "stops there with HTTP 402, before anything is sent upstream, and the balance is untouched". For btauth: "No work is done." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/); [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- Retries: the gateway "retries upstream 429 and 500–599 responses on another route within the request's attempt and time budgets"; 504 is "Upstream timeout | Yes, but account for possible prior processing"; "Avoid automatic retries after a streaming response has emitted content." — [SayGM docs: errors](https://docs.saygm.com/api/errors/)
- Video "per second requested, charged when the video completes". — [SayGM llms.txt](https://saygm.com/llms.txt)

### Inferences
- **For a canonical reasoning map:**
  - On Messages, treat `thinking` and `output_config.effort` as supported, and watch `x-gm-params-dropped`.
  - On Chat Completions and Responses for GPT models, `reasoning_effort` and `reasoning.effort` very probably reach OpenAI or Azure unchanged (schema pass-through plus unchanged forwarding at the miner), but this is undocumented.
  - For `glm-5.3-flash`, use the declared aliases.
  - For Claude on `chat.completions`, which is translated, assume reasoning controls may be lost, and check `x-gm-response-losses`.
- **Aborts favour SayGM, not the user.** A user who stops a long generation is still charged for all of it, and the cost frame never reaches the device. URnetwork must bill aborted streams from the public record or from `/balance` deltas, not from the device.

### Gaps
- Whether the gateway forwards, maps or drops `reasoning_effort` and `reasoning` for each OpenAI model and for open models other than GLM-5.3-Flash, and whether it forwards Gemini `thinkingConfig`, could not be tested without signed calls.
- What `x-gm-surface-translated` and `x-gm-response-losses` contain is undocumented.
