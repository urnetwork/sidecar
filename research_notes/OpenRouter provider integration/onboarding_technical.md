# OpenRouter provider onboarding and the provider–OpenRouter technical contract (as of 2026-11-24)

*Method: OpenRouter's docs were read on 2026-11-24 through the docs' own `llms.txt` / `llms-full.txt` dump and the per-page `.md` files. The full dump (7.4 MB) was grepped for terms such as egress, IP, TEE, attestation and enclave. Public catalog APIs were queried with unauthenticated GETs only: no sign-up, no API key, no paid call. OpenRouter doc pages carry no publication dates. Where a page states a date, it is quoted. Items marked "(search summary)" come from a web-search result digest and were not fetched page by page; treat them as unverified.*

---

## 1. Applying: is there a provider program, a form, a contract, a minimum scale or a review, and how long does it take?

### Takeaway
There is a formal, selective provider program. It runs in five steps: a 15-minute online application, a scored review, a mutual-NDA intro call, a security questionnaire with online acceptance of provider terms, and a joint go-live with test traffic. Before OpenRouter will review an application, the provider must invoice OpenRouter monthly and publish a data policy. No minimum scale and no timeline are published. OpenRouter says it has "a large backlog", reviews providers with proprietary models first, and favours providers that "fill gaps in our network". A second-hand report says it accepts about one of roughly 40 applications a day.

### Cited Findings
- **Entry point.** The docs say: "If you'd like to be a model provider and sell inference on OpenRouter, fill out our form", linking `openrouter.ai/how-to-list` — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration). On 2026-11-24 that link redirected to an application form titled "Apply — Become a Provider" at `openrouter.ai/providers/apply/form`. The form renders in client-side JavaScript, so its fields could not be read without loading the app — [Apply form](https://openrouter.ai/providers/apply/form).
- **Landing page, "Serve your models on OpenRouter".**
  - It claims "10M+ developers" and says requests are routed "across 80+ providers by performance and price".
  - "Apply once, then track review, onboarding and setup in one place", with a "Check your status" link for applicants.
  - "We're working through a large backlog of applications, and we review providers with proprietary models first."
  - "We give priority to providers that fill gaps in our network. We can't accept every provider."
  - Source: [Become a Provider](https://openrouter.ai/providers/apply).
- **The five steps**, all from [Become a Provider](https://openrouter.ai/providers/apply):
  1. **Apply.** "About 15 minutes. Tell us about your infrastructure, endpoints, models and data policies."
  2. **Review.** "We score your API compatibility, endpoint reliability, pricing and performance. We decide on a rolling basis."
  3. **Intro call.** "We sign a mutual NDA, then meet on a call."
  4. **Security and terms.** "You answer the security questionnaire, upload your security documents and accept the provider terms online."
  5. **Go live.** "We set up the integration together and send test traffic to check latency, throughput and error handling. Then you're live."
- **Prerequisites before review.** The page says: "If you don't meet them yet, we can't review your application." Source for all items: [Become a Provider](https://openrouter.ai/providers/apply).
  - **An OpenAI-compatible API.** "Your /chat/completions endpoint supports streaming and returns usage tokens for both stream and non-stream requests."
  - **A models endpoint.** "Your /models endpoint lists each model with its pricing, context length, max output tokens, supported features and datacenter locations."
  - **Monthly invoicing to OpenRouter, marked "Required".** "You invoice OpenRouter monthly for inference. We don't onboard providers on other payment terms."
  - **A published privacy and data policy.** It must say "whether you log prompts, how long you keep data, and whether you train on it."
  - **A work email on the company domain.** Gmail and Outlook addresses are not accepted.
  - "SOC 2 and zero data retention help, but neither is required."
- **Payment terms conflict.** The docs, §9, say: "For OpenRouter to use the provider we must be able to pay for inference automatically. This can be done via auto top up or invoicing" — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration). The newer, stricter landing page requires monthly invoicing only. It also says: "You set your own per-token pricing in USD. OpenRouter pays you for inference based on actual token usage through monthly invoicing… We reconcile token counts automatically" — [Become a Provider](https://openrouter.ai/providers/apply).
- **Contact.** The landing page FAQ gives a provider contact email, but it is hidden behind Cloudflare email obfuscation — [Become a Provider](https://openrouter.ai/providers/apply). A third-party guide names it as `providers@openrouter.ai` — [Dylan Vu, "How to get listed on OpenRouter as an inference provider", Aug 21 2026](https://dylanvu.substack.com/p/how-to-get-listed-on-openrouter-as).
- **Application volume and acceptance (second-hand).**
  - The guide reports remarks from an OpenRouter event on Aug 20, 2026: "about 40 provider applications each day and accepts about one."
  - The same remarks called legal review "the current bottleneck."
  - The author labels these as event remarks, not published data.
  - The guide names Shashank Goyal (provider ecosystem) and Tomas Oliva (operations and devrel) as OpenRouter contacts. Those roles are unverified.
  - Source: [Dylan Vu, Aug 21 2026](https://dylanvu.substack.com/p/how-to-get-listed-on-openrouter-as).
- **The guide's advice** (the author's own synthesis, not OpenRouter policy):
  - Don't apply before the endpoint is callable.
  - Launch with a reproducible benchmark and a public performance dashboard.
  - Give OpenRouter a separate test key.
  - Return fast 429s rather than queueing.
  - Confirm that the model license allows serving.
  - Prepare legal materials: business identity, right to serve the model, data handling and contract terms.
  - Source: [Dylan Vu](https://dylanvu.substack.com/p/how-to-get-listed-on-openrouter-as).
- **Launch gating in the docs.** A matched model entry is staged hidden and put through baseline tests. It is unhidden automatically only when all of these hold:
  - every test passes;
  - pricing is present and non-zero (unless the entry is `is_free`);
  - `is_ready` is not `false`;
  - "you already have a launched endpoint on OpenRouter (and a launched paid endpoint, for a paid entry)";
  - the endpoint serves chat completions.

  Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Provider dashboard access.** "Once onboarded, our team can give you access to it." — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Size of the field.** On 2026-11-24, `GET /api/v1/providers` returned 124 provider records, including `chutes`, `phala`, `near-ai` and `venice` — [OpenRouter providers API](https://openrouter.ai/api/v1/providers). `GET /api/v1/models` returned 470 models — [OpenRouter models API](https://openrouter.ai/api/v1/models). The landing page says "80+ providers", which does not match the 124 records.

### Inferences
- **Timeline.** Nothing is published. The backlog, roughly 1-in-40 acceptance, the NDA, the security questionnaire and a "legal review bottleneck" together suggest months rather than weeks. This is an inference, not a published figure.
- **Fit with OpenRouter's priorities.** URnetwork would bring open-weight models on another provider's GPUs (Chutes, on Bittensor). That is not "proprietary models". Chutes, Phala and Near AI are already listed providers (see §6), so "TEE inference exists on OpenRouter" is not, on its face, a gap. The pitch would have to name a concrete gap, such as models or capabilities no TEE provider serves today, or a privacy guarantee no current endpoint offers. Also, if URnetwork resells Chutes capacity, it would sit on the same model pages as its own upstream, which is already a provider. (Inference.)
- **First endpoint.** Auto-unhide requires an already-launched endpoint. A brand-new provider's first endpoint therefore has to be launched by OpenRouter staff during the go-live step. (Inference from the gating rule.)
- **Working capital.** Monthly invoicing means URnetwork extends credit to OpenRouter for a month of usage plus payment terms, which were not found. Meanwhile its upstream, Chutes or Bittensor providers, may be prepaid. (Inference.)
- **Build-and-agree checklist** (inference that consolidates §§1–8):
  - **Build:**
    - A public HTTPS, OpenAI-compatible `POST /chat/completions`, both streaming (SSE) and non-streaming, returning `usage` in both modes.
    - Well-formed tool calls.
    - SSE comment keep-alives during long time to first token (TTFT).
    - Fast 429s at capacity, with no queueing.
    - An `x-request-id` header on responses.
    - The served model id echoed back.
    - A strict v2.x `/v1/models` feed: ids, Hugging Face ids, quantization, context and output limits, USD string prices, prompt tokens-per-minute (TPM) capacity, datacenters, and `is_ready` for staged launches.
    - A provider-issued API key for OpenRouter.
    - Monthly invoicing.
    - Published ToS, privacy and data-policy pages, and a status page.
    - Security documents.
  - **Agree to:**
    - A mutual NDA.
    - The online provider terms, whose content is not public.
    - Monthly invoicing only.
    - Public per-endpoint TTFT, throughput and uptime metrics.
    - Automated routing that can starve or pause endpoints.
    - OpenRouter's data-policy classification of the endpoints.
    - OpenRouter's in-flight plaintext processing, including CSAM screening (see §6).

### Gaps
- The application form's fields, the provider terms, the security questionnaire's content, and OpenRouter's invoice payment terms (net days) are not public.
- No minimum scale, capacity or traffic threshold is published.
- No published time from application to go-live.
- No provider-side commission or revenue share is documented. Providers set USD prices and invoice OpenRouter, and OpenRouter's user-side fees were not researched here.
- The 1-in-40 acceptance figure is second-hand only.

---

## 2. The endpoint: which API, and what streaming, tool calling, structured outputs, logprobs, reasoning tokens and usage reporting require

### Takeaway
The required surface is one OpenAI-compatible `POST /chat/completions` with SSE streaming, returning `usage` token counts on both streaming and non-streaming requests. OpenRouter itself exposes Chat Completions, Responses (and a Messages API) to users and normalizes between them; providers are not asked for `/responses` or `/completions`. Advanced capabilities are never switched on by declaration: tools, tool_choice, response_format and structured outputs, logprobs and the rest of the "capability suite" turn on only when OpenRouter's automated capability tests pass against the live endpoint.

### Cited Findings
- **API format.** "Your API must be OpenAI-compatible, supporting /chat/completions with streaming. You must return usage (token counts) for both stream and non-stream requests." — [Become a Provider FAQ](https://openrouter.ai/providers/apply).
- **Model id.** "The `id` field should be the exact model identifier that OpenRouter will use when calling your API." — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Chat completions only for auto-launch.** Auto-unhide requires that "the endpoint serves chat completions". Embeddings, reranking, decisions, speech-to-text, text-to-speech, and image or video generation endpoints stay hidden after a passing run until staff unhide them — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Capabilities come only from tests.**
  - The docs say: "parameters OpenRouter verifies by test (`tools`, `tool_choice`, `response_format`, `structured_outputs`, `logprobs`, and the rest of the capability suite) are never enabled from the feed, only by the capability tests passing."
  - Plain sampling parameters are applied from the feed.
  - The legacy `supported_features` list "is parsed and ignored: OpenRouter discovers testable capabilities by running capability tests against the endpoint."
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
  - **Conflict:** the landing-page FAQ says "You declare which features you support (tools, structured outputs, JSON mode, etc.) in your /models endpoint" — [Become a Provider](https://openrouter.ai/providers/apply). The integration doc is more detailed and specific, and appears to be the operative rule.
- **Legacy vocabulary**, which still shows the parameter universe:
  - Sampling parameters: temperature, top_p, top_k, min_p, top_a, frequency_penalty, presence_penalty, repetition_penalty, stop, seed, max_tokens, logit_bias.
  - Features: tools, json_mode, structured_outputs, logprobs, web_search, reasoning.
  - Source: [Provider Integration (Legacy Format)](https://openrouter.ai/docs/guides/providers/integration-legacy).
- **Current (v2.4) parameter format.**
  - `output_modalities[text].supported_parameters` is a map of typed descriptors: `range`, `integer`, `boolean`, `enum`, `array`, `object` or `unknown`.
  - An absent key means the parameter is unsupported.
  - The docs' example: `temperature` range 0–1, `max_tokens` integer up to 128000, `stop` array with `max_items` 4, and `tools`, `structured_outputs` and `reasoning` as booleans.
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Turning capabilities on and off.** Providers can switch capabilities off with `POST /api/v1/providers/{slug}/endpoints/{id}/capabilities/disable`. Turning them back on "runs the capability tests first, so it is only available from the provider dashboard." — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **What a live endpoint advertises.** Live example, fetched 2026-11-24: Z.AI's `glm-5.3-flashx-legal` endpoint lists `supported_parameters` of reasoning, include_reasoning, max_tokens, temperature, top_p, tools, tool_choice, top_k, response_format, structured_outputs and reasoning_effort. It also lists `supports_tool_choice` as `{none:false, auto:true, required:false, function:false}` — [endpoints API](https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flashx-legal/endpoints).
- **Reasoning tokens.** Reasoning tokens are a billable output SKU, pricing type `internal_reasoning` with unit token — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Streaming behaviour.**
  - "Stream tokens as soon as they're available."
  - "If processing takes time (e.g. reasoning models), send SSE comments as keep-alives so we know you're still working on the request. Otherwise we may cancel with a fetch timeout and fallback to another provider."
  - Source: [Provider Integration §11](https://openrouter.ai/docs/guides/providers/integration).
  - Toward its own clients, OpenRouter sends `: OPENROUTER PROCESSING` SSE comments. If a backend provider fails mid-stream after `200 OK`, OpenRouter emits an error chunk before ending the stream — [OpenAI Compatibility](https://openrouter.ai/docs/guides/features/compatibility).
- **Failures that count against uptime** include "Mid-stream errors" and "Successful requests with error finish reasons" — [Provider Integration §10](https://openrouter.ai/docs/guides/providers/integration).
- **Usage and billing reconciliation.** OpenRouter pays on "actual token usage" and says "We reconcile token counts automatically" — [Become a Provider](https://openrouter.ai/providers/apply). OpenRouter's accounting can fall back to estimated prompt or completion quantities, flagged as `usage_is_estimated`, "after a usage-calculation failure" — [Broadcast docs](https://openrouter.ai/docs/guides/features/broadcast).
- **A documented parallel check list.** OpenRouter's validation of enterprise private endpoints checks that "the key is accepted, the response is OpenAI-compatible, streaming works, usage fields come back, and the served model ID matches what you entered" — [Private Endpoints](https://openrouter.ai/docs/guides/routing/private-endpoints).
- **Service tiers on one id (Option 2).** If one model id carries several tiers, the provider's API must take a `service_tier` request parameter and echo the served tier as a top-level `service_tier` field in the response. A tier endpoint is unhidden only once a baseline request "comes back echoing that same tier." The alternative is suffixed ids: `-fast`, `-turbo` or `-prime` for priority, and `-flex` for flex — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Batch endpoints.** A batch endpoint is a second document with `"variant": "batch"`, but "Batch endpoints need setup on OpenRouter's side." Capability tests on a batch endpoint run as one batch job, can take up to 6 h, and are limited to one run at a time per endpoint, 3 per endpoint and 20 per provider in any 24 hours — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Request ids.** Abuse reports identify calls by "the `x-request-id` (or `request-id`) values your endpoint returned to OpenRouter" — [Provider Integration §13](https://openrouter.ai/docs/guides/providers/integration).
- **What users call.** OpenRouter supports two request shapes, the Responses API (`POST /api/v1/responses`) and Chat Completions. Its schemas are "very similar to OpenAI's APIs" and OpenRouter "normalizes the schema" — [API Reference overview](https://openrouter.ai/docs/api_reference/overview).

### Inferences
- **No other APIs needed.** A provider need not implement `/responses`, `/completions` or Anthropic Messages. OpenRouter translates user-facing shapes onto the provider's chat completions. (Inference from the requirement naming only `/chat/completions`, and from the "normalizes the schema" statement.)
- **Tests set the wire format.** Pass or fail is decided empirically, so the exact wire conventions OpenRouter expects are effectively defined by its baseline and capability tests. Examples: the field carrying reasoning text, the shape of tool-call streaming deltas, logprobs layout, and usage in the final stream chunk. Mirroring OpenAI and vLLM conventions is the safe default. (Inference.)
- **Requests may take long.** A TEE stack with slow cold starts or long prefill should emit SSE comment keep-alives. Otherwise OpenRouter's fetch timeout cancels the request, falls back to another provider, and the failure probably counts against reliability. (Inference.)
- **The served-model-id check** implies the response `model` field should equal the requested `id`. (Inference.)

### Gaps
- The baseline and capability test suites are not published.
- The capabilities enum lives only in the authenticated `GET /api/v1/providers/{slug}/openapi`.
- The fetch-timeout value is not published.
- There is no documented list of the headers OpenRouter sends to providers. The only one documented is a hashed user id, sent to providers whose data policy requires it.
- No documented requirement for where reasoning text goes (for example `reasoning` vs `reasoning_content`).

---

## 3. Model metadata: what a provider declares per model, and how models are named and matched to OpenRouter's model ids

### Takeaway
Providers publish a strict JSON model feed, "current format", `schema_version` 2.x, documented as 2.4, with an OpenAPI 3.1 schema. OpenRouter's "provider monitor" polls it. The feed declares:
- id and Hugging Face id;
- quantization;
- typed input and output modalities carrying context and output limits, supported parameters, USD-string pricing, capacity and passthrough parameters;
- datacenters and region;
- operational flags.

Each entry attaches to OpenRouter's shared model page. It is matched by Hugging Face id first, then by a declared `openrouter.slug`, then by slug name. OpenRouter owns model names and descriptions after staging.

### Cited Findings
- **Required identity fields.** `id`, `name`, `hugging_face_id` ("required if the model is on Hugging Face"), `created`, `quantization` (or null), an optional `tokenizer`, and `description` — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Quantization enum.** `int4`, `int8`, `fp4`, `mxfp4`, `nvfp4`, `fp6`, `fp8`, `mxfp8`, `fp16`, `bf16`, `fp32`. Use `null` when undeclared — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Context and output limits.**
  - Text input `supported_inputs.max_context_length` is "the total context window: input and output tokens combined".
  - `max_prompt_length` is "the maximum input length alone", declared only when it differs.
  - Text output `max_length` becomes the endpoint's maximum completion length.
  - All three are "Applied", meaning written to the endpoint on every poll, unless staff set them manually. Non-token units are ignored with a warning.
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Pricing.**
  - Every `cost_usd` is a USD string, "to avoid floating point precision issues".
  - Input SKUs: `prompt`, `cached_prompt`, `cache_write` (qualified by `ttl_seconds` and `implicit`).
  - Output SKUs: `completion`, `internal_reasoning`.
  - Root SKUs: `request`, `web_search`.
  - "Do not zero-stuff prices."
  - Conditional pricing is billed only in two shapes: long-context tiers (`prompt_tokens.gte`, at most 2 tiers) and time-of-day windows (at most 2). Both are billed only under the `openai_extended` (and, for windows, `alibaba`) billing strategies. Other declared shapes are accepted but produce `unsupported_override` warnings and fall back to base prices.
  - "Your base pricing must be your cheapest (off-peak) rate."
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Price changes.** A change to an already-priced entry, or a first price for an unpriced endpoint, "apply automatically". Other new or removed pricing entries wait for staff review — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Operational fields**, from [Provider Integration](https://openrouter.ai/docs/guides/providers/integration):
  - `deprecation_date`: a date, which defaults to 13:00 UTC, or a UTC hour. Endpoints are hidden once it is reached.
  - `is_ready`: `false` keeps an endpoint staged but hidden, or hides a live one.
  - `is_free`: creates a `:free` variant, and any pricing sent with it is ignored.
  - `service_tier`.
  - `variant: "batch"`.
  - `discount_to_user`: user price = base × (1 − d). A negative value is a markup, and a value of 1 or more fails validation.
  - `openrouter.slug`.
- **Datacenters and region.**
  - `datacenters[]` takes an ISO-3166 alpha-2 `country_code` and an optional `region`, plus an optional `deployment_region` field.
  - For providers that OpenRouter routes to "a dedicated in-region host", these fields pin new endpoints to a region.
  - "For every other provider both fields are **detection-only**."
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Field statuses.** Each field is Applied, Reviewed, Detection-only, Staging-only or Ignored. Notable examples:
  - `name`, `created` and `tokenizer` are Ignored. "Model names come from OpenRouter's catalog."
  - `description` and `hugging_face_id` are Staging-only, read once when OpenRouter creates the model record.
  - Modality *types* on an existing endpoint are Detection-only.
  - `passthrough_parameters` changes are Reviewed.
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Strict schema.**
  - "Any other key the schema does not know… rejects the whole document."
  - The `compliance` root field was "Retired 2026-09-30" and is now accepted but ignored.
  - "The schema only gains optional fields," and any `2.x` `schema_version` is accepted.
  - Schema download: [provider-monitor-schema-v2.openapi.json](https://openrouter.ai/docs/assets/provider-monitor-schema-v2.openapi.json). Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Matching a new entry to an OpenRouter model:**
  1. **Hugging Face match**, which is authoritative. A single match auto-stages; several matches are held for manual review.
  2. **Declared `openrouter.slug` match.** This never attaches the entry to a model that has a Hugging Face id. Declared slugs for anthropic, google, openai and x-ai models are held for review.
  3. **Slug-name match**, for models without a Hugging Face id. The id must be namespaced `author/name` with a matching author.
  4. **No match.** "Nothing is staged until [staff] create or attach a model."

  Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Tooling.** The **Schema validator** tab at `https://openrouter.ai/provider/{provider_slug}/dashboard` reports warnings and rejected documents. A **Generate feed** panel builds a current-format document from the endpoints OpenRouter already serves for the provider. The legacy flat format (`context_length`, `max_output_length`, flat `pricing`, and so on) "remains supported" and has no end-of-support date — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration); [Legacy format](https://openrouter.ai/docs/guides/providers/integration-legacy).
- **Shared model pages in practice.** On 2026-11-24, `z-ai/glm-5.3` listed 47 provider endpoints, and `z-ai/glm-5.3-flash` listed 42. Tags are formed as `provider[/quantization][/region][/tier]`, for example `deepinfra/fp4/flex`, `parasail/fast`, `wafer/us`, `mistral/zdr`, `mistral/nvfp4/eu` and `near-ai/fp8` — [endpoints API, glm-5.3](https://openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints); [endpoints API, glm-5.3-flash](https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flash/endpoints).
- **Automatic hiding.** OpenRouter hides an endpoint when:
  - its id disappears from the feed;
  - `is_ready` is `false`;
  - its deprecation date is reached;
  - it received "a meaningful amount of traffic for seven days without a single successful completion and without any rate-limit (429) responses";
  - a surge of authentication, payment or not-found errors is followed by a health check that "fails deterministically".

  "An endpoint that stays hidden for 30 days is deleted." — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).

### Inferences
- **No way to mark an endpoint as TEE-attested.**
  - An attested-TEE deployment of an open-weight model would attach, through its Hugging Face id, to the same shared page as every other provider's copy. It would show as one more tag, such as `urnetwork/fp8`.
  - The feed has no field to declare "TEE/attested".
  - Id suffixes are reserved for service tiers (`-fast`, `-turbo`, `-prime`, `-flex`).
  - So nothing in OpenRouter's catalog would distinguish a TEE endpoint from a non-TEE one. (Inference from the schema and the endpoint field list in §7.)
- **Data policy is not self-declared.** The `compliance` field was retired on 2026-09-30, and the feed has no data-policy field. An endpoint's ZDR or retention classification is therefore set by OpenRouter from the provider's terms and agreements, not from the feed (see §6). (Inference.)

### Gaps
- No published rule for how OpenRouter picks the displayed endpoint tag. It looks derived from provider slug, quantization, region and tier.
- No published turnaround for "Reviewed" feed changes.

---

## 4. Uptime and routing: what OpenRouter expects and measures, how it picks among providers, and how a provider gets deprioritized or delisted

### Takeaway
- **Uptime.** Uptime is successful requests ÷ total requests, excluding user errors, and is counted only after 100 or more requests. At 95% or above routing is normal; at 80–94% the endpoint gets lower priority; below 80% it is used only as a fallback.
- **Default routing.** This is a stochastic, share-based allocation over an "adjusted price". The adjusted price combines effective (cache-adjusted, 30-minute) price, end-to-end tokens per second (TPS), TTFT, reliability errors, tool-call quality and 429s.
  - Endpoints inside a "competitive edge" get most of the traffic.
  - Endpoints outside it get small "exploration" shares.
  - A "breaker" pauses outliers, and short-term backoff answers 429 bursts.
- **Tool-calling requests** are further reordered by Auto Exacto, using throughput, tool-call success and benchmark accuracy.
- **Users can bypass all of this** with `sort`, `order`, `only`/`ignore`, `:nitro`/`:floor`, or BYOK.

### Cited Findings
- **Uptime formula and thresholds.** "successful requests ÷ total requests (excluding user errors)". Minimum data is 100 or more requests. "Normal routing: 95%+ uptime; Degraded status: 80-94% uptime → receives lower priority; Down status: <80% uptime → only used as fallback." — [Provider Integration §10](https://openrouter.ai/docs/guides/providers/integration). The landing page repeats: "Stay at 95% uptime or higher to keep standard routing priority." — [Become a Provider](https://openrouter.ai/providers/apply).
- **Errors that count against uptime:**
  - 401 (authentication issues) and 402 (payment failures);
  - 404 (model not found);
  - other setup errors: 405, 408, 410, 421, 423, 424, 426, 498;
  - all 5xx responses;
  - mid-stream errors;
  - successful requests that end with error finish reasons.

  **Errors that don't count:** 400, 413, 429 (tracked separately) and 403 geo-blocks (tracked separately). Source: [Provider Integration §10](https://openrouter.ai/docs/guides/providers/integration). The routing doc's reliability list adds "No response: dropped connections, timeouts" as counting, and 422, 451 and 499 (user disconnects) as not counting — [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **Public performance metrics.** OpenRouter "publicly tracks TTFT (time to first token) and throughput (tokens/second) for all providers on each model page". Throughput is "output tokens ÷ generation time". Generation time includes fetch latency, TTFT and streaming time, so "any queueing on your end will show up in your throughput metrics." — [Provider Integration §11](https://openrouter.ai/docs/guides/providers/integration). The public endpoint records expose `uptime_last_5m`, `uptime_last_30m`, `uptime_last_1d`, `latency_last_30m` and `throughput_last_30m` — [endpoints API](https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flashx-legal/endpoints).
- **Inputs to default routing:** "Effective price" (the price actually charged over the last 30 minutes, reflecting real cache hit rate and token mix), TTFT, "Reliability & quality", 429s, and "Speed: end-to-end TPS".
  - "A faster endpoint can cost more and still win traffic."
  - Example given: "a 1% error rate times an 8× penalty per error raises adjusted price by about 8%."
  - Example given: "95% of tool calls well formed raises adjusted price by about 5%."
  - Source: [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **Shares and the competitive edge.**
  - "Competitive: endpoints inside the edge get the most traffic… Exploration: past the edge, your share drops off fast. Every endpoint still gets a small amount of traffic no matter what."
  - "Each request picks an endpoint at random, weighted by these shares. If it fails, the retry is picked the same way from the endpoints that are left."
  - **Breaker:** "If a degradation signal like reliability, quality or 429s is far worse than your peers', routing pauses your traffic until it recovers."
  - "An endpoint with little traffic starts out looking like a typical peer and moves toward its own numbers as data comes in."
  - "The last few minutes count the most."
  - Source: [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **Other routing rules.**
  - "Follow-up requests in a conversation stay with the same provider while its prompt cache is warm."
  - "Routing learns how much load each provider can take before it returns 429s, and sends the rest to other providers."
  - Requests that include tools or `tool_choice` get "best effort" routing to tool-capable providers. When `max_tokens` is set, only providers that support that length are used.
  - Source: [Provider Routing](https://openrouter.ai/docs/guides/routing/provider-selection).
- **When default routing is bypassed.** A user sets a provider `order` or an allow/ignore list that leaves one provider, brings their own key, or sorts by price, throughput or latency — [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing). Default routing is also bypassed by the `:floor` and `:nitro` shortcuts; when `only`/`ignore` leave two or more providers, default routing picks among them — [Provider Routing](https://openrouter.ai/docs/guides/routing/provider-selection).
- **User-side `provider` controls:** `order`, `allow_fallbacks`, `zdr`, `enforce_distillable_text`, `only`, `ignore`, `require_parameters`, `data_collection` ("allow"/"deny"), `quantizations`, and `sort` (price, throughput or latency, with `partition` set to `model` or `none`).
  - `preferred_min_throughput` and `preferred_max_latency` can be set per percentile (p50, p75, p90 or p99). They are preferences, not guarantees.
  - `max_price`.
  - `:nitro` makes priority-tier endpoints eligible; `:floor` makes flex-tier endpoints eligible.
  - Source: [Provider Routing](https://openrouter.ai/docs/guides/routing/provider-selection).
- **Auto Exacto** runs "by default on every tool-calling request". Its signals are:
  - throughput, cut off at more than 1.5σ below the peer median;
  - tool-calling success rate, cut off at more than 2σ below the median, using median + MAD;
  - benchmark accuracy, cut off at the median − 2σ of roughly the first 21 days of benchmarking for that model. "An endpoint scoring below the cutoff, or missing benchmark data entirely, is deprioritized."

  Thresholds apply only with at least 4 providers or endpoints. Endpoints fall into three tiers: Good, Insufficient data (which needs 100 general requests in 30 minutes and 200 tool-call requests in 2 hours), and Deprioritized. Source: [Provider Integration §12](https://openrouter.ai/docs/guides/providers/integration). An endpoint "flagged for broken tool calls, or for benchmark accuracy well below what the model should score, falls far behind and gets exploration traffic only until the flag clears" — [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **Delisting** follows the automatic-hiding rules in §3. Hidden endpoints are deleted after 30 days. Unhiding from the dashboard re-runs the baseline tests — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).

### Inferences
- **TEE overhead costs traffic.**
  - Confidential-computing overhead (TDX plus GPU confidential compute, encrypted bounce buffers) and Bittensor-miner variability would show up directly in OpenRouter's end-to-end TPS, TTFT and reliability measures.
  - Routing has no input that rewards attestation or privacy.
  - A TEE endpoint priced at or above non-TEE peers would therefore probably sit outside the competitive edge for default traffic.
  - Its volume would come mainly from users who pin it (`only`/`order`) or filter for ZDR, assuming OpenRouter classifies it as ZDR.

  (Inference.)
- **Upstream failures land on URnetwork.** Failures in an upstream URnetwork does not control, such as Chutes miners, would count as URnetwork's errors and could trip the breaker. (Inference.)
- **Benchmark-window timing.** A late entrant to a model's 21-day benchmark window inherits a fixed cutoff, and missing benchmark data means deprioritization for tool-calling traffic. (Inference from §12's rules.)

### Gaps
- The exact share function, the competitive-edge formula, the breaker thresholds and the fetch timeout are not published.
- No numeric latency or throughput floor exists, only relative-to-peer rules.

---

## 5. Rate limits and capacity: how capacity, rate limits, 429s and errors are signalled and handled

### Takeaway
Capacity declared in the feed is mostly not enforced. Only text-input prompt tokens-per-minute is stored, and routing does not read it. The contract is: return a 429 early when overloaded, rather than queueing. 429s do not hurt uptime, but they add an adjusted-price penalty; bursts trigger short-term backoff and outliers trip the breaker. Providers can also set OpenRouter-enforced requests-per-minute and requests-per-day caps per endpoint through the Provider API.

### Cited Findings
- **Declared capacity is mostly ignored.**
  - "OpenRouter does not enforce declared capacity yet. Only the text input `type: prompt`, `unit: token`, `per: minute` entry is applied, routing does not read it, and every other entry is ignored with validator warning `unsupported_capacity_entry`."
  - "Return `429` when you are overloaded or over a rate limit: routing backs off and shifts traffic as your 429s come in."
  - Source: [Provider Integration §4](https://openrouter.ai/docs/guides/providers/integration).
- **The declaration grammar exists anyway.** Capacity entries take `type`, `unit`, `per` (minute, hour or day) and `value`, plus `concurrency`. "An absent `capacity` array means the limit is undeclared, not zero." — [Provider Integration §4](https://openrouter.ai/docs/guides/providers/integration).
- **Return 429s early.** "Return early 429s if under load, rather than queueing requests." If one account is abusing the endpoint, "report it so OpenRouter can act on the account instead of your endpoint rate limiting everyone" — [Provider Integration §11](https://openrouter.ai/docs/guides/providers/integration).
- **How 429s are penalized.**
  - Routing charges each 429 "that wait plus a penalty, weighted by how often you return 429s". Example: "a $2.50 wait plus penalty times a 0.4% 429 rate adds $0.01 to adjusted price".
  - "A burst of them triggers short-term backoff, and a rate far above your peers' trips the breaker."
  - Source: [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **Side effect on evaluation.** "Consistent rate limiting (429s) can reduce the volume of successful requests available for evaluation" for Auto Exacto benchmarking — [Provider Integration §12](https://openrouter.ai/docs/guides/providers/integration).
- **Provider-set caps.** `PATCH /api/v1/providers/{provider_slug}/endpoints/{endpoint_id}/limits` with `limit_rpm` and `limit_rpd` "sets the requests-per-minute and requests-per-day caps OpenRouter enforces before routing to one of your endpoints" — [Provider Integration §13](https://openrouter.ai/docs/guides/providers/integration).
- **429s protect against auto-hiding.** The one-week no-success auto-hide rule does not fire for endpoints that returned 429s in that week — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **What users see:**
  - "429: You are being rate limited"
  - "502: Your chosen model is down or we received an invalid response from it"
  - "503: There is no available model provider that meets your routing requirements"
  - The page also documents a `Retry-After` header.
  - Source: [Errors and debugging](https://openrouter.ai/docs/api_reference/errors-and-debugging).
- **Retries.** A failed request's retry is drawn by weighted share from the remaining endpoints — [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **BYOK rate limits.** With OpenRouter credits, "your rate limits for each provider are managed by OpenRouter"; with BYOK keys, the user's own provider account limits apply — [BYOK](https://openrouter.ai/docs/guides/overview/auth/byok).

### Inferences
- **Map upstream exhaustion to 429.** A gateway in front of Chutes should turn upstream capacity exhaustion into immediate 429s, not 5xx responses or timeouts. 5xx, timeouts and dropped connections count against both uptime and the reliability penalty; 429s do not count against uptime. (Inference from the error lists.)
- **Use the Provider API caps.** The RPM/RPD caps are the only capacity control OpenRouter actually enforces today. (Inference.)

### Gaps
- Whether OpenRouter honors a provider's `Retry-After` header.
- Numeric thresholds for short-term backoff and the breaker.

---

## 6. Network and auth: how OpenRouter authenticates to the provider, egress IPs, HTTPS and certificates, hostnames, and TLS termination inside a TEE

### Takeaway
OpenRouter calls the provider's own HTTPS API with a credential the provider issues. 401 and 402 responses from the provider count as setup errors, and the docs' payment section describes OpenRouter paying "via auto top up or invoicing" for its account with the provider. No egress IP ranges are published. The docs require HTTPS base URLs but say nothing about certificate authorities, hostnames or where TLS terminates. The decisive fact for URnetwork: OpenRouter terminates the user's TLS and processes plaintext, including in-flight CSAM screening of ZDR traffic, sampled prompt categorization and tool-call quality checks. TLS that terminates inside a TEE can therefore protect only the OpenRouter-to-provider hop. OpenRouter's docs and catalog have no TEE or attestation concept.

### Cited Findings
- **Auth failures count against the provider.** "Authentication issues (401)" and "Payment failures (402)" count against uptime. A "sudden spike of authentication, payment or not-found errors triggers a health check" that can hide the endpoint — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **OpenRouter pays the provider automatically.** "For OpenRouter to use the provider we must be able to pay for inference automatically. This can be done via auto top up or invoicing." — [Provider Integration §9](https://openrouter.ai/docs/guides/providers/integration).
- **Third-party guidance on auth (author's synthesis).** Expect "authenticated public HTTPS" and give OpenRouter "a separate OpenRouter test key" — [Dylan Vu, Aug 21 2026](https://dylanvu.substack.com/p/how-to-get-listed-on-openrouter-as).
- **HTTPS base URLs in the private-endpoint feature.**
  - Private endpoints ask for "the HTTPS base URL of your endpoint".
  - A private provider records "an OpenAI-compatible HTTPS `base_url`".
  - Requests are authenticated with the organization's own provider key, saved under BYOK.
  - Source: [Private Endpoints](https://openrouter.ai/docs/guides/routing/private-endpoints).
- **Hashed user ids.** OpenRouter sends a "hashed user id… Only providers whose data policy requires user ids receive this." — [Provider Integration §13](https://openrouter.ai/docs/guides/providers/integration).
- **No published egress IPs.**
  - A grep of the full docs dump on 2026-11-24 found no egress IP list, no static-IP statement and no IP ranges — [docs index](https://openrouter.ai/docs/llms.txt).
  - Web search found only a vendor blog about OpenRouter's **Enterprise inbound IP allowlist**, which restricts who can call OpenRouter. That is not an egress list — [QuotaGuard blog (search summary)](https://www.quotaguard.com/blog/openrouter-enterprise-static-ip-allowlist).
- **OpenRouter sees plaintext.**
  - "OpenRouter will screen inference requests, including ZDR traffic, for child sexual abuse material (CSAM) in flight. Content flagged as potential CSAM may be retained for human review."
  - "Anonymous Input Categorization: OpenRouter samples a small number of prompts for categorization."
  - OpenRouter otherwise stores prompts only on opt-in.
  - Source: [Data Collection](https://openrouter.ai/docs/guides/privacy/data-collection).
  - Routing measures "how often your responses to tool-calling requests come back well formed" — [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **No TEE concept in OpenRouter's docs or catalog.**
  - The docs dump on 2026-11-24 contains no "TEE", "enclave" or "confidential computing" terms. "Attestation" appears only as a customer's declaration about ZDR on private endpoints and BYOK keys — [ZDR](https://openrouter.ai/docs/guides/features/zdr).
  - Public endpoint records have no TEE field. Their fields are: context_length, latency_last_30m, max_completion_tokens, max_prompt_tokens, model_id, model_name, name, native_tools, pricing, provider_name, quantization, service_tier, status, supported_parameters, supports_*, tag, throughput_last_30m, and uptime_last_5m/30m/1d — [endpoints API](https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flashx-legal/endpoints).
  - A third-party comparison likewise says OpenRouter's own pages don't describe TEE, E2EE or attestation — [DEV Community comparison (search summary)](https://dev.to/trymorse/private-openai-compatible-llm-apis-compared-zero-retention-tee-and-verifiable-enclaves-2iln).
- **Data-policy tiers.**
  - OpenRouter classifies every endpoint as **ZDR**, **Safety Retention** (retained only for abuse prevention, no training) or **Retention and Training**.
  - "If OpenRouter is not able to establish or ascertain a clear policy for a provider or endpoint, we take a conservative stance and assume that the endpoint both retains and trains on data."
  - OpenRouter "in some cases creates special agreements with providers" for stricter policies.
  - The ZDR endpoint list is public at `/api/v1/endpoints/zdr`.
  - Source: [ZDR](https://openrouter.ai/docs/guides/features/zdr).
- **TEE providers already listed (catalog, 2026-11-24).** `chutes` (HQ US), `phala` (privacy policy at redpill.ai, status page status.phala.network), `near-ai` and `venice` are OpenRouter providers. Near AI serves `z-ai/glm-5.3-flash` as `near-ai/fp8` — [providers API](https://openrouter.ai/api/v1/providers); [endpoints API](https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flash/endpoints).
- **Phala's 2025 attestation-through-OpenRouter flow** (older, unverified for Nov 2026).
  - Phala's Apr 21, 2025 post describes requesting an attestation report "through OpenRouter's API at `/attestation/report?model=<model_name>`".
  - Signatures over request and response hashes come from RedPill's `/v1/signature/<REQUEST_ID>`.
  - The post does not say where TLS terminates or whether OpenRouter sees plaintext.
  - Source: [Phala blog](https://phala.com/posts/GPU-TEEs-is-Alive-on-OpenRouter).
- **Chutes' TEE status** (vendor material, search summary):
  - Chutes says "All featured models run on confidential TEE compute" — [Chutes pricing](https://chutes.ai/pricing).
  - Its catalog exposes a `confidential_compute` flag, with "TEE status verified Nov 8, 2026" — [Chutes private inference](https://chutes.ai/agents/private).
  - Counts of Chutes models on OpenRouter conflict (7 vs 19) across the search summaries — [OpenRouter Chutes provider page](https://openrouter.ai/provider/chutes).
  - An X post says Chutes' confidential hardware serves roughly a third of the crypto-native OpenRouter volume it analyzed, about Oct 2026 and unverified — [Blockworks Advisory on X](https://x.com/BlockworksAdv/status/2110415412580020472).
  - A May 2026 report describes a "Bittensor confidential routing" layer integrated with OpenRouter, also unverified — [Crypto Briefing](https://cryptobriefing.com/bittensor-confidential-routing-openrouter/).
- **In-region routing.** EU and US in-region routing exists on Business and Enterprise plans via `eu.openrouter.ai` and `us.openrouter.ai` — [Provider Logging](https://openrouter.ai/docs/guides/privacy/provider-logging). Some providers have "a dedicated in-region host" — [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).

### Inferences
- **Certificate.** The endpoint almost certainly needs HTTPS with a publicly trusted certificate on a public hostname. Nothing published constrains the hostname or the place TLS terminates, so termination inside a TEE (for example an ACME certificate whose key never leaves the enclave) looks technically compatible. (Inference: no doc states a CA requirement, and the "HTTPS base URL" wording and standard HTTP clients imply one.)
- **No end-to-end privacy through OpenRouter.**
  - OpenRouter terminates the user's TLS and reads plaintext (CSAM screening even on ZDR traffic, sampling, tool-call quality checks, token accounting).
  - So no listing on OpenRouter can be end-to-end private from user to enclave. The strongest honest claim is "attested TEE inference behind OpenRouter".
  - Under URnetwork's own rule that no URnetwork-run component may see plaintext, even inside a TEE (DESIGN §0, per the brief), the TLS endpoint OpenRouter calls would have to terminate inside the upstream (Chutes) enclave, not in a URnetwork gateway. That enclave would also need to authenticate OpenRouter's key and emit usage counts for invoicing.

  (Inference.)
- **Attestation does not reach users.** Attestation evidence has no documented path through OpenRouter's normalized responses. Users could verify only out of band, as Phala did in 2025 with its own signature endpoint. (Inference.)
- **Auth must be key-only.** With no published egress IPs, the provider endpoint has to authenticate by API key alone. Per-source-IP rate limiting would throttle all OpenRouter traffic as one client. (Inference.)

### Gaps
- OpenRouter's egress IP ranges, if any. Ask OpenRouter.
- Whether mTLS or custom auth headers are supported.
- The full set of request headers sent to providers.
- The fetch timeout.
- Whether OpenRouter today offers any TEE label, attestation pass-through or verified-TEE program. None was found.
- How OpenRouter would classify a TEE endpoint's data policy. ZDR status rests on terms and agreements, not hardware.

---

## 7. Reporting tools: provider dashboard, analytics, and pricing and model-listing APIs

### Takeaway
Onboarded providers get a provider dashboard at `openrouter.ai/provider/{slug}/dashboard`. It has a schema validator, a feed generator, per-endpoint capabilities and tests, unhide, and the same metrics Auto Exacto uses. A Provider API under `/api/v1/providers/{slug}` covers endpoint caps, visibility, capability disabling, video-input switches, public page links, abuse reports and team members. Public, unauthenticated catalog APIs expose models, per-provider endpoints with live uptime, latency and throughput, providers, and the ZDR endpoint list.

### Cited Findings
- **Provider dashboard.**
  - The **Schema validator** tab (`https://openrouter.ai/provider/{provider_slug}/dashboard`) reports warnings and rejected documents.
  - It includes a **Generate feed** panel.
  - Capability tests can be started "from the endpoint's capabilities in the provider dashboard".
  - Hidden tier endpoints show "the reason… in your provider dashboard".
  - Source: [Provider Integration](https://openrouter.ai/docs/guides/providers/integration).
- **Metrics in the dashboard.**
  - Throughput and tool-calling success rate are "the same metrics available in your provider dashboard. Once onboarded, our team can give you access to it."
  - Benchmark data will be made "available in your provider dashboard soon".
  - Source: [Provider Integration §12](https://openrouter.ai/docs/guides/providers/integration).
- **Provider API.** "Provider dashboard settings are moving to an API under `https://openrouter.ai/api/v1/providers/{provider_slug}`." It is authenticated with an OpenRouter API key from an owner or member account, and an OpenAPI 3.1 document is at `GET /api/v1/providers/{provider_slug}/openapi`. Routes:
  - `PATCH …/endpoints/{id}/limits` sets `limit_rpm` and `limit_rpd`.
  - `PATCH …/endpoints/{id}/visibility` hides an endpoint. Unhide is dashboard-only because it re-runs tests.
  - `POST …/endpoints/{id}/capabilities/disable`.
  - `PATCH …/endpoints/{id}/video-input`.
  - `PATCH /api/v1/providers/{slug}` sets the `terms_of_service_url`, `privacy_policy_url` and `status_page_url` shown on the public provider page.
  - `POST …/abuse-reports` (plus `/validate` and a GET list). Reports are reviewed by trust & safety; they do "not trigger automatic enforcement" and "do not change how OpenRouter routes traffic to you".
  - `…/members` and `…/invites` manage owner and member roles.
  - An "endpoint-health route" is mentioned.

  Source: [Provider Integration §13](https://openrouter.ai/docs/guides/providers/integration).
- **Public catalog APIs.**
  - `GET /api/v1/models/{author}/{slug}/endpoints` returns "Per-provider endpoints for a model with quantization, pricing, context limits, and availability".
  - `GET /api/v1/endpoints/zdr` returns a "preview of provider endpoints that support Zero Data Retention".
  - Source: [Models API reference](https://openrouter.ai/docs/api_reference/models).
  - `GET /api/v1/providers` returns name, slug, privacy_policy_url, terms_of_service_url, status_page_url, headquarters and datacenters (124 records on 2026-11-24) — [providers API](https://openrouter.ai/api/v1/providers).
- **Public pages and datasets.**
  - Model pages show per-provider TTFT, throughput and uptime: "Every model page shows your TTFT, throughput and uptime next to other providers" — [Become a Provider](https://openrouter.ai/providers/apply).
  - The SDKs expose "Public OpenRouter usage datasets… licensed under CC BY 4.0" — [docs index](https://openrouter.ai/docs/llms.txt).
  - The Rankings page counts prompt + completion tokens, including reasoning, and caps BYOK-heavy models: ranked tokens = non-BYOK + min(BYOK, 2 × non-BYOK) for models flagged on 90-day BYOK > 2 × non-BYOK — [Rankings Methodology](https://openrouter.ai/docs/guides/features/rankings-methodology).

### Inferences
- **Billing data source.** The provider's own logs would be the billing source of truth for its monthly invoice, reconciled against OpenRouter's counts ("We reconcile token counts automatically"). No provider-facing usage-statement API is documented. (Inference.)

### Gaps
- The full Provider API (capabilities enum, endpoint-health schema, any usage or revenue reports) sits behind authentication at `/api/v1/providers/{slug}/openapi` and could not be read.
- Whether the dashboard shows per-request logs or revenue is not documented.

---

## 8. Bring your own key: does BYOK apply to new providers?

### Takeaway
BYOK lets OpenRouter users route through their own provider accounts, for a fee of 5% of OpenRouter's normal price for that model and provider, above a plan-dependent free allowance. It is limited to providers OpenRouter has integrated for BYOK; the docs give no self-serve path for a newly listed provider to become BYOK-eligible. Separately, OpenRouter's **Private Endpoints and private providers** (an Enterprise add-on) let a customer organization point OpenRouter at any OpenAI-compatible HTTPS base URL, scoped privately to that organization, without a public listing.

### Cited Findings
- **Fee.** "The cost of using custom provider keys on OpenRouter is 5% of what the same model/provider would cost normally on OpenRouter." "The free allowance is plan-dependent and measured by list-price inference cost, not request count: Pay-as-you-go includes $25,000 per month, while Enterprise allowances are custom." — [BYOK](https://openrouter.ai/docs/guides/overview/auth/byok).
- **Key order.** Keys are tried in order: Prioritized keys, then OpenRouter (shared) endpoints, then Fallback keys. A "Shared capacity fallback" setting can forbid falling back to OpenRouter's shared endpoints. Keys can declare ZDR and region — [BYOK](https://openrouter.ai/docs/guides/overview/auth/byok).
- **BYOK bypasses default routing.** Requests that "Bring their own provider key" are excluded from default routing — [Traffic Routing](https://openrouter.ai/docs/guides/providers/traffic-routing).
- **BYOK in rankings.** BYOK-heavy models are capped on the Rankings page — [Rankings Methodology](https://openrouter.ai/docs/guides/features/rankings-methodology).
- **BYOK is per supported provider.**
  - A private endpoint must be "hosted by a provider that OpenRouter supports for BYOK", and must serve "a model that already exists in the OpenRouter catalog, with the same request and response shape".
  - Keys are managed per provider at `/settings/integrations/{provider}` (for example `/settings/integrations/openai`).
  - Sources: [Private Endpoints](https://openrouter.ai/docs/guides/routing/private-endpoints); [BYOK](https://openrouter.ai/docs/guides/overview/auth/byok).
- **Private providers (Enterprise add-on).**
  - An organization can create a private provider with a name, a slug and "an OpenAI-compatible HTTPS `base_url`", then attach private endpoints to catalog models.
  - Limits: up to 5 private providers and 10 private endpoints per organization by default.
  - Validation checks the key, OpenAI compatibility, streaming, usage fields and the served model id.
  - "OpenRouter records a newly created private provider as retaining no prompts, training on none, and publishing none… OpenRouter does not verify the upstream's actual data handling."
  - Private endpoints "do not appear in public model lists, rankings, search, charts, or benchmarks".
  - Source: [Private Endpoints](https://openrouter.ai/docs/guides/routing/private-endpoints).

### Inferences
- **BYOK for a new provider is up to OpenRouter.** BYOK for a newly onboarded provider would need OpenRouter to add it to the integrations list, and no documented process exists. Ask during onboarding. (Inference.)
- **Private providers as a stopgap.** Private providers give individual Enterprise customers a way to reach URnetwork's TEE endpoint through OpenRouter while the public application is pending, or without one. It carries the same plaintext-at-OpenRouter caveat (§6) and OpenRouter's unverified "no retention" default. (Inference.)

### Gaps
- No public list or criteria for BYOK-eligible providers, and no statement on whether new providers are added.
- Whether BYOK traffic to a provider counts toward that provider's public metrics.
