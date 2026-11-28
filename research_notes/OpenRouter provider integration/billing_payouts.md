# OpenRouter billing and payouts: how money flows between users, OpenRouter and inference providers (as of November 2026)

*Compiled 2026-11-24. Every openrouter.ai page cited was fetched that day. Text in quotation marks is the wording returned by the fetch tool, which uses a summarizing model, so treat short quotes as near-verbatim. Unquoted statements are paraphrases. Items marked [snippet] come from search-result summaries of pages that were not fetched. Items marked [inference] are this researcher's reasoning, not something a source states.*

## 1. User side: how users pay OpenRouter, the fees, markup and BYOK

### Takeaway
Users prepay US-dollar credits. They pay by card or AliPay through Stripe, or in USDC through Coinbase; Enterprise customers can also use invoices and purchase orders. OpenRouter earns a platform fee when credits are bought, never on individual requests. The fee is 5.5% (minimum $0.80) on the Standard pay-as-you-go plan, 8% on the newer Business plan and 5% on crypto, and Enterprise can negotiate it down. Inference passes through at the provider's list price with no markup. BYOK is fee-free up to $25,000 a month of list-price inference on the pay-as-you-go plans. Above that, OpenRouter charges 5% of what the same model and provider would cost on OpenRouter, deducted from credits.

### Cited Findings
- **Credits.** Credits are prepaid USD deposits: "Credits are simply deposits on OpenRouter that you use for LLM inference", and "the base currency is US dollars". Each request's cost is deducted from credits. Users top up by hand or turn on auto top-up below a threshold. — [OpenRouter FAQ](https://openrouter.ai/docs/faq)
- **Prepayment is mandatory.** "Currently, OpenRouter requires users to purchase Credits to make API calls and access the Service". The payment processors are "Stripe and Coinbase", and Auto Recharge is optional. — [OpenRouter Terms, Last Updated Aug 31, 2026](https://openrouter.ai/terms)
- **Payment methods.** "We accept all major credit cards, AliPay and cryptocurrency payments in USDC". PayPal is in progress: "We are working on integrating PayPal soon." — [FAQ](https://openrouter.ai/docs/faq)
  - The Standard and Business plans list "Credit card, crypto & more".
  - The Enterprise plan lists "Invoicing options", with invoicing and purchase orders arranged through sales.
  - Enterprise pricing is set by contract, based on volume, prepaid credits and annual commitments. — [OpenRouter Pricing](https://openrouter.ai/pricing)
- **Fees on credit purchases.** "OpenRouter charges a 5.5% ($0.80 minimum) fee when you purchase credits", and "Crypto payments are charged a fee of 5%." — [FAQ](https://openrouter.ai/docs/faq)
- **Plan tiers on the pricing page.** — [Pricing](https://openrouter.ai/pricing)
  - Free: platform fee "N/A".
  - Standard (pay-as-you-go): 5.5%, charged when credits are bought, "never on individual requests".
  - Business (pay-as-you-go): 8% on credit purchases. It comes with 1,000 workspaces and needs no contract, minimum spend or sales call; downgrading is possible 30 days after upgrading.
  - Enterprise: "Fee discounts available", plus a support SLA, a Slack channel, a customer success manager and a forward-deployed engineer.
  - Rate limits on the paid plans are "Passthrough from the provider(s)".
- **No markup on inference.**
  - "We pass through the pricing of the underlying model providers without any markup"; "there is no markup on inference pricing"; "We charge a small fee when purchasing credits." — [FAQ](https://openrouter.ai/docs/faq)
  - The pricing page says inference is billed at the provider's list price on every plan, and: "We offer discounted OpenRouter fees in our enterprise plan. We do not discount inference." — [Pricing](https://openrouter.ai/pricing)
  - The FAQ adds: "OpenRouter does not currently offer volume discounts", with exceptional cases raised by email. — [FAQ](https://openrouter.ai/docs/faq)
- **Logging discount.** Users who opt in to logging of their prompts and completions get "a 1% discount on usage costs." — [FAQ](https://openrouter.ai/docs/faq)
- **Refunds and expiry.** — [FAQ](https://openrouter.ai/docs/faq); [Terms](https://openrouter.ai/terms)
  - Unused credits can be refunded only within 24 hours of purchase.
  - "the platform fees are non-refundable", and "cryptocurrency payments are never refundable".
  - OpenRouter "reserves the right to expire unused credits three hundred sixty-five (365) days after purchase".
  - Credits are "not legal tender or currency" and cannot be transferred.
- **BYOK fees.**
  - "BYOK has a plan-dependent free allowance measured by list-price inference cost, not request count." "Pay-as-you-go includes $25,000 per month with no BYOK fee." Usage above the allowance costs "5% of what the same model and provider would normally cost on OpenRouter", and the fee "is deducted from your OpenRouter credits". Enterprise allowances are custom. — [FAQ](https://openrouter.ai/docs/faq); [BYOK docs](https://openrouter.ai/docs/use-cases/byok)
  - The pricing page shows the same allowance on Standard and on Business: "$25,000 of list price inference / month with no fees, 5% fee after". The Free tier has no BYOK. — [Pricing](https://openrouter.ai/pricing)
- **BYOK in routing.** BYOK endpoints are tried first automatically when the user has keys and sets no `order`. Within a named provider, "your own key is tried before OpenRouter's shared capacity". — [Provider routing docs](https://openrouter.ai/docs/features/provider-routing)
  - By default, BYOK spend does not count toward guardrail or workspace budgets. — [BYOK docs](https://openrouter.ai/docs/use-cases/byok)
- **Free-tier limits.** Free models are limited to 50 requests a day and 20 a minute, rising to 1,000 a day once the account has bought at least $10 of credits. The pricing page lists "25+ free models" from "4 free providers". — [Pricing](https://openrouter.ai/pricing); [FAQ](https://openrouter.ai/docs/faq)
- **CEO on fees** [summary of the 20VC interview transcript, not verbatim]. The host refers to a "5.5% take", and Atallah ties it to the pay-as-you-go plan. He accepts that the take rate can look expensive at scale, says Enterprise deals remove fees on committed volume and BYOK can remove the fee entirely, and describes a shift toward Enterprise committed-spend plans. — [20VC transcript (ulisten)](https://ulisten.ai/channels/20vc/openrouter-ceo-why-chinese-open-models-are-beating-the-us-wh_K72oZoloA4M/transcript)
- **Stripe billing integration** [snippet]. In January 2026, Stripe said developers using OpenRouter could route model requests through it while Stripe tracked usage, applied pricing and handled billing. — [AI News](https://www.artificialintelligence-news.com/news/stripe-openrouter-acquisition-ai-model-routing/)

### Inferences
- [inference] A user's effective cost is the provider's list price plus the purchase fee: about +5.5% by card on Standard, +8% on Business and +5% in USDC.
  - The $0.80 minimum makes small top-ups dearer. A $10 top-up pays 8%.
  - A user buying straight from a provider at the same list price pays 5–8% less than through OpenRouter.
- [inference] OpenRouter's revenue comes from users (the purchase fee and the BYOK overage fee), not from providers. This matches "no markup" and providers being paid "based on actual token usage" (section 3).
- [inference] Since credits are prepaid and the fees cannot be refunded, OpenRouter holds a large float of user deposits. It collects cash before inference happens.

### Gaps
- No dated announcement was found for the Business (8%) tier or the $25,000/month BYOK allowance. The blog index has no post about pricing changes.
- I could not determine whether Enterprise invoicing is ever post-paid, which would leave OpenRouter carrying credit risk. The pricing page mentions only prepaid credits and annual commitments.
- The docs do not say which providers support BYOK, or whether a new provider can be added as a BYOK target.

## 2. Provider pricing: who sets the per-token price, how it maps to the user price, and the price components

### Takeaway
The provider sets its own USD prices in a machine-readable feed, its `/models` endpoint. OpenRouter shows and bills those prices to users unchanged. Some changes wait for staff review, and changes to `:free` variants always do. A provider can also set `discount_to_user`, which lowers or raises the price users see. The feed (schema v2.4) can price:
- input as prompt, cached-prompt read or cache write;
- output as completion or internal reasoning;
- whole requests, per request or per web search;
- other units such as images, megapixels, seconds and characters.

It also supports cache TTLs, up to two time-of-day windows, long-context tiers, conditional overrides and batch endpoints.

Price does not decide traffic on its own. Default routing weighs effective price, which accounts for cache hits, alongside speed, reliability and tool-call quality.

### Cited Findings
- **Apply page FAQ.** "You set your own per-token pricing in USD." "Each model in your /models endpoint has its own pricing object." "You can also provide tiered pricing for long-context requests with different rates above a token threshold." — [Become a Provider](https://openrouter.ai/providers/apply)
- **Feed format.** — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
  - Each model's `id` must be "the exact model identifier that OpenRouter will use when calling your API".
  - The root fields include `schema_version` ("2.4"), `quantization`, `tokenizer`, `pricing`, `capacity`, `is_free`, `service_tier`, `variant`, `discount_to_user`, `datacenters` and `deployment_region`.
- **Price units and SKUs.** — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
  - Prices are strings: "All `cost_usd` fields are in string format to avoid floating point precision issues, and must be in USD."
  - Input SKUs: `prompt`, `cached_prompt`, `cache_write`. Output SKUs: `completion`, `internal_reasoning`. Request-level SKUs: `request`, `web_search`.
  - Units: token, image, megapixel, second, character, request, search.
  - Cache entries can carry `ttl_seconds` and `implicit`. Time-of-day windows use `utc_start`, `utc_end` and `utc_days`. Conditional prices use `overrides` with a `when` predicate.
  - Leave out SKUs you don't bill. A free SKU may be "0".
  - The legacy flat format has `prompt`, `completion`, `input_cache_read` and an optional `batch` object.
- **Time-of-day and batch rules.** — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
  - "Your base pricing must be your cheapest (off-peak) rate." "Up to 2 time windows per model."
  - "Batch endpoints need setup on OpenRouter's side, and your feed does not create them."
- **Review of price changes.** Some price changes wait for OpenRouter staff review, and "pricing changes on `:free` variants always wait for review". — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **`discount_to_user`.** "a decimal fraction that OpenRouter applies to your displayed pricing"; "`0.2` means users see and pay 20% less than your listed pricing"; "The discount applies to every priced SKU". The formula is user price = base price × (1 − discount_to_user). Negative values mark the price up, and values of 1 or more are rejected. — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **Service tiers.** "OpenRouter bills the served tier, so a request your API silently downgraded must come back saying so." — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **What users see.** Prices are listed per million tokens, with separate prompt and completion rates. Some models also charge per request, per image or for reasoning tokens. — [FAQ](https://openrouter.ai/docs/faq)
- **Default routing.** — [Provider routing docs](https://openrouter.ai/docs/features/provider-routing)
  - OpenRouter "picks a provider by comparing what a good response would actually cost you at each one, not by list price alone". The cost it compares is effective price, "the price the provider actually charges, reflecting its real cache hit rate". Throughput, time to first token, rate limits, reliability and tool-call quality are weighed too.
  - "Providers close to the best share most of the traffic". Providers with far worse error or 429 rates get no traffic until they recover.
  - Users can override the default with `sort` (price, throughput or latency), the `:floor` and `:nitro` shortcuts, `only`, `order`, `ignore`, `allow_fallbacks: false`, `data_collection: "deny"` and `zdr: true`.
- **Routing rebuild.** OpenRouter posted "How we rebuilt provider routing for better, faster inference" on Oct 28, 2026. The current routing page does not mention inverse-square price weighting. — [OpenRouter blog index](https://openrouter.ai/blog/); [Provider routing docs](https://openrouter.ai/docs/features/provider-routing)
- **Negotiated contracts** (investor view). OpenRouter "could negotiate contracts across providers". The Menlo post also says that OpenAI gives "exclusive discounts through OpenRouter". — [Menlo Ventures, Aug 19, 2026](https://menlovc.com/perspective/stripe-to-acquire-openrouter-why-everyone-is-obsessed-with-model-routing/)

### Inferences
- [inference] The provider controls its price, but OpenRouter controls how much traffic that price wins. A higher-priced private endpoint will get little default traffic. Its demand would come from users who pin it with `only` or `order`, or whose filters (`zdr: true`, `data_collection: "deny"`) leave few rivals.
- [inference] The docs do not say who keeps the extra money when `discount_to_user` is negative, though the provider is the likely beneficiary. Likewise, a positive discount appears to be funded by the provider.
- [unverified, from memory] Earlier versions of the routing docs described weighting providers by the inverse square of price. The current page describes cost-and-performance weighting instead.

### Gaps
- It is not public whether OpenRouter ever pays a provider less than its listed price. Menlo's mention of negotiated contracts and lab discounts suggests that may happen for large labs, but no terms are disclosed.
- How `discount_to_user` is funded, and who receives a negative discount's markup, is not stated outright.

## 3. Provider payouts: mechanism, terms, revenue share, currency, contract and credit risk

### Takeaway
A provider joining in November 2026 must invoice OpenRouter once a month for actual token usage at its own USD list prices. OpenRouter "reconcile[s] token counts automatically" and pays to the details set up during onboarding. The public material shows no revenue share or listing fee, because OpenRouter's fee is charged to users. Several terms are not public:
- payment terms (net days);
- minimum payouts;
- payout rails;
- crypto payout options;
- the provider terms themselves, which are accepted online after a mutual NDA.

### Cited Findings
- **Monthly invoicing is mandatory.** The "Monthly invoicing to OpenRouter" requirement is marked "Required": "You invoice OpenRouter monthly for inference. We don't onboard providers on other payment terms." — [Become a Provider](https://openrouter.ai/providers/apply)
- **Invoicing and reconciliation.** "You send OpenRouter one invoice a month for usage. We reconcile token counts automatically." — [Become a Provider](https://openrouter.ai/providers/apply)
- **What providers are paid.** "OpenRouter pays you for inference based on actual token usage through monthly invoicing." "OpenRouter pays providers through monthly invoicing. Payment details are set up during onboarding." — [Become a Provider](https://openrouter.ai/providers/apply)
- **Conflicting source.** The integration docs say: "For OpenRouter to use the provider we must be able to pay for inference automatically. This can be done via auto top up or invoicing." This conflicts with the apply page's invoicing-only rule. The apply page reads as the current onboarding rule, and auto top-up looks like a legacy mode. — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **Onboarding and contract.** — [Become a Provider](https://openrouter.ai/providers/apply)
  - Applications are decided "on a rolling basis".
  - "We sign a mutual NDA, then meet on a call."
  - "You answer the security questionnaire, upload your security documents and accept the provider terms online."
  - "SOC 2 and zero data retention help, but neither is required."
  - Personal email addresses such as Gmail or Outlook are not accepted.
- **Uptime and routing priority.** — [Become a Provider](https://openrouter.ai/providers/apply); [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
  - "Stay at 95% uptime or higher to keep standard routing priority." Between 80% and 94%, traffic is reduced. Below 80%, the endpoints are used only as a fallback.
  - Uptime is "successful requests ÷ total requests (excluding user errors)", measured after at least 100 requests.
  - Errors that count against uptime: 401, 402, 404, all 5xx, mid-stream errors, and successful responses with an error finish reason.
  - Errors that don't count: 400, 413, 429 and 403.
- **Revenue model.** OpenRouter passes provider prices through with no markup and charges its fee at credit purchase. — [FAQ](https://openrouter.ai/docs/faq); [Pricing](https://openrouter.ai/pricing)
  - Sacra calls it a "5% commission on all inference spend", with customers paying OpenRouter directly. — [Sacra](https://sacra.com/c/openrouter/)
- **User-side credit risk.** Users must prepay credits, and crypto payments are never refunded. The Terms do not mention chargebacks. — [Terms](https://openrouter.ai/terms)
- **Fraud** (Latent Space episode, Sep 25 [2026]; the speaker attribution in the fetched transcript is uncertain). — [Latent Space, "OpenRouter: from Seed to Stripe"](https://latent.space/p/openrouter/)
  - "We blocked 10x as much dollar volume last month as the month before."
  - The fraud includes "people trying to resell traffic against the terms of service" and "hacked accounts".
  - "if you're making a gateway or selling, like, generalized inference, you are a target for fraud."
  - The speakers also say they "worked closely with Stripe" on abuse.
- **Abuse reports from providers.** Providers can report accounts whose traffic breaks the acceptable use policy. Reports "are reviewed by OpenRouter's trust & safety team" and "do not trigger automatic enforcement". Per-user IDs go only to providers "whose data policy requires user ids". — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers); [FAQ](https://openrouter.ai/docs/faq)
- **Providers in the user Terms.** The user Terms make "Model Providers ... intended third-party beneficiaries of Sections 5, 6.1, 15, 17, and this Section 20". "Each Model Provider retains sole control over access to its Model." OpenRouter disclaims liability for any suspension or termination of a model. — [Terms](https://openrouter.ai/terms)

### Inferences
- [inference] **Revenue share.** None is visible on the provider side. The provider appears to be paid its listed price times billed usage, after any `discount_to_user`. The non-public provider terms could still contain fees, offsets or caps.
- [inference] **Credit risk and chargebacks.** OpenRouter collects in advance (credits are mandatory) and pays providers on "actual token usage", not on what it collects. So OpenRouter, not the provider, appears to carry the user-side risk: card chargebacks, stolen-card fraud and resold traffic. The provider instead carries counterparty risk on OpenRouter, Inc. for at least a month of usage plus the unknown payment term. Not confirmed, because the provider terms are not public.
- [inference] **Cash flow.** OpenRouter runs on negative working capital: users prepay, and providers are paid monthly in arrears. The provider finances its own compute (and any upstream supplier) for at least about 30 days, plus the payment term.
- [inference] **402 errors.** A 402 counts against provider uptime. This fits the legacy auto-top-up model, in which OpenRouter keeps a prepaid balance at the provider and an empty balance returns 402. Under invoicing, a provider that returns 402s, for example because its own upstream credit has run out, lowers its uptime.
- [inference] **Currency.** Prices must be in USD, and no crypto or non-USD payout appears in any provider-facing page. Settlement appears to be in US dollars, by a rail not disclosed.

### Gaps
- Not public:
  - net payment terms (net-15/30/45);
  - minimum payout thresholds;
  - payout rail (ACH, wire, Stripe Connect);
  - crypto or USDC payouts;
  - late-payment remedies, audit rights and dispute windows;
  - the full provider terms, which are behind the NDA and online acceptance.
- No listing fee or provider-side fee is mentioned anywhere I found. That does not prove none exists.
- It is unknown whether provider payouts will move onto Stripe rails after the acquisition (see section 7).

## 4. Usage accounting: who counts billed tokens, how discrepancies are reconciled, and failed, aborted and partial requests

### Takeaway
Users are billed on counts from the model's native tokenizer, and each response returns its usage and cost. For providers, OpenRouter checks token counts automatically against the monthly invoice. The public docs do not say whether those counts come from the provider's `usage` field or from OpenRouter's own tokenizing, or how disputes are settled.

Who pays for failures:
- **Failed and fallback attempts.** Users are not charged for model tokens.
- **Zero-output responses.** Under "zero completion insurance", users are not charged even if the provider charged OpenRouter for the prompt. OpenRouter therefore absorbs that cost.
- **Aborted streams.** Billing stops only for providers that support cancellation. Chutes supports it; Targon does not. With any other provider, the user pays for the whole completion.

### Cited Findings
- **Native tokenizer.** "Token counts are calculated using the model's native tokenizer." Usage includes "Input and output token counts using the model's native tokenizer". — [Usage Accounting docs](https://openrouter.ai/docs/use-cases/usage-accounting)
- **Usage fields.** — [Usage Accounting docs](https://openrouter.ai/docs/use-cases/usage-accounting)
  - Chat Completions returns `prompt_tokens`, `prompt_tokens_details` (`cached_tokens`, `cache_write_tokens`, `audio_tokens`), `completion_tokens`, `completion_tokens_details` (`reasoning_tokens`), `total_tokens`, `cost` and `cost_details.upstream_inference_cost`. The Responses API returns equivalent fields plus `is_byok`.
  - "`cost`: The total amount charged to your account".
  - "`cost_details.upstream_inference_cost`: The actual cost charged by the upstream AI provider". When fetched by generation ID, this field is available only for BYOK requests.
- **Missing usage.** When an Anthropic Messages stream fails upstream: "missing usage is not evidence that no work was billed". — [Usage Accounting docs](https://openrouter.ai/docs/use-cases/usage-accounting)
- **Agent runs.** For agent runs that use deferred tools and stop early, "every upstream model turn that completed before the stop remains billed". — [Usage Accounting docs](https://openrouter.ai/docs/use-cases/usage-accounting)
- **Provider reconciliation.** "We reconcile token counts automatically." — [Become a Provider](https://openrouter.ai/providers/apply)
  - The FAQ says, in paraphrase, that billing is based on the total tokens the provider processes. — [FAQ](https://openrouter.ai/docs/faq)
  - The public provider integration page has no `usage`-field requirement and no token-counting rules. — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **Failed attempts and streaming.** Failed or fallback attempts are not charged for model tokens. Streaming is billed per token, the same as non-streaming. — [Pricing](https://openrouter.ai/pricing)
- **Zero Completion Insurance.** — [Zero Completion Insurance docs](https://openrouter.ai/docs/guides/features/zero-completion-insurance); [announcement, Mar 25, 2025](https://openrouter.ai/blog/announcements/never-pay-for-empty-ai-responses-again/)
  - "When a response contains no output tokens and either has a blank finish reason or an error, you will not be charged for the request."
  - "This applies even in cases where OpenRouter may have been charged by the provider for prompt processing."
  - It is on for all accounts with no setup. On Mar 25, 2025 it was extended to "every model available on OpenRouter".
  - Quotes per the search result; the official URL was not fetched directly.
- **Stream cancellation.** — [Streaming docs](https://openrouter.ai/docs/api-reference/streaming)
  - "For supported providers, this immediately stops model processing and billing." "For non-streaming requests or unsupported providers, the model will continue processing" "and you will be billed for the complete response."
  - Providers that support cancellation: OpenAI, Azure, Anthropic, Fireworks, Mancer, Recursal, AnyScale, Lepton, OctoAI, Novita, DeepInfra, Together, Cohere, Hyperbolic, Infermatic, Avian, xAI, Cloudflare, SFCompute, **Nineteen**, Liquid, Friendli, **Chutes**, DeepSeek.
  - Providers that do not: AWS Bedrock, Groq, Modal, Google, Google AI Studio, Minimax, HuggingFace, Replicate, Perplexity, Mistral, AI21, Featherless, Lynn, Lambda, Reflection, SambaNova, Inflection, ZeroOneAI, AionLabs, Alibaba, Nebius, Kluster, **Targon**, InferenceNet.
  - The docs say nothing about billing after mid-stream errors.
- **Downgraded service tiers.** "OpenRouter bills the served tier", so a request the provider silently downgraded must say so in its response. — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)

### Inferences
- [inference] **Aborted streams.** With a provider that supports cancellation, the user pays only for tokens produced before the abort. The provider is then presumably paid only for those tokens too, since it is paid on "actual token usage".
  - A reseller that supports cancellation but does not pass the abort upstream would pay its supplier for tokens OpenRouter never pays for.
  - Chutes appears on OpenRouter's supported list, so a URnetwork endpoint built on Chutes could pass aborts through.
- [inference] **Zero-completion cases.** The wording "OpenRouter may have been charged by the provider for prompt processing" implies OpenRouter still pays providers for prompt processing on zero-output failures and absorbs the loss. Whether the monthly reconciliation lets a provider bill such requests is not public, so it must be confirmed in the provider terms.
- [inference] **Tokenizer drift.** OpenRouter bills users on native-tokenizer counts and reconciles provider invoices automatically. A provider whose upstream supplier counts tokens differently, or uses a different chat template, could see a mismatch between what OpenRouter pays and what the supplier charges.

### Gaps
- The reconciliation method is not public: provider-reported `usage` versus OpenRouter's own tokenizing. So are the tolerance, the dispute window and how disagreements are settled.
- No source says whether providers are paid for requests that fail mid-stream, or for 5xx and errored requests that users are not charged for.

## 5. Free and promotional traffic: who pays the provider

### Takeaway
A `:free` endpoint is one the provider flags with `is_free: true`, and "Free endpoints always have zero cost". Price changes on them always need OpenRouter's review. OpenRouter says it "keeps expanding free capacity by onboarding providers and covering costs directly". Free traffic is therefore a mix of two kinds:
- capacity a provider or model maker donates for promotion or feedback, which earns it nothing;
- capacity OpenRouter pays for, on terms that are not public.

Promotional credits are granted at OpenRouter's discretion. Paid usage bought with them is presumably paid out to providers as normal.

### Cited Findings
- **Free endpoints in the feed.** "`is_free: true` marks the endpoint as a free endpoint (`:free` suffix)." "Free endpoints always have zero cost." "pricing changes on `:free` variants always wait for review". — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **OpenRouter pays for some free capacity.** "OpenRouter keeps expanding free capacity by onboarding providers and covering costs directly." — [OpenRouter free models collection](https://openrouter.ai/collections/free-models)
- **Size of the free tier.** "25+ free models" from "4 free providers". Free requests are capped at 50 a day and 20 a minute, or 1,000 a day once at least $10 of credits has been bought. — [Pricing](https://openrouter.ai/pricing)
- **Third-party view.** TrueFoundry says free models are subsidized by OpenRouter. It warns that a free variant is not always the same deployment as the paid model of the same name. It also says some free endpoints run on a single provider with no fallback. — [TrueFoundry](https://www.truefoundry.com/blog/openrouter-free-models-whats-actually-free-and-what-it-costs-you)
- **Model-maker-funded free models** [snippet]. Search snippets of OpenRouter model pages say one NVIDIA model "continues to be offered for free by NVIDIA". Another model is "free to use during this testing period, and prompts and completions are logged by the model creator for feedback and training". — [OpenRouter free models collection](https://openrouter.ai/collections/free-models)
- **Prompt collection on free endpoints** (Latent Space, Sep 2026; speaker attribution uncertain). "We like have free endpoints too, but like those free endpoints, we, I think we're not collecting any prompts." — [Latent Space](https://latent.space/p/openrouter/)
- **Chutes, the Bittensor precedent.**
  - In 2025, Jon Durbin announced models that were free on Chutes and "Also on @openrouter free!". These included the Nemotron and Gemma 3 models. — [X, Durbin (Nemotron)](https://x.com/jon_durbin/status/1909631851217465505); [X, Durbin (Gemma 3)](https://x.com/jon_durbin/status/1899947669943906376)
  - Chutes was the only provider of DeepSeek R1 (free) on OpenRouter, and it rate-limited OpenRouter's free users to protect its own subscribers. — [RPwithAI](https://rpwithai.com/chutes-rate-limits-free-users-from-openrouter/)
  - Chutes dropped its own free tier (200 requests a day) in February 2026. — [ownyourmind.ai](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
  - An October 2026 secondary blog says Chutes "does not offer a free tier". — [Arcanum](https://arcanumrpgs.com/blog/openrouter-vs-nanogpt-vs-chutes/)
  - In February 2026, TNG's DeepSeek R1T2 Chimera got heavy default routing on OpenRouter. Part of Chutes's February revenue was "sponsored hosting paid by model makers". — [ownyourmind.ai](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
- **Promotional credits.** "OpenRouter may in its discretion provide Credits to you free of charge". "Promo Credits will not be applied against any sales, use, gross receipts" taxes. — [Terms](https://openrouter.ai/terms)
  - New users get "a small free allowance to test out OpenRouter". — [FAQ](https://openrouter.ai/docs/faq)

### Inferences
- [inference] A provider that lists a `:free` endpoint is paid nothing by OpenRouter for that traffic, unless it has a separate deal under which OpenRouter covers the cost directly. Such deals exist, but their terms are not public.
- [inference] Promotional credits and the 1% logging discount look like OpenRouter's own marketing costs. A paid model used with promo credits is still "actual token usage", which suggests the provider is paid as normal. Not confirmed.
- [inference] Free traffic can be very large, but it is fragile. Chutes's OpenRouter volume peaked during a period of heavy free and default routing (section 6). Providers fund it with emissions, sponsorship or OpenRouter payments, not with users' money.

### Gaps
- The rates OpenRouter pays for the free capacity it covers are not public, nor is the form of payment (per token or reserved capacity).
- I could not determine which four providers currently serve free endpoints.

## 6. Comparisons: what providers earn, the volumes they see, and OpenRouter versus selling direct

### Takeaway
OpenRouter is very large. As of August 2026 it handled about 4.5 quadrillion tokens a year at run rate, served about 10 million users and listed more than 500 models from more than 80 providers. Sacra estimated its annualized revenue at about $140–160M in July–August 2026, on a take of roughly 5%. Stripe agreed to buy it on Aug 19, 2026, reportedly for more than $7B.

Few providers disclose what they earn through OpenRouter. The best public Bittensor datapoint is Chutes. Its OpenRouter volume fell from a peak of about 42B tokens a day (Feb 2026) to about 7–8B a day (April–August 2026). It earns about $280K per trillion tokens across all channels.

### Cited Findings
- **Scale (Menlo).** — [Menlo Ventures, Aug 19, 2026](https://menlovc.com/perspective/stripe-to-acquire-openrouter-why-everyone-is-obsessed-with-model-routing/)
  - About "~30,000x" growth since launch, to a "4.5+ quadrillion-token annual run rate".
  - "33% MoM" growth for three years, doubling every 11 weeks.
  - More than 500 models from more than 80 providers, and "10M users". Spend is described only as "shockingly high".
  - OpenRouter has "easier to scale contracts with labs and have predictable demand for tokens", and new labs list there first for distribution.
- **Scale (Latent Space).** More than 10 million developers and more than 10 trillion tokens a day. A speaker said about 9% week-over-week token growth "sounds about right". — [Latent Space, Sep 2026](https://latent.space/p/openrouter/)
- **Revenue estimates (Sacra).** — [Sacra](https://sacra.com/c/openrouter/)
  - Annualized revenue of about $50M at the end of 2025, $140M in July 2026 and $160M in August 2026 (Sacra estimates).
  - Annualized inference spend above $100M by May 2025, up from about $19M at the end of 2024.
  - Customers spent $8M in May 2025, giving OpenRouter about $400K of revenue that month.
  - A "5% commission on all inference spend".
- **The Information** [snippet]. The Information reportedly put revenue at about $140M on Jul 29, 2026. The article is paywalled and was seen only through a summary. — [GetLatka](https://getlatka.com/companies/openrouter.ai)
- **Funding.**
  - A $113M Series B led by CapitalG at a $1.3B valuation. Most sources date it to May 2026; Tracxn says March 26. NVentures, ServiceNow Ventures, MongoDB Ventures, Snowflake Ventures and Databricks Ventures took part. — [Trending Topics](https://www.trendingtopics.eu/openrouter-investment-capitalg-others/); [Sacra](https://sacra.com/c/openrouter/)
  - Earlier: a $12.5M seed led by a16z (Feb 2025) and a $28M Series A led by Menlo (Apr 2025). — [Sacra](https://sacra.com/c/openrouter/)
- **The Stripe deal.**
  - Stripe "today announced that it has agreed to acquire OpenRouter" on Aug 19, 2026. — [Stripe newsroom](https://stripe.com/newsroom/news/stripe-agrees-to-acquire-openrouter); [CNBC](https://www.cnbc.com/2026/08/19/stripe-openrouter-fintech-ai-model-marketplace-.html); [OpenRouter blog index, "OpenRouter is Joining Stripe"](https://openrouter.ai/blog/)
  - Bloomberg reported a price above $7B on Aug 16. — [Bloomberg](https://www.bloomberg.com/news/articles/2026-08-16/stripe-nears-deal-to-buy-ai-firm-openrouter-for-over-7-billion)
  - Citing the NYT, TechCrunch reported $7.5B, said OpenRouter would keep operating independently, and expected a close within weeks [snippet]. — [TechCrunch, Aug 19](https://techcrunch.com/2026/08/19/stripe-didnt-really-buy-openrouter-because-of-the-singularity/)
  - The Latent Space episode blurb says Stripe "just bought the best known one for $7B". — [Latent Space](https://latent.space/p/openrouter/)
- **Has the deal closed? Sources conflict.**
  - Trade outlets report a close on Nov 10, 2026 [snippets]. — [TokenPost](https://www.tokenpost.com/news/business/54341); [daily.dev](https://daily.dev/posts/stripe-completes-its-acquisition-of-openrouter-ehbcesfrl); [Glitchwire](https://glitchwire.com/news/stripe-closes-75-billion-openrouter-acquisition-as-ai-token-traffic-hits-record/)
  - OpenRouter's blog index, fetched Nov 24, 2026, has no closing post. Its only Stripe post is "OpenRouter is Joining Stripe" (Aug 19). — [OpenRouter blog](https://openrouter.ai/blog/)
  - An undated Stripe careers listing says the acquisition "is under regulatory review and has not yet closed" [snippet]. — [Stripe careers](https://stripe.com/careers/listing/technical-recruiter-openrouter-fixed-term/8404144?gh_jid=8404144)
- **Chutes's earnings per token.** "Today the platform earns around $280K for every trillion tokens that move through it", and "A year ago we earned almost nothing per token we served". The article does not split out OpenRouter. — [TAO Media, Jun 3, 2026](https://www.tao.media/chutes-revenue-per-trillion-tokens-reaches-280-000/)
- **Chutes's OpenRouter volume and revenue** (independent secondary analysis, revised through Oct 2026). — [ownyourmind.ai](https://ownyourmind.ai/tokenomics/chutes-bittensor-revenue-machine/)
  - OpenRouter volume: a peak of about 42B tokens a day on Feb 7, 2026; 8–12B a day in late March; about 6.8B a day across 18 models in April; an average of 7.8B a day over the latest 89 days.
  - Chutes claims 160B tokens a day "across all surfaces", 24 times what OpenRouter measures.
  - Pine Analytics' bear case (Mar 24, 2026) puts Chutes's external revenue at $1.3–2.4M a year. The "approaching $10M ARR" claim traces to an Altcoin Buzz post.
  - Chutes's own published daily revenue averaged $15.6K a day over its last 90 published days, peaking at $22.5K on Mar 25, 2026. The series was withdrawn in mid-2026.
  - Subnet 64's share of TAO emissions fell from 14.39% (March 2026) to 6.55% (Aug 15) and 5.82% (Sep 22, 2026). Pine estimated the subsidy at 22–40 times customer revenue.
  - Unsubsidized break-even is about $1.41 per million tokens.
- **Another channel for provider traffic.** On Nov 16, 2026, OpenRouter posted "OpenRouter Now Powers Inference on Hugging Face". — [OpenRouter blog](https://openrouter.ai/blog/)

### Inferences
- [inference, rough] **Implied GMV and blended price.**
  - $140–160M of revenue at a 5–5.5% take implies about $2.5–3.2B a year of paid inference flowing to providers. This ignores BYOK fees, the 8% Business plan and Enterprise fee discounts, so it is only an order of magnitude.
  - Spread over about 4.5 quadrillion tokens a year, that is roughly $0.6–0.7 per million tokens. That count includes free and BYOK tokens, so the average paid token costs more.
- [inference, illustration only] **Chutes's OpenRouter revenue.** 7.8B tokens a day at a blended $0.28 per million is about $2.2K a day, or about $0.8M a year. This is not a disclosed figure, and Chutes's OpenRouter prices vary by model.
- [inference] **OpenRouter versus selling direct.**
  - The provider gets its full list price on OpenRouter, with no visible revenue share.
  - OpenRouter brings distribution to about 10 million users and handles payment, fraud and chargebacks. It now also feeds Hugging Face inference.
  - The costs: users pay 5–8% more than buying direct at the same list price; default routing sends traffic to the provider with the lowest effective cost; payment arrives at least 30 days late; and OpenRouter owns the customer relationship.
  - The 20VC remarks (Enterprise deals remove fees; BYOK can eliminate the fee) suggest large users may move to BYOK or Enterprise. BYOK requests would bill the provider's own account, which helps a provider with direct accounts.

### Gaps
- I found no provider that publicly discloses its OpenRouter revenue or its payment terms.
- Per-provider token shares are visible on OpenRouter's site, as cited by ownyourmind, but I did not pull current figures.
- The Information's figures could not be read directly (paywall).

## 7. Taxes, invoicing, the legal entity and the terms that govern providers

### Takeaway
User prices exclude taxes; VAT or GST may be added to invoices where required. Card buyers get Stripe receipts, and Enterprise customers can use invoices and purchase orders. The counterparty is OpenRouter, Inc., 169 Madison Avenue, New York, NY 10016. New York law governs, and disputes go to AAA arbitration; the user Terms were last updated Aug 31, 2026, after Stripe's announcement. Providers sign a mutual NDA, accept provider terms online that are not public, and invoice OpenRouter monthly. Stripe announced the acquisition on Aug 19, 2026, but whether it has closed is disputed as of Nov 24, 2026.

### Cited Findings
- **User-side taxes and receipts.** Prices exclude taxes, and VAT/GST may be added to invoices where required. — [Pricing](https://openrouter.ai/pricing)
  - Card purchases produce a Stripe receipt email. Credits can take up to an hour to appear ("Please allow up to one hour"). — [FAQ](https://openrouter.ai/docs/faq)
- **Entity, law and disputes.** — [Terms](https://openrouter.ai/terms)
  - The entity is "OpenRouter, Inc.", at "169 Madison Avenue, New York, NY 10016, United States". The Terms do not state the state of incorporation.
  - "Last Updated: August 31, 2026".
  - "These Terms are governed by the laws of the State of New York", with "exclusive jurisdiction" in the state and federal courts of New York, NY.
  - Disputes go to binding AAA arbitration, with a class-action waiver.
- **Taxes in the Terms.** The Terms have no general tax-allocation clause. The only tax wording is that promo credits "will not be applied against any sales, use, gross receipts" taxes. — [Terms](https://openrouter.ai/terms)
- **Terms that touch providers.** — [Terms](https://openrouter.ai/terms)
  - Model Terms are linked in §5.1, and a separate "Stealth Program End User License Agreement" is incorporated by reference.
  - Model Providers are third-party beneficiaries of §§5, 6.1, 15, 17 and 20.
  - "OpenRouter does not guarantee availability of any Model."
  - The Terms never describe OpenRouter as a reseller, agent or marketplace. They speak only of "access to Models provided by Model Providers".
- **The provider contract.** It is an NDA plus provider terms accepted online during onboarding, alongside a security questionnaire and security documents. Providers invoice OpenRouter monthly. — [Become a Provider](https://openrouter.ai/providers/apply)
- **Ownership.** The Stripe deal was announced on Aug 19, 2026. Its close is disputed as of Nov 24, 2026; see section 6 for sources. — [Stripe newsroom](https://stripe.com/newsroom/news/stripe-agrees-to-acquire-openrouter); [OpenRouter blog](https://openrouter.ai/blog/)

### Inferences
- [inference] A provider invoices OpenRouter, Inc. for business-to-business services. How sales tax and VAT apply depends on the provider's entity and location, and nothing public covers it.
- [inference] **The legal relationship.** The Terms call providers "Model Providers" who keep "sole control" and benefit as third parties. OpenRouter pays them on invoice while users pay OpenRouter. In practice, OpenRouter is the buyer of record of inference from providers and resells it to users at pass-through prices plus a fee. It is not a payment agent that sends user funds on to providers. The Terms do not state this outright.
- [inference] After a Stripe close, the contracting entity would likely remain OpenRouter, Inc., as a subsidiary. Unverified.

### Gaps
- Not public:
  - the provider terms text;
  - required tax forms (W-9 or W-8BEN-E) and 1099 reporting;
  - the invoice format and any self-billing or statement mechanism;
  - how OpenRouter handles VAT on non-US providers' invoices.
- Out of billing scope, but relevant to a "most private" listing and not reviewed here:
  - "Introducing Safety Retention: A Clearer Choice for AI Privacy" (Oct 26, 2026);
  - "CSAM Screening Across OpenRouter" (Oct 27, 2026);
  - "Data Processing Incidents on Inference Providers" (Nov 22, 2026);
  - in routing, `zdr: true` still allows "Safety Retention endpoints" unless the user's privacy settings exclude them. — [OpenRouter blog](https://openrouter.ai/blog/); [Provider routing docs](https://openrouter.ai/docs/features/provider-routing)

## 8. What this means for URnetwork: margin, cash flow and settlement

### Takeaway
As a listed provider, URnetwork would set its own USD list prices. From the public material, it would receive 100% of list price times billed tokens, with no revenue share; OpenRouter's 5–8% is charged to users. It would invoice OpenRouter monthly in USD. It would carry the float: it pays its Bittensor suppliers in gamma, a US-dollar service credit that is presumably prepaid, while OpenRouter pays at least a month in arrears on undisclosed terms. Its margin is list price minus gamma cost, less work that cannot be billed. That includes zero-output responses, aborts not passed upstream, failed requests and any free endpoints.

### Cited Findings
- **Pricing and payment.** Providers set their own USD per-token prices. They are paid "based on actual token usage through monthly invoicing", and invoicing is the only payment term accepted for onboarding. — [Become a Provider](https://openrouter.ai/providers/apply)
- **No markup; user-side fees.** OpenRouter adds no markup; its fees are 5.5% (minimum $0.80), 8% on Business and 5% on crypto, all charged to users. — [FAQ](https://openrouter.ai/docs/faq); [Pricing](https://openrouter.ai/pricing)
- **Free endpoints.** Free endpoints "always have zero cost". — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **Zero-output responses.** Users are not charged even when "OpenRouter may have been charged by the provider for prompt processing". — [Zero Completion Insurance](https://openrouter.ai/docs/guides/features/zero-completion-insurance)
- **Aborted streams.** Billing stops at the abort only for providers that support cancellation. Chutes is on the supported list. — [Streaming docs](https://openrouter.ai/docs/api-reference/streaming)
- **Uptime.** 95% or more keeps standard routing priority. Errors 401, 402, 404, 5xx and mid-stream errors count against uptime. — [Become a Provider](https://openrouter.ai/providers/apply); [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)
- **Default routing** weighs effective price, speed, reliability and tool-call quality. Users can pin a provider (`only`/`order`) or filter with `zdr`/`data_collection`. — [Provider routing docs](https://openrouter.ai/docs/features/provider-routing)
- **Abuse-report user IDs.** Per-user IDs for abuse reports go only to providers "whose data policy requires user ids". — [Provider integration docs](https://openrouter.ai/docs/guides/community/for-providers)

### Inferences
- [inference] **Margin per token.** URnetwork's listed price × (1 − `discount_to_user`), minus:
  - the gamma cost of the Chutes or Bittensor tokens consumed;
  - TEE gateway and attestation overhead;
  - work it cannot bill: zero-output responses if the provider terms exclude them, tokens produced after an abort when the abort is not passed to Chutes, 5xx failures, and any `:free` traffic.
  - Competitive limit: OpenRouter users pay URnetwork's price plus 5–8%. Default routing will undercut a premium private endpoint unless users pin it or filter to ZDR-only providers.
- [inference] **Cash-flow gap.** URnetwork's working capital need is roughly monthly OpenRouter volume at gamma cost × (1 month of accrual + the payment term). If the terms are net-30, which is unverified, that is about 60 days of supplier cost carried before cash arrives. OpenRouter, by contrast, collects from users up front.
- [inference] **Settlement mismatch.** OpenRouter pays in USD fiat, on a rail not disclosed. Gamma is a per-subnet US-dollar credit, presumably bought through crypto (TAO or alpha). URnetwork would carry the conversion between the two and any timing or FX exposure. No crypto payout is documented that could close the loop.
- [inference] **Token-count risk.** OpenRouter bills users on native-tokenizer counts and "reconcile[s] token counts automatically". If URnetwork's own metering and Chutes's billing count differently, URnetwork absorbs the gap. It should meter with the model's native tokenizer and keep per-request logs for disputes. It would have to square those logs with its plaintext-free design, for example by logging counts only.
- [inference] **Counterparty and fraud.** OpenRouter carries user-side fraud and chargebacks. URnetwork's credit exposure is to OpenRouter, Inc., which is Stripe-owned if the close is confirmed. Default risk looks low, but the payment term is unknown.
- [inference] **Avoid 402s.** If URnetwork's gamma balance at a subnet runs out and it returns 402s, those count against uptime. It should keep upstream credit topped up, and return 429 rather than 402 when capacity is short; 429s do not count against uptime.

### Gaps
- What URnetwork must learn under the NDA or provider terms before deciding:
  - net payment days;
  - minimum payout;
  - payout rail and currency options, including any USDC payout;
  - whether zero-output responses and errored requests can be invoiced;
  - how reconciliation and disputes work;
  - whether any fee or offset exists on the provider side;
  - whether OpenRouter would pay for free capacity;
  - whether payouts move to Stripe rails after the acquisition.
