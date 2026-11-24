# Parallel's keyless, pay-per-request Search and Extract (parallelmpp.dev): can a device call it directly, paid by an authorization URnetwork signs? (as of 2026-11-23)

Method note. The 402 challenges below are from live, unpaid requests to `https://parallelmpp.dev`, sent 2026-11-23 between 18:39 and 18:41 UTC with neutral queries. No payment, credential or forged header was sent, and no account was created. Each unpaid request appears to create a Stripe PaymentIntent on Parallel's side (see Q1), so only eight paid-endpoint POSTs were sent, plus free GETs of `/api`, `/api/x402/status`, `/openapi.json` and the home page. Every other statement cites a document. Inferences are marked.

## 1. The payment flow at Parallel's agentic-payments gateway

### Takeaway
`parallelmpp.dev` is Parallel's own gateway, launched 2026-03-18. It proxies Search, Extract, Task and Responses for a flat price: $0.01 per search in any mode, and $0.01 per URL for Extract.

Each unpaid request gets one 402 that offers two rails:
- an x402 v2 `exact` offer: USDC on Base by EIP-3009, settled through Coinbase's CDP facilitator, `maxTimeoutSeconds` 300;
- an MPP `tempo`/`charge` challenge: USDC on Tempo.

The signing step matches the Brave design: nothing in the signed authorization is bound to the query, so a party that never sees the request can sign it.

Two things do not match:
- **No fixed payee.** `payTo` is a new Stripe deposit address on every 402, so the broker cannot pin a payee address in its policy.
- **Failed calls are charged.** Parallel says payments are final and settled before the result ("No refunds"). Brave never charges a failed search.

### Cited Findings

#### What it is and what it covers
- Parallel's docs: "The Parallel MPP gateway at `parallelmpp.dev` exposes Parallel's Search, Extract, and Task APIs with pay-per-use pricing". Three ways to pay are listed: "Stripe: Pay with a credit card — no crypto wallet required"; "Tempo stablecoins: Pay with pathUSD or USDC on the Tempo blockchain"; "x402: Pay with USDC on Base using the x402 protocol". — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments)
- Paid endpoints in the docs table: `POST /api/search` $0.01; `POST /api/extract` "$0.01/url"; `POST /api/task` "0.30 (ultra)". Free: `GET /api` (schema), `GET /api/task/{run_id}`, `GET /api/wallet/balance/{address}`. — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments)
- The live schema (`GET /api`, read 2026-11-23) also lists `POST /api/responses` ("$0.01 low / $0.05 medium / $0.25 high") and `GET /api/x402/status`. Task is "$0.30 (ultra) / $0.10 (pro)". Search's body is "objective + search_queries, or query (mapped to objective). Optional mode: turbo | fast | basic | advanced". Extract's body is `urls: string[]`, `objective: string?`, "$0.01 per URL provided (minimum $0.01)". — [parallelmpp.dev/api](https://parallelmpp.dev/api) (live JSON)
- The gateway's OpenAPI document gives Search only `query`, `objective`, `search_queries` and `mode`, with `mode` "default": "fast". Extract gets only `urls` and `objective`. — [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json) (live)
- Launch: "March 18, 2026 — Parallel on Machine Payments Protocol" — [Parallel changelog](https://docs.parallel.ai/resources/changelog). The launch post: "Parallel's APIs are live on MPP from day one, enabling agents to discover and pay per use … with no account setup or human in the loop." — [Parallel blog, 2026-03-18](https://parallel.ai/blog/tempo-stripe-mpp)
- Parallel's engineering post "How we built parallelmpp.dev" (May 5, 2026, by Son Do) says it is "a gateway that puts Parallel's Search, Extract, and Task APIs behind HTTP 402 Payment Required. An agent can call it without an API key, without a contract… It pays per request in the rail of its choice (Tempo stablecoins, or x402 on Base), gets back the same response shape Parallel customers see today". — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- Hosting: the responses carry `server: Vercel` and `x-vercel-id: cle1::iad1::…`. — live headers from [parallelmpp.dev/api](https://parallelmpp.dev/api)
- The gateway calls Parallel's API with a key of its own. Its OpenAPI lists these errors for `/api/responses`: "503 Responses API unavailable or API key not configured", "502 Upstream connection failure", "504 Upstream request timed out", "422 Upstream validation error". — [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json)

#### The exact 402, captured live (unpaid `POST /api/search`, body `{"query":"weather","mode":"fast"}`, 2026-11-23 18:40:09 UTC)
- Status `HTTP/2 402`. Headers include a base64 `payment-required` header and a `www-authenticate: Payment …` header, and the body repeats the x402 object. — live request to [parallelmpp.dev/api/search](https://parallelmpp.dev/api/search)
- The decoded `PAYMENT-REQUIRED` header (identical to the JSON body):
  ```json
  {"x402Version":2,"error":"Payment required",
   "resource":{"url":"https://parallelmpp.dev/api/search","description":"Parallel /api/search endpoint","mimeType":"application/json"},
   "accepts":[{"scheme":"exact","network":"eip155:8453","amount":"10000",
     "asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
     "payTo":"0xe21e4331fea71c12a8a5cd21001088a646346699",
     "maxTimeoutSeconds":300,"extra":{"name":"USD Coin","version":"2"}}]}
  ```
  — live, [parallelmpp.dev/api/search](https://parallelmpp.dev/api/search)
  - The offer has no `extra.assetTransferMethod`; under the spec, clients "default to `eip3009`" — [x402 exact EVM scheme](https://github.com/coinbase/x402/blob/main/specs/schemes/exact/scheme_exact_evm.md).
  - It has no `extra.paymentFlow`; the spec's default flow is "`authorization` … verify → resource → settle → respond" — [x402 v2 spec](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md).
  - It has no extensions, such as `payment-identifier`.
  - The asset is the USDC contract Stripe lists for Base — [Stripe x402](https://docs.stripe.com/payments/machine/x402).
- The MPP challenge on the same response:
  - `Payment id="MeOR_0C1RO_uU-_r8LQ4UuzMBZbzgEC3UbjZOE4-ziU", realm="parallelmpp.dev", method="tempo", intent="charge", expires="2026-11-23T18:45:09.501Z"`, that is, five minutes later.
  - `request` decodes to `{"amount":"10000","currency":"0x20c000000000000000000000b9537d11c60e8b50","methodDetails":{"chainId":4217},"recipient":"0x40b3ec4aec3518ccdd30c5bb5ea0cc0fcb1da47d"}`.
  - `opaque` decodes to `{"_mppx_scope":"POST /api/search"}`.
  - There is no `digest`. There is no second `WWW-Authenticate` with `method="stripe"`, so no card offer.
  - Source: live, [parallelmpp.dev/api/search](https://parallelmpp.dev/api/search).
  - The currency is the token Stripe lists as "Tempo | USDC | `0x20c000000000000000000000b9537d11c60e8b50`" — [Stripe x402](https://docs.stripe.com/payments/machine/x402). Chain ID 4217 is Tempo mainnet — [Tempo docs index](https://docs.tempo.xyz/llms.txt).
- Seven more unpaid requests. **Both payees changed every time**: x402 `payTo` and MPP `recipient` were different addresses on every response (eight distinct of each across all eight requests). Amounts and timeouts:

  | Request | x402 `amount` | `maxTimeoutSeconds` |
  |---|---|---|
  | search, `mode` fast, advanced, turbo, or basic with `max_results: 40` | 10000 ($0.01) | 300 |
  | extract, 1 URL | 10000 | 300 |
  | extract, 3 URLs | 30000 | 300 |
  | responses, `effort: high` | 250000 | 300 |
  | task, `pro` | 100000 | 300 |

  MPP `opaque` scope followed the route (`POST /api/extract` and so on). — live requests to parallelmpp.dev, 2026-11-23

#### Why the payee changes: per-request Stripe deposit addresses (primary source)
- Parallel's engineering post:
  - "Stripe's preview API for crypto PaymentIntents returns a Tempo and Base deposit address. We cache that address in a small in-memory set, return it as the recipient on the 402 challenge, and on retry, confirm the credential references an address from our cache before passing the request to mppx or purl for verification."
  - The code shown creates a PaymentIntent with `mode: 'deposit'` and `networks: ['tempo','base']` on each unpaid request. On retry it rejects a recipient not in `validPayToAddresses` ("Invalid payTo address: not found in server cache").
  - "The cache is leak-tolerant by design. If we lose it during a deploy, the worst case is a few in-flight credentials that 500 instead of 200 because the recipient isn't recognized; the agent retries, gets a fresh challenge".
  - Source: [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev).
- Stripe's x402 sample used the same pattern until 2026-08-05:
  - Its 2026-04-15 version "Creates a new Stripe PaymentIntent to generate a fresh deposit address" on each 402.
  - It keeps a `NodeCache({ stdTTL: 300 })` of addresses and on retry checks `payload.authorization.to` against it.
  - Source: [stripe-samples/machine-payments x402 main.ts @35be9b9](https://github.com/stripe-samples/machine-payments/blob/35be9b9bd93b011f344f1bf474579534a3f009b5/x402/server/node-typescript/main.ts).
- The sample's 2026-08-05 commit is "x402: use deposit address API, remove double-spend cache" — [commit history](https://github.com/stripe-samples/machine-payments/commits/main/x402/server/node-typescript/main.ts). Stripe's current guide says "Use the deposit address from the previous step as the static `payTo` recipient" and records each settled transaction with `transaction_verification` — [Stripe x402](https://docs.stripe.com/payments/machine/x402).
- MPP's docs: "Use Stripe to create a dynamic recipient address per payment, each backed by a PaymentIntent." — [MPP Tempo charge](https://mpp.dev/payment-methods/tempo/charge)
- Stripe deposit mode: "The token amount that your customer transfers must exactly match the amount on the `PaymentIntent`". "If your customer sends funds after the `PaymentIntent` expires, we can't automatically match or return the funds." Detection "can take a few minutes". — [Stripe deposit mode](https://docs.stripe.com/payments/deposit-mode-stablecoin-payments)

#### Facilitator and settlement
- `GET /api/x402/status` returned `{"enabled":true,"network":"eip155:8453","facilitator":"https://api.cdp.coinbase.com/platform/v2/x402","payment_header":"X-Payment","client":"purl"}`. — live, [parallelmpp.dev/api/x402/status](https://parallelmpp.dev/api/x402/status)
- The schema's routing text:
  - "`X-Payment: <base64-proof>` → verify Base USDC via CDP facilitator".
  - x402 steps: "402 with x402 accepts body (USDC deposit address on Base)… purl signs + sends USDC on Base → X-Payment: <proof>… CDP facilitator verifies on-chain → 200".
  - MPP steps: "Server verifies → 200 + Payment-Receipt header".
  - Source: [parallelmpp.dev/api](https://parallelmpp.dev/api).
- Tempo rail: "The mppx CLI signs a transfer on Tempo, and the gateway verifies it with getTransactionReceipt". The route handler "sees a 200, a Payment-Receipt header, and a parsed body". — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- CDP facilitator: "OFAC and Know Your Transaction (KYT) checks identify and decline payments involving sanctioned or high-risk addresses". The seller's fees are the first 1,000 on-chain transactions a month free, then $0.001 each; "Payment verification is always free". "With `exact` and EVM `upto`, each accepted payment settles in one onchain transaction." It supports `exact`, `upto` and `batch-settlement` on Base. — [CDP facilitator](https://docs.cdp.coinbase.com/x402/core-concepts/facilitator)

#### What the payer signs, and whether it is bound to the request
- x402 `exact` EIP-3009: the payload carries `signature` and `authorization {from, to, value, validAfter, validBefore, nonce}`. Settlement calls `transferWithAuthorization` "with the `payload.signature` and `payload.authorization` parameters from the `PAYMENT-SIGNATURE` header". — [x402 exact EVM](https://github.com/coinbase/x402/blob/main/specs/schemes/exact/scheme_exact_evm.md)
- The v2 `PaymentPayload` has `resource` (optional), `accepted` (the chosen requirements) and `payload`. The client sends it in `PAYMENT-SIGNATURE` and gets `PAYMENT-RESPONSE` back with the settlement's `transaction`. — [x402 v2 spec](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md); [x402 v2 HTTP transport](https://github.com/coinbase/x402/blob/main/specs/transports-v2/http.md)
- Reference verifier checks (CDP's hosted rules are not published):
  - `authorization.to` must equal `requirements.payTo` (`ErrRecipientMismatch`).
  - "Verify validBefore is in the future (with 6 second buffer for block time)".
  - "Verify validAfter is not in the future".
  - "Verify amount exactly matches requirements".
  - The nonce must be unused.
  - Source: [x402 facilitator eip3009.ts](https://github.com/coinbase/x402/blob/main/typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009.ts).
- The reference client sets `validAfter: "0"`, `validBefore: now + maxTimeoutSeconds` and a random 32-byte nonce. — [x402 client eip3009.ts](https://github.com/coinbase/x402/blob/main/typescript/packages/mechanisms/evm/src/exact/client/eip3009.ts)
- MPP binding:
  - "Servers must bind the `id` to the expected Challenge parameters". For HMAC-bound IDs the binding covers "`realm | method | intent | request | expires | digest | opaque`". `digest` is the optional "Request-body digest in `sha-256=:<base64>:` format". — [MPP Challenges](https://mpp.dev/protocol/challenges)
  - Parallel's challenges are stateless: "The challenge has an ID field that is an HMAC-SHA256 of the challenge parameters: realm, method, intent, request body, and expiry… We never write the issued challenge anywhere." — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- MPP credential: it echoes the challenge and carries `source` ("Identity of the payer") and a method payload. Tempo payload types are `transaction` ("Signed Tempo transaction before broadcast"), `hash` ("On-chain Receipt for the submitted transaction"), `proof` and `zone`. "Payment proofs must be accepted at most once." — [MPP Credentials](https://mpp.dev/protocol/credentials)
- On Tempo: "the client signs a TIP-20 `transfer` transaction, the server broadcasts it to Tempo, and settlement completes in ~500ms with deterministic finality. The client adds a Challenge-bound attribution memo to the primary transfer". — [MPP Tempo charge](https://mpp.dev/payment-methods/tempo/charge)

#### Errors, retries, refunds
- Live schema: "All payments are final. No refunds are available once a transaction is confirmed on-chain." "Payments are settled immediately via Tempo and cannot be reversed. Please verify your request parameters before submitting paid endpoints." — [parallelmpp.dev/api](https://parallelmpp.dev/api)
- Gateway OpenAPI: `/api/responses` "400 Invalid request; checked before payment". Search and Extract list 400, 402 and 429 ("Rate limit exceeded (60 req/min)"). — [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json)
- Task: "today, the gateway charges at submission and lets the run play out". — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- Parallel's own API charges Task and Responses only for success ("Failed runs are not billed"; "You are only charged for successful responses"). It says no such thing for Search or Extract. — [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing)
- A facilitator "MAY return `settlement_pending`… with the broadcast transaction hash… so the caller can reconcile on chain before retrying". — [x402 exact EVM](https://github.com/coinbase/x402/blob/main/specs/schemes/exact/scheme_exact_evm.md)
- Stripe refunds of deposit-mode payments go "to the sending wallet address from the detected on-chain transaction". — [Stripe deposit mode](https://docs.stripe.com/payments/deposit-mode-stablecoin-payments)

#### Conflicts in Parallel's own material
- **Payment header name.** `/api` and `/api/x402/status` say `X-Payment`, the x402 v1 name. The challenge is x402 v2, whose header is `PAYMENT-SIGNATURE`. Parallel's documented client, Stripe's `purl`, sends `PAYMENT-SIGNATURE` for v2 and `X-PAYMENT` only for v1 — [purl protocol.rs](https://github.com/stripe/purl/blob/HEAD/lib/src/x402/protocol.rs). The current x402 server SDK reads only `payment-signature` — [x402HTTPResourceServer.ts](https://github.com/coinbase/x402/blob/main/typescript/packages/core/src/http/x402HTTPResourceServer.ts).
- **x402 rail status.** The home page's pre-rendered HTML says "purl / x402 on Base (USDC) — disabled (no CDP keys set on this server)", and its prompt points at `http://localhost:3000`. The live `/api/x402/status` says `"enabled":true`, and every live 402 carried an x402 offer. — [parallelmpp.dev](https://parallelmpp.dev/)
- **Card payments.** The docs offer "Stripe: Pay with a credit card". The live challenge has no Stripe method — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments); live 402.
- **Tempo token.** The gateway's text says "pathUSD on Tempo". The live challenge's currency is the token Stripe lists as Tempo USDC. — [parallelmpp.dev/api](https://parallelmpp.dev/api); [Stripe x402](https://docs.stripe.com/payments/machine/x402)
- **Default search mode.** The docs call `advanced` "(highest quality, default)". The gateway's OpenAPI says `"default": "fast"`. — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments); [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json)

### Inferences
- **Fit with the Brave design (§21.5), point by point.**

  | Step in the design | Brave x402 | Parallel gateway | Fit |
  |---|---|---|---|
  | Scheme | x402, `exact`, EIP-3009, USDC on Base | x402 v2, `exact`, EIP-3009, USDC on Base (`eip155:8453`), `extra {"USD Coin","2"}` | same |
  | Payer signs without seeing the request | yes | yes: the signature covers `from, to, value, validAfter, validBefore, nonce` only; `resource` and `accepted` are unsigned | same |
  | Device-chosen 32-byte nonce | yes | yes (EIP-3009 nonces are random, not sequential) | same |
  | Offer window | 300 s | `maxTimeoutSeconds` 300; the reference verifier needs `validAfter ≤ now` and `validBefore ≥ now + 6 s`; the design's window (minute start −60 s to +240 s) passes | fits, if CDP's hosted checks match the reference |
  | **Payee pinned in the broker's policy** | one fixed address | **a new Stripe deposit address on every 402**, valid only while it sits in the gateway's cache | **does not fit** |
  | Value | fixed $0.005 | fixed $0.01 per search; extract $0.01 × number of URLs; must match exactly | fits; the broker must learn the URL count for Extract |
  | Facilitator | Brave's own, which pays gas | Coinbase CDP; it pays gas and runs KYT/OFAC screening | fits |
  | Failed call | "A failed search is never charged" | "All payments are final"; settled before the upstream call (inference below) | **differs**: failed calls are charged |
  | Who else is in the path | Brave | Vercel (gateway host, TLS ends there), then Parallel's API under the gateway's key; Stripe and Coinbase see payment metadata | differs |
  | Request surface | full Brave API | 4 Search fields, 2 Extract fields documented | differs (Q4) |

- **The payee change matters most.** The design rests on "the broker signs … only to the payee … pinned in its policy". Here every legitimate payee is a fresh, unannounced address, so the broker cannot tell Parallel's deposit address from an address the device made up. If the broker signs whatever `payTo` a device sends, a member's device can turn its budget into USDC paid to itself. Budgets bound this, but compute balance bought by card becomes cash-out-able. That is a fraud and money-transmission exposure, not just "spending their own budget at Brave". Three ways around it:
  - **(a) The broker fetches the challenge itself.** It sends its own unpaid `POST /api/search` with a dummy body and signs to the `payTo` that came back over TLS from parallelmpp.dev. The device then sends its real request with that payment. Parallel's code checks only that the recipient is in its cache (`validPayToAddresses.has`), not which request the address was issued for, so this should work. It is untested. Costs:
    - one extra HTTPS round trip from URnetwork's servers per search;
    - the broker's own IP is held to 60 a minute (if unpaid 402s count);
    - each one creates an abandoned Stripe PaymentIntent on Parallel's account;
    - on Vercel, an in-memory cache may be per instance, so a challenge served by one instance and redeemed on another could fail (the "500 instead of 200" the post describes).
    - It needs Parallel's agreement.
  - **(b) Ask Parallel to switch to one static deposit address per network.** This is the pattern Stripe has recommended since August 2026. The broker could then pin it exactly as it pins Brave's.
  - **(c) Use the account path** with short-lived credentials (Q5).
- **Settlement comes before the search runs.** The schema promises a 200 after "CDP facilitator verifies on-chain", the post says handlers see a "Payment-Receipt", and the refund notice says payments are final. Together these suggest settlement happens before Parallel's API is called, on both rails. The x402 spec's default would be verify, then run, then settle. If settlement is first, a 422, 502 or 504 from upstream, a timeout, or a lost answer is charged. The design's rule that "a nonce used means a search was delivered" no longer holds, so the dispute and refund path in §21.8 becomes the normal path for failures, at URnetwork's cost.
- **Tempo rail.** The gateway verifies with `getTransactionReceipt`, which means push mode: the client broadcasts the transfer itself. So the money moves before the gateway even checks the recipient against its cache. A cache miss (the "500 instead of 200") would then leave a paid transfer with no answer. This is not true of the x402 rail, where the recipient check comes before verify and settle.
- **Retries.** A retry can reuse an unsettled authorization only while its `payTo` is still in the gateway's cache and before `validBefore`. A retry after settlement fails on the used nonce. A retry after the gateway loses its cache needs a fresh challenge, a new `payTo` and a new signature, so the broker must accept more than one authorization per request id.
- **Header to send.** Send `PAYMENT-SIGNATURE`, as `purl` does for v2. `X-Payment` in Parallel's JSON looks stale. Only a paid call can confirm this.
- **Exact amounts.** Stripe needs the exact PaymentIntent amount and the verifier needs an exact `value`. A wrong value, a late settlement after the PaymentIntent expires, or a payment to a stale address cannot be matched or returned automatically.

### Gaps
- The CDP hosted facilitator's exact verify rules are not published: whether it caps `validBefore − now` at `maxTimeoutSeconds`, and its buffer.
- The lifetime of the gateway's `payTo` cache and of Stripe deposit-mode PaymentIntents is not stated.
- Not documented: whether a `payTo` issued for one request or route is accepted for another, and whether the cache is shared across Vercel instances.
- Whether the x402 rail settles before or after the upstream call is not stated outright; the above is inferred from Parallel's wording.
- Not verified, because it needs a paid call: whether `X-Payment` is also accepted, and whether the response carries `PAYMENT-RESPONSE` with the transaction hash.
- No document says what the gateway does after it settles and the upstream call then fails, beyond "No refunds".

## 2. The payer and the caller can differ

### Takeaway
Nothing ties the paying address to the HTTP client: there is no registration, KYC, session, API key or IP binding on the paid path. The only published limit is 60 requests a minute per IP, with nothing per payer. Nothing on the gateway caps a payer's spending; the payer has to enforce its own cap.

### Cited Findings
- No account is needed: "An agent can call it without an API key, without a contract, and without a human in the loop." — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev). "No account setup or human in the loop." — [Parallel blog, 2026-03-18](https://parallel.ai/blog/tempo-stripe-mpp)
- x402 verification recovers the payer from the signature ("Verify the signature is valid and recovers to the `authorization.from` address") and checks balance, amount, window, token and network. It never refers to the HTTP client. — [x402 exact EVM](https://github.com/coinbase/x402/blob/main/specs/schemes/exact/scheme_exact_evm.md)
- An MPP credential's `source` is the "Identity of the payer (address, DID, account ID)", and the server verifies the payment, not the caller. — [MPP Credentials](https://mpp.dev/protocol/credentials)
- Rate limit: "**Rate limit**: 60 requests/minute per IP. Space out calls and handle `429` responses with the `Retry-After` header." — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments). The gateway's OpenAPI repeats "Rate limit exceeded (60 req/min)" — [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json). The eight unpaid 402s carried no rate-limit headers — live.
- Parallel's API limits for key holders are 600 a minute each for Search and Extract by default, and 1,500 a minute on Scale, excluding Turbo. — [Parallel rate limits](https://docs.parallel.ai/getting-started/rate-limits); [Parallel pricing](https://parallel.ai/pricing)
- Per-payer budgets are future work at Parallel: "**per-agent budget headers**: a way for a caller to advertise its remaining spend on the request". — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- Account spend limits only notify: "Limits are notify-only; they never block requests." — [Parallel FAQs](https://docs.parallel.ai/resources/faqs)
- After settlement, Stripe records "the transaction hash, buyer wallet address, network, and token currency" on the charge. — [Stripe deposit mode](https://docs.stripe.com/payments/deposit-mode-stablecoin-payments)
- The gateway's browser UI says "Sign in with a Tempo account to run this endpoint". That applies to the web page, not to API callers. — [parallelmpp.dev](https://parallelmpp.dev/)

### Inferences
- The design's split works here: a device calls from an egress exit while URnetwork's broker-signed authorization pays.
- Parallel, Stripe and Coinbase see URnetwork's payer address on every paid search. Parallel also sees the exit IP and the query.
- The 60-a-minute limit is per exit IP, not per payer. Spreading devices across exits keeps each under it, but the AUP forbids circumventing "rate limits or other use limitations, including by orchestrating usage among multiple accounts" (Q6). Capacity needs a written agreement.
- All keyless traffic probably shares the gateway's own upstream key, so its aggregate limit (unknown) is a ceiling for everyone, URnetwork included.
- Each EIP-3009 authorization is single-use and for an exact amount, so each is self-capped. The design's broker budgets, rates and float are the only spending caps.

### Gaps
- No per-payer or per-wallet limit is published, nor whether one exists.
- The gateway's own upstream quota is not published.
- Not stated whether unpaid 402 responses count toward the 60-a-minute limit.

## 3. Data handling on the keyless path

### Takeaway
No terms are written for keyless or MPP use, and the gateway has no terms or privacy page. Parallel's Customer Terms bind anyone "accessing or using the Services", and its AUP covers use "through AI agents". Under those terms Parallel may train on inputs and outputs unless zero data retention (ZDR) is in place. ZDR needs Scale with a signed agreement, or Enterprise. The EU endpoint needs an enterprise agreement and an API key. So neither ZDR nor the EU endpoint can be had keylessly, and keyless queries pass through Vercel-hosted gateway code before they reach Parallel's API.

### Cited Findings
- Customer Terms, "Effective date: November 10, 2026": "By registering an account at Parallel's online customer platform…, accessing or using the Services, or clicking a box indicating your acceptance of this Agreement, you are creating a legally binding and enforceable contract where you, together with the entity indicated during your account creation… or for which you use the Services (collectively, 'Customer'), agree to be bound". — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- §1(b) defines "Customer Input" to include "queries used to instruct the Services". — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- §4(b):
  - Parallel gets "a nonexclusive, worldwide, royalty-free, perpetual, sublicensable license to use, copy, reproduce, distribute, and make derivative works of Customer IP for the purpose of (i) performing…; (ii) internally… developing and improving the Services…; and (iii) creating Aggregated De-Identified Data".
  - "Parallel may use Customer IP to train and improve the machine learning and other artificial intelligence models used to provide the Services. Customer IP used for training is not linked to any individual during training."
  - Source: [Parallel Customer Terms](https://parallel.ai/customer-terms).
- §4(d): "Before Customer use the Services to process any 'personal data'…, Customer shall separately execute Parallel's Data Processing Addendum". — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- No terms for the keyless path were found:
  - The Customer Terms, Privacy Policy, Terms of Service and AUP never mention MPP, x402, wallets, stablecoins, crypto or blockchain (keyword scan of the 2026-11-23 texts).
  - `parallelmpp.dev/terms` and `/privacy` return 404.
  - The gateway's only stated policy is its `refund_policy`.
  - Sources: [Customer Terms](https://parallel.ai/customer-terms); [Privacy Policy](https://parallel.ai/privacy-policy); [AUP](https://parallel.ai/acceptable-use-policy); [parallelmpp.dev/api](https://parallelmpp.dev/api).
- AUP, "Effective date: August 11, 2026": it "applies to anyone who uses or interacts with any of Parallel Web Systems, Inc.'s… products and services, including all uses and interactions by, with, or through AI agents and agentic features, and/or via any authorized resellers or passthrough access". — [Parallel AUP](https://parallel.ai/acceptable-use-policy)
- FAQ: "Under the standard Customer Terms, Parallel may use inputs and outputs, not linked to any individual, to train and improve the models behind its services. Enterprise plans with zero data retention exclude that use. Search API traffic sent to the EU endpoint is also excluded." Storage is "encrypted in transit (TLS 1.2+) and at rest in US-based data centers". — [Parallel FAQs](https://docs.parallel.ai/resources/faqs)
- ZDR: "Zero data retention is included on Scale as Hybrid ZDR. It turns on once a signed agreement is in place. Once active, synchronous APIs retain no content and asynchronous APIs retain it for up to 8 days." Scale costs "$1,000 per month… Annual is $10,000 per year… for $12,000 in credits". Enterprise has "Custom data retention". — [Parallel pricing](https://parallel.ai/pricing)
- EU endpoint:
  - "EU data residency is available through an enterprise agreement. It isn't available on self-serve plans."
  - "The EU endpoint accepts the same keys as `api.parallel.ai`."
  - Search there: "`mode` is required and must be `"basic"`", up to 20 results, "no live fetches".
  - "EU traffic runs with zero data retention by default."
  - "Billing, metrics, and edge logs (no content)" stay in the US.
  - Source: [Parallel EU data residency](https://docs.parallel.ai/resources/eu-data-residency).
- Privacy Policy, "Effective date: August 11, 2026":
  - "Where business customers use our API…, we process content submitted to those Services as a processor on behalf of the customer under our Data Processing Addendum, and the customer's own privacy policy governs that processing."
  - "We retain user device/IP data for as long as we need it to ensure that our systems are working appropriately, effectively and efficiently."
  - EU: "Search API requests sent to the EU endpoint are processed and served within the European Union, and we do not retain request or response content."
  - Source: [Parallel Privacy Policy](https://parallel.ai/privacy-policy).
- The gateway documents no EU route and runs on Vercel, function region `iad1` (live headers). It calls Parallel under a key of its own ("API key not configured"). — [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json)
- Customer Terms §2(b) and §4(b) on output (relevant to keeping results): output "shall be primarily for the use of one End Customer only, and shall not be copied, cached, stored, or made available to other End Customers or other third parties", and must not be stored to create "AI and Data Selling Services". — [Parallel Customer Terms](https://parallel.ai/customer-terms)

### Inferences
- **Which terms apply.** A keyless caller most likely becomes a "Customer" under the 2026-11-10 Customer Terms just by "accessing or using the Services", and is bound by the AUP. Whether that holds when the caller never touches the Customer Platform is untested, and Parallel should confirm it in writing.
- **Whose retention settings apply.** Upstream, every keyless query arrives at `api.parallel.ai` under the gateway's own key. Retention and training for keyless traffic are therefore those of the gateway's account, which Parallel does not describe. Nothing suggests that account has ZDR, so assume the default: content may be kept and used for training, de-linked from individuals. The default retention period is not published.
- **Who sees the query.** Compared with Brave, keyless Parallel adds Vercel to the path, as Parallel's host, with TLS ending there. Payment metadata (payer address, amount, time, transaction hash) reaches Stripe and Coinbase CDP. Neither sees the query.
- **The EU endpoint cannot be paid keylessly.** It needs an enterprise agreement and an API key, and the gateway runs in the US and calls the US API.
- **Getting ZDR or EU processing.** Either needs an account and a contract: Scale's Hybrid ZDR, Enterprise, or the enterprise EU option. That means leaving the keyless path for the credential path in Q5, or getting Parallel to run the gateway's upstream under ZDR terms for URnetwork.

### Gaps
- Default retention of Search and Extract inputs and outputs for non-ZDR traffic is not published, and nothing covers gateway traffic.
- Not published: whether the gateway logs request bodies, and what Vercel logs.
- No MPP or x402-specific privacy notice exists to quote. Brave, by contrast, discloses payer-address use and the public chain record.

## 4. The Search API's shape for agents (and Extract)

### Takeaway
Parallel's `/v1/search` takes:
- `objective` (up to 5,000 characters);
- one to five `search_queries` (required);
- `mode`: turbo, fast, basic or advanced;
- `max_chars_total`, `session_id`, `client_model`;
- `advanced_settings` holding `source_policy` (include and exclude domains, `after_date`), `fetch_policy` (`max_age_seconds` of at least 600, `as_of` for sales customers), `location` (a country code) and `max_results` (default 10).

It returns `search_id`, ranked `results` (`url`, `title`, an estimated `publish_date`, markdown `excerpts`), `warnings`, `usage` and `session_id`.

There is no news mode; freshness comes from `after_date` and live fetch. Turbo handles only English and Japanese.

The gateway documents only `query`, `objective`, `search_queries` and `mode` (default `fast`) for Search, and `urls` and `objective` for Extract, at $0.01 a call or URL. Parallel's own API charges $0.001 to $0.005.

### Cited Findings
- Request schema `V1SearchRequest`:
  - `search_queries` is required: "Concise keyword search queries, 3-6 words each. At least one query is required, provide 2-3 for best results".
  - `objective`, `mode` ("Defaults to `advanced` when omitted"), `max_chars_total`, `session_id` (≤1,000 characters), `client_model`, `advanced_settings`; `additionalProperties: false`.
  - `AdvancedSearchSettings`: `source_policy`, `fetch_policy`, `excerpt_settings` ("Ignored… deprecated"), `location` ("ISO 3166-1 alpha-2 country code"), `max_results` ("Defaults to 10").
  - Auth is the `x-api-key` header.
  - Source: [Parallel Search API reference](https://docs.parallel.ai/api-reference/search/web); [OpenAPI](https://docs.parallel.ai/public-openapi.json).
- Field limits: "One to five keyword queries, each 3-6 words and no more than 200 characters… The API drops queries after the fifth". `objective` is at most 5,000 characters. — [Search best practices](https://docs.parallel.ai/search/best-practices)
- `SourcePolicy`:
  - `include_domains` and `exclude_domains` accept domains, domain/path prefixes or bare suffixes such as `.gov`. "The combined number of entries in include_domains and exclude_domains cannot exceed 200".
  - `after_date` (RFC 3339 date): "Results will be limited to content published on or after this date".
  - "Search does not support path prefixes in `turbo` mode."
  - Sources: [Search API reference](https://docs.parallel.ai/api-reference/search/web); [Advanced search settings](https://docs.parallel.ai/search/advanced-search-settings)
- `FetchPolicy`: `max_age_seconds` ("Minimum value 600 seconds"), `timeout_seconds`, `disable_cache_fallback`, and `as_of` ("Serves the latest available version of each page captured at or before that cutoff. Contact sales for access."). — [Search API reference](https://docs.parallel.ai/api-reference/search/web)
- Live fetch is off by default: "By default, Search returns excerpts from pages Parallel has already indexed. If you leave `advanced_settings.fetch_policy` out…, Parallel won't fetch the source pages during that request." — [Advanced search settings](https://docs.parallel.ai/search/advanced-search-settings)
- Freshness: "For lower end processors in the Search API, our systems prioritize reduced latency over freshness." — [Parallel FAQs](https://docs.parallel.ai/resources/faqs)
- Response `V1SearchResponse`:
  - `search_id` ("`search_cad0…`"), `results` ("ordered by decreasing relevance"), `warnings`, `usage` (SKU items such as `sku_search`), `session_id`.
  - Each result has `url`, `title`, `publish_date` ("Estimated publish date… YYYY-MM-DD, if available") and `excerpts` ("formatted as markdown").
  - Errors are `{type:"error", error:{ref_id, message, detail}}`; a 422 is a validation error.
  - Source: [Search API reference](https://docs.parallel.ai/api-reference/search/web).
- Modes, latency and Parallel's own prices:

  | Mode | Latency | Price per 1,000 requests | Notes |
  |---|---|---|---|
  | `turbo` | ~200 ms | $1 | "Turbo currently supports English and Japanese-language queries. For broader multilingual coverage, use `basic` or `advanced`." |
  | `fast` | ~700 ms | $1 | Parallel's recommended default for agents |
  | `basic` | ~1 s | $5 | the only mode on the EU endpoint |
  | `advanced` | ~3 s | $5 | the API's default |

  "Per 1,000 results beyond the first 10 in a request | 1"; "Excerpt length doesn't affect the price." — [Search modes](https://docs.parallel.ai/search/modes); [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing)
- `location` accepts a listed set of country codes, among them `ar`, `au`, `at`, `be`, `br`, `ca`, `cl`, `cn`, `dk`, `fi`, `fr`, `de`, `gr`, `hk`, `in`, `id`, `it`, `jp`, `my`, `mx` and `nl`. — [Advanced search settings](https://docs.parallel.ai/search/advanced-search-settings)
- No news or recency mode is documented. The tools for recency are `source_policy.after_date` and `fetch_policy`. — [Source policy](https://docs.parallel.ai/resources/source-policy); [Search API reference](https://docs.parallel.ai/api-reference/search/web)
- Extract (`/v1/extract`):
  - Request: `urls` ("Up to 20 URLs", required), `objective`, `search_queries`, `max_chars_total`, `session_id`, `client_model`, and `advanced_settings {fetch_policy, excerpt_settings, full_content (bool or {max_chars_per_result}), links}`.
  - Response: `extract_id`, `results` (`url`, `title`, `publish_date`, `excerpts`, `full_content`, `acquired_at`, `links`), `errors` (`url`, `error_type`, `http_status_code`, `content`), `warnings`, `usage`, `session_id`.
  - Price "$1 / 1,000 URLs", "1–20 s".
  - Sources: [Extract API reference](https://docs.parallel.ai/api-reference/extract/extract); [OpenAPI](https://docs.parallel.ai/public-openapi.json); [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing).
- Gateway surface: Search accepts `query` ("Search query (shorthand for objective)"), `objective`, `search_queries` and `mode` (enum turbo, fast, basic, advanced; "default": "fast"). Extract accepts `urls` and `objective`. — [parallelmpp.dev/openapi.json](https://parallelmpp.dev/openapi.json)
- Gateway prices: $0.01 per search in every mode, including turbo, advanced and `max_results: 40`; $0.01 per Extract URL. — live 402s; [parallelmpp.dev/api](https://parallelmpp.dev/api)
- Gateway responses are "the same response shape Parallel customers see today". — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- Parallel's API returns a 422 when `max_results`, `source_policy` or `fetch_policy` are sent at the top level, or when only `objective` is sent. — [Parallel Agentic Payments page header](https://docs.parallel.ai/integrations/agentic-payments)

### Inferences
- **Gateway premium.** The gateway costs 10× Parallel's own price for turbo and fast search ($0.01 against $0.001), 2× for basic and advanced ($0.01 against $0.005), and 10× for Extract. It is twice Brave's x402 price of $0.005. With the design's 1.20 markup, a Parallel search would cost **$0.012** on the compute balance. Since the price is flat, `advanced` mode costs nothing extra on the gateway.
- **What the gateway loses.** The design's `site` and `freshness` parameters, Parallel's own `include_domains`, `exclude_domains`, `after_date`, `location`, `max_results` and `max_chars_total` are undocumented on the gateway.
  - One unpaid probe sent a top-level `max_results: 40` and still got a 402, not a 400. So the gateway does not reject unknown fields before payment.
  - Whether it forwards them, drops them, or passes a body that Parallel rejects with a 422 after payment is unknown.
  - Until tested, a device-direct client should send only the documented fields, and put domain and recency wishes into `objective` text. Parallel suggests the objective "can name preferred sources or how recent results should be" ([Parallel MCP docs](https://docs.parallel.ai/search/search-mcp)).
- **Search IDs.** `search_id` and `session_id` are Parallel-side identifiers. Reusing one `session_id` across a run's calls would let Parallel link those searches, which it does anyway by payer and exit. A device should start a new session per run, or omit the field.
- **Shaping text.** Parallel's results are already excerpt-shaped, like Brave's LLM Context, so `objective` plus 1–3 `search_queries` maps onto the design's single `query` by having the model supply both.

### Gaps
- Whether the gateway passes `advanced_settings` or any field beyond its four through to Parallel cannot be tested without paying.
- Parallel publishes no list of supported languages beyond Turbo's English and Japanese.
- No published latency figures for the gateway itself, which adds the 402 round trip, a Stripe PaymentIntent on each 402, and on-chain settlement.

## 5. Fewer on-chain payments

### Takeaway
Parallel's gateway offers no way around one public payment per call: only x402 `exact` and MPP Tempo `charge`, with no MPP sessions, no x402 `upto` or `batch-settlement`, no MPP credits and no prepaid gateway balance. Its card path is not live, and Stripe's card tokens have a $0.50 minimum in any case. The ways to avoid per-search payments are off the gateway: a funded Parallel account with credentials minted per device, or Parallel's free, rate-limited MCP tier. Each of these brings its own terms questions.

### Cited Findings
- The live challenge offers MPP `intent="charge"` only, and x402 `scheme: "exact"` only. — live 402s, [parallelmpp.dev/api/search](https://parallelmpp.dev/api/search)
- On MPP credits: "Fund with tokens (tempo wallet fund), not --credits — MPP Credits only work for Tempo-proxied services." The home page adds "this gateway does not accept MPP Credits". — [parallelmpp.dev/api](https://parallelmpp.dev/api); [parallelmpp.dev](https://parallelmpp.dev/)
- The CDP facilitator supports `upto` and `batch-settlement` on Base. With `batch-settlement`, "vouchers are verified offchain for free" and settlement costs are spread "across thousands of requests". — [CDP facilitator](https://docs.cdp.coinbase.com/x402/core-concepts/facilitator)
- MPP sessions exist and Stripe supports them: "For MPP sessions, you can charge users for work in sub-cent increments, but the minimum settlement amount is 0.01 USDC." — [Stripe machine payments](https://docs.stripe.com/payments/machine). Tempo sessions deposit into a channel and pay "without an on-chain transaction for each payment"; "the payer's address is public on Tempo". — [mpp.dev sessions](https://mpp.dev/payment-methods/tempo/session), via the earlier [bittensor_crypto_search notes §4](</Users/brien/urnetwork/sidecar/research_notes/Resellable web search APIs/bittensor_crypto_search.md>)
- Card path: "For card payments through Shared Payment Tokens (SPTs), the minimum amount is 0.50 USD." SPTs "are scoped grants that let an agent use a customer's payment method… Each SPT includes usage and expiration limits", issued from the "Link Agent Wallet". — [Stripe machine payments](https://docs.stripe.com/payments/machine); [Stripe MPP](https://docs.stripe.com/payments/machine/mpp)
- What paying by Tempo involves:
  - a Tempo wallet holding the challenge's currency (USDC on Tempo, chain 4217);
  - the client signs a TIP-20 transfer to the challenge's fresh recipient, with a challenge-bound memo;
  - settlement takes "~500ms with deterministic finality";
  - Parallel's gateway verifies with `getTransactionReceipt` (the client broadcasts);
  - the sender pays fees ("Wallet must hold a non-zero balance"); the challenge offers no `feePayer`.
  - Tempo also has "Zones" for private payments: "Set `zones` to accept payments from a Zone balance… Tempo shows the Zone's portal paying you instead of the payer's account". Parallel's challenge lists no zones.
  - Sources: [MPP Tempo charge](https://mpp.dev/payment-methods/tempo/charge); [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev); [parallelmpp.dev/api](https://parallelmpp.dev/api); live 402.
- Account path:
  - Build is pay-as-you-go with a prepaid balance and "auto-reload" — [Parallel Customer Terms §6(b)](https://parallel.ai/customer-terms); [Parallel pricing](https://parallel.ai/pricing).
  - The service API can create apps and keys and "Create OAuth Credential": "Create a refresh token for the product API in an app. Exchange it at `token_endpoint` for access tokens". "Each refresh extends" the refresh token's expiry. Scopes: "Only `*` is valid". Credentials can be revoked.
  - Usage is broken out "by product, processor, app, and API key".
  - Sources: [Create OAuth Credential](https://docs.parallel.ai/service-api/keys/create-oauth-credential); [Create Key](https://docs.parallel.ai/service-api/keys/create-key); [Parallel docs index](https://docs.parallel.ai/llms.txt).
- The Customer Terms have no clause against sharing API keys or credentials with Authorized Users. The only credential reference is §5(c)'s "Third-Party Credentials". §5(a) makes the Customer "solely responsible and liable for all uses of the Services… including all acts and omissions of Authorized Users". — [Parallel Customer Terms](https://parallel.ai/customer-terms) (keyword scan)
- Free keyless MCP: "No API key is required to get started: `web_search`, `web_fetch`, `web_decisions`, and `image_search` in `fast` mode are free at lower rate limits." Connect to `https://mcp.parallel.ai/mcp`; "Calls without a key are free and don't report usage." — [Parallel MCP](https://docs.parallel.ai/search/search-mcp)

### Inferences
- **On the keyless path every paid search is one public transfer.** On Base it goes from URnetwork's payer to a one-time Stripe deposit address; on Tempo the payer's address is public too. Because each search pays a different address, a casual observer cannot see "payments to Parallel" without tying the deposit addresses to Stripe, for example through its sweeps. This is untested. URnetwork's own outflow (count, times, $0.01 amounts) is as visible as with Brave.
- **Parallel could reduce this on its side.** The CDP facilitator it already uses supports `batch-settlement` on Base, and Stripe supports MPP sessions. URnetwork could ask Parallel to offer either. The design would then need channel or voucher signing in place of single EIP-3009 authorizations.
- **Credentials minted per device would remove on-chain payments altogether, and with them the variable-payee problem.** URnetwork's server would mint short-lived access tokens from an OAuth refresh credential for each device.
  - Unlike Brave's 4(a), Parallel's terms do not forbid this.
  - It also unlocks ZDR (Scale) and EU processing (Enterprise), at Parallel's direct prices ($0.001 to $0.005 a search).
  - Costs: tokens cannot be scoped below `*` (Task, FindAll and the rest included), Parallel's spend limits only notify, and a device holding a token can spend until it expires.
  - The token lifetime is not published.
  - The minting server sees only token requests, never queries, so this stays within the directive. Parallel would see URnetwork's account, as it sees the payer address on x402.
- **The free MCP tier is not a basis for a paid, metered product.** Its limits are not published. Spreading one product's traffic across many exits to stay under them risks the AUP's ban on circumventing rate limits. It also contradicts CO-16, under which every search is a charge. It could serve as an emergency fallback only with Parallel's written consent.

### Gaps
- The access-token lifetime and any per-token rate limit for OAuth credentials are not published.
- The free MCP tier's rate limits are not published.
- Parallel has stated no plan for sessions, `upto` or batch settlement on the gateway, beyond "per-agent budget headers" and "streamed 402 challenges for long Task runs".

## 6. Abuse and refusal

### Takeaway
Parallel publishes nothing on misuse of the keyless gateway, and says nothing about blocking a payer address. The gateway does see the payer address before it verifies: the x402 `authorization.from` and the MPP `source`. Coinbase's facilitator declines "sanctioned or high-risk addresses", and Parallel's AUP lets it "throttle, suspend, or terminate your access". So refusing URnetwork's payer is technically easy and contractually available. Only a written agreement would make it predictable.

### Cited Findings
- AUP: "If we detect or reasonably suspect a violation of this AUP by you or through your account, we may throttle, suspend, or terminate your access to our products and services." It covers use "through AI agents and agentic features". — [Parallel AUP](https://parallel.ai/acceptable-use-policy)
- The AUP forbids actions that impose "an unreasonable or disproportionately large load on our infrastructure". It also forbids to "circumvent bans using different accounts or sharing access with previously banned entities", and to "circumvent rate limits or other use limitations, including by orchestrating usage among multiple accounts". It bars use of "inputs/outputs to train or improve an AI model without authorization". — [Parallel AUP](https://parallel.ai/acceptable-use-policy)
- Customer Terms §2(c)(vii) bars to "use or permit the use of any tools in order to probe, scan or attempt to penetrate the Services". The Terms allow suspension for non-payment (§6(b)) and termination for uncured material breach after 30 days (§10(b)). — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- CDP facilitator: "OFAC and Know Your Transaction (KYT) checks identify and decline payments involving sanctioned or high-risk addresses." — [CDP facilitator](https://docs.cdp.coinbase.com/x402/core-concepts/facilitator)
- Parallel's gateway checks each retry's recipient against its cache "before passing the request to mppx or purl for verification". So request handling can act on credential contents before payment is verified. — [Parallel blog, 2026-05-05](https://parallel.ai/blog/parallel-mpp-dev)
- Stripe's charge record for each payment includes the "buyer wallet address". — [Stripe deposit mode](https://docs.stripe.com/payments/deposit-mode-stablecoin-payments)
- No misuse, abuse-report or payer-blocking policy for parallelmpp.dev was found in Parallel's docs, blog, changelog or legal pages (searched 2026-11-23). — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments); [Parallel changelog](https://docs.parallel.ai/resources/changelog)

### Inferences
- **One address, one point of failure.** URnetwork's single payer address is a single point of refusal, as with Brave: Parallel, or CDP's KYT if the address were ever flagged, could stop all searches at once.
- **Parallel can trace abuse no further than the address.** A complaint can name a payment, which shows up in Stripe's Dashboard with the payer address and transaction hash, or a time. The design's "drop the nonce-to-network mapping at settlement" still applies, and Parallel cannot trace past URnetwork's address.
- **The variable payee creates a risk Brave's design does not have** (Q1): an authorization the broker signs to whatever address a device names can be cashed out. Mitigation (a), the broker fetching its own challenge, or (b), a static deposit address, is needed before launch. Otherwise the per-network budgets have to be sized as a fraud cap.
- **What a written agreement with Parallel needs to cover** (a G-SRCH-parallel, mirroring G-SRCH-brave):
  - a static or pinnable payee, or approval of broker-fetched challenges;
  - whether failed calls are charged, and a refund path;
  - capacity beyond 60 a minute per IP, without breaching the AUP's rate-limit clause;
  - the payer address's standing, and abuse reports early enough to act on;
  - the retention and training terms for keyless traffic, or a ZDR route;
  - which terms govern keyless use;
  - confirmation that pass-through fields such as `advanced_settings` are honored.

### Gaps
- Not published: whether Parallel or its gateway has ever blocked a payer, or how a blocked payer would be told (an HTTP status, an error body).
- CDP's KYT criteria for "high-risk" are not published, nor whether screening covers the payer, the recipient or both.
