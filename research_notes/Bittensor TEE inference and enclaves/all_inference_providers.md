# Bittensor inference providers without a TEE: btauth/1, engy (SN53), SayGM (SN28), the other gamma subnets, Chutes keys, and reasoning effort (state as of 2026-11-23)

Conventions: every page was fetched on 2026-11-23, between about 16:00 and 17:10 UTC, unless another date is given.
- **[earlier notes]** marks a fact taken from this folder's earlier files (gamma_payments_treasury.md, other_subnets_survey.md, chutes_sn64.md, engy_privacy_addendum.md). Those files cite their own primary sources, including chain reads made on 2026-11-23.
- **[code, archived]** marks a fact read from `chutesai/chutes-api`. That repository was archived after its last push on 2026-09-03 (GitHub API, read 2026-11-23), so production may differ.
- **[live call]** marks a public, unauthenticated endpoint that this researcher called. No paid or authenticated request was made to any provider.

## 1. btauth/1 (Subtensor signed-requests guide): headers, the eight-line canonical string, body hash, nonce and window, key types, what else is bound, and whether another machine may send

### Takeaway
btauth/1 signs these eight lines: protocol, scheme, method, request target, the SHA-256 of the raw body, a nanosecond-timestamp nonce, the sender and the receiver. It sends the signature in six `X-Bittensor-*` headers. A request is accepted only inside a 10 s past / 2 s future window, and only once per (hotkey, nonce). The keys are sr25519 or ed25519, plain or "hashed". Nothing else is signed: no other headers, and no host, IP or TLS channel. The guide never says whether the machine that sends a request must be the one that signed it. Since verification uses only the received bytes, the headers, the server's clock and its nonce store, a broker can sign over a body hash and a device can send the identical bytes. The same request cannot be sent twice, and the device cannot send a different body under that signature.

### Cited Findings
**Scope and purpose (guide last changed 2026-11-10, Release 489)**
- The protocol's goal, per the guide: "What those requests need is **identity**: proof that a request came from a specific hotkey, was addressed to yours, covers exactly the bytes received, and is recent." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- "Customers of a subnet service that accepts `btauth/1` sign their requests the same way, with the hotkey of their gamma deposit." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- Services guide (last changed 2026-11-19): "A `gamma` payment with `"signature": "btauth/1"` accepts signed requests. The hotkey that spent signs each request, with the service's hotkey as the receiver, and the service charges what that hotkey spent at it. Without `signature`, the service's own interface says how a request names its hotkey." — [services.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/services.mdx)
- Gamma guide: a deposit is "keyed by a hotkey, which signs the customer's requests to the service, so the hotkey works as an API key". "Requests signed with it are paid from the deposit, so never use a staking hotkey or a coldkey." "A coldkey holds at most 64 deposits per subnet." — [gamma.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/gamma.mdx)

**Headers (exact, from the normative section)**
- "A signed request carries these headers (names are case-insensitive, values exact)":
  - `X-Bittensor-Version`: `1`
  - `X-Bittensor-Hotkey`: "sender hotkey, ss58"
  - `X-Bittensor-Receiver`: "receiver hotkey, ss58 (optional — see below)"
  - `X-Bittensor-Nonce`: "unix time in **nanoseconds**, decimal string"
  - `X-Bittensor-Crypto`: "`ed25519`, `hashed`, or `hashed-ed25519` — omitted entirely for sr25519"
  - `X-Bittensor-Signature`: "`0x` + lowercase hex signature"

  — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- The SDK's constants match: `PROTOCOL = "btauth/1"` and `HEADER_VERSION … HEADER_SIGNATURE = "X-Bittensor-Signature"`. `sign()` emits `X-Bittensor-Crypto` only "for non-default schemes (absent means sr25519)" — [http_auth.py](https://github.com/RaoFoundation/subtensor/blob/main/sdk/python/bittensor/http_auth.py) (last changed 2026-11-05).

**The eight lines (quoted)**
- "The signature is over the UTF-8 bytes of exactly eight lines joined by `\n` (no trailing newline):"
  ```
  btauth/1
  <scheme: "sr25519", "ed25519", "hashed", or "hashed-ed25519">
  <HTTP method, uppercase>
  <request target: path plus ?query, exactly as sent>
  <sha256 of the raw body bytes, lowercase hex>
  <nonce, decimal>
  <sender hotkey ss58>
  <receiver hotkey ss58, or "-" if unbound>
  ```
  — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- "The request target is the **percent-encoded (wire) form** on both sides — `/a%20b?q=1`, never the decoded `/a b`." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- Golden vector: sender `//Alice`, receiver `//Bob`, nonce `1752076800000000000`, body `{"prompt": "hello"}` (19 bytes), request `POST /generate?stream=false`, `sha256(body)` = `341c5744…23c3cc`. The ed25519 signature is pinned (`0x1a6b6319…12f704`). sr25519 "signatures are randomized, so no fixed signature bytes exist". — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)

**Body hash, empty bodies and streaming**
- The algorithm is SHA-256 over the raw bytes, chosen because "**sha256** is in every standard library (this is why it was chosen over blake2b)". — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- "The one rule when wiring `verify` into any framework: hash the **raw received bytes**, before anything parses or re-serializes the body." Step 4 says to "always recompute the body hash". — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- Empty body: the guide has no rule for it. The SDK's `sign(…, body: bytes = b"", …)` defaults to empty bytes, and `build_payload` computes `hashlib.sha256(body).hexdigest()`. An empty body therefore signs sha256 of zero bytes, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (computed by this researcher). — [http_auth.py](https://github.com/RaoFoundation/subtensor/blob/main/sdk/python/bittensor/http_auth.py). SayGM's signed balance GET uses `body=b""` — [SayGM gamma guide](https://saygm.com/gamma/guide.md).
- Streaming request bodies: the guide does not cover them. The httpx recipe sets `requires_request_body = True` and signs `request.content`, so the client must buffer the whole body before signing. — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- Streaming (SSE) responses: btauth/1 signs requests only. The guide defines no response signature. — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)

**Verification order, freshness and replay**
- The guide's verification steps, quoted:
  - (1) "**Shape** — all required headers present and parseable, version is `1`, the scheme (if present) is known and matches the server's trusted scheme for the claimed sender."
  - (2) "**Receiver** — the `X-Bittensor-Receiver` value must equal the server's hotkey. Servers reject unbound requests by default (`require_receiver=False` opts out)."
  - (3) "**Freshness** — the nonce must be within `max_age` seconds in the past (default 10) and `allowed_skew` seconds in the future (default 2)."
  - (4) "**Signature** — rebuild the payload from the *received* method, path, and body (always recompute the body hash) … verify under the trusted scheme **only**."
  - (5) "**Replay** — the `(hotkey, nonce)` pair must not have been accepted before within the window. The store is consulted only after the signature verifies… The default is an in-process `InMemoryNonceStore`; a multi-process server should supply a `NonceStore` backed by shared storage (`SET NX EX` in Redis is exactly this shape)."

  — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- "Clients sign a fresh nonce for every attempt, including retries of an identical body." The guide adds: "transport-level connection retries resend the already-signed request and will be rejected as replays — retry at the application level". — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- SDK details:
  - `DEFAULT_MAX_AGE = 10.0` and `DEFAULT_ALLOWED_SKEW = 2.0`.
  - `verify()` takes the server's time when it is called (`now = time.time_ns()`), after the caller has read the raw body.
  - `InMemoryNonceStore(retention=60.0)`. `verify` refuses a store whose retention is shorter than `max_age + allowed_skew`, because "replays inside the gap would be accepted".
  
  — [http_auth.py](https://github.com/RaoFoundation/subtensor/blob/main/sdk/python/bittensor/http_auth.py)
- The drand headers are reserved: "`X-Bittensor-Drand-Round` and `X-Bittensor-Drand-Randomness` are **reserved** for a future optional extension that anchors freshness to the drand beacon… They are not part of btauth/1." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)

**Provider windows**
- engy: "A nonce is accepted once, from 10 seconds old to 2 seconds in the future". Its OpenAPI says `"nonce_window_s": {"max_age": 10, "max_future": 2}`. — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments); [engy OpenAPI](https://api.engy.ai/openapi.json)
- SayGM documents no window, only "Generate fresh signed headers for every request attempt, including retries". — [SayGM gamma guide](https://saygm.com/gamma/guide.md)

**Key types**
- Allowed schemes are `sr25519`, `ed25519`, `hashed` and `hashed-ed25519`. The guide says: "It supports ordinary and hashed Sr25519/Ed25519; ML-DSA and Falcon HTTP authentication remain unsupported."
- "sr25519 signatures use the substrate signing context (`b"substrate"` in schnorrkel) — the same as chain extrinsics; ed25519 is plain RFC 8032."
- For hashed keys: "Before a hashed hotkey can sign HTTP requests, its first on-chain transaction must finalize, retiring generation zero. HTTP signatures use that retired identity key, never the active rotating spending key."

  — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- The receiver must fix the scheme from trusted configuration: "Never copy `X-Bittensor-Crypto` into `expected_crypto_type`: the header is attacker-controlled… A missing configuration or unknown sender raises `BadSignature`, rather than guessing a scheme." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- engy and SayGM accept sr25519 and ed25519 only. — [engy OpenAPI](https://api.engy.ai/openapi.json); [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)

**What binds a request beyond the body hash**
- The signed lines also cover the method, the target (path and query), the nonce, the sender, the receiver and the scheme. The guide: "Signing the method, path, and body hash means a captured signature cannot be replayed against a different route or payload; signing the receiver means a malicious miner cannot proxy a validator's request to another miner." "Binding the scheme inside the signed payload prevents substitution of an existing signature." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- Other headers are not in the payload: Host or authority, Content-Type, Content-Encoding, and API-specific headers such as `anthropic-version` or SayGM's `X-GM-Providers`. The payload definition has exactly the eight lines above. — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)

**Whether a different machine may send a request**
- The guide neither allows nor forbids it. Verification reads only the headers, the received method, target and body, the server's clock and its nonce store. "Authentication says *who*; whether they may call you is your policy." — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)
- engy: "The `api_key` is a placeholder: when the signature headers are present, `Authorization` is ignored." — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments)
- SayGM: "Send no API key headers with a signed request." — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- The legacy v10 Dendrite scheme did not cover "method, path, receiver-bound replay, unlisted fields — which is exactly why btauth/1 replaced it". — [signed-requests.mdx](https://github.com/RaoFoundation/subtensor/blob/main/docs/guides/signed-requests.mdx)

### Inferences
- **The broker-signs, device-sends plan fits the wire format.** The payload holds only the body's hash, so the broker can sign knowing the method, target and hash, never the body.
- **What the device must do:**
  - send byte-identical body bytes, the same method and the same percent-encoded target;
  - start within 10 s of the broker's nonce timestamp, with 2 s of tolerance for a broker clock running ahead;
  - send each signed request only once, and get a new signature for every retry.
- **Time on the wire counts.** `verify()` reads the server clock after the body has arrived, so upload time over URnetwork's network counts against the 10 s. Large bodies, such as images, on slow links risk `StaleRequest`.
- **The broker cannot police cost.** Because it never sees the body, the broker cannot check `model` or `max_tokens`. Its exposure on one request is bounded only by the provider's balance check (402) and by how much balance the signing hotkey holds at that provider.
- **A small risk from hashes.** A body hash lets the broker confirm a guessed low-entropy body, and spot identical bodies across users. Realistic prompts with conversation history are high-entropy.
- **Unsigned headers.** Headers that change how a body is read (Content-Encoding) or where it goes (SayGM's `X-GM-Providers`) are unsigned. The device controls them. The safe course is not to compress request bodies, since "raw received bytes" may be read before or after decompression depending on the framework.
- **Nonce uniqueness.** Many in-flight requests from one hotkey need distinct nanosecond nonces. The broker should allocate them monotonically.

### Gaps
- The guide does not mention relays, proxies or bearer-style forwarding. Whether a provider adds IP or other policy for btauth callers is per provider; neither engy nor SayGM documents any.
- SayGM's btauth freshness window and nonce-store design are not documented.
- The guide does not say how chunked or `Content-Encoding` request bodies should be hashed.

## 2. engy (SN53, engy.ai): authentication, models and reasoning, per-request usage and signed receipts, rate limits, pricing, the zdr flag, and terms

### Takeaway
engy's OpenAI- and Anthropic-compatible API takes **either** an `sk-engy-` API key **or** btauth/1 on every inference route. With btauth, the signing hotkey is the account, and engy refuses up front (402) any request its balance cannot cover. engy says it keeps "a record of every signed request (status, nonce, signature and body hash, never the body) as billing evidence".

engy also offers **Ed25519-signed receipts**. Each one binds the request-body hash, the response-bytes hash, `usage`, `charged_micro`, `request_id` and `served.zdr`, signed by engy's published receipt key. The docs describe receipts only alongside an API key, so it is undocumented whether they work on btauth requests.

The account API can mint API keys with a 30-day dollar limit and an expiry, and look up any request's log entry by `request_id` within 24 h.

Reasoning is set with `reasoning_effort`, which takes none…max, mapped per model. Ten text models cost $0.045–$1.95/M input. The zdr flag is `provider.zdr`. The terms are silent on resale and on serving end users.

### Cited Findings
**Authentication**
- API keys: "API keys start with `sk-engy-`". They are sent as `Authorization: Bearer`; `POST /v1/messages` also takes `x-api-key`. "`GET /v1/models` and `POST /v1/messages/count_tokens` endpoints do not require a key." — [engy inference API overview](https://engy.ai/docs/api-reference/inference-api/overview)
- btauth/1, per engy's OpenAPI (v0.4.41):
  - Every paid route lists `security: [{btauth}, {bearerAuth}]`: `/v1/chat/completions`, `/v1/completions`, `/v1/messages`, `/v1/responses`, `/v2/video_generation` and its task routes, `/anthropic/v1/messages` and `/responses`.
  - The scheme text: "The sender hotkey IS the account… no sign-up or API key… When these headers are present any `Authorization` header is ignored."

  — [engy OpenAPI](https://api.engy.ai/openapi.json)
- Docs: "Every inference route accepts it: `/v1/chat/completions`, `/v1/completions`, `/v1/messages`, `/v1/responses` and video generation. Usage is charged in USD at the prices in `GET /v1/models`." The receiver is engy's service hotkey `5DXSBCCKH5ENuyHFNaAvtaMfbhEEWpjSJB4rzc4mJfsc1uvJ`. — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments)
- btauth errors:
  - "`402` `{"error": "insufficient_balance"}`: The balance can't cover this request (prompt plus `max_tokens` at the listed prices)… Nothing was run or charged."
  - "`401` | The signature doesn't verify, names another receiver, is stale or replays a nonce."
  - "`403` | The hotkey was stopped by engy."

  — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments)
- Billing evidence: "engy keeps a record of every signed request (status, nonce, signature and body hash, never the body) as billing evidence." — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments)
- Where credit lands:
  - If the coldkey is bound to an engy account, "the credit goes to that account, and the hotkey's signed requests are billed to it too".
  - If it is not bound, "the hotkey is its own engy account, created by its first spend".
  - "One Gamma adds $1 of engy credit, plus a 5% bonus", credited "within about 10 finalized blocks (about two minutes)".

  — [engy gamma payments](https://engy.ai/docs/account-and-billing/gamma-payments)
- `GET /gamma/balance?hotkey=` is "Public, CORS *. Covers every way the account was funded. An unknown hotkey returns zeros." — [engy OpenAPI](https://api.engy.ai/openapi.json)

**Account (management) API: key minting with limits, and per-request logs**
- The account API's llms.txt:
  - Tokens are `rk-engy-…` with permissions `account:read`, `keys:read`, `keys:write`, `referrals:*`. "A token never moves money and cannot manage tokens."
  - `POST /api/v1/keys` takes `name`, an optional `expires` ("the last day it works") and an optional `limit_usd` ("whole dollars it may spend per 30 days"). `PATCH` disables or re-enables a key; `DELETE` revokes it.
  - `GET /api/v1/logs` is "The request log of the last 24 hours", filterable by `?key` (an API key id) and `?request_id` ("one request, exact").
  - The rate limit is "120 requests per minute per token".

  — [engy account API llms.txt](https://engy.ai/api/v1/llms.txt); [engy account OpenAPI](https://engy.ai/api/v1/openapi.json)
- Conflicting docs on key management:
  - The docs pages say "The current endpoints are read-only".
  - They describe keys as created and deleted in the dashboard, and add "Engy stores only a hash of the key and cannot show it again".

  — [engy management API overview](https://engy.ai/docs/api-reference/management-api/overview); [engy API keys](https://engy.ai/docs/account-and-billing/api-keys)

  The account API's llms.txt and OpenAPI, which list `keys:write` endpoints, look newer.
- Usage views:
  - The dashboard's Usage page shows daily and per-model totals for 7 or 30 days.
  - Its Logs page lists requests for "Last 1 or 3 days", with Time, Model, Input, Output, Cached, TTFT, Status and Cost, and a CSV export.
  - `GET /api/v1/usage` returns totals by day and model for "complete UTC days only".

  — [engy usage and logs](https://engy.ai/docs/account-and-billing/usage-and-logs); [engy get usage](https://engy.ai/docs/api-reference/management-api/get-usage)

**Per-request charge in responses**
- `X-Engy-Request-Id` comes on every response. `X-Engy-Charged-Micro` comes on non-streaming responses from chat, completions and messages. `x_engy.request_id` and `x_engy.charged_micro` appear in non-streaming bodies and "the final streaming chunk", and `usage.cost` in USD appears in the final chat stream chunk. — [engy API overview](https://engy.ai/docs/using-the-api/overview)
- "The final chunk always contains usage information, even if you do not request it", including `completion_tokens_details.reasoning_tokens`, `cost` and `x_engy.charged_micro`. — [engy streaming](https://engy.ai/docs/using-the-api/streaming)
- Holds: "Before a request starts, Engy reserves credit for the maximum possible cost, which depends on `max_tokens`". "When a request starts, Engy places a hold… When the request completes, Engy charges the actual cost and releases the rest of the hold." — [engy API overview](https://engy.ai/docs/using-the-api/overview); [engy credits and payments](https://engy.ai/docs/account-and-billing/credits-and-payments)
- Failures and disconnects: "Engy does not charge for a request that fails… If you close the connection during a streamed response, Engy stops generation and does not charge for the request." — [engy errors and limits](https://engy.ai/docs/using-the-api/errors-and-limits); [engy streaming](https://engy.ai/docs/using-the-api/streaming)

**Signed receipts (what is signed, by which key, which fields)**
- "A signed receipt is a record, signed by both you and Engy, of one API call. It states who made the request, the exact bytes that were sent, the exact bytes that Engy returned, the amount billed, and whether the request was served only by zero data retention (ZDR) workers." They are available on chat, completions, messages and responses, streaming and non-streaming. — [engy signed receipts](https://engy.ai/docs/using-the-api/signed-receipts)
- The caller signs with its own Ed25519 key, sending four headers:
  - `X-Engy-Caller-Key` (64 hex)
  - `X-Engy-Caller-Time` (Unix ms)
  - `X-Engy-Caller-Nonce` (32–64 lowercase hex)
  - `X-Engy-Caller-Sig`

  The signed message is `engy-caller-v2|{key}|{time}|{nonce}|{path}|{auth_sha256}|{body_sha256}`, where `auth_sha256` is "The SHA-256 hex digest of your Engy API key (the value after `Bearer`, or the `x-api-key` value)". "A signature is valid for one request, on one endpoint, with one API key." — [engy signed receipts](https://engy.ai/docs/using-the-api/signed-receipts)
- engy's signing key: `GET https://api.engy.ai/v1/receipts/key` returns `alg: ed25519`, key `d99b8d426fb5aa9bca19e70ef44ceec4d918aef982fa067ddeb93d71c0c3cffd`, `"receipt": "engy-receipt v2"`. The key has been in use since 2026-11-07, and "Receipts signed with an earlier key remain verifiable with that key." — [engy signed receipts](https://engy.ai/docs/using-the-api/signed-receipts)
- Receipt format and placement:
  - `<base64url(JSON)>.<hex Ed25519 sig over the decoded token bytes>`.
  - Non-streaming: a last top-level JSON field, `x_engy_receipt`.
  - Streaming: a final SSE comment, `: engy-receipt <token>.<signature>`.
  - Fields: `v`, `kind`, `engy_key`, `time`, `path`, `status`, `caller{key,time,nonce,auth_sha256,sig}`, `req_sha256`, `resp_sha256`, `request_id`, `model`, `usage`, `charged_micro`, `key_id`, `served.zdr`.
  - "Receipts don't identify the worker or provider that served the request."

  — [engy signed receipts](https://engy.ai/docs/using-the-api/signed-receipts)
- Receipt limits:
  - Receipts come only on status 200; "If a stream breaks or ends with an error event, there is no receipt."
  - The caller time must be within 5 minutes of engy's clock. A reused nonce gets a 400. Bodies over 64 MiB get a 413.
  - "To reject replays, Engy keeps only your public key and the nonce of each signed request, for about 11 minutes."
  - "The receipt proves what Engy received, returned, and billed. To check which model produced the output, also request a proof."

  — [engy signed receipts](https://engy.ai/docs/using-the-api/signed-receipts)
- engy's OpenAPI does not mention the `X-Engy-Caller-*` headers or receipts (searched 2026-11-23). — [engy OpenAPI](https://api.engy.ai/openapi.json)

**Models (catalog generated 2026-11-23T16:50:51Z) and prices (USD per 1M tokens: input / cached / output)**

| Model | Checkpoint | Context | ZDR workers | Input / cached / output |
|---|---|---|---|---|
| `deepseek-v4.1-flash` (alias `-1017`) | deepseek-ai/DeepSeek-V4.1-Flash | 1,048,576 | Yes | 0.06 / 0.006 / 0.24 |
| `deepseek-v4-flash-0731` | DeepSeek-V4-Flash-0731 | 1,048,576 | Yes | 0.045 / 0.009 / 0.09 |
| `glm-5.2` | zai-org/GLM-5.2 | 262,144 | Yes | 0.68 / 0.18 / 1.50 |
| `glm-5.3` | zai-org/GLM-5.3 | 327,680 | Yes | 0.98 / 0.18 / 3.08 |
| `glm-5.3-flash` | zai-org/GLM-5.3-Flash | 327,680 | Yes | 0.135 / 0.027 / 0.45 |
| `kimi-k3` | moonshotai/Kimi-K3 | 1,113,088 | Yes | 1.95 / 0.195 / 9.75 |
| `kimi-k3.1-pro` | moonshotai/Kimi-K3.1-Pro | 1,113,088 | Yes | 1.40 / 0.14 / 7.00 |
| `qwen3.6-35b-a3b` | Qwen/Qwen3.6-35B-A3B-FP8 | 208,192 | **No** | 0.045 / 0.015 / 0.30 |
| `qwen3.8-27b` | Qwen/Qwen3.8-27B | 1,001,536 | Yes | 0.045 / 0.015 / 0.32 |

MiniMax-H3 video costs $0.03 per second. — [engy models and pricing](https://engy.ai/docs/get-started/models-and-pricing); [engy llms.txt](https://engy.ai/llms.txt); [api.engy.ai/v1/models](https://api.engy.ai/v1/models)
- "Engy accepts one leading vendor segment and ignores it, so `engy/glm-5.2` and `glm-5.2` select the same model." `kimi-k3` sampling is fixed (temperature 1.0, top_p 0.95). — [engy API overview](https://engy.ai/docs/using-the-api/overview)
- Cache writes are not charged extra: they "are billed at the regular input rate". — [engy models and pricing](https://engy.ai/docs/get-started/models-and-pricing)

**Reasoning parameters**
- Levels: "On `/v1/chat/completions`, set `reasoning_effort`… The `reasoning` object is an equivalent form: `"reasoning": {"effort": "high"}`." "The accepted levels, from lowest to highest, are `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, and `max`… Both `none` and `minimal` turn thinking off." "A value outside this list is passed to the model unchanged… the request then fails with HTTP status `400`, or the value is ignored." — [engy reasoning](https://engy.ai/docs/using-the-api/reasoning)
- Per-model translation (you send → model level):

  | You send | glm-5.2 | glm-5.3, glm-5.3-flash | qwen3.8-27b | kimi-k3, deepseek-v4-flash-0731 | deepseek-v4.1-flash |
  |---|---|---|---|---|---|
  | low | high | low | low | low | low |
  | medium | high | low | medium | low | high |
  | high | high | high | xhigh | high | high |
  | xhigh | max | max | xhigh | max | xhigh |
  | max | max | max | xhigh | max | max |

  "Models that are not listed, such as `qwen3.6-35b-a3b`, follow the `glm-5.2` column." For `qwen3.8-27b`, "the highest level is `xhigh`, which is also its default." — [engy reasoning](https://engy.ai/docs/using-the-api/reasoning)
- Turning thinking off:
  - `reasoning_effort: none|minimal` or `"reasoning": {"enabled": false}`, or `chat_template_kwargs: {"enable_thinking": false}`.
  - "For `kimi-k3` and `deepseek-v4.1-flash`, the switch is named `thinking`."
  - "`glm-5.3` and `glm-5.3-flash` cannot turn thinking off. When you request no thinking, Engy runs them at the `low` level."
  - Reasoning tokens are "billed as output tokens" and reported in `usage.completion_tokens_details.reasoning_tokens`.

  — [engy reasoning](https://engy.ai/docs/using-the-api/reasoning)
- Other endpoints:
  - On `/v1/messages`, `"thinking": {"type": "enabled"|"disabled"}` is accepted. "The `budget_tokens` value is ignored, and the model thinks at its default level."
  - On `/v1/responses`, `"reasoning": {"effort": …}` has the same levels and the same effect.

  — [engy reasoning](https://engy.ai/docs/using-the-api/reasoning)
- **Conflicts in engy's own docs:**
  - The API overview says that on `/v1/responses` "Stored responses…, image input, structured outputs (`text.format`), the `reasoning` object, and `prompt_cache_key`… are ignored". The reasoning page says the opposite for `reasoning` and `text.format`.
  - engy's OpenAPI types `reasoning_effort` as `enum: ["low","medium","high"]`.

  — [engy API overview](https://engy.ai/docs/using-the-api/overview); [engy reasoning](https://engy.ai/docs/using-the-api/reasoning); [engy OpenAPI](https://api.engy.ai/openapi.json)

**Rate limits**
- "The Engy API does not limit requests or tokens per minute, and it does not return rate limit headers."
- A 429 means "capacity exhausted", "account concurrency limit exceeded" or "per-model concurrency limit exceeded". The limit values are not stated. Non-streaming 429s carry `Retry-After`.
- Models time out after 600 s without output (up to 1,200 s for long-context models).

— [engy errors and limits](https://engy.ai/docs/using-the-api/errors-and-limits)

**zdr flag**
- The `provider` object takes `zdr` (bool), `region_only`, `region_exclude` (`eu`, `us`, `cn`, `apac`, `other`) and `require_proof`. "If no available worker meets them, the request fails with status `503`. … Engy removes the `provider` object before the request reaches the model." — [engy inference API overview](https://engy.ai/docs/api-reference/inference-api/overview)
- "ZDR-certified workers either use confidential computing, which keeps request content sealed from the operator, or are operated by Engy without request logging." ZDR can also be "required on your API key or account". — [engy data retention](https://engy.ai/docs/using-the-api/data-retention); [engy terms](https://engy.ai/terms)
- A receipt's `served.zdr` is "`true` only if every worker that received the prompt, including any worker attempted before a retry, is covered by zero data retention." — [engy signed receipts](https://engy.ai/docs/using-the-api/signed-receipts)
- No attestation reaches the client. [earlier notes] — [engy_privacy_addendum.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/engy_privacy_addendum.md>)

**Payments and refunds**
- Payment methods are Card, USDC (Ethereum, Base), TAO, Alpha (SN53) and Gamma (SN53). Top-ups run from $1 to $100,000.
- "You can request a refund of the unused credits from a purchase within 24 hours… Bonus and promotional credits are not refundable."

— [engy credits and payments](https://engy.ai/docs/account-and-billing/credits-and-payments)

**Terms (effective 2026-11-20)**
- "pay for the tokens you use, keep your keys secret, do not use the service to break the law".
- "You are responsible for all usage under your API keys. Keep them secret… We may suspend keys or accounts that violate these terms or generate abusive traffic."
- "If you use engy on behalf of an organization, you accept them for that organization." "You are responsible for complying with the license terms of the models you invoke."
- Liability is capped at "the amount you paid us in the three months before the claim". "We aim for high availability but offer no uptime guarantee".
- The terms contain **no clause on resale, sublicensing, white-labelling or serving one's own end users**. They also do not define "end user".

— [engy terms](https://engy.ai/terms)

### Inferences
- engy fits the plan of a broker-held hotkey, signed requests and device-sent bytes with no adaptation. The device's TLS ends at Cloudflare and then engy's gateway, so URnetwork's network carries only ciphertext.
- **Billing evidence by tier:**
  - *Best:* an engy-signed receipt that the device forwards. URnetwork would check that `req_sha256` equals the body hash the broker signed, and take `usage`/`charged_micro` from it. Whether receipts are issued on btauth requests is undocumented: `auth_sha256` and `key_id` are defined in terms of an API key.
  - *Second best (if the coldkey is bound to URnetwork's engy account):* `GET /api/v1/logs?request_id=` within 24 h, keyed by the `X-Engy-Request-Id` the device reports. The device can lie about the request id, but URnetwork can cross-check model, time and charge, and can reconcile daily against `/gamma/balance` and `/api/v1/usage`.
- **Engy does not charge for a stream the client closes early.** This favours the device: if a device aborts after getting most of the output, neither URnetwork nor the user pays. engy can stop a hotkey for abuse (403). URnetwork may want to charge for streamed tokens the device received, or watch abort rates.
- **The alternative to btauth:** the account API can now mint `sk-engy-` keys with `limit_usd` per 30 days and an expiry, one per device or user. These would be bearer secrets on devices. engy's terms make the account holder "responsible for all usage under your API keys" and say "Keep them secret". The terms contain no explicit ban on giving keys to end users.

### Gaps
- Whether signed receipts work on btauth requests: the value of `auth_sha256`, and whether `key_id` is null. Not documented; not tested, because testing would take a funded request.
- Which fields `GET /api/v1/logs` returns. The OpenAPI gives only `{ data, meta }`.
- Whether btauth hotkey requests appear in the account logs, and under which key id.
- engy's numeric concurrency limits.
- The pages not read in the earlier addendum (region routing, verify responses) were not re-read here, except for the `provider` object.

## 3. SayGM (SN28, saygm.com): authentication incl. btauth/1, models and reasoning, usage records, rate limits, pricing, privacy flags, terms, and the frontier models it resells

### Takeaway
SayGM is an Intel TDX gateway run by T34 Corporation FZCO, Dubai. It sells 67 models:
- 12 Claude, 16 GPT and 13 Gemini models (frontier tier);
- open-weight models in an `open` tier, which is not in a TEE;
- `-tee` confidential models.

SayGM's gamma API takes **btauth/1 on every inference route**: chat completions, responses, messages, Gemini generateContent, images and videos. The receiver is publisher hotkey `5Evgh9…dco3P`, and no API key may accompany a signed request.

Each response carries its settled cost (`usage.cost`, `cost_nano_usd`) and an `x-gm-request-id` ULID. SayGM has no ZDR flag. Rate limits are unpublished.

Frontier models are served by SN28 miners using **their own** Anthropic, Bedrock or Foundry, OpenAI or Azure, and Google keys, "under that provider's API terms". Anthropic's, OpenAI's and Google's API terms each restrict reselling or sublicensing raw API access, and no upstream approval was found.

New since the earlier notes: SayGM now serves a public, nonce-bound gateway attestation, `GET /attestation/info`.

### Cited Findings
**Operator, terms and acceptance**
- The terms (last updated 19 November 2026) name the operator as "T34 Corporation FZCO, Dubai World Trade Centre Authority trade licence L-3102". "Spending gamma at SayGM means you accept these terms. Calling the API with a signed request also means you accept these terms." "Gamma credit is non-refundable." Business customers are governed by UAE law, Dubai courts. — [SayGM terms](https://saygm.com/terms)
- Acceptable use bars using the Service to "resell or provide access in a way that circumvents our limits or provider policies". "Provider-specific terms or usage policies may also apply to a request routed to that provider." "We may apply reasonable rate, usage, or security limits." — [SayGM terms](https://saygm.com/terms)

**Authentication**
- API keys (`gm_live_…`) are sent as `Authorization: Bearer`. Anthropic Messages takes `x-api-key` plus a required `anthropic-version`. Gemini takes Bearer, `x-goog-api-key` or `?key=`. — [SayGM docs: authentication](https://docs.saygm.com/api/authentication/)
- btauth/1, per the gamma OpenAPI:
  - Every paid path lists `security: [{btauth: []}]` only: `/chat/completions`, `/responses`, `/messages`, `/v1beta/models/{modelAndAction}`, `/images/generations`, `/videos`, `/videos/{id}`, `/videos/{id}/content` and the signed `/balance`.
  - The scheme text: "Bittensor btauth/1 signed request from the hotkey that spent gamma… Send all six headers… The receiver is the publisher hotkey the gamma was spent at: `5Evgh9QTXJLxYLusVy3tcY5S6Z3GgRSNDb9AzXUchX5dco3P`. Sign again for every attempt, including retries. Send no API key headers with a signed request."

  — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- The services document lists one publisher (netuid 28, the hotkey above), endpoint `https://api.saygm.com`, and payment `{"type":"gamma","signature":"btauth/1","balance":"https://api.saygm.com/balance"}`. — [SayGM services.json](https://saygm.com/services.json)
- The gamma guide:
  - "A few minutes after each spend finalizes, SayGM credits $1 per gamma to the balance for the spending hotkey. That balance belongs to that hotkey." "Gamma credit is usable for any gateway model."
  - "A signed request that cannot be covered by the balance receives HTTP 402 with this body: `{"error":"insufficient_balance"}`."
  - The balance is read with a btauth-signed `GET /balance?hotkey=` and an empty body.

  — [SayGM gamma guide](https://saygm.com/gamma/guide.md)
- Sign in with SayGM (OAuth, PKCE):
  - Partner apps receive a dedicated `inference_api_key` that spends the **customer's** SayGM credits. The customer picks a monthly spending limit or "unlimited".
  - Apps are registered by the SayGM team via Discord.
  - Partner access excludes "creating, editing or deleting the customer's general API keys, changing their balance allocations".

  — [SayGM docs: OAuth](https://docs.saygm.com/api/oauth/)
- Key minting by API: `POST https://account.saygm.com/v1/keys` with an account access token, obtained through a Bittensor-signature OAuth grant. — [SayGM top-up guide](https://saygm.com/topup.md)
- Key spending: "When shared balance is on, every key can spend your entire prepaid balance — there is no per-key cap. With shared balance off, each key spends its configured allocation." — [SayGM llms.txt](https://saygm.com/llms.txt)
- Key placement: "Never put a key in browser-side JavaScript or a mobile application bundle." — [SayGM docs: API key](https://docs.saygm.com/getting-started/api-key/)

**Models (live `/v1/models`, 67 entries) and tiers**
- Counts by tier and gateway_provider:
  - frontier: openai 16, gemini 13, anthropic 12, google 1 (Veo), minimax 1, wan-ai 1;
  - open: deepseek 3, zai 3, moonshot 2, qwen 2, openai 1 (gpt-oss-20b), bfl 1;
  - confidential: zai 3, qwen 3, deepseek 2, moonshot 2, google 1.

  — [api.saygm.com/v1/models](https://api.saygm.com/v1/models)
- Claude ids:
  - claude-fable-5, -5-1, -5-2
  - claude-haiku-4-5, -5-5
  - claude-opus-4-7, -4-8, -5, -5-5
  - claude-sonnet-4-6, -5, -5-5
- GPT ids: gpt-5.4 (+mini, nano), gpt-5.5, gpt-5.5-pro, gpt-5.6 luna/sol/terra, gpt-6 astra/luna/sol, gpt-6.1 sol/terra, gpt-6.2 astra/sol, o3. These are the 16 in `/v1/models`; `o4-mini` appears only in the price table, at an "up to" price.
- Gemini ids: 3.1 flash-lite / pro-preview, 3.5 flash-lite, 3.6 flash, 3.8 flash, 4 argon/carbon/hydrogen/neon, plus image models.

  — [SayGM price table](https://saygm.com/models.md)
- Tier definitions: "`confidential` field is `true` only when inference runs in a TEE." "Open models… are not served inside a TEE… Treat an open model's data handling the same way you treat a frontier model's." — [SayGM docs: privacy model](https://docs.saygm.com/security/privacy/)

**Who serves the frontier models, and under whose terms**
- "Claude, GPT and Gemini run on hardware their provider controls, either the model maker or a cloud host, under that provider's API terms." — [saygm.com/privacy](https://saygm.com/privacy)
- "SayGM miners supply upstream model capacity and earn the spread between their declared offer and SayGM's buyer price… At least one supported upstream provider API key… Provider keys are deployed into the miner's confidential workload." — [SayGM docs: mining overview](https://docs.saygm.com/mining/overview/)
- Miner README: "You bring your own provider API keys (Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot, DeepInfra, KubeTEE, Engy, Moonmath, NEAR AI Cloud, or Bedrock/Foundry/Azure transport backends…)". "Anthropic can target direct Anthropic, AWS Bedrock, or Microsoft Foundry; OpenAI can target direct OpenAI or Azure OpenAI." It also accepts "up to 8 semicolon-separated keys" per provider. — [taostat/gm-miner README](https://github.com/taostat/gm-miner) (pushed 2026-11-23)
- Buyers can restrict routing with `X-GM-Providers` (for example `bedrock,anthropic`). Provider names include `bedrock`, `azure`, `foundry`, `anthropic`, `openai`, `google`, `kubetee`, `chutes`, `near` and `deepinfra`. "If none of your chosen providers can serve the request, SayGM returns an error". `X-GM-Routing` takes `default|cheapest|fastest`. — [SayGM docs: routing](https://docs.saygm.com/api/routing/)
- SayGM vs Anthropic: "On a Claude model, the provider serving the request still receives your prompt and processes it under its API terms. If you need a data-handling contract of your own with Anthropic, sign it directly." "Data terms: The serving provider's API terms apply." — [SayGM vs Anthropic](https://saygm.com/vs/anthropic)
- **Upstream resale terms**:
  - **Anthropic** Commercial Terms (effective Jun 17, 2025, current on 2026-11-23). A.1 permits use "to power products and services Customer makes available to its own customers and end users". D.4 says "Customer may not and must not attempt to (a) access the Services to build a competing product or service, including to train competing AI models or resell the Services except as expressly approved by Anthropic". — [Anthropic Commercial Terms](https://www.anthropic.com/legal/commercial-terms)
  - **OpenAI** Services Agreement (updated Dec 1, 2025; effective Jan 1, 2026). 2.2 grants the right "to make Customer Applications available to End Users". 3.1: "Customer may not resell or lease access to its Account or any End User Account." 3.3(g): Customer will not "buy, sell, or transfer API keys from, to, or with a third party". — [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
  - **Google** APIs Terms (last modified Nov 9, 2021) prohibit to "Sublicense an API for use by a third party. Consequently, you will not create an API Client that functions substantially the same as the APIs and offer it for use by third parties." — [Google APIs Terms of Service](https://developers.google.com/terms). The Gemini API Additional Terms (effective March 23, 2026) add no general resale clause; a fetch summary found only Grounding-with-Search limits ("cache, frame, syndicate, resell"). — [Gemini API Additional Terms](https://aistudio.google.com/docs/terms)

**Pricing**
- "A price shows a recent finalized-epoch result, or an eligible price offered by miners now… no request is charged more than list."
- Examples (input/output $/M):
  - claude-sonnet-5-5: $1.03/$5.15 (list $2/$10, 48.5% below).
  - claude-opus-5-5: $2.06/$10.30.
  - gpt-5.5: $2.58/$15.45 (48.5% below).
  - gemini-4-neon: $2.47/$12.36 (17.6% below).
  - Open tier: kimi-k3 $1.85/$9.27, glm-5.3 $0.97/$3.04, deepseek-v4.1-flash $0.10/$0.41.
  - Confidential tier: kimi-k3-tee $2.53/$12.67, glm-5.2-tee $1.37/$4.31.

  — [SayGM price table](https://saygm.com/models.md)
- `pricing.basis` is "cheapest_eligible_offer"; `price_range.ceiling` is retail. Rates are integers in nano-dollars per million tokens. — [SayGM docs: billing](https://docs.saygm.com/platform/billing/); [api.saygm.com/v1/models](https://api.saygm.com/v1/models)
- Payment methods: card, USDC, TAO, Alpha (SN28) and gamma. — [SayGM docs: billing](https://docs.saygm.com/platform/billing/); [SayGM top-up guide](https://saygm.com/topup.md)

**Per-request usage and settlement**
- "Every response with billable usage carries the amount it is charged inside its own usage block: `cost` in USD… and `cost_nano_usd`… The figure is the charge after miner pricing, buyer markup, the retail clamp and any surcharge, computed from the usage the provider reported." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- In streams, the cost fields ride "the stream's final usage-bearing event". — [SayGM docs: streaming](https://docs.saygm.com/api/streaming/)
- "Each buyer request has one gateway-generated ULID, exposed as `x-gm-request-id`. The gateway saves the usage settlement under that ID… so the charge for that ID is processed at most once." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- Messages responses also carry `request-id`, `x-gm-model-served` (`provider:model`) and `x-gm-params-dropped`. — [SayGM docs: Anthropic](https://docs.saygm.com/api/anthropic/)
- Admission: "the gateway… may lower the output limit, such as `max_tokens`, to fit what the balance can cover. When the balance falls short of the estimated input plus a minimum usable output, the request stops there with HTTP `402`". — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- **Disconnects are charged**: "If you disconnect during a stream, the gateway… keeps reading the upstream to the end, then settles the usage the provider reports, including output generated after you left… a stream that ends before one arrives costs nothing." — [SayGM docs: billing](https://docs.saygm.com/platform/billing/)
- Usage history: `GET https://account.saygm.com/v1/usage/self` returns requests, errors and spent per model or day for the presented API key, over at most 90 days. — [SayGM docs: usage](https://docs.saygm.com/platform/usage/)
- Public settlement records:
  - Each record holds `request_id`, timestamp, `gateway_id`, `product{provider, model}`, `usage{input_tokens, output_tokens}`, `effective_price_ndollars` and `success`, "with no account, key or IP address".
  - "Each settlement period's records are published as public data, so anyone can check the accounting."
  - A diagnostic record (latency, retries, error class, guardrail counts) is "Kept 30 days".

  — [saygm.com/privacy](https://saygm.com/privacy)

**Reasoning**
- On Messages: "`thinking` and `output_config.effort` pass through unchanged. Which values a model accepts is the model's own rule." "A route drops the controls its provider rejects and names them in the `x-gm-params-dropped` response header." — [SayGM docs: Anthropic](https://docs.saygm.com/api/anthropic/)
- The catalog schema has `reasoning_efforts` ("Reasoning effort values supported by this model") and `reasoning_effort_aliases` ("Accepted reasoning effort aliases and their native values"). — [SayGM gamma OpenAPI](https://saygm.com/gamma/openapi.json)
- In the live catalog only `glm-5.3-flash` and `glm-5.3-flash-tee` declare these fields: `["low","high","max"]`, with aliases `medium→low`, `minimal→low` and `xhigh→max`. — [api.saygm.com/v1/models](https://api.saygm.com/v1/models)

**Rate limits**
- The OpenAPI 429 reads "The account has reached the request rate limit. Retry after the supplied delay". No numbers are published. — [SayGM OpenAPI](https://saygm.com/openapi.json)
- The gateway retries upstream 429 and 5xx on another route within its budgets. — [SayGM docs: errors](https://docs.saygm.com/api/errors/)

**Privacy flags and the gateway TEE**
- There is no ZDR flag. Optional per-key guardrails (PII, secret and regex redaction) "run inside the gateway's enclave". — [saygm.com/privacy](https://saygm.com/privacy)
- "HTTPS for api.saygm.com terminates inside the enclave". "The confidential VM runs on Phala Cloud with dstack". — [saygm.com/privacy](https://saygm.com/privacy)
- `GET https://api.saygm.com/attestation/info?nonce=` is public. It returns `quote`, `event_log`, `vm_config` and `gateway_pubkey`, with `report_data = SHA‑512(gateway_pubkey ‖ nonce)`. — [saygm.com/privacy](https://saygm.com/privacy)
- [live call, 2026-11-23 17:05 UTC] The endpoint answered 200 for `gateway_id` `gw-mainnet-1`, `tee_platform` `intel-tdx`, with `verification_status: "not_checked"` and `policy_accepted: false`. Recomputing SHA-512(gateway_pubkey ‖ nonce) matched `report_data`. The TDX quote itself was not verified here. — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)
- The docs page (last updated Oct 29, 2026) says "The lower-level attestation verification interface is still being prepared for general buyer use", and "Attestation… does not, by itself, prove the behavior or data policy of an upstream frontier model provider." — [SayGM docs: TEE attestation](https://docs.saygm.com/security/attestation/)

### Inferences
- **SayGM fits the btauth plan as well as engy does.** The device can send the broker-signed request with no API key. TLS from the device ends inside SayGM's TDX gateway, so URnetwork's network sees ciphertext only.
- **Plaintext exposure:**
  - Frontier and `open` models: SayGM's gateway (in TDX), the miner's TDX CVM, then the upstream provider in the miner's name.
  - `-tee` models: per earlier notes, Chutes E2E or KubeTEE attested TLS from inside the miner CVM. [earlier notes]
- **Billing.** The device can report `x-gm-request-id` and `cost_nano_usd`. Those are self-reported: SayGM signs nothing for the buyer. Two checks remain:
  - (a) SayGM's public per-period settlement records, keyed by `request_id`, if URnetwork can find and fetch them (see Gaps);
  - (b) per-hotkey reconciliation against the signed `/balance`.
- **SayGM's disconnect rule differs from engy's.** SayGM charges for the full upstream generation after a disconnect; engy charges nothing. The canonical catalog should record each provider's abort rule.
- **Contract risk for Claude, GPT and Gemini.** The frontier route is a resale chain: URnetwork → SayGM → miner → the miner's Anthropic, OpenAI or Google (or Bedrock, Azure, Foundry) account. Anthropic D.4 ("resell the Services except as expressly approved"), OpenAI 3.1 and 3.3(g), and the Google APIs sublicensing clause all restrict that pattern on their direct terms. SayGM's own AUP forbids access that "circumvents… provider policies". Including SayGM's frontier models carries upstream-terms risk that URnetwork cannot audit, because the miners and their accounts are anonymous. This is an inference, not legal advice; AWS, Microsoft and Google Cloud reseller terms were not checked.
- **New attestation evidence.** The live attestation endpoint changes the earlier "none fetchable" finding for SayGM's *gateway*. It still does not let a client tie its TLS session to `gateway_pubkey`. For frontier models it does not matter, because the provider sees plaintext anyway.

### Gaps
- Where SayGM's "published" per-period settlement data lives. Not found on saygm.com or in the docs index.
- Whether btauth requests appear in any per-request usage listing (the btauth API has only `/balance`).
- SayGM's btauth freshness window, its rate-limit values, and whether per-key allocations can be set through `POST /v1/keys`.
- Whether `reasoning_effort` and `reasoning` are passed through on OpenAI and Gemini surfaces. Only the Anthropic surface is documented as pass-through.
- How the TLS certificate relates to `gateway_pubkey`.
- AWS Bedrock, Azure OpenAI and Google Cloud terms on resale by the miners' accounts were not researched.

## 4. The other gamma-enabled subnets (25, 28, 37, 51, 53, 58, 75, 76, 80, 81, 94, 103, 117): which sell LLM inference; Terza (SN103) in detail

### Takeaway
Of the 13 gamma-enabled subnets, three sell LLM inference: SN53 engy, SN28 SayGM and SN103 Terza. Terza is an early-access, invitation-for-miners gateway selling Claude, GPT, Gemini, DeepSeek, Kimi, GLM and Qwen through miners' own upstreams. It documents **no gamma or btauth path**: it is paid in USDC, USDT or TAO through API keys. Its keys can carry a monthly budget and model and IP restrictions. Its on-chain service URL (`terza.si`) does not serve a service document.

EveryFrame (SN117) takes btauth, but it sells speech, video and image generation, not LLMs. The rest sell compute, storage, sandboxes, robot data or coding outcomes, or have published no service.

### Cited Findings
- The gamma-enabled set on 2026-11-23 was 25, 28, 37, 51, 53, 58, 75, 76, 80, 81, 94, 103 and 117. Published services: 25 URnetwork, 28 saygm.com, 51 Lium, 53 engy.ai, 58 Attune, 75 Hippius, 76 Ormas, 94 Cathedral, 103 `terza.si`, 117 EveryFrame. SN37, SN80 and SN81 had enabled gamma without publishing a service. [earlier notes] — [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>)
- **SN51 Lium:** "GPU pods by the second. Gamma spent at Lium's service hotkey becomes the hotkey's USD balance." — [Lium service doc](https://lium.io/api/gamma/service.json). Its docs index lists no hosted LLM API. Inference appears only as self-serving on a rented pod ("Run a vLLM Server", "Remote Inference with @lium.machine"). — [Lium llms.txt](https://docs.lium.io/llms.txt)
- **SN58 Attune:** "Robot data (simulation and egocentric, pre-train and post-train). Robot policies. Playground runs." Its gamma payment has no `signature` field. — [Attune service doc](https://api.robotensor.ai/services.json)
- **SN75 Hippius:** "a decentralized cloud (compute, storage, S3)". Its payment entry is btauth/1. — [Hippius service doc](https://api.hippius.com/api/billing/gamma/service.json). Its docs index still lists paying with gamma "(not live yet)". — [Hippius llms.txt](https://docs.hippius.com/llms.txt)
- **SN76 Ormas:** "Coding tasks priced per accepted outcome… Miners bid on whole tasks and are paid only when the delivery is accepted". `payments: []`. — [Ormas service doc](https://api.ormas.ai/services.json)
- **SN94 Cathedral:** "Confidential sandboxes (AMD SEV-SNP)… every paid route takes btauth/1". — [Cathedral service doc](https://cathedral.computer/v1/gamma/services.json). Its gamma price list has one product, `sealed_sandbox`, at $0.005/h (1 vCPU, 2 GiB) and up. — [Cathedral gamma pricing](https://api.polaris.computer/v1/gamma/pricing)
- **SN117 EveryFrame:** "AI video, image and speech generation for agents. Spend SN117 Gamma at the publisher hotkey, then sign every API request with your hotkey (btauth/1). No sign-up or API key. 1 Gamma = 1 USD." `max_spend` is 1000. — [EveryFrame service doc](https://app.everyframe.studio/services.json). Its speech models are ElevenLabs `eleven-v4` ($0.08/1k chars) and `eleven-v4-turbo` ($0.04). — [EveryFrame speech models](https://app.everyframe.studio/api/v1/speech/models)
- **SN37 Aurelius** is categorised "Security", **SN80 OpenRoboto** "Robotics" and **SN81 Reliquary** "Training". None sells an LLM API. — [SubnetRadar SN37](https://subnetradar.com/subnet/37); [SubnetRadar SN80](https://subnetradar.com/subnet/80); [SubnetRadar SN81](https://subnetradar.com/subnet/81)
- **SN25 URnetwork:** its service document covers UR Pro plans and data, not inference. [earlier notes] — [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>)

**Terza Inference (SN103)**
- Product: "One API key for models served by independent miners on Bittensor… Every request is routed to the best offer, checked, and billed by what was actually delivered." It is "LIVE ON BITTENSOR SUBNET 103 · EARLY ACCESS". — [terza.si](https://terza.si)
- The API base is `https://terza.si/v1`, with these endpoints:
  - `POST /v1/chat/completions` (SSE, tools);
  - `/v1/responses` ("Stored for 7 days by default (`store: false` to opt out)");
  - `/v1/messages` (`x-api-key` accepted);
  - `/v1/embeddings`, `/v1/rerank`, `/v1/systemone`, images, audio, `GET /v1/realtime` and `/v1/media/tasks`.

  — [Terza API quickstart](https://terza.si/docs/quickstart/)
- Keys and payment: "top up (minimum $5) with USDC or USDT on AllScale's checkout page, or send TAO". "Under API keys, create a key. Give it a monthly budget and, optionally, restrict its models or IP addresses." Buyers "pay per use in USDC, USDT or TAO". — [Terza API quickstart](https://terza.si/docs/quickstart/); [Terza docs](https://terza.si/docs/)
- Gamma or btauth: none of the docs pages read mention gamma or btauth (quickstart, overview, privacy, miners, integrations, pricing). `https://terza.si/services.json` and `/terms/` return 404. The on-chain service URL is the bare `terza.si`. — [terza.si/services.json](https://terza.si/services.json); [Terza docs](https://terza.si/docs/); [earlier notes](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>)
- Models: the Claude Code integration uses `claude-sonnet-5-5`, `claude-haiku-5-5` and `claude-opus-5-5`. Codex uses GPT models `gpt-6.2-sol`, `gpt-6.2-astra`, `gpt-6.1-sol`, `gpt-6.1-terra`, `gpt-6-sol`, `gpt-6-astra` and `gpt-6-luna`, "for Gemini, DeepSeek, Kimi, GLM or Qwen, use Cursor or another OpenAI-compatible tool". The Codex example sets `model_reasoning_effort = "medium"`. — [Terza integrations](https://terza.si/docs/integrations/). `GET /v1/models` needs a key (401 without one). — [terza.si/v1/models](https://terza.si/v1/models)
- Pricing: "Each row is one miner's quote for one tier… The percentage compares it with the model maker's official list price." Quotes load by script, so none were captured. — [Terza pricing](https://terza.si/pricing/)
- Usage checks:
  - "Miners report usage; the gateway compares it with what was actually delivered. Implausible receipts are rejected, failures are never charged."
  - Rejection rules include `input_exceeds_request_bound`, `output_exceeds_max_tokens`, `output_exceeds_delivered_text` and `undeclared_reasoning`.
  - Each gateway-to-miner request carries "an Ed25519 signature over the method, path, your hotkey, a timestamp, a single-use nonce and the exact body… older than 60 seconds" is rejected.

  — [terza.si](https://terza.si); [Terza miners](https://terza.si/docs/miners/)
- Errors: "402 | Insufficient balance or key budget. Nothing was sent"; "429 | Rate limited"; "502/503 … No charge". — [Terza API quickstart](https://terza.si/docs/quickstart/)
- Privacy:
  - "Chat Completions and Messages | No prompt or output content. Only billing metadata."
  - "The miner that serves a request processes its content… Terza Inference cannot technically guarantee what a third-party miner does with a request."
  - "Server logs record request metadata and IP addresses".

  — [Terza privacy](https://terza.si/docs/privacy/)
- Miners "supply models through its own upstream" and must have "Upstream capacity for the models you will quote". — [Terza docs](https://terza.si/docs/); [Terza miners](https://terza.si/docs/miners/)
- Depth: the SN103 pool held about 438 TAO, so a $10k mint would lose about 10.6% to price impact. [earlier notes] — [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>)

### Inferences
- **For the btauth plan, the gamma LLM providers today are engy and SayGM only.** Terza would need its own API keys on devices. Its per-key monthly budget and IP restriction make that a bounded risk, but it is still a bearer secret, and there are no published terms to check against. Terza's frontier models carry the same upstream-resale question as SayGM's.
- **Thin pools make gamma costly.** SN103 is very thin (≈438 TAO), so paying Terza through gamma would be costly even if Terza documented it. Its documented TAO, USDC and USDT payments are the practical route.
- **EveryFrame is the only other btauth seller.** It could carry a speech or TTS catalog entry under the same broker-signs design, but it is not LLM inference.

### Gaps
- Terza's terms of service (no `/terms` page found), its model list and prices (the console needs a login; the pricing page loads by script), and whether it has any plan to accept SN103 gamma.
- What SN37, SN80 and SN81 will publish. Their identities come from SubnetRadar categories only.

## 5. Chutes' non-TEE ("Standard") models: can a device call Chutes without URnetwork's master API key?

### Takeaway
Chutes offers no x402, btauth/1 or gamma path: none appears in its OpenAPI, and SN64 has not enabled gamma. Four mechanisms exist, each with a catch:
1. **Scoped API keys.** Scopes are `images`, `chutes` or `invocations` × a specific id × `read|write|delete|invoke`. There is **no spending limit or expiry**, and Chutes' terms forbid giving end users access to API keys.
2. **Chutes' own hotkey-signature auth.** `X-Chutes-Hotkey`, `X-Chutes-Signature` and `X-Chutes-Nonce`, sr25519 over `hotkey:nonce:sha256(body)`, with a ±600 s nonce. Archived code accepts it on hostname invocations, but current docs say inference auth is Bearer only. The archived code had no replay store.
3. **Programmatic per-agent accounts.** `POST /users/agent_registration` requires about $50 in TAO per account, and `POST /users/balance_transfer` moves balance between accounts. Each account is a separate Chutes customer.
4. **"Sign in with Chutes" OAuth.** Each user pays Chutes from their own account.

The Standard models also carry extra content rules in Schedule 1, including a ban on submitting personal and sensitive data.

### Cited Findings
- No gamma: SN64's `SubnetGammaEnabled` is off, and no service is published. [earlier notes] — [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>)
- No x402 or btauth: the live management OpenAPI has 189 paths and contains the strings `x402` and `btauth` zero times. Its only declared security scheme is `APIKeyHeader` (`Authorization`). — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)
- The Standard (non-TEE) models served since 2026-11-04 are:
  - DeepSeek-V4-Pro-0813, DeepSeek-V4.1-Flash-1017;
  - GLM-5.3, GLM-5.2-Fast;
  - Qwen4-Max, Qwen3.8-Max-0902, Qwen3.8-2.4T-A95B;
  - Kimi-K2.7-Code, Hy4.

  [earlier notes] — [chutes_sn64.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/chutes_sn64.md>). The current llms.txt labels several of them "no TEE". — [chutes.ai/llms.txt](https://chutes.ai/llms.txt)

**Key-management API**
- `POST /api_keys/` ("Create a new API key. OAuth access tokens and existing API keys cannot mint credentials.") takes `{admin: bool, name, scopes: [{object_type, object_id?, action?}]}`. There are also `GET /api_keys/`, `GET` and `DELETE /api_keys/{id}`. — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)
- [code, archived] `object_type` must be one of `images`, `chutes` or `invocations`, and `Action` is `read`, `write`, `delete` or `invoke`. The key model has no spending, quota or expiry field. — [api_key/schemas.py](https://github.com/chutesai/chutes-api/blob/main/api/api_key/schemas.py)
- [code, archived] `has_access` has a "Special handler for llm.chutes.ai endpoint": for `object_type == "chutes"` and `object_id in ("__megallm__", "__megadiffuser__", "__megaembed__")`, any `chutes` scope with a matching or empty action grants access, whatever the scope's `object_id`. — [api_key/schemas.py](https://github.com/chutesai/chutes-api/blob/main/api/api_key/schemas.py)
- The CLI docs: `--chute-ids TEXT : Allow access to specific chute IDs`, `--action [read|write|delete|invoke]`, plus "Admin Keys : Full account access… Scoped Keys : Limited access based on object type and action". Chutes' own best-practice text says: "Never use your admin API key in client-side code. Create scoped keys for specific functions." — [chutes.ai/llms-full.txt](https://chutes.ai/llms-full.txt)
- Inference auth, per the current docs: "Inference auth is the Bearer token only — `X-API-Key` is not a supported inference auth scheme… User-scoped auth uses Sign in with Chutes / OAuth." "Third-party apps can add Sign in with Chutes (OAuth 2.0) so each user's API usage bills to their own Chutes account." — [chutes.ai/llms.txt](https://chutes.ai/llms.txt)

**Hotkey-signature auth (Chutes' own scheme, not btauth/1)**
- The live OpenAPI lists optional `X-Chutes-Hotkey`, `X-Chutes-Signature` and `X-Chutes-Nonce` headers on most management paths, including `/e2e/invoke` and `/api_keys/`. — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)
- [code, archived] The scheme:
  - The signed message is `f"{hotkey}:{nonce}:{payload_hash}"`, where the payload hash is the request's body SHA-256, "an sr25519 request signature".
  - `nonce_is_valid` accepts a decimal Unix-seconds nonce with `abs(time.time() - int(nonce)) < 600`.
  - No nonce-reuse store appears in `get_current_user`.
  - The user is found by `User.hotkey == hotkey`.

  — [api/util.py](https://github.com/chutesai/chutes-api/blob/main/api/util.py); [api/user/service.py](https://github.com/chutesai/chutes-api/blob/main/api/user/service.py)
- [code, archived] `hostname_invocation`, the path behind llm.chutes.ai's `__megallm__`, authenticates with `get_current_user(raise_not_found=False)`, so hotkey auth was accepted there. — [api/invocation/router.py](https://github.com/chutesai/chutes-api/blob/main/api/invocation/router.py). This conflicts with the current docs' "Inference auth is the Bearer token only". — [chutes.ai/llms.txt](https://chutes.ai/llms.txt)

**Sub-accounts and balance movement**
- `POST /users/create_user`: "Create a new user manually from an admin account". This is Chutes-admin only. — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)
- `POST /users/agent_registration`: "Register an AI agent programmatically using hotkey/coldkey/signature. Returns a payment address where the agent must send TAO to complete registration." `POST /users/{user_id}/agent_setup` then "Returns API key and config.ini template". — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)
- [code, archived] The required payment is `settings.agent_registration_threshold`: default `"50.0"` USD in TAO, 10% tolerance, 24-hour TTL. "Funds sent to expired registrations are not recoverable." — [api/config/__init__.py](https://github.com/chutesai/chutes-api/blob/main/api/config/__init__.py); [api/user/router.py](https://github.com/chutesai/chutes-api/blob/main/api/user/router.py); [scripts/agent_register.py](https://github.com/chutesai/chutes-api/blob/main/scripts/agent_register.py)
- `POST /users/balance_transfer`: "Transfer balance from the authenticated user to a target user", authenticated by "Hotkey authentication… Admin API key… Fingerprint". Per-user per-chute quotas (`POST /users/{user_id}/quotas`) are an admin operation. — [api.chutes.ai/openapi.json](https://api.chutes.ai/openapi.json)

**Terms (last updated November 01, 2026)**
- §3.3: "You may not sell, transfer, share, or sublicense your account or API keys, and you may not give any third party, including your own end users, direct access to your API keys."
- §9.1: "You may integrate the Platform into your own products and offer them to your own users".
- §9.2 requires you to "keep your API keys under your control and not give End Users direct or unrestricted access to the Platform or to any Model Provider's interfaces", and to tell End Users their content "may be processed by Chutes and by Model Providers".
- §9.3: "You may not resell, white label, or redistribute access to the Platform as a standalone inference service without a separate written agreement with Chutes."

— [Chutes terms](https://chutes.ai/terms)
- Schedule 1 (Standard Models) adds prohibited content (S1.1). S1.3: "You may not submit to a Standard Model the categories of data listed in Section 7.5". S1.6 bars bypassing Model Provider safety filters. S1.9: "A Model Provider may refuse or block any request". — [Chutes terms](https://chutes.ai/terms)

### Inferences
- No compliant way was found for a device to call Chutes' Standard models directly without either a URnetwork-account credential or the user's own Chutes account. Each option, in turn:
  - **Scoped keys on devices:** these breach §3.3 and §9.2, and they have no spend cap.
  - **Broker-signed `X-Chutes-*` requests:** structurally like btauth (the signature covers only the body hash and the nonce). But they may not be accepted for inference in production, have a 10-minute window with possibly no replay protection, and arguably still give End Users "direct… access to the Platform" (§9.2).
  - **Per-device agent accounts:** each costs a ~$50 TAO registration, makes every device a Chutes customer, and links accounts to URnetwork through balance transfers.
  - **Per-user OAuth accounts:** the users pay Chutes themselves, outside URnetwork's balance.
- **The route that fits Chutes' terms:** a written agreement under §9.3 that covers end-user access and a per-request signing scheme. Without one, Chutes Standard models fit only a URnetwork-side relay, which the plaintext rule forbids.
- **Schedule 1 S1.3 cannot be policed blind.** URnetwork cannot see prompts, so it cannot screen out the forbidden data categories. Users would have to be bound to Chutes' terms (§9.2 already requires "terms at least as protective").

### Gaps
- Whether production llm.chutes.ai accepts `X-Chutes-*` hotkey signatures today, and whether it keeps a nonce store. Not tested; the repository is archived and the docs conflict.
- Whether the megallm special case still holds, and whether llm.chutes.ai then enforces a key's `chute_ids`.
- Whether agent-account registration credits the ~$50 to the new account's balance.
- Whether Chutes offers a reseller or "authorized reseller" (§9.4) programme with public terms.

## 6. Reasoning effort per provider API, to map a canonical set (none, minimal, low, medium, high, max)

### Takeaway
There is no common control:
- **OpenAI**: one enum (`none|minimal|low|medium|high|xhigh|max`), with per-model exclusions.
- **Anthropic**: `output_config.effort` (`low|medium|high|xhigh|max`), plus a per-model `thinking` type (`adaptive`, `disabled` where allowed, `between_tools` on Sonnet 5.5). Manual `budget_tokens` is deprecated and rejected on 4.7 and later.
- **Gemini**: `thinking_level` (`minimal|low|medium|high|xhigh`) per model; thinking cannot be turned off on 2.5 Pro, 3 or 4.
- **DeepSeek**: a `thinking` toggle plus `reasoning_effort` `low|high|max`.
- **GLM**: a `thinking` toggle (forced on GLM-5.3) plus `reasoning_effort`, max being the default.
- **Qwen**: `enable_thinking` plus `thinking_budget`.
- **Kimi K3**: always thinks, with `reasoning_effort` `low|high|max`.
- **engy and SayGM** each publish their own translations.

`xhigh`, which OpenAI, Anthropic, Gemini 4 Neon and Hydrogen, GLM-5.2 and engy all support, is missing from the canonical set.

### Cited Findings
**OpenAI (official OpenAPI spec, commit 2026-11-21; reasoning guide)**
- `ReasoningEffort` is `enum ["none","minimal","low","medium","high","xhigh","max"]`, `default: "medium"`: "Not all reasoning models support every value." Chat Completions uses `reasoning_effort` and Responses uses `reasoning.effort`. — [openai-openapi openapi.json](https://github.com/openai/openai-openapi/blob/main/openapi.json)
- The Responses `Reasoning` object also has `mode` (`standard|pro`), `summary` (`auto|concise|detailed`) and `context` (`auto|current_turn|all_turns`). — [openai-openapi openapi.json](https://github.com/openai/openai-openapi/blob/main/openapi.json)
- Exceptions:
  - "GPT-6 Astra does not support `none`… returns HTTP 400."
  - "GPT-6.1 Sol does not support `none` or `minimal` and defaults to `medium`."
  - "GPT-6.2 Astra and GPT-6.2 Sol reject… `none`."
  - "`gpt-5.5` defaults to `medium`."
  - "GPT-5.6 and GPT-6 models support `standard` and `pro` reasoning modes in the Responses API."

  — [OpenAI reasoning guide](https://developers.openai.com/api/docs/guides/reasoning)

**Anthropic (Claude docs)**
- Effort: "Set `output_config.effort`… Most Claude models default to high effort…; Claude Opus 5.5 and Claude Haiku 5.5 default to medium."
- The levels are `max`, `xhigh`, `high`, `medium` and `low`. `max` is "Available on" Fable 5/5.1/5.2, Mythos, Opus 5.5/5/4.8/4.7/4.6, Sonnet 5.5/5/4.6 and Haiku 5.5. `xhigh` is on the same list minus Opus 4.6, Sonnet 4.6 and Mythos Preview. "Not every model that supports `max` supports `xhigh`."
- "Effort is a behavioral signal, not a strict token budget."

— [Claude docs: effort](https://platform.claude.com/docs/en/build-with-claude/effort)
- `thinking` per model (no field / `"adaptive"` / `"enabled"`+budget / `"between_tools"` / `"disabled"`):
  - Opus 5.5, Fable 5.x, Mythos: adaptive / adaptive / 400 / 400 / **400** (thinking cannot be off).
  - Sonnet 5.5: adaptive / adaptive / 400 / "Up-front thinking off at `high` effort or below" / 400.
  - Haiku 5.5 and Opus 5: disabled allowed only "at `high` effort or below".
  - Sonnet 5: "Thinking off" allowed.
  - Opus 4.8/4.7: thinking off by default; adaptive on request.
  - Opus/Sonnet/Haiku 4.5: "Extended thinking" with budget only.

  — [Claude docs: thinking](https://platform.claude.com/docs/en/build-with-claude/thinking)
- "Extended thinking (`thinking.type: "enabled"` with `budget_tokens`) is deprecated. Claude 4.7 and later models do not support it and reject requests that use it". `budget_tokens` has a "Minimum of 1,024 tokens" and must be "Less than `max_tokens`". — [Claude docs: extended thinking](https://platform.claude.com/docs/en/build-with-claude/extended-thinking)
- `display` defaults to `"omitted"` on Claude 5-family models, so thinking text is hidden unless `"summarized"` is set. Discovery: "read its `capabilities.thinking.types.disabled.supported`… from the Models API". — [Claude docs: thinking](https://platform.claude.com/docs/en/build-with-claude/thinking)

**Google Gemini**
- `thinking_level` support per model (default in brackets):
  - gemini-4-neon, gemini-4-hydrogen: low, medium, high, xhigh (high).
  - gemini-4-carbon, gemini-4-argon, gemini-3.8-flash: low, medium, high (medium).
  - gemini-3.6-flash: minimal, low, medium, high (medium).
  - gemini-3.5-flash-lite, gemini-3.1-flash-lite: minimal, low, medium, high (minimal).
  - gemini-3.1-pro-preview: low, medium, high (high).
  - `minimal` is "Not supported on Gemini 4 models or `gemini-3.8-flash`."

  — [Gemini thinking](https://ai.google.dev/gemini-api/docs/thinking)
- OpenAI-compatibility mapping of `reasoning_effort`:
  - `minimal` → Gemini 4 `low`, 3.1 Flash-Lite `minimal`, 2.5 budget 1,024.
  - `low` → `low`, budget 1,024.
  - `medium` → `medium`, budget 8,192.
  - `high` → `high`, budget 24,576.
  - `xhigh` → `xhigh` on Neon and Hydrogen only.
  - "Reasoning cannot be turned off for Gemini 2.5 Pro, Gemini 3, or Gemini 4 models." `none` works only on 2.5 models.
  - "`reasoning_effort` and `thinking_level`/`thinking_budget`… can't be used at the same time."

  — [Gemini OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai)

**DeepSeek**
- Toggle `{"thinking": {"type": "enabled/disabled"}}`. In the Responses format, `{"reasoning": {"effort": "none/low/high/max"}}`, where "`none` disables thinking mode". Effort is `{"reasoning_effort": "low/high/max"}` in OpenAI format and `{"output_config": {"effort": "low/high/max"}}` in Anthropic format. "Thinking mode is enabled by default, with the default effort being `high`." — [DeepSeek thinking mode](https://api-docs.deepseek.com/guides/thinking_mode)
- The mapping is minimal→low, low→low, medium→high, high→high, xhigh→high, max→max and ultra→max. Thinking mode ignores `temperature`, `presence_penalty` and `frequency_penalty`. — [DeepSeek thinking mode](https://api-docs.deepseek.com/guides/thinking_mode)
- The table's column layout was flattened when converted to text, so which format each toggle cell belongs to is slightly uncertain.

**Z.ai GLM**
- `thinking.type` is `enabled` (default) or `disabled`. "GLM-5.3 and GLM-5.3-Flash no longer support disabling thinking (an error will occur…)". — [Z.ai deep thinking](https://docs.z.ai/guides/capabilities/thinking.md)
- `reasoning_effort`, supported only by GLM-5.2 and later:
  - GLM-5.3 and 5.3-Flash take only `max`, `high` and `low` ("Any other input will result in an error"), with `max` the default.
  - GLM-5.2 takes `max`, `xhigh`, `high`, `medium`, `low`, `minimal` and `none`. "`none` or `minimal` indicate that the model stops thinking; `low`/`medium` are mapped to `high`; `xhigh` is mapped to `max`."

  — [Z.ai deep thinking](https://docs.z.ai/guides/capabilities/thinking.md)
- Preserved thinking via `clear_thinking: false` is the default "Starting from GLM-5.4". — [Z.ai thinking mode](https://docs.z.ai/guides/capabilities/thinking-mode.md)

**Qwen (Alibaba Cloud Model Studio)**
- In hybrid mode, `enable_thinking` is passed via `extra_body` because it is not an OpenAI standard parameter. "Thinking-only mode: The model always thinks… cannot be disabled." — [Model Studio deep thinking](https://www.alibabacloud.com/help/en/model-studio/deep-thinking)
- Model lists: "Qwen3.8 open-source series (Hybrid thinking mode, thinking mode enabled by default): qwen3.8-27b". "qwen3.8-2.4t-a95b" supports "thinking mode only". `qwen3.8-omni-flash` uses `reasoning_effort`. — [Model Studio deep thinking](https://www.alibabacloud.com/help/en/model-studio/deep-thinking)
- "Use the `thinking_budget` parameter to set the maximum number of tokens for the reasoning process… kimi-k3.1-pro and kimi-k3 do not support this parameter". `preserve_thinking` controls whether past `reasoning_content` is read. — [Model Studio deep thinking](https://www.alibabacloud.com/help/en/model-studio/deep-thinking)

**Moonshot Kimi**
- K3 always has thinking on. It "supports configuring reasoning strength via the top-level `reasoning_effort`", which takes `low` / `high` / `max` (default `max`). Asked whether thinking can be turned off, the docs answer: "Currently it can't be turned off". — [Kimi K3 quickstart](https://platform.kimi.com/docs/guide/kimi-k3-quickstart.md) (Chinese; translated)
- Kimi K3.1 Pro likewise takes `"low"` / `"high"` / `"max"`, default `"max"`, and the docs say "remove the K2.x `thinking` configuration". — [Kimi reasoning effort](https://platform.kimi.com/docs/guide/use-reasoning-effort.md) (Chinese; translated)
- A search summary claimed the effort guide makes `max` the only usable level. The guide as fetched lists all three levels. — [Kimi reasoning effort](https://platform.kimi.com/docs/guide/use-reasoning-effort.md)

**Aggregator conventions**
- engy: the levels are none…max, with per-model translation; see §2. — [engy reasoning](https://engy.ai/docs/using-the-api/reasoning)
- SayGM: `reasoning_efforts` and `reasoning_effort_aliases` per model, and Anthropic pass-through; see §3. — [api.saygm.com/v1/models](https://api.saygm.com/v1/models); [SayGM docs: Anthropic](https://docs.saygm.com/api/anthropic/)
- OpenRouter's unified `reasoning` object:
  - `effort` takes "max", "xhigh", "high", "medium", "low", "minimal" or "none" (OpenAI-style).
  - `max_tokens` is Anthropic-style; `enabled` and `exclude` also exist.
  - On budget-only models, effort becomes a share of the output limit: max and xhigh ≈95%, high ≈80%, medium ≈50%, low ≈20%, minimal ≈10%; "none" disables.
  - Its catalog metadata exposes `supported_efforts`, `default_effort` and `mandatory` ("do not send `effort: "none"` — the model rejects it").

  — [OpenRouter reasoning tokens](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens)
- Chutes publishes no per-model request schema for its LLM chutes: "No request schema is published for this endpoint." — [Chutes DeepSeek-V4-Pro-0813 agent guide](https://chutes.ai/app/chute/chutes-deepseek-ai-deepseek-v4-pro-0813/llms.txt)

### Inferences
- **A proposed mapping** (inference). Each cell is the parameter to send; "—" means the canonical level should not be offered for that model, so the catalog omits that `<provider>-<model>-<effort>` id.

| Canonical | OpenAI (Chat / Responses) | Anthropic Messages | Gemini (`thinking_level`) | DeepSeek | GLM (Z.ai) | Qwen (Model Studio) | Kimi K3 / K3.1 Pro | engy (any model) |
|---|---|---|---|---|---|---|---|---|
| none | `none`; — on GPT-6 Astra, 6.1 Sol, 6.2 Astra/Sol | `thinking:{type:"disabled"}` where accepted (Sonnet 5, Opus 4.x; Opus 5 and Haiku 5.5 at ≤high effort); Sonnet 5.5 `between_tools`; — on Opus 5.5, Fable, Mythos | — on 2.5 Pro, 3.x and 4.x (`minimal` is only "near-off") | `thinking:{type:"disabled"}` | GLM-5.2 `thinking:{type:"disabled"}`; — on GLM-5.3 | `enable_thinking:false` (hybrid models only) | — | `none` (GLM-5.3 runs at `low`) |
| minimal | `minimal`; — on 6.1 Sol | `effort:"low"` (no minimal) | `minimal` where listed, else `low` | `low` | GLM-5.3 `low`; GLM-5.2 — (`minimal` turns thinking off) | small `thinking_budget` | `low` | `minimal` (= off at engy) |
| low | `low` | `low` | `low` | `low` | GLM-5.3 `low`; GLM-5.2 → high | `thinking_budget` | `low` | `low` |
| medium | `medium` | `medium` | `medium` where listed | → `high` | GLM-5.3: send `high` (`medium` errors) | default | `high` | `medium` |
| high | `high` | `high` | `high` | `high` | `high` | default | `high` | `high` |
| max | `max` where supported, else `xhigh` | `max` where available | `xhigh` on Neon/Hydrogen, else `high` | `max` | `max` | thinking on, no budget | `max` | `max` |

- **Per-model lists, not provider rules.** Several providers silently remap levels (engy, DeepSeek, GLM-5.2, SayGM aliases). Some reject levels a model lacks (OpenAI 400s; GLM-5.3 errors on anything but low, high and max; Anthropic rejects `disabled` on several models). So the catalog needs a per-model effort list, preferably read from each provider's discovery fields: Anthropic `capabilities.thinking.types`, SayGM `reasoning_efforts`, OpenRouter `supported_efforts`.
- **Collapsed ids.** Where a provider maps two canonical levels to one native level, the catalog should either collapse the ids or say the two are identical. Examples: engy `glm-5.2` low=medium=high; Kimi has no medium.
- **`xhigh` has no canonical slot.** OpenAI, Anthropic, Gemini 4 Neon and Hydrogen, GLM-5.2 and engy all expose it. Either add it to the canonical set or map `max` → `xhigh` where `max` is missing.

### Gaps
- Moonshot's English-language docs were not fetched. The K3 facts come from the Chinese pages.
- Per-model effort support on OpenAI's model pages (for example, whether gpt-5.4-mini or nano accept `xhigh` or `max`) was not read one page at a time.
- How SayGM's and Terza's OpenAI-surface routes forward `reasoning_effort` to Anthropic or Gemini upstreams (translation versus pass-through) is not documented.
- Chutes' per-model reasoning switches (`chat_template_kwargs` or `reasoning_effort`) are not documented by Chutes. Its catalog only flags `reasoning` as supported.
