# Brave Search API as of 2026-11-23: endpoints, prices, terms, data handling

All primary pages below were fetched on 2026-11-23. Brave publishes a markdown copy of every docs page, indexed at https://api-dashboard.search.brave.com/llms.txt, and these notes were built from those copies. Dates of the governing documents as fetched:
- Search API Terms of Use: "Last updated: 1 Sep, 2026".
- Service Credit Terms: "Last updated: 1 Sep, 2026".
- Privacy Notice: "Updated 3 November 2026".

Base URL for every endpoint: `https://api.search.brave.com/res`. Anything older or possibly superseded is marked with its date.

## 1. Endpoints and API surface: parameters, headers, response fields, errors, rate-limit headers, versioning

### Takeaway
The current API has 12 documented endpoints under `/res/v1/`:
- AI search: LLM Context and Answers.
- Web search, plus three local endpoints (POIs, POI descriptions, Place Search) and Rich results.
- News, Videos and Images.
- Suggest and Spellcheck.

The Summarizer is deprecated and is no longer in the API reference. Web search takes `q` of at most 600 characters and 75 words, `count` up to 20 and `offset` up to 9. News, images, videos, suggest and spellcheck take `q` of at most 400 characters and 50 words. Every endpoint authenticates with the `X-Subscription-Token` header. Rate limiting uses a 1-second sliding window per plan, returns 429, and reports state in four `X-RateLimit-*` headers. Only non-error responses are billed. Versioning has two layers: `v1` in the path, plus an optional date-pinned `Api-Version: YYYY-MM-DD` header.

### Cited Findings

**Endpoint list (current API reference)**

| Endpoint | Method and path (base `https://api.search.brave.com/res`) | Source |
|---|---|---|
| LLM Context | `GET` (and `POST` with JSON body) `/v1/llm/context` | [API ref](https://api-dashboard.search.brave.com/api-reference/ai/llm_context/get), [docs](https://api-dashboard.search.brave.com/documentation/services/llm-context) |
| Answers | `POST /v1/chat/completions` (OpenAI-compatible) | [API ref](https://api-dashboard.search.brave.com/api-reference/ai/answers) |
| Web Search | `GET /v1/web/search` | [API ref](https://api-dashboard.search.brave.com/api-reference/web/search/get) |
| Local POIs | `GET /v1/local/pois` | [API ref](https://api-dashboard.search.brave.com/api-reference/web/local_pois) |
| POI Descriptions | `GET /v1/local/descriptions` | [API ref](https://api-dashboard.search.brave.com/api-reference/web/poi_descriptions) |
| Rich search | `GET /v1/web/rich` (takes `callback_key`) | [API ref](https://api-dashboard.search.brave.com/api-reference/web/rich_search) |
| News | `GET /v1/news/search` | [API ref](https://api-dashboard.search.brave.com/api-reference/news/news_search/get) |
| Videos | `GET /v1/videos/search` | [API ref](https://api-dashboard.search.brave.com/api-reference/videos/video_search/get) |
| Images | `GET /v1/images/search` | [API ref](https://api-dashboard.search.brave.com/api-reference/images/image_search) |
| Place Search | `GET /v1/local/place_search` | [API ref](https://api-dashboard.search.brave.com/api-reference/web/place_search) |
| Suggest | `GET /v1/suggest/search` | [API ref](https://api-dashboard.search.brave.com/api-reference/other/suggestions) |
| Spellcheck | `GET /v1/spellcheck/search` | [API ref](https://api-dashboard.search.brave.com/api-reference/other/spell_check) |
| Summarizer (deprecated) | `/res/v1/summarizer/search`: "Brave has deprecated it" | [x402 llms.txt](https://search.agent.s.brave.app/llms.txt) |

- The Summarizer is still reachable through the web search parameter `summary`, described as "This parameter enables summary key generation in web search results. This is required for summarizer to be enabled". `summarizer` is also still an accepted `result_filter` value. — [Web search API ref](https://api-dashboard.search.brave.com/api-reference/web/search/get)
- Brave's MCP server says `brave_summarizer` "remains available for existing Pro AI subscribers, but new integrations should use `brave_answers` instead". It also says "Summarizer requires a **Pro AI** plan" (Pro AI is a legacy plan). — [brave-search-mcp-server README](https://github.com/brave/brave-search-mcp-server)
- Brave's docs home sorts the endpoints by audience. LLM Context is "Search for *AI agents*… This is the default for RAG, tools, and chatbots". Web Search is "Search for *humans*. Ranked titles, URLs, and short snippets for a results page, plus local and rich enrichments". — [Docs home](https://api-dashboard.search.brave.com/documentation)

**Web Search (`/v1/web/search`) query parameters (verbatim limits from the API reference)** — [Web search API ref](https://api-dashboard.search.brave.com/api-reference/web/search/get)
- `q` (required): "Query can not be empty. Maximum of 600 characters and 75 words in the query."
- `country`: a 2-character code from a fixed list of 37 countries plus `ALL`. Default `US`.
- `search_lang`: 51 language codes (`en`, `en-gb`, `zh-hans`, `pt-br`, and others). Default `en`.
- `ui_lang`: locale codes such as `en-US`, `de-DE` and `es-US`. Default `en-US`.
- `count`: `1`–`20`, default `20`. "The maximum is 20. The actual number delivered may be less than requested… **NOTE:** Count only applies to web results."
- `offset`: `0`–`9`, default `0`. "The zero based offset that indicates number of search result pages (count) to skip… the maximum is 9… It is possible for multiple pages to include some overlap in results."
- `safesearch`: `off` / `moderate` / `strict`, default `moderate`.
- `spellcheck`: boolean, default `true`. "If the spell checker is enabled, the modified query is always used for search. The modified query can be found in altered key."
- `freshness`: `pd` (24 h), `pw` (7 days), `pm` (31 days), `py` (365 days), or a custom range `YYYY-MM-DDtoYYYY-MM-DD`.
- `text_decorations`: boolean, default `true`. "Whether display strings (e.g. result snippets) should include decoration markers (e.g. highlighting characters)."
- `result_filter`: a comma-delimited list of `discussions`, `faq`, `infobox`, `news`, `query`, `summarizer`, `videos`, `web`, `locations`. If omitted, all types are returned "where data is available and the plan has the corresponding option activated."
- `units`: `metric` or `imperial`.
- `goggles`: a URL or inline definition, "a single Goggle or a list of up to 3 Goggles". `goggles_id` is deprecated.
- `extra_snippets`: "allow you to get up to 5 additional, alternative excerpts."
- `summary`: legacy summarizer key, described above.
- `enable_rich_callback`: boolean, default `false`. "**NOTE**: Requires `Search` plan."
- `include_fetch_metadata`: boolean, default `false`.
- `operators`: boolean, default `true`.
- `operators_fallback`: boolean, default `false`.
- Pagination guidance: "check the `more_results_available` field… Only request the next page if `more_results_available` is `true`." — [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)

**Web Search request headers** — [Web search API ref](https://api-dashboard.search.brave.com/api-reference/web/search/get)
- `x-subscription-token` (required): "The subscription token that was generated for the product."
- Location headers:
  - `x-loc-lat` (−90 to 90) and `x-loc-long` (−180 to 180).
  - `x-loc-timezone` (IANA).
  - `x-loc-city`.
  - `x-loc-state` ("up to three characters", the first-level ISO 3166-2 subdivision) and `x-loc-state-name`.
  - `x-loc-country` (ISO 3166-1 alpha-2).
  - `x-loc-postal-code`.
- `api-version` (`YYYY-MM-DD`; "Default is the latest that is available").
- `accept` (`application/json` or `*/*`).
- `cache-control`: "Brave Search will return cached content by default. To prevent caching set the Cache-Control header to `no-cache`. This is currently done as best effort."
- `user-agent`: "Brave search can utilize the user agent to provide a different experience depending on the device."
- The examples also send `Accept-Encoding: gzip`. — [Authentication guide](https://api-dashboard.search.brave.com/documentation/guides/authentication)

**Web Search response fields** — [Web search API ref](https://api-dashboard.search.brave.com/api-reference/web/search/get)
- `query.*`: `original`, `altered` ("The altered query by the spellchecker"), `cleaned`, `is_navigational`, `is_news_breaking`, `spellcheck_off`, `country`, `more_results_available`, `search_operators`, `show_strict_warning`.
- Basic fields of `web.results[]`:
  - `title` and `url`.
  - `description` ("A description for the web page").
  - `extra_snippets` ("A list of extra alternate snippets").
  - `age` ("A human-readable representation of the web search result's age. For example, `2 days ago`").
  - `page_age` ("The page's date, based on its published or last modified date").
  - `page_fetched` ("when the web page was last fetched") and `fetched_content_timestamp`.
  - `language`, `family_friendly`, `thumbnail`, `subtype`, `is_live`, `content_type`.
- `web.results[].profile`: `{name, url, long_name, img}` ("A profile associated with the web page").
- `meta_url`: "Aggregated information on the URL", with `scheme`, `netloc`, `hostname`, `favicon` and `path` ("useful as a display string").
- `deep_results`: `news[]`, `buttons[]`, `videos[]` and `images[]`.
- Structured fields: `schemas` (schema.org-style data), `location`, `video`, `movie`, `faq`, `qa`, `book`, `rating`, `article`, `product`, `review`, `recipe`, `software`, `organization`, `creative_work`, `music_recording`, `cluster`.
- Top-level blocks: `mixed` ("Preferred ranked order of search results"), `discussions`, `faq`, `infobox`, `locations`, `news`, `videos`, `summarizer` (`{type, key}`) and `rich` (callback hint).
- The marketing page's sample response shows the description with HTML highlight tags, for example "Best `<strong>Greek</strong>` `<strong>Restaurants</strong>`…". That is what `text_decorations=true` produces. — [brave.com/search/api](https://brave.com/search/api/)

**News Search (`/v1/news/search`)** — [News API ref](https://api-dashboard.search.brave.com/api-reference/news/news_search/get)
- `q`: "Maximum of 400 characters and 50 words in the query."
- `count`: `1`–`50`, default `20`.
- `offset`: `0`–`9`.
- `safesearch` default is **`strict`** (web search defaults to `moderate`).
- Other parameters: `country` (incl. `ALL`), `search_lang`, `ui_lang`, `spellcheck` (default true), `freshness` (same values as web), `extra_snippets` ("up to 5 additional, alternative excerpts"), `goggles` (up to 3), `include_fetch_metadata`, `operators`, `operators_fallback`.
- News changelog: added 2023-08-15; freshness custom ranges 2024-03-20; "extra snippets feature for AI and Data plans" 2024-09-10; Goggles 2025-01-15. — [News docs](https://api-dashboard.search.brave.com/documentation/services/news-search)

**Other endpoints**
- Images: `q` at most 400 characters and 50 words. `count` `1`–`200`, default 50. "Image search is not paginated and has no `offset` parameter." — [Images API ref](https://api-dashboard.search.brave.com/api-reference/images/image_search)
- Videos: `q` at most 400 characters and 50 words. `count` `1`–`50`, default 20. `offset` `0`–`9`. — [Videos API ref](https://api-dashboard.search.brave.com/api-reference/videos/video_search/get)
- Suggest: `q` at most 400 characters and 50 words. `count` `1`–`20`, default 5. `rich` requires "a paid autosuggest subscription". — [Suggest API ref](https://api-dashboard.search.brave.com/api-reference/other/suggestions)
- Spellcheck: `q` at most 400 characters and 50 words. — [Spellcheck API ref](https://api-dashboard.search.brave.com/api-reference/other/spell_check)
- Place Search:
  - Takes `q` (optional), `latitude`/`longitude` or a `location` string ("`san francisco ca united states`"), `radius` (a "bias" in meters, not a strict radius; global if omitted), and `count` `1`–`100`, default 20. — [Place Search API ref](https://api-dashboard.search.brave.com/api-reference/web/place_search)
  - Added 2026-01-15. Radius restrictions lifted 2026-03-04. — [Place search docs](https://api-dashboard.search.brave.com/documentation/services/place-search)
- Local POIs and descriptions: `ids` (max 20). "The ids are valid only for 8 hours." — [Local POIs API ref](https://api-dashboard.search.brave.com/api-reference/web/local_pois). The web search docs add: "Note that the `id` fields of POIs are ephemeral and will expire after approximately 8 hours. Do not store them for later use." — [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)
- Rich results:
  - Flow: call web search with `enable_rich_callback=1`, read `rich.hint.callback_key`, then call `/v1/web/rich`.
  - Verticals include calculator, definitions (Wordnik), unit conversion, unix timestamp, package tracker, stocks (FMP), currency (Fixer), cryptocurrency (CoinGecko), weather (OpenWeatherMap), and sports (Stats Perform, API Sports).
  - Brave says: "Some of these providers will require attribution for showing this data."
  - Source: [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)

**LLM Context (`/v1/llm/context`) parameters** — [LLM Context docs](https://api-dashboard.search.brave.com/documentation/services/llm-context), [API ref](https://api-dashboard.search.brave.com/api-reference/ai/llm_context/get)
- `q`: "Maximum of 600 characters and 75 words."
- `count`: `1`–`50`, default 20 ("maximum number of search results considered").
- `maximum_number_of_urls`: `1`–`50`, default 20.
- `maximum_number_of_tokens`: `1024`–`32768`, default `8192`.
- `maximum_number_of_tokens_per_url`: `512`–`8192`, default `4096`.
- `context_threshold_mode`: `strict`, `balanced`, `lenient` or `disabled`.
- `safesearch`: "When not set, no filtering is applied — except for local recall, which stays `strict`."
- `enable_local`: auto-detects local recall from location headers.
- `goggles` (up to 3).
- `freshness`.
- `enable_source_metadata`: adds `site_name`, `favicon`, `thumbnail`, `description` and `fetched_content_timestamp`.
- `spellcheck`, `operators`, `operators_fallback` (default `true` here).
- "POST accepts the same query parameters as a JSON request body… useful for complex queries or when parameters exceed URL length limits."
- Response: `grounding.generic[]` (`url`, `title`, `snippets` = "Extracted text chunks from the page relevant to the query"), `grounding.poi`, `grounding.map`, and `sources{url: {title, hostname, age[4], description?, fetched_content_timestamp?}}`. "Snippets may contain plain text **or** JSON-serialized structured data (tables, schemas, code blocks)."
- Brave's guidance: "Set a 30-second timeout for requests" and "Handle empty `grounding.generic` arrays gracefully".

**Answers (`POST /v1/chat/completions`)** — [Answers API ref](https://api-dashboard.search.brave.com/api-reference/ai/answers)
- `messages`: "Exactly one `user` message is supported."
- `model`: `brave-pro` or `brave`, default `brave-pro`.
- `stream`: default `true`.
- `web_search_options` (`search_context_size`, `user_location`), `country`, `language`, `safesearch`.
- `enable_citations`, `enable_entities`, `enable_research`.
- Research limits: `research_maximum_number_of_queries` 1–50, `..._seconds` 1–300 (default 180), `..._results_per_query` 1–60 (default 30).
- The response includes `usage.completion_tokens_details.reasoning_tokens`.

**Error codes and error body**
- Documented error statuses per endpoint:
  - Web, News, Videos, Images, Suggest, Spellcheck and Rich: 404, 422 and 429.
  - Local POIs, POI descriptions and Place Search: also 400.
  - LLM Context: 400, 403, 404, 422 and 429.
  - Answers: 400, **402 Payment Required**, 403, 404, 422 and 429.
- Error body: `{type, error: {id, status, detail, meta, code}, time}`.
- Sources: [Web search API ref](https://api-dashboard.search.brave.com/api-reference/web/search/get), [LLM Context API ref](https://api-dashboard.search.brave.com/api-reference/ai/llm_context/get), [Answers API ref](https://api-dashboard.search.brave.com/api-reference/ai/answers)

**Rate limiting** — [Rate limiting guide](https://api-dashboard.search.brave.com/documentation/guides/rate-limiting)
- "Rate limits are enforced using a **1-second sliding window** to count requests per plan."
- "When you exceed your rate limit, the API will return a **429 status code** and your request will fail."
- The four response headers:
  - `X-RateLimit-Limit`: e.g. `1, 15000`, with "**0** for unlimited" on the monthly figure.
  - `X-RateLimit-Policy`: e.g. `1;w=1, 15000;w=2592000`, with windows in seconds (2,592,000 s = 30 days).
  - `X-RateLimit-Remaining`.
  - `X-RateLimit-Reset`: seconds until each window resets.
- "**Counted on arrival**: The request count is increased when request is received. The processing time does not affect the rate-limit."
- "**Important**: Only successful requests (non-error responses) are counted against your quota and billed."
- "**Successful requests only**: Failed requests don't count against your quota, so you're only charged for successful API calls."
- On 429, Brave advises: "check the `X-RateLimit-Reset` header to determine how long to wait before retrying. Implement exponential backoff."

**Versioning** — [Versioning guide](https://api-dashboard.search.brave.com/documentation/guides/versioning)
- Path versioning: a major version (`v1`) "rarely changed… only be used when there is a major API redesign."
- Header versioning: "Backwards incompatible changes… are dated with the format `YYYY-MM-DD`. Without a version header, API requests default to the latest version. The API behavior can be locked to a specific version by providing a version header named `Api-Version`."
- Brave treats these as backwards compatible, needing no action: "Adding new optional request parameters or headers", "Adding new properties to an existing API response", "Changing the order of properties", "Changing the length and format of string values".
- Example of a pinned version: after the 2026-07-31 LLM Context pipeline change, "pin `Api-Version: 2026-02-06` to keep the previous pipeline." — [LLM Context docs](https://api-dashboard.search.brave.com/documentation/services/llm-context)

### Inferences
- The deepest page web search can return is `offset=9` × `count=20`, about 200 web results per query string, and each page is a separately billed request.
- Brave says each successful request is billed, and failed ones (429, 4xx) are not. So a relay can meter per successful 2xx response and pass 429s through to the caller (or queue them) without paying for them.
- `text_decorations=true` (the default) puts HTML highlight markup into `description` and snippets. A relay that feeds LLM context or renders UI should send `text_decorations=false` or sanitize the markup.
- The `X-Loc-*` headers and `user-agent` carry end-user location and device data. A privacy-preserving relay should strip or coarsen them unless the person opts in, because Brave logs whatever the customer sends (see section 5).
- The q limits differ: 600 characters and 75 words for web and LLM Context, 400 and 50 for the other endpoints. Brave's own MCP server still validates 400 and 50 for web and LLM Context (see section 6). A relay should enforce limits per endpoint.

### Gaps
- I did not find documented HTTP status codes for exhausted prepaid credit or for a revoked or invalid key on web search. The web search reference lists only 404, 422 and 429. Answers lists 402 and 403.
- The legacy Summarizer endpoints and their parameters are no longer in the API reference. I did not reconstruct them, to avoid relying on memory.
- The docs give no SLA or latency guarantee. The marketing page claims "Up to 20x faster than other search APIs". The Feb 12, 2026 blog (updated 2026-09-17) says "a total latency under 500ms at p90 for calls to LLM Context."

## 2. Which endpoints generate text with an LLM, and which only retrieve or extract

### Takeaway
Two current endpoints generate text with an LLM: Answers (`/v1/chat/completions`) and POI Descriptions (`/v1/local/descriptions`, "LLM generated descriptions"). So does the deprecated Summarizer. LLM Context is retrieval plus extraction: Brave describes it as "raw extracted content… without AI-generated summaries" made of page chunks. Web, News, Images, Videos, Place Search, Local POIs, Rich, Suggest and Spellcheck are retrieval or structured-data endpoints.

### Cited Findings
- **Answers generates text.** "API for AI-generated answers backed by real-time web search and verifiable sources… Under the hood, this same service powers Brave's Ask Brave feature." The request selects a model (`brave-pro` or `brave`), billing counts input and output tokens, and research mode runs multiple searches with "extended thinking off". — [Answers docs](https://api-dashboard.search.brave.com/documentation/services/answers), [Answers API ref](https://api-dashboard.search.brave.com/api-reference/ai/answers)
- A Brave blog says Ask Brave "uses a lower performance open-weights model (Qwen3)". It does not say the Answers API uses that same model. — [Brave blog, Feb 12 2026, updated June 25 2026](https://brave.com/blog/most-powerful-search-api-for-ai/)
- **POI Descriptions generates text.** The API reference title line: "Get LLM generated descriptions about points of interest." — [POI descriptions API ref](https://api-dashboard.search.brave.com/api-reference/web/poi_descriptions). The x402 OpenAPI: "AI-generated descriptions of places found by web or place search." — [openapi.json](https://search.agent.s.brave.app/openapi.json)
- **The Summarizer generates text and is deprecated.** The MCP server: "Generates AI-powered summaries from web search results using Brave's summarization API… **Deprecated**." — [MCP README](https://github.com/brave/brave-search-mcp-server). The x402 docs: "The Summarizer (`/res/v1/summarizer/search`) is not sold: Brave has deprecated it." — [x402 llms.txt](https://search.agent.s.brave.app/llms.txt)
- **LLM Context is extraction.**
  - "LLM Context returns extracted page chunks and source metadata in a shape and length that satisfies the needs of an LLM without need for further scraping."
  - Use it when you "Want raw extracted content without AI-generated summaries".
  - "**Raw extracted content** for your own LLM pipeline. Best for AI agents, RAG, and applications where you control the model."
  - Snippets are "Extracted text chunks from the page relevant to the query".
  - Source: [LLM Context docs](https://api-dashboard.search.brave.com/documentation/services/llm-context)
- Brave's own contrast in the Answers docs: "Need extracted web content for **your** model? Use LLM Context… Answers writes the cited reply for you." — [Answers docs](https://api-dashboard.search.brave.com/documentation/services/answers)
- The Terms define generated output separately: "'Generated Results' means outputs from calls made to the API that are generated by a generative artificial intelligence system or model." They add: "GENERATED RESULTS MAY BE THE SAME OR SIMILAR TO THOSE PROVIDED TO OTHER API CUSTOMERS." — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)
- Rich results are "sourced from 3rd-party API providers" (weather, stocks and others). That is structured retrieval. — [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)

### Inferences
- Under the "all remote LLM inference must run in a TEE" rule, the sidecar should exclude Answers, the Summarizer (including the web search `summary=1` parameter and the `summarizer` result_filter), and `/local/descriptions`. Brave runs those models on its own infrastructure, outside any TEE the sidecar controls.
- LLM Context, Web, News, Images, Videos, Place Search, Local POIs, Rich, Suggest and Spellcheck return no model-written prose, so they are compatible.
- If the sidecar exposes a "local search" tool, it should call `/local/pois` and `/local/place_search` but not `/local/descriptions`. Brave's MCP `brave_local_search` tool includes "AI-generated descriptions", so it should not be reused as-is.

### Gaps
- Brave does not say whether POI descriptions are generated per request or generated in advance and cached. Either way the output is LLM text.
- Brave does not say whether LLM Context's chunk selection and ranking ("smart chunks are ranked") uses machine-learned models. No source says it generates text.
- I found no statement on whether `infobox` or `faq` fields in web results contain any model-written text.

## 3. Plans and prices, billing mechanics, keys, payment methods

### Takeaway
There is no standalone free plan. There are four self-serve prepaid plans, each with $5 of free credit that renews monthly:

| Plan | Price | Capacity |
|---|---|---|
| Search | $5 per 1,000 requests | 50 requests/s |
| Answers | $4 per 1,000 queries + $5 per 1M input tokens + $5 per 1M output tokens | 2 requests/s |
| Spellcheck | $5 per 10,000 requests | 100 requests/s |
| Autosuggest | $5 per 10,000 requests | 100 requests/s |

Enterprise is custom, and Zero Data Retention is sold there. Billing is prepaid through a Stripe card, with optional auto-reload, monthly usage limits per plan and email alerts. Service pauses when the balance reaches $0. Accounts get up to 10 keys per plan. There is no documented API for managing keys. Payment can also be made per request in USDC on Base via x402, with no account.

### Cited Findings

**Current price list (docs pricing page, rendered 2026-11-23)** — [Docs pricing](https://api-dashboard.search.brave.com/documentation/pricing)
- **Search**:
  - "$ 5.00 per 1,000 requests". "Includes free $5 in credits every month. Credits are automatically applied to your account."
  - "Capacity: 50 requests per second".
  - Features: "Web search: Human readable URLs & text snippets", "LLM context: Results optimized for models & agents", "News, videos, images, and more".
- **Answers**:
  - "$ 4.00 per 1,000 queries + $5.00 per 1,000,000 input tokens + $5.00 per 1,000,000 output tokens". Free $5 per month.
  - "Capacity: 2 requests per second".
- **Spellcheck**: "$ 5.00 per 10,000 requests". Free $5 per month. "Capacity: 100 requests per second".
- **Autosuggest**: "$ 5.00 per 10,000 requests". Free $5 per month. "Capacity: 100 requests per second".
- **Enterprise**: "Need custom terms, capacity, or ZDR? … Full-funnel Zero Data Retention · Custom agreements & NDAs · Invoicing & enterprise-grade support".
- The marketing page shows the same Search, Answers and Enterprise prices, and lists these Search plan "Special features": "Goggles: Custom reranking & result filtering · Extra alternate snippets · Schema-enriched results + added metadata". The banner reads "Up to $20 in free calls every month · Prepaid credits, no subscription." — [brave.com/search/api](https://brave.com/search/api/)
- Which plan covers what: "The **Search** plan covers web, news, image, and video search with local enrichments, rich data and LLM context for LLMs and agents… For autocomplete and spelling correction, the **Autosuggest** and **Spellcheck** plans are available separately." — [Help & Feedback FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback). "The **Search** plan includes both LLM Context (Search for AI agents) and Web Search." — [Quickstart](https://api-dashboard.search.brave.com/documentation/quickstart)
- Answers cost example from the docs: 2 queries, 1,234 input tokens and 300 output tokens cost `X-Request-Total-Cost: 0.01567` (queries $0.008, tokens in $0.00617, tokens out $0.0015). Per-request cost comes back in `X-Request-*` headers for synchronous calls and in a final `<usage>` message when streaming. "Limits are checked before answering. If limits aren't exceeded when a question starts, it will be answered in full even if it exceeds limits during processing. You'll only be charged up to your imposed limit." — [Answers docs](https://api-dashboard.search.brave.com/documentation/services/answers)

**Free tier**
- "We do not offer a standalone free plan. However, each plan receives $5 in free credits that renew every single month… equivalent to (for example) 1,000 queries per month on the Search plan… With four available plans (Search, Answers, Autosuggest, and Spellcheck) you could feasibly access $20 in total free credits each month." — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)
- Attribution condition (Feb 12, 2026): "To take advantage of this free credit, all you need to do is attribute the Brave Search API in your project's website / about pages." — [Brave blog, Feb 12 2026](https://brave.com/blog/most-powerful-search-api-for-ai/). The current FAQ and pricing pages do not repeat this condition. — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback), [Docs pricing](https://api-dashboard.search.brave.com/documentation/pricing)
- How to get the credit without spending: "enter a credit card at signup and set your prepay amount to $0… the service will still need to complete the automatic credit card check with a $0 or $1 charge hold." — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)

**Billing mechanics (prepaid)** — all quotes from the [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback) unless noted
- Card: "On a prepaid plan it is also the card we charge for the credits you buy, whether you add them yourself or through auto-reload." The payment method is changed in a "Stripe page".
- Balance exhaustion: "further usage draws down your prepaid balance, and the service pauses once that balance reaches $0." Also: "if you exhaust your prepaid balance your service will be paused — further API requests are rejected until you add more funds."
- Auto-reload:
  - Two settings: "'When balance drops below'" and "'Amount to add', minimum $5". "The amount we add is the fixed figure you chose."
  - Cap: "a monthly limit caps how much auto-reload can charge your payment method in any given calendar month. It applies to auto-reload only — top-ups you make yourself are not counted against it. If a reload would exceed what's left of that limit we add only the remainder, and skip the reload once less than $0.50 of it is left… If you leave it empty… auto-reload is uncapped."
- Usage limits (spend caps): "a usage limit caps how much a plan can spend in any given month." "Your monthly usage limit will consist of the amount you entered plus the free monthly credits." If the limit is below the prepaid balance, "the remaining prepaid balance would simply roll over to the following month."
- Alerts: "You can also set alerts for when your balance gets low in the Usage alerts tab, and you can configure usage alerts at the plan level… Brave will send you an email once your usage crosses the threshold."
- Visibility: "usage and remaining credits are visible in the dashboard at any time". The Credits balance tab shows "the current balance, the spending for each plan, total free credits, and the settings for your auto-reload."
- Refunds and expiry (FAQ): "users do not have a right to a refund of unused API credits… the credits you purchase do not expire… Free monthly credits are the exception — those are replaced each month rather than carried over."
- **Conflict on expiry.** The Service Credit Terms (1 Sep 2026) say: "Service Credits expire upon the earlier of one year from the date of issuance or the date that you close your account with us." They also say "Purchases of Prepaid Service Credits are non-refundable" and "Service Credits may not be transferred, sold, gifted, traded, or assigned. Any attempt to do so is void and may result in revocation or cancellation of the Service Credits, or suspension or termination of your access." Under the ToS order of precedence, the Service Credit Terms rank above the Terms of Use. — [Service Credit Terms](https://api-dashboard.search.brave.com/terms-of-service/credit-terms), [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)
- Debit basis: "We will debit your Service Credits balance based on your use of Services at the then-current usage rates published for the applicable Services." — [Service Credit Terms](https://api-dashboard.search.brave.com/terms-of-service/credit-terms)
- Legacy postpaid plans: "If you already have access to one of our existing, postpaid plans, nothing will change… if you decide to cancel a postpaid plan, you won't be able to activate it again." On a postpaid plan, "additional usage is charged on a pay-as-you-go basis."
- Invoices: "Your invoice settles your account as a whole… The itemised breakdown is under Invoices." "Credits can take up to two minutes to appear."
- Terms of Use on fees: "All payments are non-refundable except as otherwise expressly provided in this Agreement or as required by law. If Customer fails to pay the Fees when due, Provider may charge interest on the past due amount at the rate of 1.5% per month." Taxes are the customer's responsibility. — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)

**API keys**
- "Do I need a key for every plan? Yes… You may have up to 10 keys per plan." — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)
- Keys are created in the dashboard (API Keys section → "Add API Key", with a descriptive name). "You can generate new and revoke old keys from the dashboard." — [Quickstart](https://api-dashboard.search.brave.com/documentation/quickstart), [Authentication guide](https://api-dashboard.search.brave.com/documentation/guides/authentication)
- Rate limits count "requests per plan", not per key. — [Rate limiting guide](https://api-dashboard.search.brave.com/documentation/guides/rate-limiting)
- Terms of Use: "Provider may revoke and replace an API Key at any time." Circumventing limits "including by creating multiple accounts" is prohibited (Use Restrictions (v)). — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)

**Payment methods**
- Card via Stripe. If a card is declined, Brave recommends trying "a different Visa or Mastercard credit or debit card", or signing up "through our AWS Marketplace listing, which supports additional payment methods (Paid only)" ([AWS listing](https://aws.amazon.com/marketplace/pp/prodview-qjlabherxghtq)). — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)
- **Crypto (x402)**, launched Nov 12, 2026 — [Brave blog](https://brave.com/blog/search-api-agentic-payments/):
  - "Brave runs its own facilitator accepting USDC on the Base blockchain, with acceptance on other networks and with other stablecoins incoming soon."
  - "Gas fees for transacting on the Base blockchain will be covered for a limited time."
  - Host: `https://search.agent.s.brave.app`. "Today each request carries its own payment… Answers, Autosuggest and Spellcheck are not sold here yet." — [Agent payments guide](https://api-dashboard.search.brave.com/documentation/guides/agent-payments)
  - x402 prices: 5000 base units ($0.005, "$5/1k") for each of `/res/v1/web/search`, `/llm/context`, `/news/search`, `/videos/search`, `/images/search`, `/local/place_search`, `/local/pois` and `/local/descriptions`.
  - "There is no session, no credit balance, and no top-up." "A failed search is never charged."
  - Settlement is "USDC on Base, `eip155:8453`", x402 V2 only. "An x402 offer is payable for 300 seconds."
  - Autosuggest and Spellcheck "cost less than the fee a facilitator takes for settling one payment."
  - Source for the x402 details: [x402 llms.txt](https://search.agent.s.brave.app/llms.txt)
- Enterprise: "Invoicing & enterprise-grade support". — [Docs pricing](https://api-dashboard.search.brave.com/documentation/pricing)

**Superseded plans (for comparison; archived brave.com/search/api, 2025-06-12)** — [Wayback snapshot](https://web.archive.org/web/20250612135902/https://brave.com/search/api/)

| Tier (2025) | Price | Capacity and quota | Rights listed |
|---|---|---|---|
| Data for AI Free | Free | 1 query/s, up to 2,000/month | "Rights to use data for AI inference" |
| Data for AI Base | $5 CPM | 20 queries/s, up to 20M/month | same |
| Data for AI Pro | $9 CPM | 50 queries/s, no monthly limit | same |
| Data for Search Free | Free | 1 query/s, up to 2,000/month | web search only (no AI inference listed) |
| Data for Search Base | $3 CPM | 20 queries/s, up to 20M/month | same |
| Data for Search Pro | $5 CPM | 50 queries/s, no monthly limit | same |
| Data w/ storage rights Base | $26 CPM | 20 queries/s, up to 20M/month | "Rights to store data" + AI inference; tagline "Cache/store data to train AI models" |
| Data w/ storage rights Pro | $45 CPM | 50 queries/s, no monthly limit | same |
| Autosuggest & Spellcheck Free | Free | 5 queries/s, up to 5,000/month | — |
| Autosuggest & Spellcheck Pro | $0.50 CPM | 100 queries/s, no monthly limit | — |

The Summarizer was listed only on the Data for AI plans.

### Inferences
- Per-request cost of what the sidecar would use: $0.005 for web, LLM Context, news, images, videos and place/POI calls; $0.0005 for suggest and spellcheck.
- LLM Context costs the same per request whatever its token budget (up to 32,768 tokens). Brave charges no per-token fee for it, so a cost-plus-markup rule can be flat per call by endpoint.
- The $5 monthly credit is small, about 1,000 Search calls per plan. For a multi-user relay it is a rounding error, not a free tier.
- Usage limits, alerts and the spend counter all work per plan, not per key. Per-user or per-key spend control must be built into URnetwork's relay. Keys can still split traffic into up to 10 labeled buckets.
- 50 requests/s is per plan and shared across keys. The Terms forbid extra accounts to raise it ("creating multiple accounts"), so higher throughput means negotiating Enterprise capacity.
- At $0 balance the service pauses. With auto-reload set and a high enough monthly auto-reload limit, the relay avoids outages. An uncapped auto-reload is an unbounded liability if keys leak.
- Prepaid credits may expire after one year under the Service Credit Terms. Top-ups should be sized to roughly a quarter or less of usage, not bought in bulk.

### Gaps
- I found no Brave-dated announcement of the postpaid-to-prepaid switch. An independent write-up dated Sept 10, 2026 says Brave "recently sent a mass email" announcing that newly activated plans "will move from a postpaid, pay-as-you-go model to a prepaid, pay-as-you-go one" ([SecurityOnline](https://securityonline.info/brave-search-api-prepaid-billing/)). That makes the switch roughly Aug–Sep 2026, unconfirmed.
- Whether the free credit still requires attribution as of 2026-11-23 is unclear. The Feb 2026 blog says it does; current pages are silent.
- Purchased credits either do not expire (FAQ) or expire after one year (Service Credit Terms). Brave should confirm which.
- No programmatic key-management or usage API is documented, nor any per-key usage report or per-key spend cap. The dashboard may show per-key data, but I could not read it (login required).
- Enterprise prices, capacity tiers and current storage-rights pricing are not published.
- I could not read the AWS Marketplace listing's prices.

## 4. Terms of service and licensing (verbatim where binding)

### Takeaway
The Search API Terms of Use (1 Sep 2026) license the API only "to develop, test, and integrate the API with, the Customer Applications" and "use the Search Results with the Customer Applications". They contemplate End Users explicitly and do not forbid LLM grounding or inference. They do forbid:
- storing, caching or building a database of Search Results beyond "transient storage required for operation";
- derivative works of Search Results;
- making the API available to third parties;
- replicating the API's functionality;
- redistributing, reselling or sublicensing Search Results;
- using results to train, evaluate or benchmark AI.

The FAQ says flatly that "It is prohibited to retain any and all data received". Storage needs a custom plan. The old "Data for AI" versus "Data for Search" rights split no longer appears in the current plans or ToS. Attribution is optional under the ToS, but the Feb 2026 blog ties the free credit to it. Brave can terminate for any reason on 10 days' notice, suspend immediately for legal exposure, and suspend after a 5-day cure period for a suspected use-restriction breach.

### Cited Findings
All quotes are from the [Search API Terms of Use, last updated 1 Sep 2026](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service) (same text at [/terms-of-service](https://api-dashboard.search.brave.com/terms-of-service)) unless another source is named. Section numbers are inferred from the document's cross-references (3 = License, 4 = Customer Responsibilities, 13 = Term/Termination/Suspension), because the HTML renders the numbering automatically.

**Definitions**
- "'Customer Applications' means any applications, products or services offered by Customer that are designed to access the API."
- "'End Users' means, collectively, all third party end users of the Customer Applications."
- "'Search Query Data' means any queries or other information that Customer makes available to Provider via calls to the API."
- "'Search Results' means any outputs from calls made to the API, which may consist of (i) internet search results; (ii) Generated Results; or (iii) Third-Party Content."

**License Grant (3(a))**
- "Provider hereby grants Customer a limited, worldwide, revocable (as provided in this Agreement), non-exclusive, non-transferable and non-assignable, non-sublicensable license during the Term to (i) use the API and Documentation solely to develop, test, and integrate the API with, the Customer Applications; (ii) use the Search Results with the Customer Applications; and (iii) use and display the Provider's Marks solely as provided herein."

**Use Restrictions (3(b)), the full binding list**
- "Customer shall not use the API, Search Results, Documentation or Provider's Marks for any purposes beyond the scope of the license granted in this Agreement and the restrictions in this Section. Customer shall not and shall not permit End Users or others to:
  - (i) store, cache, or create a database of Search Results, in whole or in part, other than transient storage required for operation of Customer Applications or related software, service or systems;
  - (ii) create derivative works of the API, Documentation or Search Results;
  - (iii) rent, lease, lend, sell, distribute, publish, sublicense, assign, transfer, or otherwise make available the API or Documentation to any third party, in whole or in part;
  - (iv) reverse engineer, disassemble, decompile, decode, adapt, or otherwise attempt to derive or gain access to any software component of, the API, in whole or in part;
  - (v) circumvent or bypass rate limits or service limits through any method, including by creating multiple accounts;
  - (vi) remove any proprietary notices from the API or Documentation;
  - (vii) use the API or Search Results in any manner or for any purpose that infringes, misappropriates, or otherwise violates any intellectual property right or other right of any person, or that violates any applicable law, rule or regulation;
  - (viii) use the API or Documentation in any manner that harms the Provider, including without limitation, Provider's products, services, systems, infrastructure, brand, or goodwill;
  - (ix) combine or integrate the API with any software, services, systems, technology or materials not authorized by Provider, other than Customer Applications;
  - (x) use the API in Customer Applications to replicate or attempt to replace the functionality of the API, or circumvent use of the API;
  - (xi) attempt to obfuscate or conceal Customer's identity or the identity of the Customer Applications when requesting authorization to use the API;
  - (xii) redistribute, resell, or sublicense the Search Results;
  - (xiii) use the Search Results to create, evaluate, train, re-train, fine-tune, benchmark or otherwise improve artificial intelligence models or services offered by Customer or third parties;
  - (xiv) upon expiration or termination of this Agreement, continue any further use of the API or Documentation or retain Documentation or Search Results in Customer's possession and control; or
  - (xv) use the API in connection with any spyware, adware, or other malicious programs or code, … surveillance, interception, … or any illegal activities."

**API keys (4(a))**
- "Customer must obtain an API Key from Provider to access and use the API. Customer shall keep the API Key secure, may not share the API Key with any third party other than its affiliates, contractors and agents that need to know the API. Provider may revoke and replace an API Key at any time. Customer shall provide prompt notice to Provider of any actual or suspected unauthorized use or disclosure of an API Key."

**End Users (4(c))**
- "Customer shall ensure that each End User is bound by a written agreement with Customer pursuant to which such End User agrees to be bound by obligations substantially similar to those in section 3(b) of these Terms of Use. Customer is solely responsible for posting any privacy notices and obtaining any consents from End Users required under applicable laws… Customer is solely responsible and liable for all acts and omissions of End Users. Customer shall (i) monitor the use of the Customer Applications for End User use that may violate such obligations… and (ii) promptly suspend or restrict such End Users from use of the Customer Applications."

**Attribution (4(d))**
- "Customer may provide attribution to Provider in the Customer Applications. If Customer elects to provide attribution, such attribution shall (i) be displayed in a conspicuous manner; (ii) consist of the language 'POWERED BY BRAVE' plus Provider's logo in the description of the applicable Customer Application, or other attribution content as approved in advance by Provider in writing; and (iii) be in compliance with any written usage guidelines that Provider may specify from time to time. Provider may upon prior written notice to Customer, require Customer to change the manner of display of any such attribution or Provider's Marks or revoke the license to Provider's Marks granted herein… Customer shall not make any statement regarding use of the API, Documentation or Search Results or use Provider's Marks in any way that would suggest partnership with, sponsorship by, or endorsement by Provider."
- Other attribution sources:
  - Free credit: "To take advantage of this free credit, all you need to do is attribute the Brave Search API in your project's website / about pages." — [Brave blog, Feb 12 2026](https://brave.com/blog/most-powerful-search-api-for-ai/)
  - Rich results: "Some of these providers will require attribution for showing this data." — [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)

**Storage, retention and training (outside the ToS)**
- "**What data can be retained?** It is prohibited to retain any and all data received through the Brave Search API. If you need to store the results or train an LLM, please reach out to our team at searchapi-support@brave.com." — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)
- "Can I store results or use them to train models? Yes, with a custom plan. Contact sales to learn more about search with storage rights." — [brave.com/search/api](https://brave.com/search/api/)
- On termination the Customer must "destroy, and permanently erase all copies of the API, Documentation, Search Results (except as otherwise provided in an Order Form)". So an Order Form can change retention.
- Third-party content: "The Brave Search API does not grant any rights to third-party content such as web pages. Customers who access URLs displayed in the Brave Search API must ensure their access to those web pages complies with the copyright terms of the page publishers." — [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)

**Ownership and the license to queries**
- "as between Provider and Customer, Provider is the sole and exclusive owner of all right, title, and interest, including all intellectual property rights, in and to the Search Results, subject to the rights of third parties in any Third-Party Content… Customer is the sole and exclusive owner… in and to the Search Query Data."
- "Customer hereby grants Provider a worldwide, irrevocable, non-exclusive, sublicensable through multiple levels, royalty-free and fully paid, license during the Term to use Search Query Data for purposes of use with the API, providing the Search Results, and otherwise performing hereunder."

**Rights tiers, then and now**
- In June 2025, "Data for AI" plans listed "Rights to use data for AI inference". "Data for Search" plans did not. "Data w/ storage rights" ($26/$45 CPM) listed "Rights to store data". — [Wayback 2025-06-12](https://web.archive.org/web/20250612135902/https://brave.com/search/api/)
- In 2025, Brave told n8n users "you must ensure you are subscribed to one of the Data for AI plans". — [same snapshot](https://web.archive.org/web/20250612135902/https://brave.com/search/api/)
- Since Feb 12, 2026 the public plans are "Search, Answers, Spellcheck, and Autocomplete". — [Brave blog](https://brave.com/blog/most-powerful-search-api-for-ai/)
- The current ToS contains no AI-inference rights tier. The current docs present LLM Context, which is in the Search plan, as "the default for RAG, tools, and chatbots". — [Docs home](https://api-dashboard.search.brave.com/documentation)

**Changes, termination and suspension**
- Amendments: "We may amend this Agreement at any time. If you do not agree to the amended Agreement, you must stop using the API and Documentation."
- Updates: "Provider may require Customer to access and use the most recent version of the API… Provider will use commercially reasonable efforts to provide Customer with advance written notice of material Updates, which notice may be provided via the Website or other means by which general notice is provided to Provider's other API customers."
- Termination: "Provider may terminate this Agreement or any Order Form for any reason upon 10 days prior written notice to Customer. Customer may terminate this Agreement for any reason upon 30 days' prior written notice to Provider. Either Party may terminate this Agreement for a material breach of this Agreement by the other Party which remains uncured 30 days' following written notice describing such breach."
- Suspension: "Provider may suspend Customer's access to and use of the API: (i) immediately upon written notice to Customer if Provider reasonably believes that (A) Customer's use will imminently cause material damage to Provider's or a third party's systems, (B) Customer's use of the API or Documentation creates material legal exposure for Provider, or (C) if Provider is compelled or directed to do so by any competent court of law or government authority with jurisdiction to do so; or (ii) upon written notice to Customer after a five day cure period, for any suspected breach of section 3(b) of these Terms of Use by Customer or End Users, or Customer's failure to timely pay undisputed Fees. Provider will reinstate Customer's access to and use of the API promptly when the reason for suspension has been resolved. Provider may suspend or terminate Customer's access to Customer's service credit balance if Provider reasonably believes Customer has violated the Service Credit Terms…"
- Notices: "All Notices from the Provider to the Customer will be electronically delivered to the email address associated with the Customer's API account."

**Other binding points**
- Liability cap: "IN NO EVENT SHALL PROVIDER'S LIABILITY RELATED TO THIS AGREEMENT EXCEED, IN THE AGGREGATE, THE AMOUNT OF FEES PAID BY CUSTOMER TO THE PROVIDER IN THE 12 MONTHS PRECEDING THE DATE OF THE APPLICABLE CLAIM."
- Warranty: "PROVIDED 'AS IS,' AND 'AS AVAILABLE.'" There is no warranty that the API will "OPERATE WITHOUT INTERRUPTION".
- Indemnity: the Customer indemnifies Brave for claims relating to "(i) Customer Applications, Search Query Data, or other outputs… (ii) acts or omissions of End Users".
- Publicity: "Provider may (i) create and publish a customer list… that names Customer… without any additional prior written consent of Customer."
- Confidentiality: "the API, Documentation, and the terms and existence of this Agreement are the Confidential Information of Provider."
- Governing law: California; courts in San Francisco.
- Order of precedence: "(i) Privacy Notice; (ii) Order Forms; (iii) Service Credit Terms; (iv) Terms of Use".

### Inferences
- **Session record.** Keeping Search Results in the person's E2EE session record is probably storage beyond "transient storage required for operation" ((i)). It also likely conflicts with "retain any and all data" in the FAQ and with the post-termination duty to erase ((xiv) and Effect of Termination). Encryption does not change the plain wording: the restriction is on storing, not on who can read. If URnetwork wants results in the persistent record, it likely needs a storage-rights Order Form. The alternative is to record only non-result data: the query, Brave result IDs, or URLs the person actually opened. Even URLs and titles are "Search Results" as defined.
- **LLM outputs.** The LLM's own answer built from results could arguably be a "derivative work… of Search Results" ((ii)). Brave markets grounding heavily, which suggests it does not read (ii) that way for inference output, but that is not in writing. Ask Brave to confirm.
- **Local gateway.** Giving end users' coding harnesses search through a local gateway is not prohibited as such: results flow to End Users of a Customer Application. But the gateway must not hold or expose the Brave key ((4(a)) "may not share the API Key with any third party"). It also should not present a generic, Brave-compatible endpoint, which risks (iii) "otherwise make available the API… to any third party" and (x) "replicate… the functionality of the API". The safer design is a URnetwork-defined search tool whose results are limited to the feature, with the key kept server-side in the relay.
- **Billing per search.** Charging each search at Brave's cost plus a markup is closest to the (xii) "resell… the Search Results" prohibition. Framing it as a metered feature of URnetwork's app, not a pass-through sale of results, lowers the risk. Brave's written confirmation (api-sales@brave.com) is advisable before launch.
- **End-user terms.** URnetwork's end-user terms must include restrictions "substantially similar" to 3(b): no storage, no resale, no AI training or benchmarking, and so on. URnetwork must monitor and suspend violating users.
- **Training and evaluation.** (xiii) forbids using results to "evaluate… benchmark or otherwise improve artificial intelligence models or services offered by Customer". Logging search results to tune URnetwork's harness or prompts, or for model evaluation, would breach it.
- **Attribution.** For UI, the ToS permits but does not require "POWERED BY BRAVE" plus logo. If URnetwork relies on the free credit, the Feb 2026 condition (attribution on the website or about page) should be met. Rich-result verticals (weather, stocks, sports) carry third-party attribution duties. Avoid them or render the providers' credits.
- **Notice periods.** Brave's shortest notice for loss of service is "immediately upon written notice" (legal exposure, imminent damage). A suspected 3(b) breach gets a 5-day cure period, and termination for any reason takes 10 days. The relay design should allow switching provider within days.

### Gaps
- I could not retrieve the text of the 2024–2025 Terms that defined "Data for AI" inference rights. The Wayback CDX returned no captures for the ToS URLs tried. Only the 2025 pricing-page labels are documented here.
- No Brave source addresses chat transcripts, agent session logs or end-user-held copies as "storage". There is also no published written usage guideline for attribution, nor a logo kit URL in the ToS.
- I found no definition of "transient storage" (duration) anywhere in the docs.

## 5. Privacy and data handling for API traffic

### Takeaway
By default, Brave retains a record of API search queries for at most 90 days for billing and troubleshooting. For billing, troubleshooting and abuse prevention it processes IP address and "authentication token" (the API key). Zero Data Retention is an Enterprise option. Brave's position is that query data is not personal data in its hands, and its DPA excludes Search Query Data. The customer is responsible for end-user privacy notices and consents. The API is SOC 2 Type II attested. Brave says it does not train on or share queries, but the ToS gives it a broad license to use queries "for purposes of use with the API… and otherwise performing hereunder". Data location is not stated beyond Brave being a U.S. company.

### Cited Findings
All from the [Privacy Notice, updated 3 November 2026](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice) unless noted.
- "The Brave Search API is provided by Brave Software Inc located in the U.S."
- "A record of search queries submitted to the Brave Search API via a customer's Search API account is retained for a maximum of 90 days for the purpose of billing Search API account holders and for troubleshooting subject to Brave's legal obligations."
- "As per Section 3b of the Terms Of Service the Brave Search API customer (Licensee) is solely responsible for complying with applicable data protection law including the posting of any privacy notice with regard to queries submitted by end users via the customer's API access. Brave does not collect any identifiers that can link a search query to an individual or their devices."
- "Brave takes the position that query data sent to Brave Search API is not personal data under laws like the General Data Protection Regulation (GDPR). Brave Search API acts as a conduit… Brave has no way to identify which 'end user' made any specific query, only that a customer's account is making an API call… This is why we specifically exclude Search Query Data in our Data Processing Addendum."
- Processing table:

| Purpose | Data | Retention |
|---|---|---|
| Account access | email, full name, account UID, API key | 12 months after account deletion |
| Customer support | user ID, email, IP address, other info provided | "Maximum 6 years" |
| Payments | "Hashed Stripe identifier, Last 4 credit, expiration date" | 12 months after deletion |
| Billing queries and troubleshooting | "IP address, authentication token" | "Search Query Logs: 90 days. Option for Zero Data Retention (Enterprise clients), subject to Brave's legal obligations." Other data: 12 months after deletion |
| Abuse prevention | "IP address, authentication token" (legal basis: legitimate interests) | same 90 days / ZDR option |
| Legal obligations | IP address, auth token, account info | "To the extent required by law" |

- Payments: "Payment information is processed and held by Stripe… Brave does not have access to the personal data processed by Stripe. All plans require payment information (this is to help us safeguard against misuse of the service)."
- x402 payments: "the payer wallet address it contains is used to screen abuse and attribute payments… the resulting transaction is recorded publicly and permanently on the Base blockchain, which may be linked to you by others." On-chain records are "retained on a blockchain indefinitely".
- DPA: "List of sub-processors can be found in Annex IV of the data processing addendum." The notice links "See our data processing addendum here" to https://trust.brave.app/resources. — [Privacy Notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice) (link target read from page HTML)
- ToS Data Protection: "Provider shall implement and maintain reasonable and appropriate technical, administrative, and physical safeguards designed to protect Search Query Data." — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)
- ToS license to queries, which is broad: "to use Search Query Data for purposes of use with the API, providing the Search Results, and otherwise performing hereunder", "sublicensable through multiple levels". — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)
- Marketing claims (not binding):
  - "Architectural ZDR · Built in, not a contract bolt-on. Your queries never leave Brave." "Queries never shared or trained on · No unintended use of your data." — [brave.com/search/api](https://brave.com/search/api/)
  - "Brave doesn't use your search queries to train its own LLMs." "Zero Data Retention (ZDR): No queries are stored, logged, or linked to identities, enabling true ZDR… we can offer ZDR across all our endpoints." — [Brave blog, Feb 12 2026](https://brave.com/blog/most-powerful-search-api-for-ai/)
- **Conflict.** The blog's "No queries are stored, logged" contradicts the Privacy Notice's 90-day query-log retention for non-Enterprise accounts. The pricing page lists "Full-funnel Zero Data Retention" only under Enterprise. — [Docs pricing](https://api-dashboard.search.brave.com/documentation/pricing)
- Certifications and posture — [Security page](https://api-dashboard.search.brave.com/documentation/resources/security):
  - "The Brave Search API is SOC 2 Type II attested, with its strict security and privacy controls independently verified by a third-party auditor." The same page also still says "we are in the process of being certified for SOC 2". That line is stale and contradicts the attestation.
  - "Brave Search API's last external penetration test was completed in April 2025."
  - "ISO standards such as 27001 and 27701 provide guidance". That is guidance, not certification.
  - The DPO covers "GDPR and ePrivacy Directive, and the California Consumer Privacy Act (CCPA) and California Privacy Rights Act (CPRA)".
  - "We will promptly notify affected customers and the relevant regulatory authorities if we experience a data breach according to our obligations."
  - Trust Center: https://trust.brave.app/. Contacts: privacy@brave.com and security@brave.com.
- Index sourcing (context): results come from Brave's own crawler "plus privacy-preserving signals from Brave users who opt in to the Web Discovery Project". — [brave.com/search/api](https://brave.com/search/api/). "Does Brave ever use Google or Bing results? No… There is no fallback to another search engine for any query." — [brave.com/search/api](https://brave.com/search/api/)

### Inferences
- Through a relay, Brave sees URnetwork's relay IP, URnetwork's API key, the query text, and any `X-Loc-*`, `user-agent` or other headers the relay forwards. It cannot see end-user identity unless the query text carries it. A relay that strips location and UA headers and does not add per-user identifiers keeps Brave's 90-day logs free of user linkage.
- The query text still leaves the user's E2EE domain in plaintext to Brave. The relay sees it too, unless the relay is itself in a TEE. That is a design decision for URnetwork.
- Query retention can only be cut below 90 days through an Enterprise contract (ZDR). Self-serve plans cannot opt out.
- Because Brave excludes Search Query Data from its DPA and calls queries non-personal, URnetwork, as controller, carries GDPR/CCPA duties for its users' queries. Its privacy notice must disclose Brave as a recipient with up to 90-day retention.

### Gaps
- I could not read the DPA, its Annex IV sub-processor list, or SCC/transfer terms. trust.brave.app is JavaScript-rendered, and the curl fetch returned only a 6.6 KB shell.
- No source states server or data location (US, EU or other) for API processing or log storage.
- No source explicitly says whether API queries feed Brave's index, ranking or Web Discovery signals. The marketing says "never shared or trained on"; the binding ToS license is broad.
- The scope and terms of the Enterprise ZDR option (e.g. whether it covers abuse logs) are not published.

## 6. Brave's official MCP server and guidance for AI agents (Claude, OpenAI tools)

### Takeaway
github.com/brave/brave-search-mcp-server (MIT, latest release v2.2.0 on 2026-11-19) exposes nine tools: `brave_web_search`, `brave_local_search`, `brave_video_search`, `brave_image_search`, `brave_news_search`, `brave_llm_context`, `brave_place_search`, `brave_answers`, and the deprecated `brave_summarizer`. Tools can be enabled or disabled with `BRAVE_MCP_ENABLED_TOOLS` and `BRAVE_MCP_DISABLED_TOOLS`. The transport is STDIO by default, with an optional unauthenticated HTTP transport bound to 127.0.0.1. Brave's guidance for agents is to use LLM Context as the default agent search tool. It also publishes an "Agent Skills" repo with setup steps for Claude Code, Codex, Cursor and others. The Answers endpoint is OpenAI SDK-compatible.

### Cited Findings
- The tool registry in `src/tools/index.ts` exports `WebSearchTool`, `LocalSearchTool`, `VideoSearchTool`, `ImageSearchTool`, `NewsSearchTool`, `SummarizerTool`, `LlmContextTool`, `PlaceSearchTool` and `AnswersTool`. — [src/tools/index.ts](https://github.com/brave/brave-search-mcp-server/blob/main/src/tools/index.ts)
- Releases: v2.2.0 (2026-11-19), v2.1.5 (2026-11-17), v2.1.4 (2026-09-17), v2.1.0 (2026-07-18), v2.0.85 (2026-06-15). — [GitHub releases API](https://github.com/brave/brave-search-mcp-server/releases)
- Tool input schemas, as given in the README — [MCP README](https://github.com/brave/brave-search-mcp-server):
  - **`brave_web_search`**: `query` (string, required, "max 400 chars, 50 words"), `country` (default "US"), `search_lang` ("en"), `ui_lang` ("en-US"), `count` (1–20, **default 10**), `offset` (max 9), `safesearch` (default "moderate"), `freshness`, `text_decorations` (default true), `spellcheck` (default true), `result_filter` (array, **default ["web", "query"]**), `goggles` (array), `units`, `extra_snippets` (boolean, "Pro plans only"; that note is stale), `summary` (boolean, for the deprecated summarizer).
  - The web tool's description: "Returns a JSON list of web results with title, description, and URL." Its code maps each result to `{url, title, description, extra_snippets}` only. — [src/tools/web/index.ts](https://github.com/brave/brave-search-mcp-server/blob/main/src/tools/web/index.ts)
  - **`brave_local_search`**: "Same as `brave_web_search` with automatic location filtering". It includes "AI-generated descriptions". "Requires Pro plan for full local search capabilities. Falls back to web search otherwise."
  - **`brave_video_search`**: `query` (max 400/50), `country`, `search_lang`, `ui_lang`, `count` (1–50, default 20), `offset` (max 9), `spellcheck`, `safesearch`, `freshness`.
  - **`brave_image_search`**: `query`, `country`, `search_lang`, `count` (1–200, default 50), `safesearch` ("off" or "strict", default "strict"), `spellcheck`. v2.x removed base64 image data from responses.
  - **`brave_news_search`**: `query`, `country`, `search_lang`, `ui_lang`, `count` (1–50, default 20), `offset` (max 9), `spellcheck`, `safesearch`, `freshness` (**default "pd"**), `extra_snippets`, `goggles`.
  - **`brave_llm_context`**: `query` (max 400/50), `country`, `search_lang`, `count` (1–50), `spellcheck`, `maximum_number_of_urls` (1–50), `maximum_number_of_tokens` (1024–32768), `maximum_number_of_snippets` (1–256), `context_threshold_mode`, `maximum_number_of_tokens_per_url` (512–8192), `maximum_number_of_snippets_per_url` (1–100), `goggles`, `freshness`, `enable_local`, `enable_source_metadata`. Optional header fields: `x-loc-*`, `api-version`, `accept`, `cache-control`, `user-agent`.
  - The LLM Context tool's description ends: "When relaying results in markdown-supporting environments, cite the source URLs from the 'sources' map." — [src/tools/llm_context/index.ts](https://github.com/brave/brave-search-mcp-server/blob/main/src/tools/llm_context/index.ts)
  - **`brave_place_search`**: `query` (optional), `latitude`, `longitude`, `location`, `radius` (meters; global if omitted), `count` (1–50, default 20), `country`, `search_lang`, `ui_lang`, `units` (default metric), `safesearch` (default strict), `spellcheck`, `geoloc`.
  - **`brave_answers`**: `query` (required), `model` (`brave` or `brave-pro`), `country`, `language`, `safesearch`, `max_completion_tokens`, `enable_citations`, `enable_entities`, `enable_research`, `web_search_options`, plus the research tuning ranges. "The tool always requests a streamed (Server-Sent Events) response." "Requires an Answers plan subscription."
  - **`brave_summarizer`** (deprecated): `key` (required), `entity_info`, `inline_references`. "Remains available for existing Pro AI subscribers."
- Configuration — [MCP README](https://github.com/brave/brave-search-mcp-server):
  - `BRAVE_API_KEY` or `BRAVE_API_KEY_FILE`.
  - `BRAVE_MCP_TRANSPORT` (default "stdio").
  - `BRAVE_MCP_HOST` (default "127.0.0.1"): "set to '0.0.0.0' to expose… Only do this on a trusted network, since the HTTP endpoint is unauthenticated."
  - `BRAVE_MCP_ALLOWED_ORIGINS` (DNS-rebinding guard) and `BRAVE_MCP_ALLOWED_HOSTS`.
  - `BRAVE_MCP_ENABLED_TOOLS` / `BRAVE_MCP_DISABLED_TOOLS`.
  - `BRAVE_MCP_STATELESS`.
  - License: MIT.
- Brave's agent guidance:
  - Docs home: LLM Context "Search for *AI agents*… This is the default for RAG, tools, and chatbots." — [Docs home](https://api-dashboard.search.brave.com/documentation)
  - Web search docs: "Looking to power agents or chatbots? Use the LLM Context endpoint instead." — [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)
  - x402 OpenAPI `x-guidance`: "Call llmContext to ground an answer… size it with maximum_number_of_tokens. Call webSearch for ranked links and snippets… For places, call localPlaceSearch, then pass its location ids to localPois for details or localDescriptions for a summary." — [openapi.json](https://search.agent.s.brave.app/openapi.json)
  - LLM Context sizing advice: 2048 tokens for "Simple factual", 8192 (default) for standard, 16384 for "Complex research". "leave `count`, `maximum_number_of_urls` and `maximum_number_of_tokens_per_url` unset." — [LLM Context docs](https://api-dashboard.search.brave.com/documentation/services/llm-context)
- Skills — [Skills docs](https://api-dashboard.search.brave.com/documentation/resources/skills):
  - The official repo is github.com/brave/brave-search-skills, with one SKILL.md per API: llm-context, web-search, answers, news-search, videos-search, images-search, local-place-search, local-pois, local-descriptions, suggest, spellcheck. — [llms.txt](https://api-dashboard.search.brave.com/llms.txt)
  - "Skills work with Claude Code, Cursor, GitHub Copilot, Codex, Gemini CLI, VS Code, Windsurf, OpenClaw, Cline, Goose, Amp, Roo Code."
  - Claude Code setup: "Add to `~/.claude/settings.json`… For per-project use, add to `.claude/settings.local.json` (gitignored)". Codex setup: "config.toml" or shell profile.
  - "**Security tip:** Prefer agent-native config over shell profile exports. Coding agents can access environment variables — scoped configs limit exposure."
- OpenAI compatibility: Answers is "a single, OpenAI-compatible endpoint" used via the OpenAI SDK, with extra parameters passed through `extra_body`. — [Answers docs](https://api-dashboard.search.brave.com/documentation/services/answers)

### Inferences
- If URnetwork wants Brave's tool shapes for coding harnesses, it can model its gateway tools on `brave_llm_context` and `brave_web_search`, with Answers, Summarizer and descriptions disabled. The gateway would forward to the URnetwork relay, not to Brave with a local key. Brave's MCP server and skills both assume the key sits on the user's machine (`BRAVE_API_KEY`), which conflicts with the ToS 4(a) key-sharing limit when the key belongs to URnetwork.
- The MCP server still enforces q at 400 characters and 50 words for web and LLM Context, while the API allows 600 and 75. Re-validating at 400/50 is the conservative choice if the shapes are reused.

### Gaps
- I read the README and two tool source files, not every Zod schema file. Exact schema details beyond the README (e.g. enums for `freshness` validation, output schemas) were not checked.
- I found no Anthropic- or OpenAI-specific "web search tool" adapter from Brave, apart from MCP, Skills and the OpenAI-compatible Answers endpoint.

## 7. Changes in 2025–2026, SLA, status page and uptime

### Takeaway
2026 brought a full restructuring:
- **Feb 12, 2026:** LLM Context launched, and the old Free, Base and Pro "Data for AI" / "Data for Search" / storage-rights tiers were replaced by Search, Answers, Spellcheck and Autocomplete plans with $5 of free monthly credit each. The free plan ended.
- **Around Aug–Sep 2026:** newly activated plans moved to prepaid credits (date unconfirmed).
- **2026:** Place Search was added and the Summarizer deprecated.
- **Nov 12, 2026:** x402 USDC pay-per-request launched.

The ToS and Credit Terms were updated Sep 1, 2026, and the Privacy Notice Nov 3, 2026. There is no contractual SLA: the API is "AS IS / AS AVAILABLE". Status is published at status.brave.com, and the docs incident log ends in March 2025.

### Cited Findings

**Dated timeline** (Brave sources unless noted)
- 2023-05-23: "Brave Search API launched." — [Status updates](https://api-dashboard.search.brave.com/documentation/resources/status-updates)
- 2025-01-15: Goggles support for News. — [News docs](https://api-dashboard.search.brave.com/documentation/services/news-search)
- 2025-02-20: "Add Brave Rich Search API resource." — [Web search docs](https://api-dashboard.search.brave.com/documentation/services/web-search)
- 2025-06 (snapshot): old tiers. Data for AI: Free (2k/mo), Base $5 CPM, Pro $9 CPM. Data for Search: Free, Base $3, Pro $5. Storage rights: $26 / $45 CPM. Autosuggest/Spellcheck: Pro $0.50 CPM. — [Wayback](https://web.archive.org/web/20250612135902/https://brave.com/search/api/)
- 2025-08-05: "Launch Brave Answers API resource… OpenAI SDK compatibility". — [Answers docs](https://api-dashboard.search.brave.com/documentation/services/answers)
- 2026-01-15: "Add Place Search endpoint for geographic POI discovery." 2026-03-04: "Lifted radius restrictions." — [Place search docs](https://api-dashboard.search.brave.com/documentation/services/place-search)
- 2026-02-06: "Launch Brave LLM Context API at `/v1/llm/context`" (changelog date). — [LLM Context docs](https://api-dashboard.search.brave.com/documentation/services/llm-context)
- 2026-02-12: Blog announcing the "revamped Brave Search API" and "simpler, cheaper, but more powerful plans":
  - "We are arranging all existing API capabilities under the following public plans: Search, Answers, Spellcheck, and Autocomplete. Every plan gets $5 of free credit that renews every month (that would be $20 across all plans)".
  - Search "$5 per 1000 requests". Answers "$4 per thousand Web searches plus $5 per million tokens (input and output)". Spellcheck and Autocomplete "$5 per 10k requests".
  - The post was updated June 25, 2026 and Sept 17, 2026.
  - Source: [Brave blog](https://brave.com/blog/most-powerful-search-api-for-ai/)
- Independent dating: "Brave removed its free Search API tier in February." — [Implicator.ai, June 8, 2026](https://www.implicator.ai/brave-drops-free-search-api-tier-puts-all-developers-on-metered-billing/) (used only for dating)
- Summarizer deprecated, date unknown. It "remains available for existing Pro AI subscribers". — [MCP README](https://github.com/brave/brave-search-mcp-server), [x402 llms.txt](https://search.agent.s.brave.app/llms.txt)
- Jul 8, 2026: Brave blog "Brave Place Search API: The Google Maps Alternative That Costs 6–7x Less", at "$5 per 1,000 requests" (teaser text on the related-articles list). — [Brave blog x402 post, related list](https://brave.com/blog/search-api-agentic-payments/)
- 2026-07-31: LLM Context "new content pipeline by default", plus new `safesearch`, `enable_source_metadata`, `operators`, `operators_fallback`. — [LLM Context docs](https://api-dashboard.search.brave.com/documentation/services/llm-context)
- 2026-08-21: Answers `research_maximum_number_of_results_per_query` default changed from 60 to 30. — [Answers docs](https://api-dashboard.search.brave.com/documentation/services/answers)
- About Aug–Sep 2026: prepaid billing for newly activated plans. Brave reportedly announced it by "mass email". The FAQ has a "Prepaid credits" section describing "the new prepaid system". — [SecurityOnline, Sept 10, 2026](https://securityonline.info/brave-search-api-prepaid-billing/) (dating only), [FAQ](https://api-dashboard.search.brave.com/documentation/resources/help-feedback)
- 2026-09-01: Terms of Use and Service Credit Terms "Last updated". — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service), [Service Credit Terms](https://api-dashboard.search.brave.com/terms-of-service/credit-terms)
- 2026-11-03: Privacy Notice updated, adding x402 processing. — [Privacy Notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice)
- 2026-11-12: "The Brave Search API now accepts agentic payments via the x402 protocol." — [Brave blog](https://brave.com/blog/search-api-agentic-payments/)
- Context for alternatives: Brave's page says "Google's Custom Search JSON API shuts down Jan 1, 2027" and "Microsoft retired the Bing Search APIs." — [brave.com/search/api](https://brave.com/search/api/)

**SLA, status page and uptime**
- No SLA in the ToS. "THE API, DOCUMENTATION AND SEARCH RESULTS ARE PROVIDED 'AS IS,' AND 'AS AVAILABLE.'… PROVIDER MAKES NO WARRANTY… THAT THE API… WILL… OPERATE WITHOUT INTERRUPTION." Force majeure: "Provider will not be in breach of this Agreement if performance hereunder or the functionality of the API is delayed, prevented, degraded…" — [Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service)
- Marketing claim: "Best-in-class latencies and 99.9% uptime." — [Docs home](https://api-dashboard.search.brave.com/documentation)
- Live status: the Status updates page links to https://status.brave.com. — [Status updates](https://api-dashboard.search.brave.com/documentation/resources/status-updates) (link target read from page HTML)
- Incident log on that page:
  - Mar 27, 2025: 16 min downtime. "All api-keys were temporally disabled during a database migration."
  - Feb 16, 2025: 6 min downtime. "Subsystem failure, which cascaded."
  - Jan 4, 2025: 166 min degradation, first 15 min downtime. "Large global targeted DDoS attack."
  - Nov 27, 2024: 15 min downtime. "Failed deployment."
  - No entries after March 2025.
  - Source: [Status updates](https://api-dashboard.search.brave.com/documentation/resources/status-updates)
- The Security page offers a business continuity plan and an incident handling policy "available upon request". — [Security](https://api-dashboard.search.brave.com/documentation/resources/security)

### Inferences
- Pricing and terms changed several times within 10 months: the plan restructure in February, the billing model mid-year, the ToS in September, and the privacy notice in November. The relay should read prices from configuration, not code. It should also track the `Api-Version` header and pin a date version to avoid silent response changes.
- With no contractual SLA, uptime commitments require an Enterprise Order Form. The 2024–2025 incidents (up to 166 minutes of degradation) argue for a fallback or graceful-degradation path in the search tool.

### Gaps
- I did not fetch status.brave.com (likely a hosted status page). Current incident history and uptime percentages after March 2025 are unverified.
- The exact effective date of the prepaid switch and of the Summarizer deprecation could not be confirmed from Brave primary sources.
- Secondary sources make further claims I could not verify: a May 2026 plan "rename" and grandfathering of 2025 free-plan users at 2,000 queries/month. I did not adopt them.
- No Enterprise SLA terms are published.
