# Web search on Bittensor subnets and crypto-payable search APIs as alternatives to Brave (state as of 2026-11-23)

Conventions used in these notes:
- **[chain 2026-11-23]** marks a fact this researcher read directly from Finney (Bittensor mainnet) over public JSON-RPC on 2026-11-23. Current state was read at **finalized block 9,570,155 (2026-11-23 14:58:48 UTC, runtime spec 493)** from the [Finney entrypoint RPC](https://entrypoint-finney.opentensor.ai). History was read from the [Finney archive RPC](https://archive.chain.opentensor.ai). Storage items read: `GammaEnabled`, `SubnetGammaEnabled`, `Services`, `SubnetIdentitiesV3`, `NetworkRegisteredAt`, `SubnetOwner`, `Timestamp.Now`. Keyed maps were enumerated with `state_getKeysPaged`, so every netuid was covered.
- Verbatim quotes from desearch.ai were taken from page HTML fetched with curl on 2026-11-23 and converted to text. Quotes from other sites came through a fetch tool that summarizes pages; short quotes from those are marked as quotes, and the rest is paraphrase.
- The baseline is the Brave notes, [brave_search_api.md](</Users/brien/urnetwork/sidecar/research_notes/Brave web search tool/brave_search_api.md>), and the gamma background is [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>) (chain read at 07:26 UTC the same day).

## 1. Desearch (SN22): API, raw vs LLM endpoints, price and limits, terms, sources, miners and TEE, gamma, quality

### Takeaway
Desearch is a conventional, centralized USD API (`api.desearch.ai`) that Desearch runs on top of a web index. SN22 miners crawl pages for that index and compute embeddings. Since "Desearch 2.0", user queries never go to miners, and nothing runs in a TEE. Its cheapest raw web search, `GET /web`, costs **$1.00 per 1,000 searches ($0.001 per call, up to 20 results)**, one fifth of Brave's $0.005. Other prices: index search (`POST /search`) $0.30 per 1,000 results ($0.003 for a default 10-result call), Extract $0.50 per 1,000 pages, and X search $0.15 per 1,000 posts. LLM text comes only from opt-in or default summaries: `/search` with `summary: true`, and AI Search, whose default is `LINKS_WITH_FINAL_SUMMARY`. Payment is by card or "TAO where supported". **SN22 has not enabled gamma and has published no service.** The Terms of Service (last updated 2025-01-15) are short. They forbid "Reselling our Services without authorization" but say nothing about storing, caching or passing results on. The privacy policy keeps queries for 12 months unless zero data retention (ZDR) is arranged. The only quality evidence is a benchmark Desearch ran itself.

### Cited Findings

#### API surface (as listed 2026-11-19 in Desearch's llms.txt)
- Desearch's machine-readable overview, "last reviewed 2026-11-19 UTC", lists base `https://api.desearch.ai` and these families. Source: [Desearch llms.txt](https://www.desearch.ai/llms.txt).
  - **Search:** `POST /search`.
  - **AI Search:** `POST /desearch/ai/search`, plus `POST /desearch/ai/search/links/twitter`. A web-links variant is deprecated.
  - **Web:** `GET /web` (SERP) and `GET /web/extract` (`/web/crawl` is a deprecated alias).
  - **X:** `GET /twitter`, `/twitter/post`, `/twitter/replies`, `/twitter/trends`, `/twitter/urls`, `/twitter/user/posts`, and others.
  - **Social:** TikTok, Facebook, Instagram, YouTube (search, channel, video, comments, transcript), Reddit (search, post, comments, subreddit) and Threads, all under `/desearch/...`.
  - **Also:** People Search, Company Search and Enrich, and Monitors.
  - **Hosted MCP:** `https://mcp.desearch.ai/mcp`.
- **arXiv, Reddit, Hacker News, Wikipedia and YouTube inside AI Search are retired tools.** The OpenAPI spec says: "The YouTube, Hacker News, Reddit, Wikipedia and ArXiv tools are retired. They are still accepted in `tools`, but their `youtube_search`, `hacker_news_search` and `reddit_search` keys are never returned: `youtube` is dropped, and `reddit`, `hackernews`, `wikipedia` and `arxiv` run as a Web Search pinned to their domain through `include_domains`." — [Desearch OpenAPI](https://api.desearch.ai/openapi.json). arXiv is therefore reachable only as a domain-pinned web search. Reddit and YouTube also have dedicated social endpoints — [llms.txt](https://www.desearch.ai/llms.txt).
- `GET /web` per the OpenAPI spec: "This API allows users to search for any information over the web. This replicates a typical search engine experience… Each request returns up to 20 results." Pagination uses `start`; "A search failure or timeout returns 503 and is not charged" — [Desearch OpenAPI](https://api.desearch.ai/openapi.json). Each result has "title, link and snippet", and `start` takes "any value from 0 to 100" — [Which endpoint](https://www.desearch.ai/docs/guide/apis/which-endpoint).
- `GET /web/extract`: "Fetch a public URL and return its content as text, markdown or HTML" — [OpenAPI](https://api.desearch.ai/openapi.json). "Each call fetches the current version of the page, not a cached snapshot" — [Docs FAQ](https://www.desearch.ai/docs/guide/introduction/faq).
- Billing metadata comes back on every billable response in `X-Desearch-Cost-Usd`, `X-Desearch-Usage-Count`, `X-Desearch-Service` and `X-Desearch-Currency`, and in body fields on JSON objects — [OpenAPI](https://api.desearch.ai/openapi.json).

#### Which endpoints write text with an LLM, and which return raw results
- **`POST /search`: raw unless the caller asks for a summary.** "Use Search (POST /search) to search the web from the Desearch index. It returns ranked pages, each with the passage that best matches the query. Set summary: true to also get a short answer written from the results, with numbered citations." "summary is only returned when the request sets summary: true" — [Search API guide](https://www.desearch.ai/docs/guide/apis/search-api).
- **AI Search writes a summary by default.** "AI Search… takes a natural-language prompt and searches X posts (twitter) and the web (web). Web results come from the Desearch index, up to 20 per request. By default it also writes a summary over the results in completion" — [Search API guide](https://www.desearch.ai/docs/guide/apis/search-api). "result_type ONLY_LINKS or LINKS_WITH_FINAL_SUMMARY. Defaults to LINKS_WITH_FINAL_SUMMARY." "Streaming is on by default (streaming=true) and sends the generated summary as server-sent events" — [AI Search API page](https://www.desearch.ai/search-api).
- **`POST /desearch/ai/search/links/twitter`** is described as searching X "with leveraging AI-powered models. This API analyze links from Х posts that match the given prompt" — [OpenAPI](https://api.desearch.ai/openapi.json). It returns links, but an LLM processes the prompt.
- **`GET /twitter` is raw.** It "enables users to retrieve relevant links and tweets based on specified search queries without utilizing AI-driven models" — [OpenAPI](https://api.desearch.ai/openapi.json).
- **Other uses of AI:** Monitors use an AI classifier ("$0.05 / 1000 items" screened). People and Company Search use AI fit scoring and return "the reason they matched" — [Desearch llms-full.txt](https://www.desearch.ai/llms-full.txt); [Privacy Policy §8](https://www.desearch.ai/privacy-policy).
- **The model behind the summaries is not named** anywhere in the docs or OpenAPI. A search for gpt, claude, qwen, OpenAI and similar names in the OpenAPI spec found no model — [OpenAPI](https://api.desearch.ai/openapi.json).

#### Price, billing and rate limits
- Pricing page, verbatim: "Desearch is pay as you go: Search is $0.30 per 1,000 results with the summary at no extra charge, AI Search is $0.40 per 1,000 items, Web Search is $1.00 per 1,000 searches, Extract is $0.50 per 1,000 pages and X Search is $0.15 per 1,000 posts. New accounts get $5 in API credits after attaching a card in Console" — [desearch.ai/pricing](https://www.desearch.ai/pricing).
- Further rows on the same page:
  - X Profile Search $25.00, LinkedIn Profile Search $15.00 and TikTok Creator Search $15.00 per 1,000 profiles or creators; YouTube Creator Search $10.00 per 1,000 creators.
  - Company Search $45.00 and Company Enrich $50.00 per 1,000 companies.
  - Monitors $0.05 per 1,000 items; Monitors social reads $3.00 per 1,000 requests.
  - The dates of the rates: "Search rate as of 18 Nov 2026; other reference rates as of 7 May 2026; People Search rates as of 19 Oct 2026; Company Search rates as of 28 Oct 2026; Monitors rates as of 17 Nov 2026. All prices in USD. Confirm current rates in Console."
  - Source: [desearch.ai/pricing](https://www.desearch.ai/pricing).
- Search minimum: "Search costs $0.30 per 1,000 results. At least 10 results are billed, so a default search (count 10) costs $0.003, which is $3 per 1,000 default searches. A search that returns no results is free. The summary has no extra charge" — [Search API guide](https://www.desearch.ai/docs/guide/apis/search-api).
- Reddit, YouTube, Threads, TikTok and the other social endpoints have no public per-call price ("Social pricing in Console") — [Which endpoint](https://www.desearch.ai/docs/guide/apis/which-endpoint).
- **Payment methods**, verbatim: "Card payments: add funds with a credit or debit card." "TAO cryptocurrency payments: add funds using TAO where supported." Auto-recharge is available with a linked card — [Pricing and billing](https://www.desearch.ai/docs/guide/introduction/pricing-and-billing).
  - The Bittensor page says the opposite: users "pay in USD, and never touch the TAO token or run any network software" — [Desearch x Bittensor](https://www.desearch.ai/docs/guide/introduction/desearch-x-bittensor).
  - No page mentions gamma, alpha or x402 — [llms-full.txt](https://www.desearch.ai/llms-full.txt).
- **Rate limits**, verbatim: "Rate limits are enforced per API key on three windows: per minute, per day, and per month. The first limit reached applies… Your key's limits and usage are shown in the Console. Higher limits are an account change, not a code change: contact us." Exceeding a limit returns 429, and running out of credits returns 402 — [Rate limits & errors](https://www.desearch.ai/docs/guide/introduction/rate-limit). No numbers are published. Enterprise offers "Custom rate limits and concurrency" — [pricing](https://www.desearch.ai/pricing).

#### Terms on resale, storage and passing results on (verbatim)
All from the [Desearch Terms of Service](https://www.desearch.ai/terms-of-service), "Last updated: January 15, 2025". The whole document has ten short sections.
- §2: "Desearch provides AI-powered search APIs and related services built on the Bittensor network. Our Services include web search, Twitter/X search, AI search, and deep research capabilities accessible through our API."
- §4: "Your use of our APIs is subject to rate limits and usage quotas as specified in your plan. You agree not to circumvent these limits or use our APIs in ways that could harm our infrastructure or other users."
- §5, "Prohibited Uses": "You agree not to use our Services for: Any unlawful purpose or to violate any laws · Harassment, abuse, or harm to others · Distributing malware or other harmful code · Attempting to gain unauthorized access to our systems · **Reselling our Services without authorization**".
- §6: "All content, trademarks, and intellectual property associated with our Services remain the property of Desearch. You retain ownership of any content you submit through our Services."
- §7: "All fees are non-refundable except as required by law or as specified in our refund policy."
- §9: "We reserve the right to modify these terms at any time… Continued use of our Services after changes constitutes acceptance of the new terms."
- **The Terms have no clause on** storing or caching results, building databases, redistributing results to end users, flowing terms down to end users, attribution, AI training on results, governing law, or the legal entity. The only contact given is legal@desearch.ai — [Terms of Service](https://www.desearch.ai/terms-of-service).
- An enterprise route exists: "Talk to us when you need higher volume, custom limits, invoicing, or specific support and data requirements. Pricing, capacity, and service levels are agreed for your workload" — [pricing](https://www.desearch.ai/pricing).

#### Privacy, retention and security
- Privacy Policy, "Last updated: October 19, 2026" — [Privacy Policy](https://www.desearch.ai/privacy-policy):
  - Desearch collects "Usage Data: API calls, queries, and usage patterns" and "Technical Data: IP address, browser type, device information".
  - Among the uses: "Improve and optimize our Services".
  - Retention: "Usage data (API calls, queries and usage records): 12 months, then deleted or aggregated so it no longer identifies you." "Technical data (such as IP addresses in logs): 90 days."
  - The hosted MCP connector stores the API key encrypted (AES-256-GCM). "Where it is stored: on servers in the United States."
- Security page, "Last updated 16 September 2026" — [Security](https://www.desearch.ai/security):
  - "Desearch has a SOC 2 Type II report and handles personal data under the GDPR. A Data Processing Agreement and zero data retention are available, and our controls are aligned with the HIPAA Security Rule."
  - "Zero data retention is available. With it enabled, Desearch doesn't store your queries or results and doesn't use them for training. Without it, the privacy policy lists API calls and queries among the usage data Desearch may collect."
  - The same text appears in the docs — [Security and compliance](https://www.desearch.ai/docs/guide/introduction/security-and-compliance).

#### Where results come from: own crawl, or Google/Bing via miners?
- **Desearch 2.0 (current): an index built by SN22 miners plus Desearch's own crawler.**
  - "Subnet 22 builds Desearch's web index. Pages worth keeping are found, miners crawl them and turn their text into embeddings, validators check a sample of both, and passed work goes into the collection the search index is built from."
  - "Crawl miners claim crawl tasks, fetch every assigned page through their own proxies, and extract the text (title, dates, headings, main text) plus the page HTML."
  - "Embed miners… turn the text of crawled pages into embeddings with Desearch's embedding model, on their own GPU."
  - "Desearch runs the search API on top of the index."
  - Source: [Desearch x Bittensor](https://www.desearch.ai/docs/guide/introduction/desearch-x-bittensor).
- The index covers the public web, "company websites, news, articles, blogs and documentation", and "starts with selected sources" — [subnet-22 README](https://github.com/Desearch-ai/subnet-22).
- Desearch also runs its own crawler, DesearchBot (UA `Mozilla/5.0 (compatible; DesearchBot/1.0; +https://www.desearch.ai/crawler)`). "DesearchBot respects robots.txt", fetching "At most 1 request per second per host" — [DesearchBot page](https://www.desearch.ai/crawler).
- **`GET /web` names no source.** It is a "SERP"-style endpoint whose failures are reported as "upstream_failed, upstream_timeout" — [Rate limits & errors](https://www.desearch.ai/docs/guide/introduction/rate-limit). The docs and OpenAPI do not name the upstream, and the strings Google, Bing, SerpAPI and Brave do not appear as providers in the OpenAPI spec — [OpenAPI](https://api.desearch.ai/openapi.json).
- **X search queries X directly.** "the query is sent to X wrapped in parentheses". Errors say X search "is temporarily unavailable because the X crawler failed or timed out" — [OpenAPI](https://api.desearch.ai/openapi.json).
- **Desearch 1.0 (superseded; docs as of commit 9ae9871, 2025-05-02) used outside APIs through miners.**
  - `SERPAPI_API_KEY`: "Used to search web using Serp API… Required for: Miners exclusively".
  - `TWITTER_BEARER_TOKEN`: "Grants access to the Twitter API… Required for: Miners exclusively".
  - `APIFY_API_KEY`: "Used for Apify actors".
  - `OPENAI_API_KEY`: required for "Validator and Miners".
  - Source: [env_variables.md @ 2025-05-02](https://github.com/Desearch-ai/subnet-22/blob/9ae9871ecc97c00b53c373ce5cbb3a6841bba19a/docs/env_variables.md).
  - Miners summarized with OpenAI (default `gpt-3.5-turbo-0125`) — [running_a_miner.md @ 2025-05-02](https://github.com/Desearch-ai/subnet-22/blob/9ae9871ecc97c00b53c373ce5cbb3a6841bba19a/docs/running_a_miner.md).
  - Desearch's own blog says the first version "depended on outside search providers" — [Desearch blog, Jan 3 2026, updated Oct 17 2026](https://www.desearch.ai/blog/decentralized-search-engine-desearch-bittensor).

#### Do miners see queries? Does any part run in a TEE?
- **Miners do not see queries in 2.0.** "Miners do not serve search queries, and queries never wait on miner work" — [Desearch x Bittensor](https://www.desearch.ai/docs/guide/introduction/desearch-x-bittensor). "When you search with Desearch, your query never waits on a miner." "In the first version of Desearch, miners answered search requests and validators judged the answers" — [Desearch blog](https://www.desearch.ai/blog/decentralized-search-engine-desearch-bittensor). The README says the same: "Desearch 2.0 prepares information before a query arrives" — [subnet-22 README](https://github.com/Desearch-ai/subnet-22).
- **No TEE.** Neither the README, the blog, the Bittensor page nor the security page mentions a TEE or enclave — [README](https://github.com/Desearch-ai/subnet-22); [blog](https://www.desearch.ai/blog/decentralized-search-engine-desearch-bittensor); [Security](https://www.desearch.ai/security).
- The SN22 repo is active. Its last commit was 2026-11-17 ("Fix: request limits in memory") — [GitHub commits API](https://api.github.com/repos/Desearch-ai/subnet-22/commits?per_page=1).

#### Gamma
- **SN22 is not gamma-enabled and has published no service** [chain 2026-11-23]. `SubnetGammaEnabled` is true only for 25, 28, 37, 51, 53, 58, 75, 76, 80, 81, 94, 103 and 117. `Services` has no SN22 entry.
- SN22's on-chain identity: name "Desearch", url `https://desearch.ai`, repo `https://github.com/datura-ai/desearch`, description "Decentralized search engine". SN51's identity (Lium) points to `https://github.com/Datura-ai/lium-io` [chain 2026-11-23]. SN51 has been gamma-enabled since 2026-11-12 — [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>).
- SN22 was registered at block 2,009,702 (2023-12-26 00:06 UTC) [chain 2026-11-23].

#### Quality evidence
- The only published evaluation is Desearch's own: "Search evaluations · run by Desearch". It is a published snapshot of 19 Sept 2026 over four datasets (SimpleQA Verified, SealQA, FRAMES, BrowseComp). "The code and per-question evidence are public" — [Desearch benchmarks](https://www.desearch.ai/benchmarks).
- SimpleQA Verified (463 questions), "Reference page found in top 10":

  | Provider and mode | Reference page in top 10 | Returned text states answer @10 |
  |---|---|---|
  | Desearch fast | 99.1% | 86.6% |
  | Desearch balanced | 99.1% | 86.6% |
  | Parallel basic | 90.7% | 95.9% |
  | Parallel fast | 89.2% | 97.4% |
  | Perplexity search | 89.0% | 98.9% |
  | Exa auto | 79.5% | 95.0% |
  | Exa fast | 78.6% | 95.7% |
  | Tavily basic | 63.5% | 71.3% |

  Brave was not among the providers compared — [Desearch benchmarks](https://www.desearch.ai/benchmarks).
- Desearch's own caveat on BrowseComp: "the Desearch profile allowed up to 20 results per search and the other profiles up to 10… the result-count difference limits a direct provider ranking" — [Desearch benchmarks](https://www.desearch.ai/benchmarks).
- No independent evaluation of Desearch was found.

### Inferences
- **Fit with URnetwork's constraints.** For the sidecar's raw-results rule, the usable endpoints are:
  - `GET /web` (SERP);
  - `POST /search` with `summary` omitted;
  - AI Search only with `result_type: ONLY_LINKS`;
  - `/web/extract`, `GET /twitter`, and the Reddit and YouTube social endpoints.
  
  `summary: true`, AI Search's default, `links/twitter` ("AI-powered models") and Monitors' AI screening run Desearch-side LLMs, which are not in a client-verifiable TEE. The relay should set `result_type` and `streaming` explicitly, because the defaults produce LLM text.
- **Cost-plus pricing.** At list price plus about 20%, `GET /web` would be about $0.0012 per search and a default `POST /search` about $0.0036, against Brave at $0.006 (from $0.005).
- **Terms compared with Brave.** Desearch's terms are much thinner. Nothing forbids storing results in the person's encrypted record or passing them to the person's agents. But §5's "Reselling our Services without authorization" covers charging end users per search at cost plus a margin. URnetwork should get written authorization, which the enterprise route offers. The authorization should also cover storage and passing results on, since the terms are silent rather than permissive, and §6's IP clause is vague.
- The terms date from 2025-01-15, before Desearch 2.0 and before the current product line (Extract, Monitors, People Search). They may be revised. The relay should be ready for new restrictions.
- **Privacy.** Desearch is equivalent to a single centralized provider. It sees the relay's IP, URnetwork's key and the query, and by default keeps queries 12 months and may use them to "improve" its services. That is worse than Brave's 90-day query log, unless URnetwork negotiates ZDR.
- **Index coverage.** Desearch's high reference@10 combined with a lower "text states answer" score is consistent with an index seeded from "selected sources" that rank well on reference-URL benchmarks. That is a hypothesis, not a finding, and an independent test on URnetwork's own query mix would be needed.
- **Gamma.** Gamma cannot pay Desearch today. The same GitHub organization hosts Desearch and Lium, which runs a gamma service, so asking Desearch to set `SubnetGammaEnabled` on SN22 and publish a `services.json` is a plausible request. Until then, the owner's rule ("we pay the providers in gamma") cannot be met with Desearch. The fallback is card, or TAO "where supported".

### Gaps
- Numeric rate limits per key are shown only in the Console (login required).
- How TAO payment works was not found: address, valuation and minimum.
- The upstream behind `GET /web` is not named in any Desearch source. Whether it is Desearch's own index, a SERP vendor or something else is unknown.
- Whether Extract fetches pages through SN22 miners' proxies, which would expose the URLs a user extracts to miners, is not documented. Whether crawl tasks are derived from user queries, which would leak query topics to miners indirectly, is also not documented.
- The summary model and where it runs are not disclosed.
- The refund policy referenced in ToS §7 was not found.
- The SOC 2 report and DPA are available only by email under NDA.
- No independent quality benchmark was found. Desearch's own run excludes Brave.

## 2. Other subnets offering web search or web data (Masa/Gopher, Data Universe SN13, Hone/OpenKaito SN5, others)

### Takeaway
As of 2026-11-23, **SN22 is the only subnet that sells general web search.**
- **Macrocosmos's Data Universe (SN13)** sells raw social data, not web search: X and Reddit on demand, plus X/Reddit/YouTube datasets. It costs **$0.15 per 1,000 records via API** on pay-as-you-go. SN13 miners receive the request parameters and scrape X through an Apify actor or official APIs. There is no TEE and no gamma.
- **Masa/Gopher (SN42) is gone.** The SN42 owner key changed on 2026-03-25, the identity became "Unknown" and is now "CADmind", and Gopher's API host fails.
- **OpenKaito (SN5)** became Hone in 2025 and now does RLVR on software tasks. It has no search.
- **Others** (SN67 Harnyx deep research, SN31 rec4ll RAG/memory, SN45 AlphaRidge, SN101 Tag101) are not raw web search APIs. None is gamma-enabled.

### Cited Findings

#### How the subnet list was checked
- This researcher read the on-chain identity (`SubnetIdentitiesV3`) of every registered netuid [chain 2026-11-23]. Names or descriptions touching search or web data: SN13 "Data Universe" ("Scraping the world's social media data"), SN22 "Desearch" ("Decentralized search engine"), SN31 "rec4ll", SN45 "AlphaRidge.ai", SN67 "Harnyx" and SN101 "Tag101". **SN42's name is "CADmind"** ("Prompt to print… CADmind is…"). **SN5's name is "Hone"**, described as "an RLVR subnet: reinforcement learning from verifiable rewards. Miners are paid to solve real software-engineering tasks".
- SubnetRadar's "Every Bittensor subnet, explained" lists the same search and data subnets (SN13, SN22, SN45, SN101, SN67, SN31, SN93 Bitcast). "Masa, Gopher and OpenKaito do not appear" — [SubnetRadar](https://subnetradar.com/research/subnets).

#### Data Universe (SN13, Macrocosmos)
- **What it sells.** "55+ billion rows of structured, high-fidelity social media data from X, Reddit, and YouTube" — [datauniverse.macrocosmos.ai](https://datauniverse.macrocosmos.ai/) (www.macrocosmos.ai/sn13 redirects there). The API has two modes:
  - "The Real Time OnDemand API: pulling up to 1000 unique tweets per datetime (up to minute precision) matching your filters (usernames, keywords, hashtags, etc), including impression data (likes, retweets, etc)".
  - Asynchronous "Gravity Jobs", "where you can pull massive amounts of data, after waiting for a couple of" hours.
  - Source: [sn13-data-universe-api-examples README](https://github.com/macrocosm-os/sn13-data-universe-api-examples).
  - An MCP server is also offered — [Data Universe MCP docs](https://docs.macrocosmos.ai/subnets/subnet-13-data-universe/macrocosmos-mcp).
- **Raw data, no LLM.** On-demand requests take `source="X"` with usernames, keywords, `keyword_mode`, dates and `limit`, or a single tweet URL. They return structured posts (text, user, engagement, media URLs) — [on_demand.md](https://github.com/macrocosm-os/data-universe/blob/main/docs/on_demand.md) (last changed 2026-09-30).
- **Prices** (pricing page; no date shown) — [datauniverse.macrocosmos.ai](https://datauniverse.macrocosmos.ai/):

  | Plan | Monthly fee | Included | In app | Via API |
  |---|---|---|---|---|
  | Pay as you go | none | "$1 free usage credit" | "$0.05 / 1K records" | "$0.15 / 1K records" |
  | Astronaut | $99 | 300K records credit | $0.04 / 1K | $0.12 / 1K |
  | Cosmonaut | $499 | 4M records credit | $0.02 / 1K | $0.08 / 1K |
  | Enterprise | custom | custom | custom | custom |

  The free credit conflicts: the examples README says "First 5$ of credits is on us, when you register" — [examples README](https://github.com/macrocosm-os/sn13-data-universe-api-examples). The Gravity product page shows "$5 per 1M posts in Gravity" — [macrocosmos.ai/gravity](https://www.macrocosmos.ai/gravity) (from a search summary; not fetched).
- **Rate limits** are not published. The pricing page's FAQ asks "Do you have rate limits?" with no answer rendered — [datauniverse.macrocosmos.ai](https://datauniverse.macrocosmos.ai/).
- **Terms.** Macrocosmos's Master Service Agreement is hosted in its web app (app.macrocosmos.ai). The app is script-rendered, and `/terms`, `/msa` and `/legal` returned only an app shell to curl, so the text could not be read. A search-engine snippet of the MSA says clients may not "Resell the Services, in whole or in part, without Macrocosmos' prior written authorization" and may not "Engage in any activity that competes with Macrocosmos' Services". The snippet places these in a list tied to web-scraping or proxy features, so their scope is unclear — [search result attributed to app.macrocosmos.ai](https://app.macrocosmos.ai/icon.ico) (unverified).
- **Data provenance.**
  - The README says the data "is anonymized for privacy purposes to comply with the Terms of Service per each data source". Its miner policy (Version 1.0, March 2025) prohibits copyrighted content "unless you have explicit permission or a valid license to use it" — [data-universe README](https://github.com/macrocosm-os/data-universe).
- **Sources and tools (miners scrape).**
  - "The implementation uses the standard `ApiDojoTwitterScraper`"; "The Reddit implementation remains the same, using the Reddit API" — [on_demand.md](https://github.com/macrocosm-os/data-universe/blob/main/docs/on_demand.md).
  - Older mining docs: "As of Dec 17th 2023, we support X (Twitter) and Reddit scraping via Apify… or use official APIs from X (Twitter) and Reddit (recommended)". Scraper ids include `X.apidojo`, `X.microworlds` and `Reddit.lite`. "The Miner stores all scraped data in their local database, and uploads it to a shared S3 bucket" — [Data Universe Mining](https://docs.macrocosmos.ai/subnets/subnet-13-data-universe/data-universe-mining.md).
- **Miners see the request.**
  - Miners poll a Macrocosmos-run API for open jobs: `active_jobs_response = await client.miner_list_active_jobs(`, against `self.data_universe_api_base_url = self.config.s3_auth_url` — [neurons/miner.py](https://github.com/macrocosm-os/data-universe/blob/main/neurons/miner.py).
  - Rewards depend on how many available jobs a miner takes: "submitting nothing on a platform with available jobs is abstention (× 0.3); submitting fewer than 15% of available jobs scales down to a floor of 0.3".
  - Validators also see requests. They sample submissions and check entities "for matching the request (usernames, keywords, keyword mode, dates, url), then one entity is re-fetched from the live source".
  - Source for the last two points: [on_demand.md](https://github.com/macrocosm-os/data-universe/blob/main/docs/on_demand.md).
- **TEE:** not mentioned in the README, docs or pricing page — [README](https://github.com/macrocosm-os/data-universe); [datauniverse.macrocosmos.ai](https://datauniverse.macrocosmos.ai/).
- **Gamma:** SN13 is not gamma-enabled and has no service [chain 2026-11-23].
- **Status:** SN13 was registered 2023-12-11 [chain 2026-11-23]. The repo's last commit was 2026-10-22 — [GitHub commits API](https://api.github.com/repos/macrocosm-os/data-universe/commits?per_page=1).
- **Quality:** validators score correctness by re-fetching samples (see above). No independent quality or coverage evaluation was found.

#### Masa → Gopher (SN42): no longer operating as of 2026-11-23
- **What it was.** Gopher's miner docs give "netuid 42" for mainnet (165 for testnet).
  - Miners "use the Gopher Worker to scrape data from a secure TEE enclave", which "uses the ego framework to build, run and sign the binary", with an "Intel SGX 2.0+ enabled CPU required".
  - X was scraped with logged-in accounts or X API keys; Reddit and TikTok through Apify actors.
  - "web / llm processing" used a `CLAUDE_API_KEY` or `GEMINI_API_KEY`.
  - The page does not describe attestation.
  - Source: [Gopher miner docs](https://developers.gopher-ai.com/docs/subnet/miners) (still served on 2026-11-23; undated).
  - The live API was reportedly `POST data.gopher-ai.com/api/v1/search/live` with `type: "twitter"` (from a search summary of Gopher docs; not fetched).
- **Rebrand:** "Sep 17, 2025: Masa products are being rebranded as Gopher". "Gopher is a Layer-1 blockchain built for the AI data economy, formerly known as Masa". The founder and CEO is listed as former, "Jan 2021 ~ Apr 2026" — [RootData: Masa](https://www.rootdata.com/projects/detail/Masa?k=MzA0MQ%3D%3D).
- **Chain history [chain 2026-11-23]:**
  - SN42 has been registered since block 3,613,591 (2024-08-15 20:16 UTC). It was not re-registered.
  - The `SubnetOwner` coldkey changed at **block 7,824,429 (2026-03-25 18:06 UTC)**.
  - The identity read "Gopher" before the change, "Unknown" from at least 2026-04-01 through 2026-07-24, and "CADmind" on 2026-11-23.
- **Endpoints down (checked 2026-11-23):** `https://data.gopher-ai.com/` and `/api/v1/search/live` returned HTTP 530, and `https://gopher-ai.com/` returned HTTP 402. The gopher-lab GitHub repos were last pushed 2026-04-21 (`subnet-42`) and 2026-04-03 (`tee-worker`) — [gopher-lab repos API](https://api.github.com/orgs/gopher-lab/repos?sort=pushed&per_page=5).
- **Gamma:** SN42 (CADmind) is not gamma-enabled [chain 2026-11-23].

#### OpenKaito → Hone (SN5): no search API
- Subnet 5 was "initially focused on decentralized search and text embedding models". "On May 1, 2025, ownership of the subnet was transferred from its original creator to Latent Holdings". "On August 7, 2025, Subnet-5 was formally relaunched as Hone" — [IQ.wiki: Hone](https://iq.wiki/en/wiki/hone) (secondary; last updated 2026-04-27).
- The current on-chain identity is "Hone", an RLVR subnet whose miners "solve real software-engineering tasks". SN5 has been registered since 2024-03-04. It is not gamma-enabled [chain 2026-11-23].

#### Other candidates (none is a raw web-search API)
- **SN67 Harnyx:**
  - "Faster, cheaper, traceable research — produced by a competitive swarm of miners on Bittensor SN67". "A unified API routes queries across a competitive swarm of miners". Miners choose "models, retrieval strategies, synthesis methods".
  - TEE appears only as a future item: "Confidential compute via TEE", alongside "Zero data retention", under Phase 3.
  - No per-query price is published; a sample response shows `"credits_charged": "0.10"`.
  - Source: [harnyx.ai](https://harnyx.ai/).
  - Registered 2026-01-03; not gamma-enabled [chain 2026-11-23].
- **SN31 rec4ll:** "Recall is a decentralized RAG and memory API on Bittensor. Miners serve embeddings, reranking, vector search and LLM generation" [chain 2026-11-23 identity]. This is vector search over a customer's own data, not web search. Not gamma-enabled.
- **SN45 AlphaRidge** ("Turn financial news, X posts, and Telegram feeds into structured, real-time market intelligence") and **SN101 Tag101** (tags X posts) — [SubnetRadar](https://subnetradar.com/research/subnets). Neither is gamma-enabled [chain 2026-11-23].
- **SN1 Apex** (Macrocosmos, "A routing layer for intelligence"): no web-search or retrieval page appears in Macrocosmos's docs index — [docs.macrocosmos.ai/llms.txt](https://docs.macrocosmos.ai/llms.txt).

### Inferences
- **For general web search there is one subnet-backed option, Desearch, and it no longer depends on miners at query time.** Data Universe could feed an "X/Reddit search" tool, at $0.15 per 1,000 records (about $0.0015 for a 10-post query, before markup). But each query is broadcast to SN13's miners and to the Apify actor they run. That conflicts with the sidecar's privacy aims (see §5), and its MSA apparently needs authorization for resale.
- **Gopher was the only data subnet with TEE scraping, and it is defunct.** Even so, its "web / llm processing" sent content to Claude or Gemini outside the enclave.
- Harnyx produces LLM-synthesized research with no TEE, so it falls under the sidecar's exclusion of provider-run LLM answers.

### Gaps
- Taostats' subnet pages were not fetched (they render by script). The on-chain identity scan of all netuids and SubnetRadar were used instead.
- The Macrocosmos MSA text, Data Universe rate limits, and whether Data Universe accepts TAO or crypto were not verified.
- Whether a Gopher wind-down was announced on 2026-03-25 could not be confirmed from a primary source. A search summary attributed such an announcement to RootData, but the RootData page fetched did not contain it. The owner-key change on that date is on chain.
- Harnyx's terms, price and payment methods were not found.

## 3. Do any of the published gamma services, or any subnet that enabled gamma since, sell web search, and at what rate per gamma?

### Takeaway
**No.** At finalized block 9,570,155 (2026-11-23 14:58 UTC), gamma is on network-wide. The 13 gamma-enabled subnets are the same as at 07:26 UTC that morning (25, 28, 37, 51, 53, 58, 75, 76, 80, 81, 94, 103, 117). The `Services` map now has **11** entries: SN80 OpenRoboto added one during the day, pointing at its homepage. **None of the 11 service documents, and none of the gamma-enabled subnets, sells web search.** The search subnets (SN22 Desearch, SN13 Data Universe) are not gamma-enabled. There is therefore no rate per gamma for search. Gamma cannot pay for web search from any provider as of 2026-11-23.

### Cited Findings
- `GammaEnabled` = true; `SubnetGammaEnabled` true for exactly 25, 28, 37, 51, 53, 58, 75, 76, 80, 81, 94, 103, 117 [chain 2026-11-23]. This matches the 07:26 UTC read in [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>).
- `Services` entries (netuid → url) [chain 2026-11-23]:
  - 25 → `https://api.bringyour.com/pay/gamma/services.json`
  - 28 → `https://saygm.com/services.json`
  - 51 → `https://lium.io/api/gamma/service.json`
  - 53 → `https://engy.ai/services.json`
  - 58 → `https://api.robotensor.ai/services.json`
  - 75 → `https://api.hippius.com/api/billing/gamma/service.json`
  - 76 → `https://api.ormas.ai/services.json`
  - **80 → `https://www.openroboto.ai/`.** This is new since 07:26 UTC, when the read in gamma_payments_treasury.md listed ten services and SN80 among the subnets "enabled without a published service".
  - 94 → `https://cathedral.computer/v1/gamma/services.json`
  - 103 → `https://terza.si`
  - 117 → `https://app.everyframe.studio/services.json`
- The service documents' own descriptions (all fetched 2026-11-23):

  | Subnet | Service | Description |
  |---|---|---|
  | SN25 | URnetwork | "UR Pro plans and data" — [doc](https://api.bringyour.com/pay/gamma/services.json) |
  | SN28 | SayGM | "prepaid access to AI models through an API" — [doc](https://saygm.com/services.json) |
  | SN51 | Lium | "GPU pods by the second" — [doc](https://lium.io/api/gamma/service.json) |
  | SN53 | engy | "OpenAI-compatible LLM API… $1 per gamma plus 5%" — [doc](https://engy.ai/services.json) |
  | SN58 | Attune | "Robot data… Robot policies. Playground runs." — [doc](https://api.robotensor.ai/services.json) |
  | SN75 | Hippius | "decentralized cloud (compute, storage, S3)" — [doc](https://api.hippius.com/api/billing/gamma/service.json) |
  | SN76 | Ormas | "Coding tasks priced per accepted outcome", `payments: []` — [doc](https://api.ormas.ai/services.json) |
  | SN94 | Cathedral | "Confidential sandboxes (AMD SEV-SNP)" — [doc](https://cathedral.computer/v1/gamma/services.json) |
  | SN117 | EveryFrame | "AI video, image and speech generation… 1 Gamma = 1 USD" — [doc](https://app.everyframe.studio/services.json) |

  - SN80's url serves an HTML app shell titled "OpenRoboto — Robot intelligence built in the open", which describes a robotics-model competition. It is not a JSON service document — [openroboto.ai](https://www.openroboto.ai/).
  - SN103's url serves the Terza homepage, "LIVE ON BITTENSOR SUBNET 103 · EARLY ACCESS", offering chat, image and speech — [terza.si](https://terza.si).
- A search for "search", "web", "crawl", "scrap", "serp", "brave", "exa" and "tavily" across all 11 documents found no match. A search of the SayGM gamma guide and llms.txt, engy's llms.txt and docs, and the Terza page for "web search", "search", "online", "browse" and "grounding" found no web-search product.
  - SayGM describes itself as a "Privacy-first inference gateway on Bittensor… every request is sealed inside an Intel TDX TEE", and says it "does not make retention or training claims about upstream providers" — [SayGM llms.txt](https://saygm.com/llms.txt).
  - engy's only tool feature is ordinary function calling — [engy llms.txt](https://engy.ai/llms.txt).
- For comparison, the gamma-to-USD credit rates at the services that state one are 1 gamma = $1 (Lium, Hippius, SayGM, EveryFrame) and $1.05 (engy) — [gamma_payments_treasury.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/gamma_payments_treasury.md>); [engy service doc](https://engy.ai/services.json).

### Inferences
- The owner's rule ("people pay us fiat for compute balance, and we pay the providers in gamma") cannot be applied to web search today. Every candidate is paid in USD by card, in TAO (Desearch "where supported"), or in USDC (x402 providers).
- **The shortest path to gamma-paid search:**
  1. Desearch enables gamma on SN22 (`SubnetGammaEnabled` is set by the subnet owner).
  2. Desearch publishes a `services.json` with a `gamma` payment entry and btauth/1.
  3. Desearch credits a USD balance per spending hotkey, as Lium and SayGM do.

  URnetwork could then pay Desearch's list price per call from SN22 gamma, at the 1 gamma ≈ $1 convention.
- Routing search through SayGM or engy's LLMs, for example a model with a provider-side web-search tool, would make the provider's LLM write the answer. That is out of scope unless the model runs in a verifiable TEE, and neither documents web search.

### Gaps
- Gamma enablement can change at any block. This read is a snapshot at block 9,570,155.
- Whether SayGM passes provider-native tools through to upstream models (for example Anthropic's or OpenAI's server-side web search) was not tested. It is undocumented either way.

## 4. Search APIs payable per request in crypto (x402 or similar) other than Brave: providers, prices, terms, on-chain visibility, batching

### Takeaway
At least seven commercial search APIs take per-request USDC without an account, mostly by x402 on Base and some on Solana:

| Provider | Price per call over x402 |
|---|---|
| Brave (baseline) | $0.005 |
| You.com | $0.005 ($0.010 over MPP) |
| Exa | $0.004–$0.015 by search mode; contents $0.001 per page |
| Tavily | $0.01, advanced search only |
| Parallel | $0.01 for search, via its payment gateway (x402, Tempo MPP or card) |
| Keenable | $0.01 (against $0.004 with a prepaid key) |
| Linkup | x402, price not published |

Unverified third-party gateways charge $0.003, and one community L402 (Lightning) search server exists.

**The default x402 "exact" scheme makes one public on-chain USDC transfer per request**, from the payer's wallet to the provider, with a block timestamp. Brave's privacy notice says such transactions "may be linked to you by others". Three ways avoid per-request on-chain records:
- **Circle Gateway nanopayments.** Exa accepts them. The buyer deposits once, then signs off-chain authorizations, and Circle settles net balances in periodic batches.
- **MPP sessions on Tempo**, where vouchers are signed off-chain and settled in batches. You.com and Parallel accept MPP, but neither documents sessions.
- **The x402 batch-settlement scheme** (2026). No search provider was found offering it.

Every provider's terms checked restrict resale. Exa also forbids copying or distributing anything "obtained from or through" the Services. You.com forbids storing "significant portions" for re-use without a contract. Paying in crypto does not change any of these terms.

### Cited Findings

#### Providers, prices and payment mechanics
- **Brave (baseline):** "5000 base units ($0.005)" per request for web, LLM Context, news, videos, images, place search, POIs and descriptions; USDC on Base. "There is no session, no credit balance, and no top-up" — [Brave x402 llms.txt](https://search.agent.s.brave.app/llms.txt), via [brave_search_api.md §3](</Users/brien/urnetwork/sidecar/research_notes/Brave web search tool/brave_search_api.md>). Brave's privacy notice: "the resulting transaction is recorded publicly and permanently on the Base blockchain, which may be linked to you by others" — [Brave Search API Privacy Notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice), via the same notes.
- **You.com** — [You.com x402 docs](https://you.com/docs/administration/machine-payments/x402):
  - `GET /v1/search` costs $0.005, and `GET` or `POST /v1/agents/search` costs $0.005. `livecrawl` adds $0.001 per result. `POST /v1/finance_research` costs $0.11 (`deep`) or $0.50 (`exhaustive`); it is a research product.
  - Contents and Research APIs "return `401`… and do not offer payment terms".
  - Networks: Base and Solana, USDC; "There is no testnet."
  - "Payments settle on-chain and do not draw down your credit balance." "Each authorization carries a unique nonce and is valid for exactly one request."
  - "Zero Data Retention" is not available on x402 requests.
  - MPP: "MPP costs twice as much for Web Search and the same for Finance Research"; it is "the method-neutral alternative, settling in USDC on Tempo."
- **Exa** — [Exa x402 guide](https://exa.ai/docs/reference/x402-guide):
  - Only `/search` and `/contents` are payable: "All other endpoints are **not** available via x402."
  - Search, up to 10 results: lite/instant $0.004; auto/fast $0.007; deep-lite and deep $0.012; deep-reasoning $0.015. Summaries add $0.001 per result. Contents cost $0.001 per page.
  - "Prices are calculated upfront based on your request parameters (not actual results returned)."
  - Standard payment is a "Per-request on-chain transfer" on Base, Solana or Arc.
  - **Circle Gateway** option on Base, World Chain and Arc: deposit once, then "Each payment after that is a gasless signature that Circle verifies against your balance."
  - Limits: 10 paid requests per second per wallet. "Requests that include an API key bypass x402 entirely."
- **Tavily** — [Tavily x402 docs](https://docs.tavily.com/documentation/machine-payments/x402):
  - `POST /search` at $0.01 per call; "`search_depth` is always `advanced`".
  - USDC on Base. Tavily itself verifies and settles each call ("Verifies + settles on Base, then gets search results"), and refunds automatically if the upstream call fails after settlement.
  - "no API key, no account, no human in the loop".
  - The answer field is populated only on opt-in (`include_answer`).
- **Parallel** — [Parallel agentic payments docs](https://docs.parallel.ai/integrations/agentic-payments):
  - Through its gateway: Search (`/api/search`) $0.01, Extract $0.01 per URL, Task $0.30 (ultra).
  - Three ways to pay: "Pay with USDC on Base using the x402 protocol"; Tempo MPP with "pathUSD or USDC on the Tempo blockchain"; or "Pay with a credit card — no crypto wallet required" (Stripe).
  - Each request uses a 402 challenge and response. No sessions are described. The gateway limit is 60 requests per minute per IP.
- **Keenable** — [Keenable pay-per-request](https://docs.keenable.ai/pay-per-request):
  - "$0.01 per search or fetch, $0.10 per SELECT query". USDC on Base, by EIP-3009 authorization; "Each signed payment is good for one request".
  - A prepaid API key costs "$4 per 1,000 requests rather than $10".
  - It says only that it "searches and fetches public web pages"; it does not say whose index.
- **Linkup:** agents pay per request with "a wallet with USDC on the Base network"; the facilitator "settles the transaction on-chain". The post gives no price — [Linkup blog, 2026-05-05](https://linkup.so/blog/linkup-web-search-for-ai-agents-no-human-account-needed).
- **Firecrawl:** a search index snippet described an experimental endpoint, `https://api.firecrawl.dev/v1/x402/search`, capped at 10 results. But its docs page `docs.firecrawl.dev/x402/search` returned **HTTP 404** on 2026-11-23, and Coinbase's case study returned 403 — [Coinbase case study](https://www.coinbase.com/developer-platform/discover/case-studies/firecrawl) (not readable). Its status and price are unverified.
- **Third-party and community, unverified:**
  - "AgentSearch" tutorials list $0.003 per search and $0.005 for search plus read, settled on Base through Coinbase's CDP facilitator — [DEV tutorial](https://dev.to/agentsearchhq/x402-python-tutorial-let-your-ai-agent-pay-per-call-for-web-search-2of0) (from a search summary).
  - A "Web Search API" lists $0.003 per call over x402 — [README](https://cdn.jsdelivr.net/gh/Br0ski777/web-search-x402@main/README.md) (from a search summary).
  - `l402-search-mcp` charges per query in Lightning sats under L402 — [Glama listing](https://glama.ai/mcp/servers/llmops-pro/l402-search-mcp/tools/search) (from a search summary).
  - Lightning Labs promotes L402 for agents — [Lightning Labs, 2026-03-11](https://lightning.engineering/posts/2026-03-11-L402-for-agents/).
  - Which index any of these resells is not stated.

#### Terms of the main x402 providers (resale, storage, passing on)
- **Exa** Terms of Service, served as a PDF at exa.ai/terms on 2026-11-23, Exa Labs, Inc.; no revision date visible — [Exa Terms](https://exa.ai/terms):
  - §4.2: "You may not do, and may not permit any of your Authorized Users to do… (a) download, modify, copy, distribute, transmit, display, perform, reproduce, duplicate, publish, license, create derivative works from, or offer for sale any information contained on, or obtained from or through, the Services, except for temporary files that are automatically cached by your web browser for display purposes, or as otherwise expressly permitted in these Terms or by us in writing; … (e) resell, lease or sublicense the Services to any third party without our prior consent; (f) access, use or exploit the Services (including Output) to develop any competitive product or service".
  - §1.2(c) grants Exa "a nonexclusive, royalty-free, transferable, sub-licensable, worldwide, perpetual and irrevocable license to access, use, host, cache, store… any User Input and Output as needed to provide, develop and improve upon our products and services".
  - A "Master Subscription Agreement" controls where it applies.
- **Tavily** Terms, "Last updated: May 4, 2026", AlphaAI Technologies Inc. dba Tavily — [Tavily Terms](https://tavily.com/terms):
  - §3.2(ii) forbids to "license, sublicense, resell, distribute, lease, rent, lend, transfer, assign or otherwise dispose of the Services".
  - §9.2 grants Tavily a "perpetual, and irrevocable license to collect, host, use, access, view, store, copy" Customer Input.
  - §6.5: Tavily "may use, process, analyze, and retain Customer Input submitted to the AI Functionality and Outputs".
  - §4.4: Tavily may "accept payment of Fees in cryptocurrency or other digital assets approved by Tavily".
- **You.com** API Acceptable Use Policy, "Effective: October 22, 2026" (served at a URL ending `-may-2026`) — [You.com AUP](https://you.com/acceptable-use-policy-may-2026):
  - "Do not copy or store for re-use significant portions of Search Content without contractual authorization."
  - "Do not republish, resell, or redistribute Search Content as a standalone dataset, feed, or index."
  - It forbids to "Resell, sublicense, or offer the Services as a standalone API or service bureau" without consent.
  - "If you make the Services available to End Users or other third parties, you must bind them"; "Violations by your End Users are treated as your violations".
  - "Do not use Search Content to train or fine-tune models without written authorization."
  - Keyless x402 requests are "handled under You.com's general terms" — [You.com x402 docs](https://you.com/docs/administration/machine-payments/x402).
- Parallel, Keenable and Linkup terms were not read (see Gaps).

#### Is each payment public and per request? What avoids that?
- **x402 "exact" (default):** one on-chain transfer per request. Each provider confirms this in its own words:
  - Exa: "Per-request on-chain transfer" — [Exa](https://exa.ai/docs/reference/x402-guide).
  - You.com: "valid for exactly one request" and "settle on-chain" — [You.com](https://you.com/docs/administration/machine-payments/x402).
  - Keenable: "Each signed payment is good for one request" — [Keenable](https://docs.keenable.ai/pay-per-request).
  - Tavily settles on Base per call — [Tavily](https://docs.tavily.com/documentation/machine-payments/x402).
  - Brave says the transaction is public and linkable — [Brave Privacy Notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice).
- **x402 batch settlement**, "Introducing x402 Batch Settlement" by Cloudflare and Coinbase authors; "Last updated: 2026-06-24" — [x402.org](https://www.x402.org/writing/x402-batch-settlement):
  - The buyer commits funds to an escrow or channel. Each HTTP request carries a cumulative signed voucher, and the seller settles on chain in bulk: "Many logical payments are compressed into a single transaction."
  - It avoids "per-request gas or Facilitator fees".
  - SDK support covers TypeScript and Go, with Python in development.
  - It builds on the exact and "up to" schemes.
  - No search provider documented support for it.
- **Circle Gateway nanopayments** — [Circle: batched settlement](https://developers.circle.com/gateway/nanopayments/concepts/batched-settlement.md):
  - The deposit "is a one-time onchain transaction that establishes the buyer's Gateway balance".
  - Each payment signature "is created offchain and costs zero gas".
  - Gateway "periodically collects pending authorizations… computes net balance changes across all participants, and submits a single onchain transaction that applies the changes".
  - Exa accepts it — [Exa](https://exa.ai/docs/reference/x402-guide).
- **MPP sessions (Tempo)** — [mpp.dev sessions](https://mpp.dev/payment-methods/tempo/session):
  - "The buyer deposits stablecoins into a channel on the TIP-1034 precompile"; payments go "without an on-chain transaction for each payment"; "Opening, topping up, and closing are on-chain"; "Settlement runs on a schedule you choose".
  - Privacy: "the payer's address is public on Tempo". For private per-request payments, the page points to "charge with zones".
  - You.com and Parallel accept MPP — [You.com](https://you.com/docs/administration/machine-payments/x402); [Parallel](https://docs.parallel.ai/integrations/agentic-payments). Neither says it supports sessions as opposed to per-request charges.
- **Prepaid keys bought off-chain** (card) leave no per-request chain record:
  - Keenable: $4 per 1,000 requests — [Keenable](https://docs.keenable.ai/pay-per-request).
  - Desearch: card, or a single TAO top-up — [Desearch billing](https://www.desearch.ai/docs/guide/introduction/pricing-and-billing).
  - Brave: card — [Brave notes](</Users/brien/urnetwork/sidecar/research_notes/Brave web search tool/brave_search_api.md>).

### Inferences
- **What the public chain reveals.** In URnetwork's design the relay pays, not the end user. Per-request x402 payments would publish URnetwork's search volume and per-second timing, plus the provider and endpoint price, from a wallet anyone can link to URnetwork once it is identified. Query text never goes on chain. An adversary can still:
  - count URnetwork's searches and map their daily load;
  - confirm that a probe query they send through URnetwork's apps produces a payment;
  - in quiet periods, correlate one person's observed network activity with payment timestamps.
  
  Batching hides per-request timing behind periodic net settlements: Circle Gateway (Exa), MPP sessions (where offered), x402 batch settlement (where offered), or simply a card-funded prepaid key. Circle, or the channel counterparty, still sees every authorization.
- **Cost ranking for raw results** (list prices per call), cheapest first:
  1. Desearch `GET /web`, $0.001 (card or TAO, not x402).
  2. Desearch default `POST /search`, $0.003 (card or TAO).
  3. Keenable with a prepaid key, $0.004, and Exa instant over x402, $0.004.
  4. Brave and You.com over x402, $0.005.
  5. Tavily, Parallel and Keenable over x402, $0.01.
- **Crypto payment does not change the licence.** Every provider checked forbids resale without consent, so URnetwork's cost-plus-20% resale needs written permission everywhere. On storage:
  - Exa §4.2(a) forbids copying or distributing anything "obtained from or through" the Services, which is broader than Brave.
  - You.com's AUP allows storage below "significant portions" and forbids building a "standalone dataset, feed, or index". That arguably leaves room for a per-user encrypted record of that user's own searches, but this is untested.
  - Tavily's terms are silent on customer caching.
- **Provider-side LLM text to exclude:** Exa's summaries and deep-reasoning modes, Tavily's `include_answer`, You.com's finance research, and Parallel's Task API. The rest return links, snippets or page content.

### Gaps
- Parallel's, Keenable's and Linkup's terms, data retention and index sources were not read.
- Firecrawl's x402 endpoint status and price are unconfirmed, because the docs page returned 404.
- No search provider was found documenting support for x402 batch settlement or MPP sessions. Exa's Circle Gateway support is the only batching route confirmed.
- Whether Circle Gateway batch transactions expose individual authorizations on chain was not stated. The docs describe only net settlement.
- The AgentSearch, klymax402 and l402-search-mcp claims come from search summaries and were not verified.

## 5. Privacy on a subnet: who sees a query, and does anything stop a miner from logging it?

### Takeaway
On a standard Bittensor subnet, a validator sends work to miners as a JSON body over plain `http://`. The SDK code shows this. **Every miner queried sees the full request, and nothing in the protocol stops it from logging the request or forwarding it**, for example to a scraping API. Subnet owners who front the API see every query as well. In practice:
- **Desearch 2.0** keeps queries away from miners by serving from its own index. Desearch itself logs queries for 12 months unless ZDR is agreed.
- **SN13** lists on-demand jobs (usernames, keywords, URLs) to miners. The miners scrape with an Apify actor, and validators re-check samples.
- **Harnyx** routes queries to miners. TEE is only planned.
- **Gopher (SGX workers)** was the one TEE-based data subnet, and it is defunct.
- **Desearch 1.0** gave queries to miners, who sent them on to SerpAPI, OpenAI and the X API. It was superseded by Desearch 2.0, which a Desearch blog post dated 2026-01-03 describes; the exact switch date was not found.

No subnet offering web search today uses a TEE.

### Cited Findings
- **Protocol transport.** The Bittensor SDK's dendrite builds `return f"http://{endpoint}/{request_name}"` and posts `json=synapse.model_dump()` to the miner's axon — [RaoFoundation/bittensor dendrite.py (master, read 2026-11-23)](https://github.com/RaoFoundation/bittensor/blob/master/bittensor/core/dendrite.py). The Bittensor docs say miners "deploy Axon servers to receive and process data from validators" and validators "use Dendrite clients to transmit data to miners" — [Bittensor building blocks](https://docs.learnbittensor.org/learn/bittensor-building-blocks) (quotes from a search summary; the page now redirects to bittensor.com/docs).
- **Desearch 2.0:** "Miners do not serve search queries, and queries never wait on miner work" — [Desearch x Bittensor](https://www.desearch.ai/docs/guide/introduction/desearch-x-bittensor). Desearch keeps "Usage data (API calls, queries and usage records): 12 months" — [Privacy Policy](https://www.desearch.ai/privacy-policy). ZDR is "available… Enabled for your workload on request" — [Security](https://www.desearch.ai/security).
- **Desearch 1.0 (superseded; docs of 2025-05-02):** miners held `SERPAPI_API_KEY`, `TWITTER_BEARER_TOKEN` and `OPENAI_API_KEY` — [env_variables.md @ 2025-05-02](https://github.com/Desearch-ai/subnet-22/blob/9ae9871ecc97c00b53c373ce5cbb3a6841bba19a/docs/env_variables.md). "In the first version of Desearch, miners answered search requests and validators judged the answers" — [Desearch blog](https://www.desearch.ai/blog/decentralized-search-engine-desearch-bittensor).
- **SN13 (Data Universe):**
  - Miners poll `miner_list_active_jobs` from the Data Universe API — [miner.py](https://github.com/macrocosm-os/data-universe/blob/main/neurons/miner.py).
  - Jobs carry usernames, keywords, dates or a URL. Miners scrape them with `ApiDojoTwitterScraper` and are scored on covering at least 15% of "available jobs". Validators check entities "for matching the request (usernames, keywords, keyword mode, dates, url)" — [on_demand.md](https://github.com/macrocosm-os/data-universe/blob/main/docs/on_demand.md).
- **Harnyx (SN67):** "A unified API routes queries across a competitive swarm of miners". "Confidential compute via TEE" and "Zero data retention" are Phase 3 items — [harnyx.ai](https://harnyx.ai/).
- **Gopher (SN42, defunct):** miners scraped "from a secure TEE enclave" (Intel SGX, EGo-signed binary), but "web / llm processing" used `CLAUDE_API_KEY` or `GEMINI_API_KEY`. No attestation flow is described — [Gopher miner docs](https://developers.gopher-ai.com/docs/subnet/miners). The subnet changed owner on 2026-03-25 and the Gopher API host now fails (§2).

### Inferences
- **Nothing technical stops a miner from logging queries on a non-TEE subnet.** Miners are anonymous, can be anywhere, and are paid by emissions, not by contract with the customer. Incentive scoring only checks output quality. Contractual or reputational recourse is weaker than with one identified company. Sending sidecar searches to such a subnet would spread plaintext queries across many operators and their scraping vendors (Apify, X, Reddit), which is worse than Brave's single 90-day log.
- **Desearch 2.0 has the privacy profile of a single company, not of a subnet.** The query goes to Desearch over TLS and is logged for 12 months by default. URnetwork's relay should strip identifying headers, send no per-user identifiers, and negotiate ZDR before launch.
- **TEE-based search would need two things:**
  1. a provider whose query handling (index lookup or scraper) runs in an attested enclave the client can verify;
  2. no forwarding of the plaintext to outside APIs.
  
  As of 2026-11-23 no Bittensor subnet offers this. Gopher's design came closest and still leaked to LLM APIs.

### Gaps
- No subnet documents an encrypted transport (TLS) between validators and miners that is separate from the SDK default. Custom subnets may add their own, which was not audited.
- Whether Desearch's crawl tasks, or Extract requests, carry URLs derived from user queries to SN22 miners is undocumented.
- Whether SN13's job board shows each job to every miner, or only to some, was inferred from the scoring rule ("available jobs") rather than read in the job-API code.
