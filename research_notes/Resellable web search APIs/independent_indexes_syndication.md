# Independent web indexes, syndication sources and big-company search APIs as resellable alternatives to Brave (as of 2026-11-23)

All primary pages below were fetched on 2026-11-23, mostly with curl and converted to text so clauses could be quoted verbatim. Where a page could not be fetched that way (Yandex docs behind a CAPTCHA, some JavaScript pages), the WebFetch tool was used and this is marked. Governing documents and their dates as fetched:

| Source | Binding document | Date shown |
|---|---|---|
| Mojeek | Search API Terms of Service Agreement | No date on page. Its DPA is "Version: 3.0 (5th November 2026)" |
| EUSP / Staan | Terms of Service "provided upon registration" (not public) | FAQ "Last update: November 2026"; Privacy Policy "November 2026" |
| Kagi | Kagi API Terms of Service | "Effective Date: 2026-09-22" |
| Yep (Ahrefs) | Yep Terms of Service | "Last modified: March 26, 2026" |
| Marginalia | API page plus Polar product text | "Updated 2025-12-08"; commercial product created 2026-02-06 |
| Yandex | Terms of Use of Yandex Search API | "Date of placement: August 26, 2026", "Effective date: September 07, 2026" |
| Google (Gemini API) | Gemini API Additional Terms of Service | "Effective March 23, 2026" |
| Google Cloud | Service Specific Terms, §20(k)–(l), §21 | "Last modified November 18, 2026" |
| Microsoft (Grounding with Bing) | Two TOUs, direct and enterprise | "Last updated: November 2025" |
| Microsoft Web IQ | Terms of Use for Microsoft Web IQ | No date on page. Pricing page updated 2026-11-16 |
| Brave (baseline) | Search API Terms of Use | "Last updated: 1 Sep, 2026", from the baseline notes |
| Common Crawl | Terms of Use | "LAST UPDATED: March 7, 2024" |

Section 4 of `research_notes/Brave web search tool/brave_search_api.md` is the baseline and is not repeated here.

## 1. Do the terms permit (a) per-search charging of end users, (b) passing results to end users and their own third-party tools, (c) storing or caching results, (d) wholesale resale, syndication, white-label or a partner program?

### Takeaway
Mojeek is the only provider whose public, binding terms affirmatively permit nearly all of URnetwork's intended use. It allows commercial "subscription services" and AI agents, permits combining and modifying results with no attribution, and on its £3/1k Business plan grants indefinite storage. It is silent on wholesale resale. Staan (EUSP) says "Yes" to white-label and sub-licensing, but only in its FAQ; its binding ToS is shown only at registration. Every big-company offering forbids resale and storage:
- Kagi allows storage only with written exceptions.
- Microsoft Web IQ is pure retrieval but limited to LLM interfaces, 200 characters per source, no resale and no storing of results.
- Grounding with Google or Bing is LLM-generated, so out of scope, and also forbids resale.
- Google's full-web API is partner-only.
- Brave does sell direct licenses (Kagi has one), but has no public program.

### Cited Findings

#### At a glance (each cell is sourced in the provider sections below)

| Source | (a) Charge end users per search | (b) Results to end users and their own tools | (c) Store or cache | (d) Resale, syndication, white-label |
|---|---|---|---|---|
| **Mojeek** (Business/Enterprise) | Allowed: "commercial purposes, such as subscription services" | Allowed: "any application, including … AI agents and assistants". Silent on third-party tools | Business/Enterprise: "retain Data indefinitely". Startup: 1-hour same-user cache. Never "as part of any search index" | Silent: neither granted nor forbidden. Kagi holds a direct license |
| **Staan (EUSP)** | Not addressed publicly | Not addressed publicly | Not addressed publicly | FAQ: white label / sub-licensing "Yes" (binding ToS not public) |
| **Kagi** | Allowed inside own apps and services | Allowed, including "sending Results to an AI model". End users bound by the Terms | Only "transient caching needed to operate your application" | Forbidden as "standalone product, bulk feed, dataset, or substitute for direct Kagi API access, unless we agree in writing" |
| **Yep (Ahrefs)** | Ambiguous: "exploiting for any commercial purposes … use or access to Yep Services" needs written consent | Third-party end users contemplated (4.3) | Not prohibited by Ahrefs. Third-party rights are the customer's responsibility (5.4) | Needs "express written consent" (11.7) |
| **Marginalia** (commercial key) | "no commercial usage restriction" | Same | Silent | "Other terms are negotiable" |
| **Stract** | n/a: repository archived 2026-04-02, domain now an unrelated product | | | |
| **Yandex Search API** | Silent ("use on the Customer's product") | Silent. Result order must not be altered | Silent | Silent. No "similar product of the Yandex search engine" |
| **Microsoft Web IQ** (retrieval) | Not addressed directly, but resale of access or Content is forbidden (3.2.11) | Only "LLM Uses" within the Application. Max 200 characters per source. No access "outside of, the Application" | Only LLM Summaries per end user, and Content during one "Atomic Action" | Forbidden: "Redistribute, resell, or sublicense access to any Services or Content" |
| **Grounding with Bing** (LLM, out of scope) | Not addressed directly, but resale of Output is forbidden (4(b)(l)) | Only in "internet search experiences" | Direct TOU: forbidden. Enterprise TOU: only "as an integrated part of its own work product" | Forbidden |
| **Google Grounding** (LLM, out of scope) | Not addressed directly, but "resell" of Grounded Results is forbidden | Only to "the end user who submitted the prompt" in an app "owned and operated by you" | Up to 2 years in an end user's chat history | "cache, frame, syndicate, resell" forbidden |
| **Google Custom Search / Web Search Service** | CSE closed to new customers and ends 2027-01-01. WSS partner-only, no public terms | | | |
| **Brave** (baseline) | Not addressed. (xii) forbids resale | End users allowed with a flow-down agreement | "transient storage" only. Custom plan for storage | Forbidden in ToS. Direct licenses exist off-list (Kagi) |
| **Common Crawl** (self-host) | CC license is non-sublicensable, but its ToU does not restrict commercial use of what you build | n/a | n/a | n/a. Rights in the crawled pages are not granted |

#### Mojeek (UK; own index)
All clause quotes are from the [Mojeek Search API Terms of Service Agreement](https://www.mojeek.com/about/legal/api-terms.html), numbered as rendered (section 1 "API Services", item 6 "Usage").
- (b) Scope of use: "Data provided by the Services ("Data") may be used in any application, including internet search experiences and artificial intelligence applications such as retrieval-augmented generation, grounding, AI agents and assistants, and model evaluation, subject to these Terms." (1.6(a))
- Combining and reordering: "You may reorder the ranking of search results." (1.6(b)); "You may combine Data with search results from other sources, including other search engines." (1.6(c))
- (a) Commercial use: "You may use Data for commercial purposes, such as subscription services, and display it together with advertising from other parties, without attribution to Mojeek." (1.6(d))
- Derived content: "You may modify the Data, and generate new content from it, unless prohibited by law and subject to the exclusions below." (1.6(e))
- (c) Storage: "You may retain Data indefinitely only if you subscribe to a plan with storage rights." (1.6(f))
- Exclusions (1.6(h)):
  - "Do not compile, copy or store any Data unless you subscribe to a plan with storage rights. Without storage rights, do not cache any Data except temporarily, to serve the same user, for up to 1 hour."
  - "Do not present information that was not included in the Data as if it were part of the Data, for example invented URLs, titles or snippets shown as Mojeek search results. Content you generate from Data, such as an AI-written answer, is permitted."
  - "Do not use Data as part of any search index."
- Third-party content: "Mojeek grants no rights in the third-party content contained in or linked from the Data. You are responsible for complying with copyright law and with publishers' terms and permissions, including any reservation of rights over text and data mining…" (1.6(g))
- Custom terms: "We may vary these Terms in writing for our Enterprise customers (the "Enterprise Plan")." (1.7)
- Automated access: the ToS prohibits "using or accessing the Services by any automated means, unless you are an authorised Services user." (1.4(d))
- (d) The ToS contains no clause on reselling or sublicensing Data or API access, and none on sharing the API key.
- Which plans carry storage rights:
  - Pricing table: Startup shows a cross for "Storage Rights"; Business and Enterprise show a check. All three show a check for "AI Usage". — [Mojeek Search API page](https://www.mojeek.com/services/search/web-search-api/) (read from the page's HTML)
  - FAQ: "Yes, our Business Plan and Enterprise Plan have storage rights which permit indefinite data retention. The Startup Plan enables you to cache results for one hour…" — [same page](https://www.mojeek.com/services/search/web-search-api/)
- More FAQ answers — [same page](https://www.mojeek.com/services/search/web-search-api/):
  - "Yes, you can use our Search API for commercial reasons, such as your own subscription service, as long as you adhere to our Terms of Service Agreement and policies."
  - "Yes, you can combine our Search API results with other data sources such as other web search suppliers."
- Syndication to other engines: Kagi's January 2026 post lists "Mojeek — Direct license" among its index vendors. — [Kagi blog, 2026-01-21](https://blog.kagi.com/waiting-dawn-search)
- Termination: "Either party may terminate these Terms at any time, immediately, on notice to the other party." (8.2) Prices: "We may change any and all prices at any time with 30 days' notice. All deposits are non-refundable." (2.1) — [API ToS](https://www.mojeek.com/about/legal/api-terms.html)

#### European Search Perspective (EUSP): Staan
- White-label: "Can I integrate Staan into a broader solution marketed under my own brand (white label / sub-licensing)? Yes. From the console, you can create as many API keys as needed." — [Staan FAQ, "Last update: November 2026"](https://staan.ai/faq)
- Binding terms: "Do you have Terms of Service and a DPA? Yes. The Terms of Service are provided upon registration. The DPA (Data Processing Agreement) is available upon request." — [Staan FAQ](https://staan.ai/faq). I could not read the ToS. It is not published.
- Customers and positioning:
  - Staan "power[s] leading alternative search engines like Ecosia, Lilo, and Qwant", giving "direct access to a proprietary web index, designed specifically for enriching AI applications and agents, summarization, and embedded search." — [Staan FAQ](https://staan.ai/faq)
  - The homepage logo strip shows CamoCopy, Qwant, OVHcloud, Infomaniak, xPrivo, Ecosia and Pappers. — [staan.ai](https://staan.ai/)
- Attribution and storage: the only public statement is marketing: "Every result returned by the API is linked back to its origin — auditable, attributable, and never a black box." — [staan.ai](https://staan.ai/). The public pages say nothing on storing or caching results, per-search charging, or passing results to third-party tools.
- Operator: European Perspective SAS (Paris, RCS 928 439 785, share capital €66,574), hosted by OVH. Legal contact is legal@qwant.com. — [Staan legal notice, June 2026](https://staan.ai/legal)

#### Kagi
All quotes are from the [Kagi API Terms of Service, effective 2026-09-22](https://kagi.com/privacy/api) unless noted.
- (a)(b) Grant: "Within your plan limits, you get a limited, non-exclusive, non-transferable, non-sublicensable, revocable license to call the API and use the outputs it returns, including search results, translations, and summaries ("Results") in your own applications and services, including sending Results to an AI model to answer your users' queries. Integrating Results into your own applications and services as permitted above is not a prohibited transfer."
- (c) "You may not: Store, cache, or build a database of Results beyond the transient caching needed to operate your application. You may not create a persistent copy of, or a derivative index from, the Kagi search index or other Results, and you may not bulk download, scrape, or archive Results."
- (d) "Resell, sublicense, proxy, redistribute, or publish the API or raw Results as a standalone product, bulk feed, dataset, or substitute for direct Kagi API access, unless we agree in writing."
- Training: "Use Results to train or fine-tune a search index, ranking system, translation or summarization model, or other service that competes with Kagi, or systematically harvest Results to assemble a training or evaluation dataset."
- End users: "Your app and its users are your responsibility — their conduct through the API counts as yours, and you must ensure your end users don't do anything these Terms prohibit you from doing."
- Exceptions: "If you need something different — a service level commitment, volume pricing, or an exception to a restriction above — email developers@kagi.com and we can set amended terms in a written agreement, which controls where it differs."
- On termination: "you must stop using the API and delete any cached Results."
- Marketing line: "Licensed for commercial and AI use. Need an SLA? We'll put it in writing." — [kagi.com/products/api](https://kagi.com/products/api)

#### Yep (Ahrefs)
All quotes are from the [Yep Terms of Service, last modified March 26, 2026](https://platform.yep.com/legal/terms-of-service/) (Ahrefs Pte. Ltd., Singapore).
- License: "Ahrefs grants you a limited, non-exclusive, non-transferable, non-sublicensable and revocable licence to use Yep Services for the limited purposes set forth in the documentation for Yep Services." (11.4)
- (b) End users: "Where the User Application involves providing access to or the use of Yep Services by end users who are third parties who are outside of your organisation or unaffiliated to you, you shall ensure that any and all terms of use … with such third-party end users do not impose any additional obligations … on Ahrefs…" (4.3)
- (a)(d) Resale: the customer shall not engage in "reproducing, duplicating, copying, selling, trading, transferring, assigning, publishing, licensing, sublicensing, or exploiting for any commercial purposes, any portion of Yep Services, or use or access to Yep Services or the computer code that powers Yep Services, without our express written consent" (11.7).
- No competing products: "use Yep Services and Content, in any form and whether in whole or part, to develop a product or service which competes with us or any of our products and services" is prohibited (4.4).
- (c) Storage: there is no storage or caching prohibition. Instead: "You agree that User is solely responsible for ensuring that User has the necessary rights and permissions to use (including to process, host, store, transfer, display, modify, publish, distribute or create derivative works of) Content…" (5.4)
- Derived output: "Content may be presented in a format different from its original source and any such presentation and adaptation of Content is provided solely to enable or enhance search functionality in User Applications and shall not be construed or otherwise used as a new or derivative work." (5.1)

#### Marginalia
- Key types — [Marginalia API page, "Updated 2025-12-08"](https://about.marginalia-search.com/article/api/):
  - "Free non-commercial … Provided under CC-BY-NC-SA 4.0."
  - "Paid non-commercial … Provided under CC-BY-NC-SA 4.0."
  - "Commercial: Buy a metered commercial key with no commercial usage restriction or attribution requirement."
  - "Other terms are negotiable, email contact@marginalia-search.com."
- The commercial product is titled "Commercial License: Metered API Access, $4/1000 Queries". — [Polar checkout](https://buy.polar.sh/polar_cl_hKnbSGWkflTozpXajwIu2ycB2fYmLM8jDxsuh06Kvmt) (product record created 2026-02-06)
- No public clause addresses storage, per-search resale or third-party tools beyond "no commercial usage restriction".

#### Stract
- "This repository was archived by the owner on Apr 2, 2026. It is now read-only." — [GitHub StractOrg/stract](https://github.com/StractOrg/stract)
- The stract.com page title now reads "Stract: Track your brand and find the voices your audience trusts". That is an unrelated product, with no search API. — [stract.com](https://stract.com/)

#### Yandex Search API (Yandex Cloud)
All quotes are from the [Terms of Use of Yandex Search API, effective September 07, 2026](https://yandex.com/legal/cloud_terms_search_api/en/).
- (a)(b) "It is allowed to send requests and use search results for the purpose of their use on the Customer's product. The placement of search results is allowed in any design (design), but without alteration of results order." (3.2)
- (d) "The use of the Service is prohibited: in order to create a similar product of the Yandex search engine…" (3.3.1). "It is prohibited to make automatic Requests to the search engine … in any other way without the prior consent of Yandex." (3.5)
- Volume threshold: "Yandex has the right to restrict the Customer's access to the functionality of the Service for providing search results, including but not limited to generative responses, if: … the number of Users using such functionality exceeds 1,000,000 per day or if the total number of Requests using the functionality specified in clause 1.2 … exceeds 100,000,000 (one hundred million) within 1 calendar month." (3.6)
- Incorporated license: "Customer confirms consent with the terms of 'License to use Yandex Search Engine'" (1.5). That license, written for the consumer engine, says the service "shall be intended exclusively for personal, non-commercial use." — [License to use Yandex Search Engine](https://yandex.com/legal/termsofuse/)
- (c) The Search API ToU contains no clause on storing, caching, reselling or sublicensing results, nor any attribution requirement.

#### Google
- **Custom Search JSON API**: "Note: The Custom Search JSON API is closed to new customers. Vertex AI Search is a favorable alternative for searching up to 50 domains. Alternatively, if your use case necessitates full web search, contact us to express your interest in and get more information about our full web search solution. Existing Custom Search JSON API customers have until January 1, 2027 to transition to an alternative solution." — [Custom Search JSON API overview, updated 2026-11-19](https://developers.google.com/custom-search/v1/overview)
- **Web Search Service API (partner-only full-web)**:
  - "The Web Search Service API allows programmatic partners to develop websites and applications that retrieve and display Google Search results." — [developers.google.com/web-search-service, updated 2026-11-05](https://developers.google.com/web-search-service)
  - On 2026-11-23 its reference and "using_rest" pages returned 404 ("You may need to sign in").
  - Per SEJ (Sept 2026), every request needs "a client ID tied to a partner agreement on top of a Google Cloud project and API key", and the pages "don't provide details on how a company can become a partner, what the service costs, or what query limits might be in place." — [Search Engine Journal](https://www.searchenginejournal.com/google-documents-partner-only-api-for-full-web-search-results/589194/)
- **Grounding with Google Search (Gemini API)** — [Gemini API Additional Terms, effective March 23, 2026](https://ai.google.dev/gemini-api/terms):
  - Definition: "Grounded Results" mean "responses that Google generates using the prompt from the end user … and results from Google's search engine".
  - "You will only use Grounding with Google Search in an application that is owned and operated by you and will only display the Grounded Results with the associated Search Suggestion(s) to the end user who submitted the prompt."
  - "You will not, and will not allow your end user or any third party to, cache, frame, syndicate, resell, analyze, train on, or otherwise learn from Grounded Results or Search Suggestions… it is a violation of these terms to use Grounding with Google Search to extract or collect one or more of these components for another purpose (for example, using programmatic or automated means to collect Links, using Links to build an index…)."
  - Storage exception: "You may copy and store, for up to two (2) years, the text of the Grounded Result(s): (1) that were displayed by you only to evaluate and optimize the display… (2) in chat history of an end user of your application only for the purpose of allowing that end user to view their chat history…"
  - "You may allow end user(s) to copy and store individual Grounded Results that were displayed to them through your application as long as you do not allow Grounded Results to be accessed or collected by automated or programmatic means or to be used to create a database."
  - "Unless permitted by Google in writing, you: (1) will not modify, or intersperse any other content with, the Grounded Results or Search Suggestions…"
- **Grounding with Google Search and Web Grounding for Enterprise (Google Cloud)** — [Google Cloud Service Specific Terms, last modified November 18, 2026](https://cloud.google.com/terms/service-terms):
  - §20(k) is the same in substance as the Gemini API terms: "Will not, and will not allow its End Users or any third party to, cache, frame, syndicate, resell…". It allows storage "for up to two (2) years … in the chat history of an End User".
  - Search Suggestions may be omitted "subject to the conditions set forth on the Pricing page".
  - §20(l): "Section 20(k) … also applies to Web Grounding for Enterprise, except that … the phrase 'Google's search engine' is replaced with 'GCP's web index'".
  - §21 on Agent Search (formerly Vertex AI Search): "Customer may use only Customer Data and web domains that it owns or is authorized to utilize." So it is not a general web index.
- **DOJ remedy syndication**: the Final Judgment "compels Google … to syndicate its search results and search text ads to Qualified Competitors". But as of 2026-05-07, "the tasks of developing data-sharing and syndication license templates has not begun… Nor have Qualified Competitors been comprehensively identified". — [Order, US v. Google, 1:20-cv-03010, Doc. 1514, filed 05/07/26](https://www.courthousenews.com/wp-content/uploads/2026/05/google-mehta-denies-stay-pending-appeal-for-now-order.pdf)
- Kagi's account of Google's commercial stance: "Google does not offer a public search API. The only available path is an ad-syndication bundle with no changes to result presentation - the model Startpage uses." — [Kagi blog, 2026-01-21](https://blog.kagi.com/waiting-dawn-search)

#### Microsoft
- **Bing Search APIs retired**: "Bing Search APIs will be retired on August 11, 2025. Any existing instances of Bing Search APIs will be decommissioned completely, and the product will no longer be available to be used or new customer signup. Customers are encouraged to migrate to Grounding with Bing Search as part of Azure AI Agents." — [Microsoft Learn lifecycle notice](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement)
- **Grounding with Bing Search, direct TOU** — [Terms of Use, last updated November 2025](https://www.microsoft.com/en-us/bing/apis/grounding-legal):
  - Services "includes access to (i) Output after being processed and summarized using an LLM" (1(h)).
  - Prohibitions (4(b)):
    - "Use the Services outside of, or separately from, the Approved Microsoft Application" (a)
    - "Use the Services to create a database or service that competes with Output" (g)
    - "Redistribute, resell, or sublicense access to any Microsoft service or Output" (l)
    - "Copy, store, cache, archive, or create a database of Output" (o)
  - Display appendix: "You may only use the Output in Applications that are internet search experiences." Also: "Copy, store, or cache the Output or any associated data or content therein" and "Display advertising that is not provided by Microsoft" are prohibited.
- **Grounding with Bing Search, enterprise (Azure Foundry) TOU** — [Terms of Use, last updated November 2025](https://www.microsoft.com/en-us/bing/apis/grounding-legal-enterprise):
  - Same prohibitions, including "Redistribute, resell, or sublicense access to the Service or Bing Services Output" (3(b)(l)).
  - Storage carve-out: "Customer may copy, store, cache or archive Bing Services Output solely (1) to the extent permitted by copyright law and (2) as an integrated part of its own work product, so long as the work product is not created for the purpose of or intended for use as a substitute for the Services or the Bing Services Output (for example, creating a database of Bing Services Output, indexing links contained in the Bing Services Output, using links for crawling or scraping, or offering a separate search offering). Customer may not otherwise copy, store or cache Bing Services Output." (3(c))
- **Microsoft Web IQ (pure retrieval)** — [Terms of Use for Microsoft Web IQ](https://www.microsoft.com/en-us/webiq/webiq-legal), no date shown:
  - Grant (2.1): use "the Content, as it is provided by the Services, solely in the Application".
  - LLM Use (2.5): "Customer agrees during the Term to only (i) display Content received from the Microsoft Web IQ APIs on the same user interface as content from an LLM; and (ii) use only Grounding Content for (A) Grounding Customer's LLM, (B) displaying respective source attribution…, and (C) creating summaries for display to End Users ("LLM Summaries") within the Application".
  - Prohibitions (3.2):
    - "Provide access to the Services or Content separately from, or outside of, the Application" (3.2.1)
    - "Create or attempt to create a substitute, competitive or similar service" (3.2.7)
    - "Redistribute, resell, or sublicense access to any Services or Content" (3.2.11)
    - "Use the Content (i) as part of any machine learning or similar algorithmic activity, (ii) to train, evaluate or improve any model…" (3.2.14)
    - "Copy, store, cache, archive, or create a database of Content, except as expressly permitted in these TOU" (3.2.15)
  - Display limit (Exhibit A §1): "For any single source, Company will not display Grounding Content exceeding the lesser of (the 'Character Limit') (a) 200 characters or (b) the maximum amount specified by the applicable website owner or webmaster."
  - Search experience (Exhibit A §2): "All data returned in Responses may only be used by Customer in a search experience that helps end users find and navigate to the Response's data sources."
  - Storage exceptions (Exhibit A §4): "Store LLM Summaries solely on a non-aggregate, per End User basis for individual End User Chat history for the duration permitted by applicable law"; store summaries with links "as an integrated part of Customer's internal work product"; and "Maintain Content in a transient processing state solely to the extent strictly necessary to complete a single logical request or workflow initiated by an LLM (an 'Atomic Action')… Customer will promptly delete all such Content immediately after completion of the Atomic Action."
  - News fees (2.6): "Customer (and not Microsoft) is responsible for (i) paying any licensing or other fees that may be due to news publishers… for Customer's display or use of Responses".
  - FAQ: "Outside these exceptions, don't store the search results themselves: the Terms of Use don't allow derivative databases, persistent caching, or long-term archival of Content." — [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq)

#### Brave (baseline; resale, syndication and storage rights)
- Self-serve ToS (1 Sep 2026): forbids storage beyond "transient storage required for operation" (3(b)(i)), making the API available to third parties (iii), and "redistribute, resell, or sublicense the Search Results" (xii). — [Brave Search API Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service), quoted in full in the baseline notes.
- Storage for sale: "Can I store results or use them to train models? Yes, with a custom plan. Contact sales to learn more about search with storage rights." — [brave.com/search/api](https://brave.com/search/api/)
- Historical prices: in June 2025 the public "Data w/ storage rights" tiers were $26 CPM (Base) and $45 CPM (Pro). — [Wayback 2025-06-12](https://web.archive.org/web/20250612135902/https://brave.com/search/api/), via the baseline notes
- Syndication to other engines: "We also offer API access to Brave Search so it can power other search engines." — [brave.com/search](https://brave.com/search/)
- Kagi's January 2026 post lists "Brave — Direct license" (also Mojeek and Yandex) — [Kagi blog, 2026-01-21](https://blog.kagi.com/waiting-dawn-search). This is the only documented case found of Brave results being syndicated into another search engine that resells them (Kagi now sells its blended results through its API).
- Brave's own customer logos: "Trusted by the world's top AI labs (including ones we can't name)". Logos (image alt text) include Kagi, You.com, Mistral AI, Cohere, Together.ai, Firecrawl, Ghostery, Snowflake, Shopify, Chegg, Turnitin, Motley Fool, Axel Springer, Apollo, Causaly, Cleo, Horizon, AWS and SoftwareOne. — [brave.com/search/api](https://brave.com/search/api/). The page does not say which of them redisplay results to third parties.
- Anthropic: "Anthropic added 'Brave Search' to the 'subprocessor list' in its documentation this week", and "Claude's web search function contains a parameter called 'BraveSearchParams.'" — [TechCrunch, March 21, 2025](https://techcrunch.com/2025/03/21/anthropic-appears-to-be-using-brave-to-power-web-searches-for-its-claude-chatbot/). This is dated (2025) and was not re-verified for 2026.
- No public reseller, white-label or syndication program was found. Brave's "Partner Program" is Brave Rewards (Web3 ads), not search syndication. Brave's docs FAQ contains no resale language. — [Brave FAQ (markdown)](https://api-dashboard.search.brave.com/documentation/resources/help-feedback/index.html.md)
- **AWS Marketplace route** — [listing](https://aws.amazon.com/marketplace/pp/prodview-qjlabherxghtq), [EULA PDF](https://d7umqicpi7263.cloudfront.net/eula/wEvEFt9W2OtNKvrYTQVLOYjV4YjQM155Cvp_VBl3eSg):
  - The listing sells one dimension, "Data for AI $5 CPM, 50 queries/second, unlimited queries/month".
  - Contract: the Standard Contract for AWS Marketplace (2023-11-07), with a Brave amendment for "[Brave Search API Pro]".
  - The Standard Contract allows use "in connection with Buyer's and its Affiliates' products and services (but, for clarity, not as a stand-alone product or service…)" (2.1.3). It forbids "sub-license, lease, distribute or attempt to grant other rights to any part of the Licensed Materials to third parties" (2.3(e)) and acting "as a consultant, service bureau or application service provider" (2.3(f)).
  - The Brave amendment forbids "store, archive or create a database of Search Results except to the extent permitted by the Product Listing" (7.1.1(e)).
  - The listing's "AI Insights" FAQ (an AWS-generated "aiPricingFaq") says "The Data for AI plan grants storage rights for retrieved results". That is AWS's AI-generated text, not Brave's. It conflicts with Brave's ToS and FAQ ("It is prohibited to retain any and all data received").

#### Self-hosting on Common Crawl
- License: "CC grants you a limited, non-assignable, non-transferable, non-sublicensable, non-exclusive, limited license to access and use the Service". "Crawled Content … may be subject to separate terms of use or terms of service from the owners of such Crawled Content." — [Common Crawl Terms of Use, last updated March 7, 2024](https://commoncrawl.org/terms-of-use)
- The prohibited-use list (2(a)–(m)) covers unlawful and abusive conduct, IP violations, and harvesting personal information "for use separately from the Crawled Content". It has no clause against commercial use of derived indexes. — [same](https://commoncrawl.org/terms-of-use)

### Inferences
- **Mojeek Business fits URnetwork's use best on paper.**
  - (a) Per-search charging at cost plus 20% is "commercial purposes, such as subscription services".
  - (b) Showing results in apps and to agents is "AI agents and assistants".
  - (c) Keeping a copy in the person's E2EE record is "retain Data indefinitely" on a storage-rights plan.
  - Two clauses need care:
    - 1.6(h)(3) "Do not use Data as part of any search index". If the E2EE record's encrypted search index (see `research_notes/Encrypted repo search index formats/`) indexes stored results, that could be read as a breach. Either exclude result text from the index or get Mojeek's written reading.
    - 1.4(d) on automated access. End-user harnesses must reach Mojeek only through URnetwork's relay, never with the key.
  - Wholesale resale is not addressed. URnetwork's model is a metered feature, not wholesale. An Enterprise variation (1.7) can settle it in writing.
- **Staan is the only provider that publicly answers "white label / sub-licensing" with "Yes".** That answer is in an FAQ, and the binding ToS is unseen. Storage, per-search pass-through and MCP exposure must be confirmed by reading the ToS at registration.
- **Kagi's terms fit URnetwork's in-app and agent use, but not the E2EE copy.**
  - In-app and agent use is explicitly fine ("sending Results to an AI model").
  - A copy in the E2EE record is "Store, cache, or build a database of Results beyond the transient caching".
  - A local gateway or MCP tool exposing a generic search endpoint to the person's own harnesses risks "proxy … raw Results as … substitute for direct Kagi API access".
  - Kagi explicitly offers written exceptions.
- **Microsoft Web IQ is technically in scope** (retrieval only; the customer runs the LLM). Its terms conflict with most of the intended use:
  - Results may only be shown alongside LLM output, capped at 200 characters per source.
  - Raw results may not be given to the person's own third-party harness ("outside of, the Application").
  - Only URnetwork's own LLM summaries, not results, may be kept per user.
  - Resale is barred.
  - The closest workable pattern is a TEE-run URnetwork LLM that summarizes. Only the summary and its links go into the E2EE record.
- **Yep's terms are permissive on storage** (nothing forbids it). But per-search resale needs Ahrefs' "express written consent" (11.7), and Ahrefs may train on queries (see section 3). So it needs negotiation on both resale and privacy.
- **Yandex is permissive by silence.** It allows "use on the Customer's product" and is silent on storage and resale. But the contract runs through non-Russian Yandex entities while the engine is operated by Russian Yandex LLC (see sections 6 and 8). That needs a sanctions and export review before any money flows.
- **Grounding with Google and with Bing are out of scope** because Google's or Microsoft's LLM writes the output. Their terms would also bar resale. Google's 2-year chat-history carve-out is the only big-company precedent for keeping results in a user's own history.
- **Brave**: Kagi's "Direct license" shows Brave does sign syndication deals off the public price list. The 2025 public storage-rights price was 5–9× the base CPM. A Brave Order Form covering (i) per-search pass-through billing, (ii) gateway/MCP delivery to users' own tools, and (iii) per-user E2EE storage is the like-for-like comparison to Mojeek's £3/1k Business plan.

### Gaps
- Staan's Terms of Service are not public ("provided upon registration"). Its storage, resale and display terms are unknown beyond the FAQ.
- Mojeek's ToS page shows no date or version. The DPA it incorporates is v3.0 of 5 Nov 2026.
- Web IQ's ToU shows no date. One third-party summary says access "is subject to Microsoft's review and approval". I did not find that sentence on Microsoft's own pages.
- Google's Web Search Service terms, pricing and partner criteria are unpublished. Its subpages returned 404.
- Marginalia publishes no terms beyond the key descriptions. Storage on the commercial key is not addressed.
- No Brave source lists its syndication partners or the terms of its direct licenses. The AWS listing's storage-rights statement is AI-generated and unreliable.
- Whether URnetwork could be a DOJ "Qualified Competitor" is not addressed by any source. The remedy targets general search competitors, and its templates had not started as of May 2026.

## 2. Price per 1,000 queries, rate limits and capacity

### Takeaway
The cheapest independent options cost $4/1k or less:
- Staan €2–4.
- Mojeek £2–3.
- Yep $4–8.
- Marginalia $4.
- Yandex about $4 daytime and $0.25 deferred.

Kagi ($12) and Web IQ ($7) cost more than Brave's $5. Capacity is the constraint:
- Mojeek Business allows 10 qps and 400k/day.
- Staan allows 20 QPS.
- Web IQ allows 15 QPS by default.
- Yep publishes 60 requests/minute per key.
- Marginalia allows 15 queries per minute.

### Cited Findings

| Source | Price per 1,000 | Rate limit / capacity | Free tier |
|---|---|---|---|
| Mojeek Startup | £2 (excl. VAT) | 5 qps; 100,000/day; up to 10 results | Free credit on signup |
| Mojeek Business (storage rights) | £3 | 10 qps; 400,000/day; up to 40 results | — |
| Mojeek Enterprise | "Let's talk" | "Custom"; "No Limit"; up to 100 results | — |
| Staan Web Search | €2 | "up to 20 QPS"; fixed 10 results per call | First 1,000/month |
| Staan Web Search for AI | €4 | up to 20 QPS | First 1,000/month |
| Staan Fetch (URL→Markdown) | €0.50 per 1,000 URLs | 2 QPS; 10 URLs per call | First 1,000 URLs |
| Kagi Search (v1) | $12 | "Rate limits and quotas apply per plan" (not published) | — |
| Kagi Extract | $4 per 1,000 pages | — | — |
| Kagi Enrichment (Teclis/TinyGem) | $2 (billed only when results are non-zero) | — | — |
| Yep Balanced / Advanced | $4 / $8; extra results $1 per 1,000 | 60 req/min, 3.6K/hour, 86.4K/day per key | 1,000 free requests / "$15 free credit" |
| Marginalia commercial | $4 after 25/day free; monthly charge capped at $500 | 15 queries per minute | 25/day |
| Yandex sync daytime / night | ≈$4.00 / ≈$3.00 | "Quotas and limits" page | — |
| Yandex deferred daytime / night | ≈$0.25 / ≈$0.21 | — | — |
| Yandex with generative response | ≈$41.64 (LLM) | — | — |
| Microsoft Web IQ /web, /news, /images, /video, /places | $7.00 | 15 QPS per AppID by default; raisable | — |
| Web IQ /browse | $1.00 | — | — |
| Web IQ /auto (advanced) | $8.00 ($9.00) | — | — |
| Grounding with Bing (LLM) | $14 per 1,000 transactions | 150 TPS; 1M/day | — |
| Google Grounding and Web Grounding for Enterprise (LLM), Gemini 3/4 | $14 per 1,000 Grounding Queries (each query billed, even within one prompt) | contact sales above 1M prompts/day | 5,000 queries/month, shared |
| Google Grounding (LLM), Gemini 2.x | $35 per 1,000 grounded prompts | 1M/day | 1,500–10,000/day |
| Web Grounding for Enterprise (LLM) | $45 per 1,000 Grounding Prompts (older models) | 1M/day | — |
| Google Custom Search JSON (existing customers only) | $5 | "up to 10k queries per day" | 100/day |
| Brave Search (baseline) | $5 | 50 req/s | $5 credit/month |

- **Mojeek**:
  - Prices and capacity — [Mojeek Search API page](https://www.mojeek.com/services/search/web-search-api/):
    - "Startup £2 per 1,000 requests – 5 Queries /sec – 100,000 Queries /day"
    - "Business £3 per 1,000 requests – 10 Queries /sec – 400,000 Queries /day"
    - Enterprise: "Let's talk … Custom … No Limit"
    - "Prices exclude indirect taxes such as VAT, sales tax, GST etc."
  - Custom plans: "Custom Search API plans for large-scale deployments include Zero Data Retention and enterprise-grade support including NDAs, invoicing and authority, keyword and semantic scores." — [same](https://www.mojeek.com/services/search/web-search-api/)
- **Staan**:
  - "€2/ 1,000 REQ · up to 20 QPS"; "€4/ 1,000 REQ · up to 20 QPS"; "€0.50/ 1,000 URLs · up to 2 QPS". "The first 1,000 requests are free every month." — [staan.ai machine view](https://staan.ai/?view=machine)
  - "Each call returns 10 documents." "Can I cap my monthly usage to stay within a certain budget? This option is not currently available." "We do not offer an SLA at this stage." Fetch is "post-paid". — [Staan FAQ](https://staan.ai/faq)
- **Kagi**:
  - "Search … $12 /1k requests"; "Extract … $4 /1k pages"; "Enterprise … Volume discounts – Custom rate limits – Enterprise-grade support and SLAs". "We will invoice every 30 days or as soon as your usage reaches $100." — [Kagi API pricing](https://kagi.com/api/pricing)
  - "All /enrich APIs are currently billed at $2/1000 searches ($0.002 USD per search)… we bill only when non-zero results are returned." — [Kagi Enrichment docs](https://help.kagi.com/kagi/api/enrich.html)
  - "Rate limits and quotas apply per plan and may be adjusted to protect service quality." — [Kagi API ToS](https://kagi.com/privacy/api)
- **Yep**:
  - "Two pay-as-you-go tiers: Balanced at $4 per 1,000 requests, and Advanced at $8 per 1,000 for higher quality results. Both include up to 20 results per request; each additional result costs $1 per 1,000, only returned results are charged". "60 Requests / minute per key · 3.6 K Requests / hour per key · 86.4 K Requests / day per key · Standard limits on every plan. Need more throughput? Enterprise options". "Team-ready key management: Programmatically provision, cap, disable, and revoke API keys, with per-key rate limits". — [ahrefs.com/yep](https://ahrefs.com/yep)
  - "Price $0.004 per request Balanced, from 1 to 50 results"; "$15 free credit on signup. No card required." — [platform.yep.com](https://platform.yep.com/)
  - Conflicts: the platform page says "from 1 to 50 results", while the product FAQ says "up to 20 results". A search-engine summary of Yep's docs claimed "6,000 requests per minute per API key". The docs page (platform.yep.com/api-documentation) returned 404, so this could not be checked.
- **Marginalia**:
  - "Metered Commercial API Access. 15 QPM Rate Limit, 25 queries per day free, $4 per 1000 queries after that. Monthly charge is capped at $500.00." — [Polar checkout, commercial license](https://buy.polar.sh/polar_cl_hKnbSGWkflTozpXajwIu2ycB2fYmLM8jDxsuh06Kvmt)
  - Non-commercial: "1000 Queries / Day, Hard Limit", pay-what-you-want with "$10 minimum". — [Polar checkout, non-commercial](https://buy.polar.sh/polar_cl_B7026PKyFKrH5f0F1O6tcN6foD0ivufh1wX6l4fUeVV)
  - The shared `public` key "often hits a rate limit". — [Marginalia API page](https://about.marginalia-search.com/article/api/)
- **Yandex** (via WebFetch; curl was CAPTCHA-blocked) — [Yandex Search API pricing](https://aistudio.yandex.ru/docs/en/search-api/pricing.html):
  - USD per 1,000 excl. VAT: daytime synchronous "$3.99999936"; daytime deferred "$0.24999996"; night-time synchronous "$2.99999952"; night-time deferred "$0.2082786552"; image search "$7.4999988"; "Smart snippets for RU search" "$12.29508"; "Synchronous with generative response" "$41.6393376".
  - Reduced night rates apply "from 00:00:00 to 07:59:59 UTC+3"; errors are not billed.
- **Microsoft**:
  - Web IQ prices per 1K calls: /web $7.00, /browse $1.00, /video $7.00, /news $7.00, /images $7.00, /auto $8.00, /auto advanced $9.00, /places $7.00, Commerce $7.00 (private preview). "* Auto and Auto Advanced are charged from November 17, 2026." — [Web IQ pricing, updated 2026-11-16](https://learn.microsoft.com/en-us/web-iq/resources/pricing)
  - "Each Web IQ AppID has a default limit of 15 queries per second (QPS)… To request a higher limit, open a Web IQ Support request". "You can create as many API keys as you need… all keys for one AppID share its rate limit." — [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq)
  - "Grounding with Bing Search | 150 transactions per second | $14 per 1,000 transactions … 1 Million transactions per day" (Custom Search is the same). — [Grounding with Bing pricing](https://www.microsoft.com/en-us/bing/apis/grounding-pricing)
- **Google**:
  - Gemini 3/4: "Grounding Queries exceeding those limits are billed at $14 per 1,000 Grounding Queries", with "5,000 Grounding Queries per month at no charge".
  - Older models: "Grounding with Google Search | $35 per 1,000 Grounding Prompts"; "Web Grounding for enterprise | $45 per 1,000 Grounding Prompts. Please contact your account team if you require more than 1 million Grounding Prompts per day."
  - Source: [Vertex AI (Model Garden) pricing](https://cloud.google.com/vertex-ai/generative-ai/pricing)
  - Custom Search JSON API: "Additional requests cost $5 per 1000 queries, up to 10k queries per day" (existing customers only). — [CSE overview](https://developers.google.com/custom-search/v1/overview)
- **Self-hosting scale and cost anchors**:
  - The October 2026 Common Crawl "contains 2.16 billion web pages (or 371.19 TiB of uncompressed content)", crawled October 5th–18th. — [Common Crawl blog, Oct 21, 2026](https://commoncrawl.org/blog/october-2026-crawl-archive-now-available)
  - "Crawl data is free to access by anyone from anywhere. The data is hosted by Amazon Web Services' Open Data Sets Sponsorships program on the bucket s3://commoncrawl/, located in the US-East-1 (Northern Virginia) AWS Region." — [Common Crawl Get Started](https://commoncrawl.org/get-started)
  - "EUSP CEO Wolfgang Oels estimates the cost of a European search engine at around 50 million euros". OpenWebSearch.eu has "8.5 million euros in Horizon Europe funding. However, its funding is about to expire." — [heise, 2026-03-12](https://www.heise.de/en/news/Search-engine-initiative-aims-to-build-EU-search-11208524.html)
  - "Microsoft spent roughly $100 billion over 20 years on Bing and still holds single-digit share." — [Kagi blog, 2026-01-21](https://blog.kagi.com/waiting-dawn-search)

### Inferences
- **Markup.** At cost plus 20%, users would pay about £2.40–3.60 per 1,000 on Mojeek, €2.40–4.80 on Staan, $4.80–9.60 on Yep and $14.40 on Kagi. Mojeek and Staan bill in GBP and EUR, so URnetwork (paying USD) carries FX risk. The relay's per-search price must float or carry a buffer.
- **Mojeek capacity.** Business at 10 qps sustained is about 864k/day, but the plan caps at 400k/day (about 12M/month). Larger volume means Enterprise.
- **Staan capacity.** 20 QPS with no budget cap and no SLA. The relay must do its own spend capping.
- **Marginalia capacity.** 15 queries/minute is at most about 648k queries a month even at full rate. That suits it as a niche "small web" supplement, not a primary source. The $500 cap is reached at 125k billed queries.
- **Yep limits are per key.** If Ahrefs permits many keys per account, which the docs suggest but do not confirm for scaling, aggregate throughput could exceed 60/min. Confirm with Ahrefs before relying on it.
- **Self-hosting is a different order of cost.** Even with free access to Common Crawl's 371 TiB monthly snapshots, the published cost anchors (EUSP's €50M estimate, OWS's €8.5M) are 4–5 orders of magnitude above the API spend for a startup's search tool. Stract's archival in April 2026 (section 8) is a warning sign.

### Gaps
- Kagi's per-plan rate limits are not published.
- Yandex's quotas page and its USD payment flow could not be read (CAPTCHA).
- Brave's storage-rights and syndication prices for 2026 are not public.
- Staan custom-plan pricing and higher QPS are "Contact us".
- I found no sourced estimate of what it costs to index and serve Common Crawl as a search engine, beyond the organization-level anchors above.

## 3. Data handling: query logging and retention, zero-data-retention options, DPA

### Takeaway
Mojeek has the strongest written data terms:
- A DPA as processor that is part of the ToS.
- 90-day fault logs that are "not copied into … model-training systems".
- An optional ZDR held in volatile memory only.
- No sub-processors touching queries.
- It never receives end-user IPs.

Staan (OVH France, query obfuscation on request, DPA on request) also looks good, but sends some queries to an unnamed US "fallback" provider. The weak points:
- Kagi logs temporarily and its DPA is "finishing".
- Yep's ToS lets Ahrefs train its models on customer queries.
- Microsoft (Web IQ and Grounding with Bing) excludes its DPA and acts as an independent controller. Web IQ offers "Zero Query Logging" only on request.
- Google grounding keeps logs for 3–30 days, except Web Grounding for Enterprise, which keeps none.

### Cited Findings
- **Mojeek** — [Mojeek Search API DPA, "Version: 3.0 (5th November 2026)"](https://www.mojeek.com/about/legal/data-processing-agreement.html):
  - "Mojeek does not receive or record End User IP addresses or End User identifiers, and it cannot identify the End User who originated a Search Query."
  - Standard retention: "Mojeek retains Query Data for up to 90 (ninety) days solely to diagnose and fix faults and to verify the correct operation of the Search API." "Retained Query Data consists of the query string, request parameters, timestamp and the API key used to submit the request." "It is not copied into analytics, customer-support, backup or model-training systems." "Retained Query Data is deleted automatically at the end of the retention period."
  - ZDR: "Zero Data Retention is an optional setting available on specific plans… Query Data is held only in volatile memory for as long as it takes to execute the Search Query and return the Search Results. It is then discarded, and it is not written to any log or persistent storage."
  - Sub-processors: "At the date of this DPA, no Sub-processor has access to, or Processes, Query Data." Mojeek gives "at least 30 days' written notice of any intended addition or replacement of a Sub-processor".
  - ToS: "The Mojeek Search API Data Processing Agreement (the "DPA") forms part of this Agreement and applies automatically when you accept these Terms." Mojeek acts as processor "under the UK GDPR and, where it applies, the EU GDPR". — [Mojeek API ToS](https://www.mojeek.com/about/legal/api-terms.html)
  - Marketing: "Standard 90-day data retention with ZDR available on request." "Zero Sub-Processors: End-to-end European infrastructure powering every search result." — [Mojeek Search API page](https://www.mojeek.com/services/search/web-search-api/)
- **Staan** — [Staan Privacy Policy, November 2026](https://staan.ai/privacy-policy) and [FAQ](https://staan.ai/faq):
  - Privacy Policy: "European Perspective considers that requests sent to the Staan search API do not constitute personal data within the meaning of the GDPR… European Perspective does not collect any identifier or data allowing a request to be linked to a person or their devices."
  - Sub-processors: "OVH FRANCE … Query logs, Customer account" (France). Notion and Slack (US) process support and account data only.
  - Fallback: "To supplement certain results where necessary, we may rely, on a subsidiary basis, on a fallback solution provided by a US-based service provider… The data transmitted to this provider are search queries. These queries are not retained by the provider, which does not reuse them for its own purposes."
  - FAQ: "Your data is used solely to better understand usage patterns and improve the quality of our services. It is never shared with third parties for commercial purposes, nor used to train a language model (LLM). If you wish, you can also ask us to obfuscate all of your queries." "Staan is not SecNumCloud-qualified and holds no certification at this time."
  - No retention period is stated for API query logs.
- **Kagi** — [Kagi API ToS](https://kagi.com/privacy/api):
  - "We don't tie your queries to your account beyond metering usage for billing, we don't sell data, and we don't build profiles. Queries may be logged temporarily, separated from your account, for debugging and abuse prevention, then purged".
  - "We're finishing a Data Processing Addendum… If you need signed processing terms before then, email support@kagi.com."
  - Sensitive data: "don't send sensitive personal data (health, payment, government ID, biometrics, children's data, precise location)."
  - Proxying claim: "Every query is proxied through Kagi, so upstream sources never see you or your users." — [kagi.com/products/api](https://kagi.com/products/api)
- **Yep**:
  - ToS: "You agree that we may use User Content for our business and/or operating purposes … including to compile, develop and publish usage and performance information, train our machine learning models and operate, improve, develop, support and evolve Yep Services." (12.3) "User Content" includes "search terms, prompts". The customer also grants Ahrefs a "perpetual, irrevocable" license to User Content (11.5). — [Yep ToS](https://platform.yep.com/legal/terms-of-service/)
  - Privacy Policy: "We may retain your historical data (queries, usage patterns, preferences) to enable future features you may choose to activate". — [Yep Privacy Policy](https://platform.yep.com/legal/privacy-policy/)
  - The legal hub lists a "Data Processing Addendum" and a "Sub-Processors List". — [Yep legal](https://platform.yep.com/legal/terms-of-service/)
- **Microsoft Web IQ** — [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq) and [Web IQ ToU §4](https://www.microsoft.com/en-us/webiq/webiq-legal):
  - Logging: "API requests are logged for operational purposes: service reliability, debugging, and quality improvement." "There is no separate Web IQ-specific retention commitment beyond what the Privacy Statement describes."
  - Zero Query Logging: "Web IQ offers Zero Query Logging, which suppresses query text from telemetry… It isn't self-serve… With Zero Query Logging, the query text, result titles and URLs, the IP address and the Entra application ID aren't kept."
  - Residency: "Web IQ doesn't make region-specific data residency or in-region processing commitments".
  - DPA and controller roles: "Customer acknowledges and agrees that the Services are excluded from the Microsoft Products and Services Data Protection Addendum" (ToU 4.1). Both parties are "independent data controllers" (4.4).
- **Grounding with Bing** — [direct TOU](https://www.microsoft.com/en-us/bing/apis/grounding-legal) and [Foundry web overview](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/web-overview):
  - "Microsoft may collect information from you or End Users such as … an End User's IP address, requests, time of submissions and the results returned". "You acknowledge and agree that the Services are excluded from the Microsoft Products and Services Data Protection Addendum."
  - "When you use these services, your data flows outside the Azure compliance and Geo boundary."
- **Google**:
  - Gemini API: Google "will store prompts, contextual information that you may provide, and output for thirty (30) days for the purposes of creating Grounded Results and Search Suggestions". — [Gemini API terms](https://ai.google.dev/gemini-api/terms)
  - Google Cloud (Vertex) grounding logs queries "for up to three (3) days". — [Service Specific Terms §20(k)(ii)](https://cloud.google.com/terms/service-terms)
  - Web Grounding for Enterprise: "The service doesn't log customer data and supports VPC service controls." — [Web Grounding for Enterprise docs, updated 2026-11-20](https://cloud.google.com/vertex-ai/generative-ai/docs/grounding/web-grounding-enterprise)
- **Brave (baseline)**: 90-day query logs, ZDR for Enterprise, and query data excluded from its DPA. — baseline section 5, [Brave Privacy Notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice)
- **Brave via AWS Marketplace**: "all search query data … is System Data, and is neither Personal Data nor Buyer Data; and (ii) Licensor shall be entitled to collect, store, retain, process and use Search Query Data as System Data". — [AWS EULA amendment 7.2.5](https://d7umqicpi7263.cloudfront.net/eula/wEvEFt9W2OtNKvrYTQVLOYjV4YjQM155Cvp_VBl3eSg)

### Inferences
- **Mojeek's DPA has the cleanest privacy story** for an E2EE product. ZDR (on "specific plans", i.e. custom or Enterprise) removes even the 90-day fault log. The default log keeps the API key but no end-user data. Its UK/EU processing avoids the US CLOUD Act question that Brave, Kagi, Yep and Microsoft raise.
- **Staan's US fallback** means some queries leave the EU to an unnamed US provider. URnetwork cannot control when. Ask which provider it is and whether it can be disabled.
- **Yep's default terms conflict with URnetwork's privacy posture.** Ahrefs may train on queries and keep "historical data (queries…)". A negotiated DPA or amendment would be needed.
- **Web IQ's Zero Query Logging is better than Brave's self-serve default.** But the lack of a DPA and its independent-controller status put URnetwork's privacy notice in the same position as with Brave: disclose Microsoft as a recipient that acts as controller.

### Gaps
- I could not read Mojeek's Annex 3 (sub-processors) or which plans include ZDR beyond "Custom Search API plans" and "on request".
- I could not read the Staan DPA (on request only), the identity of its US fallback provider, or its API query-log retention period.
- Yep's DPA and sub-processor list pages were not read.
- I found no data-handling terms for Marginalia's or Yandex's search APIs.

## 4. Index: own or someone else's, size and freshness, and quality evidence

### Takeaway
Own crawler indexes:
- Mojeek (9B+ pages).
- Yep/Ahrefs (claims 100B+ pages, 8B recrawled daily).
- EUSP/Staan (FR/DE/EN only, with a US fallback).
- Marginalia (small web).
- Yandex.
- Brave.
- Microsoft (Bing, behind Web IQ and Grounding).
- Google.

Kagi is a meta-engine: its own small-web indexes plus 12 sources, including direct licenses with Brave, Mojeek and Yandex and third-party SERP scrapers for Google-like results. The only independent cross-provider benchmark found, the Artificial Analysis Search Index of Nov 19, 2026, scores Brave (LLM context) at 75. It shows no score for Mojeek, Kagi, Yep, Web IQ or Staan, so their quality is vendor-claimed only.

### Cited Findings
- **Mojeek**:
  - "From a personal project to indexing over nine billion pages". The milestone list includes "Mojeek passes 9 billion pages". — [Mojeek About](https://www.mojeek.com/about/)
  - "Independent Index: Global index with billions of fresh webpages." "Trusted Crawler: Established MojeekBot which respects Robots Exclusion Protocol." — [Mojeek Search API page](https://www.mojeek.com/services/search/web-search-api/)
  - Data returned: "publicly available URLs, page titles and query dependent snippets". — [API ToS 1.6(g)](https://www.mojeek.com/about/legal/api-terms.html)
- **EUSP / Staan**:
  - Launch: "As of today, the service is transmitting the first search results from its European search index to Ecosia users. Initially, users in France will receive some of their search results directly from the specially developed index." Until then Ecosia "used a mix of indices from the tech companies Google and Microsoft (Bing)". — [heise, 2025-08-07](https://www.heise.de/en/news/Ecosia-and-Qwant-launch-web-search-via-European-index-10513567.html)
  - March 2026: "Currently, Staan is limited to French content." — [heise, 2026-03-12](https://www.heise.de/en/news/Search-engine-initiative-aims-to-build-EU-search-11208524.html)
  - November 2026 languages: "For now, we are focusing our efforts on these three languages [French, German and English]". English codes "en-US, en-GB, en-FR, en-CA, en-AU, en-IN, en-IE, en-NZ, en-ZA and en-SG". — [Staan FAQ](https://staan.ai/faq)
  - Stack: "on the same stack as Qwant Search"; "< 800 ms p95 latency for search" (vendor claim). — [staan.ai](https://staan.ai/)
- **Kagi**:
  - Sourcing: "We succeeded with many, including: Mojeek Direct license, Brave Direct license, Yandex Direct license, Wikipedia Direct license, TripAdvisor … Yelp … Apple … Wolfram Alpha … Our own Small Web Index Proprietary". On Google and Bing: "Because direct licensing isn't available to us on compatible terms, we - like many others - use third-party API providers for SERP-style results… This is not our preferred solution." — [Kagi blog, 2026-01-21](https://blog.kagi.com/waiting-dawn-search)
  - Fan-out: "Each query fans out to 12 sources in parallel, proxied through Kagi. We merge the results and rank them in one pass". Kagi's own benchmark claim: tested "7 search APIs on 8 public benchmarks". — [kagi.com/products/api](https://kagi.com/products/api)
  - Own indexes: "sourced from our own web index (internally named 'Teclis') and news index (internally named 'TinyGem')… anonymized API calls to all major search result providers worldwide, specialized search engines like Marginalia". — [Kagi search sources](https://help.kagi.com/kagi/search-details/search-sources.html)
- **Yep**:
  - "One API call plugs your product into a 100B+ page index that powers Ahrefs." "Crawler, index, and ranking are all operated by Ahrefs. No second-hand data". "8 billion pages recrawled daily". — [ahrefs.com/yep](https://ahrefs.com/yep)
  - Caveat from Ahrefs itself: "Published, rounded figures. The crawl counts everything AhrefsBot fetches, not pages added to the index." — [platform.yep.com](https://platform.yep.com/)
- **Marginalia**: Kagi describes it as a "specialized search engine". The API returns url/title/description and a `license` field. — [Kagi search sources](https://help.kagi.com/kagi/search-details/search-sources.html), [Marginalia API](https://about.marginalia-search.com/article/api/). Marginalia's index size was not found.
- **Yandex**: the service queries "the search engine of the Limited Liability Company 'YANDEX'". — [Yandex Search API ToU 1.1](https://yandex.com/legal/cloud_terms_search_api/en/)
- **Microsoft**:
  - "It's the same index Microsoft's own AI products depend on." "Web IQ powers leading frontier AI assistants, including Microsoft Copilot and ChatGPT."
  - Benchmark claim: P95 latency "about 2 times faster than the next-fastest service tested". Microsoft's benchmark used "2,850 randomly sampled global queries, evaluated November 8–9, 2026" (vendor benchmark).
  - Exclusions: "LinkedIn results are currently excluded."
  - Source: [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq)
- **Google Web Grounding for Enterprise**: "The indexed content is a subset of what's available on Google Search… fast-changing content is updated every 6 hours, and the whole index is updated every 24 hours." — [Web Grounding for Enterprise docs](https://cloud.google.com/vertex-ai/generative-ai/docs/grounding/web-grounding-enterprise)
- **Independent benchmark**: the Artificial Analysis Search Index (latest data Nov 19, 2026) scores:
  - Parallel Search (advanced) 83
  - Exa (auto) 80
  - Perplexity Search (medium) 80
  - Brave Search (LLM context) 75
  - OpenAI Web Search 74
  - "model only" baseline 33

  Kagi, Mojeek, Yep, Web IQ, Google and Staan did not appear in the visible view. The page says it covers 26 products across 14 providers. — [Artificial Analysis Search Index](https://artificialanalysis.ai/agents/search-api) (read via WebFetch; JavaScript page)
- **Common Crawl**: the October 2026 crawl has "2.16 billion web pages… from 41.4 million hosts or 34.3 million registered domains and include 830.1 million new URLs". It was crawled over two weeks (Oct 5–18). — [Common Crawl blog](https://commoncrawl.org/blog/october-2026-crawl-archive-now-available)

### Inferences
- **Kagi's API inherits third-party SERP scrapers.** Kagi's results include "SERP-style results" from third-party scraper APIs. Its "Direct license" sources (Brave, Mojeek, Yandex) are themselves alternatives URnetwork can license directly. Reselling Kagi means reselling a blend that partly depends on providers Google is suing (section 8).
- **Mojeek's index is far smaller than Bing, Google or Yep's claim.** That affects long-tail recall. There is no independent quality score for it. A practical design is Mojeek (storage-rights primary) plus a second source for coverage, as Mojeek explicitly allows (1.6(c)).
- **Staan's coverage may lean on the fallback.** Staan's jump from "limited to French content" (March 2026) to FR/DE/EN markets (Nov 2026) may lean on the US fallback provider for non-French queries. That is unconfirmed.
- **Common Crawl is not a search index.** It is a monthly sample (about 2.2B pages, 2-week crawl windows). A self-built index would trail live indexes on freshness unless URnetwork also crawls.

### Gaps
- No independent quality benchmark covers Mojeek, Staan, Kagi's API, Yep, Marginalia, Yandex or Web IQ.
- Marginalia's index size and Staan's index size were not found.
- Brave's index size was not re-checked here (see the baseline).

## 5. Which endpoints generate text with an LLM, and which are pure retrieval

### Takeaway
Pure retrieval, in scope:
- Mojeek search.
- Staan Web Search, Web Search for AI and Fetch.
- Kagi Search, Extract and Enrichment.
- Yep search ("highlights" are excerpts).
- Marginalia.
- Yandex synchronous and deferred search.
- Every Microsoft Web IQ endpoint: "Web IQ is not an AI model or LLM".
- Google's partner-only Web Search Service.

LLM-generated, out of scope:
- Grounding with Google Search, Web Grounding for Enterprise, Grounding with Bing (Output "processed and summarized using an LLM").
- Kagi FastGPT and Summarizer.
- Yandex "generative response".
- Brave Answers and Summarizer.

### Cited Findings
- **Mojeek**: results are "URL, page title and query dependent snippets". — [Mojeek API FAQ](https://www.mojeek.com/services/search/web-search-api/)
- **Staan**:
  - "Web Search for AI — Structured JSON — You run the LLM".
  - Its pipeline is "fetch → extraction → reranking". — [Staan FAQ](https://staan.ai/faq)
  - Fetch "turns any URL into clean, LLM-ready Markdown". — [staan.ai](https://staan.ai/)
- **Kagi** — [Kagi API overview](https://help.kagi.com/kagi/api/overview.html):
  - Products: "Enrichment API: Kagi's own Teclis (web) and TinyGem (news) indexes"; "Universal Summarizer API: Summarize any content in any format"; "FastGPT API: LLM-powered answers with live web search".
  - "The summarizer endpoint is not yet available in v1."
- **Yep**: "Get query-relevant text highlights from page content alongside the title, URL, and description". — [ahrefs.com/yep](https://ahrefs.com/yep). However, the ToS says Content may include data from "third-party large language models" (5.1). — [Yep ToS](https://platform.yep.com/legal/terms-of-service/)
- **Yandex**:
  - Clause 1.2 functionality provides "advanced search results consisting of meaningful fragments of the found pages". — [Yandex ToU](https://yandex.com/legal/cloud_terms_search_api/en/)
  - Pricing lists "Synchronous with generative response" separately. — [Yandex pricing](https://aistudio.yandex.ru/docs/en/search-api/pricing.html)
- **Web IQ**: "Is Web IQ an LLM? Does it generate the final answer? No… Web IQ doesn't generate the final AI answer. It retrieves relevant information from the web, and your chosen LLM, AI agent, or application logic uses that evidence to generate a response." `/auto` "Picks the sources for a question and returns cited evidence in one call". — [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq), [pricing](https://learn.microsoft.com/en-us/web-iq/resources/pricing)
- **Grounding with Bing**: Services include "Output after being processed and summarized using an LLM". — [Grounding with Bing TOU 1(h)](https://www.microsoft.com/en-us/bing/apis/grounding-legal)
- **Google**: "'Grounded Results' mean responses that Google generates using the prompt from the end user… and results from Google's search engine." — [Gemini API terms](https://ai.google.dev/gemini-api/terms)

### Inferences
- **Microsoft Web IQ is the only big-company option compatible with the TEE-only inference rule**, because it returns evidence and URnetwork's TEE model writes the answer. Section 1's terms still sharply limit display and storage.
- **Yep's highlights may involve an LLM.** Its ToS mention of "third-party large language models" leaves open whether highlights are LLM-generated. Ask Ahrefs before treating Yep as pure retrieval.
- **Yandex "smart snippets"** ($12.30/1k, RU only) are listed apart from "generative response". Whether they are extractive or model-generated is not stated.

### Gaps
- No documentation states whether Yep highlights, Kagi Search v1 snippets or Web IQ /auto "evidence" use model-generated text rather than extracted passages.

## 6. Payment methods

### Takeaway
Card through Stripe:
- Mojeek (bank card, PAYG deposits, invoicing on Enterprise).
- Yep (card, prepaid).
- Brave (card, AWS Marketplace, or x402 USDC).

Other routes:
- Kagi bills pay-per-use in USD, invoiced at $100 or monthly, with a "payment method on file".
- Marginalia sells through Polar.
- Staan has no card payments yet ("on our roadmap") and bills in EUR.
- Microsoft (Web IQ, Grounding with Bing) and Google bill through Azure or Google Cloud.
- Yandex sells in USD only through a Serbian or a Dubai entity.

### Cited Findings
- **Mojeek**:
  - "Our PAYG plans do not process automatic payments and you can set alerts on your account to control your budget. Payments are processed by Stripe Payments Europe Ltd and you can cancel anytime. Invoicing is available on Enterprise Plans." "A bank card is required to open an account however no automatic payments are processed". — [Mojeek API FAQ](https://www.mojeek.com/services/search/web-search-api/)
  - ToS: "All deposits are non-refundable." "We may, at our sole discretion, extend, revise or revoke credit at any time." VAT number GB125810533. — [Mojeek API ToS §2](https://www.mojeek.com/about/legal/api-terms.html)
- **Staan**: "When will the console support credit card payments? Credit card payment is on our roadmap." Fetch is "post-paid". — [Staan FAQ](https://staan.ai/faq). Billing data includes "Billing address, billing contact, payment method". — [Staan Privacy Policy](https://staan.ai/privacy-policy)
- **Kagi**:
  - "The API uses a pay-per-use model. You are invoiced when your usage reaches $100 (or your custom limit) or at the end of each monthly billing cycle". The portal has "Pre-Paid API Credit" and "Set Usage Limit: Set a spending cap in USD". — [Kagi API overview](https://help.kagi.com/kagi/api/overview.html)
  - "Prices are in US dollars, excluding taxes." — [Kagi API ToS](https://kagi.com/privacy/api)
- **Yep**:
  - "You agree to our use of Stripe…". "By submitting payment information such as your credit card details". — [Yep ToS 12.2](https://platform.yep.com/legal/terms-of-service/)
  - "Billing Prepaid Limits you set, no overage". — [platform.yep.com](https://platform.yep.com/)
  - Conflict: the ToS also says plans are "billed upfront monthly or annually" (7.2) with "recurring periodic charges" (7.4), while the product page says "no subscription or monthly minimum".
- **Marginalia**: subscriptions are managed at "polar.sh/marginalia-search/portal". The commercial product is a monthly metered subscription (Polar). — [Marginalia API](https://about.marginalia-search.com/article/api/), [Polar checkout](https://buy.polar.sh/polar_cl_hKnbSGWkflTozpXajwIu2ycB2fYmLM8jDxsuh06Kvmt)
- **Yandex** (via WebFetch): "Prices in US dollars are applicable to customers of Iron Hive doo Beograd (Serbia)". USD pricing also applies to Direct Cursus Technology L.L.C. (Dubai). "Prices in Russian roubles are applicable to customers of Yandex.Cloud LLC." — [Yandex pricing](https://aistudio.yandex.ru/docs/en/search-api/pricing.html)
- **Microsoft**: "Web IQ requires a paid Azure subscription, including subscriptions bought through a Cloud Solution Provider (CSP) partner. Visual Studio, free trial and student subscriptions and Azure credits don't work for Web IQ." — [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq)
- **Google**: "Billing and payments for Paid Services are handled by Cloud Billing". — [Gemini API terms](https://ai.google.dev/gemini-api/terms)
- **Brave**: Stripe card, AWS Marketplace, and x402 (USDC on Base). — baseline section 3

### Inferences
- All options can be paid in USD except Mojeek (GBP), Staan (EUR) and Yandex (USD, but to Serbian or Emirati entities).
- Staan currently implies invoice or bank transfer. That needs an account-team setup, not self-serve card billing.

### Gaps
- I did not find the accepted payment instruments for Staan (beyond "no card yet") or for Yandex's USD entities (card versus wire).
- Kagi's accepted card or ACH types were not found.

## 7. Attribution and display requirements

### Takeaway
No attribution is required by:
- Mojeek ("without attribution to Mojeek").
- Marginalia (commercial key).
- Yandex.
- Kagi.
- Brave (optional "POWERED BY BRAVE").

Yep requires keeping authors' and owners' notices intact. Yandex forbids reordering. The big companies impose heavy display rules:
- Web IQ: citations near LLM text, 200 characters per source, no Microsoft branding, no non-Microsoft ads.
- Grounding with Bing: References in "exact form", a Bing SERP link, a Microsoft Privacy Statement link, no third-party ads.
- Google grounding: Search Suggestions shown, no modification, Client Application Guidelines.

### Cited Findings
- **Mojeek**:
  - "You may use Data for commercial purposes… without attribution to Mojeek" (1.6(d)).
  - "Do not present information that was not included in the Data as if it were part of the Data" (1.6(h)(2)).
  - "Data provided is subject to our content policy" (1.10).
  - Source: [Mojeek API ToS](https://www.mojeek.com/about/legal/api-terms.html)
- **Marginalia**: commercial key has "no commercial usage restriction or attribution requirement". Non-commercial keys are "Provided under CC-BY-NC-SA 4.0" (which requires attribution and share-alike). — [Marginalia API](https://about.marginalia-search.com/article/api/)
- **Yandex**: "The placement of search results is allowed in any design (design), but without alteration of results order." — [Yandex ToU 3.2](https://yandex.com/legal/cloud_terms_search_api/en/)
- **Kagi**: "These Terms grant you no rights in Kagi's trademarks, logos, or brand features." There is no attribution clause. — [Kagi API ToS](https://kagi.com/privacy/api)
- **Yep** — [Yep ToS](https://platform.yep.com/legal/terms-of-service/):
  - The customer must not engage in "misrepresenting the ownership or source of Content, such as obscuring, removing, changing or falsifying any trademark, copyright, author attributions or other proprietary notice" (11.7).
  - "You agree to attribute such proprietary rights in any publication or distribution, where applicable." (11.2)
  - Ahrefs may use the customer's "company name and logo on our website" (11.6), with an opt-out by email.
- **Web IQ** — [Web IQ ToU Exhibit A](https://www.microsoft.com/en-us/webiq/webiq-legal):
  - "When using Grounding Content for Grounding an LLM, Customer will provide source attribution and a link back to each source… The source attribution must be near the displayed LLM content".
  - "Customer will not display advertising that is not provided by Microsoft in proximity to the display of any Response".
  - "Customer will not provide attribution to Microsoft unless Microsoft specifies otherwise in writing."
  - FAQ: "Cite only the sources actually used to generate the answer." — [Web IQ FAQ](https://learn.microsoft.com/en-us/web-iq/resources/faq)
- **Grounding with Bing** — [Grounding with Bing TOU](https://www.microsoft.com/en-us/bing/apis/grounding-legal):
  - "You must retain and display the References in the exact form provided by Microsoft." "You must display the Resources near the displayed Output".
  - "You must prominently include a functional hyperlink to the Microsoft Privacy Statement in your Application End User terms of use. Label the hyperlink Microsoft Privacy Statement." (6(a))
  - "Display advertising that is not provided by Microsoft" is prohibited.
- **Google**: display Grounded Results "with the associated Search Suggestion(s)". "The Client Application Guidelines apply to your use of Grounding with Google Search." — [Gemini API terms](https://ai.google.dev/gemini-api/terms). On Google Cloud, Search Suggestions may be omitted "subject to the conditions set forth on the Pricing page". — [Service Specific Terms](https://cloud.google.com/terms/service-terms)
- **Staan**: no attribution requirement is published. Results are "linked back to its origin". — [staan.ai](https://staan.ai/)

### Inferences
- Mojeek, Marginalia (commercial), Yandex and Kagi impose no attribution UI. Results can be shown as plain URnetwork results in apps, agents and MCP tools. Yandex's "without alteration of results order" rules out re-ranking Yandex results, so they cannot be blended with other sources.
- Web IQ's 200-character cap and "same user interface as content from an LLM" rule out a classic search-results page in URnetwork's apps built on Web IQ.

### Gaps
- Staan's display obligations are in its unpublished ToS.

## 8. Continuity: company state and announced shutdowns or changes in 2025–2026

### Takeaway
2025–2026 changes and risks:
- Microsoft killed the Bing Search APIs (Aug 11, 2025), steering users to LLM-summarized Grounding with Bing. In October 2026 it launched Web IQ (GA), a Bing-index retrieval API.
- Google closed Custom Search to new customers and ends it Jan 1, 2027. Its full-web API is partner-only, and the DOJ syndication remedy had not started as of May 2026.
- Stract is dead (archived Apr 2, 2026).
- Yep calls itself "WHOLLY BETA".
- Kagi depends partly on SERP scrapers that Google is suing.
- Staan is young: no SLA, no certification, language-limited.
- Mojeek is a small, long-running UK independent that updated its DPA in Nov 2026. Its ToS lets either side end it "immediately".

### Cited Findings
- **Mojeek**: "Proudly providing independent search without tracking for over 15 years". Milestones include "Mojeek secures further funding to expand its team". — [Mojeek About](https://www.mojeek.com/about/). The DPA was revised to "Version: 3.0 (5th November 2026)" — [Mojeek DPA](https://www.mojeek.com/about/legal/data-processing-agreement.html). Termination: "Either party may terminate these Terms at any time, immediately, on notice". — [Mojeek API ToS 8.2](https://www.mojeek.com/about/legal/api-terms.html)
- **EUSP / Staan**:
  - On 2026-03-12, EUSP "sent open letters to the heads of government of all 27 EU member states" proposing national search indexes. It has been "operating its European search index under the name Staan … since August 2025". — [heise, 2026-03-12](https://www.heise.de/en/news/Search-engine-initiative-aims-to-build-EU-search-11208524.html)
  - "We do not offer an SLA at this stage." "Staan is not SecNumCloud-qualified and holds no certification at this time." — [Staan FAQ](https://staan.ai/faq)
- **Kagi**:
  - "In December 2025, Google sued SerpApi for scraping its results at scale." Kagi: "We plan to exit it [third-party SERP providers] as soon as direct, contractual access becomes available." — [Kagi blog, 2026-01-21](https://blog.kagi.com/waiting-dawn-search)
  - Kagi "may suspend or terminate your access … where providing the API to you is no longer commercially viable." "The API is under active development." — [Kagi API ToS](https://kagi.com/privacy/api)
- **Yep**: "YEP SERVICES ARE WHOLLY BETA PRODUCTS PROVIDED BY AHREFS ON AN 'AS IS' AND 'AS AVAILABLE' BASIS". "We reserve the right … to modify, amend, update, or fully or partially suspend or discontinue Yep Services … at any time and for any reason". — [Yep ToS 6.1–6.2](https://platform.yep.com/legal/terms-of-service/)
- **Marginalia**: the API moved to "api2.marginalia-search.com" ("Updated 2025-12-08"). The commercial license product was created 2026-02-06. — [Marginalia API](https://about.marginalia-search.com/article/api/), [Polar](https://buy.polar.sh/polar_cl_hKnbSGWkflTozpXajwIu2ycB2fYmLM8jDxsuh06Kvmt)
- **Stract**: "archived by the owner on Apr 2, 2026". — [GitHub](https://github.com/StractOrg/stract). The stract.com domain now hosts an unrelated brand-tracking product. — [stract.com](https://stract.com/)
- **Yandex**:
  - The Search API ToU was re-issued four times in 2023–2026: "Previous version of the document" dated 09082026, 15082025, 05042024 and 29092023. The current one is effective Sept 7, 2026. — [Yandex ToU](https://yandex.com/legal/cloud_terms_search_api/en/)
  - The engine is operated by "Limited Liability Company 'YANDEX' (Registration number: 1027700229193 / Tax number: 7736207543)". — [same](https://yandex.com/legal/cloud_terms_search_api/en/)
  - Documentation now redirects from yandex.cloud to aistudio.yandex.ru, which served a CAPTCHA to automated fetches on 2026-11-23 (observed).
- **Google**:
  - Custom Search JSON API "closed to new customers"; existing users "have until January 1, 2027". — [CSE overview](https://developers.google.com/custom-search/v1/overview)
  - Google "updated the main overview page and four related pages on September 9" for its partner-only Web Search Service. — [SEJ](https://www.searchenginejournal.com/google-documents-partner-only-api-for-full-web-search-results/589194/)
  - DOJ remedies: "the Technical Committee is not yet fully staffed… the tasks of developing data-sharing and syndication license templates has not begun". The judgment period is "six years". — [Order of 05/07/26](https://www.courthousenews.com/wp-content/uploads/2026/05/google-mehta-denies-stay-pending-appeal-for-now-order.pdf)
  - Vertex AI has been renamed "Gemini Enterprise Agent Platform (formerly Generative AI on Vertex AI)", and Vertex AI Search is now "Agent Search". — [Service Specific Terms](https://cloud.google.com/terms/service-terms)
- **Microsoft**:
  - Bing Search APIs retired Aug 11, 2025. — [Microsoft Learn](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement)
  - Web IQ was introduced in a Microsoft Tech Community post dated 2026-10-17 — [Tech Community](https://techcommunity.microsoft.com/blog/azuredevcommunityblog/web-iq-web-search-and-grounding-apis-for-ai-agents/4565272). It is "Generally available in Azure" — [Web IQ](https://www.microsoft.com/en-us/webiq).
  - Foundry's Web Search tool is "powered by Web IQ, which uses Bing". — [Foundry web overview, updated 2026-11-17](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/web-overview)
  - Grounding with Bing TOU: "Microsoft may in its sole discretion deprecate the Services and/or revoke your rights to use the Services at any time immediately upon written notice." — [Grounding with Bing TOU §12](https://www.microsoft.com/en-us/bing/apis/grounding-legal)
- **Brave**: ToS updated 1 Sep 2026, a shift to prepaid billing, and x402 payments launched Nov 2026. — baseline sections 3 and 7
- **OpenWebSearch.eu** (open index alternative to Common Crawl): "14 research institutions, including CERN and the Leibniz Supercomputing Centre, are building an open web index as public infrastructure with 8.5 million euros in Horizon Europe funding. However, its funding is about to expire." — [heise, 2026-03-12](https://www.heise.de/en/news/Search-engine-initiative-aims-to-build-EU-search-11208524.html)

### Inferences
- **Every option has short exit clauses.** Mojeek (immediate termination), Kagi ("no longer commercially viable"), Yep ("WHOLLY BETA"), Microsoft ("deprecate … immediately") and Brave (10 days) can all cut service quickly. URnetwork's relay should support at least two providers behind one URnetwork-defined result schema, with per-provider storage flags. Only results from a storage-rights provider are written to the E2EE record.
- **Yandex is a payments-and-compliance risk for a US payer.** It is sold through Serbian and Emirati affiliates while queries go to a Russian operator. Get a legal review before use.
- **No legitimate Google general-web API exists for URnetwork today.** WSS is partner-only, and the DOJ remedy targets "Qualified Competitors" and had not started as of May 2026.

### Gaps
- I found no 2026 financial or ownership news for Mojeek or Ahrefs' Yep beyond their own pages.
- I found no Brave announcement of syndication partners.
- Whether Web IQ onboarding needs Microsoft approval is unconfirmed. A third-party summary says so, but Microsoft's own pages say only that a paid Azure subscription is required.
- I did not check the sanctions status of Yandex entities. This needs legal research, not web research.
