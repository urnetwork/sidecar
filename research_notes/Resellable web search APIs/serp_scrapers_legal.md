# SERP-scraping APIs as a resellable web search source, as of 2026-11-23: terms, prices, privacy, legal risk

All provider pages below were fetched on 2026-11-23 with a plain HTTP client and converted to text. Quotes are verbatim from those copies. Each governing document's own date is given where it shows one. Anything older or possibly superseded is marked with its date. This is research, not legal advice.

The question being tested: could URnetwork's sidecar resell a scraper's Google or Bing results, in place of Brave Search API, by:
- charging each end user per search at cost plus about 20%;
- showing results in its apps and passing them to the person's AI agents and coding harnesses;
- keeping a copy in the person's encrypted record.

Baseline: Brave's Search API Terms of Use (1 Sep 2026) forbid storing results beyond "transient storage", redistributing, reselling or sublicensing them, and making the API available to third parties. See section 4 of `research_notes/Brave web search tool/brave_search_api.md`.

## 1. Each provider's terms on per-search resale, pass-through, storage and white-label; price, capacity, data handling, payment

### Takeaway
No provider's standard self-serve terms clearly permit URnetwork's model of per-search, cost-plus resale.
- **Need written permission to resell:**
  - SerpApi, SearchApi.io, Bright Data and Oxylabs forbid reselling the service, use of it, or access to it without written permission or a separately agreed order.
  - DataForSEO's own legal FAQ names "per-query wallet resale models", "white-label API access" and "MCP endpoints" as needing a separate written agreement.
  - ScrapingBee forbids using the service "in a commercial manner" and forbids distributing data from it "in consideration of a payment" without consent.
- **Silent on resale:** Serper's terms (29 May 2024) are the only ones with no resale, storage or pass-through prohibition. Serper bars only "no-value-added" mirroring.
- **Zenserp is unclear.** Its own terms page is gone (HTTP 410). Its footer now links to Idera's general website terms, which forbid selling or distributing "any information … obtained from the … Services".

Showing results to your own paying users inside your own product is generally not prohibited:
- DataForSEO says so expressly, subject to its "do not compete with the search engine" clause (§7.1).
- SerpApi and SearchApi.io restrict only resale of the service (SearchApi.io also bars misattributing the data).
- Serper restricts only misattribution and "as-is" mirroring.

Storage of results by the customer is almost never restricted:
- DataForSEO: "no limit".
- Apify: outputs are the customer's own data.
- SerpApi, Serper, SearchApi.io, Oxylabs and Bright Data: silent.

That is a sharp contrast with Brave. The binding obstacle is the resale and pass-through-of-access clauses, not storage.

Headline prices per 1,000 Google searches run from about $0.30 (Serper at volume) to $25 (SerpApi Starter):

| Provider | Price per 1,000 searches |
|---|---|
| Serper | $1.00 down to $0.30 |
| DataForSEO | $0.60 (standard queue) to $2.00 (live), per 10-result page |
| Oxylabs | $1.00 down to $0.50 |
| Zenserp | $2.00 down to $0.90 |
| SearchApi.io | $4 down to $1 |
| Bright Data | $1.50, or $1.30 on the Scale plan |
| Apify | from $1.80 |
| ScrapingBee | about $2.53 down to $0.48 (10–15 credits per search) |
| SerpApi | $25 down to about $9.17 on the headline plans; $7.25 down to $1.96 on the 100K–54M tiers |

### Cited Findings

#### SerpApi (SerpApi, LLC, Austin, Texas). Legal Documents "Last updated: August 27, 2026"
- (a)/(d) **Resale.** "You agree not to reproduce, duplicate, copy, sell, resell or exploit any portion of the Service, use of the Service, or access to the Service or any contact on the website through which the service is provided, without express written permission by us." (Terms, Section 2) — [SerpApi Legal](https://serpapi.com/legal)
- (a)/(d) **Orders from resellers.** "We reserve the right to limit or prohibit orders that, in our sole judgment, appear to be placed by dealers, resellers or distributors." (Section 5) — [SerpApi Legal](https://serpapi.com/legal)
- (b)/(c) **Pass-through and storage.** The Terms contain no clause on displaying, passing on or storing returned results. Section 12 prohibits use "to infringe upon or violate our intellectual property rights or the intellectual property rights of others" and "to interfere with or circumvent the security features of the Service or any related website, other websites, or the Internet". — [SerpApi Legal](https://serpapi.com/legal)
- **U.S. Legal Shield (the "legal shield").** "For all recurring plans except the Free, Starter, and Developer plans, SerpApi will assume the liabilities of scraping and parsing search engine results for both U.S. and international companies and individuals, with up to $2 million in coverage ("U.S. Legal Shield"), provided your use of the data or service is not illegal. SerpApi assumes liability for the lawful collection of public search data (scraping, parsing, and related actions), but not for how that data is ultimately used. Illegal use includes, by way of example and not limitation, copyright infringement, DMCA violations, other intellectual property infringement, privacy violations, fraud, harassment, cybercrime … U.S. Legal Shield coverage is limited to claims brought under U.S. state or federal law in a U.S. court." (Section 13) — [SerpApi Legal](https://serpapi.com/legal)
- The Legal Shield page:
  - "It is not available with the Free, Starter and Developer plans."
  - "We recommend consulting your own legal counsel regarding data usage, as its legality can vary and falls outside the scope of U.S. Legal Shield protection."
  - "Since our founding in 2017, no SerpApi customer has paid a single dollar in damages for web scraping using our tools."
  - Source: [SerpApi U.S. Legal Shield](https://serpapi.com/us-legal-shield)
- **Customer indemnity.** "You agree to indemnify, defend and hold harmless SerpApi.com … from any claim or demand, including reasonable attorneys' fees, made by any third-party due to or arising out of your breach of these Terms of Service … or your violation of any law or the rights of a third-party." (Section 14) — [SerpApi Legal](https://serpapi.com/legal)
- Other terms:
  - Governing law is Texas.
  - "A breach or violation of any of the Terms will result in an immediate termination of your Services."
  - "We reserve the right to refuse service to anyone for any reason at any time."
  - 99.95% SLA "with all plans", with credits up to 100% of the monthly price.
  - Source: [SerpApi Legal](https://serpapi.com/legal)
- **Price and capacity** — [SerpApi Pricing](https://serpapi.com/pricing):

  | Plan | Price per month | Searches per month | Throughput per hour | Cost per 1,000 searches |
  |---|---|---|---|---|
  | Free | $0 | 250 | 50 | — |
  | Starter | $25 | 1,000 | 200 | $25.00 |
  | Developer | $75 | 5,000 | 1,000 | $15.00 |
  | Production | $150 | 15,000 | 3,000 | $10.00 |
  | Big Data | $275 | 30,000 | 6,000 | about $9.17 |
  | Enterprise | custom | custom | custom | — |

  - In the page markup the Legal Shield carries a check only for Production, Big Data and Enterprise. Free, Starter and Developer show a cross.
  - The "View all plans" table is plan data embedded in the same page. It lists higher tiers. Each sets `legal_shield: true`; `zero_trace` is `false` up to Infrastructure and `true` from Cloud 1M up:

    | Plan | Price per month | Searches per month | Throughput per hour | Cost per 1,000 searches |
    |---|---|---|---|---|
    | "Searcher" | $725 | 100,000 | 20,000 | $7.25 |
    | "Volume" | $1,475 | 250,000 | 50,000 | $5.90 |
    | "Infrastructure" | $2,750 | 500,000 | 100,000 | $5.50 |
    | "Cloud 1M" | $3,750 | 1,000,000 | 110,000 | $3.75 |
    | "Cloud 10M" | $21,125 | 10,000,000 | 200,000 | $2.11 |
    | "Cloud 54M" | $106,050 | 54,000,000 | 640,000 | $1.96 |

    Cloud tiers run in 1M steps up to 54M.
  - "Only successful searches are counted… Cached, errored, and failed searches are not. The number of results returned per response will not affect the number of credits used."
  - Refund: "a full refund within 7 days … unless you've used more than 20% of your searches."
  - "Month-to-month. Cancel anytime."
- **Payment.** The subprocessor list names "Stripe, Inc.: subscription payments". — [SerpApi Legal](https://serpapi.com/legal). I found no other payment method documented.

#### Serper.dev ("Serper", governing law of the United Kingdom). Terms "Updated on May 29, 2024"
- **Business-to-business only.** "Serper is a business-to-business service and does not provide end-user (consumer) services. Permission is granted to download the materials (information or software) on the Serper website and Service for as long as your use case requires." — [Serper Terms](https://serper.dev/terms)
- (a)/(b)/(c)/(d) **The only license restrictions.** Under the license "you may not":
  - "Modify, copy, prepare derivative works of, decompile, or reverse engineer any materials and software contained on the serper.dev website";
  - "Remove any copyright or other proprietary notations from the materials";
  - "Register more than one account at any point in time";
  - "Mirror the materials on any other server as-is with no-value-added";
  - "Attempt to circumvent any restrictions or limits placed on your Serper API key or account."
  - There is no resale, sublicensing, storage or end-user clause. — [Serper Terms](https://serper.dev/terms)
- **Data License.** "Unless applicable by law or expressly permitted by the owner, you will not, and will not permit your end users or others acting on your behalf, to … Misrepresent the ownership or the source. Obscure, remove or change any copyright, trademark, or other proprietary notices. Falsify or delete any author attributions…" Also: "Serper provides web-scraped data collected from public domain sources." And: "In some cases, public-domain content accessible to Serper may also be subject to intellectual property rights. If this is the case you may not use it unless you are licensed to do so or are otherwise permitted by law." — [Serper Terms](https://serper.dev/terms)
- **Indemnity is mutual and oddly drafted.** "Both parties agree to defend, indemnify, and hold harmless each other … resulting from or arising out of a) your use of the Service, by you or any person using your account and password, or b) a breach of these Terms by either party." Liability is capped at "the fees due and payable". — [Serper Terms](https://serper.dev/terms)
- **Termination.** "This license shall automatically terminate if you violate any of these restrictions and may be terminated by Serper at any time, with or without cause, with or without notice." — [Serper Terms](https://serper.dev/terms)
- **Price and capacity** — top-up credits, "Excluding sales tax/VAT/GST", each pack "Credits valid for 6 months" — [Serper home/pricing](https://serper.dev/):

  | Pack | Price | Credits | Cost per 1,000 | Rate limit |
  |---|---|---|---|---|
  | Starter | $50 | 50k | $1.00 | 50 queries/s |
  | Standard | $375 | 500k | $0.75 | 100 queries/s |
  | Scale | $1,250 | 2.5M | $0.50 | 200 queries/s |
  | Ultimate | $3,750 | 12.5M | $0.30 | 300 queries/s |

  - 2,500 free queries.
  - "When your credit balance reaches zero, we will stop accepting new queries."
  - Refund within 7 days unless more than 20% used.
- **Payment.** "We accept all major credit cards (Visa, Mastercard, American Express, Discover) and PayPal." — [Serper home/pricing](https://serper.dev/)

#### DataForSEO (DataForSEO OÜ, Tallinn, Estonia). Terms "UPDATED: 12 JUNE, 2026"
- **§7.1 (the key restriction).** "You acknowledge and agree that any search engine results page (SERP) data or content obtained through the Service, including but not limited to data from Google, Bing, Yahoo, and other search engine providers, shall not be used to compete with or adversely affect the business interests of the search engine providers from which such data originates." — [DataForSEO Terms](https://dataforseo.com/terms-of-service)
- **§7.2.** "You agree to indemnify, defend, and hold harmless DataForSEO from any and all claims, damages and losses arising from or relating to Your violation of Section 7.1, including any use of SERP data that violates the terms of service or legal rights of the search engine providers." — [DataForSEO Terms](https://dataforseo.com/terms-of-service)
- **§8.1.** "Certain services provided by DataForSEO are resold. DataForSEO holds no responsibility for the use of our clients' accounts… We reserve the right to remove any account, without advance notice for any reason without restitution." — [DataForSEO Terms](https://dataforseo.com/terms-of-service)
- **Legal FAQ.** DataForSEO's "Quick Answers to Frequently Asked Legal Questions" says it is based on the Terms (12 June 2026), Privacy Policy (29 October 2026) and DPA (12 June 2026). All quotes in this list are from [DataForSEO legal FAQ](https://dataforseo.com/help-center/quick-answers-to-frequently-asked-legal-questions):
  - (a)/(d) Q3: "**Can we resell, redistribute, sublicense, or give our customers raw API access?** No, not under the standard Terms. The Terms of Service grant no resale, sublicensing or redistribution right, so any onward distribution of our datasets as an untransformed standalone feed, database dump, public endpoint, or raw API service requires a separate written agreement. This includes white-label API access, MCP endpoints, marketplace actors, open datasets, and per-query wallet resale models."
  - (b) Q6: "Nothing in the Terms of Service conditions use on the product being free or non-commercial… The Terms do not restrict processing API outputs into analytics, reports, dashboards or scores inside the client's own product, or showing those to the client's own paying users, and set no cap on end-user numbers. The limit that applies is Section 7.1."
  - (b) Q10: "Where an export is designed to deliver raw or near-raw API responses to third parties is considered a violation of Terms of Service."
  - (c) Q2: "The Terms of Service set no limit on how long a client keeps its own copies, and do not require deletion when service ends." Q14: "the restrictions set out in Section 7.1 continue to apply to any data retrieved prior to termination."
  - Q1 describes what §7.1 catches:
    - "Direct competition: Using search results or ranking data to build a competing search engine or a service that replicates the search engine's core functionality."
    - "Harm to business interests: Using the data in ways that divert users, advertising revenue, customers, or other commercial opportunities away from the search engine provider."
    - DataForSEO says it is "unable to confirm whether a particular product or implementation complies".
  - Q5: "The client is responsible for ensuring compliance with the applicable terms and conditions of Google, Bing, and any other relevant search engine providers. Our Terms of Service do not grant any licenses from, or confer any rights under, the terms and conditions of, any upstream provider." It also asserts: "We do not access password-protected or gated areas, and we do not circumvent authentication controls. Collecting unauthenticated public data in this manner is lawful under applicable law."
  - Q8, on AI use: "The Terms of Service contain no provision addressing AI processing, inference, retrieval pipelines, or training and fine-tuning of models. Section 7.1 applies to the use of the data however it is processed."
  - Q13: one account may serve many unrelated end clients ("Giving those end clients direct API access is a distribution question").
- **Price** — [Google Organic SERP pricing](https://dataforseo.com/pricing/serp/google-organic-serp-api), [Pricing overview](https://dataforseo.com/pricing):
  - Billed "Per SERP", one SERP being 10 results:

    | Mode | Turnaround | Price per SERP | Per 1,000 SERPs |
    |---|---|---|---|
    | Standard queue | "~5 minutes on average", "Target: 45 minutes" | $0.0006 | $0.60 |
    | Priority queue | "Up to 1 minute on average" | $0.0012 | $1.20 |
    | Live mode | "Up to 6 seconds on average" | $0.002 | $2.00 |

  - Multipliers:
    - `depth`: "+1 base price per each additional 10 results".
    - Search operators (site:, inurl: …): "x5 base price per operator used".
    - `load_async_ai_overview`: "+1 base price".
  - "$50 minimum top-up", "Balance never expires", "$1 trial credit".
  - Bing Organic is from "$0.0006 per SERP · 10 results". — [SERP API pricing](https://dataforseo.com/apis/serp-api/pricing)
- **Payment.** "DataForSEO accepts credit and debit cards, PayPal, and Amazon Pay. For payments of $5,000 or more, bank wire transfers and ACH payments are also available." — [Pricing overview](https://dataforseo.com/pricing). Processors are Paddle, FastSpring or Wise. — [DataForSEO Privacy](https://dataforseo.com/privacy-policy)
- **Eligibility.** §6.2 bars customers in Russia, Belarus, Cuba, Iran, Syria, Myanmar, North Korea, Crimea and occupied Ukrainian territories (per FAQ Q12). — [DataForSEO legal FAQ](https://dataforseo.com/help-center/quick-answers-to-frequently-asked-legal-questions)

#### SearchApi.io (SearchApi, LLC, US). Terms "Last updated: April 11, 2026"
- (a)/(d) **Resale.** "You agree not to reproduce, duplicate, copy, sell, resell or exploit any portion of the Services, use of the Services, or access to the Services without the express written permission by the Company." — [SearchApi Terms](https://www.searchapi.io/legal/terms)
- (b) **Data Licensing.** "Unless required by law or explicitly allowed by the owner, you must not, and must not allow your end-users or others acting on your behalf, to engage in the following activities with the Data obtained from the API: Misrepresent the ownership or source of the Data. Alter, remove, or conceal any copyright, trademark, or other proprietary notices… Falsify or delete any author attributions…" Also: "Some public-domain content accessible through SearchApi may also be subject to intellectual property rights. In such cases, you may only use the content if you have the appropriate license or are otherwise permitted by law." — [SearchApi Terms](https://www.searchapi.io/legal/terms)
- (c) **Storage.** The Terms have no clause on the customer storing results.
- **Legal Protection Guarantee.** All quotes from [SearchApi Terms](https://www.searchapi.io/legal/terms):
  - Scope: "SearchApi accepts legal responsibility, subject to this section, for third-party claims under U.S. law and jurisdiction that arise solely from SearchApi's own collection and parsing of publicly available search results delivered through the Services."
  - Exclusions: "It does not apply to any claim arising from your use, storage, redistribution, or commercialization of data; your contracts or obligations with third-party sites or data providers; privacy, security, or intellectual property claims tied to your systems or products…"
  - Plans: "This guarantee applies to active, paid subscriptions starting from the Production plan and above. It does not apply to free trials, Developer plans, or any period after your subscription ends."
  - Cap: "The total amount payable by SearchApi under this guarantee is capped at USD 2,000,000 aggregate per 12-month period."
  - Discretion: "We may, at our discretion, defend, settle, or pay amounts in resolution of a covered claim. Nothing in this section obligates us to appoint counsel for you."
  - Who it covers: "It creates no rights for any person or entity other than the account holder and is not assignable."
- **Customer indemnity.** It covers "your use of the Service", including "allegations that your use of the Service infringes or misappropriates any trademark, copyright, or other intellectual property", except claims inside the Guarantee. Liability is capped at fees paid in the prior 12 months. — [SearchApi Terms](https://www.searchapi.io/legal/terms)
- **Price and capacity** — [SearchApi Pricing](https://www.searchapi.io/pricing):

  | Plan | Price per month | Searches | Stated price per 1,000 |
  |---|---|---|---|
  | Developer | $40 | 10,000 | $4 |
  | Production | $100 | 35,000 | $3 |
  | BigData | $250 | 100,000 | $2.5 |
  | Scale | $500 | 250,000 | $2 |
  | Octo 500K | $900 | 500,000 | $1.8 |
  | Octo 1M | $1,500 | 1,000,000 | $1.5 |
  | Octo 2M | $2,800 | 2,000,000 | $1.4 |
  | Octo 5M | $5,000 | 5,000,000 | $1 |

  - The Legal Protection Guarantee is listed from Production up.
  - "you can utilize only up to 20% of your plan's credits each hour."
  - "Only successful searches with a 200 status code incur charges."
  - 100 free requests.
- **Payment.** "When you pay for a SearchApi product, we ask for your credit card and billing address." — [SearchApi Privacy](https://www.searchapi.io/legal/privacy)

#### Zenserp (SaaS Industries GmbH, Austria; site footer © apilayer/Idera)
- **The terms page is gone.**
  - `https://zenserp.com/terms/`, `/terms-of-service/`, `/terms-and-conditions/` and `/legal` all return HTTP 410 "Page not found".
  - The pricing-page footer links "Terms of Service (Idera)" to Idera's General Website Terms of Use.
  - Sources: [Zenserp terms URL (410)](https://zenserp.com/terms/), [Zenserp pricing](https://zenserp.com/pricing-plans/)
- **Idera General Website Terms of Use ("Published: January 24, 2004 | Updated: November 1, 2019").**
  - It covers "any website maintained or operated by Idera, Inc. or any of its affiliate entities".
  - Its prohibited activities include: "Modify, copy, distribute, transmit, display, perform, reproduce, publish, license, create derivative works from, transfer, or sell any information, software, products or services obtained from the Site, Services, or Materials."
  - It also forbids using "any … scraper, robot, crawl … to … search, generate searches … any portion of the Site".
  - Source: [Idera Terms of Use](https://www.ideracorp.com/Legal/Terms-of-Use)
- **Zenserp's own terms.** A Zenserp-specific "Zenserp Terms of Service" PDF, operated by "SaaS Industries GmbH" and undated, is hosted on Idera's domain. It covers subscriptions, refunds ("case-by-case basis"), termination "for any reason whatsoever", liability and Austrian law. It has **no** clause on resale, storage, pass-through or end users. — [Zenserp ToS PDF (Idera-hosted)](https://ideracorp.com/~/media/IderaInc/Files/SaaSIndustries/SaaS%20Industries%20Terms%20of%20Service)
- **Price and capacity.** Monthly prices, with "Yearly -20%" — [Zenserp pricing](https://zenserp.com/pricing-plans/):

  | Plan | Price per month | Searches | Cost per 1,000 |
  |---|---|---|---|
  | Free | $0 | 50 | — |
  | Small | $49.99 | 25,000 | $2.00 |
  | Medium | $149.99 | 100,000 | $1.50 |
  | Large | $299.99 | 250,000 | $1.20 |
  | Premium | $499.99 | 500,000 | $1.00 |
  | Enterprise | $899 | 1,000,000 | $0.90 |

  - Coverage: "Google, Bing, Yandex, DuckDuckGo".
  - "An AI Overview request uses 3 searches."
  - "For our standard plans, we encourage not to exceed 400 concurrent connections."
- **Payment.** "We accept all common payment methods, including credit cards (MasterCard, Visa, American Express). Enterprise and high-volume customers may request annual bank transfer payments to be enabled." — [Zenserp pricing](https://zenserp.com/pricing-plans/)

#### ScrapingBee (VostokInc SAS, Paris; French law). Terms "Last Updated: July 15th 2024"
All quotes in this list are from [ScrapingBee Terms](https://www.scrapingbee.com/terms-and-conditions/).
- (a)/(d) **Prohibitions.** Users "shall not (non-limitative list)":
  - "Use the Services or any element thereof in a commercial manner."
  - "Breach the terms and conditions of use of third-party websites, platforms, applications, databases, and other sources or using the Services in order to do so."
  - "Copy, modify, or distribute configurations or any data, content, or information from VostokInc, from the Services, or from other Users free of charge or in consideration of a payment without the consent of VostokInc or the concerned User."
- (b) **Individual use.** "The Services are limited to an individual use by the User as part of their professional activities… Users undertake not to exploit or communicate to third parties any configuration developed by others or any other element issued from their use of the Services except when expressly authorized."
- (d) **No third-party access.** "the User is strictly prohibited from any other use, in particular, any rental, adaptation, modification, translation, arrangement, distribution, decompilation, or making the API available to a third party."
- **Target-site terms.** "Websites may expressly prohibit scraping; it is therefore User's responsibility to check such potential prohibition for each website prior to scraping such websites with the Services. In case of doubt whether such websites allow scraping, user undertakes to obtain the Provider's prior authorization."
- **Responsibility.** "User acknowledges that the Provider only provides the Services and shall not under no circumstances be held liable as to the lawfulness of the User's use of the Services including the web scraping operations performed and the use of the data scraped." The User indemnifies the Provider for third-party claims.
- (c) **Storage.** No storage restriction. "User is solely responsible for backing up its User Data."
- **Price and capacity.**
  - Google Search API: "Each search can cost 10 credits with Light Request enabled, 15 otherwise. Credits are valid for one month; leftovers are not rolled over." — [ScrapingBee Google Search API](https://www.scrapingbee.com/documentation/google/)
  - Plans, as monthly price / credits / concurrency — [ScrapingBee Pricing](https://www.scrapingbee.com/pricing/):
    - $19 / 75,000 / 25
    - $49 / 250,000 / 50
    - $99 / 1,000,000 / 100
    - $249 / 3,000,000 / 200
    - $599 / 8,000,000 / 400
    - $999 / 14,000,000 / 500
    - $1,599 / 24,000,000 / 600
    - $2,399 / 41,000,000 / 700
    - $3,599 / 69,000,000 / 800
    - $5,799 / 120,000,000 / 900
  - 1,000 free credits.
- **Payment.** I found no payment methods stated on the pricing page.

#### Bright Data (Bright Data Ltd., Israel; Bright Data, Inc. for US clients). Master Service Agreement "Last Updated: October 12, 2026"
All quotes in this list are from the [Bright Data MSA](https://brightdata.com/license) unless another source is named. A markdown copy is at [license.md](https://brightdata.com/license.md).
- (a)/(d) **Proxy Services.** Under "Specific terms for the Proxy Services" the Client shall "Not engage in any reselling of the Service in whole or in part, without Bright Data's prior written authorization." The Client also shall not "enhance or operate a service that competes with the Services, or assist any other party to do so".
- **Internal use only.** Under "Proxy Services and Scraping Browser API": "Bright Data grants the Client a limited, revocable and non-transferable license (with no right to sublicense) to access and use the System solely for the purpose of Client's internal business operations."
- **Data Services.** "When using the Data Services, the Client shall not distribute, transmit, reproduce, publish, license, transfer, or sell any Data in order to offer a similar or competitive product."
- **Acceptable Use Policy.** Prohibited: "Reselling of proxies without Bright Data's prior written approval (see our partners programs)." — [Bright Data AUP](https://brightdata.com/acceptable-use-policy)
- The MSA does not say which product block governs the SERP API (it is not named). The partners page lists "Affiliates Program" and "Referral Program". I found no public reseller or white-label program. — [Bright Data partners](https://brightdata.com/partners)
- **Customer indemnity.** "Client will defend Bright Data against any claim … by a third party alleging that the Client's use of any Service infringes or misappropriates such third party's intellectual property rights or breaches applicable privacy laws or any other applicable law or causes damage to such third party." Bright Data's liability is capped at "fees actually received … during the one month period prior to the Event".
- **Amendment.** Bright Data "may, at any time, and at its sole discretion, modify this Agreement, with or without notice … effective immediately upon public posting."
- **Price and capacity** — [Bright Data SERP pricing](https://brightdata.com/pricing/serp):
  - Free Tier: 5K requests a month.
  - Pay as you go: $1.5 per 1K requests.
  - Scale: $499 a month, including 380K requests, then $1.3 per 1K additional.
  - Enterprise: custom.
  - "Unlimited concurrency". "No. There is no limit to the number of concurrent requests."
  - "In asynchronous mode, only 'send request' is counted."
- **Payment.** The pricing page shows payment icons (not machine-readable) and offers "Using AWS? You can now pay through the AWS Marketplace". Charges are "billed in USD". — [Bright Data SERP pricing](https://brightdata.com/pricing/serp). Onboarding collects "identifying documents (driver license/ID/passport)" (KYC). — [Bright Data Privacy](https://brightdata.com/privacy)

#### Oxylabs (oxylabs, UAB, Vilnius, Lithuania)
- Two sets of terms apply:
  - Self-service: "Last updated on September 25, 2024". It is accepted by "selecting and paying for one of the Services plans offered within the Dashboard". — [Oxylabs self-service ToS](https://oxylabs.io/legal/self-service-tos)
  - General Conditions, which apply with an SoW: "Last updated October 8, 2025". — [Oxylabs Terms of Service (GC)](https://oxylabs.io/legal/oxylabs-terms-of-service)
- (a)/(d) **Resale.**
  - Self-service §4.2.11: "the Customer shall not: sell, resell (unless explicitly agreed otherwise), license, sublicense, distribute, make available, rent or lease Services…"
  - GC §4.2.10: "sell, resell (unless explicitly agreed otherwise in the SoW), license, sublicense, distribute, make available, rent or lease the Services".
  - Self-service §4.2.9: "the Customer shall ensure that access credentials provided by Oxylabs will not be shared (selling, transfering, sublicensing, etc.) with third parties".
  - Sources: [self-service ToS](https://oxylabs.io/legal/self-service-tos), [GC](https://oxylabs.io/legal/oxylabs-terms-of-service)
- (b)/(c) **Data.** Self-service §8.1 — [self-service ToS](https://oxylabs.io/legal/self-service-tos):
  - "By using the Services you might be able to access, transmit, distribute, gather, reproduce or in any other way use ("Access") third party data… You are solely responsible for the Data you Access by using the Services."
  - "As long as you use the Services and Access Data legally (i.e. with consent or in accordance with Data owner terms of services, policies, copyrights, etc.) Oxylabs will not be able to suspend your use of the Services on these grounds."
  - Nothing restricts storing or passing on the scraped data as such.
- **Acceptable Use Terms ("last update … October 8, 2025").** "automated data gathering (crawling, scraping, etc.) 'as an activity itself' should not be considered illegal". The Customer must not use the Services in a way that would "Be in violation of relevant terms of use/service or other legal documents". — [Oxylabs Acceptable Use Terms](https://oxylabs.io/legal/acceptable-use-terms)
- **Indemnity.**
  - Oxylabs indemnifies only for claims that "the software of the Services" infringes IP. That indemnity is capped at "2 TIMES THE CUSTOMER'S SERVICES FEE FOR THE MONTH", and excludes use "in violation of this Agreement (including Acceptable Use Policy)".
  - The Customer indemnifies Oxylabs for "any and all claims by any third party in connection with the Customer's use of Services".
  - Source: [self-service ToS](https://oxylabs.io/legal/self-service-tos)
- **Price** — Web Scraper API, per 1K results; free $5 welcome credit; Enterprise "For plans starting at $2,500/month" — [Oxylabs pricing](https://oxylabs.io/pricing/web-scraper-api):

  | Tier | Google non-JS | Google JS |
  |---|---|---|
  | Free $5 credit | $1.00 (up to 5K) | $1.35 |
  | Starter, $15/mo | $1.00 (up to 15K) | $1.35 |
  | Basic, $100/mo | $0.90 (up to 111K) | $1.30 |
  | Flexible, $500/mo | $0.70 (up to 714K) | $1.15 |
  | Enterprise | $0.50 (5M+) | $0.90 |

- **Payment.** The pricing page states no payment methods (gap).

#### Apify (Apify Technologies s.r.o., Prague; Czech law). General Terms "Effective date: July 9, 2026"
- (a)/(d) **Platform license.** "you may not … (ii) reproduce, share, or distribute the Website or the Services … (iv) sublicense, transfer, or assign any rights or obligations under the license, in whole or in part, to third parties." — [Apify General Terms](https://docs.apify.com/legal/general-terms-and-conditions). The same wording applies to "Apify Maintained Actor(s)", the class that includes `apify/google-search-scraper`. — [Apify Actor Terms (effective July 9, 2026)](https://docs.apify.com/legal/actor-terms-and-conditions)
- (b)/(c) **Outputs belong to the customer.** "As between you and Creator … you retain all intellectual property rights that subsist in your Actor Input and Actor Output." "Any Actor Outputs retrieved by you and processed through the Platform are considered Customer Data." "you retain all right, title, and interest in and to your Customer Data." — [Apify Actor Terms](https://docs.apify.com/legal/actor-terms-and-conditions), [Apify General Terms](https://docs.apify.com/legal/general-terms-and-conditions)
- **Customer indemnity.** It covers "your use of any Actor … or your violation of any third-party's rights". — [Apify Actor Terms](https://docs.apify.com/legal/actor-terms-and-conditions)
- **Apify's own legality guidance** on the actor page: "Web scraping is legal if you are extracting publicly available data… you should also factor in Google's Terms of Use. If you're unsure whether your reason is legitimate, consult your lawyers." — [Apify Google Search scraper](https://apify.com/apify/google-search-scraper)
- **Price.**
  - "from $1.80 / 1,000 scraped search result pages", pay-per-event.
  - "On the Free plan, you get $5 of credit, which lets you scrape over 1,000 Google Search results without using add-ons."
  - Sources: [Apify Google Search scraper](https://apify.com/apify/google-search-scraper)
  - Platform plans: $0 ($5 credit), $19, $199 and $999 a month of prepaid usage. — [Apify pricing](https://apify.com/pricing)

### Inferences
- **(a) Per-search cost-plus charging** is reselling "use of"/"access to" the service under SerpApi and SearchApi.io. It needs their "express written permission".
  - Under DataForSEO it is expressly a "per-query wallet resale model" that needs a separate written agreement.
  - Under Bright Data and Oxylabs it is reselling the Service, which needs written authorization or a term in the SoW.
  - Under ScrapingBee it is "commercial" use and paid distribution without consent.
  - Serper is the only provider whose terms do not forbid it. Even there, nothing grants a right either; the terms simply say nothing. If Idera's website terms govern Zenserp, they forbid it.
- **(b) Passing results to agents and coding harnesses** works on two levels:
  - Results inside URnetwork's own app or agent context: permitted or unaddressed at SerpApi, SearchApi.io, Serper, Oxylabs and Apify. DataForSEO permits it subject to §7.1.
  - The person's own coding harness calling a URnetwork endpoint that returns near-raw SERP JSON: that is what DataForSEO calls an "MCP endpoint"/"raw API service". At SerpApi and SearchApi.io it is "access to the Service", and at Bright Data and Oxylabs "making available" the service. Expect this to need the same written agreement as (a).
- **(c) Keeping a copy in the person's encrypted record** is not barred by any of the nine providers' terms that I read.
  - The nearest restrictions are Serper's "Mirror the materials … as-is with no-value-added", ScrapingBee's distribution ban, and the Idera website terms' "copy … reproduce" (if they govern Zenserp).
  - Storage risk comes from the upstream engine (Google's or Microsoft's terms, copyright in snippets and images), not from the scrapers. That reverses Brave's position.
- **(d) Wholesale or white-label:**
  - No provider publishes a self-serve reseller or white-label program for SERP data that I found.
  - Bright Data's AUP points to "partners programs", but the partners page shows only affiliate and referral programs.
  - DataForSEO, SerpApi, SearchApi.io, Bright Data and Oxylabs all leave the door open to a negotiated written agreement. That is the path to take.
- **DataForSEO §7.1 is a distinct risk for an AI-agent search tool.** A built-in web search that answers agents' questions arguably "replicates the search engine's core functionality" or "divert[s] users … away from the search engine provider". DataForSEO says it will not pre-clear a use case.
- **Price per search** (the cost base for a 20% markup):
  - At small volume: Serper Starter ($1.00/1k), DataForSEO live ($2.00/1k), Oxylabs ($1.00/1k), Bright Data ($1.50/1k).
  - SerpApi is 5–25 times dearer at small volume ($9–$25/1k) and still $1.96–$3.75/1k at 1M–54M a month. It is the only provider with a $2M shield that has a track record. SearchApi.io offers the same shield from $100/month at $2.86–$3/1k.
  - ScrapingBee's $49 plan works out to $1.96/1k at 10 credits a search, or $2.94 at 15. Its $99 plan works out to $0.99 or $1.49.

### Gaps
- Payment methods are undocumented on the pages I read for ScrapingBee, Oxylabs and Apify. For Bright Data they appear only as unlabelled icons plus AWS Marketplace. SerpApi shows only Stripe.
- I could not determine whether Bright Data's SERP API falls under the MSA's "Proxy Services" block (internal-use license, no resale) or another block. The MSA does not name it.
- Zenserp: I could not establish which document currently governs API customers. The zenserp.com terms URLs return 410. The footer links Idera's 2019 website terms, and an undated Zenserp ToS PDF sits on Idera's domain. Ask Zenserp/apilayer for the operative contract.
- I did not find whether SerpApi or Serper accept crypto, invoices or wire transfers below the enterprise tier.
- DataForSEO's per-account rate limits were not captured from the pages read.
- Whether ScrapingBee's $19 plan includes the Google API was not verified. Per-1,000 figures above use the $49+ plans.

## 2. Legal risk of reselling scraped Google or Bing results, as of November 2026

### Takeaway
No court has yet held that scraping Google results is unlawful.

- **Google v. SerpApi (N.D. Cal.)** pleads only DMCA §1201 anti-circumvention claims. It has been dismissed twice:
  - July 20, 2026: claims over results with no copyrighted content were dismissed for good, "WITHOUT LEAVE TO AMEND".
  - November 9, 2026: the amended complaint failed too.
  - Google's last chance to amend is due **December 10, 2026**.
- **Reddit v. SerpApi (S.D.N.Y., July 31, 2026)** moved the risk downstream. The court let §1201(a)(1)(A) and civil-conspiracy claims proceed against **Perplexity, a paying SerpApi customer**, as a *direct* circumventor. Perplexity "set[s] the parameters for circumvention activity" and "conduct[s] the actual queries itself", making it "more than a bystander to, or a downstream beneficiary of, SerpApi's circumvention".

A reseller that relays its users' queries through a scraper is in Perplexity's position. The scrapers' "legal shields" do not cover that position:
- SerpApi's excludes "DMCA violations" and "how that data is ultimately used".
- SearchApi.io's excludes "use, storage, redistribution, or commercialization of data".

Google's and Microsoft's terms forbid automated access, and Microsoft's also forbid building products on Bing content. But contract claims against logged-off scrapers have mostly failed (Meta v. Bright Data) or been preempted (X v. Bright Data). The live US theory is §1201, and it turns on whether the results contain copyrighted material whose rights holder can sue.

In the EU, a real-time meta-search engine that re-serves another engine's results has been held to re-utilise its database (Innoweb, 2013).

### Cited Findings

**Google LLC v. SerpApi, LLC — N.D. Cal. No. 4:25-cv-10826-YGR (Chief Judge Yvonne Gonzalez Rogers)**
- **Complaint (filed Dec 19, 2025).** It has two counts: DMCA §1201(a)(1)(A) (circumvention) and §1201(a)(2) (trafficking). There are no contract, CFAA or trespass counts. — [Complaint, Dkt 1](https://storage.courtlistener.com/recap/gov.uscourts.cand.461513/gov.uscourts.cand.461513.1.0.pdf)
  - On automated access: "Google prohibits automated access to and scraping of its Search results in its Terms of Service Agreement with users."
  - On the alleged circumvention: "SerpApi may solve SearchGuard's challenge with a 'legitimate' request and then syndicate the resulting authorization, that is, share it with unauthorized machines around the world."
  - Relief sought:
    - an injunction against SerpApi "and those persons in active concert or participation with them";
    - statutory damages "of no less than $200 and as much as $2,500 for each of SerpApi's many statutory violations".
- Google's announcement says SerpApi "deceptively takes content that Google licenses from others… and then resells it for a fee." — [Google blog, Dec 19, 2025](https://blog.google/innovation-and-ai/technology/safety-security/serpapi-lawsuit/) (read by a parallel researcher)
- **July 20, 2026 order (Dkt 42).** All quotes in this list are from [Order, Dkt 42](https://chatgptiseatingtheworld.com/wp-content/uploads/2026/07/Google-v-SerpApi-order-granting-motion-to-dismiss-July-20-2026.pdf).
  - "To the extent that Google Search results do not contain any copyrighted content, SearchGuard cannot be said to effectively control access to a work protected under the Copyright Act." Those claims were dismissed "WITHOUT LEAVE TO AMEND because amendment would be futile, as the claims fail as a matter of law."
  - Claims over copyrighted components (Knowledge Panel images) were dismissed with leave to amend "within twenty-one (21) days".
  - The court sided with Google on two questions:
    - The DMCA's zone of interests is not limited to copyright owners.
    - "Google has alleged facts that raise the inference that SerpApi circumvented SearchGuard by bypassing it or by impairing its ability to detect and block SerpApi's automated queries."
  - hiQ (a CFAA case) is "irrelevant to the analysis here".
- **Amended complaint (Aug 10, 2026).** Same two counts. It relies on Google's content-licensing agreements, including its Reddit license, to show "authority of the copyright owner". — [Dkt 45](https://storage.courtlistener.com/recap/gov.uscourts.cand.461513/gov.uscourts.cand.461513.45.0.pdf) (read by a parallel researcher)
- **November 9, 2026 order (Dkt 62).** All quotes in this list are from [Order, Dkt 62 (SerpApi-hosted copy)](https://serpapi.com/blog/content/files/2026/11/62.0--2026-11-09--ORDER-GRANTING-MOTION-TO-DISMISS-WITH-LEAVE-TO-AMEND-by.pdf).
  - "the AC is devoid of any facts indicating that the content subject to Google's licensing agreement with Reddit was creative."
  - The other licensing allegations are "bare and conclusory".
  - "the Google Privacy Policy contains no terms that refer to 'licensed' content or to Google's protection of the same."
  - Disposition: "WITH LEAVE TO AMEND but only for the purpose of curing the deficiencies discussed above… A failure to file an amended complaint within 21 days will result in the dismissal of this action with prejudice."
- **Schedule.** Stipulation and order: "Google's deadline to file a Second Amended Complaint shall be December 10, 2026", and SerpApi's response is due "January 11, 2027". — [Dkt 64](https://storage.courtlistener.com/recap/gov.uscourts.cand.461513/gov.uscourts.cand.461513.64.0.pdf)
  - Discovery is stayed.
  - No answer, judgment, appeal or settlement appears in the RECAP entries through Dkt 64 (per a parallel researcher's docket reconstruction).
- SerpApi's public responses:
  - "We do not bypass authentication." — [SerpApi blog, Jan 23, 2026](https://serpapi.com/blog/google-v-serpapi-threatening-access-to-public-data.md)
  - [SerpApi blog, Jul 21, 2026](https://serpapi.com/blog/google-v-serpapi-the-court-granted-our-motion-to-dismiss/)
  - [SerpApi blog, Nov 10, 2026](https://serpapi.com/blog/court-dismisses-googles-amended-complaint-against-serpapi/)

**Reddit, Inc. v. SerpApi LLC, Oxylabs UAB, AWMProxy, Perplexity AI — S.D.N.Y. No. 1:25-cv-08736-PAE (Judge Paul A. Engelmayer)**
- **Opinion and Order, July 31, 2026 (Dkt 104, 63 pages, scanned; quotes from my own OCR of the RECAP copy).** All quotes in this list are from [Opinion, Dkt 104](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.104.0.pdf).
  - Disposition: "the Court predominantly denies the motions to dismiss. It sustains the claims (1) brought against both defendants under section 1201(a)(1)(A) of the DMCA, (2) against SerpApi under 1201(a)(2) of the DMCA, and (3) against both defendants for civil conspiracy under New York law. The Court, however, dismisses the claim under section 1201(b) of the DMCA against SerpApi, and the state-law unjust enrichment and unfair competition claims." The state-law claims were preempted by the Copyright Act.
  - **On the downstream customer:**
    - "Perplexity is a customer of SerpApi."
    - SerpApi "allows SerpApi's customers to customize the parameters of such circumvention, including by choosing and inputting operational data that determine 'when, how, and at what scale' the circumvention will occur."
    - Perplexity allegedly "set[s] the parameters for circumvention activity, including geographic location, rendering layouts, language settings, advanced filtering, and other operational inputs" and "conduct[s] the actual queries itself". It is "thus plausibly alleged to 'affirmatively perform[] an action that disables or voids' an access protection measure… In sum, as pled, SerpApi made the circumvention tool, and Perplexity used it to circumvent. On the pleadings, Perplexity is thus more than a bystander to, or a downstream beneficiary of, SerpApi's circumvention."
    - "section 1201(a)(1)(A), which 'targets the use of a circumvention technology, not the trafficking in such a technology,' reaches actors like Perplexity."
    - Footnote: "A person who uses a black box to access cable programming is in the same position under the statute as one who uses a data scraping tool to access copyrighted text-as Perplexity is alleged to have done. Both acts constitute circumvention."
  - **Secondary liability was not decided.** Perplexity argued "a party cannot be held liable as a secondary participant" under §1201. "Because the Court finds that the FAC has plausibly pled Perplexity's direct circumvention, the Court does not have occasion to reach that issue."
  - **Conspiracy:** steps in furtherance by "SerpApi, by providing a circumvention tool, and Perplexity, by paying for and using it". Intent was shown because "Perplexity received a cease-and-desist letter from Reddit yet continued to access and scrape Reddit data."
  - **SearchGuard is an access control:** "A more apt analogy is a facial-recognition technology programmed to open the door of a home for residents but not for other visitors." "Section 1201 does not require that the copyright holder specifically authorized the access control measure that was circumvented."
- **Other defendants** (read by a parallel researcher):
  - Oxylabs' motion to dismiss (filed Jul 21, 2026; reply Sept 8) is still pending. Its arguments are no US conduct, no copyright-owner authorization, that its customers (not Oxylabs) circumvent, and that proxies have lawful uses. — [Dkt 124](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.124.0.pdf), [Dkt 190](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.190.0.pdf)
  - AWMProxy has not been served. — [Dkt 110](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.110.0.pdf)
- **SerpApi's counterclaims** (Sherman Act §2, and declaratory judgments) are under a Reddit motion to dismiss. — [Dkt 119](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.119.0.pdf), [Dkt 183](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.183.0.pdf)
- **Schedule:** jury trial; fact discovery closes about 270 days after Oct 1, 2026, roughly late June 2027. — [Dkt 160](https://storage.courtlistener.com/recap/gov.uscourts.nysd.651592/gov.uscourts.nysd.651592.160.0.pdf) (read by a parallel researcher)

**Other suits and regulatory actions (2024–2026)**
- A parallel researcher found none of the following:
  - another Google suit against a SERP scraper;
  - a Microsoft suit over Bing scraping;
  - EU or UK regulatory action against SERP scrapers.
- Google took "legal action" against the IPIDEA residential proxy network's domains (Jan 28, 2026), framed as security, not scraping. — [Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- Related §1201 rulings on bot defenses, at the pleading stage:
  - **Ace Cam v. Runway AI** (S.D.N.Y., Oct 30, 2026): YouTube's measures plausibly "function as access controls because they condition access to the audiovisual work on the application of authorized processes". Also: "Section 1201(a) does not state or imply that plaintiffs themselves must put in place the technological measures controlling access to their work." — [Ace Cam opinion](https://www.sdnyblog.com/files/2026/11/26-Civ.-01362-2026.10.30-Ace-Cam-v.-Runway-AI-Opinion-Denying-MTD.pdf)
  - **Ted Entertainment v. ByteDance** (N.D. Cal., Oct 2, 2026) also sustained a §1201(a)(1)(A) claim. — [ruling](https://www.courthousenews.com/wp-content/uploads/2026/10/bytedance-motion-dismiss-ruling.pdf) (per a parallel researcher)
  - **Ziff Davis v. OpenAI** (S.D.N.Y., Dec 2025): robots.txt is not a §1201 access control, no more than "a sign requesting that visitors 'keep off the grass'". — [order](https://chatgptiseatingtheworld.com/wp-content/uploads/2025/12/Judge-Stein-order-on-MTD-of-Ziff-Davis.pdf) (per a parallel researcher)
- **Amazon v. Perplexity** (9th Cir. No. 26-1444, Aug 4, 2026), on the CFAA:
  - "It is the user who 'accesses' Amazon's computers, with the help of the Assistant."
  - "We do not address whether, on a different record or new facts, Perplexity may exercise control over the Assistant in such a way as to gain entry to Amazon's servers."
  - Source: [9th Cir. opinion](https://cdn.ca9.uscourts.gov/datastore/opinions/2026/08/04/26-1444.pdf)

**Google's terms on automated queries**
- Google Terms of Service, "Effective July 30, 2026". Under "abuse, harm, interfere with, or disrupt our services or systems", the examples include:
  - "using automated means to access content from any of our services in violation of the machine-readable instructions on our web pages (for example, robots.txt files that disallow crawling, training, or other activities)";
  - "providing services that encourage others to violate these terms".
  - A parallel researcher reports that the assent clause reads "whether you're signed in to a Google account or not", and that the abuse list is unchanged from the May 22, 2024 version.
  - Source: [Google Terms](https://policies.google.com/terms)
- `https://www.google.com/robots.txt` under `User-agent: *`: "Disallow: /search", with only `/search/about` and `/search/howsearchworks` allowed. — [robots.txt](https://www.google.com/robots.txt)
- Google spam policies, machine-generated traffic: "This includes scraping results for rank-checking purposes or other types of automated access to Google Search conducted without express permission." — [Google Search spam policies](https://developers.google.com/search/docs/essentials/spam-policies)
- Google's licensed alternative is closing: "The Custom Search JSON API is closed to new customers… Existing Custom Search JSON API customers have until January 1, 2027 to transition to an alternative solution." Google suggests Vertex AI Search, or contacting it about "our full web search solution". — [Custom Search JSON API overview](https://developers.google.com/custom-search/v1/overview)

**Microsoft/Bing terms**
- Microsoft Services Agreement ("Published: July 30, 2026 Effective: September 30, 2026") — [Microsoft Services Agreement](https://www.microsoft.com/en-us/servicesagreement):
  - §3(a)(vi): "Don't circumvent any restrictions on access to, usage, or availability of the Services (e.g., attempting to 'jailbreak' an AI system or impermissible scraping)."
  - Bing and MSN: "The articles, text, photos, maps, videos, video players, and third-party material available on Bing and MSN … are for your noncommercial, personal use only. Other uses, including downloading, copying, or redistributing these materials, or using these materials or products to build your own products, are permitted only to the extent specifically authorized by Microsoft or rights holders, or allowed by applicable copyright law."
- Microsoft's licensed route also forbids resale. The Grounding with Bing Search enterprise terms ("Last updated: November 2025") say you may not "Redistribute, resell, or sublicense access to the Service or Bing Services Output". Storage is allowed only "as an integrated part of its own work product, so long as the work product is not created for the purpose of or intended for use as a substitute for the Services or the Bing Services Output (for example, creating a database of Bing Services Output". — [Grounding with Bing enterprise terms](https://www.microsoft.com/en-us/bing/apis/grounding-legal-enterprise)
- Microsoft retired the Bing Search APIs on August 11, 2025. — [Microsoft Learn](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement)

**US precedents on scraping public data** (primary links supplied by a parallel researcher; holdings are long-established unless marked 2026)
- **hiQ Labs v. LinkedIn:**
  - 9th Cir. (Apr 18, 2022): "the concept of 'without authorization' does not apply to public websites" under the CFAA. — [9th Cir. opinion](https://cdn.ca9.uscourts.gov/datastore/opinions/2022/04/18/17-16783.pdf)
  - On remand (N.D. Cal., Nov 2022), LinkedIn's User Agreement "unambiguously prohibits hiQ's scraping and unauthorized use of the scraped data". hiQ was liable for its contractors, who "also acted as its agent". — [N.D. Cal. order](https://infobytes.orrick.com/wp-content/uploads/pdf/Buckley%20InfoBytes%20-%20HiQ%20Labs%2C%20Inc.%20v.%20LinkedIn%20Corp.%20-%20Order%202022.11.03.pdf)
  - Settled December 2022 by consent judgment ($500,000, injunction, deletion). — [Proskauer](https://newmedialaw.proskauer.com/2022/12/08/hiq-and-linkedin-reach-proposed-settlement-in-landmark-scraping-case/)
- **Meta v. Bright Data** (N.D. Cal., Jan 23, 2024): "the Terms do not apply to Bright Data's logged-off scraping of publicly viewable data." — [Order](https://www.govinfo.gov/content/pkg/USCOURTS-cand-3_23-cv-00077/pdf/USCOURTS-cand-3_23-cv-00077-7.pdf). Meta then dropped its remaining claim, including tortious interference aimed at Bright Data's customers. — [TechCrunch, Feb 26, 2024](https://techcrunch.com/2024/02/26/meta-drops-lawsuit-against-web-scraping-firm-bright-data-that-sold-millions-of-instagram-records/)
- **X Corp. v. Bright Data** (N.D. Cal., Alsup, J.):
  - May 9, 2024: scraping-based state claims preempted. X "would entrench its own private copyright system that rivals, even conflicts with, the actual copyright system enacted by Congress." — [Order](https://www.govinfo.gov/content/pkg/USCOURTS-cand-3_23-cv-03698/pdf/USCOURTS-cand-3_23-cv-03698-1.pdf)
  - Nov 26, 2024: access-based claims allowed (trespass, contract, §1201(a), CFAA). — [Order](https://www.govinfo.gov/content/pkg/USCOURTS-cand-3_23-cv-03698/pdf/USCOURTS-cand-3_23-cv-03698-3.pdf)
  - Dismissed with prejudice on June 27, 2025 after a confidential settlement; no §1201 ruling. — [Docket](https://www.courtlistener.com/docket/67637345/feed/), [Bloomberg Law](https://news.bloomberglaw.com/ip-law/musks-x-settles-data-scraping-dispute-against-israeli-data-firm)
- **Ryanair v. Booking.com** (D. Del.), a downstream-seller theory:
  - A July 2024 jury found Booking "intentionally directed, encouraged, or induced" its supplier's unauthorized access.
  - The verdict was set aside on Jan 22, 2025 for failure to prove $5,000 loss. — [Opinion](https://www.ded.uscourts.gov/sites/ded/files/opinions/20-1191_1.pdf)
  - The appeal is unresolved as far as found. — [EFF, Jul 2025](https://www.eff.org/deeplinks/2025/07/ryanairs-cfaa-claim-against-bookingcom-has-nothing-do-actual-hacking)
- **Reddit v. Anthropic** (remand order, Mar 30, 2026): Anthropic was "contractually bound by Reddit's User Agreement" through "constructive and actual knowledge". Reddit's state claims have "extra elements that defeat preemption". — [Remand order](https://storage.courtlistener.com/recap/gov.uscourts.cand.452341/gov.uscourts.cand.452341.60.0.pdf). The state court largely denied dismissal in Sept 2026. — [Bloomberg Government](https://news.bgov.com/us-law-week/anthropic-loses-bid-to-dismiss-reddit-ai-scraping-privacy-suit) (secondary)

**EU and UK**
- **Database Directive 96/9/EC:** Art 7(1) bars "extraction and/or re-utilization of the whole or of a substantial part" of a database with "substantial investment". Art 7(5) bars "repeated and systematic" extraction of insubstantial parts. Art 11 limits protection to EU makers. — [Art 7 (UK archive of EU text)](https://www.legislation.gov.uk/eudr/1996/9/article/7), [Art 11](https://www.legislation.gov.uk/eudr/1996/9/article/11)
- **CV-Online Latvia v Melons (C-762/19, June 3, 2021):** an engine that "copies and indexes the whole or a substantial part of a database freely accessible on the Internet" extracts and re-utilises it. The maker may prohibit this where it creates "a risk to the possibility of redeeming that investment". — [ICLR copy](https://www.iclr.co.uk/document/2021002793/casec76219/html)
- **Innoweb (C-202/12, Dec 19, 2013):** a real-time meta-search engine re-utilised the database it queried. — [Kluwer Copyright Blog](https://legalblogs.wolterskluwer.com/copyright-blog/eu-does-innoweb-hinder-innovation-on-the-web/) (commentary; official text not fetched)
- **Ryanair v PR Aviation (C-30/14, 2015):** for databases with neither copyright nor database-right protection, contractual use limits may apply under national law. — [Osborne Clarke](https://marketinglaw.osborneclarke.com/media-and-ip/could-ryanair-control-use-of-its-flight-data-by-pr-aviation-without-database-right/) (commentary)
- **DSM Directive 2019/790:** Art 4's text-and-data-mining exception covers "reproductions and extractions … for the purposes of text and data mining", kept "for as long as is necessary", unless rights are "expressly reserved … such as machine-readable means". It does not cover redisplay or resale. — [Art 4](https://www.legislation.gov.uk/eudr/2019/790/article/4)
- **Kneschke v LAION:** the German Federal Court of Justice (BGH, I ZR 281/25) heard the appeal Sept 3, 2026, and its decision is pending. — [BGH press release 085/2026](https://www.bundesgerichtshof.de/SharedDocs/Pressemitteilungen/DE/2026/2026085.html)
- **Like Company v Google (C-250/25):** Advocate General Szpunar (Nov 3, 2026) said infringement by a chatbot depends on "whether that chatbot accessed the press publication at issue unlawfully, in particular by circumventing effective technical measures (such as a paywall) designed to restrict access to, or web-scraping of, that publication". Judgment is pending. — [CJEU press release](https://curia.europa.eu/site/upload/docs/application/pdf/2026-11/cp260155en.pdf)
- **GDPR:** EDPB Guidelines 03/2026 on web scraping (adopted Jul 7, 2026, for consultation) cover scraping "by contracting another party". They treat robots.txt and CAPTCHAs as lowering what data subjects can reasonably expect. — [EDPB guidelines](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_2020603_webscraping_v1_en_0.pdf). The EU-law items in this section were read by a parallel researcher; I did not re-fetch them.

**Indemnities and "legal shields": how far they reach a reseller** (see section 1 for full quotes)
- **SerpApi U.S. Legal Shield** (Production plan and up; $2M):
  - It covers only "the lawful collection of public search data … but not for how that data is ultimately used".
  - It excludes "DMCA violations".
  - It is limited to "claims brought under U.S. state or federal law in a U.S. court".
  - Source: [SerpApi Legal](https://serpapi.com/legal)
- **SearchApi.io Legal Protection Guarantee** (Production and up; $2M a year):
  - It covers claims arising "solely from SearchApi's own collection and parsing".
  - It excludes "your use, storage, redistribution, or commercialization of data".
  - It is discretionary ("We may, at our discretion, defend, settle, or pay").
  - It "creates no rights for any person or entity other than the account holder".
  - Source: [SearchApi Terms](https://www.searchapi.io/legal/terms)
- **Everyone else makes the customer indemnify the provider:**
  - DataForSEO, for "any use of SERP data that violates the terms of service or legal rights of the search engine providers" (§7.2).
  - Bright Data, Oxylabs, ScrapingBee, Apify: general customer indemnities.
  - Serper's indemnity is mutual.
  - Sources: [DataForSEO Terms](https://dataforseo.com/terms-of-service), [Bright Data MSA](https://brightdata.com/license), [Oxylabs self-service ToS](https://oxylabs.io/legal/self-service-tos), [ScrapingBee Terms](https://www.scrapingbee.com/terms-and-conditions/), [Apify Actor Terms](https://docs.apify.com/legal/actor-terms-and-conditions), [Serper Terms](https://serper.dev/terms)

### Inferences
- **Downstream exposure is real and specific.**
  - Under Reddit v. SerpApi, a customer that chooses the queries and parameters and sends them through a scraper is pleaded as a *direct* §1201(a)(1)(A) circumventor, not a bystander.
  - A sidecar relay that turns each user's or agent's search into a scraper call looks like Perplexity on these facts.
  - Being a reseller adds no shield. It adds more queries and paying third parties.
  - Statutory damages run $200–$2,500 "per act" of circumvention (as pleaded by Google). At agent-scale volumes that is a large theoretical exposure, even though courts rarely award statutory damages per query.
- **The claim depends on what is in the results and who sues.**
  - Results with "no copyrighted content" are out of §1201 in N.D. Cal. (Google v. SerpApi).
  - Copyrighted snippets, images, Knowledge Panels, or licensed content such as Reddit posts bring §1201 back.
  - Rights holders with a Google content deal (Reddit, publishers) are the most capable plaintiffs.
  - The S.D.N.Y. view, that any authorized party's access control counts, is broader than the N.D. Cal. view.
  - Before any final judgment, the circuit split between the two district courts is the key uncertainty.
- **Notice raises the stakes.** The conspiracy claim against Perplexity rested partly on its carrying on after a cease-and-desist. A reseller that keeps going after a rights holder's notice would look worse.
- **Injunction spillover.** Google's complaint asks to enjoin "those persons in active concert or participation with" SerpApi. If such relief were granted, customers' supply could be cut by court order, not just by technical blocking.
- **Contract and CFAA risk is lower but not zero.**
  - Logged-off scraping beat Meta's terms. X's scraping claims were preempted. hiQ narrowed the CFAA.
  - But Google's terms bar "providing services that encourage others to violate these terms". Microsoft's bar helping others break its rules and bar building products on Bing content. Both could matter if URnetwork itself is a Google or Microsoft account holder.
  - Reddit v. Anthropic shows knowledge-based contract formation is still argued and sometimes wins in state court.
- **EU exposure differs.** Innoweb's meta-search holding is close to a live relay of Google results. Google's maker status under Art 11 and the "substantial part" test are untested for search results. GDPR controller duties apply to personal data in results, and to any stored copies.
- **The shields do not help with URnetwork's real risks.** They cover the scraper's own collection, at most, for the account holder only. They exclude DMCA claims (SerpApi) or redistribution and commercialization (SearchApi.io). They do not cover URnetwork's end users.

### Gaps
- Final outcomes are unknown:
  - Google may file a second amended complaint by Dec 10, 2026, or the case ends with prejudice.
  - The Oxylabs motion in Reddit is pending.
  - Secondary liability under §1201 is undecided (Reddit opinion, footnote 25).
  - No court has ruled on the merits against any scraper customer.
- I found no case holding a mere buyer or reseller of scraped search results liable on the merits.
- Docket entries not uploaded to RECAP, and paywalled Law360 and Bloomberg Law coverage, were not read.
- Read by a parallel researcher rather than by me, so I did not re-check them:
  - Dkt 45 (amended complaint);
  - Reddit docket entries other than Dkt 104 (Oxylabs, AWMProxy, counterclaims, schedule);
  - Ted Entertainment, Ziff Davis, Reddit v. Anthropic;
  - all EU items (EUR-Lex and InfoCuria blocked automated fetching; the directive texts used are the UK archive copies).
- No Microsoft enforcement action over Bing scraping was found. The Bing risk rests on terms only.

## 3. Privacy: what each scraper logs about the queries it forwards, and for how long

### Takeaway
Every provider forwards the query text to Google from its own (or a proxy partner's) IP addresses, so Google never sees the end user's IP. But every provider except Serper (which says it caches nothing) keeps the query and results for a while, from 48 hours to a year:

| Provider | Retention of queries and results |
|---|---|
| Bright Data (async) | 48 hours |
| Serper | says it caches nothing |
| SerpApi | 31 days; ZeroTrace (none) only on Enterprise and the self-serve Cloud 1M+ plans (from $3,750/month) |
| DataForSEO | 31 days for SERP output under the DPA; 365 days for task data |
| SearchApi.io | "scheduled" cache purges; no period given |
| Apify | by plan; 4 months on Free |

Bright Data's MSA also reserves the right to "retain data Client has collected and … use it for its own purposes". Only SerpApi sells a contractual no-retention mode, and only from about $3,750 a month. DataForSEO says it does not offer zero data retention.

### Cited Findings
- **SerpApi.**
  - "Search data is retained for 31 days after the search is completed, after which it expires and is deleted automatically. Customers who enable ZeroTrace Mode prevent search parameters, queries, and results from being stored on our systems entirely." (Privacy Policy §10) — [SerpApi Legal](https://serpapi.com/legal)
  - Subprocessors include "Various proxy providers: process requests to the search engines. For ZeroTrace Mode searches, requests include a Do Not Track (DNT) non-retention signal." Others are AWS, Cloudflare, "Wasabi … cloud object storage" and Airbrake. — [SerpApi Legal](https://serpapi.com/legal)
  - ZeroTrace "is only included in Enterprise plans". "We skip saving parameters, metadata, and the actual search in our database entirely… For third-party services or search engines outside our direct control, in certain cases, we add a Do Not Track (DNT) header." "there may be certain instances where SerpApi is required by law to maintain the search information for a period of time." — [SerpApi ZeroTrace](https://serpapi.com/zero-trace-mode)
  - The pricing page's plan data marks `zero_trace: true` on the self-serve "Cloud 1M" plan ($3,750 a month) and above, and `false` on every smaller plan. So the cheapest no-retention SerpApi plan is about $3,750 a month. — [SerpApi Pricing](https://serpapi.com/pricing)
- **Serper.**
  - "whenever you call our API we directly query Google for the latest results. We do not cache anything." — [Serper home/pricing](https://serper.dev/)
  - The privacy policy ("Date Last Reviewed: 5 November 2025") covers account data, including "access logs and activity logs", retained "as long as you have an account with us". It says "The provision of the services offered by Serper should normally not lead to the processing of personal data". It is silent on query logs. — [Serper Privacy](https://serper.dev/privacy)
- **DataForSEO.**
  - "we store Your DataForSEO API tasks data for You for 365 days"; "All data that has been stored for more than 365 days will be permanently deleted from our system." — [DataForSEO Privacy](https://dataforseo.com/privacy-policy)
  - Legal FAQ: "DPA Annex I.B(7), for personal data under GDPR – 31 days for SERP API output, 7 days for HTML, 6 months for pingback/postback results, 12 months for client tasks/results/payload." Also: "We do not offer zero data retention." — [DataForSEO legal FAQ](https://dataforseo.com/help-center/quick-answers-to-frequently-asked-legal-questions)
- **SearchApi.io.**
  - The DPA lists processing as "receiving and routing API requests; caching search results for performance optimization; logging API usage for billing, rate limiting, and abuse prevention". Processed data includes "Search queries (which may contain Personal Data entered by end users); IP addresses associated with API requests". "Caches are automatically purged on a scheduled basis. Application logs are retained for a limited period." — [SearchApi DPA](https://www.searchapi.io/legal/dpa)
  - On cancellation, "search result data (cached HTML and JSON responses stored on our servers) is automatically purged in accordance with our standard data retention schedule."
  - Government requests: "SearchApi, LLC is a US company and all data infrastructure are located in the US." It refuses non-US government requests "unless the US government compels us to comply through procedures outlined in a mutual legal assistance treaty".
  - Sources for the last two points: [SearchApi Privacy (Apr 11, 2026)](https://www.searchapi.io/legal/privacy)
- **Zenserp.** The privacy page is Idera's Privacy Notice ("Modified and Effective on October 5, 2026"). It retains personal data "to the extent necessary to reasonably serve customer relations, to meet our compliance and legal obligations…" and gives no query-log period. — [Zenserp/Idera privacy](https://zenserp.com/privacy-policy)
- **ScrapingBee.** "As part of Our activities, VostokInc archives and logs all actions performed on the API by the User's employees." "Personal Data relating to prospects or Customers is deleted within 3 years of its collection or within 3 years of the last contact." No period is stated for request logs. — [ScrapingBee Privacy](https://www.scrapingbee.com/privacy-policy/)
- **Bright Data.**
  - Under "Proxy Services and Scraping Browser API": "Bright Data may retain data Client has collected and may use it for its own purposes in its sole discretion." The Web Scraper IDE block has the same right over data "collected or delivered to its Clients". — [Bright Data MSA](https://brightdata.com/license)
  - SERP API async: "the result is stored for 48 hours". — [Bright Data sync vs async](https://docs.brightdata.com/concepts/sync-vs-async.md)
  - KYC collects ID documents. — [Bright Data Privacy](https://brightdata.com/privacy)
- **Oxylabs.**
  - "Oxylabs retains the right in its sole discretion to monitor Customer's use of Services" (self-service §4.3.7). — [Oxylabs self-service ToS](https://oxylabs.io/legal/self-service-tos)
  - The privacy policy gives retention only for communications ("up to 5 years"). — [Oxylabs Privacy](https://oxylabs.io/legal/privacy)
  - A search snippet of Oxylabs' Push-Pull docs says results stay retrievable for "at least 24 hours". I could not confirm that on the fetched page. — [Oxylabs Push-Pull docs](https://developers.oxylabs.io/products/web-scraper-api/integration-methods/push-pull)
- **Apify.**
  - "Free plan: Your 10 most recent runs are retained for 4 months. Paid plans: All data … follows your plan's retention period… Named storages: Always exempt from deletion." — [Apify storage docs](https://docs.apify.com/platform/storage/usage)
  - "All rights, title, and interest in and to Usage Data … shall belong exclusively to us." — [Apify General Terms](https://docs.apify.com/legal/general-terms-and-conditions)
  - Community actors' creators "may have direct access to or control over the Actor Inputs and Actor Outputs". — [Apify Actor Terms](https://docs.apify.com/legal/actor-terms-and-conditions)

### Inferences
- For an end-to-end-encrypted product, the scraper is a trusted third party that sees every query in clear text, tied to URnetwork's account, not to the person.
  - If URnetwork strips user identifiers and pools queries under one account, the scraper and Google see a stream of queries from "URnetwork". They do not see individuals, unless a query itself identifies the person.
  - That is the same exposure as Brave, whose ZDR is also enterprise-only.
- Lowest retention on paper:
  - Serper: no cache claimed, but no contractual retention term at all.
  - Bright Data async: 48 hours, but the MSA grants broad reuse rights.
  - SerpApi Cloud 1M+ or Enterprise with `zero_trace=true`: no storage, contractually stated.
- Highest retention: DataForSEO (365 days for task data, no ZDR).

### Gaps
- Serper, Oxylabs, ScrapingBee, Zenserp and Bright Data (synchronous requests) publish no retention period for query logs.
- Whether SerpApi's "Various proxy providers" (which see the query) retain it is not stated. SerpApi sends them only a DNT signal for ZeroTrace searches.
- I did not find any provider's transparency report on government requests for query data.

## 4. Continuity: has Google's anti-scraping work in 2025–2026 broken, degraded or repriced these services?

### Takeaway
Google's countermeasures have degraded these services repeatedly but have not driven any of the nine out of business. Headline prices for a first-page Google request have held or fallen since 2024. The cost increases show up in billing structure instead: per-10-result-page billing since Google killed `&num=100` in September 2025, and new surcharges.

Three waves:
1. **January 2025:** Google began requiring JavaScript (SearchGuard). That caused short outages at some providers. Google's own complaint says SearchGuard "effectively blocked SerpApi" at launch.
2. **September 2025:** Google removed `&num=100`. Top-100 results now cost about 8–10 times more where providers bill per page.
3. **September–November 2026:** Waves of "poisoned"/irrelevant results and tighter limits hit every provider. SerpApi's incident is still open as of 2026-11-23.

Bing is a separate problem:
- Microsoft retired its Bing Search APIs on 2025-08-11.
- Scraping Bing has also become less reliable.

For a sidecar that needs only the top 10 results, price risk is low. Reliability and result-quality risk is real and rising.

### Cited Findings

**January 2025: JavaScript requirement ("SearchGuard")**
- SerpApi (Jan 17, 2025): "As of January 15, 2025, Google made significant changes to its search engine. Users are now required to have JavaScript enabled in the browser in order to access Google Search results." — [SerpApi blog](https://serpapi.com/blog/google-now-requires-javascript/)
- Google's complaint, ¶30: "When SearchGuard launched in January 2025, it effectively blocked SerpApi from accessing Google's Search results … But SerpApi immediately began working on a means to circumvent." ¶21: SerpApi "sends hundreds of millions of artificial search requests each day … Over the last two years, that volume has increased by as much as 25,000%." — [Google v. SerpApi complaint, Dkt 1 (Dec 19, 2025)](https://storage.courtlistener.com/recap/gov.uscourts.cand.461513/gov.uscourts.cand.461513.1.0.pdf)
- Serper's status page logged two "Outage APIs" incidents on 2025-01-16 and 2025-01-17, attributed to "recent changes on Google's end". — [Serper status history](https://serper.betteruptime.com/incidents/2024-11/2025-01)
- Other providers on the same change:
  - DataForSEO: "business as usual". — [DataForSEO blog, 2025-01-18](https://dataforseo.com/blog/api-rates-steady-amid-serp-data-outage)
  - Oxylabs: "same performance". — [Oxylabs blog, updated 2025-02-10](https://oxylabs.io/blog/google-search-javascript)
  - These were read by a parallel researcher. I did not re-fetch them.

**September 2025: Google drops `&num=100`**
- DataForSEO (Sept 13, 2025): "Google just dropped support of the &num=100 feature … Google returns ten results on each SERP page by default in most cases." — [DataForSEO update](https://dataforseo.com/update/google-organic-serp-api-critical-updates-depth)
- DataForSEO (Sept 16, 2025): "our earlier price basis (fixed per 100 results for most search engines) no longer matches the effort … What's changing on September 19, 2025 … The number of results – depth – covered by the base price of Organic SERP APIs changes to 10 (first page) … Additional pages in the same task are 25% off." — [DataForSEO pricing update](https://dataforseo.com/update/important-serp-api-remains-fully-operational-pricing-update)
- The current DataForSEO pricing page charges "+1 base price per each additional 10 results" and makes no mention of the 25% discount. — [DataForSEO Google Organic pricing](https://dataforseo.com/pricing/serp/google-organic-serp-api)
- SerpApi made no billing change. Its own FAQ says a response with 100 results still counts as one search. It reported that users usually get "10 organic_results despite attempting to get 100". — [SerpApi Pricing](https://serpapi.com/pricing), [SerpApi blog, 2025-09-16](https://serpapi.com/blog/google-experiments-with-restricting-results-per-page/) (blog read by a parallel researcher)
- Other responses:
  - SearchApi.io launched a "Rank Tracking API" returning up to 100 results per request. — [SearchApi announcement, 2025-10-02](https://www.searchapi.io/announcements/30)
  - Bright Data dates the change to 2025-09-10 and offers a top-100 endpoint billed as one request. — [Bright Data SERP FAQ](https://docs.brightdata.com/products/serp-api/faqs)
  - Both were read by a parallel researcher, not re-fetched by me.
- Rank trackers cut depth rather than raise prices. AccuRanker tracks top 30 daily and top 100 every second week with "no price increase". — [AccuRanker](https://www.accuranker.com/depth-update)

**2026: poisoned results, throttling, surcharges**
- SerpApi's status incident "Searches returning irrelevant/poisoned results", affecting "our Google Search and Google Shopping APIs", is still open:
  - Nov 16, 2026: "While we've made progress in reducing irrelevant results, the issue hasn't been fully resolved yet."
  - Nov 23, 2026, 10:11 UTC: "Our team continues to work towards a permanent solution."
  - Source: [SerpApi status incident](https://status.serpapi.com/incidents/bhj19czp9b04)
- DataForSEO now sells a `resolve_poisoned_results` option at "+1 base price, Total = 2x base price". — [DataForSEO Google Organic pricing](https://dataforseo.com/pricing/serp/google-organic-serp-api). It was announced 2026-11-16. A parallel researcher reports it is charged "to every task … regardless … whether poisoned results are detected" (I did not re-read this). — [DataForSEO update, 2026-11-16](https://dataforseo.com/update/detect-and-resolve-poisoned-google-results-with-dataforseo-serp-api)
- Industry measurements of poisoned results (vendor figures; Google has not confirmed the practice; read by a parallel researcher, not re-fetched by me):
  - Nozzle: 8.0% of pages from 2026-09-13, peaking near 27% around Sept 27–29. — [ppc.land, 2026-10-19](https://ppc.land/google-feeds-rank-trackers-swapped-results-on-8-of-pages-nozzle-finds/)
  - DataForSEO: 20–30% since Sept 26. — [DataForSEO blog, 2026-10-23, updated 2026-11-16](https://dataforseo.com/blog/poisoned-serps-whats-happening-with-google-results-and-what-were-doing-about-it)
  - Ahrefs: 5–20% depending on provider. — [Ahrefs, 2026-10-22](https://ahrefs.com/blog/serp-data-update/)
- Serper's status history records throttling:
  - higher latency for "repeated non-generic queries … due to changes by Google" (Aug 7–10 and Aug 31, 2026);
  - a "permanent change" to News queries using `site:` (Aug 25);
  - "Google tightened its limits again" (Nov 6);
  - "Altered Google rankings … affects all providers" (Nov 20–23).
  - Sources: [Serper status, Aug–Oct 2026](https://serper.betteruptime.com/incidents/2026-08/2026-10), [Serper status, Nov 2026–Jan 2027](https://serper.betteruptime.com/incidents/2026-11/2027-01) (read by a parallel researcher)
- Apify's "Google SERP proxy" had "degraded performance" on 2026-08-03 and 2026-08-07. — [isdown.app, Aug 3](https://isdown.app/status/apify/incidents/633260-degraded-performance-of-google-serp-proxy), [isdown.app, Aug 7](https://isdown.app/status/apify/incidents/635498-degraded-performance-of-google-serp-proxy) (aggregator)
- Earlier SerpApi incidents (read by a parallel researcher):
  - Jul 3–12, 2026.
  - Sept 10, 2026 (7 days).
  - Oct 1 (6 days).
  - Empty paginated results from Oct 21 (21 days).
  - Source: [openstatus.dev SerpApi page](https://www.openstatus.dev/status/serpapi/api.md)
- Google's own licensed alternative is closing: "The Custom Search JSON API is closed to new customers… Existing Custom Search JSON API customers have until January 1, 2027 to transition to an alternative solution." — [Custom Search JSON API overview](https://developers.google.com/custom-search/v1/overview). Secondary sources date the announcement to about 2026-01-20. — [Firecrawl blog](https://www.firecrawl.dev/blog/google-search-json-api-alternative), [Bright Data blog](https://brightdata.com/blog/web-data/google-search-api)
- Price moves:
  - DataForSEO raised about eight non-SERP APIs by about 20% from 2026-07-01. The SERP API was not on the list. — [DataForSEO pricing update](https://dataforseo.com/update/pricing-update-in-dataforseo-apis) (per parallel researcher)
  - AI Overview surcharges: Zenserp ("An AI Overview request uses 3 searches") — [Zenserp pricing](https://zenserp.com/pricing-plans/); DataForSEO `load_async_ai_overview` "+1 base price" — [DataForSEO pricing](https://dataforseo.com/pricing/serp/google-organic-serp-api).
- Consolidation, not exits: Oxylabs' group bought ScrapingBee (deal dated 2025-06-19), and ScrapingBee still runs as a separate brand. — [tech.eu, 2025-06-20](https://tech.eu/2025/06/20/oxylabs-group-strengthens-position-with-eight-figure-acquisition-of-scrapingbee/) (URL from search results, not fetched)

**Bing**
- "Bing Search APIs will be retired on August 11, 2025 … decommissioned completely". Microsoft points customers to "Grounding with Bing Search" in Azure AI Agents. — [Microsoft Learn lifecycle announcement](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement)
- Grounding with Bing is reported at $35 per 1,000 transactions, against $25/$15/$6 for the old S1/S2/S3 tiers. — [ppc.land, 2025-06-09](https://ppc.land/microsoft-ends-bing-search-apis-on-august-11-alternative-costs-40-483-more/) (secondary)
- SerpApi's Bing release notes log a run of problems:
  - captchas (2025-08-14);
  - low-quality results from `count` (2025-11-26);
  - a falling success rate (2026-02-15);
  - broken pagination (2026-07-08);
  - soft blocks (Jul 14 and Aug 3, 2026);
  - irrelevant results (Nov 6, 2026).
  - Source: [SerpApi Bing release notes](https://serpapi.com/bing-search-api/release-notes) (per parallel researcher)

**Price per 1,000 Google requests, then and now** (from Wayback Machine snapshots of each pricing page, read by a parallel researcher on 2026-11-23; current figures checked by me against the live pages in section 1)

| Provider | 2024 to early 2025 | Now | Change |
|---|---|---|---|
| SerpApi | $15.00 / $10.00 / $9.17 | Same. A new $25 Starter tier was added between 2025-12-12 and 2026-01-06; the free tier rose from 100 to 250 searches | none |
| Serper | $1.00–$0.30 | Same | none |
| DataForSEO | $0.60 / $1.20 / $2.00 per 100 results | Same dollar amounts per 10 results | top-100 now about 8–10× dearer |
| SearchApi.io | $4.00–$1.00 | Same | none |
| Zenserp | $10.00–$1.60 | $2.00–$0.90, changed between 2026-01-23 and 2026-02-05 | cut |
| ScrapingBee (Google) | 25 credits a search | 15 credits, or 10 in Light mode, from mid-2025 | cut |
| Bright Data | $3.00 pay-as-you-go | $1.50 pay-as-you-go; changed between 2024-12-13 and 2025-01-23 | cut |
| Oxylabs | $2.80–$2.40 | $1.00–$0.50 | cut |
| Apify | $3.50 per 1,000 pages | From $1.80 per 1,000 pages, event-billed since 2025-09-02; a page is now 10 results, not 100 | cut |

### Inferences
- **Continuity risk now comes from upstream quality, not price.**
  - Since September 2026 every provider has been fighting Google's apparent result "poisoning", which is silent corruption rather than clean failure.
  - Agents that trust SERP snippets could be fed irrelevant results with no error signal.
  - A sidecar relay would need its own quality checks, and probably two providers to fail over between.
- **The September 2025 change barely matters for an agent tool that needs ten results.** It mostly hurts rank trackers. Requests for deeper results are now multiples of the base price at DataForSEO and Apify.
- **The legal track is linked to continuity.**
  - Google's suit (section 2) asks for an injunction reaching "those persons in active concert or participation with them".
  - If Google ever won, SerpApi-dependent products would lose the source abruptly.
  - SerpApi's and Serper's open incidents show that Google can degrade service at will without winning in court.
- **Bing via scrapers is a weaker fallback than Google.** Its official API is gone, and SerpApi's Bing notes show steady degradation through 2026.

### Gaps
- I could not re-fetch the Wayback snapshots behind the price-history table myself (the Wayback Machine returned HTTP 429). The "then" column rests on a parallel researcher's snapshot reads. Change dates are bracketed by snapshot dates, not exact.
- Third-party commentary is not primary evidence: the poisoned-results percentages, the Custom Search announcement date and the Grounding with Bing price.
- Serper, Zenserp, ScrapingBee and Oxylabs published no statement on `num=100` that I found. DataForSEO's status page did not render without JavaScript.
- Whether DataForSEO still discounts additional pages by 25% is unclear. The current pricing page charges full base price per page.
