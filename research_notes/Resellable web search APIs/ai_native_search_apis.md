# AI-native web search APIs that URnetwork might resell instead of Brave (as of 2026-11-23)

Scope and method. Every page cited here was fetched on 2026-11-23. Most were fetched as raw HTML, PDF or Markdown with curl and converted to text, so the quotes are verbatim and not model paraphrase. Where a vendor publishes Markdown docs (`.md` URLs or `llms.txt`), those copies were used. Pages that could not be read are listed under Gaps. Brave is not re-researched. The baseline is section 4 of `research_notes/Brave web search tool/brave_search_api.md` (Brave Search API Terms of Use, 1 Sep 2026). Those terms forbid:
- storing results beyond "transient storage required for operation";
- derivative works;
- making the API available to third parties;
- replicating the API;
- "redistribute, resell, or sublicense the Search Results";
- AI training or benchmarking on results.

The intended use being tested, called "the URnetwork use" below:
1. One URnetwork account and key, with every call made by URnetwork's relay.
2. Each end user charged per search from a prepaid balance, at cost plus about 20%.
3. Results shown in URnetwork's apps and given to the person's agents.
4. Results passed through a local gateway and MCP tool to the person's own harnesses (Codex, Claude Code, OpenCode).
5. A copy kept in the person's E2EE record.
6. No provider-side LLM generation (TEE rule).

Governing documents, as fetched:

| Provider | Binding document for API use | Date shown | URL |
|---|---|---|---|
| Exa | Terms of Service (PDF served from /terms) | No "Last Revised" date in the text. The PDF's metadata says it was created 2025-03-04 | https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf |
| Exa | Privacy Policy | "Last updated: June 29, 2026" | https://exa.ai/privacy-policy |
| Tavily | Platform Terms of Service | "Last updated: May 4, 2026" | https://www.tavily.com/terms |
| Tavily | Acceptable Use Policy | "Last updated: October 21, 2026" | https://www.tavily.com/acceptable-use-policy |
| Tavily | Privacy Policy | "Last updated: November 24, 2025" | https://www.tavily.com/privacy |
| Parallel | Customer Terms (API) | "Effective date: November 10, 2026" | https://parallel.ai/customer-terms |
| Parallel | Privacy Policy | "Effective date: August 11, 2026" | https://parallel.ai/privacy-policy |
| Linkup | Client General Terms and Conditions | "Last update: August 2025" | https://www.linkup.so/terms-of-use (the text is streamed into the page). A Notion copy at https://linkup-platform.notion.site/Linkup-Client-General-Terms-and-Conditions-13f161ecef69806784dfe808b4e162a1 could not be fetched |
| You.com | Master Services Agreement (Online) | "MSA v.121525" (December 2025) | https://45321510.fs1.hubspotusercontent-na1.net/hubfs/45321510/Legal/You.com%20MSA%20(Online)%20(December%202025).pdf |
| You.com | Terms of Service (website and apps) | "Last updated: August 27, 2024" | https://you.com/terms |
| You.com | DPA | "Last updated: December 12, 2025" | https://you.com/dpa |
| Perplexity | Perplexity Search Addendum (governs `/search`) | "Last updated September 22, 2025" | https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search |
| Perplexity | Perplexity API Terms of Service | "Last updated January 23, 2026" | https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service |
| Perplexity | Acceptable Use Policy | "Last updated July 8, 2025" | https://www.perplexity.ai/hub/legal/aup |
| Jina AI (Elastic) | Legal Information / Terms and Conditions | "Last Modified: May. 04, 2026" | https://jina.ai/legal |
| Firecrawl | Terms of Service | "Date of last revision: October 7, 2026" | https://www.firecrawl.dev/terms-of-service |
| Firecrawl | Privacy Policy | "Date of last revision: December 26, 2024" | https://www.firecrawl.dev/privacy-policy |
| Valyu | Platform Service Agreement | "Last updated: October 20 2025" | https://www.valyu.ai/valyu-platform-service-agreement |
| Valyu | Acceptable Use Policy | "Last updated: 06/11/25" (could be 6 Nov 2025 or 11 Jun 2025) | https://www.valyu.ai/valyu-acceptable-use-policy |
| Valyu | Website Terms | "Last updated: October 20 2025" | https://www.valyu.ai/terms |

## 1. Do the terms permit (a) per-search end-user charging, (b) passing results to end users and their own third-party tools, (c) storing results, including in a user's encrypted record, (d) wholesale resale or a reseller program?

### Takeaway
No provider's standard self-serve terms expressly bless the full URnetwork use. Several are clearly looser than Brave, and two run reseller or partner programs.

- **Parallel.** Its Customer Terms are the only ones written for this shape. They say: "make Customer Applications available to End Customers". Output must be "primarily for the use of one End Customer only" and must not be cached or served to other users. There is no ban on charging.
- **You.com.** The MSA "assigns to Customer all of our right, title, and interest" in Outputs, which favors storage. It bars selling or distributing the Services and trading API keys.
- **Jina.** It "imposes no restrictions on the Customer regarding the use of the Output". But s.jina.ai proxies Google and Bing (see Q4).
- **Tavily.** Use is "solely for Customer's internal business purposes, including for integration with Customer Applications". Output falls outside the resale clause, and there is a formal partner and marketplace program.
- **Exa.** The ToS is among the most restrictive texts on paper. It bars copying, transmitting or offering for sale "any information … obtained from or through, the Services" without written permission, and reselling without consent. But Exa runs a partner program whose tracks include "Resell the API", and it advertises inference providers (OpenRouter) offering Exa natively to their users.
- **Linkup.** It licenses results only under the EU text-and-data-mining exception, with retention limited to that purpose. It forbids acting "as a wrapper".
- **Perplexity.** Customers do not own `/search` output. Perplexity may "retain, copy, distribute and otherwise use Search Data". No personal data may be sent without written authorization. "Service bureau" use and substitute services are barred.
- **Valyu.** Its agreement forbids "resell or sublicense Outputs" and caching beyond documented windows.
- **Firecrawl.** Its ToS bans "any commercial purposes except as expressly authorized".

### Cited Findings

#### Exa (Exa Labs, Inc.)
- License: "we hereby grant you and your Authorized Users a non-exclusive, non-transferable, non-sublicensable, worldwide, revocable right and license to use our APIs for the limited purposes set forth in the documentation for the Services… We may terminate your right to use the API at any time." (§1.1) — [Exa ToS PDF](https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf)
- (a)/(d) Restrictions, 4.2: "You may not do, and may not permit any of your Authorized Users to do, any of the following… unless applicable laws or regulations prohibit these restrictions or you have our written permission to do so:
  - (a) download, modify, copy, distribute, transmit, display, perform, reproduce, duplicate, publish, license, create derivative works from, or offer for sale any information contained on, or obtained from or through, the Services, except for temporary files that are automatically cached by your web browser for display purposes, or as otherwise expressly permitted in these Terms or by us in writing;
  - … (e) resell, lease or sublicense the Services to any third party without our prior consent;
  - (f) access, use or exploit the Services (including Output) to develop any competitive product or service;
  - … (n) access or use the Services in any way not (i) expressly permitted by these Terms or (ii) in accordance with any related Documentation."
  - Source: [Exa ToS PDF](https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf)
- (b) The ToS has no "end user" concept. It speaks only of "Authorized Users": "You are responsible for ensuring that only Authorized Users access and use the Services and for such Authorized Users' compliance with this Agreement." — [Exa ToS PDF](https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf)
- Exa's license over customer data: "You grant us a nonexclusive, royalty-free, transferable, sub-licensable, worldwide, perpetual and irrevocable license to access, use, host, cache, store, reproduce, transmit, display, publish, distribute, and modify any User Input and Output as needed to provide, develop and improve upon our products and services…" (§1.2(c)) — [Exa ToS PDF](https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf)
- Other agreements: "You may purchase and/or receive additional services that are subject to the Master Subscription Agreement and/or another agreement… in the event of any conflict… the Additional Terms shall control." Enterprise offers "Custom MSA and DPA". The ToS's DPA reference is an unfilled placeholder: "Data Processing Agreement ('DPA') available at [LINK]". — [Exa ToS PDF](https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf); [Exa pricing](https://exa.ai/pricing)
- (d) The partner program explicitly covers resale: "Bring your solution to market with Exa. Resell the API, embed it in your customer deployments, and lead enterprise adoption of agent-native search in your region, industry, or vertical." Another track: "Integrate our search layer into your product, platform, or framework so your users get agent-native search as a first-class capability". Contact: partnerships@exa.ai. — [Exa partners](https://exa.ai/partners)
- (a)/(b) Precedent for pass-through to end users:
  - "Inference providers call Exa Search server-side and offer web search as a built-in feature, so developers have access to native search without needing a second vendor key… OpenRouter uses Exa as the default search for models without built-in search."
  - "How do inference providers pay for Exa? Per request or by contract… Providers that wish to offer Exa natively can learn more with our partner program."
  - Source: [Exa inference-providers page](https://exa.ai/use-cases/inference-providers)

#### Tavily (AlphaAI Technologies Inc. d/b/a Tavily, part of Nebius)
- License (§2): "a non-exclusive, revocable…, non-transferable, and non-sublicensable right… to install, access, and use the Tavily APIs… including integration of the Services with Customer Applications via the Tavily API, solely for Customer's internal business purposes… For the avoidance of doubt, the Tavily API, including any Agent Key, is intended solely for Customer's use, may not be transferred, assigned, shared, or otherwise made available to any third party, and may not be used by any third party without Tavily's prior written consent." — [Tavily Platform ToS, May 4 2026](https://www.tavily.com/terms)
- Definitions:
  - "'Customer Applications' means one or more Customer software applications, platforms and/or services (which may include without limitation, AI Tools), including third party platforms, services and/or applications…"
  - "'Output' means the outputs or results delivered… including the generated text, information, links or other materials…"
  - "For clarity, the term 'Services' does not include Output." (§1.7)
  - Source: [Tavily ToS](https://www.tavily.com/terms)
- (a)/(d) §3.2: "The Services are provided solely for Customer's internal business purposes, including for integration with Customer Applications. Customer will not…:
  - (ii) license, sublicense, resell, distribute, lease, rent, lend, transfer, assign or otherwise dispose of the Services (provided, that integration of the Services in Customer Applications in accordance with this Agreement will not constitute a violation of this subsection);
  - … (v) access the Services in order to build a competitive product or service; (vi) compete with Tavily or its business;
  - … (x) disclose to any third party any performance information or analysis relating to the Services;
  - … (xiii) attempt to cloak or conceal Customer's identity or the identity of any Customer Applications when accessing the Services…"
  - Source: [Tavily ToS](https://www.tavily.com/terms)
- (b) §3.5 End Users: "If the Customer Application involves providing access to the Services by end users who are third parties outside of Customer's organization…, Customer shall ensure that: (i) its terms of use… do not impose any additional obligations… on Tavily…; (ii)… do not imply any agency, partnership, or joint venture…; and (iii) any claims… arising from such third-party users' use… are handled exclusively between Customer and such end users." — [Tavily ToS](https://www.tavily.com/terms)
- (b) AUP §4, Downstream Users: "If Customer permits any third party, including its employees, contractors, agents, customers, or end users (collectively, 'Downstream Users'), to access or use the Services, whether directly or indirectly through Customer's applications, products, or services, Customer shall (a) impose on such Downstream Users terms and conditions that are at least as restrictive as the obligations set forth in this AUP, (b) use commercially reasonable efforts to monitor and enforce compliance…, and (c) promptly notify Tavily…" — [Tavily AUP, Oct 21 2026](https://www.tavily.com/acceptable-use-policy)
- (a) The AUP names resale as something Tavily may question: "where Tavily reasonably suspects that Customer is using the Services or Outputs for person-level profiling, high-impact decision-making, bulk person-level collection, resale, or another use restricted under this AUP, Tavily may require Customer to provide reasonable information regarding: (a) the relevant use case and purpose…" — [Tavily AUP](https://www.tavily.com/acceptable-use-policy)
- (c) Neither the ToS nor the AUP restricts storing or caching Output. The AUP bans automated harvesting of "the Services (including any data or content made available through the Services)… except as expressly permitted by the Services". — [Tavily AUP](https://www.tavily.com/acceptable-use-policy)
- (d) Authorized resellers are contemplated: "If Customer has purchased the Subscription… from a partner, marketplace, reseller or distributor authorized by Tavily ('Partner')…" — [Tavily ToS](https://www.tavily.com/terms)
- (d) Partner program: "Our marketplace partners distribute Tavily's API through their cloud platforms and tool catalogs". "Our tech partners integrate Tavily as a native, built-in tool within their developer frameworks and agent orchestration platforms." There is also co-selling and an SI/consulting track. — [Tavily partnerships](https://www.tavily.com/partnerships)
- Volume ceiling: "if Customer uses more than 30,000,000 (thirty million) credits in any 12-month period, additional charges and terms may apply." (§4.1) — [Tavily ToS](https://www.tavily.com/terms)
- Termination (§15.3): "Tavily may immediately, and without prior notice, temporarily or permanently limit, suspend, or terminate your use… for: (a) your breach of this Agreement…". §15.4: "Tavily may, at its sole discretion and without prior notice, cease operation of the Services (or any portion thereof)…" — [Tavily ToS](https://www.tavily.com/terms)

#### Parallel Web Systems
- (b) Definitions:
  - "'End Customers' means Customer's end customers who have been authorized by Customer to access and use the Services as integrated via the Parallel API(s) into the Customer's applications, products, or services (each, a 'Customer Application'), and who have agreed to be bound by terms and conditions at least as protective of the Parallel IP as those hereunder."
  - "'Authorized Users'" includes "the End Customers".
  - Source: [Parallel Customer Terms, Nov 10 2026](https://parallel.ai/customer-terms)
- (b)/(c) §2(b): "The foregoing license includes the right for Customer to use the Parallel API to integrate the Services into the Customer Applications and to make Customer Applications available to End Customers… Customer may modify, adapt, or create derivative works based on Customer Output and incorporate Customer Output (and such derivative works) into materials that Customer provides to its End Customers, provided that (i) Customer Output generated from one query shall be primarily for the use of one End Customer only, and shall not be copied, cached, stored, or made available to other End Customers or other third parties; (ii) Customer shall not copy, cache, or store any significant portion of any Customer Output to create the AI and Data Selling Services…" — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- (a)/(d) §2(c): "Customer shall not, directly or indirectly:
  - … (iii) use or access the Services or Software for timesharing or service bureau purposes or for any purpose other than for Customer's business purposes…;
  - (iv) rent, lease, lend, sell, resell, license, sublicense, assign, distribute, publish, transfer, or otherwise make available the Services, Software, or Customer Outputs (except as expressly permitted under Section 2(b) above);
  - … (vi) use the Services or any Customer Output to (A) create synthetic training data…, or (B) create databases, data brokerage, data selling/reselling businesses…;
  - … (xi) intentionally or knowingly diverge requests of Authorized Users away from the Services (such as by making available Customer Outputs from previous queries for future uses, or incorporating Customer Outputs into an AI and Data Selling Services)…"
  - Source: [Parallel Customer Terms](https://parallel.ai/customer-terms)
- (c) §4(b): "Customer agrees that, and shall ensure each End Customer agrees that, each Customer Output shall be primarily for the exclusive use of the Authorized User who submitted the corresponding query…, and shall not be copied, cached, stored, or made available to third parties in connection with any AI and Data Selling Services." — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- Version lock: "Your use is governed by the version of these Customer Terms and Conditions in effect at the time you became a customer." — [Parallel Customer Terms](https://parallel.ai/customer-terms)
- Conflict. The FAQ says "Subject to our Terms of Service - you own the output you create with Parallel, including the right to reprint, sell, and merchandise." That reads broader than §2(c)(iv). — [Parallel API FAQs](https://docs.parallel.ai/resources/faqs.md)
- (d) No reseller or white-label program was found. Enterprise lists "invoicing and marketplace billing". — [Parallel pricing](https://parallel.ai/pricing)

#### Linkup (Linkup Technologies SAS, France)
- License: "Client is granted a personal, non-exclusive, non-transferable and non-assignable right to use Linkup Product worldwide…". §6.1: "Client shall not… (i) use Linkup Product for purposes other than those authorised by the Agreement or for the benefit of any other person or entity not referred to in the Agreement, and (ii) reproduce, copy, modify, adapt, transcribe, store, translate, represent, distribute, assign, lease or otherwise transfer Linkup Product…" — [Linkup Client General Terms, Aug 2025](https://www.linkup.so/terms-of-use)
- (b)/(c) Search results are "Open Web Content", licensed only for text-and-data mining:
  - "The sole basis for referencing URL links to Open Web Content through Linkup APIs and using this Open Web Content to provide Answers is the exception for text and data mining provided for in Article 4 of EU Copyright Directive 2019/790."
  - "Client shall (i) check that the Open Web Content is lawfully accessible; (ii) limit its use of such content to reproduction and extraction for the sole purpose of text and data mining…; and (iii) retain Open Web Content for as long as is necessary for the purposes of text and data mining only. Client acknowledges and agrees that it is not authorized to use, including to distribute, Open Web Content for any purpose other than strictly specified above." (§4.1)
  - Source: [Linkup terms](https://www.linkup.so/terms-of-use)
- (a)/(b)/(d) Answers:
  - "Client is granted a personal, non-exclusive, non-transferable, worldwide right to use, reproduce and modify Answers, for its internal needs and/or for its end-users' internal needs… it is not authorized to use, including to provide or to resell, the Answers for any purpose other than strictly specified above." (§4.2)
  - "Client shall not resell, sublicense, or otherwise make available the Answers in a manner that amounts to providing a substantially similar or competing service to Linkup Solution (including, without limitation, acting as a wrapper of the Linkup APIs)." (§6.4)
  - Source: [Linkup terms](https://www.linkup.so/terms-of-use)
- Suspension: "Linkup may immediately suspend access" for use contrary to the Agreement, including use "in breach of third party rights on Open Web Content". Either party may also terminate for convenience "upon providing the other Party with thirty (30) days prior written notice". — [Linkup terms](https://www.linkup.so/terms-of-use)
- (d) No reseller program was found.

#### You.com (SuSea, Inc.)
- Scope: "THIS AGREEMENT GOVERNS CUSTOMER'S ACCESS AND USE OF THE YOU.COM PLATFORM. BY… (c) ACCESSING OR OTHERWISE USING THE YOU.COM PLATFORM, CUSTOMER AGREES…". The MSA defines "'API' means the You.com application programming interface…" and "'Customer Application(s)' means the application, product and/or service that interfaces to the Services through the API." — [You.com MSA v.121525](https://45321510.fs1.hubspotusercontent-na1.net/hubfs/45321510/Legal/You.com%20MSA%20(Online)%20(December%202025).pdf)
- (b) Users: "'User' means an individual who is authorized by Customer to access and use the Services, and for whom Customer has supplied a unique user identification and password. Users may include, for example, employees… and third parties with which Customer transacts business." §2.1: "You.com will make the Services available for access by: (a) Customer; and (b) if applicable, Customer Applications…" §3.2: Customer is responsible for "the activities of any User who… accesses the Services through the Customer Application". — [You.com MSA](https://45321510.fs1.hubspotusercontent-na1.net/hubfs/45321510/Legal/You.com%20MSA%20(Online)%20(December%202025).pdf)
- (a)/(d) Restrictions (§3.5): "(c) modifying, copying, sublicensing, leasing, selling or otherwise distributing any of our Services; … (e) automatically or programmatically extracting data or Output; … (h) developing any products or services that compete with our Services…; … (p) except when you are accessing our Services via a You.com API key…, to access the Services through automated or non-human means…; (q) using any method to extract data from the Services other than as permitted through the APIs; (r) buying, selling, or transferring API keys from, to or with a third party…" — [You.com MSA](https://45321510.fs1.hubspotusercontent-na1.net/hubfs/45321510/Legal/You.com%20MSA%20(Online)%20(December%202025).pdf)
- (c) Output ownership (§6.1): "to the extent permitted by applicable law, and subject to Customer's compliance with this Agreement, You.com hereby assigns to Customer all of our right, title, and interest, if any, in and to Outputs." "'Output' means responses generated by the Services based upon Prompts." — [You.com MSA](https://45321510.fs1.hubspotusercontent-na1.net/hubfs/45321510/Legal/You.com%20MSA%20(Online)%20(December%202025).pdf)
- The website footer links both "Terms & conditions" and "Master service agreement". The consumer Terms (Aug 27 2024) contain the same list of prohibitions (selling or distributing Services, programmatic extraction). — [You.com pricing page HTML](https://you.com/pricing); [You.com Terms](https://you.com/terms)
- (d) No reseller or white-label program was found. Customers "can call the Web Search API next to the index you already use… There is no exclusive-index requirement." — [You.com Choose the Right API](https://you.com/docs/choose-the-right-api.md)

#### Perplexity (Search API, not Sonar)
- The `/search` endpoint is governed by the Search Addendum on top of the API ToS: "This Addendum overrides the agreement… solely with respect to the particular Perplexity Search services listed on Schedule 1". "(iii) except for obligations expressly set out in this Addendum, any Perplexity obligations in the Agreement applicable to its other products and services (e.g., update, upgrade and/or zero data retention obligations) do not apply to the Search Services." — [Perplexity Search Addendum, Sep 22 2025](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search)
- (b)/(c) License (API ToS §2.1): "(ii) use the Services and the API Keys solely to submit Input… to the Service, receive Output… from the Service, and display such Output, in each case, solely within the Customer Applications in accordance with the API Documentation…". §2.2: "References to 'Customer' herein shall be deemed to include Customer, Customer's Authorized Users and end users of the Customer Applications, where applicable." — [Perplexity API ToS, Jan 23 2026](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service)
- (c) Ownership of `/search` output, Schedule 1: "Customer does not own, and Perplexity shall not grant it ownership of, the Search API's Output." This overrides the general API ToS §2.3.1, under which Customer "owns all Output". — [Perplexity Search Addendum](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search); [Perplexity API ToS](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service)
- (b) Data restrictions:
  - §2.2: "Perplexity may retain, copy, distribute and otherwise use Search Data for its lawful business purposes, including the improvement and development of products and services. Search Data is not Customer's Confidential Information…"
  - §2.3: "Customer shall not submit Personal Data (as defined in the DPA) to the Search Services unless explicitly authorized by Perplexity in writing."
  - "Input" includes materials submitted "by Customer or end users of a Customer application".
  - Source: [Perplexity Search Addendum](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search)
- (a)/(d) AUP §3, "you must not access, deploy or use the Services to: 1. Copy, distribute, rent, lease, lend, license, transfer or make derivative works of the Services or any related materials or use any of the foregoing on a service bureau or similar basis; … 5. Create or make available any products or services competitive with, similar to, or that would otherwise be a substitute for the Services…, except with Perplexity's express prior written permission". — [Perplexity AUP, Jul 8 2025](https://www.perplexity.ai/hub/legal/aup)
- Suspension (API ToS §2.5): "if Perplexity determines that a Customer Application is… competitive with Perplexity, or likely to damage Perplexity's reputation…, Perplexity may terminate the license… and deactivate the relevant API Key(s)." Termination §10.3: "by Perplexity (a) upon thirty (30) days' prior written notice…". — [Perplexity API ToS](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service)
- (d) No reseller program was found.

#### Jina AI (Jina AI GmbH, part of Elastic N.V.)
- Status of the terms: "Notice regarding acquisition by Elastic: In October 2025, Jina AI GmbH was acquired by Elastic N.V. (NYSE: ESTC). As a result, data processing for Jina AI products and services is now governed by Elastic's data processing terms… The terms and policies below were established by Jina AI GmbH prior to the acquisition and may no longer reflect the current data processing practices." — [Jina legal, May 4 2026](https://jina.ai/legal)
- (b)/(c)/(d) Output, §4.3: "Where as an outcome of the Customer's use of the Services certain results… are created through the Services (collectively, the 'Output'), Jina AI (except as expressly stated otherwise herein) claims no rights to such Output and imposes no restrictions on the Customer regarding the use of the Output unless otherwise agreed in an agreement with the Customer. To the extent that the Output consists of extracted or restructured content from existing third-party materials (e.g. websites, PDF files, search results…), the Customer acknowledges that any third party intellectual property rights in the underlying Material remain unaffected. Jina AI does not create original content…" — [Jina legal](https://jina.ai/legal)
- Limits:
  - §4.5: "Customers must not… (iii) use any Output from the Services to develop applications or services that compete with the Services offered by Jina AI; or (iv) use automated methods to extract information, data or result from the JINA-AI website or the Services, including by means of scraping, harvesting, or web data extraction."
  - §4.2: the IP license is "non-exclusive, non-sublicensable, non-transferable, revocable and limited… strictly for the purpose of using the Services agreed in an Order Form".
  - §3.6: "Customer shall be liable for all activities performed using its API keys, including the activities of any end user."
  - Source: [Jina legal](https://jina.ai/legal)
- Change notice (§13.6): "Jina AI will inform the Customer of such changes with a notice period of at least six (6) weeks". Governing law: German, Berlin courts. — [Jina legal](https://jina.ai/legal)
- (d) No reseller program was found. "For purchase orders, procurement processes, or volumes above what self-serve top-up supports, contact Elastic Sales." — [Jina Reader page FAQ](https://jina.ai/reader)

#### Firecrawl (SideGuide Technologies Inc.)
- (a)/(d) §5.d, Prohibited Activities: "5.d.1. Use the Services for any commercial purposes except as expressly authorized by Firecrawl; 5.d.2. Reproduce any portion of the Services in any form or by any means, except as expressly permitted in this Agreement or otherwise in writing…; 5.d.3. Modify, rent, lease, loan, sell, distribute, or create derivative works based on the Services in any manner…; … 5.d.18. Using or reselling Services in connection with any purpose covered by the Fair Credit Reporting Act." — [Firecrawl ToS, Oct 7 2026](https://www.firecrawl.dev/terms-of-service)
- (c) The ToS has no clause on storing scraped or search output. §8.c: "You neither possess nor retain any ownership of or rights to the Services unless the content is generated by You." — [Firecrawl ToS](https://www.firecrawl.dev/terms-of-service)
- Third-party data: "If you access data supplied by a third-party provider through the Services, your access to and use of that provider's data is subject to the provider-specific terms…". General terms are "version 2.0.0, effective September 21, 2026". Providers include Apollo, People Data Labs and Similarweb. — [Firecrawl ToS](https://www.firecrawl.dev/terms-of-service); [Third-Party Data Terms](https://www.firecrawl.dev/terms/third-party-data)
- (d) The "Partner Credits" program is platforms giving their users free Firecrawl credits: "Firecrawl partners with select platforms to offer their users free Firecrawl credits… 10,000 free Firecrawl credits… expire 3 months after they are applied." This is not a reseller program. — [Firecrawl Partner Credits](https://docs.firecrawl.dev/partner-credits.md)
- Self-hosting: the core is open source under AGPL-3.0 (repo last pushed 2026-11-23). — [GitHub API, firecrawl/firecrawl](https://github.com/firecrawl/firecrawl)

#### Valyu (Valyu.Network Ltd, UK)
- (b)/(c)/(d) PSA §3: "Valyu grants you a limited, revocable, non-exclusive, non-transferable licence to: access and call the Valyu APIs; use Outputs within your applications; store permitted cached Outputs in accordance with Section 7." — [Valyu PSA, Oct 20 2025](https://www.valyu.ai/valyu-platform-service-agreement)
- PSA §5, Output Rights: "You may: use and display Outputs within your applications; store Outputs within the caching limits of Section 7. You may not: use any Output for model training, fine-tuning, pre-training, embedding generation, or dataset construction; use Output to recreate the structure of any Valyu dataset or publisher corpus; resell or sublicense Outputs." — [Valyu PSA](https://www.valyu.ai/valyu-platform-service-agreement)
- PSA §6 and §7, caching:
  - Restricted (publisher) content: "No caching is allowed. No storage is allowed… You must delete the content immediately after the request completes… You may not display or expose full-text or substantial extracts to end users."
  - Open web content: "You may temporarily cache Output in accordance with the durations specified in the Documentation. Valyu may modify caching rules per endpoint at any time. You may not cache: full documents, large-scope result sets…"
  - Source: [Valyu PSA](https://www.valyu.ai/valyu-platform-service-agreement)
- AUP §7.2 (Open Web): "You may temporarily cache Outputs only within the durations specified by Valyu's Documentation. You may not: Store Outputs indefinitely… Store large batches of outputs from related queries…". AUP §5.2: "You may not: Embed Outputs into a vector store… Store Outputs or derivatives in structured or unstructured datasets…" — [Valyu AUP](https://www.valyu.ai/valyu-acceptable-use-policy)
- Termination: "Upon termination: you must delete all cached data…". — [Valyu PSA](https://www.valyu.ai/valyu-platform-service-agreement)

### Inferences
- **Charging per search (a).** No document addresses pass-through metering directly.
  - The lowest-risk text is Parallel's. It expressly lets the Customer make Customer Applications available to End Customers and does not regulate pricing to them.
  - Next are You.com (bans selling the "Services" and trading keys, but assigns Output) and Tavily (the resale ban covers "Services" and carves out integration into Customer Applications).
  - Exa, Perplexity, Linkup, Valyu and Firecrawl have language that a "cost + 20% per search" rebill could be read to violate:
    - Exa: "offer for sale any information… obtained from… the Services";
    - Perplexity: "service bureau or similar basis";
    - Linkup: "acting as a wrapper of the Linkup APIs";
    - Valyu: "resell or sublicense Outputs";
    - Firecrawl: "any commercial purposes except as expressly authorized".
  - Framing the charge as a metered feature of URnetwork's own product, not a sale of results, helps most where the ban is on reselling "the Services" (Tavily, You.com, Parallel).
- **Passing results to the person's own harnesses (b).** This means Codex or Claude Code receiving the results over a local MCP gateway.
  - Fits Parallel ("for the use of one End Customer"), Jina ("no restrictions") and You.com (Output assigned).
  - Strains Perplexity ("display such Output… solely within the Customer Applications") and Valyu ("use and display Outputs within your applications"), because the harness is a third party's application.
  - The relay must keep the key server-side under every set of terms: Tavily "may not be… shared", You.com "buying, selling, or transferring API keys", Perplexity "API Key is… Confidential Information".
- **Storing a copy in the E2EE record (c).**
  - Clearly fine: Jina and You.com.
  - Probably fine: Tavily (silent) and Parallel (single-user storage fits §2(b) as long as stored outputs are never reused to answer other or future queries, per §2(c)(xi)).
  - Needs a written exception: Exa (4.2(a) "except… as otherwise expressly permitted… by us in writing").
  - Conflicts: Linkup (retain only "for as long as is necessary for the purposes of text and data mining") and Valyu ("Store Outputs indefinitely" is prohibited).
  - Perplexity is silent, but the customer does not own the output and Perplexity can reuse whatever is sent.
  - Firecrawl is silent.
- **Wholesale resale or partner route (d).** Only Exa (a "Resell the API" track) and Tavily (marketplace, tech-partner and authorized-reseller language) have a documented route. Both are worth approaching for a written addendum that covers per-search rebilling and E2EE storage.
- Compared with Brave's bans on storage beyond transient use, on making the API available to third parties, and on reselling results, Parallel, You.com, Jina and Tavily are materially looser in text. Exa, Linkup, Perplexity and Valyu are similar to Brave or stricter on resale and storage.

### Gaps
- Exa's ToS has no "Last Revised" date. The PDF metadata date (2025-03-04) is the only dating found. I found no separate public Exa API agreement for self-serve accounts. The enterprise MSA is not public.
- Linkup's Notion copy of its terms could not be fetched (JS-rendered), so I could not confirm that it matches the website's August 2025 version.
- It is unclear whether You.com's self-serve API sign-up binds customers to the Online MSA or to the consumer Terms. Both are linked from the site footer, and no click-through text was visible without an account.
- None of the providers publish reseller margins, partner-program contract terms, or written policies on charging end users per call.
- Other notable APIs found but not verified from primary sources:
  - Desearch, the Bittensor subnet 22 search API, is relevant given URnetwork's Bittensor compute plans. A third-party directory lists "$1.00 per 1,000 searches" and "$0.50 per 1,000 pages", but I found no official terms or pricing page ([Infrabase listing via search](https://infrabase.ai/agents/desearch)).
  - Its GitHub README describes SN22 as the subnet behind Desearch and says the validator API "is not the public billing/auth layer" ([Desearch README](https://raw.githubusercontent.com/datura-ai/desearch/main/README.md), seen only as a search snippet).

## 2. Price per 1,000 searches and per 1,000 extractions, rate limits and capacity, enterprise options

### Takeaway
Raw search runs about $1–$8 per 1,000 calls (about 10 results) on self-serve plans:
- Parallel turbo/fast: $1.
- Perplexity Fast: $1.
- Firecrawl Scale: about $1.20.
- Exa Lite: $4.
- Linkup standard, You.com, Perplexity standard, Parallel basic/advanced, and Brave: $5.
- Valyu: about $6.25 on pay-as-you-go.
- Tavily basic: $8 on pay-as-you-go, $5 on the Growth plan.

Extraction runs about $0.60–$1.60 per 1,000 URLs (You.com $0.90; Exa, Parallel, Perplexity and Linkup standard without JS $1; Tavily basic $1.60 PAYG). JS rendering costs extra on Linkup ($5/1k). Jina's per-token price could not be read from its page.

Default throughput ranges from 10 QPS (Exa, Linkup, You.com) to 50 query units/s (Perplexity Search) and about 83–167 RPS (Firecrawl Growth/Scale). Every provider sells higher limits and ZDR through enterprise contracts. Exa's ZDR is self-serve at $12,000 per year.

### Cited Findings

#### Exa
- Pricing table (per 1k requests, up to 10 results):

  | | Lite | Auto | Deep | Contents | Monitors | Answer |
  |---|---|---|---|---|---|---|
  | Base price | $4 | $7 | $12 | $1 per 1k pages | $2 | $5 |
  | Each additional result above 10 | $1 | $1 | $1 | – | $1 | – |
  | AI page summaries, per 1k pages | $1 | $1 | $1 | $1 | $1 | – |

  Contents is "$1/1k pages per content type". — [Exa pricing](https://exa.ai/pricing)
- Plans:
  - Free: "$10 in credits every month, plus a one-time $10 onboarding bonus", 10 QPS.
  - Pay as you go: "Prepaid credits with no subscription or minimum spend", "10 QPS, up to 25 QPS".
  - Enterprise: "Custom volume pricing and optional postpaid invoicing".
  - "Add $1,000 in credits within any 30-day window and your team's rate limit rises to 25 QPS for 90 days, automatically."
  - Source: [Exa Billing and Rate Limits](https://exa.ai/docs/admin/billing.md)
- Per-endpoint defaults: "`/search`, `/answer`, `/chat/completions` | 10 QPS"; "`/search` with `type` `deep-lite`, `deep`, or `deep-reasoning` | 5 QPS"; "`/contents` | 100 QPS". "Rate limits… apply to your team as a whole, across all of its API keys. You can give an individual key a lower limit…". — [Exa Billing and Rate Limits](https://exa.ai/docs/admin/billing.md)
- Per-key budgets: "If your team exhausts its credits, requests return `402 Payment Required`. An API key that reaches its assigned budget also returns `402`." A Team Management API can "Create a new API key… with optional name and rate limit configuration". — [Exa Billing](https://exa.ai/docs/admin/billing.md); [Exa docs index](https://exa.ai/docs/llms.txt)
- Enterprise: "The annual plan costs $12,000 paid upfront and includes Zero Data Retention, $12,000 in API credits and a rate limit of 25 QPS." Custom plans add "Custom MSA and DPA… Monthly invoicing… Enterprise SLAs… Custom Search QPS… Up to 1,000 results per search." — [Exa Billing](https://exa.ai/docs/admin/billing.md); [Exa pricing](https://exa.ai/pricing)

#### Tavily
- Credits: "Pay-as-you-go: $0.008 per credit"; "Monthly plans: $0.0075 - $0.005 per credit":
  - Project: 4,000 credits for $30.
  - Bootstrap: 15,000 for $100.
  - Startup: 38,000 for $220.
  - Growth: 100,000 for $500.
  - Free Researcher: 1,000 per month.
  - Source: [Tavily Credits & Pricing](https://docs.tavily.com/documentation/api-credits.md)
- Costs per call:
  - Basic Search "1 API credit". Advanced Search "2 API credits".
  - Basic Extract: "Every 5 successful URL extractions cost 1 API credit". Advanced Extract "2 API credits" per 5.
  - Map: 1 credit per 10 pages, or 2 with instructions.
  - Research: 4–110 credits (mini) or 15–250 (pro).
  - "You never get charged if a URL extraction fails."
  - Source: [Tavily Credits & Pricing](https://docs.tavily.com/documentation/api-credits.md)
- Rate limits are "per organization… All API keys in the same organization or account share one limit":
  - Researcher (free): 100 RPM.
  - PAYGO enabled, and Project/Bootstrap/Startup: 1,000 RPM.
  - Growth and Scale: 1,500 RPM.
  - Enterprise: custom.
  - `/crawl` and `/map`: 100 RPM. `/research`: 20 RPM.
  - Source: [Tavily Rate Limits](https://docs.tavily.com/documentation/rate-limits.md)
- Enterprise per-key control: "Generate one or more API keys with custom configuration" (Enterprise only). The Organization Usage API retrieves "usage, pay-as-you-go cost, and request counts for every API key". — [Tavily Generate Keys](https://docs.tavily.com/documentation/enterprise/generate-keys.md); [Tavily docs index](https://docs.tavily.com/llms.txt)

#### Parallel
- Search:
  - "Per 1,000 `turbo` or `fast` requests (default 10 results) | 1"
  - "Per 1,000 `basic` or `advanced` requests (default 10 results) | 5"
  - "Per 1,000 results beyond the first 10 in a request | 1"
  - "Excerpt length doesn't affect the price."
  - Source: [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing.md)
- Extract: "Per 1,000 URLs | 1". — [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing.md)
- Modes: turbo about 200 ms, $1; fast about 700 ms, $1; basic about 1 s, $5; advanced (default) about 3 s, $5. "Turbo currently supports English and Japanese-language queries." "The EU endpoint at `https://eu.parallel.ai` supports only `basic` mode." — [Parallel Search Modes](https://docs.parallel.ai/search/modes.md)
- Plans:
  - Build: pay-as-you-go, "$5 free monthly with a card on file, plus up to $80 at signup".
  - Scale: "$1,000/mo, Or $10,000 / year charged upfront, for $12,000 in credits over 12 months". "Scale also raises Search and Extract limits to 1,500 requests per minute, excluding Turbo… and includes zero data retention as Hybrid ZDR."
  - Enterprise: custom.
  - Source: [Parallel pricing](https://parallel.ai/pricing)
- Rate limits: Search 600/min, Extract 600/min, Images 600/min, Places 300/min, Tasks 2,000/min. — [Parallel Rate Limits](https://docs.parallel.ai/getting-started/rate-limits.md)
- Spend limits are notify-only: "Limits are notify-only; they never block requests." — [Parallel FAQs](https://docs.parallel.ai/resources/faqs.md)

#### Linkup
- Search: `flash`/`fast`/`standard` with `searchResults` costs $0.005. With `sourcedAnswer` or `structured` it costs $0.006. `deep` with `searchResults` costs $0.05, and $0.055 with an answer or structured output. — [Linkup Pricing docs](https://docs.linkup.so/pages/documentation/platform/pricing.md)
- Fetch: "`standard` | `false` | $0.001 per call"; standard with renderJs $0.005; pro $0.005; pro with renderJs $0.01. A `schema` adds $0.001. — [Linkup Pricing docs](https://docs.linkup.so/pages/documentation/platform/pricing.md)
- Free credits: "When you first sign up with a professional email address, your account is automatically credited with $20. We will top up eligible accounts back to $20 each month." Failed calls are not charged. "If your account runs out, the API will respond with a `429` HTTP error." — [Linkup Pricing docs](https://docs.linkup.so/pages/documentation/platform/pricing.md)
- Rate limits: "our rate limits are currently set at `10 queries per second` per organization". — [Linkup Rate Limits](https://docs.linkup.so/pages/documentation/platform/rate-limits.md)
- Enterprise: "Custom pricing models… Build personalized indexes… Dedicated refresh rate of the index… Private environment… ZDR / SOC 2 Type II / SLA". — [Linkup pricing page](https://www.linkup.so/pricing)

#### You.com
- Web Search API: "$5.00 / 1k calls, up to 100 results per call. Full page add-on $1.00 / 1k pages fetched live". Extract API: "$0.90 / 1k URLs. For PDFs, `standard` adds an additional $0.50 / 1k pages". — [You.com Choose the Right API](https://you.com/docs/choose-the-right-api.md)
- Full-page extraction from cache is free: "`blend` (default) | $1.00 per 1,000 pages crawled live. Pages served from cache are free". — [You.com Billing](https://you.com/docs/administration/billing.md)
- Free credits: "New accounts get $10 in free API credit at signup, plus $90 more when you verify your account." Per-key spending caps: "set a spending cap on it from the API Keys page". — [You.com Billing](https://you.com/docs/administration/billing.md)
- Rate limits (self-serve): `/v1/search`, `/v1/contents`, `/v1/answer` and `/v1/research` are each "10 requests/second". "Enterprise plans run on custom limits set in your contract." — [You.com Rate Limits](https://you.com/docs/rate-limits.md)

#### Perplexity
- "Search API | $5.00 | Ranked web results as JSON… No model, no generated answer, no token billing." Fast Search is $1.00. "A successful request containing an array of up to five queries is one billing unit." Context API: "It costs $1.00 per 1,000 fetched URLs". — [Perplexity Pricing](https://docs.perplexity.ai/docs/getting-started/pricing.md)
- Rate limits: "POST `/search` | 50 query units per second". "Search rate limits are independent of your usage tier." — [Perplexity Rate Limits & Usage Tiers](https://docs.perplexity.ai/docs/admin/rate-limits-usage-tiers.md)

#### Jina AI
- Billing is per token: "API pricing is based on the token usage. One API key gives you access to all search foundation products." For s.jina.ai, "Every request costs a fixed number of tokens, starting from 10,000 tokens". For r.jina.ai: "Count the number of tokens in the output response." — [Jina Reader](https://jina.ai/reader); [Jina API dashboard pricing](https://jina.ai/api-dashboard/pricing/)
- Rate limits:
  - r.jina.ai: 20 RPM without a key, 500 RPM with a paid key, 5,000 RPM with a premium key.
  - s.jina.ai: blocked without a key, 100 RPM with a free or paid key, 1,000 RPM with a premium key.
  - Source: [Jina Reader](https://jina.ai/reader)
- Free tokens: "Every new API key comes with 10M free tokens!" — [Jina Reader](https://jina.ai/reader)
- Pricing change: "We introduced a new pricing model on May 6th, 2025." — [Jina Reader](https://jina.ai/reader)
- The actual price per token or package is not in the page HTML (loaded client-side). Third-party figures:
  - Activepieces (Nov 9, 2026) cites "Reader requests cost 4,000 tokens; Search requests 10,000 tokens", but its $0.05/1M rate is explicitly "my assumption". — [Activepieces](https://www.activepieces.com/blog/jina-ai-api-pricing-token-costs-limits-2026)
  - A search-result summary of xpay.sh gives "~$0.02 per 1M tokens" (refreshed 2026-05-03). It is unverified. — [xpay.sh](https://www.xpay.sh/saas-pricing/jina-reader)

#### Firecrawl
- Credits: "1 credit = 1 page on a basic scrape or crawl… Search costs 2 credits per 10 results… On Scrape and Crawl, the JSON, Question, and Highlight formats add 4 credits per page". — [Firecrawl pricing](https://www.firecrawl.dev/pricing)
- Plans (monthly, or annual per month):
  - Hobby: $19 ($16), 5,000 credits.
  - Standard: $99 ($83), 100,000 credits.
  - Growth: $399 ($333), 500,000 credits.
  - Scale: $749 ($599), 1,000,000 credits.
  - Free: 1,000 credits.
  - Pay-as-you-go top-ups: "A 5 USD increment is 1,000 credits on Hobby, 2,000 on Standard, 2,500 on Growth, and 5,000 on Scale."
  - Source: [Firecrawl pricing](https://www.firecrawl.dev/pricing)
- Rate limits for `/scrape`, `/map` and `/search`: 10/min (Free), 100/min (Hobby), 500/min (Standard), 5,000/min (Growth), 10,000/min (Scale), custom (Enterprise). Concurrency: 2, 5, 25, 50, 100. — [Firecrawl pricing](https://www.firecrawl.dev/pricing)
- Failed requests: "A scrape that returns no result is not charged. A page that responds with an error status such as 403 or 404 is still returned to you and costs 1 credit." — [Firecrawl pricing](https://www.firecrawl.dev/pricing)

#### Valyu
- Search: "Web and news | 0.1 [credits per result] | 100 [per 1,000]". "A web search that returns 10 results uses 1 credit". Pay-as-you-go: "1,600 credits per $10. Top-ups last 12 months", "$10 minimum top-up". — [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)
- Plans: $29/month for 5,000 credits, $99/month for 18,000, $499/month for 100,000. — [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)
- Contents: "0.2 credits for each successfully extracted URL. Adding a summary or structured extraction brings the price to 0.6 credits". — [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)
- Spend cap: "Set a monthly usage limit to cap pay-as-you-go spending. Requests over the limit return `402` with the code `credit_limit_reached`." — [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)
- Rate limits: plans list "Standard rate limits" and "Higher rate limits on request". — [Valyu pricing page](https://www.valyu.ai/pricing)

### Inferences
- Per 1,000 web searches of about 10 results, computed from the figures above:

  | Provider | Cost per 1k searches |
  |---|---|
  | Parallel turbo/fast | $1 |
  | Perplexity Fast | $1 |
  | Firecrawl | $1.20 (Scale) to $6.40 (Hobby); $5 on Standard pay-as-you-go top-ups |
  | Exa Lite | $4 |
  | Exa Auto | $7 |
  | Tavily basic | $5 (Growth) to $8 (PAYGO); advanced is twice that |
  | Linkup standard | $5 |
  | You.com | $5 (up to 100 results) |
  | Perplexity standard | $5 |
  | Parallel basic/advanced | $5 |
  | Valyu | $4.99 (Serious Business) to $6.25 (PAYG) |
  | Brave Search plan (baseline) | $5 |

- Per 1,000 extractions:

  | Provider | Cost per 1k URLs |
  |---|---|
  | You.com | $0.90 (+$0.50/1k PDF pages for standard parse) |
  | Exa, Parallel, Perplexity Context | $1 |
  | Linkup standard | $1; $5 with JS rendering |
  | Valyu | $1.25 (PAYG) |
  | Tavily basic | $1.60 (PAYG); $1.00 (Growth) |
  | Firecrawl | $0.60 (Scale) to $3.20 (Hobby) |

- Usage-based prepaid billing with no subscription, which suits a cost-plus relay, is offered by Exa, Linkup, You.com, Perplexity, Valyu, Jina and Parallel Build. Tavily and Firecrawl push monthly plans for their best unit rates.
- Per-user metering helpers: Exa per-key budgets and the key-management API; Tavily Enterprise key generation and per-key usage; You.com per-key spending caps. Parallel's spend limits do not block requests, so the relay must enforce its own caps.

### Gaps
- Jina's dollar price per token or package was not readable from the official page. Only unverified third-party figures exist.
- Valyu's numeric rate limits and Tavily's Enterprise pricing are not published. Exa's, Parallel's and Linkup's above-default limits are by contract.

## 3. Data handling: query logging and retention, ZDR, DPA, training use

### Takeaway
Defaults vary a lot:
- **Perplexity Search.** Data may be "retain[ed], cop[ied], distribute[d] and otherwise use[d]". ZDR does not apply, and personal data is banned.
- **Exa.** Its privacy policy says query data is used "training and fine-tuning models". ZDR is Enterprise only ($12,000 per year).
- **Parallel.** Inputs and outputs may train its models unless ZDR is on. Hybrid ZDR comes with Scale ($1,000/month) after a signed agreement. The EU endpoint retains nothing.
- **Linkup.** The ToS lets it train on "Client Data, including prompts". ZDR is on request.
- **Tavily.** It may use query data to improve results and passes some queries to third-party indexes (Google). An org-level ZDR exists.
- **You.com.** The MSA license is limited to service operation. ZDR is on enterprise agreements and also keeps queries away from Google and Bing.
- **Jina.** It states it never trains on API data, and a per-request `DNT` header blocks caching and logging.
- **Firecrawl.** ZDR is Enterprise only and processing is US-only.
- **Valyu.** It states no training on Customer Data. ZDR is enterprise.

For URnetwork's privacy posture, Jina, You.com (with ZDR), Valyu and Parallel (Hybrid ZDR or EU endpoint) are the least exposed. Perplexity Search is the most exposed.

### Cited Findings
- **Exa.**
  - "Query Data is used to improve our products and technology, including by training and fine-tuning models that power our Services". — [Exa Privacy Policy, Jun 29 2026](https://exa.ai/privacy-policy)
  - ZDR is Enterprise only, per team, and covers Search, Contents, Agent and Answer. "Websets | Not currently supported". The upgrade "costs $12,000 per year plus applicable tax, paid upfront… $12,000 in API credits, which expire at the end of each 12-month term". — [Exa ZDR](https://exa.ai/docs/admin/security/zero-data-retention.md)
  - "Visit our Trust Center to view our SOC 2 reports, Data Processing Agreement…". Exa also offers EU data residency and "honors GDPR and CCPA data-subject rights". — [Exa Security](https://exa.ai/docs/admin/security/overview.md); [Exa inference-providers](https://exa.ai/use-cases/inference-providers)
- **Tavily.**
  - "unless otherwise specified under the contract between you and us, we may use certain portions of your query data to improve our responses to future queries… legitimate interest".
  - "we may also share your query data with third-party search index providers in limited situations where our own search index is unable to retrieve the requested content".
  - Source: [Tavily Privacy, Nov 24 2025](https://www.tavily.com/privacy)
  - ToS §9.2 grants Tavily a "worldwide, royalty-free, fully paid, transferable, assignable, sublicensable (through multiple tiers), perpetual, and irrevocable license to collect, host, use… store, copy… Customer Input… to (i) provide, support, monitor, analyze, and improve the Services…". §6.5: AI-Functionality inputs and outputs may be used "for purposes of training". — [Tavily ToS](https://www.tavily.com/terms)
  - "If your account or organization has Zero Data Retention enabled, the free-text and URL content you send here is not stored". The `/logs` API "never include[s] the input or output of a request". — [Tavily llms-full](https://docs.tavily.com/llms-full.txt)
- **Parallel.**
  - "Parallel may use Customer IP to train and improve the machine learning and other artificial intelligence models used to provide the Services. Customer IP used for training is not linked to any individual during training." — [Parallel Customer Terms §4(b)](https://parallel.ai/customer-terms)
  - "Enterprise plans with zero data retention exclude that use. Search API traffic sent to the EU endpoint is also excluded." — [Parallel FAQs](https://docs.parallel.ai/resources/faqs.md)
  - "Zero data retention is included on Scale as Hybrid ZDR. It turns on once a signed agreement is in place. Once active, synchronous APIs retain no content and asynchronous APIs retain it for up to 8 days." — [Parallel pricing](https://parallel.ai/pricing)
  - "Search API requests sent to the EU endpoint are processed and served within the European Union, and we do not retain request or response content." — [Parallel Privacy Policy](https://parallel.ai/privacy-policy)
  - DPA: "Before Customer use the Services to process any… 'Personal Data'…, Customer shall separately execute Parallel's Data Processing Addendum". Storage: "encrypted… at rest in US-based data centers". — [Parallel Customer Terms](https://parallel.ai/customer-terms); [Parallel FAQs](https://docs.parallel.ai/resources/faqs.md)
- **Linkup.**
  - "Client grants Linkup a worldwide right to use, reproduce and modify the Client Data, including prompts, for the purposes of providing, maintaining, developing, training and improving the Linkup Solution." — [Linkup terms](https://www.linkup.so/terms-of-use)
  - ZDR: "ZDR can be requested on demand. It is not enabled by default… No query logging… No result retention". "By default: Queries may be processed across these regions [US, EU, Canada, APAC] based on load allocation". — [Linkup Data processing and privacy](https://docs.linkup.so/pages/security-and-privacy/data-processing-privacy.md)
  - DPA: "Data Processing Agreements (DPAs) aligned with GDPR Article 28 are available on request and can be signed via DocuSign". Certifications: SOC 2 Type II, ISO 27001, HIPAA. — [Linkup Security overview](https://docs.linkup.so/pages/security-and-privacy/overview.md)
- **You.com.**
  - MSA §6.3: "Customer grants You.com, its Affiliates and applicable service providers and subcontractors a worldwide, limited-term license to host, copy, use, transmit and display Customer Data for You.com to provide and ensure proper operation of the Services". — [You.com MSA](https://45321510.fs1.hubspotusercontent-na1.net/hubfs/45321510/Legal/You.com%20MSA%20(Online)%20(December%202025).pdf)
  - ZDR "is available for the Web Search API and the Answer API on enterprise agreements… Request and response content is not retained… Your queries are not used to train models… your queries do not go to Google or Bing." It is not offered on Extract or Research. — [You.com ZDR](https://you.com/docs/administration/zero-data-retention.md)
  - Conflict. The consumer Terms (Aug 27 2024) say "You agree that we may use Content to: (a) provide, maintain, train and improve the Services". — [You.com Terms](https://you.com/terms)
  - The DPA is dated "December 12, 2025". — [You.com DPA](https://you.com/dpa)
- **Perplexity.**
  - "Perplexity may retain, copy, distribute and otherwise use Search Data for its lawful business purposes, including the improvement and development of products and services." Zero data retention obligations "do not apply to the Search Services". — [Perplexity Search Addendum](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search)
  - Conflict. The docs page says "No training by default: Under the API Terms of Service, Perplexity does not use Customer Content to train generative AI models. Certain APIs may be subject to product-specific terms." It also says "Zero Data Retention is not default". The Search Addendum is the product-specific term that controls. — [Perplexity Privacy & Security](https://docs.perplexity.ai/docs/resources/privacy-security.md)
- **Jina.**
  - "Jina AI does not use Customer request data, inputs, prompts, or uploaded content to train its models". "Jina AI will only store Input or Output on its servers to the extent required to provide the Services." — [Jina legal §10.4, §4.6](https://jina.ai/legal)
  - FAQ: "We never use your API requests, inputs, or outputs to train our embedding, reranker, or any other models."
  - Per-request header "DNT: Prevent this request from being cached or logged on our servers."
  - "If you request the same URL within 5 minutes, the Reader API will return the cached content."
  - Source: [Jina Reader](https://jina.ai/reader)
  - "The applicable data processing agreement is the Elastic Data Processing Addendum". — [Jina legal §11.2](https://jina.ai/legal)
- **Firecrawl.**
  - "Zero Data Retention (ZDR)… is available on Enterprise plans". Scrape ZDR "Adds 1 credit per page". Search end-to-end ZDR covers "Query and result data, at Firecrawl and at our upstream search provider | 10 credits per 10 results". Anonymized ZDR: "the search provider may cache the anonymized query | 2 credits per 10 results".
  - "Firecrawl processes all data in the United States and does not offer EU data residency."
  - "Enterprise customers can sign a Data Processing Agreement". SOC 2 Type II "(renewal in progress)".
  - Source: [Firecrawl Security overview](https://docs.firecrawl.dev/security.md)
  - The privacy policy (Dec 26 2024) says: "We will retain your personally identifiable information until you request in writing that we delete" it. — [Firecrawl Privacy](https://www.firecrawl.dev/privacy-policy)
- **Valyu.**
  - "We do not use Customer Data to train models unless you give explicit written permission." The license covers processing "solely to: provide the Services, maintain security, prevent abuse, and improve system performance and quality". — [Valyu PSA §4](https://www.valyu.ai/valyu-platform-service-agreement)
  - Privacy: "We do not use query data or logs to train machine learning models." — [Valyu Privacy, Oct 20 2025](https://www.valyu.ai/privacy-policy)
  - Enterprise "Zero-data retention" and SOC 2 Type 2. — [Valyu pricing](https://www.valyu.ai/pricing)

### Inferences
- Any provider whose default terms allow training on queries (Exa, Parallel, Linkup, Tavily partly, Perplexity Search) would be learning from URnetwork users' searches unless ZDR or a contract is in place. That conflicts with an E2EE product story. Budget for ZDR from the start:
  - Exa: $12k per year.
  - Parallel: Scale at $12k per year, or the EU endpoint in `basic` mode only.
- Perplexity Search's ban on personal data is unworkable for free-form user queries. A relay cannot guarantee that queries carry no personal data.
- Jina is the only provider whose public terms give no-training and no-logging (per request) without an enterprise deal. Its search, though, depends on Google and Bing intermediaries (Q4).

### Gaps
- Default query-log retention periods are not published for Exa, Tavily, Parallel, Linkup, You.com (non-ZDR), Perplexity, Firecrawl or Valyu. Brave publishes 90 days.
- Tavily's ZDR price and eligibility are not documented publicly.
- Parallel's default retention (non-ZDR) is not stated.

## 4. Index source: own crawl and index, or Google or Bing proxy?

### Takeaway
- **Own index, stated by the provider:** Exa (ExaSearchBot; "independent search index", over 2T URLs tracked as of Oct 2026), Parallel (ShapBot crawler), Perplexity ("Perplexity's web index"), Linkup ("built on its own search index", plus licensed AFP).
- **Mixed:** Tavily uses its own index with fallback to "third-party search index providers (e.g., Google)". You.com claims "the same real-time index", but its ZDR page implies non-ZDR queries may go "to Google or Bing".
- **Proxy:** Jina s.jina.ai (Serper-Google, then Google SERP, then Bing SERP, per its open-source code). Firecrawl uses an unnamed "upstream search provider".
- **Not disclosed:** Valyu's open-web source.

The proxies carry the legal and continuity risk of upstream Google and Bing terms.

### Cited Findings
- **Exa.**
  - "It combines an independent search index with content extraction".
  - "As of October 2026, Exa's index tracks over 2 trillion URLs and serves 100 billion pages from across the public web."
  - "Exa operates `ExaSearchBot`… It respects the Robots Exclusion Protocol… and does not attempt to bypass logins, paywalls, or CAPTCHAs."
  - Source: [Exa FAQs](https://exa.ai/docs/admin/faqs.md)
- **Parallel.**
  - "ShapBot helps discover and index websites for Parallel's web APIs". Requests are signed with Web Bot Auth. — [Parallel Crawler](https://docs.parallel.ai/resources/crawler.md)
  - "By default, Search returns excerpts from Parallel's index." — [Parallel Search quickstart](https://docs.parallel.ai/search/search-quickstart.md)
  - Series B use of funds: "accelerate our index growth". — [Parallel Series B](https://parallel.ai/blog/series-b)
- **Perplexity.**
  - "`POST /search` runs your query against Perplexity's web index and returns ranked pages." — [How Search Works](https://docs.perplexity.ai/docs/search/overview.md)
  - Schedule 1: "retrieves and returns search results… from an index of public content". — [Search Addendum](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search)
- **Linkup.**
  - "Linkup can offer ZDR because its retrieval is built on its own search index and processing stack." — [Linkup Data processing](https://docs.linkup.so/pages/security-and-privacy/data-processing-privacy.md)
  - Licensed premium source: AFP, "Each AFP dispatch reaches Linkup within 60 seconds". — [Linkup Premium Sources](https://docs.linkup.so/pages/documentation/platform/premium-sources.md)
  - Legal basis for open-web content is the EU TDM exception, with opt-out checks via "robots.txt, TDMRep". — [Linkup terms](https://www.linkup.so/terms-of-use)
- **Tavily.**
  - "We may share your query data with third-party search index providers (e.g., Google) in limited situations where our own search index is unable to retrieve the requested content". "we collect information from the web, by obtaining data from third party indexes directly or via third parties." — [Tavily Privacy](https://www.tavily.com/privacy)
  - ToS §7: "Tavily may share Customer Input… as needed to provide the Services (including making queries on third-party public web indexes)". — [Tavily ToS](https://www.tavily.com/terms)
- **You.com.**
  - "All built on the same real-time index." — [You.com pricing](https://you.com/pricing)
  - ZDR: "your queries do not go to Google or Bing." — [You.com ZDR](https://you.com/docs/administration/zero-data-retention.md)
- **Jina.**
  - The open-source Reader repo (Apache-2.0, last pushed 2026-05-22) has search backends `serper.ts`, `google.ts`, `bing.ts` and `common-serp.ts`. The default provider order in `src/api/searcher.ts` is: "if (this.envConfig.SERPER_SEARCH_API_KEY) { yield this.serperGoogle; } yield this.googleSERP; yield this.bingSERP; yield this.commonGoogleSerp;". — [jina-ai/reader searcher.ts](https://raw.githubusercontent.com/jina-ai/reader/main/src/api/searcher.ts); [repo tree via GitHub API](https://api.github.com/repos/jina-ai/reader/git/trees/main?recursive=1)
  - The product page says only "Use s.jina.ai to search the web and get SERP". — [Jina Reader](https://jina.ai/reader)
- **Firecrawl.**
  - "With end-to-end ZDR, both Firecrawl and our upstream search provider enforce zero data retention." Search accepts Google-style `tbs` parameters such as "qdr:d" and "cdr:1,cd_min:…". — [Firecrawl Search](https://docs.firecrawl.dev/features/search.md)
  - The open-source code routes hosted search to an internal "fire-engine" service, with SearXNG and DuckDuckGo fallbacks for self-hosting. — [firecrawl search/v2/index.ts](https://raw.githubusercontent.com/firecrawl/firecrawl/main/apps/api/src/search/v2/index.ts)
  - Firecrawl also runs its own vertical indexes: "Research Index", "Developer Index", "Government Index". — [Firecrawl docs index](https://docs.firecrawl.dev/_llms/en/v2/documentation.txt)
- **Valyu.** It searches "The web plus SEC filings, full-text papers, clinical trials, patents, market and economic data, and licensed publications", but does not say where open-web results come from. — [Why Valyu](https://docs.valyu.ai/why-valyu.md)

### Inferences
- For continuity and legal risk, Exa, Parallel, Perplexity and Linkup are the safest bets on index ownership.
- Jina's search, and probably Firecrawl's (the Google-style `tbs` syntax suggests a Google SERP source), inherit Google and Bing scraping or SERP-reseller risk. Google has sued SERP scrapers in the past, so treat this as material.
- Tavily's Google fallback is "limited". You.com's wording implies some non-ZDR traffic may reach Google or Bing. Both are partial exposures that ZDR or contract terms can remove.

### Gaps
- Firecrawl's upstream search provider is not named in any public document found.
- Jina's production s.jina.ai configuration may differ from the open-source code.
- Valyu's web-search source is undisclosed. You.com does not say what share of results is its own index.

## 5. Which endpoints generate text with an LLM and which only retrieve or extract?

### Takeaway
Safe-to-use retrieval and extraction endpoints under the TEE rule:
- Exa: `/search` with `lite` or `auto` plus text, and `/contents` text (not summary or highlights).
- Tavily: `/search` basic, advanced or fast without `include_answer`, `/extract`, `/map`, `/crawl`.
- Parallel: `/v1/search` and `/v1/extract`.
- Linkup: `/search` with `outputType: searchResults`, and `/fetch` without `schema`.
- You.com: Web Search and Extract with `parse_effort: lite`.
- Perplexity: `/search` and `/v1/context` without `criteria`.
- Jina: r.jina.ai without OCR or captioning, and s.jina.ai.
- Firecrawl: `/search` and `/scrape` with markdown, html, links or rawHtml formats.
- Valyu: `/search` and `/contents` without `summary`.

Generative or model-in-the-loop features must be excluded:
- Exa: Answer, Agent, deep search types, `summary`; `highlights` are LLM-picked.
- Tavily: `include_answer`, Research, image descriptions, and the "NLP summary" of `ultra-fast`.
- Parallel: Task, Responses, FindAll, Monitor, Decisions.
- Linkup: `sourcedAnswer`, `structured`, Research, Fetch `schema`, Extract.
- You.com: Answer, Research, Finance, Inference Router, and `standard` PDF parse with an "advanced model".
- Perplexity: Agent and Sonar, and Context `criteria`.
- Jina: jina-ocr-v1, image captions, DeepSearch.
- Firecrawl: `json`, `summary`, `query`, highlights, Agent.
- Valyu: DeepResearch, Contents `summary`.

### Cited Findings
- **Exa.**
  - "`/answer` performs an Exa search and uses an LLM to generate either: 1. A direct answer…". — [Exa docs index](https://exa.ai/docs/llms.txt)
  - "`deep-lite`: Performs lightweight research with synthesized results"; "`deep`: Conducts comprehensive multi-step research with synthesis."
  - Highlights: "Text snippets the LLM identifies as most relevant from each page." Summary: "Custom query for the LLM-generated summary."
  - Source: [Exa Search reference](https://exa.ai/docs/reference/search.md); [Exa Contents reference](https://exa.ai/docs/reference/get-contents.md)
- **Tavily.**
  - `include_answer`: "Include an LLM-generated answer to the provided query."
  - `ultra-fast`: "Returns one NLP summary per URL."
  - `include_image_descriptions`: "add a descriptive text for each image."
  - Source: [Tavily Search reference](https://docs.tavily.com/documentation/api-reference/endpoint/search.md)
  - Research: "Run comprehensive research that searches, analyzes sources, and generates a cited report." — [Tavily docs index](https://docs.tavily.com/llms.txt)
  - The ToS defines "AI Functionality" as "generative AI Tools… for conducting research and information analysis". — [Tavily ToS §6.1](https://www.tavily.com/terms)
- **Parallel.** The pricing table lists Search and Extract with "Reasoning: n/a". Task, Responses, Monitor and FindAll show "Reasoning: low to high". The advanced Search mode "Uses a more advanced retrieval and compression pipeline". — [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing.md); [Parallel Search Modes](https://docs.parallel.ai/search/modes.md)
- **Linkup.**
  - "`sourcedAnswer` and `structured` invoke an LLM to compose or shape the response and carry a small premium over raw `searchResults`." — [Linkup Pricing docs](https://docs.linkup.so/pages/documentation/platform/pricing.md)
  - Fetch with a schema: "Structured output adds a model pass after the scrape". — [Linkup Fetch overview](https://docs.linkup.so/pages/documentation/endpoints/fetch/overview.md)
- **You.com.**
  - Web Search: "Retrieval only, no synthesis step".
  - Extract: "By default (`parse_effort: "standard"`), complex PDF pages, such as charts and images, also go through an advanced model". "`lite` extracts the content embedded in each page".
  - Source: [You.com Choose the Right API](https://you.com/docs/choose-the-right-api.md); [You.com Extract](https://you.com/docs/guides/extract.md)
- **Perplexity.**
  - Search: "This API does not generate Output through the use of artificial intelligence, including large language models." — [Search Addendum Schedule 1](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service-search)
  - Context: "With `criteria`, scoring tokens bill as Decisions API input tokens". — [Perplexity Pricing](https://docs.perplexity.ai/docs/getting-started/pricing.md)
- **Jina.**
  - "Uses jina-ocr-v1 to convert images to Markdown… Costs 40× more tokens!"
  - The "Image Caption" option "Captions all images…".
  - Conflict. The FAQ says "Images on the webpage are automatically captioned using a vision language model in the reader", while the option list presents captioning as a request header.
  - Source: [Jina Reader](https://jina.ai/reader)
- **Firecrawl.**
  - Formats include "Summary (`summary`)", "JSON (`json`) - structured output", and "Query (`query`, with `prompt`…) - ask a natural-language question about the page". "JSON mode - Structured result: Extract structured data from pages via LLMs".
  - Highlights: "Return query-relevant passages". The code has a `highlight-model.ts`.
  - Source: [Firecrawl Scrape](https://docs.firecrawl.dev/features/scrape.md); [Firecrawl docs index](https://docs.firecrawl.dev/_llms/en/v2/documentation.txt); [repo tree](https://api.github.com/repos/firecrawl/firecrawl/git/trees/main?recursive=1)
- **Valyu.** Contents `summary` accepts "`false`, `true`, an instruction string, or a JSON schema". "If the AI step fails, you pay only the 0.2 cr[edits]". DeepResearch returns "a cited report". — [Valyu Contents](https://docs.valyu.ai/guides/content-extraction.md); [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)

### Inferences
- Under the rule that every remote LLM run must sit in a client-verified TEE, the relay should set parameters explicitly per provider:
  - Exa: `highlights=false`, no `summary`, `type` = `lite` or `auto`.
  - Tavily: `include_answer=false`, no `ultra-fast`, no image descriptions, `auto_parameters=false`.
  - You.com: `parse_effort: "lite"`.
  - Jina: no OCR or captioning headers.
  - Firecrawl: markdown, html or links formats only.
  - Linkup: `searchResults` only.
- Exa's highlights and Parallel's advanced-mode "compression" are model-mediated selection whose output is page text. They are borderline. Ask the vendors whether the returned text is verbatim.

### Gaps
- No provider states whether its default search snippets or excerpts are verbatim page text or model-compressed. Perplexity says "extracted"; Parallel says "excerpts" with a "compression pipeline".
- It is unclear whether Tavily's "NLP summary" and `auto_parameters` use an LLM.

## 6. Extraction endpoints: output structure, JS rendering, price

### Takeaway
All providers return markdown. The richest structured and metadata options are Exa `/contents` and Firecrawl `/scrape`. Explicit JS rendering is documented by Linkup (`renderJs`), Parallel ("JavaScript-heavy pages"), Tavily ("Handles JavaScript-rendered pages"), Firecrawl, Jina (browser engine) and Valyu (`extract_effort: high`). It is not documented for Exa, You.com or Perplexity Context. Cheapest non-generative extraction per 1,000 URLs: You.com $0.90; Exa, Parallel, Perplexity and Linkup (no JS) $1; Valyu about $1.25; Tavily $1.00–$1.60.

### Cited Findings
- **Exa `/contents`.** Output is "Full page contents, summaries, and metadata". Options:
  - `text`: `maxCharacters` up to 5,000,000; `includeHtmlTags`; `linkStyle` `full` or `citation`; `includeSections`/`excludeSections` (header, navigation, body, footer…); verbosity compact, standard or full.
  - `highlights` and `summary` (LLM).
  - `extras.links`, `extras.imageLinks`, `subpages`.
  - `maxAgeHours`: "`0` returns live content… `-1` always uses the cache".
  - Result metadata: `title`, `publishedDate`, `author`, `image`, `favicon`, `statuses`, `costDollars`.
  - Price: "$1/1k pages per content type".
  - Source: [Exa Contents reference](https://exa.ai/docs/reference/get-contents.md); [Exa pricing](https://exa.ai/pricing)
- **Tavily `/extract`.**
  - `format` "`markdown`… `text`". `extract_depth` "`advanced` extraction retrieves more data, including tables and embedded content". `query` with `chunks_per_source` reranks about 800-character chunks. `include_images`, `include_favicon`. `timeout` default "10 seconds for basic… 30 seconds for advanced". — [Tavily Extract reference](https://docs.tavily.com/documentation/api-reference/endpoint/extract.md)
  - "Handles JavaScript-rendered pages." — [Tavily llms-full](https://docs.tavily.com/llms-full.txt)
  - Price: 1 credit per 5 URLs (basic) or 2 per 5 (advanced). — [Tavily Credits](https://docs.tavily.com/documentation/api-credits.md)
- **Parallel `/v1/extract`.**
  - "converts any public URL into clean markdown, including JavaScript-heavy pages and PDFs. It returns focused excerpts aligned to your objective, or full page content if requested." — [Parallel Extract quickstart](https://docs.parallel.ai/extract/extract-quickstart.md)
  - Fields: `excerpts` ("Relevant excerpts formatted as markdown"), `full_content`, `publish_date`, `title`. `fetch_policy.max_age_seconds`: "Minimum 600". `disable_cache_fallback`. Price $1 per 1k URLs. — [Parallel Advanced Extract Settings](https://docs.parallel.ai/extract/advanced-extract-settings.md); [Parallel pricing docs](https://docs.parallel.ai/getting-started/pricing.md)
- **Linkup `/fetch`.**
  - "returns a clean markdown rendering of the page… HTML and PDF documents are supported."
  - Options: "`renderJs`… Required for client-side-rendered pages (SPAs…)"; "`includeRawHtml`"; "`extractImages`"; `schema` returns typed `data` (model pass).
  - "Fetch reads this URL only. It does not follow links."
  - Price: $0.001 to $0.011 per call.
  - Source: [Linkup Fetch overview](https://docs.linkup.so/pages/documentation/endpoints/fetch/overview.md); [Linkup Pricing docs](https://docs.linkup.so/pages/documentation/platform/pricing.md)
- **You.com Extract.**
  - "fetches any webpage or PDF and parses it into clean Markdown or HTML… PDF tables come back as Markdown or HTML tables with their rows and columns intact."
  - Fields: `contents.full_page` (markdown and/or html), `title`, `metadata`.
  - `extraction_source` is `blend`, `cache` or `fetch`. `timeout` is 2–100 s, default 30. One URL per request.
  - Price: $0.90 per 1k URLs.
  - Source: [You.com Extract](https://you.com/docs/guides/extract.md)
- **Perplexity Context API.**
  - Formats: "`markdown`", "`html`", "`links`" ("absolute URLs, without duplicates, in page order"), "`highlights`" (query-relevant passages), plus metadata including `origin` ("cached") and `fetched_at`.
  - It is batched: "Send a batch of URLs in one request". Price: $1 per 1k URLs.
  - Source: [Perplexity Context formats](https://docs.perplexity.ai/docs/context/formats-and-freshness.md); [Context quickstart](https://docs.perplexity.ai/docs/context/quickstart.md)
- **Jina r.jina.ai.**
  - JSON mode returns "the URL, title, content, and timestamp". Headers include X-Engine (browser engine), Return-Format, X-With-Links-Summary, X-With-Images-Summary, X-Target-Selector, X-No-Cache and X-Cache-Tolerance. PDFs are supported. POST can "Execute custom JS to modify the page before content extraction."
  - Cost: output tokens.
  - Source: [Jina Reader](https://jina.ai/reader)
- **Firecrawl `/scrape`.**
  - Formats: markdown, summary, html, rawHtml, rawBase64, screenshot ("URLs expire after 24 hours"), links, json, images, branding, product, audio, video, query. It "Handles dynamic content: dynamic websites, js-rendered sites, PDFs, images".
  - Cost: 1 credit per page; +4 credits for JSON, question or highlights formats.
  - Source: [Firecrawl Scrape](https://docs.firecrawl.dev/features/scrape.md); [Firecrawl pricing](https://www.firecrawl.dev/pricing)
- **Valyu `/contents`.**
  - "Returns clean markdown for each URL. Pass up to 10 URLs synchronously, or up to 50 with async mode."
  - `extract_effort`: "`normal` (HTTP extraction), `high` (browser rendering), `auto`". Also `response_length`, `screenshot`, `include_image_links`, `max_age`.
  - Cost: 0.2 credits per URL.
  - Source: [Valyu Contents](https://docs.valyu.ai/guides/content-extraction.md); [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)

### Inferences
- For a "fetch a page into structured form" tool without provider-side generation, the best fits are:
  - Firecrawl `/scrape` (markdown + links + metadata). Its AGPL self-host option removes per-page fees and vendor terms, though URnetwork then bears the scraping-legal exposure.
  - Exa `/contents` (section filters, link styles, metadata).
  - Linkup `/fetch` (explicit JS toggle, raw HTML).
  - Parallel `/v1/extract` (JS and PDF).
- "Structured form" via JSON schemas is LLM-based everywhere it appears (Exa summary schema, Linkup `schema`, Firecrawl `json`, Valyu `summary` schema). Under the TEE rule it must run in URnetwork's own TEE inference on the markdown output.

### Gaps
- JS rendering support is not documented for Exa `/contents`, You.com Extract or Perplexity Context.

## 7. Payment methods (card, invoice, crypto or x402) and prepaid mechanics

### Takeaway
All accept cards. Most are prepaid credit balances with auto-recharge. x402 or other stablecoin per-request payment is documented for:
- Exa: USDC on Base, Solana and Arc; Circle nanopayments; Tempo MPP.
- Tavily: Advanced Search, $0.01 on Base.
- Parallel: MPP via Stripe or Tempo, and x402 on Base.
- Linkup: $0.01 per request on Base.
- You.com: x402 on Base or Solana at $0.005 per Web Search; MPP on Tempo.

Invoicing is enterprise-only almost everywhere. Brave also has x402, launched Nov 12 2026.

### Cited Findings
- **Exa.**
  - "Pay via card or bank account". "payments are processed through Stripe". Auto recharge runs from $5 to $10,000 with an optional monthly maximum. "Postpaid invoice billing is available with an Enterprise plan." — [Exa pricing](https://exa.ai/pricing); [Exa Billing](https://exa.ai/docs/admin/billing.md)
  - x402: "Pay per request with USDC on Arc, Base, World Chain, or Solana via the x402 protocol, including Circle Gateway nanopayments"; "Exa supports x402 on two endpoints: `/search` and `/contents`". An example 402 offer shows `"amount": "7000"` (that is, $0.007) on `eip155:8453`. — [Exa x402](https://exa.ai/docs/integrations/payments/x402/quickstart.md)
  - Also "Pay with MPP (Tempo)" and "Nevermined". — [Exa docs index](https://exa.ai/docs/llms.txt)
- **Tavily.**
  - ToS §4.4 Cryptocurrency Payments: "Tavily may, in its sole discretion, accept payment of Fees in cryptocurrency or other digital assets approved by Tavily… but Tavily is not obligated to do so". §4.6: "All payments are quoted and must be paid in United States Dollars unless otherwise specified". — [Tavily ToS](https://www.tavily.com/terms)
  - x402: "AI agents pay per request for Tavily Advanced Search in USDC on Base". The offer shows `"amount": "10000"` (that is, $0.01). — [Tavily x402](https://docs.tavily.com/documentation/machine-payments/x402.md)
  - The partnerships page names AWS, IBM, Snowflake, Databricks and MongoDB as partners. It says "marketplace partners distribute Tavily's API through their cloud platforms and tool catalogs", but it does not say which of these is a billing marketplace. — [Tavily partnerships](https://www.tavily.com/partnerships)
- **Parallel.**
  - Billing through a "third-party payment processor" and "auto-reload functionality"; "Customer shall make all payments hereunder in US dollars". — [Parallel Customer Terms §6](https://parallel.ai/customer-terms)
  - MPP gateway `parallelmpp.dev`: "Stripe: Pay with a credit card… Tempo stablecoins… x402: Pay with USDC on Base"; "Per-request pricing starting at $0.01 for search and extract". — [Parallel Agentic Payments](https://docs.parallel.ai/integrations/agentic-payments.md)
  - Enterprise "invoicing and marketplace billing". A post dated Nov 11 2026 is titled "Parallel Search is now available in AWS Marketplace". — [Parallel pricing](https://parallel.ai/pricing); [Parallel blog list](https://parallel.ai/blog/series-b)
- **Linkup.**
  - "API Key | USD | Prepaid credit balance"; "x402 | USD (USDC) | Per-request on-chain settlement. A minimum charge of $0.01 per request applies." — [Linkup Pricing docs](https://docs.linkup.so/pages/documentation/platform/pricing.md)
  - Conflict 1. The x402 page says "All x402-enabled endpoints are billed at a flat rate of $0.01 per request." — [Linkup x402](https://docs.linkup.so/pages/documentation/platform/x402.md)
  - Conflict 2. The terms say "All prices are in Euros, exclusive of costs and taxes." — [Linkup terms](https://www.linkup.so/terms-of-use)
- **You.com.**
  - "You.com accepts major credit and debit cards." Auto Top-Up is configurable. — [You.com Billing](https://you.com/docs/administration/billing.md)
  - Machine payments: "x402… Settles in USDC on Base or Solana | Web Search per call $0.005"; "MPP… USDC on Tempo | $0.01"; "Cards and fiat are not currently enabled on either protocol." — [You.com Machine Payments](https://you.com/docs/administration/machine-payments.md)
- **Perplexity.**
  - "Customer hereby authorizes Perplexity to automatically charge Fees using the payment information provided". Fees are in U.S. Dollars. — [Perplexity API ToS §4.1](https://www.perplexity.ai/hub/legal/perplexity-api-terms-of-service)
  - "buy API credits through AWS Marketplace". — [Perplexity docs index](https://docs.perplexity.ai/llms.txt)
- **Jina.**
  - "Payments are processed through Stripe, supporting a variety of payment methods including credit cards, Google Pay, and PayPal".
  - Auto top-up "for the last purchased package". "Depending on your location, you may be charged in USD, EUR, or other currencies."
  - Balances are per key and transferable: "Balance and rate limits belong to an API key, not to the account".
  - Source: [Jina Reader / pricing](https://jina.ai/reader)
- **Firecrawl.**
  - "We accept payments through Stripe which accepts most major credit cards, debit cards, and PayPal." Pay-as-you-go adds "5 USD increments, up to a monthly limit you set". "Also on AWS Marketplace and Google Cloud Marketplace."
  - "Credits roll over on Scale and Enterprise… Hobby, Standard and Growth credits do not roll over."
  - Source: [Firecrawl pricing](https://www.firecrawl.dev/pricing)
- **Valyu.** "Credits are prepaid and non-refundable. We may charge your payment method automatically for usage." Pay-as-you-go "Top-ups last 12 months". — [Valyu PSA §9](https://www.valyu.ai/valyu-platform-service-agreement); [Valyu Pricing docs](https://docs.valyu.ai/pricing.md)

### Inferences
- A cost-plus prepaid relay maps most cleanly onto Exa, Linkup, You.com, Perplexity and Valyu (pure usage drawdown) and Parallel Build.
- x402 could let each user's agent pay the provider directly per call, which would sidestep resale. Exa, You.com, Tavily, Linkup and Parallel accept it. But each x402 payment is a public on-chain record, a privacy cost to weigh against E2EE goals. And it would no longer be "one URnetwork account".

### Gaps
- Linkup's card or processor for top-ups was not documented on the pages fetched. Whether Valyu, Firecrawl or Jina accept x402 or crypto was not found.

## 8. Attribution requirements

### Takeaway
Only Valyu imposes attribution in published terms. Its Website Terms condition Output use on displaying "source attribution and/or citation to Valyu or it's Partners". No attribution requirement was found in the API terms of Exa, Tavily, Parallel, Linkup, You.com, Perplexity, Jina or Firecrawl. Brave's ToS makes "POWERED BY BRAVE" attribution optional, but Brave's Feb 2026 blog tied its free monthly credit to attribution on the project's website or about page (section 4 of the Brave notes).

### Cited Findings
- Valyu, §6.2: the license to "use Outputs returned by the Services, provided that any source attribution and/or citation to Valyu or it's Partners is included in the Output and is displayed clearly. It will not be removed, obscured, or disabled within your service or product. You must not modify Outputs in a way that suppresses or alters attribution, and you may not circumvent any technical attribution controls included in the Services." — [Valyu Website Terms, Oct 20 2025](https://www.valyu.ai/terms)
- Valyu AUP §10: "Misrepresent Valyu's data as proprietary to your own organisation" is prohibited. — [Valyu AUP](https://www.valyu.ai/valyu-acceptable-use-policy)
- A keyword scan for "attribut" and "powered by" across the other providers' terms found no attribution clause. Those terms are Exa's ToS, Tavily's ToS and AUP, Parallel's Customer Terms, Linkup's terms, You.com's MSA, Perplexity's API ToS and Search Addendum, Jina's T&Cs, and Firecrawl's ToS. Exa does bar any use of "trademark, service mark… logo" (§4.2(c)). — [Exa ToS](https://exa.ai/assets/Exa_Labs_Terms_of_Service.pdf)
- Linkup's AFP premium feed is access-controlled per organization. No display-attribution rule was found in the docs page. — [Linkup Premium Sources](https://docs.linkup.so/pages/documentation/platform/premium-sources.md)

### Inferences
- Showing source URLs and titles, which the UI needs anyway, satisfies any reasonable reading of Valyu's clause. Valyu's "Partners" (publishers) may need visible credit.

### Gaps
- Partner-specific attribution for licensed content (Linkup/AFP, Valyu/Wiley, Exa Connect providers, Firecrawl Alexandria providers) was not reviewed in detail.

## 9. Company stability: funding, acquisitions, ownership changes in 2025–2026

### Takeaway
Three of the nine have new owners or large late-stage rounds in 2026:
- Exa: $250M Series C, May 20 2026, $2.2B valuation.
- Parallel: $100M Series B, Apr 29 2026, $2B valuation, $230M raised in total.
- Firecrawl: $75M Series B, Sep 22 2026.

Two were acquired:
- Jina by Elastic (October 2025).
- Tavily by Nebius (agreement announced Feb 10 2026, reported $275M, now "part of the Nebius product portfolio").

Linkup raised a $10M seed (Feb 2026). You.com's last confirmed round is a $100M Series C (Sep 2025, $1.5B). Perplexity remains a large private company; its 2026 round figures come only from secondary sources. Valyu shows no verified institutional round.

### Cited Findings
- **Exa.** "Exa just raised $250M at a $2.2B valuation led by a16z to power all agents with the highest quality web search." It is dated May 20, 2026. — [Exa blog](https://exa.ai/blog/announcing-series-c). The prior round was an $85M Series B in Sep 2025 at about $700M, per [Built In](https://builtin.com/articles/exa-raises-85m-series-b-20250908) (seen only as a search result).
- **Parallel.** "April 29, 2026… Announcing our $100 million Series B at a $2 billion valuation… Sequoia Capital led the round… brings total capital raised to $230 million." The Series A was "five months ago". — [Parallel blog](https://parallel.ai/blog/series-b)
- **Firecrawl.** "We raised a $75M Series B led by Smash Capital… Published: September 22, 2026"; "Over 1.5 million users build with Firecrawl now." — [Firecrawl blog](https://www.firecrawl.dev/blog/introducing-alexandria-series-b.md)
- **Tavily.**
  - "Amsterdam, February 10, 2026 — Nebius (NASDAQ: NBIS)… today announced an agreement to acquire Tavily". — [Nebius newsroom](https://nebius.com/newsroom/nebius-announces-agreement-to-acquire-tavily-to-add-agentic-search-to-its-ai-cloud-platform)
  - Tavily's docs now say "Tavily is part of the Nebius product portfolio". — [Tavily docs index](https://docs.tavily.com/llms.txt)
  - Price: undisclosed. Bloomberg reported $275M and Calcalist up to $400M with milestones, as summarized in search results from [SiliconANGLE](https://siliconangle.com/2026/02/10/ai-infrastructure-giant-nebius-buys-agentic-search-startup-tavily/) and [Globes](https://en.globes.co.il/en/article-1001534602). These figures were not read on the primary page.
- **Jina AI.** "In October 2025, Jina AI GmbH was acquired by Elastic N.V. (NYSE: ESTC)." — [Jina legal](https://jina.ai/legal)
- **Linkup.** "Linkup… announced a $10 million seed round led by Gradient, with participation from Elaia… Seedcamp…". It is dated 10 February 2026. — [The AI Insider](https://theaiinsider.tech/2026/02/10/linkup-raises-10m-seed-round-led-by-gradient-to-build-web-search-for-ai/)
- **You.com.** "September 3, 2025… we raised $100 million in Series C funding at a $1.5 billion valuation, led by Cox Enterprises". No 2026 round was found in search. — [You.com Series C](https://you.com/resources/series-c)
- **Perplexity.**
  - The Search API launched Sep 25, 2025, per launch coverage seen in search results ([InfoQ](https://infoq.com/news/2025/09/perplexity-search-api); [Perplexity community post](https://community.perplexity.ai/t/introducing-the-perplexity-search-api/1579)).
  - Valuations reported by secondary trackers: $20B (Sep 2025) and a Jan 2026 round at $20.4B–$23B. Talks were reported in Aug 2026 at over $30B. None was confirmed on a primary page. — [Sacra](https://sacra.com/c/perplexity); [DefiLlama](https://defillama.com/pre-ipo/perplexity-ai)
- **Valyu.** Third-party trackers list only about $500K pre-seed or accelerator money (March 2024). That is not confirmed by the company. — [VCBacked](https://www.vcbacked.co/company/valyu); [Caplight](https://www.caplight.com/company/valyu)
  - Its site promotes "the Wiley x Valyu HLS Startup Program". — [Valyu pricing](https://www.valyu.ai/pricing)

### Inferences
- **Ownership-change risk.**
  - Tavily's terms now sit under Nebius, an AI-cloud and inference seller. Bundling with Nebius Token Factory may shift Tavily's priorities.
  - Jina is inside Elastic. Its own legal page says the old terms "may no longer reflect the current data processing practices", so expect re-papering under Elastic terms.
- **Best-funded independents.** Exa and Parallel are the best-capitalized independent indexes. Each runs its own crawler, which supports continuity.
- **Smaller vendors.** Linkup (seed stage) and Valyu (no verified round) carry more vendor risk.

### Gaps
- The close of Nebius–Tavily and its final price are not confirmed from a primary source. Tavily's terms (May 2026) still name "AlphaAI Technologies Inc. dba Tavily".
- Perplexity's 2026 funding and valuation were not verified from primary sources.
- Valyu's funding history is unverified.
