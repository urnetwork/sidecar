# Synthesis, branch 1.9: passing vendor security review despite the consumer network's reputation (as of 1 Nov 2026)

**What this covers.** One branch of the pitch4 research tree:
- **Level 1, [1.9]:** how URnetwork can pass vendor security review despite its consumer network's reputation. Notes: `L1-1.09-trust-and-reputation.md`.
- **Level 2, [2.12]:** how outside-in security controls classify URnetwork's domains and IP space. Notes: `L2-2.12-how-do-outside-in-security-controls-classify-urn.md`.

Both files are in this folder. The branch stops at level 2: no level-3 or level-4 question was opened from 2.12. 1.9 also co-opened L2-2.05 (how reviews treat ciphertext-only and self-hosted vendors) with 1.06 and 1.07. That note belongs to another branch, and nothing from it is used here.

**Rules for this synthesis.** Every claim comes from the two notes. Where 1.9 relied on earlier work (`Sidecar positioning and market gaps/urnetwork_right_to_win.md`), the item is marked [earlier notes]. The evidence labels are the notes' own:
- **[fetched]:** read directly on 1 Nov 2026.
- **[observed]:** a query 2.12 ran itself on 1 Nov 2026 (dig, curl, openssl).
- **[search summary]:** seen only in a search engine's summary.
- **[vendor claim]:** a company's statement about itself.
- **[inference]:** reasoning in the notes, not a sourced fact.
- **[synthesis inference]:** reasoning added here.

2.12's raw lookup outputs (resolve.txt, filters.txt, controls.txt, lists/) were saved to a temporary scratchpad folder that may not persist: `/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/b393ced6-3aa9-4b23-b53f-b2d87e80f483/scratchpad/data/`.

## 1. What the branch found

1. **The sidecar will be reviewed as a top-tier vendor because of what it does, before reputation comes in.**
   - It runs where source code and agent sessions live, opens network paths, and gates model access [1.9 inference].
   - The US interagency third-party guidance scales diligence to risk: "More comprehensive due diligence is particularly important when a third party supports higher-risk activities, including critical activities."
   - Its factors include:
     - ownership "(including identifying any beneficial ownership";
     - reliance on subcontractors;
     - insurance;
     - a check that the third party's website and marketing claims are accurate.

   Source: [88 FR, 9 Jun 2023](https://www.govinfo.gov/content/pkg/FR-2023-06-09/html/2023-12340.htm) [fetched].

2. **The likely escalation triggers specific to URnetwork, in 1.9's order** [inference]:
   1. Marketing claims a reviewer is told to verify: "No logs" next to a public threat model that lists retention, and the "Passes Proxy/VPN detection" testimonial.
   2. The split between BringYour, Inc. and the token-governed UR Foundation.
   3. Unvetted fourth parties, if any SN25 operator or provider carries sidecar packets.
   4. Domain and IP category hits.
   5. No attestation and no insurance evidence.
   6. Sanctions optics: the Iran testimonial, a generic export clause, and payouts in digital assets.

3. **Automated controls act before any reviewer, and they already file URnetwork as a personal VPN.** On 1 Nov 2026:
   - **Cisco Talos** puts ur.io, ur.network, bringyour.com and the api, connect, mcp and extender hosts in "Personal VPN", reputation Neutral or Favorable. Cisco's own definition says these "may or may not be approved for corporate usage". ur.xyz is "Computers and Internet". — [Talos JSON](https://talosintelligence.com/cloud_intel/url_reputation?url=ur.io) [fetched]
   - **DigiCert UltraDNS:** its threat tier blocks bringyour.com, its subdomains, and ur.xyz [observed].
   - **HaGeZi:** its VPN/proxy-bypass list holds all four apexes. Its Ultimate list also names api.bringyour.com, connect.bringyour.com, ur.network and ur.xyz. — [bypass list](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt), [Ultimate](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt) [fetched]
   - **Identity and firewall defaults now target the category.**
     - Okta made a curated HIGH_RISK_PROXIES category generally available on 28 Oct 2026. — [Okta release notes](https://help.okta.com/oie/en-us/content/topics/releasenotes/preview-oie.htm) [fetched]
     - Palo Alto's setup guide says to block "proxy-avoidance-and-anonymizers", "newly-registered-domain" and "unknown". — [Palo Alto docs](https://docs.paloaltonetworks.com/advanced-url-filtering/administration/configuring-url-filtering/get-started-with-url-filtering/get-started-with-url-filtering-pan-os) [fetched]
   - **Nothing marks URnetwork as malicious.** No control checked marks any URnetwork asset as malware or phishing. Every public filtering resolver tested except UltraDNS blocks none of its hosts.

4. **URnetwork has no infrastructure the sidecar could share cleanly.**
   - The API, relay, MCP and gossip hosts share a small pool in Hurricane Electric's (HE's) non-portable address space, with no reassignment to BringYour. — [ARIN RDAP](https://rdap.arin.net/registry/ip/65.49.70.70) [fetched]
   - Shodan lists the same 37 bringyour.com hostnames on those addresses, including "main-proxy". — [InternetDB](https://internetdb.shodan.io/65.49.70.70) [fetched]
   - Four of the pool's addresses are on Barracuda's reputation list [observed].
   - extender.bringyour.com resolves to six third-party VPS hosts serving a private-CA certificate. One of them is in FireHOL's open-proxy aggregate. — [firehol_proxies](https://iplists.firehol.org/files/firehol_proxies.netset) [fetched]

5. **The blocklist entries came from the provider side, and they are hard to undo.**
   - One GitHub user filed three block requests that grouped URnetwork with bandwidth-sharing apps (Honeygain, EarnApp, Grass, Pawns). Each was accepted within a day.
   - The one formal unblock request was closed five minutes after it was opened.

   Sources: [#9039](https://github.com/hagezi/dns-blocklists/issues/9039), [#11274](https://github.com/hagezi/dns-blocklists/issues/11274), [#11569](https://github.com/hagezi/dns-blocklists/issues/11569) [fetched via GitHub API].

6. **Structure, not certificates, separates a vendor from this category.**
   - Token-associated companies that won enterprise business did three things [1.9 inference from Brave, Storj, Livepeer and Akash]:
     - made the operating company the counterparty;
     - carved out a narrow product with its own attestation, on stricter infrastructure;
     - kept the token out of the buyer's payment path.
   - Bright Data holds ISO 27001 and SOC 2 and is still the archetype of the category Okta now lists. — [Bright Data](https://docs.brightdata.com/general/security/security-overview) [search summary; vendor claim]

7. **A minimum trust package costs roughly $22k–$115k in sourced year-one direct costs** [1.9 inference from vendor and broker ranges].
   - That excludes a penetration test, a protocol audit and legal work, which could not be sourced.
   - It reaches SOC 2 Type 1 in about 3–4 months and Type II in about 9–12.

8. **What this means for pitch4.**
   - The line "uses URnetwork's network only for worldwide reach" (page 6) is unsafe as written.
   - "Trust documents first" (page 6) lacks the commercial and attestation items that questionnaires ask for.
   - The branch's best idea for differentiation is "attribution, not anonymity". Every path an agent takes is named, granted and signed, down to the relay and the operator that carried it.

## 2. Directions for pitch4

### Page map

| pitch4 page | Directions that would change it |
|---|---|
| 1 The idea | D8 (the "Open source" box), D9 (the "URnetwork · Sidecar" header) |
| 2 For developers | D6 ("Nothing to change": install works behind corporate filters) |
| 3 For security buyers | D1, D3, D4, D5, D6, D7, D9 |
| 4 Open source and open weights | D4, D7, D8 ("Open core, hosted blind") |
| 5 Market and pricing | D2 (beachhead and Assured), D3 (reach row), D4 (who bills), D10 (Assured self-host) |
| 6 The plan | all ten (D1–D10) |

Directions are ordered by confidence, then by how much of pitch4 they touch.

---

### D1. Draw a hard runtime boundary between the sidecar and the consumer network
**Effect:** offering. **Confidence:** high. Level 2 upgraded this from "should" to "required by current classifications".

**What to change.** At runtime, the sidecar never depends on:
- ur.io, ur.network, ur.xyz, or any bringyour.com name, including the api, connect, mcp and extender hosts;
- the Hurricane Electric pool or the extenders;
- any URnetwork provider exit, SN25 operator or miner, so no agent packet ever crosses one.

It gets its own infrastructure [2.12 §7; 1.9 §3]:
- its own domains, registered early and paid more than two years ahead (the term the PSL withdrawal cited, see D7), with publicly trusted certificates, DNSSEC, DMARC `p=reject`, CAA and an abuse contact;
- its own relay IP ranges;
- a published allowlist of domains, SNI names, IPs and ports.

**Pitch4 change.**
- **Page 6, "Trust documents first", last bullet:** replace "uses URnetwork's network only for worldwide reach" with the boundary.
- **Page 6, "Risks we manage: Reputation":** name the boundary, not only "agents leave only through exits you run".
- **Page 3, the "IP addresses" card ("leave only through exits you run") and "Why encryption makes it safe to adopt":** state the boundary as a rule that covers relays as well as exits.
- **Page 6, "Reach comes first, as the closest to code URnetwork runs today":** make clear the sidecar reuses code, not hosts [synthesis inference].

**Why it helps.** Classifications attach to names and addresses, not to products. A sidecar on any shared name or address starts out with the consumer network's category, list entries and rating findings. A clean boundary lets a reviewer place the sidecar beside Tailscale and ngrok, not beside URnetwork's exits.

**Evidence.**
- **Every runtime host already carries the consumer classification.**
  - Talos files every bringyour.com runtime host as "Personal VPN". — [Talos JSON, mcp.bringyour.com](https://talosintelligence.com/cloud_intel/url_reputation?url=mcp.bringyour.com) [fetched]
  - UltraDNS's threat, family and business tiers all block the bringyour.com hosts [observed].
  - HaGeZi Ultimate names api.bringyour.com and connect.bringyour.com.
  - The bypass list sits in HaGeZi's wildcard folder, so wildcard blockers drop every subdomain of a listed apex. — [bypass list](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt) [fetched]
- **The most exposed name is the contracting entity's own.** bringyour.com is the name classification engines see most: Tranco rank 24,607, against about 4.4 million for ur.io. — [Tranco](https://tranco-list.eu/api/ranks/domain/bringyour.com) [fetched]
- **The address pool.**
  - It is HE's "NON-PORTABLE" space, with no reassignment to BringYour and no ARIN entity for BringYour. — [ARIN RDAP 65.19.157.42](https://rdap.arin.net/registry/ip/65.19.157.42), [entity search](https://rdap.arin.net/registry/entities?fn=BringYour*) [fetched]
  - So BringYour "cannot build IP reputation that is separate from Hurricane Electric's" [2.12 inference].
  - Barracuda lists 65.19.157.40, .41, .42 and .62 but none of their neighbors.
  - UCEPROTECT Level 3, an ASN- or allocation-level list, covers all 11 HE addresses. [observed]
- **The extenders.**
  - Six VPS hosts that BringYour does not run answer for extender.bringyour.com: Octopus Web Solution, OWS, CentrixNodes, Hostodo, HKT (Hong Kong) and ColoCrossing/HostPapa.
  - They serve an "Extender Root" private-CA certificate and send no HSTS header [observed].
  - 206.217.141.172 is in FireHOL's proxies and anonymous aggregates. — [firehol_anonymous](https://iplists.firehol.org/files/firehol_anonymous.netset) [fetched]
- **Ratings attribute by DNS and IP.** Rating vendors map assets to companies through DNS, IP/CIDR blocks and company relationships. — [Bitsight](https://help.bitsighttech.com/hc/en-us/articles/360007320574-A-Guide-to-Navigating-and-Prioritizing-Bitsight-Risk-Categories-Risk-V), [SecurityScorecard](https://securityscorecard.com/blog/securityscorecard-10-risk-factors-explained) [search summary]
- **IP intelligence works from behavior.**
  - Spur classifies an IP from "the activity it observes on it, not from who owns the IP". — [Spur FAQ](https://docs.spur.us/knowledgebase/faqs/how-does-spur-detect-vpns-residential-proxies-and-isp-proxies) [search summary; vendor claim]
  - Okta already names MYSTERIUM_VPN, a comparable dVPN. — [Okta categories](https://help.okta.com/oie/en-us/content/topics/security/network/supported-ip-service-categories.htm) [fetched]
  - 2.12 infers that URnetwork exits are probably caught by generic flags today, so "exits you run" has to stay a hard rule [inference, unverified].
- **Subcontractors.**
  - ur.xyz: "Operators run servers and deposit alpha for the traffic they serve. Miners carry encrypted traffic and earn emissions." — [ur.xyz](https://ur.xyz/) [fetched]
  - Any sidecar packet on those hosts would make them unvetted fourth parties under the interagency "reliance on subcontractors" factor [1.9 inference].

**Counter-evidence.**
- **Nothing is flagged malicious.**
  - Talos reputations are Neutral or Favorable.
  - Google Safe Browsing reports no unsafe content for the four apexes. — [Transparency Report](https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=ur.io) [fetched; undocumented endpoint, 2.12's reading]
  - Core hosts expose only ports 80 and 443 and show no CVEs.
  - None of the 17 IPv4 addresses checked is on Spamhaus ZEN, FireHOL levels 1–3 or ipsum.
- **Most filtering resolvers ignore URnetwork.** OpenDNS FamilyShield blocks 14 of 27 VPN and proxy control domains, and CleanBrowsing Family 16, but neither blocks any URnetwork host tested; CleanBrowsing's extender query timed out [observed].
- **Enterprise vendors share the same categories and lists.**
  - Tailscale's control plane and NetBird are "Personal VPN" at Talos too.
  - tailscale.com, ngrok, NetBird and ZeroTier are on HaGeZi's bypass list too.
  - They still sell to enterprises [1.9 inference].
- **The deciding data are missing.**
  - Unknown: how Zscaler, PAN-DB, Netskope, FortiGuard and Cloudflare Gateway categorize URnetwork, and whether their defaults block "Personal VPN".
  - So it is unproven that separation by itself changes outcomes.
- **Separation creates a new-domain problem.**
  - None of URnetwork's domains is newly registered; ur.io dates from 2009.
  - A fresh sidecar domain would be "newly registered" for 32 days and "unknown" until categorized, and Palo Alto recommends blocking both. — [PAN URL risk categories](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/10-0/pan-os-admin/url-filtering/url-categories/url-risk-categories.html) [search summary]
- **A new domain may still be rated as BringYour's.** If BringYour, Inc. signs (D4), vendors that map company relationships may still attach the sidecar to BringYour's profile. 2.12 thinks only a separate entity and domain would "probably" get a profile of their own [inference].

**Cost and risk.**
- No costs are sourced: new domains, relay ranges with a clean history, possibly an ASN later.
- The sidecar gives up reusing URnetwork's running relay hosts.
- Domains registered late land in the newly-registered and unknown window.
- Cheap fixes to BringYour's own rating inputs also help, in case anything stays attributed to BringYour [2.12 §6]:
  - DMARC `p=reject` on ur.io and ur.network;
  - an SPF record on ur.network;
  - a null MX and SPF `-all` on ur.xyz;
  - a public certificate on the extenders, or moving them off bringyour.com;
  - clearing the Barracuda listing.

**Test.**
- Before the first design partner, list every name and address the sidecar build contacts. Confirm none is a URnetwork name, a pool address or an extender.
- Run 2.12's checks against the new names and ranges at launch, then monthly: the Talos JSON, the three UltraDNS tiers, the HaGeZi lists, Barracuda, FireHOL and Spamhaus.
- Claim BringYour's Bitsight and SecurityScorecard profiles (both vendors offer this) to see what each attributes to BringYour and what to the sidecar.

---

### D2. Publish the trust packet that questionnaires ask for, scoped to the sidecar, before the first design partner
**Effect:** offering. **Confidence:** high that these items are asked for. The cost and timing figures are soft.

**What to change.** Expand "Trust documents first" into 1.9's staged package.

- **Weeks 0–4: documents.**
  - The contracting entity named in the MSA, a no-token and no-emissions clause, and fiat-only billing (see D4).
  - A data-flow diagram listing every hop, and a subprocessor list stating that no SN25 operator or community provider is in the path.
  - A DPA with SCCs, and EU–US Data Privacy Framework (DPF) self-certification.
  - A published sanctions policy: customer screening and embargoed-region blocking for the paid sidecar, plus a GL D-2 note for the consumer VPN.
  - CAIQ v4 or CAIQ Lite on the CSA STAR Level 1 registry, with a pre-filled "proxy-SDK disclosure" answer.
  - The sidecar's domains registered and categorized, and the allowlist published (D1, D5).
  - security.txt and the VDP extended to the sidecar's repositories.
- **Months 1–4: testing and insurance.**
  - A third-party penetration test of the client and relay, with a public summary letter.
  - The Cure53 protocol audit, published in full.
  - $1–2M of cyber and tech E&O insurance.
- **Months 2–4: SOC 2 Type 1.** Security criteria, scoped to the hosted relay, ledger and storage. The consumer network is excluded.
- **Months 4–10: SOC 2 Type II,** over a 3–6-month window.
- **Ongoing.** A trust center with a public SOC 3 or summary, yearly audits and penetration tests, and a dated canary and transparency report.
- **For EU finance:** an LEI.

**Pitch4 change.**
- **Page 6, "Trust documents first":** turn the five bullets into this dated list.
- **Page 6, design-partner table:** add a row, "Does the trust packet clear review?" (see Test).
- **Page 5, "Where we start":** "Fintech, health, and other regulated teams" will need Type II. Its observation window runs over months 4–10, and the report arrives about 9–12 months out. Say so, or reorder the beachhead.
- **Page 5, the Assured tier:** replace "compliance mappings" with the attestations and their dates.

**Why it helps.**
- 1.9 found pitch4's list necessary but incomplete. The list: open source, reproducible builds, an audit, a threat model, a canary, a no-token statement.
- What it lacks are the commercial and attestation items that questionnaires ask for. Without them a top-tier review stalls, whatever the architecture.

**Evidence.**
- **The interagency factors** include ownership, subcontractors, insurance, information security and incident management. When information cannot be obtained, the bank documents the limits and considers alternatives, including a different third party. — [88 FR](https://www.govinfo.gov/content/pkg/FR-2023-06-09/html/2023-12340.htm) [fetched]
- **SOC 2 as the gate.**
  - Proton: "SOC 2 is a baseline requirement before moving forward with a vendor," especially in "finance, healthcare, and other regulated industries". — [Proton](https://proton.me/blog/soc-2) [fetched; vendor claim]
  - Proton went from ISO 27001 (2 May 2024) to SOC 2 Type II (July 2025, audited by Schellman).
  - Brave: "Many enterprise customers require SOC 2." — [Brave](https://brave.com/blog/soc2/) [fetched; vendor claim]
  - Brave's first Type II covered only the Search API, over a three-month window, with the report under NDA through trust.brave.app.
- **The question questionnaires should add.** The CSA advises: "add proxy-SDK disclosure to vendor security questionnaires". — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-residential-proxy-economy-systemic-risk-20/) [earlier notes]
- **Cheap items.**
  - CSA STAR Level 1 is a "complimentary" CAIQ v4 self-assessment. — [CSA STAR](https://cloudsecurityalliance.org/star) [search summary]
  - DPF costs $250 a year for organizations with up to $5M in revenue. — [Hunton](https://www.hunton.com/privacy-and-cybersecurity-law-blog/commerce-department-considers-fee-schedule-revisions-for-data-privacy-framework), [GDPR Local](https://gdprlocal.com/costs-of-eu-us-data-privacy-framework/) [search summary]
  - EU financial entities record an LEI or EUID for each ICT provider. — [springlex](https://www.springlex.eu/en/packages/dora/its-roi-regulation/article-3/) [search summary]
- **Insurance.**
  - A $1M cyber limit is a common contract floor, and $2M is common at Series A and B.
  - Premiums run about $1,500–$1,837 a year.

  Sources: [LatentInsure](https://www.latentinsure.com/blog/cyber-insurance-startups-guide), [StartupNation](https://startupnation.com/manage-your-business/cyber-insurance-startup-need/), [TechInsurance](https://www.techinsurance.com/technology-business-insurance/saas-companies/cost) [search summary; broker claims].
- **SOC 2 cost and time.**
  - Type 1: $12k–$40k, over 3–8 months.
  - Type 2: $15k–$75k, over 6–20 months.

  Sources: [Scrut](https://www.scrut.io/post/cost-of-soc-2-audit), [Agency](https://blog.getagency.com/articles/soc-2-audit-cost-for-startups), [soc2auditors.org](https://soc2auditors.org/insights/soc-2-type-1-vs-type-2/), [ComplyJet](https://www.complyjet.com/blog/soc-2-for-startups) [search summary; vendor claims].
- **What URnetwork has today.**
  - It has security.txt and a VDP with safe harbor. — [security.txt](https://ur.io/.well-known/security.txt), [VDP](https://ur.io/vdp) [fetched]
  - On ur.io, `/security`, `/trust`, `/dpa`, `/subprocessors`, `/soc2`, `/warrant-canary` and `/transparency` return 404, and trust.ur.io does not respond [fetched].
  - The Cobalt penetration test is marked for internal use only, and the Cure53 work is a briefing with no published audit [earlier notes].
- **Added at level 2.** Rating vendors score DNS and mail posture, open ports and IP reputation [2.12 §6]. So the sidecar's own domains, with DNSSEC, DMARC `p=reject`, CAA and an abuse contact, belong in the packet.

**Counter-evidence.**
- **Certificates are table stakes, not separation.** Bright Data holds ISO/IEC 27001:2022, 27017 and 27018, a SOC 2 Type II, and a public SOC 3 audited by a Deloitte firm. — [Bright Data](https://docs.brightdata.com/general/security/security-overview) [search summary; vendor claim]
- **The numbers are soft.** Every dollar figure is a vendor or broker range, the ranges conflict, and no real quotes were obtained. Penetration-test, protocol-audit, legal and LEI costs are unsourced.
- **Demand is unmeasured.**
  - No primary 2026 survey measures how often SOC 2 is required. Proton's and Brave's statements describe their own customers.
  - It is unknown whether 5–150-engineer teams accept a Type 1 plus a penetration-test letter, or require Type II.
- **The SOC 2 scope may not hold.** Excluding the consumer network may not work when the same staff and some of the same infrastructure run both. That needs an auditor's view.
- **The guidance is for banks.** The interagency guidance applies to US banks; 1.9 assumes other programs follow the same lifecycle.

**Cost and risk.**
- About $22k–$115k of sourced direct cost in year one, plus the unsourced items.
- About 3–4 months to Type 1 if the documents and penetration test start now, and 9–12 months to Type II.
- Risk: regulated design partners wait for Type II.

**Test.**
- For each design partner, record:
  - which packet items the security reviewer asked for;
  - whether a Type 1, a penetration-test letter and a CAIQ cleared the review;
  - how many days approval took.
- Get two or three quotes each from auditors and penetration testers.
- Ask one auditor whether the consumer network can be carved out of the SOC 2 scope.

---

### D3. Make the reach claim checkable, and make each receipt name the relay and operator ("attribution, not anonymity")
**Effect:** both. **Confidence:** medium.

**What to change.**
- **Replace the reach line** with 2.12's wording or close to it: "relays run by BringYour, Inc. on dedicated sidecar infrastructure listed in our allowlist; no URnetwork consumer host, extender or provider exit is ever in the path". 1.9 defines worldwide reach as relays run by BringYour, Inc. in named regions, or by the customer.
- **Name the carrier in every receipt.** Each connection's signed receipt names the relay hostname, the IP and the operator (BringYour or the customer), so an auditor can check it against the published allowlist.
- **Frame the network features as attribution:** the opposite of the anonymous egress that controls block.

**Pitch4 change.**
- **Page 3, "What admins can answer":** "What was reachable, by whom, and who connected" becomes "...and which relay and operator carried it".
- **Page 3, the port-forwarding card:** "The relay carries only ciphertext" should say whose relay.
- **Page 5, market table, Reach row:** "We add per-agent grants and receipts" becomes receipts that name the path.
- **Page 6:** the "worldwide reach" bullet, as in D1.

**Why it helps.**
- It turns the proxy question, the reputation's main liability, into a feature. A residential-proxy vendor can show certificates, but not a signed record of who carried each connection [1.9 inference].
- It also answers the subcontractor question that the current line invites.

**Evidence.**
- **What the controls target.**
  - Okta's HIGH_RISK_PROXIES is "powered by an Okta-curated list of proxy providers that Okta CyberDefense has identified as consistently high-risk, based on correlation with observed attacks such as credential stuffing and rate-limit abuse". — [Okta](https://help.okta.com/oie/en-us/content/topics/releasenotes/preview-oie.htm) [fetched]
  - CISA and the FBI tell organizations to "block or closely monitor" Tor traffic. — [AA20-183A](https://www.cisa.gov/uscert/sites/default/files/publications/AA20-183A_Defending_Against_Malicious_Cyber_Activity_Originating_from_Tor_S508C.pdf) [search summary]
- **IP reputation alone is failing defenders.**
  - GreyNoise: "Nearly 4 in 10 IPs hitting GreyNoise sensors were residential".
  - Its CEO: "every organization that relies on IP reputation as a primary defensive layer is exposed right now".

  Source: [Help Net Security](https://www.helpnetsecurity.com/2026/04/06/residential-proxy-attack-traffic-ip-reputation-enterprise-security/) [fetched; vendor research relayed by press]. A signed path record gives a reviewer something IP reputation cannot [synthesis inference].
- **The current line invites the question.** SN25 operators and miners are token-incentivized third parties ([ur.xyz](https://ur.xyz/) [fetched]), and "reliance on subcontractors" is an interagency due-diligence factor.
- **What incumbents offer.**
  - Tailscale and NetBird sit in the same Talos category as URnetwork. — [Talos JSON](https://talosintelligence.com/cloud_intel/url_reputation?url=ur.io) [fetched]
  - 2.12 infers that neither offers per-connection carrier receipts [inference, not checked].

**Counter-evidence.**
- **No demand is recorded.** No buyer or reviewer in either note asks for carrier receipts, and 1.9 calls user voice on this topic thin.
- **Receipts change no automated control.**
  - They help a human reviewer only.
  - Categories follow site content, and protective DNS and IP intelligence follow observed behavior [2.12 inference].
- **Naming the network invites a search.** Mentioning URnetwork's network at all invites a reviewer to look for that traffic [2.12 §7].
- **The gap is inferred.** That incumbents lack the feature has not been verified.

**Cost and risk.**
- A small addition to receipts pitch4 already plans, plus keeping the allowlist current. Neither is costed.
- Risk: overclaiming, if any packet ever crosses an SN25 host.

**Test.** In design-partner reviews, show the statement, a sample receipt and the allowlist. Record whether the subcontractor row closes without follow-up questions.

---

### D4. Name the counterparty, keep the token out of the sidecar, and bill in fiat
**Effect:** offering. **Confidence:** medium.

**What to change.**
- **The counterparty:** BringYour, Inc., or a dedicated subsidiary, signs.
- **The MSA states three things:**
  - the sidecar has no token;
  - its fees fund no emissions;
  - its continuity does not depend on SN25.
- **Billing:** fiat only, with no wallet flow anywhere on the sidecar's domain.

**Pitch4 change.**
- **Page 6, "Trust documents first":** expand the no-token bullet into these clauses.
- **Page 5, "Who pays" footnote:** add "billed in fiat by BringYour, Inc."
- **Page 3, "Why encryption makes it safe to adopt" ("URnetwork holds only ciphertext"), and page 4, "Open core, hosted blind":** name the operating company that runs paid hosting [synthesis inference].

**Why it helps.**
- Ownership, including beneficial ownership, is a named diligence factor.
- URnetwork's public identity is split between an operating company and a token-governed foundation. A reviewer will ask who signs and where the fees go.

**Evidence.**
- **The split as a reviewer sees it.**
  - ur.io's footer: "This website is provided by BringYour, Inc., a Network Operator for the UR protocol. Visit ur.xyz for the independent protocol." — [ur.io](https://ur.io/) [fetched]
  - ur.xyz carries "© 2026 UR Foundation" and links to an "Investor Centre". — [ur.xyz](https://ur.xyz/) [fetched]
  - The terms name "BringYour, Inc. (hereinafter referred to as 'Provider')" under Texas law. They say bandwidth contributors "may receive credits (minus any service fees) in the form of digital assets". — [terms](https://ur.io/terms) [fetched]
- **Precedents.**
  - The operating companies signed the enterprise deals: Brave Software, Proton AG, Storj and Helium's operator [1.9 inference].
  - Livepeer pays for service in ETH and uses LPT for governance and staking, so "service costs [stay] predictable". — [Livepeer docs](https://docs.livepeer.org/v2/lpt/resources/lpt-eth-usage) [search summary]
  - Akash credits JWT authentication with removing "the number one barrier to enterprise adoption: cryptocurrency complexity". — [Akash](https://akash.network/blog/akash-2025-year-in-review/) [search summary; vendor claim]
- **Intelligence vendors record vetting and payment.** A search summary of Spur's public tag for Mysterium says no strict KYC or abuse process applies there and customers can pay with crypto. — [Spur MYSTERIUM_VPN](https://spur.us/tags/MYSTERIUM_VPN) [search summary; the fetch returned 429]
- **New at level 2.**
  - Two public urlscan scans of ur.io/products on 23 Oct 2026 carry the submitter tags "phishing", "drainer", "crypto-scam" and "@phish_report". — [urlscan search](https://urlscan.io/api/v1/search/?q=domain:ur.io) [fetched]
  - 2.12 infers that a sidecar with fiat-only billing and no wallet flow on its own domain avoids inheriting this.

**Counter-evidence.**
- **No outcome evidence.** 1.9 found no documented procurement win or loss attributed to a vendor's token association. The precedents show structure, not measured outcomes.
- **Helium shows a token is not always disqualifying.** It signed an AT&T commercial agreement while hotspot operators still earn HNT. Reports conflict on whether money flows through Nova Labs. — [The Block](https://www.theblock.co/post/351856/att-subscribers-will-now-automatically-connect-to-nearby-helium-hotspots-through-new-commercial-agreement) [search summary]
- **The urlscan tags are not verdicts.** urlscan's verdicts sit behind a login, and Google Safe Browsing had not acted by 1 Nov.
- **A tension with D1.** Rating vendors map company relationships and subsidiaries, so a BringYour-signed sidecar may share BringYour's rating. Whether a subsidiary would get its own profile is 2.12's "probably", not a finding.

**Cost and risk.**
- Legal time is unsourced, and a subsidiary costs more.
- If the consumer network's token economics change, continuity questions come back [synthesis inference].

**Test.** Ask each design partner's procurement team whether BringYour, Inc. plus these clauses settles ownership, or whether they want a separate entity. Record which wording closed the row.

---

### D5. Present the sidecar as a developer tool, on split domains categorized before design partners arrive
**Effect:** offering. **Confidence:** medium.

**What to change.** Follow 2.12 §7:
- **Three domains, the way ngrok does it:**
  - a marketing and docs site, aiming for "Computers and Internet" or "SaaS and B2B";
  - a control plane;
  - a relay or tunnel domain.
- **Timing:** register them months before design partners arrive, and submit recategorization requests to Talos, PAN, Zscaler, Fortinet, Netskope and Cloudflare at launch.
- **Language:** keep "VPN" out of the copy. Describe "a private IP per agent" as agent addressing inside the team's network.

**Pitch4 change.**
- **Page 3, the "IP addresses" card** ("A permanent private address for each agent and service, plus subnets you choose to route"): word it as agent addressing.
- **Page 6, "What ships, in order" or "Trust documents first":** the domains are registered and categorized before the first design partner.

**Why it helps.** Content categories follow what a domain presents. The sidecar can choose its category now rather than inherit "Personal VPN".

**Evidence.**
- **Talos categories follow what a site presents.** — [Talos JSON](https://talosintelligence.com/cloud_intel/url_reputation?url=ur.xyz) [fetched]
  - **Tunnel vendors:**
    - ngrok-free.app and ngrok.app: "Computers and Internet";
    - ngrok.io: "SaaS and B2B";
    - zrok.io: "Computer Security";
    - ts.net: "Business and Industry";
    - cfargotunnel.com: "Infrastructure and Content Delivery Networks".
  - **Mesh-VPN control planes:** login.tailscale.com, controlplane.tailscale.com and netbird.io are "Personal VPN".
  - **Residential-proxy vendors:** brightdata.com and oxylabs.io are "Computers and Internet".
  - **URnetwork itself:** its protocol site ur.xyz is "Computers and Internet", while ur.io is "Personal VPN".
- **A new domain starts out blocked.** Palo Alto treats newly registered domains (32 days) and unknown ones as high-risk, and its setup guide says to block both [1.9]. — [Palo Alto setup guide](https://docs.paloaltonetworks.com/advanced-url-filtering/administration/configuring-url-filtering/get-started-with-url-filtering/get-started-with-url-filtering-pan-os) [fetched]

**Counter-evidence.**
- **Untested.** The category a new developer-tool domain receives, and how quickly, depends on each vendor's crawler [2.12 gap].
- **Feeds that track behavior ignore content.**
  - UltraDNS's threat tier blocks ur.xyz despite its "Computers and Internet" category. It also blocks ngrok.com, trycloudflare.com, and Tailscale's login and control-plane hosts [observed].
  - CleanBrowsing Family blocks brightdata.com and oxylabs.io [observed].
- **The category's cost is unknown.** It is unverified whether "Personal VPN" is in Cisco's current default policies.

**Cost and risk.**
- Domains are cheap and recategorization forms are free. The cost is lead time.
- Risk: a relay domain still looks like a tunnel to feeds that track behavior.

**Test.**
- Register a live test domain now, with developer-tool content.
- Check it weekly in the Talos JSON, PAN Test-A-Site, Zscaler Site Review, Netskope URL Lookup, FortiGuard and Cloudflare Radar.
- Record each vendor's category and the days it took. 2.12 names this as the only way to close its gap.

---

### D6. Ship an allowlist-and-preflight kit in the first release
**Effect:** offering. **Confidence:** medium.

**What to change.** Two parts [2.12 §7]:
- **Allowlist entries,** ready-made for Zscaler, PAN, Netskope, Fortinet and Umbrella, and for Okta network zones.
- **An install-time self-test.** It detects a block by a gateway or DNS filter, or a recategorization of the relay, and says which category caused it and which recategorization form to use.

**Pitch4 change.**
- **Page 6, "First release, open source":** add the kit.
- **Page 2, "Nothing to change":** add that the sidecar checks the corporate network it lands in.
- **Page 3:** add one line near the reach cards: a published allowlist and a preflight check that works behind the customer's gateway [synthesis inference on placement].

**Why it helps.** Even successful vendors in this space hit these blocks. A kit makes the first install in a filtered network a short admin task, not a failed pilot.

**Evidence.**
- **Successful vendors are blocked too.**
  - UltraDNS's threat tier blocks tailscale.com, login.tailscale.com, controlplane.tailscale.com, ngrok.com and trycloudflare.com [observed].
  - Talos files Tailscale as "Personal VPN" [fetched].
- **Filters aimed at VPNs exist.**
  - OpenDNS FamilyShield answered 14 of 27 VPN and proxy control domains with a block page; CleanBrowsing Family answered 16 with NXDOMAIN [observed].
  - CleanBrowsing says its Family filter "blocks proxy and VPN domains that are used to bypass the filters". — [CleanBrowsing](https://cleanbrowsing.org/filters/) [fetched]
- **Allowlisting is how listed vendors still sell.** Tailscale, ngrok, NetBird and ZeroTier are on HaGeZi's bypass list and sell anyway. 1.9 infers that this works because admins can allowlist their dedicated domains.

**Counter-evidence.**
- **Unmeasured.** Nothing measures how often a design partner's network would block a sidecar domain.
- **Unverified.** The commercial gateways' defaults are unverified, and how many resolvers subscribe to HaGeZi is unmeasured.
- **Possibly redundant.** If D5 works, the kit may rarely fire.

**Cost and risk.** Engineering, plus upkeep of vendor-specific entries. Neither is costed.

**Test.** Run the preflight in every pilot install. Log blocks by vendor and category, and measure the time from a block to an allowlist entry.

---

### D7. Put public names on the customer's own domain by default
**Effect:** offering. **Confidence:** medium.

**What to change.** The TLS edge issues names on the customer's own domain by default. A domain shared across customers comes later, and only once it is on the Public Suffix List (PSL).

**Pitch4 change.**
- **Page 3, the "TLS edge" card** ("A public HTTPS name for a service on a developer's machine"): say "on your domain".
- **Page 4, "Open core, hosted blind":** the paid "names, certificates" are on the customer's domain.
- **Page 6, "Next: the team layer":** apply the same default to the TLS edge entry.

**Why it helps.** Customer-owned names keep one customer's abuse, and URnetwork's list entries, off everyone else's names. That is the job the PSL does for ngrok, Cloudflare and Tailscale's shared domains [2.12 inference].

**Evidence.**
- **The incumbents' shared domains are on the PSL.**
  - Listed: trycloudflare.com; ngrok.app, ngrok-free.app, ngrok.dev, ngrok-free.dev, ngrok.pizza, and ngrok.io with its regional subdomains; ts.net and *.c.ts.net.
  - Not listed: bringyour.com, ur.network and zrok.io.

  Source: [PSL](https://publicsuffix.org/list/public_suffix_list.dat) [fetched].
- **BringYour's PSL request was turned away.** The request for extender.bringyour.com was withdrawn unmerged on 1 Nov 2026. — [PR #3465](https://github.com/publicsuffix/list/pull/3465) [fetched]
  - The PSL reviewer cited "8 extender operators active in the last 7 days … far below the guideline scale" and a private "Extender Root" CA.
  - BringYour's withdrawal noted 14 active operators, and that "bringyour.com isn't registered more than two years out".
  - bringyour.com expires on 2027-11-15. — [RDAP](https://rdap.org/domain/bringyour.com) [fetched]
- **A listed apex takes its subdomains with it.**
  - Wildcard blockers drop every subdomain of a listed apex [2.12].
  - So any public name under ur.network or bringyour.com would fail in filtered networks. 1.9 inferred this, and 2.12's reading of the list format confirms it.

**Counter-evidence.**
- **The PSL does not prevent blocking.** UltraDNS's threat tier blocks trycloudflare.com, which is on the PSL, while it leaves ngrok-free.app, ngrok.io and ts.net alone [observed].
- **Setup cost is unmeasured.** The notes do not measure what customer-owned domains cost small teams to set up.

**Cost and risk.** Low: this is a design default. The unmeasured risk is setup friction for solo and free users.

**Test.**
- In pilots, record how many teams complete custom-domain setup, and how long the first public name takes.
- Before offering any shared domain, check the PSL's rules: scale, a registration term, public certificates, and an abuse contact.

---

### D8. Lead with proofs a reviewer can run, not with badges
**Effect:** differentiation. **Confidence:** medium.

**What to change.** [1.9 §2–3]
- **No provider code, provably:** reproducible builds and a signed SBOM that show the binary contains no provider or bandwidth-sharing code.
- **Published reviews:** the Cure53 protocol audit in full, and a public penetration-test summary.
- **"Hosted blind" with evidence:** a published audit of the key model and a dated canary.
- **No borrowed logos:** design-partner logos appear only with written permission.

**Pitch4 change.**
- **Page 1, "Open source: You don't have to trust us", and page 4, "Open core, hosted blind":** say what proves each claim.
- **Page 6, "Trust documents first":** add the SBOM, the published audit and the penetration-test letter.

**Why it helps.**
- Certificates only put the sidecar level with Bright Data.
- Claims that something has tested are what make "we hold nothing" believable.

**Evidence.**
- **Badges do not separate.** See Bright Data's certificates in D2.
- **Tested claims carry weight.**
  - Swedish police arrived at Mullvad with a warrant and left without customer data, because none existed. — [Mullvad](https://mullvad.net/en/blog/2023/4/20/mullvad-vpn-was-subject-to-a-search-warrant-customer-data-not-compromised/) [search summary of the primary]
  - Bitwarden has held SOC 2 Type 2 and SOC 3 since August 2020, publishes yearly third-party audit reports, and keeps its whole codebase on GitHub. — [Bitwarden](https://bitwarden.com/help/is-bitwarden-audited/) [search summary; vendor claim]
- **The association a reviewer needs answered.**
  - The HaGeZi requests grouped URnetwork with apps that "use bandwidth and IP address as a proxy for other users". — [#9049](https://github.com/hagezi/dns-blocklists/issues/9049)
  - Third parties already package URnetwork as a proxy. A GitHub "URnetwork-Proxy" repository was created on 30 Oct 2026 ([GitHub](https://github.com/by1021/URnetwork-Proxy) [fetched]), and an MCP directory describes proxies by country and listing egress IPs ([mcpservers.org](https://mcpservers.org/ru/servers/mcp-bringyour-com) [search summary]).
  - A binary that can be shown to contain no provider code is an answer a reviewer can check. This joins 1.9's second separating statement to 2.12's findings [synthesis inference].
- **Overclaiming backfires.** In 2022 Lime and Salesforce said they were not Helium customers, and Helium removed both logos. — [CryptoNews](https://cryptonews.net/editorial/news/lime-and-salesforce-do-not-currently-use-helium-technology/), [Techmeme](https://www.techmeme.com/220730/p4) [search summary; secondary]

**Counter-evidence.**
- **Proofs about the binary do not clear the consumer network.** The CSA: "Distinguishing a legitimate proxy network from a botnet depends on consent quality and customer vetting, not on technical architecture." [earlier notes]
- **The precedents are weakly sourced.** Mullvad's infrastructure-audit claims appear only on affiliate sites, and Bitwarden's are vendor claims.
- **None of URnetwork's evidence is public yet.** The penetration test is internal-only, the Cure53 work is a briefing, and the trust pages return 404.

**Cost and risk.**
- Audit and penetration-test costs are unsourced.
- A published audit shows its findings to everyone.

**Test.** Ask design-partner reviewers whether reproducible builds and the SBOM close the proxy-SDK disclosure row. Track which proofs they actually open.

---

### D9. Borrow nothing from consumer marketing, and decide the brand on purpose
**Effect:** both. **Confidence:** low.

**What to change.** [1.9 §3; 2.12 §7]
- **Claims.** No sidecar material uses the consumer superlatives: "No logs", "Tor-like", "Passes Proxy/VPN detection".
- **Brand.** 2.12's verdict: technical separation is required, but brand separation is a judgment call.
  - "URnetwork · Sidecar" is survivable if no runtime name is shared.
  - If the brand stays, clean up the consumer surface a reviewer finds first: the testimonials, and "No logs" next to a threat model that lists retention.
  - The alternative is a separate brand, with BringYour, Inc. named only as the contracting entity.

**Pitch4 change.**
- **Page 1 and every page header:** decide on "URnetwork · Sidecar".
- **Page 6:** "Risks we manage: Reputation".
- **Page 3:** keep VPN language out of the copy, as in D5.

**Why it helps.** Reviewers are told to check websites and marketing claims, and a reviewer's first search lands on ur.io.

**Evidence.**
- **Reviewers are told to check claims.** The interagency guidance suggests reviewing the third party's websites and marketing materials to check that its claims are accurate (paraphrased by the fetch tool). — [88 FR](https://www.govinfo.gov/content/pkg/FR-2023-06-09/html/2023-12340.htm) [fetched]
- **What a reviewer finds on ur.io:**
  - "Excellent, Very undetectable, Passes Proxy/VPN detection";
  - "I am in iran and working this app perfectly";
  - "No logs stored";
  - "Tor-like anonymization. No logs. 100% open source and reproducible".

  Source: [ur.io](https://ur.io/) [fetched].
- **And elsewhere.**
  - URnetwork's llms.txt says "residential egress in 90+ countries through a decentralized provider network". — [llms.txt](https://ur.io/llms.txt) [fetched]
  - The agent skill advertises "many distinct egress IPs (distributed scraping)" [earlier notes].
  - One public urlscan scan of ur.io/products carries a user-submitted "drainer" tag (D4).
- **The scoping precedent.** Brave's SOC 2 post does not mention BAT, Rewards or crypto. — [Brave](https://brave.com/blog/soc2/) [fetched]

**Counter-evidence.**
- **No control keys on the brand word.** None of the controls checked keys on "URnetwork", and ur.xyz, a URnetwork site, is "Computers and Internet" [2.12].
- **Cleanup does not touch the lists.** Cleaning up ur.io would not undo the HaGeZi entries, which came from the provider side [2.12 inference].
- **No precedent or measure.**
  - There is no documented case of how reviewers treated a vendor whose parent or affiliate runs a residential network after IPIDEA.
  - Nothing measures how much the brand alone escalates a review [1.9 gap].

**Cost and risk.**
- Changing the consumer site is a decision for the consumer network.
- What a separate brand gives up is unmeasured.

**Test.**
- Search for the sidecar's name the way a reviewer would, and record the first page of results.
- Show design-partner reviewers a URnetwork-branded trust page and a separately branded one, and record their objections to each.

---

### D10. Offer a self-host-first Assured route before SOC 2 Type II
**Effect:** offering. **Confidence:** low. Not pursued at level 2 in this branch.

**What to change.** Regulated design partners self-host. BringYour supplies only the software and holds no data. The route is backed by signed releases, an SBOM and the published audit [1.9 §4].

**Pitch4 change.**
- **Page 5, Assured ("on your servers too"):** lead with self-hosting for regulated pilots.
- **Page 6:** bring "a supported self-hosted install", now in the team-layer stage, forward for those partners [synthesis inference].

**Why it helps.** Diligence scales with risk and with the data held. A supplier holding no data might face a lighter review, so regulated partners could start sooner.

**Evidence.** The interagency guidance says due diligence "should be commensurate with the level of risk and complexity". When information is missing, it lets the bank consider added controls or monitoring. — [88 FR](https://www.govinfo.gov/content/pkg/FR-2023-06-09/html/2023-12340.htm) [fetched]

**Counter-evidence.**
- **No source.** 1.9 found no primary source on how buyers tier self-hosted open source.
- **The software stays top-tier.** Its access to code, network paths and model servers makes it top-tier by design, so supply-chain review still applies [1.9 inference].
- **Untested here.** This branch did not test the idea at level 2.

**Cost and risk.**
- Support cost is unsourced.
- Hosting revenue is deferred.

**Test.** Offer the route to two or three regulated design partners. Record the tier their risk program assigns and the evidence it demands.

## 3. How level 2 changed or qualified level 1

| Level 1 (1.9) | Level 2 (2.12) | Net effect |
|---|---|---|
| All four domains are on HaGeZi's bypass list. Secure web gateways "probably" put them in proxy-avoidance categories (unverified). | **Talos:** "Personal VPN", not "Filter Avoidance". No threat category; reputation Neutral or Favorable. **Safe Browsing:** no unsafe content. **Resolvers:** every one tested except UltraDNS ignores URnetwork. **But:** UltraDNS blocks the bringyour.com hosts and ur.xyz, and HaGeZi Ultimate adds the api and connect hosts. | **Qualified.** URnetwork is blockable by policy, like Tailscale's control plane, not flagged as malicious. Talos is milder than feared. Zscaler, PAN, Netskope, Fortinet and Cloudflare remain unknown. |
| The sidecar "should" have its own domain and IP space. | Every runtime host carries the consumer classification. The pool is HE's non-portable space, shared with 37 consumer hostnames. Four pool addresses are on Barracuda's list, and one extender is in FireHOL's proxy aggregate. | **Upgraded** to "required by current classifications" (D1). **New:** separate IP reputation needs new provider ranges, or eventually an ASN, and the extenders are off-limits. |
| A new sidecar domain would be "newly registered" for 32 days and "unknown" until categorized. | URnetwork's own domains are old (registered 2009–2025), and none is newly registered. | **Qualified.** Separation trades an inherited category for a new-domain window, so register early (D5). |
| Cleaning up the consumer surface is on the critical path; the alternative is a separate brand. | The list entries came from provider-side bandwidth-sharing requests, so homepage edits will not undo them. No control keys on the brand word, and ur.xyz shows a URnetwork site can be "Computers and Internet". | **Split.** Technical separation is required; brand separation is a judgment call. Cleanup helps human reviewers, not lists (D9). |
| Being on a bypass list does not stop enterprise sales (Tailscale and ngrok are listed too), because admins allowlist. | UltraDNS also blocks Tailscale's control plane, ngrok.com and trycloudflare.com, and Talos files Tailscale as "Personal VPN". | **Confirmed**, and it adds a direction: the allowlist-and-preflight kit (D6). |
| Names under ur.network would be unusable if HaGeZi's wildcard format covers subdomains (unverified). | **List format:** the bypass list is in HaGeZi's wildcard folder ("Domains (without subdomains)"), so wildcard blockers drop all subdomains. **PSL:** it is how ngrok, Cloudflare and Tailscale isolate customer names, and BringYour's request was withdrawn over scale, registration term and its private CA. | **Confirmed and extended:** public names go on customer domains by default (D7). |
| Membership of Okta's HIGH_RISK_PROXIES is unknown. | Okta's ~230 named services include no URnetwork name, but they do include MYSTERIUM_VPN. The curated list is unpublished, and Spur works from observed activity. | **Still unverifiable.** Exposure probably comes through generic flags, so "exits you run" must stay a hard rule (D1). |
| Security ratings are unknown (an account is needed). | **Grades:** still unknown. **Weak inputs:** DMARC `p=none` on ur.io and ur.network; no SPF on mail-receiving ur.network; no mail records at all on ur.xyz; DNSSEC only on ur.io; a private CA on the extenders; the Barracuda hits. **Positives:** only ports 80 and 443, no CVEs, HSTS preload. | **Partly answered.** Cheap fixes exist (D1). It surfaces a tension between BringYour as counterparty and how ratings attribute assets (D4). |
| ur.io is where a reviewer looks first. | bringyour.com is the most-seen name (Tranco 24,607, against about 4.4 million for ur.io). It carries the API, relay, MCP and extender traffic. | **New.** The contracting entity's own domain is the most exposed name (D1). |
| Marketing claims trigger escalation (the testimonials, "No logs"). | urlscan submitter tags "phishing", "drainer" and "crypto-scam" on ur.io/products. Verdicts are hidden, and Safe Browsing had not acted. | **New brand risk.** It supports fiat-only billing with no wallet flow on the sidecar's domain (D4). |

**Where the branch did not go deeper.**
- Level 2 here took up only two of 1.9's open questions: the first (classification) and part of the sixth (security ratings).
- Four were not pursued in this branch:
  - whether a token-associated parent triggers escalation, and which separation resolves it;
  - sanctions exposure;
  - which minimum artifacts unblock the beachhead;
  - how self-hosted and ciphertext-only vendors are tiered.
- The last two overlap L2-2.05, which is in another branch. No level-3 or level-4 work sits under 2.12.

**Method limits that still bound these findings.**
- 2.12 is a single-day snapshot.
- It had no browser route, so it could not use the commercial lookup forms.
- It did not enumerate certificate-transparency logs, so the host inventory may be incomplete.
- 1.9 obtained no real quotes.

## 4. What remains open

**Classification and lists**
1. **Commercial gateways.** How do Zscaler, PAN-DB, Netskope, FortiGuard and Cloudflare Gateway categorize URnetwork's domains? Do their default or recommended policies block "Personal VPN", "Anonymizer" or "Proxy Avoidance"? This decides whether separation alone is enough, or whether allowlisting is always needed.
   - Routes: Zscaler Site Review, PAN Test-A-Site, Netskope URL Lookup, FortiGuard in a browser, Cloudflare Radar or a Gateway test policy.
2. **A new domain's category.** What category does a brand-new developer-tool domain receive at each vendor, and how fast? This needs a live test domain (D5).
3. **Cisco and UltraDNS policy.** Is Talos's "Personal VPN" in Cisco's current default policy sets? The legacy Umbrella preset claim is unverified. UltraDNS's taxonomy and data source are undocumented, and its stated malware and phishing scope conflicts with its observed blocking of VPN and tunnel brands.
4. **HaGeZi's reach.** How many resolvers and DNS services subscribe to HaGeZi's Ultimate and bypass lists (for example, NextDNS and AdGuard DNS users)? What does NextDNS's own "Block bypass methods" data contain? When was ur.xyz added, and why did bringyour.com and ur.io leave Ultimate?

**IP intelligence and ratings**

5. **Exit and extender tags.** Are URnetwork's exits and extenders tagged, and under what name, by Spur, MaxMind, IPinfo, IP2Proxy, IPQS or Okta's HIGH_RISK_PROXIES? Does Entra have an equivalent category?
   - Routes: exit-IP samples plus vendor accounts, or a test Okta org with an enhanced dynamic zone and its System Log `security.request.blocked` events.
6. **BringYour's ratings.** What are BringYour's Bitsight and SecurityScorecard grades, findings and peer percentiles? Do those vendors attribute the extenders and the HE pool to BringYour, and would a subsidiary get its own profile?
   - Route: claimed company profiles.
7. **Barracuda and AbuseIPDB.** Why does Barracuda list 65.19.157.40–.62? Its lookup form gives the reason and a removal route. How many AbuseIPDB reports do the pool and the extenders have?
8. **The "drainer" tags.** Who submitted the urlscan "phishing / drainer / crypto-scam" tags via phish.report? What are urlscan's verdicts, and did Netcraft, PhishTank or SmartScreen act?

**Review, contracts and attestation**

9. **Token association.** Do security reviewers and procurement treat a token-associated parent or foundation as an escalation trigger? If so, which separation resolves it: a separate entity, a separate brand and domain, a contract clause, or a spin-out? No documented win or loss was found.
10. **Sanctions.** What is the exposure from paying contributors in digital assets, and from serving and featuring users in Iran? Does GL D-2 cover the consumer VPN but not payouts? What sanctions statement can the sidecar publish?
11. **Minimum artifacts.** Which artifacts actually unblock deals for 5–150-engineer teams (Type 1, a penetration-test letter and a CAIQ; or Type II), compared with regulated buyers?
12. **Tiering.** How do third-party-risk programs tier self-hosted open source against hosting that holds only ciphertext? (Co-opened as L2-2.05, in another branch.)
13. **SOC 2 carve-out.** Can a SOC 2 scoped to the sidecar exclude the consumer network when shared staff and some shared infrastructure run both? This needs an auditor's view.
14. **Quotes and fees.** Real quotes for SOC 2, the penetration test, the protocol audit, legal work and an LEI. Did a 2026 change to the DPF fee take effect?
15. **Precedents.** How did reviewers treat a vendor whose parent or affiliate runs a residential network, after IPIDEA? No case was found. Unverified precedent details:
    - how Livepeer Studio bills enterprises;
    - whether Akash or Seal hold a Type II;
    - whether Storj's company-level SOC 2 was completed;
    - Mullvad's infrastructure audit;
    - whether token flows sit inside Helium's AT&T deal.
16. **Carrier receipts.** Do carrier receipts and a published allowlist (D3) actually close the subcontractor row for reviewers? This is untested.
