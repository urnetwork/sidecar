# URnetwork (BringYour, Inc.): existing assets, public footprint, and reputation, and its right to win with an AI-agent sidecar (as of 31 October 2026)

Labels used throughout:
- **[Company claim]**: stated by BringYour, URnetwork, or the UR Foundation and not independently verified.
- **[Observed]**: measured directly on 31 Oct 2026 (HTTP status, API output, page text).
- **[Third party]**: an independent source.
- **[Internal]**: a local company file that I could not find at any public URL on 31 Oct 2026.

Every web check is dated 31 Oct 2026 unless a date is given. The sidecar itself is design-only. Nothing about it has shipped.

## 1. Public facts: product lines, installs, network size, open source, funding and team, launch and rebrand history, press, and IETF 124

### Takeaway
BringYour, Inc. runs a live, multi-platform decentralized VPN. It is based in San Francisco and was founded in 2023 according to directory listings. The product was rebranded from BringYour to URnetwork in an update dated 31 Oct 2024.
- **Consumer footprint:** modest. Google Play shows "50K+" downloads, and the App Store shows 303 ratings.
- **Network size:** the company publishes figures of roughly 84,000–87,000 daily providers in about 100 countries.
- **Company size:** small. Directories list 1–10 staff and a seed round of roughly $1.5–2M.
- **Press:** almost no mainstream coverage. What exists is DePIN and crypto media.
- **Crypto layer:** since 2025 the network has been wrapped in one. It is now Bittensor subnet SN25 "UR", presented by a "UR Foundation" at ur.xyz that publishes tokenholder letters.
- **IETF 124 talk:** documented only by the company's own deck. I found no trace of it in IETF records.

### Cited Findings

#### Corporate identity, team, funding
- **Entity and address [Observed]:** BringYour, Inc. The site footer reads "© 2026 BringYour, Inc." and "2261 Market Street #5245, San Francisco, CA 94114". It also shows site version "2026.10.1-1060587890". — [ur.io footer (seen on ur.io/docs pages)](https://ur.io/docs)
- **Incorporation and governing law:**
  - The company's threat model says BringYour, Inc. is a "Delaware C corporation" and that the published terms state neither the incorporating state nor a registered agent.
  - Governing law is Texas, with venue in Harris County.
  - The terms say the operator "may monitor and disclose information where required to do so by law or government order".
  - Source: [local THREAT-MODEL.md §10, dated 2026-09-17](file:///Users/brien/urnetwork/cure53/THREAT-MODEL.md). A newer version is public at [ur.io/docs/threat-model](https://ur.io/docs/threat-model); I spot-checked it but did not compare §10 line by line.
- **Founders [Third party, DePIN directory]:** DePIN Hub names Brien Colwell and Stuart Kuentzel as founders. It says BringYour is a "US C-Corp" and that the network "is moving to a Swiss foundation run by an independent board". — [DePIN Hub project page](https://depinhub.io/projects/urnetwork/)
- **Contributors listed on ur.xyz [Company claim]:** Brien Colwell (engineering), Ryan Mello (development), "Lemz" (growth; background "across web3") and Jack Ai-Leung (advisor). My extraction of the list was truncated. — [ur.xyz/about](https://ur.xyz/about)
- **Headcount and founding date:** a search summary of the AppSumo listing says the company was founded in January 2023, is headquartered in California, and has 1–10 employees. I did not fetch the page itself. — [AppSumo listing](https://appsumo.com/products/urnetwork/)
- **Funding (aggregators only; no primary announcement found):**
  - VCBacked lists a $1.5M seed round. — [VCBacked](https://www.vcbacked.co/company/bringyour)
  - CB Insights names The General Partnership as an investor. — [CB Insights](https://www.cbinsights.com/company/bringyour/financials)
  - DePIN Hub says "Seed funding $2m 2024 by 2 partners". — [DePIN Hub](https://depinhub.io/projects/urnetwork/)
  - The $1.5M and $2M figures conflict.
- **Founder background as perceived:**
  - A privacy-community post is titled "Seeking Privacy Analysis of URnetwork (ur.io) – Ex-Palantir Team, Open-Source, What Data Is Collected?". — [Lemmy, Privacy@lemmy.ml, cross-posted from r/privacy](https://lemmy.toldi.eu/post/1819621/5276720)
  - A MalwareTips thread reportedly names Brien Colwell as an early Palantir engineer. The page returned HTTP 403 to me, so this rests on search summaries only. — [MalwareTips](https://malwaretips.com/threads/ur-network.139711/)

#### Launch and rebrand history
- **Repository dates [Observed]:**
  - `android` was created 2022-07-02, `connect` 2022-12-13, and `server` 2023-01-26.
  - The `urnetwork` GitHub organization itself was created 2024-08-29.
  - The legacy `bringyour` organization still hosts 4 small repositories from 2023–2024.
  - Sources: [GitHub API, urnetwork repos](https://api.github.com/orgs/urnetwork/repos); [GitHub API, bringyour repos](https://api.github.com/orgs/bringyour/repos)
- **Launch phases [Internal, Company claim]:** the economic-model document describes a "public beta launch in H1 2024" and a "'v0' launch in H2 2024". — [local docs/economic-model/economic-model.md](file:///Users/brien/urnetwork/docs/economic-model/economic-model.md)
- **Rebrand (changelog "Update 1", dated 2024-10-31) [Company claim]:**
  - Key quotes: "We rebranded to URnetwork (https://ur.io) with a new look and app. URnetwork is now free, with a supporter subscription."
  - The same update introduced the subsidy payout, Android TV support, docs.ur.io, feedback.ur.io, support@ur.io and Discord.
  - Sources: [local changelog](file:///Users/brien/urnetwork/docs/changelog/2024-10-31-update-1/update-1.md); a public changelog now lives at ur.io/changelog per [ur.io/llms.txt](https://ur.io/llms.txt)
- **Early-2025 launch signals:**
  - The App Store app (id 6741000606) has its earliest visible reviews in February 2025. — [App Store](https://apps.apple.com/us/app/urnetwork/id6741000606)
  - A Show HN post, "URnetwork – Decentralized VPN Replacement", went up on 2025-02-24. — [HN item 43165027](https://news.ycombinator.com/item?id=43165027)
  - The IETF 124 deck says "Launched URnetwork in 2025". — [local IETF 124 deck](file:///Users/brien/urnetwork/docs/presentations/Default%20Safe_%20Realizing%20the%20Potential%20of%20Decentralized%20Networks%20%28IETF%20124%29.pdf)
- **2025 crypto phase [Internal transcripts, Company statements]:**
  - In June 2025 the company held AMAs on crypto-promotion channels and X Spaces: Block Chain Calls, BUFFULOGEMS, Coinsniper, "Crypto Clash Binance Live", Crystal Calls, Defi Eagle, Joshuwa, TEAONA and Zion.
  - Statements made there:
    - "we're launching our points campaign this week ... backdating the points all the way to the beginning of May"
    - "not only are you going to be air dropped USDC"
    - "Our token is launching later this year"
    - a "special partnership with Solana mobile where you earn extra points"
    - the apps are also in "the Solana D app store"
  - The transcripts were committed 2025-06-14. — [local docs/ama/](file:///Users/brien/urnetwork/docs/ama/)
- **2026 subnet and foundation [Company claim; Observed]:**
  - ur.xyz is titled "UR | The decentralized privacy network on Bittensor SN25". It says "UR subnet is a privacy network built on Bittensor" and "Operators run servers and deposit alpha for the traffic they serve. Miners carry encrypted traffic and earn emissions. Validators re-measure the network". The footer reads "© 2026 UR Foundation". — [ur.xyz](https://ur.xyz/)
  - Taostats lists "SN25 · UR". — [taostats SN25](https://taostats.io/subnets/25)
  - ur.io says: "This website is provided by BringYour, Inc., a Network Operator for the UR protocol. Visit ur.xyz for the independent protocol." — [ur.io](https://ur.io/)
  - DePIN Hub says "the protocol/token will be controlled by the foundation". — [DePIN Hub](https://depinhub.io/projects/urnetwork/)
- **Investor Centre (updated 28 Oct 2026) [Company claim]:**
  - "UR team locks 550,000 alpha in perpetuity" (9 Sep 2026)
  - "September Letter to Tokenholders" (25 Sep 2026)
  - "UR's Operator Ecosystem" (15 Oct 2026)
  - "UR x Apex routing competition", run on Macrocosmos's SN1 (28 Oct 2026)
  - Source: [ur.xyz/investors](https://ur.xyz/investors)

#### Product lines (public, 31 Oct 2026)
- **Consumer VPN apps:**
  - Android on Google Play and F-Droid. — [Play](https://play.google.com/store/apps/details?id=com.bringyour.network); [F-Droid](https://f-droid.org/en/packages/com.bringyour.network/)
  - iOS and macOS. — [App Store](https://apps.apple.com/us/app/urnetwork/id6741000606)
  - Windows and Linux; both repositories were created 2026-07-11. — [GitHub API](https://api.github.com/orgs/urnetwork/repos)
  - A browser extension; its repository was created 2026-02-01. — [Chrome Web Store](https://chromewebstore.google.com/detail/kpnklgbgjkihebbieiggfeokkddjbkfb)
  - The threat model refers to "all five native apps". — [ur.io/docs/threat-model](https://ur.io/docs/threat-model)
- **Plans [Company claim]:**
  - Free: 30 GiB per day and 2 concurrent clients.
  - UR Pro: 10 TiB per month, $5/month or $40/year, and 1,000 concurrent clients. — [ur.io/llms.txt](https://ur.io/llms.txt)
  - On iOS, "URnetwork Supporter" costs $4.99, or $39.99 per year. — [App Store](https://apps.apple.com/us/app/urnetwork/id6741000606)
- **Provider mode and Provider SDK:**
  - The documentation describes: "Integrate Provider — Run a URnetwork provider inside your app. Each installation provides as a client of your network and earns to one Bittensor wallet that you set once." — [ur.io/llms-full.txt](https://ur.io/llms-full.txt)
  - Example code is published. — [github.com/urnetwork/examples](https://github.com/urnetwork/examples)
- **Developer SDK:** documented in twelve languages. Only Go (`github.com/urnetwork/sdk/v2026`) and JavaScript/TypeScript (`@urnetwork/sdk`) are installable today; "the other languages' packages are not published yet". — [ur.io/llms.txt](https://ur.io/llms.txt)
- **Further documentation pages:** the docs index lists "Sign in with URnetwork", Embed, Socket, Extenders, an Operator API, and comparison pages against 21 named services. Those services include Tor, Mullvad, Proton VPN, Tailscale, Mysterium, Sentinel, Orchid, NymVPN, Obscura, Cloudflare WARP and Apple Private Relay. — [ur.io/docs](https://ur.io/docs)
- **Agent surface:** an MCP server, agents.md, a skill and x402 payments. See section 2.
- **Hardware:** "URnode: the hardware node, sold at shop.ur.io". — [ur.io/llms.txt](https://ur.io/llms.txt)
- **URmessage:** an MLS-based messenger in public development. See section 5. — [github.com/urnetwork/message](https://github.com/urnetwork/message)
- **Outage log:** "every outage, when it started and ended, what went wrong and what we changed". — [ur.io/llms.txt](https://ur.io/llms.txt)

#### Installs and ratings [Observed]
- **Google Play:**
  - "50K+" downloads (Play's bucket label), rated 4.6 stars from 2.24K reviews.
  - Updated Oct 16, 2026; author "BringYour, Inc."
  - Source: [Google Play](https://play.google.com/store/apps/details?id=com.bringyour.network)
- **App Store:**
  - Rated 4.6 out of 5 from 303 ratings; listed under Utilities with an age rating of 4+.
  - Latest version 2026.8.17 (Aug 18), with the note "Major checkpoint update, new login methods, account settings, backend changes."
  - App Privacy section: the developer states the app does not collect any data.
  - Source: [App Store](https://apps.apple.com/us/app/urnetwork/id6741000606)
- **F-Droid:**
  - Version 2026.8.22, added Aug 26, 2026; license MPL-2.0.
  - Anti-feature: "This app depends entirely on a certain instance of a network service ... Rely on bringyour.com to get providers."
  - Listing text: "URnetwork links an external Solana wallet. We do not have custody of your wallet".
  - Source: [F-Droid](https://f-droid.org/en/packages/com.bringyour.network/)
- **Browser extension:**
  - A search summary says the Chrome extension was last updated in March 2026. I did not fetch the page. — [Chrome Web Store](https://chromewebstore.google.com/detail/kpnklgbgjkihebbieiggfeokkddjbkfb)
  - extscope.org labels it "High-risk permissions". I saw this only in a search-result title. — [extscope](https://extscope.org/extension/kpnklgbgjkihebbieiggfeokkddjbkfb)

#### Network-size claims (all company-published)
- **IETF 124 deck (November 2025):** "Running with zero known issues for users and participants. Learned key principles with 180k users around the world - 100 countries, 3000 cities." — [local IETF deck](file:///Users/brien/urnetwork/docs/presentations/Default%20Safe_%20Realizing%20the%20Potential%20of%20Decentralized%20Networks%20%28IETF%20124%29.pdf)
- **Homepage counters on 31 Oct 2026:** "83,555 providers 98 countries 1,195,691 networks". — [ur.io](https://ur.io/)
- **llms.txt:** "residential egress in 90+ countries", plus per-country pages for 93 countries. — [ur.io/llms.txt](https://ur.io/llms.txt)
- **Public stats feed** (generated 2026-10-31 18:15 UTC; all values in it are zero before 8–10 Aug 2026). — [api.bringyour.com/stats/last-90](https://api.bringyour.com/stats/last-90)

  | Measure | Latest summary | Trend |
  |---|---|---|
  | Providers | 86,633 | daily average 105,018 (Aug 10–31) → 92,812 (Sep) → 84,463 (Oct); daily range 35,652–128,293 |
  | Countries | 105 | daily average ≈112 (Aug) → ≈100 (Oct) |
  | Regions | 573 | |
  | Cities | 1,566 | daily average 2,035 (Aug) → 1,366 (Oct) |
  | Networks | 1,199,645 | rose from 880,194 on 2 Aug |
  | Devices | 3,387,794 (peak) | rose from 175,119 on 10 Aug to 2,799,258 on 31 Oct |
  | Daily `all_transfer_data` | units not labelled | averages ≈2.41×10¹² (Aug), 1.74×10¹² (Sep), 2.72×10¹² (Oct); peak 7.26×10¹² (≈2.4 TB/day if the unit is bytes) |

- **June 2025 AMAs [Company statement]:** a target of "at least 30 providers in every single country", and an aspiration of "5 million nodes". — [local AMA transcripts](file:///Users/brien/urnetwork/docs/ama/)

#### Open source [Observed]
- **github.com/urnetwork:**
  - 30 public repositories with 410 stars in total; the organization has 331 followers.
  - Most-starred: `android` 224, `build` ("Reproducible builds") 57, `connect` ("Open core client, protocol, and api written in Go") 51, `server` 22, `windows` 12, `proxy` 10, `apple` 9, `warp` 9.
  - `skill` has 0 stars; `message`, `message-server` and `message-windows` have 0 each.
  - GitHub reports the license as "NOASSERTION" for most repositories.
  - Most repositories were pushed on 31 Oct 2026, which signals active development.
  - Source: [GitHub API](https://api.github.com/orgs/urnetwork/repos)
- **Positioning conflict:** the homepage says "100% open source and reproducible so you can verify it yourself" [ur.io](https://ur.io/), while the `connect` repository describes itself as "Open core" [GitHub API](https://api.github.com/orgs/urnetwork/repos).

#### Press and coverage
- **What exists is crypto, DePIN and directory coverage:**
  - DePIN Hub's "The State of Decentralized VPNs (and Why URnetwork is One to Watch)". — [DePIN Hub blog](https://depinhub.io/blog/the-state-of-decentralized-vpns-and-why-urnetwork-is-one-to-watch/)
  - DePIN Hub podcast #081, dated 21 Aug 2025 by the project page. — [DePIN Hub podcast](https://depinhub.io/blog/podcast-081-urnetwork-a-safer-faster-vpn-alternative/)
  - Solana podcast, "How Solana enables a fully encrypted internet with Brien Colwell (URnetwork)". — [Solana podcast](https://solana.com/ar/podcasts/solana-is-global-with-alex-scott/episodes/how-solana-enables-a-fully-encrypted-internet-with-brien-colwell-urnetwork-e3i7p63)
  - Airdrop-tracker listing. — [airdrops.io](https://airdrops.io/urnetwork/)
  - App directory. — [AlternativeTo](https://alternativeto.net/software/urnetwork)
  - MCP directory listing. — [mcpservers.org](https://mcpservers.org/pt-BR/servers/mcp-bringyour-com)
- **Mainstream press:** none found. The searches turned up no mainstream tech or security press about URnetwork or BringYour (see Gaps).

#### IETF 124 presentation
- **The deck [Internal; Company material]:**
  - Title: "Default Safe: Realizing the Potential of Decentralized Networks", by Brien Colwell, URnetwork.
  - It frames safety as two problems: "Risks to Users" and "Risks to Participants".
  - Its principles are "Only encrypted data in", "Auditable local security for participants with access controls" and "Limit virtual infrastructure".
  - It lists participant legal duties: "Computer Fraud and Abuse, DMCA, and Iran export".
  - It names "robust BitTorrent protocol detection" as an open problem and cites `github.com/urnetwork/arindb` and `ip_security.go`.
  - The deck was committed to the company docs repository on 2025-11-05.
  - Source: [local deck](file:///Users/brien/urnetwork/docs/presentations/Default%20Safe_%20Realizing%20the%20Potential%20of%20Decentralized%20Networks%20%28IETF%20124%29.pdf)
- **No IETF record found [Observed]:**
  - IETF 124's DINRG met on 4 Nov 2025. — [DINRG chairs' slides](https://datatracker.ietf.org/meeting/124/materials/slides-124-dinrg-ietf124-dinrg-chairs-presentation-00)
  - A datatracker API query for IETF 124 slide documents named "default-safe", "decentralized-networks" or "urnetwork" returned 0 results.
  - "Colwell" and "URnetwork" do not appear on the DINRG, PEARG or IRTF Open bluesheets. — [DINRG bluesheet](https://www.ietf.org/proceedings/124/bluesheets/bluesheets-124-dinrg-202511041930-00.txt)

#### Public status of the local company files (checked 31 Oct 2026) [Observed]
- **The docs repositories are not public:**
  - The local docs repository's origin is `github.com/bringyour/docs`, and its README invites PRs to `github.com/urnetwork/docs`. Both URLs return 404 (private or removed). — [github.com/urnetwork/docs](https://github.com/urnetwork/docs)
  - That repository holds the AMA transcripts, the IETF deck and the 2025 assessment PDFs.
- **docs.ur.io deep links are broken:** every docs.ur.io path now 301-redirects to the ur.io/docs index. For example, `docs.ur.io/threat-model` redirects to `https://ur.io/docs`. — [ur.io/docs](https://ur.io/docs)
- **Public today:**
  - `cure53/THREAT-MODEL.md` is public at [ur.io/docs/threat-model](https://ur.io/docs/threat-model), as a newer revision than the local copy.
  - `skill/SKILL.md` is public and byte-identical (10,663 bytes) at [github.com/urnetwork/skill](https://github.com/urnetwork/skill/blob/main/SKILL.md).
  - `docs/llms.txt` has been superseded by a rewritten, agent-oriented [ur.io/llms.txt](https://ur.io/llms.txt).
  - `docs/README.md` has no public counterpart; it lives in the non-public repository.
- **Not found at any public URL I tried (HTTP 404):**
  - the trust-and-safety policy
  - the warrant canary
  - the transparency report
  - the economic model
  - protocol research
  - URLs probed: `ur.io/docs/<slug>`, `ur.io/<slug>`, and `ur.io/docs-md/<slug>.md`
  - The public `llms-full.txt` (145 KB) contains no "canary", "transparency report", "notice@" or "law enforcement". — [ur.io/llms-full.txt](https://ur.io/llms-full.txt)
- **Internal only:**
  - `cli/UI.md`, the sidecar design sketch
  - `cure53/AUDIT.md`, an audit briefing "Prepared for: Cure53", dated 2026-09-17
  - The AMA transcripts, the IETF deck and the assessment PDFs are also internal now, because they sit only in the non-public docs repository.

### Inferences
- **The scale numbers do not reconcile into one "users" figure.**
  - The figures are 180k users (November 2025), 1.2M "networks" and 3.4M "devices" (October 2026), and "50K+" Play installs.
  - "Networks" probably means accounts, including guest accounts and accounts created through the SDK.
  - Devices rose about 16-fold in 80 days. That fits the launch of the provider/embed SDK and subnet, but it is unexplained.
  - A diligent buyer will ask for definitions and will discount headline numbers until they get them.
- **The network is volatile.** Published providers fell about 20% from August to October 2026, and cities fell about 33%. Publishing the declines is a credibility point, but they still show volatility, possibly tied to changes in subnet incentives.
- **The counterparty question has become complex.** The company's public identity is now split between BringYour, Inc. (a "Network Operator") and a token-governed "UR Foundation" with tokenholder letters and an Investor Centre. For an enterprise buyer that raises questions about who signs the contract, who governs the protocol, and whether token economics affect service continuity.
- **The IETF appearance is unproven.** It would be a credibility asset with standards-literate buyers, but today it can only be shown from the company's own deck, and that deck now sits in a non-public repository.

### Gaps
- **Funding:** no primary source was found (no press release, no SEC Form D), and the aggregator figures conflict ($1.5M vs $2M).
- **Team:**
  - Headcount and team composition are unverified.
  - Stuart Kuentzel's current role is unknown.
  - The Palantir claim about the founder has no primary source.
- **Installs:** Play shows only the "50K+" bucket. iOS download counts are not public. I found no numbers for the Solana dApp Store, F-Droid or IzzyOnDroid.
- **Stats feed:** units and definitions for networks, devices and transfer are undocumented.
- **IETF 124 venue:** unconfirmed. It may have been a side meeting or an informal talk, and it is not in datatracker materials.
- **Trust pages:** I could not tell whether the trust-and-safety, canary and transparency pages exist somewhere I did not probe, or were removed in the docs migration.

## 2. The existing agent surface: how it is described publicly, and adoption signals

### Takeaway
The agent surface is live and unusually broad for a company this size:
- an OAuth-protected MCP server at mcp.bringyour.com with two tools
- an agents.md with add-server recipes for 21 harnesses
- a published skill
- long-lived API keys
- x402 pricing

But it is positioned as a geo-egress and residential-IP tool for agents: fetch from a location, or get "many distinct egress IPs (distributed scraping)". It is not positioned as a collaboration substrate, and I found no public adoption signal; the skill repository has 0 stars and no usage figures are published.

The x402 status is inconsistent. The documentation says x402 is "not switched on", but on 31 Oct 2026 `/x402/skus` answered HTTP 200 with a price list.

### Cited Findings
- **The MCP server is live [Observed]:**
  - `GET https://mcp.bringyour.com` returns HTTP 401 with `www-authenticate: Bearer resource_metadata="https://mcp.bringyour.com/.well-known/oauth-protected-resource", scope="mcp:read"`. — [mcp.bringyour.com](https://mcp.bringyour.com)
  - The OAuth protected-resource metadata names the authorization server `https://auth.bringyour.com`, one read scope and one fetch scope, and bearer tokens in a header. — [OAuth metadata](https://mcp.bringyour.com/.well-known/oauth-protected-resource)
- **How agents.md describes it [Company claim]:**
  - Protocol: "MCPv2 — the stateless 2026-07-28 revision", over streamable HTTP with JSON responses; "Older revisions negotiate down automatically".
  - Sign-in: OAuth through a browser on first connect. A network account is required, and a free account is suggested.
  - Tools:
    - `providerLocations`: countries, regions and cities, with provider counts, stability and "strong-privacy" flags.
    - `fetch`: "load a URL as if browsing from a chosen place", using `signed_proxy_id`, `cookies` and `continuation`, under scope `mcp:fetch`. It returns `payment_required` at a plan limit.
  - Quote: "The happy path is the MCP server; everything else on this page is fallback or detail."
  - The page has no date stamp and gives no usage numbers. It points readers to the stats feed "for verifying claims instead of quoting them".
  - Source: [ur.io/agents.md](https://ur.io/agents.md)
- **Harnesses with add-server recipes (21) [Company claim]:**
  - The list: Claude Code, Cursor, VS Code, Codex, Cline, Claude.ai, ChatGPT, OpenClaw, Hermes, OpenCode, Antigravity, Devin ("successor to Windsurf"), Perplexity, Zed, Factory Droid, JetBrains, Trae, Qwen Code, Gemini CLI, Grok and Kimi Code.
  - Exceptions: JetBrains has "no OAuth yet" and uses a static header or the `mcp-remote` bridge; Trae supports header auth only.
  - Source: [ur.io/agents.md](https://ur.io/agents.md)
- **Positioning for agents [Company claim]:**
  - Tagline: "Open-source network privacy for humans and AI agents: residential egress in 90+ countries through a decentralized provider network, with the same identity and privacy guarantees for people and agents alike."
  - Agent-facing utilities: long-lived `urn_` API keys created with `POST /account/api-key`, a JSON "Check my IP" endpoint, and an OpenAPI 3.1 spec.
  - Source: [ur.io/llms.txt](https://ur.io/llms.txt)
- **The published skill [Observed; Company claim]:**
  - `github.com/urnetwork/skill` was created 2026-03-04 and last pushed 2026-09-01. It has 0 stars and 1 fork, and its README returns 404. — [GitHub API](https://api.github.com/orgs/urnetwork/repos)
  - Its SKILL.md is identical to the local copy. The frontmatter description reads: "Use when a task needs requests to originate from another location, needs many distinct egress IPs (distributed scraping), needs a private/anonymous network path, or when code must handle an HTTP 402 from api.bringyour.com and pay for its own plan upgrade over x402."
  - It includes a section titled "Recipe: many distinct egress IPs (distributed scraping)".
  - Plan limits it documents: Free allows 2 concurrent clients and UR Pro allows 1,000; SOCKS5 and WireGuard are Pro-only.
  - Spending rules it gives the agent: honor a `URNETWORK_X402_MAX` ceiling, "Never pay twice for the same 402", and "Pay only terms the server quoted".
  - Source: [SKILL.md](https://github.com/urnetwork/skill/blob/main/SKILL.md)
- **x402 status is inconsistent:**
  - agents.md says: "Availability: x402 is not switched on for this deployment yet. Until it is, `GET /x402/skus` answers an error instead of a sku list (today an HTTP 500 ...)". — [ur.io/agents.md](https://ur.io/agents.md)
  - llms.txt says the same: "it is not on yet". — [ur.io/llms.txt](https://ur.io/llms.txt)
  - **Contradicted by the live endpoint [Observed]:** `GET https://api.bringyour.com/x402/skus` returned HTTP 200 with asset `usdc`, networks `["base","solana"]` and three SKUs: `pro_1month` at $5 (10 TiB), `data_1tib` at $3 and `data_10tib` at $20, with `x402_version` 1. — [x402 skus](https://api.bringyour.com/x402/skus)
  - I did not attempt a purchase.
- **Developer SDK examples [Company claim]:**
  - The examples repository was created 2026-09-14. It covers Integration, Sockets, Messages, Provider and Embed in 12 languages, plus Electron, Tauri and Android apps.
  - Messages uses the "URMS v1" text/ACK protocol, and applications can register custom subprotocols.
  - Quote: "Some package coordinates are awaiting their first publication."
  - Source: [github.com/urnetwork/examples](https://github.com/urnetwork/examples)
- **Earlier MCP and skill work in the docs repository:**
  - Commits on 2026-02-21 ("mcp: skill update") and 2026-03-03 ("mcp: update skill document").
  - The latest commit, on 2026-08-26, is "docs: update legal and MCP guidance".
  - Source: [local docs/mcp/](file:///Users/brien/urnetwork/docs/mcp/), from the git log.
- **Third-party listing:** mcp.bringyour.com is listed on mcpservers.org. I could not extract listing details. — [mcpservers.org](https://mcpservers.org/pt-BR/servers/mcp-bringyour-com)

### Inferences
- **A reusable asset:** this is the clearest asset the sidecar can reuse. The company has already shipped to the harness ecosystem through OAuth MCP, recipes for 21 harnesses, a skill, API keys and agent-payable pricing. The sidecar is a subprocess driven by a text protocol rather than an MCP server, but the account and OAuth flows, the per-harness documentation and the agent-payment plumbing all carry over.
- **A positioning liability:**
  - The public agent identity today is "residential egress / distributed scraping / pass a 402 and pay".
  - For a pitch to developer teams and enterprises built on shared memory, inboxes, admin and audit, that framing works against the company.
  - A security reviewer's first search will find a scraping recipe built on residential IPs.
- **No traction proof:** there is no measurable agent adoption (a 0-star skill and no MCP usage data), so a right-to-win argument cannot rest on agent traction yet.
- **Docs lag:** the x402 contradiction suggests the documentation lags the deployment, which a diligent buyer will notice.
- **Audience split on payments:** paying in on-chain stablecoins is a differentiator for autonomous agents, but irrelevant or negative for enterprise procurement.

### Gaps
- MCP usage (OAuth grants, active connections, which harnesses) is not published.
- I did not verify whether an x402 purchase actually settles today.
- The MCP server's launch date is unknown. The earliest dated evidence is the docs commits in February–March 2026 and the skill repository's creation on 2026-03-04.
- I did not check official MCP registries or vendor connector directories.

## 3. Public sentiment: Reddit, Hacker News, Product Hunt, privacy communities, VPN review sites, and DePIN coverage

### Takeaway
Public sentiment is thin and split.
- **App-store users:** rate it highly (4.6 on both stores).
- **Company-curated praise:** centres on speed, censorship circumvention and getting paid.
- **Privacy communities:** range from skeptical to dismissive. They file it with "crypto" VPNs that have too little documentation and too few nodes, question the team's Palantir background, and read it as an exit-node or residential-proxy network.
- **Developer footprint:** negligible. There is one Show HN at 17 points, Product Hunt and Reddit were not retrievable, and I found no coverage on VPN review sites.

### Cited Findings

#### Praise
- **App Store reviews (February 2025):** "up and running in less than a minute"; "It just works"; and "Final! An Open Source VPN", the last from a reviewer glad to see a peer-to-peer solution. — [App Store](https://apps.apple.com/us/app/urnetwork/id6741000606)
- **Google Play:** rated 4.6 from 2.24K reviews. — [Google Play](https://play.google.com/store/apps/details?id=com.bringyour.network)
- **Homepage testimonial wall [Company-curated]:**
  - "Excellent, Very undetectable, Passes Proxy/VPN detection"
  - "I am in iran and working this app perfectly"
  - "the best dapp on Solana seeker"
  - "Love being early and getting rewarded for using!"
  - "Its commitment to open-source transparency and disabling outdated protocols makes it a trustworthy choice for security-conscious users."
  - Source: [ur.io](https://ur.io/)
- **Censorship circumvention on HN [Company voice]:** on 2025-08-28 the account that posted the Show HN replied in "Ask HN: The government of my country blocked VPN access. What should I use?" (a 1,338-point thread): "URnetwork works where many don't ... It used a grab bag of techniques, open source". — [HN item 45057126](https://news.ycombinator.com/item?id=45057126)
- **DePIN media:** frames URnetwork as "One to Watch" among decentralized VPNs. — [DePIN Hub blog](https://depinhub.io/blog/the-state-of-decentralized-vpns-and-why-urnetwork-is-one-to-watch/)
- **Privacy Guides forum (11 Jun 2025):** a newcomer called it "a neat idea to me" but "couldn't find much" in the way of independent reviews. — [Privacy Guides thread 28253](https://discuss.privacyguides.net/t/thoughts-on-urnetwork/28253)

#### Worries and criticism
- **Privacy Guides forum (2 Jun 2025):**
  - A forum account wrote: "We don't allow these kinds of low effort 'thoughts about x service' posts."
  - Then @dngray, who started the forum's 2023 decentralized-VPN thread, wrote: "You can add it to the list of all the other 'crypto' related VPNs with zero documentation and some cryptocurrency behind them ... All of them always have flashy websites, zero documentation or absolutely bugger all documentation. **None of them have enough nodes to actually be private, eg like Tor**."
  - Source: [Privacy Guides thread 27989](https://discuss.privacyguides.net/t/any-thoughts-on-urnetwork/27989)
- **Privacy Guides forum (13 Apr 2026):** "Could someone provide an update on this company?" had gone unanswered. — [Privacy Guides thread 28253](https://discuss.privacyguides.net/t/thoughts-on-urnetwork/28253)
- **Privacy Guides category thread on decentralized VPNs:**
  - 2023: "most of these networks seem to be over promising tor ripoffs with a blockchain attached to sell some new shitcoins".
  - 10 Jan 2026: "Decentralization does not improve security: there may be government servers on the other end of the line".
  - 10 Jan 2026: "You can't trust them". The same poster favors "Routing your connection through users' networks and bandwith sharing like i2p or Tor + Snowflake" over "using a shitcoin to incentivize users to spin up nodes on privacy-hostile hosting providers". That is a nuance partly favorable to URnetwork's residential design.
  - Source: [Privacy Guides thread 11818](https://discuss.privacyguides.net/t/decentralized-vpns-and-routing-networks/11818)
- **Lemmy (Privacy@lemmy.ml, about one year old, cross-posted from r/privacy):** "Seeking Privacy Analysis of URnetwork (ur.io) – Ex-Palantir Team, Open-Source, What Data Is Collected?". The post asks whether anyone has audited the code or tested the anonymity claims. — [Lemmy](https://lemmy.toldi.eu/post/1819621/5276720)
- **Hacker News:**
  - Show HN (24 Feb 2025): 17 points and 2 comments, the first of which was "Sounds like Tor". — [HN 43165027](https://news.ycombinator.com/item?id=43165027)
  - A reply on 29 Aug 2025: "The site is awful, and I couldn't find the technical description easily. I assume it runs an exit node for other people's traffic?" — [HN 45057126](https://news.ycombinator.com/item?id=45057126)
- **MalwareTips (HTTP 403 when fetched; from search summaries only):** the thread reportedly says URnetwork "fundamentally operates as a distributed residential proxy network", raises Web3 liquidity risk and discusses the Palantir background. — [MalwareTips](https://malwaretips.com/threads/ur-network.139711/)
- **App Store negative review (3 Nov 2025):** the app "has tons of fake reviews that are 5 stars", and the reviewer's provided-data total was reset on the leaderboard. This is an unverified user claim. — [App Store](https://apps.apple.com/us/app/urnetwork/id6741000606)
- **F-Droid:** flags the "network service" anti-feature, meaning the app depends on bringyour.com. — [F-Droid](https://f-droid.org/en/packages/com.bringyour.network/)
- **Crypto-promotion footprint:** an "airdrop" listing [airdrops.io](https://airdrops.io/urnetwork/) and June 2025 AMAs on crypto "calls" channels [local AMA transcripts](file:///Users/brien/urnetwork/docs/ama/).

### Inferences
- **Two audiences, two verdicts, and neither is the buyer:**
  - Consumers, often in censored regions or motivated by earnings, are positive.
  - Privacy experts are dismissive.
  - Developer and enterprise buyers will find almost nothing independent, so they will fall back on category priors: residential proxy, crypto, and exit-node liability.
- **An outdated critique, a live gap:**
  - The "zero documentation" charge from June 2025 is partly outdated, because a detailed and self-critical threat model is now public.
  - The artifacts privacy communities weigh most are a dated warrant canary, a current transparency report and an independent protocol audit. Those are missing, stale, or not published (see sections 4 and 5), so the critique is likely to persist.
- **Testimonials that cut both ways:** the testimonials the company chose to feature, "Passes Proxy/VPN detection" and a user in Iran, are strengths with consumers. With a security or compliance reviewer they are liabilities.

### Gaps
- **Reddit:** the reddit.com search API returned non-JSON (blocked). I retrieved no Reddit threads, including the r/privacy original behind the Lemmy cross-post.
- **Product Hunt:** producthunt.com returned 403, and hunted.space shows "No data available".
- **VPN review sites:** the searches surfaced no coverage of URnetwork on PCMag, TechRadar, Security.org, Cybernews or similar.
- **Not examined:** Discord, Telegram and X.
- **Provider payouts:** I found no independent reports of provider earnings or payouts.

## 4. Category risk: how the category is perceived, enforcement against residential proxies, enterprise controls, and the effect on a sidecar buyer

### Takeaway
Between 2025 and 2026, residential proxies went from a gray market to an active enforcement target.
- **2025:** BadBox 2.0 drew an FBI public service announcement and a Google lawsuit.
- **January 2026:** Google took down IPIDEA.
- **July 2026:** the FBI seized NetNut, and LG moved against proxy SDKs.
- **Google's consumer warning:** be "extremely wary" of apps that pay for "unused bandwidth".
- **Enterprise identity tools:** Okta and Entra flag or block anonymizing IP addresses, and the DISA STIG for Okta treats a missing anonymous-proxy block as a finding.

URnetwork structurally resembles this category. It has paid residential exit nodes, an embeddable provider SDK with crypto payouts, a scraping-oriented agent skill and SNI-spoofing extenders. Its marketing ("No logs", "Tor-like", "100% open source") also overstates what its own public threat model says.

A sidecar from this company will therefore be pre-judged by security reviewers unless it is clearly separated from the egress network, both in architecture and in how it is sold.

### Cited Findings

#### Enforcement and research on residential proxies
- **Google's IPIDEA takedown (28 Jan 2026) [Third party]:**
  - Google's Threat Intelligence Group (GTIG) calls IPIDEA "one of the largest residential proxy networks in the world".
  - Enrollment: devices were enrolled through SDKs (Castar, Earn, Hex, Packet) paid "usually on a per-download basis", through VPN apps (Galleon VPN, Radish VPN, Aman VPN) that enrolled devices "without clear disclosures", and through trojanized Windows binaries.
  - Scale: "550+" threat groups used its exit nodes within seven days; "600+" Android apps and 3,075 Windows binaries were linked to its infrastructure.
  - Actions: Play Protect removes and blocks apps that contain these SDKs. Cloudflare, Spur and Lumen's Black Lotus Labs were partners.
  - Statements from Google about the category as a whole:
    - "these proxies are overwhelmingly misused by bad actors"
    - "Consumers should be extremely wary of applications that offer payment in exchange for 'unused bandwidth' or 'sharing your internet.'"
    - "Any claims of 'ethical sourcing' must be backed by transparent, auditable proof of user consent."
    - "App developers have a responsibility to vet the monetization SDKs they integrate."
    - "the residential proxy market has become a 'gray market' that thrives on deception"
    - "this industry appears to be rapidly expanding"
  - Source: [Google Cloud blog (GTIG)](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- **CyberScoop:** reported initial data showing IPIDEA's network cut by about 40%. — [CyberScoop](https://cyberscoop.com/ipidea-proxy-network-disrupted-google-lumen/)
- **BadBox 2.0 [Third party]:**
  - The FBI issued a public service announcement on 5 Jun 2025. It said the botnet "maintains numerous backdoors to proxy services".
  - In July 2025, Google sued 25 unnamed defendants in China under the CFAA and RICO, in the Southern District of New York. The complaint describes more than 10 million infected Android-based TV boxes, tablets, projectors and car infotainment systems.
  - Sources: [The Register](https://www.theregister.com/2025/07/17/google_sues_25_unnamed_chinese/); [SecurityWeek](https://www.securityweek.com/google-sues-operators-of-10-million-device-badbox-2-0-botnet/)
  - KrebsOnSecurity's follow-up appeared in January 2026. — [KrebsOnSecurity](https://krebsonsecurity.com/2026/01/who-operates-the-badbox-2-0-botnet/)
- **Cloud Security Alliance research note (15 Aug 2026) [Third party]:**
  - NetNut: the FBI seized NetNut-linked domains on 2 Jul 2026. The connected Popa botnet comprises more than two million largely unconsenting devices, and researchers observed 316 threat-actor clusters using NetNut exit nodes in one week in June 2026.
  - Smart TVs: Spur found proxy SDKs in about 42% of LG webOS apps and more than 25% of Samsung Tizen apps, and LG then moved against those apps.
  - Browser extensions: Socket found 737 Chrome "VPN" extensions routing browser traffic through SOCKS5 infrastructure.
  - Key quote: "Distinguishing a legitimate proxy network from a botnet depends on consent quality and customer vetting, not on technical architecture."
  - Recommendations to enterprises:
    - "treat any smart TV, streaming box, or Android TV device on a corporate or home network as a potential proxy exit node"
    - "add proxy-SDK disclosure to vendor security questionnaires"
    - monitor egress by device and application behavior, not by IP reputation alone
  - Source: [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-residential-proxy-economy-systemic-risk-20/)
- **How detection works [Third party]:**
  - Residential exit IPs inherit "clean" reputations, so vendors score session behavior instead, such as one home connection serving many sessions. — [ipgeolocation.io](https://ipgeolocation.io/blog/how-residential-proxy-detection-works)
  - Spur says it continuously maps exit nodes across more than 1,000 proxy and VPN services. — [Spur](https://spur.us/platform/residential-proxy-detection)

#### Enterprise controls
- **Okta:**
  - Dynamic Zones can block IP addresses categorized as anonymizer proxies, and can block by proxy type. — [Okta, block anonymizers](https://sec.okta.com/blockanonymizers)
  - Blocklisted IPs are rejected "before any type of policy evaluation occurs". — [Okta help](https://help.okta.com/en-us/Content/Topics/Security/healthinsight/blocklist-proxies-tor.htm)
  - The DISA STIG for Okta IDaaS (2025-11-19) states: "If Network Zones are not configured to block anonymous proxies, this is a finding." — [STIG V-279692](https://www.stigviewer.com/stigs/okta_identity_as_a_service_idaas/2025-11-19/finding/V-279692)
- **Microsoft Entra ID Protection:** raises an "anonymized IP address" risk detection for VPN and Tor sign-ins, which feeds risk-based Conditional Access. — [Elastic prebuilt rule documentation](https://www.elastic.co/guide/en/security/8.18/prebuilt-rule-8-18-4-microsoft-entra-id-protection-anonymized-ip-risk-detection.html)

#### How privacy communities see decentralized VPNs and crypto incentives
- They are dismissive (see section 3): "tor ripoffs with a blockchain attached"; "You can't trust them". — [Privacy Guides thread 11818](https://discuss.privacyguides.net/t/decentralized-vpns-and-routing-networks/11818)

#### Where URnetwork overlaps the risk category (company sources)
- **An embeddable provider SDK with crypto payouts (public):**
  - "A provider example runs a URnetwork provider inside an application ... its payouts go to the developer's fixed Bittensor payout wallet."
  - The contract requires consent: "an app that integrates a URnetwork provider must collect the user's consent before it provides", and the app "must let the user stop providing at any time".
  - But the examples themselves "start providing without a consent screen of their own ... The examples do not cap bandwidth."
  - "payouts are subnet payouts".
  - Source: [PROVIDER_CONTRACT.md](https://github.com/urnetwork/examples/blob/main/PROVIDER_CONTRACT.md)
- **The agent skill markets "many distinct egress IPs (distributed scraping)".** — [SKILL.md](https://github.com/urnetwork/skill/blob/main/SKILL.md)
- **Android TV:** support launched in October 2024 [local changelog](file:///Users/brien/urnetwork/docs/changelog/2024-10-31-update-1/update-1.md). Compare the CSA's advice to treat Android TV devices as potential exit nodes [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-residential-proxy-economy-systemic-risk-20/).
- **Extenders [Internal]:** "N-TLS ... where each outer encryption uses a self-signed cert for any host name (SNI spoofing) to an intermediary IP". — [local protocol-research.md](file:///Users/brien/urnetwork/docs/protocol/protocol-research.md)
- **Abuse controls [Internal; not found publicly]:**
  - Blocked by default: plain DNS (53), HTTP (80), SMTP (25), IMAP (143), POP (110), BitTorrent (6881–6889) and IRC (6667).
  - Per-source connection-rate and parallel-connection limits apply.
  - A provider opt-in encrypted audit log is keyed by the SHA-256 hash of the TLS client random. It "is maintained for 24 months".
  - Abuse reports go to notice@bringyour.com.
  - Source: [local trust-and-safety.md](file:///Users/brien/urnetwork/docs/trust-and-safety/trust-and-safety.md)
  - The transparency report covers only January–March and April–June 2024 (0 abuse reports in both), despite a policy of "quarterly statistics". — [local transparency-report.md](file:///Users/brien/urnetwork/docs/trust-and-safety/transparency-report.md)
  - The warrant canary text carries no date or signature. — [local warrant-canary.md](file:///Users/brien/urnetwork/docs/trust-and-safety/warrant-canary.md)
  - None of these pages resolves publicly today (section 1).
- **Marketing claims [Company claim]:**
  - "No single node sees the full path. No logs stored. Privacy by architecture, not promise."
  - "Tor-like anonymization. No logs. 100% open source and reproducible"
  - Sources: [ur.io](https://ur.io/); [ur.io/llms-full.txt](https://ur.io/llms-full.txt)
- **The company's own public threat model says:**
  - "There is no independent audit of the protocol, the connect engine, or the operator's server code — the layer the privacy claims rest on".
  - "The fail-closed guarantee is bound to a toggle that still ships off in all five native apps (§2.2), so a default-configuration client opens no session to the provider at all: every application packet crosses the operator unsealed, on the standard path."
  - Source: [ur.io/docs/threat-model](https://ur.io/docs/threat-model)
  - The local copy (dated 2026-09-17) adds:
    - "There are no traffic-analysis defences. None."
    - "At the operator, everything links".
    - Connection rows, with per-connection city, are kept "8 hours", and audit rows "180 days".
    - The privacy policy "states no retention period at all".
    - Source: [local THREAT-MODEL.md](file:///Users/brien/urnetwork/cure53/THREAT-MODEL.md)
- **Sanctions optics:**
  - The IETF deck lists "Iran export" among participants' US legal duties. — [local IETF deck](file:///Users/brien/urnetwork/docs/presentations/Default%20Safe_%20Realizing%20the%20Potential%20of%20Decentralized%20Networks%20%28IETF%20124%29.pdf)
  - The homepage features the testimonial "I am in iran and working this app perfectly". — [ur.io](https://ur.io/)
  - I found no public statement of sanctions-compliance controls.

### Inferences

#### Reputational risks that would follow URnetwork into a sale to developer teams and enterprises (ordered by likely severity)
1. **Classification as "proxyware" (highest risk).**
   - After IPIDEA and NetNut, security reviewers pattern-match on three things: paid bandwidth sharing, provider SDKs inside third-party apps, and residential exit IPs. URnetwork has all three, plus a skill that advertises "distributed scraping".
   - The distinction that matters is consent quality and vetting, as the CSA note puts it. URnetwork's consent controls exist (an explicit consent contract, port blocking, an abuse process), but its public trust documentation is currently unreachable.
   - The likely result is that the company gets categorized before the sidecar is evaluated on its merits.
   - For developer teams the risk is moderate: they tolerate tools like ngrok and Tailscale. For regulated enterprises it is high.
2. **The crypto and token association.**
   - The signals: Bittensor SN25 alpha, tokenholder letters, alpha locks, an "Investor Centre", airdrop listings, AMAs on promotion channels, a Solana dApp-store presence, and payouts to wallets.
   - Privacy communities already dismiss the category on this basis.
   - Enterprise procurement will ask about counterparty, governance and continuity under the UR Foundation versus BringYour, Inc., and about whether customer fees flow into token incentives.
3. **A gap between claims and evidence.** The absolute marketing claims ("No logs stored", "100% open source", "Tor-like") sit next to a candid threat model that admits no traffic-analysis defenses, an unsealed operator path by default, and 8-hour, 180-day and 24-month retention windows. Diligence teams read both. The candor is an asset; the mismatch is a liability.
4. **Missing or stale trust artifacts.**
   - The canary, the transparency report and the trust-and-safety policy return 404 publicly, and the last transparency entry is from 2024.
   - In privacy culture, a canary that disappears reads as a warning even when the cause is a site migration.
   - An enterprise questionnaire will ask for an independent audit (the Cure53 work is still a briefing), SOC 2 or ISO certification (no evidence found), and a DPA (not checked).
5. **Vendor viability.** Directories list 1–10 employees and roughly $1.5–2M of seed funding; the scale numbers are self-published and declining; and network economics are tied to token incentives. These are standard small-vendor objections, amplified by the token.
6. **Optics of evasion and tunneling.** SNI-spoofing extenders, a "Passes Proxy/VPN detection" testimonial, and sidecar features that open tunnels, port forwards and public TLS endpoints from developer machines all resemble shadow-IT tunneling. Secure web gateways may block the network's domains as "proxy/anonymizer" (unverified; see Gaps).
7. **Sanctions and compliance optics.** The featured Iran testimonial and the absence of published OFAC controls will draw questions from compliance reviewers.
8. **Founder background as perceived by privacy communities.** The "Ex-Palantir" framing breeds suspicion there. It is probably neutral-to-positive for enterprise buyers.

#### Implications for positioning (inference)
- **Separate the trust boundary:** the sidecar's storage, inbox, forwarding and audit features should not route through consumer provider egress by default, and the sidecar binary should contain no provider mode.
- **Publish a sidecar-specific threat model and data-flow map:** state which hosts it contacts, what it stores and for how long, and who holds the keys.
- **Restore dated trust artifacts:** a dated canary and current transparency reports, plus a completed and published third-party audit.
- **Clean up the agent positioning:** drop "distributed scraping" from agent-facing materials, and drop evasion-themed testimonials.
- **Name the contracting entity** and how BringYour's operator role relates to the foundation.

### Gaps
- **The Spur 2026 IP Intelligence Study:** a search summary reported that "94% of organizations" have seen VPNs or residential proxies in security incidents. I could not load a primary source, so I am not relying on the figure.
- **URnetwork's own exit IPs:** I found no evidence on whether Spur, IPQS, IPinfo or MaxMind tag them, or under what name.
- **Domain categorization:** I did not check how secure-web-gateway and URL-categorization vendors (Zscaler, Palo Alto, Cisco, Netskope) categorize ur.io, bringyour.com or ur.network.
- **Play policy:** I did not check whether Google Play's policy changed after IPIDEA in ways that affect "earn by sharing bandwidth" apps.
- **Enforcement against URnetwork:** none found.
- **Entra:** I did not find whether Entra has a native "block residential proxy" condition, as opposed to anonymized-IP risk detection.
- **Enterprise readiness documents:** I did not check for a DPA, SOC 2 or SSO/SAML documentation.

## 5. Technical assets that transfer to the sidecar, and what is new to build

### Takeaway
**Assets that transfer:**
- **Networking substrate:** a production overlay that relays traffic through the operator, with permanent per-client IDs that act like IPv6 addresses, censorship-resistant extenders, and a userspace network stack (userspace WireGuard and a gVisor fork). This maps well onto the sidecar's IP and port forwarding and its public TLS edge.
- **Integration layer:** OAuth MCP, recipes for 21 harnesses, a skill, `urn_` API keys, "Sign in with URnetwork", and Embed ACL groups. These serve auth and distribution.
- **Encrypted messaging in progress:** URmessage uses MLS (RFC 9420) with a message server that stores records it cannot decrypt. It is a base for the group inbox.
- **Assurance material:** a candid public threat model and two narrow 2025 assessments, Cobalt (web app and API) and Leviathan (Android).

**Assets that transfer weakly:**
- P2P and NAT traversal are not the live default; traffic relays through a central hop.
- The split-knowledge design protects egress, not data the operator hosts.
- Trust and safety covers egress traffic, not hosted endpoints or mail.
- The warrant canary and transparency report are stale and unpublished.

**New to build:** encrypted storage with a git front end, email (SMTP, MX, deliverability, abuse handling), team administration and RBAC, a customer-readable admin audit trail, wildcard certificates and DNS for `*.you.ur.network`, and the `ur` CLI itself.

### Cited Findings

#### Transfer candidates
- **Topology:**
  - The audit briefing describes four legs: "client → extender → operator → provider → internet". The operator "carries the relayed packets". — [local AUDIT.md §1.1](file:///Users/brien/urnetwork/cure53/AUDIT.md)
  - Protocol research says:
    - "Multi-hop routing is done via TCP transports through a central hop."
    - "UDP transports (H3, DNS) are supported but disabled".
    - A peer-to-peer "stream" upgrade "is supported but currently disabled".
    - The goal is "to integrate tried and true protocols (WebRTC, XRay, WireGuard) as the stream upgrade".
    - The document is undated. — [local protocol-research.md](file:///Users/brien/urnetwork/docs/protocol/protocol-research.md)
  - The Show HN said "users can directly connect to each other" [Company claim]. — [HN 43165027](https://news.ycombinator.com/item?id=43165027)
- **Addressing and identity:**
  - The threat model quotes server code: "client_ids are globally unique addressess tantamount to IPv6 / they are never revoked once allocated". — [local THREAT-MODEL.md §9.3](file:///Users/brien/urnetwork/cure53/THREAT-MODEL.md)
  - The original whitepaper planned network identities of the form "you.bringyour.network", each a "globally unique IPv6 subnet".
  - It also planned a "super peer" that "exposes endpoints and subnets from a host to self, friends, and family", aimed at prosumer and small-business use cases.
  - Source: [local llms-full.txt (whitepaper section)](file:///Users/brien/urnetwork/docs/llms-full.txt)
- **Extenders:**
  - Design: "N-TLS (N>=2)" with SNI spoofing; "Anyone can host an extender"; extenders join a grant list. — [local protocol-research.md](file:///Users/brien/urnetwork/docs/protocol/protocol-research.md)
  - There is a public Extenders documentation page. — [ur.io/docs](https://ur.io/docs)
  - The company claims URnetwork works where VPNs are blocked. — [HN 45057126](https://news.ycombinator.com/item?id=45057126)
- **Userspace networking:**
  - `userwireguard` ("Wireguard-go with an integrated BringYour TAPTUN interface", created 2024-08-08) and a `gvisor` fork (created 2026-10-03). — [GitHub API](https://api.github.com/orgs/urnetwork/repos)
  - The "tether" changelog of 31 Oct 2024 describes "integrating WireGuard into URnetwork with userspace implementation and CLI management". — [local llms.txt](file:///Users/brien/urnetwork/docs/llms.txt)
  - UR-IP is "an implementation of an IP stack that runs in minimal memory". — [local protocol-research.md](file:///Users/brien/urnetwork/docs/protocol/protocol-research.md)
  - The skill already issues HTTPS proxy, SOCKS5 and WireGuard configurations. — [SKILL.md](https://github.com/urnetwork/skill/blob/main/SKILL.md)
- **End-to-end encryption:**
  - The network admits only encrypted protocols; plaintext ones are blocked. — [local trust-and-safety.md](file:///Users/brien/urnetwork/docs/trust-and-safety/trust-and-safety.md)
  - The sealed client-to-provider session ("Post Quantum Encryption") runs on the native apps. It has been fail-closed since 2026-08-08/10, but the toggle ships off by default. — [ur.io/docs/threat-model](https://ur.io/docs/threat-model)
  - Since 2026-09-17 there is signed, hash-chained registration of provider keys; a substituted key must now be signed by the operator and leaves an attributable record. — [local THREAT-MODEL.md](file:///Users/brien/urnetwork/cure53/THREAT-MODEL.md)
- **Split knowledge:**
  - "the operator knows who you are; the provider knows where you go."
  - P1, provider blindness to identity, "Holds unconditionally".
  - P2, operator blindness to content, "Holds, conditionally".
  - Source: [local AUDIT.md §1.1–1.2](file:///Users/brien/urnetwork/cure53/AUDIT.md)
- **Trust and safety:**
  - A two-tier "frontline/backline" process and the encrypted audit log described in section 4. — [local trust-and-safety.md](file:///Users/brien/urnetwork/docs/trust-and-safety/trust-and-safety.md)
  - Principles from the IETF deck. — [local IETF deck](file:///Users/brien/urnetwork/docs/presentations/Default%20Safe_%20Realizing%20the%20Potential%20of%20Decentralized%20Networks%20%28IETF%20124%29.pdf)
- **Third-party assessments [Internal PDFs]:**
  - Cobalt, "URnetwork Penetration Test Report - May 2025": test period 25 Apr–5 May 2025; report generated 12 May 2025; targets were https://ur.io and network ranges. The report says it is "intended for internal use by BringYour, Inc. only". — [local Cobalt PDF](file:///Users/brien/urnetwork/docs/audits/automatedReport_urnetwork-april-2025-pt30328.pdf)
  - Leviathan Security Group, "Mobile Application Security Assessment": completed 23 May 2025 against product version 2025.5.18-play. — [local Leviathan PDF](file:///Users/brien/urnetwork/docs/audits/mpc_com.bringyour.network_2025.pdf)
  - The public threat model says neither assessment "examined logging, retention, the data path, or the protocol". — [ur.io/docs/threat-model](https://ur.io/docs/threat-model)
  - A Cure53 audit briefing dated 2026-09-17 is internal, and I found no public Cure53 report. — [local AUDIT.md](file:///Users/brien/urnetwork/cure53/AUDIT.md)
- **Supply-chain and operational transparency:**
  - A "Reproducible builds" repository with 57 stars. — [GitHub API](https://api.github.com/orgs/urnetwork/repos)
  - F-Droid publishes a reproducibility status section for the app. — [F-Droid](https://f-droid.org/en/packages/com.bringyour.network/)
  - A public outage log and a public stats feed. — [ur.io/llms.txt](https://ur.io/llms.txt)
- **Auth and team primitives:**
  - An OAuth authorization server at auth.bringyour.com. — [OAuth metadata](https://mcp.bringyour.com/.well-known/oauth-protected-resource)
  - `urn_` API keys. — [ur.io/llms.txt](https://ur.io/llms.txt)
  - A "Sign in with URnetwork" documentation page. — [ur.io/docs](https://ur.io/docs)
  - Sign-in by Solana or Bittensor wallet signature. — [ur.io/llms-full.txt](https://ur.io/llms-full.txt)
  - Embed: the backend holds the root credential and apps receive client JWTs; an installation's ACL group is "`isolated` by default, so your users stay out of each other's peer list"; optional per-user data caps. — [examples README](https://github.com/urnetwork/examples)
- **Messaging:**
  - URmessage is "the URnetwork messaging application: message records, group sessions, MLS, ... the messaging SDK". It was moved into its own repository, with every pull request in the set merged on 2026-10-09. — [github.com/urnetwork/message](https://github.com/urnetwork/message)
  - The message server "stores encrypted records, orders them, serves history, and prunes by retention policy. It never decrypts anything". Group membership lives in "the MLS (RFC 9420) group state held by clients". Status: "Early development, and the process runs". — [github.com/urnetwork/message-server](https://github.com/urnetwork/message-server)
  - A Windows client, "URmessage Windows client — a private messenger on URnetwork. WinUI 3 / C++/WinRT", is in development. — [GitHub API](https://api.github.com/orgs/urnetwork/repos)
  - The SDK's URMS v1 text/ACK protocol and custom subprotocols. — [examples README](https://github.com/urnetwork/examples)
- **Existing operator-side audit data:**
  - "Audit rows" are kept 180 days.
  - `audit_contract_event` records client and provider identity per contract.
  - This data is operational and held by the operator; it is not a customer-facing audit trail.
  - Source: [local THREAT-MODEL.md §5.1 and §9.3](file:///Users/brien/urnetwork/cure53/THREAT-MODEL.md)

#### New to build (design-only today; source is the internal `cli/UI.md`)
- **The `ur` CLI:**
  - Commands: `ur login`, `ur daemon`, and `ur install-daemon`.
  - Every command accepts `--instance` to scope its local storage.
- **Identities, email and groups (`ur id`):**
  - Addresses: `name@you.ur.network` aliases and groups, with "`admin@<user>.ur.network`" as the admin address.
  - Send quotas: "only replies if free", "2000/day if pro".
  - The design says it "acts as a password manager".
- **Encrypted storage:**
  - A keychain encoded with a passphrase.
  - Quotas of "1GB if free" and "100GB if pro".
  - "each dir is a git server, exposed locally through ssh".
- **Bridge commands (`ur bridge`):**
  - `public-tls`, giving `hostname.you.ur.network` with "Unlimited subdomains" and "Cert issues and renews on subdomains using lets encrypt".
  - `forward`, `expose`, `invite` and `accept-invite`.
- **Infrastructure list:** "Encrypted storage", "TLS forwarder", "Cert issuer", "DNS records", "Shared SMTP".
- **Not in the sketch:** team RBAC, SSO/SCIM, and an admin audit-trail design.
- Source: [local cli/UI.md](file:///Users/brien/urnetwork/cli/UI.md)
- **Pricing constraint:** the current Free plan allows "2 concurrent clients". — [ur.io/llms.txt](https://ur.io/llms.txt)

### Inferences
- **Forwarding and the public TLS edge** sit closest to existing code: operator relay, permanent client addressing, a userspace stack and TLS everywhere. The new work is edge TLS termination or passthrough, ACME automation for wildcard subdomains, DNS for `*.you.ur.network`, and abuse handling for hosted endpoints such as phishing and malware hosting. The existing trust-and-safety process does not cover hosted endpoints. The whitepaper's "super peer" shows the feature is a long-held part of the design, not a pivot.
- **The privacy story has to change basis.**
  - Because the live path relays through a central hop, a forwarding product will be an operator-hosted relay, much like ngrok or a TURN server. The operator/provider split-knowledge story does not apply to it.
  - Storage, inbox and audit are operator-hosted too.
  - So the sidecar's privacy argument must rest on client-side encryption (the passphrase keychain, MLS), not on the egress network's split-knowledge design.
- **Group inbox:** URmessage gives a credible start on encrypted messaging between agents and people. Email interop is entirely new. It covers inbound MX, outbound SMTP with SPF, DKIM and DMARC, reputation, spam and phishing abuse, and retention of mail in encrypted storage. It must run from data-center infrastructure, since the network's default policy blocks port 25 egress through providers.
- **The admin audit trail conflicts with the company's existing privacy stance.**
  - The existing encrypted abuse log is deliberately unreadable by the company without an abuse report's key.
  - An enterprise admin audit trail must be readable by the customer's admin.
  - Reconciling the two requires an audit trail encrypted under keys the customer holds, with the operator blind to its content. That has to be designed and audited.
- **Auth and team management:** OAuth, API keys, isolated ACL groups and "Sign in with URnetwork" give a usable base for developer teams. SSO (SAML/OIDC with the customer's identity provider), SCIM, RBAC and seat billing are new, and enterprises will expect them.
- **Pricing for multi-agent teams:** the Free plan's 2-concurrent-client limit and the agent-payment design (x402 in USDC) point to a pricing redesign for teams running multiple agents. Seat-based or org plans would need to sit alongside x402.

### Gaps
- I could not tell whether the P2P "stream" upgrade or the UDP transports have been enabled since the undated protocol-research document was written.
- No evidence was found of existing SSO, SAML or SCIM support, or of any customer-facing audit-log product.
- The timing and scope of the Cure53 audit, and whether it will be published, are unknown.
- I could not tell whether the sidecar would be billed by BringYour, Inc. as an operator or would carry subnet or token economics. Public materials do not say.
- I did not check whether the URmessage clients (besides Windows) or the message server are deployed for users. The repositories call them early-stage.
