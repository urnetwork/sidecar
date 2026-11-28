# Internal audit: URnetwork's Services page, the Team plan, and the services URnetwork's designs could support

Scope: local files only, read on 2026-11-27. Line numbers are as of that read; the sidecar repo had uncommitted changes to `design/mocks/ui-site.html` and `design/mocks/ui-app.html` at the time. The owner's 27 Nov phrase "custom private, global infrastructure deployments for teams" appears in no local file yet: a search of the sidecar docs, design/, design/reports, mmm/outbound, SITEMAP.md and en.json found no match.

## 1. What does ur.io's Services page say today, and where is it linked from?

### Takeaway
Today ur.io/services is a sales page for embedding URnetwork: the SDK inside a customer's app, white-labelling, and "custom integrations". It has one action, an inquiry form that asks for monthly active users and a monthly data budget. It states no price, no SLA and no response time, and it says nothing about infrastructure deployments, teams, storage, mail, the TLS edge or enclaves. The footer, the Support page, the gift dialog's large-order nudge and the Embed docs link to it. The header, the Products page and the Agents page do not, and ur.io has no live CLI page yet.

### Cited Findings
**What the page is, by its own code comment**
- The page's scope comment reads: "Services — any embedding or custom use of URnetwork: the SDK embedded in an app (the Embed guide), a white-label app, a custom integration. One action: the inquiry form, which posts to POST /services/contact-sales. The page makes no response-time, SLA or support-tier promise, because none has been made." — [Services.jsx L9-12](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)
- It is "Rendered as a whole-page island (astro ServicesIsland, like BuyData), so the SPA route and the static page are the same tree." — [Services.jsx L14-15](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx); [ServicesIsland.jsx L2-5](/Users/brien/urnetwork/mmm/ur.io/astro/src/components/islands/ServicesIsland.jsx); [[...slug].astro L62, L1024-1026](</Users/brien/urnetwork/mmm/ur.io/astro/src/pages/[...slug].astro>)
- The Astro route is registered with the comment "Services: any embedding or custom use of URnetwork (the Embed guide, white label, custom integrations), with the inquiry form (POST /services/contact-sales)" and the entry `{ slug: "services", component: "Services", titleKey: "services" }`. — [astro/src/config/pages.js L82-85](/Users/brien/urnetwork/mmm/ur.io/astro/src/config/pages.js)
- SEO title: "White-Label Privacy Network SDK for Apps • URnetwork". Description: "Embed the URnetwork privacy network in your app under your own brand, with a client and data caps for each installation, or plan a custom integration with us." — [astro/src/config/pages.js L249-252](/Users/brien/urnetwork/mmm/ur.io/astro/src/config/pages.js)

**Copy (English), in page order**
- Hero: badge "Services", heading "Build URnetwork into your product", subtitle "Embed the privacy network in your app, ship it under your own brand, or plan a custom integration. Tell us what you're building.", CTA "Contact us", which links to `#contact`. — [en.json L690-693](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [Services.jsx L289-293](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)
- Section "What you can build" has three cards ([en.json L694-701](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [Services.jsx L295-316](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)):
  - "Embed the SDK in your app": "Your backend provisions a URnetwork client for each installation of your app, and your app sends its own traffic through the network with the SDK." It links to "Read the Embed guide" at `/docs/embed` ([Services.jsx L19, L303-305](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)).
  - "Ship it under your brand": "Your users sign in to your app, not to URnetwork, and never need a URnetwork account."
  - "Custom integrations": "Have a different use in mind? Describe what you're building and what it needs."
- Section "How it works" has three points ([en.json L702-708](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [Services.jsx L318-339](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)):
  - "The Embed plan": "Each installation of your app is one client in your network. An Embed plan starts with a review of your project and a contract; then our team enables Embed for your network and sets how many active installations it can have. An installation that hasn't connected for 30 days stops counting, and a user with a phone and a laptop counts twice."
  - "Data caps for each installation": "Give each installation a monthly data cap that resets at 00:00 UTC on the first of the month, a running total that you reset yourself, or both. Your backend sets the caps, so it can split a user's budget across their installations, and it reads each installation's usage through the API."
  - "Your keys stay on your servers": "Your backend keeps your network's root credential and gives each installation only its own scoped client token, so nothing secret ships in your app."
- Contact section: heading "Tell us about your project", intro "Share a few numbers about your plans and we'll follow up by email to start the review.", and the line "Using URnetwork in your product is covered by our" followed by a link to the Terms of Service at `/terms`. — [en.json L709-711, L385](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [Services.jsx L20, L341-353](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)
- The form's fields are Name, "Work email", Company, "Monthly active users" (hint "About how many people will use it each month."), "Total monthly data budget" (hint "For all of your users together, per month.") with a Unit select, and "Use case" (hint "Optional: what you're building, and anything else we should know."). The button reads "Send", and success shows "Thanks — we'll be in touch." — [en.json L713-725](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [Services.jsx L115-245, L89-95](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)
- The form posts the fields `monthly_active_users`, `monthly_data_budget` and `monthly_data_budget_unit`. Budget units are binary, GiB or TiB, defaulting to TiB. A hidden honeypot field, `website`, makes the server drop the inquiry if it is filled. — [Services.jsx L182, L207, L224, L258-269](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx); [servicesInquiry.js L6-9](/Users/brien/urnetwork/mmm/ur.io/react/src/lib/servicesInquiry.js)
- Client-side limits are name 200, company 200, email 254, message 4000 and monthly active users 1,000,000,000. "The server checks everything again; these rules only catch mistakes before a round trip." — [servicesInquiry.js L1-4, L11-17](/Users/brien/urnetwork/mmm/ur.io/react/src/lib/servicesInquiry.js)
- Summary of the page's content: there is no price string anywhere in the `services` block. The audience is companies building URnetwork into their own product. The only contact path is the form, with a follow-up by email. The only promise is a review followed by a contract for an Embed plan. — [en.json L689-735](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json)
- The page's CSS module also lays out the Gamma page: "the sections and their headings are the Services page's" and `import layout from "./Services.module.css"`. — [Gamma.jsx L5-6](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Gamma.jsx); the module is 678 lines ([Services.module.css](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.module.css))

**Where /services is linked from today**
- **Footer, Product column:** Products, Agents, Install, Buy data, Services, Gamma, and "Give a gift". The Services entry carries the comment "embedding and custom use: the Embed plan, per-user data caps, the inquiry form". — [Footer.jsx L63-75 (L69-70)](/Users/brien/urnetwork/mmm/ur.io/react/src/components/Footer.jsx); label "Services" at [en.json L380](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json)
- **Support page:** "Building URnetwork into your product?" followed by "See Services". — [en.json L686-687](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [Support.jsx L34-36](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Support.jsx); [Support.astro L17, L35](/Users/brien/urnetwork/mmm/ur.io/astro/src/content/Support.astro)
- **Gift dialog, at the quantity cap:** "Giving more than {max}?" followed by "Contact us for larger orders.", opening /services in a new tab. The cap is `max_quantity: 20`. — [GiftDialog.jsx L634-640](/Users/brien/urnetwork/mmm/ur.io/react/src/gift/GiftDialog.jsx); [en.json L1025-1026](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json); [pro.yml L319](/Users/brien/urnetwork/config/all/pro.yml)
- **Embed docs:** "**An Embed plan is required.** Embedding URnetwork in your own product needs an Embed plan for your network. Each plan starts with a review of your project and a contract, and then our team enables Embed for your network. [Request one on the Services page](/services), with your monthly active users and monthly data budget." The page links there again at L75 and L622. — [docs/EMBED.md L11, L75, L622](/Users/brien/urnetwork/mmm/ur.io/docs/EMBED.md)
- **Web app, account section "Embed":** this screen shares the form and its endpoint ("a message to sales"; "the form shares the Services page's rules and endpoint (lib/servicesInquiry.js, POST /services/contact-sales). Every signed-in account sees it."). Its copy is "Contact sales" and "Send the URnetwork team a message about an Embed plan or a custom use of URnetwork." — [Embed.jsx L13-19](/Users/brien/urnetwork/mmm/ur.io/react/src/app/screens/Embed.jsx); [en.json L969, L993-996](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json)
- **Not linked from:**
  - The header: no "servic" match in [Header.jsx](/Users/brien/urnetwork/mmm/ur.io/react/src/components/Header.jsx).
  - Products, Agents and Home: no services, enterprise or contact match in [Products.jsx](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Products.jsx), [Agents.jsx](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Agents.jsx) or [Home.jsx](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Home.jsx).
  - A CLI page: none exists in [react/src/pages/](/Users/brien/urnetwork/mmm/ur.io/react/src/pages), whose listing has no Cli file. The CLI page exists only in the mockup ([DESIGN-UI.md L213](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)).

**The live Products page and SITEMAP.md**
- The live Products strings define only "Community" ("Free", "30 GiB / day", "1 active hosted proxy") and "UR Pro" ("$40" "/ year", "or $5 / month", "10 TiB / month + 30 GiB / day", "1000 active hosted proxies", "14 day free trial"). The products block has no Team or Enterprise key. — [en.json L41-74](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json)
- SITEMAP.md, §2 Products: "There are three product offerings: Community, Pro, and Enterprise." It continues "Community includes all the VPN features with 1TB/month of data transfer and 1 concurrent network user." and "Pro includes all the VPN features with 10TB/month of data transfer and 100 concurrent network users. Pro includes up to 100 private reply-boxes. Price is $5/month or $40/year". It also says "Enterprise includes all the VPN features plus the ability to create networks and users via an API, and custom feature support. Contact sales for enterprise." — [SITEMAP.md L34-46](/Users/brien/urnetwork/mmm/ur.io/SITEMAP.md)
- SITEMAP.md has no Services section. Its only hits for "enterprise", "embed" or "white label" are L36, L46 and L54, and none of them names a Services page. Its header list still reads "100% open source and reproducible." (L29), which the outbound plan decided to remove or correct (Q-OB-1). — [SITEMAP.md L29](/Users/brien/urnetwork/mmm/ur.io/SITEMAP.md); [outbound PLAN.md L256-257](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- SITEMAP's Community and Pro numbers differ from the plan config: `free: concurrent_clients: 2, data: 30gib, data_period: 24h` and `pro: concurrent_clients: 1000, data: 10tib, data_period: 720h`. — [pro.yml L126-141](/Users/brien/urnetwork/config/all/pro.yml)

### Inferences
- Today's page sells the SDK and Embed. Its SEO title, its cards and its form fields (monthly active users, data budget in GiB or TiB) all fit app embedding, not team infrastructure. Expanding it around "custom private, global infrastructure deployments for teams" is a repositioning. The Embed content has to survive it, because the Embed guide (three links), the web app's Embed screen and the gift dialog all depend on /services and its endpoint.
- An infrastructure inquiry probably needs different fields, such as seats, regions, storage, mail and domains. The server re-validates the `POST /services/contact-sales` body (servicesInquiry.js L1-4), so new fields mean a server change as well as a site change. The web app's Embed form shares the same rules.
- Any restyle of Services.module.css also changes the Gamma page.
- The page's deliberate absence of SLA and response-time promises (Services.jsx L11-12) is a standing position. A services offer that promises SLAs would be a new commitment that needs the owner's decision.
- SITEMAP.md is stale on three counts: Products (1TB a month, 1 or 100 concurrent users, reply-boxes), the missing Services page, and the open-source claim. It needs rewriting with the Products, Team and Services change anyway (see DESIGN-UI.md L229, L234).

### Gaps
- I did not read the server handler for `POST /services/contact-sales` (the server repo was out of scope). Where inquiries land, who reads them and how fast they are answered are unknown.
- I did not check the other languages' translations of the `services` block, or the full contents of Services.module.css (678 lines, styling only).
- I found no analytics or inquiry counts for the page in local files.

## 2. How is the Team plan defined now, and what does the Enterprise "custom services" mention link to?

### Takeaway
The owner decided Team on 2026-11-26. It sits beside Community and Pro: $10 a month or $80 a year for the first three seats, then $10 a month or $80 a year per seat, with pooled caps of about Pro's per seat, team management, RBAC, custom sign-in and a custom domain. Seats are billed on GitHub's model, and there is one price in every region. Enterprise is to be "mentioned as custom services, and link to the services page". None of this is live yet: pro.yml has only free and pro tiers, the live Products page has only Community and UR Pro, and DESIGN.md still carries the old $100-for-5-seats Team. Nothing in any document puts services inside the Team plan. In the mockup, the Enterprise card's "See services" button links nowhere, and the mockup footer drops the Services link the live footer has.

### Cited Findings
**The owner's words (verbatim)**
- **Q-UI-19:** "The products page needs to update to include a new plan: team. The main plans are community, pro, and team. Team allocates resource caps per seat, where each seat gets basically a pro level bump to usage caps. teams also includes team management, rbac, custom auth, custom domain. Teams has a 1 seat minimum, at $10/month per seat or $80/year. The community tier includes 100mb of encrypted versioned storage, pro includes 100gb of storage. The enterprise plan should be mentioned as custom services, and link to the services page." — [DESIGN-UI.md L38](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **Q-UI-40:** "Pooled (Recommended)". — [DESIGN-UI.md L58](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **Q-UI-46:** "The app store will sell single seat team subscriptions at monthly and yearly. The user must add seats via the web with stripe billing." — [DESIGN-UI.md L64](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **UI-14:** "Create a team should upgrade to the teams plan." — [DESIGN-UI.md L83](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **UI-16,** which revises UI-15's two seats: "The app store team sub should be a 3 seat team sub. Teams pricing is the first 3 seats are charged at the cost of 1 seat. So the price of the intial sub is still $10/month or $80/year, but 3 seats are included." — [DESIGN-UI.md L85-87](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**The recorded decisions**
- **Q-UI-19, decided:** "three plans, Community, Pro and Team. Team gives each seat about Pro's caps, and adds team management, RBAC, custom sign-in and a custom domain. Its first three seats cost one seat's price, $10 a month or $80 a year together, and each further seat is $10 a month or $80 a year (UI-16). Community includes 100 MB of encrypted, versioned storage and Pro 100 GB. Enterprise is named as custom services, linking to the services page." — [DESIGN-UI.md L273](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **Q-UI-40, decided:** "Pooled: a team's caps are the per-seat caps times its seats, shared by everyone, as DESIGN's quotas are kept per network (§20.4); an admin sees the team's use against the total." — [DESIGN-UI.md L294](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **Q-UI-45:** "Yes, in place: its devices, addresses, mail and storage stay, the person becomes its first Owner and its first seat (DESIGN §7.5's team-create), and a Pro subscription's unused time is credited to the Team plan." — [DESIGN-UI.md L299](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **Q-UI-46, decided:** "the app stores sell a three-seat Team subscription, $10 a month or $80 a year (UI-16); more seats are added on the web, billed through Stripe." It records the seat model from Q-OB-9: "When a new seat is added, it has to be paid up front. The admin has to approve the new charge. This is the github or slack model. I want to adopt it." and "GitHub: seat stays until removed (Recommended)". — [DESIGN-UI.md L300](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- **Q-UI-47:** "the store bills its subscription, which covers the first three seats, and Stripe the rest; the team's seats are their sum. A person joining takes a free seat, else the inviting admin is sent to ur.io to add one. If the store subscription lapses, the Stripe seats keep the team going; if all lapse, the network drops to Pro's caps, nothing deleted." — [DESIGN-UI.md L301](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**Team's feature set (Account › Team screens)**
- The Account › Team screens cover: "every way to adopt people, devices and clients; permissions as roles (RBAC)... each role with its own IPv4 range for the bridge (Q-UI-25); and the team-only features, a custom domain and the team's own identity provider". — [DESIGN-UI.md L184](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- TM1 to TM9 cover invites, an IdP over OIDC, SCIM, auth keys, OAuth clients, an MDM profile, the audit log, billing, and the custom domain (mail addresses, published web names, sign-in routing). — [DESIGN-UI.md L188-196](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- On team visibility: "in a team, the team's admins also see agents' actions and approvals (DESIGN R-KEYS-9), and a team's visible audit reader may read sessions." — [DESIGN-UI.md L278](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**The follow-on table (changes still pending in other documents)**
- DESIGN.md §20.4 and §1.8: "The plans become Community, Pro and Team: Team's first three seats for one seat's price, $10 a month or $80 a year, and $10 a month or $80 a year for each seat after, each seat raising the caps by about Pro's; storage 100 MB on Community and 100 GB on Pro, in place of 1, 20 and 200 GiB; Enterprise as custom services. Replaces "$100/mo for 5 billable seats, then $20/seat"". — [DESIGN-UI.md L227](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- DESIGN.md §20, Team billing: the stores sell the three-seat subscription and further seats are bought on the web through Stripe, on GitHub's seat model. "Auditor, Billing admin and agents take no seat. This replaces DESIGN.md's billing by members active in the last 30 days". — [DESIGN-UI.md L228](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- SITEMAP.md and the Products page: "Products lists Community, Pro and Team, and names Enterprise as custom services linking to /services". — [DESIGN-UI.md L229](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- The Next section's step 1, "Apply the changes listed under "What this changes in other documents"", has not been done. — [DESIGN-UI.md L303-305](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**The Products mockup** ([ui-site.html L1092-1147](/Users/brien/urnetwork/sidecar/design/mocks/ui-site.html))
- Hero: "Transparent all the way down" / "Build on transparent, end-to-end encrypted infrastructure. Every plan gets the VPN, Burner, Bot and the CLI. Pro adds WireGuard profiles, a SOCKS proxy and higher caps." (L1099-1100)
- Community card: "Free", "For one person, on every device.", "The VPN, with 30 GiB of data a day", "100 MB of encrypted, versioned storage", and Burner, Bot and CLI lines (L1103-1115).
- Pro card: "$5/month or $40 a year", WireGuard and SOCKS, "10 TiB of data a month, plus 30 GiB a day", "100 GB of encrypted, versioned storage", "More mail sent a day and more public names" (L1116-1127).
- Team card: "$10/month", "for your first 3 seats, then $10 a seat · or $80 a year, 3 seats included, then $80 a seat"; "Each seat raises the team's caps by about Pro's"; "Team management: every way to add people and devices"; "Roles (RBAC), each with its own address range"; "Your own sign-in: your identity provider, directory sync"; "Your own domain for mail and web names"; button "Start a team" (L1128-1140).
- Under the cards: "On every plan, remote models, enclaves and web search draw on a compute balance you top up. Local models are free." (L1142)
- **The Enterprise card:** label "Enterprise", title "Custom services", text "Networks and users created through the API, custom features and support, for organizations that build on URnetwork." Its button is "See services", a bare `<span class="s-btn o">` with no href. (L1143)
- The mockup's notes say the plans and prices are the owner's, and that Community's and Pro's data and VPN features are the live site's (Q-OB-20). (L1147)
- **The mockup footer:** its Product column is "Products","Install",["CLI","new"],["Burner","new"],["Bot","new"],["Agents","moved"],"Buy data". It has no Services entry, and no Gamma or gift entry either, although the live footer has all three. — [ui-site.html L1590](/Users/brien/urnetwork/sidecar/design/mocks/ui-site.html); compare [Footer.jsx L64-75](/Users/brien/urnetwork/mmm/ur.io/react/src/components/Footer.jsx)
- DESIGN-UI's site plan puts only "Products, Install, CLI, Burner, Bot" in the header (L211). For the footer it says only that the Product column "gains CLI, Burner and Bot and keeps Agents" (L212); it does not say Services leaves. — [DESIGN-UI.md L211-212](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**pro.yml today**
- pro.yml is the "Product spec for plan enforcement. Read exclusively by server/pro.go, which is the single source of truth". — [pro.yml L1-6](/Users/brien/urnetwork/config/all/pro.yml)
- It defines only `free` (`concurrent_clients: 2`, `data: 30gib`, `data_period: 24h`, no SOCKS or WireGuard) and `pro` (`concurrent_clients: 1000`, `data: 10tib`, `data_period: 720h`, `price_usd: monthly: 5, yearly: 40`, regional `price_tiers`, all four proxy features). A comment adds "Both tiers get unlimited concurrent providers". — [pro.yml L126-148, L149-159, L218-224](/Users/brien/urnetwork/config/all/pro.yml)
- A search for team, seat, enterprise, storage, embed, services or custom in pro.yml finds only L154, which is about the Stripe customer's billing country. There is no Team tier, seat price or storage quota. — [pro.yml](/Users/brien/urnetwork/config/all/pro.yml)
- PROPOSAL-MARKET's Products row asks to "Add Team, with its price entry in `pro.yml` and the admin-approved seat (Q-OB-9)." — [PROPOSAL-MARKET.md L193](/Users/brien/urnetwork/mmm/outbound/PROPOSAL-MARKET.md)

**Outbound PLAN.md §7 decisions**
- **Q-OB-5:** first "No price in the emails (Recommended)". Then the owner added: "There is no regional pricing for teams. There is one price for all regions." On being asked again, the owner chose "Price in the follow-ups (Recommended)". The result: "Each role's follow-up carries "Team is $10 a month for your first three seats." The launch email carries none. The never-paid rule is set aside for Team, a plan for companies at one price everywhere." — [PLAN.md L264-267](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- **Q-OB-9:** decided as "GitHub's seat model". "When someone joins and every paid seat is taken, the join waits until an admin approves one more seat, paid up front for the rest of the billing period. A seat stays paid until an admin removes it, and removing it lowers the bill from the next renewal with no refund. The first three seats come with the subscription; Auditor, Billing admin and agents take no seat; store-billed teams pay extra seats on the web. This replaces DESIGN.md's billing by active members". — [PLAN.md L274-276](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- **Q-OB-15:** the owner chose "Add it everywhere (Recommended)". "The shared line reads "Team is $10 a month for your first three seats, and agents don't take a seat."" — [PLAN.md L291-292](/Users/brien/urnetwork/mmm/outbound/PLAN.md)

**Older Team definitions that still stand in other documents**
- DESIGN.md owner decision 27: "Team $100 a month for 5 billable seats, then $20 a seat; overage only on transfer and storage". It sits beside X16. — [DESIGN.md L157, L93](/Users/brien/urnetwork/sidecar/DESIGN.md)
- DESIGN.md also says: "pitch5 sells Solo, Team, and Assured (P5:844-846)." — [DESIGN.md L1119](/Users/brien/urnetwork/sidecar/DESIGN.md)
- DESIGN.md owner decision 515 defines active seats: "A member is active while any client under its `member_id` has an `auth_time` within 30 days." — [DESIGN.md L645](/Users/brien/urnetwork/sidecar/DESIGN.md)
- pitch5 prices recURd's Team at "$20–40 / seat*", described as "From the second person, hosted: the signed ledger, cross-harness attribution, per-client cost and policy, reach receipts, SSO/SCIM, exports." — [pitch5.html L845](/Users/brien/urnetwork/sidecar/design/pitch5.html)

### Inferences
- "Enterprise = custom services → /services" is decided (DESIGN-UI L229, L273), but /services today offers Embed, white-label and custom integrations. The link would land readers on an SDK-embedding page unless the page is expanded. The mockup's Enterprise text ("Networks and users created through the API, custom features and support") echoes SITEMAP L46, not infrastructure deployments.
- Putting services inside Team would be a new decision. Team's decided contents are pooled caps, team management, RBAC, custom sign-in and a custom domain, and no document attaches services, support tiers or deployments to Team. Pitch5's recURd tiers did offer "support for your own installs" and a self-hosted licence under Assured (see Q3).
- Three Team prices coexist: DESIGN-UI ($10 for 3 seats, then $10 a seat), DESIGN.md owner decision 27 ($100 for 5 seats, then $20) and pitch5 ($20–40 a seat). DESIGN-UI L227 says its price replaces DESIGN.md's. Pitch5 is earlier recURd positioning.
- If the mockup's footer is built as drawn, the live footer link to Services disappears. That would remove one of the page's few entry points just as Products starts sending Enterprise readers there.
- Team cannot be bought yet: it needs a pro.yml tier (or equivalent), a seat price, store SKUs and the Stripe seat flow before Products can list it truthfully.

### Gaps
- No document says what "custom services" contains, how it is priced, or whether it is a tier, an add-on or a sales conversation.
- No Team storage quota is stated. Q-UI-19 gives Community 100 MB and Pro 100 GB; Team's would be "about Pro's" per seat (pooled), but no number is written.
- I did not read DESIGN.md §20.4's full quota table, which is still on its old track, only the decision rows that cite it.

## 3. What custom "private, global infrastructure deployments" could URnetwork deliver, according to its designs?

### Takeaway
The designs support several building blocks a services offer could package:
- A worldwide member exit network.
- Embed and provider integrations through the SDK (live today, contract-based).
- The sidecar stack: end-to-end encrypted storage, a passthrough TLS edge, end-to-end mail, an IP overlay with port forwarding, Team RBAC with your own IdP and domain, and enclaves on third-party TEE providers.
- Customer-run pieces: exits, sidecars that receive mail, and indexers.

URnetwork-run infrastructure is one site in v0, with no off-site copy and no dedicated addresses. Self-hosting is deferred to a "later assured stage" with no v0 bundle. Pitch5 is the only place that names regulated, self-hosted or air-gapped offerings (the "Assured" tier). No design describes dedicated per-customer clusters, regions or white-glove deployments.

### Cited Findings
**The exit network across countries (live)**
- "The exits are thousands of member devices across a large selection of countries, searchable down to the city, not virtual IPs served from a handful of datacenters. The live counts are published at `api.bringyour.com/stats/last-90`." — [docs/OVERVIEW.md L8-10](/Users/brien/urnetwork/mmm/ur.io/docs/OVERVIEW.md)
- The Locations page says: "Explore the network in {count} countries — popular sports, apps, films, and internet content, reachable privately from anywhere." The count is filled in at runtime. — [en.json L676-678](/Users/brien/urnetwork/mmm/ur.io/react/src/i18n/en.json)
- "BringYour, Inc., a Delaware, USA company, operates the network... The ur.io apps run on one network operator; [the operator guide](https://ur.xyz/docs/operator) explains what an operator does." — [docs/FAQ.md L36-39](/Users/brien/urnetwork/mmm/ur.io/docs/FAQ.md)
- R-CTX-28 says that with a policy, "agents reach only granted ranges and model servers, and leave only through customer-run exits". — [DESIGN.md L1025](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Pitch5's risks list says "agents leave only through exits you run." — [pitch5.html L944](/Users/brien/urnetwork/sidecar/design/pitch5.html)

**SDK and integration work (live)**
- The developer docs list five ways to build: the SDK, Socket, Hosted proxies, "An app that runs a URnetwork provider and earns to one Bittensor wallet" (Integrate Provider), and "Automation over your own network" (the Operator API). — [docs/DEVELOPERS.md L3-12](/Users/brien/urnetwork/mmm/ur.io/docs/DEVELOPERS.md)
- The Embed guide: "Whitelabel URnetwork into your own apps: your backend provisions a client for each installation, your apps embed the SDK, and no root credential ships in an app." It adds that it runs on Android, iOS, macOS, Windows and Linux, and "With tunneled sockets it needs only network access: no VPN permission". Networks get "**100 active top-level clients** by default", and an Embed plan raises that. `GET /network/embed` answers `enabled`, `client_limit` and `active_client_count`. — [docs/EMBED.md L3-5, L71-77](/Users/brien/urnetwork/mmm/ur.io/docs/EMBED.md)
- Integrate Provider: "Run a URnetwork provider inside your app. Each installation provides as a client of your network and earns to one Bittensor wallet that you set once." — [docs/INTEGRATE-PROVIDER.md L3](/Users/brien/urnetwork/mmm/ur.io/docs/INTEGRATE-PROVIDER.md)
- Owner rule 1 says "The sdk exposes the sidecar components", and the design covers `sdk/sidecar.go`. — [DESIGN.md L27, L5](/Users/brien/urnetwork/sidecar/DESIGN.md)

**The sidecar stack (designed; "nothing has shipped")**
- Status: "M0-M10 build on the `sidecar` branches...; nothing has shipped." — [DESIGN.md L3](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Scope: "the horizontally scaled services that the server repo hosts for it (evs, gkm, sockets, dns with its dns edges, certs, tlsedge, smtpedge and mxedge), with the team-management and access-control additions". — [DESIGN.md L5](/Users/brien/urnetwork/sidecar/DESIGN.md)
- The CLI page plan lists six features: "storage, IP, port forwarding, the TLS edge, email and the model router". Its "Give your team the CLI" section covers "connect sign-in (OIDC, a verified domain, invitations, SCIM)... servers and CI join with an auth key or an OAuth client, with the seven roles beside it". — [DESIGN-UI.md L213](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**Storage clusters, and how they grow**
- Owner decision 20: "The file cluster is 4 hosts, each with 16 × 16 TB HDDs (about 1 PB raw)". — [DESIGN.md L150](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 116: "EC:8 on the HDD sets (about 512 TB usable) and EC:4 on the NVMe tier". — [DESIGN.md L246](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 138: "The initial metadata set is 8 × Samsung PM9A3 1.92 TB... 2 per host, 15.4 TB raw and ~7.7 TB usable at EC:4". — [DESIGN.md L268](/Users/brien/urnetwork/sidecar/DESIGN.md)
- The server hosts are "4 new hosts at one site (2 PM9A3 1.92 TB NVMe and 16 × 16 TB HDD each), the metadata cluster, more at §19.9's triggers, and the segment cluster". — [DESIGN.md L2650](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 94: "v0 has one site, one metadata and one storage cluster, "2 replicas" read as 50% parity, and no off-site copy". — [DESIGN.md L224](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 89: "v0 runs at one site: RPO 5 min for metadata and 1 h for segments, RTO 4 h, for drive and host failures only... a second site is decided from operating data." — [DESIGN.md L219](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 145: "The metadata tier grows only by adding metadata clusters, never MinIO pools: each new repo and its gkm group are placed at creation by a create-only `place/<repo_id>` on the first cluster, and all their objects stay there; a move tool is later... five to six sets in year two." — [DESIGN.md L275](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 143 sets "A two-person out-of-hours infrastructure rota on one pager service from M3, with 30-minute acknowledgment and escalation", which holds the 4 h RTO "and §19.8's SLOs... at all hours". — [DESIGN.md L273](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Owner decision 18 chose "A new self-hosted MinIO built from the final upstream source, behind `ServiceHost.Blobs`". Owner decision 69 chose "Self-hosted authoritative DNS only". R-OPS-10 reads "Self-hosted DNS on new edge hosts at the site; no dedicated addresses for user traffic or mail". — [DESIGN.md L148, L199, L20913](/Users/brien/urnetwork/sidecar/DESIGN.md)

**TLS edge and mail**
- X1: "TLS terminates in the listening sidecar. `tlsedge` routes by SNI (passthrough), never holds a user's TLS key and has no termination mode". — [DESIGN.md L15](/Users/brien/urnetwork/sidecar/DESIGN.md)
- X7: outbound mail "runs end to end from the sidecar's mail server to the destination MX through `smtpedge`". — [DESIGN.md L17](/Users/brien/urnetwork/sidecar/DESIGN.md)
- X6: inbound mail "TLS terminates on a device or a customer-run sidecar, never at a URnetwork edge". — [DESIGN.md L18](/Users/brien/urnetwork/sidecar/DESIGN.md)
- D-TLS-1: "Passthrough only: tlsedge holds no user key or user-name certificate and mounts no vault, and no URnetwork-run client (platform, proxy, hosted DeviceLocal) listens on `tls/`." — [DESIGN.md L15069](/Users/brien/urnetwork/sidecar/DESIGN.md)
- A team's custom domain carries "mail addresses, published web names, sign-in routing". — [DESIGN-UI.md L196](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**Encrypted enclaves and TEE providers**
- CO-28, the owner: "Ok I want to lock in parallel as the search provider. I want to lock in engy, saygm, and chutes as the inference providers. I want to lock in hippius, lium, and cathedral as the enclave providers". — [DESIGN-COMPUTE.md L58](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- Owner decision 737: "TEE Debian enclaves start with a sidecar and an address, reached by a bundled SSH, each with its own Harness (CO-5)." An agent's enclave is "`ur` inside a TEE VM | a full Debian with tools, a sidecar identity, an overlay address, EVS, the bundled SSH server and a Harness others attach to". — [DESIGN.md L867, L1058](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Each enclave provider has a gate, such as G-PROV-hippius ("EPC-1 to EPC-9 (§11.3)... for the indexer role, a placement URnetwork's broker does not choose") and G-PROV-cathedral. — [DESIGN-COMPUTE.md L871, L873](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- From the owner on 2026-11-26: "TEE models, encrypted enclaves and web search are all in the first release... Each gate still has to pass before that first release". — [DESIGN-UI.md L224](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- On the indexer enclave: "the indexer enclave targets Hippius (subnet 75), the closest... Closing Hippius's gaps to its gate (a measured bootstrap or attested SSH setup, documented guest reports and image measurements, published terms, placement the broker doesn't choose, the external audit) is the work that ships it". The recommended answer, not chosen, noted "No provider passes today." — [DESIGN-UI.md L263](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)
- Testing runs on "the reference provider, its self-hosted SEV-SNP host included", as M14's platform before any provider. — [DESIGN-COMPUTE.md L4230, L4295](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- Burner's indexer can also be "an always-on computer" (B10), not an enclave. — [DESIGN-UI.md L140](/Users/brien/urnetwork/sidecar/DESIGN-UI.md)

**Self-hosting, dedicated deployments and "Assured"**
- Owner decision 48: "Self-hosting comes at the later assured stage and stays possible from v0; no self-hosted bundle in v0." — [DESIGN.md L178](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Q-CTX-1: "Must the server services be self-hostable (P5:576,903)? **Decided by owner 2026-11-03...:** at the later assured stage; engines reach URnetwork-only infrastructure only through operator-core's interfaces, whose instances an `Env` creates..., and v0 ships no bundle." — [DESIGN.md L1151](/Users/brien/urnetwork/sidecar/DESIGN.md)
- operator-core is "the module of core-service interfaces and shared value types that server and sidecar import". — [DESIGN.md L5](/Users/brien/urnetwork/sidecar/DESIGN.md)
- Pitch5's "Who pays" table ([pitch5.html L844-849](/Users/brien/urnetwork/sidecar/design/pitch5.html)):
  - "Solo | Free, open source"
  - "Team | $20–40 / seat*"
  - "Assured | Annual | For regulated and defense buyers: change records, a self-hosted licence and support, compliance mappings, an air-gapped install; on your servers."
  - The footnote: "*Team dev tools run $20–50 a seat; SSO plans start near $500/mo. Agents are never metered; storage, edge traffic, and mail are. Self-hosting is free."
- Pitch5's business model: "Free and open: recURd, the admin app, relay, and entry format, and self-hosting any part, air-gapped if needed. Paid: relays, storage, and an edge we run and cannot read; names, certificates, and mail delivery; the team layer; support for your own installs." — [pitch5.html L811](/Users/brien/urnetwork/sidecar/design/pitch5.html)
- Pitch5 elsewhere:
  - "self-host any part, air-gapped if needed." (L576)
  - "Next: the team layer | ... SSO and SCIM, SIEM export, retention, the verifiable log, client packets, reach receipts, and a supported self-hosted install." (L897-898)
  - "We sell hosting we can't read, the team layer, and support." (L942)
  - "Where we start" includes "Fintech and other regulated teams" (L853-858).
  — [pitch5.html](/Users/brien/urnetwork/sidecar/design/pitch5.html)
- market2.md: "**Regulated organizations that Anthropic excludes** (zero data retention, HIPAA, customer-managed keys) are the largest prize for operator blindness, and the least forgiving of URnetwork's history. They come last." Its beachhead is "engineering teams of roughly 5 to 150 people... B2B software companies, fintech, and consultancies." — [market2.md L316, L286](/Users/brien/urnetwork/sidecar/design/market2.md)
- The market-hypothesis report: "Privacy means where the data sits | Merck and Gumloop self-host to get it... | Self-hosting's guarantee without running the server". — [Private agent network market hypothesis.md L58](</Users/brien/urnetwork/sidecar/design/reports/Private agent network market hypothesis.md>)
- DESIGN.md has no occurrence of "enterprise", "regulated", "HIPAA", "SOC 2", "sovereign", "white label" or "SLA". Searched with grep. — [DESIGN.md](/Users/brien/urnetwork/sidecar/DESIGN.md)

### Inferences
- "Global" is true today of the member exit network, which spans many countries. It is not true of URnetwork's own sidecar infrastructure, which in v0 is one site, one metadata cluster and one storage cluster, with no off-site copy and no dedicated addresses. A "global infrastructure deployment" offer that promises regional storage or edges goes beyond the design. A second site is "decided from operating data".
- Owner decision 145 places each repo on a cluster at creation (`place/<repo_id>`), and the metadata tier grows by whole clusters. That could in principle let a customer's repos sit on a designated cluster, but no design proposes customer-dedicated clusters. This is an inference, not a design.
- The parts best suited to "custom private deployments" that keep the directive are the customer-run ones. These are customer-run exits (R-CTX-28), customer-run sidecars as mail receivers (X6), always-on indexers, team servers and CI joined by auth keys (DESIGN-UI L213), and enclaves on gated third-party TEE providers. A services offer could set these up and support them, much as pitch5's "support for your own installs" describes.
- Self-hosted or air-gapped deployments of the server services are "the later assured stage", with no v0 bundle. Offering them now would contradict owner decision 48 and Q-CTX-1 unless the owner changes that.
- Embed plans and provider integrations are live, contract-based custom work. The current Services page already sells them.

### Gaps
- The operator guide lives at https://ur.xyz/docs/operator. No local copy exists (I searched /Users/brien/urnetwork to depth 4 for OPERATOR docs), so what "running an operator" involves was not read.
- There is no static country or exit count in local files; it is published live at `api.bringyour.com/stats/last-90`, which I was told not to fetch.
- I did not read DESIGN.md §19.9's growth triggers or DESIGN-DEFER.md's "next metadata cluster" entry in full.
- No document prices storage, enclaves or deployment work for a services customer.
- Before using "Assured" as a public tier name, check [ur.io/docs/COMPARE-MULLVAD.md L61-63](/Users/brien/urnetwork/mmm/ur.io/docs/COMPARE-MULLVAD.md), where the word appears in another context.

## 4. What constraints bind any such service?

### Takeaway
The owner directive makes end-to-end encryption a must. Storage, the TLS edge and mail may see only encrypted bytes and small headers, and "A server component that would see plaintext content is a design error and is never offered as an option." The only sanctioned exceptions are the abuse-report and role-mail listener and the support conversation, which the platform reads in full by the owner's choice. Even TEE providers' gateways must not see plaintext for TEE-labelled models, and no URnetwork server may see it for any model. Servers originate only denials, so URnetwork cannot add members or devices to a customer's network. Support acts on accounts only at the person's request. The public claims rules are strict: no SLA promises have been made, the protocol and server audit is still under way and its report is not public, the trust page names no firm, and customer copy does not talk about competitors.

### Cited Findings
**The directive**
- "**"End to end encryption is a must. The storage, tls edge, mail must only see encrypted bytes and some small header values like sni and spam headers."**" It goes on: "It is a requirement, not an open question, and it binds every section." — [DESIGN.md L9-13](/Users/brien/urnetwork/sidecar/DESIGN.md)
- "Connect traffic between sidecars requires e2e encryption (Required, never Opportunistic or Off)... A server component that would see plaintext content is a design error and is never offered as an option." — [DESIGN.md L19](/Users/brien/urnetwork/sidecar/DESIGN.md)

**What URnetwork's servers may see (§2.8 and the invariants)**
- §2.8's statement: "*URnetwork's servers never receive plaintext content or keys, in any mode, except `rpt.bringyour.com`'s report and role-mail listener... and the support conversation, which a person or their agents choose to send to URnetwork's support and which its feedback service and triage workspace read in full... URnetwork builds no prospective collection ([owner decision 93]) but could be compelled to record these values from now on (§21.9).*" It then lists what "An active or compelled operator keeps" (EX1 to EX8). — [DESIGN.md L1281-1292](/Users/brien/urnetwork/sidecar/DESIGN.md)
- The security invariants ([DESIGN.md L2407-2428](/Users/brien/urnetwork/sidecar/DESIGN.md)):
  - I-1: "No server receives or derives a key to evs content or names, MLS secrets, or repo or path keys".
  - I-2: client content and keys reach servers "only as ciphertext, in every mode", except the two cases above.
  - I-4: "servers store, order and deliver statements, originating only denials. An owner-bound repo gains readers only by its owner's consent (§8.5) or as [owner decision 63]'s audit member".
  - I-10: "No URnetwork-run client, the hosted ProxyDevice included..., holds Network rights".
  - I-13: logs carry opaque ids, and "client IPs are never logged or stored in the clear".
  - I-18: "Server-visible metadata changes update §2.8 before release".
  - IC-1 to IC-24 "extend and never relax" these.
- PROPOSAL-MARKET's CLI row wants the page to "Feature "no server, ours included, can add a member or a device"". — [PROPOSAL-MARKET.md L194](/Users/brien/urnetwork/mmm/outbound/PROPOSAL-MARKET.md)
- §21 says "No control acts on content (CONVENTIONS §0)." — [DESIGN.md L22746](/Users/brien/urnetwork/sidecar/DESIGN.md)

**Compute, TEEs and enclaves**
- R-PROV-3: "For a TEE label, no hop outside the TEE, the provider's own gateway included, sees plaintext; for any label, no URnetwork server does". — [DESIGN-COMPUTE.md L758](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- "DESIGN §2.8's statement holds unchanged for compute...: URnetwork's servers never receive prompts, outputs, tool calls, enclave files or enclave keys in plaintext". — [DESIGN-COMPUTE.md L425](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- IC-3: "An enclave gets keys and credentials only sealed to a key bound in evidence a device of its network verified, the bootstrap's binding included (EPC-1)". — [DESIGN-COMPUTE.md L316](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- The threat table lists a breached URnetwork broker as a risk to enclaves. — [DESIGN-COMPUTE.md L391](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- The owner's reworded TEE claim reads "Runs on the provider's TEE hardware, which proves the machine, not the code that reads your words. The provider is trusted not to attack it." Its who-can-read cell is "Only the provider". — [PLAN.md L279](/Users/brien/urnetwork/mmm/outbound/PLAN.md)

**Support access rules**
- CO-46, Q-SUP-3: "The support conversation is meant to be fully read by the platform." Q-SUP-10: "Yes, named as a subprocessor". — [DESIGN-COMPUTE.md L76](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- "The support skill (§28) adds the one place where URnetwork's servers read content". — [DESIGN-COMPUTE.md L310](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- If the feedback service is breached or compelled, the mitigations are: "the device keeps secrets, the person's private data and log content out (§28.6 to §28.8); replies untrusted to every reader, and support acting on accounts only on the person's request in the app (§28.9)". — [DESIGN-COMPUTE.md L418](/Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md)
- Q-OB-21: "I want to be clear that a human drives and reviews the support loop every day, and that a human is cc'd on every support inbox message." The required line is "A person runs and reviews our support every day and is copied on every message, and an AI agent helps sort and answer mail." The support agent uses "a hosted model (Anthropic's)", and the trust page names the model's provider. — [PLAN.md L303-307](/Users/brien/urnetwork/mmm/outbound/PLAN.md)

**What the trust and threat-model documents promise, and the claims rules**
- ur.io's threat model: "**Assurance status, stated once and applying to everything below.** There is no independent audit of the protocol, the connect engine, or the operator's server code — the layer the privacy claims rest on. Two 2025 third-party assessments cover other surfaces". — [docs/THREAT-MODEL.md L16-20, L123-127](/Users/brien/urnetwork/mmm/ur.io/docs/THREAT-MODEL.md)
- On operator blindness: "operator blindness to content holds against a passive operator and against any on-path attacker, but rests on the operator distributing provider identity keys honestly and on its not choosing your providers adversarially." — [docs/THREAT-MODEL.md L66-74](/Users/brien/urnetwork/mmm/ur.io/docs/THREAT-MODEL.md)
- On the browser and proxy paths, the client "runs on the operator's servers instead (§2.4)". — [docs/THREAT-MODEL.md L143](/Users/brien/urnetwork/mmm/ur.io/docs/THREAT-MODEL.md)
- Q-OB-22 ([PLAN.md L311-319](/Users/brien/urnetwork/mmm/outbound/PLAN.md)):
  - "An independent audit of the protocol, connect and server has been under way since September 2026. Its report isn't public yet, the directory listings wait for it, and the sidecar code is outside its scope."
  - The trust page "gives the date the current audit's report will be public, and a date for auditing the sidecar code, naming no firm."
  - "a public repo doesn't prove what runs, so the claims rest on keys held on devices".
- The audits README says the pentest firm is "named in the report; deliberately not repeated here or in the docs". — [docs/audits/README.md L33](/Users/brien/urnetwork/mmm/ur.io/docs/audits/README.md)
- Q-OB-1: the Team campaign "waits for checkable claims on the site, a plain statement in the skill and on the site of how Team relates to the exit network, and the published trust page." — [PLAN.md L256-257](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Q-OB-24: the owner chose "No: the trust page carries it". "Team stays URnetwork on ur.io whatever wave 1 shows." — [PLAN.md L324-325](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Q-OB-23: the live skill's `fetch` "runs on URnetwork's MCP server... so it reads every page an agent fetches, and its session". The decision: "Disclose; retire it at Bot launch". — [PLAN.md L320-323](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Q-OB-19: the VPN seal goes "on by default in the native apps" only from the release carrying the 2026-11-24 change. "the browser extension, the ur.io web app and the WireGuard bridge have no seal". — [PLAN.md L299-300](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- "No email mentions another company: they say why our prod[ucts are great]" (line truncated in my read). The matrix "is meant for a dated comparison page. No email names another company or argues against one." — [PLAN.md L112, L87](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- The Services page itself "makes no response-time, SLA or support-tier promise, because none has been made." — [Services.jsx L11-12](/Users/brien/urnetwork/mmm/ur.io/react/src/pages/Services.jsx)

### Inferences
- A deployment service run by URnetwork people must not have them terminate TLS, hold customer keys or run plaintext-reading components for the customer. That rules out managed decrypting gateways, hosted mail receivers on URnetwork machines, and hosted indexers outside a gated TEE.
- Admission is signed by the customer's own admin devices (I-4). Any "white-glove" onboarding has to be done by or through the customer's admins, not by URnetwork acting alone.
- Hands-on service support would sit inside the support conversation's rules. The person chooses what to send, the platform reads it in full, a person is copied on every message, and support acts on accounts only at the person's request in the app. Copy for a services offer would need the same disclosure line.
- Any services copy that cites security has to follow the trust-page rules: the audit is under way and its report is not public, no firm is named, keys are on devices, and there are no unscoped "end-to-end" or "No logs" claims. Copy also has to follow the product-forward rule with no competitor talk.
- The hosted VPN-product components (hosted proxies and the browser path, where the client runs on operator servers, and the MCP fetch until Bot launch) are disclosed exceptions on the VPN side. A "private infrastructure" services offer should not build on them.

### Gaps
- THREAT-MODEL.md L123-127 names the firm behind a 2025 Android-app assessment (not repeated here). That sits awkwardly with the trust page's "naming no firm" rule (PLAN.md L316) and with audits/README.md L33. I did not check whether this is intended.
- I did not read DESIGN-COMPUTE §28.9 to §28.15 in full; the access rule above is from the threat-table summary at L418.
- Owner decision 12 says burner mail has "no hosted or TEE receiver" ([DESIGN.md L142](/Users/brien/urnetwork/sidecar/DESIGN.md)), while DESIGN-UI B10 and Q-UI-9 add an indexer enclave. I did not read the full amendment chain (owner decision 197 and later) that reconciles them.

## 5. What do the outbound PLAN.md and PROPOSAL-MARKET.md already say about Enterprise, services or custom deployments?

### Takeaway
Almost nothing. Neither file mentions ur.io's Services page, an Enterprise offer or custom deployments. Their "enterprise" mentions are about competitors who gate SSO and RBAC behind Enterprise plans, and about the industry assumption "Agents belong to the enterprise", which the plan argues against. Both target privacy-first developers, founders and consultants who "often self-host", selling "the network and workspace they'd otherwise self-host, without running the server and without the server being able to read it". PROPOSAL-MARKET's site-change table has rows for Trust, Home, Products, CLI, Burner and Bot, and none for Services.

### Cited Findings
**Outbound PLAN.md**
- Who and what: "Privacy-first developers, founders and consultants already in URnetwork's app: desktop or CLI clients and Pro. They run things on their own machines, often self-host to keep the middle blind, and increasingly let AI agents act for them." and "**What they adopt.** The network and workspace they'd otherwise self-host, without running the server and without the server being able to read it". — [PLAN.md L30-31](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Kill signal 3: "**Self-hosters won't switch.** Ten people who run Headscale, NetBird or Pangolin wouldn't trade their setup for a verified, managed one." — [PLAN.md L56](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- On competitors' Enterprise gating: "SSO and RBAC sit mostly in Enterprise plans." Also: "Team's decided price... beats the observability vendors that keep SSO for Enterprise or sell it as a $300/mo add-on." — [PLAN.md L83, L91](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Q-OB-3 sets the Team audience as "readers likely to be at work", where "A company domain means any domain outside a list of consumer mail providers". — [PLAN.md L260-261](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Q-OB-12 sets reach as "Product, content, opt-in (Recommended)", with "No treg and no other broker", a "Tell me when Team launches" box on ur.io, and "Forward this to whoever signs off on security." in some follow-ups. — [PLAN.md L282-283](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- Q-OB-13 adopts the market hypothesis: "Team is the second sale; Burner and Bot are reasons to stay on Pro." — [PLAN.md L287-288](/Users/brien/urnetwork/mmm/outbound/PLAN.md)
- A grep of PLAN.md for enterprise, services page, /services, custom service, deployment, dedicated, on-prem, white label, embed plan, consult, regulated, assured and sovereign found no line about URnetwork offering services or Enterprise. — [PLAN.md](/Users/brien/urnetwork/mmm/outbound/PLAN.md)

**PROPOSAL-MARKET.md**
- Among "The industry's untested assumptions": "2. Agents belong to the enterprise." — [PROPOSAL-MARKET.md L29-31](/Users/brien/urnetwork/mmm/outbound/PROPOSAL-MARKET.md)
- The pains the design answers include "self-hosting is the fix, and it breaks". — [PROPOSAL-MARKET.md L38-42](/Users/brien/urnetwork/mmm/outbound/PROPOSAL-MARKET.md)
- The same who, what and self-hosters kill signal as PLAN.md appear in PROPOSAL-MARKET. — [PROPOSAL-MARKET.md L58-59, L86](/Users/brien/urnetwork/mmm/outbound/PROPOSAL-MARKET.md)
- Its site-change table ([PROPOSAL-MARKET.md L190-196](/Users/brien/urnetwork/mmm/outbound/PROPOSAL-MARKET.md)):
  - **Trust** (new, `/security`) covers "what URnetwork's servers see, by data class: edge, account, billing, support" and "a dated audit plan, naming no firm".
  - **Products:** "Add Team, with its price entry in `pro.yml` and the admin-approved seat (Q-OB-9)", plus "Say where keys live instead of an unscoped "end-to-end"".
  - **CLI:** "Add a section on what self-hosting gives you, without running the server."
  - There is no Services row.
- The related market-hypothesis report: "The buyer on every call is an enterprise, but adoption is personal." It answers "Agents belong to the enterprise" with "Sell to the person who runs agents, and let the team inherit it". — [Private agent network market hypothesis.md L45, L55](</Users/brien/urnetwork/sidecar/design/reports/Private agent network market hypothesis.md>)

### Inferences
- Linking an expanded Services page from Products, and making services part of Team, would be the first outbound or site plan to sell services. Neither campaign document covers it, so it would need its own owner decisions: its audience, whether it is priced, and whether the Team follow-ups mention it.
- The adopted hypothesis sells to individuals who self-host, offering "self-hosting's guarantee without running the server". A custom-deployment service fits as an upsell to the same readers, for example setting up customer-run exits, sidecars and indexers. That reading is consistent with pitch5's "support for your own installs".
- PROPOSAL-MARKET's CLI row ("what self-hosting gives you, without running the server") and the Trust page are natural places to link services from. They are also the places whose claims rules (Q4) any services copy must meet.

### Gaps
- I found no customer-conversation evidence, in either file or in the reports I scanned, of demand for custom deployments or Enterprise services. PLAN.md §9's conversation plan (from L337) was not read in full.
- Neither file records the owner's 27 Nov request. It may need adding to PLAN.md §7 as new Q-OB items if the campaign is to carry it.
