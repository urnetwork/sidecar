# How infrastructure, networking and security vendors package services, custom deployments and services in team plans (2024 to 27 Nov 2026)

Notes on method, for the report writer:
- Every page below was fetched on 2026-11-27 unless marked otherwise. "No date" means the page showed no publication or effective date apart from a footer copyright (usually "© 2026").
- Quotes in double quotes are verbatim. Most come from vendor pages read through a fetch tool that was told to quote verbatim. The Zscaler and Teleport PDFs were text-extracted locally, so their quotes are exact.
- Items marked "(search snippet, not fetched)" come from search-engine summaries and were not checked against the page. Treat them as lower confidence.
- Skipped or blocked: G2 returned HTTP 403, so it was skipped. One PeerSpot page returned "no reviews". Reddit and Trustpilot were not tried. TSIA research is behind a member portal. No caches, mirrors or alternate front-ends were used.
- Several vendor pages carried text aimed at AI agents (Pangolin pricing, NetBird's "Short on time?" AI links, a note in Tailscale's support doc, plugin prompts in Vercel docs). All of it was ignored.

## Q1. How do networking, zero-trust and infrastructure vendors package services (onboarding, white-glove setup, migrations, dedicated or single-tenant deployments, BYOC, custom regions, data residency, managed operations)? What is in team or business plans, what is sold separately, and at what prices?

### Takeaway
The pattern across about 25 vendors is consistent. Self-serve team and business tiers ($4–$18 per user per month, or $20–$599 per month for platforms) come with ticket or email support and self-serve docs. Hands-on help ("Solutions Engineer consultation and implementation assistance", TAMs, customer success managers, onboarding programs) sits at Enterprise or above a seat threshold. A growing middle layer is sold as separately priced, fixed-scope SKUs: support SLAs, scoped deployment packages, hour blocks, health checks and resident engineers. The most transparent price points are Zscaler's (fixed packages from $7,800 to $136,000, a $300 services credit, $2,500 per day custom work, support at 15–20% of list), ngrok's ($200 per month on-call support, $900 per month per region for dedicated IPs) and Vercel's and Render's ($100 per month for static or dedicated IPs).

### Cited Findings

**Overlay networks and zero trust (self-serve per-seat tiers)**
- Tailscale plans: Personal "$0", Standard "$8" "Per user, per month", Premium "$18", Enterprise "Custom". Enterprise only: "Solutions Engineer consultation and implementation assistance", "Custom MSA", "Pay by invoice", "Custom pricing and bundling to meet your organization's needs and budget". The page describes no onboarding program, TAM or customer-success offering. (No date.) — [Tailscale pricing](https://tailscale.com/pricing)
- Tailscale support: "All plans include Standard support: best-effort help during business hours." "Customers on Standard, Premium, and Enterprise plans can purchase SLA-backed support packages". Silver: "Contracted first-response SLAs during business hours, available self-serve." Gold: "Faster first-response SLAs and 24/7 coverage for Severity 1 issues." Platinum: "Our fastest first-response SLAs and 24/7 coverage for Severity 1 and Severity 2 issues." "Contact sales to discuss Gold or Platinum support." No prices or response times are published. — [Tailscale pricing](https://tailscale.com/pricing); [Tailscale support options](https://tailscale.com/docs/reference/support-options) (page says "Last validated Jan 5, 2026", which conflicts with the October 2026 launch date reported by PricingSaaS, below)
- Tailscale "Support Add-ons": "Support Add-ons provide separately scoped access to technical expertise for planned work, including digital enablement, Deployment Assurance, Technical Advisory, Strategic Engineering," and "These engagements are separate from support response commitments." Prices are via sales. — [Tailscale support options](https://tailscale.com/docs/reference/support-options)
- PricingSaaS reported (15 Oct 2026) that Tailscale removed "Priority (Premium) support" from Premium and Enterprise's "dedicated professional services", replacing them with Silver, Gold and Platinum packages plus "Support Add-ons". "Custom MSA & SLAs" became "Custom MSA". — [PricingSaaS, 2026-10-15](https://pricingsaas.com/news/article/tailscale-drops-premium-support-for-sla-backed-silver-gold-and-platinum-tiers)
- Tailscale's SLA document reportedly sets uptime credits from 99.99% for Platinum and 99.9% for Silver and Gold. (Search snippet, not fetched.) — [Tailscale SLA](https://tailscale.com/legal/sla)
- Tailscale "Pricing v4" (8 Apr 2026) moved business plans from active-user billing to seats and renamed Starter to Standard. A tracker headline says Standard rose from $6 to $8 per user per month. Self-serve plans gained SCIM, device posture, user-management APIs and webhooks, and can now be bought "with zero human interaction required." Existing customers keep their plan and price "for at least another 12 months." — [Tailscale blog, 2026-04-08](https://tailscale.com/blog/pricing-v4); [PricingSaaS diff title (search result)](https://pricingsaas.com/companies/tailscale/diffs/2026Q2)
- NetBird (cloud): Free "€0" (up to 5 users), Team "€6" per "user / month", Business "€12" per "user / month", Enterprise "Custom". Support by tier: Free "Community support", Team "Support via ticketing system", Business "Standard support", Enterprise "Priority Support". Enterprise also gets "Solutions Engineer consultation and implementation assistance" (the same wording as Tailscale), "Custom MSAs & SLAs", "DORA compliance", "Custom integrations". The page shows no self-hosted price. (No date.) — [NetBird pricing](https://netbird.io/pricing)
- Twingate: Teams "$5" per user per month, Business "$10", Enterprise "Custom". The comparison table also shows an unexplained "$12 user / mo". Enterprise: "Custom MSA & SLAs, Pay by invoice, DNS filtering*, Geoblocking, Exit Networks, Static IPs*" plus "Priority support" and "Additional support options*", where * marks an add-on. Support rows: "Access to Twingate technical support via ticketing system" (basic) vs "...with prioritization of responses" (priority). No onboarding or professional services are listed. Page shows "published: Nov 25, 2026". — [Twingate pricing](https://www.twingate.com/pricing)
- Pomerium: Zero Business "$9" per user per month monthly, "$7" annual. Enterprise is "Custom" with a "Self-hosted control plane" and adds "Dedicated Slack channel", "Phone support" and "Customer success manager". No onboarding, SLAs or professional services are listed. (No date.) — [Pomerium pricing](https://www.pomerium.com/pricing)
- Netmaker: Team "starts at $2 per active connection per month", Business $4, Enterprise "Custom", SaaS Professional $99 per month. Professional includes "No-Hassle Setup" and a "Free Implementation Session". Enterprise includes "Network Design and Setup", "Features Customisation", "Choice of Data Residency", "Custom MSA & SLAs" and white-label. (No date. Tier names are inconsistent across the page.) — [Netmaker pricing](https://www.netmaker.io/pricing)
- Defguard: Open Source "Always free". Business is "free up to 10 users and 1 location", then licensed by request. Enterprise is "Custom pricing" with "Free Pilot Deployment", "Enterprise Support SLA", "Offline License" and "Pay by Invoice". (No date.) — [Defguard pricing](https://defguard.net/pricing/)
- Pangolin (as summarized from the page, not verbatim): Cloud Team is $4 per user per month and Business $9 per user per month. Enterprise is custom and adds "premium relay nodes" and "priority support and SLA". The self-hosted Enterprise Edition is free for commercial use under $100K gross annual revenue. A self-serve enterprise license costs $15 per user per year and $7 per site per year, and email and priority support are paid add-ons. (Copyright 2026, no date.) — [Pangolin pricing](https://pangolin.net/pricing)
- Teleport publishes no prices: "Pay only for what you use: active users and protected resources." Its June 2026 pricing guide: "Priority Support | All products | Always included for self-hosted, hybrid and cloud deployments of the Teleport Platform." "Multi-Region High Availability Support ... Modifies Priority Support by elevating Level 1 Severity SLA from 1 hour to 30 minutes." No onboarding or professional-services SKUs are listed. — [Teleport pricing](https://goteleport.com/pricing/) (no date); [Teleport Pricing Guide, "Revision: June 16, 2026"](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_June_16_2026_5f41774f5e.pdf)

**Tunnels, edge, CDN and SASE (self-serve add-ons and enterprise success programs)**
- ngrok: Free "$0", Hobbyist "$10" monthly or "$8 / month billed as $96 / year", Pay-as-you-go "$20 base", Enterprise "Minimum spend $10,000 per year." Support add-ons on Pay-as-you-go:
  - "Dedicated On-Call (email, 8 business hour SLA, prioritized ticket handling)" at "$200 per month, or $2,400 per year"
  - "Slack or Teams add-on (requires Dedicated On-Call)" at "+$200 per month, or +$2,400 per year"
  - "24×7 Paging add-on (1 hour response SLA, 24×7; requires Dedicated On-Call)" at "+$1,000 per month, or +$12,000 per year"
  - (No date.) — [ngrok pricing](https://ngrok.com/pricing)
- Cloudflare success packages: Standard Success is "Included with Cloudflare contract" and covers "On-demand onboarding modules for a fast and efficient setup" and "Priority online support for faster resolution of issues". Premium Success is "Available as an optional upgrade to the Standard Success" with "Urgent issue response times under one hour" and "Proactive, ongoing performance and configuration optimization". "Cloudflare Success Packages are available to contracted customers." No prices are shown. (No date.) — [Cloudflare success offerings](https://www.cloudflare.com/success-offerings/)
- Cloudflare's datasheet titles suggest success tiers keyed to contract size: "Cloudflare Premium Success Offering Above 100k Datasheet 2021" and "Cloudflare Success Offering 750k". (Titles from search results only; 2021, outside the date window.) — [CF datasheet 1](https://cf-assets.www.cloudflare.com/slt3lc6tev37/6wqZRmrwGcMZpCKUPscnKp/75be42dcde058cba394de1032b0d7fe3/Cloudflare-Premium-Success-Offering-Above-100k-Datasheet-2021.pdf); [CF datasheet 2](https://www.cloudflare.com/resources/assets/slt3lc6tev37/B9OW0nUGeI0DXakgaBfge/c3cf9c0d1258827c68d8f0d72ca5b892/Cloudflare_Success_Offering_750k.pdf)
- Cloudflare "Quickstart" is described as paid, advisory-only onboarding lasting 30 to 180 days with an Onboarding Manager, in tiers Basic, Guided, Enhanced, Enterprise and Enterprise Plus. (Search snippet, not fetched; PDFs are 2021–2024.) — [Cloudflare Quickstart advisory PDF](https://cf-assets.www.cloudflare.com/slt3lc6tev37/4gZMtGhAjwK17FdBFoRNJB/4382760a2a72ef8a5e83e273b414553a/Cloudflare-Quickstart-advisory-service.pdf)
- Cloudflare migration services: "fixed-price migration offerings that ensure the right team size and fit for your Cloudflare implementation", and "Our migration services scale globally across our partner ecosystem." No prices or timelines are given. (No date; the linked datasheet filename includes "Q121".) — [Cloudflare migration services](https://www.cloudflare.com/migration-services/)
- Fastly support plans: Standard is free ("You're automatically covered by our Standard Support Plan, free of charge"). Gold offers "faster, SLA-guaranteed response times and priority routing". Enterprise is "Around-the-clock and emergency Fastly support" with phone, private Slack and "PCI/HIPAA configuration services". Severity 1 initial response: Standard next business day, Gold 2 hours, Enterprise 15 minutes. Network Services TAM and Security TAM are add-ons for Enterprise customers. The table lists "30% Discount on Fastly Professional Service Engagements"; a search snippet places it on Enterprise support. No prices are shown. (No date.) — [Fastly support plans](https://www.fastly.com/pricing/support-plans)
- Fastly onboarding packages (datasheet dated 27 Dec 2024):
  - Lite: check-ins "3, up to 6 weeks"
  - Select: check-ins "bi-weekly, up to 3 months", "Up to 10 services, single go-live support"
  - Complete: check-ins "Weekly, up to 6 months", up to 20 services, multiple go-lives
  - Custom: check-ins "As requested, up to 1 year"
  - The team "consists of a Solutions Architect and a Program Manager". Onboarding "typically takes between 4 weeks to 12 weeks, with very large and complex implementations taking up to 6 months." No prices are given. — [Fastly onboarding packages](https://www.fastly.com/resources/datasheets/onboarding-packages)

**Zscaler: the most complete public price list for productized services**
- Zscaler's 2025 services credits catalog: "PS Credits are a common currency that allows the customer to purchase credits at any time to be redeemed immediately or later (within 12 months of purchase date) toward a variety of fixed-scope service offerings". Terms: "The minimum purchase is 20 Professional Services credits". "Credits expire one calendar year from the date of purchase... Credits are non-refundable, and non-transferable". "Redemption quantity of credits must align to available service offering values. No fractional credit redemption or custom scoping is allowed". "Project implementation will be remote for all projects." (©2025; PDF metadata modified 2026-01-09.) — [Zscaler PS Credits Offerings Catalog](https://www.zscaler.com/resources/data-sheets/zscaler-professional-services-credit-offerings.pdf)
- Credit values in the same catalog:
  - Quick Start for ZIA or ZPA: "Credits = 17". Scope is "1 Professional Services Consultant and no Project Manager; based on predefined scope with no customization for quick deployment ... for up to 2500 users. Project not to exceed 6 weeks."
  - Essential Deployment Package: "Credits = 28", "not to exceed 90 days".
  - Essential Plus: "Credits = 54".
  - Advanced: "Credits = 108".
  - Enterprise: "Credits = 240", "not to exceed 180 days".
  - Staff augmentation: "Designated Remote Resource - Essential ... a block of up to 20 hours to be consumed within 30 days" for "Credits = 26". "Designated Remote Resource - Premium ... a block of up to 160 (shared) hours ... within 90 days" for "Credits = 168". "Resident Engineer 12 Mo" is "Remote - Credits = 1334" or "Onsite - Credits = 1668". "PRO360 ... up to 80 hours per month or 900 hours total during a 12 month period" for "Credits = 1200".
  - Migration: "ZIA Policy Creation/Migration ... for up to 100 Web and Firewall policies" for "Credits per Unit = 46". "Tenant (Creation/Migration) Services ... migration of a tenant from 1 Zscaler cloud to another Zscaler cloud" for "Credits per Unit = 86".
  - Source: [Zscaler PS Credits catalog](https://www.zscaler.com/resources/data-sheets/zscaler-professional-services-credit-offerings.pdf)
- Zscaler FY24 government price list (Carahsoft; PDF created 2023-07-27; list / GSA / SLP prices):
  - "ZCES-DEP-ESS Remote Deployment Services – Essential, architecture and deployment plan, training credits = 3. This services for this SKU shall be rendered by a certified deployment partner (Per Unit)" at $7,800.00 / $7,722.00 / $7,020.00
  - "ZCES-DEP-ADV Remote Deployment Services – Advanced, Lite Project plan, architecture and deployment plan, education credits = 4." at $26,000.00
  - "ZCES-DEP-ENT ... Project Plan, architecture plan, config guidance and deployments plan" at $68,000.00
  - "ZCES-DEP-ENTPLUS Remote Deployment with two 3-day onsite consulting – ... full implementation support" at $136,000.00
  - "ZCES-PRO-360 Retainer Model of 2 resources with 80 hours a month" at $360,000.00
  - "ZCES-PRO-RES-6 Resident Engineer available up to forty (40) hours a week; not to exceed ... nine hundred (900) hours during a six (6) month period" at $180,000.00. RES-12 is $360,000.00 and RES-12-ONSITE $420,000.00.
  - "ZCES-PRO-DRR Designated Zscaler Expert for a block of 160 hours to be consumed within 90 days" at $50,000.00
  - "ZCES-PRO-SVC Custom Services. Minimum 5 days, used in 5 day blocks. SOW Required. ... (Per Day + T&E)" at $2,500.00
  - "ZCES-PRO-CREDITS Professional Services Credits" at $300.00
  - "ZCES-PRO-HEALTH Remote Health Check and best practices recommendations" at $5,250.00
  - Source: [Zscaler Gov Price List FY24](https://static.carahsoft.com/concrete/files/8016/9048/7202/ZscalerGovPriceList_FY24_final.pdf)
- Zscaler support priced as a share of contract value (same FY24 list):
  - "ZCES-SUP-PREM Annual Premium Support Services (No Onsite Support Included) (% of List Price)" at 15%
  - "...with 24/7 Support & 16/5 TAM coverage" at 18%
  - "...24/5 TAM coverage (Local Time Zone & 2 International Time Zones)" at 20%
  - "ZCES-SUP-PREM-IN-CTRY Annual Premium Support Services with In-country / Local language support (% of List Price)" at 20%
  - "ZCES-SUP-DED-TAM Annual Fee for a 8/5 Dedicated TAM coverage ... Does not include Premium Support (Per Year)" at $400,000.00
  - US federal premium support ("US Citizen on US soil required") at 20%
  - Per-user premium support for the base platform: ZSC-SIP-1 lists at $17.6978 per user, its premium support SKU at $3.5396.
  - Source: [Zscaler Gov Price List FY24](https://static.carahsoft.com/concrete/files/8016/9048/7202/ZscalerGovPriceList_FY24_final.pdf)

**Developer platforms and databases (self-serve add-ons; hands-on help mostly enterprise or partner)**
- Supabase: Free, Pro "from $25/month", Team "from $599/month", Enterprise "custom pricing". Team: "Priority email support & SLAs", "SOC2 & ISO 27001", "HIPAA available as paid add-on", "Supports AWS PrivateLink", and in the support table "Email Support SLA" and "Security Questionnaire Help". Enterprise only: "Technical Account Management", "Uptime SLAs", "24×7×365 premium enterprise support", "Private Slack channel", and "Designated support," "On Boarding Support," "Designated Customer Success Team". (No date; "Pricing may change in the future.") — [Supabase pricing](https://supabase.com/pricing)
- Render: Hobby "$0/month + compute", Pro "$25/month + compute", Scale "$499/month + compute", Enterprise "Custom pricing". On Pro and Scale, "Premium support," "Private Slack channel," "Dedicated technical account team," "Support response SLAs," and "Migration assistance & architecture review" are each an "Add-on" with no price shown. All are included on Enterprise, along with "Contractual uptime SLAs". FAQ: "Render does not offer full migration professional services"; customers are referred to a partner through its expert network. (No date.) — [Render pricing](https://render.com/pricing)
- Vercel: Hobby "$0/mo.", Pro "$20/mo.", Enterprise "Custom". Enterprise: "Critical security, performance, observability, platform SLAs, and support." The page names no onboarding or professional-services offering. Pro add-ons: "SAML Single Sign-On ... $300 / month", "HIPAA BAA ... $350 / month", "Static IPs ... $100 / project / month; Starting at $0.15 per GB". (No date.) — [Vercel pricing](https://vercel.com/pricing)
- Railway: Hobby "$5", Pro "$20", Enterprise "Custom", described as "custom pricing with contractual SLAs, SSO, SCIM directory provisioning, dedicated support, and procurement options" and "Enterprise agreements add HIPAA BAAs, dedicated VMs, and support SLOs." (No date.) — [Railway pricing](https://railway.com/pricing)
- Fly.io: support comes in "Standard, Premium, and Enterprise packages", which "have access to email support", and email-support metrics are published on a public dashboard. A Custom plan offers "committed spend, volume discounts, and dedicated capacity". The pages fetched showed no support prices. (No date.) — [Fly.io support docs](https://docs.fly.io/about/support); [Fly.io pricing](https://fly.io/pricing/)

### Inferences
- Service tiers are converging on one ladder:
  1. Self-serve docs plus ticket support, bundled with the plan.
  2. Self-serve-purchasable SLA support (Tailscale Silver, ngrok Dedicated On-Call at $200 per month).
  3. Sales-quoted 24/7 support and TAMs (Tailscale Gold and Platinum, Fastly Gold and Enterprise, Cloudflare Premium Success, Zscaler at 15–20% of list).
  4. Separately scoped project work (Tailscale Support Add-ons, Zscaler credits and fixed packages, Fastly onboarding packages, Cloudflare fixed-price migrations, 1Password's catalog in Q4).
- Project services are increasingly sold as fixed-scope, time-boxed packages, not hourly. Zscaler forbids "custom scoping" on credits; Fastly caps services, ACLs and check-in cadence by tier.
- Rough price anchors, computed by me from the Zscaler FY24 list: $2,500 per day is about $312 per hour for an 8-hour day, and a 160-hour expert block at $50,000 is about $312 per hour. If credits still cost $300 (not confirmed for 2025), the 2025 Essential package (28 credits) is about $8,400 and Enterprise (240 credits) about $72,000. Those sit close to the FY24 fixed prices of $7,800 and $68,000.
- Zscaler support costs exactly 20% of the subscription per user ($3.5396 / $17.6978), and premium tiers are priced as a percentage of list. That is the clearest public "share of contract value" model in this sample.
- Two vendors with identical wording ("Solutions Engineer consultation and implementation assistance" at Tailscale and NetBird) suggest a shared category norm: implementation help is an Enterprise-tier promise, not a team-plan feature.

### Gaps
- No public dollar prices were found for: Tailscale Silver, Gold, Platinum and Support Add-ons; Cloudflare Premium Success, Quickstart and migration packages; Fastly Gold, Enterprise and onboarding packages; Render's migration add-on; Teleport; Fly.io support tiers (the pages fetched didn't show them; fly.io/support was not fetched); 1Password and Keeper services (see Q4).
- A search snippet said "First-time Fastly Network Services customers must purchase an Onboarding Package", but the onboarding datasheet I fetched did not say so. Treat it as unverified. — [Fastly Lite datasheet (search result)](https://www.fastly.com/resources/datasheets/network-services/onboarding-packages-lite)
- The Zscaler dollar list prices are FY24 (mid-2023 to mid-2024). No current-year dollar list was found, and the 2025 catalog gives credits, not dollars.
- No BYOC (customer-cloud) offering with public terms was found among the networking vendors. Self-hosted control planes (Pomerium Enterprise, Defguard, Pangolin, NetBird, Teleport self-hosted) are the closest equivalent.

## Q2. Which vendors include some service in a low-priced team plan (an onboarding call, a migration, an engineer for the first weeks), and is there evidence of the effect on conversion, retention or margin?

### Takeaway
Few infrastructure vendors include human help in a low-priced team plan, and where they do it is light: an advisory onboarding session (GoodAccess, from $7 per user per month), a "Free Implementation Session" (Netmaker), migration help from support (Proton for Business), or seat-threshold perks (NordLayer's account manager at 30+ licenses, 1Password's training and CSM at 101+ users). Hands-on implementation and dedicated engineers start at Enterprise or are sold as add-ons. I found no public, vendor-specific evidence on conversion, retention or margin effects in infrastructure. The general SaaS evidence: human touches on trials are near-universal for enterprise users and one product-led vendor saw 32% more closed deals; services carry about 30% gross margin against about 81% for subscriptions; and services below about $200K contract value tend to run at breakeven (2015 data).

### Cited Findings

**Services included in low-priced team plans**
- GoodAccess: Essential "$7" per user per month annual or "$9" monthly, and Premium "$11" or "$14", both "min. 5 users". Included on all plans: "Onboarding: Our team is ready to advise you on setting up and configuring GoodAccess." A Solution Architect ("Work with a professional Solution Architect expert in designing and deploying Zero Trust Architecture (ZTA)") is "Custom" on every plan. An account manager is Enterprise only, and Enterprise has a "minimum 50 users". (No date; G2 badges "Fall 2026".) — [GoodAccess pricing](https://www.goodaccess.com/pricing)
- Netmaker's Professional tier includes a "Free Implementation Session" and "No-Hassle Setup"; SaaS Professional is $99 per month. (No date.) — [Netmaker pricing](https://www.netmaker.io/pricing)
- NordLayer: Lite "$8", Core "$11" and Premium "$14" per user per month. "A Dedicated Account Manager is assigned with the purchase of 30 licenses or more." The technical solution architect ("Get help in planning & designing our solution's setup") is "Not included" on Lite, Core and Premium and "custom" on Custom, which needs "50 users minimum". Support: "Get first line customer support in under one minute." Page shows "As of August 3, 2026". — [NordLayer pricing](https://nordlayer.com/pricing/)
- 1Password: Teams Starter Pack "$24.95 per month when billed annually, or $299.40 per year" (shown as "$2.49 / user"), with "Get help with friendly support and onboarding resources." Business is "$8.99 / user" per month billed yearly. Seat thresholds: "Onboard confidently with personalized training for organizations with 101+ users" and "Partner with a dedicated Customer Success Manager (for organizations with 101+ users)". (No date.) — [1Password business pricing](https://1password.com/business-pricing)
- Bitwarden: Teams "$4.00 per user per month, billed annually", Enterprise "$6.00". "Dedicated onboarding, implementation, training" and a "Dedicated engagement manager who acts as an extension of your team" are Enterprise only, "for qualified customers". Teams and Enterprise both get "Priority 24/7 email support". (No date.) — [Bitwarden business pricing](https://bitwarden.com/pricing/business/)
- Proton for Business: "Priority customer support: We're here to ensure your setup runs smoothly" is listed for all business plans, and "Our dedicated Support team is also available to help your team with the migration process." Enterprise adds a "Dedicated account manager". (No date.) — [Proton for Business](https://proton.me/support/proton-for-business). Separately, Proton support pages reportedly offer phone support "for onboarding assistance only", and let organizations with 6+ members book a one-to-one call or video session. (Search snippet, not fetched.) — [Proton business start guide (search result)](https://ProtonMail.com/support/how-to-get-your-business-started-in-proton-mail)
- Supabase Team ($599 per month) includes "Security Questionnaire Help" and "Priority email support & SLAs". "On Boarding Support" is Enterprise only. (No date.) — [Supabase pricing](https://supabase.com/pricing)
- Render Pro ($25 per month) sells "Migration assistance & architecture review" only as an add-on. — [Render pricing](https://render.com/pricing)
- Keeper's onboarding tiers (summarized from the page): Free has a "2-business-day response SLA" and self-service setup. Silver adds 24/7 support, 25 phone calls a year, live expert webinars and a 1-business-day SLA. Platinum adds a 1-hour SLA, a dedicated implementation team and "curated configuration with technical assistance and oversight". Verbatim footnotes: "Dedicated implementation services are limited to the first 60 days after initial purchase." "Any custom development, restoration of data or other custom service is an additional charge." No prices are shown. (No date.) — [Keeper professional services](https://keepersecurity.com/professional-services-business.html)
- Defguard's Enterprise tier includes a "Free Pilot Deployment" (custom priced, so not a low-priced team plan). — [Defguard pricing](https://defguard.net/pricing/)

**Vendors moving human service out of plans, or to partners**
- Tailscale removed Enterprise's "dedicated professional services" and Premium's priority support (15 Oct 2026), replacing them with paid, separately scoped packages. — [PricingSaaS](https://pricingsaas.com/news/article/tailscale-drops-premium-support-for-sla-backed-silver-gold-and-platinum-tiers)
- Tailscale's April 2026 change put more features into self-serve plans "with zero human interaction required." — [Tailscale blog](https://tailscale.com/blog/pricing-v4)
- Zscaler's entry deployment SKU "shall be rendered by a certified deployment partner" (FY24). — [Zscaler Gov Price List FY24](https://static.carahsoft.com/concrete/files/8016/9048/7202/ZscalerGovPriceList_FY24_final.pdf)
- Render: "Render does not offer full migration professional services" (refers to partners). — [Render pricing](https://render.com/pricing)
- Cloudflare's migration services "scale globally across our partner ecosystem." — [Cloudflare migration](https://www.cloudflare.com/migration-services/)
- Cloudflare's Oct 2026 "enterprise for all" update moved formerly enterprise-only features (Logpush, RBAC and Terraform, network management) to self-serve: "Where our plans differ, it's in how much you can use, not what you can use." It also said: "Large or small, every customer would prefer not to have to call support." — [Cloudflare blog, 2026-10-02](https://blog.cloudflare.com/enterprise-for-all-update/)

**Evidence on conversion, retention and margin (general SaaS; none specific to infrastructure)**
- Close (CRM vendor, product-led) ran a 90-day test of calling every new trial signup, apparently in 2024. Result: "An increase in outbound calls by 598%, a boost in closed deals by 32%", and "July and August were our best months for new MRR in over 14 months." No baselines or sample sizes are given. (Published 7 Mar 2025, updated 28 May 2026.) — [Close blog](https://close.com/blog/calling-all-new-trials)
- ChartMogul and Kyle Poyar surveyed 200 B2B products in January 2026: "Among freemium products, 69% have human touchpoints when an enterprise user self-serves onto the product." "Among free trial products, 80% have human touchpoints for enterprise users." The report doesn't quantify the effect on conversion or retention. (18 Mar 2026.) — [ChartMogul SaaS Conversion Report](https://chartmogul.com/reports/saas-conversion-report-2/)
- Benchmarkit's 2025 survey, via a secondary write-up: median professional-services gross margin is 30%, against 81% for subscription revenue and 77% for total revenue. The primary report was not found. (Secondary source; date not captured.) — [Withorb summary](https://www.withorb.com/blog/saas-growth-margin-statistics)
- Tom Tunguz (31 May 2015, outside the window, cited for background) compared 13 public SaaS companies. Most run services at "between 15 to 25 points of margin". Customers pay 20%+ services margins above about $200K contract value, but below that "the data shows it to be difficult to operate a professional services team at better than breakeven." — [Tunguz](https://www.tomtunguz.com/professional_services_margins/index.md)
- TSIA's 2025 renewal research links renewals owned by customer success (not sales) to better renewal and upsell performance. The professional-services figures are behind the portal. (2025; search snippet.) — [TSIA State of Customer Growth and Renewal 2025](https://www.tsia.com/blog/state-of-customer-growth-and-renewal-2025)

### Inferences
- In this category, "service in a team plan" usually means one advisory session, onboarding guidance, priority tickets, or a perk unlocked by seat count (30+ at NordLayer, 101+ at 1Password). It rarely means hands-on deployment work. Dedicated implementation is either Enterprise-only, time-boxed (Keeper: first 60 days) or a paid add-on (Render).
- The margin data (services at about 30% gross margin; services at breakeven below about $200K contract value, per 2015 data) explains why low-price tiers keep human help minimal and push migrations to partners or fixed-scope SKUs. The October 2026 Tailscale change is a fresh example.
- Plausible but unproven: an onboarding touch raises conversion for team buyers. Close's +32% deals and the near-universal human touchpoints for enterprise users point that way, but neither isolates the effect and neither is an infrastructure vendor.

### Gaps
- No infrastructure, networking or security vendor publishes conversion, retention or margin effects for onboarding included in a team plan.
- Benchmarkit and TSIA primary figures could not be read (secondary summaries or a member portal).
- Whether GoodAccess's included onboarding is a live call or written advice is not stated.

## Q3. How do vendors sell a "custom private, global deployment" as an outcome (dedicated egress IPs, private points of presence, custom regions, sovereign or in-country deployments, compliance-ready setups)? How is it scoped, priced and delivered?

### Takeaway
Dedicated egress and private edges are productized at every price level. At small-team prices: GoodAccess $49 per month per dedicated gateway with a static IP in 35+ locations; NordLayer $40 per month per dedicated-IP server; Vercel $100 per project per month; Render $100 per month per IP set; ngrok $900 per month per region for dedicated connect IPs. At enterprise level: Cloudflare dedicated egress IPs as an Enterprise add-on, and Zscaler Source IP Anchoring, dedicated proxy ports and Private Service Edges with fixed-scope deployment packages. Multi-region resilience is sold as an SLA package (Teleport: 99.9% included vs 99.99% paid multi-region). Sovereign deployments are priced per deployment (Element) or through in-country and citizen-only support uplifts (Zscaler, 20% of list). Compliance setups are sold as add-ons or percentage uplifts: Vercel HIPAA $350 per month, Render HIPAA "20% compute premium", Supabase HIPAA add-on, Fastly "PCI/HIPAA configuration services".

### Cited Findings

**Dedicated or static egress IPs and gateways**
- GoodAccess: "+$49/mo per dedicated gateway" on Essential and Premium. "Each gateway comes with a unique static IP that dedicated to your organization." "Choose from 35+ always-available cloud gateways worldwide, or get a new one on-demand." Enterprise locations are "Custom". Branch or cloud connectors are "Add-On $29/mo". (No date.) — [GoodAccess pricing](https://www.goodaccess.com/pricing)
- NordLayer: "Server with Dedicated IP +$40/month required" (Core and Premium). Lite does not include one, and "A server with a dedicated IP is a paid add-on required for it to work." Virtual private gateways are available in "40+ countries", and Custom offers "up to 60 countries". ("As of August 3, 2026".) — [NordLayer pricing](https://nordlayer.com/pricing/)
- ngrok: "Dedicated agent connect IPs" at "$900 per month per region" and "Region-specific routing" at "$0.02 per hour (billing enabled soon)", both on Pay-as-you-go. (No date.) — [ngrok pricing](https://ngrok.com/pricing)
- Vercel Pro: "Static IPs" are "$100 / project / month; Starting at $0.15 per GB" ("Access backend services that require IP allowlisting through static egress IPs."). (No date.) — [Vercel pricing](https://vercel.com/pricing)
- Render Pro and Scale: "Dedicated IPs" at "$100 per month (for each IP set)" and "AWS private links" at "$30 per month (Includes up to 3 links)", with outbound "$0.03 per GB". Custom pricing on Enterprise. (No date.) — [Render pricing](https://render.com/pricing)
- Cloudflare Zero Trust dedicated egress IPs: "Only available as an add-on to Zero Trust Enterprise plans." "Cloudflare provisions your account with at least two dedicated egress IPs in two different cities." Each IP is "tied to a specific Cloudflare data center"; more IPs come through the account team in a scheduled service window. "Your egress traffic geolocates to the city selected in your egress policies." "IP geolocation will take at least six weeks to update across databases." "Gateway does not support dedicated egress IPs on the China Network." No price is shown. (dateModified 2026-10-12.) — [Cloudflare docs](https://developers.cloudflare.com/cloudflare-one/policies/gateway/egress-policies/dedicated-egress-ips/)
- Twingate Enterprise: "Static IPs*" and "Exit Networks" ("Route all traffic through defined egress points") are marked as add-ons. Its "Relay Performance Tier: Premium provides dedicated infrastructure for maximum performance and reliability." (Published 25 Nov 2026.) — [Twingate pricing](https://www.twingate.com/pricing)
- Zscaler (FY24 list):
  - "ZSC-SIPA-1 Annual subscription to Source IP Anchoring to selectively steer application traffic which needs source IP whitelisting for 1 to 999 users, up to 200MB Per Month / Per User" at $12.84 per user per year
  - "Z-PROXYPORT Proxy Port - Annual Management Service" at $7,490.00
  - "ZSSL-PVT-CERT SSL Interception with Private Certificate" at $12,840.00
  - "Annual subscription to 2 instances (one pair) of ZPA Private Service Edge" at $27,300.00
  - Source: [Zscaler Gov Price List FY24](https://static.carahsoft.com/concrete/files/8016/9048/7202/ZscalerGovPriceList_FY24_final.pdf)

**Private points of presence and customer-hosted edges, scoped as fixed outcomes**
- Zscaler services packages (2025 catalog):
  - "SIPA (Source IP Anchoring) ... for up to 2 pairs of App Connectors with configuration of up to 10 SIPA Applications ... project completion within four (4) weeks", "Credits per Unit = 22"
  - "ZPA Private Service Edge (PSE) ... Deployment of Private service edge instances in the customer environment ... for up to 3 pair of ZPA Private Service Edge devices (6 VM Instances ) ... within 4 weeks", "Credits per Unit = 24"
  - "ZIA Private Infra. - Hardware (PSE) ... for up to 2 pair", "Credits per Unit = 30"
  - "Branch Connectivity ... setup Tunnels for up to 20 Sites, a pair of VSE and up to 2 pair of ZIA PSEs ... within 6 weeks", "Credits per Unit = 86"
  - Source: [Zscaler PS Credits catalog](https://www.zscaler.com/resources/data-sheets/zscaler-professional-services-credit-offerings.pdf)
- Zscaler in-country connectivity packages: "China Premium Access ... sending their Internet-bound traffic to a Zscaler DC hosted on a premium Chinese ISP ... project completion within 8 weeks" for "Credits per unit = 26". "China Premium Plus Access ... combined with dedicated private connectivity ... within 12 weeks" for "Credits per unit = 56". — [Zscaler PS Credits catalog](https://www.zscaler.com/resources/data-sheets/zscaler-professional-services-credit-offerings.pdf)
- Netmaker: Team includes "Dedicated Traffic Relays"; Enterprise includes "Choice of Data Residency" (no regions named). Pangolin Enterprise includes "premium relay nodes". — [Netmaker pricing](https://www.netmaker.io/pricing); [Pangolin pricing](https://pangolin.net/pricing)
- Pomerium splits the planes: the data plane "Runs in your environment and handles traffic to protected applications". "With Pomerium Zero, the managed control plane receives configuration and operational data for cluster management." Enterprise self-hosts the control plane. (No date.) — [Pomerium pricing](https://www.pomerium.com/pricing)

**Multi-region and dedicated-network packages**
- Teleport-managed cloud is sold as service packages. "Standard High Availability is offered with Teleport-managed cloud deployments, featuring a 99.9% SLA with single-region failover and up to 50K connected resources per tenant." "Multi-Region High Availability is Teleport-managed cloud deployment offering 99.99% SLA, up to 130K connected resources, and Severity Level 1 30 minute response time." In the table, Standard HA's fee is "Included" (3 availability zones) and MRHA's fee is "Yes" (9 zones). (Rev. 16 Jun 2026.) — [Teleport Pricing Guide](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_June_16_2026_5f41774f5e.pdf)
- Teleport's cloud control-plane regions are reported as US West (Oregon), US East (N. Virginia) and Europe (Frankfurt) in v19 docs; v17 docs also listed Mumbai and Singapore. (Search snippet, not fetched.) — [Teleport cloud architecture v19](https://goteleport.com/docs/ver/19.x/reference/architecture/teleport-cloud-architecture/)
- Vercel Secure Compute: "Secure Compute is available for purchase on Enterprise plans." Each project gets a "dedicated network with static IP addresses in a region you choose", with "Your traffic stays completely separate from other customers." Failover uses an "Active Network" and a "Passive Network" in a different region. VPC peering covers AWS and site-to-site VPN covers Azure, Google Cloud and on-premises. Pricing: "Contact your Vercel account team for pricing." "Private Data Transfer is billed at $0.15/GB only for traffic that leaves the private network via the public internet." "Self-service network creation isn't available to all Enterprise teams"; otherwise the account team provisions it. (last_updated 2026-09-23.) — [Vercel Secure Compute docs](https://vercel.com/docs/connectivity/secure-compute)
- Tailscale lists "Regional routing" ("MagicRoute and regional routing" under Premium, $18 per user per month), but does not describe it as data residency. — [Tailscale pricing](https://tailscale.com/pricing)

**Data residency, sovereign and in-country deployments**
- Cloudflare Data Localization Suite:
  - "Cloudflare Regional Services helps you decide where your data should be handled"
  - Customer Metadata Boundary "ensures that logs do not leave the specified region"
  - "Keyless SSL and Geo Key Manager store private SSL keys in a user-specified region"
  - The page gives no price or plan gating. (No date.)
  - Source: [Cloudflare DLS](https://www.cloudflare.com/data-localization/)
- Element Server Suite:
  - Pro is "Priced per seat/month", "From 100" users, with "Setup, configurations and onboarding from the Element team"
  - Sovereign is "Priced per deployment": "Install and support for air-gapped, isolated and high-side instances. No internet connectivity needed." Footnote: "Maximum 1 set up per product (includes only one (1) production server and one (1) test server."
  - Support: "4 Business hours" SLA response, "Enhanced SLAs available"
  - Training: "One Time training for administrators and trainers"
  - (No date; © 2016–2026.)
  - Source: [Element pricing](https://element.io/pricing)
- Zscaler in-country and sovereign support uplifts (FY24): "Annual Premium Support Services with In-country / Local language support" at 20% of list. Federal premium support with "US Citizen on US soil required" at 20%, against 15% commercial. "Remote Health Check" at $5,250 commercial and $6,825 for the "US Citizen on US soil required" version. — [Zscaler Gov Price List FY24](https://static.carahsoft.com/concrete/files/8016/9048/7202/ZscalerGovPriceList_FY24_final.pdf)
- Tresorit: Business plan "Select the data center(s) where you want to keep data". Business Pro offers "User level data residency options". Enterprise offers "Multiple" data centers and "Bring Your Own Azure: As an enterprise Azure subscriber, you can use your own Azure data centers with Tresorit". (No date; no countries or prices rendered.) — [Tresorit business pricing](https://tresorit.com/pricing/business)
- NetBird Enterprise lists "DORA compliance". — [NetBird pricing](https://netbird.io/pricing)

**Compliance-ready setups, priced as add-ons or uplifts**
- Vercel Pro "HIPAA BAA ... $350 / month". — [Vercel pricing](https://vercel.com/pricing)
- Render "HIPAA BAA" at "20% compute premium for enabled workspaces" (Scale and Enterprise). — [Render pricing](https://render.com/pricing)
- Supabase Team: "HIPAA available as paid add-on", "SOC2 & ISO 27001". — [Supabase pricing](https://supabase.com/pricing)
- Railway: "Enterprise agreements add HIPAA BAAs, dedicated VMs, and support SLOs." — [Railway pricing](https://railway.com/pricing)
- Fastly Enterprise support includes "PCI/HIPAA configuration services". — [Fastly support plans](https://www.fastly.com/pricing/support-plans)

### Inferences
- "Private, global deployment" decomposes into SKUs that vendors already price separately:
  - a dedicated IP or gateway per location ($40–$100 per month at small-team vendors; $900 per month per region at ngrok)
  - an SLA tier for multi-region resilience (Teleport MRHA)
  - customer-hosted edges with a fixed-scope deployment package (Zscaler PSE: up to 3 pairs within 4 weeks)
  - residency controls (Cloudflare DLS, Tresorit per-data-center, Netmaker "Choice of Data Residency")
  - a support uplift for in-country or citizen-only staff (+5 points of list at Zscaler)
- The common scoping language is quantity × location × time box. Examples: "up to 2 pairs ... up to 10 SIPA Applications ... within four (4) weeks"; "at least two dedicated egress IPs in two different cities"; "Maximum 1 set up per product (... one (1) production server and one (1) test server". Outcomes are sold as bounded deliverables, not open-ended engineering.
- Lead times are part of the product. Cloudflare warns of a six-week IP geolocation lag and schedules service windows for new IPs.

### Gaps
- No public price for Cloudflare dedicated egress IPs, the Data Localization Suite, Vercel Secure Compute, Twingate static IPs, Teleport MRHA or Element Sovereign.
- No networking vendor in the sample publicly sells "custom regions" (new PoPs built for one customer) with terms. GoodAccess's "get a new one on-demand" gateway is the closest, with no stated lead time or price beyond $49 per month.

## Q4. How do privacy-first vendors run onboarding, support and deployments when they can't read customer data (customer-held keys, zero-access support, break-glass policies, shared responsibility), and what do they promise in writing?

### Takeaway
Privacy-first vendors make the "we can't see it" promise in plain written statements and design support around it. Support works on configuration, identity provider and SSO setup, training and migration tooling, not on customer content. Recovery is pushed to customer-held mechanisms: organization keys known only to admins, admin-run account recovery, emergency contacts, customer-hosted key servers, and opt-in break-glass secrets. Services contracts make the customer responsible for configuration and deliver remotely. The written cost of this is spelled out too: lose the keys or secrets and the vendor cannot recover the account.

### Cited Findings

**Zero-access promises in writing**
- Proton for Business: "Zero-access encryption means no one can access your business data, not even us." The organization password "ensures that only you (and other admins) have access to your data." (No date.) — [Proton for Business](https://proton.me/support/proton-for-business)
- Proton organization key: a key "nobody besides your organization administrators, not even Proton, has access to." "Because Proton does not have access to this key, we cannot access your data." Rotating the key "replaces your old key and is used to encrypt all your organization's data" and "No data will be lost or destroyed in this process". It is recommended if "an administrator's account is compromised or an administrator leaves your organization." (No date.) — [Proton organization key](https://proton.me/support/organization-key)
- Proton's admin-restore flow, as reported: resetting a passwordless organization's key converts non-private users to private users and emails each one. (Search snippet, not fetched.) — [Proton restore administrator](https://proton.me/support/restore-administrator/)
- Tresorit (all plans): "Tresorit can't access your files and keys." Business and Enterprise: "Admins can recover user passwords and revoke access from devices." Enterprise onboarding: "Get your team up to speed with your new Tresorit account with personalized onboarding and staff training." (No date.) — [Tresorit business pricing](https://tresorit.com/pricing/business)
- Bitwarden whitepaper: "Bitwarden team members cannot see your passwords. Bitwarden never stores and cannot access your master password or your cryptographic keys." Support also will not disable two-step login for a user. (Search snippet, not fetched.) — [Bitwarden security whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)

**Customer-held keys and break-glass recovery**
- Bitwarden Enterprise "Account recovery workflow": "Recover locked out accounts by having an administrator initiate the account recovery process." Teams and Enterprise include "Personal emergency access", which lets users "Designate other Bitwarden users as emergency contacts". (No date.) — [Bitwarden business pricing](https://bitwarden.com/pricing/business/)
- Bitwarden Key Connector:
  - "Key Connector is a self-hosted application that facilitates customer-managed encryption"
  - "your business has sole responsibility for the management of the Key Connector application"
  - Requires an Enterprise organization and "a self-hosted Bitwarden server deployed with Docker"
  - "only recommended for enterprises with a team and infrastructure"
  - "Currently, there is not a way to re-create master passwords for accounts that have removed them."
  - (© 2026; screenshot dated 2025-12-17.)
  - Source: [Bitwarden Key Connector](https://bitwarden.com/help/about-key-connector/)
- Tailscale Tailnet Lock is the clearest networking example of a customer-held trust root with opt-in break-glass:
  - "All new node keys must be signed by an existing Tailnet Lock key"
  - "you don't need to trust the Tailscale coordination server for distributing public node keys"
  - "customers must initially trust Tailscale's control plane"
  - Support can intervene only if the customer opted in by giving it a disablement secret: "Tailscale support could disable Tailnet Lock in case of an issue with how we've implemented Tailnet Lock."
  - "If you lose your disablement secrets, and you did not provide one to Tailscale support, the tailnet cannot be recovered."
  - "Tailnet Lock is available for the Personal and Enterprise plans."
  - (Last validated 2 Dec 2025.)
  - Source: [Tailscale Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
- Cloudflare Keyless SSL keeps TLS private keys on customer infrastructure, giving Cloudflare's service without "exposing their TLS private keys". It is "only available to Enterprise customers that maintain their own SSL certificate purchased from a valid Certificate Authority" and is a paid Enterprise add-on. (dateModified 2026-10-30.) — [Cloudflare Keyless SSL](https://developers.cloudflare.com/ssl/keyless-ssl/)
- Geo Key Manager stores "private SSL keys in a user-specified region". — [Cloudflare DLS](https://www.cloudflare.com/data-localization/)

**How services contracts handle the no-access constraint**
- 1Password Professional Services Catalog ("Last updated: November 2, 2026"):
  - Packages:
    - Plus Light Silver and Gold
    - Plus Silver, Gold and Platinum, each 60-day window (e.g., "Plus Silver – Enterprise Password Manager": Implementation Consultant, 4 hours of live training, TAM workshops on SSO and SCIM)
    - Premier Silver, Gold and Platinum, each 90-day window, with a Project Manager, Implementation Consultant, TAM and "Executive Concierge"
    - TAM Standard: 5-hour increments, used within 180 days, no rollover
  - "Pricing is set out in the applicable Order Form."
  - Exclusions: "On-site or in-person delivery (all sessions are remote)". "Customer retains responsibility for all system configurations." TAM excludes "Break-fix support and incident response".
  - The catalog says nothing explicit about staff access to vault data.
  - Source: [1Password PS catalog](https://1password.com/legal/professional-services-catalog)
- The 1Password Professional Services Addendum keeps services separate from the subscription and lets 1Password suspend services if the subscription is suspended. (Effective 2 Nov 2026; search snippet, not fetched.) — [1Password PS addendum](https://1password.com/legal/professional-services-addendum)
- Keeper's Platinum onboarding offers "curated configuration with technical assistance and oversight". "Any custom development, restoration of data or other custom service is an additional charge." Dedicated implementation is limited to the first 60 days. The page makes no zero-knowledge statement about onboarding. (No date.) — [Keeper professional services](https://keepersecurity.com/professional-services-business.html)
- Element delivers sovereign and air-gapped installs ("Install and support for air-gapped, isolated and high-side instances. No internet connectivity needed."), priced per deployment. That is a model where the vendor installs and supports but operates no service holding the customer's data. — [Element pricing](https://element.io/pricing)
- Pomerium's managed control plane "receives configuration and operational data", while the data plane "Runs in your environment and handles traffic". This is a written statement of what the vendor sees (configuration and operations data) and what it doesn't (application traffic). — [Pomerium pricing](https://www.pomerium.com/pricing)
- Zscaler services are "remote for all projects", and deliverables are implemented "on your Zscaler tenant", with "knowledge transfer and closeout documentation". This is a services-on-configuration model, though Zscaler is not zero-access. — [Zscaler PS Credits catalog](https://www.zscaler.com/resources/data-sheets/zscaler-professional-services-credit-offerings.pdf)

### Inferences
- The working pattern for zero-access services:
  1. Promise in one plain sentence what the vendor cannot access ("not even us").
  2. Do services on configuration, identity and SSO, rollout and training, remotely and time-boxed.
  3. Put recovery in customer-held mechanisms (organization keys, admin recovery, emergency access, self-hosted key servers) with an opt-in break-glass path (Tailscale's disablement secret).
  4. State the downside plainly ("cannot be recovered").
- Shared responsibility appears in contracts more than in marketing. Examples: "Customer retains responsibility for all system configurations" (1Password); "your business has sole responsibility for the management of the Key Connector application" (Bitwarden); "restoration of data ... is an additional charge" (Keeper).
- In 1Password's and Bitwarden's tiers, customer-held-key features and dedicated onboarding cluster at Enterprise or above 100 seats, even when the encryption model itself is on every plan.

### Gaps
- None of the privacy-first vendors' services catalogs or onboarding pages explicitly restates during-onboarding data-access rules, such as "our consultant will never ask for your master password". This was not found.
- No published support-access logs or break-glass approval policies (equivalents of hyperscaler customer-lockbox schemes) were found for Proton, Tresorit, Bitwarden or 1Password. They may exist in trust centers not fetched.
- No services prices were found for 1Password, Keeper, Tresorit, Element or Proton.

## Q5. What do buyers of these services complain about or praise (public reviews and forums), especially lock-in, cost surprises and quality of deployment help?

### Takeaway
Public complaints cluster on cost surprises (no hard spend caps, uncapped metered usage) and coercive enterprise upsells. Cloudflare's 2024 "$120K within 24h" incident is the best-known case, and Netlify's lack of a spend cap is documented in its own forum through August 2025. Vendors are now answering these publicly: Cloudflare introduced default-on budget alerts and is prototyping hard caps (October 2026), and Tailscale gave existing customers at least 12 months of grandfathered pricing (April 2026). Deployment-help reviews for enterprise SASE are mixed but mostly positive on vendor help ("vendor support included two or three resources"), with "expensive" a recurring note. Coverage is thin because major review sites block automated readers.

### Cited Findings
- Cloudflare "Enterprise upsell" incident (May 2024): a Business-plan customer (about $250 per month, per a summary) reported Cloudflare asked it to move to an "Enterprise plan costing $120,000 annually". After it declined, Cloudflare cited "domain rotation activities" and "deleted all related domains and settings". The customer concluded Cloudflare "might push organizations into their Enterprise plan" with pricing "based on what they think you'll pay." Cloudflare asked casino sites to use BYOIP because of shared-IP reputation. (InfoQ, 12 Jun 2024; the original post is titled "Cloudflare took down our website after trying to force us to pay 120k$ within 24h".) — [InfoQ](https://www.infoq.com/news/2024/06/cloudflare-service-change-impact); [Original post](https://robindev.substack.com/p/cloudflare-took-down-our-website)
- Cloudflare's own October 2026 changes: "budget alerts, which are on by default to prevent unpleasant billing surprises". Hard spending caps are being prototyped with "early availability in Q4 2026." — [Cloudflare blog, 2026-10-02](https://blog.cloudflare.com/enterprise-for-all-update/)
- Netlify spend caps. The question (2 Mar 2024): "Is there a way to set a spend limit, so that the site goes down rather than incur additional spend?" Community answer: "No, there is not". It was asked again 27 Aug 2025; the answer quoted Netlify's billing FAQ: "There is no way to set limits on metered feature usage, aside from not using a feature at all." — [Netlify forum](https://answers.netlify.com/t/is-there-or-is-there-not-a-way-to-limit-spend/113606)
- Vercel lock-in and cost unpredictability are recurring themes in third-party reviews. One says lock-in to Next-specific patterns "is real and gets harder to migrate the longer you wait". Sources conflict on whether Vercel now offers hard spend caps or only alerts and optional project pausing. (Search snippets, not fetched; low-quality secondary sources.) — [Findstack](https://findstack.com/resources/vercel-alternatives); [Cadence review](https://cadence.withremote.ai/blog/vercel-review)
- Zscaler deployment-help reviews (AWS Marketplace, Zscaler Zero Trust Exchange):
  - Positive: "The initial setup is easy and user-friendly, engineer-friendly, and environment-friendly." (user and operational engineer, 23 Jan 2025)
  - Negative: "The initial setup process was time-consuming and encountered issues, particularly with logs." (15 Jan 2024)
  - On vendor help: "For deployment, vendor support included two or three resources." and "Customer service and support have been excellent." (2 Oct 2024)
  - On cost: "The product is a bit expensive." (partner, 22 Nov 2023)
  - Source: [AWS Marketplace reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-fvp3rhgc5nvi6?page=4)
- Tailscale handled its 2026 repricing with grandfathering: existing customers keep their plan "for at least another 12 months". PricingSaaS noted it was unclear "whether Gold and Platinum pricing becomes public or stays behind a sales gate". No user reaction threads were found in search. — [Tailscale blog](https://tailscale.com/blog/pricing-v4); [PricingSaaS](https://pricingsaas.com/news/article/tailscale-drops-premium-support-for-sla-backed-silver-gold-and-platinum-tiers)
- Review sites skipped or empty: G2 returned HTTP 403 and was skipped ([G2 Twingate reviews](https://www.g2.com/products/twingate/reviews)). One PeerSpot Zscaler page showed "Sorry, no reviews are posted" ([PeerSpot](https://www.peerspot.com/products/zscaler-internet-access-reviews/page-7)).

### Inferences
- For a vendor selling "custom deployments as outcomes", the main trust risks buyers voice are:
  - an unbounded bill: metered usage with no cap
  - a forced jump from self-serve to a six-figure enterprise contract
  - lock-in through vendor-specific features or IPs. Cloudflare BYOIP is Enterprise-only per commenters; dedicated IPs tied to a vendor's data centers are hard to move.
- Fixed-scope, fixed-price packages (Zscaler, Fastly, Cloudflare migrations) and grandfathering (Tailscale) are the vendors' answers to the first two.
- Praise for deployment help centers on named people and fast response ("two or three resources", "excellent" support). Complaints center on setup time and cost, consistent with the services-scoping patterns in Q1 and Q3.

### Gaps
- Candid reviews for Tailscale, NetBird, Twingate, Teleport, ngrok, Fly.io, Render, Railway, Supabase, Proton, Tresorit and Bitwarden services were not collected. G2 blocks automated readers; Reddit and Trustpilot were not tried within the tool budget.
- No public reviews were found that specifically evaluate a paid onboarding or migration package (for example Fastly onboarding packages, Cloudflare Quickstart, or Tailscale Support Add-ons) as distinct from general support.
