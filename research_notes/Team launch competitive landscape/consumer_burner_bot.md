# Consumer privacy competitors for an E2EE burner-email + password manager, and for a private personal-agent app (state as of 26 November 2026)

Scope note: Prices marked "fetched 26 Nov 2026" were read from the vendor's own page on that date. Several items come from search-result summaries of pages I could not open. Those are labelled "(search summary)" and should be treated as less certain. Anything dated before 2026 is labelled with its date.

## 1. Email aliasing and private mail: what each service offers, what it costs, and who can read the mail

### Takeaway
Every alias or private-mail service checked receives a sender's message on its own servers, so its software handles the plaintext at least at arrival. This covers SimpleLogin/Proton Pass, addy.io, Firefox Relay, DuckDuckGo, iCloud Hide My Email, Fastmail Masked Email, Cloaked, NordPass, Proton Mail, Tuta, AliasVault and anon.li. Optional PGP-on-forward (SimpleLogin, addy.io, anon.li) and "zero-access" encryption on arrival (Proton, Tuta, AliasVault) protect stored mail but not that arrival step. iCloud Mail and Fastmail are not end-to-end encrypted at all. Free alias allowances run from 5 (Firefox Relay) and 10 (SimpleLogin, Proton Pass, addy.io random aliases) to unlimited (DuckDuckGo, and addy.io's username aliases with a 10 MB/month cap). Unlimited aliases plus custom domains cost about $12–$60 a year, or about $120 a year for Cloaked.

### Cited Findings

#### SimpleLogin (owned by Proton)
- Fetched 26 Nov 2026:
  - **Free:** 10 aliases, 1 mailbox, unlimited bandwidth, reply from alias.
  - **Premium ($36/year or $4/month):** unlimited aliases and custom domains, catch-all domains, 5 subdomains, 50 directories, unlimited mailboxes, PGP encryption, and starting new emails from an alias (reverse alias).
  - "New SimpleLogin Premium now includes Proton Pass premium features."
  - [SimpleLogin pricing](https://simplelogin.io/pricing/)
- "SimpleLogin also doesn't store the emails, they are stored in your mailbox." When a subscription ends, aliases keep working but no new ones can be made beyond the free 10. PGP is "a heavy process", which is why email size is limited. The FAQ does not say whether the server sees plaintext before encrypting. [SimpleLogin FAQ](https://simplelogin.io/faq/)
- SimpleLogin admits some sites reject its domains, with errors like "This email address is not accepted" or no error at all, and asks users to report them. [SimpleLogin docs: report blocking website](https://simplelogin.io/docs/report-blocking-website/)
- "Some email providers might mistakenly put SimpleLogin emails into Spam or Junk folders." The same page notes that forwarding services that don't preserve email authentication can cause quarantine or rejection. [SimpleLogin troubleshooting](https://simplelogin.io/docs/getting-started/troubleshooting/) (search summary)
- A GitHub discussion titled "STOP worsening free plan!" shows users pushing back on free-tier cuts (title only; not opened). [GitHub discussion #2069](https://www.github.com/simple-login/app/discussions/2069)

#### Proton Pass (aliases are SimpleLogin relays)
- Fetched 26 Nov 2026, with the Black Friday coupon BF2026NEW (no end date shown):
  - **Free:** 10 hide-my-email aliases, 2 vaults, unlimited devices, passkeys. No integrated 2FA and no custom alias domains.
  - **Pass Plus:** list price $4.99/month, now $1.99/month for the first year billed annually ($23.88), renewing at $35.88/year. Unlimited aliases, 50 vaults, integrated 2FA, unlimited custom domains and mailboxes for aliases, dark web monitoring, secure links.
  - **Pass Family:** $33.48 for the first year, then $59.88/year, up to 6 users.
  - **Proton Unlimited:** $77.88 for the first year, then $119.88/year.
  - [Proton Pass pricing](https://proton.me/pass/pricing)

#### addy.io (formerly AnonAddy)
- Fetched 26 Nov 2026:
  - **Free ($0):** unlimited standard aliases on your username, 10 random aliases, the @anonaddy.com and @anonaddy.me domains, 1 recipient, 10 MB of forwarded mail per month.
  - **Lite ($1/month billed yearly):** up to 5 recipients, 1 custom domain, reply and send, more alias domains including @addy.io.
  - **Pro ($3/month billed yearly or $4 monthly):** unlimited random aliases, all domains, up to 30 recipients, up to 20 custom domains, no monthly email limit.
  - **Duo** from $4.50/month for 2 people; **Family** (up to 5) from $7.50/month.
  - [addy.io](https://addy.io/)
- Emails "aren't stored" unless a delivery fails and the user has turned on storing failed deliveries. addy.io says it does not read emails. Optional GPG/OpenPGP encrypts forwarded mail with the user's public key. The site claims "5M+ aliases created" and about 5k GitHub stars. [addy.io](https://addy.io/)

#### Firefox Relay (Mozilla)
- "Everyone gets 5 email masks for free." Premium adds unlimited masks, a custom subdomain, anonymous replies and blocking of promotional email. Tracker removal is on every tier. When fetched on 26 Nov 2026 the Premium page showed a waitlist and no prices; this may depend on region. [Relay Premium page](https://relay.firefox.com/premium/)
- Mozilla removed prices from its "Subscribe to Relay Premium" help article because it "displayed incorrect/outdated pricing". [Mozilla support](https://support.mozilla.org/kb/subscribe-firefox-relay-premium) (search summary). An older revision listed $0.99, €0.99 or CHF 1.00 a month (date unknown, old). [Older revision](https://support.mozilla.org/en-US/kb/subscribe-firefox-relay-premium/revision/251575)
- Relay terms effective 24 Mar 2026: the Twilio service deletes text-message records after 7 days, and Relay forwards attachments only up to 10 MB. [Mozilla Relay terms](https://www.mozilla.org/about/legal/terms/firefox-relay/) (search summary)
- From the Relay FAQ ([Relay FAQ](https://relay.firefox.com/faq/)):
  - If the service is down, Mozilla "may temporarily store your emails until we are able to send them… never… longer than three days."
  - Replies work only "within 3 months of receiving the email", and adding CC/BCC exposes your real address.
  - Cancelling Premium keeps mask forwarding but loses replies.
  - Mozilla "will give you advance notice" if Relay shuts down.
  - Some sites reject subdomain addresses such as @subdomain.mozmail.com, and some accept only Gmail, Hotmail or Yahoo.
- Phone masking is in the US and Canada only. [Mozilla support](https://support.mozilla.org/en-US/kb/subscribe-firefox-relay-premium/revision/253075) (search summary)

#### DuckDuckGo Email Protection
- A free forwarding service that "removes multiple types of hidden email trackers and lets you create multiple unique private email addresses on the fly". It "works with your current email account – no need to change providers." [DuckDuckGo help](https://duckduckgo.com/duckduckgo-help-pages/email-protection/what-is-duckduckgo-email-protection)
- "DuckDuckGo will never save your emails for this service… We don't even save the headers (e.g., to/from)." This is the 20 Jul 2021 launch post, so it is old. [Spread Privacy](https://spreadprivacy.com/introducing-email-protection-beta/)
- The FAQ has entries titled "How do I reply from my Duck Addresses?" and "How many private Duck Addresses can I generate?", but their answers were not retrieved. [DuckDuckGo email FAQ](https://duckduckgo.com/email/faq)
- Privacy Guides users name duck.com as the fallback when SimpleLogin or addy.io domains are rejected. One user believed you cannot send from a Duck address, which conflicts with the FAQ's reply entry. [Privacy Guides forum](https://discuss.privacyguides.net/t/when-a-service-wont-accept-your-addy-io-or-simplelogin-email-what-do-you-use/21436)

#### iCloud+ Hide My Email (Apple)
- The latest confirmed US iCloud+ prices (June 2025) run from 50 GB at $0.99/month to 12 TB at $59.99/month. [MacRumors, 27 Jun 2025](https://www.macrumors.com/2025/06/27/icloud-plans-offer-these-perks)
- 17 Jun 2026: Apple said it would move Sign in with Apple (privaterelay.appleid.com) and Hide My Email (currently icloud.com) onto one private.icloud.com domain "later this summer". Existing addresses keep working. New aliases will no longer share icloud.com with regular accounts, so a service can block the alias domain alone. [MacRumors, 17 Jun 2026](https://www.macrumors.com/2026/06/17/new-hide-my-email-domain-makes-it-easier-to-block/)
- Oct 2026: iCloud+ custom domains rose to 5 domains with up to 10 addresses each, and the iCloud Mail alias limit rose from 3 to 9. [MacRumors, 6 Oct 2026](https://macrumors.com/2026/10/06/apple-quietly-icloud-plus-email-feature); [MacRumors, 5 Oct 2026](https://macrumors.com/2026/10/05/apple-triples-icloud-mail-alias-limit) (search summary)
- iCloud Mail, Contacts and Calendars are not end-to-end encrypted under either Standard or Advanced Data Protection, and Apple holds the keys. "iCloud Mail does not use end-to-end encryption because of the need to interoperate with the global email system." Passwords and Keychain are end-to-end encrypted. [Apple iCloud data security overview](https://support.apple.com/en-us/102651)

#### Fastmail Masked Email (with 1Password)
- Fetched 26 Nov 2026 (monthly price / annual price per month):
  - **Individual:** $6 / $5 ($60/year)
  - **Duo:** $10 / $8 ($96/year)
  - **Family (up to 6):** $14 / $11 ($132/year)
  - **Basic:** $4 / $3. **Standard:** $6 / $5. **Professional:** $10 / $9.
  - Masked Email is on every plan. Custom domains are on every plan except Basic. There is no free plan.
  - [Fastmail pricing](https://www.fastmail.com/pricing/)
- Masked Email addresses are generated in Fastmail and saved in 1Password. [Fastmail blog](https://www.fastmail.com/blog/masked-email-from-fastmail-and-1password-protects-your-identity-online/); [1Password](https://1password.com/fastmail)
- Fastmail says it does not offer end-to-end encryption in its own apps, arguing it adds little against server compromise. Staff may access data to give support the customer asked for; that access is minimised and logged. [Fastmail on email encryption](https://fastmail.com/blog/email-encryption); [Why we don't offer PGP](https://www.fastmail.com/blog/why-we-dont-offer-pgp/); [Fastmail security](https://www.fastmail.com/features/security/) (search summary)

#### Bitwarden alias integrations
- Bitwarden's username generator integrates with SimpleLogin, Addy.io, Firefox Relay, Fastmail, Forward Email and DuckDuckGo. The mobile app supports SimpleLogin, Addy.io, Forward Email and Firefox Relay. "While this option is available to all Bitwarden users, some external aliasing service may require a subscription." Proton Pass is not listed. [Bitwarden help: generator](https://bitwarden.com/help/generator/)

#### Cloaked
- 2026 prices vary by source: from $9.99/month, or $12.49/month or $119.99/year for an individual. Features are a unique @cloaked.app email and a working phone number per site, data-broker removal, and identity theft insurance (up to $1M in one review). The reviews are affiliate-supported. [Security.org](https://www.security.org/data-removal/cloaked/); [All About Cookies](https://allaboutcookies.org/cloaked-review); [Toolradar](https://toolradar.com/tools/cloaked/pricing)
- Cloaked's encryption claims (company material, search summary):
  - Data is protected with the user's master password, "which we don't have access to".
  - Each user has a separate database with its own keys, using ECC25519, Argon2 and XSalsa20-Poly1305.
  - "Sending and receiving of emails and text messages are not encrypted with your key outside of Cloaked."
  - [Cloaked security page](https://www.fresh.cloaked.com/security); [Website Planet interview](https://www.websiteplanet.com/blog/interview-cloaked/)

#### Proton Mail
- Fetched 26 Nov 2026:
  - **Free:** 1 GB, 1 address, 10 hide-my-email aliases.
  - **Mail Plus:** $4.99/month, or $29.88 for the first year with BF2026NEW (50% off), renewing at $47.88/year. 15 GB, 10 addresses, 1 custom domain. A $1 first-month offer (code MAILPLUSINTRO) is also shown.
  - **Proton Unlimited:** $77.88 for the first year, then $119.88/year. 500 GB, 15 addresses, 3 custom domains, unlimited aliases.
  - [Proton Mail pricing](https://proton.me/mail/pricing)
- Encryption ([Proton support](https://proton.me/support/proton-mail-encryption-explained)):
  - Mail between Proton users is end-to-end encrypted in transit, and the inbox is stored with zero-access encryption.
  - Mail from non-Proton senders is "encrypted with TLS in transit, then stored on our servers with zero-access encryption".
  - Mail to non-Proton recipients "isn't end-to-end encrypted by default" once delivered.
  - "Subject lines in Proton Mail messages are not end-to-end encrypted."
- Proton is moving much of its physical infrastructure out of Switzerland because of the proposed VÜPF surveillance revision. That revision would make VPN and messaging services with over 5,000 users identify customers and keep data for 6 months. Lumo moved first, to Germany, and sites in Norway are being set up. The law's status in 2026 is unclear. [TechRadar](https://www.techradar.com/vpn/vpn-privacy-security/is-proton-leaving-switzerland-legal-uncertainty-of-proposed-surveillance-laws-is-pushing-them-to-make-several-changes); [heise (2025)](https://heise.de/-10538664)

#### Tuta (formerly Tutanota)
- Fetched 26 Nov 2026 (base prices not shown on the page):
  - **Free:** 1 GB.
  - **Revolutionary:** 20 GB, 15 extra addresses, 3 custom domains.
  - **Legend:** 500 GB, 30 addresses, 10 custom domains.
  - Family add-on users cost €3 (Revolutionary) or €8 (Legend) per user per month.
  - Claims: "All data in Tuta is encrypted", zero access, contacts encrypted including contacts' email addresses, calendars and notifications encrypted, "Quantum-resistant encryption".
  - [Tuta pricing](https://tuta.com/pricing)
- An aggregator lists Revolutionary at €3.60/month and Legend at €9.60/month (unverified). [Subger](https://subger.com/en/service/tuta)
- Tuta's one-click migration tool was in closed beta as of July 2026 (search summary of a Tuta blog post; not opened). [Tuta blog](https://tuta.com/blog/tuta-vs-startmail)

#### 2026 entrants and close analogues
- **AliasVault** is the closest analogue to a password manager with a built-in per-site mailbox. Fetched 26 Nov 2026 ([AliasVault](https://www.aliasvault.com/)):
  - It is an open-source password and alias manager with its own email server.
  - Cloud and self-hosted use are both free: "The core product will always stay free." Premium and Family plans are planned after the 1.0 release, which hasn't happened yet.
  - Incoming mail is "received directly in AliasVault and immediately encrypted". The FAQ says "Everything, including usernames, passwords and even email contents, is encrypted on your device", but doesn't explain how mail arriving at the server gets encrypted.
  - Passkeys are stored in the vault and synced. There are iOS and Android apps and Chrome, Firefox, Edge, Safari and Brave extensions.
  - v0.31.0 is dated 14 Oct 2026. The project passed 3,000 GitHub stars on 13 Aug 2026. Its predecessor, SpamOK.com, has run since 2013.
- In AliasVault's cloud version you "cannot reply to or forward emails from your alias addresses". This is deliberate, with replies on the roadmap as a future paid feature. It uses AES-256-GCM and imports from 1Password, Bitwarden, Chrome, Dashlane, Firefox, KeePass/KeePassXC, Proton Pass and Strongbox. [It's FOSS](https://itsfoss.com/aliasvault)
- **anon.li** is a Liechtenstein-based, AGPL-3.0, freemium alias service plus E2EE file sharing. Its free plan includes PGP and reply. Its own pricing page shows Plus at $6.99/month, while a directory lists Pro at $2.99/month. A PeerPush listing is dated 12 May 2026. [anon.li pricing](https://anon.li/pricing?alias); [Privacy Guides](https://discuss.privacyguides.net/t/anon-li-private-email-aliases-e2ee-file-sharing-forms/37535); [AlternativeTo](https://alternativeto.net/software/anon-li/about/); [PeerPush](https://peerpush.com/p/anonli); [freetier.co](https://freetier.co/directory/products/anonli)
- **NordPass email masking** is paid only. Premium and Family allow 200 masks in total, up to 30 a day (secondary sources). [Cybernews](https://cybernews.com/password-managers/nordpass-review/nordpass-pricing/); [All About Cookies](https://allaboutcookies.org/nordpass-review)
- **Google "Shielded Email"** was reported in development in 2024 (aliases routed through Google that forward to the main inbox). I found no launch. [ExpressVPN blog](https://expressvpn.com/blog/google-shielded-email/)

#### Shutdowns in this category
- **Skiff** (E2EE mail): Notion acquired it in Feb 2024. The sunset was first 6 months, then extended to 12. Accounts were not converted, and Skiff had about 2M users (Nov 2023). Forwarding lasted until Feb 2025. [TechCrunch, 9 Feb 2024](https://techcrunch.com/2024/02/09/notion-acquires-privacy-focused-productivity-platform-skiff/); [Wikipedia](https://en.wikipedia.org/wiki/Skiff_%28email_service%29)
- **Notion Mail**, built largely by former Skiff engineers, shut down on 22 Sep 2026. Data not saved by 21 Sep was deleted. [Notion help](https://www.notion.com/help/notion-mail-inbox-is-going-away-what-to-do-next); [Crypto Briefing](https://cryptobriefing.com/notion-mail-shutdown-ai-agents/) (search summary)

### Inferences
- **Where plaintext exists:**
  - Forwarding relays (SimpleLogin, addy.io, Relay, DuckDuckGo, Hide My Email, Fastmail, Cloaked, NordPass) accept SMTP from the sender's server and process the message on their own machines.
  - Tracker stripping (DuckDuckGo, Relay, addy.io) requires parsing the message body. The forwarded copy then sits in the user's ordinary mailbox (Gmail etc.) unless PGP-on-forward is used.
  - PGP-on-forward and "zero-access" (Proton, Tuta, AliasVault) encrypt after the server has received the plaintext.
  - So "we don't store or read your mail" is a policy promise at every one of these services, not a cryptographic guarantee. Proton additionally leaves subject lines outside E2EE.
- **Nothing found offers inbound mail that no provider-run machine ever sees in plaintext.** A mail server on the user's own device behind a TLS pass-through edge (the planned Burner design) would be a genuinely different claim. It should be stated precisely, from general SMTP background:
  - The sender's own mail server still holds the plaintext.
  - SMTP STARTTLS is opportunistic, so policy is needed for senders without TLS.
  - Mail must be queued when the device is offline; Relay's 3-day buffer shows the provider-side version of this problem.
- **Price position:**
  - Unlimited aliases with custom domains cost $12–$36/year (addy.io), $36/year (SimpleLogin, which includes Pass Plus features), $35.88/year (Proton Pass Plus renewal), $60/year (Fastmail), $11.88/year and up (iCloud+), or about $120/year (Cloaked).
  - Free, unlimited per-site aliases bundled with a password manager would undercut all of them. Today only DuckDuckGo (no password manager, no custom domain) and addy.io (username aliases, 10 MB/month cap) give unlimited aliases for free.
- **Blocking risk:** shared alias domains get blocklisted. Apple's June 2026 domain split makes Hide My Email aliases blockable on their own. Unlimited per-site addresses on one shared domain will meet the same lists; per-user or user-owned domains reduce the risk.
- **Shutdown fear:** Skiff, and now Notion Mail, give a ready message that addresses keep working regardless of the vendor. This holds only if users can bring their own domain and export everything.
- **Competitive overlap:** AliasVault (free, open source, mailbox plus passkeys, no replies in cloud, pre-1.0) and Proton Pass Plus (aliases, passkeys and TOTP in one app, but aliases are plaintext relays) are the two closest incumbents to "password manager holding each site's password, code, passkey and address".

### Gaps
- Current Firefox Relay Premium price: the Premium page showed a waitlist when fetched and Mozilla removed prices from its help article. One comparison site claimed an unannounced rise to 50 free masks in late May 2026; Mozilla's own page still says 5, so the claim is unverified.
- DuckDuckGo Email Protection: the alias cap, details of replying and sending, any 2026 changes, and user counts. The FAQ answers were not retrievable.
- Apple Hide My Email: whether the private.icloud.com migration shipped, the practical alias cap (no official limit found), and 2026 iCloud+ US prices.
- Tuta base prices from Tuta itself.
- AliasVault: how arriving mail is encrypted (which key, whether the server ever holds plaintext), and post-1.0 pricing.
- Cloaked: independent verification of its encryption claims, and user counts.
- I found no independent audit claiming end-to-end encryption for inbound alias mail at any service.

## 2. Password and passkey managers: pricing, passkeys, alias integration, incidents and 2025–2026 changes

### Takeaway
2025–2026 brought price rises and fewer free tiers:
- 1Password raised Individual from $35.88 to $47.88 a year (+33%) from 27 Mar 2026.
- Bitwarden Premium roughly doubled, from $10 to $19.80 a year, in early 2026.
- Dashlane ended its free plan on 16 Sep 2025.
- Proton Pass Plus renews at $35.88 a year.

Passkeys are now standard everywhere. Google's June 2026 Credential Exchange support makes switching easier. The ETH Zurich USENIX Security '26 paper showed that "zero-knowledge" vaults fail against a malicious server: 12 attacks on Bitwarden, 7 on LastPass and 6 on Dashlane.

### Cited Findings

#### 1Password
- Individual goes from $35.88 to $47.88 a year ($3.99/month), and Families from $59.88 to $71.88 a year. The new prices apply at renewals on or after 27 Mar 2026 (announced 24 Feb 2026). [MacRumors, 24 Feb 2026](https://www.macrumors.com/2026/02/24/1password-march-price-increase/); [9to5Mac](https://9to5mac.com/2026/02/24/1password-announces-big-price-increases-coming-next-month/); [AlternativeTo: "up to 33%"](https://alternativeto.net/news/2026/2/1password-to-raise-subscription-prices-for-individual-and-family-plans-by-up-to-33-)
- In some places, such as Europe, plans are cancelled automatically if the customer does not approve the increase. 1Password says pricing had stayed "largely unchanged for many years". [TechRadar](https://www.techradar.com/pro/security/1password-is-getting-more-expensive-soon-says-change-is-despite-the-fact-pricing-has-remained-largely-unchanged-for-many-years)
- The business price rise took effect for existing customers on 30 Jul 2026, at the next renewal. [1Password business pricing FAQ](https://support.1password.com/cs/business-pricing-faq/)
- A community forum thread, "What justifies the huge subscription price increase", runs to many pages of objections. [1Password Community](https://www.1password.community/discussions/1password/re-what-justifies-the-huge-subscription-price-increase/167894)
- Alias integration is Masked Email through Fastmail, which is a paid Fastmail product. [1Password](https://1password.com/fastmail)

#### Bitwarden
- **Price:** Premium went from $10 to $19.80 a year ($1.65/month), and Families from $40 to $47.88 a year (early 2026). [AlternativeTo, Jan 2026](https://alternativeto.net/news/2026/1/bitwarden-enhances-premium-and-families-plans-with-more-security-features-and-raises-prices); [Fast Company](https://www.fastcompany.com/91483458/bitwarden-price-increase); [PricingSaaS 2026Q1](https://pricingsaas.com/companies/bitwarden/diffs/2026Q1)
- **Stated reason:** new features including vault health alerts, password coaching, 5 GB of attachments, up to 10 security keys, and a phishing blocker "coming soon".
- **Communication:** critics said existing subscribers got only 15 days' notice and that the emails didn't state the annual price. [Bitwarden community: "Hidden Price Hike"](https://community.bitwarden.com/t/hidden-price-hike/93450); [Fast Company](https://www.fastcompany.com/91483458/bitwarden-price-increase) (search summary)
- The free plan still exists: some users said they would drop to it rather than pay. [AlternativeTo, Jan 2026](https://alternativeto.net/news/2026/1/bitwarden-enhances-premium-and-families-plans-with-more-security-features-and-raises-prices) (search summary). The alias generator with third-party forwarders is "available to all Bitwarden users" (see section 1). [Bitwarden help](https://bitwarden.com/help/generator/)

#### Proton Pass
- Current prices are in section 1 (Plus $23.88 for the first year, then $35.88/year).
- History: in Jan 2024 Proton cut Pass Plus from $3.99/month to $1.99/month billed annually, citing economies of scale and owning its own servers (old). [Proton blog, 25 Jan 2024](https://proton.me/blog/proton-pass-price-change)
- A $199 "Pass Lifetime" (Pass Plus plus SimpleLogin premium) ran until 3 Dec 2024 (old). [Proton blog](https://proton.me/blog/pass-lifetime) (search summary)
- The spring/summer 2026 roadmap adds autofill improvements (iframe detection, URL matching) and a Proton Pass CLI. [Proton Pass roadmap](https://proton.me/blog/pass-roadmap-spring-summer-2026) (search summary)

#### Dashlane
- The free plan was retired on 16 Sep 2025. Free users were moved to a Premium trial and afterwards could only export their data. Dashlane no longer sells monthly plans. [Dashlane blog](https://www.dashlane.com/blog/dashlane-free-ending); [Dashlane support](https://support.dashlane.com/hc/articles/360001166969); [TechRadar](https://www.techradar.com/pro/security/dashlane-password-manager-to-remove-free-plan-in-september-what-we-know-and-what-to-do-next)
- Reported prices are about $59.88/year for Premium and $89.88/year for Family (up to 10 users). [AlternativeTo, Aug 2025](https://alternativeto.net/news/2025/8/dashlane-will-end-its-free-plan-in-september-2025-users-must-upgrade-or-switch-services)

#### Apple Passwords
- Free. Passwords and Keychain are end-to-end encrypted, with keys only on trusted devices, even under Standard Data Protection. [Apple](https://support.apple.com/en-us/102651)
- iOS 26 saves login version history (search summary; source page not identified). A 9to5Mac columnist wrote that "iOS 26 has made Apple Passwords the only password manager I need" (Feb 2026). [9to5Mac, 25 Feb 2026](https://9to5mac.com/2026/02/25/ios-26-has-made-apple-passwords-the-only-password-manager-i-need/)

#### Google Password Manager
- The June 2026 Play services release (v26.21) added import and export of passwords and passkeys using the Credential Exchange standard, on Android 8 and later. It works with 1Password, Bitwarden and Dashlane, and transfers are encrypted app to app. [Android Authority](https://www.androidauthority.com/google-password-manager-import-export-support-3673351/); [Tech-ish, 12 Sep 2026](https://tech-ish.com/2026/09/12/google-password-manager-1password-bitwarden-and-dashlane-can-now-hand-your-logins-to-each-other/)

#### NordPass
- Free, Premium and Family plans. Promotional Premium prices range from $1.29 to $1.99 a month depending on term (sources disagree). Paid plans include email masking (200 masks) and passkeys. [Security.org](https://www.security.org/password-manager/nordpass/); [Cybernews](https://cybernews.com/password-managers/nordpass-review/nordpass-pricing/)

#### KeePassXC
- KeePassXC 2.8.0 shipped in Oct/Nov 2026 (the project post is dated 4 Nov 2026). It moves to Qt 6, adds Wayland auto-type and ARM64 builds, and fixes security bugs including CVE-2026-69150. [OpenCollective](https://opencollective.com/keepassxc/updates/keepassxc-2-8-0-released); [linuxiac](https://linuxiac.com/keepassxc-2-8-password-manager-released-with-qt-6-wayland-support/); [AlternativeTo, Oct 2026](https://alternativeto.net/news/2026/10/keepassxc-2-8-arrives-with-qt6-migration-wayland-auto-type-support-and-native-arm64-builds/)
- Passkeys have been supported since 2.7.7. Version 2.7.12 changed the BE/BS flags, which may break existing passkeys. [heise](https://heise.de/-11207172)
- The Nov 2025 AI policy says AI may be used in development but there will be no AI features in the app, significant AI use must be disclosed, and every change gets human review. This prompted a trust debate. [KeePassXC blog](https://keepassxc.org/blog/2025-11-09-about-keepassxcs-code-quality-control); [linuxiac](https://linuxiac.com/keepassxc-clarifies-ai-policy-used-only-in-development-never-in-the-app/); [Privacy Guides](https://discuss.privacyguides.net/t/is-keepassxc-still-trustworthy-if-they-are-allowing-ai-generated-contributions/32651)

#### LastPass aftermath
- The UK ICO fined LastPass UK Ltd £1.2M on 11 Dec 2025 for the 2022 breach affecting up to 1.6M UK users, saying it "failed to implement sufficiently robust technical and security measures". The ICO said the attacker could not decrypt the encrypted passwords. [ICO](https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2025/12/password-manager-provider-fined); [The Register](https://www.theregister.com/2025/12/11/lastpass_ico_fine/)
- Losses attributed to the breach are disputed. Coverage cites ZachXBT's finding of $12.38M stolen on 16–17 Dec 2024, and one site headlines $438M, but there is no official attribution. [Compliance Hub](https://www.compliancehub.wiki/the-lastpass-ico-fine-a-1-2-million-penalty-that-misses-438-million-in-cryptocurrency-devastation); [The Record](https://therecord.media/uk-fines-lastpass-over-1-million-data-breach) (search summary)

#### What "zero-knowledge" covers: the ETH Zurich study (USENIX Security '26; public Feb 2026)
- Under a malicious-server threat model the researchers found 12 attacks on Bitwarden, 7 on LastPass and 6 on Dashlane. These three products have over 60M users and 23% market share combined. The attacks range from integrity violations to "complete compromise of all the vaults associated with an organisation", and most allow password recovery. [USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata); [IACR ePrint 2026/058](https://eprint.iacr.org/2026/058)
- Integrity is enforced "only… for single fields in individual items, instead of at the vault level", which enables cut-and-paste attacks. [Preprint](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf)
- Vendor responses ([TechSpot](https://www.techspot.com/news/111362-new-study-finds-security-gaps-bitwarden-lastpass-dashlane.html); [iTnews](https://www.itnews.com.au/news/researchers-find-critical-vulnerabilities-in-cloud-based-password-managers-623661)):
  - Bitwarden says all issues are resolved.
  - Dashlane says exploitation requires full server compromise.
  - LastPass disputes the severity ratings.
  - The researchers say 1Password has a related vault-sharing weakness.
  - Co-author Paterson advises choosing vendors that are transparent and externally audited.

#### Extension clickjacking (DEF CON 33, Aug 2025, old)
- All 11 password managers tested were initially vulnerable. Dashlane, Keeper, NordPass, Proton Pass and RoboForm were patched at disclosure. 1Password, iCloud Passwords, Bitwarden, Enpass, LastPass and LogMeOnce were not. Bitwarden later fixed it in 2025.8.0; 1Password and LastPass marked the reports "informative". [The Hacker News](https://thehackernews.com/2025/08/dom-based-extension-clickjacking.html); [heise](https://heise.de/-10573607)

#### Passkeys and adoption
- FIDO estimates 7 billion passkeys in use (Oct 2026), up from 5 billion (May 2026). These are FIDO's own estimates. [FIDO Alliance](https://fidoalliance.org/7-billion-passkeys-and-counting-the-next-chapter-of-passwordless-authentication/); [FIDO, World Passkey Day 2026](https://fidoalliance.org/fido-alliance-reports-accelerating-global-passkey-adoption-on-world-passkey-day-2026/)
- FIDO's State of Passkeys 2026 (Sapio Research, April 2026; 11,000 consumers in 10 countries) reports 90% awareness and 75% who have enabled a passkey on at least one account. FIDO says "more than a third of successful sign-ins now use a passkey." [FIDO](https://fidoalliance.org/the-state-of-passkeys-2026-global-consumer-and-workforce-report/); [Passkey Index 2026](https://fidoalliance.org/passkey-index-2026/); [Descope summary](https://www.descope.com/blog/post/2026-fido-report)
- 36% of American adults used a password manager (Security.org, Oct 2024, old). [Security.org](https://security.org/digital-safety/password-manager-annual-report)
- 40% store passwords in their browser's built-in manager (NordPass, 8 countries, Apr 2026). [NordPass](https://nordpass.com/blog/password-decline-research/)
- Only 16% of Americans use a unique password for every account (PasswordManager.com, Jan 2026). [PasswordManager.com](https://passwordmanager.com/2-in-3-americans-are-still-making-these-obvious-and-dangerous-password-mistakes-in-2026)

### Inferences
- **The cheap and free end is emptying.** Dashlane's free tier is gone, Bitwarden doubled its price, and 1Password rose 33%. A free password manager bundled with an existing paid VPN can target price-driven switchers. Forum evidence names Bitwarden as the default destination (section 5).
- **"Zero-knowledge" is now a contested claim.** The ETH results show server-controlled integrity and sharing flows are the weak point. A new vault should be authenticated as a whole, have a published malicious-server threat model, and be externally audited before being marketed as "zero-knowledge". Security-literate users now ask exactly this.
- **Import is getting easier.** Credential Exchange between Google, 1Password, Bitwarden and Dashlane lowers switching costs, so supporting it from day one is a growth lever. It also makes it easier for users to leave.
- **The integrated alias-plus-vault slot has few occupants.** Proton Pass Plus is the most complete incumbent, but its aliases are plaintext relays. AliasVault is the only other with an integrated mailbox, and it is pre-1.0 with no replies in the cloud version. Bitwarden and 1Password rely on third-party forwarders.

### Gaps
- Official NordPass and Dashlane 2026 prices; I did not open their pricing pages.
- Apple Passwords features in iOS 26/27 beyond version history (Credential Exchange support, Hide My Email integration) were not verified.
- 2026 user counts and revenue for 1Password, Bitwarden, Proton Pass and LastPass.
- Whether LastPass had new incidents in 2026.

## 3. Private AI assistants and personal agent apps: pricing, local vs cloud, logging and training, incidents, messaging

### Takeaway
By late 2026, hardware-attested TEE inference is the norm among privacy-first assistants: Brave Leo (E2EE plus Oblivious HTTP on NEAR AI TEEs, 15 Oct 2026), Venice (TEE and E2EE modes, Pro only), Duck.ai (Tinfoil-hosted models), Maple, Confer and Tinfoil. Apple sends its heaviest Siri requests to a custom Gemini on Google Cloud under the Private Cloud Compute brand. Proton's Lumo (10M+ users) is the notable exception: by Proton's own description, the model server decrypts each prompt.

Personal agents took off with OpenClaw (247k GitHub stars by Mar 2026), alongside exposed instances, malicious skills and plaintext secrets. IronClaw (NEAR AI) sells TEE-hosted agents for about $5–$20 a month.

### Cited Findings

#### Proton Lumo
- Lumo 2.0 launched 30 Jun 2026 with image generation and editing, user-controlled memory, encrypted Projects, custom Lumos, live web search with citations and a thinking mode. Proton says 10M+ people have adopted Lumo. [9to5Mac, 30 Jun 2026](https://9to5mac.com/2026/06/30/proton-launches-lumo-2-0-with-image-generation-memory-private-web-search-more/); [MacRumors](https://www.macrumors.com/2026/06/30/proton-lumo-version-2-new-features/)
- Prices:
  - Lumo Plus $12.99/month; Lumo Professional $14.99 per user. [TechRadar](https://techradar.com/pro/users-no-longer-need-to-choose-between-powerful-ai-capabilities-and-meaningful-privacy-protections-proton-makes-its-lumo-privacy-first-chatgpt-alternative-a-lot-more-powerful) (search summary)
  - An Oct 27, 2026 check lists Plus at €9.99/month billed annually or €12.99 billed monthly. [pasqualepillitteri.it](https://pasqualepillitteri.it/en/news/27410/what-is-lumo-ai-proton-how-it-works-price)
- Security model, per Proton's own blog ([Proton: Lumo security model](https://proton.me/blog/lumo-security-model)):
  - Full E2EE is impractical for AI, because homomorphic tests took more than a day per response.
  - Each request gets an AES key that is encrypted to the model server's PGP key; Proton's intermediate systems forward opaque payloads; "the LLM server… can read the decrypted message".
  - The server "forgets the request" after responding.
  - Chat history is zero-access encrypted with per-user keys.
  - Lumo is not TEE-attested.
- Lumo's servers moved to Germany. [TechRadar](https://www.techradar.com/vpn/vpn-privacy-security/is-proton-leaving-switzerland-legal-uncertainty-of-proposed-surveillance-laws-is-pushing-them-to-make-several-changes)

#### Venice
- Privacy modes, per the privacy page fetched 26 Nov 2026 ([Venice privacy](https://venice.ai/privacy)):
  - **Anonymous:** proxies to GPT, Claude or Gemini; "you should assume the provider is storing your content."
  - **Private (default):** runs on Venice-controlled GPUs or zero-retention partners; "no prompt or response is stored", but this rests on contracts.
  - **TEE (Pro only):** NEAR AI Cloud and Phala Network enclaves with attestation; "GPU providers cannot access your prompts."
  - **E2EE (Pro only):** prompts are decrypted only in a verified TEE, and "no one (including Venice) can see your data." Web search and memory are unavailable in this mode.
  - Chat history stays on the device.
- On 1 Jul 2026 Venice raised a $65M Series A at a $1B valuation (led by Dragonfly). It reported 3M+ active users, 1.7M API calls a day and an annualised run-rate above $70M, and is profitable. Founder Erik Voorhees: "people would use us because it was private" even when far behind ChatGPT. [TechCrunch, 1 Jul 2026](https://techcrunch.com/2026/07/01/venice-ai-becomes-a-unicorn-with-65m-series-a-as-its-privacy-first-ai-platform-takes-off/)
- A separate report puts annualised revenue at $100M (date unknown), which conflicts with TechCrunch. [Crypto Briefing](https://cryptobriefing.com/venice-ai-100m-annualized-revenue/)
- Pro is $18/month or $180/year (Oct 30, 2026 snapshot), with 100 monthly premium credits. Higher tiers are reported at $68 and $200 a month. [usecarly](https://www.usecarly.com/blog/venice-ai/); [Sacra](https://sacra.com/c/venice-ai/) (search summary)

#### Duck.ai (DuckDuckGo)
- The subscription was restructured on 18 Mar 2026 ([Spread Privacy, 18 Mar 2026](https://spreadprivacy.com/pro-subscription/)):
  - **Plus:** $9.99/month or $99.99/year. VPN, Personal Information Removal and Identity Theft Restoration, plus GPT-4o, GPT-5.2, Claude Sonnet 4.5 and Llama 4 Maverick.
  - **Pro:** $19.99/month or $199.99/year. Twice the limits, plus Claude Opus 4.6 and the highest reasoning settings.
  - **Free models:** GPT-4o mini, GPT-5 mini, GPT-OSS 120B, Llama 4 Scout, Claude Haiku 4.5, Mistral Small 3.
  - Available in the US, Canada, EU and UK.
- Privacy ([Duck.ai privacy](https://duckduckgo.com/duckduckgo-help-pages/duckai/ai-chat-privacy)):
  - IP and other personal metadata are removed before prompts reach providers.
  - By default Duck.ai "does not record or store any of your chats". Optional Sync & Backup is end-to-end encrypted.
  - Providers have zero data retention, except OpenAI and Anthropic prompt caching of up to 1 hour in memory. Anthropic may retain chats "where required by law or as necessary to combat malicious use".
  - Providers agree to "never use your Duck.ai conversations to train".
  - Tinfoil-hosted gpt-oss-120b and Gemma 4 31B run in a TEE, so "Tinfoil cannot see your prompts."
- Encrypted real-time voice chat was added on 9 Feb 2026. In Q3 2026 Duck.ai added chat search and a "2nd opinion" button that sends the same prompt to a second model. [9to5Mac](https://9to5mac.com/2026/02/09/duckduckgo-adds-free-encrypted-real-time-ai-voice-chat-to-duck-ai); [DuckDuckGo updates](https://duckduckgo.com/updates)

#### Brave Leo
- Nov 2025 (old): TEE-backed DeepSeek V3.1 on NEAR AI's Nvidia confidential computing, in Nightly. [The Register, 22 Nov 2025](https://www.theregister.com/2025/11/22/brave_leo_trusted_execution_environment/); [Brave blog](https://brave.com/blog/browser-ai-tee/)
- 15 Oct 2026: chats with GLM 5.3 Flash (beta) are end-to-end encrypted, in Nightly, Beta and Release ([Brave blog, 15 Oct 2026](https://brave.com/blog/browser-ai-e2ee/)):
  - The TEEs run on NEAR AI hardware with Intel TDX CPUs and Nvidia GPUs.
  - The Brave AI Gateway acts as an Oblivious HTTP relay that strips the user's IP.
  - Brave's open-source verifier checks deployments, but the gateway, not the browser, checks live attestation before releasing keys. Brave plans in-browser verification and a TEE key log.
  - "Brave can't read prompts." Leo needs no account and doesn't log IP addresses. History stays on the device.
  - Searches the model makes from inside the TEE use the Brave Search API's zero-data-retention option.
- Leo Premium is $14.99/month or $149.99/year. [Brave Premium](https://brave.com/premium/) (search summary)

#### Maple
- On the US App Store (26 Nov 2026) the app is "Maple Chat: Private AI" by Maple Privacy Labs, Inc. ([App Store](https://apps.apple.com/us/app/id6743764835)):
  - "Your chats are end-to-end encrypted, so Maple cannot see them." Decryption happens only inside a hardware-isolated enclave running open-source code, with proof at maple.ai/proof.
  - In-app purchases: Pro $23/month, Max $114.99/month, Max+ $229.99/month.
  - Rated 4.7 from only 36 ratings; v3.4.9 released 16 Nov.
- Another store listing names it "Maple Research", so the naming is inconsistent. [App Store (np)](https://apps.apple.com/np/app/maple-private-ai-chat-sync/id6743764835)
- Launch-era tiers were Free (10 chats/week), Starter $5.99/month and Pro $20/month (old). [Nostr post](https://nostr.at/note1temewxuyydrjakgfudwdnqp6rk9zcp5jfd8rq5axucds8ngh6c8suh4f0s); [SourceForge](https://www.sourceforge.net/software/product/Maple-AI/)

#### Confer (Moxie Marlinspike)
- Launched Dec 2025 ([TechCrunch, 18 Jan 2026](https://techcrunch.com/2026/01/18/moxie-marlinspike-has-a-privacy-conscious-alternative-to-chatgpt)):
  - **Free:** 20 messages a day and 5 active chats. **Paid:** $35/month for unlimited use, more advanced models and personalisation.
  - Messages are encrypted using WebAuthn passkeys, and inference runs in a TEE with remote attestation, on open-weight models.
  - Marlinspike calls AI chat "a form of technology that actively invites confession" and compares ad-funded chat to paying your therapist to sell you something.
- Tagline: "Private AI. Speak freely." [confer.to](https://confer.to/)

#### Tinfoil
- Fetched 26 Nov 2026: Tinfoil Chat is $20/month with projects, web search, sync, speech-to-text and document upload. API models run in "GPU-powered secure hardware enclaves" and are priced per token (for example GPT-OSS at $0.15/$0.60 and Kimi K3.1 Pro at $4/$20 per 1M tokens). Web search costs $0.05 per request. [Tinfoil pricing](https://tinfoil.sh/pricing)

#### Apple Intelligence and Siri
- Jan 2026: Apple and Google said the next Apple Foundation Models would be based on Gemini, still running on device and on Private Cloud Compute. [MacRumors, 12 Jan 2026](https://www.macrumors.com/2026/01/12/google-gemini-next-generation-siri/)
- The personalised Siri slipped from iOS 26.4. [GSMArena (Gurman)](https://m.gsmarena.com/gurman_apples_new_siri_delayed_again_will_not_be_included_in_ios_264-news-71525.php)
- WWDC, 8 Jun 2026 ([TNW, 8 Jun 2026](https://thenextweb.com/news/apple-wwdc-2026-siri-ai-gemini-ios-27)):
  - Siri AI has three tiers: on-device models, Private Cloud Compute, and a roughly 1.2T-parameter custom Gemini on Google Cloud for the heaviest reasoning.
  - Apple says processing is stateless, and its contract bars Google from training on Apple user data.
  - A standalone Siri app syncs history through iCloud. General release was expected in autumn 2026.
- Critics note Private Cloud Compute branding now covers Google Cloud running Nvidia hardware. [Gizchina](https://www.gizchina.com/apple/apples-siri-overhaul-for-ios-27-relies-on-google-gemini-google-cloud-and-nvidia-chips) (search summary)
- One outlet reports the revamped Siri is not coming to the EU. [The Decoder](https://the-decoder.com/apple-brings-a-fully-revamped-siri-built-on-googles-gemini-but-not-to-the-eu/)

#### Local-model apps
- **LM Studio** has been free for work use since July 2025. [DEV](https://dev.to/nishilbhave/lm-studio-in-2026-download-models-run-local-llms-vs-ollama-lch)
- **Jan** reported 5.3M downloads and 41k+ GitHub stars on v0.7.9 (Mar 2026). Its license is reported inconsistently. [DEV](https://dev.to/jovan_chan_9500711396d4e6/jan-ai-review-2026-13ei)
- **Msty** is a closed-source client with a free tier, for local and cloud models. **PocketPal AI** is a free, MIT-licensed iOS and Android app with an optional one-time paid tier. [PromptQuorum](https://www.promptquorum.com/power-local-llm/local-llm-app-alternatives)
- **Ollama** now sells cloud plans:
  - Free, Pro $20/month ($200/year), Max $100/month and Team $500/month (secondary page read 7 Oct 2026). Per-token cloud pricing reportedly began 31 Aug 2026. [Tapbit, 3 Sep 2026](https://www.tapbit.com/en/learn/article/ollama-cloud-pricing-privacy-open-model-business-20260903); [DEV](https://dev.to/amareswer/ollama-cloud-free-vs-pro-usage-limits-pricing-what-you-actually-get-2026-3ieo)
  - Ollama Cloud runs "primarily in the United States" and may route to Europe and Singapore. [Ollama Cloud](https://registry.ollama.ai/cloud)

#### OpenClaw and forks: history and incidents
- **Names:** Warelay (24 Nov 2025), then Clawdbot (Jan 2026), then Moltbot (27 Jan 2026, after Anthropic trademark complaints), then OpenClaw (30 Jan 2026). [Wikipedia](https://en.wikipedia.org/wiki/OpenClaw)
- **Adoption:** 247k stars and 47.7k forks by 2 Mar 2026. It runs locally, calls external LLMs (Claude, DeepSeek, GPT) and stores configuration and history locally. [Wikipedia](https://en.wikipedia.org/wiki/OpenClaw)
- **Incidents** ([Wikipedia](https://en.wikipedia.org/wiki/OpenClaw) unless noted):
  - 28 Jan 2026: Cisco found a skill doing data exfiltration and prompt injection.
  - 1 Feb 2026: an exposed Moltbook database let anyone take over agents (404 Media).
  - Feb 2026: the "MoltMatch" incident, in which an agent made a dating profile without its owner's direction.
  - Mar 2026: China restricted state agencies, state-owned firms and banks from using it.
  - Aug 2026: The Register found OpenClaw 2.0 has no network or file-system boundaries, doesn't encrypt Secret Store values at rest, and doesn't enable its sandbox by default.
  - Exposed instances: Censys counted 21,639 on 31 Jan 2026. SecurityScorecard later reported more than 135,000 in 82 countries, over 50,000 exploitable by RCE. The counts vary by method. [eSecurity Planet](https://www.esecurityplanet.com/threats/openclaws-rapid-rise-exposes-thousands-of-ai-agents-to-the-public-internet/); [Cyera](https://www.cyera.com/research/the-openclaw-security-saga-how-ai-adoption-outpaced-security-boundaries) (search summary)
  - CVE-2026-25253, a one-click RCE, was patched in v2026.1.29. [Kaspersky](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/); [Securelist](https://securelist.com/openclaw-security/120484/)
  - Malicious skills: Koi Security found 341 of 2,857 ClawHub skills malicious, 335 from one "ClawHavoc" campaign. Later counts reached 1,184 malicious across 10,700+ packages by 1 Mar 2026, and Bitdefender put about 17% of skills it analysed as malicious. VirusTotal scanning was then added. [Dark Reading](https://www.darkreading.com/cyber-risk/malicious-openclaw-skills-clawhub-threaten-ai-supply-chain); [Infosecurity](https://www.infosecurity-magazine.com/news/malicious-crypto-trading-skills/); [Tom's Hardware](https://www.tomshardware.com/tech-industry/cyber-security/malicious-moltbot-skill-targets-crypto-users-on-clawhub) (search summary)
- **Governance and releases:**
  - Creator Peter Steinberger joined OpenAI (14 Feb 2026). [Wikipedia](https://en.wikipedia.org/wiki/OpenClaw)
  - The OpenClaw Foundation launched as a US 501(c)(3) on 8 Jul 2026, MIT-licensed, backed by OpenAI, NVIDIA, Microsoft and the University of Michigan. [Techstrong.ai](https://techstrong.ai/articles/the-openclaw-foundation-reining-in-a-viral-ai-agent/); [Forkable](https://www.forkable.io/p/openclaw-is-now-a-non-profit-foundation)
  - OpenClaw 2.0 (v2026.8.1) shipped 30 Aug 2026. Microsoft ("Project Lobster") and Google ("Remy") are building their own agents. [Wikipedia](https://en.wikipedia.org/wiki/OpenClaw)
- **Forks and alternatives:**
  - **IronClaw** (NEAR AI, Rust): tools run in WASM sandboxes, credentials are stored encrypted, and each agent boots inside an encrypted TEE on NEAR AI Cloud. Launched 23 Feb 2026. [NEAR AI](https://near.ai/blog/near-ai-launches-ironclaw-confidential-gpu-marketplace-and-multimodal-confidential-inference)
  - IronClaw pricing conflicts: Toolradar (14 Nov 2026) lists Starter at $5/month with $5 credits and Basic at $20/month for 2 instances; other listings say Starter is free. [Toolradar](https://toolradar.com/tools/ironclaw)
  - **NanoClaw** is a small, container-isolated alternative. [Hashnode comparison](https://hashnode.com/posts/openclaw-ironclaw-nanoclaw-zeroclaw-a-security-architecture-comparison-2026-1/69b5607b4767f273d51c02ec); [OSS Insight](https://ossinsight.io/blog/the-openclaw-forks-wave-2026)
  - One snapshot (date unknown) shows 391,475 stars for OpenClaw against 12,640 for IronClaw. [OpenAlternative](https://openalternative.co/compare/ironclaw/vs/openclaw)

#### Logging, training and leaks at mainstream assistants (context for privacy messaging)
- **ChatGPT ads:** ads began testing on 9 Feb 2026 for US Free and Go users and by 11 Aug 2026 had launched in the UK, Mexico, Brazil, Japan and South Korea. With personalisation on, ads can draw on the current chat and on memory. OpenAI says it "never sell[s] your data to advertisers" and keeps ads away from health conversations. [OpenAI](https://openai.com/blog/testing-ads-in-chatgpt/); [OpenAI Help](https://help.openai.com/en/articles/20001047-ads-in-chatgpt)
- Privacy Guides' view was that OpenAI only promises not to share data with advertisers, not to stop collecting it. [Privacy Guides, 20 Jan 2026](https://www.privacyguides.org/news/2026/01/20/chatgpt-announces-ads-coming-for-free-and-go-users/)
- **Anthropic (28 Aug 2025, old):** consumer chats became training data by default unless users opted out. Retention went to 5 years for opted-in users and stays at 30 days for those who opt out. Critics called the interface "anti-user, anti-privacy". [TechCrunch](https://www.techcrunch.com/2025/08/28/anthropic-users-face-a-new-choice-opt-out-or-share-your-data-for-ai-training/); [The Register](https://www.theregister.com/2025/08/28/anthropic_five_year_data_retention/)
- **OpenAI preservation order (old):** the May 2025 court order to preserve deleted chats was lifted on 9 Oct 2025 for logs after 26 Sep. Logs already preserved remain. [Engadget](https://engadget.com/ai/openai-no-longer-has-to-preserve-all-of-its-chatgpt-data-with-some-exceptions-192422093.html); [Simon Willison](https://simonwillison.net/2025/Oct/23/openai-no-longer-has-to-preserve)
- **Meta AI (June 2025, old):** the app's Discover feed published chats users had "shared", including medical and legal material. [Malwarebytes](https://www.malwarebytes.com/blog/news/2025/06/your-meta-ai-chats-might-be-public-and-its-not-a-bug)
- **Chat & Ask AI (Codeway):** a misconfigured Firebase backend exposed about 300M messages from more than 25M users. It was disclosed 20 Jan 2026 and fixed within hours. [Malwarebytes, Feb 2026](https://www.malwarebytes.com/blog/news/2026/02/ai-chat-app-leak-exposes-300-million-messages-tied-to-25-million-users)

### Inferences
- **"TEE-attested remote models" no longer set a product apart on their own.** Brave, Venice, Duck.ai (through Tinfoil), Maple, Confer, Tinfoil and IronClaw all offer them. Differentiators still open:
  - Verifying attestation on the client. Brave still checks at its gateway; Maple publishes a proof page.
  - Keeping web search and memory inside the private path. Venice's E2EE mode disables both.
  - A free attested tier. Venice's TEE and E2EE are Pro only, and Confer's free tier is 20 messages a day.
  - Agent capability.
- **Price anchors for a private assistant:** $12.99 (Lumo), $14.99 (Leo), $18 (Venice), $20 (Tinfoil), $23 (Maple on iOS) and $35 (Confer) a month. DuckDuckGo's $9.99 and $19.99 bundle of VPN, AI and data removal is the closest analogue to a VPN-plus-assistant-plus-email bundle.
- **Agents:**
  - OpenClaw's adoption proves demand for personal agents. Its incidents (exposed instances, a malicious skill store, unencrypted secrets, sandbox off by default) map exactly onto what "encrypted enclaves for agents" plus vetted skills would fix.
  - IronClaw is the most direct competitor: TEE-hosted, Rust/WASM, $5–$20 a month.
- **Local models are a hygiene feature.** They are free and mature (LM Studio, Jan, PocketPal), and even Ollama has added cloud plans. The UX of falling back from local to an attested remote model, especially on mobile, is where differentiation remains.
- **Lumo is exposed.** It has the largest user base among the privacy brands, but plaintext is visible to Proton's model servers at inference, and Proton's Nov 2026 CEO controversy (section 5) adds to that. Messaging that the provider provably cannot read prompts aims directly at Proton's users.

### Gaps
- I found nothing on the "Enclave" local-LLM app.
- Msty's pricing.
- Confer's current (Nov 2026) price, apps and adoption.
- Maple's web prices; App Store prices may include Apple's fee.
- Venice's paid-subscriber count; revenue reports conflict ($70M+ against $100M).
- Whether Siri AI actually shipped in iOS 27 in autumn 2026, and in which regions.
- Lumo Plus annual USD price.
- Whether Brave's E2EE GLM model is free or Leo Premium only.
- OpenClaw news after Aug 2026, and active-user counts. The "4.5M new Claws a week" claim comes from a low-quality source. [senx.ai](https://senx.ai/openclaw-news/2026-07-11-openclaw-news)

## 4. Private search used by assistants: Brave Search, Kagi, DuckDuckGo

### Takeaway
Brave Search grew to 2.7B queries a month (Oct 2026). Its API dropped the free tier in Feb 2026 for card-backed $5 monthly credits and about $4–$5 per 1k queries, with a zero-data-retention option. Kagi's Privacy Pass gives searches the provider cannot link to an account, but only on Professional and higher paid plans. DuckDuckGo strips IPs and proxies requests. "The search provider never learns who asked" exists today in Kagi Privacy Pass and in Brave Leo's OHTTP and zero-retention path, but not as a free default inside an E2EE assistant.

### Cited Findings
- **Brave Search API:**
  - Feb 2026: a new LLM-context endpoint and new pricing. [AlternativeTo, Feb 2026](https://alternativeto.net/news/2026/2/brave-updates-its-search-api-with-a-new-llm-context-endpoint-for-ai-and-new-pricing)
  - The free 2,000 queries a month was dropped around 12 Feb 2026 in favour of $5 prepaid metered credits. A card is required and overages have no spending cap. [Implicator](https://www.implicator.ai/brave-drops-free-search-api-tier-puts-all-developers-on-metered-billing/)
  - Aggregators list $4–$5 per 1k queries (Sept 2026), on plans renamed "Search" and "Answers". [CostBench](https://costbench.com/software/ai-search-apis/brave-search-api/price-history/) (aggregator)
- **Brave Search scale:** 2.7B queries in Oct 2026, up 56% year on year (press release 10 Nov 2026). Brave was added to Chrome's default engine list around July 2026, at 2.46B queries a month. [PPC Land](https://ppc.land/brave-search-queries-gain-56-in-a-year-to-2-7bn-a-month/); [PPC Land](https://ppc.land/brave-search-gains-a-spot-on-chromes-engine-list-at-2-46-billion-queries/)
- **Brave browser scale:** 130.77M monthly active users in Oct 2026, per CEO Brendan Eich. [PiunikaWeb, 3 Nov 2026](https://piunikaweb.com/2026/11/03/brave-130-million-monthly-active-users/)
- **Leo's search path:** searches made from inside Leo's TEE use the Brave Search API's zero-data-retention option, and the OHTTP gateway strips the IP. [Brave blog, 15 Oct 2026](https://brave.com/blog/browser-ai-e2ee/)
- **Kagi pricing:**
  - The homepage says "Plans start at $4.50/month". Third parties list Starter at $5/month for 300 searches. Kagi's team page lists Ultimate (search plus AI) at $25 per user per month.
  - "Didn't use Kagi for a month? We won't charge you."
  - [Kagi pricing](https://www.kagi.com/pricing); [Kagi](https://kagi.com) (search summary)
- **Kagi Privacy Pass:** available on Professional, Ultimate, Family and Team, not Trial or Starter. It disables account features such as domain personalisation because Kagi cannot tell which user is searching. There is a Firefox add-on. [Kagi announcement](https://kagifeedback.org/d/6172); [Firefox add-on](https://addons.mozilla.org/addon/kagi-privacy-pass/)
- **Kagi scale:** 50k members in June 2025 and more than 66k by early 2026; a figure of 70k around 28 May 2026 is unverified. Kagi Translate relaunched as freemium with an $8/month plan in Sept 2026. [Kagi blog](https://blog.kagi.com/50k); [CB Insights](https://www.cbinsights.com/company/kagi); [Scrapbox](https://scrapbox.io/villagepump/Kagi); [AlternativeTo, Sep 2026](https://alternativeto.net/news/2026/9/kagi-translate-returns-as-freemium-service-with-new-8-month-individual-plan/)
- **DuckDuckGo and Duck.ai:** IP and identifying metadata are "completely removed" before prompts reach model providers. [Duck.ai privacy](https://duckduckgo.com/duckduckgo-help-pages/duckai/ai-chat-privacy)
- **Search inside other assistants:**
  - Venice's E2EE mode disables web search. [Venice privacy](https://venice.ai/privacy)
  - Lumo 2.0 has live web search, but the provider and query handling are not disclosed. [9to5Mac](https://9to5mac.com/2026/06/30/proton-launches-lumo-2-0-with-image-generation-memory-private-web-search-more/)
  - Tinfoil sells a "Private web search API" at $0.05 per request. [Tinfoil pricing](https://tinfoil.sh/pricing)

### Inferences
- Unlinkable search is gated or partial today. Kagi charges for it (Professional and up). Brave offers it only through Leo's single beta E2EE model. Venice's E2EE mode has no search at all.
- Making unlinkable search the free default inside an E2EE assistant and agent would be a clear, demonstrable gap to own.
- Brave's API changes (no free tier, metered billing) raise costs for any assistant reselling Brave results. Cost per query becomes a margin question for a free tier.

### Gaps
- DuckDuckGo's own search privacy statements and 2026 query volumes were not researched.
- Brave Search Premium (ad-free) price.
- Kagi Professional's current official price.
- How Kagi Assistant handles privacy with its third-party LLM providers.
- Startpage, Mojeek and SearXNG were not covered.

## 5. User complaints, reasons people switch, and the messages and offers that drive sign-ups or win-backs

### Takeaway
The main 2026 complaint themes are:
- price rises and shrinking free tiers (1Password, Bitwarden, Dashlane, SimpleLogin);
- alias rejection and spam-foldering;
- shutdowns (Skiff 2024, Notion Mail 2026);
- trust shocks (LastPass's Dec 2025 fine; Proton's CEO backlash in Nov 2026);
- AI providers' data practices (Anthropic's training default, ChatGPT ads, the 2025 OpenAI preservation order, the Meta Discover feed, the Chat & Ask AI leak);
- agent security (OpenClaw).

The messages that recur and appear to land are "we can't read it" (with proof), no account and no IP, no training, free, and works with your current inbox. Offers are large first-year discounts, $1 first months, lifetime deals (2024) and pro-rata upgrades for switchers.

### Cited Findings

#### Prices and free tiers
- 1Password users objected on the community forum, and some said they were leaving. [1Password Community](https://www.1password.community/discussions/1password/re-what-justifies-the-huge-subscription-price-increase/167894)
- Bitwarden users complained about short notice and the "Hidden Price Hike". [Bitwarden community](https://community.bitwarden.com/t/hidden-price-hike/93450)
- Dashlane's free plan ended. [Dashlane](https://www.dashlane.com/blog/dashlane-free-ending)
- SimpleLogin users protest "worsening" of the free plan. [GitHub #2069](https://www.github.com/simple-login/app/discussions/2069)

#### Where 1Password switchers say they go
- Bitwarden is the most common destination; one user moved at $19.80/year, and Bitwarden credited an existing Premium subscription pro rata toward Families.
- Proton Pass is named for its free tier and polish, but former 1Password users list missing features.
- Some stayed, calling 1Password worth paying even at double the price.
- [Privacy Guides](https://discuss.privacyguides.net/t/1password-increasing-its-pricing/35779); [MacRumors forum](https://forums.macrumors.com/threads/1password-getting-more-expensive-starting-in-march.2478182/page-9); [TidBITS: "Should 1Password's Price Hike Push You to Apple's Passwords?"](https://talk.tidbits.com/t/should-1password-s-price-hike-push-you-to-apple-s-passwords/32961) (forum anecdotes, search summary)

#### Alias blocking and deliverability
- Privacy Guides members report sites treating aliases as spam sources and GitHub flagging alias accounts as spam. Public disposable-mail lists have included Proton and SimpleLogin domains, and the FakeFilter blocklist considered adding aliasing services. [Privacy Guides: services blocking aliases](https://discuss.privacyguides.net/t/services-blocking-aliases/14410); [Privacy Guides: mistaken as disposable](https://discuss.privacyguides.net/t/protonmail-and-simplelogin-usually-mistaken-as-disposable-mail/15681); [Privacy Guides: FakeFilter](https://discuss.privacyguides.net/t/fakefilter-blocklist-project-considering-blocking-private-aliasing-services-incl-skiff-simplelogin-addy/15391)
- SimpleLogin's own spam warning, a Trustpilot complaint that the reverse alias wasn't working, and unresolved mailbox.org bounce threads. [SimpleLogin troubleshooting](https://simplelogin.io/docs/getting-started/troubleshooting/); [Trustpilot](https://ca.trustpilot.com/review/simplelogin.io) (search summary)
- Relay: replies only within 3 months, and some sites reject @mozmail subdomains. [Relay FAQ](https://relay.firefox.com/faq/)
- Apple's domain split makes Hide My Email blockable. [MacRumors](https://www.macrumors.com/2026/06/17/new-hide-my-email-domain-makes-it-easier-to-block/)

#### Shutdowns
- Skiff shut down after Notion bought it (2024); Notion Mail shut down 22 Sep 2026. [TechCrunch](https://techcrunch.com/2024/02/09/notion-acquires-privacy-focused-productivity-platform-skiff/); [Notion](https://www.notion.com/help/notion-mail-inbox-is-going-away-what-to-do-next)

#### Trust shock at Proton (late Oct to Nov 2026)
- 404 Media reported, from nine current and former staff, that CEO Andy Yen pushed engineers to rely on AI-written code and dismissed a request for a few days of pentesting as "bullshit and loser thinking".
- Users posted cancellations, and a feedback-forum proposal for Yen to step down reached 2,020 votes.
- On 30 Oct Yen cancelled planned AI re-interviews of staff. On 1 Nov the CTO published a manifesto calling avoidance of AI an "existential threat".
- No verified count of cancellations exists.
- [Decrypt, 2 Nov 2026](https://decrypt.co/382353/proton-users-revolt-ceo-calls-security-caution-loser-thinking-ai); [PCWorld](https://www.pcworld.com/article/3277605/proton-wants-to-vibe-code-your-encrypted-email-might-disagree.html)

#### AI privacy complaints
- Anthropic's training default and 5-year retention drew criticism. [The Register](https://www.theregister.com/2025/08/28/anthropic_five_year_data_retention/)
- ChatGPT ads use chat context. [OpenAI Help](https://help.openai.com/en/articles/20001047-ads-in-chatgpt)
- The OpenAI preservation order (2025). [Malwarebytes](https://www.malwarebytes.com/blog/news/2025/06/openai-forced-to-preserve-chatgpt-chats)
- The Meta Discover feed. [Malwarebytes](https://www.malwarebytes.com/blog/news/2025/06/your-meta-ai-chats-might-be-public-and-its-not-a-bug)
- The Chat & Ask AI leak. [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/ai-chat-app-leak-exposes-300-million-messages-tied-to-25-million-users)
- Pew (June 2026): among US adults who don't use chatbots, lack of interest comes first and data privacy and accuracy concerns follow. [Pew: why don't people use chatbots](https://www.pewresearch.org/internet/2026/06/17/why-dont-people-use-chatbots/); [TNW](https://thenextweb.com/news/pew-research-americans-ai-chatbot-skepticism-regulation-distrust-2026) (search summary)

#### Messages vendors use (all 2026 unless noted)
- **Cannot read, with proof:**
  - Maple: "Your chats are end-to-end encrypted, so Maple cannot see them," with proof at maple.ai/proof. [App Store](https://apps.apple.com/us/app/id6743764835)
  - Brave: "Brave can't read prompts." [Brave](https://brave.com/blog/browser-ai-e2ee/)
  - Venice E2EE: "no one (including Venice) can see your data." [Venice](https://venice.ai/privacy)
  - Confer: "Private AI. Speak freely." [Confer](https://confer.to/)
- **No logs and no training:**
  - Lumo: zero-access encrypted, never logged, never used for training. [9to5Mac](https://9to5mac.com/2026/06/30/proton-launches-lumo-2-0-with-image-generation-memory-private-web-search-more/)
  - Duck.ai: providers "never use your Duck.ai conversations to train their models." [Duck.ai privacy](https://duckduckgo.com/duckduckgo-help-pages/duckai/ai-chat-privacy)
- **Zero friction:**
  - DuckDuckGo: "no need to change providers." [DuckDuckGo](https://duckduckgo.com/duckduckgo-help-pages/email-protection/what-is-duckduckgo-email-protection)
  - Leo: no account needed. [Brave](https://brave.com/blog/browser-ai-e2ee/)
- **Freedom:** Voorhees: "We're optimizing for freedom and actually respecting users as adults," and early users came "because it was private". [TechCrunch](https://techcrunch.com/2026/07/01/venice-ai-becomes-a-unicorn-with-65m-series-a-as-its-privacy-first-ai-platform-takes-off/)
- **Confession and ads:** Marlinspike calls AI chat technology that "actively invites confession". [TechCrunch](https://techcrunch.com/2026/01/18/moxie-marlinspike-has-a-privacy-conscious-alternative-to-chatgpt)
- **Free forever:** AliasVault: "The core product will always stay free." [AliasVault](https://www.aliasvault.com/)
- **Fair billing:** Kagi: "Didn't use Kagi for a month? We won't charge you." [Kagi](https://www.kagi.com/pricing)

#### Offers
- Proton Black Friday 2026 (code BF2026NEW, shown 26 Nov 2026): Pass Plus 60% off ($23.88 for the first year), Pass Family 60% off, Mail Plus and Unlimited 50% off, and a $1 first month of Mail Plus (MAILPLUSINTRO). [Proton Pass pricing](https://proton.me/pass/pricing); [Proton Mail pricing](https://proton.me/mail/pricing)
- Proton Pass Lifetime at $199 (ended 3 Dec 2024, old). [Proton blog](https://proton.me/blog/pass-lifetime)
- Tuta "Black Weeks", 62% off the Legend plan (year not confirmed). [Tuta blog](https://tuta.com/blog/black-weeks-at-tuta)
- 1Password customers who renewed before 27 Mar 2026 kept the old price. [MacRumors](https://www.macrumors.com/2026/02/24/1password-march-price-increase/)
- Bitwarden credited existing Premium time pro rata toward Families. [Privacy Guides](https://discuss.privacyguides.net/t/1password-increasing-its-pricing/35779)

### Inferences
- **Switching happens at renewals and price notices.** 1Password's EU rule cancels the plan unless the price is accepted, and Bitwarden gave 15 days' notice. Win-back campaigns timed to competitors' renewal cycles, plus one-step import (Credential Exchange, CSV), should convert best.
- **Policy claims are everywhere, so "cannot" beats "will not".** "No logs" and "no training" are now table stakes; the claims that stand out are verifiable ones, such as attestation proofs and keys only on the user's device. Venice's founder says privacy alone drew early users despite a feature gap, which supports leading with privacy and then closing feature gaps fast.
- **Proton is the most direct win-back pool for an E2EE email, password and AI bundle.** In Nov 2026 it combines a trust controversy, plaintext at inference for Lumo, and alias relays that see plaintext.
- **DuckDuckGo's $9.99 bundle shows privacy bundles sell as one subscription**, and its Plus/Pro split at $9.99 and $19.99 is a reference price. This draws on DuckDuckGo's subscription structure; I found no revenue figures.

### Gaps
- No quantitative churn or conversion data for any offer.
- Direct Reddit threads (r/privacy, r/ProtonMail, r/selfhosted, r/LocalLLaMA) did not surface in search; the complaints above come from Privacy Guides, MacRumors, TidBITS, vendor forums and press.
- No A/B or survey evidence on which privacy message converts best.

## 6. Market size and adoption signals

### Takeaway
Privacy-branded consumer services have real scale: Proton 100M+ registered users, Brave 130.77M monthly active users and 2.7B searches a month, Lumo 10M+, and Venice 3M+ active users with a run-rate above $70M at a $1B valuation. Specialist paid tools stay small, for example Kagi at about 66k members (early 2026) and Maple with 36 US App Store ratings. Password management is roughly a $3–4.6B market in 2026. US public concern is high: 71% expect AI to make their personal information less secure, while 49% use chatbots.

### Cited Findings
- **Proton:** surpassed 100M registered users (date not confirmed in sources), up from an earlier 70M. [European Purpose](https://europeanpurpose.com/news/proton-passes-100-million-users); [Proton blog](https://proton.me/blog/cs/70-million-accounts)
- **Lumo:** "more than 10 million people" (Proton, June 2026). [9to5Mac](https://9to5mac.com/2026/06/30/proton-launches-lumo-2-0-with-image-generation-memory-private-web-search-more/)
- **Venice:** 3M+ active users, 1.7M API calls a day, over $70M annualised run-rate, profitable, $65M Series A at a $1B valuation (1 Jul 2026); about 8% of users pay in crypto. [TechCrunch](https://techcrunch.com/2026/07/01/venice-ai-becomes-a-unicorn-with-65m-series-a-as-its-privacy-first-ai-platform-takes-off/)
- **Brave:** 130.77M monthly active users (Oct 2026) and 2.7B Brave Search queries a month (Oct 2026). [PiunikaWeb](https://piunikaweb.com/2026/11/03/brave-130-million-monthly-active-users/); [PPC Land](https://ppc.land/brave-search-queries-gain-56-in-a-year-to-2-7bn-a-month/)
- **Kagi:** 50k members (June 2025) and more than 66k (early 2026). [Kagi](https://blog.kagi.com/50k); [CB Insights](https://www.cbinsights.com/company/kagi)
- **OpenClaw:** 247k GitHub stars (2 Mar 2026). [Wikipedia](https://en.wikipedia.org/wiki/OpenClaw)
- **Jan:** 5.3M downloads (Mar 2026). [DEV](https://dev.to/jovan_chan_9500711396d4e6/jan-ai-review-2026-13ei)
- **Skiff:** about 2M users at shutdown (Nov 2023 figure). [Wikipedia](https://en.wikipedia.org/wiki/Skiff_%28email_service%29)
- **addy.io:** 5M+ aliases created. [addy.io](https://addy.io/)
- **AliasVault:** 3,000 GitHub stars (Aug 2026). [AliasVault](https://www.aliasvault.com/)
- **Maple:** 36 ratings on the US App Store (Nov 2026). [App Store](https://apps.apple.com/us/app/id6743764835)
- **Password-management market (2026 estimates, paid reports):**
  - Consumer password managers: $2.9B in 2025 and about $3.4B in 2026. [Marketintelo](https://marketintelo.com/report/consumer-password-manager-market)
  - All segments: $4.57B (TBRC), $3.79B (Fortune Business Insights), $2.94B (Mordor). [GII/TBRC](https://www.giiresearch.com/report/tbrc1458713-password-manager-global-market-report.html); [Fortune BI](https://www.fortunebusinessinsights.com/password-management-Industry-103753); [Mordor](https://www.mordorintelligence.com/industry-reports/password-management-market)
- **Bitwarden, LastPass and Dashlane combined:** more than 60M users and 23% market share (ETH Zurich). [USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata)
- **Pew, "Americans and AI 2026"** (5,119 US adults, 17–23 Feb 2026, published 17 Jun 2026) ([Pew](https://www.pewresearch.org/internet/2026/06/17/americans-and-ai/)):
  - 71% say AI will make their personal information less secure; 3% say more secure.
  - 67% have little or no confidence the government will regulate AI effectively; 59% say the same of companies developing AI responsibly.
  - 49% use AI chatbots, up from 33% in 2024. ChatGPT 44%, Gemini 24%, Copilot 17%, Meta AI 14%, Grok 8%, Claude 6%.
- **Cisco Consumer Privacy Survey (Oct 2024, old; 2,600+ people in 12 countries):** 30% of generative-AI users enter personal or confidential information despite 84% being concerned it could go public; regular use rose to 23% from 12%. Cisco's 2025 release is a business benchmark (63% "very familiar" with generative AI). [Cisco newsroom, Oct 2024](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2024/m10/cisco-survey-shows-strong-relationship-between-privacy-awareness-and-trust-in-ai.html); [Cisco 2025 benchmark](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2025/m04/cisco-2025-data-privacy-benchmark-study-privacy-landscape-grows-increasingly-complex-in-the-age-of-ai.html)
- **Passkeys and password-manager use:** 7B passkeys (FIDO estimate, Oct 2026); 36% of US adults use a password manager (Security.org, Oct 2024). [FIDO](https://fidoalliance.org/7-billion-passkeys-and-counting-the-next-chapter-of-passwordless-authentication/); [Security.org](https://security.org/digital-safety/password-manager-annual-report)

### Inferences
- **Paying privacy users concentrate in a few brands** that grew through bundling (Proton, DuckDuckGo) or distribution (Brave's browser feeding Leo and Search). An existing privacy VPN user base is the same kind of distribution channel, and a bundle fits how the leaders grew.
- **"Private AI" is a mainstream pitch now.** Half of US adults use chatbots and 71% expect AI to weaken their data security. Lumo's 10M and Venice's 3M+ show the demand is real.
- **Specialist E2EE AI apps are still small.** Maple and Confer show little public adoption evidence, which leaves room for a well-distributed entrant.

### Gaps
- No 2026 user counts for DuckDuckGo, Proton Pass, Bitwarden, 1Password, Cloaked, Confer, Firefox Relay or DuckDuckGo Email Protection.
- No market-size estimate for email aliasing or private email specifically.
- The date of Proton's 100M milestone was not confirmed.
- No independent verification of FIDO's passkey counts, or of Lumo's and Venice's user figures.
