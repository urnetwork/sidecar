# Burner and Bot for lapsed privacy-VPN users: the consumer hypothesis

2026-11-27. Analysis only: no email string, template, page or design document was changed.

## Bottom line

- **The lapsed list is the wrong audience for a privacy pitch and the right audience for a job pitch.** The house's own research finds that people who took up a VPN for a practical need quit when the need ended, while "privacy-motivated users stayed". So "lapsed" filters out the privacy motive the current Burner opening assumes ("You came to URnetwork to keep your browsing private").
- **Burner's job is real**: a new address and login for every site, burned when it spams. People build this today from two or three products. But the job's moment of truth is the sign-up code. DESIGN.md §15.6 says "a phone alone cannot reliably receive, and phone-only users may miss time-sensitive codes". The fix is a computer left on, or an enclave at "tens of dollars a month" (DESIGN-COMPUTE §11.10). The alias market charges $1 to $4 a month.
- **Bot's consumer job** is a free AI whose words stay on your phone, with chats saved so only your devices can read them, which follow you between devices. Memory and sync are gaps the private-AI market openly concedes. TEE models, enclaves and search are the paid, disclosed step up, not the lead.
- **The market's biggest consumer opening isn't on this list.** That opening is 2026's trust-shock leavers from Proton, 1Password, Bitwarden and ChatGPT. The ur.io pages are how to reach them, so the pages should lead with guarantees and admissions, and the emails with the job.
- **Five lines outrun the truth or their own rules today** (section 6):
  - The Burner page's "fully searchable" and "reply" claims come ahead of their milestones: launch is receive-only at M8, sending is M9, search is M10.
  - The Bot email's search line leaves out Vercel.
  - The Bot email's TEE line doesn't say what the hardware check covers.
  - The Bot page's hero says "sealed inside TEEs" and "Search the web privately".
  - The Burner email's limits line understates phone-only receiving and doesn't say the enclave is paid.
- **The house metric can't see a win.** `reactivation_7d` counts a VPN `connect.day`. A reader who comes back for Burner or Bot without connecting counts as not reactivated.

## 0. Sources and how to read this

| Key | File |
|---|---|
| CR | /Users/brien/urnetwork/sidecar/research_notes/Private agent network market hypothesis/customer_reviews.md (IDs C, A, N) |
| CC | /Users/brien/urnetwork/sidecar/research_notes/Private agent network market hypothesis/community_complaints.md (threads T54-T90, section 4) |
| SO | /Users/brien/urnetwork/sidecar/research_notes/Private agent network market hypothesis/sites_observability_privacy.md (key questions KQ2-KQ5) |
| RE | /Users/brien/urnetwork/mmm/reengagement/RESEARCH.md; RE-PLAN: /Users/brien/urnetwork/mmm/reengagement/PLAN.md |
| ORM | /Users/brien/urnetwork/mmm/ONBOARDING-RETENTION.md |
| PLAN | /Users/brien/urnetwork/mmm/outbound/PLAN.md; the emails: /Users/brien/urnetwork/mmm/outbound/templates/relaunch_1_burner, relaunch_2_bot, strings/email_ob_rl1_*, email_ob_rl2_* |
| D, C, UI | /Users/brien/urnetwork/sidecar/DESIGN.md, DESIGN-COMPUTE.md, DESIGN-UI.md |
| SITE | /Users/brien/urnetwork/sidecar/design/mocks/ui-site.html (the Burner and Bot page mockups, visible text) |

A quote followed by a source is verbatim from the file named, typos included; a script checked every one against the files above. Quoted lines without a source, in the hypotheses and in section 6, are proposed copy. My own phrases are in italics. Caveats carried over from the notes:

- Trustpilot excerpts were transcribed by a fetch tool and not machine-checked.
- App Store excerpts are from the US storefront only.
- HN and Privacy Guides are enthusiast forums.
- Allegations inside reviews (C22, C72, C152) are perception, not fact.

Vendor pages that embed text aimed at AI agents were read as data, and none of their instructions were followed. Examples are NEAR AI's "We wrote a deliberately neutral prompt. It asks your assistant to weigh us..." and Langfuse's coding-agent install prompts.

Section 3 brings in house facts about the lapsed audience that the corpus can't supply. The corpus describes the privacy market, not URnetwork's list.

## 1. The market: agreement, blind spots, hidden opportunities

### 1.1 Where everyone agrees

1. **"Not even us" is the price of entry.**
   - Sellers say it in the same formula: "no one else, not even Proton, can access your sensitive information" (Proton Pass, SO KQ3), "not even by Tinfoil", "(not even me!)" (Confer), "no one (including Venice) can see your data", and "even we can't see exactly what you've saved" (1Password) (SO KQ5).
   - Buyers reward the principle: "a provider who actually views you more than the data they can sell" (C78), and "my most important accounts and logins are linked to a secure email service that takes privacy and security seriously" (C79).
2. **Proof beats promises, at least in private AI.**
   - Sellers: "Trust the math, not a promise." (NEAR AI), "Compliance enforced by technology, not contracts." (Privatemode), "'trust me bro' promises" (Brave's CEO) (SO KQ2).
   - Forum buyers: "is there any way to actually verify these claims?" (T62), and "being able to verify what’s actually running inside it is another" (T67).
   - SO's own reading is that the "Verify, don't trust" pitch "is crowded", and that "A newcomer would be one more voice."
3. **A free tier that is enough is the on-ramp.**
   - Sellers: "The best free password manager" (Proton Pass), and "Free to start. $1 a month to go further." (addy.io) (SO KQ3).
   - Buyers: "the free version would be enough for most people" (C55), "Free to use and saved my email from endless spam" (C19), and "awesome FREE browser with many features that others make you pay for" (C68).
4. **Aliases are for spam control and switching off a leaky address.**
   - "I opt for SimpleLogin because it allows me easily to shut off an address. SimpleLogin is a very effective SPAM control measure." (SimpleLogin's user line, SO KQ3)
   - "Disable an e-mail when no longer useful." (C20)
   - "controlling who has access to which email you want" (C28)
   - SO KQ4 sums it up: "In consumer tools it is control and spam reduction."
5. **Private AI trades capability for privacy.**
   - Vendors admit it. Venice's strongest tier comes with "−No web search or memory; responses may be slower" (SO KQ2).
   - Users accept it, up to a point: "can’t do everything like ChatGPT can due to encryption and privacy features present" (C96), and "complements ChatGPT ... but certainly doesn’t replace it" (C98).
6. **Local is the gold standard, and everyone assumes it's weaker.**
   - "Local AI is about as private as you can really get" (T68). "Still would prefer local of course." (T64)
   - "Privacy people want it locally, but it is 5 to 10 years away (or never, if the current economics works, there is no need to reverse the trend)." (T66)
7. **One trusted brand carries the bundle.**
   - Proton is "the only vendor that sells password manager, aliases, mail and AI under one brand" (SO KQ3).
   - Users stack its products: "give Proton Pass a try since I do use their email service" (C09), and "partly because I just really wanted to support Proton" (C10).
   - Maple's blog already frames the layers: "See what a VPN, an email alias and encrypted AI each cover." (SO KQ2)

### 1.2 Blind spots

1. **Trust breaks at the account, not in the cryptography.**
   - Vendors talk about keys. Users talk about lockouts: "I have now lost 8 years of photos and videos of my 2 kids" (C83), "They suspended my account using an automated system." (C88), and "they intiated a secret key rotated that locked me out on all devices" (C45).
   - Automated bans with no human path: "run by AI scripts that disable paying users without any real and serious path to restoring accounts" (C24), and "Manus deleted my paid account and my work" (A36).
   - End-to-end encryption makes it worse: "ALL my data has now been encrypted and is inaccessible through absolutely no fault of mine." (C89)
   - Concentration is its own fear: "I have to remove all my critical logins from Proton. I can’t be locked out of anything with 2 factor while Proton does maintenance." (C74)
   - No vendor page in SO leads with recovery or appeals. CR's inference: "Recovery design and human appeals matter as much as cryptography."
   - Burner puts a site's address, password, code and passkey in one place. That is exactly C74's worry.
2. **The alias's job ends at the sign-up form, and the sellers ignore acceptance.**
   - "More and more services reject an addy.io/simplelogin domain." (T73)
   - "So you can ban this subdomain instantly, knowing people will be "hiding" with this service by default." (T71)
   - "BLOCKED MY ACCOUNTS IN OPENAI!!!" (C29)
   - "I’m feeling like I should give up on email privacy." (T75)
   - No alias homepage in SO mentions it.
3. **The relay reads the mail, and almost no user asks about it.**
   - SO KQ3: "None claims end-to-end encryption of forwarded mail by default ... Content is visible in transit at forwarding time, which the vendors frame as forwarding without saving."
   - The only user traces are an unverified allegation, "SimpleLogin uses an AI web crawler to read their customers’ emails." (C22), and one HN comment about Proton's webapp (T89).
   - The gap is real but undemanded. Burner's strongest technical edge is one the median alias user doesn't currently ask for.
4. **Private-AI sellers argue about where decryption happens, while buyers leave over memory and capability.**
   - "Venice has no real memory or recall" (C109).
   - "having to start over each and every time you need to talk to your AI is rather annoying" (C110).
   - "it needs a way to save chats to continue the same conversations on multiple devices" (C111).
   - "a far less capable AI model with even stricter guard rails and censorship" (C92).
   - In the App Store pull, "censor" appears in 21% of Venice reviews and "credits/limits" in 12% (CR keyword table).
   - Venice's own E2EE tier drops memory (SO KQ2).
5. **Usage credits are treated as flexibility, and buyers experience them as a trap.**
   - "My credits keep decreasing even when I am not receiving the results I actually paid for." (A34)
   - "wasted over 24,900 credits for failed work using Agent AI" (C118)
   - "31,132 unused credits expired" (A35)
   - Cancellation traps: "I am stuck in an endless loop trying to cancel my subscription." (C112)
6. **Nobody shows a privacy brand carrying over from the VPN to other products.**
   - The one bundler's buying path starts from mail (C09). A Proton VPN reviewer: "I’d only use the VPN if you’re already paying for the Proton bundle" (C134).
   - CC section 4 Gaps: "I found no thread in which users ask for a single bundle of VPN, alias email, password manager and private AI."
7. **Adding AI is treated as progress, and this audience treats it as a breach of trust.**
   - "every app and website injecting AI into every one of your interactions, with no way to disable it." (T61, 557 points)
   - "Unfortunately, the service is now infected with AI crapware." (C82)
   - Title "Privacy-Image vs. AI-first - not with me." (C90)
   - "I'm kind of annoyed they've been secretly wasting their time and money on building an AI assistant." (T62)
8. **Daily usability decides VPN loyalty, and privacy homepages lead with principles.**
   - "having to constantly disable the VPN just to be able to use your devices reliably" (C141)
   - "Constant captchas and frequent full blocks." (C151)
   - "The so-called killswitch is all theater" (C139)
   - "it chewed through 72% of my battery usage" (N45)
   - CR: "What breaks loyalty is day-to-day usability".

### 1.3 Where the biggest opportunities hide, ranked

1. **2026's trust-shock leavers, who are actively shopping.**
   - "If Proton continues in this direction, I will be cancelling subscription." (C73) "i will move to different services again." (C90)
   - "what's a good open source and secure alternative? even if payed?" (T86)
   - The shocks behind them: the 1Password incident thread (T80, 1695 points), Bitwarden's governance threads (T86, 715 points), LastPass's latest breach (T87, 526 points) and the ChatGPT retention order (T54, 1132 points).
   - The opening is large and time-bound. These people are not on the lapsed list (section 3).
2. **Collapsing the kit into one tap.** People assemble the job from parts.
   - "Every new account gets a new alias from SimpleLogin via Bitwarden which then redirects to a specific ‘burner’ inbox and then can turn off the Aliases as needed." (T77)
   - addy.io advertises the seam: "Works with Bitwarden" (SO KQ3).
   - Burner does address, login, code and passkey per site in one tap. This is its natural wedge.
3. **Private AI that remembers, and that only you can read.**
   - The clearest consumer pay signal for private AI is about sync, not cryptography: "I chose Lumo+ because chat history is stored with my Proton data and is available in all my devices" (CC section 4).
   - Venice's E2EE tier has no memory (SO KQ2).
   - Bot's sessions live in encrypted storage and resume on any device (UI-8). The Bot page says "your agents and chats follow you between them".
4. **Candour as a product.**
   - SO KQ5: "Plainly stated admissions are rarer and stand out", and only 3 of 22 companies speak plainly about compelled disclosure ("Law-enforcement candour, 3/22").
   - Mullvad's praise is honesty: "Perfect honesty." (C154), and "not being treated like a marketing funnel" (C155).
   - The strongest pay signal in mail is about exactly this: "I would pay up to $10/month for an email provider who would go to jail for me." (T89)
5. **Recovery and a human on the other end.** Nobody markets either. Users single out named support staff ("Siân was able to assist", C47) and fear bots ("I hope they don't get replaced by an AI chatbot", C48).
6. **Agents with their own address for mail and calendar chores.**
   - "I would pay half that for an AI agent to do emailing and scheduling and contract rounds." "it would be a common workspace for me and my agent." (CC section 4)
   - "Give agents limited access to manage calendar events" (C102)
   - The signal is weak (one 4-point HN thread, one review), but no private product answers it. Burner's agent addresses and mail tools (UI-12) could.
7. **Private, unblockable and unlocked at once.** CC section 4: "No product is named that is private, unblockable and unlocked at once". Burner does not capture this at launch: its addresses live under `ur.network`, and custom domains are Team-only (UI).

## 2. Three questions

### 2.1 What do the winners understand about their customers that competitors miss?

- **Mullvad: restraint is the product.**
  - Quotes: "They allow anonymous payment via crypto and ask no name." (C153), "doesn't even require an email to sign up" (C156, a duplicate flagged in CR), "Perfect honesty." (C154), "There’s something refreshing about not being treated like a marketing funnel." (C155), and "Mullvad. The only VPN company I actually trust." (T90)
  - What competitors miss: they treat privacy buyers as a funnel. Reviewers complain about review prompts ("I don’t like it when apps ask too much for reviews", C11), cancellation loops (C108, C112) and AI upsell (C82).
- **Bitwarden, DuckDuckGo and Proton Pass: free that is genuinely enough wins, and taking it back is the fastest way to lose people.**
  - Quotes: "the free version would be enough for most people" (C55), "It's just better in every way for free" (C56), and "i have even got free features that i have previously paying for" (C07).
  - Then the backlash: Bitwarden "scrubs 'Always free'" (T86), "Premium: Was $10, is now $19.80 (increased by 98 %)" (T84), and "There is no such thing as a free lunch" (T85).
- **Proton, before the shock: people buy a values relationship and pay as patrons, and they leave on conduct.**
  - Patronage: "I just really wanted to support Proton" (C10), "one of the few subscriptions I have in a patron sense" (CC section 4), and "saving a few cents never justified sacrificing transparency, structural guarantees, or reliability" (C136).
  - Then conduct: "I believed this to be a company I could trust with my personal information." (C71), and "They have completely strayed from their original mission." (C85)
  - CR: "conduct and governance count as product features."
- **1Password: when something breaks, a named human is the product.**
  - "If customer service alone were the deciding factor, I'd have had no reason to leave." (C49)
  - Versus "There is literally no way to reach customer support" (C120), and "there does not appear to be reliable human support" (A37).
- **SimpleLogin against Apple: an alias you can reply from is a real address.** "Imagine hide my email but you can actually reply!" (C13). Burner's replies come at M9, after launch (D §15.17).
- **Lumo's paying users: synced history is worth paying for.** "I chose Lumo+ because chat history is stored with my Proton data and is available in all my devices" (CC section 4).
- **Apple Passwords: the free default already on the phone wins the price-sensitive majority.**
  - "I found out Apple has a passwords app." (C34), and "Apple Passwords for $0 is a pretty easy switch" (T82).
  - "rarely works nearly as good as what comes on your device for free" (C04)

**The pattern.** The winners sell restraint and continuity: free that stays enough, no funnel, a human when it breaks, and an app that works today. The others sell cryptography and features. Users can't audit cryptography. They can tell whether the free plan stayed free, whether someone answered, and whether the app worked this morning.

### 2.2 What does everyone in the category take for granted, and what if it were wrong?

| # | Assumption | Evidence that it is shaky | If it is wrong |
|---|---|---|---|
| A1 | Privacy is why people buy | VPN use is situational: "security 82%, public networks 58%, censorship 9%" and "privacy-motivated users stayed" (RE §9.2-9.3, small studies). "Is there any other real world usecases for VPN nowadays other than: 1. Getting access to geolocked data 2. Torrenting" (T88). For AI, "privacy is the reason to try and capability is the reason to leave" (CR) | A privacy-led win-back speaks to the readers who never left. Lead with a job; privacy becomes the reason to trust it |
| A2 | A trusted privacy brand carries over to other categories | No thread asks for the bundle (CC section 4 Gaps). "I’d only use the VPN if you’re already paying for the Proton bundle" (C134). Proton's AI launch drew "I’m disappointed to see the company spending money on something like this" (C92) | Each product must win its own job. Coming from the reader's VPN company may hurt with readers the VPN let down, since they lapsed |
| A3 | An alias protects you by hiding your real address | Sites block alias domains (T71-T74). Burner's own design says burners "are linkable through `<net>`" (D §15.9). Users expect the opposite: "in case of a data breach, it's impossible for the hackers to find your other accounts" (SimpleLogin's user line, SO KQ3) | Burner's real value is control (burn it), breach containment for one site, and mail no relay reads, not anonymity. Copy must never suggest unlinkability |
| A4 | Verification (TEE, attestation) is what private-AI buyers want | Forum experts do, and they still answer with a "but": "a compromise of the TEE would mean your data is exposed" (T66), "it still processes data in the clear" (T65). NEAR AI's November 2026 incident: "including requests running in confidential mode" (SO KQ2). App Store reviewers ask for capability, memory and fewer limits instead | Leading Bot with TEEs and enclaves sells to the wrong reader and invites the "not E2E" reply. Lead with free and local, and state the TEE limit plainly |
| A5 | Free converts later | "perhaps too good for the price of $0 ... I can’t still can’t figure out what their incentive is" (T74). Taking free away costs trust (T84-T86). Free and unlimited draws abuse: "because of free unlimited alias and free sending, duck.com mails are often abused for spam, thus are much more likely to be blocked" (T74) | The email's "It's in the free plan, with as many addresses as you want" invites the *what's the catch* question and abuse-driven blocklisting. Never promise "always" unless it's meant |
| A6 | Encryption makes users safer | The worst end-to-end encryption stories are self-inflicted loss: "ALL my data has now been encrypted and is inaccessible" (C89) | A product holding every login and the reset mailbox on the user's devices has to say what happens when a phone is lost |
| A7 | More AI is welcome | "infected with AI crapware" (C82); "no way to disable it" (T61); "I despise AI ... I also need to use it for my work" (T68) | Bot must be plainly opt-in and must never read Burner mail unless the person chooses a model for it. The Bot email carries the risk of higher unsubscribes |

### 2.3 Pains mentioned again and again, still poorly addressed

| Pain | Where it recurs (quote, source) | Named answers, and why they fall short | Burner or Bot |
|---|---|---|---|
| Alias addresses blocked at sign-up | T71-T75, C29: "If your website will block me out because I used a privacy friendly email, I want nothing to do with your website." (T71) | A custom domain, icloud.com or Fastmail: "the only lasting solution is to put them on the same domain as, and in the same format as, a significant number of non-private email addresses" (T72). None is private, unblockable and unlocked at once (CC section 4) | **Not addressed; possibly worse.** One suffix, word-number labels (`^[a-z]+-[0-9]{4}$`, D §15.9), free and unlimited with no creation pace limit (Q-UI-41: "Drop it"), shared sending reputation (D §15.9), a list that already draws sign-up farms (PLAN §3), and a product literally named Burner |
| Lockouts and automated bans with no human path | C23-C25, C45, C83, C84, C88, C89, A36 | No one markets recovery | **Unknown.** End-to-end encryption raises the stakes (C89), and Burner concentrates logins (C74). Must be answered on the page |
| Password-manager price hikes and moves to subscription | C33, C34, C36, C42; T81-T85: "presumably stemming from company taking advantage of the customer switching cost" (C42) | Apple Passwords at $0, KeePass ("does not offer sync and conflict resolution", T87), Vaultwarden ("a bit afraid of the self-hosting (of something this critical)", T87). "The alternatives are either more expensive ... or less convenient ... or more expensive and closed source" (T86) | **Partly.** In the free plan. But I found no password import in D or UI, and import is what makes moves painless (C58: "The ability to import all of my Lastpass data made the transition painless") |
| Private AI that forgets, censors or is weak | C92, C98, C107-C111, C126 | Lumo+ for sync; local models for privacy, called "5 to 10 years away" (T66) | **Partly.** Encrypted sessions that resume anywhere fix memory and sync. A 2.59 GB Gemma 4 E2B on phones does not fix capability (C §6.5) |
| AI chats retained, trained on or reported | T54-T58: "how could you trust a hosted model to respect such opt outs?" (T57) | Trust in a brand ("Lumo is based on the trust that Proton conveys", T65) or TEEs with a "but" | **Yes for local; disclosed for TEE; not for search.** Parallel may train on searches (C §21.6) |
| Paying for failed AI work, and credits | A34, A35, C118, C119 | None | **Inherited.** Bot's compute balance is prepaid credits, and "one that fails after its payment settles costs the same" (C §21.6, web search) |
| The middle can be trusted but not checked | T62, T66, T67, T89: "there's nothing stopping protonmail (to my knowledge) from reading your email from within their webapp via JS." | TEEs, self-hosting, Mullvad's reputation | **Strongest answer in mail.** Decryption moves to the device. It still rests on trusting the app build ("verify that an app was actually compiled from some specific git SHA", T66), and PLAN §6 bans claiming reproducible builds or audits |
| Forwarded mail lost, bounced or held where you can't see it | C12; T79: "has been hard-bouncing all forwarded mail for several days", "10MB attachment is silently dropped", "no possibility to view & release blocked mails" | Ticket requests on GitHub | **Inherited on phones.** "a phone alone cannot reliably receive" (D §15.6). Mail isn't lost while the sender retries, but codes expire |
| VPN daily usability: blocks, CAPTCHAs, disconnects, battery | C132, C142, C151, C139, C141, N45; URnetwork's own support inbox: disconnects 556, connection failures 484, slow speed 184 (RE §11.1) | Switching VPNs | **Not addressed.** Many lapsed readers' reason for leaving survives Burner and Bot |
| AI pushed without consent | T61, C82, C90 | None | **Partly.** Bot is a separate tab, and the mail tools use "any model the person picks" (Q-UI-42). Say so |
| Cancellation traps and billing surprises | C26, C33, C108, C112, A39 | None | **Burner: free. Bot: prepaid.** Keep auto-renew off by default (T7 shows it) |

## 3. Who the readers are: house facts the corpus can't supply

- **Email reaches few.** "4.0% of 128,653 networks have an email login (seed-phrase accounts are 94.9%)" (RE-PLAN, Sizing). Sign-ins over 60 days: "93% seed phrase ..., 3.6% email and password, 2.7% Google, 0.8% Solana, 0.4% Apple" (ORM §3.1). The readers are the minority who gave an email to an anonymity-first app.
- **Countries.** No marketing to CN, RU, IR, CU, KP or SY (PLAN §3). EU, EEA, UK and CH readers only with consent evidence (Q-OB-8). Russia and Iran are "82% of the 31,642 Android sign-ups" (ORM §3.3), so the mailable list is the remainder: Ukraine, the US, Germany and others.
- **Platforms.** New sign-ups run in the thousands a week on Android, hundreds on iOS and tens on Windows (ORM §3.2). Payment within 14 days is "About 0.07-0.25% of Android networks ...; Windows, 10-18%". The lapsed list's platform mix is unknown until the sizing probe counts it (PLAN §3).
- **Why they used it, and why they left.**
  - "Use is situational" (RE §9.2).
  - "People who adopted a VPN for a practical need quit when the need ended ...; privacy-motivated users stayed" (RE §9.3, Namara et al., 90 people, 7 quitters).
  - Support themes: disconnects 556, connection failures 484, earnings not updating 249, subscription payment 190, slow speed 184 (RE §11.1). Some readers are earners, not privacy buyers.
- **Who signs up.** "sign-up farms have made most email sign-ups since 2026-11-09" (PLAN §3).
- **How success is counted.** `reactivation_7d` is "the share of assigned networks with at least one `connect.day` in the 7 days after the ... send" (RE-PLAN L39). `reengage_lapsed_1`'s base rate is 1.5% (RE-PLAN L157).
- **What returns them.** "90% of the gain did not come through redemption" (RE §2.1): the reminder does most of the work. "One late Uber trip cut riders' later spending 5–10%" (RE §9.4): a failed first try costs more than no try.

The corpus is an enthusiast sample: the US App Store, Trustpilot, HN and Privacy Guides. The lapsed list is international, mostly on phones and mostly not privacy-motivated. Every inference from the corpus to this list is therefore an extrapolation, and the hypothesis below is built to be tested on the list itself.

## 4. The hypothesis, steelmanned and broken, three rounds

### Round 1: privacy refugees and a structural moat

**H1.** Lapsed URnetwork VPN users are privacy buyers by revealed preference. 2026's trust shocks have put that market in motion. Burner and Bot are the only consumer products whose operator structurally cannot read mail or prompts, they are free, and they are one tap away in an app the readers already have. Privacy-led emails will bring readers back above the holdout, and Burner plus Bot will grow into the bundle that replaces Proton for them.

**The steelman, as a top-tier partner would write it.**

- **Why now.** The category's trust is breaking in public:
  - Proton's CEO episode shows up in 13 of 77 recent Proton Mail App Store reviews, and proton.me's TrustScore is 2.0 (CR).
  - 1Password's incident thread drew 1695 points (T80), Bitwarden's governance thread 715 (T86), and LastPass's latest breach 526 (T87).
  - A court ordered ChatGPT to keep all logs (T54, 1132 points).
  - People ask for alternatives "even if payed?" (T86).
- **The market is real.** Proton VPN has 137,243 App Store ratings, Proton Mail 51,665 and 1Password 47,695. Lumo says "more than 10 million people have started using it" (CR, SO KQ2).
- **An unclaimed position.**
  - No alias relay claims end-to-end encrypted forwarding (SO KQ3), and Lumo admits "only the Lumo GPU servers are able to decrypt" prompts (SO KQ2).
  - Burner's mail edge "Holds no key and keeps no message" (SITE). That is architecture, not policy: the "verify, don't trust" the forums ask for (T62, T67).
- **Willingness to pay follows guarantees.**
  - "I would pay up to $10/month for an email provider who would go to jail for me." (T89). Burner removes the need: there is no key to hand over.
  - "$125/person for a Certified Secure password manager ... without creating a single point of failure in a SaaS company" (T80).
- **Distribution costs nothing.** Both products are tabs in the app the reader installed (PLAN §4).
- **A price wedge.** Unlimited free addresses against Proton's and SimpleLogin's 10 (SO KQ3). Free local AI against Venice's "10 text prompts per day", Maple's "25 messages per week" and Confer's reported 5-message limit (SO KQ2; T67).
- **The bundle is proven and the incumbent is wounded.** Users stack Proton products (C09, C10), and Proton's reviews are now full of leavers (C71, C73, C85, C90).

**Where H1 fails.**

1. **"Lapsed" selects against the privacy motive.** The people who quit were the practical-need users; "privacy-motivated users stayed" (RE §9.3). The revealed preference is for a VPN, for a while.
2. **The refugees aren't on this list.**
   - Every trust-shock quote comes from Proton, 1Password, Bitwarden and ChatGPT users on HN, Privacy Guides or the US App Store.
   - The list is 4% email logins, mostly phones, without RU, IR or CN, and partly sign-up farms (section 3). The corpus can't show any overlap.
3. **The moat is not a demand driver for the median user.**
   - Alias users praise spam control (C19, C20, C28).
   - Nobody in the App Store sample asks for an end-to-end encrypted relay (section 1.2, blind spot 3).
   - Private-AI users leave over capability, memory and credits, not over where decryption happens (C92, C109, C118).
4. **No one asks for the bundle, and the one bundler shows its failure mode.** "I found no thread in which users ask for a single bundle" (CC section 4 Gaps). Proton's AI launch was read as neglect: "Proton Drive still doesnt have a linux app." (T62)
5. **The structural moat has a structural cost the bull case leaves out.** "The edge cannot queue" and "a phone alone cannot reliably receive, and phone-only users may miss time-sensitive codes" (D §15.6). The property that blinds the operator also makes a phone-only Burner unreliable at the sign-up code.
6. **AI aimed at a privacy list walks into 2026's backlash** (T61, C82, C90).

**What the revision must fix:** drop privacy as the lead, and find a job that situational users have.

### Round 2: one concrete job, with privacy as the proof

**H2.** Lapsed readers come back for a concrete job, not for privacy. Burner's job is a new address and login for every site, burned when it spams. It is a daily pain that people now solve with two or three products, and Burner does it in one tap, free and unlimited. Privacy is the reason to trust it, not the reason to open it. Bot rides second: *free AI on your phone that never leaves it* is an easy, no-cost try. The Burner email does the reactivation, and the Bot email is a second reminder.

**The steelman.**

- **The job is validated across sources.**
  - The T77 workflow (alias service, password manager, burner inbox).
  - addy.io's whole headline: "A different email address for every website" (SO KQ3).
  - "Solved my whole spam problem" (addy.io's user line) and "saved my email from endless spam" (C19).
- **Burner collapses the kit.** "Works with Bitwarden" (SO KQ3) is the seam the market lives with, and Burner removes it.
- **Free that is enough is how the winners grew** (C55, C56, C07), and Burner's free plan is uncapped where the others stop at 10.
- **Adoption can be parallel.** "using Proton Pass alongside it as it matures" (C06): start with new sign-ups, no migration needed.
- **The reminder is the treatment** (RE §2.1), and a useful new tab is a reason to open the app at all.
- **Local AI is a no-risk try.** "Locally-run, native app, means beauty and privacy. I would pay for that. Happily." (CC section 4)

**Where H2 fails.**

1. **The job's moment of truth is the verification email, and a phone alone may miss it.**
   - D §15.6, item 4: the apps "listen only while open, so each ... catches only a retry that lands in that window".
   - The alias user's central fear is exactly this: "I can’t afford to wake up one day only to realize my aliases aren’t functioning." (C12)
   - A failed first sign-up confirms why many readers left: disconnects and connection failures top URnetwork's support inbox (RE §11.1).
2. **The fix costs what this market won't pay.**
   - An indexer enclave costs "tens of dollars a month at the 1.20 markup" (C §11.10). SimpleLogin is $36 a year, addy.io $1-3 a month and Pass Plus $1.99-4.99 (SO KQ3).
   - An always-on computer is free, but this list mostly lives on phones (section 3).
3. **The launch scope narrows the job.** Burner launches receive-only at M8; sending comes at M9 and search at M10 (D §15.17). Reply is the alias feature users single out (C13).
4. **The password half starts empty and fights a free default.**
   - I found no import path in D or UI. Import makes moves painless (C58), and its absence blocks them: "If you are using only an iPhone, there is no way to import the files the you can export from safari." (C03)
   - "Apple Passwords for $0 is a pretty easy switch" (T82).
   - Autofill is where managers are judged: it comes up in 10% of Proton Pass and of Bitwarden App Store reviews (CR keyword table).
5. **The address can fail at the form.**
   - T71, T73 and T74 explain how alias domains get blocked, and Burner matches the risk profile on every count. It is free and unlimited with no pace limit (Q-UI-41), and it will later send from shared addresses (D §15.9).
   - Its addresses all sit under one suffix with word-number labels, the product is named Burner, and the list already draws sign-up farms (PLAN §3).
6. **Bot's "free" is the weakest model class.** Phones with 6 GiB+ get Gemma 4 E2B, a 2.59 GB download (C §6.5). Capability is the reason to leave (C92, C98). Bot as designed is "a harness cli optimized for mobile" (UI-1), and its page demo runs `go test` and `git push origin fix/limiter-burst` (SITE). A lapsed consumer can't see themselves in it.

**What the revision must fix:** the first try must succeed on the reader's own device. Segment by what the device can do, and give Bot a consumer job beyond "free".

### Round 3: the first try works on the devices you have

**H3.** The relaunch wins the readers whose first try succeeds on devices they already have.

- **Burner on a phone alone** leads with what works there: a login, code and passkey for each site, which need no mail, plus addresses for mail that can wait.
- **Burner with a computer left on, or a paid enclave,** is the full private inbox.
- **Bot** leads with a consumer job the private-AI market fails at: a free AI on your phone whose chats are saved so only your devices can read them, and which follow you between devices.
- **Copy** states the job, the price ("free") and the limits as consequences.
- **Success** is a completed first job, not an open.

**The steelman.**

- It matches every praise pattern in the corpus: free that is enough (C55), honesty (C154, C155), and daily reliability (CR).
- It leads with the one gap private AI concedes. Venice's E2EE tier has "−No web search or memory" (SO KQ2). Users ask for "a way to save chats to continue the same conversations on multiple devices" (C111) and pay for synced history (CC section 4).
- It uses the architecture where it shines. New Windows networks pay at 10-18% within 14 days against Android's 0.07-0.25% (ORM §3.2), so computer users are where the value is. A computer left on makes Burner fully reliable and fully private.
- It turns the limits into trust: "Plainly stated admissions are rarer and stand out" (SO KQ5).
- It is measurable: a product action has a near-zero base rate in the holdout, so even small lifts show.

**Where H3 fails.**

1. **The phone segment's job is weak.**
   - *Addresses for mail that can wait* is spam control for newsletters and receipts: real (C19), but not urgent enough to bring someone back.
   - The login half meets Apple Passwords at $0 (T82) and incumbents' switching costs ("such an endeavor would also likely be pretty painful", C40) with no import.
2. **The computer segment may be tiny, and "a computer" isn't enough.**
   - Windows sign-ups run in tens a week (ORM §3.2).
   - Only an always-on, designated device receives "any time": "no app is one, since apps run their sidecar only while open" (D §15.6, item 3). A laptop that sleeps is not one.
3. **Bot's consumer job still meets the capability wall.**
   - A small on-phone model answers simple things.
   - The step up (TEE models, enclaves, search) is pay-as-you-go credits, the billing model behind the category's angriest reviews (A34, A35, C118, C119).
   - A search that fails after payment still costs (C §21.6).
4. **AI news can cost the list.** Win-back mail already unsubscribes at "3.4× regular campaigns" (RE executive summary). The AI-consent backlash (T61, C82, C90) can push the Bot email toward the 0.08% complaint stop line (PLAN §3).
5. **H3 optimizes the smaller prize.** The largest consumer opening, the trust-shock leavers (section 1.3), can't be reached by these emails at all.
6. **The house metric can't see H3's success.** `reactivation_7d` counts a `connect.day` (RE-PLAN L39). A reader who returns for Burner or Bot without connecting the VPN scores as not reactivated.

**What the revision must fix:** separate what the emails can do (a reminder with a job that works) from what the pages must do (win the leavers). Change the metric to see product use. Keep Bot narrow.

## 5. The final hypothesis, and what would prove it wrong

**Final hypothesis.**

1. **The emails.** The relaunch emails are reminders with a reason. They will bring lapsed readers back only where the reason is a job that works on the first try on the reader's own device, and only if the copy states the limits before the click.
2. **Burner's reason** is a new address and login for every site, burned when it spams. It works in full on a computer left on with URnetwork running, or with a paid enclave, and in part on a phone alone: logins and codes always, mail only when it can wait.
3. **Bot's reason** is a free AI that keeps your words on your device, with chats saved so only your devices can read them, for readers whose phone or computer can run it.
4. **Privacy is the proof, not the pitch,** for this list.
5. **The pages.** The market's largest consumer opening, 2026's trust-shock leavers, is reached by ur.io's Burner and Bot pages and the content around them, not by these emails. So the pages must lead with guarantees and admissions: who can read what, what URnetwork could be made to hand over, and what happens when you lose a phone.

**Predictions, and what would prove each wrong.** The thresholds are proposals, to be fixed before the send from the sizing probe and a power calculation.

| # | Prediction | Test | Wrong if | Then |
|---|---|---|---|---|
| P1 | Both emails beat the 20% holdout on a product action | First Burner address, and a first local-model chat, within 14 days, campaign against holdout (aggregate counts) | No lift beyond the minimum detectable effect, and no lift in any return to the app within 90 days | Burner and Bot are not a reason to come back. Treat them as acquisition products and stop the relaunch framing |
| P2 | A job-led opening beats a privacy-led one | Split the treated Burner readers 50/50: (A) the job-led draft in 6.2, (B) the current privacy-led opening with the subject "Email only your devices can read" (32 characters). Measure first addresses in 14 days | B wins at significance | The privacy motive is alive on this list, so Round 1 was right on the lead. Lead with privacy |
| P3 | The receiving limit decides Burner's first job | Among networks that made a first address, the share with a first message within 24 hours, always-on receivers against phone-only (aggregate, from what servers already see, D Appendix G) | Phone-only readers reach at least 80% of the always-on rate | The limit binds less than the design says. Soften the limits line, but keep it true |
| P3b | Same | Same | Phone-only first-mail-in-24-hours is under 50% | Burner on a phone alone isn't a mail product yet. Send the full pitch only to always-on networks, or fix receiving first |
| P4 | Bot's local try becomes repeat use | Among openers whose device can run a model: download finished, a first chat, and a chat on a second day within 14 days | Under 20% finish a first chat, or under 10% chat on a second day | Free private AI is not a job for this list. Drop Bot from re-engagement and keep it for acquisition |
| P5 | AI news doesn't cost the list | The Bot email's unsubscribes and complaints against the Burner email's and the house stop lines (unsubscribes 0.8%, complaints 0.08%) | Unsubscribes at 1.5 times the Burner email's or more, or complaints at the stop line | AI news hurts this list. Stop the Bot email and use in-app news instead |
| P6 | Burner addresses get accepted | A fixed panel of the sign-up sites readers use most, tested monthly with a fresh address from launch | More than 1 in 10 reject it within 3 months | The alias job fails at the form. Pause the Burner push and fix before scaling (section 6.6) |
| P7 | Some phone-only readers pay for an always-on receiver | Indexer creation after the B10 prompt | Near zero | Consumer Burner needs a cheaper receiver before it can be the private inbox |

**Power, as a check on what *no lift* means.** This is my arithmetic: 80% power, two-sided 5%, a 1.5% base and a 20% holdout. With 10,000 readers the smallest detectable lift in `reactivation_7d` is about 0.85 points; with 40,000 it is about 0.43. Product actions start from a near-zero holdout base, so they detect much smaller lifts, which is one more reason to make them primary here. P2's 50/50 split of 8,000 treated readers detects about 1.4 points on a 5% first-address rate. On a small list, read it as directional.

## 6. What it means for the two emails and the two pages

### 6.1 The split: emails for the lapsed, pages for the leavers

The email button opens the app at the tab, via the reader's token link. So email readers meet B2, Burner's first run, and T4, the models list, not the page. The pages are read by people who look the product up, which is where the leavers are (section 1.3). Write each for its reader:

- **The emails** lead with the job, say "free", and state the limits as consequences.
- **The pages** lead with guarantees and admissions, and keep the architecture they already explain well.

### 6.2 The Burner email (relaunch_1_burner)

| Line now | Verdict | Why | Change |
|---|---|---|---|
| Subject "A new address for every site" (28 characters) | Keep | Job-led and plain: the T77 and addy.io job | None |
| Preheader "Burner is in the URnetwork app: an address for every site, its login beside it, and mail only you can read." | Keep | Job first, then the proof | None |
| p1 "You came to URnetwork to keep your browsing private. Now the app keeps your inbox private too, with Burner." | Change | Asserts a motive the evidence says lapsed readers mostly didn't have (RE §9.3, A1) | Open with the job: p1 below. Keep this line as arm B of the P2 test |
| p2 "Burner gives every site its own email address ... burn it and the mail stops." | Keep, move up | This is the job, and it is the paragraph to lead with | Merge into the new p1 and p2 |
| p3 "Burner's mail server runs on your own device, so only your devices can read your mail. It's in the free plan, with as many addresses as you want." | Keep | Proof plus the price basics (PLAN §6: what it does, what it costs, how it keeps you safe) | Split: "free" moves next to the job |
| p4 "Two honest limits: senders keep their own copies, and on a phone, mail arrives while the app is open. Add an encrypted enclave, or run URnetwork on a computer, and it arrives any time." | Change (truth at send time) | "Two honest limits" is the most distinctive line in the email: keep it. But "mail arrives while the app is open" reads as *open the app and your mail comes in*. D §15.6 says a phone "catches only a retry that lands in that window" and "may miss time-sensitive codes". "run URnetwork on a computer" isn't enough: only an always-on, designated device receives any time (D §15.6, item 3). The enclave is paid, "tens of dollars a month" (C §11.10). Saying "paid" is not a price, so the never-paid rule allows it | p4 below |
| Button "Open Burner" | Keep | It says what happens | None |

**Proposed text** (130 body words, against the house's 150; subject unchanged):

> The URnetwork app now has Burner. It gives every site you sign up to its own email address, made in one tap, with that site's password, one-time code and passkey kept beside it.
>
> If a site leaks the address or sends spam, burn it and the mail stops. Burner is in the free plan, with as many addresses as you want.
>
> Its mail server runs on your own device, so only your devices can read your mail.
>
> Two honest limits: senders keep their own copies, and a phone takes mail only while the app is open, so a sign-up code can come late or not at all. A computer you leave on with URnetwork running, or a paid encrypted enclave that a provider hosts, receives mail any time.
>
> [Open Burner]

**Add to `manifest.json` `needs`:**

- The limits line matches D §15.6, item 4, on the send date.
- "A computer you leave on with URnetwork running" is what designates a receiver on the send date. Today that means an always-on daemon, not the desktop app alone (D §15.6, item 3). Reword the line if the qualifying setup differs.
- The enclave is still paid (C §11.10).

**Segment, using what the server knows** (platform and devices per network, PLAN §3):

- Networks with an always-on receiver get a variant whose limits line drops the phone clause.
- Phone-only networks get the text above.
- In-app, B2's first run should suggest a first address for mail that can wait, such as a shop or a newsletter. Before the first burner, it should show the `foreground-only` copy the design already requires (D §15.9).

### 6.3 The Bot email (relaunch_2_bot)

| Line now | Verdict | Why | Change |
|---|---|---|---|
| Subject "AI that stays on your phone" (27 characters) | Keep, but target | True only where the phone can run a local model: phones with 6 GiB+, a 2.59 GB download (C §6.5) | Send it only to readers whose last device can run a model (the server has the device model, ORM §3.2). Give computers a variant: "AI that stays on your computer" |
| Preheader "Free AI on your own device, an encrypted enclave for your agents, and a record only you can read." | Change if p6 goes | Three ideas, the last a developer feature | "Free AI that keeps your words on your device, chats only your devices can read, and an enclave when you need more." |
| p1 "...a private AI that runs on your phone, your computer, or your own encrypted enclave." | Keep | The owner's rule: the enclave in the first line (PLAN §4) | None |
| p2 "Local models are free, and with them, what you type never leaves your device." | Keep, extend | The consumer hook. Add sync, the gap the market concedes (section 1.3, opportunity 3) | Add: "Your chats are saved encrypted, so you can pick one up on another device, and only your devices can read them." True for a personal network (UI-8; C §24.7). In a team, Q-UI-24's audit reader applies |
| p3 "Your enclave is a private computer for your agents in the cloud, on a provider's TEE hardware..." | Keep, small fix | "Your enclave" presumes the reader has one, and it is paid | "An enclave is a private computer in the cloud, on a provider's TEE hardware..." |
| p4 "Bigger models run on TEE hardware too, and Bot shows where your words go before you send them." | Change (rule) | PLAN §6: a TEE model is named "each with its disclosure ... who runs it and what the hardware check covers". This line gives neither | "Bigger models run on a provider's TEE hardware, which proves the machine, not the code that reads your words. Bot shows where your words go before you send them." (Q-OB-10's decided wording) |
| p5 "...Parallel, the search provider, reads each search and may train on it, but never learns who asked." | Change (truth) | The design names two readers: "Parallel, whose keyless gateway answers web searches, and Vercel, which hosts it, both reading each query, never who asked" (C L260, L288). The Bot page already says so (commit 8caa68aa). The email and its manifest still name only Parallel | "Bot can search the web too. Parallel, the search provider, and Vercel, which hosts its gateway, read each search, and Parallel may train on it. Neither learns who asked." |
| p6 "Bot records each command your agents run, file they change and approval they ask for..." | Move to the page | The house's one-idea rule. It is the developer story, which the Bot page and the Team and CLI campaign already tell | Drop it from this email, and drop its `needs` item |

**Proposed text** (146 body words):

> The URnetwork app now has Bot, a private AI that runs on your phone, your computer, or your own encrypted enclave.
>
> Local models are free, and with them, what you type never leaves your device. Your chats are saved encrypted, so you can pick one up on another device, and only your devices can read them.
>
> Bigger models run on a provider's TEE hardware, which proves the machine, not the code that reads your words. Bot shows where your words go before you send them.
>
> An enclave is a private computer in the cloud, on a provider's TEE hardware. It keeps your agents working while your phone sleeps, and its keys are made inside it.
>
> Bot can search the web too. Parallel, the search provider, and Vercel, which hosts its gateway, read each search, and Parallel may train on it. Neither learns who asked.
>
> [Open Bot]

**Add to `needs`:**

- The TEE line carries what the hardware check covers.
- The search line names every reader of a search.
- Chats resume on another device in the release (UI-8; C §24.7).
- The reader's last device can run a local model.

The 2.59 GB download doesn't fit in 150 words. T4 and the page should state it ("use Wi-Fi").

### 6.4 The Burner page (ur.io/burner)

Keep: "Email only you can read", which suits a page read by privacy leavers; "Private by construction ... Not a promise to look away"; "How mail reaches you"; "Burn one and only that site loses you." These are the proof-versus-promise move that no alias seller makes (SO KQ3).

| Current (SITE) | Issue | Evidence | Proposal |
|---|---|---|---|
| Hero "fully encrypted, fully searchable email"; the card "Full search"; the step "Read, search and reply" | Outruns the launch: Burner launches receive-only at M8, replies at M9, search at M10 | D §15.17; PLAN §6 "Claims wait for their milestone". The owner asked for "fully searchable" (UI-17) | Keep the words but publish them with M10 (search) and M9 (reply), or move search into Burner's first release as Q-OB-10 did for Bot. Until then: "Read your mail. Every stored copy stays sealed." |
| "If none of your devices is receiving, the sender tries again for hours or days. An indexer, an always-on computer of yours or your own secure enclave, receives at any hour." (under "How mail reaches you") | True, but far from the button, and silent on cost | D §15.6, item 4; C §11.10; C12's fear | Also put it beside Open Burner: "On a phone alone, mail can come late, so a sign-up code may expire. A computer you leave on with URnetwork running, or a paid secure enclave, receives at any hour." |
| (missing) "If you lose your phone" | The top account-level fear, and E2EE raises the stakes | C83, C89, C45, C74; CR "Recovery design and human appeals matter as much as cryptography" | One block: how mail and logins come back after a lost phone (from DESIGN's recovery path), and that the Support tab reaches a person (S1). No new promise beyond what the design does |
| (missing) "What we could be made to hand over" | The strongest mail pay signal, and rare candour | T89 "would go to jail for me"; SO KQ5 "Law-enforcement candour, 3/22"; Tinfoil's FAQ as the model (SO KQ2) | One block from the trust page's list of what URnetwork's servers see (D Appendix G): sealed bytes no key of ours opens, and the metadata, stated plainly |
| (missing) linkability | Alias users assume unlinkability (A3) | D §15.9 "They are linkable through `<net>`"; the SimpleLogin user line (SO KQ3) | An honest-limit line, the owner's call: "Your addresses share your network's name, so sites that compare notes could tell they're yours." |
| (missing) account without email | A praised Mullvad principle the page can claim | C153, C156; seed-phrase accounts are URnetwork's default (ORM §3.1) | "Your URnetwork account needs no email address or phone number." |
| "Make Burner your password manager to fill them anywhere." | Fine. But without import, don't say "switch" | C58, C03 | No copy change. Import is product work (section 6.6) |

### 6.5 The Bot page (ur.io/bot)

Keep and move higher: "Where your words go". It is the plainly stated admission that stands out in this market (SO KQ5, "Venice's minus signs") and the direct answer to T62, T66 and T67. Keep the team-admins line (Q-UI-24).

| Current (SITE) | Issue | Evidence | Proposal |
|---|---|---|---|
| H1 "A fully private bot" | The page's own table contradicts "fully" for TEE ("Only the provider"), direct ("The model's provider") and search ("Parallel, and Vercel"). It is the owner's phrase (UI-1) | Buyers "read claims closely" (SO KQ5); "I don't agree that this is end to end encrypted" (T66); NEAR AI's TEE incident (SO KQ2); the Q-OB-10 precedent, "Reword to what's checked" | The owner's call. Recommended: "A private bot", with the subline doing the work: "Free models that never leave your device, larger ones on TEE hardware, and a plain table of who can read what." |
| Hero "remote ones sealed inside TEEs" | Outruns the decided disclosure | Q-OB-10: "proves the machine, not the code that reads your words. The provider is trusted not to attack it." | "...or larger ones on a provider's TEE hardware." |
| Hero "Search the web privately." | PLAN §6's claims table bans "private web search" unqualified | PLAN §6; C L260 | "Search the web without saying who you are." The card's body is already qualified |
| Hero demo: the agents' feed (`limiter-fix`, `git push origin fix/limiter-burst`) | A developer story leads a consumer page | UI-1's harness design; leavers from ChatGPT and Lumo want a private chat (C100, C101) | Lead with a local chat on a phone, badged "on this device", and move the agents' feed to the second section |
| (missing) a sync card | The gap private AI concedes, and a proven reason to pay | The Lumo+ quote (CC section 4); C109-C111; Venice's E2EE tier "−No web search or memory" (SO KQ2) | Card: "Your chats follow you. Saved encrypted, picked up on any of your devices, readable only by them." (UI-8; C §24.7) |
| "Local models ... free, and nothing leaves the device." | Missing the basics | C §6.5: phones with 6 GiB+, a 2.59 GB download | Add: "Needs a phone with 6 GB of memory. The first model is a 2.6 GB download." |
| Paid parts | Credits anger is the category's sharpest complaint | A34, C118, C119; C §21.6, a failed search still charged | Show each paid part's price where it's named (TEE per million tokens, enclaves by the hour, search "about a cent", as the page already does). Either stop charging for failed searches or say so |
| (optional) consent and agents near passwords | AI-injection backlash; agents and credentials | T61, C82; Bitwarden "AI agents are leaving your secrets in chat history." (SO KQ3) | Only if true at launch: "Bot never reads your Burner mail unless you choose a model for it" (Q-UI-42). "Bot's agents are refused your Burner passwords": a rule the apps enforce, not a key (D §15.8, owner decision 440). Say it that way |

### 6.6 Product work the copy can't fix

1. **Receiving on a phone alone.** This is the hypothesis's biggest risk. It can't change by mid-December.
   - Recommended for the relaunch: state the limit (6.2), point first-run phone users at mail that can wait, and measure P3.
   - Recommended for the product: price a consumer receiver near the alias market, or Burner stays a computer-first inbox. The design keeps any URnetwork component from seeing plaintext, so the edge can't queue (D §15.6). The answer has to be a cheaper always-on receiver, not a server-side mailbox.
2. **Blocklisting.** Run P6's acceptance panel from launch. Bring back the pace limit that Q-UI-41's recommendation proposed (3 a day on Community, 50 on Pro) as soon as the panel or abuse reports show trouble, and decide that trigger before launch. The research supports custom domains on personal networks as the lasting fix (T72); today they are Team-only.
3. **Import.** Add password import from the managers people already use, CSV at the least. C58 against C03 shows it decides who can switch.
4. **Charging for failure.** Refund searches and calls that fail. The design charges a search "that fails after its payment settles" (C §21.6), and A34 and C118 show what that costs in trust.
5. **The metric.** For these two emails, make the primary measures product actions, read against the 20% holdout: a first address, a first message received, and a local model used on two days. Keep `reactivation_7d` and the 90-day read as secondary. Check whether opening Burner or Bot creates a `connect.day` at all.

### 6.7 Questions for the owner, each with a recommendation

| Id | Question | Recommendation |
|---|---|---|
| Q-CH-1 | Open the Burner email with the job instead of "You came to URnetwork to keep your browsing private"? | Yes, and test the current line as arm B (P2) |
| Q-CH-2 | Reword Burner's limits line to "a phone takes mail only while the app is open, so a sign-up code can come late or not at all", with "a computer you leave on" and a "paid" enclave? | Yes. The current line is true but reads wrong against D §15.6 |
| Q-CH-3 | Add Vercel to the Bot email's search line and the manifest's need? | Yes. The design and the page already name it (C L260) |
| Q-CH-4 | Give the Bot email's TEE line what the check covers? | Yes. PLAN §6 requires it |
| Q-CH-5 | Drop the agents' record paragraph from the Bot email? | Yes. It stays on the page and in the Team and CLI campaign |
| Q-CH-6 | Send the Bot email only to readers whose device can run a local model, with a computer variant? | Yes, from the device model the server already records |
| Q-CH-7 | Hold "fully searchable" and "reply" on the Burner page until M10 and M9, or move search into the first release? | Hold them until they ship |
| Q-CH-8 | Bot page: "A fully private bot", "sealed inside TEEs" and "Search the web privately"? | Reword all three to what's checked, as in Q-OB-10 |
| Q-CH-9 | Add "lose your phone", "what we could be made to hand over" and the linkability line to the Burner page? | Yes to the first two. The linkability line is recommended, as an honest limit |
| Q-CH-10 | Product-action metrics as primary for these two emails? | Yes |
| Q-CH-11 | A trigger to bring back the address-creation pace limit? | Yes, decided before launch and tied to P6's panel and abuse reports |

## 7. Limits of this analysis

- The corpus is an enthusiast, US-heavy sample. The lapsed list is international and phone-heavy (section 3). The hypothesis is built to be tested on the list itself, and the predictions in section 5 are how.
- The study behind "privacy-motivated users stayed" is small (90 people, 7 quitters). It is a strong caution, not a measurement of this list.
- I found no password import in DESIGN.md or DESIGN-UI.md by searching for import with vault, password and CSV. If it exists elsewhere, P2's second failure point weakens.
- The power figures are illustrations. The audience size is unknown until the sizing probe runs (PLAN §3).
- Thresholds in section 5 are proposals to be set before the send, not results.
