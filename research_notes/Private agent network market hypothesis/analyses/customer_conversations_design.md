Paths: OB `mmm/outbound/PLAN.md`, RE `mmm/reengagement/PLAN.md`, ORM `mmm/ONBOARDING-RETENTION.md`, CR/CO `config/main/reengagement.yml`/`onboarding.yml`, RUN `factury/support/RUN-MAIN.md`, FB `sidecar/FEEDBACK-SYSTEM.md`.

**Two constraints.**
- **Nothing can send a new campaign email until the outbound stream exists** (OB:118). Before launch, only people who write in can be asked.
- **The support inbox isn't private.** An AI support agent works it (RUN:3), a hosted model reads it (FB:238), and git keeps it forever (FB:384). It can carry the scheduling, never the conversation.

## 1. Sources, in order

1. **Support-inbox correspondents, from now on.** When someone writes about desktop, the CLI, teams or trust, add one line to the reply they're owed (RUN:451). Not the backlog: writing again to people already answered needs the owner's go each time (`factury/support/plans/top200-opening-replies-2026-11-16.md:3`), and would be a campaign without its rules.
2. **The "Tell me when Team launches" box** (OB:208, not built). Add a separate, unchecked "I'd talk to Brien first" box. Its consent is explicit (RE:184), it is recorded as `opt_in` (RE:174), and it reaches non-users. Interviewees stay out of the launch's randomization, like other tests' readers (OB:80).
3. **Role-pickers in `team_1_launch`.** The ask sits on the first-party role page, so the email keeps one idea (OB:142). The holdout never sees that page (OB:96). Report interviewees separately in the 21-day readout.
4. **Teams created in launch week.** A Team-screen card (`sidecar/DESIGN-UI.md:188`), not email: holdout networks create teams too and may not be mailed (OB:96, 104). The measured outcome has already happened.
5. **Replies to `team_3_reply`.** They wrote first.
6. **Lapsed readers who come back to Burner or Bot, or who reply.** Only after the merge and after `reengage_lapsed_1` ends (OB:198). An on-device card (RE:112-114), shown once they're back, keeps the 90-day measure clean. Until then, ask no one in:
   - stream L (50/50, no stop date, CR:399-404);
   - stream W (20% holdout, CR:461-466);
   - an open episode;
   - onboarding, while its three tests run to 12-22 (CO:542-643).

   The owner held back P8 for the same reason (ORM:483, 505).
7. **The Support tab, once built** (FB:3). Invitation only: support reads the whole thread, and a Team's auditor can open it (`sidecar/DESIGN-COMPUTE.md:310`).

**Never ask:**
- CN, RU, IR, CU, KP or SY (CO:444);
- the EU, EEA, UK or CH without consent evidence, or an unknown country (CO:454-456);
- bot-labeled networks (OB:80);
- R2 "switched" or "not needed" answers (RE:93-94);
- anyone who self-identifies in a sanctioned region (RUN:579-589);
- anyone found through a broker (OB:204).

## 2. Mechanics

- **The ask.** `team_3_reply` gains: "or say you'd rather talk for 20 minutes, in English, and I'll send times." The role page gets an optional second button. It saves only when pressed (OB:94), is recorded like `keep` (RE:169), and is used only to arrange the call, as OB:180 limits the role. The page says: "I'll write from support@ur.io within two working days. Replies reach our support inbox, where an AI helps sort mail. The call is just us."
- **Routing.** The support agent queues each yes for the owner (RUN:59), sends only a true holding line ("Brien will write to you himself"), and never schedules. A button press becomes an inbox item through a small new `support update` source, so every email follows the reply rules (RUN:453-474).
- **Scheduling.** By email, with no booking tool. Brien offers three times and a channel: phone, Signal, FaceTime, or the reader's company tool with recording, transcription and AI notes off. The thread holds only the time and the channel.
- **The call.** 20 minutes. It opens with what is noted, where, and when it's deleted. Quotes are used only unnamed, and only with a yes. There's no recording, transcription or AI note-taker, and no hosted model reads the notes. "Talk to Brien" stays true only while Brien takes the calls.
- **Notes.**
  - One file per call, named by a code (T-SEC-03), with no name, email or company in it.
  - Files sit in an encrypted folder on Brien's device, outside every repo.
  - The key from code to contact is kept separately.
  - Both are deleted at 90 days, or on request, as the consent outreach deleted its lists (`factury/support/plans/consent-outreach-2026-11-17.md:5`).
  - Only de-identified findings go into git. The notes move into encrypted storage once it ships.

## 3. Incentives: none

- **Discounts and credits.** Never-paid readers get none (RE:5, 225). A free Team month ($10, OB:45) is worth what the welcome offer saves on a $40 Pro year (ORM:35, 239), and that offer was promised never to return (RE:15, 123).
- **Gift cards.** A vendor would learn who took part, money can't go to sanctioned regions (RE:18, 188), and they would attract sign-up farms (`mmm/onboarding/README.md:143-152`).
- **The thanks.** A note when what they raised ships, promised only if it will be sent: R3's promised note never went out (ORM:484, 506).
- **Optional:** a fixed, anonymous donation per call to a privacy nonprofit touches no offer rule.

## 4. How many, how often

| Group | Calls |
|---|---|
| Team, after launch | 5 per role (developers, product, IT and operations, security), split between team creators and role-pickers with no team |
| Team, before launch | up to 3 per role, security first, against the draft trust page (OB:98, 174) |
| "Something else" | up to 3, to find the role the list misses |
| Burner and Bot | 5 each who came back, 3 each who replied but stayed away |

- **Take every volunteer:** R2 drew 3 answers from 242 sends (ORM:277-278).
- **Stop a role** after two calls in a row add nothing new. Guest, Bunce and Johnson (2006) reached saturation within 12 interviews, with its outline by 6.
- **Pace:** at most 4 calls a week, and one per person per year. Invite each person once, with no reminders.

## 5. Note template

```
Code, date, minutes, channel, source (1–7), phase
Role (own words), team size, platform, plan, country group
Told: notes only, no recording, deleted <date>. Unnamed quotes OK? Y/N
Hypothesis: <OB:22, or the relaunch's OB:110-114>
1 What they run; where agents run; how machines connect now
2 Last time it hurt: one real, dated story
3 What they use and pay; who signs off on security; what they ask vendors
4 Their role's line (OB:58-63), read after the story: understood, doubted, tripped on
5 Team price reaction (no price to never-paid Burner or Bot readers)
6 Top objection, verbatim
7 What would make them try, or come back
8 Shown or said: installed, paid, created a team?
9 Change proposed: string key; OB section or Q-OB; product
10 Promise made (only if it will be kept)
```

## 6. Feedback

- **Weekly:** a de-identified table of objections by role and source.
- **What it can change:**
  - Team copy: the role labels (`email_ob_role_*`) and their pages (OB:94), each role's opening line (OB:58-63), `team_2_follow`, and `team_3_reply`'s three reasons;
  - the Team plan: price (Q-OB-5), seats (Q-OB-9), audience (Q-OB-3), the forward line (Q-OB-12), the trust page (Q-OB-1) and `matrix.json`;
  - the relaunch: Burner's limits line, Bot's disclosures (Q-OB-10) and the wave order (OB:110).
- **The owner decides.** Each finding becomes a question, Q-OB-13 onward, with a recommendation, and the answer is recorded word for word (OB:171). So does section 2's line about AI in the inbox.
- **What stays fixed:**
  - Copy still passes `build.mjs check` (`mmm/outbound/README.md:37`), waits on its `needs`, and avoids the banned words (OB:144-167).
  - No running test's treatment changes.
  - Conversations explain; the holdout readouts decide (OB:96, 114).
  - Bugs go to known-issues (RUN:488).
