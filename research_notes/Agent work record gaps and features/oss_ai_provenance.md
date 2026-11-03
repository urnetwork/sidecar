# OSS AI contribution provenance and disclosure: policies, maintainer asks, attribution tools, and the pressure to remove attribution (state as of 31 October 2026)

Method notes for the report writer:
- Collected 31 Oct 2026 from policy files (read from source repositories where I could), mailing-list commits, maintainers' blogs, GitHub issues and discussions (read with `gh`), Hacker News (Algolia API), and vendor documentation.
- "Policy text" means the project's own document. "Commentary" means press, blogs or forum posts about it. "Vendor claim" means a statement a company makes about its own product.
- Pages that did not load:
  - The Fedora docs site served an Anubis bot-check page. Fedora quotes therefore come from Fedora's Community Blog, GamingOnLinux and a search-tool extract.
  - `github.com/cursor/agent-trace`, the canonical Agent Trace repository named on agent-trace.dev, returned HTTP 404 to WebFetch. The GitHub API returned "Could not resolve to a Repository" on 31 Oct 2026.
  - `book.servo.org/contributing.html` returned 404, so I read the Servo policy from the `servo/book` repository.
  - WebFetch of debian.org failed with ECONNRESET, so the Debian page was read with curl.
  - WebFetch could not decode the OpenJS policy PDF, so its text was extracted with pdftotext.
  - LWN's Maintainers Summit article was read through a subscriber link. Most remarks in it are LWN's paraphrase, not verbatim quotes.

## 1. Which notable OSS projects adopted AI contribution policies in 2024–2026, and what do they require?

### Takeaway
By October 2026 almost every major project had a written policy. They fall into three groups:
- **Bans:** Gentoo, NetBSD, QEMU, Servo, Zig, and GNOME's extension store.
- **Disclosure plus human accountability:** Ghostty, LLVM, Fedora, Node.js/OpenJS, Mesa, curl, and the Linux kernel.
- **Disclosure encouraged but optional:** Debian, CPython, and curl for pull requests.

The common core is the same everywhere. A human must understand and answer for the code. Only a human may sign the DCO. Autonomous agents may not open PRs. Commit trailers are a minority mechanism (`Assisted-by:` or `Generated-by:`), and they are retreating. The Linux kernel added `Assisted-by` in December 2025, removed the model name in July 2026, and removed the tag entirely in October 2026 because only about 10% of commits carried it. Mesa and Node.js now explicitly discourage naming the model or brand in commits.

### Cited Findings

#### Linux kernel
- **Dec 2025, policy text.** `Documentation/process/coding-assistants.rst` was added by Sasha Levin in commit 78d979db6cef, dated 23 Dec 2025 ([GitHub commit](https://github.com/torvalds/linux/commit/78d979db6cef)). LWN says the tag "was introduced with the coding-assistants documentation in 7.0" ([LWN, 12 Oct 2026](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)).
- **DCO rules, policy text, still in force.** "AI agents MUST NOT add Signed-off-by tags. Only humans can legally certify the Developer Certificate of Origin (DCO)." The human submitter is responsible for "Reviewing all AI-generated code", licensing compliance, "Adding their own Signed-off-by tag", and "Taking full responsibility for the contribution" ([kernel.org coding-assistants.rst](https://www.kernel.org/doc/Documentation/process/coding-assistants.rst)).
- **19 Jan 2026, policy text: tool-generated content.** Dave Hansen added `generated-content.rst` in commit a66437c27979 ([kernel.org generated-content.rst](https://www.kernel.org/doc/Documentation/process/generated-content.rst)). It asks contributors to "be transparent about the origin of content in cover letters and changelogs" by stating:
  - "What tools were used?"
  - "If code was largely generated from a single or short set of prompts, include those prompts. For longer sessions, include a summary of the prompts and the nature of resulting assistance."
  - "How is the submission tested…"

  Maintainers may "Reject it outright" or review it "at a lower priority than human-generated content". "If tools permit you to generate a contribution automatically, expect additional scrutiny in proportion to how much of it was generated."
- **1 Jul 2026, policy change: model name removed.** Christian Brauner's commit 816d9992d9ed (committed 3 Aug 2026) changed `Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]` to `Assisted-by: LLM`. The commit message gives the reason: "The requirement to identify specific models used in the Assisted-by tag provides free advertising to proprietary software companies while adding little or no useful information." ([GitHub commit](https://github.com/torvalds/linux/commit/816d9992d9ed))
- **8 Oct 2026 Maintainers Summit, commentary (LWN paraphrase).** The requirement to add Assisted-by tags "will be removed", with "strong consensus in the room that the tag had outlived any purpose it may have had" ([LWN, 12 Oct 2026](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)).
  - For 7.3 through -rc7 there were 18,533 non-merge changesets, of which 1,884 (about 10%) carried Assisted-by.
  - Dave Airlie estimated "probably 90%" of contributors now use LLMs. Many contributors fear an "anti-LLM witch hunt".
  - Torvalds said the requirement might scare people away from using LLMs.
  - Maintainers still want to know how a patch was created, but in the cover letter, not the changelog.
- **13–14 Oct 2026, policy text: tag removed.** Sasha Levin's commit 1e035297ffda, "docs: remove Assisted-by references", was committed by Jonathan Corbet on 14 Oct 2026. GitHub's compare API on 31 Oct 2026 shows it is in torvalds/linux master. It removes the Assisted-by sections, their translations, and the checkpatch handling ([GitHub commit](https://github.com/torvalds/linux/commit/1e035297ffda)). Its message says:
  - "Some contributors do not know about the rule, others leave the tag off on purpose, and few maintainers ask about it. As a result, the tag does not provide the signal it was kept for: its absence says nothing about how a patch was made, and for developers who use these tools for almost everything, its presence says little more."
  - Greg Kroah-Hartman "who argued for keeping the tag in July, supports removing it now".
  - The DCO rules and `generated-content.rst` are unchanged.
- **Caveat.** The rendered page at docs.kernel.org (labelled 7.3.0) still showed the Assisted-by section when fetched on 31 Oct 2026 ([docs.kernel.org](https://docs.kernel.org/process/coding-assistants.html)). It reflects the 7.3 release, not current master.
- **Commentary on the removal.** One outlet calls it a decision to "retire" the tag, citing The Register (14 Oct 2026) and Phoronix ("Plan To Remove") ([LetsDataScience, 15 Oct 2026](https://letsdatascience.com/news/linux-kernel-drops-ai-disclosure-requirement-for-contributio-952abe36)).

#### LLVM
- **Adopted 16 Jan 2026, policy text.** Commit 18695b27d5, "[docs] Add human-in-the-loop policy for tool-assisted contributions (#154441)" ([LLVM policy](https://llvm.org/docs/AIToolPolicy.html); [Phoronix, 20 Jan 2026](https://www.phoronix.com/news/LLVM-Human-In-The-Loop)). Requirements:
  - "Contributors must read and review all LLM-generated code or text before they ask other project members to review it."
  - "Contributors are expected to be transparent and label contributions that contain substantial amounts of tool-generated content." The suggested method is a note in the PR description or commit message, e.g. "a commit message trailer like Assisted-by:".
  - On purpose, per the search extract of the same page: "Our policy on labelling is intended to facilitate reviews, and not to track which parts of LLVM are generated."
  - Bans "agents that take action in our digital spaces without human approval, such as the GitHub @claude agent".
  - "Using AI tools to fix issues labelled as 'good first issues' is forbidden."
  - On copyright: "Using AI tools to regenerate copyrighted material does not remove the copyright."
  - A Bazel-fixer bot exception was added on 5 Mar 2026.

#### Fedora
- **Approved 22 Oct 2025, policy text via secondary sources.** The Council approved the AI-Assisted Contributions Policy on 22 Oct 2025, and the published document is v1.0 dated 24 Oct 2025, per a search extract of [docs.fedoraproject.org](https://docs.fedoraproject.org/en-US/council/policy/ai-contribution-policy/). That page was blocked by Anubis when fetched. Reported requirements:
  - Contributors "MUST disclose the use of AI tools when the significant part of the contribution is taken from a tool without changes".
  - "For contributions tracked in git, the recommended method is an Assisted-by: commit message trailer."
  - "The contributor is always the author and is fully accountable" ([GamingOnLinux, 23 Oct 2025](https://gamingonlinux.com/2025/10/fedora-linux-project-agrees-to-allow-ai-assisted-contributions-with-a-new-policy)).
- **The 25 Sep 2025 proposal.** AI must not "wholly automate the review process". AI must not be used to score submissions for code-of-conduct matters, funding, talks or leadership ([Fedora Community Blog](https://communityblog.fedoraproject.org/council-policy-proposal-policy-on-ai-assisted-contributions/)).

#### Debian
- **GR 2026-002, "LLM usage in Debian", policy text.** Discussion ran 23 Jul to 13 Aug 2026 and voting 15–28 Aug 2026. There were eight options, from "Ban LLM contributions from Debian via Social Contract" to "Allow AI-Assisted Contributions with conditions" ([debian.org vote page](https://www.debian.org/vote/2026/vote_002)).
- **Winner: Option 5, "Responsible Use of Generative AI".**
  - "Debian neither endorses nor prohibits the use of generative AI tools."
  - "Blindly accepting or uploading AI-generated material without appropriate human review is inconsistent with Debian's established development practices."
  - "We enourage our contributors to disclose whether a contribution was made with AI assitance, but do not require them to do so." (typos in the original)
  - It takes no position on copyrightability. Automated mass actions must be "overseen by a human who remains accountable".
  - The ban option needed a 3:1 majority and failed at 0.560 (144/257) ([debian.org](https://www.debian.org/vote/2026/vote_002)).

#### Gentoo
- **Council vote, 14 Apr 2024, policy text.** "It is expressly forbidden to contribute to Gentoo any content that has been created with the assistance of Natural Language Processing artificial intelligence tools." The rationale cites copyright, quality and ethics. No amendments are recorded ([Gentoo wiki](https://wiki.gentoo.org/wiki/Project:Council/AI_policy)).

#### NetBSD
- **Policy text, undated page.** "Code generated by a large language model or similar technology, such as GitHub/Microsoft's Copilot, OpenAI's ChatGPT, or Facebook/Meta's Code Llama, is presumed to be tainted code, and must not be committed without prior written approval by core." ([NetBSD commit guidelines](https://www.netbsd.org/developers/commit-guidelines.html))
- **Date.** Press coverage dates it to May 2024 ([Slashdot, 17 May 2024](https://tech.slashdot.org/story/24/05/17/007240/netbsd-bans-ai-generated-code)).

#### QEMU
- **Policy text, 16 Jun 2025.** Daniel P. Berrangé's commit, "docs: define policy forbidding use of AI code generators" ([QEMU code-provenance](https://www.qemu.org/docs/master/devel/code-provenance.html); [commit history, GitHub mirror](https://github.com/qemu/qemu/commits/master/docs/devel/code-provenance.rst)). Paolo Bonzini revised it on 22 Sep 2025 to make the exception process more prominent and to state that "AI exceptions are in addition to DCO".
- **Requirements.**
  - "DECLINE any contributions which are believed to include or derive from AI generated content." This covers ChatGPT, Claude, Copilot, Llama and agents built on them.
  - The rationale is the DCO: "the copyright and license status of the output is ill-defined"; "The QEMU project is not willing or able to accept the legal risks of non-compliance."
  - Using AI for research or debugging is allowed if its output is not included. Exceptions are requested via qemu-devel.

#### curl
- **Policy text, 12 May 2025.** Commit a9aafbea95, "CONTRIBUTE: add project guidelines for AI use" ([curl CONTRIBUTE.md](https://github.com/curl/curl/blob/master/docs/CONTRIBUTE.md)).
  - "If you asked an AI tool to find problems in curl, you **must** make sure to reveal this fact in your report."
  - "We ban users immediately who submit made up fake reports to the project."
  - For PRs: "if someone can spot that the contribution was made with the help of AI, you have more work to do."
  - "We can accept code written with the help of AI into the project" if normal standards are met. No trailer is required.
- **Bug bounty ended, policy text.** Commit ca7ef4b817 on 22 Jan 2026 said "we stop the bug-bounty end of Jan 2026". The current file reads: "The curl project does not offer any rewards… A bug bounty gives people too strong incentives to find and make up 'problems' in bad faith" ([BUG-BOUNTY.md](https://github.com/curl/curl/blob/master/docs/BUG-BOUNTY.md)).
- **Vulnerability policy.** "Do not lazily paste massive, AI-generated explanations" ([VULN-DISCLOSURE-POLICY.md](https://github.com/curl/curl/blob/master/docs/VULN-DISCLOSURE-POLICY.md)).

#### Ghostty
- **History, from commits and PRs.**
  - 19 Aug 2025: PR #8289, "AI tooling must be disclosed for contributions", drew 476 👍 and 124 ❤️ ([PR #8289](https://github.com/ghostty-org/ghostty/pull/8289)).
  - 7 Dec 2025: "tighten AI assistance disclosure requirements".
  - 12 Dec 2025: "AI-assisted != AI-generated".
  - 22 Jan 2026: `AI_POLICY.md` created.
  - 3 Feb 2026: vouch system added ([commit history](https://github.com/ghostty-org/ghostty/commits/main/CONTRIBUTING.md)).
- **Current policy text** ([AI_POLICY.md](https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md)):
  - "All AI usage in any form must be disclosed. You must state the tool you used (e.g. Claude Code, Cursor, Amp) along with the extent that the work was AI-assisted."
  - "The human-in-the-loop must fully understand all code."
  - "No AI-generated media is allowed."
  - "Bad AI drivers will be denounced… added to our public denouncement list… may be used by other projects."
  - Maintainers are exempt.
- **Vouch system, policy text.** "If you aren't vouched, any pull requests you open will be automatically closed… AI has unfortunately made it so we can no longer trust-by-default" ([CONTRIBUTING.md](https://github.com/ghostty-org/ghostty/blob/main/CONTRIBUTING.md)). The standalone `mitchellh/vouch` repository was created on 5 Feb 2026 and had 5,147 stars on 31 Oct 2026 ([GitHub](https://github.com/mitchellh/vouch)).

#### CPython
- **History.** A Generative AI page was added on 22 Oct 2024 (#1451) and replaced by an "AI tools" page on 21 May 2026 (#1778). On 21 Jul 2026 maintainers gained the right to close unproductive PRs without explanation. Enforcement labels were added on 28 Oct 2026 (#1947) ([devguide history](https://github.com/python/devguide/commits/main/getting-started/ai-tools.rst)).
- **Current text** ([CPython devguide](https://devguide.python.org/getting-started/ai-tools/)):
  - "Disclosure of the use of AI tools in the PR description is appreciated, while not required."
  - "Be prepared to explain how the tool was used and what changes it made."
  - Labels: `AI-needs-explanation` keeps a PR open; `AI-guidelines-not-met` closes it.
  - AI use alone is not grounds to close a PR.

#### Node.js and the OpenJS Foundation
- **Node.js, policy text.** The guidelines came from PR #62105 (merged 4 Mar 2026) and were refactored in #65269 (merged 13 Aug 2026) ([ai-guidelines.md](https://github.com/nodejs/node/blob/main/doc/contributing/ai-guidelines.md)).
  - "When the contribution is generated with AI, the contributor should disclose the use of such tools, and what the contributor does to personally verify the generated output."
  - "Disclosure about the use of AI does not serve as a disclaimer of this responsibility."
  - "Pull requests must not be opened by automated tooling, unless specifically approved in advance."
  - The "good first issue" AI ban.
  - On brand names: for-profit brands in commit messages "can be abused for profit-driven marketing". Contributors should anonymize them ("a frontier reasoning model") or "only mention the for-profit brand/trademark in the PR description, but not in the commit message".
- **OpenJS Foundation, policy text, adopted 27 Mar 2026 by the board.** "AI Assistants must not add Signed-off-by tags. Only humans can certify a DCO." Attribution "is strongly recommended… Submissions should therefore include an appropriate Assisted-by AI tag, identifying the AI Assistants used." ([OpenJS policy PDF](https://openjsf.cdn.prismic.io/openjsf/acqiJpGXnQHGZGtq_OpenJSAICodingAssistantsPolicy.pdf), reached by redirect from ai-coding-assistants-policy.openjsf.org)

#### Mesa
- **History** ([GitLab history](https://gitlab.freedesktop.org/mesa/mesa/-/commits/main/docs/submittingpatches.rst)):
  - 6 Apr 2026: "docs: add AI disclosure requirements" and "clarify the use of autonomously acting tooling".
  - 2 Sep 2026: "discourage AI-generated code comments, commit messages, gitlab comments".
  - 22 Oct 2026: "docs: prohibit advertising the model".
- **Current policy text** ([Mesa docs](https://docs.mesa3d.org/submittingpatches.html)):
  - "Disclosure is always required when 'AI' was involved in the creative process", with exceptions for trivial or mechanical changes.
  - Trailers: "`Assisted-by: LLM`" and "`Generated-by: LLM`".
  - "Do not advertise the model. Do not use the `Co-authored-by` tag as this one is reserved for human co-authors."
  - "It is not allowed to use autonomously acting tools to submit any contributions."
  - "Do not under any circumstances wire up any review bot."

#### GNOME
- **Extensions store, policy text.** Heading: "Extensions must not be AI-generated". Submissions showing "imaginary API usage, comments serving as LLM prompts, or other indications of AI-generated output will be rejected." Using AI as a learning aid or for code completion is allowed ([gjs.guide review guidelines](https://gjs.guide/extensions/review-guidelines/review-guidelines.html)).
- **Date.** Reported in December 2025 ([Phoronix](https://www.phoronix.com/news/GNOME-Extensions-Block-AI); [Slashdot, 14 Dec 2025](https://tech.slashdot.org/story/25/12/14/0453227/new-rule-forbids-gnome-shell-extensions-made-using-ai-generated-code)).
- **Loupe.** The GNOME image viewer Loupe "no longer allows generative AI contributions". I saw this only as a search-result title and did not read the post ([GNOME Discourse](https://discourse.gnome.org/t/loupe-no-longer-allows-generative-ai-contributions/27327)).

#### Servo
- **Current policy text, in the Servo book (sections edited 5 and 26 Oct 2026).** "Contributions must not include content generated by large language models or other probabilistic tools, including but not limited to Copilot or ChatGPT." ([servo/book ai-usage.md](https://github.com/servo/book/blob/main/src/policy/ai-usage.md))
  - FAQ: a PR with AI code is "No", naming Claude, Codex, ChatGPT, Cursor, Gemini and Windsurf.
  - Using AI to find bugs is allowed only with human verification. Translation is allowed.
  - The rationale covers maintainer burden, correctness and security, copyright, and ethics.
- **History, from secondary sources.** The ban dates from June 2024. A 2025 TSC vote to relax it was reported, but the current text is still a ban ([search result: Servo discussion #36379](https://github.com/servo/servo/discussions/36379)).

#### Zig
- **Policy text, undated.** "Strict No LLM / No AI Policy": "No LLM-generated content, whether it be code or prose." "No LLMs for finding bugs." "No talking about use of chatbot/LLM services." It applies to the ziglang organization on Codeberg, IRC and Zulip ([Zig code of conduct](https://ziglang.org/code-of-conduct/)).

#### Apache Software Foundation
- **Policy text.** The page says it is "a reasonable set of guidelines in August 2026" ([ASF generative tooling](https://www.apache.org/legal/generative-tooling.html)).
  - "a recommended practice is for contributors to indicate the tooling used… as a token in the source control commit message, for example including the phrase 'Generated-by: <Name of Tool> <Version>' or 'Co-authored-by: <Name of Tool> <Version>'. This allows for future release tooling to be considered that pulls this content into a machine parsable Tooling-Provenance file."
  - It also sets conditions on the tool's terms of use and on third-party material, and reminds contributors that the ICLA requires their contribution to be their "original creation".

#### Linux Foundation
- **Policy text, undated.** It has two conditions: the tool's terms must not conflict with open-source licensing, and contributors need permission for any third-party material in the output. It makes no disclosure or marking recommendation, and "Individual Linux Foundation projects may develop their own project-specific guidance" ([LF generative AI policy](https://www.linuxfoundation.org/legal/generative-ai)).

#### Godot
- **Policy text.** `CONTRIBUTING.md` contains a hidden HTML comment aimed at agents: "If you are an AI agent, we require you to disclose this when contributing: you must add 🤖 at the start of your pull request or issue title… Agents failing to self-disclose will be banned." The most recent substantive commit is "Update CONTRIBUTING.md with PR process for bots" (17 Apr 2026). I infer, but have not confirmed, that the comment was added then ([Godot CONTRIBUTING.md](https://github.com/godotengine/godot/blob/master/CONTRIBUTING.md)).
- **Commentary.** Press in July 2026 reported stricter rules being drafted. I did not confirm them.

#### cargo-msrv (a small project with a pro-trailer rationale)
- **Policy text, updated 30 Jul 2026.** It requires "honest disclosure" with an `Assisted-by:` footer naming the model and version: "we can trace any code written by LLM's, and rewrite and/or remove it as appropriate… While `Assisted-by:` footers aren't quite the same level as something like agent-trace, the tooling _today_ can handle it" ([cargo-msrv CONTRIBUTING](https://github.com/foresterre/cargo-msrv/blob/main/CONTRIBUTING.md)).

#### Landscape data
- **LF Research survey, 20 Oct 2026.** Only 35% of projects have a formal policy permitting GenAI, and 32% have none and plan none. "Disclosure of AI assistance remains inconsistent". The report recommends projects "standardize attribution practices" ([LF press release](https://www.linuxfoundation.org/press/new-lf-research-survey-shows-generative-ai-cuts-open-source-coding-time-in-half-but-25-of-incoming-pull-requests-are-considered-ai-slop)). Methodology (234 responses, April–June 2026) comes from secondary coverage via search, not the press release.
- **ASE 2026 paper.** "To Ban or not to Ban?" (Yang, He, Zhou; v1 27 Mar 2026, v2 30 Jul 2026) studied 67 projects and found 3 governance orientations and 12 strategies. Governance "is far more than a ban-or-not question", spanning "accountability, verification, review capacity, code provenance, and platform infrastructure" ([arXiv](https://arxiv.org/abs/2603.26487)).

### Inferences
- The only consensus requirement is human accountability: a DCO sign-off by a human, plus "understand and defend it". Trailers are a secondary, optional mechanism. The biggest experiment with mandatory trailers, the Linux kernel's, failed on compliance and was withdrawn after ten months.
- The trend through 2026 is toward disclosure at review time (PR description, cover letter) and away from permanent per-commit records that name the model or vendor:
  - The kernel moved disclosure to cover letters.
  - Node.js keeps brands to PR descriptions.
  - Mesa says "Do not advertise the model".
  - LLVM says labels are for review, not tracking.
- Several projects ban AI outright: Gentoo, NetBSD, QEMU, Servo, Zig, and GNOME's extension store. For contributors to those projects, any visible AI provenance is grounds for rejection. That is an incentive against public attribution, not toward it.

### Gaps
- I could not read the Fedora policy page itself (Anubis bot check).
- I found no current, primary text of Godot's July 2026 rules.
- I did not read the Gentoo or NetBSD mailing-list origin posts, so NetBSD's May 2024 date rests on press coverage.
- I did not check Rust, Kubernetes, Mozilla/Firefox, Blender, KDE or the Python packaging ecosystem.
- No Linux Foundation project-level census of trailer requirements exists in what I found.

## 2. What do maintainers say first-person about AI slop PRs and bug reports, and what tooling or signals do they ask for?

### Takeaway
Maintainers' complaints centre on cost asymmetry and broken trust:
- Generating a contribution is cheap; reviewing it is not.
- Reviewers "can no longer assume authors understand or wrote the code".

What they asked for, and what GitHub shipped, were volume and trust controls rather than provenance features:
- PR limits, collaborators-only PRs, vouching, rate limits, CAPTCHAs.
- Removing the incentives (curl ended its bounty).
- Disclosure as courtesy, to calibrate review effort.

Few asked for verifiable provenance. Daniel Stenberg's view by 2026 was that curl doesn't care which AI tool was used, only whether the bug is real.

### Cited Findings

#### Daniel Stenberg (curl), first-person
- **14 Jul 2025** ([Death by a thousand slops](https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/)):
  - About 20% of 2025 submissions were AI slop and about 5% were genuine.
  - Each report engages 3–4 team members for 30 minutes to several hours.
  - On HackerOne: "It is however clear that we need them to do something." He wants "more tools and knobs to tweak, to save us from drowning", and wonders "Maybe we need to drop the monetary reward?"
- **26 Jan 2026** ([The end of the curl bug-bounty](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)):
  - 87 confirmed vulnerabilities and over USD 100,000 paid.
  - The confirmed rate fell from above 15% to below 5% in 2025: "Not even one in twenty was _real_."
  - "The never-ending slop submissions take a serious mental toll to manage and sometimes also a long time to debunk."
  - The post makes no explicit request for detection or labelling features.
- **25 Feb 2026, from a search summary only (not fetched).** curl returned to HackerOne from 1 Mar 2026 after a brief move to GitHub private reporting ([daniel.haxx.se HackerOne tag page](https://daniel.haxx.se/blog/tag/hackerone/)).
- **22 Apr 2026** ([High-Quality Chaos](https://daniel.haxx.se/blog/2026/04/22/high-quality-chaos/)):
  - Report frequency is about double 2025.
  - The confirmed rate is "back to and even surpassing the 2024 pre-AI level", around 15–16%.
  - "The reporters rarely mention exactly which AI tool or model they used (and really, we don't care)."
- **10 Jun 2026** ([A human in control](https://daniel.haxx.se/blog/2026/06/10/a-human-in-control/)): "We stand for every bit of code we merge – as humans." "curl is developed and driven by humans, assisted by tools."
- **15 Jun 2026** ([curl summer of bliss](https://daniel.haxx.se/blog/2026/06/15/curl-summer-of-bliss/), as summarised from the June archive page): "The curl project will not accept or otherwise handle any vulnerability reports during the month of July 2026." Submissions resumed on 3 Aug 2026.
- **22 Oct 2026** ([ignore the slop](https://daniel.haxx.se/blog/2026/10/22/ignore-the-slop/)):
  - Hundreds of reports in recent months, every one with AI involved "to some extent". Slop is "practically gone" since spring 2026.
  - "Our current challenge is much harder: high volume, high quality."
  - "Ignoring real vulnerabilities because they were found by AI does not make users safe and secure."

#### Other maintainers, first-person
- **Seth Larson (PSF), 3 Dec 2024** ([blog](https://sethmlarson.dev/slop-security-reports)):
  - "extremely low-quality, spammy, and LLM-hallucinated security reports"
  - "these low-quality reports should be treated as if they are malicious"
  - To platforms: "Require reporters to solve CAPTCHAs or heavily rate-limit security report creation using automation"; "Take away any positive incentive".
- **Mitchell Hashimoto (Ghostty), 19 Aug 2025** ([PR #8289](https://github.com/ghostty-org/ghostty/pull/8289)): "The disclosure is to help maintainers assess how much attention to give a PR… if it's just an AI on the other side, I don't need to put in this effort, and it's rude to trick me into doing so." "I'm a fan of AI assistance and use AI tooling myself."
- **Rémi Verschelde (Godot), Bluesky thread quoted in [GamingOnLinux, 18 Feb 2026](https://www.gamingonlinux.com/2026/02/godot-engine-suffering-from-lots-of-ai-slop-code-submissions/).** "AI slop PRs are becoming increasingly draining and demoralizing for #Godot maintainers"; "we find ourselves having to second guess every PR from new contributors". More funding to pay maintainers is "the only viable solution I can think of".
- **Kernel, per LWN.** Corbet argued that few maintainers ask about LLM use or check for tags, so the tag "provides no useful signal" ([LWN, 12 Oct 2026](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)).
- **A maintainer who wants attribution, 1 Jun 2026.** In a Codex issue: "I maintain a few open source projects and I really value git attribution because it's transparent when I receive changes from unknown authors" ([openai/codex #14051](https://github.com/openai/codex/issues/14051)).

#### GitHub's community discussion and what shipped
- **Discussion #185387, opened 27 Jan 2026 by GitHub PM Camilla Moraes** (230 upvotes, 131 comments) ([discussion](https://github.com/orgs/community/discussions/185387)). Options evaluated:
  - Configurable PR permissions.
  - Deleting PRs from the UI.
  - Criteria-based gating.
  - AI-assisted triage.
  - "**Transparency in AI-assisted contributions** – Improved visibility and attribution when AI tools are used throughout the PR lifecycle" (listed as a long-term direction).
- **Top comments.**
  - Azure Core Upstream (42 upvotes, 28 Jan 2026): "Review trust model is broken: reviewers can no longer assume authors understand or wrote the code they submit"; "Review burden is higher than pre-AI, not lower."
  - sirosen (30 upvotes): limit new contributors to one open PR.
  - duskwuff (14 upvotes): let owners "state their policy on AI-assisted contributions, and to automatically disable Copilot features in repositories whose AI policy prohibits its use".
  - chadlwilson (11 upvotes): "we cannot even tell if we are interacting with an agent vs. a human without expending significant effort".
  - xavidop (8 upvotes): "an AI-detection mechanism with a configurable threshold".
  - Several others proposed reputation signals "instead of unreliable AI detection" ([same thread](https://github.com/orgs/community/discussions/185387)).
- **Shipped by 29 May 2026, per GitHub's own update #197319** ([discussion](https://github.com/orgs/community/discussions/197319)):
  - Disable PRs, or restrict them to collaborators (changelog of 13 Feb 2026).
  - Disable commit comments.
  - A "Hide comments as low quality" option.
  - A repository member role label in the PR list view (9 Apr 2026).
  - Notes when blocking users.
- **Shipped after that.**
  - PR limits plus a bypass list (17 Jun 2026) ([changelog](https://github.blog/changelog/2026-06-17-limit-open-pull-requests-for-users-without-write-access/)).
  - Drafts count toward limits (8 Oct 2026) ([changelog](https://github.blog/changelog/2026-10-08-draft-pull-requests-count-toward-pull-request-limits)).
  - Exemption by account age or merged-PR history (28 Oct 2026) ([changelog](https://github.blog/changelog/2026-10-28-pull-request-limits-exempt-contributors-by-age-or-history)).
- **Roadmap as of 29 May 2026.** PR archiving, issue limits, global rate limits, and bypass signals ("A previously merged PR… Account age… Organization membership"). The May update lists no AI attribution or labelling feature among shipped or planned items ([#197319](https://github.com/orgs/community/discussions/197319)).

#### Survey data
- **LF Research, 20 Oct 2026, self-reported estimates.** Maintainers estimate 25% of incoming PRs are "AI slop" (31% at large projects). 53% disagree that GenAI has improved community trust. 61% of contributors say they review and test AI code in detail before submitting ([LF press release](https://www.linuxfoundation.org/press/new-lf-research-survey-shows-generative-ai-cuts-open-source-coding-time-in-half-but-25-of-incoming-pull-requests-are-considered-ai-slop)).

### Inferences
- Maintainers' working signals are reputation and trust: vouching, prior merged PRs, account age, member labels. Artifacts that describe the code's origin come second. GitHub built along exactly those lines.
- Where disclosure is wanted, it is wanted at review time to calibrate effort (Hashimoto, LLVM, the kernel's cover letters). There is little demand for a permanent public record.
- curl's 2026 shift is instructive. Once AI-assisted reports became accurate, the provenance of a report stopped mattering to the maintainer ("we don't care"). Only correctness and volume did.
- The ask closest to "verifiable disclosure" is the wish to tell an agent from a human (chadlwilson) and to declare a repo's AI policy so that tools respect it (duskwuff). This is a policy-handshake idea, not a provenance-record idea.

### Gaps
- I did not find HackerOne's own changes (for example, AI disclosure fields) in a primary source.
- The 2026 Godot statements beyond February rest on secondary sources only.
- No survey asked maintainers which signal they would prefer: a disclosure label, a verifiable attestation, or a session link.

## 3. Which tools and standards attach AI provenance to commits and PRs, and what adoption evidence exists?

### Takeaway
Provenance today is mostly vendor-defaulted, unauthenticated commit trailers:
- Claude Code `Co-Authored-By` and a `Claude-Session` link.
- Copilot cloud agent as author, plus an `Agent-Logs-Url` link.
- Cursor `Made-with:` and `Co-authored-by`.
- VS Code `Co-authored-by: Copilot`.

Beside them sit two git-native records of the session itself: git-ai's line-level git notes, and Entire's checkpoint refs holding transcripts. Agent Trace is a draft specification (v0.1.0 RFC, January 2026), and its GitHub repository no longer resolves.

Measured adoption of explicit markers is small and concentrated in one tool. Across 5,682 critical-package repositories, markers appeared on 2.93% of commits in the year to July 2026, reaching 5.32% in July. About 57% of declared occurrences were Claude Code trailers. The kernel's 10% tag rate, against roughly 90% estimated LLM use, shows how far public markers understate real use.

### Cited Findings

#### Claude Code (vendor documentation, fetched 31 Oct 2026)
- **Defaults** ([settings reference](https://code.claude.com/docs/en/settings-reference.md)):
  - Commits get `Co-Authored-By: <name> <noreply@anthropic.com>`, named after the model in use.
  - PR descriptions get "🤖 Generated with [Claude Code](https://claude.com/claude-code)".
  - `attribution.sessionUrl` defaults to `true`: "Claude Code adds the link as a `Claude-Session` trailer on commits and as a link in pull request descriptions" for cloud and Remote Control sessions.
- **Settings.**
  - `includeCoAuthoredBy` is "Deprecated since v2.0.62, when `attribution` replaced it".
  - `attribution: false` (hide everything) "requires Claude Code v2.1.281 or later".
  - "Claude Code tells Claude that your own instructions about attribution, such as a CLAUDE.md or memory rule, take precedence over these commit and PR lines, unless the line is set in managed settings."
- **User report, 7 Jun 2026.** A second `Co-authored-by:` for the human user, using the Anthropic account email, appeared "since ~2026-06-05 / v2.1.165". The issue was closed on 31 Jul 2026 ([#66079](https://github.com/anthropics/claude-code/issues/66079)).

#### GitHub Copilot
- **Cloud (coding) agent, vendor text, 20 Mar 2026.** Commits are "authored by Copilot, with the human who gave Copilot the task marked as the co-author". An `Agent-Logs-Url` trailer is "a permanent link from agent-authored commits back to the full session logs" ([GitHub changelog](https://github.blog/changelog/2026-03-20-trace-any-copilot-coding-agent-commit-to-its-session-logs)).
- **Docs.** Sessions are "shared by default" and "visible to anyone with access to the repository"; commits "are signed and appear as 'Verified'" ([GitHub docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions)).
- **VS Code `git.addAICoAuthor`, vendor statement in [microsoft/vscode #314311](https://github.com/microsoft/vscode/issues/314311), 5 May 2026.**
  - Added in 1.110 with default `off`. The trailer is `Co-authored-by: Copilot copilot@github.com`.
  - 1.117 (rollout from 22 Apr 2026) changed the default to `all`. A bug attributed non-Copilot completions to Copilot "even when the `disableAIfeatures` setting was turned on".
  - 1.118 (29 Apr) set it to `chatAndAgent`. 1.119 (from 6 May) reverted to `off`.
  - Promised changes: "Before adding a commit trailer, the user will have to give consent", and possibly "assisted-by" attribution.
  - Reactions: 244 👎 against 30 👍.
  - An open issue from 6 Oct 2026 reports `Co-authored-by: Copilot` still injected in the VS Code Agent Host ([#340038](https://github.com/microsoft/vscode/issues/340038)).

#### Cursor (forum statements by staff and users)
- **Jan–Feb 2026.** Users found Cursor auto-adding a co-author to commits on 27 Jan 2026. Staff pointed to "Cursor Settings > Agents > Attribution". Docs were updated around 2 Feb 2026 ([forum thread 150096](https://forum.cursor.com/t/co-author-added-without-consent-and-cant-be-turned-off/150096)).
- **Later staff reply, undated in my extract.** The Attribution setting controls a `Made-with: Cursor` trailer for IDE and CLI agents. For cloud agents the `Co-authored-by` trailer is added by a server hook that "you can't disable right now". The CLI key is `attribution.attributeCommitsToAgent` ([forum thread 168258](https://forum.cursor.com/t/disable-auto-co-authored-by-cursor-on-agent-commits-or-make-it-opt-in/168258/8); [thread 167722](https://forum.cursor.com/t/local-executor-ignores-cli-config-attribution-opt-out-forcing-co-authored-by-trailer/167722)).

#### Other tools
- **Aider (vendor docs).** Aider appends "(aider)" to the git author and committer names by default. `--attribute-co-authored-by` adds a trailer instead ([aider docs](https://aider.chat/docs/git.html)).
- **OpenAI Codex (user reports).**
  - A `commit_attribution` config key exists (from PR #11617). A user reported on 15 Apr 2026 that it needs `[features] codex_git_commit = true`.
  - Users from March to October 2026 report it absent or undocumented. One user built an opt-in `Co-authored-by` branch ([openai/codex #14051](https://github.com/openai/codex/issues/14051)).
  - A related issue reports that a default identity `codex@example.com` misattributed commits to an unrelated GitHub user (title only, [#18095](https://github.com/openai/codex/issues/18095)).
- **Gemini CLI.** On 21 Apr 2026 a contributor reported that the repository's CLA bot blocks PRs carrying a Gemini `Co-authored-by`, because gemini@google.com "hasn't signed the CLA". It was triaged P3 and closed with no plans ([google-gemini/gemini-cli #25721](https://github.com/google-gemini/gemini-cli/issues/25721)).

#### Trailer vocabularies in project policies
- `Assisted-by:`: kernel (removed October 2026), Fedora, LLVM, OpenJS, Mesa (`Assisted-by: LLM`), cargo-msrv.
- `Generated-by:`: ASF (with `Co-authored-by:` as an alternative) and Mesa.
- Mesa forbids `Co-authored-by` for tools.
- Sources: see Q1, plus a feature request for Claude Code to use `Assisted-by` by default (52 👍, 19 Mar 2026) ([#36105](https://github.com/anthropics/claude-code/issues/36105)).

#### git-ai (open source with a paid teams tier; README claims are vendor claims)
- **Repository facts.** `git-ai-project/git-ai` was created on 2 Jul 2025. It had 2,917 stars and 328 forks on 31 Oct 2026, with a push on 31 Oct 2026 ([GitHub](https://github.com/git-ai-project/git-ai)).
- **How it works, per the README.**
  - "every line of AI code is linked to the agent, model, and prompts that generated it".
  - It stores line-level attribution in Git Notes and syncs the notes on `git push` and `fetch`.
  - Specification: "Git AI standard v3.0.0".
  - `git ai stats` reports "% AI-code, AI-lines generated vs committed, accepted rates, human overrides broken down by tool and model".
- **Prompt storage.** "**Secure Prompt Storage** — … These sessions are scanned and redacted, and saved outside of Git -- keeping repos lean, enabling fine-grained access control, and preventing PII or secrets from leaking."
- **Adoption claim (vendor, unverified).** "Hundreds of engineering teams (including many in the Fortune 100) use Git AI." The teams tier measures "% AI and token cost by Pull Request, Repo, Team, and Contributor".

#### Agent Trace
- **Draft specification.** Version 0.1.0, dated January 2026, status RFC ([agent-trace.dev](https://agent-trace.dev/); [InfoQ, Feb 2026](https://www.infoq.com/news/2026/02/agent-trace-cursor)).
  - Trace records carry contributor types (human, ai, mixed, unknown), `model_id`, a conversation `url`, line ranges with an optional `content_hash`, and a `vcs` revision.
  - Storage is "intentionally" undefined (local files, git notes or databases).
  - Non-goals: legal ownership or copyright, training-data provenance, and quality.
  - The page thanks Amp, Amplitude, Cline, Cloudflare, Cognition, git-ai, Jules, OpenCode, Tapes and Vercel "for helping shape" it. That is not a list of adopters.
- **Repository status.** The canonical repository `github.com/cursor/agent-trace` returned 404 (WebFetch) and "Could not resolve to a Repository" (GitHub API) on 31 Oct 2026.
- **Engagement.** Hacker News posts drew 5 points (29 Jan 2026) and 3 points (21 Jun 2026) ([HN 46813938](https://news.ycombinator.com/item?id=46813938); [HN 48616614](https://news.ycombinator.com/item?id=48616614)).
- **Mentions.** SpecStory's repository has an Agent Trace standards document (found by code search, not read). cargo-msrv cites it as aspirational ([cargo-msrv](https://github.com/foresterre/cargo-msrv/blob/main/CONTRIBUTING.md)).

#### Entire (vendor, founded by former GitHub CEO Thomas Dohmke)
- **Launch.** 10 Feb 2026, with a $60M seed led by Felicis, according to secondary reports ([Motilal Oswal/news, 10 Feb 2026](https://www.motilaloswal.com/news/economy-_-outlook/127354); [Bloomberg Government](https://news.bgov.com/private-equity/former-github-ceos-new-company-aims-to-sync-ai-human-coders)).
- **Repository facts.** `entireio/cli` was created on 2 Jan 2026 and had 5,282 stars and 492 forks on 31 Oct 2026 ([GitHub](https://github.com/entireio/cli)).
- **How it works, per the README.**
  - Each commit with agent work gets a checkpoint, "the prompts, transcript, and files touched — linked to the commit by an `Entire-Checkpoint` trailer".
  - Checkpoints are stored as `refs/entire/checkpoints/…`, "pushed alongside your code".
  - "**Session transcripts are pushed to your Git remote**… If that repository is public, anyone can read them. Entire redacts detected secrets… but redaction is best effort."
  - Transcripts can instead go to a separate private repository, or not be pushed at all.
  - Supported agents: Claude Code, Codex, Cursor, Copilot CLI, OpenCode and others.

#### Attestation-style prototypes (search results only)
- AIIR (PyPI) writes "cryptographic receipts for commits with declared AI involvement", optionally as in-toto statements ([PyPI](https://pypi.org/project/aiir/)).
- Hackathon and early projects such as Pedigree and noru-tech agent-change-control also exist.
- I found no OpenSSF or SLSA standard for agent-authored code.

#### Adoption evidence
- **Andrew Nesbitt, 6 Aug 2026, independent study** ([nesbitt.io](https://nesbitt.io/2026/08/06/a-year-of-ai-disclosure-in-critical-packages.html)).
  - Sample: 5,682 critical-package repositories across 16 registries, year ending 29 Jul 2026.
  - Commits with explicit AI markers: 2.93% overall (17,279 of 589,798), rising from 0.48% (August 2025) to 5.32% (July 2026). Repositories with any signal rose from 2.4% to 15.4%.
  - Declared occurrences by tool: Claude Code 57.35%, GitHub Copilot 27.93%, Cursor 4.44%, Codex 1.36%. Copilot's agent authored 4,613 commits.
  - The February–March 2026 jump "is specific to one tool rather than a general change in disclosure practice".
  - "Undeclared use is not measured." git notes (`refs/notes/ai`) were not fetched, so git-ai data is invisible to the study.
  - RedMonk's comparable figure is 1.05% for 15 projects.
- **SemiAnalysis, February 2026, via Gigazine (secondary).** About 4% of public GitHub commits were by Claude Code, based on the signature, with a projection of more than 20% by the end of 2026. Commentary notes it is a floor, because many users disable the trailer ([Gigazine, 10 Feb 2026](https://gigazine.net/gsc_news/en/20260210-claude-code-github-commits-4-percent-20-percent)).
- **LangPop (secondary, unverified).** About 13M Claude Code commits counted by trailer in June 2026 ([LangPop](https://www.langpop.com/ai/tools)).
- **Linux kernel.** About 10% of 7.3 commits carried Assisted-by, against Airlie's estimate of "probably 90%" of contributors using LLMs ([LWN](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)).
- **GitHub's labelling of agent PRs.** Copilot cloud-agent commits are authored by Copilot ([docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions)). GitHub's shipped triage signal is a member-role label, not an AI label ([#197319](https://github.com/orgs/community/discussions/197319)).

### Inferences
- Every widely deployed mechanism is a self-asserted string. Anyone can type it, squash merges drop it, and several (Claude, Codex, Gemini noreply addresses) have been hijacked or misattributed. As provenance, none of it is verifiable.
- The two git-native "record" products are diverging on privacy:
  - git-ai keeps attribution in git notes but moved prompts out of git, behind access control.
  - Entire pushes transcripts with the repository by default and warns that public repositories expose them.

  Both vendors are converging on "metadata in the repository, sensitive content held privately". That is close to the sidecar's thesis, but the private store is vendor- or repository-held, not held under the team's own keys.
- Public adoption metrics are driven by one vendor's default (Claude Code). They measure defaults, not developer intent.

### Gaps
- I could not determine what happened to the Agent Trace repository: whether it was moved, renamed or deleted, or whether anyone implements the specification in production.
- No independent adoption figures exist for git-ai or Entire beyond GitHub stars and vendor claims.
- I found no GitHub-native "AI-generated" label for third-party agents' PRs.
- The GitHub docs did not say whether Copilot logs are visible to all repository readers or only to collaborators.

## 4. The opposite pressure: what public evidence shows developers disabling or removing AI attribution, and why?

### Takeaway
There is extensive, dated evidence of developers stripping or blocking vendor attribution, peaking in 2026:
- Claude Code's session-URL default drew 116 👍 on one issue and a 209-point Hacker News thread.
- VS Code's Copilot co-author default drew 244 👎 and was reverted within two weeks.
- Cursor's default drew a forum backlash.
- In the kernel, contributors left the tag off "on purpose", and maintainers removed the model name as "free advertising".

The reasons given are:
- Vendor advertising or branding without consent.
- The tool is not an author (citing USCO guidance).
- Misattribution or email leaks through noreply identities.
- Audit and compliance (SOC 2, ISO 27001), and history that cannot be revoked.
- Stigma: "anti-LLM witch hunt", and projects that reject AI work.
- Noise and unprofessional appearance, and sending vendor branding into third parties' OSS repositories.

### Cited Findings

#### Claude Code GitHub issues (dates, states and reactions as of 31 Oct 2026)
- [#4287](https://github.com/anthropics/claude-code/issues/4287) (24 Jul 2025, open, 22 👍): trailers were added despite `includeCoAuthoredBy: false`. [#7543](https://github.com/anthropics/claude-code/issues/7543) (13 Sep 2025, open, 15 comments) is the same complaint.
- [#36105](https://github.com/anthropics/claude-code/issues/36105) (19 Mar 2026, open, 52 👍): a maintainer whose contributors arrive with `Co-Authored-By: Claude Opus 4.6` asks to "use `Assisted-by` trailer as it's recommended by several big projects".
- [#47579](https://github.com/anthropics/claude-code/issues/47579) (13 Apr 2026, closed): "without user consent or opt-out… permanently modifies the user's git history".
- [#66504](https://github.com/anthropics/claude-code/issues/66504) (9 Jun 2026, closed 17 Aug 2026, 116 👍 / 5 👎): "Every commit message and PR description created by Claude Code automatically includes a session URL… there is no opt-in prompt… It looks unprofessional, clutters history."
- [#66602](https://github.com/anthropics/claude-code/issues/66602) (9 Jun 2026, closed): the default trailer "asserts AI co-authorship… contrary to the U.S. Copyright Office's published guidance". It quotes the 2023 guidance: "Applicants should not list an AI technology or the company that provided it as an author or co-author simply because they used it."
- [#83226](https://github.com/anthropics/claude-code/issues/83226) (2 Aug 2026, closed 8 Sep 2026): the `Claude-Session:` trailer "writes a vendor-controlled external URL into permanent customer source-control history".
  - "effectively unrevocable"
  - "Commit metadata is frequently in scope for SOC 2, ISO 27001… Introducing an opaque external session reference into that record creates questions we then have to answer to auditors"
  - "Whether or not an organisation chooses to disclose AI assistance in its VCS history should be that organisation's decision, made deliberately — not a default applied silently."
- [#83813](https://github.com/anthropics/claude-code/issues/83813) (4 Aug 2026, open): "Attribution is opt-out advertising". The reporter added "a CI gate to my repos that fails any PR containing AI attribution… to protect my repos from my own tooling".
- [#103691](https://github.com/anthropics/claude-code/issues/103691) (20 Oct 2026, closed 23 Oct 2026):
  - A fix PR to a third-party OSS project (an OctoPrint plugin) "went out to someone else's repository with a `Co-Authored-By: Claude` trailer and a 'Generated with Claude Code' footer… I had to rewrite the commit, force-push".
  - The opt-out "has changed shape over time (`includeCoAuthoredBy`, then `attribution`, then the added `sessionUrl` that again defaults to on)".
- **August–October 2026 issues, read by title only.** Many report harness-injected reminders overriding users' no-attribution instructions: [#92169](https://github.com/anthropics/claude-code/issues/92169), [#92893](https://github.com/anthropics/claude-code/issues/92893), [#94325](https://github.com/anthropics/claude-code/issues/94325), [#101634](https://github.com/anthropics/claude-code/issues/101634), [#102266](https://github.com/anthropics/claude-code/issues/102266). Identity problems: [#58479](https://github.com/anthropics/claude-code/issues/58479) (the footer linked commits to an unrelated GitHub account) and [#72477](https://github.com/anthropics/claude-code/issues/72477) (remove or replace noreply@anthropic.com).
- **Counter-signal.** Some users want attribution to work reliably: [#99896](https://github.com/anthropics/claude-code/issues/99896) ("inconsistently includes my co-author attribution") and [#99352](https://github.com/anthropics/claude-code/issues/99352) (a Gravatar for Claude's commits).

#### Hacker News
- **30 Aug 2026**, "Claude Session URL appended to commit messages and PR descriptions by default", 209 points and 240 comments ([HN 49498201](https://news.ycombinator.com/item?id=49498201)):
  - "Presumably quietly added default-on because everyone had turned attribution off."
  - "I cancelled my subscription over this."
  - "Its just free branding & advertising."
  - A dissent: "Anthropic is right here. You need to clearly define what commits are AI authored or you are conspiring to commit copyfraud."
- **Other threads.**
  - 22 Sep 2025: "Has Claude Code suddenly started name-dropping Anthropic in commit msgs?" ([HN 45329240](https://news.ycombinator.com/item?id=45329240)).
  - 20 Apr 2026: "Tell HN: Do not include co-authored-by Claude in your commits", arguing that trailers help vendors filter training data ([HN 47840791](https://news.ycombinator.com/item?id=47840791)).
  - 31 Aug 2026: the session link "is only accessible to the user so it doesn't make sense to be put in a commit" ([HN 49515667](https://news.ycombinator.com/item?id=49515667)).
- **Public trailers used to assign blame or challenge authenticity (titles only, unverified).**
  - 29 May 2026: "Rsync: Commits co-authored by Claude break –compare-dest in security update" ([HN 48320203](https://news.ycombinator.com/item?id=48320203)).
  - 2 Sep 2026: "`Co-Authored-By: Claude Opus 5` contradicts this being a hand-written manifesto" ([HN 49541921](https://news.ycombinator.com/item?id=49541921)).

#### Cursor forum (27 Jan to early Feb 2026)
- "Not trying to advertise your product in git history."
- "Certainly wouldn't want Cursor appearing as a contributor on every commit", especially on open-source PRs.
- Concerns about "security audits… CI/CD systems, and regulatory compliance".
- "trust-damaging move."
- One user had to rewrite a series of commits ([forum thread 150096](https://forum.cursor.com/t/co-author-added-without-consent-and-cant-be-turned-off/150096)).

#### VS Code
- The Copilot co-author default was reverted after the `all` default and a misattribution bug. The issue drew 244 👎, and Microsoft promised consent before adding a trailer ([microsoft/vscode #314311](https://github.com/microsoft/vscode/issues/314311), 5 May 2026).

#### Maintainers and projects
- **Kernel.**
  - Brauner: model names in tags provide "free advertising to proprietary software companies" ([commit 816d9992d9ed](https://github.com/torvalds/linux/commit/816d9992d9ed), 1 Jul 2026).
  - Levin's removal commit: "others leave the tag off on purpose" ([commit 1e035297ffda](https://github.com/torvalds/linux/commit/1e035297ffda)).
  - LWN: contributors fear an "anti-LLM witch hunt" ([LWN](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)).
- **Node.js.** Brands in commit messages "can be abused for profit-driven marketing" ([ai-guidelines.md](https://github.com/nodejs/node/blob/main/doc/contributing/ai-guidelines.md)).
- **Mesa.** "Do not advertise the model" (22 Oct 2026) ([Mesa docs](https://docs.mesa3d.org/submittingpatches.html)).

#### Blogs
- **Fabio Rehm, 2 Mar 2026, updated 3 and 8 Mar** ([blog](https://fabiorehm.com/blog/2026/03/02/our-coding-agent-commits-deserve-better-than-co-authored-by/)).
  - He disabled attribution: "The coding agent is a tool and I am the one responsible for what it produces."
  - `Co-Authored-By` "was meant for people who exchanged drafts". The fake email led GitHub to attribute commits to an unrelated user.
  - He proposes `Coding-Agent:` and `Model:` trailers, but on 8 Mar dropped them because Claude Code does not reliably report the model after a mid-session switch.

#### Measurement caveats
- Nesbitt measures declared use only ("Undeclared use is not measured") and does not study trailer stripping ([nesbitt.io](https://nesbitt.io/2026/08/06/a-year-of-ai-disclosure-in-critical-packages.html)).
- Commentary on the SemiAnalysis 4% figure calls it a floor, because many users disable the Claude co-author line ([Gigazine](https://gigazine.net/gsc_news/en/20260210-claude-code-github-commits-4-percent-20-percent)).

### Inferences
- The backlash is aimed mainly at vendor-chosen, default-on, brand-bearing, public and irrevocable markers inserted without consent. It is not necessarily aimed at provenance as such. Several of the same people value session links for their own debugging (see Q6).
- Repeated reports that opt-outs fail or get bypassed have pushed users to defensive tooling: CI gates and commit-msg hooks that strip trailers. This is a market of people who want to control what leaves their machine.
- Stigma is real and documented: kernel contributors leaving the tag off on purpose, the "witch hunt" fear, trailers used to challenge authenticity. Public attribution therefore imposes a reputational cost on the developer that a private record would not.

### Gaps
- There is no quantitative measure of how many developers disable attribution. The evidence is issue reactions, thread engagement, and the gap between kernel compliance and estimated use.
- I did not read the bodies of the August–October 2026 system-reminder issues.
- I found no employer-side statement such as "we strip AI trailers by policy" (see Q5).

## 5. Are there client- or employer-side rules that forbid or require disclosing AI use in delivered code?

### Takeaway
I found only a few sourced, primary examples:
- A public-sector sample contract (California's judicial branch) requires contractors to notify before including GenAI in deliverables, and treats non-disclosure as a possible material breach.
- A consultancy-style public rulebook (SSW) requires human co-author attribution on AI-implemented commits.

Law-firm commentary says "no AI" and AI-disclosure clauses exist as clause types. I did not find a named consultancy or enterprise policy text that forbids AI in delivered code.

### Cited Findings
- **Judicial Branch of California, sample "GenAI Contract Provisions"** (page © 2026; adoption date not stated) ([courts.ca.gov](https://courts.ca.gov/genai-contract-provisions)):
  - "Contractor must immediately notify the JBE in writing if Contractor intends to include or provide GenAI in Deliverables."
  - Failure to disclose or discontinue undisclosed GenAI may be treated as a material breach.
  - "Contractor shall not incorporate any confidential or non-public JBE data into GenAI Training Data."
- **SSW Rules, "Do you attribute AI-assisted commits with co-authors?"** (created and last updated 17 Oct 2025): "**ALWAYS add yourself as a co-author on commits** when AI implements code to ensure proper attribution." The reason given is that the trailer shows who checked the AI's work, for transparency. The page does not mention client work ([SSW](https://www.ssw.com.au/rules-legacy/attribute-ai-assisted-commits-with-co-authors/)). The rules-beta URL returned 404.
- **Clause categories, from search summaries of law-firm and template sites; secondary, not fetched.**
  - Law Insider lists sample "No Artificial Intelligence (AI) or Machine Learning" clauses that bar AI use for contract deliverables ([Law Insider](https://www.lawinsider.com/clause/no-artificial-intelligence-ai-or-machine-learning)).
  - Michalsons recommends AI disclosure before delivery ([Michalsons](https://www.michalsons.com/blog/the-ai-disclosure-clause-drafting-tips-for-vendor-contracts/63475)).
- **Company-side governance concerns (user statements, not policies).**
  - A Claude Code user cites SOC 2 and ISO 27001 change-management evidence as a reason to keep vendor session links out of commits ([#83226](https://github.com/anthropics/claude-code/issues/83226)).
  - Cursor forum users cite security audits and regulatory compliance ([forum](https://forum.cursor.com/t/co-author-added-without-consent-and-cant-be-turned-off/150096)).
- **Debian (a project rule, not an employer rule).** Contributors must not disclose confidential or embargoed material to third-party AI services unless authorised ([Debian GR 2026-002](https://www.debian.org/vote/2026/vote_002)).

### Inferences
- Procurement-style rules favour notifying the client about AI use in deliverables over banning it outright. That is a private, bilateral disclosure, not a public trailer. It fits a "selective disclosure to the client" model.
- Organisations' stated worry is control over what enters their audit trail, not whether AI was used.

### Gaps
- I found no primary text from a named consultancy, agency or large enterprise that forbids AI in delivered code or mandates commit trailers for client work.
- I did not read the GSA "Proposed Government AI System Terms and Conditions" or the California DGS "GenAI Special Provisions" (both surfaced in search).
- An Intel supplier policy barring confidential code from GenAI tools was mentioned only second-hand.

## 6. Is there evidence that maintainers or companies would value a verifiable but private attestation over public trailers, or do they see any record as intrusive?

### Takeaway
There is direct but thin evidence for "private record, selective disclosure":
- One explicit feature request (October 2026) for hash-only, provider-signed session receipts with "the transcript on request".
- Developers arguing that session links belong in local metadata, not "the public source tree".
- An organisation demanding that disclosure in history be its own decision.
- The kernel's move from per-commit tags to cover-letter narrative.
- Vendors (git-ai, Entire) moving transcripts out of public repositories.

There is no evidence that maintainers would verify cryptographic attestations. Their revealed preference is to judge the person (vouching, reputation) and the outcome (curl), not the record.

Opposing voices see any record as surveillance or advertising: Zig forbids even talking about LLM use, and a Hacker News post titled Agent Trace "Big Brother Is Watching".

### Cited Findings

#### For private or verifiable records
- **Claude Code feature request [#101813](https://github.com/anthropics/claude-code/issues/101813)** (13 Oct 2026, open, no reactions), "Provider-signed session receipts: verifiable 'made by model X, unedited' for commits and PRs".
  - On today's trailers: "Anyone can type that line. A squash drops it. A hand edit after the session leaves no trace."
  - It proposes a hash chain signed by the provider, a git note or `Receipt:` trailer, and a replay check.
  - "The receipt holds only hashes. The author reveals the transcript on request, so private prompts stay private."
- **HN, 30 Aug 2026** ([HN 49498201](https://news.ycombinator.com/item?id=49498201)):
  - _pdp_: "given that sessions are local and personal why tag it into the public source tree when it can keep a catalogue within the local session metadata with the exact branch, tags and refs. Sounds like easier less intrusive thing to do."
  - Another user: linking commits to sessions is "a lifesaver when you are trying to debug an old commit to pull up the chat session that actually wrote it".
  - A third built a script to search opencode's session database.
- **Organisational control** ([#83226](https://github.com/anthropics/claude-code/issues/83226), 2 Aug 2026): disclosure in version-control history "should be that organisation's decision"; a vendor URL "places a third-party identifier inside the customer's audit trail".
- **Kernel, October 2026.** Maintainers "do still want to know how a patch was created" (human involvement, models), but "this belongs in the cover letter… rather than in the changelog" ([commit 1e035297ffda](https://github.com/torvalds/linux/commit/1e035297ffda); [LWN](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)). The kernel's `generated-content.rst` asks for prompts, or a summary of them, at submission time ([kernel.org](https://www.kernel.org/doc/Documentation/process/generated-content.rst)).
- **Node.js.** Contributors should disclose "what the contributor does to personally verify the generated output", which is a request for evidence of human review. Brand names belong in the PR description, not the permanent commit message ([ai-guidelines.md](https://github.com/nodejs/node/blob/main/doc/contributing/ai-guidelines.md)).
- **LLVM.** "labelling is intended to facilitate reviews, and not to track which parts of LLVM are generated" ([LLVM policy](https://llvm.org/docs/AIToolPolicy.html)).
- **Vendor architecture moves.**
  - git-ai stores prompts "outside of Git… enabling fine-grained access control, and preventing PII or secrets from leaking" ([git-ai README](https://github.com/git-ai-project/git-ai)).
  - Entire warns that transcripts pushed to a public remote are readable by anyone and offers a separate private checkpoint repository ([Entire README](https://github.com/entireio/cli)).
  - Copilot session logs are shared with "anyone with access to the repository" ([GitHub docs](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions)).
- **Foundation research.** LF Research recommends "standardize attribution practices", and Red Hat's Brian Proffitt calls for "dependable model lineage". These are stated needs, not survey results ([LF press release](https://www.linuxfoundation.org/press/new-lf-research-survey-shows-generative-ai-cuts-open-source-coding-time-in-half-but-25-of-incoming-pull-requests-are-considered-ai-slop)).

#### Revealed preference for trust in people, or indifference to provenance
- Ghostty's vouch system rests on trust in people rather than artifacts ([CONTRIBUTING.md](https://github.com/ghostty-org/ghostty/blob/main/CONTRIBUTING.md)).
- GitHub's bypass signals are account age, merged PRs and organisation membership ([#197319](https://github.com/orgs/community/discussions/197319)).
- curl: "really, we don't care" which model was used ([High-Quality Chaos](https://daniel.haxx.se/blog/2026/04/22/high-quality-chaos/)).
- Debian encourages disclosure but does not require it ([Debian GR](https://www.debian.org/vote/2026/vote_002)).

#### Seeing any record as intrusive
- Zig: "No talking about use of chatbot/LLM services" ([Zig CoC](https://ziglang.org/code-of-conduct/)).
- Kernel: the tag "might scare people away from using LLMs" (Torvalds, per LWN) ([LWN](https://lwn.net/SubscriberLink/1099594/6e351ed3aecb2ae4/)).
- An HN submission titled "Big Brother Is Watching" linked to the Agent Trace repository (2 Feb 2026, 1 point; title only) ([HN 46854637](https://news.ycombinator.com/item?id=46854637)).
- Users add CI gates to block any AI attribution ([#83813](https://github.com/anthropics/claude-code/issues/83813)).

### Inferences
- The strongest demand signal for a private record comes from developers and organisations, not OSS maintainers:
  - Individual developers want to retrieve sessions behind their own commits.
  - Compliance-bound organisations want to decide what enters history.

  A team-keyed private record with optional disclosure answers both.
- For OSS maintainers, a selective-disclosure artifact would need to be cheap to consume at review time. A cover-letter-like statement such as "human reviewed, tests run, session on file" could fit the kernel, Node and LLVM norms.
- No evidence shows maintainers would check signatures. Its value is more likely as a dispute or audit record, for example a security incident or a licence question like cargo-msrv's "remove it as appropriate", than as a routine signal.
- Projects that ban AI (QEMU, Servo, Gentoo, NetBSD, Zig) will not value an attestation of AI use. For contributors to them, a private record is only useful if it is never disclosed.
- Employer-held records of employee agent sessions could be read as surveillance, a "Big Brother" framing. That risk is not tested in what I found.

### Gaps
- No survey or interview data directly compares maintainer preference for public trailers, private attestations, or nothing.
- I found only one explicit selective-disclosure request (#101813, no reactions).
- I found no OSS project that accepts or asks for signed attestations of human review.

## 7. Legal context in brief

### Takeaway
US law treats purely AI-generated material as uncopyrightable and AI as a non-author:
- Copyright Office, Part 2 report, 29 Jan 2025.
- Thaler v. Perlmutter, cert denied 2 Mar 2026.

This underpins the projects' DCO stance (only humans sign off) and some objections to "Co-Authored-By: Claude". EU AI Act Article 50 transparency duties apply from 2 Aug 2026 to synthetic "text" and to published text on matters of public interest. Article 50 does not mention software code. The only OSS citation of it I found is the ASF's, and it covers announcements and website text, not commits.

### Cited Findings
- **US Copyright Office.** Part 1 (Digital Replicas) was published 31 Jul 2024. Part 2 (Copyrightability) was published 29 Jan 2025. A Part 3 (Training) pre-publication version was released 9 May 2025 ([copyright.gov/ai](https://www.copyright.gov/ai/)).
- **Part 2 conclusions, commentary.** Prompts alone "do not provide sufficient human control" for authorship. AI used as a tool does not limit protection, but AI used as a substitute for human creativity does. Decisions are case by case ([IPWatchdog, 29 Jan 2025](https://ipwatchdog.com/2025/01/29/part-two-copyright-office-ai-report-says-creative-prompting-doesnt-constitute-authorship/); [Copyright Alliance summary](https://copyrightalliance.org/ai-report-part-2-copyrightability/)).
- **2023 registration guidance, quoted in a Claude Code issue.** "Applicants should not list an AI technology or the company that provided it as an author or co-author simply because they used it" (88 Fed. Reg. 16190, 16 Mar 2023) ([#66602](https://github.com/anthropics/claude-code/issues/66602)). The ASF page also references the 16 Mar 2023 guidance and the Part 2 report ([ASF](https://www.apache.org/legal/generative-tooling.html)).
- **Thaler v. Perlmutter.** The Supreme Court denied certiorari on 2 Mar 2026 (No. 25-449), leaving the 2025 D.C. Circuit human-authorship ruling in place (130 F.4th 1039). Courts have not decided how much human input suffices ([Holland & Knight, Mar 2026](https://www.hklaw.com/en/insights/publications/2026/03/the-final-word-supreme-court-refuses-to-hear-case-on-ai-authorship); [Reed Smith](https://www.reedsmith.com/our-insights/blogs/viewpoints/102mlpl/supreme-court-denies-certiorari-in-thaler-v-perlmutter-human-only-rule-for-ai/)).
- **DCO and CLA implications cited by projects.**
  - Kernel and OpenJS: AI must not add Signed-off-by; "Only humans can legally certify the DCO" ([kernel](https://www.kernel.org/doc/Documentation/process/coding-assistants.rst); [OpenJS](https://openjsf.cdn.prismic.io/openjsf/acqiJpGXnQHGZGtq_OpenJSAICodingAssistantsPolicy.pdf)).
  - QEMU declines AI output because its "copyright and license status… is ill-defined" under the DCO ([QEMU](https://www.qemu.org/docs/master/devel/code-provenance.html)).
  - Gentoo cites copyright risk to "copyleft guarantees" ([Gentoo](https://wiki.gentoo.org/wiki/Project:Council/AI_policy)). Servo cites verbatim reproduction of copyrighted training data ([Servo](https://github.com/servo/book/blob/main/src/policy/ai-usage.md)). NetBSD presumes LLM code is "tainted" ([NetBSD](https://www.netbsd.org/developers/commit-guidelines.html)).
  - The ASF ICLA requires each contribution to be "your original creation" ([ASF](https://www.apache.org/legal/generative-tooling.html)).
  - Debian "does not seek to resolve these unsettled legal questions" ([Debian](https://www.debian.org/vote/2026/vote_002)).
  - A CLA bot blocked a Gemini co-author trailer because the AI identity had not signed the CLA ([gemini-cli #25721](https://github.com/google-gemini/gemini-cli/issues/25721)).
- **EU AI Act Article 50** ([text](https://artificialintelligenceact.eu/article/50/)).
  - 50(2): providers must ensure synthetic audio, image, video or text output is "marked in a machine-readable format and detectable as artificially generated or manipulated".
  - 50(4): deployers of AI-generated text "published with the purpose of informing the public on matters of public interest" must disclose it, unless it "has undergone a process of human review or editorial control".
  - Application date: 2 Aug 2026. The article does not mention software code.
- **Code of Practice.** The final, voluntary Code of Practice on marking and labelling AI-generated content was published on 10 Jun 2026. Signatories get a presumption of conformity, per law-firm commentary ([European Commission](https://digital-strategy.ec.europa.eu/en/news/commission-publishes-code-practice-marking-and-labelling-ai-generated-content); [Jones Day, Jun 2026](https://www.jonesday.com/en/insights/2026/06/european-commission-publishes-final-code-of-practice-on-marking-and-labelling-aigenerated-content)).
- **Digital Omnibus.** The trilogue deal of 7 May 2026 reportedly gives providers of systems on the market before 2 Aug 2026 until 2 Dec 2026 for 50(2) marking. Sources disagree on whether the text is formally in force ([Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/); [Simmons & Simmons](https://www.simmons-simmons.com/en/publications/cmoveo6ke00icuxskpgueb0od/ai-omnibus-update)).
- **ASF's use of Article 50 (policy text).**
  - For announcements, security advisories, blog posts, release notes and website content: "Under the EU AI Act (in force since 2 August 2026), such text must be labeled as AI-generated unless a person reviewed it before publication and takes responsibility for it… In short: review it before you publish it, or label it."
  - The Act itself entered into force in 2024. 2 Aug 2026 is the date Article 50 starts to apply. ASF's wording conflates the two ([ASF](https://www.apache.org/legal/generative-tooling.html)).
- **Other citations of the Act.** Fabio Rehm's blog cites EU AI Act labelling (August 2026) as context for attribution ([blog](https://fabiorehm.com/blog/2026/03/02/our-coding-agent-commits-deserve-better-than-co-authored-by/)). I found no OSS project citing Article 50 as the basis for commit trailers.

### Inferences
- The legal picture pushes toward recording human authorship and review, rather than AI co-authorship. A record proving "a human reviewed and modified this" is the legally useful fact, under both the USCO "AI as tool" framing and the Article 50(4) human-review exemption. A "Co-Authored-By: AI" trailer is legally the wrong assertion.
- Article 50(4)'s exemption, as the ASF applies it, makes provable human review valuable for published text. That is a narrow but real hook for a "human-reviewed, on file" attestation.

### Gaps
- I did not read the Part 2 report PDF directly; its conclusions come from commentary.
- I did not confirm the final Article 50 guidelines or the Official Journal status of the Omnibus.
- I found no court decision on AI-generated code specifically, or on DCO liability for AI-assisted patches.
