# User-reported gaps in Claude Code, GitHub Copilot, Codex, and Cursor

Scope: what users say is missing or broken, late 2026. Today is 2026-10-31. Quotes below are short exact lines from pages that were opened. Reaction counts are included only when that page showed them. Vendor changelog text is labeled as vendor, not as a user. Reddit threads did not render (old.reddit.com returned only a shell), so they are not quoted. No Stack Overflow 2026 survey page was opened, so no survey share is claimed. URnetwork is not cited.

Jobs these complaints were scored against, and only when the user's words match:

1. Context and project memory that survives a session, preferably as files a team can share.
2. Reaching a service on the user's machine.
3. A public TLS name for that service.
4. An inbox or group thread shared by people and agents.
5. Team auth.
6. An admin record of what the agent read or changed.
7. Driving the same local tool from more than one harness.

Copilot Memory timing: GitHub's changelog dated 28 October 2026 says "GitHub Copilot Memory is now generally available on paid Copilot plans." That sentence is vendor copy from the changelog listing, not a user. Every Copilot user complaint opened below is about instruction files or cloud-agent loading, and all of them were posted before 28 October 2026 except one follow-up on 19 October 2026 that is still pre-GA. No opened user post after 28 October evaluates the Memory product itself. Three days is too short to treat silence as satisfaction.

## What do users say about memory between sessions, repeated mistakes, and instruction files that do not carry to the next run?

### Takeaway

Across all four products, users already have a project instruction file (CLAUDE.md, AGENTS.md, .cursor/rules, .github/copilot-instructions.md) and still report that the agent drops those rules inside a long session, especially after compaction or later turns. That pattern is repeated on each product's own tracker or forum, not one angry post. A second, narrower complaint is that automatic memory notes are local, wrong, or never loaded, so a new session does not start from the last correction.

### Cited Findings

Claude Code, repeated theme, issue still open when fetched:

- flux627, 22 August 2025, on anthropics/claude-code #6354 (page showed 30 thumbs-up on the issue): "I noticed that I have to tell it to re-read this every time it compacts, otherwise it starts doing things in 'common sense' ways that deviate from the 'correct way' that is defined." Expected behavior he wrote: "After compaction, Claude should remember or re-read CLAUDE.md." The bot on the same issue listed three earlier reports of the same failure (#4017, #4517, #1027). — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- DougJoseph, 12 September 2025, same issue (8 thumbs-up on the comment): "I have this problem with every auto-compact. Claude Code forgets what is in Claude.md and I have to tell it to read again." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- rogerc66, 21 October 2025, same issue: "After conversation compaction/summarization, Claude needs to be explicitly reminded to follow CLAUDE.md conventions, otherwise it reverts to generic behavior that doesn't match my established patterns." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- tatyree, 24 November 2025, same issue (4 thumbs-up): "I routinely have this problem as well. It just wiped out a running production project because it carried on making changes after compaction and before I could catch it." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- solace-rcampbell, 7 January 2026, same issue (6 thumbs-up): "After every compact, I have to tell it to re-read the memory files." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- SebRogala, 4 February 2026, same issue, after testing a SessionStart hook: the hook fired and injected text on `/compact`, but "Claude follows it?" was marked no. "The compacted conversation summary creates 'momentum' that overrides the injected reminder." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- asvishnyakov, 29 January 2026, same issue: "HALF A YEAR! And nothing done for that. I'm sorry, this isn't even free, we pay you money for that." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- John-Rood, 27 September 2026, same issue, describing current builds rather than the 2025 bug as originally filed: "The rules text surviving is mostly handled now. What still fails is rank. After compaction the summary is the live frame, so anything re-injected reads as background and gets outranked." — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- David Corvoysier, 21 October 2026, first-person essay, not an issue tracker: "My experience is that you get obsessed with delusional or obsolete facts or conclusions that you fetch from notes I never sanctioned." He also wrote: "A fresh session has less context, yet can act on them with complete confidence. I then have to untangle its interpretation of a summary I never approved." He turned auto-memory off (`autoMemoryEnabled: false`) and kept rules in a CLAUDE.md he commits. The Claude reply he quotes is the model's words, not an independent user. — [Hugging Face essay](https://huggingface.co/blog/dacorvo/the-ambiguous-state-trap)
- stanleypdp, 25 October 2026, anthropics/claude-code #105076 (open; one human reply, which is a product pitch). Single thread, not a chorus: "Memory written in these sessions lands under the scratch path and is deleted together with the session. In two days I got four separate throwaway memory directories." And: "Memory and CLAUDE.md that months of sessions accumulated under the real project folders ... are never loaded. Claude behaves as if it had never seen the project." He says this is because auto-memory is keyed to the primary working directory. — [Issue #105076](https://github.com/anthropics/claude-code/issues/105076)

Cursor, repeated forum theme from 2025 into 2026. The opened thread does not show a reaction count. The forum's related-topics table lists other threads with reply and view counts; those are not agreement counts:

- Kinland, 31 October 2025, Cursor forum: "while it seems to follow rules for new chats, it forgets about them after a few messages, making rules more or less useless." Also: "Cursor rules are not any better than asking an agent to 'always do ___' in chat." He points at an older thread, "Cursor just ignores rules," and says the behavior had lasted at least seven months. Version he reported: 2.0.43. — [Cursor ignores project rules](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)
- user1094, 8 November 2025, same thread: "If it will not adhere you the rules, then how can you trust the output." — [same thread](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)
- jee1lee, 11 November 2025, same thread: "I agree. I don't know why the cursor doesn't fix the rules." — [same thread](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)
- condor, Cursor staff, 11 November 2025, same thread. This is a vendor reply, included because it confirms the limit users are hitting: "AI models are not deterministic, therefore when they processes the rules but may ignore them. This is not necessarily a Cursor thing but rather LLM related." Staff advice on that page: keep threads short; don't make rules long. — [same thread](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)
- Related-topics table on that page, not opened individually: "Cursor just ignores rules" (16 replies, 2984 views, activity 14 November 2025), "Cursor Does Not Respect Rules" (8 replies, 632 views, 6 September 2025), "Why does Cursor ignore rules?" (8 replies, 1086 views, 28 November 2025), "Cursorrules getting ignored" (1 reply, 177 views, 21 January 2026). Views are not votes. — [same thread](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)

OpenAI Codex. Two different failures, both on openai/codex:

- guidedways, 30 August 2025, issue #2927 (9 thumbs-up; closed 25 December 2025 by etraut-openai, an OpenAI contributor, with "I think this bug is stale and no longer relevant"). User text: "after a `/compact` it does not inject the file and forgets these instructions." Expected: "`AGENTS.md` should always be read just as it does when you start a new conversation." wbdb, 11 September 2025: "Still up to date with 0.34.0." No later user on that thread confirmed the close. Treat the compact-drop as a 2025 report that the vendor marked stale, not as a 2026 confirmation it still happens. — [Issue #2927](https://github.com/openai/codex/issues/2927)
- guidedways, 3 March 2026, issue #13386 (12 thumbs-up; still open when fetched; last comment 24 October 2026): "Codex silently truncates `AGENTS.md` at `32 KB` ... Any instructions past that limit are dropped and never sent to the model - with no warning anywhere in the TUI, /stats, exec, or VS Code extension." — [Issue #13386](https://github.com/openai/codex/issues/13386)
- jdanbrown, 14 July 2026, same issue, Codex 0.144.4: "I only accidentally discovered today that my 40KB AGENTS.md was being truncated to 32KB and silently omitting 20% of my instructions!" The 20% is his file, not a survey. — [Issue #13386](https://github.com/openai/codex/issues/13386)
- phrypy, 16 June 2026, same issue: "there's no easy way to see which instructions ended up past the cut, so a rule that's 'being ignored' looks like the model misbehaving when it actually never received the text." — [Issue #13386](https://github.com/openai/codex/issues/13386)

GitHub Copilot. These are about instruction files, not about Copilot Memory the product. All are before the 28 October 2026 general availability.

- Szer, 24 February 2026, GitHub Community discussion #187926 (page showed 15 votes): "Custom instructions have no observable effect on Copilot Code Review on GitHub.com." Also: "The reviewer piles on findings and comments on trivial style - exactly what the instructions tell it not to do." He had `.github/copilot-instructions.md` and a path-specific `.instructions.md`, and said the repo setting "Use custom instructions when reviewing pull requests" was on. — [Discussion #187926](https://github.com/orgs/community/discussions/187926)
- CyanoFresh, 16 March 2026, same discussion (1 vote): "Copilot completely ignores it every time." — [Discussion #187926](https://github.com/orgs/community/discussions/187926)
- davideoliveri, 19 October 2026, same discussion (2 votes): "A few months in, the issue is still there. Is there an effective way to instruct the reviewer agent?" — [Discussion #187926](https://github.com/orgs/community/discussions/187926)
- Tomosu-AI, 20 October 2026, reply on that discussion, workaround not a fix: "treating the instructions file as a nice-to-have and moving anything that must hold into a deterministic check ... the reviewer can still miss the instructions, but the rule can't be skipped." — [Discussion #187926](https://github.com/orgs/community/discussions/187926)
- yukishigure, 26 May 2026, discussion #196934 (2 votes). One repro, not a pile-on: on an organization-owned repo, Copilot cloud agent from the Agents tab never fetched `.github/copilot-instructions.md`. "The session log shows no evidence of the file being fetched at any point during the session. The instruction is completely ignored." The same file worked, in his tests, on a personal repo in the Agents tab and on the org repo inside VS Code. — [Discussion #196934](https://github.com/orgs/community/discussions/196934)

Vendor, not a user, for the Memory date only: GitHub changelog, 28 October 2026, "GitHub Copilot Memory is now generally available on paid Copilot plans. Copilot can remember personal preferences and repository conventions across sessions and clients." — [Changelog](https://github.blog/changelog/2026-10-28-github-intelligence-puts-your-code-context-and-history-to-work)

### Inferences

- Job 1 matches the dominant complaint. Users are trying to keep project rules in a file a teammate could commit (CLAUDE.md, AGENTS.md, copilot-instructions.md, .cursor/rules). The failure they describe is not "there is no file." It is that a new turn, a compaction, a review agent, or a silent size cut does not honor the file.
- Claude's auto-memory and the notes Corvoysier audited are the opposite of a shared file: the agent writes them, the user did not approve them, and the next session treats them as fact. That is a user rejecting automatic memory, not asking for more of it.
- Codex #2927 (compaction) was closed by the vendor in December 2025 without a user saying it was fixed. Codex #13386 (silent 32 KB cut) was still being reproduced in October 2026. Do not collapse those into one "Codex has no memory" claim.
- Copilot complaints opened here predate Memory's general availability. They do not show whether repository memories fixed code-review instructions. They do show that, through 19 October 2026, a committed instructions file was not enough for the review agent.
- Cursor's own staff, on the opened thread, treats rule-following as model non-determinism. Users on that thread treat it as the product failing at the thing rules were supposed to do.

### Gaps

- No opened user quote after 28 October 2026 about Copilot Memory itself (wrong memories, can't edit, not shared, or working). The 93% "better adherence" figure on the changelog is a vendor review of preview sessions, not a survey of users, and is not used here as a user statistic.
- Reddit r/ClaudeCode threads about forgetting after compaction (including a 20 October 2026 post) appeared in search and were not quoted, because the page did not return the post body.
- openai/codex issues #4466 (September 2025, "now it ignores my agents file"), #25884 (June 2026, rules read early then applied inconsistently), and #44171 (September 2026, "does not reliably follow explicit instructions") showed up in search. The full threads were not opened, so they are not quoted. They suggest the AGENTS.md-ignored theme is broader than the two issues that were opened.
- microsoft/vscode #272492 (21 October 2025) showed up in search with a user saying Copilot "forgets" instructions mid-thread. The issue was not opened; the search extract also said the reporter later closed it after finding custom instructions. Not quoted.
- No opened page was a neutral survey of how often any of this happens. Thumbs-up and discussion votes are the only counts.

## What do users say is missing when they try to keep a correction for the next session or the next teammate?

### Takeaway

A correction typed in chat does not, in these reports, become a durable team rule by itself. Users who want the next session to keep it put it in a file. That file then fails in product-specific ways: Claude compaction outranks it, Codex clips the tail with no warning, Cursor's model ignores it after a few messages, and Copilot code review does not read it. Automatic notes that do persist are per user or per machine, and at least one Claude user says they persist the wrong conclusion.

### Cited Findings

- Corvoysier, 21 October 2026, on why a correction does not safely carry: the agent "write[s] a note at the end of a session from [its] own conclusion, you never see it, and the next session loads it as a fact and defends it." What he uses instead: "Rules go in files I write. ... every change is a commit I can read." He keeps a CLAUDE.md and an AGENTS.md side by side in dotfiles so more than one agent gets the same rules. — [Hugging Face essay](https://huggingface.co/blog/dacorvo/the-ambiguous-state-trap)
- unitedideas, 27 May 2026, on Codex #13386, about sharing one instruction file across people and tools: "When teams share AGENTS.md / CLAUDE.md-style files across tools, the last sections are often the guardrails: deploy checks, secret rules, browser limits, and 'do not run this' notes. Silent truncation means the user can believe the harness migrated cleanly while the riskiest instructions are the ones that disappeared." He asked for "an inspectable assembled-instructions path" so someone can prove what was loaded before the first edit. — [Issue #13386](https://github.com/openai/codex/issues/13386)
- jdanbrown, 14 July 2026, same issue: he had believed Codex was unreliable for two months before noticing the file was clipped. The correction was in the file; the next session never received the end of it. — [Issue #13386](https://github.com/openai/codex/issues/13386)
- stanleypdp, 25 October 2026: memory and CLAUDE.md "are never loaded" when the desktop app starts the session in a scratch directory, so months of accumulated project context are not there for the next session. He also says there is "no app setting for a default folder per Project," so the folder has to be re-attached every session. One reporter. — [Issue #105076](https://github.com/anthropics/claude-code/issues/105076)
- Kinland, 31 October 2025: a project rule in `.cursor/rules` "seems to follow rules for new chats" and then "forgets about them after a few messages." That is inside one chat, before the next teammate even matters. A committed rule file did not hold the correction for the rest of the session. — [Cursor forum](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)
- Szer, 24 February 2026, and davideoliveri, 19 October 2026: repo-level Copilot instructions, which are the file a teammate would commit, "have no observable effect" on code review, and months later "the issue is still there." — [Discussion #187926](https://github.com/orgs/community/discussions/187926)
- yukishigure, 26 May 2026: the committed instructions file reached the cloud agent on a personal repository and in VS Code, and did not reach it on an organization-owned repository. Teammates using the org repo from the Agents tab would not get the correction even though it was in git. Two votes. One thread. — [Discussion #196934](https://github.com/orgs/community/discussions/196934)
- flux627 and the later #6354 comments, August 2025 through September 2026: the correction is already in CLAUDE.md, which can be committed, and the next stretch of the same session still does not apply it after compaction. John-Rood's September 2026 note says re-injecting the file is no longer the missing piece; the summary outranks it. — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)

### Inferences

- Job 1 again, with a sharper edge: "for the next teammate" only works if the memory is a file in the repo. Users who describe that path say the file is necessary and not sufficient.
- Nothing opened shows a user successfully handing a chat correction to a teammate through the product's own memory store. The working pattern they describe is hand-editing CLAUDE.md, AGENTS.md, or copilot-instructions.md, then hoping the next run loads all of it.
- Corvoysier's side-by-side CLAUDE.md and AGENTS.md is the closest opened remark to job 7 (one set of rules, more than one harness). It is his workaround, not a report that one local service can be driven from two harnesses. Job 7 does not match.
- yukishigure's org-versus-personal split is the nearest thing to job 5 (team auth). He describes a silent failure to fetch a file on org repos, not a missing login or an auth model he wishes existed. One thread, two votes. Do not generalize it to "Copilot has no team auth."

### Gaps

- No opened user said, in those words, that a saved Copilot memory could not be seen or edited by a teammate. Secondary write-ups of the docs claim that limit. Those pages were not opened, so the limit is not cited.
- No opened user described Codex memories (`~/.codex/memories`) failing to sync to another machine or another person. Vendor docs say memories are local and off by default; that page was not opened, so it is not quoted.
- Cursor user-rules living only in a local database, with no export, appeared in a February 2026 forum search hit. That thread was not opened, so it is not quoted. Project rules in `.cursor/rules` are the shareable path, and the opened complaint is that the model does not follow them.

## What do users say about admin logs, privacy of prompts, or not being able to see what the agent did?

### Takeaway

The opened complaints are about missing records, not about prompts being too visible. Cursor users asked for an audit trail of tool calls and approvals and reported that the in-chat change list hides files the agent wrote. Codex users said there is no signal when instructions are dropped before the model sees them. No opened user post in this pass complained that an admin could read their prompts.

### Cited Findings

- villepispa, 30 March 2026, Cursor forum feature request: "Cursor agents propose tool calls (file edits, shell commands, MCP calls, file deletions) and the user accepts or rejects each one. None of these proposals or decisions are persisted in any queryable, exportable form." He says the Enterprise audit log "explicitly excludes agent actions" and quotes the product as: "We do not log agent responses or generated code content." He says hooks cover prompts and generated code "but not tool call proposals, approval/rejection decisions, timestamps, or which model requested the action." The question he says an organization cannot answer: "What did the AI agent do, and did a human authorize it?" The "we do not log" line is his quotation of Cursor, not a docs page opened for this note. — [Cursor forum](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247)
- znuttyone, 9 October 2026, same thread: "This still has not been addressed." A command-approval card asked to run `ls` commands. "the agent could not find a record of the request, and that there is no system-wide audit trail." "Right now a request against my own machine can't be traced to its source." He says he set local commands back to ask-first. This is one person bumping a March feature request, with other comments in May, June, and July 2026. The page does not show a vote count. — [same thread](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247)
- safal207, 23 June 2026, same thread: an audit trail that does not bind the approved action to the executed action "may still be impossible to prove that the executed action was precisely the action the user approved." — [same thread](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247)
- Evelinah, 24 October 2026, separate Cursor bug, version 3.27.12: the change list "does not show all of the changed files making me rely on external source control software to see what my agent avoided telling me it changed." Expected: "I must be able to see ALL of the changed files." On 26 October she said Review still missed a file, and that cleaning it up would mean opening "100 older agents." No vote count on the page. — [Cursor forum](https://forum.cursor.com/t/agent-file-change-tracking-is-wrong-almost-all-of-the-time/176037)
- hahaha1, 29–30 October 2026, same bug thread: "Same issue on linux 3.27." After retesting 3.23 through 3.26: "They all have the same issue. Parallel editing → some line count missing in the keep. sequential editing is fine." — [same thread](https://forum.cursor.com/t/agent-file-change-tracking-is-wrong-almost-all-of-the-time/176037)
- Colin, Cursor staff, 26 October 2026, same thread. Vendor admission on that page, not a user: terminal or script edits "aren't tracked as pending changes at all," and "Source Control remains the complete record, including terminal-made changes." Also, the All Changes tab "isn't available in chats that used subagents." — [same thread](https://forum.cursor.com/t/agent-file-change-tracking-is-wrong-almost-all-of-the-time/176037)
- phrypy, 16 June 2026, and guidedways, 3 March 2026, Codex #13386: no warning "anywhere in the TUI, /stats, exec, or VS Code extension" when instructions are truncated, and no easy way to see which sections were cut. That is "what did the agent actually read," not a full admin log of edits. — [Issue #13386](https://github.com/openai/codex/issues/13386)
- yukishigure, 26 May 2026: he could tell the instruction file was skipped only because "the session log shows no evidence of the file being fetched." He had a session log. The gap he reports is that the fetch never happened, not that no log exists. One thread. — [Discussion #196934](https://github.com/orgs/community/discussions/196934)
- tatyree, 24 November 2025, Claude Code #6354: the agent "carried on making changes after compaction" before he could catch it. He describes damage from an action he could not see coming, not an admin export. — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)

GitHub's own agent audit-log docs came up in search (enterprise owners can filter `actor:Copilot`, and a streaming preview can include request or response bodies for some enterprise types). That page was not opened and is vendor documentation. It is not a user saying the log is missing or sufficient. It is not used as evidence that Copilot users are satisfied.

### Inferences

- Job 6 matches Cursor specifically, in two layers: no persisted record of proposed tool calls and approvals (villepispa, still complained about on 9 October 2026), and an incomplete on-screen list of files changed (Evelinah and hahaha1, late October 2026, with staff saying terminal edits and subagent chats are outside that list). Users fall back to git.
- Job 6 matches Codex only for "what text was loaded into the prompt," not for "what files were edited." The user pain is a silent clip, so ignored rules look like a bad model.
- Job 6 does not have an opened Claude Code or Copilot user quote of the form "admin cannot see what the agent read or changed." Claude users describe the agent acting after it has forgotten the rules. That is a control problem, not an audit-log request.
- Job 2 (reaching a service on the user's machine) does not match. znuttyone's `ls` card is about not being able to trace a local command, not about the agent being unable to reach a local service.
- No opened complaint matches job 3 (a public TLS name) or job 4 (a shared inbox or group thread).

### Gaps

- No opened user post about prompt privacy, training on prompts, or an admin seeing chat text, for these four coding products. Absence here means this pass did not open one, not that nobody has complained.
- A secondary blog claimed Claude Code deletes session transcripts after 30 days and pointed at anthropics/claude-code #62476 (opened 26 May 2026). That issue was not opened, so it is not quoted.
- Copilot enterprise audit content (what is and is not in the log) was not checked against a user. Do not infer a Copilot admin-log gap or the lack of one from the docs titles in search.

## Which complaints are common across products, and which sit on one product's tracker?

### Takeaway

The repeated, cross-product complaint is: a project instruction file does not govern the agent for the whole session or the next run. Compaction is the named trigger on Claude Code (open issue, comments from August 2025 through September 2026) and was the named trigger on Codex in 2025 (closed by the vendor as stale). Cursor users describe the same symptom without calling it compaction, across several forum threads. Copilot users describe it for code review, with 15 votes on one discussion that was still active on 19 October 2026. The mechanisms that are not shared are Codex's silent 32 KB cut, Claude desktop's scratch-workspace memory key, Copilot cloud agent skipping organization repos, and Cursor's missing tool-approval audit log.

### Cited Findings

Common pattern, one opened source per product:

- Claude: "Claude does not remember CLAUDE.md after compaction" (flux627, 22 August 2025, #6354, 30 thumbs-up, still open, with users repeating it into 2026). — [Issue #6354](https://github.com/anthropics/claude-code/issues/6354)
- Codex: "after a `/compact` it does not inject the file and forgets these instructions" (guidedways, 30 August 2025, #2927, 9 thumbs-up, closed by OpenAI 25 December 2025 as stale). Separate 2026 mechanism on the same repo: silent truncation (#13386, 12 thumbs-up, open). — [Issue #2927](https://github.com/openai/codex/issues/2927); [Issue #13386](https://github.com/openai/codex/issues/13386)
- Cursor: "it forgets about them after a few messages, making rules more or less useless" (Kinland, 31 October 2025), with staff saying models may ignore rules, and the forum listing several similar threads from 2025 into January 2026. — [Cursor forum](https://forum.cursor.com/t/cursor-ignores-project-rules/140303)
- Copilot: "Custom instructions have no observable effect on Copilot Code Review" (Szer, 24 February 2026, 15 votes), still reported 19 October 2026, before Memory GA. — [Discussion #187926](https://github.com/orgs/community/discussions/187926)

One product's tracker, or a single thread:

- Claude desktop only: scratch working directory drops per-folder memory and does not load CLAUDE.md. stanleypdp, 25 October 2026, #105076. One reporter plus a vendor-of-another-product reply. He links #95485 and #76694; those were not opened. — [Issue #105076](https://github.com/anthropics/claude-code/issues/105076)
- Codex only: 32 KB shared budget, no UI warning, root file can starve a nested AGENTS.md. Opened thread #13386, March through 24 October 2026, 12 thumbs-up. Claude, on the same thread, is cited by the reporter as warning when CLAUDE.md is too big. That contrast is his claim. — [Issue #13386](https://github.com/openai/codex/issues/13386)
- Copilot only: cloud agent on an organization-owned repo never fetches `.github/copilot-instructions.md` while the personal-repo and VS Code paths do. yukishigure, 26 May 2026, #196934, 2 votes. Do not treat this as the same bug as code review ignoring instructions (#187926), which is about the reviewer not applying a file, not about the file never being fetched. — [Discussion #196934](https://github.com/orgs/community/discussions/196934)
- Cursor only: no exportable record of tool-call proposals and approvals, and a change list that omits files. villepispa 30 March 2026 and znuttyone 9 October 2026; Evelinah 24 October 2026 and hahaha1 29–30 October 2026. Two threads, both still active in October 2026. Not found in the opened Claude, Codex, or Copilot threads. — [Audit request](https://forum.cursor.com/t/platform-level-audit-trail-for-agent-tool-call-proposals-and-user-approval-decisions/156247); [File tracking](https://forum.cursor.com/t/agent-file-change-tracking-is-wrong-almost-all-of-the-time/176037)
- Claude only, one author: auto-memory notes the user never approved are loaded next session and defended. Corvoysier, 21 October 2026. He says he checked the notes and "Claude marked only about 20% of the project notes as still valid." That 20% is his project, measured by the model, not a user survey. — [Hugging Face essay](https://huggingface.co/blog/dacorvo/the-ambiguous-state-trap)

### Inferences

- Safe cross-product sentence: users of all four products report that writing the rule down in the product's instruction file does not make the agent keep it. The file is the shared-memory mechanism they already have (job 1), and they say it does not hold.
- Unsafe cross-product sentence: "none of them have memory." Claude has auto-memory that at least one user turned off because it remembered the wrong thing. Codex has an AGENTS.md loader that at least one user found was clipping the file rather than ignoring it. Copilot shipped a Memory product on 28 October 2026; this pass has no user verdict on it.
- Jobs 2, 3, 4, and 7 have no opened user wording that matches. Job 5 has only the single org-repo fetch bug, which is a bad fit. Job 6 is a Cursor theme in this pass, plus a narrower Codex "show me what you loaded" complaint.

### Gaps

- Search hits that look like more of the same theme were not opened: Codex #4466, #7774, #8547, #9987, #25884, #44171; Cursor forum threads linked from the related-topics table; Copilot community #164390 (June 2025), #184036 (January 2026), and #197646 (June 2026); vscode #300804 ("Copilot user memory never used," March 2026, closed not-planned) and #308669 (April 2026). They are leads, not citations.
- No opened Hacker News thread and no opened 2026 developer survey.
- Post-GA Copilot Memory user reaction: not found in pages opened between the 28 October announcement and 31 October. Do not fill that with the pre-GA instruction-file complaints.
