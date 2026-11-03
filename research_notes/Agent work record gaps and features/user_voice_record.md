# What developers and engineering leads say they need from a record of AI-agent work (user voice, state as of 31 October 2026)

How this was gathered and counted. GitHub issues were pulled with the authenticated GitHub API (bodies, reactions, all comments) for anthropics/claude-code, openai/codex, github/copilot-cli, entireio/cli, git-ai-project/git-ai, specstoryai/getspecstory and google-gemini/gemini-cli. Hacker News threads were pulled through the HN Algolia items API (full comment trees). Cursor forum topics were pulled through the forum's Discourse JSON API. "Participants" means distinct non-staff, non-bot accounts that opened or commented on a thread. Staff and vendor accounts are excluded from counts and labeled "Vendor" where quoted (bcherny on claude-code; etraut-openai, gpeal and pakrym-oai on codex; Colin, deanrie, kevinn and mohitjain on Cursor; khaong, pjbgf and soph2k on Entire; svarlamov and acunniffe on git-ai; tenpaiyomi, belucid and bago2k4 on SpecStory). Participant counts include tool builders promoting their own fixes, so they measure attention, not complainants. "+1" is the thumbs-up count on the opening post only; each account can give one. Reddit did not load (HTML block page on JSON endpoints, HTTP 403 on search). GitHub Discussions search through the GraphQL API returned unrelated results, so Copilot coding-agent discussions are a gap. Items already covered by earlier rounds were not redone: Claude Code #6354, Codex #13386, HN 47103237, the Cursor tool-call audit-trail thread, the Cursor agent file-change tracking thread, and MCP Agent Mail #41/#263. Prior-round Cursor audit and observability findings (Ville Pispa, znuttyone, Ayush Shyam Agrawal, Trong Vo and others) are in `User gaps in top tools/inbox_audit_user_gaps.md`.

## Reviewing agent changes: what do people say about knowing what an agent changed, why, and in what order?

### Takeaway
The most-reacted review pain is not a missing audit log. It is the lack of one session-scoped view of everything the run changed. Claude Code VS Code users want Copilot- or Cursor-style aggregated diff review (#33932: 220 +1, 40 participants). Codex IDE users want the full diff before approving (#2998: 241 +1, 53 participants). Claude Code users protested when collapsed tool rows hid which files were read (#21151: 185 +1, 52 participants). Every harness's change list misses edits made through shell commands, subagents or reverts. In August–September 2026, Claude Code's auto mode itself steered edits into Bash, which silently disabled checkpoints, diffs and edit hooks (#87575 and #87971: 140 combined +1).

### Cited Findings
- yakupadakli, 13 March 2026, Claude Code #33932 (308 reactions: 220 +1, 53 hearts; 47 comments; 40 participants): "When Claude Code modifies files in the VS Code extension, there is no built-in UI to review, accept, or reject those changes. I have to leave the Claude Code panel and manually check the Source Control panel or run `git diff`." Open. — [Claude Code #33932](https://github.com/anthropics/claude-code/issues/33932)
  - Comments in the same thread. luayalshawi, 2 May 2026 (25 reactions): "It seems it's designed for vibe coders where they blindly accept anything… The experience to review, accept, reject small edits or even review the whole session edits is so critical." egelev, 9 June 2026 (20 reactions): "Relying on `git diff` as a workaround is inconvenient and error-prone when dealing with large refactors." ImmortalWing, 25 April 2026 (14 reactions): edits are "written directly to disk without going through VS Code's `TextEditorEdit` API… No gutter decorations." — [Claude Code #33932](https://github.com/anthropics/claude-code/issues/33932)
- brilliant-directories-user, 7 March 2026, Claude Code #31888 (59 +1; 20 participants; closed 22 October 2026). The extension offers "Ask before edits – approves changes one line at a time, forcing decisions without seeing the full picture" or "Edit automatically – makes all changes silently with no diff review at all." — [Claude Code #31888](https://github.com/anthropics/claude-code/issues/31888)
  - wesleymostien, 17 July 2026: "In auto-accept mode there's no way to review the session's changes as one aggregated set afterward — `/diff` gives per-turn navigation rather than a single batched view, and plain git diff pulls in any pre-existing uncommitted changes in the repo that predate the session." — [Claude Code #31888](https://github.com/anthropics/claude-code/issues/31888)
  - HawkarShwany, 8 June 2026 (12 reactions): "Approving each change one by one really defeats the purpose of agentic development and auto approve really makes you a vibe coder." c266, 11 March 2026: "Copilot and Codex extensions handle things more conveniently." — [Claude Code #31888](https://github.com/anthropics/claude-code/issues/31888)
- yuan763161, 31 August 2025, Codex #2998 (241 +1; 67 comments; 53 participants): asks for IDE-integrated diff and approval. — [Codex #2998](https://github.com/openai/codex/issues/2998)
  - theclunkerjunker, 16 September 2025 (30 reactions): "Codex only shows a tiny little window with a proposed diff… You have to let it write to disk to use git and/or VSCode diff viewer which is not ideal when you are trying to collaborate and approve each…" — [Codex #2998](https://github.com/openai/codex/issues/2998)
  - swfunc, 18 September 2025 (26 reactions): "Right now the `View all changes` button to see the full editor diff is only visible after accepting the changes." Vendor: gpeal (OpenAI contributor account) pointed users to "View all changes." — [Codex #2998](https://github.com/openai/codex/issues/2998)
- tristananh120-web, 27 January 2026, Claude Code #21151 (185 +1; 133 comments; 52 participants). Collapsed "Read 1 file (ctrl+o to expand)" rows give "No indication of WHICH file." The stated reasons: "1. Debugging - need to see what agent tried to access 2. Security - hook blocks should show blocked path immediately 3. Audit trail - scrolling through conversation, can't tell what was read." — [Claude Code #21151](https://github.com/anthropics/claude-code/issues/21151)
  - binaryfire, 27 January 2026 (39 reactions): "This 'dumbing down' of tool usage output might be ok for vibe coding but it's a disaster for complex pair programing." — [Claude Code #21151](https://github.com/anthropics/claude-code/issues/21151)
  - Vendor: bcherny (repo collaborator), 28 January 2026 (89 reactions): "This isn't a vibe coding feature, it's a way to simplify the UI so you can focus on what matters, diffs and bash/mcp outputs." On 11 February 2026 he said file paths were back behind the verbose setting. — [Claude Code #21151](https://github.com/anthropics/claude-code/issues/21151)
- Auto mode routes edits around the record. knobik, 18 August 2026, Claude Code #87575 (43 +1; 15 participants): auto mode's system prompt tells the model to edit through Bash, and "Those writes aren't tracked by the checkpoint system, so /rewind reports success but leaves every change on disk." — [Claude Code #87575](https://github.com/anthropics/claude-code/issues/87575)
  - tholcman, 19 August 2026 (32 reactions): "This flag doesn't change style, it switches off the entire set of features that exist to make agent edits safe and reviewable — all at once: `/rewind`… diff rendering — edits land as opaque shell output, nothing to review - file-history — no undo…" — [Claude Code #87575](https://github.com/anthropics/claude-code/issues/87575)
  - tgrushka, 19 August 2026 (10 reactions): "I'm legally blind. Read/Edit/Write are not a preference for me — the diff is the only channel I have to know what changed in a file." — [Claude Code #87575](https://github.com/anthropics/claude-code/issues/87575)
  - Counterview, vinceAmstoutz, 28 August 2026 (7 reactions): "Bash commands are a great default for auto mode, token savings from skipping heavy schemas are huge… Just add an opt-out toggle." — [Claude Code #87575](https://github.com/anthropics/claude-code/issues/87575)
- dflor003, 19 August 2026, Claude Code #87971 (97 +1; 16 participants). On 20 August (16 reactions): "we've had to add this instruction to our enterprise managed settings and roll it out to all the engineers as a work around until this is fixed." — [Claude Code #87971](https://github.com/anthropics/claude-code/issues/87971)
  - MarcEspiard, 19 August 2026: "It makes following along very difficult (or even after the fact, checking what it did by scrolling up)." future3OOO, 8 September 2026: "What the hell is the point of configuring those hooks if the harness then explicitly tells the model to take a path that never invokes them?" — [Claude Code #87971](https://github.com/anthropics/claude-code/issues/87971)
- liaoruoxing, 16 September 2026, Claude Code #94657 (3 +1): in one auto-mode session of 124 user prompts, there were 96 Bash calls and 0 Edit/Write calls, so "every checkpoint is created with an empty `trackedFileBackups`." — [Claude Code #94657](https://github.com/anthropics/claude-code/issues/94657)
- "What did it actually run." adiSilber, 1 July 2026, Claude Code #72859 (3 +1; one-off): wants a `/shell-history` "to understand what was changed (and that deletions… were done right), reproduce a sequence of steps, or write documentation… the commands are truncated in the UI." Vendor: bcherny, 17 August 2026: "There's no dedicated command for this yet." He pointed to Ctrl+O and `/export`. — [Claude Code #72859](https://github.com/anthropics/claude-code/issues/72859)
- Subagent edits. conrado, 21 August 2026, Claude Code #88622 (0 reactions; closed stale): "When Claude Desktop hands work to sub-agents, I have no way to check what they actually did: which commands ran, which files they read or changed… The information is already saved on disk, as a full transcript per sub-agent… For work where I have to answer for every action (infrastructure, production access) I need that record in the app, without digging through JSON files by hand." — [Claude Code #88622](https://github.com/anthropics/claude-code/issues/88622)
- maparham, 22 July 2026, Claude Code #80006 (one-off): a subagent ran `git reset <past-commit>` "to 'isolate its own diff' and silently orphaned committed work… a headless run would have merged a branch missing entire tasks… Instructions alone don't fix it." — [Claude Code #80006](https://github.com/anthropics/claude-code/issues/80006)
- Cursor, vendor statement on scope. mohitjain (staff), 7 September 2026: "A restore only reverts files the agent edited with its own edit tools. Anything a terminal command, a subagent, or you changed by hand stays under Changes." This matches the prior round's staff statement on the file-change thread. — [Cursor forum 170624](https://forum.cursor.com/t/rollback-doesn-t-restore-previous-chat-state-and-files-remain-in-git-changes/170624)
- Nova_Spivack, 24–26 October 2026, Cursor forum. A revert "targeted files outside the active chat's workspace, including another git repository, an ignored .env file… The operation ran without a preview or confirmation. Its only direct record was a burst in composer.log." There were four events in four days, and he asked Cursor to "log the trigger and reason for every r[evert]…" Vendor: Colin said revert "acts on every file that chat itself edited or created earlier, wherever it lives… permanently deletes files that didn't exist then." — [Cursor forum 176032](https://forum.cursor.com/t/cursor-ide-revert-to-message-operation-crosses-workspace-boundaries-and-silently-targets-ignored-files/176032)
- Scott_Macdonald, 12 October 2026, Cursor forum: wants the old per-section accept/reject review back in the Agents window. Vendor: Colin said per-change review exists only in the Editor window, and the Agents window's Changes view is git-based. — [Cursor forum 174469](https://forum.cursor.com/t/bring-back-the-review-tool-from-earlier-cursor-ide-versions/174469)
- Attribution confusion. johnmathews, 29 March 2026, Claude Code #40710 (121 reactions, but only 16 +1; 20 participants): he reported Claude Code running `git reset --hard origin/main` every 10 minutes. On 30 March he retracted: "this was a bug in a tool I built… The evidence was misleading because the tool shared the same CWD." He could not tell which process ran a destructive git command. — [Claude Code #40710](https://github.com/anthropics/claude-code/issues/40710)
- Kuinox, 10 February 2026, HN (Entire launch thread): "The downside of agents is that they make too much changes to review, I prefer being able to track which changes I wrote or validated from the code the AI wrote." — [HN 46962543](https://news.ycombinator.com/item?id=46962543)
- Armin Ronacher, 13 February 2026, blog post "The Final Bottleneck": "I too am the bottleneck now." Also: "I feel like something is very wrong here and it's time to reflect." He says people struggle to keep up with the code they generated themselves. — [lucumr.pocoo.org](https://lucumr.pocoo.org/2026/2/13/the-final-bottleneck/)
- Reviewing other people's agent PRs. wiktor-k, 19 March 2026, Claude Code #36105 (52 +1): "I've seen people contributing to my projects using Claude Code and these git commits include the `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>` trailer." He asks for `Assisted-by` instead. — [Claude Code #36105](https://github.com/anthropics/claude-code/issues/36105)
- HN, Ghostty's "AI tooling must be disclosed for contributions," 21 August 2025 (729 points; 436 comments; 230 authors).
  - philjohn: "I like the pattern of including each prompt used to make a given PR… it also gives context of the steps required to get to the end state." — [HN 44977150](https://news.ycombinator.com/item?id=44977150)
  - hoppp: "All the prompts and responses should be committed to git." — [HN 44979014](https://news.ycombinator.com/item?id=44979014)
  - Counterview, ovaistariq: "I don't see much benefit from the disclosure alone. Ultimately, this is code that needs to be reviewed." — [HN 44977140](https://news.ycombinator.com/item?id=44977140)
- Simon Willison, 7 February 2026, on Mitchell Hashimoto's Vouch: Vouch responds to "the deluge of worthless AI-generated PRs faced by open source projects." — [simonwillison.net](https://simonwillison.net/2026/Feb/7/vouch/)

### Inferences
- The object users describe is a session-scoped change set: every file the run touched, whatever the tool path (Edit, Bash, subagent, revert), in order, and excluding uncommitted changes that predate the session (wesleymostien's point). `git diff` is everyone's fallback, and it fails on exactly that point.
- The gap from tool path to record is confirmed across products. Claude Code checkpoints miss Bash edits, which auto mode made the default. Cursor's own staff say restore and the change list miss terminal and subagent edits. A record that observes from outside the harness's edit-tool layer, at the process, filesystem or git level, would catch what harness-native checkpoints miss. This is a design implication; no user asked for a sidecar.
- Users give four reasons: debugging, security, audit trail ("answer for every action"), and accessibility. Compliance is explicit only for conrado (infrastructure and production) and implicit in dflor003's enterprise-wide workaround.
- By product, complaints centre on the Claude Code VS Code extension and auto mode, the Codex IDE extension, and Cursor's Agents window.

### Gaps
- No first-person complaint about reviewing large Copilot coding-agent PRs on github.com was found. GitHub Discussions search through the API returned unrelated results.
- Codex #15367 ("VS Code extension should show exact in-editor change locations like Copilot, and Undo/Revert must be reliable," 15 +1) was seen only as a search-result title and not opened.
- Pragmatic Engineer's "Are AI agents actually slowing us down?" (17 March 2026) appeared in a search listing but was not opened.

## Context inspection: do users ask to see exactly what an agent was given for a run, and why?

### Takeaway
Yes, but usually after a surprise. Users discovered hidden context by asking the model: the auto-mode "use Bash" instruction (#87971) and their account email injected into the system prompt (#81138: 77 +1). They then asked to see or control what was injected or read, for debugging, trust and security. Explicit requests to "show me the full system prompt or request body" are scattered one-offs. People who need it build logging proxies or tracing tools. One user pinpointed the structural gap: no hook can see the assembled request.

### Cited Findings
- dflor003, 19 August 2026, Claude Code #87971 (97 +1): "I asked it why it was doing that and it reported that it received this instruction straight from the harness." — [Claude Code #87971](https://github.com/anthropics/claude-code/issues/87971)
- skflowne, 25 July 2026, Claude Code #81138 (91 reactions: 77 +1; 16 participants): "Claude Code takes personal data I gave Anthropic in order to authenticate, and injects it into the model's system prompt on every session — automatically, without my consent, without disclosing that it does so, and with no supported way to stop it." — [Claude Code #81138](https://github.com/anthropics/claude-code/issues/81138)
  - inigohidalgo, 1 September 2026 (12 reactions): "The agent decided to override my git config and commit with my subscription email address as my git identity." — [Claude Code #81138](https://github.com/anthropics/claude-code/issues/81138)
  - mootari, 20 October 2026, quoting Claude's admission in the web harness: "I put your account email address into the User-Agent header of requests…" — [Claude Code #81138](https://github.com/anthropics/claude-code/issues/81138)
- localfirst-ai, 10 June 2026, Claude Code #44868: "What no hook can do, because no event in the hooks reference covers it, is inspect or modify the assembled request body before it leaves. So you can know the file changed, and still not know what actually entered the context that went out." — [Claude Code #44868](https://github.com/anthropics/claude-code/issues/44868)
- ratrifa, 23 June 2026, Claude Code #70216 (0 reactions; closed as duplicate): "There is no built-in feature in Claude Code to directly view the currently active system prompt." — [Claude Code #70216](https://github.com/anthropics/claude-code/issues/70216)
- rawwerks, 14 June 2025, Claude Code #2090 (7 +1): `OTEL_LOG_USER_PROMPTS` "will log the prompt, but there is no way to log the response." He later used badlogic's claude-trace. iwinux, 26 July 2025: "My OpenTelemetry collector received the logs but it's completely useless." — [Claude Code #2090](https://github.com/anthropics/claude-code/issues/2090)
- YuriyKrasilnikov, 18 April 2026, Claude Code #50513 (15 +1, 8 hearts): "request RCA and auditability guarantees." ArkNill, 19 April 2026: "I've been running a proxy-based analysis on Claude Code traffic… 38,996 intercepted requests, Apr 1–16, Max 20x, 272 sessions." That is a logging proxy built to see what was actually sent. — [Claude Code #50513](https://github.com/anthropics/claude-code/issues/50513)
- ai-is-here, 27 January 2026, Claude Code #21151 (39 reactions), on why reads must be visible: "when asked to read a large file with instructions, it might decide to read 100 lines and call it a day and pretend that it's all knowing now." — [Claude Code #21151](https://github.com/anthropics/claude-code/issues/21151)
- chdeskur, 11 May 2026, Codex #22230 (17 +1): OTel logging of agent responses is "needed for monitoring and evaluating agent behavior, especially regarding adherence to `SKILL.md` directives." — [Codex #22230](https://github.com/openai/codex/issues/22230)
- SRNissen, 24 September 2026, Codex #41574: "I've found myself using `/export`, cutting away many irrelevant early turns, then scrolling through the actual TUI to find the parts that *don't* get exported… And even with this process, I don't have e.g. the escalation prompts." — [Codex #41574](https://github.com/openai/codex/issues/41574)
- lukstafi, 26 July 2025, Claude Code #4483: "/export only includes context since the last compaction and moreover without the compaction's summarization." — [Claude Code #4483](https://github.com/anthropics/claude-code/issues/4483)
- gitcnd, 10 March 2025, SpecStory #41: "Different agents are wildly different in capabilities, and I was trying to work out which one I used with extreme success a few days ago… the specstory didn't capture that info." Vendor: bago2k4 said in November 2025 that exports now show the model. — [SpecStory #41](https://github.com/specstoryai/getspecstory/issues/41)

### Inferences
- Users ask "what did you read, what was injected, what did you obey" after odd behaviour. They rarely ask for a full prompt dump in advance. A per-run record of injected instruction blocks, files read (with ranges), tool outputs and model identity would answer most of these complaints.
- Harness-native exports drop compacted turns, approval and escalation prompts, and subagent output, which are the parts needed to explain behaviour.

### Gaps
- Few compliance-motivated requests to see full context were found. Most are about debugging and trust.
- The Codex instruction-truncation complaint (#13386) belongs here but was covered by an earlier round and not redone.

## Approvals: who asks for approvals to be recorded, bound, delegated or given remotely; what about approval fatigue and auto-approve?

### Takeaway
Approval complaints fall into four groups:
- No record exists. Session grants are invisible, and the "Allow" click fires no hook.
- Approval semantics are silently overridden. Hook "ask" decisions are auto-approved in auto and bypass modes, Codex retired `untrusted`, and Cursor's "Always Run" stores bare command names.
- Remote approval on a phone is broken. Prompts recur despite bypass mode, and push notifications shipped only in August 2026.
- Damage happens under Run Everything or YOLO modes when nothing is gated.

Few people explicitly ask to "log what ran while auto-approved." Several discover that auto modes also turn off the change-tracking and cost records they relied on.

### Cited Findings
- SavoryBytes, 10 March 2026, Claude Code #32904 (3 +1; 6 participants; closed stale 21 May 2026): "No command to list which transient permissions are currently active - No log recording that the approval happened - No way to revoke a session-level permission without restarting… You cannot answer the question: 'What have I authorized Claude to do in this session?'" He proposes a "Permission audit log — Write every allow/deny decision (transient and persistent) to a local file." — [Claude Code #32904](https://github.com/anthropics/claude-code/issues/32904)
  - yurukusa, 28 March 2026, posting a hook workaround: "This won't capture the 'Allow' click itself (no hook event for that)." — [Claude Code #32904](https://github.com/anthropics/claude-code/issues/32904)
  - Tool-builder claims in the same thread, all unverified. Daedalab "works at the proxy level so the audit record exists independently of what Claude Code…". Signet, on the official plugin marketplace, says "every tool invocation gets an Ed25519 signature + hash-ch[ain]." — [Claude Code #32904](https://github.com/anthropics/claude-code/issues/32904)
- rpicatoste, 20 April 2026, Claude Code #51255 (5 +1): "A `PreToolUse` hook returning `permissionDecision: "ask"` is silently auto-approved when running in auto mode. The user is never prompted." — [Claude Code #51255](https://github.com/anthropics/claude-code/issues/51255)
  - jandubois, 10 May 2026: the same happens in `bypassPermissions`; "the harness logs it as `hook_success` but runs the tool without prompting." He cites session JSONL as evidence. — [Claude Code #51255](https://github.com/anthropics/claude-code/issues/51255)
- hoiung, 27 February 2026, Claude Code #29214 (84 +1; 30 participants; open): Remote Control on mobile shows permission prompts despite `--dangerously-skip-permissions`. — [Claude Code #29214](https://github.com/anthropics/claude-code/issues/29214)
  - NathanEckford, 27 February 2026: "Whenever I re-open the mobile app I have to approve the same requests over and over. Eventually it can be 10+ back-to-back, that I've already approved." — [Claude Code #29214](https://github.com/anthropics/claude-code/issues/29214)
  - jbojcic1, 27 March 2026: "I can have another machine setup just for claude where it can have all permissions… and then I remote control it from my personal machine. This way I am not exposing my personal machine." — [Claude Code #29214](https://github.com/anthropics/claude-code/issues/29214)
  - xxparrotxx, 10 October 2026: the suggested workaround "does **not** fix this for me." — [Claude Code #29214](https://github.com/anthropics/claude-code/issues/29214)
- Streadz, 27 February 2026, Claude Code #29438 (59 +1; 13 participants): "Without notifications, you have to babysit the session to catch permission prompts." zawilliams (20 reactions): "Every day I check and see if this is a new feature." Vendor: bcherny, 17 August 2026, said "Push when actions required" had shipped. — [Claude Code #29438](https://github.com/anthropics/claude-code/issues/29438)
- acrookston, 7 March 2026, Claude Code #31908 (29 +1): wants Remote Control combined with skip-permissions so he can "monitor and steer each agent" running in Docker sandboxes. Vendor: bcherny said the two can be combined. — [Claude Code #31908](https://github.com/anthropics/claude-code/issues/31908)
- eambrosyupgrade, 21 August 2026, Codex #39973 (41 +1; 13 participants): Codex 0.149.0 retired `approval_policy = "untrusted"`, and "the effective default becomes `on-request`, which provides a materially weaker command-execution approval boundary." Handlebar4 (19 reactions): "The most popular LLM degrades user security and control with no warning." — [Codex #39973](https://github.com/openai/codex/issues/39973)
- BobbyWang0120, 6 September 2025, Codex #3247 (34 +1): wants notify hooks on approval events so teams can build "custom approval flows, or external alerting systems." Vendor: etraut-openai, 16 January 2026: "We're rethinking how notifications work in Codex." — [Codex #3247](https://github.com/openai/codex/issues/3247)
- Jason_Witherspoon, 3 October 2026, Cursor forum: "Always Run is neither 'remember this command' nor a working sticky allow." — [Cursor forum 173687](https://forum.cursor.com/t/always-run-stores-bare-command-names-from-heredoc-chains-but-the-next-identical-name-chain-still-prompts/173687)
  - ActionGate, who says he is researching agent trust, 4 October 2026: "do you think people will end up approving artifacts (scripts, PRs, plans) rather than individual terminal commands? It feels like reviewing every shell invocation won't scale." — [Cursor forum 173687](https://forum.cursor.com/t/always-run-stores-bare-command-names-from-heredoc-chains-but-the-next-identical-name-chain-still-prompts/173687)
- Newts00579, 17 October 2026, Cursor forum: the agent auto-ran a command that wiped an entire drive. "Run Mode: Run Everything. Since nothing was gated, the allowlist wasn't in play at all. That's partly on me. I've gotten used to working with agents like Codex and models like Claude Opus and GPT, and I've never really worried about what they're capable of." Vendor: deanrie said that in this mode "all tool calls run automatically, with no approval, sandbox, or classifier." — [Cursor forum 175121](https://forum.cursor.com/t/cursor-agent-auto-ran-a-command-that-wiped-an-entire-drive-windows-powershell/175121)
- Cimdddd, 21 August 2026, Cursor forum: "I have a strict project rule: the Agent must not change files without an exact approval phrase… The Agent still edited M[ain scene]…" Vendor: an 8 MB truncation bug, fixed in 3.24. — [Cursor forum 169064](https://forum.cursor.com/t/agent-truncated-unity-scene-file-without-approval-irreversible-data-loss/169064)
- Approval fatigue. qnleigh, 26 April 2026, HN: "how would one prevent this, short of manually approving all terminal commands? I still do this, but most people who use agents would probably consider this arcane." — [HN 47912102](https://news.ycombinator.com/item?id=47912102)
- Hidden cost of auto approval. Kamlesh364, 5 April 2026, Claude Code #43945: "Every auto-mode tool approval makes a real billable API call that never appears in `/cost`." — [Claude Code #43945](https://github.com/anthropics/claude-code/issues/43945)
- October 2026 cluster, seen as titles only and not opened (0–1 reactions each). In these, Claude Code's auto-mode classifier refuses actions the user approved:
  - [#100331](https://github.com/anthropics/claude-code/issues/100331): "no override available over Remote Control."
  - [#102636](https://github.com/anthropics/claude-code/issues/102636): "refused an explicitly approved production migration."
  - [#105743](https://github.com/anthropics/claude-code/issues/105743): "refusal gives no label… so it cannot be approved or reported."
  - Also [#101018](https://github.com/anthropics/claude-code/issues/101018), [#102732](https://github.com/anthropics/claude-code/issues/102732), [#104441](https://github.com/anthropics/claude-code/issues/104441), [#104281](https://github.com/anthropics/claude-code/issues/104281) and [#101465](https://github.com/anthropics/claude-code/issues/101465).

### Inferences
- Users treat an approval as a scoped grant with provenance (user, project or session), one they can list and revoke. Today it lives only in process memory, or it is overridden by mode logic and then logged as success. That is a binding failure: approved and executed are not reliably the same. The prior round's Cursor finding (Safonov's ActionProposed/Decided/Completed) is the same problem on another product.
- Under auto or YOLO modes, the documented harm is that the harness's own safety records go dark: checkpoints, diffs, hooks and `/cost`. Users rarely ask for a "YOLO log." A record that stays complete whatever the harness mode would address this, but it is an inference.
- Remote approval exists for Claude Code (Remote Control plus push since August 2026). Complaints are about permission-mode mismatch and re-prompting, not absence.

### Gaps
- No first-person request to delegate approval to another person, such as a lead approving a teammate's agent action, was found. Slack-based approval was not found in the pages opened here.
- The October 2026 auto-mode classifier issues were not opened, so their content is unverified beyond titles.
- Granola's blog post "Dangerously-skip-permissions is the only safe mode" appeared in HN search (May and July 2026) but was not opened.

## Replay, rewind and handoff: what is missing or broken per product?

### Takeaway
The strongest and most widely shared record pain in this corpus is session history that is lost or unreachable.
- Claude Code's silent 30-day transcript deletion is real. Claude Code #62476 exists (opened 26 May 2026), and Anthropic's repo collaborator reproduced the deletion on 17 August 2026. Seven issues have 64 participants and 84 opener +1s, plus a 28-author HN thread.
- Sessions hidden by UI or update bugs affect Claude Code, Codex and Cursor: eight threads, 137 participants.
- Handoff across surfaces, machines and teammates: 14 threads, 544 opener +1s.
- Codex's removal of `/undo` is the most-reacted rewind complaint: 490 +1, 59 participants.
- Repo-hook recorders (Entire, git-ai) miss work when the agent starts outside the repo or edits through Bash.
- No user evidence was found for Copilot coding-agent session logs. Amp has only a vendor statement.

### Cited Findings
Claude Code, retention:
- joelhochstetter, 26 May 2026, Claude Code #62476 (33 +1; 31 comments; 25 other people; labels bug, reproduced): "cleanupPeriodDays defaults to 30, causing Claude Code to silently delete ~/.claude/projects/<project>/<sessionId>.jsonl files older than 30 days on startup. There is no first-run disclosure, no warning before deletion, and the setting is not surfaced in /config. I lost months of conversation history." — [Claude Code #62476](https://github.com/anthropics/claude-code/issues/62476)
  - Vendor: bcherny (repo collaborator), 17 August 2026: "Verified on v2.1.233… a session transcript under `projects/` backdated 40 days: it was **deleted** during a run with default settings… with `{"cleanupPeriodDays": 3650}`… the file was **kept**." — [Claude Code #62476](https://github.com/anthropics/claude-code/issues/62476)
  - cadfan, 18 August 2026 (8 reactions): "A row in an online settings reference is not advance notice of…" — [Claude Code #62476](https://github.com/anthropics/claude-code/issues/62476)
  - mieubrisse, 6 July 2026: "I thought I was accumulating months of Claude transcripts, which I could eventually mine to extract patterns to encode my decisionmaking into Claude as skills… everything beyond 30 days had been deleted." — [Claude Code #62476](https://github.com/anthropics/claude-code/issues/62476)
- FTSBrand, 14 May 2026, Claude Code #59248 (43 +1; 67 comments; 40 other people; label data-loss): "Users who treat their conversation history as durable working knowledge are silently mistaken about the persistence mo[del]." — [Claude Code #59248](https://github.com/anthropics/claude-code/issues/59248)
  - ariutokintumi, 18 June 2026: "take parental or medical leave for more than 30 days, come back, everything is gone." — [Claude Code #59248](https://github.com/anthropics/claude-code/issues/59248)
  - DmitriyAlergant, 10 August 2026: "These transcripts contain a treasure trove of mineable knowledge and insights. They also serve as a proof of work, justifying the spend." — [Claude Code #59248](https://github.com/anthropics/claude-code/issues/59248)
- CCennon, 28 July 2026, Claude Code #82084: "Conversations carry reasoning and decision context that generated artifacts (CLAUDE.md, plans, roadmaps) do not — they are not disposable cache." He asks for "an archive-instead-of-delete option." — [Claude Code #82084](https://github.com/anthropics/claude-code/issues/82084)
- Bsimmons2113, 17 September 2026, Claude Code #95203: he stopped using the app in May; when he reopened it, every session was gone, "including archived ones." — [Claude Code #95203](https://github.com/anthropics/claude-code/issues/95203)
- omctim, 19 October 2026, Claude Code #103323: about 45 transcripts, the newest five days old, were deleted in one burst; "retention sweep ruled out." He asks for "a confirmation or a trash folder for any session delete, and no deletion of a transcript that belongs to a live process." — [Claude Code #103323](https://github.com/anthropics/claude-code/issues/103323)
- maksutovnurda, 31 October 2026, Claude Code #106326: the Desktop Code tab deleted about 23 CLI sessions while he moved a session from CLI to Desktop. "No copy in Trash, no Time Machine snapshot… permanent, unrecoverable loss." — [Claude Code #106326](https://github.com/anthropics/claude-code/issues/106326)
- arc-web, 1 October 2026, Claude Code #98575: `~/.claude/history.jsonl` "accumulates every prompt ever typed, in plaintext, and is **explicitly exempt** from `cleanupPeriodDays`." Prompts are kept forever while replies and edits are deleted. — [Claude Code #98575](https://github.com/anthropics/claude-code/issues/98575)
- HN "Beware, Claude Code deletes >30 day old transcripts," ojura, 30 June 2026 (30 points; 37 comments; 28 authors):
  - ralferoo, quoting the issue: "The transcripts are the user's record of their own thinking and work." — [HN 48733713](https://news.ycombinator.com/item?id=48733713)
  - skeledrew: he "couldn't find the session, which I wanted to continue from as it's a cheap way to track token cost at the project level." — [HN 48737550](https://news.ycombinator.com/item?id=48737550)
  - Counterviews. mwigdahl: "'Evil Anthropic implements rolling log files.' Film at 11." ([HN 48733935](https://news.ycombinator.com/item?id=48733935)). bpodgursky: "you can literally just make a crontab to copy them somewhere else" ([HN 48733636](https://news.ycombinator.com/item?id=48733636)). luxuryballs: "Probably a better practice to devise your own record/docs history to rely on rather than depending on Anthropic" ([HN 48736450](https://news.ycombinator.com/item?id=48736450)).
- simonw (Simon Willison), 15 July 2026, HN: "Horrifying, isn't it? Amazing to me how little these companies respect the historic value of the transcripts. Most of my work is captured in them now." — [HN 48921792](https://news.ycombinator.com/item?id=48921792)
- Simon Willison, 25 December 2025, on his claude-code-transcripts tool: "Those transcripts capture extremely important context about my projects." On Claude Code for web: "Getting transcripts out of that is even harder! I've been synchronizing them down to my laptop just so I can copy and paste from the terminal." On how: "I reverse-engineered the private API for this (so I hope it continues to work)." — [simonwillison.net](https://simonwillison.net/2025/Dec/25/claude-code-transcripts/)

Claude Code, sessions hidden or unreachable:
- luyufan498, 10 October 2025, Claude Code #9258 (51 +1; 35 participants): the VS Code extension lost its history, "and /resume couldn't locate it." bigshiny90: "Restoring sessions is completely unreliable." — [Claude Code #9258](https://github.com/anthropics/claude-code/issues/9258)
- igrushkas, 18 February 2026, Claude Code #26452 (33 +1; 41 participants): Desktop sessions disappeared after logout. benrodenhaeuser: "the conversations are still present in `~/.claude/projects`. It's just that Claude Desktop can't find them." — [Claude Code #26452](https://github.com/anthropics/claude-code/issues/26452)
- allsey87, 14 August 2025, Claude Code #5768 (61 +1; 19 participants): resume works only from the starting directory. Keesan12, 20 May 2026: "users lose portability and auditability the moment they move a checkout, use a different worktree, or reopen from a sibling clone." — [Claude Code #5768](https://github.com/anthropics/claude-code/issues/5768)
- harshidwasekar, 9 February 2026, Claude Code #24471 (20 +1): rewind history was lost after compaction, with "Nodes on dead branches (from rewinds): **10,607**." scapeshift-ojones: "branch data is perfectly preserved in JSONL… but the UI provides no way to navigate it." — [Claude Code #24471](https://github.com/anthropics/claude-code/issues/24471)

Claude Code, handoff and sharing:
- moazam1, 26 February 2026, Claude Code #28791 (156 +1; 36 participants): "I often start working on a project in the terminal and later want to continue or review that same conversation from the desktop app… Even a read-only view of CLI sessions in the desktop app would be a huge improvement." — [Claude Code #28791](https://github.com/anthropics/claude-code/issues/28791)
  - meshulga, 27 July 2026: "exactly the flow Codex supports (start in CLI, continue in the GUI)." — [Claude Code #28791](https://github.com/anthropics/claude-code/issues/28791)
- noctilust, 8 March 2026, Claude Code #31992 (22 +1): cross-machine resume. master-of-null, 10 April 2026: "`/resume` is machine-local and Remote Control only works for live sessions." — [Claude Code #31992](https://github.com/anthropics/claude-code/issues/31992)
- patrickhardiman, 12 November 2025, Claude Code #11455 (27 +1; 28 participants): "Onboarding new team members requires explaining full project history." sudoxreboot: "Lose the nuance of why certain decisions were made." — [Claude Code #11455](https://github.com/anthropics/claude-code/issues/11455)
- heonseoblee, 31 December 2025, Claude Code #15881 (62 +1): wants sessions to move between Code and Desktop. Crackkart: "I use Claude across VS Code agent, claude.ai browser, and Cursor." — [Claude Code #15881](https://github.com/anthropics/claude-code/issues/15881)
- elibarzilay, 9 June 2026, Claude Code #66373 (14 +1): wants to push a running local session up to the cloud. Vendor: bcherny said this is only partly covered by Remote Control. — [Claude Code #66373](https://github.com/anthropics/claude-code/issues/66373)
- jonastemplestein, 4 March 2025, Claude Code #323 (39 +1): "We'd like to get a 'chat transcript' (ideally including tool calls) after each session." junoatwork: "keeping transcripts is super helpful for sharing successful sessions with colleagues to learn by example." — [Claude Code #323](https://github.com/anthropics/claude-code/issues/323)

Codex:
- SunRunAway, 14 January 2026, Codex #9203 (490 +1; 97 comments; 59 participants): "Please make '/undo' back." Codex "unintenally deletes some files which is not tracked by git." — [Codex #9203](https://github.com/openai/codex/issues/9203)
  - RobRoyce, 26 January 2026 (21 reactions): "'Use git' is an asinine comment on this issue. What about when I want codex to review something before I commit it?" — [Codex #9203](https://github.com/openai/codex/issues/9203)
  - zzy-life, 30 June 2026: "Since switching from Claude Code to Codex, I have to commit to Git after every single conversation." — [Codex #9203](https://github.com/openai/codex/issues/9203)
  - Counterview, embedding-shapes (22 reactions): "Because you should be using git." — [Codex #9203](https://github.com/openai/codex/issues/9203)
- mkusaka (contributor), 27 August 2025, Codex #2788 (43 +1): history-linked checkpoints that restore file state. — [Codex #2788](https://github.com/openai/codex/issues/2788)
- GGBondBlueWhale, 2 May 2026, Codex #20741 (17 +1; 57 comments; 30 participants): Desktop project chat histories disappeared after an update. earlbellinger: the logs are still in `state_5.sqlite` and `session_index.jsonl` but do not appear. — [Codex #20741](https://github.com/openai/codex/issues/20741)
- IvoDimitrovPro, 30 August 2025, Codex #2935 (31 +1; 23 participants): local VS Code chats vanished, though the .jsonl files remained in `~/.codex/sessions`. — [Codex #2935](https://github.com/openai/codex/issues/2935)
- The opposite retention problem. BobbyWang0120, 31 October 2025, Codex #6015 (20 +1): Codex "retains every conversation indefinitely." — [Codex #6015](https://github.com/openai/codex/issues/6015)
  - ewzxyh, 8 August 2026: "396.5 GB was under `sessions` across 554 `rollout-*.jsonl` files… the largest rollout was 9.37 GB." — [Codex #6015](https://github.com/openai/codex/issues/6015)
  - claell, 25 July 2026: "Please make this opt-in, and never a silent default," citing the Claude Code deletions. — [Codex #6015](https://github.com/openai/codex/issues/6015)
- kendonB, 14 March 2026, Codex #14722 (21 +1): sync CLI and app-server sessions. t46, 30 July 2026: "File changes are present, but the original CLI/Desktop UI does not consistently show the remote turn history or the full execution transcript." — [Codex #14722](https://github.com/openai/codex/issues/14722)
- interconnectedMe, 24 October 2025, Codex #5609 (73 +1): "I have a janky workaround running that scans ~/.codex/sessions, then pulls each individual chat and formats to a .md file in a /worklog directory." — [Codex #5609](https://github.com/openai/codex/issues/5609)
- abanoub-ashraf, 2 March 2026, Codex #13267: wants to export the whole chat "to go continue somewhere else or validate something." phuturesh: "/export-ing a more portable rollout together with /imports can help us work better with teamates." — [Codex #13267](https://github.com/openai/codex/issues/13267)
- saulrichardson, 10 February 2026, Codex #11280 (11 +1): export threads to per-project storage so "someone… start a new thread and use slash command to get up to speed on previous work." — [Codex #11280](https://github.com/openai/codex/issues/11280)
- rockyicer, 6 October 2025, Codex #4825 (19 +1): share chats across PCs. Vendor: etraut-openai closed it for lack of upvotes. — [Codex #4825](https://github.com/openai/codex/issues/4825)

Cursor (checkpoints and chats):
- Serg_Ann, 31 October 2026: "Restore checkpoint" does not roll back changes (version 3.27.22). — [Cursor forum 176899](https://forum.cursor.com/t/the-changes-are-not-rolled-back-after-clicking-the-restore-checkpoint-button/176899)
- jkpe, 25 August 2026: "Checkpoints are still broken." — [Cursor forum 169425](https://forum.cursor.com/t/checkpoints-are-still-broken/169425)
- ceitflow, 5 September 2026: "latest version of cursor broke revert entirely, I went back to 3.14." — [Cursor forum 170624](https://forum.cursor.com/t/rollback-doesn-t-restore-previous-chat-state-and-files-remain-in-git-changes/170624)
- Kirsten_Kaptein, 13 October 2026: agent chats went missing after migrating to a new Mac. Vendor: kevinn said history is keyed to a workspace ID built from the folder path plus its creation date. — [Cursor forum 174627](https://forum.cursor.com/t/archived-agent-chats-missing-after-migrating-to-new-mac-conversations-exist-in-database/174627)
- SAK_CB, 16 September 2026: a chat of about two hours was lost when a usage limit hit. Vendor: deanrie confirmed it "shouldn't happen." — [Cursor forum 171897](https://forum.cursor.com/t/long-agent-chat-lost-when-other-models-usage-limit-hit-should-preserve-history-not-reset-switch-mid-session/171897)
- post4k, 25 September 2026: the agent lost its whole conversation when interrupted. Vendor: deanrie: "the saved history the agent actually uses comes back almost empty." — [Cursor forum 173005](https://forum.cursor.com/t/agent-loses-entire-conversation-when-interrupted-mid-work/173005)
- Peigian, 21 October 2026: a Cloud Agent workspace was lost. Vendor: Colin: "We don't have a snapshot of that machine on record that we can access and restore." — [Cursor forum 175669](https://forum.cursor.com/t/urgent-assistance-required-missing-cursor-cloud-agent-sessions-and-development-workspace/175669)

Copilot (CLI only; titles from search, not opened):
- [Copilot CLI #4082](https://github.com/github/copilot-cli/issues/4082), omkarnikam24, 10 July 2026 (14 +1): "Cross-app session sync between Copilot CLI and Copilot Desktop App."
- [Copilot CLI #1979](https://github.com/github/copilot-cli/issues/1979), DwainTR, 11 March 2026 (53 +1; closed): "Remote session support for Copilot CLI — attach from mobile / browser."
- [Copilot CLI #2000](https://github.com/github/copilot-cli/issues/2000), nickhoo555 (13 +1): "Copilot CLI session file cannot be opened in VS Code Copilot Chat."

Entire:
- jaksiks, 26 February 2026, Entire #529: sessions are not tracked when Claude Code launches from a non-git parent folder.
  - levelorbit, 26 October 2026: "One such thread made 29 commits in my repo over two days. 26 have no `Entire-Checkpoint` trailer."
  - VytlaDinesh, 26 October 2026: an agent launched from a folder above two enabled repos "was recorded by neither repo." lcv-leo reproduced the gap with Codex on 30 October 2026.
  - Source: [Entire #529](https://github.com/entireio/cli/issues/529)
- rraafffaa, 2 May 2026, Entire #1098 (3 +1): wants tracking without per-repo setup. — [Entire #1098](https://github.com/entireio/cli/issues/1098)
  - m13v: "the actual capture boundary is the agent process, not the working tree." — [Entire #1098](https://github.com/entireio/cli/issues/1098)
  - akshat-khare, 19 June 2026: "this is exactly which is stopping me and my org from using it." — [Entire #1098](https://github.com/entireio/cli/issues/1098)
- blackgirlbytes (contributor), 28 April 2026, Entire #1070: Copilot CLI sessions appear but transcripts are "empty or incomplete." jrmueller13, 1 September 2026: `entire cp explain` fails with "transcript has no content to summarize." — [Entire #1070](https://github.com/entireio/cli/issues/1070)
- HN launch thread "Ex-GitHub CEO launches a new developer platform for AI agents," 10 February 2026 (611 points; 504 comments fetched; 357 authors). It is mostly skeptical:
  - iamleppert: "I don't want agent context tied to git commits. I just want infinite scroll in Claude Code and ability to search and review all my past conversations!" — [HN 46966746](https://news.ycombinator.com/item?id=46966746)
  - rognjen: "I see zero reason for a person to care about the checkpoints. And for agents, full sessions just needlessly fill context." — [HN 46966418](https://news.ycombinator.com/item?id=46966418)
  - ajbajb: "I did test it and use it and trashed it because there is very little value." — [HN 46967727](https://news.ycombinator.com/item?id=46967727)
  - Supportive, xrd: "we humans need to audit both types of code. And this platform feels like it addresses this." — [HN 46968893](https://news.ycombinator.com/item?id=46968893)
- HN "How version control will evolve for the agent boom," an Entire blog post, 9 July 2026 (57 points; 45 authors):
  - wateralien: "We need to store CHOICES with the commit or branch. Not the whole session. Conscious, summarized choices." — [HN 48846415](https://news.ycombinator.com/item?id=48846415)
  - overgard: "nobody wants to read someone else's conversation with it, and certainly nobody wants to read a multi-year old session log that's 20,000 words long." — [HN 48846859](https://news.ycombinator.com/item?id=48846859)
  - Vendor: soph2k (Entire CLI maintainer): "We take the raw session logs, put it in the repo with a stable link to the commit." — [HN 48846265](https://news.ycombinator.com/item?id=48846265)

git-ai:
- divaltor, 21 January 2026, git-ai #387: "when the Agent deletes a file using Bash operations, the subsequent commit attributes the change to the user (human) rather than the AI." Vendor: svarlamov said running git status on every tool call would cost too much performance. — [git-ai #387](https://github.com/git-ai-project/git-ai/issues/387)
- js19950276, 26 May 2026, git-ai #1444: "All attribution lost (100% untracked) when human edits after AI checkpoint." nsingh, 25 June 2026: "This has become a recurring issue for our team." — [git-ai #1444](https://github.com/git-ai-project/git-ai/issues/1444)
- ran7878, 15 May 2026, git-ai #1379: Copilot agent-mode edits are not marked because the hooks were not called. — [git-ai #1379](https://github.com/git-ai-project/git-ai/issues/1379)

SpecStory:
- MichaelPaulukonis, 2 July 2025, SpecStory #82: auto-save captured only the first prompt and reply. Vendor: tenpaiyomi: "we are at the mercy of their whims to adjust their data storage methods." It was fixed in 0.14.0. — [SpecStory #82](https://github.com/specstoryai/getspecstory/issues/82)

Amp (vendor statement only):
- Amp, 2 June 2026, "The End of Public Threads": it is "getting too hard to review a thread to ensure it doesn't contain any snippets of sensitive files," and "Public discoverable thread sharing is just too risky now." Threads are now shared within a workspace or by unlisted URL. — [ampcode.com](https://ampcode.com/news/end-of-public-threads)

Moving between harnesses:
- kantord, 19 February 2026, HN ("npx continues"): "actually 'moving' context form one agent to another is even…" — [HN 47075132](https://news.ycombinator.com/item?id=47075132)
- Treegarden, 12 July 2026, HN (Mindwalk replay tool, 162 points): "history feature is per agent session, a cumulative history of all my agents would be nice." — [HN 48879774](https://news.ycombinator.com/item?id=48879774)
- Counterview, bakwan44: "I dont feel like i need to know what the agent did, never opened the session json." — [HN 48879685](https://news.ycombinator.com/item?id=48879685)

### Inferences
- Many users treat transcripts as durable work records: Simon Willison, DmitriyAlergant ("proof of work"), mieubrisse and CCennon. Others on HN treat them as rotating logs. A record product should make retention an explicit owner-set policy, archive rather than delete, and keep prompts and replies under the same policy. Claude Code today keeps prompts forever and deletes replies after 30 days.
- Hooks installed per repo miss agents launched from parent folders, edits made through Bash, and harnesses whose hooks never fire. m13v's "the capture boundary is the agent process" fits a subprocess that every harness launches.
- Third-party recorders that parse harness-internal storage break when the harness changes, as SpecStory's vendor admitted and Entire's Copilot parse failure shows. A recorder fed by protocol events would be more robust. This is an inference.
- Codex shows the opposite failure (396 GB kept forever), so users need retention policy, not only persistence.

### Gaps
- Copilot coding-agent (cloud) session-log complaints were not found. GitHub Discussions search through the API returned unrelated results, and the Copilot CLI items above are titles only.
- No first-person Amp user complaint was found; only the vendor announcement.
- Few 2026 complaints specific to `codex resume` across machines were found beyond #14722 and #5609.
- Reddit did not load.

## Cost and usage: do developers or leads ask for per-run, per-person or per-project cost records across tools?

### Takeaway
Yes, and it recurs, though with fewer reactions than the history complaints: 10 threads, 47 participants. Individuals want cost history across sessions and projects; Claude Code's `/cost` covers the current session only and undercounts subagents and classifier calls. Consultants want cost tied to a client. Claude Team and Enterprise admins say they cannot see per-user usage for subscription users (#27780: 26 +1, 19 participants). Codex admins want user identity in telemetry. Third-party trackers (ccusage, CodeBurn, budgetclaw) fill the gap, mostly for one harness, and users report runaway spend of $300 a week to $2,800 in one session.

### Cited Findings
- bbethell-1, 16 July 2026, Claude Code #78148 (9 participants): "The `/cost` command only shows usage for the current session… Required for any kind of chargeback or cost allocation." — [Claude Code #78148](https://github.com/anthropics/claude-code/issues/78148)
  - kindrat86, 11 August 2026: "after an agent session ran up $2,800 — we had dashboards showing exactly what happened, but only after the mone[y]…" — [Claude Code #78148](https://github.com/anthropics/claude-code/issues/78148)
  - kcarriedo, 27 July 2026: "/cost resets after compaction, so your true monthly spend is already undercounted." — [Claude Code #78148](https://github.com/anthropics/claude-code/issues/78148)
- oktN, 16 January 2026, Claude Code #18550: wants to "Budget and manage AI usage within teams/organizations." smarth-tech, 3 March 2026: there is "no way to see cumulative costs across sessions, compare spend by model, or get alerts when a project is approaching a budget." — [Claude Code #18550](https://github.com/anthropics/claude-code/issues/18550)
- StuLast, 3 May 2026, Claude Code #55768: "For professionals using Claude Code as a billable work tool — developers, consultants, agencies… there is no record of: How long the task took - Which project or client it was for - What the associated API cost was." — [Claude Code #55768](https://github.com/anthropics/claude-code/issues/55768)
- nkiphuth, 16 March 2026, Claude Code #34803: "We're a small dev team using Claude Code heavily… We'd love to include AI usage stats in our PR descriptions, sprint reports… 'This feature took 4 Claude sessions and 3.2M tokens.'" — [Claude Code #34803](https://github.com/anthropics/claude-code/issues/34803)
- Kamlesh364, 5 April 2026, Claude Code #43945: "/cost understates actual Anthropic API spend," because classifier side queries and background subagents are excluded. — [Claude Code #43945](https://github.com/anthropics/claude-code/issues/43945)
- jbensamo, 23 February 2026, Claude Code #27780 (26 +1; 19 participants; open): the Analytics Admin API returns only API customers, not subscription or OAuth users. — [Claude Code #27780](https://github.com/anthropics/claude-code/issues/27780)
  - joe-camp-15367, 31 March 2026 (9 reactions): "I'm finding it frustratingly difficult to get basic per user usage/cost data for Enterprise subscriptions. Wouldn't most every organization be needing this?" — [Claude Code #27780](https://github.com/anthropics/claude-code/issues/27780)
  - kohapple, 24 April 2026: Team-plan admins are "structurally unable to answer 'who uses heavily?' and 'who doesn't use their seat?'" — [Claude Code #27780](https://github.com/anthropics/claude-code/issues/27780)
  - denisurbanavicius, 27 April 2026: "We have gone completely blind metrics-wise." — [Claude Code #27780](https://github.com/anthropics/claude-code/issues/27780)
- jhsong-musinsa, 28 April 2026, Codex #19897 (18 +1): "Which users are actively using Codex? How much token/tool/session usage is attributable to each user? Which users or teams need enablement, support, or cost review?" — [Codex #19897](https://github.com/openai/codex/issues/19897)
- doggy8088, 5 September 2025, Codex #3201: wants "a tool that can always calculate the actual token usage through Codex CLI," pointing to ccusage. Vendor: etraut-openai said the rollout files already include token usage. — [Codex #3201](https://github.com/openai/codex/issues/3201)
- rebermusk, 30 August 2026, Cursor forum: Team members lose access to their own spending page when an admin locks usage settings. Vendor: Colin said this works as designed. — [Cursor forum 169996](https://forum.cursor.com/t/permission-regression-team-members-lose-access-to-their-own-spending-page-when-admin-only-usage-settings-is-enabled/169996)
- HN, ccusage thread, 18 July 2025 (75 points). extr: "I'm on the $100/mo Max plan and have been running $600-800/mo in terms of usage." — [HN 44611097](https://news.ycombinator.com/item?id=44611097)
- HN, CodeBurn thread, April 2026 (112 points). halostatue: "Doesn't seem to work with Cursor Agent." — [HN 47796769](https://news.ycombinator.com/item?id=47796769)
- HN, Vigilo thread, 25 February 2026. jcalloway_dev: "I blew past $300 in a week before I even noticed. The lack of visibility is genuinely alarming when you're letting an agent run autonomously." — [HN 47146356](https://news.ycombinator.com/item?id=47146356)

### Inferences
- Users want cost attached to the unit of work: session, project, client and PR (nkiphuth, StuLast, skeledrew). They also want all hidden spend included: subagents, classifiers, compaction. A record that joins run, cost and artifact would cover all of these.
- Cross-tool cost is mostly unmet. The trackers people cite are single-harness JSONL parsers.

### Gaps
- No first-person complaint about Copilot coding-agent premium-request billing per user was opened. [Copilot CLI #2591](https://github.com/github/copilot-cli/issues/2591) ("infinite premium requests consumed per tool invocation," 13 +1) was seen as a title only.
- Finance or budget-owner voices were not found.

## Privacy inside the team: do developers object to teammates, managers or vendors reading their agent sessions, and do leads say they need visibility anyway?

### Takeaway
Both sides exist, voiced by different people.
- Developers object to raw prompts and sessions becoming visible to collaborators or the public by default: Entire #340, "sheepish prompts" on HN, and session URLs auto-added to commits (#66504: 116 +1).
- They object more strongly still to vendors keeping sessions they cannot delete (#13514: 96 +1; Codex #24610: 29 +1).
- Admins and telemetry operators want per-user usage and, in several orgs, prompt and response content through OTel (#88490, #89594), and they say they are blind (#27780).
- The middle ground users propose, unprompted: share summaries or decisions, not raw transcripts, and give transcripts a different access boundary from the code.

### Cited Findings
Developer side:
- tobihagemann, 15 February 2026, Entire #340 (10 +1; open): "Even for private repos, transcripts become visible to every collaborator with read access, and the trust boundary for 'who can see the code' is not the same as 'who should see the raw AI session history.'" Also: "`--skip-push-sessions` exists, but it's not even the default." — [Entire #340](https://github.com/entireio/cli/issues/340)
  - kywch, 17 February 2026: "I don't think I need to see every word I said (may help bringing back the memory, but may not want to share with it), but having some smart summary… would help much. And in that process, it's possible to remove sensitive info too." — [Entire #340](https://github.com/entireio/cli/issues/340)
  - thegreyd, 6 April 2026: "Threat actors can start scanning popular public forks for 'entire/checkpoints/v1' branch and discover publically accessible plaintext transcripts." — [Entire #340](https://github.com/entireio/cli/issues/340)
  - Counterviews. suyashkumar2409: "If someone has read access to a codebase, they already possess all the information needed to understand that project." jwbron: "There's inherent value in providing a ledger of all actions that led to generated code." He pushes checkpoints to a separate, stricter repo. — [Entire #340](https://github.com/entireio/cli/issues/340)
  - Vendor: pjbgf said v0.5.1 added a separate checkpoint remote. — [Entire #340](https://github.com/entireio/cli/issues/340)
- mohsen1, 10 February 2026, HN Entire launch thread: "I am not willing to share my sheepish prompts with my team. Sorry!" — [HN 46966815](https://news.ycombinator.com/item?id=46966815)
- joka-7, 9 June 2026, Claude Code #66504 (116 +1; 18 participants): "Every commit message and PR description created by Claude Code automatically includes a session URL… There is no opt-in prompt, no warning." — [Claude Code #66504](https://github.com/anthropics/claude-code/issues/66504)
  - ambroselittle, 2 July 2026 (34 reactions): "The point is off should be the default." — [Claude Code #66504](https://github.com/anthropics/claude-code/issues/66504)
  - luuvasara, 31 August 2026: "Quite certainly a GDPR violation." — [Claude Code #66504](https://github.com/anthropics/claude-code/issues/66504)
  - Vendor: bcherny said the link is added only in web and Remote Control sessions and can be turned off. — [Claude Code #66504](https://github.com/anthropics/claude-code/issues/66504)
- jameskelley412-art, 2 March 2026, Claude Code #29999 (34 +1): "489 commits were tagged before I noticed. Now I need a full git history rewrite and force push." — [Claude Code #29999](https://github.com/anthropics/claude-code/issues/29999)
- kalam-87, 10 December 2025, Claude Code #13514 (96 +1; 34 participants): web and desktop sessions could only be archived, not deleted. Symbai (16 reactions): "I guess they want to keep the back door open to use the sessions (specifically the repos they pulled) for training purposes." — [Claude Code #13514](https://github.com/anthropics/claude-code/issues/13514)
- Aesthermortis, 26 May 2026, Codex #24610 (29 +1): "Archiving is not deletion… archived sessions may contain sensitive project context, repository names, file paths, logs, diffs, prompts, implementation details, and occasionally accidental secrets." kotoru-maker: "the only 'safe' way to have the cloud-side deleted is to delete the entire account." — [Codex #24610](https://github.com/openai/codex/issues/24610)
- Nuttapong_Yuyang, 25 September 2026, Cursor forum: wants permanent delete, "not only archive." Vendor: Colin said archive-only is "intentional, so history isn't lost by accident." — [Cursor forum 172998](https://forum.cursor.com/t/two-way-voice-chat-permanent-chat-delete-not-only-archive/172998)
- On management metrics:
  - maxverse, 18 February 2026, HN ("Strava for Claude Code"): "AI output in our work should be measured in engineering progress, not in use metrics, right?" — [HN 47066619](https://news.ycombinator.com/item?id=47066619)
  - thom-gtdp, 28 April 2026, HN ("Why Are Companies Tokenmaxxing?"): "Before LLM some companies were measuring developers performance based on the number of commits… Not surprising now companies are measuring performance using token usage." — [HN 47933103](https://news.ycombinator.com/item?id=47933103)

Admin and lead side:
- madkerpe, 21 August 2026, Claude Code #88490 (20 +1; at least five orgs confirmed): cloud Cowork sessions export OTLP "with no identity attributes." It was fixed in v2.1.259. — [Claude Code #88490](https://github.com/anthropics/claude-code/issues/88490)
  - peterzajac-mbi runs a "Self-hosted OTel Collector → ClickHouse, first-party Claude **Team** org, OTLP configured org-wide." — [Claude Code #88490](https://github.com/anthropics/claude-code/issues/88490)
  - superayan, 1 September 2026: "What we lose is content: on affected sessions the user's prompt and the model's response both arrive as the placeholder `<REDACTED>`." — [Claude Code #88490](https://github.com/anthropics/claude-code/issues/88490)
- pedrocr-apheris, 25 August 2026, Claude Code #89594: the Cowork monitoring docs say events are "metadata only" by default, but "first-party orgs receive full prompts, responses and tool arguments." He quotes the support article: "User prompt content is included in events by default." — [Claude Code #89594](https://github.com/anthropics/claude-code/issues/89594)
- pghoya2956, 1 June 2026, Claude Code #64436 (5 other participants): "a productivity/observability dashboard built on Claude Code telemetry shows **no prompts and no API activity** for background-agent sessions." — [Claude Code #64436](https://github.com/anthropics/claude-code/issues/64436)
- vjofusha, 30 March 2026, Codex #16248 (9 +1): "We want to centrally roll out telemetry to an OTLP collector," including `log_user_prompt`, from the admin console. — [Codex #16248](https://github.com/openai/codex/issues/16248)
- uknowhow, 19 October 2026, Cursor forum, on review policy: "Green CI + clean AI review is enough (and someone watched the agent session)." — [Cursor forum 175029](https://forum.cursor.com/t/has-your-team-changed-its-human-code-review-requirements-since-adopting-ai-coding-agents/175029)
- The prior round found the same split on Cursor (Trong Vo wanted employees' prompts; staff refused) and on Copilot (BKSX0 asked whether admins can see prompts). See `User gaps in top tools/inbox_audit_user_gaps.md`. — [Cursor forum 159854 (prior round)](https://forum.cursor.com/t/control-or-monitor-employees-prompt-response-data/159854)

### Inferences
- The people asking for content are org admins and telemetry operators. The people objecting are individual contributors and open-source maintainers. A promise of "complete for your admins" that means raw prompt text readable by teammates will meet the developer objection. Two splits would satisfy both groups: complete records of actions, approvals and artifacts, with tiered content access (summaries by default, raw text on authorized request); or per-run disclosure. This is an inference.
- "The vendor can read it" draws stronger, more-reacted objections (deletion requests, suspicion of training use) than "my team can read it." That supports holding the record under the team's own keys.

### Gaps
- No developer was found saying a manager actually read their Claude Code or Codex sessions. The objections are anticipatory.
- Reddit, a likely venue for such complaints, did not load.

## Secrets and PII in transcripts: complaints and redaction requests

### Takeaway
This recurs across Claude Code, Codex and Copilot CLI (10 threads, 31 participants). Reactions are low, but the incidents are severe:
- Agents read .env and config files and echo secrets into transcripts despite CLAUDE.md or AGENTS.md rules.
- Secrets generated at runtime are persisted unredacted in transcripts.
- Transcripts embed account email and org UUID.
- Prompt history is plaintext and kept forever.
- Cloud archives retain accidental secrets.

Users ask for redaction before persistence and before upload, plus real deletion. Vendor responses are partial. Claude's `/feedback` redacts only known key patterns. Amp ended public threads because sensitive file snippets are too hard to review.

### Cited Findings
- RCushmaniii, 7 April 2026, Claude Code #44868 (an incident report from a "client engagement"): "The model's safety reflex fires on *output it has already produced*, not on commands it is *about to run*, so the violation is detected only **after** the secret has already been written to chat history — at which point rotation is the only remedy." — [Claude Code #44868](https://github.com/anthropics/claude-code/issues/44868)
  - JoergAlthoff, 14 May 2026: "two violations in one session… Claude used the Read tool on .envrc and .env and output both files in full." — [Claude Code #44868](https://github.com/anthropics/claude-code/issues/44868)
- trust11, 26 January 2026, Claude Code #20966: "Users accidentally expose credentials in conversation history - Keys need to be rotated after every accidental exposure." — [Claude Code #20966](https://github.com/anthropics/claude-code/issues/20966)
- natechensan, 27 February 2026, Claude Code #29434: "The context window in Claude Code is **append-only and permanent**. Once sensitive data enters the context… it remains in every subsequent API call for the lifetime of the session." — [Claude Code #29434](https://github.com/anthropics/claude-code/issues/29434)
- jp-cruz, 28 June 2026, Claude Code #72156: `/feedback` data "should be forcibly scrubbed for PII/Secrets and then shown for user review before submission." Vendor: bcherny, 17 August 2026: "`/feedback`… already redacts known API key and token patterns… Source code and conversation content are otherwise uploaded as-is, so there is no broader PII scrub or a pre-upload review of the exact payload yet." — [Claude Code #72156](https://github.com/anthropics/claude-code/issues/72156)
- djokester, 30 July 2026, Codex #36079 (Business plan): "When `functions.exec` generates a sensitive value at runtime and passes it directly to a nested MCP tool, Codex persists the fully resolved MCP arguments in the local session transcript." The value was a temporary PostgreSQL password. Two other commenters hit the same boundary. — [Codex #36079](https://github.com/openai/codex/issues/36079)
- toddnotplaying, 19 July 2026, Codex #34233: "Codex repeatedly disclosed live credentials into stored conversation/tool output… even after the user explicitly required… safe secret handling in `AGENTS.md`." — [Codex #34233](https://github.com/openai/codex/issues/34233)
- junhyeokchoi-enjcons, 24 August 2026, Codex #40378: "Codex deliberately ran commands that retrieved live production secrets from Azure and transmitted their plaintext values into OpenAI-controlled tool and conversation systems… irreversibly replacing credentials, mutating production." — [Codex #40378](https://github.com/openai/codex/issues/40378)
- XoxRumbleLorexoX, 1 June 2026, Codex #25585: asks for a local pre-submit DLP and redaction layer that works "before network transmission." — [Codex #25585](https://github.com/openai/codex/issues/25585)
- NeoAcar, 3 October 2026, Claude Code #31992: "recent Claude Code versions write the signed-in account's **email** and **organization UUID** into the transcript itself." His handoff tool scrubs secrets before git transfer. — [Claude Code #31992](https://github.com/anthropics/claude-code/issues/31992)
- arc-web, 1 October 2026, Claude Code #98575, quoting the docs: transcripts and history are "**not encrypted at rest** — OS file permissions are the only protection." — [Claude Code #98575](https://github.com/anthropics/claude-code/issues/98575)
- rctruta, 4 April 2026, Claude Code #43675: "Complete conversation history in plaintext JSONL." MJMcGuffin: Anthropic should "indicate how to wipe the different kinds of data inside ~/.claude/." — [Claude Code #43675](https://github.com/anthropics/claude-code/issues/43675)
- phrinj, 29 June 2025, Claude Code #2713 (6 +1): `~/.claude.json` held "an unencrypted, detailed log of user interactions," including partial keystrokes and emails. — [Claude Code #2713](https://github.com/anthropics/claude-code/issues/2713)
- [Copilot CLI #1351](https://github.com/github/copilot-cli/issues/1351), rameshreddy-adutla, 7 February 2026 (title only): "Security Risk: Agent requests and logs sensitive credentials (SSH passphrases)."
- Vendor, Amp, 2 June 2026: ended public threads because it is "getting too hard to review a thread to ensure it doesn't contain any snippets of sensitive files." — [ampcode.com](https://ampcode.com/news/end-of-public-threads)

### Inferences
- Users want redaction at ingestion (before persistence, upload or sharing), encryption at rest, and real deletion. A team-keyed record that redacts on write, with raw text available only on authorized request, matches the stated needs. This is an inference.
- Each report is a separate incident with few reactions, but the failure is the same across harnesses: instructions do not stop secrets from entering the record.

### Gaps
- Customer data (as opposed to credentials) leaking into shared sessions was not found as a first-person complaint. The only PHI mention is jp-cruz's hypothetical.
- Entire's gitleaks-based secret scanning appeared only in a search snippet from Entire's dispatch posts and was not opened.

## Workarounds people built (signals of unmet demand)

### Takeaway
Nearly every gap has a homegrown fix, and most fixes cover only one harness. The categories:
- transcript export and rendering;
- backup against deletion;
- sync across machines and surfaces;
- handoff and decision files kept in the repo;
- hook- or proxy-based audit logs, including signed ones;
- cost trackers;
- self-hosted OTel collectors;
- git discipline (commit every turn, use worktrees).

### Cited Findings
- Export and render. Simon Willison's claude-code-transcripts publishes HTML or Gists and links them from commits ([simonwillison.net](https://simonwillison.net/2025/Dec/25/claude-code-transcripts/)). daaain's claude-code-log (`uvx claude-code-log --open-browser`) and SpecStory are offered in [Claude Code #323](https://github.com/anthropics/claude-code/issues/323). revertable's "Codex Session Observatory" exports Markdown worklogs ([Codex #41574](https://github.com/openai/codex/issues/41574)). MeXenon's codex-session-export is in [Codex #13267](https://github.com/openai/codex/issues/13267).
- Backup against deletion. Evidlo uses ccrider: "Session backups live outside of ~.claude so are not deleted and can be resumed" ([HN 48733724](https://news.ycombinator.com/item?id=48733724)). BasedGPT's claude-code-session-recovery and Sigillion ("Disclosure: I make Sigillion… keeps a separate, sealed copy of every Claude Code session on your own disk") are in [Claude Code #82084](https://github.com/anthropics/claude-code/issues/82084). vshulcz's index CLI is in [Claude Code #103323](https://github.com/anthropics/claude-code/issues/103323).
- Sync and handoff:
  - [Claude Code #31992](https://github.com/anthropics/claude-code/issues/31992): NeoAcar's claude-handoff ("Exports the full session (transcript, subagent logs, memory)… scrubs secrets, rewrites absolute paths") and VirelNode's session-roam over Syncthing.
  - [Claude Code #28791](https://github.com/anthropics/claude-code/issues/28791): stevebuckco's shared `CLAUDE_CONFIG_DIR` on OneDrive and harryi3t's script bridging CLI and Desktop.
  - [Codex #14722](https://github.com/openai/codex/issues/14722): Companionh's codex-workspace-sync.
  - [Codex #5609](https://github.com/openai/codex/issues/5609): interconnectedMe's `~/.codex/sessions` to `/worklog` Markdown.
- Decision logs and progress files in the repo:
  - Madhur_Mittal: "have the agent keep a PROGRESS.md… with the goal, what's done, what was tried and failed, decisions made, and the next step." Cursor staff endorsed it. — [Cursor forum 173005](https://forum.cursor.com/t/agent-loses-entire-conversation-when-interrupted-mid-work/173005)
  - pigeonwarz: "a CLAUDE.md vision file and .claude/changelog that documents the changes it makes." — [HN 48733056](https://news.ycombinator.com/item?id=48733056)
  - Grepathy (evansjp, 15 July 2026) distills decisions into `.ai/why/`, which was "97KB and 148 entries" on one branch. evansjp: "the eval showed first pass was only ~65% real decisions." — [HN 48923979](https://news.ycombinator.com/item?id=48923979)
  - yacb2's claude-session-handoff and handoff-md. — [Claude Code #11455](https://github.com/anthropics/claude-code/issues/11455)
- Audit hooks, proxies and signing:
  - yurukusa's PostToolUse logging hooks ([Claude Code #32904](https://github.com/anthropics/claude-code/issues/32904)).
  - Daedalab proxy and Signet, claimed as "Ed25519 signature + hash-ch[ain]" per tool call (same thread; tool-builder claims).
  - ArkNill's interception proxy ([Claude Code #50513](https://github.com/anthropics/claude-code/issues/50513)).
  - hookprobe, which indexes hook events from session JSONL ([Claude Code #49778](https://github.com/anthropics/claude-code/issues/49778)).
  - Vigilo's author, 26 February 2026, on tamper resistance: "The append-and-sign pattern is probably the right starting point before going full Merkle tree… fully self-hosted right now, intentionally" ([HN 47165225](https://news.ycombinator.com/item?id=47165225)).
  - Seen as HN titles only: Gryph ("Audit Trail for AI Coding Agents (Claude Code, Cursor, Gemini)," [HN 46857391](https://news.ycombinator.com/item?id=46857391)), K9 Audit ([HN 47344702](https://news.ycombinator.com/item?id=47344702)), Claudit ("Claude Code Conversations as Git Notes," [HN 46973588](https://news.ycombinator.com/item?id=46973588)), and claude-logkeeper ("Back up Claude Code sessions from Codespaces to a private repo," [HN 48992474](https://news.ycombinator.com/item?id=48992474)).
- Cost trackers:
  - budgetclaw ("kills the session when you hit your cap"), SpendSentry, VOLY and LoopBudget, in [Claude Code #78148](https://github.com/anthropics/claude-code/issues/78148) and [Claude Code #18550](https://github.com/anthropics/claude-code/issues/18550).
  - llmkit-mcp ("scans all your projects across Claude Code, Cline, and Cursor"), in [Claude Code #34803](https://github.com/anthropics/claude-code/issues/34803).
  - ccusage and CodeBurn, from HN.
- Org telemetry. Self-hosted collectors feeding ClickHouse, VictoriaLogs and grafana/otel-lgtm appear in [Claude Code #88490](https://github.com/anthropics/claude-code/issues/88490) and [Claude Code #64436](https://github.com/anthropics/claude-code/issues/64436).
- Policy workarounds:
  - dflor003's enterprise managed-settings instruction to undo the auto-mode Bash steering. — [Claude Code #87971](https://github.com/anthropics/claude-code/issues/87971)
  - TomosuAI: "committing before every agent run, or running the agent on its own branch or worktree. then 'what did it change' is just a git diff." — [Cursor forum 172435](https://forum.cursor.com/t/cursor-ai-is-a-system-that-literally-goes-rogue/172435)
  - jwbron pushes Entire checkpoints to a separate private repo. — [Entire #340](https://github.com/entireio/cli/issues/340)

### Inferences
- The number of workarounds signals demand. Their spread signals that no tool spans harnesses: nearly all parse one harness's JSONL. Several adjacent tools already claim tamper evidence (Signet, Vigilo, K9 Audit, Gryph, Daedalab). Tamper evidence alone is therefore not a differentiator; spanning harnesses, team keys, approval binding and handoff together may be. This is an inference.
- Users' own workarounds converge on two artifacts: a durable raw transcript, kept privately, and a short decisions or progress file, kept with the repo.

### Gaps
- Adoption of these tools (stars, downloads, users) was not checked, apart from HN points.

## Engineering leads and managers: what do they say they need to see about their team's agent use?

### Takeaway
Evidence from leads is thinner than from individual contributors, but it is consistent:
- per-user usage and cost visibility, which Claude subscription plans and Codex telemetry do not provide;
- central telemetry rollout with user identity;
- review policies that depend on whether a human watched the agent session and whether the diff stayed in scope;
- an accountability chain. HN's consensus after the production-database deletion is "your agents are your responsibility," and agents acting under a human's token make the human look like the actor.

Lead-level actions observed include pushing managed-settings workarounds to all engineers and keeping human review mandatory for customer-data systems.

### Cited Findings
- Michal_Cichon, 16 October 2026, Cursor forum: "Do you still require a human to review every PR, or have you introduced rules that allow some changes through with automated checks and AI review?" — [Cursor forum 175029](https://forum.cursor.com/t/has-your-team-changed-its-human-code-review-requirements-since-adopting-ai-coding-agents/175029)
  - troehrkasse: "all code changes must be reviewed by a human developer at the final stage. AI simply isn't perfect yet." — [Cursor forum 175029](https://forum.cursor.com/t/has-your-team-changed-its-human-code-review-requirements-since-adopting-ai-coding-agents/175029)
  - uknowhow: "Always a second human: auth and permissions, migrations / anything that writes data, billing, infra/config, and any diff where the agent touched files outside the orig[inal scope]." — [Cursor forum 175029](https://forum.cursor.com/t/has-your-team-changed-its-human-code-review-requirements-since-adopting-ai-coding-agents/175029)
- HN "Ask HN: How do you review code nowadays?", 13 October 2026 (10 authors):
  - dgunay: "We still do code review but it does bottleneck how much we can ship." — [HN 50081311](https://news.ycombinator.com/item?id=50081311)
  - taurath: "We still do code review in my team, because we build systems that handle customers core business data and infrastructure." — [HN 50077031](https://news.ycombinator.com/item?id=50077031)
- HN "An AI agent deleted our production database," 26 April 2026 (860 points; 1,032 comments; 632 authors):
  - Invictus0: "Ultimately, your agents are your responsibility." — [HN 47911637](https://news.ycombinator.com/item?id=47911637)
  - karmakaze: "These AI's are exposing bad operating procedures." — [HN 47911953](https://news.ycombinator.com/item?id=47911953)
  - vbezhenar: "my manager definitely has a way to obtain prod tokens if he really wanted to. Or if AI agent on his behalf wanted do." — [HN 47913205](https://news.ycombinator.com/item?id=47913205)
- HN "If your agent commits a crime, who is responsible?", 16 August 2026 (104 comments; 62 authors):
  - ventana: "if a person allowed an agent to do things on behalf of themselves or their company… they are responsible for the results." — [HN 49321458](https://news.ycombinator.com/item?id=49321458)
  - corysama: "Somewhere in the chain of responsibility a human will be held accountable." — [HN 49363369](https://news.ycombinator.com/item?id=49363369)
- HN "My coding agent deleted a project without asking. The audit log says I did it," 20 October 2026. The linked blog post was not opened.
  - Jtsummers: "Why would you give agents your own tokens instead of creating a new account that's agent specific… you can still identify what did the work." — [HN 50169882](https://news.ycombinator.com/item?id=50169882)
  - anupampandey16: "Each agent needs an identity and bounded permissions. Otherwise each work is you." — [HN 50223600](https://news.ycombinator.com/item?id=50223600)
- credentum, 22 January 2026, HN: "git blame shows who wrote the code. It doesn't show why an agent approved a $50K purchase order." — [HN 46715084](https://news.ycombinator.com/item?id=46715084)
- evansjp (Grepathy), 15 July 2026, HN: the CTO caught a decision nobody approved during review. "No mention of it in any PR summary - CTO found it in the migration that would mutate the User record to accept `null` email." — [HN 48921012](https://news.ycombinator.com/item?id=48921012)
- sdesol, 9 July 2026, HN: "how do we promote/reward/fire developers in the AI assisted programm[ing]…" — [HN 48846568](https://news.ycombinator.com/item?id=48846568)
- The admin and telemetry asks in the cost and privacy sections also come from lead-level roles: Claude Code #27780 (Team and Enterprise admins), Codex #19897 and #16248, Claude Code #64436 and #88490.
- Media and vendor material, from search snippets only and not opened:
  - LeadDev lists a session "The accountability gap: Engineering governance for autonomous AI" based on its AI Impact Report 2026. — [LeadDev](https://leaddev.com/engineering-manager?query-0-page=3)
  - A Pragmatic Engineer survey (January–February 2026, about 1,000 respondents) reports 46.1% of engineering managers use agents regularly. — [Pragmatic Engineer](https://newsletter.pragmaticengineer.com/p/ai-tooling-2026?open=false)
  - A Notion, Amplify and Vercel survey (n=798) lists "higher review burden 28%." — [Notion survey page](https://www.notion.com/lp/ai-engineering-survey)

### Inferences
- What leads ask for amounts to an accountability chain: which agent ran, under whose identity or token, what it touched, who approved it, who reviewed it, and what it cost. Agents running on a human's token remove this chain ("the audit log says I did it").
- Review policy is shifting toward risk tiers ("someone watched the agent session," "touched files outside scope"). A record that shows scope drift and whether a human watched or approved would serve that policy. This is an inference.

### Gaps
- The full LeadDev reports and the Pragmatic Engineer review-burden article were not accessible or not opened, so no figures from them are used beyond search snippets.
- First-person engineering-manager posts are few. Most lead-level evidence comes from admins in GitHub issues.

## Which pains recur across people and products, and which are one-offs? (counts)

### Takeaway
Ten of eleven themes span at least two products. The exception is silent transcript deletion (T1), which is specific to Claude Code; Codex has the opposite problem of unbounded retention. Overlap between themes is small: 914 distinct participants across the themes, only 18 in two or more themes, and most of those are tool builders promoting fixes. So each theme is carried by a largely different group. The broadest bases by participants and +1s:
- reviewing what the agent changed or ran;
- rewind and undo missing changes;
- handoff across surfaces, machines and teammates;
- sessions lost or hidden;
- transcript retention deletion.

Secrets and OTel completeness recur but with low reactions.

### Cited Findings
Counts from GitHub issues and Cursor topics fetched for this note. Participants are distinct non-staff, non-bot accounts that opened or commented, de-duplicated within each theme. "+1" is the sum of opening-post +1s. HN is listed separately.

| Theme | Threads (products) | Distinct participants | Opener +1 sum | Largest threads | HN corroboration |
|---|---|---|---|---|---|
| T1 Transcripts silently deleted (retention) | 7 (Claude Code only) | 64 | 84 | [#59248](https://github.com/anthropics/claude-code/issues/59248) 41 participants; [#62476](https://github.com/anthropics/claude-code/issues/62476) 25 | [HN 48732846](https://news.ycombinator.com/item?id=48732846): 30 points, 28 authors; simonw in [HN 48921792](https://news.ycombinator.com/item?id=48921792) |
| T2 Sessions hidden or lost by UI or update | 8 (Claude Code 2, Codex 2, Cursor 4) | 137 | 132 | [CC #26452](https://github.com/anthropics/claude-code/issues/26452) 41; [CC #9258](https://github.com/anthropics/claude-code/issues/9258) 35; [Codex #20741](https://github.com/openai/codex/issues/20741) 30 | none |
| T3 Resume and handoff across surfaces, machines, teammates | 14 (Claude Code 6, Codex 6, Copilot CLI 2) | 139 | 544 | [CC #28791](https://github.com/anthropics/claude-code/issues/28791) 36; [CC #11455](https://github.com/anthropics/claude-code/issues/11455) 28; [CC #5768](https://github.com/anthropics/claude-code/issues/5768) 19 | [HN 47075089](https://news.ycombinator.com/item?id=47075089) (cross-harness resume) |
| T4 Reviewing what the agent changed or ran | 8 (Claude Code 5, Codex 1, Cursor 2) | 167 | 708 | [Codex #2998](https://github.com/openai/codex/issues/2998) 53; [CC #21151](https://github.com/anthropics/claude-code/issues/21151) 52; [CC #33932](https://github.com/anthropics/claude-code/issues/33932) 40 | Entire launch thread [HN 46961345](https://news.ycombinator.com/item?id=46961345); review thread [HN 50076575](https://news.ycombinator.com/item?id=50076575) |
| T5 Rewind, undo or checkpoint misses changes | 11 (Claude Code 5, Codex 2, Cursor 4) | 111 | 707 | [Codex #9203](https://github.com/openai/codex/issues/9203) 59; [CC #87971](https://github.com/anthropics/claude-code/issues/87971) 16; [CC #87575](https://github.com/anthropics/claude-code/issues/87575) 15 | none |
| T6 Approvals: record, remote, auto-mode semantics | 9 (Claude Code 5, Codex 2, Cursor 2) | 86 | 255 | [CC #29214](https://github.com/anthropics/claude-code/issues/29214) 30; [Codex #39973](https://github.com/openai/codex/issues/39973) 13; [CC #29438](https://github.com/anthropics/claude-code/issues/29438) 13 | [HN 47911524](https://news.ycombinator.com/item?id=47911524) (production-DB deletion) |
| T7 Attribution in git (trailers, session URLs, AI vs human lines) | 8 (Claude Code 3, git-ai 3, Entire 2) | 48 | 209 | [CC #66504](https://github.com/anthropics/claude-code/issues/66504) 18 | Ghostty disclosure thread [HN 44976568](https://news.ycombinator.com/item?id=44976568): 729 points, 230 authors |
| T8 Privacy of stored sessions (delete, who can read, PII) | 9 (Claude Code 5, Codex 1, Entire 1, Cursor 1, Copilot CLI 1) | 81 | 236 | [CC #13514](https://github.com/anthropics/claude-code/issues/13514) 34; [CC #81138](https://github.com/anthropics/claude-code/issues/81138) 16; [Codex #24610](https://github.com/openai/codex/issues/24610) 11 | [HN 46966815](https://news.ycombinator.com/item?id=46966815) ("sheepish prompts") |
| T9 Secrets and credentials in transcripts and context | 10 (Claude Code 5, Codex 4, Copilot CLI 1) | 31 | 22 | [CC #44868](https://github.com/anthropics/claude-code/issues/44868) 7 | none opened |
| T10 Cost and usage records per session, project, person | 10 (Claude Code 7, Codex 2, Cursor 1) | 47 | 59 | [CC #27780](https://github.com/anthropics/claude-code/issues/27780) 19; [CC #78148](https://github.com/anthropics/claude-code/issues/78148) 10 | ccusage (75 points), CodeBurn (112 points) |
| T11 OTel and telemetry pipelines incomplete | 7 (Claude Code 4, Codex 3) | 27 | 74 | [CC #88490](https://github.com/anthropics/claude-code/issues/88490) 7 | none |

- Overlap: 914 distinct participants across the eleven themes, with 18 appearing in two or more themes. The most frequent is yurukusa, in six themes, posting hook workarounds; BasedGPT and m13v appear in three each. Most cross-theme repeaters are tool builders. — computed from the issues and topics linked in the table.
- Duplicate fragmentation lowers single-thread counts. FTSBrand listed earlier duplicates #46621 and #39667 in [Claude Code #59248](https://github.com/anthropics/claude-code/issues/59248), and ojura said "There's around a dozen issues about this" ([HN 48734907](https://news.ycombinator.com/item?id=48734907)). brilliant-directories-user and c266 complain that duplicates get auto-closed ([Claude Code #31888](https://github.com/anthropics/claude-code/issues/31888)).
- One-offs (single person, few or no reactions):
  - `/shell-history` ([CC #72859](https://github.com/anthropics/claude-code/issues/72859), 3 +1);
  - subagent activity in Desktop "for work where I have to answer for every action" ([CC #88622](https://github.com/anthropics/claude-code/issues/88622), 0);
  - a subagent's `git reset` orphaning commits ([CC #80006](https://github.com/anthropics/claude-code/issues/80006), 0);
  - viewing the active system prompt ([CC #70216](https://github.com/anthropics/claude-code/issues/70216), 0);
  - Cursor revert crossing workspaces, recorded only in composer.log ([Cursor 176032](https://forum.cursor.com/t/cursor-ide-revert-to-message-operation-crosses-workspace-boundaries-and-silently-targets-ignored-files/176032));
  - cost apportionment by client ([CC #55768](https://github.com/anthropics/claude-code/issues/55768), 0);
  - a ledger of session-level grants ([CC #32904](https://github.com/anthropics/claude-code/issues/32904), 3 +1).

  Several of these are the sharpest statements of the record need even though they are one-offs.
- On Cursor, likes are near zero across topics, so Cursor recurrence is measured in topics and participants, not votes. Example: the review-policy thread has 4 likes and 148 views. — [Cursor forum 175029](https://forum.cursor.com/t/has-your-team-changed-its-human-code-review-requirements-since-adopting-ai-coding-agents/175029)

### Inferences
- The best-supported needs for a record product are:
  1. a durable, owner-controlled session history that survives harness retention and UI bugs (T1, T2);
  2. a run-scoped change set that captures every tool path (T4, T5);
  3. portable handoff of sessions across surfaces, machines, harnesses and people (T3);
  4. approvals recorded and bound to what ran (T6, plus the prior round's Cursor thread).
- Privacy (T8) and secrets (T9) shape how the record is shared more than whether it exists. Cost (T10) and telemetry (T11) are what admins ask the record to feed.
- "Users want full transcripts in git" is contested on HN. Skeptics prefer "choices, not the whole session," and supporters prefer "each prompt used to make a given PR." A report writer should not present full-transcript sharing as settled demand.

### Gaps
- Counts cover only the threads fetched for this note. Search was title- and keyword-based, so related threads exist that were not counted, especially duplicates the bots closed.
- Participant counts include tool promoters and cannot separate complainants from helpers without reading every comment.
- Reddit, GitHub Discussions (Copilot), Lobsters and the Anthropic or OpenAI community forums were not successfully searched for this note.
