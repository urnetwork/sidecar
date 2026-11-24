# PiG (Pi-in-Go) agent harness: what it is and how it works, as a candidate to embed in a Go program

Scope and method. I read the PiG repository at `main` commit `40b509fbdf108c21ad95ce0d8e0108586dc8c5ae` (committed 2026-11-18T01:24:27+01:00, "fix(ci): run the full plan again outside a pull request (#544)"), cloned 2026-11-23 with `--depth 50`. I only read files; nothing was built, run, or generated. The GitHub repository page, releases, and issues, plus the upstream Pi pages, were fetched on 2026-11-23. Code links below point at that commit, so line numbers are stable. File, line, and size counts marked "measured" are my own counts on the clone. The import closures come from a static scanner I wrote in the scratchpad (it reads `import` blocks and follows in-module imports). It includes files of every build tag, so it over-approximates.

## What PiG is: purpose, language, size, packages, entry points, and whether there is a clean library API

### Takeaway
PiG is a very large (about 1.04M lines of non-test Go), behavior-exact Go port of the Pi coding agent (Pi 1.5.0). It ships as a CLI/TUI binary (`pig`) with print, JSON, and RPC modes. It also has a documented Go SDK (`coding`) and lower-level, Pi-equivalent `agent` and `ai` packages. Embedding is supported but not clean. The `agent` package is the narrowest usable seam. The `coding` SDK drags in most of the CLI's internals, leaks `internal/` types into its signatures, and is explicitly not API-stable.

### Cited Findings
- PiG describes itself as "Pi, the minimal and extensible coding agent for the terminal, rebuilt in Go as one native binary". It says it "starts quickly, needs no Node.js, and runs Pi's TypeScript extensions unchanged". It also states: "PiG is a pre-stable 0.x release. Core paths are ported and checked against Pi 1.5.0 with paired parity scenarios; edge cases are still hardening." — [README.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
- The GitHub description reads "PiG (Pi in Go) is a faithful Go port of upstream Pi, the TypeScript codebase behind the Pi coding agent." Topics are ai-agent, ai-coding, ai-tools, go, golang, pi. — [GitHub repo page](https://github.com/MichaelKinsy/PiG)
- Language: Go module `github.com/MichaelKinsy/PiG` with `go 1.26.0` and `toolchain go1.27.4`. There is a nested module `extensions/sdk` (go.work also uses `./piglets/porter/extensions/pig-porter`). — [go.mod](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/go.mod), [go.work](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/go.work)
- Size (measured): 13,018 `.go` files, of which 3,990 are non-test (1,044,460 lines) and 9,028 are `_test.go` (1,408,385 lines). The working tree is 432 MB. Non-test lines by top-level directory: `internal` 193,823 (932 files), `coding` 159,642 (649), `durable` 118,133 (379), `ai` 97,670 (275, including the 28,632-line generated `ai/models_generated.go`), `test` 95,307, `chord` 90,216, `tui` 60,878 (194), `extensions` 52,315, `schema` 9,541, `agent` 9,009 (29 files), `env` 8,799, `mcp` 7,135, `codemode` 6,433, `telemetry` 3,048, `cmd` 2,365. The repo also holds about 1,371 `.mjs`, 1,261 `.js`, 721 `.ts`, 382 `.py` and 136 `.rs` files (SDKs, fixtures, Node runtime pack). — [repository tree at 40b509fb](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae)
- The repository map assigns these roles: `agent/` = "Pi-compatible Agent loop, messages, and harness Session state"; `ai/` = providers, model catalog, authentication, streaming types; `coding/` = "Public coding-agent SDK, extension contracts, Package support, and Piglet support"; `tui/` = public terminal components; `cmd/pig/` = the CLI and RPC process; `internal/` = private implementation; `extensions/` = Go/Rust/Python/declaration-only TS extension SDKs; `piglets/` = agent compositions. — [README.md "Repository map"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
- Beyond the four core Pi packages, the repo ports the rest of Pi's monorepo: `chord` (application-composition runtime), `durable` (detached durable Session runtime), `env` (runs a Durable execution environment on another machine over SSH), `codemode` (sandboxed code execution), `mcp` (MCP client library), `schema`, `telemetry`, and `evals`. — [docs/parity/PORT_MAP.md "Package scope"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/parity/PORT_MAP.md)
- Interfaces (all share one agent loop and one session format): interactive `pig`, print `pig -p`, JSON `pig --mode json`, RPC `pig --mode rpc`, and the Go SDK `github.com/MichaelKinsy/PiG/coding`. — [docs/site/docs/how-pig-works.md "Interfaces"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/how-pig-works.md)
- The CLI entry is `cmd/pig/main.go`. It imports `ai/all` and `coding/extension/host/lispcell` and calls `cli.Main(os.Args[1:], nil)`. `coding/cli` is "the pig command line as a library: [Main] runs it for an argument list". — [cmd/pig/main.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/cmd/pig/main.go), [coding/cli/main.go:699](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/cli/main.go#L699)
- The SDK is a three-layer composition. `Services` is the dependency container (auth storage, model registry, settings manager). `Runtime` is the session factory and owns extension execution. `Session` is one live conversation and exposes `Send`, `Events`, `Fork`, `Clone`, `Tree`, `SetName`, and `DispatchSlash`. — [coding/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/doc.go)
- Minimal SDK flow: `coding.CreateAgentSessionServices`, then `coding.NewRuntime`, then `coding.BuildModel("provider/model", svcs)`, then `rt.New(coding.SessionStartOptions{Model, SystemPrompt, ExtraTools})`, then `sess.Send(ctx, prompt)`. "A failed model call is not a Send error (as in Pi): it is recorded on the last assistant message." — [examples/sdk/main.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/examples/sdk/main.go), [docs/site/docs/sdk.md:26-84, 178](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md)
- Stability disclaimer: "PiG is under active development. Pin an exact release or commit when you embed it. Do not assume API stability before the first public release." — [docs/site/docs/sdk.md:13](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L13)
- The lowest-level seam needs no `coding` package. `agent.NewAgent(agent.AgentOptions{...})` needs a `StreamFn` or a host default set with `agent.SetDefaultStreamFn`. Otherwise it fails with `ErrNoDefaultStreamFunction`. — [agent/agent.go:931-998](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L931-L998), [agent/stream_fn.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/stream_fn.go)
- `ai.StreamSimple(ctx, model, transcript, options)` has the same signature as `agent.StreamFn`. `ai.LookupModel(spec)` returns a `*GeneratedModel`, and `(*GeneratedModel).ToModel()` converts it to an `*ai.Model`. — [ai/direct_simple.go:19](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/direct_simple.go#L19), [agent/agent.go:863-865](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L863-L865), [ai/registry.go:97, 206](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/registry.go#L97)
- Leaky public API, example 1: the public `coding.Create{Edit,Find,Grep,Ls,PowerShell,Read,Write}ToolDefinition(cwd, options)` functions take option pointers from `internal/codingagent/tools`, which code outside the module cannot import. — [coding/tool_definitions.go:24-56](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/tool_definitions.go#L24-L56)
- Leaky public API, example 2: `Session.Tree()` returns `*icodingagent.SessionTreeNode`, an internal type. — [coding/session_ops.go:189](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session_ops.go#L189)
- Import closure (measured, static): `agent` reaches 47 in-module packages, 41 of them `internal/...`. `coding` reaches 133 packages, 97 internal, including `tui`, `internal/codingagent`, the subprocess extension host, `chord`, and the root package that embeds the gzipped CHANGELOG. — [coding/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding), [embed.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/embed.go)
- Built with the release flags (`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`), the headless embedding example is 36.7 MB on linux/amd64, against 69.7 MB for `pig`. With all strip tags except `pig_strip_mcp` it is 30.2 MB on linux/amd64, 28.8 MB on darwin/arm64, and 31.5 MB on windows/amd64. — [docs/site/docs/sdk.md:360-384](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L360-L384)

### Inferences
- For sidecar, the realistic reuse surfaces are (a) `agent` + `ai`: the loop, message and event types, and provider streaming, with sidecar-owned tools, persistence, and UI; or (b) the out-of-process RPC protocol for the remote harness. Embedding `coding.Session` brings the CLI's settings, trust, extension host, `~/.pig` directory conventions, and terminal code, which are a poor fit for a phone app or a browser extension.
- Even `agent` is not small. Its closure includes JavaScript-emulation machinery (`internal/jsloop`, `internal/jsstring`, `internal/jsonstringify`, an assembly-based goroutine-ID reader), process-spawn helpers, file locks, OAuth, websockets, and zstd. It is a faithful port, not a minimal library.

### Gaps
- I did not build anything, so I have no binary size for an `agent`+`ai`-only program, and no confirmation that the static closure matches `go list -deps`.
- I did not check pkg.go.dev rendering or API docs for the tagged release.

## What PiG derives from (upstream Pi) and how it compares

### Takeaway
PiG is a Go port of Mario Zechner's "pi" coding agent. That project is formerly `badlogic/pi-mono` and now lives at `earendil-works/pi` after Zechner joined Earendil in April 2026. PiG pins Pi v1.5.0 and mirrors the upstream package boundaries (`agent`, `ai`, `coding-agent`, `tui`, plus newer packages: `chord`, `durable`, `env`, `codemode`, `mcp`). It matches Pi's APIs, events, session format, and RPC protocol, and it records numbered divergences. The biggest architectural difference is that extensions run out-of-process instead of in-process TypeScript.

### Cited Findings
- PiG's NOTICE names its basis: "PiG is a Go implementation designed to provide behavior corresponding to the Pi coding-agent project: https://github.com/earendil-works/pi/". It reproduces Pi's notice "Copyright (c) 2025 Mario Zechner" and says "PiG is not an official release of the upstream Pi project. The upstream maintainers do not endorse PiG." — [NOTICE](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/NOTICE)
- The pin is `ref=v1.5.0`, `commit=f9a26365568127461c47a07a37dcb42c140a3ac5`. The comment calls it "the full commit of a pinned pi-mono commit". `pig --version` prints `<PiG release>+<Pi release>`, for example `0.7.0+1.5.0`. — [.upstream/pin](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/.upstream/pin), [README.md "Project facts"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
- Inconsistency: `docs/project/PROVENANCE.md` still says "Upstream release: `v0.99.1`" (commit `d86654ab…`), while the pin is v1.5.0. — [docs/project/PROVENANCE.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/project/PROVENANCE.md); contradicted by [.upstream/pin](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/.upstream/pin)
- Upstream repository: "AI agent toolkit: unified LLM API, agent loop, TUI, coding agent CLI". It shows 123.4k stars, 15.9k forks, 8,159 commits on `main`, and an MIT license. Packages: `@earendil-works/chord`, `pi-telemetry`, `pi-ai`, `pi-durable`, `pi-agent-core`, `pi-coding-agent`, `pi-tui`. — [earendil-works/pi](https://github.com/earendil-works/pi)
- History: Armin Ronacher's post of April 8, 2026 says Mario Zechner is "joining Earendil" and that "we want Pi to continue to exist as a high-quality, open, extensible piece of software". Zechner posted his own account the same day. — [lucumr.pocoo.org, "Mario and Earendil"](https://lucumr.pocoo.org/2026/4/8/mario-and-earendil/), [mariozechner.at post](https://mariozechner.at/posts/2026-04-08-ive-sold-out)
- Upstream `pi-agent-core` API, as documented, has the same shape as PiG's `agent` package:
  - Agent options: `initialState`, `streamFn`, `convertToLlm`, `transformContext`, `steeringMode`/`followUpMode` (`one-at-a-time` default), `toolExecution` (`parallel` default), and the hooks `beforeToolCall`, `afterToolCall`, `prepareRequest`, `finishTurn`.
  - Methods: `prompt`, `continue`, `steer`, `followUp`, `abort`, `waitForIdle`, `subscribe`, `reset`.
  - Events: `agent_start`/`agent_end`/`turn_*`/`message_*`/`tool_execution_*`.
  - `AgentTool.execute(toolCallId, params, signal, onUpdate)`, low-level `agentLoop` and `agentLoopContinue`, and parameters built with `@earendil-works/pi-schema` builders.
  - [upstream packages/agent/README.md](https://github.com/earendil-works/pi/blob/main/packages/agent/README.md)
- Upstream summary of Pi's interfaces: interactive, print, JSON (events as JSONL), RPC (JSONL commands on stdin, responses and events on stdout), and SDK (the TypeScript SDK controls sessions in process). "Extensions are TypeScript modules loaded into the Pi process." — [docs.pi.dev "How Pi works"](https://docs.pi.dev/latest/how-pi-works)
- The main difference: "Pi loads TypeScript extensions into its own Node.js process. PiG does not embed a JavaScript runtime and does not load Go plugins. PiG instead starts each source extension as a separate process and talks to it over a local socket." — [docs/site/docs/how-pig-works.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/how-pig-works.md)
- Porting philosophy: AGENTS.md tells maintainers (AI agents) to "Treat the port as a compiler from upstream TypeScript behavior to Go behavior". `pig` "must match upstream `pi` observable behavior unless `docs/parity/DIVERGENCES.md` records a numbered, scrutinized exception." — [AGENTS.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/AGENTS.md)
- Parity status: 910 of 929 intended-portable PORT_MAP entries are ported (98.0%), and behavior is verified for 837 of 910 (92.0%). The four core packages are at 521/522 ported. The figures come from 1,032 PORT_MAP entries and 839 parity scenarios. — [test/parity/coverage.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/test/parity/coverage.md)
- Scope statement and a conflict: the README says PiG "does not implement Pi's experimental remote Session packages or its standalone telemetry and evaluation packages". But coverage.md lists `telemetry` (7/7) and `evals` (6/6) as 100% ported, and a `telemetry/` package exists. — [README.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md); contradicted by [test/parity/coverage.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/test/parity/coverage.md)
- About 150 distinct divergence IDs (D-numbers) are referenced in DIVERGENCES.md (measured). Examples: D132 (session dirs created 0700 instead of umask), D19 (choice of TypeScript runtime), D56 (extension liveness check), D70 (new extension processes per session), D82 (snapshots, not live partials, across process boundaries), D174 (GOMAXPROCS policy), D191 (TLS distrust list). — [docs/parity/DIVERGENCES.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/parity/DIVERGENCES.md), [docs/site/docs/sessions.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sessions.md)
- The upstream `packages/agent` has 6 source files (coverage table). PiG's `agent` package has 29 non-test files and 9,009 lines (measured). — [test/parity/coverage.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/test/parity/coverage.md), [agent/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent)

### Inferences
- "Pi" in 2026 is much larger than the 2025 `pi-mono` (ai/agent/coding-agent/tui). Pi 1.x adds Chord, Durable, env, codemode, and MCP packages, structured system messages, and more. PiG tracks all of it, which explains much of its size.
- If the owner's intent is "a Go agent harness modeled on Pi", the upstream `pi-agent-core` API (one small Agent class plus loop functions) is the design to copy. PiG's `agent` package is a faithful Go rendering of that design, with byte-level JS-parity baggage.

### Gaps
- I did not clone or line-count upstream Pi, so I have no direct size comparison of upstream `packages/agent` against PiG's `agent`.
- Reports that some future Pi components might be Fair Source came only from an aggregator summary in search results. I could not verify them and excluded them.

## The agent loop: turns, tool calls, parallel tools, cancellation/steering/follow-up, compaction, retries, max turns, thinking

### Takeaway
The loop matches Pi's. Each turn streams one assistant response, runs its tool calls (parallel by default, sequential if any tool requires it), and then polls the steering queue. When no tool calls remain it polls the follow-up queue, and a `FinishTurn` hook can force or end continuation. Abort cancels a context. Compaction and auto-retry live in the session layer (`coding`), not the core `agent` loop. Max turns defaults to unlimited.

### Cited Findings
- Loop structure: an inner loop runs while there are tool calls or pending (steering) messages. After each turn it re-polls steering. When the agent would stop, it checks follow-ups, then honors an explicit `AgentTurnContinue` decision with one context-only turn. The code comment calls this the mirror of "upstream runLoop: the inner loop processes tool calls and steering messages, the outer loop follow-up messages and FinishTurn continuation requests". — [agent/agent_loop.go:195-275](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent_loop.go#L195-L275)
- One turn (`runTurn`) streams the assistant response. Error and aborted responses are hard exits. If the stop reason is `length`, every tool call is failed rather than executed ("every tool call may carry truncated arguments"). Then `FinishTurn` runs and `TurnEndEvent` is emitted. — [agent/agent_loop.go:288-333](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent_loop.go#L288-L333)
- Turn hooks (all mirror upstream):
  - `FinishTurn(ctx, AgentTurnContext) (*AgentTurnDecision, error)` with actions `continue` or `end`.
  - `PrepareNextTurn` can replace the context, model, or thinking level and append messages.
  - `PrepareRequest` runs before every provider request.
  - [agent/types.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/types.go)
- Message pipeline hooks on `AgentOptions`: `TransformContext(ctx, []AgentMessage)` runs before each request, then `ConvertToLlm([]AgentMessage) ([]ai.Message, error)`, then `TransformLLMMessages`. `OnPayload` and `OnResponse` let callers inspect or replace provider payloads and responses. `GetAPIKey(provider)` resolves credentials per request. — [agent/agent.go:747-862](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L747-L862)
- Parallel tools:
  - Default `ToolExecution` is parallel. "A tool whose ExecutionMode is sequential forces its batch to run sequentially." — [agent/agent.go:810](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L810), [agent/tool_execution.go:56-64](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/tool_execution.go#L56-L64)
  - Calls are prepared in order (`tool_execution_start` is emitted in call order), then run on goroutines. "The calls' tool_execution_end events follow the order their tools settle." A file-mutation queue orders edits and writes. — [agent/tool_execution.go:115-175](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/tool_execution.go#L115-L175)
  - Upstream documents that persisted tool results keep assistant source order. — [upstream agent README](https://github.com/earendil-works/pi/blob/main/packages/agent/README.md)
- Early termination: `AgentToolResult.Terminate` stops the run after the batch only when every finalized result in the batch sets it. — [agent/agent.go:249-299](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L249-L299)
- Steering and follow-up:
  - `Agent.Steer(msg)`, `Agent.FollowUp(msg)`, and `QueueNextTurn` (messages for the next user prompt, Pi's `deliverAs: "nextTurn"`). — [agent/agent.go:1636-1657](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L1636-L1657)
  - Queue modes are `all` and `one-at-a-time` (the default). — [agent/queue.go:8-17](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/queue.go#L8-L17)
  - At the session level, `Session.Steer`/`FollowUp(ctx, text, images, options)` accept images. — [coding/session_prompt.go:53-58](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session_prompt.go#L53-L58)
  - User-facing semantics: a steering message is delivered "After the current turn, before the next model request". A follow-up is delivered "After the agent has no more work, before the run ends". — [docs/site/docs/how-pig-works.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/how-pig-works.md)
- Cancellation:
  - `Agent.Abort()` cancels the active run's context and does nothing when idle. `WaitForIdle()` blocks until the run and its synchronous listeners settle. — [agent/lifecycle.go:145-165](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/lifecycle.go#L145-L165)
  - Tools receive the run's `context.Context` in `Execute`. — [agent/agent.go:361-375](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L361-L375)
  - An aborted response ends with `StopReason` `"aborted"`. — [agent/agent.go:43-84](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L43-L84)
  - `Session.Abort(ctx)` is the session-level form. — [coding/session_run_state.go:168](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session_run_state.go#L168)
- Concurrency rule: a second prompt while running fails with `"Agent is already processing a prompt. Use steer() or followUp() to queue messages, or wait for completion."` — [agent/agent.go:1063](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L1063)
- Max turns: `MaxTurns int // 0 = unlimited, as upstream, which has no turn cap`. The cap is "A pig-only safety cap". Hitting it returns `ErrMaxTurnsReached`, and a run that ends on unanswered tool results returns `ErrToolResultsUnanswered`. — [agent/agent.go:754](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L754), [agent/agent_loop.go:203-212](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent_loop.go#L203-L212), [agent/agent.go:1076-1080](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L1076-L1080)
- Compaction (session layer):
  - Automatic when `contextTokens > contextWindow - reserveTokens`, and also when the provider rejects a request as too large, after which the turn is retried. Defaults: `compaction.enabled=true`, `reserveTokens=16384`, `keepRecentTokens=20000`.
  - Cuts never split a tool call from its result. `/compact` and `Session.Compact(ctx, customInstructions)` trigger it by hand. Events are `compaction_start`/`compaction_end`.
  - [docs/site/docs/compaction.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/compaction.md), [coding/session.go:2790](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session.go#L2790), [agent/agent.go:588-607](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L588-L607)
- Retries come in two layers:
  - Provider-level `StreamOptions.MaxRetries` and `MaxRetryDelayMs`. — [ai/types.go:810+](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L810)
  - Session-level auto-retry with defaults "enabled=true, maxRetries=3, baseDelayMs=2000". — [internal/codingagent/settings.go:181-196](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/settings.go#L181-L196)
  - Auto-retry emits `auto_retry_start`/`auto_retry_end`, and a retried request produces more than one `agent_start`/`agent_end` pair. — [agent/agent.go:625-643](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L625-L643), [docs/site/docs/json.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/json.md)
- Thinking and reasoning:
  - Levels are `off`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`. — [ai/types.go:684-690](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L684-L690)
  - Per-model `ThinkingLevelMap`, `ThinkingBudgets`, and Anthropic `effort` (`low`..`max`) are supported. — [ai/types.go:1124-1156](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L1124-L1156)
  - Thinking streams as `thinking_start/delta/end`. Stored `thinking` blocks carry an opaque `thinkingSignature` and a `redacted` flag. — [docs/site/docs/session-format.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/session-format.md), [ai/events.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/events.go)
- A standalone loop without the `Agent` class exists: `RunAgentLoop` and `RunAgentLoopContinue` take an `AgentEventSink`, and `AgentLoop` and `AgentLoopContinue` return an `AgentEventStream` "buffered without bound until read". — [agent/standalone_loop.go:16-26, 151-226](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/standalone_loop.go#L151-L226)

### Inferences
- A sidecar Harness built on `agent` gets steering, follow-up, abort, parallel tools, hooks, and events for free. It would have to supply compaction, auto-retry, and persistence, because those live in `coding`/`internal/codingagent`, or else adopt `coding.Session`.
- Listeners are awaited synchronously, so a slow UI listener throttles the loop. A mobile UI bridge should buffer.

### Gaps
- I did not trace provider-level retry defaults (`defaultProviderMaxRetryDelayMs`) or the exact retryable-error classification.

## Providers: model APIs, how a provider plugs in, model registry, cost tracking

### Takeaway
`ai` implements ten wire APIs, including OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, Google Generative AI/Vertex, Mistral, Bedrock, Azure, and Codex. It ships a generated catalog of about 1,590 model entries across 40+ provider IDs, with per-token cost data. New providers plug in through a global API registry (`ai.RegisterAPIProvider`), a `models.json` entry for OpenAI-compatible endpoints, or an extension. A caller-owned `*http.Client` can be injected per request.

### Cited Findings
- APIs: `openai-completions`, `mistral-conversations`, `openai-responses`, `azure-openai-responses`, `openai-codex-responses`, `anthropic-messages`, `bedrock-converse-stream`, `google-generative-ai`, `google-vertex`, `pi-messages`. — [ai/types.go:51-62](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L51-L62)
- Registry: `APIProvider{API, Stream, StreamSimple}` is registered with `RegisterAPIProvider(provider, sourceID...)`, which replaces the built-in for that API. The built-ins register lazily in `compat.ts` order. `ai.Stream`/`ai.Complete` route through the registry. — [ai/compat.go:24-67, 120-136, 285-310](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/compat.go#L24-L67)
- The `Provider` interface is `ID()`, `Stream(ctx, TranscriptContext, StreamOptions) (*AssistantMessageEventStream, error)`, and `io.Closer`. — [ai/types.go:927-934](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L927-L934)
- Model catalog: "The model catalogs are generated from the exact published Pi package pinned by extensions/sdk-ts." — [ai/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/doc.go)
  - `ai/models_generated.go` is 28,632 lines. I measured about 1,590 entries, the largest being openrouter 388, vercel-ai-gateway 303, amazon-bedrock 197, opencode 79, huggingface 78, openai 44, mistral 34, github-copilot 27, google 23, anthropic 19. — [ai/models_generated.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/models_generated.go)
  - `LookupModel` resolves `provider/model` or a bare id. — [ai/registry.go:97](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/registry.go#L97)
- Cost tracking:
  - `Usage{Input, Output, CacheRead, CacheWrite, CacheWrite1h, Reasoning, TotalTokens, Cost{Input, Output, CacheRead, CacheWrite, Total, TotalFromProvider}}`. "The component costs are catalog estimates; Total is the best available total." — [ai/types.go:565-588](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L565-L588)
  - The model's `ModelCapabilities` carries USD-per-1M rates (input, output, cache read/write) and cost tiers. — [ai/types.go:938-952](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L938-L952)
  - A `usage` session entry records out-of-band usage, such as cache warming. — [docs/site/docs/session-format.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/session-format.md)
- Custom or local models: an OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, llama.cpp server) is added through `~/.pig/agent/models.json` with `"api": "openai-completions"`. Provider extensions cover custom auth or stream behavior. — [docs/site/docs/custom-provider.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/custom-provider.md)
- Transport injection:
  - `StreamOptions.Fetch *http.Client`: "Fetch replaces HTTP execution with a caller-owned client, preserving its redirect policy and request context". — [ai/types.go:816](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/types.go#L816), [ai/http_transport.go:56-72](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/http_transport.go#L56-L72)
  - `StreamOptions.AnthropicClient` replaces Anthropic client construction. — [docs/site/docs/sdk.md:320-324](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L320-L324)
  - The Agent's per-run `StreamOptions` do not set `Fetch`. — [agent/agent_loop.go:23-38](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent_loop.go#L23-L38)
- Auth: `ai` has OAuth flows for Anthropic, OpenAI ChatGPT/Codex, GitHub Copilot, xAI, Kimi, OpenRouter, Meta, and Radius (`ai/oauth_*.go`). Credentials live in `auth.json`. — [ai/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai), [docs/site/docs/configuration.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/configuration.md)
- Test doubles: `ai.NewFauxProvider` / `RegisterFauxProvider` stream scripted responses through the normal lifecycle. — [ai/faux.go:338](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/faux.go#L338), [docs/site/docs/sdk.md:316](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L316)
- Binary hygiene: Bedrock and the AWS SDK sit in `ai/providers/bedrock`, which "`import ai` does not link". Vertex and Mistral can be dropped with `pig_strip_*` tags. "There is no tag that keeps one provider and removes the others." — [docs/site/docs/sdk.md:368-390](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L368-L390)

### Inferences
- To send provider traffic through sidecar's own network stack (for example a URnetwork-routed `http.Client`), wrap `StreamFn`: set `options.Fetch` and call `ai.StreamSimple`. No fork is needed.
- The registry and API-key state are process-global (package-level maps). That is fine for one Harness per process and awkward for multi-tenant use.

### Gaps
- I did not confirm what the `pi-messages` API is (likely Pi's own hosted service) or which cost fields each provider fills.

## Tools: interface, built-ins, registration, permissions, sandboxing

### Takeaway
A tool is a small Go interface: name, label, JSON schema, `Execute(ctx, id, rawJSON, onUpdate)`, and an execution mode. It can stream complete-so-far partial results and can block, rewrite, or override calls through before/after hooks. Built-ins are `read`, `bash`, `edit`, `write` (default), plus `grep`, `find`, `ls`, and Windows `powershell`. They are local-OS bound (`os/exec` of a shell, `rg`, `fd`) and live in `internal/`. Their pluggable operations (Pi's "for example over SSH") cannot be set from outside the module. There is no sandbox and no permission system beyond hooks, allow/deny lists, and project trust.

### Cited Findings
- The `AgentTool` interface is `Name()`, `Label()`, `Schema() ai.ToolSchema`, `Execute(ctx context.Context, toolCallID string, params json.RawMessage, onUpdate ToolUpdateCallback) (AgentToolResult, error)`, and `ExecutionMode()`. An optional `ArgumentPreparer.PrepareArguments(raw)` normalizes input before schema validation. — [agent/agent.go:361-402](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L361-L402)
- Results:
  - `AgentToolResult{Content []ai.ToolResultMessageContent (ordered text/image), Details any, StructuredContent json.RawMessage, IsError, Thrown, Usage, Terminate, Preview}`. `Preview` is a PiG-only serializable collapsed-view summary for subprocess extensions. — [agent/agent.go:249-299](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L249-L299)
  - Streaming progress: `onUpdate(partial)`, where "every update is a complete-so-far snapshot, not a delta". — [agent/agent.go:548-553](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L548-L553)
- Hooks:
  - `BeforeToolCallHook(ctx, id, name, args) ToolCallHookResult{Block, Reason, Terminate, Args (mutated), Err}`. — [agent/agent.go:688-703](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L688-L703)
  - `AfterToolCallHook(...) AfterToolCallResult{Content, Details, IsError, Usage, Terminate, StructuredContent}`. — [agent/agent.go:705-729](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L705-L729)
- Extension-level tool definition: `ToolDefinition{Name, Label, Description, PromptSnippet, PromptGuidelines, Parameters (JSON Schema), ConstrainedSampling, RenderShell, PrepareArguments, ExecutionMode, Execute, RenderCall, RenderResult, DefaultActive, PrepareLoadout, ...}`. It is registered with `api.RegisterTool`. — [coding/extension/tool.go:166-205](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/tool.go#L166-L205), [coding/extension/api.go:85+](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/api.go#L85)
- Defaults:
  - `defaultToolNames = []string{"read", "bash", "edit", "write"}`. — [internal/codingagent/settings_default_tools.go:10](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/settings_default_tools.go#L10)
  - "`grep`, `find` and `ls` are available but off by default. On Windows, PiG also offers a `powershell` tool." — [docs/site/docs/how-pig-works.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/how-pig-works.md)
  - Conflict: `coding/doc.go` says a fresh Session has "read, write, bash, edit, grep, find, ls". — [coding/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/doc.go)
- Built-ins are OS-bound:
  - `bash` runs `exec.Command(shell.Path, ...)`. — [internal/codingagent/tools/bash_operations.go:127](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/bash_operations.go#L127)
  - `grep` executes `rg` and `find` executes `fd`. — [internal/codingagent/tools/grep.go:129, 257](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/grep.go#L257), [internal/codingagent/tools/find.go:102, 134](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/find.go#L134)
  - A `ToolsManager` "provides the download/install pipeline for fd and rg" from GitHub Releases into `<agent-dir>/bin/`. — [internal/codingagent/tools/tools_manager.go:1-131](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/tools_manager.go), [docs/site/docs/configuration.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/configuration.md)
- Pluggable operations exist internally (Pi's design):
  - "ReadOperations is upstream's ReadOperations: pluggable file reads, for example over SSH." — [internal/codingagent/tools/read.go:35-41](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/read.go#L35-L41)
  - `EditOperations` and `WriteOperations` exist as well. — [internal/codingagent/tools/edit.go:31-51](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/edit.go#L31-L51), [internal/codingagent/tools/write.go:23-41](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/tools/write.go#L23-L41)
  - Only `BashOperations.Exec(ctx, command, cwd, options)` is public. — [coding/extension/bash_operations.go:30-32](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/bash_operations.go#L30-L32)
  - It is used by user bash (`Session.ExecuteBash` with `ExecuteBashOptions.Operations`) and by the `user_bash` extension event result. — [coding/session.go:2064-2120](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session.go#L2064-L2120), [coding/extension/events.go:804-807](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/events.go#L804-L807)
- Selecting tools in the SDK: `SessionStartOptions` has `AllowedTools`, `InitialActiveToolNames`, `ExcludedTools`, `NoTools` (`"all"`/`"builtin"`), `SkipBuiltinTools`, `BeforeToolCall` hooks, `ExtraTools []agent.AgentTool`, and `SkipExtensionTools`. — [coding/runtime.go:59-119](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/runtime.go#L59-L119)
- Security: "PiG runs with the permissions of the user who starts it. PiG does not provide a security sandbox for model output, tools, extensions, skills, hooks, or shell commands." — [README.md "Security boundary"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
  - PiG asks for project trust before loading project settings and resources. "A separate process isolates crashes. It is not a security sandbox." — [docs/site/docs/how-pig-works.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/how-pig-works.md)
  - Upstream likewise has "no built-in permission system" and points to Gondolin, Docker, or OpenShell for containment. — [earendil-works/pi README](https://github.com/earendil-works/pi)
- `codemode` runs model-written JavaScript in QuickJS compiled to WebAssembly and hosted by wazero, reaching the host only through one bridge function. This is an actual sandbox, but only for that tool. — [codemode/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/codemode/doc.go)

### Inferences
- The local sidecar Harness should not use PiG's built-ins. It should implement its own `agent.AgentTool`s (ssh, minimal git, storage) and disable built-ins with `SkipBuiltinTools`/`NoTools`, or simply never add them when using `agent` directly. Reusing PiG's `read`/`edit` logic (edit diffing, truncation) with sidecar storage would require a fork or an upstream change that exports the option types.
- Permissioning for sidecar would be built from `BeforeToolCall` (block with a reason) plus an allow-list. It maps cleanly onto a UI confirmation dialog.

### Gaps
- I did not read the bash tool's output-truncation and timeout code paths in detail, or the edit tool's diff algorithm.

## Events and output: event types, machine-readable streams, TUI rendering, non-terminal subscribers

### Takeaway
Everything is driven by a typed Go event union (`agent.AgentEvent`) carrying nested provider stream events (`ai.AssistantMessageEvent`: text, thinking, and toolcall start/delta/end, done, error). Go callers get it through `Agent.Subscribe`, `AgentOptions.EventCh`/`OnEvent`, or `coding.Session.Subscribe`/`Events()`. The CLI serializes the same events as Pi-identical JSON Lines (`--mode json`, `--mode rpc`), but that encoder is unexported. The terminal renderer is a Go port of pi-tui, not a reusable app SDK. A non-terminal UI can subscribe to the same events.

### Cited Findings
- Agent events and their fields:
  - `AgentStartEvent`; `AgentEndEvent{Messages, WillRetry}`; `AgentSettledEvent{Aborted}`.
  - `QueueUpdateEvent{Steering, FollowUp}`; `SessionInfoChangedEvent{Name}`; `BashExecutionUpdateEvent{ID, Delta}`; `ThinkingLevelChangedEvent{Level}`.
  - `TurnStartEvent{TurnIndex, Timestamp}`; `TurnEndEvent{TurnIndex, Message, ToolResults, MessageEntryID, ToolResultEntryIDs}`.
  - `MessageStartEvent{Message}`; `MessageUpdateEvent{Message, AssistantMessageEvent}`; `MessageEndEvent{Message}`.
  - `ToolExecutionStartEvent{ToolCallID, ToolName, ToolLabel, Args, ParentToolCallID}`; `ToolExecutionUpdateEvent{..., PartialResult, Args}`; `ToolExecutionEndEvent{Result, IsError, DurationMs, ...}`.
  - `CompactionStart/EndEvent`, `AutoRetryStart/EndEvent`, `SummarizationRetry*Event`, `EntryAppendedEvent{Entry}`.
  - [agent/agent.go:404-681](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L404-L681)
- Provider stream events: `StartEvent`, `TextStart/Delta/EndEvent`, `ThinkingStart/Delta/EndEvent`, `ToolCallStart/Delta/EndEvent`, `DoneEvent`, and error, each with `MarshalJSON`. — [ai/events.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/events.go)
- Message types:
  - The `AgentMessage` union has exactly one non-nil field: `System`, `User`, `Assistant`, `ToolResult`, or `Custom map[string]any` (for `bashExecution`, `custom`, `branchSummary`, `compactionSummary`). — [agent/agent.go:19-154](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L19-L154)
  - `AssistantMessage` carries `Content`, `Usage`, `API`, `Provider`, `ModelID`, `StopReason` (stop/toolUse/aborted/error/length), `ErrorMessage`, and `DurationMs`. — [agent/agent.go:43-84](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L43-L84)
- Delivery:
  - `Agent.Subscribe(func(ctx, AgentEvent) error)`: "Listeners run in subscription order with the active run context; the run waits for each callback to return." — [agent/lifecycle.go:25-30](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/lifecycle.go#L25-L30)
  - `message_update` events are skipped entirely when no listener observes them (`SubscribeObservingUpdates`). — [agent/lifecycle.go:40-55](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/lifecycle.go#L40-L55)
  - Options-based delivery: `EventCh` (blocking delivery, with `EventDone` for detach), `OnEvent` (synchronous, may replace a `message_end` message), `AfterEvent`, and `OnMessagePersist` (called once per new message, in production order). — [agent/agent.go:812-847](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/agent.go#L812-L847)
- Session-level delivery:
  - `Session.Subscribe(func(agent.AgentEvent))` is synchronous, so "keep it short". — [coding/session.go:2315-2325](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session.go#L2315-L2325), [docs/site/docs/sdk.md:174](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L174)
  - `Session.Events()` is a buffered channel that must be opened before `Send`. Each event must be passed to `coding.AcknowledgeEvent` so the end-of-turn flush barrier is answered. — [coding/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/doc.go), [coding/session_event_barrier.go:69](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session_event_barrier.go#L69)
  - Observed event order for a simple prompt: AgentStart, TurnStart, Message start/end × 3 (system, user, assistant with updates), TurnEnd, AgentEnd, AgentSettled. — [docs/site/docs/sdk.md:88-174](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L88-L174)
- Partial-message semantics are JS-shaped: "Agent `message_start` and `message_update` messages retain Pi's shallow-copy meaning. Copied top-level fields stay fixed, while referenced nested content can advance"; use `partial.Observe()` or `ai.RefreshEvent` to read current state. — [docs/site/docs/sdk.md:280-290](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L280-L290)
- JSON mode:
  - "JSON mode runs one prompt and writes its Session header and model-loop events as JSON Lines." The first line is `{"type":"session","version":3,...}`.
  - `message_update` carries one `assistantMessageEvent` and no cumulative partial. "The final `message_end` record is authoritative".
  - Tool events carry `toolCallId`, `toolName`, `args`, `partialResult`, `result`, `isError`, and `durationMs`.
  - [docs/site/docs/json.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/json.md)
- RPC mode:
  - `pig --mode rpc` speaks "the RPC protocol of Pi 1.5.0", JSONL on stdin/stdout with `id`-correlated responses. — [docs/site/docs/rpc.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/rpc.md)
  - Commands include `prompt`, `steer`, `follow_up`, `abort`, `get_state`, `set_model`, `set_thinking_level`, `compact`, `set_auto_retry`, `bash`, `get_session_stats`, `switch_session`, `fork`, `clone`, `get_tree`, `get_messages`, `export_html`, and `get_extensions` (PiG-only). — [docs/site/docs/rpc-commands.md:5-42](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/rpc-commands.md)
  - Additional RPC events: `extension_ui_request`, `extension_error`, `error`. — [docs/site/docs/rpc.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/rpc.md)
- The JSON encoder is not public. It lives in `coding/cli/rpc_events.go` ("Ports packages/coding-agent/src/modes/json-event.ts") as unexported functions over `session.Subscribe`. — [coding/cli/rpc_events.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/cli/rpc_events.go)
  - `coding/rpcclient` (a port of Pi's `RpcClient`) starts a local `pig` via `CliPath`, `Cwd`, `Env`, and `Args`. It has no custom-transport option. — [coding/rpcclient/types.go:10-24](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/rpcclient/types.go#L10-L24)
- Extension UI for non-terminal hosts: RPC maps `ctx.ui` calls onto `extension_ui_request` with dialog methods (`select`, `confirm`, `input`, `editor`, answered by `extension_ui_response`) and fire-and-forget methods (`notify`, `setStatus`, `setWidget` with string lines, `setTitle`, `set_editor_text`). Terminal-only calls such as `custom()`, `setFooter`, and themes are no-ops. — [docs/site/docs/rpc-extension-ui.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/rpc-extension-ui.md)
- The TUI:
  - "Package tui provides Pi-compatible terminal rendering, input, components, keybindings, and screen lifecycle management." — [tui/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/tui/doc.go)
  - Markdown comes from a Go port of the `marked` 18.0.11 lexer. — [tui/markdown_marked.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/tui/markdown_marked.go)
  - Highlighting comes from a Go port of highlight.js 10.7.3, and mermaid from a Go port of grok-mermaid. — [NOTICE](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/NOTICE)
  - The tui.md page "does not expose PiG's internal TUI packages as a stable application SDK". — [docs/site/docs/tui.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/tui.md)
  - Extension renderers (`RenderCall`, `RenderResult`, `RegisterMessageRenderer`) return terminal components. — [coding/extension/tool.go:166-205](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/tool.go#L166-L205)

### Inferences
- For sidecar apps that render UI components, the Go event union is a good basis for a UI-neutral event schema. The JSON shapes in json.md/rpc.md (Pi's) are a ready-made wire format, which sidecar would have to re-encode itself. A terminal renderer can be rebuilt over the same events. Borrowing `tui` wholesale brings the whole pi-tui port.
- Using deltas for live display and `message_end` as authoritative avoids PiG's shallow-copy partial semantics.

### Gaps
- I did not map which `tui` components (for example `assistant_message_block.go`, `diff_component.go`) are callable without `internal/codingagent` glue.

## Sessions: storage format, branching, resume, export

### Takeaway
Sessions are Pi-format JSONL (version 3). The first line is a header, and every later line is an entry carrying `id`/`parentId`, so the file stores a tree with an active leaf: branching happens in-file, and fork/clone write new files. Compaction and branch summaries are entries. The default location is `~/.pig/agent/sessions/--<cwd>--/<timestamp>_<uuid>.jsonl`. In-memory managers exist for embedding.

### Cited Findings
- Format: "PiG stores each Session as JSON Lines. Line 1 is a Session header. Each later line is one entry in a tree."
  - The header is `{"type":"session","version":3,"id":...,"timestamp":...,"cwd":...}`, plus `parentSession` after fork or clone.
  - Entry types: `message` (roles `system`, `user`, `assistant`, `toolResult`, `bashExecution`, `custom`, `branchSummary`, `compactionSummary`), `model_change`, `usage`, `thinking_level_change`, `compaction{summary, firstKeptEntryId, tokensBefore, ...}`, `branch_summary`, `custom` (extension state, not in context), and custom messages (in context).
  - "PiG keeps each entry's JSON as it was read, so unknown fields, unknown entry types and the member order survive".
  - [docs/site/docs/session-format.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/session-format.md)
- System messages are versioned in the log: the first stores all prompt `sections` and `toolsAdded`, and later ones patch sections by name and list `toolsAdded`/`toolsRemoved`. — [docs/site/docs/session-format.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/session-format.md)
- Location: `GetDefaultSessionDirPath` returns `filepath.Join(agentDir, "sessions", "--"+encoded(cwd)+"--")`, with directories created 0700 (D132). — [internal/codingagent/session_manager.go:66-109](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/codingagent/session_manager.go#L66-L109)
  - Stale and conflicting: `coding/doc.go:56` and `examples/sdk` claim `<CWD>/.pig/sessions/<id>.jsonl`. — [coding/doc.go:56](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/doc.go#L56)
- Save timing: "PiG saves a new session when the first user message is added". The resume flags are `--continue`/`-c`, `--resume`/`-r`, `--session <id>`, `--session-dir`, and `sessionDir` in settings. — [docs/site/docs/sessions.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sessions.md)
- SDK:
  - `Runtime.New`/`Resume`/`Open`/`Continue`, `Session.Fork(entryID)`, `Session.Clone()`, and `Session.Tree()`. — [coding/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/doc.go), [coding/session_ops.go:25-251](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/session_ops.go#L25-L251)
  - `coding.NewInMemorySessionManager(cwd)`: "`coding.SessionManager` is the actual append-only log". — [docs/site/docs/sdk.md:237-270](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L237-L270)
  - `Runtime.ImportFromJsonl` imports a log. — [docs/site/docs/sdk.md:209](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L209)
- Export: `/export` writes HTML (with embedded Highlight.js and Marked), or JSONL of the current branch when given a `.jsonl` path. RPC has `export_html`. — [docs/site/docs/sessions.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sessions.md), [NOTICE](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/NOTICE), [docs/site/docs/rpc-commands.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/rpc-commands.md)
- Separate durable runtime:
  - `durable` ports Pi Durable ("durable conversation, task, and document runtime") with a `harness` subpackage (scheduler, inbox, submissions, task graph, compaction). — [durable/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/durable/doc.go), [docs/parity/PORT_MAP.md "packages/durable/src/"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/parity/PORT_MAP.md)
  - `durable/core` is a PiG-designed "synchronous Durable core … one deterministic state machine per Session" with no I/O. It builds "natively, as a Go wasip1 reactor and as a TinyGo wasip1 reactor". ADR status: "proposed, 2026-10-06". It is 65,224 lines (measured). — [durable/core/core.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/durable/core/core.go), [durable/core/cmd/corewasm/main.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/durable/core/cmd/corewasm/main.go), [docs/plan/durable-core/ADR-0001-core-architecture.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/plan/durable-core/ADR-0001-core-architecture.md)

### Inferences
- The tree-of-entries JSONL format suits an encrypted, append-only store such as sidecar's (entries are independent lines with stable IDs). Sidecar could adopt Pi's entry schema for interoperability with Pi/PiG tooling even without adopting PiG code.
- `durable/core` (pure, wasm-buildable) is the only part of the repo designed for wasm. It is a storage state machine, not the provider or tool runtime, and its status is "proposed".

### Gaps
- I did not verify how `Runtime.Resume` rebuilds context after compaction (`firstKeptEntryId` semantics) beyond the docs.

## Extensibility: extensions, hooks, skills, prompts, MCP, custom tools, themes

### Takeaway
Pi's extension model is fully present: tools, commands, shortcuts, flags, providers, about 40 lifecycle and event hooks, renderers, and UI. PiG runs extensions as subprocesses (Go, Rust, Python, Node, and Common Lisp), with in-process Go factories for embedders. Skills, prompt templates, themes, packages (npm/git/local), a built-in MCP client extension, and PiG-only "Piglets" (named agent compositions) round it out.

### Cited Findings
- In-process extension type: `type ExtensionFactory func(api API) error`, `InlineExtension`, and `NamedInlineExtension{Name, Factory}`. The headless example passes `mcpext.CreateMcpExtension(...)` this way. — [coding/extension/extension.go:17-26](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/extension.go#L17-L26), [examples/headless/main.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/examples/headless/main.go)
- The `extension.API` surface:
  - Hooks: `OnSessionStart`, `OnSessionBeforeCompact`, `OnContext`, `OnBeforeProviderRequest`, `OnAfterProviderResponse`, `OnBeforeAgentStart`, `OnTurnStart/End`, `OnMessageStart/Update/End`, `OnToolExecution*`, `OnToolCall` (can block), `OnToolResult` (can modify), `OnUserBash`, `OnInput`, `OnModelSelect`, and more.
  - Registration: `RegisterTool`, `RegisterCommand`, `RegisterShortcut`, `RegisterFlag`, `RegisterMessageRenderer`/`EntryRenderer`/`ToolRenderer`, `RegisterMarkdownTransformer`.
  - Actions: `SendMessage`, `SendUserMessage`, `AppendEntry`, `SetSessionName`, `Exec`, `GetActiveTools`, and others.
  - [coding/extension/api.go:85+](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/extension/api.go#L85)
- Process model: "Normal dynamic extensions are subprocesses. Pig does not run extensions in WASM, embedded JavaScript, `plugin.Open`, or dynamic Go plugin runtimes." Compatible same-language extensions can be packed into one process, and Go factories can be "fused" into a Piglet Binary. — [docs/extension-runtime-cells.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/extension-runtime-cells.md)
- TypeScript extensions need an external Node: "By default, Node runs that subprocess: the `node` on your `PATH`, version 22.13 or newer". The "embedded Node runtime" strip tag refers to bundled runtime modules served to that Node, a 5.07 MB saving. — [docs/site/docs/typescript-runtimes.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/typescript-runtimes.md), [docs/site/docs/sdk.md:374-376](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L374-L376)
  - This is in tension with the README's "needs no Node.js, and runs Pi's TypeScript extensions unchanged". — [README.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
- v0.7.0 "Adds Common Lisp extensions and a large part of the extension SDK surface, including Pi's `Type`, `createProvider`, and the extension runner". — [GitHub releases](https://github.com/MichaelKinsy/PiG/releases)
- Skills: "PiG loads the full instructions of a skill only when the model reads them". The system prompt lists each skill's name and description. Context files such as `AGENTS.md` and `SYSTEM.md`/`APPEND_SYSTEM.md` shape the prompt. — [docs/site/docs/how-pig-works.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/how-pig-works.md), [docs/site/docs/skills.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/skills.md)
- MCP: `mcp` is "a small, standalone Model Context Protocol client. It does not depend on an MCP SDK or on other PiG packages", with stdio and Streamable HTTP transports. `mcpext` wraps it as an extension, and `Options.Terminal=nil` keeps terminal code out. — [mcp/doc.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/mcp/doc.go), [docs/site/docs/sdk.md:393-395](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L393-L395)
- Piglets: "A Piglet explicitly selects Resources, tools, discovery, defaults, and environment requirements for one agent." A Piglet Binary is "a direct executable build output for one pinned Piglet composition". — [README.md "Stock PiG and compositions"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md), [docs/site/docs/derivative-harnesses.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/derivative-harnesses.md)

### Inferences
- In-process Go extension factories are usable from an embedder and avoid subprocesses. Sidecar could, for example, express its tools and UI hooks as an `ExtensionFactory` inside `coding`. Everything else in the extension story (subprocess cells, Node, packages, sockets) is unusable on iOS or in a browser.
- The standalone `mcp` client package (no other PiG deps, per its doc) is the most reusable piece for sidecar if MCP is wanted.

### Gaps
- I did not verify the `mcp` package's import closure, and its "no other PiG packages" claim is untested by me.

## Configuration

### Takeaway
Configuration follows Pi's layout with PiG directory names: a root `~/.pig` (`PIG_HOME`/XDG) and an agent directory `~/.pig/agent` (`PIG_CODING_AGENT_DIR`). It holds `settings.json`, `models.json`, `auth.json`, `mcp.json`, `trust.json`, context and system-prompt files, resource directories, and sessions, plus a trust-gated project `.pig/`. The SDK can run with in-memory settings and sessions.

### Cited Findings
- Agent directory files: `settings.json`, `keybindings.json`, `mcp.json`, `models.json`, `auth.json`, `trust.json`, `AGENTS.md`, `SYSTEM.md`, `APPEND_SYSTEM.md`, `extensions/`, `skills/`, `prompts/`, `themes/`, `sessions/`, `bin/` (downloaded `fd`/`rg`), `npm/`, `git/`, `crashes.json`, `exit.log`. — [docs/site/docs/configuration.md:29-62](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/configuration.md)
- Project directory `.pig/` holds `settings.json` (which overrides user settings), `mcp.json`, `SYSTEM.md`, `APPEND_SYSTEM.md`, `extensions/`, `skills/`, `prompts/`, `themes/`, packages, and Piglets. It is gated by project trust. — [docs/site/docs/configuration.md:84-109](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/configuration.md)
- `coding.DefaultAgentDir()` resolves `PIG_CODING_AGENT_DIR`, else `<root>/agent` with root = `$PIG_HOME`, `$XDG_CONFIG_HOME/pig`, or `~/.pig`. `PIG_USE_PI_DIRS=1` uses Pi's `~/.pi/agent` (D2). — [docs/site/docs/sdk.md:179](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L179)
- File-free embedding options:
  - `coding.NewInMemorySettingsManager(initialSettings)`. — [docs/site/docs/sdk.md:195](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L195)
  - `coding.NewInMemorySessionManager(cwd)`. — [docs/site/docs/sdk.md:239-268](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L239-L268)
  - `CreateModelRuntimeOptions` selects `AuthPath`, `ModelsPath` (nil, disabled, or a path), `ModelsStore`, and `AllowModelNetwork`. — [docs/site/docs/sdk.md:304-306](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L304-L306)

### Inferences
- On iOS, Android, and in a browser extension, the `coding` layer's assumption of a real home directory with lock files (`gofrs/flock`, `internal/pilock`) and atomic-rename files would need in-memory substitutes everywhere. Using `agent`+`ai` directly sidesteps most of it, though `ai` still has file-based auth storage code paths.

### Gaps
- I did not enumerate every `settings.json` key.

## Dependencies, cgo, and gomobile / wasm blockers

### Takeaway
There is no cgo, and Android/arm64 is a shipped target, so gomobile Android is plausible. iOS is untested but likely compiles, since iOS satisfies `darwin`/`unix` build tags. Statically, `GOOS=js`/`wasip1` will not compile even the core `agent`→`ai` closure: `ai` defines required functions only for `unix` and `windows`, and `!windows` files use `golang.org/x/sys/unix` and `syscall` process attributes. Binaries are large (about 30-37 MB headless). Importing `agent` mutates `http.DefaultTransport` process-wide. The module download is huge (one release was retracted for exceeding the Go module size limit).

### Cited Findings
- Direct requires: BurntSushi/toml, the `extensions/sdk` module, Microsoft/go-winio, alecthomas/chroma/v2, aws-sdk-go-v2 (+credentials, smithy), clipperhouse/uax29, dlclark/regexp2, evanw/esbuild, fsnotify, gofrs/flock, google/uuid, gorilla/websocket, klauspost/compress, mattn/go-runewidth, rivo/uniseg, tetratelabs/wazero, yuin/goldmark, x/exp, x/net, x/oauth2, x/term, x/text, and modernc.org/sqlite.
  - The same go.mod also pins golangci-lint and about 150 linter modules as indirect or `tool` dependencies.
  - It sets `godebug winsymlink=0` and `retract v0.5.0` ("its module source is larger than the Go module size limit").
  - [go.mod](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/go.mod)
- Where heavy deps are used (measured by grep): `goldmark` and `chroma` only in `automation/portlens`; `modernc.org/sqlite` in `durable/core/sqlhost`, benches, and the parity closure; `esbuild` in `chord/nextnode/plugins`; `wazero` in `codemode`. None of these is in the static closure of `agent` or `coding`. — [automation/portlens](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/automation/portlens), [durable/core/sqlhost](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/durable/core/sqlhost), [codemode/engine_wazero.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/codemode/engine_wazero.go)
- `agent` closure, external modules (measured): `extensions/sdk/json`, `dlclark/regexp2`, `google/uuid`, `gorilla/websocket`, `klauspost/compress/zstd`, `x/net/idna`, `x/oauth2` (+google), `x/sys/unix`, `x/sys/windows`, `x/text`.
  - Std flags: `os/exec` in 8 packages (`internal/configvalue`, `crossspawn`, `linkerexec`, `nodespawn`, `shellconfig`, …), `syscall` in 15, `unsafe` in 10, `net/http` in 4.
  - No `import "C"` anywhere in the `agent` or `coding` closures.
  - [agent/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent), [internal/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal)
- `coding` closure additionally pulls `x/term`, `fsnotify`, `gofrs/flock`, `go-winio`, `charmbracelet/x/ansi`, `x/mod`, `yaml`, `toml`, `os/signal`, `os/user`, and `os/exec` in 25 packages (measured). — [coding/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding)
- `GOOS=js`/`wasip1` blockers:
  - `authFileRevision` is defined only in `ai/auth_revision_unix.go` (`//go:build unix`) and `ai/auth_revision_windows.go`. — [ai/auth_revision_unix.go:17](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/auth_revision_unix.go#L17), [ai/auth_revision_windows.go:36](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/auth_revision_windows.go#L36)
  - `piUserAgentRelease` is likewise only in `ai/user_agent_unix.go` and `ai/user_agent_windows.go`. — [ai/user_agent_unix.go:9](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/ai/user_agent_unix.go#L9)
  - `internal/nodefs/access_other.go` and `exists_other.go` (`//go:build !windows`) import `golang.org/x/sys/unix`. — [internal/nodefs/access_other.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/nodefs/access_other.go)
  - `internal/nodespawn/spawn_other.go` (`!windows`) uses `syscall`. — [internal/nodespawn/spawn_other.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/nodespawn/spawn_other.go)
  - A repository-wide grep finds `js/wasm`/`wasip1`/`GOOS=js` only under `durable/core` and its plans/docs, never for the agent runtime. — [durable/core/cmd/corewasm/main.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/durable/core/cmd/corewasm/main.go)
- Mobile:
  - The release matrix builds `android` plus linux, darwin, and windows, and has no `ios`. — [.github/workflows/release-candidate.yml:37-55](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/.github/workflows/release-candidate.yml#L37-L55)
  - The install docs list "Android with Termux (arm64)" and npm platform packages including Android arm64. — [README.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
  - Release builds use `CGO_ENABLED=0`. — [docs/site/docs/sdk.md:362-366](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L362-L366)
- Runtime hacks that matter on unusual targets:
  - `internal/goroutineid` reads the goroutine ID with assembly under `gc && (linux || darwin) && (amd64 || arm64)` and has a slow fallback elsewhere. — [internal/goroutineid/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/goroutineid)
  - `internal/jsloop` models Pi's JavaScript event loop inside the agent. — [agent/lifecycle.go:118-123](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/agent/lifecycle.go#L118-L123)
- Process-global side effects:
  - `internal/tlsdistrust` (in the `agent` closure via `ai`) has an `init()` that sets or hardens `http.DefaultTransport.TLSClientConfig`: "importing this package hardens [http.DefaultTransport] for every client that leaves its Transport nil" (D191). — [internal/tlsdistrust/tlsdistrust.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/tlsdistrust/tlsdistrust.go)
  - The GOMAXPROCS cap (`procpolicy.Apply`, D174) is applied only by the CLI. — [coding/cli/main.go:701, 900](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/coding/cli/main.go#L701), [internal/procpolicy/procpolicy.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/internal/procpolicy/procpolicy.go)
- Size and toolchain: binary sizes are as above (36.7 MB headless, 69.7 MB `pig`, linux/amd64). The repo working tree is 432 MB (measured; `test/` about 156 MB, `coding/` about 88 MB). Go ≥ 1.26 is required, and releases build with Go 1.27.4. — [docs/site/docs/sdk.md:362-384](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/sdk.md#L362-L384), [README.md "Install with Go"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
- Remote execution pieces use the system `ssh` binary:
  - The `env` package is "the remote execution environment of Pi Durable: an agent's tools run on another machine, usually over SSH". Its `ConnectionOptions.Command` spawns, for example, `ssh -T -- host ~/.pi/mobile/tools/pi-env`. — [env/connection.go](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/env/connection.go)
  - `env/ssh.go` runs `exec.CommandContext(..., sshProgram(target), ...)` and `ssh-keygen`. — [env/ssh.go:273-292, 405](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/env/ssh.go#L273-L292)
  - The remote daemon (`env/cmd/pi-env`) is a Go program speaking Pi's daemon wire protocol (D96), with exec, fs, pty (no cgo), and watch. — [docs/parity/PORT_MAP.md "packages/env/daemon/"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/parity/PORT_MAP.md)

### Inferences
- gomobile (Android): likely compiles. On iOS, everything that spawns processes compiles but cannot run in an app sandbox: the bash tool, `rg`/`fd`, `configvalue` (likely `!command`-style key resolution), extensions, and `env`'s ssh. A sidecar Harness must avoid all of those paths.
- gomobile bind cannot export PiG's types directly (interfaces, generics, `any` maps). Sidecar would expose its own facade in either case.
- Browser wasm: PiG cannot be used as-is. Porting `agent`+`ai` to `GOOS=js` would mean patching at least `ai`'s unix/windows-only files, the `internal/nodefs`/`nodespawn`/`pilock`/`atomicfile` dependencies, and the websocket (Codex) path. The cumulative closure (41 internal packages for `agent` alone) makes that a sizable fork. Reimplementing a small loop over sidecar's own provider client is probably cheaper for the wasm target.
- Go semantics: `godebug` lines in a dependency's go.mod do not apply to the main module, so an embedder would not inherit `winsymlink=0`. That only matters on Windows.

### Gaps
- No compile attempts were made (forbidden by scope), so all `GOOS=js`/`ios`/`android` conclusions are from static reading and need confirming with a sandboxed `GOOS=… go build ./agent ./ai` before any decision.
- I have no binary-size figure for a minimal `agent`+`ai` program.

## License, authorship, activity, releases, tests, issues; maturity and risks (fork vs vendor vs reimplement)

### Takeaway
PiG is MIT-licensed (as is upstream Pi). It is very young (first public release 0.2.0 on 2026-09-25; latest v0.7.0 on 2026-11-05) and very active (4,716 commits). It is dominated by one creator, Michael Kinsy (who started it at HPE), and is maintained under rules written for AI agents. It is heavily tested for parity with Pi, has 893 stars, and is explicitly pre-stable with breaking Go API changes between minor releases. Depending on it directly is high-risk for sidecar's mobile and wasm targets. It is best treated as a reference implementation and as an RPC-compatible remote harness, not as a vendored library.

### Cited Findings
- License: MIT, "Copyright Michael Kinsy". Pi's own MIT notice is retained, and the repository is REUSE/SPDX-annotated. — [LICENSE](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/LICENSE), [NOTICE](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/NOTICE)
  - Third-party embedded assets carry their own licenses: Highlight.js (BSD-3-Clause), Marked (MIT), grok-mermaid (Apache-2.0), and Unicode data (Unicode-3.0). — [NOTICE](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/NOTICE)
- Authorship: "Michael Kinsy created PiG working at Hewlett Packard Enterprise." It is "maintained as an independent open-source project." — [README.md "Origins"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
  - The core committee lists Kinsy as "Creator, maintainer, release authority, and security-response owner" plus five maintainers. — [docs/project/MAINTAINERS.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/project/MAINTAINERS.md)
  - In the last 227 commits of the clone, 210 are by Michael Kinsy (measured).
  - AGENTS.md opens "Operating rules for AI agents maintaining `pig`". — [AGENTS.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/AGENTS.md)
  - "The public repository starts from a reviewed clean source root. Earlier private development history is not part of the public Git history." — [docs/project/PROVENANCE.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/project/PROVENANCE.md)
- GitHub stats (2026-11-23): 893 stars, 82 forks, 6 watchers, 27 open issues, 40 open pull requests, 4,716 commits. — [GitHub repo page](https://github.com/MichaelKinsy/PiG)
- Releases:
  - v0.7.0 "PiG 0.7.0" (05 Nov, Latest), v0.5.3 (23 Oct), v0.5.2 (22 Oct), v0.5.1 (19 Oct), v0.5.0 (19 Oct), v0.4.1 (05 Oct), v0.4.0 (03 Oct), v0.3.1 (01 Oct), v0.3.0, v0.2.0. — [GitHub releases](https://github.com/MichaelKinsy/PiG/releases)
  - The CHANGELOG dates 0.2.0 to 2026-09-25 and 0.5.0 to 2026-10-14, which differs from the release page's 19 Oct. There is no 0.6.x. — [CHANGELOG.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/CHANGELOG.md)
- Breaking changes between minors:
  - v0.5.3: "Breaking Go API changes: `Storage.Commit` takes an adopt callback, watch types move to `chord`, and several `DocumentState` helpers are removed".
  - v0.7.0: "Moves the Bedrock provider to its own Go package, changes the Durable watch API, and bumps stored formats".
  - [GitHub releases](https://github.com/MichaelKinsy/PiG/releases)
- Latest activity on `main`: 40b509fb on 2026-11-18. Earlier the same week there were many merges of audit, CI, and parity fixes, for example #524 (extension socket paths, 2026-11-17) and #488 (auth credential write fix, 2026-11-15). — [commit 40b509fb](https://github.com/MichaelKinsy/PiG/commit/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae)
- Tests: 9,028 `_test.go` files (measured) and 839 parity scenarios. Many tests run Pi itself as an oracle, so local parity work needs Node 24.22.1, npm 12.1.0, Python 3.12, Rust 1.97.1, and tmux. — [test/parity/coverage.md](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/test/parity/coverage.md), [README.md "Build from source"](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/README.md)
  - CI includes CodeQL, OpenSSF Scorecard, REUSE, nightly, and live-provider workflows. — [.github/workflows/](https://github.com/MichaelKinsy/PiG/tree/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/.github/workflows)
- Open issues relevant to embedding:
  - #214 "Separate headless MCP runtime, provider registration, and optional extension assets".
  - #410 "Expose a wazero interpreter mode for embedded Code Mode".
  - #432 "load TypeScript-authored Durable extensions from Go hosts".
  - #451 "expose error-returning selective branch reads for embedded Go consumers".
  - #551 "Go SDK: support reload continuations".
  - Bugs: #427 "an interactive shell run by the bash tool suspends PiG", #516 "a Node extension with a `prepareLoadout` tool hangs PiG", #429 "each subprocess-extension `message_update` handler costs ~0.5 ms CPU per chunk".
  - [GitHub issues](https://github.com/MichaelKinsy/PiG/issues)
- Upstream scale for contrast: earendil-works/pi has 123.4k stars and 8,159 commits. — [earendil-works/pi](https://github.com/earendil-works/pi)

### Inferences
- Maturity: high test investment and very fast iteration, but two months of public history, one dominant (largely AI-agent-driven) author, about 1M lines, and documented Go API breaks per minor. The bus factor and churn risk are high.
- Fork: owning a 1M-line, upstream-tracking codebase whose value lies in byte-parity with a moving TypeScript target is a poor trade for sidecar, which does not need Pi parity, subprocess extensions, or the TUI.
- Vendor (`go get` a pinned tag and use `agent`+`ai`): workable for the CLI/daemon and probably Android. It is blocked for wasm, risky for iOS, and imports process-global side effects, global registries, and a very large module download (v0.5.0 exceeded the module size limit).
- Reimplement modeled on Pi/PiG: copy the `pi-agent-core` design (Agent with prompt/steer/followUp/abort/subscribe; typed events matching Pi's JSON shapes; `AgentTool` with `Execute(ctx, id, args, onUpdate)`; before/after hooks; parallel tool batches with ordered persistence; JSONL entry-tree sessions). Implement only the providers sidecar needs. This keeps wasm and gomobile viable and lets the apps reuse Pi's event and RPC schema.
- Remote harness (Debian VM with full tools): stock `pig --mode rpc` (or upstream Node `pi --mode rpc`) can run in the VM unmodified and be driven over sidecar's SSH channel with the Pi 1.5.0 JSONL RPC protocol. Sidecar would write a small client, because `coding/rpcclient` only spawns a local binary. The same event JSON would then flow to the app renderers for both local and remote harnesses.

### Gaps
- The contributor count and closed-issue count were not shown on the fetched GitHub pages.
- I did not review the security advisories or SECURITY.md process, and did not inspect CI pass rates.
- Whether PiG's maintainers intend a stable Go API (a 1.0 timeline) is not stated in the material I read.
