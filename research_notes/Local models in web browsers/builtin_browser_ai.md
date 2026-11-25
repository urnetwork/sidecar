# Built-in browser AI APIs (browser-provided on-device models for web pages), state as of 2026-11-25

Scope: whether, where and how a web app can use a model that the browser itself supplies (Chrome Prompt API with Gemini Nano, Edge with Phi-4-mini and now Aion Instruct, Firefox, Safari), instead of downloading its own model. Research done 2026-11-25. Every claim carries the date of its source; "undated" marks sources with no date. A caution on dates: developer.chrome.com "Last updated" stamps lag the content. For example, get-started still says "Last updated: May 20, 2025" but describes Chrome 149 language support, so treat those stamps as lower bounds only.

Reference calendar, from [chromiumdash milestone schedule](https://chromiumdash.appspot.com/schedule), fetched 2026-11-25:
- Chrome 148 stable: 2026-05-05.
- Chrome 156: 2026-10-20.
- Chrome 157: 2026-11-03.
- Chrome 158: 2026-11-17.
- Chrome 159: early stable 2026-11-18, stable 2026-12-08.
- Chrome 160: 2027-01-05.
- Chrome 161: 2027-01-19.

Chrome moved to two-week milestones after about M152. On 2026-11-24, the Windows Stable channel was serving 159.0.8154.34 ([chromiumdash releases](https://chromiumdash.appspot.com/releases?platform=Windows)).

## 1. Chrome's Prompt API (`LanguageModel`): status for web pages, OSes, hardware, Gemini Nano versions, download flow, Workers and iframes

### Takeaway
The Prompt API is **shipped on the open web, on by default, in desktop Chrome 148 (stable 2026-05-05)**. It had been in Chrome extensions since Chrome 138. It runs only on Windows 10/11, macOS 13+, Linux and Chromebook Plus. It does not run on Android, iOS, WebView or other ChromeOS devices.

Hardware: more than 4 GB of VRAM, or 16 GB of RAM and 4 cores for CPU mode, plus 22 GB of free disk.

The first `create()` needs user activation, which triggers a roughly 4 GB shared download. The API exists only in Window contexts, so dedicated Workers are out. Same-origin iframes get it by default. A cross-origin iframe, including a same-site one such as sidecar.ur.io inside ur.io, needs `allow="language-model"`.

Chrome picks the Gemini Nano variant per device (for example about 4B or 2B, or a CPU build). It updates the model silently and gives JavaScript no way to read the version.

### Cited Findings
**Ship status (web vs extensions)**
- Chrome's Prompt API doc (last updated 2026-10-21) lists **Web: Chrome 148** and **Extensions: Chrome 138**. A separate row covers the sampling-parameters origin trial. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api)
- Chrome 148 release notes (stable 2026-05-05), Web APIs section: "The Prompt API gives web developers direct access to a browser-provided on-device AI language model. The initial implementation supports text, image, and audio inputs. … response constraints ensure that generated text conforms with predefined regular expression and JSON schema formats." The same release started a new origin trial, "Prompt API sampling parameters". — [Chrome 148 release notes](https://developer.chrome.com/release-notes/148)
- Conflict: those release notes carry a generic note that changes apply to "Android, ChromeOS, Linux, macOS, and Windows" unless noted otherwise. The Intent to Ship and the docs both say the launch is desktop-only (see the platform bullets below). — [Chrome 148 release notes](https://developer.chrome.com/release-notes/148); [blink-dev Intent to Ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/iR6R7-nQeHI)
- blink-dev Intent to Ship, posted 2026-04-01 by Deepti Bogadi:
  - Milestones: DevTrial on desktop in 137, web origin trial in 139–144, extension origin trial ending in 147, shipping on desktop in 148.
  - Rollout: "will ship enabled for all users".
  - Platforms: Windows, Mac, Linux and ChromeOS (Chromebook Plus). Android is being prototyped for later. WebView is "Not Applicable".
  - Scope: tool use is listed only as a possible post-launch additive change.

  — [blink-dev I2S: Prompt API](https://groups.google.com/a/chromium.org/g/blink-dev/c/iR6R7-nQeHI/m/gN4iEGEdAQAJ)
- Approvals: LGTM1 from Mike Taylor (2026-04-03), LGTM2 from Vladimir Levin (2026-04-08) and LGTM3 from Rick Byers (2026-04-08).
  - On 2026-04-30, Alex Russell suggested "finching the Prompt API off for 148 and moving back to OT". He cited unversioned model behavior and interop, and said Microsoft's experiments suggest multimodal interop "is not a given".
  - On 2026-05-01, Rick Byers declined, noting the API was already in early stable.
  - Reilly Grant replied: "The browser picks the model."

  — [blink-dev thread (mail-archive)](https://mail-archive.com/blink-dev@chromium.org/msg16440.html)
- The chromestatus entry (updated 2026-04-22) lists:
  - Desktop 148; origin trial desktop 139 to 144; extension trial through 147.
  - Android, WebView and iOS: null.
  - Safari "Oppose", Firefox "Negative", web developers "Strongly positive".

  Its status-text field still reads "Proposed", and chromestatus status text is stale for several of these APIs. — [chromestatus 5134603979063296 (API JSON)](https://chromestatus.com/api/v0/features/5134603979063296)
- A separate entry, "Prompt API on Android", is "Proposed" with no milestones (last updated 2026-07-30). — [chromestatus 5888755098583040](https://chromestatus.com/feature/5888755098583040)

**OS and hardware requirements (Chrome docs)**
- Operating systems: "Windows 10 or 11; macOS 13+ (Ventura and onwards); Linux; or ChromeOS (from Platform 16389.0.0 and onwards) on Chromebook Plus devices. Chrome for Android, iOS, and ChromeOS on non-Chromebook Plus devices are not yet supported by the APIs which use foundation models." — [Chrome: Get started with built-in AI](https://developer.chrome.com/docs/ai/get-started) (stamp 2025-05-20, content newer; see the caution above); same text in [Prompt API doc](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)
- Storage: "At least 22 GB of free space on the volume that contains your Chrome profile". If free space drops below 10 GB after the download, the model is removed and downloads again later. — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)
- GPU: "Strictly more than 4 GB of VRAM."
- CPU: "16 GB of RAM or more and 4 CPU cores or more."
- "The Prompt API with audio input requires a GPU."
- Network: "Unlimited data or an unmetered connection", needed only for the initial download.

  — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)
- CPU inference for Gemini Nano rolled out in Chrome 140. "Gemini Nano remains consistent across both GPU and CPU inference … the results themselves will remain consistent", though responses are slower. — [Chrome blog: Gemini Nano CPU support](https://developer.chrome.com/blog/gemini-nano-cpu-support) (2025-10-01)
- Internal thresholds observed by one developer (secondary, 2026-05-05):
  - CPU backend needs at least 15000 MiB of RAM, 4 cores and a 64-bit processor.
  - Install needs 20 GiB free plus more than twice the model size in `TMPDIR`.
  - Removal happens after 30 days unused or below 5 GiB free disk. That 5 GiB conflicts with the official 10 GB figure.
  - Performance classes such as `kVeryLow` apply below 3000 MiB of VRAM.
  - Distro-packaged Chromium lacks the proprietary component, so `availability()` returns "downloading" or "unavailable".

  — [adsm.dev: The Prompt API is now on by default in Chrome](https://adsm.dev/posts/prompt-api/)
- Google's user help page: Chrome downloads only on supported hardware, with an unmetered network, "about 20GB of free disk space" and enough device performance. Specific requirements "may change over time." — [Google Chrome Help: Manage on-device generative AI models](https://support.google.com/chrome/answer/16961953) (undated, ©2026)

**Gemini Nano versions and variants**
- Chrome benchmarks the GPU with a representative shader. It then downloads "a larger, more capable Gemini Nano variant (such as 4B parameters)" or "a smaller, more efficient Gemini Nano variant (such as 2B parameters)". Otherwise it falls back to CPU inference, if the static requirements are met. — [Chrome: Understand built-in model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management) (2025-10-21)
- `chrome://on-device-internals` showed model name `v3Nano`, version `2025.06.30.1229`, on a GPU machine with Chrome 148. The GPU build is about 4 GB and the CPU build about 2.7 GB. The model "often claims to be Gemma" when asked, and the API reports no model or version (2026-05-05). — [adsm.dev](https://adsm.dev/posts/prompt-api/)
- One developer saw "Model Name: v3Nano", "Backend Type: GPU (highest quality)" and a folder of about 4,072 MiB, verified on Chrome 149 and 154 (undated repo). — [GitHub Ar9av/gemini-nano-chrome](https://github.com/Ar9av/gemini-nano-chrome)
- Google's Mike Wasserman (2026-04-30): "We've already experimentally deployed various model versions over trial phases of the API… we're exploring support for newer Gemma 4 open models." Downstream Chromium projects are exploring "Microsoft's work to integrate Android MLKit and early prototyping of Apple foundational model integration." — [mozilla/standards-positions #1213](https://github.com/mozilla/standards-positions/issues/1213)
- Chrome docs name only "Gemini Nano" and give no version number. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)

**Download flow and user activation**
- `availability()` returns one of four values:
  - "unavailable"
  - "downloadable" ("User activation may be required to call create()")
  - "downloading"
  - "available"

  If it returns "downloadable" or "downloading", "the user must meaningfully interact with your page" before `create()`; check `navigator.userActivation.isActive`. — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)
- Pass the same options (`expectedInputs` and `expectedOutputs` with types and languages) to `availability()` as to `prompt()`. `create({monitor(m){ m.addEventListener('downloadprogress', …) }})` reports progress. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)
- The spec defines availability as `available`, `downloading`, `downloadable` or `unavailable`. — [Prompt API spec, Draft CG Report 2026-11-09](https://webmachinelearning.github.io/prompt-api/)
- How downloads behave:
  - The first `*.create()` of any Gemini Nano API triggers the download.
  - It resumes after network loss or tab close, and after a browser restart within 30 days.
  - "Sometimes, calling availability() can trigger the model download", on a fresh profile when Gemini Nano scam detection is active.

  — [Chrome: model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management) (2025-10-21)
- How updates behave:
  - Updates are full downloads, "hot swapped" with no downtime. "It's possible for a prompt running at the exact moment of the swap to fail."
  - The model can be purged "at any time, even mid-session".
  - After a purge it is not downloaded again until some site calls `create()`.
  - Purges also happen after 30 days without meeting eligibility (for example, API usage), or when an enterprise policy disables the feature.

  — [Chrome: model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management)
- The spec's privacy section says: "Create an AI model object both requires and consumes user activation". — [Writing Assistance APIs spec §6.1.2](https://webmachinelearning.github.io/writing-assistance-apis/) (Draft CG Report 2026-11-09)
- WebKit's critique (2026-04-30): "User activation is required only for initiating model downloads, not for prompting." — [WebKit/standards-positions #495](https://github.com/WebKit/standards-positions/issues/495)
- User and admin controls:
  - Users: Settings > AI innovations > On-device AI is "the only supported method for managing generative AI models". Turning it off deletes the model and blocks future downloads. — [Google Chrome Help](https://support.google.com/chrome/answer/16961953) (undated)
  - Enterprises: `GenAILocalFoundationalModelSettings` disables model download, and `BuiltInAIAPIsEnabled` blocks the built-in AI APIs while leaving other on-device GenAI features on. — [I2S](https://groups.google.com/a/chromium.org/g/blink-dev/c/iR6R7-nQeHI/m/gN4iEGEdAQAJ) (2026-04-01)

**Workers and iframes**
- Spec IDL: `LanguageModel` is `[Exposed=Window, SecureContext]`. It is "gated behind the policy-controlled feature 'language-model'" with default allowlist `'self'`. — [Prompt API spec](https://webmachinelearning.github.io/prompt-api/) (2026-11-09)
- Chrome: "By default, the Prompt API is only available to top-level windows and to their same-origin iframes. Access to the API can be delegated to cross-origin iframes using the Permission Policy allow="" attribute: `<iframe src="https://cross-origin.example.com/" allow="language-model">`." Also: "The Prompt API isn't available in Web Workers for now, due to the complexity of establishing a responsible document for each worker in order to check the permissions policy status." — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)
- Explainer: "This API is currently not available in workers". Browsers could expose it to extension service workers. — [webmachinelearning/prompt-api explainer](https://github.com/webmachinelearning/prompt-api) (undated, ©2026)

### Inferences
- **For the sidecar layout:** a dedicated Worker cannot call `LanguageModel` in Chrome, because the interface is Window-only. Calls must come from the sidecar iframe's document, on its main thread. Data would move between a Worker and that document by `postMessage`.
- **Same-site does not help with iframes.** Permissions Policy matches on origin, with default allowlist `'self'`. https://sidecar.ur.io inside https://ur.io is cross-origin, so the `<iframe>` in the ur.io page needs `allow="language-model"`. Add `summarizer`, `translator`, `language-detector`, `writer`, `rewriter` or `proofreader` if those APIs are used. If ur.io sends a `Permissions-Policy` header for these features, it must not exclude https://sidecar.ur.io.
- **The first-download gesture probably has to happen inside the iframe.** HTML user activation spreads to ancestor frames, not to cross-origin descendants, so a click in the ur.io top-level page probably won't activate the sidecar frame. This comes from the general HTML activation model; I did not verify it against Chrome's implementation.
- **No stable model identity.** Users of one Chrome version can get different models: about 4B on GPU, about 2B on GPU, or the CPU build. Chrome swaps models without notice. The model can't be named canonically or pinned the way the native apps' SHA-256-checked Gemma 4 file is (see §8).

### Gaps
- I found no official Chrome statement of the exact current Gemini Nano version or its parameter count. The "4B/2B" figures are examples in Chrome's doc, and `v3Nano 2025.06.30.1229` comes from one May 2026 user report.
- I found no Chrome source on whether the Prompt API will ever be exposed in dedicated Workers. The docs say only "for now".
- I did not verify in Chrome how user activation behaves when the gesture occurs in the cross-origin parent rather than in the frame.

## 2. Capabilities and limits: context window and quota, sessions and `clone()`, `responseConstraint`, tool use, multimodal input, languages and sampling, per-origin quotas, speed

### Takeaway
On the web, Chrome 148+ offers:
- Text, image and audio **input** (audio needs a GPU); output is text only.
- System, user and assistant roles, plus assistant prefill.
- JSON Schema or RegExp `responseConstraint`.
- `clone()` and `destroy()`.
- A context window that one developer and one forum reply both measured at **9216 tokens**. Chrome does not document it, and `contextWindow` should be read at runtime.

**Tool use or function calling is not shipped.** The spec marks it experimental, and Chrome has only an Intent to Prototype from 2025.

Sampling on the web is limited to `samplingMode` presets. Those are in an origin trial now, and Chrome plans to ship them in Chrome 160 (2027-01-05). Raw `temperature` and `topK` are extensions-only.

Languages are en, ja and es, with de and fr since Chrome 149. Chrome documents no per-origin quota.

Measured decode speed is about 35–50 tokens/s on a GPU and about 15 tokens/s on a CPU, with first-token latency around 100 ms warm.

### Cited Findings
**Context window and quota**
- `session.contextUsage` and `session.contextWindow` report usage. On overflow, Chrome drops the oldest prompt-response pairs and never the system prompt, then fires `contextoverflow`. If nothing can be dropped, `prompt()` rejects with `QuotaExceededError`, which carries `requested` and `contextWindow`. `measureContextUsage()` estimates the cost of a prompt. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)
- The old `inputUsage`, `inputQuota` and `measureInputUsage()` are "deprecated in extensions and removed on the web". — [Prompt API explainer](https://github.com/webmachinelearning/prompt-api) (undated)
- The TAG called the term "quota" misleading (2025-11-11). — [TAG review #1093](https://github.com/w3ctag/design-reviews/issues/1093)
- A forum reply (2026-01-05; the poster's affiliation isn't stated) showed `inputUsage` 11 and `inputQuota` 9216 after a short `append()`. — [chrome-ai-dev-preview-discuss: How to get context window size](https://groups.google.com/a/chromium.org/g/chrome-ai-dev-preview-discuss/c/wdx5knkJW5M)
- One developer reports "Context window: 9216 tokens", shared between input and output, on Chrome 149 and 154 (undated). — [GitHub Ar9av/gemini-nano-chrome](https://github.com/Ar9av/gemini-nano-chrome)
- Historical figure from Chrome's Thomas Steiner (2024-11-07): "a per prompt limit of 1024 tokens, and the session can retain the last 4096 tokens". This is outdated. — [chrome-ai-dev-preview-discuss: Maximum Token Limits](https://groups.google.com/a/chromium.org/g/chrome-ai-dev-preview-discuss/c/WO2NIK_9Ue4)

**Sessions, prompting and `clone()`**
- `initialPrompts` accepts `system`, `user` and `assistant` roles. `prefix: true` on a trailing assistant message prefills the reply. Session methods:
  - `append()` adds messages without prompting.
  - `prompt()` returns the whole reply; `promptStreaming()` returns a ReadableStream.
  - `clone()` forks the conversation and accepts a `signal`.
  - `destroy()` frees resources and aborts running work.
  - An AbortSignal stops a prompt.

  — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)

**Structured output**
- `responseConstraint` takes a JSON Schema; the explainer also allows a RegExp. The constraint uses context-window space unless `omitResponseConstraintInput` is set, in which case Chrome advises putting format guidance in the prompt. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api); [explainer](https://github.com/webmachinelearning/prompt-api)
- Google's Wasserman (2026-04-30) presented constraint enforcement as the interop mechanism: "we are enforcing objective response conformance with constraints that ensure model output adheres to known JSON schemas or regexes." — [mozilla/standards-positions #1213](https://github.com/mozilla/standards-positions/issues/1213)

**Tool use and function calling: not shipped**
- The spec defines `LanguageModelToolDeclaration` (`name`, `description`, `inputSchema`) and tool-call and tool-response message types, all marked "EXPERIMENTAL: Only available in experimental contexts." — [Prompt API spec](https://webmachinelearning.github.io/prompt-api/) (2026-11-09)
- Explainer: the current mode is open loop, where the app runs the tools. Closed loop "is a planned future extension and is not yet part of the specification or implemented in browsers." — [Prompt API explainer](https://github.com/webmachinelearning/prompt-api)
- chromestatus "Function Calling capability in Prompt API" has an Intent to Prototype only, with no milestones; it was last updated 2025-08-05. — [chromestatus 5085580563841024](https://chromestatus.com/feature/5085580563841024)
- "Chrome 148 does not support the spec's `tools` option". The author's workaround drives a loop through `responseConstraint` JSON (2026-05-05). — [adsm.dev](https://adsm.dev/posts/prompt-api/)
- Chrome's Prompt API page (2026-10-21) never mentions tools; I checked the markdown copy of the page. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api)
- Also in prototype: "Prompt API Thinking Mode" (`thinkingEffort` from "none" to "high", plus `{type:"thought"}` outputs), Proposed and last updated 2026-10-06. — [chromestatus 5098001721851904](https://chromestatus.com/feature/5098001721851904)

**Multimodal input**
- Shipped in Chrome 148: "text, image, and audio inputs". — [Chrome 148 release notes](https://developer.chrome.com/release-notes/148)
- Accepted audio inputs: AudioBuffer, ArrayBufferView, ArrayBuffer and Blob.
- Accepted image inputs: HTMLImageElement, SVGImageElement, HTMLVideoElement, HTMLCanvasElement, ImageBitmap, OffscreenCanvas, VideoFrame, Blob and ImageData.
- Output is text only. Unsupported combinations raise `NotSupportedError`.

  — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21)
- The Summarizer, Writer, Rewriter and Proofreader APIs are text-to-text only. — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)

**Languages**
- The I2S (2026-04-01) gives the history: English only through M139, Spanish and Japanese added in M140. — [I2S](https://groups.google.com/a/chromium.org/g/blink-dev/c/iR6R7-nQeHI/m/gN4iEGEdAQAJ)
- "From Chrome 149, the models support English, Spanish, Japanese, German, and French for input and output text." — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)
- The Prompt API page lists `"en"`, `"ja"`, `"es"`, `"de"` and `"fr"`, with more "in development". — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api)

**Sampling parameters**
- On the web, the `samplingMode` presets are `most-predictable`, `predictable`, `slightly-predictable`, `balanced` (the default), `slightly-creative`, `creative` and `most-creative`. `topK` and `temperature` "are deprecated and available only in extension contexts". — [Prompt API spec](https://webmachinelearning.github.io/prompt-api/) (2026-11-09); [explainer](https://github.com/webmachinelearning/prompt-api)
- Chrome web docs (2026-10-21): `samplingMode` is "Available on the web with the Sampling Parameters Origin Trial enabled". For extensions, `LanguageModel.params()` returns values such as `{defaultTopK: 3, maxTopK: 128, defaultTemperature: 1, maxTemperature: 2}`, and code must set both `topK` and `temperature` or neither. — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api)
- chromestatus "Prompt API Sampling Mode" (updated 2026-11-25) shows an origin trial in desktop 148–153 and a planned ship in desktop **160** (stable 2027-01-05). Firefox and Safari views are "Negative" and "Oppose", inherited from the parent spec. — [chromestatus 6325545693478912](https://chromestatus.com/feature/6325545693478912)
- The design changed along the way. The Chrome 148 release notes described this trial as adding "`temperature` and `topK` parameters"; it was later recast as `samplingMode` presets. — [Chrome 148 release notes](https://developer.chrome.com/release-notes/148)

**Per-origin quotas and resource limits**
- The spec says user agents "should ensure that one web page's use of these APIs does not overly interfere with another web page's use", for example through queuing, rate limiting or abuse detection. They may fail calls with "UnknownError". — [Writing Assistance APIs spec §7.2](https://webmachinelearning.github.io/writing-assistance-apis/) (2026-11-09); the Prompt API spec defers to it
- Observed behavior: "A circuit breaker disables the API with exponential backoff after three crashes". Using a destroyed session throws `InvalidStateError` (2026-05-05). — [adsm.dev](https://adsm.dev/posts/prompt-api/)

**Measured speed**
Developer measurements, not official benchmarks:

1. adsm.dev (2026-05-05). Hardware: i7-12800H with an RTX A2000 8 GB, Arch Linux, Chrome 148.

   | Backend | Prefill | Decode | Time to first token |
   |---|---|---|---|
   | CPU (8 threads) | 183 tok/s | 15.4 tok/s | 498 ms |
   | GPU `HIGHEST_QUALITY` | 1157 tok/s | 34.7 tok/s | 114 ms |
   | GPU `FASTEST_INFERENCE` | 1668 tok/s | 48.0 tok/s | 100 ms |

   For comparison, `gemma3n:e4b` Q4 under Ollama on the same machine ran at about 1000 tok/s prefill and 40 tok/s decode. — [adsm.dev](https://adsm.dev/posts/prompt-api/)

2. Ar9av (undated repo). Hardware: Apple M4 Pro with 24 GB, Chrome 149/154.
   - Decode: about 50 tok/s (47.3–51.5 across runs).
   - Prefill: about 1,000 tok/s.
   - Time to first token: 80–90 ms warm, about 2.9 s for a prompt of about 3,000 tokens.

   — [GitHub Ar9av/gemini-nano-chrome](https://github.com/Ar9av/gemini-nano-chrome)

- The API exposes no timing data, so developers must time `promptStreaming()` themselves (2026-05-05). — [adsm.dev](https://adsm.dev/posts/prompt-api/)

### Inferences
- A context of about 9K tokens, shared by input and output, is small for "summarize my mailbox" work. Long mail threads would need chunking or map-reduce, and `measureContextUsage()` checks.
- Without native tool calling, tool use has to be emulated with JSON-schema-constrained output and an app-side loop. Reliability then rests on a roughly 2–4B model choosing actions under that schema (see §9).
- `samplingMode` will not be generally available on the web before Chrome 160 (2027-01-05). Until then, web pages get the default "balanced" sampling unless they hold an origin-trial token.

### Gaps
- Chrome does not document `contextWindow`. The 9216 figure comes from one forum reply and one developer repo, and it may differ between the GPU and CPU variants.
- I found no published per-origin rate limit or session-concurrency cap for Chrome.
- I found no systematic benchmark of `responseConstraint` reliability, such as rates of schema-valid output that is semantically wrong, for the current Gemini Nano.

## 3. The other built-in APIs and whether each shipped: Summarizer, Writer, Rewriter, Proofreader, Translator, Language Detector

### Takeaway
Shipped in desktop Chrome 138, on the web and in extensions:
- **Translator**
- **Language Detector**
- **Summarizer**

Writer and Rewriter shared an origin trial from Chrome 137 to 148 and are now back to "Developer trial". An undated Chrome demo page calls them "deprecated". Proofreader had an origin trial from Chrome 141 to 145 and is in developer trial. None of the foundation-model APIs runs on mobile. chromestatus plans Language Detector for Android in Chrome 157 and Translator for Android in Chrome 161. All of these APIs are Window-only and gated by Permissions Policy, like the Prompt API.

### Cited Findings
- Chrome's status table:
  - Translator: Chrome 138 on the web and in extensions.
  - Language Detector: Chrome 138 on both.
  - Summarizer: Chrome 138 on both.
  - Writer, Rewriter and Proofreader: "Developer trial" on both.
  - Prompt API: Chrome 148 on the web, Chrome 138 in extensions.

  The page stamp says 2025-09-12, but the table already shows the Chrome 148 Prompt API row. — [Chrome: Built-in AI APIs](https://developer.chrome.com/docs/ai/built-in-apis)
- The Translator and Language Detector use "expert models". All the other APIs use the foundation language model. — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)
- The Translator and Language Detector "work in Chrome on desktop. These APIs do not work on mobile devices." — [Chrome: Get started](https://developer.chrome.com/docs/ai/get-started)
- Writer API: "running in Chrome 137 to 148" as a joint Writer and Rewriter origin trial; the status table now reads "Developer trial". "The Writer API isn't available in Web Workers." Cross-origin frames need `allow="writer"`. — [Chrome: Writer API](https://developer.chrome.com/docs/ai/writer-api) (published 2025-10-22)
- "The Writer and Rewriter APIs are deprecated. Don't build new features on them." The same page says to join the Early Preview Program to enable them. It is undated, and it conflicts with the Writer doc, which carries no deprecation notice. — [Chrome demo: Writer/Rewriter playground](https://chrome.dev/web-ai-demos/writer-rewriter-api-playground/)
- Proofreader: "origin trial, running in Chrome 141 to 145", now "Developer trial". Permission name `proofreader`. "isn't available in Web Workers." It uses LoRA weights on the base model. — [Chrome: Proofreader API](https://developer.chrome.com/docs/ai/proofreader-api) (2025-09-12); [model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management) (2025-10-21)
- The Summarizer has been "available from Chrome 138 stable". It is not in Workers "for now", and cross-origin frames need `allow="summarizer"`. — [Chrome: Summarizer API](https://developer.chrome.com/docs/ai/summarizer-api) (stamp 2025-07-30)
- The Translator "isn't available in Web Workers" and needs `allow="translator"`. It "hides the download status of specific language pairs… all language pairs are reported as downloadable until individual sites create a translator for a given pair." — [Chrome: Translator API](https://developer.chrome.com/docs/ai/translator-api) (stamp 2025-05-20)
- The Language Detector needs `allow="language-detector"` and is not in Web Workers. — [Chrome: Language detection](https://developer.chrome.com/docs/ai/language-detection) (stamp 2025-05-20)
- Spec: Summarizer, Writer and Rewriter are `[Exposed=Window, SecureContext]` with features `summarizer` and `writer` (default allowlist `'self'`). — [Writing Assistance APIs spec](https://webmachinelearning.github.io/writing-assistance-apis/) (Draft CG Report 2026-11-09)
- Android rollout:
  - "Language Detector API on Android": ship milestone Android 157 (updated 2026-10-16). — [chromestatus 5087964794322944](https://chromestatus.com/feature/5087964794322944)
  - "Translator API on Android": ship milestone Android 161, including Custom Tabs (updated 2026-11-25). — [chromestatus 5106126157905920](https://chromestatus.com/feature/5106126157905920)
- New in prototyping:
  - "Decisions API" (`window.DecisionModel`): single-pass scoring of logits against candidate options. It has an Intent to Prototype and lists desktop 157 at the dev-trial stage (updated 2026-10-14). — [chromestatus 5155080092385280](https://chromestatus.com/feature/5155080092385280)
  - WebMCP: Proposed in Chrome (updated 2026-11-25). Mozilla's position is "neutral". — [mozilla/standards-positions #1412](https://github.com/mozilla/standards-positions/issues/1412)

### Inferences
- For summarizing or translating mail inside the sidecar iframe, the APIs that actually ship are Summarizer, Translator and Language Detector (desktop Chrome 138+). Writer, Rewriter and Proofreader can't be relied on in production.
- The chromestatus status-text field is stale. It labels Summarizer and Language Detector as "In developer trial" although they shipped in 138, so shipping state should come from the docs and release notes.

### Gaps
- I found no official Chrome announcement that confirms or explains the Writer and Rewriter "deprecated" banner. Also unclear: whether Language Detector actually reached Chrome 157 Android stable. I didn't check the 157 release notes.

## 4. Microsoft Edge: Prompt API and Writing Assistance APIs, Phi-4-mini, now Aion Instruct

### Takeaway
On 2026-11-19, Edge **replaced Phi-4-mini with "Aion Instruct" (microsoft/Aion-1.0-Instruct-2.3B, MIT license)** as its built-in model.

The Prompt API moved from a Canary/Dev developer preview to an **origin trial** that works on live sites. It is **not on by default** for ordinary pages. The Writing Assistance APIs (Summarizer, Writer, Rewriter) are a flag-gated developer preview from Edge 158.

Requirements:
- Windows 10/11, macOS 13.3+, or x64 Linux with Vulkan (Edge 159+).
- 3 GB of VRAM.
- 20 GB of free disk.

From Edge 158, generated text carries an invisible watermark.

### Cited Findings
- 2025-05-19 launch: the Prompt API and Writing Assistance APIs entered developer preview in Edge Canary and Dev, using a local Phi-4-mini. — [Edge blog 2025-05-19](https://blogs.windows.com/msedgedev/2025/05/19/introducing-the-prompt-and-writing-assistance-apis/)
- Older versions of the Learn page dated the preview from version 138.0.3309.2. An older GitHub copy says "By default, the Prompt API uses the Phi-4-mini model", with Aion-1.0-Instruct as an optional prerelease model behind a flag. Both come from search-result snippets; the live Learn URL now serves the Aion text. — [Edge Learn (web-platform URL)](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/prompt-api); [MicrosoftDocs/edge-developer copy](https://github.com/MicrosoftDocs/edge-developer/blob/main/microsoft-edge/web-platform/prompt-api.md)
- 2026-11-19: "Aion now replaces Phi-4-mini as the browser's built-in small language model."
  - Size: 2.3B parameters.
  - Download: only when a site or feature first needs it, and only "on devices that can run it well".
  - Prompt API: it was previously a developer preview in Edge Canary and Dev only. It is now an origin trial in which "you can call the API from your live site in Microsoft Edge". The post gives no Edge versions or dates for the trial.
  - Decisions API: developer preview in Canary and Dev.
  - "Hybrid intelligence" here means developers falling back to "a configured cloud provider". The post does not say the browser itself sends anything to the cloud.

  — [Edge blog 2026-11-19: Hybrid intelligence on the Web](https://blogs.windows.com/msedgedev/2026/11/19/hybrid-intelligence-on-the-web-introducing-aion-instruct-and-prompt-api-in-microsoft-edge/)
- Edge Prompt API doc (ms.date 2026-11-17, updated 2026-11-23):
  - "available as a developer preview… Locally… [or] On your production website, by registering for an origin trial."
  - Local testing needs Edge 158+ and the `edge://flags` "Prompt API" flag.
  - `edge://on-device-internals` must show "Device performance class" Medium or higher.
  - Documented options: `monitor`, `initialPrompts`, `clone()`, `prompt` and `promptStreaming`, `responseConstraint` (JSON schema or regex), multi-message prompts, AbortController and `destroy()`.

  — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api)
- Edge requirements:
  - OS: "Windows 10 or 11. macOS 13.3 or later. 64-bit (x64) Linux with Vulkan GPU drivers and Microsoft Edge 159 or later."
  - Storage: "At least 20 GB available"; the model is deleted below 5 GB.
  - GPU: "3 GB of VRAM or more."
  - Network: unmetered.
  - No CPU-only mode is documented.

  — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api)
- The model is unavailable in three cases:
  - "On-device AI" is off under Settings > Copilot and AI. It is off by default in Canary, Dev and Beta, and enabling the flag turns it on.
  - The `GenAILocalFoundationalModelSettings` or `ComponentUpdatesEnabled` policies block it.
  - The device doesn't meet the requirements.

  — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api)
- Watermark: "Starting with Microsoft Edge version 158, text generated by the Prompt API includes an invisible watermark… The watermark isn't applied to responses that are generated by using the responseConstraint option." Edge adds that "you are responsible for making sure that your website or extension meets all applicable requirements for marking AI-generated content." — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api)
- Writing Assistance APIs: "available as a developer preview in Microsoft Edge, starting with version 158… locally… on your device only", through the Summarizer, Writer and Rewriter flags. They use the same Aion model and the same requirements and watermark. No origin trial is mentioned. — [Edge: Writing Assistance APIs](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/writing-assistance-apis) (ms.date 2026-11-18)
- Aion model card:
  - MIT license; about 2.29B parameters.
  - Hybrid attention: 21 sliding-window layers (window 2048) and 7 full-attention layers.
  - Context: 32,768 tokens.
  - Languages: EN, DE, ES, PT, IT, FR, ZH and JA.
  - Knowledge cutoff: 2025-12.
  - It supports tool calls (`<|tool_call|>`) at the model level.
  - An optimized version "will become the Windows OS SLM by the end of January 2027".

  — [Hugging Face: microsoft/Aion-1.0-Instruct-2.3B](https://huggingface.co/microsoft/Aion-1.0-Instruct-2.3B) (undated card)
- Edge's own "Prompt API Sampling Parameters" origin trial lists an expiry of 2026-10-06 (search-result snippet; page not opened). — [Edge origin trials: Prompt API Sampling Parameters](https://developer.microsoft.com/en-us/microsoft-edge/origin-trials/trials/32d0cd0f-611d-411e-b48e-cfd8edfdbf73)
- Secondary (2026-05-05): Edge had planned to ship the Prompt API with Phi-4-mini in Edge 148, but "Days before release, an Edge developer announced the API would be disabled behind a flag, citing 'unversioned models and limited developer feedback.'" — [adsm.dev](https://adsm.dev/posts/prompt-api/)
- A microsoft.com account last updated chromestatus "Prompt API on Android" (2026-07-30). Wasserman cites "Microsoft's work to integrate Android MLKit" (2026-04-30). — [chromestatus 5888755098583040](https://chromestatus.com/feature/5888755098583040); [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)

### Inferences
- For a production web app in late November 2026, Edge's Prompt API works only with an Edge origin-trial token, on capable desktops with "On-device AI" enabled. Without a token, `LanguageModel` is absent unless the user has set flags.
- The same JavaScript runs a different model in Edge (Aion, 2.3B, 32K native context) than in Chrome (Gemini Nano). That model difference is the interop problem the vendors argue about in §7.
- The watermark can alter generated text in ways that matter for parsing, diffing or hashing. Constrained (`responseConstraint`) output is exempt.

### Gaps
- Not found:
  - The Edge Prompt API origin-trial ID and its start and end versions.
  - Whether Edge exposes the API in Workers.
  - Edge's `contextWindow` value.
  - Whether Edge accepts image or audio input.
  - Edge's language list for the API.

  The Edge docs cover none of these.

## 5. Firefox: built-in model API for pages or extensions, and Mozilla's position on the Prompt API

### Takeaway
Firefox gives **web pages no built-in model API**. Extensions get an experimental `browser.trial.ml` (Firefox 134+): on by default in Nightly, behind prefs in Beta and Release, and limited to Transformers.js-compatible models from allow-listed hubs. wllama/GGUF has been usable from extensions since Firefox 142.

Mozilla's position on the Prompt API is **negative**: labeled 2025-06-06 and reaffirmed on 2026-04-29 as "We continue to oppose this API". Mozilla is also negative on the Writing Assistance APIs and the Web Translation API.

### Cited Findings
- `browser.trial.ml` (endpoints `createEngine`, `runEngine`, `onProgress`, `deleteCachedModels`):
  - "added in Firefox 134"; "enabled by default in Nightly". Beta and Release need `browser.ml.enable` and `extensions.ml.enabled`.
  - Requires the `"optional_permissions": ["trialML"]` permission.
  - "Any model in Hugging Face that is compatible with Transformers.js should work", but "Firefox will not authorize web extensions to download any model that is not in our model hub" or the allowed HF organizations, Mozilla and Xenova.
  - Models cache in OPFS.
  - The API may change between major versions.

  — [Firefox source docs: WebExtensions AI API](https://firefox-source-docs.mozilla.org/toolkit/components/ml/extensions.html) (undated)
- Bug 1976704 "Enable wllama for extensions": RESOLVED FIXED, target 142 Branch, last changed 2025-07-24. — [Bugzilla 1976704](https://bugzilla.mozilla.org/show_bug.cgi?id=1976704)
- Mozilla blog post on extension inference (undated in my fetch). — [Mozilla blog: Running inference in web extensions](https://blog.mozilla.org/en/firefox/firefox-ai/running-inference-in-web-extensions/)
- Mozilla #1213 (Prompt API): `position: negative`, labeled by bgrins on 2025-06-06; the issue closed 2026-05-05.
  - bgrins (2025-05-20): the API "encourages model-specific behavior that increases interoperability risk" and "needs much more baking in userland before web APIs are shipped".
  - Jake Archibald (2026-04-29): "We continue to oppose this API, and feel it has severe negative consequences to the interoperability, updatability, and neutrality of the web platform". He cites calcification around one model's quirks, sites sniffing the model by prompting it for its ID, and Google's usage-policy terms.

  — [mozilla/standards-positions #1213](https://github.com/mozilla/standards-positions/issues/1213)
- Mozilla's other positions on related APIs:
  - Writing Assistance APIs (#1067): `position: negative`, closed 2025-02-05.
  - Web Translation API (#1015): `position: negative`, closed 2026-01-12.
  - Language Detector API (#1219): open, no position.

  — [mozilla #1067](https://github.com/mozilla/standards-positions/issues/1067); [mozilla #1015](https://github.com/mozilla/standards-positions/issues/1015); [mozilla #1219](https://github.com/mozilla/standards-positions/issues/1219)
- bgrins (2025-05-29) on Writing Assistance: "shipping this in Chrome bakes Gemini into the platform. The built-in model has a structural advantage and multi-gigabyte head start". — [mozilla #1067](https://github.com/mozilla/standards-positions/issues/1067)
- Archibald on the Translator (2026-01-27/28) showed Chrome's Translator turning `<scripte>…</scripte>` into a valid `<script>` tag, and `〈 脚本>` into `<script>` from zh. His conclusion: "any handling of HTML in the current API is coincidental and not safe". — [mozilla #1015](https://github.com/mozilla/standards-positions/issues/1015)
- Mozilla's alternative (2025-05-22): experiment through web extensions, using the trial API and a WebML CG proposal for a Prompt-like extension API with developer-specified models. — [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)
- A third party (kenzic) proposed a "Web Models API" in which "developers should be able to choose the right model for the job" (2026-11-02). — [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)

### Inferences
- On Firefox the web app has to bring its own model, through WebGPU, WASM or WebNN. A `LanguageModel` feature check fails there.

### Gaps
- I found no Mozilla plan to expose any built-in model to web pages. I didn't establish whether `trial.ml` has reached Release without prefs as of 2026-11.

## 6. Safari/WebKit: standards position, and whether Apple Intelligence or Foundation Models reach web content

### Takeaway
WebKit's position on the Prompt API is **oppose**, set 2026-05-27 with the concerns interoperability, portability and privacy. It has no position yet on the Writing Assistance APIs or the Web Translation API.

**Safari gives web content no Apple Intelligence or Foundation Models API.** Apple says Foundation Models "doesn't provide any JavaScript interface". The only route is a native app bridging into a WKWebView through `WKUserContentController`. Third-party extensions and local servers fill the gap unofficially.

### Cited Findings
- WebKit #495 "ML Prompt API": `position: oppose`, applied by marcoscaceres on 2026-05-27, with concerns interoperability, portability and privacy. hober posted the reasoning on 2026-04-30:
  - "The API has no user consent mechanism for running inference"; sites get free compute while users pay in battery and responsiveness.
  - "Developers will tune their prompts and application logic to whichever model is most widely available".
  - "On platforms where the system manages AI models, the browser is a client of the system model, not a host".
  - "User activation is required only for initiating model downloads, not for prompting".
  - "model availability remains a fingerprinting vector".
  - On-device inference isn't inherently more private, because the site still controls prompts and receives outputs.

  — [WebKit/standards-positions #495](https://github.com/WebKit/standards-positions/issues/495)
- Google's michaelwasserman (2026-05-06) replied that UAs can gate `create()` behind consent, and that "the Translator API's download-masking approach could apply here". — [WebKit #495](https://github.com/WebKit/standards-positions/issues/495)
- Other WebKit issues:
  - Writing Assistance APIs (#393): open, no position label.
  - Web Translation API (#339): open, no position label.
  - #308, "New attribute to control UA-provided writing assistance" (the `writingsuggestions` attribute): `position: support`. It lets pages turn UA writing help off; it does not let them call it.

  All fetched from GitHub on 2026-11-25. — [WebKit #393](https://github.com/WebKit/standards-positions/issues/393); [WebKit #339](https://github.com/WebKit/standards-positions/issues/339); [WebKit #308](https://github.com/WebKit/standards-positions/issues/308)
- Apple DTS engineer Ziqiao Chen (Jun 2026, accepted answer): "The Foundation Models framework doesn't provide any JavaScript interface… WebKit provides a mechanism (WKUserContentController) for a web app to run your app's native code." — [Apple Developer Forums thread 833716](https://developer.apple.com/forums/thread/833716)
- Third-party bridges exist, for example a Safari/Chrome extension that exposes Apple's on-device model to pages and needs macOS 15+ with Apple Intelligence (README, undated). — [GitHub zats/local-llm](https://github.com/zats/local-llm)
- Chromium (not WebKit) has "early prototyping of Apple foundational model integration" in downstream projects (2026-04-30). — [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)

### Inferences
- On Safari, a web app cannot use a browser- or OS-provided model. It must ship its own model or use a native wrapper. On iOS, Chrome's docs list iOS as unsupported anyway, and iOS browsers outside the EU's alternative-engine allowance use WebKit. Sidecar's native apps, with pinned Gemma 4, already cover that case.

### Gaps
- I didn't check the Safari 26.x release notes for any AI-related web API. None turned up in searches.

## 7. Standards: Prompt API and Writing Assistance APIs in the W3C WebML CG/WG, the TAG review, and other vendors' interop concerns

### Takeaway
The Prompt API and the Writing Assistance APIs are still **Community Group incubations**: Draft CG Reports dated 2026-11-09, explicitly not on the W3C standards track. The WebML Working Group's deliverables remain WebNN.

The TAG review of the Prompt API ended on 2025-11-11 with "Resolution: lack of consensus", after an earlier "validated" label. Positions stand at Mozilla negative, WebKit oppose and Edge a collaborator, though Edge has not shipped the API by default.

The central interop worry is that prompts tuned to one browser's model calcify the web around that model. Chrome's answer is model-agnostic API surface plus response constraints. Its own explainer disclaims cross-browser quality guarantees.

### Cited Findings
- The Prompt API spec is a "Draft Community Group Report, 9 November 2026" from the Web Machine Learning Community Group, "not a W3C Standard". The Writing Assistance APIs spec is a Draft CG Report of the same date and "not… on the W3C Standards Track". — [Prompt API spec](https://webmachinelearning.github.io/prompt-api/); [Writing Assistance APIs spec](https://webmachinelearning.github.io/writing-assistance-apis/)
- The CG charter lists the Writing Assistance APIs, the Translator and Language Detector APIs, the Prompt API, the Proofreader API and WebMCP.
  - The WebML WG's deliverables are WebNN and an Ethical Principles document (WG meeting, 2025-11-09).
  - The CG reported first versions of the Prompt, Writing Assistance and Translator/Language Detector specs delivered (CG meeting, 2025-11-11).

  — [WebML CG charter](https://webmachinelearning.github.io/charter/); [WebML WG minutes 2025-11-09](https://www.w3.org/2025/11/09-webmachinelearning-minutes.html); [WebML CG minutes 2025-11-11](https://www.w3.org/2025/11/11-webmachinelearning-minutes.html)
- Edge docs point design discussion to the "W3C Web Machine Learning Working Group repository", but the repository is the CG's prompt-api repo (2026-11-17). — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api)
- TAG review #1093, opened 2025-05-14 by Domenic Denicola:
  - 2025-08-26: labeled "Resolution: validated", with "significant concerns about the current level of specification detail". The TAG recommended a "minimal, testable capability baseline".
  - 2025-11-11: relabeled "Resolution: lack of consensus" and closed. The TAG was "skeptical of the potential goal to reveal 'some identifier for the language model in use'", flagged a "fingerprinting vector based on what capabilities are available to a model", and said "We also don't think permissions policy is enough".
  - A participant shown in the thread as "Reilly Eon" (2025-10-30), answering Christian Liebel: a conforming implementation could run on-device or in the cloud.
  - chromestatus lists the TAG status as "Issues addressed".

  — [w3ctag/design-reviews #1093](https://github.com/w3ctag/design-reviews/issues/1093); [chromestatus](https://chromestatus.com/feature/5134603979063296)
- The explainer: "We do not intend to provide guarantees of language model quality, stability, or interoperability between browsers." A stated potential goal is to let developers "know some identifier for the language model in use". — [Prompt API explainer](https://github.com/webmachinelearning/prompt-api)
- I2S interop text (2026-04-01): "Variance in behaviors and responses is a well understood expectation amongst developers employing this technology". Microsoft Edge is "a strong collaborator" shipping "a different underlying model". — [I2S](https://groups.google.com/a/chromium.org/g/blink-dev/c/iR6R7-nQeHI/m/gN4iEGEdAQAJ)
- Rick Byers, Blink API owner (2026-04-30): "I admit that I share the concerns here in Mozilla's standards position". He proposed tracking webcompat bugs that look like "preserve some weird quirk", and said he would "advocate for breaking those quirks in Chrome" if other browsers had to copy them. — [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)
- Mozilla and WebKit positions: see §5 and §6.

### Inferences
- Standardization is stalled at the CG stage, with two of three engine vendors opposed. Prompt API behavior should therefore be treated as Chromium-specific for the foreseeable future, Edge needing an origin-trial token. It is not a portable web-platform capability.

### Gaps
- I found no WebML WG recharter in 2026 adopting the task APIs, and no TAG review outcomes for the Writing Assistance or Translator APIs. I didn't search for those.

## 8. Privacy and terms: does input leave the device, telemetry, required terms, cross-site fingerprinting, and learning or pinning the model version

### Takeaway
On inputs, Chrome says: "No data is sent to Google or any third party when using the model." Edge says input "never leaves the device, and isn't collected to train AI models." The spec, however, **allows user-agent-provided cloud backends**, and pages cannot require or verify on-device execution.

On terms, Chrome's docs told developers to "acknowledge Google's Generative AI Prohibited Uses Policy" in an April 2026 snapshot. That sentence was gone by the 2026-08-01 snapshot and is absent from the 2026-10-21 page.

On fingerprinting, the model is one shared, per-browser download. Its availability state is a known fingerprinting vector. The spec recommends per-site masking, and Chrome documents masking only for the Translator's language pairs.

On versioning, **JavaScript cannot read or pin the model version**. Chrome hot-swaps models and picks a variant per device. The exact model is visible only on `chrome://on-device-internals` or `edge://on-device-internals`.

### Cited Findings
**Does input leave the device?**
- Chrome: "The network requirement is only for the initial download of the model. Subsequent use of the model does not require a network connection. No data is sent to Google or any third party when using the model." — [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api) (2026-10-21); [Get started](https://developer.chrome.com/docs/ai/get-started)
- Edge: "The data input to the model never leaves the device, and isn't collected to train AI models." — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api) (2026-11-17)
- Spec §6.5: implementations may delegate to "user-agent-provided cloud-based services". This is "not, in itself, a significant privacy risk", but developers with third-party data restrictions "should still be aware". A possible future control is tracked in issue #38. — [Writing Assistance APIs spec](https://webmachinelearning.github.io/writing-assistance-apis/) (2026-11-09)
- In the TAG thread (2025-10-30), a participant shown as "Reilly Eon" said a conforming implementation could use either on-device or cloud. — [TAG #1093](https://github.com/w3ctag/design-reviews/issues/1093)
- The spec says "Implementations must not train or fine-tune models on user input", and must not store input for later retrieval, such as RAG. — [Writing Assistance APIs spec §6](https://webmachinelearning.github.io/writing-assistance-apis/)
- Google's user help page: on-device AI means "data is processed locally, which can enhance privacy and speed". It says nothing about telemetry (undated). — [Google Chrome Help](https://support.google.com/chrome/answer/16961953)
- WebKit (2026-04-30): on-device inference isn't inherently more private, because the site still controls the prompts and receives the outputs. — [WebKit #495](https://github.com/WebKit/standards-positions/issues/495)

**Terms and policies**
- An archived Chrome Prompt API page (snapshot 2026-04-12, page stamp "Last updated: September 21, 2025") reads: "Before you use this API, acknowledge Google's Generative AI Prohibited Uses Policy." — [Wayback 2026-04-12](http://web.archive.org/web/20260412172511/https://developer.chrome.com/docs/ai/prompt-api)
- The sentence is absent from:
  - the 2026-08-01 snapshot (page stamp "Last updated: May 19, 2026");
  - the 2026-10-02 snapshot (stamp 2026-08-26);
  - the live page dated 2026-10-21. I checked its markdown copy for "Prohibited" and "acknowledg".

  — [Wayback 2026-08-01](http://web.archive.org/web/20260801143843/https://developer.chrome.com/docs/ai/prompt-api); [Chrome: The Prompt API](https://developer.chrome.com/docs/ai/prompt-api)
- Archibald (2026-04-29) said the policy's rules "go beyond law" and asked who would be held liable when a user's "summarize" click violates it. Wasserman replied the same day: "The concerns regarding UA-specific policies are well-taken. We are actively exploring ways to address these concerns." — [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)
- The policy itself restricts, among other things, privacy violations, sexually explicit content, misinformation and circumventing safety filters. It is enforced with automated and human review. — [Google Generative AI Prohibited Use Policy](https://policies.google.com/terms/generative-ai/use-policy)
- Edge: model disclaimer (it "can potentially behave in ways that are unreliable, inaccurate, unfair, or offensive"); the watermark rule (see §4); and the developer's responsibility to meet AI-content marking requirements. The model weights are MIT-licensed. — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api); [Aion model card](https://huggingface.co/microsoft/Aion-1.0-Instruct-2.3B)

**Shared model, fingerprinting and cross-site concerns**
- Spec §6.1: "the exact download status of the AI model or fine-tuning data can present a fingerprinting vector".
  - Recommended mitigation: report "downloadable" by default per (API, options, storage key) until a successful `create()`, reset with site storage.
  - Pages should not be able to cancel downloads or evict models.
  - "Pretending to download" protects sensitive language availability, but is "not a fingerprinting mitigation".
  - Probing expected input languages could reveal demographics.

  — [Writing Assistance APIs spec §6](https://webmachinelearning.github.io/writing-assistance-apis/)
- Chrome documents masking only for the Translator ("all language pairs are reported as downloadable until individual sites create a translator for a given pair"). — [Chrome: Translator API](https://developer.chrome.com/docs/ai/translator-api)
- WebKit (2026-04-30): "model availability remains a fingerprinting vector". Wasserman (2026-05-06): the Translator masking approach "could apply here". — [WebKit #495](https://github.com/WebKit/standards-positions/issues/495)
- The model is "shared across all websites", downloaded once on first API use (Edge, 2026-11-17). Chrome downloads on the first `create()` from any origin, and Gemini Nano scam detection can also trigger it (2025-10-21). — [Edge: Prompt API](https://learn.microsoft.com/en-us/microsoft-edge/web-ai/prompt-api); [Chrome: model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management)
- Spec §7.2: one page's use should not "overly interfere" with another page's use of the shared runtime. — [Writing Assistance APIs spec](https://webmachinelearning.github.io/writing-assistance-apis/)

**Can a site learn or pin the model version?**
- Chrome: "While you can't programmatically query the model version from JavaScript, you can manually check which version is installed on chrome://on-device-internals." Updates are hot-swapped. — [Chrome: model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management) (2025-10-21)
- Spec: "these APIs do not expose model versions directly", and download size is censored in progress events. Behavioral probing can still reveal the version, so the spec recommends tying model versions to UA versions. — [Writing Assistance APIs spec §6](https://webmachinelearning.github.io/writing-assistance-apis/)
- Reilly Grant (blink-dev, 2026-05-01): "The browser picks the model". Exposing versions risks problems like user-agent sniffing. — [blink-dev thread](https://mail-archive.com/blink-dev@chromium.org/msg16440.html)
- The TAG was "skeptical" of exposing a model identifier (2025-11-11). — [TAG #1093](https://github.com/w3ctag/design-reviews/issues/1093)
- Developers' workaround is to ask the model to name itself. It returned inconsistent self-reports ("Gemini, 1.0, Google DeepMind" and "Gemini, version 1.0, Google DeepMind"), while `chrome://on-device-internals` showed `v3Nano` `2025.06.30.1229` (2026-05-05). — [adsm.dev](https://adsm.dev/posts/prompt-api/)
- Archibald's example of the same sniffing pattern: a prompt for the model's ID returned `'gpt-3.5-turbo-0613, Gemma, 2024-02-29, Google DeepMind'`. — [mozilla #1213](https://github.com/mozilla/standards-positions/issues/1213)

### Inferences
- **Sending decrypted private mail to the model.** Today's Chrome and Edge both document on-device-only inference. That is a vendor promise per browser, not a web-platform guarantee: the spec allows a cloud-backed implementation, and pages have no API to require or check locality. For data that must never leave the device, a policy could allow the built-in model only in browsers whose docs promise local inference (Chrome desktop, Edge). Those docs would need re-checking when they change.
- **Telemetry is undocumented.** Both vendors describe what happens to prompt contents. Neither says whether usage metadata (calls, errors, latency) reaches their ordinary browser usage statistics.
- **No canonical model label.** Pages can't read the model's identity, and Chrome serves different variants (GPU at about 4B or 2B, or the CPU build) and hot-swaps them. Results can't be reproduced or audited the way the native apps' SHA-256-pinned Gemma 4 can. The most precise honest label is something like "browser-provided model (Chrome: Gemini Nano, version not exposed)". A user-agent check can pick "Chrome" or "Edge", but nothing finer. The model version could be logged only through manual `chrome://on-device-internals` inspection.
- **Fingerprinting.** For a privacy-focused product, calling `availability()` passively may itself be a minor fingerprinting concern for users. Sites could also use it to learn whether a user has the shared model downloaded, which reveals prior use of built-in AI or scam detection on that profile.

### Gaps
- I found no Chrome or Edge documentation of telemetry or usage metrics for built-in AI API calls, in either direction.
- I found no current Chrome statement of any terms a site or user must accept now that the acknowledgment sentence is gone. I also didn't verify whether Chrome's user ToS reference the Prohibited Use Policy for on-device features.
- I didn't confirm whether Chrome masks the Prompt API's `availability()` per site today. The WebKit comments suggest it doesn't.

## 9. Practical experience: quality, tool-use reliability, latency and failure modes

### Takeaway
Reports are mixed. Gemini Nano runs at interactive speed on good GPUs (about 35–50 tokens/s, about 100 ms warm first-token latency) and is slow on CPU (about 15 tokens/s). Developers call its quality "niche-toy" level for general use.

There is **no native tool calling**. Developers emulate it with JSON-schema constraints, and constraints can degrade quality.

Common failures:
- the model is missing (ineligible hardware, distro Chromium builds, purges, a download still running);
- `QuotaExceededError` on the small window;
- crash circuit-breakers;
- prompts failing during a model hot-swap;
- prompt injection.

### Cited Findings
- Quality: Gemini Nano is "not the _best_ model" and "unlikely to be much more than a niche toy for now". Response constraints "can hurt the response quality" if instructions are poor or the model has no room to reason (2026-05-05). — [adsm.dev](https://adsm.dev/posts/prompt-api/)
- Failure modes seen in practice:
  - `QuotaExceededError` ("The input is too large").
  - `LanguageModel is not defined` when flags or a relaunch are missing.
  - `availability()` stuck on "downloading" if `create()` was never called.
  - `LanguageModel.params is not a function` on some builds.

  Undated repo. — [GitHub Ar9av/gemini-nano-chrome](https://github.com/Ar9av/gemini-nano-chrome)
- Failure modes documented by Chrome:
  - A purge can happen "at any time, even mid-session".
  - A prompt "running at the exact moment of the swap" can fail.
  - After a purge, the model does not come back until some site calls `create()`.

  — [Chrome: model management](https://developer.chrome.com/docs/ai/understand-built-in-model-management) (2025-10-21)
- Chrome's debugging guide shows a misinterpretation bug: the Prompt API ran `toString()` on message arrays. It recommends `chrome://on-device-internals` Event Logs for debugging. — [Chrome: Debug Gemini Nano](https://developer.chrome.com/docs/ai/debug-gemini-nano) (2025-02-28)
- Security: Mint built two small browser agents on the Prompt API. A single malicious blog comment could make one send money from a bank tab and the other leak open-tab URLs and titles, with the "model behaving as designed". — [Mint Security blog](https://www.mint.security/blog/beware-of-the-tiny-agents-in-your-browser-a-chrome-prompt-api-case-study) (about 2026-05-05 per [NHI Mgmt Group coverage](https://nhimg.org/articles/chrome-prompt-api-exposes-browser-agents-to-indirect-prompt-injection/))
- WebML.ai (2026-06-06): system instructions and page content share no privilege boundary. Its advice is to treat the API as progressive enhancement, build the fallback first, and treat output from untrusted content as untrusted. It also says `availability()` can block while the model downloads. — [webml.ai](https://www.webml.ai/articles/prompt-api-web-pages-chrome-148)
- Chrome's agent security guidance (2026-06-09) says WebMCP data should be treated as untrusted. — [Chrome: agents security](https://developer.chrome.com/docs/agents/security)
- Translator output safety: see Archibald's `<script>` examples in §5. — [mozilla #1015](https://github.com/mozilla/standards-positions/issues/1015)
- Latency figures are in §2. — [adsm.dev](https://adsm.dev/posts/prompt-api/); [Ar9av](https://github.com/Ar9av/gemini-nano-chrome)
- Developers tune to Gemini in practice. Mozilla cited a Jetpack AI client commit that added logic based on Gemini's observed Summarizer behavior, and a site labeling summaries "made with the help of Gemini Nano" (2025-05/06). — [mozilla #1067](https://github.com/mozilla/standards-positions/issues/1067)

### Inferences
- In this design, the built-in model can only serve as an opportunistic fast path. A fallback is required for most users: the app's own model, or the native apps.
  - Many users won't qualify: mobile, Safari, Firefox, low-VRAM machines, distro Chromium, admin-disabled machines.
  - The model can vanish or change mid-session.
- With decrypted mail as prompts, prompt injection carried in incoming messages is the dominant risk if the model drives any action. Treat the model's output as untrusted, and don't let it call tools with authority.

### Gaps
- I found no independent, systematic quality benchmark of the current Chrome Gemini Nano (for example `v3Nano`) or of Edge's Aion on web tasks. I also found no measured data on how reliably JSON-schema tool emulation works.
