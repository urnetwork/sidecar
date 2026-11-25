# JavaScript/WebAssembly engines for local LLM, classifier and embedder inference in a web page or Web Worker (state as of 2026-11-25)

Conventions:
- "Today" is 2026-11-25. npm registry metadata, the npm download API, the GitHub REST API and Hugging Face API listings were read on 2026-11-25.
- On 2026-11-25 the published npm tarballs of each engine were downloaded and scanned statically for CSP-relevant code: `new Function`, `eval`, `blob:` workers, `importScripts`, dynamic `import()`, CDN hosts and `SharedArrayBuffer`. No engine code was executed, so CSP behaviour is read from code paths, not observed at run time.
- Sizes are uncompressed bytes. "gz" means gzip level 6, computed locally.
- Google doc pages show no date unless one is quoted. Everything dated 2025 is marked "possibly superseded".
- This file extends and corrects the earlier LiteRT-LM notes (`research_notes/Compute extension building blocks/litert_lm.md`, read 2026-11-23). Corrections are flagged **[correction]**.

## 1. Engines: license, latest version, cadence, health, bundle size, Worker support, SharedArrayBuffer / cross-origin isolation, and CSP needs

### Takeaway
Five engines can run LLMs inside a page or Worker today:
- **LiteRT-LM JS** (`@litert-lm/core` 0.20.0, Google, "early preview")
- **Transformers.js v4 on ONNX Runtime Web** (4.3.2, Hugging Face + Microsoft, by far the most used)
- **WebLLM** (0.2.89, MLC)
- **wllama** (4.0.0, llama.cpp; effectively one maintainer)
- **MediaPipe LLM Inference web** (0.10.30, in maintenance; its docs now redirect to LiteRT-LM)

Under the target policy (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'`, no COOP/COEP):
- **LiteRT-LM fits, with one condition.** Its code has no eval and no blob workers, it is single-threaded (no SharedArrayBuffer), and its wasm can be self-hosted. It must run in a **classic** Worker until a fixed `@litertjs/wasm-utils` reaches npm.
- **WebLLM fits only if** its executable model libraries are self-hosted.
- **Transformers.js/ORT fits only if** `wasmPaths` is self-hosted and `env.useWasmCache=false`. It runs single-threaded, and its WebGPU glue carries an embind `new Function` path that must be checked at run time.
- **wllama does not fit.** It always starts its worker from a `blob:` URL, so it needs `worker-src blob:`.

### Cited Findings

#### Summary table (npm and GitHub, read 2026-11-25)

| Engine | Package, latest version (publish date) | License | Repo health | Core runtime download | Threads / SharedArrayBuffer | Fetches by default | CSP-relevant code |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| LiteRT-LM JS | `@litert-lm/core` 0.20.0 (2026-11-23); nightly 0.21.0-nightly.20261124 | Apache-2.0 | 6,936★, 804 forks, 820 open issues+PRs, 53 contributors, pushed 2026-11-25 | JSPI build 22.60 MB (7.13 MB gz); Asyncify build 34.75 MB (10.10 MB gz); package unpacked 121.6 MB | single-threaded; no pthread/SAB code | wasm from `cdn.jsdelivr.net` unless `loadLiteRtLm(path)`; `hf://` → `huggingface.co` | no `new Function`/`eval`; glue loaded by `importScripts` or `<script>` |
| MediaPipe LLM Inference web | `@mediapipe/tasks-genai` 0.10.30 (2026-10-25); nightly 1.3.0-rc.20261122 | Apache-2.0 | mediapipe repo 37,847★, 243 open, 128 contributors, release v1.2.3 2026-11-11 | 25.79 MB (7.33 MB gz), 3 variants | no SAB code found | none (caller passes wasm base path) | no eval; `importScripts`, falls back to `import()` |
| WebLLM | `@mlc-ai/web-llm` 0.2.89 (2026-11-17) | Apache-2.0 | 19,406★, 160 open, 63 contributors, pushed 2026-11-20 | `lib/index.js` 6.51 MB (2.17 MB gz), self-contained; **plus a 6–12 MB compiled model library per model** | no SAB code found | model libs from `raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs`; weights from `huggingface.co` | no eval; tokenizer/xgrammar wasm inlined as base64 |
| Transformers.js v4 | `@huggingface/transformers` 4.3.2 (2026-10-27); next 4.4.0-next.1 | Apache-2.0 | 16,457★, 302 open, 92 contributors, pushed 2026-11-25 | `transformers.web.min.js` 0.43 MB (0.12 MB gz) + ORT asyncify wasm 27.42 MB (6.86 MB gz) | ORT threads only if `crossOriginIsolated`, else 1 | ORT wasm from `cdn.jsdelivr.net` unless `wasmPaths` set; models from `huggingface.co` | turns ORT's factory into a `blob:` URL when `useWasmCache` is on (default) |
| ONNX Runtime Web | `onnxruntime-web` 1.31.1 (2026-10-26); dev 1.33.0-dev.20261112 | MIT | **github.com/microsoft/onnxruntime returned 404 on 2026-11-25** | plain 14.16 MB (3.63 gz); asyncify/WebGPU EP 27.42 (6.86); jsep 28.15 (6.64); jspi 17.09 (4.22); package unpacked 150.6 MB | pthreads via `new Worker(import.meta.url, {type:"module"})`; need COI | none (paths relative to script) | embind `new Function` in WebGPU glue; `blob:` only for cross-origin multithreaded loads |
| wllama | `@wllama/wllama` 4.0.0 (2026-11-22) | MIT | 1,411★, 142 forks, 48 open, 10 contributors; user-owned repo (ngxson) | `wllama.wasm` 10.34 MB (3.01 MB gz) | multithreading and RPC workers need COOP/COEP | compat wasm from `cdn.jsdelivr.net`; `huggingface.co` | **always `new Worker(URL.createObjectURL(new Blob([code])))`** |
| llama.cpp WebGPU backend (ggml-webgpu) | no npm package (reached through wllama); build b12728 (2026-11-25) | MIT | 136,244★, 2,651 open, 2,313 contributors | n/a | n/a | n/a | n/a |

Sources for the table:
- npm registry JSON: [@litert-lm/core](https://registry.npmjs.org/@litert-lm/core), [@mediapipe/tasks-genai](https://registry.npmjs.org/@mediapipe/tasks-genai), [@mlc-ai/web-llm](https://registry.npmjs.org/@mlc-ai/web-llm), [@huggingface/transformers](https://registry.npmjs.org/@huggingface/transformers), [onnxruntime-web](https://registry.npmjs.org/onnxruntime-web), [@wllama/wllama](https://registry.npmjs.org/@wllama/wllama)
- GitHub repos (via API): [LiteRT-LM](https://github.com/google-ai-edge/LiteRT-LM), [mediapipe](https://github.com/google-ai-edge/mediapipe), [web-llm](https://github.com/mlc-ai/web-llm), [transformers.js](https://github.com/huggingface/transformers.js), [wllama](https://github.com/ngxson/wllama), [llama.cpp](https://github.com/ggml-org/llama.cpp), [microsoft/onnxruntime](https://github.com/microsoft/onnxruntime) (404)
- Tarballs scanned: [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz), [tasks-genai-0.10.30.tgz](https://registry.npmjs.org/@mediapipe/tasks-genai/-/tasks-genai-0.10.30.tgz), [web-llm-0.2.89.tgz](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz), [transformers-4.3.2.tgz](https://registry.npmjs.org/@huggingface/transformers/-/transformers-4.3.2.tgz), [onnxruntime-web-1.31.1.tgz](https://registry.npmjs.org/onnxruntime-web/-/onnxruntime-web-1.31.1.tgz), [wllama-4.0.0.tgz](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz)

Weekly npm downloads (week to 2026-11-25), from the npm downloads API (`api.npmjs.org/downloads/point/last-week/<pkg>`):
- `onnxruntime-web` 8,060,326
- `@huggingface/transformers` 4,550,253 (includes Node.js use)
- `@mlc-ai/web-llm` 194,909
- `@litertjs/core` 49,411
- `@wllama/wllama` 27,098
- `@litert-lm/core` 24,630
- `@mediapipe/tasks-genai` 16,311

— [npm registry](https://registry.npmjs.org/@litert-lm/core)

#### CSP mechanics that apply to all engines
- If `worker-src` is absent, "the user agent will first look for the child-src directive, then the script-src directive, then finally for the default-src directive, when governing worker execution". MDN's example shows a `data:` worker being blocked. — [MDN worker-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/worker-src) (undated)
- Under the target policy, workers therefore inherit `script-src 'self'`: same-origin worker scripts are allowed, and `blob:`/`data:` workers are blocked (inference from the rule above).

#### LiteRT-LM JS (`@litert-lm/core`)
- **[correction]** The npm `latest` is **0.20.0** (2026-11-23), not 0.12.1. The earlier notes read 0.12.1 from the repo's `package.json`.
  - Non-nightly npm versions and dates: 0.12.0 (2026-05-18), 0.12.1 (05-19), 0.13.1 (06-03), 0.14.0 (07-01), 0.15.0 (07-31), 0.16.0 (08-11), 0.17.0 (09-04), 0.17.1 (09-16), 0.18.0 (10-06), 0.18.1 (10-16), 0.19.0 (10-30), 0.20.0 (11-23).
  - There are also 29 nightlies; 41 versions in all.
  - The only runtime dependency is `@litertjs/wasm-utils ^2.0.0`, whose newest version is 2.6.0 (2026-10-22).
  - — [npm @litert-lm/core](https://registry.npmjs.org/@litert-lm/core); [npm @litertjs/wasm-utils](https://registry.npmjs.org/@litertjs/wasm-utils)
- GitHub release v0.20.0 (2026-11-23) has no web-specific items. Its items are NPU metadata defaults, Python 3.10 deprecation, benchmark init time and reproducible `.litertlm` builds. — [v0.20.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.20.0)
- The package ships four wasm builds (tarball, 2026-11-25), and `load.js` picks one at run time:
  - It tests `relaxedSimd` by instantiating a tiny module.
  - It tests JSPI with `'Suspending' in WebAssembly`.
  - The four builds:
    - `litertlm_wasm_internal.wasm` (relaxed SIMD + JSPI): 22.60 MB
    - `litertlm_wasm_asyncify_internal.wasm`: 34.75 MB
    - `litertlm_wasm_compat_internal.wasm`: 22.43 MB
    - `litertlm_wasm_compat_asyncify_internal.wasm`: 34.58 MB
  - The JS glue for each is about 0.28–0.29 MB.
  - — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz) (`dist/load.js`, `dist/wasm_feature_detect.js`, `wasm/`)
- Asyncify builds were added for Firefox and Safari. Issue #2616 (2026-06-20) reported that the JSPI-only build fails on iOS Safari (`new WebAssembly.Suspending` undefined). A Google collaborator answered (2026-07-01): "We'll have an `asyncify` version of the Wasm build that works on Firefox and very recent versions of Safari"; the issue was closed "Fixed in 0.14.0" (2026-07-06). — [#2616](https://github.com/google-ai-edge/LiteRT-LM/issues/2616)
- **Single-threaded; no SharedArrayBuffer needed.** The glue declares "Single threaded MINIMAL_RUNTIME programs" (tarball). Issue #4786 (open, 2026-11-24) measured that `numThreads` has no effect with or without cross-origin isolation, and says "None of the four loader scripts in the package … contains pthread or `SharedArrayBuffer` code." — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz); [#4786](https://github.com/google-ai-edge/LiteRT-LM/issues/4786)
- **Glue loading, and a module-worker failure.**
  - `@litertjs/wasm-utils` `runScript()` calls `importScripts(url)` when it exists, else appends a `<script>` element. The glue then sets the global `self.ModuleFactory`.
  - Issue #4080 (opened 2026-10-17) shows that module workers expose `importScripts` but throw: "TypeError: … Module scripts don't support importScripts()". The issue was closed 2026-11-06 after a fix landed in google-ai-edge/LiteRT#11608.
  - The reporter retested on 2026-11-24 with `@litert-lm/core@0.20.0`: module workers "still fail" because the fix is not in `@litertjs/wasm-utils` 2.6.0, the newest on npm.
  - Main thread and **classic workers work**.
  - — [wasm-utils-2.6.0.tgz](https://registry.npmjs.org/@litertjs/wasm-utils/-/wasm-utils-2.6.0.tgz); [#4080](https://github.com/google-ai-edge/LiteRT-LM/issues/4080)
- **CDN default.** `static DEFAULT_WASM_PATH = 'https://cdn.jsdelivr.net/npm/@litert-lm/core@0.20.0/wasm'` is used when `loadLiteRtLm()` was not called first. `loadLiteRtLm('/path/')` accepts a directory or one specific `.js` file. — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz) (`dist/litertlm_web.js`, `dist/load_litertlm.js`)
- **Other network and storage behaviour.**
  - `hf://` URIs resolve against `https://huggingface.co`.
  - The model cache uses the Cache API, `navigator.storageBuckets`, `navigator.storage` and Web Locks.
  - The scan found no `eval`/`new Function`.
  - The only `createObjectURL` calls are Emscripten's image/audio preload plugins.
  - — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz) (`dist/model-cache/*.js`)
- **WebGPU device request.** It asks for `powerPreference: 'high-performance'` and sets `requiredLimits` `maxBufferSize`/`maxStorageBufferBindingSize` to the adapter maximum. It requests the `shader-f16` and `subgroups` features when available. — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz) (`dist/litertlm_web.js`)
- **Documentation gaps.** The JS guide (fetched 2026-11-25, undated) still says nothing about browser versions, WebGPU, COOP/COEP, Workers or caching. The README inside the 0.20.0 tarball still says "This is an early preview that supports text-in / text-out running in WebGPU", although v0.19.0 added image and audio input (see section 3). — [JS guide](https://developers.google.com/edge/litert-lm/js); [core-0.20.0.tgz README](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz)
- **Packaging regressions in npm releases:**
  - #3364 (closed): `@litert-lm/core@0.16.0` "contains only package.json".
  - #4051 (closed): `0.18.1` "is latest on npm but ships 0.19-shaped wasm, so Engine.create always fails".
  - — [#3364](https://github.com/google-ai-edge/LiteRT-LM/issues/3364); [#4051](https://github.com/google-ai-edge/LiteRT-LM/issues/4051)

#### MediaPipe LLM Inference web (`@mediapipe/tasks-genai`)
- **Cadence.** npm versions 0.10.26 (2026-01-06), 0.10.27 (04-02), 0.10.28 (06-25), 0.10.29 (07-08) and 0.10.30 (10-25), plus daily `1.x.y-rc.<date>` nightlies (1.2.0-rc.20261029 … 1.3.0-rc.20261122). — [npm @mediapipe/tasks-genai](https://registry.npmjs.org/@mediapipe/tasks-genai)
- **Docs status.** `ai.google.dev/edge/mediapipe/solutions/genai/llm_inference/web_js` returns 301 to developers.google.com. That URL now serves a LiteRT-LM landing page ("Last updated 2026-10-06 UTC") with no deprecation notice and no MediaPipe web API content (fetched 2026-11-25). — [web_js guide](https://developers.google.com/edge/mediapipe/solutions/genai/llm_inference/web_js)
- **Relation to LiteRT-LM.** Google's May 2026 blog says LiteRT-LM's web support builds on "the foundational success of the MediaPipe LLM Inference engine's web solution" (cited in the earlier notes). LiteRT-LM still loads `.task` files, and HF still publishes `-web.task` files. — [Google Developers Blog, 2026-05-19](https://developers.googleblog.com/blazing-fast-on-device-genai-with-litert-lm/); [earlier notes](../Compute%20extension%20building%20blocks/litert_lm.md)
- **Code (0.10.30):**
  - Three wasm variants (`genai_wasm_internal`, `_module_internal`, `_nosimd_internal`), each 25.79 MB.
  - The loader tries `importScripts`, and on `TypeError` it falls back to `self.import`/`import()`, so it works in module workers.
  - The scan found no `eval`/`new Function`.
  - `requiredFeatures:["shader-f16"]` is unconditional, and it errors when `maxStorageBufferBindingSize` is below what is "usually at least 524550144".
  - — [tasks-genai-0.10.30.tgz](https://registry.npmjs.org/@mediapipe/tasks-genai/-/tasks-genai-0.10.30.tgz) (`genai_bundle.mjs`)

#### WebLLM (`@mlc-ai/web-llm`)
- **Release cadence in 2026 (GitHub releases):** v0.2.81 (02-18), v0.2.82 (03-13), v0.2.83 (04-24), v0.2.85 (09-08), v0.2.86 (10-11), v0.2.87 (10-30), v0.2.88 (11-10), v0.2.89 (11-17). There was a gap from April to September. — [web-llm releases](https://github.com/mlc-ai/web-llm/releases)
- **Dependencies** (npm):
  - `@mlc-ai/web-runtime` 0.28.0-dev2 (2026-11-09), the TVM web runtime
  - `@mlc-ai/web-xgrammar` 0.1.27 (2025-12-25, possibly superseded)
  - `@mlc-ai/web-tokenizers` 0.1.6 (2025-05-03, possibly superseded)
  - `lib/index.js` inlines them: it contains three `data:application/octet-stream;base64` wasm blobs, which Emscripten decodes with `atob`/`tryParseAsDataURI` instead of fetching.
  - — [npm @mlc-ai/web-runtime](https://registry.npmjs.org/@mlc-ai/web-runtime); [npm @mlc-ai/web-xgrammar](https://registry.npmjs.org/@mlc-ai/web-xgrammar); [web-llm-0.2.89.tgz](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz)
- **Model libraries are code fetched from GitHub by default.**
  - Prebuilt entries use `model_lib: modelLibURLPrefix + modelVersion + "/<model>-webgpu.wasm"`, with `modelLibURLPrefix = "https://raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs/main/web-llm-models/"` and `modelVersion = "v0_2_87/base"`.
  - Weights come from `https://huggingface.co/mlc-ai/...`.
  - The scan found no `eval`/`new Function`.
  - Storage uses the Cache API, IndexedDB and OPFS.
  - — [web-llm-0.2.89.tgz](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz)
- **Release-note items on storage and integrity:**
  - v0.2.83 (2026-04-24): "Add support for cross-origin storage", "Support integrity verification for model artifacts".
  - v0.2.85 (2026-09-08): "Add OPFS synchronous access handles and committed cache records".
  - — [v0.2.83](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.83); [v0.2.85](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.85)
- **Workers.** The README lists "Web Worker & Service Worker Support". The code documents `new webllm.WebWorkerMLCEngine(new Worker(new URL('./worker.ts', import.meta.url), {type: 'module'}))`. — [web-llm-0.2.89.tgz README](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz)

#### Transformers.js v4 + ONNX Runtime Web
- **Release dates (npm):** 4.0.0 (2026-03-30), 4.0.1 (04-02), 4.1.0 (04-15), 4.2.0 (04-22), 4.3.0 (09-16), 4.3.1 (10-06), 4.3.2 (10-27). — [npm @huggingface/transformers](https://registry.npmjs.org/@huggingface/transformers)
- **v4.0.0 changes:**
  - It moved to "a new WebGPU Runtime, completely rewritten in C++", built with the ONNX Runtime team.
  - The build moved to esbuild, and `transformers.web.js` became "53% smaller".
  - Tokenization split out as `@huggingface/tokenizers`.
  - A `ModelRegistry` API was added.
  - `env.useWasmCache` "enables caching of WASM runtime files".
  - — [Transformers.js 4.0.0 release](https://github.com/huggingface/transformers.js/releases/tag/4.0.0)
- 4.3.0 "adds … WebGPU support for Safari 26+" and upgraded ONNX Runtime. — [4.3.0 release](https://github.com/huggingface/transformers.js/releases/tag/4.3.0)
- 4.3.2 pins `onnxruntime-web 1.31.0-dev.20260914-8d85527a0`, `@huggingface/jinja ^0.5.10` and `@huggingface/tokenizers ^0.2.0`. — [npm @huggingface/transformers](https://registry.npmjs.org/@huggingface/transformers)
- **CDN default and the blob factory path (4.3.2 code):**
  - If `env.backends.onnx.wasm.wasmPaths` is unset, it is set to `https://cdn.jsdelivr.net/npm/onnxruntime-web@<ver>/dist/ort-wasm-simd-threaded.asyncify.{mjs,wasm}`. The suffix is `""` for Safari < 26 without WebGPU.
  - With `env.useWasmCache` (default when the Cache API exists) and `wasmPaths` as an object, `loadWasmFactory()` fetches the `.mjs` and rewrites `globalThis.process?.versions?.node` to `false`. It then returns `URL.createObjectURL(new Blob([code], {type:"text/javascript"}))` for ORT to `import()`. This is skipped in service workers and Chrome extensions.
  - It sets `ONNX_ENV.wasm.proxy = false` and `webgpu.powerPreference = "high-performance"`.
  - — [transformers-4.3.2.tgz](https://registry.npmjs.org/@huggingface/transformers/-/transformers-4.3.2.tgz) (`dist/transformers.web.js`)
- **ORT Web 1.31.1 code:**
  - **Threads:** `numThreads>1` without `crossOriginIsolated` logs a warning and falls back to 1 thread. Pthreads are module workers created with `new Worker(new URL(import.meta.url), {type:"module", name:"em-pthread"})`.
  - **Blob URLs:** `preload()` turns a script into a `blob:` URL only when the wasm module URL is cross-origin and multithreaded ("needPreload").
  - **Eval:** the WebGPU builds' glue (`ort-wasm-simd-threaded.asyncify.mjs`, `.jsep.mjs`) contains embind's emval method caller, which builds `new Function(Object.keys(k), h)`. The plain `ort-wasm-simd-threaded.mjs` contains none.
  - — [onnxruntime-web-1.31.1.tgz](https://registry.npmjs.org/onnxruntime-web/-/onnxruntime-web-1.31.1.tgz)
- **Runtime evidence on `new Function`.** One third-party project enforced `script-src 'self' 'wasm-unsafe-eval'` (no `'unsafe-eval'`) with `worker-src 'self' blob:`, using ORT files served from its own site. It reported "no violation" while a model ran on `onnx-webgpu` in Chrome (issue closed 2026-11-20). Single project, not a vendor statement. — [Quantum-Daemons/QSMPC-QKD-QHE-AI-Hybrid#70](https://github.com/Quantum-Daemons/QSMPC-QKD-QHE-AI-Hybrid/issues/70)
- **Older eval note.** Transformers.js issue #378 (opened 2023-11-03, still open) has a 2023 maintainer comment that the only `eval` came from protobuf.js `inquire` (possibly superseded). The 2026-11-25 scan of `ort.webgpu.mjs` 1.31.1 found no `eval(`. — [#378](https://github.com/huggingface/transformers.js/issues/378)
- **ORT Web cadence (npm):** 1.24.1 (2026-02-05), 1.24.2 (02-19), 1.24.3 (03-05), 1.25.1 (04-29), 1.26.0 (05-08), 1.27.0 (06-19), 1.29.0 (08-24), 1.30.0 (09-14), 1.31.1 (10-26), with dev builds up to 1.33.0-dev.20261112. — [npm onnxruntime-web](https://registry.npmjs.org/onnxruntime-web)
- **GitHub status.** On 2026-11-25, `https://github.com/microsoft/onnxruntime` and `…/onnxruntime-genai` returned HTTP 404. `git ls-remote` said "Repository not found", and the search API said the repo "cannot be searched". npm still lists `git+https://github.com/Microsoft/onnxruntime.git`, and onnxruntime.ai docs load. A web search found no announcement of a move. — [github.com/microsoft/onnxruntime](https://github.com/microsoft/onnxruntime); [npm onnxruntime-web](https://registry.npmjs.org/onnxruntime-web)

#### wllama (`@wllama/wllama`)
- **Releases:** 3.5.1 (2026-06-15), 3.6.0 (08-16), 3.6.1 (08-27), 3.8.1 (10-02), 3.13.0 (11-08), 4.0.0 (11-22). Most changes are "[autosync] llama.cpp" PRs by the maintainer. — [wllama releases](https://github.com/ngxson/wllama/releases)
- **Blob worker in 4.0.0 code.** `createWorker()` does `new Worker(URL.createObjectURL(new Blob([workerCode], {type:"text/javascript"})), {type:"module"})`. The worker code is assembled at run time, and since PR #327 ("put js glue into wasm") the Emscripten glue is read out of the wasm module. No option for a static worker URL was found. — [wllama-4.0.0.tgz](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz) (`src/worker.ts`, `esm/index.js`); [4.0.0 release](https://github.com/ngxson/wllama/releases/tag/4.0.0)
- **Threads and CDN.**
  - README: "To enable multi-thread, you must add `Cross-Origin-Embedder-Policy` and `Cross-Origin-Opener-Policy` headers."
  - v4 guide: "RPC workers need multi-threading, so the page must be cross-origin isolated … Without it, a model whose CPU part is bigger than 4GB cannot be loaded."
  - The compat build URL defaults to `https://cdn.jsdelivr.net/npm/@wllama/wllama-compat@4.0.0/wasm/wllama.wasm`.
  - — [wllama README / guides/intro-v4.md in tarball](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz); [intro-v4.md](https://github.com/ngxson/wllama/blob/master/guides/intro-v4.md)

#### llama.cpp WebGPU backend
- **Build docs.** `docs/build.md` has a WebGPU section ("relies on Dawn"). Its "Browser Support" text says Emscripten is used with Dawn's `emdawnwebgpu` bindings. A `wasi:webgpu` target is also documented. — [docs/build.md](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md)
- **Op coverage.** `docs/ops.md` (read 2026-11-25) lists 122 ggml ops: WebGPU fully supports 71, partially 13, none 38. For comparison, Metal is 71/20/31 and Vulkan 95/10/17. Commits to `ggml/src/ggml-webgpu` landed on 2026-11-24 and 2026-11-25 (softmax indexing fix, POOL_1D, log1p). — [docs/ops.md](https://github.com/ggml-org/llama.cpp/blob/master/docs/ops.md); [ggml-webgpu commits](https://github.com/ggml-org/llama.cpp/commits/master/ggml/src/ggml-webgpu)
- **Maintainer.** wllama's README says "The WebGPU backend for llama.cpp is maintained by Reese Levine". — [wllama README](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz)

#### ONNX Runtime GenAI for web
- The generate() API docs (fetched 2026-11-25, undated) list Python, C#, C, C++ and Java APIs, and no JavaScript or web binding. They say "this API is in preview and is subject to change". — [ORT generate() docs](https://onnxruntime.ai/docs/genai/)
- npm search found no `onnxruntime-genai` web package (2026-11-25). — [npm search](https://registry.npmjs.org/-/v1/search?text=onnxruntime-genai)

#### Newer and smaller entrants
- **Ratchet** (huggingface/ratchet): 771★, last push 2026-09-24, no GitHub releases. Its npm `@ratchet-ml/ratchet-web` was last published at 0.4.0 on 2024-04-29 and had 11 downloads that week. — [huggingface/ratchet](https://github.com/huggingface/ratchet); [npm](https://registry.npmjs.org/@ratchet-ml/ratchet-web)
- **Candle** (huggingface/candle): 21,415★, tag 0.11.0 (2026-06-26). Its in-browser demos (T5, Phi-1.5/2, Whisper, SAM) are WASM. — [candle README](https://github.com/huggingface/candle)
- **Burn** (tracel-ai/burn): 16,347★, v0.23.0-pre.2 (2026-11-09). Its CubeCL backend lists WebGPU for Wasm. `tracel-ai/burn-lm` has 267★ and was last pushed 2026-09-04. — [burn README](https://github.com/tracel-ai/burn); [burn-lm](https://github.com/tracel-ai/burn-lm)
- **web-rwkv** (cryscan/web-rwkv): "implemented in pure WebGPU", "WASM support (can run in browser)". 361★, v0.10.20 (2026-04-01), license NOASSERTION. — [web-rwkv](https://github.com/cryscan/web-rwkv)
- **LiteRT.js** (`@litertjs/core` 2.6.0, 2026-10-22, Apache-2.0) runs classic `.tflite` models. It ships four wasm builds of 10.44–11.98 MB (default build 2.96 MB gz), including a `litert_wasm_threaded_internal` build. — [npm @litertjs/core](https://registry.npmjs.org/@litertjs/core); [core-2.6.0.tgz](https://registry.npmjs.org/@litertjs/core/-/core-2.6.0.tgz)
- **Firefox ML runtime** is browser-internal. It is "an experimental machine learning local inference runtime based on Transformers.js and the ONNX runtime"; extensions get a "WebExtensions AI API". See section 7. — [Firefox ML docs](https://firefox-source-docs.mozilla.org/toolkit/components/ml/) (undated)

### Inferences
- **What the target policy allows** (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' <hosts>`, no COOP/COEP):
  - Allowed: same-origin `importScripts()`, same-origin dynamic `import()`, `WebAssembly.instantiate*` and same-origin dedicated workers.
  - Blocked: `blob:`/`data:` workers and scripts, and any `new Function`/`eval` that actually runs.
  - Not governed by CSP: WebGPU, Cache API, OPFS and IndexedDB.
- **Per-engine fit:**
  - **LiteRT-LM:** needs only self-hosting of `wasm/` (call `loadLiteRtLm('/v1/…/wasm/')` before `Engine.create`) and a classic Worker. If the model URL is same-origin or behind the listed hosts, nothing else is fetched.
  - **WebLLM:** needs a custom `appConfig` pointing `model` and `model_lib` at self-hosted copies; otherwise `raw.githubusercontent.com` and `huggingface.co` (plus HF's CDN redirects) must be in `connect-src`.
  - **Transformers.js:** needs `env.backends.onnx.wasm.wasmPaths` set to self-hosted ORT files and `env.useWasmCache=false` (or a string prefix rather than an object). Leave `numThreads` at 1. Test for a `securitypolicyviolation` on the embind `new Function` path before relying on the WebGPU EP.
  - **wllama:** needs `worker-src blob:`, which the policy forbids, or a fork.
- **Bundles are tens of MB.** Every LLM engine adds about 7–10 MB gz of wasm (LiteRT-LM, MediaPipe, ORT WebGPU) or 2–3 MB gz (wllama, WebLLM core) before any model. With WebLLM, every model also brings its own 6–12 MB code library.
- **Maintenance risk:**
  - Highest: wllama (one maintainer) and Ratchet (dormant).
  - LiteRT-LM is very active but ships npm packaging regressions and labels the JS API "early preview".
  - ORT's GitHub disappearing on 2026-11-25 may be transient, but it would block issue tracking.

### Gaps
- No engine documents its CSP needs. Run-time confirmation is needed for: whether ORT's embind `new Function` path fires with the WebGPU EP for LLM sessions; whether LiteRT-LM or MediaPipe hit any eval path not visible statically; and which redirect hosts HF downloads use from a Worker.
- Why github.com/microsoft/onnxruntime returned 404 on 2026-11-25 could not be determined.
- Whether WebGPU is exposed in cross-origin iframes by default, or needs a Permissions Policy, was not researched here (adjacent topic).
- No release date was found for a `@litertjs/wasm-utils` version containing the module-worker fix.

## 2. Models and formats: availability per engine, quantizations and sizes, licenses, and whether artifacts contain executable code

### Takeaway
- **LiteRT-LM JS** officially targets Gemma 4 (E2B, E4B, 12B, 26B-A4B, 31B; Apache-2.0, ungated). **[correction]** The E2B model card now says web uses `gemma-4-E2B-it-gpu.litertlm` (2.34 GB, up to 128k context), not the `-web.litertlm` file (2.00 GB).
- **WebLLM** ships precompiled MLC builds of Gemma 4 E2B, Gemma 3 1B, Qwen3/Qwen3.5, Phi-4-mini, Llama 3.2 and SmolLM3. It has no Gemma 4 E4B, no Gemma 3n and no Gemma 3 270M.
- **Transformers.js** has onnx-community ONNX exports of every listed family, including multimodal Gemma 4 and Gemma 3n.
- **wllama** loads any GGUF.
- Only WebLLM's model packages contain executable code (compiled WASM with WGSL kernels). The other formats are data plus chat templates, which interpreters render.

### Cited Findings
- **LiteRT-LM collection.** The "Web LLM Models" collection (updated 2026-10-30) has 40 repos:
  - Gemma 4 E2B/E4B/12B/26B-A4B/31B (ungated)
  - gated Gemma 3n E2B/E4B, Gemma 3 270M/1B/4B/12B/27B, TranslateGemma and MedGemma
  - non-Gemma models such as SmolLM3-3B, Ministral-3-3B, Phi-4-mini-reasoning, granite-4.1/4.2-3b, Qwen3-4B-Thinking-2507, Qwen2.5-Coder-1.5B, OLMo-2-1B, DeepSeek-R1-Distill-Qwen-7B, Shieldstral-1.0-3B
  - — [HF collection](https://huggingface.co/collections/litert-community/web-llm-models-68c1d5e66b5461ef41bc4943)
- **Web-relevant LiteRT-LM file sizes** (HF tree API, 2026-11-25):

  | Repo | Files and sizes | License / gating |
  | :--- | :--- | :--- |
  | gemma-4-E2B-it-litert-lm (rev 2e12bfd8, 2026-11-20) | `-gpu.litertlm` 2.34 GB; `-web.litertlm` 2.00 GB; `-web.task` 2.00 GB; base 2.58 GB | apache-2.0, ungated |
  | gemma-4-E4B-it-litert-lm | `-gpu` 3.31 GB; `-web` 2.96 GB; `-web.task` 2.96 GB | apache-2.0 |
  | gemma-4-12B-it-litert-lm | `-gpu` 6.19 GB; `-web` 5.98 GB | apache-2.0 |
  | gemma-4-26B-A4B-it-litert-lm | `-gpu` 16.39 GB; `-web` 15.78 GB | apache-2.0 |
  | gemma-4-31B-it-litert-lm | `-gpu` 19.83 GB; `-web` 19.21 GB | apache-2.0 |
  | google/gemma-3n-E2B-it-litert-lm | `-int4-Web.litertlm` 3.03 GB | Gemma terms, manual gate |
  | google/gemma-3n-E4B-it-litert-lm | `-int4-Web.litertlm` 4.27 GB | Gemma terms, manual gate |
  | gemma-3-270m-it | `q4_0-web.task` 0.24 GB; `q8-web.task` 0.27 GB | gated (auto) |
  | Gemma3-1B-IT | many `.task` variants 0.55–4.01 GB; `q4_ekv4096.litertlm` 0.58 GB | gated (auto) |
  | SmolLM3-3B | `q4_block32_ekv4096.litertlm` 2.00 GB (no `-web` file) | ungated |

  — [E2B tree](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main); [E4B](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/tree/main); [12B](https://huggingface.co/litert-community/gemma-4-12B-it-litert-lm/tree/main); [26B-A4B](https://huggingface.co/litert-community/gemma-4-26B-A4B-it-litert-lm/tree/main); [31B](https://huggingface.co/litert-community/gemma-4-31B-it-litert-lm/tree/main); [gemma-3n-E2B](https://huggingface.co/google/gemma-3n-E2B-it-litert-lm); [gemma-3-270m-it](https://huggingface.co/litert-community/gemma-3-270m-it); [Gemma3-1B-IT](https://huggingface.co/litert-community/Gemma3-1B-IT); [SmolLM3-3B](https://huggingface.co/litert-community/SmolLM3-3B)
- **[correction] Which E2B file the web uses.** The E2B card (updated 2026-11-20) says: "Web on LiteRT-LM uses a specially optimized model (gemma-4-E2B-it-gpu.litertlm) for Web because of its unique memory constraints. The model can support up to 128k context length." It also points LiteRT-LM.js users to `gemma-4-E2B-it-gpu.litertlm`. Its web benchmark row lists a 2341 MB model (the `-gpu` file size). — [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- **Choosing the file for a backend.** The JS README says a `hf://` URI without a path makes LiteRT-LM choose "the model file in the repo for the engine's backend. If several files match, it loads one and logs a warning". — [core-0.20.0.tgz README](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz)
- **Non-web builds can fail on WebGPU.** Issue #2322 (closed): `@litert-lm/core@0.12.0` failed on `gemma3-1b-it-int4.litertlm` with "model lacks WebGPU artifacts". — [#2322](https://github.com/google-ai-edge/LiteRT-LM/issues/2322)
- **[correction / addition] Browser RAM.** A Google collaborator (2026-09-16): "Gemma 4 E2B requires around 4GB of free ram when running in the browser, and it won't work on iOS." — [#2368](https://github.com/google-ai-edge/LiteRT-LM/issues/2368)
- **WebLLM 0.2.89 prebuilt catalog.** It has 173 entries. Each relevant entry below gives VRAM in MB; the prebuilt context is 4096 unless noted.
  - Gemma: `gemma-4-E2B-it-q4f16_1` 3,387 (requires `shader-f16`), `-q4f32_1` 3,863; `gemma3-1b-it-q4f16_1` 711.
  - Qwen3: `Qwen3-0.6B-q4f16_1` 1,403; `Qwen3-1.7B` 2,037; `Qwen3-4B` 3,432; `Qwen3-8B` 5,696.
  - Qwen3.5: `Qwen3.5-0.8B` 1,629; `2B` 2,245; `4B` 3,868; `9B` 6,433.
  - `Phi-4-mini-instruct-q4f16_1` 3,438, `-q4f32_1` 4,221.
  - `Llama-3.2-1B-Instruct-q4f16_1` 879, `-q4f32_1` 1,129; `Llama-3.2-3B-q4f16_1` 2,264.
  - `SmolLM3-3B-q4f16_1` 2,053 (`shader-f16`), `-q4f32_1` 2,589.
  - `LFM2.5-1.2B` 1,001; `Ministral-3-3B` 2,864.
  - Embedders: `snowflake-arctic-embed-s/m` 239–1,408.
  - — [web-llm-0.2.89.tgz](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz) (`prebuiltAppConfig`)
- **Gemma 4 in WebLLM.** v0.2.86 (2026-10-11) "Add Gemma 4 E2B instruction-tuned models in `q4f16_1` and `q4f32_1`, with text and audio input. The FP32 variant does not require `shader-f16`." Gemma 4 (#810, opened 2026-04-03) and Gemma-3n-E2B (#729) model requests are still open. — [v0.2.86](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.86); [#810](https://github.com/mlc-ai/web-llm/issues/810); [#729](https://github.com/mlc-ai/web-llm/issues/729)
- **WebLLM artifacts** (HF and GitHub, 2026-11-25):
  - Weights: `mlc-ai/gemma-4-E2B-it-q4f16_1-MLC` is 94 files, 2.83 GB, apache-2.0.
  - Model libraries in `v0_2_87/base`: `gemma-4-E2B-it-q4f16_1_cs512-webgpu.wasm` 12 MB, `Llama-3.2-1B-Instruct-q4f16_1_cs1k-webgpu.wasm` 6.2 MB, `Phi-4-mini-instruct-q4f16_1_cs1k-webgpu.wasm` 6.4 MB, `Qwen3-1.7B-q4f16_1_cs1k-webgpu.wasm` 6.5 MB, `SmolLM3-3B-q4f16_1_cs1k-webgpu.wasm` 7.3 MB.
  - v0.2.86 notes: "Rebuild 224 WebGPU libraries: 112 each in `base` and `sg32`. The release includes compiler revisions, configuration snapshots, checksums, validation results, and a rebuild script."
  - — [mlc-ai/gemma-4-E2B-it-q4f16_1-MLC](https://huggingface.co/mlc-ai/gemma-4-E2B-it-q4f16_1-MLC); [binary-mlc-llm-libs v0_2_87/base](https://github.com/mlc-ai/binary-mlc-llm-libs/tree/main/web-llm-models/v0_2_87/base); [v0.2.86](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.86)
- **Transformers.js (onnx-community) q4f16 totals** (HF tree API, 2026-11-25):

  | Repo | q4f16 total | Notes | License |
  | :--- | :--- | :--- | :--- |
  | `gemma-4-E2B-it-ONNX` | 3.38 GB | decoder + embed + audio + vision encoders | apache-2.0 |
  | `gemma-4-E4B-it-ONNX` | 5.17 GB | decoder data split in two files | apache-2.0 |
  | `gemma-3-270m-it-ONNX` | 0.27 GB | | gemma |
  | `gemma-3-1b-it-ONNX` | 0.76 GB | | gemma |
  | `gemma-3n-E2B-it-ONNX` | 3.31 GB | | gemma |
  | `Qwen3-0.6B-ONNX` | 0.56 GB | | no tag |
  | `Qwen3-1.7B-ONNX` | 1.42 GB | | no tag |
  | `Qwen3-4B-ONNX` | 2.83 GB | | no tag |
  | `Qwen3.5-0.8B-ONNX` | 0.64 GB | incl. vision; text-only repo 0.46 GB | apache-2.0 |
  | `Qwen3.5-2B-ONNX` | 1.58 GB | | |
  | `Phi-4-mini-instruct-ONNX` | 2.55 GB | | no tag |
  | `Llama-3.2-1B-Instruct-ONNX` | 1.08 GB | | llama3.2 |
  | `Llama-3.2-3B-Instruct-ONNX` | 2.40 GB | | llama3.2 |
  | `HuggingFaceTB/SmolLM3-3B-ONNX` | 2.12 GB | | apache-2.0 |

  Files above 2 GB are split into `.onnx_data`, `.onnx_data_1`, and so on. — [HF API onnx-community](https://huggingface.co/onnx-community); [gemma-4-E2B-it-ONNX](https://huggingface.co/onnx-community/gemma-4-E2B-it-ONNX); [gemma-4-E4B-it-ONNX](https://huggingface.co/onnx-community/gemma-4-E4B-it-ONNX); [SmolLM3-3B-ONNX](https://huggingface.co/HuggingFaceTB/SmolLM3-3B-ONNX)
- **Transformers.js model releases:**
  - 4.1.0 (2026-04): "Add support for Gemma 4", and "Add support for `q1`, `q1f16`, `q2`, and `q2f16` data types".
  - 4.0.0: Qwen3.5 / Qwen3-VL / Gemma3 VLM support.
  - 4.0.0: "we've been able to run GPT-OSS 20B (q4f16) at ~60 tokens per second on an M4 Pro Max".
  - 4.3.0: "Pin the WebGPU KV cache for Gemma3n and Gemma4 image-audio-text-to-text models".
  - — [4.1.0](https://github.com/huggingface/transformers.js/releases/tag/4.1.0); [4.0.0](https://github.com/huggingface/transformers.js/releases/tag/4.0.0); [4.3.0](https://github.com/huggingface/transformers.js/releases/tag/4.3.0)
- **wllama/GGUF:**
  - `ggml-org/gemma-4-E2B-it-GGUF`: Q4_0 2.84 GB, Q8_0 4.96 GB, `mmproj` Q8_0 0.55 GB, MTP draft Q4_0 0.05 GB.
  - `gemma-4-E4B-it-GGUF`: Q4_0 4.59 GB.
  - wllama's HF helper defaults to quants `["Q4_K_M","Q8_0"]`.
  - v4: "a GGUF file of any size can be loaded as-is … models bigger than 4GB are spread across multiple wasm instances".
  - — [ggml-org/gemma-4-E2B-it-GGUF](https://huggingface.co/ggml-org/gemma-4-E2B-it-GGUF); [ggml-org/gemma-4-E4B-it-GGUF](https://huggingface.co/ggml-org/gemma-4-E4B-it-GGUF); [wllama-4.0.0.tgz](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz); [intro-v4.md](https://github.com/ngxson/wllama/blob/master/guides/intro-v4.md)
- **Format contents:**
  - `.litertlm` is a FlatBuffer-headered container of tokenizer, LiteRT graphs and metadata (earlier notes; `schema/core/litertlm_header_schema.fbs`).
  - Transformers.js renders chat templates with `@huggingface/jinja`, "a minimalistic JavaScript implementation of the Jinja templating engine". The 2026-11-25 scans of `@huggingface/jinja` 0.5.13 and `@huggingface/tokenizers` 0.2.0 found no `eval`/`new Function`.
  - — [earlier notes](../Compute%20extension%20building%20blocks/litert_lm.md); [litertlm_header_schema.fbs](https://github.com/google-ai-edge/LiteRT-LM/blob/main/schema/core/litertlm_header_schema.fbs); [npm @huggingface/jinja](https://registry.npmjs.org/@huggingface/jinja)

### Inferences
- **Same model family as the native apps.** For a web build that matches the native apps (Gemma 4 with LiteRT-LM), LiteRT-LM JS is the only engine that runs the same `.litertlm` artifacts. Use the `-gpu.litertlm` files for WebGPU, mirrored to self-hosted storage; Gemma 4's Apache-2.0 license allows this.
  - Plan on about 2.3 GB for E2B and 3.3 GB for E4B.
  - Plan on about 4 GB of free RAM (Google's own figure for E2B).
  - The 26B/31B web files (15.8–19.2 GB) are desktop-only curiosities.
- **WebLLM's model libraries are executable.** The supply-chain surface is the model libraries (WASM + WGSL compiled by MLC), not the weights. They must be pinned, self-hosted and integrity-checked like application code. All the other engines' model downloads are data.
- **Gemma 3 and 3n licensing.** Gemma 3 and 3n carry the Gemma terms (gated upstream). The onnx-community copies are ungated but still `license:gemma`. For licensing simplicity, prefer Gemma 4, Qwen3.5 (Apache-2.0 tag on some repos), SmolLM3 (Apache-2.0) or Phi-4-mini (MIT, per the earlier notes).

### Gaps
- Whether the non-Gemma `.litertlm` files in the "Web LLM Models" collection (no `-web`/`-gpu` suffix) actually run on LiteRT-LM WebGPU is not documented. No Qwen3/Qwen3.5 0.6B–2B or Llama 3.2 `.litertlm` web build was found in that collection.
- The difference between E2B's `-gpu.litertlm` and `-web.litertlm`, and which one `hf://` picks for `Backend.GPU`, is not documented.
- Licenses of some onnx-community repos (Qwen3, Phi-4-mini) are not tagged; check the upstream model cards.

## 3. Features: OpenAI-style chat, streaming, cancel, tools, JSON-schema constrained decoding, multimodal, concurrent sessions, KV/prefix reuse, browser context limits

### Takeaway
- **wllama** has the most complete OpenAI-style feature set, because it embeds llama-server's `server-context`: tools, `tool_choice`, `response_format` `json_schema`, GBNF grammars, parallel slots and slot save/restore.
- **WebLLM** has a full OpenAI chat API with XGrammar JSON-schema/EBNF/structural-tag constraints, but `tools` only for five Hermes models.
- **LiteRT-LM JS** has OpenAI-like messages, `tool_calls`, `AutoToolChat`, `clone()` prefix reuse and image/audio input. Its constrained decoding covers only tool-call syntax: there is no JSON-schema/regex constraint and no `tool_choice` in the web SDK (open request #4785, 2026-11-24).
- **Transformers.js** renders `tools` into chat templates and offers an experimental structured-output package, but leaves tool-call parsing to the app.

### Cited Findings
- **LiteRT-LM JS 0.20.0 API** (from `.d.ts`):
  - `Engine.create(settings)`, `engine.createConversation(config)`, `engine.createSession()`.
  - `Conversation.sendMessage(MessageLike): Promise<Message>`, `sendMessageStreaming(): ReadableStream<Message>`, `cancel()`, `getHistory()`, `getTokenCount()`, `getBenchmarkInfo()`, `clone()`, `delete()`.
  - `Message` has `role`, `content` (string or parts: `text`, `image`, `audio`, `video`, `tool_response`), `channels` and `tool_calls` (`{type, id?, function:{name, arguments: Record<string, JsonValue>}}`).
  - `ConversationConfig` has `sessionConfig`, `preface {messages, tools, extra_context}`, `enableConstrainedDecoding`, `prefillPrefaceOnInit` and `filterChannelContentFromKvCache`.
  - `EngineSettings` include `backend`, `activationDataType`, `visionBackend`, `audioBackend`, `maxVisionTokensPerImage`, `mainExecutorSettings.maxNumTokens` and `speculativeDecodingConfig`.
  - Backends: `GPU_ARTISAN`, `CPU`, `GPU`, `GOOGLE_TENSOR_ARTISAN`, `NPU`.
  - Also exported: `AutoToolChat` and a `WebMcpTool` adapter (`{name, description, inputSchema, execute}`).
  - — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz) (`dist/*.d.ts`)
- **LiteRT-LM JS guide** (fetched 2026-11-25, undated):
  - Branching: "`clone()` forks a conversation without re-prefilling history".
  - Thinking is toggled with `enable_thinking` in `extra_context`, and reasoning appears in `channels['thought']`.
  - "Dedicated token budget constraints are supported in the Python, Kotlin, and Swift SDKs". The web SDK is not on that list.
  - Context length comes from `mainExecutorSettings.maxNumTokens`; the example uses 8192.
  - — [JS guide](https://developers.google.com/edge/litert-lm/js)
- **LiteRT-LM release history for web features:**
  - v0.14.0 (2026-07-08): "full tool calling support in LiteRT-LM.js".
  - v0.15.0 (2026-08-04): `AutoToolChat`.
  - v0.18.0 (2026-10-06): EmbeddingGemma 2 across platforms including "Web (JavaScript)".
  - v0.19.0 (2026-11-02): "@litert-lm/core now stream-loads all models, defaults to the GPU backend, and supports image and audio inputs".
  - — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases); [v0.19.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.0)
- **LiteRT-LM constraints in the web SDK.** Issue #4785 (2026-11-24): "The web SDK has neither. Its only related option is `enableConstrainedDecoding`, which covers tool calls in the model's own format." A collaborator answered 2026-11-25 that they will file the feature request. The wasm binary does contain llguidance grammar keywords (`KwLLGuidance`, `KwLark`, `KwJson`) and Google's FST constraint library (string scan), so the capability is compiled in but not bound to JS. — [#4785](https://github.com/google-ai-edge/LiteRT-LM/issues/4785); [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz)
- **Cost of LiteRT-LM constrained decoding on web.** Measured with Gemma 4 E2B `-gpu`, `GPU_ARTISAN`, Edge 158 and an RX 7900 XT: "Creating a conversation takes about 950 ms every time, against about 1 ms without constraints". Tool-call decoding "runs at 53 tokens per second, against 118 without constraints". Google reproduced it (871–927 ms). — [#4784](https://github.com/google-ai-edge/LiteRT-LM/issues/4784)
- **LiteRT-LM concurrency.** The `Conversation` constructor takes shared `mutexes: {executor: Mutex}`, so conversations on one engine share a serialized executor (`.d.ts`). Native issue #4407 (closed 2026-11-04) reported "Every session switch deep-copies the outgoing session's KV cache (430 ms on Metal, 1.46 s on Adreno 840)". — [core-0.20.0.tgz](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz); [#4407](https://github.com/google-ai-edge/LiteRT-LM/issues/4407)
- **WebLLM features:**
  - The README says "fully compatible with OpenAI API … streaming, JSON-mode, function-calling (WIP)".
  - The engine exposes `chatCompletion` (streaming returns `AsyncIterable<ChatCompletionChunk>`), `interruptGenerate()`, `unload()`, `reload(modelId | modelId[])`, `resetChat()`, `tokenize()` and `forwardTokensAndSample()`.
  - `functionCallingModelIds` lists only Hermes-2-Pro-Llama-3-8B (×2), Hermes-2-Pro-Mistral-7B and Hermes-3-Llama-3.1-8B (×2).
  - `response_format` types include `grammar`, `json_schema` and `structural_tag`, through `@mlc-ai/web-xgrammar`.
  - — [web-llm-0.2.89.tgz](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz) (`README.md`, `lib/engine.d.ts`, `lib/types.d.ts`, `lib/index.js`)
- **WebLLM release history for these features:**
  - v0.2.81 (2026-02-18): "multi-model loading … concurrency handling … function calling and embeddings support".
  - v0.2.86: "crash-resumable generation".
  - v0.2.87: "Fix JSON schema generation for Qwen3.5".
  - v0.2.89: "Expose tokenization through the engine and worker APIs".
  - — [v0.2.81](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.81); [v0.2.86](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.86); [v0.2.87](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.87); [v0.2.89](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.89)
- **wllama features:**
  - v3.0 "replaces the custom wllama core with `server-context`, the inference component from `llama-server`". It offers "Full OAI-compatible API: `createChatCompletion`, `createCompletion`, `createEmbedding`", "Native tool calling support" and "Jinja-based chat template parsing (same as llama-server)".
  - Types expose `tool_choice` and `response_format: {type: 'text'|'json_object'|'json_schema', json_schema:{name, schema, strict}}`, `grammar`, `n_parallel` (one shared KV cache by default) and `abortSignal`.
  - v4 adds `saveSlotState()`/`restoreSlotState()`, LoRA, speculative decoding ("On WebGPU, DFlash, DSpark and MTP make generation about 1.2x faster"), video input and realtime audio.
  - — [intro-v3.md](https://github.com/ngxson/wllama/blob/master/guides/intro-v3.md); [wllama-4.0.0.tgz](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz) (`src/types/*.ts`, `src/wllama.ts`); [intro-v4.md](https://github.com/ngxson/wllama/blob/master/guides/intro-v4.md)
- **Transformers.js features:**
  - 4.2.0 (2026-04-22) added `tools` to `TextGenerationPipeline` ("pipe(messages, { tools, ... })"), passed into the chat template.
  - 4.1.0 added "Cached generation improvements (+ `past_key_values` via pipeline function)".
  - 4.3.0 added "experimental, dependency-free `@huggingface/transformers-structured-output`" (JSON schema, JSON object or regex; npm 4.3.2, 2026-10-27, 728 KB unpacked).
  - The 4.3.2 bundle contains `InterruptableStoppingCriteria` and no `tool_call` parsing code.
  - — [4.2.0](https://github.com/huggingface/transformers.js/releases/tag/4.2.0); [PR #1655](https://github.com/huggingface/transformers.js/pull/1655); [4.1.0](https://github.com/huggingface/transformers.js/releases/tag/4.1.0); [4.3.0](https://github.com/huggingface/transformers.js/releases/tag/4.3.0); [npm structured-output](https://registry.npmjs.org/@huggingface/transformers-structured-output); [transformers-4.3.2.tgz](https://registry.npmjs.org/@huggingface/transformers/-/transformers-4.3.2.tgz)
- **Long prompts on iOS need chunked prefill.** Issue #1836 (2026-10-29) asks for chunked prefill because "reading long prompts in one pass crashes iOS Safari". It quotes "WebKit arms a 3-second watchdog per committed command buffer", so "each forward pass has to finish well under 3 s". — [#1836](https://github.com/huggingface/transformers.js/issues/1836)
- **MediaPipe 0.10.30 API:**
  - `LlmInference.createFromOptions(wasmFileset, options)`.
  - `generateResponse(query, loraModel?, progressListener?)` and `generateResponses(...)` (multiple candidates).
  - `sizeInTokens()`, `cancelProcessing()`, `clearCancelSignals()`, `close()`.
  - No chat-message, tool or constraint API.
  - — [tasks-genai-0.10.30.tgz](https://registry.npmjs.org/@mediapipe/tasks-genai/-/tasks-genai-0.10.30.tgz) (`genai.d.ts`)

### Inferences
- **Engine choice by feature.** For an agent harness that wants the same JSON messages, tools and constrained decoding as native LiteRT-LM:
  - **LiteRT-LM JS** matches the message and tool shapes; tool `arguments` arrive as objects. It lacks JSON-schema constraints and `tool_choice` today.
  - **wllama** has every feature but fails the CSP.
  - **WebLLM** has constraints but no tool calling for Gemma, Qwen or Llama-3.2-class models.
  - **Transformers.js** needs the app to parse tool calls itself.
- **LiteRT-LM prefix reuse.** Use `prefillPrefaceOnInit` with a long system/tool preface, then `clone()` per turn or branch. This both reuses the KV cache and works around the cancel bug (section 4).
- **Concurrency.** Expect one active generation per engine in every engine (shared executor or GPU queue). Concurrent conversations interleave rather than run in parallel.

### Gaps
- No published browser context-length limits per device. Only model maxima (E2B web 128k; WebLLM prebuilt default 4096) and memory-driven crashes are documented.
- No accuracy data on LiteRT-LM's tool-syntax constrained decoding versus unconstrained decoding on web.
- No WebLLM or Transformers.js prefix-cache documentation was examined beyond the APIs named above.

## 4. Known web faults from issue trackers: GPU precision, memory leaks, Safari/iOS, device-loss recovery, very large models

### Takeaway
Every engine has open web-specific faults:
- **LiteRT-LM JS** (issues filed 2026-11-24/25 against 0.20.0 and reproduced by Google): cancel leaves the conversation unusable; a failed reply on a lost WebGPU device leaves `delete()`/`createConversation()` hanging and freezes the page; streaming swallows send errors; deleting a clone breaks the original.
- **iOS Safari** kills pages at about 2 GB of process memory and arms a 3-second GPU command-buffer watchdog. Google says Gemma 4 E2B "won't work on iOS" in LiteRT-LM.
- **WebLLM** has Adreno device-loss failures and recent regressions.
- **ORT Web's** documentation still says it cannot run models larger than 4 GB, contradicting Transformers.js claims. wllama v4 works around the 4 GB limit only with cross-origin isolation.

### Cited Findings
- **LiteRT-LM JS API faults** (all with `@litert-lm/core@0.20.0`, Gemma 4 E2B `-gpu`, Edge 158 and an RX 7900 XT):
  - #4783 (open): "After `conversation.cancel()`, the conversation can no longer be used. The next `sendMessage` on it rejects with `Task cancelled`". Google reproduced it, and suggested `clone()`. The reporter found a clone works only "when the clone is taken before the turn that gets canceled".
  - #4782 (open): after a reply fails on a lost device, "`engine.createConversation()`, `conversation.delete()` and `engine.delete()` each failed to return … `engine.delete()` … the page's thread itself is blocked … The only path I found that works is to leave the engine alone and reload the runtime". Google reproduced it on 2026-11-25.
  - #4779 (open): "`sendMessageStreaming()` returns a stream that closes normally with zero chunks" on a failed send.
  - #4810 (open, 2026-11-25): deleting a clone before the original sends again makes the original reject with "Dependency task N is invalid".
  - #4781 (open): `GPU_ARTISAN` `TOP_K` without `p` is greedy.
  - #4778 (open): `EmbeddingOptions.inputOverflowStrategy` is ignored.
  - — [#4783](https://github.com/google-ai-edge/LiteRT-LM/issues/4783); [#4782](https://github.com/google-ai-edge/LiteRT-LM/issues/4782); [#4779](https://github.com/google-ai-edge/LiteRT-LM/issues/4779); [#4810](https://github.com/google-ai-edge/LiteRT-LM/issues/4810); [#4781](https://github.com/google-ai-edge/LiteRT-LM/issues/4781); [#4778](https://github.com/google-ai-edge/LiteRT-LM/issues/4778)
- **LiteRT-LM GPU faults shared with the web path:**
  - #3866 (open, native WebGPU on Adreno 750): a 148 MiB embedding table bound as one storage buffer exceeds the 128 MiB device limit. "Dawn rejects the bind group and engine creation continues with no error", producing garbage.
  - #1881 (open): "WebGPU GPU backend segfaults on Pascal (GTX 1060) — FP16 shaders generated without capability check".
  - #3083 (open): the GPU backend "silently omits trailing generated content after a tag-like boundary".
  - FP16 digit corruption on iOS Metal and Adreno (#3913, #4001; native, from the earlier notes).
  - #3775 (open): web decode kernels are inefficient on M2 Max under Chrome 146.
  - — [#3866](https://github.com/google-ai-edge/LiteRT-LM/issues/3866); [#1881](https://github.com/google-ai-edge/LiteRT-LM/issues/1881); [#3083](https://github.com/google-ai-edge/LiteRT-LM/issues/3083); [#3913](https://github.com/google-ai-edge/LiteRT-LM/issues/3913); [#3775](https://github.com/google-ai-edge/LiteRT-LM/issues/3775)
- **LiteRT-LM on iOS and mobile:**
  - #2616 (closed 2026-07-06): the JSPI-only web runtime failed on iOS Safari; Asyncify builds shipped in 0.14.0.
  - #2368 (closed 2026-09-21): the Google collaborator was "able to run Gemma 4 E2B on our web demo on my Pixel 9 (although native performance is better)". Later: "Gemma 4 E2B requires around 4GB of free ram when running in the browser, and it won't work on iOS."
  - — [#2616](https://github.com/google-ai-edge/LiteRT-LM/issues/2616); [#2368](https://github.com/google-ai-edge/LiteRT-LM/issues/2368)
- **iOS Safari memory, with Transformers.js 4.3.2 / ORT WebGPU on an iPhone 16 Pro Max (iOS 26/27):**
  - #1827 (open, 2026-10-29): `memorystatus: com.apple.WebKit.WebContent … exceeded mem limit: ActiveHard 2048 MB (fatal)`. At the end of a 760 MB `.onnx_data` download, "Gigacage (JS ArrayBuffers) 1452 MB" is about 2× the file. A 2026-11-17 follow-up got LFM3 1.7B (1.09 GB of data) running by storing it in OPFS and not holding the external data twice.
  - #1835 (open): Asyncify builds leave some functions "over 1 MB. Safari's optimizing compiler spends seconds and hundreds of MB compiling them". It asks to use ORT's JSPI build, since "Safari 27 (macOS and iOS 27.2) and recent Chrome ship JSPI" (reporter's claim).
  - — [#1827](https://github.com/huggingface/transformers.js/issues/1827); [#1835](https://github.com/huggingface/transformers.js/issues/1835)
- **WebLLM on iOS.** #753 (closed 2026-03-23): iOS 26 Safari kills the tab after downloading Qwen2.5-3B, while SmolLM2-135M works. The collaborator cites a WebKit thread suggesting WebContent processes may be limited to about 1.5 GB ("couldn't find any official documentation"). — [#753](https://github.com/mlc-ai/web-llm/issues/753)
- **WebLLM device loss and regressions:**
  - #836 (open, 2026-06-21): "Engine Initialization Fails on Qualcomm Adreno GPUs with VK_ERROR_DEVICE_LOST" on Adreno 6xx and 810. The collaborator notes 0.2.79 works and 0.2.80+ fails; 0.2.80 moved CPU work in `llm_chat.ts` to GPU.
  - #844 (closed 2026-10-04): a 0.2.83 regression disposed in-use ShapeTuples, causing "Object has already been disposed" and then `DXGI_ERROR_DEVICE_HUNG`. "A page reload is not enough to recover — the browser has to be fully restarted". It was fixed in apache/tvm#20501.
  - #873 (closed 2026-10-30): `gemma3-1b-it-q4f16_1-MLC` could not load, and with `sliding_window_size: -1` it "answered with `H` on every line" (Pixel 8 Pro, Mali).
  - — [#836](https://github.com/mlc-ai/web-llm/issues/836); [#844](https://github.com/mlc-ai/web-llm/issues/844); [#873](https://github.com/mlc-ai/web-llm/issues/873)
- **Transformers.js / ORT faults:**
  - #1739 (open): "Whisper ASR pipeline leaks ~650 MB of GPU memory per 30 s chunk on WebGPU".
  - #1734 (closed): Chatterbox KV cache leak.
  - #1767 (closed): "createInferenceSession() memoises a rejected session promise, breaking every later session creation in the process".
  - #1801 (closed): `from_pretrained()` never settles when an `.onnx_data` download fails; fixed in 4.3.2.
  - #1518 (open, 17 comments): "Still crashing using WebGPU with translation pipeline".
  - #1599 (open): Qwen3.5-4B q4f16 is about 3× slower decode and about 20× slower TTFT than Qwen3-4B on WebGPU.
  - #1625 (open): request for resumable downloads and integrity verification.
  - — [#1739](https://github.com/huggingface/transformers.js/issues/1739); [#1767](https://github.com/huggingface/transformers.js/issues/1767); [#1801](https://github.com/huggingface/transformers.js/issues/1801); [#1518](https://github.com/huggingface/transformers.js/issues/1518); [#1599](https://github.com/huggingface/transformers.js/issues/1599); [#1625](https://github.com/huggingface/transformers.js/issues/1625)
- **ORT Web size limits** (large-models doc, undated, fetched 2026-11-25):
  - "The maximum size of a protobuf file is 2GB."
  - Chrome's maximum ArrayBuffer is "0x7fe00000 bytes (around 2GB)"; ORT "creates array buffers > 2GB by using new WebAssembly.Memory()", which "is not transferable" (incompatible with the proxy).
  - "WebAssembly has a memory limit of 4GB … Currently, there is no way for ONNX Runtime Web to run models larger than 4GB."
  - This conflicts with Transformers.js 4.0.0's GPT-OSS 20B q4f16 claim and its ">8B parameters" support.
  - — [ORT large models doc](https://onnxruntime.ai/docs/tutorials/web/large-models.html); [Transformers.js 4.0.0](https://github.com/huggingface/transformers.js/releases/tag/4.0.0)
- **Other engines and models above 4 GB:**
  - wllama v4: "A wasm instance cannot use more than 4GB of memory". Files of 4 GB or more become virtual shards, and layers that do not fit spill to RPC workers, which require cross-origin isolation.
  - LiteRT-LM streams model loading (v0.19.0) and publishes 15.8–19.2 GB web files (v0.15.0).
  - WebLLM shards weights into many files (94 for the 2.83 GB Gemma 4 E2B).
  - — [intro-v4.md](https://github.com/ngxson/wllama/blob/master/guides/intro-v4.md); [v0.19.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.0); [mlc-ai/gemma-4-E2B-it-q4f16_1-MLC](https://huggingface.co/mlc-ai/gemma-4-E2B-it-q4f16_1-MLC)
- **WebNN.** Transformers.js #1748 (open): Chrome 153 Canary renamed the WebNN device type (`'npu'`, not `'webnn-npu'`). A later comment says Transformers.js already maps it correctly. — [#1748](https://github.com/huggingface/transformers.js/issues/1748)

### Inferences
- **Device loss.** Treat the engine as disposable: run it in its own dedicated Worker and recover by `worker.terminate()` and respawn. No engine offers a reliable in-place recovery; LiteRT-LM #4782 shows in-place cleanup can freeze the thread.
- **iOS.** Assume no local LLM tier on iOS Safari for models above about 1 GB of weights. Use the remote TEE path there, or only sub-1 GB models streamed to OPFS and never buffered twice.
- **Cancel.** For LiteRT-LM, implement cancel as: cancel, drop the conversation, continue from a pre-turn `clone()` or re-prefill the history. Never reuse the canceled handle; this matches the native C API rule in the earlier notes.

### Gaps
- No systematic cross-GPU precision study for web engines was found. The reports are per-device issues.
- WebKit's per-process memory limit is not officially documented. The figures 1.5 GB (WebLLM thread) and 2048 MB ActiveHard (Transformers.js syslog) come from reporters.
- No ORT GitHub issues could be read (repo 404 on 2026-11-25), so ORT-level web faults may be under-represented.

## 5. Driving an engine from Go compiled to WASM (`syscall/js`), and mapping onto load / generate(stream) / cancel / unload

### Takeaway
Go code cannot call any of these engines directly as a library. They are ES-module JavaScript APIs built on Promises, ReadableStreams, async iterators and callbacks, wrapping their own separate wasm instances. The practical shape is a small JS adapter. It is bundled into a classic script and loaded with `importScripts` in the same (classic) Worker as `sidecar.wasm`, or in a sibling same-origin Worker. It exposes `load`/`generate`/`cancel`/`unload` and a chunk callback, which Go calls through `syscall/js` without ever blocking inside a `js.FuncOf` callback. All five engines map onto that interface. LiteRT-LM's cancel is destructive, so it maps as "cancel, then re-clone".

### Cited Findings
- **Go `syscall/js` rule.** `js.FuncOf` doc: "Invoking the wrapped Go function from JavaScript will pause the event loop and spawn a new goroutine … if one wrapped function blocks, JavaScript's event loop is blocked until that function returns. Hence, calling any async JavaScript API, which requires the event loop, like fetch (http.Client), will cause an immediate deadlock. Therefore a blocking function should explicitly start a new goroutine." — [pkg.go.dev syscall/js](https://pkg.go.dev/syscall/js)
- **All packages are ES modules:**
  - LiteRT-LM `dist/*.js` use `import … from '@litertjs/wasm-utils'`.
  - WebLLM ships `lib/index.js` (ESM).
  - Transformers.js ships `dist/transformers.web.js` (ESM).
  - wllama ships `esm/index.js` plus `esm/index.cjs`.
  - Their internal glue loads by `importScripts`/`<script>` (LiteRT-LM, MediaPipe) or by dynamic `import()` (ORT).
  - — tarballs: [LiteRT-LM](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz), [WebLLM](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz), [Transformers.js](https://registry.npmjs.org/@huggingface/transformers/-/transformers-4.3.2.tgz), [wllama](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz)
- **LiteRT-LM needs a classic Worker** in 0.20.0, because module workers fail (#4080; see section 1). — [#4080](https://github.com/google-ai-edge/LiteRT-LM/issues/4080)
- **API mapping (from each package's types):**

  | Interface step | LiteRT-LM JS | WebLLM | Transformers.js | wllama | MediaPipe |
  | :--- | :--- | :--- | :--- | :--- | :--- |
  | load | `loadLiteRtLm(wasmDir)` + `Engine.create({model: URL/Blob/ReadableStream, backend, mainExecutorSettings:{maxNumTokens}})` + `createConversation({preface})` | `CreateMLCEngine(id, {appConfig})` / `engine.reload(id)` | `pipeline('text-generation', id, {device:'webgpu', dtype})` | `new Wllama(pathConfig)` + `loadModelFromUrl()` | `FilesetResolver` + `LlmInference.createFromOptions()` |
  | generate (stream) | `sendMessageStreaming(msg)` → `ReadableStream<Message>` | `chatCompletion({messages, stream:true, tools, response_format})` → `AsyncIterable` | `generator(messages, {streamer})` (TextStreamer callback) | `createChatCompletion({stream:true, abortSignal})` → async iterator | `generateResponse(prompt, listener)` |
  | cancel | `conversation.cancel()` (conversation then unusable, #4783) | `interruptGenerate()` | `InterruptableStoppingCriteria` | `AbortController.abort()` | `cancelProcessing()` |
  | unload | `conversation.delete()`, `engine.delete()`, `unloadLiteRtLm()` | `unload()` | `pipe.dispose()` | `exit()` | `close()` |

  — [LiteRT-LM .d.ts](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz); [WebLLM engine.d.ts](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz); [Transformers.js `_base.d.ts` `dispose()`](https://registry.npmjs.org/@huggingface/transformers/-/transformers-4.3.2.tgz); [wllama src/wllama.ts](https://registry.npmjs.org/@wllama/wllama/-/wllama-4.0.0.tgz); [MediaPipe genai.d.ts](https://registry.npmjs.org/@mediapipe/tasks-genai/-/tasks-genai-0.10.30.tgz)
- **LiteRT-LM model input.** It accepts "a URL, a `hf://` URI, a `ModelSource`, or the model's data" (Blob/File/ReadableStream). Issues show `fetch('/gemma-4-E2B-it-gpu.litertlm').body` passed directly as the model. — [core-0.20.0.tgz `engine_settings.d.ts`](https://registry.npmjs.org/@litert-lm/core/-/core-0.20.0.tgz); [#4810](https://github.com/google-ai-edge/LiteRT-LM/issues/4810)

### Inferences
- **Suggested adapter contract** (`globalThis.sidecarLLM`):
  - `load(spec) → Promise<handle>`
  - `generate(handle, messagesJSON, optsJSON, onChunk(jsonString), onDone(err)) → requestId`
  - `cancel(requestId)`
  - `unload(handle) → Promise`
- **Go side of the adapter:**
  - Go passes and receives JSON strings, so no Go↔JS object marshalling is needed.
  - Go calls `load` and `generate` from a goroutine and waits on a channel that the `then`/`onChunk` callbacks fill.
  - The callbacks only copy the string and send it non-blockingly.
- **Keep model bytes out of Go.** The adapter fetches or streams the model from OPFS/Cache or same-origin URLs directly into the engine. Copying multi-GB weights through `js.CopyBytesToGo` would double memory, which is exactly the iOS failure mode in #1827.
- **Sibling Worker over shared Worker.** A sibling dedicated Worker (same-origin URL, allowed by `script-src 'self'`) is the more robust placement. Engine crashes, wasm OOM and device-loss hangs (#4782) can then be cleared with `terminate()` without killing the Go runtime. The cost is one extra `postMessage` hop per chunk.

### Gaps
- No engine publishes a Go binding or example. Whether nested dedicated Workers (a Worker spawning a Worker) behave identically on Safari, Firefox and Chrome for WebGPU was not checked.
- Whether LiteRT-LM's dist bundles cleanly into an IIFE for `importScripts` (bundler compatibility) was not tested.

## 6. Small models: Prompt Guard 2 (22M/86M) and small embedders in the browser via Transformers.js / ORT Web or LiteRT

### Takeaway
Prompt Guard 2 can run in-browser on Transformers.js/ORT Web:
- Transformers.js 4.3.2 includes `DebertaV2ForSequenceClassification`, and community ONNX exports exist.
- 22M: int8 72 MB (fp32 284 MB). 86M: int8 281–317 MB (fp32 1.1 GB).
- Context is 512 tokens. The license is the Llama 4 Community License (gated upstream).
- No LiteRT/LiteRT-LM conversions were found, and no published browser latencies.

For embedders, EmbeddingGemma 2 (Apache-2.0) is available both as ONNX for Transformers.js (text q4f16 156 MB) and as LiteRT-LM `.litertlm` (164 MB). For tiny encoders, the WASM backend can beat WebGPU.

### Cited Findings
- **Prompt Guard 2 model card:**
  - "Both Llama Prompt Guard 2 models support a 512-token context window. For longer inputs, split prompts into segments and scan them in parallel".
  - The 86M model is based on mDeBERTa-base; the 22M model on DeBERTa-xsmall, which "reduces latency and compute costs by 75%".
  - Latency per classification (A100 GPU, 512 tokens): 92.4 ms (86M), 19.3 ms (22M).
  - AUC (English) .998 / .995; Recall @1% FPR 97.5% / 88.7%.
  - "There is no version of deberta-xsmall with multilingual pretraining", so 22M is weaker on multilingual input.
  - — [PurpleLlama Prompt Guard 2 86M model card](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md); [22M model card](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/22M/MODEL_CARD.md)
- **Upstream repos** (HF API, 2026-11-25): `meta-llama/Llama-Prompt-Guard-2-22M` (283 MB safetensors) and `-86M` (1,115 MB) are `license:other` with a manual gate. — [HF search](https://huggingface.co/models?search=Prompt-Guard-2)
- **ONNX conversions** (HF tree API, 2026-11-25):
  - `gravitee-io/Llama-Prompt-Guard-2-22M-onnx`: `model.onnx` 284 MB, `model.quant.onnx` 72 MB; license tag llama4; updated 2026-05-07. Its card reports quantized accuracy 0.9579 vs 0.9564 (jackhhao/jailbreak-classification).
  - `gravitee-io/Llama-Prompt-Guard-2-86M-onnx`: 1,116 MB fp32, 281 MB quantized.
  - `sinatras/Llama-Prompt-Guard-2-86M-ONNX` (tagged `transformers.js`, `deberta-v2`; 2025-05-27, possibly superseded): int8/uint8/quantized 317 MB, fp16 576 MB, q4f16 454 MB, q4 865 MB, fp32 1,152 MB.
  - — [gravitee-io 22M](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-22M-onnx); [gravitee-io 86M](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-86M-onnx); [sinatras 86M](https://huggingface.co/sinatras/Llama-Prompt-Guard-2-86M-ONNX)
- **Transformers.js support.** The 4.3.2 bundle includes the `deberta-v2` architecture and `DebertaV2ForSequenceClassification`. — [transformers-4.3.2.tgz](https://registry.npmjs.org/@huggingface/transformers/-/transformers-4.3.2.tgz)
- **Embedders** (HF tree API, 2026-11-25):
  - `onnx-community/embeddinggemma-2-ONNX` (apache-2.0, 2026-10-06): text model q4f16 156 MB, q4 174 MB, fp16 542 MB; the audio encoder is separate.
  - `onnx-community/embeddinggemma-300m-ONNX` (license gemma): q4f16 175 MB, q4 196 MB, quantized 308 MB, fp16 617 MB.
  - `Xenova/all-MiniLM-L6-v2`: int8 22 MB, fp16 45 MB, fp32 90 MB.
  - `onnx-community/Qwen3-Embedding-0.6B-ONNX`: q4f16 0.56 GB.
  - `litert-community/embeddinggemma-2-text-270m-litert-lm` (apache-2.0): 164 MB.
  - — [embeddinggemma-2-ONNX](https://huggingface.co/onnx-community/embeddinggemma-2-ONNX); [embeddinggemma-300m-ONNX](https://huggingface.co/onnx-community/embeddinggemma-300m-ONNX); [all-MiniLM-L6-v2](https://huggingface.co/Xenova/all-MiniLM-L6-v2); [Qwen3-Embedding-0.6B-ONNX](https://huggingface.co/onnx-community/Qwen3-Embedding-0.6B-ONNX); [embeddinggemma-2-text-270m-litert-lm](https://huggingface.co/litert-community/embeddinggemma-2-text-270m-litert-lm)
- **Transformers.js embedder speedups.** 4.3.1 (2026-10-07) added EmbeddingGemma 2 through the `feature-extraction` pipeline (`device: "webgpu"` or `"wasm"`). 4.0.0 says adopting `com.microsoft.MultiHeadAttention` gave "a ~4x speedup for BERT-based embedding models". — [4.3.1](https://github.com/huggingface/transformers.js/releases/tag/4.3.1); [4.0.0](https://github.com/huggingface/transformers.js/releases/tag/4.0.0)
- **LiteRT-LM CPU embedding latency in the browser** (#4786, 2026-11-24): `embeddinggemma-2-text-270m`, one 440-token text, Chromium 159, 8-core Linux, `Backend.CPU`. It took 3.4–5.2 s per embedding, and thread count made no difference because the build is single-threaded. — [#4786](https://github.com/google-ai-edge/LiteRT-LM/issues/4786)
- **WASM vs WebGPU for a tiny embedder** (third-party, single run, one unnamed device): `Xenova/all-MiniLM-L6-v2` on Transformers.js took 9,470 ms to initialise and 183 ms to embed on WASM, versus 33,583 ms and 1,765 ms on WebGPU ("~3.5× faster to init and ~9.6× faster to embed"). — [webai-bench SP3 findings](https://github.com/Sallamhamza/webai-bench/blob/main/docs/spikes/sp3-findings.md); [transformers.js#1750](https://github.com/huggingface/transformers.js/issues/1750)
- **LiteRT.js "Web Classical Models".** The collection lists whisper-tiny/base, moonshine-tiny, Gecko-110m-en, embeddinggemma-300m, efficientdet, segmentation models and others. No prompt-injection classifier is listed. — [HF collection](https://huggingface.co/collections/litert-community/web-classical-models-6a1fc1ba70a35860474350ad)

### Inferences
- **Prompt Guard 2 placement.** Prompt Guard 2 22M int8 (72 MB) on the ORT **WASM** EP (single-threaded, no COI) is the cheapest in-browser injection filter. The 86M int8 (about 280–320 MB) is the multilingual option.
- **Size is mostly the embedding table.** The 22M model's 283 MB fp32 size implies about 70M total parameters (283 MB ÷ 4 bytes), so most weight is the vocabulary embedding table. This is arithmetic from the safetensors size.
- **Latency is unmeasured.** Browser latency on WASM for 512-token inputs should be measured. As an expectation only, extrapolating from A100 latencies and the MiniLM WASM data point, it is likely tens to hundreds of ms per segment on laptops.
- **One runtime for classifier and embedder.** Using Transformers.js for both the classifier and the embedder gives one runtime for small models. If LiteRT-LM is chosen for the LLM, EmbeddingGemma 2 can share that runtime instead. Its single-threaded CPU path is slow (3–5 s per 440 tokens), so use its GPU backend.

### Gaps
- No published in-browser latency for Prompt Guard 2 (22M or 86M) on any engine.
- No LiteRT/TFLite conversion of Prompt Guard 2 found.
- The quantized-accuracy impact on Meta's own benchmarks is not published for the community ONNX conversions.
- Whether ORT WebGPU runs DeBERTa-v2 disentangled-attention ops without falling back to CPU was not verified.

## 7. Production use and case studies: who ships in-browser LLM inference to real users, and what they report learning

### Takeaway
The largest real-user deployments of on-device inference "in the browser" are browser built-ins, not page-embedded engines:
- **Chrome's Prompt API** (Gemini Nano). LiteRT-LM says it "powers on-device GenAI experiences in Chrome".
- **Firefox's ML runtime.** Mozilla moved from WASM to native backends: native ONNX, then llama.cpp/parakeet.cpp in a sandboxed `HWInference` process, citing speed.

Page-embedded engines are mostly demos and developer apps (WebLLM Chat, HF Spaces, Google's LiteRT-LM web demo). No vendor publishes user metrics. The practical lessons come from engineers' bug reports: memory limits, iOS, device loss and WASM-vs-WebGPU crossovers.

### Cited Findings
- **Chrome Prompt API** (page "last updated October 21, 2026"):
  - It shipped "in Chrome 148 on the web and Chrome 138 for extensions".
  - Supported OS: Windows 10/11, macOS 13+, Linux and Chromebook Plus. Android and iOS are unsupported.
  - Requirements: "At least 22 GB free" storage; GPU with "Strictly more than 4 GB of VRAM", or CPU with 16 GB RAM and 4+ cores.
  - It "isn't available in Web Workers for now". Cross-origin iframes need `allow="language-model"`.
  - It supports `responseConstraint` JSON Schema, `clone()`, and image and audio input.
  - — [Chrome Prompt API docs](https://developer.chrome.com/docs/ai/prompt-api)
- **LiteRT-LM in Google products.** The README says LiteRT-LM "powers on-device GenAI experiences in **Chrome**, **Chromebook Plus**, **Pixel Watch**" (native, per the earlier notes). Google hosts a LiteRT-LM web chat demo at `google-ai-edge.github.io/LiteRT-LM/web_demos/chat/`, cited by a collaborator in #2368 (2026-07-01). The E2B card links a Hugging Face Space web demo. — [LiteRT-LM README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md); [#2368](https://github.com/google-ai-edge/LiteRT-LM/issues/2368); [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- **Firefox ML architecture** (undated docs, fetched 2026-11-25):
  - The inference process hosts `MLEngineChild` and the backends. It is isolated because "they can be quite performance and memory hungry", and on Android "the OS may choose to kill a process that is consuming too many resources".
  - Backends: onnx (wasm, Transformers.js + onnxruntime-web in DOM Workers), onnx-native (prebuilt shared library), llama.cpp (vendored, compiled in-tree), openai (remote) and static-embeddings.
  - Wasm runtime binaries come via Remote Settings metadata ("the CDN URL, filename, hash, and size"). They are hash-checked and cached in OPFS, and ship outside the main package "to reduce the size of the initial download".
  - Models come from `ModelHub` (OPFS plus IndexedDB metadata). Allowed hubs include model-hub.mozilla.org, huggingface.co/Mozilla and huggingface.co/Xenova.
  - — [Firefox ML architecture](https://firefox-source-docs.mozilla.org/toolkit/components/ml/architecture.html)
- **Firefox HWInference** (undated docs, fetched 2026-11-25): a utility process that "runs native, hardware-accelerated inference libraries (`parakeet.cpp` and `llama.cpp`, backed by `libggml`)".
  - It has its own sandbox kind, `HW_INFERENCE`.
  - Content processes "can only request a task-specific identifier … cannot name a model file", and model files pass by file descriptor (mmap).
  - ONNX Runtime "is expected to follow".
  - Browser text generation uses llama.cpp when `browser.ml.llama.hwInference` is enabled.
  - — [HWInference](https://firefox-source-docs.mozilla.org/toolkit/components/ml/HWInference.html)
- **Mozilla retrospective** (Tarek Ziadé, Mozilla engineer, personal blog, 2025-12-05, possibly superseded):
  - PDF.js alt text shipped in Firefox 130: a ViT encoder with a distilled GPT-2 decoder, about 180M parameters, "under 200MB", that "runs in a couple of seconds on a laptop".
  - Smart Tabs shipped in Firefox 141.
  - Moving "from WebAssembly to a pure C++ ONNX runtime under Transformers.js" brought "significantly better performance".
  - Stated lessons: data quality beats model size, reusable infrastructure, process over models, start small with privacy as a requirement.
  - WebNN is listed as future work.
  - — [Two Years of Building AI in Firefox](https://blog.ziade.org/2025/12/05/two-years-of-ai-at-mozilla/)
- **Secondary press on Firefox (2025-08, possibly superseded).** Firefox's on-device features became "up to 10x faster" after moving from WASM to a native backend. A secondary report cites PDF alt-text latency dropping from 3.5 s to 350 ms. These are secondary sources. — [OMG! Ubuntu, 2025-08](https://www.omgubuntu.co.uk/2025/08/firefoxs-on-device-ai-features-are-now-up-to-10x-faster); [letsdatascience summary](https://letsdatascience.com/news/firefox-integrates-on-device-ai-runtime-for-features-1555091e)
- **Mozilla tab-grouping write-up.** Mozilla describes running tab-group suggestions locally with a small model. — [Mozilla blog: How Firefox suggests tab groups with local AI](https://blog.mozilla.org/en/firefox/ai-tab-groups/)
- **Llamas on the Web** (arXiv 2605.20706, 2026-05-20; Levine, Sorensen et al.): a WebGPU backend for llama.cpp, "evaluate[d] … on 16 devices from 8 vendors". It "requires 29-33% less memory" than "existing browser-based LLM frameworks" and "increases decode throughput by 45-69% across four GPUs from separate vendors". The abstract does not name the baselines. — [arXiv 2605.20706](https://arxiv.org/abs/2605.20706)
- **Hugging Face and MLC deployments:**
  - Transformers.js v4 launched with a "Demo Collection" (webml-community).
  - The WebLLM README shows "WebLLM Chat — Deployed" at chat.webllm.ai.
  - WebLLM shipped a Chrome-extension example and service-worker fixes (v0.2.85: "Register service-worker handlers during startup so restarted workers can receive requests").
  - — [Transformers.js 4.0.0](https://github.com/huggingface/transformers.js/releases/tag/4.0.0); [web-llm-0.2.89 README](https://registry.npmjs.org/@mlc-ai/web-llm/-/web-llm-0.2.89.tgz); [v0.2.85](https://github.com/mlc-ai/web-llm/releases/tag/v0.2.85)
- **Third-party engineering reports:**
  - iPhone deployments needed OPFS storage, no double-buffering of weights, and prefill chunks under 3 s ([transformers.js#1827](https://github.com/huggingface/transformers.js/issues/1827), [#1836](https://github.com/huggingface/transformers.js/issues/1836)).
  - A strict-CSP deployment self-hosted ORT and enforced CSP in CI with headless Chrome ([QSMPC#70](https://github.com/Quantum-Daemons/QSMPC-QKD-QHE-AI-Hybrid/issues/70)).
  - A benchmark found WASM beating WebGPU for tiny models ([webai-bench SP3](https://github.com/Sallamhamza/webai-bench/blob/main/docs/spikes/sp3-findings.md)).
- **Published web speeds:**
  - LiteRT-LM Gemma 4 E2B on M4 Max WebGPU: prefill 4,853 tok/s, decode 73 tok/s, TTFT 1.09 s, about 1,800 MB GPU memory ([HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)).
  - The same model on an RX 7900 XT / Edge 158 decodes at 118 tok/s unconstrained ([#4784](https://github.com/google-ai-edge/LiteRT-LM/issues/4784)).
  - wllama v4 CPU on Chrome (6 threads, Apple M5-series): LFM2.5-1.2B Q4_K_M prompt 207 t/s, generation 118 t/s ([intro-v4.md](https://github.com/ngxson/wllama/blob/master/guides/intro-v4.md)).

### Inferences
- **The browser vendors' own lesson.** Both vendors with the most users moved inference out of page-level WASM: Mozilla went to native ONNX and llama.cpp in a sandboxed process, and Chrome uses a built-in native model. Page-embedded engines are viable mainly on WebGPU desktops with at least 4 GB free memory.
- **Chrome's Prompt API is no shortcut here.** It cannot run in the sidecar's Worker, and in the cross-origin ur.io → sidecar.ur.io iframe it would also need `allow="language-model"` on the iframe. It is also Chrome-only and gives a different model (Gemini Nano) from native Gemma 4.
- **Lessons a design can adopt directly:**
  - Distribute runtime binaries separately from the app, with hash pinning (Firefox Remote Settings pattern).
  - Store models in OPFS, and stream them to the engine without copies.
  - Run the engine in an isolated, killable context.
  - Gate by device capability, with a remote fallback.

### Gaps
- No public production case study of an app-embedded web LLM with real user counts or failure-rate metrics was found, whether from Google, Hugging Face, MLC or a third party.
- No Mozilla 2026 primary blog post on the move to llama.cpp/HWInference was found. The HWInference page is undated.
- Which Chrome or Google product features (beyond the Prompt API) use LiteRT-LM's JS/WASM path specifically, rather than native, is not stated by Google.
