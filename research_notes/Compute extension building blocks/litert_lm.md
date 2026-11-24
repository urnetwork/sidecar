# LiteRT-LM as the local on-device inference engine for a Go program (CLI, gomobile iOS/Android, browser extension)

Snapshot conventions: "today" = 2026-11-23. Repo facts come from a shallow clone of `main` at commit `097bd757` (committed 2026-11-22) and from the GitHub releases API, both read 2026-11-23. Latest tagged release = **v0.19.1 (2026-11-05)**; `main` declares the next version `0.20.0` and C API `1.1.0`. Web pages fetched 2026-11-23; most Google doc pages carry no "last updated" date, so a page's date is "undated (fetched 2026-11-23)" unless stated. Anything from 2025 is marked possibly superseded.

## 1. Platforms and support status (Android, iOS, macOS, Linux, Windows, Web, Raspberry Pi/embedded)

### Takeaway
As of November 2026, LiteRT-LM runs on CPU on Android, iOS, macOS, Windows, Linux and IoT boards (Raspberry Pi), and on GPU everywhere except IoT. NPU is supported on Android, in preview on Windows (Intel), and available in narrower forms on Linux (Qualcomm IQ-series, Intel). Kotlin, C++, Python and the CLI are labeled stable. Swift (iOS/macOS) and JavaScript (web, WASM + WebGPU) are labeled "Early Preview". There are no prebuilt binaries for Windows ARM64 and no Intel-Mac build of the C library.

### Cited Findings
- Official platform matrix (overview page, undated, fetched 2026-11-23). CPU: ✅ Android, iOS, macOS, Windows, Linux, IoT. GPU: ✅ Android, iOS, macOS, Windows, Linux; "-" for IoT. NPU: ✅ Android, 🚀 Windows, "-" for iOS, macOS, Linux. The matrix has no legend for 🚀; on the same page 🚀 means "Early Preview" in the language table. Web is not a column. — [LiteRT-LM overview](https://developers.google.com/edge/litert-lm/overview)
- Language API status (README on `main`, 2026-11-22, matching the overview page): Python ✅ Stable; Kotlin ✅ Stable ("Android apps & JVM"); **Swift 🚀 Early Preview** ("Native iOS & macOS"); **JavaScript (web) 🚀 Early Preview**; Flutter 🚀 Community (the community package [flutter_gemma](https://github.com/DenisovAV/flutter_gemma)); C++ ✅ Stable. The overview page also lists the CLI as ✅ Stable. — [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md); [overview](https://developers.google.com/edge/litert-lm/overview)
- README key features: "Cross-Platform Support: Android, iOS, Web, Desktop, and IoT (e.g. Raspberry Pi)". It says LiteRT-LM "powers on-device GenAI experiences in **Chrome**, **Chromebook Plus**, **Pixel Watch**, and more." — [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md)
- Platform milestones from the release notes:
  - v0.6.0 (2025-06-10): first prebuilt binaries.
  - v0.8.0 (2025-11-25): desktop GPU support, Kotlin API for Android and JVM (Linux, macOS, Windows).
  - v0.11.0 (2026-05-07): "Windows Native Support: The LiteRT-LM CLI now runs natively on Windows with both CPU and GPU". In v0.10.1 (2026-04-03) Windows still meant WSL.
  - v0.12.0 (2026-05-18): Swift APIs with Metal GPU; Web JavaScript APIs ("web GPU/CPU"); CLI NPU support "across Linux, macOS, and Windows", including Intel OpenVINO NPU via `--backend=npu`.
  - v0.13.0 (2026-06-02): the Swift package supports macOS as well as iOS.
  - v0.14.0 (2026-07-08): the CLI and Python API run directly on Android (aarch64 and x86_64), for example in Termux.
  - — [GitHub releases](https://github.com/google-ai-edge/LiteRT-LM/releases)
- Swift package minimums: `platforms: [.iOS(.v15), .macOS(.v12)]`. Binary targets: `CLiteRTLM.xcframework.zip` (iOS) and `CLiteRTLM_mac.xcframework.zip` (macOS), both pinned to v0.19.1. — [Package.swift](https://github.com/google-ai-edge/LiteRT-LM/blob/main/Package.swift)
- Prebuilt platform folders in the repo: `android_arm64`, `android_x86_64`, `ios_arm64`, `ios_sim_arm64`, `linux_arm64`, `linux_x86_64`, `macos_arm64`, `windows_x86_64`. There is **no `macos_x86_64` and no `windows_arm64`**. — [prebuilt/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/prebuilt)
- Windows ARM64 is unsupported. Open requests: #1192 (2026-01-08), #2612 (2026-06-19, Snapdragon), #3713 (2026-09-23), #4459 (2026-11-08). — [#1192](https://github.com/google-ai-edge/LiteRT-LM/issues/1192), [#2612](https://github.com/google-ai-edge/LiteRT-LM/issues/2612), [#3713](https://github.com/google-ai-edge/LiteRT-LM/issues/3713), [#4459](https://github.com/google-ai-edge/LiteRT-LM/issues/4459)
- Intel Macs: the macOS xcframework in v0.19.1 contains `CLiteRTLM_mac.xcframework/macos-arm64_x86_64/libCLiteRTLM_mac.dylib` (143 MB). The folder name follows the xcframework convention for a universal arm64+x86_64 slice. The C API zip, however, ships only `macos_arm64`. — [CLiteRTLM_mac.xcframework.zip v0.19.1](https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/CLiteRTLM_mac.xcframework.zip); [litert_lm_c_api-1.0.0.zip](https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/litert_lm_c_api-1.0.0.zip)
- Web: npm package `@litert-lm/core` (`package.json` version 0.12.1, Apache-2.0). Models load from a URL, an `hf://` URI (SHA-256 checked), a `Blob`/`File`, or a `ReadableStream<Uint8Array>`. Self-hosted WASM loads via `loadLiteRtLm('/path/to/wasm/directory/')`. The JS guide does not document browser version, WebGPU, SharedArrayBuffer or worker requirements. — [JS guide](https://developers.google.com/edge/litert-lm/js); [js/packages/core/package.json](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/package.json)
- v0.19.0 (2026-11-02): "@litert-lm/core now stream-loads all models, defaults to the GPU backend, and supports image and audio inputs." v0.15.0 (2026-08-04): Gemma 4 12B, 26B A4B and 31B "officially supported on web". — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases)
- May 19, 2026 blog: the JS API runs via WASM and is "Powered by WebGPU". At that date NPU was available on Android only. — [Blazing-fast on-device GenAI with LiteRT-LM](https://developers.googleblog.com/blazing-fast-on-device-genai-with-litert-lm/)
- IoT/embedded: benchmarks are published for Raspberry Pi 5 16GB (CPU), Jetson Orin Nano (CPU/GPU) and Qualcomm Dragonwing IQ8 (IQ-8275, NPU). A Qualcomm QCS8275 NPU build of Gemma 4 E2B exists for the Arduino "Ventuno Q" board on Ubuntu 24.04 ARM64. — [HF gemma-4-E2B-it-litert-lm model card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- The iOS Simulator is broken: on arm64, CPU inference fails INTERNAL and GPU reports "Failed to create engine" (issue #2504, open since 2026-06-08). — [#2504](https://github.com/google-ai-edge/LiteRT-LM/issues/2504)
- Docs conflict: a Google LiteRT-LM landing page ("Last updated 2026-10-06 UTC") still says iOS Swift with "macOS coming soon", although the Swift package has supported macOS since v0.13.0 (2026-06-02). — [developers.google.com landing page](https://developers.google.com/edge/mediapipe/solutions/genai/llm_inference); [v0.13.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.13.0)

### Inferences
- For the four desktop targets, macOS arm64, Linux x86_64/arm64 and Windows x86_64 are covered with prebuilt binaries. Windows ARM64 (Copilot+ PCs) and Intel Macs need a fallback. An Intel Mac could perhaps use the universal `libCLiteRTLM_mac.dylib` from the Swift xcframework, but that is unverified and not a documented C distribution.
- "Stable" applies to Kotlin, C++, Python and the CLI only. The Swift (iOS) and JS (browser) surfaces, the two that matter for the iOS app and the extension, are still preview and change quickly.

### Gaps
- No official minimum OS for Android (minSdk) appeared in the files read. The Kotlin README gives Maven coordinates but no minSdk line.
- Browser/WebGPU version requirements and behavior in workers or extensions are not documented by LiteRT-LM.
- The meaning of the Windows NPU "🚀" (preview vs. production) is not defined on the page.

## 2. APIs and bindings, and how a Go program would call it (C API, cgo/purego, gomobile, static link, CLI/server)

### Takeaway
There is now a **versioned, plain-C API** (`c/engine.h`, `c/conversation.h` and others; C API **1.0.0** shipped with v0.19.x, `main` is at 1.1.0). Prebuilt shared libraries exist for Android, macOS arm64, Linux and Windows x64; iOS gets a **dynamic** xcframework. The C API takes OpenAI-style JSON for messages and tools and streams through a C callback, so Go can bind it with cgo or with dlopen/purego. Google publishes no Go binding, and the tracker mentions none. Static single-binary linking is impractical: the prebuilts are shared libraries only, source builds are Bazel-first (the CMake path is verified only for gcc on Ubuntu), and GPU accelerator plugins are closed, dynamically loaded binaries. The CLI's `litert-lm serve` provides an OpenAI-compatible HTTP server, but it is a Python program.

### Cited Findings
- C API versioning: it "is versioned independently of the LiteRT LM release, following semantic versioning". Header macros are `LITERT_LM_C_API_VERSION_MAJOR 1 / MINOR 1 / PATCH 0` on `main`. Runtime check: `LiteRtLmStatusCode litert_lm_get_api_version(int* out_major, int* out_minor, int* out_patch)`. The header recommends refusing to proceed if the major differs or the minor is older, and says libraries older than 1.0.0 do not export it, "so a caller that loads the library dynamically and cannot resolve this symbol should treat the library as incompatible." — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h); [version.bzl](https://github.com/google-ai-edge/LiteRT-LM/blob/main/version.bzl) (`VERSION = "0.20.0"`, `C_API_VERSION = "1.1.0"`, `LITERT_VERSION = "2.4.0"`)
- C API 1.0.0 is a breaking change (v0.19.0, 2026-11-02; zip attached to v0.19.1, 2026-11-05): "Functions that can fail now return LiteRtLmStatusCode with results in out_* parameters, and only litert_lm_* symbols are exported." The first versioned C API prebuilts (`litert_lm_c_api-0.1.0.zip`) shipped in v0.16.0 (2026-08-11) "for all supported platforms… creating language bindings without the hassle of building shared libraries." — [v0.19.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.0), [v0.19.1](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.1), [v0.16.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.16.0)
- C API surface (exported names in `c/engine.h` on `main`):
  - Engine: `litert_lm_engine_settings_create(model_path, backend_str ("cpu","gpu",…), vision_backend_str, audio_backend_str, &out)`, `litert_lm_engine_settings_create_from_raw_file_descriptor`, `litert_lm_engine_create`, `litert_lm_engine_create_session`, `litert_lm_engine_tokenize`/`_detokenize`.
  - Engine settings: `…_set_max_num_tokens`, `…_set_num_threads`, `…_set_cache_dir`, `…_set_litert_dispatch_lib_dir` (NPU), `…_set_enable_speculative_decoding`, `…_set_lora_rank`, `…_set_supported_lora_ranks`, `…_set_activation_data_type` (Float32/Float16/Int16/Int8), `…_set_gpu_enable_metal_residency_set`, `…_set_enable_ynnpack`, `…_set_use_ringbuffers_local_attention`, `…_set_parallel_file_section_loading`.
  - Session: `litert_lm_session_generate_content`, `litert_lm_session_generate_content_stream`, `…_run_prefill`, `…_run_decode`, `…_run_decode_async`, `…_run_text_scoring`, `…_save_checkpoint`, `…_rewind_to_checkpoint`, `…_rewind_to_step`, `…_clone`, `…_cancel_process`, `…_get_benchmark_info`.
  - Sampling: `litert_lm_sampler_params_set_{temperature,top_k,top_p,seed}`.
  - — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
- Conversation C API: `litert_lm_conversation_config_set_tools(config, const char* tools_json)` ("tools description in JSON array format"), `…_set_system_message(json)`, `…_set_messages(json)`, `…_set_prompt_template`, `…_set_enable_constrained_decoding`, `…_set_constraint_provider`, `…_set_stream_tool_calls`, `…_set_thinking_config`, `…_set_filter_channel_content_from_kv_cache`. Per call: `litert_lm_conversation_send_message`, `litert_lm_conversation_send_message_stream`, `…_optional_args_set_{constraint,tool_choice,max_output_tokens,repetition_penalty_config,no_repeat_ngram_config,suppress_tokens_config,thinking_config,visual_token_budget}`. Also `litert_lm_conversation_cancel_process`, `…_clone`, `…_get_token_count`, `…_wait_until_done`, `…_render_message_to_string`. Stream chunks expose `…_get_text`, `…_is_final`, `…_get_error`, `…_get_finish_reason`, `…_get_executor_stats_json`. — [c/conversation.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/conversation.h)
- Threading model, quoted from the header ("current behavior… not a commitment"):
  - "Handles are not thread-safe: calls that use the same handle MUST NOT overlap."
  - "Stream callbacks can run on library-owned threads that are shared by all streams of an engine, so a callback should return quickly."
  - A callback "MUST NOT call LiteRT LM functions on the engine that runs the stream… with one exception: … it may stop the stream with `litert_lm_session_cancel_process` or `litert_lm_conversation_cancel_process`."
  - "After … cancel_process, the session or conversation MUST NOT be reused; only delete it."
  - The last error is thread-local.
  - Callback type: `typedef void (*LiteRtLmStreamCallback)(void* callback_data, …)`.
  - — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
- Exports: `LITERT_LM_C_API_EXPORT` defaults to `__declspec(dllexport)` on Windows or `visibility("default")`. Clients may override it "with `__declspec(dllimport)` when consuming the Windows .dll, or with an empty definition when linking against the API statically." — [c/api_export.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/api_export.h)
- Other C headers on `main`:
  - `embedding_engine.h`, `model_info.h`, `experimental.h` and `error_reporter.h` ship in the 1.0.0 zip.
  - `decision_engine.h` is EXPERIMENTAL. It answers yes/no, choice and score questions with calibrated probabilities from next-token probabilities, "follow[ing] the concepts of the Gemini Decisions API".
  - `model_sync.h` is "Added in version 1.1.0", so not yet in a release. It is a range-fetcher-based model synchronization API.
  - — [c/decision_engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/decision_engine.h); [c/model_sync.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/model_sync.h)
- **Prebuilt C API zip contents** (`litert_lm_c_api-1.0.0.zip`, 123.5 MB compressed, attached to v0.19.1; uncompressed sizes):
  - `lib/android_arm64/liblitert-lm.so` 22.8 MB
  - `lib/android_x86_64/liblitert-lm.so` 26.9 MB
  - `lib/macos_arm64/liblitert-lm.dylib` 51.0 MB
  - `lib/linux_x86_64/liblitert-lm.so` 85.1 MB
  - `lib/linux_arm64/liblitert-lm.so` 84.7 MB
  - `lib/windows_x86_64/bin/litert-lm.dll` 53.0 MB, plus `lib/litert-lm.lib` import library
  - headers in `include/`
  - 232 third-party license files
  - **No iOS and no static archives.**
  - — [litert_lm_c_api-1.0.0.zip](https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/litert_lm_c_api-1.0.0.zip) (listed 2026-11-23)
- **iOS binary is a dynamic framework.** `CLiteRTLM.xcframework.zip` (v0.19.1, 95.8 MB compressed) contains `ios-arm64/CLiteRTLM.framework/CLiteRTLM` (47.97 MB; `file`: "Mach-O 64-bit dynamically linked shared library arm64") and an `ios-arm64-simulator` slice (45.98 MB). The macOS xcframework ships `libCLiteRTLM_mac.dylib` (143 MB, `macos-arm64_x86_64`). — [CLiteRTLM.xcframework.zip](https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/CLiteRTLM.xcframework.zip); [CLiteRTLM_mac.xcframework.zip](https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/CLiteRTLM_mac.xcframework.zip)
- Extra shared libraries needed for GPU and constraints: the `prebuilt/<platform>/` folders hold `libGemmaModelConstraintProvider.{so,dylib,dll}` (9.1 MB on macOS) and `libwebgpu_dawn.{so,dylib}` / `webgpu_dawn.dll` (per-platform folders 20–38 MB). The source references `libLiteRtTopKOpenClSampler.so`, `libLiteRtTopKWebGpuSampler.{so,dylib,dll}`, `libLiteRtTopKMetalSampler.dylib`, `libLiteRtGpuAccelerator.so` and `libLiteRtDispatch_Nvidia.so`. The build guide says GPU runs need the prebuilt .so/.dll/.dylib files in the same directory as the binary, and that "Running GPU on Windows needs DirectXShaderCompiler". — [prebuilt/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/prebuilt); [build-and-run.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/getting-started/build-and-run.md)
- **The GPU accelerator is closed and dynamically loaded.**
  - Issue #1050 (open since 2025-12-03) asks to "Enable building GPU accelerator plugins from source". Its reporter, building Rust bindings, hit ABI mismatches with the prebuilt `libLiteRtGpuAccelerator.so` against a source-built runtime. A contributor answered on 2026-04-07: "the plan has been delayed. Hope this can be open sourced this year. Not confirmed at all though." — [#1050](https://github.com/google-ai-edge/LiteRT-LM/issues/1050)
  - #4611 (open, 2026-11-15), "[v0.19.1] [REGRESSION] macOS and Android C API builds have hard dependency on libwebgpu_dawn", even for CPU/Metal-only apps. — [#4611](https://github.com/google-ai-edge/LiteRT-LM/issues/4611)
  - #4448 (open, 2026-11-06) proposes to "statically link GPU samplers and remove sampler shared libraries". — [#4448](https://github.com/google-ai-edge/LiteRT-LM/issues/4448)
  - #2211 (open, 2026-05-08): GPU samplers fail to dlopen for AAR consumers and the runtime "silently falls back to CPU sampling", about 3× slower decode with MTP. — [#2211](https://github.com/google-ai-edge/LiteRT-LM/issues/2211)
- Build system:
  - Primary build is Bazel (`.bazelversion` 7.6.1) with Rust components (llguidance, cxx bridge). — [repo root](https://github.com/google-ai-edge/LiteRT-LM)
  - The CMake build is "strictly verified for the GNU toolchain on Debian-based Linux (e.g., Ubuntu 24.04)". It needs gcc/g++ 13+ (C++20), CMake 3.25+, Python 3.12+, OpenJDK 17+ (ANTLR 4) and a Rust toolchain. Memory warning: "Available RAM / 8GB = Max `-j`". — [docs/getting-started/cmake.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/getting-started/cmake.md)
  - Issue #3245 (2026-08-14): "the CMake lane is stale vs the bazel truth in four independent ways". — [#3245](https://github.com/google-ai-edge/LiteRT-LM/issues/3245)
  - Android source builds need NDK r28b or newer. — [build-and-run.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/getting-started/build-and-run.md)
- Kotlin/JVM: `com.google.ai.edge.litertlm:litertlm-android` and `com.google.ai.edge.litertlm:litertlm-jvm` ("JVM (Linux, MacOS, Windows)") on Google Maven. The Android API supports "automatic tool calling" with annotated methods. — [kotlin/README.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/kotlin/README.md); [tool-use.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/api/cpp/tool-use.md)
- Swift: the `LiteRTLM` product, and `LiteRTLMFoundationModels`, an adapter in which "`LiteRTLanguageModel` conforms to the iOS 27 `LanguageModel` protocol" (`@available(iOS 27.0, macOS 27.0, *)`). It exposes a LiteRT-LM model "as an Apple Foundation Models backend". The adapter shipped in v0.15.0 (2026-08-04). — [swift/apple_fm/LiteRTLanguageModel.swift](https://github.com/google-ai-edge/LiteRT-LM/blob/main/swift/apple_fm/LiteRTLanguageModel.swift); [v0.15.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.15.0)
- Python/CLI: `uv tool install litert-lm`, then `litert-lm run --from-huggingface-repo=… --backend=gpu --speculative-decoding=on`. The HF card's Python example pins `litert-lm-api==0.18.0`. CLI subcommands in `python/litert_lm_cli/commands/`: `run`, `serve`, `benchmark`, `convert`, `import`, `describe`, `list`, `delete`, `rename`, `pack`, `unpack`. — [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md); [commands/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/python/litert_lm_cli/commands)
- **OpenAI-compatible server** (added v0.13.0, 2026-06-02).
  - `litert-lm serve` implements `/v1/chat/completions` (with `tools`, `tool_choice`, `stream` over SSE), `/v1/responses`, `/v1/models` and `/v1/embeddings` (added v0.18.0), plus a Gemini-API handler (`gemini_handler.py`).
  - It is built on Python's `http.server`.
  - A June 3, 2026 blog gives the endpoint `localhost:9379/v1/chat/completions`.
  - — [serve/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/python/litert_lm_cli/commands/serve); [v0.13.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.13.0); [Gemma 4 12B laptop blog](https://developers.googleblog.com/bringing-gemma-4-12b-to-your-laptop-unlocking-local-agentic-workflows-with-google-ai-edge/)
- Standalone native CLI binaries: through v0.10.1 (2026-04-03) releases attached `lit_*` binaries (for example `lit_macos_arm64` 93.6 MB, `lit_linux_x86_64` 142 MB, `lit_windows_x86_64.exe` 68.9 MB). From v0.11.0 releases attach only the `litert_lm_main.*` C++ demo binaries (v0.19.1: `litert_lm_main.macos_arm64` 29.6 MB). — [releases API listing](https://github.com/google-ai-edge/LiteRT-LM/releases)
- Third-party bindings: Rust bindings by "Meos Labs" (mentioned in #1050). No Go binding was found: tracker searches for "golang", "go binding" and "gomobile" returned no relevant issues on 2026-11-23. — [#1050](https://github.com/google-ai-edge/LiteRT-LM/issues/1050); [issue search](https://github.com/google-ai-edge/LiteRT-LM/issues)

### Inferences
- **Desktop CLI (Go).** Two paths:
  - **(a) cgo** against `liblitert-lm.{so,dylib}` or `litert-lm.dll` + `litert-lm.lib`, shipping the library (51–85 MB) plus the Dawn and constraint-provider libraries next to the binary (with rpath `$ORIGIN` / `@loader_path`).
  - **(b) dlopen through purego** (no cgo, like yzma for llama.cpp). The C API was explicitly designed for this case (the `litert_lm_get_api_version` handshake), and it keeps the Go binary cross-compilable. The library can then be downloaded on first use rather than bundled.
  - Either way, Go must own each handle on a single goroutine, because handles are not thread-safe. The streaming callback must only copy text into a channel, and it runs on a library thread (with cgo this means an `//export` function invoked from a foreign thread).
- **Static single-file binaries are not realistic today.** There are no static prebuilts. Source builds need Bazel + Rust + C++20, and the CMake path is Linux/gcc-only and lags Bazel. GPU accelerators and Dawn are closed or prebuilt shared objects loaded at runtime (#1050, #4611). Expect "Go binary + sidecar shared libraries" on every desktop OS.
- **Android via gomobile.** `gomobile bind` produces an AAR with `libgojni.so`. Options:
  - **(a)** package `liblitert-lm.so` (arm64 22.8 MB / x86_64 26.9 MB) in `jniLibs` and dlopen it from Go. GPU needs the sampler and Dawn .so files, and #2211 shows dlopen pitfalls in AAR packaging.
  - **(b)** let the host app depend on `litertlm-android` (Kotlin, "Stable") and expose it to Go as a Go interface implemented in Kotlin through gomobile's reverse binding.
  - (b) rides the supported path, but streaming and tool calls then cross JNI twice.
- **iOS via gomobile.** gomobile emits a static framework. LiteRT-LM's iOS binary is a dynamic `CLiteRTLM.framework` (~48 MB arm64), so the host app must embed and sign that framework, and the Go archive must either link it (`-framework CLiteRTLM`, `-F`) or dlopen it from the app bundle. The alternative is a Swift-side bridge using the `LiteRTLM` Swift package (Early Preview) behind a Go interface. Either way the app grows by about 48 MB of code before any model.
- **Browser extension (wasm).** Go-compiled wasm cannot host LiteRT-LM's native core. The only path is the JS SDK (`@litert-lm/core`: WASM + WebGPU), called from JS (or from Go-wasm via `syscall/js`), probably inside an offscreen document (see section 8).
- **Subprocess option.** `litert-lm serve` speaks OpenAI chat-completions with tools and SSE, so a Go harness could reuse an OpenAI client unchanged. It drags in a Python runtime, though (desktop-only, `uv`-installed), and its HTTP server is `http.server`-based. It suits development or "bring your own" setups, not the shipped CLI.

### Gaps
- Whether Google intends to publish static C API libraries, or make Dawn optional again (#4611), is unknown.
- No first-party statement on ABI stability of the iOS framework across minor releases beyond the C API semver rules.
- Untested here (no code was run): whether `libCLiteRTLM_mac.dylib` exports the same `litert_lm_*` C symbols, usable by cgo on Intel Macs.
- Minimum Android API level and iOS memory entitlements needed were not found in the docs read.

## 3. Models and formats (.litertlm / .task, catalog, hosting, sizes, quantization, context, multimodal, licenses)

### Takeaway
Models ship as **`.litertlm`** bundles: a FlatBuffer-headered container of tokenizer, LiteRT graphs and metadata, plus per-accelerator variants (`-gpu`, `-web`, NPU builds per chip). The runtime still reads legacy MediaPipe **`.task`** files. They are hosted on Hugging Face, mainly under **`litert-community`** (500 repos as of 2026-11-23). The flagship is **Gemma 4**: E2B 2.59 GB, E4B 3.66 GB, 12B 6.9 GB, 26B-A4B about 16 GB GPU, 31B on web. **Gemma 4 is Apache-2.0** (since 2026-04-02). Gemma 3/3n/FunctionGemma remain under the gated Gemma terms. Qwen3/3.5, Phi-4-mini, LFM2.5, SmolLM, Granite, DeepSeek-R1-Distill and others are also packaged.

### Cited Findings
- Format: `schema/core/litertlm_header_schema.fbs` defines a FlatBuffer header with typed sections (`enum AnySectionDataType`) and "In the LitRT-LM file format, BLOCK_SIZE = 16 * 1024". The executor "Supports .task and .litertlm formats." `.litertlm` files are built with the `litert_lm_builder` tooling, and the CLI has `convert`, `import`, `pack` and `unpack`. v0.10.1 (2026-04-03) added importing models directly from Hugging Face and "auto-conversion for missing models during 'run' commands". — [litertlm_header_schema.fbs](https://github.com/google-ai-edge/LiteRT-LM/blob/main/schema/core/litertlm_header_schema.fbs); [litert_compiled_model_executor_utils.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/runtime/executor/litert_compiled_model_executor_utils.h); [docs/litert_lm_builder.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/litert_lm_builder.md); [v0.10.1](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.10.1)
- v0.18.0 (2026-10-06) added `ModelInfo` and `litert-lm describe` "for full model introspection—covering metadata, capabilities, and runtime requirements before loading". — [v0.18.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.18.0)
- **Gemma 4 file sizes** (HF API, 2026-11-23):

  | Repo | Variant | Size |
  | :--- | :--- | :--- |
  | gemma-4-E2B-it-litert-lm (updated 2026-11-20) | `gemma-4-E2B-it.litertlm` | 2.59 GB |
  | | `-gpu.litertlm` | 2.34 GB |
  | | `-web.litertlm` | 2.01 GB |
  | | `-web.task` | 2.00 GB |
  | | `_Google_Tensor_G5` | 3.21 GB |
  | | `_Google_Tensor_G6` | 3.45 GB |
  | | `_Qualcomm_QCS8275` | 2.72 GB |
  | | `_intel_LNL` | 2.96 GB |
  | | `_intel_PTL` | 2.95 GB |
  | | `_NPU_Uncompiled` | 2.61 GB |
  | gemma-4-E4B-it-litert-lm | base | 3.66 GB |
  | | `-gpu` | 3.31 GB |
  | | `-web` | 2.97 GB |
  | gemma-4-12B-it-litert-lm | base | 6.88 GB |
  | | `-gpu` | 6.20 GB |
  | | `-web` | 5.99 GB |
  | | `Intel_PTL_NPU` | 7.72 GB |
  | gemma-4-26B-A4B-it-litert-lm | `-gpu` | 16.39 GB |
  | | `-web` | 15.79 GB |
  | | `Intel_PTL_NPU` | 13.25 GB |

  All carry the `license:apache-2.0` tag and none is gated. — [gemma-4-E2B](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main), [gemma-4-E4B](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/tree/main), [gemma-4-12B](https://huggingface.co/litert-community/gemma-4-12B-it-litert-lm/tree/main), [gemma-4-26B-A4B](https://huggingface.co/litert-community/gemma-4-26B-A4B-it-litert-lm/tree/main)
- Gemma 4 31B web file: v0.15.0 links `gemma-4-31B-it-web.litertlm` under `litert-community/gemma-4-31B-it-litert-lm`. — [v0.15.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.15.0)
- Gemma 4 E2B model card:
  - It uses a "Gemma-4 mobile quantization scheme… a mixture of 2bit, 4bit and 8 bit weights". For text-only use "the weight footprint in memory can be as low as 0.8 GB while the runtime uses memory mapping" for 1.12 GB of embedding parameters.
  - "The model can support up to 32k context length" (benchmarks use 2048). The web model "can support up to 128k context length".
  - NPU builds: "The NPU context length is fixed at compilation and cannot be increased at runtime."
  - — [HF model card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Docs conflict: the Gemma 4 doc page says LiteRT-LM "supports only E2B and E4B today… support for larger models coming soon". Release notes and HF repos show 12B (multimodal + MTP + extended context in v0.17.0, 2026-09-09) and 26B-A4B/31B on web (v0.15.0). The doc page appears stale. — [Gemma 4 page](https://developers.google.com/edge/litert-lm/models/gemma-4); [v0.17.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.17.0)
- **Gemma 4 license**: Google's Open Source Blog calls Gemma 4 the first in the Gemmaverse under the OSI-approved Apache 2.0 license (launched April 2, 2026). The family is E2B, E4B, a 26B MoE and a 31B dense model. A HF discussion noted a missing physical LICENSE file in `google/gemma-4-E4B-it`; whether that has been fixed was not verified. — [Google Open Source Blog](https://opensource.googleblog.com/2026/03/gemma-4-expanding-the-gemmaverse-with-apache-20.html); [VentureBeat](https://venturebeat.com/technology/google-releases-gemma-4-under-apache-2-0-and-that-license-change-may-matter); [HF discussion #44](https://huggingface.co/google/gemma-4-E4B-it/discussions/44)
- Older Gemma models keep the Gemma license:
  - `google/gemma-3n-E2B-it-litert-lm` is `license:gemma`, gated (manual approval), last modified 2025-12-08 (possibly superseded). Files: `gemma-3n-E2B-it-int4.litertlm` 3.66 GB, `-int4-Web` 3.04 GB, `.mediatek.mt6993` 4.33 GB. — [HF gemma-3n-E2B](https://huggingface.co/google/gemma-3n-E2B-it-litert-lm)
  - `Gemma3-1B-IT`, `embeddinggemma-300m` and `gemma-3-270m-it` are gated `license:gemma`. — [litert-community org](https://huggingface.co/litert-community)
- Officially listed models with sizes (overview page): Gemma4-E2B 2583 MB; Gemma4-E4B 3654 MB; Gemma-3n-E2B 2965 MB; Gemma-3n-E4B 4235 MB; Gemma3-1B 1005 MB; FunctionGemma (Base) 289 MB; phi-4-mini 3906 MB; Qwen2.5-1.5B 1598 MB; Qwen3-0.6B 586 MB; Qwen2.5-0.5B 521 MB. Embedding: EmbeddingGemma 2 at 740M (485 MB; text, images, video, audio), 440M (388 MB) and 270M (165 MB). — [overview](https://developers.google.com/edge/litert-lm/overview)
- Other litert-community packages (HF API, 2026-11-23):
  - Qwen3-4B: `qwen3_4b_mixed_int4.litertlm` 2.27 GB, int8 5.67 GB; Apache-2.0
  - Qwen3.5-2B: int8 2.12 GB, VL int8 3.15 GB
  - Qwen3.5-4B: mixed_int4 2.75 GB, int8 4.42 GB, plus `_gpu_composite_v0190` variants
  - LFM2.5-1.2B-Instruct: int4 0.74 GB, int8 1.25 GB; `license:other`
  - Phi-4-mini-instruct: q8 ekv4096 `.litertlm` 3.91 GB; MIT
  - DeepSeek-R1-Distill-Qwen-1.5B (MIT); Qwen2.5-1.5B/0.5B-Instruct; Qwen3-0.6B/1.7B/8B; Qwen3.5-0.8B/9B/35B-A3B
  - SmolLM2/SmolLM3-3B; granite-4.x; Ministral-3-3B-Instruct-2512; NVIDIA Nemotron variants; Qwen2-VL-2B, SmolVLM2-500M, FastVLM-0.5B (`apple-amlr` license)
  - Speech: whisper, parakeet, moonshine, Kokoro-82M, Qwen3-ASR/TTS
  - Function calling: `functiongemma-270m-ft-mobile-actions`, `functiongemma-270m-lora-litertlm`, `functiongemma-270m-verified-litertlm`
  - — [HF API litert-community](https://huggingface.co/api/models?author=litert-community); [Qwen3-4B](https://huggingface.co/litert-community/Qwen3-4B); [Qwen3.5-4B](https://huggingface.co/litert-community/Qwen3.5-4B); [LFM2.5-1.2B-Instruct](https://huggingface.co/litert-community/LFM2.5-1.2B-Instruct); [Phi-4-mini-instruct](https://huggingface.co/litert-community/Phi-4-mini-instruct)
- Model-specific prompt/tool processors in the runtime: `function_gemma`, `gemma3` (Gemma 3/3n), `gemma4`, `qwen3` (`tool_code_regex`), `lfm2`, `minicpm5`, `minicpmv`, `fastvlm` and `generic`. The generic processor takes a `ToolCallConfig` from model metadata. The minicpmv and fastvlm processors have no tool handling. — [model_data_processor/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/runtime/conversation/model_data_processor)
- Multimodal and speech:
  - Vision and audio input supported "when models support it" since v0.8.0 (2025-11-25).
  - Gemma 4 E2B/E4B accept text, image and audio input (E2B NPU example).
  - v0.19.1 (2026-11-05): multimodal Gemma 4 on the "Artisan GPU backend".
  - v0.19.0: ASR/TTS models (Qwen3-ASR, Kokoro, Qwen3-TTS) under `omni/`.
  - v0.18.0: multimodal EmbeddingGemma 2 with Matryoshka truncation.
  - — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases); [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- The README lists "Gemma, Llama, Phi-4, Qwen, and more". — [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md)

### Inferences
- A sensible tiering by device class:
  - Phones and the iOS app: Gemma 4 E2B (2.3–2.6 GB download; text, vision, audio; Apache-2.0).
  - 8 GB+ laptops: E4B (3.3–3.7 GB).
  - 16 GB+ GPU laptops: 12B (6.2–6.9 GB).
  - Very-low-end devices or tool routing: FunctionGemma 270M (289 MB) or LFM2.5-1.2B (0.74 GB), with license checks.
  - Qwen3-4B mixed-int4 (2.27 GB, Apache-2.0) is a non-Google alternative with a dedicated tool parser.
- Gemma 4's Apache-2.0 license removes the gated-download and use-policy pass-through issues of Gemma 3/3n/FunctionGemma. Models from Gemma 4 on can be mirrored or CDN-hosted by URnetwork and fetched without HF tokens.
- Each accelerator wants its own file (CPU base, `-gpu`, `-web`, per-NPU-chip). A per-device model manifest is needed rather than a single URL. The unreleased `model_sync` C API (1.1.0) hints at a future first-party ranged-download/update mechanism.

### Gaps
- Exact licenses for FunctionGemma and the LFM2.5 "other" license were not checked.
- Context-length limits per variant (E4B, 12B, CPU vs. GPU builds) are not stated on the pages read. Only E2B's 32k (base) / 128k (web) were found.
- No official list of which non-Gemma models are tool-calling-tuned and validated with LiteRT-LM's parsers.
- No Llama `.litertlm` file was confirmed in the HF listing slice examined (the top 90 repos by downloads).

## 4. Features (streaming, sessions/KV reuse, templates, tool calling, constrained decoding, structured output, sampling, LoRA, cancellation)

### Takeaway
LiteRT-LM has the features an agent harness needs. It streams through callbacks or ReadableStreams. Its Conversation API takes OpenAI-shaped JSON messages, tools and `tool_calls`. The C API exposes `tool_choice`, streaming of tool-call tokens, thinking channels with budgets, and **constrained decoding**: tool-syntax constraints, or LLGuidance regex / JSON Schema / Lark, GPU-accelerated since v0.19.0. It also supports session clone/checkpoint/rewind for KV reuse, the usual sampling controls, LoRA ranks and cancellation. Rough edges remain around multi-conversation state, cancel-then-reuse and GPU sampler parameters.

### Cited Findings
- Tool-calling flow (C++ docs):
  - Tools are declared as a JSON array of schemas with `name`, `description` and `parameters`.
  - The model's reply is parsed into `{"tool_calls":[{"type":"function","function":{"name":"get_weather","arguments":{"location":"Paris"}}}]}`.
  - Tool results go back as a message with `"role": "tool"`.
  - With `SendMessageAsync`, text chunks stream normally. When a tool call starts, the runtime waits for the full call, parses it, and delivers it in `tool_calls`.
  - Formatting and parsing happen per model in `ModelDataProcessor::FormatTools` / `ToMessage` / `MessageToTemplateInput`.
  - — [docs/api/cpp/tool-use.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/api/cpp/tool-use.md)
- v0.14.0 (2026-07-08): "Enabled real-time streaming of tool call tokens in C and Swift APIs, full tool calling support in LiteRT-LM.js, and support for reasoning/thinking channels." v0.15.0 (2026-08-04): JS `AutoToolChat`, "which automatically runs tool calls that the model emits". v0.17.1 (2026-09-16) fixed "a tool call int type issue". — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases)
- Constrained decoding:
  - **(1)** "Constrained Decoding for Tool Calling" via `SetEnableConstrainedDecoding(true)` ("the function call string is constrained to follow the function-calling syntax of the model").
  - **(2)** "Custom Constrained Decoding" via `LlGuidanceConfig()` (Regex, JSON Schema, Lark grammars, through `LlgConstraintType::kRegex/kJsonSchema/kLark`) or `ExternalConstraintConfig()` for custom C++ `Constraint` objects. Constraints apply per message via `OptionalArgs.decoding_constraint`.
  - "You can only choose *one* of these options when constructing a `Conversation` object."
  - In C: `litert_lm_conversation_config_set_enable_constrained_decoding`, `…_set_constraint_provider`, `litert_lm_conversation_optional_args_set_constraint`.
  - — [docs/api/cpp/constrained-decoding.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/api/cpp/constrained-decoding.md); [c/conversation.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/conversation.h)
- v0.19.0 (2026-11-02): "Accelerated Logit Masking: Enables faster constrained decoding on GPUs, with full support for MTP-enabled decoding." A prebuilt `libGemmaModelConstraintProvider` ships per platform. — [v0.19.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.0); [prebuilt/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/prebuilt)
- May 2026 blog: function calling was "introduced in FunctionGemma and refined in Gemma 4". The runtime pauses, returns structured tool-call requests, and resumes on tool output. Constrained decoding can enforce JSON schemas or grammars on the tool payload. — [Google Developers Blog, 2026-05-19](https://developers.googleblog.com/blazing-fast-on-device-genai-with-litert-lm/)
- Streaming:
  - C: `litert_lm_conversation_send_message_stream`, `litert_lm_session_generate_content_stream` (`LiteRtLmStreamCallback`). Chunks carry text, final flag, error, finish reason and executor stats JSON. — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h); [c/conversation.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/conversation.h)
  - JS: `conversation.sendMessageStreaming(text)` returns a `ReadableStream`; breaking out of `for await` cancels; `conversation.cancel()`. — [JS guide](https://developers.google.com/edge/litert-lm/js)
- Sessions and KV reuse:
  - `litert_lm_session_clone`, `litert_lm_conversation_clone`, `litert_lm_session_save_checkpoint` / `rewind_to_checkpoint` / `rewind_to_step`, `litert_lm_conversation_get_token_count`. — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
  - v0.10.1: "LiteRT-based KV cache implementation, speculative decoding support, and improved context merging for conversation history". v0.18.0: "dynamic on-demand KV cache growth on NPU". — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases)
  - An open issue title refers to "Cross-conversation token dedup reus[ing] recurrent state". — [#3165](https://github.com/google-ai-edge/LiteRT-LM/issues/3165)
- Templates: `litert_lm_conversation_config_set_prompt_template`, `litert_lm_session_config_set_apply_prompt_template`, `litert_lm_conversation_render_message_to_string`, `…_render_preface_to_string`. — [c/conversation.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/conversation.h)
- Sampling:
  - temperature, top_k, top_p, seed; repetition penalty (frequency/presence/repetition, window); no-repeat n-gram; suppress tokens; `max_output_tokens`. — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
  - v0.19.0: "GPU sampling now matches CPU for the same seed." — [v0.19.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.0)
  - Open bug #2080: GPU/NPU executor "ignores session-level sampler params (seed / temperature / topK / topP)". — [#2080](https://github.com/google-ai-edge/LiteRT-LM/issues/2080)
- Thinking: `litert_lm_thinking_config_set_enable_thinking`, `…_set_thinking_token_budget`. The CLI `config.json` (v0.15.0) sets "thinking budgets, and context window sizes" per model. — [c/conversation.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/conversation.h); [v0.15.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.15.0)
- LoRA: `litert_lm_engine_settings_set_lora_rank`, `…_set_supported_lora_ranks`, `…_set_audio_lora_rank`, `litert_lm_session_config_set_lora_path`, `…_set_audio_lora_path`. — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
- Speculative decoding / MTP:
  - `litert_lm_engine_settings_set_enable_speculative_decoding`, `…_set_speculative_decoding_config` (mode, lenience). — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
  - Gemma 4 MTP shipped in v0.11.0 (2026-05-07). — [v0.11.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.11.0)
- Cancellation: `litert_lm_session_cancel_process` / `litert_lm_conversation_cancel_process`, callable from inside a non-final chunk callback. After cancel the handle "MUST NOT be reused; only delete it". — [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
- Embeddings: `EmbeddingEngine` in C/Kotlin/Swift/JS/Python (v0.18.0). — [v0.18.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.18.0)
- Known feature-level bugs (open as of 2026-11-23):
  - #2807: "A suspended conversation silently loses its state" when interleaving conversations (0.14.0 wheel).
  - #3771: SIGSEGV if a Conversation is destroyed mid-prefill.
  - #3439: speculative decoding drops `<|im_end|>` in multi-turn transcripts.
  - #3445: think-prefix history is never closed, so long conversations lose coherence.
  - #4641: Android native memory grows about 30 MB per request with MTP plus `Conversation.clone()/close()`.
  - — [#2807](https://github.com/google-ai-edge/LiteRT-LM/issues/2807), [#3771](https://github.com/google-ai-edge/LiteRT-LM/issues/3771), [#3439](https://github.com/google-ai-edge/LiteRT-LM/issues/3439), [#3445](https://github.com/google-ai-edge/LiteRT-LM/issues/3445), [#4641](https://github.com/google-ai-edge/LiteRT-LM/issues/4641)

### Inferences
- The JSON tool and `tool_calls` shapes are close to OpenAI's function-calling format. A Go harness can keep one internal message/tool representation for both local LiteRT-LM and remote TEE providers, with a thin adapter. Note that arguments come back as a JSON object, not a JSON string.
- For dependable local tool calls, enable tool-syntax constrained decoding. Remember it is mutually exclusive with custom LLGuidance constraints on the same Conversation. For structured outputs, use a separate Conversation with a JSON Schema constraint.
- The safest harness pattern given the open bugs:
  - one Conversation per agent thread
  - no interleaving of conversations on one engine
  - on cancel, delete and re-create from saved message history (or a session checkpoint), rather than reusing the handle
  - optionally disable MTP where clone/close churn is heavy on Android

### Gaps
- No published accuracy numbers for LiteRT-LM tool calling (e.g., BFCL) per model.
- Whether LoRA works on all backends (CPU/GPU/NPU/web) is not documented in what was read.
- Whether `tool_choice` supports forcing a specific function or only auto/required/none was not checked in the header details.

## 5. Hardware acceleration and performance (CPU/GPU/NPU, published tokens/sec, memory, minimum RAM)

### Takeaway
- **CPU** uses XNNPACK (YNNPACK experimental on Linux arm64).
- **GPU** uses Google's "ML Drift": OpenCL on Android, Metal on Apple, WebGPU/Dawn on desktop and web, D3D12 or Vulkan on Windows and Linux. A separate "Artisan" GPU path exists.
- **NPU** covers Qualcomm, MediaTek, Google Tensor and Intel (OpenVINO), each needing AOT-compiled, chip-specific model files.

Published Gemma 4 E2B numbers: about 52–56 tok/s decode on flagship phone GPUs, 143–160 tok/s on desktop GPUs, 25–47 tok/s on phone CPUs, and 8 tok/s on a Raspberry Pi 5. Peak process memory runs 0.6–1.7 GB on phones and up to 3.5 GB on Windows. MTP adds up to 2.2× (GPU) or 1.5× (CPU) decode speed. No official minimum RAM is published.

### Cited Findings
- Acceleration stack: "LiteRT provides the foundational hardware acceleration via XNNPack for CPU and ML Drift for GPU". — [HF E2B model card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Other backend notes:
  - v0.16.0 added an "Experimental YNNPACK Delegate… enabled for linux arm64 builds in the LiteRT-LM CLI and Python API".
  - v0.17.0 added "Metal residency support".
  - v0.7.0 (2025-06-24, possibly superseded) "Added Qualcomm & MediaTek NPU support for Gemma3 1B".
  - v0.12.0 added Intel OpenVINO NPU via `--backend=npu`.
  - — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases)
- The runtime source mentions `GPU_ARTISAN` ("run their decoders outside LiteRT") and an internal `TENSOR_LLM` path. — [runtime/framework/resource_management/resource_manager.cc](https://github.com/google-ai-edge/LiteRT-LM/blob/main/runtime/framework/resource_management/resource_manager.cc)
- Windows GPU needs DirectXShaderCompiler. — [build-and-run.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/docs/getting-started/build-and-run.md)
- Issues show a D3D12 path on Intel Windows (#4460) and Vulkan on Linux/Intel (#2584, `VK_ERROR_OUT_OF_DEVICE_MEMORY` with Gemma-4-12B on 32 GB). — [#4460](https://github.com/google-ai-edge/LiteRT-LM/issues/4460), [#2584](https://github.com/google-ai-edge/LiteRT-LM/issues/2584)
- NPU file variants exist for Google Tensor G5/G6, Qualcomm QCS8275, Intel LNL/PTL and MediaTek MT6993 (Gemma 3n). The C API exposes `litert_lm_engine_settings_set_litert_dispatch_lib_dir` "for NPU backend". — [HF E2B files](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main); [HF gemma-3n](https://huggingface.co/google/gemma-3n-E2B-it-litert-lm); [c/engine.h](https://github.com/google-ai-edge/LiteRT-LM/blob/main/c/engine.h)
- Benchmark methodology (E2B card): 1024 prefill tokens, 256 decode tokens, context 2048. CPU runs use XNNPACK with 4 threads. TTFT excludes load time, with caches enabled and initialized. Memory is `ru_maxrss` (Android/Linux/Pi), `phys_footprint` (iOS/macOS) or `PrivateUsage` (Windows). — [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- **Gemma 4 E2B (2.58 GB)**, prefill / decode tok/s, TTFT, peak memory:

  | Device | Backend | Prefill | Decode | TTFT | Peak memory |
  | :--- | :--- | ---: | ---: | ---: | ---: |
  | S26 Ultra | CPU | 557 | 47 | 1.8 s | 1733 MB |
  | S26 Ultra | GPU | 3808 | 52 | 0.3 s | 676 MB |
  | iPhone 17 Pro | CPU | 532 | 25 | 1.9 s | 607 MB |
  | iPhone 17 Pro | GPU | 2878 | 56–57 | 0.3 s | 1450 MB |
  | Linux Arm 2.3/2.8 GHz | CPU | 260 | 35 | 4 s | 1628 MB |
  | RTX 4090 | GPU | 11234 | 143 | 0.1 s | 913 MB |
  | MacBook Pro M4 Max | CPU | 901 | 42 | 1.1 s | 736 MB |
  | MacBook Pro M4 Max | GPU | 7835 | 160 | 0.1 s | 1623 MB |
  | Intel LunarLake | CPU | 435 | 30 | 2.4 s | 3505 MB |
  | Intel LunarLake | GPU | 3751 | 48 | 0.3 s | 3540 MB |
  | Raspberry Pi 5 16GB | CPU | 133 | 8 | 7.8 s | 1546 MB |

  — [overview](https://developers.google.com/edge/litert-lm/overview); [Gemma 4 page](https://developers.google.com/edge/litert-lm/models/gemma-4)
- Extra E2B rows (HF card):

  | Device | Backend | Prefill | Decode | TTFT | Memory |
  | :--- | :--- | ---: | ---: | ---: | ---: |
  | Jetson Orin Nano | CPU | 109 | 12.2 | 9.4 s | 3681 MB |
  | Jetson Orin Nano | GPU | 1142 | 24.2 | 0.9 s | 2739 MB |
  | Qualcomm IQ-8275 | NPU | 3747 | 31.7 | 0.3 s | 1869 MB (2967 MB model, 4096 ctx) |
  | Web, M4 Max | WebGPU | 4853 | 73 | 1.09 s | ~1800 MB GPU (2341 MB model) |

  — [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- **Gemma 4 E4B (3.65 GB)**, prefill / decode tok/s, TTFT, memory:

  | Device | Backend | Prefill | Decode | TTFT | Memory |
  | :--- | :--- | ---: | ---: | ---: | ---: |
  | S26 Ultra | CPU | 195 | 18 | 5.3 s | 3283 MB |
  | S26 Ultra | GPU | 1293 | 22 | 0.8 s | 710 MB |
  | iPhone 17 Pro | CPU | 159 | 10 | 6.5 s | 961 MB |
  | iPhone 17 Pro | GPU | 1189 | 25 | 0.9 s | 3380 MB |
  | Linux | CPU | 82 | 18 | 12.6 s | 3139 MB |
  | RTX 4090 | GPU | 7260 | 91 | 0.2 s | 1119 MB |
  | M4 Max | CPU | 277 | 27 | 3.7 s | 890 MB |
  | M4 Max | GPU | 2560 | 101 | 0.4 s | 3217 MB |
  | LunarLake | CPU | 173 | 17 | 6.0 s | 9372 MB |
  | LunarLake | GPU | 1202 | 25 | 0.9 s | 7147 MB |
  | Pi 5 | CPU | 51 | 3 | 20.5 s | 3069 MB |

  — [Gemma 4 page](https://developers.google.com/edge/litert-lm/models/gemma-4)
- Older and smaller models (overview), CPU then GPU prefill/decode tok/s:
  - Gemma-3n-E2B: S24 Ultra 111/16 CPU, 816/16 GPU; MBP M3 CPU 233/28
  - Gemma-3n-E4B: S24 Ultra 74/9 CPU, 548/9 GPU
  - Gemma3-1B: S24 Ultra 177/33 CPU, 1191/24 GPU
  - FunctionGemma: S25 Ultra CPU 2238/154
  - phi-4-mini: S24 Ultra 67/7 CPU, 314/10 GPU
  - Qwen2.5-1.5B: S25 Ultra 298/34 CPU, 1668/31 GPU
  - Qwen3-0.6B: Vivo X300 Pro 165/9 CPU, 580/21 GPU
  - Qwen2.5-0.5B: S24 Ultra CPU 251/30
  - — [overview](https://developers.google.com/edge/litert-lm/overview)
- **MTP / speculative decoding**:
  - Up to 2.2× decode on mobile GPUs and up to 1.5× on mobile CPUs, with "significant acceleration" on SME hardware such as M4. Recommended for GPU always and for E4B on CPU; on E2B CPU it can slightly slow free-form generation. — [Gemma 4 page](https://developers.google.com/edge/litert-lm/models/gemma-4)
  - S26 Ultra GPU decode: baseline 51.5 tok/s vs. 91.7 (summarize), 84.4 (code), 87.4 (rewrite), 66.5 (free form). CPU: baseline 40.7 vs. 36.3–47.5. — [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Blog (2026-05-19): E2B GPU decode 52 tok/s on Android (OpenCL) and 56 tok/s on iOS (Metal). Web reaches "up to 76 tokens/sec" on a MacBook Pro. The 2.58 GB E2B "runs with a physical memory footprint of 607MB on Apple mobile CPUs, using XNNPACK weight caching". — [Google Developers Blog](https://developers.googleblog.com/blazing-fast-on-device-genai-with-litert-lm/)
- GPU numeric-correctness bugs with default FP16 activations (open):
  - #3913: iOS GPU, Gemma 4 E4B "duplicates digits at ~3.7K-token context; CPU and float32 are correct".
  - #4001: Adreno 840, digits scrambled past about 2,048 tokens; FLOAT32 fixes it.
  - #2814: iOS/Metal digit corruption.
  - — [#3913](https://github.com/google-ai-edge/LiteRT-LM/issues/3913), [#4001](https://github.com/google-ai-edge/LiteRT-LM/issues/4001), [#2814](https://github.com/google-ai-edge/LiteRT-LM/issues/2814)
- Older-device compatibility questions exist, for example "Pixel 5 GPU compatibility" (#2241) and a Mali-G715 field report (#2202). — [#2241](https://github.com/google-ai-edge/LiteRT-LM/issues/2241); [#2202](https://github.com/google-ai-edge/LiteRT-LM/issues/2202)

### Inferences
- Rough device floor from the published peak memory: E2B needs about 0.6–1.7 GB of process memory on phones and about 1.5–3.5 GB on desktops. In practice that means devices with 6–8 GB+ RAM for E2B and 12–16 GB+ for E4B on Windows CPU (9.4 GB peak) or 12B. This is an inference; Google publishes no minimum.
- A decode rate of 25–56 tok/s on phones is fine for interactive agent turns, but prefill on CPU (110–560 tok/s) makes long tool-result contexts slow (TTFT of several seconds per 1K tokens). Prefer GPU where available, and keep tool outputs short.
- Because digits get corrupted under FP16 GPU activations at longer contexts, an agent harness that copies numbers (addresses, amounts, IDs) should consider `litert_lm_engine_settings_set_activation_data_type(Float32)` on GPU, or validate numeric round-trips.
- NPU paths need per-chip model files and dispatch libraries, and fix the context at compile time. Treat NPU as a later optimization, not a baseline.

### Gaps
- No published numbers for Gemma 4 12B / 26B-A4B on LiteRT-LM (the 12B blog gives none), for mid-range or old Android phones, or for Intel Macs.
- No official minimum RAM, GPU family or OS-version floor.
- No independent third-party benchmarks comparing LiteRT-LM with llama.cpp or MLX on identical hardware were found. The May 2026 blog shows a chart vs. MLX and ONNX Runtime Web, but without numbers in the text.

## 6. Packaging, binary size, licensing, release cadence, maturity, known issues

### Takeaway
LiteRT-LM is Apache-2.0, very active, and pre-1.0. There have been 35 releases since 2025-06-05, about every 2–4 weeks in 2026, and v0.19.1 is current. The native library adds roughly 23–27 MB (Android), about 48 MB (iOS), 51 MB (macOS), 53 MB (Windows) or 85 MB (Linux) uncompressed, plus GPU helper libraries. Models add 0.3–16 GB. The project is "production-ready" by Google's description and powers Chrome and Pixel Watch, but the tracker shows frequent regressions, breaking API changes and GPU-numerics bugs.

### Cited Findings
- Repo license Apache-2.0. Created 2025-04-14. As of 2026-11-23: 6,920 stars, 800 forks, 805 open issues + PRs; description: "Google's production-ready, high-performance, open-source inference framework for deploying Large Language Models on edge devices". — [GitHub repo](https://github.com/google-ai-edge/LiteRT-LM) (via GitHub API)
- Third-party notices:
  - The C API zip bundles 232 license files (TensorFlow, XNNPACK, Abseil-era deps, SentencePiece, tokenizers, Rust crates, SwiftShader, Vulkan headers, and others). — [litert_lm_c_api-1.0.0.zip](https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/litert_lm_c_api-1.0.0.zip)
  - v0.15.0 and v0.16.0 attached `THIRD_PARTY_NOTICES.txt` (1.9 MB) and `CLiteRTLM.spdx.json`. — [v0.16.0](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.16.0)
  - Issue #3194 requests a binary-specific SBOM for the xcframework. — [#3194](https://github.com/google-ai-edge/LiteRT-LM/issues/3194)
- Binary sizes (v0.19.1; full list in section 2):
  - C API shared libraries 22.8–85.1 MB uncompressed (123.5 MB zip)
  - iOS framework 47.97 MB uncompressed (95.8 MB xcframework zip with the simulator slice)
  - macOS universal dylib 143 MB
  - prebuilt GPU/constraint helper folders 20–38 MB per platform
  - — [release assets](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.1); [prebuilt/](https://github.com/google-ai-edge/LiteRT-LM/tree/main/prebuilt)
- Growth trend: `litert_lm_main.macos_arm64` was 7.6 MB in v0.6.1 (2025-06-10), 15.1 MB in v0.8.0 (2025-11-25), 19.8 MB in v0.11.0 (2026-05-07) and 29.6 MB in v0.19.1 (2026-11-05). — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases)
- Release timeline (GitHub releases API):

  | Release | Date | Highlights |
  | :--- | :--- | :--- |
  | v0.1.0-alpha | 2025-06-05 | first tag |
  | v0.7.0 | 2025-06-24 | |
  | v0.8.0 | 2025-11-25 | Conversation API, function calling, Kotlin, desktop GPU |
  | v0.9.0 | 2026-03-27 | |
  | v0.10.1 | 2026-04-03 | Gemma 4 |
  | v0.11.0 | 2026-05-07 | MTP, native Windows |
  | v0.12.0 | 2026-05-18 | Swift, JS |
  | v0.13.0 | 2026-06-02 | OpenAI server |
  | v0.14.0 | 2026-07-08 | |
  | v0.15.0 | 2026-08-04 | |
  | v0.16.0 | 2026-08-11 | C API prebuilts |
  | v0.17.0 | 2026-09-09 | |
  | v0.18.0 | 2026-10-06 | |
  | v0.19.0 | 2026-11-02 | C API 1.0.0 |
  | v0.19.1 | 2026-11-05 | current |

  `main` = 0.20.0-dev; a nightly `0.20.0.dev20261106` is referenced in #4460. — [releases](https://github.com/google-ai-edge/LiteRT-LM/releases); [#4460](https://github.com/google-ai-edge/LiteRT-LM/issues/4460)
- Maturity signals:
  - The README calls the project "production-ready" and says it powers Chrome, Chromebook Plus and Pixel Watch.
  - Swift and JS are "Early Preview".
  - Kotlin `litertlm-android` 0.17.0–0.18.1 "carry Kotlin metadata 2.4.0" (a compatibility note in the Kotlin README).
  - — [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md); [kotlin/README.md](https://github.com/google-ai-edge/LiteRT-LM/blob/main/kotlin/README.md)
- Most-discussed open issues (sorted by comments, 2026-11-23):
  - #3508: NPU prefill loses chunks for Gemma 3 on Qualcomm/Intel
  - #3913: iOS GPU digit duplication
  - #3165: recurrent-state reuse
  - #2814: iOS Metal digit corruption
  - #1050: closed GPU plugins
  - #4001: Adreno digit scrambling
  - #3296: SwiftPM `main` doesn't build against pinned xcframeworks
  - #2211: GPU samplers fail to dlopen in AARs
  - #3245: CMake stale vs. Bazel
  - Regressions: #4611 (Dawn hard dependency), #2966 (closed; 0.14.0 used twice the memory of 0.13.1), #2699 (closed; per-conversation GPU memory not reclaimed)
  - — [issues](https://github.com/google-ai-edge/LiteRT-LM/issues?q=is%3Aissue+is%3Aopen+sort%3Acomments-desc); [#2966](https://github.com/google-ai-edge/LiteRT-LM/issues/2966); [#2699](https://github.com/google-ai-edge/LiteRT-LM/issues/2699)
- Swift-specific crashes: #2613 (engine teardown via `litert_lm_engine_delete` on an arbitrary thread in `deinit`) and #2370 (Gemma 4 E4B vision fails on iOS with `STABLEHLO_COMPOSITE` missing, as of native v0.12.0). — [#2613](https://github.com/google-ai-edge/LiteRT-LM/issues/2613), [#2370](https://github.com/google-ai-edge/LiteRT-LM/issues/2370)

### Inferences
- Pin exact LiteRT-LM versions per platform and gate upgrades behind the sidecar's own regression suite. Breaking changes (C API 1.0.0) and regressions such as the Dawn dependency and memory growth land in minor releases.
- Download the model after install: E2B alone is 2.3–2.6 GB. The native library can be bundled on mobile (about 23–48 MB). On desktop it can be bundled or fetched on first run.
- Shipping LiteRT-LM binaries means redistributing Apache-2.0 code plus about 230 third-party notices. Budget for an attribution file in each app and CLI distribution.

### Gaps
- Google publishes no LTS or support policy, and no deprecation policy for the C API beyond semver in the header.
- No published per-platform "minimal CPU-only" binary size (without GPU and constraint-provider libraries).

## 7. Relationship to MediaPipe LLM Inference API and Google AI Edge Gallery

### Takeaway
LiteRT-LM is the successor engine. Google's MediaPipe LLM Inference guide now says the API is deprecated or maintenance-only, and the Android and iOS versions point developers to LiteRT-LM. The live URLs largely redirect to LiteRT-LM content. LiteRT-LM still loads `.task` files, and HF repos still publish `-web.task` variants for MediaPipe-web compatibility. Google AI Edge Gallery is Google's reference app on Android, iOS and macOS, built on LiteRT-LM.

### Cited Findings
- Search snippets of Google's MediaPipe LLM Inference guide show two wordings:
  - (a) the API "for Android, iOS, and Web is now in maintenance-only mode", with new features going to LiteRT-LM and web projects advised to migrate to the LiteRT-LM JavaScript API;
  - (b) Android and iOS are "deprecated", Web is "NOT deprecated", and mobile projects should migrate to LiteRT-LM.
  - Which wording is current could not be determined.
  - — [LLM Inference guide](https://developers.google.com/edge/mediapipe/solutions/genai/llm_inference); [Web guide](https://developers.google.com/edge/mediapipe/solutions/genai/llm_inference/web_js); [Android guide](https://developers.google.com/edge/mediapipe/solutions/genai/llm_inference/android)
- `https://ai.google.dev/edge/mediapipe/solutions/genai/llm_inference` returns HTTP 301 to developers.google.com. On 2026-11-23 the fetched content was a LiteRT-LM landing page ("Last updated 2026-10-06 UTC") that only mentions `.litertlm`. — [redirect target](https://developers.google.com/edge/mediapipe/solutions/genai/llm_inference)
- The May 2026 blog says LiteRT-LM's web support builds on "the foundational success of the MediaPipe LLM Inference engine's web solution". — [Google Developers Blog](https://developers.googleblog.com/blazing-fast-on-device-genai-with-litert-lm/)
- LiteRT-LM still reads `.task` ("Supports .task and .litertlm formats"). HF still hosts `gemma-4-E2B-it-web.task` (2.00 GB) and `gemma-4-E4B-it-web.task` (2.96 GB). — [executor utils](https://github.com/google-ai-edge/LiteRT-LM/blob/main/runtime/executor/litert_compiled_model_executor_utils.h); [HF E2B files](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main)
- Google AI Edge Gallery is on Google Play and the App Store, and the README presents it as the way to "run models immediately on your device". A June 3, 2026 blog says the Gallery app (and the "Eloquent" app) are "now available on macOS" with Gemma 4 12B. — [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md); [Gallery repo](https://github.com/google-ai-edge/gallery); [Gemma 4 12B laptop blog](https://developers.googleblog.com/bringing-gemma-4-12b-to-your-laptop-unlocking-local-agentic-workflows-with-google-ai-edge/)
- The Google Tensor SDK release notes reportedly list a July 2, 2026 release with "an on-device LiteRT-LM chatbot app for Gemma 4 on Pixel TPUs". This comes from a search snippet; the page was not fetched. — [Tensor SDK release notes](https://developers.google.cn/edge/tensor-sdk/release-notes)

### Inferences
- New work should target LiteRT-LM, not MediaPipe GenAI. The `.task` compatibility helps only for legacy web models.

### Gaps
- An exact MediaPipe LLM Inference end-of-life date was not found.

## 8. Alternatives and fallbacks for a Go program (llama.cpp + Go bindings, MLC LLM, Apple Foundation Models, Android AICore/Gemini Nano, ONNX Runtime GenAI, Ollama, browser options)

### Takeaway
No single alternative covers every target:
- llama.cpp via the cgo-free Go binding **yzma** is the strongest desktop fallback, and covers Windows ARM64 and Intel-Mac gaps only if llama.cpp builds exist for them.
- **Apple Foundation Models** (Swift-only, 4,096-token on-device context) and **Android AICore/Gemini Nano** (Kotlin-only, device-limited, foreground-only) are zero-download system models, reachable from Go only through host-app bridges.
- **ONNX Runtime GenAI** is a C-API peer with similar constrained-decoding tool calling.
- **MLC/WebLLM** is mainly relevant to the browser.
- **Ollama** is a user-installed daemon option on desktop.
- Remote TEE inference remains the fallback for devices that cannot run local models.

### Cited Findings
- **llama.cpp + Go**:
  - yzma uses "`purego`… and `ffi`… packages so CGo is not needed", with "normal `go build` and `go run`… No C compiler needed!". Platforms: Linux amd64/arm64 (CUDA, Vulkan, HIP, ROCm, SYCL, OpenVINO), macOS arm64 (Metal), Windows amd64 (CUDA, Vulkan, HIP, SYCL, OpenCL, OpenVINO), Browser wasm32 (WebGPU, CPU fallback). Newest listed tag v1.33.0, paired with llama.cpp b12347+. No Android or iOS mention. — [hybridgroup/yzma](https://github.com/hybridgroup/yzma)
  - Kronk (Ardan Labs) builds on yzma. — [ardanlabs/kronk](https://github.com/ardanlabs/kronk)
  - gollama.cpp uses purego + libffi "without CGO". — [dianlight/gollama.cpp](https://github.com/dianlight/gollama.cpp)
  - The older cgo binding go-skynet/go-llama.cpp still exists. — [go-skynet/go-llama.cpp](https://github.com/go-skynet/go-llama.cpp)
  - Ollama ships a cgo `llama` package. — [pkg.go.dev ollama/llama](https://pkg.go.dev/github.com/ollama/ollama@v0.15.2/llama)
- **MLC LLM / WebLLM**:
  - Third-party guides describe Metal on iOS and OpenCL on Android, with example apps that bundle a compiled model. — [promptquorum explainer](https://www.promptquorum.com/power-local-llm/mlc-llm-explained)
  - The MLC Chat iOS app requires iOS 17.0+ and is about 1.8 GB. — [App Store](https://apps.apple.com/app/mlc-chat/id6448482937)
  - WebLLM is described in an arXiv paper revised April 2026. — [arXiv 2412.15803v2](https://arxiv.org/html/2412.15803v2)
  - WebLLM ships a "chrome-extension-webgpu-service-worker" example. — [web-llm example](https://github.com/mlc-ai/web-llm/blob/HEAD/examples/chrome-extension-webgpu-service-worker/)
  - No official 2026 MLC LLM release announcement was found.
- **Apple Foundation Models**:
  - Tool calling via `Tool`; arguments use guided generation, and tools can be called in parallel. `GenerationOptions.ToolCallingMode` takes `.required` / `.allowed` / `.disallowed`. `@Generable` guided generation guarantees structure through constrained decoding. — [Apple: Expanding generation with tool calling](https://developer.apple.com/documentation/foundationmodels/expanding-generation-with-tool-calling)
  - The on-device context window is **4,096 tokens per session**, input and output combined. — [TN3193](https://developer.apple.com/documentation/technotes/tn3193-managing-the-on-device-foundation-model-s-context-window)
  - iOS 26.4 added `contextSize` and a token-counting method (back-deployed). — [InfoQ, 2026-03](https://infoq.com/news/2026/03/apple-foundation-models-context)
  - A WWDC26 session cites a 32,000-token context for Apple's server-side model. — [WWDC26 session 241](https://developer.apple.com/videos/play/wwdc2026/241/)
  - Forum reports claim tool calling and guided generation became less reliable after iOS 26.4. These are anecdotal. — [Apple Developer Forums, Foundation Models](https://developer.apple.com/forums/topics/machine-learning-and-ai/machine-learning-and-ai-foundation-models)
  - LiteRT-LM ships `LiteRTLMFoundationModels`, which plugs LiteRT-LM models into the iOS 27 / macOS 27 `LanguageModel` protocol. — [LiteRTLanguageModel.swift](https://github.com/google-ai-edge/LiteRT-LM/blob/main/swift/apple_fm/LiteRTLanguageModel.swift)
- **Android AICore / Gemini Nano**:
  - The ML Kit GenAI Prompt API sends text and multimodal requests to Gemini Nano through AICore. It was released in alpha in October 2025 (possibly superseded).
  - Devices split into nano-v2 and nano-v3. Google said it "performs best on the Pixel 10 device series", and the device lists differ between page snapshots.
  - Inference is allowed only when the app is the top foreground app (per search snippet).
  - — [ML Kit GenAI overview](https://developers.google.com/ml-kit/genai); [Prompt API alpha blog](https://android-developers.googleblog.com/2025/10/ml-kit-genai-prompt-api-alpha-release.html)
  - The LiteRT-LM Gemma 4 E2B card itself says: "On supported Android devices, Gemma 4 is available through Android AI Core as Gemini Nano, which is the recommended path for production applications." — [HF E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- **ONNX Runtime GenAI**:
  - Has C/C++, C# and Python APIs, multi-turn, multimodal, and "tool calling via constrained decoding (JSON schema or Lark grammar)" using LLGuidance. Platforms: Windows, Linux, macOS and Android (x86, x64, arm64); one undated table also lists iOS. — [onnxruntime-genai README](https://raw.githubusercontent.com/microsoft/onnxruntime-genai/main/README.md); [ONNX Runtime generate() API docs](https://onnxruntime.ai/docs/genai/)
  - Version data conflicts: NuGet lists 0.17.1 (2026-09-29), while a mirror lists 0.15.0 (2026-07-30) as latest. — [NuGet](https://www.nuget.org/packages/Microsoft.ML.OnnxRuntimeGenAI/)
- **Ollama**:
  - Streaming responses with tool calling in the native API since a 2025-05-28 blog (possibly superseded). — [Ollama blog](https://registry.ollama.ai/blog/streaming-tool)
  - Tool-calling docs exist. — [Ollama tool calling docs](https://docs.ollama.com/capabilities/tool-calling)
  - A 2026 report says Ollama 0.20.2 fixed Gemma 4 tool-call parsing, and that both the native and OpenAI-compatible endpoints return tool calls in streaming. — [opencode #20995](https://github.com/anomalyco/opencode/issues/20995)
- **Browser extension pattern**:
  - Community sources say WebGPU inference cannot run in an MV3 service worker. The model runs in an **offscreen document**, and the service worker routes messages. Example: Gemma Gem runs Gemma 4 E2B/E4B in Chrome this way, with about 500 MB disk for E2B by its own claim. — [kessler/gemma-gem](https://github.com/kessler/gemma-gem); [HF Transformers.js extension guide](https://huggingface.co/blog/transformersjs-chrome-extension)
  - This conflicts with MLC's service-worker example above.
  - A Chromium-extensions thread discusses WASM OOM when downloading 500 MB models. — [chromium-extensions thread](https://groups.google.com/a/chromium.org/g/chromium-extensions/c/-4CNcu5bUGA)
  - Chrome also offers built-in AI APIs, and LiteRT-LM's README says it powers on-device GenAI in Chrome. — [Chrome AI docs](https://developer.chrome.com/docs/ai); [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/README.md)

### Inferences
- **llama.cpp (via yzma or similar).** This is the best fallback for the desktop CLI:
  - It is pure-Go-buildable, because purego dlopens a llama.cpp shared library at runtime. Covered backends: Metal on Apple Silicon; CUDA/Vulkan on Linux and Windows x64.
  - It uses the huge GGUF ecosystem, with no per-accelerator model files.
  - It fills LiteRT-LM gaps (Windows ARM64, Intel Macs, older GPUs) only where llama.cpp itself has builds; yzma's matrix lists no Windows ARM64 or macOS x86_64 entries.
  - For gomobile, llama.cpp can be compiled for Android and iOS, but yzma documents no mobile support, so a custom cgo/NDK build would be needed (unverified here).
  - Tool calling depends on chat-template parsing and GBNF/JSON-schema grammars rather than a first-party conversation API, so the harness would own more of the tool-call parsing.
- **MLC LLM.** Strong GPU performance on iOS (Metal) and Android (OpenCL). Models must be compiled per target with TVM, and the runtime is C++ with Swift/Kotlin/JS front-ends and no Go binding. Its main relevance is WebLLM as an alternative JS engine for the browser extension. It is a weak fit for a Go CLI or gomobile core.
- **Apple Foundation Models.** Free, zero-download and system-managed, with first-class tool calling and guided generation. However it is Swift-only, needs Apple Intelligence-eligible hardware and recent OS versions, and has only 4,096 tokens of context, which is tight for an agent harness with tool schemas. From Go via gomobile, it needs a Swift adapter that implements a Go-declared interface. A good "no-download" tier on iOS/macOS for short tasks. With iOS 27, LiteRT-LM can even plug into the same `LanguageModel` protocol, so a Swift-side abstraction could switch between the system model and Gemma 4.
- **Android AICore / Gemini Nano.** Zero-download and system-managed. Google's own LiteRT-LM card calls it "the recommended path for production" on supported devices. It is reachable only from Kotlin/Java (ML Kit), runs only for the foreground app, and covers only nano-v2/v3 devices. From Go it needs a gomobile reverse binding to a Kotlin implementation. Good as the first choice on supported Pixel/Samsung flagships, with LiteRT-LM as the fallback elsewhere.
- **ONNX Runtime GenAI.** The closest architectural peer: a C API that cgo can wrap, with tool calling via LLGuidance-constrained decoding on Windows, Linux, macOS and Android, and DirectML/NPU paths on Windows (including ARM64 via Microsoft's ecosystem; not verified here). Its model catalog and Gemma 4 support were not checked. A plausible Windows ARM64 fallback.
- **Ollama.** Not embeddable in a shipped CLI the same way, because it is a separate user-installed daemon (written in Go, using llama.cpp/ggml through cgo). It is the easiest "bring your own local model" option: the Go harness talks to its HTTP API (native or OpenAI-compatible, with streaming tool calls). Desktop only; no gomobile or browser story.
- **Devices that cannot run LiteRT-LM at all**: Windows ARM64, Intel Macs without the universal dylib, phones under about 6 GB RAM or with broken GPU drivers, and browsers without WebGPU. The realistic fallbacks, in order: system models (AICore, Apple FM), then a llama.cpp/yzma CPU path on desktop, then remote TEE inference. A small FunctionGemma-class model (289 MB) on CPU could still handle local tool routing.

### Gaps
- Not verified this session: current Apple Intelligence device and OS eligibility for Foundation Models, current AICore device lists, MLC LLM's 2026 release status, ONNX Runtime GenAI's latest version and mobile/iOS status, yzma's license, and llama.cpp Windows ARM64 and Intel-Mac build availability.
- No head-to-head benchmarks (LiteRT-LM vs. llama.cpp vs. MLX vs. ORT GenAI) on the same devices from a credible third party were found.
- Whether Chrome's built-in Prompt API supports tool calling, and its availability for extensions in November 2026, was not checked.
