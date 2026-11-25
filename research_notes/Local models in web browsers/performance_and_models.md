# Local LLM inference in web browsers: measured performance, memory ceilings, models per device class, and device detection (state as of 2026-11-25)

Conventions: each number carries the date, hardware, browser, engine, model and quantization where its source states them. "[>12 mo]" marks data from before about November 2025, which may be outdated. "(search excerpt)" marks a claim I saw only in a search-result summary and did not confirm on the opened page; treat those as leads, not facts.

## 1. Published WebGPU benchmarks: decode, prefill, TTFT, load/compile time, and ratio to native

### Takeaway
Vendors publish browser numbers almost only for Apple-Silicon desktops in Chrome. LiteRT-LM's web build runs Gemma 4 E2B at 73 tok/s decode, 4,853 tok/s prefill and 1.09 s TTFT on an M4 Max, and E4B at 44 tok/s, 1,590 tok/s and 1.75 s. That is about 44–46% of native GPU decode and about 62% of native GPU prefill on the same machine. Across engines and studies, browser/native ratios run from about 40% to 97% for decode and about 10% to 62% for prefill. For phones there is one 2026 academic study and a few GitHub issues. They show 4–17 tok/s decode, and only models of 0.4 GB or less fit on iPhones and most Android GPUs. Firefox's WebGPU path runs at about 1–10 tok/s, which makes it unusable.

### Cited Findings

#### LiteRT-LM web (Gemma 4): the only vendor-published browser numbers for E2B and E4B
- Gemma 4 E2B web build `gemma-4-E2B-it-gpu.litertlm` (listed as 2,341 MB) on a MacBook Pro M4 Max, WebGPU backend: prefill 4,853 tok/s, decode 73 tok/s, TTFT 1.09 s, GPU memory "~1800" MB. Test conditions: 1,024 prefill tokens, 256 decode tokens, 2,048-token context. TTFT excludes load time and was measured with caches "enabled and initialized"; "first-run latency and memory may differ". The card gives no browser version or run date, and calls the web file "specially optimized" for web memory constraints. — [HF model card, gemma-4-E2B-it-litert-lm](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Native on the same M4 Max, same card: GPU prefill 7,835, decode 160.2 tok/s, TTFT 0.1 s, 1,623 MB; CPU (XNNPACK, 4 threads) 901 and 41.6 tok/s, 1.1 s, 736 MB. — [HF model card, E2B](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Gemma 4 E4B web build `gemma-4-E4B-it-gpu.litertlm` (3,311 MB) on the M4 Max, WebGPU: prefill 1,590, decode 44 tok/s, TTFT 1.75 s, GPU memory "~3300" MB. Native GPU on the same machine: 2,560 and 101.1 tok/s, 0.4 s, 3,217 MB; native CPU 277 and 27.0 tok/s, 3.7 s. — [HF model card, gemma-4-E4B-it-litert-lm](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)
- Native references from the same cards, none with a browser counterpart:
  - E2B: S26 Ultra GPU 3,808 prefill, 52.1 decode, 0.3 s TTFT, 676 MB; iPhone 17 Pro GPU 2,878, 56.5, 0.3 s, 1,450 MB; Intel Lunar Lake GPU 3,751, 48.4, 0.29 s; RTX 4090 11,234, 143.4.
  - E4B: S26 Ultra GPU 1,293, 22.1, 0.8 s; iPhone 17 Pro GPU 1,189, 25.1, 0.9 s, 3,380 MB; Lunar Lake GPU 1,202, 25.13, 0.89 s; RTX 4090 7,260, 91.2.
  - Sources: [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm); [E4B card](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)
- Speculative decoding (MTP) on the S26 Ultra GPU raises E2B decode from a 51.5 tok/s baseline to 66.5–91.7 tok/s, depending on task. It needs model files downloaded after May 5, 2026. The card says it is available on CPU and GPU for mobile and desktop, and says nothing about web. — [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Google Developers Blog, May 19, 2026: "up to 76 tokens/sec decode" for Gemma 4 E2B on WebGPU, in Chrome on a 2024 MacBook Pro with M4 Max. The web runtime "runs on WASM and is powered by WebGPU", with a JS API at ai.google.dev/edge/litert-lm/js. The post mentions no browser other than Chrome and gives no web TTFT or prefill figures in its text. — [Google Developers Blog](https://developers.googleblog.com/blazing-fast-on-device-genai-with-litert-lm/)
- (search excerpt) A Nearform write-up reports about 75 tok/s for E2B on LiteRT-LM.js on an M5 Max, and calls the figure anecdotal. It also attributes to Google engineers the statement that E2B needs about 4 GB of free RAM in the browser. — [Nearform](https://nearform.com/digital-community/web-ai-runtimes-five-ways-to-run-a-language-model-in-the-browser/)

#### WebLLM (MLC)
- WebLLM paper, measured on an M3 Max MacBook Pro in Chrome Canary 133.0.6870.0 with WebLLM v0.2.75 against MLC-LLM commit d23d6f5, 4-bit models. Llama-3.1-8B decodes at 41.1 tok/s against 57.7 native (71.2%); Phi-3.5-mini at 71.1 against 89.3 (79.6%). The paper reports no prefill, memory or load-time numbers. v1 was posted in Dec 2024 and v2 on 13 Apr 2026. [>12 mo: the measurements use late-2024 builds] — [arXiv 2412.15803v2](https://arxiv.org/html/2412.15803v2)
- Dispatch-overhead study (Jędrzej Maczan, submitted 9 Feb 2026), WebLLM q4f16, Qwen2.5-Instruct. The author warns that each run generated only about 7 tokens, so these figures are noisier than the paper's native results. — [arXiv 2604.02344v1](https://arxiv.org/html/2604.02344v1)

  | Machine | Browser | 0.5B decode / prefill (tok/s) | 1.5B decode / prefill (tok/s) |
  |---|---|---|---|
  | MacBook Air M2 (8-core GPU, 16 GB), macOS 26.2 | Chrome 143 | 46.4 ± 0.2 / ~510 | 36.0 ± 0.4 / ~225 |
  | same | Safari 26.2 | 41.7 ± 0.5 / ~257 | 29.7 ± 0.3 / ~93 |
  | same | Firefox 147 | 9.6 / ~77 | 9.6 / ~58 |
  | Windows 11 laptop, RTX PRO 2000 Blackwell 8 GB | Chrome 144 (D3D12) | 51.1 ± 5.9 / ~650 | 45.7 ± 6.3 / ~350 |
  | same | Firefox 147 | 9.1 / ~73 | 9.1 / ~55 |

- Same study, cost per dispatch when dispatches are issued in sequence (µs): Chrome on an RTX 5090 under Linux/Vulkan 32.8; Chrome on the RTX PRO 2000 under D3D12 58.7; Chrome on an Intel iGPU under D3D12 66.5; Safari on M2/Metal 31.7; Firefox about 1,037–1,047 on every platform, which the author says is "consistent with rate-limiting". — [arXiv 2604.02344v1](https://arxiv.org/html/2604.02344v1)
- Follow-up paper by the same author (9 Aug 2026, v3 26 Oct 2026, accepted to COLM 2026 workshops): at batch size 1, dispatch overhead rather than kernel quality is the bottleneck, and dispatch count is the cause. Per-dispatch cost does not depend on data type. — [arXiv 2608.08730](https://arxiv.org/abs/2608.08730)
- (search excerpt, abstract only) A GPU-resident speculative-decoding runtime, Oct 2026, reports decoding 3.5–8.6× faster than WebLLM on three client GPUs. — [arXiv 2610.39761](https://arxiv.org/html/2610.39761v1)

#### Transformers.js / ONNX Runtime Web
- Transformers.js v4 (Hugging Face blog, 9 Feb 2026) ships a new WebGPU runtime "completely rewritten in C++". The blog's only LLM figure is GPT-OSS 20B (q4f16) at about 60 tok/s on an "M4 Pro Max" (sic). BERT-style embedding models run about 4× faster. Models larger than 8B parameters are now supported. The post has no benchmark table and no Safari, iOS or Android notes. — [HF blog: Transformers.js v4](https://huggingface.co/blog/transformersjs-v4)
- Practitioner report from May 2026 (no versions given): Gemma 4 E2B on Transformers.js with WebGPU ran at about 2 tok/s on an RTX 3050 laptop (6 GB VRAM). MediaPipe on the same machine ran it at 14–16 tok/s. — [DEV Community](https://dev.to/jpablortiz96/5-production-patterns-for-running-gemma-4-in-the-browser-what-the-docs-dont-tell-you-2ai1)

#### MediaPipe LLM Inference (web)
- Same May 2026 report, using `@mediapipe/tasks-genai` with WebGPU:
  - Gemma 4 E2B (`gemma-4-e2b-it-int4-web.task`) ran at 14–16 tok/s on the RTX 3050 6 GB laptop.
  - E4B spilled into shared system memory and dropped to about 1.8 tok/s.
  - On NVIDIA Optimus laptops, Chrome can route WebGPU to the Intel UHD iGPU (Chromium bug 369219127).
  - Source: [DEV Community](https://dev.to/jpablortiz96/5-production-patterns-for-running-gemma-4-in-the-browser-what-the-docs-dont-tell-you-2ai1)
- The litert-community repos still host MediaPipe `.task` web files: `gemma-4-E2B-it-web.task` (2 GB) and `gemma-4-E4B-it-web.task` (2.96 GB), both about 8 months old as of 2026-11-25 (roughly March 2026). — [E2B file list](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main); [E4B file list](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/tree/main)

#### llama.cpp/wllama on WebGPU ("LlamaWeb"): the only cross-device study that includes phones
- "Llamas on the Web" (UC Santa Cruz and Microsoft Research, arXiv v1 20 May 2026) extends wllama with WebGPU. Setup:
  - 16 GPUs from 8 vendors.
  - Chrome everywhere except iOS, where Safari is used. Firefox was excluded. No browser versions are given.
  - 512-token prefill, 128 decoded tokens, KV depths 0 and 2,048, 5 repetitions.
  - Source: [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Device clusters from that study (k-means on 40 features):
  - High: RTX 5080, RTX 5070, RTX 40-series, RX 7900 XT, Arc B580, M4 (32 GB), M3 (16 GB).
  - Mid: Intel Iris Xe iGPU, M2, Snapdragon X Elite, Galaxy S24 (Xclipse).
  - Low: iPhone 17 Pro Max, iPhone 15, Adreno 7xx, Mali (Valhall), PowerVR D-series.
  - Source: [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Throughput by cluster, same study:
  - High cluster: smaller models "reach above 3k tok/s during prefill and 100 tok/s during decode", "dropping to 65 tok/s during prefill and 30 tok/s during decode on the large gemma4 model" (Gemma 4 E2B, GGUF q4_k_m, 3.11 GB).
  - Low cluster: "decode in the range of 4–17 tok/s".
  - Llama-3.2-1B q4_k on the high cluster: 107 tok/s decode at KV depth 0 and 99 at depth 2,048.
  - Mid cluster prefill for Llama-3.2-1B: f16 152 tok/s against 79 for q4_k_m, so f16 prefill is faster.
  - Source: [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Same study, against other engines (geometric means over 4 GPUs, Transformers.js 4.0, WebLLM version not stated):
  - Decode: LlamaWeb is about 54% faster than WebLLM and about 69% faster than Transformers.js.
  - Prefill: LlamaWeb reaches only 49% of WebLLM's throughput and 79% of Transformers.js's.
  - Source: [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Same study: on an Apple M3, Llama-3.2-1B q4_k_m runs at "∼1 tok/s on Firefox, but ∼52 tok/s on Chrome". — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Same study: "Kernel compilation incurs a one-time cost (~1-5 seconds) during the first forward pass." A full benchmark sweep took about 10 minutes on a high-end discrete GPU and over an hour on low-power mobile GPUs. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)

#### Android Chrome
- wllama issue #307 (opened 7 Nov 2026): Pixel 10 Pro (Tensor G5, PowerVR GPU, adapter vendor `img-tec`), LFM2.5-350M Q4_K_M, llama.cpp wasm build 19cce69.
  - With the stock WebGPU path, generation ran at about 2.5 tok/s and prompt processing at about 40 tok/s, which was "slower than the CPU build".
  - After a vendor-specific path, generation reached about 38 tok/s and prompt processing about 700 tok/s (810 tok/s for a 3,000-token prompt).
  - "each queue wait costs a few ms on Android even with nothing in flight"; the scheduler waits about 20 times per token; a token takes about 450 dispatches.
  - Creating a pipeline for a new batch size costs tens of milliseconds.
  - Source: [wllama #307](https://github.com/ngxson/wllama/issues/307)
- Chrome enables WebGPU by default on Android 12+ devices with Qualcomm and ARM GPUs from Chrome 121. Chrome's troubleshooting page also lists Chrome 121 as the Android minimum. — [Chrome blog: New in WebGPU 121](https://developer.chrome.com/blog/new-in-webgpu-121); [Chrome WebGPU troubleshooting](https://developer.chrome.com/docs/web-platform/webgpu/troubleshooting-tips?hl=en)
- (search excerpt) On a OnePlus with an Adreno 6xx GPU, Android Chrome's adapter lacked `shader-f16`, so WebGPU offload fell back to CPU. — [wllama64 PR #13](https://github.com/actuallymentor/wllama64/pull/13)
- Transformers.js has an open report titled "WebGPU crash on Android Chrome running SmolVLM-256M-Instruct" (title only). — [transformers.js #1205](https://github.com/huggingface/transformers.js/issues/1205)

#### iPhone and iPad Safari
- Safari 26.0 (15 Sep 2025) shipped WebGPU on macOS, iOS, iPadOS and visionOS (search excerpt of the WebKit release post). — [WebKit: Features in Safari 26.0](https://webkit.org/blog/17333/webkit-features-in-safari-26-0/)
- The LlamaWeb study puts the iPhone 17 Pro Max and iPhone 15 in its low cluster (4–17 tok/s decode), and only its four smallest models (0.23–0.40 GB files) fit there. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- WebKit bug 311598 (filed 6 Apr 2026, still NEW), Safari 26 on iOS 26:
  - A llama.cpp WebGPU backend issues about 400–600 compute passes per forward pass, in batches of 16–32 command buffers. Queue waits stall and time out on iOS 26.3.1. The reporter says it seemed more stable on 26.4.
  - A WebKit engineer recommends one command buffer and says "We don't coalesce command buffers, so this might be creating GPU resource exhaustion".
  - Grouping 64 compute passes per command buffer was more stable.
  - Source: [WebKit bug 311598](https://bugs.webkit.org/show_bug.cgi?id=311598)
- llama-web-bridge keeps a cap of one GPU layer on Safari before 27 (decision D3 in its issue #257). Full offload on iOS 27+ is listed as a follow-up "with no device to measure it". — [llama-web-bridge #257](https://github.com/leehack/llama-web-bridge/issues/257)
- I found no published tok/s figure for WebLLM, Transformers.js or LiteRT-LM.js on an iPhone or iPad in Safari 26 or 27 (see Gaps).

#### Native ratios stated by sources
- LlamaWeb study, Llama-3.2-1B against llama-bench on the same GPUs:
  - RTX 5080: CUDA and Vulkan beat WebGPU by up to 10× on prefill and 2.5× on decode.
  - Apple M4 Pro: Metal beats WebGPU by over 2× on prefill and about 50% on decode.
  - Intel Arc B580: WebGPU with safety checks off beats SYCL by 23% (f16 prefill) and 10% (f16 decode).
  - WebGPU's safety checks cost 14–23% of prefill, and up to 42% on the RTX 5080.
  - Source: [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Dispatch study, M2: WebLLM in Chrome at 46.4 tok/s (q4f16) against native PyTorch MPS fp16 at 47.8 tok/s, about 97%. The precisions differ, so this is not like-for-like. — [arXiv 2604.02344v1](https://arxiv.org/html/2604.02344v1)

### Inferences
- Same-hardware ratios computed from the LiteRT-LM cards (M4 Max):

  | Model | Web decode / native GPU decode | Web prefill / native GPU prefill | Web TTFT vs native | Web decode vs native CPU |
  |---|---|---|---|---|
  | E2B | 73 / 160.2 = 46% | 4,853 / 7,835 = 62% | 1.09 s vs 0.1 s | 1.75× faster than CPU |
  | E4B | 44 / 101.1 = 44% | 1,590 / 2,560 = 62% | 1.75 s vs 0.4 s | 1.6× faster than CPU |

- The web TTFT is mostly fixed overhead, not compute. 1,024 tokens at 4,853 tok/s is about 0.21 s, yet TTFT is 1.09 s. The extra ~0.9 s probably goes to per-dispatch, synchronization and pipeline costs of the kind the dispatch papers measure. It should shrink relative to compute as prompts get longer.
- Across all sources, a design can expect browser decode at about 40–80% of native on Apple and NVIDIA desktops, with Chrome close to the top of that range. Prefill lands at about 10–60% of native, so long prompts suffer most. The ~97% figure is an outlier because it compares q4f16 in the browser with fp16 native.
- Decode speed in today's browser engines is limited by dispatch count, not model size. Qwen2.5-0.5B and 1.5B run at a similar 46–51 tok/s on the RTX PRO 2000, and Android pays "a few ms" per queue wait. Engine choice and kernel fusion matter more than parameter count for 0.3–2B models.
- No source measures the same model both natively and in the browser on a phone. As a rough, not like-for-like comparison: low-cluster phones manage 4–17 tok/s on models of 0.4 GB or less in the browser, while native LiteRT-LM runs the 2.6 GB Gemma 4 E2B at 52–56 tok/s on an S26 Ultra and an iPhone 17 Pro. The browser on phones looks several times slower and limited to much smaller models. Measure your own engine before relying on this.
- Treat Firefox's WebGPU as no usable GPU as of Firefox 147: about 1 ms per dispatch and 1–10 tok/s.

### Gaps
- No vendor or independent browser numbers for Gemma 4 or LiteRT-LM.js on Android Chrome, iPhone/iPad Safari, Windows iGPUs, M1–M3 or M5 Macs (except the anecdotal M5 Max figure), or Safari on macOS.
- No per-device tok/s tables for WebLLM, Transformers.js or MediaPipe on phones. The LlamaWeb study's per-device figures are only in plots (Figs. 8–11); its text gives cluster ranges.
- No CPU-only WASM (wllama, multi-threaded) benchmark with stated hardware and versions turned up in this pass.
- No Qwen3.5 in-browser speed numbers were found, although WebLLM ships Qwen3.5 builds.
- No source gives load time from a warm cache for any engine. LiteRT-LM's TTFT deliberately excludes load.
- Several GitHub items surfaced in search returned HTTP 404 when opened, so I excluded their claims. They were onnxruntime #33753, #33793 and #33751, which claimed a ~900-token single-pass prefill crash of Safari's GPU process on iOS 27, a ~2 GB tab ceiling, and tab death past ~4,096 tokens on an iPhone 16 Pro Max; and camsteinberg/eco PR #406, which claimed a WebLLM loader killed near 1.5 GB on iPhone. Treat these as unverified leads.

## 2. Memory ceilings (iOS Safari jetsam, Android Chrome, desktop) and KV-cache memory at 4K/8K/32K

### Takeaway
iOS Safari is the binding constraint. The best evidence is a jetsam "ActiveHard" limit of about 2 GiB (2,097,154 KiB) on the WebContent process: iPhone 17 Pro, iOS 26.5, November 2026. A Worker does not get its own budget. Load-time copies of the model count against the limit, so an 805 MB model was killed until the loader was fixed. An academic study measured an even tighter "<500 MB" budget on its iPhone. Android Chrome and desktop browsers have no documented per-tab LLM ceiling. Desktop tabs survived multi-GB peaks, up to about 10 GB in leak cases. KV cache is small for Gemma 3/3n/4 and Qwen3.5, roughly 30–530 MiB at 32K, because of sliding windows, KV sharing and linear attention. For dense Llama, Qwen3 and Phi models it is large: 0.45–0.58 GiB at 4K and 3.5–4.5 GiB at 32K for the 3–4B models.

### Cited Findings

#### iOS / iPadOS Safari
- llama-web-bridge issue #257, opened 20 Nov 2026 and closed 21 Nov 2026 by PR #281:
  - Device: iPhone 17 Pro on iOS 26.5; RAM not stated.
  - The issue cites the "WebContent process's 2048 MB memory limit". System logs record kills at the "ActiveHard limit (2,097,154 KiB)" in direct mode and at 2,097,266 KiB in Worker mode.
  - Qwen3-0.6B Q8_0 (804,753,632 bytes) was killed during load, with `nCtx: 512`. Qwen3-0.6B Q4_K_M (396,704,416 bytes) loaded and generated in both modes.
  - The maintainer's analysis: "A peak above 2 GB for an 805 MB model means the load holds the model in memory more than once."
  - After the fix, 17 of 17 cases passed on the iPhone 17 Pro with no jetsam kill.
  - Source: [llama-web-bridge #257](https://github.com/leehack/llama-web-bridge/issues/257)
- Same issue, on WebKit storage: Cache Storage holds a whole entry's body in WebContent, and `cache.match` returns it as one 767.5 MiB chunk. On macOS Safari 27, a 767.5 MiB `cache.put` alone peaked at 2,331 MB. The fix stores models as 16 MiB part entries with the manifest written last. — [llama-web-bridge #257](https://github.com/leehack/llama-web-bridge/issues/257)
- Same issue, load-peak memory before → after the fix: Chromium 1,805 → ~1,085 MB; macOS Safari 2,650 → 1,871 MB. Cold load with the default cache 3,727 → ~1,345 MB; reload from cache 3,031 → ~1,500 MB; prefetch 2,392 → ~220 MB. — [llama-web-bridge #257](https://github.com/leehack/llama-web-bridge/issues/257)
- LlamaWeb study (May 2026): "on iOS devices Safari tab memory is limited to <500 MB". It does not say which iPhone, which iOS version, or how this was measured. Gemma 4 E2B "did not run on an iPhone with a tight tab-memory cap". Low-cluster devices "were only able to fit the four smallest models": LFM2.5-350M (0.23 GB), Bonsai-1.7B 1-bit (0.25 GB), Gemma3-270M (0.25 GB) and Qwen3-0.6B (0.40 GB), all q4_k_m GGUF except Bonsai. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- A WebKit engineer in bug 302711 (Nov–Dec 2025): "iOS will terminate due to memory pressure whereas macOS will not until it reaches much higher thresholds." — [WebKit bug 302711](https://bugs.webkit.org/show_bug.cgi?id=302711)
- The LiteRT-LM card's native iOS footprint for Gemma 4 on an iPhone 17 Pro (GPU, `phys_footprint`) is 1,450 MB for E2B and 3,380 MB for E4B. — [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm); [E4B card](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)
- (search excerpt, secondary blog) "Safari's Metal backend imposes per-buffer limits that range from 256MB on older iPhones to 993MB on iPad Pro." — [TianPan.co, Apr 2026](https://tianpan.co/blog/2026-04-17-browser-native-llm-inference-webgpu)

#### Android Chrome
- LlamaWeb study: Adreno 7xx, Mali and PowerVR devices fit only the four smallest models. On Mali and PowerVR, LFM2.5, Gemma3-270M, Qwen3-0.6B and Qwen3.5-2B ran at KV depth 0 "but crashed at depth 2048". The Galaxy S24 (Xclipse) was in the mid cluster with no failures reported. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Chrome's troubleshooting guidance treats repeated GPU-process crashes as a reload-or-restart condition. — [Chrome WebGPU troubleshooting](https://developer.chrome.com/docs/web-platform/webgpu/troubleshooting-tips?hl=en)
- (search excerpt) Chrome 121's Android launch notes say the adapter's memory heap sizes can be read through the adapter info only behind a developer-features flag. — [Chrome blog: New in WebGPU 121](https://developer.chrome.com/blog/new-in-webgpu-121)
- The LiteRT-LM card's native Android footprint on the S26 Ultra (GPU, `ru_maxrss`) is 676 MB for E2B and 710 MB for E4B. The GPU-side allocation is not included in that metric. — [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm); [E4B card](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)

#### Desktop
- WebGPU's default limits are `maxBufferSize` 268,435,456 bytes (256 MiB) and `maxStorageBufferBindingSize` 134,217,728 bytes (128 MiB). Adapters may expose more (search excerpt). — [MDN GPUSupportedLimits](https://developer.mozilla.org/en-US/docs/Web/API/GPUSupportedLimits)
- LiteRT-LM web GPU memory on the M4 Max is about 1,800 MB for E2B and about 3,300 MB for E4B. Native GPU on the same machine uses 1,623 MB and 3,217 MB. — [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm); [E4B card](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)
- LlamaWeb study, peak memory for f16 Llama-3.2-1B:
  - Leaks: Transformers.js in Safari on an M4 Pro grew to about 10 GB until the tab was killed; WebLLM on an RTX 5080 under Windows also grew to about 10 GB, with no crash reported.
  - Savings: LlamaWeb used 13–61% less memory than WebLLM and 16–59% less than Transformers.js, depending on device and browser.
  - Source: [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- WebKit bug 311598: in a later comment the reporter says a Transformers.js demo "crashed due to increasing memory" in Safari on an M3 MacBook. — [WebKit bug 311598](https://bugs.webkit.org/show_bug.cgi?id=311598)
- Practitioner rule of thumb (May 2026): keep the model in dedicated VRAM after reserving about 1.5 GB for browser and system overhead. E4B (~3 GB) "needs 8 GB+ VRAM"; on a 6 GB RTX 3050 it spilled to shared memory and ran at about 1.8 tok/s. — [DEV Community](https://dev.to/jpablortiz96/5-production-patterns-for-running-gemma-4-in-the-browser-what-the-docs-dont-tell-you-2ai1)
- Chrome's own gate for its built-in Gemini Nano: a GPU with more than 4 GB VRAM, or 16 GB RAM and 4+ CPU cores; at least 22 GB free on the profile drive; Windows 10/11, macOS 13+, Linux, and ChromeOS on Chromebook Plus only. Android and iOS are not supported. [>12 mo: page last updated 20 May 2025] — [Chrome built-in AI: get started](https://developer.chrome.com/docs/ai/get-started)
- Firefox bug title (search result): "WebGPU queue.writeBuffer() fails when WebAssembly heap size > 2GB (i.e. Wasm4GB and Wasm64 modes are not supported)". — [Mozilla bug 2022805](https://bugzilla.mozilla.org/show_bug.cgi?id=2022805)

#### WebLLM's per-model memory requirements (`vram_required_MB`, main branch, fetched 2026-11-25; prebuilt records default to a 4,096-token context)
- Source for all rows: [web-llm src/config.ts](https://raw.githubusercontent.com/mlc-ai/web-llm/main/src/config.ts)

  | Model (q4f16_1 unless noted) | vram_required_MB | low_resource_required |
  |---|---|---|
  | gemma3-1b-it (`sliding_window_size: -1`) | 711.07 | true |
  | Llama-3.2-1B-Instruct | 879.04 | true |
  | Qwen3-0.6B | 1,403.34 | true |
  | Qwen3.5-0.8B | 1,629.49 | true |
  | SmolLM2-1.7B-Instruct | 1,774.19 | true |
  | Qwen3-1.7B | 2,036.66 | true |
  | SmolLM3-3B (needs shader-f16) | 2,053.32 | false |
  | Qwen3.5-2B | 2,245.44 | false |
  | Llama-3.2-3B-Instruct | 2,263.69 | true |
  | Gemma 4 E2B (gemma-4-E2B-it-q4f16_1-MLC) | 3,387.37 | not reported |
  | Qwen3-4B | 3,431.59 | true |
  | Phi-4-mini-instruct | 3,437.58 | false |
  | Phi-3.5-mini-instruct | 3,672.07 (2,520.07 for the `-1k`, 1,024-token variant) | false (true for `-1k`) |
  | Qwen3.5-4B | 3,867.82 | false |
  | q4f32 variants | about 15–40% higher, e.g. Qwen3-4B 4,327.71; Llama-3.2-3B 2,951.51 | — |

#### KV-cache inputs (from each model's config.json)
- Dense attention models:
  - Llama-3.2-1B: 16 layers, 8 KV heads, head_dim 64. — [config](https://huggingface.co/unsloth/Llama-3.2-1B-Instruct/blob/main/config.json)
  - Llama-3.2-3B: 28 layers, 8 KV heads, head_dim 128. — [config](https://huggingface.co/unsloth/Llama-3.2-3B-Instruct/blob/main/config.json)
  - Qwen3-0.6B and Qwen3-1.7B: 28 layers, 8 KV heads, head_dim 128. — [0.6B config](https://huggingface.co/Qwen/Qwen3-0.6B/blob/main/config.json); [1.7B config](https://huggingface.co/Qwen/Qwen3-1.7B/blob/main/config.json)
  - Qwen3-4B: 36 layers, 8 KV heads, head_dim 128. — [config](https://huggingface.co/Qwen/Qwen3-4B/blob/main/config.json)
  - Phi-4-mini: 32 layers, 8 KV heads, hidden 3,072 over 24 heads, so head_dim 128. — [config](https://huggingface.co/microsoft/Phi-4-mini-instruct/blob/main/config.json)
  - SmolLM3-3B: 36 layers, 4 KV heads, head_dim 128. — [config](https://huggingface.co/HuggingFaceTB/SmolLM3-3B/blob/main/config.json)
- Gemma 3 (1 KV head, head_dim 256, 512-token sliding window):
  - 270M: 18 layers, 15 sliding and 3 full. — [config](https://huggingface.co/unsloth/gemma-3-270m-it/blob/main/config.json)
  - 1B: 26 layers, with a sliding-window pattern of 6, giving 4 full layers. — [config](https://huggingface.co/unsloth/gemma-3-1b-it/blob/main/config.json)
- Gemma 3n (2 KV heads, head_dim 256, 512-token window):
  - E2B: 30 layers, 24 sliding and 6 full; `num_kv_shared_layers` 10. — [config](https://huggingface.co/unsloth/gemma-3n-E2B-it/blob/main/config.json)
  - E4B: 35 layers, 28 sliding and 7 full; `num_kv_shared_layers` 15. — [config](https://huggingface.co/unsloth/gemma-3n-E4B-it/blob/main/config.json)
- Gemma 4 (512-token window, sliding head_dim 256, `global_head_dim` 512):
  - E2B: 35 layers, 28 sliding and 7 full; 1 KV head; `num_kv_shared_layers` 20. — [config](https://huggingface.co/unsloth/gemma-4-E2B-it/blob/main/config.json)
  - E4B: 42 layers, 35 sliding and 7 full; 2 KV heads; `num_kv_shared_layers` 18. — [config](https://huggingface.co/unsloth/gemma-4-E4B-it/blob/main/config.json)
  - The model card describes "hybrid local sliding-window and full global attention" with a 512-token window, and global layers with "unified Keys and Values". — [Gemma 4 model card](https://gemma.ai/models/gemma-4/model-card/)
- Qwen3.5 (repeating pattern of 3 Gated DeltaNet linear-attention layers then 1 full-attention layer):
  - 0.8B and 2B: 24 layers, 6 full, 2 KV heads, head_dim 256. — [0.8B config](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/main/config.json); [2B config](https://huggingface.co/Qwen/Qwen3.5-2B/blob/main/config.json)
  - 4B: 32 layers, 8 full, 4 KV heads, head_dim 256. — [4B config](https://huggingface.co/Qwen/Qwen3.5-4B/blob/main/config.json); [Qwen3.5-4B card](https://huggingface.co/Qwen/Qwen3.5-4B)

### Inferences
- KV-cache size per sequence, which I computed from the config values above. Assumptions: fp16 K and V; sliding-window layers hold only 512 tokens, as in a ring-buffer implementation; KV-shared layers store nothing of their own; for Gemma 4, global layers use the sliding-layer KV-head count with head_dim 512. The figures exclude weights, activations and workspace. q4f32 engines that keep KV in f32 need twice as much.

  | Model | 4K | 8K | 32K | If every layer cached the full context (naive engine) |
  |---|---|---|---|---|
  | Llama-3.2-1B (32 KiB/token) | 128 MiB | 256 MiB | 1,024 MiB | same |
  | Llama-3.2-3B (112 KiB/token) | 448 MiB | 896 MiB | 3,584 MiB | same |
  | Qwen3-0.6B / Qwen3-1.7B (112 KiB/token) | 448 MiB | 896 MiB | 3,584 MiB | same |
  | Qwen3-4B (144 KiB/token) | 576 MiB | 1,152 MiB | 4,608 MiB | same |
  | Phi-4-mini (128 KiB/token) | 512 MiB | 1,024 MiB | 4,096 MiB | same |
  | SmolLM3-3B (72 KiB/token) | 288 MiB | 576 MiB | 2,304 MiB | same |
  | Gemma 3 270M | 20 MiB | 32 MiB | 104 MiB | 72 / 144 / 576 MiB |
  | Gemma 3 1B | 27 MiB | 43 MiB | 139 MiB | 104 / 208 / 832 MiB |
  | Gemma 3n E2B | 48 MiB | 80 MiB | 272 MiB | 240 / 480 / 1,920 MiB |
  | Gemma 3n E4B | 48 MiB | 80 MiB | 272 MiB | 280 / 560 / 2,240 MiB |
  | Gemma 4 E2B | 30 MiB | 54 MiB | 198 MiB | ~140 / 280 / 1,120 MiB |
  | Gemma 4 E4B | 84 MiB | 148 MiB | 532 MiB | ~336 / 672 / 2,688 MiB |
  | Qwen3.5-0.8B / Qwen3.5-2B | 48 MiB (+~9 MiB fixed DeltaNet state) | 96 MiB | 384 MiB | — |
  | Qwen3.5-4B | 128 MiB (+~24 MiB fixed state) | 256 MiB | 1,024 MiB | — |

- These numbers explain WebLLM's figures. Qwen3-0.6B needs 1,403 MB of VRAM against 879 MB for the larger Llama-3.2-1B, and at 4K its KV cache is 448 MiB against 128 MiB. WebLLM sets `sliding_window_size: -1` for gemma3-1b, which suggests it allocates the naive full-context cache rather than the sliding-window one. Engine choice can therefore change KV memory by 4–8× for Gemma models.
- On iOS, a ~2 GiB WebContent ceiling must hold the model's CPU-side copies, staging buffers, the WASM heap and possibly WebGPU staging. In practice only models up to roughly 0.4–0.8 GB fit, at short context (512–2K). Dense 1–4B models at 4K+ context do not fit: their KV cache alone is 0.45–0.58 GB for the 3–4B dense models. The Gemma 4 E2B web build (2.0–2.34 GB file, ~1.8 GB GPU memory on desktop) is very unlikely to load in iPhone Safari as of iOS 26.5.
- Moving the model into a Worker does not buy memory on iOS. The Worker run hit the same ActiveHard limit (2,097,266 KiB). A same-site iframe most likely shares the parent page's WebContent or renderer process as well. That is my inference; no source here tests the iframe case.
- On desktop, tabs survived peaks of 2.3–3.7 GB in Safari 27 and Chromium, and about 10 GB in leak cases, so the working ceiling is set by VRAM or unified memory rather than a browser cap. A 6 GB dGPU cannot hold E4B in dedicated VRAM; once it spills to shared memory, decode collapses to about 1.8 tok/s.
- Use chunked storage, not one Cache Storage entry per model. WebKit keeps a whole entry in WebContent, so one 2 GB entry would alone exceed the iOS ceiling. Store 16 MiB parts, or use OPFS, which the LlamaWeb study streams through four 1 MB buffers.

### Gaps
- No source measures which model sizes load on 6 GB, 8 GB and 12 GB iPhones separately. The 2 GiB limit comes from one device on iOS 26.5. The "<500 MB" claim names no device or iOS version. No iPad data turned up.
- No iOS 27 / Safari 27 measurements on iPhone were found.
- The jetsam limit for Safari's GPU process (com.apple.WebKit.GPU), where WebGPU buffers may be accounted, is undocumented.
- Android Chrome's renderer and GPU-process memory caps, and the low-memory-killer thresholds that apply to large WebGPU allocations, are undocumented. No Chromium bug confirming them turned up.
- I did not verify per-device `maxBufferSize` or `maxStorageBufferBindingSize` values for iOS Safari, Android Chrome or macOS. Search excerpts mentioned ~2 GiB on an M1 Max in Safari 17.4 and 16 GiB in one comparison gist. The web3dsurvey.com per-platform pages are the place to check.
- No measured KV-cache allocation for LiteRT-LM web or Transformers.js was found. The table above is theoretical.

## 3. Practical models per device class, with tool-calling and instruction-following quality

### Takeaway
On sizes the browser can hold, three tiers emerge. iPhones and low-end Android can run 0.25–0.4 GB models (Gemma 3 270M, Qwen3-0.6B Q4, LFM2.5-350M), which are weak at tool calling. Mid-range desktops and flagship Android can run about 1–2.3 GB (Gemma 4 E2B web, Qwen3.5-2B, Qwen3-1.7B, Llama-3.2-1B/3B). Only well-equipped desktops can run 3–4 GB (Gemma 4 E4B web, Qwen3.5-4B, Qwen3-4B, Phi-4-mini, SmolLM3-3B). On vendor-reported agentic and tool-use scores, Qwen3.5-4B (BFCL-V4 50.3, TAU2 79.9) and Qwen3.5-2B (BFCL-V4 43.6, TAU2 48.8) lead their sizes. Gemma 4 E4B and E2B report Tau2 42.2% and 24.5% but come with the fastest web runtime. Sub-1B models score poorly on every tool-use benchmark.

### Cited Findings

#### Browser-relevant sizes per model
- Gemma 4 LiteRT-LM files:
  - E2B: `-web.litertlm` 2.01 GB (about 6 months old as of 2026-11-25); `-gpu.litertlm` 2.34 GB (about 15 days old), which is the build in the card's current web benchmark; native `.litertlm` 2.59 GB.
  - E4B: `-web.litertlm` 2.97 GB; `-gpu.litertlm` 3.31 GB; native 3.66 GB.
  - Sources: [E2B files](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main); [E4B files](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/tree/main)
- The E4B native file (3.66 GB) includes 2.24 GB of decoder weights and 0.67 GB of embedding parameters. The embeddings are memory-mapped, and the vision and audio parts load on demand. — [E4B card](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)
- Gemma 4 parameter counts: E2B is "2.3B effective (5.1B with embeddings)" and E4B "4.5B effective (8B with embeddings)", both with 128K context. The LiteRT-LM card says the web variant supports up to 128K context, while the benchmarks use 2,048. — [Gemma 4 model card](https://gemma.ai/models/gemma-4/model-card/); [E2B LiteRT card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- GGUF file sizes used in the LlamaWeb study (q4_k_m unless noted): LFM2.5-350M 0.23 GB; Bonsai-1.7B (q1_0) 0.25 GB; Gemma3-270M 0.25 GB; Qwen3-0.6B 0.40 GB; Granite4-1B 0.90 GB; Qwen3.5-2B 1.28 GB; SmolLM3-3B 1.92 GB; Ministral3-3B 2.15 GB; Gemma4-E2B 3.11 GB; Llama3.2-1B 0.81 GB (0.58 GB q2_k, 1.32 GB q8_0, 2.48 GB f16). — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Qwen3.5 ships in 0.8B, 2B, 4B and 9B sizes, not 0.6B, 1.7B and 4B. All have WebLLM builds. — [web-llm config.ts](https://raw.githubusercontent.com/mlc-ai/web-llm/main/src/config.ts)
- WebLLM has no Gemma 3 270M or Gemma 3n records. Its `functionCallingModelIds` lists only Hermes-2-Pro-Llama-3-8B and Hermes-3-Llama-3.1-8B, at 4,876–6,051 MB VRAM. — [web-llm config.ts](https://raw.githubusercontent.com/mlc-ai/web-llm/main/src/config.ts)

#### Tool calling and instruction following (vendor-reported unless noted; BFCL v2, v3 and v4 are different suites and not comparable)
- Qwen3.5 (released Feb 2026; per the cards, thinking-mode scores):
  - 4B: BFCL-V4 50.3, TAU2-Bench 79.9, IFEval 89.8, IFBench 59.2, MMLU-Pro 79.1. 9B for reference: BFCL-V4 66.1, TAU2 79.1. — [Qwen3.5-4B card](https://huggingface.co/Qwen/Qwen3.5-4B)
  - 2B: BFCL-V4 43.6, TAU2 48.8, IFEval 78.6 (61.2 non-thinking), IFBench 41.3.
  - 0.8B: BFCL-V4 25.3, TAU2 11.6, IFEval 44.0 (52.1 non-thinking), IFBench 21.0.
  - Qwen3-4B-2507 in the same table: BFCL-V4 39.9, TAU2 43.2, IFEval 87.4.
  - The 2B "is more prone to thinking loops" in thinking mode and defaults to non-thinking.
  - Source for 2B, 0.8B and 4B-2507: [Qwen3.5-2B card](https://huggingface.co/Qwen/Qwen3.5-2B)
- Qwen3, from the technical report (arXiv 2505.09388) [>12 mo: May 2025]:

  | Model | BFCL v3, thinking / non-thinking | IFEval strict, thinking / non-thinking |
  |---|---|---|
  | Qwen3-4B | 65.9 / 57.6 | 81.9 / 81.2 |
  | Qwen3-1.7B | 56.6 / 52.2 | 72.5 / 68.2 |
  | Qwen3-0.6B | 46.4 / 44.1 | 59.2 / 54.5 |

  The same report's non-thinking baselines: Phi-4-mini 31.3 BFCL v3 and 68.6 IFEval; Gemma-3-1B-IT 16.3 and 54.5; Qwen2.5-3B 50.4 and 58.2. — [Qwen3 Technical Report](https://arxiv.org/html/2505.09388)
- Llama 3.2 model card (released 25 Sep 2024) [>12 mo]:
  - BFCL V2: 1B 25.7, 3B 67.0. Nexus: 13.5 and 34.3. IFEval: 59.5 and 77.4.
  - Quantized 3B scores: SpinQuant BFCL V2 60.1, QLoRA 63.5.
  - Quantized 1B (SpinQuant) decodes at 50.2 tok/s on a OnePlus 12 CPU with ExecuTorch (native).
  - Source: [Llama-3.2-3B-Instruct card](https://huggingface.co/meta-llama/Llama-3.2-3B-Instruct)
- (search excerpt) The BFCL V4 leaderboard lists Llama-3.2-3B-Instruct (FC) at 21.95 overall (rank 98) and Gemma-3-4b-it (Prompt) at 19.62 (rank 101). The snapshot seen was about 227 days old. — [BFCL V4 leaderboard](https://gorilla.cs.berkeley.edu/leaderboard.html)
- SmolLM3-3B card (Hugging Face's own evaluation; release date not stated on the card):
  - BFCL: 92.3 non-thinking, 88.8 thinking. Qwen3-1.7B 89.5 / 88.8; Qwen3-4B 95.0 / 95.5.
  - IFEval: 76.7 non-thinking, 71.2 thinking. Qwen3-1.7B 74.0 / 74.2; Qwen3-4B 68.9 / 85.4.
  - 64K training context, up to 128K with YaRN.
  - Source: [SmolLM3-3B card](https://huggingface.co/HuggingFaceTB/SmolLM3-3B)
- Gemma 4 model card (2026):
  - Tau2 (average over 3): E2B 24.5%, E4B 42.2%. MMLU Pro 60.0% and 69.4%. LiveCodeBench v6 44.0% and 52.0%.
  - "Native support for structured tool use".
  - No BFCL or IFEval figures.
  - Source: [Gemma 4 model card](https://gemma.ai/models/gemma-4/model-card/)
- Gemma 3n model card: E2B and E4B IT score MMLU-Pro 40.5 and 50.6, MMLU 60.1 and 64.9, and LiveCodeBench v5 18.6 and 25.7, with 32K context. The card has no IFEval, BFCL or tau-bench rows. [>12 mo likely: 2025 model] — [Gemma 3n model card](https://gemma.ai/models/gemma-3n/model-card/)
- Gemma 3 270M: Google reports IFEval 51.2 [>12 mo: Aug 2025]. A Hugging Face discussion reports reproductions of only 20–27%, and Google said it was investigating. (search excerpt) The Gemma 3 model card gives IFEval 80.2 for the 1B IT model; the Qwen3 report measured 54.5 strict for Gemma-3-1B-IT. — [The Register](https://www.theregister.com/2025/08/15/little_llm_on_the_ram/); [HF discussion](https://huggingface.co/google/gemma-3-270m-it/discussions/4); [Gemma 3 model card](https://ai.google.dev/gemma/docs/core/model_card_3)
- (search excerpt) An Aug 2026 paper reports that on BFCL, Phi-4-mini's official decoder "finds a call in none of its answers", so its score depends heavily on the parser. After fine-tuning it reached 74.5 non-live and 63.8 live. — [arXiv 2608.22472](https://arxiv.org/pdf/2608.22472)
- Practitioner report on Gemma 4 E2B through MediaPipe web: strict "JSON only" prompts worked about 70% of the time. — [DEV Community](https://dev.to/jpablortiz96/5-production-patterns-for-running-gemma-4-in-the-browser-what-the-docs-dont-tell-you-2ai1)

### Inferences
- Suggested default per device class. This is my synthesis from the measurements above, not a published recommendation.

  | Device class (how to recognise it, see section 6) | Evidence | Suggested default / ceiling |
  |---|---|---|
  | Desktop high: Chrome or Edge on Apple M3/M4/M5 with 16 GB+, or an NVIDIA/AMD dGPU with 8 GB+ VRAM | LiteRT-LM web E4B 44 tok/s and E2B 73–76 tok/s on M4 Max; LlamaWeb "high" cluster | Gemma 4 E4B web (`-gpu`, ~3.3 GB GPU memory) or Qwen3.5-4B (WebLLM 3.87 GB) when tool use matters most; E2B when latency matters |
  | Desktop mid: M1/M2 base, 8 GB Macs, Intel Iris Xe/Lunar Lake or AMD iGPU, dGPU of 6 GB or less | M2 is in the "mid" cluster (WebLLM in Chrome: 46 / 36 tok/s at 0.5B / 1.5B); E4B on 6 GB VRAM collapses to 1.8 tok/s | Gemma 4 E2B web (~1.8 GB) or Qwen3.5-2B (WebLLM 2.25 GB); context of 4–8K |
  | Android flagship: Chrome 121+, Android 12+, shader-f16 present | Galaxy S24 in the "mid" cluster; no LiteRT-LM web data on phones | Start at 0.8–1.7B (Qwen3.5-0.8B / Qwen3-1.7B / Llama-3.2-1B, about 0.9–2 GB VRAM in WebLLM) at 2–4K context; attempt Gemma 4 E2B web only after a runtime probe |
  | Android mid/low: Mali, PowerVR, older Adreno, no shader-f16 | "Low" cluster, 4–17 tok/s; only models of 0.4 GB or less; crashes at KV depth 2,048 on Mali/PowerVR | Gemma 3 270M / Qwen3-0.6B Q4 / LFM2.5-350M with context of 2K or less, or no local model |
  | iPhone and iPad in Safari 26/27 | ~2 GiB WebContent ActiveHard limit (iPhone 17 Pro); "<500 MB" in the academic study; 805 MB Q8 killed before the loader fix | Models of 0.4 GB or less (Qwen3-0.6B Q4_K_M, 397 MB, loaded on iPhone 17 Pro); context 512–2K; Gemma 4 E2B web is not expected to load |
  | Firefox, any device | About 1 ms per dispatch, 1–10 tok/s | Treat as having no usable GPU; fall back to server or CPU |

- Tool-calling quality falls off sharply below about 2B. Qwen3.5-0.8B scores BFCL-V4 25.3 and TAU2 11.6; Gemma-3-1B scores BFCL v3 16.3; Llama-3.2-1B scores BFCL V2 25.7. The iPhone and low-Android tiers are therefore fit only for narrow tasks such as classification, extraction and short rewrites, not for agentic tool loops.
- Between Gemma 4 E2B and Qwen3.5-2B in the mid tier: Qwen3.5-2B reports better agentic scores (TAU2 48.8 against Gemma 4 E2B's Tau2 24.5%). Gemma 4 E2B has the only vendor-optimised, vendor-benchmarked web runtime, and it matches what the native apps ship. Neither model has a measured browser speed on phones.
- Do not compare BFCL numbers across sources. Hugging Face's SmolLM3 table shows Qwen3-4B at 95.0, while Qwen's own BFCL v3 gives 57.6–65.9. Use vendor numbers only within one table, or re-run a common harness.

### Gaps
- No single, current, independent BFCL-V4 run covers all the candidates. Gemma 3n and Gemma 4 have no published BFCL or IFEval scores, and Phi-4-mini's score depends on the parser.
- No head-to-head browser speed data exists for Qwen3.5 (WebLLM), SmolLM3, Phi-4-mini or Llama-3.2-3B on mobile.
- Gemma 3n web builds and their browser performance were not covered by any source found.

## 4. First-use cost: download size and time, warmup and shader compilation, load from cache

### Takeaway
The first visit is dominated by download time. At the May 2026 global median mobile speed (113 Mbps), a 2.0–2.34 GB Gemma 4 E2B web file takes about 2.4–2.8 minutes, the 2.97–3.31 GB E4B files about 3.5–3.9 minutes, and a 0.4 GB phone-tier model about 30 s. At 25 Mbps the Gemma files take 11–18 minutes. Shader and pipeline compilation adds about 1–5 s on the first forward pass. No source reports load time from a warm cache.

### Cited Findings
- Global medians in May 2026 (Speedtest-based): mobile download 113.16 Mbps, fixed broadband 125.47 Mbps. — [Statista](https://www.statista.com/statistics/896779/average-internet-connection-speed-worldwide/)
- US, first half of 2026 (Ookla, via IEEE ComSoc): T-Mobile median download 275.55 Mbps across all technologies (314.38 Mbps on 5G); AT&T Fiber median 374.75 Mbps. — [ComSoc Technology Blog](https://techblog.comsoc.org/2026/07/23/highlights-from-ooklas-u-s-speedtest-connectivity-report-mobile-fixed-networks/)
- File sizes: see section 3 (Gemma 4 web 2.01 / 2.34 / 2.97 / 3.31 GB; GGUF 0.23–3.11 GB). — [E2B files](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main); [E4B files](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/tree/main); [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- LlamaWeb: kernel compilation costs about 1–5 s, once, during the first forward pass. Weights stream from OPFS through four 1 MB buffers. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)
- Pixel 10 Pro (Chrome, wllama): "Pipeline creation at a new batch size costs tens of ms"; generic flash-attention shaders took 140 ms per layer for a 512-token batch. — [wllama #307](https://github.com/ngxson/wllama/issues/307)
- LiteRT-LM's published TTFT (1.09 s for E2B web, 1.75 s for E4B web) excludes load time and assumes caches are "enabled and initialized". The card warns that "first-run latency and memory may differ". — [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm); [E4B card](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm)
- Cache behaviour matters for memory, not only time. Loading from the default cache peaked at 3,031 MB before the fix and ~1,500 MB after. WebKit's Cache Storage returns a whole entry as one chunk, hence the move to 16 MiB part entries; OPFS is listed as a follow-up. — [llama-web-bridge #257](https://github.com/leehack/llama-web-bridge/issues/257)
- Transformers.js v4 adds `env.useWasmCache` to cache the WASM runtime files for offline use after the first load. — [HF blog: Transformers.js v4](https://huggingface.co/blog/transformersjs-v4)
- Chrome's built-in model download requires an "unlimited or unmetered connection" and at least 22 GB free. If free space drops below 10 GB, Chrome removes the model. [>12 mo] — [Chrome built-in AI: get started](https://developer.chrome.com/docs/ai/get-started)

### Inferences
- Ideal download times, computed as size × 8 / speed with decimal GB and no protocol or CDN overhead:

  | File | 25 Mbps | 50 Mbps | 113 Mbps (global mobile median, May 2026) | 300 Mbps |
  |---|---|---|---|---|
  | Qwen3-0.6B Q4_K_M GGUF, 0.40 GB | 2.1 min | 1.1 min | 28 s | 11 s |
  | Llama-3.2-1B q4_k_m, 0.81 GB | 4.3 min | 2.2 min | 57 s | 22 s |
  | Qwen3.5-2B q4_k_m, 1.28 GB | 6.8 min | 3.4 min | 90 s | 34 s |
  | Gemma 4 E2B `-web`, 2.01 GB | 10.7 min | 5.4 min | 142 s | 54 s |
  | Gemma 4 E2B `-gpu`, 2.34 GB | 12.5 min | 6.2 min | 165 s | 62 s |
  | Gemma 4 E4B `-web`, 2.97 GB | 15.8 min | 7.9 min | 210 s | 79 s |
  | Gemma 4 E4B `-gpu`, 3.31 GB | 17.7 min | 8.8 min | 234 s | 88 s |

- A design should download in the background, resumably, in 16 MiB-class chunks into OPFS or chunked Cache Storage. It should not block first use on the download. It should gate multi-GB downloads on an explicit user choice or on an unmetered connection, as Chrome does for its own model.
- Budget 1–5 s of one-time shader and pipeline compilation per session and per new batch-size shape, on top of reading weights from disk into GPU memory. Prefill the system prompt and warm up during idle time.

### Gaps
- I found no measured cold-start or warm-cache load times (disk to GPU-ready) for any engine on any device.
- No published shader-compile breakdown exists for LiteRT-LM.js, WebLLM or Transformers.js v4, nor any figure for how much browser shader caching between sessions helps.

## 5. Thermal throttling and battery drain under sustained WebGPU inference

### Takeaway
I found no controlled study of sustained WebGPU LLM inference in a browser. The best native evidence (March/June 2026, Qwen2.5-1.5B 4-bit) shows phones throttle within seconds. An iPhone 16 Pro lost nearly half its throughput within two iterations, and a Galaxy S24 Ultra hit an OS-enforced GPU frequency floor that ended inference. A laptop RTX 4050 ran at 131.7 tok/s at 34.1 W. The browser path should be expected to throttle at least as much.

### Cited Findings
- "LLM Inference at the Edge: Mobile, NPU, and GPU Performance Efficiency Trade-offs Under Sustained Load" (v1 24 Mar 2026, v2 7 Jun 2026):
  - Workload: Qwen 2.5 1.5B, 4-bit, a fixed 258-token prompt, 20 warm iterations per device.
  - The iPhone 16 Pro "loses nearly half its throughput within two iterations".
  - The Galaxy S24 Ultra hits an OS-enforced GPU frequency floor that ends inference entirely.
  - The RTX 4050 laptop ran at about 131.7 tok/s at 34.1 W; a Hailo-10H NPU at about 6.9 tok/s under 2 W.
  - No browser or WebGPU runs are included.
  - Source: [arXiv 2603.23640](https://arxiv.org/abs/2603.23640)
- (search excerpt of the same paper's PDF) The S24 Ultra run "yielded only 6 iterations before the OS intervened". The iPhone 16 Pro recorded about a 10% battery drop over 20 iterations, and "power per inference cannot be directly measured". — [arXiv 2603.23640 PDF](https://arxiv.org/pdf/2603.23640v1)
- MDN on `powerPreference: "high-performance"`: use it only when necessary, because it "may reduce battery life and increase GPUDevice loss". — [MDN requestAdapter](https://developer.mozilla.org/en-US/docs/Web/API/GPU/requestAdapter)
- The LlamaWeb study notes benchmark sweeps took "over an hour on low-power mobile GPUs". This is a duration, not a thermal measurement. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)

### Inferences
- On phones, sustained generation (long answers, agent loops) will settle well below the peak tok/s that short benchmarks report. A design should cap generation length on phones, prefer short bursts, and watch tokens per second at runtime to detect throttling, for example falling back or pausing when throughput drops by 40% or more.
- On laptops, the battery power ceiling (per the RTX 4050 result) and the low-power/high-performance adapter choice change both speed and drain. `powerPreference: "low-power"` may pick the iGPU on dual-GPU laptops, the same routing problem seen on Optimus machines.

### Gaps
- No measured battery drain (% per hour or J/token) for in-browser WebGPU inference on any phone or laptop.
- No sustained-load browser measurement (minutes of continuous decode) on Android Chrome, iOS Safari or laptops.
- Practitioner claims seen only in search excerpts, such as about 30 s of phone GPU inference before throttling, Android Chrome at 40–60% of desktop Chrome on the same chip, and 12–24% battery per hour on a budget phone with native apps, could not be tied to verified pages. One candidate source is [DEV: Running a coaching LLM in the browser](https://dev.to/renato_silva_71eef0fc385f/running-a-coaching-llm-in-the-browser-what-webgpu-really-costs-k05). Treat these as unverified.

## 6. Device detection from JavaScript, and how existing engines choose or refuse a model

### Takeaway
No API reports usable GPU memory, so a page has to combine coarse signals and finish with a probe. The signals are `navigator.deviceMemory` (Chrome 146+: buckets 2/4/8 on Android and 2/4/8/16/32 elsewhere, Chromium-only per MDN's "limited availability"), WebGPU adapter presence, `info` (vendor), features (`shader-f16`) and limits, `isFallbackAdapter`, and the browser engine. Existing engines gate by static per-model memory requirements (WebLLM's `vram_required_MB`, `low_resource_required` and `required_features`), by separate web-optimised builds (LiteRT-LM), by vendor checks (wllama's `img-tec` path) and by browser version (llama-web-bridge's Safari <27 cap). Chrome's own built-in AI uses VRAM, RAM, core and disk thresholds.

### Cited Findings

#### `navigator.deviceMemory`
- Chrome's Intent to Ship (Barry Pollard, 19 Jan 2026) changes the reported values from Chrome 146 on desktop, Android and WebView:
  - Old values on every platform: 0.25, 0.5, 1, 2, 4, 8.
  - New values: 2, 4, 8 on Android; 2, 4, 8, 16, 32 elsewhere. Android's upper bound stays at 8 because ">8GB RAM is still rare for mobile devices".
  - Kill switch: `kUpdatedDeviceMemoryLimitsFor2026`. Alex Russell gave an LGTM.
  - The entry is tagged with `Sec-CH-DeviceMemory`, which suggests the client hint changes too.
  - Source: [blink-dev Intent to Ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/vXtAmrVZeDk)
- MDN (last modified 6 Nov 2026): the value is "coarsened to a power of two value, clamped to implement-defined limits", with bounds that "may change over time". It is available only in secure contexts, also exists as `WorkerNavigator.deviceMemory`, and is marked "Limited availability" (not Baseline). — [MDN Navigator.deviceMemory](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/deviceMemory); [MDN WorkerNavigator.deviceMemory](https://developer.mozilla.org/en-US/docs/Web/API/WorkerNavigator/deviceMemory); [MDN Device-Memory header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Device-Memory)
- The W3C draft of Dec 2025 still recommends an 8 GiB upper bound and a 0.25 GiB lower bound. The 2026 drafts make the bounds implementation-defined, adjustable over time, and possibly different by device type (search excerpts). — [W3C WD 2025-12-11](https://www.w3.org/TR/2025/WD-device-memory-1-20251211/); [W3C Device Memory (latest)](https://www.w3.org/TR/device-memory-1/)

#### WebGPU adapter
- `navigator.gpu.requestAdapter()`:
  - `featureLevel` is `"core"` (the default) or `"compatibility"`, a restricted subset for OpenGL ES 3.1 / D3D11-class hardware.
  - `powerPreference` is `"low-power"` or `"high-performance"`, and is only a hint.
  - `forceFallbackAdapter` "is not yet supported by any browser".
  - The call resolves to `null` when no suitable adapter exists and throws no exceptions.
  - Pages should check `GPUAdapter.isFallbackAdapter` before `requestDevice()`.
  - It is available in Web Workers and only in secure contexts.
  - Source: [MDN GPU.requestAdapter](https://developer.mozilla.org/en-US/docs/Web/API/GPU/requestAdapter)
- Adapter vendor strings are usable for gating. wllama's PowerVR fast path is enabled only when the adapter vendor is `img-tec` (Pixel 10 Pro). — [wllama #307](https://github.com/ngxson/wllama/issues/307)
- WebLLM models with `shader-f16` in `required_features` fail on adapters without it, with "This model requires WebGPU extension shader-f16". q4f32 variants exist as the fallback. — [web-llm #254](https://github.com/mlc-ai/web-llm/issues/254); [web-llm config.ts](https://raw.githubusercontent.com/mlc-ai/web-llm/main/src/config.ts)
- (search excerpt) The adapter's memory heap sizes are exposed only behind Chrome's WebGPU developer-features flag (Chrome 121 Android notes), so they are not available to ordinary pages. — [Chrome blog: New in WebGPU 121](https://developer.chrome.com/blog/new-in-webgpu-121)
- WebGPU's default limits are 256 MiB `maxBufferSize` and 128 MiB `maxStorageBufferBindingSize`. Pages must request higher limits explicitly, from what the adapter offers (search excerpt). — [MDN GPUSupportedLimits](https://developer.mozilla.org/en-US/docs/Web/API/GPUSupportedLimits)

#### How engines and demos choose or refuse
- WebLLM:
  - Each prebuilt model record carries `vram_required_MB`, a `low_resource_required` flag, `required_features` and a context-window override (default 4,096).
  - Smaller-context `-1k` variants (1,024 tokens) exist for lower-memory devices, e.g. Phi-3.5-mini 3,672 → 2,520 MB.
  - Source: [web-llm config.ts](https://raw.githubusercontent.com/mlc-ai/web-llm/main/src/config.ts)
- LiteRT-LM ships separate web builds of Gemma 4 that are "specially optimized" for browser memory (`-web.litertlm`, and now `-gpu.litertlm`), alongside native and NPU-specific files. — [E2B card](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm); [E2B files](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main)
- llama-web-bridge:
  - Caps GPU offload to one layer on Safari before 27 (`nGpuLayers: 0` raises the memory ceiling).
  - Enables heap-resident staging when at most one GPU layer is used.
  - Plans staging on by default for iOS Safari, which implies engine detection of iOS Safari.
  - Source: [llama-web-bridge #257](https://github.com/leehack/llama-web-bridge/issues/257)
- Chrome's built-in Gemini Nano refuses to run below its thresholds: more than 4 GB VRAM or 16 GB RAM with 4 cores, 22 GB free disk, and desktop OS only; it is unsupported on Android and iOS. [>12 mo] — [Chrome built-in AI: get started](https://developer.chrome.com/docs/ai/get-started)
- The LlamaWeb study shows clustering devices by measured throughput (k-means, k=3) separates classes better than hardware labels. The Galaxy S24 lands with the M2 and Iris Xe, while Adreno 7xx lands with iPhones. — [arXiv 2605.20706v1](https://arxiv.org/html/2605.20706v1)

### Inferences
- A workable detection sequence, my synthesis:
  1. If `navigator.gpu` is missing, `requestAdapter()` returns null, or `isFallbackAdapter` is true, use no local GPU model.
  2. Identify the engine. Firefox means no usable GPU for LLMs (about 1 ms per dispatch). For Safari on iOS or iPadOS, apply the iPhone tier ceiling regardless of other signals, because there is a ~2 GiB WebContent cap and `deviceMemory` is not exposed (MDN: limited availability).
  3. Read adapter `info.vendor`, `features.has('shader-f16')`, and `limits.maxBufferSize` / `maxStorageBufferBindingSize`. No f16 means q4f32 builds and a lower tier.
  4. Use `deviceMemory` as a coarse RAM bucket. On Android it saturates at 8, so it cannot tell 8 GB from 12–16 GB flagships. On desktop it now distinguishes 16 and 32.
  5. Probe: load the tier's model, then time a fixed prefill and about 32 decode tokens. Persist the measured tok/s, any OOM or device-lost event, and whether a reload happened (on iOS a jetsam kill shows up as a page reload, not an exception). Downgrade on failure.
- An iframe plus Worker gives isolation but no extra memory headroom, at least on iOS (Worker mode hit the same limit). Put detection and probing in the Worker, since `deviceMemory` and WebGPU are both available in Workers.

### Gaps
- I did not research `navigator.hardwareConcurrency` (its caps and rounding per browser) or User-Agent Client Hints (`Sec-CH-UA-Model`, platform version, Safari and Firefox support) in this pass.
- I did not open the full `GPUAdapterInfo` field list (vendor, architecture, device, description, subgroup sizes) or check what Safari actually returns. MDN's compatibility tables for `deviceMemory` and `requestAdapter` did not render in the fetch, so per-browser version support is unverified here.
- No published engine logic maps `deviceMemory` or adapter limits to a model choice beyond WebLLM's static `vram_required_MB`. Chrome's internal benchmark-based gating for Gemini Nano is not documented in detail.
