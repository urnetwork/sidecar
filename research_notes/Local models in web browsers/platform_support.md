# Browser platform support for local LLM inference: WebGPU, WebNN and WebAssembly, as of 2026-11-25

Research date: 2026-11-25. Every claim carries a date or is marked undated. "Default" means shipped and on by default in the stable channel. Flags, origin trials (OT), Nightly and Technology Preview/beta are labelled as such. Three machine-readable sources were downloaded and parsed directly, not read through summaries: the caniuse full data (updated 2026-11-24), MDN browser-compat-data (BCD) 8.1.10 (timestamp 2026-11-19), and the webassembly.org feature table. Engine source files (Chromium, Dawn, V8, WebKit/JSC, SpiderMonkey) were read from their `main` branches on 2026-11-25. `main` can be ahead of stable releases.

## 1. Which browser versions, on which OSes, enable WebGPU by default, and which GPUs, drivers or OS versions are excluded?

### Takeaway
As of 2026-11-25, WebGPU is on by default in these places:
- **Chromium browsers** (Chrome, Edge, Opera, Samsung Internet) on Windows x64 (D3D12), macOS and ChromeOS since 113 (2023-05-02).
- **Chromium on Android** since 121 (2024-01-23), but only on Android 12+ with Qualcomm, ARM (Mali) or Intel GPUs. Imagination GPUs need Android 16+ (Chrome 139).
- **Chromium on Linux** only for Intel Gen12+ with Mesa 22.0 or newer (Chrome 144, 2026-01-13) and NVIDIA driver 535.183.01 or newer on Wayland (Chrome 147, 2026-04-07).
- **Safari** only on iOS, iPadOS and visionOS 26+ and on macOS 26 Tahoe+. Safari 26/27 running on Sequoia or Sonoma does not enable it.
- **Firefox** only on Windows (141) and Apple Silicon macOS (145 on Tahoe; 147 on all macOS versions).

The largest holes are Firefox on Linux and Android, Linux AMD, Android GPUs from other vendors (Samsung Xclipse/Exynos in particular) and Android below 12. Windows-on-Arm status is contradictory between sources.

### Cited Findings

**Current stable versions on 2026-11-25** (BCD release table, 2026-11-19):
- Chrome 158, released 2026-11-17; 159 beta is due 2026-12-08.
- Edge 157, released 2026-11-05.
- Firefox 160, released 2026-11-10; 161 is due 2026-11-24.
- Safari 27.2, released 2026-10-26; Safari 27.3 beta (WebKit 626.1.17) appeared 2026-11-16.
- Samsung Internet 31.0, released 2026-09-23, on Chromium 148.

Source: [BCD data.json](https://unpkg.com/@mdn/browser-compat-data/data.json) ([repo](https://github.com/mdn/browser-compat-data)).

Release cadence:
- Chrome now ships every 2 weeks: 152 on 2026-08-25, 153 on 2026-09-08, 154 on 2026-09-22, 155 on 2026-10-06 and 156 on 2026-10-20 ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- Firefox shows the same 2-week spacing: 157 on 2026-09-29, 158 on 2026-10-13, 159 on 2026-10-27 and 160 on 2026-11-10 ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).

**Support matrix (default-on status for `navigator.gpu`)**

| Browser / OS | Status as of 2026-11 | Conditions and exclusions | Sources |
|---|---|---|---|
| Chrome/Edge, Windows x64 | Default since 113 (2023-05-02) | Uses the D3D12 backend. Adapters on the D3D11 backend are blocklisted. On D3D12, AMD, Intel, Microsoft and NVIDIA are allowed; NVIDIA is blocked only on 32-bit x86 builds. Any other vendor is blocked ("Other OS versions/GPU vendor combinations may be fine, but have not had sufficient testing yet"). | [gpuweb wiki, edited 2026-10-02](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [Chromium webgpu_blocklist_impl.cc, main, read 2026-11-25](https://github.com/chromium/chromium/blob/main/gpu/config/webgpu_blocklist_impl.cc) |
| Chrome/Edge, Windows ARM64 (Snapdragon) | **Conflicting.** The wiki says behind a flag (`chrome://flags/#enable-unsafe-webgpu`). Chromium source says on by default for one GPU and driver range. | In Chromium `main`, `kWebGPUQualcommWindows` is `FEATURE_ENABLED_BY_DEFAULT`. The default adapter blocklist then blocks Adreno 6xx Windows parts (7180, 7280, 8180, 8280) and the 8340. It allows the 8380 (`0x36334330`, adreno-7xx) only with driver 31.0.117.0 or newer. A Japanese report dated 2025-10-06 quotes the Chromium commit "Enable WebGPU support for Qualcomm Windows by default." | [gpuweb wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [webgpu_blocklist_impl.cc](https://github.com/chromium/chromium/blob/main/gpu/config/webgpu_blocklist_impl.cc); [gpu_finch_features.cc](https://github.com/chromium/chromium/blob/main/gpu/config/gpu_finch_features.cc); [helentech.jp, 2025-10-06](https://helentech.jp/news-75702/) |
| Chrome/Edge, macOS | Default since 113 | The blocklist code read has no macOS-specific vendor rules. Its cross-platform rule is that CPU adapters are blocked. | [gpuweb wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [webgpu_blocklist_impl.cc](https://github.com/chromium/chromium/blob/main/gpu/config/webgpu_blocklist_impl.cc) |
| Chrome, ChromeOS | Default since 113 | The AMD GPU with device ID `0x98e4` is blocked ("AMDMissingDrmFormatModifier"). | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [webgpu_blocklist_impl.cc](https://github.com/chromium/chromium/blob/main/gpu/config/webgpu_blocklist_impl.cc) |
| Chrome (and Chromium browsers), Android | Default since 121 (2024-01-23) for Qualcomm, ARM and Intel on Android 12+. Imagination GPUs on Android 16+ since Chrome 139 (2025-08-05). | On the Vulkan backend, ARM, Qualcomm and Intel need Android 12 (SDK S) or later; Imagination needs Android 16 (SDK Baklava) or later. The opt-in OpenGL ES backend (compatibility mode) allows ARM, Qualcomm and Intel on Android 10+ and Imagination on Android 13+. Imagination driver "PowerVR 25.1" is blocklisted. All other vendors are blocked ("AndroidLimitedSupport"). The wiki lists Samsung Xclipse GPUs as "planned, date TBD". | [Chrome 121 post](https://developer.chrome.com/blog/new-in-webgpu-121); [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [webgpu_blocklist_impl.cc](https://github.com/chromium/chromium/blob/main/gpu/config/webgpu_blocklist_impl.cc) |
| Chrome/Edge, Linux | Default only for Intel Gen12+ (Chrome 144, 2026-01-13) and NVIDIA on Wayland with driver 535.183.01+ (Chrome 147, 2026-04-07). Every other configuration is behind a flag. | Software-rendering-list entry 186 ("Disable webgpu on vk via gl interop") applies to all of Linux. Its exceptions are Intel GPU generation 12+ with Mesa 22.0+, and NVIDIA driver 535.183.01+. The flag path is `--enable-unsafe-webgpu --ozone-platform=x11 --use-angle=vulkan --enable-features=Vulkan,VulkanFromANGLE`. WebGPU runs on Vulkan while the rest of Chromium stays on OpenGL. `shader-f16` on NVIDIA Linux arrived only in Chrome 155–156. | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [software_rendering_list.json](https://github.com/chromium/chromium/blob/main/gpu/config/software_rendering_list.json); [Chrome 144 post, 2026-01-07](https://developer.chrome.com/blog/new-in-webgpu-144); [Chrome 147–148 post, 2026-04-22](https://developer.chrome.com/blog/new-in-webgpu-147-148); [Chrome 155–156 post](https://developer.chrome.com/blog/new-in-webgpu-155-156) |
| Samsung Internet, Android | Default. caniuse says since 24 (2024-01-25, Chromium 117); BCD says since 25.0 (2024-04-24, Chromium 121). The two sources conflict. | Same Chromium base; current version 31.0 is on Chromium 148. | [caniuse](https://caniuse.com/webgpu); [BCD](https://unpkg.com/@mdn/browser-compat-data/data.json) |
| Opera | caniuse marks it supported since Opera 99, "Not enabled on Linux by default" | — | [caniuse](https://caniuse.com/webgpu) |
| Safari, macOS | Default **only on macOS 26 Tahoe or later**, since Safari 26.0 (2025-09-15) | Safari 26.x also ships on Sequoia and Sonoma, and Safari 27 (2026-09-14) on macOS 27, macOS 26 and Sequoia. caniuse still marks Safari 26.0 and later as "Partial support refers to only being enabled by default on macOS 26 Tahoe or later" and records no change for 27.x. | [caniuse](https://caniuse.com/webgpu); [Safari 26 notes](https://developer.apple.com/documentation/safari-release-notes/safari-26-release-notes); [Safari 27 notes](https://developer.apple.com/documentation/safari-release-notes/safari-27-release-notes) |
| Safari, iOS, iPadOS and visionOS | Default since 26 (2025-09-15): "In macOS Tahoe 26, iOS 26, iPadOS 26, and visionOS 26, WebGPU is supported and enabled by default." | iOS 18 and older: off by default; a feature flag is available. | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [caniuse](https://caniuse.com/webgpu) |
| Chrome, Edge and Firefox on iOS; WKWebView; iOS in-app browsers | Follow WebKit: BCD lists `webview_ios` WebGPU support at 26 | Inferred to match the installed iOS version (see Inferences). | [BCD](https://unpkg.com/@mdn/browser-compat-data/data.json) |
| Android WebView | BCD lists `webview_android` at 121 | Unconfirmed. The Chrome Status "WebGPU on Android" entry lists ship milestones for desktop 113 and Android 121 but none for WebView. | [BCD](https://unpkg.com/@mdn/browser-compat-data/data.json); [Chrome Status 5119617865613312](https://chromestatus.com/feature/5119617865613312) |
| Firefox, Windows | Default since 141 (2025-07-22) | — | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [BCD](https://unpkg.com/@mdn/browser-compat-data/data.json) |
| Firefox, macOS | Apple Silicon: default since 145 (2025-11-11) on macOS 26+, and since 147 (2026-01-13) on all macOS versions. Intel Macs: Nightly only. | — | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status) |
| Firefox, Linux | Nightly only. "Mozilla expects to ship on Linux in 2026." | Bug 2028252 (Firefox 151 Nightly) records a developer saying "We'll have to fix this before we can ship on Linux" about Linux presentation problems. | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [bug 2028252](https://bugzilla.mozilla.org/show_bug.cgi?id=2028252) |
| Firefox, Android | Behind a flag, disabled by default. Requires Beta or Nightly plus `gfx.webgpu.ignore-blocklist`. "Mozilla expects to do Android work in 2026." | caniuse marks Firefox for Android 160 "n d". | [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status); [caniuse](https://caniuse.com/webgpu) |

**Other platform facts:**
- **CPU adapters.** Chromium blocklists CPU adapters (reason "CPUAdapter"), so the SwiftShader fallback is not offered by default ([webgpu_blocklist_impl.cc](https://github.com/chromium/chromium/blob/main/gpu/config/webgpu_blocklist_impl.cc)). Web3D Survey (undated) reports that "0.05% of working adapters use a fallback adapter" ([web3dsurvey](https://web3dsurvey.com/webgpu)).
- **Blocklist bypass.** The Chrome flag `--enable-unsafe-webgpu` (`chrome://flags/#enable-unsafe-webgpu`) bypasses the blocklist ([Chrome Status WebGPU entry](https://chromestatus.com/feature/6213121689518080); [wiki](https://github.com/gpuweb/gpuweb/wiki/Implementation-Status)).
- **Compatibility mode** (Chrome 146, 2026-03-10).
  - It is opt-in via `requestAdapter({ featureLevel: "compatibility" })`.
  - It runs WebGPU on OpenGL ES 3.1, starting with Android. The team is "exploring support for other devices, such as ChromeOS with OpenGL ES 3.1 and Windows with Direct3D 11" ([Chrome 146 post, 2026-02-25](https://developer.chrome.com/blog/new-in-webgpu-146)).
  - Its Chrome Status ship stage lists desktop, Android and WebView at 146 ([Chrome Status 6436406437871616](https://chromestatus.com/feature/6436406437871616)).
- **SPIR-V validation.** Chrome 146 turned on SPIR-V validation by default on Android, "to provide an additional security layer and prevent driver instability from malformed input" ([Chrome 146 post](https://developer.chrome.com/blog/new-in-webgpu-146)).

### Inferences
- iOS has no Chromium or Gecko engine outside the EU arrangements, so every iOS browser and in-app WKWebView shares the iOS-version gate: WebGPU needs iOS/iPadOS 26+. This rests on the BCD `webview_ios` 26 entry; whether EU alternative-engine builds exist was not researched.
- Android device eligibility depends on the GPU vendor, not on the browser. Qualcomm or Mali on Android 12+ qualifies. Exynos phones with Xclipse GPUs get no WebGPU in Chrome by default. Those are the GPUs Samsung lists for some Exynos Galaxy models; the device list itself is not sourced here. Pixel phones with Imagination GPUs need Android 16+.
- For the Linux desktop minority, expect no WebGPU on AMD or older Intel GPUs in any browser without flags. Web3D Survey's Linux working-adapter share of 18.03% (Q7) is consistent with this.
- The Windows ARM64 conflict is best handled at runtime: call `requestAdapter()` and fall back when it returns `null`. Do not use user-agent sniffing.

### Gaps
- No primary Chrome release note was found for the stable milestone that enabled Qualcomm Windows. The gpuweb wiki (edited 2026-10-02) contradicts Chromium `main`.
- WebGPU in Android WebView is not confirmed by any Chrome primary source; BCD alone says 121.
- No source says whether Safari 27.x enables WebGPU on macOS Sequoia. caniuse implies it does not.
- No source shows Chrome blocking Intel Macs. Safari's WebKit code does include `MTLGPUFamilyMac2` limits, which cover Intel and AMD Mac GPUs (see Q3).
- Whether the Xclipse GPU's vendor ID is caught by the Android "default" blocked branch is inferred, not tested.
- No information was found on WebGPU in EU alternative-engine iOS browsers.

## 2. Is WebGPU exposed in dedicated Workers, SharedWorkers and service workers? Does an iframe need a Permissions-Policy? Do Lockdown Mode or enterprise policies disable WebGPU or WebAssembly?

### Takeaway
- **Workers.** Dedicated workers have WebGPU in every browser that ships it. Chrome also has it in SharedWorker and service workers (124); Firefox excludes service workers.
- **iframes.** The WebGPU spec defines no Permissions-Policy feature and needs only a secure context, so a same-site or cross-site HTTPS iframe needs no `allow=` attribute for WebGPU.
- **Lockdown Mode.** Apple Lockdown Mode disables WebGPU, and in practice WebAssembly too; a WebKit bug says site exceptions have not restored WebAssembly since iOS 17.4.
- **Edge.** Edge is trialling a Lockdown Mode in Canary that blocks WebGPU.
- **Chrome.** No Chrome enterprise policy dedicated to WebGPU was found. The JIT policy can disable WebAssembly, and Chromium `main` blocks WebGPU under Android Advanced Protection Mode.

### Cited Findings
**Spec and iframes**
- The WebGPU spec IDL marks the interfaces `[Exposed=(Window, Worker), SecureContext]`. `NavigatorGPU` (`[SameObject, SecureContext] readonly attribute GPU gpu`) is included by both `Navigator` and `WorkerNavigator`. A grep of the spec source found no "policy-controlled" feature and no Permissions-Policy text ([gpuweb spec index.bs, main, read 2026-11-25](https://github.com/gpuweb/gpuweb/blob/main/spec/index.bs)).
- BCD's list of Permissions-Policy directives (2026-11-19) has no WebGPU or "gpu" directive ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- Anecdote, unverified: a Figma plugin developer found `navigator.gpu` undefined in a null-origin plugin UI frame, and loading the content in a hosted iframe fixed it ([Figma forum](https://forum.figma.com/ask-the-community-7/webgpu-api-is-not-supported-in-the-plugin-23219)).

**Workers by browser**
- **Chrome/Edge:** `WorkerNavigator.gpu` since 113 ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)). Service worker and SharedWorker support since 124 (2024-04-16) ([Chrome 124 post](https://developer.chrome.com/blog/new-in-webgpu-124); [Chrome Status 4875951026733056](https://chromestatus.com/feature/4875951026733056)).
- **Chrome experimental:** a `GPUBuffer.mapSync()` restricted to workers, behind `--enable-features=WebGPUMapSyncOnWorkers` ([Chrome 145 post, 2026-01-28](https://developer.chrome.com/blog/new-in-webgpu-145)).
- **Firefox:** "Supports all contexts except service workers. See bug 1942431" ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)). BCD's `firefox_android` WorkerNavigator row copies the desktop notes even though `Navigator.gpu` is `false` on Firefox for Android. This looks like a BCD data error.
- **Safari:** BCD lists `WorkerNavigator.gpu` at Safari 26 with no worker-type caveat ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)). WebKit's standards position on WebGPU in service and shared workers was "Closed Without a Position" ([Chrome Status 4875951026733056](https://chromestatus.com/feature/4875951026733056)). Safari 27.3 beta (2026-11-16) adds "support for creating dedicated workers from shared workers" ([Safari 27.3 beta notes](https://developer.apple.com/documentation/safari-release-notes/safari-27_3-release-notes)).

**Apple Lockdown Mode**
- A WebKit commit from May 2024 is titled "[Lockdown Mode] Explicitly disable WebGPU" ([webkit-changes, 2024-05](https://lists.webkit.org/pipermail/webkit-changes/2024-May/301532.html)).
- WebKit bug 273824, "REGRESSION (iOS 17.4): WebAssembly blocked in lockdown mode, even if exception is added", was filed 2024-05-07 and was still NEW at its last modification on 2025-03-14. It has a Radar but no engineer comment ([bug 273824](https://bugs.webkit.org/show_bug.cgi?id=273824)).
- **Conflict:** Apple's support page (published 2026-09-14) says only that "Certain complex web technologies are blocked". It also says an excluded site is "no longer impacted and limited by WebKit restrictions", and that iOS apps can be excluded so that "web content limits are removed for that app" ([Apple support 105120](https://support.apple.com/en-us/105120)). The bug report says site exceptions do not restore WebAssembly.

**Microsoft Edge Lockdown Mode** (Canary experiment, reported 2026-11-19)
- It blocks the WebGL, WebGL2 and WebGPU APIs.
- It builds on Enhanced Security Mode, which disables the JIT.
- It is enabled by the user through the `#edge-sdsm-plus` flag, with Strict mode set. No enterprise control is mentioned.
- Source: [BleepingComputer, 2026-11-19](https://www.bleepingcomputer.com/news/microsoft/microsoft-tests-new-edge-lockdown-mode-that-disables-gpu-apis/).

**Chrome enterprise policy**
- The `DefaultJavaScriptJitSetting` policy (value `BlockJavaScriptJit`) carries this warning: "Disabling the JavaScript JIT will mean that Google Chrome may render web content more slowly, and may also disable parts of JavaScript including WebAssembly." It can be overridden per site with `JavaScriptJitAllowedForSites` and `JavaScriptJitBlockedForSites` ([policy definition, Chromium main](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/ContentSettings/DefaultJavaScriptJitSetting.yaml)).
- Searches found no Chrome enterprise policy that specifically disables WebGPU. The one lead is a Chrome Enterprise release-notes entry titled "Chrome WebGPU Toggle in AAPM", seen only in a search snippet with no detail ([search result: Chrome Enterprise release notes](https://support.google.com/chrome/a/answer/7679408)).

**Android Advanced Protection Mode (AAPM)**
- Chromium `main` contains `BASE_FEATURE(kAAPMBlocksWebGPU, base::FEATURE_ENABLED_BY_DEFAULT)` with the comment "Feature enforces WebGPU security in Android Advanced Protection Mode" ([gpu_finch_features.cc](https://github.com/chromium/chromium/blob/main/gpu/config/gpu_finch_features.cc)).
- A March 2026 teardown of Google Play Services v26.10.31 found the option "Turn off WebGPU to help protect against security threats" ([Android Authority, via search; also anti-malware.ru 2026-03-10](https://www.androidauthority.com/android-advanced-protection-mode-disable-chrome-webgpu-apk-teardown-3647502)).
- Separately, Advanced Protection already disables V8's higher-level optimizing JavaScript compilers. This requires Android 16 and Chrome 137+ ([Google security blog, via search](https://blog.google/security/advancing-protection-in-chrome-on/)).

### Inferences
- For a dedicated Worker inside the same-site iframe `https://sidecar.ur.io/v1/` framed by `https://ur.io`: WebGPU should be available with no `allow="..."` attribute and no COOP/COEP. The supporting facts are that WebGPU is exposed to workers, gated only by SecureContext, and has no policy-controlled feature.
- The iframe's CSP should not affect WebGPU itself. CSP has no GPU directive in the sources reviewed, but this was not verified against a spec.
- Weight downloads are governed by `connect-src`.
- Expect a small but real share of security-conscious users (Lockdown Mode on Apple, Advanced Protection on Android, Edge Lockdown or Enhanced Security, or a JIT-blocking enterprise policy) to have no WebGPU and/or no WebAssembly. These users need a server fallback.
- Safari 26 added "an in-place interpreter for Wasm" ([Safari 26 notes](https://developer.apple.com/documentation/safari-release-notes/safari-26-release-notes)). Whether Lockdown Mode now uses it to allow WebAssembly is unknown; treat Wasm as unavailable under Lockdown.

### Gaps
- No primary Apple statement lists WebAssembly or WebGPU among Lockdown Mode's blocked technologies.
- The site-exception behaviour is contradictory between Apple's support page and WebKit bug 273824.
- It is unconfirmed whether Safari exposes WebGPU in service workers or SharedWorkers.
- It is unknown when, or whether, `kAAPMBlocksWebGPU` reached Chrome stable, and whether it is admin-controllable.
- No source confirms what happens to WebGPU when Chrome's `HardwareAccelerationModeEnabled` is set to false. It is assumed but not verified that WebGPU then becomes unavailable.

## 3. Which WebGPU features and limits matter for LLM inference, how widely are they available, what are typical adapter limits per GPU family, and does Safari cap them below the hardware?

### Takeaway
- **`shader-f16`:** Chrome since 120/121 and Safari since 26. BCD says Firefox does not support it. Web3D Survey reports it on about 94% of tested reports, but it is largely missing on NVIDIA Maxwell/Pascal, Intel Gen8, AMD GCN-4 and Adreno 6xx.
- **`subgroups`:** Chrome 134. Safari only from 27.3 beta (2026-11-16, so not yet in stable). Firefox: no.
- **`timestamp-query`:** Chrome 121 and Safari 26. Firefox: no.
- **Per-binding ceilings vary by roughly 16x:**
  - about 2 GiB−4 on Windows and Chrome on Mac;
  - ≤1 GiB per buffer and per binding in Safari on iOS (a deliberate cap);
  - only 128 MiB `maxStorageBufferBindingSize` on most Snapdragon Adreno 7xx phones.
- **Workgroup memory:** `maxComputeWorkgroupStorageSize` is 32 KiB on Safari and most adapters.

### Cited Findings
**Feature availability** (BCD, 2026-11-19; [data](https://unpkg.com/@mdn/browser-compat-data/data.json))

| Feature | Chrome/Edge desktop | Chrome Android | Safari macOS/iOS | Firefox | Samsung Internet |
|---|---|---|---|---|---|
| `shader-f16` | 120 (2023-12-05); Linux Intel Gen12+ only until NVIDIA Linux was added in 155–156 | 121 | 26 | **not supported** | 25.0 |
| `subgroups` | 134 (2025-03-04) | 134 | **27.3 (beta)** | not supported | 29.0 |
| `subgroup-size-control` | 152 (2026-08-25) | 152 | no | no | no |
| `timestamp-query` | 121 | 121 | 26 | not supported | 25.0 |

- **Chrome subgroups:** "now available" in 134, published 2025-02-26. "Google Meet saw 2.3-2.9 times speed increases when benchmarking subgroups against packed integer dot products for matrix-vector multiply shaders on some devices" ([Chrome 134 post](https://developer.chrome.com/blog/new-in-webgpu-134)).
- **Chrome f16:** the WebLLM Llama 2 7B f16 build on an Apple M1 Pro showed "a 28% improvement in prefill speed and a 41% improvement in decoding speed" over f32 ([Chrome 120 post](https://developer.chrome.com/blog/new-in-webgpu-120)).
- **Chrome on Linux NVIDIA:** `shader-f16` is "now supported on Linux for recent NVIDIA GPU drivers" ([Chrome 155–156 post, published after 2026-10-06](https://developer.chrome.com/blog/new-in-webgpu-155-156)).
- **Safari subgroups:** 27.3 beta (2026-11-16) says "Added support for subgroups in WebGPU" ([Safari 27.3 beta notes](https://developer.apple.com/documentation/safari-release-notes/safari-27_3-release-notes)). This had appeared in Safari Technology Preview 249 ([STP 249](https://webkit.org/blog/18182/release-notes-for-safari-technology-preview-249/)).
- **Firefox f16:** Mozilla bug 1909504 (open, last updated about eight months before it was retrieved) records that Proton Mail's WebGPU ML features cannot ship to Firefox because of stability issues and missing `shader-f16` ([bug 1909504](https://bugzilla.mozilla.org/show_bug.cgi?id=1909504)).
- **Conflict on Firefox f16:** Web3D Survey reports Firefox at 93.7% `shader-f16` among reports tested ([web3dsurvey shader-f16](https://web3dsurvey.com/webgpu/features/shader-f16)). Possible explanations are a different denominator, Nightly builds, or BCD lagging behind a recent ship.

**Aggregate feature prevalence** (Web3D Survey; undated, no date range or sample size given)
- Overall: `shader-f16` 94.31%, `subgroups` 67.42%, `timestamp-query` 98.86% of reports tested ([web3dsurvey](https://web3dsurvey.com/webgpu)).
- `shader-f16` by platform: Android 88.45%, ChromeOS 99.79%, iOS 100%, Linux 78.49%, macOS 99.74%, Windows 91.26% ([web3dsurvey shader-f16](https://web3dsurvey.com/webgpu/features/shader-f16)).
- `shader-f16` by architecture, same source:

  | Vendor | Architecture: share |
  |---|---|
  | NVIDIA | Kepler 6.77%, Maxwell 0.29%, Pascal 0.24%, Turing 98.71%, Ampere 99.25%, Lovelace 98.86%, Blackwell 98.9% |
  | Intel | Gen-8 28.76%, Gen-9 86.74%, Gen-11 100%, Gen-12lp 99.86%, Xe-LPG 99.81% |
  | AMD | GCN-4 24.09%, GCN-5 99.55%, RDNA-1 to RDNA-3 ≥99.7% |
  | Qualcomm | Adreno 6xx 28.07%, 7xx 97.33%, 8xx 98.86% |
  | ARM | Bifrost and Valhall 100% |
  | Apple | 100% |

**How Chrome/Dawn rounds limits.** Dawn reports limits rounded down to fixed tiers ([Dawn Limits.cpp, main](https://github.com/google/dawn/blob/main/src/dawn/native/Limits.cpp)):
- `maxBufferSize`: 256 MiB (compat and tier0), 1 GiB, 2 GiB, 4 GiB−4.
- `maxStorageBufferBindingSize`: 128 MiB (compat and tier0), 256 MiB, 512 MiB, 1 GiB, 2 GiB−4, 4 GiB−4.
- `maxComputeWorkgroupStorageSize`: 16384 (compat and tier0), 32768, 49152, 65536.

MDN explains that browsers "report different tier values" to limit fingerprinting ([MDN GPUSupportedLimits, via search](https://developer.mozilla.org/en-US/docs/Web/API/GPUSupportedLimits)). Firefox capped some high limits in 2023, partly over fingerprinting: "it's also a potential fingerprinting surface so lets cap them to something reasonable" ([bug 1865344, via search](https://bugzilla.mozilla.org/show_bug.cgi?id=1865344)).

**Safari's deliberate caps** ([WebKit HardwareCapabilities.mm, main, read 2026-11-25](https://github.com/WebKit/WebKit/blob/main/Source/WebGPU/WebGPU/HardwareCapabilities.mm)):
- `maxBuffersToAllow = 3`.
- **macOS:** `maxBufferSize = max(min(maxBufferLength, 1 GiB), min(INT_MAX, maxBufferLength/3))`, so the most it can be is INT_MAX, about 2 GiB.
- **Non-Mac (iOS, iPadOS, visionOS):** `maxBufferSize = max(256 MiB default, min(1 GiB, maxBufferLength/3))`, a hard 1 GiB cap whatever the RAM.
- In both cases `maxStorageBufferBindingSize` and `maxUniformBufferBindingSize` are set equal to `maxBufferSize`.
- `maxComputeWorkgroupStorageSize` is fixed at 32 KiB for every Apple family.
- Features: `ShaderF16` is always appended. `Subgroups` is added only if the device supports `MTLGPUFamilyMetal3`. `TimestampQuery` is added only if a timestamp counter set exists.
- An earlier WebKit fix (2024-02) had the adapter use WebGPU.framework's 256 MB default for `maxBufferSize` instead of 128 MB ([webkit-changes, 2024-02](https://lists.webkit.org/pipermail/webkit-changes/2024-February/297366.html)).
- A WebLLM demo needing a 1 GB buffer failed on iOS. The WebKit maintainer said iOS was too likely to jetsam at 1 GB. WebLLM cut its buffer to 256 MB and no WebKit change was made ([WebKit bug 275958](https://bugs.webkit.org/show_bug.cgi?id=275958), date not verified).
- Safari 27 (2026-09-14) "Restored `maxStorageBuffersInFragmentStage` and related WebGPU limits" ([Safari 27 notes](https://developer.apple.com/documentation/safari-release-notes/safari-27-release-notes)).

**Observed `maxBufferSize`** (Web3D Survey, undated; figures are cumulative shares of reports at or above each value; [source](https://web3dsurvey.com/webgpu/limits/maxBufferSize))
- Overall: ≥2,147,483,647 (2 GiB−1) in 76% of reports.
- By platform: Windows 92% ≥2 GiB−1; macOS 65% ≥2 GiB−1; Android 80% ≥2,147,483,644; iOS 83% ≥1 GiB (consistent with the 1 GiB cap).
- By browser: Safari 84% ≥858,993,456 (≈819 MiB), 30% ≥1,252,698,792 (≈1.17 GiB), 20% ≥2,010,044,824 (≈1.87 GiB).
- By architecture: the "apple - metal-3" bucket is 100% ≥2 GiB−1. Web3D Survey does not say which browser reports that label; reading it as Chromium on Apple GPUs is an interpretation, while Safari appears to report the "apple" label. Qualcomm Adreno 6xx is 8%, 7xx 76% and 8xx 100% ≥2 GiB−1; ARM Bifrost and Valhall 100% ≥2 GiB−1.

**Observed `maxStorageBufferBindingSize`** (Web3D Survey, undated; cumulative; [source](https://web3dsurvey.com/webgpu/limits/maxStorageBufferBindingSize)) — **the key limit for weight tensors**
- Overall: 78% ≥1,252,698,792; only 16% ≥2,147,483,647.
- By platform:
  - Windows: 99% ≥2,147,483,642.
  - macOS: 61% ≥2 GiB−1.
  - iOS: 83% ≥1 GiB.
  - ChromeOS: 100% ≥1 GiB, 42% ≥2 GiB−4.
  - Linux: 75% ≥1 GiB.
  - **Android: 73% ≥256 MiB, 52% ≥512 MiB, 41% ≥962,281,472, 40% ≥2 GiB−4.**
- By architecture:
  - **Qualcomm Adreno 7xx: only 6% ≥256 MiB, so about 94% report the 128 MiB floor.**
  - Adreno 6xx: 69% ≥512 MiB.
  - Adreno 8xx: 98% ≥2 GiB−4.
  - ARM Valhall: 58% ≥1 GiB. ARM Bifrost: 72% ≥1 GiB.
  - Intel Gen-12lp: 92% ≥2 GiB−4.
  - NVIDIA Maxwell through Blackwell and AMD RDNA-1 through RDNA-3: 100% ≥2 GiB−4.
  - Apple "apple" family (Safari): 83% ≥1 GiB, 24% ≥1,430,224,896, 16% ≥2,010,044,824.

**Observed `maxComputeWorkgroupStorageSize`:** "≥ 49152" in only 6% of reports ([web3dsurvey](https://web3dsurvey.com/webgpu)). Combined with Dawn's tiers and Safari's fixed 32 KiB, the large majority of adapters expose at most 32 KiB.

**Timestamps:** Chrome quantizes timestamps; the Chrome 120 post lists "timestamp quantization" ([WebGPU news index](https://developer.chrome.com/docs/web-platform/webgpu/news)). WebKit implements timestamp queries with MTLSharedEvent, which a WebKit engineer called "fairly heavyweight" across browsers ([WebKit bug 311598, 2026-04](https://bugs.webkit.org/show_bug.cgi?id=311598)).

### Inferences
- **Weight sharding per platform:** for portable LLM inference, plan every binding at or below 128 MiB on Android (Adreno 7xx is the most common modern Snapdragon class) and ≤1 GiB on iOS and Safari. Desktop Chrome can use 1–2 GiB bindings.
- **Shader work:** assume 32 KiB of workgroup memory. Ship both f16 and f32 shader variants.
- **Firefox:** the lack of f16 roughly doubles activation and KV memory with f32 compute, if BCD is right.
- **Subgroups:** treat them as Chrome-only until Safari 27.3 reaches stable (likely shortly after 2026-11). Subgroup-based kernels need a fallback path.
- **Specific iPhones:** no per-device survey exists for A17 Pro, A18 or A19. By WebKit's code all iOS devices report at most 1 GiB per buffer, so newer iPhones do not get larger WebGPU buffers than older ones; only `maxBufferLength/3`, when below 1 GiB, varies.

### Gaps
- No public per-device limit dumps were found for A17 Pro, A18 or A19 iPhones, for specific Adreno or Mali parts, or for Apple M-series in Chrome versus Safari. Web3D Survey aggregates by vendor and architecture only and publishes no date range or sample size.
- Firefox's `shader-f16` status conflicts between BCD and Web3D Survey.
- Firefox's exact limit caps on Windows and macOS were not determined.

## 4. What is WebNN's status in Chrome and Edge, which backends does it use, and what are Safari's and Firefox's positions?

### Takeaway
On 2026-11-25 WebNN is **not shipped and has no active origin trial** in Chrome; it is usable only behind `chrome://flags/#web-machine-learning-neural-network`.
- **Chrome OT:** planned for M146–148, re-enabled for M147–149, then disabled again on 2026-03-27 because of release-blocking issues. In May 2026 the OT team was asked to remove it.
- **Edge OT:** closed, with an expiry of 2026-08-11.
- **Backends:** LiteRT/TFLite, Windows ML (ONNX) and Core ML. GPU and NPU coverage is limited.
- **Positions:** Mozilla is positive but has no implementation. WebKit has no position and no implementation.

### Cited Findings
- **Flag:** BCD lists `navigator.ml`, `MLContext` and `MLGraphBuilder` in Chrome, Chrome Android and Edge at 112 behind the flag `#web-machine-learning-neural-network`. Firefox, Safari, Samsung Internet and both WebViews are `false` ([BCD, 2026-11-19](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- **Chrome Status entry 5176273954144256** (last updated 2026-04-08 by reillyg; [Chrome Status](https://chromestatus.com/feature/5176273954144256)):
  - Flag `web-machine-learning-neural-network`; Finch name `WebMachineLearningNeuralNetwork`.
  - Developer-trial stage at desktop and Android 125.
  - Origin-trial stage "desktop_first 147".
  - Ongoing constraints: "WebNN can currently execute models on CPU across all platforms but support for GPU and NPU execution is more limited."
- **blink-dev "Intent to Experiment: WebNN" thread** ([thread](https://groups.google.com/a/chromium.org/g/blink-dev/c/5CWKSChYo98)):
  - 2026-02-05: "The Origin Trial will start in M-146 and run through M-148" ([msg15748](https://mid.mail-archive.com/blink-dev@chromium.org/msg15748.html)).
  - February 2026: Android was excluded from the OT because the implementation was too immature there ([msg15857](https://mid.mail-archive.com/blink-dev@chromium.org/msg15857.html)).
  - 2026-03-10: "We've re-enabled the WebNN Origin Trial in M-147 … will now run from M-147 to M-149 … disabled for now on Android" ([msg15933](https://go.mail-archive.com/blink-dev@chromium.org/msg15933.html)).
  - 2026-03-27: "Due to more release blocking issues reported, we decided to disable the Original Trial."
  - 2026-05-15: Ingvar Stepanyan reported tokens failing with "ValidTokenNotProvided"/"UnknownTrial". Reilly Grant replied, "I've reached out to the Origin Trials team to have it removed" ([msg16537](http://www.mail-archive.com/blink-dev@chromium.org/msg16537.html)).
  - Searches found no Intent to Ship or Intent to Extend for WebNN ([search results](http://www.mail-archive.com/blink-dev@chromium.org/msg16535.html)).
  - For reference, M147 shipped 2026-04-07 and M149 2026-06-02 ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- **Edge:** Microsoft's WebNN origin trial page is marked "[Closed]", with an expiration of 2026-08-11 according to a search summary ([Edge origin trials](https://developer.microsoft.com/microsoft-edge/origin-trials/trials/19857284-cf52-484b-8b09-8ca50ac9dccb)).
- **Backends** ([WebNN implementation status](https://webmachinelearning.github.io/webnn-status/), undated, © 2026):
  - Lists LiteRT (Chromium's TFLite op resolver), Windows ML (ONNX operators) and Core ML. DirectML is not mentioned.
  - "The total number of WebNN ops is 95."
  - Shows Chrome Canary and Edge Canary as "experimental".
  - Frameworks: ONNX Runtime Web (WebNN Execution Provider) and LiteRT.js (External Delegate).
- **Web developer signals:** "Microsoft's ONNX runtime includes an execution provider for WebNN … Google's LiteRT.js framework has announced that they are working on WebNN support" ([Chrome Status](https://chromestatus.com/feature/5176273954144256)).
- **Mozilla:** standards-positions #1215 is closed with the label "position: positive". On 2025-11-12 tarekziade wrote: "We're supportive of this specification. The proposed set of operators provides a clear path toward more efficient, in-browser inference…" ([mozilla/standards-positions#1215](https://github.com/mozilla/standards-positions/issues/1215)). The Chrome Status entry adds that "Edge is planning to ship alongside Chrome and Firefox is planning to implement".
- **WebKit:** standards-positions #486 is open with no position; it was reopened in November 2025 and last updated 2026-05-01 ([WebKit/standards-positions#486](https://github.com/WebKit/standards-positions/issues/486)). Chrome Status records Safari as "No signal: Apple is participating in the WebML WG but has made no public statements about implementation."

### Inferences
- WebNN is not a deployable target for a production web app in November 2026: there is no stable support anywhere, no active OT and no Safari engagement. At most it is a future Chromium-only accelerator behind ONNX Runtime Web or LiteRT.js.
- WebGPU, with WebAssembly as fallback, is the only realistic path today.

### Gaps
- No Chrome release notes for M150–M158 were checked line by line for a silent WebNN re-enable. The Chrome Status entry has been unchanged since 2026-04-08.
- No per-OS breakdown of backend use (for example, Core ML NPU use on macOS) could be extracted from the status page.

## 5. WebAssembly: SIMD, relaxed SIMD, threads and cross-origin isolation, Memory64, JSPI, the 4 GiB wasm32 limit and per-browser maximum ArrayBuffer size

### Takeaway
- **Universal:** SIMD and threads (Chrome, Firefox and Safari 16.4+).
- **Not yet in stable Safari:** relaxed SIMD and Memory64 are in Chrome (114, 133) and Firefox (145/146, 134), but Safari added both only in 27.3 beta (2026-11-16).
- **JSPI:** Chrome 137, Firefox 153, Safari 27.
- **Cross-origin isolation:** threads require it everywhere. Safari supports neither COEP `credentialless` nor Document-Isolation-Policy, so in Safari threads need COOP plus COEP `require-corp` on the top-level page.
- **Engine caps:** wasm32 memory is capped at 4 GiB in all three engines; Memory64 and ArrayBuffers are capped at 16 GiB, or 32 GiB−1 for ArrayBuffers in V8.

### Cited Findings
**Feature matrix** (BCD, 2026-11-19 [data](https://unpkg.com/@mdn/browser-compat-data/data.json); cross-checked with [webassembly.org features](https://webassembly.org/features/) ([data](https://github.com/WebAssembly/website/blob/main/features.json)) and the Safari release notes)

| Feature | Chrome/Edge | Firefox | Safari (macOS/iOS) | Samsung Internet |
|---|---|---|---|---|
| Fixed-width SIMD | 91 | 89 | 16.4 (2023-03-27) | 16.0 |
| Relaxed SIMD | 114 (2023-05-30) | **146 per BCD; 145 per webassembly.org (conflict)** | **27.3 beta (2026-11-16)**; webassembly.org still says JSC flag `useWebAssemblyRelaxedSIMD` | 23.0 |
| Threads and atomics | 74 (Android 88) | 79 | 15.2 per BCD; webassembly.org says 14.1 (iOS 14.5) | 15.0 |
| Memory64 | 133 (2025-02-04) | 134 (2025-01-07) | **27.3 beta**; webassembly.org says "Supported in Safari Technical Preview 251" | 29.0 (2025-10-25) |
| JSPI | 137 (2025-05-27) | 153 (2026-07-21) | 27 (2026-09-14) | 30.0 (2026-05-11) |
| `Memory.toResizableBuffer()` | 144 | 145 | 26.2 (2025-12-12) | 31.0 |

- Android WebView, which many Android in-app browsers use: BCD lists `webassembly.threads-and-atomics`, shared `WebAssembly.Memory` and `SharedArrayBuffer` as `false` for `webview_android` ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)). The Document-Isolation-Policy explainer likewise says WebView has no process isolation, so COI-gated APIs are unavailable there ([WICG/document-isolation-policy](https://github.com/WICG/document-isolation-policy)).
- Safari 27.3 beta notes say: "Added support for relaxed SIMD instructions." and "Added support for WebAssembly Memory64." Safari 27 notes say: "Added support for WebAssembly JavaScript Promise Integration (JSPI)." ([27.3 beta](https://developer.apple.com/documentation/safari-release-notes/safari-27_3-release-notes); [27](https://developer.apple.com/documentation/safari-release-notes/safari-27-release-notes))
- Safari 26 (2025-09-15) notes include "Fixed an issue causing `wasm-unsafe-eval` to not get parsed as a valid CSP keyword" and "Added support for an in-place interpreter for Wasm" ([Safari 26 notes](https://developer.apple.com/documentation/safari-release-notes/safari-26-release-notes)).

**Cross-origin isolation**
- caniuse note: SharedArrayBuffer "Requires cross-origin isolation by having Cross-Origin-Embedder-Policy (COEP) and Cross-Origin-Opener-Policy (COOP) headers set" (Chrome 91+, Firefox 79+, Safari 15.2+) ([caniuse SharedArrayBuffer](https://caniuse.com/sharedarraybuffer)).
- BCD notes for Safari say shared `WebAssembly.Memory` "is gated behind COOP/COEP" ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- Safari 27 fixed `structuredClone()` and `postMessage()` to "correctly throw a DataCloneError when serializing a SharedArrayBuffer outside of cross-origin isolated contexts" ([Safari 27 notes](https://developer.apple.com/documentation/safari-release-notes/safari-27-release-notes)).
- **COEP `credentialless`:** Chrome and Edge 96 (2021-11-15), Firefox desktop 119 (2023-10-24) but **not Firefox for Android**, Samsung 17.0, Android WebView 96. **Safari and iOS WebView: not supported** ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- **`<iframe credentialless>`:** Chrome 110 only; not Firefox or Safari ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- **`cross-origin-isolated` Permissions-Policy:** Chrome 88, Samsung 15; not Firefox or Safari ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)).
- **`Document-Isolation-Policy`:** Chrome and Edge desktop 137, **Chrome Android 146**, Samsung 31.0. Not Firefox, Safari, Android WebView or iOS WebView ([BCD](https://unpkg.com/@mdn/browser-compat-data/data.json)). According to the explainer (undated):
  - DIP "will enable crossOriginIsolation for the document" by isolating it into its own process.
  - Its values are `isolate-and-require-corp` and `isolate-and-credentialless`.
  - Workers inherit it: DIP and COI status "are inherited from the creator of a DedicatedWorker or a SharedWorker".
  - An embedded widget can use DIP "regardless of whether its embedder deployed COI or not".
  - Without process isolation, as in Android WebView, "COI-gated APIs will not be available".
  - Source: [WICG/document-isolation-policy](https://github.com/WICG/document-isolation-policy).

**Memory ceilings in engine source** (main branches, read 2026-11-25)
- **V8:**
  - `kSpecMaxMemory32Pages = 65'536; // 4GB` and `kSpecMaxMemory64Pages = 262'144; // 16GB`.
  - `kV8MaxWasmMemory32Pages` is 65,536 (4 GiB) on 64-bit and 32,767 (2 GiB−64 KiB) on 32-bit.
  - `kV8MaxWasmMemory64Pages` is 262,144 (16 GiB) on 64-bit.
  - `kV8MaxWasmModuleSize = 1 GiB`.
  - Source: [V8 wasm-limits.h](https://chromium.googlesource.com/v8/v8/+/main/src/wasm/wasm-limits.h).
- **V8 ArrayBuffer:**
  - `JSArrayBuffer::kMaxByteLength = kMaxSafeBufferSizeForSandbox` when `V8_ENABLE_SANDBOX` is set, where `kMaxSafeBufferSizeForSandbox = 32ULL * GB - 1`.
  - Otherwise it is `kMaxInt` on 32-bit and `kMaxSafeInteger` on other 64-bit builds.
  - Sources: [js-array-buffer.h](https://chromium.googlesource.com/v8/v8/+/main/src/objects/js-array-buffer.h); [v8-internal.h](https://chromium.googlesource.com/v8/v8/+/main/include/v8-internal.h).
- **SpiderMonkey (Firefox):** `ByteLengthLimit = size_t(16) * 1024 * 1024 * 1024; // 16 GB.` on `JS_64BIT`, else INT32_MAX ([ArrayBufferObject.h](https://github.com/mozilla-firefox/firefox/blob/main/js/src/vm/ArrayBufferObject.h)).
- **JavaScriptCore (Safari):**
  - `MAX_ARRAY_BUFFER_SIZE (1ull << 34)` (16 GiB) under `USE(LARGE_TYPED_ARRAYS)` (64-bit), else `0x7fffffff` (2 GB).
  - `maxMemory32PageCount = 64 * 1024` (4 GiB).
  - Memory64's declarable maximum is capped by the page-aligned `MAX_ARRAY_BUFFER_SIZE`.
  - Sources: [PageCount.h](https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/runtime/PageCount.h); [WasmLimits.h](https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/wasm/WasmLimits.h).

**Memory64 costs** (SpiderMonkey blog, 2025-01-15):
- "the WebAssembly JS API constrains memories to a maximum size of 16GB".
- Memory64 workloads can be slower by "just 10% to over 100%" because bounds checks can no longer be elided.
- Recommendation: use it only if you need more than 4 GB.
- Source: [SpiderMonkey blog](https://spidermonkey.dev/blog/2025/01/15/is-memory64-actually-worth-using.html).

**Firefox interop bug:**
- Bug 2022805 (open, P2/S3): "WebGPU queue.writeBuffer() fails when WebAssembly heap size > 2GB". It throws "TypeError: GPUQueue.writeBuffer: ArrayBufferView branch … can't be an ArrayBuffer or an ArrayBufferView larger than 2 GB"; `writeTexture`, `setImmediateData` and `setBindGroup` are affected too.
- Roblox works around it by capping Wasm memory below 2 GiB in Firefox ([bug 2022805](https://bugzilla.mozilla.org/show_bug.cgi?id=2022805)).

### Inferences
- **The sidecar iframe needs cross-origin isolation for threaded Wasm.** The iframe runs without COOP/COEP today, so multi-threaded Wasm (SharedArrayBuffer) is unavailable in every browser. The options are:
  - **(a) Top-level isolation.** `ur.io` sends COOP `same-origin` and COEP. The iframe sends COEP and, in Chromium, is delegated with `allow="cross-origin-isolated"`. Safari needs COEP `require-corp`, which means CORP headers on every subresource.
  - **(b) Document-Isolation-Policy on the iframe document.** This works in Chrome/Edge desktop 137+ and Chrome Android 146+ only.
  - **(c) Single-threaded Wasm SIMD.** This works everywhere.
- **CPU fallback memory:** a wasm32 build cannot hold a ~2.6–3.7 GB model plus runtime state in one 4 GiB heap with comfortable headroom. Memory64 is a Chrome and Firefox option now and Safari only after 27.3 ships. Firefox's 2 GB `writeBuffer` bug penalizes Wasm-heap staging of weights for WebGPU. Streaming weights in chunks of ≤2 GB (better, ≤128 MiB to match Android bindings) avoids it.
- **CSP:** the CSP `script-src 'self' 'wasm-unsafe-eval'` should allow Wasm compilation in current browsers. Safari before 26 had a parsing bug for `wasm-unsafe-eval`, whose exact impact was not determined.

### Gaps
- It is not confirmed whether Chrome's shipped 64-bit builds on every platform (Android in particular) enable `V8_ENABLE_SANDBOX`, which determines whether the ArrayBuffer cap is 32 GiB−1 in practice.
- iOS-specific JSC caps on Wasm memory (for example fast-memory or reservation limits on iPhone) were not found.
- Firefox relaxed SIMD is 145 or 146 depending on the source.
- The Safari threads version is 14.1 or 15.2 depending on the source.
- No browser documents a per-tab total memory budget.

## 6. How do browsers behave with multi-GB model weights: device loss, GPU-process memory limits, the GPU watchdog and TDR, and known allocation ceilings?

### Takeaway
- **Hard ceilings are per buffer and per binding:** Dawn tiers of at most 4 GiB−4; Safari at most about 2 GiB on Mac and 1 GiB on iOS; 128 MiB bindings on most Adreno 7xx. No browser publishes a total VRAM budget, so the real total ceiling is process memory.
- **iOS** is the most fragile. WebKit says 1 GB buffers are "too likely to jetsam". WebKit now converts out-of-memory into device loss rather than a process crash, and has open bugs about stuck queues and GPU-resource exhaustion with LLM workloads.
- **Windows** resets the GPU after a default 2 s TDR, and Chromium has its own GPU watchdog. Long dispatches must be split.

### Cited Findings
**WebKit and iOS**
- WebKit commit, October 2024: "[WebGPU] Out of memory should trigger a device lost", aimed at avoiding process crashes on iOS ([webkit-changes, 2024-10](https://lists.webkit.org/pipermail/webkit-changes/2024-October/308501.html)).
- WebKit maintainer: iOS is too likely to jetsam at a 1 GB buffer; WebLLM reduced to 256 MB ([WebKit bug 275958](https://bugs.webkit.org/show_bug.cgi?id=275958)).
- WebKit bug 311598, "Limitations on submitted compute WebGPU CommandBuffers on iOS" (filed 2026-04-06; NEW; [bug 311598](https://bugs.webkit.org/show_bug.cgi?id=311598)):
  - Setup: a llama.cpp WebGPU backend built with Emscripten, using 400–600 compute passes per forward pass.
  - On iOS 26.3.1 the queue wait "gets stuck, repeatedly timing out" with no device-lost error, and two command buffers in flight were enough to trigger it. It was "more stable" on 26.4.
  - On an M3 Mac, transformers.js on Safari "crashed due to increasing memory" at about 29 tok/s.
  - Ad hoc M3 decode rates in tok/s:

    | Runtime | Chrome | Safari |
    |---|---|---|
    | llama.cpp WebGPU | 47.4 | 25.6 |
    | WebLLM | 42.1 | 40.3 |
    | transformers.js | 42.7 | crashed |

  - WebKit engineer advice: prefer one command buffer, or buffers each representing several milliseconds of work. WebKit "does not coalesce" command buffers or compute passes, and too many submissions "might be creating GPU resource exhaustion".
- An iPadOS 26 report saw the GPU process killed for memory once unattributed usage reached about 650 MB ([WebKit bug 303203](https://bugs.webkit.org/show_bug.cgi?id=303203); search-snippet detail only, not read in full).
- Safari 27.3 beta (2026-11-16) WebGPU fixes relevant to compute stability ([Safari 27.3 beta notes](https://developer.apple.com/documentation/safari-release-notes/safari-27_3-release-notes)):
  - "render bundles on some GPUs could cause the device to be unexpectedly lost";
  - "a GPU hang when a render pass issued repeated drawIndirect()…";
  - "an array value constructor referenced through a type alias could generate invalid Metal Shading Language, silently producing incorrect compute results";
  - "inlining three or more calls to a function operating on a large struct could silently miscompile on some devices";
  - "asynchronous pipeline creation could stall rendering".
- Safari 27.3 beta also improved Web Inspector's memory estimate to include WebGL and WebGPU textures and buffers (same notes).

**Windows TDR and the Chromium watchdog**
- Microsoft documents `TdrDelay`, "effectively the timeout threshold", with a default of 2 seconds. `TdrDdiDelay` defaults to 5 seconds, after which the OS bug-checks with VIDEO_TDR_FAILURE (0x116). After 5 TDRs (`TdrLimitCount`) within 60 s (`TdrLimitTime`) the system crashes. The default level is "Recover on timeout" ([Microsoft Learn, ms.date 2025-11-05](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/tdr-registry-keys)).
- Corentin Wallez (Chromium WebGPU), December 2021: "OSes have mechanisms to reset the GPU if it is unresponsive for a while, like Windows' TDR mechanism. Chromium has a 'watchdog' mechanism that triggers when GPU execution takes too long, and will restart the GPU process in that case." ([public-webapps-github, 2021-12](https://lists.w3.org/Archives/Public/public-webapps-github/2021Dec/0233.html)).

**Chrome device-loss and memory APIs**
- Chrome 116 returns a lost device from `requestDevice()` instead of rejecting ([WebGPU news index](https://developer.chrome.com/docs/web-platform/webgpu/news)).
- Adapter `memoryHeaps` (heap sizes and types) are exposed only behind the "WebGPU Developer Features" flag ([Chrome 121 post](https://developer.chrome.com/blog/new-in-webgpu-121)).
- A Chromium feature `kWebGPUUseDedicatedTransferBuffer` ("dedicated shared memory transfer buffers for mapped WebGPU buffers") exists but is disabled by default ([gpu_finch_features.cc](https://github.com/chromium/chromium/blob/main/gpu/config/gpu_finch_features.cc)).

**Allocation ceilings:** Dawn tiers cap `maxBufferSize` at 4 GiB−4 and `maxStorageBufferBindingSize` at 4 GiB−4 ([Dawn Limits.cpp](https://github.com/google/dawn/blob/main/src/dawn/native/Limits.cpp)). WebKit caps them at ≤INT_MAX on macOS and ≤1 GiB on iOS ([HardwareCapabilities.mm](https://github.com/WebKit/WebKit/blob/main/Source/WebGPU/WebGPU/HardwareCapabilities.mm)). See Q3 for observed distributions.

**Field reports** (low confidence)
- A 2026 write-up, seen only through a Hacker News mirror whose page later returned 404, reported two things. First, WebGPU exposure and adapter limits did not predict whether a small LLM would finish across four test environments. Second, an iPhone 11 Pro Max reporting a large `maxBufferSize` still had its tab restart mid-run, while a Pixel 8a on Chrome completed ([HN mirror search result](https://hackernews-dynamic.seasondane.workers.dev/news/48624985); original not located).

### Inferences
- **E2B on iPhones:** a ~2.6 GB E2B model on iPhone Safari needs at least three ≤1 GiB buffers and stays exposed to WebContent and GPU-process jetsam. Expect it to succeed only on high-RAM iPhones, and plan for tab reloads; the RAM threshold is unverified.
- **E4B on desktop:** a ~3.7 GB E4B model is feasible on desktop Chrome or Edge with 2 GiB bindings and enough VRAM or unified memory.
- **App design under these limits:**
  - Handle `device.lost` and re-initialize.
  - Use error scopes for `GPUOutOfMemoryError` when creating each weight buffer.
  - Split decode work into command buffers of a few milliseconds each, well under the 2 s TDR.
  - Avoid many small submits on Safari.
- **No VRAM query API:** without a standard API, apps must probe by allocating with error scopes, or fall back on device-class heuristics.

### Gaps
- No primary documentation was found for these:
  - Chrome's GPU-process memory cap or eviction policy on Android or desktop;
  - the Chromium watchdog timeout value;
  - Firefox's GPU-process memory limits or watchdog;
  - per-tab WebContent memory limits on iOS 26/27 by device RAM.
- The original of the "feature detection was not enough" write-up was not found.
- WebKit bug 303203 was seen only as a search snippet.

## 7. What share of desktop and mobile users can run WebGPU today?

### Takeaway
- **Published estimates:** caniuse, based on StatCounter, puts browser-level WebGPU support at **86.83% full plus 3.32% partial** of global usage (data 2026-11-24). Web3D Survey, which measures real adapters, reports **82.89%** of reports returning a working adapter (undated).
- **By platform** (Web3D Survey): Android about 70% and Linux about 18%; Windows about 88%, macOS about 91% and iOS about 90%.
- **LLM-capable share:** no published figure exists for the share that can run a multi-GB LLM. It is materially lower than the above once f16, binding size, RAM and Firefox are considered.

### Cited Findings
- **caniuse** WebGPU (data updated 2026-11-24): `usage_perc_y` 86.83 and `usage_perc_a` 3.32 ([caniuse webgpu](https://caniuse.com/webgpu); [raw data](https://github.com/Fyrd/caniuse/blob/main/fulldata-json/data-2.0.json)).
  - Partial means Firefox (Windows only from 141; Windows plus Tahoe on Apple Silicon from 145) and macOS Safari (Tahoe+ only).
  - caniuse marks Chrome for Android 157 and Samsung Internet as fully supported even though device GPU gating applies (Q1). Chrome desktop is marked "Support on Linux depends on hardware and drivers" (note 9).
- **Web3D Survey** (undated; no date range or sample size stated; "Share of all reports where WebGPU returned a working adapter"; [web3dsurvey](https://web3dsurvey.com/webgpu)):
  - Overall: **82.89%**.
  - By platform: Android 69.8%, ChromeOS 92.7%, iOS 89.96%, Linux 18.03%, macOS 90.87%, Windows 88.12%.
  - By browser: Chrome/Chromium 84.25%, Edge 93.21%, Firefox 59.16%, Opera 89.51%, Safari 84.33%, Samsung Internet 75.34%, Other 81.68%.
- **Chrome Status, WebGPU Compatibility Mode** (entry created 2025-03-20, updated 2026-03-18; statistics undated within it):
  - "on Chrome on Windows, 31% of Chrome users do not have Direct3D FL 11.1 or higher. On Android, 23% of Android users do not have Vulkan 1.1, including 15% who do not have Vulkan at all (https://developer.android.com/about/dashboards). On ChromeOS, Vulkan penetration is still quite low, while OpenGL ES 3.1 is ubiquitous."
  - The Windows figure is quoted verbatim and looks surprisingly high. It may refer to a D3D12-at-FL-11.1 capability; this was not verified.
  - Source: [Chrome Status 6436406437871616](https://chromestatus.com/feature/6436406437871616).
- **Features among WebGPU-capable reports** (Web3D Survey, undated): `shader-f16` 94.31%, `subgroups` 67.42%; `maxStorageBufferBindingSize` ≥2 GiB−1 in only 16% of reports; Android ≥512 MiB in only 52% ([web3dsurvey](https://web3dsurvey.com/webgpu); [limits](https://web3dsurvey.com/webgpu/limits/maxStorageBufferBindingSize)).

### Inferences
- **Order of magnitude:** about 80–87% of visitors have *some* WebGPU adapter, measured by browser share or by survey.
- **Multi-GB LLM share:** the share that can run a multi-GB, f16, quantized LLM entirely on GPU is lower still. A plausible upper bound is about 60–70% on desktop and well below 50% on phones; this is an estimate, not a sourced figure.
- **Who is excluded:** Firefox users without f16, Linux, Android Adreno 7xx (128 MiB bindings, workable only with heavy sharding), iPhones below the RAM needed for a 2.6 GB model, low-VRAM Windows GPUs, and users of Lockdown, Advanced Protection or similar modes.
- **Data source:** Web3D Survey's per-platform shares come from its own visitor base (developer-heavy sites) and probably overstate the general population.

### Gaps
- No vendor (Google, Apple, Mozilla, Microsoft) has published a WebGPU-capable share of their users. Chrome Platform Status use counters measure page usage, not capability, and were not retrieved.
- Web3D Survey gives no sampling window, sample size or population description.
- No source estimates the share of devices with enough RAM or VRAM for 2.6–3.7 GB models in-browser.
