# Security and trust model of local AI inference in an end-to-end-encrypted web app, and alternatives to running the model in the page (state as of 2026-11-25)

Conventions used below:
- **[Shipped]** means it is in a stable browser release. **[Proposal]** means a draft spec, an intent, a prototype, a flag or an origin trial. **[Undated]** means the source page shows no date.
- Dates are the source's publication date unless noted otherwise.
- **(excerpt)** marks a claim I read only in a search-engine excerpt of the cited page, not in a full fetch of it. Unmarked claims came from fetching the page itself.
- Inferences about the design (ur.io pages served through Cloudflare, framing https://sidecar.ur.io/v1/, whose dedicated Worker decrypts) are kept in the Inferences subsections. They are not sourced facts.

## Code integrity for end-to-end-encrypted web apps

### Takeaway
As of November 2026, no shipped browser feature lets a site prove that its top-level page, an iframe document or a Worker script matches a signed or publicly logged release. SRI, Integrity-Policy (Chrome 138, Firefox 145 partial, Safari 26 partial) and signature-based SRI (Chrome 141) only bind subresources to hashes or keys named in HTML that the same server delivers. That protects against a CDN or a third-party host, but not against the origin itself. The fix designed for this gap, WAICT (a manifest, a transparency log and a preload list), exists only as draft specs and a Firefox Nightly prototype. What can be deployed today is:
- user-installed verifier extensions (Code Verify, WEBCAT alpha), all of which a 2026 study found to have exfiltration bugs;
- Isolated Web Apps, which are still limited to managed ChromeOS.

### Cited Findings

#### Subresource Integrity and Integrity-Policy [Shipped]
- Integrity-Policy lets a site require SRI metadata on every resource of the listed request destinations. In MDN's words, the browser "will block requests on specified request destinations that omit integrity metadata, and will also block requests in no-cors mode from ever being made".
  - Directives: `blocked-destinations` (`script`, `style`); `sources` (only `inline`, meaning the integrity attribute); `endpoints` (reporting through the Reporting API, with a Report-Only variant).
  - MDN marks it "not Baseline". Page last modified 2026-11-23. — [MDN Integrity-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy)
- Browser support, from MDN browser-compat-data read in November 2026 — [MDN BCD Integrity-Policy.json](https://raw.githubusercontent.com/mdn/browser-compat-data/main/http/headers/Integrity-Policy.json):
  - **Chrome 138:** scripts only; `style` is not supported. Edge and Android follow Chrome.
  - **Firefox 145:** partial. Reporting `endpoints` are ignored and violations are only logged to the console. `style` has been experimental since Firefox 142 behind `security.integrity_policy.stylesheet.enabled`.
  - **Safari 26:** partial. "Module scripts are blocked even when an import map provides integrity metadata." `style` is not supported.
- Chrome's Intent to Implement and Ship for "Integrity Policy for scripts" was posted 2025-04-23 by Yoav Weiss (Shopify). It targeted M137 and received three LGTMs that day. At the time Gecko and WebKit had given no formal signal; the author said Mozilla was "planning to follow suite AFAIK". — [blink-dev intent](https://groups.google.com/a/chromium.org/g/blink-dev/c/Q304_OkDAZA)
- `fetch()` takes an `integrity` option (`sha256`, `sha384` or `sha512`). The browser hashes the fetched resource and rejects the request with a network error on a mismatch. This is the hook for pinning WASM or model files fetched by script. MDN page modified 2026-06-26. — [MDN RequestInit](https://developer.mozilla.org/en-US/docs/Web/API/RequestInit)
- **Coverage gaps:**
  - The WAICT explainer [Undated] says SRI "is restricted to scripts at this time", with styles, WASM and "further subresources" to follow — [WAICT explainer](https://github.com/beurdouche/explainers/blob/main/waict-explainer.md).
  - Cloudflare (2025-10-16) lists "extending SRI to more data types" as a next step and treats SRI for WASM as still to come — [Cloudflare blog](https://blog.cloudflare.com/improving-the-trustworthiness-of-javascript-on-the-web/).

#### Signature-based SRI [Shipped in Chrome 141 per its intent; I did not confirm this in release notes]
- The Intent to Ship was posted 2025-08-13 — [blink-dev I2S](https://groups.google.com/a/chromium.org/g/blink-dev/c/R6isgRnE1j4):
  - **Mechanism:** servers sign responses with an Ed25519 key, and pages can require the browser to verify the signature against a specific public key. It uses the `Signature` and `Signature-Input` headers, and parses and enforces `Unencoded-Digest`.
  - **Timeline:** the origin trial ran M135 to M141, and the target was Chrome 141 on desktop, Android and WebView. Three API-owner LGTMs came on 2025-08-13, 08-18 and 08-19.
  - **Other engines:** WebKit's signal was "Support"; Gecko's was "No signal".
- In the WICG draft, the page puts the Ed25519 public key in the `integrity` attribute, and the signature covers the resource's digest (excerpt) — [WICG Signature-based Integrity](https://wicg.github.io/signature-based-sri).
- The origin trial ran M135 to M141 on desktop, Android and WebView (excerpt) — [blink-dev Intent to Experiment](https://groups.google.com/a/chromium.org/g/blink-dev/c/QSsuBmjlnfk/m/jZA-M5VhAgAJ)

#### WAICT: Web Application Integrity, Consistency and Transparency [Proposal; Firefox Nightly prototype]
- **Cloudflare's design post** (published 2025-10-16; page metadata shows a modification on 2026-07-15) — [Cloudflare](https://blog.cloudflare.com/improving-the-trustworthiness-of-javascript-on-the-web/):
  - **Components:** an integrity manifest maps asset hashes to paths and sets an integrity policy. Each site has a hash-chain log of its manifests, and a global prefix tree maps each domain to its log. Witnesses check tree updates and sign the root, and browsers check those signatures.
  - **Enrollment:** browsers ship a "transparency preload list". "Participation in transparency should be strictly opt-in." Unenrolling leaves a timestamped tombstone, and clients enforce a 24-hour cooldown.
  - **What it does not do:** "One problem that WAICT doesn't solve is that of provenance." "Transparency does not help detect malicious code or even prevent its distribution." For v1.0, "We will not achieve the strongest version of consistency".
  - **Standing and plans:** the post calls WAICT a W3C-backed effort among browser vendors, cloud providers and encrypted-communication developers. Cloudflare plans to run a transparency service and a witness, and "hope[s] to have some exciting betas soon". No dates are given.
- **Mozilla Hacks** (2026-05-05, Firefox Security Team) — [Mozilla Hacks](https://hacks.mozilla.org/2026/05/trustworthy-javascript-for-the-open-web/):
  - **Properties:** "Integrity: The code executed by the user matches what the developer committed to in a manifest". "Transparency: These manifests are publicly logged and can be independently audited."
  - **Enforcement:** sites opt in. If an opted-in site serves code that was not logged, "the browser rejects it".
  - **Collaborators named:** Cloudflare, the Freedom of the Press Foundation and Meta.
  - **Status:** an "early prototype" sits "behind a pref in Firefox Nightly". A demo at waict.dev includes an E2EE video-calling app. The specs are developed at github.com/waict-wg. Mozilla calls it "a work in progress, not a finished solution". It was presented in a joint talk at Real World Crypto 2026.
- **The waict-wg GitHub organization**, as fetched 2026-11 — [GitHub waict-wg](https://github.com/waict-wg):
  - draft `waict-integrity-spec`, last updated 2026-09-29, with 27 open issues;
  - draft `waict-transparency-spec`, last updated 2026-05-27, with 17 open issues;
  - `demo-site`, last updated 2026-03-08.
  - The org lists no public members.
- **The WAICT explainer** [Undated] — [explainer](https://github.com/beurdouche/explainers/blob/main/waict-explainer.md):
  - **Opt-in:** an HTTP header, possibly a CSP extension, with an `integrity-manifest` directive, `integrity-manifest-src` and `integrity-enforcement-level`. Downgrade protection works "similar to HSTS".
  - **Coverage:** scripts first, then styles and WASM. The explainer does not address workers, service workers, iframes or eval/blob code.
  - **Venues:** W3C WebAppSec and the IETF are named as possible venues.

#### Verifier extensions and an independent evaluation
- **Meta's Code Verify** — [Firefox Add-ons listing](https://addons.mozilla.org/en-US/firefox/addon/code-verify/):
  - It is an MIT-licensed browser extension that checks the web clients of WhatsApp, Facebook, Instagram and Messenger. It compares their JavaScript with a "source of truth posted on Cloudflare" and alerts the user on mismatch.
  - The listing shows version 4.1.0, updated 2025-09-17 (excerpt).
  - It launched in March 2022 for WhatsApp Web: Cloudflare publishes the hash, and the extension compares it with the code actually running (excerpt) — [Cloudflare 2022](https://blog.cloudflare.com/cloudflare-verifies-code-whatsapp-web-serves-users/), [The Register 2022-03-10](https://www.theregister.com/2022/03/10/whatsapp_cloudflare_code/)
- **WEBCAT** (Freedom of the Press Foundation / SecureDrop; update posted 2026-05-04) — [SecureDrop](https://securedrop.org/news/webcat-update-independent-evaluation-waict-and-a-growing-team/):
  - It is a browser extension in alpha on Mozilla's add-ons site, "heading toward a beta release" with no date given.
  - Its design and WAICT are converging on shared choices: a split between active and passive content, and a default-fallback page pattern.
  - Open differences: preventing dynamic code execution, closer scrutiny of HTTP headers, and the CSP header.
  - The post says "A web-native standard shipped by multiple browsers beats any extension-based approach."
- **"Trust on Reload: Securing Browser-Based End-to-End Encryption"** (Schwarz, Bauckholt, Trampert; CISPA; The Web Conference 2026; listed 2026-04-12):
  - It surveyed five client-side code-integrity tools and found that they only partly address real threats. It reports "over a dozen bugs" that allowed secret exfiltration across all the tools. — [CISPA](https://cispa.de/en/research/publications/213253-trust-on-reload-securing-browser-based-end-to-end-encryption)
  - SecureDrop puts the counts at nine common pitfalls and 18 disclosed bugs. It says the paper found WEBCAT "provides the broadest security guarantees". It names two pitfalls in WEBCAT's original version, both since fixed: P3, missing verification of the HTTP Location header, and P5, no option to verify non-active resources such as fonts and images. — [SecureDrop](https://securedrop.org/news/webcat-update-independent-evaluation-waict-and-a-growing-team/)
  - The paper also proposes a new design, built as a proof-of-concept extension that "exhaustively verifies a web application while blocking modified resources" — [CISPA](https://cispa.de/en/research/publications/213253-trust-on-reload-securing-browser-based-end-to-end-encryption)

#### Isolated Web Apps and Signed Web Bundles [Shipped only for managed ChromeOS]
- Chrome's IWA docs [Undated] — [Chrome IWA introduction](https://developer.chrome.com/docs/iwa/introduction):
  - **Availability:** the first release is limited to "Chrome Enterprise administered ChromeOS devices and select development partners", with "unmanaged and cross-platform devices in the future". Admins install IWAs on managed Chromebooks.
  - **Developer mode:** set `chrome://flags/#enable-isolated-web-app-dev-mode` (Chrome or ChromeOS 120 and later).
  - **Packaging and identity:** apps ship as Signed Web Bundles (`.swbn`) with an integrity block, signed with Ed25519 or ECDSA P-256. "Instead of TLS keys, IWAs are signed with a key that can be kept securely offline." The origin is `isolated-app://<Web Bundle ID>/`, derived from the public key.
  - **Mandatory restrictions:** a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, `require-trusted-types-for 'script'`) plus COOP, COEP and CORP.
  - **Updates:** checked every 4 to 6 hours against an update manifest.
- The Intent to Ship (July 2024) said ChromeOS would come first and installation would be by enterprise policy on managed devices only (excerpt) — [blink-dev IWA I2S](https://groups.google.com/a/chromium.org/g/blink-dev/c/iMfYonTs414/m/tgT7z51CBAAJ)
- From Chrome 143 on ChromeOS, only IWAs on Google's allowlist can be installed or updated through the Admin Panel. The same restriction will apply to other operating systems "starting from their initial support for Isolated Web Apps", which implies they had none when the page was written (excerpt) — [Chrome IWA allowlist](https://developer.chrome.com/docs/iwa/allowlist)
- "Currently, Isolated Web Apps are the only use case for Signed Web Bundles" (excerpt) — [Chromium IWA doc](https://chromium.googlesource.com/chromium/src/+show/lkgr-android-internal/docs/webapps/isolated_web_apps.md)

#### Service-worker code pinning [Technique only; browsers offer no pinning]
- Chromium's Service Worker Security FAQ (excerpt) — [Chromium SW security FAQ](https://chromium.org/Home/chromium-security/security-faq/service-worker-security-faq):
  - "The browser performs an update check after any navigation using the Service Worker, invalidating the HTTP cache every 24 hours". "Site operators can shrink the window of vulnerability by setting lower TTLs on SW scripts."
  - It encourages a "kill-switch SW": "The right cleanup strategy (for this and other issues) is Clear-Site-Data."
  - Together these mean a server can always replace or remove a pinned service worker.
- Academic prior art exists. Sutter et al. (2021, ZHAW), "Web content signing with service workers". I did not read it. — [PDF](https://srv-clst-301-data66.zhaw.ch/bitstream/11475/22514/3/2021_Sutter-etal_Web-content-signing-with-service-workers.pdf)

#### What end-to-end-encrypted services do on the web
- **Signal** has no web client:
  - Its desktop client began as a Chrome App. In 2017 Signal launched a standalone desktop app (Electron) and deprecated the Chrome App (excerpt) — [Signal blog](https://signal.org/blog/standalone-signal-desktop/).
  - Third-party docs confirm there is no web app (excerpt) — [WebCatalog](https://docs.webcatalog.io/en/articles/10809948-does-webcatalog-desktop-support-signal).
  - I found no official Signal statement of its reasons (see Gaps).
- **WhatsApp** runs WhatsApp Web and addresses code trust with Code Verify (above).
  - Until its 2021 multi-device launch, WhatsApp's design used the phone as the source of truth. After it, each companion device has its own identity key (excerpt; Meta Engineering, July 2021) — [Meta Engineering](https://engineering.fb.com/2021/07/14/security/whatsapp-multi-device/)
- **Proton** ships web apps but rates them below its native clients. Its threat model page [Undated; it carries a 2019 update note] (excerpt) — [Proton threat model](https://proton.me/blog/protonmail-threat-model):
  - says TLS protects delivery of the web code;
  - says the mobile apps and the Bridge desktop software are harder to compromise than the web client;
  - lists a malicious software update as a threat it addresses only partly.
- A 2020 FOSDEM talk by Proton's Daniel Huigens, "Building a Web App that Doesn't Trust the Server", treated open-source clients as necessary but not sufficient and proposed a "Source Code Transparency" system (excerpt) — [FOSDEM 2020](https://archive.fosdem.org/2020/schedule/event/dip_securing_protonmail/). A matching WICG proposal also exists (excerpt) — [WICG proposals #124](https://github.com/WICG/proposals/issues/124).
- FPF (2024-12-19) lists WhatsApp Web, Proton Mail, Tuta, browser-based collaboration suites, crypto wallets and whistleblowing platforms as sharing this "chicken-and-egg problem". SecureDrop's browser-based redesign is the reason WEBCAT exists. — [FPF](https://freedom.press/tech/news/the-long-and-winding-road-to-safe-browser-based-cryptography/)

### Inferences
- **What each shipped feature covers.**
  - SRI, Integrity-Policy and signature-based SRI all take their expected hash or key from the HTML of the document that loads the resource.
  - For `sidecar.ur.io/v1/`, whoever controls that origin's responses controls the expected values. These features protect the loader and WASM against tampering by a third-party host. They do not protect against the sidecar origin's own server being compromised or coerced.
  - Nothing shipped verifies the iframe's own HTML or the dedicated Worker's script against the signed release checksums.
- **Signature-based SRI** is the closest shipped fit for "signed release checksums": the release key can sign the loader and WASM responses. But Gecko gave no signal, and the public key still comes from unverified HTML. It raises the bar against partial tampering, not against a malicious origin.
- **WAICT** is the only proposal that matches the design's rule that no company server is trusted. It offers a preload list with no trust on first use, plus public logs that make targeted versions detectable. Its timing is unknown: draft specs, one Nightly prototype, and no Chrome or Safari commitment found. The design should not count on it before 2027 or later.
- **Service-worker pinning can only delay or detect.** The server can force an update within at most 24 hours and can wipe the registration with `Clear-Site-Data`, and the pin does not exist on first load. It does not prevent an attack.
- **Verifier extensions** are the practical way today to give advanced users independent checking. "Trust on Reload" suggests a homegrown verifier is likely to have exfiltration bugs unless it follows that paper's pitfalls list.
- **The ur.io page script** cannot read the Worker's memory through web APIs, because the frames are cross-origin. But it chooses what to frame, it can send arbitrary postMessage requests, and it receives every view the Worker grants. The view policy, not code integrity, bounds what Cloudflare-altered script can obtain.

### Gaps
- I found no official Signal statement explaining why there is no web client. The reasons commonly given come from low-quality secondary sites.
- I found no evidence that Apple or WebKit takes part in WAICT. Mozilla's May 2026 post names only Cloudflare, FPF and Meta, and no WebKit standards position on WAICT turned up. Google's Chrome position on WAICT was also not found.
- I could not confirm whether Integrity-Policy's `script` destination covers worker scripts (`new Worker()`, `importScripts`) or WASM fetched by script. Chrome's intent and MDN only say "scripts".
- The 24-hour service-worker update rule and the kill-switch advice come from search excerpts of the Chromium FAQ. Hard-reload bypass of service workers was not verified.
- I did not confirm on chromestatus or in Chrome release notes that signature-based SRI reached stable in M141.
- I found no 2026 announcement that IWAs reached Windows, macOS, Linux or unmanaged devices.

## Model artifacts as code

### Takeaway
Among in-browser engines, WebLLM/MLC is the clear case of a model that ships code: each model's "model library" is a WASM module with embedded WGSL GPU kernels, so it must be pinned and trusted exactly like the app's own code. The other formats (`.litertlm`/`.task`, ONNX, GGUF, safetensors) are data, but they are parsed by memory-unsafe C++ compiled to WASM, and GGUF and ONNX parsers have a 2024–2026 record of crafted-file heap overflows. Browsers can hash-pin any fetched file with `fetch(..., {integrity})`, but WebLLM and Transformers.js do not verify hashes by default, and no browser verifies model signatures.

### Cited Findings
- **WebLLM and MLC model libraries are code:**
  - A WebLLM model has two parts: converted, quantized weights and a WASM library. The library holds compiled WebGPU kernels in WGSL (for prefill and decode) plus non-kernel code. It is built by MLC-LLM and Apache TVM with `--target webgpu`.
  - At runtime, MLCEngine runs the WGSL kernels through WebGPU and the non-kernel functions as WebAssembly (excerpt) — [WebLLM paper, arXiv 2412.15803](https://arxiv.org/html/2412.15803v1), [MLC blog 2024-06-13](https://blog.mlc.ai/2024/06/13/webllm-a-high-performance-in-browser-llm-inference-engine)
  - Several weight variants can share one library, and custom weights point at a library through the `model_lib_url` field (excerpt) — [web-llm GitHub](https://github.com/mlc-ai/web-llm)
- **LiteRT-LM `.litertlm`** is "a single unified container that packages your TFLite models, tokenizer files, external weights, and associated model metadata".
  - Its section types include `SP_Tokenizer` (a SentencePiece model), `LlmMetadata` (protobuf) and `TFLiteModel`. The builder also accepts a Hugging Face `tokenizer.json`. — [Google AI Edge, LiteRT-LM File Builder](https://ai.google.dev/edge/litert-lm/file_builder) (excerpt)
  - A secondary teardown says it also carries the chat template and execution graph and is "closer to an APK for inference" than a plain model file — [dev.to](https://dev.to/jdshah/i-opened-a-litertlm-file-here-is-what-is-actually-in-there-4aof) (excerpt)
- **GGUF (llama.cpp) parser bugs from crafted files** (all excerpt):
  - Cisco Talos, 2024: heap overflows in GGUF parsing. CVE-2024-21825 is in array and string parsing; Talos says a crafted `.gguf` can lead to code execution. CVE-2024-21802 (tensor-info parsing) is CVSS 8.8. CVE-2024-21836 is a related bug. — [Talos TALOS-2024-1912](https://talosintelligence.com/vulnerability_reports/TALOS-2024-1912), [NVD CVE-2024-21836](https://nvd.nist.gov/vuln/detail/CVE-2024-21836)
  - CVE-2025-53630: an integer overflow in `gguf_init_from_file_impl` leads to out-of-bounds heap reads and writes — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-53630).
  - GHSA-3p4r-fq3f-q74v is a follow-on integer overflow in the same function. It says the main model-loading path is not affected, but control vectors and the `llama-gguf` and `llama-quantize` tools are — [llama.cpp advisory](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v).
- **ONNX:** the known crafted-model bugs are path traversal through "external data" references, in the Python `onnx` library rather than onnxruntime (all excerpt):
  - CVE-2024-27318 (ONNX 1.4.0 to 1.15.0) — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-27318/), [HiddenLayer advisory, Feb 2024](https://www.hiddenlayer.com/sai-security-advisory/2024-02-onnx)
  - CVE-2025-51480 (arbitrary write through `save_external_data`) — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-51480/)
  - CVE-2026-34446 (hardlinks) and CVE-2026-34447 (symlinks), both fixed in ONNX 1.21.0 — [SentinelOne 34446](https://www.sentinelone.com/vulnerability-database/cve-2026-34446), [SentinelOne 34447](https://www.sentinelone.com/vulnerability-database/cve-2026-34447)
- **safetensors** (all excerpt):
  - A Trail of Bits review ran 2023-03-20 to 24, commissioned by EleutherAI, Hugging Face and Stability AI. Its notable finding was that a crafted file could be parsed as two different models (polyglot files, a validation gap). — [Trail of Bits report](https://www.trailofbits.com/documents/2023-03-eleutherai-huggingface-safetensors-securityreview%20(2).pdf), [Hugging Face blog](https://huggingface.co/blog/safetensors-security-audit)
  - EleutherAI: "while it is impossible to prove the absence of flaws, this is a major step in giving reassurance that safetensors is indeed safe to use" — [EleutherAI](https://blog.eleuther.ai/safetensors-security-audit/)
- **Model signing:** OpenSSF Model Signing (OMS) (all excerpt):
  - The `model-signing` v1.0 library and CLI launched in April 2025, built on sigstore-python — [Sigstore blog](https://blog.sigstore.dev/model-transparency-v1.0).
  - The format was formalized as OMS in June 2025 — [OpenSSF 2025-06-25](https://openssf.org/blog/2025/06/25/).
  - OMS defines a detached signature file in Sigstore Bundle Format, kept with the model, and works with bare keys, PKI chains or Sigstore keyless signing — [OMS spec README](https://raw.githubusercontent.com/ossf/model-signing-spec/main/README.md).
  - NVIDIA signs NGC catalog models, and Google was prototyping it on Kaggle — [HiddenLayer](https://hiddenlayer.com/insight/openssf-model-signing-for-safer-ai-supply-chains).
  - Hugging Face had not committed to OMS by default, according to a weak secondary source — [Safeguard.sh](https://safeguard.sh/resources/blog/openssf-model-signing-v1-0-sigstore-ml-supply-chain).
- **Hash pinning in the browser:**
  - `fetch()` supports SRI hashes natively — [MDN RequestInit](https://developer.mozilla.org/en-US/docs/Web/API/RequestInit).
  - Searches turned up no default hash checking in WebLLM or Transformers.js. A third-party package, VerifyFetch, checks WebLLM and Transformers.js files against SRI hashes before they enter web-llm's cache (excerpt) — [pkgstats @verifyfetch/webllm](https://www.pkgstats.com/pkg:@verifyfetch/webllm), [SitePoint](https://www.sitepoint.com/security-client-side-models/).
  - A Mozilla Bugzilla entry opened in November 2026 proposes re-verifying cached model copies when they are loaded from OPFS, and loading models without a published hash only after the user agrees (excerpt) — [Bugzilla 2091099](https://bugzilla.mozilla.org/show_bug.cgi?id=2091099)

### Inferences
- **Per-format risk inside a browser:**
  - **MLC/WebLLM:** the model library is first-party-equivalent code. A malicious library runs with the full authority of the Worker that loads it, including any plaintext or keys in that Worker. It should be pinned like the loader, ideally built and checksummed in the same signed release.
  - **GGUF** (wllama and similar), **TFLite/`.litertlm`/`.task`** (flatbuffers and protobuf parsed by the MediaPipe/LiteRT WASM) and **ONNX** (protobuf parsed by onnxruntime-web): a crafted file can at most corrupt memory inside the WASM instance. It cannot escape the browser sandbox without a second bug.
    - But that instance's linear memory holds the prompt and output, and the JS around it may have network access. A parser exploit there could read the plaintext and try to send it out.
    - The ONNX external-data path bugs are filesystem bugs. They should not apply in a browser, which has no filesystem paths. This is unverified for onnxruntime-web.
  - **safetensors** has the least parser surface: a JSON header and raw tensors. It is still parsed by whatever engine converts it.
  - **Tokenizer files and chat templates** (inside GGUF metadata, `tokenizer.json`/`tokenizer_config.json`, `.litertlm`) act like code. In JS engines a template interpreter cannot run arbitrary JS, but a malicious template can rewrite prompts silently. This is inferred, not sourced.
- **Isolation:** load model files in a Worker that holds no keys. Pass it only the plaintext needed for the request, so a malicious weight file or parser exploit can reach that plaintext at most, never the key material.
- **Verification options:**
  1. Pin SHA-256/384 hashes of every file (weights, tokenizer, config, model library) in the signed release manifest and fetch with `integrity`, or hash in-Worker before use.
  2. Treat cached copies in Cache, IndexedDB or OPFS as untrusted and re-verify them on load, as the Mozilla bug proposes.
  3. Verify OMS/Sigstore bundles in WASM if model provenance matters. No browser does this natively.

### Gaps
- I did not confirm what a MediaPipe `.task` bundle contains, or whether the MediaPipe or LiteRT web runtimes execute anything shipped with the model beyond parsing.
- I did not check WebLLM's or Transformers.js's source to see whether they verify cached artifacts or support integrity options.
- Whether `fetch()` integrity checking of multi-gigabyte files buffers the whole response before resolving, and the memory cost of that, was not researched.
- I found no published CVE specific to onnxruntime-web or the MediaPipe web runtime's parsers.

## WebGPU security

### Takeaway
WebGPU adds a large, memory-unsafe attack surface to the GPU process, which is "less sandboxed" than renderers and shared across origins.
- **Exploited bugs:** Chrome's Dawn had many use-after-free bugs in 2025–2026, including CVE-2026-5281, exploited in the wild (fixed in Chrome 146, April 2026). Firefox's WebGPU had a series of 2026 CVEs.
- **Cross-origin memory reads:** none are known through WebGPU. Memory is zero-initialized and shader accesses are bounds-checked; LeftoverLocals did not affect WebGPU.
- **Side channels:** contention and cache timing side channels across origins are documented and acknowledged in the spec. They can reveal that, and roughly when, another page uses the GPU, plus keystroke timing and website fingerprints.

### Cited Findings

#### Memory leakage: LeftoverLocals and later work
- LeftoverLocals (CVE-2023-4969), published by Trail of Bits on 2024-01-16 (excerpt) — [Trail of Bits](https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/), [CERT VU#446598](https://kb.cert.org/vuls/id/446598):
  - It lets a co-resident process read leftover GPU local memory on Apple, AMD, Qualcomm and Imagination GPUs. It was shown "listening to LLM responses".
  - Browser GPU frameworks such as WebGPU "appear not to be currently impacted" because they add dynamic memory checks to GPU kernels.
  - Imagination shipped a fix in DDK 23.3 in December 2023 — [The New Stack](https://thenewstack.io/with-leftoverlocals-gpus-can-leak-llm-prompt-data/), [SC Media](https://scmagazine.com/news/amd-apple-qualcomm-imagination-gpus-could-leak-ai-secrets-via-leftoverlocals).
- SafeRace (Levine, Sorensen et al.; ACM DOI 10.1145/3763075; date not confirmed) (excerpt) — [SafeRace PDF](https://reeselevine.github.io/assets/pdf/saferace.pdf), [summary](https://tyler-utah.github.io/files/summaries/saferace.md):
  - Under current specs, WGSL bounds checks "can be optimized away in some programs" that contain data races, which could lead to memory-safety violations.
  - The authors report GPU memory-isolation vulnerabilities in Apple and AMD GPUs, and a security-critical WGSL miscompilation in a pre-release Firefox.
- WebKit added a bounds-checking pass to its WGSL compiler in February 2024, and robust-access CTS tests pass with it — [webkit-changes](https://lists.webkit.org/pipermail/webkit-changes/2024-February/297570.html). A 2026 WebKit bug says bounds checks on override-sized arrays should happen at pipeline creation — [WebKit bug 306411](https://bugs.webkit.org/show_bug.cgi?id=306411) (both excerpt).

#### Side channels and fingerprinting
- **"Generic and Automated Drive-by GPU Cache Attacks from the Browser"** (TU Graz; ASIA CCS 2024) (excerpt) — [paper](https://www.gruss.cc/files/WebGPUAttacks.pdf), [SecurityWeek](https://www.securityweek.com/new-attack-shows-risks-of-browsers-giving-websites-access-to-gpu/):
  - It is the first GPU cache side channel mounted from WebGPU.
  - Inter-keystroke timing attack: F1 82–98% on NVIDIA.
  - Prime+Probe covert channel from native code to the browser: up to 10.9 kB/s.
  - Tested on 11 desktop GPUs (two AMD, nine NVIDIA).
- **WebGPU-SPY** (ASIA CCS 2024): a GPU cache attack on Intel integrated GPUs in which the compute stack spies on the rendering stack. Website fingerprinting reached precision of 90 for the top 100 sites (excerpt) — [arXiv 2401.04349](https://arxiv.org/pdf/2401.04349)
- **GPU.zip** (September 2023) (excerpt) — [GPU.zip site](https://www.hertzbleed.com/gpu.zip), [CMU CyLab](https://cylab.cmu.edu/news/2023/09/26-gpu-zip.html), [PC Gamer](https://pcgamer.com/hackers-could-steal-your-data-via-an-unpatched-gpu-pixel-stealing-attack-though-that-could-is-doing-some-real-heavy-lifting):
  - It steals pixels across origins through GPU data compression. It works in Chrome and Edge when cross-origin iframes load with cookies, SVG filters render on iframes, and rendering is on the GPU.
  - Firefox and Safari did not meet all the conditions. Sites that refuse cross-origin embedding through X-Frame-Options or CSP are not susceptible.
  - It was reported as unpatched in 2023. I found no later fix.
- **Fingerprinting through compute behavior** (excerpt):
  - "AtomicIncrement" (Hohentanner, Kemmerzell, Florschütz; WiSec 2025) uses compute-shader scheduling behavior to re-identify a device with 70% accuracy among 500 devices — [FAU CRIS](https://cris.fau.de/publications/348779971).
  - LockedApart (Laor and Oren, poster) measures contention between GPU threads. It is up to 310 times faster and 1.8 times more accurate than DrawnApart — [RUB OJS](https://ojs.ub.rub.de/index.php/uASC/article/view/12008).
  - MDN says GPUAdapterInfo is kept minimal because of fingerprinting risk — [MDN GPUAdapterInfo](https://developer.mozilla.org/docs/Web/API/GPUAdapterInfo).
- **Token leakage from local LLM inference via CPU caches:**
  - "Spill The Beans" (May 2025) — [arXiv 2505.00817](https://arxiv.org/abs/2505.00817v1).
  - "I Know What You Said", which covers GPU-accelerated inference by attacking the CPU side — [arXiv 2505.06738](https://arxiv.org/pdf/2505.06738) (excerpt).
  - Both are native attacks, not browser attacks.

#### What the WebGPU spec concedes
The W3C Candidate Recommendation Draft of 2026-11-16 says — [W3C WebGPU](https://www.w3.org/TR/webgpu/):
- **Memory:**
  - "WebGPU conceptually initializes all the resources to zero" (§2.1.3).
  - Bounds on buffer access are not guaranteed by the hardware, so robust buffer access or inserted checks are used (§2.1.4).
- **Timing:**
  - Timestamp queries are reduced in precision.
  - "cross-origin isolation (provided by COOP/COEP) does not provide isolation of device/queue-timeline timers" (§2.1.7).
- **Row hammer:** "WebGPU does not have any specific mitigations in place" (§2.1.8).
- **Observing other sites:**
  - Workload identification: "An application can try to indirectly probe how constrained these global resources are" (§2.1.10).
  - VRAM allocation failures can reveal other applications' memory use (§2.1.11).
  - "If one site uses WebGPU at the same time as another, it may observe the increase in time it takes to process some work" (§2.1.12).
- **Fingerprinting:**
  - Limits can be binned (§2.2.1).
  - Compute pipelines expose the GPU "unobstructed by the fixed-function hardware", a fingerprinting vector (§2.2.3).
  - Adapter identifiers "should be as broad as possible"; browsers may report only vendor or architecture, or nothing (§2.2.6).

#### How browsers sandbox WebGPU
- The gpuweb explainer [Undated; living document] — [gpuweb explainer](https://gpuweb.github.io/gpuweb/explainer/):
  - "GPU processes are less sandboxed than content processes, and they are typically shared between multiple origins." The GPU process therefore validates every message, so a compromised renderer cannot read another renderer's GPU memory.
  - Shader and pipeline caches must not leak across origins, and should not be reused in private browsing.
- **Chrome:** the security team's "WebGPU Technical Report" [Undated in excerpt; authors tiszka, bookholt, mattdr] names two new attack surfaces (excerpt) — [Chromium](https://chromium.googlesource.com/chromium/src/+/main/docs/security/research/graphics/webgpu_technical_report.md):
  - "the WebGPU API Implementation which was added to the GPU process & renderer process";
  - "the WGSL shader compiler added to the GPU process".
- **Firefox:** WebGPU is built on wgpu (Rust). Content requests go over IPC to a "GPU sandbox process". It shipped on Windows in Firefox 141 (2025-07-15) — [Mozilla gfx blog](https://mozillagfx.wordpress.com/2025/07/15/shipping-webgpu-on-windows-in-firefox-141/).
- **Shipping status** per web.dev (2025-11-25) — [web.dev](https://web.dev/blog/webgpu-supported-major-browsers):
  - Chrome and Edge 113 on Windows, macOS and ChromeOS; Chrome 121 on Android 12+ with Qualcomm or ARM GPUs. Chromium on Linux is "in progress".
  - Firefox 145 on macOS Tahoe ARM64. Linux, Android and Intel Macs are "in progress".
  - Safari 26 on macOS, iOS, iPadOS and visionOS 26.
- Firefox 147 (January 2026) extended WebGPU to Apple Silicon on all supported macOS versions (excerpt) — [AlternativeTo](https://alternativeto.net/news/2026/1/firefox-147-brings-apple-silicon-webgpu-support-improved-video-playback-and-pip-and-more)

#### Notable WebGPU CVEs, 2025–2026
- **Chrome (Dawn)**, all excerpt:
  - **2025:**
    - CVE-2025-10500, use-after-free, fixed before 140.0.7339.185, CVSS 8.8 — [OSV](https://osv.dev/vulnerability/CVE-2025-10500), [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2397869)
    - CVE-2025-14765, WebGPU use-after-free, fixed in 143.0.7499.147 — [Mondoo](https://mondoo.com/vulnerability-intelligence/vulnerability/CVE-2025-14765)
  - **CVE-2026-5281** — [Help Net Security 2026-04-01](https://helpnetsecurity.com/2026/04/01/google-chrome-zero-day-cve-2026-5281), [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-fixes-fourth-chrome-zero-day-exploited-in-attacks-in-2026/amp/), [The Hacker News](https://thehackernews.com/2026/04/new-chrome-zero-day-cve-2026-5281-under.html?m=0):
    - a Dawn use-after-free that Google said was exploited in the wild, the fourth Chrome zero-day of 2026;
    - fixed in 146.0.7680.177/178;
    - added to CISA KEV on 2026-04-01.
  - **Other 2026 Dawn bugs:**
    - CVE-2026-5286, use-after-free, fixed in 146.0.7680.178, code execution through crafted HTML — [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2453690)
    - CVE-2026-6310, use-after-free, fixed in 147.0.7727.101, sandbox escape once the renderer is compromised — [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2458791)
    - CVE-2026-10909, use-after-free, sandbox escape from a compromised renderer — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-10909)
    - CVE-2026-17758, heap buffer overflow, possible sandbox escape (aggregator source) — [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-17758/)
    - CVE-2026-14417 (July 2026) — [Red Hat](https://access.redhat.com/security/cve/CVE-2026-14417)
    - Further "Use after free in Dawn" entries, with details not read: CVE-2026-4676, 5284, 9874, 11154 and 14424 — [Red Hat 4676](https://bugzilla.redhat.com/show_bug.cgi?id=2450571), [5284](https://bugzilla.redhat.com/show_bug.cgi?id=2453684), [9874](https://bugzilla.redhat.com/show_bug.cgi?id=2482988), [11154](https://bugzilla.redhat.com/show_bug.cgi?id=2485286), [14424](https://bugzilla.redhat.com/show_bug.cgi?id=2496262)
- **Firefox**, all excerpt:
  - CVE-2026-5733, "Incorrect boundary conditions in the Graphics: WebGPU component", affects versions before 149.0.2 — [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2455902).
  - Other 2026 entries surfaced in a WebGPU-specific search; I did not confirm their component on Mozilla's advisories:
    - CVE-2026-12293, use-after-free, fixed in 152 (NVD 9.8, Red Hat 7.5) — [Debian](https://security-tracker.debian.org/tracker/CVE-2026-12293)
    - CVE-2026-16376, denial of service, fixed in 153 — [Rapid7](https://www.rapid7.com/db/vulnerabilities/cve-2026-16376/)
    - CVE-2026-84123, privilege escalation through use-after-free, fixed in 155 and ESR 153.2 — [Rapid7](https://www.rapid7.com/db/vulnerabilities/cve-2026-84123/)
    - CVE-2026-8967, information disclosure, fixed in 151 — [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=2479872)
- **Safari:** no Apple advisory explicitly naming WebGPU was found (see Gaps).

#### Can the embedding page or another tab observe an iframe Worker's GPU work or memory?
- **Same-site frames can share a process:** by default Chromium keys agent clusters by site, so `https://example.com` and `https://subdomain.example.com` "can be placed in the same site-keyed agent cluster" (excerpt) — [Chromium agent_cluster_key.h](https://chromium.googlesource.com/chromium/src/+/HEAD/content/browser/agent_cluster_key.h).
- **Process locking:** a locked renderer "can be limited to documents and workers from a single web site or origin, even if such documents are in iframes". Full site-per-process applies on desktop; Android has partial isolation (excerpt) — [Chromium process model doc](https://chromium.googlesource.com/chromium/src/+show/main/docs/process_model_and_site_isolation.md).
- **Origin-Agent-Cluster** (Chrome 88+) only hints at a separate process. web.dev says origin-keying "is not a security feature" (excerpt) — [web.dev Origin-Agent-Cluster](https://web.dev/articles/origin-agent-cluster).

### Inferences
- **Memory:** no web API path is known by which another page or tab can read a cross-origin Worker's GPU buffers. Zero-initialization, validation and bounds checks hold, and LeftoverLocals did not apply. The residual risks are:
  - a GPU-process or driver exploit, of which Dawn has had many, including one exploited in the wild in 2026; any page in the browser, including Cloudflare-altered ur.io script, could deliver one;
  - bounds-check miscompilation of the SafeRace kind.
- **Work:** another tab or the embedding page can detect GPU contention. That reveals that, and roughly when, inference runs, and possibly its token cadence. This is inferred from spec §2.1.12 and the side-channel papers; no paper found shows token recovery through WebGPU.
- **Process placement:** ur.io and sidecar.ur.io are same-site, so by default Chrome may place the parent page and the sidecar frame and its Worker in the same renderer process. A renderer exploit or a Spectre-style read from ur.io script would then reach the Worker's memory, keys included.
  - Serving the sidecar from a different registrable domain (cross-site) would get process separation from Site Isolation on desktop Chrome. Origin-Agent-Cluster is only a hint.
  - This conclusion is inferred and should be verified by testing.
- **Pixel stealing:** if the sidecar frame ever renders plaintext, GPU.zip-style stealing by the embedding page is a known Chrome/Edge risk class. The sidecar can only refuse embedding by origins other than ur.io, and ur.io itself is the untrusted embedder in this threat model.
- **Fingerprinting:** WebGPU in the sidecar frame exposes adapter info and compute timing to whoever runs code in that frame, but not to the parent. The parent's own WebGPU use can fingerprint the device independently.

### Gaps
- I found no Apple or WebKit document describing how Safari 26 sandboxes WebGPU (GPU process, WGSL to MSL compilation), and no Safari advisory explicitly naming a WebGPU CVE.
- Per-platform details of the GPU-process sandbox in Chrome and Firefox were not obtained. The Chromium technical report is large, and only its summary statements were captured.
- I did not establish whether a cross-origin iframe's dedicated Worker shares a GPU process or device queue with the parent page, beyond the general statement that GPU processes are shared across origins.
- New 2026 GPU-isolation papers surfaced but were not read: PAGE404, "Breaking GPU Isolation Through Hardware-assisted Page Migration" ([arXiv 2610.20962](https://arxiv.org/pdf/2610.20962)), and SparLeak ([arXiv 2609.38830](https://arxiv.org/pdf/2609.38830)), which concerns shared server GPUs.
- The fix status of GPU.zip in Chrome and Edge as of 2026 is unknown.

## Local helpers

### Takeaway
An https page can reach a native process on 127.0.0.1 or localhost in Chromium browsers and Firefox, behind a permission prompt:
- **Chrome 142+** prompts for Local Network Access, with a separate `loopback-network` permission since Chrome 145. Fetch with `targetAddressSpace: 'loopback'`, `ws://` to loopback, and WebTransport are all gated. A cross-origin iframe needs the permission delegated by the top-level page.
- **Edge 143+** behaves the same.
- **Firefox** has a prompt in rollout from Firefox 151, with an enterprise policy since Firefox 145.

Safari still blocks `http://` loopback from https pages as mixed content (WebKit bug 171934 is open). The local server must defend itself: Origin allowlists (Ollama), Host-header checks against DNS rebinding (Ollama CVE-2024-28224, NemoClaw 2026) and real authentication (LM Studio API tokens), because CORS is not authentication.

### Cited Findings

#### Chrome: Local Network Access [Shipped]
- **Timeline:**
  - The blog post (2025-06-09) offered flag-based testing from Chrome 138. Its update of 2025-09-29 says "The Local Network Access permission prompt is launching in Chrome 142" — [Chrome blog](https://developer.chrome.com/blog/local-network-access).
  - Earlier text in the same post: WebSockets, WebTransport and WebRTC were "not yet gated", and Service Workers and Shared Workers needed a prior grant. The mixed-content exemption applies when Chrome knows the destination is local before resolving it: a private IP literal, a `.local` name, or `targetAddressSpace`. — [Chrome blog](https://developer.chrome.com/blog/local-network-access)
- **The permission split:** an Intent to Ship dated 2026-01-08 splits the permission into `local-network` and `loopback-network` for Chrome 145 on desktop and Android. `local-network-access` stays as an alias "for the foreseeable future". LGTMs came from Byers, Taylor and Harrelson, all on 2026-01-08. — [blink-dev](https://groups.google.com/a/chromium.org/g/blink-dev/c/Zl3P6NHhMBw)
- **Current Chrome guide** [Undated] — [Chrome LNA guide](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access):
  - **Address spaces:** loopback is `127.0.0.0/8`, `::1/128` and `localhost`. Checks apply only "when a request crosses from a less private address space into a more private address space", so a localhost-served page calling localhost is not checked.
  - **Permission:** `loopback-network` is required from public or local origins to loopback.
  - **Fetch:** `targetAddressSpace: 'loopback'` (or `'local'`) exempts `http://` targets from Mixed Content once granted. After DNS resolution, Chrome checks the actual IP and aborts with a `TypeError` on mismatch.
  - **WebSocket:** `ws://` from https is exempt from Mixed Content for loopback or private IP literals, `localhost` and `.local`; "gating happens on the permission prompt".
  - **WebTransport:** requires `https://` and takes no `targetAddressSpace`. `ready` waits on the permission.
  - **Workers:** Service Workers and Shared Workers cannot trigger the first prompt.
  - **Iframes:** cross-origin iframes are blocked by default (the allowlist is `'self'`). They need `allow="local-network; loopback-network"` plus a `Permissions-Policy` header on the top-level document.
  - **Secure context:** insecure top-level contexts are auto-denied.
  - **PNA:** Private Network Access preflight headers are deprecated.
- `RequestInit.targetAddressSpace` takes `local`, `loopback` or `public` and "controls how the user agent will handle mixed-content" — [MDN RequestInit](https://developer.mozilla.org/en-US/docs/Web/API/RequestInit)

#### Edge [Shipped]
All excerpt — [Microsoft Learn](https://learn.microsoft.com/en-us/deployedge/ms-edge-local-network-access):
- LNA restrictions became the default in Edge 143. The prompt appears when a site connects to the local network or localhost. Requests to private IPs are noted as working in Edge 144+.
- A secure context is required, and iframes need explicit delegation.
- Policies include `LocalNetworkAccessAllowedForUrls`. A temporary opt-out policy is "removed after Microsoft Edge version 156". Edge 146 adds a policy for cross-origin subframe inheritance.
- Loopback-specific policies exist — [LoopbackNetworkAllowedForUrls](https://learn.microsoft.com/is-is/deployedge/microsoft-edge-policies/loopbacknetworkallowedforurls).

#### Firefox [Shipped as policy; default prompt rolling out]
- The `LocalNetworkAccess` enterprise policy is available since Firefox 145 (ESR 153; Firefox Enterprise 149). Page updated 2026-11-24. — [Firefox admin docs](https://firefox-admin-docs.mozilla.org/reference/policies/localnetworkaccess/)
  - It governs requests to "localhost and local network addresses".
  - Keys: `Enabled`, `BlockTrackers` (experimental), `EnablePrompting`, `SkipDomains` and `Locked`.
  - Prefs: `network.lna.enabled`, `network.lna.block_trackers`, `network.lna.blocking` and `network.lna.skip-domains`.
- **User-facing behavior** (excerpt; the page itself returned a bot challenge) — [Mozilla Support](https://support.mozilla.org/en-US/kb/control-personal-device-local-network-permissions-firefox), [Bugzilla 2011186](https://bugzilla.mozilla.org/show_bug.cgi?id=2011186):
  - The prompt resembles the camera and microphone prompts, with allow or block "for that visit".
  - The restriction is "gradually rolled out to all Firefox users beginning with Firefox 151".
  - The prefs are available from Firefox 147.
- FOSDEM 2026 included the talk "Cleaning Up Local Mess: Firefox's Implementation of Local Network Access" (excerpt) — [FOSDEM](https://fosdem.org/schedule/event/QCSKWL-firefox-local-network-access)

#### Safari [Blocks http loopback from https]
- WebKit bug 171934, "Don't treat loopback addresses … as mixed content", is still NEW, with no fix landed — [WebKit bug 171934](https://bugs.webkit.org/show_bug.cgi?id=171934):
  - Comment 96 (2021-11-11) says `http://127.0.0.1` and `localhost` from https pages are "blocked as mixed content", and that WebKit treats loopback as "Not Trustworthy" contrary to the spec.
  - Apple's position (John Wilander, 2021-07-01) was that the browser should block localhost from http pages before allowing it from https pages.
  - Chrome and Firefox treat `*.localhost` as a secure context (comment 102, 2022-10-11).
- A Safari 18 beta report describes new blocking of localhost from https sites and failed upgrade attempts (excerpt) — [WebKit bug 279249](https://bugs.webkit.org/show_bug.cgi?id=279249).
- Bug 281149 notes Safari's inconsistency (`isSecureContext` is true, yet mixed content does not load). A pull request was linked in March 2026, but I found no confirmation that it shipped (excerpt). — [WebKit bug 281149](https://bugs.webkit.org/show_bug.cgi?id=281149)

#### Prior art: Ollama and LM Studio
- **Ollama** — [Ollama FAQ](https://docs.ollama.com/faq):
  - It binds 127.0.0.1:11434 by default; `OLLAMA_HOST` changes that.
  - "Ollama allows cross-origin requests from `127.0.0.1` and `0.0.0.0` by default. Additional origins can be configured with `OLLAMA_ORIGINS`." Browser extensions must be allowed explicitly (`chrome-extension://*`, `moz-extension://*`, `safari-web-extension://*`).
  - The FAQ describes no authentication for the local API.
  - Sources conflict on the defaults: a third-party guide claims 17 hard-coded default origins, including localhost variants, which is unverified (excerpt) — [simplified.guide](https://www.simplified.guide/ollama/origins-set).
- **Ollama DNS-rebinding history** (excerpt):
  - CVE-2024-28224 (fixed in 0.1.29) gave full API access through DNS rebinding even without network exposure. NCC Group recommends validating the Host header. — [NCC Group](https://www.nccgroup.com/research/technical-advisory-ollama-dns-rebinding-attack-cve-2024-28224/), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-28224)
  - In 2026, NVIDIA's NemoClaw bound Ollama to 0.0.0.0, which "disables Ollama's built-in Host header validation", allowing drive-by model poisoning from a visited page. Reported as CVE-2026-65105 and patched by NVIDIA for non-Windows systems. — [Cyera](https://www.cyera.com/research/nemoclaw-one-website-visit-to-hijack-your-ai-agent), [CSA research note 2026-08-27](https://labs.cloudsecurityalliance.org/research/csa-research-note-nvidia-nemoclaw-model-poisoning-20260827-c/), [The Hacker News, Aug 2026](https://thehackernews.com/2026/08/a-malicious-webpage-could-poison-your.html)
- **LM Studio** (excerpt):
  - CORS is off by default (`lms server start --cors`). The docs warn that "enabling CORS can expose your server to security risks; we recommend enabling authentication" — [LM Studio server start](https://lmstudio.ai/docs/cli/server-start).
  - "By default, the LM Studio API runs without enforcing authentication". API Token authentication can be turned on, with per-token permissions — [LM Studio authentication](https://www.lmstudio.ai/docs/typescript/authentication).
  - "Serve on Local Network" binds to the LAN IP instead of localhost — [LM Studio serve on network](https://lmstudio.ai/docs/developer/core/server/serve-on-network).
- **Brave Leo BYOM** (desktop 1.69+) is a browser-UI feature, not a page API. It calls a local endpoint such as `http://localhost:11434/v1/chat/completions` with an optional API key (excerpt) — [Brave blog](https://brave.com/blog/byom-nightly/), [Brave support](https://support.brave.app/hc/articles/34070140231821)

#### Extension native messaging as a bridge [Shipped in Chrome]
- Native messaging — [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging):
  - **Registration:** a host manifest (`type: stdio`) lists `allowed_origins` as extension IDs, and "`allowed_origins` values can't contain wildcards". Windows registers through the registry; macOS and Linux use fixed manifest paths.
  - **Message format and limits:** JSON with a 32-bit length prefix. "The maximum size of a single message from the native messaging host is 1 MB"; messages to the host can be up to 64 MiB.
  - **Who can call it:** the APIs are "not available inside content scripts". The extension's service worker must validate `sender.origin` before forwarding.
- Web pages reach an extension directly through `externally_connectable` match patterns and `runtime.sendMessage(extensionId, …)`. "It is not possible to send a message from an extension to a web page" through this API. Content-script messages should be treated as attacker-crafted. — [Chrome messaging](https://developer.chrome.com/docs/extensions/develop/concepts/messaging)

### Inferences
- **For the design in Chrome and Edge:** the sidecar frame is cross-origin to ur.io, so the ur.io top-level document must:
  - add `allow="loopback-network"` (and possibly `local-network`) to the iframe;
  - send a `Permissions-Policy` header delegating it.
  - Because ur.io is served through Cloudflare, Cloudflare could withhold the delegation, but that only denies service.
- **Prompts and workers:** the person sees a prompt attributed to the frame. The guide documents no rule for dedicated Workers, so the first request may need to come from the frame's document.
- **Safari's mixed-content block** leaves two Safari options:
  - **https to the daemon:** a certificate the browser trusts for a loopback name, such as a public DNS name pointing to 127.0.0.1 with a real certificate. That puts a private key on every install and is fragile.
  - **No direct link:** fall back to an extension (Safari web extensions with a containing app) or to the person's other devices.
  - WebTransport's `serverCertificateHashes` might avoid the certificate problem in Chromium, but I did not research it.
- **The daemon must not rely on CORS.** At a minimum it needs:
  - an exact Origin allowlist (`https://sidecar.ur.io` only);
  - a strict Host-header check (127.0.0.1/localhost only) against DNS rebinding;
  - a per-session secret or key exchange so other local processes and pages cannot drive it.
  - Better still, the frame and the daemon run an authenticated key exchange, so plaintext crosses the loopback socket only under encryption to a key the daemon proves it holds.
- **Serving the UI from the daemon:** a page served by the daemon itself (`http://localhost:port`) needs no LNA permission, because loopback to loopback is not checked. Its code would then come from the signed local install rather than from the network, which is a stronger code-integrity story than any shipped web mechanism.
- **Native messaging** gives a store-signed extension a bridge to the daemon with message caps (1 MB inbound). The extension could also act as a Code Verify-style checker of the sidecar's served code.

### Gaps
- Firefox's exact current default (whether the prompt is on for all users in Firefox 151 or later, as of November 2026) is unconfirmed, because the support page could not be fetched.
- I did not verify whether Firefox 151+ LNA covers WebSocket and WebTransport, or how it treats loopback from https (Firefox historically allowed `http://localhost` as potentially trustworthy).
- Safari has no LNA-style permission that I found. Nor did I find whether Safari 26 or 27 changed the loopback mixed-content rule; the March 2026 pull request status is unknown.
- How Chrome's LNA treats requests from a dedicated Worker inside a delegated cross-origin iframe is not documented in the sources found.
- The Register (2025-08-19) reported a drive-by issue in Ollama ("Don't want drive-by Ollama attackers snooping on your local chats? Patch now"). I did not read its details — [The Register](https://www.theregister.com/2025/08/19/ollama_driveby_attack/)
- Native messaging details for Firefox and Safari (size limits, how a Safari containing app bridges) were not researched.

## The person's own devices

### Takeaway
Products do this today, but no web-standard protocol does. The clearest prior art:
- LM Studio's **LM Link** (February 2026, preview) carries prompts end to end encrypted between a person's own devices over Tailscale tsnet, including from LM Studio's iPhone and iPad app "Locally" to a desktop.
- Tether's **QVAC** offers peer-to-peer "delegated inference" between devices.
- **WhatsApp Web** before its 2021 multi-device launch is the historical case of a browser client depending on the person's phone.

All of the modern examples use native clients on both ends. A web page cannot join a tailnet or a Holepunch swarm, so a browser client would need a relay and its own end-to-end encryption.

### Cited Findings
- **LM Link** — [Tailscale blog](https://tailscale.com/blog/lm-link-remote-llm-access):
  - Tailscale and LM Studio announced it on 2026-02-25.
  - It is "built on tsnet, a userspace Go program", with an "end-to-end encrypted connection" between authenticated devices, peer to peer.
  - Prompts and responses are "never seen, either by Tailscale or LM Studio's backend service". LM Studio's service handles discovery, keep-alives and configuration.
  - Setup is `lms login` then `lms link enable`.
- The LM Studio FAQ says its hub only handles discovery, and that chats and model listings travel over Tailscale's encrypted connection (excerpt) — [LM Studio LM Link FAQ](https://lmstudio.ai/docs/lmlink/basics/faq). The feature is labeled "in preview" (excerpt) — [lmstudio.ai/link](https://lmstudio.ai/link).
- Further LM Link details (all excerpt):
  - The iPhone and iPad app "Locally" uses LM Link to reach models on a desktop — [LM Studio docs](https://lmstudio.ai/docs/lmlink/lmlink-in-locally).
  - A November 2026 post adds remote agent control over LM Link — [LM Studio blog](https://lmstudio.ai/blog/agent-remote-control).
  - An LM Studio account must be signed in on each device — [9to5Mac](https://9to5mac.com/?p=1054565).
  - Remote models appear to local tools at `localhost:1234`, per a secondary source — [Digital Citizen](https://www.digitalcitizen.life/how-to-use-local-models-remotely-with-lm-link-in-lm-studio/).
- **QVAC (Tether)** is an open-source SDK for local-first, peer-to-peer AI on Linux, macOS, Windows, Android and iOS. It has peer-to-peer model fetching and "blind relays" that "route traffic through relay peers when devices cannot connect directly across NATs and firewalls" — [QVAC README](https://raw.githubusercontent.com/tetherto/qvac/main/README.md).
  - Its delegated-inference docs: a provider joins a topic and publishes its public key; a consumer calls `loadModel({ delegate: … })`; delegation is "peer-to-peer … via Holepunch stack" (excerpt; staging docs host) — [QVAC delegated inference](https://qvacdocs-rk0zz.kinsta.page/sdk/p2p/delegated-inference).
- **WhatsApp:** before multi-device (July 2021), WhatsApp's design used the smartphone as the source of truth. Multi-device gave each companion its own identity key so it works without the phone (excerpt) — [Meta Engineering](https://engineering.fb.com/2021/07/14/security/whatsapp-multi-device/). A commentary piece describes the old web app as using "your phone as a server" (excerpt) — [snarky.ca](https://snarky.ca/why-whatsapp-made-its-web-app-use-your-phone-as-a-server/).
- **Signal Desktop** is a linked device, paired by scanning a QR code from the phone's Linked Devices settings (excerpt) — [Signal blog](https://signal.org/blog/standalone-signal-desktop/)

### Inferences
- **Design pattern from prior art:** pair the devices with an out-of-band QR code or key; let a coordination service see only discovery metadata; keep inference traffic end to end encrypted to the device's key.
- **For a web client:**
  - The Worker would hold a pairing key for the person's phone or daemon.
  - It would run an authenticated key exchange (for example Noise or HPKE in WASM) to that device.
  - It would send prompts through a company relay over WebSocket or WebTransport, or over WebRTC data channels, with the relay seeing only ciphertext and small headers. That fits the design's rule.
  - None of the sources show a browser-to-own-device product built this way; this is inferred.
- **Phones as servers** face limits: OS background execution, battery and thermal throttling, and NAT. LM Link and QVAC address NAT with tailnets and blind relays.

### Gaps
- QVAC's encryption details (whether delegated inference is end to end encrypted with Noise through Holepunch) were not verified from primary docs, and its docs host appears to be a staging site.
- I found no open protocol or standard for "web client to own device" inference, and no product that does it from a plain web page rather than a native app.
- I did not research Apple or Google features that offload inference to the person's own devices, as opposed to the vendor's cloud.

## Privacy of local inference in a browser

### Takeaway
Local inference in a browser is private from servers, but not from the local environment:
- **Extensions** with host permissions can inject scripts into all frames, including a cross-origin sidecar frame, and read its DOM. An extension with the `debugger` permission can attach to workers.
- **Storage:** Chrome keeps IndexedDB (LevelDB) and OPFS as files in the profile with no browser-level encryption at rest.
- **Crash reports** "may include memory contents" at the time of the crash, so uploaded reports can carry prompt or key fragments.

### Cited Findings
- **Content scripts** — [Chrome content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts):
  - They "read details of the web pages the browser visits, make changes to them", and share the DOM while running in an isolated world.
  - `all_frames` injects into all frames that match. `match_origin_as_fallback` covers `about:`, `data:`, `blob:` and `filesystem:` frames.
  - `world: MAIN` runs a script in the page's own world.
  - Host permissions are required, or temporary `activeTab`.
- **`chrome.debugger`:** its targets include "a tab, an iframe or a worker". An extension can attach to "associated workers", using flat sessions since Chrome 125. It needs the `debugger` permission and does not expose every DevTools Protocol domain (excerpt). — [chrome.debugger](https://developer.chrome.com/docs/extensions/reference/api/debugger)
- **Native messaging warning:** content scripts share a renderer process with untrusted pages, so their messages should be validated — [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
- **Storage at rest** (all excerpt):
  - Chrome stores IndexedDB on disk in LevelDB — [Chrome for Developers](https://developer.chrome.com/docs/chromium/indexeddb-storage-improvements).
  - A vendor of an encryption layer, which has an interest in the claim, says IndexedDB is not encrypted at rest and is readable by anyone who can read the profile folder — [RxDB](https://rxdb.info/articles/indexeddb/indexeddb-encryption.html).
  - Chrome's app-bound encryption covers cookies, not IndexedDB or OPFS — [Browsertech Digest](https://buttondown.com/browsertech/archive/browsertech-digest-encrypting-offline-storage-for/).
  - Mozilla has an open bug to support OPFS in Private Browsing, which needs encryption there — [Bugzilla 1975760](https://bugzilla.mozilla.org/show_bug.cgi?id=1975760).
- **Crash reports** (all excerpt):
  - Chrome's help page says crash reports can include memory from the crash, which may hold page contents, payment details and passwords, plus settings, installed extensions and the open page — [Chrome Help 96817](https://support.google.com/chrome/answer/96817).
  - Google's privacy explainer says reports may include site URLs, activity before the crash and "memory contents at the time of the crash" — [Chrome Help 14746339](https://support.google.com/chrome/answer/14746339).
  - Crashpad minidumps include exception state, call stacks, stack memory and loaded modules — [Chromium crash reports](https://chromium.org/developers/crash-reports).
  - The 2018 "Crashing Privacy" study found substantial sensitive data left in a browser's crash-report database after partial anonymization — [arXiv 1808.01718](https://ar5iv.labs.arxiv.org/html/1808.01718).
- **Shader caches:** implementations cache compiled shaders and pipelines, must keep driver caches from leaking across origins, and should not reuse them in private mode — [gpuweb explainer](https://gpuweb.github.io/gpuweb/explainer/).

### Inferences
- **Store only public data in plaintext.**
  - Weights and model libraries in Cache, IndexedDB or OPFS can be plaintext, since they are public.
  - Conversation history, KV caches and embeddings persisted by the page must be encrypted by the app, with keys the Worker holds. The browser offers no encryption at rest, so the OS's full-disk encryption is the only other layer.
- **Extensions:** an extension the person installs with host access to `sidecar.ur.io` can see anything the frame renders and any postMessage traffic. With `debugger` it can see the Worker too. This is outside what the design can prevent; it can only be documented.
- **Crash reports:** a crash in the renderer hosting the Worker, or in the GPU process holding mapped buffers, could upload memory fragments with prompts, outputs or keys if the person opted into crash reporting.
  - Keeping key material in short-lived WASM memory and wiping buffers after use narrows the window.
  - GPU-process minidumps contain stack memory; whether they contain GPU buffer contents is unknown.

### Gaps
- I found no authoritative Chrome, Firefox or Safari document stating the on-disk format and encryption status of OPFS. On iOS, OS data-protection classes may apply to Safari storage, but I did not research that.
- Whether GPU driver crash or TDR dumps (Windows Error Reporting, NVIDIA, AMD or Apple GPU restart logs) can contain GPU memory with weights or activations was not found.
- I did not research whether WebGPU or WebNN telemetry in Chrome's UMA/UKM records anything beyond adapter and performance data.
- I did not verify which extension powers (content scripts, `debugger`, `webRequest`/`declarativeNetRequest` script replacement) are available in Firefox and Safari, or how they differ.
