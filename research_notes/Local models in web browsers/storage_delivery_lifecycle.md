# Shipping 0.5–4 GB model files to a web page: storage, delivery, integrity and lifecycle (state as of 2026-11-25)

Conventions used below. **[Shipped]**, **[Proposal]**, **[Flag]** (behind an experimental or runtime flag) and **[Undated]** (the doc shows no date; accessed 2026-11-25) mark status. "Observed 2026-11-25" means I probed it myself with curl at about 18:19 UTC from a US vantage point (CloudFront POP ORD58), using a generic test `Origin: https://example.com`. "Code at main, read 2026-11-25" means I read the source file on that day. Lines marked "(search summary)" come from search-result summaries of pages I did not open, so give them less weight.

## 1. Where to keep 2–4 GB model files: Cache API vs OPFS (incl. `createSyncAccessHandle`) vs IndexedDB, and reading weights into WebGPU

### Takeaway
All three APIs count against the same per-origin quota and sit in the same default bucket, which is evicted all at once. Chrome's storage team recommends the Cache API for models and calls IndexedDB the worst choice for large blobs. OPFS is the only one of the three that can write at an offset, which is what resumable streamed downloads need, and it has synchronous worker I/O. The two production engines that have shipped caching both store models in the Cache API: LiteRT-LM Web (optionally inside a Storage Bucket) and Transformers.js. WebLLM's TVM runtime offers Cache API, IndexedDB, OPFS and cross-origin backends. I found no controlled benchmark of multi-GB reads into WebGPU.

### Cited Findings
- IndexedDB, the Cache API, OPFS and "other APIs in the File System API family" are all managed by the browser's storage manager and quota, per origin. An evicted origin loses everything at once ("all-or-nothing… IndexedDB, Cache, and so on"). Writes over quota fail with `QuotaExceededError`. MDN, last modified 2026-01-05. — [MDN: Storage quotas and eviction criteria](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- Chrome's AI-model caching guide **[Undated]**:
  - The Chrome storage team recommends the Cache API "for optimal performance". It is usable from the main thread or a regular worker, not only from a service worker, by storing a `Response` built from the blob under a fake URL key.
  - OPFS is the alternative; stream into it with `blob.stream().pipeTo(writable)`.
  - IndexedDB is "the worst place to store large models" because data is serialized on write and deserialized on read.
  - Call `navigator.storage.persist()` after caching, and consider `navigator.storageBuckets.open('models', { durability: 'strict', persisted: true })`.
  - Serve released model files with `Cache-Control: public, max-age=31536000, immutable` and give new versions new URLs.
  - Models cached on the client can be pulled out with DevTools. — [Chrome for Developers: Cache models in the browser](https://developer.chrome.com/docs/ai/cache-models)
- A vendor write-up from Lumafield **[Undated]** found IndexedDB slower than OPFS and the Cache API for large ArrayBuffers, because of serialization and transaction costs. It also says reading a cached file's size is slow through the Cache API (search summary; one vendor's claim). — [Lumafield: 3x faster project loads with OPFS](https://barndoors.lumafield.com/3x-faster-project-loads-with-the-origin-private-file-system/)
- RxDB's published latencies cover only small records (reads of about 0.1 ms for IndexedDB, 1.28 ms for OPFS on the main thread, 1.41 ms in a worker), not large files (search summary). — [RxDB storage comparison](https://rxdb.info/articles/localstorage-indexeddb-cookies-opfs-sqlite-wasm.html)
- **[Shipped]** Safari 26.0 (released 2025-09-15) added the File System WritableStream API (`createWritable()` / `FileSystemWritableFileStream`). Before it, Safari could write to OPFS only through `createSyncAccessHandle()` in a worker (search summary of release notes and the WebKit post). — [Safari 26 release notes](https://developer.apple.com/documentation/safari-release-notes/safari-26-release-notes); [WebKit Features in Safari 26.0](https://webkit.org/?p=17333)
- WebKit bug 320355 (filed 2026-07-27) reports that quota accounting over-charges positioned writes in `FileSystemWritableFileStream`. A pull request exists, but I could not confirm it landed (search summary). — [WebKit bug 320355](https://bugs.webkit.org/show_bug.cgi?id=320355)
- LiteRT-LM Web SDK (`@litert-lm/core`; code at main, read 2026-11-25). npm `latest` is 0.20.0, published 2026-11-23, and the model-cache types were added 2026-10-27/28.
  - `ModelCache` keeps models as Cache API entries. Metadata rides in headers (`X-LiteRTLM-SHA256`, `X-LiteRTLM-Source-URL`, `X-LiteRTLM-HF-Repo/Path/Revision`, `X-LiteRTLM-Stored-At`).
  - Keys that aren't URLs map to `https://litertlm-model-cache.invalid/<key>`.
  - `put()` is atomic: a model "only becomes visible once it has been written completely, and nothing is left behind if the write fails or is aborted."
  - Callers coordinate across tabs and workers with a Web Lock per model. The lock is held shared while reading the `Blob` from `get()`, "since deleting or replacing the entry may make that `Blob` unreadable". It is held exclusively while downloading, "so that other tabs wait for the download instead of repeating it".
  - The environment types include `navigator.storageBuckets` ("which only Chromium supports"), using `bucket.caches`. `persist()` is noted as "Only available in windows, not workers."
  - Helpers are exported for apps that call `cache.put()` themselves "e.g. from a Background Fetch handler". — [model_cache.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/model_cache.ts); [environment.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/environment.ts); [npm @litert-lm/core](https://www.npmjs.com/package/@litert-lm/core)
- LiteRT-LM commit history shows "Read Blob models with random access in the LiteRT-LM Web SDK" (2026-10-26) and "Upload streamed weights per model instead of through global state" (2026-11-13). Weights are streamed from a `Blob` or `ReadableStream` into the engine rather than loaded whole. — [LiteRT-LM js/packages/core commits](https://github.com/google-ai-edge/LiteRT-LM/commits/main/js/packages/core)
- Transformers.js (code at main, `VERSION = '4.3.2'`) checks caches in this order: `env.customCache`, then experimental Cross-Origin Storage, then the Cache API (`caches.open(env.cacheKey)`; `useBrowserCache` "is `true` if available"), then a Node file cache. — [transformers.js cache.js](https://github.com/huggingface/transformers.js/blob/main/packages/transformers/src/utils/cache.js); [env.js](https://github.com/huggingface/transformers.js/blob/main/packages/transformers/src/env.js)
- Apache TVM's web runtime, used by WebLLM (code at main), defines `ArtifactCacheType = "cache" | "indexeddb" | "cross-origin" | "opfs"`. `ArtifactOPFSCache` takes an OPFS access mode that defaults to `"async"`. — [tvm web/src/artifact_cache.ts](https://github.com/apache/tvm/blob/main/web/src/artifact_cache.ts)

### Inferences
- Resuming a 2–4 GB download needs offset writes. OPFS provides them: `createWritable({keepExistingData:true})` with `seek`/`write({position})`, or `SyncAccessHandle.write(buf, {at})` in a worker. A Cache API `put()` consumes one whole `Response`, so a dropped connection stores nothing, as LiteRT-LM's atomic `put()` shows. A Cache-API design therefore needs a staging area (an OPFS temp file, or chunked entries) to resume. Either way is fine for reads.
- Read path into WebGPU:
  - Both `cache.match()` → `response.blob()` and OPFS `getFile()` give disk-backed Blobs that can be `slice()`d and streamed without loading the whole file. LiteRT-LM's Blob random-access path depends on this.
  - In a dedicated worker, `SyncAccessHandle.read(view, {at})` gives synchronous positioned reads into one reusable buffer for `GPUQueue.writeBuffer`.
  - Every path copies through JS/wasm memory in chunks. GPU upload and engine parsing probably cost more than the choice of storage API, but this is not benchmarked.
- If the deployment puts its keychain and state (IndexedDB) and a 2–4 GB model in the same default bucket, evicting one evicts both, because eviction is all-or-nothing per origin. Only Storage Buckets avoid this, and they are Chromium-only (section 5). Separating models from keys therefore has to be designed per engine.

### Gaps
- No controlled benchmark of multi-GB read throughput from Cache API vs OPFS vs IndexedDB into WebGPU, per browser.
- Per-entry size limits for Cache API responses or IndexedDB Blobs of 2–4 GB in each engine: not found.
- I did not re-verify in this pass which Chrome and Firefox versions first shipped `createWritable()` and `createSyncAccessHandle()`.

## 2. Per-browser quotas for a top-level origin and for a same-site iframe (Chrome, Edge, Firefox, Safari 17+/26 on macOS and iOS)

### Takeaway
- **Chrome and Edge:** up to 60% of total disk per origin.
- **Firefox:** best-effort storage is capped at the smaller of 10% of disk or 10 GiB, shared by every origin of the same site; persistent storage goes up to 50% of disk, capped at 8 TiB.
- **Safari 17+:** about 60% of disk per origin in browser apps (15% in other apps that embed WebKit); cross-origin frames get a separate partition at 10% of the main frame's origin quota.

For a same-site iframe such as `sidecar.ur.io` under `ur.io`:
- **Chrome:** keeps the full per-origin quota, under the same storage key as a top-level visit.
- **Firefox:** shares ur.io's group limit.
- **Safari:** WebKit's wording ("cross-origin frames") suggests the 10% frame quota applies even when the frame is same-site. This is unverified and needs device testing.

### Cited Findings
- Chrome and Chromium-based browsers (Chrome, Edge) allow up to 60% of total disk per origin in both best-effort and persistent modes, and cap all origins together at 80% of disk. MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- Firefox's best-effort limit is the smaller of 10% of the profile's disk or 10 GiB. This "group limit" is shared by all origins of the same site. Persistent storage goes up to 50% of total disk, capped at 8 TiB, and is not subject to the group limit. Example: on a 500 GiB drive, 10 GiB best-effort and 250 GiB persistent. MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- Safari / WebKit (macOS 14+ / iOS 17+). MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
  - Browser apps get about 60% of total disk per origin.
  - Other apps that embed web content, such as `WKWebView`, get about 15% per origin.
  - Home Screen and Dock web apps use the browser-app quota.
  - Cross-origin iframes get a separate quota of roughly 1/10 of their parent's.
  - Overall caps are 80% of disk for browser apps and 20% for other apps.
  - Before Safari 17 the initial quota was 1 GiB per origin, and the user was asked beyond that.
- In the EU, iOS 17.4+ allows other browser engines, which then use their own policies. Firefox and Chromium base quotas on total disk, not free space, so an origin may be unable to reach its quota. Limits may vary to resist fingerprinting. MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- WebKit's own statement (2023-08-10, Safari 17 / iOS 17 / macOS Sonoma). — [WebKit: Updates to Storage Policy](https://webkit.org/blog/14403/updates-to-storage-policy/)
  - "For a browser app, the origin quota is up to 60% of the total disk space"; other apps get 15%; overall quotas are 80% and 20%.
  - Cross-origin frames "use a separate storage partition" with quota "currently 10% of the main frame's origin quota."
  - Home Screen web apps have the same quotas as the browser.
  - `estimate()` reports the origin quota, which "may change based on factors like existing usage and site visit frequency".
- Chrome manages each storage partition as a separate quota bucket, and `navigator.storage.estimate()` reports partition-specific figures. Privacy Sandbox page, last updated 2025-06-13. — [Storage partitioning](https://privacysandbox.google.com/3pcd/storage-partitioning)

### Inferences
- `sidecar.ur.io` framed by `ur.io`:
  - **Chrome and Edge.** The storage key is (origin `https://sidecar.ur.io`, top-level site `https://ur.io`), the same key as a top-level visit to sidecar.ur.io, whose site is also ur.io. So framed and direct visits share one quota of about 60% of disk, separate from `ur.io`'s own origin quota.
  - **Firefox.** sidecar.ur.io, ur.io and every other *.ur.io origin share one best-effort group limit of 10 GiB or 10% of disk, whichever is smaller. A single 4 GB model fits, but two model variants plus other ur.io data approach the cap unless the user grants persistence.
  - **Safari.** If the "cross-origin frame" rule applies by origin, the frame gets 10% × 60% = about 6% of disk. That is about 3.8 GB on a 64 GB iPhone, 7.7 GB on 128 GB and 15 GB on 256 GB, before other usage and fingerprinting variance. A 4 GB model may not fit on small devices. A top-level sidecar.ur.io page (e.g., a Home Screen app) would get the full origin quota.
- For Safari 18 and 26, I assume the 2023 policy still holds because I found no newer WebKit storage-policy post.

### Gaps
- I did not verify in WebKit source whether a same-site but cross-origin frame counts as a "cross-origin frame" for the 10% quota, or which partition key WebKit uses (top-level origin vs top-level site).
- No WebKit storage-policy update after 2023-08-10 was found.
- Edge-specific deviations from Chromium quotas were not checked.

## 3. How each browser decides `navigator.storage.persist()`

### Takeaway
Chrome and Edge decide silently. Chromium's code grants persistence only to the top-level origin, so `persist()` called from a cross-origin iframe, same-site included, always resolves `false` in Chrome. At top level, Chrome grants it when the registrable domain is an installed web app or is among the profile's 10 most "important" registrable domains. Firefox asks the user with a prompt. Safari uses heuristics, the documented one being whether the site is opened as a Home Screen web app. `persist()` is exposed only in Window contexts.

### Cited Findings
- Firefox shows a permission popup. Safari and Chromium (Chrome, Edge) "automatically grant or deny the request based on the user's interaction history with the site", with no prompt. MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- Chrome's heuristics are "level of site engagement", "whether the site has been installed or bookmarked" and "whether the site has notification permission". A denied site can ask again and is re-evaluated **[Undated]**. — [web.dev: Persistent storage](https://web.dev/articles/persistent-storage)
- Chromium source (code at main, read 2026-11-25), `PersistentStoragePermissionContext`. — [persistent_storage_permission_context.cc](https://github.com/chromium/chromium/blob/main/chrome/browser/storage/persistent_storage_permission_context.cc)
  - "Durable is only allowed to be granted to the top-level origin. Embedding origin is the last committed navigation origin to the web contents." If `requesting_origin != embedding_origin`, the request is answered not-granted, with no prompt.
  - It also refuses when cookies for the origin are session-only or full cookie access isn't allowed.
  - It grants when the requesting origin's registrable domain (private registries included) is among installed web-app domains.
  - It grants when the domain is among the top 10 "important" registrable domains from `ImportantSitesUtil::GetImportantRegisterableDomains`.
  - Otherwise it does not grant.
- WebKit "currently grants a request based on heuristics like whether the website is opened as a Home Screen Web App". An origin in persistent mode "might be excluded from eviction"; this is not a guarantee. Safari 17, 2023-08-10. — [WebKit: Updates to Storage Policy](https://webkit.org/blog/14403/updates-to-storage-policy/)
- `persist()` is Window-only. The Chromium `StorageBucket` IDL marks `persist()` `[Exposed=Window]` (code at main), and LiteRT-LM's model cache notes `persist()` is "Only available in windows, not workers." — [storage_bucket.idl](https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/modules/buckets/storage_bucket.idl); [LiteRT-LM environment.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/environment.ts)

### Inferences
- In Chrome and Edge, the deployment's `navigator.storage.persist()` from the framed page will always return `false`, so the keychain, state and any model there are best-effort and evictable under storage pressure. Two things are likely but need testing:
  - Because Chrome keys the iframe's storage like a top-level sidecar.ur.io visit, a persistence grant obtained in a top-level sidecar.ur.io context (direct navigation or an installed PWA) would cover the iframe's data too.
  - Because grants are evaluated by registrable domain, ur.io's engagement or install status counts toward sidecar.ur.io.
- Firefox's prompt and Safari's Home Screen heuristic are both outside the page's control. No browser offers a guaranteed programmatic path to persistence.

### Gaps
- Firefox's handling of `persist()` from a cross-origin iframe (whether it prompts, and which origin it names): not found.
- Safari's handling of `persist()` from an iframe: not found.
- Whether Edge adds its own heuristics: not checked.
- Whether `storageBuckets.open(name, {persisted: true})` follows the same top-level-only rule: likely, since it is the same permission, but unverified.

## 4. Eviction rules: LRU under storage pressure, Safari's seven-day cap (OPFS? Cache API?), Home Screen exemption

### Takeaway
Under storage pressure, or when the browser-wide cap is exceeded, browsers evict whole best-effort origins, least recently used first. Persistent origins are skipped (Safari says "might be excluded"). Safari also has a proactive ITP rule: after seven days of Safari use with no user interaction on a site, it deletes all of the site's script-writable storage. WebKit lists IndexedDB, LocalStorage, SessionStorage, media keys and service worker registrations and cache, which covers the Cache API. Its 2023 storage policy names the Cache API and "File System", but no WebKit text names OPFS in the seven-day rule. The first-party domain of a Home Screen web app is exempt.

### Cited Findings
- Storage-pressure eviction deletes the least recently used origin's data first, then the next, "until the problem is resolved", and applies only to non-persistent origins. When combined usage exceeds the browser maximum (e.g., Chrome's 80% of disk), best-effort origins are evicted by the same LRU rule. Deletion is all-or-nothing per origin. MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- Safari-only proactive eviction: with cross-site tracking prevention on, an origin with no user interaction (click or tap) in the last seven days of browser use has its script-created data deleted; server-set cookies are exempt. MDN, 2026-01-05. — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- WebKit's original post (2020-03-24) deletes "all of a website's script-writable storage after seven days of Safari use without user interaction on the site". It lists IndexedDB, LocalStorage, Media keys, SessionStorage and "Service Worker registrations and cache". Home Screen web apps "are not part of Safari" and have their own days-of-use counter; the first party there is not expected to lose data, and such deletion would be a serious bug. — [WebKit: Full Third-Party Cookie Blocking and More](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/)
- "The first-party domain of home screen web applications is exempt from ITP's 7-day cap on all script-writeable storage" **[Undated]**. — [WebKit Tracking Prevention](https://webkit.org/tracking-prevention/)
- Safari 17's storage policy (2023-08-10) puts localStorage, Cache API, IndexedDB, Service Worker and File System in scope. Eviction triggers are exceeding the overall quota, system storage pressure, and a site unused "for some time" (ITP). Origins are deleted LRU, and an origin "might be excluded from eviction if it has active page at the time of eviction, or its storage is in persistent mode." — [WebKit: Updates to Storage Policy](https://webkit.org/blog/14403/updates-to-storage-policy/)
- A WebKit Bugzilla discussion says the only things capped at 7 days for a Home Screen app's main domain are JavaScript-created cookies and cookies set in third-party CNAME-cloaked responses (search summary). — [WebKit bug 237350](https://bugs.webkit.org/show_bug.cgi?id=237350)

### Inferences
- Cache API data falls under the seven-day rule: it is "Service Worker… cache" in 2020 and named in 2023. OPFS probably falls under it too, since "File System" is in scope in 2023, but no WebKit text says so. Test it.
- For a deployment framed by ur.io in Safari, a user who doesn't interact with the site for seven days of Safari use could lose the keychain, token and model together. How ITP counts interaction for a same-site iframe (does interaction on the ur.io top-level page count?) is undocumented. A Home Screen web app avoids the rule for its first-party domain, but in an ur.io Home Screen app the sidecar frame is still a cross-origin frame (section 2).

### Gaps
- No WebKit statement on whether a granted `persist()` exempts an origin from the seven-day deletion.
- No explicit WebKit statement that OPFS is included.
- No documentation of how the seven-day interaction rule applies to a same-site (cross-origin) iframe.

## 5. Storage Buckets API: status, support, and keeping an evictable model cache apart from critical keys

### Takeaway
Storage Buckets are **[Shipped]** only in Chromium: Chrome and Edge 122 on desktop and Android. Mozilla's position is "Positive" but Firefox hasn't implemented them; WebKit has given "No signal". Current Chromium exposes per-bucket `indexedDB`, `caches` and `getDirectory()` (OPFS), plus `persist()`, `persisted()`, `estimate()` and `setExpires()`/`expires()`. `durability()` and per-bucket `locks` are still **[Flag]**. Chrome may evict each bucket independently, so a non-persisted "models" bucket can be dropped while the default bucket survives. This works only in Chromium, and in an iframe the default bucket remains best-effort because `persist()` is refused (section 3).

### Cited Findings
- ChromeStatus feature 5739224579964928, "Storage Buckets API" (accessed 2026-11-25). — [ChromeStatus: Storage Buckets](https://chromestatus.com/feature/5739224579964928)
  - Status: "Enabled by default", desktop 122 and Android 122; origin trial ran Chrome 115–118.
  - Firefox: "Positive" (Mozilla standards-positions). Safari: "No signal" ([WebKit standards-positions #181](https://github.com/WebKit/standards-positions/issues/181)).
  - Summary: "allowing user agents to evict the grouped data independently of that which is in other buckets… IndexedDB and CacheStorage."
- Chrome's article **[Undated]** says the feature is "available as of Chromium 122". The browser "may choose to delete each bucket independently of other buckets". Options are `persisted` (default false) and `durability` ('relaxed' default, or 'strict'). It also says "the current implementation is only the IndexedDB API", which is older text that today's IDL contradicts (next item). — [Chrome: Storage Buckets](https://developer.chrome.com/docs/web-platform/storage-buckets)
- Chromium `StorageBucket` IDL (code at main, read 2026-11-25). — [storage_bucket.idl](https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/modules/buckets/storage_bucket.idl); [runtime_enabled_features.json5](https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/platform/runtime_enabled_features.json5)
  - The interface is exposed to Window and Worker, under the "StorageBuckets" flag, whose status is "stable".
  - Members: `persist()` [Window], `persisted()`, `estimate()`, `setExpires()`, `expires()`, `indexedDB`, `caches` (CacheStorage) and `getDirectory()` (FileSystemDirectoryHandle).
  - `durability()` sits behind `StorageBucketsDurability` (status "experimental"), and `locks` behind `StorageBucketsLocks` ("experimental").
- The WICG spec IDL includes `caches` and `getDirectory()`, which "matches StorageManager.getDirectory()" (search summary). — [WICG Storage Buckets](https://wicg.github.io/storage-buckets); [explainer](https://wicg.github.io/storage-buckets/explainer)
- Chrome partitions the Storage Buckets API along with other storage. Page updated 2025-06-13. — [Storage partitioning](https://privacysandbox.google.com/3pcd/storage-partitioning)
- LiteRT-LM's Web model cache can put its Cache API entries in a Storage Bucket (`StorageBucketLike.caches`), "which only Chromium supports" (code at main). — [LiteRT-LM environment.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/environment.ts)
- MDN's "Storage buckets" guide URL returned 404 on 2026-11-25. — [MDN (404)](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_buckets)

### Inferences
- In Chromium the pattern works. Open `navigator.storageBuckets.open('models', {persisted:false})` and keep weights in `bucket.caches` or `bucket.getDirectory()`; keep keys and state in the default bucket's IndexedDB. Under pressure Chrome can drop the models bucket alone, so the app must handle a cache miss and re-download.
- In Firefox and Safari everything lives in the default bucket, so evicting the model wipes the keys. An app that needs key survival there should keep the model in a different origin's storage (e.g., another subdomain, which in Firefox still shares the eTLD+1 group limit), or accept the coupling.
- The "durability: 'strict'" option that Chrome's model-caching guide shows corresponds to a getter that is still behind an experimental flag. Don't depend on it.

### Gaps
- Chromium's eviction order across buckets (whether its quota manager picks LRU by bucket, and whether the default bucket is preferred or protected) is not documented in what I found.
- The Chrome milestone in which `caches` and `getDirectory()` on buckets shipped was not found.
- Whether a bucket opened with `persisted:true` in a cross-origin iframe is refused, like `persist()`, was not verified.

## 6. Storage partitioning: same-site vs cross-site iframes in Chrome, Firefox and Safari, and effects on quota

### Takeaway
Chrome (115+) and Firefox (103+) key third-party storage by the top-level site, so a same-site iframe is not split from its first-party storage. Chrome also gives each partition its own quota. Safari partitions third-party (cross-site) storage per first-party website and makes it ephemeral. Separately, WebKit describes cross-origin frames as having their own partition at 10% quota, which may catch same-site frames (section 2).

### Cited Findings
- Chrome's partition key is the top-level site plus the frame's origin, with an "ancestor bit" set when a cross-site document sits in between; same-site chains are not split further. Enabled for all users in Chrome 115+. Page updated 2025-06-13. — [Storage partitioning](https://privacysandbox.google.com/3pcd/storage-partitioning)
  - Partitioned: IndexedDB, Cache storage, Web Storage, OPFS, the Storage Buckets API, Clear-Site-Data (scoped to one partition) and the Blob URL store (Chrome 137+).
  - Also partitioned: Broadcast Channel, SharedWorker, Web Locks, and service workers registered from third-party contexts.
  - Each partition is a separate quota bucket.
- Firefox double-keys client-side state by the resource's origin and the top-level site ("scheme and registrable domain of the top-level page"). State Partitioning has been on by default since Firefox 103; network partitioning since Firefox 85. MDN, last modified 2026-06-15. — [MDN: State Partitioning](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/State_Partitioning)
  - Statically partitioned: localStorage, sessionStorage, DOM Cache, IndexedDB, Broadcast Channel, Shared Workers and Service Workers.
  - Network state, including the HTTP cache, is partitioned permanently.
  - OPFS and Web Locks are not mentioned.
- "Third-party LocalStorage and IndexedDB are partitioned per first-party website and also made ephemeral"; third-party service workers and their cache and IndexedDB are partitioned; third-party HTTP cache entries are partitioned per first-party website **[Undated]**. — [WebKit Tracking Prevention](https://webkit.org/tracking-prevention/)
- Cross-origin frames use "a separate storage partition" with 10% of the main frame's origin quota. WebKit, 2023-08-10. — [WebKit: Updates to Storage Policy](https://webkit.org/blog/14403/updates-to-storage-policy/)

### Inferences
- **Chrome and Firefox, same-site iframe:** storage, Web Locks and BroadcastChannel are shared with top-level sidecar.ur.io tabs. In Chrome they share the same key (https://sidecar.ur.io, https://ur.io), so cross-tab download locks (LiteRT-LM style) coordinate between framed and direct instances. Cross-site embedding (top-level not *.ur.io) would get a separate partition with its own quota and lose that sharing.
- **Safari:** treat the frame as partitioned and quota-reduced until tested.
- **HTTP cache:** browsers partition it by top-level site, so it never shares model bytes across sites. Within ur.io's site, ur.io and sidecar.ur.io pages would share one HTTP-cache partition.

### Gaps
- WebKit's partition key for a same-site, cross-origin frame (top-level origin or site): not confirmed in source.
- Firefox's handling of OPFS and Web Locks under partitioning: not documented on the page.

## 7. Sharing model downloads across origins by hash: Cross-Origin Storage (COS) and similar

### Takeaway
COS is a **[Proposal]**: a WICG explainer and spec plus a Chrome extension polyfill. Its ChromeStatus entry (created 2026-05-11, updated 2026-11-25) is at "Proposed", with an intent-to-prototype thread but no milestone and no origin trial. Firefox's position is "Under consideration"; Safari has given no signal. Files are keyed by SHA-256, the same value as Hugging Face's LFS oid and the native apps' pinned hashes. Transformers.js, WebLLM (via TVM) and wllama already integrate the extension API. No shipping browser offers hash-keyed cross-site sharing, and HTTP caches are partitioned.

### Cited Findings
- The WICG README documents `navigator.crossOriginStorage.getFileHandle(hash, options)`, with `{create: true}` to store and no option to read. **[Proposal]** — [WICG cross-origin-storage README](https://github.com/WICG/cross-origin-storage); [spec](https://wicg.github.io/cross-origin-storage)
  - SHA-256 is the default; any WebCrypto hash except SHA-1 is allowed.
  - Grants are keyed to the top-level site. By default only the storing origin and its same-site origins can read an entry.
  - An explicit `origins` list requires a `Cross-Origin-Storage-Allow-Origin` header from the server that supplies the bytes.
  - Global sharing (`'*'`) works only for hashes on a Public Hash List, and the browser may sometimes answer as if the file is absent (GREASE).
  - Cross-site lookups have a small budget (about 8–16 per time window). Permissions Policy can disable COS. Service workers cannot use it.
  - "this API is not yet natively implemented in browsers"; testing goes through a Chrome Web Store extension and a Vite plugin.
  - Authors: Thomas Steiner (Google Chrome), Christian Liebel (Thinktecture), François Beaufort (Google Chrome).
- ChromeStatus "Cross-Origin Storage" (feature 5163371507875840, created 2026-05-11, updated 2026-11-25). — [ChromeStatus: Cross-Origin Storage](https://chromestatus.com/feature/5163371507875840); [Mozilla standards-positions #1427](https://github.com/mozilla/standards-positions/issues/1427); [WebKit standards-positions #703](https://github.com/WebKit/standards-positions/issues/703)
  - Status "Proposed"; no desktop, Android or iOS milestones; no origin trial or flag.
  - Summary: "a content-addressable browser cache that shares files across origins by hash, with k-anonymity-based availability gating". The motivation notes that "Traditional HTTP caching cannot solve this because browsers partition cach[e]".
  - Firefox: "Under consideration". Safari: "No signal".
  - Developer support it cites:
    - Transformers.js PR #1549, TVM PR #18893 (WebLLM) and wllama PR #248 integrate the extension API.
    - "The LiteRT-LM JS team at Google is working on adding support."
    - WebLLM filed Mozilla bug 2071521 and WebKit bug 324017.
    - Flutter, Emscripten, SQLite Wasm, Nuxt and Prebid.js are also listed.
- Engine code (at main, read 2026-11-25):
  - Transformers.js gates COS behind `env.experimental_useCrossOriginStorage` and calls `navigator.crossOriginStorage.requestFileHandle(...)`, an older method name than the README's `getFileHandle`. It resolves SHA-256 "cheaply" from the Git LFS pointer file and keeps a url→hash map in a Cache API cache named `experimental_transformers-hash-cache`.
  - TVM's `ArtifactCrossOriginStorageCache` calls `getFileHandle(hash, {create:true, origins:'*'})`. When the hash is unknown it computes SHA-256 with `blob.arrayBuffer()` + `crypto.subtle.digest`, i.e., the whole file in memory. The extension has no delete API. — [transformers.js CrossOriginStorageCache.js](https://github.com/huggingface/transformers.js/blob/main/packages/transformers/src/utils/cache/CrossOriginStorageCache.js); [tvm artifact_cache.ts](https://github.com/apache/tvm/blob/main/web/src/artifact_cache.ts)

### Inferences
- Nothing to rely on in 2026. If COS ships, the native apps' pinned SHA-256 could serve directly as the COS key. Its default "storing origin plus same-site origins" scope would let ur.io and sidecar.ur.io share one copy without the cross-site budget. Sharing with other sites would need the Public Hash List or `Cross-Origin-Storage-Allow-Origin` from the byte host.
- COS isn't available to service workers, so a Background-Fetch-in-SW design couldn't write into COS directly.

### Gaps
- No Chrome milestone or origin-trial date.
- The API surface is still moving (`requestFileHandle` vs `getFileHandle`; see the TVM fallback comment).
- No other hash-keyed cross-site sharing mechanism was found in any engine.

## 8. Downloading: streaming multi-GB files into OPFS, resuming with HTTP Range, progress, Background Fetch, and service workers

### Takeaway
The cross-browser path is a fetch in a dedicated worker:
- stream `response.body` into an OPFS file (via `createWritable()` in Chrome, Firefox and Safari 26+, or a `SyncAccessHandle` in a worker);
- record the byte offset that has been written durably;
- resume with `Range: bytes=<offset>-`;
- report progress from `Content-Range`, `X-Linked-Size` or `Content-Length`.

Hugging Face's CDN leg answers Range requests with 206 and permissive CORS. Its signed URLs expire after one hour. Background Fetch is Chromium-only (Chrome 74+, desktop and Android). It cannot send preflighted requests, and it restarts a resource from zero when a connection can't resume, so it isn't a resumable-range tool. A service worker can host Background Fetch handlers and serve cached models, but it has bounded event lifetimes and cannot use COS.

### Cited Findings
- Observed 2026-11-25: `GET https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/resolve/main/gemma-4-E2B-it-web.litertlm` with `Range: bytes=0-15` returned **302**. Following it to `https://us.aws.cdn.hf.co/xet-bridge-us/…` returned **206**. — [probe target](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
  - The 206 carried `content-range: bytes 0-15/2008432640`, `accept-ranges: bytes`, `access-control-allow-origin: *`, `access-control-expose-headers: *` and `etag: "769c6039…"` (the Xet hash, not SHA-256).
  - The body began `LITERTLM`.
  - A CORS preflight to the CDN asking for `range` got `access-control-allow-headers: *` and `access-control-allow-methods: *`, with no max-age.
  - A preflight to the huggingface.co resolve URL got `access-control-allow-headers: range` and `access-control-max-age: 86400`.
- Observed 2026-11-25: the signed CDN URL's `Expires` parameter was exactly 3600 s after the request (1795634378 vs a local epoch of 1795630778), and the 302 carried `cache-control: no-store`. — [probe target](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Chrome's model-caching guide **[Undated]** recommends `fetch-in-chunks` for parallel ranged downloads stitched together on the client: `maxParallelRequests` (default 6), `chunkSize` (default file size ÷ parallel requests), `progressCallback(downloaded, total)` and an `AbortSignal`. It shows OPFS writes via `blob.stream().pipeTo(writable)`. — [Chrome: Cache models in the browser](https://developer.chrome.com/docs/ai/cache-models)
- **[Shipped]** Background Fetch is enabled by default in Chrome 74 on desktop and Android. Firefox and Safari: "No signal". ChromeStatus 5712608971718656, entry updated 2025-08-22. — [ChromeStatus: Background Fetch](https://chromestatus.com/feature/5712608971718656)
- Chrome's Background Fetch article **[Undated]**. — [Chrome: Background Fetch](https://developer.chrome.com/blog/background-fetch)
  - Call `registration.backgroundFetch.fetch(id, requests, {title, icons, downloadTotal})`. The browser shows a progress notification, and the fetch aborts if downloads exceed `downloadTotal`.
  - Events: `backgroundfetchsuccess`, `backgroundfetchfail`, `backgroundfetchabort` and `backgroundfetchclick`.
  - Responses are accessible only during those events in Chrome's implementation, so they must be copied, e.g., into the Cache API.
  - Closing the site's pages doesn't stop the fetch; on Android the OS may take over.
  - "Chrome doesn't currently support requests that need a CORS preflight." If a connection drops and can't resume, the resource restarts from scratch.
  - Quota is enforced (`failureReason: "quota-exceeded"`). Service workers can't stay open indefinitely in the handlers. The spec is a WICG draft.
- **[Proposal]** ChromeStatus lists "CORS enforcement for Background Fetch" (Proposed, milestone 157) and "Local Network Access restrictions for Background Fetch" (Proposed, 154); accessed 2026-11-25. — [ChromeStatus 6210300985606144](https://chromestatus.com/feature/6210300985606144); [ChromeStatus 6225598451154944](https://chromestatus.com/feature/6225598451154944)
- LiteRT-LM exports `createCacheEntryHeaders()` and `getCacheRequestUrlForSource()` so an app can `cache.put()` a model "from a Background Fetch handler". Its model-cache directory is built to be importable "on its own, e.g. from a service worker" (code at main). — [model_cache.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/model_cache.ts); [model-cache index.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/index.ts)
- **[Shipped]** Safari 26.0 (2025-09-15) supports `FileSystemWritableFileStream` (search summary). — [Safari 26 release notes](https://developer.apple.com/documentation/safari-release-notes/safari-26-release-notes)
- COS "service workers cannot use it". — [WICG cross-origin-storage](https://github.com/WICG/cross-origin-storage)

### Inferences
- **Resumable recipe:**
  1. A dedicated worker fetches the resolve URL.
  2. It reads `response.url`, the final signed CDN URL; Fetch exposes the post-redirect URL.
  3. It issues Range requests straight to the CDN for up to an hour.
  4. It pipes each body into an OPFS file at the matching position.
  5. It persists a small progress record (offset, ETag, commit) to IndexedDB at intervals.
  6. After an hour, or on a 403 from an expired signature, it re-resolves through huggingface.co.
  7. It sends `If-Range` with the CDN ETag (the Xet hash) so a changed file isn't spliced.
  8. It pins downloads to a commit (`/resolve/<commit>/`) rather than `main`.
- Progress total comes from `Content-Range`'s total. The CDN exposes all headers, and the 302's `X-Linked-Size` is readable only when fetched with `redirect:'manual'`, which yields an opaque redirect. In practice, use the pinned size or the `Content-Range` total.
- Background Fetch fits a "download while the tab is closed" UX in Chrome and Edge only. It can't do preflighted Range requests, and it restarts a dropped file from zero. Store-after-success into the Cache API (LiteRT-LM's path) is the supported pattern, and it has to be paired with a Firefox/Safari fallback.

### Gaps
- No primary-source numbers for Chrome, Firefox or Safari service-worker idle and event-time limits in page (non-extension) contexts.
- No measurements of OPFS streaming-write throughput at multi-GB size per browser.
- Whether Background Fetch continues on desktop Chrome after the whole browser closes is undocumented.
- Whether Fetch's `Range` header triggers a preflight in every engine was not checked; HF answers preflights either way.

## 9. Hugging Face hosting (CORS, redirects and hostnames for `connect-src`, rate limits, terms) and self-hosting alternatives

### Takeaway
A browser download of a LiteRT-LM file (observed 2026-11-25) touches `https://huggingface.co` (API and `/resolve/`, CORS echoing the Origin) and then a signed, one-hour URL on `https://us.aws.cdn.hf.co` (CORS `*`, Range supported). The 302 exposes `X-Linked-ETag`, which equals the file's SHA-256. Anonymous rate limits are per IP per 5-minute window: 3,000 resolver requests and 500 API calls. HF publishes no official CDN hostname allowlist, and the hosts have changed over time (cdn-lfs → cas-bridge.xethub → *.cdn.hf.co). I found no HF terms that address apps serving many end users. Gemma 4 E2B/E4B LiteRT-LM repos are ungated and Apache-2.0; the Gemma 3 repos are gated.

### Cited Findings
- 302 response headers (observed 2026-11-25). — [probe target](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
  - `location: https://us.aws.cdn.hf.co/xet-bridge-us/<id>/<xethash>?…Expires=…&Policy=…&Signature=…&Key-Pair-Id=…`
  - `access-control-allow-origin: <echoed origin>`, `vary: Origin, Accept`, `access-control-max-age: 86400`
  - `access-control-expose-headers: X-Repo-Commit, X-HF-Warning, X-Request-Id, X-Error-Code, X-Error-Message, X-Total-Count, ETag, Link, Accept-Ranges, Content-Range, X-Linked-Size, X-Linked-ETag, X-Xet-Hash, RateLimit, RateLimit-Policy`
  - `x-linked-size: 2008432640`, `x-linked-etag: "3a08e8d9…35b5"` (equal to the LFS SHA-256 in the tree API), `x-xet-hash`, `x-repo-commit`
  - `ratelimit: "resolvers";r=2999;t=199` and `ratelimit-policy: "fixed window";"resolvers";q=3000;w=300`
  - `x-hf-warning: unauthenticated; … Please set a HF_TOKEN to enable higher rate limits and faster downloads.`
  - A `Link` header pointing to `https://cas-server.xethub.hf.co/v1/reconstructions/<xethash>` (rel `xet-reconstruction-info`) and to a `xet-read-token` API.
- CDN response (observed 2026-11-25): `x-hf-cdn-pop: aws-us-east-1`, plus `content-security-policy: default-src 'none'; media-src 'self'; sandbox allow-same-origin`, which only matters if the file is navigated to. — [probe target](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- DNS (observed 2026-11-25):
  - These resolve: `us.aws.cdn.hf.co`, `cas-bridge.xethub.hf.co`, `cdn-lfs.hf.co`, `cdn-lfs-us-1.hf.co`, `cdn-lfs-eu-1.hf.co`.
  - These did not: `eu.aws.cdn.hf.co`, `ap.aws.cdn.hf.co`. Region naming for non-US clients is therefore unknown. — [probe target](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)
- Community and third-party allowlists. These are not HF-official and predate `us.aws.cdn.hf.co`. — [Cloudera air-gap allowlist](https://docs.cloudera.com/machine-learning/1.5.5/model-hub/topics/ml-model-hub-air-gap-installation.html); [HF forum: list of download redirections](https://discuss.huggingface.co/t/how-to-get-a-list-of-all-huggingface-download-redirections-to-whitelist/30486)
  - Hosts: `huggingface.co`, `cdn-lfs.huggingface.co`, `cdn-lfs-us-1`/`-eu-1` variants, `cas-bridge.xethub.hf.co`, `transfer.xethub.hf.co`, `cas-server.xethub.hf.co`, `*.cloudfront.net`.
  - An HF staff reply in the forum said to allowlist cas-bridge, transfer and cas-server. A user dates cas-bridge's arrival in the download path to the February 2025 Xet migration (search summary).
- HF rate limits, "current rate limits (in September '25)", over 5-minute fixed windows. — [HF Hub rate limits](https://huggingface.co/docs/hub/rate-limits)

  | Plan | API | Resolvers | Pages |
  |---|---|---|---|
  | Anonymous (per IP) | 500 | 3,000 | 100 |
  | Free | 1,000 | 5,000 | 200 |
  | PRO | 2,500 | 12,000 | 400 |
  | Team | 3,000 | 20,000 | 400 |
  | Enterprise | 6,000 | 50,000 | 600 |
  | Enterprise Plus | 10,000 | 100,000 | 1,000 |
  | Enterprise Plus with "Higher Hub Rate Limits" | 100,000 | 500,000 | 10,000 |

  - Resolvers are "all the URLs that contain a `/resolve/` segment".
  - Exceeding a limit returns 429, with IETF draft-09 `RateLimit` and `RateLimit-Policy` headers.
  - Anonymous and Free limits are "subject to change over time depending on platform health"; organization limits apply per member.
- litert-community gating, from the HF API (observed 2026-11-25). — [HF API: litert-community models](https://huggingface.co/api/models?author=litert-community)
  - `gemma-4-E2B-it-litert-lm` and `gemma-4-E4B-it-litert-lm` have `gated: False` and license `apache-2.0` (E2B last modified 2026-11-20).
  - `Gemma3-1B-IT`, `Gemma3-4B-IT` and `gemma-3-270m-it` have `gated: auto`.
  - The E2B repo's files: `-web.litertlm` 2,008,432,640 B; `-gpu.litertlm` 2,340,870,772 B; `.litertlm` 2,588,147,712 B; NPU variants up to 3,453,960,202 B.
- LiteRT-LM's README says "Some of these models are gated". To load one, pass the user's access token, e.g., from Sign in with Hugging Face (OAuth) with the `gated-repos` scope. "Don't embed your own access token in a web page: everyone who loads the page can read it." (Code at main.) — [LiteRT-LM js/packages/core README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/README.md); [hugging_face.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/hugging_face.ts)
- Terms:
  - HF's Terms of Service (effective 2022-09-15) and Content Policy prohibit platform abuse, including "using unauthorized bot APIs" (search summary).
  - An HF staff post says public storage is free and "(unless blatant abuse) unlimited"; the storage-limits doc mentions mitigations against abuse (search summary).
  - A forum question about using the Hub as a CDN for a client-side Transformers.js app got only community answers ("no per-GB egress caps are published"; rate limits apply), with no staff reply (thread from 2024-11-29; replies 2025-10). — [HF Terms of Service](https://huggingface.co/terms-of-service); [HF Content Policy](https://huggingface.co/content-policy); [HF forum: Hub as CDN](https://discuss.huggingface.co/t/using-huggingface-as-a-hosting-cdn-for-a-pretrained-model/128442)
- For self-hosting, Chrome advises `Cache-Control: public, max-age=31536000, immutable` and a new URL per model version **[Undated]**. — [Chrome: Cache models in the browser](https://developer.chrome.com/docs/ai/cache-models)

### Inferences
- **`connect-src` for HF.** The policy must allow every redirect hop (CSP checks the post-redirect URL). The minimum observed set is `https://huggingface.co https://us.aws.cdn.hf.co`, but the CDN host is chosen per region and request and has changed more than once since early 2025.
  - A sturdier policy is `https://huggingface.co https://*.hf.co`. A CSP `*.` host wildcard matches any subdomain depth; this is CSP3 host matching, not re-fetched in this pass.
  - Optionally add `https://*.huggingface.co` for legacy `cdn-lfs*.huggingface.co` redirects.
  - `cas-server`, `transfer` and `cas-bridge` are needed only by Xet-protocol clients or by older redirects. A plain `fetch()` follows the 302 Location and never calls the `Link` targets.
- **Rate limits.**
  - Each browser counts against its own IP's anonymous bucket. Each new file download costs one resolve; each re-resolve on resume after an hour costs another.
  - Engines that resolve `hf://` call `/api/models/{repo}/revision/{rev}?blobs=true`, which uses the API bucket: 500 per 5 minutes per IP when anonymous.
  - Users behind shared egress IPs (carrier NAT, offices, VPN exits) pool into one bucket. Pinning exact `/resolve/<commit>/<file>` URLs and the SHA-256 in the app avoids API calls entirely.
- **Self-hosting** (own CDN or object storage) removes third-party hosts from `connect-src` and HF's rate limits.
  - Same-origin hosting (e.g., `https://sidecar.ur.io/v1/models/<sha256>.litertlm`) also removes CORS and preflights and any COEP/CORP question.
  - Cross-origin hosting needs `Access-Control-Allow-Origin`, `Access-Control-Expose-Headers: Content-Range, Content-Length, ETag`, `Access-Control-Allow-Headers: Range` on preflight, and 206 support.
  - Gemma 4 E2B/E4B LiteRT-LM files are Apache-2.0 (per HF metadata), which permits redistribution with notices. The gated Gemma 3 files fall under Gemma's own terms.

### Gaps
- No official HF hostname list for browser downloads.
- No CDN host names observed for EU or APAC vantage points.
- No official HF statement on apps that have many end users download multi-GB files anonymously (bandwidth or acceptable-use thresholds). The full ToS text was not reviewed clause by clause.
- Whether authenticated requests are actually faster (as the `x-hf-warning` header claims) was not measured.

## 10. Integrity: verifying SHA-256 of a multi-GB file in the browser; SRI limits; how LiteRT-LM and other engines check

### Takeaway
No browser ships a streaming or incremental WebCrypto digest. `crypto.subtle.digest()` needs the whole input in memory, and a 2026 streaming proposal is only at the pull-request and discussion stage. Fetch's `integrity` (SRI) makes the browser buffer the entire body before handing it over, so it is impractical at 2–4 GB. Engines in practice:
- LiteRT-LM Web's `hf://` check is a metadata check. It resolves the revision to a commit, reads the Hub's LFS SHA-256 and size, and compares them with the caller's pin. I found no hashing of downloaded bytes in its JS code.
- Native LiteRT-LM verifies per-section SHA-256 values carried in the `.litertlm` header, hashing incrementally.
- WebLLM verifies SRI only for config, wasm and tokenizer files, using one-shot `digest()`.
- The COS adapters hash whole Blobs in memory or trust LFS metadata.

Verifying a full-file SHA-256 in the browser therefore needs an incremental SHA-256 in WASM or JS, or per-chunk hashes.

### Cited Findings
- The standard `digest()` doesn't take streaming input; "you must read the entire input into memory" (search summary of MDN). — [MDN: SubtleCrypto.digest()](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/digest)
- **[Proposal]** 2026 Web Engines Hackfest notes on the Web Cryptography API (wiki last edited 2026-09-23):
  - "There is a PR that uses the latest syntax for Async iterables for the digest operation, and the spec doesn´t strictly specify that the hashing is done incrementally."
  - Engine reactions: "we are not going to implement it immediately", "I don't think there is a lot of interest", and willingness "to implement it for digests".
  - Standards-position requests were planned. — [Igalia Web Engines Hackfest 2026: Web Cryptography API](https://github.com/Igalia/webengineshackfest/wiki/2026-Web-Cryptography-API)
- A WinterCG repo is "the beginning of a proposal to define streaming support for Web Crypto" (search summary). Cloudflare Workers has a non-standard `crypto.DigestStream`, server-side only. — [wintercg/proposal-webcrypto-streams](https://www.github.com/wintercg/proposal-webcrypto-streams); [Cloudflare Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- Fetch with `integrity` buffers the whole body. These are mailing-list mirrors of whatwg/fetch GitHub threads (search summary). — [Denicola, 2021-02](https://lists.w3.org/Archives/Public/public-webapps-github/2021Feb/0665.html); [van Kesteren, 2021-02](https://lists.w3.org/Archives/Public/public-webapps-github/2021Feb/0689.html); [Flynn, 2024-05](https://lists.w3.org/Archives/Public/public-webapps-github/2024May/0528.html); [West, 2025-10](https://lists.w3.org/Archives/Public/public-webapps-github/2025Oct/0291.html)
  - Domenic Denicola (2021, whatwg/fetch #661): implementations "put the entire response in memory, check the integrity, and then feed you a stream backed by memory instead of network". Anne van Kesteren proposed formalizing "a buffering proxy that does SRI".
  - Tim Flynn (2024, #1754) describes stream-locking problems in the spec's fully-read step.
  - Mike West's signature-based integrity PR (#1867, Oct–Nov 2025) verifies integrity "at the end of Main Fetch, alongside SRI's existing check".
- LiteRT-LM Web `hf://` resolution (code at main; commits 2026-10-28 to 2026-10-30). — [hugging_face.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model-cache/hugging_face.ts); [model_input.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/model_input.ts); [README](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/README.md)
  - It parses `hf://<org>/<repo>[@<revision>][/<path>]`.
  - It calls `https://huggingface.co/api/models/<repo>/revision/<rev>?blobs=true` to get the commit `sha` and each file's `lfs.sha256` and `size`.
  - It builds `https://huggingface.co/<repo>/resolve/<commit>/<path>`.
  - If the caller's `ModelSource` gives `sha256`, it compares that with the Hub's value and throws `"<uri> has SHA-256 <hub>, not <pinned>"` on mismatch; the size is checked the same way.
  - The SHA-256 becomes the default cache key (`cacheKey ?? sha256 ?? url`).
  - The README says: "The revision is resolved to its current commit before anything is downloaded, so the file that's downloaded always matches its SHA-256."
  - A grep of `js/packages/core/src` found no `crypto.subtle`, `digest` or SHA-256 hashing call. The files checked were `engine.ts`, `engine_creation.ts`, `load*.ts`, the stream wrappers, `model_input.ts`, all of `model-cache/`, `cpp/readable_stream_data_stream.cc` and `cpp/litertlm_web.cc`.
- LiteRT-LM native `sync/model_sync.cc` (code at main). The `.litertlm` header carries a SHA-256 per section. — [model_sync.cc](https://github.com/google-ai-edge/LiteRT-LM/blob/main/sync/model_sync.cc)
  - `VerifyFileSectionChecksums` hashes each section payload and compares it with the header value.
  - A `HashingStreambuf` updates "a Sha256Hasher incrementally" while writing.
  - A sync plan computes the byte ranges of changed sections, so updates fetch only those through a `RangeFetcher`.
- WebLLM `ModelIntegrity` (code at main):
  - It takes SRI strings (`sha256-`/`sha384-`/`sha512-` + base64) for `config` (`mlc-chat-config.json`), `model_lib` (the WASM library) and `tokenizer` files, with `onFailure: "error" | "warn"`.
  - `verifyIntegrity()` runs `crypto.subtle.digest()` over a whole ArrayBuffer.
  - Weight shards are not among the fields.
  - `artifact_manifest.ts` uses `sha256:<hex>` identifiers for interface and parameter-schema contracts. — [web-llm src/integrity.ts](https://github.com/mlc-ai/web-llm/blob/main/src/integrity.ts); [artifact_manifest.ts](https://github.com/mlc-ai/web-llm/blob/main/src/artifact_manifest.ts)
- TVM's COS cache computes a file's SHA-256 via `blob.arrayBuffer()` + `crypto.subtle.digest`. Transformers.js's COS cache takes LFS hashes from pointer files, and on a "slow path" reads the stream to compute the hash (code at main). — [tvm artifact_cache.ts](https://github.com/apache/tvm/blob/main/web/src/artifact_cache.ts); [transformers.js CrossOriginStorageCache.js](https://github.com/huggingface/transformers.js/blob/main/packages/transformers/src/utils/cache/CrossOriginStorageCache.js)
- HF exposes the SHA-256 as `X-Linked-ETag` on the `/resolve/` 302. The CDN's `ETag` is the Xet hash (observed 2026-11-25). — [probe target](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm)

### Inferences
- **Full-file SHA-256 matching the native pins.** Run an incremental SHA-256 (a WASM or JS library) in the download worker. Feed it each chunk as it is written to OPFS (tee the stream) so no second pass is needed. Only after the digest matches the pinned value, atomically rename or publish the file and mark it verified.
  - On resume, either persist the hasher's internal state with the byte offset, or re-hash the already-written prefix with one sequential OPFS read.
  - Never pass a 2–4 GB `ArrayBuffer` to `digest()`. Chrome, TVM and WebLLM's whole-buffer approach doesn't scale to this size, and fetch `integrity` buffers the whole body.
- **Per-chunk verification**, for parallel or resumable ranges. Publish a manifest with a SHA-256 per fixed-size chunk (e.g., 16–64 MiB), and pin the manifest's own hash alongside the file hash. Each range is then verifiable on arrival. `.litertlm`'s per-section SHA-256 values already provide this for LiteRT-LM files, but a browser would have to parse the header itself, which the Web SDK does not do today.
- LiteRT-LM Web's `hf://` check protects against a wrong file or revision, as reported by HF's metadata. It does not protect against a compromised CDN or a corrupted transfer. A deployment that requires "check against a pinned SHA-256 before loading", as the native apps do, must hash the bytes itself before handing a Blob to the engine.

### Gaps
- No measured SHA-256 throughput for WASM or JS implementations on 2–4 GB files per browser and device.
- No primary source for engine-specific `ArrayBuffer` size limits.
- The Xet hash algorithm (used for the CDN ETag) was not researched.

## 11. Lifecycle: does WebGPU inference in a Worker survive switching tabs (throttling, hidden tabs, freezing, discarding, Web Locks, iOS Safari, Android Chrome)?

### Takeaway
**Chrome desktop.** A hidden tab's worker and WebGPU work keep running unless the tab is frozen or discarded.
- Freezing (Chrome 133+) applies only when Energy Saver is on and the tab has been hidden and silent for more than 5 minutes and is CPU-intensive.
- Holding a Web Lock (or an IndexedDB lock) blocks every Chromium freezing type.
- Discarding (Memory Saver, or memory pressure) kills the renderer outright. Web Locks are not a documented discard exemption.

**Android Chrome.** It freezes background renderers' task queues after a 5-minute grace period, and the OS kills background renderers first under memory pressure.

**iOS Safari.** It suspends WebContent processes shortly after the user leaves Safari or locks the screen, and suspends background tabs as well.

**All platforms.** Design long jobs to checkpoint and resume.

### Cited Findings
- Page Lifecycle doc (last updated 2026-10-16). — [Chrome: Page Lifecycle API](https://developer.chrome.com/docs/web-platform/page-lifecycle-api)
  - States: active, passive, hidden, frozen, terminated, discarded.
  - While frozen, "JavaScript timers and fetch callbacks don't run".
  - Discards "typically occur under resource constraints" and fire no events.
  - "Hidden pages that play audio, use WebRTC, update the title or favicon, show alerts, or send push notifications won't be discarded unless resources are extremely constrained."
  - It recommends releasing Web Locks and closing IndexedDB connections on freeze.
  - `document.wasDiscarded` is available on desktop from Chrome 68.
- Freezing on Energy Saver (published 2025-01-20; Chrome 133, February 2025). — [Chrome: Freezing on Energy Saver](https://developer.chrome.com/blog/freezing-on-energy-saver)
  - Conditions: the tab is "hidden and silent for more than five minutes", "CPU-intensive" (threshold not published) and Energy Saver is active.
  - Freezing suspends event handlers, timers and promise resolvers; the page stays in memory.
  - Exemptions include audio or video conferencing, WebRTC, WebUSB/Bluetooth/HID/Serial, and "Web Locks, or IndexedDB connections that block operations outside the group".
  - The `BackgroundPageFreezeOptOut` origin trial is available, and a "Progress Notification API" is planned.
  - Eligibility is visible at `chrome://discards`.
- The Freezing on Energy Saver intent to ship planned to calibrate the CPU threshold so that about 10% of background tabs freeze when Energy Saver is active. A later update reported a 1% rollout on Chrome 133 stable (search summary). — [blink-dev: Intent to Ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/OVoSqEhtpNI); [blink-dev update](https://go.mail-archive.com/blink-dev@chromium.org/msg12586.html)
- Chromium freezing policy (code at main, read 2026-11-25). — [cannot_freeze_reason.h](https://github.com/chromium/chromium/blob/main/components/performance_manager/public/freezing/cannot_freeze_reason.h); [freezing_policy.cc](https://github.com/chromium/chromium/blob/main/components/performance_manager/freezing/freezing_policy.cc)
  - `CannotFreezeReason` includes `kHoldingWebLock`, `kHoldingIndexedDBLock`, `kHoldingBlockingIndexedDBLock`, `kWebRTC`, `kNotificationPermission`, `kAudible`/`kRecentlyAudible`, the `kCapturing*` and `kConnectedTo*` reasons, `kLoading`, `kOptedOut` and `kMostRecentlyUsed`.
  - `CannotFreezeReasonsForType()` applies all reasons to both freezing types, `kBatterySaver` and the feature-flagged `kInfiniteTabs`. The only exceptions are `kRecentlyVisible`, which is ignored for infinite-tabs freezing, and `kMostRecentlyUsed`, which is ignored otherwise.
- Memory Saver (Chrome 108+) proactively discards tabs "that have been unused in the background for some time" (no duration given). Users can exempt sites. Discarded tabs reload on return with `document.wasDiscarded === true`, and `beforeunload`/`pagehide`/`unload` don't fire **[Undated]**. — [Chrome: Memory and Energy Saver modes](https://developer.chrome.com/blog/memory-and-energy-saver-mode)
- Android:
  - The Blink intervention "Freezing task queues in background on mobile" freezes all freezable task queues "when a renderer has been in the background after grace time of 5 minutes, on Android" (search summary; date not captured). — [blink-dev: Freezing task queues in background on mobile](https://groups.google.com/a/chromium.org/g/blink-dev/c/NKtuFxLsKgo)
  - A Chromium design doc says that under memory pressure Android "will kill Chrome background renderer service[s] first" (search summary; doc not opened). — [Chromium design doc (Google Docs)](https://docs.google.com/document/d/1zQuI6qDX9eOmI2ki_SFRz_Z0sAASxYKwJPJrrNOt10M/export?format=pdf)
- Dedicated workers:
  - A 2018 Blink intent to throttle dedicated workers in background tabs notes that 43% of background-tab CPU went to dedicated workers. Its shipping status is unconfirmed (search summary). — [blink-dev: Throttling background dedicated workers](https://groups.google.com/a/chromium.org/d/topic/blink-dev/8xpEA-iNHwg)
  - A 2019 intent to "Pause Worklets and Dedicated Workers Execution on document freeze" notes Firefox already pauses dedicated workers in frozen (bfcache) documents. Shipping status in Chrome is unconfirmed (search summary). — [blink-dev: Pause dedicated workers on freeze](https://groups.google.com/a/chromium.org/g/blink-dev/c/KwDF6Eavfek/m/Qb48J5ceAwAJ)
- Chrome's budget-based background timer throttling dates to Chrome 57 (2017) (search summary). — [Chrome: Background tabs in Chrome 57](https://developer.chrome.com/blog/background_tabs)
- iOS and macOS Safari (no official Apple doc found):
  - WebKit bug 169824 (2017-03-17) notes that iOS background tabs can be suspended, and limited responsiveness detection to Mac (search summary). — [WebKit bug 169824](https://bugs.webkit.org/show_bug.cgi?id=169824)
  - A WebKit engineer: "When you lock the screen or home out of Safari, our processes get suspended shortly after" (search summary; bug number not captured).
  - Third-party reports put WebKit's suspension of hidden views at about 4–5 minutes (a Tauri-based app) and at 20–30 s after an app leaves the screen. These are weak sources. — [ribbon issue #158](https://github.com/KhalidAdan/ribbon/issues/158)
- WebGPU availability:
  - Firefox 141 on Windows and Firefox 145 on Apple-silicon macOS Tahoe 26; Safari 26. Chrome has shipped WebGPU since 113 (Chrome's version not re-verified in this pass) (search summary of web.dev). — [web.dev: WebGPU supported in major browsers](https://web.dev/blog/webgpu-supported-major-browsers)
  - Transformers.js code notes "Safari >= 26 enables WebGPU by default". — [transformers.js env.js](https://github.com/huggingface/transformers.js/blob/main/packages/transformers/src/env.js)
  - Firefox enabled WebGPU in dedicated workers by default on Nightly (bug 1938659, 136 branch) and in service workers (bug 1942431, 148). When the worker support reached stable is unconfirmed (search summary). — [Mozilla bug 1938659](https://bugzilla.mozilla.org/show_bug.cgi?id=1938659); [Mozilla bug 1942431](https://bugzilla.mozilla.org/show_bug.cgi?id=1942431)

### Inferences
- **Chrome and Edge desktop:** a Worker running WebGPU inference generally survives a tab switch. Holding a Web Lock for the duration of a job (as LiteRT-LM already does while downloading or reading) keeps the tab out of Energy Saver freezing, per Chromium's FreezingPolicy. It does not prevent discard. Under Memory Saver or memory pressure the renderer, worker and GPU device are gone, and the page reloads with `document.wasDiscarded`. The lifecycle doc's advice to release locks on freeze conflicts with holding them to avoid freezing; holding a lock also blocks bfcache.
- **Android Chrome:** treat any job that runs longer than about 5 minutes in the background as likely to be frozen, and any backgrounded tab as killable. Checkpoint job state to IndexedDB and resume on `visibilitychange`/`resume`.
- **iOS and iPadOS Safari:** assume work stops within seconds of leaving Safari and that background tabs are eventually suspended. Keep jobs short or resumable. No published API lets a page keep running.
- **Firefox:** background tabs follow its own throttling and tab-unloading rules. No 2025–2026 primary source on worker or WebGPU behaviour in hidden tabs was found.

### Gaps
- No authoritative source on whether Chrome throttles dedicated workers or deprioritizes WebGPU queue execution in hidden (unfrozen) tabs today.
- No source on whether Chrome's current freezing pauses a frozen page's dedicated workers.
- Whether a Web Lock exempts a tab from Memory Saver discards (no source either way).
- The default state of Chromium's "infinite tabs freezing" feature.
- iOS suspension timings from Apple.
- Firefox's tab-unloading rules on each OS.
- Whether Safari runs WebGPU in dedicated workers on iOS 26.

## 12. Cross-origin isolation for a framed same-site iframe (COOP, COEP `require-corp`/`credentialless`, `allow="cross-origin-isolated"`, Document-Isolation-Policy) and its costs

### Takeaway
With classic COOP+COEP, `crossOriginIsolated` (needed for SharedArrayBuffer and wasm threads) in the `sidecar.ur.io` iframe requires the whole chain:
- `ur.io` sends `COOP: same-origin` and `COEP: require-corp` or `credentialless`;
- the iframe document and its worker scripts send COEP;
- the iframe response sends CORP (`same-site` suffices);
- the `<iframe>` carries `allow="cross-origin-isolated"`, because the policy's default allowlist is `self`.

Safari has no `credentialless` (through 27.x), so the top page needs CORP or CORS on every cross-origin subresource. COOP `same-origin` cuts `window.opener` between the page and cross-origin popups, which breaks opener-based OAuth and payment popups.

**[Shipped]** Chromium has Document-Isolation-Policy (DIP): desktop 137, Android 146 per ChromeStatus, enabled by default in code. With it the iframe can isolate itself whatever the embedder sends, and with no top-level delegation. Firefox's position on DIP is "Positive" but it isn't implemented; WebKit's is "Negative".

### Cited Findings
- To isolate an embedded document, add `allow="cross-origin-isolated"` to the `<iframe>`; "The entire chain of the documents, including parent frames and child frames, must be cross-origin isolated, too." Apply enforced COEP "to all documents including those that are embedded with iframes and worker scripts", and give iframe resources `Cross-Origin-Resource-Policy: cross-origin` (or `same-site`/`same-origin`). Under COOP `same-origin`, opened windows go to a separate browsing context group, and "mutual communication between both windows is disabled" (`window.opener` is lost). web.dev, published 2020-04-13, updated 2022-06-21. — [web.dev: COOP and COEP](https://web.dev/articles/coop-coep)
- The `cross-origin-isolated` Permissions Policy has default allowlist `self`. Where it's blocked, `crossOriginIsolated` is always `false` regardless of headers. MDN, 2025-07-04, marked experimental. — [MDN: Permissions-Policy cross-origin-isolated](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy/cross-origin-isolated)
- COEP values (MDN, last modified 2026-09-04):
  - `require-corp`: cross-origin `no-cors` resources load only with a permitting CORP header; `cors`-mode requests aren't blocked by COEP but must pass CORS.
  - `credentialless`: no-cors resources load without credentials.
  - Isolation needs COOP `same-origin` + COEP, and the Permissions Policy must not block it. — [MDN: COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)
- `COEP: credentialless` support, caniuse (accessed 2026-11-25): Chrome 96+, Edge 96+, Firefox 119+, Samsung Internet 17+, Chrome for Android (only 157 listed). Not supported in Safari macOS (through 27.3) or Safari iOS (through 27.2). — [caniuse: COEP credentialless](https://caniuse.com/mdn-http_headers_cross-origin-embedder-policy_credentialless)
- Chrome's `iframe credentialless` (anonymous iframes) is enabled by default in Chrome 110 on desktop and Android. Firefox: "No signal". Safari: "No signal". ChromeStatus, accessed 2026-11-25. — [ChromeStatus: Iframe credentialless](https://chromestatus.com/feature/5729461725036544)
- Document-Isolation-Policy. — [ChromeStatus: Document-Isolation-Policy](https://chromestatus.com/feature/5141940204208128); [Mozilla standards-positions #1074](https://github.com/mozilla/standards-positions/issues/1074); [WebKit standards-positions #399](https://github.com/WebKit/standards-positions/issues/399); [Chrome blog: Document Isolation Policy](https://developer.chrome.com/blog/document-isolation-policy); [Chromium network features.cc](https://github.com/chromium/chromium/blob/main/services/network/public/cpp/features.cc)
  - ChromeStatus (entry updated 2026-01-22): "allows a document to enable crossOriginIsolation for itself, without having to deploy COOP or COEP, and regardless of the crossOriginIsolation status of the page", backed by process isolation.
  - Shipping stage: desktop 137, Android 146 (the status text oddly reads "In development"); origin trial 132–134.
  - Firefox "Positive". Safari "Negative", with notes on low-end Android plans.
  - Chrome blog (2025-05-01): Chrome 137 desktop. Modes are `isolate-and-require-corp` and `isolate-and-credentialless`. The policy "applies per frame and makes no requirements of subframes". Isolated frames lose synchronous DOM access to non-isolated same-origin frames. Popups and iframes are unrestricted.
  - Chromium code at main: `BASE_FEATURE(kDocumentIsolationPolicy, base::FEATURE_ENABLED_BY_DEFAULT)`.
- DIP explainer **[Undated]**: — [WICG document-isolation-policy explainer](https://github.com/WICG/document-isolation-policy/blob/main/README.md)
  - A DIP iframe gets COI-gated APIs "regardless of whether its embedder deployed COI or not", and a document with COEP and DIP has access "whether the top-level delegated the permission or not".
  - Workers inherit DIP and crossOriginIsolation status from their creator.
  - COI APIs require process isolation; Android WebView lacks it, and low-end Android has limited process isolation.
  - "An iframe with DIP but no COEP may not be embedded in a COEP document."
- LiteRT-LM Web probes `SharedArrayBuffer` transferability (`postMessage(new SharedArrayBuffer(1))`) in its wasm feature detection, i.e., it uses wasm threads when isolation allows (code at main). — [wasm_feature_detect.ts](https://github.com/google-ai-edge/LiteRT-LM/blob/main/js/packages/core/src/wasm_feature_detect.ts)

### Inferences
- **Chrome and Edge, desktop and Android** (where site isolation is available): `sidecar.ur.io` can send `Document-Isolation-Policy: isolate-and-credentialless` (or `isolate-and-require-corp`) on its document and get `crossOriginIsolated` in the frame and its dedicated worker. ur.io needs no change: no COOP, no COEP, no `allow` attribute. OAuth popups and third-party embeds on ur.io are unaffected.
  - The frame's own `cors`-mode fetches to Hugging Face are unaffected, since CORS is present.
  - The frame should also not ship COEP unless the embedder does, per the explainer's embedding rule.
- **Firefox and Safari:** isolation needs ur.io itself to send COOP `same-origin` + COEP. In Safari that means `require-corp`, so every cross-origin image, script and iframe on ur.io needs CORP or CORS.
  - ur.io's OAuth and payment popups that rely on `window.opener` break.
  - The sidecar response needs COEP + `CORP: same-site`, and the `<iframe>` needs `allow="cross-origin-isolated"`.
  - The practical fallback is to run single-threaded wasm, or WebGPU only, when `crossOriginIsolated` is false. WebGPU itself doesn't require isolation (general knowledge; not re-verified here).
- The deployment's CSP (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src …`) is independent of COI. COI headers don't relax or tighten CSP.

### Gaps
- No source confirmed that the Android 146 DIP launch reached all Android tiers. ChromeStatus status text conflicts with its shipping stage.
- No Safari or Firefox timeline for DIP or `credentialless`.
- Whether a same-site (vs cross-site) iframe changes any COI rule: no source draws that distinction, so treat it as a cross-origin iframe.

## 13. Memory pressure: how browsers kill tabs or GPU processes holding large buffers

### Takeaway
None of the browsers publishes per-tab memory caps. Under pressure, Chrome discards hidden tabs, and a GPU-process crash loses every `GPUDevice`. Android kills background renderers first. iOS jetsams the tab's process at a per-process limit. WebKit charges a tab's GPU-process memory to the tab, and its WebGPU out-of-memory → device-lost fix was reverted (bug still open), so on iOS a large model may die without a JS-visible error and Safari may auto-reload the page. Handle `device.lost`, destroy buffers, and plan to re-load.

### Cited Findings
- Chrome discards pages "typically… under resource constraints", from hidden or frozen state, with no events. Chrome is conservative about tabs using audio or WebRTC. Page Lifecycle, updated 2026-10-16. — [Chrome: Page Lifecycle API](https://developer.chrome.com/docs/web-platform/page-lifecycle-api)
- Chrome's WebGPU troubleshooting page points to device-loss handling and mentions the "GPU process crashed several times" condition, after which users reload or restart Chrome (search summary) **[Undated]**. — [Chrome: WebGPU troubleshooting tips](https://developer.chrome.com/docs/web-platform/webgpu/troubleshooting-tips)
- WebKit bug 280929, "[WebGPU] Out of memory should trigger a device lost" (reported 2024-10-04): committed as 285178@main on 2024-10-14, reopened 2024-10-15 after it "caused a race and fuzzer crashes" (revert tracked in bug 281507). Status: REOPENED. — [WebKit bug 280929](https://bugs.webkit.org/show_bug.cgi?id=280929)
- WebKit bug 300782 (reported 2025-10-15, NEW, Safari 18 / iOS 18): WebGL-heavy pages "are killed under iOS memory pressure and immediately reloaded", looping. No OOM error reaches JS, and no `webglcontextlost` fires before the kill. A 2026-03-10 comment says iOS limits app memory rather than physical RAM; a WebKit engineer (2026-03-11) asked for a repro. — [WebKit bug 300782](https://bugs.webkit.org/show_bug.cgi?id=300782)
- WebKit developers have said WebKit assigns a tab's GPU-process memory cost to the tab itself, and one WebKit bug reports a WebLLM demo failing on iOS because it "requires 1GB buffer size" (search summary; bug numbers not captured).
- Under memory pressure Android kills Chrome's background renderer service first (search summary of a Chromium design doc). — [Chromium design doc (Google Docs)](https://docs.google.com/document/d/1zQuI6qDX9eOmI2ki_SFRz_Z0sAASxYKwJPJrrNOt10M/export?format=pdf)
- Mozilla bug 1860803, "Weird crashes if you open a webgpu demo in 30 background tabs in quick succession" (title from search). — [Mozilla bug 1860803](https://bugzilla.mozilla.org/show_bug.cgi?id=1860803)
- A developer article reports GPU weight buffers surviving SPA teardown: about 1 GiB pinned after five route changes, until an OOM tab crash. Explicit `.destroy()` fixes it. Single-author claim (search summary). — [SitePoint: profiling WebGPU memory](https://www.sitepoint.com/profiling-webgpu-memory-local-ai/)

### Inferences
- **Device loss.** A 2–4 GB model sitting in GPU buffers is the largest allocation in the tab and the likeliest trigger for discard, jetsam or GPU-process loss. Every engine path needs a `device.lost` handler that re-requests an adapter and device and re-uploads weights from storage. That is one more reason the cached file must survive tab death.
- **Peak memory.** Avoid holding a JS or wasm copy of the weights after upload, and stream uploads in chunks so the peak doesn't hit 2× model size. Call `destroy()` on buffers when switching models.
- **iOS.** Prefer the smallest model variant: the 2.0 GB `-web`/`-gpu` file over the 2.6–3.5 GB variants. Test on 6–8 GB-RAM devices, since no limit is published.

### Gaps
- No published per-process or per-tab memory limits for Chrome, Firefox, or iOS/macOS Safari WebContent and GPU processes.
- No published WebGPU `maxBufferSize`/`maxStorageBufferBindingSize` per platform in 2026 (not researched here).
- No Chrome statement on whether the GPU process is restarted transparently, or on how many crashes disable WebGPU for the session.
