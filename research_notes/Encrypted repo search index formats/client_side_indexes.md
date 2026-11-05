# Client-side downloadable search indexes: formats, sizes, chunking, and lessons for a fully downloaded encrypted index

Research date: 2026-11-05. Versions are the latest published as of that date. Numbers marked **measured** come from my own downloads of live Pagefind and Stork demo bundles on 2026-11-05. I fetched every index chunk, sampled 800 fragments per site, decoded the CBOR/MessagePack, and recompressed the data locally. The measured bundle URLs are cited; the method is described where the numbers appear. Everything else is cited to primary sources (source code, READMEs, release notes, docs) or to named secondary sources.

## 1. Pagefind: index format, chunking, fragment loading, size relative to content, large-site numbers

### Takeaway
Pagefind keeps each query's download small by splitting a sorted inverted index into gzipped CBOR chunks, each covering a range of terms, and fetching only the chunk for each query term plus the data for the results shown. Its whole word index is large, though, because it stores every word position. On Pagefind's own demo sites I measured it at 0.38–0.52× the raw text size, gzipped (about 400–530 bytes per KB of text). For MDN that is 12.4 MB of index for about 31 MB of text, against about 300 KB for one single-term query.

### Cited Findings
**Version and status**
- Latest release is v1.6.0 (2026-11-01). Earlier releases: v1.5.0 (2026-04-06), v1.4.0 (2025-09-01), v1.3.0 (2024-12-18), v1.0.0 (2023-09-13). The npm `pagefind` latest is also 1.6.0 — [GitHub releases](https://github.com/CloudCannon/pagefind/releases), [npm](https://www.npmjs.com/package/pagefind)
- The docs now describe Pagefind as "an independent open source project, originally created and developed at CloudCannon". Doc links point to github.com/pagefind/pagefind — [Pagefind homepage source](https://github.com/CloudCannon/pagefind/blob/main/docs/content/_index.md)

**Design goal and size claim**
- Quote: "Pagefind's search index is split into chunks, so that searching in the browser only ever needs to load a small subset of the search index. Pagefind can run a full-text search on a 10,000 page site with a total network payload under 300kB, including the Pagefind library itself. For most sites, this will be closer to 100kB." — [pagefind.app](https://pagefind.app/)
- Sample indexing output in the quick start: "Indexed 2496 pages / Indexed 22852 words / ... / Created 27 index chunks" — [Pagefind quick start](https://pagefind.app/docs/)

**On-disk format (from the Rust source)**
- `pagefind-entry.json` is plain JSON with the version and, per language, `{hash, wasm, page_count}`. Example from MDN: `{"version":"1.5.0","languages":{"en-us":{"hash":"en-us_d93ca1932bd43","wasm":"en-us","page_count":14242}}...}` — [MDN demo entry file](https://mdn.pagefind.app/pagefind/pagefind-entry.json)
- `pagefind.<lang_hash>.pf_meta` is minicbor-encoded `MetaIndex {version, pages: Vec<MetaPage{hash, word_count, group_hash}>, index_chunks: Vec<MetaChunk{from, to, hash}>, filters: Vec<MetaFilter{filter, hash}>, sorts: Vec<MetaSort{sort, pages}>, meta_fields}`. It is loaded at init. Each `MetaChunk` tells the client which `.pf_index` file holds words that sort between `from` and `to` — [index_metadata.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/index_metadata.rs)
- `index/<hash>.pf_index` is CBOR `WordIndex {words: Vec<PackedWord{word, pages: Vec<PackedPage{page_number, locs: Vec<i32>, meta_locs: Vec<i32>}>, additional_variants: Vec<PackedVariant{form, pages}>}>}`. This is a positional inverted index: for each word, every page and every word location, plus diacritic variants — [index_words.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/index_words.rs)
- `filter/<hash>.pf_filter` is CBOR `FilterIndex {filter, values: Vec<PackedValue{value, pages: Vec<usize>}>}`, an inverted index from facet value to pages — [index_filter.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/index_filter.rs)
- `fragment/<hash>.pf_fragment` is JSON `{url, content, word_count, filters, meta, anchors[{element,id,text,title,location}]}`. It holds the page's full plain text, used to build excerpts and sub-results — [fragments/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/fragments/mod.rs)
- The `.pf_meta`, `.pf_index`, `.pf_fragment` and `.pf_filter` files are written with `GzEncoder::new(..., Compression::best())`, and the 12-byte signature `pagefind_dcd` is written inside the gzip stream. The JS client checks for the signature to tell whether the host already removed the gzip encoding — [output/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/output/mod.rs), [coupled_search.ts](https://github.com/CloudCannon/pagefind/blob/main/pagefind_web_js/lib/coupled_search.ts)
- The search core is Rust compiled to WASM. A gzipped WASM file is shipped per language (`wasm.<lang>.pagefind`, carrying that language's stemmer), plus a generic `wasm.unknown.pagefind` — [output/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/output/mod.rs)

**How chunking works**
- Words are sorted lexicographically and added to the current chunk. Each word adds Σ over its pages of `(locs.len() + meta_locs.len() + 1)`, plus its number of variants. A chunk closes once that total reaches `index_chunk_size`. So chunks are sized by posting and position count, not bytes — [index/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/mod.rs)
- The default `index_chunk_size` is `20000`. It can be overridden only through the env var `PAGEFIND_UNSTABLE_INDEX_CHUNK_SIZE`. The source has a TODO: "Parameterize these chunk sizes via byte size rather than word count" — [options.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/options.rs), [index/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/mod.rs)
- Chunk `from`/`to` bounds are trimmed to the shortest distinguishing prefixes (`get_prefixes`). The term range of every chunk is therefore listed in plaintext in `pf_meta`, e.g. MDN chunk `["logc","loop",...]` — [index/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/mod.rs), [MDN demo](https://mdn.pagefind.app/)
- Positions are sorted by weight, then by position, and delta-encoded. A weight change is written inline as a negative marker `-(weight)-1` followed by an absolute position. Page numbers are delta-encoded within each word's page list — [index/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/mod.rs)
- v1.5.0 release note: "Pagefind's index chunks are now ~45% smaller thanks to delta-encoding page numbers and word locations" — [v1.5.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.5.0)
- v1.6.0 changes:
  - Fixes "a bug where a word with many variants could produce an oversized index chunk".
  - Makes the index more deterministic between builds.
  - Adds `--max-fragments`, which bundles fragments into groups "for hosting providers that cap the number of uploaded files".

  — [v1.6.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.6.0)
- v1.3.0: "if an HTML page has not changed between two Pagefind indexes, the fragment filename will not change … saves you from having to re-upload all fragment files after every Pagefind build" — [v1.3.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.3.0)
- Ranking:
  - v1.0 added inverse document frequency.
  - v1.1 aligned ranking with BM25.
  - v1.5 searches metadata such as the title by default.

  — [v1.0.0](https://github.com/CloudCannon/pagefind/releases/tag/v1.0.0), [v1.1.0](https://github.com/CloudCannon/pagefind/releases/tag/v1.1.0), [v1.5.0](https://github.com/CloudCannon/pagefind/releases/tag/v1.5.0)

**How the client loads chunks and fragments**
- `pagefind.init()` "will load the Pagefind dependencies and the metadata about the site". The metadata file "is fetched fresh on every page load". v1.5 added `metaCacheTag` to control its cache-busting — [Pagefind JS API docs](https://pagefind.app/docs/api/), [v1.5.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.5.0)
- WASM `request_indexes(query)` picks chunks whose `[from,to]` contains the raw or stemmed term. If no chunk matches strictly, it falls back to prefix ("loose") matching. Loaded chunks are cached by hash. Fetches are throttled with `maxConcurrentFetches = 100` — [pagefind_web/src/lib.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind_web/src/lib.rs), [coupled_search.ts](https://github.com/CloudCannon/pagefind/blob/main/pagefind_web_js/lib/coupled_search.ts)
- Preloading: "Since indexes are chunked alphabetically, running `pagefind.preload("s")` will likely load the index required to search for `static` by the time the user has finished typing". `debouncedSearch` defaults to 300 ms — [Pagefind JS API docs](https://pagefind.app/docs/api/)
- Fragments load lazily: "To reduce bandwidth usage, the data for each result (e.g. URL & title) must be loaded independently". The docs show loading the first five with `results.slice(0, 5).map(r => r.data())` — [Pagefind JS API docs](https://pagefind.app/docs/api/)
- From v1.5, "Pagefind's search now runs in a Web Worker automatically … doesn't make the search faster, per se, but it dramatically improves perceived performance on large websites" — [v1.5.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.5.0)

**Measured bundles (2026-11-05)**

Method: I fetched each site's entry file, `pf_meta`, every `.pf_index` chunk and the WASM/JS, and sampled 800 fragments (all 48 for pagefind.app). Text size is estimated from the fragments' `content` fields, scaled up to the page count. Sizes are as served to a client that sent no Accept-Encoding header; the index files are pre-gzipped. Bundles: [MDN](https://mdn.pagefind.app/pagefind/pagefind-entry.json) (built with v1.5.0), [Godot docs](https://godot.pagefind.app/pagefind/pagefind-entry.json) (v1.5.0-beta.2), [XKCD](https://xkcd.pagefind.app/pagefind/pagefind-entry.json) (v1.5.0-beta.2), [pagefind.app docs](https://pagefind.app/pagefind/pagefind-entry.json) (v1.6.0).

| Site | Pages | Words | Est. raw text | `pf_meta` gz | Chunks | All chunks gz | Median / max chunk gz | Unique terms | Postings (term,page) | Position entries |
|---|---|---|---|---|---|---|---|---|---|---|
| pagefind.app | 48 | 25,279 | 189 KB | 0.5 KB | 3 | 70 KB | 24.6 / 28.2 KB | 2,415 | 10,577 | 43,334 |
| XKCD | 3,000 | 562,118 | 3.28 MB | 21.9 KB | 63 | 1.66 MB | 26.6 / 49.0 KB | 33,111 | 349,016 | 927,521 |
| Godot docs | 1,579 | 1,561,945 | 11.2 MB | 14.0 KB | 122 | 4.37 MB | 33.2 / 97.5 KB | 60,396 | 392,789 | 2,501,882 |
| MDN | 14,242 | 5,047,089 | 31.4 MB | 105.6 KB | 322 | 12.28 MB | 30.3 / 308.6 KB | 66,652 | 1,859,431 | 7,972,484 |

| Site | Full word index gz (meta+chunks+filters) | ÷ raw text | Bytes per KB of text | Bytes per page | Chunks raw CBOR ÷ text | Whole index as one blob: gzip-9 / brotli-11 / zstd-19 | All fragments gz (est.) |
|---|---|---|---|---|---|---|---|
| pagefind.app | 71.1 KB | 0.377 | 386 | 1,481 | 0.83 | 68.9 / 60.1 / 64.2 KB | 86 KB |
| XKCD | 1.69 MB | 0.516 | 529 | 565 | 1.16 | 1.63 / 1.41 / 1.46 MB | 2.21 MB |
| Godot docs | 4.38 MB | 0.391 | 401 | 2,774 | 0.70 | 4.31 / 3.64 / 3.76 MB | 4.17 MB |
| MDN | 12.39 MB | 0.395 | 405 | 870 | 0.77 | 12.11 / 10.33 / 10.73 MB | 15.4 MB |

- **Measured.** MDN library assets (v1.5.0): `pagefind.js` 45.5 KB, `pagefind-worker.js` 41.2 KB, `wasm.en-us.pagefind` 72.2 KB (gzipped WASM). On pagefind.app (v1.6.0) the same assets are 47.2 KB, 42.9 KB and 59.8 KB — [MDN demo](https://mdn.pagefind.app/), [pagefind.app](https://pagefind.app/)
- **Measured.** The compressed index costs 4.8–11.1 bytes per posting and 1.5–1.8 bytes per position entry. MDN: 6.6 B per posting, 1.54 B per position — [MDN demo](https://mdn.pagefind.app/)
- **Measured.** `pf_meta` grows with page count: about 7.3–8.9 bytes gzipped per page (MDN 105.6 KB for 14,242 pages) — [MDN demo](https://mdn.pagefind.app/), [XKCD demo](https://xkcd.pagefind.app/)
- **Measured.** A single-term search on MDN costs about 298 KB. That is JS 45.5 KB + worker 41.2 KB + WASM 72.2 KB + meta 105.6 KB + one median chunk of 30.3 KB + five fragments at about 0.7 KB each. It matches the "under 300kB" claim at 14k pages. Downloading the whole word index instead (12.4 MB gz) is about 41× larger — [MDN demo](https://mdn.pagefind.app/)

**Large-site reports**
- Hugo forum, "Scaling Pagefind to over 1 million pages" (Oct–Dec 2025):
  - Indexing crashed after about 300,000 pages.
  - The best result was 250,000 pages indexed without crashing a local machine.
  - The poster proposed splitting into per-URL-prefix shards merged with `mergeIndex`, but did not confirm adopting it.
  - Conclusion: "We found pagefind too hard to scale with even a site of 500k". They switched to a custom 3-tier JSON system.

  — [Hugo discourse](https://discourse.gohugo.io/t/scaling-pagefind-to-over-1-million-pages/56109)

### Inferences
- Pagefind gets its small per-query payload from term-range fetching. A full download gives that up, and the full positional index is about 40% of the raw text size gzipped (33% with whole-blob brotli). For a client that must download everything, Pagefind's format is the wrong trade-off: it is optimized to fetch a small part of a large index.
- Word positions, not doc IDs, take up most of the bytes. MDN has 7.97M position entries against 1.86M postings. My re-encode experiment (Section 8) shows a docID+tf layout of the same index is about one-fifth the size.
- Gzipping each chunk separately and then recompressing the whole index as one brotli-11 blob saved about 15% (MDN 12.28 → 10.33 MB). A whole-download format should be compressed as large blocks.
- `pf_meta` (per-page hashes and word counts) is loaded on every init and grows linearly. At 7.4 B/page, a 1M-page site would need about 7.4 MB before any query. This fits the Hugo reports of trouble past 250–500k pages, although those failures were at indexing time.
- Leakage of Pagefind's on-demand model: on MDN each chunk covers about 207 terms (66,652 terms / 322 chunks), and the chunk's term range is public in `pf_meta`. A host that sees which chunk was fetched learns each query term to within about 200 alphabetically adjacent candidates. Fragment fetches then reveal exactly which result documents were displayed. This shows concretely why on-demand fetching fails the target system's privacy requirement.

### Gaps
- I found no official Pagefind measurements of query latency (ms) or memory use, on desktop or phones.
- The fragment totals and text sizes above are estimates from samples of 800 pages (all pages for pagefind.app). Three of the four demo bundles were built with v1.5.0 or v1.5.0-beta.2, not v1.6.0.
- The JS sizes are as served without HTTP compression. A browser that negotiates gzip or brotli would download less JS.

## 2. Stork: binary index format, WASM approach, and maintenance status

### Takeaway
Stork is effectively abandoned. Its author announced in June 2023 that he was "winding down" work, and the last releases were Stork 2.0 betas in March 2023. Its v3 `.st` format is a single MessagePack file loaded whole, which stores every document's full text plus precomputed per-term results and prefix aliases. I measured its own demo index at 4.8× the size of the text it indexes, uncompressed (1.4× after brotli).

### Cited Findings
- The README banner reads: "Project update: I'm winding down my work with Stork." It links to discussion #360 — [Stork README](https://github.com/jameslittle230/stork)
- Discussion #360 (June 18, 2023):
  - Quote: "I'm no longer able to work on Stork to the degree the project and its users deserve."
  - Reasons given: burnout, Stork being a solo project, and his day job.
  - He names "Tinysearch and PageFind" as "philosophically, the most similar alternatives to Stork".
  - He would publish the work-in-progress 2.0.0 branches.

  — [Stork discussion #360](https://github.com/jameslittle230/stork/discussions/360)
- The repo is not archived; the last push was 2023-07-01. The newest GitHub release is v2.0.0-beta.2 (2023-03-05). The npm `stork-search` package was last published as 1.0.4 (2021-01-18) — [GitHub API repo metadata](https://api.github.com/repos/jameslittle230/stork), [Stork releases](https://github.com/jameslittle230/stork/releases), [npm](https://www.npmjs.com/package/stork-search)
- Stork 2.0 alpha/beta notes:
  - "the indexing binary, WASM blob, and Javascript file are all smaller than the 1.x branch. Searches are faster."
  - "The new index format includes support for sharded indexes, meaning future indexes will be able to be made up of multiple size-limited files that get loaded dynamically as your user types."
  - Beta 1 says sharding does not work yet: "the builder doesn't yet know how to split an index into multiple parts."

  — [v2.0.0-alpha.3](https://github.com/jameslittle230/stork/releases/tag/v2.0.0-alpha.3), [v2.0.0-beta.1](https://github.com/jameslittle230/stork/releases/tag/v2.0.0-beta.1)
- Format: the `search-v3` feature serializes with `rmp-serde` (MessagePack); the older `search-v2` used `bincode` — [stork-lib/Cargo.toml](https://github.com/jameslittle230/stork/blob/master/stork-lib/Cargo.toml)
- The v3 `Index` holds:
  - `config` (url_prefix, title_boost, excerpt_buffer, excerpts_per_result, displayed_results_count)
  - `entries: Vec<Entry{contents, title, url, fields}>`
  - `containers: BTreeMap<String, Container{results: BTreeMap<EntryIndex, SearchResult{excerpts…}>, aliases: BTreeMap<AliasTarget, Score>}>`

  "Each valid query should return a single Container", so every searchable term and prefix has precomputed results — [index_v3/mod.rs](https://github.com/jameslittle230/stork/blob/master/stork-lib/src/index_v3/mod.rs)
- Stork's JS registers an index URL, `stork.register("federalist", "http://files.stork-search.net/federalist.st")`, and `stork.js` "will load the Stork WebAssembly blob". The whole `.st` file is the index — [Stork README](https://github.com/jameslittle230/stork)
- **Measured** on the demo `federalist.st`:
  - Header: an 8-byte length, the version string `stork-3`, an 8-byte payload length, then MessagePack.
  - 20 entries holding 234,939 bytes of text.
  - The file is 1,125,456 bytes, 4.79× the text. gzip-9 gives 423,085 B (1.80×); brotli-11 gives 323,559 B (1.38×).
  - 15,910 containers (terms plus prefixes), 14,095 result references, 27,303 alias references.

  — [federalist.st](https://files.stork-search.net/federalist.st)
- **Measured.** Stork WASM sizes: `releases/v1.6.0/stork.wasm` is 336,673 B; `releases/latest/stork.wasm` is 197,981 B — [v1.6.0 wasm](https://files.stork-search.net/releases/v1.6.0/stork.wasm), [latest wasm](https://files.stork-search.net/releases/latest/stork.wasm)

### Inferences
- Stork shows that precomputing excerpts and prefix expansions into the index makes it larger than the text it indexes. A downloaded-whole design should leave snippets and prefix expansion to query time.
- Sharding was only designed in Stork 2.0, never shipped. The two maintained successors either fetch term-range shards (Pagefind) or bundle everything into one small file (tinysearch).

### Gaps
- I did not verify the release date of Stork v1.6.0, or which version `releases/latest` points to.
- No Stork query-latency or memory measurements were found.

## 3. FlexSearch, MiniSearch, lunr.js, elasticlunr, Orama: serialized formats, size per document or per KB, browser memory

### Takeaway
All five are JavaScript, in-memory engines, and their serialization is JSON or JSON-like: lunr, elasticlunr and MiniSearch emit JSON; FlexSearch emits keyed JSON strings or generated JS; Orama emits JSON, dpack, hex-encoded MessagePack or seqproto. None ships a compact, chunked binary format like Pagefind's. Published size data is thin:
- A lunr JSON index can be larger than the source text (1.7 MB raw for two novels, 192 KB brotli).
- elasticlunr claims about half of lunr's size.
- MiniSearch claims less than half of lunr's memory.
- FlexSearch says its export size equals its memory footprint.

### Cited Findings
**Versions**
- MiniSearch 7.2.0 (2025-09-16).
- FlexSearch 0.8.212 on npm (2025-09-06); the newest GitHub release is 0.8.2 (2025-05-21), and 0.8.0 (2025-03-17) followed 0.7.31 (2022-10-03).
- @orama/orama 3.1.18 (2025-12-19).
- lunr 2.3.9 (2020-08-19); elasticlunr 0.9.5 (2016-09-08). Neither has had a release since.

— [npm minisearch](https://www.npmjs.com/package/minisearch), [npm flexsearch](https://www.npmjs.com/package/flexsearch), [FlexSearch releases](https://github.com/nextapps-de/flexsearch/releases), [npm @orama/orama](https://www.npmjs.com/package/@orama/orama), [npm lunr](https://www.npmjs.com/package/lunr), [npm elasticlunr](https://www.npmjs.com/package/elasticlunr)

**FlexSearch**
- `index.export((key, data) => …)` emits several key/data string pairs. "You need to import every key! Otherwise, your index does not work". The config is not stored in the export.
- "The size of the export corresponds to the memory consumption of the library. To reduce export size you have to use a configuration which has less memory footprint."
- Persistent and Worker indexes do not support export/import.
- An experimental "Fast-Boot Serialization" emits JS source (`index.reg = new Set([...]); index.map = new Map([...]); index.ctx = new Map([...])`).

— [FlexSearch export-import.md](https://github.com/nextapps-de/flexsearch/blob/master/doc/export-import.md)
- v0.8 adds persistent indexes backed by IndexedDB (browser), Redis, SQLite, Postgres, MongoDB or Clickhouse — [FlexSearch README](https://github.com/nextapps-de/flexsearch)
- The maintainer's v0.8 README benchmark uses the "Gulliver's Travels" corpus. It reports "terms per second", and its Memory column is "the amount of memory which was additionally allocated during search", with no unit given.

  | Library | Single-term queries/s | Memory allocated during search |
  |---|---|---|
  | flexsearch | 50,955,718 | 16 |
  | minisearch | 30,589 | 4,777 |
  | orama | 29,445 | 5,355 |
  | elasticlunr | 14,326 | 3,073 |
  | lunr | 11,527 | 2,443 |
  | fuse | 422 | 247,107 |

  The hardware is not stated — [FlexSearch README](https://github.com/nextapps-de/flexsearch)
- Older (0.7.x) FlexSearch docs reportedly said that enabling the contextual index raised memory from 2.9 MB to 12.5 MB, and that "the most memory-optimized meaningful setting will allocate just 1.2 Mb for the whole book indexed". I saw this only through a search-result summary, not on the page itself — [FlexSearch 0.7.31 tree](https://github.com/nextapps-de/flexsearch/tree/0.7.31)

**MiniSearch**
- The index is a radix tree. The README claims a "Memory-efficient index, designed to support memory-constrained use cases like mobile browsers" — [MiniSearch README](https://github.com/lucaong/minisearch)
- Serialization is `JSON.stringify(miniSearch)`, producing `{documentCount, nextId, documentIds, fieldIds, fieldLength, averageFieldLength, storedFields, dirtCount, index: [term, {fieldId: entry}][], serializationVersion}`. The index is stored as a flat term list, so the tree is rebuilt on load, and `loadJSON` needs the same options as the original build. `loadJSONAsync` "loads the index in batches, leaving pauses between them to avoid blocking the main thread. It tends to be slower than the synchronous version" — [MiniSearch.ts](https://github.com/lucaong/minisearch/blob/master/src/MiniSearch.ts)
- The author's 2019 claims:
  - "MiniSearch typically uses less than half of the space used by Lunr" on his apps.
  - With a radix tree, "the index size will be of the same order of dimension as the size of the collection of documents".
  - 5,000 docs × 200 chars is "roughly 2MB" as JS strings (2 bytes/char).
  - No absolute index sizes are given.

  — [Luca Ongaro blog](https://lucaongaro.eu/blog/2019/01/30/minisearch-client-side-fulltext-search-engine.html)

**lunr.js**
- John Millikin indexed *Pride and Prejudice* and *Moby Dick* (two documents; 14,060 + 21,624 lines).
  - lunr's own JSON was 1.7 MB raw, 249 KB gzip, 216 KB zstd, 192 KB brotli.
  - Compacting the inverted index brought it to 751 KB raw, 188 KB gzip, 145 KB brotli.
  - Also compacting the field vectors brought it to 741 KB raw, 137 KB gzip, 120 KB zstd, 118 KB brotli.
  - The redundancies he removed: field names repeated for every token, document refs repeated for every token, and sequential integers in the fieldVectors.

  — [Compacting Lunr search indices](https://john-millikin.com/compacting-lunr-search-indices)
- Raymond Camden found that "my pre-built index was bigger than the raw data". He also noted the cost of a second, "potentially big" network load — [raymondcamden.com](https://www.raymondcamden.com/2021/01/22/using-pre-built-lunr-indexes-with-eleventy)
- Other reports, which I saw only through search summaries and did not open:
  - A serialized lunr index of about 20 MB ([lunr issue #268](https://github.com/olivernn/lunr.js/issues/268)).
  - About 11 MB of Markdown producing about 6 MB of search data ([just-the-docs #1396](https://www.github.com/just-the-docs/just-the-docs/issues/1396)).
  - A Nuxt lunr module warning that the client must parse the JSON, which can be a problem on mobile ([nuxt lunr-module](https://github.com/nuxt-community/lunr-module)).

**elasticlunr**
- The README says: "Elasticlunr.js did not store TokenCorpus … The index size is about half size of lunr.js index file". Storing the original documents is optional (`saveDocument(false)`) and "can reduce the index size significantly". The index is saved with `JSON.stringify(idx)` and loaded with `elasticlunr.Index.load(JSON.parse(...))` — [elasticlunr README](https://github.com/weixsong/elasticlunr.js)

**Orama**
- `persist(db, format = 'binary')` supports four formats:
  - `'json'` (`JSON.stringify`)
  - `'dpack'`
  - `'binary'`: MessagePack via `@msgpack/msgpack`, then converted to a hex string with `toString('hex')` in Node or `slowHexToString` elsewhere. "binary" output is therefore text at twice the MessagePack size.
  - `'seqproto'`

  — [plugin-data-persistence/src/index.ts](https://github.com/oramasearch/orama/blob/main/packages/plugin-data-persistence/src/index.ts)

### Inferences
- None of these JS libraries gives a format a Go client could reuse. The formats are JSON object graphs tied to each library's in-memory structures, and some are not even stable across configurations: FlexSearch and MiniSearch need identical options at load time.
- A downloaded JSON index has to be fully parsed into JS objects before the first query. Memory then holds the JSON string, the parsed objects and the rebuilt tree or maps. This is why MiniSearch added `loadJSONAsync` and why the Nuxt module warns about mobile. A binary format that can be decoded lazily avoids most of this.
- Millikin's lunr numbers give two lessons. First, brotli removes most of the textual redundancy (1.7 MB → 192 KB). Second, structural compaction still saves another ~40% after compression (192 → 118 KB brotli). Compressed size depends on both the encoding and the compressor.
- FlexSearch's "terms per second" figures in the tens of millions most likely measure cached or tiny lookups. They show raw lookup cost, not end-to-end query time.

### Gaps
- I found no independent, current (2025–2026) benchmark that measures serialized index size per KB of text for FlexSearch 0.8, MiniSearch 7, Orama 3 and lunr 2.3.9 on one shared corpus. The FlexSearch table measures allocation during search, not index size.
- Byte counts for Millikin's corpus are not stated, only line counts.
- I could not get exact byte sizes for Orama's JSON, dpack and seqproto formats from any source.

## 4. tinysearch: Bloom/Xor-filter approach and sizes

### Takeaway
tinysearch began as a per-article Bloom-filter engine. Its default is now an exact, sorted vocabulary with delta- and varint-encoded posting lists, with per-article xor8 filters kept as an option. The whole index is compiled into one WASM binary. That is about 1 kB compressed per article, which limits it to small and medium sites.

### Cited Findings
- tinysearch is "a Rust/WASM port of the Python code from the article 'Writing a full-text search engine using Bloom filters'" — [tinysearch README](https://github.com/tinysearch/tinysearch), [Stavros Korokithakis' article](https://www.stavros.io/posts/bloom-filter-search-engine/)
- The current default: "By default, tinysearch stores one sorted vocabulary with exact posting lists that map each word to the articles containing it. Document IDs are delta- and varint-encoded, which keeps the index compact and compressible. Exact and prefix searches use the same index and do not introduce probabilistic false positives." — [tinysearch README](https://github.com/tinysearch/tinysearch)
- The option: "The optional `xor8` indexer creates smaller probabilistic per-article filters. It supports title prefixes, but body and metadata searches require complete words." — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Size: "The current endler.dev index with 73 posts creates an optimized WASM payload of 179 kB (83 kB gzipped, 72 kB Brotli-compressed)". That payload is the engine plus the index — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Limits:
  - "Since we bundle all search indices for all articles into one static binary, we recommend to only use it for small- to medium-size websites. Expect around 2 kB uncompressed per article (~1 kb compressed)."
  - With the default indexer, "prefix matching starts once a query term reaches three characters".

  — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Latest release is v0.11.1 (2026-09-14); v0.11.0 came out on 2026-08-14 — [tinysearch releases](https://github.com/tinysearch/tinysearch/releases)

### Inferences
- tinysearch is the closest existing match to the target's whole-download requirement. It has no per-term fetches and a single blob, and it moved from Bloom filters to exact, compressible, delta+varint posting lists. That suggests exact, compact posting lists beat probabilistic per-document filters for size and correctness once the vocabulary is shared.
- Per-document filters grow as O(docs × filter size) and must all be scanned at query time. A shared sorted vocabulary with posting lists compresses better and needs only one lookup per term.

### Gaps
- The README gives no query-latency numbers and no sizes for corpora larger than a 73-post blog.

## 5. Range-request approaches (sql.js-httpvfs, DuckDB-WASM): bytes per query and privacy

### Takeaway
Range-request engines query large static files by fetching only the pages they need: about 1 KB for a simple SQLite lookup, about 70 KiB for an FTS query against an 8 MB FTS table, and 130–270 KiB for a multi-join query. Every range they fetch, though, is visible to the server or CDN, and on a static file it maps directly to B-tree pages, and therefore to terms or row ranges. That access-pattern leakage is what the searchable-encryption literature shows can be exploited to recover queries.

### Cited Findings
- phiresky's demo database:
  - The World Development Indicators dataset, "6 tables and over 8 million rows (670 MiByte total)", with SQLite's page size set to 1 KiB.
  - A simple query "fetches only 1kB of data". An index lookup takes 7 page reads: 3 for the schema (cached), 2 for the B-tree, 2 for the table.
  - A join + aggregate query took 10–20 GET requests and 130–270 KiB.
  - Full-text search: the FTS table is "around 8 MByte" and a query "should fetch around 70 KiB".
  - Prefetch uses three separate virtual read heads, which exponentially increase request size on sequential reads. Scans therefore cost a number of requests logarithmic in the bytes scanned.

  — [phiresky blog](https://phiresky.github.io/blog/2021/hosting-sqlite-databases-on-github-pages/)
- sql.js-httpvfs README:
  - The library is read-only.
  - "There's also no cache eviction, so the more data is fetched the more RAM it will use".
  - `maxBytesToRead` caps reads per query.
  - `worker.getResetAccessedPages()` returns the pages read, and `dbstat` shows what each page contains.
  - The DB can be split into chunk files for hosts with file-size limits and for CDN caching.

  — [sql.js-httpvfs README](https://github.com/phiresky/sql.js-httpvfs)
- DuckDB-WASM:
  - It "issues paged reads". With Parquet, "we may not need to download the entire file for a query but only required bytes".
  - A remote `count(*)` "will finish in milliseconds even on remote files that are several terabytes large". Row groups can be skipped by metadata statistics.
  - Remote files need CORS headers.
  - The only timings published are TPC-H SF0.5: Q1 0.855 s vs 8.441 s for sql.js, on an unstated device.

  — [DuckDB-Wasm blog (2021)](https://duckdb.org/2021/10/29/duckdb-wasm.html)
- Cash, Grubbs, Perry and Ristenpart (CCS 2015) introduced "leakage-abuse attacks", meaning query-recovery and plaintext-recovery attacks that exploit the access-pattern and other leakage profiles of searchable encryption, given varying server prior knowledge — [IACR ePrint 2016/718](https://eprint.iacr.org/2016/718)
- Later work keeps improving query recovery from access- and search-pattern leakage by an honest-but-curious server — [Jigsaw attack, arXiv 2403.01155](https://arxiv.org/pdf/2403.01155)

### Inferences
- With sql.js-httpvfs over a public file, the host sees the (offset, length) of every range. The same `dbstat` mapping the README recommends for debugging lets an observer turn offsets into FTS5 segment and term ranges, and then into result rows.
- Encrypting the pages does not help if the file layout is deterministic. The page offsets, sizes and co-access patterns stay the same, which is the leakage profile the attacks above exploit.
- DuckDB/Parquet range reads reveal which columns and row groups were touched, for example a time range through min/max statistics.
- Range requests are therefore incompatible with the target's "server must not learn searched terms" rule unless they are combined with oblivious access (ORAM/PIR) or fully padded fetch schedules. Those approaches are out of scope here and cost much more bandwidth.
- These systems are still useful as a sizing reference. Interactive search over very large stores is possible with tens to hundreds of KiB per query. A whole download trades that for a bandwidth cost that grows with corpus size, which is why the per-repo index must be compact.

### Gaps
- I found no measurements of bytes fetched per query for DuckDB-WASM full-text search (its FTS extension) or for an FTS5 database larger than phiresky's example.
- I found no published attack targeting range-request static-site search specifically. The leakage argument above is my inference from the general SSE literature.

## 6. Partitioning when the index must be downloaded whole: what keeps mobile downloads practical, and what these tools recommend

### Takeaway
The tools partition the index four ways:
- by language (Pagefind, automatically)
- by site or bundle, merged at query time (Pagefind `mergeIndex`)
- by restricting what is indexed (Pagefind `data-pagefind-body`; lunr users indexing titles only)
- by keeping sites small (tinysearch)

None offers a time-partitioned whole-download format. The measured numbers suggest per-repo partitions should be split into immutable, cacheable segments, with a lean postings-only body index.

### Cited Findings
- Pagefind multilingual: "Indexing will then run independently for each detected language. When Pagefind initializes in the browser it will check the same `lang` attribute and load the appropriate index." `forceLanguage` opts out and builds one index for the whole site — [Pagefind multilingual docs](https://pagefind.app/docs/multilingual/)
- Pagefind multisite: `mergeIndex` adds further bundles at search time, each with `indexWeight` and `mergeFilter` — [Pagefind multisite docs](https://pagefind.app/docs/multisite/)
- Pagefind content scoping: "If `data-pagefind-body` is found anywhere on your site, any pages without this attribute will not be indexed". Individual elements can also be excluded — [Pagefind indexing docs](https://pagefind.app/docs/indexing/)
- Pagefind `--max-fragments` caps the number of fragment files "per language" by bundling fragments that are "loaded as a set when required" — [v1.6.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.6.0)
- Pagefind v1.3 made fragment filenames stable for unchanged pages, which avoids re-uploads — [v1.3.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.3.0)
- The Hugo 1M-page attempt proposed per-URL-prefix Pagefind shards, but the poster moved to custom JSON tiers — [Hugo discourse](https://discourse.gohugo.io/t/scaling-pagefind-to-over-1-million-pages/56109)
- tinysearch recommends "only … small- to medium-size websites", at about 1 kB compressed per article — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Stork 2.0 planned "multiple size-limited files that get loaded dynamically" but never shipped it — [Stork v2.0.0-alpha.3](https://github.com/jameslittle230/stork/releases/tag/v2.0.0-alpha.3)
- sql.js-httpvfs suggests splitting the DB into chunk files "if your hoster has a maximum file size" and for better CDN caching — [sql.js-httpvfs README](https://github.com/phiresky/sql.js-httpvfs)
- A lunr/Hugo user kept the index small by indexing only titles and descriptions; I saw this through a search summary — [Hugo discourse](https://discourse.gohugo.io/t/search-index-json-file-for-lunr-js/6286)

### Inferences
These inferences are for the target design and use the numbers measured in Sections 1 and 8.
- **Partition by repo (given), then by immutable time or version segments.** Each sealed segment is content-addressed and cached encrypted on the client, LSM-style. Only the newest small "head" segment changes between versions, so a returning client downloads deltas rather than the whole index. Pagefind's stable fragment hashes (v1.3) and deterministic builds (v1.6) show that stable, content-addressed outputs are what make caching and incremental upload work.
- **Partition by field or document type.** Ship a small metadata index (paths, titles, commit messages, tags) separately from the full-text body index. Download the metadata index eagerly and the body index on demand, or on Wi-Fi. The lunr titles-only practice and Pagefind's title and metadata weighting show where users find the most value per byte.
- **Budget with the measured ratios.**
  - A Pagefind-style positional index costs about 0.33–0.40× the text (brotli to gzip). 10 MB of text becomes about 3.3–4 MB to download.
  - A docID+term-frequency index costs about 0.06× the text, dictionary included. 10 MB becomes about 0.6–0.7 MB.
  - A front-coded term dictionary is about 219–235 KB brotli for 60–67k terms.

  For mobile, per-segment downloads under about 1 MB look achievable for repos with up to roughly 15 MB of text if positions are dropped.
- **Leakage.** Downloading whole partitions shows the server only which repo and segment was fetched, which it already knows as storage metadata, plus each segment's size. Padding segment sizes to buckets limits what the sizes reveal.

### Gaps
- None of the tools publishes guidance on time-based partitioning, or a mobile download budget.
- The 1 MB mobile threshold above is a judgment, not a cited figure.

## 7. Query latency and memory on mobile browsers and devices

### Takeaway
I found no controlled, published measurements of query latency or memory use on phones for any of these libraries. The evidence is limited to design claims (MiniSearch built for mobile memory limits; Pagefind moving search into a Web Worker), desktop-only microbenchmarks (FlexSearch's table) and anecdotes.

### Cited Findings
- Pagefind v1.5 moved search into a Web Worker for perceived performance on large sites. It "doesn't make the search faster, per se". It falls back to the main thread if Web Workers are unavailable — [v1.5.0 release](https://github.com/CloudCannon/pagefind/releases/tag/v1.5.0)
- Pagefind provides `debouncedSearch` (300 ms default) and `preload()`, which hide chunk-fetch latency while the user types — [Pagefind JS API docs](https://pagefind.app/docs/api/)
- MiniSearch was designed "to support memory-constrained cases like mobile apps". It offers `loadJSONAsync` so that deserializing large indexes does not block the main thread, at some cost in speed — [Luca Ongaro blog](https://lucaongaro.eu/blog/2019/01/30/minisearch-client-side-fulltext-search-engine.html), [MiniSearch.ts](https://github.com/lucaong/minisearch/blob/master/src/MiniSearch.ts)
- FlexSearch's benchmark gives these single-term query rates per second: MiniSearch 30,589 (about 33 µs per query), Orama 29,445, elasticlunr 14,326, lunr 11,527, Fuse 422. These are desktop microbenchmarks by the FlexSearch maintainer; the device is not stated — [FlexSearch README](https://github.com/nextapps-de/flexsearch)
- A Hugo forum thread reports Pagefind stuck on "searching for…" on one user's phone but working on another commenter's Android. This is a bug report, not a performance measurement — [Hugo discourse](https://discourse.gohugo.io/t/pagefind-on-mobile/50429)
- sql.js-httpvfs has no cache eviction, so its RAM grows with the bytes fetched — [sql.js-httpvfs README](https://github.com/phiresky/sql.js-httpvfs)

### Inferences
- For whole-download indexes, the costs on a phone are likely, in order: (1) the download (MB over cellular); (2) decrypting and decompressing (linear in size); (3) parsing or decoding into memory (largest for JSON formats); and (4) the query itself, which is microseconds to milliseconds for in-memory indexes. Shrinking the index (Sections 1 and 8) therefore helps on every axis. Keeping postings compressed in memory and decoding them per term, as Pagefind's WASM does per chunk, keeps the heap small.
- These libraries say nothing about a pure-Go WASM worker or gomobile client. Their numbers come from JS and Rust/WASM engines, so Go-side latency and memory would have to be measured directly.

### Gaps
- There are no device-specific latency or memory numbers (e.g., a mid-range Android phone, iPhone Safari) for Pagefind, MiniSearch, FlexSearch, lunr, Orama or tinysearch in any source I found.
- There are no measurements of a Go (WASM or gomobile) search client's memory or decode time.

## 8. Lessons for an encrypted index that a client downloads in full

### Takeaway
Most of what makes the existing tools small is fetching a subset on demand, which the target system cannot use because it leaks query terms. A whole-download index has to get its size from the encoding instead. Re-encoding Pagefind's own MDN and Godot indexes (measured) gives these sizes relative to the raw text, brotli-compressed:
- keeping positions: about 30%
- keeping only docIDs and term frequencies: about 6%
- docIDs only: about 4–5%
- the front-coded term dictionary alone: about 220–235 KB

### Cited Findings
**Re-encoding experiment (measured, 2026-11-05)**

Method: I decoded every downloaded Pagefind chunk, rebuilt a sorted term list, and wrote four layouts. The term dictionary is front-coded (shared-prefix length + suffix). Postings are varint per page, delta docIDs as in Pagefind 1.5, with either the full position lists, term frequency (count of real occurrences) or nothing.

| Layout | MDN raw / gzip-9 / brotli-11 / zstd-19 | MDN ÷ text (brotli) | Godot raw / gzip-9 / brotli-11 / zstd-19 | Godot ÷ text (brotli) |
|---|---|---|---|---|
| Pagefind as served (per-chunk gzip) | 24.04 MB raw → 12.28 MB gz | 0.39 (gz) | 7.82 MB raw → 4.37 MB gz | 0.39 (gz) |
| Positions kept, varint + front-coded dictionary | 15.29 / 10.54 / 9.53 / 9.79 MB | 0.304 | 5.01 / 3.71 / 3.26 / 3.38 MB | 0.292 |
| DocID + term frequency | 4.56 / 2.38 / 1.99 / 2.13 MB | 0.063 | 1.53 / 0.84 / 0.69 / 0.73 MB | 0.062 |
| DocID only | 2.69 / 1.58 / 1.35 / 1.44 MB | 0.043 | 1.13 / 0.63 / 0.53 / 0.55 MB | 0.047 |
| Term dictionary only (66,716 / 60,443 terms) | 488 / 254 / 219 / 229 KB | 0.007 | 589 / 279 / 235 / 244 KB | 0.021 |

— source data: [MDN Pagefind bundle](https://mdn.pagefind.app/pagefind/pagefind-entry.json), [Godot Pagefind bundle](https://godot.pagefind.app/pagefind/pagefind-entry.json)

Further measured observations:
- Brotli-11 beat zstd-19 (long mode) and gzip-9 on every layout. The same was true of Millikin's lunr JSON: 192 KB brotli vs 216 KB zstd vs 249 KB gzip — [MDN Pagefind bundle](https://mdn.pagefind.app/), [Compacting Lunr search indices](https://john-millikin.com/compacting-lunr-search-indices)
- Snippet and excerpt storage roughly doubles the download if it is shipped with the index:
  - Pagefind's fragments total about 0.37–0.67× the text, gzipped (MDN 15.4 MB, against 12.4 MB of word index).
  - Stork stores full contents inside the index: 4.79× the text raw, 1.38× after brotli.

  — [MDN Pagefind bundle](https://mdn.pagefind.app/), [federalist.st](https://files.stork-search.net/federalist.st)
- Pagefind's only per-page table (`pf_meta`: page hash + word count) costs 7.3–8.9 B gzipped per page — [MDN Pagefind bundle](https://mdn.pagefind.app/)
- tinysearch moved from per-article Bloom filters to "exact posting lists … delta- and varint-encoded" for compactness and no false positives — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Elasticlunr dropped stored token vectors to halve lunr's size, and Millikin removed repeated field names and doc refs for a further ~40% after compression. Both show that per-posting redundancy, not raw term text, is what inflates JSON indexes — [elasticlunr README](https://github.com/weixsong/elasticlunr.js), [Compacting Lunr search indices](https://john-millikin.com/compacting-lunr-search-indices)

### Inferences
1. **Drop positions from the downloaded index by default.** Positions are about 80% of the bytes (9.53 MB vs 1.99 MB brotli on MDN). Phrase queries and snippets can instead be checked against the candidate documents, which the client decrypts locally. If phrase search must be fast, ship positions only for a small, recent "head" partition.
2. **Use a simple binary layout that is easy to implement in Go.** A sorted, front-coded term dictionary, delta+varint docIDs, a 1-byte-or-varint term frequency, and per-document lengths for BM25. Then compress the whole segment as one block with brotli or zstd before encrypting, since encryption removes all compressibility and compression must come first. Whole-blob compression beat per-chunk gzip by about 15% on MDN. This mirrors Pagefind's and tinysearch's postings, minus the chunking.
3. **Keep snippets, excerpts and stored fields out of the index.** Stork's 4.8× index and Pagefind's fragment files show how much they cost. Snippets can be produced from the documents themselves after the client downloads or decrypts them.
4. **Plan the per-document table.** BM25 needs document lengths. Pagefind's per-page table costs about 7–9 B/page gzipped, and a varint docLength table would be smaller. Put it in the same segment blob so there is no separate "meta" fetch.
5. **Partition for caching, not for term lookup.** Immutable, content-addressed time or version segments per repo, plus a small mutable head segment, with periodic merges. A client re-downloads only new segments. The server learns which segments a client holds, but never which terms it searches.
6. **Avoid JSON on phones.** JSON indexes (lunr, MiniSearch, Orama `json`, FlexSearch export) must be fully materialized on load, and Orama's "binary" is hex text at twice the size. A binary segment can be memory-mapped or decoded on demand: the dictionary is binary-searchable, and posting lists are decoded only for query terms.
7. **Budget.** With docID+tf, roughly 63–65 B per KB of text, dictionary included, a repo with 10 MB of text needs about 0.6–0.7 MB to download. One with 100 MB needs roughly 6 MB, because the dictionary grows sublinearly (Heaps' law) and its share shrinks. With positions, the same repos need about 3–4 MB and 30–40 MB.

### Gaps
- The re-encoding experiment did not include block-level postings compression (e.g., PForDelta/Roaring), skip lists or per-field postings. Its numbers are an upper bound on what a tuned Go format could reach.
- I measured only English documentation (MDN, Godot) and comics transcripts (XKCD). Code-heavy repos, logs or CJK text may have very different vocabularies and dictionary-to-postings ratios.
- I found no data on how AES-GCM or ChaCha20-Poly1305 decryption plus brotli or zstd decompression of multi-MB segments performs in Go WASM or gomobile on phones. This needs direct measurement.
