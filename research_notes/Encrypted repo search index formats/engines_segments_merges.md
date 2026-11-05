# Full-text engines: on-disk segment formats, segment merges, deletes, size and speed, and pure-Go options (for an E2EE client-side index)

Checked 2026-11-05. Versions examined:
- Lucene 10.6.0, released 2026-10-30. Codec docs were read from the main-branch `lucene104` sources.
- Tantivy 0.26.1 release (main branch is 0.27.0).
- Bleve v2.6.3 (2026-11-04). Its default segment format is zapx v17.2.5.
- Bluge v0.2.2 (2022-07-04), with ice v1.0.0 and v2.0.1.
- modernc.org/sqlite v1.61.1 and ncruces/go-sqlite3 v0.36.0. Both embed SQLite 3.54.1.
- Xapian 1.4 docs.

**Local measurements** ("local run" below):
- Environment: Go 1.27.3 on an Apple M1 Max (10 cores), macOS 27.2.
- Corpus: 20 Newsgroups "bydate" ([dataset](http://qwone.com/~jason/20Newsgroups/)). It holds 18,846 email-like posts with headers, 35,854,963 bytes in total, 1,902 B per doc on average.
- Indexing: unless stated otherwise, each index was built in one batch or transaction, giving one segment.
- Binaries: built with `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`. "base" is the same benchmark harness with no engine (fmt/os/filepath/sha256), so a size delta measures the engine alone.
- Latency: warm averages over 30 runs.
- Raw outputs: [run_exp.zsh](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/run_exp.zsh), [exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log) and [followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log). They are in the session scratchpad and may be deleted, so every number these notes rely on is copied below.

## Lucene: segment file formats, live-docs deletion bitmaps, TieredMergePolicy, and typical index size

### Takeaway
A Lucene 10.x segment is a write-once set of per-format files:
- a block-tree terms dictionary, whose index has been a trie rather than an FST since 10.3;
- packed postings blocks, 256 docs per block since 10.4;
- norms, doc values, and stored fields compressed with LZ4 or DEFLATE.

Deletes are a separate, optional, generation-numbered `.liv` bitset per segment. TieredMergePolicy (8 segments per tier, 16 MB floor, 5 GB maximum, 20% deletes allowed) keeps the segment count small. Lucene claims an index is "roughly 20-30% the size of text indexed". Every file carries a 16-byte random/unique ID and the `.si` file carries diagnostics, so Lucene segments are not byte-reproducible by design.

### Cited Findings
- The latest release is Lucene 10.6.0, published 2026-10-30. — [apache/lucene release](https://github.com/apache/lucene/releases/tag/releases/lucene/10.6.0)
- Homepage claims: "index size roughly 20-30% the size of text indexed"; indexing "over 800GB/hour on modern hardware"; "small RAM requirements -- only 1MB heap"; "incremental indexing as fast as batch indexing". — [Lucene core homepage](https://lucene.apache.org/core/)
- **Per-segment file types:**
  - `.si` segment info; `.cfs`/`.cfe` optional compound file; `.fnm` fields;
  - `.fdx`/`.fdt` stored fields; `.tim`/`.tip` terms dictionary and terms index;
  - `.doc` docs and freqs; `.pos` positions; `.pay` payloads and offsets;
  - `.nvd`/`.nvm` norms; `.dvd`/`.dvm` doc values; `.tvx`/`.tvd` term vectors;
  - `.liv` live docs; `.kdd`/`.kdi`/`.kdm` points; `.vec`/`.vem`/`.veq`/`.vex` vectors.
  - Index-level files are `segments_N` (the commit point) and `write.lock`. — [lucene104 package-info](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene104/package-info.java)
- **File naming and commits:**
  - "File names are never re-used."
  - Commit points are `segments_1`, `segments_2`, ..., with generations written in base 36.
  - Since 4.8, the last 8 bytes of every file are a zlib-crc32 checksum.
  - Deleted docs leave gaps in doc numbering, and "Deleted documents are dropped when segments are merged".
  - Doc numbers are Int32. — [lucene104 package-info](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene104/package-info.java)
- **Format changes in 10.x:**
  - 10.1 optimized block encoding for `int[]` instead of `long[]`.
  - 10.3: the block tree index "switched from an FST to a specialized trie".
  - 10.4 raised the postings block size from 128 to 256, with skip pointers every 256 and 8,192 postings instead of every 128 and 4,096. — [lucene104 package-info](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene104/package-info.java)
- **Lucene104PostingsFormat:**
  - It "encodes postings in packed integer blocks for fast decode", with a fixed block size of 256.
  - Doc-delta blocks are not patched; frequency blocks use patching (PFOR-style); blocks where every value is the same are encoded specially.
  - The tail goes into VInt blocks.
  - Positions are stored in `.pos`, payloads and offsets in `.pay`.
  - Level-0 skip data sits between every packed block; level-1 skip data sits every 32 blocks.
  - Impacts (CompetitiveFreqDelta/NormDelta) let the reader skip non-competitive documents.
  - Small metadata goes in `.psm`; the term dictionary is a block tree (`.tim`) with a `.tip` index. — [Lucene104PostingsFormat.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene104/Lucene104PostingsFormat.java)
- Lucene encodes dense postings blocks as bit sets. This is one reason Lucene beats Tantivy and PISA on some disjunctive COUNT queries. — [jpountz, analysis of Search Benchmark the Game (2025)](https://jpountz.github.io/2025/05/12/analysis-of-Search-Benchmark-the-Game.html)
- Stored fields are compressed with LZ4 "by default in 8KB blocks and shared dictionaries" (BEST_SPEED), or with DEFLATE "with 48KB blocks and shared dictionaries" (BEST_COMPRESSION). — [Lucene90StoredFieldsFormat.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene90/Lucene90StoredFieldsFormat.java)
- Norms encode each value "with the minimum number of bytes needed". — [Lucene90NormsFormat.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene90/Lucene90NormsFormat.java)
- Live docs: "The .liv file is optional, and only exists when a segment contains deletions". Its layout is `Deletions (.liv) --> IndexHeader,Generation,Bits`, where Bits is a sequence of Int64 words (a plain bitset). — [Lucene90LiveDocsFormat.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene90/Lucene90LiveDocsFormat.java)
- **Non-determinism by design:**
  - `.si` = Header, SegVersion, SegSize, IsCompoundFile, Diagnostics, Files, Attributes, IndexSort, Footer. — [Lucene99SegmentInfoFormat.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene99/Lucene99SegmentInfoFormat.java)
  - Every file's `IndexHeader` = CodecHeader, ObjectID (16 bytes), ObjectSuffix; `id` is documented as a "Unique identifier for this particular file instance". — [CodecUtil.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/CodecUtil.java)
- **TieredMergePolicy defaults:**

  | Setting | Default |
  |---|---|
  | maxMergedSegment | 5 GB |
  | floorSegment | 16 MB |
  | segsPerTier | 8.0 |
  | maxMergeAtOnce | no longer exists; mergeFactor = (int) segsPerTier |
  | deletesPctAllowed | 20.0 |
  | forceMergeDeletesPctAllowed | 10.0 |
  | targetSearchConcurrency | 1 |

  The javadoc says it "Merges segments of approximately equal size, subject to an allowed number of segments per tier" and favors merges with "lower skew, smaller size and those reclaiming more deletes". Segments under the floor are "rounded up" to it, which "helps prevent frequent flushing of tiny segments to create a long tail of small segments". — [TieredMergePolicy.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/index/TieredMergePolicy.java)
- IndexWriterConfig defaults: `DEFAULT_RAM_BUFFER_SIZE_MB = 16.0`; `DEFAULT_MAX_FULL_FLUSH_MERGE_WAIT_MILLIS = 500`, which is how long a commit or refresh waits for merges of the segments it just flushed. — [IndexWriterConfig.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/index/IndexWriterConfig.java)

### Inferences
- **The model fits an append-only store:**
  - immutable per-segment objects plus a small commit-point list (`segments_N`);
  - deletes as a new bitset generation rather than a segment rewrite;
  - "never reuse file names", which suits content-addressed encrypted blobs.
- **What breaks reproducibility:** the 16-byte per-file IDs and the `.si` diagnostics. An encrypted-repo design that wants identical bytes from any client would have to drop them.
- **No pure-Go Lucene exists**, so Lucene is a format to imitate, not a dependency.
- **The 20–30% claim is old and almost certainly excludes stored fields.** Positions and stored fields dominate real index size; the Bleve, Bluge and FTS5 measurements below show positions alone costing 2.7–3.3x.
- **State of the art for postings:** FOR blocks (256 docs) with PFOR only for freqs, bitsets for dense blocks, and a trie/FST terms index pointing into blocked term dictionaries. A minimal Go codec can copy this layout.

### Gaps
- I did not run Lucene on the test corpus, so there is no same-corpus index size or latency. Lucene's 20–30% is a homepage claim, not a measurement.
- I found no figure for the minimum bytes per segment: the header (codec name + 16-byte ID + suffix) and the checksum footer repeat in every file, and the total across a tiny segment's 10+ files was not measured.
- I did not read the `.liv` generation file naming (`_N_gen.liv`) from source.

## Tantivy: segment format, merge policy, deletes, size and performance

### Takeaway
Tantivy follows Lucene closely:
- Segments are immutable and named by UUID; a commit writes one segment per indexing thread, and `meta.json` lists them.
- Terms are in an FST; postings are bitpacked blocks of 128 docs; fieldnorms take 1 byte per doc.
- The doc store is LZ4 (or zstd) in 16 KB blocks.
- Deletes are immutable alive-bitset files named `segment.opstamp.del`.
- LogMergePolicy merges a log-size level once it holds 8 segments, with a 10k-doc floor.

Tantivy is not usable from pure Go: tantivy-go is cgo plus a Rust static library. I found no reliable published index-size or MB/s numbers for it.

### Cited Findings
- **Segments:** "A tantivy index is a collection of smaller independent immutable segments."
  - Segment IDs are UUIDs, and files are named "segment-id . ext".
  - `meta.json` tracks the segment list and the schema, and is updated atomically on commit.
  - A commit writes one segment per indexing thread.
  - DocIds are `[0, max_doc)` in insertion order; `max_doc` counts deleted docs. — [Tantivy ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)
- **Components:**
  - postings file: a TermInfo holds an offset and a doc count;
  - positions in `.pos`;
  - term dictionary: an FST (`fst` crate) mapping Term to TermOrdinal, plus a term-info store;
  - fast fields: column-oriented, with bitpacking as the only compression;
  - fieldnorms: one byte per doc, values ≤40 exact;
  - doc store: row-oriented, "compressed using a general-purpose algorithm like LZ4". — [ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)
- **Postings:** blocks of 128 documents. Each block of delta-encoded, bitpacked doc IDs is followed by a block of bitpacked term frequencies. The last block (1–127 docs) uses variable-int encoding. — [ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)
- **Deletes:**
  - A delete targets a term.
  - On commit, Tantivy updates the alive bitset of each affected segment. The files are immutable and named "segment_id.commit_opstamp.del", so several can coexist.
  - Merges remove tombstoned docs.
  - A Searcher holds a stable snapshot of segment readers. — [ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)
- **LogMergePolicy:**
  - Defaults: `DEFAULT_LEVEL_LOG_SIZE` 0.75, `DEFAULT_MIN_LAYER_SIZE` 10,000, `DEFAULT_MIN_NUM_SEGMENTS_IN_MERGE` 8, `DEFAULT_MAX_DOCS_BEFORE_MERGE` 10,000,000, `DEFAULT_DEL_DOCS_RATIO_BEFORE_MERGE` 1.0. The default of 1.0 means deletes are not considered.
  - Algorithm: segments are grouped into levels by log2(max(10k, num_docs)). A level becomes one merge once it has ≥8 segments, or once any segment in it exceeds the deletes ratio. — [log_merge_policy.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/indexer/log_merge_policy.rs)
- `SegmentId` is created with `Uuid::new_v4()` (random). An alternative cfg uses an auto-incremented ID. — [segment_id.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/index/segment_id.rs)
- Doc store: the default compressor is LZ4 block (zstd behind a feature flag). The buffer is compressed when it exceeds `block_size` ("defaults to 16K"), and a skip list locates blocks. — [compressors.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/store/compressors.rs), [store/mod.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/store/mod.rs)
- Index writer: `MEMORY_BUDGET_NUM_BYTES_MIN` = 15 × 1,000,000 bytes and `MAX_NUM_THREAD` = 8. — [index_writer.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/indexer/index_writer.rs)
- Activity: release 0.26.1 (2026-05-10); main `Cargo.toml` says 0.27.0; 16,401 stars; pushed 2026-11-02. — [GitHub API](https://api.github.com/repos/quickwit-oss/tantivy), [Cargo.toml](https://github.com/quickwit-oss/tantivy/blob/main/Cargo.toml)
- **Benchmarks:**
  - The public "Search Benchmark, the Game" currently compares Lucene and Tantivy, using English Wikipedia (~6M docs) and AOL queries.
  - jpountz's 2025 analysis covers Lucene 10.2.0 and PISA 0.8.2. Lucene wins on long queries (block-max MAXSCORE vs WAND) and on some disjunctive COUNT queries (dense blocks as bitsets).
  - "The benchmark does not report index size or indexing time." — [jpountz 2025](https://jpountz.github.io/2025/05/12/analysis-of-Search-Benchmark-the-Game.html), [search-benchmark-game](https://github.com/quickwit-oss/search-benchmark-game)
- **tantivy-go (Anytype):**
  - Build: Rust builds a static `libtantivy_go.a` for each architecture.
  - Production use in Anytype "across all major platforms", including iOS, Android and desktop.
  - The README says Bleve is "surprisingly slow compared to Tantivy", but gives no numbers.
  - The Jieba tokenizer is included by default; building without it saves "approximately 5MB".
  - WebAssembly is not mentioned.
  - Latest version v1.0.6 (2026-01-06). — [tantivy-go README](https://github.com/anyproto/tantivy-go), [GitHub API](https://api.github.com/repos/anyproto/tantivy-go)

### Inferences
- **Design reference for per-commit deltas:** UUID-named per-commit segments plus per-opstamp `.del` files map almost one-to-one onto "one encrypted delta object per commit, plus tombstone-bitset objects".
- **Not a Go dependency:** cgo and a Rust static library are needed for each gomobile target, and there is no js/wasm path through Go.
- **Not reproducible as configured:** the random UUID names mean identical bytes would at least need the UUIDs normalized.

### Gaps
- I found no reliable published Tantivy index-size ratio or indexing MB/s. The only throughput number was an informal Hacker News commenter's arithmetic (~11 MB/s per core for Quickwit 0.8), which I treat as unreliable — [HN thread](https://hn.jakechampion.name/item/39756367).
- I did not run Tantivy locally.
- Whether segment *contents*, ignoring the UUID names, are byte-identical across runs was not verified.

## Bleve (Go): scorch, the zap segment format (versions), vellum FST and roaring, the merge planner, size and speed vs Lucene, binary size, js/wasm and gomobile

### Takeaway
Bleve v2.6.3's Scorch engine uses this architecture:
- **Segments:** immutable zap files. The default writer is zapx v17; readers for v11–v16 are compiled in too.
- **Inside a segment:** a vellum FST dictionary per field, roaring-bitmap postings, chunked freq/norm/location streams, and snappy-compressed stored fields.
- **Deletes and state:** per-segment deleted bitmaps live in snapshots that are persisted to a bbolt `root.bolt`.
- **Merging:** a planner "inspired by Lucene's TieredMergePolicy" that measures segments in doc counts.

On the 36 MB email-like corpus (local run):
- Indexing ran at 7–22 MB/s on 10 cores.
- Index size was 50% of raw text without positions, 136% with term vectors, and 376% with the default mapping.
- Single-term queries took 14–900 µs.
- It adds 12.4–13.4 MB to a stripped Go binary.
- It compiles for iOS and Android but does not build for js/wasm, because of bbolt and mmap-go.
- Its segment bytes differ from run to run.

### Cited Findings
- **Versions and activity:**
  - bleve v2.6.3 (2026-11-04); zapx/v17 v17.2.5 (2026-11-04); zapx/v16 v16.3.4 (2026-04-16); vellum v1.2.1 (2026-11-02).
  - Bleve requires roaring/v2 v2.14.5 (the latest is v2.30.0), bbolt v1.4.0 and mmap-go v1.2.0.
  - Repo: 11,251 stars, 303 open issues, pushed 2026-11-04. — [proxy.golang.org (go list -m)](https://proxy.golang.org/github.com/blevesearch/bleve/v2/@latest), [GitHub API](https://api.github.com/repos/blevesearch/bleve), [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Zap versions:** zapx v17 is registered as the default segment plugin. v16, v15, v14, v13, v12 and v11 are registered too, so all seven versions are compiled in for reading. — [segment_plugin.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/segment_plugin.go)
- **Zap layout (v17 `zap.md`):** a file has these sections:
  - Inverted Text Index Section, Vector Index Section (Faiss), Synonym Index Section;
  - Sections Info and Sections Index;
  - a footer carrying, among other fields, the version V, the chunk factor and the CRC.
  - In the inverted index, "the dictionary is encoded in Vellum format" as (term, offset-of-postings) pairs, followed by Freq/Norm (chunked) and Location Details (chunked). — [zapx zap.md](https://github.com/blevesearch/zapx/blob/master/zap.md)
- **zapx README:**
  - It is a fork of zap that "removes dependency on bleve", depending only on `bleve_index_api` and `scorch_segment_api`.
  - The file is written in reverse order of access, so it can be written in one pass.
  - Readers "mmap the entire file"; the crc-32 and version sit at a fixed position at the end.
  - The footer gives the docValue, fields-index and stored-data-index offsets, plus numDocs and the chunk factor.
  - Stored fields: "compress the data slice using snappy".
  - Freq/norm and location data are chunked, so a reader can "jump to the correct chunk (docNum/chunkFactor)".
  - Doc values are chunks of "compressed columnar field data". — [zapx README](https://github.com/blevesearch/zapx/blob/master/README.md)
- **Scorch:**
  - A `SegmentSnapshot` holds a segment plus a `deleted` postings list. An `IndexSnapshot` is a list of SegmentSnapshots.
  - Every batch builds, for each existing segment, "a per-segment bitset which tells us which documents in that segment are obsoleted by the addition of the new segment", and ORs it into that segment's deleted list.
  - Readers hold a pointer to an immutable IndexSnapshot. — [scorch README](https://github.com/blevesearch/bleve/blob/master/index/scorch/README.md)
- Persistence uses bbolt: `persister.go`, `rollback.go` and `scorch.go` import it. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Merge planner:**
  - It is "inspired by Lucene's TieredMergePolicy.java".
  - Defaults: MaxSegmentsPerTier 10, MaxSegmentSize 5,000,000 (docs), MaxSegmentFileSize 4 GiB, TierGrowth 10.0, SegmentsPerMergeTask 10, FloorSegmentSize 2000, ReclaimDeletesWeight 2.0.
  - The budget is computed with a logarithmic "staircase" (`CalcBudget`).
  - A segment's planning size is `FullSize() = segment.Count()`, its doc count. — [merge_plan.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/mergeplan/merge_plan.go), [snapshot_segment.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/snapshot_segment.go)
  - Scorch exposes `ForceMerge(ctx, *MergePlanOptions)`; options are set through the `scorchMergePlanOptions` config key. — [merge.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/merge.go)
- **Size, speed and memory (local run):** one batch → one zap segment, M1 Max, 10 cores. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)

  | Bleve v2.6.3 mapping | Index bytes | % of raw | Index MB/s | Peak RSS |
  |---|---|---|---|---|
  | default (dynamic: stored + docvalues + term vectors + `_all`) | 134,955,884 | 376.4% | 7.24 | 2.90 GB |
  | "lean" (body indexed with term vectors; no store, docvalues or `_all`) | 48,827,348 | 136.2% | 16.5 | 1.45 GB |
  | "nopos" (lean without term vectors, so no phrase search) | 18,101,231 | 50.5% | 22.0 | 0.79 GB |

  Every index also contains a fixed 262,144-byte `root.bolt` and a 42-byte `index_meta.json`.

- **Throughput depends on parallel analysis (local run):** "nopos" indexed at 10.18 MB/s with GOMAXPROCS=1 and 21.42 MB/s with GOMAXPROCS=10. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Query latency (local run)**, top-10 by score plus total hits, single segment:

  | Query (hits) | default | lean | nopos |
  |---|---|---|---|
  | "subject" (18,846) | 911 µs | 907 µs | 913 µs |
  | "computer" (2,505) | 134 µs | 131 µs | 129 µs |
  | "encryption" (424) | 27 µs | 31 µs | 25 µs |
  | "shuttle" (180) | 13 µs | 14 µs | 13 µs |
  | phrase "space shuttle" (60) | 253 µs | 246 µs | returns 0 hits with `err=nil` (no positions) |

  — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Binary size (local run)**, stripped, compared with the base harness:
  - bleve: darwin/arm64 14,227,282 B (+12.39 MB); android/arm64 15,401,254 B (+13.37 MB); gzip -9 5.38 MB.
  - zapx/v16 alone, with Open/New/Merge referenced: darwin 2,595,794 B (+0.75 MB); android 2,883,878 B (+0.85 MB).
  - vellum + roaring alone: +0.19 MB darwin, +0.33 MB android, +0.25 MB js/wasm. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **js/wasm build fails (local run):**
  - bleve: `go.etcd.io/bbolt@v1.4.0 ... undefined: syscall.Flock` and `undefined array length maxMapSize`.
  - zapx alone: `blevesearch/mmap-go ... undefined: mmap`.
  - mmap-go v1.2.0's `mmap_unix.go` is built only for `darwin || dragonfly || freebsd || linux || openbsd || solaris || netbsd`. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log), [blevesearch/mmap-go](https://github.com/blevesearch/mmap-go)
- **gomobile targets (local run):**
  - `GOOS=ios GOARCH=arm64 go build github.com/blevesearch/bleve/v2` compiles.
  - Linking an iOS executable requires cgo ("ios/arm64 requires external (cgo) linking"), which gomobile provides.
  - android/arm64 builds and links with CGO_ENABLED=0. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Not deterministic (local run):**
  - Three builds of the same corpus ("nopos": the first, GOMAXPROCS=1, GOMAXPROCS=10) produced zap files of the same size (17,839,045 B) with three different SHA-256 hashes.
  - Two "lean" builds differed by 7 bytes (48,565,162 vs 48,565,169).
  - Likely causes in source: `Batch.IndexOps` is a `map[string]Document` (Go randomizes map iteration order), and scorch stores analysis results in channel-completion order (`analysisResults[itemsDeQueued] = result`). — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log), [bleve_index_api batch.go](https://github.com/blevesearch/bleve_index_api/blob/master/batch.go), [scorch.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/scorch.go)
- **Deletes are bitmaps (local run):** deleting one doc left the zap file byte-identical (hash `c51b9ed62912` before and after); only `root.bolt` changed. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Compressibility (local run):** the "nopos" zap compresses from 17.8 MB to 10.8 MB with gzip -9 (60.7%) and 9.1 MB with zstd -19 (51.1%), i.e. 25.4% of raw text. The "lean" zap gzips to 69.2%. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- I found no published Bleve-vs-Lucene comparison of index size or speed. The only published Bleve performance claim found is tantivy-go's qualitative "surprisingly slow". — [tantivy-go README](https://github.com/anyproto/tantivy-go)

### Inferences
- **Default mapping:** it is about 7.5x the size of the no-positions index. A client-side design must explicitly turn off store, docvalues and `_all`, and decide whether phrase search is worth 2.7x the bytes. Bleve's term vectors also store offsets and array positions, which makes them much heavier than FTS5's positions: 136% vs 45% of raw.
- **What could be reused:** the format, not the engine.
  - zapx alone adds about 0.75 MB, versus 12.4 MB for the whole of bleve (the full analyzer registry plus seven zap versions).
  - zapx assumes mmap, so a js/wasm build needs a fork that loads segments from `[]byte`.
  - Scorch's bbolt root, file locking and fsync-per-batch persistence do not match an object store of encrypted deltas.
- **Determinism:** probably fixable by building from a deterministically ordered doc slice (for example, sorted by ID) instead of from a map. This is unverified.
- **Mobile memory:** peak RSS of 0.8–2.9 GB to index a single 36 MB batch means batches must be kept small on mobile and wasm (wasm32 has a 4 GB address space).

### Gaps
- There is no same-hardware, same-corpus Bleve-vs-Lucene measurement; I did not run a JVM, and published comparisons were not found.
- Untested: whether `zapx.New` gives byte-identical output for a fixed doc order.
- No GitHub issue specifically about bleve on js/wasm or gomobile turned up in search. The js/wasm failure is established by the local build only.

## Bluge (Go): the ice segment format, its relationship to Bleve, and maintenance status

### Takeaway
Bluge v0.2.2 is a Bleve-lineage library. Its ice segment format is described in the same terms as zap: footer at the end, chunk factor, chunked freq/norm and location streams, snappy stored fields. Its .seg files came out byte-identical across runs in my tests. It is smaller than Bleve (+2.9 MB) but slower on term queries (about 2.5x), does not build for js/wasm, and has been dormant since July 2022. Its last commit reverted the default to ice v1 because "ice v2 has several issues". ZincSearch now depends on community forks of ice (vcaesar/*).

### Cited Findings
- Versions: bluge v0.2.2 (2022-07-04); ice v1.0.0 and ice/v2 v2.0.1 (both 2022-05-26). — [proxy.golang.org (go list -m)](https://proxy.golang.org/github.com/blugelabs/bluge/@latest), [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Maintenance:**
  - The last default-branch commit is dated 2022-07-04: "switch the default back to ice v1 (#124) ice v2 has several issues at the moment, we should not default to using it at this time". The commit before it was "update ice v2 to fix merge crash (#120)".
  - The repo is not archived; it has 2,036 stars and 67 open issues; `pushed_at` is 2026-01-25, but that push is not on the default branch.
  - ice was last pushed 2022-07-04. — [bluge commits](https://github.com/blugelabs/bluge/commits/master), [GitHub API bluge](https://api.github.com/repos/blugelabs/bluge), [GitHub API ice](https://api.github.com/repos/blugelabs/ice)
- **Relationship to Bleve:**
  - Bluge depends on blevesearch/vellum v1.0.7, blevesearch/segment, blevesearch/mmap-go v1.0.4 and RoaringBitmap/roaring v0.9.4. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
  - The ice README repeats zap's description: "crc-32 bytes and version are in fixed position at the end of the file", footer with "number of docs and chunk factor", stored fields "compress the data slice using snappy", freq/norm and location sections chunked "(docNum/chunkFactor)", and the norm factor stored as a float32. — [ice README](https://github.com/blugelabs/ice/blob/master/README.md)
- **Size, speed and memory (local run):**

  | Bluge v0.2.2 | Index bytes | % of raw | Index MB/s | Peak RSS |
  |---|---|---|---|---|
  | with positions (`SearchTermPositions`) | 63,302,931 | 176.6% | 10.9 | 2.0–2.4 GB |
  | without positions | 21,089,730 | 58.8% | 14.7 | 1.24 GB |

  Latencies with positions: "computer" 333 µs, "subject" 2,458 µs, "encryption" 58 µs, phrase "space shuttle" 188 µs. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Deterministic in tests (local run):**
  - The no-positions .seg file was byte-identical across three builds, including GOMAXPROCS=1 vs 10 (hash `d99f56be6f77`, 21,089,714 B).
  - The with-positions .seg was identical across two builds (`111051ce239b`).
  - The number of 16-byte `.snp` snapshot files varied from run to run. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Compressibility (local run):** the no-positions .seg compresses to 61.4% with gzip -9 and 48.3% with zstd -19 (28.4% of raw text). The with-positions .seg gzips to 72.2%. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Tiny segment (local run):** a 1-doc, 4-token segment is 421 B, plus one or two 16-byte `.snp` files. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Binary size and targets (local run):**
  - darwin/arm64 4,762,402 B (+2.92 MB); android/arm64 5,308,710 B (+3.28 MB).
  - js/wasm fails in mmap-go and in bluge's `index/lock` ("undefined: open").
  - The iOS library compiles. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)

### Inferences
- **Determinism and size:** ice is the only Bleve-lineage format that rebuilt byte-for-byte here, and it is about 4x smaller in binary terms than bleve.
- **Risk:** it is unmaintained (ice v2 reverted for bugs, nothing since 2022) and still assumes mmap and file locks. Adopting it means vendoring and owning the format.
- **A frozen format cuts both ways:** it is stable for a long-lived encrypted wire format, but you get no upstream fixes.

### Gaps
- I did not read Bluge's own README statement on its relationship to Bleve; the grep of its README found no "bleve" mention. The lineage claim rests on shared dependencies and the identical format description.
- Bluge deletes and merges were not tested locally. They presumably follow scorch, but that is not verified.

## SQLite FTS5: the segment b-tree, incremental merges (automerge, crisismerge), prefix indexes, detail=none/column/full sizes, and pure-Go availability and binary size

### Takeaway
FTS5 keeps each segment as a b-tree of ~4 KB leaf blobs in `%_data`, with a `%_idx` "remainder" index. It merges incrementally by level: automerge 4, crisismerge 16, usermerge 4, deletemerge 10%. It supports prefix indexes, three detail levels, delete markers, tombstones (`contentless_delete`, 3.43.0) and in-place `secure-delete` (3.42.0).

On the 36 MB corpus (local run):
- Index size was 45% of raw text with detail=full, 31% with column and 13.6% with none; prefix='2 3' roughly doubled it.
- It indexed at 25–34 MB/s single-threaded in pure Go, at about 87 MB RSS.
- After optimize, the index blocks were byte-identical regardless of insert history, implementation (modernc vs ncruces) and platform (native vs js/wasm).

Pure-Go options:
- **modernc.org/sqlite:** +4.8 MB native; no js/wasm build.
- **ncruces/go-sqlite3 v0.36.0 with `ext/fts5`:** +7.4 MB native, or +15.7 MB raw and +4.1 MB gzip in js/wasm. In the browser it needs the memdb VFS or a custom VFS, and under Node it ran about 4x slower than native.

### Cited Findings
- **Detail option:** `full` (default), `column` or `none`.
  - Docs measurement on about 1636 MiB of emails: "the FTS index was 743 MiB on disk with detail=full, 340 MiB with detail=column and 134 MiB with detail=none". That is 45.4%, 20.8% and 8.2% of the source.
  - detail=column disables phrase and NEAR queries; detail=none also disables column filters. — [SQLite FTS5 docs](https://www.sqlite.org/fts5.html)
- **Merge configuration:**

  | Option | Default | What it does |
  |---|---|---|
  | `automerge` | 4 (max 16; 0 disables) | Merging begins "once there exist M or more b-trees with the same level" |
  | `crisismerge` | 16 | "all b-trees on the level are immediately merged into a single b-tree" |
  | `usermerge` | 4 (2–16) | Minimum fan-in for the `'merge'` command |
  | `deletemerge` | 10 | Percentage of tombstoned rows that makes a b-tree merge-eligible |
  | `pgsz` | 4050 | Leaf blob size |

  - `'merge', N` does roughly N pages of merge work; a negative N merges across levels.
  - `'optimize'` "merges all individual b-trees ... into a single large b-tree". — [SQLite FTS5 docs](https://www.sqlite.org/fts5.html)
- Prefix indexes: `prefix='2 3'` builds one extra index per prefix length. Without them, a prefix query "requires a range scan". — [SQLite FTS5 docs](https://www.sqlite.org/fts5.html)
- **Deletes:**
  - Normal tables: "delete-keys are added to the new b-tree created by the transaction", and old entries remain until a merge.
  - `secure-delete=1` (first in **3.42.0**; it bumps the file format so older versions fail): "full-text entries are actually removed".
  - `contentless_delete` (**3.43.0**): a tombstone is attached to the b-tree holding the row; on merge "both the deleted rows and their tombstone markers are discarded"; `deletemerge` triggers merges of b-trees with many tombstones. — [SQLite FTS5 docs](https://www.sqlite.org/fts5.html)
- **On-disk structures:**
  - Shadow tables:
    - `%_data(id INTEGER PRIMARY KEY, block BLOB)` holds the structure record (id=10), the averages record (id=1), segment leaf pages and doclist-index pages.
    - `%_idx(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID` maps the first term of each leaf page to that page.
    - `%_config`, `%_docsize` (one varint token count per column; dropped with `columnsize=0`) and `%_content` (dropped for contentless or external-content tables).
  - `%_data` rowids pack a tombstone flag, a 16-bit segment id, a doclist-index flag, the tree height and a 32-bit page number.
  - The structure record holds:
    - a 32-bit cookie incremented on every change;
    - the number of levels, the number of segments, and the leaves written to level 0;
    - for each level: the inputs of any ongoing incremental merge, then each segment's segid and first/last leaf page.
  - Segments under about 4000 bytes are a single blob. Larger ones are split into ~4000-byte pages; a key or varint never spans pages.
  - Each page has a 4-byte header and a footer of key offsets.
  - Keys are prefix-compressed. Their first byte is '0' for the main index and '1', '2', ... for prefix indexes.
  - Doclists store the first rowid as a varint, then deltas. Each poslist starts with a varint `nSize*2 + bDel`, where bDel is the delete flag; positions are delta+2 varints.
  - A doclist index is used once a doclist spans more than 4 leaves.
  - Tombstone pages store the rowid at slot `R mod nTombstonePage`, with 4- or 8-byte slots. — [SQLite FTS5 docs §9](https://www.sqlite.org/fts5.html)
- **Size and speed (local run):** SQLite 3.54.1 via modernc; one transaction, then optimize and VACUUM.

  | FTS5 config | DB file | % raw | `%_data` blobs (% raw) | MB/s | Peak RSS |
  |---|---|---|---|---|---|
  | contentless, detail=full | 16,248,832 | 45.3% | 15,745,250 (43.9%) | 25.2 | 87 MB |
  | contentless, detail=column | 11,128,832 | 31.0% | 10,708,300 (29.9%) | 26.1 | 86 MB |
  | contentless, detail=none | 4,874,240 | 13.6% | 4,564,818 (12.7%) | 34.4 | 87 MB |
  | contentless, detail=full, prefix='2 3' | 36,753,408 | 102.5% | 35,921,971 (100.2%) | 11.1 | 93 MB |
  | detail=full with stored content | 59,113,472 | 164.9% | 15,745,250 (same index) | 23.6 | 89 MB |

  One 36 MB transaction produced 6–14 segments before optimize. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Latency (local run)**, contentless detail=full:
  - `count(*) ... MATCH` — "subject" (18,846) 1,272 µs; "computer" (2,513) 187 µs; "encryption" (424) 44 µs; "shuttle" (181) 33 µs.
  - `ORDER BY rank LIMIT 10` (bm25) for "computer": 4,005 µs. This is about 30x Bleve's top-10.
  - Phrase "space shuttle": 62 hits. With detail=column or none, a phrase query returns an explicit error: "fts5: phrase queries are not supported (detail!=full)". — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Compressibility (local run):** the contentless detail=full DB compresses to 75.7% with gzip -9 and 74.2% with zstd -19, which is 33.6% of raw text. The varint/delta format is already dense. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Deterministic content (local run):** the optimized segment blocks (`%_data` rows with id>10, excluding the rowids) had the same hash `5cf83cb7e395` for the 1000-doc subset when built
  - in one transaction,
  - in 1000 transactions with automerge=0, then optimize, and
  - in 1000 transactions with default automerge, then optimize.
  - Only the segment id inside the rowids differed (hashes including rowids: `51c3f273f6d5` / `2d1c664438d5` / `5708f3a84a8f`).
  - The full corpus gave the same block hash `5d80b67c3dc5` from modernc native, ncruces native, and ncruces js/wasm under Node.
  - A 5000-doc build reached the same blocks (`01e25880cf69`) even though the two implementations went through different intermediate segment counts (7 vs 4). — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log), [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Delete behaviour (local run):** one optimized segment of 412 blocks (2000 docs); delete one row.
  - Contentless + `contentless_delete=1`: +1 block (tombstone page) and 2 changed records (structure and averages). Setting secure-delete to 0 or 1 made no difference.
  - Regular table, secure-delete=0: +1 block, and the table now has 2 segments (delete markers).
  - Regular table, secure-delete=1: **151 of 412 blocks rewritten in place**, none added, still 1 segment. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Tiny-segment overhead (local run):**
  - An empty table holds 7 B in 2 rows of `%_data` (structure and averages).
  - After the first 4-token doc: 61 B in 3 rows (+54 B).
  - After the second: 103 B in 4 rows (+42 B), plus one `%_idx` row per segment.
  - The whole DB file is 20,480 B (5 pages). — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **modernc.org/sqlite v1.61.1 (2026-10-31; SQLite 3.54.1):**
  - Pure Go, transpiled from C. FTS5 is built in.
  - The documented "Supported platforms" are darwin amd64/arm64, freebsd, linux (386, amd64, arm, arm64, loong64, ppc64le, riscv64, s390x), netbsd amd64 and openbsd amd64/arm64. Android, iOS and js/wasm are not listed. — [modernc.org/sqlite doc.go](https://pkg.go.dev/modernc.org/sqlite)
- **modernc build results (local run):**
  - darwin/arm64 6,670,018 B (+4.83 MB); android/arm64 7,209,254 B (+5.18 MB).
  - js/wasm fails: "modernc.org/libc/errno: build constraints exclude all Go files".
  - The iOS library compiles. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- Go's rule: "Using GOOS=android matches build tags and files as for GOOS=linux"; GOOS=ios matches as GOOS=darwin. This explains why modernc builds for Android and iOS without listing them. — [cmd/go build constraints](https://pkg.go.dev/cmd/go#hdr-Build_constraints)
- **ncruces/go-sqlite3 v0.36.0 (2026-10-29; SQLite 3.54.1):**
  - "Go bindings to SQLite using wasm2go". It depends on ncruces/wasm2go v0.4.19 and go-sqlite3-wasm/v6.
  - The old `embed` package is deprecated ("importing github.com/ncruces/go-sqlite3/embed is unnecessary").
  - FTS5 is opt-in: `ext/fts5` with `fts5.Register(conn)`. Without it, the local run failed with `no such module: fts5`.
  - The VFS packages include `memdb`, `readervfs`, `adiantum`, `xts` and `mvcc`. — [ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3), [ext/fts5](https://pkg.go.dev/github.com/ncruces/go-sqlite3/ext/fts5), [vfs/readervfs](https://pkg.go.dev/github.com/ncruces/go-sqlite3/vfs/readervfs), [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **ncruces build sizes (local run):**

  | Build | darwin/arm64 | android/arm64 | js/wasm |
  |---|---|---|---|
  | driver only | 7,862,610 B (+6.02 MB) | 8,323,366 B (+6.29 MB) | 15,654,328 B (+12.58 MB; gzip 4.30 MB) |
  | with `ext/fts5` | 9,236,594 B (+7.39 MB) | 9,699,622 B (+7.67 MB) | 18,736,435 B (+15.67 MB over a 3.07 MB base; gzip 4,989,380 B, +4.12 MB) |

  — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **ncruces performance (local run):**
  - Native: indexing at 27.4 MB/s with the file VFS and 28.9 MB/s with memdb; "computer" 250–258 µs; bm25 top-10 3.1–3.2 ms.
  - js/wasm under Node v24.14.1 with memdb: indexing at **7.0 MB/s** (36 MB in 5.13 s); "computer" 1,163 µs; "subject" 7,676 µs; "shuttle" 206 µs; bm25 top-10 22.6 ms.
  - js/wasm with the default OS VFS failed: "PRAGMA journal_mode=OFF sqlite3: disk I/O error". — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)

### Inferences
- **FTS5 is the strongest reuse candidate here:**
  - The merged content is deterministic across clients, implementations and platforms, given the same SQLite version, tokenizer and rowids.
  - A segment costs only tens of bytes plus its term data.
  - Segments and levels are explicit, and both tombstones and in-place purge exist.
  - The same pure-Go engine runs on gomobile (modernc or ncruces) and in wasm (ncruces). In wasm, ncruces+FTS5 uses about 15.7 MB of the 40 MB budget, and the in-browser download is about 5 MB gzipped.
- **For the browser:** ncruces' `readervfs` (open a DB from an `io.ReaderAt`) or `memdb` fits "download the whole index, then search locally". Its `adiantum`/`xts` VFSes could keep the local copy encrypted at rest. These are noted from the package list; neither was evaluated.
- **FTS5's own segment bookkeeping is single-writer:**
  - 16-bit segids, a structure record with a cookie, and 64-bit rowids that must not collide.
  - Concurrent committers therefore cannot each append "an FTS5 segment" without coordination. A plausible design ships commit deltas in a neutral format, or as rowid-disjoint FTS5 segments that the client re-numbers, then rebuilds or merges locally. That merge output is reproducible.
- **detail=none (13.6%) or column (31%)** suit email/record search that does not need phrases: 3–3.5x smaller to download than detail=full. Avoid prefix indexes (2.3x); FTS5 can answer prefix queries without one, through a range scan.
- **Crypto-shredding:**
  - In a contentless index, deletes are tombstones only. The erased document's terms stay in the leaf pages until a merge or optimize rewrites the segment.
  - With stored or external content, secure-delete can purge in place, but it rewrote 37% of a 2000-doc segment's pages for one document. That is about as costly as re-encrypting the whole segment.

### Gaps
- `FTS5_MAX_SEGMENT` (a hard cap on segments) and the `hashsize` flush threshold were not in the fetched text. 1000 segments worked locally.
- The detail=column/none on-disk poslist format was not covered by the fetched excerpt.
- Browser performance (rather than Node) and an OPFS VFS for ncruces were not measured or checked.
- I did not measure how well detail=none compresses.

## Xapian: the glass backend (brief, for comparison)

### Takeaway
Xapian's glass backend (the 1.4 default) is not segment-based. It keeps one B-tree file per table (postlist, termlist, docdata, position, spelling, synonym), with 8 KB blocks, an in-file freelist, an `iamglass` metadata file and 32-bit revisions. Its closest analogue to segment merging is `xapian-compact`, which can merge several databases into one, or into a read-only single file.

### Cited Findings
- "The default database backend for the 1.4 release series is called glass." Chert is deprecated. — [Xapian admin notes](https://xapian.org/docs/admin_notes.html)
- Tables:
  - `postlist` is always present.
  - `termlist` is present by default but optional.
  - `docdata`, `position`, `spelling` and `synonym` are created only when they hold data.
  - Each table is its own file, e.g. `postlist.glass`. — [Xapian admin notes](https://xapian.org/docs/admin_notes.html)
- Storage: blocks are 8 KB by default. Unused blocks are tracked in a freelist stored in unused blocks, and other metadata lives in `iamglass`. Glass can produce a read-only single-file database by compacting. — [Xapian admin notes](https://xapian.org/docs/admin_notes.html)
- `xapian-compact`:
  - removes spare space in blocks, which speeds up searches;
  - takes an output block size that is a power of 2 from 2 KB to 64 KB;
  - can merge several source databases (`--multipass` helps with more than three);
  - can reset the 32-bit revision numbers to 1. — [Xapian admin notes](https://xapian.org/docs/admin_notes.html)

### Inferences
- **Poor fit for append-only encrypted deltas:** an updatable B-tree means every commit rewrites interior and leaf blocks.
- **Useful pattern:** "many small databases → compact/merge into one read-only file" mirrors segment compaction.
- **No pure-Go path:** Xapian is a C++ library (general knowledge, not from the fetched page), so Go use needs cgo.

### Gaps
- Glass's deletion handling, copy-on-write semantics and index-size ratio were not in the fetched page.
- The newer "honey" backend was not covered.

## Other Go full-text libraries (zapx, Typesense-like embedded options): are any maintained and small?

### Takeaway
There is no maintained, small, pure-Go full-text engine beyond:
- Bleve (maintained, but 12–13 MB and no wasm);
- Bluge (dormant since 2022);
- SQLite FTS5 compiled to Go (modernc, ncruces).

The small reusable pieces are zapx (+0.75 MB, needs an mmap shim for wasm) and the raw primitives, vellum FST and roaring (+0.2–0.33 MB). ZincSearch now rides on lightly maintained vcaesar forks of ice. Older Go engines are archived or dormant, and tantivy-go is maintained but needs cgo.

### Cited Findings
- zapx is a fork of zap that "removes dependency on bleve, and instead depends only on the independent interface modules" (`bleve_index_api`, `scorch_segment_api`). — [zapx README](https://github.com/blevesearch/zapx/blob/master/README.md)
- **Size of the pieces (local run):**
  - vellum v1.2.1 + roaring v1.9.4: +189,920 B darwin, +327,680 B android, +250,517 B js/wasm (gzip 945,318 B vs 871,455 B base).
  - zapx/v16: +754,176 B darwin, +851,968 B android; js/wasm fails in mmap-go. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **ZincSearch:**
  - Its `go.mod` (main) depends on `github.com/vcaesar/ice v1.2.3`, `github.com/vcaesar/bluge_segment_api v1.2.0` and `github.com/vcaesar/riot v1.23.1`, but not on `blugelabs/bluge`.
  - ZincSearch has 17,932 stars; v1.0.0-beta3 was released 2026-09-16.
  - vcaesar/ice was pushed 2026-11-04 and vcaesar/bluge_segment_api 2026-10-30; both have 0 stars. — [zincsearch go.mod](https://github.com/zincsearch/zincsearch/blob/main/go.mod), [GitHub API zincsearch](https://api.github.com/repos/zincsearch/zincsearch), [GitHub API vcaesar/ice](https://api.github.com/repos/vcaesar/ice)
- **Dormant or archived engines:** mosuka/blast is archived (last push 2021-12-10); mosuka/phalanx was last pushed 2023-03-02; huichen/wukong was last pushed 2021-08-24; go-ego/riot now returns "moved permanently". — [GitHub API blast](https://api.github.com/repos/mosuka/blast), [phalanx](https://api.github.com/repos/mosuka/phalanx), [wukong](https://api.github.com/repos/huichen/wukong)
- **tantivy-go:** maintained (v1.0.6, 2026-01-06), but requires a Rust-built static library per platform (cgo). — [tantivy-go](https://github.com/anyproto/tantivy-go)

### Inferences
Three realistic paths for a pure-Go E2EE client:
1. **A custom segment codec on vellum + roaring** (FST term dictionary → roaring or FOR-block postings → optional positions). About 0.2–0.3 MB, deterministic by construction, mmap-free.
2. **Vendored zapx** with a `[]byte` loader instead of mmap. About 0.75 MB; reuses a production format and merge code (`Merge(segments, drops []*roaring.Bitmap, ...)`), but needs a determinism fix.
3. **FTS5 via ncruces.** About 7.4 MB native and 15.7 MB wasm; the most complete and deterministic option today.

Bluge/ice forks are a risky fourth option.

### Gaps
- I found no embeddable "Typesense-like" pure-Go engine. Typesense and Meilisearch are servers, and their Go modules are clients; this was not searched exhaustively.
- `wizenheimer/blaze` and similar 2025–2026 hobby engines could not be verified (the API returned nothing).

## Cross-cutting: deletes (tombstones vs bitmaps), merge cost vs segment size, deterministic segment builds, minimum per-segment overhead

### Takeaway
Every segment engine here deletes logically and purges only on merge:
- Lucene, Tantivy and Bleve use a per-segment bitmap, stored as a separate object or in a snapshot.
- FTS5 uses in-segment delete markers or tombstone pages, plus an optional in-place secure-delete.

Merges rewrite whole input segments, so merge cost is proportional to the bytes being merged. The exception is FTS5, which spreads merge work incrementally ('merge' N pages).

Only FTS5 (strongly) and ice (in tests) produced byte-identical segments for identical input. Lucene embeds random IDs, Tantivy uses random UUIDs, and Bleve shuffles doc order.

The smallest segment overhead is FTS5's (~42–54 B per tiny segment). Bleve's ~0.6 KB zap is dwarfed by its bbolt root, which grew to 67 MB after 1000 commits.

### Cited Findings
- **Summary table**, from the sections above. — [Lucene90LiveDocsFormat.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene90/Lucene90LiveDocsFormat.java), [CodecUtil.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/CodecUtil.java), [Tantivy ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md), [segment_id.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/index/segment_id.rs), [scorch README](https://github.com/blevesearch/bleve/blob/master/index/scorch/README.md), [SQLite FTS5 docs](https://www.sqlite.org/fts5.html), [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log), [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)

  | Engine | Delete representation | Physically purged | Same input → same bytes? | Minimum per-segment overhead |
  |---|---|---|---|---|
  | Lucene 10.x | Optional per-segment `.liv` bitset with a generation number | On merge; TMP `deletesPctAllowed` 20%, `forceMergeDeletesPctAllowed` 10% | No: a 16-byte unique ObjectID in every file header, plus Diagnostics in `.si` | Not measured: ~10+ files, each with header + ID + checksum footer (or `.cfs`/`.cfe`) |
  | Tantivy | Immutable `segment_id.opstamp.del` alive-bitset files | On merge (LogMergePolicy ignores deletes by default) | No for names (UUID v4); contents unverified | Not measured |
  | Bleve/scorch | Roaring "deleted" bitmap per segment in the snapshot (bbolt `root.bolt`); the zap file is untouched | On merge, which takes per-segment `drops` bitmaps | **No**: same-size files with different hashes on every build | Zap file 569 B for a 4-token doc; empty index 262,186 B (256 KiB bbolt); `root.bolt` reached 67,338,240 B after 1000 one-doc commits |
  | Bluge/ice | Scorch-style (inferred, not tested) | On merge (inferred) | **Yes** in 3 builds (.seg identical; `.snp` count varies) | 421 B .seg + 16 B .snp |
  | SQLite FTS5 | Delete keys in a new segment (normal); tombstone pages (contentless_delete); in-place removal (secure-delete, not available for contentless) | On merge/optimize, or immediately with secure-delete | **Yes** for merged content, across history, implementation and platform; segids differ | +42–54 B of `%_data` per 1-doc segment, plus a `%_idx` row |

- **Merge timings (local run):**
  - Bleve ForceMerge of 1000 one-doc segments into one took 2.06–2.44 s. The result (3,914,306 B) was not byte-equal to a single-batch build of the same 1000 docs (3,941,900 B).
  - FTS5 optimize of 1000 segments (2.10 MB → 1.07 MB) took 0.07 s, or 0.02 s when automerge had already kept it at 11 segments. — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log), [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)
- **Space amplification of unmerged tiny segments (local run):** 1000 one-doc FTS5 segments held 2,104,059 B of `%_data`, versus 1,071,783 B merged (about 2x). — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)

### Inferences
- **Crypto-shredding means rewriting segments in every engine.** A bitmap or tombstone only hides the document; its terms (and in Bleve's case possibly stored fields) remain in the segment's dictionary and postings until a merge drops it. Cost is proportional to the size of the segments that contain the erased doc.
  - So bound the maximum segment size, or partition segments (by mailbox or time), to cap the shred cost. This trades against query fan-out.
  - With per-segment encryption keys, a shred becomes: rewrite the affected segments, then destroy the old keys.
- **Determinism enables verifiable, idempotent compaction:** two clients compacting the same deltas would produce identical ciphertext inputs (with deterministic encryption) or at least identical plaintext hashes. FTS5 already does this; for Bleve-style or Lucene-style formats it must be engineered (sorted doc order, no random IDs or timestamps).
- **Segment-local doc numbering** (Lucene, Tantivy, zap, ice) lets concurrent committers build deltas without coordination. FTS5 needs collision-free global 64-bit rowids, e.g. (committer, sequence) packed together or hash-derived.

### Gaps
- Lucene and Tantivy minimum per-segment byte overheads were not measured.
- Bluge deletes were not tested.
- Untested: whether Tantivy segment contents are reproducible, and whether FTS5 tombstone pages are deterministic.

## Merge-policy guidance for many tiny segments (e.g. one per commit): how many segments can a reader query before latency degrades?

### Takeaway
Per-query cost grows roughly linearly with segment count:
- **FTS5:** about 3–4.7 µs per segment per term. With 1000 segments, a term query took 3.2–4.7 ms, against 18–84 µs after merging; even 100 segments were about 10x slower.
- **Bleve:** 1000 segments were 15–56x slower than one.

Mature engines therefore merge tiny segments eagerly, with fan-in 4–10 and a floor size:

| Engine | Policy |
|---|---|
| FTS5 | automerge 4, crisismerge 16 |
| Lucene | 8 segments per tier, 16 MB floor, 500 ms merge-on-commit |
| Tantivy | 8 segments per level, 10k-doc floor |
| Bleve | 10 per tier, 2000-doc floor |

Keeping reader-visible segments at about 10–20 kept latency within about 2–4x of a fully merged index in these tests.

### Cited Findings
- **FTS5, 1000 one-doc commits (local run):** automerge=0 and crisismerge=2000 (no merging), contentless detail=full, `count(*)` latency.

  | Segments | "computer" | "subject" | "shuttle" | bm25 top-10 | `%_data` bytes |
  |---|---|---|---|---|---|
  | 1 | 17 µs | 21 µs | 17 µs | 24 µs | 1,197 |
  | 10 | 49 µs | 65 µs | 61 µs | 93 µs | 18,130 |
  | 100 | 234 µs | 434 µs | 388 µs | 477 µs | 189,793 |
  | 300 | 721 µs | 1,252 µs | 1,133 µs | 1,433 µs | 653,254 |
  | 1000 | 3,235 µs | 4,725 µs | 4,169 µs | 6,378 µs | 2,104,059 |
  | after optimize (1 segment, 0.07 s) | 30 µs | 84 µs | 18 µs | 333 µs | 1,071,783 |

  With the defaults (automerge=4, crisismerge=16) the index held at most 16 segments (11 after 1000 commits). Latency was then "computer" 66 µs, "subject" 133 µs and bm25 405 µs, and the 1000 commits took 0.3 s (journal_mode=OFF, synchronous=OFF). — [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Bleve, 1000 one-doc `Index()` calls (local run):** `scorchMergePlanOptions` {MaxSegmentsPerTier 1e6, FloorSegmentSize 1} (no merging). The default 2000-doc floor rounds tiny segments up, so the default planner merged anyway, leaving 5 zap files at 1000 docs.

  | Segments | "computer" | "subject" | "shuttle" | phrase "space shuttle" | Dir bytes |
  |---|---|---|---|---|---|
  | 10 | 5 µs | 11 µs | 3 µs | 145 µs | 588,119 |
  | 100 | 56 µs | 273 µs | 53 µs | 340 µs | 4,858,971 |
  | 300 | 127 µs | 283 µs | 339 µs | 161 µs | 18,973,409 |
  | 1000 | 889 µs | 1,076 µs | 319 µs | 726 µs | 75,056,759 |
  | after ForceMerge (1 segment, 2.44 s) | 17 µs | 71 µs | 3 µs | 13 µs | 71,252,702 (`root.bolt` 67,338,240 + zap 3,914,306) |

  The 1000 commits took 32.5 s (about 32 ms per commit, because each batch is fsync'd); peak RSS was 255 MB. — [local followup.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log), [local exp.log](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)
- **Lucene:**
  - TieredMergePolicy uses segsPerTier 8 and rounds segments under the 16 MB floor up, so as "to prevent frequent flushing of tiny segments to create a long tail of small segments". — [TieredMergePolicy.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/index/TieredMergePolicy.java)
  - A commit or refresh waits up to 500 ms (`DEFAULT_MAX_FULL_FLUSH_MERGE_WAIT_MILLIS`) for merges of the segments it just flushed. — [IndexWriterConfig.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/index/IndexWriterConfig.java)
- **Tantivy:** all segments under 10,000 docs fall into one level, and that level is merged once it holds ≥8 segments. — [log_merge_policy.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/indexer/log_merge_policy.rs)
- **Bleve:** budget staircase with MaxSegmentsPerTier 10, a FloorSegmentSize of 2000 docs, and SegmentsPerMergeTask 10. — [merge_plan.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/mergeplan/merge_plan.go)
- **FTS5:** merging starts when a level reaches 4 b-trees (automerge), and a level is merged immediately at 16 (crisismerge). — [SQLite FTS5 docs](https://www.sqlite.org/fts5.html)

### Inferences
- **One segment per commit works as a write format but not as a read format.** Readers should see O(10–20) segments, not O(commits).
  - Past about 100 un-merged segments, both FTS5 and Bleve were about 5–15x slower per term.
  - At 1000 segments, about 50x slower on selective terms.
- **A leveled merge with fan-in 4–8 and a floor size,** run by whichever client next downloads and searches, bounds the segment count to about fan-in × log(N) and halves the downloaded bytes compared with unmerged one-doc deltas.
- **With deterministic merge output (FTS5 or a custom codec),** compaction can be done by any client and verified by others.
- **Keep segment-list metadata out of a mutable shared store.** Scorch's bbolt root grew to 67 MB over 1000 commits; the encrypted repo's own commit log should be the snapshot list instead. That segment-list snapshots cause this growth is an inference, not measured directly.

### Gaps
- Segment-count scaling was tested only with 1-doc segments, up to 1000 segments (1000 docs, 2 MB). It was not tested with large segments, larger corpora, multi-term AND/OR queries, or in a real browser.
- The durability settings differed: FTS5 ran with `synchronous=OFF`, while Bleve fsyncs each batch. The 0.3 s vs 32.5 s commit-time gap therefore mixes engine and durability costs.
