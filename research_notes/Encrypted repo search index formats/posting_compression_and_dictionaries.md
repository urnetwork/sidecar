# Posting-list compression and term-dictionary formats for a compact, client-downloadable full-text index

Scope: how small an inverted index can be made and at what CPU cost, covering posting-list codecs, term dictionaries, and docid-only versus positional variants. The lens is an E2EE git-shaped store whose clients (pure Go on desktop, gomobile, and a js/wasm browser worker) download the latest index and search locally. Research date: 2026-11-05. Each number carries its source year. "Own measurement" marks numbers from a pure-Go harness I wrote and ran in this session (setup is under Q1). Those numbers are original and have no published counterpart, so treat them as indicative.

## Q1. Posting-list codecs: bits per posting on standard collections, decode speed, and suitability for small, frequently created segments

### Takeaway
On large web collections (Gov2, ClueWeb09, CC-News) the most compact codecs are interpolative coding (BIC), Packed+ANS, and partitioned Elias-Fano (PEF). They need about 3–5.5 bits per docid. VByte, Group Varint and Stream VByte need 8.8–12 bits, and Roaring needs 6.6–9.8 bits. Decode costs about 0.5–1.3 ns/int for the fast group (with SIMD in C++) and 5–7 ns/int for BIC. In small, frequently created segments most lists are tiny: 31–83% of terms have df=1 in my corpora. There, per-list and per-block overheads dominate. Byte-aligned VByte, or 128-int bit-packed blocks with a VByte tail (Lucene/Tantivy style), stay at about 7–10 bits per posting. Roaring (19–55 bits) and word-aligned block codecs (Simple-8b and the intcomp BP128 implementation, 7–48 bits) degrade badly.

### Cited Findings

#### Published numbers on standard collections
- **Pibiri & Venturini survey (ACM CSUR 2020), Table 11.** Docids only. Lists longer than 4096 are kept, covering 93/94/98% of postings, with docids in URL order, on an i9-9900K with gcc -O3 -march=native. Values are bits/int and ns/int for Gov2 | ClueWeb09 | CCNews:
  - VByte (Masked-VByte SIMD decoder): 8.81, 0.96 | 9.20, 1.09 | 9.29, 1.03
  - Opt-VByte: 3.89, 0.73 | 5.72, 0.92 | 6.42, 0.72
  - BIC: 2.94, 5.06 | 4.43, 6.31 | 5.24, 6.97
  - δ: 3.74, 3.56 | 5.17, 3.72 | 6.36, 3.85
  - Rice: 4.08, 2.92 | 5.31, 3.25 | 5.82, 3.32
  - PEF: 3.12, 0.76 | 4.99, 1.10 | 5.45, 1.31
  - DINT: 3.53, 1.13 | 5.35, 1.56 | 6.44, 1.65
  - Opt-PFor: 3.63, 1.38 | 5.46, 1.79 | 6.07, 1.53
  - Simple16: 4.19, 1.53 | 5.85, 1.87 | 6.41, 1.89
  - QMX: 5.12, 0.80 | 7.29, 0.87 | 7.40, 0.84
  - Roaring: 6.63, 0.50 | 9.78, 0.71 | 9.49, 0.61
  - Slicing: 4.31, 0.53 | 7.06, 0.68 | 7.78, 0.69

  The empirical entropy of the gaps is 3.02 / 4.46 / 5.44 bits. The prefix sum over gaps costs another 0.5 ns/int, which "sometimes dominates" gap decoding. — [Pibiri & Venturini, arXiv 1908.10598](https://arxiv.org/abs/1908.10598)
- **Same survey, query costs.** Average AND time (ms), Gov2 / ClueWeb09 / CCNews: Roaring 0.6 / 2.9 / 2.5; Slicing 1.0 / 4.5 / 4.3; PEF 2.9 / 13.5 / 21.2; VByte 2.8 / 12.5 / 19.5; BIC 10.0 / 45.3 / 72.8. Average OR time: Roaring 3.7 / 10.3 / 9.2; VByte 54.4 / 156.7 / 172.3. The authors attribute Roaring's lead to SIMD: "with SIMD disabled" Roaring's timings were "almost identical" to Slicing. — [Pibiri & Venturini](https://arxiv.org/abs/1908.10598)
- **Mallia, Siedlaczek & Suel (ECIR 2019), PISA, Table 2.** Gov2 (24.6M docs, 5.74B postings) and ClueWeb09-B (50.1M docs, 15.86B postings). Text was lowercased and Porter2-stemmed with no stopword removal, blocks of 128, on a Haswell i7-4770. Docids in URL order; values are index GB, doc bits, freq bits, Gov2 | ClueWeb09:
  - Packed+ANS2: 4.17, 3.96, 1.85 | 14.47, 5.36, 1.94
  - Interpolative: 4.26, 3.80, 2.14 | 13.90, 5.15, 1.87
  - PEF: 4.65, 4.11, 2.37 | 15.95, 5.85, 2.20
  - OptPFD: 4.92, 4.48, 2.38 | 17.04, 6.18, 2.41
  - Simple16: 5.96, 5.34, 2.90 | 19.36, 6.92, 2.79
  - Simple8b: 6.32, 5.53, 3.27 | 21.46, 7.36, 3.47
  - QMX: 6.71, 5.98, 3.36 | 23.27, 7.98, 3.75
  - SIMD-BP128: 7.00, 6.35, 3.41 | 25.08, 8.68, 3.97
  - Varint-G8IU: 13.75, 10.35, 8.81 | 38.82, 10.75, 8.83
  - VarintGB (Group Varint): 15.02, 11.15, 9.77 | 42.10, 11.43, 9.80
  - StreamVByte: 15.37, 11.37, 10.04 | 42.97, 11.65, 10.03

  — [Mallia et al., ECIR 2019 PDF](https://research.engineering.nyu.edu/~suel/papers/daat-ecir19.pdf)
- **Same paper, effect of docid order.** With random order, Gov2 grows to 7.36 GB (Packed+ANS2) and 10.35 GB (SIMD-BP128). URL ordering shrinks Packed+ANS2 by 43% (Gov2) and 27% (ClueWeb09), and Recursive Graph Bisection (BP) shrinks it further, to 3.57 GB on Gov2. "Variable byte methods benefit little from URL or BP reordering." — [Mallia et al. 2019](https://research.engineering.nyu.edu/~suel/papers/daat-ecir19.pdf)
- **Same paper, query speed.** URL order, TREC05, Gov2, MaxScore: SIMD-BP128 4.27 ms, Varint-G8IU 3.96, VarintGB 4.02, StreamVByte 4.48, OptPFD 5.08, PEF 8.62, Interpolative 9.89, Packed+ANS2 9.00. "SIMD-BP128 basically matches the performance of Varint-G8IU" while using about half the space. — [Mallia et al. 2019](https://research.engineering.nyu.edu/~suel/papers/daat-ecir19.pdf)
- **Ottaviano & Venturini, partitioned Elias-Fano (SIGIR 2014).** Gov2 / ClueWeb09, no SIMD. Values are doc bits and freq bits:
  - EF single: 7.53, 3.14 / 7.46, 2.44 (index +64.7% / +23.1% vs EF-optimal)
  - EF uniform (128-chunks): 4.63, 2.58 / 6.58, 2.39
  - EF-optimal (PEF): 4.10, 2.38 / 5.85, 2.20
  - Interpolative: 4.03, 2.33 / 5.33, 2.04 (only 1.8% / 8.3% smaller than PEF)
  - OptPFD: 4.72, 2.55 / 6.42, 2.56 (12.3% / 11.6% larger than PEF, and slower)
  - Varint-G8IU: 10.60, 8.98 / 10.99, 8.98

  Optimal chunks average 231 docids and 466 freqs on Gov2. — [PEF paper PDF](http://groups.di.unipi.it/~ottavian/files/elias_fano_sigir14.pdf)
- **Lemire & Boytsov, "Decoding billions of integers per second through vectorization" (SPE 2015; arXiv v7 2021), Table V.** Posting lists only, weighted by the AOL query log. ClueWeb09 had stopwords removed, the top 1M words kept and no reordering. Values are encode mis / decode mis / bits per int (mis = millions of ints per second), ClueWeb09 | GOV2:
  - SIMD-BP128* (vectorized delta): 1600/2300/11 | 1600/2500/7.6
  - SIMD-BP128: 1000/1600/9.5 | 1000/1700/6.3
  - SIMD-FastPFOR: 250/1200/8.1 | 290/1400/5.3
  - varint-G8IU: 210/1200/11 | 230/1300/9.6
  - Simple-8b: 280/730/7.5 | 340/780/4.8
  - OptPFD: 14/500/7.1 | 23/710/4.5
  - Variable Byte: 570/540/9.6 | 730/680/8.7

  "VSEncoding and OptPFD are two orders of magnitude slower during encoding than our fastest schemes." — [Lemire & Boytsov, arXiv 1209.2137](https://arxiv.org/abs/1209.2137)
- **Stream VByte (Lemire, Kurz & Rupp, IPL 2018).** It decodes "more than 4 billion differentially-coded integers per second" on a 3.4 GHz Haswell. On ClueWeb09 lists it ranges from 4.0 B ints/s (highly compressible) down to 1.1 B ints/s. For comparison, VARINT-G8IU runs at 2.7–1.1, Masked VByte and VARINT-GB at 2.6–0.5, and scalar VByte at 1.1–0.3. Stream VByte and G8IU "use .5 to 2 more bits per integer than VByte," and Stream VByte has "almost exactly the same storage requirements" as Group Varint. — [Stream VByte, arXiv 1709.08990](https://arxiv.org/abs/1709.08990)
- **Roaring (Lemire et al., CRoaring paper, arXiv v6 2022).** Memory in bits per value: CensusInc 2.60, Census1881 15.1 (a plain bitset needs 524), Weather 5.38, Wikileaks 5.89; on sorted variants 0.60 / 2.16 / 0.34 / 1.63. The serialized size differs from in-memory size mainly for the sets with the fewest values per set. — [Lemire et al., arXiv 1709.07821](https://arxiv.org/abs/1709.07821)
- **Roaring format and size bound.** Go Roaring's README gives the bound: "Given N integers in [0,x)… the serialized size in bytes… should never exceed… 8 + 9 * ((long)x+65535)/65536 + 2 * N". That is, at most 2 bytes per integer plus a per-64K-chunk overhead. — [RoaringBitmap/roaring README](https://github.com/RoaringBitmap/roaring). The format spec has an 8-byte header for the no-run cookie plus a 4-byte descriptive entry per container and a 4-byte offset per container. — [RoaringFormatSpec](https://github.com/RoaringBitmap/RoaringFormatSpec)
- **Lucene's current production codec.**
  - Lucene 10.4.0 raised the postings block size from 128 to 256. The entry reads "This gives a noticeable speedup to many queries" (GITHUB#15160, merged 2025-09-10). The Lucene104 `ForUtil.BLOCK_SIZE = 256`.
  - Since 10.2.0, "Dense blocks of postings are now encoded as bit sets" (GITHUB#14133).
  - Since 9.12, skip data is inlined, with only 2 levels: every block and every 32 blocks (GITHUB#13585).

  — [Lucene CHANGES.txt](https://github.com/apache/lucene/blob/main/lucene/CHANGES.txt); [PR #15160](https://github.com/apache/lucene/pull/15160); [PR #14133](https://github.com/apache/lucene/pull/14133); [PR #13585](https://github.com/apache/lucene/pull/13585)
- **Lucene block encoding.** Packed blocks use one bit width per block, with a special case for all-equal blocks. Frequency blocks use patching (PFOR) and doc-delta blocks do not. Leftover values go in VInt blocks. The files are .doc (docids, freqs, skip data), .pos (positions), .pay (payloads and offsets), .tim (terms) and .tip (terms index). — [Lucene 10.3 Lucene103PostingsFormat javadoc](https://lucene.apache.org/core/10_3_0/core/org/apache/lucene/codecs/lucene103/Lucene103PostingsFormat.html)
- **Tantivy's codec.** "The posting list is organized in block of 128 documents… doc ids are delta encoded and bitpacked. The term frequencies are bitpacked… the last block… [uses] variable int encoding." Positions live in a separate .pos file. — [Tantivy ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)

#### Own measurement: pure-Go codecs on small corpora (this session)
- **Setup.**
  - Harness: `/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/idxexp/main.go`, with raw outputs in `out_*.txt` in the same directory. Go 1.27.3, Apple Silicon darwin/arm64 natively; js/wasm under Node v24.14.1 (V8).
  - Tokenizer: Unicode letter/digit runs, lowercased, tokens over 64 bytes dropped, no stemming, no stopwords. Docids are assigned in input order.
  - Codecs: my own VByte (LEB128) and scalar bp128 (128-int frame-of-reference blocks with a 1-byte width and VByte tail, Lucene/Tantivy style); library codecs from [mhr3/streamvbyte](https://github.com/mhr3/streamvbyte), [ronanh/intcomp](https://github.com/ronanh/intcomp) (BP128), [jwilder/encoding/simple8b](https://github.com/jwilder/encoding) and [RoaringBitmap/roaring v2.30.0](https://github.com/RoaringBitmap/roaring) with RunOptimize. Elias-Fano and BIC sizes are computed analytically, without skip or select pointers.
  - Every decoder was round-trip verified against the original docids on native, pure-Go (`-tags noasm`) and wasm runs.
- **Corpora:**
  - "Go src": the first 52.5 MB (2,868 files) of `.go` files from the Go 1.27.3 source tree, with testdata excluded. [Go source](https://go.dev/dl/)
  - "Kafka email": dev@kafka.apache.org, Jan–Apr 2025, 3,019 messages and 10.8 MB of decoded text/plain (From/To/Cc/Subject headers kept). [Apache list archive mbox API](https://lists.apache.org/list.html?dev@kafka.apache.org)
  - "Logs": 16 Loghub 2k-line samples in chunks of 50 lines, 640 docs and 4.46 MB. [Loghub](https://github.com/logpai/loghub)
- **Docid bits per posting, all lists** (Go src / Kafka email / Logs):
  - VByte: 9.84 / 8.61 / 10.24
  - bp128 (scalar): 8.96 / 7.15 / 9.90
  - StreamVByte: 12.35 / 10.54 / 13.25
  - intcomp BP128: 27.07 / 10.60 / 47.52
  - Simple-8b: 14.85 / 7.41 / 24.27
  - Roaring: 34.95 / 18.59 / 55.44
  - Elias-Fano (computed): 7.81 / 5.78 / 7.78
  - BIC (computed): 6.16 / 4.68 / 5.56

  The share of terms with df=1 is 53.1% / 30.7% / 82.9%, and the share of postings in lists with df<128 is 60.0% / 35.0% / 81.4%. — own measurement ([harness libs](https://github.com/RoaringBitmap/roaring); corpora as above)
- **Decode speed on long lists** (Go src, the 1,005 lists with df≥128, including prefix sum; native arm64 vs js/wasm under Node), in ns/posting:
  - VByte: 0.89 → 3.68
  - scalar bp128: 1.57–1.88 → 8.21
  - StreamVByte: 0.55 with NEON asm, 0.86 with pure Go (`noasm`) → 3.57
  - intcomp BP128: 0.78 → 2.05
  - Simple-8b: 1.20 → 4.04
  - Roaring (FromBuffer + NextMany): 1.50 → 4.36

  On all lists (short-list heavy), native: VByte 4.41, Roaring 22.99 on Go src; VByte 1.95, Roaring 6.00 on Kafka; wasm on Kafka: VByte 4.98, Roaring 32.97. — own measurement
- **Whole-stream zstd** (klauspost/compress level 3) over the concatenated postings. Docids: VByte goes from 2.50% to 1.23% of raw (Go src), bp128 from 2.28% to 1.29%, Roaring from 8.90% to 2.10%. Positions: VByte goes from 17.67% to 11.64%, bp128 from 19.09% to 14.15%. Byte-aligned VByte leaves redundancy that zstd removes; bit-packed data does not. — own measurement ([klauspost/compress](https://github.com/klauspost/compress))

### Inferences
- **Roaring is a poor fit for tiny lists in small segments.** Under the spec, a df=1 list costs 8 + 4 + 4 + 2 = 18 bytes (144 bits) against 1–3 bytes for VByte; this is derived from the format spec, not measured. That matches the measured 35–55 bits per posting on short-list-heavy corpora. Roaring pays off only for long or dense lists where fast AND/OR matters.
- **Block codecs fall back to the VByte tail on short lists.** Any 128-int block codec (SIMD-BP128, PFOR, Lucene/Tantivy FOR) behaves like VByte on lists under 128 postings, so the "bits per int" advantage seen on Gov2 lists longer than 4096 largely disappears in small personal corpora. Word-aligned implementations add padding: intcomp writes 32-bit words and Simple-8b 64-bit words.
- **Interpolative coding keeps its size edge on small data.** BIC was the smallest codec everywhere (4.2–6.2 bits per posting, including 4.15 on the 1.8 MB Lucene email corpus), and its 5–7 ns/int decode cost hardly matters at MB scale. Its weaknesses are no random access and recursive decoding.
- **Wasm costs about 2.5–5× native.** Pure-Go code compiled to js/wasm ran 2.5–5× slower than native arm64. At about 2–8 ns per posting, a browser worker can still decode tens of millions of postings per second, which is ample for MB-scale indexes.
- **An Opt-VByte/Lucene-10.2-style hybrid is easy in pure Go.** VByte (or FOR blocks with a VByte tail) plus bitsets for dense blocks needs no SIMD. In C++ it reaches 3.9–6.4 bits per int at about 0.7–0.9 ns/int on web collections.

### Gaps
- I found no published bits-per-posting numbers for any codec on small or personal corpora (MBs, mostly df=1 lists). The only such numbers here are my own measurements.
- No published decode-speed numbers exist for these codecs under Go or WebAssembly; mine are a single machine and runtime (Apple Silicon, Node 24 V8). Safari and Firefox wasm engines were not tested.
- I did not implement partitioned Elias-Fano or Opt-VByte in the harness, so their small-corpus sizes are unmeasured.
- Group Varint and Simple-16 were not measured in Go.

## Q2. Which codecs have mature pure-Go implementations (packages, licenses, maintenance, SIMD dependence)?

### Takeaway
Roaring (RoaringBitmap/roaring v2), the vellum FST (blevesearch/vellum) and VByte (stdlib `encoding/binary`) have mature, actively maintained pure-Go implementations. Roaring and vellum are the core of Bleve's zap segment format. Roaring and Stream VByte ship assembly (AVX2/AVX-512/NEON/SSE4.1) with pure-Go fallbacks, so they build for js/wasm, wasip1 and android/arm64 with cgo off. BP128 (ronanh/intcomp), Simple-8b (jwilder) and Elias-Fano (Erigon, LGPL) exist but are thinly maintained or tied to other projects. I found no maintained pure-Go PFOR/OptPFD, partitioned Elias-Fano or interpolative coder. Go SIMD itself is still experimental: archsimd arrived in Go 1.26 for amd64, and Go 1.27 added arm64, wasm and a portable `simd` package under GOEXPERIMENT=simd.

### Cited Findings
- **Repository metadata.** Taken from the GitHub API on 2026-11-05; "last commit" is the default branch. — [GitHub API](https://docs.github.com/rest/repos/repos)
  - [RoaringBitmap/roaring](https://github.com/RoaringBitmap/roaring): Apache-2.0, about 2,950 stars, release v2.30.0 (2026-10-19), last commit 2026-11-03. It has 7 assembly files, including AVX2/AVX-512 popcount, AVX-512 bitset ops, VBMI2 fill and NEON popcount. Each has a `*_generic.go` fallback (popcnt_generic.go, bitsetops_generic.go, fillarray_generic.go, fillbits_generic.go).
  - [blevesearch/vellum](https://github.com/blevesearch/vellum): Apache-2.0, tag v1.2.1, last commit 2026-11-02, no assembly. The original [couchbase/vellum](https://github.com/couchbase/vellum) was last pushed 2023-02.
  - [blevesearch/zapx](https://github.com/blevesearch/zapx): Apache-2.0, tag v17.2.5, last commit 2026-11-04. [blevesearch/bleve](https://github.com/blevesearch/bleve): v2.6.1 (2026-08-24), about 11.3k stars.
  - [mhr3/streamvbyte](https://github.com/mhr3/streamvbyte): Apache-2.0, v0.4.0, last commit 2026-07-27, 3 stars. Ships SSE4.1 and NEON decoders plus a generic path under `//go:build noasm || (!amd64 && !arm64)`.
  - [thempatel/streamvbyte-simdgo](https://github.com/thempatel/streamvbyte-simdgo): Apache-2.0, last push 2021.
  - [ronanh/intcomp](https://github.com/ronanh/intcomp): Apache-2.0, release v1.1.0 (2023) with a later v1.1.1 tag, last commit 2025-02-18, no assembly. Provides delta + zigzag BP128 blocks and VarByte.
  - [jwilder/encoding](https://github.com/jwilder/encoding) (simple8b): MIT, last commit 2017-08.
  - [zentures/encoding](https://github.com/zentures/encoding) ("Integer Compression Libraries for Go"): Apache-2.0, last push 2017-12.
  - [amallia/go-ef](https://github.com/amallia/go-ef) (Elias-Fano): MIT, last commit 2017-09.
  - [erigontech/erigon](https://github.com/erigontech/erigon): LGPL-3.0, active. Contains Go Elias-Fano in `db/recsplit/eliasfano32/elias_fano.go` and `db/recsplit/eliasfano16/elias_fano.go`, and RecSplit MPHF in `db/recsplit/recsplit.go`.
  - [dgraph-io/sroar](https://github.com/dgraph-io/sroar) (serialized roaring) is archived. Its fork [weaviate/sroar](https://github.com/weaviate/sroar) is at v0.0.18 (2026-09-16), Apache-2.0, with no assembly.
  - [kelindar/bitmap](https://github.com/kelindar/bitmap): MIT, v1.5.7 (2026-09-23), with AVX/AVX-512/NEON assembly.
  - [bits-and-blooms/bitset](https://github.com/bits-and-blooms/bitset): BSD-3, active.
  - MPHF packages: [alecthomas/mph](https://github.com/alecthomas/mph) (BSD-3, CHD, last commit 2024-09); [dgryski/go-mph](https://github.com/dgryski/go-mph) (MIT, 2021); [opencoff/go-bbhash](https://github.com/opencoff/go-bbhash) (GPL-2.0, archived); [relab/bbhash](https://github.com/relab/bbhash) (MIT, 2025).
  - Tries and rank/select: [openacid/slim](https://github.com/openacid/slim) (MIT; its description claims "11 bits/key; 100 ns/get"); [hillbig/rsdic](https://github.com/hillbig/rsdic) (MIT, 2020).
  - Code search: [sourcegraph/zoekt](https://github.com/sourcegraph/zoekt) (Apache-2.0, active) and [google/codesearch](https://github.com/google/codesearch) (BSD-3).
- **Pure-Go build check (own measurement).** One program importing roaring/v2, vellum (with levenshtein), klauspost zstd, mhr3/streamvbyte, ronanh/intcomp and jwilder simple8b built for GOOS=js/GOARCH=wasm, wasip1/wasm, android/arm64 (CGO_ENABLED=0) and linux/amd64 (CGO_ENABLED=0). ios/arm64 with CGO_ENABLED=0 failed with "ios/arm64 requires external (cgo) linking". That is a Go toolchain requirement for the iOS target, not a library dependency; gomobile links with cgo anyway. — own measurement ([Go toolchain](https://go.dev/dl/))
- **A Stream VByte asm/pure-Go inconsistency (own measurement).**
  - In mhr3/streamvbyte v0.4.0, the pure-Go scalar decoder (`decodeDeltaScalar`) decodes `len(opts.Buffer)` values rather than `count`. With a larger reusable buffer it panicked under js/wasm reading past the input, while the NEON path on arm64 did not panic with the same inputs.
  - With an exactly sized buffer, all paths round-tripped correctly.
  - Throughput on long lists: NEON 0.55 ns/posting; pure-Go natively 0.86; wasm 3.57, about the same as plain VByte at 3.68.

  — own measurement ([encoding_scalar_delta.go](https://github.com/mhr3/streamvbyte))
- **Go SIMD status (2026).** "Go 1.26 introduced the architecture-dependent `archsimd` API for amd64." Go 1.27 adds archsimd for arm64 (NEON) and wasm, and an experimental portable `simd` package. All are enabled with `GOEXPERIMENT=simd`, emulated when hardware is missing, and outside the Go 1 compatibility promise. — [Go blog, "Platform-independent SIMD in Go", 2026-09-24](https://go.dev/blog/simd-experiment); [tracking issue #73787](https://github.com/golang/go/issues/73787)
- **Bleve's zap segment format** (Go, used by Couchbase FTS) combines a vellum FST term dictionary per field with Roaring postings. Freq/norm and location data (field, pos, start, end, array positions) are stored as chunked varint streams, and stored fields are snappy-compressed. — [zapx README](https://github.com/blevesearch/zapx)

### Inferences
- **A cgo-free client stack is available today.** Stdlib varint, or a small hand-written FOR/bp128 like the harness's (about 100 lines), covers postings; vellum covers the dictionary; roaring/v2 is optional for long lists; klauspost/compress handles transport compression. All of it compiles to wasm and gomobile targets.
- **SIMD codecs gain nothing in the browser today.** Stream VByte and other SIMD-designed codecs have no advantage under js/wasm until Go's wasm SIMD (Go 1.27 experiment) matures and libraries adopt it. In wasm, the pure-Go BP128 (intcomp) was the fastest docid decoder on long lists (2.05 ns vs 3.68 for VByte). On short-list-heavy data VByte was fastest (Kafka, all lists: 4.98 vs 6.20 ns).
- **License matters for Elias-Fano.** Erigon's Elias-Fano and RecSplit are LGPL-3.0, which may matter for app distribution; amallia/go-ef is MIT but unmaintained since 2017.

### Gaps
- I did not search exhaustively for Go Group Varint, Simple-16, PFOR/OptPFD, partitioned Elias-Fano or interpolative-coding packages. None surfaced among the candidates checked.
- I did not measure the maintenance quality (tests, fuzzing, issue response) of the smaller repos.
- kelindar/bitmap's non-asm fallback was not verified.

## Q3. Term dictionaries: FST, front-coded sorted blocks and minimal perfect hashing (size per term, lookup cost, prefix/fuzzy/range support)

### Takeaway
BurntSushi's Rust fst stored large English vocabularies at 29–54% of raw key bytes (2015). On my smaller vocabularies, vellum (term → ordinal) took 60–80% of raw term bytes (6.7–9.7 bytes/term), about the same as plain front coding in buckets of 16 (5.7–8.9 B/term). After zstd, front coding is markedly smaller (about 2.8–3.9 B/term vs about 4.6–5.9 B/term for the FST). Both support prefix and range scans, and both can drive Levenshtein or regex automata: Lucene runs automaton intersection over its block-tree dictionary, not only over FSTs. Minimal perfect hashing needs about 1.8–3.4 bits/key plus stored keys or fingerprints, and supports only exact lookup. Lucene itself dropped the FST for its terms index in 10.3 in favour of a specialized trie.

### Cited Findings
- **BurntSushi fst (Rust, 2015).** Keys, input size, FST size (share of input), and comparisons:
  - Dictionary: 119,095 keys, 1.1 MB input → 324 KB FST (29.4%); gzip 302 KB, xz 232 KB
  - Gutenberg terms: 3.54M keys, 41 MB → 22 MB (53.7%); gzip 13 MB, xz 10 MB
  - Wikipedia titles: 15.8M keys, 384 MB → 157 MB (40.9%)
  - DOI URLs: 49.1M keys, 2.8 GB → 113 MB (4.0%)
  - Common Crawl URLs: 1.65B keys, 134 GB → 27 GB (20.1%)

  Peak build memory with sorted input was 9.4–56 MB. A regex `Homer the.*` over Wikipedia titles took 0.023 s, and a fuzzy distance-2 search for "Homer Simpson" took 0.094 s. Supported operations: range (ge/gt/le/lt), streaming, regex, Levenshtein, and set union/intersection/difference. Keys must be inserted in sorted order and the FST is immutable. A bounded cache (about 10,000 slots) makes it "close to minimal but not guaranteed minimal." — [Gallant, "Index 1,600,000,000 Keys with Automata and Rust"](https://burntsushi.net/transducers/)
- **vellum (Go).** Maps `[]byte` to uint64, with lexicographic enumeration, "bounded memory use while building," streaming output and optional mmap. Keys "MUST" be inserted in lexicographic order. Levenshtein and regexp subpackages exist. The Levenshtein builder doc says: "takes only a few milliseconds for d=2, it grows exponentially with d… only reasonable to d <= 5." — [vellum README](https://github.com/blevesearch/vellum); [pkg docs](https://pkg.go.dev/github.com/blevesearch/vellum/levenshtein)
- **Bleve/zapx turned off FST suffix sharing (2026-11).** vellum v1.2.1 notes: "`RegistryTableSize: 0` now turns off suffix sharing… The FST is still valid and readable, just not minimal. Used by the zapx change that turns off suffix sharing for term dictionaries. On a 1M-doc Wikipedia FTS index build, the two together were 20% faster, used 19% less CPU and 15% less peak memory." No size impact was stated. — [vellum commit (#32)](https://github.com/blevesearch/vellum/commits/master); [zapx #453](https://github.com/blevesearch/zapx/commits/master)
- **Lucene BlockTree.** Terms sit on disk in blocks of 25–48 entries (`DEFAULT_MIN_BLOCK_SIZE = 25`, `DEFAULT_MAX_BLOCK_SIZE = 48`). An enum `CompressionAlgorithm` exists for "suffixes of a block of terms," and the writer imports LZ4. — [Lucene103BlockTreeTermsWriter.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene103/blocktree/Lucene103BlockTreeTermsWriter.java)
  - Lucene 10.3.0: "Introduce a specialized trie for block tree index, instead of FST" (GITHUB#14333). On its benchmark, .tip size fell by 14.24% overall (27.55 MB to 23.63 MB) and by 12.6–30.4% per segment. The PR says: "very few suffix get shared in block tree… for `tip`, performance is more important than storage size, which is usually a very small part of the whole index, and loaded off-heap." — [PR #14333](https://github.com/apache/lucene/pull/14333); [CHANGES.txt](https://github.com/apache/lucene/blob/main/lucene/CHANGES.txt)
  - Lucene's blocktree package contains `IntersectTermsEnum` and `IntersectTermsEnumFrame`. The class names indicate automaton intersection directly over the block-tree dictionary rather than an FST of all terms. — [Lucene blocktree source](https://github.com/apache/lucene/tree/main/lucene/core/src/java/org/apache/lucene/codecs/lucene103/blocktree)
- **Tantivy.** "Term ⟶ TermOrdinal is addressed by a finite state transducer, implemented by the fst crate. TermOrdinal ⟶ TermInfo is addressed by the term info store." When compiled with the `quickwit` feature it uses `sstable_termdict` instead. Latest release is 0.26.1 (2026-05-10). — [Tantivy ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md); [tantivy src/termdict/mod.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/termdict/mod.rs)
- **Compressed string dictionaries (Martínez-Prieto et al., Information Systems 2016).** The "Words" dataset is 25.6M distinct ClueWeb09 words, 257 MB, average length 10.5. On it, plain front coding reaches 47.33% of the original, trie nodes 37.78% and Re-Pair 60.50%. Plain front coding (PFC) is "the fastest choice in all cases… at the price of being the least effective." HTFC-huff (Hu-Tucker front coding with Huffman) leads on Words, URIs and DNA. The best hash structure (HashDAC-rp) achieves 12–60% with 0.5–3.2 µs per locate. XBW reaches 3–20% at 20–200 µs per locate. — [CSD paper PDF](https://users.dcc.uchile.cl/~gnavarro/ps/is15.2.pdf)
- **IIR (Manning, Raghavan & Schütze), Reuters-RCV1.** A dictionary of fixed-width entries takes 11.2 MB, and blocking plus front coding cuts it to 5.9 MB. I saw these figures via search snippets and course notes, because the nlp.stanford.edu host was unreachable this session. — [IIR ch. 5](https://nlp.stanford.edu/IR-book/html/htmledition/gamma-codes-1.html)
- **Minimal perfect hashing (PTHash paper, SIGIR 2021).** Space lower bound log2 e ≈ 1.44 bits/key. At n = 10^8 64-bit keys:
  - CHD: 2.01–2.17 bits/key, about 200 ns lookup (about 417 ns at 10^9)
  - BBHash γ=1: 3.06 bits/key, 119 ns
  - RecSplit (ℓ=8, b=100): 1.80 bits/key, 124 ns, 92 s build
  - PTHash: 2.26–4.05 bits/key at 28–49 ns
  - On strings (GoogleBooks n-grams, ClueWeb09 and UK2005 URLs): 2.97–3.18 bits/key at 22–63 ns

  — [PTHash, arXiv 2104.10402](https://arxiv.org/abs/2104.10402)
- **Own measurement: dictionaries in Go** (Go src 179,100 terms, average 10.7 bytes / Kafka email 15,794 terms, 9.4 bytes / Logs 39,900 terms, 7.35 bytes). Values are bytes per term:
  - Raw terms with separators: 11.69 / 10.39 / 8.35
  - vellum FST mapping term → ordinal: 7.04 / 7.80 / 6.70
  - Front coding, bucket 16 plus a 4-byte offset per bucket: 7.03 / 7.24 / 5.73
  - Front coding, bucket 64: 6.60 / 6.88 / 5.40
  - After zstd-3: front-coded data 3.41 / 3.86 / 2.77; FST 5.11 / 5.89 / 4.63
  - Term metadata (df + postings offset varints): about 2.0

  — own measurement ([vellum](https://github.com/blevesearch/vellum); corpora per Q1)
- **Own measurement: lookup cost** (Go src, 200k random existing terms; native arm64 → js/wasm):
  - FST Get: 336–405 ns → 1,587 ns
  - Front-coded-16 binary search plus scan: 420–480 ns → 1,528 ns
  - 3-character prefix enumeration (about 1,037 hits): about 100 µs → 655 µs
  - Levenshtein d=1 (vellum DFA ∩ FST): about 90 µs → 521 µs, about 10 matches
  - Levenshtein d=2: about 547 µs → 3.46 ms, about 133 matches; building the d=2 automaton builder takes about 0.6 ms → 5 ms
  - Kafka (15.8k terms): FST Get 257 ns, front-coding 359 ns, d=2 fuzzy 227 µs (native)

  — own measurement

### Inferences
- **Front coding is the better default for a downloaded dictionary.** Sorted front-coded blocks of 16–64 terms with first-term offsets match the FST's raw size, compress better under the transport zstd, are trivial to specify byte-exactly (see Q6), and support prefix and range natively. Fuzzy and regex work by walking a Levenshtein or regex DFA in step with the sorted blocks, as Lucene's IntersectTermsEnum does over BlockTree. An FST pays off mainly when the dictionary is mmapped and used without decompression, and that advantage disappears if the index is zstd-compressed and encrypted as a whole.
- **MPHF is a poor primary dictionary.** It does not support prefix, fuzzy or range queries, and it maps absent terms to arbitrary slots unless keys or fingerprints are stored. That removes most of its 2–3 bits/key advantage once the 7+ bytes/term of key material are counted. It could serve only as an exact-match accelerator.
- **The dictionary is a large share of small indexes.** At MB scale, dictionary plus metadata is 1–8% of raw text: FST 2.4% of Go src, 1.1% of Kafka email, 6.0% of logs. That is comparable to or larger than docid postings (2.5–4.7%), so dictionary format and tokenization (case folding, dropping hex IDs and timestamps from logs) matter as much as the posting codec.

### Gaps
- No published byte-per-term measurements for vellum or Lucene's 10.3 trie on standard vocabularies were found; only Lucene's relative .tip deltas.
- The size cost of turning off suffix sharing in zapx was not stated.
- Tantivy's sstable vs FST size numbers were not found.

## Q4. Index size as a fraction of raw text (docid-only, +tf, positional): Lucene, Tantivy and research measurements, and the effect of stopwords, stemming and case folding

### Takeaway
In classic and recent measurements, a compressed docid-only (or docid+tf) index takes about 5–12% of raw text. A positional index takes about 20–50%, with positions 2–4× the size of the non-positional postings. Lucene says "index size roughly 20-30% the size of text indexed." In my pure-Go measurements of fully merged indexes:
- docid-only, including dictionary: 5.1–12% of raw
- +tf: 7.0–17%
- positional: 24.5–35% (VByte, before zstd)

Small corpora (≤5 MB) land at the high end because the dictionary weighs more. Stopword removal cuts positional postings by 31–53% and docid postings much less. Case folding and stemming mainly shrink the dictionary.

### Cited Findings
- **Lucene.** The features page says: "index size roughly 20-30% the size of text indexed." Latest release is Lucene 10.6.0. — [lucene.apache.org/core](https://lucene.apache.org/core/)
- **IIR rules of thumb** (reproduced in University of Ioannina 2024 lecture slides): a positional index is 2–4 times larger than a non-positional one, and a compressed positional index is 35–50% of the original text volume, for English and similar languages. — [UoI IR slides 2024 (IIR ch. 2/5)](https://www.cse.uoi.gr/~pitoura/courses/ap/ap24/slides/statistics-compression-2024.pdf)
- **IIR, Reuters-RCV1.** 806,791 docs in about 1 GB (about 1.25 KB/doc), 391,623 terms. Non-positional postings are 400 MB uncompressed, 116 MB with variable byte and 101 MB with Elias γ, i.e. about 11.6% and 10.1% of the text. — [Princeton COS435 notes 2017](https://www.cs.princeton.edu/courses/archive/spring17/cos435/Notes/compressionSummaryPart2.pdf)
- **TREC-3 (Moffat & Zobel, as summarized in the same notes).** 1.7 GB of text, 538,244 terms. A (docid, tf) index of 1.1 GB uncompressed compresses to 184 MB (Golomb gaps + γ tf), about 10.8% of the text. — [Princeton COS435 notes](https://www.cs.princeton.edu/courses/archive/spring17/cos435/Notes/compressionSummaryPart2.pdf)
- **Effect of preprocessing (IIR Table 5.1, RCV1).** Terms (K) / non-positional postings (K) / positional postings (K):
  - Unfiltered: 484 / 109,971 / 197,879
  - No numbers: 474 (−2%) / 100,680 (−8%) / 179,158 (−9%)
  - Case folding: 392 (−17%) / 96,969 (−3%) / 179,158 (0%)
  - 30 stopwords: 391 (0%) / 83,390 (−14%) / 121,858 (−31%)
  - 150 stopwords: 391 (0%) / 67,002 (−30%) / 94,517 (−47%)
  - Stemming: 322 (−17%) / 63,812 (−4%) / 94,517 (0%)
  - Cumulative: −33% terms, −42% non-positional, −52% positional

  — [UoI slides reproducing IIR Table 5.1](https://www.cse.uoi.gr/~pitoura/courses/ap/ap24/slides/statistics-compression-2024.pdf); [IIR section](https://nlp.stanford.edu/IR-book/html/htmledition/statistical-properties-of-terms-in-information-retrieval-1.html)
- **Research systems in absolute terms (docids + freqs, no positions).** Gov2 (5.74B postings) takes 4.17–4.65 GB with the best codecs and 15.0–15.4 GB with Group Varint or Stream VByte. ClueWeb09-B (15.86B postings) takes 13.9–16.0 GB and 42–43 GB respectively. — [Mallia et al. 2019](https://research.engineering.nyu.edu/~suel/papers/daat-ecir19.pdf)
- **Elasticsearch, logs.** `match_only_text` (which drops norms, freqs and positions) gave "about 10% smaller" indices on average for application logs (Elasticsearch 7.14, 2021). — [Elastic blog, 2021-08-03](https://www.elastic.co/blog/save-10-percent-disk-space-on-your-logging-datasets-with-match-only-text). A 2026 Elastic article puts the field-level cut at "roughly 40%" of the inverted index for a text field, with the 2021 whole-index effect "only about 10%" because other structures dominate. — [Elastic Observability Labs, 2026-04-09](https://www.elastic.co/observability-labs/blog/elasticsearch-logsdb-storage-evolution)
- **Independent log benchmark (2023).** 1.74B log docs, about 1,500 GB raw:
  - Elasticsearch (`match_only_text`): about 352 GB total, of which .fdt (stored _source) is 219.35 GB, .doc 55.87 GB and .tim 10.42 GB.
  - OpenSearch (`text`): about 381 GB, with .pos 20.16 GB and .doc 63.94 GB.

  — [blunders.io, 2023-12-04](https://blunders.io/posts/es-benchmark-2-outlier-digging)
- **Tantivy (qualitative).** Per a search snippet I did not open, its author writes that without positions or stored documents an inverted index is "typically much smaller in size than the original data itself." No quantitative figure was found. — [fulmicoton, "Of tantivy's indexing"](https://fulmicoton.com/posts/behold-tantivy-part2)
- **Own measurement: full merged index as % of raw text** (VByte postings, vellum FST and df/offset metadata; no skip data, norms or stored text):
  - Go src (52.5 MB): FST 2.40 + metadata 0.69 + docids 2.50 = 5.6%; +tf 2.05 → 7.6%; +positions 17.67 → 25.3%. On the 2,000-doc subset (42 MB): 5.1 / 7.0 / 24.5%.
  - Kafka email (10.8 MB): 6.3 / 10.7 / 26.9%.
  - Lucene dev email (1.8 MB, 513 messages): 12.0 / 17.2 / 35.1%.
  - Logs (4.5 MB): 12.1 / 14.8 / 34.9%.
  - With whole-stream zstd-3, Go src docids fall from 2.50% to 1.23%, tf from 2.05% to 0.75% and positions from 17.67% to 11.64%. Kafka positions fall from 16.21% to 10.45%.

  — own measurement (corpora: [Go](https://go.dev/dl/), [dev@kafka](https://lists.apache.org/list.html?dev@kafka.apache.org), [dev@lucene](https://lists.apache.org/list.html?dev@lucene.apache.org), [Loghub](https://github.com/logpai/loghub))
- **Own measurement: stopwords** (dropping the 30 or 150 terms with the highest collection frequency):
  - Go src, top 30 (`0, v, 1, if, return, the, x, t`…): postings −4.3%, tokens −24.8%, positional bytes −21.0%, docid bytes −3.5%.
  - Go src, top 150: postings −12.8%, positional −40.7%, docid −10.5%.
  - Kafka email, top 30 (`the, to, kafka, a, apache, org, and, for`…): postings −11.7%, tokens −30.9%, positional bytes −25.6%, docid bytes −10.9%.
  - Kafka email, top 150: postings −34.2%, positional −48.1%, docid −31.8%.

  — own measurement
- **Own measurement: case folding.** Without folding, Go src has 200,914 terms vs 179,100 with folding (−10.9%), postings 1,150,345 vs 1,069,223 (−7.1%), FST 1.45 MB vs 1.26 MB (−13.1%), positional bytes −0.9%. Kafka email: terms −13.9%, postings −8.0%, FST −14.0%, positional −1.7%. — own measurement

### Inferences
- For the target corpora, a fully merged positional index will be about 25–35% of raw text before compression and about 15–17% after zstd, assuming the measured shares hold. A docid+tf index will be about 7–17% before zstd and about 4–7% after. These figures are estimated from the measured per-structure zstd ratios, with metadata left uncompressed. For a 50 MB repository that means roughly 12–13 MB positional (about 8 MB after zstd) or about 4 MB docid+tf (about 2 MB after zstd). The 2–4× positional premium in IIR and the 20–30% Lucene figure are consistent with these numbers.
- Stemming was not measured. IIR shows it cuts dictionary terms by 17% but non-positional postings by only 4% and positional postings by 0% on RCV1. It is mainly a dictionary and recall decision, not a size lever. Stemming is also a poor fit for source code and log tokens.
- Log-like and email corpora generate many unique tokens (83–84% df=1 in logs and raw MIME email), such as timestamps, hex IDs, base64 and HTML artifacts. Tokenizer hygiene (MIME decoding, HTML stripping, a cap on token length or on digit-heavy tokens) changed the index far more than any codec choice. In the first, incorrectly parsed email run, the FST alone reached 44% of raw text.

### Gaps
- No published Tantivy index-size-vs-raw measurement was found.
- Lucene's 20–30% claim has no stated corpus or settings.
- I found no 2024–2026 published measurement of positional vs non-positional Lucene indexes on English prose beyond the Elastic log numbers.
- Stemming was not tested in the harness, and email/transcript corpora closer to agent transcripts (tool output, JSON, diffs) were not tested.

## Q5. What does a phrase query require, and what is its size premium?

### Takeaway
Exact phrase and proximity queries need term positions within each document, either stored in the index (Lucene .pos/.pay, Tantivy .pos, Bleve location chunks) or recomputed by re-tokenizing candidate documents. Positions cost about 2–4× the docid+tf postings. In my corpora they were 16–20% of raw text vs 4.5–9% for docids+tf, and they compress worse. Elasticsearch's `match_only_text` shows the alternative: drop positions and verify phrases against the stored source, which is slower but "still much faster than a linear scan".

### Cited Findings
- **Lucene layout.** Lucene stores positions in .pos and payloads and offsets in .pay. Position counts follow `PackedPosBlockNum = floor(totalTermFreq/PackedBlockSize)` with a VInt tail. — [Lucene103PostingsFormat javadoc](https://lucene.apache.org/core/10_3_0/core/org/apache/lucene/codecs/lucene103/Lucene103PostingsFormat.html)
- **Tantivy layout.** Positions are optional per field ("specify in the schema that a field should store positions"). They are stored in a separate .pos file, and the reader advances by term frequency per doc. — [Tantivy ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)
- **Bleve/zap layout.** Location data per hit is field (uint16), pos, start, end, number of array positions, and each array position, all varint-encoded in chunks. That is heavier than positions alone because offsets are included. — [zapx README](https://github.com/blevesearch/zapx)
- **Elasticsearch without positions.** `match_only_text` runs phrase queries by loading `_source` only for documents that already match the other filters and all phrase terms. Phrase and intervals queries are slower but "still much faster than a linear scan"; span queries are unsupported, and scores reduce to the count of matched terms. — [Elastic blog 2021](https://www.elastic.co/blog/save-10-percent-disk-space-on-your-logging-datasets-with-match-only-text)
- **Size premium, published.** IIR: positional index 2–4× non-positional. — [UoI slides (IIR)](https://www.cse.uoi.gr/~pitoura/courses/ap/ap24/slides/statistics-compression-2024.pdf). RCV1 has 197.9M positional vs 110.0M non-positional postings (1.8× in count, before compression). — [same](https://www.cse.uoi.gr/~pitoura/courses/ap/ap24/slides/statistics-compression-2024.pdf). On logs, OpenSearch's .pos was 20.16 GB against Elasticsearch's 55.87 GB .doc and 10.42 GB .tim. — [blunders.io 2023](https://blunders.io/posts/es-benchmark-2-outlier-digging)
- **Size premium, own measurement.** Positions with VByte (bits per position, % of raw):
  - Go src: 10.18 bits, 17.67%, vs docids+tf 4.55% (3.9×)
  - Kafka email: 10.95 bits, 16.21%, vs 9.12% (1.8×)
  - Logs: 9.49 bits, 20.15%, vs 6.08% (3.3×)

  bp128 does not shrink positions: 19.09% for Go src. After zstd-3, VByte positions keep about 60–66% of their size, while docids and tf keep about 30–50%. — own measurement

### Inferences
- **A docid+tf index with phrase verification against decrypted documents is viable.** The client already holds the plaintext after decrypting the store, so phrase checks can run on candidate documents. This saves about 58–70% of index bytes relative to a positional index (merged totals: Go src 25.3% vs 7.6%, Kafka 26.9% vs 10.7%, logs 34.9% vs 14.8% of raw), at the cost of fetching and decrypting candidate documents at query time. Whether that is acceptable depends on whether the client has the documents locally or must download them per query, which is outside this topic.
- **Code search needs a different index.** Substring and regex search over code usually relies on trigram indexes (google/codesearch, zoekt) rather than word positions. That index is a different design point and was not measured here.

### Gaps
- No published measurement was found of phrase-query latency with source verification vs a positional index on small corpora.
- I did not measure biword or n-gram alternatives.

## Q6. Determinism: can the encoding be byte-identical across implementations for the same input (sorted terms, canonical docid assignment)?

### Takeaway
Yes, but only by specifying the format byte-exactly and avoiding the nondeterminism built into common engines:
- Lucene writes a random 16-byte segment ID into every file header.
- Tantivy names segments with random UUIDv4s.
- Roaring permits two serializations of the same bitmap and leaves container choice to `RunOptimize`.
- FST byte layout depends on builder heuristics (cache or registry size, suffix sharing) and can change between library versions.

With fixed rules, my Go harness produced SHA-256-identical bytes across rebuilds and across darwin/arm64 vs js/wasm for every structure, on three corpora. Cross-implementation identity (Go vs Rust vs Java) is realistic only for simple formats you specify yourself, such as VByte/FOR blocks and front-coded dictionaries.

### Cited Findings
- **Lucene.** `StringHelper.randomId()` "generates a non-cryptographic globally unique id" (ID_LENGTH 16). Lucene's postings writer passes `state.segmentInfo.getId()` to `CodecUtil.writeIndexHeader` for the meta, doc, pos, pay and terms outputs. — [StringHelper.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/util/StringHelper.java); [Lucene104PostingsWriter.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene104/Lucene104PostingsWriter.java)
- **Tantivy.** "A segment is identified by a segment id that is in fact a UUID." `create_uuid()` returns `Uuid::new_v4()`; a deterministic auto-increment variant exists for tests. — [Tantivy ARCHITECTURE.md](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md); [segment_id.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/index/segment_id.rs)
- **Roaring.** The spec states: "A bitmap without run container can be stored in two different manners… you may find two different serialization for the exact same bitmap… implementations can ensure isomorphism by, for example, always serializing bitmaps without run containers with the SERIAL_COOKIE_NO_RUNCONTAINER cookie." Array vs bitset is fixed by cardinality (≤4096 means array), but run containers appear only if the writer converts them (`RunOptimize`). — [RoaringFormatSpec](https://github.com/RoaringBitmap/RoaringFormatSpec); [roaring README](https://github.com/RoaringBitmap/roaring)
- **FSTs.** BurntSushi's builder uses a bounded cache, so output is "close to minimal but not guaranteed minimal." — [burntsushi.net/transducers](https://burntsushi.net/transducers/). vellum's registry size controls suffix sharing, and size 0 disables it (v1.2.1, 2026-11-02). Bleve/zapx just switched it off for term dictionaries. — [vellum commits](https://github.com/blevesearch/vellum/commits/master); [zapx commits](https://github.com/blevesearch/zapx/commits/master)
- **MPHF.** alecthomas/mph's latest commit is titled "Allowing seeding the builder to get reproducible data" (2024-09-04), meaning construction is randomized unless seeded. — [alecthomas/mph](https://github.com/alecthomas/mph)
- **Docid order changes size, not only identity.** URL or BP ordering shrinks Packed+ANS2 indexes by 27–43% or more vs random order. — [Mallia et al. 2019](https://research.engineering.nyu.edu/~suel/papers/daat-ecir19.pdf)
- **Own measurement.**
  - For VByte, bp128, StreamVByte, intcomp, Simple-8b, Roaring, the vellum FST and front-coded dictionaries, the SHA-256 of the output bytes was identical between darwin/arm64 native and js/wasm on Go src, Kafka email and Loghub ("ALL HASHES IDENTICAL").
  - The vellum FST rebuilt from the same sorted terms was byte-identical (`rebuild-identical=true`).
  - Inputs were sorted bytewise (Go `sort.Strings`) with docids in deterministic input order.

  — own measurement ([harness](https://github.com/blevesearch/vellum))

### Inferences
- **A canonical format is achievable with a short list of rules:**
  - terms sorted by raw bytes after a fixed, versioned normalization (Unicode normalization and case-folding tables pinned)
  - docids assigned by a canonical rule independent of merge history, e.g. a stable document key order or commit order
  - fixed block size and bit-width rule
  - VByte with minimal-length encoding
  - front-coded buckets of fixed size
  - no random IDs or timestamps inside the encrypted index
  - any Roaring use pinned to the no-run cookie, or to an explicit, deterministic run-container rule
- **Library outputs are stable only within a pinned version.** vellum and Roaring outputs are reproducible across platforms but not guaranteed across versions or ports; vellum's builder changed on 2026-11-02. A byte-exact spec owned by the project is safer than "whatever library X emits" if multiple implementations (Go client, future Rust or JS) must agree.
- **Rebuild compaction from logical content.** A compacted index should be a function of the logical document set, not of the sequence of deltas, so different clients compacting independently produce identical bytes. Docids must therefore be renumbered canonically at compaction time.

### Gaps
- Byte-identity across different implementations was not tested: Rust fst vs vellum, CRoaring vs Go roaring for the same RunOptimize policy.
- I found no published work on deterministic or reproducible inverted-index builds.

## Q7. Survey-level guidance: which codec gives the best size/speed trade-off for small, mergeable segments?

### Takeaway
The surveys decline to name a single winner ("the solution should always be determined by considering the actual data distribution"). For large lists they find a cluster with similar trade-offs (PEF, DINT, Opt-VByte, Simple16, Opt-PFor, QMX). BIC, δ and Rice are dominated, and Roaring is fastest but large. Industry engines (Lucene, Tantivy) converged on fixed-size bit-packed blocks with VByte tails, and recently on bitsets for dense blocks. For small, frequently merged segments in pure Go/wasm, that leaves a simple byte-aligned or block format (VByte, or 128-int FOR with a VByte tail, optionally bitsets for dense blocks), whole-index zstd for transport, and an aggressive compaction policy. In my measurements, 1–10-document segments inflated a docid-only index 2–8.5× and a positional index 1.2–2.8× versus the merged index, mostly through duplicated dictionaries. That is far more than any codec difference.

### Cited Findings
- **Pibiri & Venturini (2020).** "Electing a solution as the 'best' one is not generally easy… the solution should always be determined by considering the actual data distribution." "Devising 'simpler' compression formats that can be decoded with algorithms using low-latency instructions (e.g., bitwise) and with as few branches as possible, is a profitable line of research." They list "dynamic and compressed representations" supporting additions and deletions as an open direction. — [arXiv 1908.10598](https://arxiv.org/abs/1908.10598)
- **Same survey.** "There is a cluster of techniques providing similar efficiency/effectiveness trade-offs, including PEF, DINT, Opt-VByte, Simple16, Opt-PFor and QMX, whereas BIC, δ and Rice are always the slowest and dominated." — [arXiv 1908.10598](https://arxiv.org/abs/1908.10598)
- **Lemire & Boytsov.** "SIMD-BP128 is preferable in every way to varint-G8IU*, varint-G8IU, PFOR, and PFOR2008." The competitive set is SIMD-BP128, SIMD-FastPFOR, FastPFOR, Simple-8b and OptPFD "depending on how much compression is desired." Encoding speed matters for memory-based and network applications, and OptPFD and VSEncoding are about 100× slower to encode. — [arXiv 1209.2137](https://arxiv.org/abs/1209.2137)
- **Mallia et al. (2019).** "There is a clear trade-off between index size and query speed. Variable byte encoding is extremely fast, but also gains the least from reordering." Packing methods "are highly sensitive to ordering." — [ECIR 2019](https://research.engineering.nyu.edu/~suel/papers/daat-ecir19.pdf)
- **Lucene's trajectory, 2024–2025.** Inlined two-level skip data (9.12), bitset-encoded dense blocks (10.2), and 256-doc blocks for CPU efficiency (10.4): "reduces the likelihood of skipping blocks… in exchange for better CPU efficiency." — [PR #15160](https://github.com/apache/lucene/pull/15160); [CHANGES.txt](https://github.com/apache/lucene/blob/main/lucene/CHANGES.txt)
- **Own measurement: small-segment overhead.** The first N docs were split into segments of S docs. Values are the sum over segments as % of raw text, docid-only / +tf / +positions (VByte postings + vellum FST + metadata):
  - Go src (2,000 docs, 42 MB): S=1 20.1 / 22.0 / 39.5; S=10 10.9 / 12.8 / 30.3; S=100 6.7 / 8.7 / 26.2; S=1000 5.3 / 7.3 / 24.8; merged 5.1 / 7.0 / 24.5
  - Kafka email (3,000 docs, 10.7 MB): S=1 53.6 / 58.0 / 74.2; S=10 27.1 / 31.4 / 47.6; S=100 12.2 / 16.6 / 32.8; S=1000 7.2 / 11.6 / 27.8; merged 6.3 / 10.7 / 26.9
  - Logs (640 docs): S=1 31.3 / 34.0 / 54.1; merged 12.1 / 14.8 / 34.9
  - The growth is almost entirely the per-segment FST and metadata: Kafka FST is 36.1% of raw at S=1 vs 1.1% merged. With Roaring instead of VByte, docids at S=1 cost 34.6% (Go src) and 79.0% (Kafka) of raw.

  — own measurement

### Inferences
- **Per-commit deltas.** Keep them in the simplest canonical format: front-coded terms plus VByte docids, tf and positions. Since a delta is typically 1–10 documents, its index can be 1–3× the delta's own text, so compact often and on a size basis, e.g. once deltas exceed a few percent of the base. The client downloads base plus deltas, so any un-compacted tail costs bandwidth directly.
- **Compacted base.** Re-encode postings as 128- or 256-int FOR blocks with a VByte tail. Optionally switch dense blocks to bitsets, and optionally use Roaring only for lists above a length threshold. Use front-coded buckets for the dictionary. Then zstd the whole index before encryption. Measured: VByte+zstd was the smallest transport form for docids, and positions shrank by about a third.
- **The best-compression codecs are not worth it here.** BIC, PEF and ANS save at most another 20–40% of postings bytes, which zstd over VByte largely recovers for transport. They also add implementation risk: no maintained pure-Go code exists, and they are harder to specify canonically.
- **CPU is a non-issue at personal-corpus scale.** Even in a wasm worker, decoding every posting and position takes about 12 ms for the 10.8 MB Kafka index (476k postings, 1.28M positions) and about 40 ms for the 52 MB Go-source index (1.07M postings, 7.29M positions). These are estimates from the measured wasm costs of 2–8 ns per docid posting and 5–11 ns per position. Dictionary lookups take about 1.5 µs and d=2 fuzzy queries about 1.3–3.5 ms.

### Gaps
- No survey directly evaluates codecs for small, frequently merged segments or for client-side (wasm or mobile) decoding.
- Merge cost (re-encode time) per codec in Go was not measured.
- Memory high-water marks for decoding on gomobile under tens-of-MB budgets were not measured. The harness's process memory reflects the experiment, not a client.
