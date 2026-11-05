# Alternatives to word-level inverted indexes for a compact, client-downloadable E2EE search index: n-gram/trigram indexes, signature/filter indexes, succinct self-indexes

Compiled 2026-11-05. Labels used: **computed** = arithmetic I did from formulas or tables in the cited source (not a published measurement). "Repo status" lines come from the GitHub REST API (`gh api repos/...`), queried 2026-11-05.

## Cross-family comparison (objective): size vs text, query types, false positives, update/merge, deletion, pure-Go availability

### Takeaway
Three families are small enough for a client to download the whole index:
- **Compressed doc-level inverted files:** about 6–8 bits per (term, doc) posting, or about 2–8% of text on Gov2.
- **Per-document filters:** about 10–12 bits per unique term per document at a 0.4% false-positive rate (FPR).
- **Non-positional trigram indexes:** about 18–20% of source. The candidate files still have to be checked against the content.

Two families are too large or too hard to build on a client:
- **Positional trigrams (zoekt):** about 3.5x the corpus, content included.
- **FM-index and compressed-suffix-array self-indexes:** 0.3–0.8x the text, and they replace the text. They are exact. But they are static and need 5–9x the text in RAM to build (measured in 2007). The pure-Go implementations are small and have not been updated since 2023.

### Cited Findings
- Non-positional trigram index (codesearch): the Linux 3.1.3 sources, "a total of 420 MB, creates a 77 MB index"; the index "tends to be around 20% of the size of the files being indexed" (Jan 2012) — [Cox, Regular Expression Matching with a Trigram Index](https://swtch.com/~rsc/regexp/regexp4.html)
- Positional trigram index (zoekt): "about 3x the corpus size, composed of 2x (offsets), and 1x (original content)"; shards are "about 3.5x the corpus size"; search "only requires 1.2x corpus size of RAM" — [zoekt doc/design.md](https://github.com/sourcegraph/zoekt/blob/main/doc/design.md)
- GitHub Blackbird uses sparse n-grams. Its corpus is 115 TB of code, 28 TB after dedup. The index is 25 TB, "including all indices and a compressed copy of the unique content" (roughly a quarter of the original data). Published Feb 6, 2023 — [GitHub blog, The technology behind GitHub's new code search](https://github.blog/engineering/architecture-optimization/the-technology-behind-githubs-new-code-search/)
- Bit-sliced signatures (BitFunnel, SIGIR 2017), measured on Gov2 shards: 11.69–38.43 bits per posting at false-positive rates of 1.62–4.32%. Partitioned Elias-Fano (PEF) inverted indexes on the same shards: 6.15–7.64 bits per posting with 0% false positives — [BitFunnel paper, Table 3](https://danluu.com/bitfunnel-sigir.pdf)
- Modern static filters: xor filters are "within 23% of the theoretical lower bound in storage as opposed to 44% for Bloom filters". Binary fuse filters are within 13% (3-wise), or within 8% if you accept slower queries (4-wise) — [Graf & Lemire, Binary Fuse Filters, arXiv 2201.01174 / JEA 27, 2022](https://arxiv.org/abs/2201.01174)
- Ribbon filters: below 10% overhead with some extra CPU time, and below 1% for the experimental load-balanced design — [Dillinger & Walzer, arXiv 2103.02515, Mar 2021](https://arxiv.org/abs/2103.02515)
- FM-index / compressed suffix array (CSA), measured on 200 MB texts:
  - Count-only: 0.28–0.74 of the text.
  - Count plus locate and extract: "within 40%–80% of its original size".
  - Plain suffix array: 5x the text.
  - The index includes the text.
  - Construction needs 5–9x the text size in memory.
  - Source: [Ferragina, González, Navarro, Venturini, Compressed Text Indexes: From Theory to Practice, arXiv 0712.3360](https://arxiv.org/abs/0712.3360) (PDF: [arxiv.org/pdf/0712.3360](https://arxiv.org/pdf/0712.3360))
- Inverted files versus signature files: inverted files "are distinctly superior to signature files". They answer typical queries in less time, need less space, and provide greater functionality (ACM TODS 23(4), 1998) — [Zobel, Moffat, Ramamohanarao abstract](https://people.eng.unimelb.edu.au/ammoffat/abstracts/zmr98acmtods.html)
- Go availability (repo status, 2026-11-05):

  | Library | Language, license | Status |
  |---|---|---|
  | google/codesearch | Go, BSD-3-Clause | last push 2026-08-30 |
  | sourcegraph/zoekt | Go | last push 2026-11-03; google/zoekt is archived (last push 2024-01-16) |
  | FastFilter/xorfilter | Go, Apache-2.0 | tag v0.5.1, last push 2026-11-03 |
  | RibbonFilter/ribbonGo | Go | 15 stars, last push 2026-08-01 |
  | shenwei356/bwt | Go, MIT | v0.6.1, last push 2023-04-07 |
  | rossmerr/fm-index | Go, MIT | last push 2023-03-05 |
  | BitFunnel/BitFunnel | C++, MIT | last push 2022-01-04 |
  | tinysearch/tinysearch | Rust, Apache-2.0 | last push 2026-09-14 |

  Sources: [google/codesearch](https://github.com/google/codesearch), [sourcegraph/zoekt](https://github.com/sourcegraph/zoekt), [google/zoekt](https://github.com/google/zoekt), [FastFilter/xorfilter](https://github.com/FastFilter/xorfilter), [ribbonGo](https://github.com/RibbonFilter/ribbonGo), [shenwei356/bwt](https://github.com/shenwei356/bwt), [rossmerr/fm-index](https://github.com/rossmerr/fm-index), [BitFunnel](https://github.com/BitFunnel/BitFunnel), [tinysearch](https://github.com/tinysearch/tinysearch)
- The Go standard library has a pure-Go suffix array, `index/suffixarray`. It does "substring search in logarithmic time using an in-memory suffix array", builds in O(N), and has regexp `FindAllIndex` (docs shown for go1.27.3) — [pkg.go.dev/index/suffixarray](https://pkg.go.dev/index/suffixarray)

### Inferences
Comparison matrix. This is my synthesis. Numbers link to their sources, and "computed" means derived by me.

| Family | Size vs text (measured unless noted) | Query types | False positives | Incremental update / merge | Deletion / erasure | Pure Go (2026) |
|---|---|---|---|---|---|---|
| Non-positional trigram (codesearch) | ~18% of source; content not included ([Cox](https://swtch.com/~rsc/regexp/regexp4.html)) | regex via trigram AND/OR plan; substring; prefix as substring; no ranking | candidates are a superset, checked by running the regex on the content | appends by default; `Merge(dst, src1, src2)` merges two indexes without reading source files ([merge.go](https://raw.githubusercontent.com/google/codesearch/master/index/merge.go)) | no per-file delete; a newer index that covers the same root replaces old entries at merge time | yes (codesearch) |
| Positional trigram (zoekt) | ~3x (2x offsets + 1x content); ~3.5x per shard ([design.md](https://github.com/sourcegraph/zoekt/blob/main/doc/design.md)) | substring, regex, boolean, symbols; code-aware ranking + BM25 | positions cut candidates; still checked against content | full per-repo rebuild, or delta shards + file tombstones; compound-shard merge re-indexes stored content ([builder.go](https://github.com/sourcegraph/zoekt/blob/main/index/builder.go), [merge.go](https://github.com/sourcegraph/zoekt/blob/main/index/merge.go)) | tombstones (per file in deltas, per repo in compound shards); bytes are removed only at full rebuild or merge | yes (sourcegraph/zoekt) |
| Per-document filters (Bloom / xor / binary fuse) | **computed:** 645–768 B per 500-term document at FPR ~0.39%; 1.3–1.5 KB at ~0.0015% | exact-term membership; AND/OR; prefix or substring only if prefixes or n-grams are inserted as keys; no term-frequency ranking | per-term per-document FPR ε; NOT is unsafe | segments are concatenations of independent filters; no recomputation | drop the document's filter → gone at the next compaction | yes (FastFilter/xorfilter) |
| Bit-sliced signatures (BitFunnel) | 11.7–38.4 bits per posting vs PEF 6.2–7.6 ([paper](https://danluu.com/bitfunnel-sigir.pdf)) | conjunctive matching; ranking done downstream (forward index with term frequencies) | 1.6–4.3% of results | rows are shared across documents (see deletion section) | not described in the paper (gap) | no (C++) |
| FM-index / CSA | 0.28–0.74 count-only; 0.4–0.8 with locate/extract; **includes the text** ([JEA paper](https://arxiv.org/abs/0712.3360)) | exact substring count, locate, extract | none (exact) | static; 1–4 s/MB and 5–9x text RAM to build; BWT merge tools exist for DNA | rebuild | only small libraries, last updated 2023 |
| Plain suffix array | 5x text, text included ([JEA paper](https://arxiv.org/abs/0712.3360)) | substring; Go stdlib regexp accelerated only through a literal prefix | none | rebuild, O(N) | rebuild | yes (stdlib) |
| Doc-level inverted file (PEF), the baseline | 6.15–7.64 bits per posting; **computed** 1.6–7.8% of Gov2 input text | word AND/OR; ranking needs term frequencies stored separately | none | posting-list concatenation with document-ID remapping | tombstones, then compaction | n/a (the baseline from the other research thread) |

- For a client that downloads the whole index, the realistic shortlist is:
  1. Doc-level word postings for prose and email.
  2. Non-positional trigram postings for code and logs.
  3. Per-document xor filters, if per-document independence (trivial merge and erasure) matters more than about 1.5–3x extra size and false positives.
- Positional trigram indexes and self-indexes are best treated as optional, locally built accelerators, not as the shipped index format.

### Gaps
- I found no measured head-to-head of all families on one corpus. The numbers come from different corpora (Linux, Gov2, Pizza&Chili) and different hardware generations (2007–2017).
- I could not get the full text of Zobel et al. 1998, so its numeric results (index sizes as a percentage of text, disk accesses) are missing.

## Trigram indexes for code: codesearch and zoekt (format, positional trigrams, shards, size vs source, memory, speed, Sourcegraph fork). What fraction of the corpus are they, and do zoekt shards update incrementally?

### Takeaway
- Russ Cox's codesearch index stores document IDs only, with no positions. It measures about 18–20% of the source (420 MB of Linux source gives a 77 MB index) and needs the content to verify candidates.
- zoekt stores positional trigrams plus the content: about 3x the corpus for the index, about 3.5x per shard, and 1.2x the corpus in RAM.
- zoekt shards are immutable. Updates are either a full per-repository rebuild or "delta shards" stacked on older shards, which get path-level tombstones in their metadata.
- Merging shards into compound shards re-indexes the stored content.

### Cited Findings
**codesearch (Cox, January 2012; Google Code Search ran from Oct 5, 2006 until its shutdown was announced in Oct 2011)** — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)

Size and structure:
- On Linux 3.1.3 (36,972 files, 420 MB) the index is 77 MB. The index "tends to be around 20% of the size of the files being indexed" — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)
- The index holds a list of paths, a list of indexed files, and one posting list of document IDs per trigram. The trigram example stores no positions, unlike the word index example, which stores positions for phrase queries — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)
- Trigrams were chosen because there are "too few distinct 2-grams and too many distinct 4-grams" — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)
- `csearch` maps the index with mmap. `cindex` skips files with invalid UTF-8, very long lines, or very many distinct trigrams; the article gives no thresholds — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)

Query planning:
- Regexes become boolean trigram queries. Concatenation becomes AND, alternation becomes OR, and strings shorter than 3 characters become ANY (no filtering).
- `/Google.*Search/` becomes `Goo AND oog AND ogl AND gle AND Sea AND ear AND arc AND rch`.
- `ab[cd]e` gives a choice: the exact form (abc AND bce) OR (abd AND bde), or the cheaper and less precise (abc OR abd) AND (bce OR bde).
- Source: [Cox](https://swtch.com/~rsc/regexp/regexp4.html)

Measured speed (Linux 3.1.3):
- `hello world`: 25 candidate files, 0.01 s real, against 1.96 s for brute force ("about 100x").
- Case-insensitive `hello world`: 599 candidates, 0.08 s, against 1.59 s. The excerpt lists about 10 matching files, so most candidates are false positives (my reading of the excerpt).
- `DATAKIT` in /usr/include: 3 candidates, all of them matches.
- Source: [Cox](https://swtch.com/~rsc/regexp/regexp4.html)

Current on-disk format (read.go on master):
- Paths are sorted and prefix-compressed, and every 16th name has prefix length 0 so random access is possible.
- Each posting list is a 3-byte trigram followed by "[γ-coded] deltas between file IDs", "ending with a zero delta".
- The posting-list index stores the file count and offset as varints.
- The trailer ends with `"\ncsearch trlr 2\n"`. The older version 1 used uvarint deltas.
- Source: [codesearch index/read.go](https://raw.githubusercontent.com/google/codesearch/master/index/read.go)

Updates and merging:
- `cindex` adds to an existing index by default. Running it with no arguments rescans and rewrites the index — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)
- `Merge` "creates a new index in the file dst that corresponds to merging the two indices src1 and src2". "If both src1 and src2 claim responsibility for a path, src2 is assumed to be newer and is given preference."
  - File IDs are renumbered through `idrange{lo,hi,new}` maps.
  - It reads only the two index files, never the source files.
  - It makes sequential passes over names and posting lists, which suggests linear cost; that is an inference from the code, not a documented bound.
  - Source: [codesearch index/merge.go](https://raw.githubusercontent.com/google/codesearch/master/index/merge.go)

**zoekt (design doc on sourcegraph/zoekt main)** — [design.md](https://github.com/sourcegraph/zoekt/blob/main/doc/design.md)

Goals and size:
- The goal is "sub-50ms results on large codebases, such as Android (~2G text) or Chrome" on one Linux machine with an SSD.
- The positional trigram index is about 3x the corpus (2x offsets, 1x original content). A shard is about 3.5x the corpus, including content, posting lists and metadata. Search needs 1.2x the corpus in RAM.
- Positional trigram example: "banana" gives "ban": 0, "ana": 1,3, "nan": 2.

Shard limits:
- All offsets are uint32, so a shard "should be below 4G", which caps content at "1G" per shard.
- "a single goroutine searches all documents" in a shard, so larger shards mean less parallelism.

Query handling:
- Regexes are reduced to literal substrings for index lookup, and candidates are then checked with the full regex.
- Each query needs at least one positive atom; negations only prune.
- Case-insensitive search expands all case variants of the term.

Encoding and branches:
- Offsets are rune offsets, with a rune-to-byte table stored "every 100 runes"; pure-ASCII corpora skip it.
- Each blob carries a branch bitmask, so similar branches add "little space overhead".

Ranking and building:
- Ranking signals include atoms matched, proximity, word boundaries, symbol definitions and file recency. BM25 is available through `UseBM25Scoring`.
- The design doc says construction "can easily be made incremental" and that multiple repositories can be merged into one compound shard.

**zoekt in practice (sourcegraph/zoekt source, fetched 2026-11-05)**
- Repository status: google/zoekt is archived (last push 2024-01-16). sourcegraph/zoekt is the maintained fork (last push 2026-11-03, about 2,030 stars, no tagged releases) — [GitHub API: google/zoekt](https://github.com/google/zoekt), [sourcegraph/zoekt](https://github.com/sourcegraph/zoekt)
- Full builds: "Non-delta shard builds delete all existing shards before they write out new ones."
- Delta builds:
  - "delta shard builds work by stacking changes on top of existing shards."
  - Delta shard numbers start after the most recent shard.
  - `MarkFileAsChangedOrRemoved(path)`: "If this build is a delta build, these files will be tombstoned in the older shards for this repository."
  - "delta shard builds don't support repositories contained in compound shards".
  - Source: [zoekt index/builder.go](https://github.com/sourcegraph/zoekt/blob/main/index/builder.go)
- Tombstone metadata: `FileTombstones` is "a set of file paths that should be ignored across all branches in this shard". The repository-level `Tombstone` field means "we are not allowed to search this repo" — [zoekt api.go](https://github.com/sourcegraph/zoekt/blob/main/api.go). Repository tombstones are set in the shard's `.meta` sidecar file — [zoekt index/tombstones.go](https://github.com/sourcegraph/zoekt/blob/main/index/tombstones.go)
- Compound-shard merge: `Merge(dstDir, files...)` builds a compound shard. The internal `merge()` skips tombstoned repositories. For every surviving document it calls `readContents(docID)` and re-adds the document through `ShardBuilder.Add`, so trigram postings are recomputed from the stored content. `Explode` splits a compound shard back into one shard per repository — [zoekt index/merge.go](https://github.com/sourcegraph/zoekt/blob/main/index/merge.go). The `cmd/zoekt-merge-index` command exists — [zoekt cmd/](https://github.com/sourcegraph/zoekt/tree/main/cmd)
- Delta admission PR: sourcegraph/zoekt PR #1050, "Add stats-v1 delta admission and branch-aware Git indexing", has been open since 2026-04-25. It estimates the size of a candidate delta and tracks "tombstone pressure and shard fanout" so it can fall back to a full build — [PR #1050](https://github.com/sourcegraph/zoekt/pull/1050) (status from the GitHub API; description from a search-result summary)
- GitLab: GitLab's zoekt indexer uses incremental (delta) indexing. One merge request traced missing search data to an unset `IsDelta` flag and added integration tests — [gitlab-zoekt-indexer MR 33](https://gitlab.com/gitlab-org/gitlab-zoekt-indexer/-/merge_requests/33) (search-result summary)

**GitHub Blackbird (Feb 6, 2023)** — [GitHub blog](https://github.blog/engineering/architecture-optimization/the-technology-behind-githubs-new-code-search/)
- Scale: 45M repositories, 115 TB, 15.5B documents. After dedup there are 28 TB of unique content; the index is 25 TB including compressed content.
- Latency: per-shard p99 is about 100 ms.
- Ingest: about 120,000 docs/s. A full re-index takes about 18 h with delta indexing, against about 36 h without.
- Sharding is by Git blob SHA.
- Trigrams produced too many false positives for common grams at this scale, so Blackbird uses "sparse grams": variable-length grams chosen from bigram weights, with only the covering grams used at query time.
- Deletions are handled at compaction.

### Inferences
- **Fraction of corpus.**
  - Non-positional trigram index: about 0.18–0.20x source, excluding content ([Cox](https://swtch.com/~rsc/regexp/regexp4.html)).
  - Positional (zoekt): about 2x for offsets alone, about 3.5x per shard with content. That is roughly 10x the non-positional index before content.
  - GitHub's index with compressed content is about 0.89x of unique content (25/28 TB, computed) and about 0.22x of the raw corpus (25/115 TB, computed).
- **Trigram plus content download.** Trigram filtering only produces candidates, so the client also needs the content locally to verify. Compressed source runs about 0.19–0.22x (bzip2/gzip on the JEA "sources" file: 1.493 and 1.790 bits per character, [JEA Table 3](https://arxiv.org/pdf/0712.3360)). A trigram index plus compressed content therefore comes to roughly 0.4x of raw source (computed).
- **Zoekt deltas are append-only plus tombstones.** Deleted files' content and postings stay in older shard bytes until a full rebuild or merge. PR #1050 adding "tombstone pressure" heuristics suggests that deltas build up a cost that eventually forces full rebuilds.
- **Fit with per-commit deltas.** Zoekt's model maps directly onto "each commit appends an encrypted delta; compact later":
  - delta shard ≈ commit delta;
  - FileTombstones ≈ per-commit removals;
  - full rebuild or merge ≈ compaction.
- **What does not fit.** The 3.5x size and the 1 GB-per-shard limit make zoekt's file format wrong for whole-index download. Its design, delta-plus-tombstone layering and query planner are reusable ideas.

### Gaps
- zoekt's design doc gives targets and approximate size ratios, not benchmark tables. I found no current (2025–2026) Sourcegraph measurements of shard size or memory per GB of code.
- I did not locate cindex's exact thresholds (line length, trigram count).
- Blackbird's split between posting lists and stored content is not published.

## Signature files and per-document filters: tinysearch, BitFunnel, Zobel/Moffat/Ramamohanarao 1998, xor / binary fuse / ribbon filters and their Go implementations. How large is a per-document filter index at about 500 unique terms per document, how are false positives verified, and how do AND/OR work?

### Takeaway
- At 500 unique terms per document, a static per-document filter costs about 645 B (xor8) to 768 B (binary fuse 8) at FPR ≈ 0.39%, and about 1.3–1.5 KB at 16-bit fingerprints (computed from FastFilter's Go code). That is roughly 1.5–3.7x a compressed doc-ID inverted file (about 414 B per document at 6.63 bits per posting).
- Binary fuse filters lose their space advantage at small set sizes because of a small-n size factor (1.43x at n = 500). That leaves xor8 the smallest static choice per document.
- The false-positive rate per term per document matters a lot: over 100k documents, a single-term query yields about 391 false-positive documents at 8-bit fingerprints, against about 1.5 at 16-bit.
- BitFunnel (Bing) measured 1.6–4.3% false positives at 1.9–5x the bits per posting of PEF.

### Cited Findings
**tinysearch** (Rust to WASM; README as of 2026)
- The default "exact indexer" is "one sorted vocabulary with exact posting lists", with document IDs delta- and varint-encoded. An optional `xor8` indexer builds "smaller probabilistic per-article filters" — [tinysearch README](https://github.com/tinysearch/tinysearch)
- The project is described as a port of code from an article about Bloom filters. So Bloom filters were the original design, but the current default is exact postings — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Measured: endler.dev's 73 posts give "179 kB (83 kB gzipped, 72 kB Brotli-compressed)". Rule of thumb: "around 2 kB uncompressed per article (~1 kb compressed)" — [tinysearch README](https://github.com/tinysearch/tinysearch)
- Prefix search works from 3 characters in the default indexer. xor8 "only supports prefixes in titles", and body text needs complete words. Exact indexes "do not introduce probabilistic false positives". The README gives no FPR for xor8 — [tinysearch README](https://github.com/tinysearch/tinysearch)

**BitFunnel** (Goodwin, Hopcroft, Luu, Clemmer, Curmei, Elnikety, He; SIGIR 2017, DOI 10.1145/3077136.3080789) — [paper PDF](https://danluu.com/bitfunnel-sigir.pdf)

Production context:
- "For the past 4 years, BitFunnel has powered Bing's fresh index of recently crawled documents" on thousands of machines.
- Compared with the inverted-list system it replaced, BitFunnel "improved server query capacity by a factor of 10".

Mechanism:
- Each document's signature is a Bloom filter of its terms.
- Bit-sliced layout: each document is a column and each bit position is a row, so a conjunctive query ANDs only the rows its terms hash to.
- Bit-sliced blocked signatures put several documents per column (shorter rows). This adds noise ("unsuccessful block match").

The paper's three innovations:
1. Higher rank rows. A rank-r row has blocking factor 2^r and is ANDed through "rank-0 equivalent" rows.
2. Frequency-conscious signatures, which use a different number of rows per term frequency class.
3. Sharding by document length, meaning by unique-term count.

Hash count needed for signal-to-noise ratio φ = 10 at bit density d = 0.1 (rare terms need more hashes):

| Term frequency s | Hashes k |
|---|---|
| 0.1 | 1.95 |
| 0.01 | 3.00 |
| 0.001 | 4.00 |
| 0.0001 | 5.00 |
| 0.00001 | 6.00 |

Corpus (TREC Gov2, terms lowercased, not stemmed):

| Shard | Unique terms per doc | Docs | Postings | Input text |
|---|---|---|---|---|
| A | 64–127 | 5.870M | 563M | 6.85 GB |
| B | 128–255 | 7.545M | 1,411M | 25.48 GB |
| C | 256–511 | 3.726M | 1,268M | 21.02 GB |
| D | 1,024–2,047 | 0.494M | 687M | 22.89 GB |
| E | 2,048–4,095 | 0.157M | 432M | 20.26 GB |

Experiment setup: 4.0 GHz i7-6700, 32 GB, 8 threads, about 98k TREC 2006 efficiency queries, φ = 10.

Table 3 (BitFunnel vs PEF; PEF had 0.00% false positives on every shard):

| Shard | BitFunnel QPS | BitFunnel FP | BitFunnel bits/posting | PEF QPS | PEF bits/posting |
|---|---|---|---|---|---|
| A | 21,427 | 1.62% | 38.43 | 14,675 | 7.64 |
| B | 8,674 | 4.32% | 20.72 | 5,049 | 7.33 |
| C | 12,722 | 3.88% | 16.91 | 3,959 | 6.63 |
| D | 57,014 | 2.43% | 13.69 | 8,268 | 6.25 |
| E | 105,782 | 2.64% | 11.69 | 13,151 | 6.15 |

Lucene ran at 3,011–6,310 QPS.

Table 2 (shard D, density 0.15):
- Classic bit-sliced signatures: 46.7 bits per posting, 9.1k QPS.
- With frequency-conscious signatures: 14.7 bits per posting, 24.0k QPS (3.2x smaller, 2.6x faster).
- Full BitFunnel: 13.7 bits per posting, 57.0k QPS. Its DQ (queries per second divided by bits per posting) is 21x that of classic bit-sliced signatures.

Comparison notes from the paper:
- "in Corpus A, BitFunnel uses 5x as many bits per posting while yielding a false positive rate of 1.62%".
- In shard C it shows "3.2x the QPS of PEF while using only 2.6x the space".

False positives and ranking:
- BitFunnel only solves conjunctive matching.
- In web search "the cost of filtering out false positives is negligible", because a downstream ranker scores every candidate anyway.
- "The version of BitFunnel used by Bing includes a forward index with term frequencies used for BM25F ranking". False positives are therefore weeded out with a per-document forward index, not by re-reading raw documents.

**Classic comparison**
- Zobel, Moffat & Ramamohanarao (ACM TODS 23(4):453–490, 1998): "inverted files are distinctly superior to signature files". They evaluate typical queries in less time, need less space, and provide greater functionality — [abstract page](https://people.eng.unimelb.edu.au/ammoffat/abstracts/zmr98acmtods.html), [dblp](https://dblp1.uni-trier.de/rec/journals/tods/ZobelMR98.html)
- An earlier VLDB 1992 paper by Zobel, Moffat and Sacks-Davis reported that "bit sliced signature files require at least as many disc accesses" as their compressed inverted files — [VLDB 1992 P353](https://www.vldb.org/conf/1992/P353.PDF) (quoted from a search-result excerpt; I did not read the full text)
- Counterpoint: TopSig (Geva & De Vries, CIKM 2011) argues that newer signature methods can match inverted-file systems — [arXiv 1204.5373](https://arxiv.org/pdf/1204.5373)

**Modern filters**
- Xor filters: within 23% of the storage lower bound log2(1/ε); Bloom filters: 44% — [binary fuse paper](https://arxiv.org/abs/2201.01174)
- Binary fuse filters (Graf & Lemire, JEA 27, 2022): within 13% of the bound, within 8% with slightly slower queries; construction "more than twice as fast" as xor filters — [arXiv 2201.01174](https://arxiv.org/abs/2201.01174)
- Ribbon filters (Dillinger & Walzer, Mar 2021): for f ≥ 2^-4, practical filters need at least 20% overhead. Ribbon gets below 10% with some extra CPU, and the load-balanced design gets below 1%. It is especially competitive for f ≥ 2^-7 — [arXiv 2103.02515](https://arxiv.org/abs/2103.02515)

**FastFilter/xorfilter (Go, Apache-2.0, v0.5.1)**

README:

| Fingerprint | FPR | Memory |
|---|---|---|
| 8-bit binary fuse (default) | about 0.39% | "less than 9 bits per entry for sizeable sets"; more per key for small sets |
| 16-bit | 0.0015% | about 18 bits per key |
| 32-bit (not recommended) | 2e-08% | about 36 bits per key |

- Generic `NewBinaryFuse[T]` supports uint8, uint16 and uint32.
- `Save` / `Load` use a portable, endian-neutral format, but "There is not data integrity check".
- Construction "needs many bytes of memory per set entry".
- Source: [FastFilter/xorfilter](https://github.com/FastFilter/xorfilter)

Binary fuse sizing code (arity 3):
- Segment length: `1 << floor(ln(n)/ln(3.33) + 2.25)`, capped at 262144.
- Size factor: `max(1.125, 0.875 + 0.25*ln(1e6)/ln(n))`.
- Capacity: `round(n*sizeFactor)`.
- The array length is rounded up to whole segments.
- The seed starts from `rngcounter := uint64(1)` through splitmix64, and construction retries with a new seed on failure, up to `MaxIterations`.
- Duplicate keys are pruned, and pruning mutates the input slice.
- Source: [binaryfusefilter.go](https://raw.githubusercontent.com/FastFilter/xorfilter/master/binaryfusefilter.go)

Xor8 sizing code:
- Capacity: `32 + ceil(1.23*n)`, rounded down to a multiple of 3; BlockLength = capacity/3.
- The seed comes from a constant `rngcounter = 1`.
- Duplicates are removed at iteration 10.
- `MaxIterations` defaults to 1024.
- Source: [xorfilter.go](https://raw.githubusercontent.com/FastFilter/xorfilter/master/xorfilter.go)

**Other implementations**
- A Go ribbon filter exists: RibbonFilter/ribbonGo ("practically smaller than Bloom and Xor"), with 15 stars and last push 2026-08-01 — [ribbonGo](https://github.com/RibbonFilter/ribbonGo)
- Production precedent for logs: VictoriaLogs (Go) checks per-block token Bloom filters.
  - The Oct 2024 storage format v1 splits Bloom and value data into shards (8, later adjusted per part by column count), because reads happen in blocks of at least 4 KiB (usually 64–512 KiB).
  - Older v0 parts are converted during background merges.
  - A 2024 fix stopped OR filters from wrongly skipping blocks because of common tokens.
  - Source: [VictoriaMetrics lib/logstorage mirror](https://forge.k3s.fr/github-mirrors/VictoriaMetrics/commits/branch/master/lib/logstorage/part.go), [CHANGELOG mirror](https://forge.k3s.fr/github-mirrors/VictoriaMetrics/commits/commit/b82e2cabc53220f963e99f594e50ead5a6418981/docs/VictoriaLogs/CHANGELOG.md) (secondhand: a mirror of the repository, read through search summaries)

### Inferences
**Per-document filter size (computed from FastFilter's Go formulas above, and the optimal Bloom size m = −n·ln ε/(ln 2)²).** Values are bytes per document, with bits per key in parentheses; the small fixed header (seed and segment parameters) is excluded.

| unique terms n | xor8 | binary fuse 8 | Bloom ε=1/256 (k≈8) | Bloom ε=1% | xor16 | binary fuse 16 | Bloom ε=2⁻¹⁶ |
|---|---|---|---|---|---|---|---|
| 100 | 153 (12.2) | 192 (15.4) | 144 (11.5) | 120 (9.6) | 306 (24.5) | 384 (30.7) | 289 (23.1) |
| 500 | **645 (10.3)** | **768 (12.3)** | 721 (11.5) | 599 (9.6) | 1,290 (20.6) | 1,536 (24.6) | 1,443 (23.1) |
| 1,000 | 1,260 (10.1) | 1,408 (11.3) | 1,443 (11.5) | 1,198 (9.6) | 2,520 (20.2) | 2,816 (22.5) | 2,885 (23.1) |
| 10,000 | 12,330 (9.9) | 12,800 (10.2) | 14,427 (11.5) | 11,981 (9.6) | 24,660 (19.7) | 25,600 (20.5) | 28,854 (23.1) |
| 1,000,000 | (9.84) | (9.04) | (11.5) | (9.6) | (19.7) | (18.1) | (23.1) |

- Binary fuse's advantage appears only at large n. At n = 500 its size factor is 1.431 with a segment length of 128, which makes it larger than xor8 and even than Bloom at the same FPR. For per-document filters, xor8/xor16 are the smallest static choices. Bloom at 1% is smaller still, but with 2.6x the FPR.
- Whole-corpus size for 100k documents × 500 unique terms:

  | Structure | Size |
  |---|---|
  | xor8 | 64.5 MB |
  | binary fuse 8 | 76.8 MB |
  | Bloom ε=1/256 | 72.1 MB |
  | xor16 | 129 MB |
  | binary fuse 16 | 154 MB |
  | Doc-ID inverted file at PEF's 6.63 bits per posting | 41.4 MB |
  | BitFunnel at shard C's 16.91 bits per posting | 105.7 MB |

  At 1M documents, multiply by 10.
- Relative to text, the closest measured analogue is BitFunnel shard C (256–511 unique terms per document): **computed** 12.8% of input text for BitFunnel against 5.0% for PEF. Across shards A–E, BitFunnel is 3.1–39.5% of input text and PEF is 1.6–7.8%.
- **False positives scale with corpus size.** A filter reports a document lacking term t with probability ε, so a single-term query over N documents returns about N·ε false documents:

  | N documents | 8-bit fingerprints | 16-bit fingerprints | Bloom 1% |
  |---|---|---|---|
  | 100k | ~391 | ~1.5 | ~1,000 |
  | 1M | ~3,906 | ~15 | ~10,000 |

  - AND of k terms: documents missing every term match falsely with probability ε^k, but documents missing just one term still match with probability ε, so FPs concentrate on near-misses.
  - OR: FPs add up, roughly k·N·ε.
  - NOT: unsafe. A false positive on the excluded term wrongly drops a true match, which is a false negative. NOT must therefore prune only after verification, the same rule as zoekt's "negations only prune".
- **Verification options in an E2EE client:**
  - (a) A per-document forward index of term IDs, as Bing does. It is exact but costs more than the filter.
  - (b) Decrypt locally cached documents.
  - (c) Fetch candidate blobs from the server. This adds bandwidth and reveals which objects were candidates.

  Moving from 8- to 16-bit fingerprints (about 2x the size) cuts the number of candidates to verify by 256x.
- **Query cost.** Per-document filters force a linear probe across all N filters, about 3 memory accesses per term per document. With 100k documents that is about 300k probes per term; this is an estimate, not measured in Go.
- **Bit-sliced alternative.** Transposing fixed-size per-document Bloom filters into BitFunnel-style rows makes AND read only the query's rows (N bits each, about 12.5 KB per row at 100k documents). The cost is that all documents in a slice must share m and the hash functions, so shards must be grouped by document length.
- **Ranking.** No filter family gives term frequencies. BM25 needs a separate term-frequency store, which is what BitFunnel's downstream forward index does.

### Gaps
- I found no published measurements of Go filter probe throughput on mobile or WASM.
- I could not confirm whether FastFilter output bytes are independent of key order for the same key set.
- The BitFunnel paper does not describe deletion or updates.
- I could not get the numeric tables from Zobel et al. 1998.
- tinysearch's xor8 false-positive rate, and whether it verifies hits, are not documented.

## Succinct self-indexes (FM-index, compressed suffix arrays): space relative to the text they replace, substring search speed, construction cost and memory, dynamic or incremental variants, Go implementations

### Takeaway
- FM-indexes and CSAs store the text inside the index. They take 0.28–0.74 of the text for count-only use and 0.4–0.8 with locate and extract, against 5x for a plain suffix array.
- Counting is fast: 20k–50k patterns of 20 characters per second on 2007 hardware. Locating occurrences is 100–1000x slower than a plain suffix array (about 100k occurrences per second).
- Construction needs 5–9x the text in RAM.
- Dynamic and mergeable BWTs exist only in bioinformatics tools.
- The r-index (O(r) space, where r is the number of BWT runs) is the theoretical match for highly repetitive, versioned collections.
- Pure Go offers only the stdlib plain suffix array and small FM-index libraries last updated in 2023.

### Cited Findings
**Measurements: Ferragina, González, Navarro, Venturini** (arXiv 0712.3360, Dec 2007; Pizza&Chili indexes on a 2.6 GHz Pentium 4 with 1.5 GB, gcc 4.0.2, 200 MB texts) — [arXiv](https://arxiv.org/abs/0712.3360), [PDF](https://arxiv.org/pdf/0712.3360)

Older full-text indexes needed "several times the size of the text" — [arXiv abstract](https://arxiv.org/abs/0712.3360)

Table 6, counting (time in µs per pattern character / space as a fraction of the text, count-only structures):

| Text | SSA | AF-FMI | CSA | LZ-index | plain suffix array |
|---|---|---|---|---|---|
| english | 2.147 / 0.60 | 2.694 / 0.42 | 4.758 / 0.44 | 68.774 / 1.27 | 0.512 / 5 |
| sources (C/Java from linux-2.6.11.6 + gcc-4.0.0) | 2.635 / 0.72 | 2.946 / 0.49 | 4.345 / 0.38 | 162.444 / 1.27 | 0.499 / 5 |
| xml | 2.764 / 0.69 | 2.256 / 0.34 | 4.321 / 0.29 | 306.711 / 0.71 | 0.605 / 5 |
| dna | 0.956 / 0.29 | 1.914 / 0.28 | 5.220 / 0.46 | — | 0.542 / 5 |

The plain suffix array "is 2–6 times faster than any compressed index, but its space occupancy can be up to 18 times larger". Source: [PDF](https://arxiv.org/pdf/0712.3360)

Locating:
- A plain suffix array locates in 0.005–0.007 µs per occurrence (5 bytes per indexed symbol). That is "between 100 and 1000 times faster than any compressed index".
- Locating is slow in compressed indexes because each occurrence needs several random memory accesses that depend on the suffix-array sampling step sA. The SSA and AF-index need O(sA) wavelet-tree accesses per located occurrence, in exchange for (n log n)/sA extra bits.
- Source: [PDF](https://arxiv.org/pdf/0712.3360)

Summary bounds from the paper:
- "Counting. We can compress the text within 30%–50% of its original size, and search for 20,000–50,000 patterns of 20 chars each within a second."
- "Locate. ... within 40%–80% of its original size, and locate about 100,000 pattern occurrences per second."
- "Extract. ... within 40%–80% ..., and decompress its symbols at a rate of about 1 MB/second."
- The paper says these indexes are 1 (count) to 3 (locate) orders of magnitude slower than a plain suffix array, "using up to 18 times less space".
- Source: [PDF](https://arxiv.org/pdf/0712.3360)

Self-index property: the paper notes "the space of the index should be equal to that of the text (recall that it includes the text)" when comparing options. CSA was the most attractive at equal-to-text space except on dna and xml — [PDF](https://arxiv.org/pdf/0712.3360)

Construction:
- "1–4 sec/MB". Memory "is 5–9 times the text size". This limited the authors to 200 MB.
- Table 5, english 200 MB (build time / peak memory):

  | Index | Time | Peak memory |
  |---|---|---|
  | AF-index | 772 s | 1,751 MB |
  | CSA | 423 s | 1,801 MB |
  | LZ-index | 198 s | 1,037 MB |
  | SSA | 217 s | 1,251 MB |

- Source: [PDF](https://arxiv.org/pdf/0712.3360)

General compressors on the same texts (bits per character, for reference): sources gzip 1.790, bzip2 1.493, PPMDi 1.016; english gzip 3.011, bzip2 2.246, PPMDi 1.957 — [PDF Table 3](https://arxiv.org/pdf/0712.3360)

**Repetitive collections: the r-index** (Gagie, Navarro, Prezza; arXiv 1809.02792, Sep 2018, revised Jul 2019; journal DOI 10.1145/3375890)
- Locates occurrences "within O(r) space (in loglogarithmic time each)".
- Counts in optimal O(m) time.
- Optimal O(m + occ) locate takes O(r log log_w(σ + n/r)) space.
- The earlier run-length FM-index could count in O(r) space but not locate efficiently.
- Source: [arXiv 1809.02792](https://arxiv.org/abs/1809.02792)

**Dynamic, incremental and mergeable BWTs** (all bioinformatics tools)
- ropebwt3 (2024) computes a partial multi-string BWT for a batch and merges it into the existing run-length BWT stored in a B+-tree — [arXiv 2409.00613](https://arxiv.org/pdf/2409.00613)
- Holt & McMillan (2014) merge two or more multi-string BWTs into one — [PMC4318930](https://pmc.ncbi.nlm.nih.gov/articles/PMC4318930)
- ropebwt2 builds an FM-index incrementally by inserting sequences, mixing BCR and a dynamic FM-index — [PMC4221129](https://pmc.ncbi.nlm.nih.gov/articles/PMC4221129)
- bwt-merge merges BWTs of read collections and classifies itself as "insert, static" — [bwt-merge README](https://github.com/jltsiren/bwt-merge/blob/a8f9d747f33c1cdb76b316a7e3d5b2a155a50fe8/README.md)

Note: some of the details in this group came from search-result summaries.

**Go**

Standard library `index/suffixarray` (docs shown for go1.27.3):
- New is O(N).
- Lookup is O(log(N)·len(s) + len(result)).
- `FindAllIndex(*regexp.Regexp, n)` returns sorted non-overlapping matches.
- Source: [pkg.go.dev](https://pkg.go.dev/index/suffixarray)

Its source code:
- The suffix array is `[]int32`, or `[]int64` "when len(data) > maxData32" (math.MaxInt32).
- `FindAllIndex` uses the regexp's literal prefix with Lookup to find candidate start positions. With no literal prefix, the "worst-case scenario" calls `r.FindAllIndex(x.data, n)`, a full scan.
- `Write` stores the length, the raw data, then the suffix array in varint-encoded chunks.
- Source: [suffixarray.go](https://raw.githubusercontent.com/golang/go/master/src/index/suffixarray/suffixarray.go)

Pure-Go FM-index libraries:
- shenwei356/bwt: BWT plus FM-index, MIT, v0.6.1, last push 2023-04-07. Its docs name suffix-array construction (O(n log n)) as the bottleneck — [pkg.go.dev shenwei356/bwt](https://pkg.go.dev/github.com/shenwei356/bwt@v0.6.1), [GitHub](https://github.com/shenwei356/bwt)
- rossmerr/fm-index: a wavelet-tree FM-index with Count/Locate/Extract, MIT, last push 2023-03-05, 0 stars — [pkg.go.dev](https://pkg.go.dev/github.com/rossmerr/fm-index)
- A `gh search repos fm-index --language=go` search otherwise returned only 0–1-star student or experimental repositories (for example rleiwang/hfmi, last push 2020; birc-gsa/fm-index-go, last push 2022) — [GitHub search, 2026-11-05](https://github.com/search?q=fm-index+language%3AGo&type=repositories)

### Inferences
- **Replacing the text.** For code, a CSA or AF-FMI over "sources" is 0.38–0.49 of the text count-only, or about 0.4–0.8 with locate and extract, and it replaces the text. A non-positional trigram index (0.18x) plus bzip2 content (0.19x) is about 0.37x. The two are comparable in size, but the self-index is exact (no false positives).
- **Regex.** The self-index gives up Cox-style regex planning. FM-indexes natively answer exact substrings; regex needs backtracking over the BWT or literal extraction plus verification (not researched here).
- **Construction.** 5–9x the text in RAM (2007 measurements) rules out building a self-index for multi-GB corpora on gomobile or WASM. The Go stdlib suffix array needs text plus 4 bytes per byte (about 5x, computed from the int32 layout), matching the paper's plain suffix array.
- **Incremental fit.** Static self-indexes do not fit a design where each commit appends a delta. Each delta would need its own small FM-index, with a client querying every delta until compaction. Compaction would then need a BWT merge (Holt–McMillan style) or a full rebuild, and no Go implementation exists for either.
- **Versioned data.** The r-index's O(r) space is the theoretically right tool for git-shaped history, where successive versions are near-duplicates. It has no Go implementation, and its engineering complexity is high. Treat it as research-stage for this project.

### Gaps
- I did not read the Navarro & Mäkinen survey (ACM CSUR 2007) itself. The numbers above come from the companion experimental paper by the same group.
- I found no modern (2020s) measurements of FM-index space and speed on source code or email corpora, and no measured construction memory for any Go FM-index.
- I did not research FM-index support for document listing (which documents contain the pattern, needed for boolean queries) or for regex.
- I found no evidence that any dynamic FM-index supports efficient deletion.

## Suffix-array + n-gram hybrids: which approaches suit code and logs (substring, regex) versus prose and email (words)?

### Takeaway
- **Code (and to some extent logs):** n-gram indexes (trigram, or sparse grams at GitHub scale) are the proven choice. A regex-to-gram query plan, then verification against content, is the standard pipeline.
- **Logs in production:** systems commonly use per-block token Bloom filters plus scanning (VictoriaLogs).
- **Prose and email:** word-level indexes fit, either a sorted vocabulary with postings (prefix search through the vocabulary) or per-document term filters.
- **Suffix arrays:** the Go stdlib suffix array is a pure-Go building block, but it gives no speedup for regexes without a literal prefix, and it costs about 5x the text.

### Cited Findings
- Cox's plan turns any regex into a trigram AND/OR query, then runs the full regex on candidate files. The word-index example stores positions for phrase queries, while the trigram index does not — [Cox](https://swtch.com/~rsc/regexp/regexp4.html)
- zoekt pairs positional trigrams with stored content. Literal regexes are simplified to substring queries (`a\.b` becomes the substring "a.b"), and code-specific ranking uses symbol definitions, word boundaries and comment/string context — [zoekt design.md](https://github.com/sourcegraph/zoekt/blob/main/doc/design.md)
- GitHub abandoned plain trigrams at scale because common grams like "for" produce too many false positives. Sparse grams pick variable-length grams where inner bigram weights are smaller than border weights — [GitHub blog](https://github.blog/engineering/architecture-optimization/the-technology-behind-githubs-new-code-search/)
- Go's `index/suffixarray` accelerates regexps only through a literal prefix. With no prefix it scans all the data — [suffixarray.go](https://raw.githubusercontent.com/golang/go/master/src/index/suffixarray/suffixarray.go)
- VictoriaLogs (Go) uses token-based per-block Bloom filters to skip log blocks, and converts parts during background merges — [VictoriaMetrics logstorage mirror](https://forge.k3s.fr/github-mirrors/VictoriaMetrics/commits/branch/master/lib/logstorage/part.go) (secondhand)
- tinysearch for prose: an exact sorted vocabulary with delta/varint postings supports prefixes of 3 or more characters. Per-article xor8 filters support only complete words (title prefixes excepted) — [tinysearch](https://github.com/tinysearch/tinysearch)
- BitFunnel indexed lowercased, unstemmed word terms for web prose, and relied on a forward index with term frequencies for BM25F ranking — [BitFunnel paper](https://danluu.com/bitfunnel-sigir.pdf)
- On "sources" (C/Java code), compressed self-indexes reach 0.38 (CSA) to 0.72 (SSA) of the text count-only. On english they reach 0.42–0.60 — [JEA Table 6](https://arxiv.org/pdf/0712.3360)

### Inferences
- **Code (source repos):** a non-positional, doc-level trigram index of about 0.18x source, plus locally available compressed content of about 0.2x. Use Cox's regex planner, then verify on the client. Positional postings (zoekt) cut verification work but cost about 10x more index; they could be built on demand locally, but should not be shipped.
- **Logs and agent transcripts:** these are highly repetitive and token-structured. Practical options:
  - (a) Per-segment (per-commit-delta) token filters as a skip layer, VictoriaLogs-style, plus decompress-and-scan of matching segments.
  - (b) Trigram postings when substring search inside tokens matters.

  Because logs repeat so much, compressing the content helps more than any index trick.
- **Prose and email:** use word-level search with a sorted vocabulary, which enables prefix search and typo or stem expansion on the client. Either use doc-level postings (about 6–8 bits per posting, exact, can be extended with term frequencies for BM25), or per-message xor8 filters (about 10.3 bits per term at 500 terms, with false positives, no ranking).
- **Hybrid:** one encrypted index blob with two sections, a word vocabulary plus postings for prose/email/transcripts and trigram postings for code/logs. Both are doc-level and non-positional, and both merge the same way (posting concatenation with document-ID remapping).
- **Suffix arrays:** keep them as an optional local accelerator for a single hot repository. At about 5x the text they are never the downloaded format.

### Gaps
- I did not research livegrep (suffix-array-based code search) or ClickHouse's `ngrambf_v1`/`tokenbf_v1` skip indexes, so I have no measured sizes for them.
- I have no measured trigram index ratio for email or prose corpora. Cox's 18–20% is for source code.

## How does each family handle per-document deletion, and erasure where a document's terms must leave the index?

### Takeaway
- **Per-document filters** are the only family where a document's index data is physically separate. Deleting the document means dropping its bytes at the next compaction, with no other document's data touched.
- **Posting-based indexes** (trigram, word, BitFunnel rows) delete logically, through tombstones. Erasure happens only when compaction rewrites the shared postings.
- **Self-indexes and suffix arrays** contain the text itself, so erasure requires a rebuild.

### Cited Findings
- codesearch has no per-file delete. `Merge` drops every src1 entry under a root that the newer src2 also covers, then renumbers the surviving IDs — [codesearch merge.go](https://raw.githubusercontent.com/google/codesearch/master/index/merge.go)
- zoekt:
  - Delta builds tombstone changed or removed paths in older shards' `FileTombstones` metadata.
  - Non-delta builds delete all existing shards for the repository and write new ones — [builder.go](https://github.com/sourcegraph/zoekt/blob/main/index/builder.go), [api.go](https://github.com/sourcegraph/zoekt/blob/main/api.go)
  - Repository-level `Tombstone` is set in `.meta` — [tombstones.go](https://github.com/sourcegraph/zoekt/blob/main/index/tombstones.go)
  - Compound-shard `merge()` skips tombstoned repositories when rewriting — [merge.go](https://github.com/sourcegraph/zoekt/blob/main/index/merge.go)
- GitHub Blackbird runs compaction "on a shorter interval, which is where document deletions are handled" — [GitHub blog](https://github.blog/engineering/architecture-optimization/the-technology-behind-githubs-new-code-search/)
- BitFunnel stores each document as a column of shared bit-sliced rows. Higher-rank rows OR together the bits of 2^r documents — [BitFunnel paper](https://danluu.com/bitfunnel-sigir.pdf)
- Self-indexes "include the text" — [JEA paper](https://arxiv.org/pdf/0712.3360). The Go `suffixarray.Index` holds `data []byte` plus the suffix array, with no mutation API beyond New and Read — [suffixarray.go](https://raw.githubusercontent.com/golang/go/master/src/index/suffixarray/suffixarray.go)

### Inferences
- **Trigram and word postings.** Deletion means a tombstone (doc ID or path) in a newer delta, then compaction that rewrites postings without the document.
  - Until compaction, the old encrypted segments still encode which grams or terms the document contained.
  - In an E2EE store, erasure equals: rewrite the compacted index, delete the old index blobs and deltas, and crypto-shred their keys.
  - Erasure latency is therefore set by compaction frequency.
- **zoekt's merge-time re-indexing** means erasure costs a re-index of the merged shards.
- **Per-document filters (xor/fuse/Bloom).** A segment is a list of (doc ref, filter bytes). Deletion is a tombstone in the newer delta, and compaction drops the dead entries without recomputing anyone else's filter, so erasure cost is O(bytes copied).
- **Avoid shared filters.** A single shared Bloom or xor filter over many documents (for example, one per segment used as a skip layer) cannot remove one document's terms; only a rebuild from the remaining documents can. Keep any segment-level skip filters derived from, and rebuildable from, the per-document data.
- **BitFunnel.** Clearing a deleted document's rank-0 column is possible in principle, but its bits in higher-rank rows are ORed with other documents' bits. It can only be soft-deleted, for example by masking with a live-document row, until those rows are rebuilt. This is my inference; the paper does not describe deletion.
- **FM-index, CSA and suffix arrays.** Rebuild from the remaining text. Under per-commit deltas, each small delta index could be dropped whole, but a compacted base index needs a full rebuild to erase one document.

### Gaps
- I found no BitFunnel documentation of deletion or expiry.
- I found no dynamic FM-index with measured deletion support.
- I did not find how often Sourcegraph or GitHub compact in practice, or how many tombstones they tolerate before doing so (Sourcegraph's PR #1050 heuristics were still unmerged as of 2026-11-05).

## Determinism and merge: can segments built by different clients be merged cheaply and reproducibly?

### Takeaway
- **Cheap merges:** doc-ID posting indexes (codesearch-style) merge by streaming the posting lists and renumbering IDs. No source text is needed, and the cost looks linear.
- **Trivial merges:** per-document filters merge by concatenation. FastFilter's Go constructions start from a fixed seed, so identical key sets should produce identical bytes.
- **Expensive merges:** zoekt's compound-shard merge re-indexes stored content. FM-index or BWT merging exists only in bioinformatics tools, and none of them are in Go.

### Cited Findings
- codesearch `Merge(dst, src1, src2)` reads only the two index files. It maps old IDs through `idrange{lo,hi,new}` ranges, sequentially. Name and root lists are kept sorted (by `Path.Cmp`) — [merge.go](https://raw.githubusercontent.com/google/codesearch/master/index/merge.go), [read.go](https://raw.githubusercontent.com/google/codesearch/master/index/read.go)
- zoekt `merge()`:
  - Sorts the input shards by repository priority with `sort.Slice`.
  - Builds a fresh `ShardBuilder`.
  - Re-adds every non-tombstoned document from its stored content (`readContents`) plus symbols and branch masks.
  - Delta builds are refused for repositories in compound shards.
  - Sources: [zoekt merge.go](https://github.com/sourcegraph/zoekt/blob/main/index/merge.go), [builder.go](https://github.com/sourcegraph/zoekt/blob/main/index/builder.go)
- FastFilter Go: binary fuse uses `rngcounter := uint64(1)` and then `splitmix64` for the seed, reseeding on failure. Xor8 starts from `rngcounter = 1`, with up to 1024 iterations. Both prune duplicate keys and mutate the input — [binaryfusefilter.go](https://raw.githubusercontent.com/FastFilter/xorfilter/master/binaryfusefilter.go), [xorfilter.go](https://raw.githubusercontent.com/FastFilter/xorfilter/master/xorfilter.go). The serialized format is portable across endianness — [README](https://github.com/FastFilter/xorfilter)
- BWT merging: Holt & McMillan merge multi-string BWTs — [PMC4318930](https://pmc.ncbi.nlm.nih.gov/articles/PMC4318930). ropebwt3 merges partial BWTs into a run-length B+-tree BWT — [arXiv 2409.00613](https://arxiv.org/pdf/2409.00613). bwt-merge is "insert, static" — [bwt-merge README](https://github.com/jltsiren/bwt-merge/blob/a8f9d747f33c1cdb76b316a7e3d5b2a155a50fe8/README.md)
- Blackbird gets query consistency at the commit level from Kafka per-shard ordering. Its initial ingest order comes from a minimum-spanning-tree approximation that yields about 90% of the delta-compression benefit — [GitHub blog](https://github.blog/engineering/architecture-optimization/the-technology-behind-githubs-new-code-search/)

### Inferences
**Requirements for reproducible merges across clients.** Two clients compacting the same deltas should produce byte-identical plaintext before encryption. That allows deduplication, verification, and avoiding conflicting compactions. It requires:
- (1) A canonical document-ID order. Sort by stable keys such as (path, blob hash) or commit order, never by arrival order. codesearch's sorted name lists already do this.
- (2) Canonical posting encodings. Delta or γ codes are deterministic.
- (3) Fixed hash seeds and parameters for filters. FastFilter's constant starting `rngcounter` satisfies this for a given key set. Order-independence is unverified, so sort the keys before construction to be safe.
- (4) No unstable sorts on tied keys. zoekt sorts by priority with `sort.Slice`, which Go documents as not stable, so equal-priority inputs could reorder between runs.

**Merge cost by family:**
- Posting indexes: linear streaming. They can be merged on mobile and in WASM in bounded memory.
- Per-document filters: concatenation plus dropping tombstoned entries.
- zoekt: a full re-index of the merged content.
- Self-indexes: a rebuild or a BWT merge, neither available in Go.

**Bloom-specific options.** Bloom filters with identical m, k and hash function can be unioned by bitwise OR. This is useful for building segment-level skip filters from per-document filters without the original terms, but such unions cannot be un-merged. Xor, binary fuse and ribbon filters cannot be unioned; they must be rebuilt from the keys (inferred from the full-key-set construction APIs above).

### Gaps
- I did not verify whether FastFilter's output is identical across key permutations, or across Go versions and architectures (beyond the README's endianness note).
- I found no source describing deterministic or reproducible zoekt shard builds.
- I found no Go implementation of any BWT merge algorithm.
