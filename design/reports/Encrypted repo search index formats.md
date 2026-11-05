# Time-bucketed trigram indexes make evs searchable

Yes on both counts. Every evs commit can carry a small encrypted index delta in its own push. A client can download a repo's whole index and search it locally, which removes the search-pattern and access-pattern leakage that leakage-abuse attacks exploit in searchable symmetric encryption (SSE). The owner's target is finding an email or a note. For that, a document-level trigram index measured **7–17% of the text after zstd** on three mail corpora. That is **1.3–1.7× a word index** on the same mail, and far below the roughly 30% a positional index keeps even after brotli. The owner's two 30-day buckets fit a phone. At 100 messages a day they total about **2–3 MB** and are searched at once. Five years of the "all" partition comes to roughly **50–65 MB**; desktops fetch it in the background, and phones fetch it on "search more" or while on Wi-Fi and charging. The trade-off to weigh is precision rather than size. Trigram hits are candidates that must be checked against text, and **median precision for rare-word queries fell from 0.89 at 513 messages to 0.19 at 18,846**. Small buckets therefore read cleanly. The large all partition needs local text on desktops, or on phones an exact word-postings complement costing another 4–11% of the text. Head-only "versionless" storage is a requirement, not an optimization. evs keeps push history for a repo's life, and only an index kept outside that history lets per-entry erasure finish: it rewrites the few objects that hold an entry and destroys their keys. The recommended byte-exact pure-Go format adds about **1–2 MB** to client binaries, against 7–16 MB for SQLite FTS5 and 12–13 MB for Bleve.

## Downloading the whole index leaves the server nothing to learn from queries

No shipping end-to-end-encrypted product syncs a text index through its servers.

- **Tuta** builds its index on each device. In browsers it is a hand-rolled IndexedDB index with deterministically encrypted words. Since March 2025, native clients use a contentless SQLite FTS5 table inside the SQLCipher offline database ([Tuta commit](https://github.com/tutao/tutanota/commit/86d5775e16ed441695457f2567ffeec9478bf109), [OfflineStoragePersistence.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/OfflineStoragePersistence.ts)).
- **Proton** indexes per browser per device. It caps the local cache at 600 MB, with a 500 MB target sized for about 50,000 emails ([Proton constants.ts](https://github.com/ProtonMail/WebClients/blob/HEAD/packages/encrypted-search/lib/constants.ts)).
- **Skiff** serialized its whole MiniSearch index, encrypted it, and rewrote it into IndexedDB at most every 30 seconds ([Skiff searchIndex.ts](https://github.com/skiff-org/skiff-apps/blob/HEAD/libs/skiff-front-search/src/searchIndex.ts)).
- **Keybase** put a Bleve index inside encrypted KBFS blocks, but pointed the block and metadata servers at local directories ([kbfs/search/init.go](https://github.com/keybase/client/blob/HEAD/go/kbfs/search/init.go)).

The one production system found that syncs derived search data as server-side encrypted objects is Ente. Its embeddings are "compressed lossless and encrypted using the file key", so a new device pulls them rather than recomputing ([Ente](https://ente.com/ml/)). A per-repo synced index is therefore new ground for evs, and its payoff is what all of these products lack: a new device can search without first downloading, decrypting and reindexing everything. Tuta users describe that reindexing as taking "ages" ([tutanota#2681](https://github.com/tutao/tutanota/issues/2681)).

The contrast with server-assisted search is sharp. Searchable encryption leaks three things: the search pattern (which queries repeat), the access pattern (which documents match) and result volumes ([SoK, IEEE S&P 2017](https://arxiv.org/abs/1703.02014)). Leakage-abuse attacks turn that leakage into recovered queries and plaintext ([Cash et al.](https://eprint.iacr.org/2016/718)).

- **File injection is cheap.** About 9 injected files recover a query token, and recovery succeeds about 70% of the time once 20% of the files have leaked ([Zhang, Katz, Papamanthou](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_zhang.pdf)).
- **Generic reconstruction** from access-pattern or volume leakage works even against ORAM- and homomorphic-encryption-backed systems ([Kellaris et al.](https://privacytools.seas.harvard.edu/publications/generic-attacks-secure-outsourced-databases)).
- **Forward- and backward-private schemes** narrow what updates and deletions reveal, but leave search and access patterns in place ([Sophos](https://eprint.iacr.org/2016/728), [Bost–Minaud–Ohrimenko](https://eprint.iacr.org/2017/805)).
- **Google's patented design** for Gmail client-side encryption keeps exactly such a server-side index, and states that the server still learns search patterns over time ([US 11,308,224](https://patents.google.com/patent/US11308224)).

Client-side tools that fetch only part of an index leak the same way. Pagefind publishes each chunk's term range, so on MDN's bundle a host that sees which chunk was fetched narrows the query term to about 200 alphabetically adjacent candidates ([Pagefind index/mod.rs](https://github.com/CloudCannon/pagefind/blob/main/pagefind/src/index/mod.rs), [MDN bundle](https://mdn.pagefind.app/pagefind/pagefind-entry.json)). Range-request SQLite exposes the B-tree pages each query touches ([phiresky](https://phiresky.github.io/blog/2021/hosting-sqlite-databases-on-github-pages/)). SSE's real advantage is bandwidth proportional to the result rather than to the corpus. That only matters once an index is too large to download, so the measurements below decide where evs's threshold sits.

Whole-index download reduces the server's view to object sizes, rewrite timing, writer identity, and which partitions a device fetches by sync position. evs already exposes most of that for commits. Two sharp edges remain.

The first is a **compression oracle**. DBREACH worked against compressed, encrypted InnoDB and WiredTiger tables using only approximate file sizes and the ability to insert rows. It detected whether a random string was present with over 90% accuracy and extracted 10-character random strings more than 95% of the time. Its authors call turning compression off the only foolproof defence ([DBREACH](https://crypto.unc.edu/papers/dbreach.pdf)). evs gives attackers an injection channel through inbound mail and collaborator commits. The design response is:

- compress each per-commit delta alone, so it carries only its own document;
- pad every shared object (rebuilt bucket bases and all-blocks) with Padmé.

Padmé leaks O(log log M) bits of length at no more than 12% overhead ([Padmé](https://arxiv.org/abs/1806.03160)), and evs already applies it to per-file change sizes ([DESIGN.md §11.5](../DESIGN.md)).

The second edge is that a phone's on-demand "search more" download tells the server that the user searched, and when, though not what. Background prefetch on Wi-Fi removes even that signal.

One rule follows from the SSE literature: never store the index as one server object per term or posting row. Tuta-style deterministic term rows turned into server objects would rebuild classic frequency and co-occurrence leakage.

## Each commit can push a forward delta of a third to half its text

When a repo's index is on, the committing client normalizes each changed document and extracts its set of trigrams. It then writes one sealed delta object, listing (document key, version, sorted trigram set), inside the same push. The index advances atomically with the commit and needs no extra store round trip.

How the delta is laid out matters more than which codec encodes it. Encoded as a forward list (one sorted trigram set per document, compressed alone), a one-message commit costs **29% of the message's text on Kafka dev mail, 34% on Lucene dev mail and 52% on 20 Newsgroups**. A median message's delta is 64–77% of its own text, because short messages compress poorly. The same document written as a one-document inverted segment costs **139–254%**, and even ten-document inverted segments cost 69–138% (own measurement, [Kafka](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/kafka.txt), [Lucene](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/lucene.txt), [20 Newsgroups](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/news20.txt)). Per-commit objects should therefore be forward lists, converted to inverted postings only when a bucket is rebuilt.

CPU cost is negligible. NFKC normalization with case folding ran at 41–66 MB/s, and trigram-set extraction at 17–39 MB/s, on one Apple M1 Max core. A typical 3.6 KB email costs about 0.3 ms. The notes measured pure-Go wasm at 2.5–5× native, which keeps even a browser commit near a millisecond ([notes harness](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/idxexp/main.go)).

Deltas cannot stay the read format for long. In the notes' measurements, splitting a corpus into one-to-ten-document segments inflated a docid index **2–8.5×**, mostly through duplicated dictionaries. Query cost grew linearly with segment count: an FTS5 term query took 3.2–4.7 ms across 1,000 one-document segments against 18–84 µs once merged, and Bleve ran 15–56× slower ([engines notes, local run](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)). Every mature engine therefore merges small segments eagerly:

| Engine | Merge trigger | Floor |
|---|---|---|
| Lucene TieredMergePolicy ([source](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/index/TieredMergePolicy.java)) | 8 segments per tier | 16 MB |
| Tantivy ([log_merge_policy.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/indexer/log_merge_policy.rs)) | 8 segments per level | 10,000 documents |
| Bleve ([merge_plan.go](https://github.com/blevesearch/bleve/blob/master/index/scorch/mergeplan/merge_plan.go)) | 10 segments per tier | 2,000 documents |
| FTS5 ([docs](https://www.sqlite.org/fts5.html)) | automerge at 4 b-trees per level, crisis merge at 16 | none |

Keeping reader-visible segments near 10–20 held latency within 2–4× of a fully merged index in those tests. The owner's bucket model provides that bound by construction, because forward deltas cost almost nothing to probe and the bucket rebuild absorbs them.

Two practical cases need explicit handling:

- **Turning the index on or off per repo.** Turning it on means one full build by a device that holds the repo's text. Turning it off deletes every index object and destroys their keys.
- **Committers that skip the index.** "Every committer updates the index" will not always hold: old clients, headless agents, or a phone that skipped indexing can all commit without a delta. The index head should record the last commit it covers. A reader that finds newer commits indexes them from local text or labels them "not yet searchable", and the next capable writer backfills the gap.

Concurrency is easy. Deltas are one object per commit and never conflict. Only the small index head changes in place, by compare-and-swap like evs's own heads. Rebuilds are deterministic, so two clients that race to compact the same inputs produce identical plaintext and the loser simply discards its copy.

## Mail trigram indexes run 7–17% of the text, 1.3–1.7× a word index

The notes held trigram sizes only for source code. Russ Cox's codesearch index is about 20% of the indexed files: 77 MB for 420 MB of Linux source ([Cox](https://swtch.com/~rsc/regexp/regexp4.html)). Nothing in the notes covered prose or mail, so this report measured doc-level trigram indexes directly. It used the notes' own corpora and their MIME decoder:

- 3,019 Kafka dev messages (10.8 MB of text, [archive](https://lists.apache.org/list.html?dev@kafka.apache.org));
- 513 Lucene dev messages (1.8 MB, [archive](https://lists.apache.org/list.html?dev@lucene.apache.org));
- the 18,846-post 20 Newsgroups set (35.9 MB at 1.9 KB per post, [dataset](http://qwone.com/~jason/20Newsgroups/)).

A word index was built alongside, with the same normalization. Two checks calibrate the method:

- **Word index.** The harness reproduces the notes' figure exactly: 5.6% of text for a docid-only index on the same Go source slice.
- **Trigrams on code.** Case-sensitive byte trigrams on that Go source came to 9.4–13.8% depending on codec. That is the same order as Cox's Linux figure, whose smaller files carry more trigrams per byte.

The program and its raw outputs are in the session scratchpad, and every number used here is reproduced in this report ([program](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure/main.go), [Go](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/gosrc.txt), [serializations](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/serializations.txt)).

| Index size, share of decoded text | Trigram, punctuation kept | Trigram, punctuation folded | Word docid+tf | Trigram (folded) ÷ word |
|---|---|---|---|---|
| Kafka dev mail (3,019 × 3.6 KB), zstd | 10.1% | **7.1%** | 4.2% | 1.7× |
| Lucene dev mail (513 × 3.5 KB), zstd | 13.5% | **9.2%** | 7.0% | 1.3× |
| 20 Newsgroups (18,846 × 1.9 KB), zstd | 25.1% | **16.6%** | 10.8% | 1.5× |
| Same three, uncompressed in memory | 16.5 / 23.4 / 32.7% | 11.2 / 15.4 / 20.7% | 10.6 / 16.8 / 22.4% | about 1× |

How the table was measured:

- **Trigram encoding.** VByte docid gaps, with bitsets for lists that cover more than an eighth of the documents, plus a 3-byte-key directory.
- **Compression.** zstd at its best level, in process.
- **Word ratio.** Against a docid-only word index, the folded trigram index is 1.7–2.4×.
- **Brotli.** Brotli-11 beat zstd -19 by a further 5–11% on the same bytes (7.6–10.8% on trigram indexes) ([CLI compression](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/cli_compression.txt)).

The surprising row is the last one. Uncompressed in memory, a punctuation-folded trigram index with bitsets is about the size of a word docid+tf index.

**Document length is the strongest driver.** Short documents repeat few trigrams, so almost every three-byte window adds a posting. Chunking Kafka bodies to fixed lengths gave:

| Chunk length | Uncompressed trigram index, share of text | Trigram postings per KB | Trigram ÷ word |
|---|---|---|---|
| 128 bytes | 76% | 688 | 5.2× |
| 1 KB | 49% | 460 | 4.9× |
| 4 KB | 31% | 289 | 4.3× |
| 64 KB | 9% | 72 | 2.6× |

(Own measurement, [Kafka](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/kafka.txt).) Notes are therefore the worst case per byte but the cheapest in total. A vault of 2,000 notes of 1 KB each is about 2 MB of text, which indexes to well under 1 MB.

**Normalization is the second lever.**

- **NFKC with full case folding** cut the Kafka index 16% against raw case-sensitive bytes.
- **Punctuation folding** maps every run of punctuation and whitespace to one space, as pg_trgm does when it "ignores non-word characters" ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)). It cut another 29–33% on all three corpora.
- **No precision cost.** Letter-only trigrams never span punctuation, so candidates and precision were identical in every word, prefix and infix test. Because queries are folded the same way, punctuation-bearing strings such as addresses still match.

**MIME hygiene is the third lever, and the easiest to get wrong.** Indexing undecoded messages, with transport headers, base64 and quoted-printable left in, inflated the trigram index **3.2× on Kafka and 5.9× on Lucene**. Lucene's raw messages were 16× their decoded text, and on raw Kafka the word dictionary alone reached 17% of text. The indexer must decode MIME, strip HTML, drop attachments and transport headers, and index only what a person would search for.

The codec results echo the notes' word-index findings:

- **Bit-level codes.** γ and Elias-Fano codes are about half the size of VByte uncompressed. After zstd, plain VByte gaps (7.6% on Kafka) undercut them (9.1% and 9.5%), because byte-aligned output leaves redundancy that zstd removes.
- **Dense-list bitsets.** Encoding lists that cover more than an eighth of the documents as bitsets, as Lucene 10.2 does for dense blocks ([PR #14133](https://github.com/apache/lucene/pull/14133)), saves 36–44% in memory and 2–7% compressed.
- **Directory.** The fixed 3-byte trigram directory costs only 0.7–3.6% of text, so trigram keys need neither an FST nor front coding.
- **zstd level.** zstd's default level came out only 8–13% larger than its best level, which suits frequent rebuilds.
- **Blocks.** Independently compressed 256 KiB blocks cost 2–9% more than compressing the whole stream.
- **Stop trigrams.** Dropping the 250–360 trigrams that appear in over half of all documents would save only 4–11% after compression, at an unmeasured precision cost, so it is not recommended.

Every alternative family the notes examined is larger, less exact, or harder to maintain under per-commit deltas:

| Family | Cost | Problem |
|---|---|---|
| Positional word index ([MDN bundle](https://mdn.pagefind.app/pagefind/pagefind-entry.json)) | about 30% of text after brotli (Pagefind, re-encoded) | large |
| Positional trigrams, zoekt ([design](https://github.com/sourcegraph/zoekt/blob/main/doc/design.md)) | about 3× the corpus, 3.5× per shard with content | large |
| Per-document xor8 filters ([FastFilter](https://github.com/FastFilter/xorfilter)) | about 645 bytes per 500-term document at a 0.39% false-positive rate; 1.5–3.7× compressed docid postings | false positives scale with corpus size, to about 391 false documents per query at 100,000 documents |
| Bit-sliced signatures, BitFunnel ([paper](https://danluu.com/bitfunnel-sigir.pdf)) | 1.9–5× the bits per posting of partitioned Elias-Fano | 1.6–4.3% false positives |
| FM-index ([Ferragina et al.](https://arxiv.org/abs/0712.3360)) | 0.28–0.74 of the text for counting | contains the text, is static, needs 5–9× the text in RAM to build, and has only stale Go libraries |

Zobel, Moffat and Ramamohanarao's verdict, that inverted files are "distinctly superior to signature files", still holds ([TODS 1998](https://people.eng.unimelb.edu.au/ammoffat/abstracts/zmr98acmtods.html)). The browser-side tools teach the same lesson:

- Stork's precomputed index was 4.8× its text ([federalist.st](https://files.stork-search.net/federalist.st)).
- A lunr JSON index of two novels was 1.7 MB raw ([Millikin](https://john-millikin.com/compacting-lunr-search-indices)).
- tinysearch abandoned per-article Bloom filters for exact delta-and-varint postings at about 1 kB per article ([tinysearch](https://github.com/tinysearch/tinysearch)).

If the word complement recommended below is added, the notes' posting findings apply directly:

- **Short lists dominate.** On personal-scale corpora, 31–83% of terms occur in just one document.
- **VByte or frame-of-reference blocks** of 128–256 integers with a VByte tail land at 7–10 bits per posting.
- **Roaring** costs 19–55 bits on such tiny lists.
- **Interpolative coding** is smallest at 4.7–6.2 bits but has no maintained Go implementation ([Pibiri & Venturini](https://arxiv.org/abs/1908.10598), [notes harness](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/idxexp/main.go)).
- **Dictionaries.** Front-coded term blocks matched the vellum FST uncompressed and beat it after zstd, at 2.8–3.9 bytes per term against 4.6–5.9. Minimal perfect hashing answers only exact lookups.

## Trigram hits need checking, and precision falls as the searched set grows

A trigram AND returns every document that contains all of a query's trigrams. That makes it complete: full-text scans confirmed no missed match in any of the 25 checked queries per type, on every corpus. But it returns a superset, and the superset grows with the number of documents searched, because unrelated documents assemble a short query's trigrams by chance. Median per-query precision (true matches over candidates) measured as follows (own measurement, [Kafka](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/kafka.txt), [Lucene](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/lucene.txt), [20 Newsgroups](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/news20.txt)):

| Query type (400 sampled per cell) | Lucene, 513 messages | Kafka, 3,019 | 20 Newsgroups, 18,846 |
|---|---|---|---|
| Word of five or more letters | 1.00 | 0.99 | 0.76 |
| Rare word, in 2–20 documents (median candidates / true) | **0.89** (9 / 5) | **0.67** (18 / 6) | **0.19** (38 / 5) |
| Five-letter prefix of a long word | 0.94 | 0.91 | 0.77 |
| Four-letter infix of a long word | 0.94 | 0.91 | 0.74 |
| Two adjacent words | 0.55 | 0.27 | 0.08 |

Padding whole-word queries with spaces, to exploit word-boundary trigrams, did not help. Rare whole words reached only 0.16 on 20 Newsgroups and 0.48 on Kafka ([padded queries](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/query_padded.txt)). The low precision is inherent to the index, not a tuning problem. CPU is not the issue either. The median query touched 374 to 73,000 postings (p90 under 120,000), roughly a millisecond at the notes' 2–8 ns per posting in wasm.

How candidates get checked therefore decides the experience, and it differs by device:

- **Desktops and the always-on device** hold the repo's text. They verify every candidate against the decrypted document locally, at no privacy cost, which turns trigram search into exact substring search.
- **Phones** head-read the mailbox's `m/` tree rather than mirroring it ([DESIGN.md §18.4](../DESIGN.md)), so unverified candidates are the norm. A phone has three options:
  - **Possible matches, verified on open.** Show candidates as ranked "possible matches" and verify each one when the user opens it. Opening a message is a fetch the server sees anyway, so this leaks nothing new.
  - **Fetch candidate bodies.** This reveals a query-dependent candidate set, the access pattern SSE attacks feed on, so it should not be the default.
  - **Exact word postings** for whole-word queries, described below.

Ranking should put recency first, as Tuta does by ordering FTS5 hits by received date ([OfflineStorageSearchFacade.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/OfflineStorageSearchFacade.ts)), with confirmed matches ahead of possible ones.

A doc table inside each partition makes "possible matches" usable, and confirms a whole class of them.

- **Cost.** A 16-byte document key, date, sender and subject cost 33–37 bytes per message after zstd (0.9–2.0% of text). Adding a 160-byte opening snippet raises that to 68–85 bytes (1.9–4.3%), enough to render a result list without touching any message body.
- **Exact header matches.** Any message whose subject, sender or recipients contain the query necessarily contains all of its trigrams. Checking the candidates' doc-table fields therefore finds every header match without a fetch, and those can be shown first as confirmed.
- **Per-field postings aren't worth it.** Separate posting lists for from, to, subject and body cost **12.6–17.3% more index** and only prune candidates for field-scoped queries. One unified posting set plus doc-table fields is the better trade.

Trigrams buy three capabilities a word index lacks.

- **Substring and partial-word matching.** Prefixes and infixes resolve at 0.74–0.94 median precision, whereas a word index answers infixes only by scanning its vocabulary.
- **Multilingual text with no tokenizer, provided the trigrams are over bytes.** A CJK character is exactly three UTF-8 bytes, and UTF-8 lead and continuation bytes occupy disjoint ranges ([RFC 3629](https://www.rfc-editor.org/rfc/rfc3629)). An aligned byte trigram is therefore exactly one character. A one-character query hits a single posting list, and a two-character query hits four lists, including the straddling trigrams that link the two characters. By contrast:
  - a word index needs a segmenter, like the FTS5 tokenizer Signal ships for CJK ([Signal-FTS5-Extension](https://github.com/signalapp/Signal-FTS5-Extension));
  - SQLite's own trigram tokenizer counts Unicode characters, so "substrings consisting of fewer than 3 unicode characters do not match any rows", which fails common two-character CJK words ([FTS5](https://www.sqlite.org/fts5.html)).

  The measured corpora were ASCII (at most 0.9% non-ASCII bytes), so CJK index sizes remain unmeasured.
- **Typo tolerance.** pg_trgm pads each word with two leading spaces and one trailing space, and its similarity operator defaults to a threshold of 0.3 ([pg_trgm](https://www.postgresql.org/docs/current/pgtrgm.html)). The same scheme run over the index's vocabulary, with shared-over-union similarity, ranked the intended word first for 77–92% of single-edit typos and in the top five for 99–100%. The median expansion was 4–17 vocabulary words above 0.3. Without a vocabulary the idea fails. Keeping documents that contain all but three of a typo's trigrams (an edit can destroy at most three) returned **324–3,564 candidates against 8–13 documents** that actually contained the intended word.

Those results argue for an optional word complement in the large partition, not for abandoning trigrams. Word docid+tf postings with a front-coded vocabulary cost 4.2–10.8% of text after zstd, about 0.15–0.25 KB per message. That is 0.59–0.76× the size of the trigram index they back up. They buy three things:

- exact whole-word and multi-word results, with no verification;
- term frequencies for BM25;
- the vocabulary that makes typo expansion work.

The off-the-shelf alternative falls short. FTS5's trigram tokenizer keeps its index small with `detail=none` only because LIKE and GLOB matching re-check the stored row ([FTS5](https://www.sqlite.org/fts5.html)), and a contentless E2EE index has no row to re-check.

## Two 30-day buckets keep a phone's search to a few megabytes

The owner's layout has three partitions:

- **Current bucket.** Commits write to it.
- **Previous bucket.** Sealed.
- **All.** A search merges both buckets immediately and folds all in later.

Buckets should be fixed calendar windows of W days, aligned to UTC, so every client computes the same boundaries. A document belongs to the bucket of its latest change, timed by the commit's signed timestamp rather than the reader's clock. Coverage then oscillates between W and 2W: just after a boundary the current bucket is empty and the previous one holds the last full window, and just before the next boundary both are full. At the 30-day default that is 30–60 days, 45 on average. A repo that promises a searchable window on phones without "search more" needs W at least that long. The team record's "90 days searchable" requirement ([DESIGN.md §16](../DESIGN.md)), for example, needs W of 90 days, or an all partition its readers keep in the background.

**Commits write only to the current bucket.** Updating all on every commit would rewrite an all-block per commit, or pile deltas onto the largest partition, which is the daily churn the owner's roll-up avoids.

**Within the current bucket, a rebuild absorbs the deltas.** Forward deltas accumulate until a desktop or the always-on device rebuilds the bucket's inverted base. On Kafka, forward deltas cost about 2.3× the inverted form per message (29% against 12.4% of text for a 30-day bucket). Rebuilding once the delta tail reaches a quarter of the base, or 256 KiB, keeps the download small; at 100 messages a day that is roughly ten rebuilds per bucket (an estimate). Because the format is deterministic, a phone that already holds the old base and the deltas can reproduce the new base itself and check it against the hash in the head instead of downloading it.

**At the boundary, the roll-up runs once.** The current bucket seals into previous. The expired previous bucket is rolled into all once and dropped, and under head-only storage its objects are then collected. The roll-up is a streaming merge (own measurement, [Kafka](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/kafka.txt), [20 Newsgroups](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/news20.txt)):

- **Merge speed.** Decoding, merging and re-encoding ran at **7.0–9.7 ns per posting** on one native core. 2.5 million postings took 18 ms and 15.2 million took 147 ms; decoding alone ran at 1.7–1.8 ns per posting.
- **Wasm** runs 2.5–5× slower.
- **Cost per roll-up.** Merging a 30-day bucket into a 16 MiB all-block costs under half a second natively and a second or two in wasm. Such a block holds about 27–44 million postings at the measured 0.38–0.61 compressed bytes per posting.

That cost recurs once per bucket length, plus one upload of the rewritten block.

**Masking resolves documents that appear in more than one partition, and the newest version wins.** Each partition's doc table carries document keys:

- **Masking by key.** The current bucket's keys mask both the previous bucket and all, and the previous bucket's keys mask all. The check is a set lookup over a few thousand keys per query.
- **Deletions and renames** enter the current bucket as tombstones keyed the same way.
- **At roll-up**, the merge drops all's superseded versions of the rolled documents when it rewrites the youngest all-block.
- **Older sealed all-blocks** can hide superseded versions with a per-block dead-document bitmap until the block is next rewritten. That is Lucene's live-docs file in miniature, and Lucene itself tolerates 20% deleted documents before merging them away ([Lucene90LiveDocsFormat](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/lucene90/Lucene90LiveDocsFormat.java), [TieredMergePolicy](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/index/TieredMergePolicy.java)).

Masking is fine for edits but never for erasure, which the next section covers.

Shorter windows cost more per message but less in total. Against a single merged index, per-bucket overhead (duplicated directories and sparser lists) measured:

| Window | Overhead, Kafka | Overhead, Lucene (about 3 messages/day) |
|---|---|---|
| 7 days | +44% | +79% |
| 30 days | +16% | +35% |
| 90 days | +5% | +16% |

Seven-day buckets suit very heavy mailboxes. At 365 days, "latest" becomes a year of mail, about 11–13 MB per bucket at 100 messages a day, which defeats its purpose on phones. The table below extrapolates the measured per-message costs of the recommended format, doc-table rows included, to typical mail volumes:

| Mail volume | One 30-day bucket | Both buckets, worst case | All, five years | Word complement for all |
|---|---|---|---|---|
| 25 messages a day | 0.26–0.39 MB | under 0.8 MB | 13–16 MB | 7–11 MB |
| 100 messages a day | 1.1–1.5 MB | under 3.1 MB | 53–65 MB | 28–45 MB |
| 300 messages a day | 3.2–4.6 MB | under 9.3 MB | 160–195 MB | 83–134 MB |

The per-message costs behind the table are 0.35–0.52 KB in a 30-day bucket and 0.29–0.36 KB in all. They come from mailing-list mail averaging 3.5 KB of plain text, scaled from the measured case-folded buckets by the measured effect of punctuation folding and bitsets. HTML-heavy commercial mail will differ. The extrapolation also assumes the cost per message stays flat as all grows; doc-level postings make that plausible, but it was not tested beyond 18,846 documents.

A search therefore runs in two phases:

- **Phase one: buckets.** The buckets are always synced, so a search runs against them locally at once and shows confirmed header matches first.
- **Phase two: all.** If all is already cached, it is searched immediately as well. Otherwise it is downloaded or refreshed and searched block by block, in a fixed newest-first order that does not depend on the query. Results are merged under newest-version-wins as each block arrives.

The owner's device policy maps onto two triggers for phase two: automatic background download, and an explicit "search more" that downloads or refreshes all and then runs the query on it.

| Device | Buckets | All partition |
|---|---|---|
| Desktop app, `ur daemon`, always-on device | kept in sync | downloaded and refreshed in the background; searched with every query and verified against local text |
| Phone on Wi-Fi and charging | kept in sync | prefetched in the background |
| Phone otherwise | kept in sync | fetched or refreshed on "search more" |
| Browser extension worker (suggested) | kept in sync | on "search more", since its heap is capped at 64 MiB ([DESIGN.md §18.4](../DESIGN.md)) |

Every index object is immutable and named by its content, so sync is incremental. A device fetches:

- **daily:** new deltas;
- **after each rebuild:** the new current base, unless it folds the base locally;
- **once per bucket length:** the sealed previous bucket and the rewritten youngest all-block;
- **once:** each sealed all-block, unless an erasure rewrites it.

At 100 messages a day the deltas come to about 0.1 MB a day.

Memory, not bandwidth, sets the block size. evs's design caps the working set at 4 MiB in the iOS app and never holds more than 1 MiB of a segment in RAM ([DESIGN.md §11.14](../DESIGN.md)). Partitions should therefore sit encrypted on disk in 256 KiB blocks and be searched one block at a time. A query decodes only its own trigrams' lists, and even in a 182,500-message all partition a bitset list is 23 KB, so the working set stays far below the cap.

## Head-only storage turns erasure into a bounded rewrite

evs keeps push history for a repo's life by default ([DESIGN.md §2.8, evs-12](../DESIGN.md)). An index stored as ordinary versioned files would keep every delta, every rebuilt base and every all-block forever. That multiplies storage by the merges' write amplification. Worse, it preserves the trigram set of every document a user later erases. The design already names this hazard: erasure must destroy "every key of every representation", because "a shared index or live deposit would otherwise outlive the erasure" ([DESIGN.md D-EVS-26](../DESIGN.md)). A document's trigram set is a strong fingerprint of its vocabulary, so the index is such a representation. It is also derived data, rebuildable from the repo head, so history adds nothing worth keeping. Versionless storage should therefore be the index's only storage class, not an option.

Head-only means immutable sealed objects plus one small mutable head:

- **Objects.** Deltas, bucket bases, doc tables and all-blocks, each under its own key.
- **Head.** It names the current and previous bucket ids, the objects in each partition, their plaintext hashes, the last commit covered, and the format and normalization versions. Writers update it by compare-and-swap.
- **Collection.** Objects the head no longer names are collected after a grace period long enough for in-flight downloads; evs already deletes uploads that no push adopted after 25–49 hours ([DESIGN.md §2.8](../DESIGN.md)). Collection destroys the object's key, so the server's eventual deletion of the ciphertext is not on the critical path.

Per-entry erasure in record-class repos and mail is required "from the start" and is "never deferred by a hold" ([DESIGN.md R-EVS-11](../DESIGN.md)). Across the buckets and all, an erasure takes five steps:

1. Drop the entry's own forward deltas. These are per-document objects, like Ente's per-file keys.
2. Rebuild whichever bucket base holds the entry: current, previous or both.
3. Rewrite every all-block that holds any version of it.
4. Publish a new head.
5. Destroy the superseded objects' keys.

Readers and mirrors already delete "entry, search and `ur://record` caches" on an ERASE hint ([DESIGN.md §16.8](../DESIGN.md)), and they would drop cached index blocks the same way.

Capping all-blocks is what bounds the cost. Erasing one message costs at most a bucket rebuild of a few megabytes, a sub-second merge, and the upload of one 16 MiB block. The 16 MiB cap is a judgment, to be tuned against real erasure frequency.

Logical deletion is the wrong tool for erasure:

- Lucene's live-docs bitsets, Tantivy's delete files, Bleve's deleted bitmaps and zoekt's file tombstones all hide a document while leaving its terms in the segment.
- FTS5's contentless tombstones keep the terms until a merge, and its in-place secure-delete rewrote 151 of 412 pages (37%) to purge a single document ([engines notes, local run](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)).

Determinism across clients is what makes local folds, verifiable rebuilds and convergent roll-ups possible, and off-the-shelf engines don't provide it:

- **Lucene** writes a 16-byte random object ID into every file header ([CodecUtil.java](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/codecs/CodecUtil.java)).
- **Tantivy** names segments with random UUIDv4s ([segment_id.rs](https://github.com/quickwit-oss/tantivy/blob/main/src/index/segment_id.rs)).
- **Bleve** produced three different SHA-256 hashes from three builds of the same corpus ([engines notes, local run](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)).
- **Roaring** permits two serializations of the same bitmap ([RoaringFormatSpec](https://github.com/RoaringBitmap/RoaringFormatSpec)).
- **vellum** changed its FST builder's suffix sharing in November 2026 ([vellum commits](https://github.com/blevesearch/vellum/commits/master)).
- **FTS5** is the exception. After optimize it produced identical blocks across modernc, ncruces, native and wasm builds ([engines notes, local run](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/exp.log)).

The notes' own pure-Go encodings hashed identically on darwin/arm64 and js/wasm ([notes harness](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/idxexp/main.go)). The rules for evs's format are short:

- **Normalization tables.** Pin them to the x/text Unicode version and record it in the format version.
- **Grams.** Use byte trigrams.
- **Docids.** Assign local docids in a canonical order: bucket, then document key.
- **Encoding.** Write minimal VByte with a fixed bitset threshold and a fixed block size.
- **Hashing.** Hash plaintext before compression, because zstd output can change across library versions, and before encryption, which uses random nonces.

Go library availability rules out adopting an engine and favours a small custom codec:

| Option | Binary cost | Blocker |
|---|---|---|
| Bleve ([engines notes, local run](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/followup.log)) | +12.4–13.4 MB | fails to build for js/wasm (bbolt, mmap-go); nondeterministic |
| SQLite FTS5 through [ncruces](https://github.com/ncruces/go-sqlite3) | +7.4 MB native, +15.7 MB wasm (4.1 MB gzipped) | deterministic, but its trigram tokenizer has the verification and short-query limits above; term queries took 1.2–7.7 ms in wasm |
| modernc SQLite | not measured | does not build for js/wasm |
| zapx | 0.75 MB | assumes mmap |
| tantivy-go | not measured | needs cgo and a Rust static library per platform ([tantivy-go](https://github.com/anyproto/tantivy-go)) |
| Custom stack: x/text normalization + klauspost pure-Go zstd | +1.06 MB darwin/arm64, +1.18 MB android/arm64, +1.82 MB js/wasm (0.52 MB gzipped) | none; the codec itself adds a few hundred lines |

Within the custom stack, x/text normalization alone adds 0.38–0.59 MB and zstd alone 0.71–1.26 MB ([binary sizes](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/trimeasure_out/binsize.txt)). Brotli would add another 2.7–3.4 MB for its 5–11% gain, which is not worth it on phones.

Licensing fits too. [x/text](https://pkg.go.dev/golang.org/x/text/unicode/norm) is BSD-3-Clause, and [klauspost/compress](https://github.com/klauspost/compress) is BSD-3-Clause with some Apache-2.0 parts; DESIGN.md §4.7 allows both. Its refusal of the GPL family excludes Erigon's LGPL Elias-Fano code, which the format doesn't need. Google's BSD-licensed codesearch is worth borrowing from for its regexp-to-trigram query planner and its linear index merge ([codesearch merge.go](https://raw.githubusercontent.com/google/codesearch/master/index/merge.go)).

## A byte-exact format now, a semantic layer later

The recommended format follows directly from the measurements above:

| Layer | Choice | Measured basis |
|---|---|---|
| Input | MIME-decoded, HTML-stripped text; no attachments or transport headers | raw MIME inflates the index 3.2–5.9× |
| Normalization | NFKC; full case folding; diacritics removed; each non-letter, non-digit run becomes one space; document padded with spaces | punctuation folding −29–33%, with identical word-query precision |
| Trigrams | bytes of the normalized UTF-8; 24-bit keys | one-character CJK queries resolve to one list |
| Postings | doc-level; canonical local docids; VByte gaps; bitset when a list covers over 1/8 of documents | 7.1–16.6% of text after zstd; −36–44% in memory |
| Directory | sorted 3-byte keys with document count and offset | 0.7–3.6% of text |
| Doc table | document key, version, date, sender, subject; recipients and a 160-byte snippet optional | 33–37 B per message, 68–85 B with snippet |
| Per-commit delta | forward trigram list per changed document, compressed alone | 29–52% of the document's text, against 139–254% inverted |
| Partitions | current and previous W-day buckets (30 by default, 7–365 per repo); all as size-tiered blocks capped near 16 MiB | 30-day buckets +16–35% over a single index |
| Blocks | 256 KiB plaintext blocks; zstd (default level for rebuilds, best for sealed blocks); AEAD per block; Padmé per object | blocks +2–9%; Padmé at most +12% |
| Head | one versionless manifest updated by compare-and-swap; unreferenced objects collected and their keys destroyed | erasure cost bounded by bucket size and block cap |
| Optional | word docid+tf postings and a front-coded vocabulary in all-blocks, built by a device that holds the text | +4.2–10.8% of text; exact words; typo expansion |

A semantic layer fits the same bucket layout, and can wait.

- **Size.** Binary 1-bit codes take 48 bytes per 384-dimension chunk. At 512-token chunks, which Azure found recalled better than 8,191-token ones, that is about 2–3% of the text (computed), well under the trigram index ([Azure AI Search](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-search-outperforming-vector-search-with-hybrid-retrieval-and-ranking-capabilities/3929167), [HF quantization](https://huggingface.co/blog/embedding-quantization)).
- **Quality.** Rescoring with a float query keeps 75–96% of float nDCG@10, depending on the model; MiniLM keeps 94%.
- **Index structure.** A flat scan of one million codes took 3.8 ms natively and 8–34 ms in Go wasm ([notes benchmark](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hambench/main.go)), so flat per-bucket segments need no HNSW graph. HNSW would add 128–256 bytes of links per vector, depends on seeds and insertion order, and cannot truly delete ([Faiss](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes), [hnswlib](https://github.com/nmslib/hnswlib)).
- **Determinism.** Vectors must be computed once, by the committer or the always-on device, and stored as data, never recomputed and compared. Go's arm64 compiler fuses multiply-adds: 8,140 of 10,000 dot products differed from amd64 and wasm until explicit `float32()` rounding made all three agree ([Go spec](https://go.dev/ref/spec#Arithmetic_operators), [notes test](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/fmatest/main.go)).
- **Payoff for mail.** Modest. On keyword queries, Azure measured BM25 at 79.2 nDCG@3 against 11.7 for vectors. Vectors won on low-overlap queries (36.1 against 23.0) and on misspellings ([Azure AI Search](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-search-outperforming-vector-search-with-hybrid-retrieval-and-ranking-capabilities/3929167)), and vocabulary-based typo expansion already covers misspellings.
- **Runtime cost.** Too heavy for phones. Pure-Go Hugot builds to 15.4 MB natively and 31.8 MB in wasm; ONNX Runtime Web is 2.4 MB brotli plus a 23–34 MB int8 model ([Hugot](https://github.com/knights-analytics/hugot), [ORT-Web files](https://data.jsdelivr.com/v1/packages/npm/onnxruntime-web@1.31.1?structure=flat), [MiniLM ONNX](https://huggingface.co/Xenova/all-MiniLM-L6-v2/tree/main/onnx)).

That makes semantic search a later feature for desktops and the always-on device.

## Conclusion

Size is not the binding constraint. A punctuation-folded trigram index costs about 1.5× a word index on mail after compression, and no more in memory. What binds is verification, because trigram precision depends on how many documents are searched. That reframes the owner's bucket model. Two 30-day buckets do more than cap a phone's download: they keep the immediately searched set small enough (hundreds to a few thousand messages) that unverified hits are mostly right. The large all partition belongs where text is local, or where exact word postings back it. The practical rule follows:

- **Trigrams everywhere**, for partial words, CJK and typo expansion.
- **Local verification on desktops.**
- **For phones' "search more"**, either verify-on-open, or a word complement smaller than the trigram blocks it backs.

Determinism quietly enables everything incremental. It lets phones fold deltas into bases without downloading them, lets any client check another's roll-up, and makes racing roll-ups converge on one head.

The open questions are empirical and cheap to close:

- **Real mailboxes.** Measure an HTML-heavy, multilingual mailbox, because every number here comes from plain-text technical lists in ASCII.
- **Phone throughput.** Measure decryption plus zstd for a 16 MiB block on gomobile and Safari's wasm engine, which the notes flag as unmeasured.
- **Block cap.** Choose the all-block cap against real erasure frequency.
- **What phones fetch.** Decide whether phones' "search more" fetches all's trigram blocks, its word complement, or both.

On a 300-message-a-day mailbox, five years of all approaches 200 MB. That is where SSE's result-proportional bandwidth starts to look attractive. Even there, the cheaper answer is word-only all-blocks for phones, not server-side search.
