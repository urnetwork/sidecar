# Compact semantic / vector search indexes for client-side search in an E2EE versioned store

Scope: an optional semantic layer beside a lexical index. Clients download a per-repo index in full and search on device. Embeddings are computed only on user devices, by committers or a designated always-on device. Clients are pure Go (desktop, gomobile iOS/Android) plus a WASM browser worker. Research date 2026-11-05.

**Local measurements in these notes.** Some numbers were measured locally on an Apple M1 Max (10 cores, macOS), Go 1.27.3 and Node v24.14.1. These are labelled "[local benchmark]" with the path of the program used. The programs are in the session scratchpad, which is temporary, so the method is described inline. They were not run on phones, and the phone figures here are inferences.
- Hamming/int8/float scan benchmark: `/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hambench/main.go`. Pure Go, no cgo, no assembly. It uses random data, which does not change scan cost. It reports the median of 5–11 repetitions.
- Float determinism test: `/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/fmatest/main.go`
- Pure-Go embedder (Hugot) build: `/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hugotbench/main.go`. It was compiled only. Running it was blocked by the permission classifier because it executes third-party code.

---

## Q1. Quantization: bytes per vector and measured quality loss (binary + rescoring, int8, PQ/OPQ, Matryoshka)

### Takeaway
Binary (1-bit) codes are 32x smaller than float32: 48, 96 and 128 bytes at 384, 768 and 1024 dims. With rescoring against a float query they keep about 92–96% of nDCG@10 on models that tolerate it, but retention depends heavily on the model: e5-base-v2 keeps 75%, nomic 88%, MiniLM 94% and mxbai 96%. int8 keeps about 97% without rescoring and about 99% with it. Matryoshka (MRL) truncation multiplies with quantization: 64 B/vector keeps about 91% (mxbai, 512-d binary) and 128 B/vector keeps 98% (Arctic-M v1.5, 256-d int4). Generic PQ and LSH degrade sharply at 32x compression unless the PQ is trained jointly with the encoder (JPQ).

### Cited Findings

**Bytes per vector.** These are computed from the formulas cited.

| Format | 384-d | 768-d | 1024-d | Formula / source |
|---|---|---|---|---|
| float32 | 1,536 | 3,072 | 4,096 | 4·d ([Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes)) |
| fp16 / bf16 | 768 | 1,536 | 2,048 | 2·d. Vespa found bf16 vectors had "zero quality loss vs FP32" ([Vespa, Jan 2026](https://blog.vespa.ai/embedding-tradeoffs-quantified/)) |
| int8 scalar (SQ8) | 384 | 768 | 1,024 | d ([Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes)), plus one shared per-dimension min/max calibration table per index ([HF](https://huggingface.co/blog/embedding-quantization)) |
| int4 (SQ4) | 192 | 384 | 512 | d/2 ([Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes)) |
| binary 1-bit (sign) | 48 | 96 | 128 | d/8 ([HF](https://huggingface.co/blog/embedding-quantization), [mixedbread](https://www.mixedbread.com/blog/binary-mrl)) |
| RaBitQ 1-bit (Faiss) | 56 | 104 | 136 | d/8 + 8 ([Faiss guidelines](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index)) |
| PQ, M sub-quantizers × 8 bits | M (e.g. 48 / 96 / 128 at M = d/8) | | | ceil(M·nbits/8). M is "typically <= 64" ([Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes), [guidelines](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index)) |
| OPQ + 4-bit PQ fast-scan | M/2 | | | "the total storage is M/2 bytes per vector" ([Faiss guidelines](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index)) |
| MRL + binary, examples | 512-d → 64 B; 256-d → 32 B; 128-d → 16 B | | | [mixedbread](https://www.mixedbread.com/blog/binary-mrl) |
| MRL + int4, Arctic-M v1.5 | 256-d → 128 B | | | [Snowflake arctic-embed README](https://github.com/Snowflake-Labs/arctic-embed) |

**Binary quantization with rescoring: Hugging Face, Mar 22 2024.** MTEB Retrieval subset of 15 BEIR-style datasets, NDCG@10. Binary results use rescoring with top_k = 100 and rescore_multiplier = 4 (400 candidates). int8 results use a direct dot product with no rescoring ([HF blog](https://huggingface.co/blog/embedding-quantization)).

| Model (dim) | float32 | int8 (no rescore) | binary (rescored) |
|---|---|---|---|
| mxbai-embed-large-v1 (1024) | 54.39 | 52.79 (97%) | 52.46 (96.45%) |
| Cohere embed-english-v3.0 (1024) | 55.0 | 55.0 (100%) | 52.3 (94.6%) |
| nomic-embed-text-v1.5 (768) | 53.01 | n/a | 46.49 (87.7%) |
| e5-base-v2 (768) | 50.77 | 47.54 (94.68%) | 37.96 (74.77%) |
| all-MiniLM-L6-v2 (384) | 41.66 | 37.82 (90.79%) | 39.07 (93.79%) |

Further findings from the same post:
- Without rescoring, mxbai binary keeps about 92.5%. Raising rescore_multiplier from 1 to 10 gave no further gain for binary.
- int8 with a multiplier of 4–5 kept about 99%. The headline figures are "int8 ~99.3%, binary ~96%."
- The authors blame e5-base-v2's collapse on "dimension collapse" and recommend testing each model.
- int8 ranges are per-dimension min/max from a calibration set (example: 1,000 NQ questions). The authors note "the calibration set strongly affects performance."
- Demo: 41M Wikipedia texts, a 5.2 GB in-RAM binary index plus a 47.5 GB on-disk int8 index. Retrieval takes the top 40 by binary and rescores with int8 to return 10.
- Source: [HF blog](https://huggingface.co/blog/embedding-quantization).

**Binary combined with Matryoshka: mixedbread, mxbai-embed-large-v1.** MTEB retrieval, 13 public BEIR datasets, NDCG@10. Binarisation maps values > 0 to 1. Binary candidates are re-ranked with the float32 query ([mixedbread](https://www.mixedbread.com/blog/binary-mrl)).

| dims | 1024 | 512 | 256 | 128 | 64 |
|---|---|---|---|---|---|
| float32 NDCG@10 | 54.39 | 51.79 | 46.78 | 36.63 | 18.63 |
| binary NDCG@10 | 52.46 | 49.37 | 43.25 | 32.80 | 17.61 |
| binary retention vs float32 at 1024 | 96.46% | **90.76% (64 B)** | 79.52% (32 B) | 60.31% (16 B) | 32.38% (8 B) |

**Cohere Embed v3, multilingual, MIRACL.** Figures are from Cohere's own repo ([cohere-ai/BinaryVectorDB](https://github.com/cohere-ai/BinaryVectorDB)).
- Scores: float32 66.3; binary 62.8 (94.7%, computed); binary with int8 rescore 66.3.
- Search time over 1M docs: 460 ms float, 24 ms binary, 28 ms binary with rescore.
- Memory for 250M vectors: 954 GB float versus 30 GB binary (plus 240 GB int8 on disk).
- The pipeline has three steps:
  1. Hamming popcount(xor) search.
  2. Take the top 100 and rescore with the float query · (2·binary_doc − 1). This asymmetric step needs no extra storage.
  3. Take the top 30 and rescore with int8 vectors loaded from disk.
- Cohere states relative quality as binary ~90%, float-query rescoring ~95%, int8 rescoring ~99.99%. The "~90%" figure is not consistent with the table's 94.7%; the benchmark behind it is unclear.
- Cohere's blog (Nils Reimers, Mar 18 2024) also claims int8 keeps 99.99% at 4x less memory. The blog body could not be fetched, so this claim comes via [Simon Willison's summary](https://simonwillison.net/2024/Mar/26/cohere-int8-binary-embeddings).

**Vespa, "Embedding Tradeoffs, Quantified" (Thomas H. Thoresen, Jan 14 2026).** NanoBEIR nDCG@10, binary vectors versus float ([Vespa](https://blog.vespa.ai/embedding-tradeoffs-quantified/)):
- GTE-ModernBERT: 0.670 vs 0.685 (98%)
- E5-base-v2: 0.602 vs 0.651 (92%)
- E5-small-v2: 87% retention (absolute values not given)

**Qdrant (Sept 2023, archived).** Recall here is overlap with float results, not nDCG ([Qdrant](https://qdrant.tech/articles/binary-quantization/)):

| Model | Dims | Recall | Oversampling |
|---|---|---|---|
| OpenAI text-embedding-3-large | 3072 | 0.9966 | 3x |
| OpenAI text-embedding-3-small | 1536 | 0.9847 | 3x |
| OpenAI ada-002 | 1536 | 0.98 | 4x |
| Gemini | 768 | 0.9563 | 3x |
| Mistral Embed | 768 | 0.9445 | 3x |

Qdrant also states BQ "will" give worse results below 1024 dims. That contradicts its own 768-d rows.

**Weaviate rotational quantization (RQ).** 8-bit RQ gives about 4x compression at 98–99% recall. 1-bit RQ gives close to 32x, with an expected recall of 70–90% on 1536-d vectors. Default rescoring is 20 candidates for 8- and 4-bit and 512 for 1-bit. 8-bit RQ shipped for HNSW in v1.32 and for flat indexes in v1.35; 1-bit shipped for HNSW in v1.33 and for flat in v1.35 ([Weaviate docs](https://docs.weaviate.io/weaviate/configuration/compression/rq-compression), [Weaviate blog, Aug 26 2025](https://weaviate.io/blog/8-bit-rotational-quantization)).

**CoRECT (arXiv 2510.19340; v1 Oct 22 2025, v3 Jan 15 2026)** ([CoRECT](https://arxiv.org/html/2510.19340v3)):
- 1-bit zero-threshold binarisation, Recall@100 at 10k passages versus full precision:
  - Jina-v3: 83.39 vs 83.85
  - Snowflake-M v2: 82.62 vs 82.00
  - E5-large-instruct: 71.23 vs 84.31; a median threshold raises it to 86.31
- Losses grow with corpus size. At 100M passages:
  - Jina: 44.15 → 41.39
  - E5: 50.92 → 19.23
  - Snowflake-M v1: 50.92 → 32.46
- LSH and PQ "perform relatively well at lower ratios" but their effectiveness "drops substantially at 32× compression" on BEIR.
- For 3 of 4 models, moderate truncation combined with quantization beat heavier quantization at the same compression ratio.
- Scalar quantization "barely impacts performance" on Snowflake V2.

**PQ / OPQ in dense retrieval.**
- Thakur, Reimers and Lin found that naive learning-to-hash (BPR binary, JPQ product quantization) underperforms TAS-B "by up to 14% nDCG@10" on BEIR at 32x memory. Domain adaptation recovers 11.5% (BPR) and 8.2% (JPQ). CPU speedups are 14x (BPR) and 2x (JPQ) ([arXiv 2205.11498](https://arxiv.org/abs/2205.11498)).
- The INCOME project reports average BEIR nDCG@10 of 0.414 for TAS-B fp16, 0.402 for JPQ at 32x and 0.357 for BPR at 32x. These figures come from a search snippet of [INCOME on PyPI](https://pypi.org/project/income/) and were not fetched.
- The JPQ paper reports about 30x index compression with roughly 10x CPU and 2x GPU speedups, nearly matching brute-force dense retrieval on MS MARCO. It argues that conventional OPQ "hurts effectiveness substantially" because the encoder and the compression are optimised separately ([arXiv 2108.00644](https://arxiv.org/abs/2108.00644); search snippet).

**Matryoshka truncation.**
- **HF, Feb 23 2024.** At 8.3% of size (64 of 768 dims), an MRL-trained mpnet keeps 98.37% of STSB Spearman, against 96.46% for a standard model ([HF Matryoshka](https://huggingface.co/blog/matryoshka)).
- **nomic-embed-text-v1.5**, MTEB average by dimension. Truncation requires layer_norm before slicing ([model card](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5)):

  | dims | 768 | 512 | 256 | 128 | 64 |
  |---|---|---|---|---|---|
  | MTEB | 62.28 | 61.96 | 61.04 | 59.34 | 56.10 |

- **EmbeddingGemma-300M**, MTEB English v2 mean(task) by dimension ([model card](https://huggingface.co/google/embeddinggemma-300m)):

  | dims | 768 | 512 | 256 | 128 |
  |---|---|---|---|---|
  | English v2 | 69.67 | 69.18 | 68.37 | 66.66 |
  | Code v1 | 68.76 | 68.48 | 66.74 | 62.96 |

  QAT weight quantization at 768-d scores 69.49 (Q8_0) and 69.31 (Q4_0) on English v2.
- **Snowflake arctic-embed-m-v1.5.** At 256 dims with int4, 128 B/vector, it scores 53.7 on MTEB Retrieval NDCG@10 (98%) against 55.1 at full 768-d ([arctic-embed README](https://github.com/Snowflake-Labs/arctic-embed), [Snowflake blog](https://www.snowflake.com/en/engineering-blog/arctic-embed-m-v1-5-enterprise-retrieval)). The HF card's "54.2 (100%)" is the 256-d int8 figure against its own 256-d baseline, so it is not comparable.
- **static-retrieval-mrl-en-v1.** Halving the dimension lowers NanoBEIR NDCG@10 from 0.5031 to 0.4957 (−1.47%) ([HF static embeddings](https://huggingface.co/blog/static-embeddings)).

### Inferences
- For 384-d models, a binary code is only 48 B, but retention varies a lot. MiniLM keeps 93.8% (HF), E5-small-v2 87% (Vespa) and e5-base 75% (HF). The model choice must be validated with binarisation on representative repo data such as transcripts, logs, code and email. No published number covers those domains.
- Rescoring with a float query against the binary document codes needs no extra index bytes. Cohere's step 2 lifts quality from about 90% to 95%, and HF's mxbai result goes from 92.5% to 96.45%. This suits a downloaded index best. Storing int8 vectors for rescoring adds d bytes per vector, 8x the binary payload, which multiplies download size.
- A middle option is int8 or int4 rescoring vectors at a truncated MRL dimension, for example 256-d int8 at 256 B or 256-d int4 at 128 B.
- If int8 or int4 are used, the calibration ranges must be fixed per model version and shipped with the index format. Every committer then quantizes identically, avoiding the calibration-set sensitivity HF reports.
- For MRL models, a two-stage layout fits a downloadable index. A short binary prefix (for example 256-bit) is used for the scan, and longer codes are used only for candidates.

### Gaps
- No published binary or int8 retention found for bge-small-en-v1.5, gte-small, EmbeddingGemma (at 256 or 128 d) or mxbai-embed-xsmall-v1.
- No plain (non-joint) PQ/OPQ nDCG figures on BEIR found for current small models. Only the JPQ/BPR/TAS-B results and CoRECT's qualitative statement were found.
- Cohere's primary blog body could not be fetched. Its relative-quality claims come from Cohere's GitHub repo and secondary summaries.
- Elastic BBQ and RaBitQ measured BEIR numbers were not researched.
- No measurements on agent transcripts, tool logs, code or email domains exist in any source found.

---

## Q2. Index structures: flat scan vs HNSW vs IVF-PQ, per-vector overhead, and when a flat binary scan fits in about 100 ms

### Takeaway
At 1M chunks or fewer, a flat brute-force scan of 1-bit codes plus rescoring of a few hundred candidates is fast enough on every target.
- Measured in pure Go on an M1 Max, a 1M × 384-bit scan with exact top-400 selection takes about 3.8 ms on one thread (0.7 ms on 4 threads).
- The same scan compiled to WASM under Node takes about 8 ms.
- HNSW adds 128–256+ B/vector of graph links at typical M values. That is more than the 48–128 B codes themselves, and buys nothing at this scale.
- The binding constraint at 1M is download and RAM size, not CPU.

### Cited Findings

**Per-vector overhead formulas from Faiss.**
- Flat adds nothing; it "does not add overhead".
- HNSW costs "(d * 4 + M * 2 * 4) bytes per vector" with 4 ≤ M ≤ 64. So M = 16 adds 128 B and M = 32 adds 256 B of links.
- IVFFlat costs 4·d + 8, where the 8 bytes store the vector ID.
- IVF-SQ8 costs d + 8 and IVF-SQ4 costs d/2 + 8.
- IVFPQ costs ceil(M·nbits/8) + 8.
- IndexLSH (binary codes compared by Hamming distance) costs ceil(nbits/8).
- Sources: [Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes), [Faiss guidelines](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index).

**Other Faiss guidance.**
- Only Flat guarantees exact results.
- For "1000-10000" searches, build time is not amortised, so Flat is the most efficient choice.
- IVF below 1M vectors should use K = 4·√N to 16·√N centroids, trained on 30·K to 256·K vectors ([Faiss guidelines](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index)).

**Other memory figures.**
- hnswlib says M "strongly affects memory consumption (~M)" ([hnswlib](https://github.com/nmslib/hnswlib)).
- Qdrant's rule of thumb is memory = 1.5 × N × d × 4 bytes. For 100K × 1536-d that is about 900 MB, against 128 MB with BQ ([Qdrant](https://qdrant.tech/articles/binary-quantization/)).
- Cohere's 42M-vector example needs about 160 GB of float32 plus about 20 GB of HNSW, against about 5 GB binary ([cohere-ai/BinaryVectorDB](https://github.com/cohere-ai/BinaryVectorDB)).

**Published speed figures.**
- HF measured exact CPU search with binary at 15.05x, 24.76x and 45.8x (min, mean, max) faster than float32 (Faiss 1.8.0). int8 was 2.99–4.8x faster (USearch 2.9.2) ([HF](https://huggingface.co/blog/embedding-quantization)).
- Cohere measured 1M docs in 460 ms float versus 24 ms binary ([cohere-ai/BinaryVectorDB](https://github.com/cohere-ai/BinaryVectorDB)).
- Vespa reports "~1 billion hamming distance calculations per second", roughly 7x more than prenormalised angular distance ([Vespa](https://blog.vespa.ai/embedding-tradeoffs-quantified/)).

**Local benchmark: binary scan.** Pure Go 1.27.3, darwin/arm64, M1 Max. No cgo, assembly or SIMD intrinsics; `math/bits.OnesCount64`. Each run is a scan plus exact top-400 via a distance histogram, then rescoring of 400 candidates. Median times in ms. [local benchmark](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hambench/main.go)

| code bits | N | index size | native, 1 thread | native, 4 threads (scan only) | WASM (Go js/wasm, Node 24/V8, 1 thread) | rescore 400 cands: int8·int8 / f32·int8 (native) | rescore 400 (WASM) |
|---|---|---|---|---|---|---|---|
| 384 | 10k | 0.5 MB | 0.04 | 0.02 | 0.09 | 0.055 / 0.18 | 0.22 / 0.55 |
| 384 | 100k | 4.8 MB | 0.38 | 0.10–0.12 | 0.83 | 0.055 / 0.18 | 0.22 / 0.55 |
| 384 | 1M | 48 MB | 3.8 | 0.68–0.74 | 8.2 (an earlier run gave 34) | 0.055 / 0.18 | 0.22 / 0.54 |
| 768 | 1M | 96 MB | 8.4–8.9 | 2.1–2.6 | 33 | 0.11 / 0.39 | 0.43 / 1.1 |
| 1024 | 1M | 128 MB | 10.1–10.6 | 2.5–3.1 | 40 | 0.14 / 0.52 | 0.59 / 1.5 |

Notes on the binary-scan runs:
- The 384-bit kernel is a hand-unrolled 6-word loop; 768 and 1024 bits use a generic loop. In WASM the generic loop was about 2x slower per word, so codegen matters there.
- Go js/wasm ran with GOMAXPROCS = 1, so there is no thread parallelism.

**Local benchmark: exact scans without binary codes.** Same setup, scalar Go.
- float32 384-d: 43 ms at 100k native; 139 ms in WASM.
- float32 768-d: 93 ms at 100k native; 276 ms in WASM.
- int8 384-d: 14 ms at 100k and 141 ms at 1M native; 97–100 ms at 100k in WASM.
- Measured scalar Go throughput is about 0.89 GMAC/s native and about 0.28 GMAC/s in WASM (computed as 38.4M MACs / 43 ms and / 139 ms).
- Source: [local benchmark](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hambench/main.go).

### Inferences

**Phones.** The phone figures assume a current mid-range big core is 2–5x slower than an M1 Max core on this popcount/memory-bound loop, and about 10x slower for little cores. Both factors are assumptions and were not measured.
- A 1M × 384-bit single-thread scan would take about 8–40 ms; 1024-bit about 20–100 ms.
- **About 1M chunks is the practical ceiling for under 100 ms on phones** with 256–512-bit codes, and comfortably so with 2–4 threads.
- 100k chunks takes about 1–5 ms on any device.
- Exact float32 flat scan in scalar Go goes over 100 ms near 200k × 384-d on desktop, and much sooner in WASM or on phones. Binary codes, or SIMD kernels, are needed beyond about 100k.

**Download size.** This dominates the decision, not CPU. Computed sizes:

| Chunks | Binary 384-bit | int8 384-d rescoring vectors |
|---|---|---|
| 100k | 4.8 MB | +38 MB |
| 1M | 48 MB | +384 MB |

Rescoring against binary codes with a float query keeps the index at 48 B per chunk.

**Leakage.** Fetching only the needed int8 rows from the server on demand would leak query-dependent access patterns to the server. Rescoring data should therefore be downloaded whole or not used.

**IVF at small N.** Centroid and ID overhead is not negligible at these sizes (computed from the Faiss rules). For N = 100k at 384-d:
- K ≈ 1,265–5,060 centroids, taking 1.9–7.8 MB as float32.
- IDs add 0.8 MB.
- The binary codes themselves are only 4.8 MB.

IVF also needs a training step, which makes the index layout depend on which device trained it. Flat segments avoid both problems.

**HNSW.** At M = 16 an HNSW graph would be about 2.7x the size of 48 B binary codes. The graph is random-seeded and depends on insertion order (see Q7), so it is not reproducible across devices.

### Gaps
- No direct measurement on Android or iOS hardware. Phone numbers above are extrapolated from M1 Max.
- Not measured: Go assembly or `GOEXPERIMENT=simd` kernels, gomobile builds on devices, multiple Web Workers.
- No published phone Hamming-scan benchmark found.

---

## Q3. Small embedding models for on-device use: size, quantized size, throughput, quality

### Takeaway
The realistic on-device tier is about 22–33M-parameter BERT-small models, 23–34 MB as int8 ONNX:
- all-MiniLM-L6-v2: MTEB retrieval 41.7
- bge-small-en-v1.5: MTEB retrieval 51.7, average 62.2
- gte-small and e5-small-v2: MTEB retrieval about 49

The quality tier is EmbeddingGemma-300M: MTEB English v2 69.7, about 197 MB as q4, under 200 MB RAM, and MRL down to 128-d.

Static (lookup-table) models are 30–125 MB and roughly 60–400x faster on CPU. They retain 85–90% of MiniLM/mpnet retrieval quality but are only about 11% above BM25 on NanoBEIR.

Per-chunk latency on CPU ranges from a few ms (optimised int8 ONNX on modern ARM) to hundreds of ms in browser WASM. Mobile measurements are scarce.

### Cited Findings

**Model table.**

| Model (release) | Params | Dims (MRL) | Max tokens | Quality | ONNX fp32 / int8 / q4f16 size (HF API, Nov 2026) |
|---|---|---|---|---|---|
| all-MiniLM-L6-v2 | 22.7M ([sbert](https://sbert.net/docs/sentence_transformer/usage/efficiency.html)) | 384 | 256 (sbert truncation) | MTEB retrieval 41.66 ([HF](https://huggingface.co/blog/embedding-quantization)); NanoBEIR 0.5623 ([HF static](https://huggingface.co/blog/static-embeddings)) | 90.4 / 23.0 / 30.0 MB ([Xenova/all-MiniLM-L6-v2](https://huggingface.co/Xenova/all-MiniLM-L6-v2/tree/main/onnx)) |
| bge-small-en-v1.5 | 33.4M | 384 | 512 | MTEB avg (56) 62.17; retrieval 51.68 ([card](https://huggingface.co/BAAI/bge-small-en-v1.5)) | 133.1 / 33.8 / 36.2 MB ([Xenova/bge-small-en-v1.5](https://huggingface.co/Xenova/bge-small-en-v1.5/tree/main/onnx)) |
| gte-small | same size class (identical ONNX sizes) | 384 | 512 | MTEB 61.36; retrieval 49.46 ([bge card table](https://huggingface.co/BAAI/bge-small-en-v1.5)) | 133.1 / 33.8 / 36.2 MB ([Xenova/gte-small](https://huggingface.co/Xenova/gte-small/tree/main/onnx)) |
| e5-small-v2 | same size class | 384 | 512 | MTEB 59.93; retrieval 49.04 ([bge card table](https://huggingface.co/BAAI/bge-small-en-v1.5)); binary keeps 87% on NanoBEIR ([Vespa](https://blog.vespa.ai/embedding-tradeoffs-quantified/)) | 133.1 / 33.8 / 36.2 MB ([Xenova/e5-small-v2](https://huggingface.co/Xenova/e5-small-v2/tree/main/onnx)) |
| mxbai-embed-xsmall-v1 | about 24M (computed from 96 MB fp32) | 384 | n/a | not retrieved | 96.0 / 24.4 / 32.9 MB ([mixedbread-ai/mxbai-embed-xsmall-v1](https://huggingface.co/mixedbread-ai/mxbai-embed-xsmall-v1/tree/main/onnx)) |
| nomic-embed-text-v1.5 | 0.1B on card (about 137M computed from 547 MB) | 768 (512 / 256 / 128 / 64) | 8192 | MTEB 62.28 @768 … 56.10 @64; needs `search_query:` / `search_document:` prefixes ([card](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5)) | 547.3 / 137.3 / 111.1 MB ([nomic-ai/nomic-embed-text-v1.5](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5/tree/main/onnx)) |
| EmbeddingGemma-300M (Sept 4 2025) | 308M: about 100M transformer + 200M embedding params ([Google](https://developers.googleblog.com/en/introducing-embeddinggemma/)) | 768 (512 / 256 / 128) | 2048 | MTEB Eng v2 69.67, Multilingual v2 61.15, Code 68.76 @768 ([card](https://huggingface.co/google/embeddinggemma-300m)) | fp32 1,234.5 MB; fp16 617.4; q8 308.9; q4 196.7; q4f16 175.4 ([onnx-community](https://huggingface.co/onnx-community/embeddinggemma-300m-ONNX/tree/main/onnx)) |
| mxbai-embed-large-v1 | 335M ([sbert](https://sbert.net/docs/sentence_transformer/usage/efficiency.html)) | 1024 (MRL) | 512 | MTEB retrieval 54.39 ([HF](https://huggingface.co/blog/embedding-quantization)) | desktop-only class |
| static-retrieval-mrl-en-v1 (Jan 15 2025) | lookup table | 1024 (32–1024) | n/a | NanoBEIR 0.5032, 87.4% of all-mpnet-base-v2 ([HF static](https://huggingface.co/blog/static-embeddings)) | 125.0 MB safetensors fp32 ([HF repo](https://huggingface.co/sentence-transformers/static-retrieval-mrl-en-v1/tree/main/0_StaticEmbedding)) |
| potion-base-8M (Model2Vec) | 8M | 256 | n/a | NanoBEIR 0.4421, below BM25's 0.4518 ([HF static](https://huggingface.co/blog/static-embeddings)) | 30.24 MB safetensors ([minishlab/potion-base-8M](https://huggingface.co/minishlab/potion-base-8M/tree/main)) |
| bekko-embedding-v1-a8m (Jul 28 2026) | under 8M active params | 384 (256 / 128 / 64) | 8192 | MMTEB Multilingual v2 retrieval nDCG@10 56.2, above the multilingual-e5 family and BGE-M3 | 124 MiB ONNX with int8 vocab rows; runs in Transformers.js ([arXiv 2607.25180](https://arxiv.org/abs/2607.25180)) |

Notes on the table:
- MTEB versions differ between rows (v1 English 56-task averages versus MTEB English v2 versus MMTEB), so scores are not comparable across rows.
- EmbeddingGemma activations do not support float16 ([card](https://huggingface.co/google/embeddinggemma-300m)).

**Throughput and latency (measured where available).**
- **HF static-embeddings blog, CPU sentences/sec.** The hardware is not stated in the extracted text ([HF static](https://huggingface.co/blog/static-embeddings)).

  | Model | CPU sentences/sec |
  |---|---|
  | all-MiniLM-L6-v2 | 1,739 |
  | all-mpnet-base-v2 | 270 |
  | bge-base-en-v1.5 | 265 |
  | bge-large-en-v1.5 | 81 |
  | static-retrieval-mrl-en-v1 | 107,420 (397x mpnet; about 62x MiniLM, computed) |
  | potion-base-8M | 124,030 |
  | BM25 | 49,707 |

- **Vespa, Graviton3 ARM CPU.** INT8 model weights run 2.7–3.4x faster than FP32 while keeping 94–98% of quality. E5-small-v2 INT8 takes 2.5 ms for an 8-word query on Graviton3. A T4 GPU is 4–7x faster than Graviton3. On GPU, INT8 is 4–5x *slower* than FP32 ([Vespa](https://blog.vespa.ai/embedding-tradeoffs-quantified/)).
- **Google.** EmbeddingGemma runs in "<15ms embedding inference time (256 input tokens) on EdgeTPU" and in "less than 200MB of RAM with quantization" ([Google](https://developers.googleblog.com/en/introducing-embeddinggemma/)).
- **Phone (self-published, low confidence).** E5-small (33M) on a Snapdragon 8 Gen 2 takes about 28 ms with ONNX Runtime fp32, about 14 ms with int8, and 4.7 ms with hand-tuned NEON int8. Sequence length is unspecified ([DEV Community](https://dev.to/software_mvp-factory/arm-neon-simd-intrinsics-for-mobile-text-embedding-building-a-sub-10ms-semantic-search-pipeline-3cob)).
- **Browser, Transformers.js (forum anecdote).** bge-small-en-v1.5 took about 490–760 ms per note; MiniLM took about half that ([Joplin forum](https://discourse.joplinapp.org/t/gsoc-2026-proposal-draft-idea-3-ai-based-categorisation-harsh16gupta/49363/8)).
- **Bekko a8m** is 1.6x faster than multilingual-e5-small on x86 CPU and the fastest model tested on Raspberry Pi 5. The abstract gives no milliseconds ([arXiv 2607.25180](https://arxiv.org/abs/2607.25180)).
- **SwiftEmbed** (static lookup on potion-base-8M, Rust) reaches 1.12 ms p50 per text, 50k req/s, and MTEB 60.6 average over 8 tasks. It keeps about 75% of SBERT on complex retrieval ([arXiv 2510.24793](https://arxiv.org/abs/2510.24793)).
- **Sentence-Transformers CPU benchmarks** were run on an i7-13700K. OpenVINO INT8 was fastest there, and llama.cpp was fastest on a cloud CPU. The speedup ratios are only in chart images ([sbert efficiency](https://sbert.net/docs/sentence_transformer/usage/efficiency.html)).

### Inferences
- **Compute per chunk.** all-MiniLM-L6-v2 at 256 tokens needs about 3.0 GMAC, or 6 GFLOP. This is computed from 6 layers × (4·384² + 2·384·1536) MACs per token × 256 tokens, plus attention.
  - A 1M-chunk corpus therefore needs about 3 PMAC, or 6 PFLOP, of embedding work.
  - Vespa measured 2.5 ms for an 8-word E5-small-v2 INT8 query on Graviton3. E5-small-v2 has 12 layers. Scaling that linearly to 256 tokens and 6 layers gives about 30 ms per MiniLM chunk.
  - So assume about 30–100 chunks/s per device for optimised int8 ONNX. This is an assumption, not a measurement.
  - At that rate a 1M-chunk corpus takes about 3–9 hours, and a 100k-chunk repo about 17–56 minutes.
  - This favours embedding by committers at write time, incrementally, or offloading to the always-on device.
- **Vocabulary size.** The vocabulary embedding table dominates the size of small models:
  - EmbeddingGemma: 200M of 308M parameters.
  - MiniLM: about 47 MB of its 90 MB fp32 file, computed as 30,522 × 384 × 4 B for the standard BERT vocabulary.
  - Row-wise int8 on the vocabulary table, as in Bekko, is the cheapest size win.
- **Static models.** A static model is the only "model" that is trivial to run in pure Go and deterministic, but it beats BM25 only modestly on NanoBEIR: +11% for static-retrieval-mrl, and potion-8M is below BM25. Its value as a semantic layer *beside* BM25 is uncertain.

### Gaps
- No rigorous published per-chunk latency on iPhone or Android CPUs for MiniLM, bge-small or EmbeddingGemma.
- HF's static-embeddings CPU hardware is not identified in the extracted text.
- mxbai-embed-xsmall-v1 quality was not retrieved.
- No code- or transcript-specific small-model comparison was gathered. EmbeddingGemma's MTEB Code 68.76 is the only code number.

---

## Q4. Running embedding models from Go without cgo, and in WASM: libraries, binary size, practicality in 2026

### Takeaway
A cgo-free path exists as of November 2026: Hugot v0.8.5 with GoMLX's pure-Go backend.
- It compiles (verified locally) to a 15.4 MB stripped darwin/arm64 binary, 14.9 MB for linux/arm64, and 31.8 MB (6.5 MB gzip) for js/wasm.
- Its maintainers position it for small models such as MiniLM, and say it is much slower than ONNX Runtime or XLA. A related pure-Go ONNX runtime was about 8x slower than ONNX Runtime.

In the browser, ONNX Runtime Web 1.31.1 with Transformers.js 4.3.2 is the mature path:
- CPU WASM is 14.9 MB raw / 2.4 MB brotli; the WebGPU build is 29.5 MB / 4.0 MB.
- v4 added a C++ WebGPU runtime with about 4x faster BERT embeddings.

The practical split: keep Go for indexing and scan, use ORT-Web in the browser worker, and treat pure-Go transformer inference as a slow fallback. Static-embedding models are trivially portable.

### Cited Findings
- **Hugot backends** ([knights-analytics/hugot](https://github.com/knights-analytics/hugot)):
  - ONNX Runtime (`ORT` build tag), "currently the fastest backend".
  - OpenXLA (`XLA` build tag).
  - A pure Go backend "provided by the GoMLX project … does not require any cgo dependencies". It is intended for "smaller models such as all-MiniLM-L6-v2" and cgo-free environments, works best with batches of about 32, and `GOEXPERIMENT=simd` gives a "significant performance boost" with no figures. Only amd64-linux is stated as built and tested.
- **Local module resolution (Nov 2026)** of `github.com/knights-analytics/hugot@latest` gave v0.8.5 with:
  - gomlx v0.28.19, onnx-gomlx v0.5.16, gomlx/compute v0.1.16, gomlx/compute-onnx v0.1.15, gomlx/go-huggingface v0.4.17
  - cgo-backend dependencies daulet/tokenizers v1.27.0 (Rust), yalue/onnxruntime_go v1.26.0, and `github.com/microsoft/onnxruntime/go` (pseudo-version dated 2026-10-30)
  - The package includes a `backends/tokenizer_go.go` pure-Go tokenizer file.
  - [local build](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hugotbench/main.go)
- **Local compile-only measurement.** A minimal Hugot feature-extraction program built with `CGO_ENABLED=0 -ldflags="-s -w"`:
  - darwin/arm64: 15.4 MB
  - linux/arm64: 14.9 MB
  - GOOS=js GOARCH=wasm: 31.8 MB (6.5 MB gzip -9)
  - For comparison, a plain Go program (the scan benchmark) is 2.7 MB native and 2.9 MB WASM (0.84 MB gzip, 0.63 MB brotli).
  - WASM *execution* and latency were not measured; running it was blocked by permissions.
  - [local build](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/hugotbench/main.go)
- **onnx-gomlx docs.** Pure Go execution "will be slower (~8x based on a SentenceEncoder model, BERT based using gonnx vs ONNXRuntime)". This compares gonnx, not GoMLX's SimpleGo backend ([onnx-gomlx on pkg.go.dev](https://pkg.go.dev/github.com/gomlx/onnx-gomlx); search snippet).
- **GoMLX.** The Go backend is described as "slower but very portable (compiles to WASM/Windows/etc.)". XLA is "only linux/amd64 for now" ([GoMLX on pkg.go.dev](https://pkg.go.dev/github.com/gomlx/gomlx@v0.23.0); search snippet).
- **onnx-gomlx benchmark doc.** It covers KnightsAnalytics/all-MiniLM-L6-v2 at 128-token and about 13-token inputs, but publishes no numbers and does not cover the pure-Go backend ([benchmarks.md](https://github.com/gomlx/onnx-gomlx/blob/main/docs/benchmarks.md)).
- **Go SIMD, local Go 1.27.3 docs.**
  - `GOEXPERIMENT=simd` provides a portable, vector-size-agnostic `simd` package, "implemented in hardware (for example, arm64 'Neon' or amd64 'AVX/AVX2/AVX512') … or emulated in pure Go".
  - It also provides `simd/archsimd`, which "currently supports AMD64".
  - Both are experimental and "not subject to the Go 1 compatibility promise" (`go doc simd`, `go doc simd/archsimd`, [local toolchain](/usr/local/go/src/simd)).
- **Model2Vec.** The official implementations are Python and Rust (`model2vec-rs`). No official Go port was found; a niche pure-Go runner (laya-tools wiki) claims to match upstream output on potion-base-2M ([Model2Vec](https://github.com/MinishLab/model2vec), [model2vec-rs](https://docs.rs/model2vec-rs/latest/model2vec_rs/model/struct.StaticModel.html), [laya-tools wiki](https://github.com/teamswyg/laya-tools/wiki/Static-Embeddings-04-EN)).
- **Static model inference** is "as simple as using a torch EmbeddingBag" with mean pooling ([HF static](https://huggingface.co/blog/static-embeddings)).
- **Browser runtime versions (npm registry, local query):**
  - `@huggingface/transformers` latest is 4.3.2 (2026-10-27); `next` is 4.4.0-next.0.
  - `onnxruntime-web` latest is 1.31.1 (2026-10-26); `dev` is 1.32.0-dev.20261102.
- **ORT-Web 1.31.1 WASM sizes (local download and compression):**

  | File | Raw | gzip -9 | brotli -11 |
  |---|---|---|---|
  | `ort-wasm-simd-threaded.wasm` (CPU) | 14.85 MB | 3.79 MB | 2.39 MB |
  | `ort-wasm-simd-threaded.jsep.wasm` (WebGPU/JSEP) | 29.52 MB | 6.88 MB | 3.97 MB |
  | `.jspi.wasm` | 17.92 MB | | |
  | `.asyncify.wasm` | 28.75 MB | | |

  The `transformers.web.min.js` 4.3.2 bundle is 0.46 MB ([jsDelivr listing](https://data.jsdelivr.com/v1/packages/npm/onnxruntime-web@1.31.1?structure=flat)).
- **Transformers.js v4 (Feb 9 2026)** ([HF blog](https://huggingface.co/blog/transformersjs-v4)):
  - WebGPU runtime "rewritten in C++", tested with the ONNX Runtime team on about 200 architectures.
  - The `com.microsoft.MultiHeadAttention` operator gave "~4x speedup" for BERT-based embedding models.
  - The default `transformers.web.js` is 53% smaller.
  - `@huggingface/tokenizers` is 8.8 kB gzipped.
  - `env.useWasmCache = true` enables offline use after the first load.
  - Runs in browsers, Node, Bun and Deno.
- **EmbeddingGemma** is supported by sentence-transformers, llama.cpp, MLX, Ollama, LiteRT, Transformers.js and others, and has an onnx-community ONNX build ([Google](https://developers.googleblog.com/en/introducing-embeddinggemma/)).

### Inferences
- **Rough upper bound for naive pure-Go inference.** At the measured about 0.89 GMAC/s of naive scalar Go (Q2), MiniLM's about 3.0 GMAC per 256-token chunk would take about 3.4 s on one native thread and about 11 s in Go-WASM. Blocked or SIMD kernels such as GoMLX's should be much faster. Even so, the maintainers' "~8x slower than ORT" framing suggests tens to hundreds of ms per chunk on desktop. That suits only incremental, commit-time embedding of modest volumes, or query embedding.
- **Browser worker.** Shipping Hugot or GoMLX inside the Go WASM worker would add about 6.5 MB gzip and run single-threaded with no WASM SIMD guarantee. Loading ORT-Web (2.4 MB brotli) plus Transformers.js alongside the Go WASM search core is more practical. Embeddings cross the JS↔Go boundary as Float32Array.
- **gomobile.** gomobile's generated language bridge itself uses cgo, so for mobile the real constraint is "no third-party native library", not "no cgo". Linking ONNX Runtime Mobile via cgo (yalue/onnxruntime_go or the new official `microsoft/onnxruntime/go`) is technically possible but adds per-ABI native libraries. This should be verified against the project's build constraints.
- **Simplest deterministic semantic layer.** A static model (Model2Vec/potion or static-retrieval-mrl) needs only a WordPiece tokenizer, a 30–125 MB table and mean pooling. That is a few hundred lines of pure Go and would be bit-reproducible (see Q6). Its quality ceiling is low (Q3).

### Gaps
- No measured latency of Hugot's pure-Go backend, or of GoMLX SimpleGo, for any embedding model. The local run was blocked, and no published numbers were found.
- Whether Hugot's Go backend actually runs under js/wasm (as opposed to compiling) was not verified.
- The ONNX Runtime Mobile library size for iOS/Android was not researched.
- Whether ORT-Web's WASM build uses relaxed-SIMD is unknown (relevant to Q6).

---

## Q5. Hybrid lexical + semantic retrieval (BM25 + embeddings, RRF): reported quality gains

### Takeaway
Adding dense vectors to BM25 with rank fusion typically gains about 3–5 nDCG points over dense alone, and 8–20% relative over BM25 alone, on BEIR-like sets. Lexical search remains far better for keyword, identifier and exact-snippet queries, which dominate code and tool-log search. Gains shrink, and can turn negative, when the dense model is much stronger than BM25.

### Cited Findings
- **Azure AI Search** (Sept 2023, updated Nov 2024; Ada-002; RRF) ([Microsoft](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-search-outperforming-vector-search-with-hybrid-retrieval-and-ranking-capabilities/3929167)):

  | Benchmark (metric) | BM25 | vector | hybrid (RRF) | hybrid + semantic reranker |
  |---|---|---|---|---|
  | BEIR (NDCG@10) | 40.6 | 45.0 | 48.4 | 50.0 |
  | Customer sets (NDCG@3) | 40.6 | 43.8 | 48.4 | 60.1 |
  | MIRACL (NDCG@10) | 49.6 | 58.3 | 58.8 | 72.0 |

  - By query type, NDCG@3 (BM25 / vector / hybrid):
    - Keyword queries: 79.2 / **11.7** / 61.0
    - Exact snippet: 51.1 / 41.5 / 51.0
    - Low term overlap: 23.0 / 36.1 / 35.9
    - Misspellings: 28.8 / 39.1 / 40.6
  - Chunking, Recall@50: 512 tokens per vector gives 42.4 versus 34.9 for 8,191. A 25% overlap gives 43.9 versus 40.9 when breaking at token boundaries.
- **Vespa (Jan 2026), NanoBEIR.** "Every model scored higher with hybrid retrieval". The best hybrid method (among RRF, atan and linear) beats semantic-only by 3–5 nDCG points on average ([Vespa](https://blog.vespa.ai/embedding-tradeoffs-quantified/)).
- **Anthropic Contextual Retrieval (Sept 19 2024).** Top-20 retrieval failure rate fell from about 5.7% (embeddings) to:
  - 3.7% with contextual embeddings (−35%)
  - 2.9% with contextual embeddings + contextual BM25 (−49%)
  - 1.9% with reranking added (−67%)

  Domains included codebases. "Embeddings+BM25 is better than embeddings on their own". The fusion algorithm was not specified ([Anthropic](https://www.anthropic.com/news/contextual-retrieval)).
- **Elastic, BEIR.** RRF raised average nDCG@10 by 1.4% over its learned sparse encoder (ELSER) alone and 18% over BM25 alone ([Elastic](https://www.elastic.co/search-labs/blog/improving-information-retrieval-elastic-stack-hybrid); search snippet).
- **2026 study on BRIGHT (reasoning-heavy queries, not BEIR).** Linear fusion with BM25 lifted BGE from 13.7 to 17.2 nDCG@10. It hurt stronger retrievers: GTE-Qwen2 23.3 → 21.3, ReasonIR 24.1 → 21.2. The study also tested RRF at k = 60 and recommends linear fusion over RRF ([arXiv 2604.03676](https://arxiv.org/pdf/2604.03676); search snippet).
- **NanoBEIR NDCG@10, HF:** BM25 0.4518 versus all-MiniLM-L6-v2 0.5623, static-retrieval-mrl 0.5032 and bge-base 0.6376 ([HF static](https://huggingface.co/blog/static-embeddings)).

### Inferences
- **Lexical first.** Agent transcripts, tool logs and code are identifier-heavy. Azure's keyword-query row (BM25 79.2 versus vector 11.7) argues for a lexical-first design, with semantic as an additive RRF signal. That matches the "optional layer" framing. RRF needs only ranks, so the semantic layer can be absent or stale for some segments without breaking scoring.
- **Biggest expected win.** Concept and paraphrase queries with low term overlap: vector 36.1 versus BM25 23.0, and misspellings.
- **Contextual chunking.** Anthropic's contextual chunk prefixes could be generated on the committer's device at write time, since the server cannot do it. The 49% failure-rate reduction combines contextual embeddings and contextual BM25, so part of the benefit also accrues to the lexical index.

### Gaps
- No hybrid results specific to code, chat transcripts or email with small on-device models.
- No measurement of hybrid BM25 combined with *binary-quantized* small-model vectors. Fusion may cover part of the binarisation loss, but this is unmeasured.
- The primary sources for the Elastic and BRIGHT numbers were seen only as search snippets.

---

## Q6. Determinism: are embeddings bit-identical across CPUs and platforms?

### Takeaway
They are not, by default. Even the same pure-Go code gives different float32 bits on arm64 than on amd64 or WASM, because the Go compiler fuses multiply-adds on arm64. ONNX Runtime uses different kernels per instruction-set architecture (ISA), including an AVX2 int8 path that can saturate. WASM relaxed-SIMD is non-deterministic by design.

The differences are tiny (ULP-level) and almost never flip a sign bit. Binary codes are therefore nearly but not guaranteed identical. The robust design is to compute document embeddings once, by the committer, and store them as data in the index. Never require recomputation to match; if bit-exactness is needed, use integer or explicitly rounded fixed-order arithmetic.

### Cited Findings
- **Go spec.** "An implementation may combine multiple floating-point operations into a single fused operation, possibly across statements, and produce a result that differs from the value obtained by executing and rounding the instructions individually. An explicit floating-point type conversion rounds to the precision of the target type, preventing fusion that would discard that rounding." Source: [Go spec, Arithmetic operators](https://go.dev/ref/spec#Arithmetic_operators); quoted from the local `go1.27.3/doc/go_spec.html`, lines 5093–5096.
- **Local test, Go 1.27.3: 10,000 dot products of 384-d float32 vectors with `s += a[i]*b[i]`.**
  - darwin/arm64 compiled the loop with a fused multiply-add (one FMADD-family instruction in `main.dot`).
  - amd64 (GOAMD64 = v1 under Rosetta, and also a v3 build inspected with objdump) and js/wasm did not fuse.
  - arm64 results differed from the amd64/WASM results in **8,140 of 10,000** dot products, with zero sign flips. Result hashes were arm64 `52e92858…` versus amd64/WASM `e5a39663…`.
  - With explicit `float32(a[i]*b[i])` rounding, all three platforms produced the identical hash `e5a39663b43b34da`.
  - [local test](/private/tmp/claude-501/-Users-brien-urnetwork-sidecar/ab317000-f07f-4dd3-a893-6aa3b74b038e/scratchpad/fmatest/main.go)
- **ONNX Runtime quantization docs** ([ORT quantization](https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html)):
  - On x86-64 AVX2/AVX512 (non-VNNI), U8S8 uses `VPMADDUBSW`, which "might suffer from saturation issues", so the output may not fit in 16 bits.
  - "There is no such issue on other CPU architectures (x64 with VNNI and Arm®)."
  - `reduce_range` (7-bit weights) or U8U8 are the mitigations.
  - The docs recommend dynamic quantization for transformers; its scales are computed per forward pass, so they depend on the input batch.
- **Field reports and per-ISA kernels.**
  - A BERT INT8 model gave incorrect results on an AVX2-only CPU but worked on AVX-512; UINT8 worked on both ([HF forum](https://discuss.huggingface.co/t/difference-in-the-vector-generated-by-the-int8-quantized-model-vs-base-onnx-model/164270); user report).
  - ORT's MLAS library has separate kernels per ISA: AVX2 u8u8/u8s8/avxvnni and AVX512 u8u8/u8s8/avx512vnni ([ORT commit](https://app.semanticdiff.com/gh/microsoft/onnxruntime/commit/a4e58e8feb375f266a4e80c669d7b467a11ea0a3); search snippet).
- **ARM study (2026 preprint).** ONNX Runtime 1.25.0 CPU EP and PyTorch 2.11.0 qnnpack INT8 produced byte-identical outputs across two ARM nodes for MobileNetV2 and ResNet18. This is a small preliminary study, image models only ([arXiv 2607.23227](https://arxiv.org/pdf/2607.23227); search snippet).
- **WASM relaxed-SIMD.**
  - It "introduce[s] local non-determinism where the results … may vary based on hardware support" ([WebAssembly design #1401](https://www.github.com/WebAssembly/design/issues/1401)).
  - `relaxed_madd` "might round once or twice" ([LLVM discussion](https://lists.llvm.org/pipermail/llvm-commits/Week-of-Mon-20250929/1747062.html)).
  - LLVM now lowers `fmuladd` to `relaxed_madd` when relaxed-SIMD is enabled ([LLVM commit](https://lists.llvm.org/pipermail/llvm-commits/Week-of-Mon-20251013/1753482.html)).
- **hnswlib** seeds its RNG (`random_seed`, default 100) and builds with all cores by default (`num_threads`). It makes no determinism claim ([hnswlib](https://github.com/nmslib/hnswlib)).

### Inferences
- **Rules that follow for a shared, multi-committer index:**
  1. Document vectors are produced once by whoever commits the chunk, or by the designated device, and stored keyed by (chunk content hash, model ID, model version, quantization version). Readers never recompute them.
  2. Query vectors computed on another platform may differ at ULP level, which does not matter for ranking quality.
  3. Mixing vectors from different devices in one index is fine for approximate search.
- **Bit-exact recomputation.** Needed, for example, to dedupe or verify another committer's vectors, or to make index segments reproducible and content-addressed. It requires:
  - a pinned tokenizer, weights and quantization parameters;
  - fixed reduction order;
  - no FMA fusion (explicit rounding in Go), or integer-only arithmetic;
  - no thread-count-dependent reductions;
  - avoiding relaxed-SIMD in WASM.

  A static (lookup + mean) model in integer or fixed-point arithmetic meets all of these easily. Transformer stacks in ORT across x86, ARM and WASM do not.
- **Binary codes are robust.** A component flips only if it sits within the error band around 0, so measured sign flips were 0 in 10,000 dot products. Binary codes from different devices will match in nearly all bits. A rare flip changes Hamming distance by 1 and is harmless for search but fatal for byte-level content addressing.
- **Batch dependence.** Dynamic int8 quantization (ORT's recommendation for transformers) computes activation scales per forward pass. Embedding the same chunk in different batches, or with different padding, can therefore change the output. Embed with batch size 1, or fix the padding and static scales, if reproducibility matters. This is an inference from the ORT docs' description, not measured.

### Gaps
- No official ONNX Runtime statement on fp32 bit-identity across AVX2, AVX-512, NEON and WASM was found.
- Not measured: ORT CPU EP thread-count invariance and batch-size invariance for BERT-class models.
- Not verified: whether ORT-Web builds enable relaxed-SIMD.
- Not measured: how many binary-code bits actually differ between devices for a full transformer (as opposed to a single dot product).

---

## Q7. Incremental updates and deletions: does HNSW need rebuilds?

### Takeaway
HNSW supports incremental inserts but not true deletes. Libraries tombstone deleted nodes (hnswlib `mark_deleted`); Faiss HNSW cannot remove at all. Heavy churn accumulates unreachable nodes and slower queries, so periodic rebuild or compaction is the industry norm; FreshDiskANN-style repair is the research answer.

Flat (and IVF) indexes handle appends and deletes trivially. For a versioned store, append-only flat segments with tombstone bitmaps and periodic compaction fit far better, and stay deterministic and diffable.

### Cited Findings
- **hnswlib** has "full support for incremental index construction and updating the elements" ([hnswlib](https://github.com/nmslib/hnswlib)).
  - `mark_deleted` omits an element from results but leaves it in the graph.
  - `allow_replace_deleted` / `replace_deleted` reuse deleted slots ("allows to save memory").
  - `resize_index` is not thread-safe with add or query.
  - The latest stable release is 0.9.0; 0.10.0rc2 is a release candidate.
- **Faiss.** HNSW "does not support removing vectors from the index" because removal would break the graph. Flat supports `remove`, but it shrinks the index and renumbers vectors; IDs require `IndexIDMap` ([Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes), [Faiss guidelines](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index)).
- **Xiao et al., Jul 2024.** "During update operations, HNSW can result in some data points becoming unreachable", which "could significantly affect the search accuracy". Under many real-time operations "the performance of HNSW and most graph-based indices become unacceptable". Their MN-RU method suppresses the growth of unreachable points; the abstract gives no figures ([arXiv 2407.07871](https://arxiv.org/abs/2407.07871)).
- **Mishra et al., Dec 2025.** Prior deletion methods "come at the cost of increased query latency, decreased recall, or prolonged deletion time". They propose random-walk-based deletion ([arXiv 2512.18060](https://arxiv.org/abs/2512.18060)).
- **FreshDiskANN (2021).** Graph ANN algorithms "support only static indices", and the industry rebuilds periodically, which can be "prohibitively expensive". FreshDiskANN keeps ">95%" 5-recall@5 with "thousands of concurrent real-time inserts, deletes and searches per second", at a "5-10x reduction in the cost of maintaining freshness" ([arXiv 2105.09613](https://arxiv.org/abs/2105.09613)).
- **Practitioner advice (blog, low authority).** Reindex pgvector HNSW when the tombstone ratio passes about 10% ([pg_trickle blog](https://pgxn.org/dist/pg_trickle/0.36.0/blog/hnsw-recall-distribution-drift.html)).
- **Weaviate** documents rescoring and compression for both HNSW and flat indexes. Flat-index RQ support arrived in v1.35 ([Weaviate docs](https://docs.weaviate.io/weaviate/configuration/compression/rq-compression)).

### Inferences
- **Fit with a versioned E2EE store.** A flat segmented vector index maps directly onto the store:
  - Each commit range adds an immutable segment of (chunk ID, binary code, optional int8/MRL rescoring bytes).
  - Deletions and updates become a tombstone bitmap per segment.
  - Compaction rewrites segments.
  - Segments are deterministic given their inputs, so they can be content-addressed, encrypted and delta-downloaded.
  - Search cost is the sum of segment scans. These are linear, and measured at about 0.4 ms per 100k × 384-bit (Q2).
- **HNSW.** Graphs are seeded, depend on insertion order and are often built multi-threaded. Two devices building the "same" index get different bytes, which defeats deduplication and diffing. Each graph must also be rebuilt or repaired as tombstones accumulate, which is expensive on phones. The graph adds 128–256 B/vector of download (Q2).
- **IVF.** Inserts and deletes are list-local, but the trained centroids are a shared, model-specific artefact. Retraining as the corpus drifts reshuffles every list. The drift claim is an inference, not measured in a source here.

### Gaps
- The often-repeated figure "HNSW 5-recall@5 fell from ~98% to ~88% after 20 update batches" could not be traced to a primary source in this session.
- No measured cost of rebuilding HNSW on a phone was found.
- Not researched: how Qdrant, Lucene and Weaviate compact HNSW after deletes.
