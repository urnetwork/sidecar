# The search index's vectors

D-TEST-15 and §22.9's Index determinism row: every file here is reproduced byte for byte, plaintext and hashes, on every
build leg, by the tests the table below names. A leg that builds a different byte, or reads a vector differently,
fails there and names its leg (the every-leg runner sets `SIDECAR_LEG`).

What pins the bytes:

- **Normalizer 1** (§11.14's tables row; FI-22): `norm.Version`, `cases.UnicodeVersion` and `unicode.Version` 17.0.0,
  from golang.org/x/text v0.43.0 linked unreplaced. A writer records the linked `norm.Version` and module version in
  every file's `IndexFileHeader` (fields 5 and 14), and a build whose tables are any other writes nothing. A toolchain
  or x/text bump therefore fails these tests until a new normalizer is assigned: it is never a vector rewrite.
- **Extractor 1** (DESIGN-DETAILS 11.2): `conformance/` is the design's own, read and never rewritten.
- **The format** (`protocol/INDEX-FORMAT.md`): entries, slots, shards, small files and the remote bodies' sizes.

## Files

Each row is a file under `testdata/index/` and the tests that reproduce it. `evs_index_vectors_test.go` holds this
table to the directory, both ways, so a new vector file needs a test that reproduces it, and a test named here must
exist.

| File | What it pins | Reproduced by |
|---|---|---|
| `conformance/charsets.json` | extractor 1's charset labels and the encoding each names (C1) | `TestIndexCharsetLabels` |
| `conformance/entities.json` | HTML's named character references (E1-E4) | `TestIndexReferenceTableIsCurrent`, `TestIndexReferenceTableIsEntitiesJson` |
| `conformance/file.json` | extractor 1's file documents | `TestIndexConformanceFile`, and in one pass `TestIndexStreamConformanceFile` |
| `conformance/mail.json` | extractor 1's mail documents | `TestIndexConformanceMail`, and in one pass `TestIndexStreamConformanceMail` |
| `conformance/sizes.json` | remote search's padded body sizes (Z2, Z3) | `TestSearchSizeVectors` (not on the `sidecar_http` leg, which runs no remote search) |
| `conformance/skip.json` | D6's shard test, lone(d) against ShardBody | `TestIndexSkipVectors` |
| `entry/vectors.json` | entries, file and companion | `TestEntryVectors` |
| `extract/doc_keys.json` | doc_keys from K_ref | `TestDocKeyVectors` |
| `extract/vectors.json` | documents, normalized text and key counts | `TestExtractVectors` |
| `head/vectors.json` | writer heads, slots and large entries | `TestIndexHeadVectors` |
| `merge/vectors.json` | merges' shards and manifests | `TestIndexMergeVectors` |
| `normalize/vectors.json` | normalizer 1's text and key sets, with the tables they were written under | `TestNormalizationVectors`, `TestLinkedTablesAreNormalizerOne` |
| `rollup/vectors.json` | roll-ups' all shards, manifests and removals | `TestIndexRollupVectors` |
| `shard/vectors.json` | bucket and all shards, their doc and tombstone tables | `TestShardVectors` |
| `slot/vectors.json` | slots, padded and full | `TestSlotVectors` |

## How they run

- **On this host, under every runtime.** `TestIndexVectorsUnderEveryRuntime` runs the tests above again in a child of
  the test binary under GOMAXPROCS 1 and 16, twice each, and under other time zones and locales (Turkish, Japanese,
  C), so nothing a build's runtime chooses reaches an index object's bytes. It needs to start a process, so a js/wasm
  leg reports it not run and runs the tests themselves directly.
- **The linked build.** `TestIndexHeadersRecordTheLinkedBuild` holds the header a writer records to normalizer 1's
  versions and to the headers the vectors carry, and fails a planted other module version.
- **On every leg.** `make index-vectors` runs the table's tests through the every-leg runner
  (`sidecartest/legs/legs_search_test.go`, tag `sidecar_legs`): darwin/arm64 natively, linux/arm64 and linux/amd64 in a
  container of `SIDECAR_LEGS_IMAGE`, windows/amd64 compiled, js/wasm and the `sidecar_http` page Worker in Node, and
  the gomobile legs by SDK-M10-06's cells, each one-pass conformance test in a process of its own (on js/wasm, in one
  process, the tests after them ran out of wasm's 4 GiB). A leg that cannot run here says so, and never reads as a pass.
- **Under the sdk's module graph.** `sdk/sidecar_index_vectors_test.go` reproduces the normalize, slot and shard
  vectors through `TestHookIndexVectorFindings` in the binary the sdk builds, where the apps' x/text is selected.
- **make check.** `check/` fails a leg that selects another x/text (the deps row), an `ios_extension` leg that compiles
  an index or search file (behind its switch until QD-988's split lands), and a `sidecar_http` leg that compiles a
  `search_remote_` file.

## Rewriting

`SIDECAR_WRITE_VECTORS=1 go test -run '<the test>' .` rewrites the vectors a test owns, as after a format change
before the freeze; a run without it holds them to what the code builds. `conformance/` is never rewritten. A rewrite
under tables other than normalizer 1's is refused by the normalizer before it writes anything.
