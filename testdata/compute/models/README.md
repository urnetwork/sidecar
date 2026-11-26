# Model mirror vectors

The api's model mirror and its release tooling (DESIGN-COMPUTE §6.5's mirror row, §14.5's `compute_model_mirror`;
CO-49; CSRV-M11-02): sidecar/model's `ComputeModelMirror` and `sidecarctl compute models` in server.

`draft.json` is a draft release manifest, INFER-M11-10's format before its index pins: two local models naming two
files, the second file under both models, so the tooling copies, indexes and serves it once. Its urls are a synthetic
hub's, `hub.example`, at pinned commits under `litert-community`, so a test sets the mirror's `HubHost` to
`hub.example` and serves the files from a fake hub. No file is stored here: byte i of each is (i + seed) mod 251.

| File | Bytes | Seed |
|---|---|---|
| `test-mirror-a.litertlm` | 2,621,440 (2.5 MiB) | 0 |
| `test-mirror-b-gpu.litertlm` | 1,048,577 (1 MiB and a byte) | 7 |

`indexed.json` is `draft.json` as the tooling's index step writes it with 1 MiB chunks, the least
`InferSettings.ModelChunkMinByteCount` takes, so the files have three chunks and two: every model file carries its
`index_sha256`, the SHA-256 of the chunk index `InferModelIndexBuild` computes from the mirrored bytes, and the whole
parses under `ParseInferManifest`. The indexes it pins are the format's (compute-plan-model-index-format, QD-1408).

`TestComputeModelMirrorVectorsAreCurrent` (sidecar/model/compute_model_mirror_test.go) holds `indexed.json` to what the
tooling writes; it changes only with the index format or `draft.json`, through
`SIDECAR_REGENERATE_COMPUTE_MODEL_VECTORS=1 go test -run '^TestComputeModelMirrorVectorsAreCurrent$' ./model/`.
server's `sidecarctl compute models` tests read both files.
