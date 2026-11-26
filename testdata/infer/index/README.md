# Chunk index vectors

A local model file's chunk index (DESIGN-COMPUTE §6.5, CO-49; compute-plan-model-index-format, QD-1408), as sidecar's
`InferModelIndexBuild` writes it: RFC 8785 canonical JSON of

```
{"byte_count":<the file's size>,"chunk_byte_count":<the chunk size>,"chunks":["<lowercase hex SHA-256>",...],"sha256":"<the file's lowercase hex SHA-256>","version":1}
```

with chunk n covering [n × chunk_byte_count, min((n + 1) × chunk_byte_count, byte_count)).

`vectors.json` lists five files: of 0 bytes, 1 byte, one 16 MiB chunk, a chunk and a byte, and three chunks and a tail.
Byte i of each file is i mod 251, so no two of a file's whole chunks are alike, and no file is stored here. Each
vector names its index file, which holds the index's bytes exactly, with no newline, and gives the file's SHA-256 and
the index's, the pin a manifest carries as `index_sha256`.

`TestInferModelIndexVectors` (infer_model_index_test.go) builds each index from its file and holds it to these bytes;
the browser's engine Worker's tests read the same vectors (INFER-M13-02). The files are the format: they change only
with it, through `SIDECAR_REGENERATE_INFER_INDEX_VECTORS=1 go test -run '^TestInferModelIndexVectors$' .`, and a
change to them changes every manifest's pins.
