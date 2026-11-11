# CallToolResult schemas by protocol version

One JSON Schema per MCP version that go-sdk v1.7.0 serves (2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 and
2026-07-28), each describing a `tools/call` result and the content blocks it may hold at that version: text, image
and embedded resources from 2024-11-05, audio from 2025-03-26, `resource_link` and `structuredContent` from
2025-06-18, a resource link's icons from 2025-11-25. `mcp/result_test.go` validates the daemon's small and over-limit
results against each, as §22.5's §16 row asks a strict client to.

These are written by hand from the published specification's `CallToolResult` definitions, not vendored copies of
its `schema.json` files, since this build fetches nothing but Go modules. They keep only what a result can carry, and
none sets `additionalProperties: false` on a result, as the specification's result types do not. 2026-07-28's result
is taken to be 2025-11-25's: that version's changes are to the session and the handshake. Replace each with the
specification's own file when one is vendored.
