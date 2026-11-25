# The support skill: the build's notes

DESIGN-COMPUTE.md §28 (CO-45, with the owner's answers in CO-46), drafted by track `support-skill`. This file says what
is built, where, the readings the design left open, and what waits; DESIGN-COMPUTE.md stays the design. A design-records
track folds CO-45 and CO-46, and RECORD.md's kind 30, into the design documents.

## M11: the support log (built)

| Piece | Where |
|---|---|
| The registry: components, codes, fields, enums and buckets, each numbered for good | `support/registry.yml` |
| The generated code constants, enum types and one constructor per field | `support_log_registry.go`, from `check/support_log_test.go` (`SIDECAR_REGENERATE_SUPPORT_LOG=1 go test -tags sidecar_check -run '^TestSupportLogRegistryIsCurrent$' ./check`) |
| The typed API, `supportLog.Event(code, fields...)`, and the ring: segments of CRC-framed records, 7 days or 8 MiB, written by one goroutine, never blocking a caller | `support_log.go` |
| Bundles: the window, per-bundle salted tokens, the header, the 4 MiB bound, the manifest | `support_log_bundle.go` |
| The vet analyzer: every write passes a code constant and that code's constructors, directly | `check/support_log_test.go` (sidecar), `sdk/sidecar_support_log_vet_test.go` (sdk) |
| The canary corpus, driven through every field of every code and the bundle's header, scanning rings, bundles and their JSON | `support_log_canary_test.go`; a component adds its driver to `testSupportLogCanaryDrivers` |
| The daemon's ring, `<state>/support-log`, with `daemon.started` and `daemon.stopped` | `cli/cmd_support.go`'s `startUrSupportLog`, called from `cli/cmd_daemon.go` |
| The app's ring, under the sdk Sidecar's state directory, with `app.started` and `app.stopped` | `sdk/sidecar_support.go` |
| `ur support logs [--json]`, printed on /dev/tty alone, refused to a caller under a harness | `cli/cmd_support.go` |
| Settings | `support_settings.go`, `SidecarSettings.Support`; the process's ring is `SidecarSettings.SupportLog` |

Readings, each changing no format the design fixes:

- **Tokens.** §28.7 gives a token as the first 8 bytes of HMAC-SHA256 of an object's id under a salt drawn for each
  bundle. The ring must hold no byte of an id (the canary corpus), so it keeps HMAC-SHA256 of the id under a key of its
  own (16 bytes), and a bundle's token is the first 8 bytes of HMAC-SHA256 under the bundle's salt of that: a token
  still relates a bundle's events, no two bundles share one, and the key never leaves the device.
- **Buckets.** The registry states the count, duration and size buckets itself, so a bucket's edge is the format's
  and changes by a reviewed diff with the registry's version; counts are FB section 10.3's occurrences with 0 before.
- **Versions.** A version field keeps digits and dots, an optional leading v, and a build suffix of lowercase hex after
  `+` or `-`; anything else reads `invalid`, so no word reaches the ring through one. The header's channel is one of
  stable, beta, nightly and development, else `other`; ur has no channel variable yet, so it names none.
- **Bundle format.** gzip'd JSON, `{"format": "urnetwork-support-log-bundle-v1", "header": {...}, "events": [...]}`,
  each event `{t, component, code, severity, fields}` in the registry's words.
- **The analyzer** is a check rule over every module's non-test files (make check and landcheck run it), not a
  `go vet` tool: a vettool needs golang.org/x/tools as a direct requirement, whose go.mod line only CARCH-M11-02 edits
  (CONTRACTS C-28).

## M13b: the support client, the tools and the wire (draft)

See the section that track adds below once it lands.
