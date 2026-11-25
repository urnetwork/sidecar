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

Everything here is behind the release's switch, `SupportSettings.ServiceEnabled`, off by default until G-SUP-service
passes (§28.21): with it off every surface answers `ErrSupportUnavailable`, no MCP session lists the tools or the
resource, nothing is posted, and `ur support logs` alone works. FB's feedback service is FB's to build; the device side is
built against FB section 12's API and Appendix J's additions, with a fake in tests (`support_client_test.go`).

| Piece | Where |
|---|---|
| Kind 27 `support_send` at CanonicalAction version 5: field 80 `SupportFields` (81-89 reserved), its row and checks, field 70's rules `private_data` (15) and `attachment` (16) | `protocol/record.proto`, `approval_compute_support.go`, edits to `approval_compute_kinds.go`, `record_action_rules.go`, `sidecar_gate.go` |
| Kind 30 `support_message`, `SupportMessageBody`, its team projection with no V: field | `protocol/record.proto`, `record_kind.go`, `record_body.go` |
| The client: §28.6's checks in order, the gate (W or kind 27), §28.14's limits, the outbox with its retries under one client_ref, the service's transport over TLS to the policy's host alone, the member's events by a cursor, kind-30 entries, enumerated updates | `support_client.go`, `support_state.go`, `support_service.go`, `support_form.go`, `support_body.go`, `support_sources.go` |
| The client as a Sidecar's compute component | `support_component.go` |
| MCP's `support_send` (O), `support_list` (R), `support_read` (R, tainting first) and `ur://support/urnetwork` | `mcp/tools_support.go`; §16.5's rows in `mcp/catalog.go`, listed unbuilt while the switch is off |
| `ur support`, `show`, `send`, `watch`, `delete`, `settings`, `set`, and `logs --sent` | `cli/cmd_support_conversation.go`, `cli/cmd_support.go` |
| The apps' `Support()`: Conversation, Send, Delete, Logs, Settings, SetSettings, AddListener | `sdk/sidecar_support_conversation.go` |
| The skill's text | `skill/support/SKILL.md`, embedded by `support_skill.go` |

Readings:

- **client_ref under kind 27.** Field 3 hashes the SupportBody posted, which names its client_ref, so the client_ref is
  fixed when the message is built (the run's for a Harness run, random otherwise) and the use's effect key maps to it in
  the outbox, rather than being derived from the effect key as §28.6 says for a kind-27 use; question
  `support-skill-kind27-client-ref.md`.
- **The service's routes** beyond FB section 12's: attachments post to `/v1/entries/{id}/attachments` after their entry
  is known, each under the message's client_ref and its place; `DELETE /v1/entries/{id}` removes an item; events carry
  a message's body and sender with `include=note,body`, which `scope=member` reads.
- **A message whose run's marks cannot be read** counts as marked, rule `private_data`, the closed reading.
- **An MCP session's, a harness process's or a container socket's message** is basis taint with the run file's own taint
  reasons, none invented (`SupportSendActionArgs.CountsTainted`); `inputs_unknown` is the classifier's rule at the
  decision, not the action's.
- **The release's switch** is `SupportSettings.ServiceEnabled`, a setting until the release manifest (INFER's) carries a
  `support` switch; no host turns it on.
- **A message given up** after 7 days, or a request with no decision in 7 days, stays in the outbox, shown as not
  sent, until the person removes it; a posted message's bundle and files go after 7 days.
- **The person's support key** is kept in the client's sealed state until the harness config's `support` key exists
  (DESIGN §16.6's harness/ path), written only by the person's own act (`ur support set` on /dev/tty, `SetSettings`).
- **`ur support send` from a harness's process** is the run's message under the session agent's name, kind 27, and at
  a terminal no run binds the person's, a Confirm method; a person's message the scan warns on asks again on /dev/tty.

Waiting on others (each failing closed meanwhile):

- ATTEST: the signed policy's `support` line (§5.4), kept as raw JSON the way `search` and `services` are, for
  `ParseSupportPolicyLine`; until then no host is named and messages wait in the outbox.
- CTRUST (CTRUST-M11-01, -M12-01, -M13-01): `support:urnetwork`'s text in the policy, the person's acknowledgment, and
  compute credentials in the scan; until then every message answers `disclosure_required`.
- FB's service and its token route (G-SUP-service, FB's G1 to G5): the token source; until then nothing is posted.
- HARN (HARN-M11-02's run marks, -M11-03's tools, -M11-01's `support_update` event, -M14-05's enclave profile): the
  Harness's support tools and the private mark.
- SAFE (SAFE-M13-06, -M13-09, -M13-11): the classifier deciding a tainted run's kind 27; until then the person decides.
- CACL-M12-02: version 5's render, kind 27's card among it (§28.8's card: who reads it first, the whole text escaped,
  the item and its status, the bundle's manifest, each file whole, the run's taint and marks); until it lands a render
  shows field 80 as unshown and a kind-27 request takes no approval, so an outward message waits.
- SKILL (SKILL-M11-05, -M11-06): inbox notices and wakes for an agent whose run is closed, and `ur install-harness`
  writing the skill beside recurd's.
- CACL (§16.4's compute block): the network's `support` settings; until then the block's defaults.
- The push service: the `support` topic's hint and its wake.
