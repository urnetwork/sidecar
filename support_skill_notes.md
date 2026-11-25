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
| The app's ring, under the sdk Sidecar's state directory, with `app.started` and `app.stopped`, opened deferred (`SupportLogArgs.Deferred`) and started once the instance opens, so a locked or failed key store's sidecar creates nothing there | `sdk/sidecar_support.go` |
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
passes (§28.21): with it off sending and reporting answer `ErrSupportUnavailable`, no MCP session lists the tools or the
resource, nothing is posted, and the conversation stays empty; `ur support logs` and `ur support export` with no id
need no conversation and work. FB's feedback service is FB's to build; the device side is built against FB section 12's
API and Appendix J's additions, with a fake in tests (`support_client_test.go`).

| Piece | Where |
|---|---|
| Kind 27 `support_send` at CanonicalAction version 5: field 80 `SupportFields` (81-89 reserved), its row and checks, field 70's rules `private_data` (15) and `attachment` (16) | `protocol/record.proto`, `approval_compute_support.go`, edits to `approval_compute_kinds.go`, `record_action_rules.go`, `sidecar_gate.go` |
| Kind 30 `support_message`, `SupportMessageBody`, its team projection with no V: field, and its rules in `RecordBodyValidate` (caps in `RecordBodySettings`) | `protocol/record.proto`, `record_kind.go`, `record_body.go` |
| The client: §28.6's checks in order, the gate (W or kind 27), §28.14's limits, the outbox with its retries under one client_ref, the service's transport over TLS to the policy's host alone, the member's events by a cursor, kind-30 entries, enumerated updates | `support_client.go`, `support_state.go`, `support_service.go`, `support_form.go`, `support_body.go`, `support_sources.go` |
| The client as a Sidecar's compute component | `support_component.go` |
| The files a message names: an agent's beneath one root through `os.Root`, the person's where they name them; the run a caller's ancestry binds | `support_files.go` |
| `ur support export`'s archive, and FB section 10.3's enumerated report | `support_export.go`, `support_report.go` |
| MCP's `support_send` (O, with `files`), `support_list` (R), `support_read` (R, tainting first) and `ur://support/urnetwork` | `mcp/tools_support.go`; §16.5's rows in `mcp/catalog.go`, listed unbuilt while the switch is off |
| `ur support`, `show`, `send`, `watch`, `delete`, `settings`, `set`, `logs --sent`, `export` and `report` | `cli/cmd_support_conversation.go`, `cli/cmd_support.go`; `cli/UI.md`'s section |
| The apps' `Support()`: Conversation, Send, Delete, Logs, Settings, SetSettings, AddListener, on the local core and, remotely, over ur daemon's support methods | `sdk/sidecar_support_conversation.go`; `sdk/sidecar_backend.go`'s `dialOwn` |
| The skill's text | `skill/support/SKILL.md`, embedded by `support_skill.go` |

Readings:

- **client_ref under kind 27** (QD-1398, the owner's answer to `support-skill-kind27-client-ref`). Field 3 hashes the
  SupportBody posted, which names its client_ref, so the client_ref is fixed when the message is built (the run's for a
  Harness run, random otherwise) and the use's effect key maps to it in the outbox. The decider and its tier are posted
  beside the body: a kind-27 body names neither, and every post carries `Support-Tier` and `Support-Approved`, which the
  effect takes from the decisions its use spent: the person's where one is a device's, a presence key's or the harness
  prompt's, released; the classifier's otherwise, channel 4's and any decision that does not parse, agent, so a
  person's approval is claimed only where a decision shows one. The effect moves nothing unless the stored action's
  field 3, and the decided action's where it is kind 27's, hashes the body the outbox holds.
- **Kind 30 as a message leaves** (§28.6's outbox row, §28.12). The sent entry is written once, before the first post:
  its entry the item a follow-up continues or none, its seq 0, the bundle's whole manifest; the outbox item keeps that
  it was, so a retry writes none, and a crash between the write and its mark writes it twice, which its client_ref
  joins. The post's answer is recorded as a received entry, the acknowledgment the client_ref joins, with no text (the
  sent entry holds it), only where the view did not hold the message, so a lost answer whose events came first records
  it once. A received event's label past its cap is cut at a character's edge and a fixed_in past its cap left out,
  so the service cannot keep an event off the record by its size.
- **Files.** An agent's are read beneath one root, the MCP session's run's worktree where a hook bound one, else the
  harness's working directory, and a harness process's run's worktree for `ur support send`, through `os.Root`, so `..`
  and links cannot leave it; an absolute name is taken only beneath it. `ur support send --attach` names each file by
  its absolute path and the daemon reads it, since three 10 MiB files cannot ride the daemon's 4 MiB request; a harness
  process's inline bytes are refused, so an agent's file is always the daemon's read. The apps' files ride the request,
  within that bound, which the remote backend cannot pass.
- **Export.** A zip: README, `item.json` and `messages.txt` for an item, and each of this device's messages on it the
  outbox keeps (`body.json`, its bundle, its files); one message by its client_ref, for one with no entry yet; with
  neither, the next bundle alone, from the daemon's ring, which needs no network or conversation. At most
  `ExportMaxByteCount`, 40 MiB, so the control reply stays within ur's 64 MiB answer; ur writes a new file, never over
  one; refused under a harness, as `logs` is.
- **Report.** FB section 10.3's closed schema, filled from the registry and the ring, which must hold the code
  (`not_found` otherwise, a code the registry does not name too): registry version, component, code, severity, FB's
  occurrence bucket and the first day, ur's format-checked version, OS and arch, the sender and the disclosure version;
  posted from the outbox, tier auto, on the person's limits. The person's at a terminal, confirmed; an agent's needs
  FB's `feedback.auto` grant, which nothing builds, so it is refused `grant_required` (registry version 2 adds the
  value), and the auto tier's own limits wait with the grant. The conversation and the vault show it as one line:
  code, severity, occurrences and day.
- **The remote `Support()`** calls the daemon's methods: reads unconfirmed, `send`, `delete` and `set` confirmed (the
  person's acts in the app's UI); its listener long-polls `support.watch` on a session of its own (`dialOwn`), so the
  backend's one call session stays free.
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
