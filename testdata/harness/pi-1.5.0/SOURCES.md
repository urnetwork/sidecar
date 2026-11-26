# Where each golden line comes from

Every line here is copied unchanged from github.com/MichaelKinsy/PiG v0.7.0 (third_party/pig/URNETWORK.md),
from its fixtures or from the Pi 1.5.0 documentation it embeds at
coding/extension/host/subprocess/runtime-node/shims/pi-dist/pi-coding-agent/docs/ (written `docs/` below).
Lines are numbered from 1.

## events.jsonl

| Line | Event | Source |
|---|---|---|
| 1 | agent_start | docs/json.md, Event sequence |
| 2 | turn_start | docs/json.md, Event sequence |
| 3 | message_start, user | docs/json.md, Event sequence |
| 4 | message_end, user | docs/json.md, Event sequence |
| 5 | message_start, assistant | coding/cli/rpc_event_bytes_test.go, TestRPCEventBytesMatchPi's first event, as Pi's toJsonEvent writes it |
| 6 | message_update, text_delta | the same test's second event |
| 7 | message_update, text_delta with usage | docs/json.md, Reconstruct streaming messages |
| 8 | message_end, assistant | the message of line 5 under message_end, which toJsonEvent passes unchanged (docs/../modes/json-event.js) |
| 9 | turn_end | TestRPCEventBytesMatchPi's third event |
| 10 | agent_end | TestRPCEventBytesMatchPi's fourth event |
| 11 | agent_settled | docs/json.md, Event sequence |
| 12 | tool_execution_start | docs/json.md, Tool execution events |
| 13 | tool_execution_update | docs/json.md, Tool execution events |
| 14 | tool_execution_end | docs/json.md, Tool execution events |
| 15 | tool_execution_end with durationMs | coding/cli/rpc_agent_settled_aborted_test.go:42 |
| 16 | queue_update | test/parity/scenarios/rpc/25-rpc-clear-queue.toml:32's record |
| 17 | compaction_start | docs/json.md, Compaction events |
| 18 | compaction_end | docs/json.md, Compaction events, its placeholder usage and its empty details left out, as Pi leaves out an absent usage and details (PiG's coding/cli/rpc_events.go:80-95) |
| 19 | auto_retry_start | docs/json.md, Retry events |
| 20 | auto_retry_end | docs/json.md, Retry events |

## entries.jsonl

| Line | Entry | Source |
|---|---|---|
| 1-15 | header, model_change, thinking_level_change, message (user, assistant), label, branch_summary, custom_message, compaction, context_edit, custom | test/parity/scenarios/testdata/registry-session.jsonl, whole |
| 16 | message, system with sections and toolsAdded | docs/session-format.md, SessionMessageEntry |
| 17 | message, system patch with toolsRemoved | docs/session-format.md, SessionMessageEntry |
| 18 | message, toolResult | docs/session-format.md, SessionMessageEntry |
| 19 | usage | docs/session-format.md, UsageEntry |
| 20 | message, bashExecution | test/parity/scenarios/interactive-rendering/testdata/resumed-bash-cwd/sessions/resumed-bash.jsonl:2 |
| 21 | message, assistant with thinking blocks | test/parity/scenarios/interactive-rendering/testdata/thinking-cwd/sessions/2025-01-01T00-00-00-000Z_parity-thinking-21.jsonl:3 |
