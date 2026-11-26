# Where each RPC golden line comes from

Every line here is copied unchanged from github.com/MichaelKinsy/PiG v0.7.0 (third_party/pig/URNETWORK.md), from the
Pi 1.5.0 documentation it embeds at
coding/extension/host/subprocess/runtime-node/shims/pi-dist/pi-coding-agent/docs/ (written `docs/` below) or from its
tests. Lines are numbered from 1. The Harness's RPC (harness_rpc.go, HARN-M14-01) reads and writes each as Pi does,
member for member and in Pi's order; sidecar's own rule that a command carry an id is the codec's, so the lines here
without one are Pi's grammar, which the codec then refuses.

## commands.jsonl

| Line | Command | Source |
|---|---|---|
| 1 | prompt with an id | docs/rpc-commands.md:12, prompt |
| 2 | prompt with images | docs/rpc-commands.md:17, prompt |
| 3 | prompt with streamingBehavior | docs/rpc-commands.md:23, prompt, during streaming |
| 4 | steer | docs/rpc-commands.md:51, steer |
| 5 | steer with images | docs/rpc-commands.md:56, steer |
| 6 | follow_up | docs/rpc-commands.md:75, follow_up |
| 7 | follow_up with images | docs/rpc-commands.md:80, follow_up |
| 8 | abort | docs/rpc-commands.md:99, abort |
| 9 | get_state | docs/rpc-commands.md:160, get_state |
| 10 | get_messages | docs/rpc-commands.md:193, get_messages |
| 11 | set_model | docs/rpc-commands.md:215, set_model |
| 12 | compact | docs/rpc-commands.md:372, compact |
| 13 | compact with customInstructions | docs/rpc-commands.md:377, compact |
| 14 | switch_session | docs/rpc-commands.md:597, switch_session |
| 15 | fork | docs/rpc-commands.md:615, fork |
| 16 | clone | docs/rpc-commands.md:643, clone |
| 17 | get_tree | docs/rpc-commands.md:724, get_tree |
| 18 | get_state with an id | docs/rpc.md:40, Correlate commands and responses |
| 19 | prompt with an id | docs/rpc.md:63, Run lifecycle |

## responses.jsonl

| Line | Response | Source |
|---|---|---|
| 1 | prompt, started | docs/rpc-commands.md:37, prompt |
| 2 | steer, queued | docs/rpc-commands.md:63, steer |
| 3 | follow_up, queued | docs/rpc-commands.md:87, follow_up |
| 4 | abort, no data | docs/rpc-commands.md:104, abort |
| 5 | switch_session, not cancelled | docs/rpc-commands.md:602, switch_session |
| 6 | get_state with an id | docs/rpc.md:41, Correlate commands and responses |
| 7 | prompt with an id, started | docs/rpc.md:64, Run lifecycle |
| 8 | a failed set_model | docs/rpc.md:78, Errors |
| 9 | a parse failure, no id | docs/rpc.md:84, Errors |
| 10 | an unknown command with an id | coding/cli/rpc_mode_test.go:653, its want |
| 11 | an unknown command without an id | coding/cli/rpc_mode_test.go:662, its want |
