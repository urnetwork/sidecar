# Local model gateway as a drop-in API for coding-agent harnesses (Codex, Claude Code, others): API surfaces, config, translation problems, existing gateways, local security

Research date: 2026-11-23. Each claim is dated: by its source's date, by a product version, or "retrieved 2026-11-23" for undated live docs. Codex source claims come from a shallow clone of `openai/codex` main at commit `5f645d73` (committed 2026-11-23). Behavior at that commit may not be in a tagged release yet. Items marked "possibly superseded" come from older or secondary sources.

## 1. OpenAI Responses API: objects, streaming events, tools, reasoning, state, and the subset Codex needs

### Takeaway
To serve Codex, a gateway needs one streaming `POST {base_url}/responses` endpoint. It must accept stateless, full-history requests: `store: false`, input items whose ids the gateway never issued, and `include: ["reasoning.encrypted_content"]`. It must also emit a well-formed SSE item lifecycle that ends in `response.completed` carrying an `id` and integer `usage`. Codex's custom-provider path does not use `previous_response_id`, `background`, `conversation`, GET/DELETE/cancel, or WebSockets (default off) (Codex main, 2026-11-23). The vendor-neutral "Open Responses" spec (launched 2026-01-15, revised 2026-04-24) is the clearest conformance target for a multi-backend implementation.

### Cited Findings
**Request surface (OpenAI, current as of 2026-11-23)**
- `POST /v1/responses` body parameters in the official Python SDK types: `access_programs, background, background_options, context_management, conversation, image, include, input, instructions, max_output_tokens, max_tool_calls, metadata, model, moderation, parallel_tool_calls, previous_response_id, prompt, prompt_cache_key, prompt_cache_options, prompt_cache_retention, reasoning, safety_identifier, service_tier, store, stream_options, temperature, text, tool_choice, tools, top_logprobs, top_p, truncation, user`, plus `stream` — [openai-python response_create_params.py (main)](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_create_params.py)
- `store` "Defaults to true when omitted", and stored responses are kept for at least 30 days — [openai-python response_create_params.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_create_params.py)
- Allowed `include` values: `file_search_call.results`, `web_search_call.results`, `web_search_call.action.sources`, `message.input_image.image_url`, `computer_call_output.output.image_url`, `code_interpreter_call.outputs`, `reasoning.encrypted_content`, `message.output_text.logprobs` — [OpenAI API ref: create response](https://developers.openai.com/api/reference/resources/responses/methods/create); [openai-python response_includable.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_includable.py)
- Other parameters (retrieved 2026-11-23):
  - `background` (default `false`).
  - `background_options.completion_window`: `soonest` (default), `2h`, or `8h`.
  - `context_management`: entries `[{type: "compaction", compact_threshold}]` for server-side compaction.
  - `conversation`: a conversation id whose items are prepended to `input`.
  — [OpenAI API ref: create response](https://developers.openai.com/api/reference/resources/responses/methods/create)
- Tool types in the current schema: `function`, `file_search`, `computer`, `computer_use_preview`, `web_search`, `web_search_preview`, `mcp`, `code_interpreter`, `image_generation`, `local_shell`, `shell`, `custom`, `tool_search`, `programmatic_tool_calling`, `apply_patch` — [OpenAI API ref: create response](https://developers.openai.com/api/reference/resources/responses/methods/create)
- Top-level fields of the Response object: `id, access_programs, created_at, error, incomplete_details, instructions, metadata, model, object, output, parallel_tool_calls, temperature, tool_choice, tools, top_p, background, completed_at, conversation, image, input_transformations, max_output_tokens, max_tool_calls, moderation, previous_response_id, prompt, prompt_cache_diagnostics, prompt_cache_key, prompt_cache_options, prompt_cache_retention, reasoning, safety_identifier, service_tier, status, text, tool_usage, top_logprobs, truncation, usage, user` — [openai-python response.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response.py)
- `usage` fields: `input_tokens`, `input_tokens_details{cached_tokens, cache_write_tokens, cache_write_tokens_details}`, `output_tokens`, `output_tokens_details{reasoning_tokens}`, `total_tokens` — [openai-python response_usage.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_usage.py)

**Streaming events (OpenAI)**
- The SDK's `ResponseStreamEvent` union contains these event classes:
  - Lifecycle: Created, InProgress, Queued, Completed, Failed, Incomplete, Error.
  - Items and content parts: OutputItemAdded/Done, ContentPartAdded/Done.
  - Text: TextDelta/Done (`response.output_text.*`), OutputTextAnnotationAdded, RefusalDelta/Done.
  - Tool calls: FunctionCallArgumentsDelta/Done, CustomToolCallInputDelta/Done.
  - Reasoning: ReasoningSummaryPartAdded/Done, ReasoningSummaryTextDelta/Done, ReasoningTextDelta/Done.
  - Compaction: CompactionCompacting.
  - Hosted tools: WebSearchCall{InProgress,Searching,Completed}, FileSearchCall{InProgress,Searching,Completed}, CodeInterpreterCall{InProgress,Interpreting,Completed,CodeDelta,CodeDone}, ImageGenCall{InProgress,Generating,PartialImage,Completed}, McpCall{InProgress,Completed,Failed,ArgumentsDelta,ArgumentsDone}, McpListTools{InProgress,Completed,Failed}, ShellCall{CommandAdded,CommandDelta,CommandDone,OutputContentDelta,OutputContentDone}.
  - Audio: AudioDelta/Done, AudioTranscriptDelta/Done.

  — [openai-python response_stream_event.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_stream_event.py)
- Wire `type` strings confirmed from SDK literals or from Codex's parser:
  - Lifecycle: `response.created`, `response.in_progress`, `response.completed`, `response.incomplete`, `response.failed`.
  - Items and parts: `response.output_item.added`, `response.output_item.done`, `response.content_part.added`, `response.content_part.done`.
  - Text: `response.output_text.delta`, `response.output_text.done`, `response.refusal.delta`.
  - Tool calls: `response.function_call_arguments.delta`, `response.function_call_arguments.done`, `response.custom_tool_call_input.delta`, `response.custom_tool_call_input.done`, `response.mcp_call_arguments.delta`.
  - Reasoning: `response.reasoning_summary_part.added`, `response.reasoning_summary_part.done`, `response.reasoning_summary_text.delta`, `response.reasoning_summary_text.done`, `response.reasoning_text.delta`.
  - Errors: `error`.

  — [openai-python response_text_delta_event.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_text_delta_event.py); [Codex sse/responses.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses.rs)
- `response.compaction.compacting` is a newer event, emitted while a `compaction_trigger` is processed and "at most once every 30 seconds". `response.output_item.done` carries the final encrypted content of compaction items — [OpenAI streaming-events reference](https://developers.openai.com/api/reference/resources/responses/streaming-events) (retrieved 2026-11-23)
- `response.output_text.delta` fields: `content_index, delta, item_id, logprobs, output_index, sequence_number, type`. `logprobs` is a non-optional list in the SDK model — [openai-python response_text_delta_event.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_text_delta_event.py)
- `error` event fields: `type: "error"`, `message`, `code` (optional), `param` (optional), `sequence_number` — [openai-python response_error_event.py](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_error_event.py)
- A community thread (possibly stale) reports that the streaming guide shows tool-specific events missing from the API reference, so the reference may be incomplete — [OpenAI community thread](https://community.openai.com/t/inconsistency-in-streaming-events-documentation-for-the-v1-responses-endpoint/1274977)

**WebSocket mode and compaction (OpenAI, retrieved 2026-11-23)**
- WebSocket mode keeps a "persistent connection to `/v1/responses`".
  - Each turn is a `response.create` client event that "mirrors the normal Responses create body"; `stream` and `background` are not used.
  - WebSocket-only fields are `stream_id` and `generate: false` (warmup).
  - Continuation sends `previous_response_id` plus only the new items.
  - With `store=false`, prior state lives in a "connection-local in-memory cache"; an uncached id returns `previous_response_not_found`.
  - A connection holds up to 16 in-flight responses across lanes and 32 named `stream_id`s, and lasts 60 minutes (then `websocket_connection_limit_reached`, HTTP 400).
  - OpenAI claims "up to roughly 40% faster" end-to-end for rollouts with 20+ tool calls.

  — [OpenAI WebSocket mode guide](https://developers.openai.com/api/docs/guides/websocket-mode)
- The standalone `/responses/compact` endpoint is stateless. It returns a compacted input window, not a response id, and the window includes an opaque encrypted `compaction` item. OpenAI says not to prune it — [OpenAI compaction guide](https://developers.openai.com/api/docs/guides/compaction)
- Vercel's gateway notes the compaction item is OpenAI server-side state that other providers can't read — [Vercel AI Gateway compaction docs](https://vercel.com/docs/ai-gateway/sdks-and-apis/responses/compaction)

**Open Responses (vendor-neutral spec)**
- Open Responses is an "open-source specification and ecosystem for multi-provider, interoperable LLM interfaces based on the OpenAI Responses API".
  - Current version is 2026-04-24, which added the WebSocket transport.
  - The first version is dated 2026-01-15.
  - A compliant implementation implements the spec directly or is a proper superset of it.

  — [openresponses.org/specification](https://www.openresponses.org/specification); [Open Responses changelog](https://www.openresponses.org/changelog)
- Required behavior:
  - JSON bodies, and SSE with `Content-Type: text/event-stream`.
  - The SSE `event` field must equal the body's `type`, and servers SHOULD NOT use `id`.
  - Every stream ends with a terminal `response.completed`, `response.failed`, or `response.incomplete`. `[DONE]` is optional, and clients must accept a stream without it.
  - Item lifecycle: `response.output_item.added` → `response.content_part.added` → deltas → `response.<type>.done` → `response.content_part.done` → `response.output_item.done`.
  - Items carry `id`, `type`, and `status`.
  - `allowed_tools` is a hard constraint.
  - Provider extensions use slug prefixes, e.g. `openai:web_search_call`.

  — [openresponses.org/specification](https://www.openresponses.org/specification)
- Reasoning items have three optional fields: `content` (raw trace), `summary` (`summary_text` parts), and `encrypted_content` ("opaque, provider-specific payload that allows round-tripping without exposure") — [openresponses.org/specification](https://www.openresponses.org/specification)
- Error types: `server_error` 500, `invalid_request` 400, `not_found` 404, `model_error` 500, `too_many_requests` 429. The error object carries `message`, `type`, `param`, and `code` — [openresponses.org/specification](https://www.openresponses.org/specification)
- The 2026-04-24 revision "made logprobs optional" — [Open Responses changelog](https://www.openresponses.org/changelog) (seen via search snippet)
- InfoQ (Feb 2026) reports early adoption by Hugging Face, OpenRouter, Vercel, Ollama, LM Studio, and vLLM — [InfoQ](https://www.infoq.com/news/2026/02/openai-open-responses)
- A third-party article says the project moved under the Linux Foundation's Agentic AI Foundation, but only secondary sources report this (unverified) — [dev.to](https://dev.to/hassann/what-is-open-responses-gjp)

**What Codex actually sends (Codex main @5f645d73, 2026-11-23)**
- `ResponsesApiRequest` fields: `model, stream, service_tier?, input, tools?, tool_choice, parallel_tool_calls, reasoning, store, stream_options?, include, prompt_cache_key?, prompt_cache_options?, text?, client_metadata?, access_programs?, request_country`.
  - The struct has no top-level `instructions` field.
  - A code comment says routing fields come first because "gateways may inspect request bodies incrementally before potentially multi-megabyte input".

  — [Codex common.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/common.rs)
- Values Codex sets in the request:
  - `store: false` and `tool_choice: "auto"`.
  - `reasoning: Some(...)` on every request.
  - `include` starts as `["reasoning.encrypted_content"]` and conditionally adds `"output.encrypted_content"`.
  - `prompt_cache_key` comes from the thread metadata.
  - `text` carries verbosity only when the model supports it; otherwise Codex logs "model_verbosity is set but ignored".

  — [Codex core/client.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/core/src/client.rs)
- Base instructions go in as the first `input` item, a message with a content-derived id (`msg_…`), not as `instructions`. For "responses lite" models, tools travel as an `additional_tools` developer item instead of the `tools` parameter — [Codex core/client.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/core/src/client.rs)
- Input item variants Codex can replay (serde `tag = "type"`, snake_case): `message`, `agent_message`, `reasoning`, `local_shell_call`, `function_call`, `function_call_output`, `custom_tool_call`, `custom_tool_call_output`, `tool_search_call`, `tool_search_output`, `web_search_call`, `image_generation_call`, `compaction`, `compaction_trigger`, `context_compaction`, `additional_tools`, `configuration_update` — [Codex protocol/models.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/protocol/src/models.rs)
- The `reasoning` item is `{id?, summary: [...], content?: [...], encrypted_content: Option<String>}` — [Codex protocol/models.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/protocol/src/models.rs)
- Freeform ("custom") tools serialize with `format: {type: "grammar", syntax: "lark", definition: …}` — [Codex core/client_tests.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/core/src/client_tests.rs)
- The `apply_patch` tool is registered only when model metadata sets `apply_patch_tool_type`, whose only variant is `Freeform`. Otherwise the model edits through shell tools — [Codex core/tools/spec_plan.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/core/src/tools/spec_plan.rs); [Codex protocol/openai_models.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/protocol/src/openai_models.rs)
- In DeepSeek tests through a Responses router (Aug 2026), the model wrote files through the shell rather than Codex's patch tool — [Opper Codex router guide](https://opper.ai/blog/codex-router)
- zstd request-body compression applies only to the built-in `openai` provider with ChatGPT (Codex-backend) auth. Custom providers receive uncompressed JSON — [Codex core/client.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/core/src/client.rs)
- Request headers Codex sets (OpenAI-oriented; a gateway can ignore them): `originator`, `x-client-request-id`, `OpenAI-Beta`, `x-codex-turn-metadata`, `x-codex-turn-state`, `x-codex-window-id`, `x-codex-installation-id`, `x-codex-parent-thread-id`, `x-codex-beta-features`, `x-openai-subagent` — [Codex core/client.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/core/src/client.rs); [Codex requests/headers.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/requests/headers.rs)

**What Codex consumes from the stream (Codex main @5f645d73)**
- Events Codex acts on:
  - `response.created`: reads `response.id`.
  - `response.output_item.added`.
  - `response.output_item.done`: Codex takes complete items, including function calls, from here.
  - `response.output_text.delta`: reads `delta`.
  - `response.custom_tool_call_input.delta`: needs `delta` plus `item_id` or `call_id`.
  - `response.reasoning_summary_part.added`: needs `summary_index`.
  - `response.reasoning_summary_text.delta` and `.done`.
  - `response.reasoning_text.delta`: needs `content_index`.
  - `response.completed`, `response.incomplete`, `response.failed`, and `error`.

  — [Codex sse/responses.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses.rs)
- Events Codex explicitly ignores (trace only): `response.function_call_arguments.delta/.done`, `response.content_part.added/.done`, `response.output_text.done`, `response.in_progress`, `response.reasoning_summary_part.done`, `response.custom_tool_call_input.done`, and any other `*.delta`. Tool-argument streaming is therefore not needed for correctness — [Codex sse/responses.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses.rs)
- How Codex parses `response.completed`:
  - It deserializes into `{id: String (required), usage?, usage_metadata?, end_turn?}`.
  - If `usage` is present, `input_tokens`, `output_tokens`, and `total_tokens` must be integers; the detail objects are optional.
  - A parse failure is a stream error: "failed to parse ResponseCompleted".

  — [Codex sse/responses.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses.rs)
- A `response.incomplete` whose `incomplete_details.reason` is anything other than `"interrupted"` becomes an error. `content_filter` maps to a ContentFilter error — [Codex sse/responses.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses.rs)
- A stream that ends before `response.completed` fails with "stream closed before response.completed". Silence beyond the idle timeout fails with "idle timeout waiting for SSE". Codex then retries up to `stream_max_retries` — [Codex sse/responses.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses.rs); [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- Error-code semantics:
  - Not retried: `insufficient_quota` and `credit_balance_exhausted` (QuotaExceeded), `usage_not_included`, `invalid_prompt`, and `context_length_exceeded` (ContextWindowExceeded).
  - Retried with retry-after parsing: `rate_limit_exceeded` and `slow_down` (RateLimitExceeded), `server_is_overloaded`, and `policy_capacity_unavailable`.
  - Any other `response.failed` code is treated as Retryable.

  — [Codex codex-api/error.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/error.rs); [Codex sse/responses_error.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/codex-api/src/sse/responses_error.rs)

**Statelessness pitfalls seen in the field**
- Replaying item ids with `store=false` against OpenAI can 404 with "Items are not persisted when `store` is set to false". A reasoning item sent without its following item fails with "Item rs_* of type reasoning was provided without its required following item". The usual workaround is `include: ['reasoning.encrypted_content']` plus replaying full items, or stripping ids the server can't resolve (community reports, 2025–2026) — [OpenAI community thread](https://community.openai.com/t/one-potential-cause-of-item-rs-xx-of-type-reasoning-was-provided-without-its-required-following-item-error-stateless-using-agents-sdk/1370540); [opencode-openai-codex-auth architecture notes](https://numman-ali.github.io/opencode-openai-codex-auth/development/ARCHITECTURE)
- The ChatGPT Codex backend rejects `store: true` with "Store must be false" — [OpenAI community thread](https://community.openai.com/t/store-true-doesnt-work-with-codex-it-return-400-bad-request-store-must-be-false/1382556)

### Inferences
- **Minimum endpoints for Codex.** `POST /v1/responses` with `stream: true` over SSE, and probably a non-streaming JSON variant for other clients. Codex does not exercise GET/DELETE `/v1/responses/{id}`, `previous_response_id`, `conversation`, `background`, `/responses/compact`, or WebSocket. OpenRouter and Ollama both ship stateless Responses implementations (Section 5), and Codex works against them.
- **Event sequence to emit.** Always emit `response.created` first and a terminal `response.completed`, `response.failed`, or `response.incomplete` last, with monotonically increasing `sequence_number`. Put fully formed items in `response.output_item.done`: `message` with `output_text` parts, `function_call` with `call_id`, `name`, and `arguments` as a JSON string, and `reasoning`. Include `"logprobs": []` on text deltas, because strict SDK clients model it as required. Never close the stream without a terminal event: Codex treats that as a disconnect and replays the whole turn, which double-bills unless the gateway deduplicates.
- **Reasoning round-trip.** `reasoning.encrypted_content` is the natural slot for gateway-owned opaque state. The gateway can carry backend-native reasoning state (Chat Completions `reasoning_content`, Anthropic `thinking` plus `signature`, or LiteRT-LM state) inside an authenticated-encrypted envelope bound to backend and model. If the turn is routed to a different backend, drop the envelope. LiteLLM documents this same trade-off as "encrypted reasoning without a peer" (Section 5).
- **Opaque item ids.** Treat every input item `id` (`msg_…`, `rs_…`, `fc_…`) as opaque and never resolve it as a reference. Codex now derives ids client-side from content.
- **Instructions in two places.** Accept a system or developer `message` as the first `input` item (current Codex) as well as top-level `instructions` (other clients and the spec).
- **Unknown fields and tools.** Accept and ignore unknown top-level fields such as `access_programs`, `request_country`, `client_metadata`, and `prompt_cache_options`. Map `custom` (freeform grammar) tools either to a single-string-argument function, wrapping and unwrapping `custom_tool_call` items, or keep them away by setting the model catalog's `apply_patch_tool_type` to null for non-OpenAI models.
- **Balance exhaustion.** When the prepaid balance runs out, emit `response.failed` with `error.code: "insufficient_quota"` (or return a 429 whose error type is `insufficient_quota`). Codex classifies that as a non-retryable QuotaExceeded instead of retrying. `rate_limit_exceeded` with a "try again in Ns" message should be reserved for transient throttling.
- **Affinity key.** `prompt_cache_key`, the thread id, is a good affinity key for keeping a conversation on one backend, so the backend's KV or prefix cache gets reused.

### Gaps
- I couldn't read the full OpenAI streaming-events reference: the page is 2.3 MB and was truncated at 100 k characters. Wire strings for hosted-tool events (web_search, file_search, code_interpreter, image_generation, mcp, shell) are inferred from SDK class names and not verified one by one.
- `output.encrypted_content` is in Codex's `include` but not in the SDK's public `ResponseIncludable` list. It looks Codex/OpenAI-internal, and its trigger condition wasn't traced.
- I didn't determine which tagged Codex release first moved base instructions into `input`, or which first omits `instructions`. Older releases may still send `instructions`.

## 2. OpenAI Codex CLI: custom-provider configuration, auth, Chat Completions status, known third-party issues

### Takeaway
Codex speaks only the Responses API. `wire_api = "chat"` was deprecated on 2025-12-09 and removed in early February 2026; it now fails at startup with a hard error. A gateway is configured through a `[model_providers.<id>]` table in `~/.codex/config.toml`. That table can also run a command that fetches a short-lived bearer token (`[model_providers.<id>.auth]`), which suits a local daemon that issues per-harness tokens. Non-OpenAI backends need metadata through `model_catalog_json`, and usually also `web_search = "disabled"` and the multi-agent tools turned off.

### Cited Findings
**Chat Completions removal**
- On 2025-12-09 maintainer etraut-openai announced that `chat/completions` "has increasingly hampered our ability to improve Codex" and that removal was "slated for early February 2026". On 2026-01-15 a maintainer said it "won't be removed until Feb 1". On 2026-02-05 a user reported it gone and linked PR #10157 — [openai/codex Discussion #7782](https://github.com/openai/codex/discussions/7782)
- Current error string: "`wire_api = \"chat\"` is no longer supported. How to fix: set `wire_api = \"responses\"` in your provider config." The `ollama-chat` provider is also removed ("replace `ollama-chat` with `ollama`") — [Codex model-provider-info/lib.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/model-provider-info/src/lib.rs)
- `wire_api` accepts only `responses`, which is also the default — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference) (retrieved 2026-11-23; `developers.openai.com/codex/*` now 308-redirects to `learn.chatgpt.com/docs/config-file/*`)

**`[model_providers.<id>]` keys** (config reference, retrieved 2026-11-23)
- Basic connection: `name`, `base_url`, `env_key`, `env_key_instructions`, `query_params` (map), `http_headers` (map), and `env_http_headers` (map of header → env var name). `experimental_bearer_token` exists but is discouraged.
- `wire_api`: `responses` only.
- Retries and timeouts: `request_max_retries` (default `4`), `stream_max_retries` (default `5`), `stream_idle_timeout_ms` (default `300000`).
- Capability flags: `requires_openai_auth` (default `false`), `supports_websockets` (boolean), `supports_standalone_web_search` (default `false`), `capabilities.remote_compaction` (`unsupported` → local compaction, or `v2` → compaction triggers sent through Responses), `capabilities.external_web_access`, and `model_catalog_url`.
- `auth` table: `auth.command`, `auth.args`, `auth.cwd`, `auth.timeout_ms` (default `5000`), `auth.refresh_interval_ms` (default `300000`; `0` means refresh only after an auth retry).

  — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- `supports_websockets` defaults to `false` for custom providers and is `true` for the built-in OpenAI provider. AWS-signed providers can't combine with it — [Codex model-provider-info/lib.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/model-provider-info/src/lib.rs)
- Command-backed auth: the command gets no stdin and prints the token to stdout. It must not be combined with `env_key`, `experimental_bearer_token`, or `requires_openai_auth`. There is also `[model_providers.<id>.gateway_oauth]`, which takes authorization and token URLs, a public client id, and an optional `device_authorization_url` — [Codex advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced)
- `env_key` is sent as a Bearer token — [Codex custom providers guide (Apr 2026)](https://codex.danielvaughan.com/2026/04/23/codex-cli-custom-model-providers-configuration-guide/)
- Reserved provider ids: `openai`, `ollama`, `lmstudio`, `amazon-bedrock`, `amazon-bedrock-runtime`, `gcp`. You can't override `[model_providers.openai]` — [Codex advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced)
- The config reference lists only `openai`, `ollama`, and `lmstudio` as reserved — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- `openai_base_url` changes the built-in `openai` provider's URL without defining a new provider. A project-level `.codex/config.toml` ignores `openai_base_url`, `model_provider`, `model_providers`, and `profile`/`profiles`, so these must live in `~/.codex/config.toml` — [Codex advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced)

**Model and reasoning keys** (retrieved 2026-11-23)
- `model_reasoning_effort` examples: `low`, `medium`, `high`, `xhigh`, `max`, `ultra` ("availability depends on model and client").
- `model_reasoning_summary`: `auto | concise | detailed | none`.
- `model_verbosity`: `low | medium | high`, Responses-only; per the advanced-config page, Chat Completions providers ignore it.
- `model_context_window`, `model_auto_compact_token_limit`, and `model_catalog_json` (path to a JSON model catalog loaded at startup).
- `show_raw_agent_reasoning` and `hide_agent_reasoning`.
- `oss_provider`: `lmstudio | ollama`, used with `--oss` / `--local-provider`.

  — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- Profiles changed in 0.134.0: `[profiles.<name>]` and `profile = "<name>"` "are no longer supported". `codex --profile <name>` now overlays `~/.codex/<name>.config.toml` onto `~/.codex/config.toml`. Tutorials that use `[profiles.x]` are superseded — [Codex advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced)
- Model-catalog metadata fields (the `ModelInfo` struct) include:
  - Identity: `slug`, `display_name`.
  - Reasoning: `default_reasoning_level`, `supported_reasoning_levels`, `supports_reasoning_summary_parameter`, `default_reasoning_summary`, `support_verbosity`.
  - Tools: `shell_type`, `apply_patch_tool_type`, `web_search_tool_type`, `supports_search_tool`, `experimental_supported_tools`.
  - Context: `context_window`, `max_context_window`, `auto_compact_token_limit`, `effective_context_window_percent`, `truncation_policy`.
  - Other: `input_modalities`, `use_responses_lite`, `multi_agent_version`.

  — [Codex protocol/openai_models.rs @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/protocol/src/openai_models.rs)
- Codex warns that it has no metadata for non-OpenAI model ids and falls back to defaults — [Opper Codex router guide (Aug–Sep 2026)](https://opper.ai/blog/codex-router)

**Example configs from the docs** (retrieved 2026-11-23)
- Proxy: `[model_providers.proxy] name = "OpenAI using LLM proxy"`, `base_url = "http://proxy.example.com"`, `env_key = "OPENAI_API_KEY"`.
- Ollama: `[model_providers.local_ollama] base_url = "http://localhost:11434/v1"`.
- Azure: `query_params = { api-version = "2025-04-01-preview" }`, `request_max_retries = 4`, `stream_max_retries = 10`, `stream_idle_timeout_ms = 300000`.

  — [Codex advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced)

**Known problems with third-party Responses backends**
- Built-in web search breaks non-OpenAI upstreams. DeepSeek returned "Extra inputs are not permitted" and Gemini returned a 502 naming the tool; the fix is `web_search = "disabled"`. Multi-agent tools, including `tool_search`, "can cause sessions to hang or drop" on third-party backends; `features.multi_agent = false` avoids this but loses sub-agents. OpenAI-specific tool payloads were rejected in tests on Codex 0.137.0 and 0.147.0 (Aug 2026). OpenRouter `codex exec` intermittent failures were closed as not planned. Feature flags "can change with any release" — [Opper Codex router guide](https://opper.ai/blog/codex-router)
- Field reports from Jan–Feb 2026 (possibly superseded):
  - LM Studio 0.3.39 with Codex 0.92.0 had streaming failures.
  - z.ai glm-4.7 failed with "Incorrect role information" after Codex 0.80.0.
  - LiteLLM's chat wire "never used tools", and its responses wire failed to connect.
  - vLLM 15.1 [sic] did not work with Responses.
  - llama.cpp "kind of works", because the server converts Responses to Chat Completions.
  - DeepSeek thinking mode requires replaying `reasoning_content`.

  — [openai/codex Discussion #7782](https://github.com/openai/codex/discussions/7782)
- Practical tips: some providers need a `/v1` suffix and others don't, and trailing slashes matter; streaming-only failures can be addressed with `stream_idle_timeout_ms` or retries; LiteLLM's `drop_params: true` filters OpenAI-only fields — [Codex custom providers guide (Apr 2026)](https://codex.danielvaughan.com/2026/04/23/codex-cli-custom-model-providers-configuration-guide/)
- "stream disconnected before completion" is a generic Codex error with many causes. A related "websocket closed by server before response.completed" message and a WebSocket→HTTPS fallback warning also appear in reports — [openai/codex #1581](https://github.com/openai/codex/issues/1581); [openai/codex #18960](https://github.com/openai/codex/issues/18960); [openai/codex #14877](https://github.com/openai/codex/issues/14877)

### Inferences
- A sidecar-managed Codex config might look like this:
  ```toml
  model_provider = "urnetwork"
  model = "<id>"
  web_search = "disabled"
  model_catalog_json = "~/.codex/urnetwork-models.json"

  [model_providers.urnetwork]
  name = "URnetwork sidecar"
  base_url = "http://127.0.0.1:<port>/v1"
  wire_api = "responses"
  supports_websockets = false
  capabilities.remote_compaction = "unsupported"

  [model_providers.urnetwork.auth]
  command = "urnetwork-sidecar"
  args = ["token", "--harness", "codex"]
  refresh_interval_ms = 300000
  ```
  The catalog declares `context_window`, `supported_reasoning_levels`, and `apply_patch_tool_type` per backend model. The `urnetwork-sidecar token` command is hypothetical.
- Because project-level config cannot set providers, the sidecar must write the user-level `~/.codex/config.toml`, or a `~/.codex/<profile>.config.toml` used with `codex --profile`. Keeping the sidecar in its own profile file avoids clobbering a user's OpenAI setup.
- `model_reasoning_effort` values reach the gateway as `reasoning.effort`. They must map onto each backend: Ollama's aliasing (`minimal→low`, `xhigh|ultra→max`, Section 5) is one precedent.

### Gaps
- The exact on-disk schema of `model_catalog_json` (the wrapper object around `ModelInfo` entries) isn't documented on the pages fetched. The field list comes from source.
- I didn't verify whether Codex calls `GET {base_url}/models` on custom providers (an endpoint module exists in `codex-api`), or what `model_catalog_url` expects.
- `gh search issues` returned nothing in this environment, so specific Codex issue numbers about third-party Responses providers (beyond those above) were not collected.

## 3. Claude Code: custom endpoint configuration and the Anthropic Messages features it needs

### Takeaway
Claude Code treats any `ANTHROPIC_BASE_URL` as the Claude API. It needs `POST /v1/messages` with streaming SSE through the final `message_delta` and `message_stop`. `/v1/messages/count_tokens` and `GET /v1/models` are optional. It forwards a growing set of `anthropic-beta` values and body fields. For unrecognized model ids it sends every current-Claude feature (adaptive thinking, effort, context management, mid-conversation `role: "system"` messages), then retries without a feature when an upstream 400 names it. Anthropic states it "doesn't support routing Claude Code to non-Claude models through any gateway" (docs retrieved 2026-11-23, Claude Code v2.1.3xx era). A non-Anthropic backend therefore works only on a best-effort basis. Done well, the gateway tolerates unknown fields, never buffers, emits `ping` events, keeps thinking signatures opaque, and declares the real context window through `CLAUDE_CODE_MAX_CONTEXT_TOKENS`.

### Cited Findings
**Endpoints and formats** (retrieved 2026-11-23)
- Anthropic Messages, selected by `ANTHROPIC_BASE_URL`, uses `/v1/messages` and `/v1/messages/count_tokens` (optional). The gateway must forward `anthropic-beta` and `anthropic-version` unchanged.
- Bedrock InvokeModel (`ANTHROPIC_BEDROCK_BASE_URL` + `CLAUDE_CODE_USE_BEDROCK=1`) uses `/model/{model}/invoke`, `/invoke-with-response-stream`, and `/count-tokens`.
- Vertex rawPredict (`ANTHROPIC_VERTEX_BASE_URL` + `CLAUDE_CODE_USE_VERTEX=1`) uses `:rawPredict`, `:streamRawPredict`, and `count-tokens:rawPredict`.

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Inference requests post to `/v1/messages?beta=true`, so match on the path. Startup sends a best-effort `HEAD /api/hello` connection-warming probe, which a gateway may reject. When count_tokens is absent, Claude Code falls back to a character-based estimate — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- "Anthropic doesn't endorse, maintain, or audit third-party gateway products, and doesn't support routing Claude Code to non-Claude models through any gateway" — [Claude Code: Other LLM gateways](https://code.claude.com/docs/en/llm-gateway)

**Streaming requirements**
- If the gateway buffers a response, Claude Code stalls. It expects the full event sequence "through the final `message_delta` and `message_stop`". A body that ends after a content block has started but before the final `message_delta` counts as a dropped connection.
- Claude Code aborts after a streaming idle timeout. During long thinking pauses, SSE `ping` events may be the only bytes on the stream, so a gateway that strips them, or translates from an upstream without pings, can trip the timeout.

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- `API_FORCE_IDLE_TIMEOUT` overrides the 5-minute body idle timeout; `0` disables it, for example for "a slow gateway or local model". `CLAUDE_BYTE_STREAM_IDLE_TIMEOUT_MS` is clamped to between 10 s and 30 min. `API_TIMEOUT_MS` (default 600000) bounds the wait for response headers. `CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK=1` stops the non-streaming retry that "can produce duplicate tool execution" behind proxies — [Claude Code env vars](https://code.claude.com/docs/en/env-vars)
- Messages SSE event order:
  - `message_start` (a Message with empty `content`).
  - Per block: `content_block_start` → `content_block_delta`* → `content_block_stop`.
  - One or more `message_delta` (usage is cumulative), then `message_stop`.
  - `ping` events can appear anywhere.
  - Errors arrive as `event: error` with `data: {"type":"error","error":{"type":"overloaded_error",…}}`.
  - "New event types may be added": clients must ignore unknown events.

  — [Anthropic streaming docs](https://platform.claude.com/docs/en/build-with-claude/streaming)
- Delta types:
  - `text_delta`.
  - `input_json_delta`: `partial_json` chunks, parsed at `content_block_stop`; tool_use blocks start with `input: {}`.
  - `thinking_delta`.
  - `signature_delta`: sent "just before the `content_block_stop`" of a thinking block.
  - `redacted_thinking` blocks and server-tool results arrive whole, with no deltas.
  - With `display: "omitted"`, a thinking block receives an empty `thinking_delta` and then one `signature_delta`.

  — [Anthropic streaming docs](https://platform.claude.com/docs/en/build-with-claude/streaming)

**Headers**
- Request headers:
  - `anthropic-version` (Claude Code sends `2023-06-01`).
  - `anthropic-beta`: forward verbatim; "don't allowlist individual values".
  - `Authorization` and/or `x-api-key`.
  - `x-claude-code-session-id`, `x-claude-code-agent-id`, `x-claude-code-parent-agent-id`.

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Optional hint headers, sent behind a custom base URL only when `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1` (v2.1.273+):
  - `x-claude-code-request-class`: `main | subagent | workflow | compaction | auxiliary`.
  - `x-claude-code-agent-type`.
  - `x-claude-code-compaction`: `auto | manual | reactive`.
  - `x-claude-code-context-compacted`.
  - `x-claude-code-prev-tool-durations`.
  - `x-claude-code-prompt-id` (v2.1.283+).

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Response headers Claude Code reads:
  - `content-type: text/event-stream`.
  - `retry-after`: integer seconds. Outside `CLAUDE_CODE_RETRY_WATCHDOG` sessions, a value above 60 stops retries and shows the error at once.
  - `x-should-retry`.
  - `anthropic-ratelimit-unified-*`.

  Error bodies should be forwarded unmodified, because the retry logic matches on error wording — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)

**Feature pass-through and what breaks** (retrieved 2026-11-23)
- Model ids Claude Code doesn't recognize, such as gateway aliases, are treated as current models. They receive `thinking: {"type": "adaptive"}`, effort (`output_config`), context management, and mid-conversation `role: "system"` entries in `messages`. A Bedrock- or Vertex-format connection instead sends fixed-budget thinking and no effort or context-management fields — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Automatic recovery on specific 400 errors:
  - When `thinking.type` is rejected, Claude Code switches between `enabled` and `adaptive`.
  - When an upstream rejects `role: "system"` inside messages, it retries once with that text moved into user messages.
  - When `cache_control` is rejected on a system message, it moves the marker.
  - On "bound to a different conversation" thinking-signature errors, it strips earlier thinking blocks.
  - When `output_config.effort`, `context_management` ("Extra inputs are not permitted"), the advisor tool (`Input tag 'advisor_20260301'`), or a named beta value (`Unexpected value(s)` or a `capability_rejected: beta_header:` token) is rejected, it retries without that part.
  - On `defer_loading` / `tool_reference` (tool search) errors, v2.1.305+ retries without them.

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Prompt caching has no beta pairing. `cache_control` markers go on `system` blocks and `messages` entries. If a gateway strips them or flattens block-form content to strings, there's no error, only uncached billing. Token counting is optional — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- System prompt attribution block: Claude Code prepends a block with its version and a conversation fingerprint, which `api.anthropic.com` strips by position. Since v2.1.181 the block is stable for a whole conversation behind a custom base URL. Before that it changed on every request, defeating prefix caches. `CLAUDE_CODE_ATTRIBUTION_HEADER=0` omits it — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- vLLM recommends `CLAUDE_CODE_ATTRIBUTION_HEADER=0` for vLLM ≤0.17.1 because "Claude Code can inject a per-request hash into the system prompt… which defeats prefix caching" — [vLLM Claude Code integration (v0.31.0 docs)](https://docs.vllm.ai/en/v0.31.0/serving/integrations/claude_code/)
- `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` stops sending `context_management`, beta tool fields (`strict`, `defer_loading`), `output_config.format`, `output_config.task_budget`, and MCP tool search. It leaves in place the adaptive `thinking` field, `output_config.effort`, mid-conversation system messages, and the beta values for extended context, interleaved thinking, and effort — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Fine-grained tool streaming is off by default behind a custom base URL. `CLAUDE_CODE_ENABLE_FINE_GRAINED_TOOL_STREAMING=1` forces it on. With it off, "a large tool input such as a long file write arrives only after Claude finishes generating it" — [Claude Code env vars](https://code.claude.com/docs/en/env-vars)
- Preserved thinking: "`thinking` or `redacted_thinking` blocks in the latest assistant message cannot be modified". A gateway that rewrites `system`, `tools`, or earlier `messages` can trigger "Invalid `signature` in `thinking` block. The block is bound to a different conversation." — [Claude API errors](https://platform.claude.com/docs/en/api/errors); [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Claude API error types:
  - 400 `invalid_request_error`, also returned on spend-limit exhaustion.
  - 401 `authentication_error`.
  - 402 `billing_error`.
  - 403 `permission_error`.
  - 404 `not_found_error`.
  - 409 `conflict_error`.
  - 413 `request_too_large`.
  - 429 `rate_limit_error`; a tier spend-cap 429 has no `retry-after`.
  - 500 `api_error`.
  - 504 `timeout_error`.
  - 529 `overloaded_error`.

  Errors have the shape `{"type":"error","error":{"type","message"},"request_id"}` — [Claude API errors](https://platform.claude.com/docs/en/api/errors)

**Configuration variables and settings** (retrieved 2026-11-23)
- Credentials:
  - `ANTHROPIC_BASE_URL` points Claude Code at the gateway.
  - `ANTHROPIC_AUTH_TOKEN` is sent as `Authorization: Bearer` and takes precedence immediately.
  - `ANTHROPIC_API_KEY` is sent as `x-api-key` and needs a one-time interactive approval.
  - `apiKeyHelper` (settings.json) runs a command whose stdout is "sent in both the `Authorization` and `x-api-key` headers". The output is cached 5 minutes by default (`CLAUDE_CODE_API_KEY_HELPER_TTL_MS`). Since v2.1.227, any extra output fails the helper.
  - Settings-file `env` blocks override shell exports.

  — [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect)
- A reachable base URL isn't a credential. Claude Code still shows the login screen unless `ANTHROPIC_AUTH_TOKEN` is set in the shell, in `~/.claude/settings.json`, or in managed settings. Project-level settings apply only after first-run and trust — [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect)
- vLLM's guide likewise says `ANTHROPIC_AUTH_TOKEN` "Is required. Can be any value." — [vLLM Claude Code integration](https://docs.vllm.ai/en/v0.31.0/serving/integrations/claude_code/)
- `ANTHROPIC_CUSTOM_HEADERS` takes newline-separated `Name: Value` pairs. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` stops version checks, telemetry, and auto-updates. The WebFetch domain safety check and the fast-mode check still call `api.anthropic.com` directly; `skipWebFetchPreflight: true` disables the former. Remote Control and voice dictation are unavailable while gateway credentials are active — [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect)
- Model selection:
  - `ANTHROPIC_MODEL`.
  - `ANTHROPIC_DEFAULT_MODEL` (v2.1.236+).
  - `ANTHROPIC_DEFAULT_OPUS_MODEL`, `ANTHROPIC_DEFAULT_SONNET_MODEL`, `ANTHROPIC_DEFAULT_HAIKU_MODEL`, `ANTHROPIC_DEFAULT_FABLE_MODEL`, with `_NAME` and `_DESCRIPTION` variants for picker display.
  - `CLAUDE_CODE_SUBAGENT_MODEL`.
  - `ANTHROPIC_SMALL_FAST_MODEL` is "[DEPRECATED]".

  — [Claude Code model config](https://code.claude.com/docs/en/model-config); [Claude Code env vars](https://code.claude.com/docs/en/env-vars)
- Behind `ANTHROPIC_BASE_URL`, background tasks use the main model unless `ANTHROPIC_DEFAULT_HAIKU_MODEL` pins another. The `ANTHROPIC_DEFAULT_*_MODEL_SUPPORTED_CAPABILITIES` variables "have no effect behind an `ANTHROPIC_BASE_URL` gateway"; capabilities are mapped through `modelOverrides` instead — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Limits for unrecognized model ids:
  - Since v2.1.323 Claude Code assumes a 1M-token context window.
  - `CLAUDE_CODE_MAX_CONTEXT_TOKENS` overrides the assumed window "when routing to a model through `ANTHROPIC_BASE_URL` whose context window does not match".
  - `CLAUDE_CODE_AUTO_COMPACT_WINDOW` must be ≥100000.
  - `CLAUDE_CODE_MAX_OUTPUT_TOKENS` defaults to 32000 with a cap of 128000.
  - A gateway that rewrites context-limit errors in its own words prevents automatic compaction.

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol); [Claude Code env vars](https://code.claude.com/docs/en/env-vars); [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect)
- Request-body passthrough knobs: `ANTHROPIC_BETAS` (extra beta values) and `CLAUDE_CODE_EXTRA_BODY` (a JSON object merged into request bodies) — [Claude Code env vars](https://code.claude.com/docs/en/env-vars)
- Model discovery (`CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1`):
  - Request: `GET /v1/models?limit=1000` with a 3 s timeout (`CLAUDE_CODE_GATEWAY_MODEL_DISCOVERY_TIMEOUT_MS`). Any redirect is treated as failure.
  - Response: Claude Code reads `data[].id`, `display_name`, and `description`.
  - Filter: an entry is kept only when its `id` contains `claude` or `anthropic`.
  - The result is cached in `~/.claude/cache/gateway-models.json`.

  — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Managed `allowedProviders: ["customEndpoint"]` (v2.1.285+) pins Claude Code to one `ANTHROPIC_BASE_URL` — [Claude Code: Other LLM gateways](https://code.claude.com/docs/en/llm-gateway)
- In the VS Code extension, variables are set through `claudeCode.environmentVariables`. Claude Desktop uses its own "Configure Third-Party Inference" setting, and its SSH sessions can't reach a gateway at the local machine's `localhost` — [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect)

**Non-Anthropic backends speaking Messages (evidence of what breaks)**
- Ollama `/v1/messages` supports:
  - streaming events `message_start` through `message_stop`, plus `ping` and `error`, with `text_delta`, `input_json_delta`, and `thinking_delta`;
  - `tool_use` and `tool_result` blocks, including `tool_reference`;
  - `defer_loading`, base64 images, and string or array `system`.

  It does not support `/v1/messages/count_tokens`, `tool_choice`, `metadata`, `cache_control`, batches, citations, PDF `document` blocks, mid-stream `error` events, or URL images. `budget_tokens` is accepted but not enforced. Token counts are approximate. Claude Code setup is `ANTHROPIC_AUTH_TOKEN=ollama` and `ANTHROPIC_BASE_URL=http://localhost:11434` (retrieved 2026-11-23) — [Ollama Anthropic compatibility](https://docs.ollama.com/api/anthropic-compatibility)
- vLLM:
  - Ids with `/` don't work in Claude Code, so use `--served-model-name`.
  - Serve with `--enable-auto-tool-choice` and a matching `--tool-call-parser`.
  - The model needs strong tool calling.

  The guide was written for vLLM v0.31.0 docs; `/v1/messages` arrived in PR #22627, merged 2025-10-22 — [vLLM Claude Code integration](https://docs.vllm.ai/en/v0.31.0/serving/integrations/claude_code/); [vLLM PR #22627](https://github.com/vllm-project/vllm/pull/22627)
- A third-party developer reports that some vLLM versions' Anthropic endpoint rejects Claude Code requests containing system or developer roles inside `messages`, and built a compatibility proxy for it. This came from a search summary; the original post was not pinned down. A related thread is linked — [NVIDIA forum thread (related, unverified match)](https://forums.developer.nvidia.com/t/claude-code-vllm-on-nvcr-io-nvidia-vllm/374787)
- Several vendors run hosted Anthropic-compatible endpoints for Claude Code: DeepSeek `https://api.deepseek.com/anthropic`, Moonshot `https://api.moonshot.ai/anthropic`, z.ai `https://api.z.ai/api/anthropic`, and MiniMax. URLs vary by source; this is a secondary source, Aug 2026 — [Atlas Cloud guide](https://www.atlascloud.ai/blog/guides/claude-code-third-party-api-setup)

### Inferences
- **Fields to accept.** Accept and ignore, rather than reject, the fields Claude Code sends for unknown ids: `thinking.type=adaptive`, `output_config`, `context_management`, `cache_control`, `defer_loading`, `strict`, `tool_reference`, and `role: "system"` inside `messages`. Rejecting forces a retry, so each first turn costs two requests, and some rejections persist for the session. Alternatively, the sidecar's generated settings can set `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1`.
- **Thinking blocks.** Emit thinking blocks only when the backend produces reasoning. Never open an empty one: LiteLLM bugs show Claude Code then rejects the stream (Section 5). Use the `signature` field as the gateway's own MAC'd envelope, since Claude Code returns thinking blocks verbatim, and the backend reasoning state can round-trip through it as with Responses `encrypted_content`.
- **Generated Claude Code settings.** The `env` block in `~/.claude/settings.json`, or a project `settings.local.json`, should set:
  - `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>` and a per-harness credential (a static `ANTHROPIC_AUTH_TOKEN`, or `apiKeyHelper` for rotation);
  - `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL`, with `ANTHROPIC_DEFAULT_HAIKU_MODEL` pointing at the local LiteRT-LM model so cheap background calls stay on-device;
  - `CLAUDE_CODE_MAX_CONTEXT_TOKENS` set to the real window, which avoids the 1M default;
  - `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.
- **Model names in the picker.** Discovery only lists model ids containing "claude" or "anthropic", so non-Claude models served under their own names won't appear. Pinning through `ANTHROPIC_DEFAULT_*_MODEL` is more honest than renaming models to include "claude".
- **Pings and timeouts.** Emit an SSE `ping` every ~10–15 s while a local model is prefilling, or while a remote TEE backend is queued. Remote TEE latency could otherwise exceed the 5-minute body idle timeout or the stream watchdogs.
- **Token counting.** Implementing `/v1/messages/count_tokens` with the backend's tokenizer improves `/context` accuracy and compaction timing. Without it, Claude Code falls back to estimates.
- **Balance exhaustion.** 402 `billing_error` is the semantically correct status for an empty prepaid balance, but I found no documentation of how Claude Code presents it (see Gaps). A 429 with `retry-after` above 60 stops retries immediately per the docs.

### Gaps
- I couldn't confirm how Claude Code handles 402 `billing_error` (retry or not, and the message shown).
- I didn't fetch the current `anthropic-beta` value list ([beta headers reference](https://platform.claude.com/docs/en/api/beta-headers)).
- The env-var page was read only to 100 k of 194 k characters. No Unix-socket variable appeared in that portion, but the rest of the page was not checked.
- `/v1/messages/count_tokens` request and response shape wasn't fetched; it is assumed to match the Messages request body and return `{input_tokens}`.

## 4. Other harnesses: which wire API each speaks and how to point it at a custom endpoint

### Takeaway
Chat Completions is still the lowest common denominator: it is the default for OpenCode custom providers, Goose, Aider, Cline/Roo, Continue, Copilot CLI BYOK, Zed custom providers, and pi. Responses is mandatory only for Codex. It is optional in Copilot CLI (`wireApi: "responses"`), Zed (`chat_completions: false`), pi (`openai-responses`), and OpenCode (`/responses` package), and Cursor's agent mode sends Responses-format requests. Anthropic Messages is mandatory for Claude Code and optional in Zed, Copilot CLI, pi, OpenCode, and Goose. The Gemini API is needed only for Gemini CLI. Cursor can't reach a loopback gateway, and Amp has no BYOK.

### Cited Findings
**OpenCode** (docs retrieved 2026-11-23)
- Custom providers sit under `providers.<id>` with `name`, `env` (list of key variable names), `package` (`@opencode/ai/providers/openai-compatible` or `@opencode/ai/providers/openai-compatible/responses`; also `openai/chat` and `openai/responses`), `settings.baseURL`, `headers`, `body`, and `models.<id>` (`modelID`, `limit`).
- Built-in providers (`anthropic`, `openai`) can be routed through a proxy by overriding `settings.baseURL`.
- Ollama, LM Studio, and vLLM are discovered automatically; vLLM-discovered models start with tools disabled.
- This schema differs from the 2025-era `provider` / `npm: "@ai-sdk/openai-compatible"` / `options.baseURL` form, which is possibly superseded.

  — [OpenCode providers docs](https://opencode.ai/docs/providers/)

**Goose** (repo now `aaif-goose/goose`; docs on main, retrieved 2026-11-23)
- OpenAI provider variables: `OPENAI_API_KEY`, `OPENAI_HOST`, `OPENAI_BASE_PATH` (default `v1/chat/completions`), `OPENAI_ORGANIZATION`, `OPENAI_PROJECT`, `OPENAI_CUSTOM_HEADERS` (`HEADER_A=VALUE_A,…`), and `OPENAI_STORE` ("persist the generated Responses API response…", default `false`). The last implies some models go over Responses.
- Anthropic uses `ANTHROPIC_HOST`; Ollama uses `OLLAMA_HOST`.
- Declarative custom providers are JSON files in `~/.config/goose/custom_providers/` with `"engine": "openai"`, `api_key_env`, a `base_url` that is the full request URL including `/v1/chat/completions`, `headers`, `supports_streaming`, `requires_auth`, and `models[{name, context_limit}]`.
- `GOOSE_PROVIDER` and `GOOSE_MODEL` select the active provider and model.

  — [Goose providers doc (main)](https://github.com/aaif-goose/goose/blob/main/documentation/docs/getting-started/providers.md)

**Aider**
- Chat Completions over any OpenAI-compatible endpoint, configured with `OPENAI_API_BASE` and `OPENAI_API_KEY` and a model prefixed `openai/<name>` — [Aider OpenAI-compatible docs](https://aider.chat/docs/llms/openai-compat.html)
- Some guides use `openai-api-base` in `~/.aider.conf.yml` instead — [Vercel Aider guide](https://vercel.com/docs/ai-gateway/coding-agents/aider)

**Cline / Roo Code / Continue**
- Cline and Roo have an "OpenAI Compatible" provider configured with base URL (usually ending `/v1`), API key, and model id — [Cline OpenAI-compatible docs](https://docs.cline.bot/provider-config/openai-compatible); [Roo Code OpenAI-compatible docs](https://docs.roocode.com/providers/openai-compatible)
- Continue uses `provider: openai` with `apiBase`. `capabilities: [tool_use]` forces native tools, and some proxies don't pass tool calling through — [Continue reference](https://docs.continue.dev/reference); [Continue FAQ](https://docs.continue.dev/faqs)

**Cursor** (forum and third-party, 2026)
- "Override OpenAI Base URL" applies to non-Claude, non-Gemini models.
- Requests go through Cursor's cloud backend, so `http://localhost` is never reached and a public tunnel is required.
- With a custom base URL, Agent mode sends Responses-format requests. A bug report's forum slug reads "agent chat fails with missing required parameter tools 6 custom when using custom openai api key and base url override", which suggests Cursor sends `custom` (freeform) tools.
- Tab completion always uses Cursor's own models.

  — [Cursor forum: custom OpenAI-compatible API](https://forum.cursor.com/t/how-to-use-a-custom-openai-compatible-api-in-cursor-setup-limits-and-tips/171497); [dev.to: why localhost doesn't work](https://dev.to/orchidfiles/why-localhost-doesnt-work-as-openai-base-url-in-cursor-and-how-to-fix-it-589e); [Cursor forum bug](https://forum.cursor.com/t/bug-agent-chat-fails-with-missing-required-parameter-tools-6-custom-when-using-custom-openai-api-key-and-base-url-override/167894); [LiteLLM Cursor tutorial](https://docs.litellm.ai/docs/tutorials/cursor_integration)

**Zed** (retrieved 2026-11-23)
- OpenAI-compatible providers live under `language_models.openai_compatible.<name>`: `api_url` and `available_models[{name, display_name, max_tokens, max_output_tokens, reasoning_effort, capabilities{tools, images, parallel_tool_calls, prompt_cache_key, chat_completions, interleaved_reasoning, max_tokens_parameter}}]`.
  - `chat_completions` defaults to `true`; setting it to `false` makes Zed use "the Responses endpoint".
- Anthropic-compatible providers live under `language_models.anthropic_compatible.<name>` with `api_url`, `custom_headers`, and `available_models` (with `capabilities{tools, images, prompt_caching}` and `extra_beta_headers`).
- Keys come from `<PROVIDER_ID>_API_KEY` env vars (upper snake case).
- External ACP agents configure their own model access.

  — [Zed: Use API access](https://zed.dev/docs/ai/use-api-access)
- The Anthropic-compatible provider support was merged in June 2026 — [Zed PR #50381](https://github.com/zed-industries/zed/pull/50381)

**Gemini CLI** (main, retrieved 2026-11-23)
- `GOOGLE_GEMINI_BASE_URL` "Overrides the default base URL for Gemini API requests (when using `gemini-api-key` authentication)". It must use HTTPS "unless pointing to `localhost` (or `127.0.0.1` / `[::1]`)". `GOOGLE_VERTEX_BASE_URL` is the Vertex equivalent. The sandbox copies both variables. A unit test is named "should detect GATEWAY when GOOGLE_GEMINI_BASE_URL is present" — [gemini-cli configuration.md](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md); [gemini-cli sandbox.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/cli/src/utils/sandbox.ts); [gemini-cli contentGenerator.test.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/core/contentGenerator.test.ts)
- Google OAuth login bypasses the custom base URL, so an API key is needed — [dev.to LiteLLM + Gemini CLI](https://dev.to/polar3130/using-gemini-cli-through-litellm-proxy-1627)
- `GEMINI_CLI_CUSTOM_HEADERS` is used by some gateways (third-party) — [Cequence docs](https://docs.aigateway.cequence.ai/docs/llm-registry/gemini-cli)

**GitHub Copilot CLI**
- BYOK and local models were announced in a changelog dated April 7, 2026 on the page (its URL path says 2026-04-10). It requires tool calling and streaming, recommends a context window of at least 128k, supports Azure OpenAI, Anthropic, and any OpenAI-compatible endpoint, and adds `COPILOT_OFFLINE=true` — [GitHub changelog](https://github.blog/changelog/2026-04-10-copilot-cli-now-supports-byok-and-local-models/)
- Current docs (retrieved 2026-11-23) configure BYOK through `providers.json`, with `COPILOT_PROVIDERS_CONFIG` pointing to an alternate file.
  - Provider entries: `name`, `type` (`openai` default, `azure`, `anthropic`), `baseUrl`, `apiKey`, `bearerToken`, `wireApi` (`completions` default or `responses`), and `azure.apiVersion`.
  - Model entries: `id`, `provider`, `wireModel`, `modelId`, `maxPromptTokens`, `maxOutputTokens`.
  - Models are selected with `copilot --model PROVIDER-NAME/MODEL-NAME`.
  - `$VARS` in the file are not expanded, and credentials are stored in plaintext.

  — [GitHub Docs: BYOK models in Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models)
- Older env-var setup (`COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_TYPE`, `COPILOT_PROVIDER_API_KEY`, `COPILOT_MODEL`): the CLI "appends /chat/completions" and "cannot send custom request headers". This is possibly superseded by `providers.json` — [Cloudflare AI Gateway: Copilot CLI](https://developers.cloudflare.com/ai-gateway/integrations/coding-agents/github-copilot-cli/)

**Amp**
- Amp removed "Isolated Mode", which allowed your own API keys, because "it's not possible for it to meet our quality bar" — [Amp: No More BYOK](https://ampcode.com/news/no-more-byok)
- The only first-party route is Model Routing through Vercel AI Gateway, in early access and requiring a Megawatt or Gigawatt membership. Third-party proxies (CLIProxyAPI, byokey) emulate Amp's `/api/provider/*` routes — [Vercel: Amp](https://vercel.com/docs/ai-gateway/coding-agents/amp); [CLIProxyAPI Amp](https://mintlify.com/router-for-me/CLIProxyAPI/integrations/amp-cli)

**pi (badlogic, now `@earendil-works/pi-coding-agent`, 0.83.0)**
- Configuration lives in `~/.pi/agent/models.json`.
- `api` values: `openai-completions` ("most compatible"), `openai-responses`, `anthropic-messages`, `google-generative-ai`.
- Provider fields: `baseUrl`, `api`, `apiKey`, `oauth`, `headers`, `authHeader`, `models`, `modelOverrides`.
- Model fields: `id`, `name`, `reasoning`, `input`, `contextWindow` (default 128000), `maxTokens` (default 16384), `cost`, `compat`.
- OpenAI `compat` flags: `supportsDeveloperRole`, `supportsReasoningEffort`, `supportsStore`, `maxTokensField`, and `thinkingFormat` (`reasoning_effort|openrouter|deepseek|together|zai|qwen|chat-template|qwen-chat-template`).
- Anthropic `compat` flags: `supportsEagerToolInputStreaming`, `forceAdaptiveThinking`, `allowEmptySignature`, `supportsStrictTools`.

  — [pi models.md (0.83.0)](https://unpkg.com/@earendil-works/pi-coding-agent@0.83.0/docs/models.md)

### Inferences
- **Three wire APIs cover nearly everything.** A gateway exposing `/v1/chat/completions`, `/v1/responses`, and `/v1/messages` on one loopback port covers every harness listed except Gemini CLI, Cursor (cloud-side requests), and Amp (closed). Adding `/v1beta/models/{model}:generateContent` and `:streamGenerateContent?alt=sse` would cover Gemini CLI. These paths are from general knowledge and were not verified this session.
- **"One config file" means fan-out.** Each harness reads its own file: `~/.codex/config.toml` or a profile file, `~/.claude/settings.json` `env`, `opencode.json`, Copilot's `providers.json`, `~/.pi/agent/models.json`, Goose `custom_providers/*.json`, Zed `settings.json`, and env vars for Gemini CLI and Aider. The sidecar's single config therefore has to be rendered into per-harness files, ideally each with its own token.
- **Reasoning dialects.** pi's `thinkingFormat` list shows how many incompatible reasoning dialects exist on Chat Completions backends. The gateway must normalize them per backend, for example DeepSeek-style `reasoning_content` versus `reasoning_effort` versus Qwen chat-template flags.

### Gaps
- Not determined: whether Cline, Roo, or Continue can use Responses; which Goose `engine` selects Responses; whether Goose's OpenAI provider auto-switches to Responses for certain models.
- Cursor's official docs on custom keys weren't fetched; the Cursor findings come from the forum and third parties.
- Other harnesses (Factory Droid, Qwen Code, Kimi CLI, Crush, Mistral Vibe, Warp) weren't researched.

## 5. Existing gateways that translate between APIs: what they map, what they lose, common bugs

### Takeaway
Every mature gateway converges on the same three-API surface, and most now claim Open Responses compliance. They lose fidelity at the same seams:
- reasoning state across backends (encrypted or signed reasoning can't move between providers);
- prompt-caching markers;
- `count_tokens`;
- hosted or server tools (web search, compaction, shell);
- freeform/custom tools;
- stateful features (`previous_response_id`, often unsupported or DB-backed);
- streaming edge cases (empty thinking blocks, wrong `stop_reason` after tool calls, mid-stream errors).

### Cited Findings
**LiteLLM proxy** (docs retrieved 2026-11-23)
- Bridging:
  - Providers without native Responses config (`custom_openai/`, `baseten/`, `openai_like/`, most OpenAI-compatible providers) bridge `/v1/responses` through `/v1/chat/completions`.
  - `supported_endpoints: ["/v1/responses"]` forwards untranslated.
  - `use_chat_completions_api: true` or the `openai/chat_completions/<model>` prefix forces the bridge.
  - Native Responses: `openai`, `azure`, `azure_ai`.
  - WebSocket: native only for OpenAI and Azure; other providers get "HTTP streaming over WebSocket".
- State: `previous_response_id` relies on stored sessions (`store_prompts_in_spend_logs`, `cold_storage_custom_logger: s3_v2`). Response ids are encrypted per user (`disable_responses_id_security`, `allow_unmanaged_response_ids`). Affinity headers are `x-litellm-session-id` and `x-litellm-trace-id`.
- Stated limitations:
  - "Encrypted reasoning without a peer: the turn is served without the encrypted payload. Summaries are kept, and Anthropic thinking blocks are dropped whole".
  - Server-side compaction and the shell tool work only for `openai` and `azure`.

  — [LiteLLM Responses API docs](https://docs.litellm.ai/docs/response_api)
- Claude Code × LiteLLM compatibility matrix (generated 2026-10-21; LiteLLM v1.106.1, Claude Code 2.1.302):
  - Anthropic, Bedrock (Invoke and Converse), Vertex, and Azure Foundry pass messaging, streaming, tool use, caching, vision, thinking, PDFs, web search, and structured outputs.
  - The `openai` backend column is untested (—).
  - `azure_openai`, i.e. GPT behind `/v1/messages`, passes only basic messaging, streaming, and tool use.
  - count_tokens is untested for Vertex, and "Long context (1M)" is untested everywhere.

  — [LiteLLM Claude Code compatibility matrix](https://docs.litellm.ai/docs/claude_code_compatibility)
- Bug reports (titles and summaries via search; status not verified):
  - "Multiple bugs in Anthropic /v1/messages experimental pass-through to OpenAI", including unsupported `input_text` content types from Claude Code — [LiteLLM #23841](https://github.com/BerriAI/litellm/issues/23841)
  - An empty thinking block makes Claude Code reject the stream ("Content block is not a thinking block") and retry non-streaming, which doubles calls; the fix is to open a thinking block only when reasoning text exists. The PR number was not verified: search returned both of these — [BerriAI/litellm PR #17106](https://github.com/BerriAI/litellm/pull/17106); [digitalocean/litellm PR #33](https://github.com/digitalocean/litellm/pull/33)
  - Anthropic thinking converted to Chat Completions lands in a custom `thinking_blocks` field instead of `reasoning_content`, so a DeepSeek reasoning endpoint fails on the second turn. This was reported in a LiteLLM GitHub issue surfaced by search; the exact issue number was not verified — [LiteLLM issue search](https://github.com/BerriAI/litellm/issues?q=thinking_blocks+reasoning_content)
  - LiteLLM strips the `safeguards` field before translating `/v1/messages` for non-Anthropic models, avoiding 400s — [LiteLLM anthropic_unified docs](https://docs.litellm.ai/docs/anthropic_unified/)
- With Codex (Jan 2026, possibly superseded): the "chat wire connected but never used tools; Responses wire failed to connect" — [openai/codex Discussion #7782](https://github.com/openai/codex/discussions/7782)

**OpenRouter**
- `https://openrouter.ai/api/v1/responses` is "stateless". `store: true` or a non-null `previous_response_id` is rejected with 400, and clients send full history. It offers reasoning with "encrypted reasoning chains", parallel function calling, and web search — [OpenRouter Responses overview](https://openrouter.ai/docs/api/reference/responses/overview) (retrieved 2026-11-23)
- Claude Code setup:
  - `ANTHROPIC_BASE_URL=https://openrouter.ai/api`, with the key in `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY=""` set explicitly empty.
  - It is "only guaranteed to work with the Anthropic first-party provider".
  - Non-Anthropic models aren't supported through the native endpoint.

  — [OpenRouter Claude Code integration](https://openrouter.ai/docs/guides/coding-agents/claude-code-integration)
- Codex works over Responses — [OpenRouter Codex blog](https://openrouter.ai/blog/tutorials/codex-cli-openrouter/)
- There are reports of intermittent Responses failures with `codex exec` — [Opper Codex router guide](https://opper.ai/blog/codex-router)

**Portkey**
- `/v1/responses` "works with every provider and model in Portkey's catalog", and Portkey claims to be "fully Open Responses compliant". `/v1/messages` (Anthropic format) routes to 3,000+ models. Claude Code connects through `ANTHROPIC_BASE_URL`, without Bedrock or Vertex flags. The January 2026 changelog lists "Claude Code with any provider". Some docs paths are rebranded as "Prisma AIRS AI Gateway" (`/docs/aigw/…`) — [Portkey Responses API](https://portkey.ai/docs/product/ai-gateway/responses-api); [Portkey Messages API](https://portkey.ai/docs/product/ai-gateway/messages-api); [Portkey Claude Code compatibility](https://portkey.ai/docs/integrations/libraries/claude-code-gateway-compatibility); [Portkey Jan 2026 changelog](https://portkey.ai/docs/changelog/2026/january)

**Bifrost (Maxim)**
- `npx -y @maximhq/bifrost-cli` configures and launches Claude Code, Codex CLI, Gemini CLI, and OpenCode against a gateway (default `http://localhost:8080`), and auto-registers Bifrost's MCP server for Claude Code. The documented endpoints are `ANTHROPIC_BASE_URL` for Claude Code and `…/openai/v1` for Codex. This comes from vendor marketing, and sources disagree on the variable names — [Bifrost CLI agents](https://www.getmaxim.ai/bifrost/resources/cli-agents); [Maxim: Codex with Bifrost](https://getmaxim.ai/articles/using-openai-codex-cli-with-multiple-model-providers-using-bifrost/)
- Bug: "Anthropic streaming translation emits end_turn after mixed text + tool-call streams from vLLM". A wrong `stop_reason` makes the client end the turn instead of running the tool — [Bifrost #3638](https://github.com/maximhq/bifrost/issues/3638)

**claude-code-router (musistudio)**
- v3.1.6 is a "local model gateway and control plane for coding agents".
  - The gateway listens on `http://127.0.0.1:3456` by default, with a UI on 3458.
  - Supported formats: OpenAI Chat and Responses, Anthropic Messages, Gemini Generate Content and Interactions.
  - It offers per-client keys with expiry, plus local request, token, and image limits.
  - Routing rules can match headers and bodies, and support fallbacks.
  - Release notes mention a "Codex balance display".

  — [claude-code-router README](https://github.com/musistudio/claude-code-router)
- Router keys include `default`, `background`, `think`, `longContext` (+ `longContextThreshold`), `webSearch`, and `image`. Custom transformers are JS files listed in `transformers`. CCR 3.x moved configuration from `config.json` into SQLite plus a UI — [CCR config API](https://musistudio.github.io/claude-code-router/docs/server/api/config-api); [Morph CCR guide (2026)](https://www.morphllm.com/claude-code-router)

**Local inference servers**
- Ollama (retrieved 2026-11-23):
  - `/v1/responses` was added in v0.13.3. "Only the non-stateful flavor is supported (i.e., there is no `previous_response_id` or `conversation` support)".
  - Supported fields: `model, input, instructions, tools, stream, temperature, top_p, max_output_tokens, reasoning.effort`, plus `think`.
  - Reasoning summaries are supported for thinking models.
  - The cloud API lacks "custom/freeform tool-call replay".
  - Effort aliasing: `minimal`→`low`, `xhigh`/`ultra`→`max`.
  - Anthropic `/v1/messages` support is as listed in Section 3.

  — [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility); [Ollama Anthropic compatibility](https://docs.ollama.com/api/anthropic-compatibility)
- LM Studio added an Anthropic-compatible `/v1/messages` in 0.4.1 (2026-01-30) for Claude Code, and 0.4.1 also fixed Codex errors "when unsupported tools were passed". Later bug reports against 0.4.19 and 0.4.20 involve Claude Code tool use with Qwen custom templates and gpt-oss — [LM Studio Claude Code blog](https://lmstudio.ai/blog/claudecode); [LM Studio 0.4.1 changelog](https://lmstudio.ai/changelog/lmstudio-v0.4.1); [LM Studio Anthropic compat docs](https://lmstudio.ai/docs/developer/anthropic-compat)
- The Codex team said LM Studio supports Responses (Dec 2025) — [openai/codex Discussion #7782](https://github.com/openai/codex/discussions/7782)
- llama.cpp `llama-server` added `/v1/messages` in January 2026 and "converts Anthropic-format requests into OpenAI format internally". Its README lists a responses route — [HF blog: Anthropic Messages API in llama.cpp](https://huggingface.co/blog/ggml-org/anthropic-messages-api-in-llamacpp); [llama.cpp PR #17570](https://github.com/ggml-org/llama.cpp/pull/17570)
- vLLM's Responses API serves function tools through per-model tool parsers (Hermes, Llama, Mistral), streams `response.function_call_arguments.delta/.done`, and supports MCP tools server-side (GPT-OSS examples). This is from a March 2026 blog seen only on mirror domains, so it's unverified — [vLLM Responses API blog (mirror)](https://vllm-project-github-ju3u7rcr9-simon-mos-projects.vercel.app/2026/03/11/responses-api.html)

### Inferences
- **Recurring failures.** The same bugs recur across gateways:
  1. Wrong `stop_reason` or `finish_reason` mapping after interleaved text and tool calls (`end_turn` vs `tool_use`).
  2. Empty or misordered thinking blocks.
  3. Reasoning fields with no standard home in Chat Completions (`reasoning_content` vs `reasoning` vs `thinking_blocks`).
  4. Strict validators upstream rejecting new fields.
  5. Stateless-only Responses implementations that clients assume are stateful.

  The sidecar's translation layer should have golden-stream tests for each of these against Codex's and Claude Code's real request shapes.
- **Internal representation.** A canonical item model close to Open Responses works well internally: items with ids and status, reasoning with an opaque encrypted payload, and function or custom calls. Both Chat Completions and Anthropic Messages map into it with fewer losses than going directly Messages↔Chat. Portkey and claude-code-router appear to take the multi-format approach as well.
- **Backend choice.** Pushing Responses and Messages to backends that implement them natively (Ollama, vLLM, LM Studio, llama.cpp) avoids double translation. But their implementations are themselves partial, often converting to chat internally, and regress between releases. A gateway that terminates both APIs itself and talks Chat Completions (or native LiteRT-LM) to backends gives more control.

### Gaps
- SGLang's Responses API status, and official Bifrost docs (`docs.getbifrost.ai`), weren't researched.
- Whether the LiteLLM issues listed are fixed in current releases wasn't checked.
- claude-code-router's built-in transformer list for 3.x wasn't found; the official docs site was only partly accessible.

## 6. Local security: loopback vs Unix socket, per-harness tokens, browser and DNS-rebinding defenses

### Takeaway
Bind only to loopback (127.0.0.1 / ::1). Validate the `Host` header against loopback names to defeat DNS rebinding, refuse or 403 any request carrying a browser `Origin`, send no CORS headers, and require a per-harness bearer token. Unix domain sockets aren't a practical transport for these harnesses: none of the base-URL mechanisms found accepts one. Tokens are most useful when short-lived and fetched by command (Codex `auth.command`, Claude Code `apiKeyHelper`). They attribute usage and stop browsers and other users, but not malware running as the same user.

### Cited Findings
- The MCP spec's security warning (2025-11-25) for local HTTP servers:
  - "Servers MUST validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks". An invalid `Origin` gets HTTP 403.
  - "When running locally, servers SHOULD bind only to localhost (127.0.0.1) rather than all network interfaces (0.0.0.0)".
  - "Servers SHOULD implement proper authentication for all connections".
  - "Without these protections, attackers could use DNS rebinding to interact with local MCP servers from remote websites."

  — [MCP spec 2025-11-25: Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- Ollama before 0.1.29 (CVE-2024-28224) had a DNS-rebinding flaw: a malicious site could drive the victim's browser to the local API to chat with, delete, or exhaust models, and even exfiltrate files. It was fixed in v0.1.29 on 2024-03-14. NCC Group recommends server-side `Host` validation: "For services listening on the loopback interface, this set of whitelisted host values should only contain localhost" — [NCC Group advisory](https://www.nccgroup.com/research/technical-advisory-ollama-dns-rebinding-attack-cve-2024-28224/); [NVD CVE-2024-28224](https://nvd.nist.gov/vuln/detail/CVE-2024-28224)
- In August 2026 a regression pattern appeared: NVIDIA NemoClaw started Ollama with `OLLAMA_HOST=0.0.0.0:11434`. When Ollama is bound to a non-loopback address, its Host-header validation is skipped, enabling DNS-rebinding model poisoning (CVE-2026-65105, CVSS 8.1, per secondary reports) — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nvidia-nemoclaw-model-poisoning-20260827-c/); [The Hacker News](https://thehackernews.com/2026/08/a-malicious-webpage-could-poison-your.html)
- Chrome Local Network Access, shipping from Chrome 142 (blog published 2025-06-09, updated Sep 2025):
  - Websites need user permission before sending requests to local-network or loopback servers; the separate `loopback-network` permission covers public→loopback.
  - It applies to fetch, subresources, subframes, WebSocket, and WebTransport.
  - The old Private Network Access preflight headers "should no longer be relied on".

  — [Chrome: Local Network Access](https://developer.chrome.com/blog/local-network-access)
- The Claude API returns 401 "CORS requests are not allowed for this Organization" when a request has an `Origin` header, which "browsers add". This shows a real provider distinguishing browser traffic by `Origin` — [Claude API errors](https://platform.claude.com/docs/en/api/errors)
- Harness-side protections and credential mechanisms:
  - Gemini CLI refuses non-HTTPS base URLs except `localhost`, `127.0.0.1`, and `[::1]` — [gemini-cli configuration.md](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md)
  - Claude Code's model discovery treats any redirect as failure "so the credential can't leak to a redirect target" — [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
  - Claude Code `apiKeyHelper` runs a command whose output is cached (default 5 min, `CLAUDE_CODE_API_KEY_HELPER_TTL_MS`) and re-runs it. Managed `allowedProviders: ["customEndpoint"]` pins the endpoint — [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect); [Claude Code: Other LLM gateways](https://code.claude.com/docs/en/llm-gateway)
  - Codex `[model_providers.<id>.auth]` runs a token command with no stdin, a timeout, and a proactive refresh interval — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
  - Copilot CLI `providers.json` stores credentials in plaintext and does not expand `$VAR` — [GitHub Docs: BYOK models](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models)
- Unix sockets: Codex's provider and API crates contain no Unix-socket support (grep at commit 5f645d73) — [Codex model-provider-info @5f645d73](https://github.com/openai/codex/blob/5f645d732cc2905c0d7e02a5d1683631fe8a02e7/codex-rs/model-provider-info/src/lib.rs)
- Claude Code supports mTLS client certificates (`CLAUDE_CODE_CLIENT_CERT`, `CLAUDE_CODE_CLIENT_KEY`, `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`) and `NODE_EXTRA_CA_CERTS`; no Unix-socket variable appeared in the portion of the env-var list read — [Claude Code env vars](https://code.claude.com/docs/en/env-vars); [Connect Claude Code to an LLM gateway](https://code.claude.com/docs/en/llm-gateway-connect)
- Precedents for loopback defaults:
  - claude-code-router binds `127.0.0.1:3456` by default and supports per-client keys with expiry and limits — [claude-code-router README](https://github.com/musistudio/claude-code-router)
  - Ollama's local `/v1/messages` "does not validate API keys" — [Ollama Anthropic compatibility](https://docs.ollama.com/api/anthropic-compatibility)

### Inferences
- **Request checks.**
  - Reject requests whose `Host` isn't `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`.
  - Reject any request with an `Origin` header or `Sec-Fetch-Site`/`Sec-Fetch-Mode` headers. CLI harnesses (Node, Rust reqwest, Go) don't send them; browsers do.
  - Answer `OPTIONS` without CORS allow headers.
  - These steps defeat DNS rebinding and drive-by fetches even in browsers without Chrome's LNA prompt.
- **Per-harness tokens.**
  - Issue random tokens of at least 128 bits, one per harness profile: Codex via `auth.command`; Claude Code via `apiKeyHelper` or `ANTHROPIC_AUTH_TOKEN`; Copilot `bearerToken`; Zed `<PROVIDER>_API_KEY`; Gemini via `GEMINI_API_KEY`.
  - Store them in user-only (0600) files or the OS keychain.
  - Accept both `Authorization: Bearer` and `x-api-key`, since Claude Code may send either.
  - Bind each token to its allowed wire API and models, to a spend cap within the prepaid balance, and to the usage-ledger identity.
- **Token minting over a local socket.** The sidecar's own token-minting CLI can reach the daemon over a Unix socket with peer-credential checks (`SO_PEERCRED`, or `LOCAL_PEERCRED` on macOS), even though the harness→gateway leg must be loopback TCP.
- **Same-user limits.** Any process running as the same user can read harness config or invoke the helper, so tokens are about attribution, revocation, and blocking browsers and other users, not a sandbox. Real isolation needs OS mechanisms beyond this research. Mapping loopback TCP connections to PIDs is possible but racy (an unverified idea).
- **Never bind 0.0.0.0.** The NemoClaw/Ollama case shows that binding wide can also disable Host checks inside the server.

### Gaps
- Not verified exhaustively: whether any of these harnesses accepts a `unix://` base URL (only Codex source and part of the Claude Code env-var docs were checked).
- Firefox and Safari local-network protections weren't researched.
- I found no source on how harnesses behave if the gateway requires mTLS. Claude Code supports client certs; Codex's support wasn't checked.
