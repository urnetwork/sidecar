# Hosted web search in coding harnesses, and how a gateway can emulate it (as of 2026-11-23)

Versions examined: Codex CLI 0.171.0 (latest stable, published 2026-11-20) and `openai/codex` main at commit a52fdb3 (2026-11-23); openai-python 3.57.0 (commit f63f14b, 2026-11-20); anthropic-sdk-python 2.12.0 (commit 8baaef1, 2026-11-20); Claude Code 2.1.330 (latest on npm, 2026-11-20), whose shipped native binary embeds its minified JavaScript, which was read locally. Source links below are pinned to those commits. Claims marked "(binary)" come from reading that minified code. Their identifiers are minified, so the logic is reported as read, and anything not fully traced is flagged.

## 1. OpenAI Responses API `web_search` tool (and `web_search_preview`)

### Takeaway
The hosted tool is `{"type":"web_search"}` (alias `web_search_2025_08_26`). Its request fields are `external_web_access`, `filters`, `search_context_size` and `user_location`; the guide also documents `filters.blocked_domains`, `return_token_budget`, `search_content_types` and `image_settings`, which openai-python 3.57.0 does not yet type. The output is a `web_search_call` item with `id`, `status` and an `action` (`search` / `open_page` / `find_in_page`), followed by a `message` whose `output_text` carries `url_citation` annotations. Streaming adds three bare progress events (`response.web_search_call.in_progress`, `.searching`, `.completed`) that carry only `item_id`, `output_index` and `sequence_number`; the item itself travels in `response.output_item.added`/`.done`. Search counts appear in `response.tool_usage.web_search.num_requests`, not in `usage`.

### Cited Findings
**Request (tool definition)**
- `WebSearchTool.type` is `Literal["web_search", "web_search_2025_08_26"]`. Its optional fields are `external_web_access: bool` ("Defaults to true when omitted. When false, the web search tool runs in offline/cache-only mode and will not fetch new external content."), `filters: {allowed_domains: [str]}` ("If not provided, all domains are allowed. Subdomains of the provided domains are allowed as well."), `search_context_size: "low"|"medium"|"high"` ("`medium` is the default") and `user_location` — [openai-python 3.57.0 `web_search_tool.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/web_search_tool.py)
- `user_location` for `web_search` has optional `type: "approximate"`, `city`, `country` (two-letter ISO), `region` and `timezone` (IANA). "If omitted or null, defaults to the United States. To avoid this fallback, pass `{"type": "approximate"}` without location fields." — [openai-python `web_search_tool.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/web_search_tool.py)
- `WebSearchPreviewTool.type` is `Literal["web_search_preview", "web_search_preview_2025_03_11"]`. Its fields are `search_content_types: ["text"|"image"]`, `search_context_size` and `user_location` (`type: "approximate"` required). It has no `filters` and no `external_web_access` — [openai-python `web_search_preview_tool.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/web_search_preview_tool.py)
- The guide recommends `{ "type": "web_search" }` for new integrations. `web_search_preview` "does not support newer controls such as `filters`, `external_web_access`, and `return_token_budget`". Preview variants "ignore this parameter and behave as if `external_web_access` is `true`". — [OpenAI web search guide (.md)](https://developers.openai.com/api/docs/guides/tools-web-search.md)
- Domain filtering: "With the `filters` parameter you can configure up to 100 `allowed_domains` or up to 100 `blocked_domains`." Omit the scheme (`openai.com`, not `https://openai.com/`). Filtering "also includes subdomains" and "is only available in the Responses API with the `web_search` tool". The Go example sets `blocked_domains` through `SetExtraFields`, meaning the typed SDKs lag the docs. — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md); openai-python 3.57.0 has no `blocked_domains` in its Responses types ([`web_search_tool.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/web_search_tool.py))
- `return_token_budget` accepts `default` or `unlimited` and applies "only to the hosted Responses API `web_search` tool with GPT-5+ reasoning web search" — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)
- Image search: set `search_content_types` to include `image`, with optional `image_settings` (`max_results`, `caption`). With `include: ["web_search_call.results"]`, raw results come back in `web_search_call.results[]` as `{"type":"image_result","image_url","thumbnail_url","source_website_url","caption"}` — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)
- Limits: "The web search context window is limited to 128k". "With `tool_choice: "auto"`, search is optional. Use `tool_choice: "required"` or a specific web search tool choice when search must run." For `gpt-5`, web search needs reasoning effort above `minimal`. The guide's examples use the model `gpt-6.2-astra`. — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)

**Output item `web_search_call`**
- `ResponseFunctionWebSearch` has `id: str`, `action: Action`, `status: Literal["in_progress","searching","completed","failed","incomplete"]` and `type: Literal["web_search_call"]`; none is Optional in the type. `Action` is a union discriminated on `type`:
  - `search`: `queries?: [str]`, `query?: str`, `sources?: [{type:"url", url}]`
  - `open_page`: `url?: str`
  - `find_in_page`: `pattern: str` and `url: str`, both required

  Source: [openai-python `response_function_web_search.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_function_web_search.py)
- The guide's output example is `{"type":"web_search_call","id":"ws_67c9fa…","status":"completed","action":{"type":"search","query":"latest news about AI"}}`, followed by a `message` item (`id: "msg_…"`, `status: "completed"`, `role: "assistant"`) whose `content[0]` is `output_text` with `annotations`. A `search` action "will usually (but not always) include the search `queries`". `open_page` and `find_in_page` are "Supported in reasoning models". — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)
- The beta Responses type (`BetaResponseFunctionWebSearch`) adds an optional `agent: {agent_name}` field and is otherwise the same — [openai-python `beta_response_function_web_search.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/beta/beta_response_function_web_search.py)

**Citations (`url_citation`)**
- In `output_text`, `annotations: List[Annotation]` is required (it may be empty), as are `text` and `type: "output_text"`. `AnnotationURLCitation` requires `type: "url_citation"`, `url`, `title`, `start_index` and `end_index` ("The index of the first/last character of the URL citation in the message") — [openai-python `response_output_text.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_output_text.py)
- The guide's example annotation is `{"type":"url_citation","start_index":2606,"end_index":2758,"url":"https://...","title":"Title..."}`. "When your interface displays web results or information from them, you must show inline citations as prominent, clickable links." — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)

**Streaming events**
- `response.web_search_call.in_progress` ("Emitted when a web search call is initiated"), `response.web_search_call.searching` ("…is executing") and `response.web_search_call.completed` each carry only `type`, `item_id`, `output_index` and `sequence_number` — [in_progress](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_web_search_call_in_progress_event.py), [searching](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_web_search_call_searching_event.py), [completed](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_web_search_call_completed_event.py)
- The official streaming reference confirms these schemas (`ResponseWebSearchCallInProgressEvent` etc.), with examples like `{"type":"response.web_search_call.in_progress","output_index":0,"item_id":"ws_123","sequence_number":0}` — [Responses streaming events reference (.md)](https://developers.openai.com/api/reference/resources/responses/streaming-events.md)
- The same reference lists the item as `WebSearchCall object { id, status, type, action }` with "`action: optional Search { type, queries, query, sources } or OpenPage { type, url } or FindInPage { pattern, type, url }`". That is, `action` is optional there (14 occurrences), while openai-python 3.57.0 types `action` as required. — [Responses streaming events reference](https://developers.openai.com/api/reference/resources/responses/streaming-events.md); contradicted by [openai-python `response_function_web_search.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_function_web_search.py)
- `response.output_text.annotation.added` carries `annotation`, `annotation_index`, `content_index`, `item_id`, `output_index` and `sequence_number` — [openai-python `response_output_text_annotation_added_event.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_output_text_annotation_added_event.py)
- Codex's mock-server fixtures model the item frames this way:
  - `response.output_item.added`: `{"type":"web_search_call","id":…,"status":…}`, with no `action`
  - `response.output_item.done`: the same item plus `"action":{"type":"search","query":…}`

  Source: [codex `core/tests/common/responses.rs` L976-997](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/tests/common/responses.rs#L976-L997)

**`include` and usage**
- `ResponseIncludable` includes `"web_search_call.results"` and `"web_search_call.action.sources"` — [openai-python `response_includable.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_includable.py)
- `web_search_call.action.sources` returns "the complete list of URLs the model consulted", usually more than the citations. "Real-time third-party feeds are also surfaced here and are labeled as `oai-sports`, `oai-weather`, or `oai-finance`." It works with both `web_search` and `web_search_preview`. — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)
- `Response.tool_usage` is optional: `{image_gen: …, web_search: {num_requests: int}}`. "`web_search.num_requests` counts billable searches. Discounted searches and actions such as opening a page are excluded." `ResponseUsage` itself has no web-search field. — [openai-python `response.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response.py), [`response_usage.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_usage.py), [`beta_response.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/beta/beta_response.py)
- "Search actions incur a tool call cost." Rate limits are the "Same as tiered rate limits for underlying model". — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)

**Which fields a client needs**
- In the SDK types, a `web_search_call` needs `id`, `action` (with `type`), `status` and `type`, and a `url_citation` needs all five of its fields — [openai-python types above](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/responses/response_function_web_search.py)
- Codex needs less. Every field of its `WebSearchCall` except the `type` tag is `#[serde(default)]` Option (`encrypted_content`, `id`, `status`, `action`), and an unknown `action.type` parses as `Other` — [codex `protocol/src/models.rs` L1353-1370, L2197-2225](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/protocol/src/models.rs#L1353-L1370)

### Inferences
- A gateway that wants to satisfy every Responses client, not only Codex, should emit the full set of frames:
  1. `response.output_item.added` with `{type:"web_search_call", id:"ws_…", status:"in_progress", action:{type:"search", …}}`
  2. `response.web_search_call.in_progress`, then `.searching`, then `.completed`
  3. `response.output_item.done` with `status:"completed"` and the final `action` (`query` and `queries`, plus `sources` as `{type:"url",url}` when the request's `include` asks for `web_search_call.action.sources`)
  4. A `message` item with `url_citation` annotations whose character offsets point into the final text

  It should also fill `tool_usage.web_search.num_requests`. OpenAI does not publish this ordering, but Ollama's working Responses emulation (section 4) emits exactly `output_item.added` (in_progress, with `action.search.query`) → `web_search_call.in_progress` → `.searching` → `.completed` → `output_item.done`.
- Brave Search maps naturally onto `action.search` (query) and `sources` (result URLs), with Brave result titles as `url_citation.title`. `open_page` and `find_in_page` need a page fetcher, which Brave does not provide.
- `external_web_access:false` ("cache-only") is close to what a search-index API such as Brave already is. A gateway can treat `false` as "search only, no live page fetches" and `true` as "search plus fetch".

### Gaps
- OpenAI does not publish, in the pages fetched, the full ordered SSE sequence for a `web_search_call`. It is also unclear whether `output_item.added` carries an `action` in production, and what `action` a `failed` or `incomplete` call carries.
- The JSON shape of feed sources (`oai-sports` etc.) inside `action.sources` was not confirmed. The SDK types sources only as `{type:"url", url}`.
- `indexed_web_access`, which Codex sends (section 2), is not in the public SDK or the guide; its server semantics are undocumented.

## 2. Codex CLI (0.171.0 stable; main a52fdb3)

### Takeaway
Codex sends the hosted `{"type":"web_search",…}` tool to every provider whose runtime capability `web_search` is true. Custom `[model_providers.<id>]` inherit `web_search: true`, and their config cannot turn it off; only the built-in GCP provider and Bedrock outside its Mantle endpoint turn it off. So a custom backend must accept or emulate the tool, or the user must set `web_search = "disabled"`. The default mode is `cached` (`external_web_access:false`). Codex parses only the `web_search_call` items in `response.output_item.added`/`.done`; it drops the `response.web_search_call.*` events into a debug log. It shows "Searching the web" / "Searched the web for <query>" and resends the items in later `input`. A separate "standalone web search" path, still under development and off by default, replaces the hosted tool with a function tool `web.run`. Codex executes that tool client-side by POSTing to `{base_url}/alpha/search`. A provider opts in with `supports_standalone_web_search = true`.

### Cited Findings
**Config values and defaults**
- `web_search` is `disabled | cached | indexed | live`. Docs: "Web search mode (default: `"cached"`; cached uses an OpenAI-maintained index without external web access; indexed permits external access only when gated by the search index; if you use `--yolo` or another full access sandbox setting, it defaults to `"live"`). Use `"live"` for unrestricted live retrieval, or `"disabled"` to remove the tool." — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference) (developers.openai.com/codex/config-reference now 308-redirects there)
- In source, `WebSearchMode` is `Disabled | Cached (#[default]) | Indexed | Live` — [codex `protocol/src/config_types.rs` L376-382](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/protocol/src/config_types.rs#L376-L382)
- Full access (`PermissionProfile::Disabled`) promotes `cached`/`live` to `live`, and `indexed` only when the mode was not set explicitly. A mode the provider does not allow falls back in the order cached → live → disabled. — [codex `core/src/config/mod.rs` L3400-3445](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/config/mod.rs#L3400-L3445)
- Feature `web_search_indexed_default` (stage Stable, `default_enabled: false`) makes `indexed` the default — [codex `features/src/lib.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/features/src/lib.rs), [codex `core/tests/suite/web_search.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/tests/suite/web_search.rs)
- Deprecated toggles: `features.web_search_cached` ("true maps to `web_search = "cached"`"), `features.web_search_request` ("true maps to `web_search = "live"`") and `features.web_search`. `allowed_web_search_modes` lists the modes allowed by requirements ("`disabled` is always allowed"). — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- The `[tools.web_search]` table (`WebSearchToolConfig`) takes `allowed_domains`, `context_size` (`low|medium|high`) and `location` (`city`, `country`, `region`, `timezone`) — [codex `core/config.schema.json`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/config.schema.json)

**What Codex sends (hosted tool)**
- Mode to JSON: Cached → `external_web_access:false`; Indexed → `external_web_access:true, indexed_web_access:true`; Live → `external_web_access:true`; Disabled → no tool. Models whose catalog entry has `web_search_tool_type = "text_and_image"` also get `search_content_types:["text","image"]`. — [codex `core/src/tools/hosted_spec.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/tools/hosted_spec.rs), [`tools/src/tool_spec.rs` L34-52](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/tools/src/tool_spec.rs#L34-L52)
- A source comment admits a gap: "TODO: Understand why we get an error on web_search although the API docs say it's supported." — [codex `tools/src/tool_spec.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/tools/src/tool_spec.rs#L34-L52)
- Test of the full forwarded shape, with config `web_search = "live"` and `[tools.web_search] context_size="high", allowed_domains=["example.com"], location={country="US", city="New York", timezone="America/New_York"}`, under full access:
  ```json
  {"type":"web_search","external_web_access":true,"search_context_size":"high",
   "filters":{"allowed_domains":["example.com"]},
   "user_location":{"type":"approximate","country":"US","city":"New York","timezone":"America/New_York"}}
  ```
  Source: [codex `core/tests/suite/web_search.rs` L587-640](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/tests/suite/web_search.rs#L587-L640)
- Hosted tools go only to providers with `provider.capabilities().web_search`, and not when the standalone tool is available. Models with `use_responses_lite` get none ("Responses Lite accepts schemas for client-executed tools, not hosted Responses tools."). — [codex `core/src/tools/spec_plan.rs` L692-721](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/tools/spec_plan.rs#L692-L721); the logic is identical in [rust-v0.171.0](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/tools/spec_plan.rs)
- `ProviderCapabilities::default()` is `web_search: true, external_web_access: true`. A custom provider's config can override only `external_web_access` (and `remote_compaction`), not `web_search`. — [codex `model-provider/src/capabilities.rs` L21-55](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider/src/capabilities.rs#L21-L55)
- The built-in GCP provider sets `web_search: false` ([`gcp/mod.rs` L85](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider/src/gcp/mod.rs#L85)). Bedrock sets `web_search: self.endpoint == BedrockEndpoint::Mantle` and `external_web_access: false` ([`amazon_bedrock/mod.rs` L309](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider/src/amazon_bedrock/mod.rs#L309)).
- `model_providers.<id>.capabilities.external_web_access`: "Whether the provider's hosted web search can access the live web. Omit to keep provider defaults; model and turn settings may restrict access further." — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference); type in [codex `model-provider-info/src/capabilities.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider-info/src/capabilities.rs)
- With it `false`, `live` and `indexed` are disallowed. A test with a custom provider and `[model_providers.custom.capabilities] external_web_access = false` asserts that the request's tool has `external_web_access: false`. — [codex `core/src/config/mod.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/config/mod.rs#L3400-L3445), [`core/tests/suite/scenarios_provider_capabilities.rs` L13-30, L84-88](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/tests/suite/scenarios_provider_capabilities.rs#L13-L30)
- `wire_api` has a single variant, `responses`; Chat Completions is no longer a Codex wire API — [codex `model-provider-info/src/lib.rs` L119-123](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider-info/src/lib.rs#L119-L123)

**What Codex parses and shows**
- The SSE handler acts on `response.output_item.added` and `.done` (parsing `item` as a `ResponseItem`). Other events fall to `debug!("unhandled responses event: …")` or `trace!`. That branch includes all `response.web_search_call.*` events, which have no match arm. — [codex `codex-api/src/sse/responses.rs` L548-585](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/codex-api/src/sse/responses.rs#L548-L585)
- An added or done `WebSearchCall` becomes a `TurnItem::WebSearch {id, query, action}`. The query detail is `query`, or else the first of `queries` with " ..." appended when there are several, or the `open_page` URL, or `'<pattern>' in <url>`. The item maps to the legacy events `WebSearchBegin` and `WebSearchEnd`. — [codex `core/src/event_mapping.rs` L232-243](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/event_mapping.rs#L232-L243), [`core/src/web_search.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/web_search.rs)
- TUI labels: "Searching the web" / "Searched the web" + " for <detail>", "Opening"/"Opened" <url>, "Searching for"/"Searched for" '<pattern>' in <url>, and "Browsing the web" for an in-progress call with no detail — [codex `tui/src/history_cell/search.rs` L83-120](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/tui/src/history_cell/search.rs#L83-L120)
- 0.156.0 (2026-09-22): "Preserve web search actions and results in exec JSON output" (#46319) — [Codex releases](https://github.com/openai/codex/releases/tag/rust-v0.156.0)
- `web_search_call` items count as model-generated history and are replayed. The HTTP `ResponsesApiRequest` has `input` and `store` but no `previous_response_id`, which only the WebSocket transport uses, so later turns resend `web_search_call` items in `input`. — [codex `context_manager/history.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/context_manager/history.rs), [`codex-api/src/common.rs` L407-437](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/codex-api/src/common.rs#L407-L437), [`core/src/client.rs` header comment](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/client.rs)
- `output_text.annotations` is kept as opaque `Vec<serde_json::Value>`, "Preserve provider metadata, including empty arrays, for sampled-output replay." Annotations therefore come back in later `input`; Codex does not render `url_citation`. — [codex `protocol/src/models.rs` L970-980](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/protocol/src/models.rs#L970-L980)
- Codex's `include` is `["reasoning.encrypted_content"]`, plus `output.encrypted_content` for OpenAI only. It never requests `web_search_call.action.sources`. — [codex `core/src/client.rs` L1333-1336](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/client.rs#L1333-L1336)

**Standalone web search (`supports_standalone_web_search`)**
- Docs: "Advertise support for a compatible standalone web search endpoint (default: false). Standalone search remains under development and off by default; provider compatibility alone doesn't enable it." — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference); field in [codex `model-provider-info/src/lib.rs` L231-233](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider-info/src/lib.rs#L231-L233)
- The extension contributes the tool when `config.model_provider.is_openai() || …uses_openai_actor_authorization() || …supports_standalone_web_search`, and only when the mode is not `disabled` — [codex `ext/web-search/src/extension.rs` L45-51](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/src/extension.rs#L45-L51)
- It is enabled only when `provider.capabilities().web_search && (model_info.use_responses_lite || features.standalone_web_search)`. Feature `standalone_web_search` is `Stage::UnderDevelopment, default_enabled: false`. — [codex `core/src/tools/spec_plan.rs` L1159-1167](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/tools/spec_plan.rs#L1159-L1167), [`features/src/lib.rs` L1499-1503](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/features/src/lib.rs#L1499-L1503)
- The docs describe `features.standalone_web_search` differently: "Experimental. Set to `true` to keep the desktop app's native web search configuration when hosted search through MCP would otherwise be available." This matches the 0.168–0.171 Search-MCP design (see below) more than main. — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- Tool given to the model: a Responses `namespace` tool, `{"type":"namespace","name":"web","description":"Tools in the web namespace.","tools":[{"type":"function","name":"run","strict":false,"parameters":<SearchCommands schema>,"description":<web_run_description.md>}]}`. It supports parallel calls. The model calls it as a `function_call` with `namespace:"web"`, `name:"run"`. — [codex `ext/web-search/src/tool.rs` L48-95](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/src/tool.rs#L48-L95), [`protocol/src/models.rs` FunctionCall](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/protocol/src/models.rs#L1218-L1244), [`ext/web-search/web_run_description.md`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/web_run_description.md)
- `SearchCommands` arguments are: `search_query`, `literature_search_query` (model-gated), `image_query` (each `[{q, recency?, domains?}]`); `open` `[{ref_id, lineno?}]`; `click` `[{ref_id, id}]`; `find` `[{ref_id, pattern}]`; `screenshot` `[{ref_id, pageno}]`; `finance`, `weather`, `sports` and `time`; and `response_length: short|medium|long`. Description rule: "`search_query` must have length at most 4 in each call." — [codex `codex-api/src/search.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/codex-api/src/search.rs), [`web_run_description.md`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/web_run_description.md)
- Endpoint: `POST` to `SEARCH_ENDPOINT = "alpha/search"` under the provider base URL. Tests use `/v1/alpha/search` for a custom Responses provider and `/backend-api/codex/alpha/search` (or `/api/codex/alpha/search`) for ChatGPT. Codex adds the `x-codex-turn-metadata` and originator headers. — [codex `codex-api/src/endpoint/search.rs` L15, L34-47](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/codex-api/src/endpoint/search.rs#L15), [`app-server/tests/suite/v2/web_search.rs` L285-286](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/app-server/tests/suite/v2/web_search.rs#L285-L286), [`ext/web-search/src/tool.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/src/tool.rs#L126-L135)
- Request body `SearchRequest`:
  - `id`: session id
  - `model`
  - `reasoning?`
  - `input?`: recent visible messages, "the previous user text message, up to 1k tokens of assistant text that followed it, and the current user text message"
  - `commands?`: the model's arguments
  - `settings?`:
    - `user_location{type:"approximate",country?,region?,city?,timezone?}`
    - `search_context_size`
    - `filters{allowed_domains?,blocked_domains?}`
    - `image_settings{max_results?,caption?}`
    - `allowed_callers:["direct"]`
    - `external_web_access`: `false` for cached, `"indexed"` for indexed, `true` for live
  - `max_output_tokens?`

  Sources: [codex `codex-api/src/search.rs` L8-21 and settings types](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/codex-api/src/search.rs#L8-L21), [`ext/web-search/src/extension.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/src/extension.rs), [`ext/web-search/src/history.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/src/history.rs)
- Response body `SearchResponse` is `{encrypted_output: string|null, output: string, results?: [opaque JSON]}` ("Structured result DTOs are passed to clients out-of-band from `output`"). `output` goes back to the model as `function_call_output` with `[{type:"input_text", text}]`. An error becomes `success:false` text, truncated to 1024 bytes ("Return standalone web search failures to the model", 0.167.0). — [codex `codex-api/src/search.rs` L301-308](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/codex-api/src/search.rs#L301-L308), [`ext/web-search/src/output.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/ext/web-search/src/output.rs), [release 0.167.0](https://github.com/openai/codex/releases/tag/rust-v0.167.0)
- Standalone release history:
  - 0.157.0 (2026-09-25): proxy routing for standalone search
  - 0.166.0 (2026-10-29): model-gated literature search
  - 0.167.0 (2026-11-06): failures returned to the model; turn-scoped permissions
  - 0.168.0 (2026-11-13): #59033 "Add web search provider metadata and configuration": `ModelInfo.web_search_provider` (`standalone`|`search_mcp`), `tools.client_search_provider`, feature `hosted_search_policy`
  - 0.171.0 (2026-11-20): #62144 "Preserve web search provider ownership across thread resumes" ("Search MCP and native web search produce provider-specific references")

  Sources: [Codex releases](https://github.com/openai/codex/releases), [PR #59033](https://github.com/openai/codex/pull/59033), [PR #62144](https://github.com/openai/codex/pull/62144)
- `WebSearchProvider`, `client_search_provider` and `core/src/model_search.rs` exist at tag rust-v0.171.0 but are absent from main at a52fdb3 (2026-11-23) — [rust-v0.171.0 `core/src/model_search.rs`](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/core/src/model_search.rs)

**Model-catalog fields**
- `web_search_tool_type: WebSearchToolType` is `text` (default) or `text_and_image`. It only adds `search_content_types` to the hosted tool. — [codex `protocol/src/openai_models.rs` L347-351, L464](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/protocol/src/openai_models.rs#L347-L351), [`hosted_spec.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/tools/hosted_spec.rs)
- `supports_search_tool: bool` (default false) has nothing to do with web search. It gates the `tool_search` tool and deferred exposure of MCP and other tools. — [codex `protocol/src/openai_models.rs` L490](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/protocol/src/openai_models.rs#L490), [`core/src/tools/spec_plan.rs` L150-165, L395-410](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/tools/spec_plan.rs#L395-L410)
- `use_responses_lite: bool` removes hosted tools and turns on standalone search where the provider supports it — [codex `spec_plan.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/core/src/tools/spec_plan.rs#L1159-L1167)
- Catalogs load from `model_catalog_json` (a local path) or `model_providers.<id>.model_catalog_url` ("must serve the Codex catalog format, not the public `/v1/models` API") — [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference), [`model-provider-info/src/lib.rs`](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider-info/src/lib.rs)

### Inferences
- **Hosted emulation for Codex.** It needs very little. The gateway must:
  - accept a `tools[]` entry `{"type":"web_search", …}` and ignore unknown fields (`indexed_web_access`, `search_content_types`)
  - run the search loop internally
  - stream `response.output_item.added` and then `.done` for each `web_search_call` (id plus `action.search.query` so the TUI has text)
  - stream the final assistant `message`
  - on later turns, accept `web_search_call` items and `annotations` coming back in `input`, and turn them into something the open model understands (drop them, or render them as text)

  The `response.web_search_call.*` events are optional for Codex.
- **Pinning to search-only.** The generated config can set `[model_providers.sidecar.capabilities] external_web_access = false`. Codex then always sends `external_web_access:false` (cached), even under `--yolo`, which matches "Brave index search, no live page fetch".
- **Standalone path.** It would let Codex run the loop client-side, with the gateway serving `POST /v1/alpha/search` (Brave behind it). But it needs `features.standalone_web_search = true` (under development) or a `use_responses_lite` catalog entry. The Responses endpoint must also accept `namespace` tools and namespaced `function_call` output. Its contract changed in every release from 0.157 to 0.171, so it is the less stable target.

### Gaps
- The exact meaning of `indexed_web_access` and of `external_web_access:"indexed"` on OpenAI's side is not publicly documented.
- No Codex code path handles `status:"failed"` on a `web_search_call` specially; whether it does in the TUI renderer was not verified.
- It was not confirmed which `features.standalone_web_search` semantics the 0.171.0 binary uses (docs and main differ).

## 3. Claude Code (2.1.330)

### Takeaway
Claude Code's `WebSearch` is a client tool. When the main model calls it, Claude Code makes a separate streaming Messages request. That request contains only the server tool `{"type":"web_search_20250305","name":"web_search","max_uses":8,…}`, with `tool_choice:{"type":"tool","name":"web_search"}`, thinking off and a fixed system prompt. It runs on the main loop model by default (a Haiku-class model when a remote flag is on). From the reply, Claude Code keeps the text plus each `web_search_tool_result`'s `title`/`url` (or `error_code`), and hands the main model a plain-text block. Behind a plain `ANTHROPIC_BASE_URL` gateway, Claude Code still treats the provider as "firstParty", offers WebSearch and sends that side request to the gateway. It disables WebSearch on Bedrock and on "Claude apps gateway" (`CLAUDE_CODE_USE_GATEWAY`) sessions. No env var disables WebSearch; a `WebSearch` deny rule does. WebFetch is client-side; Claude Code does not use the API's `web_fetch` server tool.

### Cited Findings
**WebSearch tool and the side request**
- Tool name `"WebSearch"`. Input `{query (min 2 chars), allowed_domains?, blocked_domains?}`, plus `mode: "standard"|"extended"` only when a firstParty-only flag or env var (`CLAUDE_CODE_WEB_SEARCH_FAST_ARG`, undocumented) enables it. It validates "Error: Cannot specify both allowed_domains and blocked_domains in the same request". `maxResultSizeChars: 1e5`. — (binary) [@anthropic-ai/claude-code 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- The side request (`querySource:"web_search_tool"`), from the minified code (binary, [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)):
  - `extraToolSchemas:[{type:"web_search_20250305", name:"web_search", allowed_domains, blocked_domains, max_uses: 8, …(search_profile:"fast" when mode is "standard")}]` and `tools:[]`
  - `toolChoice:{type:"tool",name:"web_search"}`
  - `thinkingConfig:{type:"disabled"}` and `enablePromptCaching:false`
  - system prompt: "You run a web search for another Claude model, which is waiting on the result and can search again. Search once, then reply with a brief summary of the results."
  - user message: "Perform a web search for the query: " + query
- `search_profile` appears in no anthropic-sdk-python 2.12.0 tool type; it is undocumented — [anthropic-sdk-python `web_search_tool_20250305_param.py`](https://github.com/anthropics/anthropic-sdk-python/blob/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types/web_search_tool_20250305_param.py)
- Model choice: `{useHaiku: flag("tengu_plum_vx3", false), model: useHaiku ? <small fast model> : loopModel()}`, so by default the side request uses the main loop model. With a second flag (`tengu_quick_otter`), Haiku runs at `effort:"low"`. (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- Docs: "The tool may issue up to eight backend searches per call." "When the search request hits an overloaded API, Claude Code retries it with backoff." "The search backend is not configurable. To search with a different provider, add an MCP server that exposes a search tool." — [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference#websearch-tool-behavior)
- Other search paths exist for hosted environments: an injected host search function, a "search service", and a CCR proxy (`CLAUDE_CODE_WEBSEARCH_USE_CCR_PROXY`). A local CLI on the Messages API takes the side-request path. (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)

**Availability and disabling**
- `isEnabled()` (binary, [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)):
  - false unless a gate keyed `"allow_web_search"` passes
  - true for provider `firstParty` (and a helper-defined set of first-party-like providers)
  - false for `"gateway"`
  - for `vertex`, true unless the model is Claude 3.x or older than `claude-opus-4-0`
  - true for `foundry`, but the call throws "Web search is not available on this Foundry deployment." when the model lacks the capability
  - false otherwise (Bedrock, Mantle)
- Provider resolution `ve()` returns `"gateway"` for Claude-apps-gateway credentials (`CLAUDE_CODE_USE_GATEWAY`). Otherwise it picks `bedrock`/`foundry`/`anthropicAws`/`anthropicGoogleCloud`/`mantle`/`vertex` from the `CLAUDE_CODE_USE_*` vars, and `"firstParty"` otherwise. A plain `ANTHROPIC_BASE_URL` is therefore `firstParty`. (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- Docs: "WebSearch is available on the Claude API, Claude Platform on AWS, Claude Models on Google Cloud (Anthropic managed), and Microsoft Foundry. On Google Cloud's Agent Platform it works with Opus 4, Sonnet 4, Haiku 4.5, and later models. Amazon Bedrock doesn't expose the server-side web search tool." — [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference#websearch-tool-behavior), [Amazon Bedrock page](https://code.claude.com/docs/en/amazon-bedrock)
- Claude apps gateway: "Server-side web search: Not available. The CLI can't see which upstream provider the gateway routes to, so it can't verify web search support and disables WebSearch on gateway sessions" — [Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway)
- `ANTHROPIC_BASE_URL` gateways: "Claude Code treats an `ANTHROPIC_BASE_URL` gateway as an Anthropic-format endpoint and sends it the beta headers and request body fields it sends to `api.anthropic.com`" except a small set of direct-connection defaults. "Forward the header verbatim; don't allowlist individual values." — [gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- Disabling: "WebSearch permission rules take no specifier. A bare `WebSearch` entry in `allow` or `deny` is the only form." — [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference#websearch-tool-behavior)
- `CLAUDE_CODE_DISABLE_WEB_FETCH=1` turns off WebFetch and "The WebSearch tool stays available" (v2.1.285+). No documented env var disables WebSearch. — [Claude Code env vars](https://code.claude.com/docs/en/env-vars)
- Limits: 200 calls per interactive session (`CLAUDE_CODE_MAX_WEB_SEARCHES_PER_SESSION`, v2.1.212+), refilling at about 100 per hour (`CLAUDE_CODE_WEB_SEARCH_REFILLS_PER_HOUR`, v2.1.290+). The limit is per turn in `-p` and the Agent SDK. — [Claude Code env vars](https://code.claude.com/docs/en/env-vars), [tools reference](https://code.claude.com/docs/en/tools-reference#websearch-tool-behavior)

**Blocks Claude Code parses from the side request**
- Streaming, from the minified code (binary, [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)):
  - `content_block_start` with `content_block.type === "server_tool_use"`: records `id`
  - `content_block_delta` with `delta.type === "input_json_delta"`: accumulates `partial_json` and regex-extracts `"query"` for progress display
  - `content_block_start` with `web_search_tool_result`: counts `content.length` for a "results received" progress event
- Final assembly reads the completed assistant content (binary, [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)):
  - `server_tool_use` blocks are counted
  - for each `web_search_tool_result`, a non-array `content` becomes the string `Web search error: ${content.error_code}`; otherwise it maps to `[{title, url}]` keyed by `tool_use_id`
  - `text` blocks are concatenated as commentary
  - `citations` are not read
  - the output's `searchCount` ("Number of web searches performed") is `Math.max(<server_tool_use count>, <web_search_tool_result count>)`
- Cost: `usage.server_tool_use.web_search_requests × <web search price>` is added to session cost (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- Results-only mode, new in late 2026:
  - beta constant `web_search_results_only` = `"web-search-results-only-2026-11-15"`, added only when the provider is `firstParty` and further conditions hold (the model must be a recognised Claude model at or newer than `claude-opus-5-5`, among others)
  - in this mode Claude Code reads `encrypted_content` as plain page text unless it matches `/^[\w+/=-]*$/` (base64-like)

  (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- The legacy beta `"web-search-2025-03-05"` is listed with `when: (e) => e.provider==="vertex" && <model is Claude 4+> || e.provider==="foundry"`. It is not sent for `firstParty`, so a plain `ANTHROPIC_BASE_URL` gateway does not see it. (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)

**What the main model receives**
- Default `tool_result` content is plain text. It starts with `Web search results for query: "<query>"\n\n`. Then, per result entry, it adds the commentary string, or `Links: <serialized [{title,url},…]>`, or `No links found.`. It ends with `\nREMINDER: You MUST include the sources above in your response to the user using markdown hyperlinks.` In results-only mode the ending is instead "These results carry no citations, so a source reaches the user only as a markdown link in the response." (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- With the undocumented `CLAUDE_CODE_WEBSEARCH_CITATIONS` set, and hits carrying snippets, the `tool_result` instead holds `search_result` blocks: `{type:"search_result", source:url, title, content:[{type:"text",text:snippet}], citations:{enabled:true}}` (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- When the budget is exhausted, the result text is "Web search was not performed: this session's web search budget is used up (…)", with an instruction not to work around it through curl, a browser or a proxy (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)

**Messages API web search contract (what a gateway must emit)**
- Versions:
  - `web_search_20250305`: basic
  - `web_search_20260209`: adds dynamic filtering; `allowed_callers` defaults to `["code_execution_20260120"]`; set `["direct"]` to call directly
  - `web_search_20260318`: adds `response_inclusion: "full"|"excluded"`

  Tool fields: `max_uses`, `allowed_domains` / `blocked_domains` ("not both", or a 400), `user_location{type:"approximate",city,region,country,timezone}`. — [Claude web search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool), [anthropic-sdk-python types](https://github.com/anthropics/anthropic-sdk-python/blob/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types/web_search_tool_20260318_param.py)
- Blocks:
  - `ServerToolUseBlock{id, input: object, name: "web_search"|…, type:"server_tool_use", caller?}`
  - `WebSearchToolResultBlock{tool_use_id, type:"web_search_tool_result", content: WebSearchResultBlock[] | WebSearchToolResultErrorObject, caller?}`
  - `WebSearchResultBlock{type:"web_search_result", url, title, encrypted_content (required), page_age?}`
  - `WebSearchToolResultErrorObject{type:"web_search_tool_result_error", error_code}`

  `error_code` is one of `"invalid_tool_input","unavailable","max_uses_exceeded","too_many_requests","query_too_long","request_too_large"`. — [anthropic-sdk-python types](https://github.com/anthropics/anthropic-sdk-python/tree/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types) (`server_tool_use_block.py`, `web_search_tool_result_block.py`, `web_search_result_block.py`, `web_search_tool_result_error_object.py`, `web_search_tool_result_error_code.py`)
- Citations: `CitationsWebSearchResultLocation{type:"web_search_result_location", url, title?, encrypted_index, cited_text}`. Usage: `usage.server_tool_use{web_search_requests, web_fetch_requests}`. — [`citations_web_search_result_location.py`](https://github.com/anthropics/anthropic-sdk-python/blob/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types/citations_web_search_result_location.py), [`server_tool_usage.py`](https://github.com/anthropics/anthropic-sdk-python/blob/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types/server_tool_usage.py)
- Docs semantics:
  - Errors return HTTP 200 with the error object as `content`. "A search that succeeds but matches no results returns an empty `content` list, not an error."
  - `cited_text` is "Up to 150 characters".
  - "If `encrypted_content` is missing or modified, the request fails with a 400 validation error." This applies on later turns.
  - "$10 USD per 1,000 searches". "A web search that fails with an error is not billed."
  - `pause_turn` for long turns.

  Source: [Claude web search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool)
- Streaming example (docs):
  1. `content_block_start` `{"type":"server_tool_use","id":"srvtoolu_xyz789","name":"web_search"}`
  2. `content_block_delta` `{"type":"input_json_delta","partial_json":"{\"query\":\"…\"}"}`
  3. a pause while the search runs
  4. `content_block_start` with the whole `web_search_tool_result` (content array inline; no deltas)

  Text citations stream as `content_block_delta` with `delta:{type:"citations_delta", citation:{…}}`. — [Claude web search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool), [anthropic-sdk-python `citations_delta.py`](https://github.com/anthropics/anthropic-sdk-python/blob/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types/citations_delta.py)

**WebFetch**
- Claude Code's WebFetch is client-side: "It asks a question about the page, and a separate model call reads the page and returns an answer". It sends `User-Agent` "Claude-User…" and refuses `localhost`. A built-in `web-fetch` subagent is used with claude.ai login (v2.1.287+). — [Claude Code tools reference](https://code.claude.com/docs/en/tools-reference#webfetch-tool-behavior)
- The 2.1.330 binary contains no `web_fetch_20…` tool-type string, so Claude Code does not use the API's `web_fetch` server tool (binary) [npm 2.1.330](https://www.npmjs.com/package/@anthropic-ai/claude-code)
- The API's `web_fetch` server tool exists, in versions `web_fetch_20250910`, `web_fetch_20260209`, `web_fetch_20260309` (adds `use_cache`) and `web_fetch_20260318` (adds `response_inclusion`). Fields: `max_uses`, `allowed_domains`, `blocked_domains`, `citations`, `max_content_tokens`, `url_sources`. The result block is `web_fetch_tool_result` with `web_fetch_result{url, content: document, retrieved_at?}` or an error. Error codes: `invalid_tool_input, url_too_long, url_not_allowed, url_not_in_prior_context, url_not_accessible, unsupported_content_type, too_many_requests, max_uses_exceeded, unavailable, content_too_large`. — [anthropic-sdk-python types](https://github.com/anthropics/anthropic-sdk-python/tree/8baaef1c4d23b2e4861d05da0dca65252e879eb8/src/anthropic/types) (`web_fetch_tool_2026*_param.py`, `web_fetch_block.py`, `web_fetch_tool_result_error_code.py`)

### Inferences
- For Claude Code behind the sidecar (plain `ANTHROPIC_BASE_URL`), the main conversation needs no hosted-tool emulation: `WebSearch` is an ordinary client `tool_use`/`tool_result`. The gateway only has to recognise the side request: a `tools` array holding only a `web_search_2025…` server tool, with `tool_choice` forced to it. It then streams:
  - `server_tool_use` (`id` matching `^[\w-]+$`, e.g. `srvtoolu_…`, plus an `input_json_delta` with `{"query":…}`)
  - one `web_search_tool_result` with `web_search_result` items (`url`, `title`, an opaque non-empty `encrypted_content`, optional `page_age`)
  - a short text summary
  - `message_delta` with `stop_reason:"end_turn"` and optionally `usage.server_tool_use.web_search_requests`

  Up to 8 searches per side request are permitted.
- Claude Code never sends the side conversation back, so `encrypted_content` and `encrypted_index` need not decrypt to anything. Avoid placing raw page text there only if results-only mode could trigger; with open-weight model IDs it should not (it needs recognised `claude-opus-5-5`+ models).
- Claude Code adds `web_search_requests` × list price to its displayed cost, so a gateway may prefer to report 0 or the true count deliberately.
- The officially recommended alternative is to deny `WebSearch` and add a search MCP server (Brave's official MCP server, see section 4). That needs no gateway emulation, but the model sees a differently named tool.

### Gaps
- The `"allow_web_search"` gate function, the "first-party-like" provider helper, and the conditions that gate the results-only beta could not be fully decoded from minified code.
- Feature-flag defaults (`tengu_plum_vx3` etc.) are served remotely, so which model a given user's side request uses can vary. Flags take code defaults when flag fetching is disabled; that is inferred, not verified.

## 4. Gateway and harness precedents that emulate hosted web search with a third-party search API

### Takeaway
Four patterns exist:
1. Route the request to a model that searches natively.
2. Search first, then inject the results into the prompt.
3. A gateway-run loop: the gateway exposes its own function tool to the model and synthesizes the hosted-tool shapes for the client. This is the sidecar's design.
4. A plain client-side tool inside the harness.

Ollama is the closest working precedent for both target harnesses. It emulates Anthropic `web_search_*` on `/v1/messages` and OpenAI `web_search` on `/v1/responses`, emitting the full `web_search_call` event sequence on the latter, and its Codex docs say Codex web-search requests are executed by Ollama. LiteLLM's `websearch_interception`, whose providers include Brave, is the other gateway-run loop; its issue tracker is the best catalogue of failure modes.

Brave is used by LiteLLM, CCR v3, Pi's official skill, pi-web-access, OpenClaw and Brave's own MCP server. It is not used by OpenRouter, Portkey, Ollama (engine undisclosed), OpenCode, Gemini CLI or Aider.

Shallow clones used for checks: LiteLLM 3e27fc2 (2026-11-23), claude-code-router 6b6ca0c (2026-11-21), Ollama 318ee28 (2026-11-22), Open Responses dce9ddb (2026-10-29), Pi d91ac96 (2026-11-23), PiG 40b509f (2026-11-17), OpenCode 0089ba9 (2026-11-23). A research subagent compiled this section. Its key claims about LiteLLM, Ollama, CCR, Open Responses, OpenCode, Gemini CLI and PiG were re-checked against those clones; the rest rest on the links given.

### Cited Findings
**LiteLLM (BerriAI/litellm), Brave supported**
- `websearch_interception` is a callback. It replaces the client's hosted search tool with a function tool, runs searches through a configured `/search` provider, calls the model again and returns one response. It shipped as the headline of v1.81.0 ("Claude Code - Web Search Across All Providers"); native result blocks came in v1.86.0 (May 2026). — [LiteLLM docs](https://docs.litellm.ai/docs/integrations/websearch_interception), [ARCHITECTURE.md](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/ARCHITECTURE.md), [v1.81.0 notes](https://docs.litellm.ai/release_notes/v1.81.0/v1-81-0), [v1.86.0 notes](https://docs.litellm.ai/release_notes/v1.86.0/v1-86-0)
- Config keys:
  - `litellm_settings.callbacks: ["websearch_interception"]`
  - `websearch_interception_params`: `enabled_providers` (required), `search_tool_name`, `max_agentic_loops` (default 3)
  - `search_tools: [{search_tool_name, litellm_params:{search_provider, api_key}}]`

  Source: [LiteLLM docs](https://docs.litellm.ai/docs/integrations/websearch_interception)
- Detection:
  - Anthropic `type` starting with `web_search_` (any version)
  - Claude Code `name=="web_search"`
  - a bare `{name:"WebSearch"}` only when it has no `input_schema`, to avoid hijacking Cowork's real client tool
  - Responses `web_search`, `web_search_2025_08_26`, `web_search_preview`, `web_search_preview_2025_03_11`
  - Chat `{type:"web_search"}`

  The internal tool is named `litellm_web_search` ("Search the web for information. Use this when you need current information…"). It takes `query`, plus `objective`/`search_queries` for Parallel AI only. A forced `tool_choice` is rewritten to name it. — [tools.py](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/tools.py)
- The loop turns `stream=true` into a non-streaming call and rebuilds the SSE stream afterwards. Results go to the model as text: `Title: …\nURL: …\nSnippet: …`. — [ARCHITECTURE.md](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/ARCHITECTURE.md), [transformation.py](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/transformation.py)
- `/v1/messages` output, only when the client sent an Anthropic-native `web_search_*` tool:
  - a `server_tool_use` with id `f"srvtoolu_{uuid.uuid4().hex}"` and `input:{query}`
  - a `web_search_tool_result` whose results are `{url, title, page_age, encrypted_content: "", snippet}`; `snippet` is non-spec, and `encrypted_content` "stays empty rather than holding plaintext"
  - errors as `{"type":"web_search_tool_result_error","error_code":…}`
  - no `web_search_result_location` citations

  A comment warns that a result keyed by the model's `toolu_…` id "is rejected on replay ("String should match pattern '^srvtoolu_'")". — [handler.py](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/handler.py), [transformation.py L429-498](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/transformation.py#L429-L498)
- `/v1/responses` interception synthesizes no `web_search_call` items. `/chat/completions` returns plain tool messages ("OpenAI tool_result format has no equivalent of Anthropic's web_search_tool_result block"). — [handler.py](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/handler.py), [ARCHITECTURE.md](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/ARCHITECTURE.md)
- Claude Code short-circuit: `try_short_circuit_search` recognises Claude Code's side request (the user text starts with "Perform a web search for the query:"). For providers without native search it runs the search with no model call, returning `server_tool_use` + result block + a text block of raw results. — [handler.py L111, L352](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/integrations/websearch_interception/handler.py#L352)
- `web_search_options` mapping (since v1.71.0):
  - OpenAI: search models only
  - xAI: its Responses `web_search` tool
  - Anthropic: `web_search_20250305` with `max_uses` low=1/medium=5/high=10, plus `user_location`
  - Vertex/Gemini: Google Search
  - Perplexity: native

  The Responses→chat bridge maps `web_search`/`web_search_preview` to `web_search_options`. It rebuilds `web_search_call` items only from provider data (Anthropic `server_tool_use`, Gemini `groundingMetadata.webSearchQueries`). — [LiteLLM web search docs](https://docs.litellm.ai/docs/completion/web_search), [responses transformation](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/responses/litellm_completion_transformation/transformation.py)
- `/search` endpoint (v1.78.7+): `POST /v1/search/{search_tool_name}`, Perplexity-compatible.
  - Request: `query`, `max_results` 1–20, `search_domain_filter`, `max_tokens_per_page`, `country`
  - Response: `{object:"search", results:[{title,url,snippet,date?}]}`
  - Providers: `perplexity, tavily, parallel_ai, exa_ai, brave, google_pse, dataforseo, firecrawl, searxng, linkup, duckduckgo, searchapi, serper, you_com, …`

  Source: [LiteLLM search docs](https://docs.litellm.ai/docs/search/)
- Brave provider: GET `https://api.search.brave.com/res/v1/web/search`, header `X-Subscription-Token`, env `BRAVE_API_KEY`/`BRAVE_API_BASE`, `count` ≤ 20 ("Brave max is 20"). Added in PR #19433 (merged 2026-01-20). — [brave/search/transformation.py](https://github.com/BerriAI/litellm/blob/3e27fc2a88d2545a706fb9cc1a85ea99e474f18c/litellm/llms/brave/search/transformation.py), [PR #19433](https://github.com/BerriAI/litellm/pull/19433)
- Issues (open unless noted):
  - Claude Code shows "Did 0 searches" though searches ran: [#37577](https://github.com/BerriAI/litellm/issues/37577)
  - only the first of several searches reported, `usage.server_tool_use` missing: [#50691](https://github.com/BerriAI/litellm/issues/50691)
  - short-circuit searched the last user message instead of the model's query: [#31902](https://github.com/BerriAI/litellm/issues/31902); the "Perform a web search…" prefix leaked into the query: [#43456](https://github.com/BerriAI/litellm/issues/43456)
  - Claude Code v2.1.183's forced `tool_choice` gave Bedrock 400 "Tool 'web_search' not found": [#30822](https://github.com/BerriAI/litellm/issues/30822)
  - non-`srvtoolu_` ids gave multi-turn 400s: [#31569](https://github.com/BerriAI/litellm/issues/31569)
  - the internal `litellm_web_search` call leaked to the client: [#35334](https://github.com/BerriAI/litellm/issues/35334)
  - result blocks dropped when re-wrapping the stream: [#35333](https://github.com/BerriAI/litellm/issues/35333); `stream=true` crash: [#41411](https://github.com/BerriAI/litellm/issues/41411)
  - `allowed_domains`/`blocked_domains` dropped: [#44188](https://github.com/BerriAI/litellm/issues/44188); follow-up hardcodes `max_tokens` 1024: [#44834](https://github.com/BerriAI/litellm/issues/44834)
  - follow-up duplicated Claude Code's `context_management`/`output_config`: [#26163](https://github.com/BerriAI/litellm/issues/26163)
  - Codex-relevant: duplicate `prompt_cache_key` crash: [#38022](https://github.com/BerriAI/litellm/issues/38022); streaming `/v1/responses` 500: [#42770](https://github.com/BerriAI/litellm/issues/42770); `search_content_types` rejected by bedrock_mantle: [#43964](https://github.com/BerriAI/litellm/issues/43964)

**OpenRouter, no Brave**
- Legacy plugin: `plugins:[{"id":"web", engine, max_results (default 5), search_prompt, include_domains, exclude_domains, …}]`, and the `:online` slug suffix enables the same thing.
  - Engines: `native`, `exa`, `firecrawl`, `parallel`, `perplexity`. Default: native when the provider supports it, otherwise Exa. `native` never falls back.
  - It searches once before the model answers.
  - "The web search plugin … is deprecated"; "The `:online` variant is deprecated".

  Sources: [OpenRouter web search](https://openrouter.ai/docs/features/web-search), [Responses web search reference](https://openrouter.ai/docs/api/reference/responses/web-search.md), [agentic web tools announcement](https://openrouter.ai/blog/announcements/agentic-web-tools/)
- Server tool `{"type":"openrouter:web_search","parameters":{…}}` (beta, announced 2026-05-07):
  - parameters: `engine` (auto|native|exa|firecrawl|parallel|perplexity), `max_results` 1–25, `max_uses` (Anthropic native only), `search_context_size`, `user_location`, `allowed_domains`, `excluded_domains`, …
  - top-level `max_tool_calls` (≤30)
  - usage under `usage.server_tool_use_details.web_search_requests`
  - "Supported APIs: Chat Completions, Responses, and Anthropic Messages"

  Sources: [server tool docs](https://openrouter.ai/docs/guides/features/server-tools/web-search.md), [tool page](https://openrouter.ai/tool/web-search)
- Output:
  - Chat: `message.annotations[]` of `{type:"url_citation", url_citation:{url,title,content?,start_index,end_index}}`
  - Responses (beta): `web_search_call` items plus `url_citation` annotations, with `uncited: true` for consulted-but-uncited sources
  - Anthropic-format result blocks: not documented
- Pricing: Exa $0.007–$0.015/request, Parallel $0.001–$0.005, Perplexity $0.005, Firecrawl $0.005 + $0.0125/result; native is a pass-through.

  Sources: [OpenRouter web search](https://openrouter.ai/docs/features/web-search), [server tool docs](https://openrouter.ai/docs/guides/features/server-tools/web-search.md)
- Claude Code through OpenRouter's Anthropic endpoint is "Only guaranteed to work with the Anthropic first-party provider" — [Claude Code integration](https://openrouter.ai/docs/cookbook/coding-agents/claude-code-integration.md)

**claude-code-router (musistudio), Brave in v3**
- v1.x–v2.0.0:
  - `Router.webSearch` is chosen when `req.body.tools.some(tool => tool.type?.startsWith("web_search"))`. The README says it "requires the model itself to support the feature" (e.g. an OpenRouter `:online` model or Gemini).
  - The Gemini transformer maps a function named `web_search` to `{googleSearch:{}}`. The Anthropic transformer converts the resulting `url_citation` annotations back into `server_tool_use` (with `input:{query:""}`) and `web_search_tool_result` blocks; when streaming it emits one result block per annotation, with fresh ids and no paired `server_tool_use`.

  Sources: [router.ts@v2.0.0](https://github.com/musistudio/claude-code-router/blob/v2.0.0/packages/core/src/utils/router.ts), [anthropic.transformer.ts@v2.0.0](https://github.com/musistudio/claude-code-router/blob/v2.0.0/packages/core/src/transformer/anthropic.transformer.ts)
- v2 issues:
  - "Tool names must be unique" with `:online` models, shown as "Did 0 searches": [#1066](https://github.com/musistudio/claude-code-router/issues/1066)
  - search count not shown: [#345](https://github.com/musistudio/claude-code-router/issues/345)
  - `web_search_20250305` turned into a function with undefined parameters: [#1419](https://github.com/musistudio/claude-code-router/issues/1419)
- v3 (3.0.0 on 2026-06-25; 3.1.6 on 2026-11-21) adds a hosted-web-search bridge.
  - Detection: `normalized === "web_search" || normalized === "web_search_20250305"`, matched exactly, so `web_search_20260209`/`20260318` are missed. Also OpenAI `web_search`/`web_search_preview*`/`web_search_options` and Gemini `googleSearch`.
  - It pre-searches, taking the query from user text and stripping "Perform a web search for the query:".
  - It injects "A hidden in-app browser web search has already been performed for this request." and strips the hosted tool and `tool_choice`.
  - It synthesizes Anthropic `server_tool_use` + `web_search_tool_result` (`encrypted_content:""`, `snippet`) or Responses `web_search_call` `{action:{type:"search",query}, status:"completed"}` with `annotations: []`.
  - Brave backend: `searchEnv(input, "BRAVE_SEARCH_ENDPOINT") || "https://api.search.brave.com/res/v1/web/search"`.

  Sources: [discovery.ts L101, L547](https://github.com/musistudio/claude-code-router/blob/6b6ca0cbc47398fb95d55cf01cc5734d45da1130/packages/core/src/gateway/features/hosted-web-search/discovery.ts#L547), [request-transform.ts L359](https://github.com/musistudio/claude-code-router/blob/6b6ca0cbc47398fb95d55cf01cc5734d45da1130/packages/core/src/gateway/features/hosted-web-search/request-transform.ts#L359), [fusion web search docs](https://github.com/musistudio/claude-code-router/blob/6b6ca0cbc47398fb95d55cf01cc5734d45da1130/docs/src/content/docs/en/configuration/fusion-web-search.md)

**Portkey, no Brave, no hosted-tool emulation**
- `web_search_options` is passed through to OpenAI, Azure OpenAI, Azure AI Inference and Perplexity. A `google_search` function becomes `{googleSearch:{…}}` on Vertex/Gemini. — [Portkey gateway](https://github.com/Portkey-AI/gateway)
- The open-source Exa plugin "Online Search" (`beforeRequestHook`) calls `https://api.exa.ai/search` (`numResults` default 5, include/exclude domains) and inserts results into the system message inside `<web_search_context>`. A Tavily "Online Search" guardrail does the same. — [plugins/exa/online.ts](https://github.com/Portkey-AI/gateway/blob/main/plugins/exa/online.ts), [Tavily plugin docs](https://portkey.ai/docs/aigw/integrations/plugins/tavily.md)

**Ollama, search engine undisclosed**
- Web search and fetch API, announced 2025-09-24:
  - `POST https://ollama.com/api/web_search` with `{query, max_results (default 5, max 10)}` returns `{results:[{title,url,content}]}`
  - `POST https://ollama.com/api/web_fetch` with `{url}` returns `{title, content, links}`
  - auth `Authorization: Bearer $OLLAMA_API_KEY`
  - no published quota

  Sources: [Ollama blog](https://ollama.com/blog/web-search), [web search docs](https://docs.ollama.com/capabilities/web-search)
- `/v1/messages` emulation:
  - any `web_search*` tool becomes a function `web_search`, and a user tool with the same name is dropped
  - the loop runs up to `min(10, max_uses)` times
  - each search emits `server_tool_use` (id `"srvtoolu_" + strings.TrimPrefix(messageID, "msg_")`, suffixed per search) and `web_search_tool_result` with `{type,url,title}` only (no `encrypted_content`)
  - at the cap it emits `web_search_tool_result_error`/`max_uses_exceeded`
  - it also uses non-spec codes `invalid_request` and `api_error`, plus `unavailable`
  - `citations` are never populated

  Local models allowed since PR #14787 (2026-03-11). Domain filters are an open PR, [#17312](https://github.com/ollama/ollama/pull/17312). — [middleware/anthropic.go](https://github.com/ollama/ollama/blob/318ee284aa3b5558de57efefff730ea33c4a9bef/middleware/anthropic.go), [PR #14787](https://github.com/ollama/ollama/pull/14787)
- `/v1/responses` emulation (PR #17686, merged 2026-08-12). It handles exact `web_search` only; `web_search_preview` passes through. The stream sequence, verified in code:
  1. `response.output_item.added` with `{"id","type":"web_search_call","status":"in_progress","action":{"type":"search","query"}}`
  2. `response.web_search_call.in_progress`
  3. `response.web_search_call.searching`
  4. the search runs
  5. `response.web_search_call.completed`
  6. `response.output_item.done` with the item

  On failure the item gets `status:"failed"`. `annotations` is always `[]` ("does not synthesize OpenAI citation annotations"). Replayed `web_search_call` input items are ignored. The loop cap went from 3 to 10 in PR #18602 (2026-09-28). At the cap it removes the tool and appends "The web search limit for this response has been reached…" (PR #18328). — [openai/responses.go L1890-1971](https://github.com/ollama/ollama/blob/318ee284aa3b5558de57efefff730ea33c4a9bef/openai/responses.go#L1890-L1971), [PR #17686](https://github.com/ollama/ollama/pull/17686)
- Docs:
  - Codex: "Codex web-search requests sent through the Ollama profile are executed by Ollama for both local and cloud models"; disable with `-c 'web_search="disabled"'` ([Codex integration](https://docs.ollama.com/integrations/codex))
  - Claude Code: "Hosted WebSearch and advanced tool controls are not fully supported" ([Claude Code integration](https://docs.ollama.com/integrations/claude-code))
  - `tool_choice` and `citations` are listed as unsupported in Anthropic compatibility ([compatibility](https://docs.ollama.com/api/anthropic-compatibility))

**Open Responses specification, no Brave**
- Current spec 2026-04-24: "Model providers may emit their own types of items not contained in the Open Responses spec. These items MUST be prefixed with the canonical provider slug, eg `openai:web_search_call`."
  - New item types and streaming events "MUST be prefixed with the implementor slug (for example, `acme:search_result`)".
  - A hosted tool's item should allow it to "be round-tripped back to the API for lossless rehydration on a followup request".

  Source: [spec 2026-04-24.mdx L344, L715-764](https://github.com/openresponses/openresponses/blob/dce9ddb91921427c2ba06901c7dfaf0cc7056799/src/specifications/2026-04-24.mdx)
- The standard tool param union has only function tools, so no standard `web_search` exists. `url_citation` (`type,url,start_index,end_index,title`) is standard. Issue #5, "allow custom internally hosted tools", is open. No rule says what to do with an unsupported hosted tool. — [schema/tools.tsp](https://github.com/openresponses/openresponses/blob/dce9ddb91921427c2ba06901c7dfaf0cc7056799/schema/tools.tsp), [schema/content.tsp](https://github.com/openresponses/openresponses/blob/dce9ddb91921427c2ba06901c7dfaf0cc7056799/schema/content.tsp), [issue #5](https://github.com/openresponses/openresponses/issues/5)

**Pi and PiG, Brave via extensions**
- `badlogic/pi-mono` now resolves to `earendil-works/pi`. Built-in tools are `read, write, edit, bash, grep, find, ls` (+ `powershell`); there is no web search. — [pi tools dir](https://github.com/badlogic/pi-mono/tree/d91ac96a49753003fc8987efb03eb462931ea65a/packages/coding-agent/src/core/tools)
- Official skill `brave-search`: `search.js` calls `https://api.search.brave.com/res/v1/web/search` (`X-Subscription-Token`, `BRAVE_API_KEY`; `-n` ≤ 20, `--freshness`, `--country`), and `content.js` fetches a URL as markdown — [pi-skills/brave-search](https://github.com/badlogic/pi-skills/tree/main/brave-search)
- `pi-web-access` (v0.48.0) provides tools `web_search`, `fetch_content`, `get_search_content`, `source_check`.
  - Providers include `brave`, `exa`, `tavily`, `openai` and `ollama`.
  - Brave calls go through a queue honoring `X-RateLimit-*`, retrying once on 429 after `Retry-After`.
  - Its `openai` provider uses Responses-hosted `web_search` and rejects a response without a `web_search_call` ("an ordinary model-only response is rejected").

  Source: [pi-web-access](https://github.com/nicobailon/pi-web-access)
- PiG is "the Go port of upstream `pi`", checked against Pi 1.5.0 with parity scenarios. It has no built-in search; its docs show an extension `web-access` contributing `tools: [web_search, web_fetch]`. — [PiG AGENTS.md / README](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/AGENTS.md), [piglets.md L55-75](https://github.com/MichaelKinsy/PiG/blob/40b509fbdf108c21ad95ce0d8e0108586dc8c5ae/docs/site/docs/piglets.md)

**OpenCode (sst/opencode → anomalyco/opencode), no Brave**
- v1 `websearch`:
  - calls Exa's hosted MCP `https://mcp.exa.ai/mcp` (`web_search_exa`, no key)
  - parameters `query`, `numResults` (8), `livecrawl`, `type`, `contextMaxCharacters`
  - gated to `providerID === "opencode" || OPENCODE_ENABLE_EXA`

  Source: [websearch.ts@v1.1.49](https://github.com/anomalyco/opencode/blob/v1.1.49/packages/opencode/src/tool/websearch.ts)
- v2 `websearch`:
  - takes only `query` and returns `[{url,title,published,content}]`
  - providers `exa`, `firecrawl`, `parallel`, `tavily`, `tinyfish`, `claude-agent` and `random`, with 429 cooldowns
  - `claude-agent` exists because "WebSearch returns page contents encrypted, so a Claude model has to run each search. Haiku runs it"

  Sources: [websearch.mdx](https://github.com/anomalyco/opencode/blob/0089ba9e39a9ff7701b83fa87d62964612b61a66/services/site/src/docs/content/websearch.mdx), [plugin/websearch/exa.ts](https://github.com/anomalyco/opencode/blob/0089ba9e39a9ff7701b83fa87d62964612b61a66/packages/core/src/plugin/websearch/exa.ts)
- Issues:
  - never exposed to custom or local providers: [#44307](https://github.com/anomalyco/opencode/issues/44307)
  - Exa 402 Payment Required: [#11980](https://github.com/anomalyco/opencode/issues/11980)
  - `random` sticks to a failing provider: [#54311](https://github.com/anomalyco/opencode/issues/54311)
  - a volatile date in the tool description busted the cache: [#13559](https://github.com/anomalyco/opencode/pull/13559)

**Gemini CLI, no Brave**
- Tool `google_web_search(query)`. It runs a separate `generateContent` on the alias `web-search` (`gemini-3-flash-preview` with `tools:[{googleSearch:{}}]`). The main model receives `Web search results for "<query>":\n\n` + the wrapped (untrusted) answer with `[n]` markers + `\n\nSources:\n[1] Title (uri)`. — [defaultModelConfigs.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/config/defaultModelConfigs.ts), [web-search.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/tools/web-search.ts), [docs](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/web-search.md)
- Search fails when the hard-coded sub-model is unavailable, regardless of the main model: [#20952](https://github.com/google-gemini/gemini-cli/issues/20952). It loops on no results: [#28037](https://github.com/google-gemini/gemini-cli/issues/28037). Qwen Code (a fork) moved to DashScope server-side `web_search` or MCP. — [Qwen Code docs](https://qwenlm.github.io/qwen-code-docs/en/developers/tools/web-search/)

**Aider, no Brave**
- No web search; feature request [#2754](https://github.com/Aider-AI/aider/issues/2754) is open. `/web <url>` "Scrape[s] a webpage, convert[s] to markdown", using Playwright or httpx with pypandoc. Last release v0.86.0 (2025-08-09). — [commands.py](https://github.com/Aider-AI/aider/blob/main/aider/commands.py), [scrape.py](https://github.com/Aider-AI/aider/blob/main/aider/scrape.py)

**Other Brave users**
- `@brave/brave-search-mcp-server` 2.x exposes `brave_web_search`, `brave_local_search`, `brave_image_search`, `brave_news_search`, `brave_video_search`, `brave_answers`, `brave_llm_context` (`/res/v1/llm/context`, pre-extracted grounding content, `maximum_number_of_tokens` 1024–32768) and others — [brave-search-mcp-server](https://github.com/brave/brave-search-mcp-server)
- Goose and Zed integrate Brave through MCP — [Goose Brave tutorial](https://block.github.io/goose/docs/mcp/brave-mcp), [Zed extension](https://zed.dev/extensions/mcp-server-brave-search)
- OpenClaw's `web_search` auto-detection tries Brave first. It wraps results as `externalContent {untrusted:true}`, and it keeps the native Claude Code `WebSearch` / Codex hosted `web_search` unless a provider is pinned. — [OpenClaw web tools](https://docs.openclaw.ai/tools/web)

### Inferences
- Use Ollama's Responses code as the template for Codex: the `added` → `in_progress` → `searching` → `completed` → `done` sequence, `status:"failed"` on error, and keeping pre-search text as its own message item. Go beyond it in two places:
  - emit `url_citation` annotations (Ollama sends `[]`)
  - re-materialize replayed `web_search_call` items (Ollama ignores them)
- For Claude Code, the pitfalls the precedents hit translate into these requirements:
  - pair each `server_tool_use` with its result and use `srvtoolu_`-prefixed ids
  - one pair per search, so the "Did N searches" count is right (Claude Code's binary computes `searchCount = max(#server_tool_use, #web_search_tool_result)`; see section 3)
  - take the query from the model's tool input, not from the "Perform a web search for the query:" text
  - honor `allowed_domains`/`blocked_domains`; how to express these in a Brave query was not researched here
  - never forward synthesized blocks to the real Anthropic API
- Match hosted tool types by prefix (`web_search_`) rather than exact version; CCR v3 misses `web_search_20260209`/`20260318`.
- Pick a distinctive internal function name (LiteLLM uses `litellm_web_search`) so it cannot collide with a user tool. Ollama drops a user tool also named `web_search`.
- Brave's `X-RateLimit-*` headers and 429 `Retry-After` should drive backoff (pi-web-access does this). On exhaustion, return the hosted error code (`too_many_requests`) rather than failing the turn.

### Gaps
- Cline, Roo, Kilo, Crush, Continue and Zed's built-in search were not checked (GitHub code-search rate limit).
- OpenRouter does not document what its Anthropic-Messages endpoint returns for `openrouter:web_search`, or whether it translates client-sent `web_search_2025…` tools for non-Anthropic models.
- Ollama does not disclose its search engine or quotas.
- The Portkey Tavily guardrail being hosted-only is inferred from its absence in the open-source repo.

## 5. Chat Completions conventions for web search

### Takeaway
Chat Completions web search is a request parameter (`web_search_options`) for dedicated search models, not a tool. Results come back as `message.annotations[]` of type `url_citation`, with the fields nested under `url_citation` (unlike the flat Responses annotation). Neither Codex (Responses-only wire API) nor Claude Code (Messages) uses it; see section 4 for gateways that map it.

### Cited Findings
- `web_search_options` is `{search_context_size?: "low"|"medium"|"high", user_location?: {type: "approximate" (required), approximate: {city?, country?, region?, timezone?} (required)}}`. Note the extra `approximate` nesting compared with Responses. — [openai-python `chat/completion_create_params.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/chat/completion_create_params.py)
- The response annotation is `{"type":"url_citation","url_citation":{"start_index","end_index","url","title"}}`, under `choices[].message.annotations` — [openai-python `chat/chat_completion_message.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/chat/chat_completion_message.py)
- The only Chat Completions search model is `gpt-5-search-api` (200k context). It does not support "domain filters, complete source lists, live-access control, and returned-token budget control". `gpt-4o-search-preview` and `gpt-4o-mini-search-preview` "shut down on 2026-07-23". "Chat Completions search models always search before responding; Responses search is a tool." — [OpenAI web search guide](https://developers.openai.com/api/docs/guides/tools-web-search.md)
- Codex's `WireApi` has only `Responses`, and the codex-rs tree contains no `web_search_options` — [codex `model-provider-info/src/lib.rs` L119-123](https://github.com/openai/codex/blob/a52fdb3ba61dea9f0e62196bcf00157d7b9ab0fb/codex-rs/model-provider-info/src/lib.rs#L119-L123)

### Inferences
- A gateway's Chat Completions surface can treat `web_search_options` as "always search first". It would run Brave on the last user message and inject the results. It would then return `message.annotations` in the nested shape, and in streaming put `annotations` on the delta. The streaming placement is the usual convention but was not confirmed here.
- Harness reliance is mainly indirect, through gateways such as OpenRouter and LiteLLM (section 4).

### Gaps
- The streaming delta placement of Chat Completions `annotations` was not confirmed from a primary source. openai-python 3.57.0's streaming chunk type (`chat_completion_chunk.py`, `ChoiceDelta`) has no `annotations` field at all ([openai-python `chat_completion_chunk.py`](https://github.com/openai/openai-python/blob/f63f14b34754fa77fc839ac2cf95da3ef42e1f6a/src/openai/types/chat/chat_completion_chunk.py)), so streamed annotations, where providers send them, are untyped.
