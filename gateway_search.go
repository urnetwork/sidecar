//go:build !ios_extension && !sidecar_http

// The gateway serves no hosted web search (DESIGN-COMPUTE §21.7 and §8.5's hosted web search; R-SRCH-5, D-SRCH-5,
// CO-26). Serving a harness's own search tool behind the gateway would make Parallel's Services available inside
// another vendor's tool, which Parallel's §2(c)(iv) bars, so external harnesses search through URnetwork's own MCP
// web_search (Q-SRCH-7, QD-1362) and the gateway drops or refuses theirs. These are functions over a request's raw
// JSON that GW's fronts call before routing, so no GW type is needed and nothing is ever served:
//
//   - Responses: every tool whose type starts with web_search (web_search, web_search_preview, web_search_2025_08_26
//     and any later suffix: §21.7's matching, so a new version needs no release) is dropped and the call goes on with
//     the rest; a tool_choice naming a dropped tool becomes auto, and include entries under web_search_call. go,
//     since the upstream would answer them with a schema error.
//   - Chat Completions: web_search_options is dropped, since only OpenAI's search models read it and the catalog holds
//     none. A tool whose type starts with web_search, which the API does not define, goes as in Responses.
//   - Messages: a request whose tools are all web_search_* server tools, Claude Code's WebSearch side request, is
//     answered at once with an assistant message of two blocks, a server_tool_use named web_search and a
//     web_search_tool_result naming it whose content is the error unavailable, as JSON or as the API's events: no
//     model call, so no hold, no charge and no model_call, and nothing asked of the router or the ledger. A
//     web_search_* server tool among other tools is dropped as in Responses, the plan's reading of §21.15's "dropped
//     or refused, never served", since §21.7 names only the one-tool side request.
//
// Codex's experimental standalone search (/alpha/search, supports_standalone_web_search) is not served either: GW's
// mux mounts no such route. The network's search.enabled changes nothing here, hosted search being refused either way
// (§21.7's policy off).
//
// A tool is matched by its type, never its name, so URnetwork's own MCP tool, which Codex and Claude Code name
// mcp__ur__web_search, and a function named web_search pass untouched, and every tool kept keeps its bytes, since
// harnesses send fields the gateway does not know (§8.5's unknown fields). A key is matched unescaped and without
// regard to case, underscores or dashes, wider than encoding/json or its v2 matches a struct's field, and every member
// a decoder might take is filtered, so no spelling or repetition of a key carries a hosted tool past this to a front's
// decoder, whichever decoder a front uses. A body that is not a JSON object, or whose tools are not objects with
// string types, is refused with ErrGatewayHostedSearchMalformed, which a front answers 400 in its API's words.
//
// Each request whose hosted search went counts into GatewayHostedSearchNotice by harness, which `ur status` and
// `ur gateway status` show as a warning: a harness that still sends hosted search has its own search on, which the
// settings `ur install-harness <h> --gateway` writes turn off (§8.8).

package sidecar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// The identifiers this file reads and writes: the APIs' keys, hosted search's types and include entries, and the
// Messages API's block types, error code, stop reason, events and id forms.
const (
	// what every hosted search tool's type starts with, in Responses (web_search, web_search_preview,
	// web_search_2025_08_26) and in Messages (web_search_20250305, web_search_20260318)
	gatewayHostedSearchToolTypePrefix = "web_search"
	// what Responses' include entries asking for a hosted search's results start with
	gatewayHostedSearchIncludePrefix = "web_search_call."

	gatewayHostedSearchKeyTools        = "tools"
	gatewayHostedSearchKeyToolChoice   = "tool_choice"
	gatewayHostedSearchKeyInclude      = "include"
	gatewayHostedSearchKeyChatOptions  = "web_search_options"
	gatewayHostedSearchKeyType         = "type"
	gatewayHostedSearchKeyName         = "name"
	gatewayHostedSearchKeyFunction     = "function"
	gatewayHostedSearchKeyAllowedTools = "allowed_tools"
	gatewayHostedSearchKeyModel        = "model"
	gatewayHostedSearchKeyStream       = "stream"
	gatewayHostedSearchKeyNoParallel   = "disable_parallel_tool_use"

	// tool_choice's types and values that name no tool but need one
	gatewayHostedSearchChoiceAllowedTools = "allowed_tools"
	gatewayHostedSearchChoiceRequired     = "required"
	gatewayHostedSearchChoiceAny          = "any"
	gatewayHostedSearchChoiceAuto         = "auto"

	// the Messages API's answer
	gatewayHostedSearchMessageType         = "message"
	gatewayHostedSearchMessageRole         = "assistant"
	gatewayHostedSearchServerToolUseType   = "server_tool_use"
	gatewayHostedSearchServerToolName      = "web_search"
	gatewayHostedSearchToolResultType      = "web_search_tool_result"
	gatewayHostedSearchToolResultErrorType = "web_search_tool_result_error"
	gatewayHostedSearchErrorUnavailable    = "unavailable"
	gatewayHostedSearchStopReasonEndTurn   = "end_turn"
	gatewayHostedSearchMessageIdPrefix     = "msg_01"
	gatewayHostedSearchServerToolIdPrefix  = "srvtoolu_01"
	gatewayHostedSearchIdAlphabet          = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	gatewayHostedSearchEventMessageStart      = "message_start"
	gatewayHostedSearchEventContentBlockStart = "content_block_start"
	gatewayHostedSearchEventContentBlockStop  = "content_block_stop"
	gatewayHostedSearchEventMessageDelta      = "message_delta"
	gatewayHostedSearchEventMessageStop       = "message_stop"

	gatewayHostedSearchContentTypeJson = "application/json"
	gatewayHostedSearchContentTypeSse  = "text/event-stream"
)

// A request this file cannot read as its API's: not one JSON object, or with tools, a tool_choice or a stream it
// cannot tell hosted search in. Wrapped with what was wrong; a front answers it 400 in its API's words, and the
// request goes nowhere.
var ErrGatewayHostedSearchMalformed = errors.New("gateway hosted search: malformed request")

// The API a request came through, as the notice names it.
type GatewayHostedSearchApi string

const (
	GatewayHostedSearchApiResponses       GatewayHostedSearchApi = "responses"
	GatewayHostedSearchApiChatCompletions GatewayHostedSearchApi = "chat_completions"
	GatewayHostedSearchApiMessages        GatewayHostedSearchApi = "messages"
)

// The bounds of the hosted search refusal (§21.7), which GatewaySettings carries as HostedSearch.
type GatewayHostedSearchSettings struct {
	// How many of the latest refusals the notice's ring keeps, each with its time, harness, API and what went, for
	// `ur gateway status`: 32, a screen of them. An older one leaves the ring and stays counted in its harness's totals.
	// Non-positive keeps none.
	NoticeRingCount int
	// How many harnesses the notice counts by name: 16, more than ur installs the gateway for. Refusals from harnesses
	// past it count together under no name. Non-positive counts every harness together.
	NoticeHarnessCount int
	// How many of one refusal's items, a tool's type, an include entry or web_search_options, its ring entry names, the
	// rest only counted: 8, so a body of many hosted tools holds no more of the ring than any other. Non-positive names
	// none.
	NoticeItemCount int
	// The most bytes of an item's name a ring entry keeps, a longer one cut at a character's end and marked: 64, past
	// every type the APIs define. Non-positive keeps names whole.
	NoticeItemByteCount int
	// The random characters of an id made up for the answer to WebSearch's side request, after the Messages API's
	// msg_01 or srvtoolu_01: 22, the length the API's own ids have there. Each is one of 62, so 22 hold some 131 bits.
	// Non-positive makes an id of the prefix alone.
	IdRandomCharCount int
}

// The design's values (§21.7, §8.5).
func DefaultGatewayHostedSearchSettings() *GatewayHostedSearchSettings {
	return &GatewayHostedSearchSettings{
		NoticeRingCount:     32,
		NoticeHarnessCount:  16,
		NoticeItemCount:     8,
		NoticeItemByteCount: 64,
		IdRandomCharCount:   22,
	}
}

// What NewGatewayHostedSearch takes.
type GatewayHostedSearchArgs struct {
	// Nil is DefaultGatewayHostedSearchSettings.
	Settings *GatewayHostedSearchSettings
	// What the notice's times read. Nil is real time.
	Clock Clock
	// What the made-up answer's ids are drawn from. Nil is crypto/rand's reader. It is read from the fronts' goroutines
	// at once, so it must be safe for concurrent use, as crypto/rand's is.
	Random io.Reader
}

// The hosted search filter GW's fronts call before routing, with its notice. Safe for concurrent use.
type GatewayHostedSearch struct {
	settings *GatewayHostedSearchSettings
	random   io.Reader
	notice   *GatewayHostedSearchNotice
}

// A filter over args, with an empty notice. Nil args take every default.
func NewGatewayHostedSearch(args *GatewayHostedSearchArgs) *GatewayHostedSearch {
	if args == nil {
		args = &GatewayHostedSearchArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultGatewayHostedSearchSettings()
	}
	random := args.Random
	if random == nil {
		random = rand.Reader
	}
	return &GatewayHostedSearch{
		settings: settings,
		random:   random,
		notice:   newGatewayHostedSearchNotice(settings, clockOrReal(args.Clock)),
	}
}

// The refusals so far, by harness.
func (self *GatewayHostedSearch) Notice() *GatewayHostedSearchNotice {
	return self.notice
}

// A Responses request's body without hosted search, for the front to route: every tool whose type starts with
// web_search dropped, a tool_choice naming one auto, and include's web_search_call. entries gone. The body itself,
// the same bytes, where it asked for none. harness is the grant's, for the notice.
func (self *GatewayHostedSearch) FilterResponses(harness string, body []byte) ([]byte, error) {
	edit, err := newGatewayHostedSearchEdit(body)
	if err != nil {
		return nil, err
	}
	tools, err := edit.readTools()
	if err != nil {
		return nil, err
	}
	edit.dropTools(tools)
	if err := edit.chooseAuto(tools, []byte(`"`+gatewayHostedSearchChoiceAuto+`"`)); err != nil {
		return nil, err
	}
	if err := edit.dropIncludes(); err != nil {
		return nil, err
	}
	return self.route(harness, GatewayHostedSearchApiResponses, edit), nil
}

// A Chat Completions request's body without hosted search, for the front to route: web_search_options gone, and a
// tool whose type starts with web_search dropped as FilterResponses drops one. The body itself where it asked for none.
func (self *GatewayHostedSearch) FilterChatCompletions(harness string, body []byte) ([]byte, error) {
	edit, err := newGatewayHostedSearchEdit(body)
	if err != nil {
		return nil, err
	}
	edit.dropChatOptions()
	tools, err := edit.readTools()
	if err != nil {
		return nil, err
	}
	edit.dropTools(tools)
	if err := edit.chooseAuto(tools, []byte(`"`+gatewayHostedSearchChoiceAuto+`"`)); err != nil {
		return nil, err
	}
	return self.route(harness, GatewayHostedSearchApiChatCompletions, edit), nil
}

// A Messages request's answer, or its body for the front to route; never both. WebSearch's side request, whose tools
// are all web_search_* server tools, gets the answer, which the front writes as it is in place of a model call. Any
// other request gets its body, without the web_search_* server tools it held among others and with a tool_choice
// naming one made auto, or the body itself where it held none.
func (self *GatewayHostedSearch) AnswerMessages(harness string, body []byte) (*GatewayHostedSearchAnswer, []byte, error) {
	edit, err := newGatewayHostedSearchEdit(body)
	if err != nil {
		return nil, nil, err
	}
	tools, err := edit.readTools()
	if err != nil {
		return nil, nil, err
	}
	if 0 < len(tools.tools) && tools.keptCount() == 0 {
		answer, err := self.answerMessages(edit)
		if err != nil {
			return nil, nil, err
		}
		items := []string{}
		for _, tool := range tools.tools {
			items = append(items, tool.hostedType)
		}
		self.notice.record(harness, GatewayHostedSearchApiMessages, true, items)
		return answer, nil, nil
	}
	edit.dropTools(tools)
	if err := edit.chooseAuto(tools, []byte(`{"type":"`+gatewayHostedSearchChoiceAuto+`"}`)); err != nil {
		return nil, nil, err
	}
	return nil, self.route(harness, GatewayHostedSearchApiMessages, edit), nil
}

// The body to route after edit: the request's own bytes where nothing changed, else the edit's, counted in the notice
// where something of hosted search went. A web_search_options of null, left out though it names no search, is no
// refusal.
func (self *GatewayHostedSearch) route(harness string, api GatewayHostedSearchApi, edit *gatewayHostedSearchEdit) []byte {
	if !edit.changed() {
		return edit.body
	}
	if 0 < len(edit.items) {
		self.notice.record(harness, api, false, edit.items)
	}
	return edit.bytes()
}

// What the gateway writes for WebSearch's side request in place of a model call: the Messages API's answer, whole, as
// JSON or as its events. Made from the request's model and fresh ids alone; it holds zero usage, so nothing is held or
// charged for it.
type GatewayHostedSearchAnswer struct {
	// Whether the request streams, so that the front writes Events rather than Json.
	Stream bool
	// The message, as the API answers a request that does not stream.
	Json []byte
	// The API's events for the same message, in order: message_start, content_block_start and content_block_stop for
	// each block, message_delta and message_stop.
	Events []*GatewayHostedSearchSseEvent
}

// One server-sent event of the API's stream.
type GatewayHostedSearchSseEvent struct {
	// The event's name, as its data's type names it.
	Name string
	// Its data: one line of JSON.
	Data []byte
}

// The answer's Content-Type, by whether it streams.
func (self *GatewayHostedSearchAnswer) ContentType() string {
	if self.Stream {
		return gatewayHostedSearchContentTypeSse
	}
	return gatewayHostedSearchContentTypeJson
}

// The answer's HTTP body: Json, or Events in the server-sent events' framing, each an event line, a data line and a
// blank line.
func (self *GatewayHostedSearchAnswer) Bytes() []byte {
	if !self.Stream {
		return self.Json
	}
	out := []byte{}
	for _, event := range self.Events {
		out = append(out, "event: "...)
		out = append(out, event.Name...)
		out = append(out, "\ndata: "...)
		out = append(out, event.Data...)
		out = append(out, "\n\n"...)
	}
	return out
}

// The Messages API's usage, every count zero: no model ran and no search was made.
type gatewayHostedSearchUsage struct {
	InputTokens              int                             `json:"input_tokens"`
	CacheCreationInputTokens int                             `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int                             `json:"cache_read_input_tokens"`
	OutputTokens             int                             `json:"output_tokens"`
	ServerToolUse            *gatewayHostedSearchServerUsage `json:"server_tool_use"`
}

type gatewayHostedSearchServerUsage struct {
	WebSearchRequests int `json:"web_search_requests"`
}

// The server_tool_use block. Its input is empty, since no model wrote a query.
type gatewayHostedSearchServerToolUse struct {
	Type  string          `json:"type"`
	Id    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// The web_search_tool_result block, its content the error object.
type gatewayHostedSearchToolResult struct {
	Type      string                              `json:"type"`
	ToolUseId string                              `json:"tool_use_id"`
	Content   *gatewayHostedSearchToolResultError `json:"content"`
}

type gatewayHostedSearchToolResultError struct {
	Type      string `json:"type"`
	ErrorCode string `json:"error_code"`
}

// The message, in the API's field order. Content and the stop reason are empty and null in message_start's copy.
type gatewayHostedSearchMessage struct {
	Id           string                    `json:"id"`
	Type         string                    `json:"type"`
	Role         string                    `json:"role"`
	Model        string                    `json:"model"`
	Content      []any                     `json:"content"`
	StopReason   *string                   `json:"stop_reason"`
	StopSequence *string                   `json:"stop_sequence"`
	Usage        *gatewayHostedSearchUsage `json:"usage"`
}

type gatewayHostedSearchMessageStart struct {
	Type    string                      `json:"type"`
	Message *gatewayHostedSearchMessage `json:"message"`
}

type gatewayHostedSearchBlockStart struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock any    `json:"content_block"`
}

type gatewayHostedSearchBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type gatewayHostedSearchMessageDelta struct {
	Type  string                         `json:"type"`
	Delta *gatewayHostedSearchStopReason `json:"delta"`
	Usage *gatewayHostedSearchUsage      `json:"usage"`
}

type gatewayHostedSearchStopReason struct {
	StopReason   *string `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

type gatewayHostedSearchMessageStop struct {
	Type string `json:"type"`
}

// The answer to WebSearch's side request in edit: its model and stream read from the body, the message id drawn
// first and the server_tool_use's second.
func (self *GatewayHostedSearch) answerMessages(edit *gatewayHostedSearchEdit) (*GatewayHostedSearchAnswer, error) {
	model, err := edit.onlyString(gatewayHostedSearchKeyModel)
	if err != nil {
		return nil, err
	}
	stream, err := edit.onlyBool(gatewayHostedSearchKeyStream)
	if err != nil {
		return nil, err
	}
	messageId, err := self.drawId(gatewayHostedSearchMessageIdPrefix)
	if err != nil {
		return nil, err
	}
	toolUseId, err := self.drawId(gatewayHostedSearchServerToolIdPrefix)
	if err != nil {
		return nil, err
	}

	usage := func() *gatewayHostedSearchUsage {
		return &gatewayHostedSearchUsage{ServerToolUse: &gatewayHostedSearchServerUsage{}}
	}
	stopReason := gatewayHostedSearchStopReasonEndTurn
	blocks := []any{
		&gatewayHostedSearchServerToolUse{
			Type:  gatewayHostedSearchServerToolUseType,
			Id:    toolUseId,
			Name:  gatewayHostedSearchServerToolName,
			Input: json.RawMessage(`{}`),
		},
		&gatewayHostedSearchToolResult{
			Type:      gatewayHostedSearchToolResultType,
			ToolUseId: toolUseId,
			Content: &gatewayHostedSearchToolResultError{
				Type:      gatewayHostedSearchToolResultErrorType,
				ErrorCode: gatewayHostedSearchErrorUnavailable,
			},
		},
	}
	message := func(content []any, stopReason *string) *gatewayHostedSearchMessage {
		return &gatewayHostedSearchMessage{
			Id:         messageId,
			Type:       gatewayHostedSearchMessageType,
			Role:       gatewayHostedSearchMessageRole,
			Model:      model,
			Content:    content,
			StopReason: stopReason,
			Usage:      usage(),
		}
	}

	answer := &GatewayHostedSearchAnswer{Stream: stream}
	if answer.Json, err = gatewayHostedSearchMarshal(message(blocks, &stopReason)); err != nil {
		return nil, err
	}
	event := func(name string, data any) error {
		encoded, err := gatewayHostedSearchMarshal(data)
		if err != nil {
			return err
		}
		answer.Events = append(answer.Events, &GatewayHostedSearchSseEvent{Name: name, Data: encoded})
		return nil
	}
	start := &gatewayHostedSearchMessageStart{Type: gatewayHostedSearchEventMessageStart, Message: message([]any{}, nil)}
	if err := event(gatewayHostedSearchEventMessageStart, start); err != nil {
		return nil, err
	}
	for index, block := range blocks {
		blockStart := &gatewayHostedSearchBlockStart{Type: gatewayHostedSearchEventContentBlockStart, Index: index, ContentBlock: block}
		if err := event(gatewayHostedSearchEventContentBlockStart, blockStart); err != nil {
			return nil, err
		}
		blockStop := &gatewayHostedSearchBlockStop{Type: gatewayHostedSearchEventContentBlockStop, Index: index}
		if err := event(gatewayHostedSearchEventContentBlockStop, blockStop); err != nil {
			return nil, err
		}
	}
	delta := &gatewayHostedSearchMessageDelta{
		Type:  gatewayHostedSearchEventMessageDelta,
		Delta: &gatewayHostedSearchStopReason{StopReason: &stopReason},
		Usage: usage(),
	}
	if err := event(gatewayHostedSearchEventMessageDelta, delta); err != nil {
		return nil, err
	}
	if err := event(gatewayHostedSearchEventMessageStop, &gatewayHostedSearchMessageStop{Type: gatewayHostedSearchEventMessageStop}); err != nil {
		return nil, err
	}
	return answer, nil
}

// prefix and IdRandomCharCount characters of the API's alphabet, each from a word of the random reader taken modulo
// the alphabet's size, whose bias a 64-bit word makes negligible.
func (self *GatewayHostedSearch) drawId(prefix string) (string, error) {
	count := max(self.settings.IdRandomCharCount, 0)
	words := make([]uint64, count)
	if err := binary.Read(self.random, binary.BigEndian, words); err != nil {
		return "", fmt.Errorf("gateway hosted search: drawing an id: %w", err)
	}
	id := []byte(prefix)
	alphabetCount := uint64(len(gatewayHostedSearchIdAlphabet))
	for _, word := range words {
		id = append(id, gatewayHostedSearchIdAlphabet[word%alphabetCount])
	}
	return string(id), nil
}

// JSON as the APIs write it: no HTML escaping, no trailing newline.
func gatewayHostedSearchMarshal(value any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("gateway hosted search: %w", err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// The hosted searches the gateway dropped or answered, by harness, which `ur status` and `ur gateway status` show as
// a warning (§21.7). Counts, times and the names of what went only: never a query, a request's text or a result.
// Safe for concurrent use.
type GatewayHostedSearchNotice struct {
	settings *GatewayHostedSearchSettings
	clock    Clock

	stateLock sync.Mutex
	// by harness, at most NoticeHarnessCount
	harnessCounts map[string]*GatewayHostedSearchHarnessCount
	// the harnesses past NoticeHarnessCount, together; nil until one comes
	otherCount *GatewayHostedSearchHarnessCount
	// the latest refusals, at most NoticeRingCount; once full, ringNext is the oldest
	ringEntries []*GatewayHostedSearchNoticeEntry
	ringNext    int
}

// One harness's refusals, or those of every harness past NoticeHarnessCount, whose Harness is empty.
type GatewayHostedSearchHarnessCount struct {
	Harness string `json:"harness,omitempty"`
	// requests whose hosted search the gateway dropped and routed
	Dropped uint64 `json:"dropped"`
	// WebSearch side requests answered unavailable
	Answered uint64 `json:"answered"`
	// the latest refusal's time
	Last time.Time `json:"last"`
}

// One refusal in the ring.
type GatewayHostedSearchNoticeEntry struct {
	Time    time.Time              `json:"time"`
	Harness string                 `json:"harness"`
	Api     GatewayHostedSearchApi `json:"api"`
	// whether the request was answered unavailable rather than routed without its hosted search
	Answered bool `json:"answered,omitempty"`
	// what went, at most NoticeItemCount: each hosted tool's type, `include <entry>`, `tool_choice <type>` or
	// web_search_options
	Items []string `json:"items,omitempty"`
	// how many items went, those not named included
	ItemCount int `json:"item_count"`
}

// The notice at one moment: each named harness's counts, sorted by name, the rest's, and the ring, oldest first.
type GatewayHostedSearchNoticeSnapshot struct {
	Harnesses []*GatewayHostedSearchHarnessCount `json:"harnesses,omitempty"`
	Other     *GatewayHostedSearchHarnessCount   `json:"other,omitempty"`
	Recent    []*GatewayHostedSearchNoticeEntry  `json:"recent,omitempty"`
}

// An empty notice bounded by settings, its times read from clock.
func newGatewayHostedSearchNotice(settings *GatewayHostedSearchSettings, clock Clock) *GatewayHostedSearchNotice {
	return &GatewayHostedSearchNotice{
		settings:      settings,
		clock:         clock,
		harnessCounts: map[string]*GatewayHostedSearchHarnessCount{},
	}
}

// Counts one refusal: its harness's totals and an entry in the ring naming what went.
func (self *GatewayHostedSearchNotice) record(harness string, api GatewayHostedSearchApi, answered bool, items []string) {
	now := self.clock.Now()
	entry := &GatewayHostedSearchNoticeEntry{
		Time:      now,
		Harness:   harness,
		Api:       api,
		Answered:  answered,
		ItemCount: len(items),
	}
	for _, item := range items[:min(len(items), max(self.settings.NoticeItemCount, 0))] {
		entry.Items = append(entry.Items, gatewayHostedSearchCut(item, self.settings.NoticeItemByteCount))
	}

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count, ok := self.harnessCounts[harness]
	if !ok {
		if len(self.harnessCounts) < self.settings.NoticeHarnessCount {
			count = &GatewayHostedSearchHarnessCount{Harness: harness}
			self.harnessCounts[harness] = count
		} else {
			if self.otherCount == nil {
				self.otherCount = &GatewayHostedSearchHarnessCount{}
			}
			count = self.otherCount
		}
	}
	if answered {
		count.Answered++
	} else {
		count.Dropped++
	}
	count.Last = now
	ringCount := self.settings.NoticeRingCount
	switch {
	case ringCount <= 0:
	case len(self.ringEntries) < ringCount:
		self.ringEntries = append(self.ringEntries, entry)
	default:
		self.ringEntries[self.ringNext%len(self.ringEntries)] = entry
		self.ringNext = (self.ringNext + 1) % len(self.ringEntries)
	}
}

// A copy of the notice now.
func (self *GatewayHostedSearchNotice) Snapshot() *GatewayHostedSearchNoticeSnapshot {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	snapshot := &GatewayHostedSearchNoticeSnapshot{}
	for _, count := range self.harnessCounts {
		copied := *count
		snapshot.Harnesses = append(snapshot.Harnesses, &copied)
	}
	sort.Slice(snapshot.Harnesses, func(i int, j int) bool {
		return snapshot.Harnesses[i].Harness < snapshot.Harnesses[j].Harness
	})
	if self.otherCount != nil {
		copied := *self.otherCount
		snapshot.Other = &copied
	}
	for index := range self.ringEntries {
		entry := *self.ringEntries[(self.ringNext+index)%len(self.ringEntries)]
		entry.Items = slices.Clone(entry.Items)
		snapshot.Recent = append(snapshot.Recent, &entry)
	}
	return snapshot
}

// The notice's warning lines now (Snapshot's Warnings).
func (self *GatewayHostedSearchNotice) Warnings() []string {
	return self.Snapshot().Warnings()
}

// One line for each harness that sent hosted search, named ones by name and then the rest together, for `ur status`
// and `ur gateway status` to print as warnings: how often, when last, and what to do.
func (self *GatewayHostedSearchNoticeSnapshot) Warnings() []string {
	lines := []string{}
	line := func(who string, fix string, count *GatewayHostedSearchHarnessCount) {
		lines = append(lines, fmt.Sprintf(
			"%s sent hosted web search, which the gateway serves none of: %d requests had it dropped and %d were "+
				"answered unavailable, the last at %s. It searches through MCP's web_search; %s",
			who, count.Dropped, count.Answered, count.Last.UTC().Format(time.RFC3339), fix))
	}
	for _, count := range self.Harnesses {
		who, name := count.Harness, count.Harness
		if name == "" {
			who, name = "a harness with no name", "<harness>"
		}
		line(who, fmt.Sprintf("`ur install-harness %s --gateway` turns its own search off.", name), count)
	}
	if self.Other != nil {
		line("other harnesses", "the settings `ur install-harness <harness> --gateway` writes turn their own search off.", self.Other)
	}
	return lines
}

// item, cut to at most byteCount bytes at a character's end and marked with an ellipsis where it was longer.
// Non-positive keeps it whole.
func gatewayHostedSearchCut(item string, byteCount int) string {
	if byteCount <= 0 || len(item) <= byteCount {
		return item
	}
	cut := byteCount
	for 0 < cut && !utf8.RuneStart(item[cut]) {
		cut--
	}
	return item[:cut] + "…"
}

// A request body read as one JSON object, its top-level members found, and the changes made to it so far.
type gatewayHostedSearchEdit struct {
	body    []byte
	members []*gatewayHostedSearchMember
	// new values of members, by member
	replaced map[*gatewayHostedSearchMember][]byte
	// members left out
	removed map[*gatewayHostedSearchMember]bool
	// what went, for the notice
	items []string
}

// body read as one JSON object: an error wrapping ErrGatewayHostedSearchMalformed otherwise.
func newGatewayHostedSearchEdit(body []byte) (*gatewayHostedSearchEdit, error) {
	if !json.Valid(body) {
		return nil, fmt.Errorf("%w: not JSON", ErrGatewayHostedSearchMalformed)
	}
	members, err := gatewayHostedSearchMembers(body)
	if err != nil {
		return nil, err
	}
	return &gatewayHostedSearchEdit{
		body:     body,
		members:  members,
		replaced: map[*gatewayHostedSearchMember][]byte{},
		removed:  map[*gatewayHostedSearchMember]bool{},
	}, nil
}

// Whether anything was dropped or replaced.
func (self *gatewayHostedSearchEdit) changed() bool {
	return 0 < len(self.replaced) || 0 < len(self.removed)
}

// The object with the changes made, every other member's bytes as they were.
func (self *gatewayHostedSearchEdit) bytes() []byte {
	return gatewayHostedSearchRebuildObject(self.body, self.members, self.replaced, self.removed)
}

// Every top-level member whose key a decoder would take for key.
func (self *gatewayHostedSearchEdit) find(key string) []*gatewayHostedSearchMember {
	return gatewayHostedSearchFind(self.members, key)
}

// The string of the one member key names, or empty where none does. More than one, or one that is not a string, is
// malformed: a decoder might take either.
func (self *gatewayHostedSearchEdit) onlyString(key string) (string, error) {
	members := self.find(key)
	switch len(members) {
	case 0:
		return "", fmt.Errorf("%w: no %s", ErrGatewayHostedSearchMalformed, key)
	case 1:
	default:
		return "", fmt.Errorf("%w: %d members named %s", ErrGatewayHostedSearchMalformed, len(members), key)
	}
	value, ok, err := gatewayHostedSearchStringValue(members[0].value(self.body))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w: %s is not a string", ErrGatewayHostedSearchMalformed, key)
	}
	return value, nil
}

// The boolean of the one member key names, false where none does or it is null. More than one, or one that is
// neither, is malformed.
func (self *gatewayHostedSearchEdit) onlyBool(key string) (bool, error) {
	members := self.find(key)
	switch len(members) {
	case 0:
		return false, nil
	case 1:
	default:
		return false, fmt.Errorf("%w: %d members named %s", ErrGatewayHostedSearchMalformed, len(members), key)
	}
	switch string(members[0].value(self.body)) {
	case "true":
		return true, nil
	case "false", "null":
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s is not a boolean", ErrGatewayHostedSearchMalformed, key)
	}
}

// One tool of a tools member.
type gatewayHostedSearchTool struct {
	// the tools member it is in, and its bytes there
	member *gatewayHostedSearchMember
	raw    []byte
	// the type that makes it a hosted search, empty for any other tool
	hostedType string
	// the names it goes by: its name members, and a Chat Completions function's name
	names []string
}

// Every tool of every tools member, each read for whether it is a hosted search.
type gatewayHostedSearchTools struct {
	tools []*gatewayHostedSearchTool
}

// How many tools are no hosted search.
func (self *gatewayHostedSearchTools) keptCount() int {
	count := 0
	for _, tool := range self.tools {
		if tool.hostedType == "" {
			count++
		}
	}
	return count
}

// Whether any tool goes.
func (self *gatewayHostedSearchTools) dropsAny() bool {
	return self.keptCount() < len(self.tools)
}

// The names of the tools that go, without those a kept tool also goes by, which a reference may still mean.
func (self *gatewayHostedSearchTools) droppedNames() map[string]bool {
	keptNames := map[string]bool{}
	for _, tool := range self.tools {
		if tool.hostedType == "" {
			for _, name := range tool.names {
				keptNames[name] = true
			}
		}
	}
	droppedNames := map[string]bool{}
	for _, tool := range self.tools {
		if tool.hostedType != "" {
			for _, name := range tool.names {
				if !keptNames[name] {
					droppedNames[name] = true
				}
			}
		}
	}
	return droppedNames
}

// The tools of every member a decoder would take for tools. A tools that is null holds none; one that is not an array
// of objects is malformed, as is a tool whose type is not a string.
func (self *gatewayHostedSearchEdit) readTools() (*gatewayHostedSearchTools, error) {
	tools := &gatewayHostedSearchTools{}
	for _, member := range self.find(gatewayHostedSearchKeyTools) {
		value := member.value(self.body)
		if string(value) == "null" {
			continue
		}
		elements, err := gatewayHostedSearchElements(value)
		if err != nil {
			return nil, fmt.Errorf("%w: tools is not an array", ErrGatewayHostedSearchMalformed)
		}
		for _, element := range elements {
			tool, err := gatewayHostedSearchReadTool(element)
			if err != nil {
				return nil, err
			}
			tool.member = member
			tools.tools = append(tools.tools, tool)
		}
	}
	return tools, nil
}

// One tool's bytes, read: which hosted search it is, if any, and its names. A tool is a hosted search where any member
// a decoder would take for its type is a string starting with web_search; its name is never read for that.
func gatewayHostedSearchReadTool(raw []byte) (*gatewayHostedSearchTool, error) {
	members, err := gatewayHostedSearchMembers(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: a tool is not an object", ErrGatewayHostedSearchMalformed)
	}
	tool := &gatewayHostedSearchTool{raw: raw}
	hostedType, err := gatewayHostedSearchHostedType(raw, members)
	if err != nil {
		return nil, err
	}
	tool.hostedType = hostedType
	tool.names = gatewayHostedSearchNames(raw, members)
	return tool, nil
}

// The type that makes members a hosted search reference, empty where none does. A type member that is not a string is
// malformed.
func gatewayHostedSearchHostedType(raw []byte, members []*gatewayHostedSearchMember) (string, error) {
	hostedType := ""
	for _, member := range gatewayHostedSearchFind(members, gatewayHostedSearchKeyType) {
		value, ok, err := gatewayHostedSearchStringValue(member.value(raw))
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("%w: a type is not a string", ErrGatewayHostedSearchMalformed)
		}
		if hostedType == "" && strings.HasPrefix(value, gatewayHostedSearchToolTypePrefix) {
			hostedType = value
		}
	}
	return hostedType, nil
}

// The names members go by: each string name member, and each string name of a function member, Chat Completions'
// form.
func gatewayHostedSearchNames(raw []byte, members []*gatewayHostedSearchMember) []string {
	names := []string{}
	add := func(raw []byte, members []*gatewayHostedSearchMember) {
		for _, member := range gatewayHostedSearchFind(members, gatewayHostedSearchKeyName) {
			if name, ok, err := gatewayHostedSearchStringValue(member.value(raw)); err == nil && ok {
				names = append(names, name)
			}
		}
	}
	add(raw, members)
	for _, member := range gatewayHostedSearchFind(members, gatewayHostedSearchKeyFunction) {
		functionRaw := member.value(raw)
		if functionMembers, err := gatewayHostedSearchMembers(functionRaw); err == nil {
			add(functionRaw, functionMembers)
		}
	}
	return names
}

// Drops the hosted search tools from each tools member, keeping every other tool's bytes, an emptied list as [].
func (self *gatewayHostedSearchEdit) dropTools(tools *gatewayHostedSearchTools) {
	if !tools.dropsAny() {
		return
	}
	for _, member := range self.find(gatewayHostedSearchKeyTools) {
		keptRaws := [][]byte{}
		dropped := false
		for _, tool := range tools.tools {
			if tool.member != member {
				continue
			}
			if tool.hostedType == "" {
				keptRaws = append(keptRaws, tool.raw)
			} else {
				dropped = true
				self.items = append(self.items, tool.hostedType)
			}
		}
		if dropped {
			self.replaced[member] = gatewayHostedSearchRebuildArray(keptRaws)
		}
	}
}

// Makes each tool_choice auto that names a hosted search, by its type or by a dropped tool's name, or that needs a
// tool where every one went; and drops hosted search from an allowed_tools list, auto where none is left. auto is the
// API's own.
func (self *gatewayHostedSearchEdit) chooseAuto(tools *gatewayHostedSearchTools, auto []byte) error {
	droppedNames := tools.droppedNames()
	noneLeft := tools.dropsAny() && tools.keptCount() == 0
	for _, member := range self.find(gatewayHostedSearchKeyToolChoice) {
		value := member.value(self.body)
		replacement, item, err := gatewayHostedSearchToolChoice(value, droppedNames, noneLeft, auto)
		if err != nil {
			return err
		}
		if replacement != nil {
			self.replaced[member] = replacement
		}
		if item != "" {
			self.items = append(self.items, item)
		}
	}
	return nil
}

// A tool_choice's value without hosted search: nil where it stays, auto where it named a hosted search or needed a
// tool where none is left, or an allowed_tools object with its list cut. item names a hosted type it named, for the
// notice, empty where it named none by type.
func gatewayHostedSearchToolChoice(value []byte, droppedNames map[string]bool, noneLeft bool, auto []byte) ([]byte, string, error) {
	if text, ok, err := gatewayHostedSearchStringValue(value); err != nil {
		return nil, "", err
	} else if ok {
		if noneLeft && (text == gatewayHostedSearchChoiceRequired || text == gatewayHostedSearchChoiceAny) {
			return auto, "", nil
		}
		return nil, "", nil
	}
	members, err := gatewayHostedSearchMembers(value)
	if err != nil {
		// null, or a form no API has: nothing of hosted search to take out
		return nil, "", nil
	}
	hostedType, err := gatewayHostedSearchHostedType(value, members)
	if err != nil {
		return nil, "", err
	}
	if hostedType != "" {
		return auto, gatewayHostedSearchKeyToolChoice + " " + hostedType, nil
	}
	if slices.ContainsFunc(gatewayHostedSearchNames(value, members), func(name string) bool { return droppedNames[name] }) {
		return gatewayHostedSearchAutoKeeping(value, members, auto), "", nil
	}
	choiceTypes := []string{}
	for _, member := range gatewayHostedSearchFind(members, gatewayHostedSearchKeyType) {
		if text, ok, err := gatewayHostedSearchStringValue(member.value(value)); err == nil && ok {
			choiceTypes = append(choiceTypes, text)
		}
	}
	if noneLeft && slices.Contains(choiceTypes, gatewayHostedSearchChoiceAny) {
		return gatewayHostedSearchAutoKeeping(value, members, auto), "", nil
	}
	if slices.Contains(choiceTypes, gatewayHostedSearchChoiceAllowedTools) {
		return gatewayHostedSearchAllowedTools(value, members, droppedNames, auto)
	}
	return nil, "", nil
}

// auto, with value's disable_parallel_tool_use kept where auto is an object, as Messages' is.
func gatewayHostedSearchAutoKeeping(value []byte, members []*gatewayHostedSearchMember, auto []byte) []byte {
	keeps := gatewayHostedSearchFind(members, gatewayHostedSearchKeyNoParallel)
	if len(keeps) == 0 || !bytes.HasPrefix(auto, []byte("{")) {
		return auto
	}
	autoMembers, err := gatewayHostedSearchMembers(auto)
	if err != nil || len(autoMembers) == 0 {
		return auto
	}
	out := slices.Clone(auto[:autoMembers[len(autoMembers)-1].end])
	for _, keep := range keeps {
		out = append(out, ',')
		out = append(out, value[keep.start:keep.end]...)
	}
	return append(out, '}')
}

// An allowed_tools tool_choice with its hosted search references cut: Responses' list at tools, Chat Completions'
// at allowed_tools.tools. auto where a list it cut is left empty; nil where nothing was cut.
func gatewayHostedSearchAllowedTools(value []byte, members []*gatewayHostedSearchMember, droppedNames map[string]bool, auto []byte) ([]byte, string, error) {
	items := []string{}
	emptied := false
	// a list of tool references without the hosted ones: nil where it held none
	cutList := func(list []byte) ([]byte, error) {
		elements, err := gatewayHostedSearchElements(list)
		if err != nil {
			return nil, nil
		}
		keptRaws := [][]byte{}
		cut := false
		for _, element := range elements {
			referenceMembers, err := gatewayHostedSearchMembers(element)
			if err != nil {
				keptRaws = append(keptRaws, element)
				continue
			}
			hostedType, err := gatewayHostedSearchHostedType(element, referenceMembers)
			if err != nil {
				return nil, err
			}
			named := slices.ContainsFunc(gatewayHostedSearchNames(element, referenceMembers), func(name string) bool {
				return droppedNames[name]
			})
			if hostedType != "" || named {
				cut = true
				if hostedType != "" {
					items = append(items, gatewayHostedSearchKeyToolChoice+" "+hostedType)
				}
				continue
			}
			keptRaws = append(keptRaws, element)
		}
		if !cut {
			return nil, nil
		}
		emptied = emptied || len(keptRaws) == 0
		return gatewayHostedSearchRebuildArray(keptRaws), nil
	}
	cutObject := func(object []byte, objectMembers []*gatewayHostedSearchMember) ([]byte, error) {
		replaced := map[*gatewayHostedSearchMember][]byte{}
		for _, member := range gatewayHostedSearchFind(objectMembers, gatewayHostedSearchKeyTools) {
			list, err := cutList(member.value(object))
			if err != nil {
				return nil, err
			}
			if list != nil {
				replaced[member] = list
			}
		}
		if len(replaced) == 0 {
			return nil, nil
		}
		return gatewayHostedSearchRebuildObject(object, objectMembers, replaced, nil), nil
	}

	replaced := map[*gatewayHostedSearchMember][]byte{}
	for _, member := range gatewayHostedSearchFind(members, gatewayHostedSearchKeyTools) {
		list, err := cutList(member.value(value))
		if err != nil {
			return nil, "", err
		}
		if list != nil {
			replaced[member] = list
		}
	}
	for _, member := range gatewayHostedSearchFind(members, gatewayHostedSearchKeyAllowedTools) {
		inner := member.value(value)
		innerMembers, err := gatewayHostedSearchMembers(inner)
		if err != nil {
			continue
		}
		object, err := cutObject(inner, innerMembers)
		if err != nil {
			return nil, "", err
		}
		if object != nil {
			replaced[member] = object
		}
	}
	item := strings.Join(items, ", ")
	if emptied {
		return auto, item, nil
	}
	if len(replaced) == 0 {
		return nil, "", nil
	}
	return gatewayHostedSearchRebuildObject(value, members, replaced, nil), item, nil
}

// Drops each include entry under web_search_call., Responses' asks for a hosted search's results.
func (self *gatewayHostedSearchEdit) dropIncludes() error {
	for _, member := range self.find(gatewayHostedSearchKeyInclude) {
		value := member.value(self.body)
		if string(value) == "null" {
			continue
		}
		elements, err := gatewayHostedSearchElements(value)
		if err != nil {
			return fmt.Errorf("%w: include is not an array", ErrGatewayHostedSearchMalformed)
		}
		keptRaws := [][]byte{}
		dropped := false
		for _, element := range elements {
			entry, ok, err := gatewayHostedSearchStringValue(element)
			if err != nil {
				return err
			}
			if ok && strings.HasPrefix(entry, gatewayHostedSearchIncludePrefix) {
				dropped = true
				self.items = append(self.items, gatewayHostedSearchKeyInclude+" "+entry)
				continue
			}
			keptRaws = append(keptRaws, element)
		}
		if dropped {
			self.replaced[member] = gatewayHostedSearchRebuildArray(keptRaws)
		}
	}
	return nil
}

// Leaves out every web_search_options member, Chat Completions' search parameter; one that is null names no search
// and is no item.
func (self *gatewayHostedSearchEdit) dropChatOptions() {
	for _, member := range self.find(gatewayHostedSearchKeyChatOptions) {
		self.removed[member] = true
		if string(member.value(self.body)) != "null" {
			self.items = append(self.items, gatewayHostedSearchKeyChatOptions)
		}
	}
}

// One member of a JSON object, by offsets into the bytes that hold the object.
type gatewayHostedSearchMember struct {
	// the key, its escapes undone
	key string
	// where the key's opening quote is, where the value starts, and just past the value
	start      int
	valueStart int
	end        int
}

// The member's value in data, the object's bytes.
func (self *gatewayHostedSearchMember) value(data []byte) []byte {
	return data[self.valueStart:self.end]
}

// The members a decoder might take for key, in order: those whose key, its escapes undone, equals key without regard
// to case, underscores or dashes. encoding/json matches a struct's field by strings.EqualFold, and its v2 under
// case:ignore or MatchCaseInsensitiveNames also skips underscores and dashes, so this takes every member either would.
func gatewayHostedSearchFind(members []*gatewayHostedSearchMember, key string) []*gatewayHostedSearchMember {
	foldedKey := gatewayHostedSearchFoldKey(key)
	found := []*gatewayHostedSearchMember{}
	for _, member := range members {
		if strings.EqualFold(gatewayHostedSearchFoldKey(member.key), foldedKey) {
			found = append(found, member)
		}
	}
	return found
}

// key without its underscores and dashes.
func gatewayHostedSearchFoldKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' {
			return -1
		}
		return r
	}, key)
}

// The members of the JSON object data holds, in order. data must be JSON that json.Valid accepts, as each part of a
// request body that passed it is; a value that is not an object is malformed.
func gatewayHostedSearchMembers(data []byte) ([]*gatewayHostedSearchMember, error) {
	offset := gatewayHostedSearchSkipSpace(data, 0)
	if len(data) <= offset || data[offset] != '{' {
		return nil, fmt.Errorf("%w: not an object", ErrGatewayHostedSearchMalformed)
	}
	members := []*gatewayHostedSearchMember{}
	offset = gatewayHostedSearchSkipSpace(data, offset+1)
	if offset < len(data) && data[offset] == '}' {
		return members, nil
	}
	for offset < len(data) && data[offset] == '"' {
		start := offset
		keyEnd := gatewayHostedSearchStringEnd(data, start)
		key, ok, err := gatewayHostedSearchStringValue(data[start:keyEnd])
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: a key does not read", ErrGatewayHostedSearchMalformed)
		}
		offset = gatewayHostedSearchSkipSpace(data, keyEnd)
		if len(data) <= offset || data[offset] != ':' {
			break
		}
		valueStart := gatewayHostedSearchSkipSpace(data, offset+1)
		end := gatewayHostedSearchValueEnd(data, valueStart)
		members = append(members, &gatewayHostedSearchMember{key: key, start: start, valueStart: valueStart, end: end})
		offset = gatewayHostedSearchSkipSpace(data, end)
		if offset < len(data) && data[offset] == ',' {
			offset = gatewayHostedSearchSkipSpace(data, offset+1)
			continue
		}
		if offset < len(data) && data[offset] == '}' {
			return members, nil
		}
		break
	}
	return nil, fmt.Errorf("%w: an object does not read", ErrGatewayHostedSearchMalformed)
}

// The elements of the JSON array data holds, each its bytes, in order. data must be JSON json.Valid accepts; a value
// that is not an array is an error.
func gatewayHostedSearchElements(data []byte) ([][]byte, error) {
	offset := gatewayHostedSearchSkipSpace(data, 0)
	if len(data) <= offset || data[offset] != '[' {
		return nil, fmt.Errorf("%w: not an array", ErrGatewayHostedSearchMalformed)
	}
	elements := [][]byte{}
	offset = gatewayHostedSearchSkipSpace(data, offset+1)
	if offset < len(data) && data[offset] == ']' {
		return elements, nil
	}
	for offset < len(data) {
		end := gatewayHostedSearchValueEnd(data, offset)
		if end <= offset {
			break
		}
		elements = append(elements, data[offset:end])
		offset = gatewayHostedSearchSkipSpace(data, end)
		if offset < len(data) && data[offset] == ',' {
			offset = gatewayHostedSearchSkipSpace(data, offset+1)
			continue
		}
		if offset < len(data) && data[offset] == ']' {
			return elements, nil
		}
		break
	}
	return nil, fmt.Errorf("%w: an array does not read", ErrGatewayHostedSearchMalformed)
}

// The string a JSON value holds, its escapes undone as encoding/json undoes them; ok is false for a value that is not
// a string.
func gatewayHostedSearchStringValue(value []byte) (string, bool, error) {
	if len(value) == 0 || value[0] != '"' {
		return "", false, nil
	}
	text := ""
	if err := json.Unmarshal(value, &text); err != nil {
		return "", false, fmt.Errorf("%w: %v", ErrGatewayHostedSearchMalformed, err)
	}
	return text, true, nil
}

// The first offset at or after offset that holds no JSON whitespace.
func gatewayHostedSearchSkipSpace(data []byte, offset int) int {
	for offset < len(data) {
		switch data[offset] {
		case ' ', '\t', '\n', '\r':
			offset++
		default:
			return offset
		}
	}
	return offset
}

// Just past the JSON value that starts at offset, in JSON json.Valid accepts: a string past its closing quote, an
// object or array past its closing bracket, a number or literal at the byte that ends it.
func gatewayHostedSearchValueEnd(data []byte, offset int) int {
	if len(data) <= offset {
		return offset
	}
	switch data[offset] {
	case '"':
		return gatewayHostedSearchStringEnd(data, offset)
	case '{', '[':
		depth := 0
		for offset < len(data) {
			switch data[offset] {
			case '"':
				offset = gatewayHostedSearchStringEnd(data, offset)
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return offset + 1
				}
			}
			offset++
		}
		return offset
	default:
		for offset < len(data) {
			switch data[offset] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return offset
			}
			offset++
		}
		return offset
	}
}

// Just past the JSON string whose opening quote is at offset: a backslash takes the byte after it with it.
func gatewayHostedSearchStringEnd(data []byte, offset int) int {
	offset++
	for offset < len(data) {
		switch data[offset] {
		case '\\':
			offset += 2
		case '"':
			return offset + 1
		default:
			offset++
		}
	}
	return len(data)
}

// data's object, the members in replaced with their new values and those in removed left out, joined by commas;
// every other member's bytes, its key's spelling and the space around its colon included, as they were.
func gatewayHostedSearchRebuildObject(
	data []byte,
	members []*gatewayHostedSearchMember,
	replaced map[*gatewayHostedSearchMember][]byte,
	removed map[*gatewayHostedSearchMember]bool,
) []byte {
	out := []byte{'{'}
	first := true
	for _, member := range members {
		if removed[member] {
			continue
		}
		if !first {
			out = append(out, ',')
		}
		first = false
		if value, ok := replaced[member]; ok {
			out = append(out, data[member.start:member.valueStart]...)
			out = append(out, value...)
		} else {
			out = append(out, data[member.start:member.end]...)
		}
	}
	return append(out, '}')
}

// An array of the elements' bytes, as they are, joined by commas.
func gatewayHostedSearchRebuildArray(elementRaws [][]byte) []byte {
	return append(append([]byte{'['}, bytes.Join(elementRaws, []byte{','})...), ']')
}
