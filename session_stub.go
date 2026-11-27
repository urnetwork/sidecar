//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.9's search stubs in every form the daemon writes (CTXH-M13-01; R-CTXH-7, D-CTXH-7, CO-26, Q-CTXH-3,
// CONTRACTS C-31): a web search's results are never stored, so each copy of one is replaced by §21.6's stub wherever
// the daemon would record it.
//
//	harness   the Harness's own result: the journal's keep: false stub (session_exceptions.go, CTXH-M11-03)
//	mcp       the MCP web_search tool's result: the tool sets McpResult.RecordStub, which the call sink records in place
//	          of the result (mcp/result.go, mcp/tool.go), and serves its texts' hashes here (SessionServedHashes.Serve)
//	gateway   a harness's own copies in its later requests through the gateway: the recorder stubs each item before
//	          its recorded form is taken, the stubs counted in the node (session_gateway.go)
//	ingest    a harness's transcript lines and hook payloads (DESIGN §16.7's ingest): a line holding a result is
//	          replaced whole, so the tail keeps its line framing, and a payload's result in place, before either is
//	          redacted or sealed (mcp/ingest_transcript.go, mcp/ingest.go)
//
//	match     first by the call that carried it: a result whose tool call names the MCP web_search tool in the
//	          harness's own form (mcp__ur__web_search, ur__web_search and the like, or an invocation naming server ur
//	          and tool web_search), which holds when a harness cuts a result short or saves it to a file; then by
//	          hashes of what the MCP tool served: a string, or a transcript line, whose SHA-256 is one SRCH served in
//	          a run the copy may come from
//	served    SessionServedHashes keeps, in the daemon's sealed state, run by run, the SHA-256 of each text the tool
//	          served of at least SessionSettings.ServedTextMinByteCount bytes, with the stub of the search that served
//	          it, and the harness's own ids of its web_search calls as its transcript names them, for
//	          SessionSettings.ServedLife after the run's last; hashes and ids only, never a result to match against
//	stub      a result's text becomes [web_search result not kept: <stub>], a transcript line
//	          {"ur_stub":"web_search","search":<stub>}; the stub is SRCH's (§21.6: the call, the number of results,
//	          the answer's hash, the payment and the charge) where a served hash names it, else null, the call itself
//	          being in the record already
//
// A copy the matcher misses, reworded or quoted in part inside other text, is §24.15's risk, which the marker corpus
// tests.
//
// Safe for concurrent use: SessionServedHashes under its stateLock, held across no store call; a SessionStubber is one
// caller's.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// The MCP server and tool whose results are stubbed (CO-26, §21.7), and the record's names for a stub: format values.
const (
	sessionStubServer      = "ur"
	sessionStubTool        = "web_search"
	sessionStubTextLead    = "[web_search result not kept"
	sessionStubLineMember  = "ur_stub"
	sessionStubLineSearch  = "search"
	sessionServedVersion   = 1
	sessionServedComponent = "session_served"
)

// The MCP web_search tool's name in each harness's own form: Claude Code's and the hooks' mcp__ur__web_search,
// Codex's ur__web_search for an MCP tool, and the forms other harnesses join a server and a tool by.
var sessionStubToolNames = []string{
	"mcp__" + sessionStubServer + "__" + sessionStubTool,
	sessionStubServer + "__" + sessionStubTool,
	sessionStubServer + "_" + sessionStubTool,
	sessionStubServer + "." + sessionStubTool,
	sessionStubServer + "/" + sessionStubTool,
	sessionStubServer + ":" + sessionStubTool,
}

// The members a call's id rides in, a result's reference to its call, a result's own text, and a result's type or
// role: the harnesses' and the fronts' names.
var (
	sessionStubIdMembers        = []string{"id", "call_id", "tool_use_id", "tool_call_id", "callId", "toolUseId", "toolCallId"}
	sessionStubReferenceMembers = []string{"call_id", "tool_use_id", "tool_call_id", "callId", "toolUseId", "toolCallId"}
	sessionStubResultMembers    = []string{"output", "content", "result", "tool_response", "toolUseResult", "structuredContent"}
	sessionStubResultTypes      = []string{"tool_result", "function_call_output", "custom_tool_call_output", "mcp_tool_call_end", "mcp_tool_call_output"}
	sessionStubResultRoles      = []string{"tool", "toolResult"}
)

var (
	// A served set past SessionSettings.ServedRunHashCount or ServedRunCallCount: the tool does not serve what the
	// record could not stub (§24.9).
	ErrSessionServedFull = errors.New("session served hashes full")
	// A stub that is no JSON object.
	ErrSessionStubInvalid = errors.New("session stub invalid")
)

// The text a copy of a search result becomes: the stub's canonical JSON where one is known.
func SessionSearchStubText(stub []byte) string {
	if len(stub) == 0 {
		return sessionStubTextLead + "]"
	}
	return sessionStubTextLead + ": " + string(stub) + "]"
}

// A transcript line holding a search result, replaced whole: one JSON object, its stub or null, and the newline the
// line ended with.
func SessionSearchStubLine(stub []byte, newline bool) []byte {
	search := "null"
	if len(stub) != 0 {
		search = string(stub)
	}
	line := `{"` + sessionStubLineMember + `":"` + sessionStubTool + `","` + sessionStubLineSearch + `":` + search + `}`
	if newline {
		line += "\n"
	}
	return []byte(line)
}

// One run's served hashes and call ids.
type sessionServedRun struct {
	hashStubs  map[[sha256.Size]byte][]byte
	callIds    map[string]bool
	names      []string
	lastMillis int64
}

// One segment as stored.
type sessionServedSegment struct {
	Version int   `json:"version"`
	RunId   Id    `json:"run_id"`
	Millis  int64 `json:"millis"`
	// lowercase hex
	Sha256s []string        `json:"sha256s,omitempty"`
	Stub    json.RawMessage `json:"stub,omitempty"`
	CallIds []string        `json:"call_ids,omitempty"`
}

// What the MCP web_search tool served, run by run (see the file header's served row). Safe for concurrent use.
type SessionServedHashes struct {
	store    SidecarStore
	settings *SessionSettings
	clock    Clock

	stateLock    sync.Mutex
	runs         map[Id]*sessionServedRun
	segmentCount uint64
}

// A served set over store, which reads each run's segments at its first use.
func NewSessionServedHashes(store SidecarStore, settings *SessionSettings, clock Clock) (*SessionServedHashes, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: a served set needs its store", ErrSessionGatewayRefused)
	}
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	return &SessionServedHashes{store: store, settings: settings, clock: clockOrReal(clock), runs: map[Id]*sessionServedRun{}}, nil
}

// A run's directory in the store.
func sessionServedRunDirectory(runId Id) string {
	return hex.EncodeToString(runId[:]) + "/"
}

// The run's set, its segments read at its first use. A segment that does not read fails the read, so no match is
// made on a set that may be short.
func (self *SessionServedHashes) runOf(runId Id) (*sessionServedRun, error) {
	held := func() *sessionServedRun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.runs[runId]
	}()
	if held != nil {
		return held, nil
	}
	run := &sessionServedRun{hashStubs: map[[sha256.Size]byte][]byte{}, callIds: map[string]bool{}}
	directory := sessionServedRunDirectory(runId)
	entries, err := self.store.List(directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		reader, err := self.store.Open(entry.Name)
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return nil, err
		}
		segment := &sessionServedSegment{}
		if err := recordChainDecode(content, segment); err != nil || segment.Version != sessionServedVersion || segment.RunId != runId {
			return nil, fmt.Errorf("%w: a served segment %s", ErrRecordChainCorrupt, entry.Name)
		}
		if err := run.apply(segment, entry.Name); err != nil {
			return nil, err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held := self.runs[runId]; held != nil {
		return held, nil
	}
	self.runs[runId] = run
	return run, nil
}

// Adds a segment to the run's set.
func (self *sessionServedRun) apply(segment *sessionServedSegment, name string) error {
	for _, digest := range segment.Sha256s {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("%w: a served hash", ErrRecordChainCorrupt)
		}
		self.hashStubs[[sha256.Size]byte(decoded)] = []byte(segment.Stub)
	}
	for _, callId := range segment.CallIds {
		self.callIds[callId] = true
	}
	self.names = append(self.names, name)
	self.lastMillis = max(self.lastMillis, segment.Millis)
	return nil
}

// Writes a segment of the run durably, then adds it.
func (self *SessionServedHashes) write(run *sessionServedRun, segment *sessionServedSegment) error {
	content, err := json.Marshal(segment)
	if err != nil {
		return err
	}
	segmentCount := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.segmentCount += 1
		return self.segmentCount
	}()
	name := sessionServedRunDirectory(segment.RunId) + fmt.Sprintf("%016x-%016x", segment.Millis, segmentCount)
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return run.apply(segment, name)
}

// Records that the MCP web_search tool served texts in runId under stub, §21.6's stub of the search as SRCH builds it
// (nil for none): the SHA-256 of each text of at least ServedTextMinByteCount bytes, durable before this returns, so
// the tool returns no result text the record could not stub (§24.9). ErrSessionServedFull past ServedRunHashCount.
func (self *SessionServedHashes) Serve(runId Id, served [][]byte, stub []byte) error {
	if runId == (Id{}) {
		return fmt.Errorf("%w: no run", ErrSessionGatewayRefused)
	}
	var canonical []byte
	if len(stub) != 0 {
		object, err := sessionGatewayObjectOf(stub)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSessionStubInvalid, err)
		}
		if canonical, err = sessionCanonical(object); err != nil {
			return fmt.Errorf("%w: %v", ErrSessionStubInvalid, err)
		}
	}
	run, err := self.runOf(runId)
	if err != nil {
		return err
	}
	segment := &sessionServedSegment{Version: sessionServedVersion, RunId: runId, Millis: self.clock.Now().UnixMilli(), Stub: canonical}
	for _, text := range served {
		if len(text) < self.settings.ServedTextMinByteCount {
			continue
		}
		digest := sha256.Sum256(text)
		segment.Sha256s = append(segment.Sha256s, hex.EncodeToString(digest[:]))
	}
	full := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.settings.ServedRunHashCount < len(run.hashStubs)+len(segment.Sha256s)
	}()
	if full {
		return fmt.Errorf("%w: run %s", ErrSessionServedFull, runId)
	}
	return self.write(run, segment)
}

// Notes a harness's own id of a web_search call in runId, as its transcript names it, so a result a later line holds
// is matched by its call. ErrSessionServedFull past ServedRunCallCount.
func (self *SessionServedHashes) NoteCall(runId Id, callId string) error {
	if runId == (Id{}) || callId == "" {
		return nil
	}
	run, err := self.runOf(runId)
	if err != nil {
		return err
	}
	noted, full := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return run.callIds[callId], self.settings.ServedRunCallCount <= len(run.callIds)
	}()
	if noted {
		return nil
	}
	if full {
		return fmt.Errorf("%w: run %s", ErrSessionServedFull, runId)
	}
	return self.write(run, &sessionServedSegment{Version: sessionServedVersion, RunId: runId, Millis: self.clock.Now().UnixMilli(), CallIds: []string{callId}})
}

// The stub of a text one of runIds served, false where none did.
func (self *SessionServedHashes) stubOf(runIds []Id, text []byte) ([]byte, bool, error) {
	if len(text) < self.settings.ServedTextMinByteCount {
		return nil, false, nil
	}
	digest := sha256.Sum256(text)
	for _, runId := range runIds {
		run, err := self.runOf(runId)
		if err != nil {
			return nil, false, err
		}
		stub, ok := func() ([]byte, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			stub, ok := run.hashStubs[digest]
			return stub, ok
		}()
		if ok {
			return stub, true, nil
		}
	}
	return nil, false, nil
}

// Whether one of runIds noted callId.
func (self *SessionServedHashes) callNoted(runIds []Id, callId string) (bool, error) {
	for _, runId := range runIds {
		run, err := self.runOf(runId)
		if err != nil {
			return false, err
		}
		noted := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return run.callIds[callId]
		}()
		if noted {
			return true, nil
		}
	}
	return false, nil
}

// The call ids runIds noted.
func (self *SessionServedHashes) callIdsOf(runIds []Id) ([]string, error) {
	callIds := []string{}
	for _, runId := range runIds {
		run, err := self.runOf(runId)
		if err != nil {
			return nil, err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for callId := range run.callIds {
				callIds = append(callIds, callId)
			}
		}()
	}
	return callIds, nil
}

// Drops every run whose last serve or note is older than ServedLife, segments and all, by the times their names
// carry.
func (self *SessionServedHashes) Sweep() error {
	entries, err := self.store.List("")
	if err != nil {
		return err
	}
	cutoffMillis := self.clock.Now().Add(-self.settings.ServedLife).UnixMilli()
	runNames := map[string][]string{}
	runLastMillis := map[string]int64{}
	for _, entry := range entries {
		directory, name, ok := strings.Cut(entry.Name, "/")
		if !ok {
			continue
		}
		millisText, _, _ := strings.Cut(name, "-")
		millis, err := strconv.ParseInt(millisText, 16, 64)
		if err != nil {
			continue
		}
		runNames[directory] = append(runNames[directory], entry.Name)
		runLastMillis[directory] = max(runLastMillis[directory], millis)
	}
	for directory, names := range runNames {
		if cutoffMillis <= runLastMillis[directory] {
			continue
		}
		if decoded, err := hex.DecodeString(directory); err == nil && len(decoded) == len(Id{}) {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.runs, Id(decoded))
			}()
		}
		for _, name := range names {
			if err := self.store.Remove(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// One caller's matcher over the runs a copy may come from (see the file header's match row).
type SessionStubber struct {
	served *SessionServedHashes
	runIds []Id
	// the web_search calls this stubber met, beside those the served set noted
	callIds map[string]bool
}

// A stubber for copies in runIds, the first the run they are recorded in; served nil matches by call alone.
func NewSessionStubber(served *SessionServedHashes, runIds ...Id) *SessionStubber {
	return &SessionStubber{served: served, runIds: slices.Clone(runIds), callIds: map[string]bool{}}
}

// Each object of value, depth first, parents before children.
func sessionStubWalk(value any, visit func(object map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed)
		for _, member := range typed {
			sessionStubWalk(member, visit)
		}
	case []any:
		for _, element := range typed {
			sessionStubWalk(element, visit)
		}
	}
}

// Whether object names the MCP web_search tool: by a name in a harness's form, by a function naming it, or by an
// invocation of server ur's tool web_search.
func sessionStubNamesSearch(object map[string]any) bool {
	for _, member := range []string{"name", "tool_name", "toolName"} {
		if name, ok := object[member].(string); ok && slices.Contains(sessionStubToolNames, name) {
			return true
		}
	}
	if function, ok := object["function"].(map[string]any); ok {
		if name, ok := function["name"].(string); ok && slices.Contains(sessionStubToolNames, name) {
			return true
		}
	}
	invocation, ok := object["invocation"].(map[string]any)
	if !ok {
		invocation = object
	}
	server, _ := invocation["server"].(string)
	tool, _ := invocation["tool"].(string)
	return server == sessionStubServer && tool == sessionStubTool
}

// The ids object carries.
func sessionStubIdsOf(object map[string]any) []string {
	ids := []string{}
	for _, member := range sessionStubIdMembers {
		if id, ok := object[member].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// Whether object is a tool's result: by its type or its role.
func sessionStubIsResult(object map[string]any) bool {
	if kind, ok := object["type"].(string); ok && slices.Contains(sessionStubResultTypes, kind) {
		return true
	}
	role, ok := object["role"].(string)
	return ok && slices.Contains(sessionStubResultRoles, role)
}

// Whether object carries a result's text.
func sessionStubHoldsResult(object map[string]any) bool {
	for _, member := range sessionStubResultMembers {
		if _, ok := object[member]; ok {
			return true
		}
	}
	return false
}

// Notes the web_search calls value names, in memory and, for the stubber's run, in the served set.
func (self *SessionStubber) noteCalls(value any) error {
	var noteErr error
	sessionStubWalk(value, func(object map[string]any) {
		if !sessionStubNamesSearch(object) {
			return
		}
		for _, id := range sessionStubIdsOf(object) {
			if self.callIds[id] {
				continue
			}
			self.callIds[id] = true
			if self.served != nil && 0 < len(self.runIds) && noteErr == nil {
				noteErr = self.served.NoteCall(self.runIds[0], id)
			}
		}
	})
	return noteErr
}

// The web_search calls met, in memory and in the served set.
func (self *SessionStubber) knownCallIds() ([]string, error) {
	callIds := []string{}
	for callId := range self.callIds {
		callIds = append(callIds, callId)
	}
	if self.served == nil {
		return callIds, nil
	}
	noted, err := self.served.callIdsOf(self.runIds)
	if err != nil {
		return nil, err
	}
	return append(callIds, noted...), nil
}

// Whether a web_search call of callId was met.
func (self *SessionStubber) searchCall(callId string) (bool, error) {
	if self.callIds[callId] {
		return true, nil
	}
	if self.served == nil {
		return false, nil
	}
	return self.served.callNoted(self.runIds, callId)
}

// Whether object is the result of a web_search call: a result naming a call met, or an object naming the tool and
// carrying a result's text, as Codex's mcp_tool_call_end does.
func (self *SessionStubber) searchResult(object map[string]any) (bool, error) {
	if sessionStubNamesSearch(object) && sessionStubHoldsResult(object) && sessionStubIsResult(object) {
		return true, nil
	}
	if !sessionStubIsResult(object) {
		return false, nil
	}
	for _, member := range sessionStubReferenceMembers {
		if callId, ok := object[member].(string); ok && callId != "" {
			found, err := self.searchCall(callId)
			if err != nil || found {
				return found, err
			}
		}
	}
	return false, nil
}

// The stub of a text a served hash names, nil where none does.
func (self *SessionStubber) stubOf(text []byte) ([]byte, bool, error) {
	if self.served == nil {
		return nil, false, nil
	}
	return self.served.stubOf(self.runIds, text)
}

// The stub a result object's own text names by its hash, nil for none: its result members' strings, each alone.
func (self *SessionStubber) resultStub(object map[string]any) ([]byte, error) {
	var found []byte
	var stubErr error
	for _, member := range sessionStubResultMembers {
		value, ok := object[member]
		if !ok {
			continue
		}
		sessionStubStrings(value, func(text string) {
			if found != nil || stubErr != nil {
				return
			}
			stub, ok, err := self.stubOf([]byte(text))
			if err != nil {
				stubErr = err
			} else if ok {
				found = stub
			}
		})
	}
	return found, stubErr
}

// Each string of value.
func sessionStubStrings(value any, visit func(text string)) {
	switch typed := value.(type) {
	case string:
		visit(typed)
	case map[string]any:
		for _, member := range typed {
			sessionStubStrings(member, visit)
		}
	case []any:
		for _, element := range typed {
			sessionStubStrings(element, visit)
		}
	}
}

// value with every string a served hash names replaced by its stub's text, and how many were.
func (self *SessionStubber) stubStrings(value any) (any, int, error) {
	switch typed := value.(type) {
	case string:
		stub, ok, err := self.stubOf([]byte(typed))
		if err != nil || !ok {
			return value, 0, err
		}
		return SessionSearchStubText(stub), 1, nil
	case map[string]any:
		total := 0
		for key, member := range typed {
			replaced, count, err := self.stubStrings(member)
			if err != nil {
				return nil, 0, err
			}
			typed[key] = replaced
			total += count
		}
		return typed, total, nil
	case []any:
		total := 0
		for index, element := range typed {
			replaced, count, err := self.stubStrings(element)
			if err != nil {
				return nil, 0, err
			}
			typed[index] = replaced
			total += count
		}
		return typed, total, nil
	}
	return value, 0, nil
}

// Stubs in place each web_search result an object of value holds: its result members become the stub's text.
// Answers how many results were stubbed.
func (self *SessionStubber) stubResults(value any) (int, error) {
	count := 0
	var stubErr error
	sessionStubWalk(value, func(object map[string]any) {
		if stubErr != nil {
			return
		}
		result, err := self.searchResult(object)
		if err != nil {
			stubErr = err
			return
		}
		if !result {
			return
		}
		stub, err := self.resultStub(object)
		if err != nil {
			stubErr = err
			return
		}
		for _, member := range sessionStubResultMembers {
			if _, ok := object[member]; ok {
				object[member] = SessionSearchStubText(stub)
			}
		}
		count += 1
	})
	return count, stubErr
}

// Stubs a request's items in place (the gateway's): the web_search calls any item names are met first, so a result
// in a later item, or in the same one, is stubbed by its call; then each string a served hash names. Answers each
// item's count.
func (self *SessionStubber) StubItems(items []map[string]any) ([]int, error) {
	for _, item := range items {
		sessionStubWalk(item, func(object map[string]any) {
			if sessionStubNamesSearch(object) {
				for _, id := range sessionStubIdsOf(object) {
					self.callIds[id] = true
				}
			}
		})
	}
	counts := make([]int, len(items))
	for i, item := range items {
		results, err := self.stubResults(item)
		if err != nil {
			return nil, err
		}
		_, matched, err := self.stubStrings(item)
		if err != nil {
			return nil, err
		}
		counts[i] = results + matched
	}
	return counts, nil
}

// A transcript line as the ingest takes it: the stub line in its place where it holds a web_search result, by its
// call, or by a served hash of the line or of a string in it, keeping its newline; the line as it was otherwise. The
// calls it names are noted for the lines after it.
func (self *SessionStubber) StubLine(line []byte) ([]byte, bool, error) {
	newline := 0 < len(line) && line[len(line)-1] == '\n'
	body := strings.TrimRight(string(line), "\r\n")
	if body == "" {
		return line, false, nil
	}
	if stub, ok, err := self.stubOf([]byte(body)); err != nil || ok {
		if err != nil {
			return nil, false, err
		}
		return SessionSearchStubLine(stub, newline), true, nil
	}
	value, err := sessionDecodeJson([]byte(body))
	if err != nil {
		// a line that is no JSON, a line the tail cut short among them: matched by a web_search call it names
		callIds, err := self.knownCallIds()
		if err != nil {
			return nil, false, err
		}
		for _, callId := range callIds {
			if strings.Contains(body, strconv.Quote(callId)) {
				return SessionSearchStubLine(nil, newline), true, nil
			}
		}
		return line, false, nil
	}
	if err := self.noteCalls(value); err != nil {
		return nil, false, err
	}
	var stub []byte
	matched := false
	var lineErr error
	sessionStubWalk(value, func(object map[string]any) {
		if matched || lineErr != nil {
			return
		}
		result, err := self.searchResult(object)
		if err != nil {
			lineErr = err
			return
		}
		if result {
			matched = true
			stub, lineErr = self.resultStub(object)
		}
	})
	if lineErr != nil {
		return nil, false, lineErr
	}
	if !matched {
		sessionStubStrings(value, func(text string) {
			if matched || lineErr != nil {
				return
			}
			found, ok, err := self.stubOf([]byte(text))
			if err != nil {
				lineErr = err
			} else if ok {
				matched, stub = true, found
			}
		})
		if lineErr != nil {
			return nil, false, lineErr
		}
	}
	if !matched {
		return line, false, nil
	}
	return SessionSearchStubLine(stub, newline), true, nil
}

// A hook payload as the ingest takes it: where the event's tool is the MCP web_search (names, or the payload naming
// it), its result members become the stub's text; then each string a served hash names. Answers the payload, rewritten
// only where something was stubbed, and the count.
func (self *SessionStubber) StubPayload(payload []byte, names bool) ([]byte, int, error) {
	value, err := sessionDecodeJson(payload)
	if err != nil {
		if stub, ok, err := self.stubOf(payload); err != nil || ok {
			if err != nil {
				return nil, 0, err
			}
			return []byte(strconv.Quote(SessionSearchStubText(stub))), 1, nil
		}
		return payload, 0, nil
	}
	object, ok := value.(map[string]any)
	count := 0
	if ok && (names || sessionStubNamesSearch(object)) {
		stub, err := self.resultStub(object)
		if err != nil {
			return nil, 0, err
		}
		for _, member := range sessionStubResultMembers {
			if _, held := object[member]; held {
				object[member] = SessionSearchStubText(stub)
				count += 1
			}
		}
	}
	results, err := self.stubResults(value)
	if err != nil {
		return nil, 0, err
	}
	_, matched, err := self.stubStrings(value)
	if err != nil {
		return nil, 0, err
	}
	count += results + matched
	if count == 0 {
		return payload, 0, nil
	}
	rewritten, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	return rewritten, count, nil
}

// The component: the served set once built.
type sidecarSessionServed struct {
	stateLock sync.Mutex
	served    *SessionServedHashes
}

// Registers the component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(sessionServedComponent, func(sidecar *Sidecar) (*sidecarSessionServed, error) {
		return &sidecarSessionServed{}, nil
	}, nil)
}

// The network's served set, built at the first call over its sealed directory: what SRCH's MCP web_search serves into
// and the gateway's recorder and the ingest match against. ErrSidecarStoreLocked before enrollment.
func (self *Sidecar) SessionServedHashes() (*SessionServedHashes, error) {
	component, err := sidecarComputeComponent[sidecarSessionServed](self, sessionServedComponent)
	if err != nil {
		return nil, err
	}
	component.stateLock.Lock()
	defer component.stateLock.Unlock()
	if component.served != nil {
		return component.served, nil
	}
	store, err := self.LocalStore().Directory(sessionServedComponent, sessionComponentName)
	if err != nil {
		return nil, err
	}
	settings := self.settings.Session
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	served, err := NewSessionServedHashes(store, settings, self.settings.ClockOrReal())
	if err != nil {
		return nil, err
	}
	component.served = served
	return served, nil
}
