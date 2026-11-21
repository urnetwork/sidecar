//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The search tools' calls and the daemon's control-mode search methods (§16.10's MCP tools, CLI and wire rows; §5.8's
// control mode; R-MCP-12, D-MCP-13, D-MCP-17, D-MCP-20, D-MCP-25, I-7, I-9, I-13, FS-80; SEARCH-M10-29): one
// implementation of search, search_agents and search_status over a network's engine (SearchTools), which the MCP tools
// (mcp/tools_search.go) and the daemon's control methods both run, so `ur search` and an agent read the same results.
//
//	in        §16.10's search in row: query (required unless filters are set), scope (repo or network), repos,
//	          filters {agent, sidecar, member, run, session, kind[], since, until, path_prefix, fields{subject, from,
//	          to, title}}, group_by (none | agent | run | repo), sort (time | path), latest, more, verify (local |
//	          none), untrusted (withhold | include), fuzzy, limit (hits 1-100, default 20; groups 1-50, default 10),
//	          wait_ms (0-25,000, default 2,000), cursor; a value outside them is refused with constant text that
//	          names no argument's value
//	pages     a call computes its first page whatever its wait, then pages on until it holds limit hits, the search
//	          is done or wait_ms passes on the engine's clock, and answers what landed, with complete false and
//	          next_cursor; hits past limit go back to the cursor, first on its next page, so no page is revised; a
//	          cursor of another session or a forged one is refused, and one an erasure, a CUT, a drop or a lost read
//	          in scope ended answers cursor_expired
//	group_by  a call collects up to HitMaxCount hits and groups those (search_group.go), limit counting groups; the
//	          hits ride in the groups' tops, and a next_cursor groups the hits after them on its own
//	trust     each hit judged for the reader (search_trust.go): untrusted text withheld as stubs unless include, whose
//	          taint lands, fsynced, before any untrusted text is kept (D-MCP-16), and is then put between §16.6's
//	          markers; a hit whose text holds the daemon's credentials is a stub whatever its trust (I-7)
//	open      each hit names the R tool that opens it and its hit_id, opaque and bound to the session, which lasts as
//	          long as its cursor: OpenHit answers what an id names to that session alone, so a stub opens only by it
//	progress  while a call collects pages, phase 2's and "search more"'s included, its report gets the search's
//	          progress; none once the call returns (§16.10's async row)
//	status    per repo the engine's status (§18.5's SidecarSearchStatus), no requester and no query
//	control   search, search.agents and search.status take the tools' arguments on the call's network; a search that
//	          asks for progress gets search.progress notifications on its session until it answers; include first
//	          taints, fsynced, each run whose harness process is the caller's ancestor, by the peer pid the system
//	          reports (§5.8; §16.7's pid ancestry), and a caller whose process cannot be read gets no untrusted text
//
// Not built yet, each refused with constant text rather than narrowed in silence: scope all, which fans out over every
// network the daemon hosts; a named ref; and remote serving counters in search_status, which wait on SEARCH-M10-32's
// served record. verify none checks as local does, since the engine checks only text this host already holds.
//
// The search tools are R: they file no request, sign nothing and are never evidence. No MCP or control path sets a
// remote mode or writes index settings (D-MCP-17). Queries, hits and cursors are never logged (I-13). Safe for
// concurrent use as the engine is.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The control methods the search tools run as, and the notification a search streams (§16.10's wire row).
const (
	DaemonMethodSearch       = "search"
	DaemonMethodSearchAgents = "search.agents"
	DaemonMethodSearchStatus = "search.status"
	// A notification, never a method: a search's progress, sent on its session while the call runs.
	DaemonMethodSearchProgress = "search.progress"
)

var (
	// A search tool's argument outside what §16.10 takes. Constant text: it never echoes an argument.
	ErrSearchToolArguments = errors.New("search: an argument outside §16.10's: a query or filters, and scope, group_by, sort, verify, untrusted, limit and wait_ms within their ranges")
	// A network-bound tool was asked to search every network the daemon hosts.
	ErrSearchToolUnbuilt = errors.New("search: all-network scope requires a host-wide search session")
)

// What a search tool call holds to (§16.10's search in row).
type SearchToolSettings struct {
	// Hits a call returns where it names no limit: 20, and at most 100. Positive, the default within the most.
	HitCount    int
	HitMaxCount int
	// Groups a call returns where it names no limit: 10, and at most 50. Positive, the default within the most.
	GroupCount    int
	GroupMaxCount int
	// How long a call pages where it names no wait: 2 s, and at most 25 s, inside 16.4's 30 s. Positive.
	Wait    time.Duration
	WaitMax time.Duration
	// Hits a cursor keeps for their ids to open, the oldest forgotten first: 4,096, past what a cursor's pages give
	// in its ten minutes at 100 hits a call. Positive.
	OpenHitCount int
}

// The defaults, the only source of their values. A fresh value each call.
func DefaultSearchToolSettings() *SearchToolSettings {
	return &SearchToolSettings{
		HitCount: 20, HitMaxCount: 100, GroupCount: 10, GroupMaxCount: 50, Wait: 2 * time.Second, WaitMax: 25 * time.Second,
		OpenHitCount: 4096,
	}
}

// Refuses values no call can run on.
func (self *SearchToolSettings) check() error {
	if self.HitCount <= 0 || self.HitMaxCount < self.HitCount || self.GroupCount <= 0 || self.GroupMaxCount < self.GroupCount ||
		self.Wait <= 0 || self.WaitMax < self.Wait || self.OpenHitCount <= 0 {
		return fmt.Errorf("%w: the search tools' bounds", errInvalidSettings)
	}
	return nil
}

// search's filters (§16.10's search in row).
type SearchToolFilters struct {
	Agent string `json:"agent,omitempty"`
	// A sidecar or a member, by id.
	Sidecar string   `json:"sidecar,omitempty"`
	Member  string   `json:"member,omitempty"`
	Run     string   `json:"run,omitempty"`
	Session string   `json:"session,omitempty"`
	Kind    []string `json:"kind,omitempty"`
	// RFC 3339, inclusive.
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	// subject, from, to or title, each confining its text to that field.
	Fields map[string]string `json:"fields,omitempty"`
}

// search's arguments, the MCP tool's and the control method's alike.
type SearchToolArgs struct {
	Query     string             `json:"query,omitempty"`
	Scope     string             `json:"scope,omitempty"`
	Repos     []string           `json:"repos,omitempty"`
	Ref       string             `json:"ref,omitempty"`
	Filters   *SearchToolFilters `json:"filters,omitempty"`
	GroupBy   string             `json:"group_by,omitempty"`
	Sort      string             `json:"sort,omitempty"`
	Latest    bool               `json:"latest,omitempty"`
	More      bool               `json:"more,omitempty"`
	Verify    string             `json:"verify,omitempty"`
	Untrusted string             `json:"untrusted,omitempty"`
	Fuzzy     bool               `json:"fuzzy,omitempty"`
	Limit     int                `json:"limit,omitempty"`
	WaitMs    *int               `json:"wait_ms,omitempty"`
	Cursor    string             `json:"cursor,omitempty"`
}

// search_agents' arguments.
type SearchAgentsToolArgs struct {
	Task      string   `json:"task,omitempty"`
	Since     string   `json:"since,omitempty"`
	Until     string   `json:"until,omitempty"`
	Repos     []string `json:"repos,omitempty"`
	Untrusted string   `json:"untrusted,omitempty"`
	Limit     int      `json:"limit,omitempty"`
	WaitMs    *int     `json:"wait_ms,omitempty"`
}

// search_status' arguments.
type SearchStatusToolArgs struct {
	Repos []string `json:"repos,omitempty"`
}

// A hit's document.
type SearchToolDoc struct {
	// file, message, entry, run or announcement.
	Type string `json:"type"`
	// The doc_key in hex: opaque, the same on every reader.
	Key string `json:"key"`
}

// The R tool that opens a hit, and its arguments: a whole file's repo, path and version, which evs_read takes as they
// are; else the hit's id, which a stub opens by alone (§16.10's open row): evs_read and record_query take it, each
// reading it through SearchTools.OpenHit for the session (mcp/tools_hit.go), while mail_read's and directory_list's
// wait on their tools.
type SearchToolOpen struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// One hit as the tools return it (§16.10's search out row). Untrusted strings sit between §16.6's markers.
type SearchToolHit struct {
	HitId   string        `json:"hit_id"`
	RepoId  string        `json:"repo_id"`
	Network string        `json:"network"`
	Ref     string        `json:"ref,omitempty"`
	Doc     SearchToolDoc `json:"doc"`
	Version uint64        `json:"version"`
	Time    string        `json:"time"`
	Kind    string        `json:"kind,omitempty"`
	// confirmed, possible or near; by is text or field for a confirmed one.
	Match      string `json:"match"`
	By         string `json:"by,omitempty"`
	Correction string `json:"correction,omitempty"`
	// local, current, previous, older or all.
	Partition string `json:"partition"`
	Trust     string `json:"trust"`
	// index, or content for a scan of a ref with no index.
	Source string `json:"source"`
	// A stub: its text withheld.
	Stub bool `json:"stub,omitempty"`
	// By field name: subject, from, to, title, or the class's registered names.
	Fields  map[string]string `json:"fields,omitempty"`
	Snippet string            `json:"snippet,omitempty"`
	// The indexer that served it, by config name; empty for this device.
	Indexer string          `json:"indexer,omitempty"`
	Open    *SearchToolOpen `json:"open"`
}

// One run a group holds.
type SearchToolRun struct {
	RunId        string `json:"run_id,omitempty"`
	Title        string `json:"title,omitempty"`
	Started      string `json:"started,omitempty"`
	LastActivity string `json:"last_activity,omitempty"`
	Ended        string `json:"ended,omitempty"`
}

// One claim a group holds.
type SearchToolClaim struct {
	ClaimId string `json:"claim_id"`
	Text    string `json:"text,omitempty"`
	Expires string `json:"expires,omitempty"`
	State   string `json:"state,omitempty"`
}

// One group as the tools return it.
type SearchToolGroup struct {
	Network    string `json:"network,omitempty"`
	Key        string `json:"key"`
	AgentLabel string `json:"agent_label,omitempty"`
	AgentId    string `json:"agent_id,omitempty"`
	// The sidecar's id and its member's, where shown.
	Device       string             `json:"device,omitempty"`
	Member       string             `json:"member,omitempty"`
	Trust        string             `json:"trust"`
	Stub         bool               `json:"stub,omitempty"`
	Active       bool               `json:"active"`
	LastActivity string             `json:"last_activity,omitempty"`
	Runs         []*SearchToolRun   `json:"runs,omitempty"`
	Claims       []*SearchToolClaim `json:"claims,omitempty"`
	HitCount     int                `json:"hit_count"`
	Top          []*SearchToolHit   `json:"top,omitempty"`
}

// A search's counts (§16.10's counts).
type SearchToolCounts struct {
	Confirmed         int `json:"confirmed"`
	Possible          int `json:"possible"`
	Near              int `json:"near"`
	UntrustedWithheld int `json:"untrusted_withheld"`
	Masked            int `json:"masked"`
	Repos             int `json:"repos"`
	Excluded          int `json:"excluded"`
}

// A search call's status (§16.10's status).
type SearchToolStatus struct {
	Complete   bool   `json:"complete"`
	TooBroad   bool   `json:"too_broad,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
	// The call returned untrusted text, the run tainted first.
	Tainted bool `json:"tainted"`
	// The lowest trust of what the call shows.
	Trust        string `json:"trust"`
	MeteredBytes int64  `json:"metered_bytes"`
}

// One ref's coverage in a result, or one repo or ref left out and why.
type SearchToolCoverage struct {
	Network        string `json:"network,omitempty"`
	RepoId         string `json:"repo_id"`
	RefId          string `json:"ref_id,omitempty"`
	IndexedThrough uint64 `json:"indexed_through,omitempty"`
	LatestFrom     string `json:"latest_from,omitempty"`
	All            string `json:"all,omitempty"`
	// searched, or an exclusion's reason.
	State string `json:"state"`
}

// search's result.
type SearchToolResult struct {
	Hits     []*SearchToolHit      `json:"hits"`
	Groups   []*SearchToolGroup    `json:"groups,omitempty"`
	Coverage []*SearchToolCoverage `json:"coverage"`
	Counts   SearchToolCounts      `json:"counts"`
	Status   SearchToolStatus      `json:"status"`
}

// search_agents' result.
type SearchAgentsToolResult struct {
	Groups   []*SearchToolGroup `json:"groups"`
	Counts   SearchToolCounts   `json:"counts"`
	Complete bool               `json:"complete"`
	Tainted  bool               `json:"tainted"`
	Trust    string             `json:"trust"`
}

// A search's progress (§16.10's async row): partitions searched of the total, "search more"'s bytes, changes not yet
// searchable, what it waits on, and its counts so far. Numbers and fixed words only.
type SearchToolProgress struct {
	Searched     int              `json:"searched"`
	Total        int              `json:"total"`
	FetchBytes   int64            `json:"fetch_bytes"`
	FetchedBytes int64            `json:"fetched_bytes"`
	Uncovered    int              `json:"uncovered"`
	Waiting      string           `json:"waiting,omitempty"`
	Counts       SearchToolCounts `json:"counts"`
}

// One repo's status as search_status gives it.
type SearchToolRepoStatus struct {
	Network             string `json:"network,omitempty"`
	RepoId              string `json:"repo_id,omitempty"`
	IndexOn             bool   `json:"index_on"`
	FormatSupported     bool   `json:"format_supported"`
	Policy              string `json:"policy,omitempty"`
	LatestFrom          string `json:"latest_from,omitempty"`
	AllCachedThrough    string `json:"all_cached_through,omitempty"`
	AllCachedByteCount  int64  `json:"all_cached_bytes"`
	AllMissingByteCount int64  `json:"all_missing_bytes"`
	Uncovered           int    `json:"uncovered"`
}

// search_status' result.
type SearchStatusToolResult struct {
	Repos []*SearchToolRepoStatus `json:"repos"`
}

// What the search tools read of one network: its engine, the reader its hits are judged for, and the call's bounds.
// Safe for concurrent use.
type SearchTools struct {
	engine    *SearchEngine
	networkId Id
	reader    func() *SearchTrustReader
	settings  *SearchToolSettings
	// Registers a stream with the cache's open cursors, so a lock ends it; nil registers nothing.
	addCursor func(end func()) func()
	// The team directory's folded view behind search_agents (DirectoryClient.SearchAgentsFold); nil in a personal
	// network and before the directory exists.
	agentsFold func(hits []SearchHit) []SearchHit
	allowRepo  func(Id) bool
}

// Tools over engine, on networkId, judged for reader (nil judges every hit untrusted); nil settings take
// DefaultSearchToolSettings.
func NewSearchTools(engine *SearchEngine, networkId Id, reader func() *SearchTrustReader, settings *SearchToolSettings) (*SearchTools, error) {
	if engine == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	if settings == nil {
		settings = DefaultSearchToolSettings()
	}
	if err := settings.check(); err != nil {
		return nil, err
	}
	if reader == nil {
		reader = func() *SearchTrustReader { return nil }
	}
	return &SearchTools{engine: engine, networkId: networkId, reader: reader, settings: settings}, nil
}

// Narrows the tool view to the caller's current repo grants, including queries and status without named repos.
// The host keeps its own view. Each paged request keeps checking the original session's grant.
func (self *SearchTools) WithRepoAccess(allow func(Id, time.Time) bool) *SearchTools {
	narrowed := *self
	narrowed.allowRepo = func(repo Id) bool { return allow != nil && allow(repo, self.engine.clock.Now()) }
	return &narrowed
}

// The search tools of this Sidecar's network: its installed engine, judged for this sidecar's member by its newest
// verified config state, each search's stream ended by a lock. ErrSidecarSearchUnavailable while no SEARCH-M10-26
// engine is installed.
func (self *Sidecar) SearchTools() (*SearchTools, error) {
	installed, err := self.searchEngine()
	if err != nil {
		return nil, err
	}
	engine, ok := installed.(*SearchEngine)
	if !ok {
		return nil, ErrSidecarSearchUnavailable
	}
	networkId, err := self.searchNetworkId()
	if err != nil {
		return nil, err
	}
	tools, err := NewSearchTools(engine, networkId, self.searchTrustReader, nil)
	if err != nil {
		return nil, err
	}
	if cache, err := self.SearchCache(); err == nil {
		tools.addCursor = cache.AddCursor
	}
	if directory := self.Directory(); directory != nil {
		tools.agentsFold = directory.SearchAgentsFold
	}
	return tools, nil
}

// This sidecar's trust reader (§16.6's team views): its member, each sidecar's member or sponsor and each repo's kind,
// from the newest verified config state. Nil before a state verifies, which reads every hit untrusted.
func (self *Sidecar) searchTrustReader() *SearchTrustReader {
	follower := self.ConfigFollower()
	identity := self.Identity()
	if follower == nil || identity == nil {
		return nil
	}
	state := follower.VerifiedState()
	if state == nil {
		return nil
	}
	memberId, ok := state.searchWriterMember(identity.SidecarId)
	if !ok {
		return nil
	}
	return &SearchTrustReader{
		MemberId: memberId,
		MemberOf: state.searchWriterMember,
		RepoKind: func(repoId Id) protocol.RepoKind {
			return state.Repo(repoId).GetKind()
		},
	}
}

// What one tool call runs with.
type SearchToolEnv struct {
	// The calling session, whose limits, cursors and hit ids the call takes.
	Session Id
	// Taints the call's run, fsynced, before untrusted text joins the result (D-MCP-16); nil refuses include.
	Taint func(ctx context.Context) error
	// Puts an untrusted string between §16.6's markers; nil leaves it as it is.
	Fence func(text string) string
	// Whether text holds the daemon's credentials or a token form; nil matches nothing.
	Secret func(text []byte) bool
	// Gets the search's progress while the call pages, on the call's goroutine or a fetch's, never after the call
	// returns; nil reports nothing.
	Report func(progress *SearchToolProgress)
	// Whether a hit may be named at all, by its repo and whole path: MCP's guard on a search target (QD-673). A hit it
	// refuses is left out before anything of it is shown; nil admits every hit.
	Admit func(repoId Id, path string) bool
}

// A tool time as RFC 3339 in UTC, "" for zero.
func searchToolTime(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}

// An RFC 3339 argument, zero for "".
func searchToolParseTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, ErrSearchToolArguments
	}
	return parsed, nil
}

// The ids of repo arguments.
func searchToolRepoIds(repos []string) ([]Id, error) {
	repoIds := []Id{}
	for _, repo := range repos {
		repoId, err := ParseId(strings.TrimPrefix(repo, "id:"))
		if err != nil {
			return nil, ErrSearchToolArguments
		}
		repoIds = append(repoIds, repoId)
	}
	return repoIds, nil
}

// args as the engine's request: its partitions, repos, times and §16.10's filters, the member's expanded to its
// sidecars by the reader's state.
func searchToolRequest(args *SearchToolArgs, reader *SearchTrustReader, pageSize int) (*SearchRequest, error) {
	request := &SearchRequest{Text: args.Query, Ref: args.Ref, Fuzzy: args.Fuzzy, Scope: SearchCached, PageSize: pageSize}
	switch {
	case args.Latest && args.More:
		return nil, ErrSearchToolArguments
	case args.Latest:
		request.Scope = SearchLatest
	case args.More:
		request.Scope = SearchAll
	}
	var err error
	if request.Repos, err = searchToolRepoIds(args.Repos); err != nil {
		return nil, err
	}
	if args.Ref == string(EvsIndexRefName) || (args.Scope == "repo" || args.Ref != "") && len(request.Repos) == 0 {
		return nil, ErrSearchToolArguments
	}
	if filters := args.Filters; filters != nil {
		if request.Since, err = searchToolParseTime(filters.Since); err != nil {
			return nil, err
		}
		if request.Until, err = searchToolParseTime(filters.Until); err != nil {
			return nil, err
		}
		add := func(name string, value string) {
			if value != "" {
				request.Filters = append(request.Filters, SearchFieldFilter{Name: name, Value: value})
			}
		}
		add("agent", filters.Agent)
		add("run", filters.Run)
		add("session", filters.Session)
		add("path_prefix", filters.PathPrefix)
		if filters.Sidecar != "" {
			sidecarId, err := ParseId(filters.Sidecar)
			if err != nil {
				return nil, ErrSearchToolArguments
			}
			add("sidecar", sidecarId.String())
		}
		for _, kind := range filters.Kind {
			if kind == "" {
				return nil, ErrSearchToolArguments
			}
			add("kind", kind)
		}
		if filters.Member != "" {
			memberId, err := ParseId(filters.Member)
			if err != nil {
				return nil, ErrSearchToolArguments
			}
			// the member's sidecars, one of which wrote the row; a member the state names no sidecar of matches none
			request.Filters = append(request.Filters, SearchFieldFilter{Name: "member", Value: memberId.String()})
		}
		names := []string{}
		for name := range filters.Fields {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if !slices.Contains([]string{"subject", "from", "to", "title"}, name) || filters.Fields[name] == "" {
				return nil, ErrSearchToolArguments
			}
			add(name, filters.Fields[name])
		}
	}
	if strings.TrimSpace(request.Text) == "" && len(request.Filters) == 0 {
		return nil, ErrSearchToolArguments
	}
	return request, nil
}

// A count argument: its default for 0, refused outside [1, maximum].
func searchToolCount(value int, defaultCount int, maxCount int) (int, error) {
	if value == 0 {
		return defaultCount, nil
	}
	if value < 1 || maxCount < value {
		return 0, ErrSearchToolArguments
	}
	return value, nil
}

// The wait a call pages for: wait_ms, else the default, refused below 0 or past the most.
func (self *SearchTools) wait(waitMs *int) (time.Duration, error) {
	if waitMs == nil {
		return self.settings.Wait, nil
	}
	wait := time.Duration(*waitMs) * time.Millisecond
	if *waitMs < 0 || self.settings.WaitMax < wait {
		return 0, ErrSearchToolArguments
	}
	return wait, nil
}

// Whether an untrusted argument asks for untrusted text.
func searchToolInclude(untrusted string) (bool, error) {
	switch untrusted {
	case "", "withhold":
		return false, nil
	case "include":
		return true, nil
	}
	return false, ErrSearchToolArguments
}

// The doc type a hit shows: file, message, entry, run or announcement.
func searchToolDocType(hit *SearchHit, reader *SearchTrustReader) string {
	switch indexDocKind(hit.DocKind) {
	case indexDocMail:
		return "message"
	case indexDocRecord:
		return "entry"
	case indexDocDerived:
		if reader.directory(hit.Repo) {
			return "announcement"
		}
		return "run"
	}
	return "file"
}

// A field's name in a hit's result: §11.14's header names, else the class's registered name, else its number.
func searchToolFieldName(field int, registry *IndexFieldRegistry) string {
	switch field {
	case indexFieldSubject:
		return "subject"
	case indexFieldFrom:
		return "from"
	case indexFieldTo:
		return "to"
	case indexFieldTitle:
		return "title"
	}
	if registry != nil && indexFieldFirstRegistered <= field && field <= indexFieldLast {
		if name := registry.FieldNames[field-indexFieldFirstRegistered]; name != "" {
			return name
		}
	}
	return strconv.Itoa(field)
}

// A shown hit as the tools return it, its untrusted strings fenced.
func (self *SearchTools) toolHitOf(session Id, view *SearchHit, reader *SearchTrustReader, fence func(text string) string) *SearchToolHit {
	untrusted := !view.Withheld && !view.Trust.shown()
	text := func(value string) string {
		if untrusted && fence != nil && value != "" {
			return fence(value)
		}
		return value
	}
	out := &SearchToolHit{
		HitId:      self.engine.cursors.hitId(session, view),
		RepoId:     view.Repo.String(),
		Network:    self.networkId.String(),
		Doc:        SearchToolDoc{Type: searchToolDocType(view, reader), Key: hex.EncodeToString(view.DocKey[:])},
		Version:    view.Version,
		Time:       searchToolTime(view.Time),
		Kind:       searchHitField(view, searchFieldKind),
		Correction: text(view.Correction),
		Partition:  view.PartitionName,
		Trust:      string(searchTrustMin(view.Trust, view.Trust)),
		Source:     "index",
		Stub:       view.Withheld,
		Snippet:    text(view.Snippet),
		Indexer:    view.By,
	}
	if view.Ref != (Id{}) {
		out.Ref = view.Ref.String()
	}
	switch view.State {
	case SearchVerified:
		out.Match, out.By = "confirmed", "text"
	case SearchConfirmed:
		out.Match, out.By = "confirmed", "field"
	case SearchNear:
		out.Match = "near"
	default:
		out.Match = "possible"
	}
	if out.Partition == "" {
		// a scan of a ref with no index (§11.14's off row)
		out.Partition, out.Source = "current", "content"
	}
	// a registered class's names: the directory's in the team directory, a record log's on any other record or derived
	// row
	var registry *IndexFieldRegistry
	switch {
	case reader.directory(view.Repo):
		registry = indexDirectoryFieldRegistry()
	case indexDocKind(view.DocKind).hasRegisteredFields():
		registry = indexRecordFieldRegistry()
	}
	for _, field := range view.Fields {
		if out.Fields == nil {
			out.Fields = map[string]string{}
		}
		out.Fields[searchToolFieldName(field.Field, registry)] = text(field.Text)
	}
	if view.Signer != (Id{}) {
		if out.Fields == nil {
			out.Fields = map[string]string{}
		}
		out.Fields[searchToolFieldName(searchFieldWriter, registry)] = view.Signer.String()
	}
	open := map[string]any{"hit": out.HitId}
	switch out.Doc.Type {
	case "message":
		out.Open = &SearchToolOpen{Tool: "mail_read", Arguments: open}
	case "entry", "run":
		out.Open = &SearchToolOpen{Tool: "record_query", Arguments: open}
	case "announcement":
		out.Open = &SearchToolOpen{Tool: "directory_list", Arguments: open}
	default:
		if !view.Withheld && !untrusted && view.refName == "" {
			// a file's own or a member's: evs_read takes its repo, path and version as they are
			open = map[string]any{"repo": out.RepoId, "path": view.Path, "version": view.Version}
		}
		out.Open = &SearchToolOpen{Tool: "evs_read", Arguments: open}
	}
	return out
}

// A group as the tools return it.
func (self *SearchTools) toolGroupOf(session Id, group *SearchGroup, reader *SearchTrustReader, fence func(text string) string) *SearchToolGroup {
	untrusted := !group.Trust.shown()
	text := func(value string) string {
		if untrusted && fence != nil && value != "" {
			return fence(value)
		}
		return value
	}
	out := &SearchToolGroup{
		Key: group.Key, AgentLabel: text(group.AgentLabel), AgentId: group.AgentId, Trust: string(group.Trust), Stub: group.Stub,
		Active: group.Active, LastActivity: searchToolTime(group.LastActivity), HitCount: group.HitCount,
	}
	if group.SidecarId != nil {
		out.Device = group.SidecarId.String()
	}
	if group.MemberId != nil {
		out.Member = group.MemberId.String()
	}
	for _, run := range group.Runs {
		out.Runs = append(out.Runs, &SearchToolRun{
			RunId: run.RunId, Title: text(run.Title), Started: searchToolTime(run.Started), LastActivity: searchToolTime(run.LastActivity),
			Ended: searchToolTime(run.Ended),
		})
	}
	for _, claim := range group.Claims {
		out.Claims = append(out.Claims, &SearchToolClaim{ClaimId: claim.ClaimId, Text: text(claim.Text), Expires: searchToolTime(claim.Expires), State: claim.State})
	}
	for index := range group.Top {
		out.Top = append(out.Top, self.toolHitOf(session, &group.Top[index], reader, fence))
	}
	return out
}

// A progress as the tools give it.
func searchToolProgressOf(progress *SearchProgress) *SearchToolProgress {
	return &SearchToolProgress{
		Searched: progress.Searched, Total: progress.Total, FetchBytes: progress.FetchBytes, FetchedBytes: progress.FetchedBytes,
		Uncovered: progress.Uncovered, Waiting: progress.Waiting, Counts: searchToolCountsOf(progress),
	}
}

// A progress's counts as the tools give them.
func searchToolCountsOf(progress *SearchProgress) SearchToolCounts {
	return SearchToolCounts{
		Confirmed: progress.Counts.Confirmed, Possible: progress.Counts.Possible, Near: progress.Counts.Near,
		Masked: progress.Counts.Masked, Repos: progress.Counts.Repos, Excluded: progress.Counts.Excluded,
	}
}

// A search's stream for a call: the cursor's, resumed in the call's session, or a new search of args.
func (self *SearchTools) stream(ctx context.Context, session Id, args *SearchToolArgs, reader *SearchTrustReader, pageSize int) (*searchEngineStream, string, error) {
	if args.Cursor != "" {
		self.engine.cursors.sweep()
		stream, err := self.engine.cursors.take(session, args.Cursor)
		return stream, args.Cursor, err
	}
	request, err := searchToolRequest(args, reader, pageSize)
	if err != nil {
		return nil, "", err
	}
	request.allowRepo = self.allowRepo
	stream, token, err := self.engine.open(ctx, session, request)
	if err != nil {
		return nil, "", err
	}
	if self.addCursor != nil {
		stream.onClose(self.addCursor(stream.Close))
	}
	return stream, token, nil
}

// Runs one search call: see the file header.
func (self *SearchTools) Search(ctx context.Context, env *SearchToolEnv, args *SearchToolArgs) (*SearchToolResult, error) {
	if env == nil || args == nil {
		return nil, ErrSearchToolArguments
	}
	include, err := searchToolInclude(args.Untrusted)
	if err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"", "none", "agent", "run", "repo"}, args.GroupBy) || !slices.Contains([]string{"", "time", "path"}, args.Sort) ||
		!slices.Contains([]string{"", "local", "none"}, args.Verify) || !slices.Contains([]string{"", "repo", "network", "all"}, args.Scope) {
		return nil, ErrSearchToolArguments
	}
	if args.Scope == "all" {
		return nil, ErrSearchToolUnbuilt
	}
	if include && env.Taint == nil {
		return nil, ErrSearchToolInclude
	}
	by := SearchGroupBy(args.GroupBy)
	if by == "none" {
		by = SearchGroupByNone
	}
	count, err := searchToolCount(args.Limit, self.settings.HitCount, self.settings.HitMaxCount)
	groupCount := 0
	if by != SearchGroupByNone {
		groupCount, err = searchToolCount(args.Limit, self.settings.GroupCount, self.settings.GroupMaxCount)
		count = self.settings.HitMaxCount
	}
	if err != nil {
		return nil, err
	}
	wait, err := self.wait(args.WaitMs)
	if err != nil {
		return nil, err
	}
	reader := self.reader()
	stream, token, err := self.stream(ctx, env.Session, args, reader, count)
	if err != nil {
		return nil, err
	}
	var report func(progress SearchProgress)
	if env.Report != nil {
		report = func(progress SearchProgress) {
			env.Report(searchToolProgressOf(&progress))
		}
	}
	// a new search this call cannot answer ends with it: its cursor is never given out
	abandon := func() {
		if args.Cursor == "" {
			self.engine.cursors.finish(env.Session, token)
		}
	}
	hits, progress, done, err := searchCollect(ctx, stream, self.engine.clock, count, wait, report)
	if err != nil {
		abandon()
		return nil, err
	}
	if env.Admit != nil {
		hits = slices.DeleteFunc(hits, func(hit SearchHit) bool { return !env.Admit(hit.Repo, hit.Path) })
	}
	switch args.Sort {
	case "path":
		slices.SortStableFunc(hits, func(a SearchHit, b SearchHit) int { return strings.Compare(a.Path, b.Path) })
	case "time":
		slices.SortStableFunc(hits, func(a SearchHit, b SearchHit) int { return b.Time.Compare(a.Time) })
	}
	searchJudgeTrust(hits, reader)
	withheld, err := searchWithhold(ctx, hits, &searchWithholdArgs{reader: reader, include: include, taint: env.Taint, secret: env.Secret})
	if err != nil {
		abandon()
		return nil, err
	}
	self.engine.cursors.noteHits(env.Session, token, hits, self.settings.OpenHitCount)
	result := &SearchToolResult{Hits: []*SearchToolHit{}, Coverage: []*SearchToolCoverage{}, Counts: searchToolCountsOf(&progress)}
	result.Counts.UntrustedWithheld = withheld.untrustedCount + withheld.secretCount
	result.Status = SearchToolStatus{
		Complete: done, TooBroad: progress.TooBroad, Tainted: withheld.untrusted, Trust: string(withheld.trust), MeteredBytes: progress.FetchedBytes,
	}
	if done {
		// no page is left; the cursor stays, its hit ids opening until it idles out
		self.engine.cursors.finish(env.Session, token)
	} else {
		result.Status.NextCursor = token
	}
	result.Coverage = searchToolCoverageOf(&progress)
	if by != SearchGroupByNone {
		groups := searchGroup(hits, withheld.hits, by, self.networkId, self.engine.clock.Now(), reader, self.engine.groups)
		for _, group := range groups[:min(len(groups), groupCount)] {
			result.Groups = append(result.Groups, self.toolGroupOf(env.Session, group, reader, env.Fence))
		}
	} else {
		for index := range withheld.hits {
			result.Hits = append(result.Hits, self.toolHitOf(env.Session, &withheld.hits[index], reader, env.Fence))
		}
	}
	if stream.scopeEnded() {
		return nil, ErrSearchCursorExpired
	}
	return result, nil
}

// Formats ref coverage and exclusion reasons together for the tool response.
func searchToolCoverageOf(progress *SearchProgress) []*SearchToolCoverage {
	rows := make([]*SearchToolCoverage, 0, len(progress.Coverage)+len(progress.Excluded))
	for _, coverage := range progress.Coverage {
		rows = append(rows, &SearchToolCoverage{
			RepoId: coverage.RepoId.String(), RefId: coverage.RefId.String(), IndexedThrough: coverage.IndexedThrough,
			LatestFrom: searchToolTime(coverage.LatestFrom), All: coverage.All, State: coverage.State,
		})
	}
	for _, exclusion := range progress.Excluded {
		row := &SearchToolCoverage{RepoId: exclusion.RepoId.String(), State: exclusion.Reason}
		if exclusion.RefId != nil {
			row.RefId = exclusion.RefId.String()
		}
		rows = append(rows, row)
	}
	return rows
}

// Runs one search_agents call.
func (self *SearchTools) Agents(ctx context.Context, env *SearchToolEnv, args *SearchAgentsToolArgs) (*SearchAgentsToolResult, error) {
	if env == nil || args == nil {
		return nil, ErrSearchToolArguments
	}
	include, err := searchToolInclude(args.Untrusted)
	if err != nil {
		return nil, err
	}
	if include && env.Taint == nil {
		return nil, ErrSearchToolInclude
	}
	groupCount, err := searchToolCount(args.Limit, self.settings.GroupCount, self.settings.GroupMaxCount)
	if err != nil {
		return nil, err
	}
	wait, err := self.wait(args.WaitMs)
	if err != nil {
		return nil, err
	}
	reader := self.reader()
	request := &SearchAgentsRequest{
		Task: args.Task, GroupCount: groupCount, Include: include, Taint: env.Taint, Reader: reader, Secret: env.Secret, Admit: env.Admit,
		Wait: wait, Fold: self.agentsFold, allowRepo: self.allowRepo,
	}
	if request.Since, err = searchToolParseTime(args.Since); err != nil {
		return nil, err
	}
	if request.Until, err = searchToolParseTime(args.Until); err != nil {
		return nil, err
	}
	if request.Repos, err = searchToolRepoIds(args.Repos); err != nil {
		return nil, err
	}
	agents, err := self.engine.Agents(ctx, env.Session, self.networkId, request)
	if err != nil {
		return nil, err
	}
	self.engine.cursors.noteHits(env.Session, agents.cursor, agents.hits, self.settings.OpenHitCount)
	result := &SearchAgentsToolResult{
		Groups: []*SearchToolGroup{}, Complete: agents.Complete, Tainted: agents.Untrusted, Trust: string(agents.Trust),
		Counts: SearchToolCounts{
			Confirmed: agents.Counts.Confirmed, Possible: agents.Counts.Possible, Near: agents.Counts.Near, Masked: agents.Counts.Masked,
			Repos: agents.Counts.Repos, Excluded: agents.Counts.Excluded, UntrustedWithheld: agents.UntrustedWithheld + agents.SecretWithheld,
		},
	}
	for _, group := range agents.Groups {
		result.Groups = append(result.Groups, self.toolGroupOf(env.Session, group, reader, env.Fence))
	}
	if err := self.engine.cursors.visit(env.Session, agents.cursor, nil); err != nil {
		return nil, err
	}
	return result, nil
}

// Runs one search_status call: each named repo's status, or every repo's together. A status carries no requester and
// no query.
func (self *SearchTools) Status(args *SearchStatusToolArgs) (*SearchStatusToolResult, error) {
	if args == nil {
		return nil, ErrSearchToolArguments
	}
	repoIds, err := searchToolRepoIds(args.Repos)
	if err != nil {
		return nil, err
	}
	result := &SearchStatusToolResult{Repos: []*SearchToolRepoStatus{}}
	read := func(repoId *Id) error {
		status, err := self.engine.status(repoId, self.allowRepo)
		if err != nil {
			return err
		}
		repo := &SearchToolRepoStatus{
			IndexOn: status.IndexOn, FormatSupported: status.FormatSupported, Policy: status.Policy,
			LatestFrom: searchToolTime(status.LatestFrom), AllCachedThrough: searchToolTime(status.AllCachedThrough),
			AllCachedByteCount: status.AllCachedByteCount, AllMissingByteCount: status.AllMissingByteCount, Uncovered: status.Uncovered,
		}
		if repoId != nil {
			repo.RepoId = repoId.String()
		}
		result.Repos = append(result.Repos, repo)
		return nil
	}
	if len(repoIds) == 0 {
		return result, read(nil)
	}
	for _, repoId := range repoIds {
		if self.allowRepo != nil && !self.allowRepo(repoId) {
			continue
		}
		if err := read(&repoId); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// What a hit id names, for session alone, while the cursor that gave it lives: what evs_read, mail_read, record_query
// and directory_list open a hit by (§16.10's open row). ErrSearchHitUnknown for any other id.
func (self *SearchTools) OpenHit(session Id, hitId string) (*SearchHitRef, error) {
	return self.engine.cursors.openHit(session, hitId)
}

// Ends what session holds on this network's engine, its cursors, hit ids and limits (SearchEngine.EndSession): what
// an MCP session's close calls in each network it searched in (D-MCP-25).
func (self *SearchTools) EndSession(session Id) {
	self.engine.EndSession(session)
}

// Each control session's search session: its cursors, limits and hit ids are its own. Once the session ends its id is
// forgotten, and each engine it searched in ends what it held there (SearchEngine.EndSession), as an MCP session's
// close does (D-MCP-25).
type daemonSearchSessions struct {
	// called once an ended session's engines ended it: a test's seam, nil otherwise
	endedHook func(session Id)

	stateLock  sync.Mutex
	sessionIds map[<-chan struct{}]Id
	// the engines each session searched in
	sessionIdEngines map[Id]map[*SearchEngine]bool
}

// The search session of call's control session, minted at its first search, which tools' engine ends at the
// session's end; a call no session reader watches is a session of its own.
func (self *daemonSearchSessions) of(call *DaemonCall, tools *SearchTools) Id {
	if call.SessionDone == nil {
		return NewId()
	}
	sessionId, added := func() (Id, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.sessionIds == nil {
			self.sessionIds = map[<-chan struct{}]Id{}
			self.sessionIdEngines = map[Id]map[*SearchEngine]bool{}
		}
		sessionId, ok := self.sessionIds[call.SessionDone]
		if !ok {
			sessionId = NewId()
			self.sessionIds[call.SessionDone] = sessionId
			self.sessionIdEngines[sessionId] = map[*SearchEngine]bool{}
		}
		if tools != nil {
			self.sessionIdEngines[sessionId][tools.engine] = true
		}
		return sessionId, !ok
	}()
	if added {
		// forgotten when the session ends, which ends this wait
		go func(done <-chan struct{}) {
			<-done
			engines := func() map[*SearchEngine]bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.sessionIds, done)
				engines := self.sessionIdEngines[sessionId]
				delete(self.sessionIdEngines, sessionId)
				return engines
			}()
			for engine := range engines {
				engine.EndSession(sessionId)
			}
			if self.endedHook != nil {
				self.endedHook(sessionId)
			}
		}(call.SessionDone)
	}
	return sessionId
}

// What the control methods act through, for the call's Sidecar. A nil Tools, TaintAncestors or Secret takes the
// Sidecar's own.
type DaemonSearchBackends struct {
	// The network's search tools: Sidecar.SearchTools.
	Tools func(sidecar *Sidecar) (*SearchTools, error)
	// Taints, fsynced, each run of the network whose harness process is an ancestor of pid: Sidecar.TaintAncestorRuns.
	TaintAncestors func(ctx context.Context, sidecar *Sidecar, pid int) error
	// The daemon's credentials as a matcher (I-7): Sidecar.SecretMatcher's, an error while it cannot be read.
	Secret func(sidecar *Sidecar) (func(text []byte) bool, error)
	// Called once an ended control session's engines ended what it held: a test's seam, nil otherwise.
	sessionEnded func(session Id)
}

// search's control params: the tool's arguments, the call's network, and whether to stream search.progress.
type daemonSearchParams struct {
	SearchToolArgs
	Network  string `json:"network,omitempty"`
	Progress bool   `json:"progress,omitempty"`
}

// search.agents' control params.
type daemonSearchAgentsParams struct {
	SearchAgentsToolArgs
	Network string `json:"network,omitempty"`
}

// search.status' control params.
type daemonSearchStatusParams struct {
	SearchStatusToolArgs
	Network string `json:"network,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// The daemon's control-mode search methods over backends: search, search.agents and search.status, each on its call's
// network with the MCP tools' arguments, none a Confirm one (they sign nothing). The daemon's composition registers
// them with RegisterMethod.
func DaemonSearchMethods(backends *DaemonSearchBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonSearchBackends{}
	}
	toolsOf := backends.Tools
	if toolsOf == nil {
		toolsOf = func(sidecar *Sidecar) (*SearchTools, error) {
			return sidecar.SearchTools()
		}
	}
	taintAncestors := backends.TaintAncestors
	if taintAncestors == nil {
		taintAncestors = func(ctx context.Context, sidecar *Sidecar, pid int) error {
			return sidecar.TaintAncestorRuns(ctx, pid)
		}
	}
	secretOf := backends.Secret
	if secretOf == nil {
		secretOf = func(sidecar *Sidecar) (func(text []byte) bool, error) {
			matcher, err := sidecar.SecretMatcher()
			if err != nil {
				return nil, err
			}
			return matcher.Matches, nil
		}
	}
	sessions := &daemonSearchSessions{endedHook: backends.sessionEnded}
	decode := func(call *DaemonCall, params any) error {
		if len(call.Params) == 0 {
			return nil
		}
		decoder := json.NewDecoder(strings.NewReader(string(call.Params)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(params); err != nil {
			return ErrSearchToolArguments
		}
		return nil
	}
	envOf := func(call *DaemonCall) (*SearchTools, *SearchToolEnv, error) {
		if call.Sidecar == nil {
			return nil, nil, ErrSidecarSearchUnavailable
		}
		tools, err := toolsOf(call.Sidecar)
		if err != nil {
			return nil, nil, err
		}
		env := &SearchToolEnv{
			Session: sessions.of(call, tools),
			// the caller's harness runs read untrusted text through this answer: they are tainted first, by the pid the
			// system reports for the socket's peer, never the hello's, which the caller writes (§5.8)
			Taint: func(ctx context.Context) error {
				pid := 0
				if call.Hello != nil {
					pid = int(call.Hello.PeerPid)
				}
				if pid <= 0 {
					return errors.New("the caller's process cannot be read, so no untrusted text is returned")
				}
				return taintAncestors(ctx, call.Sidecar, pid)
			},
		}
		return tools, env, nil
	}
	// the daemon's credentials, which a hit holding one is withheld for (I-7): a call whose result could carry text is
	// refused while they cannot be read, as MCP's tools are
	matcherOf := func(call *DaemonCall, env *SearchToolEnv) error {
		secret, err := secretOf(call.Sidecar)
		if err != nil {
			return fmt.Errorf("the daemon's credentials cannot be read to check the result: %w", err)
		}
		env.Secret = secret
		return nil
	}
	return []*DaemonMethod{
		{
			Name:        DaemonMethodSearch,
			Network:     true,
			allNetworks: daemonSearchAllScope,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &daemonSearchParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				if params.Scope == "all" || strings.HasPrefix(params.Cursor, daemonSearchAllPrefix) {
					return daemonSearchAll(ctx, call, params, envOf, matcherOf)
				}
				tools, env, err := envOf(call)
				if err != nil {
					return nil, err
				}
				if err := matcherOf(call, env); err != nil {
					return nil, err
				}
				if params.Progress && call.Notify != nil {
					env.Report = func(progress *SearchToolProgress) {
						// a notification past the call's answer is dropped by the session
						call.Notify(DaemonMethodSearchProgress, progress)
					}
				}
				return tools.Search(ctx, env, &params.SearchToolArgs)
			},
		},
		{
			Name:    DaemonMethodSearchAgents,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &daemonSearchAgentsParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				tools, env, err := envOf(call)
				if err != nil {
					return nil, err
				}
				if err := matcherOf(call, env); err != nil {
					return nil, err
				}
				return tools.Agents(ctx, env, &params.SearchAgentsToolArgs)
			},
		},
		{
			Name:        DaemonMethodSearchStatus,
			Network:     true,
			allNetworks: daemonSearchAllScope,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &daemonSearchStatusParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				if params.Scope == "all" {
					if params.Network != "" || len(params.Repos) > 0 {
						return nil, ErrSearchToolArguments
					}
					if len(call.Networks) == 0 {
						return nil, ErrSidecarSearchUnavailable
					}
					out := &SearchStatusToolResult{Repos: []*SearchToolRepoStatus{}}
					for _, network := range call.Networks {
						tools, err := toolsOf(network.Sidecar)
						if err != nil {
							return nil, err
						}
						status, err := tools.Status(&params.SearchStatusToolArgs)
						if err != nil {
							return nil, err
						}
						for _, repo := range status.Repos {
							repo.Network = network.NetworkId.String()
							out.Repos = append(out.Repos, repo)
						}
					}
					return out, nil
				}
				tools, _, err := envOf(call)
				if err != nil {
					return nil, err
				}
				return tools.Status(&params.SearchStatusToolArgs)
			},
		},
	}
}
