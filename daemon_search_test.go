//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// SEARCH-M10-29's tests of the search tools' calls and control methods (§16.10's MCP tools and wire rows; §5.8; FS-80;
// §22.6's MCP-arguments target; I-7, I-9, I-13, D-MCP-16): arguments outside §16.10's ranges refused with constant
// text; pages by cursor in one session, a cursor of another refused, no hit given twice and limit's surplus kept for
// the next page; untrusted text withheld as a stub, include tainting the run first and a failed taint failing the
// call; hit ids opening in their own session alone; the guard's admission leaving a hit out before anything of it
// shows; progress reported while a call pages and never after; the control methods on the call's network, none a
// Confirm one, include tainting the caller's ancestor runs by the peer pid and refused for a caller whose process
// cannot be read; search.progress streamed on a session before the answer and dropped after it; a status naming no
// requester or query.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Tools over the world's engine, read by testTrustReader's member.
func testSearchTools(t *testing.T, world *testEngineWorld) *SearchTools {
	t.Helper()
	tools, err := NewSearchTools(world.engine, evsTestId("network"), testTrustReader, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tools
}

func TestSearchToolsRefuseArgumentsOutsideTheirRanges(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/a.md", "rate limiter notes"))
	tools := testSearchTools(t, world)
	env := &SearchToolEnv{Session: NewId()}
	tooLong, negative := 25001, -1
	for _, args := range []*SearchToolArgs{
		{},
		{Query: "limiter", WaitMs: &tooLong},
		{Query: "limiter", WaitMs: &negative},
		{Query: "limiter", Limit: 101},
		{Query: "limiter", Limit: -1},
		{Query: "limiter", GroupBy: "agent", Limit: 51},
		{Query: "limiter", Scope: "galaxy"},
		{Query: "limiter", Scope: "repo"},
		{Query: "limiter", GroupBy: "colour"},
		{Query: "limiter", Untrusted: "maybe"},
		{Query: "limiter", Verify: "fetch"},
		{Query: "limiter", Sort: "size"},
		{Query: "limiter", Latest: true, More: true},
		{Query: "limiter", Repos: []string{"not a repo"}},
		{Query: "limiter", Filters: &SearchToolFilters{Fields: map[string]string{"body": "x"}}},
		{Query: "limiter", Filters: &SearchToolFilters{Since: "yesterday"}},
		{Query: "limiter", Filters: &SearchToolFilters{Sidecar: "not an id"}},
		{Query: "limiter", Filters: &SearchToolFilters{Member: "not an id"}},
		{Query: "limiter", Filters: &SearchToolFilters{Kind: []string{""}}},
	} {
		if _, err := tools.Search(context.Background(), env, args); !errors.Is(err, ErrSearchToolArguments) {
			t.Errorf("%+v: %v", args, err)
		}
	}
	for _, args := range []*SearchToolArgs{{Query: "limiter", Scope: "all"}, {Query: "limiter", Ref: "main"}} {
		if _, err := tools.Search(context.Background(), env, args); !errors.Is(err, ErrSearchToolUnbuilt) {
			t.Errorf("%+v: %v", args, err)
		}
	}
	// every refusal's text is constant: none echoes what it was given
	if _, err := tools.Search(context.Background(), env, &SearchToolArgs{Query: "limiter", Scope: "synthetic-canary-scope"}); err == nil || strings.Contains(err.Error(), "canary") {
		t.Errorf("a refusal echoed its argument: %v", err)
	}
	// include where nothing can taint the run first
	if _, err := tools.Search(context.Background(), env, &SearchToolArgs{Query: "limiter", Untrusted: "include"}); !errors.Is(err, ErrSearchToolInclude) {
		t.Errorf("include with no taint: %v", err)
	}
	if _, err := tools.Agents(context.Background(), env, &SearchAgentsToolArgs{Task: "limiter", Untrusted: "include"}); !errors.Is(err, ErrSearchToolInclude) {
		t.Errorf("search_agents' include with no taint: %v", err)
	}
	// filters alone are a search
	if result, err := tools.Search(context.Background(), env, &SearchToolArgs{Filters: &SearchToolFilters{PathPrefix: "notes/"}}); err != nil || len(result.Hits) != 1 {
		t.Errorf("a path prefix alone: %v", err)
	}
}

// A call returns limit hits and a cursor the same session resumes, the surplus of a page given first next; another
// session's use of the cursor is refused; every hit comes once, and the search completes.
func TestSearchToolsPageByCursorInOneSession(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 6 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%d.md", index), "rate limiter notes"))
	}
	world := newTestEngineWorld(t, nil, documents...)
	tools := testSearchTools(t, world)
	mine, theirs := &SearchToolEnv{Session: NewId()}, &SearchToolEnv{Session: NewId()}
	first, err := tools.Search(context.Background(), mine, &SearchToolArgs{Query: "limiter", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status.Complete || first.Status.NextCursor == "" || len(first.Hits) != 2 {
		t.Fatalf("a first page of two: complete %v, cursor %q, %d hits", first.Status.Complete, first.Status.NextCursor, len(first.Hits))
	}
	if _, err := tools.Search(context.Background(), theirs, &SearchToolArgs{Cursor: first.Status.NextCursor}); !errors.Is(err, ErrSearchCursorInvalid) {
		t.Fatalf("another session's cursor: %v", err)
	}
	if _, err := tools.Search(context.Background(), mine, &SearchToolArgs{Cursor: "forged" + first.Status.NextCursor}); !errors.Is(err, ErrSearchCursorInvalid) {
		t.Fatalf("a forged cursor: %v", err)
	}
	seen := map[string]bool{}
	for _, hit := range first.Hits {
		seen[hit.HitId] = true
	}
	cursor := first.Status.NextCursor
	for range 20 {
		page, err := tools.Search(context.Background(), mine, &SearchToolArgs{Cursor: cursor, Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		if 3 < len(page.Hits) {
			t.Fatalf("a page of %d past its limit", len(page.Hits))
		}
		for _, hit := range page.Hits {
			if seen[hit.HitId] {
				t.Fatal("a page gave a hit again")
			}
			seen[hit.HitId] = true
		}
		if page.Status.Complete {
			if page.Status.NextCursor != "" || len(seen) != 6 {
				t.Fatalf("%d hits over the pages, cursor %q", len(seen), page.Status.NextCursor)
			}
			if _, err := tools.Search(context.Background(), mine, &SearchToolArgs{Cursor: cursor}); !errors.Is(err, ErrSearchCursorExpired) {
				t.Fatalf("a finished search's cursor: %v", err)
			}
			return
		}
		cursor = page.Status.NextCursor
	}
	t.Fatal("the search never completed")
}

// FS-80: a tainted run's entry comes back as a stub, counted, the run untainted and nothing fenced; include taints the
// run before its text is in the result, fenced; a failed taint fails the call and returns nothing.
func TestSearchToolsIncludeTaintsTheRunFirst(t *testing.T) {
	world := newTestEngineWorld(t, nil,
		testAgentsDocument(t, "note", 1, "note", evsTestId("dana laptop"), "scraper", "rate limiter from a pasted page", time.Time{}, true),
	)
	world.scope.repos[0].Kind = protocol.RepoKind_REPO_KIND_VAULT
	tools := testSearchTools(t, world)
	tainted, fenced := 0, 0
	env := &SearchToolEnv{Session: NewId(), Taint: func(ctx context.Context) error {
		tainted += 1
		return nil
	}, Fence: func(text string) string {
		fenced += 1
		return "<<" + text + ">>"
	}}
	withheld, err := tools.Search(context.Background(), env, &SearchToolArgs{Query: "limiter"})
	if err != nil {
		t.Fatal(err)
	}
	if len(withheld.Hits) != 1 || withheld.Counts.UntrustedWithheld != 1 || withheld.Status.Tainted || tainted != 0 || fenced != 0 {
		t.Fatalf("withheld: %d hits, %d withheld, tainted %v (%d), fenced %d", len(withheld.Hits), withheld.Counts.UntrustedWithheld, withheld.Status.Tainted, tainted, fenced)
	}
	stub := withheld.Hits[0]
	if !stub.Stub || stub.Snippet != "" || stub.Fields["title"] != "" || stub.Fields["agent"] != "" || stub.Kind != "note" ||
		stub.Trust != string(SearchTrustUntrusted) || stub.Open.Arguments["hit"] != stub.HitId || stub.Open.Arguments["path"] != nil ||
		withheld.Status.Trust != string(SearchTrustMember) {
		t.Fatalf("a stub: %+v, the result's trust %s", stub, withheld.Status.Trust)
	}
	included, err := tools.Search(context.Background(), env, &SearchToolArgs{Query: "limiter", Untrusted: "include"})
	if err != nil {
		t.Fatal(err)
	}
	if tainted != 1 || !included.Status.Tainted || included.Status.Trust != string(SearchTrustUntrusted) || included.Hits[0].Stub ||
		included.Hits[0].Fields["title"] != "<<rate limiter from a pasted page>>" || included.Hits[0].Fields["agent"] != "<<scraper>>" {
		t.Fatalf("include: tainted %d, %+v", tainted, included.Hits[0])
	}
	env.Taint = func(ctx context.Context) error { return errors.New("the run file could not be written") }
	if result, err := tools.Search(context.Background(), env, &SearchToolArgs{Query: "limiter", Untrusted: "include"}); err == nil || result != nil {
		t.Fatal("a failed taint returned untrusted text")
	}
}

// A hit id opens what it names in its own session while its cursor lives; another session, and a forged id, open
// nothing; the guard's admission leaves a hit out before anything of it is shown.
func TestSearchToolsHitIdsOpenInTheirSessionAlone(t *testing.T) {
	world := newTestEngineWorld(t, nil,
		testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "harbor lights"),
		testEngineDocument(t, "doc", 2, 1, "private/harbor.md", "harbor plans"),
	)
	tools := testSearchTools(t, world)
	mine := &SearchToolEnv{Session: NewId()}
	result, err := tools.Search(context.Background(), mine, &SearchToolArgs{Query: "harbor"})
	if err != nil || len(result.Hits) != 2 {
		t.Fatalf("%v, %+v", err, result)
	}
	for _, hit := range result.Hits {
		opened, err := tools.OpenHit(mine.Session, hit.HitId)
		if err != nil || opened.RepoId != world.sync.repoId || opened.RefId != world.sync.refId || opened.Version != 1 || !strings.HasSuffix(opened.Path, "/harbor.md") {
			t.Fatalf("opening %s: %+v %v", hit.HitId, opened, err)
		}
		if _, err := tools.OpenHit(NewId(), hit.HitId); !errors.Is(err, ErrSearchHitUnknown) {
			t.Fatalf("another session opened a hit: %v", err)
		}
	}
	if _, err := tools.OpenHit(mine.Session, "forged"); !errors.Is(err, ErrSearchHitUnknown) {
		t.Fatalf("a forged hit id: %v", err)
	}
	admitted := &SearchToolEnv{Session: NewId(), Admit: func(repoId Id, path string) bool { return !strings.HasPrefix(path, "private/") }}
	result, err = tools.Search(context.Background(), admitted, &SearchToolArgs{Query: "harbor"})
	if err != nil || len(result.Hits) != 1 || result.Hits[0].Open.Arguments["path"] != "notes/harbor.md" {
		t.Fatalf("a refused hit came back: %v %+v", err, result)
	}
}

// §16.10's async row: a call's report gets progress while it pages, never once it returned.
func TestSearchToolsReportProgressUntilReturn(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 8 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%d.md", index), "rate limiter notes"))
	}
	// pages of about two hits, so one call pages several times
	world := newTestEngineWorld(t, func(settings *SidecarSearchSettings) { settings.PageByteCount = 600 }, documents...)
	tools := testSearchTools(t, world)
	session := NewId()
	reportLock := sync.Mutex{}
	reports, late := 0, 0
	// one call's environment, whose reports count as late once the call returned
	call := func(args *SearchToolArgs) (*SearchToolResult, error) {
		returned := false
		env := &SearchToolEnv{Session: session, Report: func(progress *SearchToolProgress) {
			reportLock.Lock()
			defer reportLock.Unlock()
			if returned {
				late += 1
			}
			reports += 1
		}}
		result, err := tools.Search(context.Background(), env, args)
		reportLock.Lock()
		returned = true
		reportLock.Unlock()
		return result, err
	}
	result, err := call(&SearchToolArgs{Query: "limiter", Limit: 8, WaitMs: new(int)})
	if err != nil {
		t.Fatal(err)
	}
	// a wait of 0 still computes the first page, and the call returns after it
	if len(result.Hits) == 0 || 8 <= len(result.Hits) || result.Status.Complete {
		t.Fatalf("a call with no wait: %d hits, complete %v", len(result.Hits), result.Status.Complete)
	}
	given := len(result.Hits)
	waitMs := 25000
	result, err = call(&SearchToolArgs{Cursor: result.Status.NextCursor, Limit: 8, WaitMs: &waitMs})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Status.Complete || given+len(result.Hits) != 8 {
		t.Fatalf("the rest: %d and %d hits, complete %v", given, len(result.Hits), result.Status.Complete)
	}
	reportLock.Lock()
	defer reportLock.Unlock()
	if reports == 0 || late != 0 {
		t.Fatalf("%d reports, %d after a call returned", reports, late)
	}
}

// search_status names each repo's index state and holds no requester and no query.
func TestSearchToolsStatusNamesNoRequesterOrQuery(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/a.md", "rate limiter notes"))
	tools := testSearchTools(t, world)
	if _, err := tools.Search(context.Background(), &SearchToolEnv{Session: NewId()}, &SearchToolArgs{Query: "synthetic-canary-query"}); err != nil {
		t.Fatal(err)
	}
	status, err := tools.Status(&SearchStatusToolArgs{})
	if err != nil || len(status.Repos) != 1 {
		t.Fatalf("%v %+v", err, status)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "requester") || strings.Contains(string(encoded), "canary") {
		t.Fatalf("a status names a requester or a query: %s", encoded)
	}
	if _, err := tools.Status(&SearchStatusToolArgs{Repos: []string{"not a repo"}}); !errors.Is(err, ErrSearchToolArguments) {
		t.Fatalf("a malformed repo: %v", err)
	}
}

// What the search methods' backends were asked.
type testSearchBackends struct {
	stateLock sync.Mutex
	taintPids []int
	taintErr  error
	tools     *SearchTools
}

func (self *testSearchBackends) backends() *DaemonSearchBackends {
	return &DaemonSearchBackends{
		Tools: func(sidecar *Sidecar) (*SearchTools, error) {
			return self.tools, nil
		},
		TaintAncestors: func(ctx context.Context, sidecar *Sidecar, pid int) error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.taintPids = append(self.taintPids, pid)
			return self.taintErr
		},
	}
}

// A daemon hosting one network, its search methods over fakes.
func newTestSearchDaemon(t *testing.T, fakes *testSearchBackends) *Daemon {
	t.Helper()
	daemon := newDispatchTestDaemon(t)
	if err := daemon.AddSidecar(NewId(), newSidecarBase(nil, cheapKeychainSettings())); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonSearchMethods(fakes.backends()) {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return daemon
}

// The control methods run on the call's network and none is a Confirm one; include taints the caller's ancestor runs
// by the peer pid before any untrusted text, a caller whose process cannot be read gets none, and a failed taint fails
// the call; search.agents and search.status answer; an unknown argument is refused.
func TestDaemonSearchMethods(t *testing.T) {
	for _, method := range DaemonSearchMethods(nil) {
		if !method.Network || method.Confirm {
			t.Errorf("%s: network %v, confirm %v", method.Name, method.Network, method.Confirm)
		}
	}
	world := newTestEngineWorld(t, nil,
		testAgentsDocument(t, "note", 1, "note", evsTestId("dana laptop"), "scraper", "rate limiter from a pasted page", time.Time{}, true),
	)
	world.scope.repos[0].Kind = protocol.RepoKind_REPO_KIND_VAULT
	fakes := &testSearchBackends{tools: testSearchTools(t, world)}
	daemon := newTestSearchDaemon(t, fakes)
	const pid = 4242
	dispatch := func(mode string, pid int, line string) *daemonRpcResponse {
		hello := &DaemonHello{UrLocal: 1, Mode: mode, Version: "synthetic-version", PeerPid: int64(pid)}
		return daemon.dispatch([]byte(line), &daemonSession{hello: hello}, runUnbounded)
	}
	result := &SearchToolResult{}
	response := dispatch(DaemonModeControl, pid, `{"jsonrpc":"2.0","id":1,"method":"search","params":{"query":"limiter"}}`)
	if response.Error != nil || json.Unmarshal(response.Result, result) != nil || len(result.Hits) != 1 || !result.Hits[0].Stub || result.Status.Tainted {
		t.Fatalf("a search: %+v %s", response.Error, response.Result)
	}
	if strings.Contains(string(response.Result), "pasted") || len(fakes.taintPids) != 0 {
		t.Fatalf("a stub search tainted or showed text: %s", response.Result)
	}
	response = dispatch(DaemonModeControl, pid, `{"jsonrpc":"2.0","id":2,"method":"search","params":{"query":"limiter","untrusted":"include"}}`)
	if response.Error != nil || json.Unmarshal(response.Result, result) != nil || !result.Status.Tainted || !strings.Contains(string(response.Result), "pasted") ||
		len(fakes.taintPids) != 1 || fakes.taintPids[0] != pid {
		t.Fatalf("an include: %+v %s, taints %v", response.Error, response.Result, fakes.taintPids)
	}
	if response = dispatch(DaemonModeControl, 0, `{"jsonrpc":"2.0","id":3,"method":"search","params":{"query":"limiter","untrusted":"include"}}`); response.Error == nil ||
		response.Result != nil || len(fakes.taintPids) != 1 {
		t.Fatalf("an unread caller got untrusted text: %+v %s", response.Error, response.Result)
	}
	fakes.taintErr = errors.New("synthetic fsync failure")
	if response = dispatch(DaemonModeControl, pid, `{"jsonrpc":"2.0","id":4,"method":"search","params":{"query":"limiter","untrusted":"include"}}`); response.Error == nil ||
		response.Result != nil || strings.Contains(response.Error.Message, "pasted") {
		t.Fatalf("a failed taint answered: %+v %s", response.Error, response.Result)
	}
	agents := &SearchAgentsToolResult{}
	if response = dispatch(DaemonModeMcp, pid, `{"jsonrpc":"2.0","id":5,"method":"search.agents","params":{"task":"limiter","since":"2000-01-01T00:00:00Z"}}`); response.Error != nil ||
		json.Unmarshal(response.Result, agents) != nil || len(agents.Groups) != 1 || !agents.Groups[0].Stub {
		t.Fatalf("search.agents: %+v %s", response.Error, response.Result)
	}
	status := &SearchStatusToolResult{}
	if response = dispatch(DaemonModeControl, pid, `{"jsonrpc":"2.0","id":6,"method":"search.status"}`); response.Error != nil || json.Unmarshal(response.Result, status) != nil ||
		len(status.Repos) != 1 || strings.Contains(string(response.Result), "requester") || strings.Contains(string(response.Result), "query") {
		t.Fatalf("search.status: %+v %s", response.Error, response.Result)
	}
	if response = dispatch(DaemonModeControl, pid, `{"jsonrpc":"2.0","id":7,"method":"search","params":{"query":"limiter","colour":"blue"}}`); response.Error == nil {
		t.Fatal("an unknown argument was taken")
	}
}
