// SEARCH-M10-30 (§16.10's CLI block; FS-80's CLI cases; §22.6's flags target): ur search and ur agents against a daemon
// whose search methods are fakes that record what each call asked, the peer pid the system reported for it, and the
// taint an include asked for first: untrusted text withheld off a terminal, asked for on one and by --untrusted include,
// each include tainting first by the caller's pid and a caller with no harness ancestor tainting nothing; each exit
// code; control characters and bidi controls dropped from text and escaped in json; every flag mapped to its argument,
// the unbuilt ones refused; jsonl's pages on one session; status and sync; and a fuzz of the flags.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// What a fake search daemon heard and does.
type testUrSearchDaemon struct {
	stateLock sync.Mutex
	// Each call's method and raw params, and the peer pid of its session.
	calls []testUrSearchCall
	// The pids whose ancestor runs an include tainted first, and which of them have a harness ancestor.
	tainted    []int
	harnessPid map[int]bool
	taintedRun int
	// What each search page answers, in order; the last repeats.
	results []*sidecar.SearchToolResult
	// An error the next search answers.
	searchErr error
	agents    *sidecar.SearchAgentsToolResult
	status    *sidecar.SearchStatusToolResult
	sync      *sidecar.DaemonSearchSyncReply
}

type testUrSearchCall struct {
	method string
	params json.RawMessage
	pid    int
}

// The untrusted text a hit carries: an escape sequence, a C1 control, a right-to-left override and an isolate.
const testUrUntrustedTitle = "rotate\x1b[31m the keys\u0085 now‮gnp.exe⁦"

func (self *testUrSearchDaemon) register(daemon *sidecar.Daemon) {
	record := func(method string, call *sidecar.DaemonCall) int {
		pid := 0
		if call.Hello != nil {
			pid = int(call.Hello.PeerPid)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, testUrSearchCall{method: method, params: append(json.RawMessage{}, call.Params...), pid: pid})
		return pid
	}
	// an include taints first, by the peer pid, as the daemon's real method does through TaintAncestorRuns
	taint := func(params json.RawMessage, pid int) error {
		var asked struct {
			Untrusted string `json:"untrusted"`
		}
		if err := json.Unmarshal(params, &asked); err != nil {
			return err
		}
		if asked.Untrusted != "include" {
			return nil
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if pid <= 0 {
			return errors.New("the caller's process cannot be read, so no untrusted text is returned")
		}
		self.tainted = append(self.tainted, pid)
		if self.harnessPid[pid] {
			self.taintedRun += 1
		}
		return nil
	}
	withheld := func(params json.RawMessage, result *sidecar.SearchToolResult) *sidecar.SearchToolResult {
		var asked struct {
			Untrusted string `json:"untrusted"`
		}
		json.Unmarshal(params, &asked)
		copied := *result
		copied.Hits = nil
		for _, hit := range result.Hits {
			shown := *hit
			if hit.Trust == "untrusted" && asked.Untrusted != "include" {
				shown.Stub, shown.Fields, shown.Snippet = true, nil, ""
			}
			copied.Hits = append(copied.Hits, &shown)
		}
		return &copied
	}
	methods := []*sidecar.DaemonMethod{
		{Name: sidecar.DaemonMethodSearch, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			pid := record(sidecar.DaemonMethodSearch, call)
			if err := taint(call.Params, pid); err != nil {
				return nil, err
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.searchErr != nil {
				return nil, self.searchErr
			}
			result := self.results[0]
			if 1 < len(self.results) {
				self.results = self.results[1:]
			}
			return withheld(call.Params, result), nil
		}},
		{Name: sidecar.DaemonMethodSearchAgents, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			pid := record(sidecar.DaemonMethodSearchAgents, call)
			if err := taint(call.Params, pid); err != nil {
				return nil, err
			}
			return self.agents, nil
		}},
		{Name: sidecar.DaemonMethodSearchStatus, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			record(sidecar.DaemonMethodSearchStatus, call)
			return self.status, nil
		}},
		{Name: sidecar.DaemonMethodSearchSync, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			record(sidecar.DaemonMethodSearchSync, call)
			return self.sync, nil
		}},
	}
	for _, method := range methods {
		if err := daemon.RegisterMethod(method); err != nil {
			panic(err)
		}
	}
}

// The params of the calls of method, decoded into fresh values of T.
func testUrSearchParams[T any](t *testing.T, fake *testUrSearchDaemon, method string) []*T {
	t.Helper()
	fake.stateLock.Lock()
	defer fake.stateLock.Unlock()
	params := []*T{}
	for _, call := range fake.calls {
		if call.method != method {
			continue
		}
		decoded := new(T)
		if err := json.Unmarshal(call.params, decoded); err != nil {
			t.Fatal(err)
		}
		params = append(params, decoded)
	}
	return params
}

// A result of one trusted file hit and one untrusted message hit, complete.
func testUrSearchResult() *sidecar.SearchToolResult {
	return &sidecar.SearchToolResult{
		Hits: []*sidecar.SearchToolHit{
			{
				HitId: "h1", RepoId: "repo-a", Network: "net", Doc: sidecar.SearchToolDoc{Type: "file", Key: "aa"}, Version: 3,
				Time: "2026-11-05T07:12:09Z", Match: "confirmed", By: "text", Partition: "current", Trust: "own", Source: "index",
				Fields: map[string]string{"title": "The plan"},
				Open:   &sidecar.SearchToolOpen{Tool: "evs_read", Arguments: map[string]any{"repo": "repo-a", "path": "notes/plan.md", "version": 3}},
			},
			{
				HitId: "h2", RepoId: "repo-b", Network: "net", Doc: sidecar.SearchToolDoc{Type: "message", Key: "bb"}, Version: 1,
				Time: "2026-11-05T08:00:00Z", Match: "possible", Partition: "current", Trust: "untrusted", Source: "index",
				Fields:  map[string]string{"subject": testUrUntrustedTitle},
				Snippet: "keys‮ and more",
				Open:    &sidecar.SearchToolOpen{Tool: "mail_read", Arguments: map[string]any{"hit": "h2"}},
			},
		},
		Coverage: []*sidecar.SearchToolCoverage{{RepoId: "repo-a", RefId: "ref-a", State: "searched"}, {RepoId: "repo-c", State: sidecar.SearchExcludedNoIndex}},
		Counts:   sidecar.SearchToolCounts{Confirmed: 1, Possible: 1, Repos: 2, Excluded: 1},
		Status:   sidecar.SearchToolStatus{Complete: true, Trust: "untrusted"},
	}
}

// A fake search daemon on its own socket and a ur whose stdout is a terminal where terminal says.
func testUrSearchWorld(t *testing.T, terminal bool) (*testUrSearchDaemon, *urCli, *strings.Builder, *strings.Builder) {
	t.Helper()
	fake := &testUrSearchDaemon{
		harnessPid: map[int]bool{}, results: []*sidecar.SearchToolResult{testUrSearchResult()},
		agents: &sidecar.SearchAgentsToolResult{Complete: true, Trust: "member", Groups: []*sidecar.SearchToolGroup{{
			Key: "net/sidecar/limiter-fix", AgentLabel: "limiter-fix", Device: "dana-laptop", Member: "Dana", Trust: "member",
			Active: true, HitCount: 2, Runs: []*sidecar.SearchToolRun{{RunId: "4b7e", Title: "Fix the limiter"}},
		}}},
		status: &sidecar.SearchStatusToolResult{Repos: []*sidecar.SearchToolRepoStatus{{RepoId: "repo-a", IndexOn: true, FormatSupported: true, Policy: "background"}}},
		sync:   &sidecar.DaemonSearchSyncReply{Synced: 2, Evicted: true, Policy: "never"},
	}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), fake.register)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	cli.stdout, cli.stderr = stdout, stderr
	cli.stdoutIsTerminal = func() bool { return terminal }
	return fake, cli, stdout, stderr
}

// Runs ur with args, bounded by urTestTimeout.
func testUrRun(cli *urCli, args ...string) int {
	ctx, cancel := context.WithTimeout(context.Background(), urTestTimeout)
	defer cancel()
	return cli.main(ctx, append([]string{"ur"}, args...))
}

// FS-80's CLI case: off a terminal, ur search asks the daemon to withhold untrusted text, taints nothing, and prints
// the untrusted hit as a stub.
func TestUrSearchWithholdsOffATerminal(t *testing.T) {
	fake, cli, stdout, stderr := testUrSearchWorld(t, false)
	if code := testUrRun(cli, "search", "rotate keys"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	asked := testUrSearchParams[urSearchParams](t, fake, sidecar.DaemonMethodSearch)
	if len(asked) != 1 || asked[0].Untrusted != "withhold" || asked[0].WaitMs != nil {
		t.Fatalf("the call asked %+v", asked)
	}
	if len(fake.tainted) != 0 {
		t.Fatalf("a withheld search tainted %v", fake.tainted)
	}
	if !strings.Contains(stdout.String(), "[untrusted: withheld]") || strings.Contains(stdout.String(), "rotate") {
		t.Fatalf("the output %q", stdout.String())
	}
}

// FS-80's CLI cases: --untrusted include from a harness's shell tool taints that harness's run first, by the pid the
// system reports for ur's socket; from a terminal outside every harness, include is asked by default and taints
// nothing, since no harness process is an ancestor.
func TestUrSearchIncludeTaintsByTheCallersPid(t *testing.T) {
	fake, cli, stdout, stderr := testUrSearchWorld(t, false)
	fake.harnessPid[os.Getpid()] = true
	if code := testUrRun(cli, "search", "rotate keys", "--untrusted", "include"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !slices.Equal(fake.tainted, []int{os.Getpid()}) || fake.taintedRun != 1 {
		t.Fatalf("tainted %v, %d runs", fake.tainted, fake.taintedRun)
	}
	if !strings.Contains(stdout.String(), "rotate") {
		t.Fatalf("an include printed no untrusted text: %q", stdout.String())
	}

	outside, terminalCli, _, terminalErr := testUrSearchWorld(t, true)
	if code := testUrRun(terminalCli, "search", "rotate keys"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, terminalErr.String())
	}
	asked := testUrSearchParams[urSearchParams](t, outside, sidecar.DaemonMethodSearch)
	if len(asked) != 1 || asked[0].Untrusted != "include" || asked[0].WaitMs == nil || *asked[0].WaitMs != 10000 {
		t.Fatalf("a terminal's call asked %+v", asked)
	}
	if len(outside.tainted) != 1 || outside.taintedRun != 0 {
		t.Fatalf("a terminal outside every harness tainted %d runs", outside.taintedRun)
	}
}

// Terminal output drops C0 and C1 controls and bidi controls; json keeps every character, escaping those.
func TestUrSearchDropsControlCharacters(t *testing.T) {
	_, cli, stdout, stderr := testUrSearchWorld(t, true)
	if code := testUrRun(cli, "search", "rotate keys"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, r := range stdout.String() {
		if r != '\n' && urSearchUnsafeRune(r) {
			t.Fatalf("the text output holds %U: %q", r, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), "rotate[31m the keys now") {
		t.Fatalf("the text output %q", stdout.String())
	}
	_, jsonCli, jsonOut, jsonErr := testUrSearchWorld(t, true)
	if code := testUrRun(jsonCli, "search", "rotate keys", "--format", "json"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, jsonErr.String())
	}
	for _, r := range jsonOut.String() {
		if r != '\n' && urSearchUnsafeRune(r) {
			t.Fatalf("the json output holds %U", r)
		}
	}
	decoded := &sidecar.SearchToolResult{}
	if err := json.Unmarshal([]byte(jsonOut.String()), decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hits[1].Fields["subject"] != testUrUntrustedTitle {
		t.Fatalf("the json output lost a character: %q", decoded.Hits[1].Fields["subject"])
	}
}

// Each exit code: 0 a hit, 1 none, 2 an error, 3 partial for the wait, a query too broad and a coverage gap.
func TestUrSearchExitCodes(t *testing.T) {
	none := testUrSearchResult()
	none.Hits = nil
	waited := testUrSearchResult()
	waited.Status.Complete = false
	broad := testUrSearchResult()
	broad.Status.TooBroad = true
	gap := testUrSearchResult()
	gap.Coverage = append(gap.Coverage, &sidecar.SearchToolCoverage{RepoId: "repo-d", State: sidecar.SearchExcludedUnbuilt})
	cases := []struct {
		result *sidecar.SearchToolResult
		err    error
		code   int
	}{
		{result: testUrSearchResult(), code: urExitOk},
		{result: none, code: urSearchExitNone},
		{result: testUrSearchResult(), err: errors.New("the engine is not installed"), code: urSearchExitError},
		{result: waited, code: urSearchExitPartial},
		{result: broad, code: urSearchExitPartial},
		{result: gap, code: urSearchExitPartial},
	}
	for _, c := range cases {
		fake, cli, _, stderr := testUrSearchWorld(t, false)
		fake.results, fake.searchErr = []*sidecar.SearchToolResult{c.result}, c.err
		if code := testUrRun(cli, "search", "rotate keys"); code != c.code {
			t.Errorf("exit %d, want %d: %s", code, c.code, stderr.String())
		}
	}
	_, cli, _, _ := testUrSearchWorld(t, false)
	if code := testUrRun(cli, "search", "rotate", "--latest", "--more"); code != urExitUsage {
		t.Errorf("--latest with --more: exit %d", code)
	}
}

// Every flag reaches its argument as §16.10's search in row names it; --include and --verify fetch are refused, not
// narrowed in silence.
func TestUrSearchFlagsReachTheirArguments(t *testing.T) {
	fake, cli, _, stderr := testUrSearchWorld(t, false)
	before := time.Now()
	code := testUrRun(cli, "search", "rotate keys", "--scope", "repo", "--repo", "id:01", "--repo", "02", "--network", "work",
		"--agent", "limiter-fix", "--sidecar", "s1", "--member", "m1", "--run", "r1", "--session", "x1", "--kind", "file,message",
		"--since", "7d", "--until", "2026-11-05T00:00:00Z", "--path", "notes/", "--field", "subject=keys", "--field", "title=plan",
		"--latest", "--group", "agent", "--sort", "time", "--limit", "7", "--cursor", "c1", "--verify", "none", "--fuzzy", "--wait", "3s")
	if code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	asked := testUrSearchParams[urSearchParams](t, fake, sidecar.DaemonMethodSearch)
	if len(asked) != 1 {
		t.Fatalf("%d calls", len(asked))
	}
	args := asked[0]
	filters := args.Filters
	since, err := time.Parse(time.RFC3339, filters.Since)
	if err != nil || since.After(before.Add(-7*24*time.Hour+time.Second)) || since.Before(before.Add(-7*24*time.Hour-time.Minute)) {
		t.Fatalf("--since 7d as %q", filters.Since)
	}
	if args.Network != "work" || args.Scope != "repo" || !slices.Equal(args.Repos, []string{"id:01", "02"}) || !args.Latest || args.More ||
		args.GroupBy != "agent" || args.Sort != "time" || args.Limit != 7 || args.Cursor != "c1" || args.Verify != "none" || !args.Fuzzy ||
		args.WaitMs == nil || *args.WaitMs != 3000 || filters.Agent != "limiter-fix" || filters.Sidecar != "s1" || filters.Member != "m1" ||
		filters.Run != "r1" || filters.Session != "x1" || !slices.Equal(filters.Kind, []string{"file", "message"}) ||
		filters.Until != "2026-11-05T00:00:00Z" || filters.PathPrefix != "notes/" || filters.Fields["subject"] != "keys" || filters.Fields["title"] != "plan" {
		t.Fatalf("the call asked %+v with filters %+v", args, filters)
	}
	for _, refused := range [][]string{{"--include", "spam,trash"}, {"--verify", "fetch"}, {"--scope", "nowhere"}, {"--field", "nameless"}} {
		_, refusedCli, _, refusedErr := testUrSearchWorld(t, false)
		if code := testUrRun(refusedCli, append([]string{"search", "rotate"}, refused...)...); code != urSearchExitError {
			t.Errorf("%v: exit %d: %s", refused, code, refusedErr.String())
		}
	}
}

// jsonl pages on one control session, a line a hit as each page lands, then its summary; the second page's call names
// the first's cursor.
func TestUrSearchJsonlPagesOnOneSession(t *testing.T) {
	fake, cli, stdout, stderr := testUrSearchWorld(t, false)
	first := testUrSearchResult()
	first.Hits = first.Hits[:1]
	first.Status.Complete, first.Status.NextCursor = false, "cursor-1"
	second := testUrSearchResult()
	second.Hits = second.Hits[1:]
	fake.results = []*sidecar.SearchToolResult{first, second}
	if code := testUrRun(cli, "search", "rotate keys", "--format", "jsonl", "--explain"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[2], `"summary":true`) {
		t.Fatalf("the jsonl output %q", stdout.String())
	}
	asked := testUrSearchParams[urSearchParams](t, fake, sidecar.DaemonMethodSearch)
	if len(asked) != 2 || asked[0].Cursor != "" || asked[1].Cursor != "cursor-1" {
		t.Fatalf("the pages asked %+v", asked)
	}
	fake.stateLock.Lock()
	pids := []int{fake.calls[0].pid, fake.calls[1].pid}
	fake.stateLock.Unlock()
	if pids[0] != pids[1] || pids[0] != os.Getpid() {
		t.Fatalf("the pages' peer pids %v", pids)
	}
	explain := stderr.String()
	if !strings.Contains(explain, `term "rotate"`) || !strings.Contains(explain, `"rot"`) || !strings.Contains(explain, "page 2:") ||
		!strings.Contains(explain, "scope repo-c: no_index") {
		t.Fatalf("the explain output %q", explain)
	}
}

// ur agents groups by agent, asks search.agents with its flags, and exits as ur search does; --more and --scope all
// are refused as not built.
func TestUrAgents(t *testing.T) {
	fake, cli, stdout, stderr := testUrSearchWorld(t, false)
	if code := testUrRun(cli, "agents", "rate limiter", "--since", "24h", "--limit", "5"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	asked := testUrSearchParams[urAgentsParams](t, fake, sidecar.DaemonMethodSearchAgents)
	if len(asked) != 1 || asked[0].Task != "rate limiter" || asked[0].Limit != 5 || asked[0].Since == "" || asked[0].Untrusted != "withhold" {
		t.Fatalf("the call asked %+v", asked)
	}
	if !strings.Contains(stdout.String(), "## limiter-fix on dana-laptop (Dana), active, 2 hits") || !strings.Contains(stdout.String(), "run 4b7e") {
		t.Fatalf("the output %q", stdout.String())
	}
	for _, refused := range [][]string{{"--more"}, {"--scope", "all"}} {
		_, refusedCli, _, _ := testUrSearchWorld(t, false)
		if code := testUrRun(refusedCli, append([]string{"agents", "task"}, refused...)...); code != urSearchExitError {
			t.Errorf("%v: exit %d", refused, code)
		}
	}
	empty, emptyCli, _, _ := testUrSearchWorld(t, false)
	empty.agents = &sidecar.SearchAgentsToolResult{Complete: true}
	if code := testUrRun(emptyCli, "agents", "task"); code != urSearchExitNone {
		t.Errorf("no group: exit %d", code)
	}
}

// ur search status prints each repo's state; ur search sync asks for the repo, more, evict and policy it names.
func TestUrSearchStatusAndSync(t *testing.T) {
	fake, cli, stdout, stderr := testUrSearchWorld(t, false)
	if code := testUrRun(cli, "search", "status", "--repo", "repo-a"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "repo-a  index on  format read  all policy background") {
		t.Fatalf("the status %q", stdout.String())
	}
	if code := testUrRun(cli, "search", "sync", "--repo", "repo-a", "--more", "--evict", "--policy", "never"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	asked := testUrSearchParams[sidecar.DaemonSearchSyncParams](t, fake, sidecar.DaemonMethodSearchSync)
	if len(asked) != 1 || asked[0].Repo != "repo-a" || !asked[0].More || !asked[0].Evict || asked[0].Policy != "never" {
		t.Fatalf("the sync asked %+v", asked)
	}
	if !strings.Contains(stdout.String(), "synced 2 index refs") || !strings.Contains(stdout.String(), "this device's search state stays") {
		t.Fatalf("the sync's output %q", stdout.String())
	}
	if code := testUrRun(cli, "search", "sync", "--policy", "sometimes"); code != urSearchExitError {
		t.Errorf("an unknown policy: exit %d", code)
	}
}

// §22.6's flags target: any flags ur search and ur agents parse give no panic, and no error echoes an argument.
func FuzzUrSearchFlags(f *testing.F) {
	f.Add("rotate keys", "--scope", "repo", "--since", "7d")
	f.Add("x", "--field", "subject=secret-value", "--wait", "-5s")
	f.Add("", "--limit", "secret-value", "--format", "yaml")
	f.Add("q", "--kind", ",,", "--until", "2026-13-40T99:99:99Z")
	f.Fuzz(func(t *testing.T, query string, flagA string, valueA string, flagB string, valueB string) {
		cli, _, _ := newTestUrCli("unused")
		cli.stdoutIsTerminal = func() bool { return false }
		for _, usage := range []string{urCommands["search"].usage, urCommands["agents"].usage} {
			parser := &docopt.Parser{HelpHandler: docopt.NoHelpHandler, SkipHelpFlags: true}
			args := []string{"search", query, flagA, valueA, flagB, valueB}
			if strings.HasPrefix(usage, "  ur agents") {
				args[0] = "agents"
			}
			options, err := parser.ParseArgs("Usage:\n"+usage+"\n", args, "")
			if err != nil {
				continue
			}
			var parseErr error
			if args[0] == "agents" {
				_, _, parseErr = urAgentsParamsOf(cli, options)
			} else {
				_, _, parseErr = urSearchParamsOf(cli, options)
			}
			if parseErr == nil {
				continue
			}
			for _, value := range []string{query, valueA, valueB} {
				if 6 <= len(value) && strings.Contains(parseErr.Error(), value) {
					t.Fatalf("an error echoes %q: %s", value, parseErr)
				}
			}
		}
	})
}
