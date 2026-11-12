//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-12's catalog: the daemon's catalog against §16.5's table, every design name registered or listed unbuilt and
// each registered tool's tier and hints its design row's; a static tool list, the same for every session and closed
// once installed. The fixtures here, a tool network, a catalog of test tools and a session bound to a real run, are
// what result_test.go, guard_test.go, the fuzz target and the benchmark share.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A network as tools read it: the fake network, an identity, the grants a test allows, repo kinds and the credentials
// its matcher holds.
type fakeMcpToolNetwork struct {
	*fakeMcpNetwork
	identity *sidecar.SidecarIdentity

	stateLock   sync.Mutex
	installed   bool
	allowed     []McpAccess
	repoKinds   map[sidecar.Id]protocol.RepoKind
	credentials [][]byte
	matcherErr  error
}

// A tool network over network, a policy installed that allows nothing.
func newFakeMcpToolNetwork(network *fakeMcpNetwork, credentials ...[]byte) *fakeMcpToolNetwork {
	return &fakeMcpToolNetwork{
		fakeMcpNetwork: network,
		identity:       &sidecar.SidecarIdentity{NetworkId: sidecar.NewId(), SidecarId: sidecar.NewId()},
		installed:      true,
		repoKinds:      map[sidecar.Id]protocol.RepoKind{},
		credentials:    credentials,
	}
}

// The network's identity.
func (self *fakeMcpToolNetwork) Identity() *sidecar.SidecarIdentity {
	return self.identity
}

// Whether the test installed a policy.
func (self *fakeMcpToolNetwork) PolicyInstalled() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.installed
}

// Allowed when a test listed the action on the resource's text.
func (self *fakeMcpToolNetwork) Allow(action protocol.AclAction, resource sidecar.AclResource, now time.Time) (sidecar.AclCheck, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.installed {
		return sidecar.AclCheck{}, false
	}
	for _, access := range self.allowed {
		if access.Action == action && access.Resource.String() == resource.String() {
			return sidecar.AclCheck{Allowed: true}, true
		}
	}
	return sidecar.AclCheck{Reason: sidecar.AclReasonNoGrant}, true
}

// What a test set.
func (self *fakeMcpToolNetwork) RepoKind(repoId sidecar.Id) protocol.RepoKind {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.repoKinds[repoId]
}

// A matcher of the test's credentials, or its error.
func (self *fakeMcpToolNetwork) SecretMatcher() (*sidecar.SecretMatcher, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.matcherErr != nil {
		return nil, self.matcherErr
	}
	return sidecar.NewSecretMatcher(self.credentials, nil), nil
}

// Allows one more grant.
func (self *fakeMcpToolNetwork) allow(access McpAccess) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.allowed = append(self.allowed, access)
}

// A test tool's input and output.
type testToolIn struct {
	Text string `json:"text"`
	Size int    `json:"size,omitempty"`
}

type testToolOut struct {
	Text string `json:"text"`
	Blob string `json:"blob,omitempty"`
}

// A synthetic credential the test network's matcher holds.
var testToolCredential = []byte("synthetic-daemon-credential-0123456789")

// The test tools' grant: dial to a fixed sidecar, which a test allows or not.
var testToolGrantTarget = sidecar.NewId()

// Registers the test tools on catalog, recording what test_write's sink saw on sink.
func addTestTools(catalog *McpCatalog) {
	none := func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }
	echo := func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
		result.SetSource("test:echo")
		return &testToolOut{Text: in.Text}, nil
	}
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_read", Tier: McpTierRead, Description: "answers its text", Access: none}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_write", Tier: McpTierWrite, Description: "writes its text", Access: none}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_act", Tier: McpTierOutward, Description: "acts outward", Access: none}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_untrusted", Tier: McpTierRead, Description: "answers its text as untrusted data", Access: none},
		func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			if err := result.Untrusted(ctx); err != nil {
				return nil, err
			}
			result.SetSource("test:outside")
			return &testToolOut{Text: result.Fence(in.Text)}, nil
		})
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_unfenced", Tier: McpTierRead, Description: "fences without tainting", Access: none},
		func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			return &testToolOut{Text: result.Fence(in.Text)}, nil
		})
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_large", Tier: McpTierRead, Description: "answers size bytes", Access: none},
		func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			result.SetSource("test:large")
			result.SetResource("ur://evs/test/large")
			McpMeter(ctx, int64(in.Size))
			return &testToolOut{Text: in.Text, Blob: strings.Repeat("x", in.Size)}, nil
		})
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_fail", Tier: McpTierRead, Description: "fails naming its text", Access: none},
		func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			return nil, errors.New("the tool could not use " + in.Text)
		})
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "test_fail_mcp", Tier: McpTierRead, Description: "fails with its own error", Access: none},
		func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			return nil, NewMcpError(McpCodeFailed, "could not use "+in.Text, false)
		})
	AddTool(catalog, &McpToolSpec[testToolIn]{
		Name: "test_grant", Tier: McpTierRead, Description: "needs a dial grant",
		Access: func(call *McpCall, in *testToolIn) ([]McpAccess, error) {
			return []McpAccess{testToolGrant()}, nil
		},
	}, echo)
	AddTool(catalog, &McpToolSpec[testToolIn]{
		Name: "test_secret_repo", Tier: McpTierRead, Description: "reads a secret repo", Access: none,
		Targets: func(call *McpCall, in *testToolIn) ([]McpTarget, error) {
			return []McpTarget{{Kind: McpTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_SECRET, Operation: McpRepoRead}}, nil
		},
	}, echo)
	addTestRepoTools(catalog)
}

// The grant test_grant needs.
func testToolGrant() McpAccess {
	return McpAccess{
		Action:   protocol.AclAction_ACL_ACTION_DIAL,
		Resource: sidecar.AclResource{Kind: sidecar.AclResourceSubject, Subject: sidecar.AclSelector{Kind: sidecar.AclSelectorSidecar, Id: testToolGrantTarget}},
	}
}

// What a test sink saw of W calls.
type testCallSink struct {
	stateLock sync.Mutex
	calls     []testSunkCall
}

// One call the sink saw.
type testSunkCall struct {
	toolName  string
	arguments []byte
	result    []byte
	err       error
}

// Keeps the call.
func (self *testCallSink) RecordMcpCall(ctx context.Context, call *McpCall, toolName string, arguments []byte, result []byte, startedMillis int64, endedMillis int64, callErr error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, testSunkCall{toolName: toolName, arguments: bytes.Clone(arguments), result: bytes.Clone(result), err: callErr})
}

// The calls so far.
func (self *testCallSink) sunk() []testSunkCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]testSunkCall{}, self.calls...)
}

// A server with one tool network and the test tools, and a Claude Code harness whose fresh session opened a run, so a
// session of its relay acts in a real run.
type testToolEnv struct {
	*hookTestEnv
	tools   *fakeMcpToolNetwork
	catalog *McpCatalog
	sink    *testCallSink
	claude  *sidecartest.FakeHarness
	runId   sidecar.Id
}

// The env, its run untainted.
func newTestToolEnv(t *testing.T) *testToolEnv {
	t.Helper()
	env := &testToolEnv{hookTestEnv: newHookTestEnv(t), sink: &testCallSink{}}
	env.tools = newFakeMcpToolNetwork(env.network, testToolCredential)
	env.daemon.hostNetwork(env.networkId, env.tools)
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	addTestTools(env.catalog)
	env.catalog.Install(env.server)
	env.claude = env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := env.claude.SessionStart("tool session", "startup"); err != nil {
		t.Fatal(err)
	}
	env.runId = env.runOf("claude-code", "tool session")
	if env.network.runs.Tainted(env.runId) {
		t.Fatal("the fresh run is tainted")
	}
	return env
}

// A session of the harness's relay, initialized at version, 2026-07-28's taking none.
func (self *testToolEnv) conn(version string) *testMcpConn {
	self.t.Helper()
	conn := startTestMcpConn(self.t, self.server, self.claude.RelayHello("builder"))
	if version != "2026-07-28" {
		conn.initialize(version)
	}
	return conn
}

// A tools/call at version: 2026-07-28's carries its version in _meta.
func (self *testToolEnv) callTool(conn *testMcpConn, version string, name string, arguments any) *testMcpResponse {
	self.t.Helper()
	params := map[string]any{"name": name, "arguments": arguments}
	if version == "2026-07-28" {
		params["_meta"] = testMcpLatestMeta()
	}
	return conn.call("tools/call", params)
}

// The _meta every 2026-07-28 request carries, which has no initialize.
func testMcpLatestMeta() map[string]any {
	return map[string]any{
		gomcp.MetaKeyProtocolVersion:    "2026-07-28",
		gomcp.MetaKeyClientInfo:         map[string]any{"name": "test", "version": "1"},
		gomcp.MetaKeyClientCapabilities: map[string]any{},
	}
}

// A result's envelope from its structuredContent.
func testEnvelopeOf(t *testing.T, response *testMcpResponse) *mcpResultEnvelope {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("error %d %s", response.Error.Code, response.Error.Message)
	}
	result := struct {
		StructuredContent json.RawMessage `json:"structuredContent"`
	}{}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	envelope := &mcpResultEnvelope{}
	if err := json.Unmarshal(result.StructuredContent, envelope); err != nil {
		t.Fatalf("structuredContent %s: %v", result.StructuredContent, err)
	}
	return envelope
}

// The daemon's catalog is §16.5's: every design name registered or listed unbuilt, never both, each registered tool's
// tier and hints its row's, nothing registered outside the table.
func TestCatalogMatchesDesign(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	if err := checkMcpCatalog(NewDaemonMcpCatalog(server, nil)); err != nil {
		t.Error(err)
	}
	names := map[string]bool{}
	for _, design := range mcpCatalogDesign {
		if names[design.name] {
			t.Errorf("%s twice in the table", design.name)
		}
		names[design.name] = true
		if design.owner == "" || design.tier < McpTierRead || McpTierOutward < design.tier {
			t.Errorf("%s: owner %q, tier %d", design.name, design.owner, design.tier)
		}
	}

	// a tool at the wrong tier, one listed unbuilt and registered, and one outside the table all fail
	wrong := NewMcpCatalog(server.settings.Mcp, clock, nil)
	none := func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }
	echo := func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
		return &testToolOut{}, nil
	}
	AddTool(wrong, &McpToolSpec[testToolIn]{Name: "evs_read", Tier: McpTierWrite, Description: "reads", Access: none}, echo)
	AddTool(wrong, &McpToolSpec[testToolIn]{Name: "not_a_design_tool", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	err := checkMcpCatalog(wrong)
	if err == nil || !strings.Contains(err.Error(), "evs_read is not W") && !strings.Contains(err.Error(), "evs_read is registered and still listed unbuilt") ||
		!strings.Contains(err.Error(), "not_a_design_tool is no §16.5 tool") {
		t.Errorf("a wrong catalog: %v", err)
	}

	// an evs or search tool that reports nothing to the guard fails, one whose Targets reaches no repo does not
	unguarded := NewMcpCatalog(server.settings.Mcp, clock, nil)
	AddTool(unguarded, &McpToolSpec[testToolIn]{Name: "evs_history", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	AddTool(unguarded, &McpToolSpec[testToolIn]{Name: "search_status", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	AddTool(unguarded, &McpToolSpec[testToolIn]{Name: "evs_repos", Tier: McpTierRead, Description: "names", Access: none,
		Targets: func(call *McpCall, in *testToolIn) ([]McpTarget, error) { return nil, nil }}, echo)
	AddTool(unguarded, &McpToolSpec[testToolIn]{Name: "team_members", Tier: McpTierRead, Description: "reads", Access: none}, echo)
	err = checkMcpCatalog(unguarded)
	if err == nil || !strings.Contains(err.Error(), "evs_history reports nothing to the guard") ||
		!strings.Contains(err.Error(), "search_status reports nothing to the guard") ||
		strings.Contains(err.Error(), "evs_repos reports nothing") || strings.Contains(err.Error(), "team_members reports nothing") {
		t.Errorf("an unguarded catalog: %v", err)
	}
}

// The tool list is static: two sessions of other agents and versions list the same bytes, each tool's hints follow
// its tier, a description is the spec's constant, and the catalog refuses a tool once installed.
func TestToolListStatic(t *testing.T) {
	env := newTestToolEnv(t)
	first := env.conn("2025-06-18")
	second := startTestMcpConn(t, env.server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Agent: "other-agent"})
	second.initialize("2024-11-05")
	firstList := first.call("tools/list", map[string]any{})
	secondList := second.call("tools/list", map[string]any{})
	if firstList.Error != nil || secondList.Error != nil || !bytes.Equal(firstList.Result, secondList.Result) {
		t.Fatalf("the lists differ:\n%s\n%s", firstList.Result, secondList.Result)
	}
	listed := struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Annotations struct {
				ReadOnlyHint  bool  `json:"readOnlyHint"`
				OpenWorldHint *bool `json:"openWorldHint"`
			} `json:"annotations"`
			InputSchema struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}{}
	if err := json.Unmarshal(firstList.Result, &listed); err != nil {
		t.Fatal(err)
	}
	tiers := map[string]McpTier{"test_read": McpTierRead, "test_write": McpTierWrite, "test_act": McpTierOutward}
	for _, tool := range listed.Tools {
		tier, ok := tiers[tool.Name]
		if !ok {
			continue
		}
		openWorld := tool.Annotations.OpenWorldHint != nil && *tool.Annotations.OpenWorldHint
		if tool.Annotations.ReadOnlyHint != (tier == McpTierRead) || openWorld != (tier == McpTierOutward) || tool.Annotations.OpenWorldHint == nil {
			t.Errorf("%s's hints %+v", tool.Name, tool.Annotations)
		}
		if tool.InputSchema.Properties["network"] == nil {
			t.Errorf("%s takes no network", tool.Name)
		}
	}
	if len(listed.Tools) != len(env.catalog.Names()) {
		t.Errorf("%d tools listed of %d", len(listed.Tools), len(env.catalog.Names()))
	}
	defer func() {
		if recover() == nil {
			t.Error("a tool added after the catalog was installed")
		}
	}()
	AddTool(env.catalog, &McpToolSpec[testToolIn]{Name: "test_late", Tier: McpTierRead, Description: "late",
		Access: func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }},
		func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			return nil, nil
		})
}

// A spec that cannot serve panics at registration: no Access, an unknown tier, a name taken, or an input naming
// network itself.
func TestAddToolRefusesBadSpecs(t *testing.T) {
	catalog := NewMcpCatalog(sidecar.DefaultSidecarSettings().Mcp, nil, nil)
	echo := func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
		return nil, nil
	}
	none := func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil }
	type networkIn struct {
		Network string `json:"network"`
	}
	panics := func(name string, add func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		add()
	}
	panics("no access", func() {
		AddTool(catalog, &McpToolSpec[testToolIn]{Name: "a", Tier: McpTierRead, Description: "d"}, echo)
	})
	panics("no tier", func() {
		AddTool(catalog, &McpToolSpec[testToolIn]{Name: "b", Description: "d", Access: none}, echo)
	})
	AddTool(catalog, &McpToolSpec[testToolIn]{Name: "c", Tier: McpTierRead, Description: "d", Access: none}, echo)
	panics("a name taken", func() {
		AddTool(catalog, &McpToolSpec[testToolIn]{Name: "c", Tier: McpTierRead, Description: "d", Access: none}, echo)
	})
	panics("network named", func() {
		AddTool(catalog, &McpToolSpec[networkIn]{Name: "e", Tier: McpTierRead, Description: "d",
			Access: func(call *McpCall, in *networkIn) ([]McpAccess, error) { return nil, nil }},
			func(ctx context.Context, call *McpCall, in *networkIn, result *McpResult) (*testToolOut, error) {
				return nil, nil
			})
	})
}
