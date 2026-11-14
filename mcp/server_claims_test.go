//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M6-01's sessions (D-MCP-29, R-MCP-16; §16.11's instructions row): a session's instructions text is the text of
// the claims value it starts under, read once at its start; a later change of the value reaches only sessions started
// after it; and the daemon keeps one go-sdk Server per text, every one with the same static tools. Each is read
// through initialize and, at 2026-07-28, server/discover, which are the two places a harness learns the text.

package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A daemon whose claims value a test moves: each session's claims resolve a network at its first ask and keep the
// answer, as sidecar.DaemonSessionClaims does.
type fakeClaimsDaemon struct {
	*fakeMcpDaemon

	stateLock sync.Mutex
	team      bool
	value     sidecar.SidecarClaims
	// how many times a session's claims resolved a network
	resolveCount int
}

func newFakeClaimsDaemon(value sidecar.SidecarClaims) *fakeClaimsDaemon {
	return &fakeClaimsDaemon{fakeMcpDaemon: newFakeMcpDaemon(), team: true, value: value}
}

func (self *fakeClaimsDaemon) set(value sidecar.SidecarClaims) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.value = value
}

func (self *fakeClaimsDaemon) resolves() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.resolveCount
}

func (self *fakeClaimsDaemon) SessionClaims(hello *sidecar.DaemonHello) McpSessionClaims {
	return &fakeSessionClaims{daemon: self, networkIdClaims: map[sidecar.Id]*sidecar.SidecarClaimsResolution{}}
}

type fakeSessionClaims struct {
	daemon *fakeClaimsDaemon

	stateLock       sync.Mutex
	networkIdClaims map[sidecar.Id]*sidecar.SidecarClaimsResolution
}

func (self *fakeSessionClaims) For(ctx context.Context, networkId sidecar.Id) *sidecar.SidecarClaimsResolution {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if resolution, ok := self.networkIdClaims[networkId]; ok {
		return resolution
	}
	self.daemon.stateLock.Lock()
	defer self.daemon.stateLock.Unlock()
	self.daemon.resolveCount += 1
	resolution := &sidecar.SidecarClaimsResolution{Claims: self.daemon.value, Source: sidecar.SidecarClaimsSourceTeam}
	if !self.daemon.team {
		resolution.Claims, resolution.Source = sidecar.SidecarClaimsOff, sidecar.SidecarClaimsSourcePersonal
	}
	self.networkIdClaims[networkId] = resolution
	return resolution
}

// The test's texts, one constant per value, as RECORD-M6-22's are.
func testClaimsTexts(resolution *sidecar.SidecarClaimsResolution) string {
	if resolution.Source == sidecar.SidecarClaimsSourcePersonal {
		return "text personal"
	}
	return "text team " + resolution.Claims.String()
}

// The instructions a 2026-07-28 session reads from server/discover.
func testDiscoverInstructions(t *testing.T, conn *testMcpConn) string {
	t.Helper()
	discover := conn.call("server/discover", map[string]any{"_meta": map[string]any{
		gomcp.MetaKeyProtocolVersion:    "2026-07-28",
		gomcp.MetaKeyClientInfo:         map[string]any{"name": "test", "version": "1"},
		gomcp.MetaKeyClientCapabilities: map[string]any{},
	}})
	if discover.Error != nil {
		t.Fatalf("server/discover: %s", discover.Error.Message)
	}
	return testInstructionsOf(discover.Result)
}

func testInstructionsOf(result json.RawMessage) string {
	fields := map[string]json.RawMessage{}
	json.Unmarshal(result, &fields)
	text := ""
	json.Unmarshal(fields["instructions"], &text)
	return text
}

func testInitializeInstructions(t *testing.T, conn *testMcpConn, version string) string {
	t.Helper()
	text := ""
	json.Unmarshal(conn.initialize(version)["instructions"], &text)
	return text
}

// A session's text is its claims value's, read at its start: before the harness sends a line, and once.
func TestSessionTextFixedAtStart(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeClaimsDaemon(sidecar.SidecarClaimsAuto)
	networkId, _ := daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	server.SetClaimsInstructions(testClaimsTexts)
	installTestEcho(server)

	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	// the session has started once it answers anything: its value was read before Serve read a line
	conn.call("ping", map[string]any{})
	if count := daemon.resolves(); count != 1 {
		t.Fatalf("the session's start resolved its claims %d times", count)
	}
	sessions := server.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("sessions open: %d", len(sessions))
	}
	session := sessions[0]
	if start := session.StartClaims(); start == nil || start.Claims != sidecar.SidecarClaimsAuto {
		t.Fatalf("the session started under %+v", start)
	}
	if session.Instructions() != "text team auto" {
		t.Errorf("the session's text is %q", session.Instructions())
	}
	if got := testInitializeInstructions(t, conn, "2025-11-25"); got != "text team auto" {
		t.Errorf("initialize answered %q", got)
	}
	// every later ask of the same network reads the session's value, never the daemon's again
	for range 3 {
		if resolution := session.Claims(context.Background(), networkId); resolution == nil || resolution.Claims != sidecar.SidecarClaimsAuto {
			t.Errorf("a later ask answered %+v", resolution)
		}
	}
	if response := conn.callTool("test_echo", map[string]any{"text": "a"}); response.Error != nil {
		t.Fatalf("a call: %s", response.Error.Message)
	}
	if count := daemon.resolves(); count != 1 {
		t.Errorf("the session resolved its claims %d times in all", count)
	}
	// a copy: a caller's edit reaches nothing
	session.StartClaims().Claims = sidecar.SidecarClaimsOff
	if session.StartClaims().Claims != sidecar.SidecarClaimsAuto {
		t.Error("a caller's edit moved the session's value")
	}
}

// A change of the value after a session's start leaves the session on its text and its value, at a legacy version
// and at 2026-07-28, while a session started after it takes the new one.
func TestLaterClaimsChangeLeavesSession(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeClaimsDaemon(sidecar.SidecarClaimsPrompt)
	networkId, _ := daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	server.SetClaimsInstructions(testClaimsTexts)

	legacy := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	legacy.call("ping", map[string]any{})
	current := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	current.call("ping", map[string]any{})
	started := server.Sessions()

	// the member turns claims off (or a committed .ur narrows it): both sessions began before
	daemon.set(sidecar.SidecarClaimsOff)
	if got := testInitializeInstructions(t, legacy, "2024-11-05"); got != "text team prompt" {
		t.Errorf("the open legacy session's text became %q", got)
	}
	if got := testDiscoverInstructions(t, current); got != "text team prompt" {
		t.Errorf("the open 2026-07-28 session's text became %q", got)
	}
	for _, session := range started {
		if resolution := session.Claims(context.Background(), networkId); resolution == nil || resolution.Claims != sidecar.SidecarClaimsPrompt {
			t.Errorf("an open session's value became %+v", resolution)
		}
	}

	later := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, later, "2025-11-25"); got != "text team off" {
		t.Errorf("a session started after the change reads %q", got)
	}
	laterDiscover := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testDiscoverInstructions(t, laterDiscover); got != "text team off" {
		t.Errorf("a 2026-07-28 session started after the change reads %q", got)
	}
	// the texts changing leaves both too: the rule is read at a session's start
	server.SetClaimsInstructions(func(resolution *sidecar.SidecarClaimsResolution) string { return "another text" })
	if got := testDiscoverInstructions(t, current); got != "text team prompt" {
		t.Errorf("new texts moved an open session to %q", got)
	}
}

// One go-sdk Server per text, not per session: sessions under one value share a Server, a second value makes a
// second, and every Server lists the same static tools.
func TestOneServerPerText(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeClaimsDaemon(sidecar.SidecarClaimsAuto)
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	server.SetClaimsInstructions(testClaimsTexts)
	installTestEcho(server)
	serverCount := func() int {
		server.stateLock.Lock()
		defer server.stateLock.Unlock()
		return len(server.instructionsServers)
	}
	toolNames := func(conn *testMcpConn) []string {
		t.Helper()
		response := conn.call("tools/list", map[string]any{})
		if response.Error != nil {
			t.Fatalf("tools/list: %s", response.Error.Message)
		}
		listed := struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}{}
		if err := json.Unmarshal(response.Result, &listed); err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, tool := range listed.Tools {
			names = append(names, tool.Name)
		}
		slices.Sort(names)
		return names
	}

	first := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	second := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, first, "2025-11-25"); got != "text team auto" {
		t.Fatalf("the first session reads %q", got)
	}
	if got := testInitializeInstructions(t, second, "2025-06-18"); got != "text team auto" {
		t.Fatalf("the second session reads %q", got)
	}
	if count := serverCount(); count != 1 {
		t.Fatalf("two sessions under one text made %d Servers", count)
	}
	if server.ServerFor("text team auto") != server.ServerFor("text team auto") {
		t.Fatal("one text answered two Servers")
	}

	daemon.set(sidecar.SidecarClaimsOff)
	third := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, third, "2025-11-25"); got != "text team off" {
		t.Fatalf("the third session reads %q", got)
	}
	daemon.set(sidecar.SidecarClaimsPrompt)
	fourth := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testDiscoverInstructions(t, fourth); got != "text team prompt" {
		t.Fatalf("the fourth session reads %q", got)
	}
	if count := serverCount(); count != 3 {
		t.Fatalf("three texts made %d Servers", count)
	}
	if server.ServerFor("text team auto") == server.ServerFor("text team off") {
		t.Fatal("two texts share one Server")
	}
	// the same static tools on each, one installed after the Servers were made among them
	server.Install(func(server *gomcp.Server) {
		gomcp.AddTool(server, &gomcp.Tool{Name: "test_late", Description: "added late"},
			func(ctx context.Context, request *gomcp.CallToolRequest, in testEchoIn) (*gomcp.CallToolResult, testEchoOut, error) {
				return nil, testEchoOut{}, nil
			})
	})
	want := []string{"test_echo", "test_late"}
	for name, conn := range map[string]*testMcpConn{"auto": first, "auto again": second, "off": third} {
		if names := toolNames(conn); !slices.Equal(names, want) {
			t.Errorf("the %s session lists %v", name, names)
		}
	}
}

// A session whose daemon reads no claims, or in which no network resolves at its start, takes the one empty text, and
// so does every session once no texts are set: nothing guesses a value.
func TestSessionWithoutClaimsTakesTheEmptyText(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	// a daemon that reads no claims
	plain := newTestMcpServer(newFakeMcpDaemon(), clock)
	plain.SetClaimsInstructions(testClaimsTexts)
	conn := startTestMcpConn(t, plain, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, conn, "2025-11-25"); got != "" {
		t.Errorf("a session with no claims reads %q", got)
	}
	if sessions := plain.Sessions(); len(sessions) != 1 || sessions[0].StartClaims() != nil ||
		sessions[0].Claims(context.Background(), sidecar.NewId()) != nil {
		t.Error("a session of a daemon that reads no claims holds a value")
	}

	// a daemon hosting no network: nothing resolves at the session's start
	daemon := newFakeClaimsDaemon(sidecar.SidecarClaimsAuto)
	empty := newTestMcpServer(daemon, clock)
	empty.SetClaimsInstructions(testClaimsTexts)
	conn = startTestMcpConn(t, empty, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, conn, "2025-11-25"); got != "" {
		t.Errorf("a session with no network at its start reads %q", got)
	}
	if daemon.resolves() != 0 {
		t.Error("a session with no network at its start resolved a value")
	}

	// a personal network's session reads the personal text, and with no texts set the empty one
	personal := newFakeClaimsDaemon(sidecar.SidecarClaimsAuto)
	personal.team = false
	personal.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(personal, clock)
	server.SetClaimsInstructions(testClaimsTexts)
	conn = startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, conn, "2025-11-25"); got != "text personal" {
		t.Errorf("a personal network's session reads %q", got)
	}
	server.SetClaimsInstructions(nil)
	conn = startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	if got := testInitializeInstructions(t, conn, "2025-11-25"); got != "" {
		t.Errorf("with no texts a session reads %q", got)
	}
}

// The real daemon's sessions read their claims: DaemonOf's daemon is an McpClaimsDaemon, so `ur daemon` needs no
// further wiring to fix a session's value at its start.
func TestDaemonOfReadsSessionClaims(t *testing.T) {
	if _, ok := DaemonOf(nil).(McpClaimsDaemon); !ok {
		t.Fatal("DaemonOf's daemon reads no session claims")
	}
}
