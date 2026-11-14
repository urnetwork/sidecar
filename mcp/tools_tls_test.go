//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's tls tools (TLS-M5-23) on the tool framework, with the network's publisher faked: each tool's tier and hints;
// tls_publish handing the daemon's publish the checked arguments and the call's run, answering a pending gate with the
// approval's id and a publish with its URL, grant and client-certificate file's path; every refusal by a constant text;
// tls_unpublish as the subject's own filing from MCP; and each MCP version's wire and output schemas on both tools.

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A tool network that publishes what a test sets, and keeps what it was asked.
type fakeMcpTlsNetwork struct {
	*fakeMcpToolNetwork

	stateLock    sync.Mutex
	published    []*sidecar.TlsPublishSettings
	result       *sidecar.TlsPublishResult
	publishErr   error
	unpublished  []string
	origins      []sidecar.SidecarActOrigin
	unpublishErr error
}

func (self *fakeMcpTlsNetwork) PublishTls(ctx context.Context, settings *sidecar.TlsPublishSettings) (*sidecar.TlsPublishResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.published = append(self.published, settings)
	if self.publishErr != nil {
		return nil, self.publishErr
	}
	return self.result, nil
}

func (self *fakeMcpTlsNetwork) UnpublishTls(ctx context.Context, host string, port int, origin sidecar.SidecarActOrigin) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unpublished = append(self.unpublished, host)
	self.origins = append(self.origins, origin)
	return self.unpublishErr
}

// When the tools' clock reads.
var testTlsToolNow = time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)

// A server with the tls tools on a fake publisher, a session of a harness's relay bound to a fresh run.
type testTlsToolEnv struct {
	*hookTestEnv
	network *fakeMcpTlsNetwork
	catalog *McpCatalog
	sink    *testCallSink
	claude  *sidecartest.FakeHarness
}

func newTestTlsToolEnv(t *testing.T) *testTlsToolEnv {
	t.Helper()
	env := &testTlsToolEnv{hookTestEnv: newHookTestEnv(t), sink: &testCallSink{}}
	env.network = &fakeMcpTlsNetwork{
		fakeMcpToolNetwork: newFakeMcpToolNetwork(env.hookTestEnv.network, testToolCredential),
		result: &sidecar.TlsPublishResult{
			Name:        "tls/443/blog",
			Url:         "https://blog.abcdefghij.sidecar.example",
			ServerNames: []string{"blog.abcdefghij.sidecar.example"},
			GrantId:     []byte{0xab, 0xcd},
			Expires:     testTlsToolNow.Add(24 * time.Hour),
			Audience:    sidecar.TlsPublishAudienceMembers,
			AppMode:     sidecar.TlsPublishAppModeHttp,
			Passthrough: sidecar.TlsPublishPassthrough,
			Serving:     true,
		},
	}
	env.daemon.hostNetwork(env.networkId, env.network)
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	addTlsTools(env.catalog, func() time.Time { return testTlsToolNow })
	env.catalog.Install(env.server)
	env.claude = env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := env.claude.SessionStart("tls session", "startup"); err != nil {
		t.Fatal(err)
	}
	return env
}

// A session at version, 2026-07-28's taking none.
func (self *testTlsToolEnv) conn(version string) *testMcpConn {
	self.t.Helper()
	conn := startTestMcpConn(self.t, self.server, self.claude.RelayHello("builder"))
	if version != "2026-07-28" {
		conn.initialize(version)
	}
	return conn
}

// A tools/call at version.
func (self *testTlsToolEnv) callTool(conn *testMcpConn, version string, name string, arguments any) *testMcpResponse {
	self.t.Helper()
	params := map[string]any{"name": name, "arguments": arguments}
	if version == "2026-07-28" {
		params["_meta"] = testMcpLatestMeta()
	}
	return conn.call("tools/call", params)
}

// tls_publish is outward and tls_unpublish a write, and the daemon's catalog holds both registered, neither still
// unbuilt.
func TestTlsToolTiers(t *testing.T) {
	env := newTestTlsToolEnv(t)
	conn := env.conn("2025-06-18")
	listed := struct {
		Tools []struct {
			Name        string `json:"name"`
			Annotations struct {
				ReadOnlyHint  bool  `json:"readOnlyHint"`
				OpenWorldHint *bool `json:"openWorldHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}{}
	response := conn.call("tools/list", map[string]any{})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	json.Unmarshal(response.Result, &listed)
	want := map[string][2]bool{
		"tls_publish":   {false, true},
		"tls_unpublish": {false, false},
	}
	for _, tool := range listed.Tools {
		hints, ok := want[tool.Name]
		if !ok {
			continue
		}
		delete(want, tool.Name)
		if tool.Annotations.ReadOnlyHint != hints[0] || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint != hints[1] {
			t.Errorf("%s's hints %+v", tool.Name, tool.Annotations)
		}
	}
	if len(want) != 0 {
		t.Errorf("not listed: %v", want)
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	if err := checkMcpCatalog(NewDaemonMcpCatalog(newTestMcpServer(newFakeMcpDaemon(), clock), nil)); err != nil {
		t.Error(err)
	}
}

// With no grant the gate files the request, and the tool answers the approval's id and nothing else.
func TestTlsPublishAnswersAPendingApproval(t *testing.T) {
	env := newTestTlsToolEnv(t)
	approvalId := sidecar.NewId()
	env.network.publishErr = &sidecar.ApprovalPendingError{ApprovalId: approvalId}
	conn := env.conn("2025-06-18")
	response := env.callTool(conn, "2025-06-18", "tls_publish", map[string]any{"host": "blog", "local_port": 8080})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	out := &mcpTlsPublishOut{}
	testSocketToolData(t, response, out)
	if out.Status != "approval_pending" || out.ApprovalId != approvalId.String() || out.Url != "" || out.GrantId != "" {
		t.Errorf("out %+v", out)
	}
	// the daemon's publish got the checked arguments and the call's run, on 127.0.0.1 alone
	if len(env.network.published) != 1 {
		t.Fatalf("%d publishes asked", len(env.network.published))
	}
	settings := env.network.published[0]
	if settings.Host != "blog" || settings.Port != 0 || settings.Target != "127.0.0.1:8080" || settings.Tcp || settings.Audience != "" || settings.Expires != 0 {
		t.Errorf("settings %+v", settings)
	}
	if settings.RunId == nil || *settings.RunId == (sidecar.Id{}) || settings.Decision != nil {
		t.Errorf("the publish is not bound to the call's run")
	}
}

func TestTlsPublishAnswersThePublish(t *testing.T) {
	env := newTestTlsToolEnv(t)
	env.network.result.ClientCertificateFile = "/synthetic/link-5671-db.pem"
	conn := env.conn("2025-06-18")
	expires := testTlsToolNow.Add(2 * time.Hour)
	response := env.callTool(conn, "2025-06-18", "tls_publish", map[string]any{
		"host": "db", "port": 5671, "local_port": 5432, "audience": "link", "app_mode": "raw", "alpn": []string{"postgresql"},
		"expires": expires.Format(time.RFC3339),
	})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	out := &mcpTlsPublishOut{}
	testSocketToolData(t, response, out)
	if out.Status != "published" || out.Url != "https://blog.abcdefghij.sidecar.example" || out.GrantId != "abcd" || !out.Serving {
		t.Errorf("out %+v", out)
	}
	// the client key is a file's path, never its bytes
	if out.CertFile != "/synthetic/link-5671-db.pem" || out.Passthrough != "passthrough: key on this device" || out.Audience != "members" {
		t.Errorf("out %+v", out)
	}
	if out.Expires != testTlsToolNow.Add(24*time.Hour).Format(time.RFC3339) {
		t.Errorf("expires %q", out.Expires)
	}
	settings := env.network.published[0]
	if settings.Host != "db" || settings.Port != 5671 || settings.Target != "127.0.0.1:5432" || !settings.Tcp || settings.Audience != "link" || settings.Expires != 2*time.Hour {
		t.Errorf("settings %+v", settings)
	}
	if len(settings.Alpn) != 1 || settings.Alpn[0] != "postgresql" {
		t.Errorf("alpn %v", settings.Alpn)
	}
}

func TestTlsPublishRefusesByConstantTexts(t *testing.T) {
	env := newTestTlsToolEnv(t)
	conn := env.conn("2025-06-18")
	// refused before the daemon's publish is asked
	for _, arguments := range []map[string]any{
		{"host": "blog", "local_port": 0},
		{"host": "blog", "local_port": 70000},
		{"host": "blog", "local_port": 8080, "app_mode": "udp"},
		{"host": "blog", "local_port": 8080, "expires": "tomorrow"},
		{"host": "blog", "local_port": 8080, "expires": testTlsToolNow.Add(-time.Hour).Format(time.RFC3339)},
	} {
		response := env.callTool(conn, "2025-06-18", "tls_publish", arguments)
		if response.Error == nil || response.Error.Code != McpCodeInvalidArguments {
			t.Errorf("%v: %+v", arguments, response.Error)
		}
	}
	if len(env.network.published) != 0 {
		t.Fatalf("a refused call reached the publish")
	}
	// the publish's own refusals, each by a text that names nothing of the call
	cases := []struct {
		err  error
		code int
	}{
		{err: sidecar.ErrTlsPublishInvalid, code: McpCodeInvalidArguments},
		{err: sidecar.ErrTlsPublishHostTaken, code: McpCodeRefused},
		{err: sidecar.ErrTlsProbeRefused, code: McpCodeRefused},
		{err: sidecar.ErrTlsPublishPublished, code: McpCodeFailedPrecondition},
		{err: sidecar.ErrTlsPublishUnavailable, code: McpCodeUnavailable},
		{err: sidecar.ErrTlsComponentAbsent, code: McpCodeUnavailable},
		{err: sidecar.ErrSidecarGateDenied, code: McpCodeRefused},
		{err: sidecar.ErrAclGrantFile, code: McpCodeRefused},
	}
	for _, c := range cases {
		env.network.publishErr = c.err
		response := env.callTool(conn, "2025-06-18", "tls_publish", map[string]any{"host": "secret-host", "local_port": 18080})
		if response.Error == nil || int(response.Error.Code) != c.code {
			t.Errorf("%v: %+v", c.err, response.Error)
			continue
		}
		if strings.Contains(response.Error.Message, "secret-host") || strings.Contains(response.Error.Message, "18080") {
			t.Errorf("%v: the refusal names the call's host or port", c.err)
		}
	}
}

func TestTlsUnpublishIsTheSubjectsOwnFilingFromMcp(t *testing.T) {
	env := newTestTlsToolEnv(t)
	conn := env.conn("2025-06-18")
	out := &mcpTlsUnpublishOut{}
	response := env.callTool(conn, "2025-06-18", "tls_unpublish", map[string]any{"host": "blog"})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	testSocketToolData(t, response, out)
	if out.Status != "unpublished" || len(env.network.unpublished) != 1 || env.network.unpublished[0] != "blog" || env.network.origins[0] != sidecar.SidecarActMcp {
		t.Errorf("out %+v, asked %v from %v", out, env.network.unpublished, env.network.origins)
	}
	env.network.unpublishErr = sidecar.ErrTlsPublishAbsent
	response = env.callTool(conn, "2025-06-18", "tls_unpublish", map[string]any{"host": "blog", "port": 8443})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	testSocketToolData(t, response, out)
	if out.Status != "not_published" {
		t.Errorf("out %+v", out)
	}
}

func TestTlsToolsSchemasAtEveryVersion(t *testing.T) {
	env := newTestTlsToolEnv(t)
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "tls_publish", arguments: map[string]any{"host": "blog", "local_port": 8080}},
		{tool: "tls_unpublish", arguments: map[string]any{"host": "blog"}},
	}
	for _, version := range testMcpVersions {
		conn := env.conn(version)
		for _, call := range calls {
			response := env.callTool(conn, version, call.tool, call.arguments)
			if response.Error != nil {
				t.Fatalf("%s %s: %s", version, call.tool, response.Error.Message)
			}
			testValidateWire(t, version, response.Result)
			result := testWireResult{}
			json.Unmarshal(response.Result, &result)
			var structured any
			json.Unmarshal(result.StructuredContent, &structured)
			if err := testOutputSchema(t, conn, version, call.tool).Validate(structured); err != nil {
				t.Errorf("%s %s: structuredContent against outputSchema: %v", version, call.tool, err)
			}
		}
	}
}
