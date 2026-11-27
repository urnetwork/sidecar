//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DESIGN-COMPUTE §8.6's tokens (GW-M12-02): ur_gw_ and 32 random bytes in base64url, valid an hour on the fake clock,
// kept as their SHA-256 alone; presented in Authorization or x-api-key; reaching only the gateway's own routes, as their
// own grant; and minted only while the port is served, a run handle only under the grant's harness process.

// A token is ur_gw_ and TokenByteCount random bytes in base64url, valid for TokenLife and not a moment past it, and
// what the store keeps of it is its hash, never the token.
func TestTokenFormatAndHourLife(t *testing.T) {
	clock := newRecordTestClock()
	settings := DefaultGatewaySettings()
	network := newTestGatewayNetwork(t, settings, clock)
	grant, _, err := network.grants.Make(context.Background(), &GatewayGrantArgs{Harness: "codex", AgentLabel: "codex", AgentId: NewId()})
	if err != nil {
		t.Fatal(err)
	}
	token, record, err := network.grants.Mint(context.Background(), grant.GrantId, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, GatewayTokenPrefix))
	if !strings.HasPrefix(token, "ur_gw_") || err != nil || len(raw) != settings.TokenByteCount {
		t.Fatalf("a token of the wrong form: %d bytes, %v", len(raw), err)
	}
	if record.ExpiresMillis != clock.Now().Add(time.Hour).UnixMilli() {
		t.Fatalf("expires %d, an hour on is %d", record.ExpiresMillis, clock.Now().Add(time.Hour).UnixMilli())
	}
	other, _, err := network.grants.Mint(context.Background(), grant.GrantId, nil)
	if err != nil || other == token {
		t.Fatalf("a second mint: %v", err)
	}
	hash := GatewayTokenSha256(token)
	clock.advance(time.Hour - time.Millisecond)
	if _, _, err := network.grants.Authenticate(hash); err != nil {
		t.Fatalf("a token within its hour: %v", err)
	}
	clock.advance(time.Millisecond)
	if _, _, err := network.grants.Authenticate(hash); !errors.Is(err, ErrGatewayTokenExpired) {
		t.Fatalf("a token at its hour: %v", err)
	}

	store, err := network.instance.Store(&testNetworkId).Directory(gatewayGrantDirectoryName, gatewayGrantClass)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open(gatewayGrantFileName)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(token)) || bytes.Contains(content, []byte(strings.TrimPrefix(token, GatewayTokenPrefix))) {
		t.Fatal("the store holds a token")
	}
	otherHash := GatewayTokenSha256(other)
	encodedHash, _ := json.Marshal(otherHash[:])
	if !bytes.Contains(content, bytes.Trim(encodedHash, `"`)) {
		t.Fatal("the store does not hold a live token's hash")
	}

	reply := &GatewayTokenReply{Token: token}
	if err := checkDaemonReply(reply); err != nil {
		t.Fatalf("gateway.token's answer is refused by the reply walk: %v", err)
	}
}

// Authorization's bearer and x-api-key carry a token; anything else carries none.
func TestTokenHeaders(t *testing.T) {
	token := GatewayTokenPrefix + "c3ludGhldGlj"
	for _, header := range []map[string]string{
		{"Authorization": "Bearer " + token},
		{"Authorization": "bearer  " + token},
		{"x-api-key": token},
	} {
		request := httptest.NewRequest(http.MethodPost, "http://placeholder.invalid/v1/responses", nil)
		for name, value := range header {
			request.Header.Set(name, value)
		}
		if got := gatewayRequestToken(request); got != token {
			t.Errorf("%v: %q", header, got)
		}
	}
	for _, header := range []map[string]string{
		{},
		{"Authorization": "Basic " + token},
		{"Authorization": token},
		{"Authorization": "Bearer sk-synthetic"},
		{"x-api-key": "sk-ant-synthetic"},
		{"Authorization": "Bearer sk-synthetic", "x-api-key": token},
	} {
		request := httptest.NewRequest(http.MethodPost, "http://placeholder.invalid/v1/responses", nil)
		for name, value := range header {
			request.Header.Set(name, value)
		}
		if got := gatewayRequestToken(request); got != "" {
			t.Errorf("%v carried %q", header, got)
		}
	}
}

// A token answers on the gateway's own listener alone, for its own grant: a front's route sees the token's grant and no
// other, whatever the request names; a revoked or expired token, or none, is refused in the words of the API the
// request is to; the Host check comes before the token; and no route over HTTP lists, makes or revokes grants.
func TestTokenReachesOnlyItsGrant(t *testing.T) {
	world := newTestGatewayWorld(t, false)
	codex := world.make(&GatewayGrantsParams{Harness: "codex"}).Grants[0].Grant
	claude := world.make(&GatewayGrantsParams{Harness: "claude-code"}).Grants[0].Grant
	codexToken, _, err := world.network.grants.Mint(context.Background(), codex.GrantId, nil)
	if err != nil {
		t.Fatal(err)
	}
	claudeToken, _, err := world.network.grants.Mint(context.Background(), claude.GrantId, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/ur/balance", "/v1/messages"} {
		world.server.Handle(path, func(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
			io.WriteString(writer, caller.Grant.GrantId.String())
		})
	}
	status := world.server.Status()
	base := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(status.Port))
	ask := func(path string, headers map[string]string) (int, string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range headers {
			if name == "Host" {
				request.Host = value
				continue
			}
			request.Header.Set(name, value)
		}
		response, err := (&http.Transport{Proxy: nil}).RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if code, body := ask("/v1/ur/balance", map[string]string{"Authorization": "Bearer " + codexToken, "X-Ur-Grant": claude.GrantId.String()}); code != http.StatusOK || body != codex.GrantId.String() {
		t.Errorf("codex's token: %d %q", code, body)
	}
	if code, body := ask("/v1/ur/balance?grant_id="+codex.GrantId.String(), map[string]string{"x-api-key": claudeToken}); code != http.StatusOK || body != claude.GrantId.String() {
		t.Errorf("claude's token: %d %q", code, body)
	}
	if code, body := ask("/v1/ur/balance", map[string]string{"Authorization": "Bearer " + codexToken, "Host": "rebind.example:" + strconv.Itoa(status.Port)}); code != http.StatusMisdirectedRequest || strings.Contains(body, codex.GrantId.String()) {
		t.Errorf("a rebound host with a token: %d %q", code, body)
	}
	for _, path := range []string{"/v1/ur/grants", "/v1/gateway/grants", "/v1/ur/token"} {
		if code, _ := ask(path, map[string]string{"Authorization": "Bearer " + codexToken}); code != http.StatusNotFound {
			t.Errorf("%s answers %d over HTTP", path, code)
		}
	}
	if code, body := ask("/v1/ur/balance", nil); code != http.StatusUnauthorized || !strings.Contains(body, `"invalid_api_key"`) {
		t.Errorf("no token: %d %q", code, body)
	}
	if _, err := world.server.RevokeGrant(context.Background(), claude.GrantId); err != nil {
		t.Fatal(err)
	}
	if code, body := ask("/v1/messages", map[string]string{"x-api-key": claudeToken}); code != http.StatusUnauthorized || !strings.Contains(body, `"authentication_error"`) {
		t.Errorf("a revoked grant's token on the Messages front: %d %q", code, body)
	}
	world.clock.advance(world.settings.TokenLife)
	if code, _ := ask("/v1/ur/balance", map[string]string{"Authorization": "Bearer " + codexToken}); code != http.StatusUnauthorized {
		t.Errorf("an expired token: %d", code)
	}
}

// A binder a test steers: the harness process it finds for any pid, and what it was asked.
type testGatewayBinder struct {
	process  *GatewayHarnessProcess
	runId    Id
	union    *GatewayRunUnion
	unionErr error
	unions   [][]*GatewayRunHandle
}

func (self *testGatewayBinder) HarnessProcess(ctx context.Context, network GatewayRunNetwork, pid int) (*GatewayHarnessProcess, error) {
	return self.process, nil
}

func (self *testGatewayBinder) BindRun(ctx context.Context, network GatewayRunNetwork, harness string, handle *GatewayRunHandle, sessionId string) (Id, error) {
	return self.runId, nil
}

func (self *testGatewayBinder) Union(ctx context.Context, network GatewayRunNetwork, handles []*GatewayRunHandle) (*GatewayRunUnion, error) {
	self.unions = append(self.unions, handles)
	if self.unionErr != nil {
		return nil, self.unionErr
	}
	return self.union, nil
}

// A token minted by a command under the grant's harness process, by name or because a run names it, is that process's
// run handle; under a terminal emulator, a shell or no harness, or at a prompt, it is unbound; and nothing is minted
// while the port is not served.
func TestMintBindsOnlyAHarnessProcess(t *testing.T) {
	world := newTestGatewayWorld(t, false)
	world.make(&GatewayGrantsParams{Harness: "claude-code"})
	binder := &testGatewayBinder{}
	world.server.SetRunBinder(binder)
	hello := &DaemonHello{Mode: DaemonModeControl, PeerPid: 4242}
	identity := ProcessIdentity{Pid: 4200, StartMillis: 1}
	above := []ProcessIdentity{{Pid: 4100, StartMillis: 0}}
	cases := []struct {
		process     *GatewayHarnessProcess
		interactive bool
		bound       bool
	}{
		{process: &GatewayHarnessProcess{Process: &ProcessInfo{Identity: identity, Name: "node"}, Above: above}, bound: true},
		{process: &GatewayHarnessProcess{Process: &ProcessInfo{Identity: identity, Name: "claude"}}, bound: true},
		{process: &GatewayHarnessProcess{Process: &ProcessInfo{Identity: identity, Name: "iTerm2"}}, bound: false},
		{process: &GatewayHarnessProcess{Process: &ProcessInfo{Identity: identity, Name: "tmux"}, Known: true}, bound: true},
		{process: &GatewayHarnessProcess{Process: &ProcessInfo{Identity: identity, Name: "claude"}}, interactive: true, bound: false},
		{process: nil, bound: false},
	}
	for i, each := range cases {
		binder.process = each.process
		reply, err := world.server.MintToken(context.Background(), hello, &GatewayTokenParams{Harness: "claude-code", Interactive: each.interactive})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		_, record, err := world.network.grants.Authenticate(GatewayTokenSha256(reply.Token))
		if err != nil {
			t.Fatal(err)
		}
		if reply.Bound != each.bound || (record.Handle != nil) != each.bound {
			t.Errorf("case %d: bound %v, its record's handle %+v", i, reply.Bound, record.Handle)
		}
		if each.bound && (record.Handle.Process != identity || (each.process.Above != nil && record.Handle.Above[0] != above[0])) {
			t.Errorf("case %d: the handle %+v", i, record.Handle)
		}
	}
	if _, err := world.server.MintToken(context.Background(), hello, &GatewayTokenParams{Harness: "codex"}); !errors.Is(err, ErrGatewayGrantUnknown) {
		t.Errorf("a harness with no grant: %v", err)
	}
	world.server.Close()
	if _, err := world.server.MintToken(context.Background(), hello, &GatewayTokenParams{Harness: "claude-code"}); !errors.Is(err, ErrGatewayNotServing) {
		t.Errorf("a mint while the port is not served: %v", err)
	}
}
