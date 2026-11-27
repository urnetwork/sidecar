package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A port both loopback addresses have free now, from a range no system hands out on its own.
func testUrGatewayPort(t *testing.T) int {
	t.Helper()
	settings := sidecar.DefaultGatewaySettings()
	settings.PortFirst, settings.PortLast = 30000, 31999
	port, err := sidecar.ChooseGatewayPort(settings, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// A gateway over a fresh state directory, its state holding port while hold, started, and closed at the test's end.
func startTestUrGateway(t *testing.T, directory string, port int, hold bool, holder func(address string) string) *sidecar.GatewayServer {
	t.Helper()
	if 0 < port {
		if err := sidecar.WriteGatewayState(directory, &sidecar.GatewayState{Version: 1, Port: port, Hold: hold}); err != nil {
			t.Fatal(err)
		}
	}
	gateway := sidecar.NewGatewayServer(&sidecar.GatewayServerArgs{StateDirectory: directory, Holder: holder})
	t.Cleanup(gateway.Close)
	gateway.Start()
	return gateway
}

// A control daemon with ur's methods over target, and methods besides: a gateway's, or a test's in their place.
func startTestUrMethodsDaemon(t *testing.T, directory string, target urDaemonTarget, methods ...*sidecar.DaemonMethod) *testUrDaemon {
	t.Helper()
	return startTestUrDaemon(t, directory, func(daemon *sidecar.Daemon) {
		if err := registerUrDaemonMethods(daemon, "test", target, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
		for _, method := range methods {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// The gateway's own methods of names alone.
func testUrGatewayMethods(gateway *sidecar.GatewayServer, names ...string) []*sidecar.DaemonMethod {
	methods := []*sidecar.DaemonMethod{}
	for _, method := range gateway.DaemonMethods() {
		for _, name := range names {
			if method.Name == name {
				methods = append(methods, method)
			}
		}
	}
	return methods
}

// A gateway.token that records each ask and answers a synthetic token.
type testUrTokenMethod struct {
	stateLock sync.Mutex
	asked     []*sidecar.GatewayTokenParams
}

// The synthetic token it answers.
const testUrGatewayToken = sidecar.GatewayTokenPrefix + "c3ludGhldGljLXRva2VuLWZvci1hLXRlc3Q"

func (self *testUrTokenMethod) method() *sidecar.DaemonMethod {
	return &sidecar.DaemonMethod{
		Name: sidecar.DaemonMethodGatewayToken,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &sidecar.GatewayTokenParams{}
			if err := json.Unmarshal(call.Params, params); err != nil {
				return nil, err
			}
			self.stateLock.Lock()
			self.asked = append(self.asked, params)
			self.stateLock.Unlock()
			return &sidecar.GatewayTokenReply{Token: testUrGatewayToken, ExpiresMillis: 1, GrantId: sidecar.NewId(), Bound: !params.Interactive}, nil
		},
	}
}

func (self *testUrTokenMethod) asks() []*sidecar.GatewayTokenParams {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.GatewayTokenParams{}, self.asked...)
}

// ur gateway token asks for a token only once the daemon's own listener answered the proof, and prints the token alone;
// at a terminal it says so, so the token binds no process.
func TestGatewayTokenPrintsOnlyAfterProof(t *testing.T) {
	directory := shortTestDirectory(t)
	gateway := startTestUrGateway(t, directory, testUrGatewayPort(t), true, nil)
	tokens := &testUrTokenMethod{}
	methods := append(testUrGatewayMethods(gateway, sidecar.DaemonMethodGatewayKey, sidecar.DaemonMethodGatewayStatus), tokens.method())
	daemon := startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{}, methods...)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "gateway", "token", "--harness=codex"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if stdout.String() != testUrGatewayToken+"\n" {
		t.Fatalf("stdout %q", stdout.String())
	}
	asked := tokens.asks()
	if len(asked) != 1 || asked[0].Harness != "codex" || asked[0].Interactive {
		t.Fatalf("asked %+v", asked)
	}
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.stdoutIsTerminal = func() bool { return true }
	if code := cli.main(context.Background(), []string{"ur", "gateway", "token", "--harness=claude-code", "--agent=reviewer"}); code != urExitOk {
		t.Fatalf("at a terminal: exit %d", code)
	}
	asked = tokens.asks()
	if last := asked[len(asked)-1]; !last.Interactive || last.Agent != "reviewer" || last.Harness != "claude-code" {
		t.Fatalf("at a terminal, asked %+v", last)
	}
}

// Another process on the port gets no token: where the daemon says another holds the port, where the daemon serves
// nothing, and where a key names the port as the daemon's while a foreign process answers on it, ur gateway token
// prints nothing on stdout, exits non-zero, and never asks for a token.
func TestListenerProofRefusesForeignHolderAtTheCommand(t *testing.T) {
	port := testUrGatewayPort(t)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	foreignListener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	foreign := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(`{"mac":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`))
	})}
	served := make(chan struct{})
	go func() {
		defer close(served)
		foreign.Serve(foreignListener)
	}()
	t.Cleanup(func() {
		foreign.Close()
		<-served
	})

	keys := []*sidecar.GatewayListenerKey{
		// the daemon names the port as its own, and a foreign process answers there
		{KeyId: "synthetic", Key: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Port: port, Addresses: []string{address}},
		// the daemon says another process holds it
		{KeyId: "synthetic", Key: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Port: port, HeldElsewhere: []string{address}},
	}
	for i, key := range keys {
		directory := shortTestDirectory(t)
		tokens := &testUrTokenMethod{}
		keyMethod := &sidecar.DaemonMethod{
			Name:    sidecar.DaemonMethodGatewayKey,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) { return key, nil },
		}
		daemon := startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{}, keyMethod, tokens.method())
		cli, stdout, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), []string{"ur", "gateway", "token", "--harness=codex"}); code == urExitOk {
			t.Errorf("key %d: exit 0", i)
		}
		if stdout.Len() != 0 || len(tokens.asks()) != 0 || !strings.Contains(stderr.String(), "no token") {
			t.Errorf("key %d: stdout %q, %d asks, stderr %q", i, stdout.String(), len(tokens.asks()), stderr.String())
		}
	}

	// a daemon whose own gateway could not bind the taken port gives no key at all
	directory := shortTestDirectory(t)
	gateway := startTestUrGateway(t, directory, port, true, func(address string) string { return "pid 77 (synthetic), uid 501" })
	tokens := &testUrTokenMethod{}
	daemon := startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{},
		append(testUrGatewayMethods(gateway, sidecar.DaemonMethodGatewayKey), tokens.method())...)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "gateway", "token", "--harness=codex"}); code == urExitOk || stdout.Len() != 0 || len(tokens.asks()) != 0 {
		t.Errorf("a taken port: exit %d, stdout %q, %d asks", code, stdout.String(), len(tokens.asks()))
	}
}

// ur status names the gateway's port and that this daemon holds it; where another process holds an address it names
// that process, as the OS shows it, and says ur gateway token refuses; with no port it says nothing of the gateway.
func TestStatusNamesGatewayPortAndHolder(t *testing.T) {
	port := testUrGatewayPort(t)
	directory := shortTestDirectory(t)
	gateway := startTestUrGateway(t, directory, port, true, nil)
	daemon := startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{}, testUrGatewayMethods(gateway, sidecar.DaemonMethodGatewayStatus)...)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if want := "gateway:    port " + strconv.Itoa(port) + ", held by this daemon on 127.0.0.1:" + strconv.Itoa(port); !strings.Contains(stdout.String(), want) {
		t.Errorf("the served port: %q", stdout.String())
	}

	taken := testUrGatewayPort(t)
	foreign, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(taken)))
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	directory = shortTestDirectory(t)
	gateway = startTestUrGateway(t, directory, taken, true, func(address string) string { return "pid 77 (synthetic), uid 501" })
	daemon = startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{}, testUrGatewayMethods(gateway, sidecar.DaemonMethodGatewayStatus)...)
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if want := "127.0.0.1:" + strconv.Itoa(taken) + " is held by another process, pid 77 (synthetic), uid 501: ur gateway token refuses"; !strings.Contains(stdout.String(), want) {
		t.Errorf("a taken port: %q", stdout.String())
	}

	directory = shortTestDirectory(t)
	gateway = startTestUrGateway(t, directory, 0, false, nil)
	daemon = startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{}, testUrGatewayMethods(gateway, sidecar.DaemonMethodGatewayStatus)...)
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if strings.Contains(stdout.String(), "gateway:") {
		t.Errorf("no gateway installed: %q", stdout.String())
	}
}

// A gateway.grants that answers a test's grant and records each ask.
type testUrGrantsMethod struct {
	stateLock sync.Mutex
	asked     []*sidecar.GatewayGrantsParams
	reply     *sidecar.GatewayGrantsReply
}

func (self *testUrGrantsMethod) method() *sidecar.DaemonMethod {
	return &sidecar.DaemonMethod{
		Name: sidecar.DaemonMethodGatewayGrants,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &sidecar.GatewayGrantsParams{}
			if err := json.Unmarshal(call.Params, params); err != nil {
				return nil, err
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.asked = append(self.asked, params)
			if params.Action == sidecar.GatewayGrantsActionRevoke {
				return &sidecar.GatewayGrantsReply{Revoked: true}, nil
			}
			return self.reply, nil
		},
	}
}

// ur gateway grants lists each grant with its budget, its pending raise and its unbound tokens with the command that
// binds them, ur status names a grant with unbound tokens too, and ur gateway grants revoke revokes the grant named.
func TestGatewayGrantsListsAndRevokes(t *testing.T) {
	grantId, approvalId, networkId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	day := int64(5_000_000_000)
	grants := &testUrGrantsMethod{reply: &sidecar.GatewayGrantsReply{Grants: []*sidecar.GatewayGrantView{{
		NetworkId: networkId,
		Grant: &sidecar.GatewayGrant{GrantId: grantId, Harness: "codex", AgentLabel: "codex", AgentId: sidecar.NewId(), DayNanoUsd: &day,
			PendingRaises: []*sidecar.GatewayGrantRaise{{Period: "month", AmountNanoUsd: 80_000_000_000, ApprovalId: approvalId}}},
		LiveTokenCount:  3,
		BoundTokenCount: 1,
		BindCommand:     "ur gateway token --harness codex",
	}}}}
	directory := shortTestDirectory(t)
	gateway := startTestUrGateway(t, directory, testUrGatewayPort(t), true, nil)
	daemon := startTestUrMethodsDaemon(t, directory, &testUrDaemonTarget{},
		append(testUrGatewayMethods(gateway, sidecar.DaemonMethodGatewayStatus), grants.method())...)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "gateway", "grants"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	for _, want := range []string{"grant:      " + grantId.String() + "  codex, agent codex", "$5.00 a day", "the agent's default a month",
		"raise:    to $80.00 a month waits on approval " + approvalId.String(), "3 live, 1 bound", "2 token(s) bind no harness process",
		"`ur gateway token --harness codex`"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the list lacks %q: %q", want, stdout.String())
		}
	}
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if !strings.Contains(stdout.String(), "2 unbound token(s)") || !strings.Contains(stdout.String(), "ur gateway token --harness codex") {
		t.Errorf("ur status does not name the unbound grant: %q", stdout.String())
	}
	cli, stdout, stderr = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "gateway", "status"}); code != urExitOk {
		t.Fatalf("ur gateway status: exit %d: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), ", held by this daemon on 127.0.0.1:") || !strings.Contains(stdout.String(), "grant:      "+grantId.String()) {
		t.Errorf("ur gateway status: %q", stdout.String())
	}
	cli, stdout, stderr = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "gateway", "grants", "revoke", grantId.String()}); code != urExitOk {
		t.Fatalf("revoke: exit %d: %q", code, stderr.String())
	}
	grants.stateLock.Lock()
	last := grants.asked[len(grants.asked)-1]
	grants.stateLock.Unlock()
	if last.Action != sidecar.GatewayGrantsActionRevoke || last.GrantId == nil || *last.GrantId != grantId || !strings.Contains(stdout.String(), "revoked") {
		t.Errorf("revoke asked %+v, printed %q", last, stdout.String())
	}
	cli, _, _ = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "gateway", "grants", "revoke", "not-an-id"}); code == urExitOk {
		t.Error("a revoke of no grant id passed")
	}
}
