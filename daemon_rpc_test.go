//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// The JSON-RPC dispatcher alone, with no socket: what each mode may call and what a reply may carry.

// A daemon with no listener, for dispatch tests.
func newDispatchTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	settings := &DaemonSettings{Instance: "default", StateDirectory: t.TempDir(), Local: DefaultSidecarSettings().LocalSettings, Version: "synthetic-version"}
	return newDaemonOn(context.Background(), settings, nopCloser{}, nil)
}

type nopCloser struct{}

func (self nopCloser) Close() error { return nil }

// Runs a handler with no bound, as a dispatch test needs.
func runUnbounded(handler func(ctx context.Context) (any, error)) (any, error, bool) {
	result, err := handler(context.Background())
	return result, err, false
}

// One request line's response in mode.
func dispatchTest(daemon *Daemon, mode string, line string) *daemonRpcResponse {
	return daemon.dispatch([]byte(line), &DaemonHello{UrLocal: 1, Mode: mode, Version: "synthetic-version"}, runUnbounded)
}

// D-CORE-9: the mode selects a protocol, never a privilege. A Confirm method runs only from control with the ur's
// confirmation; hook's confirmation counts for nothing, and a method without Confirm runs from either.
func TestModeGrantsNothing(t *testing.T) {
	daemon := newDispatchTestDaemon(t)
	ran := map[string]int{}
	for _, method := range []*DaemonMethod{
		{Name: "synthetic.approve", Confirm: true, Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			if !call.Confirmed || call.Hello.Mode != DaemonModeControl {
				return nil, errors.New("ran unconfirmed")
			}
			ran["approve"] += 1
			return map[string]bool{"ok": true}, nil
		}},
		{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			ran["read"] += 1
			return map[string]bool{"confirmed": call.Confirmed}, nil
		}},
	} {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		mode string
		line string
		code int
	}{
		{mode: DaemonModeControl, line: `{"jsonrpc":"2.0","id":1,"method":"synthetic.approve","ur_confirmed":true}`},
		{mode: DaemonModeControl, line: `{"jsonrpc":"2.0","id":2,"method":"synthetic.approve"}`, code: DaemonRpcConfirmationRequired},
		{mode: DaemonModeHook, line: `{"jsonrpc":"2.0","id":3,"method":"synthetic.approve","ur_confirmed":true}`, code: DaemonRpcConfirmationRequired},
		{mode: DaemonModeMcp, line: `{"jsonrpc":"2.0","id":4,"method":"synthetic.approve","ur_confirmed":true}`, code: DaemonRpcConfirmationRequired},
		{mode: DaemonModeHook, line: `{"jsonrpc":"2.0","id":5,"method":"synthetic.read","ur_confirmed":true}`},
	}
	for _, c := range cases {
		response := dispatchTest(daemon, c.mode, c.line)
		if c.code == 0 {
			if response.Error != nil {
				t.Errorf("%s %s: %v", c.mode, c.line, response.Error)
			}
			continue
		}
		if response.Error == nil || response.Error.Code != c.code {
			t.Errorf("%s %s: %+v", c.mode, c.line, response)
		}
	}
	if ran["approve"] != 1 || ran["read"] != 1 {
		t.Fatalf("ran %v", ran)
	}
	// hook's ur_confirmed never reaches a handler
	response := dispatchTest(daemon, DaemonModeHook, `{"jsonrpc":"2.0","id":6,"method":"synthetic.read","ur_confirmed":true}`)
	if string(response.Result) != `{"confirmed":false}` {
		t.Fatalf("hook's confirmation reached the handler: %s", response.Result)
	}
}

// I-7: no reply carries a token, key, seed or pass. Every registered method runs with canary secrets in what it
// returns, and each holding one answers an internal error with none of the canary in it.
func TestRepliesHoldNoSecret(t *testing.T) {
	daemon := newDispatchTestDaemon(t)
	canary := "synthetic-canary-secret"
	authKey := &AuthKey{bearer: canary}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	secretReplies := map[string]any{
		"auth_key":         authKey,
		"bundle_in_struct": struct{ Bundle *AuthKeyBundle }{Bundle: &AuthKeyBundle{DelegationSigningSeed: []byte(canary)}},
		"private_key":      map[string]ed25519.PrivateKey{"key": privateKey},
		"service_token":    &SidecarServiceToken{AccessToken: canary},
		"enroll_result":    []any{&SidecarEnrollResult{ByClientJwt: canary}},
		"identity_keys":    []*sidecarIdentityKeys{{identitySeed: []byte(canary)}},
		"auth_client":      SidecarAuthClientResult{ByClientJwt: canary},
		"nested_any":       map[string]any{"deep": []any{struct{ Key *AuthKey }{Key: authKey}}},
	}
	for name, reply := range secretReplies {
		reply := reply
		if err := daemon.RegisterMethod(&DaemonMethod{Name: "secret." + name, Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			return reply, nil
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := daemon.RegisterMethod(&DaemonMethod{Name: "clean", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return map[string]any{"state": "online", "generation": 3, "ids": []Id{NewId()}}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	daemon.stateLock.Lock()
	names := []string{}
	for name := range daemon.methods {
		names = append(names, name)
	}
	daemon.stateLock.Unlock()
	for _, name := range names {
		response := dispatchTest(daemon, DaemonModeControl, `{"jsonrpc":"2.0","id":1,"method":"`+name+`"}`)
		encoded, _ := json.Marshal(response)
		if strings.Contains(string(encoded), canary) {
			t.Errorf("%s: the reply holds the canary: %s", name, encoded)
		}
		if name == "clean" {
			if response.Error != nil {
				t.Errorf("clean: %v", response.Error)
			}
			continue
		}
		if response.Error == nil || response.Error.Code != daemonRpcInternalError {
			t.Errorf("%s: %+v", name, response)
		}
	}
}

// JSON-RPC's own refusals: a line that is not JSON, a request that is not 2.0, a method nobody registered, and a
// notification, which gets no answer.
func TestDaemonRpcRefusals(t *testing.T) {
	daemon := newDispatchTestDaemon(t)
	if err := daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return "ok", nil
	}}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		line string
		code int
	}{
		{line: `not json`, code: daemonRpcParseError},
		{line: `{"jsonrpc":"1.0","id":1,"method":"synthetic.read"}`, code: daemonRpcInvalidRequest},
		{line: `{"jsonrpc":"2.0","id":1}`, code: daemonRpcInvalidRequest},
		{line: `{"jsonrpc":"2.0","id":1,"method":"synthetic.missing"}`, code: daemonRpcMethodNotFound},
	}
	for _, c := range cases {
		response := dispatchTest(daemon, DaemonModeControl, c.line)
		if response == nil || response.Error == nil || response.Error.Code != c.code {
			t.Errorf("%s: %+v", c.line, response)
		}
	}
	if response := dispatchTest(daemon, DaemonModeControl, `{"jsonrpc":"2.0","method":"synthetic.read"}`); response != nil {
		t.Fatalf("a notification was answered: %+v", response)
	}
	if err := daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return nil, nil
	}}); !errors.Is(err, ErrDaemonRegistration) {
		t.Fatalf("a second registration: %v", err)
	}
	if err := daemon.RegisterMode(DaemonModeControl, func(context.Context, *DaemonHello, io.ReadWriter) error {
		return nil
	}); !errors.Is(err, ErrDaemonRegistration) {
		t.Fatalf("a handler for control: %v", err)
	}
}

// A Network method reads its network argument from the params.
func TestNetworkMethodReadsItsArgument(t *testing.T) {
	daemon := newDispatchTestDaemon(t)
	if err := daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.status", Network: true, Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return call.Network, nil
	}}); err != nil {
		t.Fatal(err)
	}
	response := dispatchTest(daemon, DaemonModeControl, `{"jsonrpc":"2.0","id":1,"method":"synthetic.status","params":{"network":"k7q2m9"}}`)
	if string(response.Result) != `"k7q2m9"` {
		t.Fatalf("%s", response.Result)
	}
}

// §5.8's hello: every mode's fields, version skew refused, and a refusal that repeats nothing of the line.
func TestDaemonHelloParse(t *testing.T) {
	version := "synthetic-version"
	accepted := []string{
		`{"ur_local":1,"mode":"mcp","version":"synthetic-version","harness":"synthetic","agent":"a","cwd":"/tmp/x","pid":42}`,
		`{"ur_local":1,"mode":"control","version":"synthetic-version"}`,
		`{"ur_local":1,"mode":"hook","version":"synthetic-version","pid":1}`,
		`{"ur_local":1,"mode":"git","version":"synthetic-version","repo":"k7q2m9/repo","service":"git-upload-pack"}`,
	}
	for _, line := range accepted {
		if _, code, err := parseDaemonHello([]byte(line), version); err != nil {
			t.Errorf("%s: %s %v", line, code, err)
		}
	}
	refused := map[string]string{
		`{"ur_local":1,"mode":"control","version":"other-version"}`:                                             DaemonHelloErrorVersionSkew,
		`{"ur_local":2,"mode":"control","version":"synthetic-version"}`:                                         DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"admin","version":"synthetic-version"}`:                                           DaemonHelloErrorMode,
		`{"ur_local":1,"mode":"control","version":"synthetic-version","extra":1}`:                               DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"control","version":"synthetic-version"} {}`:                                      DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"git","version":"synthetic-version","repo":"k7q2m9","service":"git-upload-pack"}`: DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"git","version":"synthetic-version","repo":"a/../b","service":"git-upload-pack"}`: DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"git","version":"synthetic-version","repo":"a/b","service":"git-secret"}`:         DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"control","version":"synthetic-version","repo":"a/b"}`:                            DaemonHelloErrorMalformed,
		`{"ur_local":1,"mode":"control","version":"synthetic-version","pid":-1}`:                                DaemonHelloErrorMalformed,
		`not json`: DaemonHelloErrorMalformed,
	}
	for line, want := range refused {
		_, code, err := parseDaemonHello([]byte(line), version)
		if code != want || !errors.Is(err, ErrDaemonHello) {
			t.Errorf("%s: %s %v", line, code, err)
		}
		if err != nil && strings.Contains(err.Error(), "synthetic") {
			t.Errorf("the refusal repeats the line: %v", err)
		}
	}
}
