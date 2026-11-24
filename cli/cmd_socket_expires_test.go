package main

// ur socket listen's --expires (§9.9; owner decision 687) against an in-process daemon whose socket.listen a test
// stands in for: the flag rides the call as expires_ms, in Go's durations or whole days; omitted, the call names no
// expiry at all, so the rule's expiresDefault applies and a daemon that predates the field still decodes it; a word, a
// negative, a zero and a duration under a millisecond are refused before the daemon is called.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// --expires rides socket.listen as milliseconds from now, and an omitted one leaves expires_ms out of the call.
func TestUrSocketListenSendsItsExpires(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	approvalId := sidecar.NewId()
	cli, out, _ := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodSocketListen, func(params json.RawMessage) (any, error) {
		return &sidecar.DaemonSocketListenReply{ApprovalId: &approvalId}, nil
	}))
	for flag, want := range map[string]time.Duration{"--expires=3d": 3 * 24 * time.Hour, "--expires=36h": 36 * time.Hour} {
		if code := cli.main(context.Background(), []string{"ur", "socket", "listen", "acme:smtp/25/mx", "2525", flag}); code != urExitFailed {
			t.Errorf("%s: exit %d", flag, code)
		}
		params := &sidecar.DaemonSocketListenParams{}
		daemon.lastParams(t, params)
		if params.ExpiresMs != want.Milliseconds() || params.Address != "acme:smtp/25/mx" || params.Network != "acme" {
			t.Errorf("%s: params %+v", flag, params)
		}
	}
	if !strings.Contains(out.String(), "ur approve "+approvalId.String()) {
		t.Errorf("stdout %q", out.String())
	}

	if code := cli.main(context.Background(), []string{"ur", "socket", "listen", "acme:smtp/25/mx", "2525"}); code != urExitFailed {
		t.Errorf("no --expires: exit %d", code)
	}
	raw := func() json.RawMessage {
		daemon.stateLock.Lock()
		defer daemon.stateLock.Unlock()
		return daemon.params[len(daemon.params)-1]
	}()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, named := fields["expires_ms"]; named {
		t.Errorf("a listen with no --expires named one: %s", raw)
	}
}

// A word, a negative, a zero and a duration under a millisecond are refused before the daemon is called.
func TestUrSocketListenRefusesABadExpires(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	cli, _, errOut := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodSocketListen, func(params json.RawMessage) (any, error) {
		return &sidecar.DaemonSocketListenReply{}, nil
	}))
	for _, flag := range []string{"--expires=soon", "--expires=-1h", "--expires=0d", "--expires=0s", "--expires=500us"} {
		if code := cli.main(context.Background(), []string{"ur", "socket", "listen", "tls/443/blog", "8443", flag}); code == urExitOk {
			t.Errorf("%s taken", flag)
		}
	}
	if !strings.Contains(errOut.String(), "--expires takes a duration") {
		t.Errorf("stderr %q", errOut.String())
	}
	daemon.stateLock.Lock()
	defer daemon.stateLock.Unlock()
	if len(daemon.params) != 0 {
		t.Errorf("a refused --expires called the daemon %d times", len(daemon.params))
	}
}
