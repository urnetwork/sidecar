package main

// The grant end ur socket listen prints (owner decision 687) against an in-process daemon whose socket methods a test
// stands in for: the listen's line ends until <time>, its grant's end in RFC 3339, which ur socket's listing repeats;
// an outward listen with no end says a standing grant covers it; an application listen says neither.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The listen's line names its grant's end, an outward one with none says a standing grant covers it, and an application
// listen names neither; ur socket's listing names the end beside the listen.
func TestUrSocketListenPrintsItsGrantEnd(t *testing.T) {
	end := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	replies := map[string]*sidecar.DaemonSocketStatus{
		"tls/443/blog": {Kind: sidecar.DaemonSocketKindListen, Name: "tls/443/blog", Target: "127.0.0.1:8443", Serving: true, GrantExpiresMs: end.UnixMilli()},
		"smtp/25/mx":   {Kind: sidecar.DaemonSocketKindListen, Name: "smtp/25/mx", Target: "127.0.0.1:2525", Serving: true},
		"db/primary":   {Kind: sidecar.DaemonSocketKindListen, Name: "db/primary", Target: "127.0.0.1:5432", Serving: true},
	}
	daemon := &testUrSocketDaemon{}
	cli, out, _ := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodSocketListen, func(params json.RawMessage) (any, error) {
			listen := &sidecar.DaemonSocketListenParams{}
			if err := json.Unmarshal(params, listen); err != nil {
				return nil, err
			}
			return &sidecar.DaemonSocketListenReply{Status: replies[listen.Address]}, nil
		}),
		daemon.method(sidecar.DaemonMethodSocketLocal, func(params json.RawMessage) (any, error) {
			return &sidecar.DaemonSocketLocalReply{Sockets: []*sidecar.DaemonSocketStatus{replies["tls/443/blog"], replies["db/primary"]}}, nil
		}),
	)
	standing := "a standing grant covers it"
	for _, c := range []struct {
		address  string
		line     string
		standing bool
	}{
		{address: "tls/443/blog", line: "listen  tls/443/blog to 127.0.0.1:8443 (serving), 0 in flight, until 2030-01-02T03:04:05Z\n"},
		{address: "smtp/25/mx", line: "listen  smtp/25/mx to 127.0.0.1:2525 (serving), 0 in flight\n", standing: true},
		{address: "db/primary", line: "listen  db/primary to 127.0.0.1:5432 (serving), 0 in flight\n"},
	} {
		out.Reset()
		if code := cli.main(context.Background(), []string{"ur", "socket", "listen", c.address, "8443"}); code != urExitOk {
			t.Fatalf("%s: exit %d", c.address, code)
		}
		if !strings.HasPrefix(out.String(), c.line) || strings.Contains(out.String(), standing) != c.standing {
			t.Errorf("%s printed %q", c.address, out.String())
		}
	}

	out.Reset()
	if code := cli.main(context.Background(), []string{"ur", "socket"}); code != urExitOk {
		t.Fatalf("ur socket: exit %d", code)
	}
	if !strings.Contains(out.String(), "listen  tls/443/blog to 127.0.0.1:8443 (serving), 0 in flight, until 2030-01-02T03:04:05Z") ||
		strings.Contains(out.String(), "db/primary to 127.0.0.1:5432 (serving), 0 in flight, until") {
		t.Errorf("ur socket printed %q", out.String())
	}
}
