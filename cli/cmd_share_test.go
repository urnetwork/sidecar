package main

// ur share (SOCK-M5-15) against an in-process daemon whose share methods a test stands in for: add hashes the file here,
// sends the token and secret it drew and prints a link that carries them, its count and expiry read as QD-241 says;
// get runs the getter's half over a socket session holding the link's sidecar and writes <out>; the listing and rm
// print what the person needs, never a link.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// add hashes the file, sends what it drew, and prints a link that the getter parses back to the same secret, its
// uses one when --count is omitted and its expiry --expires's.
func TestUrShareAddPrintsLink(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	sidecarId := sidecar.NewId()
	cli, stdout, _ := startTestUrSocketCli(t, daemon.method(sidecar.DaemonMethodShareAdd, func(params json.RawMessage) (any, error) {
		add := &sidecar.DaemonShareAddParams{}
		json.Unmarshal(params, add)
		return &sidecar.DaemonShareAddReply{Token: add.Token, NetworkLabel: "abcdefghij", SidecarId: sidecarId, Uses: add.Uses,
			ExpireMillis: time.Date(2026, time.November, 12, 0, 0, 0, 0, time.UTC).UnixMilli()}, nil
	}))
	content := bytes.Repeat([]byte("synthetic file\n"), 1000)
	path := filepath.Join(t.TempDir(), "data.bin")
	os.WriteFile(path, content, 0o600)
	if code := cli.main(context.Background(), []string{"ur", "share", "add", path, "--expires=7d"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	params := &sidecar.DaemonShareAddParams{}
	daemon.lastParams(t, params)
	sum := sha256.Sum256(content)
	if params.Path != path || params.Size != int64(len(content)) || !bytes.Equal(params.Sha256, sum[:]) || params.Uses != 1 ||
		params.ExpiresMillis != (7*24*time.Hour).Milliseconds() || len(params.Secret) != 32 {
		t.Errorf("params %+v", params)
	}
	lines := strings.Split(stdout.String(), "\n")
	link, err := sidecar.ParseShareLink(lines[0])
	if err != nil || link.Token != params.Token || link.SidecarId != sidecarId || !bytes.Equal(link.Secret, params.Secret) || link.NetworkLabel != "abcdefghij" {
		t.Errorf("the printed link %q: %+v %v", lines[0], link, err)
	}
	if !strings.Contains(stdout.String(), "uses: 1; expires 2026-11-12T00:00:00Z") || !strings.Contains(stdout.String(), "stays up while the share lives") {
		t.Errorf("stdout %q", stdout.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "share", "add", path, "--count=0"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	unlimited := &sidecar.DaemonShareAddParams{}
	daemon.lastParams(t, unlimited)
	if unlimited.Uses != 0 || unlimited.ExpiresMillis != 0 || !strings.Contains(stdout.String(), "uses: unlimited") {
		t.Errorf("an unlimited share's params %+v", unlimited)
	}
}

// --count and --expires's grammar.
func TestUrShareFlagsGrammar(t *testing.T) {
	for text, want := range map[string]uint32{"": 1, "0": 0, "3": 3} {
		if count, err := parseUrShareCount(text); err != nil || count != want {
			t.Errorf("--count %q: %d %v", text, count, err)
		}
	}
	for _, bad := range []string{"-1", "x", "4294967296"} {
		if _, err := parseUrShareCount(bad); err == nil {
			t.Errorf("--count %q taken", bad)
		}
	}
	for text, want := range map[string]time.Duration{"": 0, "36h": 36 * time.Hour, "30d": 30 * 24 * time.Hour, "90m": 90 * time.Minute} {
		if expires, err := parseUrShareExpires(text); err != nil || expires != want {
			t.Errorf("--expires %q: %v %v", text, expires, err)
		}
	}
	for _, bad := range []string{"0d", "d", "-1h", "1w", "0s"} {
		if _, err := parseUrShareExpires(bad); err == nil {
			t.Errorf("--expires %q taken", bad)
		}
	}
}

// get dials the link's share holding its sidecar, runs the getter's half and writes <out>, and nothing of the link
// reaches stdout.
func TestUrShareGetWritesOut(t *testing.T) {
	cli, stdout, _ := newTestUrCli("/nonexistent")
	near, far := testUrSocketPair(t)
	var hello *sidecar.DaemonHello
	cli.openSocketSession = func(ctx context.Context, opened *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
		hello = opened
		return near, func() { near.Close() }, nil
	}
	token, secret := sidecar.NewShareCredentials()
	sharer := sidecar.NewId()
	linkText := sidecar.FormatShareLink("abcdefghij", token, sharer, secret)
	content := bytes.Repeat([]byte{0x2a, 0x00, 0x7f}, 50000)
	sum := sha256.Sum256(content)
	sharerDone := make(chan error, 1)
	go func() {
		// the sharer's half, as §9.9's header writes it: version, secret, get_id, offset; then ok, size and hash
		header := make([]byte, 57)
		if _, err := io.ReadFull(far, header); err != nil || header[0] != 1 || !bytes.Equal(header[1:33], secret) {
			sharerDone <- io.ErrUnexpectedEOF
			return
		}
		answer := append([]byte{0}, binary.BigEndian.AppendUint64(nil, uint64(len(content)))...)
		far.Write(append(append(answer, sum[:]...), content...))
		done := make([]byte, 1)
		if _, err := io.ReadFull(far, done); err != nil || done[0] != 1 {
			sharerDone <- io.ErrUnexpectedEOF
			return
		}
		far.Close()
		sharerDone <- nil
	}()
	out := filepath.Join(t.TempDir(), "got.bin")
	if code := cli.main(context.Background(), []string{"ur", "share", "get", linkText, out}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if err := <-sharerDone; err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, content) {
		t.Errorf("out: %d bytes, %v", len(got), err)
	}
	if hello == nil || hello.Socket != "abcdefghij:share/"+token || hello.SocketSidecarId == nil || *hello.SocketSidecarId != sharer {
		t.Errorf("hello %+v", hello)
	}
	if strings.Contains(stdout.String(), linkText[strings.Index(linkText, "#")+1:]) {
		t.Error("stdout holds the link's fragment")
	}
}

// The listing prints each live share's uses and expiry with no link, says the daemon stays up, and counts records
// that serve nothing; rm prints its end.
func TestUrShareListAndRm(t *testing.T) {
	daemon := &testUrSocketDaemon{}
	cli, stdout, _ := startTestUrSocketCli(t,
		daemon.method(sidecar.DaemonMethodShareList, func(params json.RawMessage) (any, error) {
			return &sidecar.DaemonShareListReply{
				Shares: []*sidecar.DaemonShareStatus{
					{Token: "abcdefghijklmnopqrstuvwxyz", Path: "/synthetic/a.bin", RemainingCount: 2, ExpireMillis: 0, Serving: true},
					{Token: "bcdefghijklmnopqrstuvwxyza", Path: "/synthetic/b.bin", RemainingCount: -1, ExpireMillis: 0},
				},
				FailedTokens: []string{"cdefghijklmnopqrstuvwxyzab"},
			}, nil
		}),
		daemon.method(sidecar.DaemonMethodShareRemove, func(params json.RawMessage) (any, error) {
			return &sidecar.DaemonShareRemoveReply{Removed: true}, nil
		}),
	)
	if code := cli.main(context.Background(), []string{"ur", "share"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"abcdefghijklmnopqrstuvwxyz  /synthetic/a.bin, 2 uses left, expires 1970-01-01T00:00:00Z, serving",
		"bcdefghijklmnopqrstuvwxyza  /synthetic/b.bin, unlimited uses, expires 1970-01-01T00:00:00Z, not serving yet",
		"cdefghijklmnopqrstuvwxyzab does not read and serves nothing",
		"the daemon stays up while a share lives",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("no %q in %q", want, stdout.String())
		}
	}
	if code := cli.main(context.Background(), []string{"ur", "share", "rm", "abcdefghijklmnopqrstuvwxyz", "--network=acme"}); code != urExitOk {
		t.Fatalf("rm exit %d", code)
	}
	params := &sidecar.DaemonShareRemoveParams{}
	daemon.lastParams(t, params)
	if params.Token != "abcdefghijklmnopqrstuvwxyz" || params.Network != "acme" {
		t.Errorf("params %+v", params)
	}
}

// A daemon target that holds sockets and live shares, as ur daemon's does.
type testUrSocketsTarget struct {
	*testUrDaemonTarget
	sockets int
	shares  int
}

func (self *testUrSocketsTarget) socketCounts() (int, int) {
	return self.sockets, self.shares
}

// ur status says the daemon holds sockets and live shares and stays up while any is, and says nothing of them when
// it holds none.
func TestUrStatusSaysSharesKeepTheDaemonUp(t *testing.T) {
	target := &testUrSocketsTarget{testUrDaemonTarget: &testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline}}, sockets: 2, shares: 1}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "status"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "sockets:    2 held, 1 live shares; the daemon stays up while any is") {
		t.Errorf("status %q", stdout.String())
	}
	quiet := startTestControlDaemon(t, &testUrSocketsTarget{testUrDaemonTarget: &testUrDaemonTarget{}}, nil)
	cli, stdout, _ = newTestUrCli(quiet.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if strings.Contains(stdout.String(), "sockets:") {
		t.Errorf("status with nothing held %q", stdout.String())
	}
}
