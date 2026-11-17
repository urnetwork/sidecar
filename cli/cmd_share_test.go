package main

// ur share (SOCK-M5-15) against an in-process daemon whose share methods a test stands in for: add hashes the file here,
// sends the token and secret it drew and prints a link that carries them, its count and expiry read as QD-241 says;
// get runs the getter's half over a socket session holding the link's sidecar and writes <out>, the link taken from
// argv or, with `-`, from stdin or the terminal with echo off (owner decision 336), and a bad line refused unrepeated;
// the listing and rm print what the person needs, never a link.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
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

// The sharer's half of one get of content under secret, as §9.9's header writes it: version, secret, get_id, offset;
// then ok, size and hash, the bytes, and the getter's done. Answers nil once the done arrived; far closes either way,
// so a getter refused here ends rather than waits.
func serveTestUrShareGet(far net.Conn, secret []byte, content []byte) chan error {
	sum := sha256.Sum256(content)
	sharerDone := make(chan error, 1)
	go func() {
		defer far.Close()
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
		sharerDone <- nil
	}()
	return sharerDone
}

// A stdin that fails the test that reads it.
type testUrUnreadStdin struct {
	t *testing.T
}

func (self *testUrUnreadStdin) Read(p []byte) (int, error) {
	self.t.Error("stdin was read")
	return 0, io.EOF
}

// A terminal that gives its lines only with echo off: a read with echo on fails the test.
type testUrQuietTty struct {
	*testTty
	t *testing.T
}

func (self *testUrQuietTty) readLine() (string, error) {
	self.t.Error("the terminal was read with echo on")
	return self.testTty.readLine()
}

// get dials the link's share holding its sidecar, runs the getter's half and writes <out>, and nothing of the link
// reaches stdout. The plain form, the link in argv, reads nothing from stdin.
func TestUrShareGetWritesOut(t *testing.T) {
	cli, stdout, _ := newTestUrCli("/nonexistent")
	cli.stdin = &testUrUnreadStdin{t: t}
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
	sharerDone := serveTestUrShareGet(far, secret, content)
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

// `ur share get - <out>` takes the link from stdin's first line, its line ending and the blanks around it dropped and
// what follows it left unread, and redeems it as the plain form does, the secret reaching the sharer and nothing of
// the link reaching stdout or stderr; -h names the form.
func TestUrShareGetReadsLinkFromStdin(t *testing.T) {
	cli, stdout, stderr := newTestUrCli("/nonexistent")
	near, far := testUrSocketPair(t)
	var hello *sidecar.DaemonHello
	cli.openSocketSession = func(ctx context.Context, opened *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
		hello = opened
		return near, func() { near.Close() }, nil
	}
	token, secret := sidecar.NewShareCredentials()
	sharer := sidecar.NewId()
	linkText := sidecar.FormatShareLink("abcdefghij", token, sharer, secret)
	cli.stdin = strings.NewReader(" \t" + linkText + " \r\nnot a link, and never read as one\n")
	content := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 40000)
	sharerDone := serveTestUrShareGet(far, secret, content)
	out := filepath.Join(t.TempDir(), "got.bin")
	if code := cli.main(context.Background(), []string{"ur", "share", "get", "-", out}); code != urExitOk {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
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
	fragment := linkText[strings.Index(linkText, "#")+1:]
	if strings.Contains(stdout.String(), fragment) || strings.Contains(stderr.String(), fragment) {
		t.Error("an output holds the link's fragment")
	}
	help, helpOut, _ := newTestUrCli("/nonexistent")
	if code := help.main(context.Background(), []string{"ur", "share", "-h"}); code != urExitOk || !strings.Contains(helpOut.String(), "ur share get - <out>") {
		t.Errorf("-h exit %d: %q", code, helpOut.String())
	}
}

// `-` refuses a first line that is empty, blank, too long or no link, before dialing or writing anything, and
// repeats nothing of what it read: neither the token nor any of the fragment reaches stdout or stderr (I-13).
func TestUrShareGetRefusesBadStdinLinkUnrepeated(t *testing.T) {
	token, secret := sidecar.NewShareCredentials()
	linkText := sidecar.FormatShareLink("abcdefghij", token, sidecar.NewId(), secret)
	fragment := linkText[strings.Index(linkText, "#")+1:]
	for _, stdin := range []string{
		"",
		"\n",
		" \t\r\n",
		// the link on the second line: only the first is read
		"\n" + linkText + "\n",
		// a fragment two characters short, whose k is no longer 48 bytes
		linkText[:len(linkText)-2] + "\n",
		// no # before the fragment
		strings.Replace(linkText, "#", "", 1) + "\n",
		// a tls/ name where share/ goes
		strings.Replace(linkText, ":share/", ":tls/", 1) + "\n",
		// past ShareLinkByteCount
		linkText + strings.Repeat("A", 2000) + "\n",
		linkText + "\x00\n",
	} {
		cli, stdout, stderr := newTestUrCli("/nonexistent")
		cli.stdin = strings.NewReader(stdin)
		cli.openSocketSession = func(ctx context.Context, opened *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
			t.Error("dialed")
			return nil, nil, errors.New("no dial in this test")
		}
		out := filepath.Join(t.TempDir(), "got.bin")
		if code := cli.main(context.Background(), []string{"ur", "share", "get", "-", out}); code != urExitFailed {
			t.Errorf("stdin %d bytes: exit %d", len(stdin), code)
		}
		if !strings.HasPrefix(stderr.String(), "ur share: ") || stdout.Len() != 0 {
			t.Errorf("stdin %d bytes: stdout %q, stderr %q", len(stdin), stdout.String(), stderr.String())
		}
		for _, output := range []string{stdout.String(), stderr.String()} {
			if strings.Contains(output, token) || strings.Contains(output, fragment[:8]) || strings.Contains(output, fragment[len(fragment)-10:len(fragment)-2]) {
				t.Errorf("stdin %d bytes: an output repeats the link: %q", len(stdin), output)
			}
		}
		for _, path := range []string{out, out + ".part", out + ".part.id"} {
			if _, err := os.Lstat(path); err == nil {
				t.Errorf("stdin %d bytes: %s was written", len(stdin), filepath.Base(path))
			}
		}
	}
}

// When stdin is a terminal, `-` asks for the link on /dev/tty and reads it with echo off, as a pass is: it prompts
// there, writes nothing of the link there, and reads nothing from stdin.
func TestUrShareGetReadsLinkFromTerminalUnechoed(t *testing.T) {
	cli, stdout, stderr := newTestUrCli("/nonexistent")
	near, far := testUrSocketPair(t)
	cli.openSocketSession = func(ctx context.Context, opened *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
		return near, func() { near.Close() }, nil
	}
	token, secret := sidecar.NewShareCredentials()
	linkText := sidecar.FormatShareLink("abcdefghij", token, sidecar.NewId(), secret)
	tty := &testUrQuietTty{testTty: &testTty{lines: []string{linkText}}, t: t}
	cli.stdinIsTerminal = func() bool { return true }
	cli.openTty = func() (urTty, error) { return tty, nil }
	cli.stdin = &testUrUnreadStdin{t: t}
	content := bytes.Repeat([]byte("synthetic bytes\n"), 3000)
	sharerDone := serveTestUrShareGet(far, secret, content)
	out := filepath.Join(t.TempDir(), "got.bin")
	if code := cli.main(context.Background(), []string{"ur", "share", "get", "-", out}); code != urExitOk {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if err := <-sharerDone; err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, content) {
		t.Errorf("out: %d bytes, %v", len(got), err)
	}
	written := tty.written.String()
	if !strings.Contains(written, "share link (not echoed): ") || strings.Contains(written, token) {
		t.Errorf("the terminal got %q", written)
	}
	fragment := linkText[strings.Index(linkText, "#")+1:]
	if strings.Contains(stdout.String(), fragment) || strings.Contains(stderr.String(), fragment) {
		t.Error("an output holds the link's fragment")
	}
}

// When stdin is a terminal and /dev/tty does not open, `-` refuses, saying to pipe the link in, rather than read the
// link from stdin with echo on; nothing is dialed or written.
func TestUrShareGetTerminalStdinWithoutTtyRefuses(t *testing.T) {
	cli, _, stderr := newTestUrCli("/nonexistent")
	cli.stdinIsTerminal = func() bool { return true }
	// newTestUrCli's terminal does not open
	cli.stdin = &testUrUnreadStdin{t: t}
	cli.openSocketSession = func(ctx context.Context, opened *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
		t.Error("dialed")
		return nil, nil, errors.New("no dial in this test")
	}
	out := filepath.Join(t.TempDir(), "got.bin")
	if code := cli.main(context.Background(), []string{"ur", "share", "get", "-", out}); code != urExitFailed {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "pipe the link in instead") {
		t.Errorf("stderr %q", stderr.String())
	}
	if _, err := os.Lstat(out + ".part"); err == nil {
		t.Error("the part was written")
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
