package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// How long a test waits on a daemon before calling itself broken. Every wait is on a channel; this bounds a hang.
const urTestTimeout = 30 * time.Second

// A short directory for a socket, since a test's temp directory can pass sun_path's 104 bytes on macOS.
func shortTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "ur-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return directory
}

// An in-process daemon on its own socket, closed at the test's end.
type testUrDaemon struct {
	daemon     *sidecar.Daemon
	socketPath string
	done       chan struct{}
}

// Starts a daemon in directory, with register run on it before it serves.
func startTestUrDaemon(t *testing.T, directory string, register func(daemon *sidecar.Daemon)) *testUrDaemon {
	t.Helper()
	socketPath := filepath.Join(directory, "s")
	daemon, err := sidecar.NewDaemon(context.Background(), &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if register != nil {
		register(daemon)
	}
	started := &testUrDaemon{daemon: daemon, socketPath: socketPath, done: make(chan struct{})}
	go func() {
		defer close(started.done)
		daemon.Run()
	}()
	t.Cleanup(func() {
		daemon.Close()
		<-started.done
	})
	return started
}

// A terminal that answers the lines a test gives it, recording what ur wrote to it.
type testTty struct {
	stateLock sync.Mutex
	lines     []string
	written   bytes.Buffer
}

func (self *testTty) Write(p []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.written.Write(p)
}

func (self *testTty) next() (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.lines) == 0 {
		return "", io.EOF
	}
	line := self.lines[0]
	self.lines = self.lines[1:]
	return line, nil
}

func (self *testTty) readSecretLine() ([]byte, error) {
	line, err := self.next()
	return []byte(line), err
}

func (self *testTty) readLine() (string, error) {
	return self.next()
}

func (self *testTty) Close() error {
	return nil
}

// A ur on in-memory streams, its daemon at socketPath, with no terminal and nothing spawned.
func newTestUrCli(socketPath string) (*urCli, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cli := newUrCli()
	cli.stdin = strings.NewReader("")
	cli.stdout = stdout
	cli.stderr = stderr
	cli.stdinIsTerminal = func() bool { return false }
	cli.openTty = func() (urTty, error) { return nil, errors.New("no terminal in this test") }
	cli.socketPath = func(instance string) (string, error) { return socketPath, nil }
	cli.spawnDaemon = func(args []string) error { return errors.New("nothing spawns in this test") }
	cli.getenv = func(name string) string { return "" }
	cli.settings.SpawnRetryInterval = time.Millisecond
	// no test reads the embedded host table or dials a host it names
	cli.serviceUrls = func(settings *sidecar.SidecarSettings) error { return errors.New("no service urls in this test") }
	cli.hostList = func() (*sidecar.SidecarHostList, error) { return nil, errors.New("no host table in this test") }
	cli.hostProber = newRefusingTestHostProber()
	return cli, stdout, stderr
}

// An mcp mode that answers each line with "echo: " and the line.
func echoMcpMode(daemon *sidecar.Daemon) {
	daemon.RegisterMode(sidecar.DaemonModeMcp, func(ctx context.Context, hello *sidecar.DaemonHello, stream io.ReadWriter) error {
		reader := bufio.NewReader(stream)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return nil
			}
			if _, err := io.WriteString(stream, "echo: "+line); err != nil {
				return err
			}
		}
	})
}

// Bare ur on a terminal prints help and reaches no daemon (owner decision 57).
func TestBareUrHelpsOnPty(t *testing.T) {
	cli, stdout, _ := newTestUrCli(filepath.Join(shortTestDirectory(t), "none"))
	cli.stdinIsTerminal = func() bool { return true }
	dialed := false
	cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
		dialed = true
		return nil, errors.New("not here")
	}
	if code := cli.main(context.Background(), []string{"ur"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if dialed {
		t.Error("bare ur on a terminal dialed the daemon")
	}
	for _, name := range []string{"status", "connect", "daemon", "mcp", "unlock"} {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("the help does not list %s", name)
		}
	}
}

// Bare ur on a pipe speaks MCP: a hello of mode mcp, then stdio relayed both ways, stdout holding only the
// daemon's bytes.
func TestBareUrSpeaksMcpOnPipe(t *testing.T) {
	daemon := startTestUrDaemon(t, shortTestDirectory(t), echoMcpMode)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	stdout := newSyncBuffer()
	cli.stdout = stdout
	var mode string
	dial := cli.dialDaemon
	cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
		mode = hello.Mode
		return dial(ctx, socketPath, hello)
	}
	pipeReader, pipeWriter := io.Pipe()
	cli.stdin = pipeReader
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(context.Background(), []string{"ur"})
	}()
	io.WriteString(pipeWriter, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
	stdout.awaitContains(t, "echo: ")
	// the harness closes stdin, which ends the relay
	pipeWriter.Close()
	select {
	case code := <-finished:
		if code != urExitOk {
			t.Errorf("exit %d; stderr %q", code, stderr.String())
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the relay did not end with stdin")
	}
	if mode != sidecar.DaemonModeMcp {
		t.Errorf("hello mode %q", mode)
	}
	if stdout.String() != "echo: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n" {
		t.Errorf("stdout %q holds more than the daemon's bytes", stdout.String())
	}
}

// A buffer safe for a writer and a reader at once, which signals each write.
type syncBuffer struct {
	stateLock sync.Mutex
	buffer    bytes.Buffer
	written   chan struct{}
}

func newSyncBuffer() *syncBuffer {
	return &syncBuffer{written: make(chan struct{}, 1)}
}

func (self *syncBuffer) Write(p []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	n, err := self.buffer.Write(p)
	select {
	case self.written <- struct{}{}:
	default:
	}
	return n, err
}

func (self *syncBuffer) String() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.String()
}

// Waits until the buffer holds text.
func (self *syncBuffer) awaitContains(t *testing.T, text string) {
	t.Helper()
	deadline := time.After(urTestTimeout)
	for !strings.Contains(self.String(), text) {
		select {
		case <-self.written:
		case <-deadline:
			t.Fatalf("never wrote %q; holds %q", text, self.String())
		}
	}
}

// The global --instance comes off wherever it sits, in both spellings, and a bad name is a usage error.
func TestInstanceFlagIsGlobal(t *testing.T) {
	cases := []struct {
		args     []string
		rest     []string
		instance string
	}{
		{args: []string{"--instance", "work", "status"}, rest: []string{"status"}, instance: "work"},
		{args: []string{"status", "--instance=work", "--stats"}, rest: []string{"status", "--stats"}, instance: "work"},
		{args: []string{"status"}, rest: []string{"status"}, instance: ""},
	}
	for _, c := range cases {
		rest, instance, err := takeInstanceFlag(c.args)
		if err != nil || strings.Join(rest, " ") != strings.Join(c.rest, " ") || instance != c.instance {
			t.Errorf("%v: %v %q %v", c.args, rest, instance, err)
		}
	}
	cli, _, stderr := newTestUrCli("unused")
	if code := cli.main(context.Background(), []string{"ur", "--instance", "Not An Instance", "status"}); code != urExitUsage {
		t.Errorf("a bad instance name: exit %d, %q", code, stderr.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "no-such-command"}); code != urExitUsage {
		t.Errorf("an unknown command: exit %d", code)
	}
}

// Run as git-remote-ur, ur goes to that entry, which §11's track registers; until then it refuses.
func TestGitRemoteUrDispatches(t *testing.T) {
	cli, _, stderr := newTestUrCli("unused")
	if code := cli.main(context.Background(), []string{"/usr/local/bin/git-remote-ur", "origin", "ur://x"}); code != urExitFailed {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "git-remote-ur") {
		t.Errorf("stderr %q", stderr.String())
	}
}

// A fake of what the daemon's methods act on, recording what reached it.
type testUrDaemonTarget struct {
	stateLock   sync.Mutex
	unlockPass  []string
	authKeys    []string
	logouts     int
	statusValue sidecar.SidecarStatus
}

func (self *testUrDaemonTarget) status() (sidecar.SidecarStatus, string) {
	return self.statusValue, ""
}

func (self *testUrDaemonTarget) stats() sidecar.SidecarStats {
	return sidecar.SidecarStats{GenerationCount: 3, Components: []sidecar.SidecarComponentStats{{Name: "evs", QueuedCount: 2}}}
}

func (self *testUrDaemonTarget) unlock(pass []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unlockPass = append(self.unlockPass, string(pass))
	return nil
}

func (self *testUrDaemonTarget) lock() {}

func (self *testUrDaemonTarget) enroll(ctx context.Context, credential *sidecar.SidecarEnrollCredential) (int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.authKeys = append(self.authKeys, credential.AuthKey)
	credential.Erase()
	return 1, nil
}

func (self *testUrDaemonTarget) logout(ctx context.Context) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.logouts += 1
	return nil
}

func (self *testUrDaemonTarget) changePass(oldPass []byte, newPass []byte) error {
	return nil
}

func (self *testUrDaemonTarget) rotateKeychain(ctx context.Context, pass []byte) error {
	return nil
}

// A daemon with ur's control methods over target.
func startTestControlDaemon(t *testing.T, target urDaemonTarget, hostStores func() []sidecar.SidecarHostCredentialStore) *testUrDaemon {
	t.Helper()
	if hostStores == nil {
		hostStores = func() []sidecar.SidecarHostCredentialStore { return nil }
	}
	return startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := registerUrDaemonMethods(daemon, "test", target, osKeyStoreKeyFile, hostStores); err != nil {
			t.Fatal(err)
		}
	})
}

// ur unlock reads the pass from the terminal alone: what stdin holds never reaches the daemon, and with no terminal
// it refuses rather than read stdin.
func TestPassNeverFromStdin(t *testing.T) {
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	cli.stdin = strings.NewReader("stdin-pass\n")
	if code := cli.main(context.Background(), []string{"ur", "unlock"}); code != urExitFailed {
		t.Fatalf("no terminal: exit %d", code)
	}
	if !strings.Contains(stderr.String(), "terminal") || len(target.unlockPass) != 0 {
		t.Errorf("without a terminal: %q, passes %v", stderr.String(), target.unlockPass)
	}

	tty := &testTty{lines: []string{"tty-pass"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "unlock"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if len(target.unlockPass) != 1 || target.unlockPass[0] != "tty-pass" {
		t.Errorf("the daemon got %v", target.unlockPass)
	}
}

// ur login drops the OAuth token before anything reaches the daemon, which gets only the single-use key.
func TestLoginDropsOauthToken(t *testing.T) {
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	oauthToken := "synthetic-oauth-token"
	dropped := false
	var calledBeforeDrop bool
	dial := cli.dialDaemon
	cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
		if !dropped {
			calledBeforeDrop = true
		}
		return dial(ctx, socketPath, hello)
	}
	cli.login = func(ctx context.Context, cli *urCli, invite string) (string, func(), error) {
		return "ur-authkey-synthetic", func() {
			dropped = true
			oauthToken = ""
		}, nil
	}
	if code := cli.main(context.Background(), []string{"ur", "login"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if !dropped || calledBeforeDrop || oauthToken != "" {
		t.Error("the OAuth token outlived the key's mint")
	}
	if len(target.authKeys) != 1 || target.authKeys[0] != "ur-authkey-synthetic" {
		t.Errorf("the daemon got %v", target.authKeys)
	}

	cli.login = nil
	if code := cli.main(context.Background(), []string{"ur", "login"}); code != urExitFailed {
		t.Errorf("ur login with no ur-cli: exit %d", code)
	}
}

// ur status prints the state and counters and nothing secret; the reply holds only its known fields.
func TestStatusHoldsNoSecret(t *testing.T) {
	target := &testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 2}}
	daemon := startTestControlDaemon(t, target, func() []sidecar.SidecarHostCredentialStore {
		return []sidecar.SidecarHostCredentialStore{{Kind: "extension"}}
	})
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "status", "--stats"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"online", "generation: 2", "key_file", "extension", "component evs: queued 2"} {
		if !strings.Contains(text, want) {
			t.Errorf("status lacks %q:\n%s", want, text)
		}
	}

	client, err := sidecar.DialDaemon(context.Background(), daemon.socketPath, cli.hello(sidecar.DaemonModeControl))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw := json.RawMessage{}
	if err := client.Call(context.Background(), urMethodStatus, &urStatusParams{Stats: true}, false, &raw); err != nil {
		t.Fatal(err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		switch name {
		case "instance", "state", "reason", "generation", "no_sidecar", "key_store", "credential_stores", "stats":
		default:
			t.Errorf("status's reply carries %q", name)
		}
	}
}

// ur connect hands the key to the daemon once, and the error ur prints for a refusal never repeats a key.
func TestConnectSendsTheKeyToTheDaemon(t *testing.T) {
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "connect", "--token=ur-authkey-synthetic"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if len(target.authKeys) != 1 || target.authKeys[0] != "ur-authkey-synthetic" || !strings.Contains(stdout.String(), "generation 1") {
		t.Errorf("the daemon got %v; stdout %q", target.authKeys, stdout.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "connect"}); code != urExitUsage {
		t.Errorf("connect with no token: exit %d", code)
	}
}

// ur logout asks on the terminal first, and a no changes nothing.
func TestLogoutConfirmsOnTty(t *testing.T) {
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "logout"}); code != urExitOk || target.logouts != 0 {
		t.Errorf("a no logged out: exit %d, logouts %d", code, target.logouts)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "logout"}); code != urExitOk || target.logouts != 1 {
		t.Errorf("a yes did not log out: exit %d, logouts %d", code, target.logouts)
	}
}
