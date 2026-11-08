//go:build !js && !ios && !android && !sdk_mobile_bind && !windows

package sidecar

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The daemon over a real Unix socket in a short temporary directory, since a test's own directory can pass
// sun_path's 104 bytes on macOS.

const testDaemonVersion = "synthetic-version"

// A short directory of its own, removed at the test's end.
func shortTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "ur")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return directory
}

// A serving daemon and its socket path. Run's result arrives on the channel once it returns.
type testDaemon struct {
	daemon     *Daemon
	socketPath string
	stateDir   string
	ran        chan error
}

func startTestDaemon(t *testing.T, edit func(settings *DaemonSettings)) *testDaemon {
	t.Helper()
	directory := shortTestDirectory(t)
	settings := &DaemonSettings{
		Instance:       "default",
		StateDirectory: filepath.Join(directory, "state"),
		SocketPath:     filepath.Join(directory, "run", "default.sock"),
		Local:          DefaultSidecarSettings().LocalSettings,
		Version:        testDaemonVersion,
		Log:            NewNoopLogger(),
	}
	if edit != nil {
		edit(settings)
	}
	daemon, err := NewDaemon(context.Background(), settings)
	if err != nil {
		t.Fatal(err)
	}
	started := &testDaemon{daemon: daemon, socketPath: settings.SocketPath, stateDir: settings.StateDirectory, ran: make(chan error, 1)}
	go func() {
		started.ran <- daemon.Run()
	}()
	t.Cleanup(func() {
		daemon.Close()
		<-started.ran
	})
	return started
}

// A control session's client.
func dialTestDaemon(t *testing.T, started *testDaemon, mode string) *DaemonClient {
	t.Helper()
	client, err := DialDaemon(context.Background(), started.socketPath, &DaemonHello{Mode: mode, Version: testDaemonVersion})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// The real peer check passes this process's own connections, and a peer of another uid is refused before its hello
// is read (§5.8, owner decision 84).
func TestOtherUidRefused(t *testing.T) {
	started := startTestDaemon(t, nil)
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return "ok", nil
	}}); err != nil {
		t.Fatal(err)
	}
	client := dialTestDaemon(t, started, DaemonModeControl)
	var answer string
	if err := client.Call(context.Background(), "synthetic.read", nil, false, &answer); err != nil || answer != "ok" {
		t.Fatalf("the same uid: %v %q", err, answer)
	}

	started.daemon.setPeerCheck(func(conn net.Conn) error {
		return checkDaemonPeerUid(os.Getuid()+1, os.Getuid())
	})
	if _, err := DialDaemon(context.Background(), started.socketPath, &DaemonHello{Mode: DaemonModeControl, Version: testDaemonVersion}); err == nil {
		t.Fatal("a peer of another uid got a session")
	}
	if checkDaemonPeerUid(os.Getuid(), os.Getuid()) != nil || checkDaemonPeerUid(0, 1) == nil {
		t.Fatal("the uid comparison")
	}
}

// One daemon per instance: a second takes no lock while the first holds it, and takes it once the first stops.
func TestTwoDaemonsOneLock(t *testing.T) {
	directory := shortTestDirectory(t)
	settings := func(socketName string) *DaemonSettings {
		return &DaemonSettings{
			Instance:       "default",
			StateDirectory: filepath.Join(directory, "state"),
			SocketPath:     filepath.Join(directory, "run", socketName),
			Local:          DefaultSidecarSettings().LocalSettings,
			Version:        testDaemonVersion,
		}
	}
	first, err := NewDaemon(context.Background(), settings("a.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDaemon(context.Background(), settings("b.sock")); !errors.Is(err, ErrDaemonRunning) {
		t.Fatalf("a second daemon: %v", err)
	}
	ran := make(chan error, 1)
	go func() { ran <- first.Run() }()
	first.Close()
	if err := <-ran; err != nil {
		t.Fatal(err)
	}
	second, err := NewDaemon(context.Background(), settings("b.sock"))
	if err != nil {
		t.Fatalf("after the first stopped: %v", err)
	}
	second.Close()
	second.shutdown()
}

// A ur of another version is refused with the daemon's version, so a just-upgraded ur restarts the daemon rather
// than relaying through it.
func TestVersionSkewRefused(t *testing.T) {
	started := startTestDaemon(t, nil)
	_, err := DialDaemon(context.Background(), started.socketPath, &DaemonHello{Mode: DaemonModeControl, Version: "another-version"})
	refusal := &DaemonHelloRefusal{}
	if !errors.As(err, &refusal) || refusal.Code != DaemonHelloErrorVersionSkew || refusal.Version != testDaemonVersion {
		t.Fatalf("%v", err)
	}
}

// mcp and git hand the stream to their mode's handler, past the hello, and reach no control method; a mode with no
// handler is refused.
func TestModeHandlersTakeTheStream(t *testing.T) {
	started := startTestDaemon(t, nil)
	if _, err := DialDaemon(context.Background(), started.socketPath, &DaemonHello{Mode: DaemonModeMcp, Version: testDaemonVersion}); err == nil {
		t.Fatal("mcp with no handler got a session")
	}
	ran := false
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		ran = true
		return "ok", nil
	}}); err != nil {
		t.Fatal(err)
	}
	if err := started.daemon.RegisterMode(DaemonModeMcp, func(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
		line, err := bufio.NewReader(stream).ReadString('\n')
		if err != nil {
			return err
		}
		_, err = stream.Write([]byte("echo " + line))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	client := dialTestDaemon(t, started, DaemonModeMcp)
	stream := client.Stream()
	if _, err := stream.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"synthetic.read"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	echoed, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil || !strings.HasPrefix(echoed, "echo ") || ran {
		t.Fatalf("%q %v, ran %t", echoed, err, ran)
	}
}

// §5.9's socket path fits sun_path: a long TMPDIR or XDG_RUNTIME_DIR falls back to /tmp/ur-<uid>, and a relative
// one is ignored.
func TestLongStatePathFitsSunPath(t *testing.T) {
	longInstance := strings.Repeat("a", 32)
	longBase := "/" + strings.Repeat("d", 90)
	cases := []struct {
		goos string
		env  map[string]string
		want string
	}{
		{goos: "darwin", env: map[string]string{"TMPDIR": "/var/folders/synthetic/T/"}, want: "/var/folders/synthetic/T/ur/" + longInstance + ".sock"},
		{goos: "darwin", env: map[string]string{"TMPDIR": longBase}, want: "/tmp/ur-501/" + longInstance + ".sock"},
		{goos: "linux", env: map[string]string{"XDG_RUNTIME_DIR": "/run/user/501"}, want: "/run/user/501/ur/" + longInstance + ".sock"},
		{goos: "linux", env: map[string]string{"XDG_RUNTIME_DIR": longBase}, want: "/tmp/ur-501/" + longInstance + ".sock"},
		{goos: "linux", env: map[string]string{"XDG_RUNTIME_DIR": "relative/dir"}, want: "/tmp/ur-501/" + longInstance + ".sock"},
		{goos: "linux", env: map[string]string{}, want: "/tmp/ur-501/" + longInstance + ".sock"},
	}
	for _, c := range cases {
		socketPath, err := daemonSocketPathFor(longInstance, c.goos, func(name string) string { return c.env[name] }, 501)
		if err != nil || socketPath != c.want {
			t.Errorf("%s %v: %q %v", c.goos, c.env, socketPath, err)
		}
		if daemonSunPathMaxByteCount(c.goos) < len(socketPath) {
			t.Errorf("%q is past sun_path", socketPath)
		}
	}
	if _, err := daemonSocketPathFor("Not An Instance", "linux", func(string) string { return "" }, 501); err == nil {
		t.Fatal("an invalid instance name made a path")
	}
}

// A socket directory another user could reach is refused, not used.
func TestOpenSocketDirectoryRefused(t *testing.T) {
	directory := filepath.Join(shortTestDirectory(t), "open")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := listenDaemon(filepath.Join(directory, "d.sock")); err == nil {
		t.Fatal("a daemon listened in a directory open to others")
	}
}

// An auto-spawned daemon exits after IdleExitTimeout with no session and no request, never while a session is open
// or its busy rule holds, and a unit-run one never does.
func TestIdleExit(t *testing.T) {
	clock := newTokenTestClock()
	busy := false
	busyLock := sync.Mutex{}
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.AutoSpawned = true
		settings.Clock = clock
		settings.Busy = func() bool {
			busyLock.Lock()
			defer busyLock.Unlock()
			return busy
		}
	})
	armed := clock.awaitArmed(t, 1)
	if armed != 10*time.Minute {
		t.Fatalf("waits %v", armed)
	}
	// a session holds it open past the timeout
	client := dialTestDaemon(t, started, DaemonModeControl)
	clock.Advance(20 * time.Minute)
	select {
	case <-started.ran:
		t.Fatal("exited with a session open")
	default:
	}
	// busy holds it too, once the session is gone
	busyLock.Lock()
	busy = true
	busyLock.Unlock()
	armedBefore := clock.armed.Value()
	client.Close()
	clock.awaitArmed(t, armedBefore+1)
	clock.Advance(10 * time.Minute)
	clock.awaitArmed(t, armedBefore+2)
	select {
	case <-started.ran:
		t.Fatal("exited while busy")
	default:
	}
	busyLock.Lock()
	busy = false
	busyLock.Unlock()
	clock.Advance(10 * time.Minute)
	select {
	case err := <-started.ran:
		if err != nil {
			t.Fatal(err)
		}
		started.ran <- nil
	case <-time.After(10 * time.Second):
		t.Fatal("an idle auto-spawned daemon did not exit")
	}
}

// A unit-run daemon's idle loop returns at once and arms no wait, so it never idles out.
func TestUnitRunDaemonNeverIdlesOut(t *testing.T) {
	clock := newTokenTestClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Clock = clock
	})
	returned := make(chan struct{})
	go func() {
		started.daemon.idle()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("a unit-run daemon's idle loop kept running")
	}
	if armed := clock.armed.Value(); armed != 0 {
		t.Fatalf("a unit-run daemon armed %d waits", armed)
	}
}

// A request line past SidecarLocalSettings.RequestByteCount closes its session, since what follows cannot be framed.
func TestOversizeRequestClosesSession(t *testing.T) {
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		local := *settings.Local
		local.RequestByteCount = 1024
		settings.Local = &local
	})
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return "ok", nil
	}}); err != nil {
		t.Fatal(err)
	}
	client := dialTestDaemon(t, started, DaemonModeControl)
	err := client.Call(context.Background(), "synthetic.read", map[string]string{"pad": strings.Repeat("x", 2048)}, false, nil)
	if err == nil {
		t.Fatal("an oversize request was answered")
	}
	if err := client.Call(context.Background(), "synthetic.read", nil, false, nil); err == nil {
		t.Fatal("the session stayed open")
	}
}

// A method past SidecarLocalSettings.RequestTimeout answers a timeout, on the daemon's clock.
func TestRequestTimeoutAnswers(t *testing.T) {
	clock := newTokenTestClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Clock = clock
	})
	entered := make(chan struct{})
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.slow", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}); err != nil {
		t.Fatal(err)
	}
	client := dialTestDaemon(t, started, DaemonModeControl)
	result := make(chan error, 1)
	go func() {
		result <- client.Call(context.Background(), "synthetic.slow", nil, false, nil)
	}()
	<-entered
	clock.awaitArmed(t, 1)
	clock.Advance(30 * time.Second)
	err := <-result
	rpcErr := &DaemonRpcError{}
	if !errors.As(err, &rpcErr) || rpcErr.Code != DaemonRpcTimeout {
		t.Fatalf("%v", err)
	}
}
