// ur connect --token-file (MCP-M4-02): the key file reaches the daemon once and is gone, and a key in ur's
// environment enrolls nothing, by either flag, and leaves the file where it was.

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// The key a setup step left in a file enrolls, and the file is removed; a second connect finds no file.
func TestConnectTakesTheKeyFileOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owner-only file mode")
	}
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	path := filepath.Join(t.TempDir(), "authkey")
	if err := os.WriteFile(path, []byte("ur-authkey-synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cli.main(context.Background(), []string{"ur", "connect", "--token-file=" + path}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if len(target.authKeys) != 1 || target.authKeys[0] != "ur-authkey-synthetic" || !strings.Contains(stdout.String(), "generation 1") {
		t.Errorf("the daemon got %d keys; stdout %q", len(target.authKeys), stdout.String())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the key file is still there: %v", err)
	}
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "connect", "--token-file=" + path}); code == urExitOk || len(target.authKeys) != 1 {
		t.Errorf("a second connect from the removed file: exit %d, %d keys", code, len(target.authKeys))
	}
	if strings.Contains(stderr.String(), path) || strings.Contains(stderr.String(), "ur-authkey-") {
		t.Errorf("the refusal shows the path or a key: %q", stderr.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "connect", "--token=ur-authkey-synthetic", "--token-file=" + path}); code == urExitOk || len(target.authKeys) != 1 {
		t.Errorf("both flags: exit %d, %d keys", code, len(target.authKeys))
	}
}

// With an auth key in ur's environment nothing enrolls, from a file or from --token, the daemon hears nothing and
// the file stays. Its twin, the same call under an ordinary environment, enrolls.
func TestConnectRefusesAKeyInTheEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owner-only file mode")
	}
	target := &testUrDaemonTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	path := filepath.Join(t.TempDir(), "authkey")
	if err := os.WriteFile(path, []byte("ur-authkey-synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := urEnviron
	t.Cleanup(func() { urEnviron = saved })
	urEnviron = func() []string { return []string{"PATH=/usr/bin", "UR_AUTH_KEY=ur-authkey-inherited"} }
	for _, args := range [][]string{
		{"ur", "connect", "--token-file=" + path},
		{"ur", "connect", "--token=ur-authkey-synthetic"},
	} {
		stderr.Reset()
		if code := cli.main(context.Background(), args); code == urExitOk {
			t.Errorf("%s enrolled with a key in the environment", args[2][:12])
		}
		if strings.Contains(stderr.String(), "ur-authkey-inherited") || strings.Contains(stderr.String(), "UR_AUTH_KEY") {
			t.Errorf("the refusal shows the environment: %q", stderr.String())
		}
	}
	if len(target.authKeys) != 0 {
		t.Fatalf("the daemon got %d keys", len(target.authKeys))
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the key file was taken: %v", err)
	}
	// the daemon's own environment is held to the same rule: ur connect's is clean here, the daemon's is not
	var reads atomic.Int32
	urEnviron = func() []string {
		if reads.Add(1) == 1 {
			return []string{"PATH=/usr/bin"}
		}
		return []string{"PATH=/usr/bin", "UR_AUTH_KEY=ur-authkey-inherited"}
	}
	if code := cli.main(context.Background(), []string{"ur", "connect", "--token=ur-authkey-synthetic"}); code == urExitOk || len(target.authKeys) != 0 || reads.Load() != 2 {
		t.Errorf("a daemon with a key in its environment: exit %d, %d keys, %d reads", code, len(target.authKeys), reads.Load())
	}
	// twin
	urEnviron = func() []string { return []string{"PATH=/usr/bin"} }
	if code := cli.main(context.Background(), []string{"ur", "connect", "--token-file=" + path}); code != urExitOk || len(target.authKeys) != 1 {
		t.Errorf("the twin: exit %d, %d keys: %q", code, len(target.authKeys), stderr.String())
	}
}
