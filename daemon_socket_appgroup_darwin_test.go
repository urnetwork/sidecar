//go:build darwin && !ios && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A sandboxed app's socket in its app-group container serves the daemon as the main socket does, under the same peer
// check; a container that does not exist is passed over, and the daemon makes none (§5.9; QD-345).
func TestAppGroupSocketServesTheDaemon(t *testing.T) {
	// under /tmp, so the container's path and the name fit sun_path
	home, err := os.MkdirTemp("/tmp", "ur")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	container := filepath.Join(home, "Library", "Group Containers", "6BGU69Q742.group.network.ur")
	if err := os.MkdirAll(container, 0o700); err != nil {
		t.Fatal(err)
	}
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Home = home
	})
	if err := started.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.read", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		return "ok", nil
	}}); err != nil {
		t.Fatal(err)
	}
	paths := started.daemon.ServeAppGroupSockets()
	if len(paths) != 1 || paths[0] != filepath.Join(container, "ur") {
		t.Fatalf("the app-group sockets: %v", paths)
	}
	direct := filepath.Join(home, "Library", "Group Containers", "6BGU69Q742.group.com.bringyour.urnetwork")
	if _, err := os.Stat(direct); !os.IsNotExist(err) {
		t.Fatalf("the daemon made a container: %v", err)
	}

	client, err := DialDaemon(context.Background(), paths[0], &DaemonHello{Mode: DaemonModeControl, Version: testDaemonVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var answer string
	if err := client.Call(context.Background(), "synthetic.read", nil, false, &answer); err != nil || answer != "ok" {
		t.Fatalf("a call through the app-group socket: %v %q", err, answer)
	}

	started.daemon.setPeerCheck(func(conn net.Conn) error {
		return checkDaemonPeerUid(os.Getuid()+1, os.Getuid())
	})
	if _, err := DialDaemon(context.Background(), paths[0], &DaemonHello{Mode: DaemonModeControl, Version: testDaemonVersion}); err == nil {
		t.Fatal("a peer of another uid got a session through the app-group socket")
	}

	// every other instance's name is as short, and its own
	if name := DaemonAppGroupSocketName("work"); len(name) != 8 || name[0] != 'u' || name == DaemonAppGroupSocketName("default") ||
		name == DaemonAppGroupSocketName("work2") {
		t.Fatalf("a named instance's socket name %q", name)
	}
	// a home whose container path would pass sun_path takes no socket there
	long := filepath.Join(home, "a-directory-name-long-enough-that-the-container-path-and-its-socket-pass-sun-path")
	if err := os.MkdirAll(filepath.Join(long, "Library", "Group Containers", "6BGU69Q742.group.network.ur"), 0o700); err != nil {
		t.Fatal(err)
	}
	if paths := DaemonAppGroupSocketPaths("default", long); len(paths) != 0 {
		t.Fatalf("a path past sun_path: %v", paths)
	}
}
