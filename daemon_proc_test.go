//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's pid ancestry (daemon_proc.go): a walk up a process tree that stops at the first process, at a parent younger
// than its child, at a cycle and at its bound; the harness process past any shells; /proc's stat line; and, for real,
// this test's own ancestry and the peer pid a daemon reads of a dialer.

package sidecar

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A process tree a test writes by hand.
type testProcessTable map[int]*ProcessInfo

func (self testProcessTable) Process(pid int) (*ProcessInfo, error) {
	process, ok := self[pid]
	if !ok {
		return nil, ErrProcessUnknown
	}
	copied := *process
	return &copied, nil
}

// Adds a process.
func (self testProcessTable) add(pid int, parentPid int, startMillis int64, name string) {
	self[pid] = &ProcessInfo{Identity: ProcessIdentity{Pid: pid, StartMillis: startMillis}, ParentPid: parentPid, Name: name}
}

// The pids of an ancestry.
func ancestorPids(ancestors []*ProcessInfo) []int {
	pids := []int{}
	for _, ancestor := range ancestors {
		pids = append(pids, ancestor.Identity.Pid)
	}
	return pids
}

func TestProcessAncestorsWalksToTheFirstProcess(t *testing.T) {
	table := testProcessTable{}
	table.add(1, 0, 1, "launchd")
	table.add(10, 1, 100, "zsh")
	table.add(20, 10, 200, "claude")
	table.add(30, 20, 300, "sh")
	table.add(40, 30, 400, "ur")
	ancestors, err := ProcessAncestors(table, 40, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got := ancestorPids(ancestors); len(got) != 4 || got[0] != 40 || got[3] != 10 {
		t.Errorf("ancestry %v, want [40 30 20 10]", got)
	}
	if harness := HarnessProcessOf(ancestors, DefaultSidecarSettings().Ingest.ShellNames); harness == nil || harness.Identity.Pid != 20 {
		t.Errorf("the harness process is %v, want claude past the hook's shell", harness)
	}
	if _, err := ProcessAncestors(table, 99, 64); err == nil {
		t.Error("a pid with no process has an ancestry")
	}
}

// A parent younger than its child is a reused pid, and a walk stops before it; so does a cycle, and the bound.
func TestProcessAncestorsStopsAtAReusedParent(t *testing.T) {
	table := testProcessTable{}
	table.add(10, 1, 100, "zsh")
	// 20's parent exited, and its pid went to a process started after 20
	table.add(20, 30, 200, "claude")
	table.add(30, 10, 900, "unrelated")
	ancestors, err := ProcessAncestors(table, 20, 64)
	if err != nil || len(ancestors) != 1 {
		t.Errorf("ancestry %v through a reused parent: %v", ancestorPids(ancestors), err)
	}
	cycle := testProcessTable{}
	cycle.add(50, 60, 100, "a")
	cycle.add(60, 50, 100, "b")
	if ancestors, err := ProcessAncestors(cycle, 50, 64); err != nil || len(ancestors) != 2 {
		t.Errorf("a cycle's ancestry %v: %v", ancestorPids(ancestors), err)
	}
	if ancestors, _ := ProcessAncestors(table, 20, 1); len(ancestors) != 1 {
		t.Errorf("the bound let %d entries through", len(ancestors))
	}
}

// Shells are stepped over by name, any case, .exe or not; a chain of only shells has no harness.
func TestHarnessProcessSkipsShells(t *testing.T) {
	table := testProcessTable{}
	table.add(10, 1, 100, "Cursor Helper")
	table.add(20, 10, 200, "PowerShell.exe")
	table.add(30, 20, 300, "bash")
	table.add(40, 30, 400, "ur")
	ancestors, _ := ProcessAncestors(table, 40, 64)
	if harness := HarnessProcessOf(ancestors, DefaultSidecarSettings().Ingest.ShellNames); harness == nil || harness.Identity.Pid != 10 {
		t.Errorf("the harness process is %v", harness)
	}
	shells := testProcessTable{}
	shells.add(30, 1, 300, "bash")
	shells.add(40, 30, 400, "ur")
	ancestors, _ = ProcessAncestors(shells, 40, 64)
	if harness := HarnessProcessOf(ancestors, DefaultSidecarSettings().Ingest.ShellNames); harness != nil {
		t.Errorf("a chain of shells has harness %v", harness)
	}
}

// /proc's stat line: a comm with spaces and parentheses is read from its last ')', and starttime's ticks become
// milliseconds since boot.
func TestParseProcStat(t *testing.T) {
	line := "4242 (node (claude) x) S 4100 4242 4100 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 11 0 123456 0 0\n"
	process, err := parseProcStat(4242, []byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if process.Name != "node (claude) x" || process.ParentPid != 4100 || process.Identity.StartMillis != 1234560 {
		t.Errorf("read %+v", process)
	}
	for _, bad := range []string{"", "4242 node S 1", "4242 (x) S", "4242 (x) S notapid 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"} {
		if _, err := parseProcStat(4242, []byte(bad)); err == nil {
			t.Errorf("%q read", bad)
		}
	}
}

// This test's own ancestry, from the system: itself first, then its parent, each with a start time.
func TestSystemProcessAncestryOfThisProcess(t *testing.T) {
	ancestors, err := ProcessAncestors(SystemProcessTable(), os.Getpid(), 64)
	if err != nil {
		t.Fatalf("this process's ancestry: %s", err)
	}
	if ancestors[0].Identity.Pid != os.Getpid() || ancestors[0].Identity.StartMillis <= 0 {
		t.Errorf("first entry %+v", ancestors[0])
	}
	if 1 < os.Getppid() && (len(ancestors) < 2 || ancestors[1].Identity.Pid != os.Getppid()) {
		t.Errorf("ancestry %v, want the parent %d second", ancestorPids(ancestors), os.Getppid())
	}
	again, _ := SystemProcessTable().Process(os.Getpid())
	if again == nil || again.Identity != ancestors[0].Identity {
		t.Error("two readings of this process differ")
	}
}

// The daemon reads a session's peer pid from the system, never the hello: a dialer in this process is this process.
func TestDaemonPeerPidIsTheDialer(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "ur-proc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socketPath := filepath.Join(directory, "s")
	daemon, err := NewDaemon(context.Background(), &DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          DefaultSidecarSettings().LocalSettings,
	})
	if err != nil {
		t.Fatal(err)
	}
	hellos := make(chan *DaemonHello, 1)
	daemon.RegisterMode(DaemonModeMcp, func(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
		hellos <- hello
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run()
	}()
	defer func() {
		daemon.Close()
		<-done
	}()
	client, err := DialDaemon(context.Background(), socketPath, &DaemonHello{Mode: DaemonModeMcp, Pid: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	hello := <-hellos
	if hello.Pid != 12345 || hello.PeerPid != int64(os.Getpid()) {
		t.Errorf("the hello's pid %d, its peer pid %d, want %d", hello.Pid, hello.PeerPid, os.Getpid())
	}
}
