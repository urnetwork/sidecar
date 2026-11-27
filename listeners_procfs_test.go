//go:build !ios_extension && !sidecar_http && !js && !windows

package sidecar

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A fixture /proc: each pid's comm and its fds, each a link to its target, socket:[<inode>] for a socket's. A pid whose
// fds are nil has a directory that refuses this process, as another user's does.
func testProcTree(t *testing.T, processes map[int]testProcProcess) string {
	t.Helper()
	root := t.TempDir()
	for pid, process := range processes {
		directory := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(filepath.Join(directory, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "comm"), []byte(process.comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for fd, target := range process.fds {
			if err := os.Symlink(target, filepath.Join(directory, "fd", strconv.Itoa(fd))); err != nil {
				t.Fatal(err)
			}
		}
		if process.refused {
			if err := os.Chmod(filepath.Join(directory, "fd"), 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(filepath.Join(directory, "fd"), 0o755) })
		}
	}
	// what else /proc holds: a file and a directory that are no process
	os.WriteFile(filepath.Join(root, "uptime"), []byte("1.0 1.0\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "sys", "net", "ipv4"), 0o755)
	return root
}

type testProcProcess struct {
	comm    string
	fds     map[int]string
	refused bool
}

// A socket of a dump: TCP on port, its inode and uid.
func testProcSocket(port uint16, inode uint64, uid uint32) *ListenersSocket {
	return &ListenersSocket{Protocol: protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: port, Inode: inode, Uid: uid, UidKnown: true}
}

// Owners from the fixture tree: a socket of this user's process by its comm, another user's as "another user's program"
// without a scan, and as root by its comm; a socket no process holds after a whole pass, a system program's.
func TestListenersProcOwners(t *testing.T) {
	root := testProcTree(t, map[int]testProcProcess{
		100: {comm: "postgres", fds: map[int]string{0: "/dev/null", 3: "socket:[1001]", 4: "pipe:[77]"}},
		200: {comm: "node", fds: map[int]string{5: "socket:[1002]"}},
		300: {comm: "sshd", fds: map[int]string{3: "socket:[1003]"}},
	})
	scanner := newListenersProcScanner(root, 1000, 4096)
	ours := testProcSocket(5432, 1001, 1000)
	node := testProcSocket(3000, 1002, 1000)
	other := testProcSocket(22, 1003, 0)
	orphan := testProcSocket(2049, 1009, 1000)
	scanner.owners([]*ListenersSocket{ours, node, other, orphan}, nil)
	if ours.Owner != ListenersOwnerProgram || ours.Program != "postgres" || ours.Pid != 100 {
		t.Errorf("ours: %+v", *ours)
	}
	if node.Owner != ListenersOwnerProgram || node.Program != "node" || node.Pid != 200 {
		t.Errorf("node: %+v", *node)
	}
	if other.Owner != ListenersOwnerOtherUser || other.Program != "" {
		t.Errorf("another user's: %+v", *other)
	}
	if orphan.Owner != ListenersOwnerSystem {
		t.Errorf("one no process holds: %+v", *orphan)
	}

	// as root, another user's socket is named by its process
	superuser := newListenersProcScanner(root, 0, 4096)
	other = testProcSocket(22, 1003, 0)
	otherUser := testProcSocket(5432, 1001, 1000)
	superuser.owners([]*ListenersSocket{other, otherUser}, nil)
	if other.Owner != ListenersOwnerProgram || other.Program != "sshd" || otherUser.Program != "postgres" {
		t.Errorf("as root: %+v, %+v", *other, *otherUser)
	}
}

// A directory that refuses this process is passed over, its sockets unnamed by it.
func TestListenersProcOwnersPassesARefusedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory mode 000")
	}
	root := testProcTree(t, map[int]testProcProcess{
		100: {comm: "secret", fds: map[int]string{3: "socket:[1001]"}, refused: true},
		200: {comm: "node", fds: map[int]string{3: "socket:[1002]"}},
	})
	scanner := newListenersProcScanner(root, 1000, 4096)
	hidden := testProcSocket(8080, 1001, 1000)
	node := testProcSocket(3000, 1002, 1000)
	scanner.owners([]*ListenersSocket{hidden, node}, nil)
	if hidden.Owner != ListenersOwnerSystem || node.Program != "node" {
		t.Errorf("%+v, %+v", *hidden, *node)
	}
}

// The budget: at most maxCount links a call, the scan resuming where it stopped, a socket named once its process's
// link is reached; a socket first asked for in the middle of a pass is not called a system program's until a whole
// pass after it has missed it.
func TestListenersProcOwnersBudgetResumes(t *testing.T) {
	root := testProcTree(t, map[int]testProcProcess{
		100: {comm: "a", fds: map[int]string{0: "/dev/null", 1: "/dev/null", 2: "/dev/null"}},
		200: {comm: "b", fds: map[int]string{0: "/dev/null", 1: "socket:[2001]"}},
		300: {comm: "c", fds: map[int]string{0: "socket:[3001]"}},
	})
	scanner := newListenersProcScanner(root, 1000, 2)
	b := testProcSocket(80, 2001, 1000)
	c := testProcSocket(81, 3001, 1000)
	scanner.owners([]*ListenersSocket{b, c}, nil)
	if b.Owner != ListenersOwnerUnknown || c.Owner != ListenersOwnerUnknown {
		t.Fatalf("two links named %+v, %+v", *b, *c)
	}
	scanner.owners([]*ListenersSocket{b, c}, nil)
	if b.Owner != ListenersOwnerUnknown {
		t.Fatalf("four links: %+v", *b)
	}
	// the third call reaches both, and asks besides for a socket mid-pass, behind the scan's place
	late := testProcSocket(82, 1009, 1000)
	scanner.owners([]*ListenersSocket{b, c, late}, nil)
	if b.Owner != ListenersOwnerProgram || b.Program != "b" || c.Owner != ListenersOwnerProgram || c.Program != "c" {
		t.Fatalf("six links: %+v, %+v", *b, *c)
	}
	// the pass in progress ends, then a whole pass runs over its six links, two a call: only its end names late's
	// socket one no process holds
	for call := range 3 {
		scanner.owners([]*ListenersSocket{late}, nil)
		if late.Owner != ListenersOwnerUnknown {
			t.Fatalf("late named at call %d, before a whole pass: %+v", call, *late)
		}
	}
	scanner.owners([]*ListenersSocket{late}, nil)
	if late.Owner != ListenersOwnerSystem {
		t.Errorf("late after a whole pass: %+v", *late)
	}
	if len(scanner.wantedSince) != 0 {
		t.Errorf("the scanner still asks for %v", scanner.wantedSince)
	}
}
