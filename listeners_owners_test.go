//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"slices"
	"strconv"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A process table as libproc shows it to this user: each pid's socket fds and the handles behind them, its name, and
// whether it refuses this process; the lookups it answered, counted.
type testOwnerSource struct {
	processes map[int]testOwnerProcess
	lookups   int
}

type testOwnerProcess struct {
	name    string
	handles []uint64
	refused bool
}

func (self *testOwnerSource) pids() []int {
	pids := []int{}
	for pid := range self.processes {
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	return pids
}

func (self *testOwnerSource) fds(pid int) []string {
	process, ok := self.processes[pid]
	if !ok || process.refused {
		return []string{}
	}
	fds := []string{}
	for fd := range process.handles {
		fds = append(fds, strconv.Itoa(fd))
	}
	return fds
}

func (self *testOwnerSource) identity(pid int, fd string) (uint64, bool) {
	self.lookups += 1
	number, err := strconv.Atoi(fd)
	process := self.processes[pid]
	if err != nil || len(process.handles) <= number {
		return 0, false
	}
	return process.handles[number], true
}

func (self *testOwnerSource) name(pid int) string {
	return self.processes[pid].name
}

// A TCP socket of the dump on port, its identity and uid.
func testOwnerSocket(port uint16, identity uint64, uid uint32) *ListenersSocket {
	return &ListenersSocket{Protocol: protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, Port: port, Inode: identity, Uid: uid, UidKnown: true}
}

// Owner matching on a fake libproc table: a socket's handle found in the process its record names, looked in first,
// with no scan; another user's named without a lookup; one whose hinted process holds it no longer found by the scan
// in its real process; one in a process that refuses this one, after a whole pass, a system program's.
func TestListenersOwnersMatchOnAFakeLibprocTable(t *testing.T) {
	source := &testOwnerSource{processes: map[int]testOwnerProcess{
		400: {name: "postgres", handles: []uint64{0x5, 0x11}},
		401: {name: "node", handles: []uint64{0x12}},
		402: {name: "WindowServer", handles: []uint64{0x13}, refused: true},
		403: {name: "python3", handles: []uint64{0x6, 0x7, 0x8, 0x14}},
	}}
	scanner := newListenersOwnerScanner(source, 501, 4096)
	hinted := testOwnerSocket(5432, 0x11, 501)
	other := testOwnerSocket(3000, 0x15, 0)
	moved := testOwnerSocket(8000, 0x14, 501)
	refused := testOwnerSocket(7000, 0x13, 501)
	hints := map[uint64][]int32{0x11: {0, 400}, 0x14: {401}}

	scanner.owners([]*ListenersSocket{hinted}, hints)
	if hinted.Owner != ListenersOwnerProgram || hinted.Program != "postgres" || hinted.Pid != 400 || source.lookups != 2 {
		t.Errorf("hinted: %+v after %d lookups", *hinted, source.lookups)
	}
	scanner.owners([]*ListenersSocket{other, moved, refused}, hints)
	if other.Owner != ListenersOwnerOtherUser || other.Program != "" {
		t.Errorf("another user's: %+v", *other)
	}
	if moved.Program != "python3" || moved.Pid != 403 {
		t.Errorf("a hint that missed: %+v", *moved)
	}
	if refused.Owner != ListenersOwnerSystem {
		t.Errorf("in a process that refuses this one: %+v", *refused)
	}
}
