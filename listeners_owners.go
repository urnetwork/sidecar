//go:build !ios_extension && !sidecar_http

// Which process holds a socket (DESIGN-COMPUTE §26.5's owner column; LSTN-M13-02, LSTN-M13-03): a resumable scan of
// the processes this one may read, over an OS's source of them, Linux's /proc (listeners_procfs.go) or macOS's libproc
// (listeners_discover_darwin.go). No OS tag: a fixture source stands in on every host.
//
//	who      a socket of another OS user is "another user's program" unless this process is root, as an enclave's
//	         daemon is (§26.5); a root process scans every process, any other only its own user's, the rest of the
//	         OS refusing it
//	hints    a socket whose table names a process that used it (macOS's so_last_pid) is looked for there first
//	budget   at most OwnerScanMaxCount socket lookups a call, resuming where the last call stopped, so a machine with
//	         many processes is covered over several dumps and no dump scans them all
//	misses   a socket still unfound after a whole pass that began once it was asked for is "a system program": its
//	         process is gone, in another PID namespace, protected, or the kernel's own
//
// Nothing read here reaches a log (I-13). Not safe for concurrent use: the poller calls it from its one goroutine.

package sidecar

import (
	"slices"
)

// The processes an OS lets this one read, and their sockets.
type listenersOwnerSource interface {
	// Every process's pid, ascending.
	pids() []int
	// pid's descriptors that may be sockets, in order; none where the OS refuses this process or pid ended.
	fds(pid int) []string
	// The socket identity behind pid's fd, as a dump names it, and false where fd is no socket.
	identity(pid int, fd string) (uint64, bool)
	// pid's name, empty where it does not read.
	name(pid int) string
}

// A resumable scan of one source.
type listenersOwnerScanner struct {
	source    listenersOwnerSource
	superuser bool
	euid      uint32
	maxCount  int

	// the pass in progress: its number, its pids, the pid it is at and that pid's fds, the fd it is at
	pass    uint64
	pids    []int
	pidNext int
	fds     []string
	fdNext  int
	// the pass each socket still asked for was first asked in, by identity
	wantedSince map[uint64]uint64
}

// A scanner over source for a process of euid, at most maxCount lookups a call.
func newListenersOwnerScanner(source listenersOwnerSource, euid uint32, maxCount int) *listenersOwnerScanner {
	return &listenersOwnerScanner{
		source:      source,
		superuser:   euid == 0,
		euid:        euid,
		maxCount:    maxCount,
		wantedSince: map[uint64]uint64{},
	}
}

// Names what of sockets it can (the file's comment): another user's at once, then each hinted pid, then the scan,
// within the budget. Each socket named leaves the asked-for set; the set is trimmed to sockets, so a socket gone is no
// longer looked for. hints names, by identity, a process to look in first.
func (self *listenersOwnerScanner) owners(sockets []*ListenersSocket, hints map[uint64][]int32) {
	wanted := map[uint64][]*ListenersSocket{}
	for _, socket := range sockets {
		switch {
		case socket.Owner != ListenersOwnerUnknown:
		case !self.superuser && socket.UidKnown && socket.Uid != self.euid:
			socket.Owner = ListenersOwnerOtherUser
		case socket.Inode == 0:
			socket.Owner = ListenersOwnerSystem
		default:
			wanted[socket.Inode] = append(wanted[socket.Inode], socket)
		}
	}
	for identity := range self.wantedSince {
		if _, ok := wanted[identity]; !ok {
			delete(self.wantedSince, identity)
		}
	}
	if len(wanted) == 0 {
		return
	}
	// a socket first asked for now waits for a pass that begins after this one, unless no pass is under way
	since := self.pass
	if self.pids != nil {
		since += 1
	}
	for identity := range wanted {
		if _, ok := self.wantedSince[identity]; !ok {
			self.wantedSince[identity] = since
		}
	}

	name := func(identity uint64, pid int) {
		sockets := wanted[identity]
		if sockets == nil {
			return
		}
		program := self.source.name(pid)
		for _, socket := range sockets {
			socket.Pid = int32(pid)
			if program == "" {
				// a process with no name, or one that ended as it was read
				socket.Owner = ListenersOwnerSystem
			} else {
				socket.Owner = ListenersOwnerProgram
				socket.Program = program
			}
		}
		delete(wanted, identity)
		delete(self.wantedSince, identity)
	}
	budget := self.maxCount

	// the hinted processes first, each looked through once a call
	hinted := []int{}
	for identity := range wanted {
		for _, pid := range hints[identity] {
			if 0 < pid && !slices.Contains(hinted, int(pid)) {
				hinted = append(hinted, int(pid))
			}
		}
	}
	slices.Sort(hinted)
	for _, pid := range hinted {
		for _, fd := range self.source.fds(pid) {
			if budget <= 0 || len(wanted) == 0 {
				break
			}
			budget -= 1
			if identity, ok := self.source.identity(pid, fd); ok {
				name(identity, pid)
			}
		}
	}

	for 0 < budget && 0 < len(wanted) {
		if self.pids == nil {
			self.pass += 1
			self.pids = self.source.pids()
			self.pidNext = 0
			self.fds = nil
		}
		if self.fds == nil {
			if len(self.pids) <= self.pidNext {
				// the pass is done: what it was asked for from its start and did not find has no process to name
				for identity, wantedSince := range self.wantedSince {
					if wantedSince <= self.pass {
						for _, socket := range wanted[identity] {
							socket.Owner = ListenersOwnerSystem
						}
						delete(wanted, identity)
						delete(self.wantedSince, identity)
					}
				}
				self.pids = nil
				continue
			}
			self.fds = self.source.fds(self.pids[self.pidNext])
			self.fdNext = 0
		}
		pid := self.pids[self.pidNext]
		for self.fdNext < len(self.fds) && 0 < budget {
			fd := self.fds[self.fdNext]
			self.fdNext += 1
			budget -= 1
			if identity, ok := self.source.identity(pid, fd); ok {
				name(identity, pid)
			}
		}
		if len(self.fds) <= self.fdNext {
			self.fds = nil
			self.pidNext += 1
		}
	}
}
