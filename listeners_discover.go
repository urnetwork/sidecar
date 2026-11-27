//go:build !ios_extension && !sidecar_http

// Discovery (DESIGN-COMPUTE §26.5, R-LSTN-3, D-LSTN-2, IC-21; LSTN-M13-02): what a device's bridge reads of its OS's
// socket tables, and the poll that keeps it current.
//
//	ListenersDiscoverer  an OS's tables: every TCP socket listening and every bound, unconnected UDP socket, IPv4 and
//	                     IPv6, with what the table says of its owner (Dump); the owners of sockets new to the poller,
//	                     within a budget a dump (Owners); and a destruction notice where the OS multicasts one
//	                     (Destroyed). Linux's sock_diag (listeners_discover_linux.go), macOS's pcblist and libproc and
//	                     Windows' iphlpapi (LSTN-M13-03); none on iOS, Android, js and every other leg
//	                     (listeners_discover_other.go, R-LSTN-9), whose lists hold no sockets
//	ListenersPoller      a dump every PollInterval on the injected clock, and at once at a live ask (Ask, §26.8) or a
//	                     destruction notice, never two within DumpMinInterval; owners looked up only for a socket new
//	                     since the last dump, from a cache keyed by the socket's identity and trimmed to the live set
//
// Never a probe (D-LSTN-2, IC-21): discovery reads tables and opens no socket but the OS's table interface (netlink on
// Linux); it sends nothing to any port and reads no banner. A dump cut by an error, a timeout or a short read is no
// change, never every socket gone: the poller keeps its last dump and hands nothing on. Nothing a table holds reaches a
// log but counts (I-13).

package sidecar

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What the OS says of a socket's owner.
type ListenersOwner int

const (
	// not looked up yet, or not found within a dump's budget: the next dump looks again
	ListenersOwnerUnknown ListenersOwner = iota
	// a process the bridge may name: Program holds its name
	ListenersOwnerProgram
	// another OS user's process, which the bridge may not name: "another user's program" (§26.4)
	ListenersOwnerOtherUser
	// a socket the OS names no process for, or will not: "a system program" (§26.4)
	ListenersOwnerSystem
)

// One socket of an OS's table.
type ListenersSocket struct {
	// TCP, listening; or UDP, bound and unconnected
	Protocol protocol.ListenersProtocol
	// The address it binds, the unspecified one for every interface of its family; an IPv6 link-local one keeps its
	// zone.
	Bind netip.Addr
	Port uint16
	// An IPv6 socket that takes no IPv4: Linux's INET_DIAG_SKV6ONLY, macOS's IN6P_IPV6_V6ONLY or a pcb without
	// INP_IPV4.
	V6Only bool
	// Windows' "::" socket, whose table does not say whether it takes IPv4 (§26.5's v4?).
	V4Uncertain bool
	// The OS's identity of the socket while it lives, which the owner cache is keyed by: Linux's inode, macOS's
	// socket's kernel id, Windows' row's own (protocol, address, port and pid).
	Inode uint64
	// The OS user whose socket it is, where the table says (UidKnown): Linux's and macOS's.
	Uid      uint32
	UidKnown bool
	// Its owner's pid where known, 0 otherwise.
	Pid int32
	// Its owner's name, set with ListenersOwnerProgram: the OS's word, which the list cleans as a description.
	Program string
	Owner   ListenersOwner
}

// One dump that succeeded.
type ListenersDump struct {
	Sockets []*ListenersSocket
	// The OS's first ephemeral port: Linux's ip_local_port_range, else EphemeralFirstPort (§26.5's UDP rule).
	EphemeralFirstPort uint16
	// The poller's clock when the dump finished.
	At time.Time
}

// An OS's socket tables (the file's comment). Dump and Owners are called from one goroutine at a time; Destroyed and
// EphemeralFirstPort are safe for concurrent use.
type ListenersDiscoverer interface {
	// Every TCP socket in LISTEN and every bound, unconnected UDP socket, IPv4 and IPv6, with Inode, the table's owner
	// fields and Owner as the table alone settles it. An error is a cut dump, which changes nothing.
	Dump(ctx context.Context) ([]*ListenersSocket, error)
	// Fills Owner, Pid and Program on what of sockets, all ListenersOwnerUnknown and new to the poller, it can name
	// within OwnerScanMaxCount lookups, resuming where it stopped at the next call; what it cannot reach yet stays
	// unknown.
	Owners(ctx context.Context, sockets []*ListenersSocket) error
	// Fires after a socket the last dump listed is destroyed: nil where the OS sends no notice (macOS, Windows).
	Destroyed() <-chan struct{}
	// The OS's first ephemeral port.
	EphemeralFirstPort() uint16
	// Ends what the discoverer holds open. A dump in flight ends with an error.
	Close() error
}

// Discovery is not on this leg: iOS, Android, js and every leg but desktop Linux, macOS and Windows (R-LSTN-9).
var ErrListenersNoDiscovery = errors.New("listeners: this device's OS shows no other program's sockets")

// What NewListenersPoller takes.
type ListenersPollerArgs struct {
	Discoverer ListenersDiscoverer
	// Takes each dump that succeeded, on the poller's goroutine, which waits for it: it must not block on the poller.
	// Nil drops them, Last still answering.
	OnDump func(dump *ListenersDump)
	// nil is real time
	Clock Clock
	// nil is the default logger
	Log Logger
	// nil is DefaultListenersSettings
	Settings *ListenersSettings
}

// The poll (the file's comment): it runs from NewListenersPoller until Close or its context ends. Safe for concurrent
// use.
type ListenersPoller struct {
	ctx        context.Context
	cancel     context.CancelFunc
	discoverer ListenersDiscoverer
	onDump     func(dump *ListenersDump)
	clock      Clock
	log        Logger
	settings   *ListenersSettings
	// woken by Ask, holding at most one wake
	askWake chan struct{}
	done    chan struct{}

	stateLock sync.Mutex
	last      *ListenersDump
	// closed after the next dump that starts after an Ask, and replaced
	askDone chan struct{}
	asked   bool
	// the owners named so far, by socket identity, trimmed to each dump's live set
	owners map[uint64]*ListenersSocket
	// failed dumps and owner lookups, counted, never their contents (I-13)
	failedDumpCount  uint64
	failedOwnerCount uint64
}

// A poller running at once, its first dump made as it starts.
func NewListenersPoller(ctx context.Context, args *ListenersPollerArgs) (*ListenersPoller, error) {
	if args == nil || args.Discoverer == nil {
		return nil, ErrListenersNoDiscovery
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultListenersSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := loggerOrDefault(args.Log)
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &ListenersPoller{
		ctx:        cancelCtx,
		cancel:     cancel,
		discoverer: args.Discoverer,
		onDump:     args.OnDump,
		clock:      clock,
		log:        log,
		settings:   settings,
		askWake:    make(chan struct{}, 1),
		done:       make(chan struct{}),
		askDone:    make(chan struct{}),
		owners:     map[uint64]*ListenersSocket{},
	}
	go self.run()
	return self, nil
}

// Asks for a dump at once (§26.8's live ask), or as soon as DumpMinInterval since the last has passed; the channel
// closes once a dump that started after the ask has ended, whether or not it succeeded, or the poller has closed.
func (self *ListenersPoller) Ask() <-chan struct{} {
	var done chan struct{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.asked = true
		done = self.askDone
	}()
	select {
	case self.askWake <- struct{}{}:
	default:
		// a wake is already waiting, which this ask joins
	}
	return done
}

// The last dump that succeeded, nil before one. The caller must not change it.
func (self *ListenersPoller) Last() *ListenersDump {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.last
}

// How many dumps were cut and how many owner lookups failed, for ur status's counts (I-13).
func (self *ListenersPoller) FailureCounts() (dumps uint64, owners uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.failedDumpCount, self.failedOwnerCount
}

// Ends the poll and waits for its goroutine, then closes the discoverer.
func (self *ListenersPoller) Close() {
	self.cancel()
	<-self.done
	self.discoverer.Close()
}

// The loop (the file's comment): a dump, then a wait for the interval, an ask or a notice, at most one dump each
// DumpMinInterval.
func (self *ListenersPoller) run() {
	defer close(self.done)
	defer func() {
		// an ask still waiting ends with the poller
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		close(self.askDone)
	}()
	destroyed := self.discoverer.Destroyed()
	var lastDumpAt time.Time
	for {
		if !lastDumpAt.IsZero() {
			// rate-limit a run of asks and notices: one dump each DumpMinInterval at most, the wait set for its time
			// so a clock moved meanwhile sets it no later (clock_at.go)
			if next := lastDumpAt.Add(self.settings.DumpMinInterval); self.clock.Now().Before(next) {
				select {
				case <-self.ctx.Done():
					return
				case <-ClockAfterAt(self.clock, next):
				}
			}
		}
		lastDumpAt = self.clock.Now()
		self.dump()

		// the next poll PollInterval after this one began
		tick := make(chan struct{})
		stop := ClockAfterFuncAt(self.clock, lastDumpAt.Add(self.settings.PollInterval), func() {
			close(tick)
		})
		select {
		case <-self.ctx.Done():
			stop()
			return
		case <-tick:
		case <-self.askWake:
		case <-destroyed:
		}
		stop()
	}
}

// One dump: the table, the owners of what is new, the cache trimmed, then OnDump. An ask waiting when it starts is
// answered when it ends.
func (self *ListenersPoller) dump() {
	var askDone chan struct{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.asked {
			askDone = self.askDone
			self.askDone = make(chan struct{})
			self.asked = false
		}
	}()
	if askDone != nil {
		defer close(askDone)
	}

	dumpCtx, cancel := context.WithTimeout(self.ctx, self.settings.DumpTimeout)
	defer cancel()
	sockets, err := self.discoverer.Dump(dumpCtx)
	if err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.failedDumpCount += 1
		}()
		if self.ctx.Err() == nil {
			self.log.Warningf("[listeners] a dump failed and changes nothing")
		}
		return
	}

	owners := func() map[uint64]*ListenersSocket {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.owners
	}()
	unknown := []*ListenersSocket{}
	for _, socket := range sockets {
		if socket.Owner != ListenersOwnerUnknown {
			continue
		}
		if owner, ok := owners[socket.Inode]; ok {
			socket.Owner, socket.Pid, socket.Program = owner.Owner, owner.Pid, owner.Program
			continue
		}
		unknown = append(unknown, socket)
	}
	if 0 < len(unknown) {
		if err := self.discoverer.Owners(dumpCtx, unknown); err != nil {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.failedOwnerCount += 1
			}()
		}
	}
	// the cache keeps what is named, trimmed to the live set
	nextOwners := map[uint64]*ListenersSocket{}
	for _, socket := range sockets {
		if socket.Owner != ListenersOwnerUnknown {
			nextOwners[socket.Inode] = &ListenersSocket{Owner: socket.Owner, Pid: socket.Pid, Program: socket.Program}
		}
	}
	slices.SortStableFunc(sockets, listenersSocketCompare)
	dump := &ListenersDump{
		Sockets:            sockets,
		EphemeralFirstPort: self.discoverer.EphemeralFirstPort(),
		At:                 self.clock.Now(),
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.owners = nextOwners
		self.last = dump
	}()
	if self.onDump != nil {
		self.onDump(dump)
	}
}

// The dump's order: protocol, port, address, identity, so two dumps of one table read alike.
func listenersSocketCompare(a *ListenersSocket, b *ListenersSocket) int {
	switch {
	case a.Protocol != b.Protocol:
		return int(a.Protocol) - int(b.Protocol)
	case a.Port != b.Port:
		return int(a.Port) - int(b.Port)
	}
	if order := a.Bind.Compare(b.Bind); order != 0 {
		return order
	}
	switch {
	case a.Inode < b.Inode:
		return -1
	case b.Inode < a.Inode:
		return 1
	}
	return 0
}

// Whether the poller holds an owner for identity, for tests of the cache's trim.
func (self *ListenersPoller) ownerCached(identity uint64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, ok := self.owners[identity]
	return ok
}
