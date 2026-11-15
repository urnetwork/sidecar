// The sender's forward-confirmed PTR (§15.5's MailIngress.ptr_name, §2.8 mx-1; MAIL-M7-19): looked up on
// a goroutine of its own from the session's admission, so the dialog runs while it answers, and read once,
// without waiting, when MailIngress is built. A lookup the handoff outruns, one that fails, one past
// PtrTimeout and one the process has no slot for all leave "", which a receiver reads as no PTR: labels
// use the receiver's own lookup, never this one (§15.5), so a missing or late answer costs a reader
// nothing it relies on.
//
// Forward-confirmed is RFC 8601 §3's iprev: a name the address's PTR answers whose own A or AAAA answers
// hold the address. At most PtrNameCount names are tried, in the order the resolver gave them, and the
// first that confirms wins. The resolver is the host's (MxEdgeRouterDeps.LookupPtr and LookupHost), and
// nil answers nothing.
//
// No name, address or error here reaches a log or a metric (I-13). Safe for concurrent use.

package mxedgeservice

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// One session's lookup.
type mxPtrLookup struct {
	cancel context.CancelFunc
	// closed once the lookup has ended, its name set first
	done chan struct{}
	name string
}

// A lookup that never ran: no resolver, or no slot.
func newMxPtrLookupNone() *mxPtrLookup {
	done := make(chan struct{})
	close(done)
	return &mxPtrLookup{cancel: func() {}, done: done}
}

// The confirmed name if the lookup has ended, else "", with no wait.
func (self *mxPtrLookup) Name() string {
	select {
	case <-self.done:
		return self.name
	default:
		return ""
	}
}

// Ends the lookup, which a session does at its end. Safe more than once.
func (self *mxPtrLookup) Stop() {
	self.cancel()
}

// The process's lookups, bounded by PtrLookupCount at once.
type mxPtrLookups struct {
	settings   *MxEdgeSettings
	lookupPtr  func(ctx context.Context, sender netip.Addr) ([]string, error)
	lookupHost func(ctx context.Context, name string) ([]netip.Addr, error)
	service    *MxEdgeService
	// a token for each lookup running
	slots chan struct{}
	// every lookup's goroutine, which the engine waits for at its end
	group sync.WaitGroup
	// lookups ended, each counted once its name is readable, so a wait can see one land
	endCount *sidecar.MonitorValue[int]
}

func newMxPtrLookups(service *MxEdgeService, deps *MxEdgeRouterDeps) *mxPtrLookups {
	return &mxPtrLookups{
		settings:   service.settings,
		lookupPtr:  deps.LookupPtr,
		lookupHost: deps.LookupHost,
		service:    service,
		slots:      make(chan struct{}, service.settings.PtrLookupCount),
		endCount:   sidecar.NewMonitorValue(0),
	}
}

// Starts sender's lookup, bounded by PtrTimeout on the engine's clock and by the engine's life. With no
// resolver or no free slot it starts nothing, and the name stays "".
func (self *mxPtrLookups) Start(sender netip.Addr) *mxPtrLookup {
	if self.lookupPtr == nil || self.lookupHost == nil {
		return newMxPtrLookupNone()
	}
	select {
	case self.slots <- struct{}{}:
	default:
		self.service.metrics.ptrLookups.Add(1, mxPtrResultNoSlot)
		return newMxPtrLookupNone()
	}
	ctx, cancel := context.WithCancel(self.service.ctx)
	stopTimer := self.service.clock.AfterFunc(self.settings.PtrTimeout, cancel)
	lookup := &mxPtrLookup{cancel: cancel, done: make(chan struct{})}
	self.group.Add(1)
	go func() {
		defer self.group.Done()
		defer func() {
			<-self.slots
		}()
		defer self.endCount.Update(func(count int) int { return count + 1 })
		defer close(lookup.done)
		defer stopTimer()
		defer cancel()
		name := self.confirm(ctx, sender)
		if ctx.Err() != nil {
			// an answer after the bound or the session's end is no answer
			name = ""
		}
		lookup.name = name
		if name == "" {
			self.service.metrics.ptrLookups.Add(1, mxPtrResultNone)
		} else {
			self.service.metrics.ptrLookups.Add(1, mxPtrResultConfirmed)
		}
	}()
	return lookup
}

// The first of sender's PTR names whose forward lookup holds sender, normalized, or "".
func (self *mxPtrLookups) confirm(ctx context.Context, sender netip.Addr) string {
	sender = sender.Unmap().WithZone("")
	names, err := self.lookupPtr(ctx, sender)
	if err != nil {
		return ""
	}
	for i, name := range names {
		if self.settings.PtrNameCount <= i {
			break
		}
		name, ok := self.normalize(name)
		if !ok {
			continue
		}
		addrs, err := self.lookupHost(ctx, name)
		if err != nil {
			if ctx.Err() != nil {
				return ""
			}
			continue
		}
		for _, addr := range addrs {
			if addr.Unmap().WithZone("") == sender {
				return name
			}
		}
	}
	return ""
}

// A PTR name as MailIngress carries it: lowercase, no final dot, LDH labels within RFC 1035's lengths,
// so it is valid UTF-8 and names a host. false for anything else.
func (self *mxPtrLookups) normalize(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !self.settings.ldhNameFits(name) || self.settings.Ingress.HostNameMaxByteCount < len(name) {
		return "", false
	}
	return name, true
}
