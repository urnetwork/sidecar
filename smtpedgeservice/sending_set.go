// The sending set (§14.6, owner decision 124, R-SMTP-14): the host's shared lb IPv4 addresses that may
// send now. An address sends only once its FCrDNS holds, its PTR naming its HELO name and that name's A
// record naming the address, checked at start and each FcrdnsCheckInterval off the path; and not while
// §21.5's breaker lists it, which removes it from sending within the feed refresh and leaves it in
// ingress (SmtpBreakerState.ListedAddresses). With no usable address the engine is not ready.
//
// A dial picks the usable address with the fewest live connections to the MX's /24, under §14.7's
// smtp_destination_concurrency (SmtpDestinationCaps), and holds that slot until its connection ends.
//
// A lookup that fails for now keeps the address's last verdict, so a DNS hiccup does not empty the set;
// an answer that disagrees takes the address out until a later check agrees. No address or name reaches
// a log or a metric label.
//
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// Reverse DNS for the sending addresses' FCrDNS, which server supplies (SMTP-M9-20) over the host's
// resolver. Safe for concurrent use.
type SmtpPtrResolver interface {
	// The PTR names of address, lowercase or not, with or without a trailing dot.
	// sidecar.ErrSmtpMxTemporary when the lookup failed for now.
	LookupPtr(ctx context.Context, address netip.Addr) ([]string, error)
}

// One address's FCrDNS verdict and whether it has ever been checked.
type smtpSendingAddressState struct {
	checked bool
	fcrdns  bool
}

// One edge's sending set: each sending address's FCrDNS verdict, checked by a run loop, and §21.5's
// listings, read at each use.
type SmtpSendingSet struct {
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	ptr      SmtpPtrResolver
	resolver sidecar.SmtpMxResolver
	breaker  func() (*SmtpBreakerState, bool)
	gauge    sidecar.MetricsGauge

	stateLock     sync.Mutex
	addressStates map[netip.Addr]*smtpSendingAddressState
	checkCount    *sidecar.MonitorValue[int]
	cancel        context.CancelFunc
	released      chan struct{}
}

// The set over settings' sending addresses, checking their FCrDNS through ptr and resolver now and each
// FcrdnsCheckInterval until ctx ends or Close. breaker gives §21.5's state, nil none.
func NewSmtpSendingSet(ctx context.Context, settings *SmtpEdgeSettings, clock sidecar.Clock, metrics sidecar.Metrics, ptr SmtpPtrResolver, resolver sidecar.SmtpMxResolver, breaker func() (*SmtpBreakerState, bool)) *SmtpSendingSet {
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &SmtpSendingSet{
		settings: settings,
		clock:    clock,
		ptr:      ptr,
		resolver: resolver,
		breaker:  breaker,
		gauge: metrics.Gauge("urnetwork_smtpedge_sending_addresses",
			"Sending addresses by state: usable, failing FCrDNS, or listed.", "state"),
		addressStates: map[netip.Addr]*smtpSendingAddressState{},
		checkCount:    sidecar.NewMonitorValue(0),
		cancel:        cancel,
		released:      make(chan struct{}),
	}
	for _, sendingAddress := range settings.SendingAddresses {
		self.addressStates[sendingAddress.Address.Unmap()] = &smtpSendingAddressState{}
	}
	go self.run(cancelCtx)
	return self
}

// Checks now and each FcrdnsCheckInterval.
func (self *SmtpSendingSet) run(ctx context.Context) {
	defer close(self.released)
	for {
		self.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.FcrdnsCheckInterval):
		}
	}
}

// Whether name names host, without case and a trailing dot.
func smtpSameName(name string, host string) bool {
	return strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(host, "."))
}

// One pass over every address, each under FcrdnsTimeout.
func (self *SmtpSendingSet) check(ctx context.Context) {
	for _, sendingAddress := range self.settings.SendingAddresses {
		address := sendingAddress.Address.Unmap()
		verdict, decided := self.checkOne(ctx, address, sendingAddress.HeloName)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			state := self.addressStates[address]
			if decided {
				state.checked = true
				state.fcrdns = verdict
			}
		}()
	}
	self.reportGauge()
	self.checkCount.Update(func(count int) int { return count + 1 })
}

// Whether address's FCrDNS holds for heloName, and false for decided when a lookup failed for now.
func (self *SmtpSendingSet) checkOne(ctx context.Context, address netip.Addr, heloName string) (verdict bool, decided bool) {
	if self.ptr == nil || self.resolver == nil {
		return false, true
	}
	checkCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.FcrdnsTimeout, cancel)
	defer func() {
		stop()
		cancel()
	}()
	transient := func(err error) bool {
		return errors.Is(err, sidecar.ErrSmtpMxTemporary) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	names, err := self.ptr.LookupPtr(checkCtx, address)
	if err != nil {
		return false, !transient(err)
	}
	if !slices.ContainsFunc(names, func(name string) bool { return smtpSameName(name, heloName) }) {
		return false, true
	}
	addresses, err := self.resolver.LookupAddresses(checkCtx, heloName)
	if err != nil {
		return false, !transient(err)
	}
	return slices.ContainsFunc(addresses, func(other netip.Addr) bool { return other.Unmap() == address }), true
}

// The breaker's state, or none while it is not loaded: the gate refuses every preamble then.
func (self *SmtpSendingSet) breakerState() *SmtpBreakerState {
	if self.breaker == nil {
		return nil
	}
	state, ok := self.breaker()
	if !ok {
		return nil
	}
	return state
}

// Sets the gauge from the states now.
func (self *SmtpSendingSet) reportGauge() {
	breaker := self.breakerState()
	usable, failing, listed := 0, 0, 0
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for address, state := range self.addressStates {
			switch {
			case breaker.Listed(address):
				listed += 1
			case state.fcrdns:
				usable += 1
			default:
				failing += 1
			}
		}
	}()
	self.gauge.Set(float64(usable), "usable")
	self.gauge.Set(float64(failing), "failing")
	self.gauge.Set(float64(listed), "listed")
}

// The addresses that may send now, in settings' order.
func (self *SmtpSendingSet) Usable() []SmtpSendingAddress {
	breaker := self.breakerState()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	usable := []SmtpSendingAddress{}
	for _, sendingAddress := range self.settings.SendingAddresses {
		address := sendingAddress.Address.Unmap()
		if state := self.addressStates[address]; state != nil && state.fcrdns && !breaker.Listed(address) {
			usable = append(usable, sendingAddress)
		}
	}
	return usable
}

// A usable address for a dial to mxAddress, the one with the fewest live connections to its /24 under
// cap, and the release of its slot; false when every usable address is at cap or none is usable.
func (self *SmtpSendingSet) pick(mxAddress netip.Addr, caps *SmtpDestinationCaps, cap int64) (*SmtpSendingAddress, func(), bool) {
	usable := self.Usable()
	slices.SortStableFunc(usable, func(a SmtpSendingAddress, b SmtpSendingAddress) int {
		countA, countB := caps.Count(a.Address, mxAddress), caps.Count(b.Address, mxAddress)
		switch {
		case countA < countB:
			return -1
		case countB < countA:
			return 1
		}
		return 0
	})
	for _, sendingAddress := range usable {
		if release, ok := caps.Acquire(sendingAddress.Address, mxAddress, cap); ok {
			picked := sendingAddress
			return &picked, release, true
		}
	}
	return nil, nil, false
}

// Stops the checks and waits for them.
func (self *SmtpSendingSet) Close() {
	self.cancel()
	<-self.released
}
