//go:build !sidecar_http

// §15.5's dns and work rows for one message (D-MAIL-14, FS-121; MAIL-M7-07): at most 64 queries beyond stub hits,
// 8 in flight, each answered within 5 s or temperror, and 30 s for the whole check, counted from when a check slot
// takes the message (MAIL-M7-09), so a sender's many signatures or slow selectors cost a receiver a bounded amount.
// A query waits for a slot in priority order, DMARC's record and the aligned DKIM keys first, then SPF, the PTR, the
// other keys and ARC's, arrival order breaking ties, so under contention what decides DMARC is asked first.
//
// What the budget refuses is a bound, never a DNS answer: ErrMailAuthQueriesSpent past 64, ErrMailAuthDeadline once
// the check's time is up, both ErrMailAuthBound, so a caller records the check as incomplete and sets limits' reason
// (bit 1 a count, bit 2 the deadline) rather than calling it temperror. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Which part of a message's check a query serves, in the order §15.5's dns row gives them, which is the order
// they wait in.
type MailAuthPriority int

const (
	// DMARC's record and the DKIM keys whose d= aligns with From under DMARC's relaxed rule.
	MailAuthPriorityDmarc MailAuthPriority = iota
	MailAuthPrioritySpf
	// The forward-confirmed PTR of sender_ip, and the SNI host's TLSA.
	MailAuthPriorityPtr
	// The other selected DKIM keys.
	MailAuthPriorityKeys
	MailAuthPriorityArc
)

var (
	// A bound of §15.5's cut the work: the check is incomplete, never temperror.
	ErrMailAuthBound = errors.New("mail auth: a bound cut the check")
	// The message's 64 queries are spent.
	ErrMailAuthQueriesSpent = fmt.Errorf("%w: the message's queries are spent", ErrMailAuthBound)
	// The message's 30 s are up, or its check ended.
	ErrMailAuthDeadline = fmt.Errorf("%w: the message's time is up", ErrMailAuthBound)
)

// §15.5's per-message bounds, the receiver's stub and the checks' own bounds, which a receiver's checks are tuned by.
type MailAuthSettings struct {
	// Queries a message may send beyond stub hits (§15.5's dns row).
	QueryMaxCount int
	// Queries in flight at once for one message.
	InFlightMaxCount int
	// One query's time, past which it is temperror.
	QueryTimeout time.Duration
	// The whole check's time, from when a slot takes the message after its last byte; whatever is unfinished then
	// is incomplete (§15.5's work row).
	CheckTimeout time.Duration
	// The answers a receiver's stub keeps, least recently used out (g0-recheck-0-receiver-evidence#1).
	StubEntryMaxCount int
	// The longest a stub keeps an answer, whatever its TTL says.
	StubMaxTtl time.Duration
	// The longest it keeps an NXDOMAIN or NODATA, whatever its SOA says; without an SOA it keeps none.
	StubNegativeMaxTtl time.Duration
	// The header section's bytes the checks read; fields past it are only counted (§15.5's headers row).
	HeaderMaxByteCount int
	// The DKIM-Signature fields counted; past it a field is not even parsed (§15.5's headers row).
	DkimFieldMaxCount int
	// The signatures selected and verified (§15.5's dkim row).
	DkimSelectMaxCount int
	// The largest RSA key a signature is verified under (§15.5's dkim row, RFC 8301 §3.2).
	DkimRsaMaxBitCount int
	// The PTR names of sender_ip looked up forward, as RFC 7208 §4.6.4 bounds a ptr term.
	PtrNameMaxCount int
}

// The one default: §15.5's numbers.
func DefaultMailAuthSettings() *MailAuthSettings {
	return &MailAuthSettings{
		QueryMaxCount:      64,
		InFlightMaxCount:   8,
		QueryTimeout:       5 * time.Second,
		CheckTimeout:       30 * time.Second,
		StubEntryMaxCount:  4096,
		StubMaxTtl:         3600 * time.Second,
		StubNegativeMaxTtl: 300 * time.Second,
		HeaderMaxByteCount: 256 * 1024,
		DkimFieldMaxCount:  64,
		DkimSelectMaxCount: 8,
		DkimRsaMaxBitCount: 8192,
		PtrNameMaxCount:    10,
	}
}

// A query waiting for a slot.
type mailAuthWaiter struct {
	priority MailAuthPriority
	sequence uint64
	// One value: nil once admitted, else why not.
	ready chan error
}

// One message's queries and time. See the file header.
type MailAuthBudget struct {
	settings *MailAuthSettings
	// Ends when the check's time is up or Close ends it: every query the check made runs under it.
	ctx          context.Context
	cancel       context.CancelFunc
	stopDeadline func() bool

	stateLock     sync.Mutex
	sentCount     int
	inFlightCount int
	refusedCount  int
	deadline      bool
	closed        bool
	waiters       []*mailAuthWaiter
	nextSequence  uint64
}

// A message's budget, whose time starts now on clock, real time when nil.
func NewMailAuthBudget(clock Clock, settings *MailAuthSettings) *MailAuthBudget {
	ctx, cancel := context.WithCancel(context.Background())
	budget := &MailAuthBudget{settings: settings, ctx: ctx, cancel: cancel}
	budget.stopDeadline = clockOrReal(clock).AfterFunc(settings.CheckTimeout, budget.expire)
	return budget
}

// What every query of the check runs under: it ends when the check's time is up or Close ends it.
func (self *MailAuthBudget) Context() context.Context {
	return self.ctx
}

// The check's time is up: every waiting query is refused, and every query in flight ends.
func (self *MailAuthBudget) expire() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		self.deadline = true
		self.refuseWaitersWithLock(ErrMailAuthDeadline)
	}()
	self.cancel()
}

// Ends the check: its timer stops, and anything still asked is refused as past its time, though no deadline is
// recorded.
func (self *MailAuthBudget) Close() {
	self.stopDeadline()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		self.refuseWaitersWithLock(ErrMailAuthDeadline)
	}()
	self.cancel()
}

func (self *MailAuthBudget) refuseWaitersWithLock(err error) {
	for _, waiter := range self.waiters {
		waiter.ready <- err
	}
	self.waiters = nil
}

// A query's place in the budget, taken in the caller's order: admitted at once, refused at once, or waiting.
type mailAuthTicket struct {
	budget *MailAuthBudget
	// Set while it waits for a slot.
	waiter *mailAuthWaiter
	// Set when it was refused at once.
	err error
}

// Takes a place for one query at priority now, without waiting, so queries a check starts in priority order take
// the budget in that order even when slots are free: refused once 64 have been sent or the check's time is up,
// admitted while a slot is free and nothing waits, else queued.
func (self *MailAuthBudget) reserve(priority MailAuthPriority) *mailAuthTicket {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case self.deadline || self.closed:
		return &mailAuthTicket{budget: self, err: ErrMailAuthDeadline}
	case self.settings.QueryMaxCount <= self.sentCount:
		self.refusedCount += 1
		return &mailAuthTicket{budget: self, err: ErrMailAuthQueriesSpent}
	case self.inFlightCount < self.settings.InFlightMaxCount && len(self.waiters) == 0:
		self.sentCount += 1
		self.inFlightCount += 1
		return &mailAuthTicket{budget: self}
	}
	waiter := &mailAuthWaiter{priority: priority, sequence: self.nextSequence, ready: make(chan error, 1)}
	self.nextSequence += 1
	self.waiters = append(self.waiters, waiter)
	return &mailAuthTicket{budget: self, waiter: waiter}
}

// The ticket's slot once it has one, or a bound's error: ErrMailAuthQueriesSpent once 64 have been sent, and
// ErrMailAuthDeadline once the check's time is up. release frees the slot when the query ends, once.
func (self *mailAuthTicket) wait(ctx context.Context) (release func(), err error) {
	if self.err != nil {
		return nil, self.err
	}
	budget := self.budget
	release = sync.OnceFunc(func() {
		budget.stateLock.Lock()
		defer budget.stateLock.Unlock()
		budget.inFlightCount -= 1
		budget.admitWithLock()
	})
	if self.waiter == nil {
		return release, nil
	}
	select {
	case err := <-self.waiter.ready:
		if err != nil {
			return nil, err
		}
		return release, nil
	case <-ctx.Done():
		admitted := func() bool {
			budget.stateLock.Lock()
			defer budget.stateLock.Unlock()
			if index := slices.Index(budget.waiters, self.waiter); 0 <= index {
				budget.waiters = slices.Delete(budget.waiters, index, index+1)
				return false
			}
			return true
		}()
		if admitted {
			// decided while it gave up: a slot goes back, and a refusal is the budget's answer, not the caller's
			if err := <-self.waiter.ready; err != nil {
				return nil, err
			}
			release()
		}
		return nil, ctx.Err()
	}
}

// A slot for one query at priority: reserve, then wait.
func (self *MailAuthBudget) acquire(ctx context.Context, priority MailAuthPriority) (release func(), err error) {
	return self.reserve(priority).wait(ctx)
}

// Fills free slots with the waiting queries in priority order, then arrival order, refusing each past the count.
func (self *MailAuthBudget) admitWithLock() {
	for self.inFlightCount < self.settings.InFlightMaxCount && 0 < len(self.waiters) {
		best := 0
		for index, waiter := range self.waiters {
			if waiter.priority < self.waiters[best].priority ||
				(waiter.priority == self.waiters[best].priority && waiter.sequence < self.waiters[best].sequence) {
				best = index
			}
		}
		waiter := self.waiters[best]
		self.waiters = slices.Delete(self.waiters, best, best+1)
		if self.settings.QueryMaxCount <= self.sentCount {
			self.refusedCount += 1
			waiter.ready <- ErrMailAuthQueriesSpent
			continue
		}
		self.sentCount += 1
		self.inFlightCount += 1
		waiter.ready <- nil
	}
}

// What the check spent: the queries sent, stub hits excluded (AuthLimits.dns_queries); how many the count refused;
// and whether its time ran out.
func (self *MailAuthBudget) Spent() (sentCount int, refusedCount int, deadline bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sentCount, self.refusedCount, self.deadline
}
