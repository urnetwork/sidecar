//go:build !ios_extension && !sidecar_http

// The remote-work gate (DESIGN-COMPUTE §5.4, D-ATTEST-5, D-ATTEST-8, IC-9; the second review's R2-11): the one check
// every remote operation a revocation protects calls before it sends a byte or binds URnetwork to a provider, and what
// fetches, calendar links and connected services read where they use the policy's lines. Its rules, each §5.4's:
//
//   - Current. Remote work runs only while the device holds a ticket with not_before <= now < not_after, inside its
//     batch's expiry, and a policy of the ticket's version N or later that is the newest version it has seen and is
//     not past its own not_after: a ticket never extends or revives a policy.
//   - Bounds. A ticket whose window passes 72 hours or its batch's expiry, or whose batch expires more than 14 days
//     after its sitting, is refused, whatever its signature says (AttestSettings, §5.4's numbers).
//   - The clock. Now is the device's clock, but never earlier than the not_before of the newest ticket verified as
//     current, persisted, nor, once the device has seen its held ticket lapse, earlier than that ticket's not_after,
//     so a clock set back revives no ticket. The second floor is this file's reading of §5.4's "a clock set back
//     revives no ticket", which its first floor alone would leave to a clock set back inside a lapsed ticket's window.
//   - Early tickets. A ticket whose not_before is still ahead is neither used, kept nor passed on; one more than
//     TicketEarlyAlarm early, which only a leak from the ticket host or a wrong clock explains, raises an alarm.
//   - A newer version seen. Once anything verified names N+1, no remote work runs under N, and no ticket naming less
//     is honored, until N+1 is held, which the fetcher takes from any path; the answer says why meanwhile.
//
// RemoteWork(op) is the check for remote model calls on the TEE and direct paths, enclave creates and starts, a
// member's device seating an indexer incarnation, and searches. PolicyCurrent is the policy's own not_after alone,
// which fetches, calendar links and connected services read, so a lapse of tickets stops none of them. Local inference
// calls neither (CO-9): the plan's reading of §5.4's "local inference ... run on until the policy's not_after", which
// keeps CO-9's local inference free of any server and any policy. A staging build's policy expires
// StagingPolicyLifetime after the device first took it, whatever it says, and Staging tells the apps to show the
// staging banner while one is in force (D-ATTEST-8).
//
// Every refusal is a ComputeRemoteLapsedError, errors.Is with ErrComputeRemoteLapsed, whose reason the router, the
// search tool and the enclave flow show. A refusal a fetch could answer asks the gate's Refresh first, once at a time
// and at most once per FetchMinInterval, within the caller's context.
//
// Safe for concurrent use: the gate keeps only its refresh state, under stateLock; what it judges is the store's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// One remote operation §5.4's lapse stops.
type ComputeRemoteOperation string

const (
	// A remote model call on the TEE path (§6.6).
	ComputeRemoteModelCallTee ComputeRemoteOperation = "model_call_tee"
	// A remote model call on the direct path, to a provider without a TEE (§6.6).
	ComputeRemoteModelCallDirect ComputeRemoteOperation = "model_call_direct"
	// An enclave's create (§11.7).
	ComputeRemoteEnclaveCreate ComputeRemoteOperation = "enclave_create"
	// An enclave's start (§11.11).
	ComputeRemoteEnclaveStart ComputeRemoteOperation = "enclave_start"
	// A member's device seating an indexer incarnation (§11.10).
	ComputeRemoteIndexerSeat ComputeRemoteOperation = "indexer_seat"
	// A web search (§21).
	ComputeRemoteSearch ComputeRemoteOperation = "search"
)

// Every operation RemoteWork answers. Local inference, fetches, calendar links and connected services are none of
// them.
var ComputeRemoteOperations = []ComputeRemoteOperation{
	ComputeRemoteModelCallTee,
	ComputeRemoteModelCallDirect,
	ComputeRemoteEnclaveCreate,
	ComputeRemoteEnclaveStart,
	ComputeRemoteIndexerSeat,
	ComputeRemoteSearch,
}

// Why remote work may not run.
type ComputeRemoteLapseReason string

const (
	// No verified policy: none in the release and none fetched.
	ComputeRemoteLapsePolicyUnavailable ComputeRemoteLapseReason = "policy_unavailable"
	// Something verified named a newer version than the newest held.
	ComputeRemoteLapsePolicyNewerSeen ComputeRemoteLapseReason = "policy_newer_seen"
	// The newest policy is past its not_after, or, in a staging build, its staging lifetime.
	ComputeRemoteLapsePolicyExpired ComputeRemoteLapseReason = "policy_expired"
	// No ticket held.
	ComputeRemoteLapseTicketUnavailable ComputeRemoteLapseReason = "ticket_unavailable"
	// The ticket held is past its window or its batch's expiry.
	ComputeRemoteLapseTicketExpired ComputeRemoteLapseReason = "ticket_expired"
	// An operation the gate does not know, which it never allows.
	ComputeRemoteLapseOperationUnknown ComputeRemoteLapseReason = "operation_unknown"
)

// What every refusal of the gate wraps.
var ErrComputeRemoteLapsed = errors.New("remote compute work lapsed")

// What PolicyCurrent answers with no policy current.
var ErrComputePolicyNotCurrent = errors.New("no compute policy current")

// An offered ticket whose not_before is still ahead: refused, not kept and not passed on.
var ErrComputePolicyTicketEarly = errors.New("freshness ticket not yet started")

// An offered ticket already past its window or its batch's expiry: refused and not kept.
var ErrComputePolicyTicketLapsed = errors.New("freshness ticket already lapsed")

// The gate's refusal of an operation, with what it saw.
type ComputeRemoteLapsedError struct {
	Operation ComputeRemoteOperation
	Reason    ComputeRemoteLapseReason
	// The newest policy's version, 0 with none.
	PolicyVersion uint64
	// The highest version seen.
	HighestSeen uint64
	// When the newest policy stops, or stopped, being current; zero with none.
	PolicyNotAfter time.Time
	// When the held ticket stops, or stopped, being current; zero with none.
	TicketNotAfter time.Time
}

// What the router, the search tool and the enclave flow show.
func (self *ComputeRemoteLapsedError) Error() string {
	reason := ""
	switch self.Reason {
	case ComputeRemoteLapsePolicyUnavailable:
		reason = "no signed compute policy is held yet; fetching it"
	case ComputeRemoteLapsePolicyNewerSeen:
		reason = fmt.Sprintf("compute policy version %d is named and not yet held (holding %d); fetching it", self.HighestSeen, self.PolicyVersion)
	case ComputeRemoteLapsePolicyExpired:
		reason = fmt.Sprintf("the compute policy (version %d) expired at %s; fetching a newer one", self.PolicyVersion, self.PolicyNotAfter.UTC().Format(time.RFC3339))
	case ComputeRemoteLapseTicketUnavailable:
		reason = "no freshness ticket is held for the compute policy; fetching one"
	case ComputeRemoteLapseTicketExpired:
		reason = fmt.Sprintf("the compute policy's freshness ticket lapsed at %s; fetching a newer one", self.TicketNotAfter.UTC().Format(time.RFC3339))
	case ComputeRemoteLapseOperationUnknown:
		reason = "the operation is not one the gate knows"
	default:
		reason = string(self.Reason)
	}
	return fmt.Sprintf("%s: %s: %s", ErrComputeRemoteLapsed, self.Operation, reason)
}

// errors.Is with ErrComputeRemoteLapsed.
func (self *ComputeRemoteLapsedError) Unwrap() error {
	return ErrComputeRemoteLapsed
}

// Whether a fetch could answer the reason.
func (self ComputeRemoteLapseReason) fetchable() bool {
	return self != ComputeRemoteLapseOperationUnknown
}

// A ticket offered more than TicketEarlyAlarm before its not_before: a leak from the ticket host, or this device's
// clock wrong.
type ComputePolicyAlarm struct {
	// The ticket's batch and window.
	BatchId   Id
	NotBefore time.Time
	// The gate's time when it was offered.
	Now time.Time
}

// What NewComputePolicyGate builds on.
type ComputePolicyGateArgs struct {
	// Required: the policy, the highest version seen, the held ticket and the clock's floors.
	Store *ComputePolicyStore
	// Required: verifies offered tickets, as the store's verifies policies.
	Verifier *ComputePolicyVerifier
	// Required.
	Settings *AttestSettings
	// Nil logs nothing.
	Log Logger
	// Called, on the offering goroutine, for each ticket more than TicketEarlyAlarm early; nil only logs.
	Alarm func(alarm *ComputePolicyAlarm)
	// Asked when remote work lapsed for a reason a fetch could answer, once at a time and at most once per
	// FetchMinInterval; the component gives the fetcher's Fetch. Nil asks nothing.
	Refresh func(ctx context.Context) error
}

// §5.4's gate over a store.
type ComputePolicyGate struct {
	store    *ComputePolicyStore
	verifier *ComputePolicyVerifier
	settings *AttestSettings
	log      Logger
	alarm    func(alarm *ComputePolicyAlarm)
	refresh  func(ctx context.Context) error
	// One refresh at a time: a slot taken within the caller's context.
	refreshSlot chan struct{}
	// Closed at the first remote work asked, which starts the fetcher's own schedule.
	wanted     chan struct{}
	wantedOnce sync.Once

	stateLock sync.Mutex
	// When the last refresh started, on the device's clock.
	refreshedAt time.Time
}

// A gate over args.
func NewComputePolicyGate(args *ComputePolicyGateArgs) (*ComputePolicyGate, error) {
	if args == nil || args.Store == nil || args.Verifier == nil || args.Settings == nil {
		return nil, errors.New("compute policy gate: a store, a verifier and settings")
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &ComputePolicyGate{
		store:       args.Store,
		verifier:    args.Verifier,
		settings:    args.Settings,
		log:         log,
		alarm:       args.Alarm,
		refresh:     args.Refresh,
		refreshSlot: make(chan struct{}, 1),
		wanted:      make(chan struct{}),
	}, nil
}

// Nil where operation may run now; else a *ComputeRemoteLapsedError saying why. A refusal a fetch could answer asks
// Refresh once first, within ctx, and judges again.
func (self *ComputePolicyGate) RemoteWork(ctx context.Context, operation ComputeRemoteOperation) error {
	if !slices.Contains(ComputeRemoteOperations, operation) {
		return &ComputeRemoteLapsedError{Operation: operation, Reason: ComputeRemoteLapseOperationUnknown}
	}
	self.wantedOnce.Do(func() {
		close(self.wanted)
	})
	lapsed := self.check(operation)
	if lapsed == nil || !lapsed.Reason.fetchable() || self.refresh == nil {
		return computeRemoteLapseError(lapsed)
	}
	if !self.refreshOnce(ctx) {
		return lapsed
	}
	return computeRemoteLapseError(self.check(operation))
}

// The lapse as an error, nil for none.
func computeRemoteLapseError(lapsed *ComputeRemoteLapsedError) error {
	if lapsed == nil {
		return nil
	}
	return lapsed
}

// The newest policy, where its own not_after (or a staging build's lifetime) has not passed; else an error wrapping
// ErrComputePolicyNotCurrent. Tickets do not enter into it: a lapse of tickets stops remote work, not fetches,
// calendar links or connected services.
func (self *ComputePolicyGate) PolicyCurrent() (*ComputePolicy, error) {
	now, state := self.store.judged()
	policy, acceptedMs := state.newest, state.acceptedMs
	if policy == nil {
		return nil, fmt.Errorf("%w: none held", ErrComputePolicyNotCurrent)
	}
	if notAfter := self.policyNotAfter(policy, acceptedMs); !now.Before(notAfter) {
		return nil, fmt.Errorf("%w: version %d expired at %s", ErrComputePolicyNotCurrent, policy.Version, notAfter.UTC().Format(time.RFC3339))
	}
	return policy, nil
}

// Whether the apps show the staging banner: a staging or CI build holding a staging policy still in force.
func (self *ComputePolicyGate) Staging() bool {
	if !self.verifier.Staging() {
		return false
	}
	_, err := self.PolicyCurrent()
	return err == nil
}

// The gate's time: the device's clock, never earlier than its floors.
func (self *ComputePolicyGate) Now() time.Time {
	return self.store.now()
}

// The held ticket's file while it is current, to pass on to another device of the network; nil with none, so a
// ticket not yet started, which is never kept, is never passed on either.
func (self *ComputePolicyGate) Ticket() []byte {
	ticket := self.store.heldTicket()
	if ticket == nil || !ticket.Current(self.store.now(), self.settings) {
		return nil
	}
	return ticket.File()
}

// A channel closed once remote work has been asked for, which the fetcher's schedule waits on, so a device that
// never uses remote compute fetches nothing.
func (self *ComputePolicyGate) Wanted() <-chan struct{} {
	return self.wanted
}

// Verifies a ticket file from any source and keeps it where it is current and newer than the one held. The
// signature, not the source, is what is trusted (§5.4), so a ticket from ur.io, a mirror or another device of the
// network is judged the same. Every verified ticket names a version, noted as seen whether it is kept or not, except
// one not yet started, which is neither used, kept nor passed on. Returns the ticket held after the offer.
func (self *ComputePolicyGate) OfferTicket(file []byte) (*ComputePolicyTicket, error) {
	now := self.store.now()
	ticket, err := self.verifier.VerifyTicket(file, now)
	if err != nil {
		return nil, err
	}
	if now.Before(ticket.NotBefore) {
		early := ticket.NotBefore.Sub(now)
		if self.settings.TicketEarlyAlarm < early {
			alarm := &ComputePolicyAlarm{BatchId: ticket.Batch.Id, NotBefore: ticket.NotBefore, Now: now}
			self.log.Warningf("[attest]a freshness ticket arrived %s before its start: a leak from the ticket host or a wrong clock", early)
			if self.alarm != nil {
				self.alarm(alarm)
			}
		}
		return nil, fmt.Errorf("%w: it starts in %s", ErrComputePolicyTicketEarly, early)
	}
	if err := self.store.noteVersionSeen(ticket.PolicyVersion); err != nil {
		self.log.Warningf("[attest]the version a ticket names is held in memory alone: %s", err)
	}
	if !ticket.Current(now, self.settings) {
		return nil, fmt.Errorf("%w: it ended at %s", ErrComputePolicyTicketLapsed, ticket.NotAfter.UTC().Format(time.RFC3339))
	}
	held, err := self.store.keepTicket(ticket)
	if err != nil {
		return nil, err
	}
	return held, nil
}

// The lapse operation meets now, or nil where it may run.
func (self *ComputePolicyGate) check(operation ComputeRemoteOperation) *ComputeRemoteLapsedError {
	now, state := self.store.judged()
	policy, acceptedMs, ticket := state.newest, state.acceptedMs, state.ticket
	lapsed := &ComputeRemoteLapsedError{Operation: operation, HighestSeen: state.highestSeen}
	if ticket != nil {
		lapsed.TicketNotAfter = computePolicyMinTime(ticket.NotAfter, ticket.Batch.Expires)
	}
	if policy == nil {
		lapsed.Reason = ComputeRemoteLapsePolicyUnavailable
		return lapsed
	}
	lapsed.PolicyVersion = policy.Version
	lapsed.PolicyNotAfter = self.policyNotAfter(policy, acceptedMs)
	switch {
	case policy.Version < lapsed.HighestSeen:
		lapsed.Reason = ComputeRemoteLapsePolicyNewerSeen
	case !now.Before(lapsed.PolicyNotAfter):
		lapsed.Reason = ComputeRemoteLapsePolicyExpired
	case ticket == nil:
		lapsed.Reason = ComputeRemoteLapseTicketUnavailable
	case policy.Version < ticket.PolicyVersion:
		lapsed.Reason = ComputeRemoteLapsePolicyNewerSeen
	case !ticket.Current(now, self.settings):
		lapsed.Reason = ComputeRemoteLapseTicketExpired
		// seen lapsing, it never comes back by a clock set back
		if !now.Before(lapsed.TicketNotAfter) {
			if err := self.store.raiseClockFloor(lapsed.TicketNotAfter); err != nil {
				self.log.Warningf("[attest]the clock's floor is held in memory alone: %s", err)
			}
		}
	default:
		return nil
	}
	return lapsed
}

// The instant policy stops being current here: its not_after, and in a staging build no later than
// StagingPolicyLifetime after the device first took it.
func (self *ComputePolicyGate) policyNotAfter(policy *ComputePolicy, acceptedMs int64) time.Time {
	notAfter := policy.NotAfter()
	if self.verifier.Staging() {
		notAfter = computePolicyMinTime(notAfter, time.UnixMilli(acceptedMs).UTC().Add(self.settings.StagingPolicyLifetime))
	}
	return notAfter
}

// Runs Refresh once where none ran within FetchMinInterval, one at a time, waiting no longer than ctx. Whether it ran
// one, or waited on another's to its end.
func (self *ComputePolicyGate) refreshOnce(ctx context.Context) bool {
	select {
	case self.refreshSlot <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() {
		<-self.refreshSlot
	}()
	now := self.store.clock.Now()
	due := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.refreshedAt.IsZero() && now.Sub(self.refreshedAt) < self.settings.FetchMinInterval && !now.Before(self.refreshedAt) {
			return false
		}
		self.refreshedAt = now
		return true
	}()
	if !due {
		return true
	}
	if err := self.refresh(ctx); err != nil {
		self.log.Warningf("[attest]fetching the compute policy: %s", strings.TrimSpace(err.Error()))
	}
	return true
}
