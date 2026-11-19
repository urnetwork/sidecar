// §15.6's step 5, the router's wake hold (M8; R-MAIL-8, FS-36, D-PROTO-5, I-12; owner decision 88; plan-MAIL-hints #2;
// MAIL-M8-05): a session whose Find misses is held a while, its ClientHello unanswered, while its network's lapsed
// receivers are woken, rather than closed in the handshake at once.
//
//	miss    the session's first Find and open answers no listener, or sockets unavailable (§15.4's row), and its route
//	        lists receivers whose key is published (MailRoute.ReceiverSidecarIds). A route with none holds nothing: no
//	        receiver could be woken, and none serves before its key is published (§15.5)
//	bounds  at most WakeHoldCount (1,000) sessions held at once in this process and WakeHoldNetworkCount (4) for one
//	        network; past either a miss closes in the handshake at once, as M7's does
//	hint    a network's first hold hints its receivers: a forced MailHint{RECEIVER_NEEDED, host} on topic mail, its
//	        version the clock's milliseconds (plan-MAIL-hints #3), through ServiceHost.Push.HintSidecars on a goroutine
//	        of its own, within WakeHintTimeout and at most WakeHintCount in flight, past which the hint is dropped and
//	        counted. The hold never waits on it, and nothing on the path reads Postgres (I-12): the host resolves each
//	        sidecar to its client as plan-KEYS-hint-addressing settles, then §18.7's enqueue, due now since the hint is
//	        forced, and §19's push sender wake a lapsed desktop receiver; an app's wake only resyncs (owner decision
//	        197). A miss with sockets unavailable hints no one, since its receivers may well be online
//	retry   the Find and open again every WakeHoldFindInterval (2 s), each bounded by what is left of the hold
//	end     a stream opens: the session splices as any does. WakeHoldTimeout (30 s) passing, a busy, denied or spent
//	        answer, a drain or the engine's close: it closes in the handshake as M7's does, the closed-handshake memory
//	        written first. The sender is not read while held, so a byte it sends stays in its socket for the splice
//	        (FI-11), and one that left is found when its alert is written
//	off     MxEdgeSettings.WakeHold is false by default: until plan-KEYS-hint-addressing's internal route lets a host
//	        resolve a sidecar to its client with no Postgres, every hint is lost, and plan-MAIL-hints' interim keeps
//	        M7's close
//
// Nothing here logs or counts a network, a name or an address (I-13). Safe for concurrent use.

package mxedgeservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// How a hold ended: urnetwork_mxedge_wake_holds_total's results.
const (
	// A retry's stream opened, and the session spliced.
	mxWakeHoldResultTaken = "taken"
	// WakeHoldTimeout passed with no receiver.
	mxWakeHoldResultExpired = "expired"
	// A bound refused the hold, so the miss closed at once.
	mxWakeHoldResultFull = "full"
	// A retry answered busy, denied or spent, which no wait mends.
	mxWakeHoldResultRefused = "refused"
	// A drain or the engine's close ended it.
	mxWakeHoldResultEnded = "ended"
)

// How a hold's hint went: urnetwork_mxedge_wake_hints_total's results.
const (
	mxWakeHintResultSent = "sent"
	// The host's push answered an error or did not answer in time: a sidecar it could not resolve included.
	mxWakeHintResultFailed = "failed"
	// WakeHintCount hints were in flight already.
	mxWakeHintResultDropped = "dropped"
	// The host gave no Push.
	mxWakeHintResultNoPush = "no_push"
)

// The router's holds: their counts and the hints they send. Built once with the router.
type mxWakeHolds struct {
	ctx      context.Context
	push     sidecar.Push
	settings *MxEdgeSettings
	clock    sidecar.Clock
	metrics  *mxMetrics
	// closed once a drain begins, which ends every hold and lets none begin
	draining  chan struct{}
	drainOnce sync.Once
	// a token for each hint in flight
	hintSlots chan struct{}
	hintGroup sync.WaitGroup
	// sessions held now, so a test can see one begin or end
	holdCount *sidecar.MonitorValue[int]

	stateLock       sync.Mutex
	networkIdCounts map[sidecar.Id]int
}

// Holds on settings' bounds, their hints through push, which may be nil, on ctx.
func newMxWakeHolds(ctx context.Context, push sidecar.Push, settings *MxEdgeSettings, clock sidecar.Clock, metrics *mxMetrics) *mxWakeHolds {
	return &mxWakeHolds{
		ctx:             ctx,
		push:            push,
		settings:        settings,
		clock:           clock,
		metrics:         metrics,
		draining:        make(chan struct{}),
		hintSlots:       make(chan struct{}, settings.WakeHintCount),
		holdCount:       sidecar.NewMonitorValue(0),
		networkIdCounts: map[sidecar.Id]int{},
	}
}

// Takes one hold for networkId: false past either bound or once a drain has begun. first is whether it is the
// network's only hold now, whose session hints.
func (self *mxWakeHolds) acquire(networkId sidecar.Id) (first bool, ok bool) {
	select {
	case <-self.draining:
		return false, false
	default:
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := self.holdCount.Value()
	if self.settings.WakeHoldCount <= count || self.settings.WakeHoldNetworkCount <= self.networkIdCounts[networkId] {
		return false, false
	}
	self.networkIdCounts[networkId] += 1
	self.holdCount.Set(count + 1)
	return self.networkIdCounts[networkId] == 1, true
}

// Gives back a hold acquire took.
func (self *mxWakeHolds) release(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if count := self.networkIdCounts[networkId]; count <= 1 {
		delete(self.networkIdCounts, networkId)
	} else {
		self.networkIdCounts[networkId] = count - 1
	}
	self.holdCount.Update(func(count int) int { return count - 1 })
}

// Ends every hold, at a drain's start. Safe more than once.
func (self *mxWakeHolds) drain() {
	self.drainOnce.Do(func() {
		close(self.draining)
	})
}

// Waits for every hint in flight, at the engine's release.
func (self *mxWakeHolds) close() {
	self.hintGroup.Wait()
}

// Hints route's receivers that a session waits for one: see the file header's hint row. Returns at once.
func (self *mxWakeHolds) hint(route *MailRoute) {
	if self.push == nil {
		self.metrics.wakeHints.Add(1, mxWakeHintResultNoPush)
		return
	}
	select {
	case self.hintSlots <- struct{}{}:
	default:
		self.metrics.wakeHints.Add(1, mxWakeHintResultDropped)
		return
	}
	receiverIds := route.ReceiverSidecarIds[:min(len(route.ReceiverSidecarIds), self.settings.RouteReceiverCount)]
	sidecarIds := make([]connect.Id, 0, len(receiverIds))
	for _, receiverId := range receiverIds {
		sidecarIds = append(sidecarIds, connect.Id(receiverId))
	}
	body, err := proto.Marshal(&protocol.MailHint{Kind: protocol.MailHintKind_MAIL_HINT_RECEIVER_NEEDED, Host: route.Host})
	if err != nil {
		<-self.hintSlots
		self.metrics.wakeHints.Add(1, mxWakeHintResultFailed)
		return
	}
	hint := &sidecar.ClientHint{
		Topic: sidecar.PushTopicMail,
		// the writer's clock in ms, which the hint script raises past a stored version (plan-MAIL-hints #3)
		Version: uint64(max(self.clock.Now().UnixMilli(), 1)),
		Kind:    uint32(protocol.MessageType_MAIL_HINT),
		Body:    body,
		Forced:  true,
	}
	self.hintGroup.Add(1)
	go func() {
		defer self.hintGroup.Done()
		defer func() { <-self.hintSlots }()
		err := func() error {
			hintCtx, cancel := context.WithCancel(self.ctx)
			stop := self.clock.AfterFunc(self.settings.WakeHintTimeout, cancel)
			defer func() {
				stop()
				cancel()
			}()
			testHookBarrier("mxedge.wake_hint.before", "")
			defer testHookBarrier("mxedge.wake_hint.after", "")
			return self.push.HintSidecars(hintCtx, sidecarIds, hint)
		}()
		if err != nil {
			self.metrics.wakeHints.Add(1, mxWakeHintResultFailed)
			return
		}
		self.metrics.wakeHints.Add(1, mxWakeHintResultSent)
	}()
}

// One Find and open within timeout, as step 6 makes it.
type mxRouterDial func(timeout time.Duration) (MxEdgeStream, uint64, error)

// Whether err is a miss the hold waits out: no listener, or sockets unavailable.
func mxWakeHoldMiss(err error) bool {
	return errors.Is(err, sidecar.ErrSocketNoListener) || errors.Is(err, sidecar.ErrSocketUnavailable)
}

// Step 6's miss under the hold (see the file header): the stream a retry opened and its grant expiry, or the error
// the session closes on, missErr itself where nothing was held. Called with the session's lease and caps held.
func (self *MxEdgeService) holdForReceiver(route *MailRoute, missErr error, dial mxRouterDial) (MxEdgeStream, uint64, error) {
	holds := self.router.holds
	if !self.settings.WakeHold || holds == nil || len(route.ReceiverSidecarIds) == 0 || !mxWakeHoldMiss(missErr) {
		return nil, 0, missErr
	}
	first, ok := holds.acquire(route.NetworkId)
	if !ok {
		self.metrics.wakeHolds.Add(1, mxWakeHoldResultFull)
		return nil, 0, missErr
	}
	defer holds.release(route.NetworkId)
	testHookBarrier("mxedge.wake_hold.begin", "")
	if first && errors.Is(missErr, sidecar.ErrSocketNoListener) {
		holds.hint(route)
	}
	deadline := self.clock.Now().Add(self.settings.WakeHoldTimeout)
	lastErr := missErr
	for {
		left := deadline.Sub(self.clock.Now())
		if left <= 0 {
			self.metrics.wakeHolds.Add(1, mxWakeHoldResultExpired)
			return nil, 0, lastErr
		}
		select {
		case <-self.clock.After(min(self.settings.WakeHoldFindInterval, left)):
		case <-holds.draining:
			self.metrics.wakeHolds.Add(1, mxWakeHoldResultEnded)
			return nil, 0, lastErr
		case <-self.ctx.Done():
			self.metrics.wakeHolds.Add(1, mxWakeHoldResultEnded)
			return nil, 0, lastErr
		}
		left = deadline.Sub(self.clock.Now())
		if left <= 0 {
			self.metrics.wakeHolds.Add(1, mxWakeHoldResultExpired)
			return nil, 0, lastErr
		}
		stream, grantExpireTimeMillis, err := dial(min(self.settings.AcceptSetupTimeout, left))
		if err == nil {
			self.metrics.wakeHolds.Add(1, mxWakeHoldResultTaken)
			return stream, grantExpireTimeMillis, nil
		}
		if !mxWakeHoldMiss(err) {
			self.metrics.wakeHolds.Add(1, mxWakeHoldResultRefused)
			return nil, 0, err
		}
		lastErr = err
	}
}
