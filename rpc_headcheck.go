//go:build !sidecar_http

// HeadCheck's transport (§6.4, §6.5; D-PROTO-14, D-PROTO-17, D-TRUST-10): the HEAD_CHECK exchange that
// carries each side's pins to the other, run on the reconcile engine (rpc_headcheck_state.go) through
// the network's HeadStopState (rpc_headcheck_stop.go), which holds the sources and persists what was
// found. AttachHeadCheck joins one to a client generation's dispatcher: it registers the HEAD_CHECK and
// HEAD_CHECK_PROOF_REQUEST handlers, starts the rounds (rpc_headcheck_rounds.go) and hooks the first
// exchange per peer per hour.
//
// An exchange: the initiator, its Hello standing, sends HeadCheck; the responder reconciles it, answers
// HeadCheckResult with its own pins, and then runs what reconcile asked for; the initiator reconciles the
// result and runs what that asked for. Each side then asks witnessDecision whether the exchange counts,
// after its acts have run, so a witness names only the pin it compared, never one it did not reconcile.
// The acts are I/O, run here with no lock held: a fetch from api (FetchAuth), a proof from the claimant
// (rpc_headcheck_proof.go), a forward read of gen/ or a ref, a veto to the auth source. A fetch api has
// not served by HeadCheckFetchTimeout (two tries) moves to a proof request in the background, since the
// exchange that found it has long been answered.
//
// Each message carries network_id, this side's auth pin, at most HeadCheckMaxListCount each of groups,
// gens and refs, rotating per peer so a fork between two communicating peers shows within
// ceil(shared items / 16) exchanges, at most HeadCheckMaxVetoCount vetoes, and the relay rows' proven
// and unverified (at most HeadCheckMaxUnverifiedSendCount): about 5.2 KB at its caps, which Call chunks
// into two envelopes. Any admitted sidecar answers, agents and read_only devices included; the sources
// answer only what both sides hold, so agents and wrap-reading member devices send no group heads.
//
// testHookBarrier runs at rpc.head_check.before and .after around each exchange's call, and at
// rpc.head_proof_verified, each keyed by the peer's sidecar_id.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A HeadCheckEnv missing what the transport cannot run without.
	errHeadCheckEnv = errors.New("invalid head check env")
	// A dispatcher that already runs HeadCheck.
	errHeadCheckAttached = errors.New("head check already attached")
	// The peer's sidecar_id could not be resolved to a client whose binding its admission holds.
	errHeadCheckPeerUnresolved = errors.New("head check: peer not resolved")
)

// What HeadCheck's transport runs on for one network. Every field but Random is required.
type HeadCheckEnv struct {
	// The network's stops and head check state, which hold its HeadCheckSources (PROTO-M2-04). One per
	// network, outliving each client generation's dispatcher.
	Stop *HeadStopState
	// The admitted sidecars a round picks from, as this device's state holds them (§6.4's round row).
	Candidates func() []HeadCheckCandidate
	// A sidecar's identity as api holds it: SidecarApi.GetIdentity with no page. Its binding counts only
	// once it verifies and its identity key is the admission's.
	Identity func(ctx context.Context, sidecarId Id) (*SidecarIdentityRecord, error)
	// Draws a round's picks, uniform in [0, n). Nil draws from crypto/rand; a test passes a seeded one.
	Random func(n int) int
}

// Refuses an env missing a field.
func (self *HeadCheckEnv) validate() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: none", errHeadCheckEnv)
	case self.Stop == nil:
		return fmt.Errorf("%w: no stop state", errHeadCheckEnv)
	case self.Candidates == nil:
		return fmt.Errorf("%w: no candidates", errHeadCheckEnv)
	case self.Identity == nil:
		return fmt.Errorf("%w: no identity lookup", errHeadCheckEnv)
	}
	return nil
}

// One client generation's HeadCheck: its dispatcher, the network's stop state, and what it keeps per
// peer. Safe for concurrent use.
type headCheckTransport struct {
	ctx         context.Context
	cancel      context.CancelFunc
	subprotocol *Subprotocol
	env         *HeadCheckEnv
	stop        *HeadStopState
	sources     *HeadCheckSources
	settings    *SidecarProtocolSettings
	clock       Clock
	random      func(n int) int

	// every goroutine the transport starts: the run loop, exchanges, and acts that outlive the exchange
	// that found them
	workers sync.WaitGroup
	// asks the run loop for a round now
	roundRequests chan struct{}
	// exchanges finished, either way, an initiator's once its witness is asked and a responder's once
	// its acts have run: what a test waits on, with no sleep
	exchangeCount *MonitorValue[uint64]
	// rounds finished
	roundCount *MonitorValue[uint64]

	stateLock sync.Mutex
	// where each peer's lists rotate from
	peerRotations map[Id]*headCheckRotation
	// the last exchange with each peer, either way, which the first-exchange hook reads
	peerExchangeTimes map[Id]time.Time
	// peers an exchange runs with now, so a hook does not start a second
	peerExchangesRunning map[Id]bool
}

// Where one peer's lists start next.
type headCheckRotation struct {
	groups int
	gens   int
	refs   int
}

// Joins HeadCheck to this dispatcher until the answer is called: the HEAD_CHECK and
// HEAD_CHECK_PROOF_REQUEST handlers, the rounds, and the first-exchange hook. The detach unregisters
// them, ends the run loop and joins every exchange and act still running. One at a time per
// dispatcher.
func (self *Subprotocol) AttachHeadCheck(env *HeadCheckEnv) (detach func(), err error) {
	if err := env.validate(); err != nil {
		return nil, err
	}
	random := env.Random
	if random == nil {
		random = cryptoRandomInt
	}
	ctx, cancel := context.WithCancel(self.ctx)
	transport := &headCheckTransport{
		ctx:                  ctx,
		cancel:               cancel,
		subprotocol:          self,
		env:                  env,
		stop:                 env.Stop,
		sources:              env.Stop.env.Sources,
		settings:             self.settings,
		clock:                self.clock,
		random:               random,
		roundRequests:        make(chan struct{}, 1),
		exchangeCount:        NewMonitorValue[uint64](0),
		roundCount:           NewMonitorValue[uint64](0),
		peerRotations:        map[Id]*headCheckRotation{},
		peerExchangeTimes:    map[Id]time.Time{},
		peerExchangesRunning: map[Id]bool{},
	}
	if !self.headCheck.CompareAndSwap(nil, transport) {
		cancel()
		return nil, errHeadCheckAttached
	}
	removeHeadCheck, err := self.Handle(protocol.MessageType_HEAD_CHECK, transport.handleHeadCheck, nil)
	if err != nil {
		self.headCheck.CompareAndSwap(transport, nil)
		cancel()
		return nil, err
	}
	removeProof, err := self.Handle(protocol.MessageType_HEAD_CHECK_PROOF_REQUEST, transport.handleProofRequest, nil)
	if err != nil {
		removeHeadCheck()
		self.headCheck.CompareAndSwap(transport, nil)
		cancel()
		return nil, err
	}
	transport.workers.Add(1)
	go transport.run()
	var once sync.Once
	return func() {
		once.Do(func() {
			removeHeadCheck()
			removeProof()
			self.headCheck.CompareAndSwap(transport, nil)
			cancel()
			transport.workers.Wait()
		})
	}, nil
}

// Starts work the transport joins at its detach, unless it is ending.
func (self *headCheckTransport) goWorker(work func()) bool {
	if self.ctx.Err() != nil {
		return false
	}
	self.workers.Add(1)
	go func() {
		defer self.workers.Done()
		work()
	}()
	return true
}

// The next window of items, rotating from where the peer's last one ended: at most
// HeadCheckMaxListCount, in the source's stable order, wrapping at its end.
func headCheckRotate[T any](items []T, offset *int) []T {
	if len(items) <= HeadCheckMaxListCount {
		*offset = 0
		return items
	}
	start := *offset % len(items)
	window := make([]T, 0, HeadCheckMaxListCount)
	for i := 0; i < HeadCheckMaxListCount; i += 1 {
		window = append(window, items[(start+i)%len(items)])
	}
	*offset = (start + HeadCheckMaxListCount) % len(items)
	return window
}

// This side's HeadCheck to a peer: its pin, the next rotation of each list, its vetoes and the relay
// rows. errHeadCheckNoState when this device holds no verified state, since there is nothing to send.
func (self *headCheckTransport) message(peerSidecarId Id) (*protocol.HeadCheck, error) {
	pin := self.sources.Auth.Pin()
	if !headCheckPinValid(pin) {
		return nil, errHeadCheckNoState
	}
	groups := self.sources.Groups.GroupHeads(peerSidecarId)
	gens := self.sources.Gens.GenHeads(peerSidecarId)
	refs := self.sources.Refs.RefHeads(peerSidecarId)
	vetoes := self.sources.Auth.Vetoes()
	if HeadCheckMaxVetoCount < len(vetoes) {
		vetoes = vetoes[:HeadCheckMaxVetoCount]
	}
	proven, unverified := self.stop.relayed(peerSidecarId)
	message := &protocol.HeadCheck{
		NetworkId:  self.stop.env.NetworkId.Bytes(),
		Auth:       headCheckPinCopy(pin),
		Vetoes:     vetoes,
		Proven:     proven,
		Unverified: unverified,
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		rotation := self.peerRotations[peerSidecarId]
		if rotation == nil {
			rotation = &headCheckRotation{}
			self.peerRotations[peerSidecarId] = rotation
		}
		message.Groups = headCheckRotate(groups, &rotation.groups)
		message.Gens = headCheckRotate(gens, &rotation.gens)
		message.Refs = headCheckRotate(refs, &rotation.refs)
	}()
	return message, nil
}

// The same fields as a HeadCheckResult (§6.5: the same fields and numbers).
func headCheckResultOf(message *protocol.HeadCheck) *protocol.HeadCheckResult {
	return &protocol.HeadCheckResult{
		NetworkId:  message.NetworkId,
		Auth:       message.Auth,
		Groups:     message.Groups,
		Gens:       message.Gens,
		Refs:       message.Refs,
		Vetoes:     message.Vetoes,
		Proven:     message.Proven,
		Unverified: message.Unverified,
	}
}

// Records an exchange with the peer, either way, now.
func (self *headCheckTransport) noteExchanged(peerSidecarId Id) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.peerExchangeTimes[peerSidecarId] = now
}

// The responder's half: reconciles the peer's HeadCheck and answers HeadCheckResult with this side's
// pins, then runs the acts reconcile asked for and asks whether the exchange counts, off the handler,
// since a fetch may wait out HeadCheckFetchTimeout. A message reconcile refuses changes nothing and is
// answered with its code.
func (self *headCheckTransport) handleHeadCheck(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
	if request.Peer == nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
	}
	peerSidecarId := request.Peer.SidecarId
	message := &protocol.HeadCheck{}
	if err := proto.Unmarshal(request.Body, message); err != nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT}
	}
	step, err := self.stop.reconcile(peerSidecarId, message)
	if err != nil {
		return nil, headCheckRefusal(err)
	}
	self.noteExchanged(peerSidecarId)
	reply, err := self.message(peerSidecarId)
	if err != nil {
		return nil, headCheckRefusal(err)
	}
	body, err := proto.Marshal(headCheckResultOf(reply))
	if err != nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
	}
	self.goWorker(func() {
		defer self.exchangeCount.Update(func(count uint64) uint64 {
			return count + 1
		})
		forked := step.forked
		if self.runActs(self.ctx, step.acts) {
			forked = true
		}
		self.stop.witness(peerSidecarId, message, forked)
	})
	return body, nil
}

// The code a refused HeadCheck answers with.
func headCheckRefusal(err error) error {
	switch {
	case errors.Is(err, errHeadCheckMalformed):
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT}
	case errors.Is(err, errHeadCheckPeer):
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_PERMISSION_DENIED}
	}
	return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
}

// The initiator's half, with a peer whose Hello this side runs first: HeadCheck out, its result
// reconciled, the acts run, and the witness asked. Answers the witness the exchange made, nil for none.
// A scheduled exchange (exclusive) is skipped when another with the peer is running.
func (self *headCheckTransport) exchange(ctx context.Context, clientId connect.Id, exclusive bool) (*headCheckWitness, error) {
	defer self.exchangeCount.Update(func(count uint64) uint64 {
		return count + 1
	})
	if err := self.subprotocol.ensurePeerVerified(ctx, clientId); err != nil {
		return nil, err
	}
	peer, ok := self.subprotocol.PeerIdentity(Id(clientId))
	if !ok {
		return nil, errHeadCheckPeerUnresolved
	}
	peerSidecarId := peer.SidecarId
	if exclusive {
		if !self.claimExchange(peerSidecarId) {
			return nil, nil
		}
		defer self.releaseExchange(peerSidecarId)
	}
	message, err := self.message(peerSidecarId)
	if err != nil {
		return nil, err
	}
	body, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	testHookBarrier("rpc.head_check.before", peerSidecarId.String())
	resultBody, err := self.subprotocol.Call(ctx, Id(clientId), protocol.MessageType_HEAD_CHECK, body, &CallOptions{Timeout: self.settings.HeadCheckTimeout})
	testHookBarrier("rpc.head_check.after", peerSidecarId.String())
	if err != nil {
		return nil, err
	}
	result := &protocol.HeadCheckResult{}
	if err := proto.Unmarshal(resultBody, result); err != nil {
		return nil, fmt.Errorf("%w: %w", errHeadCheckMalformed, err)
	}
	self.noteExchanged(peerSidecarId)
	step, err := self.stop.reconcile(peerSidecarId, result)
	if err != nil {
		return nil, err
	}
	forked := step.forked
	if self.runActs(ctx, step.acts) {
		forked = true
	}
	return self.stop.witness(peerSidecarId, result, forked), nil
}

// Marks an exchange with the peer running, false if one already is.
func (self *headCheckTransport) claimExchange(peerSidecarId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.peerExchangesRunning[peerSidecarId] {
		return false
	}
	self.peerExchangesRunning[peerSidecarId] = true
	return true
}

// Ends the mark claimExchange set.
func (self *headCheckTransport) releaseExchange(peerSidecarId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.peerExchangesRunning, peerSidecarId)
}

// Runs acts in order, each with no lock held, feeding each outcome back to the stop state and running
// what that asks for in turn. Answers whether any step found a fork. A fetch api has not served is
// followed to its deadline in the background (followFetch), so the caller's witness is asked at once.
func (self *headCheckTransport) runActs(ctx context.Context, acts []headCheckAct) bool {
	forked := false
	for len(acts) != 0 {
		act := acts[0]
		acts = acts[1:]
		var step headCheckStep
		switch act.kind {
		case headCheckActFetch:
			fetchCtx, cancel := self.clockContext(ctx, self.settings.HeadCheckTimeout)
			err := self.sources.Auth.FetchAuth(fetchCtx, act.pin)
			cancel()
			if err != nil && self.subprotocol.log.V(1).Enabled() {
				self.subprotocol.log.Infof("[headcheck]fetch through %d: %s\n", act.pin.GetVersion(), err)
			}
			step = self.stop.fetched()
			if headCheckRelate(self.sources.Auth, self.sources.Auth.Pin(), act.pin) == headCheckRelationAhead {
				// the second try's wait is taken here, before the exchange answers, so the schedule
				// is fixed by the time the caller moves on
				fetch := act
				halfway := fetch.deadline.Add(-self.settings.HeadCheckFetchTimeout / 2)
				halfwayFire := self.clock.After(halfway.Sub(self.clock.Now()))
				self.goWorker(func() {
					self.followFetch(fetch, halfwayFire)
				})
			}
		case headCheckActAskProof:
			step = self.askProof(ctx, act)
		case headCheckActCatchUpGen:
			outcome, err := self.sources.Gens.CatchUpGen(ctx, act.gen)
			if err != nil {
				outcome = HeadCheckCatchUpUnserved
			}
			step = self.stop.caughtUp(act, outcome)
		case headCheckActCatchUpRef:
			outcome, err := self.sources.Refs.CatchUpRef(ctx, act.ref)
			if err != nil {
				outcome = HeadCheckCatchUpUnserved
			}
			step = self.stop.caughtUp(act, outcome)
		case headCheckActHoldVeto:
			if err := self.sources.Auth.HoldVeto(ctx, act.veto); err != nil && self.subprotocol.log.V(1).Enabled() {
				self.subprotocol.log.Infof("[headcheck]veto from %s refused: %s\n", act.peerId, err)
			}
		}
		if step.forked {
			forked = true
		}
		acts = append(acts, step.acts...)
	}
	return forked
}

// A fetch api did not serve at once: the second try halfway to its deadline, when halfwayFire fires,
// then at the deadline the fetch rows judge it, which asks its claimant for a proof (§6.4's auth row).
// Ends early once api has served it, or with the transport.
func (self *headCheckTransport) followFetch(act headCheckAct, halfwayFire <-chan time.Time) {
	select {
	case <-halfwayFire:
	case <-self.ctx.Done():
		return
	}
	fetchCtx, cancel := self.clockContext(self.ctx, self.settings.HeadCheckTimeout)
	self.sources.Auth.FetchAuth(fetchCtx, act.pin)
	cancel()
	step := self.stop.fetched()
	self.runActs(self.ctx, step.acts)
	if headCheckRelate(self.sources.Auth, self.sources.Auth.Pin(), act.pin) != headCheckRelationAhead {
		return
	}
	if wait := act.deadline.Sub(self.clock.Now()); 0 < wait {
		select {
		case <-self.clock.After(wait):
		case <-self.ctx.Done():
			return
		}
	}
	step = self.stop.fetched()
	self.runActs(self.ctx, step.acts)
}

// A ctx that ends with parent or once timeout passes on this side's clock, so a fake clock bounds the
// sources' I/O as it bounds everything else here.
func (self *headCheckTransport) clockContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	expire := self.clock.After(timeout)
	go func() {
		select {
		case <-expire:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// The client this side reaches the sidecar at: a standing Hello's, else its current binding from api,
// which counts only once it verifies, names this network and the sidecar, and its identity key is the
// sidecar's admission's in this side's state (§6.4's round row: checked before dialing).
func (self *headCheckTransport) resolve(ctx context.Context, sidecarId Id) (connect.Id, error) {
	if clientId, ok := self.subprotocol.verifiedClientOf(sidecarId); ok {
		return clientId, nil
	}
	admissions := self.subprotocol.admissions
	if admissions == nil {
		return connect.Id{}, errHeadCheckPeerUnresolved
	}
	authority := admissions.Authority()
	if authority == nil {
		return connect.Id{}, errHeadCheckPeerUnresolved
	}
	admission := authority.Admission(sidecarId)
	if admissionStanding(admission, sidecarId, self.clock.Now().UnixMilli()) != nil {
		return connect.Id{}, errHeadCheckPeerUnresolved
	}
	record, err := self.env.Identity(ctx, sidecarId)
	if err != nil {
		return connect.Id{}, fmt.Errorf("%w: %w", errHeadCheckPeerUnresolved, err)
	}
	binding, err := VerifySidecarIdentityBinding(record.Binding)
	if err != nil {
		return connect.Id{}, fmt.Errorf("%w: %w", errHeadCheckPeerUnresolved, err)
	}
	if binding.SidecarId != sidecarId || binding.NetworkId != self.stop.env.NetworkId ||
		!slices.Equal(binding.IdentityPublicKey, admission.Row.GetIdentityPublicKey()) {
		return connect.Id{}, errHeadCheckPeerUnresolved
	}
	return connect.Id(binding.ClientId), nil
}

// The client whose standing Hello showed sidecarId, if one stands.
func (self *Subprotocol) verifiedClientOf(sidecarId Id) (connect.Id, bool) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for sourceId, identity := range self.sourceIdIdentities {
		if identity.peer != nil && identity.peer.SidecarId == sidecarId && now.Before(identity.expireTime) {
			return sourceId, true
		}
	}
	return connect.Id{}, false
}

// Runs one HeadCheck exchange with the peer behind clientId now, its Hello first, whatever the round
// schedule says. Answers whether it counted as a consistent witness (§6.4's witness row), which
// refreshed witnessed_at. errHeadCheckEnv when no HeadCheck is attached.
func (self *Subprotocol) HeadCheckNow(ctx context.Context, clientId Id) (bool, error) {
	transport := self.headCheck.Load()
	if transport == nil {
		return false, fmt.Errorf("%w: not attached", errHeadCheckEnv)
	}
	witness, err := transport.exchange(ctx, connect.Id(clientId), false)
	if err != nil {
		return false, err
	}
	return witness != nil, nil
}
