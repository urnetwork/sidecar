//go:build sidecar_http

// One client generation on the sidecar_http leg (§5.4's lifecycle, §6.8's long-poll, §18.10): where a connect leg's
// generation is its Required client with §6's dispatcher and the components, this leg's is GET /sidecar/sync/poll in a
// loop on SidecarApi, which carries `core` and every other topic a page Worker follows, and nothing attaches. The
// token and the ClientKey's DPoP signer are SidecarApi's, which the core installs for every leg, and D-CORE-8's
// refresher keeps them (sidecar_generation.go), so install here has no holder of its own to update.
//
// The generation is Online while polls answer and Offline while they fail, as a connect leg follows its client's
// connection. A poll answering 401 ends the poll client: the generation goes Offline, asks the refresher for a
// refresh, as connect's AuthorizationClosed does, and polls again once a refreshed token is installed, waiting out a
// doubling interval if 401s repeat. A refresh that is refused ends the generation through the refresher, never here
// (D-CORE-8).
//
// js/wasm runs one thread (§18.10's threads row): the poll's fetch is asynchronous, so the poll loop holds the thread
// only while it applies a reply, and nothing here waits on the keychain under a lock the poll needs. Long keychain or
// MLS work yields between steps (sidecar_yield.go), so a poll's reply and a page's requests interleave with it.
//
// The poll keeps its topic versions in the network's subprotocol store, as every leg does, and a sealed file there that
// fails decoding is §5.9's Failed (owner decision 616). The generation's start reads the versions the poll client
// will start from, so such a file fails the start as the connect leg's does, wrapped in errSidecarSubprotocolStoreFailed:
// the core keeps the sidecar Offline at the generation with subprotocol_store_failed, raises refused once and retries
// at the next wake. A poll client started again later in the generation, after a 401, that finds the file failed
// raises the same through the core, the poll loop trying again at the next install or RetryMaxInterval, so a damaged
// store never spins it; the next poll client that reads the store ends the reason before it polls.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The network directory and seal class the poll's topic versions are kept in: the connect legs' dispatcher keeps its
// push client's there too (sidecarSubprotocolStoreName), so the file is where every leg keeps it.
const sidecarHttpPushStoreName = "subprotocol"

// This leg's half of a Sidecar: no component, no client strategy.
type sidecarHttpLeg struct {
	sidecar *Sidecar
}

// Starts nothing yet: the poll starts once the run loop publishes the generation (start). It reads the topic versions
// the poll client will start from, so a sealed file there that fails decoding fails the start, as the file header says.
// See sidecarLeg.
func (self *sidecarHttpLeg) startGeneration(generation *sidecarGeneration) (sidecarLegGeneration, error) {
	networkId := generation.networkId
	store, err := self.sidecar.instance.Store(&networkId).Directory(sidecarHttpPushStoreName, sidecarHttpPushStoreName)
	if err != nil {
		return nil, err
	}
	if _, err := loadPushVersions(store); err != nil {
		if errors.Is(err, ErrSidecarStoreFailed) {
			return nil, fmt.Errorf("%w: %w", errSidecarSubprotocolStoreFailed, err)
		}
		return nil, err
	}
	settings := DefaultPushClientSettings()
	settings.SyncRefetchInterval = self.sidecar.settings.ProtocolSettings.SyncRefetchInterval
	return &sidecarHttpGeneration{
		leg:        self,
		generation: generation,
		store:      store,
		settings:   settings,
		installs:   NewMonitorValue[uint64](0),
		done:       make(chan struct{}),
	}, nil
}

// None: a page Worker registers nothing at api that a restore loses.
func (self *sidecarHttpLeg) restorers() []SidecarRestorer {
	return nil
}

// Zero: this leg has no dispatcher.
func (self *sidecarHttpLeg) subprotocolStats() SidecarSubprotocolStats {
	return SidecarSubprotocolStats{}
}

// Nothing to close: no component and no client strategy.
func (self *sidecarHttpLeg) close() {
}

// One generation's long-poll.
type sidecarHttpGeneration struct {
	leg        *sidecarHttpLeg
	generation *sidecarGeneration
	// the poll's topic versions, beside every leg's
	store    SidecarStore
	settings *PushClientSettings
	// raised at each refreshed token's install, which a poll a 401 ended waits for
	installs *MonitorValue[uint64]
	// closed once run has returned; nil-safe to wait on only after start
	done chan struct{}

	stateLock sync.Mutex
	started   bool
	// what the generation last reported: Online while polls answer
	online   bool
	reported bool
}

// Starts the poll loop. See sidecarLegGeneration.
func (self *sidecarHttpGeneration) start() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.started = true
	}()
	go self.run()
}

// A refreshed token is SidecarApi's already, which every poll reads; a poll a 401 ended starts again on it.
func (self *sidecarHttpGeneration) install(byJwt string) {
	self.installs.Update(func(count uint64) uint64 {
		return count + 1
	})
}

// Nothing attaches on this leg.
func (self *sidecarHttpGeneration) reconcileComponents() {
}

// Zero: no dispatcher.
func (self *sidecarHttpGeneration) subprotocolStats() SidecarSubprotocolStats {
	return SidecarSubprotocolStats{}
}

// Waits for the poll loop, which ends with the generation's ctx. See sidecarLegGeneration.
func (self *sidecarHttpGeneration) closeAndWait() {
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.started
	}()
	if started {
		<-self.done
	}
}

// Online or Offline as polls answer or fail, reported once per change.
func (self *sidecarHttpGeneration) report(online bool) {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.reported && self.online == online {
			return false
		}
		self.reported = true
		self.online = online
		return true
	}()
	if changed {
		self.generation.connectionChanged(online)
	}
}

// The poll client of one token: §6.8's machine on GET /sidecar/sync/poll and /sidecar/sync/versions, its core notices
// to the core, every poll's outcome to report.
func (self *sidecarHttpGeneration) newPollClient() (*PushPollClient, error) {
	sidecar := self.leg.sidecar
	generation := self.generation
	// no request goes before core is subscribed, so no notice of the first reply is lost
	subscribed := make(chan struct{})
	awaitSubscribed := func(ctx context.Context) error {
		select {
		case <-subscribed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	poll := func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		if err := awaitSubscribed(ctx); err != nil {
			return nil, err
		}
		response, err := sidecar.sidecarApi.SyncPoll(ctx, cursor)
		if ctx.Err() == nil {
			self.report(err == nil)
		}
		return response, err
	}
	versions := func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		if err := awaitSubscribed(ctx); err != nil {
			return nil, err
		}
		return sidecar.sidecarApi.SyncVersions(ctx, cursor)
	}
	pollClient, err := newPushPollClient(generation.ctx, poll, versions, self.store, self.settings, sidecar.clock, sidecar.log,
		sidecar.emitEvent)
	if err != nil {
		return nil, err
	}
	generationNumber := generation.generation
	if _, err := pollClient.Subscribe(PushTopicCore, generation.receiveCoreNotice); err != nil {
		pollClient.Close()
		return nil, err
	}
	// The Worker may open its replica before or after this poll client. Resolve the current
	// follower on delivery so notices survive token refresh and an intervening close.
	for _, topic := range []string{PushTopicTeam, PushTopicGkm, PushTopicGkmGroupPrefix} {
		if _, err := pollClient.Subscribe(topic, func(notice PushNotice) {
			follower := sidecar.ConfigFollower()
			if follower == nil {
				return
			}
			if topic == PushTopicTeam {
				follower.receiveNotice(notice)
			} else if hints := follower.args.Hints; hints != nil {
				hints.Receive(notice)
			}
		}); err != nil {
			pollClient.Close()
			return nil, err
		}
	}
	// it read the store: a reason an earlier poll client's failure raised ends before this one's first poll reports
	sidecar.subprotocolStoreRead(generationNumber)
	close(subscribed)
	return pollClient, nil
}

// Ends generation's subprotocol_store_failed once a poll client of it has read the store: Offline at generation with no
// reason, only while the sidecar stands at that reason, checked and moved under stateLock, so nothing the poll or the
// refresher moved meanwhile is undone. Raises the state event as applyTransition does.
func (self *Sidecar) subprotocolStoreRead(generation int64) {
	storeFailed := sidecarLifecycle{
		state:      SidecarStateOffline,
		reason:     SidecarReasonSubprotocolStoreFailed,
		generation: generation,
	}
	var next sidecarLifecycle
	moved := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.lifecycle != storeFailed {
			return false
		}
		var result sidecarTransitionResult
		next, result = nextSidecarLifecycle(self.lifecycle, sidecarTransition{to: SidecarStateOffline, generation: generation})
		if result != sidecarTransitionApplied {
			return false
		}
		self.lifecycle = next
		self.state.Set(next.state)
		return true
	}()
	if moved {
		self.emitEvent(SidecarEvent{
			Kind:       SidecarEventState,
			Generation: next.generation,
			State:      next.state,
			Reason:     next.reason,
		})
	}
}

// The generation's poll, until its ctx ends: a poll client, and after a 401 the refresher's next token. See the file
// header.
func (self *sidecarHttpGeneration) run() {
	defer close(self.done)
	generation := self.generation
	sidecar := self.leg.sidecar
	retryInterval := time.Duration(0)
	for generation.ctx.Err() == nil {
		// subscribed before the poll starts, so an install while it runs is never missed
		_, installed := self.installs.Get()
		pollClient, err := self.newPollClient()
		if err != nil {
			// a locked, lost or failed instance: the run loop sees its state and ends the generation. A sealed file that
			// fails decoding while the instance stands open is §5.9's Failed, raised once, as at the generation's start
			// (owner decision 616)
			sidecar.log.Warningf("[sidecar]generation %d's poll did not start: %s", generation.generation, err)
			self.report(false)
			if errors.Is(err, ErrSidecarStoreFailed) && sidecar.instance.stateError() == nil {
				sidecar.subprotocolStoreFailed(generation.generation)
			}
			select {
			case <-generation.ctx.Done():
			case <-installed:
			case <-sidecar.clock.After(self.settings.RetryMaxInterval):
			}
			continue
		}
		startTime := sidecar.clock.Now()
		select {
		case <-generation.ctx.Done():
			pollClient.Close()
			return
		case <-pollClient.Done():
		}
		ended := pollClient.Ended()
		pollClient.Close()
		if generation.ctx.Err() != nil {
			return
		}
		var apiError *SidecarApiError
		if ended == nil || !errors.As(ended, &apiError) {
			// the poll client ends only at Close or a 401
			continue
		}
		self.report(false)
		// D-CORE-8: a 401 asks for a refresh and nothing more; a refused refresh ends the generation
		generation.authorizationClosed(false)
		if retryInterval == 0 || self.settings.RetryMaxInterval <= sidecar.clock.Now().Sub(startTime) {
			retryInterval = self.settings.RetryMinInterval
		} else {
			retryInterval = min(2*retryInterval, self.settings.RetryMaxInterval)
		}
		select {
		case <-generation.ctx.Done():
			return
		case <-installed:
		}
		select {
		case <-generation.ctx.Done():
			return
		case <-sidecar.clock.After(retryInterval):
		}
	}
}
