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

package sidecar

import (
	"context"
	"errors"
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

// Starts nothing yet: the poll starts once the run loop publishes the generation (start). See sidecarLeg.
func (self *sidecarHttpLeg) startGeneration(generation *sidecarGeneration) (sidecarLegGeneration, error) {
	networkId := generation.networkId
	store, err := self.sidecar.instance.Store(&networkId).Directory(sidecarHttpPushStoreName, sidecarHttpPushStoreName)
	if err != nil {
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
	poll := func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		response, err := sidecar.sidecarApi.SyncPoll(ctx, cursor)
		if ctx.Err() == nil {
			self.report(err == nil)
		}
		return response, err
	}
	pollClient, err := newPushPollClient(generation.ctx, poll, sidecar.sidecarApi.SyncVersions, self.store, self.settings,
		sidecar.clock, sidecar.log, sidecar.emitEvent)
	if err != nil {
		return nil, err
	}
	generationNumber := generation.generation
	if _, err := pollClient.Subscribe(PushTopicCore, func(notice PushNotice) {
		sidecar.receiveCoreHint(generationNumber, notice.Hint)
	}); err != nil {
		pollClient.Close()
		return nil, err
	}
	return pollClient, nil
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
			// the store is locked or failed: the run loop sees the instance's state and ends the generation
			sidecar.log.Warningf("[sidecar]generation %d's poll did not start: %s", generation.generation, err)
			self.report(false)
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
