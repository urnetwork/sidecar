//go:build !ios_extension && !sidecar_http

// A share host's FriendsAndFamily (§17.9's isolation row, §6.10.1 items 4 and 5; C18, D-PROTO-6, D-PROTO-15;
// PROTO-M6-01's "FriendsAndFamily held only while a share lives"): the bridge component's part that holds the mode on
// each client generation's dispatcher while the state the device role holds in force serves a share whose grant
// stands, and releases it once none does. CreateContract settles a share link's contract as FriendsAndFamily only to
// a destination that provides the mode (server's resolveNonCompanionProvideMode), so without the hold a host refuses
// every share link and the accepting network's reachers reach none of its targets.
//
//	serve    the shares of each state the device role takes in force (BridgeRules.shares, which the compile fills only
//	         from a grant file whose grant is live, and only with the targets this host hosts): a share stands while its
//	         grant is neither revoked since that state nor past its expires
//	revoke   a GrantRevoke of a served share's grant, handed to the device role at its own position, ends that share
//	         at once: a pure denial wants no compile, so the release does not wait for one
//	expire   the earliest standing grant's expires, on the component's clock
//	hold     one hold (Subprotocol.HoldProvideMode) on each live generation's dispatcher while any share stands, one
//	         provide frame at the first and one at the release; released once none stands, when the generation ends
//	         or the component leaves it, and at the component's close. A generation with no dispatcher holds nothing
//
// The accepting network's end of a share, its release of the aliases, reaches no host of the sharing network: the
// accepting network's routers stop sending, and the host serves the share until its own network revokes the grant or
// the grant expires (§17.9's share pins).
//
// The mode is what the platform settles a contract by, never an authority: the host's hook checks every share flow's
// principal, share and grant per flow (device/bridge_share.go), and the role ends a revoked share's flows at the
// denial, so a hold that outlives a revocation by a moment admits nothing.
//
// A goroutine of its own applies the holds, so the compile's goroutine never waits on connect's control path, and it
// alone calls the dispatchers. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a generation holds a provide mode on: its Subprotocol.
type bridgeShareModeHolder interface {
	HoldProvideMode(mode connectprotocol.ProvideMode) (release func(), err error)
}

var _ bridgeShareModeHolder = (*Subprotocol)(nil)

// One share a state in force serves: its grant, and when that grant ends.
type bridgeShareStanding struct {
	shareId Id
	grantId []byte
	// zero for a grant with no expiry
	expires time.Time
}

// A client generation the mode is held on, from its attach until its ctx ends.
type bridgeShareModeGeneration struct {
	ctx    context.Context
	holder bridgeShareModeHolder
	// removes the wake the generation's end raises
	stopWake func() bool

	// owned by run: the hold's release, nil while none is held
	release func()
	// owned by run: the dispatcher refused a hold, as a closed one does, so the generation holds nothing more
	refused bool
}

// What run last applied: the input's version it read and how many generations it held the mode on.
type bridgeShareModeApplied struct {
	version   uint64
	heldCount int
}

// The share host's hold (the file's comment).
type bridgeShareMode struct {
	ctx       context.Context
	networkId Id
	clock     Clock
	log       Logger
	// wakes run, which reads everything again; one pending wake is enough
	wake chan struct{}
	// closed when run returns, every hold released
	done chan struct{}
	// moves after each pass of run
	applied *MonitorValue[bridgeShareModeApplied]

	stateLock sync.Mutex
	// moves at each change of the inputs below
	version uint64
	// the shares the state in force serves
	shares []bridgeShareStanding
	// the served grants a GrantRevoke named since that state
	revokedGrantIds map[string]bool
	// the live generations, oldest first
	generations []*bridgeShareModeGeneration
}

// A hold for networkId's component, its goroutine running until ctx ends.
func newBridgeShareMode(ctx context.Context, networkId Id, clock Clock, log Logger) *bridgeShareMode {
	self := &bridgeShareMode{
		ctx:             ctx,
		networkId:       networkId,
		clock:           clock,
		log:             log,
		wake:            make(chan struct{}, 1),
		done:            make(chan struct{}),
		applied:         NewMonitorValue(bridgeShareModeApplied{}),
		revokedGrantIds: map[string]bool{},
	}
	go self.run()
	return self
}

// Wakes run without waiting.
func (self *bridgeShareMode) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Takes a client generation: its dispatcher holds the mode while a share stands, until ctx ends. A generation with no
// dispatcher holds nothing.
func (self *bridgeShareMode) attach(ctx context.Context, subprotocol *Subprotocol) {
	if subprotocol == nil {
		return
	}
	self.attachHolder(ctx, subprotocol)
}

// attach, over any holder.
func (self *bridgeShareMode) attachHolder(ctx context.Context, holder bridgeShareModeHolder) {
	if ctx == nil || holder == nil {
		return
	}
	// the generation's end wakes run, which releases its hold
	generation := &bridgeShareModeGeneration{ctx: ctx, holder: holder, stopWake: context.AfterFunc(ctx, self.poke)}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generations = append(self.generations, generation)
		self.version += 1
	}()
	self.poke()
}

// Takes a state the device role holds in force: its shares are the ones that stand from now, less a grant a later
// GrantRevoke names. Rules that do not parse serve no share, so nothing is held for them.
func (self *bridgeShareMode) serve(state *bridge.BridgeState) {
	shares := bridgeServedShares(state)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.shares = shares
		// a revocation the state already holds dropped its share, and one it does not hold is kept, so the revoked
		// set stays among the served grants
		for grantId := range self.revokedGrantIds {
			if !slices.ContainsFunc(shares, func(share bridgeShareStanding) bool { return string(share.grantId) == grantId }) {
				delete(self.revokedGrantIds, grantId)
			}
		}
		self.version += 1
	}()
	self.poke()
}

// A GrantRevoke of grantId, handed to the device role at its own position: the share it ends stands no more. A grant
// no served share names changes nothing.
func (self *bridgeShareMode) revoke(grantId []byte) {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if len(grantId) == 0 || self.revokedGrantIds[string(grantId)] {
			return false
		}
		if !slices.ContainsFunc(self.shares, func(share bridgeShareStanding) bool { return bytes.Equal(share.grantId, grantId) }) {
			return false
		}
		self.revokedGrantIds[string(grantId)] = true
		self.version += 1
		return true
	}()
	if changed {
		self.poke()
	}
}

// Whether a share stands at now, and the earliest end of a standing one, zero for none. Under stateLock.
func (self *bridgeShareMode) standingWithLock(now time.Time) (bool, time.Time) {
	standing := false
	nextEnd := time.Time{}
	for _, share := range self.shares {
		if self.revokedGrantIds[string(share.grantId)] {
			continue
		}
		if !share.expires.IsZero() && !now.Before(share.expires) {
			continue
		}
		standing = true
		if !share.expires.IsZero() && (nextEnd.IsZero() || share.expires.Before(nextEnd)) {
			nextEnd = share.expires
		}
	}
	return standing, nextEnd
}

// The loop that applies the holds: each pass reads the inputs, releases an ended generation's hold, then holds on each
// live generation while a share stands and releases each once none does, and waits for a change or the next end. The
// next end's wake is armed once for that end, on the clock, and again only when the earliest end changes, so a pass
// that changed nothing arms nothing.
func (self *bridgeShareMode) run() {
	defer close(self.done)
	heldGenerations := []*bridgeShareModeGeneration{}
	// the end the armed wake is for, zero for none, and what stops it
	var wakeEnd time.Time
	var stopWake func() bool
	defer func() {
		if stopWake != nil {
			stopWake()
		}
		// the component's end: every hold goes, and no generation's end wakes it any more
		for _, generation := range heldGenerations {
			self.release(generation)
		}
		generations := func() []*bridgeShareModeGeneration {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			generations := self.generations
			self.generations = nil
			return generations
		}()
		for _, generation := range generations {
			generation.stopWake()
		}
	}()
	for {
		now := self.clock.Now()
		var version uint64
		var standing bool
		var nextEnd time.Time
		var liveGenerations []*bridgeShareModeGeneration
		endedGenerations := []*bridgeShareModeGeneration{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			version = self.version
			standing, nextEnd = self.standingWithLock(now)
			kept := make([]*bridgeShareModeGeneration, 0, len(self.generations))
			for _, generation := range self.generations {
				if generation.ctx.Err() != nil {
					endedGenerations = append(endedGenerations, generation)
					continue
				}
				kept = append(kept, generation)
			}
			self.generations = kept
			liveGenerations = slices.Clone(kept)
		}()
		for _, generation := range endedGenerations {
			self.release(generation)
		}
		heldCount := 0
		for _, generation := range liveGenerations {
			switch {
			case standing && generation.release == nil && !generation.refused:
				testHookBarrier("bridge_share.provide_mode.before", self.networkId.String())
				release, err := generation.holder.HoldProvideMode(connectprotocol.ProvideMode_FriendsAndFamily)
				testHookBarrier("bridge_share.provide_mode.after", self.networkId.String())
				if err != nil {
					generation.refused = true
					self.log.Warningf("[bridge]%s a generation's dispatcher refused FriendsAndFamily for the shares this host serves: %v", self.networkId, err)
				} else {
					generation.release = release
				}
			case !standing && generation.release != nil:
				self.release(generation)
			}
			if generation.release != nil {
				heldCount += 1
			}
		}
		heldGenerations = slices.DeleteFunc(liveGenerations, func(generation *bridgeShareModeGeneration) bool { return generation.release == nil })
		self.applied.Set(bridgeShareModeApplied{version: version, heldCount: heldCount})
		if !wakeEnd.IsZero() && !now.Before(wakeEnd) {
			// the wake for that end fired, or is due: this pass read past it
			stopWake()
			wakeEnd, stopWake = time.Time{}, nil
		}
		if !nextEnd.Equal(wakeEnd) {
			if stopWake != nil {
				stopWake()
			}
			wakeEnd, stopWake = nextEnd, nil
			if !nextEnd.IsZero() {
				stopWake = self.clock.AfterFunc(nextEnd.Sub(now), self.poke)
			}
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		}
	}
}

// Releases a generation's hold, if it holds one. On run's goroutine.
func (self *bridgeShareMode) release(generation *bridgeShareModeGeneration) {
	if generation.release == nil {
		return
	}
	testHookBarrier("bridge_share.provide_mode.before", self.networkId.String())
	generation.release()
	testHookBarrier("bridge_share.provide_mode.after", self.networkId.String())
	generation.release = nil
}

// The shares a state serves at this host (BridgeRules.shares), each with a target: none for a nil state or rules that
// do not parse.
func bridgeServedShares(state *bridge.BridgeState) []bridgeShareStanding {
	shares := []bridgeShareStanding{}
	if state == nil {
		return shares
	}
	rules := &bridge.BridgeRules{}
	if err := proto.Unmarshal(state.GetRules(), rules); err != nil {
		return shares
	}
	for _, share := range rules.GetShares() {
		shareId, err := IdFromBytes(share.GetShareId())
		if err != nil || len(share.GetGrantId()) == 0 || len(share.GetTargets()) == 0 {
			continue
		}
		standing := bridgeShareStanding{shareId: shareId, grantId: bytes.Clone(share.GetGrantId())}
		if expires := share.GetExpires(); expires != 0 {
			standing.expires = time.UnixMilli(expires)
		}
		shares = append(shares, standing)
	}
	return shares
}
