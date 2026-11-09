// Links (§17.5's links row, Q-BRIDGE-2, D-BRIDGE-5, D-BRIDGE-17, I-3): one per target, each a multi client a BridgeHost
// builds with one Required window client (bridge_link_settings.go), whose every contract carries the subject's
// WindowDelegation and answers to the target's identity binding (bridge_link_generator.go). BridgeLinkManager keeps them:
//
//	build    lazily, at a target's first packet, outside Route: Route hands a packet to the link's client once it has
//	         one, and until then refuses it, so the packet stays its caller's and a sender waits behind a bounded
//	         refusal rather than a block; one build per link however many packets ask
//	pin      before the build, the target's identity binding, fetched by the host and verified here against the key
//	         the rules pin, so every contract the link takes must carry the client key it names (FS-38's sender row)
//	idle     a link that carried nothing for 600 s closes, and builds again at its next packet
//	rebuild  a link 6 days old is replaced by a new link to its target, the old one draining under the pins until its
//	         window clients' strict_exp, then closing (§7.4)
//	room     past LinkCountMax open links, a build closes the least recently used link idle for LinkRoomIdleTimeout;
//	         a busy link is never closed for room, and no build is refused for count (R-BRIDGE-11)
//	health   a refused contract, a failed destination check, an identity failure, no sealed session 3 s after the
//	         first packet, or a failed build marks the link down (plan-BRIDGE-small-readings #15); the bridge takes it
//	         out of new pairs while another advertiser is up, and a failed build is tried again only after
//	         LinkDownTimeout, while Route answers its packets with rejects
//	close    on the manager's own goroutine, outside every lock, never inside a client's callback (CODESTYLE's
//	         CloseAndWait rule): a client's callbacks only set flags and wake it
//
// A link can be built only with a host, the sidecar role's signer and the binding fetch, an identity to sign as, and a
// LinkCountMax other than 0; with any missing, Route answers every link with a reject, which fails closed.
//
// Safe for concurrent use. Route is lock- and allocation-free.

package device

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Signs one window client's WindowDelegation as this device's sidecar role (§17.9's sign, §18.6's signer row).
// delegation is the body to sign: this network, this sidecar as subject, the window client and its ClientKey, the
// target, and not_after_ms, the window client's strict_exp. Returns the marshalled Signed, type 0x1908 and purpose
// window-delegation. The signer refuses what it would not sign: another subject, or a target its newest state does not
// name. Called off the packet path, once per window client, and may wait on §18.6's channel until ctx ends.
type BridgeSignFunction func(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error)

// Fetches the identity binding of a link's target client (§5.5): the marshalled SignedSidecarIdentityBinding api
// answers for it, from GET /sidecar/identity?client_id=<id> or the binding of GET /sidecar/identity/<sidecar_id> that
// names the client. The link verifies it against the identity key the rules pin before it trusts the client key it
// names, so neither the host nor api is trusted. Called off the packet path, once per link build.
type BridgeTargetKeyFunction func(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error)

// What a link reaches, one link per target (Q-BRIDGE-2): the target's client and sidecar, the identity key the rules
// pin for it (BridgeRuleLink.target_identity_public_key), and on a share link its share (BRIDGE-M6-05), zero here.
type BridgeLinkTarget struct {
	ClientId          connect.Id
	SidecarId         connect.Id
	IdentityPublicKey [ed25519.PublicKeySize]byte
	ShareId           connect.Id
}

// One link of a target as an entry takes it: the target's current link, or one a rebuild replaced, draining from
// DrainingSince until DrainUntil, its window clients' strict_exp.
type BridgeLinkUse struct {
	Link          BridgeLinkId
	DrainingSince time.Time
	DrainUntil    time.Time
}

// What Route makes of a link.
type bridgeLinkRoute int

const (
	// It has a client, which takes the packet.
	bridgeLinkRouteClient bridgeLinkRoute = iota
	// It is building: the packet is refused, and stays its caller's.
	bridgeLinkRouteWait
	// It cannot carry the packet: no link can be built here, it left its target, or its last build failed and waits
	// to try again.
	bridgeLinkRouteReject
)

// A link that cannot be built or used.
var ErrBridgeLinkRefused = errors.New("bridge link refused")

// A target's binding that does not verify against what the rules pin.
var ErrBridgeLinkTargetUnverified = errors.New("bridge link target unverified")

// The context key a link's build hands its host, carrying the build, for NewBridgeLinkGenerator.
type bridgeLinkContextKey struct{}

// §5.5's binding purposes (plan-CORE-binding-wire #1), which the root's identity_binding.go names too.
const (
	bridgeBindingClientPurpose   = "binding-client"
	bridgeBindingIdentityPurpose = "binding-identity"
	// a canonical binding is under 250 bytes; this only stops a decoder reading garbage whole
	bridgeBindingMaxByteCount = 4 * 1024
)

// One link, by id, for as long as it serves an entry. Its client comes and goes: built at a packet, closed at idle.
type bridgeLink struct {
	id      BridgeLinkId
	target  BridgeLinkTarget
	manager *BridgeLinkManager

	// the build in force, nil while the link has no client
	built atomic.Pointer[bridgeLinkBuilt]
	// a packet asked for a build that has not started
	buildWanted atomic.Bool
	building    atomic.Bool
	// seconds since the manager's epoch, plus one, of the last packet Route handed the link; 0 for none
	lastRouteSecond atomic.Uint32
	// unix ns before which a failed build is not tried again; Route rejects until then
	retryUntilNano atomic.Int64

	// left its target, or drained: it builds nothing, Route rejects for it, and run closes it; set under the
	// manager's stateLock
	retired atomic.Bool

	// under the manager's stateLock: when a rebuild replaced it, zero while it is its target's current link, and
	// when its drain ends
	replacedAt time.Time
	drainUntil time.Time
}

// One build of a link: the host's client and what its window clients answer to.
type bridgeLinkBuilt struct {
	link    *bridgeLink
	manager *BridgeLinkManager
	// ends with the build: the host's client is built on it, and sign stops with it
	ctx     context.Context
	cancel  context.CancelFunc
	builtAt time.Time
	// who the window clients sign as
	networkId []byte
	sidecarId []byte
	// the client key the target's verified binding names, which every contract must carry
	targetClientKey ed25519.PublicKey

	// set before the build is published, never after
	client connect.UserNatClient

	// unix ns of the first packet routed to the build, 0 until one
	firstRouteNano atomic.Int64
	// a window client's session with the target sealed
	sealed atomic.Bool
	// a refusal seen and not yet reported
	refused atomic.Bool
	// the connect timeout was reported
	connectTimedOut atomic.Bool
	// the latest strict_exp a window client was signed for, unix ms, 0 for none
	notAfterMs atomic.Int64
}

// The links of one bridge. See the file's comment.
type BridgeLinkManager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *BridgeSettings
	clock    Clock
	host     BridgeHost
	// what route seconds count from
	epoch time.Time

	// the links by id, replaced whole when one is added or removed, so Route finds one with one load and no lock
	links atomic.Pointer[map[BridgeLinkId]*bridgeLink]

	// wakes run: a build asked for, a first packet, a refusal, a timer
	wake chan struct{}
	// closed when run returns
	done chan struct{}
	// the builds in flight, which Close joins
	builds sync.WaitGroup

	changeCallbacks *connect.CallbackList[func()]
	downCallbacks   *connect.CallbackList[func(BridgeLinkId)]
	// called after each pass of run and each build's end; nil outside tests
	passedForTest atomic.Pointer[func()]

	// whether networkId and sidecarId name an identity, for Route
	hasIdentity atomic.Bool

	stateLock sync.Mutex
	// who links sign as: this network and this device's sidecar_id, nil before a posture names them
	networkId []byte
	sidecarId []byte
	// each target's current link
	targetLinks map[BridgeLinkTarget]*bridgeLink
	lastLinkId  BridgeLinkId
	closed      bool
}

// A manager whose links host builds; nil host builds none. Nil settings are DefaultBridgeSettings. Starts run.
func NewBridgeLinkManager(ctx context.Context, host BridgeHost, settings *BridgeSettings) *BridgeLinkManager {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := settings.clock()
	self := &BridgeLinkManager{
		ctx:             cancelCtx,
		cancel:          cancel,
		settings:        settings,
		clock:           clock,
		host:            host,
		epoch:           clock.Now(),
		wake:            make(chan struct{}, 1),
		done:            make(chan struct{}),
		changeCallbacks: connect.NewCallbackList[func()](),
		downCallbacks:   connect.NewCallbackList[func(BridgeLinkId)](),
		targetLinks:     map[BridgeLinkTarget]*bridgeLink{},
	}
	links := map[BridgeLinkId]*bridgeLink{}
	self.links.Store(&links)
	go self.run()
	return self
}

// Stops run, joins every build, and closes every link's client, outside every lock.
func (self *BridgeLinkManager) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	self.cancel()
	<-self.done
	self.builds.Wait()
	builds := []*bridgeLinkBuilt{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, link := range *self.links.Load() {
			if built := link.built.Swap(nil); built != nil {
				builds = append(builds, built)
			}
		}
	}()
	for _, built := range builds {
		built.close()
	}
}

// Who links sign as: the network and this device's sidecar_id, from the posture (§17.9's sign); nil for none, which
// builds nothing. A change closes every built link, since its window clients were signed for as another subject; each
// builds again at its next packet.
func (self *BridgeLinkManager) SetIdentity(networkId []byte, sidecarId []byte) {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if bytes.Equal(self.networkId, networkId) && bytes.Equal(self.sidecarId, sidecarId) {
			return false
		}
		self.networkId = bytes.Clone(networkId)
		self.sidecarId = bytes.Clone(sidecarId)
		self.hasIdentity.Store(len(networkId) == bridgeRuleIdByteCount && len(sidecarId) == bridgeRuleIdByteCount)
		for _, link := range *self.links.Load() {
			link.retryUntilNano.Store(0)
		}
		return true
	}()
	if changed {
		self.wakeRun()
	}
}

// Calls callback, on a goroutine of the manager's and under none of its locks, after a link of a target is added,
// replaced or retired, so the bridge gives its entries the links Retain names; the returned function removes it.
func (self *BridgeLinkManager) AddChangeCallback(callback func()) func() {
	callbackId := self.changeCallbacks.Add(callback)
	return func() {
		self.changeCallbacks.Remove(callbackId)
	}
}

// Calls callback with a link that refused, as the change callbacks are called, so the bridge marks it down in every
// entry it serves (§17.5's health row); the returned function removes it.
func (self *BridgeLinkManager) AddDownCallback(callback func(link BridgeLinkId)) func() {
	callbackId := self.downCallbacks.Add(callback)
	return func() {
		self.downCallbacks.Remove(callbackId)
	}
}

// The links targets take, each target's current one and those a rebuild replaced and that still drain, by target;
// a target with none gets a link, unbuilt. Every link of a target not among targets leaves it, and run closes it.
func (self *BridgeLinkManager) Retain(targets []BridgeLinkTarget) map[BridgeLinkTarget][]BridgeLinkUse {
	uses := map[BridgeLinkTarget][]BridgeLinkUse{}
	retired := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		kept := map[BridgeLinkTarget]bool{}
		for _, target := range targets {
			kept[target] = true
			if self.targetLinks[target] == nil && !self.closed {
				self.newLinkWithLock(target)
			}
		}
		for target := range self.targetLinks {
			if !kept[target] {
				delete(self.targetLinks, target)
			}
		}
		for _, link := range self.sortedLinksWithLock() {
			if link.retired.Load() {
				continue
			}
			if !kept[link.target] {
				link.retired.Store(true)
				retired = true
				continue
			}
			use := BridgeLinkUse{Link: link.id}
			if !link.replacedAt.IsZero() {
				use.DrainingSince = link.replacedAt
				use.DrainUntil = link.drainUntil
			}
			uses[link.target] = append(uses[link.target], use)
		}
	}()
	if retired {
		self.wakeRun()
	}
	return uses
}

// Adds a current link of target, unbuilt.
func (self *BridgeLinkManager) newLinkWithLock(target BridgeLinkTarget) *bridgeLink {
	self.lastLinkId += 1
	if self.lastLinkId == 0 {
		self.lastLinkId = 1
	}
	link := &bridgeLink{id: self.lastLinkId, target: target, manager: self}
	self.targetLinks[target] = link
	links := maps.Clone(*self.links.Load())
	links[link.id] = link
	self.links.Store(&links)
	return link
}

// Every link, by id, for a pass in one order.
func (self *BridgeLinkManager) sortedLinksWithLock() []*bridgeLink {
	links := slices.Collect(maps.Values(*self.links.Load()))
	slices.SortFunc(links, func(a *bridgeLink, b *bridgeLink) int {
		return cmp.Compare(a.id, b.id)
	})
	return links
}

// Whether a link can be built now: open, with a host, the signer and the fetch, an identity, and links allowed at all.
func (self *BridgeLinkManager) canBuildWithLock() bool {
	return !self.closed && self.canBuild()
}

// The second of now, counted from the epoch, plus one, so 0 means none.
func (self *BridgeLinkManager) routeSecond(now time.Time) uint32 {
	elapsed := now.Sub(self.epoch)
	if elapsed < 0 {
		return 1
	}
	return uint32(elapsed/time.Second) + 1
}

// The time a route second stands for.
func (self *BridgeLinkManager) routeSecondTime(second uint32) time.Time {
	return self.epoch.Add(time.Duration(second-1) * time.Second)
}

// What carries a packet to link at now: its client, a wait while it builds, or a reject. Asks for a build when it has
// no client. Lock- and allocation-free: one map load, a few atomics, and a wake that never blocks.
func (self *BridgeLinkManager) route(linkId BridgeLinkId, now time.Time) (connect.UserNatClient, bridgeLinkRoute) {
	link := (*self.links.Load())[linkId]
	if link == nil || link.retired.Load() {
		return nil, bridgeLinkRouteReject
	}
	second := self.routeSecond(now)
	if link.lastRouteSecond.Load() != second {
		link.lastRouteSecond.Store(second)
	}
	if built := link.built.Load(); built != nil {
		if built.firstRouteNano.Load() == 0 && built.firstRouteNano.CompareAndSwap(0, now.UnixNano()) {
			self.wakeRun()
		}
		return built.client, bridgeLinkRouteClient
	}
	if now.UnixNano() < link.retryUntilNano.Load() {
		return nil, bridgeLinkRouteReject
	}
	if !self.canBuild() {
		return nil, bridgeLinkRouteReject
	}
	if !link.buildWanted.Load() && link.buildWanted.CompareAndSwap(false, true) {
		self.wakeRun()
	}
	return nil, bridgeLinkRouteWait
}

// Whether a link of this manager can ever be built, as Route reads it, with no lock: the settings never change, and
// the identity is one atomic load.
func (self *BridgeLinkManager) canBuild() bool {
	return self.host != nil && self.settings.LinkSign != nil && self.settings.LinkTargetKey != nil &&
		self.settings.LinkCountMax != 0 && self.hasIdentity.Load()
}

// Wakes run, never blocking.
func (self *BridgeLinkManager) wakeRun() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Keeps the links: one maintain pass at each wake, and a timer for the next time a link's state changes.
func (self *BridgeLinkManager) run() {
	defer close(self.done)
	for {
		next := self.maintain()
		stop := func() bool { return false }
		if !next.IsZero() {
			stop = self.clock.AfterFunc(next.Sub(self.clock.Now()), self.wakeRun)
		}
		select {
		case <-self.ctx.Done():
			stop()
			return
		case <-self.wake:
		}
		stop()
	}
}

// One pass over the links at the clock's now, by the file's rows: refusals and connect timeouts reported, idle and
// drained links closed, old links replaced, wanted builds started, and room made past LinkCountMax. Closes, builds and
// callbacks run after the pass, outside the lock. Returns the next time a link's state changes, zero for none.
func (self *BridgeLinkManager) maintain() time.Time {
	now := self.clock.Now()
	var next time.Time
	soonest := func(at time.Time) {
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	closes := []*bridgeLinkBuilt{}
	starts := []*bridgeLink{}
	downs := []BridgeLinkId{}
	changed := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		unbuild := func(link *bridgeLink) {
			if built := link.built.Swap(nil); built != nil {
				closes = append(closes, built)
			}
		}
		removed := false
		links := maps.Clone(*self.links.Load())
		for _, link := range self.sortedLinksWithLock() {
			if link.retired.Load() {
				unbuild(link)
				if !link.building.Load() {
					delete(links, link.id)
					removed = true
				}
				continue
			}
			if built := link.built.Load(); built != nil &&
				(!bytes.Equal(built.networkId, self.networkId) || !bytes.Equal(built.sidecarId, self.sidecarId)) {
				// signed for as another subject: closed, to build again as this one at its next packet
				unbuild(link)
			}
			if built := link.built.Load(); built != nil {
				if built.refused.Swap(false) {
					downs = append(downs, link.id)
				}
				if first := built.firstRouteNano.Load(); first != 0 && !built.sealed.Load() && !built.connectTimedOut.Load() {
					deadline := time.Unix(0, first).Add(self.settings.LinkConnectTimeout)
					if now.Before(deadline) {
						soonest(deadline)
					} else {
						built.connectTimedOut.Store(true)
						downs = append(downs, link.id)
					}
				}
			}
			if built := link.built.Load(); built != nil {
				active := built.builtAt
				if second := link.lastRouteSecond.Load(); second != 0 && self.routeSecondTime(second).After(active) {
					active = self.routeSecondTime(second)
				}
				idleAt := active.Add(self.settings.LinkIdleTimeout)
				if now.Before(idleAt) {
					soonest(idleAt)
				} else {
					unbuild(link)
					if !link.replacedAt.IsZero() {
						// a replaced link idle: its pairs are gone
						link.retired.Store(true)
						changed = true
					}
				}
			}
			if built := link.built.Load(); built != nil && link.replacedAt.IsZero() {
				rebuildAt := built.builtAt.Add(self.settings.LinkRebuildInterval)
				if now.Before(rebuildAt) {
					soonest(rebuildAt)
				} else {
					successor := self.newLinkWithLock(link.target)
					links[successor.id] = successor
					successor.buildWanted.Store(true)
					link.replacedAt = now
					link.drainUntil = now
					if notAfterMs := built.notAfterMs.Load(); 0 < notAfterMs {
						link.drainUntil = time.UnixMilli(notAfterMs)
					}
					changed = true
				}
			}
			if !link.replacedAt.IsZero() && !link.retired.Load() {
				if now.Before(link.drainUntil) {
					soonest(link.drainUntil)
				} else {
					link.retired.Store(true)
					changed = true
					unbuild(link)
				}
			}
		}
		// builds wanted, each once, after its retry wait
		openCount := 0
		for _, link := range links {
			if link.built.Load() != nil || link.building.Load() {
				openCount += 1
			}
		}
		for _, link := range self.sortedLinksWithLock() {
			if link.retired.Load() || link.built.Load() != nil || link.building.Load() || !link.buildWanted.Load() {
				continue
			}
			if retryUntil := time.Unix(0, link.retryUntilNano.Load()); now.Before(retryUntil) {
				soonest(retryUntil)
				continue
			}
			link.buildWanted.Store(false)
			if !self.canBuildWithLock() {
				continue
			}
			link.building.Store(true)
			starts = append(starts, link)
			openCount += 1
		}
		// room: the least recently used links idle for LinkRoomIdleTimeout close, and never a busy one
		if 0 < self.settings.LinkCountMax {
			for self.settings.LinkCountMax < openCount {
				var victim *bridgeLink
				var victimSecond uint32
				for _, link := range self.sortedLinksWithLock() {
					if link.built.Load() == nil {
						continue
					}
					second := link.lastRouteSecond.Load()
					lastRoute := link.built.Load().builtAt
					if second != 0 && self.routeSecondTime(second).After(lastRoute) {
						lastRoute = self.routeSecondTime(second)
					}
					if now.Sub(lastRoute) < self.settings.LinkRoomIdleTimeout {
						continue
					}
					if victim == nil || second < victimSecond {
						victim = link
						victimSecond = second
					}
				}
				if victim == nil {
					break
				}
				unbuild(victim)
				if !victim.replacedAt.IsZero() {
					victim.retired.Store(true)
					changed = true
				}
				openCount -= 1
			}
		}
		if removed || changed {
			self.links.Store(&links)
		}
	}()
	if 0 < len(closes) {
		testHookBarrier("bridge_link.close.before", "")
		for _, built := range closes {
			built.close()
		}
		testHookBarrier("bridge_link.close.after", "")
	}
	for _, link := range starts {
		self.builds.Add(1)
		go self.build(link)
	}
	for _, linkId := range downs {
		for _, callback := range self.downCallbacks.Get() {
			connect.HandleError(func() {
				callback(linkId)
			})
		}
	}
	if changed {
		for _, callback := range self.changeCallbacks.Get() {
			connect.HandleError(callback)
		}
	}
	if passed := self.passedForTest.Load(); passed != nil {
		(*passed)()
	}
	return next
}

// Builds link on its own goroutine: the target's binding fetched and verified, then the host's link, published unless
// the link left its target or the manager closed meanwhile. A failure waits LinkDownTimeout before the next try, and
// reports the link down.
func (self *BridgeLinkManager) build(link *bridgeLink) {
	defer self.builds.Done()
	err := self.buildLink(link)
	link.building.Store(false)
	if err != nil {
		link.retryUntilNano.Store(self.clock.Now().Add(self.settings.LinkDownTimeout).UnixNano())
		for _, callback := range self.downCallbacks.Get() {
			connect.HandleError(func() {
				callback(link.id)
			})
		}
	}
	self.wakeRun()
	if passed := self.passedForTest.Load(); passed != nil {
		(*passed)()
	}
}

// The build itself. See build.
func (self *BridgeLinkManager) buildLink(link *bridgeLink) error {
	networkId, sidecarId := func() ([]byte, []byte) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.networkId, self.sidecarId
	}()
	subject, err := connect.IdFromBytes(sidecarId)
	if err != nil || len(networkId) != bridgeRuleIdByteCount {
		return fmt.Errorf("%w: no identity to sign as", ErrBridgeLinkRefused)
	}
	clientKey, err := func() (ed25519.PublicKey, error) {
		fetchCtx, fetchCancel := context.WithCancel(self.ctx)
		defer fetchCancel()
		stop := self.clock.AfterFunc(self.settings.LinkBuildTimeout, fetchCancel)
		defer stop()
		signedBinding, err := self.settings.LinkTargetKey(fetchCtx, link.target.SidecarId, link.target.ClientId)
		if err != nil {
			return nil, fmt.Errorf("%w: the target's binding was not fetched", ErrBridgeLinkRefused)
		}
		return verifyBridgeTargetBinding(signedBinding, link.target, networkId)
	}()
	if err != nil {
		return err
	}
	linkCtx, linkCancel := context.WithCancel(self.ctx)
	built := &bridgeLinkBuilt{
		link:            link,
		manager:         self,
		ctx:             linkCtx,
		cancel:          linkCancel,
		builtAt:         self.clock.Now(),
		networkId:       networkId,
		sidecarId:       sidecarId,
		targetClientKey: clientKey,
	}
	client, err := self.host.NewBridgeLink(
		context.WithValue(linkCtx, bridgeLinkContextKey{}, built),
		link.target.ClientId,
		subject,
		nil,
		built.sign,
	)
	if err == nil && client == nil {
		err = fmt.Errorf("%w: the host built no client", ErrBridgeLinkRefused)
	}
	if err != nil {
		linkCancel()
		return err
	}
	// a multi client routes what its policy drops to its local NAT with the bypass on, which would dial a bridged
	// destination on the physical network (plan-BRIDGE-small-readings #3)
	client.SetLocalSecurityBypass(false)
	built.client = client
	testHookBarrier("bridge_link.publish.before", "")
	published := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || link.retired.Load() {
			return false
		}
		link.built.Store(built)
		return true
	}()
	testHookBarrier("bridge_link.publish.after", "")
	if !published {
		built.close()
	}
	return nil
}

// Closes the host's client and ends the build's context, which stops its window clients' signing. On the manager's
// goroutine or a build's, outside every lock.
func (self *bridgeLinkBuilt) close() {
	self.client.Close()
	self.cancel()
}

// The link's sign for its host (§10's BridgeHost.NewBridgeLink): one window client's delegation, from this network and
// this sidecar to the target, until notAfter, the window client's strict_exp, signed by the sidecar role. A window
// client with no strict_exp, or a key that is no Ed25519 key, gets none, so it opens no contract.
func (self *bridgeLinkBuilt) sign(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error) {
	if self.ctx.Err() != nil {
		return nil, fmt.Errorf("%w: the link closed", ErrBridgeLinkRefused)
	}
	if len(windowClientPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: a window client key of %d bytes", ErrBridgeLinkRefused, len(windowClientPublicKey))
	}
	if notAfter.IsZero() {
		return nil, fmt.Errorf("%w: a window client with no strict_exp", ErrBridgeLinkRefused)
	}
	delegation := &bridge.WindowDelegation{
		NetworkId:             bytes.Clone(self.networkId),
		SubjectSidecarId:      bytes.Clone(self.sidecarId),
		WindowClientId:        windowClientId.Bytes(),
		WindowClientPublicKey: bytes.Clone(windowClientPublicKey),
		TargetSidecarId:       self.link.target.SidecarId.Bytes(),
		NotAfterMs:            notAfter.UnixMilli(),
	}
	signed, err := self.manager.settings.LinkSign(self.ctx, delegation)
	if err != nil {
		return nil, errors.Join(ErrBridgeLinkRefused, err)
	}
	if len(signed) == 0 {
		return nil, fmt.Errorf("%w: the signer returned no delegation", ErrBridgeLinkRefused)
	}
	for {
		held := self.notAfterMs.Load()
		if notAfter.UnixMilli() <= held || self.notAfterMs.CompareAndSwap(held, notAfter.UnixMilli()) {
			break
		}
	}
	return signed, nil
}

// connect.ContractDestinationCheckFunction for every window client of the build: the contract's destination must be
// the target's client, and its stored key the one the target's verified binding names. A refusal marks the link
// down. Inline on connect's contract paths: compares, one atomic store and a wake that never blocks.
func (self *bridgeLinkBuilt) destinationAllowed(destinationId connect.Id, destinationClientPublicKey []byte) bool {
	if destinationId == self.link.target.ClientId && bytes.Equal(destinationClientPublicKey, self.targetClientKey) {
		return true
	}
	self.refuse()
	return false
}

// A contract status of a window client: any refusal of a contract marks the link down (#15).
func (self *bridgeLinkBuilt) contractStatus(status *connect.ContractStatus) {
	if status != nil && status.Error != nil {
		self.refuse()
	}
}

// An encryption event of a window client: a sealed session with the target, or a verified failure of its identity,
// which marks the link down. A failed establishment alone waits for the connect timeout.
func (self *bridgeLinkBuilt) encryptionEvent(event *connect.EncryptionEvent) {
	if event == nil || event.PeerId != self.link.target.ClientId {
		return
	}
	switch event.Type {
	case connect.EncryptionEventSealed:
		self.sealed.Store(true)
	case connect.EncryptionEventIdentityFailed, connect.EncryptionEventKeyIdentityRejected:
		self.refuse()
	}
}

// Notes a refusal for run to report, never blocking: callers include a client's own callbacks.
func (self *bridgeLinkBuilt) refuse() {
	self.refused.Store(true)
	self.manager.wakeRun()
}

// The links open and building now, for a status.
func (self *BridgeLinkManager) counts() (openCount int, buildingCount int) {
	for _, link := range *self.links.Load() {
		if link.built.Load() != nil {
			openCount += 1
		}
		if link.building.Load() || link.buildWanted.Load() {
			buildingCount += 1
		}
	}
	return openCount, buildingCount
}

// Checks signedBinding, the target's SignedSidecarIdentityBinding as its host fetched it, against what the rules pin,
// and answers the client key it binds: both messages canonical with nothing unknown, the body naming this network,
// the target's sidecar and client and the pinned identity key, a distinct 32-byte client key, a generation and a time,
// and both signatures over the body as received, the ClientKey's under binding-client and the identity key's under
// binding-identity. These are the root's VerifySidecarIdentityBinding checks with the pin applied; this package may
// not import the root (§4.4).
func verifyBridgeTargetBinding(signedBinding []byte, target BridgeLinkTarget, networkId []byte) (ed25519.PublicKey, error) {
	fault := func(what string) error {
		return fmt.Errorf("%w: %s", ErrBridgeLinkTargetUnverified, what)
	}
	if len(signedBinding) == 0 || bridgeBindingMaxByteCount < len(signedBinding) {
		return nil, fault("its size")
	}
	canonical := func(message proto.Message, encoded []byte) bool {
		if len(message.ProtoReflect().GetUnknown()) != 0 {
			return false
		}
		remarshalled, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		return err == nil && bytes.Equal(remarshalled, encoded)
	}
	signed := &bridge.SignedSidecarIdentityBinding{}
	if proto.Unmarshal(signedBinding, signed) != nil || !canonical(signed, signedBinding) {
		return nil, fault("it does not decode canonically")
	}
	body := &bridge.SidecarIdentityBinding{}
	if proto.Unmarshal(signed.GetBody(), body) != nil || !canonical(body, signed.GetBody()) {
		return nil, fault("its body does not decode canonically")
	}
	if !bytes.Equal(body.GetNetworkId(), networkId) {
		return nil, fault("another network")
	}
	if !bytes.Equal(body.GetSidecarId(), target.SidecarId.Bytes()) || !bytes.Equal(body.GetClientId(), target.ClientId.Bytes()) {
		return nil, fault("another sidecar or client")
	}
	if !bytes.Equal(body.GetIdentityPublicKey(), target.IdentityPublicKey[:]) {
		return nil, fault("an identity key other than the pinned one")
	}
	if len(body.GetClientPublicKey()) != ed25519.PublicKeySize || bytes.Equal(body.GetClientPublicKey(), body.GetIdentityPublicKey()) {
		return nil, fault("its client key")
	}
	if body.GetGeneration() < 1 || body.GetIssuedAtMs() <= 0 {
		return nil, fault("its generation or time")
	}
	clientSignedBytes := bridge.SignedBytes(bridgeBindingClientPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, signed.GetBody())
	if !ed25519.Verify(body.GetClientPublicKey(), clientSignedBytes, signed.GetClientSignature()) {
		return nil, fault("the ClientKey's signature")
	}
	identitySignedBytes := bridge.SignedBytes(bridgeBindingIdentityPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, signed.GetBody())
	if !ed25519.Verify(target.IdentityPublicKey[:], identitySignedBytes, signed.GetIdentitySignature()) {
		return nil, fault("the identity key's signature")
	}
	return ed25519.PublicKey(bytes.Clone(body.GetClientPublicKey())), nil
}
