//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §17.7.1's discovery on a ur daemon host (owner decision 778, D-BRIDGE-22 to D-BRIDGE-25): the Sidecar's
// "bridge-discovery" component, beside its bridge. One network's host and viewer:
//
//	host      run, started at construction, recomputes what the host publishes (bridge_discovery_host.go) at each
//	          gatherer report, setting, share, change of the device role's state and expiry, and runs the gatherer
//	          while the host serves and a watch or its person's own view asked within GatherDemandTimeout, so the LAN
//	          is queried on demand (RFC 8766 §1)
//	watch     each generation's dispatcher serves DNS_SD_WATCH, which §6's step 6 refuses on the control class, so a
//	          viewer asks only a host §8.10's reach(viewer, host) admits; the answer holds while the view equals since,
//	          up to the asked hold and WatchHoldTimeout, and carries what the hook passes for the viewer
//	viewer    while this device runs ur tun or the advertising proxy (Viewing), each generation watches the hosts its
//	          own rules reach, its own member's first, at most WatchHostCount, calling again at once after each answer;
//	          it keeps an instance only at an address its host serves by the config, a /32 of the host or a prefix or
//	          exposed prefix it advertises, and only where its own router sends that address to the host, a LAN prefix
//	          of its own winning; it withdraws a host's instances once its watch has failed for HostLossTimeout, at
//	          each TTL's end, at an answer that drops them and at a compile whose rows no longer reach them, and asks a
//	          host that answered serving false again after NotServingRetryInterval
//
// The view goes to OnView whole at each change, for ur tun's resolver (device.Bridge.SetDiscoveryView, §12.9.1) and the
// advertising proxy (cli/). Logs name opaque ids and counts, never a name, a type or an address (I-13).
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// The component's name among a Sidecar's components, its keychain namespace and its store's directory.
const bridgeDiscoveryComponentName = "bridge-discovery"

// What the component reaches of a generation's dispatcher: a *Subprotocol, which a test fakes.
type bridgeDiscoveryDispatcher interface {
	Handle(messageType protocol.MessageType, handler SubprotocolHandler, options *HandleOptions) (remove func(), err error)
	EnsureHello(ctx context.Context, clientId Id) error
	PeerIdentity(clientId Id) (*SubprotocolPeerIdentity, bool)
	Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error)
}

// One instance a viewer keeps, as its resolver and advertising proxy take it.
type BridgeDiscoveryViewInstance struct {
	// The host that answered it, and its private name, which the target sits below.
	HostSidecarId Id
	HostName      string
	Name          string
	Service       string
	Subtypes      []string
	Port          uint16
	Txt           []byte
	// The target's own label under the host's name.
	HostLabel string
	// Where this device reaches it.
	Address netip.Addr
	// The host's own service.
	Own     bool
	Expires time.Time
}

// What the component is built over. Every function may be nil, and each missing one fails closed as its comment says.
type BridgeDiscoveryArgs struct {
	NetworkId Id
	// This sidecar, and its member, zero for a tagged sidecar, whose hosts a viewer watches first.
	SidecarId Id
	MemberId  Id
	// What discovery reads of the device role's state in force, nil before one: nil publishes and watches nothing.
	Routes func() *BridgeDiscoveryRoutes
	// Hears each change of the device role's state; its answer removes the callback. Nil hears none, so only the
	// component's own timers refresh what it reads.
	AddRoutesCallback func(callback func()) func()
	// The hook's verdict (device.Bridge.DiscoveryReach): nil answers every viewer with no instance.
	Reach BridgeDiscoveryReachFunction
	// The hook's generation (device.Bridge's policy generation), which a host's version follows. Nil reads 0, and the
	// version then follows what it publishes alone.
	ReachGeneration func() uint64
	// The advertisers this device's router sends an address to (device.Bridge.RouteTargets): nil keeps no instance.
	RouteTargets func(address netip.Addr) []Id
	// The ACL document's discovery block, from the network's local policy; nil, or a nil answer, is the default list.
	DiscoveryBlock func() *AclDiscoveryBlock
	// This host's own label, which its own instances' targets take; nil or empty publishes no listed entry, and an own
	// instance takes its mDNS host name's.
	HostLabel func() string
	// The gatherer: nil gathers nothing, so the host publishes nothing but listed entries.
	Gatherer BridgeDiscoveryGatherer
	// The listeners' listed set, M13a's (bridge_discovery_listed.go): nil lists nothing.
	Listed func() []*BridgeDiscoveryListedEntry
	// Whether this device runs ur tun or the advertising proxy now: nil watches nothing (§17.7.1's viewer row).
	Viewing func() bool
	// Takes the whole view at each change, on the component's goroutine; it must not block. Nil drops it.
	OnView func(view []*BridgeDiscoveryViewInstance)
	// The filings a share makes (bridge_discovery_share.go): nil refuses every share.
	Filer BridgeDiscoveryFiler
	// What the platform's advertising proxy holds, for ur bridge devices; nil shows none.
	ProxyStatus func() *BridgeDiscoveryProxyStatus
	Clock       Clock
	Log         Logger
	// Nil is DefaultBridgeDiscoverySettings.
	Settings *BridgeDiscoverySettings
}

// What a viewer holds of one host: its last answer and when it came.
type bridgeDiscoveryHostAnswer struct {
	host      BridgeDiscoveryHost
	instances []*protocol.DnsSdInstance
	received  time.Time
}

// One network's discovery. See the file's comment.
type BridgeDiscoveryComponent struct {
	args     *BridgeDiscoveryArgs
	settings *BridgeDiscoverySettings
	clock    Clock
	log      Logger
	ctx      context.Context
	cancel   context.CancelFunc
	// closed when run returns
	done chan struct{}
	// wakes run; buffered one
	wake chan struct{}
	// wakes each generation's viewer; one channel swapped at each poke
	viewWake *connect.Monitor
	// the host's view the watch handler waits on; never nil after construction
	hostView *connect.MonitorValue[*bridgeDiscoveryHostView]
	// removes the routes callback
	removeRoutesCallback func()

	stateLock sync.Mutex
	// the sealed settings, nil until the first generation's store reads; the store
	state    *bridgeDiscoveryState
	stateErr error
	store    SidecarStore
	gathered []*BridgeDiscoveryGathered
	// until when a watch served, and the person's own view, keep the gatherer running; whether it runs
	watchDemandEnd time.Time
	viewDemandEnd  time.Time
	gatherRunning  bool
	// each host's last answer, and how many of its instances the checks dropped
	answers      map[Id]*bridgeDiscoveryHostAnswer
	droppedCount map[Id]int
	// the view last handed out
	view []*BridgeDiscoveryViewInstance
	// the instances the advertising proxy holds now, which keeps the gatherer running for the names rule
	closed bool
}

// The component over args, its host loop running until Close. args.Settings must validate.
func NewBridgeDiscoveryComponent(args *BridgeDiscoveryArgs) (*BridgeDiscoveryComponent, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: discovery needs its args", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultBridgeDiscoverySettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	self := &BridgeDiscoveryComponent{
		args:         args,
		settings:     settings,
		clock:        clock,
		log:          loggerOrDefault(args.Log),
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		wake:         make(chan struct{}, 1),
		viewWake:     connect.NewMonitor(),
		hostView:     connect.NewMonitorValue[*bridgeDiscoveryHostView](&bridgeDiscoveryHostView{version: 1}),
		answers:      map[Id]*bridgeDiscoveryHostAnswer{},
		droppedCount: map[Id]int{},
	}
	if args.AddRoutesCallback != nil {
		self.removeRoutesCallback = args.AddRoutesCallback(func() {
			self.poke()
			self.viewWake.NotifyAll()
		})
	}
	go self.run()
	return self, nil
}

// See SidecarComponent.
func (self *BridgeDiscoveryComponent) Name() string {
	return bridgeDiscoveryComponentName
}

// Serves the watch on the generation's dispatcher and, while Viewing, watches from it, until env.Ctx ends. The first
// generation's store holds the sealed settings. See SidecarComponent.
func (self *BridgeDiscoveryComponent) Attach(env *SidecarEnv) error {
	if env == nil || env.Subprotocol == nil {
		return errors.New("discovery needs the generation's dispatcher")
	}
	self.loadState(env.Store)
	return self.attach(env.Ctx, env.Subprotocol)
}

// Attach on a dispatcher, which a test fakes.
func (self *BridgeDiscoveryComponent) attach(ctx context.Context, dispatcher bridgeDiscoveryDispatcher) error {
	remove, err := dispatcher.Handle(protocol.MessageType_DNS_SD_WATCH, self.handleWatch, nil)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, remove)
	go self.viewer(ctx, dispatcher)
	return nil
}

// Ends the host loop and every watch. See SidecarComponent.
func (self *BridgeDiscoveryComponent) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	if self.removeRoutesCallback != nil {
		self.removeRoutesCallback()
	}
	self.cancel()
	<-self.done
}

// Reads the sealed settings from store once; a file that does not read leaves the defaults with sharing refused.
func (self *BridgeDiscoveryComponent) loadState(store SidecarStore) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state != nil || self.stateErr != nil {
		return
	}
	self.store = store
	self.state, self.stateErr = readBridgeDiscoveryState(store)
	if self.stateErr != nil {
		self.log.Warningf("[discovery]the sealed settings do not read; sharing stays stopped: %v", self.stateErr)
	}
	self.pokeWithLock()
}

// The settings in force: the sealed file's, or defaults, with no share, while it does not read or before the first
// generation. Called with stateLock held.
func (self *BridgeDiscoveryComponent) stateWithLock() *bridgeDiscoveryState {
	if self.state == nil {
		return newBridgeDiscoveryState()
	}
	return self.state
}

// Wakes run.
func (self *BridgeDiscoveryComponent) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Wakes run; the wake channel needs no lock, so this is poke under its name for callers holding stateLock.
func (self *BridgeDiscoveryComponent) pokeWithLock() {
	self.poke()
}

// Tells the viewers that Viewing may have changed: ur tun started or stopped, or the proxy was switched.
func (self *BridgeDiscoveryComponent) ViewingChanged() {
	self.viewWake.NotifyAll()
	self.poke()
}

// Keeps the gatherer running for GatherDemandTimeout: a watch served, while the host serves, or the person's own view
// asked, whatever the host publishes, since the person picks a device to share from it.
func (self *BridgeDiscoveryComponent) demand(person bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	end := self.clock.Now().Add(self.settings.GatherDemandTimeout)
	held := &self.watchDemandEnd
	if person {
		held = &self.viewDemandEnd
	}
	if held.Before(end) {
		*held = end
	}
	self.pokeWithLock()
}

// The effective list of types now.
func (self *BridgeDiscoveryComponent) types() []string {
	var block *AclDiscoveryBlock
	if self.args.DiscoveryBlock != nil {
		block = self.args.DiscoveryBlock()
	}
	return BridgeDiscoveryEffectiveTypes(block)
}

// What the host's publishing reads now.
func (self *BridgeDiscoveryComponent) hostInput() *bridgeDiscoveryHostInput {
	input := &bridgeDiscoveryHostInput{types: self.types()}
	if self.args.Routes != nil {
		input.routes = self.args.Routes()
	}
	if self.args.Listed != nil {
		input.listed = self.args.Listed()
	}
	if self.args.HostLabel != nil {
		input.hostLabel = self.args.HostLabel()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	input.gathered = self.gathered
	input.state = self.stateWithLock().clone()
	return input
}

// Whether a host serves: it would publish something, its own services, a listed entry or a share, whatever its LAN
// holds this moment (§12.9.1's serving).
func bridgeDiscoveryServes(input *bridgeDiscoveryHostInput) bool {
	if input.routes == nil || input.state == nil {
		return false
	}
	if input.routes.hostAddress().IsValid() && !input.state.OwnOff && !input.state.HiddenDevice {
		return true
	}
	return slices.ContainsFunc(input.state.Shares, func(share *bridgeDiscoveryShare) bool {
		return share.State == bridgeDiscoveryShareActive
	})
}

// The host loop (the file's host row): recomputes what the host publishes at each wake and the next expiry, and runs
// the gatherer on demand, until Close.
func (self *BridgeDiscoveryComponent) run() {
	defer close(self.done)
	var gatherCancel context.CancelFunc
	var gatherTypes []string
	setRunning := func(running bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.gatherRunning = running
	}
	stopGather := func() {
		if gatherCancel != nil {
			gatherCancel()
			gatherCancel = nil
			gatherTypes = nil
			setRunning(false)
		}
	}
	defer stopGather()
	for {
		now := self.clock.Now()
		input, serving, published := self.refresh(now)
		self.upkeepShares(input, now)

		// the gatherer runs while a watch of a serving host asked, the person's own view asked, or the viewer keeps
		// remote instances whose names the advertising proxy holds against the LAN's (Q-BRIDGE-11)
		wantGather := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.args.Gatherer != nil &&
				((serving && now.Before(self.watchDemandEnd)) || now.Before(self.viewDemandEnd) || 0 < len(self.view))
		}()
		switch {
		case wantGather && !slices.Equal(gatherTypes, input.types):
			stopGather()
			gatherCtx, cancel := context.WithCancel(self.ctx)
			gatherCancel = cancel
			gatherTypes = input.types
			go self.args.Gatherer.Gather(gatherCtx, slices.Clone(input.types), self.gatheredReport(gatherCtx))
			setRunning(true)
		case !wantGather:
			stopGather()
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.gathered = nil
			}()
		}

		// the next time something here lapses: an expiry, the demand's end, the shares' upkeep, a listed TTL's renewal
		next := now.Add(self.settings.ShareUpkeepInterval)
		next = bridgeDiscoveryEarlier(next, now.Add(self.settings.ListedTtl/2))
		for _, item := range published {
			next = bridgeDiscoveryEarlier(next, item.expires)
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, end := range []time.Time{self.watchDemandEnd, self.viewDemandEnd} {
				if now.Before(end) {
					next = bridgeDiscoveryEarlier(next, end)
				}
			}
		}()
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-self.clock.After(max(next.Sub(now), time.Millisecond)):
		}
	}
}

// Recomputes what the host publishes at now and swaps it in where it moved; answers what it read and published.
func (self *BridgeDiscoveryComponent) refresh(now time.Time) (*bridgeDiscoveryHostInput, bool, []*bridgeDiscoveryPublished) {
	input := self.hostInput()
	serving := bridgeDiscoveryServes(input)
	published := bridgeDiscoveryPublish(input, now, self.settings)
	if !serving {
		published = nil
	}
	self.publish(serving, published)
	return input, serving, published
}

// Whether the host's own inputs stand: its sealed settings read and the device role's state in force. Until they do a
// watch is answered UNAVAILABLE, which a viewer retries soon, never serving false, which it would not ask again for
// NotServingRetryInterval.
func (self *BridgeDiscoveryComponent) settled() bool {
	if self.args.Routes == nil || self.args.Routes() == nil {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state != nil && self.stateErr == nil
}

// The earlier of a and b.
func bridgeDiscoveryEarlier(a time.Time, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// The gatherer's report, which keeps each snapshot while gatherCtx stands and wakes run.
func (self *BridgeDiscoveryComponent) gatheredReport(gatherCtx context.Context) func(gathered []*BridgeDiscoveryGathered) {
	return func(gathered []*BridgeDiscoveryGathered) {
		if gatherCtx.Err() != nil {
			return
		}
		snapshot := make([]*BridgeDiscoveryGathered, 0, len(gathered))
		for _, item := range gathered {
			if item != nil {
				held := *item
				snapshot = append(snapshot, &held)
			}
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.gathered = snapshot
		self.pokeWithLock()
	}
}

// Swaps in a new host view where what it publishes, or the hook's generation, moved, one version past the last.
func (self *BridgeDiscoveryComponent) publish(serving bool, published []*bridgeDiscoveryPublished) {
	var generation uint64
	if self.args.ReachGeneration != nil {
		generation = self.args.ReachGeneration()
	}
	digest := bridgeDiscoveryPublishedDigest(published)
	self.hostView.Update(func(previous *bridgeDiscoveryHostView) *bridgeDiscoveryHostView {
		if previous.serving == serving && previous.generation == generation && previous.digest == digest {
			return previous
		}
		return &bridgeDiscoveryHostView{
			version:    previous.version + 1,
			serving:    serving,
			published:  published,
			generation: generation,
			digest:     digest,
		}
	})
}

// DNS_SD_WATCH's handler (the file's watch row): the view for the viewer, at once where it differs from since, else at
// its next change or the hold.
func (self *BridgeDiscoveryComponent) handleWatch(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
	if request.Peer == nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_PERMISSION_DENIED}
	}
	watch := &protocol.DnsSdWatch{}
	if err := proto.Unmarshal(request.Body, watch); err != nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT}
	}
	self.demand(false)
	if !self.settled() {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
	}
	// the view as it stands at this call, not as the host loop last left it
	self.refresh(self.clock.Now())
	wire := self.settings.wire()
	hold := min(time.Duration(watch.GetHoldMs())*time.Millisecond, wire.WatchHoldTimeout)
	view, changed := self.hostView.Get()
	if view.serving && view.version == watch.GetSince() && 0 < hold {
		timeout := self.clock.After(hold)
	wait:
		for {
			select {
			case <-ctx.Done():
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED}
			case <-self.ctx.Done():
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
			case <-timeout:
				break wait
			case <-changed:
				view, changed = self.hostView.Get()
				if !view.serving || view.version != watch.GetSince() {
					break wait
				}
			}
		}
	}
	result := bridgeDiscoveryAnswer(view, request.Peer.SidecarId, self.args.Reach, self.clock.Now(), wire)
	return proto.Marshal(result)
}

// The viewer (the file's viewer row) on one generation's dispatcher: a watch per host while Viewing, until ctx ends.
func (self *BridgeDiscoveryComponent) viewer(ctx context.Context, dispatcher bridgeDiscoveryDispatcher) {
	type watching struct {
		host   BridgeDiscoveryHost
		cancel context.CancelFunc
	}
	watchers := map[Id]*watching{}
	defer func() {
		for hostId, watcher := range watchers {
			watcher.cancel()
			self.withdrawHost(hostId)
		}
		self.rebuildView()
	}()
	for {
		changed := self.viewWake.NotifyChannel()
		hosts := self.watchHosts()
		for hostId, watcher := range watchers {
			index := slices.IndexFunc(hosts, func(host BridgeDiscoveryHost) bool { return host.SidecarId == hostId })
			if index < 0 {
				// a compile whose rows no longer reach it, or Viewing ended: withdrawn at once
				watcher.cancel()
				delete(watchers, hostId)
				self.withdrawHost(hostId)
				continue
			}
			watcher.host = hosts[index]
		}
		for _, host := range hosts {
			if _, held := watchers[host.SidecarId]; held {
				continue
			}
			watchCtx, cancel := context.WithCancel(ctx)
			watchers[host.SidecarId] = &watching{host: host, cancel: cancel}
			go self.watch(watchCtx, dispatcher, host)
		}
		// the checks again: a route the router no longer sends to a host withdraws what it held there
		next := self.rebuildView()
		var expiry <-chan time.Time
		if !next.IsZero() {
			expiry = self.clock.After(max(next.Sub(self.clock.Now()), time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-expiry:
		}
	}
}

// The hosts to watch now: the ones this device's links reach, not itself, its own member's first, then by id, at most
// WatchHostCount; none while not Viewing.
func (self *BridgeDiscoveryComponent) watchHosts() []BridgeDiscoveryHost {
	if self.args.Viewing == nil || !self.args.Viewing() || self.args.Routes == nil {
		return nil
	}
	routes := self.args.Routes()
	if routes == nil {
		return nil
	}
	hosts := []BridgeDiscoveryHost{}
	for _, host := range routes.Hosts {
		if host.SidecarId != self.args.SidecarId && host.SidecarId != (Id{}) && host.ClientId != (Id{}) {
			hosts = append(hosts, host)
		}
	}
	own := func(host BridgeDiscoveryHost) bool {
		return self.args.MemberId != (Id{}) && host.MemberId == self.args.MemberId
	}
	slices.SortStableFunc(hosts, func(a BridgeDiscoveryHost, b BridgeDiscoveryHost) int {
		if own(a) != own(b) {
			if own(a) {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.SidecarId.Bytes(), b.SidecarId.Bytes())
	})
	if self.settings.WatchHostCount < len(hosts) {
		hosts = hosts[:self.settings.WatchHostCount]
	}
	return hosts
}

// One host's watch (the file's viewer row): calls again at once after each answer, backs off after a failure,
// withdraws its instances once it has failed for HostLossTimeout, and waits NotServingRetryInterval after serving false.
func (self *BridgeDiscoveryComponent) watch(ctx context.Context, dispatcher bridgeDiscoveryDispatcher, host BridgeDiscoveryHost) {
	since := uint64(0)
	lastAnswer := self.clock.Now()
	retry := self.settings.WatchRetryInterval
	wait := func(timeout time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-self.clock.After(timeout):
			return true
		}
	}
	for ctx.Err() == nil {
		result, err := self.callWatch(ctx, dispatcher, host, since)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if self.settings.HostLossTimeout <= self.clock.Now().Sub(lastAnswer) {
				self.withdrawHost(host.SidecarId)
				self.viewWake.NotifyAll()
			}
			if !wait(retry) {
				return
			}
			retry = min(2*retry, self.settings.WatchRetryMaxInterval)
			continue
		}
		retry = self.settings.WatchRetryInterval
		lastAnswer = self.clock.Now()
		if !result.GetServing() {
			self.withdrawHost(host.SidecarId)
			self.viewWake.NotifyAll()
			since = 0
			if !wait(self.settings.NotServingRetryInterval) {
				return
			}
			continue
		}
		since = result.GetVersion()
		self.setAnswer(host, result.GetInstances(), lastAnswer)
		self.viewWake.NotifyAll()
	}
}

// One watch call to host, its Hello first and its peer held to the host's sidecar.
func (self *BridgeDiscoveryComponent) callWatch(ctx context.Context, dispatcher bridgeDiscoveryDispatcher, host BridgeDiscoveryHost, since uint64) (*protocol.DnsSdWatchResult, error) {
	callCtx, cancel := context.WithTimeout(ctx, self.settings.WatchCallTimeout)
	defer cancel()
	if err := dispatcher.EnsureHello(callCtx, host.ClientId); err != nil {
		return nil, err
	}
	peer, ok := dispatcher.PeerIdentity(host.ClientId)
	if !ok || peer.SidecarId != host.SidecarId {
		return nil, errors.New("the host's client is another sidecar's")
	}
	body, err := proto.Marshal(&protocol.DnsSdWatch{
		Since:  since,
		HoldMs: uint32(self.settings.wire().WatchHoldTimeout / time.Millisecond),
	})
	if err != nil {
		return nil, err
	}
	response, err := dispatcher.Call(callCtx, host.ClientId, protocol.MessageType_DNS_SD_WATCH, body, &CallOptions{Timeout: self.settings.WatchCallTimeout})
	if err != nil {
		return nil, err
	}
	result := &protocol.DnsSdWatchResult{}
	if err := proto.Unmarshal(response, result); err != nil {
		return nil, err
	}
	return result, nil
}

// Holds host's answer, received at received, which the next rebuild checks.
func (self *BridgeDiscoveryComponent) setAnswer(host BridgeDiscoveryHost, instances []*protocol.DnsSdInstance, received time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers[host.SidecarId] = &bridgeDiscoveryHostAnswer{host: host, instances: instances, received: received}
}

// Drops what a host answered.
func (self *BridgeDiscoveryComponent) withdrawHost(hostId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.answers, hostId)
	delete(self.droppedCount, hostId)
}

// Rebuilds the view from the answers held (the file's checks): every instance of its shape, at an address its host
// serves by the config and the router sends to that host, whose TTL has not run out. Hands it to OnView where it
// changed, and answers the next expiry, zero for none.
func (self *BridgeDiscoveryComponent) rebuildView() time.Time {
	now := self.clock.Now()
	wire := self.settings.wire()
	answers := func() []*bridgeDiscoveryHostAnswer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		answers := make([]*bridgeDiscoveryHostAnswer, 0, len(self.answers))
		for _, answer := range self.answers {
			answers = append(answers, answer)
		}
		return answers
	}()
	var routes *BridgeDiscoveryRoutes
	if self.args.Routes != nil {
		routes = self.args.Routes()
	}
	view := []*BridgeDiscoveryViewInstance{}
	dropped := map[Id]int{}
	var next time.Time
	for _, answer := range answers {
		host := answer.host
		if routes != nil {
			// the host's routes as they stand now, not as they stood when its watch began
			if index := slices.IndexFunc(routes.Hosts, func(held BridgeDiscoveryHost) bool { return held.SidecarId == host.SidecarId }); 0 <= index {
				host = routes.Hosts[index]
			}
		}
		for _, instance := range answer.instances {
			expires := answer.received.Add(time.Duration(instance.GetTtl()) * time.Second)
			if !expires.After(now) {
				continue
			}
			address := bridgeDiscoveryAddrOf(instance.GetIpv4())
			kept := protocol.CheckDnsSdInstance(instance, wire) == nil && host.Name != "" &&
				slices.ContainsFunc(host.Prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) &&
				self.args.RouteTargets != nil && slices.Contains(self.args.RouteTargets(address), host.SidecarId)
			if !kept {
				dropped[host.SidecarId] += 1
				continue
			}
			if next.IsZero() || expires.Before(next) {
				next = expires
			}
			view = append(view, &BridgeDiscoveryViewInstance{
				HostSidecarId: host.SidecarId,
				HostName:      host.Name,
				Name:          instance.GetName(),
				Service:       strings.ToLower(instance.GetService()),
				Subtypes:      slices.Clone(instance.GetSubtypes()),
				Port:          uint16(instance.GetPort()),
				Txt:           slices.Clone(instance.GetTxt()),
				HostLabel:     strings.ToLower(instance.GetHostLabel()),
				Address:       address,
				Own:           instance.GetOwn(),
				Expires:       expires,
			})
		}
	}
	slices.SortFunc(view, func(a *BridgeDiscoveryViewInstance, b *BridgeDiscoveryViewInstance) int {
		if order := bytes.Compare(a.HostSidecarId.Bytes(), b.HostSidecarId.Bytes()); order != 0 {
			return order
		}
		return strings.Compare(a.Service+"\x00"+a.Name, b.Service+"\x00"+b.Name)
	})
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.droppedCount = dropped
		if bridgeDiscoveryViewEqual(self.view, view) {
			return false
		}
		self.view = view
		return true
	}()
	if changed && self.args.OnView != nil {
		self.args.OnView(view)
	}
	return next
}

// Whether two views hold the same instances in the same order.
func bridgeDiscoveryViewEqual(a []*BridgeDiscoveryViewInstance, b []*BridgeDiscoveryViewInstance) bool {
	return slices.EqualFunc(a, b, func(x *BridgeDiscoveryViewInstance, y *BridgeDiscoveryViewInstance) bool {
		return x.HostSidecarId == y.HostSidecarId && x.HostName == y.HostName && x.Name == y.Name &&
			x.Service == y.Service && slices.Equal(x.Subtypes, y.Subtypes) && x.Port == y.Port &&
			bytes.Equal(x.Txt, y.Txt) && x.HostLabel == y.HostLabel && x.Address == y.Address && x.Own == y.Own &&
			x.Expires.Equal(y.Expires)
	})
}

// The view this viewer keeps now: a copy the caller owns.
func (self *BridgeDiscoveryComponent) View() []*BridgeDiscoveryViewInstance {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.view)
}

// What the gatherer holds now, its LocalOnly answers included: a copy the caller owns, for the advertising proxy's
// names rule (bridge_discovery_names.go).
func (self *BridgeDiscoveryComponent) Gathered() []*BridgeDiscoveryGathered {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.gathered)
}
