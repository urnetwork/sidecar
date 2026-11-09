// device.Bridge (§17.10, D-SDK-20): one network's bridge on one device, the keyless device role's half of §17. It
// satisfies §18.6's deviceBridge: the sender's router (bridge_route.go) over its table and pins (bridge_table.go,
// bridge_pin*.go) and its links (bridge_link*.go, through a BridgeHost), the route export (bridge_export.go), the
// provider hook (bridge_egress*.go) and the zone.
//
// It embeds the posture (posture.go), so §17.8's states are one machine with §18.6's (D-SDK-13, D-BRIDGE-18): what is
// in force is what the posture decided, and the bridge turns that decision into what it enforces (bridge_state.go). A
// state's rules are parsed once, when the bridge adopts the decision, off the packet path; rules that do not parse are
// held as none and alarm, which opens nothing.
//
// The constructor restores the posture from its store and publishes its decision to the provider hook before it
// returns, so the first packet meets what was in force (DP1), and starts run, which watches the clock for the next time
// a row's meaning changes, an expiry, the end of a drain, the end of the previous block's drain, and publishes again
// then, ending the flows of what lapsed.
//
// A Bridge is safe for concurrent use. Status reads a snapshot; nothing here blocks a packet.

package device

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One network's bridge. See the file's comment.
type Bridge struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *BridgeSettings
	clock    Clock
	host     BridgeHost
	posture  *Posture
	// the sender's pins, for every entry this bridge routes
	pins *BridgePinTable
	// the sender's links, its reject client and what Route hands the resolver's queries, and what Route reads, which
	// every adoption rebuilds
	links      *BridgeLinkManager
	reject     *BridgeRejectClient
	resolver   connect.UserNatClient
	routeState atomic.Pointer[bridgeRouteState]
	// removes the bridge's callbacks from its link manager
	linkCallbackRemovals []func()
	// the provider hook, the one value EgressHook returns, and the NATs it is installed on, which CloseFlows reaches
	policy          *BridgeEgressPolicy
	hook            *bridgeEgressHook
	closers         *connect.CallbackList[connect.EgressFlowCloser]
	changeCallbacks *connect.CallbackList[func()]

	// the next time a row's meaning changes, zero for none; run waits on it
	deadline *connect.MonitorValue[time.Time]
	// closed when run returns
	done chan struct{}

	// serializes what publishes, a posture call with its adoption, a revocation and a check of the clock, so the hook's
	// states follow the posture's decisions in order; held across the posture's store I/O, never by a packet path
	operationLock sync.Mutex
	// Revoke's narrowing, each held until a state at or past its position; under operationLock
	revocations []PostureOverlayEntry
	// when the hook's state was last published; under operationLock
	publishedAt time.Time
	// under operationLock: this device's local addresses, nil while unknown (SetLocalAddresses); each link entry's
	// pins by prefix, and the exits'; the entries held as rejects, since they lost their last advertiser; and the
	// overlay's drained rule ids, since the bridge first saw each
	localAddrs        []netip.Addr
	entryStates       map[netip.Prefix]*BridgeEntryState
	egressState       *BridgeEntryState
	heldRejects       map[netip.Prefix]time.Time
	overlayDrainSince map[string]time.Time

	stateLock sync.Mutex
	// the posture's decision the bridge last adopted
	decision PostureDecision
	// the rules of decision's state, parsed; nil for none, refused ones included
	rules  *bridge.BridgeRules
	alarms []BridgeAlarm
	// what the last check of the clock found
	drainingCount int
	expiredCount  int
	// what the last build of the route state found
	routeFindings bridgeRouteFindings
	egressMode    bridge.BridgeEgressMode
}

// Restores the posture from store and publishes its decision before it returns, then starts run. host builds links and
// may be nil, as on a device that runs none. Nil settings are DefaultBridgeSettings.
func NewBridge(ctx context.Context, store PostureStore, host BridgeHost, settings *BridgeSettings) (*Bridge, error) {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	err := settings.validate()
	if err != nil {
		return nil, err
	}
	posture, decision := NewPosture(store, settings.PostureSettings)
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Bridge{
		ctx:               cancelCtx,
		cancel:            cancel,
		settings:          settings,
		clock:             settings.clock(),
		host:              host,
		posture:           posture,
		pins:              NewBridgePinTable(settings),
		links:             NewBridgeLinkManager(cancelCtx, host, settings),
		reject:            NewBridgeRejectClient(nil, settings),
		policy:            NewBridgeEgressPolicy(settings.PolicyProfile, settings),
		closers:           connect.NewCallbackList[connect.EgressFlowCloser](),
		changeCallbacks:   connect.NewCallbackList[func()](),
		deadline:          connect.NewMonitorValue(time.Time{}),
		done:              make(chan struct{}),
		entryStates:       map[netip.Prefix]*BridgeEntryState{},
		heldRejects:       map[netip.Prefix]time.Time{},
		overlayDrainSince: map[string]time.Time{},
	}
	// the resolver answers at BRIDGE-M4-14: until then a query to <block>.0.53 is refused as any service address is
	self.resolver = self.reject
	self.hook = &bridgeEgressHook{BridgeEgressPolicy: self.policy, bridge: self}
	self.linkCallbackRemovals = []func(){
		self.links.AddDownCallback(self.markLinkDown),
		self.links.AddChangeCallback(self.relink),
	}
	// no hook is installed yet, so no flow exists to end
	func() {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		self.adoptWithLock(decision, true)
	}()
	go self.run()
	return self, nil
}

// Stops run and waits for it, then closes the links. The posture's store is the caller's.
func (self *Bridge) Close() {
	self.cancel()
	<-self.done
	for _, remove := range self.linkCallbackRemovals {
		remove()
	}
	self.links.Close()
}

// Where packets the bridge answers itself enter the tun: rejects (§17.5's rejects row) and, under `ur tun`, the
// resolver's replies (§17.10). receive borrows each packet; nil drops them, a reject counting as unsent. The sdk's
// DeviceLocal and the CLI set it to their tun's write.
func (self *Bridge) SetReceivePacket(receive connect.ReceivePacketFunction) {
	self.reject.SetReceive(receive)
}

// Rebuilds what Route reads after the link manager changed a target's links: a rebuild replaced one, or one drained.
func (self *Bridge) relink() {
	self.apply(func() (PostureDecision, bool, error) {
		return self.posture.Decision(), false, nil
	})
}

// Waits for the next time a row's meaning changes, and publishes again then, until the bridge closes.
func (self *Bridge) run() {
	defer close(self.done)
	for {
		deadline, update := self.deadline.Get()
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timeout = self.clock.After(deadline.Sub(self.clock.Now()))
		}
		select {
		case <-self.ctx.Done():
			return
		case <-update:
		case <-timeout:
			self.refresh()
		}
	}
}

// What the bridge has in force and what it found, at the last adoption or check of the clock. Counts the live pins by
// a scan, so call it off the packet path.
func (self *Bridge) Status() BridgeStatus {
	pinnedPairCount := self.pins.PinnedCount()
	verifiedCount, mismatchCount := self.policy.principalCounts()
	linkOpenCount, linkBuildingCount := self.links.counts()
	rejectSentCount, rejectUnsentCount := self.reject.Counts()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := BridgeStatus{
		State:                  self.decision.State,
		PolicyProfile:          self.policy.Profile(),
		PolicyGeneration:       self.policy.PolicyGeneration(),
		PrincipalVerifiedCount: verifiedCount,
		DrainingCount:          self.drainingCount,
		ExpiredCount:           self.expiredCount,
		PinnedPairCount:        pinnedPairCount,
		UnpinnedPickCount:      self.pins.UnpinnedPickCount(),
		LinkOpenCount:          linkOpenCount,
		LinkBuildingCount:      linkBuildingCount,
		RejectSentCount:        rejectSentCount,
		RejectUnsentCount:      rejectUnsentCount,
		HeldRejectCount:        self.routeFindings.heldCount,
		RouteConflictCount:     self.routeFindings.conflictCount,
		EgressMode:             self.egressMode,
		PostureAlarms:          append([]PostureAlarm(nil), self.decision.Alarms...),
		Alarms:                 append([]BridgeAlarm(nil), self.alarms...),
	}
	if 0 < self.routeFindings.carvedAddressCount {
		status.Alarms = append(status.Alarms, BridgeAlarm{
			Kind:   BridgeAlarmCarvedAddress,
			Reason: "a local address the physical path needs is a host's overlay address; cycle the block",
		})
	}
	if 0 < self.routeFindings.conflictCount {
		status.Alarms = append(status.Alarms, BridgeAlarm{
			Kind:   BridgeAlarmRouteConflict,
			Reason: "subnet routes overlapping a local network were dropped",
		})
	}
	if 0 < linkBuildingCount {
		status.Waits = append(status.Waits, BridgeWait{Kind: BridgeWaitLink, Count: linkBuildingCount})
	}
	if 0 < mismatchCount {
		status.Alarms = append(status.Alarms, BridgeAlarm{
			Kind:   BridgeAlarmPrincipalMismatch,
			Reason: "contracts refused whose sealed subject their delegation's subject does not bind",
		})
	}
	if self.decision.Pin != nil {
		status.PinN = self.decision.Pin.GetVersion()
	}
	if self.decision.BridgeState != nil {
		status.HasDocument = self.decision.BridgeState.GetHasDocument()
	}
	if self.decision.State == PosturePending {
		status.Waits = append(status.Waits, BridgeWait{Kind: BridgeWaitState, Count: 1})
	}
	rules := self.rules
	if rules == nil {
		return status
	}
	if block, ok := bridgeRulePrefix(rules.GetBlock()); ok {
		status.Block = block
	}
	if previousBlock, ok := bridgeRulePrefix(rules.GetPreviousBlock()); ok {
		status.PreviousBlock = previousBlock
		status.PreviousBlockDrainUntil = time.UnixMilli(rules.GetPreviousBlockDrainUntil())
	}
	for _, address := range rules.GetAddresses() {
		status.Addresses = append(status.Addresses, bridgeRuleAddr(address))
	}
	status.EntryCount = len(rules.GetEntries())
	status.MapCount = len(rules.GetMaps())
	status.ServedCount = len(rules.GetServed())
	status.SubjectCount = len(rules.GetSubjects())
	return status
}

// What scanBridgeRulesTimes finds at one moment.
type bridgeRulesTimes struct {
	drainingCount int
	expiredCount  int
	// the earliest time after the moment at which a row's meaning changes; zero for none
	next time.Time
}

// When a drain that started at drainingSince and runs to drainUntil ends: no sooner than §17.5's idles allow a pair
// or flow it serves, from its start (the removed row's max(drain_seconds, 600 s) and max(drain_seconds, 5 min)).
func bridgeDrainEnd(drainingSince int64, drainUntil int64, settings *BridgeSettings) time.Time {
	end := time.UnixMilli(drainingSince).Add(max(settings.PinTcpIdleTimeout, settings.PinIdleTimeout))
	if until := time.UnixMilli(drainUntil); until.After(end) {
		end = until
	}
	return end
}

// Reads every row whose meaning depends on the time: what drains at now, what expired by now, and when the next such
// change falls.
func scanBridgeRulesTimes(rules *bridge.BridgeRules, now time.Time, settings *BridgeSettings) bridgeRulesTimes {
	times := bridgeRulesTimes{}
	if rules == nil {
		return times
	}
	at := func(when time.Time) bool {
		if when.After(now) {
			if times.next.IsZero() || when.Before(times.next) {
				times.next = when
			}
			return false
		}
		return true
	}
	expires := func(expiresMs int64) {
		if expiresMs != 0 && at(time.UnixMilli(expiresMs)) {
			times.expiredCount += 1
		}
	}
	drains := func(drainingSince int64, drainUntil int64) {
		if drainingSince == 0 {
			return
		}
		if at(bridgeDrainEnd(drainingSince, drainUntil, settings)) {
			times.expiredCount += 1
		} else {
			times.drainingCount += 1
		}
	}
	if rules.GetPreviousBlock() != nil {
		if at(time.UnixMilli(rules.GetPreviousBlockDrainUntil())) {
			times.expiredCount += 1
		} else {
			times.drainingCount += 1
		}
	}
	for _, entry := range rules.GetEntries() {
		for _, link := range entry.GetLinks() {
			drains(link.GetDrainingSince(), link.GetDrainUntil())
		}
	}
	for _, ruleMap := range rules.GetMaps() {
		expires(ruleMap.GetExpires())
		drains(ruleMap.GetDrainingSince(), ruleMap.GetDrainUntil())
	}
	for _, served := range rules.GetServed() {
		drains(served.GetDrainingSince(), served.GetDrainUntil())
	}
	for _, subject := range rules.GetSubjects() {
		for _, rows := range [][]*bridge.BridgeRuleReach{subject.GetDial(), subject.GetRoute(), subject.GetExit()} {
			for _, reach := range rows {
				expires(reach.GetExpires())
			}
		}
	}
	if egress := rules.GetEgress(); egress != nil {
		for _, link := range egress.GetExits() {
			drains(link.GetDrainingSince(), link.GetDrainUntil())
		}
	}
	return times
}
