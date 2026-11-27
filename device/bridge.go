// device.Bridge (§17.10, D-SDK-20): one network's bridge on one device, the keyless device role's half of §17. It
// satisfies §18.6's deviceBridge: the sender's router (bridge_route.go) over its table and pins (bridge_table.go,
// bridge_pin*.go) and its links (bridge_link*.go, through a BridgeHost), its rejects (bridge_reject.go), the route
// export (bridge_export.go), the provider hook (bridge_egress*.go), and the private names: the zone and `ur tun`'s
// resolver (bridge_zone.go, bridge_resolver.go).
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
// Those times are the wall clock's, from the signed rules, and run waits for them on a runtime timer, which stops
// while the system sleeps (mach_absolute_time on darwin, CLOCK_MONOTONIC on linux), so a device that slept past one,
// or whose clock stepped forward past one, would end those flows only when the timer's remaining awake time ran out
// (§17.8's after sleep or a clock step, owner decision 789). New flows are refused at once regardless, since the hook
// reads the wall clock for each, and revocations publish at once. Two seams keep the old flows to the rules: the
// platform calls CheckClock when the device wakes and when its clock changes, and run publishes at now and arms its
// wait again from the wall clock; and ClockCheckInterval caps the wait on a desktop, where no one wake signal reaches
// Go, so run reads the wall clock again at least that often while anything is timed. The link manager's wait takes
// both, for a replaced link's drain until its window clients' strict_exp and the other times it keeps.
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
	resolver   *BridgeResolverClient
	routeState atomic.Pointer[bridgeRouteState]
	// what Route hands an IPv6 packet under exits, which counts it and hands it to reject (owner decision 482)
	ipv6Reject *bridgeIpv6RejectClient
	// §12.9's names of the state in force, nil for none, and the LocalZone that reads them
	zone     atomic.Pointer[BridgeZone]
	zoneView *bridgeZoneView
	// §12.9.1's discovery view, nil for none (bridge_discovery.go), which the resolver answers DNS-SD names from
	discovery atomic.Pointer[BridgeDiscoveryView]
	// §17.5's IPv6 translator while ur tun carries the network, nil while off, what Route hands a packet to its /96,
	// and its counts (bridge_translate.go)
	translator      atomic.Pointer[bridgeTranslator]
	translate       *bridgeTranslateClient
	translateCounts bridgeTranslateCounts
	// removes the bridge's callbacks from its link manager
	linkCallbackRemovals []func()
	// the provider hook, the one value EgressHook returns, and the NATs it is installed on, which CloseFlows reaches
	policy          *BridgeEgressPolicy
	hook            *bridgeEgressHook
	closers         *connect.CallbackList[connect.EgressFlowCloser]
	changeCallbacks *connect.CallbackList[func()]
	// the reach events the hook reported, their callbacks and what waits for one (bridge_reach.go); reachDone closes
	// when runReach returns
	reach     *bridgeReach
	reachDone chan struct{}

	// the next time a row's meaning changes, zero for none; run waits on it
	deadline *connect.MonitorValue[time.Time]
	// has run read the clock again at once (CheckClock), holding one check, so checks that come while one waits are one
	clockCheck chan struct{}
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
	// whether the rules the router reads require default egress on, under exits alone (QD-1053)
	defaultEgressRequired bool
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
	reject := NewBridgeRejectClient(nil, settings)
	self := &Bridge{
		ctx:               cancelCtx,
		cancel:            cancel,
		settings:          settings,
		clock:             settings.clock(),
		host:              host,
		posture:           posture,
		pins:              NewBridgePinTable(settings),
		links:             NewBridgeLinkManager(cancelCtx, host, settings),
		reject:            reject,
		ipv6Reject:        &bridgeIpv6RejectClient{reject: reject},
		policy:            NewBridgeEgressPolicy(settings.PolicyProfile, settings),
		closers:           connect.NewCallbackList[connect.EgressFlowCloser](),
		changeCallbacks:   connect.NewCallbackList[func()](),
		deadline:          connect.NewMonitorValue(time.Time{}),
		clockCheck:        make(chan struct{}, 1),
		done:              make(chan struct{}),
		entryStates:       map[netip.Prefix]*BridgeEntryState{},
		heldRejects:       map[netip.Prefix]time.Time{},
		overlayDrainSince: map[string]time.Time{},
		reachDone:         make(chan struct{}),
	}
	self.reach = newBridgeReach(self.policy.reach, settings)
	// the shares' ratchets live in the posture's store, so a restart refuses a ShareCert below one kept (§17.9)
	self.policy.SetShareRatchet(posture)
	self.zoneView = &bridgeZoneView{bridge: self}
	self.resolver = NewBridgeResolverClient(cancelCtx, self.zone.Load, nil, settings)
	self.resolver.discovery = self.discovery.Load
	self.translate = &bridgeTranslateClient{bridge: self}
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
	go self.runReach()
	return self, nil
}

// Stops run and the reach drain and waits for them, then closes the links. The drain's last pass hands the reach
// callbacks what was reported; events still waiting for a callback are lost with the bridge. The posture's store is the caller's.
func (self *Bridge) Close() {
	self.cancel()
	<-self.done
	<-self.reachDone
	for _, remove := range self.linkCallbackRemovals {
		remove()
	}
	self.links.Close()
	self.resolver.Close()
}

// Where packets the bridge answers itself enter the tun: rejects (§17.5's rejects row) and, under `ur tun`, the
// resolver's replies (§17.10). receive borrows each packet; nil drops them, a reject counting as unsent. The sdk's
// DeviceLocal and the CLI set it to their tun's write.
func (self *Bridge) SetReceivePacket(receive connect.ReceivePacketFunction) {
	self.reject.SetReceive(receive)
	self.resolver.SetReceive(receive)
}

// Rebuilds what Route reads after the link manager changed a target's links: a rebuild replaced one, or one drained.
func (self *Bridge) relink() {
	self.apply(func() (PostureDecision, bool, error) {
		return self.posture.Decision(), false, nil
	})
}

// Waits for the next time a row's meaning changes, and publishes again then, until the bridge closes. Each turn arms
// the wait for that time, or for ClockCheckInterval past the wall clock's now when that comes first; a capped wait
// that ends short of the time only reads the clock again, and a check from CheckClock publishes at once, as the timer
// does, then arms the wait anew. The wait is set for its time itself (clockAfterAt), so a move of the clock between
// run's reading and the wait cannot leave the wait late (QD-1425). Nothing is published once the bridge has closed, a
// timer, a check or an update taken as it closed included, and a closed bridge asks the clock for nothing.
func (self *Bridge) run() {
	defer close(self.done)
	// select takes any of its ready cases at random: a case taken as the bridge closed reads as the end
	for self.ctx.Err() == nil {
		deadline, update := self.deadline.Get()
		var timeout <-chan time.Time
		capped := false
		if !deadline.IsZero() {
			wakeAt := deadline
			if interval := self.settings.ClockCheckInterval; 0 < interval {
				if checkAt := self.clock.Now().Add(interval); checkAt.Before(deadline) {
					wakeAt = checkAt
					capped = true
				}
			}
			timeout = clockAfterAt(self.clock, wakeAt)
		}
		select {
		case <-self.ctx.Done():
		case <-update:
		case <-self.clockCheck:
			if self.ctx.Err() == nil {
				self.refresh()
			}
		case <-timeout:
			// a capped wait publishes only once the wall clock has reached the time; short of it, the next turn waits
			// for what remains
			if self.ctx.Err() == nil && (!capped || !self.clock.Now().Before(deadline)) {
				self.refresh()
			}
		}
	}
}

// Reads the clock again at once (§17.8's after sleep or a clock step, owner decision 789): run publishes at now, as its
// timer does, so the flows of an expiry, a drain's end or the previous block's drain that the device slept past, or
// that a step of its clock passed, end then, and it arms its wait again from now, so a wait armed before the sleep
// does not run late; the link manager takes a pass at now too. The platform calls it when the device wakes and when
// its clock changes. It hands the check to run and returns at once, so it never blocks and is safe at any time from
// any goroutine, a change callback's included; checks that come while one waits are one, and after Close it does
// nothing. A revocation needs none: Revoke, SetState and ApplyDeltas publish at once.
func (self *Bridge) CheckClock() {
	select {
	case self.clockCheck <- struct{}{}:
	default:
	}
	self.links.checkClock()
}

// What the bridge has in force and what it found, at the last adoption or check of the clock. Counts the live pins by
// a scan, so call it off the packet path.
func (self *Bridge) Status() BridgeStatus {
	pinnedPairCount := self.pins.PinnedCount()
	verifiedCount, mismatchCount := self.policy.principalCounts()
	linkOpenCount, linkBuildingCount := self.links.counts()
	rejectSentCount, rejectUnsentCount := self.reject.Counts()
	resolverAnsweredCount, resolverPassedCount, resolverDroppedCount := self.resolver.Counts()
	nameCount := 0
	if zone := self.zone.Load(); zone != nil {
		nameCount = zone.NameCount()
	}
	reachNotedCount, reachWaitingCount, reachDroppedCount := self.reach.counts()
	// the exits the router reads now: a route state is immutable once stored, and its egress pins swap whole
	egressExitCount := 0
	if routeState := self.routeState.Load(); routeState != nil && routeState.egress != nil {
		egressExitCount = len(routeState.egress.Links())
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := BridgeStatus{
		EgressExitCount:        egressExitCount,
		ReachNotedCount:        reachNotedCount,
		ReachWaitingCount:      reachWaitingCount,
		ReachDroppedCount:      reachDroppedCount,
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
		Ipv6RejectedCount:      self.ipv6Reject.rejectedCount.Load(),
		HeldRejectCount:        self.routeFindings.heldCount,
		RouteConflictCount:     self.routeFindings.conflictCount,
		EgressMode:             self.egressMode,
		DefaultEgressRequired:  self.defaultEgressRequired,
		NameCount:              nameCount,
		ResolverAnsweredCount:  resolverAnsweredCount,
		ResolverPassedCount:    resolverPassedCount,
		ResolverDroppedCount:   resolverDroppedCount,
		PostureAlarms:          append([]PostureAlarm(nil), self.decision.Alarms...),
		Overdue:                bridgeOverdueCopy(self.decision.Overdue),
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
	reachExpires := func(subject *bridge.BridgeRuleSubject) {
		for _, rows := range [][]*bridge.BridgeRuleReach{subject.GetDial(), subject.GetRoute(), subject.GetExit()} {
			for _, reach := range rows {
				expires(reach.GetExpires())
			}
		}
	}
	for _, subject := range rules.GetSubjects() {
		reachExpires(subject)
	}
	// autogroup:untagged's rows, which another client holds at an sdk provider; none when the rules carry no such field
	reachExpires(rules.GetUntagged())
	if egress := rules.GetEgress(); egress != nil {
		for _, link := range egress.GetExits() {
			drains(link.GetDrainingSince(), link.GetDrainUntil())
		}
	}
	return times
}

// A copy of overdue, nil for none, so a status shares nothing with the decision in force.
func bridgeOverdueCopy(overdue *PostureOverdue) *PostureOverdue {
	if overdue == nil {
		return nil
	}
	copied := *overdue
	return &copied
}
