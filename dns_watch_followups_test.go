//go:build !sidecar_http && !js && !ios_extension

package sidecar

// The zone watch's follow-ups (D-TRUST-9; DNS-M5-22). Pass compares every resolver's answer, however many the watch
// asks, where it compared only the first two: a third resolver's other answer alarms as a split; a split the once more
// no longer shows is judged on the answers that agree; a resolver failing at the once more degrades the pass; and a
// split whose once more gathers nothing judges nothing, rather than one side of it. A watch asks at least two
// resolvers, which NewDnsWatch and the DoH settings hold, and a DoH resolver of three compares all three. Passes wait
// at least the settings' PassMinWait, and settings out of range are refused.
//
// A host that stays up runs the network's watch through its component: composed at the first client generation that
// can, once, on the host's settings, its file in the network's dns/ directory, its passes on the Sidecar's clock, its
// degraded state in SidecarStatus and its alarms the Sidecar's dns_alarm events; a locked keychain, no network or the
// public defaults in a test compose nothing and leave it to a later generation; and Close detaches it, ends it and
// releases its resolvers. Every name and address is synthetic.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Resolvers in memory, as many as tables holds, each answering from its own table, NODATA where it holds nothing, or
// failing. A resolver's queued answers at a name and type come first, one an asking, a nil one failing that asking.
type testDnsWatchResolvers struct {
	stateLock sync.Mutex
	tables    []map[string]*DnsWatchAnswer
	queued    []map[string][]*DnsWatchAnswer
	failing   []bool
	// every resolver's askings, by name and type
	askCounts map[string]int
}

func newTestDnsWatchResolvers(resolverCount int) *testDnsWatchResolvers {
	self := &testDnsWatchResolvers{askCounts: map[string]int{}}
	for range resolverCount {
		self.tables = append(self.tables, map[string]*DnsWatchAnswer{})
		self.queued = append(self.queued, map[string][]*DnsWatchAnswer{})
		self.failing = append(self.failing, false)
	}
	return self
}

// Every resolver answers values at name and qType.
func (self *testDnsWatchResolvers) set(name string, qType uint16, values ...string) {
	for resolver := range self.tables {
		self.setOne(resolver, name, qType, values...)
	}
}

func (self *testDnsWatchResolvers) setOne(resolver int, name string, qType uint16, values ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.tables[resolver][testDnsWatchKey(name, qType)] = &DnsWatchAnswer{Values: slices.Clone(values)}
}

// resolver's next askings at name and qType answer answers in turn, a nil one failing, before its table answers.
func (self *testDnsWatchResolvers) queue(resolver int, name string, qType uint16, answers ...*DnsWatchAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := testDnsWatchKey(name, qType)
	self.queued[resolver][key] = append(self.queued[resolver][key], answers...)
}

func (self *testDnsWatchResolvers) fail(resolver int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing[resolver] = true
}

// How many times the resolvers were asked about name and qType, all of them counted.
func (self *testDnsWatchResolvers) asked(name string, qType uint16) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCounts[testDnsWatchKey(name, qType)]
}

func (self *testDnsWatchResolvers) ResolverCount() int {
	return len(self.tables)
}

func (self *testDnsWatchResolvers) Lookup(ctx context.Context, resolver int, name string, qType uint16) (*DnsWatchAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := testDnsWatchKey(name, qType)
	self.askCounts[key] += 1
	copied := func(answer *DnsWatchAnswer) *DnsWatchAnswer {
		copied := *answer
		copied.Values = slices.Clone(answer.Values)
		return &copied
	}
	if queued := self.queued[resolver][key]; 0 < len(queued) {
		self.queued[resolver][key] = queued[1:]
		if queued[0] == nil {
			return nil, errors.New("synthetic resolver failure")
		}
		return copied(queued[0]), nil
	}
	if self.failing[resolver] {
		return nil, errors.New("synthetic resolver failure")
	}
	if answer, ok := self.tables[resolver][key]; ok {
		return copied(answer), nil
	}
	return &DnsWatchAnswer{Values: []string{}}, nil
}

// The edge's addresses at testDnsWatchHost, as every resolver gives them.
func testDnsWatchFollowupHealthy(resolvers *testDnsWatchResolvers) {
	resolvers.set(testDnsWatchHost, DnsWatchTypeA, "192.0.2.44", "192.0.2.45")
	resolvers.set(testDnsWatchHost, DnsWatchTypeAaaa, "2001:db8::44")
}

// The zone testDnsWatchHost sits in, whose A and AAAA there the edge answers.
func testDnsWatchFollowupZone(networkId Id) *DnsZone {
	return &DnsZone{
		NetworkId: networkId,
		Root:      "root.example.",
		Label:     "lbl0000001",
		Version:   12,
		RecordSets: []DnsZoneRecordSet{
			{Name: testDnsWatchHost, Type: "A", Ttl: 60, Kind: "edge"},
			{Name: testDnsWatchHost, Type: "AAAA", Ttl: 60, Kind: "edge"},
		},
	}
}

// A watch over resolver that publishes testDnsWatchHost, with every alarm kept in order.
func newTestDnsWatchFollowup(t *testing.T, resolver DnsWatchResolver) (*DnsWatch, func() []SidecarDnsAlarm) {
	t.Helper()
	var alarmLock sync.Mutex
	alarms := []SidecarDnsAlarm{}
	zone := testDnsWatchFollowupZone(NewId())
	watch, err := NewDnsWatch(t.Context(), &DnsWatchArgs{
		Resolver: resolver,
		Store:    newTestDnsMemoryStore(),
		Zone: func(ctx context.Context) (*DnsZone, error) {
			return zone, nil
		},
		PublishedHosts: func() []string { return []string{testDnsWatchHost} },
		Event: func(event SidecarEvent) {
			alarmLock.Lock()
			defer alarmLock.Unlock()
			if event.Kind == SidecarEventDnsAlarm {
				alarms = append(alarms, event.DnsAlarm)
			}
		},
		Clock: newTokenTestClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	return watch, func() []SidecarDnsAlarm {
		alarmLock.Lock()
		defer alarmLock.Unlock()
		return slices.Clone(alarms)
	}
}

// Of three resolvers, the first two agreeing and the third answering another address alarm as a split, asked once
// more at every resolver first: the pass compares every answer, where it compared only the first two and passed.
func TestDnsWatchThirdResolversOtherAnswerAlarmsASplit(t *testing.T) {
	resolvers := newTestDnsWatchResolvers(3)
	testDnsWatchFollowupHealthy(resolvers)
	resolvers.setOne(2, testDnsWatchHost, DnsWatchTypeA, "198.51.100.66")
	watch, alarms := newTestDnsWatchFollowup(t, resolvers)
	if !watch.Pass(t.Context()) || !slices.Equal(alarms(), []SidecarDnsAlarm{SidecarDnsAlarmSplit}) {
		t.Fatalf("a third resolver's other address: alarms %v", alarms())
	}
	if asked := resolvers.asked(testDnsWatchHost, DnsWatchTypeA); asked != 6 {
		t.Errorf("the split was asked %d times over three resolvers, not twice each", asked)
	}
	if watch.Status().Degraded {
		t.Errorf("three resolvers answering degraded the watch")
	}
}

// A third resolver's other answer that the once more no longer shows is no split: the answers that agree are judged,
// and pass. The once more is asked because the third differed, which a pass reading only the first two never saw.
func TestDnsWatchSplitTheOnceMoreNoLongerShowsIsJudged(t *testing.T) {
	resolvers := newTestDnsWatchResolvers(3)
	testDnsWatchFollowupHealthy(resolvers)
	resolvers.queue(2, testDnsWatchHost, DnsWatchTypeA, &DnsWatchAnswer{Values: []string{"198.51.100.66"}})
	watch, alarms := newTestDnsWatchFollowup(t, resolvers)
	if watch.Pass(t.Context()) || len(alarms()) != 0 {
		t.Fatalf("a split gone at the once more alarmed: %v", alarms())
	}
	if asked := resolvers.asked(testDnsWatchHost, DnsWatchTypeA); asked != 6 {
		t.Errorf("the third resolver's other answer was asked %d times over three resolvers, not twice each", asked)
	}
	if watch.Status().Degraded {
		t.Errorf("no resolver failed, but the watch is degraded")
	}

	// once more, every resolver agreeing on no address at the edge's host is judged as the zone's mismatch
	resolvers.queue(0, testDnsWatchHost, DnsWatchTypeAaaa, &DnsWatchAnswer{Values: []string{"2001:db8::66"}})
	resolvers.set(testDnsWatchHost, DnsWatchTypeAaaa)
	if !watch.Pass(t.Context()) || !slices.Equal(alarms(), []SidecarDnsAlarm{SidecarDnsAlarmZoneMismatch}) {
		t.Fatalf("the once more's agreed answer: alarms %v", alarms())
	}
}

// A resolver failing only at the once more degrades the pass, which judges what the others agree on.
func TestDnsWatchResolverFailingAtTheOnceMoreDegrades(t *testing.T) {
	resolvers := newTestDnsWatchResolvers(2)
	testDnsWatchFollowupHealthy(resolvers)
	resolvers.queue(1, testDnsWatchHost, DnsWatchTypeA, &DnsWatchAnswer{Values: []string{"198.51.100.66"}}, nil)
	watch, alarms := newTestDnsWatchFollowup(t, resolvers)
	if watch.Pass(t.Context()) || len(alarms()) != 0 {
		t.Fatalf("the other resolver's answer at the once more alarmed: %v", alarms())
	}
	if !watch.Status().Degraded {
		t.Fatal("a resolver that failed at the once more left the watch undegraded")
	}
	if watch.Pass(t.Context()) || watch.Status().Degraded {
		t.Fatalf("a pass with every resolver answering: alarms %v, status %+v", alarms(), watch.Status())
	}
}

// A split whose once more gathers no answer judges nothing, where it judged the first resolver's side of the split:
// here a CNAME at the edge's host, which alarmed as the zone's mismatch though no asking confirmed it. The pass is
// degraded, and the next judges again.
func TestDnsWatchSplitWithNoAnswerAtTheOnceMoreJudgesNothing(t *testing.T) {
	resolvers := newTestDnsWatchResolvers(2)
	testDnsWatchFollowupHealthy(resolvers)
	resolvers.queue(0, testDnsWatchHost, DnsWatchTypeA, &DnsWatchAnswer{Cname: "elsewhere.example.", Values: []string{"192.0.2.44"}}, nil)
	resolvers.queue(1, testDnsWatchHost, DnsWatchTypeA, &DnsWatchAnswer{Values: []string{"192.0.2.44", "192.0.2.45"}}, nil)
	watch, alarms := newTestDnsWatchFollowup(t, resolvers)
	if watch.Pass(t.Context()) || len(alarms()) != 0 {
		t.Fatalf("an unconfirmed split was judged: alarms %v", alarms())
	}
	if !watch.Status().Degraded {
		t.Fatal("a once more that gathered nothing left the watch undegraded")
	}
	if watch.Pass(t.Context()) || len(alarms()) != 0 || watch.Status().Degraded {
		t.Fatalf("the next pass: alarms %v, status %+v", alarms(), watch.Status())
	}
}

// A watch compares at least two resolvers' answers: NewDnsWatch refuses a resolver of fewer, and the DoH settings a
// ResolverCount under two before the factory is asked.
func TestDnsWatchAsksAtLeastTwoResolvers(t *testing.T) {
	for _, resolverCount := range []int{0, 1} {
		_, err := NewDnsWatch(t.Context(), &DnsWatchArgs{
			Resolver: newTestDnsWatchResolvers(resolverCount),
			Store:    newTestDnsMemoryStore(),
			Zone: func(ctx context.Context) (*DnsZone, error) {
				return testDnsWatchFollowupZone(NewId()), nil
			},
			PublishedHosts: func() []string { return nil },
			Clock:          newTokenTestClock(),
		})
		if !errors.Is(err, errInvalidSettings) {
			t.Errorf("a watch over %d resolvers: %v", resolverCount, err)
		}
	}
	asked := 0
	settings := testDnsWatchSeamSettings(func() (*DnsWatchForwarders, error) {
		asked += 1
		return &DnsWatchForwarders{Forwarders: []DnsWatchForwarder{newTestDnsWatchSeamForwarder()}}, nil
	})
	settings.ResolverCount = 1
	if _, err := NewDnsWatchDohResolver(settings); !errors.Is(err, errInvalidSettings) || asked != 0 {
		t.Errorf("one resolver: %v, the factory asked %d times", err, asked)
	}
}

// A DoH resolver of three, its settings' count, gives a watch whose passes ask all three and alarm as a split when the
// third alone answers another address.
func TestDnsWatchOverThreeDohResolversComparesAllThree(t *testing.T) {
	forwarders := []*testDnsWatchSeamForwarder{newTestDnsWatchSeamForwarder(), newTestDnsWatchSeamForwarder(), newTestDnsWatchSeamForwarder()}
	settings := testDnsWatchSeamSettings(func() (*DnsWatchForwarders, error) {
		return &DnsWatchForwarders{Forwarders: []DnsWatchForwarder{forwarders[0], forwarders[1], forwarders[2]}}, nil
	})
	settings.ResolverCount = 3
	resolver, err := NewDnsWatchDohResolver(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if resolver.ResolverCount() != 3 {
		t.Fatalf("%d resolvers", resolver.ResolverCount())
	}
	for _, forwarder := range forwarders {
		forwarder.set(testDnsWatchHost, netip.MustParseAddr("192.0.2.44"), netip.MustParseAddr("2001:db8::44"))
	}
	watch, alarms := newTestDnsWatchFollowup(t, resolver)
	if watch.Pass(t.Context()) || len(alarms()) != 0 {
		t.Fatalf("three agreeing resolvers: alarms %v", alarms())
	}
	forwarders[2].set(testDnsWatchHost, netip.MustParseAddr("198.51.100.66"), netip.MustParseAddr("2001:db8::44"))
	if !watch.Pass(t.Context()) || !slices.Equal(alarms(), []SidecarDnsAlarm{SidecarDnsAlarmSplit}) {
		t.Fatalf("the third resolver's other address: alarms %v", alarms())
	}
	question := testDnsWatchSeamQuestion{qType: dnsmessage.TypeA, domain: "shop.lbl0000001.root.example"}
	for index, forwarder := range forwarders {
		count := 0
		for _, asked := range forwarder.asked() {
			if asked == question {
				count += 1
			}
		}
		// once at the first pass, and twice at the second, its split asked once more
		if count != 3 {
			t.Errorf("forwarder %d was asked the host's A %d times", index, count)
		}
	}
}

// The watch waits at least PassMinWait before a pass, whatever a shorter Interval says, and the settings' own
// Interval where it is longer; numbers out of range are refused.
func TestDnsWatchPassesWaitAtLeastPassMinWait(t *testing.T) {
	newWatch := func(settings *DnsWatchSettings, clock Clock) (*DnsWatch, error) {
		return NewDnsWatch(t.Context(), &DnsWatchArgs{
			Resolver: newTestDnsWatchResolvers(2),
			Store:    newTestDnsMemoryStore(),
			Zone: func(ctx context.Context) (*DnsZone, error) {
				return testDnsWatchFollowupZone(NewId()), nil
			},
			PublishedHosts: func() []string { return nil },
			Settings:       settings,
			Clock:          clock,
		})
	}
	for _, c := range []struct {
		interval time.Duration
		want     time.Duration
	}{
		{interval: time.Millisecond, want: time.Minute},
		{interval: time.Hour, want: time.Hour},
	} {
		settings := DefaultDnsWatchSettings()
		settings.Interval = c.interval
		settings.Jitter = 0
		settings.PassMinWait = time.Minute
		clock := newTokenTestClock()
		watch, err := newWatch(settings, clock)
		if err != nil {
			t.Fatal(err)
		}
		if wait := clock.awaitArmed(t, 1); wait != c.want {
			t.Errorf("an interval of %s waited %s, not %s", c.interval, wait, c.want)
		}
		watch.Close()
	}
	for index, change := range []func(settings *DnsWatchSettings){
		func(settings *DnsWatchSettings) { settings.Interval = 0 },
		func(settings *DnsWatchSettings) { settings.Jitter = -time.Second },
		func(settings *DnsWatchSettings) { settings.PassMinWait = 0 },
		func(settings *DnsWatchSettings) { settings.LookupTimeout = 0 },
		func(settings *DnsWatchSettings) { settings.NameMaxCount = 0 },
	} {
		settings := DefaultDnsWatchSettings()
		change(settings)
		if _, err := newWatch(settings, newTokenTestClock()); !errors.Is(err, errInvalidSettings) {
			t.Errorf("settings change %d: %v", index, err)
		}
	}
	if DefaultDnsWatchSettings().PassMinWait != time.Second {
		t.Errorf("the default floor is %s", DefaultDnsWatchSettings().PassMinWait)
	}
}

// A forwarder that fails while failing is set, and asks the one it wraps otherwise.
type testDnsWatchFailingForwarder struct {
	forwarder *testDnsWatchSeamForwarder
	failing   atomic.Bool
}

func (self *testDnsWatchFailingForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	if self.failing.Load() {
		return nil, false
	}
	return self.forwarder.Forward(ctx, qType, domain)
}

// A ForwarderFactory of two forwarders a build, the second able to fail, every build and release counted.
type testDnsWatchComponentForwarders struct {
	stateLock    sync.Mutex
	built        [][]*testDnsWatchSeamForwarder
	failing      []*testDnsWatchFailingForwarder
	releaseCount []int
}

func (self *testDnsWatchComponentForwarders) factory() (*DnsWatchForwarders, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pair := []*testDnsWatchSeamForwarder{newTestDnsWatchSeamForwarder(), newTestDnsWatchSeamForwarder()}
	failing := &testDnsWatchFailingForwarder{forwarder: pair[1]}
	index := len(self.built)
	self.built = append(self.built, pair)
	self.failing = append(self.failing, failing)
	self.releaseCount = append(self.releaseCount, 0)
	return &DnsWatchForwarders{
		Forwarders: []DnsWatchForwarder{pair[0], failing},
		Close: func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.releaseCount[index] += 1
		},
	}, nil
}

// How many builds there were, and how many times each was released.
func (self *testDnsWatchComponentForwarders) counts() (int, []int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.built), slices.Clone(self.releaseCount)
}

// Build index's two forwarders, and the wrapper the second answers through.
func (self *testDnsWatchComponentForwarders) build(index int) ([]*testDnsWatchSeamForwarder, *testDnsWatchFailingForwarder) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.built[index], self.failing[index]
}

// A Sidecar enrolled in zone's network on an instance in memory, whose time is clock and whose DnsClient reads zone
// from a fake dns block on real time.
func newTestDnsWatchSidecar(t *testing.T, clock Clock, zone *DnsZone) (*Sidecar, *SidecarInstance) {
	t.Helper()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	networkId := zone.NetworkId
	enrollTestNetwork(t, instance, networkId)
	settings := validSidecarSettings()
	settings.Clock = clock
	running := newSidecarBase(nil, settings)
	running.instance = instance
	running.networkId = &networkId
	running.dns.client = newTestDnsClient(t, newTestDnsBlock(zone), nil, networkId)
	return running, instance
}

// The component settings over forwarders, unjittered.
func testDnsWatchComponentSettings(forwarders *testDnsWatchComponentForwarders) *DnsWatchComponentSettings {
	settings := DefaultDnsWatchComponentSettings()
	settings.Watch.Jitter = 0
	settings.Doh.ForwarderFactory = forwarders.factory
	return settings
}

// Waits until the watch's run loop has armed its wait after a pass, counting armed waits from after from: a lookup
// arms LookupTimeout, the loop Interval. Answers the count that wait was.
func awaitTestDnsWatchNextWait(t *testing.T, clock *tokenTestClock, from int, interval time.Duration) int {
	t.Helper()
	for count := from + 1; ; count += 1 {
		if clock.awaitArmed(t, count) == interval {
			return count
		}
	}
}

// The component composes the network's watch at its first generation, once, on its settings' resolvers, attached to
// the Sidecar, its file the network's own in dns/; each pass runs at the settings' interval on the Sidecar's clock, a
// failing resolver showing as "zone watch degraded" in SidecarStatus and a split raising the Sidecar's dns_alarm; and
// Close detaches the watch, ends it and releases its resolvers once, after which no generation composes another.
func TestDnsWatchComponentRunsTheNetworksWatch(t *testing.T) {
	clock := newTokenTestClock()
	running, _ := newTestDnsWatchSidecar(t, clock, testDnsWatchFollowupZone(testConfigId("watched network")))
	alarms := make(chan SidecarDnsAlarm, 16)
	removeCallback := running.AddEventCallback(func(event SidecarEvent) {
		if event.Kind == SidecarEventDnsAlarm {
			alarms <- event.DnsAlarm
		}
	})
	defer removeCallback()
	forwarders := &testDnsWatchComponentForwarders{}
	settings := testDnsWatchComponentSettings(forwarders)
	component := running.NewDnsWatchComponent(settings)
	if component.Name() != "dns-watch" || checkSidecarComponentName(component.Name()) != nil {
		t.Fatalf("component name %q", component.Name())
	}
	if running.mailDnsWatch() != nil {
		t.Fatal("a watch before any generation")
	}
	env := &SidecarEnv{Ctx: t.Context(), Log: NewNoopLogger()}
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	watch := running.mailDnsWatch()
	if watch == nil {
		t.Fatal("the first generation composed no watch")
	}
	if err := component.Attach(env); err != nil || running.mailDnsWatch() != watch {
		t.Fatalf("the next generation composed another watch: %v", err)
	}
	if built, releases := forwarders.counts(); built != 1 || releases[0] != 0 {
		t.Fatalf("%d resolvers built, released %v", built, releases)
	}
	// the watch's file is the network's own, in its dns/ directory under class dns
	if err := watch.Watch(testDnsWatchHost); err != nil {
		t.Fatal(err)
	}
	store, err := running.LocalStore().Directory(dnsDirectoryName, dnsDirectoryName)
	if err != nil {
		t.Fatal(err)
	}
	if file, err := readDnsWatchFile(store); err != nil || !slices.Equal(file.Names, []string{testDnsWatchHost}) {
		t.Fatalf("the network's watch file: %+v %v", file, err)
	}

	// a pass at the interval, the second resolver failing: degraded, and no alarm
	interval := settings.Watch.Interval
	if wait := clock.awaitArmed(t, 1); wait != interval {
		t.Fatalf("the first pass waits %s, not the settings' %s", wait, interval)
	}
	pair, second := forwarders.build(0)
	for _, forwarder := range pair {
		forwarder.set(testDnsWatchHost, netip.MustParseAddr("192.0.2.44"), netip.MustParseAddr("2001:db8::44"))
	}
	second.failing.Store(true)
	clock.Advance(interval)
	armed := awaitTestDnsWatchNextWait(t, clock, 1, interval)
	if !running.Status().ZoneWatchDegraded {
		t.Fatal("a failing resolver left SidecarStatus undegraded")
	}
	if status := watch.Status(); status.NameCount != 3 {
		t.Fatalf("the pass watched %d names and types", status.NameCount)
	}

	// the next, the second resolver answering another address: a split, the Sidecar's dns_alarm
	second.failing.Store(false)
	pair[1].set(testDnsWatchHost, netip.MustParseAddr("198.51.100.66"), netip.MustParseAddr("2001:db8::44"))
	clock.Advance(interval)
	awaitTestDnsWatchNextWait(t, clock, armed, interval)
	if running.Status().ZoneWatchDegraded {
		t.Fatal("every resolver answered, but SidecarStatus is degraded")
	}
	select {
	case alarm := <-alarms:
		if alarm != SidecarDnsAlarmSplit {
			t.Fatalf("alarm %s", alarm)
		}
	default:
		t.Fatal("the split raised no dns_alarm on the Sidecar")
	}

	component.Close()
	if running.mailDnsWatch() != nil || running.Status().ZoneWatchDegraded {
		t.Fatal("Close left the watch attached")
	}
	if built, releases := forwarders.counts(); built != 1 || releases[0] != 1 {
		t.Fatalf("Close: %d resolvers built, released %v", built, releases)
	}
	if err := component.Attach(env); err != nil || running.mailDnsWatch() != nil {
		t.Fatalf("a generation after Close composed a watch: %v", err)
	}
	component.Close()
	if built, releases := forwarders.counts(); built != 1 || releases[0] != 1 {
		t.Fatalf("a second Close: %d resolvers built, released %v", built, releases)
	}
}

// A generation that cannot compose the watch leaves it to the next and still attaches: with the keychain locked the
// watch's file does not read, and the resolver built for it is released; the generation after the unlock composes it.
// A Sidecar with no network asks for no resolver, and in a test binary the public defaults compose nothing.
func TestDnsWatchComponentWaitsForAGenerationThatCan(t *testing.T) {
	running, instance := newTestDnsWatchSidecar(t, newTokenTestClock(), testDnsWatchFollowupZone(testConfigId("locked network")))
	forwarders := &testDnsWatchComponentForwarders{}
	component := running.NewDnsWatchComponent(testDnsWatchComponentSettings(forwarders))
	defer component.Close()
	env := &SidecarEnv{Ctx: t.Context(), Log: NewNoopLogger()}
	instance.Lock()
	if err := component.Attach(env); err != nil || running.mailDnsWatch() != nil {
		t.Fatalf("a locked keychain's generation: %v", err)
	}
	if built, releases := forwarders.counts(); built != 1 || releases[0] != 1 {
		t.Fatalf("a locked keychain's generation: %d resolvers built, released %v", built, releases)
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := component.Attach(env); err != nil || running.mailDnsWatch() == nil {
		t.Fatalf("the generation after the unlock composed no watch: %v", err)
	}
	if built, releases := forwarders.counts(); built != 2 || releases[1] != 0 {
		t.Fatalf("after the unlock: %d resolvers built, released %v", built, releases)
	}

	unenrolled := newSidecarBase(nil, validSidecarSettings())
	idle := &testDnsWatchComponentForwarders{}
	unenrolledComponent := unenrolled.NewDnsWatchComponent(testDnsWatchComponentSettings(idle))
	defer unenrolledComponent.Close()
	if err := unenrolledComponent.Attach(env); err != nil || unenrolled.mailDnsWatch() != nil {
		t.Fatalf("a Sidecar with no network: %v", err)
	}
	if built, _ := idle.counts(); built != 0 {
		t.Fatalf("a Sidecar with no network built %d resolvers", built)
	}

	public, _ := newTestDnsWatchSidecar(t, newTokenTestClock(), testDnsWatchFollowupZone(testConfigId("public network")))
	defaults := public.NewDnsWatchComponent(nil)
	defer defaults.Close()
	if err := defaults.Attach(env); err != nil || public.mailDnsWatch() != nil {
		t.Fatalf("the public defaults in a test binary: %v", err)
	}
}
