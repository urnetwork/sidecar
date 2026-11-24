//go:build !sidecar_http && !js && !ios_extension

package sidecar

// The zone watch's follow-ups (D-TRUST-9; DNS-M5-22). Pass compares every resolver's answer, however many the watch
// asks, where it compared only the first two: a third resolver's other answer alarms as a split; a split the once more
// no longer shows is judged on the answers that agree; a resolver failing at the once more degrades the pass; and a
// split whose once more gathers nothing judges nothing, rather than one side of it. A watch asks at least two
// resolvers, which NewDnsWatch and the DoH settings hold, and a DoH resolver of three compares all three. Passes wait
// at least the settings' PassMinWait, and settings out of range are refused. Every name and address is synthetic.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
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
