//go:build !ios_extension

package sidecar

// The zone watch (DNS-M5-22; D-TRUST-9), T2 on a fake DnsWatchResolver: M5's exit case, an operator-side change
// alarming while a requested one does not; one resolver failing degrading without an alarm; split answers alarming;
// both resolvers disagreeing with the zone alarming; nothing watched with no published name.

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
)

// Two resolvers in memory, each answering from its own table, or failing.
type testDnsWatchResolver struct {
	stateLock sync.Mutex
	answers   [2]map[string]*DnsWatchAnswer
	failing   [2]bool
	calls     int
}

func newTestDnsWatchResolver() *testDnsWatchResolver {
	return &testDnsWatchResolver{answers: [2]map[string]*DnsWatchAnswer{{}, {}}}
}

func testDnsWatchKey(name string, qType uint16) string {
	return name + " " + strconv.Itoa(int(qType))
}

// Both resolvers answer values for name and qType.
func (self *testDnsWatchResolver) set(name string, qType uint16, values ...string) {
	self.setOne(0, name, qType, values...)
	self.setOne(1, name, qType, values...)
}

func (self *testDnsWatchResolver) setOne(resolver int, name string, qType uint16, values ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers[resolver][testDnsWatchKey(name, qType)] = &DnsWatchAnswer{Values: append([]string{}, values...)}
}

func (self *testDnsWatchResolver) ResolverCount() int {
	return 2
}

func (self *testDnsWatchResolver) Lookup(ctx context.Context, resolver int, name string, qType uint16) (*DnsWatchAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls += 1
	if self.failing[resolver] {
		return nil, errors.New("synthetic resolver failure")
	}
	if answer, ok := self.answers[resolver][testDnsWatchKey(name, qType)]; ok {
		copied := *answer
		copied.Values = append([]string{}, answer.Values...)
		return &copied, nil
	}
	return &DnsWatchAnswer{Values: []string{}}, nil
}

const (
	testDnsWatchApex = "lbl0000001.root.example."
	testDnsWatchHost = "shop.lbl0000001.root.example."
)

// A watch over resolver for a zone whose published host is shop, edge-answered, and whose apex holds a system TXT,
// with every alarm kept in the answer's slice.
func newTestDnsWatch(t *testing.T, resolver *testDnsWatchResolver, hosts []string, extra ...DnsZoneRecordSet) (*DnsWatch, *[]SidecarDnsAlarm) {
	t.Helper()
	alarms := &[]SidecarDnsAlarm{}
	var alarmLock sync.Mutex
	zone := &DnsZone{
		NetworkId: NewId(),
		Root:      "root.example.",
		Label:     "lbl0000001",
		Version:   12,
		RecordSets: append([]DnsZoneRecordSet{
			{Name: testDnsWatchHost, Type: "A", Ttl: 60, Kind: "edge"},
			{Name: testDnsWatchHost, Type: "AAAA", Ttl: 60, Kind: "edge"},
			{Name: testDnsWatchApex, Type: "TXT", Ttl: 300, Kind: "system", Values: []string{`"v=spf1 -all"`}},
		}, extra...),
	}
	settings := DefaultDnsWatchSettings()
	watch, err := NewDnsWatch(context.Background(), &DnsWatchArgs{
		Resolver: resolver,
		Store:    newTestDnsMemoryStore(),
		Zone: func(ctx context.Context) (*DnsZone, error) {
			return zone, nil
		},
		PublishedHosts: func() []string { return hosts },
		Event: func(event SidecarEvent) {
			alarmLock.Lock()
			defer alarmLock.Unlock()
			if event.Kind == SidecarEventDnsAlarm {
				*alarms = append(*alarms, event.DnsAlarm)
			}
		},
		Settings: settings,
		Clock:    newTokenTestClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	return watch, alarms
}

// The edge's addresses at the published host and @'s answers, as both resolvers give them.
func testDnsWatchHealthy(resolver *testDnsWatchResolver) {
	resolver.set(testDnsWatchHost, DnsWatchTypeA, "11.22.33.44", "11.22.33.45")
	resolver.set(testDnsWatchHost, DnsWatchTypeAaaa, "2001:db8::44")
}

// M5's exit case: a record this device requested (Expect) passes, and the same name changed on the operator's side,
// or a CAA it never asked for, alarms.
func TestDnsWatchAlarmsOnAnOperatorChangeAndNotARequestedOne(t *testing.T) {
	resolver := newTestDnsWatchResolver()
	testDnsWatchHealthy(resolver)
	watch, alarms := newTestDnsWatch(t, resolver, []string{testDnsWatchHost})
	note := "_note." + testDnsWatchHost
	if err := watch.Expect(note, DnsWatchTypeTxt, []string{`"requested by this device"`}); err != nil {
		t.Fatal(err)
	}
	resolver.set(note, DnsWatchTypeTxt, "requested by this device")
	if watch.Pass(context.Background()) || len(*alarms) != 0 {
		t.Fatalf("a requested record alarmed: %v", *alarms)
	}
	if status := watch.Status(); status.Degraded || status.NameCount == 0 {
		t.Fatalf("status %+v", status)
	}
	resolver.set(note, DnsWatchTypeTxt, "changed by the operator")
	if !watch.Pass(context.Background()) || len(*alarms) != 1 || (*alarms)[0] != SidecarDnsAlarmUnrequested {
		t.Fatalf("an operator's change: %v", *alarms)
	}
	resolver.set(note, DnsWatchTypeTxt, "requested by this device")
	resolver.set(testDnsWatchHost, DnsWatchTypeCaa, `0 issue other-ca.example`)
	if !watch.Pass(context.Background()) || len(*alarms) != 2 || (*alarms)[1] != SidecarDnsAlarmUnrequested {
		t.Fatalf("an unrequested CAA: %v", *alarms)
	}
}

// One resolver failing marks the watch degraded and alarms on nothing the other answers as expected.
func TestDnsWatchOneResolverFailingDegradesWithoutAlarm(t *testing.T) {
	resolver := newTestDnsWatchResolver()
	testDnsWatchHealthy(resolver)
	resolver.failing[1] = true
	watch, alarms := newTestDnsWatch(t, resolver, []string{testDnsWatchHost})
	if watch.Pass(context.Background()) || len(*alarms) != 0 {
		t.Fatalf("alarms %v", *alarms)
	}
	if !watch.Status().Degraded {
		t.Fatalf("not degraded")
	}
	resolver.failing[1] = false
	watch.Pass(context.Background())
	if watch.Status().Degraded {
		t.Fatalf("still degraded")
	}
}

// The two resolvers answering differently, twice running, alarm as a split.
func TestDnsWatchSplitAnswersAlarm(t *testing.T) {
	resolver := newTestDnsWatchResolver()
	testDnsWatchHealthy(resolver)
	resolver.setOne(1, testDnsWatchHost, DnsWatchTypeA, "11.22.33.99")
	watch, alarms := newTestDnsWatch(t, resolver, []string{testDnsWatchHost})
	if !watch.Pass(context.Background()) || len(*alarms) != 1 || (*alarms)[0] != SidecarDnsAlarmSplit {
		t.Fatalf("alarms %v", *alarms)
	}
}

// Both resolvers agreeing with each other but not with what GET /dns/zone shows alarm, and an edge-answered host
// that answers a CNAME does too.
func TestDnsWatchResolversDisagreeingWithTheZoneAlarm(t *testing.T) {
	resolver := newTestDnsWatchResolver()
	testDnsWatchHealthy(resolver)
	blog := "blog.lbl0000001.root.example."
	resolver.set(blog, DnsWatchTypeA, "11.22.33.99")
	watch, alarms := newTestDnsWatch(t, resolver, []string{testDnsWatchHost, blog},
		DnsZoneRecordSet{Name: blog, Type: "A", Ttl: 300, Kind: "user", Values: []string{"11.22.33.50"}})
	if !watch.Pass(context.Background()) || len(*alarms) != 1 || (*alarms)[0] != SidecarDnsAlarmZoneMismatch {
		t.Fatalf("alarms %v", *alarms)
	}
	resolver.set(blog, DnsWatchTypeA, "11.22.33.50")
	func() {
		resolver.stateLock.Lock()
		defer resolver.stateLock.Unlock()
		for index := range 2 {
			resolver.answers[index][testDnsWatchKey(testDnsWatchHost, DnsWatchTypeA)] = &DnsWatchAnswer{Cname: "elsewhere.example.", Values: []string{"11.22.33.44"}}
		}
	}()
	if !watch.Pass(context.Background()) || len(*alarms) != 2 || (*alarms)[1] != SidecarDnsAlarmZoneMismatch {
		t.Fatalf("a CNAME at an edge host: %v", *alarms)
	}
}

// A published host the edge answers through *, which the device's view of the zone does not show, passes on the
// edge's addresses and alarms on a CNAME or on no address at all.
func TestDnsWatchPublishedHostAnsweredThroughTheWildcard(t *testing.T) {
	resolver := newTestDnsWatchResolver()
	testDnsWatchHealthy(resolver)
	blog := "blog.lbl0000001.root.example."
	resolver.set(blog, DnsWatchTypeA, "11.22.33.44", "11.22.33.45")
	resolver.set(blog, DnsWatchTypeAaaa, "2001:db8::44")
	watch, alarms := newTestDnsWatch(t, resolver, []string{testDnsWatchHost, blog})
	if watch.Pass(context.Background()) || len(*alarms) != 0 {
		t.Fatalf("the edge's addresses alarmed: %v", *alarms)
	}
	resolver.set(blog, DnsWatchTypeAaaa)
	if !watch.Pass(context.Background()) || len(*alarms) != 1 || (*alarms)[0] != SidecarDnsAlarmZoneMismatch {
		t.Fatalf("a published host with no address: %v", *alarms)
	}
}

// A sidecar with no published name and nothing it asked for watches nothing and asks no resolver.
func TestDnsWatchWatchesNothingWithoutAPublishedName(t *testing.T) {
	resolver := newTestDnsWatchResolver()
	watch, alarms := newTestDnsWatch(t, resolver, nil)
	if watch.Pass(context.Background()) || len(*alarms) != 0 || resolver.calls != 0 {
		t.Fatalf("%d lookups, alarms %v", resolver.calls, *alarms)
	}
	if status := watch.Status(); status.NameCount != 0 || status.Degraded {
		t.Fatalf("status %+v", status)
	}
}

// Each type's presentation text and its wire form read the same.
func TestDnsWatchValuesCompareInOneForm(t *testing.T) {
	cases := []struct {
		qType        uint16
		presentation string
		canonical    string
	}{
		{qType: DnsWatchTypeA, presentation: "11.22.33.44", canonical: "11.22.33.44"},
		{qType: DnsWatchTypeAaaa, presentation: "2001:DB8::44", canonical: "2001:db8::44"},
		{qType: DnsWatchTypeTxt, presentation: `"two " "strings"`, canonical: "two strings"},
		{qType: DnsWatchTypeMx, presentation: "10 MX.Example.", canonical: "10 mx.example."},
		{qType: DnsWatchTypeTlsa, presentation: "3 1 1 abcdef", canonical: "3 1 1 ABCDEF"},
		{qType: DnsWatchTypeCaa, presentation: `0 issue "ca.example"`, canonical: "0 issue ca.example"},
	}
	for _, c := range cases {
		if got := canonicalDnsWatchValue(c.qType, c.presentation); got != c.canonical {
			t.Errorf("%d %q: %q, want %q", c.qType, c.presentation, got, c.canonical)
		}
	}
}
