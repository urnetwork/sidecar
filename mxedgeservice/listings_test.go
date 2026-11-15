// IP listings (MAIL-M7-20) on synthetic prefixes, RFC 5737's and RFC 3849's: a listed exploit or botnet
// source gets 554 at the banner, any other category passes on in MailIngress, a stale or failing mirror
// rejects nothing, and a swap under load misses no read.

package mxedgeservice_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One synthetic entry.
type testListing struct {
	prefix   string
	category string
}

// A mirror a test scripts: its entries, when its data was current, and whether a load fails.
type testListingSource struct {
	stateLock   sync.Mutex
	listings    []testListing
	currentTime time.Time
	failing     bool
	loadCount   int
}

func (self *testListingSource) set(currentTime time.Time, listings ...testListing) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.currentTime = currentTime
	self.listings = listings
	self.failing = false
}

func (self *testListingSource) fail() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = true
}

func (self *testListingSource) Load(ctx context.Context, add mxedgeservice.MxListingAdd) (time.Time, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.loadCount += 1
	if self.failing {
		return time.Time{}, errors.New("the mirror cannot be read")
	}
	for _, listing := range self.listings {
		if err := add(netip.MustParsePrefix(listing.prefix), listing.category); err != nil {
			return time.Time{}, err
		}
	}
	return self.currentTime, nil
}

// The synthetic feed every router test here starts on.
func testListings(currentTime time.Time) []testListing {
	return []testListing{
		{prefix: "192.0.2.0/24", category: mxedgeservice.MxListingCategoryExploit},
		{prefix: "198.51.100.7/32", category: "pbl"},
		{prefix: "198.51.100.0/24", category: "sbl"},
		{prefix: "2001:db8::/32", category: mxedgeservice.MxListingCategoryBotnet},
	}
}

// A router on source, past its first load.
func newTestListedRouter(t *testing.T, source *testListingSource) *testRouter {
	t.Helper()
	router := newTestRouter(t, &testRouterOptions{router: func(routerDeps *mxedgeservice.MxEdgeRouterDeps) {
		routerDeps.Listings = source
	}})
	router.service.AwaitListingLoads(1)
	return router
}

// Connects as sender and expects the banner's 554, after which only QUIT does anything.
func (self *testRouter) expectBannerRefused(sender string) {
	self.t.Helper()
	client := self.dial(sender)
	client.expect("554 5.7.1 " + testBannerHostName + " Service refused")
	client.write("EHLO relay.example\r\n")
	client.expect("503 5.5.1 Bad sequence of commands")
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	client.expectEnd()
}

// A listed exploit source and a listed botnet source get 554 at the banner; a "pbl" source passes, its
// categories in MailIngress, as does an unlisted one with none.
func TestListingsRejectOnlyBotnetAndExploit(t *testing.T) {
	source := &testListingSource{}
	start := sidecartest.DefaultClockStart()
	source.set(start, testListings(start)...)
	router := newTestListedRouter(t, source)
	router.expectBannerRefused("192.0.2.77")
	router.expectBannerRefused("2001:db8:1::25")
	if len(router.dialer.Receivers()) != 0 {
		t.Fatal("a refused sender reached a dial")
	}

	client, receiver := router.dialFrom("198.51.100.7", testRouteSni)
	if listings := receiver.ingress.GetIpListings(); !slices.Equal(listings, []string{"pbl", "sbl"}) {
		t.Errorf("a pbl source's MailIngress lists %v", listings)
	}
	receiver.writer.Close()
	client.expectEnd()
	client, receiver = router.dialFrom("203.0.113.40", testRouteSni)
	if listings := receiver.ingress.GetIpListings(); len(listings) != 0 {
		t.Errorf("an unlisted source's MailIngress lists %v", listings)
	}
	receiver.writer.Close()
	client.expectEnd()
	if value := router.host.Metrics.Value("urnetwork_mxedge_listing_loads_total", "loaded"); value != 1 {
		t.Errorf("%v loads", value)
	}
}

// A mirror whose data is stale rejects nothing and passes nothing on.
func TestListingsStaleRejectNothing(t *testing.T) {
	source := &testListingSource{}
	start := sidecartest.DefaultClockStart()
	settings := mxedgeservice.DefaultMxEdgeSettings()
	source.set(start.Add(-settings.ListingStaleTimeout-time.Second), testListings(start)...)
	router := newTestListedRouter(t, source)
	client, receiver := router.dialFrom("192.0.2.77", testRouteSni)
	if listings := receiver.ingress.GetIpListings(); len(listings) != 0 {
		t.Errorf("a stale mirror passed %v on", listings)
	}
	receiver.writer.Close()
	client.expectEnd()
}

// A mirror that stops answering keeps the set in use until its data goes stale, then rejects nothing; the
// next good load rejects again.
func TestListingsFeedDownRejectsNothingOnceStale(t *testing.T) {
	source := &testListingSource{}
	start := sidecartest.DefaultClockStart()
	source.set(start, testListings(start)...)
	router := newTestListedRouter(t, source)
	source.fail()
	interval := router.settings.ListingRefreshInterval
	router.clock.Advance(interval)
	router.service.AwaitListingLoads(2)
	router.expectBannerRefused("192.0.2.77")

	// past the stale bound with every load failing
	router.clock.AdvanceTo(start.Add(router.settings.ListingStaleTimeout + time.Second))
	client, receiver := router.dialFrom("192.0.2.77", testRouteSni)
	receiver.writer.Close()
	client.expectEnd()
	if value := router.host.Metrics.Value("urnetwork_mxedge_listing_loads_total", "failed"); value < 1 {
		t.Errorf("%v failed loads counted", value)
	}

	// a load that answers again rejects again
	source.set(router.clock.Now(), testListings(start)...)
	loadCount := router.service.ListingLoadCount()
	router.clock.Advance(interval)
	router.service.AwaitListingLoads(loadCount + 1)
	router.expectBannerRefused("192.0.2.77")
}

// Reads during swaps see the old set or the new one, both listing the prefix, and never neither.
func TestListingsSwapUnderLoadMissesNoRead(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := mxedgeservice.DefaultMxEdgeSettings()
	source := &testListingSource{}
	source.set(clock.Now(), testListings(clock.Now())...)
	listings := mxedgeservice.NewListings(source, settings, clock, sidecartest.NewFakeMetrics(nil))
	listings.Load(ctx)
	listed := netip.MustParseAddr("192.0.2.9")
	var misses atomic.Int64
	var reads atomic.Int64
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !listings.Refused(listed) {
					misses.Add(1)
				}
				reads.Add(1)
			}
		}()
	}
	for i := range 200 {
		extra := testListing{prefix: fmt.Sprintf("203.0.113.%d/32", i%250), category: "pbl"}
		source.set(clock.Now(), append(testListings(clock.Now()), extra)...)
		listings.Load(ctx)
	}
	close(stop)
	readers.Wait()
	if misses.Load() != 0 {
		t.Errorf("%d of %d reads missed the listing during swaps", misses.Load(), reads.Load())
	}
}

// A mirror past ListingPrefixCount, with a category past the format's 12 B, or with more categories than a
// mask holds, loads nothing, and the set in use stays.
func TestListingsRefuseAMirrorPastItsBounds(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.ListingPrefixCount = 4
	source := &testListingSource{}
	source.set(clock.Now(), testListings(clock.Now())...)
	listings := mxedgeservice.NewListings(source, settings, clock, sidecartest.NewFakeMetrics(nil))
	listings.Load(ctx)
	listed := netip.MustParseAddr("192.0.2.9")
	if !listings.Refused(listed) {
		t.Fatal("the first set does not list its exploit source")
	}
	tooMany := []testListing{}
	for i := range 65 {
		tooMany = append(tooMany, testListing{prefix: fmt.Sprintf("203.0.113.%d/32", i), category: fmt.Sprintf("c%d", i)})
	}
	for name, entries := range map[string][]testListing{
		"past the count":          append(testListings(clock.Now()), testListing{prefix: "203.0.113.1/32", category: "pbl"}),
		"a category past 12 B":    {{prefix: "203.0.113.1/32", category: "a-category-too-long"}},
		"a category with a space": {{prefix: "203.0.113.1/32", category: "two words"}},
		"65 categories":           tooMany,
	} {
		bounded := *settings
		if name == "65 categories" {
			bounded.ListingPrefixCount = 100
		}
		source.set(clock.Now(), entries...)
		other := mxedgeservice.NewListings(source, &bounded, clock, sidecartest.NewFakeMetrics(nil))
		other.Load(ctx)
		if len(other.Categories(netip.MustParseAddr("203.0.113.1"))) != 0 {
			t.Errorf("%s: loaded", name)
		}
		listings.Load(ctx)
		if !listings.Refused(listed) {
			t.Errorf("%s: a refused load replaced the set in use", name)
		}
	}
}

// An IPv4-mapped prefix lists the IPv4 addresses it names, and overlapping prefixes add their categories.
func TestListingsMapAndOverlap(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	source := &testListingSource{}
	source.set(clock.Now(),
		testListing{prefix: "::ffff:192.0.2.0/120", category: mxedgeservice.MxListingCategoryExploit},
		testListing{prefix: "192.0.2.128/25", category: "pbl"},
		testListing{prefix: "2001:db8:aa::/48", category: "pbl"},
		testListing{prefix: "2001:db8:aa:bb::1/128", category: "sbl"},
	)
	listings := mxedgeservice.NewListings(source, mxedgeservice.DefaultMxEdgeSettings(), clock, sidecartest.NewFakeMetrics(nil))
	listings.Load(ctx)
	if !listings.Refused(netip.MustParseAddr("192.0.2.200")) || !listings.Refused(netip.MustParseAddr("::ffff:192.0.2.1")) {
		t.Error("a mapped prefix does not list its IPv4 addresses")
	}
	if got := listings.Categories(netip.MustParseAddr("192.0.2.200")); !slices.Equal(got, []string{"exploit", "pbl"}) {
		t.Errorf("overlapping prefixes gave %v", got)
	}
	if got := listings.Categories(netip.MustParseAddr("2001:db8:aa:bb::1")); !slices.Equal(got, []string{"pbl", "sbl"}) {
		t.Errorf("IPv6 overlap gave %v", got)
	}
	if got := listings.Categories(netip.MustParseAddr("2001:db8:ab::1")); len(got) != 0 {
		t.Errorf("an unlisted IPv6 address gave %v", got)
	}
}

// A lookup allocates nothing.
func TestListingLookupAllocatesNothing(t *testing.T) {
	listings := testBenchListings(t)
	senders := []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9")}
	if allocs := testing.AllocsPerRun(1000, func() {
		for _, sender := range senders {
			listings.Refused(sender)
		}
	}); allocs != 0 {
		t.Errorf("a lookup allocated %v times", allocs)
	}
}

// Listings over a mirror of many /32s and a few wider prefixes, both families.
func testBenchListings(tb testing.TB) *mxedgeservice.Listings {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	source := &testListingSource{}
	entries := testListings(clock.Now())
	for i := range 50000 {
		entries = append(entries, testListing{prefix: fmt.Sprintf("10.%d.%d.%d/32", i/65536, (i/256)%256, i%256), category: mxedgeservice.MxListingCategoryExploit})
	}
	source.set(clock.Now(), entries...)
	listings := mxedgeservice.NewListings(source, mxedgeservice.DefaultMxEdgeSettings(), clock, sidecartest.NewFakeMetrics(nil))
	listings.Load(context.Background())
	if !listings.Refused(netip.MustParseAddr("10.0.1.2")) {
		tb.Fatal("the bench set did not load")
	}
	return listings
}

// The banner's lookup, which must allocate nothing.
func BenchmarkMxListingLookup(b *testing.B) {
	listings := testBenchListings(b)
	sender := netip.MustParseAddr("203.0.113.9")
	b.ReportAllocs()
	for b.Loop() {
		listings.Refused(sender)
	}
}
