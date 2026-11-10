//go:build !sidecar_http && !js

// MAIL-M7-07's budget on FakeMailZone and a fake clock (FS-121's dns row): 65 lookups send 64 queries and refuse one
// as a bound; 9 at once keep 8 in flight; priorities hold under contention; 30 s cut what is in flight and what
// waits, as a bound and not temperror; and stub hits spend nothing. Every name is synthetic.

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A zone, its clock, a receiver's stub over it, and one message's budget and resolver.
type mailAuthTestWorld struct {
	clock    *sidecartest.FakeClock
	zone     *sidecartest.FakeMailZone
	settings *sidecar.MailAuthSettings
	stub     *sidecar.MailDnsStub
	budget   *sidecar.MailAuthBudget
	resolver *sidecar.MailAuthResolver
}

func newMailAuthTestWorld(t *testing.T) *mailAuthTestWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	zone := sidecartest.NewFakeMailZone(clock)
	settings := sidecar.DefaultMailAuthSettings()
	stub := sidecar.NewMailDnsStub(zone, clock, settings)
	world := &mailAuthTestWorld{clock: clock, zone: zone, settings: settings, stub: stub}
	world.newMessage(t)
	return world
}

// A new message's budget and resolver over the same stub.
func (self *mailAuthTestWorld) newMessage(t *testing.T) {
	t.Helper()
	self.budget = sidecar.NewMailAuthBudget(self.clock, self.settings)
	t.Cleanup(self.budget.Close)
	self.resolver = sidecar.NewMailAuthResolver(self.stub, self.budget, sidecar.MailAuthPriorityDmarc)
}

// n synthetic TXT names, each answering one record.
func (self *mailAuthTestWorld) txtNames(n int, tag string) []string {
	names := []string{}
	for index := range n {
		name := fmt.Sprintf("%s%d._domainkey.sender.example", tag, index)
		self.zone.AddTxt(name, "v=DKIM1; p=synthetic")
		names = append(names, name+".")
	}
	return names
}

// Waits until count queries wait in the zone.
func (self *mailAuthTestWorld) awaitInFlight(t *testing.T, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := self.zone.AwaitInFlight(ctx, count); err != nil {
		t.Fatalf("waiting for %d in flight: %v", count, err)
	}
}

// Waits until count queries wait in the zone with their delay's timer set, delay from the clock's now: what a test
// waits for before it moves the clock past the answers, since a query counts as in flight before its timer is set.
func awaitMailZoneDelays(t *testing.T, clock *sidecartest.FakeClock, count int, delay time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		pending, added := clock.WatchTimers()
		target := clock.Now().Add(delay)
		set := 0
		for _, at := range pending {
			if at.Equal(target) {
				set += 1
			}
		}
		if count <= set {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatalf("waiting for %d answers %s on: %d set", count, delay, set)
		}
	}
}

// 65 distinct lookups send 64 queries; the 65th is refused as a bound, which callers tell from a DNS failure.
func TestMailAuthBudgetSends64QueriesAndRefusesThe65th(t *testing.T) {
	world := newMailAuthTestWorld(t)
	names := world.txtNames(65, "s")
	errs := []error{}
	for _, name := range names {
		_, _, err := world.resolver.LookupTXT(context.Background(), name)
		errs = append(errs, err)
	}
	for index, err := range errs[:64] {
		if err != nil {
			t.Fatalf("lookup %d: %v", index, err)
		}
	}
	if !errors.Is(errs[64], sidecar.ErrMailAuthQueriesSpent) || !errors.Is(errs[64], sidecar.ErrMailAuthBound) {
		t.Fatalf("the 65th: %v", errs[64])
	}
	if len(world.zone.Queries()) != 64 {
		t.Errorf("%d queries reached the zone", len(world.zone.Queries()))
	}
	sent, refused, deadline := world.budget.Spent()
	if sent != 64 || refused != 1 || deadline {
		t.Errorf("spent %d, refused %d, deadline %t", sent, refused, deadline)
	}
	if !world.resolver.Cut(names[64], dnsmessage.TypeTXT) || world.resolver.Cut(names[0], dnsmessage.TypeTXT) || !world.resolver.CutAt(sidecar.MailAuthPriorityDmarc) {
		t.Error("Cut does not say which lookup the bound cut")
	}
}

// 9 lookups at once keep 8 in flight: the ninth waits for a slot and goes when one frees.
func TestMailAuthBudgetKeepsEightInFlight(t *testing.T) {
	world := newMailAuthTestWorld(t)
	names := world.txtNames(9, "f")
	for _, name := range names {
		world.zone.SetDelay(strings.TrimSuffix(name, "."), time.Second)
	}
	done := make(chan error, len(names))
	for _, name := range names {
		go func() {
			_, _, err := world.resolver.LookupTXT(context.Background(), name)
			done <- err
		}()
	}
	awaitMailZoneDelays(t, world.clock, 8, time.Second)
	// the eight hold their slots; the ninth has no query yet
	if queries := len(world.zone.Queries()); queries != 8 {
		t.Fatalf("%d queries began", queries)
	}
	world.clock.Advance(time.Second)
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	// the ninth took a freed slot, and its answer comes a second on
	awaitMailZoneDelays(t, world.clock, 1, time.Second)
	world.clock.Advance(time.Second)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if world.zone.MaxInFlight() != 8 || len(world.zone.Queries()) != 9 {
		t.Errorf("at most %d in flight, %d queries", world.zone.MaxInFlight(), len(world.zone.Queries()))
	}
}

// Under contention, waiting queries go in priority order, DMARC's first and ARC's last, whatever order they asked in:
// with every slot held, five wait, one at each priority, asked from the last to the first; one slot frees, and the
// five pass through it one at a time, so the zone sees them in the order they were admitted.
func TestMailAuthBudgetHoldsPrioritiesUnderContention(t *testing.T) {
	world := newMailAuthTestWorld(t)
	blockers := world.txtNames(8, "block")
	for index, name := range blockers {
		delay := 4 * time.Second
		if index == 0 {
			delay = time.Second
		}
		world.zone.SetDelay(strings.TrimSuffix(name, "."), delay)
	}
	blocked := make(chan error, len(blockers))
	for _, name := range blockers {
		go func() {
			_, _, err := world.resolver.WithPriority(sidecar.MailAuthPriorityKeys).LookupTXT(context.Background(), name)
			blocked <- err
		}()
	}
	awaitMailZoneDelays(t, world.clock, 1, time.Second)
	awaitMailZoneDelays(t, world.clock, 7, 4*time.Second)
	priorities := []sidecar.MailAuthPriority{sidecar.MailAuthPriorityArc, sidecar.MailAuthPriorityKeys, sidecar.MailAuthPriorityPtr, sidecar.MailAuthPrioritySpf, sidecar.MailAuthPriorityDmarc}
	waiterNames := map[sidecar.MailAuthPriority]string{}
	done := make(chan error, len(priorities))
	for _, priority := range priorities {
		name := fmt.Sprintf("p%d.sender.example", priority)
		world.zone.AddTxt(name, "v=spf1 -all")
		waiterNames[priority] = name
		go func() {
			_, _, err := world.resolver.WithPriority(priority).LookupTXT(context.Background(), name+".")
			done <- err
		}()
	}
	// every waiter has asked once the budget holds five; none reaches the zone while the slots are full
	for sidecar.MailAuthBudgetWaitingForTest(world.budget) < len(priorities) {
		runtime.Gosched()
	}
	world.clock.Advance(time.Second)
	for range priorities {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	order := []string{}
	for _, query := range world.zone.Queries() {
		if strings.HasPrefix(query.Name, "p") {
			order = append(order, query.Name)
		}
	}
	want := []string{waiterNames[sidecar.MailAuthPriorityDmarc], waiterNames[sidecar.MailAuthPrioritySpf], waiterNames[sidecar.MailAuthPriorityPtr], waiterNames[sidecar.MailAuthPriorityKeys], waiterNames[sidecar.MailAuthPriorityArc]}
	if !slices.Equal(order, want) {
		t.Errorf("admitted %v", order)
	}
	world.clock.Advance(3 * time.Second)
	for range blockers {
		if err := <-blocked; err != nil {
			t.Fatal(err)
		}
	}
}

// The check's 30 s cut what is in flight and what waits, each as a bound and never a DNS failure, and later lookups
// are refused the same way.
func TestMailAuthBudgetDeadlineCutsAsABound(t *testing.T) {
	world := newMailAuthTestWorld(t)
	names := world.txtNames(10, "slow")
	for _, name := range names {
		world.zone.SetDelay(strings.TrimSuffix(name, "."), time.Hour)
	}
	done := make(chan error, len(names))
	for _, name := range names {
		go func() {
			_, _, err := world.resolver.LookupTXT(context.Background(), name)
			done <- err
		}()
	}
	world.awaitInFlight(t, 8)
	world.budget.Close()
	for range names {
		if err := <-done; !errors.Is(err, sidecar.ErrMailAuthBound) {
			t.Errorf("a lookup at the check's end: %v", err)
		}
	}
	if _, _, err := world.resolver.LookupTXT(context.Background(), "late.sender.example."); !errors.Is(err, sidecar.ErrMailAuthDeadline) {
		t.Errorf("a lookup after the end: %v", err)
	}

	// the same through the clock: 30 s cut a query that would have answered at 31 s, its own timeout set past both
	world.settings.QueryTimeout = time.Minute
	world.newMessage(t)
	world.zone.AddTxt("thirty.sender.example", "v=spf1 -all")
	world.zone.SetDelay("thirty.sender.example", 31*time.Second)
	cut := make(chan error, 1)
	go func() {
		_, _, err := world.resolver.LookupTXT(context.Background(), "thirty.sender.example.")
		cut <- err
	}()
	world.awaitInFlight(t, 1)
	world.clock.Advance(30 * time.Second)
	if err := <-cut; !errors.Is(err, sidecar.ErrMailAuthDeadline) {
		t.Errorf("at 30 s: %v", err)
	}
	if _, _, deadline := world.budget.Spent(); !deadline {
		t.Error("the deadline is not recorded")
	}
	world.clock.Advance(time.Second)
}

// A stub hit spends nothing: a second message asking what the first asked sends no query and keeps all 64.
func TestMailAuthBudgetStubHitsCountNothing(t *testing.T) {
	world := newMailAuthTestWorld(t)
	names := world.txtNames(3, "hit")
	for _, name := range names {
		if _, _, err := world.resolver.LookupTXT(context.Background(), name); err != nil {
			t.Fatal(err)
		}
	}
	world.newMessage(t)
	for _, name := range names {
		if _, _, err := world.resolver.LookupTXT(context.Background(), name); err != nil {
			t.Fatal(err)
		}
	}
	if sent, _, _ := world.budget.Spent(); sent != 0 || len(world.zone.Queries()) != 3 {
		t.Errorf("the second message sent %d, the zone saw %d", sent, len(world.zone.Queries()))
	}
	// a PTR and an address through the same stub
	world.zone.AddPtr(netip.MustParseAddr("192.0.2.25"), "mail.sender.example")
	if names, _, err := world.resolver.LookupAddr(context.Background(), "192.0.2.25"); err != nil || !slices.Equal(names, []string{"mail.sender.example."}) {
		t.Errorf("%v, %v", names, err)
	}
}
