//go:build !sidecar_http && !js

// MAIL-M7-09's check slots (§15.5's receiver row, FS-121) on a fake clock: 4 messages check at once and the rest wait
// in arrival order; a waiter whose session ends leaves the line; a message's 30 s start when its slot takes it, not
// when it arrived; and 15 hostile sessions at once, each check cut only by its 30 s, while a 16th normal message,
// arriving last, completes within 2 min of its last byte, checked in full. Every name and address is synthetic.

package sidecar_test

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Waits until slots holds taken slots and waiting arrivals.
func awaitMailAuthSlots(t *testing.T, slots *sidecar.MailAuthSlots, taken int, waiting int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		takenCount, waitingCount := sidecar.MailAuthSlotsStateForTest(slots)
		if takenCount == taken && waitingCount == waiting {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("slots %d taken and %d waiting, wanted %d and %d", takenCount, waitingCount, taken, waiting)
		default:
		}
		// a taker queues on its own goroutine; let it
		runtime.Gosched()
	}
}

// Waits until count checks' 30 s deadlines are set from the clock's now: each running check's budget.
func awaitMailAuthDeadlines(t *testing.T, world *mailAuthCheckWorld, count int) {
	t.Helper()
	awaitMailZoneDelays(t, world.clock, count, world.settings.CheckTimeout)
}

// 4 take a slot at once; a 5th and 6th wait, and a freed slot goes to the 5th, the earlier arrival, never the 6th.
func TestMailAuthSlotsAdmitFourInArrivalOrder(t *testing.T) {
	settings := sidecar.DefaultMailAuthSettings()
	slots := sidecar.NewMailAuthSlots(settings)
	releases := []func(){}
	for range 4 {
		release, err := slots.Take(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	taken := make(chan int, 2)
	laterReleases := make(chan func(), 2)
	for arrival := 5; arrival <= 6; arrival += 1 {
		go func() {
			release, err := slots.Take(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			taken <- arrival
			laterReleases <- release
		}()
		awaitMailAuthSlots(t, slots, 4, arrival-4)
	}
	releases[0]()
	// releasing twice frees one slot, once
	releases[0]()
	if first := <-taken; first != 5 {
		t.Fatalf("arrival %d took the freed slot", first)
	}
	awaitMailAuthSlots(t, slots, 4, 1)
	releases[1]()
	if second := <-taken; second != 6 {
		t.Fatalf("arrival %d took the next slot", second)
	}
	awaitMailAuthSlots(t, slots, 4, 0)
	(<-laterReleases)()
	(<-laterReleases)()
	releases[2]()
	releases[3]()
	awaitMailAuthSlots(t, slots, 0, 0)
}

// A waiter whose context ends leaves the line with its error, and the slot freed next goes to the one behind it.
func TestMailAuthSlotsLeaveTheLineOnContextEnd(t *testing.T) {
	settings := sidecar.DefaultMailAuthSettings()
	settings.CheckSlotMaxCount = 1
	slots := sidecar.NewMailAuthSlots(settings)
	release, err := slots.Take(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gone := make(chan error, 1)
	go func() {
		_, err := slots.Take(ctx)
		gone <- err
	}()
	awaitMailAuthSlots(t, slots, 1, 1)
	next := make(chan func(), 1)
	go func() {
		release, err := slots.Take(context.Background())
		if err != nil {
			t.Error(err)
		}
		next <- release
	}()
	awaitMailAuthSlots(t, slots, 1, 2)
	cancel()
	if err := <-gone; err != context.Canceled {
		t.Fatalf("a waiter left with %v", err)
	}
	awaitMailAuthSlots(t, slots, 1, 1)
	release()
	(<-next)()
	awaitMailAuthSlots(t, slots, 0, 0)
}

// A message that waits 30 s for a slot still gets its whole 30 s: its selector answers 20 s after its slot takes it,
// 50 s after it arrived, and it verifies with no deadline cut.
func TestMailAuthSlotsStartTheThirtySecondsAtTheSlot(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.settings.CheckSlotMaxCount = 1
	world.settings.QueryTimeout = time.Minute
	slots := sidecar.NewMailAuthSlots(world.settings)
	// the first message's DMARC record never answers, so its check holds the one slot its whole 30 s
	hostile := testMailAuthMessage("hostile.example", "holds-the-slot")
	world.zone.Fail("_dmarc.hostile.example", dnsmessage.TypeTXT, sidecartest.FakeMailZoneHang)
	signed, err := world.corpus.AlignedAfterInvalid(0)
	if err != nil {
		t.Fatal(err)
	}
	world.zone.SetDelay("good._domainkey.aligned.example", 20*time.Second)
	first := make(chan *sidecar.MailAuthOutcome, 1)
	go func() {
		outcome, err := slots.Check(context.Background(), world.checker, testMailAuthInput(hostile, ""))
		if err != nil {
			t.Error(err)
		}
		first <- outcome
	}()
	awaitMailAuthSlots(t, slots, 1, 0)
	second := make(chan *sidecar.MailAuthOutcome, 1)
	arrival := world.clock.Now()
	go func() {
		outcome, err := slots.Check(context.Background(), world.checker, testMailAuthInput(signed.Bytes, ""))
		if err != nil {
			t.Error(err)
		}
		second <- outcome
	}()
	awaitMailAuthSlots(t, slots, 1, 1)
	awaitMailAuthDeadlines(t, world, 1)
	world.clock.Advance(30 * time.Second)
	if outcome := <-first; outcome.Limits.GetReason()&sidecar.MailAuthLimitDeadline == 0 {
		t.Errorf("the first check's limits %v", outcome.Limits)
	}
	awaitMailZoneDelays(t, world.clock, 1, 20*time.Second)
	world.clock.Advance(20 * time.Second)
	outcome := <-second
	if elapsed := world.clock.Now().Sub(arrival); elapsed != 50*time.Second {
		t.Errorf("finished %s after arriving", elapsed)
	}
	if outcome.Limits != nil || len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_PASS {
		t.Errorf("limits %v, dkim %v", outcome.Limits, outcome.Dkim)
	}
	world.clock.Advance(time.Minute)
}

// FS-121's load row: 15 hostile sessions at once, each a message of 64 maximal signatures and 8 ARC sets, each by its
// own forwarder, whose every lookup never answers, under a query timeout past the check's so each check runs its
// whole 30 s, the receiver's worst case; and a 16th, normal message arriving last, from another sender. Slots take 4 at
// a time, so the normal one's slot comes at 90 s and it completes then, inside 2 min of its last byte, checked in
// full, with at most 8 queries in flight a running message.
func TestMailAuthSlotsFifteenHostileWhileANormalCompletes(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	// past the check's 30 s, and off its multiples, so a query's timer is never taken for a deadline below
	world.settings.QueryTimeout = 45 * time.Second
	slots := sidecar.NewMailAuthSlots(world.settings)
	hostile, err := world.corpus.MaximalSignatures(64)
	if err != nil {
		t.Fatal(err)
	}
	hostileMessage := testMailArcDistinctChain(t, world.zone, hostile.Bytes, 8, world.clock.Now())
	hostileInput := func() *sidecar.MailAuthInput {
		input := testMailAuthInput(hostileMessage, "sender.example")
		input.SenderIp = netip.MustParseAddr("198.51.100.66")
		input.SniHost = "mx.h0st1le.root.example"
		return input
	}
	// every lookup a hostile message makes never answers: DMARC's record, SPF's, its selectors, its sealers, its
	// sender's PTR and its SNI host's TLSA
	for _, name := range []string{"_dmarc.sender.example", "sender.example"} {
		world.zone.Fail(name, dnsmessage.TypeTXT, sidecartest.FakeMailZoneHang)
	}
	for _, signature := range hostile.Signatures {
		world.zone.Fail(sidecartest.MailDkimKeyName(signature.Selector, signature.Domain), dnsmessage.TypeTXT, sidecartest.FakeMailZoneHang)
	}
	for instance := 1; instance <= 8; instance += 1 {
		world.zone.Fail(sidecartest.MailDkimKeyName("arc", fmt.Sprintf("forwarder%d.example", instance)), dnsmessage.TypeTXT, sidecartest.FakeMailZoneHang)
	}
	world.zone.Fail(sidecartest.MailZoneReverseName(netip.MustParseAddr("198.51.100.66")), dnsmessage.TypePTR, sidecartest.FakeMailZoneHang)
	world.zone.Fail("_25._tcp.mx.h0st1le.root.example", sidecartest.MailZoneTypeTlsa, sidecartest.FakeMailZoneHang)
	// the normal sender publishes everything, and signs
	world.publishSender("normal.example")
	normalSigner, err := sidecartest.NewMailDkimSigner("normal.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "normal.example"), normalSigner.KeyRecord())
	normalMessage, err := normalSigner.Sign(testMailAuthMessage("normal.example", "normal"))
	if err != nil {
		t.Fatal(err)
	}

	start := world.clock.Now()
	hostileOutcomes := make(chan *sidecar.MailAuthOutcome, 15)
	for arrival := range 15 {
		go func() {
			outcome, err := slots.Check(context.Background(), world.checker, hostileInput())
			if err != nil {
				t.Error(err)
			}
			hostileOutcomes <- outcome
		}()
		awaitMailAuthSlots(t, slots, min(arrival+1, 4), max(0, arrival+1-4))
	}
	normalOutcome := make(chan *sidecar.MailAuthOutcome, 1)
	go func() {
		outcome, err := slots.Check(context.Background(), world.checker, testMailAuthInput(normalMessage, "normal.example"))
		if err != nil {
			t.Error(err)
		}
		normalOutcome <- outcome
	}()
	awaitMailAuthSlots(t, slots, 4, 12)

	// three rounds of 4 hostile checks, each cut at its 30 s, and then the normal one's slot
	for round := range 3 {
		awaitMailAuthDeadlines(t, world, 4)
		world.clock.Advance(30 * time.Second)
		for range 4 {
			if outcome := <-hostileOutcomes; outcome.Limits.GetReason()&sidecar.MailAuthLimitDeadline == 0 {
				t.Errorf("round %d: a hostile check's limits %v", round, outcome.Limits)
			}
		}
	}
	normal := <-normalOutcome
	elapsed := world.clock.Now().Sub(start)
	if 2*time.Minute <= elapsed {
		t.Errorf("the normal message completed %s after its last byte", elapsed)
	}
	if elapsed != 90*time.Second {
		t.Errorf("the normal message's slot came %s after its last byte", elapsed)
	}
	if normal.Limits != nil || normal.Spf.GetResult() != protocol.SpfVerdict_SPF_PASS || normal.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS ||
		len(normal.Dkim) != 1 || normal.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_PASS || !normal.SniTlsaLive || normal.PtrName != "mail.normal.example" {
		t.Errorf("the normal message was not checked in full: limits %v, spf %v, dmarc %v, dkim %v, ptr %q, tlsa %t",
			normal.Limits, normal.Spf, normal.Dmarc, normal.Dkim, normal.PtrName, normal.SniTlsaLive)
	}
	awaitMailAuthDeadlines(t, world, 3)
	world.clock.Advance(30 * time.Second)
	for range 3 {
		if outcome := <-hostileOutcomes; outcome.Limits.GetReason()&sidecar.MailAuthLimitDeadline == 0 {
			t.Errorf("the last round's limits %v", outcome.Limits)
		}
	}
	if 4*8 < world.zone.MaxInFlight() {
		t.Errorf("%d queries in flight at once", world.zone.MaxInFlight())
	}
	awaitMailAuthSlots(t, slots, 0, 0)
	world.clock.Advance(time.Minute)
}
