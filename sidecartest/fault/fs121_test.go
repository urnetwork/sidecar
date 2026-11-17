//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

package fault

// FS-121 (§22.8; §15.5's reception-time evidence and its bounds, D-MAIL-14; MAIL-M7-27) on T2, through the receiver's
// session: mailworld.MailWorld's router splices each hostile message to the receiver, whose checks run over the
// world's FakeMailZone on its fake clock, and whose deposit into evs's engine is read back by the owner's device before
// its ingest labels it. On it:
//
//   - 64 DKIM signatures with distinct maximal d= and s=, each selector answering after 4.9 s: at most 8 keys looked
//     up, at most 8 queries in flight, 64 queries and 8,192 B of evidence at most, its limits naming the count bound
//     with 64 seen and 8 checked, and 250 once the deposit is durable; the same message with every selector failing
//     looks up 8 keys again and seals them temperror;
//   - ARC: the 8-set chain's newest AMS and seals verified, cv=pass; the 12-set chain cv=incomplete, and the 51-set
//     chain and one lacking instance 3 cv=fail, none of the three asking for a sealer's key;
//   - an aligned valid signature behind 3 invalid ones passes DKIM and DMARC; a spoofed From with 9 aligned bogus
//     signatures is a DMARC fail, labeled opportunistic;
//   - no message whose evidence a bound cut is labeled validated.
//
// The load clause, 15 such sessions at once while a 16th completes within 2 min checked in full, runs at the check
// slots in the root package (TestMailAuthSlotsFifteenHostileWhileANormalCompletes) and is not
// composed here: the review phase drives it through sixteen sessions. T3's run and this row's fault.Builder are the
// review phase's too, so a gate sweep reads FS-121 missing until then.

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// FS-121's slow selector: under the query timeout's 5 s.
const fs121SlowSelector = 4900 * time.Millisecond

// One hostile message through the world: its reply, its deposit's evidence and the zone's queries while it was checked.
type fs121Delivery struct {
	evidence *protocol.MailAuthEvidence
	queries  []sidecartest.FakeMailZoneQuery
	message  *sidecar.MailMessage
}

type fs121World struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	world     *mailworld.MailWorld
	owner     *sidecar.EvsClient
	ingestor  *sidecar.MailIngestor
	recipient string
	ingested  []*sidecar.MailMessage
}

func newFs121World(t *testing.T) *fs121World {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := mailworld.DefaultMailWorldSettings()
	world := mailworld.NewMailWorld(t, host, clock, settings)
	self := &fs121World{t: t, ctx: ctx, clock: clock, world: world, recipient: settings.Addresses[0]}
	self.owner = world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	self.ingestor = world.Ingestor(self.owner, world.Owner.SidecarId, func(message *sidecar.MailMessage) {
		self.ingested = append(self.ingested, message)
	}, nil)
	return self
}

// Delivers message through the router; slowCount > 0 waits for that many lookups in flight and moves the clock past
// the slow selectors' delay before the reply. The deposit's evidence is read back, then the message ingested.
func (self *fs121World) deliver(message *sidecartest.MailCorpusMessage, slowCount int) *fs121Delivery {
	self.t.Helper()
	world := self.world
	before := len(world.Zone.Queries())
	mta := world.Begin(&mailworld.MailWorldSend{
		Sender: netip.MustParseAddr("203.0.113.9"), Sni: world.Settings().MxHost(), From: "sender@" + message.FromDomain, Recipients: []string{self.recipient},
	})
	defer mta.Close()
	type outcome struct {
		reply *sidecartest.MailReply
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		reply, err := mta.Data(message.Bytes)
		done <- outcome{reply: reply, err: err}
	}()
	if 0 < slowCount {
		if err := world.Zone.AwaitInFlight(self.ctx, slowCount); err != nil {
			self.t.Fatal(err)
		}
		self.awaitDelays(slowCount, fs121SlowSelector)
		self.clock.Advance(fs121SlowSelector)
	}
	var result outcome
	select {
	case result = <-done:
	case <-time.After(world.Settings().StepTimeout):
		self.t.Fatalf("%s: no reply to its end of DATA", message.Name)
	}
	if result.err != nil || !result.reply.Is(250) {
		self.t.Fatalf("%s: %s %v", message.Name, result.reply, result.err)
	}
	mta.Quit()
	deposits, err := world.StandingDeposits(self.owner)
	if err != nil || len(deposits) != 1 {
		self.t.Fatalf("%s: %d deposits standing after its 250, %v", message.Name, len(deposits), err)
	}
	delivery := &fs121Delivery{evidence: deposits[0].Trailer.GetEvidence(), queries: world.Zone.Queries()[before:]}
	self.ingested = self.ingested[:0]
	if pass, err := self.ingestor.Ingest(self.ctx); err != nil || pass.Ingested != 1 || len(self.ingested) != 1 {
		self.t.Fatalf("%s: ingest %+v, %v", message.Name, pass, err)
	}
	delivery.message = self.ingested[0]
	if size := proto.Size(delivery.evidence); 8192 < size {
		self.t.Errorf("%s: %d B of evidence", message.Name, size)
	}
	if 64 < len(delivery.queries) {
		self.t.Errorf("%s: %d queries", message.Name, len(delivery.queries))
	}
	if delivery.evidence.GetLimits() != nil && delivery.message.Entry.GetTlsLabel() == protocol.MailTlsLabel_MAIL_TLS_VALIDATED {
		self.t.Errorf("%s: incomplete evidence labeled validated", message.Name)
	}
	return delivery
}

// Waits until count of the zone's answers wait delay from now on the clock, so the clock moves only once every slow
// lookup it means is waiting on it.
func (self *fs121World) awaitDelays(count int, delay time.Duration) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, self.world.Settings().StepTimeout)
	defer cancel()
	for {
		pending, added := self.clock.WatchTimers()
		target := self.clock.Now().Add(delay)
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
			self.t.Fatalf("%d of %d slow answers waiting", set, count)
		}
	}
}

// The key names a delivery's queries asked for.
func fs121KeyQueries(queries []sidecartest.FakeMailZoneQuery) map[string]int {
	names := map[string]int{}
	for _, query := range queries {
		if query.Type == dnsmessage.TypeTXT && strings.Contains(query.Name, "._domainkey.") {
			names[query.Name] += 1
		}
	}
	return names
}

// 64 maximal signatures, slow and then failing: 8 keys looked up each time, the count bound named, 250 each time.
func TestFs121MaximalSignaturesThroughTheReceiver(t *testing.T) {
	self := newFs121World(t)
	corpus := sidecartest.NewMailCorpus(self.world.Zone, self.clock.Now())
	maximal, err := corpus.MaximalSignatures(64)
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range maximal.Signatures {
		self.world.Zone.SetDelay(sidecartest.MailDkimKeyName(signature.Selector, signature.Domain), fs121SlowSelector)
	}
	slow := self.deliver(maximal, 8)
	limits := slow.evidence.GetLimits()
	if limits.GetReason()&1 == 0 || limits.GetDkimSeen() != 64 || limits.GetDkimChecked() != 8 || len(slow.evidence.GetDkim()) != 8 {
		t.Fatalf("the slow message's limits %v, %d dkim entries", limits, len(slow.evidence.GetDkim()))
	}
	for _, dkim := range slow.evidence.GetDkim() {
		if dkim.GetResult() != protocol.DkimVerdict_DKIM_PASS {
			t.Fatalf("a selected valid signature answering in 4.9 s: %v", dkim.GetResult())
		}
	}
	if keys := fs121KeyQueries(slow.queries); len(keys) != 8 {
		t.Fatalf("%d keys looked up", len(keys))
	}
	if inFlight := self.world.Zone.MaxInFlight(); 8 < inFlight {
		t.Fatalf("%d queries in flight", inFlight)
	}
	if !slow.message.Entry.GetAuthResults().GetChecksIncomplete() {
		t.Fatal("a cut check's row does not say so")
	}

	// past the stub's TTL, every selector failing: 8 keys asked again, each temperror
	self.clock.Advance(10 * time.Minute)
	for _, signature := range maximal.Signatures {
		self.world.Zone.SetDelay(sidecartest.MailDkimKeyName(signature.Selector, signature.Domain), 0)
		self.world.Zone.Fail(sidecartest.MailDkimKeyName(signature.Selector, signature.Domain), dnsmessage.TypeTXT, sidecartest.FakeMailZoneServFail)
	}
	failing := self.deliver(maximal, 0)
	if keys := fs121KeyQueries(failing.queries); len(keys) != 8 {
		t.Fatalf("%d keys looked up for the failing selectors", len(keys))
	}
	for _, dkim := range failing.evidence.GetDkim() {
		if dkim.GetResult() != protocol.DkimVerdict_DKIM_TEMPERROR {
			t.Fatalf("a failing selector's signature: %v", dkim.GetResult())
		}
	}
}

// ARC's bounds through the receiver: 8 sets verified, 12 incomplete and 51 or a gap failed, those three with no lookup
// of a sealer's key.
func TestFs121ArcChainsThroughTheReceiver(t *testing.T) {
	self := newFs121World(t)
	corpus := sidecartest.NewMailCorpus(self.world.Zone, self.clock.Now())
	sealerKey := sidecartest.MailDkimKeyName("arc", "forwarder.example")
	eight, err := corpus.ArcChain(8, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	verified := self.deliver(eight, 0)
	if arc := verified.evidence.GetArc(); arc.GetCv() != protocol.ArcVerdict_ARC_PASS || len(arc.GetSets()) == 0 {
		t.Fatalf("the 8-set chain: %v", arc)
	}
	if fs121KeyQueries(verified.queries)[sealerKey] == 0 {
		t.Fatal("the 8-set chain's sealer key was not looked up")
	}
	// past the stub's TTL, so a lookup would reach the zone
	self.clock.Advance(10 * time.Minute)
	for _, chain := range []struct {
		setCount int
		gapAt    int
		want     protocol.ArcVerdict
	}{
		{12, 0, protocol.ArcVerdict_ARC_INCOMPLETE},
		{51, 0, protocol.ArcVerdict_ARC_FAIL},
		{8, 3, protocol.ArcVerdict_ARC_FAIL},
	} {
		message, err := corpus.ArcChain(chain.setCount, chain.gapAt, false)
		if err != nil {
			t.Fatal(err)
		}
		delivery := self.deliver(message, 0)
		if cv := delivery.evidence.GetArc().GetCv(); cv != chain.want {
			t.Errorf("%s: cv=%v, want %v", message.Name, cv, chain.want)
		}
		if count := fs121KeyQueries(delivery.queries)[sealerKey]; count != 0 {
			t.Errorf("%s: the sealer's key asked %d times", message.Name, count)
		}
	}
}

// DKIM's selection through the receiver: an aligned valid signature behind 3 invalid ones passes DKIM and DMARC; a
// spoofed From with 9 aligned bogus signatures fails DMARC, labeled opportunistic.
func TestFs121AlignmentThroughTheReceiver(t *testing.T) {
	self := newFs121World(t)
	corpus := sidecartest.NewMailCorpus(self.world.Zone, self.clock.Now())
	aligned, err := corpus.AlignedAfterInvalid(3)
	if err != nil {
		t.Fatal(err)
	}
	delivery := self.deliver(aligned, 0)
	if results := delivery.message.Entry.GetAuthResults(); results.GetDkim() != protocol.DkimVerdict_DKIM_PASS || results.GetDmarc() != protocol.DmarcVerdict_DMARC_PASS {
		t.Fatalf("an aligned signature behind 3 invalid ones: %v", results)
	}
	spoofed, err := corpus.SpoofedFrom(9)
	if err != nil {
		t.Fatal(err)
	}
	delivery = self.deliver(spoofed, 0)
	if results := delivery.message.Entry.GetAuthResults(); results.GetDmarc() != protocol.DmarcVerdict_DMARC_FAIL || results.GetDkim() == protocol.DkimVerdict_DKIM_PASS {
		t.Fatalf("a spoofed From: %v", results)
	}
	if label := delivery.message.Entry.GetTlsLabel(); label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
		t.Fatalf("a spoofed From labeled %v", label)
	}
}
