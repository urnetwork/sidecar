// §14.8's halt rule (SMTP-M9-16; §22.5's §14 row): every row with a twin just below it, burner labels
// included, the suspension rung reaching §21 once, a lift's recheck, the status hints, and the edge's reload
// on a fake clock.

package smtpedgeservice_test

import (
	"context"
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// The ladder on the fakes, for one network of a tier, which sent recipientCount recipients an hour ago.
type haltWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	store     *sidecartest.FakeSmtpEdgeStore
	sink      *sidecartest.FakeSmtpAbuseSink
	settings  *smtpedgeservice.SmtpEdgeSettings
	quota     *smtpedgeservice.SmtpQuota
	ladder    *smtpedgeservice.SmtpHaltLadder
	networkId sidecar.Id
	clientId  sidecar.Id
	// complaints made, for distinct Message-IDs
	complaintCount int
}

// A tier's limits as the ladder reads them, with QD-199's bounce keys.
func haltLimits(tier string) *sidecar.QuotaLimits {
	limits := proLimits()
	if tier == "free" {
		limits = communityLimits()
	}
	limits.Tier = tier
	limits.Limits[smtpedgeservice.SmtpLimitHardBouncePercent] = 10
	limits.Limits[smtpedgeservice.SmtpLimitHardBounceFloor] = 10
	return limits
}

func newHaltWorld(t *testing.T, tier string, recipientCount uint32) *haltWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	settings := testSettings()
	self := &haltWorld{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		host:      host,
		store:     sidecartest.NewFakeSmtpEdgeStore(clock, nil),
		sink:      sidecartest.NewFakeSmtpAbuseSink(),
		settings:  settings,
		networkId: sidecar.NewId(),
		clientId:  sidecar.NewId(),
	}
	host.Quota.SetLimits(connect.Id(self.networkId), haltLimits(tier))
	quota, err := smtpedgeservice.NewSmtpQuota(ctx, host.ServiceHost(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Breaker().Close)
	self.quota = quota
	ladder, err := smtpedgeservice.NewSmtpHaltLadder(host.ServiceHost(), &smtpedgeservice.SmtpHaltLadderDeps{
		Store:   self.store,
		Lookups: self.store,
		Halts:   self.store,
		Quota:   quota,
		Sink:    self.sink,
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	self.ladder = ladder
	if 0 < recipientCount {
		self.addSend(recipientCount, "sent")
	}
	return self
}

// A send of the network an hour ago with result.
func (self *haltWorld) addSend(recipientCount uint32, result string) {
	self.t.Helper()
	sendId := sha256.Sum256([]byte(sidecar.NewId().String()))
	err := self.store.InsertSends(self.ctx, []*smtpedgeservice.SmtpSendRecord{{
		SendId:          sendId[:smtpedgeservice.SmtpSendIdByteCount],
		NetworkId:       self.networkId,
		ClientId:        self.clientId,
		SendingAddress:  joinSendingAddress,
		RecipientDomain: "receiver.example",
		MxHost:          "mx.receiver.example",
		StartTime:       self.clock.Now().Add(-time.Hour),
		RecipientCount:  recipientCount,
		Result:          result,
	}})
	if err != nil {
		self.t.Fatal(err)
	}
}

// Stores a complaint about a message of its own against domain, then runs the ladder, returning what it set.
func (self *haltWorld) complain(domain string, complaintType string, confidence smtpedgeservice.SmtpConfidence) []*smtpedgeservice.SmtpHalt {
	self.complaintCount += 1
	return self.complainAbout(domain, complaintType, confidence, "<m"+strconv.Itoa(self.complaintCount)+"@"+domain+">")
}

// As complain, about messageId.
func (self *haltWorld) complainAbout(domain string, complaintType string, confidence smtpedgeservice.SmtpConfidence, messageId string) []*smtpedgeservice.SmtpHalt {
	self.t.Helper()
	complaint := &smtpedgeservice.SmtpComplaint{
		ComplaintId:   sidecar.NewId(),
		NetworkId:     self.networkId,
		Reporter:      "loop.example",
		Type:          complaintType,
		ArrivalTime:   self.clock.Now(),
		Domain:        domain,
		MessageIdHash: smtpedgeservice.SmtpMessageIdHash(messageId),
		JoinResult:    string(confidence),
	}
	if err := self.store.InsertComplaint(self.ctx, complaint); err != nil {
		self.t.Fatal(err)
	}
	return self.apply(&smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventComplaint, NetworkId: self.networkId, Time: complaint.ArrivalTime, Complaint: complaint})
}

func (self *haltWorld) apply(event *smtpedgeservice.SmtpHaltEvent) []*smtpedgeservice.SmtpHalt {
	self.t.Helper()
	halts, err := self.ladder.Apply(self.ctx, event)
	if err != nil {
		self.t.Fatalf("apply: %v", err)
	}
	return halts
}

// Fails unless halts is exactly one halt of label with trigger.
func expectHalt(t *testing.T, halts []*smtpedgeservice.SmtpHalt, label string, trigger string) *smtpedgeservice.SmtpHalt {
	t.Helper()
	if len(halts) != 1 || halts[0].Label != label || halts[0].Trigger != trigger {
		t.Fatalf("halts %+v, want one of label %q by %s", haltsText(halts), label, trigger)
	}
	return halts[0]
}

func expectNoHalt(t *testing.T, halts []*smtpedgeservice.SmtpHalt) {
	t.Helper()
	if len(halts) != 0 {
		t.Fatalf("halts %v, want none", haltsText(halts))
	}
}

func haltsText(halts []*smtpedgeservice.SmtpHalt) []string {
	texts := []string{}
	for _, halt := range halts {
		texts = append(texts, halt.Trigger+":"+halt.Label)
	}
	return texts
}

// Past one halt's day.
func (self *haltWorld) nextDay() {
	self.clock.Advance(smtpedgeservice.SmtpHaltDuration + time.Minute)
}

func TestHaltLabelComplaintHaltsTheLabelOnAnyTier(t *testing.T) {
	for _, tier := range []string{"free", "pro", "team"} {
		w := newHaltWorld(t, tier, 1000)
		halt := expectHalt(t, w.complain("otter-1234.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceMedium), "otter-1234", smtpedgeservice.SmtpHaltTriggerLabelComplaint)
		if halt.NetworkId != w.networkId || !halt.StartTime.Equal(w.clock.Now()) {
			t.Fatalf("%s: halt %+v", tier, halt)
		}
		// the twin: a low join halts nothing
		twin := newHaltWorld(t, tier, 1000)
		expectNoHalt(t, twin.complain("otter-1234.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceLow))
	}
}

func TestHaltCommunityFirstComplaintHaltsTheNetwork(t *testing.T) {
	w := newHaltWorld(t, "free", 5)
	expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerCommunityComplaint)
	// the twin: one complaint on Pro, under its rate
	twin := newHaltWorld(t, "pro", 1000)
	expectNoHalt(t, twin.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh))
}

func TestHaltCommunitySecondLabelHaltsTheNetwork(t *testing.T) {
	w := newHaltWorld(t, "free", 5)
	expectHalt(t, w.complain("otter-1234.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "otter-1234", smtpedgeservice.SmtpHaltTriggerLabelComplaint)
	halts := w.complain("heron-5678.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh)
	if len(halts) != 2 || halts[0].Label != "heron-5678" || halts[1].Label != "" || halts[1].Trigger != smtpedgeservice.SmtpHaltTriggerSecondLabel {
		t.Fatalf("halts %v", haltsText(halts))
	}
	// the twin: a second label on Pro halts that label alone
	twin := newHaltWorld(t, "pro", 1000)
	twin.complain("otter-1234.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh)
	expectHalt(t, twin.complain("heron-5678.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "heron-5678", smtpedgeservice.SmtpHaltTriggerLabelComplaint)
}

// Pro halts above 0.5% of the day's recipients, at least 2: at 1,000 recipients the sixth complaint, and
// never one complaint alone.
func TestHaltProRate(t *testing.T) {
	w := newHaltWorld(t, "pro", 1000)
	for range 5 {
		expectNoHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh))
	}
	expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerProRate)

	floor := newHaltWorld(t, "pro", 10)
	expectNoHalt(t, floor.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh))
	expectHalt(t, floor.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerProRate)
}

// Team halts above 0.1%, at least 5: at 5,000 recipients the sixth complaint, and with 100 recipients not
// before the fifth.
func TestHaltTeamRate(t *testing.T) {
	w := newHaltWorld(t, "team", 5000)
	for range 5 {
		expectNoHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh))
	}
	expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerTeamRate)

	floor := newHaltWorld(t, "team", 100)
	for range 4 {
		expectNoHalt(t, floor.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh))
	}
	expectHalt(t, floor.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerTeamRate)
}

func TestHaltFraudHaltsAnyTierWithReview(t *testing.T) {
	w := newHaltWorld(t, "team", 100000)
	expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeFraud, smtpedgeservice.SmtpConfidenceMedium), "", smtpedgeservice.SmtpHaltTriggerFraud)
	reports := w.sink.Reports()
	if len(reports) != 1 || reports[0].Category != smtpedgeservice.SmtpComplaintTypeFraud || reports[0].NetworkId != w.networkId || reports[0].ReporterClass != smtpedgeservice.SmtpReporterClassLoop {
		t.Fatalf("cases %+v", reports)
	}
	twin := newHaltWorld(t, "team", 100000)
	expectNoHalt(t, twin.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeVirus, smtpedgeservice.SmtpConfidenceLow))
	if len(twin.sink.Reports()) != 0 {
		t.Fatal("a low join reached §21")
	}
}

func TestHaltTwoRecordCutsHaltTheNetwork(t *testing.T) {
	w := newHaltWorld(t, "team", 100)
	cut := &smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventRecordCut, NetworkId: w.networkId, Time: w.clock.Now()}
	w.addSend(1, "cut")
	expectNoHalt(t, w.apply(cut))
	w.addSend(1, "cut")
	expectHalt(t, w.apply(cut), "", smtpedgeservice.SmtpHaltTriggerRecordCuts)
}

// Over 10% hard bounces of the day's recipients, at least 10 sent (QD-199): 11 of 100 halt, 10 do not, and 9
// of 9 do not.
func TestHaltHardBouncesHaltTheNetwork(t *testing.T) {
	w := newHaltWorld(t, "pro", 100)
	bounces := func(count uint32) []*smtpedgeservice.SmtpHalt {
		return w.apply(&smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventHardBounces, NetworkId: w.networkId, Time: w.clock.Now(), HardBounceCount: count})
	}
	expectNoHalt(t, bounces(4))
	w.clock.Advance(2 * time.Hour)
	expectNoHalt(t, bounces(6))
	expectHalt(t, bounces(1), "", smtpedgeservice.SmtpHaltTriggerHardBounces)

	floor := newHaltWorld(t, "pro", 9)
	expectNoHalt(t, floor.apply(&smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventHardBounces, NetworkId: floor.networkId, Time: floor.clock.Now(), HardBounceCount: 9}))

	// a bounce more than a day old has left the window
	old := newHaltWorld(t, "pro", 100)
	old.apply(&smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventHardBounces, NetworkId: old.networkId, Time: old.clock.Now(), HardBounceCount: 10})
	old.clock.Advance(26 * time.Hour)
	old.addSend(100, "sent")
	expectNoHalt(t, old.apply(&smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventHardBounces, NetworkId: old.networkId, Time: old.clock.Now(), HardBounceCount: 1}))
}

// Three network halts in 30 days ask §21 to suspend, once; a label's halt is no strike.
func TestHaltThreeHaltsInThirtyDaysReachTheSinkOnce(t *testing.T) {
	w := newHaltWorld(t, "free", 5)
	for day := range 4 {
		w.complain("otter-1234.n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh)
		w.clock.Advance(time.Minute)
		expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerCommunityComplaint)
		suspensions := w.sink.Suspensions()
		want := 0
		if 2 <= day {
			want = 1
		}
		if len(suspensions) != want {
			t.Fatalf("day %d: %d suspensions", day, len(suspensions))
		}
		w.nextDay()
	}
	if request := w.sink.Suspensions()[0]; request.NetworkId != w.networkId || len(request.HaltIds) != 3 {
		t.Fatalf("request %+v", request)
	}
}

// Each (network, Message-ID hash) counts once, and a not-spam cancels its hash.
func TestHaltDuplicateAndNotSpamCountAsSection14_8Says(t *testing.T) {
	w := newHaltWorld(t, "free", 5)
	expectHalt(t, w.complainAbout("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh, "<dup@n1.root.example>"), "", smtpedgeservice.SmtpHaltTriggerCommunityComplaint)
	w.nextDay()
	expectNoHalt(t, w.complainAbout("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh, "<dup@n1.root.example>"))

	cancelled := newHaltWorld(t, "free", 5)
	cancelled.complainAbout("n1.root.example", smtpedgeservice.SmtpComplaintTypeNotSpam, smtpedgeservice.SmtpConfidenceHigh, "<ns@n1.root.example>")
	expectNoHalt(t, cancelled.complainAbout("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh, "<ns@n1.root.example>"))

	// a Pro rate counts a duplicate once: six complaints about five messages stay at 0.5% of 1,000
	rate := newHaltWorld(t, "pro", 1000)
	for index := range 6 {
		messageId := "<r" + strconv.Itoa(min(index, 4)) + "@n1.root.example>"
		expectNoHalt(t, rate.complainAbout("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh, messageId))
	}
}

// A halt hints the network's recent clients HALTED with its retry, and a lift CLEAR (plan-SMTP-wire-gaps#2).
func TestHaltHintsTheSendersStatus(t *testing.T) {
	w := newHaltWorld(t, "free", 5)
	halt := expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerCommunityComplaint)
	hints := w.host.Push.Hints(connect.Id(w.clientId))
	if len(hints) != 1 || hints[0].Topic != sidecar.PushTopicMail || hints[0].Kind != uint32(protocol.MessageType_SMTP_STATUS) {
		t.Fatalf("hints %+v", hints)
	}
	status := &protocol.SmtpStatus{}
	if err := proto.Unmarshal(hints[0].Body, status); err != nil {
		t.Fatal(err)
	}
	if status.Kind != uint32(protocol.SmtpStatusKind_SMTP_STATUS_HALTED) || status.RetryAfterMs != uint32(smtpedgeservice.SmtpHaltDuration.Milliseconds()) {
		t.Fatalf("status %+v", status)
	}
	// a not-spam cancels the one complaint, and the recheck lifts the halt
	w.complainAbout("n1.root.example", smtpedgeservice.SmtpComplaintTypeNotSpam, smtpedgeservice.SmtpConfidenceHigh, "<m1@n1.root.example>")
	lifted, err := w.ladder.Lift(w.ctx, w.networkId, halt.HaltId)
	if err != nil || !lifted {
		t.Fatalf("lifted %v, %v", lifted, err)
	}
	hints = w.host.Push.Hints(connect.Id(w.clientId))
	if err := proto.Unmarshal(hints[len(hints)-1].Body, status); err != nil || status.Kind != uint32(protocol.SmtpStatusKind_SMTP_STATUS_CLEAR) {
		t.Fatalf("last hint %+v, %v", status, err)
	}
}

// A recheck lifts nothing that still holds, and never a cut's halt, which §21 reviews.
func TestHaltLiftKeepsWhatStillHolds(t *testing.T) {
	w := newHaltWorld(t, "free", 5)
	halt := expectHalt(t, w.complain("n1.root.example", smtpedgeservice.SmtpComplaintTypeAbuse, smtpedgeservice.SmtpConfidenceHigh), "", smtpedgeservice.SmtpHaltTriggerCommunityComplaint)
	if lifted, err := w.ladder.Lift(w.ctx, w.networkId, halt.HaltId); err != nil || lifted {
		t.Fatalf("lifted %v, %v", lifted, err)
	}
	cuts := newHaltWorld(t, "team", 100)
	cuts.addSend(1, "cut")
	cuts.addSend(1, "cut")
	cutHalt := expectHalt(t, cuts.apply(&smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventRecordCut, NetworkId: cuts.networkId, Time: cuts.clock.Now()}), "", smtpedgeservice.SmtpHaltTriggerRecordCuts)
	if lifted, err := cuts.ladder.Lift(cuts.ctx, cuts.networkId, cutHalt.HaltId); err != nil || lifted {
		t.Fatalf("a cut's halt lifted %v, %v", lifted, err)
	}
}

// The intake's ladder has no quota: its halt reaches the edge at the edge's next reload, within
// HaltReloadInterval on the fake clock; a Redis wipe loses no halt, since the reload writes it again; and a
// lifted halt admits the next preamble once the edge reloads.
func TestHaltReachesTheEdgeAndALiftAdmitsAgain(t *testing.T) {
	w := newEdgeWorld(t, func(world *edgeWorld) {
		limits := haltLimits("free")
		world.gate.SetFacts(world.networkId, &smtpedgeservice.SmtpGateFacts{
			MailEnableTime: world.clock.Now().Add(-48 * time.Hour),
			Label:          testLabel,
			ReportToken:    testReportToken,
			Limits:         limits,
		})
		world.host.Quota.SetLimits(connect.Id(world.networkId), limits)
	})
	sink := sidecartest.NewFakeSmtpAbuseSink()
	ladder, err := smtpedgeservice.NewSmtpHaltLadder(w.host.ServiceHost(), &smtpedgeservice.SmtpHaltLadderDeps{Store: w.store, Lookups: w.store, Halts: w.store, Sink: sink}, w.settings)
	if err != nil {
		t.Fatal(err)
	}
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK).Abandon(w.ctx)

	complaint := &smtpedgeservice.SmtpComplaint{
		ComplaintId:   sidecar.NewId(),
		NetworkId:     w.networkId,
		Type:          smtpedgeservice.SmtpComplaintTypeAbuse,
		ArrivalTime:   w.clock.Now(),
		Domain:        "n1.root.example",
		MessageIdHash: smtpedgeservice.SmtpMessageIdHash("<one@n1.root.example>"),
		JoinResult:    string(smtpedgeservice.SmtpConfidenceHigh),
	}
	if err := w.store.InsertComplaint(w.ctx, complaint); err != nil {
		t.Fatal(err)
	}
	halts, err := ladder.Apply(w.ctx, &smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventComplaint, NetworkId: w.networkId, Time: complaint.ArrivalTime, Complaint: complaint})
	if err != nil || len(halts) != 1 {
		t.Fatalf("halts %v, %v", halts, err)
	}
	// before the reload the edge has not heard
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK).Abandon(w.ctx)
	w.clock.Advance(w.settings.HaltReloadInterval)
	w.awaitProbes(2)
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED)

	// Redis loses everything; the edge's memory holds, and the next reload writes the flag again
	w.host.Redis.LoseEverything()
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED)
	w.clock.Advance(w.settings.HaltReloadInterval)
	w.awaitProbes(3)
	if value, found, err := w.host.Redis.HashGet(w.ctx, "{smq_"+w.networkId.String()+"}", "h"); err != nil || !found || len(value) == 0 {
		t.Fatalf("the halt's flag after the reload: %q %v %v", value, found, err)
	}

	// a not-spam cancels the complaint; the lift removes the row, and the next reload admits the network
	notSpam := *complaint
	notSpam.ComplaintId = sidecar.NewId()
	notSpam.Type = smtpedgeservice.SmtpComplaintTypeNotSpam
	if err := w.store.InsertComplaint(w.ctx, &notSpam); err != nil {
		t.Fatal(err)
	}
	if lifted, err := ladder.Lift(w.ctx, w.networkId, halts[0].HaltId); err != nil || !lifted {
		t.Fatalf("lifted %v, %v", lifted, err)
	}
	w.clock.Advance(w.settings.HaltReloadInterval)
	w.awaitProbes(4)
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK).Abandon(w.ctx)
}
