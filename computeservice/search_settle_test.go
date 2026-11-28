package computeservice

// SRCH-M13-08: the broker's answers to the signer's reports (search_settle.go) and the report loop's pull
// (search_reports.go), on the search fixture's fake ledger and signer (search_fixture_test.go).

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// Admits requestId's attempt and answers the ticket the signer was given.
func (self *computeSearchFixture) admitTicket(t testing.TB, requestId []byte, attempt uint32) []byte {
	t.Helper()
	before := len(self.signer.signList())
	if recorder, _ := self.authorize(self.request(requestId, attempt)); recorder.Code != http.StatusOK {
		t.Fatalf("attempt %d: %d %s", attempt, recorder.Code, recorder.Body.String())
	}
	signs := self.signer.signList()
	if len(signs) != before+1 {
		t.Fatalf("%d sign requests, want %d", len(signs), before+1)
	}
	return signs[before].GetTicket()
}

// The fixture's minute now, as a report names it.
func (self *computeSearchFixture) minuteS() int64 {
	return self.clock.Now().Unix() / 60 * 60
}

// One pull, failing the test where it errs or did not lease.
func (self *computeSearchFixture) pull(t testing.TB) *ComputeSearchPull {
	t.Helper()
	pull, err := self.admission().Reports().Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !pull.Leased {
		t.Fatal("the pull did not hold the lease")
	}
	return pull
}

// The answer the signer last got for ticket.
func (self *computeSearchFixture) answerOf(ticket []byte) protocol.SearchReportAnswer {
	answer := protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_UNSPECIFIED
	for _, given := range self.signer.answerList() {
		if bytes.Equal(given.GetTicket(), ticket) {
			answer = given.GetAnswer()
		}
	}
	return answer
}

// R2-08's acceptance: attempts 2 and 1 of one request settled in reverse order in one minute, both reports repeated,
// and attempt 3 lapsed: exactly two charges, each at its own key and that minute, each its hold, attempt 3 released.
func TestSearchSettleReverseAttemptsOneMinute(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	requestId := testSearchRequestId("reverse")
	tickets := map[uint32][]byte{}
	for attempt := uint32(1); attempt <= 3; attempt += 1 {
		tickets[attempt] = fixture.admitTicket(t, requestId, attempt)
	}
	minuteS := fixture.minuteS()
	settled := protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED
	fixture.signer.report(tickets[2], settled, minuteS, nil, nil)
	fixture.signer.report(tickets[1], settled, minuteS, nil, nil)
	fixture.signer.report(tickets[3], protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_LAPSED, minuteS, nil, nil)
	if pull := fixture.pull(t); pull.AnsweredCount != 3 {
		t.Fatalf("answered %d of 3", pull.AnsweredCount)
	}
	// both settlements reported again, as after the signer lost the broker's answers
	fixture.signer.report(tickets[2], settled, minuteS, nil, nil)
	fixture.signer.report(tickets[1], settled, minuteS, nil, nil)
	fixture.pull(t)
	charges := fixture.ledger.chargeList()
	if len(charges) != 2 {
		t.Fatalf("%d charges, want 2", len(charges))
	}
	keys := map[sidecar.Id]bool{}
	for _, charge := range charges {
		keys[charge.chargeId] = true
		if charge.minute.Unix() != minuteS || charge.amount != 12*1000*1000 || charge.cost != 10*1000*1000 {
			t.Fatalf("a charge: %+v", charge)
		}
	}
	if !keys[fixture.opKey(fixture.networkId, requestId, 1)] || !keys[fixture.opKey(fixture.networkId, requestId, 2)] {
		t.Fatal("the charges are not attempts 1 and 2's own keys")
	}
	if op := fixture.ledger.op(fixture.opKey(fixture.networkId, requestId, 3)); op == nil || op.state != model.ComputeOpStateVoid {
		t.Fatalf("attempt 3 was not released: %+v", op)
	}
	for attempt, want := range map[uint32]protocol.SearchReportAnswer{
		1: protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED,
		2: protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED,
		3: protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_RELEASED,
	} {
		if answer := fixture.answerOf(tickets[attempt]); answer != want {
			t.Fatalf("attempt %d answered %s, want %s", attempt, answer, want)
		}
	}
	if fixture.metrics.Value("urnetwork_compute_search_authorizations_total", "settled") != 2 ||
		fixture.metrics.Value("urnetwork_compute_search_authorizations_total", "lapsed") != 1 {
		t.Fatal("the settlements and the lapse are not counted once each")
	}
}

// A report sent twice in one pull gets one answer and books one charge.
func TestSearchSettleReportTwice(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	ticket := fixture.admitTicket(t, testSearchRequestId("twice"), 1)
	settled := protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED
	fixture.signer.report(ticket, settled, fixture.minuteS(), nil, nil)
	fixture.signer.report(ticket, settled, fixture.minuteS(), nil, nil)
	fixture.pull(t)
	answers := fixture.signer.answerList()
	if len(answers) != 2 || answers[0].GetAnswer() != answers[1].GetAnswer() || answers[0].GetAnswer() != protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED {
		t.Fatalf("the answers: %v", answers)
	}
	if charges := fixture.ledger.chargeList(); len(charges) != 1 {
		t.Fatalf("%d charges", len(charges))
	}
}

// A ticket {cmpa} does not hold answers unknown, settled or lapsed, and books nothing; an out-of-band one alarms, with
// no network to keep a record with.
func TestSearchSettleUnknownTicket(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	for _, kind := range []protocol.SearchSignerReportKind{
		protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED,
		protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_LAPSED,
		protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND,
	} {
		ticket := bytes.Repeat([]byte{byte(kind)}, 32)
		fixture.signer.report(ticket, kind, fixture.minuteS(), bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 32))
		fixture.pull(t)
		if answer := fixture.answerOf(ticket); answer != protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_UNKNOWN {
			t.Fatalf("%s answered %s", kind, answer)
		}
	}
	if len(fixture.ledger.chargeList()) != 0 || len(fixture.searchFlags.all()) != 0 {
		t.Fatal("an unknown ticket booked a charge or a record")
	}
	if fixture.metrics.Value("urnetwork_compute_alarms_total", computeAlarmSearchOutOfBandUnknown) != 1 {
		t.Fatal("an unknown out-of-band settlement did not alarm")
	}
	// a report of no ticket's size is answered nothing, and comes again
	fixture.signer.report([]byte("short"), protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED, fixture.minuteS(), nil, nil)
	if pull := fixture.pull(t); pull.FailedCount != 1 {
		t.Fatalf("a malformed report: %+v", pull)
	}
}

// A lapsed authorization releases its hold and voids its row: the balance back whole, released.
func TestSearchSettleLapseReleases(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	available := fixture.ledger.available(fixture.networkId)
	requestId := testSearchRequestId("lapse")
	ticket := fixture.admitTicket(t, requestId, 1)
	fixture.signer.report(ticket, protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_LAPSED, fixture.minuteS(), nil, nil)
	fixture.pull(t)
	if answer := fixture.answerOf(ticket); answer != protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_RELEASED {
		t.Fatalf("answered %s", answer)
	}
	if op := fixture.ledger.op(fixture.opKey(fixture.networkId, requestId, 1)); op == nil || op.state != model.ComputeOpStateVoid {
		t.Fatalf("the row: %+v", op)
	}
	if after := fixture.ledger.available(fixture.networkId); after != available {
		t.Fatalf("the balance is %d, want %d", after, available)
	}
}

// An out-of-band settlement is charged, its payee and transaction kept with the network and sidecar as a sanctions
// record, the network flagged for review and paged, its search going on until the review.
func TestSearchSettleOutOfBand(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	ticket := fixture.admitTicket(t, testSearchRequestId("out of band"), 1)
	payee := bytes.Repeat([]byte{0x33}, 20)
	transaction := bytes.Repeat([]byte{0x44}, 32)
	fixture.signer.report(ticket, protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND, fixture.minuteS(), payee, transaction)
	fixture.pull(t)
	if answer := fixture.answerOf(ticket); answer != protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED {
		t.Fatalf("answered %s", answer)
	}
	if charges := fixture.ledger.chargeList(); len(charges) != 1 {
		t.Fatalf("%d charges", len(charges))
	}
	flags := fixture.searchFlags.all()
	if len(flags) != 1 || flags[0].Reason != model.ComputeSearchFlagReasonOutOfBand || flags[0].NetworkId != fixture.networkId ||
		flags[0].SidecarId != fixture.sidecarId || !bytes.Equal(flags[0].Payee, payee) || !bytes.Equal(flags[0].Transaction, transaction) {
		t.Fatalf("the record: %+v", flags)
	}
	if fixture.metrics.Value("urnetwork_compute_alarms_total", ComputeAlarmSearchSanctionsRecord) != 1 {
		t.Fatal("the record did not page")
	}
	if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("after the flag"), 1)); recorder.Code != http.StatusOK {
		t.Fatalf("a flagged network's search was suspended: %d %s", recorder.Code, recorder.Body.String())
	}
}

// A record write that fails answers nothing, and the next pull keeps the record and charges nothing more.
func TestSearchSettleOutOfBandRecordRetried(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	ticket := fixture.admitTicket(t, testSearchRequestId("record retried"), 1)
	fixture.signer.report(ticket, protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND, fixture.minuteS(), bytes.Repeat([]byte{5}, 20), bytes.Repeat([]byte{6}, 32))
	func() {
		fixture.searchFlags.stateLock.Lock()
		defer fixture.searchFlags.stateLock.Unlock()
		fixture.searchFlags.failing = true
	}()
	if pull := fixture.pull(t); pull.AnsweredCount != 0 || pull.FailedCount != 1 {
		t.Fatalf("a failed record answered: %+v", pull)
	}
	func() {
		fixture.searchFlags.stateLock.Lock()
		defer fixture.searchFlags.stateLock.Unlock()
		fixture.searchFlags.failing = false
	}()
	fixture.pull(t)
	if len(fixture.searchFlags.all()) != 1 || len(fixture.ledger.chargeList()) != 1 {
		t.Fatal("the retried report did not keep one record and one charge")
	}
}

// After settlement nothing joins the payment to its network: {cmpa} keeps the answer alone under the ticket, the index
// is gone, the ledger's rows and charges name no ticket, no line was written, and no other store holds the ticket.
func TestSearchSettleKeepsNoJoin(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	ticket := fixture.admitTicket(t, testSearchRequestId("no join"), 1)
	fixture.signer.report(ticket, protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED, fixture.minuteS(), nil, nil)
	fixture.pull(t)
	ticketHex := hex.EncodeToString(ticket)
	for key, value := range fixture.admissionsRedis.Dump() {
		switch {
		case key == computeSearchTicketKey(ticket):
			if len(value) != 3 || value[1] != byte(computeSearchTicketAnswered) {
				t.Fatalf("the ticket's record still holds %d bytes", len(value))
			}
		case strings.HasPrefix(key, ComputeSearchAdmissionsRedisKey()+computeSearchIndexKeyPart):
			t.Fatalf("the index %s outlived the answer", key)
		case bytes.Contains(value, fixture.networkId[:]):
			t.Fatalf("{cmpa}'s %s names the network", key)
		}
	}
	for key, value := range fixture.redis.Dump() {
		if strings.Contains(key, ticketHex) || bytes.Contains(value, ticket) {
			t.Fatalf("the host's Redis holds the ticket under %s", key)
		}
	}
	for _, charge := range fixture.ledger.chargeList() {
		if bytes.Contains(charge.chargeId[:], ticket[:8]) {
			t.Fatal("a charge's key holds the ticket")
		}
	}
	if lines := fixture.serviceLog.lines(); len(lines) != 0 {
		t.Fatalf("%d service log lines", len(lines))
	}
	if len(fixture.searchFlags.all()) != 0 {
		t.Fatal("a settlement kept a record")
	}
}

// Two broker instances pull under one lease: the second finds it held and pulls nothing, until the first gives it up.
func TestSearchReportLoopOnePuller(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	second := newComputeSearchFixture(t, &computeSearchFixtureOptions{sharedWith: fixture})
	ticket := fixture.admitTicket(t, testSearchRequestId("one puller"), 1)
	fixture.signer.report(ticket, protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED, fixture.minuteS(), nil, nil)
	fixture.pull(t)
	pull, err := second.admission().Reports().Pull(context.Background())
	if err != nil || pull.Leased {
		t.Fatalf("the second instance pulled under the first's lease: %+v %v", pull, err)
	}
	if err := fixture.admission().tickets.unlease(context.Background(), fixture.admission().Reports().holder); err != nil {
		t.Fatal(err)
	}
	if pull, err := second.admission().Reports().Pull(context.Background()); err != nil || !pull.Leased {
		t.Fatalf("the second instance did not take the given-up lease: %+v %v", pull, err)
	}
	if charges := fixture.ledger.chargeList(); len(charges) != 1 {
		t.Fatalf("%d charges", len(charges))
	}
}
