package computeservice

// SRCH-M13-07: POST compute/v1/search/authorize on the engine's fixture with a fake ledger, signer and clock
// (search_fixture_test.go; computetest.Broker has not landed). Each refusal holds nothing it does not undo, and nothing
// reaches the signer before the operation's row stands.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// One admission: the hold at the authorization's value times the markup ($0.012 at $0.01), its row standing before the
// signer saw the ticket, and the sign request carrying the ticket, the amount, the minute and the sealed payee unread,
// whose sealed answer comes back as the signer gave it.
func TestSearchAdmitHoldsAndRelays(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	requestId := testSearchRequestId("holds")
	opKey := fixture.opKey(fixture.networkId, requestId, 1)
	rowsAtSign := []string{}
	fixture.signer.set(func(signer *fakeSearchSigner) {
		signer.onSign = func(request *protocol.SearchSignRequest) {
			op := fixture.ledger.op(opKey)
			if op == nil || op.state != model.ComputeOpStateOpen {
				rowsAtSign = append(rowsAtSign, "none")
				return
			}
			rowsAtSign = append(rowsAtSign, "open")
		}
	})
	request := fixture.request(requestId, 1)
	recorder, response := fixture.authorize(request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("answered %d %s", recorder.Code, recorder.Body.String())
	}
	op := fixture.ledger.op(opKey)
	if op == nil || op.state != model.ComputeOpStateOpen || op.hold != 12*1000*1000 {
		t.Fatalf("the hold: %+v", op)
	}
	if minute := fixture.clock.Now().UTC().Truncate(time.Minute); !op.minute.Equal(minute) {
		t.Fatalf("the row's minute %s, want %s", op.minute, minute)
	}
	if len(rowsAtSign) != 1 || rowsAtSign[0] != "open" {
		t.Fatalf("the row at the signer's sight: %v", rowsAtSign)
	}
	signs := fixture.signer.signList()
	if len(signs) != 1 {
		t.Fatalf("%d sign requests", len(signs))
	}
	sign := signs[0]
	if len(sign.GetTicket()) != 32 || sign.GetAmount() != 10_000 || !bytes.Equal(sign.GetSealedPayee(), request.GetSealedPayee()) ||
		sign.GetMinuteS() != fixture.clock.Now().Unix()/60*60 {
		t.Fatalf("the sign request: %v", sign)
	}
	if !bytes.Equal(response.GetSealedAuthorization(), fakeSearchAuthorization(sign)) {
		t.Fatal("the sealed authorization is not the signer's")
	}
	if fixture.metrics.Value("urnetwork_compute_search_authorizations_total", "authorized") != 1 {
		t.Fatal("the authorization is not counted")
	}
	record, err := fixture.admission().tickets.read(fixture.ctx, sign.GetTicket())
	if err != nil || record == nil || record.state != computeSearchTicketAdmitted || record.opKey != opKey {
		t.Fatalf("{cmpa}'s record: %+v %v", record, err)
	}
}

// Each refusal before or after the hold, answered with its code and reason, the hold undone and nothing signed.
func TestSearchAdmitRefusals(t *testing.T) {
	type refusalCase struct {
		name string
		// the broker's search settings, beside the fixture's
		settings func(settings *ComputeSearchSettings)
		// before the searches before it
		setup   func(fixture *computeSearchFixture)
		prepare func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest)
		// searches admitted before the refused one, each its own request id
		before int
		code   ComputeRefusalCode
		reason string
	}
	cases := []refusalCase{
		{name: "catalog_stale", code: ComputeRefusalCatalogStale, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			request.CatalogVersion = 9
		}},
		{name: "asset", code: ComputeRefusalInvalid, reason: ComputeSearchInvalidReasonAsset, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			request.Asset = bytes.Repeat([]byte{7}, 20)
		}},
		{name: "network", code: ComputeRefusalInvalid, reason: ComputeSearchInvalidReasonNetwork, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			request.Network = "eip155:11155111"
		}},
		{name: "past the ceiling", code: ComputeRefusalInvalid, reason: ComputeSearchInvalidReasonCeiling, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			request.Amount = 15_001
		}},
		{name: "past the catalog's price", code: ComputeRefusalInvalid, reason: ComputeSearchInvalidReasonPrice, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			request.Amount = 10_100
		}},
		{name: "no search line", code: ComputeRefusalSearchOff, reason: ComputeSearchOffReasonPolicyLine, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.setPolicy(&sidecar.ComputePolicy{})
		}},
		{name: "no clause", code: ComputeRefusalSearchOff, reason: ComputeSearchOffReasonClause, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.ledger.setClause(fixture.networkId, false)
		}},
		{name: "search off", code: ComputeRefusalSearchOff, reason: ComputeSearchOffReasonPolicy, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.setAcl(fixture.networkId, &fakeComputeSearchAcl{rows: &protocol.AclComputeRows{SearchEnabled: false}, allowed: true})
		}},
		{name: "compute:search denied", code: ComputeRefusalSearchOff, reason: ComputeSearchOffReasonQuery, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.setAcl(fixture.networkId, &fakeComputeSearchAcl{allowed: false})
		}},
		{name: "grace", code: ComputeRefusalInsufficientQuota, reason: "balance", prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.ledger.account(fixture.networkId, func(account *fakeSearchAccount) { account.state = model.ComputeAccountStateGrace })
		}},
		{name: "suspended", code: ComputeRefusalInsufficientQuota, reason: "balance", prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.ledger.account(fixture.networkId, func(account *fakeSearchAccount) { account.state = model.ComputeAccountStateSuspended })
		}},
		{name: "below zero", code: ComputeRefusalInsufficientQuota, reason: "balance", prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.ledger.account(fixture.networkId, func(account *fakeSearchAccount) { account.availableNanoUsd = -1 })
		}},
		{name: "promotional credit only", code: ComputeRefusalInsufficientQuota, reason: "balance", prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.ledger.account(fixture.networkId, func(account *fakeSearchAccount) { account.promoNanoUsd = account.availableNanoUsd })
		}},
		{name: "the agent's budget", code: ComputeRefusalInsufficientQuota, reason: "budget", prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			agentId := testComputeId("agent-a")
			request.AgentId = agentId[:]
			fixture.ledger.spend(agentId, model.ComputeBudgetAgent, fixture.clock.Now(), model.DefaultComputeLedgerSettings().DefaultAgentDayNanoUsd)
		}},
		{name: "the device's ceiling", code: ComputeRefusalInsufficientQuota, reason: "budget", prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.ledger.spend(fixture.sidecarId, model.ComputeBudgetCeiling, fixture.clock.Now(), model.DefaultComputeLedgerSettings().DefaultDeviceCeilingDayNanoUsd)
		}},
		{name: "day_max", before: 1, code: ComputeRefusalRateLimited, reason: ComputeSearchRateLimitedReasonDay, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			fixture.setAcl(fixture.networkId, &fakeComputeSearchAcl{rows: &protocol.AclComputeRows{SearchEnabled: true, SearchDayMax: 1}, allowed: true})
		}},
		{name: "the search cap past day_max", before: 1, code: ComputeRefusalRateLimited, reason: ComputeSearchRateLimitedReasonDay, setup: func(fixture *computeSearchFixture) {
			fixture.setAcl(fixture.networkId, &fakeComputeSearchAcl{rows: &protocol.AclComputeRows{SearchEnabled: true, SearchDayMax: 2000}, allowed: true})
			fixture.ledger.setCap(fixture.networkId, 1)
		}},
		{name: "the network's rate", before: 20, code: ComputeRefusalRateLimited, reason: ComputeSearchRateLimitedReasonRate, settings: func(settings *ComputeSearchSettings) {
			settings.GlobalWindowCount = 1000
		}},
		{name: "the global limiter", before: 10, code: ComputeRefusalRateLimited, reason: ComputeSearchRateLimitedReasonGlobal},
		{name: "a fourth attempt", code: ComputeRefusalInvalid, reason: ComputeSearchInvalidReasonRequest, prepare: func(fixture *computeSearchFixture, request *protocol.ComputeSearchAuthorizeRequest) {
			request.Attempt = 4
		}},
	}
	for _, c := range cases {
		settings := DefaultComputeEngineSettings()
		settings.Search.ReportPollInterval = 0
		if c.settings != nil {
			c.settings(settings.Search)
		}
		fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{settings: settings})
		if c.setup != nil {
			c.setup(fixture)
		}
		admittedSigns := 0
		for i := 0; i < c.before; i += 1 {
			if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId(c.name+"-before-"+string(rune('a'+i))), 1)); recorder.Code != http.StatusOK {
				t.Fatalf("%s: search %d before answered %d %s", c.name, i, recorder.Code, recorder.Body.String())
			}
			admittedSigns += 1
		}
		request := fixture.request(testSearchRequestId(c.name), 1)
		if c.prepare != nil {
			c.prepare(fixture, request)
		}
		available := fixture.ledger.available(fixture.networkId)
		recorder, _ := fixture.authorize(request)
		requireComputeSearchRefusal(t, recorder, c.code, c.reason)
		if open := fixture.ledger.openCount(); open != c.before {
			t.Errorf("%s: %d holds stand, want the %d before it", c.name, open, c.before)
		}
		if after := fixture.ledger.available(fixture.networkId); after != available {
			t.Errorf("%s: the balance moved from %d to %d", c.name, available, after)
		}
		if signs := len(fixture.signer.signList()); signs != admittedSigns {
			t.Errorf("%s: %d sign requests, want %d", c.name, signs, admittedSigns)
		}
	}
}

// Two networks at the global rate each get half of a window before either takes more, once both are active.
func TestSearchAdmitEqualShare(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	_, otherToken := fixture.addNetwork("b")
	count := 0
	authorize := func(token string) int {
		count += 1
		recorder, _ := fixture.authorizeAs(token, fixture.request(testSearchRequestId("share-"+string(rune('a'+count%26))+string(rune('a'+count/26))), 1))
		return recorder.Code
	}
	// a window where both search, so each is active in the window before the next
	if code := authorize(""); code != http.StatusOK {
		t.Fatalf("the first network's warm-up search answered %d", code)
	}
	if code := authorize(otherToken); code != http.StatusOK {
		t.Fatalf("the second network's warm-up search answered %d", code)
	}
	fixture.clock.Advance(time.Second)
	admitted := map[string]int{}
	for i := 0; i < 10; i += 1 {
		if authorize("") == http.StatusOK {
			admitted["a"] += 1
		}
	}
	for i := 0; i < 10; i += 1 {
		if authorize(otherToken) == http.StatusOK {
			admitted["b"] += 1
		}
	}
	if admitted["a"] != 5 || admitted["b"] != 5 {
		t.Fatalf("admitted %v, want 5 each", admitted)
	}
	if code := authorize(""); code == http.StatusOK {
		t.Fatal("a network took more than its share of a full window")
	}
}

// Attempts 1 to 3 of one request are each their own operation and hold; a fourth is refused.
func TestSearchAdmitAttempts(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	requestId := testSearchRequestId("attempts")
	for attempt := uint32(1); attempt <= 3; attempt += 1 {
		if recorder, _ := fixture.authorize(fixture.request(requestId, attempt)); recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d: %d %s", attempt, recorder.Code, recorder.Body.String())
		}
		if op := fixture.ledger.op(fixture.opKey(fixture.networkId, requestId, int16(attempt))); op == nil || op.state != model.ComputeOpStateOpen {
			t.Fatalf("attempt %d holds nothing", attempt)
		}
	}
	if open := fixture.ledger.openCount(); open != 3 {
		t.Fatalf("%d holds, want 3", open)
	}
	recorder, _ := fixture.authorize(fixture.request(requestId, 4))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalInvalid, ComputeSearchInvalidReasonRequest)
	if open := fixture.ledger.openCount(); open != 3 {
		t.Fatalf("the fourth attempt held: %d holds", open)
	}
}

// A retry of an admitted request id and attempt gets the same sealed bytes from one ticket, with no second hold; one
// with another amount is refused, and the first admission stands.
func TestSearchAdmitRetrySameAttempt(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	request := fixture.request(testSearchRequestId("retry"), 1)
	_, first := fixture.authorize(request)
	_, again := fixture.authorize(request)
	if first == nil || again == nil || !bytes.Equal(first.GetSealedAuthorization(), again.GetSealedAuthorization()) {
		t.Fatal("the retry did not answer the same sealed bytes")
	}
	signs := fixture.signer.signList()
	if len(signs) != 2 || !bytes.Equal(signs[0].GetTicket(), signs[1].GetTicket()) {
		t.Fatalf("the retry was not signed under the first ticket: %d", len(signs))
	}
	if open := fixture.ledger.openCount(); open != 1 {
		t.Fatalf("%d holds", open)
	}
	if events := fixture.ledger.eventList(); len(events) != 1 {
		t.Fatalf("the ledger moved %v", events)
	}
	if fixture.metrics.Value("urnetwork_compute_search_authorizations_total", "authorized") != 1 {
		t.Fatal("the retry counted as a second authorization")
	}
	moved := fixture.request(testSearchRequestId("retry"), 1)
	moved.Amount = 9_000
	recorder, _ := fixture.authorize(moved)
	requireComputeSearchRefusal(t, recorder, ComputeRefusalInvalid, ComputeSearchInvalidReasonRetry)
	if open := fixture.ledger.openCount(); open != 1 {
		t.Fatal("a refused retry released the first admission")
	}
}

// Two admissions of one request id and attempt at once: one holds and signs, the other answers the same ticket or
// capacity, and never a second hold.
func TestSearchAdmitConcurrentRetryHoldsOnce(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	request := fixture.request(testSearchRequestId("concurrent"), 1)
	codes := make([]int, 2)
	waitGroup := sync.WaitGroup{}
	for i := range codes {
		waitGroup.Go(func() {
			recorder, _ := fixture.authorize(request)
			codes[i] = recorder.Code
		})
	}
	waitGroup.Wait()
	if open := fixture.ledger.openCount(); open != 1 {
		t.Fatalf("%d holds for one request id and attempt (%v)", open, codes)
	}
	tickets := map[string]bool{}
	for _, sign := range fixture.signer.signList() {
		tickets[hex.EncodeToString(sign.GetTicket())] = true
	}
	if len(tickets) != 1 {
		t.Fatalf("%d tickets signed", len(tickets))
	}
}

// The signer refused the payee: the hold released, the payee kept with the network, sidecar and time as a sanctions
// record, a page, and the network's search suspended until reviewed, here and at a second broker.
func TestSearchAdmitPayeeRefused(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	payee := bytes.Repeat([]byte{0x5a}, 20)
	fixture.signer.set(func(signer *fakeSearchSigner) {
		signer.refusal = protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_PAYEE_REFUSED
		signer.refusePayee = payee
	})
	requestId := testSearchRequestId("refused payee")
	recorder, _ := fixture.authorize(fixture.request(requestId, 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalPayeeRefused, "")
	if op := fixture.ledger.op(fixture.opKey(fixture.networkId, requestId, 1)); op == nil || op.state != model.ComputeOpStateVoid {
		t.Fatalf("the hold was not released: %+v", op)
	}
	flags := fixture.searchFlags.all()
	if len(flags) != 1 || flags[0].Reason != model.ComputeSearchFlagReasonPayeeRefused || flags[0].NetworkId != fixture.networkId ||
		flags[0].SidecarId != fixture.sidecarId || !bytes.Equal(flags[0].Payee, payee) || flags[0].Transaction != nil ||
		!flags[0].FlagTime.Equal(fixture.clock.Now().UTC()) {
		t.Fatalf("the sanctions record: %+v", flags)
	}
	if fixture.metrics.Value("urnetwork_compute_alarms_total", ComputeAlarmSearchSanctionsRecord) != 1 {
		t.Fatal("the record did not page")
	}
	fixture.signer.set(func(signer *fakeSearchSigner) {
		signer.refusal = protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_UNSPECIFIED
	})
	recorder, _ = fixture.authorize(fixture.request(testSearchRequestId("after the refusal"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalSearchOff, ComputeSearchOffReasonReview)
	second := newComputeSearchFixture(t, &computeSearchFixtureOptions{sharedWith: fixture})
	recorder, _ = second.authorize(second.request(testSearchRequestId("at the second broker"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalSearchOff, ComputeSearchOffReasonReview)
	// the operator's review clears it, past the cache's age
	fixture.searchFlags.review(fixture.networkId, fixture.clock.Now())
	fixture.clock.Advance(DefaultComputeSearchSettings().SuspensionCacheMaxAge)
	if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("after the review"), 1)); recorder.Code != http.StatusOK {
		t.Fatalf("after the review: %d %s", recorder.Code, recorder.Body.String())
	}
}

// Each of the signer's other refusals releases the hold and drops the ticket, answering as the device reads it; an
// unreachable signer answers capacity with the hold released.
func TestSearchAdmitSignerRefusals(t *testing.T) {
	cases := []struct {
		refusal protocol.SearchSignRefusal
		failing bool
		code    ComputeRefusalCode
		reason  string
	}{
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_RATE_LIMITED, code: ComputeRefusalRateLimited, reason: "signer_rate"},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_UNSETTLED_CAP, code: ComputeRefusalRateLimited, reason: "unsettled_cap"},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_DAY_CAP, code: ComputeRefusalRateLimited, reason: "day_cap"},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_NONCE_REUSED, code: ComputeRefusalInvalid, reason: "nonce_reused"},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_CEILING, code: ComputeRefusalInvalid, reason: ComputeSearchInvalidReasonCeiling},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_SEAL_INVALID, code: ComputeRefusalInvalid, reason: "seal"},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_LISTS_STALE, code: ComputeRefusalCapacity, reason: "lists_stale"},
		{refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_STOPPED, code: ComputeRefusalCapacity, reason: "stopped"},
		{failing: true, code: ComputeRefusalCapacity, reason: ComputeSearchCapacityReasonSigner},
	}
	for _, c := range cases {
		fixture := newComputeSearchFixture(t, nil)
		fixture.signer.set(func(signer *fakeSearchSigner) {
			signer.refusal = c.refusal
			signer.failing = c.failing
		})
		requestId := testSearchRequestId("signer refusal")
		recorder, _ := fixture.authorize(fixture.request(requestId, 1))
		requireComputeSearchRefusal(t, recorder, c.code, c.reason)
		if open := fixture.ledger.openCount(); open != 0 {
			t.Errorf("%s: %d holds stand", c.refusal, open)
		}
		if len(fixture.searchFlags.all()) != 0 {
			t.Errorf("%s kept a sanctions record", c.refusal)
		}
		for key := range fixture.admissionsRedis.Dump() {
			if strings.Contains(key, computeSearchTicketKeyPart) || strings.Contains(key, computeSearchIndexKeyPart) {
				t.Errorf("%s left {cmpa}'s %s", c.refusal, key)
			}
		}
	}
}

// The request's outcome counts reach {cmpo}'s hour by class, across all networks, with no network in any field, and a
// retry adds nothing; counts past the network's searches today are dropped whole.
func TestSearchAdmitOutcomesHourlyOnly(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	request := fixture.request(testSearchRequestId("outcomes"), 1)
	request.Outcomes = &protocol.SearchOutcomes{Ok: 1}
	fixture.authorize(request)
	fixture.authorize(request)
	second := fixture.request(testSearchRequestId("outcomes 2"), 1)
	second.Outcomes = &protocol.SearchOutcomes{Ok: 1, Timeout: 1}
	fixture.authorize(second)
	swamping := fixture.request(testSearchRequestId("outcomes 3"), 1)
	swamping.Outcomes = &protocol.SearchOutcomes{ProviderError: 1000}
	fixture.authorize(swamping)
	hour := DefaultComputeSearchSettings().outcomeHourAt(fixture.clock.Now())
	fields, err := fixture.redis.HashGetAll(fixture.ctx, ComputeSearchOutcomesRedisKey())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		computeSearchOutcomeField(hour, model.ComputeSearchOutcomeOk):      "2",
		computeSearchOutcomeField(hour, model.ComputeSearchOutcomeTimeout): "1",
	}
	if len(fields) != len(want) {
		t.Fatalf("{cmpo} holds %v", fields)
	}
	for field, value := range want {
		if string(fields[field]) != value {
			t.Fatalf("{cmpo}'s %s is %q, want %s", field, fields[field], value)
		}
	}
	networkHex := sidecar.EvsKeyId(fixture.networkId)
	for field, value := range fields {
		if strings.Contains(field, networkHex) || bytes.Contains(value, fixture.networkId[:]) {
			t.Fatalf("{cmpo} names the network: %s", field)
		}
	}
	if fixture.metrics.Value("urnetwork_compute_search_outcomes_total", "ok") != 2 ||
		fixture.metrics.Value("urnetwork_compute_search_outcomes_total", "provider_error") != 0 {
		t.Fatal("the outcomes' counter does not match {cmpo}")
	}
}

// No payee, nonce or sealed byte anywhere the broker keeps or says anything, and no line per authorization: a real
// sealed payee is relayed and the signer refused it, so even the refusal's path is scanned.
func TestSearchAdmitNoPayeeNoNonce(t *testing.T) {
	log := &recordingComputeLogger{}
	fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{log: log})
	payTo := sidecar.WebSearchAddress{}
	copy(payTo[:], bytes.Repeat([]byte{0x42}, 20))
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed, _, err := sidecar.WebSearchSealPayee(fixture.line.SignerKey, &protocol.SearchPayee{PayTo: payTo[:], Nonce: nonce},
		&sidecar.WebSearchSealBinding{Amount: 10_000, Asset: fixture.line.Asset, Network: fixture.line.Network}, sidecar.DefaultWebSearchSettings())
	if err != nil {
		t.Fatal(err)
	}
	for i, label := range []string{"sealed a", "sealed b"} {
		request := fixture.request(testSearchRequestId(label), 1)
		request.SealedPayee = sealed
		if i == 1 {
			fixture.signer.set(func(signer *fakeSearchSigner) {
				signer.refusal = protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_RATE_LIMITED
			})
		}
		fixture.authorize(request)
	}
	secrets := [][]byte{payTo[:], nonce, sealed, []byte(hex.EncodeToString(payTo[:])), []byte(hex.EncodeToString(nonce)), []byte(hex.EncodeToString(sealed))}
	for key, value := range fixture.dumpRedis() {
		for _, secret := range secrets {
			if bytes.Contains([]byte(key), secret) || bytes.Contains(value, secret) {
				t.Fatalf("Redis's %s holds a payee, nonce or sealed byte", key)
			}
		}
	}
	for _, op := range fixture.ledger.ops {
		if bytes.Contains(op.requestId[:], payTo[:4]) {
			t.Fatal("a row names the payee")
		}
	}
	if lines := fixture.serviceLog.lines(); len(lines) != 0 {
		t.Fatalf("%d service log lines", len(lines))
	}
	if lines := log.lines(); len(lines) != 0 {
		t.Fatalf("the engine logged %v", lines)
	}
	if dump := strings.Join(fixture.metrics.Dump(), "\n"); strings.Contains(dump, hex.EncodeToString(payTo[:])) || strings.Contains(dump, sidecar.EvsKeyId(fixture.networkId)) {
		t.Fatal("a metric names the payee or the network")
	}
}

// {cmpa}'s instance keeping snapshots or an append-only file refuses every search, as does one whose persistence was
// never read, while the rest of the broker serves on.
func TestSearchAdmitRefusesPersistentRedis(t *testing.T) {
	for _, persistence := range []*ComputeRedisPersistence{{Snapshots: true}, {AppendOnly: true}} {
		fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{persistence: persistence})
		recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("persistent"), 1))
		requireComputeSearchRefusal(t, recorder, ComputeRefusalCapacity, ComputeSearchCapacityReasonAdmissions)
		if fixture.metrics.Value("urnetwork_compute_alarms_total", "search_admissions_persistent") != 1 {
			t.Fatal("a persistent {cmpa} did not alarm")
		}
		if open := fixture.ledger.openCount(); open != 0 || len(fixture.signer.signList()) != 0 {
			t.Fatal("a search was held or signed on a persistent {cmpa}")
		}
		if !fixture.engine.Ready() {
			t.Fatal("the broker stopped serving")
		}
	}
	unread := newComputeSearchFixture(t, &computeSearchFixtureOptions{noPersistenceReader: true})
	recorder, _ := unread.authorize(unread.request(testSearchRequestId("unread"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalCapacity, ComputeSearchCapacityReasonAdmissions)
}

// The real ledger refuses the search path until BAL-M13-02 lands its script, and the clause reads not accepted until
// BAL-M13-03: each search is refused, never held some other way.
func TestSearchAdmitRealLedgerFailsClosed(t *testing.T) {
	ledger := NewComputeSearchLedger(nil, nil)
	accepted, err := ledger.ClauseAccepted(context.Background(), testComputeId("network-a"))
	if err != nil || accepted {
		t.Fatalf("the clause read %v %v before BAL-M13-03", accepted, err)
	}
	if _, err := ledger.DeleteBefore(context.Background(), time.Now(), 1); err != ErrComputeSearchLedgerUnbuilt {
		t.Fatalf("the purge's deletion answered %v before BAL-M13-02", err)
	}
	fixture := newComputeSearchFixture(t, nil)
	real := newComputeFixture(t, &computeFixtureOptions{
		handlers:     map[string]ComputeHandler{ComputeRouteSearchAuthorize: computeSearchAuthorizeHandler},
		catalogStore: fixture.catalog,
		sharedWith:   fixture.computeFixture,
		editDeps: func(deps *ComputeEngineDeps) {
			deps.Policy = func() *sidecar.ComputePolicy { return fixture.policy }
			deps.SearchSigner = fixture.signer
			// BAL's ledger, which the hold path refuses before it reaches any store; its clause as BAL-M13-03's would read
			// an accepting network's
			deps.SearchLedger = &clauseAcceptingLedger{ComputeSearchLedger: NewComputeSearchLedger(nil, nil)}
			deps.AdmissionsPersistence = func(ctx context.Context) (*ComputeRedisPersistence, error) { return &ComputeRedisPersistence{}, nil }
			deps.testSearch.acl = func(caller *ComputeCaller) computeSearchAcl { return &fakeComputeSearchAcl{allowed: true} }
		},
	})
	body := fixture.request(testSearchRequestId("real ledger"), 1)
	recorder := real.serve(http.MethodPost, "/v1/search/authorize", real.token(), string(mustMarshal(t, body)), nil)
	requireComputeSearchRefusal(t, recorder, ComputeRefusalCapacity, ComputeSearchCapacityReasonLedger)
	if len(fixture.signer.signList()) != 0 {
		t.Fatal("the real ledger's refusal reached the signer")
	}
}

// The real ledger, its clause read accepted, as BAL-M13-03's will read for a network that accepted it.
type clauseAcceptingLedger struct {
	ComputeSearchLedger
}

func (self *clauseAcceptingLedger) ClauseAccepted(ctx context.Context, networkId sidecar.Id) (bool, error) {
	return true, nil
}

// message's bytes, or a failed test.
func mustMarshal(t testing.TB, message proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Every line a Logger was given, at any level. Safe for concurrent use.
type recordingComputeLogger struct {
	stateLock sync.Mutex
	entries   []string
}

func (self *recordingComputeLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append(self.entries, line)
}

func (self *recordingComputeLogger) lines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.entries...)
}

func (self *recordingComputeLogger) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *recordingComputeLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *recordingComputeLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *recordingComputeLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *recordingComputeLogger) V(level int32) sidecar.Verbose {
	return &recordingComputeVerbose{log: self}
}

// Every level enabled, so a guarded line is seen too.
type recordingComputeVerbose struct {
	log *recordingComputeLogger
}

func (self *recordingComputeVerbose) Enabled() bool {
	return true
}

func (self *recordingComputeVerbose) Info(args ...any) {
	self.log.add(fmt.Sprint(args...))
}

func (self *recordingComputeVerbose) Infof(format string, args ...any) {
	self.log.add(fmt.Sprintf(format, args...))
}
