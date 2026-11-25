//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The compute client (BAL-M12-17) on a fake api: each route's method, path, query and body and its answer read into
// the client's types; answers out of shape refused whole; a Checkout url that is not Checkout's refused; kind 21 filed
// through the gate with its BudgetFields, and refused unfiled while BAL-M12-16's effect is absent; and compute_low
// raised once per change, on the poll and on a refused hold, in version order, with the poll standing down while a
// generation holds the compute push topic. The loop runs on a clock the test moves, so no test sleeps.

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A host for a compute client: a scripted api, the events it raises, an identity, and a gate that records each
// action and answers as the test says.
type testComputeHost struct {
	api       *SidecarApi
	networkId Id
	events    chan SidecarEvent

	stateLock sync.Mutex
	identity  *SidecarIdentity
	actions   []*SidecarAction
	authorize func(action *SidecarAction) error
}

// A host on transport, with an identity, its events buffered for the test to read.
func newTestComputeHost(t *testing.T, transport *scriptedApiTransport) *testComputeHost {
	t.Helper()
	networkId := NewId()
	return &testComputeHost{
		api:       newTestSidecarApi(t, transport),
		networkId: networkId,
		events:    make(chan SidecarEvent, 64),
		identity:  &SidecarIdentity{NetworkId: networkId, SidecarId: NewId(), ClientId: NewId(), Generation: 1},
	}
}

// The scripted api.
func (self *testComputeHost) computeApi() *SidecarApi {
	return self.api
}

// Buffers the event for the test.
func (self *testComputeHost) emitEvent(event SidecarEvent) {
	self.events <- event
}

// The test's identity, or none.
func (self *testComputeHost) currentIdentity() *SidecarIdentity {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.identity
}

// Records the action, and answers as the test set, approval_pending by default.
func (self *testComputeHost) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.actions = append(self.actions, action)
	if self.authorize != nil {
		return self.authorize(action)
	}
	return &ApprovalPendingError{ApprovalId: NewId()}
}

// Seals the detail under a test key of the config repo, as the device's own sealer does.
func (self *testComputeHost) SealActionDetail5(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5) (*StoredCanonicalAction, error) {
	return NewSealedCanonicalAction5(clear, detail, evsTestRepoKey(evsTestId("compute config repo"), 1), self.networkId, cryptorand.Reader)
}

// What the gate saw.
func (self *testComputeHost) authorized() []*SidecarAction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.actions)
}

// The next event the client raised, failing past a bound that only a missing event reaches.
func (self *testComputeHost) nextEvent(t *testing.T) SidecarEvent {
	t.Helper()
	select {
	case event := <-self.events:
		return event
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
		return SidecarEvent{}
	}
}

// An api of routes: each request answered by its route's function, by method and path; an unknown route 404s.
func testComputeApi(routes map[string]func(request *http.Request, body []byte) (int, string)) *scriptedApiTransport {
	return &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			route, ok := routes[request.Method+" "+request.URL.Path]
			if !ok {
				return syntheticResponse(request, http.StatusNotFound, `{"code":"not_found"}`, nil), nil
			}
			status, answer := route(request, body)
			return syntheticResponse(request, status, answer, nil), nil
		},
	}
}

// A manual client over host: no loop, so a test drives each read.
func newTestComputeClient(t *testing.T, host *testComputeHost, sources *ComputeLabelSources) *ComputeClient {
	t.Helper()
	client, err := NewComputeClient(&ComputeClientArgs{Host: host, Sources: sources, manual: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// A balance answer at state and version.
func testComputeBalanceBody(state ComputeAccountState, version uint64, extra string) string {
	return fmt.Sprintf(`{"available_nano_usd":7500000000,"held_nano_usd":250000000,"balance_nano_usd":7750000000,`+
		`"promo_nano_usd":0,"state":%q,"version":%d,"may_buy":true,"sales_open":false,"update_time_ms":1795000000000%s}`,
		state, version, extra)
}

// A spend figure's JSON.
func testComputeFigures(amount int64, refunded int64, count int64) string {
	return fmt.Sprintf(`{"amount_nano_usd":%d,"refunded_nano_usd":%d,"count":%d,"units":{"input_tokens":%d}}`, amount, refunded, count, count*1000)
}

// Seven days' figures, each amount.
func testComputeSevenDays(amount int64) string {
	days := []string{}
	for range 7 {
		days = append(days, testComputeFigures(amount, 0, 1))
	}
	return "[" + strings.Join(days, ",") + "]"
}

// The window the spend answers name: 2026-11-18 to 2026-11-24.
const testComputeSpendDays = `["2026-11-18","2026-11-19","2026-11-20","2026-11-21","2026-11-22","2026-11-23","2026-11-24"]`

// Each route: its method, path and query as sent, its body, the jwt as bearer, and its answer read into the client's
// types. RaiseBudget's kind 21 is its own test, since it reaches the gate, not a route.
func TestComputeClientCallsEachRoute(t *testing.T) {
	lotId, chargeId, memberId, sidecarId, enclaveId := NewId(), NewId(), NewId(), NewId(), NewId()
	var stateLock sync.Mutex
	bodies := map[string]string{}
	queries := map[string]string{}
	keep := func(route string, request *http.Request, body []byte) {
		stateLock.Lock()
		defer stateLock.Unlock()
		bodies[route] = string(body)
		queries[route] = request.URL.RawQuery
		if request.Header.Get("Authorization") != "Bearer "+testByJwt {
			t.Errorf("%s: authorization %q", route, request.Header.Get("Authorization"))
		}
	}
	routes := map[string]func(request *http.Request, body []byte) (int, string){
		"GET /compute/balance": func(request *http.Request, body []byte) (int, string) {
			keep("balance", request, body)
			return http.StatusOK, testComputeBalanceBody(ComputeAccountStateLow, 7,
				fmt.Sprintf(`,"auto_renew":{"threshold":{"on":false,"below_nano_usd":5000000000,"pack_credits":20,"month_limit_nano_usd":200000000000,"off_reason":"failed"},"monthly":{"on":true,"credits":25,"market":2}},"at_risk_enclave_ids":[%q],"indexer_days_left":4`, enclaveId))
		},
		"POST /compute/checkout": func(request *http.Request, body []byte) (int, string) {
			keep("checkout", request, body)
			return http.StatusOK, `{"url":"https://checkout.stripe.com/c/pay/cs_test_synthetic","expire_time_ms":1795003600000}`
		},
		"GET /compute/auto-renew": func(request *http.Request, body []byte) (int, string) {
			keep("auto_renew", request, body)
			return http.StatusOK, fmt.Sprintf(`{"threshold":{"on":true,"below_nano_usd":5000000000,"pack_credits":20,"month_limit_nano_usd":200000000000,"payer_member_id":%q,"top_ups_today":1},"monthly":{"on":false}}`, memberId)
		},
		"POST /compute/auto-renew": func(request *http.Request, body []byte) (int, string) {
			keep("set_auto_renew", request, body)
			return http.StatusOK, `{"threshold":{"on":false},"monthly":{"on":true,"credits":50,"market":1}}`
		},
		"GET /compute/charges": func(request *http.Request, body []byte) (int, string) {
			keep("charges", request, body)
			return http.StatusOK, fmt.Sprintf(`{"charges":[{"charge_id":%q,"kind":1,"subject_ref":%q,"sidecar_id":%q,"member_id":%q,`+
				`"catalog_id":"chutes-qwen3.8-27b-tee-high","provider":1,"units":{"input_tokens":1200,"output_tokens":300},`+
				`"amount_nano_usd":4500000,"absorbed_nano_usd":0,"start_time_ms":1795000000000,"end_time_ms":1795000004000,`+
				`"settle_time_ms":1795000006000}],"next_cursor":"page-2"}`, chargeId, NewId(), sidecarId, memberId)
		},
		"GET /compute/statement": func(request *http.Request, body []byte) (int, string) {
			keep("statement", request, body)
			return http.StatusOK, fmt.Sprintf(`{"month":"2026-11","rows":[{"day":"2026-11-03","kind":2,"sidecar_id":%q,"member_id":%q,`+
				`"catalog_id":"cpu-2","provider":4,"enclave_id":%q,"units":{"seconds":3600},"amount_nano_usd":120000000,"count":6}],`+
				`"lots":[{"lot_id":%q,"kind":1,"market":1,"amount_nano_usd":25000000000,"remaining_nano_usd":20000000000,"create_time_ms":1794000000000}]}`,
				sidecarId, memberId, enclaveId, lotId)
		},
		"GET /compute/spend": func(request *http.Request, body []byte) (int, string) {
			keep("spend", request, body)
			return http.StatusOK, fmt.Sprintf(`{"by":"provider","days":%s,"first_charge_day":"2026-10-02","held_nano_usd":2580000000,`+
				`"update_time_ms":1795000000000,"lines":[{"kind":1,"total":%s,"days":%s,"rows":[{"provider":1,"total":%s,"days":%s}]}]}`,
				testComputeSpendDays, testComputeFigures(9000000000, 500000000, 40), testComputeSevenDays(100000000),
				testComputeFigures(9000000000, 500000000, 40), testComputeSevenDays(100000000))
		},
		"POST /compute/refund": func(request *http.Request, body []byte) (int, string) {
			keep("refund", request, body)
			return http.StatusOK, fmt.Sprintf(`{"lot_id":%q,"refunded_nano_usd":20000000000}`, lotId)
		},
		"POST /compute/promo/redeem": func(request *http.Request, body []byte) (int, string) {
			keep("redeem", request, body)
			return http.StatusOK, fmt.Sprintf(`{"lot_id":%q,"credit_nano_usd":10000000000,"expire_time_ms":1797600000000}`, lotId)
		},
	}
	host := newTestComputeHost(t, testComputeApi(routes))
	client := newTestComputeClient(t, host, nil)
	ctx := context.Background()

	balance, err := client.Balance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if balance.AvailableNanoUsd != 7500000000 || balance.HeldNanoUsd != 250000000 || balance.BalanceNanoUsd != 7750000000 ||
		balance.State != ComputeAccountStateLow || balance.Version != 7 || !balance.MayBuy || balance.SalesOpen ||
		!slices.Equal(balance.AtRiskEnclaveIds, []Id{enclaveId}) || balance.IndexerDaysLeft == nil || *balance.IndexerDaysLeft != 4 ||
		!balance.UpdateTime.Equal(time.UnixMilli(1795000000000)) {
		t.Errorf("balance %+v", balance)
	}
	if balance.AutoRenew.Threshold.On || balance.AutoRenew.Threshold.OffReason != ComputeAutoRenewOffFailed ||
		!balance.AutoRenew.Monthly.On || balance.AutoRenew.Monthly.Credits != 25 || balance.AutoRenew.Monthly.Market != ComputeMarketAppStore {
		t.Errorf("auto-renew %+v %+v", balance.AutoRenew.Threshold, balance.AutoRenew.Monthly)
	}
	state, err := client.AccountState(ctx)
	if err != nil || state != ComputeAccountStateLow || !state.CanPay() {
		t.Errorf("state %s, %v", state, err)
	}

	checkout, err := client.Checkout(ctx, &ComputeCheckoutArgs{PackCredits: 25, AutoRenew: ComputeAutoRenewThreshold, BelowNanoUsd: 5000000000})
	if err != nil || checkout.Url != "https://checkout.stripe.com/c/pay/cs_test_synthetic" || !checkout.ExpireTime.Equal(time.UnixMilli(1795003600000)) {
		t.Errorf("checkout %+v, %v", checkout, err)
	}
	autoRenew, err := client.AutoRenew(ctx)
	if err != nil || !autoRenew.Threshold.On || autoRenew.Threshold.PayerMemberId == nil || *autoRenew.Threshold.PayerMemberId != memberId ||
		autoRenew.Threshold.TopUpsToday != 1 || autoRenew.Monthly.On {
		t.Errorf("auto-renew %+v, %v", autoRenew, err)
	}
	changed, err := client.SetAutoRenew(ctx, &ComputeAutoRenewChange{Mode: ComputeAutoRenewMonthly, On: true, Credits: 50})
	if err != nil || !changed.Monthly.On || changed.Monthly.Credits != 50 || changed.Threshold.On {
		t.Errorf("changed %+v, %v", changed, err)
	}
	charges, err := client.Charges(ctx, "")
	if err != nil || len(charges.Charges) != 1 || charges.NextCursor != "page-2" {
		t.Fatalf("charges %+v, %v", charges, err)
	}
	charge := charges.Charges[0].Charge
	if charge.ChargeId != chargeId || charge.Kind != ComputeChargeKindInference || charge.SidecarId != sidecarId ||
		charge.MemberId == nil || *charge.MemberId != memberId || charge.Units.InputTokens != 1200 || charge.AmountNanoUsd != 4500000 ||
		!charge.SettleTime.Equal(time.UnixMilli(1795000006000)) {
		t.Errorf("charge %+v", charge)
	}
	if _, err := client.Charges(ctx, "page-2"); err != nil {
		t.Fatal(err)
	}
	statement, err := client.Statement(ctx, "2026-11")
	if err != nil || statement.Month != "2026-11" || len(statement.Rows) != 1 || len(statement.Lots) != 1 ||
		statement.Rows[0].Row.Units.Seconds != 3600 || statement.Lots[0].LotId != lotId || statement.Lots[0].Market != ComputeMarketStripe {
		t.Errorf("statement %+v, %v", statement, err)
	}
	spend, err := client.Spend(ctx, ComputeSpendByProvider)
	if err != nil || len(spend.Lines) != 1 || spend.Lines[0].Service != ComputeServiceInference || len(spend.Lines[0].Rows) != 1 ||
		spend.Lines[0].Rows[0].Name.Text != "chutes" || spend.Lines[0].Total.RefundedNanoUsd != 500000000 ||
		spend.AllTotal.AmountNanoUsd != 9000000000 || spend.AllDays[6].AmountNanoUsd != 100000000 || spend.HeldNanoUsd != 2580000000 {
		t.Errorf("spend %+v, %v", spend, err)
	}
	refund, err := client.Refund(ctx, lotId)
	if err != nil || refund.LotId != lotId || refund.RefundedNanoUsd != 20000000000 {
		t.Errorf("refund %+v, %v", refund, err)
	}
	redemption, err := client.Redeem(ctx, "SPRINGPROMO2026")
	if err != nil || redemption.LotId != lotId || redemption.CreditNanoUsd != 10000000000 {
		t.Errorf("redemption %+v, %v", redemption, err)
	}

	stateLock.Lock()
	defer stateLock.Unlock()
	wantBodies := map[string]string{
		"balance":        "",
		"checkout":       `{"pack_credits":25,"auto_renew":"threshold","below_nano_usd":5000000000}`,
		"auto_renew":     "",
		"set_auto_renew": `{"mode":"monthly","on":true,"credits":50}`,
		"charges":        "",
		"statement":      "",
		"spend":          "",
		"refund":         fmt.Sprintf(`{"lot_id":%q}`, lotId),
		"redeem":         `{"code":"SPRINGPROMO2026"}`,
	}
	for route, want := range wantBodies {
		if got, ok := bodies[route]; !ok || got != want {
			t.Errorf("%s's body %q, want %q", route, got, want)
		}
	}
	wantQueries := map[string]string{
		"charges":   "cursor=page-2&limit=100",
		"statement": "month=2026-11",
		"spend":     "by=provider",
	}
	for route, want := range wantQueries {
		if queries[route] != want {
			t.Errorf("%s's query %q, want %q", route, queries[route], want)
		}
	}
}

// What a route cannot take is refused before anything is sent: a pack §9.5 does not sell, threshold without a pack, a
// monthly plan §9.8 does not offer, a code out of form, a month or a cursor out of form, and a raise of no subject.
func TestComputeClientRefusesArgumentsUnsent(t *testing.T) {
	transport := testComputeApi(map[string]func(request *http.Request, body []byte) (int, string){})
	host := newTestComputeHost(t, transport)
	client := newTestComputeClient(t, host, nil)
	ctx := context.Background()
	for _, args := range []*ComputeCheckoutArgs{
		nil,
		{PackCredits: 5},
		{PackCredits: 20},
		{AutoRenew: ComputeAutoRenewThreshold},
		{PackCredits: 25, MonthlyCredits: 50},
		{PackCredits: 25, BelowNanoUsd: 1},
		{AutoRenew: ComputeAutoRenewMonthly, MonthlyCredits: 500},
		{AutoRenew: ComputeAutoRenewMonthly, MonthlyCredits: 50, PackCredits: 25},
		{PackCredits: 25, AutoRenew: "weekly"},
	} {
		if _, err := client.Checkout(ctx, args); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("checkout %+v: %v", args, err)
		}
	}
	for _, code := range []string{"", "SHORT", "has space in it", strings.Repeat("A", 33), "PROMO-2026-X"} {
		if _, err := client.Redeem(ctx, code); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("code %q: %v", code, err)
		}
	}
	for _, change := range []*ComputeAutoRenewChange{nil, {Mode: "weekly"}, {Mode: ComputeAutoRenewThreshold, Credits: 50},
		{Mode: ComputeAutoRenewMonthly, Credits: 30}, {Mode: ComputeAutoRenewMonthly, PackCredits: 20}, {Mode: ComputeAutoRenewThreshold, BelowNanoUsd: -1}} {
		if _, err := client.SetAutoRenew(ctx, change); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("change %+v: %v", change, err)
		}
	}
	for _, month := range []string{"", "2026-13", "2026-1", "November"} {
		if _, err := client.Statement(ctx, month); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("month %q: %v", month, err)
		}
	}
	if _, err := client.Charges(ctx, "a cursor with spaces"); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("cursor: %v", err)
	}
	if _, err := client.Spend(ctx, "sidecar"); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("spend by sidecar: %v", err)
	}
	if _, err := client.Refund(ctx, Id{}); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("refund of no lot: %v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests sent", count)
	}
}

// An answer that is not its route's is refused whole: a balance without its state or with one §9.9 does not name, a
// Checkout url that is not Checkout's, a spend window that is not 7 consecutive UTC days or a line repeating its kind,
// a row of another breakdown, an agent row with a total, and a refusal read as the route's code.
func TestComputeClientRefusesAnswersOutOfShape(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		route  string
		status int
		answer string
		call   func(client *ComputeClient) error
		code   string
	}{
		{name: "no state", route: "GET /compute/balance", answer: `{"available_nano_usd":1,"held_nano_usd":0,"balance_nano_usd":1,"version":1,"may_buy":true,"sales_open":true,"update_time_ms":1}`},
		{name: "a state no one names", route: "GET /compute/balance", answer: testComputeBalanceBody("frozen", 1, "")},
		{name: "a negative hold", route: "GET /compute/balance", answer: strings.Replace(testComputeBalanceBody(ComputeAccountStateActive, 1, ""), `"held_nano_usd":250000000`, `"held_nano_usd":-1`, 1)},
		{name: "an off reason in prose", route: "GET /compute/balance", answer: testComputeBalanceBody(ComputeAccountStateActive, 1, `,"auto_renew":{"threshold":{"on":false,"off_reason":"Your card was declined."}}`)},
		{name: "a url to another host", route: "POST /compute/checkout", answer: `{"url":"https://checkout.example/pay","expire_time_ms":1}`,
			call: func(client *ComputeClient) error {
				_, err := client.Checkout(ctx, &ComputeCheckoutArgs{PackCredits: 10})
				return err
			}},
		{name: "a url over http", route: "POST /compute/checkout", answer: `{"url":"http://checkout.stripe.com/pay","expire_time_ms":1}`,
			call: func(client *ComputeClient) error {
				_, err := client.Checkout(ctx, &ComputeCheckoutArgs{PackCredits: 10})
				return err
			}},
		{name: "six days", route: "GET /compute/spend", answer: `{"by":"","days":["2026-11-18","2026-11-19","2026-11-20","2026-11-21","2026-11-22","2026-11-23"],"held_nano_usd":0,"update_time_ms":1,"lines":[]}`,
			call: func(client *ComputeClient) error {
				_, err := client.Spend(ctx, ComputeSpendByNone)
				return err
			}},
		{name: "days out of order", route: "GET /compute/spend", answer: `{"by":"","days":["2026-11-18","2026-11-20","2026-11-19","2026-11-21","2026-11-22","2026-11-23","2026-11-24"],"held_nano_usd":0,"update_time_ms":1,"lines":[]}`,
			call: func(client *ComputeClient) error {
				_, err := client.Spend(ctx, ComputeSpendByNone)
				return err
			}},
		{name: "a kind twice", route: "GET /compute/spend",
			answer: fmt.Sprintf(`{"by":"","days":%s,"held_nano_usd":0,"update_time_ms":1,"lines":[{"kind":1,"total":%s,"days":%s},{"kind":1,"total":%s,"days":%s}]}`,
				testComputeSpendDays, testComputeFigures(1, 0, 1), testComputeSevenDays(1), testComputeFigures(1, 0, 1), testComputeSevenDays(1)),
			call: func(client *ComputeClient) error {
				_, err := client.Spend(ctx, ComputeSpendByNone)
				return err
			}},
		{name: "enclave_disk, never written", route: "GET /compute/spend",
			answer: fmt.Sprintf(`{"by":"","days":%s,"held_nano_usd":0,"update_time_ms":1,"lines":[{"kind":3,"total":%s,"days":%s}]}`,
				testComputeSpendDays, testComputeFigures(1, 0, 1), testComputeSevenDays(1)),
			call: func(client *ComputeClient) error {
				_, err := client.Spend(ctx, ComputeSpendByNone)
				return err
			}},
		{name: "a member row in a provider view", route: "GET /compute/spend",
			answer: fmt.Sprintf(`{"by":"provider","days":%s,"held_nano_usd":0,"update_time_ms":1,"lines":[{"kind":1,"total":%s,"days":%s,"rows":[{"member_id":%q,"total":%s,"days":%s}]}]}`,
				testComputeSpendDays, testComputeFigures(1, 0, 1), testComputeSevenDays(1), NewId(), testComputeFigures(1, 0, 1), testComputeSevenDays(1)),
			call: func(client *ComputeClient) error {
				_, err := client.Spend(ctx, ComputeSpendByProvider)
				return err
			}},
		{name: "an agent row with a total", route: "GET /compute/spend",
			answer: fmt.Sprintf(`{"by":"agent","days":%s,"held_nano_usd":0,"update_time_ms":1,"lines":[{"kind":1,"total":%s,"days":%s,"rows":[{"agent_id":%q,"total":%s,"days":%s}]}]}`,
				testComputeSpendDays, testComputeFigures(1, 0, 1), testComputeSevenDays(1), NewId(), testComputeFigures(1, 0, 1), testComputeSevenDays(1)),
			call: func(client *ComputeClient) error {
				_, err := client.Spend(ctx, ComputeSpendByAgent)
				return err
			}},
		{name: "a refusal keeps its code", route: "POST /compute/promo/redeem", status: http.StatusConflict, answer: `{"code":"code_redeemed","error":"This code was already used by your network."}`,
			call: func(client *ComputeClient) error {
				_, err := client.Redeem(ctx, "SPRINGPROMO2026")
				return err
			}, code: ComputeRefusalCodeRedeemed},
	} {
		status := c.status
		if status == 0 {
			status = http.StatusOK
		}
		transport := testComputeApi(map[string]func(request *http.Request, body []byte) (int, string){
			c.route: func(request *http.Request, body []byte) (int, string) { return status, c.answer },
		})
		host := newTestComputeHost(t, transport)
		client := newTestComputeClient(t, host, nil)
		call := c.call
		if call == nil {
			call = func(client *ComputeClient) error {
				_, err := client.Balance(ctx)
				return err
			}
		}
		err := call(client)
		if c.code != "" {
			if ComputeRefusalCodeOf(err) != c.code || strings.Contains(err.Error(), "already used") {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Kind 21 through the gate: a version-5 compute_budget_raise whose field 43 names the agent, the period, the new and
// the current amount, its detail sealed, BAL-M12-16's effect on it, the asker's words as its summary, answered
// approval_pending with the gate's id; done once the gate passes it; and, while the effect is not in this build,
// refused before anything reaches the gate, as a raise naming no subject or no rise is.
func TestComputeRaiseBudgetFilesKind21(t *testing.T) {
	registered := computeBudgetRaiseEffectSource
	t.Cleanup(func() {
		computeBudgetRaiseEffectSource = registered
	})
	computeBudgetRaiseEffectSource = nil
	host := newTestComputeHost(t, testComputeApi(nil))
	client := newTestComputeClient(t, host, nil)
	ctx := context.Background()
	agentId := NewId()
	args := &ComputeBudgetRaiseArgs{AgentId: &agentId, Period: "day", AmountNanoUsd: 10000000000, CurrentNanoUsd: 5000000000, Summary: "the build needs more"}
	if _, err := client.RaiseBudget(ctx, args); !errors.Is(err, ErrComputeBudgetRaiseUnavailable) {
		t.Errorf("without the effect: %v", err)
	}
	if actions := host.authorized(); len(actions) != 0 {
		t.Fatalf("%d actions filed without the effect", len(actions))
	}

	effects := 0
	computeBudgetRaiseEffectSource = func(client *ComputeClient, action *StoredCanonicalAction) SidecarEffect {
		effects += 1
		return &testComputeEffect{}
	}
	for _, invalid := range []*ComputeBudgetRaiseArgs{
		nil,
		{Period: "day", AmountNanoUsd: 2, CurrentNanoUsd: 1},
		{AgentId: &agentId, GrantId: &agentId, Period: "day", AmountNanoUsd: 2, CurrentNanoUsd: 1},
		{AgentId: &agentId, Period: "week", AmountNanoUsd: 2, CurrentNanoUsd: 1},
		{AgentId: &agentId, Period: "day", AmountNanoUsd: 1, CurrentNanoUsd: 1},
	} {
		if _, err := client.RaiseBudget(ctx, invalid); !errors.Is(err, ErrComputeBudgetRaiseInvalid) {
			t.Errorf("%+v: %v", invalid, err)
		}
	}
	approvalId := NewId()
	host.authorize = func(action *SidecarAction) error {
		return &ApprovalPendingError{ApprovalId: approvalId}
	}
	result, err := client.RaiseBudget(ctx, args)
	if err != nil || result.Outcome != ComputeBudgetRaisePending || result.ApprovalId == nil || *result.ApprovalId != approvalId {
		t.Fatalf("result %+v, %v", result, err)
	}
	actions := host.authorized()
	if len(actions) != 1 || effects != 1 {
		t.Fatalf("%d actions, %d effects", len(actions), effects)
	}
	action := actions[0]
	if action.Kind != SidecarActionComputeBudgetRaise || action.Effect == nil || action.Summary != "the build needs more" ||
		action.Risk != SidecarRiskNormal {
		t.Errorf("action %+v", action)
	}
	stored, err := ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	budget := stored.Action.GetBudget()
	if stored.Action.GetVersion() != canonicalActionVersionCompute || len(stored.Action.GetSealedDetail()) == 0 ||
		!slices.Equal(budget.GetAgentId(), agentId.Bytes()) || budget.GetPeriod() != approvalComputeBudgetPeriodDay ||
		budget.GetAmount() != 10000000000 || budget.GetCurrent() != 5000000000 {
		t.Errorf("stored %+v", stored.Action)
	}

	host.authorize = func(action *SidecarAction) error {
		return nil
	}
	grantId := NewId()
	result, err = client.RaiseBudget(ctx, &ComputeBudgetRaiseArgs{GrantId: &grantId, Period: "month", AmountNanoUsd: 2, CurrentNanoUsd: 1})
	if err != nil || result.Outcome != ComputeBudgetRaiseDone || result.ApprovalId != nil {
		t.Errorf("a passed raise %+v, %v", result, err)
	}
}

// An effect a test hands the gate: it records nothing and is never run here, since the test's gate runs none.
type testComputeEffect struct{}

// Answers no reference.
func (self *testComputeEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	return nil, nil
}

// A clock a test moves: each After is a timer the test fires by advancing past it, and each one armed is reported, so
// the test knows the loop is waiting.
type testComputeClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []*testComputeTimer
	armed     chan time.Duration
}

// One armed timer.
type testComputeTimer struct {
	at   time.Time
	fire chan time.Time
}

// A clock at a fixed instant.
func newTestComputeClock() *testComputeClock {
	return &testComputeClock{now: time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC), armed: make(chan time.Duration, 64)}
}

// The test's instant.
func (self *testComputeClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// A timer the test fires by advancing to its instant; reported on armed.
func (self *testComputeClock) After(timeout time.Duration) <-chan time.Time {
	timer := &testComputeTimer{fire: make(chan time.Time, 1)}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		timer.at = self.now.Add(timeout)
		self.timers = append(self.timers, timer)
	}()
	self.armed <- timeout
	return timer.fire
}

// As After, calling function when it fires.
func (self *testComputeClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-fire:
			function()
		case <-stopped:
		}
	}()
	var once sync.Once
	return func() bool {
		stoppedNow := false
		once.Do(func() {
			close(stopped)
			stoppedNow = true
		})
		return stoppedNow
	}
}

// Moves the clock by, firing each timer it passes.
func (self *testComputeClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	kept := []*testComputeTimer{}
	for _, timer := range self.timers {
		if timer.at.After(self.now) {
			kept = append(kept, timer)
			continue
		}
		timer.fire <- self.now
	}
	self.timers = kept
}

// The next timer the loop armed, which must be want.
func (self *testComputeClock) waitArmed(t *testing.T, want time.Duration) {
	t.Helper()
	select {
	case armed := <-self.armed:
		if armed != want {
			t.Fatalf("armed %s, want %s", armed, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("nothing armed, want %s", want)
	}
}

// compute_low on the loop: the first read active raises nothing; a refused hold's read at low raises it once, with the
// enclaves and the indexer's days; the poll's read at the same state raises nothing; one at grace raises it again; an
// older answer, read after a newer one, changes nothing; and a generation holding the push topic stops the poll.
// Every read keeps BalanceReadMinInterval from the last, two refusals in a burst read once, and the listener gets each
// notice in full. Each step waits for the read before it changes the next answer, as the loop reads one at a time.
func TestComputeLowRaisedOncePerChange(t *testing.T) {
	enclaveId := NewId()
	var stateLock sync.Mutex
	answerBody := ""
	reads := make(chan struct{}, 64)
	transport := testComputeApi(map[string]func(request *http.Request, body []byte) (int, string){
		"GET /compute/balance": func(request *http.Request, body []byte) (int, string) {
			stateLock.Lock()
			defer stateLock.Unlock()
			reads <- struct{}{}
			return http.StatusOK, answerBody
		},
	})
	answer := func(state ComputeAccountState, version uint64, extra string) {
		stateLock.Lock()
		defer stateLock.Unlock()
		answerBody = testComputeBalanceBody(state, version, extra)
	}
	waitRead := func() {
		t.Helper()
		select {
		case <-reads:
		case <-time.After(10 * time.Second):
			t.Fatal("no read")
		}
	}
	host := newTestComputeHost(t, transport)
	clock := newTestComputeClock()
	settings := DefaultComputeClientSettings()
	client, err := NewComputeClient(&ComputeClientArgs{Host: host, Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	notices := make(chan *ComputeLowNotice, 16)
	removeListener := client.AddLowListener(func(notice *ComputeLowNotice) {
		notices <- notice
	})
	defer removeListener()
	clock.waitArmed(t, settings.BalancePollInterval)

	// the poll's first read, active, raises nothing; the poll arms again
	answer(ComputeAccountStateActive, 1, "")
	clock.advance(settings.BalancePollInterval)
	clock.waitArmed(t, settings.BalancePollInterval)
	waitRead()

	// two refused holds ask one read, held to the interval from the last; it shows low
	answer(ComputeAccountStateLow, 2, fmt.Sprintf(`,"at_risk_enclave_ids":[%q],"indexer_days_left":5`, enclaveId))
	client.HoldRefused()
	client.HoldRefused()
	clock.waitArmed(t, settings.BalanceReadMinInterval)
	clock.advance(settings.BalanceReadMinInterval)
	waitRead()
	event := host.nextEvent(t)
	if event.Kind != SidecarEventComputeLow || event.Outcome != string(ComputeAccountStateLow) {
		t.Errorf("event %+v", event)
	}
	notice := <-notices
	if notice.State != ComputeAccountStateLow || notice.Previous != ComputeAccountStateActive || notice.Version != 2 ||
		!slices.Equal(notice.EnclaveIds, []Id{enclaveId}) || notice.IndexerDaysLeft == nil || *notice.IndexerDaysLeft != 5 {
		t.Errorf("notice %+v", notice)
	}

	// the same state on the poll raises nothing, and refreshes the notice; grace on a refusal raises
	answer(ComputeAccountStateLow, 3, `,"indexer_days_left":4`)
	clock.advance(settings.BalancePollInterval)
	clock.waitArmed(t, settings.BalancePollInterval)
	waitRead()
	answer(ComputeAccountStateGrace, 4, "")
	client.HoldRefused()
	clock.waitArmed(t, settings.BalanceReadMinInterval)
	clock.advance(settings.BalanceReadMinInterval)
	waitRead()
	event = host.nextEvent(t)
	if event.Outcome != string(ComputeAccountStateGrace) {
		t.Errorf("event %+v: the poll's read at low raised", event)
	}
	if notice := <-notices; notice.State != ComputeAccountStateGrace || notice.Previous != ComputeAccountStateLow {
		t.Errorf("notice %+v", notice)
	}

	// an answer older than the newest read changes nothing; suspended, after it, raises
	answer(ComputeAccountStateActive, 3, "")
	client.HoldRefused()
	clock.waitArmed(t, settings.BalanceReadMinInterval)
	clock.advance(settings.BalanceReadMinInterval)
	waitRead()
	answer(ComputeAccountStateSuspended, 5, "")
	client.HoldRefused()
	clock.waitArmed(t, settings.BalanceReadMinInterval)
	clock.advance(settings.BalanceReadMinInterval)
	waitRead()
	event = host.nextEvent(t)
	if event.Outcome != string(ComputeAccountStateSuspended) {
		t.Errorf("event %+v: the older answer moved the state", event)
	}
	if low := client.LowNotice(); low == nil || low.State != ComputeAccountStateSuspended || low.Previous != ComputeAccountStateGrace {
		t.Errorf("the newest notice %+v", low)
	}

	// a generation holding the compute topic stands the poll down
	client.holdPush(1)
	clock.advance(settings.BalancePollInterval)
	clock.waitArmed(t, settings.BalancePollInterval)
	select {
	case <-reads:
		t.Error("the poll read while push was held")
	default:
	}
	select {
	case event := <-host.events:
		t.Errorf("an extra event %+v", event)
	default:
	}
}

// The tracker on its own: version order, one notice a change, the first active silent, and a read at the state
// already raised refreshing its notice's enclaves and days while keeping when it was raised.
func TestComputeLowTrackerAppliesInVersionOrder(t *testing.T) {
	tracker := &computeLowTracker{}
	at := time.Date(2026, time.November, 24, 0, 0, 0, 0, time.UTC)
	balance := func(state ComputeAccountState, version uint64, days int64) *ComputeBalance {
		return &ComputeBalance{State: state, Version: version, IndexerDaysLeft: &days, AtRiskEnclaveIds: []Id{}}
	}
	if notice := tracker.apply(balance(ComputeAccountStateActive, 1, 0), at); notice != nil || tracker.latest() != nil {
		t.Errorf("the first read, active: %+v", notice)
	}
	notice := tracker.apply(balance(ComputeAccountStateLow, 3, 6), at.Add(time.Minute))
	if notice == nil || notice.State != ComputeAccountStateLow || notice.Previous != ComputeAccountStateActive || *notice.IndexerDaysLeft != 6 {
		t.Fatalf("low: %+v", notice)
	}
	if notice := tracker.apply(balance(ComputeAccountStateActive, 2, 0), at.Add(2*time.Minute)); notice != nil {
		t.Errorf("an older read raised %+v", notice)
	}
	if notice := tracker.apply(balance(ComputeAccountStateLow, 4, 5), at.Add(3*time.Minute)); notice != nil {
		t.Errorf("the same state raised %+v", notice)
	}
	latest := tracker.latest()
	if latest.State != ComputeAccountStateLow || *latest.IndexerDaysLeft != 5 || latest.Version != 4 || !latest.Time.Equal(at.Add(time.Minute)) {
		t.Errorf("the refreshed notice %+v", latest)
	}
	if notice := tracker.apply(balance(ComputeAccountStateActive, 5, 0), at.Add(4*time.Minute)); notice == nil ||
		notice.State != ComputeAccountStateActive || notice.Previous != ComputeAccountStateLow || notice.IndexerDaysLeft != nil {
		t.Errorf("back to active: %+v", notice)
	}
	// a first read that is not active raises
	fresh := &computeLowTracker{}
	if notice := fresh.apply(balance(ComputeAccountStateGrace, 9, 0), at); notice == nil || notice.Previous != "" {
		t.Errorf("a first read in grace: %+v", notice)
	}
}

// A failed read retries from BalanceRetryFirstInterval, doubling to BalanceRetryMaxInterval.
func TestComputeBalanceRetryBacksOff(t *testing.T) {
	host := newTestComputeHost(t, testComputeApi(nil))
	client := newTestComputeClient(t, host, nil)
	settings := client.settings
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for attempt, wait := range want {
		if got := client.retryWait(attempt); got != wait {
			t.Errorf("attempt %d waits %s, want %s", attempt, got, wait)
		}
	}
	if settings.BalanceRetryFirstInterval != want[0] || settings.BalanceRetryMaxInterval != want[len(want)-1] {
		t.Errorf("settings %s to %s", settings.BalanceRetryFirstInterval, settings.BalanceRetryMaxInterval)
	}
}

// Stripe's packs and plans from the settings; a store's products only once ComputeStoreProducts registers them,
// refused meanwhile; a market that sells nothing refused.
func TestComputePacksFromSettingsAndTheStoreSource(t *testing.T) {
	registered := computeStoreProductsSource
	t.Cleanup(func() {
		computeStoreProductsSource = registered
	})
	computeStoreProductsSource = nil
	host := newTestComputeHost(t, testComputeApi(nil))
	client := newTestComputeClient(t, host, nil)
	packs, err := client.Packs(ComputeMarketStripe)
	if err != nil {
		t.Fatal(err)
	}
	credits := []int64{}
	monthly := []int64{}
	for _, pack := range packs {
		if pack.Monthly {
			monthly = append(monthly, pack.Credits)
		} else {
			credits = append(credits, pack.Credits)
		}
	}
	if !slices.Equal(credits, []int64{10, 25, 50, 100, 250, 500}) || !slices.Equal(monthly, []int64{10, 25, 50, 100, 250}) {
		t.Errorf("packs %v, plans %v", credits, monthly)
	}
	if _, err := client.Packs(ComputeMarketAppStore); !errors.Is(err, ErrComputeStoreProductsUnavailable) {
		t.Errorf("app store without products: %v", err)
	}
	computeStoreProductsSource = func(market ComputeMarket) []*ComputePack {
		return []*ComputePack{
			{Market: ComputeMarketAppStore, Credits: 10, ProductId: "compute.pack.10"},
			{Market: ComputeMarketGooglePlay, Credits: 10, ProductId: "compute.pack.10"},
		}
	}
	packs, err = client.Packs(ComputeMarketAppStore)
	if err != nil || len(packs) != 1 || packs[0].ProductId != "compute.pack.10" || packs[0].Market != ComputeMarketAppStore {
		t.Errorf("app store %+v, %v", packs, err)
	}
	if _, err := client.Packs(ComputeMarketPromotion); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("promotion: %v", err)
	}
}

// Amounts to the cent, rounded half away from zero, "< $0.01" for a charge that rounds to none, so none shows free.
func TestComputeMoneyTextToTheCent(t *testing.T) {
	for _, c := range []struct {
		nanoUsd int64
		text    string
	}{
		{nanoUsd: 0, text: "$0.00"},
		{nanoUsd: 1, text: "< $0.01"},
		{nanoUsd: 4_999_999, text: "< $0.01"},
		{nanoUsd: 5_000_000, text: "$0.01"},
		{nanoUsd: 10_000_000, text: "$0.01"},
		{nanoUsd: 2_580_000_000, text: "$2.58"},
		{nanoUsd: 12_345_000_000, text: "$12.35"},
		{nanoUsd: 10_000_000_000_000, text: "$10000.00"},
		{nanoUsd: -1, text: "> -$0.01"},
		{nanoUsd: -500_000_000, text: "-$0.50"},
		{nanoUsd: -9223372036854775808, text: "-$9223372036.85"},
	} {
		if got := ComputeMoneyText(c.nanoUsd); got != c.text {
			t.Errorf("%d: %q, want %q", c.nanoUsd, got, c.text)
		}
	}
}

// The compute topic is a raised clock in §6.8's registry (QD-1238), so a generation's feed takes the client's
// subscription, and a hint on it reaches the subscriber.
func TestComputeTopicIsARaisedClock(t *testing.T) {
	if PushTopicClassOf(PushTopicCompute) != PushTopicClock || !PushTopicRaisesClock(PushTopicCompute) {
		t.Errorf("class %d, raises %t", PushTopicClassOf(PushTopicCompute), PushTopicRaisesClock(PushTopicCompute))
	}
	feed := NewPushTestFeed(t)
	notices := []PushNotice{}
	remove, err := feed.Subscribe(PushTopicCompute, func(notice PushNotice) {
		notices = append(notices, notice)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer remove()
	feed.ApplyHint(&protocol.PushHint{Topic: PushTopicCompute, Version: 1795000000000, Seq: 1})
	if len(notices) != 1 || notices[0].Topic != PushTopicCompute || notices[0].Version != 1795000000000 {
		t.Errorf("notices %+v", notices)
	}
}

// A notice's JSON holds its state, ids and numbers, nothing else.
func TestComputeLowNoticeJsonHoldsIdsAndNumbers(t *testing.T) {
	days := int64(3)
	notice := &ComputeLowNotice{State: ComputeAccountStateSuspended, Previous: ComputeAccountStateGrace, Version: 9,
		EnclaveIds: []Id{NewId()}, IndexerDaysLeft: &days, Time: time.Date(2026, time.November, 24, 0, 0, 0, 0, time.UTC)}
	data, err := json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for key := range decoded {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if want := []string{"enclave_ids", "indexer_days_left", "previous", "state", "time", "version"}; !slices.Equal(keys, want) {
		t.Errorf("keys %v, want %v", keys, want)
	}
}
