//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

// The daemon's compute methods (BAL-M12-17) on the dispatcher with no socket: redemption, auto-renew's changes and
// refunds run only from a confirmed control call, an unconfirmed one or one from mcp reaching no route; the reads and
// a budget raise run unconfirmed; a refusal api answered is the reply, its code without its text; and a reply passes
// the walk that keeps secrets out of replies.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// A daemon hosting one network's Sidecar, the compute methods registered over a client on a scripted api.
type testComputeDaemonWorld struct {
	daemon    *Daemon
	networkId Id
	transport *scriptedApiTransport
}

// The world, its api answering redeem with a lot, or code_redeemed for the code the test names refused, and the
// auto-renew change with both modes.
func newTestComputeDaemonWorld(t *testing.T) *testComputeDaemonWorld {
	t.Helper()
	lotId := NewId()
	transport := testComputeApi(map[string]func(request *http.Request, body []byte) (int, string){
		"POST /compute/promo/redeem": func(request *http.Request, body []byte) (int, string) {
			if strings.Contains(string(body), "USEDCODE2026") {
				return http.StatusConflict, `{"code":"code_redeemed","error":"already redeemed"}`
			}
			return http.StatusOK, fmt.Sprintf(`{"lot_id":%q,"credit_nano_usd":10000000000,"expire_time_ms":1797600000000}`, lotId)
		},
		"POST /compute/auto-renew": func(request *http.Request, body []byte) (int, string) {
			return http.StatusOK, `{"threshold":{"on":true,"below_nano_usd":5000000000,"pack_credits":20,"month_limit_nano_usd":200000000000},"monthly":{"on":false}}`
		},
		"POST /compute/refund": func(request *http.Request, body []byte) (int, string) {
			// the lot the request names, refunded
			refund := struct {
				LotId Id `json:"lot_id"`
			}{}
			if json.Unmarshal(body, &refund) != nil {
				return http.StatusBadRequest, `{"code":"bad_request"}`
			}
			return http.StatusOK, fmt.Sprintf(`{"lot_id":%q,"refunded_nano_usd":5000000000}`, refund.LotId)
		},
		"GET /compute/balance": func(request *http.Request, body []byte) (int, string) {
			return http.StatusOK, testComputeBalanceBody(ComputeAccountStateActive, 1, "")
		},
	})
	host := newTestComputeHost(t, transport)
	client := newTestComputeClient(t, host, nil)
	sidecar, _, _ := newIdentityTestSidecar(t)
	identity := sidecar.Identity()
	daemon := newDispatchTestDaemon(t)
	if err := daemon.AddSidecar(identity.NetworkId, sidecar); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonComputeMethods(&DaemonComputeBackends{Client: func(sidecar *Sidecar) (*ComputeClient, error) {
		return client, nil
	}}) {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return &testComputeDaemonWorld{daemon: daemon, networkId: identity.NetworkId, transport: transport}
}

// One request line of method in mode, its params, confirmed as asked.
func (self *testComputeDaemonWorld) call(t *testing.T, mode string, method string, params any, confirmed bool) *daemonRpcResponse {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	request := &daemonRpcRequest{JsonRpc: "2.0", Id: json.RawMessage("1"), Method: method, Params: encoded, UrConfirmed: confirmed}
	line, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return dispatchTest(self.daemon, mode, string(line))
}

// Redemption and auto-renew's changes, and refunds, are Confirm methods: an unconfirmed control call, or a confirmed
// one from mcp or hook, is refused before any route is called; a confirmed control call reaches its route and answers
// its result, or api's refusal as a code. Every compute method acts on a network, and no other is a Confirm method.
func TestDaemonComputeMethodsConfirmRedeemAndAutoRenew(t *testing.T) {
	confirmed := []string{}
	for _, method := range DaemonComputeMethods(nil) {
		if !method.Network || method.Handler == nil {
			t.Errorf("%s: network %t", method.Name, method.Network)
		}
		if method.Confirm {
			confirmed = append(confirmed, method.Name)
		}
	}
	slices.Sort(confirmed)
	if want := []string{DaemonMethodComputeAutoRenewSet, DaemonMethodComputeRedeem, DaemonMethodComputeRefund}; !slices.Equal(confirmed, want) {
		t.Errorf("confirm methods %v, want %v", confirmed, want)
	}

	world := newTestComputeDaemonWorld(t)
	network := world.networkId.String()
	redeem := &DaemonComputeRedeemParams{Network: network, Code: "SPRINGPROMO2026"}
	change := &DaemonComputeAutoRenewSetParams{Network: network, ComputeAutoRenewChange: ComputeAutoRenewChange{Mode: ComputeAutoRenewThreshold, On: true}}
	lotId := NewId()
	refund := &DaemonComputeRefundParams{Network: network, LotId: &lotId}
	for _, c := range []struct {
		method string
		params any
	}{
		{method: DaemonMethodComputeRedeem, params: redeem},
		{method: DaemonMethodComputeAutoRenewSet, params: change},
		{method: DaemonMethodComputeRefund, params: refund},
	} {
		for _, refused := range []struct {
			mode      string
			confirmed bool
		}{
			{mode: DaemonModeControl, confirmed: false},
			{mode: DaemonModeMcp, confirmed: true},
			{mode: DaemonModeHook, confirmed: true},
		} {
			response := world.call(t, refused.mode, c.method, c.params, refused.confirmed)
			if response.Error == nil || response.Error.Code != DaemonRpcConfirmationRequired {
				t.Errorf("%s from %s, confirmed %t: %+v", c.method, refused.mode, refused.confirmed, response)
			}
		}
	}
	if count := world.transport.requestCount(); count != 0 {
		t.Fatalf("%d requests from unconfirmed calls", count)
	}

	response := world.call(t, DaemonModeControl, DaemonMethodComputeRedeem, redeem, true)
	if response.Error != nil {
		t.Fatalf("a confirmed redemption: %+v", response.Error)
	}
	redemption := &ComputeRedemption{}
	if err := json.Unmarshal(response.Result, redemption); err != nil || redemption.CreditNanoUsd != 10000000000 {
		t.Errorf("redemption %s, %v", response.Result, err)
	}
	response = world.call(t, DaemonModeControl, DaemonMethodComputeAutoRenewSet, change, true)
	autoRenew := &ComputeAutoRenew{}
	if response.Error != nil || json.Unmarshal(response.Result, autoRenew) != nil || !autoRenew.Threshold.On {
		t.Errorf("a confirmed change: %+v %s", response.Error, response.Result)
	}
	response = world.call(t, DaemonModeControl, DaemonMethodComputeRefund, refund, true)
	if response.Error != nil {
		t.Errorf("a confirmed refund: %+v", response.Error)
	}

	// api's refusal is the reply: its code, never its text
	response = world.call(t, DaemonModeControl, DaemonMethodComputeRedeem, &DaemonComputeRedeemParams{Network: network, Code: "USEDCODE2026"}, true)
	if response.Error != nil || string(response.Result) != `{"refusal":{"code":"code_redeemed"}}` {
		t.Errorf("a refused code: %+v %s", response.Error, response.Result)
	}

	// a read runs unconfirmed, from mcp too
	response = world.call(t, DaemonModeMcp, DaemonMethodComputeBalance, &DaemonComputeParams{Network: network}, false)
	balance := &ComputeBalance{}
	if response.Error != nil || json.Unmarshal(response.Result, balance) != nil || balance.State != ComputeAccountStateActive {
		t.Errorf("a balance read: %+v %s", response.Error, response.Result)
	}
	// params it cannot read are refused, naming none of them
	response = world.call(t, DaemonModeControl, DaemonMethodComputeRedeem, map[string]string{"network": network, "code": "X", "extra": "secret-canary"}, true)
	if response.Error == nil || strings.Contains(response.Error.Message, "secret-canary") {
		t.Errorf("unknown params: %+v", response)
	}
}

// Every reply the methods give passes the walk that keeps secrets out of replies.
func TestDaemonComputeRepliesPassTheSecretWalk(t *testing.T) {
	days := int64(2)
	for _, reply := range []any{
		&DaemonComputeLowReply{Notice: &ComputeLowNotice{State: ComputeAccountStateLow, EnclaveIds: []Id{NewId()}, IndexerDaysLeft: &days}},
		&DaemonComputeRefusalReply{Refusal: &DaemonComputeRefusal{Code: ComputeRefusalSalesClosed}},
		&DaemonComputePacksReply{Packs: []*ComputePack{{Market: ComputeMarketStripe, Credits: 10}}},
		&ComputeSpendView{Lines: []*ComputeSpendViewLine{{Rows: []*ComputeSpendViewRow{{Name: computePlainName("you"), Row: &ComputeSpendRow{}}}}}},
		&ComputeBudgetRaiseResult{Outcome: ComputeBudgetRaisePending},
	} {
		if err := checkDaemonReply(reply); err != nil {
			t.Errorf("%T: %v", reply, err)
		}
	}
}
