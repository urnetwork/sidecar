package handler

// GET and POST /compute/auto-renew through the frame (BAL-M12-11; DESIGN-COMPUTE §9.8, §9.10, §14.3): registered;
// refused to an agent's token, a tagged sidecar, an enclave and a member without compute:buy before the ledger is
// asked; a body that is not the device's ComputeAutoRenewChange refused 400; and the answer's shape the device's
// computeAutoRenewAnswer, both modes with their on, the payer an opaque id and no card. The changes on real stores run
// in server/computet3/compute_auto_renew_t3_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Both routes are registered, and refuse a caller who may not buy before any store is asked.
func TestComputeAutoRenewRoutesRefuseWhoMayNotBuy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		route := testComputeApiRoute(t, method, "/compute/auto-renew")
		body := []byte(nil)
		if method == http.MethodPost {
			body = []byte(`{"mode":"threshold","on":false}`)
		}
		agent := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		agent.Credential = ComputeApiCredentialAgent
		tagged := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		tagged.Tagged = true
		enclave := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		enclave.Enclave = true
		for name, caller := range map[string]*ComputeApiCaller{
			"an agent":                   agent,
			"a tagged sidecar":           tagged,
			"an enclave":                 enclave,
			"a member without the grant": testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER),
			"an admin":                   testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN),
		} {
			answer := route.Serve(context.Background(), caller, nil, body)
			if code, _ := testComputeApiCode(t, answer); answer.Status == http.StatusNotImplemented || code == ComputeApiRefusalNotBuilt {
				t.Fatalf("%s %s answers not_built", method, name)
			} else if answer.Status != http.StatusForbidden {
				t.Errorf("%s %s: %d %s", method, name, answer.Status, code)
			}
		}
	}
}

// A body that is not the device's ComputeAutoRenewChange is refused 400 before the ledger is asked: no mode, a mode
// §9.8 does not name, no on, a field the device never sends, a figure of the wrong type.
func TestComputeSetAutoRenewRefusesBadRequests(t *testing.T) {
	route := testComputeApiRoute(t, http.MethodPost, "/compute/auto-renew")
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	for _, body := range []string{
		`{"on":true}`,
		`{"mode":"weekly","on":true}`,
		`{"mode":"threshold"}`,
		`{"mode":"threshold","on":true,"card":"pm_x"}`,
		`{"mode":"threshold","on":true,"pack_credits":"20"}`,
	} {
		answer := route.Serve(context.Background(), owner, nil, []byte(body))
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusBadRequest || code != ComputeApiRefusalBadRequest {
			t.Errorf("%s: %d %s", body, answer.Status, code)
		}
	}
}

// The answer's body is the device's: both modes, each with on, the off reason as its code, the payer an opaque id,
// and no card, customer or subscription.
func TestComputeAutoRenewBodyIsTheDevicesShape(t *testing.T) {
	payer := sidecar.NewId()
	reason := model.ComputeAutoRenewOffFailed
	body := ComputeAutoRenewBodyOf(&controller.ComputeAutoRenewState{
		Threshold: &controller.ComputeThresholdState{
			BelowNanoUsd: 5_000_000_000, PackCredits: 20, MonthLimitNanoUsd: 200_000_000_000, OffReason: &reason,
			PayerMemberId: &payer, TopUpsToday: 1, FailuresToday: 3, MonthNanoUsd: 20_000_000_000,
		},
		Monthly: &controller.ComputeMonthlyState{On: true, Credits: 25, Market: model.ComputeMarketStripe, PayerMemberId: &payer},
	})
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]map[string]any{}
	if err := json.Unmarshal(encoded, &read); err != nil {
		t.Fatal(err)
	}
	threshold, monthly := read["threshold"], read["monthly"]
	if threshold["on"] != false || threshold["off_reason"] != "failed" || threshold["pack_credits"] != float64(20) ||
		threshold["payer_member_id"] != payer.String() || threshold["failures_today"] != float64(3) {
		t.Errorf("threshold: %v", threshold)
	}
	if monthly["on"] != true || monthly["credits"] != float64(25) || monthly["market"] != float64(1) || monthly["payer_member_id"] != payer.String() {
		t.Errorf("monthly: %v", monthly)
	}
	for _, mode := range read {
		for _, field := range []string{"stripe_customer_id", "stripe_payment_method_id", "stripe_subscription_id", "card"} {
			if _, ok := mode[field]; ok {
				t.Errorf("the answer holds %s", field)
			}
		}
	}
}
