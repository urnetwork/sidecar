package handler

// POST /compute/promo/redeem through the frame (BAL-M12-13; DESIGN-COMPUTE §9.10, §9.11, §14.3): registered, refused to
// an agent's or MCP's token, a tagged sidecar, an enclave, a Delegation's device and a member without compute:buy before
// the ledger is asked; a body that is not {"code": "..."} refused 400; and with no promotion key on the host, refused
// 503 unavailable, never redeemed. The redemption itself runs on the private stack (server/computet3).

import (
	"context"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestPromoRouteIsRegistered(t *testing.T) {
	if computeApiHandlerOf(http.MethodPost, "/compute/promo/redeem") == nil {
		t.Fatal("POST /compute/promo/redeem answers not_built")
	}
}

func TestPromoRefusedToAgentsTaggedAndMembersWithoutBuy(t *testing.T) {
	route := testComputeApiRoute(t, http.MethodPost, "/compute/promo/redeem")
	body := []byte(`{"code":"WELCOME2026"}`)
	for label, change := range map[string]func(caller *ComputeApiCaller){
		"an agent's token":       func(caller *ComputeApiCaller) { caller.Credential = ComputeApiCredentialAgent },
		"a tagged sidecar":       func(caller *ComputeApiCaller) { caller.Tagged = true },
		"an enclave":             func(caller *ComputeApiCaller) { caller.Enclave = true },
		"a Delegation's device":  func(caller *ComputeApiCaller) { caller.DelegationAdmitted = true },
		"a member without buy":   func(caller *ComputeApiCaller) { caller.Role = bridge.MemberRole_MEMBER_ROLE_MEMBER },
		"an admin, who sees all": func(caller *ComputeApiCaller) { caller.Role = bridge.MemberRole_MEMBER_ROLE_ADMIN },
	} {
		caller := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		change(caller)
		answer := route.Serve(context.Background(), caller, nil, body)
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusForbidden || (code != ComputeApiRefusalMayNotBuy && code != ComputeApiRefusalCredentialRefused) {
			t.Errorf("%s: %d %s", label, answer.Status, code)
		}
	}
}

// A body other than the one field is refused before the ledger; a good one with no promotion key on the host fails
// closed, 503 unavailable.
func TestPromoRouteRefusesBadBodiesAndAnUnkeyedHost(t *testing.T) {
	route := testComputeApiRoute(t, http.MethodPost, "/compute/promo/redeem")
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	for _, body := range []string{`{}`, `{"code":5}`, `{"code":"WELCOME2026","network":"x"}`, `{"code":null}`} {
		answer := route.Serve(context.Background(), owner, nil, []byte(body))
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusBadRequest || code != ComputeApiRefusalBadRequest {
			t.Errorf("%s: %d %s", body, answer.Status, code)
		}
	}
	answer := route.Serve(context.Background(), owner, nil, []byte(`{"code":"WELCOME2026"}`))
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusServiceUnavailable || code != ComputeApiRefusalUnavailable {
		t.Errorf("with no promotion key: %d %s", answer.Status, code)
	}
}
