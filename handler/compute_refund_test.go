package handler

// POST /compute/refund through the frame (BAL-M12-14; DESIGN-COMPUTE §9.10, §9.12, §14.3): registered; refused to an
// Admin, a Member, an agent's token, a tagged sidecar and an enclave before the ledger is asked, as only an Owner or a
// Billing admin on a person's surface refunds; a body that is not {"lot_id"} refused 400; and a host with no Stripe
// refunds refused 503, fail closed. A refund on real stores runs in server/computet3/compute_refund_t3_test.go.

import (
	"context"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Every role but an Owner and a Billing admin, and every surface but a person's, is refused before the ledger.
func TestComputeRefundRouteRefusesOtherRolesAgentsAndTaggedSidecars(t *testing.T) {
	route := testComputeApiRoute(t, http.MethodPost, "/compute/refund")
	body := []byte(`{"lot_id":"` + sidecar.NewId().String() + `"}`)
	agent := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	agent.Credential = ComputeApiCredentialAgent
	tagged := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagged.Tagged = true
	enclave := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN)
	enclave.Enclave = true
	for name, caller := range map[string]*ComputeApiCaller{
		"an admin":         testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN),
		"an auditor":       testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_AUDITOR),
		"a member":         testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER),
		"an agent":         agent,
		"a tagged sidecar": tagged,
		"an enclave":       enclave,
	} {
		answer := route.Serve(context.Background(), caller, nil, body)
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, answer.Status, code)
		}
	}
}

// A body that is not {"lot_id"} is refused 400, and an Owner's refund on a host with no Stripe refunds 503.
func TestComputeRefundRouteRefusesBadRequestsAndFailsClosed(t *testing.T) {
	route := testComputeApiRoute(t, http.MethodPost, "/compute/refund")
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	for _, body := range []string{`{}`, `{"lot_id":"x"}`, `{"lot_id":null}`, `{"lot_id":"` + sidecar.NewId().String() + `","amount":5}`} {
		answer := route.Serve(context.Background(), owner, nil, []byte(body))
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusBadRequest || code != ComputeApiRefusalBadRequest {
			t.Errorf("%s: %d %s", body, answer.Status, code)
		}
	}
	if controller.ComputeRegisteredStripeRefunds() != nil {
		t.Skip("this test binary registered Stripe refunds")
	}
	answer := route.Serve(context.Background(), owner, nil, []byte(`{"lot_id":"`+sidecar.NewId().String()+`"}`))
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusServiceUnavailable || code != ComputeApiRefusalUnavailable {
		t.Fatalf("no Stripe refunds: %d %s", answer.Status, code)
	}
}
