package handler

// POST /compute/checkout through the frame (BAL-M12-08; DESIGN-COMPUTE §9.5, §9.10, §9.11, §14.3): registered;
// refused to an agent's or MCP's token, a tagged sidecar, an enclave, a Delegation's device and a member without
// compute:buy before the ledger or Stripe is asked; a body that is not the device's ComputeCheckoutArgs refused 400; a
// pack §9.5 does not sell refused 400; the monthly plan refused 503 on a host whose Stripe for auto-renew is not
// registered, and threshold's card taken by auto-renew (BAL-M12-11), so its checkout meets the sales check as a pack's
// does; a host without Stripe or a payer key refused 503; and sales closed until a service can spend credit, with no
// session made. A checkout that opens runs on the private stack (server/computet3).

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The ledger's keys for these tests: synthetic, test only.
type testCheckoutSecrets struct{}

func (self testCheckoutSecrets) PayerHashKey() ([]byte, error) {
	return []byte("synthetic handler payer hash key, test only"), nil
}

func (self testCheckoutSecrets) PromoHashKey() ([]byte, error) {
	return []byte("synthetic handler promo hash key, test only"), nil
}

// A Stripe checkout that counts the sessions asked of it and makes none.
type testCheckoutStripe struct {
	stateLock sync.Mutex
	requests  []*controller.ComputeStripeCheckoutRequest
}

func (self *testCheckoutStripe) CreateCheckout(ctx context.Context, request *controller.ComputeStripeCheckoutRequest) (*controller.ComputeStripeCheckoutSession, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, request)
	return nil, context.Canceled
}

func (self *testCheckoutStripe) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// Registers the checkout route for the test over keyed secrets and stripe, putting the route's own back after.
func testCheckoutRoute(t *testing.T, stripe *testCheckoutStripe) *ComputeApiRoute {
	testRegisterComputeApiHandler(t, http.MethodPost, "/compute/checkout", NewComputeCheckoutHandler(
		nil,
		func() controller.ComputeLedgerSecrets { return testCheckoutSecrets{} },
		func() controller.ComputeStripeCheckout { return stripe },
	))
	return testComputeApiRoute(t, http.MethodPost, "/compute/checkout")
}

func TestComputeCheckoutRouteIsRegistered(t *testing.T) {
	if computeApiHandlerOf(http.MethodPost, "/compute/checkout") == nil {
		t.Fatal("POST /compute/checkout answers not_built")
	}
}

// An agent's token, a tagged sidecar, an enclave, a Delegation's device and a Member without compute:buy are refused
// by the frame before the ledger or Stripe is asked; so is an Admin, who sees all but buys nothing.
func TestComputeCheckoutRefusedToWhoMayNotBuy(t *testing.T) {
	stripe := &testCheckoutStripe{}
	route := testCheckoutRoute(t, stripe)
	body := []byte(`{"pack_credits":25}`)
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
	if stripe.count() != 0 {
		t.Fatalf("a refused caller made %d sessions", stripe.count())
	}
}

// Credits are not sold while nothing the network may use can spend them (Q-BAL-13): sales_closed, and no session.
func TestComputeCheckoutClosedUntilSalesOpen(t *testing.T) {
	stripe := &testCheckoutStripe{}
	route := testCheckoutRoute(t, stripe)
	for _, role := range []bridge.MemberRole{bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN} {
		answer := route.Serve(context.Background(), testComputeMemberDevice(role), nil, []byte(`{"pack_credits":100}`))
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusConflict || code != string(controller.ComputeCheckoutRefusalSalesClosed) {
			t.Errorf("%s with no service that can spend: %d %s", role, answer.Status, code)
		}
	}
	if stripe.count() != 0 {
		t.Fatalf("closed sales made %d sessions", stripe.count())
	}
}

// A body that is not the device's ComputeCheckoutArgs, a pack §9.5 does not sell, settings of a mode not turned on and
// a monthly plan beside a pack are refused 400; the monthly plan answers 503 where the host holds no Stripe for
// auto-renew, and a pack with threshold on meets the sales check, auto-renew taking its card (BAL-M12-11); none
// reaches Stripe.
func TestComputeCheckoutRefusesBadRequestsAndUnbuiltModes(t *testing.T) {
	stripe := &testCheckoutStripe{}
	route := testCheckoutRoute(t, stripe)
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	for _, body := range []string{
		`{}`,
		`{"pack_credits":5}`,
		`{"pack_credits":"25"}`,
		`{"pack_credits":25,"network_id":"x"}`,
		`{"pack_credits":25,"auto_renew":"weekly"}`,
		`{"pack_credits":25,"below_nano_usd":5000000000}`,
		`{"pack_credits":25,"auto_renew":"monthly","monthly_credits":25}`,
		`{"auto_renew":"monthly","monthly_credits":30}`,
		`{"pack_credits":25,"auto_renew":"threshold","below_nano_usd":-1}`,
	} {
		answer := route.Serve(context.Background(), owner, nil, []byte(body))
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusBadRequest || code != ComputeApiRefusalBadRequest {
			t.Errorf("%s: %d %s", body, answer.Status, code)
		}
	}
	for body, want := range map[string]struct {
		status int
		code   string
	}{
		`{"auto_renew":"monthly","monthly_credits":25}`: {http.StatusServiceUnavailable, ComputeApiRefusalUnavailable},
		`{"pack_credits":25,"auto_renew":"threshold"}`:   {http.StatusConflict, string(controller.ComputeCheckoutRefusalSalesClosed)},
	} {
		answer := route.Serve(context.Background(), owner, nil, []byte(body))
		if code, _ := testComputeApiCode(t, answer); answer.Status != want.status || code != want.code {
			t.Errorf("%s: %d %s", body, answer.Status, code)
		}
	}
	// a mount that names no paying member has none to make a customer for
	noMember := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	noMember.Credential = ComputeApiCredentialNetwork
	noMember.SidecarId = nil
	noMember.MemberId = nil
	answer := route.Serve(context.Background(), noMember, nil, []byte(`{"pack_credits":25}`))
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusForbidden || code != ComputeApiRefusalCredentialRefused {
		t.Errorf("no paying member: %d %s", answer.Status, code)
	}
	if stripe.count() != 0 {
		t.Fatalf("a refused request made %d sessions", stripe.count())
	}
}

// The route as registered at init, on a host that registered no Stripe checkout and no payer key, fails closed: 503
// unavailable, never a session.
func TestComputeCheckoutUnavailableWithoutStripeOrKeys(t *testing.T) {
	route := testComputeApiRoute(t, http.MethodPost, "/compute/checkout")
	answer := route.Serve(context.Background(), testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER), nil, []byte(`{"pack_credits":25}`))
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusServiceUnavailable || code != ComputeApiRefusalUnavailable {
		t.Fatalf("an unkeyed host without Stripe: %d %s", answer.Status, code)
	}
	// keyed, still without Stripe
	testRegisterComputeApiHandler(t, http.MethodPost, "/compute/checkout", NewComputeCheckoutHandler(
		nil,
		func() controller.ComputeLedgerSecrets { return testCheckoutSecrets{} },
		func() controller.ComputeStripeCheckout { return nil },
	))
	answer = testComputeApiRoute(t, http.MethodPost, "/compute/checkout").Serve(context.Background(), testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER), nil, []byte(`{"pack_credits":25}`))
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusServiceUnavailable || code != ComputeApiRefusalUnavailable {
		t.Fatalf("a keyed host without Stripe: %d %s", answer.Status, code)
	}
	// Stripe, without keys
	stripe := &testCheckoutStripe{}
	testRegisterComputeApiHandler(t, http.MethodPost, "/compute/checkout", NewComputeCheckoutHandler(
		nil,
		func() controller.ComputeLedgerSecrets { return nil },
		func() controller.ComputeStripeCheckout { return stripe },
	))
	answer = testComputeApiRoute(t, http.MethodPost, "/compute/checkout").Serve(context.Background(), testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER), nil, []byte(`{"pack_credits":25}`))
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusServiceUnavailable || code != ComputeApiRefusalUnavailable || stripe.count() != 0 {
		t.Fatalf("an unkeyed host with Stripe: %d %s, %d sessions", answer.Status, code, stripe.count())
	}
}
