package handler

// The api/compute frame (BAL-M12-06): §14.3's routes, each answering not_built until registered; the caller's rights
// checked before any handler; no secret taken from a query string; refusals written as the device reads them; and the
// handler handed the process's global Env.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	operator "github.com/urnetwork/operator-core"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Registers handler for the test alone.
func testRegisterComputeApiHandler(t *testing.T, method string, path string, handler ComputeApiHandler) {
	RegisterComputeApiHandler(method, path, handler)
	t.Cleanup(func() {
		computeApiStateLock.Lock()
		defer computeApiStateLock.Unlock()
		delete(computeApiHandlers, computeApiRouteKey(method, path))
	})
}

// The route of method and path.
func testComputeApiRoute(t *testing.T, method string, path string) *ComputeApiRoute {
	for _, route := range ComputeApiRoutes(nil) {
		if route.Method == method && route.Path == path {
			return route
		}
	}
	t.Fatalf("no route %s %s", method, path)
	return nil
}

// A refusal's code and retry from an answer's body.
func testComputeApiCode(t *testing.T, answer *ComputeApiAnswer) (string, uint32) {
	body := struct {
		Code         string `json:"code"`
		RetryAfterMs uint32 `json:"retry_after_ms"`
	}{}
	if err := json.Unmarshal(answer.Body, &body); err != nil {
		t.Fatalf("the answer's body %q: %v", answer.Body, err)
	}
	return body.Code, body.RetryAfterMs
}

// Every route of §14.3's api/compute rows answers not_built until its task registers it; a registered one answers its
// handler's JSON; a route the table does not name, a second registration and a nil handler are refused.
func TestComputeApiRoutesRefuseUntilRegistered(t *testing.T) {
	want := []string{
		"GET /compute/balance", "POST /compute/checkout", "GET /compute/auto-renew", "POST /compute/auto-renew",
		"GET /compute/charges", "GET /compute/statement", "GET /compute/spend", "POST /compute/refund",
		"POST /compute/promo/redeem", "GET /compute/terms", "POST /compute/terms",
	}
	routes := ComputeApiRoutes(nil)
	if len(routes) != len(want) {
		t.Fatalf("%d routes", len(routes))
	}
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	for i, route := range routes {
		if route.Method+" "+route.Path != want[i] {
			t.Errorf("route %d is %s %s, want %s", i, route.Method, route.Path, want[i])
		}
		body := []byte(nil)
		if route.Method == http.MethodPost {
			body = []byte("{}")
		}
		answer := route.Serve(context.Background(), owner, nil, body)
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusNotImplemented || code != ComputeApiRefusalNotBuilt {
			t.Errorf("%s %s answers %d %s", route.Method, route.Path, answer.Status, code)
		}
	}

	envs := []operator.Env{}
	testRegisterComputeApiHandler(t, http.MethodGet, "/compute/balance", func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		envs = append(envs, env)
		return map[string]any{"available_nano_usd": 5, "may_buy": caller.MayBuy()}, nil
	})
	answer := testComputeApiRoute(t, http.MethodGet, "/compute/balance").Serve(context.Background(), owner, nil, nil)
	if answer.Status != http.StatusOK || string(answer.Body) != `{"available_nano_usd":5,"may_buy":true}` {
		t.Errorf("the registered route answers %d %s", answer.Status, answer.Body)
	}
	if len(envs) != 1 || envs[0] != operator.GlobalEnv() {
		t.Error("the handler was not handed the process's global Env")
	}

	for label, register := range map[string]func(){
		"no route": func() {
			RegisterComputeApiHandler(http.MethodGet, "/compute/cards", func(operator.Env, context.Context, *ComputeApiCaller, *ComputeApiRequest) (any, error) {
				return nil, nil
			})
		},
		"a method": func() {
			RegisterComputeApiHandler(http.MethodPost, "/compute/balance", func(operator.Env, context.Context, *ComputeApiCaller, *ComputeApiRequest) (any, error) {
				return nil, nil
			})
		},
		"twice": func() {
			RegisterComputeApiHandler(http.MethodGet, "/compute/balance", func(operator.Env, context.Context, *ComputeApiCaller, *ComputeApiRequest) (any, error) {
				return nil, nil
			})
		},
		"a nil one": func() { RegisterComputeApiHandler(http.MethodGet, "/compute/spend", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
}

// The caller's rights are checked before any handler runs, by §14.3's Auth column: an Auditor never reaches checkout,
// a Member's tagged sidecar never the spend view, an agent's token never the balance, neither a Member nor an Admin a
// refund, and a Member never accepts terms; and the callers it lets through reach their handlers.
func TestComputeApiFrameChecksRightsBeforeHandlers(t *testing.T) {
	reached := 0
	handler := func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		reached += 1
		return map[string]any{}, nil
	}
	for _, route := range ComputeApiRoutes(nil) {
		testRegisterComputeApiHandler(t, route.Method, route.Path, handler)
	}
	taggedMember := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	taggedMember.Tagged = true
	agent := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	agent.Credential = ComputeApiCredentialAgent
	unconsented := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	unconsented.Consented = false
	type call struct {
		label  string
		method string
		path   string
		caller *ComputeApiCaller
		code   string
	}
	for _, c := range []call{
		{label: "an Auditor's checkout", method: http.MethodPost, path: "/compute/checkout", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_AUDITOR), code: ComputeApiRefusalMayNotBuy},
		{label: "a Member's redemption", method: http.MethodPost, path: "/compute/promo/redeem", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER), code: ComputeApiRefusalMayNotBuy},
		{label: "an agent's auto-renew", method: http.MethodPost, path: "/compute/auto-renew", caller: agent, code: ComputeApiRefusalMayNotBuy},
		{label: "a tagged sidecar's spend view", method: http.MethodGet, path: "/compute/spend", caller: taggedMember, code: ComputeApiRefusalConsentedDeviceRequired},
		{label: "an unconsented device's spend view", method: http.MethodGet, path: "/compute/spend", caller: unconsented, code: ComputeApiRefusalConsentedDeviceRequired},
		{label: "a tagged sidecar's charges", method: http.MethodGet, path: "/compute/charges", caller: taggedMember, code: ComputeApiRefusalMayNotSee},
		{label: "an agent's balance", method: http.MethodGet, path: "/compute/balance", caller: agent, code: ComputeApiRefusalCredentialRefused},
		{label: "a Member's refund", method: http.MethodPost, path: "/compute/refund", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER), code: ComputeApiRefusalRoleRequired},
		{label: "an Admin's refund", method: http.MethodPost, path: "/compute/refund", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN), code: ComputeApiRefusalRoleRequired},
		{label: "a Member's acceptance", method: http.MethodPost, path: "/compute/terms", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER), code: ComputeApiRefusalRoleRequired},
		{label: "a tagged sidecar's terms", method: http.MethodGet, path: "/compute/terms", caller: taggedMember, code: ComputeApiRefusalCredentialRefused},
		{label: "no caller", method: http.MethodGet, path: "/compute/balance", caller: nil, code: ComputeApiRefusalCredentialRefused},
	} {
		body := []byte(nil)
		if c.method == http.MethodPost {
			body = []byte("{}")
		}
		answer := testComputeApiRoute(t, c.method, c.path).Serve(context.Background(), c.caller, nil, body)
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusForbidden || code != c.code {
			t.Errorf("%s answers %d %s", c.label, answer.Status, code)
		}
	}
	if reached != 0 {
		t.Errorf("a refused caller reached a handler %d times", reached)
	}
	// and the callers §14.3 lets through reach it: a Member's own charges, its consented device's spend view, the
	// Owner's network credential's checkout, a tagged sidecar's balance, an Admin's acceptance
	taggedBalance := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED)
	taggedBalance.Tagged = true
	taggedBalance.MemberId = nil
	for _, c := range []call{
		{method: http.MethodGet, path: "/compute/charges", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)},
		{method: http.MethodGet, path: "/compute/spend", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)},
		{method: http.MethodPost, path: "/compute/checkout", caller: &ComputeApiCaller{Credential: ComputeApiCredentialNetwork, Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		{method: http.MethodGet, path: "/compute/balance", caller: taggedBalance},
		{method: http.MethodPost, path: "/compute/terms", caller: testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN)},
	} {
		body := []byte(nil)
		if c.method == http.MethodPost {
			body = []byte("{}")
		}
		if answer := testComputeApiRoute(t, c.method, c.path).Serve(context.Background(), c.caller, nil, body); answer.Status != http.StatusOK {
			t.Errorf("%s %s answers %d %s", c.method, c.path, answer.Status, answer.Body)
		}
	}
	if reached != 5 {
		t.Errorf("the allowed callers reached a handler %d times", reached)
	}
}

// A POST takes no query, so no code, card or token rides one; a GET takes its route's keys alone, once each, and no
// body; a POST's body is one JSON object within its bound. The handler sees only what passed.
func TestComputeApiFrameTakesNoSecretFromAQueryString(t *testing.T) {
	requests := []*ComputeApiRequest{}
	handler := func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		requests = append(requests, request)
		return map[string]any{}, nil
	}
	testRegisterComputeApiHandler(t, http.MethodPost, "/compute/promo/redeem", handler)
	testRegisterComputeApiHandler(t, http.MethodGet, "/compute/charges", handler)
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	redeem := testComputeApiRoute(t, http.MethodPost, "/compute/promo/redeem")
	charges := testComputeApiRoute(t, http.MethodGet, "/compute/charges")
	refused := map[string]*ComputeApiAnswer{
		"a code in the query":   redeem.Serve(context.Background(), owner, url.Values{"code": {"TESTCODE1234"}}, []byte("{}")),
		"no body":               redeem.Serve(context.Background(), owner, nil, nil),
		"no JSON":               redeem.Serve(context.Background(), owner, nil, []byte("code=TESTCODE1234")),
		"a JSON array":          redeem.Serve(context.Background(), owner, nil, []byte(`["TESTCODE1234"]`)),
		"a body past its bound": redeem.Serve(context.Background(), owner, nil, []byte(`{"code":"`+strings.Repeat("a", 64*1024)+`"}`)),
		"an unknown key":        charges.Serve(context.Background(), owner, url.Values{"token": {"x"}}, nil),
		"a key twice":           charges.Serve(context.Background(), owner, url.Values{"cursor": {"a", "b"}}, nil),
		"a GET's body":          charges.Serve(context.Background(), owner, nil, []byte("{}")),
	}
	for label, answer := range refused {
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusBadRequest || code != ComputeApiRefusalBadRequest {
			t.Errorf("%s answers %d %s", label, answer.Status, code)
		}
	}
	if len(requests) != 0 {
		t.Fatalf("a refused request reached the handler")
	}
	if answer := redeem.Serve(context.Background(), owner, nil, []byte(` {"code":"TESTCODE1234"} `)); answer.Status != http.StatusOK {
		t.Errorf("a redemption answers %d", answer.Status)
	}
	if answer := charges.Serve(context.Background(), owner, url.Values{"cursor": {"next"}}, nil); answer.Status != http.StatusOK {
		t.Errorf("a page of charges answers %d", answer.Status)
	}
	if len(requests) != 2 || string(requests[0].Body) != `{"code":"TESTCODE1234"}` || len(requests[0].Query) != 0 || requests[1].Query.Get("cursor") != "next" {
		t.Errorf("the handler saw %+v and %+v", requests[0], requests[1])
	}
}

// A handler's refusal is written with its status, code and retry, as the device's client reads one; any other error
// answers 500 internal with none of its text.
func TestComputeApiRefusalsReadAsTheClientReadsThem(t *testing.T) {
	failure := errors.New("the database at pg.test.example refused: secret detail")
	testRegisterComputeApiHandler(t, http.MethodGet, "/compute/balance", func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		return nil, &ComputeApiRefusal{Status: http.StatusPaymentRequired, Code: "compute_balance", RetryAfterMs: 1500}
	})
	testRegisterComputeApiHandler(t, http.MethodGet, "/compute/statement", func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		return nil, failure
	})
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	answer := testComputeApiRoute(t, http.MethodGet, "/compute/balance").Serve(context.Background(), owner, nil, nil)
	if code, retry := testComputeApiCode(t, answer); answer.Status != http.StatusPaymentRequired || code != "compute_balance" || retry != 1500 {
		t.Errorf("a handler's refusal answers %d %s %d", answer.Status, code, retry)
	}
	answer = testComputeApiRoute(t, http.MethodGet, "/compute/statement").Serve(context.Background(), owner, url.Values{"month": {"2026-11"}}, nil)
	if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusInternalServerError || code != ComputeApiRefusalInternal {
		t.Errorf("a handler's failure answers %d %s", answer.Status, code)
	}
	if strings.Contains(string(answer.Body), "secret") || strings.Contains(string(answer.Body), "example") {
		t.Errorf("a failure's text reached the answer: %s", answer.Body)
	}
}
