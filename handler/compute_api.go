// The api/compute/* routes' frame (DESIGN-COMPUTE §14.3; BAL-M12-06): sidecar/handler, the api half of owner decision
// 594, so CSRV's mount (C§14.3) binds every route of §14.3's api/compute rows at once, each answering not_built until
// its task registers a handler (BAL-M12-08, 11, 13, 14, 15, BAL-M13-03).
//
// The routes, as api serves them (host api, path /compute/x for api/compute/x), each with who may call it, which the
// frame checks before any handler runs:
//
//	GET  /compute/balance       a sidecar or the network's credential
//	POST /compute/checkout      MayBuy
//	GET  /compute/auto-renew    MayBuy
//	POST /compute/auto-renew    MayBuy
//	GET  /compute/charges       SeesNetwork, or a Member's own (SeesMember)
//	GET  /compute/statement     as charges
//	GET  /compute/spend         as charges, and only from the person's consented device
//	POST /compute/refund        an Owner or a Billing admin
//	POST /compute/promo/redeem  MayBuy
//	GET  /compute/terms         a member device or the network's credential
//	POST /compute/terms         an Owner or an Admin, from an untagged sidecar or the network's credential
//
// A handler takes the process's global Env (operator.GlobalEnv, owner decision 594), the caller, and the request: a
// GET's query, which the frame holds to the route's own keys, or a POST's JSON body, which the frame holds to its size
// and to JSON, a POST taking no query at all, so a code, a card or any other secret never travels in a query string.
// It answers a value the frame writes as JSON, or a *ComputeApiRefusal, written as the device's client reads one
// (sidecar/api_client.go): its status and {"code", "retry_after_ms"}. Any other error answers 500 internal, with none
// of its text.
//
// Rights come from the verified state the api holds, never from the request: the mount fills ComputeApiCaller
// (compute_caller.go) and the frame reads nothing of the request for them.

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"

	operator "github.com/urnetwork/operator-core"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §14.3's and the frame's refusal codes, as the device's client reads them (sidecar/compute_client_api.go).
const (
	// The route's handler is not built yet.
	ComputeApiRefusalNotBuilt = "not_built"
	// The caller may not buy (§9.10).
	ComputeApiRefusalMayNotBuy = "may_not_buy"
	// The caller sees no charges or spend view (§9.10).
	ComputeApiRefusalMayNotSee = "may_not_see"
	// The spend view asks for the person's consented device (§14.3; Q-BAL-11).
	ComputeApiRefusalConsentedDeviceRequired = "consented_device_required"
	// The route asks for a role the caller lacks: an Owner or Billing admin to refund, an Owner or Admin to accept
	// terms.
	ComputeApiRefusalRoleRequired = "role_required"
	// The route takes no agent's or MCP's credential.
	ComputeApiRefusalCredentialRefused = "credential_refused"
	// The query names a key the route does not take, a POST carries a query, or the body is no JSON object or is
	// past its bound.
	ComputeApiRefusalBadRequest = "bad_request"
	// The handler failed; its text stays in the server.
	ComputeApiRefusalInternal = "internal"
)

// A route's refusal: its status and code, with a retry hint where it has one.
type ComputeApiRefusal struct {
	Status       int
	Code         string
	RetryAfterMs uint32
}

// The status and code, nothing else.
func (self *ComputeApiRefusal) Error() string {
	return fmt.Sprintf("compute api refused: %d %s", self.Status, self.Code)
}

// The frame's settings.
type ComputeApiSettings struct {
	// The most a POST's JSON body may hold: 64 KiB, past every compute route's request (a checkout's pack and its
	// auto-renew, a code, a lot id).
	BodyMaxByteCount int
}

// The frame's defaults, the only place one is set.
func DefaultComputeApiSettings() *ComputeApiSettings {
	return &ComputeApiSettings{
		BodyMaxByteCount: 64 * 1024,
	}
}

// A request as a handler reads it.
type ComputeApiRequest struct {
	// A GET's query, held to the route's keys; empty for a POST.
	Query url.Values
	// A POST's JSON body; empty for a GET.
	Body []byte
}

// A route's handler: env is the process's global Env, caller the verified caller, request what the frame let
// through. It answers a value written as JSON, or a *ComputeApiRefusal.
type ComputeApiHandler func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error)

// What a route answers: a status and a JSON body.
type ComputeApiAnswer struct {
	Status int
	Body   []byte
}

// One of §14.3's api/compute routes.
type ComputeApiRoute struct {
	// GET or POST.
	Method string
	// As api serves it: /compute/balance.
	Path string
	// The query keys a GET takes.
	queryKeys []string
	// Who may call it, before its handler runs: nil where the caller may, else the refusal.
	authorize func(caller *ComputeApiCaller) *ComputeApiRefusal
	settings  *ComputeApiSettings
}

// A refusal with its status.
func computeApiRefusal(status int, code string) *ComputeApiRefusal {
	return &ComputeApiRefusal{Status: status, Code: code}
}

// The checks §14.3's Auth column names, by the caller's rights.
var (
	computeApiSidecarOrNetwork = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if caller.Credential == ComputeApiCredentialSidecar && caller.SidecarId != nil {
			return nil
		}
		if caller.Credential == ComputeApiCredentialNetwork {
			return nil
		}
		return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalCredentialRefused)
	}
	computeApiMayBuy = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if !caller.MayBuy() {
			return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalMayNotBuy)
		}
		return nil
	}
	computeApiMaySee = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if _, member := caller.SeesMember(); !caller.SeesNetwork() && !member {
			return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalMayNotSee)
		}
		return nil
	}
	computeApiMaySeeFromConsentedDevice = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if !caller.ConsentedDevice() {
			return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalConsentedDeviceRequired)
		}
		return computeApiMaySee(caller)
	}
	computeApiMayRefund = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if !caller.hasRole(bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN) {
			return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalRoleRequired)
		}
		return nil
	}
	computeApiMemberDeviceOrNetwork = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if caller.Credential == ComputeApiCredentialNetwork {
			return nil
		}
		if caller.Credential == ComputeApiCredentialSidecar && caller.SidecarId != nil && caller.MemberId != nil && !caller.Tagged {
			return nil
		}
		return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalCredentialRefused)
	}
	computeApiMayAcceptTerms = func(caller *ComputeApiCaller) *ComputeApiRefusal {
		if !caller.hasRole(bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN) {
			return computeApiRefusal(http.StatusForbidden, ComputeApiRefusalRoleRequired)
		}
		return nil
	}
)

// §14.3's api/compute rows, in its order.
func computeApiRouteTable(settings *ComputeApiSettings) []*ComputeApiRoute {
	route := func(method string, path string, authorize func(caller *ComputeApiCaller) *ComputeApiRefusal, queryKeys ...string) *ComputeApiRoute {
		return &ComputeApiRoute{Method: method, Path: path, queryKeys: queryKeys, authorize: authorize, settings: settings}
	}
	return []*ComputeApiRoute{
		route(http.MethodGet, "/compute/balance", computeApiSidecarOrNetwork),
		route(http.MethodPost, "/compute/checkout", computeApiMayBuy),
		route(http.MethodGet, "/compute/auto-renew", computeApiMayBuy),
		route(http.MethodPost, "/compute/auto-renew", computeApiMayBuy),
		route(http.MethodGet, "/compute/charges", computeApiMaySee, "cursor"),
		route(http.MethodGet, "/compute/statement", computeApiMaySee, "month"),
		route(http.MethodGet, "/compute/spend", computeApiMaySeeFromConsentedDevice, "by"),
		route(http.MethodPost, "/compute/refund", computeApiMayRefund),
		route(http.MethodPost, "/compute/promo/redeem", computeApiMayBuy),
		route(http.MethodGet, "/compute/terms", computeApiMemberDeviceOrNetwork),
		route(http.MethodPost, "/compute/terms", computeApiMayAcceptTerms),
	}
}

// The routes' handlers as registered, by method and path.
var (
	computeApiStateLock sync.Mutex
	computeApiHandlers  = map[string]ComputeApiHandler{}
)

// A route's registry key.
func computeApiRouteKey(method string, path string) string {
	return method + " " + path
}

// Binds a route of §14.3's table to its handler, from an init function in the handler's own file. A route the table
// does not name, a second registration, or a nil handler is a build error, which panics.
func RegisterComputeApiHandler(method string, path string, handler ComputeApiHandler) {
	if handler == nil {
		panic("compute api: a nil handler")
	}
	if !slices.ContainsFunc(computeApiRouteTable(DefaultComputeApiSettings()), func(route *ComputeApiRoute) bool {
		return route.Method == method && route.Path == path
	}) {
		panic(fmt.Sprintf("compute api: %s %s is no route of §14.3", method, path))
	}
	computeApiStateLock.Lock()
	defer computeApiStateLock.Unlock()
	key := computeApiRouteKey(method, path)
	if _, registered := computeApiHandlers[key]; registered {
		panic(fmt.Sprintf("compute api: %s registered twice", key))
	}
	computeApiHandlers[key] = handler
}

// The registered handler of a route, nil until one registers.
func computeApiHandlerOf(method string, path string) ComputeApiHandler {
	computeApiStateLock.Lock()
	defer computeApiStateLock.Unlock()
	return computeApiHandlers[computeApiRouteKey(method, path)]
}

// Every route of §14.3's api/compute rows, for the mount to bind at once; nil settings take the defaults.
func ComputeApiRoutes(settings *ComputeApiSettings) []*ComputeApiRoute {
	if settings == nil {
		settings = DefaultComputeApiSettings()
	}
	return computeApiRouteTable(settings)
}

// A refusal as the client reads one.
func computeApiRefusalAnswer(refusal *ComputeApiRefusal) *ComputeApiAnswer {
	body, _ := json.Marshal(map[string]any{"code": refusal.Code, "retry_after_ms": refusal.RetryAfterMs})
	return &ComputeApiAnswer{Status: refusal.Status, Body: body}
}

// Serves one call of the route: the caller's rights first, then the request's shape, then the registered handler,
// with the process's global Env, or not_built.
func (self *ComputeApiRoute) Serve(ctx context.Context, caller *ComputeApiCaller, query url.Values, body []byte) *ComputeApiAnswer {
	if caller == nil {
		return computeApiRefusalAnswer(computeApiRefusal(http.StatusForbidden, ComputeApiRefusalCredentialRefused))
	}
	if refusal := self.authorize(caller); refusal != nil {
		return computeApiRefusalAnswer(refusal)
	}
	request := &ComputeApiRequest{Query: url.Values{}}
	switch self.Method {
	case http.MethodGet:
		for key, values := range query {
			if !slices.Contains(self.queryKeys, key) || len(values) != 1 {
				return computeApiRefusalAnswer(computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest))
			}
			request.Query.Set(key, values[0])
		}
		if 0 < len(body) {
			return computeApiRefusalAnswer(computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest))
		}
	case http.MethodPost:
		trimmed := bytes.TrimSpace(body)
		if 0 < len(query) || self.settings.BodyMaxByteCount < len(body) || len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
			return computeApiRefusalAnswer(computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest))
		}
		request.Body = trimmed
	}
	handler := computeApiHandlerOf(self.Method, self.Path)
	if handler == nil {
		return computeApiRefusalAnswer(computeApiRefusal(http.StatusNotImplemented, ComputeApiRefusalNotBuilt))
	}
	answer, err := handler(operator.GlobalEnv(), ctx, caller, request)
	if err != nil {
		var refusal *ComputeApiRefusal
		if errors.As(err, &refusal) {
			return computeApiRefusalAnswer(refusal)
		}
		return computeApiRefusalAnswer(computeApiRefusal(http.StatusInternalServerError, ComputeApiRefusalInternal))
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return computeApiRefusalAnswer(computeApiRefusal(http.StatusInternalServerError, ComputeApiRefusalInternal))
	}
	return &ComputeApiAnswer{Status: http.StatusOK, Body: encoded}
}
