// The compute routes' shape and their handlers' registration (§14.3). routes_design.go is the design's table, one
// ComputeRoute per route; each area registers its handlers by route name from its own computeservice/<area>_*.go file
// at init, through registerComputeRoutes, as mcp/'s tools and cli/'s commands register (C-21), so no area edits the
// engine to add one. A design route no area has registered answers 503 not_built behind the full guard, and stays
// listed in computeRouteUnbuilt until its area lands: TestComputeDesignRoutesAreRegisteredOrUnbuilt fails a route that
// is neither, or both, and the area removes its line in the change that registers it.
//
// The registry is written at init and read once by each engine's constructor, so nothing guards it beyond that order.

package computeservice

import (
	"fmt"
	"maps"
)

// Who a route takes its caller from (§14.3's Auth column).
type ComputeRouteAuth int

const (
	// A sidecar's service token for the compute audience, through the whole guard (auth.go).
	ComputeRouteAuthSidecar ComputeRouteAuth = 1
	// No caller: vendor-signed collateral anyone may read (§5.7). Only the gate's being enabled at all is asked.
	ComputeRouteAuthNone ComputeRouteAuth = 2
	// The route checks its own credential, an enclave VM's per-VM token (§11.7), which its handler verifies; the
	// guard asks only whether the gate is enabled at all.
	ComputeRouteAuthOwn ComputeRouteAuth = 3
)

// A pending migration group a route reads beyond the block's, by §14.4's name (CSRV-M12-02).
type ComputeMigrationGroup string

const (
	// The ledger (M12): the block's readiness requires it.
	ComputeMigrationGroupC1 ComputeMigrationGroup = "MG-C1"
	// Providers, gamma and search outcomes (M12): the block's readiness requires it.
	ComputeMigrationGroupC2 ComputeMigrationGroup = "MG-C2"
	// Enclaves (M14): checked per request, so the block is ready between M12's exit and M14's.
	ComputeMigrationGroupC3 ComputeMigrationGroup = "MG-C3"
)

// An approval a route admits only with, as §16.3 numbers its kinds.
type ComputeApprovalKind int

const (
	// enclave_create, and an enclave start a tool asked for (§16.3, §7.5).
	ComputeApprovalKindEnclaveCreate ComputeApprovalKind = 19
	// compute_budget_raise (§16.3).
	ComputeApprovalKindBudgetRaise ComputeApprovalKind = 21
)

// Answers one request that has passed every guard step. It runs on the request's goroutine and answers through the
// request's methods; an answer it never writes fails closed as 503 unavailable.
type ComputeHandler func(request *ComputeRequest)

// One compute route: what it is, who may call it and how the guard holds it.
type ComputeRoute struct {
	// "GET", "POST" or "DELETE".
	Method string
	// net/http's pattern from the root of compute.<root>, under /v1/: §14.3's compute/v1/x is host compute, path
	// /v1/x, as its api/compute/x is host api (§5.7 writes compute.bringyour.com/v1/tunnel).
	Pattern string
	// The method and pattern, which hold no id: the route's label in metrics and the service log (I-13), and the
	// name an area registers its handler by.
	Name string
	Auth ComputeRouteAuth
	// The group whose tables the route reads beyond the block's, checked per request; "" for none.
	Group ComputeMigrationGroup
	// The area that builds its handler: INFER, ATTEST, BAL, SRCH or ENC.
	Owner string
	// Answers as a stream (an SSE response or a long poll), so the guard's handler may run past the status server's
	// write timeout through ComputeStream.
	Streams bool
	// Hijacks its connection: the tunnel's WebSocket, which ATTEST's handler upgrades.
	Hijacks bool
	// Takes Idempotency-Key: <effect_key>, which the guard requires before the handler.
	IdempotencyKey bool
	// The approval kind the route admits only with, 0 for none.
	Approval ComputeApprovalKind
	// The approval is asked only where the request carries one, which the approval gate decides: an enclave start a
	// tool asked for (§14.3).
	ApprovalConditional bool
	// A broker admission, which every registered ComputeAdmissionCheck reads: remote calls, searches and enclave
	// creates and starts (CARCH-M12-01).
	Admission bool
	// Leaves no service log line: its counts go to metrics alone (§14.2's Logs row, §21.5).
	NoLog bool
	// The registered handler, nil for a route no area has built yet.
	handler ComputeHandler
}

// Whether a closed gate's `writes: false` closes the route: every route but a GET.
func (self *ComputeRoute) Write() bool {
	return self.Method != "GET"
}

// The handlers areas registered, by route name.
var computeRouteHandlers = map[string]ComputeHandler{}

// Registers an area's handlers by route name, from its file's init. A name that is no design route, a nil handler and
// a second registration of one route each panic: a build that registers wrongly does not start.
func registerComputeRoutes(handlers map[string]ComputeHandler) {
	designNames := map[string]bool{}
	for _, route := range computeRouteDesign() {
		designNames[route.Name] = true
	}
	for name, handler := range handlers {
		if !designNames[name] {
			panic(fmt.Errorf("compute route %q is not one of §14.3's", name))
		}
		if handler == nil {
			panic(fmt.Errorf("compute route %q registered with no handler", name))
		}
		if _, registered := computeRouteHandlers[name]; registered {
			panic(fmt.Errorf("compute route %q registered twice", name))
		}
		computeRouteHandlers[name] = handler
	}
}

// The registered handlers, a copy.
func registeredComputeRouteHandlers() map[string]ComputeHandler {
	return maps.Clone(computeRouteHandlers)
}

// The design's routes with each handler resolved from handlers, a fresh copy for one engine.
func computeRoutes(handlers map[string]ComputeHandler) []*ComputeRoute {
	routes := computeRouteDesign()
	for _, route := range routes {
		route.handler = handlers[route.Name]
	}
	return routes
}
