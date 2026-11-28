// §14.3's nineteen compute routes, on compute.<root> under /v1/, as the guard holds each: its caller, the group it
// reads beyond the block's, its owner and its flags. The api/compute/* routes are api's (CSRV-M12-04), not these.
//
// The groups: MG-C1 and MG-C2 are the block's, whose readiness already requires them (computehost), so a route that
// reads only them names none; MG-C3's enclave tables are read per request, so the block is ready between M12's exit
// and M14's while every enclave route answers 503 until MG-C3 links; collateral reads no table.

package computeservice

// Each route's name: its method and pattern, which hold no id (I-13).
const (
	ComputeRouteCatalog             = "GET /v1/catalog"
	ComputeRouteTunnel              = "GET /v1/tunnel"
	ComputeRouteInferPrepare        = "POST /v1/infer/prepare"
	ComputeRouteInfer               = "POST /v1/infer"
	ComputeRouteInferDispute        = "POST /v1/infer/dispute"
	ComputeRouteInferAuthorize      = "POST /v1/infer/authorize"
	ComputeRouteSearchAuthorize     = "POST /v1/search/authorize"
	ComputeRouteSearchOutcomes      = "POST /v1/search/outcomes"
	ComputeRouteBudgetRaise         = "POST /v1/budget/raise"
	ComputeRouteCollateral          = "GET /v1/collateral/{vendor}/{item}"
	ComputeRouteEnclaveCreate       = "POST /v1/enclaves"
	ComputeRouteEnclaveList         = "GET /v1/enclaves"
	ComputeRouteEnclaveGet          = "GET /v1/enclaves/{id}"
	ComputeRouteEnclaveEvidenceGet  = "GET /v1/enclaves/{id}/evidence"
	ComputeRouteEnclaveEvidencePost = "POST /v1/enclaves/{id}/evidence"
	ComputeRouteEnclaveProvision    = "POST /v1/enclaves/{id}/provision"
	ComputeRouteEnclaveStop         = "POST /v1/enclaves/{id}/stop"
	ComputeRouteEnclaveStart        = "POST /v1/enclaves/{id}/start"
	ComputeRouteEnclaveDelete       = "DELETE /v1/enclaves/{id}"
)

// The areas that build the handlers.
const (
	computeOwnerInfer  = "INFER"
	computeOwnerAttest = "ATTEST"
	computeOwnerBal    = "BAL"
	computeOwnerSrch   = "SRCH"
	computeOwnerEnc    = "ENC"
)

// §14.3's routes, a fresh copy each call so no engine shares one. Name is Method and Pattern joined by a space.
func computeRouteDesign() []*ComputeRoute {
	routes := []*ComputeRoute{
		// remote catalog entries and prices, versioned (§6.3)
		{Method: "GET", Pattern: "/v1/catalog", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerInfer},
		// a WebSocket byte relay to an allowlisted provider host, or to an enclave VM's setup address while its
		// incarnation is set up (§5.7, §11.7); the handler reads MG-C3 itself for the enclave case
		{Method: "GET", Pattern: "/v1/tunnel", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerAttest, Hijacks: true},
		// a model's instance keys and one-use nonces (§6.6)
		{Method: "POST", Pattern: "/v1/infer/prepare", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerInfer},
		// one remote call: ComputeInferHeader and the sealed envelope, streaming the chunks and ur_usage (§6.6)
		{Method: "POST", Pattern: "/v1/infer", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerInfer, Streams: true, Admission: true},
		// a charge_mismatch (§6.7)
		{Method: "POST", Pattern: "/v1/infer/dispute", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerInfer},
		// a direct call's btauth/1 headers, after floor, providers, budget and hold (§6.6)
		{Method: "POST", Pattern: "/v1/infer/authorize", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerInfer, Admission: true},
		// one search's admission and the sealed relay to and from searchsigner; no log line (§21.5)
		{Method: "POST", Pattern: "/v1/search/authorize", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerSrch, Admission: true, NoLog: true},
		// a device's unreported search outcome counts (§21.8)
		{Method: "POST", Pattern: "/v1/search/outcomes", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerSrch},
		// kind 21's raise past a default budget (§16.3)
		{Method: "POST", Pattern: "/v1/budget/raise", Auth: ComputeRouteAuthSidecar, Owner: computeOwnerBal, IdempotencyKey: true, Approval: ComputeApprovalKindBudgetRaise},
		// vendor-signed collateral (§5.7)
		{Method: "GET", Pattern: "/v1/collateral/{vendor}/{item}", Auth: ComputeRouteAuthNone, Owner: computeOwnerAttest},
		// kind 19's create (§11.7, §16.3)
		{Method: "POST", Pattern: "/v1/enclaves", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc, IdempotencyKey: true, Approval: ComputeApprovalKindEnclaveCreate, Admission: true},
		// the network's enclaves the caller may see
		{Method: "GET", Pattern: "/v1/enclaves", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc},
		{Method: "GET", Pattern: "/v1/enclaves/{id}", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc},
		// the VM's evidence for a nonce, to a member device of the sponsor
		{Method: "GET", Pattern: "/v1/enclaves/{id}/evidence", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc},
		// the VM's init posts evidence and reads nonces by long poll, under its per-VM token
		{Method: "POST", Pattern: "/v1/enclaves/{id}/evidence", Auth: ComputeRouteAuthOwn, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc, Streams: true},
		// the sealed bundle, relayed once and never stored
		{Method: "POST", Pattern: "/v1/enclaves/{id}/provision", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc},
		// lifecycle (§11.11), a start with its kind 19 where a tool asked for it (§7.5)
		{Method: "POST", Pattern: "/v1/enclaves/{id}/stop", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc},
		{Method: "POST", Pattern: "/v1/enclaves/{id}/start", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc, Approval: ComputeApprovalKindEnclaveCreate, ApprovalConditional: true, Admission: true},
		{Method: "DELETE", Pattern: "/v1/enclaves/{id}", Auth: ComputeRouteAuthSidecar, Group: ComputeMigrationGroupC3, Owner: computeOwnerEnc},
	}
	for _, route := range routes {
		route.Name = route.Method + " " + route.Pattern
	}
	return routes
}

// The design routes whose owners have not landed their handlers: every one, at CSRV-M12-01. An area removes its
// routes in the change that registers them.
var computeRouteUnbuilt = []string{
	ComputeRouteTunnel,
	ComputeRouteInferPrepare,
	ComputeRouteInfer,
	ComputeRouteInferDispute,
	ComputeRouteInferAuthorize,
	ComputeRouteSearchOutcomes,
	ComputeRouteCollateral,
	ComputeRouteEnclaveCreate,
	ComputeRouteEnclaveList,
	ComputeRouteEnclaveGet,
	ComputeRouteEnclaveEvidenceGet,
	ComputeRouteEnclaveEvidencePost,
	ComputeRouteEnclaveProvision,
	ComputeRouteEnclaveStop,
	ComputeRouteEnclaveStart,
	ComputeRouteEnclaveDelete,
}
