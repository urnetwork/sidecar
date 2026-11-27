// The api/compute routes still waiting for their handlers (DESIGN-COMPUTE §14.3; CSRV-M12-04). The routes' table, the
// caller's rights and the registry are the frame's (compute_api.go, compute_caller.go; BAL-M12-06), which server's
// mount binds all at once (server/api/sidecar_handler_mount.go), each route answering 501 not_built through the frame
// until its task registers a handler from its own sidecar/handler/compute_*.go file.
//
// computeApiRouteUnbuilt names the routes no task has registered yet, as the compute engine's computeRouteUnbuilt does
// for compute.<root>'s: TestComputeApiRoutesAreRegisteredOrUnbuilt fails a route that is neither registered nor listed,
// or both, and a task removes its route's line in the change that registers its handler.

package handler

// The routes of §14.3's api/compute rows no handler is registered for, as "METHOD path", with the task that builds each.
var computeApiRouteUnbuilt = []string{
	// §9.13's balance, BAL-M12-15
	"GET /compute/balance",
	// §9.10's and §9.13's reads, BAL-M12-15
	"GET /compute/charges",
	"GET /compute/statement",
	"GET /compute/spend",
	// §21.9's terms and their clauses, BAL-M13-03
	"GET /compute/terms",
	"POST /compute/terms",
}
