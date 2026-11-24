package computeservice

// §14.3's route table (CSRV-M12-01): nineteen routes on compute.<root> under /v1/, each registered by its area or
// listed unbuilt and never both, an unbuilt route answering not_built behind the whole guard, and the registry refusing
// what no design route is.

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Every design route is registered or listed unbuilt, never both and never neither, and every listed name is a design
// route: as mcpCatalogUnbuilt holds MCP's tools, so a gap between the areas' plans fails here, never in a block.
func TestComputeDesignRoutesAreRegisteredOrUnbuilt(t *testing.T) {
	design := computeRouteDesign()
	if len(design) != 19 {
		t.Fatalf("the table holds %d routes, §14.3 nineteen", len(design))
	}
	registered := registeredComputeRouteHandlers()
	names := map[string]bool{}
	patterns := map[string]bool{}
	for _, route := range design {
		if names[route.Name] || patterns[route.Method+" "+route.Pattern] {
			t.Errorf("%s twice", route.Name)
		}
		names[route.Name] = true
		patterns[route.Method+" "+route.Pattern] = true
		if route.Name != route.Method+" "+route.Pattern || !strings.HasPrefix(route.Pattern, "/v1/") {
			t.Errorf("%s is not its method and a pattern under /v1/", route.Name)
		}
		if !slices.Contains([]string{computeOwnerInfer, computeOwnerAttest, computeOwnerBal, computeOwnerSrch, computeOwnerEnc}, route.Owner) {
			t.Errorf("%s has no owner", route.Name)
		}
		_, isRegistered := registered[route.Name]
		unbuilt := slices.Contains(computeRouteUnbuilt, route.Name)
		switch {
		case isRegistered && unbuilt:
			t.Errorf("%s is registered and still listed unbuilt", route.Name)
		case !isRegistered && !unbuilt:
			t.Errorf("%s (%s) is neither registered nor listed unbuilt", route.Name, route.Owner)
		}
	}
	for _, name := range computeRouteUnbuilt {
		if !names[name] {
			t.Errorf("%s is listed unbuilt and is no §14.3 route", name)
		}
	}
	for name := range registered {
		if !names[name] {
			t.Errorf("%s is registered and is no §14.3 route", name)
		}
	}
}

// The flags §14.3 gives its routes, as the guard reads them.
func TestComputeDesignRoutesCarryTheirFlags(t *testing.T) {
	routes := map[string]*ComputeRoute{}
	for _, route := range computeRouteDesign() {
		routes[route.Name] = route
	}
	for name, auth := range map[string]ComputeRouteAuth{ComputeRouteCollateral: ComputeRouteAuthNone, ComputeRouteEnclaveEvidencePost: ComputeRouteAuthOwn} {
		if routes[name].Auth != auth {
			t.Errorf("%s's caller is %d", name, routes[name].Auth)
		}
	}
	for name, route := range routes {
		enclave := strings.HasPrefix(route.Pattern, "/v1/enclaves")
		if enclave != (route.Group == ComputeMigrationGroupC3) {
			t.Errorf("%s reads group %q", name, route.Group)
		}
		if !enclave && route.Group != "" {
			t.Errorf("%s names a group the block's readiness already requires", name)
		}
		if name != ComputeRouteCollateral && name != ComputeRouteEnclaveEvidencePost && route.Auth != ComputeRouteAuthSidecar {
			t.Errorf("%s does not take a sidecar's token", name)
		}
	}
	if !routes[ComputeRouteSearchAuthorize].NoLog || 1 < len(slices.DeleteFunc(slices.Collect(maps.Values(routes)), func(route *ComputeRoute) bool { return !route.NoLog })) {
		t.Error("search authorize alone leaves no line")
	}
	if route := routes[ComputeRouteBudgetRaise]; route.Approval != ComputeApprovalKindBudgetRaise || !route.IdempotencyKey {
		t.Error("budget raise takes kind 21 under an Idempotency-Key")
	}
	if route := routes[ComputeRouteEnclaveCreate]; route.Approval != ComputeApprovalKindEnclaveCreate || !route.IdempotencyKey || !route.Admission {
		t.Error("an enclave create takes kind 19 under an Idempotency-Key, and is an admission")
	}
	if route := routes[ComputeRouteEnclaveStart]; route.Approval != ComputeApprovalKindEnclaveCreate || !route.ApprovalConditional || !route.Admission {
		t.Error("a start takes its kind 19 where a tool asked for it, and is an admission")
	}
	for _, name := range []string{ComputeRouteInfer, ComputeRouteInferAuthorize, ComputeRouteSearchAuthorize, ComputeRouteEnclaveCreate, ComputeRouteEnclaveStart} {
		if !routes[name].Admission {
			t.Errorf("%s is no admission", name)
		}
	}
	if !routes[ComputeRouteInfer].Streams || !routes[ComputeRouteEnclaveEvidencePost].Streams || !routes[ComputeRouteTunnel].Hijacks {
		t.Error("infer streams, the VM's evidence long-polls and the tunnel hijacks")
	}
}

// With no area's handler, every design route answers 503 not_built to a caller every guard step admits, collateral
// and the VM's evidence route included, and the engine lists each as unbuilt.
func TestComputeUnbuiltRouteAnswersNotBuilt(t *testing.T) {
	fixture := newComputeFixture(t, &computeFixtureOptions{approvalGate: &fakeComputeApprovalGate{}})
	headers := map[string]string{ComputeIdempotencyKeyHeader: "effect-key-1"}
	for _, route := range computeRouteDesign() {
		path := strings.ReplaceAll(route.Pattern, "{id}", sidecar.EvsKeyId(testComputeId("enclave-1")))
		path = strings.ReplaceAll(path, "{vendor}", "intel")
		path = strings.ReplaceAll(path, "{item}", "tcb-info")
		recorder := fixture.serve(route.Method, path, fixture.token(), "", headers)
		if recorder.Code != http.StatusServiceUnavailable || computeRefusalCodeOf(recorder) != ComputeRefusalNotBuilt {
			t.Errorf("%s: %d %s", route.Name, recorder.Code, recorder.Body.String())
		}
	}
	if unbuilt := fixture.engine.UnbuiltRoutes(); len(unbuilt) != 19 {
		t.Fatalf("the engine lists %d routes unbuilt", len(unbuilt))
	}
	// a route with no caller still waits on an enabled gate
	if err := fixture.gates.Set(""); err != nil {
		t.Fatal(err)
	}
	requireComputeRefusal(t, fixture.serve(http.MethodGet, "/v1/collateral/intel/tcb-info", "", "", nil), http.StatusServiceUnavailable, ComputeRefusalUnavailable)
}

// The registry takes a design route's handler once, and refuses a name that is no route, a nil handler and a second
// registration, each a panic at init.
func TestComputeRegistryRefusesWhatIsNoRoute(t *testing.T) {
	saved := computeRouteHandlers
	t.Cleanup(func() { computeRouteHandlers = saved })
	computeRouteHandlers = map[string]ComputeHandler{}
	handler := func(request *ComputeRequest) { request.Reply(nil) }
	registerComputeRoutes(map[string]ComputeHandler{ComputeRouteCatalog: handler})
	if _, ok := registeredComputeRouteHandlers()[ComputeRouteCatalog]; !ok {
		t.Fatal("the catalog's handler did not register")
	}
	for label, handlers := range map[string]map[string]ComputeHandler{
		"no route":    {"GET /v1/nothing": handler},
		"no handler":  {ComputeRouteTunnel: nil},
		"a second go": {ComputeRouteCatalog: handler},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			registerComputeRoutes(handlers)
		}()
	}
	savedChecks := computeAdmissionChecks
	t.Cleanup(func() { computeAdmissionChecks = savedChecks })
	computeAdmissionChecks = nil
	check := func(request *ComputeRequest) *ComputeRefusal { return nil }
	registerComputeAdmissionCheck("hold", check)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a check registered twice")
			}
		}()
		registerComputeAdmissionCheck("hold", check)
	}()
}
