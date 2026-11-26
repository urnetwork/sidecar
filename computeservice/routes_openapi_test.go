package computeservice

// §14.3's compute routes as bringyour.yml documents them (CSRV-M12-04): connect/api/check-routes.sh runs this beside
// gkm's and sockets' spec tests, with URNETWORK_CONNECT_OPENAPI_SPEC naming the document it checks.

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/specroutes"
)

// The host bringyour.yml documents compute's routes on (§14.2).
const computeOpenApiHost = "https://compute.bringyour.com"

// computeRouteDesign and the spec's operations on compute's host match both ways, and the engine serves each one, its
// handler built or not; api's /v1/seed.bin, under the same prefix on api's host, is not compute's.
func TestComputeRoutesMatchOpenApi(t *testing.T) {
	fixture := newComputeFixture(t, nil)
	patterns := []string{}
	for _, route := range fixture.engine.Routes() {
		patterns = append(patterns, route.Method+" "+route.Pattern)
	}
	if len(patterns) != len(computeRouteDesign()) {
		t.Fatalf("the engine serves %d routes, the design %d", len(patterns), len(computeRouteDesign()))
	}
	specroutes.CheckHost(t, computeOpenApiHost, "/v1/", fixture.engine.Handler().(*http.ServeMux), patterns)
}
