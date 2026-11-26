package handler

// The api/compute routes' unbuilt list (CSRV-M12-04): every route of the frame's table is registered or listed
// unbuilt, never both, and a listed one answers not_built through the frame to a caller its rights let through.

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Each of §14.3's eleven api/compute routes is registered or listed unbuilt, never both and never neither; the list
// names no route the table lacks, and twice none.
func TestComputeApiRoutesAreRegisteredOrUnbuilt(t *testing.T) {
	routes := ComputeApiRoutes(nil)
	if len(routes) != 11 {
		t.Fatalf("the table holds %d routes, §14.3's api/compute rows eleven", len(routes))
	}
	keys := map[string]bool{}
	for _, route := range routes {
		key := computeApiRouteKey(route.Method, route.Path)
		if keys[key] {
			t.Errorf("%s twice in the table", key)
		}
		keys[key] = true
		registered := computeApiHandlerOf(route.Method, route.Path) != nil
		unbuilt := slices.Contains(computeApiRouteUnbuilt, key)
		switch {
		case registered && unbuilt:
			t.Errorf("%s is registered and still listed unbuilt", key)
		case !registered && !unbuilt:
			t.Errorf("%s is neither registered nor listed unbuilt", key)
		}
	}
	listed := map[string]bool{}
	for _, key := range computeApiRouteUnbuilt {
		if listed[key] {
			t.Errorf("%s is listed unbuilt twice", key)
		}
		listed[key] = true
		if !keys[key] {
			t.Errorf("%s is listed unbuilt and is no route of the table", key)
		}
	}
}

// A route listed unbuilt answers 501 not_built once the caller's rights and the request's shape pass, so a device
// learns the handler is missing rather than that it was refused.
func TestComputeApiUnbuiltRouteAnswersNotBuilt(t *testing.T) {
	owner := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	answered := 0
	for _, route := range ComputeApiRoutes(nil) {
		if !slices.Contains(computeApiRouteUnbuilt, computeApiRouteKey(route.Method, route.Path)) {
			continue
		}
		body := []byte(nil)
		if route.Method == http.MethodPost {
			body = []byte("{}")
		}
		answer := route.Serve(context.Background(), owner, nil, body)
		if code, _ := testComputeApiCode(t, answer); answer.Status != http.StatusNotImplemented || code != ComputeApiRefusalNotBuilt {
			t.Errorf("%s %s answers %d %s", route.Method, route.Path, answer.Status, code)
		}
		answered += 1
	}
	if answered != len(computeApiRouteUnbuilt) {
		t.Errorf("%d unbuilt routes answered, %d listed", answered, len(computeApiRouteUnbuilt))
	}
}
