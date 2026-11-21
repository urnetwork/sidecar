package gkmservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/specroutes"
)

func TestGkmRoutesMatchOpenApi(t *testing.T) {
	fixture := newGkmFixture(t)
	patterns := make([]string, 0, len(gkmRoutes))
	for _, route := range gkmRoutes {
		patterns = append(patterns, route.Pattern)
	}
	specroutes.Check(t, "/gkm/", fixture.engine.Handler().(*http.ServeMux), patterns)
}
