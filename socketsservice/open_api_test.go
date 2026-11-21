package socketsservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/specroutes"
)

func TestSocketsRoutesMatchOpenApi(t *testing.T) {
	service := &SocketsService{}
	patterns := make([]string, 0, len(socketsRoutes))
	for _, route := range socketsRoutes {
		patterns = append(patterns, route.pattern)
	}
	specroutes.Check(t, "/socket/", service.Handler().(*http.ServeMux), patterns)
}
