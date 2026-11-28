//go:build !sidecar_testhooks

package computetest

// The untagged build's half of broker_testhooks_test.go: no seam into the engine is linked, so a broker asked to plant
// a handler or a check refuses with ErrBrokerPlantUnlinked, and its admissions read the Env's tables, which T2 holds
// none of, so they refuse 503 rather than admit.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/computeservice"
)

func TestBrokerPlantNeedsTheTestHooksBuild(t *testing.T) {
	_, err := NewBroker(&BrokerArgs{Handlers: map[string]computeservice.ComputeHandler{
		computeservice.ComputeRouteInfer: func(request *computeservice.ComputeRequest) { request.Reply(nil) },
	}})
	if !errors.Is(err, ErrBrokerPlantUnlinked) {
		t.Fatalf("planted on the untagged build: %v", err)
	}
	_, err = NewBroker(&BrokerArgs{AdmissionChecks: []computeservice.ComputeAdmissionCheck{
		func(request *computeservice.ComputeRequest) *computeservice.ComputeRefusal { return nil },
	}})
	if !errors.Is(err, ErrBrokerPlantUnlinked) {
		t.Fatalf("a check planted on the untagged build: %v", err)
	}
	world := newTestBrokerWorld(t, nil)
	if world.broker.AbuseHolds() != nil || world.broker.CatalogVersions() != nil {
		t.Fatal("the untagged build answers stand-ins its engine never reads")
	}
	response, err := world.laptop.Do(context.Background(), http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "an admission with no table", response, http.StatusServiceUnavailable, computeservice.ComputeRefusalUnavailable)
}
