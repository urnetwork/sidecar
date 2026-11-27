//go:build sidecar_testhooks

package computetest

// CTEST-M12-01's tests that plant into the broker through computeservice's sidecar_testhooks seam: a handler
// registered by route name as an area registers one, served behind the whole guard; an admission route reading the
// abuse hold's and the region's stores, each refusal answered before the handler; and a plant the registry would
// refuse refused.

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/computeservice"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A handler that records each caller it served and the row it names, answering 200 with no body.
type testBrokerHandler struct {
	stateLock sync.Mutex
	callers   []*computeservice.ComputeCaller
	rowId     sidecar.Id
}

func (self *testBrokerHandler) serve(request *computeservice.ComputeRequest) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.callers = append(self.callers, request.Caller)
	}()
	request.NoteRowIds(self.rowId)
	request.Reply(nil)
}

func (self *testBrokerHandler) served() []*computeservice.ComputeCaller {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*computeservice.ComputeCaller{}, self.callers...)
}

// A handler planted by design route name, as an area registers one, runs behind the whole guard: it sees the caller
// the state admitted (network, sidecar, member, role and consent), answers as the engine writes an answer, and its line
// names the route, the status and its row, and nothing a caller sent.
func TestBrokerServesARegisteredRoute(t *testing.T) {
	handler := &testBrokerHandler{rowId: sidecar.NewId()}
	world := newTestBrokerWorld(t, &BrokerArgs{Handlers: map[string]computeservice.ComputeHandler{
		computeservice.ComputeRouteInferDispute: handler.serve,
	}})
	world.broker.AuthState().SetMember(world.network.NetworkId, world.aliceId, bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN)
	response, err := world.laptop.Do(context.Background(), http.MethodPost, "/v1/infer/dispute", []byte("a body the handler never read"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusOK || response.Header.Get("Content-Type") != "application/x-protobuf" {
		t.Fatalf("answered %d %s %q", response.Status, response.Header.Get("Content-Type"), response.Body)
	}
	if response.Header.Get(sidecar.ComputeServiceTimeHeader) == "" {
		t.Error("the answer carries no broker time")
	}
	callers := handler.served()
	if len(callers) != 1 {
		t.Fatalf("%d calls", len(callers))
	}
	caller := callers[0]
	if caller.NetworkId != world.network.NetworkId || caller.SidecarId != world.laptop.SidecarId || caller.MemberId != world.aliceId ||
		caller.Role != bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN || !caller.Consented || caller.Tagged() {
		t.Fatalf("the handler saw %+v", caller)
	}
	if world.broker.UnbuiltRoutes() == nil {
		t.Fatal("no unbuilt routes listed")
	}
	for _, name := range world.broker.UnbuiltRoutes() {
		if name == computeservice.ComputeRouteInferDispute {
			t.Error("the planted route is still listed unbuilt")
		}
	}
	lines := world.broker.ServiceLog().Lines()
	if len(lines) != 1 {
		t.Fatalf("%d lines", len(lines))
	}
	line := lines[0]
	if line.Route != computeservice.ComputeRouteInferDispute || line.Status != http.StatusOK || line.Code != "" || len(line.RowIds) != 1 || line.RowIds[0] != handler.rowId {
		t.Fatalf("the line %+v", line)
	}

	// a tagged sidecar of the network is served as its tags, with no member
	tagged, err := world.network.AddSidecar(&BrokerSidecarArgs{Label: "ci-runner", TagLabels: []string{"ci"}})
	if err != nil {
		t.Fatal(err)
	}
	response, err = tagged.Do(context.Background(), http.MethodPost, "/v1/infer/dispute", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	callers = handler.served()
	if response.Status != http.StatusOK || len(callers) != 2 || !callers[1].Tagged() || callers[1].MemberId != (sidecar.Id{}) {
		t.Fatalf("a tagged sidecar: %d, %+v", response.Status, callers)
	}
}

// An admission route's handler runs only after every registered admission check has read its store and admitted: the
// network's §21.7 standing, its abuse hold, and the request's region. Each refusal answers before the handler, and a
// store that cannot answer refuses 503, never admits (CARCH-M12-01's checks through the broker's stand-ins).
func TestBrokerAdmissionsReadTheirStores(t *testing.T) {
	handler := &testBrokerHandler{rowId: sidecar.NewId()}
	world := newTestBrokerWorld(t, &BrokerArgs{Handlers: map[string]computeservice.ComputeHandler{
		computeservice.ComputeRouteInfer: handler.serve,
	}})
	ctx := context.Background()
	response, err := world.laptop.Do(ctx, http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusOK || len(handler.served()) != 1 {
		t.Fatalf("an admitted call answered %d %q", response.Status, response.Body)
	}
	regions := world.broker.Regions().(*FakeComputeRegions)
	if world.broker.AbuseHolds().ReadCount() != 1 || regions.AskedCount() != 1 {
		t.Fatalf("the admission read %d holds and %d regions", world.broker.AbuseHolds().ReadCount(), regions.AskedCount())
	}

	// an operator's hold on a second network, set before its first admission reads it
	held, err := world.broker.AddNetwork("held", 0)
	if err != nil {
		t.Fatal(err)
	}
	daveId, err := held.AddMember("dave", bridge.MemberRole_MEMBER_ROLE_OWNER)
	if err != nil {
		t.Fatal(err)
	}
	davePhone, err := held.AddSidecar(&BrokerSidecarArgs{Label: "dave-phone", MemberId: daveId, Consented: true})
	if err != nil {
		t.Fatal(err)
	}
	world.broker.AbuseHolds().Set(held.NetworkId, &model.ComputeAbuseHold{
		Reason:      model.ComputeAbuseHoldReasonMining,
		HoldStaffId: sidecar.NewId(),
		HoldTime:    world.broker.Clock().Now(),
	})
	response, err = davePhone.Do(ctx, http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "an operator's hold", response, http.StatusForbidden, computeservice.ComputeRefusalSuspended)

	// §21.7's standing
	world.broker.Abuse().SetStanding(connect.Id(world.network.NetworkId), sidecar.AbuseStandingSuspended)
	response, err = world.laptop.Do(ctx, http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a suspended standing", response, http.StatusForbidden, computeservice.ComputeRefusalSuspended)
	world.broker.Abuse().SetStanding(connect.Id(world.network.NetworkId), sidecar.AbuseStandingStandard)

	// a refused region, and a lookup that cannot answer
	regions.Place(netip.MustParseAddr("127.0.0.1"), &computeservice.ComputeRegion{CountryCode: "kp"})
	response, err = world.laptop.Do(ctx, http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a refused region", response, http.StatusUnavailableForLegalReasons, computeservice.ComputeRefusalRegionRefused)
	regions.Place(netip.MustParseAddr("127.0.0.1"), nil)
	regions.SetFailing(true)
	response, err = world.laptop.Do(ctx, http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a region lookup that cannot answer", response, http.StatusServiceUnavailable, computeservice.ComputeRefusalUnavailable)
	if len(handler.served()) != 1 {
		t.Fatalf("the handler ran %d times", len(handler.served()))
	}
}

// A plant the registry would refuse is refused before any broker serves: a name that is no design route, and a nil
// handler.
func TestBrokerRefusesPlantingAnUnknownRoute(t *testing.T) {
	for _, handlers := range []map[string]computeservice.ComputeHandler{
		{"GET /v1/nothing": func(request *computeservice.ComputeRequest) { request.Reply(nil) }},
		{computeservice.ComputeRouteInfer: nil},
	} {
		broker, err := NewBroker(&BrokerArgs{Handlers: handlers})
		if err == nil {
			broker.Stop()
			t.Fatalf("planted %v", handlers)
		}
		if errors.Is(err, ErrBrokerPlantUnlinked) {
			t.Fatalf("the tagged build refused as untagged: %v", err)
		}
	}
}
