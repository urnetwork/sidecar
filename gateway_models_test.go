//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// GW-M12-04's catalog endpoints (DESIGN-COMPUTE §8.4): /v1/models lists only what the grant may call, /v1/ur/catalog
// gives the entries whole, and /v1/ur/balance the grant's budget and the network's state, never its balance.

// A network that answers its compute balance as a test sets it.
type testGatewayBalanceNetwork struct {
	*testGatewayFrontNetwork
	answer *ComputeBalanceToolAnswer
	err    error
	asked  []*HarnessBudget
}

func (self *testGatewayBalanceNetwork) GatewayBalance(ctx context.Context, agentId Id, caps *HarnessBudget) (*ComputeBalanceToolAnswer, error) {
	self.asked = append(self.asked, caps)
	return self.answer, self.err
}

// Serves a GET of path through handler for the world's caller.
func (self *testGatewayFrontWorld) get(handler func(*GatewayFronts, http.ResponseWriter, *http.Request, *GatewayCaller), path string) *httptest.ResponseRecorder {
	self.t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	recorder := httptest.NewRecorder()
	handler(self.fronts, recorder, request, self.caller)
	return recorder
}

// /v1/models lists, in OpenAI's shape, the canonical names this device may use and the grant's list admits: a model
// outside the grant's globs is absent, as are an unavailable one and a search endpoint.
func TestModelsListOnlyGrantable(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	catalog, err := NewInferCatalog([]*InferCatalogEntry{
		testInferRemoteEntry("chutes", "kimi-k3-tee", ComputeLabelAp, InferEffortHigh),
		testInferRemoteEntry("chutes", "glm-tee", ComputeLabelAp, InferEffortLow, InferEffortHigh),
		testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortOff, InferEffortHigh),
		testInferSearchEntry("parallel", "search"),
	}, DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	world.router.catalog = catalog.Refuse(func(entry *InferCatalogEntry) string {
		if entry.Model == "glm-tee" {
			return "the network's floor"
		}
		return ""
	}, "")
	world.caller.Grant.Models = []string{"chutes-*"}
	answer := world.get((*GatewayFronts).serveModels, "/v1/models")
	decoded := &struct {
		Object string `json:"object"`
		Data   []struct {
			Id      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(answer.Body.Bytes(), decoded); err != nil || answer.Code != http.StatusOK {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	ids := []string{}
	for _, model := range decoded.Data {
		ids = append(ids, model.Id)
		if model.Object != "model" || model.OwnedBy != "chutes" {
			t.Errorf("an entry %+v", model)
		}
	}
	if decoded.Object != "list" || !slices.Equal(ids, []string{"chutes-kimi-k3-tee-high"}) {
		t.Errorf("listed %v", ids)
	}
	world.caller.Grant.Models = nil
	everything := world.get((*GatewayFronts).serveModels, "/v1/models")
	if !strings.Contains(everything.Body.String(), "engy-glm-5.2-off") || strings.Contains(everything.Body.String(), "parallel") ||
		strings.Contains(everything.Body.String(), "glm-tee") {
		t.Errorf("a grant with no list: %s", everything.Body.String())
	}
}

// /v1/ur/catalog gives each entry whole, every field §6.3 gives it, with its names, alias, disclosure, the names the
// grant admits, and its attestation; and why no local or remote entry is offered.
func TestCatalogEntriesWhole(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.caller.Grant.Models = []string{"engy-*-off"}
	answer := world.get((*GatewayFronts).serveCatalog, "/v1/ur/catalog")
	decoded := &struct {
		Object  string           `json:"object"`
		Entries []map[string]any `json:"entries"`
	}{}
	if err := json.Unmarshal(answer.Body.Bytes(), decoded); err != nil || answer.Code != http.StatusOK || decoded.Object != "ur.catalog" {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	if len(decoded.Entries) != len(world.router.catalog.Entries()) {
		t.Fatalf("%d entries of %d", len(decoded.Entries), len(world.router.catalog.Entries()))
	}
	for i, entry := range world.router.catalog.Entries() {
		whole, _ := json.Marshal(entry)
		fields := map[string]any{}
		json.Unmarshal(whole, &fields)
		got := decoded.Entries[i]
		for field, value := range fields {
			gotField, _ := json.Marshal(got[field])
			wantField, _ := json.Marshal(value)
			if string(gotField) != string(wantField) {
				t.Errorf("entry %d's %s: %s, want %s", i, field, gotField, wantField)
			}
		}
		names, _ := json.Marshal(entry.Names())
		gotNames, _ := json.Marshal(got["names"])
		if string(names) != string(gotNames) || got["disclosure_id"] != entry.DisclosureId() {
			t.Errorf("entry %d's names or disclosure: %v", i, got)
		}
	}
	engy := decoded.Entries[1]
	granted, _ := json.Marshal(engy["granted"])
	if string(granted) != `["engy-glm-5.2-off"]` || engy["attestation"] != gatewayAttestationNone || decoded.Entries[0]["attestation"] != gatewayAttestationPerCall {
		t.Errorf("the gateway's fields: %v / %v", engy, decoded.Entries[0])
	}
}

// /v1/ur/balance answers the grant's budget, its caps from the grant, and the network's state and whether it can pay,
// never the network's balance; a network that does not read is a 503.
func TestBalanceNeverNetworkBalance(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	day, month, left := int64(5_000_000_000), int64(50_000_000_000), int64(1_250_000_000)
	network := &testGatewayBalanceNetwork{
		testGatewayFrontNetwork: world.front,
		answer: &ComputeBalanceToolAnswer{
			State:     ComputeAccountStateLow,
			CanPay:    true,
			Budget:    &ComputeBudgetLeft{Day: &ComputeBudgetPeriodLeft{CapNanoUsd: &day, LeftNanoUsd: &left}, Month: &ComputeBudgetPeriodLeft{CapNanoUsd: &month}},
			LeftKnown: true,
		},
	}
	world.caller.Network = network
	world.caller.Grant.DayNanoUsd = &day
	answer := world.get((*GatewayFronts).serveBalance, "/v1/ur/balance")
	if answer.Code != http.StatusOK {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	decoded := &GatewayBalanceAnswer{}
	if err := json.Unmarshal(answer.Body.Bytes(), decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.State != ComputeAccountStateLow || !decoded.CanPay || decoded.GrantId != world.grant.GrantId || decoded.Harness != "codex" ||
		decoded.Budget == nil || decoded.Budget.Day == nil || *decoded.Budget.Day.LeftNanoUsd != left {
		t.Errorf("the answer: %s", answer.Body.String())
	}
	for _, member := range []string{"balance", "balance_nano_usd", "available_nano_usd", "credit"} {
		if strings.Contains(answer.Body.String(), `"`+member) {
			t.Errorf("the answer names the network's %s: %s", member, answer.Body.String())
		}
	}
	if len(network.asked) != 1 || network.asked[0].DayNanoUsd != uint64(day) || network.asked[0].MonthNanoUsd != 0 {
		t.Errorf("the caps asked: %+v", network.asked)
	}
	network.err = errors.New("the broker does not answer")
	if failed := world.get((*GatewayFronts).serveBalance, "/v1/ur/balance"); failed.Code != http.StatusServiceUnavailable {
		t.Errorf("a state that does not read: %d", failed.Code)
	}
	world.caller.Network = world.front
	if none := world.get((*GatewayFronts).serveBalance, "/v1/ur/balance"); none.Code != http.StatusServiceUnavailable {
		t.Errorf("a network with no balance: %d", none.Code)
	}
}

// The routes answer only with a grant's token, through the listener.
func TestCatalogRoutesNeedTheToken(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	for _, path := range []string{"/v1/models", "/v1/ur/catalog", "/v1/ur/balance"} {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		recorder := httptest.NewRecorder()
		world.server.mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d", path, recorder.Code)
		}
	}
}
