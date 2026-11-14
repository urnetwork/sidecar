package dnsservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// POST /dns/key-record (DNS-M7-02) and POST /dns/label-reclaim (DNS-M5-16) on the block, on fakes: the receiver gate
// before the model, a scope's host unjudged and so unavailable, the model's refusals answered as they are; a reclaim
// for another network refused before the model.

// The key and reclaim stores the block hands writes to.
type fakeKeyRecordStore struct {
	stateLock sync.Mutex
	keyCalls  []*dnsservice.DnsKeyRecordCall
	reclaims  []*dnsservice.DnsReclaimCall
	err       error
}

func (self *fakeKeyRecordStore) PublishKeyRecord(ctx context.Context, call *dnsservice.DnsKeyRecordCall) (*sidecar.DnsKeyRecordAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keyCalls = append(self.keyCalls, call)
	if self.err != nil {
		return nil, self.err
	}
	return &sidecar.DnsKeyRecordAnswer{Version: 21}, nil
}

func (self *fakeKeyRecordStore) ReclaimLabel(ctx context.Context, call *dnsservice.DnsReclaimCall) (*sidecar.DnsLabelReclaimAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reclaims = append(self.reclaims, call)
	if self.err != nil {
		return nil, self.err
	}
	return &sidecar.DnsLabelReclaimAnswer{Name: call.Request.Name, Kind: "label"}, nil
}

// A receiver gate allowing the listed sidecars on the network's own mx.
type fakeKeyRecordGate struct {
	allowed []sidecar.Id
}

func (self *fakeKeyRecordGate) MayReceive(networkId sidecar.Id, sidecarId sidecar.Id, scope string, now time.Time) dnsservice.DnsGateVerdict {
	if scope != "" {
		return dnsservice.DnsGateUnavailable
	}
	for _, allowed := range self.allowed {
		if allowed == sidecarId {
			return dnsservice.DnsGateAllowed
		}
	}
	return dnsservice.DnsGateDenied
}

// A block with store as both the key and reclaim store and gate as the receiver gate, and a receiver's token.
func newTestKeyRecordApi(t testing.TB, store *fakeKeyRecordStore, allow bool) (*testApi, string, sidecar.Id, sidecar.Id) {
	t.Helper()
	sidecarId := connect.NewId()
	networkId := sidecar.NewId()
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) {
		deps.KeyRecords = store
		deps.Reclaims = store
		gate := &fakeKeyRecordGate{}
		if allow {
			gate.allowed = []sidecar.Id{sidecar.Id(sidecarId)}
		}
		deps.KeyRecordGate = gate
	})
	token := api.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(networkId),
		ClientId:  connect.NewId(),
		SidecarId: &sidecarId,
		Audience:  dnsservice.DnsServiceTokenAudience,
		ExpiresAt: api.clock.Now().Add(time.Hour),
	})
	return api, token, networkId, sidecar.Id(sidecarId)
}

func testKeyRecordBody(t testing.TB, host string) string {
	t.Helper()
	body, err := json.Marshal(&sidecar.DnsKeyRecordRequest{Host: host, Spki: []byte("synthetic spki"), Attestation: []byte("synthetic attestation")})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (self *testApi) withToken(method string, path string, token string, body string) *http.Request {
	request := self.request(method, path, "", body)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

// A receiver with the listen grant reaches the model; one without is refused 403, and a scope's host 503, neither
// reaching it; a host that is no mx is 400.
func TestDnsKeyRecordRouteGatesTheReceiver(t *testing.T) {
	store := &fakeKeyRecordStore{}
	api, token, networkId, sidecarId := newTestKeyRecordApi(t, store, true)
	recorder := api.serve(api.withToken(http.MethodPost, sidecar.DnsKeyRecordPath, token, testKeyRecordBody(t, "mx")))
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"version":21}` {
		t.Fatalf("a receiver: %d %s", recorder.Code, recorder.Body.String())
	}
	if call := store.keyCalls[0]; call.NetworkId != networkId || call.SidecarId != sidecarId || call.Request.Host != "mx" {
		t.Fatalf("the call %+v", call)
	}
	if recorder := api.serve(api.withToken(http.MethodPost, sidecar.DnsKeyRecordPath, token, testKeyRecordBody(t, "mx.team1"))); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a scope's host: %d", recorder.Code)
	}
	if recorder := api.serve(api.withToken(http.MethodPost, sidecar.DnsKeyRecordPath, token, testKeyRecordBody(t, "www"))); recorder.Code != http.StatusBadRequest {
		t.Fatalf("a host that is no mx: %d", recorder.Code)
	}

	denied := &fakeKeyRecordStore{}
	deniedApi, deniedToken, _, _ := newTestKeyRecordApi(t, denied, false)
	if recorder := deniedApi.serve(deniedApi.withToken(http.MethodPost, sidecar.DnsKeyRecordPath, deniedToken, testKeyRecordBody(t, "mx"))); recorder.Code != http.StatusForbidden {
		t.Fatalf("no listen grant: %d", recorder.Code)
	}
	if len(store.keyCalls) != 1 || len(denied.keyCalls) != 0 {
		t.Fatalf("calls %d %d", len(store.keyCalls), len(denied.keyCalls))
	}
}

// The model's refusal of a key that is not the caller's answers 403 as it is.
func TestDnsKeyRecordRouteAnswersTheModelsRefusal(t *testing.T) {
	store := &fakeKeyRecordStore{err: &sidecar.DnsApiError{Status: http.StatusForbidden, Code: sidecar.DnsApiCodeRefused, Message: "the attestation does not prove the key is the caller's"}}
	api, token, _, _ := newTestKeyRecordApi(t, store, true)
	recorder := api.serve(api.withToken(http.MethodPost, sidecar.DnsKeyRecordPath, token, testKeyRecordBody(t, "mx")))
	parsed := sidecar.ParseDnsApiError(recorder.Code, recorder.Body.Bytes(), 0)
	if recorder.Code != http.StatusForbidden || parsed.Code != sidecar.DnsApiCodeRefused {
		t.Fatalf("%d %+v", recorder.Code, parsed)
	}
}

// A reclaim whose tuple names the token's network reaches the model; one naming another network is refused 403
// before it.
func TestDnsLabelReclaimRouteHoldsTheTupleToTheTokensNetwork(t *testing.T) {
	store := &fakeKeyRecordStore{}
	api, token, networkId, sidecarId := newTestKeyRecordApi(t, store, true)
	body := func(networkId sidecar.Id) string {
		data, _ := json.Marshal(&sidecar.DnsLabelReclaimRequest{Name: "lost00001.zone.example", NetworkId: networkId, IncidentId: sidecar.NewId(), Leaf: []byte("leaf"), Signature: []byte("signature")})
		return string(data)
	}
	if recorder := api.serve(api.withToken(http.MethodPost, sidecar.DnsLabelReclaimPath, token, body(networkId))); recorder.Code != http.StatusOK {
		t.Fatalf("its own network: %d %s", recorder.Code, recorder.Body.String())
	}
	if call := store.reclaims[0]; call.NetworkId != networkId || call.SidecarId != sidecarId || call.Root != edgeTestRoot {
		t.Fatalf("the call %+v", call)
	}
	if recorder := api.serve(api.withToken(http.MethodPost, sidecar.DnsLabelReclaimPath, token, body(sidecar.NewId()))); recorder.Code != http.StatusForbidden {
		t.Fatalf("another network: %d", recorder.Code)
	}
	if len(store.reclaims) != 1 {
		t.Fatalf("%d reclaims", len(store.reclaims))
	}
}
