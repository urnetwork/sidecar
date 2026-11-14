package dnsservice_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// The record store the block hands writes to: what it was called with, and what it answers.
type fakeRecordStore struct {
	stateLock sync.Mutex
	calls     []*dnsservice.DnsRecordsCall
	answer    []byte
	err       error
	zone      *sidecar.DnsZone
}

func (self *fakeRecordStore) WriteRecords(ctx context.Context, call *dnsservice.DnsRecordsCall) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
	if self.err != nil {
		return nil, self.err
	}
	return self.answer, nil
}

func (self *fakeRecordStore) Zone(ctx context.Context, root string, networkId sidecar.Id) (*sidecar.DnsZone, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.zone == nil {
		return nil, &sidecar.DnsApiError{Status: http.StatusServiceUnavailable, Code: sidecar.DnsApiCodeUnavailable}
	}
	zone := *self.zone
	zone.RecordSets = slices.Clone(self.zone.RecordSets)
	return &zone, nil
}

func (self *fakeRecordStore) callCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.calls)
}

// A gate that allows admin on adminHosts and view on viewHosts, or answers unavailable to all.
type fakeRecordGate struct {
	adminHosts  []string
	viewHosts   []string
	unavailable bool
}

func (self *fakeRecordGate) MayAdmin(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) dnsservice.DnsGateVerdict {
	switch {
	case self.unavailable:
		return dnsservice.DnsGateUnavailable
	case slices.Contains(self.adminHosts, host):
		return dnsservice.DnsGateAllowed
	}
	return dnsservice.DnsGateDenied
}

func (self *fakeRecordGate) MayView(networkId sidecar.Id, sidecarId sidecar.Id, host string, now time.Time) dnsservice.DnsGateVerdict {
	switch {
	case self.unavailable:
		return dnsservice.DnsGateUnavailable
	case slices.Contains(self.viewHosts, host), slices.Contains(self.adminHosts, host):
		return dnsservice.DnsGateAllowed
	}
	return dnsservice.DnsGateDenied
}

// A block with store and gate, and a sidecar's token of aud dns.
type testRecordsApi struct {
	*testApi
	store     *fakeRecordStore
	networkId sidecar.Id
	token     string
}

func newTestRecordsApi(t testing.TB, store *fakeRecordStore, gate dnsservice.DnsRecordGate) *testRecordsApi {
	t.Helper()
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) {
		if store != nil {
			deps.Records = store
		}
		if gate != nil {
			deps.RecordGate = gate
		}
	})
	networkId := sidecar.NewId()
	sidecarId := connect.NewId()
	token := api.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(networkId),
		ClientId:  connect.NewId(),
		SidecarId: &sidecarId,
		Audience:  dnsservice.DnsServiceTokenAudience,
		ExpiresAt: api.clock.Now().Add(time.Hour),
	})
	return &testRecordsApi{testApi: api, store: store, networkId: networkId, token: token}
}

// A request carrying token as its bearer, empty for none.
func (self *testRecordsApi) recordsRequest(method string, path string, token string, body string) *http.Request {
	request := self.request(method, path, "", body)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

// A write of a TXT at each owner.
func testRecordsBody(t testing.TB, owners ...string) string {
	t.Helper()
	request := &sidecar.DnsRecordsRequest{}
	for _, owner := range owners {
		request.Upserts = append(request.Upserts, sidecar.DnsRecordUpsert{Name: owner, Type: "TXT", Values: []string{`"synthetic"`}})
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A token the host refuses, or none, is 401; a token that names no sidecar is 403; neither reaches the store.
func TestDnsRecordsRouteRefusesACallerThatIsNoSidecar(t *testing.T) {
	store := &fakeRecordStore{answer: []byte(`{"version":7}`)}
	api := newTestRecordsApi(t, store, &fakeRecordGate{adminHosts: []string{"www"}})
	body := testRecordsBody(t, "www.label0001."+edgeTestRoot)
	clientToken := api.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(api.networkId),
		ClientId:  connect.NewId(),
		Audience:  dnsservice.DnsServiceTokenAudience,
		ExpiresAt: api.clock.Now().Add(time.Hour),
	})
	otherAudience := api.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(api.networkId),
		ClientId:  connect.NewId(),
		Audience:  "certs",
		ExpiresAt: api.clock.Now().Add(time.Hour),
	})
	cases := []struct {
		token  string
		status int
	}{
		{token: "", status: http.StatusUnauthorized},
		{token: "fake-service-token-unknown", status: http.StatusUnauthorized},
		{token: otherAudience, status: http.StatusUnauthorized},
		{token: clientToken, status: http.StatusForbidden},
	}
	for _, c := range cases {
		for _, request := range []*http.Request{
			api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, c.token, body),
			api.recordsRequest(http.MethodGet, sidecar.DnsZonePath, c.token, ""),
		} {
			if recorder := api.serve(request); recorder.Code != c.status {
				t.Errorf("%s %q: %d, want %d", request.Method, c.token, recorder.Code, c.status)
			}
		}
	}
	if count := store.callCount(); count != 0 {
		t.Fatalf("the store was called %d times", count)
	}
	// an internal bearer is no service token
	request := api.request(http.MethodPost, sidecar.DnsRecordsPath, dnsservice.DnsCallerCerts, body)
	if recorder := api.serve(request); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an internal bearer: %d", recorder.Code)
	}
}

// Under a standing grant every owner's host needs admin: a write naming a host the caller holds no grant on is
// refused whole, and one naming only granted hosts reaches the store with no effect key.
func TestDnsRecordsRouteNeedsAdminOnEveryHost(t *testing.T) {
	store := &fakeRecordStore{answer: []byte(`{"version":7}`)}
	api := newTestRecordsApi(t, store, &fakeRecordGate{adminHosts: []string{"www", "@"}})
	apex := "label0001." + edgeTestRoot
	refused := api.serve(api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, testRecordsBody(t, "www."+apex, "api."+apex)))
	if refused.Code != http.StatusForbidden || !strings.Contains(refused.Body.String(), sidecar.DnsApiCodeRefused) {
		t.Fatalf("a grant on another host: %d %s", refused.Code, refused.Body.String())
	}
	if count := store.callCount(); count != 0 {
		t.Fatalf("the store was called %d times", count)
	}
	written := api.serve(api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, testRecordsBody(t, "www."+apex, "_x.www."+apex, apex, "_y."+apex)))
	if written.Code != http.StatusOK || written.Body.String() != `{"version":7}` {
		t.Fatalf("a write on granted hosts: %d %s", written.Code, written.Body.String())
	}
	call := store.calls[0]
	if call.NetworkId != api.networkId || call.EffectKey != nil || call.Root != edgeTestRoot || len(call.Request.Upserts) != 4 {
		t.Fatalf("the call: %+v", call)
	}
}

// With no gate, or one that has not loaded the network, a write under a grant answers 503 and writes nothing.
func TestDnsRecordsRouteAnswersUnavailableWithNoGateState(t *testing.T) {
	for _, gate := range []dnsservice.DnsRecordGate{nil, &fakeRecordGate{unavailable: true}} {
		store := &fakeRecordStore{answer: []byte(`{"version":7}`)}
		api := newTestRecordsApi(t, store, gate)
		recorder := api.serve(api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, testRecordsBody(t, "www.label0001."+edgeTestRoot)))
		if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
			t.Errorf("gate %T: %d", gate, recorder.Code)
		}
		if count := store.callCount(); count != 0 {
			t.Errorf("gate %T: the store was called %d times", gate, count)
		}
	}
}

// Under a decision the block checks no grant: the decision and its Idempotency-Key go to the model, whose gate is
// §16.6's. A decision with no key, and a key with no decision, are refused.
func TestDnsRecordsRouteHandsADecisionToTheModel(t *testing.T) {
	store := &fakeRecordStore{answer: []byte(`{"version":9}`)}
	api := newTestRecordsApi(t, store, &fakeRecordGate{})
	request := &sidecar.DnsRecordsRequest{
		Upserts:  []sidecar.DnsRecordUpsert{{Name: "www.label0001." + edgeTestRoot, Type: "A", Values: []string{"192.0.2.10"}}},
		Approval: &sidecar.DnsRecordsApproval{Decisions: [][]byte{[]byte("decision")}, Action: []byte("action")},
	}
	body, _ := json.Marshal(request)
	effectKey := []byte("synthetic effect key of 32 bytes")
	keyText := base64.RawURLEncoding.EncodeToString(effectKey)

	withKey := api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, string(body))
	withKey.Header.Set(sidecar.DnsIdempotencyKeyHeader, keyText)
	if recorder := api.serve(withKey); recorder.Code != http.StatusOK || recorder.Body.String() != `{"version":9}` {
		t.Fatalf("a decision: %d %s", recorder.Code, recorder.Body.String())
	}
	if call := store.calls[0]; string(call.EffectKey) != string(effectKey) || call.Request.Approval == nil {
		t.Fatalf("the call: %+v", call)
	}
	noKey := api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, string(body))
	if recorder := api.serve(noKey); recorder.Code != http.StatusBadRequest {
		t.Fatalf("a decision with no key: %d", recorder.Code)
	}
	keyOnly := api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, testRecordsBody(t, "www.label0001."+edgeTestRoot))
	keyOnly.Header.Set(sidecar.DnsIdempotencyKeyHeader, keyText)
	if recorder := api.serve(keyOnly); recorder.Code != http.StatusBadRequest {
		t.Fatalf("a key with no decision: %d", recorder.Code)
	}
	if count := store.callCount(); count != 1 {
		t.Fatalf("the store was called %d times", count)
	}
}

// The model's refusals answer with their status and body: a conflict with its code, a limit with the whole
// QuotaRefusal and its Retry-After, which ParseDnsApiError reads back as they were.
func TestDnsRecordsRouteAnswersTheModelsRefusals(t *testing.T) {
	cases := []struct {
		err     *sidecar.DnsApiError
		status  int
		code    string
		refusal *sidecar.QuotaRefusal
	}{
		{err: &sidecar.DnsApiError{Status: http.StatusConflict, Code: sidecar.DnsApiCodeVersionConflict, Message: "moved"}, status: http.StatusConflict, code: sidecar.DnsApiCodeVersionConflict},
		{err: &sidecar.DnsApiError{Status: http.StatusConflict, Code: sidecar.DnsApiCodeSpent}, status: http.StatusConflict, code: sidecar.DnsApiCodeSpent},
		{
			err:     sidecar.NewDnsQuotaError(&sidecar.QuotaRefusal{LimitKey: "dns_entries", Limit: 5, Used: 5, Upgrade: true}),
			status:  http.StatusPaymentRequired,
			code:    sidecar.DnsApiCodeQuota,
			refusal: &sidecar.QuotaRefusal{LimitKey: "dns_entries", Limit: 5, Used: 5, Upgrade: true},
		},
		{
			err:     sidecar.NewDnsQuotaError(&sidecar.QuotaRefusal{LimitKey: "dns_changes_per_hour", Limit: 60, Used: 60, RetryAfterMs: 90 * 1000}),
			status:  http.StatusTooManyRequests,
			code:    sidecar.DnsApiCodeQuota,
			refusal: &sidecar.QuotaRefusal{LimitKey: "dns_changes_per_hour", Limit: 60, Used: 60, RetryAfterMs: 90 * 1000},
		},
	}
	for _, c := range cases {
		store := &fakeRecordStore{err: c.err}
		api := newTestRecordsApi(t, store, &fakeRecordGate{adminHosts: []string{"www"}})
		recorder := api.serve(api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, testRecordsBody(t, "www.label0001."+edgeTestRoot)))
		if recorder.Code != c.status {
			t.Errorf("%s: %d, want %d", c.code, recorder.Code, c.status)
			continue
		}
		retryAfter := time.Duration(0)
		if text := recorder.Header().Get("Retry-After"); text == "90" {
			retryAfter = 90 * time.Second
		}
		parsed := sidecar.ParseDnsApiError(recorder.Code, recorder.Body.Bytes(), retryAfter)
		if parsed.Code != c.code {
			t.Errorf("%s: parsed %+v", c.code, parsed)
		}
		if c.refusal != nil && (parsed.Refusal == nil || *parsed.Refusal != *c.refusal) {
			t.Errorf("%s: the refusal %+v, want %+v whole", c.code, parsed.Refusal, c.refusal)
		}
		if c.refusal != nil && c.refusal.RetryAfterMs != 0 && retryAfter != 90*time.Second {
			t.Errorf("%s: Retry-After %q", c.code, recorder.Header().Get("Retry-After"))
		}
	}
}

// GET /dns/zone shows the label, alias and version, and only the RRsets on whose host the caller holds publish or
// admin; with no gate it shows none.
func TestDnsZoneRouteShowsOnlyTheCallersHosts(t *testing.T) {
	apex := "label0001." + edgeTestRoot
	zone := &sidecar.DnsZone{
		Root:    edgeTestRoot,
		Label:   "label0001",
		Alias:   "synthetic-alias",
		Version: 41,
		RecordSets: []sidecar.DnsZoneRecordSet{
			{Name: apex, Type: "TXT", Ttl: 300, Kind: "system", Values: []string{`"v=spf1 -all"`}},
			{Name: "www." + apex, Type: "A", Ttl: 300, Kind: "user", Values: []string{"192.0.2.10"}},
			{Name: "_x.www." + apex, Type: "TXT", Ttl: 300, Kind: "user", Values: []string{`"x"`}},
			{Name: "api." + apex, Type: "A", Ttl: 300, Kind: "user", Values: []string{"192.0.2.11"}},
		},
	}
	shown := func(gate dnsservice.DnsRecordGate) *sidecar.DnsZone {
		api := newTestRecordsApi(t, &fakeRecordStore{zone: zone}, gate)
		recorder := api.serve(api.recordsRequest(http.MethodGet, sidecar.DnsZonePath, api.token, ""))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
		}
		answer := &sidecar.DnsZone{}
		if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil {
			t.Fatal(err)
		}
		return answer
	}
	viewed := shown(&fakeRecordGate{viewHosts: []string{"www"}})
	if viewed.Label != "label0001" || viewed.Alias != "synthetic-alias" || viewed.Version != 41 || len(viewed.RecordSets) != 2 ||
		viewed.RecordSets[0].Name != "www."+apex || viewed.RecordSets[1].Name != "_x.www."+apex {
		t.Fatalf("a view of www: %+v", viewed)
	}
	if none := shown(nil); none.Label != "label0001" || len(none.RecordSets) != 0 {
		t.Fatalf("with no gate: %+v", none)
	}
}

// §19.11's dns gate: writes: false refuses POST and leaves GET, and a disabled gate refuses both.
func TestDnsRecordsRoutesFollowTheDnsGate(t *testing.T) {
	store := &fakeRecordStore{answer: []byte(`{"version":7}`), zone: &sidecar.DnsZone{Root: edgeTestRoot, Label: "label0001"}}
	api := newTestRecordsApi(t, store, &fakeRecordGate{adminHosts: []string{"www"}})
	body := testRecordsBody(t, "www.label0001."+edgeTestRoot)
	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: true, writes: false}\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := api.serve(api.recordsRequest(http.MethodPost, sidecar.DnsRecordsPath, api.token, body)); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a write with writes off: %d", recorder.Code)
	}
	if recorder := api.serve(api.recordsRequest(http.MethodGet, sidecar.DnsZonePath, api.token, "")); recorder.Code != http.StatusOK {
		t.Fatalf("a read with writes off: %d", recorder.Code)
	}
	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: false}\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := api.serve(api.recordsRequest(http.MethodGet, sidecar.DnsZonePath, api.token, "")); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a read with the gate off: %d", recorder.Code)
	}
	if count := store.callCount(); count != 0 {
		t.Fatalf("the store was called %d times", count)
	}
}

// The host §8.4's dns:<host> names for each owner form.
func TestDnsOwnerHost(t *testing.T) {
	root := edgeTestRoot
	apex := "label0001." + root
	cases := []struct {
		owner string
		host  string
		ok    bool
	}{
		{owner: apex, host: "@", ok: true},
		{owner: "_x." + apex, host: "@", ok: true},
		{owner: "www." + apex, host: "www", ok: true},
		{owner: "*.www." + apex, host: "www", ok: true},
		{owner: "_x.www." + apex, host: "www", ok: true},
		{owner: "_sip._tcp.www." + apex, host: "www", ok: true},
		{owner: root, ok: false},
		{owner: "www.other.example.", ok: false},
	}
	for _, c := range cases {
		host, ok := dnsservice.DnsOwnerHost(root, c.owner)
		if host != c.host || ok != c.ok {
			t.Errorf("%s: %q %t, want %q %t", c.owner, host, ok, c.host, c.ok)
		}
	}
}

// A gate built over no view or state source answers unavailable to everything, never an allow.
func TestDnsAclRecordGateWithNoStateIsUnavailable(t *testing.T) {
	gate := dnsservice.NewDnsAclRecordGate(nil, nil)
	if verdict := gate.MayAdmin(sidecar.NewId(), sidecar.NewId(), "www", time.Now()); verdict != dnsservice.DnsGateUnavailable {
		t.Fatalf("admin: %v", verdict)
	}
	if verdict := gate.MayView(sidecar.NewId(), sidecar.NewId(), "www", time.Now()); verdict != dnsservice.DnsGateUnavailable {
		t.Fatalf("view: %v", verdict)
	}
}
