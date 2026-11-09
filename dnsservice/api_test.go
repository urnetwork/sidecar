package dnsservice_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Visibly synthetic bearers, 32 bytes each in unpadded base64url, by class.
var apiTestBearers = map[dnsservice.DnsCallerClass]string{
	dnsservice.DnsCallerEdge:           base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("e", 32))),
	dnsservice.DnsCallerCerts:          base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
	dnsservice.DnsCallerMonitor:        base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("m", 32))),
	dnsservice.DnsCallerMonitorOutside: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32))),
}

// internal-verify.yml for apiTestBearers.
func apiTestVerifyFile() string {
	lines := []string{}
	for class, bearer := range apiTestBearers {
		digest := sha256.Sum256([]byte(bearer))
		lines = append(lines, fmt.Sprintf("%s-1: {class: %s, sha256: [%s]}", class, class, hex.EncodeToString(digest[:])))
	}
	return strings.Join(lines, "\n") + "\n"
}

// One block on fakes, its store and the edge-side keys its feed answers name.
type testApi struct {
	api      *dnsservice.DnsApi
	host     *sidecartest.FakeHost
	clock    *sidecartest.FakeClock
	store    *sidecartest.FakeDnsStore
	faults   *sidecartest.FaultQueue
	settings *dnsservice.DnsSettings
	keys     *edgeTestKeys
	soa      *fakeSoaReader
	ready    *fakeReadyStore
}

// A block over a store holding edgeTestRows at serial 1, the dns gate open, a verifier for
// apiTestBearers, and fakes for SOA reads and dns_ns and dns_canary_verdict. deps may change the deps
// before the block starts.
func newTestApi(t testing.TB, change func(deps *dnsservice.DnsApiDeps)) *testApi {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	if err := host.Gates.Set("sidecar:\n  dns: {enabled: true}\n"); err != nil {
		t.Fatal(err)
	}
	faults := sidecartest.NewFaultQueue()
	store := sidecartest.NewFakeDnsStore(clock, faults)
	settings := edgeTestSettings(t)
	self := &testApi{
		host:     host,
		clock:    clock,
		store:    store,
		faults:   faults,
		settings: settings,
		keys:     newEdgeTestKeys(t, edgeTestRoot, sidecartest.DefaultClockStart()),
		soa:      newFakeSoaReader(),
		ready:    &fakeReadyStore{},
	}
	if err := store.EnsureRoot(t.Context(), edgeTestRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write(t.Context(), &dnsservice.DnsZoneWrite{Root: edgeTestRoot, Upserts: edgeTestRows()}); err != nil {
		t.Fatal(err)
	}
	verifier, err := dnsservice.NewDnsInternalVerifier([]byte(apiTestVerifyFile()))
	if err != nil {
		t.Fatal(err)
	}
	deps := &dnsservice.DnsApiDeps{
		Auth:       verifier,
		Interfaces: feedTestInterfaces,
		KeyWindow: func(root string, now time.Time) *dnsservice.DnsKeyWindow {
			return self.keys.window
		},
		ReadyStore: self.ready,
		SoaReader:  self.soa,
	}
	if change != nil {
		change(deps)
	}
	api, err := dnsservice.NewDnsApi(t.Context(), host.ServiceHost(), settings, store, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	self.api = api
	self.awaitProbes(t, 1)
	return self
}

// Waits until count store probes have finished.
func (self *testApi) awaitProbes(t testing.TB, count int) {
	t.Helper()
	for {
		current, changed := self.api.Probes()
		if count <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("probes %d", current)
		}
	}
}

// Waits until at least count holds are parked in their wait.
func (self *testApi) awaitParked(t testing.TB, count int) {
	t.Helper()
	for {
		current, changed := self.api.ParkedForTest()
		if count <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("parked %d, want %d", current, count)
		}
	}
}

// A request to path as class's caller; an empty class sends no bearer.
func (self *testApi) request(method string, path string, class dnsservice.DnsCallerClass, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if class != "" {
		request.Header.Set("Authorization", "Bearer "+apiTestBearers[class])
	}
	return request
}

// Serves request to the end and returns what was written.
func (self *testApi) serve(request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	self.api.Handler().ServeHTTP(recorder, request)
	return recorder
}

// Every internal route takes only its own class's bearer: none, a wrong one and another class's are 403.
func TestDnsApiRefusesAnInternalRouteWithoutItsCredential(t *testing.T) {
	api := newTestApi(t, nil)
	cases := []struct {
		name   string
		path   string
		method string
		header string
	}{
		{name: "no bearer", method: http.MethodGet, path: dnsservice.DnsSnapshotPath},
		{name: "a bearer no caller holds", method: http.MethodGet, path: dnsservice.DnsSnapshotPath, header: "Bearer " + base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		{name: "certs on the feed", method: http.MethodGet, path: dnsservice.DnsSnapshotPath, header: "Bearer " + apiTestBearers[dnsservice.DnsCallerCerts]},
		{name: "an edge on ready", method: http.MethodGet, path: dnsservice.DnsReadyPath + "?serial=1", header: "Bearer " + apiTestBearers[dnsservice.DnsCallerEdge]},
		{name: "not a bearer", method: http.MethodGet, path: dnsservice.DnsSnapshotPath, header: "Basic " + apiTestBearers[dnsservice.DnsCallerEdge]},
	}
	for _, c := range cases {
		request := httptest.NewRequest(c.method, c.path, nil)
		if c.header != "" {
			request.Header.Set("Authorization", c.header)
		}
		if recorder := api.serve(request); recorder.Code != http.StatusForbidden {
			t.Errorf("%s: %d", c.name, recorder.Code)
		}
	}
	if recorder := api.serve(api.request(http.MethodGet, dnsservice.DnsSnapshotPath, dnsservice.DnsCallerEdge, "")); recorder.Code != http.StatusOK {
		t.Errorf("the edge's own bearer: %d", recorder.Code)
	}
	if refused := api.host.Metrics.Value("urnetwork_dns_internal_refused_total", "credential"); refused != float64(len(cases)) {
		t.Errorf("refused %v", refused)
	}
}

// A host with no verifier configured refuses every internal route with 403, so nothing is exposed
// while the vault entries wait (plan-DNS-internal-route-credential).
func TestDnsApiWithNoVerifierRefusesEveryInternalRoute(t *testing.T) {
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.Auth = nil })
	for _, path := range []string{dnsservice.DnsJournalPath + "?after=0", dnsservice.DnsSnapshotPath, dnsservice.DnsReadyPath + "?serial=1"} {
		if recorder := api.serve(api.request(http.MethodGet, path, dnsservice.DnsCallerEdge, "")); recorder.Code != http.StatusForbidden {
			t.Errorf("%s: %d", path, recorder.Code)
		}
	}
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsReloadDiffPath, dnsservice.DnsCallerEdge, "{}")); recorder.Code != http.StatusForbidden {
		t.Errorf("reload-diff: %d", recorder.Code)
	}
}

// §19.11: with the dns gate disabled every route answers 503 with Retry-After, and the block stays
// ready, so a rollout does not revert it.
func TestDnsApiGateClosedAnswers503AndStaysReady(t *testing.T) {
	api := newTestApi(t, nil)
	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: false}\n"); err != nil {
		t.Fatal(err)
	}
	for _, request := range []*http.Request{
		api.request(http.MethodGet, dnsservice.DnsJournalPath+"?after=0", dnsservice.DnsCallerEdge, ""),
		api.request(http.MethodGet, dnsservice.DnsSnapshotPath, dnsservice.DnsCallerEdge, ""),
		api.request(http.MethodGet, dnsservice.DnsReadyPath+"?serial=1", dnsservice.DnsCallerCerts, ""),
	} {
		recorder := api.serve(request)
		if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "60" {
			t.Errorf("%s: %d %q", request.URL.Path, recorder.Code, recorder.Header().Get("Retry-After"))
		}
	}
	if !api.api.Ready() {
		t.Error("a closed gate made the block not ready")
	}
	// writes: false, the incident switch, leaves the feed's reads and the diff alone
	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: true, writes: false}\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := api.serve(api.request(http.MethodGet, dnsservice.DnsSnapshotPath, dnsservice.DnsCallerEdge, "")); recorder.Code != http.StatusOK {
		t.Errorf("a read with writes off: %d", recorder.Code)
	}
}

// Ready only once a probe has read every root's dns_root row, which the block adds where none is.
func TestDnsApiIsReadyOnceItReadsItsStore(t *testing.T) {
	api := newTestApi(t, nil)
	if !api.api.Ready() {
		t.Fatal("not ready on a store that answers")
	}
	if _, err := api.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "dns.RootState", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	count, _ := api.api.Probes()
	api.clock.Advance(time.Duration(api.settings.Api.StoreProbeSeconds) * time.Second)
	api.awaitProbes(t, count+1)
	if api.api.Ready() {
		t.Error("ready on a store that does not answer")
	}
	api.faults.Clear()
	count, _ = api.api.Probes()
	api.clock.Advance(time.Duration(api.settings.Api.StoreProbeSeconds) * time.Second)
	api.awaitProbes(t, count+1)
	if !api.api.Ready() {
		t.Error("not ready once the store answers again")
	}
}

func TestDnsInternalVerifierRefusals(t *testing.T) {
	digest := hex.EncodeToString(make([]byte, 32))
	for _, text := range []string{
		"",
		"dnsedge-1: {class: nobody, sha256: [" + digest + "]}\n",
		"dnsedge-1: {class: dnsedge, sha256: []}\n",
		"dnsedge-1: {class: dnsedge, sha256: [abcd]}\n",
		"dnsedge-1: {class: dnsedge, sha256: [" + digest + "], extra: 1}\n",
		"not: [yaml\n",
	} {
		if _, err := dnsservice.NewDnsInternalVerifier([]byte(text)); !errors.Is(err, dnsservice.ErrDnsCredentialRefused) {
			t.Errorf("%q: %v", text, err)
		}
	}
	// a rotation: the previous bearer still passes beside the current
	current, previous := apiTestBearers[dnsservice.DnsCallerEdge], base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	currentDigest, previousDigest := sha256.Sum256([]byte(current)), sha256.Sum256([]byte(previous))
	verifier, err := dnsservice.NewDnsInternalVerifier([]byte(fmt.Sprintf("dnsedge-2: {class: dnsedge, sha256: [%s, %s]}\n",
		hex.EncodeToString(currentDigest[:]), hex.EncodeToString(previousDigest[:]))))
	if err != nil {
		t.Fatal(err)
	}
	for _, bearer := range []string{current, previous} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", "Bearer "+bearer)
		if class, ok := verifier.Authenticate(request); !ok || class != dnsservice.DnsCallerEdge {
			t.Errorf("%s: %s %v", bearer, class, ok)
		}
	}
}

func TestLoadDnsInternalCredential(t *testing.T) {
	current := apiTestBearers[dnsservice.DnsCallerEdge]
	bearer, err := dnsservice.LoadDnsInternalCredential([]byte("current: " + current + "\nprevious: " + apiTestBearers[dnsservice.DnsCallerCerts] + "\n"))
	if err != nil || bearer != current {
		t.Errorf("%q %v", bearer, err)
	}
	for _, text := range []string{
		"previous: " + current + "\n",
		"current: " + current[:20] + "\n",
		"current: " + current + "=\n",
		"current: " + current + "\nprevious: short\n",
		"current: " + current + "\nnext: " + current + "\n",
	} {
		bearer, err := dnsservice.LoadDnsInternalCredential([]byte(text))
		if !errors.Is(err, dnsservice.ErrDnsCredentialRefused) {
			t.Errorf("%q: %q %v", text, bearer, err)
		}
		if err != nil && strings.Contains(err.Error(), current) {
			t.Errorf("%q: the refusal holds the bearer", text)
		}
	}
}
