package dnsservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The canary's write through the store's one write path, as dnshost.Canaries writes it on Postgres.
type testCanaryWriter struct {
	store *sidecartest.FakeDnsStore
}

func (self *testCanaryWriter) PutCanary(ctx context.Context, root string, value string, ttl uint32) (uint64, error) {
	if _, err := dnsservice.ParseDnsCanaryValue(value); err != nil {
		return 0, err
	}
	return self.store.Write(ctx, &dnsservice.DnsZoneWrite{Root: root, Upserts: []dnsservice.DnsRecordSet{{
		Owner: dnsservice.DnsCanaryOwner(root), Type: dns.TypeTXT, Ttl: ttl, Kind: dnsservice.DnsRecordKindCanary,
		Rdata: []string{dnsservice.DnsCanaryRdata(value)},
	}}})
}

// A block with the canary writer and a verdict store that GET ready reads.
func newTestCanaryApi(t testing.TB) (*testApi, *sidecartest.FakeDnsRestoreStore) {
	t.Helper()
	verdicts := sidecartest.NewFakeDnsRestoreStore(nil)
	// the store exists only once the block does, and nothing writes before this returns
	writer := &testCanaryWriter{}
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) {
		deps.ReadyStore = verdicts
		deps.CanaryVerdicts = verdicts
		deps.Canaries = writer
	})
	writer.store = api.store
	return api, verdicts
}

// A canary value written now.
func testCanaryValue(api *testApi) string {
	return strconv.FormatInt(api.clock.Now().UnixMilli(), 10) + " site"
}

// The site monitor's write takes one serial and one journal row at canary.<root>, TTL ttl.canary, of
// kind canary; another class's bearer is refused, and so is a value no canary may hold.
func TestDnsApiCanaryWritesThroughTheJournal(t *testing.T) {
	api, _ := newTestCanaryApi(t)
	value := testCanaryValue(api)
	recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryPath, dnsservice.DnsCallerMonitor, `{"value":"`+value+`"}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d %s", recorder.Code, recorder.Body.String())
	}
	answer := &dnsservice.DnsCanaryAnswer{}
	if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil || answer.Serial != 2 {
		t.Fatalf("answer %+v %v", answer, err)
	}
	read, err := api.store.Journal(t.Context(), edgeTestRoot, 1, 10)
	if err != nil || len(read.Rows) != 1 {
		t.Fatalf("journal %+v %v", read, err)
	}
	row := read.Rows[0].Upserts[0]
	if row.Owner != "canary."+edgeTestRoot || row.Kind != dnsservice.DnsRecordKindCanary || row.Ttl != 60 || row.Rdata[0] != `"`+value+`"` {
		t.Errorf("the row %+v", row)
	}
	for _, c := range []struct {
		name  string
		class dnsservice.DnsCallerClass
		body  string
		code  int
	}{
		{name: "the outside monitor", class: dnsservice.DnsCallerMonitorOutside, body: `{"value":"` + value + `"}`, code: http.StatusForbidden},
		{name: "certs", class: dnsservice.DnsCallerCerts, body: `{"value":"` + value + `"}`, code: http.StatusForbidden},
		{name: "no milliseconds", class: dnsservice.DnsCallerMonitor, body: `{"value":"site"}`, code: http.StatusBadRequest},
		{name: "a quote", class: dnsservice.DnsCallerMonitor, body: `{"value":"1 \""}`, code: http.StatusBadRequest},
		{name: "65 bytes", class: dnsservice.DnsCallerMonitor, body: `{"value":"1 ` + strings.Repeat("x", 63) + `"}`, code: http.StatusBadRequest},
		{name: "another root", class: dnsservice.DnsCallerMonitor, body: `{"root":"other.example.","value":"` + value + `"}`, code: http.StatusBadRequest},
	} {
		if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryPath, c.class, c.body)); recorder.Code != c.code {
			t.Errorf("%s: status %d", c.name, recorder.Code)
		}
	}
}

// While restoring the write answers 503 with Retry-After and takes no serial; the incident switch,
// writes: false, refuses it, and leaves the report be.
func TestDnsApiCanaryWaitsForARestoreAndTheWriteSwitch(t *testing.T) {
	api, _ := newTestCanaryApi(t)
	if err := api.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryPath, dnsservice.DnsCallerMonitor, `{"value":"`+testCanaryValue(api)+`"}`))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Errorf("restoring: status %d", recorder.Code)
	}
	if err := api.store.SetRestoring(t.Context(), edgeTestRoot, false); err != nil {
		t.Fatal(err)
	}
	if err := api.host.Gates.Set("sidecar:\n  dns: {enabled: true, writes: false}\n"); err != nil {
		t.Fatal(err)
	}
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryPath, dnsservice.DnsCallerMonitor, `{"value":"`+testCanaryValue(api)+`"}`)); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("writes off: status %d", recorder.Code)
	}
	report := `{"source":"site","serial":1,"ok":true}`
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryReportPath, dnsservice.DnsCallerMonitor, report)); recorder.Code != http.StatusNoContent {
		t.Errorf("a report with writes off: status %d", recorder.Code)
	}
}

// Each monitor reports only its own source, and the verdicts reach GET ready: clean, then failing at once
// on a bad site verdict, and a failing outside verdict holds orders too.
func TestDnsApiCanaryReportsReachReady(t *testing.T) {
	api, verdicts := newTestCanaryApi(t)
	api.soa.set("ns1", 1)
	api.soa.set("ns2", 1)
	report := func(class dnsservice.DnsCallerClass, source string, ok bool) int {
		body := `{"source":"` + source + `","serial":1,"ok":` + strconv.FormatBool(ok) + `}`
		return api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryReportPath, class, body)).Code
	}
	if code := report(dnsservice.DnsCallerMonitorOutside, dnsservice.DnsCanarySourceSite, true); code != http.StatusBadRequest {
		t.Errorf("the outside monitor as site: %d", code)
	}
	if code := report(dnsservice.DnsCallerMonitor, dnsservice.DnsCanarySourceOutside, true); code != http.StatusBadRequest {
		t.Errorf("the site monitor as outside: %d", code)
	}
	if code := report(dnsservice.DnsCallerCerts, dnsservice.DnsCanarySourceSite, true); code != http.StatusForbidden {
		t.Errorf("certs: %d", code)
	}
	if answer := api.awaitAnswer(t, api.askReady(t, 1)); answer.Answer != dnsservice.DnsReadyCanaryFailing {
		t.Errorf("with no verdict %+v", answer)
	}
	if code := report(dnsservice.DnsCallerMonitor, dnsservice.DnsCanarySourceSite, true); code != http.StatusNoContent {
		t.Fatalf("the site's verdict: %d", code)
	}
	if answer := api.awaitAnswer(t, api.askReady(t, 1)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("with a clean verdict %+v", answer)
	}
	stored, _ := verdicts.CanaryVerdicts(t.Context(), edgeTestRoot)
	if len(stored) != 1 || !stored[0].ReportTime.Equal(api.clock.Now()) {
		t.Errorf("stored %+v", stored)
	}
	api.clock.Advance(10 * time.Second)
	if code := report(dnsservice.DnsCallerMonitor, dnsservice.DnsCanarySourceSite, false); code != http.StatusNoContent {
		t.Fatalf("a bad verdict: %d", code)
	}
	if answer := api.awaitAnswer(t, api.askReady(t, 1)); answer.Answer != dnsservice.DnsReadyCanaryFailing {
		t.Errorf("just after a bad verdict %+v", answer)
	}
	report(dnsservice.DnsCallerMonitor, dnsservice.DnsCanarySourceSite, true)
	if code := report(dnsservice.DnsCallerMonitorOutside, dnsservice.DnsCanarySourceOutside, false); code != http.StatusNoContent {
		t.Fatalf("the outside's verdict: %d", code)
	}
	if answer := api.awaitAnswer(t, api.askReady(t, 1)); answer.Answer != dnsservice.DnsReadyCanaryFailing {
		t.Errorf("with a failing outside verdict %+v", answer)
	}
}

// A block with no verdict store keeps no verdict: each report answers 503 and ready stays canary_failing.
func TestDnsApiCanaryReportWithNoStoreIsRefused(t *testing.T) {
	api := newTestApi(t, nil)
	recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryReportPath, dnsservice.DnsCallerMonitor, `{"source":"site","serial":1,"ok":true}`))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d", recorder.Code)
	}
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCanaryPath, dnsservice.DnsCallerMonitor, `{"value":"1 site"}`)); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a write with no writer: status %d", recorder.Code)
	}
}
