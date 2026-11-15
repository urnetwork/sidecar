package dnsservice_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The custom-host map (api_map.go; DNS-M6-03), FS-122's and FS-35's dns side on a fake lbmap and a fake clock:
// the long-poll; reports and probes; a host pending with one interface stopped, naming it, past 15 and 20 min;
// a refused nginx -t reported; map-stale at 20 min, never the last; current then ready; a changed master or a
// silent lbmap counting as no version; a failing probe of the probe name or of an added host keeping an
// interface not current until it passes; three adds and a remove loading as one version; a removal leaving the
// next version; and the feed naming each interface's state.

func init() {
	apiTestBearers[dnsservice.DnsCallerLbmap] = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("l", 32)))
}

// The two interfaces feedTestInterfaces names.
const (
	mapTestFirst  = "lb-1"
	mapTestSecond = "lb-2"
)

// A block over the fake map store, both lb interfaces in its inventory.
type testMapApi struct {
	*testApi
	maps *sidecartest.FakeDnsCustomHostMapStore
}

func newTestMapApi(t testing.TB) *testMapApi {
	t.Helper()
	maps := sidecartest.NewFakeDnsCustomHostMapStore()
	api := newTestApi(t, func(deps *dnsservice.DnsApiDeps) { deps.CustomHostMaps = maps })
	return &testMapApi{testApi: api, maps: maps}
}

// lbmap's report of version and its digest from name's nginx under master pid, adding added.
func (self *testMapApi) report(t testing.TB, name string, version uint64, digest string, pid int, added ...string) {
	t.Helper()
	body, _ := json.Marshal(&dnsservice.DnsCustomHostMapReport{
		Format:    dnsservice.DnsFormat,
		Interface: name,
		Version:   version,
		Digest:    digest,
		Master:    &dnsservice.DnsMapMaster{Pid: pid, StartTimeMillis: 1},
		Added:     added,
	})
	if recorder := self.serve(self.request(http.MethodPost, dnsservice.DnsCustomHostMapAppliedPath, dnsservice.DnsCallerLbmap, string(body))); recorder.Code != http.StatusNoContent {
		t.Fatalf("report %s %d: %d %s", name, version, recorder.Code, recorder.Body.String())
	}
}

// One edge's round: name's probe name for version passing or not, and each host's result.
func (self *testMapApi) probe(t testing.TB, name string, version uint64, digest string, passed bool, hosts map[string]bool) {
	t.Helper()
	result := dnsservice.DnsRouteProbeResult{Name: name, Version: version, ProbeName: dnsservice.DnsCustomHostMapProbeName(digest), ProbePassed: passed}
	for host, hostPassed := range hosts {
		result.Hosts = append(result.Hosts, dnsservice.DnsRouteProbeHost{Host: host, Passed: hostPassed})
	}
	body, _ := json.Marshal(&dnsservice.DnsRouteProbeReport{Format: dnsservice.DnsFormat, Interfaces: []dnsservice.DnsRouteProbeResult{result}})
	if recorder := self.serve(self.request(http.MethodPost, dnsservice.DnsRouteProbesPath, dnsservice.DnsCallerEdge, string(body))); recorder.Code != http.StatusNoContent {
		t.Fatalf("probes %s: %d %s", name, recorder.Code, recorder.Body.String())
	}
}

// A poll from name's lbmap: loaded and its master pid, with applied set to loaded, answered at once or after a
// hold.
func (self *testMapApi) poll(t testing.TB, name string, loaded uint64, pid int) int {
	t.Helper()
	path := fmt.Sprintf("%s?interface=%s&loaded=%d&master_pid=%d&master_start_ms=1", dnsservice.DnsCustomHostMapPath, name, loaded, pid)
	return self.serve(self.request(http.MethodGet, path, dnsservice.DnsCallerLbmap, "")).Code
}

// The judgment of the store's state now.
func (self *testMapApi) judge(t testing.TB) *dnsservice.DnsMapJudgment {
	t.Helper()
	state, err := self.maps.CustomHostMapState(t.Context(), edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	return self.settings.Map.Judge(state, self.clock.Now())
}

// The store's interface rows follow the inventory once a probe round has run.
func (self *testMapApi) sync(t testing.TB) {
	t.Helper()
	count, _ := self.api.Probes()
	self.clock.Advance(time.Duration(self.settings.Api.StoreProbeSeconds) * time.Second)
	self.awaitProbes(t, count+1)
}

// Both interfaces report version and pass its probe name and each added host.
func (self *testMapApi) loadEverywhere(t testing.TB, version uint64, digest string, added ...string) {
	t.Helper()
	hosts := map[string]bool{}
	for _, host := range added {
		hosts[host] = true
	}
	for _, name := range []string{mapTestFirst, mapTestSecond} {
		self.report(t, name, version, digest, 100, added...)
		self.probe(t, name, version, digest, true, hosts)
	}
}

// GET answers the newest version at once with no applied, holds while applied is the newest until a raise
// answers the new one, and answers 204 when the hold ends with nothing newer; no version is 204 at once.
func TestDnsCustomHostMapLongPoll(t *testing.T) {
	api := newTestMapApi(t)
	path := dnsservice.DnsCustomHostMapPath + "?interface=" + mapTestFirst
	if recorder := api.serve(api.request(http.MethodGet, path, dnsservice.DnsCallerLbmap, "")); recorder.Code != http.StatusNoContent {
		t.Fatalf("no version: %d", recorder.Code)
	}
	digest := api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	recorder := api.serve(api.request(http.MethodGet, path, dnsservice.DnsCallerLbmap, ""))
	answer := &dnsservice.DnsCustomHostMap{}
	if err := json.Unmarshal(recorder.Body.Bytes(), answer); err != nil || recorder.Code != http.StatusOK || answer.Version != 1 || answer.Digest != digest || !slices.Equal(answer.Hosts, []string{"www.corp.example"}) {
		t.Fatalf("at once: %d %+v", recorder.Code, answer)
	}
	done := make(chan int, 1)
	go func() {
		done <- api.serve(api.request(http.MethodGet, path+"&applied=1", dnsservice.DnsCallerLbmap, "")).Code
	}()
	api.awaitParked(t, 1)
	api.maps.Raise(2, []string{"www.corp.example", "shop.corp.example"}, api.clock.Now())
	api.clock.Advance(time.Duration(api.settings.Map.HoldPollSeconds) * time.Second)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("a raise during the hold: %d", code)
	}
	go func() {
		done <- api.serve(api.request(http.MethodGet, path+"&applied=2", dnsservice.DnsCallerLbmap, "")).Code
	}()
	for range api.settings.Map.HoldSeconds {
		api.awaitParked(t, 1)
		api.clock.Advance(time.Second)
	}
	if code := <-done; code != http.StatusNoContent {
		t.Fatalf("the hold's end: %d", code)
	}
}

// Only lbmap's bearer polls and reports, only an edge's posts probes, an interface outside the inventory is
// refused, and a block with no store answers 503.
func TestDnsCustomHostMapRoutesTakeTheirCallers(t *testing.T) {
	api := newTestMapApi(t)
	path := dnsservice.DnsCustomHostMapPath + "?interface=" + mapTestFirst
	for _, class := range []dnsservice.DnsCallerClass{dnsservice.DnsCallerEdge, dnsservice.DnsCallerCerts, ""} {
		if recorder := api.serve(api.request(http.MethodGet, path, class, "")); recorder.Code != http.StatusForbidden {
			t.Errorf("%q polled: %d", class, recorder.Code)
		}
	}
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsRouteProbesPath, dnsservice.DnsCallerLbmap, `{"format":1}`)); recorder.Code != http.StatusForbidden {
		t.Errorf("lbmap posted probes: %d", recorder.Code)
	}
	if recorder := api.serve(api.request(http.MethodGet, dnsservice.DnsCustomHostMapPath+"?interface=lb-9", dnsservice.DnsCallerLbmap, "")); recorder.Code != http.StatusForbidden {
		t.Errorf("an interface outside the inventory: %d", recorder.Code)
	}
	none := newTestApi(t, nil)
	if recorder := none.serve(none.request(http.MethodGet, path, dnsservice.DnsCallerLbmap, "")); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("no store: %d", recorder.Code)
	}
}

// A report naming a version the block holds under another digest, a stage that is none and a host list past
// report_hosts are refused, with nothing recorded.
func TestDnsCustomHostMapRefusesAReportItCannotTake(t *testing.T) {
	api := newTestMapApi(t)
	api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	other := dnsservice.DnsCustomHostMapDigest([]string{"other.corp.example"})
	tooMany := []string{}
	for index := range api.settings.Map.ReportHostMaxCount + 1 {
		tooMany = append(tooMany, fmt.Sprintf("h%d.corp.example", index))
	}
	for _, report := range []*dnsservice.DnsCustomHostMapReport{
		{Format: dnsservice.DnsFormat, Interface: mapTestFirst, Version: 1, Digest: other},
		{Format: dnsservice.DnsFormat, Interface: mapTestFirst, Version: 1, Digest: "not-hex"},
		{Format: dnsservice.DnsFormat, Interface: mapTestFirst, Failure: &dnsservice.DnsMapFailure{Version: 1, Stage: "deploy"}},
		{Format: dnsservice.DnsFormat, Interface: "lb-9"},
		{Format: dnsservice.DnsFormat, Interface: mapTestFirst, Added: tooMany},
		{Format: 9, Interface: mapTestFirst},
	} {
		body, _ := json.Marshal(report)
		if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCustomHostMapAppliedPath, dnsservice.DnsCallerLbmap, string(body))); recorder.Code != http.StatusBadRequest {
			t.Errorf("%+v: %d", report.Failure, recorder.Code)
		}
	}
	if row := api.maps.Interface(mapTestFirst); row != nil && row.ReportedVersion != 0 {
		t.Fatalf("a refused report was recorded: %+v", row)
	}
}

// Current, then ready: a host waits until both interfaces report its version and pass its probe name and its
// own probe, and only then takes a ready time; one interface stopped keeps it pending past 15 and 20 min, named,
// and never turns it ready by time.
func TestDnsCustomHostReadyOnceEveryInterfaceIsCurrent(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	digest := api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	api.report(t, mapTestFirst, 1, digest, 100, "www.corp.example")
	api.probe(t, mapTestFirst, 1, digest, true, map[string]bool{"www.corp.example": true})
	// the second interface's lbmap is stopped: it never reports
	for _, minutes := range []int{15, 20} {
		api.clock.Advance(time.Duration(minutes)*time.Minute - api.clock.Now().Sub(sidecartest.DefaultClockStart()) + time.Duration(api.settings.Api.StoreProbeSeconds)*time.Second)
		// keep the first interface fresh, as its lbmap and the edges are
		api.poll(t, mapTestFirst, 1, 100)
		api.probe(t, mapTestFirst, 1, digest, true, nil)
		if _, ready := api.maps.Ready("www.corp.example"); ready {
			t.Fatalf("ready at %d min with an interface stopped", minutes)
		}
		if pending := api.judge(t).Pending[1]; !slices.Equal(pending, []string{mapTestSecond}) {
			t.Fatalf("at %d min pending %v", minutes, pending)
		}
	}
	api.report(t, mapTestSecond, 1, digest, 200, "www.corp.example")
	api.probe(t, mapTestSecond, 1, digest, true, map[string]bool{"www.corp.example": true})
	if readyTime, ready := api.maps.Ready("www.corp.example"); !ready || !readyTime.Equal(api.clock.Now()) {
		t.Fatalf("not ready once both are current: %v %t", readyTime, ready)
	}
}

// A refused nginx -t is reported: the failure counted by stage, the interface staying on its prior version and
// not current for the new one.
func TestDnsCustomHostMapReportsARefusedTest(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	first := api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	api.loadEverywhere(t, 1, first, "www.corp.example")
	second := api.maps.Raise(2, []string{"www.corp.example", "shop.corp.example"}, api.clock.Now())
	body, _ := json.Marshal(&dnsservice.DnsCustomHostMapReport{
		Format: dnsservice.DnsFormat, Interface: mapTestFirst, Version: 1, Digest: first,
		Master:  &dnsservice.DnsMapMaster{Pid: 100, StartTimeMillis: 1},
		Failure: &dnsservice.DnsMapFailure{Version: 2, Digest: second, Stage: dnsservice.DnsMapStageTest},
	})
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsCustomHostMapAppliedPath, dnsservice.DnsCallerLbmap, string(body))); recorder.Code != http.StatusNoContent {
		t.Fatalf("%d", recorder.Code)
	}
	if failures := api.host.Metrics.Value("urnetwork_dns_custom_host_map_load_failures_total", dnsservice.DnsMapStageTest); failures != 1 {
		t.Errorf("failures %v", failures)
	}
	if row := api.maps.Interface(mapTestFirst); row.ReportedVersion != 1 {
		t.Fatalf("row %+v", row)
	}
	if pending := api.judge(t).Pending[2]; !slices.Contains(pending, mapTestFirst) {
		t.Fatalf("pending %v", pending)
	}
	if _, ready := api.maps.Ready("shop.corp.example"); ready {
		t.Fatal("ready on an interface whose test refused it")
	}
}

// A changed nginx master, a poll naming an older map and a silent lbmap each count as no version.
func TestDnsCustomHostMapNoVersionAfterAMasterChangeOrSilence(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	digest := api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	api.loadEverywhere(t, 1, digest, "www.corp.example")
	if _, ready := api.maps.Ready("www.corp.example"); !ready {
		t.Fatal("not ready")
	}
	api.poll(t, mapTestFirst, 1, 999)
	if row := api.maps.Interface(mapTestFirst); row.ReportedVersion != 0 {
		t.Fatalf("a new master kept the version: %+v", row)
	}
	api.report(t, mapTestFirst, 1, digest, 999, "www.corp.example")
	api.probe(t, mapTestFirst, 1, digest, true, map[string]bool{"www.corp.example": true})
	api.poll(t, mapTestFirst, 0, 999)
	if row := api.maps.Interface(mapTestFirst); row.ReportedVersion != 0 {
		t.Fatalf("a poll running no map kept the version: %+v", row)
	}
	// the second interface's lbmap falls silent past poll_silence_s
	api.report(t, mapTestFirst, 1, digest, 999, "www.corp.example")
	api.probe(t, mapTestFirst, 1, digest, true, map[string]bool{"www.corp.example": true})
	api.clock.Advance(time.Duration(api.settings.Map.PollSilenceSeconds+1) * time.Second)
	api.poll(t, mapTestFirst, 1, 999)
	api.probe(t, mapTestFirst, 1, digest, true, nil)
	if pending := api.judge(t).Pending[1]; !slices.Equal(pending, []string{mapTestSecond}) {
		t.Fatalf("pending %v", pending)
	}
	if _, ready := api.maps.Ready("www.corp.example"); ready {
		t.Fatal("ready with a silent lbmap")
	}
}

// A reported version whose probe name fails stays not current, and an added host whose probe fails keeps the
// interface not current until a probe of it passes.
func TestDnsCustomHostMapFailingProbesKeepAnInterfaceNotCurrent(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	digest := api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	api.report(t, mapTestSecond, 1, digest, 200, "www.corp.example")
	api.probe(t, mapTestSecond, 1, digest, true, map[string]bool{"www.corp.example": true})
	api.report(t, mapTestFirst, 1, digest, 100, "www.corp.example")
	api.probe(t, mapTestFirst, 1, digest, false, map[string]bool{"www.corp.example": true})
	if pending := api.judge(t).Pending[1]; !slices.Equal(pending, []string{mapTestFirst}) {
		t.Fatalf("a failing probe name: pending %v", pending)
	}
	api.probe(t, mapTestFirst, 1, digest, true, map[string]bool{"www.corp.example": false})
	if pending := api.judge(t).Pending[1]; !slices.Equal(pending, []string{mapTestFirst}) {
		t.Fatalf("a failing host: pending %v", pending)
	}
	// a probe for another version, or under another probe name, is not taken
	api.probe(t, mapTestFirst, 2, digest, true, map[string]bool{"www.corp.example": true})
	if pending := api.judge(t).Pending[1]; !slices.Equal(pending, []string{mapTestFirst}) {
		t.Fatalf("another version's probe was taken: %v", pending)
	}
	api.probe(t, mapTestFirst, 1, digest, true, map[string]bool{"www.corp.example": true})
	if _, ready := api.maps.Ready("www.corp.example"); !ready {
		t.Fatal("not ready once the host's probe passes")
	}
}

// At 20 min an interface not current for the newest version that old is map-stale, and the feed names it; when
// every interface would be, the one that reported the newest version stands, so never all.
func TestDnsCustomHostMapStaleAtTwentyMinutesNeverAll(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	first := api.maps.Raise(1, []string{"www.corp.example"}, api.clock.Now())
	api.loadEverywhere(t, 1, first, "www.corp.example")
	second := api.maps.Raise(2, []string{"www.corp.example", "shop.corp.example"}, api.clock.Now())
	api.report(t, mapTestFirst, 2, second, 100, "shop.corp.example")
	api.probe(t, mapTestFirst, 2, second, true, map[string]bool{"shop.corp.example": true})
	api.clock.Advance(time.Duration(api.settings.Map.StaleAfterSeconds-60) * time.Second)
	api.poll(t, mapTestFirst, 2, 100)
	api.poll(t, mapTestSecond, 1, 100)
	api.probe(t, mapTestFirst, 2, second, true, nil)
	api.probe(t, mapTestSecond, 1, first, true, nil)
	if stale := api.judge(t).MapStale; len(stale) != 0 {
		t.Fatalf("stale before 20 min: %v", stale)
	}
	api.clock.Advance(2 * time.Minute)
	api.poll(t, mapTestFirst, 2, 100)
	api.poll(t, mapTestSecond, 1, 100)
	api.probe(t, mapTestFirst, 2, second, true, nil)
	api.probe(t, mapTestSecond, 1, first, true, nil)
	stale := api.judge(t).MapStale
	if !stale[mapTestSecond] || stale[mapTestFirst] {
		t.Fatalf("at 20 min stale %v", stale)
	}
	answer := api.journal(t)
	for _, lbInterface := range answer.Interfaces {
		if lbInterface.MapStale != (lbInterface.Name == mapTestSecond) {
			t.Errorf("the feed: %+v", lbInterface)
		}
	}
	// the first interface's edges stop probing too: both would be stale, and the one on the newest version stands
	api.clock.Advance(time.Duration(api.settings.Map.ProbeFreshSeconds+1) * time.Second)
	api.poll(t, mapTestFirst, 2, 100)
	api.poll(t, mapTestSecond, 1, 100)
	stale = api.judge(t).MapStale
	if !stale[mapTestSecond] || stale[mapTestFirst] {
		t.Fatalf("never all: %v", stale)
	}
}

// The journal's answer at once, from an edge at serial 0.
func (self *testMapApi) journal(t testing.TB) *dnsservice.DnsFeedAnswer {
	t.Helper()
	recorder := self.serve(self.request(http.MethodGet, dnsservice.DnsJournalPath+"?after=0", dnsservice.DnsCallerEdge, ""))
	answer, err := dnsservice.DecodeDnsFeedAnswer(recorder.Body.Bytes())
	if err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("journal %d %v", recorder.Code, err)
	}
	return answer
}

// The feed names each interface's reported version with its probe name and the hosts it added, at most
// probe.route_hosts, and none for an interface that reported nothing.
func TestDnsFeedNamesEachInterfacesMapState(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	hosts := []string{}
	for index := range api.settings.Probe.RouteHostCount + 2 {
		hosts = append(hosts, fmt.Sprintf("h%02d.corp.example", index))
	}
	digest := api.maps.Raise(1, hosts, api.clock.Now())
	api.report(t, mapTestFirst, 1, digest, 100, hosts...)
	answer := api.journal(t)
	for _, lbInterface := range answer.Interfaces {
		switch lbInterface.Name {
		case mapTestFirst:
			if lbInterface.ReportedVersion != 1 || lbInterface.ProbeName != dnsservice.DnsCustomHostMapProbeName(digest) ||
				len(lbInterface.AddedHosts) != api.settings.Probe.RouteHostCount || lbInterface.AddedHosts[0] != hosts[0] {
				t.Errorf("first %+v", lbInterface)
			}
		case mapTestSecond:
			if lbInterface.ReportedVersion != 0 || lbInterface.ProbeName != "" || len(lbInterface.AddedHosts) != 0 {
				t.Errorf("second %+v", lbInterface)
			}
		}
	}
	// the inventory's own slice is not the answer's
	if inventory := feedTestInterfaces(); inventory[0].ReportedVersion != 0 {
		t.Fatal("the answer wrote into the inventory")
	}
}

// Three adds and a remove inside one window load as one version: the interface reports the newest, adding the
// three, and is current for each host's earlier version once it passes their probes; the removed host is in no
// version the interface runs (FS-35's route removed at the next version).
func TestDnsCustomHostMapLoadsSeveralChangesAsOneVersion(t *testing.T) {
	api := newTestMapApi(t)
	api.sync(t)
	base := api.maps.Raise(1, []string{"old.corp.example"}, api.clock.Now())
	api.loadEverywhere(t, 1, base, "old.corp.example")
	api.maps.Raise(2, []string{"old.corp.example", "a.corp.example"}, api.clock.Now())
	api.maps.Raise(3, []string{"old.corp.example", "a.corp.example", "b.corp.example"}, api.clock.Now())
	api.maps.Raise(4, []string{"old.corp.example", "a.corp.example", "b.corp.example", "c.corp.example"}, api.clock.Now())
	newest := api.maps.Raise(5, []string{"a.corp.example", "b.corp.example", "c.corp.example"}, api.clock.Now())
	customHostMap, _ := api.maps.CustomHostMap(t.Context(), edgeTestRoot)
	if customHostMap.Version != 5 || slices.Contains(customHostMap.Hosts, "old.corp.example") {
		t.Fatalf("the newest version %+v", customHostMap)
	}
	api.loadEverywhere(t, 5, newest, "a.corp.example", "b.corp.example", "c.corp.example")
	for _, host := range []string{"a.corp.example", "b.corp.example", "c.corp.example"} {
		if _, ready := api.maps.Ready(host); !ready {
			t.Errorf("%s not ready", host)
		}
	}
	if _, ready := api.maps.Ready("old.corp.example"); ready {
		t.Error("the removed host stays")
	}
}
