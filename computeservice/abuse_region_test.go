package computeservice

// Compute refused by region at the broker (CARCH-M12-01; DESIGN-COMPUTE §17.2, I-13): an address the lookup places in
// a refused country or subdivision is refused 451 region_refused at every admission, any other admits; an admission
// that cannot check its region refuses; and the address reaches no log line, metric, Redis key or value.

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Synthetic addresses from the documentation ranges, placed as a test wants them.
var (
	testRegionRefusedCountryAddr     = netip.MustParseAddr("203.0.113.77")
	testRegionRefusedSubdivisionAddr = netip.MustParseAddr("2001:db8:5:6::77")
	testRegionAdmittedAddr           = netip.MustParseAddr("198.51.100.9")
)

// The fixture's lookup with the three addresses placed: one in a refused country, one in a refused subdivision of a
// country that is not refused, one in neither.
func placeTestRegions(fixture *computeFixture) {
	fixture.regions.place(testRegionRefusedCountryAddr, &ComputeRegion{CountryCode: "ir", SubdivisionGeonameId: 111})
	fixture.regions.place(testRegionRefusedSubdivisionAddr, &ComputeRegion{CountryCode: "ua", SubdivisionGeonameId: 703883})
	fixture.regions.place(testRegionAdmittedAddr, &ComputeRegion{CountryCode: "ua", SubdivisionGeonameId: 222})
}

// Serves every admission from forwarded, the ingress's X-UR-Forwarded-For, answering each recorder.
func serveTestAbuseAdmissionsFrom(fixture *computeFixture, forwarded string) map[string]int {
	routeCodes := map[string]int{}
	for _, admission := range testAbuseAdmissions() {
		headers := map[string]string{computeForwardedForHeader: forwarded}
		for name, value := range admission.headers {
			headers[name] = value
		}
		recorder := fixture.serve(admission.method, admission.path, fixture.token(), "", headers)
		if recorder.Code == http.StatusUnavailableForLegalReasons && computeRefusalCodeOf(recorder) != ComputeRefusalRegionRefused {
			routeCodes[admission.route] = -1
			continue
		}
		routeCodes[admission.route] = recorder.Code
	}
	return routeCodes
}

// An address in a refused country, or in a refused subdivision of any country, is refused 451 region_refused at the
// infer, search authorize and enclave create and start admissions with no handler running; an address in neither is
// admitted; routes that admit nothing check no region.
func TestRegionRefusedAtEveryAdmission(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	placeTestRegions(fixture)
	for _, forwarded := range []string{testRegionRefusedCountryAddr.String() + ":40123", "[" + testRegionRefusedSubdivisionAddr.String() + "]:443"} {
		for route, code := range serveTestAbuseAdmissionsFrom(fixture, forwarded) {
			if code != http.StatusUnavailableForLegalReasons {
				t.Errorf("%s from a refused region answered %d", route, code)
			}
		}
	}
	if counting.count() != 0 {
		t.Fatalf("%d handlers ran behind a region refusal", counting.count())
	}
	for route, code := range serveTestAbuseAdmissionsFrom(fixture, testRegionAdmittedAddr.String()+":5000") {
		if code != http.StatusOK {
			t.Errorf("%s from an admitted region answered %d", route, code)
		}
	}
	// a v4 address mapped into v6 is the v4 address
	mapped := "[::ffff:" + testRegionRefusedCountryAddr.String() + "]:40123"
	if codes := serveTestAbuseAdmissionsFrom(fixture, mapped); codes[ComputeRouteInfer] != http.StatusUnavailableForLegalReasons {
		t.Fatalf("a v4-mapped address answered %d", codes[ComputeRouteInfer])
	}
	// the catalog is no admission, so it asks no region
	asked := len(fixture.regions.asked)
	headers := map[string]string{computeForwardedForHeader: testRegionRefusedCountryAddr.String() + ":40123"}
	if recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", headers); recorder.Code != http.StatusOK {
		t.Fatalf("the catalog from a refused region: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(fixture.regions.asked) != asked {
		t.Fatal("the catalog asked the region lookup")
	}
	// a request no ingress fronts is checked by its peer, httptest's 192.0.2.1
	if recorder := fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("a request with no forwarded address: %d %s", recorder.Code, recorder.Body.String())
	}
	if last := fixture.regions.asked[len(fixture.regions.asked)-1]; last != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("the peer looked up was %v", last)
	}
}

// An admission that cannot check its region refuses unavailable: a block given no lookup, a lookup that fails, a
// forwarded header that is not one address, two forwarded headers.
func TestRegionThatCannotBeCheckedRefuses(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	fixture.regions.failing = true
	for route, code := range serveTestAbuseAdmissionsFrom(fixture, testRegionAdmittedAddr.String()+":5000") {
		if code != http.StatusServiceUnavailable {
			t.Errorf("%s with a failing lookup answered %d", route, code)
		}
	}
	fixture.regions.failing = false
	for _, forwarded := range []string{"not an address", "198.51.100.9:5000, 198.51.100.10:5000", ""} {
		recorder := fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", map[string]string{computeForwardedForHeader: forwarded})
		requireComputeRefusal(t, recorder, http.StatusServiceUnavailable, ComputeRefusalUnavailable)
	}
	request := httptest.NewRequestWithContext(fixture.ctx, http.MethodPost, "http://compute.example/v1/infer/authorize", strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+fixture.token())
	request.Header.Add(computeForwardedForHeader, testRegionAdmittedAddr.String()+":5000")
	request.Header.Add(computeForwardedForHeader, testRegionAdmittedAddr.String()+":5001")
	recorder := httptest.NewRecorder()
	fixture.engine.Handler().ServeHTTP(recorder, request)
	requireComputeRefusal(t, recorder, http.StatusServiceUnavailable, ComputeRefusalUnavailable)
	if counting.count() != 0 {
		t.Fatalf("%d handlers ran behind an unchecked region", counting.count())
	}

	unlooked := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(&countingComputeHandler{}), approvalGate: &fakeComputeApprovalGate{}})
	unlooked.engine.deps.RegionLookup = nil
	requireComputeRefusal(t, unlooked.serve(http.MethodPost, "/v1/infer/authorize", unlooked.token(), "", nil), http.StatusServiceUnavailable, ComputeRefusalUnavailable)
}

// Settings with no refused region refuse no address, and the lists are read as the settings give them.
func TestRegionListsAreTheSettings(t *testing.T) {
	settings := DefaultComputeEngineSettings()
	settings.Abuse.RefusedCountryCodes = nil
	settings.Abuse.RefusedSubdivisionGeonameIds = []uint32{222}
	fixture, _ := newTestAbuseBroker(t, nil, settings)
	placeTestRegions(fixture)
	codes := serveTestAbuseAdmissionsFrom(fixture, testRegionRefusedCountryAddr.String()+":1")
	if codes[ComputeRouteInfer] != http.StatusOK {
		t.Fatalf("a country no setting lists answered %d", codes[ComputeRouteInfer])
	}
	codes = serveTestAbuseAdmissionsFrom(fixture, testRegionAdmittedAddr.String()+":1")
	if codes[ComputeRouteInfer] != http.StatusUnavailableForLegalReasons {
		t.Fatalf("a subdivision the settings list answered %d", codes[ComputeRouteInfer])
	}
	defaults := DefaultComputeAbuseSettings()
	for _, region := range []*ComputeRegion{{CountryCode: "cu"}, {CountryCode: "ir"}, {CountryCode: "kp"}, {SubdivisionGeonameId: 703883}, {CountryCode: "ru", SubdivisionGeonameId: 694422}, {SubdivisionGeonameId: 709716}, {SubdivisionGeonameId: 702657}} {
		if !defaults.refusesRegion(region) {
			t.Errorf("the defaults admit %+v", region)
		}
	}
	for _, region := range []*ComputeRegion{{}, {CountryCode: "ua"}, {CountryCode: "de", SubdivisionGeonameId: 2950157}} {
		if defaults.refusesRegion(region) {
			t.Errorf("the defaults refuse %+v", region)
		}
	}
}

// A capture of everything a broker keeps or says while it refuses and admits by region holds no form of the address
// it looked up: not the service log, nor the engine's log, nor a metric's series, nor a Redis key or value (I-13).
func TestRegionAddressReachesNoLogMetricOrKey(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	log := capture.Logger("compute")
	recording := &recordingComputeServiceLog{}
	counting := &countingComputeHandler{}
	fixture := newComputeFixture(t, &computeFixtureOptions{
		handlers:     countingComputeHandlers(counting),
		approvalGate: &fakeComputeApprovalGate{},
		log:          log,
		serviceLog:   teeComputeServiceLog{recording, NewLoggerComputeServiceLog(log)},
	})
	placeTestRegions(fixture)
	addrPorts := []string{
		testRegionRefusedCountryAddr.String() + ":40123",
		"[" + testRegionRefusedSubdivisionAddr.String() + "]:443",
		testRegionAdmittedAddr.String() + ":50000",
	}
	for _, addrPort := range addrPorts {
		capture.Forbid("the address and port", []byte(addrPort))
	}
	capture.Forbid("the refused address", []byte(testRegionRefusedCountryAddr.String()))
	capture.Forbid("the refused v6 address", []byte(testRegionRefusedSubdivisionAddr.String()))
	capture.Forbid("the admitted address", []byte(testRegionAdmittedAddr.String()))
	capture.AddSource(func() []*sidecartest.PrivacyItem {
		items := []*sidecartest.PrivacyItem{}
		for key, value := range fixture.redis.Dump() {
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassRedis, Name: "redis key", Body: []byte(key)})
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassRedis, Name: "redis value", Body: value})
		}
		for _, series := range fixture.metrics.Dump() {
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassMetric, Name: "metric", Body: []byte(series)})
		}
		return items
	})
	refused := 0
	for _, addrPort := range addrPorts {
		for _, code := range serveTestAbuseAdmissionsFrom(fixture, addrPort) {
			if code == http.StatusUnavailableForLegalReasons {
				refused += 1
			}
		}
	}
	if refused != 2*len(testAbuseAdmissions()) || counting.count() != len(testAbuseAdmissions()) {
		t.Fatalf("%d refused and %d admitted, so the capture proves nothing", refused, counting.count())
	}
	if !slices.Contains(fixture.regions.asked, testRegionRefusedCountryAddr) || !slices.Contains(fixture.regions.asked, testRegionAdmittedAddr) {
		t.Fatal("the lookup was not asked the addresses, so the capture proves nothing")
	}
	if capture.ItemCount(sidecartest.PrivacyClassLog) < 3*len(testAbuseAdmissions())-3 {
		t.Fatalf("%d log lines captured", capture.ItemCount(sidecartest.PrivacyClassLog))
	}
	if capture.ItemCount(sidecartest.PrivacyClassRedis) == 0 || capture.ItemCount(sidecartest.PrivacyClassMetric) == 0 {
		t.Fatal("no Redis entry or metric captured, so the scan reads nothing there")
	}
	for _, finding := range capture.Scan() {
		t.Errorf("the address reached %s", finding)
	}
	// the scan sees what it is shown: a line that did hold the address would fail it
	planted := sidecartest.NewPrivacyCapture()
	planted.Forbid("the refused address", []byte(testRegionRefusedCountryAddr.String()))
	planted.Logger("planted").Infof("[compute] refused %s", testRegionRefusedCountryAddr)
	if len(planted.Scan()) == 0 {
		t.Fatal("a planted line holding the address passed the scan")
	}
	// the region refusal is counted by its code, the only trace it leaves
	if fixture.metrics.Value("urnetwork_compute_refusals_total", ComputeRouteInfer, string(ComputeRefusalRegionRefused)) != 2 {
		t.Fatalf("the refusals were not counted: %v", fixture.metrics.Dump())
	}
	// and the abuse hold's own key holds no address either: its value is a version and a class
	if value := fixture.redis.Dump()[model.ComputeAbuseHoldRedisKey(fixture.networkId)]; string(value) != "0:0" {
		t.Fatalf("the hold's projection reads %q", value)
	}
}
