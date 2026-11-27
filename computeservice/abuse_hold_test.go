package computeservice

// The abuse hold at the broker (CARCH-M12-01; DESIGN-COMPUTE §17.2, D-CABUSE-1, D-CABUSE-2): a network an operator
// suspends, or §21 suspends, is refused `suspended` at every admission, on every broker instance that shares the
// Redis, until a resume; an admission that cannot read the hold refuses; the projection never goes back to an older
// version; and the other areas' flags refuse only the routes they name.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The admission routes a test serves, each as a device would ask it.
type testAbuseAdmission struct {
	route   string
	method  string
	path    string
	headers map[string]string
}

func testAbuseAdmissions() []*testAbuseAdmission {
	enclaveId := sidecar.EvsKeyId(testComputeId("enclave-1"))
	key := map[string]string{ComputeIdempotencyKeyHeader: "effect-key-1"}
	return []*testAbuseAdmission{
		{route: ComputeRouteInfer, method: http.MethodPost, path: "/v1/infer"},
		{route: ComputeRouteInferAuthorize, method: http.MethodPost, path: "/v1/infer/authorize"},
		{route: ComputeRouteSearchAuthorize, method: http.MethodPost, path: "/v1/search/authorize"},
		{route: ComputeRouteEnclaveCreate, method: http.MethodPost, path: "/v1/enclaves", headers: key},
		{route: ComputeRouteEnclaveStart, method: http.MethodPost, path: "/v1/enclaves/" + enclaveId + "/start"},
	}
}

// A broker on a world with every admission's handler counting and an approval gate that approves.
func newTestAbuseBroker(t *testing.T, sharedWith *computeFixture, settings *ComputeEngineSettings) (*computeFixture, *countingComputeHandler) {
	counting := &countingComputeHandler{}
	fixture := newComputeFixture(t, &computeFixtureOptions{
		handlers:     countingComputeHandlers(counting),
		approvalGate: &fakeComputeApprovalGate{},
		settings:     settings,
		sharedWith:   sharedWith,
	})
	return fixture, counting
}

// What a staff act leaves: the row changed, then projected, as ComputeAbuseHoldSuspend and Resume do.
func testAbuseHoldAct(t *testing.T, fixture *computeFixture, reason model.ComputeAbuseHoldReason, held bool) {
	t.Helper()
	state := fixture.abuseHolds.set(fixture.networkId, reason, held, fixture.clock.Now())
	projected, err := model.ComputeAbuseHoldProject(fixture.ctx, fixture.redis, model.DefaultComputeAbuseHoldSettings(), fixture.networkId, state)
	if err != nil || !projected {
		t.Fatalf("the act's projection: %v %v", projected, err)
	}
}

// Fails unless every admission answers status with code and reason, and its handler did not run.
func requireAbuseAdmissions(t *testing.T, fixture *computeFixture, counting *countingComputeHandler, status int, code ComputeRefusalCode, reason string) {
	t.Helper()
	before := counting.count()
	for _, admission := range testAbuseAdmissions() {
		recorder := fixture.serve(admission.method, admission.path, fixture.token(), "", admission.headers)
		if status == http.StatusOK {
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s: answered %d %s", admission.route, recorder.Code, recorder.Body.String())
			}
			continue
		}
		requireComputeRefusal(t, recorder, status, code)
		if got := testComputeRefusalReason(recorder); got != reason {
			t.Fatalf("%s: reason %q, want %q", admission.route, got, reason)
		}
	}
	ran := counting.count() - before
	if status == http.StatusOK && ran != len(testAbuseAdmissions()) {
		t.Fatalf("%d handlers ran of %d admissions", ran, len(testAbuseAdmissions()))
	}
	if status != http.StatusOK && ran != 0 {
		t.Fatalf("%d handlers ran behind a refusal", ran)
	}
}

// A refusal's reason, "" for none.
func testComputeRefusalReason(recorder *httptest.ResponseRecorder) string {
	body := &computeRefusalBody{}
	if err := json.Unmarshal(recorder.Body.Bytes(), body); err != nil {
		return ""
	}
	return body.Reason
}

// A network an operator suspends is refused suspended at the infer, search authorize and enclave create and start
// admissions of two broker instances sharing Redis, with no handler running; a resume admits again on both; routes
// that admit nothing are left alone throughout; the balance and the records are never read or written.
func TestAbuseHoldRefusesEveryAdmissionAcrossTwoBrokers(t *testing.T) {
	first, firstCounting := newTestAbuseBroker(t, nil, nil)
	second, secondCounting := newTestAbuseBroker(t, first, nil)
	requireAbuseAdmissions(t, first, firstCounting, http.StatusOK, "", "")
	requireAbuseAdmissions(t, second, secondCounting, http.StatusOK, "", "")

	testAbuseHoldAct(t, first, model.ComputeAbuseHoldReasonMining, true)
	requireAbuseAdmissions(t, first, firstCounting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	requireAbuseAdmissions(t, second, secondCounting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	// what admits nothing is not held: the catalog, the enclave list, a stop
	for _, fixture := range []*computeFixture{first, second} {
		for _, path := range []string{"/v1/catalog", "/v1/enclaves"} {
			if recorder := fixture.serve(http.MethodGet, path, fixture.token(), "", nil); recorder.Code != http.StatusOK {
				t.Fatalf("GET %s on a held network: %d %s", path, recorder.Code, recorder.Body.String())
			}
		}
		stop := "/v1/enclaves/" + sidecar.EvsKeyId(testComputeId("enclave-1")) + "/stop"
		if recorder := fixture.serve(http.MethodPost, stop, fixture.token(), "", nil); recorder.Code != http.StatusOK {
			t.Fatalf("a stop on a held network: %d %s", recorder.Code, recorder.Body.String())
		}
	}

	// another reason is still a hold, and says nothing of its class
	testAbuseHoldAct(t, first, model.ComputeAbuseHoldReasonTakedown, true)
	requireAbuseAdmissions(t, second, secondCounting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)

	testAbuseHoldAct(t, first, model.ComputeAbuseHoldReasonTakedown, false)
	requireAbuseAdmissions(t, first, firstCounting, http.StatusOK, "", "")
	requireAbuseAdmissions(t, second, secondCounting, http.StatusOK, "", "")

	// the hold reads only its own key, in the network's slot: no ledger key was written or read
	for key := range first.redis.Dump() {
		if key != model.ComputeAbuseHoldRedisKey(first.networkId) {
			t.Errorf("the hold left %s", key)
		}
	}
}

// DESIGN §21's suspension, and a standing this build does not know, refuse every admission as the operator's hold
// does, reason standing; a network the gate has not loaded answers unavailable; probation, restricted and trusted
// networks admit.
func TestAbuseHoldReadsDesignTwentyOnesStanding(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	networkId := connect.Id(fixture.networkId)
	for _, standing := range []sidecar.AbuseStanding{sidecar.AbuseStandingProbation, sidecar.AbuseStandingRestricted, sidecar.AbuseStandingTrusted} {
		fixture.abuse.SetStanding(networkId, standing)
		requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")
	}
	fixture.abuse.SetStanding(networkId, sidecar.AbuseStandingSuspended)
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonStanding)
	fixture.abuse.SetStanding(networkId, sidecar.AbuseStanding("frozen"))
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonStanding)
	fixture.abuse.Unload(networkId)
	requireAbuseAdmissions(t, fixture, counting, http.StatusServiceUnavailable, ComputeRefusalUnavailable, "")
	// a §21 suspension holds whatever the operator's hold says: the standing is read first
	fixture.abuse.Set(networkId, sidecar.AbuseStandingSuspended, true)
	testAbuseHoldAct(t, fixture, model.ComputeAbuseHoldReasonFraud, true)
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonStanding)
	testAbuseHoldAct(t, fixture, model.ComputeAbuseHoldReasonFraud, false)
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonStanding)
	fixture.abuse.SetStanding(networkId, sidecar.AbuseStandingStandard)
	requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")
}

// With no projection the first admission reads the row and projects it, and the next reads the projection alone; a
// projection lost to a failover, expired, or holding what this build does not write is filled again from the row.
func TestAbuseHoldFillsFromTheRowOnAMiss(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	fixture.abuseHolds.set(fixture.networkId, model.ComputeAbuseHoldReasonSpam, true, fixture.clock.Now())
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	if reads := fixture.abuseHolds.reads(); reads != 1 {
		t.Fatalf("five admissions read the row %d times", reads)
	}
	key := model.ComputeAbuseHoldRedisKey(fixture.networkId)
	if value := fixture.redis.Dump()[key]; string(value) != "1:3" {
		t.Fatalf("the fill projected %q", value)
	}
	fixture.redis.LoseEverything()
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	if reads := fixture.abuseHolds.reads(); reads != 2 {
		t.Fatalf("a lost projection was read again %d times", reads-1)
	}
	// the projection's life passes: the row is read again, and a resume the projection never took is honored
	fixture.abuseHolds.set(fixture.networkId, model.ComputeAbuseHoldReasonSpam, false, fixture.clock.Now())
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	fixture.clock.Advance(model.DefaultComputeAbuseHoldSettings().ProjectionMaxAge)
	requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")
	if value := fixture.redis.Dump()[key]; string(value) != "2:0" {
		t.Fatalf("the refill projected %q", value)
	}
	// a value this package does not write reads as absent, and the row replaces it
	if err := fixture.redis.Set(fixture.ctx, key, []byte("9:one"), time.Minute); err != nil {
		t.Fatal(err)
	}
	requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")
	if value := fixture.redis.Dump()[key]; string(value) != "2:0" {
		t.Fatalf("a broken projection became %q", value)
	}
}

// A network no row names reads version 0 and no hold, and is projected so: the row is read once a projection's life.
func TestAbuseHoldNetworkNeverHeldIsProjectedClear(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")
	if reads := fixture.abuseHolds.reads(); reads != 1 {
		t.Fatalf("five admissions of a network never held read the store %d times", reads)
	}
	if value := fixture.redis.Dump()[model.ComputeAbuseHoldRedisKey(fixture.networkId)]; string(value) != "0:0" {
		t.Fatalf("a network never held projected %q", value)
	}
}

// An admission that cannot read the hold refuses: Redis failing, the row failing on a miss, a block with no Redis.
func TestAbuseHoldThatCannotBeReadRefuses(t *testing.T) {
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	fixture.abuseHolds.failing = true
	requireAbuseAdmissions(t, fixture, counting, http.StatusServiceUnavailable, ComputeRefusalUnavailable, "")
	fixture.abuseHolds.failing = false
	requireAbuseAdmissions(t, fixture, counting, http.StatusOK, "", "")

	if _, err := fixture.faults.Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: model.ComputeAbuseHoldRedisKey(fixture.networkId), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", nil)
	requireComputeRefusal(t, recorder, http.StatusServiceUnavailable, ComputeRefusalUnavailable)
	if counting.count() != len(testAbuseAdmissions()) {
		t.Fatal("a handler ran behind a hold Redis did not answer")
	}

	fixture.host.Redis = nil
	requireAbuseAdmissions(t, fixture, counting, http.StatusServiceUnavailable, ComputeRefusalUnavailable, "")
}

// Settings that keep no projection read the row at every admission and write nothing to Redis.
func TestAbuseHoldWithNoProjectionReadsTheRowEachTime(t *testing.T) {
	settings := DefaultComputeEngineSettings()
	settings.Abuse.Hold.ProjectionMaxAge = 0
	fixture, counting := newTestAbuseBroker(t, nil, settings)
	fixture.abuseHolds.set(fixture.networkId, model.ComputeAbuseHoldReasonScanning, true, fixture.clock.Now())
	requireAbuseAdmissions(t, fixture, counting, http.StatusForbidden, ComputeRefusalSuspended, ComputeSuspendedReasonHold)
	if reads := fixture.abuseHolds.reads(); reads != len(testAbuseAdmissions()) {
		t.Fatalf("%d admissions read the row %d times", len(testAbuseAdmissions()), reads)
	}
	if dump := fixture.redis.Dump(); len(dump) != 0 {
		t.Fatalf("no projection, yet Redis holds %v", dump)
	}
}

// A projection never goes back: an older version written after a newer one leaves the newer standing, a writer racing
// a concurrent one wins or leaves the newer, and a value that does not read is replaced.
func TestAbuseHoldProjectionNeverGoesBack(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(ctx, clock, nil, nil, nil)
	settings := model.DefaultComputeAbuseHoldSettings()
	networkId := testComputeId("network-a")
	key := model.ComputeAbuseHoldRedisKey(networkId)
	project := func(version int64, reason model.ComputeAbuseHoldReason) {
		t.Helper()
		projected, err := model.ComputeAbuseHoldProject(ctx, redis, settings, networkId, &model.ComputeAbuseHoldState{Version: version, Reason: reason})
		if err != nil || !projected {
			t.Fatalf("projecting %d: %v %v", version, projected, err)
		}
	}
	project(2, model.ComputeAbuseHoldReasonMining)
	project(1, model.ComputeAbuseHoldReasonNone)
	if value := redis.Dump()[key]; string(value) != "2:1" {
		t.Fatalf("an older version replaced a newer: %q", value)
	}
	project(3, model.ComputeAbuseHoldReasonNone)
	if value := redis.Dump()[key]; string(value) != "3:0" {
		t.Fatalf("a newer version did not replace an older: %q", value)
	}
	for _, broken := range []string{"", "3", "x:0", "-1:0", "03:0", "3:99", "0:1", "3:1:2"} {
		if _, err := model.ParseComputeAbuseHoldProjection([]byte(broken)); !errors.Is(err, model.ErrComputeAbuseHoldProjection) {
			t.Errorf("%q read as a projection: %v", broken, err)
		}
	}
	if err := redis.Set(ctx, key, []byte("99:x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	project(4, model.ComputeAbuseHoldReasonSpam)
	if value := redis.Dump()[key]; string(value) != "4:3" {
		t.Fatalf("a broken value was not replaced: %q", value)
	}
	// it expires after its life, so a write that failed after its commit stands at most that long
	clock.Advance(settings.ProjectionMaxAge)
	if state, err := model.ComputeAbuseHoldProjected(ctx, redis, networkId); err != nil || state != nil {
		t.Fatalf("the projection outlived its life: %v %v", state, err)
	}
	// settings with no projection write none and say it took
	noProjection := &model.ComputeAbuseHoldSettings{}
	if projected, err := model.ComputeAbuseHoldProject(ctx, redis, noProjection, networkId, &model.ComputeAbuseHoldState{Version: 5}); err != nil || !projected || 0 < len(redis.Dump()) {
		t.Fatalf("no projection wrote one: %v %v %v", projected, err, redis.Dump())
	}
}

// A flag another area registers refuses only the routes it names, after the hold; registering one wrongly panics.
func TestAbuseFlagRefusesOnlyItsRoutes(t *testing.T) {
	saved := computeAbuseFlags
	t.Cleanup(func() { computeAbuseFlags = saved })
	computeAbuseFlags = nil
	asked := []string{}
	refuse := true
	registerComputeAbuseFlag(&ComputeAbuseFlag{
		Name:   "direct_mismatch",
		Routes: []string{ComputeRouteInferAuthorize},
		Check: func(request *ComputeRequest) *ComputeRefusal {
			asked = append(asked, request.Route().Name)
			if refuse {
				return &ComputeRefusal{Code: ComputeRefusalSuspended, Reason: "direct"}
			}
			return nil
		},
	})
	fixture, counting := newTestAbuseBroker(t, nil, nil)
	for _, admission := range testAbuseAdmissions() {
		recorder := fixture.serve(admission.method, admission.path, fixture.token(), "", admission.headers)
		switch admission.route {
		case ComputeRouteInferAuthorize:
			requireComputeRefusal(t, recorder, http.StatusForbidden, ComputeRefusalSuspended)
		default:
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s behind another route's flag: %d %s", admission.route, recorder.Code, recorder.Body.String())
			}
		}
	}
	if !slices.Equal(asked, []string{ComputeRouteInferAuthorize}) || counting.count() != len(testAbuseAdmissions())-1 {
		t.Fatalf("the flag was asked for %v, handlers ran %d times", asked, counting.count())
	}
	// a held network is refused by its hold before any flag is asked
	testAbuseHoldAct(t, fixture, model.ComputeAbuseHoldReasonFraud, true)
	asked = nil
	requireComputeRefusal(t, fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", nil), http.StatusForbidden, ComputeRefusalSuspended)
	if 0 < len(asked) {
		t.Fatal("a flag was asked for a held network")
	}
	refuse = false
	testAbuseHoldAct(t, fixture, model.ComputeAbuseHoldReasonFraud, false)
	if recorder := fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("a flag that admits: %d %s", recorder.Code, recorder.Body.String())
	}
	check := func(request *ComputeRequest) *ComputeRefusal { return nil }
	for label, flag := range map[string]*ComputeAbuseFlag{
		"no name":            {Routes: []string{ComputeRouteInfer}, Check: check},
		"no routes":          {Name: "a"},
		"no check":           {Name: "a", Routes: []string{ComputeRouteInfer}},
		"no admission route": {Name: "a", Routes: []string{ComputeRouteCatalog}, Check: check},
		"a second go":        {Name: "direct_mismatch", Routes: []string{ComputeRouteInfer}, Check: check},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			registerComputeAbuseFlag(flag)
		}()
	}
}

// The abuse settings validate as written, and refuse what no lookup could ever match.
func TestComputeAbuseSettingsValidate(t *testing.T) {
	if err := DefaultComputeAbuseSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, countryCode := range []string{"IR", "irn", "i", "", "1r"} {
		settings := DefaultComputeAbuseSettings()
		settings.RefusedCountryCodes = []string{countryCode}
		if err := settings.Validate(); err == nil {
			t.Errorf("the country code %q validated", countryCode)
		}
	}
	settings := DefaultComputeAbuseSettings()
	settings.RefusedSubdivisionGeonameIds = []uint32{0}
	if err := settings.Validate(); err == nil {
		t.Error("a subdivision id of 0 validated")
	}
	engineSettings := DefaultComputeEngineSettings()
	engineSettings.Abuse.RefusedCountryCodes = []string{"XX"}
	if err := engineSettings.Validate(); err == nil {
		t.Error("an engine with a broken abuse setting validated")
	}
}
