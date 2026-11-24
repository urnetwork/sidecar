package computeservice

// The guard (CSRV-M12-01, §14.2, §14.3): every refusal in its order before a planted handler runs, a network whose
// state is not loaded never allowed, the admission checks before the handler, the refusal table, and the service log's
// lines holding nothing a request carried (IC-13).

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Each step's refusal, on a world where every earlier step passes, answered before a handler planted on every route
// runs; and with nothing refused, the handler answers.
func TestComputeGuardRefusesInOrder(t *testing.T) {
	type guardCase struct {
		name string
		// changes the fixture so this step refuses; returns the bearer to send
		set     func(fixture *computeFixture) string
		method  string
		path    string
		headers map[string]string
		status  int
		code    ComputeRefusalCode
		// the Retry-After the refusal carries, "" for none
		retryAfter string
	}
	sidecarToken := func(fixture *computeFixture) string { return fixture.token() }
	cases := []guardCase{
		{
			name:   "no token",
			set:    func(fixture *computeFixture) string { return "" },
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusUnauthorized, code: ComputeRefusalUnauthenticated,
		},
		{
			name: "another audience",
			set: func(fixture *computeFixture) string {
				return fixture.authenticator.Issue(fixture.principal("evs"))
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusUnauthorized, code: ComputeRefusalUnauthenticated,
		},
		{
			name: "a token without ur_sidecar_id",
			set: func(fixture *computeFixture) string {
				principal := fixture.principal(ComputeAudience)
				principal.SidecarId = nil
				return fixture.authenticator.Issue(principal)
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusForbidden, code: ComputeRefusalScope,
		},
		{
			name: "a voided subject",
			set: func(fixture *computeFixture) string {
				fixture.authState.revoke(fixture.sidecarId)
				return fixture.token()
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusUnauthorized, code: ComputeRefusalUnauthenticated,
		},
		{
			name: "rev/ that does not answer",
			set: func(fixture *computeFixture) string {
				fixture.authState.revocationUnknown = true
				return fixture.token()
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusServiceUnavailable, code: ComputeRefusalUnavailable, retryAfter: "1",
		},
		{
			name: "an unloaded network",
			set: func(fixture *computeFixture) string {
				fixture.authState.unload(fixture.networkId)
				return fixture.token()
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusServiceUnavailable, code: ComputeRefusalUnavailable, retryAfter: "1",
		},
		{
			name: "an unadmitted sidecar",
			set: func(fixture *computeFixture) string {
				principal := fixture.principal(ComputeAudience)
				other := connect.Id(testComputeId("sidecar-b"))
				principal.SidecarId = &other
				return fixture.authenticator.Issue(principal)
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusForbidden, code: ComputeRefusalScope,
		},
		{
			name: "an unimplemented feature",
			set: func(fixture *computeFixture) string {
				fixture.authState.load(fixture.networkId, ComputeAuthFeatureComputePolicy|ComputeAuthFeatureEnclaves)
				return fixture.token()
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusServiceUnavailable, code: ComputeRefusalUpgradeRequired,
		},
		{
			name: "a closed gate",
			set: func(fixture *computeFixture) string {
				if err := fixture.gates.Set(""); err != nil {
					fixture.t.Fatal(err)
				}
				return fixture.token()
			},
			method: http.MethodGet, path: "/v1/catalog",
			status: http.StatusServiceUnavailable, code: ComputeRefusalUnavailable, retryAfter: "60",
		},
		{
			name: "a gate that takes no writes",
			set: func(fixture *computeFixture) string {
				text := fmt.Sprintf("sidecar:\n  compute: {enabled: true, writes: false, networks: [%s], percent: 0}\n", connect.Id(fixture.networkId))
				if err := fixture.gates.Set(text); err != nil {
					fixture.t.Fatal(err)
				}
				return fixture.token()
			},
			method: http.MethodPost, path: "/v1/infer/prepare",
			status: http.StatusServiceUnavailable, code: ComputeRefusalUnavailable, retryAfter: "60",
		},
		{
			name: "an unlinked group",
			set: func(fixture *computeFixture) string {
				fixture.unlink(ComputeMigrationGroupC3)
				return fixture.token()
			},
			method: http.MethodGet, path: "/v1/enclaves",
			status: http.StatusServiceUnavailable, code: ComputeRefusalUnavailable, retryAfter: "1",
		},
		{
			name:   "a missing Idempotency-Key",
			set:    sidecarToken,
			method: http.MethodPost, path: "/v1/budget/raise",
			status: http.StatusBadRequest, code: ComputeRefusalIdempotencyKeyRequired,
		},
		{
			name:   "an approval route with no gate",
			set:    sidecarToken,
			method: http.MethodPost, path: "/v1/budget/raise", headers: map[string]string{ComputeIdempotencyKeyHeader: "effect-key-1"},
			status: http.StatusServiceUnavailable, code: ComputeRefusalUnavailable, retryAfter: "1",
		},
		{
			name:   "a path no route takes",
			set:    sidecarToken,
			method: http.MethodGet, path: "/v1/nothing",
			status: http.StatusNotFound, code: ComputeRefusalNotFound,
		},
		{
			name:   "a method no route takes",
			set:    sidecarToken,
			method: http.MethodPut, path: "/v1/catalog",
			status: http.StatusNotFound, code: ComputeRefusalNotFound,
		},
	}
	for _, c := range cases {
		counting := &countingComputeHandler{}
		fixture := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(counting)})
		bearer := c.set(fixture)
		recorder := fixture.serve(c.method, c.path, bearer, "", c.headers)
		if recorder.Code != c.status || computeRefusalCodeOf(recorder) != c.code {
			t.Errorf("%s: answered %d %s, want %d %q", c.name, recorder.Code, recorder.Body.String(), c.status, c.code)
		}
		if got := recorder.Header().Get("Retry-After"); got != c.retryAfter {
			t.Errorf("%s: Retry-After %q, want %q", c.name, got, c.retryAfter)
		}
		if counting.count() != 0 {
			t.Errorf("%s: the handler ran", c.name)
		}
	}

	// nothing refused: the route's handler answers, once
	counting := &countingComputeHandler{}
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(counting)})
	if recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("an admitted sidecar's catalog read: %d %s", recorder.Code, recorder.Body.String())
	}
	if counting.count() != 1 {
		t.Fatalf("the handler ran %d times", counting.count())
	}
	caller := counting.requests[0].Caller
	if caller == nil || caller.SidecarId != fixture.sidecarId || caller.NetworkId != fixture.networkId || caller.MemberId != fixture.memberId || !caller.Consented {
		t.Fatalf("the handler's caller is %+v", caller)
	}
}

// A network whose state is not loaded answers 503 on every sidecar route and never runs a handler, through the fake
// and through the real state over a cache that holds nothing, which is asked to load the network.
func TestComputeUnloadedNetworkIsNeverAllowed(t *testing.T) {
	counting := &countingComputeHandler{}
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(counting)})
	fixture.authState.unload(fixture.networkId)
	headers := map[string]string{ComputeIdempotencyKeyHeader: "effect-key-1"}
	for _, route := range computeRouteDesign() {
		if route.Auth != ComputeRouteAuthSidecar {
			continue
		}
		path := strings.ReplaceAll(route.Pattern, "{id}", sidecar.EvsKeyId(testComputeId("enclave-1")))
		recorder := fixture.serve(route.Method, path, fixture.token(), "", headers)
		if recorder.Code != http.StatusServiceUnavailable || computeRefusalCodeOf(recorder) != ComputeRefusalUnavailable {
			t.Errorf("%s with the network unloaded: %d %s", route.Name, recorder.Code, recorder.Body.String())
		}
	}
	if counting.count() != 0 {
		t.Fatalf("a handler ran %d times for an unloaded network", counting.count())
	}

	// the real state, over a cache that holds nothing yet
	states := sidecartest.NewFakeAclContractStates()
	real := NewComputeAuthState(states, &testComputeRevocations{}, fixture.clock)
	if caller, answer := real.Caller(fixture.principal(ComputeAudience)); caller != nil || answer != ComputeAuthUnknown {
		t.Fatalf("the real state answered %v for a network it holds nothing of", answer)
	}
	if _, answer := real.Features(fixture.networkId); answer != ComputeAuthUnknown {
		t.Fatalf("the real state's features answered %v for a network it holds nothing of", answer)
	}
	if !slices.Contains(states.ChangedNetworks(), fixture.networkId) {
		t.Fatal("the real state did not ask the cache to load the network")
	}
}

// An admission route runs every check before its handler, and a refusing check keeps the handler from running; a
// route that admits nothing runs none.
func TestComputeAdmissionChecksRunBeforeTheHandler(t *testing.T) {
	order := []string{}
	refuse := false
	check := func(request *ComputeRequest) *ComputeRefusal {
		order = append(order, "check "+request.Route().Name)
		if request.Caller == nil || request.Caller.SidecarId == (sidecar.Id{}) {
			order = append(order, "a check without its caller")
		}
		if refuse {
			return NewComputeRefusal(ComputeRefusalSuspended)
		}
		return nil
	}
	handler := func(request *ComputeRequest) {
		order = append(order, "handler "+request.Route().Name)
		request.Reply(nil)
	}
	fixture := newComputeFixture(t, &computeFixtureOptions{
		handlers:        map[string]ComputeHandler{ComputeRouteInferAuthorize: handler, ComputeRouteCatalog: handler},
		admissionChecks: []ComputeAdmissionCheck{check},
	})
	if recorder := fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("an admitted authorize: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("the catalog: %d %s", recorder.Code, recorder.Body.String())
	}
	refuse = true
	recorder := fixture.serve(http.MethodPost, "/v1/infer/authorize", fixture.token(), "", nil)
	requireComputeRefusal(t, recorder, http.StatusForbidden, ComputeRefusalSuspended)
	want := []string{
		"check " + ComputeRouteInferAuthorize, "handler " + ComputeRouteInferAuthorize,
		"handler " + ComputeRouteCatalog,
		"check " + ComputeRouteInferAuthorize,
	}
	if !slices.Equal(order, want) {
		t.Fatalf("ran %q, want %q", order, want)
	}
}

// The approval gate is asked after every other step, for its route's kind, and its refusal stands; a conditional
// approval route asks it too, so the gate decides.
func TestComputeApprovalGateDecidesItsRoutes(t *testing.T) {
	counting := &countingComputeHandler{}
	gate := &fakeComputeApprovalGate{}
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(counting), approvalGate: gate})
	headers := map[string]string{ComputeIdempotencyKeyHeader: "effect-key-1"}
	if recorder := fixture.serve(http.MethodPost, "/v1/budget/raise", fixture.token(), "", headers); recorder.Code != http.StatusOK {
		t.Fatalf("an approved raise: %d %s", recorder.Code, recorder.Body.String())
	}
	enclavePath := "/v1/enclaves/" + sidecar.EvsKeyId(testComputeId("enclave-1")) + "/start"
	if recorder := fixture.serve(http.MethodPost, enclavePath, fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("a start: %d %s", recorder.Code, recorder.Body.String())
	}
	gate.refusal = NewComputeRefusal(ComputeRefusalScope)
	requireComputeRefusal(t, fixture.serve(http.MethodPost, "/v1/enclaves", fixture.token(), "", headers), http.StatusForbidden, ComputeRefusalScope)
	if want := []ComputeApprovalKind{ComputeApprovalKindBudgetRaise, ComputeApprovalKindEnclaveCreate, ComputeApprovalKindEnclaveCreate}; !slices.Equal(gate.kinds, want) {
		t.Fatalf("the gate was asked %v, want %v", gate.kinds, want)
	}
	if counting.count() != 2 {
		t.Fatalf("handlers ran %d times", counting.count())
	}
}

// A code the table does not have is a handler's fault: it alarms and answers 503 unavailable in its place.
func TestComputeRefusalOutsideTheTableAnswersUnavailable(t *testing.T) {
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: map[string]ComputeHandler{
		ComputeRouteCatalog: func(request *ComputeRequest) {
			request.Refuse(&ComputeRefusal{Code: "made_up", RetryAfter: 0})
		},
	}})
	recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil)
	requireComputeRefusal(t, recorder, http.StatusServiceUnavailable, ComputeRefusalUnavailable)
	if fixture.metrics.Value("urnetwork_compute_alarms_total", "refusal_code") != 1 {
		t.Fatal("no alarm for the code")
	}
	// every code of the table answers its own status, and a retry time rides both the header and the body
	for code, status := range computeRefusalStatuses {
		got, ok := ComputeRefusalStatus(code)
		if !ok || got != status {
			t.Errorf("%s answers %d", code, got)
		}
	}
	body := string((&ComputeRefusal{Code: ComputeRefusalHeld, Reason: "holds", RetryAfter: 1500 * 1000 * 1000}).body())
	if body != `{"code":"held","reason":"holds","retry_after_ms":1500}` {
		t.Fatalf("a held refusal's body is %s", body)
	}
}

// The service log's lines hold no body, header value, query or path value the requests carried, whatever a handler
// read, and the handler's row ids are on them.
func TestComputeServiceLogHoldsNoBody(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	bodyCanary := capture.Canary("body")
	headerCanary := capture.CanaryText("header")
	pathCanary := capture.CanaryText("path value")
	queryCanary := capture.CanaryText("query")
	keyCanary := capture.CanaryText("idempotency key")
	rowId := testComputeId("operation-1")
	read := []string{}
	handler := func(request *ComputeRequest) {
		body, ok := request.ReadBody()
		if !ok {
			return
		}
		read = append(read, string(body), request.PathValue("id"), request.Http.URL.Query().Get("host"), request.Http.Header.Get("X-Canary"))
		request.NoteRowIds(rowId)
		request.Reply(nil)
	}
	log := capture.Logger("compute")
	recording := &recordingComputeServiceLog{}
	fixture := newComputeFixture(t, &computeFixtureOptions{
		handlers: map[string]ComputeHandler{
			ComputeRouteEnclaveStop: handler, ComputeRouteTunnel: handler, ComputeRouteBudgetRaise: handler,
		},
		approvalGate: &fakeComputeApprovalGate{},
		log:          log,
		serviceLog:   teeComputeServiceLog{recording, NewLoggerComputeServiceLog(log)},
	})
	headers := map[string]string{"X-Canary": headerCanary, ComputeIdempotencyKeyHeader: keyCanary}
	for _, path := range []string{"/v1/enclaves/" + pathCanary + "/stop", "/v1/budget/raise"} {
		if recorder := fixture.serve(http.MethodPost, path, fixture.token(), string(bodyCanary), headers); recorder.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	if recorder := fixture.serve(http.MethodGet, "/v1/tunnel?host="+queryCanary, fixture.token(), "", headers); recorder.Code != http.StatusOK {
		t.Fatalf("the tunnel: %d %s", recorder.Code, recorder.Body.String())
	}
	// a refusal's line too
	fixture.serve(http.MethodPost, "/v1/enclaves/"+pathCanary+"/stop", "", string(bodyCanary), headers)
	if !slices.Contains(read, string(bodyCanary)) || !slices.Contains(read, pathCanary) || !slices.Contains(read, queryCanary) || !slices.Contains(read, headerCanary) {
		t.Fatal("the handler did not read what the requests carried, so the test proves nothing")
	}
	if capture.ItemCount(sidecartest.PrivacyClassLog) < 4 {
		t.Fatalf("%d log lines captured", capture.ItemCount(sidecartest.PrivacyClassLog))
	}
	for _, finding := range capture.Scan() {
		t.Errorf("the service log holds %s", finding)
	}
	// the lines carry the handler's row ids
	noted := 0
	for _, entry := range recording.lines() {
		if slices.Contains(entry.RowIds, rowId) {
			noted += 1
		}
	}
	if noted != 3 {
		t.Fatalf("%d lines carry the row id", noted)
	}
}

// Every line to both logs.
type teeComputeServiceLog []ComputeServiceLog

func (self teeComputeServiceLog) Write(entry *ComputeServiceLogEntry) {
	for _, log := range self {
		log.Write(entry)
	}
}

// POST /v1/search/authorize leaves no line, whatever it answers, while its counts reach the metrics.
func TestComputeSearchAuthorizeLeavesNoLogLine(t *testing.T) {
	counting := &countingComputeHandler{}
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(counting)})
	if recorder := fixture.serve(http.MethodPost, "/v1/search/authorize", fixture.token(), "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("an authorize: %d %s", recorder.Code, recorder.Body.String())
	}
	fixture.serve(http.MethodPost, "/v1/search/authorize", "", "", nil)
	if lines := fixture.serviceLog.lines(); len(lines) != 0 {
		t.Fatalf("search authorize left %d lines", len(lines))
	}
	if fixture.metrics.Value("urnetwork_compute_requests_total", ComputeRouteSearchAuthorize, "200") != 1 ||
		fixture.metrics.Value("urnetwork_compute_requests_total", ComputeRouteSearchAuthorize, "401") != 1 {
		t.Fatalf("the metrics did not count the searches: %v", fixture.metrics.Dump())
	}
	// any other route leaves its line
	fixture.serve(http.MethodPost, "/v1/search/outcomes", fixture.token(), "", nil)
	if lines := fixture.serviceLog.lines(); len(lines) != 1 || lines[0].Route != ComputeRouteSearchOutcomes {
		t.Fatalf("outcomes left %d lines", len(lines))
	}
}

// A body over its route's bound answers 400 invalid before the handler sees it, a declared length past the bound
// without reading it.
func TestComputeBodyOverItsBoundIsInvalid(t *testing.T) {
	settings := DefaultComputeEngineSettings()
	settings.RouteBodyMaxByteCounts = map[string]int64{ComputeRouteInferDispute: 16}
	read := 0
	fixture := newComputeFixture(t, &computeFixtureOptions{
		settings: settings,
		handlers: map[string]ComputeHandler{ComputeRouteInferDispute: func(request *ComputeRequest) {
			if _, ok := request.ReadBody(); ok {
				read += 1
				request.Reply(nil)
			}
		}},
	})
	if recorder := fixture.serve(http.MethodPost, "/v1/infer/dispute", fixture.token(), strings.Repeat("a", 16), nil); recorder.Code != http.StatusOK {
		t.Fatalf("a body at its bound: %d", recorder.Code)
	}
	requireComputeRefusal(t, fixture.serve(http.MethodPost, "/v1/infer/dispute", fixture.token(), strings.Repeat("a", 17), nil), http.StatusBadRequest, ComputeRefusalInvalid)
	if read != 1 {
		t.Fatalf("read %d bodies", read)
	}
	settings.RouteBodyMaxByteCounts = map[string]int64{"POST /v1/nothing": 16}
	if _, err := NewComputeEngine(context.Background(), fixture.host, settings, nil); err == nil {
		t.Fatal("a bound for no route was taken")
	}
}
