package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// GET /abuse/status's body, with an action that ends by itself and one only a lift ends.
const testAbuseStatusJson = `{"standing":"restricted","verified":true,"actions":[` +
	`{"action_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a51","case_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a50",` +
	`"category":"phishing","kind":"host_kill","target":"login.n1.example","review_state":"pending",` +
	`"create_time_ms":1767225600000,"until_time_ms":0},` +
	`{"action_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a53","case_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a52",` +
	`"category":"spam","kind":"mail_halt","target":"n1","review_state":"upheld",` +
	`"create_time_ms":1767229200000,"until_time_ms":1767315600000}]}`

// testAbuseStatusJson as a struct.
func testAbuseStatus(t *testing.T) *AbuseStatus {
	t.Helper()
	id := func(idStr string) Id {
		parsed, err := ParseId(idStr)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	return &AbuseStatus{
		Standing: AbuseStandingRestricted,
		Verified: true,
		Actions: []*AbuseStatusAction{
			{
				ActionId:     id("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a51"),
				CaseId:       id("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a50"),
				Category:     "phishing",
				Kind:         "host_kill",
				Target:       "login.n1.example",
				ReviewState:  "pending",
				CreateTimeMs: 1767225600000,
			},
			{
				ActionId:     id("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a53"),
				CaseId:       id("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a52"),
				Category:     "spam",
				Kind:         "mail_halt",
				Target:       "n1",
				ReviewState:  "upheld",
				CreateTimeMs: 1767229200000,
				UntilTimeMs:  1767315600000,
			},
		},
	}
}

// What api writes, the sidecar and the page Worker read, byte for byte, on every leg.
func TestAbuseStatusRoundTrip(t *testing.T) {
	want := testAbuseStatus(t)
	status := &AbuseStatus{}
	if err := json.Unmarshal([]byte(testAbuseStatusJson), status); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(status, want) {
		t.Errorf("%+v, want %+v", status, want)
	}
	for _, value := range []any{want, *want} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != testAbuseStatusJson {
			t.Errorf("%s, want %s", encoded, testAbuseStatusJson)
		}
	}
}

// A network with no action still answers a list, so a reader of the body never meets null.
func TestAbuseStatusWithNoActionsHoldsAnEmptyList(t *testing.T) {
	want := `{"standing":"probation","verified":false,"actions":[]}`
	for _, status := range []*AbuseStatus{
		{Standing: AbuseStandingProbation},
		{Standing: AbuseStandingProbation, Actions: []*AbuseStatusAction{}},
	} {
		encoded, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != want {
			t.Errorf("%s, want %s", encoded, want)
		}
	}
}

// D-ABUSE-8 and plan-ABUSE-small-readings #6: the status tells a network nothing about a hold or a
// barred case. Every field, at every depth, is pinned by name, so a field added here is a reviewed
// change to this list; none may be named for what a hold or a bar is made of; and none may be a map,
// an interface or raw bytes, which could carry any key at all.
func TestAbuseStatusHoldsNoHoldField(t *testing.T) {
	wantTypeJsonNames := map[string][]string{
		"AbuseStatus": {"standing", "verified", "actions"},
		"AbuseStatusAction": {
			"action_id", "case_id", "category", "kind", "target", "review_state", "create_time_ms", "until_time_ms",
		},
	}
	// what a hold, a bar or a seal is made of (§21.9's hold row, §21.8's notice), and the words a
	// stray copy of one would carry
	forbiddenWords := []string{
		"hold", "held", "bar", "seal", "legal", "preserv", "2703", "2258", "counsel", "nondisclosure",
		"copied", "scope", "expire", "order", "request", "production", "reporter", "join",
	}

	typeJsonNames := map[string][]string{}
	var walk func(valueType reflect.Type)
	walk = func(valueType reflect.Type) {
		switch valueType.Kind() {
		case reflect.Pointer, reflect.Slice:
			if valueType.Kind() == reflect.Slice && valueType.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s holds raw bytes", valueType)
				return
			}
			walk(valueType.Elem())
			return
		case reflect.Map, reflect.Interface:
			t.Errorf("%s may hold any key", valueType)
			return
		case reflect.Struct:
		default:
			// a string, a bool, a number or Id's fixed 16 bytes
			return
		}
		if _, ok := typeJsonNames[valueType.Name()]; ok {
			return
		}
		typeJsonNames[valueType.Name()] = []string{}
		for i := 0; i < valueType.NumField(); i += 1 {
			field := valueType.Field(i)
			jsonName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if jsonName == "" || jsonName == "-" {
				t.Errorf("%s.%s has no wire name", valueType.Name(), field.Name)
			}
			typeJsonNames[valueType.Name()] = append(typeJsonNames[valueType.Name()], jsonName)
			for _, name := range []string{field.Name, jsonName, field.Type.String()} {
				for _, word := range forbiddenWords {
					if strings.Contains(strings.ToLower(name), word) {
						t.Errorf("%s.%s names %q", valueType.Name(), field.Name, word)
					}
				}
			}
			walk(field.Type)
		}
	}
	walk(reflect.TypeOf(AbuseStatus{}))

	if len(typeJsonNames) != len(wantTypeJsonNames) {
		t.Errorf("types %v, want %v", typeJsonNames, wantTypeJsonNames)
	}
	for typeName, wantJsonNames := range wantTypeJsonNames {
		if jsonNames := typeJsonNames[typeName]; !slices.Equal(jsonNames, wantJsonNames) {
			t.Errorf("%s's fields %q, want %q", typeName, jsonNames, wantJsonNames)
		}
	}
}

// §21.7's five states, and nothing else, so a gate refuses whatever a later build adds.
func TestAbuseStandingKnowsOnlyTheFiveStates(t *testing.T) {
	for _, standing := range []AbuseStanding{
		AbuseStandingProbation, AbuseStandingStandard, AbuseStandingTrusted, AbuseStandingRestricted, AbuseStandingSuspended,
	} {
		if !standing.Known() {
			t.Errorf("%q unknown", standing)
		}
	}
	for _, standing := range []AbuseStanding{"", "Probation", "suspended ", "frozen"} {
		if standing.Known() {
			t.Errorf("%q known", standing)
		}
	}
}

// A sidecar asks with its own client token, a bearer and no proof, and reads the body as api wrote it.
func TestSidecarApiReadsAbuseStatus(t *testing.T) {
	transport := answerWith(200, testAbuseStatusJson)
	api := newTestSidecarApi(t, transport)

	status, err := api.AbuseStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := testAbuseStatus(t); !reflect.DeepEqual(status, want) {
		t.Errorf("%+v, want %+v", status, want)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != http.MethodGet || request.URL.String() != "https://api.example/abuse/status" {
		t.Errorf("%s %s", request.Method, request.URL)
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt || request.Header.Get("DPoP") != "" || len(body) != 0 {
		t.Errorf("headers %v, body %q", request.Header, body)
	}
}

// A network with no action reads an empty list, whether api left it out, sent null or sent [].
func TestSidecarApiReadsAbuseStatusWithNoActions(t *testing.T) {
	for _, answer := range []string{
		`{"standing":"standard","verified":true}`,
		`{"standing":"standard","verified":true,"actions":null}`,
		`{"standing":"standard","verified":true,"actions":[]}`,
	} {
		api := newTestSidecarApi(t, answerWith(200, answer))
		status, err := api.AbuseStatus(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", answer, err)
		}
		want := &AbuseStatus{Standing: AbuseStandingStandard, Verified: true, Actions: []*AbuseStatusAction{}}
		if !reflect.DeepEqual(status, want) {
			t.Errorf("%s: %+v", answer, status)
		}
	}
}

// A standing this build does not know comes back as sent, and Known says so, so the caller decides.
func TestSidecarApiPassesOnAnUnknownStanding(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(200, `{"standing":"frozen","verified":false,"actions":[]}`))
	status, err := api.AbuseStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Standing != "frozen" || status.Standing.Known() {
		t.Errorf("standing %q", status.Standing)
	}
}

// An answer that is not the route's is refused whole, never read in part.
func TestSidecarApiRefusesAnAbuseStatusNotTheRoutes(t *testing.T) {
	for _, answer := range []string{
		``,
		`null`,
		`[]`,
		`{"standing":"","verified":true,"actions":[]}`,
		`{"verified":true,"actions":[]}`,
		`{"standing":7,"verified":true,"actions":[]}`,
		`{"standing":"standard","verified":"yes","actions":[]}`,
		`{"standing":"standard","verified":true,"actions":{}}`,
		`{"standing":"standard","verified":true,"actions":[null]}`,
		// no id, no case, no kind, an id that is no id
		`{"standing":"standard","verified":true,"actions":[{"case_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a50","kind":"host_kill"}]}`,
		`{"standing":"standard","verified":true,"actions":[{"action_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a51","kind":"host_kill"}]}`,
		`{"standing":"standard","verified":true,"actions":[{"action_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a51","case_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a50"}]}`,
		`{"standing":"standard","verified":true,"actions":[{"action_id":"x","case_id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a50","kind":"host_kill"}]}`,
	} {
		api := newTestSidecarApi(t, answerWith(200, answer))
		status, err := api.AbuseStatus(context.Background())
		if !errors.Is(err, ErrSidecarApiReply) || status != nil {
			t.Errorf("%s: %+v, %v", answer, status, err)
		}
	}
}

// A refusal carries the route, its status and its code, and no text of the server's.
func TestSidecarApiAbuseStatusRefusal(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(403, `{"error":"A sidecar token cannot call this route.","code":"sidecar_token_refused"}`))
	status, err := api.AbuseStatus(context.Background())
	if status != nil {
		t.Errorf("status %+v", status)
	}
	apiErr := asSidecarApiError(t, err)
	if apiErr.Route != "GET /abuse/status" || apiErr.Status != 403 || apiErr.Code != "sidecar_token_refused" {
		t.Errorf("%+v", apiErr)
	}
	if strings.Contains(err.Error(), "cannot call") {
		t.Errorf("the server's text reached the error: %v", err)
	}
}

// Without a token nothing is sent.
func TestSidecarApiAbuseStatusNeedsAToken(t *testing.T) {
	transport := answerWith(200, testAbuseStatusJson)
	api := newTestSidecarApi(t, transport)
	api.SetByJwt("")
	if _, err := api.AbuseStatus(context.Background()); !errors.Is(err, ErrSidecarApiNoToken) {
		t.Errorf("err %v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
}
