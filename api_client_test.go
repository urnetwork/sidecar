package sidecar

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// An api in this process: each request is recorded with its body, then answered by answer. Runs on
// every leg, since it opens nothing.
type scriptedApiTransport struct {
	stateLock sync.Mutex
	requests  []*http.Request
	bodies    [][]byte
	answer    func(request *http.Request, body []byte) (*http.Response, error)
}

func (self *scriptedApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request)
		self.bodies = append(self.bodies, body)
	}()
	return self.answer(request, body)
}

func (self *scriptedApiTransport) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The one request it saw, and its body.
func (self *scriptedApiTransport) onlyRequest(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.requests) != 1 {
		t.Fatalf("%d requests", len(self.requests))
	}
	return self.requests[0], self.bodies[0]
}

// Answers every request with status and body.
func answerWith(status int, body string) *scriptedApiTransport {
	return &scriptedApiTransport{
		answer: func(request *http.Request, requestBody []byte) (*http.Response, error) {
			return syntheticResponse(request, status, body, nil), nil
		},
	}
}

func syntheticResponse(request *http.Request, status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

const testByJwt = "synthetic-client-jwt-canary"

// The instant every test api's clock reads, so a Retry-After date asks for one wait.
var testApiNow = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

func testApiClock() time.Time {
	return testApiNow
}

// A client of the scripted api, with validSidecarSettings's urls and testByJwt installed.
func newTestSidecarApi(t *testing.T, transport http.RoundTripper) *SidecarApi {
	t.Helper()
	api, err := newSidecarApi(validSidecarSettings(), transport, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	return api
}

var testDpopNow = time.Unix(1767225600, 0)

// Installs a signer on a synthetic ClientKey and returns its public key.
func installTestDpopSigner(t *testing.T, api *SidecarApi) ed25519.PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	signer, err := newDpopSigner(seed, func() time.Time { return testDpopNow }, api.currentApiClockOffset, cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api.setDpopSigner(signer)
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

// The request's one DPoP proof, verified by publicKey, for method and requestUrl over token.
func checkTestDpopHeader(t *testing.T, request *http.Request, publicKey ed25519.PublicKey, method string, requestUrl string, token string) {
	t.Helper()
	proofs := request.Header.Values("DPoP")
	if len(proofs) != 1 {
		t.Fatalf("%d proofs", len(proofs))
	}
	claims := verifyTestDpopProof(t, proofs[0], publicKey)
	if claims.Htm != method || claims.Htu != requestUrl || claims.Ath != dpopAth(token) || claims.Iat != testDpopNow.Unix() {
		t.Errorf("claims %+v", claims)
	}
}

func asSidecarApiError(t *testing.T, err error) *SidecarApiError {
	t.Helper()
	apiErr := &SidecarApiError{}
	if !errors.As(err, &apiErr) {
		t.Fatalf("err %v is not a SidecarApiError", err)
	}
	return apiErr
}

func TestNewSidecarApiRefusesInvalidSettings(t *testing.T) {
	settings := validSidecarSettings()
	settings.ApiUrl = ""
	if _, err := newSidecarApi(settings, answerWith(200, "{}"), testApiClock); !errors.Is(err, errInvalidSettings) {
		t.Errorf("err %v", err)
	}
	if _, err := newSidecarApi(nil, answerWith(200, "{}"), testApiClock); !errors.Is(err, errInvalidSettings) {
		t.Errorf("err %v", err)
	}
}

// §7.4's trap: a strict_exp refresh with no signer is not sent at all, which leaves the sidecar
// unenrolled, never proofless.
func TestRefreshNotSentWithoutSigner(t *testing.T) {
	transport := answerWith(200, `{"by_jwt":"synthetic-new-jwt"}`)
	api := newTestSidecarApi(t, transport)

	byJwt, err := api.Refresh(context.Background())
	if !errors.Is(err, ErrSidecarApiNoDpopSigner) || byJwt != "" {
		t.Errorf("%q, %v", byJwt, err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests left without a proof", count)
	}

	// a signer removed again is the same
	installTestDpopSigner(t, api)
	api.setDpopSigner(nil)
	if _, err := api.Refresh(context.Background()); !errors.Is(err, ErrSidecarApiNoDpopSigner) {
		t.Errorf("err %v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests left without a proof", count)
	}
}

func TestCallsPresentingATokenAreNotSentWithoutOne(t *testing.T) {
	transport := answerWith(200, `{}`)
	api, err := newSidecarApi(validSidecarSettings(), transport, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	installTestDpopSigner(t, api)
	ctx := context.Background()
	checks := []error{}
	_, err = api.Refresh(ctx)
	checks = append(checks, err)
	_, err = api.Bind(ctx, []byte("synthetic-binding"))
	checks = append(checks, err)
	_, err = api.ExchangeToken(ctx, "https://evs.example", []string{"repo:synthetic:r"})
	checks = append(checks, err)
	_, err = api.AuthClient(ctx, &SidecarAuthClientArgs{})
	checks = append(checks, err)
	checks = append(checks, api.RemoveClient(ctx, NewId()))
	_, err = api.GetIdentity(ctx, NewId(), 0)
	checks = append(checks, err)
	for i, err := range checks {
		if !errors.Is(err, ErrSidecarApiNoToken) {
			t.Errorf("call %d: %v", i, err)
		}
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
}

func TestRefreshCarriesItsBearerAndProof(t *testing.T) {
	transport := answerWith(200, `{"by_jwt":"synthetic-new-jwt"}`)
	api := newTestSidecarApi(t, transport)
	publicKey := installTestDpopSigner(t, api)

	byJwt, err := api.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if byJwt != "synthetic-new-jwt" {
		t.Errorf("by_jwt %q", byJwt)
	}
	// the token manager installs it after persisting it, never Refresh
	if current := api.currentByJwt(); current != testByJwt {
		t.Errorf("Refresh installed %q", current)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "GET" || request.URL.String() != "https://api.example/auth/refresh" || len(body) != 0 {
		t.Errorf("%s %s %q", request.Method, request.URL, body)
	}
	if authorization := request.Header.Get("Authorization"); authorization != "Bearer "+testByJwt {
		t.Errorf("authorization %q", authorization)
	}
	checkTestDpopHeader(t, request, publicKey, "GET", "https://api.example/auth/refresh", testByJwt)
}

// A refusal comes back as what the token manager maps (§18.5): a 200's error object with its code,
// restore_required included, and a 401 with or without session_revoked.
func TestRefreshRefusalsCarryTheirCodes(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		header http.Header
		code   string
	}{
		{status: 200, body: `{"error":{"message":"Synthetic text.","code":"restore_required"}}`, code: SidecarApiCodeRestoreRequired},
		{status: 200, body: `{"error":{"message":"Client does not exist"}}`, code: ""},
		{status: 401, body: `{"error":"Session request could not be completed.","code":"session_revoked"}`, code: SidecarApiCodeSessionRevoked},
		{status: 401, body: "Not authorized.\n", header: http.Header{"Content-Type": {"text/plain"}}, code: ""},
		{status: 403, body: "A sidecar token needs a proof of its client key on this route.\n", header: http.Header{"Content-Type": {"text/plain"}}, code: ""},
	} {
		transport := &scriptedApiTransport{
			answer: func(request *http.Request, body []byte) (*http.Response, error) {
				return syntheticResponse(request, c.status, c.body, c.header), nil
			},
		}
		api := newTestSidecarApi(t, transport)
		installTestDpopSigner(t, api)
		byJwt, err := api.Refresh(context.Background())
		if byJwt != "" {
			t.Errorf("%s: by_jwt %q", c.body, byJwt)
		}
		apiErr := asSidecarApiError(t, err)
		if apiErr.Status != c.status || apiErr.Code != c.code || apiErr.Route != "GET /auth/refresh" {
			t.Errorf("%s: %+v", c.body, apiErr)
		}
	}
}

func TestRefreshRefusesAReplyWithNoToken(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(200, `{}`))
	installTestDpopSigner(t, api)
	if _, err := api.Refresh(context.Background()); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("err %v", err)
	}
}

func testEnrollArgs() *SidecarEnrollArgs {
	return &SidecarEnrollArgs{
		AuthKey:          "synthetic01-synthetic02",
		ClientPublicKey:  make([]byte, ed25519.PublicKeySize),
		DeviceSpec:       "ur synthetic/0",
		DeclaresNoEgress: true,
	}
}

// §7.8's guard: a key's client-only bundle never leaves, whichever field it rides in, and a urn_ API
// key is not an auth key.
func TestEnrollRefusesBundle(t *testing.T) {
	bundled := testEnrollArgs()
	bundled.AuthKey = "synthetic01-synthetic02#c3ludGhldGljLWJ1bmRsZQ"
	full := testEnrollArgs()
	full.AuthKey = "ur-authkey-synthetic01-synthetic02#c3ludGhldGljLWJ1bmRsZQ"
	inSpec := testEnrollArgs()
	inSpec.DeviceSpec = "ur synthetic/0 #c3ludGhldGljLWJ1bmRsZQ"
	urn := testEnrollArgs()
	urn.AuthKey = "urn_synthetic"

	transport := answerWith(200, `{"by_client_jwt":"synthetic-jwt","client_id":"`+NewId().String()+`","approval_state":"approved","admin_refused":true}`)
	api := newTestSidecarApi(t, transport)
	for _, args := range []*SidecarEnrollArgs{bundled, full, inSpec, urn} {
		result, err := api.Enroll(context.Background(), args)
		if !errors.Is(err, ErrSidecarApiBundle) || result != nil {
			t.Errorf("%q: %v", args.AuthKey, err)
		}
		if strings.Contains(err.Error(), "synthetic") {
			t.Errorf("the error repeats the key: %v", err)
		}
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests left with a bundle", count)
	}
}

func TestEnrollRefusesArgsItCannotSend(t *testing.T) {
	noKey := testEnrollArgs()
	noKey.AuthKey = ""
	noSpec := testEnrollArgs()
	noSpec.DeviceSpec = ""
	shortKey := testEnrollArgs()
	shortKey.ClientPublicKey = make([]byte, 31)

	transport := answerWith(200, `{}`)
	api := newTestSidecarApi(t, transport)
	for _, args := range []*SidecarEnrollArgs{nil, noKey, noSpec, shortKey} {
		if _, err := api.Enroll(context.Background(), args); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("err %v", err)
		}
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
}

// Enrollment is Public: it presents no token and no proof, even with both installed, and always
// carries §7.4's marks.
func TestEnrollSendsTheMarksAndNoToken(t *testing.T) {
	clientId := NewId()
	transport := answerWith(200, `{"by_client_jwt":"synthetic-new-jwt","client_id":"`+clientId.String()+`","approval_state":"pending","admin_refused":true,"close":"synthetic-close"}`)
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)
	args := testEnrollArgs()
	for i := range args.ClientPublicKey {
		args.ClientPublicKey[i] = byte(i)
	}

	result, err := api.Enroll(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	if result.ByClientJwt != "synthetic-new-jwt" || result.ClientId != clientId || result.ApprovalState != "pending" ||
		!result.AdminRefused || result.Close != "synthetic-close" {
		t.Errorf("result %+v", *result)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != "https://api.example/network/enroll" {
		t.Errorf("%s %s", request.Method, request.URL)
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("DPoP") != "" {
		t.Error("enrollment presented a token or a proof")
	}
	if contentType := request.Header.Get("Content-Type"); contentType != "application/json" {
		t.Errorf("content type %q", contentType)
	}
	sent := map[string]any{}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"auth_key":           "synthetic01-synthetic02",
		"client_public_key":  base64.StdEncoding.EncodeToString(args.ClientPublicKey),
		"device_spec":        "ur synthetic/0",
		"declares_no_egress": true,
		"admin_refused":      true,
		"strict_exp":         true,
	}
	if fmt.Sprint(sent) != fmt.Sprint(want) {
		t.Errorf("body %s", body)
	}
}

// The caller persists nothing unless api confirms admin_refused (D-CORE-7), so an answer without the
// mark must read as without it.
func TestEnrollReportsAnUnconfirmedMark(t *testing.T) {
	transport := answerWith(200, `{"by_client_jwt":"synthetic-new-jwt","client_id":"`+NewId().String()+`","approval_state":"approved"}`)
	api := newTestSidecarApi(t, transport)
	result, err := api.Enroll(context.Background(), testEnrollArgs())
	if err != nil {
		t.Fatal(err)
	}
	if result.AdminRefused {
		t.Error("admin_refused read as confirmed")
	}
}

func TestEnrollRefusesAReplyWithoutAClient(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"by_client_jwt":"synthetic-new-jwt"}`,
		`{"by_client_jwt":"synthetic-new-jwt","client_id":null}`,
		`{"client_id":"` + NewId().String() + `"}`,
		`not json`,
	} {
		api := newTestSidecarApi(t, answerWith(200, body))
		if _, err := api.Enroll(context.Background(), testEnrollArgs()); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// A preview or no_genesis refusal surfaces as its code, for `ur` to print.
func TestEnrollRefusalCarriesItsCode(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(403, `{"error":"Synthetic refusal.","code":"no_genesis"}`))
	_, err := api.Enroll(context.Background(), testEnrollArgs())
	if apiErr := asSidecarApiError(t, err); apiErr.Status != 403 || apiErr.Code != "no_genesis" {
		t.Errorf("%+v", apiErr)
	}
}

func TestAuthClientCarriesItsProofAndMarks(t *testing.T) {
	clientId := NewId()
	sourceClientId := NewId()
	transport := answerWith(200, `{"by_client_jwt":"synthetic-child-jwt","client_id":"`+clientId.String()+`","admin_refused":true,"strict_exp":true}`)
	api := newTestSidecarApi(t, transport)
	publicKey := installTestDpopSigner(t, api)

	result, err := api.AuthClient(context.Background(), &SidecarAuthClientArgs{
		SourceClientId:   &sourceClientId,
		Description:      "synthetic window",
		DeviceSpec:       "ur synthetic/0",
		DeclaresNoEgress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ByClientJwt != "synthetic-child-jwt" || result.ClientId != clientId || !result.AdminRefused || !result.StrictExp {
		t.Errorf("result %+v", *result)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != "https://api.example/network/auth-client" {
		t.Errorf("%s %s", request.Method, request.URL)
	}
	if authorization := request.Header.Get("Authorization"); authorization != "Bearer "+testByJwt {
		t.Errorf("authorization %q", authorization)
	}
	checkTestDpopHeader(t, request, publicKey, "POST", "https://api.example/network/auth-client", testByJwt)
	sent := map[string]any{}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["source_client_id"] != sourceClientId.String() || sent["admin_refused"] != true || sent["strict_exp"] != true ||
		sent["declares_no_egress"] != true {
		t.Errorf("body %s", body)
	}
	if _, ok := sent["client_id"]; ok {
		t.Errorf("a new client's mint named a client: %s", body)
	}
}

// A strict_exp bearer mints only with a proof (§7.4), so without a signer nothing is sent.
func TestAuthClientNotSentWithoutSigner(t *testing.T) {
	transport := answerWith(200, `{"by_client_jwt":"synthetic-child-jwt"}`)
	api := newTestSidecarApi(t, transport)
	if _, err := api.AuthClient(context.Background(), &SidecarAuthClientArgs{}); !errors.Is(err, ErrSidecarApiNoDpopSigner) {
		t.Errorf("err %v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
}

func TestAuthClientLimitIsARefusal(t *testing.T) {
	for _, c := range []struct {
		body string
		code string
	}{
		{body: `{"error":{"client_limit_exceeded":true,"upgrade_required":true,"message":"Synthetic."}}`, code: "upgrade_required"},
		{body: `{"error":{"client_limit_exceeded":true,"message":"Synthetic."}}`, code: "client_limit_exceeded"},
		{body: `{"error":{"message":"Client does not exist."}}`, code: ""},
	} {
		api := newTestSidecarApi(t, answerWith(200, c.body))
		installTestDpopSigner(t, api)
		_, err := api.AuthClient(context.Background(), &SidecarAuthClientArgs{})
		if apiErr := asSidecarApiError(t, err); apiErr.Status != 200 || apiErr.Code != c.code {
			t.Errorf("%s: %+v", c.body, apiErr)
		}
	}
}

func TestRemoveClientPostsItsClient(t *testing.T) {
	clientId := NewId()
	transport := answerWith(200, `{}`)
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)

	if err := api.RemoveClient(context.Background(), clientId); err != nil {
		t.Fatal(err)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != "https://api.example/network/remove-client" ||
		string(body) != `{"client_id":"`+clientId.String()+`"}` {
		t.Errorf("%s %s %s", request.Method, request.URL, body)
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt || request.Header.Get("DPoP") != "" {
		t.Error("remove-client presents its bearer and no proof")
	}

	refused := newTestSidecarApi(t, answerWith(200, `{"error":{"message":"Synthetic."}}`))
	if apiErr := asSidecarApiError(t, refused.RemoveClient(context.Background(), clientId)); apiErr.Status != 200 {
		t.Errorf("%+v", apiErr)
	}
	if err := refused.RemoveClient(context.Background(), Id{}); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("err %v", err)
	}
}

// Bind posts the wrapper's bytes in base64 under its bearer and takes no proof
// (plan-CORE-binding-wire #6).
func TestBindPostsTheWrapper(t *testing.T) {
	binding := []byte("synthetic\x00binding\xffbytes")
	transport := answerWith(200, `{"generation":3}`)
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)

	generation, err := api.Bind(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 3 {
		t.Errorf("generation %d", generation)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != "https://api.example/sidecar/bind" {
		t.Errorf("%s %s", request.Method, request.URL)
	}
	if string(body) != `{"binding":"`+base64.StdEncoding.EncodeToString(binding)+`"}` {
		t.Errorf("body %s", body)
	}
	if request.Header.Get("Authorization") != "Bearer "+testByJwt || request.Header.Get("DPoP") != "" {
		t.Error("bind presents its bearer and no proof")
	}
}

func TestBindRefusalsCarryTheirCodes(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
	}{
		{status: 403, code: SidecarApiCodeSidecarRevoked},
		{status: 400, code: SidecarApiCodeBindingInvalid},
		{status: 409, code: SidecarApiCodeGenerationConflict},
		{status: 409, code: SidecarApiCodeClientBound},
	} {
		api := newTestSidecarApi(t, answerWith(c.status, `{"error":"Synthetic text.","code":"`+c.code+`"}`))
		_, err := api.Bind(context.Background(), []byte("synthetic-binding"))
		if apiErr := asSidecarApiError(t, err); apiErr.Status != c.status || apiErr.Code != c.code || apiErr.Route != "POST /sidecar/bind" {
			t.Errorf("%+v", apiErr)
		}
	}
	for _, body := range []string{`{}`, `{"generation":0}`, `{"generation":-1}`} {
		api := newTestSidecarApi(t, answerWith(200, body))
		if _, err := api.Bind(context.Background(), []byte("synthetic-binding")); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v", body, err)
		}
	}
}

func TestGetIdentityReadsItsRecord(t *testing.T) {
	sidecarId := NewId()
	key := make([]byte, ed25519.PublicKeySize)
	reply := map[string]any{
		"identity_public_key": base64.StdEncoding.EncodeToString(key),
		"identity_alg":        "ed25519",
		"status":              "active",
		"binding":             base64.StdEncoding.EncodeToString([]byte("synthetic-binding-3")),
		"bindings": []string{
			base64.StdEncoding.EncodeToString([]byte("synthetic-binding-3")),
			base64.StdEncoding.EncodeToString([]byte("synthetic-binding-2")),
		},
	}
	replyBytes, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	transport := answerWith(200, string(replyBytes))
	api := newTestSidecarApi(t, transport)

	record, err := api.GetIdentity(context.Background(), sidecarId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if record.SidecarId != sidecarId || record.IdentityAlg != "ed25519" || record.Status != "active" ||
		string(record.Binding) != "synthetic-binding-3" || len(record.Bindings) != 2 || string(record.Bindings[1]) != "synthetic-binding-2" {
		t.Errorf("record %+v", record)
	}
	if _, err := api.GetIdentity(context.Background(), sidecarId, 3); err != nil {
		t.Fatal(err)
	}
	transport.stateLock.Lock()
	urls := []string{transport.requests[0].URL.String(), transport.requests[1].URL.String()}
	transport.stateLock.Unlock()
	want := []string{
		"https://api.example/sidecar/identity/" + sidecarId.String(),
		"https://api.example/sidecar/identity/" + sidecarId.String() + "?before_generation=3",
	}
	if !slices.Equal(urls, want) {
		t.Errorf("urls %q", urls)
	}
}

// api is untrusted: an answer about another sidecar, or with no key or status, is not taken.
func TestGetIdentityRefusesAnotherSidecarsAnswer(t *testing.T) {
	for _, body := range []string{
		`{"sidecar_id":"` + NewId().String() + `","identity_public_key":"AAAA","identity_alg":"ed25519","status":"active"}`,
		`{"identity_alg":"ed25519","status":"active"}`,
		`{"identity_public_key":"AAAA","identity_alg":"ed25519"}`,
	} {
		api := newTestSidecarApi(t, answerWith(200, body))
		if _, err := api.GetIdentity(context.Background(), NewId(), 0); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v", body, err)
		}
	}
	api := newTestSidecarApi(t, answerWith(200, `{}`))
	if _, err := api.GetIdentity(context.Background(), Id{}, 0); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("err %v", err)
	}
	if _, err := api.GetIdentity(context.Background(), NewId(), -1); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("err %v", err)
	}
}

func TestGetIdentityByClientNamesItsSidecar(t *testing.T) {
	clientId := NewId()
	sidecarId := NewId()
	transport := answerWith(200, `{"sidecar_id":"`+sidecarId.String()+`","identity_public_key":"AAAA","identity_alg":"ed25519","status":"active","binding":"AAAA","bindings":["AAAA"]}`)
	api := newTestSidecarApi(t, transport)

	record, err := api.GetIdentityByClient(context.Background(), clientId)
	if err != nil {
		t.Fatal(err)
	}
	if record.SidecarId != sidecarId || len(record.Bindings) != 0 {
		t.Errorf("record %+v", record)
	}
	request, _ := transport.onlyRequest(t)
	if request.URL.String() != "https://api.example/sidecar/identity?client_id="+clientId.String() {
		t.Errorf("url %s", request.URL)
	}

	missing := newTestSidecarApi(t, answerWith(404, `{"error":"Synthetic.","code":"not_found"}`))
	_, err = missing.GetIdentityByClient(context.Background(), clientId)
	if apiErr := asSidecarApiError(t, err); apiErr.Status != 404 {
		t.Errorf("%+v", apiErr)
	}
	unnamed := newTestSidecarApi(t, answerWith(200, `{"identity_public_key":"AAAA","identity_alg":"ed25519","status":"active"}`))
	if _, err := unnamed.GetIdentityByClient(context.Background(), clientId); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("err %v", err)
	}
}

// §7.8's exchange: form-encoded to AuthUrl, the jwt as subject token and nowhere else, and a proof
// over it.
func TestExchangeTokenPostsItsFormAndProof(t *testing.T) {
	transport := answerWith(200, `{"access_token":"synthetic-service-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"N_A","expires_in":900,"scope":"repo:synthetic-1:r repo:synthetic-2:rw"}`)
	api := newTestSidecarApi(t, transport)
	publicKey := installTestDpopSigner(t, api)

	token, err := api.ExchangeToken(context.Background(), "https://evs.example", []string{"repo:synthetic-1:r", "repo:synthetic-2:rw"})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "synthetic-service-token" || token.ExpiresIn != 15*time.Minute ||
		!slices.Equal(token.Scopes, []string{"repo:synthetic-1:r", "repo:synthetic-2:rw"}) || token.TokenType != "N_A" {
		t.Errorf("token %+v", *token)
	}
	request, body := transport.onlyRequest(t)
	if request.Method != "POST" || request.URL.String() != "https://auth.example/oauth/token" {
		t.Errorf("%s %s", request.Method, request.URL)
	}
	if contentType := request.Header.Get("Content-Type"); contentType != "application/x-www-form-urlencoded" {
		t.Errorf("content type %q", contentType)
	}
	if request.Header.Get("Authorization") != "" {
		t.Error("the exchange presented a bearer")
	}
	checkTestDpopHeader(t, request, publicKey, "POST", "https://auth.example/oauth/token", testByJwt)
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {testByJwt},
		"subject_token_type": {"urn:ur:params:oauth:token-type:client-jwt"},
		"resource":           {"https://evs.example"},
		"scope":              {"repo:synthetic-1:r repo:synthetic-2:rw"},
	}
	if form.Encode() != want.Encode() {
		t.Errorf("form %s", body)
	}
}

// The body's subject token and the proof's ath are of one token, even when SetByJwt races the call.
func TestExchangeSubjectTokenIsTheOneItsProofHashes(t *testing.T) {
	var api *SidecarApi
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			// a refresh landing while this request is in flight
			api.SetByJwt("synthetic-later-jwt")
			return syntheticResponse(request, 200, `{"access_token":"synthetic-service-token","expires_in":900}`, nil), nil
		},
	}
	api = newTestSidecarApi(t, transport)
	publicKey := installTestDpopSigner(t, api)

	if _, err := api.ExchangeToken(context.Background(), "https://gkm.example", nil); err != nil {
		t.Fatal(err)
	}
	request, body := transport.onlyRequest(t)
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("subject_token") != testByJwt || form.Has("scope") {
		t.Errorf("form %s", body)
	}
	checkTestDpopHeader(t, request, publicKey, "POST", "https://auth.example/oauth/token", testByJwt)
	if api.currentByJwt() != "synthetic-later-jwt" {
		t.Error("the racing token was not installed")
	}
}

// At most 64 repo: scopes an exchange (§7.8): one more is refused before sending, and the caller
// splits.
func TestExchangeRefusesPastSixtyFourRepoScopes(t *testing.T) {
	transport := answerWith(200, `{"access_token":"synthetic-service-token","expires_in":900}`)
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)
	scopes := []string{"recovery:synthetic-member"}
	for i := 0; i < 64; i += 1 {
		scopes = append(scopes, fmt.Sprintf("repo:synthetic-%d:r", i))
	}

	if _, err := api.ExchangeToken(context.Background(), "https://evs.example", scopes); err != nil {
		t.Fatal(err)
	}
	scopes = append(scopes, "repo:synthetic-64:r")
	if _, err := api.ExchangeToken(context.Background(), "https://evs.example", scopes); !errors.Is(err, ErrSidecarApiArgs) {
		t.Errorf("err %v", err)
	}
	if count := transport.requestCount(); count != 1 {
		t.Errorf("%d requests", count)
	}
}

func TestExchangeRefusesWhatItCannotAskFor(t *testing.T) {
	transport := answerWith(200, `{"access_token":"synthetic-service-token","expires_in":900}`)
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)
	for _, c := range []struct {
		resource string
		scopes   []string
	}{
		// the api audience is never issued
		{resource: "https://api.example"},
		{resource: ""},
		{resource: "evs.example"},
		{resource: "https://evs.example#fragment"},
		{resource: "https://evs.example?a=1"},
		{resource: "https://synthetic-user@evs.example"},
		{resource: "https://evs.example", scopes: []string{""}},
		{resource: "https://evs.example", scopes: []string{"repo:a:r repo:b:r"}},
		{resource: "https://evs.example", scopes: []string{"repo:\"a\":r"}},
	} {
		if _, err := api.ExchangeToken(context.Background(), c.resource, c.scopes); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("%q %q: %v", c.resource, c.scopes, err)
		}
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
	unsigned := newTestSidecarApi(t, transport)
	if _, err := unsigned.ExchangeToken(context.Background(), "https://evs.example", nil); !errors.Is(err, ErrSidecarApiNoDpopSigner) {
		t.Errorf("err %v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
}

// RFC 6749's error envelope gives the code.
func TestExchangeRefusalCarriesItsCode(t *testing.T) {
	for _, c := range []struct {
		body string
		code string
	}{
		{body: `{"error":"invalid_grant","error_description":"Synthetic description."}`, code: "invalid_grant"},
		{body: `{"error":"restore_required"}`, code: SidecarApiCodeRestoreRequired},
	} {
		api := newTestSidecarApi(t, answerWith(400, c.body))
		installTestDpopSigner(t, api)
		_, err := api.ExchangeToken(context.Background(), "https://evs.example", nil)
		if apiErr := asSidecarApiError(t, err); apiErr.Status != 400 || apiErr.Code != c.code || apiErr.Route != "POST /oauth/token" {
			t.Errorf("%s: %+v", c.body, apiErr)
		}
	}
	for _, body := range []string{`{}`, `{"access_token":"synthetic","expires_in":-1}`, `{"access_token":"synthetic","expires_in":9300000000000}`} {
		api := newTestSidecarApi(t, answerWith(200, body))
		installTestDpopSigner(t, api)
		if _, err := api.ExchangeToken(context.Background(), "https://evs.example", nil); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// Every line a test logger receives, at every level.
type capturingApiLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *capturingApiLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *capturingApiLogger) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *capturingApiLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *capturingApiLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *capturingApiLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *capturingApiLogger) V(level int32) Verbose {
	return capturingApiVerbose{log: self}
}

// Every level enabled, so a guarded line is captured too.
type capturingApiVerbose struct {
	log *capturingApiLogger
}

func (self capturingApiVerbose) Enabled() bool {
	return true
}

func (self capturingApiVerbose) Info(args ...any) {
	self.log.add(fmt.Sprint(args...))
}

func (self capturingApiVerbose) Infof(format string, args ...any) {
	self.log.add(fmt.Sprintf(format, args...))
}

// I-7: a fake 500 that echoes everything it was sent leaves no token, proof, key or body in an error
// or a log.
func TestErrorsAndLogsFromAFake500HoldNoToken(t *testing.T) {
	log := &capturingApiLogger{}
	settings := validSidecarSettings()
	settings.Log = log
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			echo := request.Header.Get("Authorization") + " " + request.Header.Get("DPoP") + " " + string(body) + " " + request.URL.String()
			return syntheticResponse(request, 500, `{"error":"`+echo+`","detail":"`+echo+`"}`, http.Header{"X-Echo": {echo}}), nil
		},
	}
	api, err := newSidecarApi(settings, transport, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	installTestDpopSigner(t, api)
	ctx := context.Background()

	errs := []error{}
	_, err = api.Refresh(ctx)
	errs = append(errs, err)
	_, err = api.Enroll(ctx, testEnrollArgs())
	errs = append(errs, err)
	_, err = api.ExchangeToken(ctx, "https://evs.example", []string{"repo:synthetic:r"})
	errs = append(errs, err)
	_, err = api.Bind(ctx, []byte("synthetic-binding-canary"))
	errs = append(errs, err)
	_, err = api.AuthClient(ctx, &SidecarAuthClientArgs{Description: "synthetic-description-canary"})
	errs = append(errs, err)
	sidecarId := NewId()
	_, err = api.GetIdentity(ctx, sidecarId, 0)
	errs = append(errs, err)

	canaries := []string{testByJwt, "synthetic01-synthetic02", "eyJ", "binding-canary", "description-canary", "api.example", sidecarId.String()}
	for _, err := range errs {
		apiErr := asSidecarApiError(t, err)
		if apiErr.Status != 500 || apiErr.Code != "" {
			t.Errorf("%+v", apiErr)
		}
		for _, text := range []string{err.Error(), fmt.Sprintf("%v %+v %#v", err, err, err)} {
			for _, canary := range canaries {
				if strings.Contains(text, canary) {
					t.Errorf("an error holds %q: %s", canary, text)
				}
			}
		}
	}
	log.stateLock.Lock()
	defer log.stateLock.Unlock()
	if len(log.lines) == 0 {
		t.Fatal("nothing logged, so nothing was checked")
	}
	for _, line := range log.lines {
		for _, canary := range canaries {
			if strings.Contains(line, canary) {
				t.Errorf("a log line holds %q: %s", canary, line)
			}
		}
	}
}

// Failing before any answer, as a dead network does.
type failingApiTransport struct{}

func (self failingApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		request.Body.Close()
	}
	return nil, errors.New("synthetic dial failure")
}

// A failure before any answer is the transport's, named by the route, without the url net/http puts
// on it, and is not a SidecarApiError, so the caller retries it as a network error.
func TestTransportFailureHoldsNoUrl(t *testing.T) {
	sidecarId := NewId()
	api := newTestSidecarApi(t, failingApiTransport{})
	_, err := api.GetIdentity(context.Background(), sidecarId, 0)
	if err == nil || !strings.Contains(err.Error(), "synthetic dial failure") || !strings.Contains(err.Error(), "GET /sidecar/identity/<sidecar_id>") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), sidecarId.String()) || strings.Contains(err.Error(), "api.example") {
		t.Errorf("the error repeats the url: %v", err)
	}
	apiErr := &SidecarApiError{}
	if errors.As(err, &apiErr) {
		t.Error("a transport failure read as a refusal")
	}

	// a transport ends a request whose context ends, as net/http's does, and the cause survives
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := newTestSidecarApi(t, &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			if err := request.Context().Err(); err != nil {
				return nil, err
			}
			return syntheticResponse(request, 200, `{"generation":1}`, nil), nil
		},
	})
	if _, err := canceled.Bind(ctx, []byte("synthetic-binding")); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

// Following a redirect would repeat the bearer, or a form holding the subject token, wherever the
// answer pointed, so none is followed.
func TestRedirectIsNotFollowed(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		transport := &scriptedApiTransport{
			answer: func(request *http.Request, body []byte) (*http.Response, error) {
				return syntheticResponse(request, status, ``, http.Header{"Location": {"https://elsewhere.example/oauth/token"}}), nil
			},
		}
		api := newTestSidecarApi(t, transport)
		installTestDpopSigner(t, api)
		_, err := api.ExchangeToken(context.Background(), "https://evs.example", nil)
		if apiErr := asSidecarApiError(t, err); apiErr.Status != status {
			t.Errorf("%d: %+v", status, apiErr)
		}
		if count := transport.requestCount(); count != 1 {
			t.Errorf("%d: %d requests", status, count)
		}
	}
}

// An answer past ApiResponseByteCount is refused, not buffered.
func TestAnAnswerPastItsBoundIsRefused(t *testing.T) {
	settings := validSidecarSettings()
	body := `{"generation":1}`
	settings.ApiResponseByteCount = int64(len(body))
	api, err := newSidecarApi(settings, answerWith(200, body), testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	if generation, err := api.Bind(context.Background(), []byte("synthetic-binding")); err != nil || generation != 1 {
		t.Errorf("an answer of exactly the bound: %d, %v", generation, err)
	}

	padded := `{"generation":1} `
	api, err = newSidecarApi(settings, answerWith(200, padded), testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	if _, err := api.Bind(context.Background(), []byte("synthetic-binding")); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("err %v", err)
	}
}

// The body's retry_after_ms first, else Retry-After's, clamped to a uint32.
func TestRetryHintIsRead(t *testing.T) {
	for _, c := range []struct {
		body       string
		retryAfter string
		ms         uint32
	}{
		{body: `{"limit_key":"synthetic","retry_after_ms":1500}`, retryAfter: "7", ms: 1500},
		{body: `{"limit_key":"synthetic","retry_after_ms":1500}`, retryAfter: testApiNow.Add(time.Minute).Format(http.TimeFormat), ms: 1500},
		{body: `{"error":"Synthetic."}`, retryAfter: "7", ms: 7000},
		{body: `{"error":"Synthetic."}`, retryAfter: "86400", ms: 86400000},
		{body: `{"error":"Synthetic."}`, retryAfter: "99999999999", ms: 4294967295},
		// a date before the clock's now
		{body: `{"error":"Synthetic."}`, retryAfter: "Wed, 21 Oct 2015 07:28:00 GMT", ms: 0},
		{body: `{"error":"Synthetic."}`, retryAfter: testApiNow.Add(time.Minute).Format(http.TimeFormat), ms: 60000},
		{body: `{"retry_after_ms":-5}`, retryAfter: "", ms: 0},
		{body: `{"retry_after_ms":1e400}`, retryAfter: "", ms: 0},
		{body: `{"retry_after_ms":1e12}`, retryAfter: "", ms: 4294967295},
		{body: `Synthetic text`, retryAfter: "", ms: 0},
	} {
		transport := &scriptedApiTransport{
			answer: func(request *http.Request, body []byte) (*http.Response, error) {
				return syntheticResponse(request, 429, c.body, http.Header{"Retry-After": {c.retryAfter}}), nil
			},
		}
		api := newTestSidecarApi(t, transport)
		_, err := api.Bind(context.Background(), []byte("synthetic-binding"))
		if apiErr := asSidecarApiError(t, err); apiErr.Status != 429 || apiErr.RetryAfterMs != c.ms {
			t.Errorf("%s %q: %+v", c.body, c.retryAfter, apiErr)
		}
	}
}

// The refusal a 429 answer with retryAfter as its Retry-After makes, from api.
func retryAfterRefusal(t *testing.T, api *SidecarApi, retryAfter string) *SidecarApiError {
	t.Helper()
	api.setTransport(&scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			return syntheticResponse(request, 429, `{"error":"Synthetic."}`, http.Header{"Retry-After": {retryAfter}}), nil
		},
	})
	_, err := api.Bind(context.Background(), []byte("synthetic-binding"))
	return asSidecarApiError(t, err)
}

// Retry-After as delay-seconds, digits alone, or as an HTTP-date in any of RFC 9110's three forms,
// read against the api's clock: a date already past asks for no wait, and one past a uint32 of ms
// for the longest.
func TestRetryAfterDateIsReadAgainstTheClock(t *testing.T) {
	inThirtySeconds := testApiNow.Add(30 * time.Second)
	for _, c := range []struct {
		retryAfter string
		ms         uint32
	}{
		{retryAfter: inThirtySeconds.Format(http.TimeFormat), ms: 30000},
		{retryAfter: inThirtySeconds.Format("Monday, 02-Jan-06 15:04:05 GMT"), ms: 30000},
		{retryAfter: inThirtySeconds.Format(time.ANSIC), ms: 30000},
		{retryAfter: testApiNow.Add(90 * time.Minute).Format(http.TimeFormat), ms: 5400000},
		{retryAfter: testApiNow.Format(http.TimeFormat), ms: 0},
		{retryAfter: testApiNow.Add(-time.Hour).Format(http.TimeFormat), ms: 0},
		{retryAfter: testApiNow.Add(50 * 24 * time.Hour).Format(http.TimeFormat), ms: math.MaxUint32},
		// no zone, so not an HTTP-date
		{retryAfter: inThirtySeconds.Format("Mon, 02 Jan 2006 15:04:05"), ms: 0},
		{retryAfter: "30", ms: 30000},
		{retryAfter: "0", ms: 0},
		{retryAfter: "+30", ms: 0},
		{retryAfter: "-30", ms: 0},
		{retryAfter: "3.5", ms: 0},
		{retryAfter: "30 ", ms: 0},
		{retryAfter: "99999999999999999999999", ms: math.MaxUint32},
	} {
		api := newTestSidecarApi(t, answerWith(200, `{}`))
		if apiErr := retryAfterRefusal(t, api, c.retryAfter); apiErr.RetryAfterMs != c.ms {
			t.Errorf("%q: %d ms, want %d", c.retryAfter, apiErr.RetryAfterMs, c.ms)
		}
	}
}

// A nil clock is real time: a date long past asks for no wait and one far ahead for the longest,
// which the zero time would read the other way round.
func TestNilClockReadsRealTime(t *testing.T) {
	api, err := newSidecarApi(validSidecarSettings(), answerWith(200, `{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	if apiErr := retryAfterRefusal(t, api, "Sun, 06 Nov 1994 08:49:37 GMT"); apiErr.RetryAfterMs != 0 {
		t.Errorf("a past date: %d ms", apiErr.RetryAfterMs)
	}
	if apiErr := retryAfterRefusal(t, api, "Fri, 31 Dec 2117 23:59:59 GMT"); apiErr.RetryAfterMs != math.MaxUint32 {
		t.Errorf("a date far ahead: %d ms", apiErr.RetryAfterMs)
	}
}

// A body field of an unexpected type drops only itself: the code beside it is still read, and a
// retry_after_ms that is not a number leaves the header's hint.
func TestAMalformedRetryHintKeepsTheCode(t *testing.T) {
	for _, body := range []string{
		`{"code":"synthetic_code","retry_after_ms":"soon"}`,
		`{"code":"synthetic_code","retry_after_ms":{"ms":5}}`,
		`{"error":{"code":"synthetic_code","retry_after_ms":[1]}}`,
		`{"error":"synthetic_code","retry_after_ms":null}`,
	} {
		transport := &scriptedApiTransport{
			answer: func(request *http.Request, requestBody []byte) (*http.Response, error) {
				return syntheticResponse(request, 429, body, http.Header{"Retry-After": {"7"}}), nil
			},
		}
		api := newTestSidecarApi(t, transport)
		_, err := api.Bind(context.Background(), []byte("synthetic-binding"))
		if apiErr := asSidecarApiError(t, err); apiErr.Code != "synthetic_code" || apiErr.RetryAfterMs != 7000 {
			t.Errorf("%s: %+v", body, apiErr)
		}
	}
}

// Only a well-formed code is read as one, so no text of the server's reaches an error.
func TestOnlyAWellFormedCodeIsRead(t *testing.T) {
	for _, c := range []struct {
		body string
		code string
	}{
		{body: `{"error":"Some Synthetic Text"}`, code: ""},
		{body: `{"error":"synthetic text with spaces"}`, code: ""},
		{body: `{"code":"Synthetic_Code"}`, code: ""},
		{body: `{"code":"9synthetic"}`, code: ""},
		{body: `{"code":"` + strings.Repeat("a", 65) + `"}`, code: ""},
		{body: `{"code":"` + strings.Repeat("a", 64) + `"}`, code: strings.Repeat("a", 64)},
		{body: `{"error":{"code":"synthetic_code_2","message":"Text."}}`, code: "synthetic_code_2"},
		{body: `{"code":7}`, code: ""},
		{body: `[]`, code: ""},
	} {
		api := newTestSidecarApi(t, answerWith(400, c.body))
		_, err := api.Bind(context.Background(), []byte("synthetic-binding"))
		if apiErr := asSidecarApiError(t, err); apiErr.Code != c.code {
			t.Errorf("%s: %+v", c.body, apiErr)
		}
	}
}

// A %v of anything holding a token prints none of it.
func TestTokenHoldersPrintNoToken(t *testing.T) {
	api := newTestSidecarApi(t, answerWith(200, `{}`))
	installTestDpopSigner(t, api)
	holders := []any{
		api,
		&SidecarEnrollResult{ByClientJwt: testByJwt, Close: "synthetic-close-canary"},
		&SidecarAuthClientResult{ByClientJwt: testByJwt, Close: "synthetic-close-canary"},
		&SidecarServiceToken{AccessToken: testByJwt, Scopes: []string{"repo:synthetic:r"}},
	}
	for _, holder := range holders {
		text := fmt.Sprintf("%v %+v %#v %s", holder, holder, holder, holder)
		if strings.Contains(text, testByJwt) || strings.Contains(text, "close-canary") {
			t.Errorf("%T prints a token: %s", holder, text)
		}
	}
}

// A call in flight keeps the token it started with, and the next one presents the new token.
func TestACallKeepsTheTokenItStartedWith(t *testing.T) {
	var api *SidecarApi
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			api.SetByJwt("synthetic-later-jwt")
			return syntheticResponse(request, 200, `{"generation":1}`, nil), nil
		},
	}
	api = newTestSidecarApi(t, transport)
	for i := 0; i < 2; i += 1 {
		if _, err := api.Bind(context.Background(), []byte("synthetic-binding")); err != nil {
			t.Fatal(err)
		}
	}
	transport.stateLock.Lock()
	defer transport.stateLock.Unlock()
	if transport.requests[0].Header.Get("Authorization") != "Bearer "+testByJwt ||
		transport.requests[1].Header.Get("Authorization") != "Bearer synthetic-later-jwt" {
		t.Error("a call presented another token than the one it started with")
	}
}

// Counts the idle-connection drops a SidecarApi asks of the transport it replaces.
type closingApiTransport struct {
	transport  *scriptedApiTransport
	closeCount int
}

func (self *closingApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return self.transport.RoundTrip(request)
}

func (self *closingApiTransport) CloseIdleConnections() {
	self.closeCount += 1
}

func TestSetTransportDropsTheOldIdleConnections(t *testing.T) {
	old := &closingApiTransport{transport: answerWith(200, `{"generation":1}`)}
	api := newTestSidecarApi(t, old)
	replacement := answerWith(200, `{"generation":2}`)
	api.setTransport(replacement)
	if old.closeCount != 1 {
		t.Errorf("%d closes", old.closeCount)
	}
	generation, err := api.Bind(context.Background(), []byte("synthetic-binding"))
	if err != nil || generation != 2 {
		t.Errorf("%d, %v", generation, err)
	}
	if old.transport.requestCount() != 0 || replacement.requestCount() != 1 {
		t.Error("the request went to the old transport")
	}
}

// Whatever transport is given still refuses a request that is not absolute, as the page Worker's
// fetch would take one.
func TestAGivenTransportGoesBehindTheUrlCheck(t *testing.T) {
	transport := answerWith(200, `{"generation":1}`)
	api := newTestSidecarApi(t, transport)
	_, err := api.send(context.Background(), &sidecarApiRequest{
		route:     "POST /sidecar/bind",
		operation: "bind",
		method:    "POST",
		url:       "/sidecar/bind",
		bearer:    true,
	})
	if !errors.Is(err, errServiceUrl) {
		t.Errorf("err %v", err)
	}
	if count := transport.requestCount(); count != 0 {
		t.Errorf("%d requests", count)
	}
}
