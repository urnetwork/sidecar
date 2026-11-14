package pushservice_test

// APNs and FCM (SDK-M8-10; §18.7, §19.4) against fake vendors served over HTTP/2 with TLS: each submission's
// request as the vendor documents it, its provider token or access token verified under the test's key with
// its claims, tokens reused within their life and made anew after it or on the vendor's word, each answer
// mapped to sent, unregistered, retry or refused, a Retry-After kept, and the arguments a vendor refuses. Every
// key is made by the test, and every token, team, project and host is synthetic.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One request a fake vendor took.
type testVendorRequest struct {
	path       string
	protoMajor int
	header     http.Header
	body       []byte
}

// A vendor's HTTP/2 server answering from a script: each answer a status, a body and headers, then 200.
type testVendorServer struct {
	server *httptest.Server

	stateLock sync.Mutex
	requests  []*testVendorRequest
	answers   []testVendorAnswer
	// answers a path before the script does, for FCM's token endpoint
	route func(request *http.Request, body []byte) (testVendorAnswer, bool)
}

type testVendorAnswer struct {
	status int
	body   string
	header map[string]string
}

func newTestVendorServer(t *testing.T) *testVendorServer {
	t.Helper()
	self := &testVendorServer{}
	self.server = httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		answer := testVendorAnswer{status: http.StatusOK}
		routed := false
		self.stateLock.Lock()
		route := self.route
		self.stateLock.Unlock()
		if route != nil {
			if routedAnswer, ok := route(request, body); ok {
				answer, routed = routedAnswer, true
			}
		}
		if !routed {
			self.stateLock.Lock()
			self.requests = append(self.requests, &testVendorRequest{path: request.URL.EscapedPath(), protoMajor: request.ProtoMajor, header: request.Header.Clone(), body: body})
			if 0 < len(self.answers) {
				answer = self.answers[0]
				self.answers = self.answers[1:]
			}
			self.stateLock.Unlock()
		}
		for name, value := range answer.header {
			writer.Header().Set(name, value)
		}
		writer.WriteHeader(answer.status)
		writer.Write([]byte(answer.body))
	}))
	self.server.EnableHTTP2 = true
	self.server.StartTLS()
	t.Cleanup(self.server.Close)
	return self
}

func (self *testVendorServer) answer(answers ...testVendorAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers = append(self.answers, answers...)
}

func (self *testVendorServer) taken() []*testVendorRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*testVendorRequest{}, self.requests...)
}

// A JWT's parts: its header and claims decoded, and whether its signature verifies under verify.
func testJwtParts(t *testing.T, token string, verify func(signingInput []byte, signature []byte) bool) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("a jwt of %d parts", len(parts))
	}
	decode := func(part string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		value := map[string]any{}
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !verify([]byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("the jwt's signature does not verify under the test's key")
	}
	return decode(parts[0]), decode(parts[1])
}

// A P-256 key and its .p8 PEM.
func testApnsKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// An APNs vendor on server, with key, on clock.
func newTestApnsVendor(t *testing.T, server *testVendorServer, keyPem []byte, clock *sidecartest.FakeClock) *pushservice.ApnsVendor {
	t.Helper()
	settings := pushservice.DefaultApnsVendorSettings()
	settings.Endpoint = server.server.URL
	settings.Topic = "example.synthetic.wake"
	vendor, err := pushservice.NewApnsVendor(&pushservice.ApnsVendorArgs{
		TeamId:        "SYNTHTEAM1",
		KeyId:         "SYNTHKEY01",
		PrivateKeyPem: keyPem,
		Settings:      settings,
		Transport:     server.server.Client().Transport,
		Clock:         clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vendor
}

// An APNs submission is a POST over HTTP/2 to /3/device/<token> with a background push's headers and body, and a
// provider token that verifies under the team's key, names its team and key and the time it was signed; the token
// is reused for 40 min and signed anew after.
func TestApnsVendorSendsABackgroundPush(t *testing.T) {
	server := newTestVendorServer(t)
	key, keyPem := testApnsKey(t)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	vendor := newTestApnsVendor(t, server, keyPem, clock)
	payload := &pushservice.WakePayload{TopicClass: "mail", Version: 42}
	if result := vendor.Send(t.Context(), "synthetic0apns0token", payload); result.Outcome != pushservice.WakeVendorSent || result.Status != 200 {
		t.Fatalf("%+v", result)
	}
	clock.Advance(39 * time.Minute)
	vendor.Send(t.Context(), "synthetic0apns0token", payload)
	clock.Advance(2 * time.Minute)
	vendor.Send(t.Context(), "synthetic0apns0token", payload)
	requests := server.taken()
	if len(requests) != 3 {
		t.Fatalf("%d requests", len(requests))
	}
	request := requests[0]
	if request.path != "/3/device/synthetic0apns0token" || request.protoMajor != 2 || request.header.Get("apns-push-type") != "background" ||
		request.header.Get("apns-priority") != "5" || request.header.Get("apns-topic") != "example.synthetic.wake" ||
		string(request.body) != `{"aps":{"content-available":1},"t":"mail","v":42}` {
		t.Fatalf("request %+v %s", request, request.body)
	}
	tokens := []string{}
	for _, request := range requests {
		bearer, found := strings.CutPrefix(request.header.Get("authorization"), "bearer ")
		if !found {
			t.Fatalf("authorization %q", request.header.Get("authorization"))
		}
		tokens = append(tokens, bearer)
	}
	header, claims := testJwtParts(t, tokens[0], func(signingInput []byte, signature []byte) bool {
		digest := sha256.Sum256(signingInput)
		return len(signature) == 64 && ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	})
	if header["alg"] != "ES256" || header["kid"] != "SYNTHKEY01" || claims["iss"] != "SYNTHTEAM1" ||
		int64(claims["iat"].(float64)) != sidecartest.DefaultClockStart().Unix() {
		t.Fatalf("header %v, claims %v", header, claims)
	}
	if tokens[1] != tokens[0] || tokens[2] == tokens[0] {
		t.Fatal("a token not reused within its 40 min, or reused past them")
	}
}

// APNs' answers: 410 unregistered; 400 refused with its reason; 429 and 503 retried, a Retry-After kept; a 403
// ExpiredProviderToken retried with a token signed anew.
func TestApnsVendorMapsItsAnswers(t *testing.T) {
	server := newTestVendorServer(t)
	_, keyPem := testApnsKey(t)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	vendor := newTestApnsVendor(t, server, keyPem, clock)
	payload := &pushservice.WakePayload{TopicClass: "team", Version: 9}
	cases := []struct {
		answer  testVendorAnswer
		outcome pushservice.WakeVendorOutcome
		reason  string
		after   time.Duration
	}{
		{answer: testVendorAnswer{status: 410, body: `{"reason":"Unregistered","timestamp":1800000000000}`}, outcome: pushservice.WakeVendorUnregistered, reason: "Unregistered"},
		{answer: testVendorAnswer{status: 400, body: `{"reason":"BadDeviceToken"}`}, outcome: pushservice.WakeVendorRefused, reason: "BadDeviceToken"},
		{answer: testVendorAnswer{status: 429, body: `{"reason":"TooManyRequests"}`, header: map[string]string{"retry-after": "7"}}, outcome: pushservice.WakeVendorRetry, reason: "TooManyRequests", after: 7 * time.Second},
		{answer: testVendorAnswer{status: 503, body: `{"reason":"ServiceUnavailable"}`}, outcome: pushservice.WakeVendorRetry, reason: "ServiceUnavailable"},
		{answer: testVendorAnswer{status: 403, body: `{"reason":"ExpiredProviderToken"}`}, outcome: pushservice.WakeVendorRetry, reason: "ExpiredProviderToken"},
		{answer: testVendorAnswer{status: 400, body: `{"reason":"a reason with spaces and a token synthetic0apns0token"}`}, outcome: pushservice.WakeVendorRefused, reason: ""},
	}
	for _, c := range cases {
		server.answer(c.answer)
		result := vendor.Send(t.Context(), "synthetic0apns0token", payload)
		if result.Outcome != c.outcome || result.Status != c.answer.status || result.Reason != c.reason || result.RetryAfter != c.after {
			t.Errorf("%d %s: %+v", c.answer.status, c.answer.body, result)
		}
	}
	requests := server.taken()
	// the token after ExpiredProviderToken is a new one
	if requests[4].header.Get("authorization") == requests[5].header.Get("authorization") {
		t.Error("a token APNs called expired was sent again")
	}
}

// A service account's JSON key with key, its token endpoint on server.
func testFcmAccount(t *testing.T, server *testVendorServer) (*rsa.PrivateKey, *pushservice.FcmServiceAccount) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyJson, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "synthetic-wake-project",
		"private_key_id": "synthetic-key-id",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "wake-sender@synthetic-wake-project.example",
		"token_uri":      server.server.URL + "/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := pushservice.ParseFcmServiceAccount(keyJson)
	if err != nil {
		t.Fatal(err)
	}
	return key, account
}

// A token endpoint on server that checks each assertion under key and answers access tokens in turn, counting
// the exchanges.
func (self *testVendorServer) serveFcmTokens(t *testing.T, key *rsa.PrivateKey, clock *sidecartest.FakeClock) *int {
	exchanges := 0
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.route = func(request *http.Request, body []byte) (testVendorAnswer, bool) {
		if request.URL.Path != "/token" {
			return testVendorAnswer{}, false
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			return testVendorAnswer{status: 400}, true
		}
		header, claims := testJwtParts(t, form.Get("assertion"), func(signingInput []byte, signature []byte) bool {
			digest := sha256.Sum256(signingInput)
			return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) == nil
		})
		now := clock.Now().Unix()
		if header["alg"] != "RS256" || header["kid"] != "synthetic-key-id" || claims["iss"] != "wake-sender@synthetic-wake-project.example" ||
			claims["scope"] != pushservice.FcmMessagingScope || claims["aud"] != self.server.URL+"/token" ||
			int64(claims["iat"].(float64)) != now || int64(claims["exp"].(float64)) != now+3600 {
			t.Errorf("assertion header %v, claims %v", header, claims)
			return testVendorAnswer{status: 400}, true
		}
		self.stateLock.Lock()
		exchanges += 1
		count := exchanges
		self.stateLock.Unlock()
		answer, _ := json.Marshal(map[string]any{"access_token": "synthetic-access-token-" + string(rune('0'+count)), "expires_in": 3600, "token_type": "Bearer"})
		return testVendorAnswer{status: 200, body: string(answer)}, true
	}
	return &exchanges
}

// An FCM vendor on server, its token endpoint serving key's assertions.
func newTestFcmVendor(t *testing.T, server *testVendorServer, clock *sidecartest.FakeClock) (*pushservice.FcmVendor, *int) {
	t.Helper()
	key, account := testFcmAccount(t, server)
	exchanges := server.serveFcmTokens(t, key, clock)
	settings := pushservice.DefaultFcmVendorSettings()
	settings.Endpoint = server.server.URL
	vendor, err := pushservice.NewFcmVendor(&pushservice.FcmVendorArgs{
		Account:   account,
		Settings:  settings,
		Transport: server.server.Client().Transport,
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vendor, exchanges
}

// An FCM submission is a data message at high priority posted to the project's messages:send with an access
// token the vendor exchanged for its own signed assertion, reused until 5 min before it lapses.
func TestFcmVendorSendsADataMessage(t *testing.T) {
	server := newTestVendorServer(t)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	vendor, exchanges := newTestFcmVendor(t, server, clock)
	payload := &pushservice.WakePayload{TopicClass: "core", Version: 18446744073709551615}
	if result := vendor.Send(t.Context(), "synthetic-fcm-token", payload); result.Outcome != pushservice.WakeVendorSent {
		t.Fatalf("%+v", result)
	}
	clock.Advance(54 * time.Minute)
	vendor.Send(t.Context(), "synthetic-fcm-token", payload)
	clock.Advance(2 * time.Minute)
	vendor.Send(t.Context(), "synthetic-fcm-token", payload)
	requests := server.taken()
	if len(requests) != 3 || *exchanges != 2 {
		t.Fatalf("%d requests, %d exchanges", len(requests), *exchanges)
	}
	request := requests[0]
	if request.path != "/v1/projects/synthetic-wake-project/messages:send" || request.protoMajor != 2 ||
		request.header.Get("authorization") != "Bearer synthetic-access-token-1" ||
		string(request.body) != `{"message":{"token":"synthetic-fcm-token","data":{"t":"core","v":"18446744073709551615"},"android":{"priority":"high"}}}` {
		t.Fatalf("request %+v %s", request, request.body)
	}
	if requests[1].header.Get("authorization") != "Bearer synthetic-access-token-1" || requests[2].header.Get("authorization") != "Bearer synthetic-access-token-2" {
		t.Fatalf("tokens %q, %q", requests[1].header.Get("authorization"), requests[2].header.Get("authorization"))
	}
}

// FCM's answers: UNREGISTERED unregistered; INVALID_ARGUMENT refused; 429 and 503 retried; a 401 retried with a
// token exchanged anew.
func TestFcmVendorMapsItsAnswers(t *testing.T) {
	server := newTestVendorServer(t)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	vendor, exchanges := newTestFcmVendor(t, server, clock)
	fcmError := func(status int, statusName string, errorCode string) string {
		return fmt.Sprintf(`{"error":{"code":%d,"message":"synthetic","status":%q,"details":[{"@type":%q,"errorCode":%q}]}}`,
			status, statusName, pushservice.FcmErrorDetailType, errorCode)
	}
	payload := &pushservice.WakePayload{TopicClass: "evs", Version: 3}
	cases := []struct {
		answer  testVendorAnswer
		outcome pushservice.WakeVendorOutcome
		reason  string
	}{
		{answer: testVendorAnswer{status: 404, body: fcmError(404, "NOT_FOUND", "UNREGISTERED")}, outcome: pushservice.WakeVendorUnregistered, reason: "UNREGISTERED"},
		{answer: testVendorAnswer{status: 400, body: fcmError(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT")}, outcome: pushservice.WakeVendorRefused, reason: "INVALID_ARGUMENT"},
		{answer: testVendorAnswer{status: 429, body: fcmError(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED")}, outcome: pushservice.WakeVendorRetry, reason: "QUOTA_EXCEEDED"},
		{answer: testVendorAnswer{status: 503, body: fcmError(503, "UNAVAILABLE", "UNAVAILABLE")}, outcome: pushservice.WakeVendorRetry, reason: "UNAVAILABLE"},
		{answer: testVendorAnswer{status: 401, body: `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`}, outcome: pushservice.WakeVendorRetry, reason: "UNAUTHENTICATED"},
	}
	for _, c := range cases {
		server.answer(c.answer)
		result := vendor.Send(t.Context(), "synthetic-fcm-token", payload)
		if result.Outcome != c.outcome || result.Status != c.answer.status || result.Reason != c.reason {
			t.Errorf("%d: %+v", c.answer.status, result)
		}
	}
	if *exchanges != 1 {
		t.Fatalf("%d exchanges before the 401's retry", *exchanges)
	}
	vendor.Send(t.Context(), "synthetic-fcm-token", payload)
	if requests := server.taken(); *exchanges != 2 || requests[len(requests)-1].header.Get("authorization") != "Bearer synthetic-access-token-2" {
		t.Errorf("%d exchanges after the 401", *exchanges)
	}
}

// A vendor refuses what it cannot run on: an endpoint that is not an https origin, no topic or team, a key that is
// not P-256, a service account with no project or an http token_uri, a key that is not RSA.
func TestWakeVendorsRefuse(t *testing.T) {
	_, apnsPem := testApnsKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Der, _ := x509.MarshalPKCS8PrivateKey(p384)
	p384Pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384Der})
	apns := func(endpoint string, topic string, team string, keyPem []byte) error {
		settings := pushservice.DefaultApnsVendorSettings()
		settings.Endpoint, settings.Topic = endpoint, topic
		_, err := pushservice.NewApnsVendor(&pushservice.ApnsVendorArgs{TeamId: team, KeyId: "SYNTHKEY01", PrivateKeyPem: keyPem, Settings: settings})
		return err
	}
	if err := apns("https://apns.synthetic.example", "example.synthetic.wake", "SYNTHTEAM1", apnsPem); err != nil {
		t.Fatalf("a good apns vendor: %v", err)
	}
	for name, err := range map[string]error{
		"http":     apns("http://apns.synthetic.example", "example.synthetic.wake", "SYNTHTEAM1", apnsPem),
		"a path":   apns("https://apns.synthetic.example/3/device", "example.synthetic.wake", "SYNTHTEAM1", apnsPem),
		"no host":  apns("", "example.synthetic.wake", "SYNTHTEAM1", apnsPem),
		"no topic": apns("https://apns.synthetic.example", "", "SYNTHTEAM1", apnsPem),
		"no team":  apns("https://apns.synthetic.example", "example.synthetic.wake", "", apnsPem),
		"a p-384":  apns("https://apns.synthetic.example", "example.synthetic.wake", "SYNTHTEAM1", p384Pem),
		"not pem":  apns("https://apns.synthetic.example", "example.synthetic.wake", "SYNTHTEAM1", []byte("synthetic")),
		"no key":   apns("https://apns.synthetic.example", "example.synthetic.wake", "SYNTHTEAM1", nil),
	} {
		if err == nil {
			t.Errorf("apns with %s opened", name)
		}
	}

	server := newTestVendorServer(t)
	_, account := testFcmAccount(t, server)
	fcm := func(edit func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings)) error {
		copied := *account
		settings := pushservice.DefaultFcmVendorSettings()
		settings.Endpoint = "https://fcm.synthetic.example"
		edit(&copied, settings)
		_, err := pushservice.NewFcmVendor(&pushservice.FcmVendorArgs{Account: &copied, Settings: settings})
		return err
	}
	if err := fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {}); err != nil {
		t.Fatalf("a good fcm vendor: %v", err)
	}
	for name, err := range map[string]error{
		"no project": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			account.ProjectId = ""
		}),
		"no account": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			account.ClientEmail = ""
		}),
		"an http token": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			account.TokenUri = "http://token.synthetic.example"
		}),
		"an ec key": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			account.PrivateKey = string(apnsPem)
		}),
		"no endpoint": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			settings.Endpoint = ""
		}),
		"a margin past": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			settings.AccessTokenRefreshMargin = 2 * time.Hour
		}),
		"a bad endpoint": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			settings.Endpoint = "https://fcm.synthetic.example/v1"
		}),
		"a missing key": fcm(func(account *pushservice.FcmServiceAccount, settings *pushservice.FcmVendorSettings) {
			account.PrivateKey = ""
		}),
		"a json key file": nil,
	} {
		if name == "a json key file" {
			if _, err := pushservice.ParseFcmServiceAccount([]byte("not json")); err == nil {
				t.Error("a key file that is not json parsed")
			}
			continue
		}
		if err == nil {
			t.Errorf("fcm with %s opened", name)
		}
	}
}
