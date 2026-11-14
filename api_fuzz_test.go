//go:build !js

// §22.6 for SidecarApi's decoders: on any answer, newSidecarApiError and each route's reply decoder
// end, and what comes back says nothing of the answer's text but a well-formed code (I-7). An error is
// one of a few fixed texts per route, so neither the body nor a token it echoes can reach one, and a
// result holds what its route requires of it. The seeds run as ordinary tests. Off the js leg, as
// keys_fuzz_test.go is, where a fuzz target cannot read its corpus in a Worker.

package sidecar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// What a *SidecarApiError of route, status and code says, which is all it may say.
func sidecarApiErrorText(route string, status int, code string) string {
	if code == "" {
		return fmt.Sprintf("sidecar api %s refused: %d", route, status)
	}
	return fmt.Sprintf("sidecar api %s refused: %d %s", route, status, code)
}

func FuzzSidecarApiError(f *testing.F) {
	for _, seed := range []struct {
		status     int
		body       string
		retryAfter string
	}{
		{status: 401, body: `{"error":"Synthetic.","code":"session_revoked"}`},
		{status: 409, body: `{"error":"Synthetic.","code":"client_bound"}`},
		{status: 400, body: `{"error":"invalid_grant","error_description":"Synthetic."}`},
		{status: 400, body: `{"error":{"code":"synthetic_code","message":"Text."}}`},
		{status: 400, body: `{"error":{"code":{"code":"synthetic_code"}}}`},
		{status: 400, body: `{"code":"Synthetic Text"}`, retryAfter: "+30"},
		{status: 429, body: `{"limit_key":"synthetic","limit":5,"used":5,"retry_after_ms":1500,"upgrade":false}`, retryAfter: "7"},
		{status: 429, body: `{"code":"synthetic_code","retry_after_ms":"soon"}`, retryAfter: "-1"},
		{status: 503, body: ``, retryAfter: "Thu, 01 Jan 2026 00:00:30 GMT"},
		{status: 503, body: ``, retryAfter: "Thursday, 01-Jan-26 00:00:30 GMT"},
		{status: 503, body: ``, retryAfter: "Thu Jan  1 00:00:30 2026"},
		{status: 500, body: `Synthetic text`, retryAfter: "99999999999999999999999"},
	} {
		f.Add(seed.status, []byte(seed.body), seed.retryAfter)
	}
	f.Fuzz(func(t *testing.T, status int, body []byte, retryAfter string) {
		// 300 to 599, each seed's status as it stands: not 2xx, which is all newSidecarApiError is given
		status = 300 + int(uint(status-300)%300)
		route := "POST /sidecar/bind"
		response := &http.Response{
			StatusCode: status,
			Header:     http.Header{"Retry-After": {retryAfter}},
		}
		apiErr := newSidecarApiError(route, response, body, testApiClock)
		if apiErr.Route != route || apiErr.Status != status {
			t.Fatalf("%+v", apiErr)
		}
		if apiErr.Code != "" && !isSidecarApiCode(apiErr.Code) {
			t.Fatalf("code %q", apiErr.Code)
		}
		if text := apiErr.Error(); text != sidecarApiErrorText(route, status, apiErr.Code) {
			t.Fatalf("the error says more than its route, status and code: %q", text)
		}
		if !json.Valid(body) {
			if apiErr.Code != "" {
				t.Fatalf("a code %q from a body that is not JSON", apiErr.Code)
			}
			if retryAfter == "" && apiErr.RetryAfterMs != 0 {
				t.Fatalf("a wait of %d ms from no hint", apiErr.RetryAfterMs)
			}
		}
	})
}

// The ids FuzzSidecarApiReplies asks about.
var (
	fuzzSidecarApiSidecarId = Id{0x01, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	fuzzSidecarApiClientId  = Id{0x01, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// The longest answer FuzzSidecarApiReplies's api reads, short, so an answer past it is in reach.
const fuzzSidecarApiResponseByteCount = 4096

func FuzzSidecarApiReplies(f *testing.F) {
	binding := base64.StdEncoding.EncodeToString([]byte("synthetic-binding"))
	identityPublicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, seed := range []struct {
		status int
		body   string
	}{
		{status: 200, body: `{"by_client_jwt":"synthetic-jwt","client_id":"` + fuzzSidecarApiClientId.String() + `","approval_state":"approved","admin_refused":true}`},
		{status: 200, body: `{"by_client_jwt":"synthetic-jwt","admin_refused":true,"strict_exp":true,"close":"synthetic-close"}`},
		{status: 200, body: `{"error":{"client_limit_exceeded":true}}`},
		{status: 200, body: `{"error":{"message":"Synthetic.","code":"restore_required"}}`},
		{status: 200, body: `{"error":{"message":"Synthetic text"}}`},
		{status: 200, body: `{"generation":2}`},
		{status: 201, body: `{"generation":1}`},
		{status: 200, body: `{"sidecar_id":"` + fuzzSidecarApiSidecarId.String() + `","identity_public_key":"` + identityPublicKey + `","identity_alg":"ed25519","status":"active","binding":"` + binding + `","bindings":["` + binding + `"]}`},
		{status: 200, body: `{"sidecar_id":"` + fuzzSidecarApiClientId.String() + `","identity_public_key":"` + identityPublicKey + `","identity_alg":"ed25519","status":"active"}`},
		{status: 200, body: `{"by_jwt":"synthetic-jwt"}`},
		{status: 200, body: `{"access_token":"synthetic-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900,"scope":"repo:synthetic:r"}`},
		{status: 200, body: `{"access_token":"synthetic-token","expires_in":-1}`},
		{status: 200, body: `{"access_token":"synthetic-token","expires_in":9223372036854775807}`},
		{status: 200, body: `{"client_id":null,"sidecar_id":7}`},
		{status: 200, body: `null`},
		{status: 200, body: `[]`},
		{status: 204, body: ``},
		{status: 200, body: `{"generation":1,"pad":"` + strings.Repeat("x", fuzzSidecarApiResponseByteCount) + `"}`},
		{status: 401, body: `{"error":"Synthetic.","code":"session_revoked"}`},
		{status: 429, body: `{"retry_after_ms":1500}`},
		{status: 500, body: `Synthetic text`},
	} {
		f.Add(seed.status, []byte(seed.body))
	}
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		// 200 to 599, each seed's status as it stands
		status = 200 + int(uint(status-200)%400)
		settings := validSidecarSettings()
		settings.ApiResponseByteCount = fuzzSidecarApiResponseByteCount
		api, err := newSidecarApi(settings, &scriptedApiTransport{
			answer: func(request *http.Request, requestBody []byte) (*http.Response, error) {
				return syntheticResponse(request, status, string(body), nil), nil
			},
		}, testApiClock)
		if err != nil {
			t.Fatal(err)
		}
		api.SetByJwt(testByJwt)
		installTestDpopSigner(t, api)
		ctx := context.Background()
		answered2xx := 200 <= status && status < 300

		// Whether route's call took the answer. An error it gives is a refusal saying only its route,
		// status and code, a 2xx's error object reading as 200, or a 2xx answer that is not the
		// route's, in one of two fixed texts.
		took := func(route string, err error) bool {
			t.Helper()
			if err == nil {
				if !answered2xx {
					t.Fatalf("%s took a %d answer", route, status)
				}
				return true
			}
			apiErr := &SidecarApiError{}
			if errors.As(err, &apiErr) {
				wantStatus := status
				if answered2xx {
					wantStatus = http.StatusOK
				}
				if apiErr.Route != route || apiErr.Status != wantStatus || apiErr.Code != "" && !isSidecarApiCode(apiErr.Code) {
					t.Fatalf("%s: %+v", route, apiErr)
				}
				if err.Error() != sidecarApiErrorText(route, wantStatus, apiErr.Code) {
					t.Fatalf("%s: the error says more than its route, status and code: %q", route, err)
				}
				return false
			}
			if !answered2xx {
				t.Fatalf("%s: a %d answer is not a refusal: %q", route, status, err)
			}
			malformed := "sidecar api " + route + ": " + ErrSidecarApiReply.Error()
			if text := err.Error(); text != malformed && text != fmt.Sprintf("%s: past %d bytes", malformed, fuzzSidecarApiResponseByteCount) {
				t.Fatalf("%s: %q", route, text)
			}
			return false
		}

		enrolled, err := api.Enroll(ctx, testEnrollArgs())
		if took("POST /network/enroll", err) && (enrolled.ByClientJwt == "" || enrolled.ClientId == (Id{})) {
			t.Fatalf("enroll took an answer with no token or client: %v", enrolled)
		}
		minted, err := api.AuthClient(ctx, &SidecarAuthClientArgs{Description: "synthetic"})
		if took("POST /network/auth-client", err) && minted.ByClientJwt == "" {
			t.Fatal("auth-client took an answer with no token")
		}
		took("POST /network/remove-client", api.RemoveClient(ctx, fuzzSidecarApiClientId))
		bound, err := api.Bind(ctx, []byte("synthetic-binding"))
		if took("POST /sidecar/bind", err) && (bound.Generation < 1 || bound.ByClientJwt == "" || bound.SidecarId == (Id{})) {
			t.Fatalf("bind took %v", bound)
		}
		record, err := api.GetIdentity(ctx, fuzzSidecarApiSidecarId, 0)
		if took("GET /sidecar/identity/<sidecar_id>", err) &&
			(record.SidecarId != fuzzSidecarApiSidecarId || len(record.IdentityPublicKey) == 0 || record.IdentityAlg == "" || record.Status == "") {
			t.Fatalf("an identity lookup took %+v", record)
		}
		record, err = api.GetIdentityByClient(ctx, fuzzSidecarApiClientId)
		if took("GET /sidecar/identity?client_id=<client_id>", err) &&
			(record.SidecarId == (Id{}) || len(record.IdentityPublicKey) == 0 || record.IdentityAlg == "" || record.Status == "" || record.Bindings != nil) {
			t.Fatalf("a client's identity lookup took %+v", record)
		}
		byJwt, err := api.Refresh(ctx)
		if took("GET /auth/refresh", err) && byJwt == "" {
			t.Fatal("refresh took an answer with no token")
		}
		serviceToken, err := api.ExchangeToken(ctx, "https://evs.example", []string{"repo:synthetic:r"})
		if took("POST /oauth/token", err) && (serviceToken.AccessToken == "" || serviceToken.ExpiresIn < 0) {
			t.Fatalf("the exchange took %v, expiring in %v", serviceToken, serviceToken.ExpiresIn)
		}
	})
}
