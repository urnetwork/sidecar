//go:build sidecar_testhooks

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"
)

// Every credential SidecarApi sees reaches the privacy harness as it arrives, the ClientKey at the
// signer's derivation included, so S1's scan finds one that leaks (§22.7, I-7), and every request
// passes its barriers.
func TestApiCredentialsReachTheSecretHook(t *testing.T) {
	recorder := recordHooks(t)
	clientId := NewId()
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			switch request.URL.Path {
			case "/network/enroll":
				return syntheticResponse(request, 200, `{"by_client_jwt":"synthetic-enroll-jwt","client_id":"`+clientId.String()+`","admin_refused":true,"close":"synthetic-close"}`, nil), nil
			case "/auth/refresh":
				return syntheticResponse(request, 200, `{"by_jwt":"synthetic-refresh-jwt"}`, nil), nil
			case "/network/auth-client":
				return syntheticResponse(request, 200, `{"by_client_jwt":"synthetic-child-jwt"}`, nil), nil
			default:
				return syntheticResponse(request, 200, `{"access_token":"synthetic-service-token","expires_in":900}`, nil), nil
			}
		},
	}
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)
	ctx := context.Background()
	if _, err := api.Enroll(ctx, testEnrollArgs()); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := api.AuthClient(ctx, &SidecarAuthClientArgs{}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.ExchangeToken(ctx, "https://evs.example", nil); err != nil {
		t.Fatal(err)
	}

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, want := range [][]byte{
		ed25519.NewKeyFromSeed(seed),
		[]byte(testByJwt),
		[]byte("synthetic01-synthetic02"),
		[]byte("synthetic-enroll-jwt"),
		[]byte("synthetic-close"),
		[]byte("synthetic-refresh-jwt"),
		[]byte("synthetic-child-jwt"),
		[]byte("synthetic-service-token"),
	} {
		found := false
		for _, secret := range recorder.secrets {
			if bytes.Equal(secret, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q never reached the hook", want[:min(len(want), 12)])
		}
	}
	for _, kind := range []string{"ClientKey", "by_client_jwt", "auth_key", "close", "service_token"} {
		if !recorder.kinds[kind] {
			t.Errorf("no %s", kind)
		}
	}
	for _, name := range []string{"api.send.before", "api.send.after", "api.set_by_jwt.before", "api.set_by_jwt.after"} {
		if !recorder.barriers[name] {
			t.Errorf("no %s barrier", name)
		}
	}
}

// A proof refused for its iat passes the offset's barriers as the refusal's Date is kept, and the retry's
// before it is signed once more (§7.4, QD-757).
func TestApiClockRetryPassesItsBarriers(t *testing.T) {
	recorder := recordHooks(t)
	world := newTestApiClockWorld(t, 10*time.Minute)
	if _, err := world.api.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, name := range []string{"api.clock_offset.before", "api.clock_offset.after", "api.send.iat_retry"} {
		if !recorder.barriers[name] {
			t.Errorf("no %s barrier", name)
		}
	}
}
