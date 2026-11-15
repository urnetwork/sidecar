package sidecar

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The forwarding client presents F's token with a proof of F's own ClientKey on every route the Forwarder reads, and
// its refresh answers the new token, installing nothing until the caller does.
func TestForwardingClientPresentsItsOwnProof(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x37
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sidecarId := NewId()
	transport := &scriptedApiTransport{answer: func(request *http.Request, body []byte) (*http.Response, error) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/auth/refresh"):
			return syntheticResponse(request, 200, `{"by_jwt":"synthetic-forward-jwt-2"}`, nil), nil
		case strings.Contains(request.URL.Path, "/sidecar/identity/"):
			return syntheticResponse(request, 200, `{"sidecar_id":"`+sidecarId.String()+`","identity_public_key":"AAAA","identity_alg":"ed25519","status":"active"}`, nil), nil
		}
		return syntheticResponse(request, 404, "", nil), nil
	}}
	client, err := NewForwardingClient(&ForwardingClientArgs{
		Settings:      validSidecarSettings(),
		Transport:     transport,
		ByJwt:         "synthetic-forward-jwt-1",
		ClientKeySeed: seed,
		Now:           func() time.Time { return testDpopNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	byJwt, err := client.Refresh(context.Background())
	if err != nil || byJwt != "synthetic-forward-jwt-2" {
		t.Fatalf("refresh %q, %v", byJwt, err)
	}
	refresh := transport.requests[0]
	if refresh.Header.Get("Authorization") != "DPoP synthetic-forward-jwt-1" && refresh.Header.Get("Authorization") != "Bearer synthetic-forward-jwt-1" {
		t.Errorf("refresh presented %q", refresh.Header.Get("Authorization"))
	}
	checkTestDpopHeader(t, refresh, publicKey, "GET", validSidecarSettings().ApiUrl+"/auth/refresh", "synthetic-forward-jwt-1")

	// nothing installed until the caller keeps it: the next call still presents the old token
	if _, err := client.Binding(context.Background(), sidecarId); err == nil {
		t.Error("a record with no binding answered one")
	}
	if presented := transport.requests[1].Header.Get("Authorization"); !strings.HasSuffix(presented, "synthetic-forward-jwt-1") {
		t.Errorf("before SetByJwt the client presented %q", presented)
	}
	client.SetByJwt(byJwt)
	client.Binding(context.Background(), sidecarId)
	if presented := transport.requests[2].Header.Get("Authorization"); !strings.HasSuffix(presented, "synthetic-forward-jwt-2") {
		t.Errorf("after SetByJwt the client presented %q", presented)
	}
	if client.String() != "ForwardingClient{}" || strings.Contains(client.String(), "jwt") {
		t.Error("the client's text names its token")
	}
}

// A forwarding client needs F's token and a 32-byte ClientKey seed.
func TestForwardingClientRefusesWhatItCannotProve(t *testing.T) {
	for _, args := range []*ForwardingClientArgs{
		nil,
		{Settings: validSidecarSettings(), ClientKeySeed: make([]byte, ed25519.SeedSize)},
		{Settings: validSidecarSettings(), ByJwt: "synthetic", ClientKeySeed: make([]byte, 31)},
		{ByJwt: "synthetic", ClientKeySeed: make([]byte, ed25519.SeedSize)},
	} {
		if _, err := NewForwardingClient(args); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%+v made a client: %v", args, err)
		}
	}
}
