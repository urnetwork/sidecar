//go:build !sidecar_http && !js

// QD-797 end to end on T2 (QD-040, plan-SOCK-client-auth): a sidecar enrolled through sidecartest's fake api holds
// the token POST /sidecar/bind re-minted with its sidecar_id, and the sockets engine on the Net, authenticating
// Client-class tokens as server's verifier does (FakeApi.ClientTokenAuthenticator), admits its call, where it denies
// the token the enrollment answered, which names no sidecar (SocketErrorCodeDenied). A refresh keeps the claim, so
// the refreshed token is admitted too. The call is the sidecar's own route code, SidecarApi.SocketList, on the
// engine's transport. Fake clock throughout.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// The sockets engine's process name on the Net.
const bindSocketsEngine = "sockets"

// The sidecar_id claim of a client token, read unverified as a sidecar reads its claims, "" for none.
func bindSocketsSidecarClaim(t *testing.T, byJwt string) string {
	t.Helper()
	parts := strings.Split(byJwt, ".")
	if len(parts) != 3 {
		t.Fatal("not a token")
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		t.Fatal(err)
	}
	sidecarId, _ := claims["sidecar_id"].(string)
	return sidecarId
}

// GET /socket/list at the Net's sockets engine, presenting byJwt, through SidecarApi on settings.
func bindSocketsList(t *testing.T, net *sidecartest.Net, settings *sidecar.SidecarSettings, byJwt string) *sidecar.SocketListResult {
	t.Helper()
	// no sockets route takes a proof, so any ClientKey serves
	seed := make([]byte, ed25519.SeedSize)
	client, err := sidecar.NewSidecarApiWithClientKey(settings, net.EngineClient(bindSocketsEngine).Transport, byJwt, seed, net.Clock().Now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SocketList(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// The adopted token is admitted where the enrollment's is denied, and so is its refresh.
func TestAdoptedTokenIsAdmittedBySockets(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	if err := net.Fakes().Gates.Set("sidecar:\n  sockets: {enabled: true, percent: 100}\n"); err != nil {
		t.Fatal(err)
	}
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	_, err = net.AddEngine(bindSocketsEngine, func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		// server's sockets block: Client-class tokens for its audience, service tokens for the rest
		hostCopy := *host
		hostCopy.Authenticator = api.ClientTokenAuthenticator(socketsservice.SocketsAudience, host.Authenticator)
		store := sidecartest.NewFakeSocketStore(net.Clock(), nil, nil)
		// GET /socket/list asks the gate nothing (socketsservice/list.go)
		return socketsservice.NewSocketsService(ctx, &hostCopy, store, socketsservice.ClosedSocketGate{}, socketsservice.DefaultSocketsSettings())
	})
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := laptop.NetworkRecord()
	if !ok {
		t.Fatal("no network record")
	}

	tokens := api.ClientTokens(record.ClientId)
	held := sidecar.SidecarByJwtForTest(laptop.Sidecar())
	if len(tokens) != 2 || held != tokens[1] {
		t.Fatalf("the sidecar does not hold bind's re-mint of its %d tokens", len(tokens))
	}
	enrolled := tokens[0]
	if bindSocketsSidecarClaim(t, held) != record.SidecarId.String() || bindSocketsSidecarClaim(t, enrolled) != "" {
		t.Fatal("the adopted token does not name the sidecar, or the enrollment's does")
	}

	if before := bindSocketsList(t, net, laptop.Settings, enrolled); before.Error == nil || before.Error.Code != sidecar.SocketErrorCodeDenied {
		t.Errorf("the enrollment's token: %+v", before.Error)
	}
	if after := bindSocketsList(t, net, laptop.Settings, held); after.Error != nil || after.Names == nil {
		t.Errorf("the adopted token: %+v", after.Error)
	}

	// connect's report of a refused credential asks for a refresh, which keeps the claim
	count := api.ClientTokenCount(record.ClientId)
	laptop.CloseAuthorization()
	deadline := time.After(30 * time.Second)
	for api.ClientTokenCount(record.ClientId) <= count {
		// subscribed before the read, so a mint between them wakes the wait
		_, minted := api.Mints()
		if count < api.ClientTokenCount(record.ClientId) {
			break
		}
		select {
		case <-minted:
		case <-deadline:
			t.Fatal("no refresh was minted")
		}
	}
	refreshed := api.ClientTokens(record.ClientId)[count]
	if bindSocketsSidecarClaim(t, refreshed) != record.SidecarId.String() {
		t.Fatal("the refresh dropped the claim")
	}
	if renewed := bindSocketsList(t, net, laptop.Settings, refreshed); renewed.Error != nil {
		t.Errorf("the refreshed token: %+v", renewed.Error)
	}
}
