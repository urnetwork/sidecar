//go:build !sidecar_http && !js

// sidecar's own client of §7.8's exchange, SidecarApi.ExchangeToken, against T2's fake api (sidecartest.FakeApi):
// the form, the DPoP proof by the ClientKey and the answer as the client writes and reads them, so a T2 schedule that
// exchanges through the fake runs the client's real bytes. Fake clock throughout.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A fake api and a client of it holding a client token, its ClientKey bound at the api.
type exchangeFakeWorld struct {
	ctx       context.Context
	clock     *sidecartest.FakeClock
	api       *sidecartest.FakeApi
	settings  *sidecar.SidecarSettings
	client    *sidecar.SidecarApi
	clientId  sidecar.Id
	sidecarId sidecar.Id
}

func newExchangeFakeWorld(t *testing.T) *exchangeFakeWorld {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	cluster, err := sidecartest.NewFakeBlobs(clock, faults, nil, sidecartest.DefaultFakeBlobsSettings()).FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	api := sidecartest.NewFakeApi(ctx, clock, faults, nil, cluster, nil)
	settings := sidecar.DefaultSidecarSettings()
	settings.ApiUrl = api.Origin()
	settings.AuthUrl = api.AuthOrigin()
	settings.PlatformUrl = "wss://connect.sidecartest.example"
	settings.EvsUrl = api.ServiceOrigin("evs")
	settings.GkmUrl = api.ServiceOrigin("gkm")
	settings.SocketsUrl = api.ServiceOrigin("sockets")
	settings.DnsUrl = api.ServiceOrigin("dns")

	clientId := sidecar.NewId()
	sidecarId := sidecar.NewId()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	api.BindClientKey(clientId, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	token := api.ClientToken(sidecar.NewId(), clientId, sidecarId)
	client, err := sidecar.NewSidecarApiWithClientKey(settings, api.Transport(), token, seed, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &exchangeFakeWorld{ctx: ctx, clock: clock, api: api, settings: settings, client: client, clientId: clientId, sidecarId: sidecarId}
}

// The code of the refusal err carries, empty for none.
func exchangeRefusalCode(err error) string {
	apiErr := &sidecar.SidecarApiError{}
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest {
		return ""
	}
	return apiErr.Code
}

// The client's exchange gets a token the fake api's authenticator takes for the audience asked, with the scopes the
// fake's source grants, and reads each refusal's code.
func TestSidecarApiExchangesTokensWithTheFakeApi(t *testing.T) {
	world := newExchangeFakeWorld(t)
	serviceToken, err := world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if serviceToken.ExpiresIn != 15*time.Minute || serviceToken.TokenType != "Bearer" || len(serviceToken.Scopes) != 0 {
		t.Errorf("the token: %v, %s, %d scopes", serviceToken.ExpiresIn, serviceToken.TokenType, len(serviceToken.Scopes))
	}
	principal, err := world.api.Authenticator().Authenticate(world.ctx, "evs", serviceToken.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ClientId != connect.Id(world.clientId) || principal.SidecarId == nil || *principal.SidecarId != connect.Id(world.sidecarId) {
		t.Errorf("the principal: %+v", principal)
	}

	repoScope := "repo:" + sidecar.NewId().String() + ":r"
	if _, err := world.client.ExchangeToken(world.ctx, world.settings.GkmUrl, []string{repoScope}); exchangeRefusalCode(err) != "invalid_scope" {
		t.Errorf("a scope with no projection: %v", err)
	}
	world.api.SetExchangeScopeSource(func(ctx context.Context, request *sidecartest.FakeApiScopeRequest) (*sidecartest.FakeApiScopeGrant, error) {
		return &sidecartest.FakeApiScopeGrant{Scopes: request.Scopes, ProjVersion: 3}, nil
	})
	scopes := []string{repoScope, "repo:" + sidecar.NewId().String() + ":rw"}
	serviceToken, err = world.client.ExchangeToken(world.ctx, world.settings.GkmUrl, scopes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(serviceToken.Scopes, scopes) {
		t.Errorf("the client read scopes %v", serviceToken.Scopes)
	}
	if principal, err := world.api.Authenticator().Authenticate(world.ctx, "gkm", serviceToken.AccessToken); err != nil || principal.ProjVersion != 3 {
		t.Errorf("the scoped token: %v", err)
	}

	world.api.SetReseed(true)
	_, err = world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil)
	if exchangeRefusalCode(err) != sidecar.SidecarApiCodeRestoreRequired {
		t.Errorf("re-seed mode: %v", err)
	}
	world.api.SetReseed(false)

	world.clock.Advance(7 * 24 * time.Hour)
	if _, err := world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil); exchangeRefusalCode(err) != "invalid_grant" {
		t.Errorf("an expired client token: %v", err)
	}
}

// A client whose ClientKey is not the bound one, as a copier of the token holds, is refused invalid_dpop_proof.
func TestSidecarApiExchangeWithAnotherKeyIsRefusedByTheFakeApi(t *testing.T) {
	world := newExchangeFakeWorld(t)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	world.api.BindClientKey(world.clientId, otherKey.Public().(ed25519.PublicKey))
	if _, err := world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil); exchangeRefusalCode(err) != "invalid_dpop_proof" {
		t.Errorf("another key's proof: %v", err)
	}
}
