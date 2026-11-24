// The engine world's own seams on an admission network whose log api holds: the exchange's scopes come from the gate's
// state of the token's network, refused as api's exchange refuses them (server/oauth/exchange_scopes.go): a network
// the gate has not loaded, a bootstrapping one before its base 1 among them, answers temporarily_unavailable and is
// asked for; a client the state does not admit, not yet or no longer, invalid_grant whatever it asks; and a request
// none of whose scopes the state grants, a grant not at the gate yet among them, invalid_scope. A network's bootstrap
// past KF1 on these engines is the daemon's test (cli/daemon_clients_evs_test.go), whose key client and follower are
// the daemon's own.

package enginenet

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An admission network whose log the Net's api holds, and the engines over the Net: the gate has not loaded the
// network yet.
type enginesTestWorld struct {
	t       *testing.T
	ctx     context.Context
	net     *sidecartest.Net
	network *sidecartest.AdmissionNet
	engines *Engines
}

func newEnginesTestWorld(t *testing.T) *enginesTestWorld {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	network := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(network.Close)
	return &enginesTestWorld{t: t, ctx: ctx, net: net, network: network, engines: NewEngines(t, net, nil)}
}

// Has the gate hold api's tip of the network.
func (self *enginesTestWorld) sync() {
	self.t.Helper()
	if err := self.engines.Sync(self.ctx, self.network.NetworkId()); err != nil {
		self.t.Fatal(err)
	}
}

// The source's answer to sidecarId, nil for a client bound to none, asking scopes at audience.
func (self *enginesTestWorld) ask(sidecarId *sidecar.Id, audience string, scopes ...string) (*sidecartest.FakeApiScopeGrant, error) {
	return self.engines.exchangeScopes(self.ctx, &sidecartest.FakeApiScopeRequest{
		NetworkId: self.network.NetworkId(), ClientId: sidecar.NewId(), SidecarId: sidecarId, Audience: audience, Scopes: scopes,
	})
}

// Fails the test unless the source refuses sidecarId's ask with want, and with none of the exchange's other codes.
func (self *enginesTestWorld) refused(name string, want error, sidecarId *sidecar.Id, audience string, scopes ...string) {
	self.t.Helper()
	grant, err := self.ask(sidecarId, audience, scopes...)
	for _, code := range []error{sidecartest.ErrFakeApiInvalidGrant, sidecartest.ErrFakeApiInvalidScope, sidecartest.ErrFakeApiExchangeUnavailable} {
		if errors.Is(err, code) != (code == want) {
			self.t.Errorf("%s: %+v %v, want %v", name, grant, err, want)
			return
		}
	}
}

// Fails the test unless the source grants sidecarId's ask exactly want, at the tip's position, naming memberId.
func (self *enginesTestWorld) granted(name string, want []string, memberId sidecar.Id, sidecarId *sidecar.Id, audience string, scopes ...string) {
	self.t.Helper()
	grant, err := self.ask(sidecarId, audience, scopes...)
	if err != nil {
		self.t.Errorf("%s: %v", name, err)
		return
	}
	tip := self.network.Tip().GetVersion()
	if !slices.Equal(grant.Scopes, want) || grant.ProjVersion != tip || grant.MemberId == nil || *grant.MemberId != memberId {
		self.t.Errorf("%s: %v at %d naming %v, want %v at %d naming %s", name, grant.Scopes, grant.ProjVersion, grant.MemberId, want, tip, memberId)
	}
}

// The scope repo:<repoId>:<role>.
func enginesTestScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// A client of the Net's api bound to a sidecar, its ClientKey bound, which exchanges its token at the token endpoint
// with a proof of each request, as SidecarApi.ExchangeToken sends it.
type enginesTestClient struct {
	world    *enginesTestWorld
	token    string
	key      ed25519.PrivateKey
	jtiCount int
}

func (self *enginesTestWorld) client(sidecarId sidecar.Id) *enginesTestClient {
	seed := sha256.Sum256([]byte("enginenet test client " + sidecarId.String()))
	key := ed25519.NewKeyFromSeed(seed[:])
	clientId := sidecar.NewId()
	api := self.engines.Api()
	api.BindClientKey(clientId, key.Public().(ed25519.PublicKey))
	return &enginesTestClient{world: self, token: api.ClientToken(self.network.NetworkId(), clientId, sidecarId), key: key}
}

// The exchange's answer to scopes at audience: its status, and the token's granted scopes on a 200 or the refusal's
// code otherwise.
func (self *enginesTestClient) exchange(audience string, scopes ...string) (int, []string, string) {
	t := self.world.t
	t.Helper()
	api := self.world.engines.Api()
	form := url.Values{
		"grant_type":         {sidecartest.FakeApiExchangeGrantType},
		"subject_token":      {self.token},
		"subject_token_type": {sidecartest.FakeApiExchangeSubjectTokenType},
		"resource":           {api.ServiceOrigin(audience)},
	}
	if 0 < len(scopes) {
		form.Set("scope", strings.Join(scopes, " "))
	}
	request, err := http.NewRequestWithContext(self.world.ctx, http.MethodPost, api.TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", self.proof(api.TokenEndpoint()))
	response, err := api.Transport().RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	answer := struct {
		Scope string `json:"scope"`
		Error string `json:"error"`
	}{}
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatalf("the exchange's answer %d: %v", response.StatusCode, err)
	}
	return response.StatusCode, strings.Fields(answer.Scope), answer.Error
}

// A DPoP proof of a POST to htu over the client's token, by its key, now on the api's clock: header and claims as
// api_dpop.go signs them, iat in whole seconds, a fresh jti.
func (self *enginesTestClient) proof(htu string) string {
	self.jtiCount += 1
	jwk := map[string]string{"crv": "Ed25519", "kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(self.key.Public().(ed25519.PublicKey))}
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "jwk": jwk, "typ": "dpop+jwt"})
	hash := sha256.Sum256([]byte(self.token))
	claims, _ := json.Marshal(map[string]any{
		"ath": base64.RawURLEncoding.EncodeToString(hash[:]),
		"htm": http.MethodPost,
		"htu": htu,
		"iat": self.world.net.Clock().Now().Unix(),
		"jti": fmt.Sprintf("enginenet-test-jti-%d", self.jtiCount),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(self.key, []byte(signingInput)))
}

// The exchange's scopes for the owner's device: refused temporarily_unavailable until the gate holds the network, then
// §8's table at the gate's state, which grants the config's r and leaves out a repo the state does not hold.
func TestEnginesScopesComeFromTheGatesState(t *testing.T) {
	world := newEnginesTestWorld(t)
	network := world.network
	owner := network.Owner()
	configScope := enginesTestScope(network.ConfigRepoId(), "r")
	unknownScope := enginesTestScope(sidecar.NewId(), "r")
	world.refused("scopes before the gate holds the network", sidecartest.ErrFakeApiExchangeUnavailable, &owner.SidecarId, "evs", configScope, unknownScope)
	world.refused("no scope before the gate holds the network", sidecartest.ErrFakeApiExchangeUnavailable, &owner.SidecarId, "dns")
	world.sync()
	world.granted("the gate's scopes", []string{configScope}, owner.MemberId, &owner.SidecarId, "evs", configScope, unknownScope)
}

// A revoked device is refused invalid_grant once the gate holds its revocation, as api's exchange refuses it, whatever
// it asks and at every audience: not invalid_scope, which a client rides out for §8.9's 5 s (QD-1226), nor a token
// granting nothing, which a service then refuses. Until the gate holds the revocation the device is granted, as at
// api, and other devices are granted after it. On the code before, the revoked device got a 200 token granting
// nothing.
func TestEnginesExchangeRefusesARevokedDeviceInvalidGrant(t *testing.T) {
	world := newEnginesTestWorld(t)
	network := world.network
	owner := network.Owner()
	phone := network.Device("enginenet revoked phone", owner.MemberId)
	network.AdmitDevice(owner, phone, 0)
	world.sync()
	configRead := enginesTestScope(network.ConfigRepoId(), "r")
	world.granted("the phone before its revocation", []string{configRead}, owner.MemberId, &phone.SidecarId, "evs", configRead)

	network.MustLand(network.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, network.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	if grant, err := world.ask(&phone.SidecarId, "evs", configRead); err != nil || !slices.Equal(grant.Scopes, []string{configRead}) {
		t.Fatalf("the phone while the gate does not hold its revocation: %+v %v", grant, err)
	}
	world.sync()
	world.refused("the revoked phone's config r at evs", sidecartest.ErrFakeApiInvalidGrant, &phone.SidecarId, "evs", configRead)
	world.refused("the revoked phone's config r at gkm", sidecartest.ErrFakeApiInvalidGrant, &phone.SidecarId, "gkm", configRead)
	world.refused("the revoked phone's config r beside a repo it never held", sidecartest.ErrFakeApiInvalidGrant, &phone.SidecarId, "evs", configRead, enginesTestScope(sidecar.NewId(), "rw"))
	world.refused("the revoked phone's token of no scope at evs", sidecartest.ErrFakeApiInvalidGrant, &phone.SidecarId, "evs")
	world.refused("the revoked phone's token of no scope at dns", sidecartest.ErrFakeApiInvalidGrant, &phone.SidecarId, "dns")
	world.granted("the owner's device after the revocation", []string{configRead}, owner.MemberId, &owner.SidecarId, "gkm", configRead)

	// through the token endpoint, as the phone's client asks it
	phoneClient := world.client(phone.SidecarId)
	for _, audience := range []string{"evs", "gkm"} {
		if status, scopes, code := phoneClient.exchange(audience, configRead); status != http.StatusBadRequest || code != "invalid_grant" {
			t.Errorf("the revoked phone's exchange at %s: %d %v %q", audience, status, scopes, code)
		}
	}
	if status, scopes, code := world.client(owner.SidecarId).exchange("evs", configRead); status != http.StatusOK || !slices.Equal(scopes, []string{configRead}) {
		t.Errorf("the owner's exchange: %d %v %q", status, scopes, code)
	}
}

// A client the gate's state does not admit is refused invalid_grant whatever it asks, as api's exchange refuses an
// unadmitted client: one bound to no sidecar, one bound to a sidecar the state never admitted, and a device whose
// admission has landed in the log but is not at the gate yet, which is granted once the gate holds it. The
// recovery:<M> scope, which api grants an unadmitted client of member M at gkm, is not modeled here and is refused
// too. On the code before, each got a 200 token, or invalid_scope where a client bound to no sidecar asked a scope.
func TestEnginesExchangeRefusesAClientTheGateDoesNotAdmit(t *testing.T) {
	world := newEnginesTestWorld(t)
	network := world.network
	owner := network.Owner()
	world.sync()
	configRead := enginesTestScope(network.ConfigRepoId(), "r")
	stranger := sidecar.NewId()
	for _, audience := range []string{"evs", "gkm", "dns"} {
		world.refused("a client bound to no sidecar at "+audience, sidecartest.ErrFakeApiInvalidGrant, nil, audience)
		world.refused("a sidecar the state never admitted at "+audience, sidecartest.ErrFakeApiInvalidGrant, &stranger, audience)
	}
	world.refused("a client bound to no sidecar asking the config's r", sidecartest.ErrFakeApiInvalidGrant, nil, "evs", configRead)
	world.refused("a sidecar the state never admitted asking the config's r", sidecartest.ErrFakeApiInvalidGrant, &stranger, "evs", configRead)
	world.refused("an unadmitted client's recovery scope", sidecartest.ErrFakeApiInvalidGrant, &stranger, "gkm", "recovery:"+owner.MemberId.String())

	phone := network.Device("enginenet late phone", owner.MemberId)
	network.AdmitDevice(owner, phone, 0)
	world.refused("a device whose admission is not at the gate yet", sidecartest.ErrFakeApiInvalidGrant, &phone.SidecarId, "evs", configRead)
	phoneClient := world.client(phone.SidecarId)
	if status, scopes, code := phoneClient.exchange("evs", configRead); status != http.StatusBadRequest || code != "invalid_grant" {
		t.Errorf("the late phone's exchange: %d %v %q", status, scopes, code)
	}
	world.sync()
	world.granted("the device once the gate holds its admission", []string{configRead}, owner.MemberId, &phone.SidecarId, "evs", configRead)
	if status, scopes, code := phoneClient.exchange("evs", configRead); status != http.StatusOK || !slices.Equal(scopes, []string{configRead}) {
		t.Errorf("the phone's exchange once the gate holds it: %d %v %q", status, scopes, code)
	}
}

// A request none of whose scopes the gate's state grants is refused invalid_scope, as api's exchange refuses it, and
// one some of whose scopes it grants gets those alone: a repo the state does not hold, a repo whose creation is not at
// the gate yet until the gate holds it, a repo scope at an audience that takes none, and the config's admin to a
// device that writes no config. A request of no scope gets a token naming the sidecar's member at every audience. On
// the code before, a request granted nothing got a 200 token granting nothing.
func TestEnginesExchangeRefusesAScopeTheGateDoesNotGrant(t *testing.T) {
	world := newEnginesTestWorld(t)
	network := world.network
	owner := network.Owner()
	readOnly := network.Device("enginenet read only", owner.MemberId)
	network.AdmitDevice(owner, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	world.sync()
	configRead := enginesTestScope(network.ConfigRepoId(), "r")
	configAdmin := enginesTestScope(network.ConfigRepoId(), "admin")
	unknownRead := enginesTestScope(sidecar.NewId(), "r")

	world.refused("a repo the state does not hold", sidecartest.ErrFakeApiInvalidScope, &owner.SidecarId, "evs", unknownRead)
	world.granted("a repo the state does not hold beside one it gives", []string{configRead}, owner.MemberId, &owner.SidecarId, "evs", unknownRead, configRead)
	world.refused("a repo scope at dns", sidecartest.ErrFakeApiInvalidScope, &owner.SidecarId, "dns", configRead)
	world.refused("an admitted sidecar's recovery scope", sidecartest.ErrFakeApiInvalidScope, &owner.SidecarId, "gkm", "recovery:"+owner.MemberId.String())
	for _, audience := range []string{"evs", "gkm", "dns", "sockets"} {
		world.granted("no scope at "+audience, []string{}, owner.MemberId, &owner.SidecarId, audience)
	}
	for _, audience := range []string{"evs", "gkm"} {
		world.granted("the config's admin to its writer at "+audience, []string{configAdmin}, owner.MemberId, &owner.SidecarId, audience, configAdmin)
		world.refused("the config's admin to a read_only device at "+audience, sidecartest.ErrFakeApiInvalidScope, &readOnly.SidecarId, audience, configAdmin)
		world.granted("the config's admin beside its r to a read_only device at "+audience, []string{configRead}, owner.MemberId, &readOnly.SidecarId, audience, configAdmin, configRead)
	}

	// a grant not at the gate yet: the owner's new repo, whose admin it is once the gate holds its creation
	repoId := network.Id("enginenet late repo")
	network.MustLand(network.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: network.Header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	repoAdmin := enginesTestScope(repoId, "admin")
	world.refused("a repo whose creation is not at the gate yet", sidecartest.ErrFakeApiInvalidScope, &owner.SidecarId, "gkm", repoAdmin)
	ownerClient := world.client(owner.SidecarId)
	if status, scopes, code := ownerClient.exchange("gkm", repoAdmin); status != http.StatusBadRequest || code != "invalid_scope" {
		t.Errorf("the exchange of a repo whose creation is not at the gate yet: %d %v %q", status, scopes, code)
	}
	world.sync()
	world.granted("the repo once the gate holds its creation", []string{repoAdmin}, owner.MemberId, &owner.SidecarId, "gkm", repoAdmin)
	if status, scopes, code := ownerClient.exchange("gkm", repoAdmin); status != http.StatusOK || !slices.Equal(scopes, []string{repoAdmin}) {
		t.Errorf("the exchange once the gate holds the repo: %d %v %q", status, scopes, code)
	}
}

// Through the token endpoint, a network the gate holds no state of answers 503 temporarily_unavailable, which the
// client asks again past, and the ask has the gate load the network, so the next exchange is judged by its state. On
// the code before, it answered 500 server_error.
func TestEnginesExchangeAnswersTemporarilyUnavailableBeforeTheGateLoads(t *testing.T) {
	world := newEnginesTestWorld(t)
	network := world.network
	owner := network.Owner()
	configRead := enginesTestScope(network.ConfigRepoId(), "r")
	ownerClient := world.client(owner.SidecarId)
	loadCount, _ := world.engines.loads.Get()
	if status, scopes, code := ownerClient.exchange("evs", configRead); status != http.StatusServiceUnavailable || code != "temporarily_unavailable" {
		t.Fatalf("the exchange before the gate holds the network: %d %v %q", status, scopes, code)
	}
	// the refusal asked the gate for the network: a load finishes with no Sync to start it
	for {
		count, changed := world.engines.loads.Get()
		if loadCount < count {
			break
		}
		select {
		case <-changed:
		case <-world.ctx.Done():
			t.Fatal("the refusal did not start the network's load")
		}
	}
	world.sync()
	if status, scopes, code := ownerClient.exchange("evs", configRead); status != http.StatusOK || !slices.Equal(scopes, []string{configRead}) {
		t.Errorf("the exchange once the gate holds the network: %d %v %q", status, scopes, code)
	}
}
