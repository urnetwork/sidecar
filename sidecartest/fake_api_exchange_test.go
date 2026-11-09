// The fake api's token exchange on T2, §22.5's §7 row as TEAM-M1-06 runs it on server: a copied token fails, an
// expired subject is refused, a replayed proof is refused, the api audience is never issued, a 65th repo: scope is
// refused; and what the fake adds for schedules: no scope without a projection, the scope source seam, a removed
// client, re-seed mode, a proof that names another request, and the tokens the Net's engines take.

package sidecartest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// A client of a fake api with its ClientKey bound, ready to exchange its token.
type fakeApiExchangeFixture struct {
	t         *testing.T
	ctx       context.Context
	clock     *FakeClock
	api       *FakeApi
	networkId sidecar.Id
	clientId  sidecar.Id
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
	token     string
	jtiCount  int
}

func newFakeApiExchangeFixture(t *testing.T) *fakeApiExchangeFixture {
	world := newFakeApiTestWorld(t)
	return newFakeApiExchangeFixtureOn(t, world.ctx, world.clock, world.api)
}

func newFakeApiExchangeFixtureOn(t *testing.T, ctx context.Context, clock *FakeClock, api *FakeApi) *fakeApiExchangeFixture {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	self := &fakeApiExchangeFixture{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		api:       api,
		networkId: configLogSuiteId(),
		clientId:  configLogSuiteId(),
		sidecarId: configLogSuiteId(),
		key:       key,
	}
	self.token = api.ClientToken(self.networkId, self.clientId, self.sidecarId)
	api.BindClientKey(self.clientId, key.Public().(ed25519.PublicKey))
	return self
}

// A DPoP proof in the layout api_dpop.go signs: header and claims with their keys sorted, iat in whole seconds.
func fakeApiTestProof(key ed25519.PrivateKey, method string, htu string, token string, jti string, iat int64) string {
	jwk := map[string]string{"crv": "Ed25519", "kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "jwk": jwk, "typ": "dpop+jwt"})
	hash := sha256.Sum256([]byte(token))
	claims, _ := json.Marshal(map[string]any{
		"ath": base64.RawURLEncoding.EncodeToString(hash[:]),
		"htm": method,
		"htu": htu,
		"iat": iat,
		"jti": jti,
	})
	return fakeApiTestSign(key, header, claims)
}

// The compact JWS of header and claims, signed by key.
func fakeApiTestSign(key ed25519.PrivateKey, header []byte, claims []byte) string {
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signingInput)))
}

// A fresh jti.
func (self *fakeApiExchangeFixture) jti() string {
	self.jtiCount += 1
	return fmt.Sprintf("fixture-jti-%d", self.jtiCount)
}

// A good proof of this client's exchange, by its key, now.
func (self *fakeApiExchangeFixture) proof() string {
	return fakeApiTestProof(self.key, http.MethodPost, self.api.TokenEndpoint(), self.token, self.jti(), self.clock.Now().Unix())
}

// The exchange's form for the client's token, resource and scopes.
func (self *fakeApiExchangeFixture) form(resource string, scopes ...string) url.Values {
	form := url.Values{
		"grant_type":         {FakeApiExchangeGrantType},
		"subject_token":      {self.token},
		"subject_token_type": {FakeApiExchangeSubjectTokenType},
		"resource":           {resource},
	}
	if 0 < len(scopes) {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return form
}

// One POST of form to the token endpoint through the api's transport, with the proofs and bearer given. The reply's
// JSON is decoded into result when 200, and returned as a map otherwise.
func (self *fakeApiExchangeFixture) post(form url.Values, proofs []string, bearer string, result any) (int, map[string]any) {
	self.t.Helper()
	request, err := http.NewRequestWithContext(self.ctx, http.MethodPost, self.api.TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		self.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, proof := range proofs {
		request.Header.Add("DPoP", proof)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := self.api.Transport().RoundTrip(request)
	if err != nil {
		self.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	if response.StatusCode == http.StatusOK {
		if result != nil {
			if err := json.Unmarshal(body, result); err != nil {
				self.t.Fatal(err)
			}
		}
		return response.StatusCode, nil
	}
	refusal := map[string]any{}
	json.Unmarshal(body, &refusal)
	return response.StatusCode, refusal
}

// Exchanges for resource and scopes with a good proof, expecting a token.
func (self *fakeApiExchangeFixture) exchange(resource string, scopes ...string) *fakeApiExchangeResult {
	self.t.Helper()
	result := &fakeApiExchangeResult{}
	if status, refusal := self.post(self.form(resource, scopes...), []string{self.proof()}, "", result); status != http.StatusOK {
		self.t.Fatalf("the exchange: %d %v", status, refusal)
	}
	return result
}

// Exchanges form with the proofs given and expects a 400 with code.
func (self *fakeApiExchangeFixture) refused(name string, form url.Values, proofs []string, code string) {
	self.t.Helper()
	status, refusal := self.post(form, proofs, "", nil)
	if status != http.StatusBadRequest || refusal["error"] != code {
		self.t.Errorf("%s: %d %v, not %s", name, status, refusal, code)
	}
}

// A token with no scope names its client, its sidecar and the one audience asked, lives 15 minutes, and authenticates
// for that audience alone.
func TestFakeApiExchangeMintsAServiceTokenForItsClient(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	issueTime := fixture.clock.Now()
	result := fixture.exchange(fixture.api.ServiceOrigin("evs"))
	if result.TokenType != "Bearer" || result.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" || result.ExpiresIn != 15*60 || result.Scope != "" {
		t.Errorf("the answer: %+v", result)
	}
	principal, err := fixture.api.Authenticator().Authenticate(fixture.ctx, "evs", result.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.NetworkId != connect.Id(fixture.networkId) || principal.ClientId != connect.Id(fixture.clientId) ||
		principal.SidecarId == nil || *principal.SidecarId != connect.Id(fixture.sidecarId) || principal.SubjectClientId != nil ||
		principal.MemberId != nil || principal.Audience != "evs" || len(principal.Scopes) != 0 || principal.ProjVersion != 0 {
		t.Errorf("the principal: %+v", principal)
	}
	if !principal.IssuedAt.Equal(issueTime) || !principal.ExpiresAt.Equal(issueTime.Add(15*time.Minute)) {
		t.Errorf("issued %v, expires %v", principal.IssuedAt, principal.ExpiresAt)
	}
	if _, err := fixture.api.Authenticator().Authenticate(fixture.ctx, "gkm", result.AccessToken); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("another audience: %v", err)
	}
	fixture.clock.Advance(15 * time.Minute)
	if _, err := fixture.api.Authenticator().Authenticate(fixture.ctx, "evs", result.AccessToken); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("past 15 minutes: %v", err)
	}
}

// Until a projection's source is installed the exchange grants no scope, as server's does: a repo: or recovery:
// scope, or any other, is refused.
func TestFakeApiExchangeGrantsNoScopeWithoutAProjection(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	for _, scope := range []string{"repo:" + configLogSuiteId().String() + ":r", "recovery:" + configLogSuiteId().String(), "directory"} {
		fixture.refused(scope, fixture.form(fixture.api.ServiceOrigin("gkm"), scope), []string{fixture.proof()}, "invalid_scope")
	}
}

// A copied token fails: a proof by another key, no proof, two proofs, and a client with no key bound are each refused.
func TestFakeApiExchangeRefusesACopiedToken(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	resource := fixture.api.ServiceOrigin("evs")
	_, copier, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copied := fakeApiTestProof(copier, http.MethodPost, fixture.api.TokenEndpoint(), fixture.token, fixture.jti(), fixture.clock.Now().Unix())
	fixture.refused("another key's proof", fixture.form(resource), []string{copied}, "invalid_dpop_proof")
	fixture.refused("no proof", fixture.form(resource), nil, "invalid_dpop_proof")
	fixture.refused("two proofs", fixture.form(resource), []string{fixture.proof(), fixture.proof()}, "invalid_dpop_proof")

	unbound := newFakeApiExchangeFixtureOn(t, fixture.ctx, fixture.clock, fixture.api)
	unbound.clientId = configLogSuiteId()
	unbound.token = fixture.api.ClientToken(unbound.networkId, unbound.clientId, unbound.sidecarId)
	unbound.refused("no bound key", unbound.form(resource), []string{unbound.proof()}, "invalid_dpop_proof")

	// a rebind replaces the key: the old one's proof no longer passes
	_, rebound, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.api.BindClientKey(fixture.clientId, rebound.Public().(ed25519.PublicKey))
	fixture.refused("the old binding's key", fixture.form(resource), []string{fixture.proof()}, "invalid_dpop_proof")
	fixture.key = rebound
	fixture.exchange(resource)
}

// A replayed proof is refused, and a proof refused for another reason spends no jti.
func TestFakeApiExchangeRefusesAReplayedProof(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	resource := fixture.api.ServiceOrigin("dns")
	proof := fixture.proof()
	if status, refusal := fixture.post(fixture.form(resource), []string{proof}, "", nil); status != http.StatusOK {
		t.Fatalf("the first use: %d %v", status, refusal)
	}
	fixture.refused("the replay", fixture.form(resource), []string{proof}, "invalid_dpop_proof")

	jti := fixture.jti()
	elsewhere := fakeApiTestProof(fixture.key, http.MethodPost, fixture.api.Origin()+"/oauth/token", fixture.token, jti, fixture.clock.Now().Unix())
	fixture.refused("a proof for api's origin", fixture.form(resource), []string{elsewhere}, "invalid_dpop_proof")
	here := fakeApiTestProof(fixture.key, http.MethodPost, fixture.api.TokenEndpoint(), fixture.token, jti, fixture.clock.Now().Unix())
	if status, refusal := fixture.post(fixture.form(resource), []string{here}, "", nil); status != http.StatusOK {
		t.Errorf("the jti a refused proof named: %d %v", status, refusal)
	}

	// a spent jti is kept past the iat window, so its proof cannot come back
	fixture.clock.Advance(59 * time.Second)
	fixture.refused("the replay 59 s on", fixture.form(resource), []string{here}, "invalid_dpop_proof")
}

// A subject token past its 7-day exp is refused, as server refuses it whatever reject_expired says, and every route
// refuses it as a bearer.
func TestFakeApiExchangeRefusesAnExpiredSubject(t *testing.T) {
	world := newFakeApiTestWorld(t)
	fixture := newFakeApiExchangeFixtureOn(t, world.ctx, world.clock, world.api)
	fixture.clock.Advance(7*24*time.Hour - time.Second)
	fixture.exchange(fixture.api.ServiceOrigin("evs"))
	fixture.clock.Advance(time.Second)
	fixture.refused("an expired subject", fixture.form(fixture.api.ServiceOrigin("evs")), []string{fixture.proof()}, "invalid_grant")
	if status, _, err := world.call(http.MethodGet, "/network/config/projection?after=0", fixture.token, nil, nil); err != nil || status != http.StatusUnauthorized {
		t.Errorf("an expired bearer: %d %v", status, err)
	}
}

// The api audience is never issued, nor one no service has; the exchange takes exactly one resource, an origin.
func TestFakeApiExchangeNeverIssuesTheApiAudience(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	resources := []string{
		fixture.api.Origin(),
		"https://api." + fixture.api.settings.ServiceDomain + "/",
		"https://API." + fixture.api.settings.ServiceDomain,
		fixture.api.ServiceOrigin("billing"),
		"http://evs." + fixture.api.settings.ServiceDomain,
		fixture.api.ServiceOrigin("evs") + "/evs/v1",
		fixture.api.ServiceOrigin("evs") + "?scope=all",
		"https://evs.another.example",
		"",
	}
	for _, resource := range resources {
		fixture.refused(resource, fixture.form(resource), []string{fixture.proof()}, "invalid_target")
	}
	two := fixture.form(fixture.api.ServiceOrigin("evs"))
	two.Add("resource", fixture.api.ServiceOrigin("gkm"))
	fixture.refused("two resources", two, []string{fixture.proof()}, "invalid_target")
	none := fixture.form(fixture.api.ServiceOrigin("evs"))
	none.Del("resource")
	fixture.refused("no resource", none, []string{fixture.proof()}, "invalid_target")
	for _, audience := range []string{"evs", "gkm", "dns", "certs", "mail"} {
		result := fixture.exchange(fixture.api.ServiceOrigin(audience) + "/")
		if _, err := fixture.api.Authenticator().Authenticate(fixture.ctx, audience, result.AccessToken); err != nil {
			t.Errorf("%s: %v", audience, err)
		}
	}
}

// A 65th repo: scope is refused before any source sees it, and 64 pass to a source that grants them; a repeated scope
// counts once.
func TestFakeApiExchangeRefusesA65thRepoScope(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	fixture.api.SetExchangeScopeSource(func(ctx context.Context, request *FakeApiScopeRequest) (*FakeApiScopeGrant, error) {
		return &FakeApiScopeGrant{Scopes: request.Scopes}, nil
	})
	scopes := []string{}
	for range 65 {
		scopes = append(scopes, "repo:"+configLogSuiteId().String()+":r")
	}
	fixture.refused("65 repo: scopes", fixture.form(fixture.api.ServiceOrigin("evs"), scopes...), []string{fixture.proof()}, "invalid_scope")
	repeated := append(slices.Clone(scopes[:64]), scopes[0], "recovery:"+configLogSuiteId().String())
	result := fixture.exchange(fixture.api.ServiceOrigin("evs"), repeated...)
	principal, err := fixture.api.Authenticator().Authenticate(fixture.ctx, "evs", result.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(principal.Scopes) != 65 || !slices.Equal(principal.Scopes[:64], scopes[:64]) || len(strings.Fields(result.Scope)) != 65 {
		t.Errorf("granted %d scopes", len(principal.Scopes))
	}
	fixture.refused("a scope that is no scope-token", fixture.form(fixture.api.ServiceOrigin("evs"), "repo:\"x\""), []string{fixture.proof()}, "invalid_scope")
}

// The source sees who asks and for what, and its grant becomes the token's claims; a refusal is invalid_scope, a grant
// past the request a server error, and a nil source restores the one that grants nothing.
func TestFakeApiExchangeTakesItsScopesFromTheSource(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	repoId := configLogSuiteId()
	memberId := configLogSuiteId()
	asked := []string{"repo:" + repoId.String() + ":rw", "repo:" + repoId.String() + ":admin"}
	var seen *FakeApiScopeRequest
	fixture.api.SetExchangeScopeSource(func(ctx context.Context, request *FakeApiScopeRequest) (*FakeApiScopeGrant, error) {
		seen = request
		if slices.Contains(request.Scopes, "recovery:"+memberId.String()) {
			return nil, fmt.Errorf("%w: not at this audience", ErrFakeApiInvalidScope)
		}
		if slices.Contains(request.Scopes, "repo:"+repoId.String()+":r") {
			return &FakeApiScopeGrant{Scopes: []string{"repo:" + repoId.String() + ":deposit"}}, nil
		}
		return &FakeApiScopeGrant{Scopes: request.Scopes[:1], ProjVersion: 7, MemberId: &memberId}, nil
	})
	result := fixture.exchange(fixture.api.ServiceOrigin("gkm"), asked...)
	if seen == nil || seen.NetworkId != fixture.networkId || seen.ClientId != fixture.clientId || seen.SubjectClientId != fixture.clientId ||
		seen.SidecarId == nil || *seen.SidecarId != fixture.sidecarId || seen.Audience != "gkm" || !slices.Equal(seen.Scopes, asked) {
		t.Errorf("the source saw %+v", seen)
	}
	principal, err := fixture.api.Authenticator().Authenticate(fixture.ctx, "gkm", result.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(principal.Scopes, asked[:1]) || result.Scope != asked[0] || principal.ProjVersion != 7 ||
		principal.MemberId == nil || *principal.MemberId != connect.Id(memberId) {
		t.Errorf("the principal: %+v", principal)
	}
	fixture.refused("the source's refusal", fixture.form(fixture.api.ServiceOrigin("gkm"), "recovery:"+memberId.String()), []string{fixture.proof()}, "invalid_scope")
	status, refusal := fixture.post(fixture.form(fixture.api.ServiceOrigin("gkm"), "repo:"+repoId.String()+":r"), []string{fixture.proof()}, "", nil)
	if status != http.StatusInternalServerError || refusal["error"] != "server_error" {
		t.Errorf("a grant past the request: %d %v", status, refusal)
	}
	fixture.api.SetExchangeScopeSource(nil)
	fixture.refused("the source removed", fixture.form(fixture.api.ServiceOrigin("gkm"), asked...), []string{fixture.proof()}, "invalid_scope")
}

// A removed client's token buys nothing, and no route takes it.
func TestFakeApiExchangeRefusesARemovedClient(t *testing.T) {
	world := newFakeApiTestWorld(t)
	fixture := newFakeApiExchangeFixtureOn(t, world.ctx, world.clock, world.api)
	fixture.exchange(fixture.api.ServiceOrigin("evs"))
	fixture.api.RemoveClient(fixture.clientId)
	fixture.refused("a removed client", fixture.form(fixture.api.ServiceOrigin("evs")), []string{fixture.proof()}, "invalid_grant")
	if status, _, err := world.call(http.MethodGet, "/network/config/projection?after=0", fixture.token, nil, nil); err != nil || status != http.StatusUnauthorized {
		t.Errorf("a removed client's bearer: %d %v", status, err)
	}
}

// Re-seed mode holds the exchange with restore_required, and lifting it lets it through.
func TestFakeApiExchangeAnswersRestoreRequiredInReseed(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	fixture.api.SetReseed(true)
	fixture.refused("in re-seed mode", fixture.form(fixture.api.ServiceOrigin("evs")), []string{fixture.proof()}, "restore_required")
	fixture.api.SetReseed(false)
	fixture.exchange(fixture.api.ServiceOrigin("evs"))
}

// A proof must name this request, by this key, now: each of these is refused.
func TestFakeApiExchangeRefusesAProofOfAnotherRequest(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	endpoint := fixture.api.TokenEndpoint()
	now := fixture.clock.Now().Unix()
	jwk := map[string]string{"crv": "Ed25519", "kty": "OKP", "x": base64.RawURLEncoding.EncodeToString(fixture.key.Public().(ed25519.PublicKey))}
	hash := sha256.Sum256([]byte(fixture.token))
	ath := base64.RawURLEncoding.EncodeToString(hash[:])
	signed := func(header map[string]any, claims map[string]any) string {
		headerBytes, _ := json.Marshal(header)
		claimsBytes, _ := json.Marshal(claims)
		return fakeApiTestSign(fixture.key, headerBytes, claimsBytes)
	}
	goodHeader := map[string]any{"alg": "EdDSA", "jwk": jwk, "typ": "dpop+jwt"}
	claimsOf := func(jti string) map[string]any {
		return map[string]any{"ath": ath, "htm": "POST", "htu": endpoint, "iat": now, "jti": jti}
	}
	with := func(name string, value any) string {
		claims := claimsOf(fixture.jti())
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
		return signed(goodHeader, claims)
	}
	privateJwk := map[string]string{"crv": "Ed25519", "kty": "OKP", "x": jwk["x"], "d": base64.RawURLEncoding.EncodeToString(fixture.key.Seed())}
	badSignature := signed(goodHeader, claimsOf(fixture.jti()))
	badSignature = badSignature[:strings.LastIndex(badSignature, ".")+1] + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	cases := []struct {
		name  string
		proof string
	}{
		{name: "htm GET", proof: with("htm", "GET")},
		{name: "htu at api's origin", proof: with("htu", fixture.api.Origin()+"/oauth/token")},
		{name: "htu over http", proof: with("htu", strings.Replace(endpoint, "https://", "http://", 1))},
		{name: "htu at another path", proof: with("htu", fixture.api.AuthOrigin()+"/oauth/register")},
		{name: "ath of another token", proof: with("ath", base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)))},
		{name: "no ath", proof: with("ath", nil)},
		{name: "iat 61 s old", proof: with("iat", now-61)},
		{name: "iat 61 s ahead", proof: with("iat", now+61)},
		{name: "no iat", proof: with("iat", nil)},
		{name: "no jti", proof: with("jti", nil)},
		{name: "a jti past 256 bytes", proof: with("jti", strings.Repeat("j", 257))},
		{name: "typ jwt", proof: signed(map[string]any{"alg": "EdDSA", "jwk": jwk, "typ": "jwt"}, claimsOf(fixture.jti()))},
		{name: "alg none", proof: signed(map[string]any{"alg": "none", "jwk": jwk, "typ": "dpop+jwt"}, claimsOf(fixture.jti()))},
		{name: "a private jwk", proof: signed(map[string]any{"alg": "EdDSA", "jwk": privateJwk, "typ": "dpop+jwt"}, claimsOf(fixture.jti()))},
		{name: "no jwk", proof: signed(map[string]any{"alg": "EdDSA", "typ": "dpop+jwt"}, claimsOf(fixture.jti()))},
		{name: "a bad signature", proof: badSignature},
		{name: "not a JWS", proof: "not-a-proof"},
	}
	for _, c := range cases {
		fixture.refused(c.name, fixture.form(fixture.api.ServiceOrigin("evs")), []string{c.proof}, "invalid_dpop_proof")
	}
	for _, offset := range []int64{-60, 60} {
		proof := with("iat", now+offset)
		if status, refusal := fixture.post(fixture.form(fixture.api.ServiceOrigin("evs")), []string{proof}, "", nil); status != http.StatusOK {
			t.Errorf("iat %d s off: %d %v", offset, status, refusal)
		}
	}
	defaultPort := fakeApiTestProof(fixture.key, http.MethodPost, strings.Replace(endpoint, ".example/", ".example:443/", 1)+"?q=1", fixture.token, fixture.jti(), now)
	if status, refusal := fixture.post(fixture.form(fixture.api.ServiceOrigin("evs")), []string{defaultPort}, "", nil); status != http.StatusOK {
		t.Errorf("htu with https's port and a query: %d %v", status, refusal)
	}
}

// The token route is the exchange alone: a sidecar's bearer is refused there as off its allowlist, another grant is
// unsupported, and a form that names no client token is malformed.
func TestFakeApiTokenRouteServesTheExchangeAlone(t *testing.T) {
	fixture := newFakeApiExchangeFixture(t)
	status, refusal := fixture.post(fixture.form(fixture.api.ServiceOrigin("evs")), []string{fixture.proof()}, fixture.token, nil)
	if status != http.StatusForbidden || refusal["error"] != fakeApiStrictExpRefusedText {
		t.Errorf("a sidecar bearer: %d %v", status, refusal)
	}
	other := fixture.form(fixture.api.ServiceOrigin("evs"))
	other.Set("grant_type", "refresh_token")
	fixture.refused("a refresh grant", other, []string{fixture.proof()}, "unsupported_grant_type")
	untyped := fixture.form(fixture.api.ServiceOrigin("evs"))
	untyped.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	fixture.refused("another subject type", untyped, []string{fixture.proof()}, "invalid_request")
	unknown := fixture.form(fixture.api.ServiceOrigin("evs"))
	unknown.Set("subject_token", "fake-client-token-"+strconv.Itoa(1000))
	fixture.refused("an unknown subject", unknown, []string{fixture.proof()}, "invalid_grant")
}

// A lost answer leaves the client with no token and its proof spent: its next send, with a new proof, gets one.
func TestFakeApiExchangeLostAnswerIsRetriedWithANewProof(t *testing.T) {
	world := newFakeApiTestWorld(t)
	fixture := newFakeApiExchangeFixtureOn(t, world.ctx, world.clock, world.api)
	fired, err := world.faults.Add(&FaultPlan{Op: FaultOpHttp, KeyPrefix: "/oauth/token", Result: ApplyThenDrop})
	if err != nil {
		t.Fatal(err)
	}
	proof := fixture.proof()
	request, err := http.NewRequestWithContext(world.ctx, http.MethodPost, fixture.api.TokenEndpoint(), strings.NewReader(fixture.form(fixture.api.ServiceOrigin("evs")).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", proof)
	if _, err := fixture.api.Transport().RoundTrip(request); !errors.Is(err, errFakeApiTransport) {
		t.Fatalf("the lost answer: %v", err)
	}
	<-fired
	fixture.refused("the same proof again", fixture.form(fixture.api.ServiceOrigin("evs")), []string{proof}, "invalid_dpop_proof")
	fixture.exchange(fixture.api.ServiceOrigin("evs"))
}

// The Net's api mints with the Net host's authenticator, so its engines take the tokens.
func TestNetApiMintsTokensTheNetsEnginesTake(t *testing.T) {
	net := NewNet(context.Background(), nil)
	defer net.Close()
	api, err := net.AddApi(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newFakeApiExchangeFixtureOn(t, net.Context(), net.Clock(), api)
	result := fixture.exchange(api.ServiceOrigin("gkm"))
	principal, err := net.Host().Authenticate(net.Context(), "gkm", result.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ClientId != connect.Id(fixture.clientId) {
		t.Errorf("the principal names %s", principal.ClientId)
	}
	if _, err := net.Host().Authenticate(net.Context(), "evs", result.AccessToken); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("another audience at the engines: %v", err)
	}
}
