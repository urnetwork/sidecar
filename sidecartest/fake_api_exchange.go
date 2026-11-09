// §7.8's token exchange on the fake api (RFC 8693): a sidecar trades its client token for a 15-minute service token
// for evs, gkm, dns, certs or mail.
//
//	POST <AuthOrigin>/oauth/token  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//	     subject_token=<client token>  subject_token_type=urn:ur:params:oauth:token-type:client-jwt
//	     resource=https://<audience>.<ServiceDomain>  scope=<within the service's>  DPoP: <proof by the ClientKey>
//
// It copies server/oauth/exchange.go (TEAM-M1-06) step for step, in its order, so a schedule sees the same refusals at
// the same points: the form's shape, exactly one service resource and never the api's audience, at most 64 repo:
// scopes, re-seed mode's restore_required, the subject token's exp, the ClientKey's proof (fake_api_dpop.go, which
// spends its jti), the client's removal, then the scope source and the mint. The token is minted by the authenticator
// the api was given, the Net host's, so T2's engines authenticate it as server's verify its JWT.
//
// Scopes come from the installed FakeApiScopeSource. Until a test installs one the api grants no scope at all, as
// server's does until TEAM-M2-15 installs the projection's: a request for any scope is refused invalid_scope, and a
// request for none gets a token that grants nothing but names its client. A client acts as itself here, so a token
// never carries ur_subject_client_id, and the act claim has no place in sidecar.Principal. Other grants are not served:
// ur-cli's run on T3 (TEAM-M1-08). Tokens are never kept.

package sidecartest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

const (
	// RFC 8693 §2.1's grant type.
	FakeApiExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// §7.8's subject token type: a client's token.
	FakeApiExchangeSubjectTokenType = "urn:ur:params:oauth:token-type:client-jwt"
	// RFC 8693 §3's type of what the exchange issues.
	fakeApiExchangeIssuedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	// §7.8: at most 64 repo: scopes in one token, keeping the bearer under the lb's 8 KiB header line.
	fakeApiExchangeMaxRepoScopeCount = 64
	// An evs or gkm capability scope, repo:<id>:<role>.
	fakeApiExchangeRepoScopePrefix = "repo:"
	// route_authz's refusal of a strict_exp bearer off its allowlist, which POST /oauth/token is.
	fakeApiStrictExpRefusedText = "A sidecar token cannot call this route."
)

// The audiences a service token may name (§7.8). The api's is never one.
var fakeApiServiceAudiences = map[string]bool{
	"evs":   true,
	"gkm":   true,
	"dns":   true,
	"certs": true,
	"mail":  true,
}

// A scope the exchange will not grant (RFC 6749 §5.2). A FakeApiScopeSource refuses with an error wrapping it.
var ErrFakeApiInvalidScope = errors.New("invalid_scope")

// The exchange's other refusals, each its RFC code.
var (
	errFakeApiInvalidRequest   = errors.New("invalid_request")
	errFakeApiInvalidTarget    = errors.New("invalid_target")
	errFakeApiInvalidDpopProof = errors.New("invalid_dpop_proof")
	errFakeApiInvalidGrant     = errors.New("invalid_grant")
	errFakeApiRestoreRequired  = errors.New("restore_required")
)

// What the exchange asks its scope source, as server's ExchangeScopeRequest carries it: who asks, for which service,
// and which scopes.
type FakeApiScopeRequest struct {
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	// The §8 subject the client acts as: the client itself here.
	SubjectClientId sidecar.Id
	// The sidecar the client is bound to, nil for none.
	SidecarId *sidecar.Id
	Audience  string
	// As asked, each once, in the order first asked.
	Scopes []string
}

// What a scope source grants.
type FakeApiScopeGrant struct {
	// A subset of the request's: a scope it did not ask for fails the exchange as server's error.
	Scopes []string
	// The log position the scopes came from, the claim proj_v; 0 for none.
	ProjVersion uint64
	// The member the sidecar belongs to, nil for none.
	MemberId *sidecar.Id
}

// Where the exchange's scopes come from: §8's rows in the newest projection, once TEAM-M2-15 and ACL-M2-14 build the
// real one. A refusal wraps ErrFakeApiInvalidScope; any other error is the exchange's server error.
type FakeApiScopeSource func(ctx context.Context, request *FakeApiScopeRequest) (*FakeApiScopeGrant, error)

// The source until one is installed, as server's until a projection's: it grants no scope at all.
func fakeApiNoProjectionScopeSource(ctx context.Context, request *FakeApiScopeRequest) (*FakeApiScopeGrant, error) {
	if 0 < len(request.Scopes) {
		return nil, fmt.Errorf("%w: no projection grants scopes yet", ErrFakeApiInvalidScope)
	}
	return &FakeApiScopeGrant{}, nil
}

// One spent jti, in its client's space.
type fakeApiJtiKey struct {
	clientId sidecar.Id
	jti      string
}

// The exchange's state on FakeApi, under its stateLock.
type fakeApiExchangeState struct {
	// each client's newest bound ClientKey, which its proofs must be signed by (§7.4)
	clientKeys map[sidecar.Id]ed25519.PublicKey
	// each spent jti, until it may be forgotten
	spentJtiExpireTimes map[fakeApiJtiKey]time.Time
	// sidecar.yml's reseed (§19.10)
	reseed      bool
	scopeSource FakeApiScopeSource
}

func newFakeApiExchangeState() fakeApiExchangeState {
	return fakeApiExchangeState{
		clientKeys:          map[sidecar.Id]ed25519.PublicKey{},
		spentJtiExpireTimes: map[fakeApiJtiKey]time.Time{},
		scopeSource:         fakeApiNoProjectionScopeSource,
	}
}

// Binds clientKey as the client's newest key, as POST /sidecar/bind's identity binding does (§5.15): every proof of
// the client, the exchange's included, must be signed by it, and a client with none bound has no proof that passes.
// A rebind replaces the key. CORE-M1-13's bind route sets the same.
func (self *FakeApi) BindClientKey(clientId sidecar.Id, clientKey ed25519.PublicKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.exchange.clientKeys[clientId] = slices.Clone(clientKey)
}

// The client's bound key, nil for none.
func (self *FakeApi) clientKey(clientId sidecar.Id) ed25519.PublicKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.exchange.clientKeys[clientId]
}

// Installs source as the exchange's scope source; nil restores the one that grants no scope.
func (self *FakeApi) SetExchangeScopeSource(source FakeApiScopeSource) {
	if source == nil {
		source = fakeApiNoProjectionScopeSource
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.exchange.scopeSource = source
}

// Turns sidecar.yml's reseed on or off (§19.10). While it is on the exchange answers restore_required to every
// request that gets that far, as server's does until re-seed mode's admin tokens are built.
func (self *FakeApi) SetReseed(reseed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.exchange.reseed = reseed
}

// The issuer's token endpoint, which an exchange's proof names as htu.
func (self *FakeApi) TokenEndpoint() string {
	return self.settings.AuthOrigin + "/oauth/token"
}

// The service origin of audience, which the exchange takes as its resource.
func (self *FakeApi) ServiceOrigin(audience string) string {
	return "https://" + audience + "." + self.settings.ServiceDomain
}

// One exchange request, as its form and DPoP header carry it.
type fakeApiExchangeArgs struct {
	subjectToken     string
	subjectTokenType string
	// every resource the form names; the exchange takes exactly one
	resources []string
	scope     string
	// every DPoP header the request carries; the exchange takes exactly one
	proofs []string
}

// RFC 8693 §2.2.1's answer.
type fakeApiExchangeResult struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// The route, on the api's mux.
func (self *FakeApi) addExchangeRoutes() {
	self.mux.HandleFunc("POST /oauth/token", self.handleToken)
}

// The service audience a resource names (RFC 8707): exactly https://<audience>.<ServiceDomain> for a service
// audience, its path empty or /. The api's origin is refused by name: the exchange never issues the api audience.
func (self *FakeApi) serviceAudienceForResource(resource string) (string, error) {
	parsed, err := url.Parse(resource)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.Contains(resource, "#") || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("%w: not a service origin", errFakeApiInvalidTarget)
	}
	host := strings.ToLower(parsed.Host)
	apiOrigin, err := url.Parse(self.settings.Origin)
	if err != nil {
		return "", err
	}
	if host == "api."+self.settings.ServiceDomain || host == strings.ToLower(apiOrigin.Host) {
		return "", fmt.Errorf("%w: the api audience is never issued", errFakeApiInvalidTarget)
	}
	audience, ok := strings.CutSuffix(host, "."+self.settings.ServiceDomain)
	if !ok || !fakeApiServiceAudiences[audience] {
		return "", fmt.Errorf("%w: no such service", errFakeApiInvalidTarget)
	}
	return audience, nil
}

// Whether scope is an RFC 6749 §3.3 scope-token: printable ASCII but space, " and \.
func isFakeApiScopeToken(scope string) bool {
	if scope == "" {
		return false
	}
	for i := 0; i < len(scope); i += 1 {
		c := scope[i]
		if c < 0x21 || 0x7e < c || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// How many of scopes are repo: scopes.
func fakeApiRepoScopeCount(scopes []string) int {
	count := 0
	for _, scope := range scopes {
		if strings.HasPrefix(scope, fakeApiExchangeRepoScopePrefix) {
			count += 1
		}
	}
	return count
}

// The scopes a form asks for, each once in the order first asked, and at most 64 repo: scopes: a 65th is refused, not
// dropped.
func fakeApiExchangeScopes(scope string) ([]string, error) {
	scopes := []string{}
	seen := map[string]bool{}
	for _, s := range strings.Fields(scope) {
		if !isFakeApiScopeToken(s) {
			return nil, fmt.Errorf("%w: not a scope", ErrFakeApiInvalidScope)
		}
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	if fakeApiExchangeMaxRepoScopeCount < fakeApiRepoScopeCount(scopes) {
		return nil, fmt.Errorf("%w: more than %d repo: scopes", ErrFakeApiInvalidScope, fakeApiExchangeMaxRepoScopeCount)
	}
	return scopes, nil
}

// Exchanges a client token for a service token, or refuses with an error wrapping one of the exchange's codes; any
// other error is the server's.
func (self *FakeApi) exchangeToken(ctx context.Context, args *fakeApiExchangeArgs) (*fakeApiExchangeResult, error) {
	if args.subjectTokenType != FakeApiExchangeSubjectTokenType || args.subjectToken == "" {
		return nil, fmt.Errorf("%w: a client token is the only subject", errFakeApiInvalidRequest)
	}
	if len(args.resources) != 1 {
		return nil, fmt.Errorf("%w: exactly one resource", errFakeApiInvalidTarget)
	}
	audience, err := self.serviceAudienceForResource(args.resources[0])
	if err != nil {
		return nil, err
	}
	scopes, err := fakeApiExchangeScopes(args.scope)
	if err != nil {
		return nil, err
	}
	reseed, scopeSource := func() (bool, FakeApiScopeSource) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.exchange.reseed, self.exchange.scopeSource
	}()
	if reseed {
		return nil, fmt.Errorf("%w: a restore holds the exchange", errFakeApiRestoreRequired)
	}

	// the subject token as session's verifier reads it, refused past its exp whatever reject_expired says
	now := self.clock.Now()
	client := func() *fakeApiClient {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.bearerClients[args.subjectToken]
	}()
	if client == nil {
		return nil, fmt.Errorf("%w: the subject token does not verify", errFakeApiInvalidGrant)
	}
	if !now.Before(client.expireTime) {
		return nil, fmt.Errorf("%w: the subject token is expired", errFakeApiInvalidGrant)
	}

	// the ClientKey's proof of this request, before any state is read: its jti is spent whatever follows
	if len(args.proofs) != 1 {
		return nil, fmt.Errorf("%w: not exactly one proof", errFakeApiInvalidDpopProof)
	}
	clientKey := self.clientKey(client.clientId)
	if clientKey == nil {
		return nil, fmt.Errorf("%w: the client has no bound key", errFakeApiInvalidDpopProof)
	}
	err = self.verifyDpop(&fakeApiDpopRequest{
		proof:    args.proofs[0],
		method:   http.MethodPost,
		uri:      self.TokenEndpoint(),
		token:    args.subjectToken,
		key:      clientKey,
		replayId: client.clientId,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFakeApiInvalidDpopProof, err)
	}

	if self.clientOfToken(args.subjectToken) == nil {
		return nil, fmt.Errorf("%w: the client is not active", errFakeApiInvalidGrant)
	}
	var sidecarId *sidecar.Id
	if client.sidecarId != (sidecar.Id{}) {
		boundSidecarId := client.sidecarId
		sidecarId = &boundSidecarId
	}
	grant, err := scopeSource(ctx, &FakeApiScopeRequest{
		NetworkId:       client.networkId,
		ClientId:        client.clientId,
		SubjectClientId: client.clientId,
		SidecarId:       sidecarId,
		Audience:        audience,
		Scopes:          slices.Clone(scopes),
	})
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, errors.New("the scope source granted nothing and refused nothing")
	}
	asked := map[string]bool{}
	for _, scope := range scopes {
		asked[scope] = true
	}
	for _, granted := range grant.Scopes {
		if !asked[granted] {
			return nil, errors.New("the scope source granted a scope the request did not ask for")
		}
	}
	if fakeApiExchangeMaxRepoScopeCount < fakeApiRepoScopeCount(grant.Scopes) {
		return nil, fmt.Errorf("the scope source granted more than %d repo: scopes", fakeApiExchangeMaxRepoScopeCount)
	}

	principal := &sidecar.Principal{
		NetworkId:   connect.Id(client.networkId),
		ClientId:    connect.Id(client.clientId),
		Audience:    audience,
		Scopes:      slices.Clone(grant.Scopes),
		ProjVersion: grant.ProjVersion,
		IssuedAt:    now,
		ExpiresAt:   now.Add(self.settings.ServiceTokenTimeout),
	}
	if sidecarId != nil {
		claimId := connect.Id(*sidecarId)
		principal.SidecarId = &claimId
	}
	if grant.MemberId != nil {
		claimId := connect.Id(*grant.MemberId)
		principal.MemberId = &claimId
	}
	if err := principal.Validate(); err != nil {
		return nil, fmt.Errorf("service token: %w", err)
	}
	return &fakeApiExchangeResult{
		AccessToken:     self.authenticator.Issue(principal),
		IssuedTokenType: fakeApiExchangeIssuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       int64(self.settings.ServiceTokenTimeout / time.Second),
		Scope:           strings.Join(grant.Scopes, " "),
	}, nil
}

// Writes RFC 6749 §5.2's error envelope, never cached, as server's oauth handlers do.
func fakeApiOauthError(writer http.ResponseWriter, status int, code string, description string) {
	writer.Header().Set("Cache-Control", "no-store")
	fakeApiWriteJson(writer, status, map[string]any{"error": code, "error_description": description})
}

// Maps an exchange error to its code, with server's fixed descriptions: the detail never reaches the answer.
func fakeApiExchangeFailure(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errFakeApiInvalidRequest):
		fakeApiOauthError(writer, http.StatusBadRequest, "invalid_request", "The request is malformed.")
	case errors.Is(err, errFakeApiInvalidTarget):
		fakeApiOauthError(writer, http.StatusBadRequest, "invalid_target", "The resource is not a service this server issues tokens for.")
	case errors.Is(err, ErrFakeApiInvalidScope):
		fakeApiOauthError(writer, http.StatusBadRequest, "invalid_scope", "The scope is not granted.")
	case errors.Is(err, errFakeApiInvalidDpopProof):
		fakeApiOauthError(writer, http.StatusBadRequest, "invalid_dpop_proof", "The DPoP proof is invalid.")
	case errors.Is(err, errFakeApiInvalidGrant):
		fakeApiOauthError(writer, http.StatusBadRequest, "invalid_grant", "The grant is invalid or expired.")
	case errors.Is(err, errFakeApiRestoreRequired):
		fakeApiOauthError(writer, http.StatusBadRequest, "restore_required", "The network is being restored. Try again later.")
	default:
		fakeApiOauthError(writer, http.StatusInternalServerError, "server_error", "Please try again.")
	}
}

// POST /oauth/token: the exchange alone. The route is Public, and a sidecar's bearer is refused there on every grant,
// as route_authz's strict_exp gate refuses it off its allowlist: the client token rides in the form as the subject
// token, never as a bearer.
func (self *FakeApi) handleToken(writer http.ResponseWriter, request *http.Request) {
	if bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer "); found && self.clientOfToken(bearer) != nil {
		fakeApiWriteJson(writer, http.StatusForbidden, map[string]any{"error": fakeApiStrictExpRefusedText})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, self.settings.MaxRequestByteCount)
	if err := request.ParseForm(); err != nil {
		fakeApiOauthError(writer, http.StatusBadRequest, "invalid_request", "The form could not be parsed.")
		return
	}
	if request.PostFormValue("grant_type") != FakeApiExchangeGrantType {
		fakeApiOauthError(writer, http.StatusBadRequest, "unsupported_grant_type", "Supported: "+FakeApiExchangeGrantType+".")
		return
	}
	result, err := self.exchangeToken(request.Context(), &fakeApiExchangeArgs{
		subjectToken:     request.PostFormValue("subject_token"),
		subjectTokenType: request.PostFormValue("subject_token_type"),
		resources:        request.PostForm["resource"],
		scope:            request.PostFormValue("scope"),
		proofs:           request.Header.Values("DPoP"),
	})
	if err != nil {
		fakeApiExchangeFailure(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	fakeApiWriteJson(writer, http.StatusOK, result)
}
