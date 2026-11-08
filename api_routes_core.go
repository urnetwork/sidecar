// §5's and §7's routes on SidecarApi (§5.6, §5.15, §7.4, §7.8): enrollment, a client's mint and
// removal, the identity binding and its lookups, refresh and the token exchange. Each call sends one
// request and refuses before sending what its route forbids: a proof-carrying call without a signer,
// an auth key holding its client-only bundle, an exchange past its scope bound.
//
// A sidecar always sends §7.4's marks, admin_refused and strict_exp, so no call here can leave them
// out. Every token a reply carries is reported to testHookSecret as it arrives, so the privacy
// harness finds one that leaks (I-7), and the types holding one print without it.
//
// The bindings these routes carry are opaque bytes here: api is untrusted, so a binding is checked by
// VerifySidecarIdentityBinding (CORE-M1-05) against the caller's pin before anything reads it, and an
// identity's status is a candidate a caller verifies against the config (§5.6), never authority.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The token exchange's format values (§7.8, RFC 8693).
const (
	sidecarExchangeGrantType        = "urn:ietf:params:oauth:grant-type:token-exchange"
	sidecarExchangeSubjectTokenType = "urn:ur:params:oauth:token-type:client-jwt"
	// repo: scopes in one exchange, which keeps the bearer under the lb's 8 KiB header line
	// (warp/warpctl/config.go:1299). A caller splits a larger set into several exchanges.
	sidecarExchangeMaxRepoScopeCount = 64
	// The prefix of an evs or gkm capability scope, repo:<id>:r|rw|admin|deposit.
	sidecarExchangeRepoScopePrefix = "repo:"
)

// What POST /network/enroll takes (§7.8), less the marks every sidecar sends.
type SidecarEnrollArgs struct {
	// The key's bearer, <id>-<secret>, split from its client-only #<bundle> before this call
	// (TEAM-M1-05's ParseAuthKey). A key holding # is refused before anything is sent, and so is a
	// urn_ API key (§5.6).
	AuthKey string
	// The new client's Ed25519 public key, 32 bytes, from the ClientKey seed the daemon generated.
	ClientPublicKey []byte
	// The device's description for the client, which must not be empty.
	DeviceSpec string
	// true unless `ur proxy` or a public exit is set (§20.8).
	DeclaresNoEgress bool
}

// POST /network/enroll's body.
type sidecarEnrollWire struct {
	AuthKey          string `json:"auth_key"`
	ClientPublicKey  []byte `json:"client_public_key"`
	DeviceSpec       string `json:"device_spec"`
	DeclaresNoEgress bool   `json:"declares_no_egress"`
	AdminRefused     bool   `json:"admin_refused"`
	StrictExp        bool   `json:"strict_exp"`
}

// What POST /network/enroll answers (§7.8).
type SidecarEnrollResult struct {
	// The new client's token. It goes to the keychain and SidecarApi, nowhere else (I-7).
	ByClientJwt string
	ClientId    Id
	// api's approval state for the client, as it answers it.
	ApprovalState string
	// Whether api confirmed the client refuses administration. A sidecar keeps its keychain only
	// when it did (§5.6, D-CORE-7), so the caller checks this before persisting anything.
	AdminRefused bool
	// An ephemeral mint's close capability, 128 random bits returned only here (§7.7), else empty.
	Close string
}

// Says what it is, never the token or the capability.
func (self *SidecarEnrollResult) String() string {
	return "SidecarEnrollResult{client " + self.ClientId.String() + "}"
}

// As String, for %#v.
func (self *SidecarEnrollResult) GoString() string {
	return self.String()
}

// POST /network/enroll's answer.
type sidecarEnrollReply struct {
	ByClientJwt   string `json:"by_client_jwt"`
	ClientId      Id     `json:"client_id"`
	ApprovalState string `json:"approval_state"`
	AdminRefused  bool   `json:"admin_refused"`
	Close         string `json:"close"`
}

// POST /network/enroll (§7.8): creates the sidecar's top-level client from an auth key. Public, so it
// presents no token. Refuses before sending an auth key holding # or naming a urn_ API key, and any
// request body holding #, so a bundle cannot ride in another field (§7.8, D-TEAM-22). Until
// TEAM-M2-16 lands no admission is sent, which tagged and ephemeral enrollments need past base 1.
func (self *SidecarApi) Enroll(ctx context.Context, args *SidecarEnrollArgs) (*SidecarEnrollResult, error) {
	route := "POST /network/enroll"
	if args == nil || args.AuthKey == "" || args.DeviceSpec == "" || len(args.ClientPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	testHookSecret("auth_key", []byte(args.AuthKey))
	if strings.Contains(args.AuthKey, "#") || strings.HasPrefix(args.AuthKey, "urn_") {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiBundle)
	}
	body, err := json.Marshal(&sidecarEnrollWire{
		AuthKey:          args.AuthKey,
		ClientPublicKey:  args.ClientPublicKey,
		DeviceSpec:       args.DeviceSpec,
		DeclaresNoEgress: args.DeclaresNoEgress,
		AdminRefused:     true,
		StrictExp:        true,
	})
	if err != nil {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	// encoding/json writes # as itself, so a bundle in any field shows here
	if bytes.IndexByte(body, '#') != -1 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiBundle)
	}

	reply := &sidecarEnrollReply{}
	err = self.sendJson(ctx, &sidecarApiRequest{
		route:       route,
		operation:   "enroll",
		method:      "POST",
		url:         self.settings.ApiUrl + "/network/enroll",
		body:        body,
		contentType: "application/json",
	}, nil, reply)
	if err != nil {
		return nil, err
	}
	if reply.ByClientJwt == "" || reply.ClientId == (Id{}) {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	testHookSecret("by_client_jwt", []byte(reply.ByClientJwt))
	if reply.Close != "" {
		testHookSecret("close", []byte(reply.Close))
	}
	return &SidecarEnrollResult{
		ByClientJwt:   reply.ByClientJwt,
		ClientId:      reply.ClientId,
		ApprovalState: reply.ApprovalState,
		AdminRefused:  reply.AdminRefused,
		Close:         reply.Close,
	}, nil
}

// What POST /network/auth-client takes from a sidecar (§7.4, §7.7), less the marks every sidecar
// sends.
type SidecarAuthClientArgs struct {
	// An existing client to reissue a token for, nil for a new one.
	ClientId *Id
	// A new child's parent, such as this sidecar's own client for a window client (§17.5), nil for
	// none.
	SourceClientId *Id
	// A new device's name.
	Description string
	// A new device's spec.
	DeviceSpec string
	// true unless the client provides egress (§20.8).
	DeclaresNoEgress bool
}

// POST /network/auth-client's body.
type sidecarAuthClientWire struct {
	ClientId         *Id    `json:"client_id,omitempty"`
	SourceClientId   *Id    `json:"source_client_id,omitempty"`
	Description      string `json:"description"`
	DeviceSpec       string `json:"device_spec"`
	DeclaresNoEgress bool   `json:"declares_no_egress"`
	AdminRefused     bool   `json:"admin_refused"`
	StrictExp        bool   `json:"strict_exp"`
}

// What POST /network/auth-client answers.
type SidecarAuthClientResult struct {
	// The client's token. It stays in this process (I-7).
	ByClientJwt string
	// The client's id, or zero when api's answer did not name it.
	ClientId Id
	// The marks api confirmed. A sidecar keeps nothing of a client whose answer does not confirm
	// admin_refused (§5.6).
	AdminRefused bool
	StrictExp    bool
	// An ephemeral mint's close capability (§7.7), else empty.
	Close string
}

// Says what it is, never the token or the capability.
func (self *SidecarAuthClientResult) String() string {
	return "SidecarAuthClientResult{client " + self.ClientId.String() + "}"
}

// As String, for %#v.
func (self *SidecarAuthClientResult) GoString() string {
	return self.String()
}

// POST /network/auth-client's answer.
type sidecarAuthClientReply struct {
	ByClientJwt  string                 `json:"by_client_jwt"`
	ClientId     *Id                    `json:"client_id"`
	AdminRefused bool                   `json:"admin_refused"`
	StrictExp    bool                   `json:"strict_exp"`
	Close        string                 `json:"close"`
	Error        *sidecarApiResultError `json:"error"`
}

// POST /network/auth-client (§7.4): mints a child of this sidecar's client, or reissues a client's
// token, with the jwt as bearer and a DPoP proof over it, which a strict_exp bearer must carry to
// mint. Not sent without a signer. A limit api answers in a 200 is a *SidecarApiError with status 200
// and code upgrade_required or client_limit_exceeded.
func (self *SidecarApi) AuthClient(ctx context.Context, args *SidecarAuthClientArgs) (*SidecarAuthClientResult, error) {
	route := "POST /network/auth-client"
	if args == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarAuthClientReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "auth_client",
		method:    "POST",
		url:       self.settings.ApiUrl + "/network/auth-client",
		bearer:    true,
		dpop:      true,
	}, &sidecarAuthClientWire{
		ClientId:         args.ClientId,
		SourceClientId:   args.SourceClientId,
		Description:      args.Description,
		DeviceSpec:       args.DeviceSpec,
		DeclaresNoEgress: args.DeclaresNoEgress,
		AdminRefused:     true,
		StrictExp:        true,
	}, reply)
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		return nil, reply.Error.apiError(route)
	}
	if reply.ByClientJwt == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	testHookSecret("by_client_jwt", []byte(reply.ByClientJwt))
	if reply.Close != "" {
		testHookSecret("close", []byte(reply.Close))
	}
	result := &SidecarAuthClientResult{
		ByClientJwt:  reply.ByClientJwt,
		AdminRefused: reply.AdminRefused,
		StrictExp:    reply.StrictExp,
		Close:        reply.Close,
	}
	if reply.ClientId != nil {
		result.ClientId = *reply.ClientId
	}
	return result, nil
}

// POST /network/remove-client's body.
type sidecarRemoveClientWire struct {
	ClientId Id `json:"client_id"`
}

// POST /network/remove-client's answer.
type sidecarRemoveClientReply struct {
	Error *sidecarApiResultError `json:"error"`
}

// POST /network/remove-client (§5.6, §7.4): removes this sidecar's own client or one of its children,
// as `ur logout` and re-enrollment do. A refusal in a 200 is a *SidecarApiError with status 200.
func (self *SidecarApi) RemoveClient(ctx context.Context, clientId Id) error {
	route := "POST /network/remove-client"
	if clientId == (Id{}) {
		return fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarRemoveClientReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "remove_client",
		method:    "POST",
		url:       self.settings.ApiUrl + "/network/remove-client",
		bearer:    true,
	}, &sidecarRemoveClientWire{ClientId: clientId}, reply)
	if err != nil {
		return err
	}
	if reply.Error != nil {
		return reply.Error.apiError(route)
	}
	return nil
}

// POST /sidecar/bind's body: the marshalled SignedSidecarIdentityBinding, which encoding/json
// writes in standard base64 (plan-CORE-binding-wire #6).
type sidecarBindWire struct {
	Binding []byte `json:"binding"`
}

// POST /sidecar/bind's answer.
type sidecarBindReply struct {
	Generation int64 `json:"generation"`
}

// POST /sidecar/bind (§5.5, §5.6): appends this client's binding, signedBinding being the
// marshalled SignedSidecarIdentityBinding (CORE-M1-05), with the jwt as bearer and no proof, since
// bind takes none. Answers the generation api recorded. A byte-identical retry answers the same
// generation; a refusal is a *SidecarApiError with code sidecar_revoked, binding_invalid,
// generation_conflict or client_bound. Re-registration after a restore posts the newest binding
// again through here.
func (self *SidecarApi) Bind(ctx context.Context, signedBinding []byte) (int64, error) {
	route := "POST /sidecar/bind"
	if len(signedBinding) == 0 {
		return 0, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarBindReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "bind",
		method:    "POST",
		url:       self.settings.ApiUrl + "/sidecar/bind",
		bearer:    true,
	}, &sidecarBindWire{Binding: signedBinding}, reply)
	if err != nil {
		return 0, err
	}
	if reply.Generation < 1 {
		return 0, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return reply.Generation, nil
}

// What api holds about one sidecar's identity (§5.15), never its user_id. All of it is unverified:
// a binding counts only once VerifySidecarIdentityBinding checks it and its identity key against the
// caller's pin, so api stays untrusted.
type SidecarIdentityRecord struct {
	SidecarId Id
	// The Ed25519 identity public key as api holds it.
	IdentityPublicKey []byte
	// "ed25519" in v0 (owner decision 44).
	IdentityAlg string
	// The identity's status as api holds it, such as active or revoked: a candidate, never authority.
	Status string
	// The current binding, a marshalled SignedSidecarIdentityBinding as api stored it.
	Binding []byte
	// A page of the sidecar's stored bindings, newest first, at most 64 a page
	// (plan-CORE-client-to-sidecar-lookup); empty from a client_id lookup.
	Bindings [][]byte
}

// GET /sidecar/identity's answer, for both lookups.
type sidecarIdentityReply struct {
	SidecarId         *Id      `json:"sidecar_id"`
	IdentityPublicKey []byte   `json:"identity_public_key"`
	IdentityAlg       string   `json:"identity_alg"`
	Status            string   `json:"status"`
	Binding           []byte   `json:"binding"`
	Bindings          [][]byte `json:"bindings"`
}

// GET /sidecar/identity/<sidecar_id> (§5.15): a sidecar of the caller's own network, or of one
// sharing with it (§8.11). beforeGeneration zero answers the newest page of bindings, and a
// generation answers the page below it (plan-CORE-client-to-sidecar-lookup). Never the packet path.
func (self *SidecarApi) GetIdentity(ctx context.Context, sidecarId Id, beforeGeneration int64) (*SidecarIdentityRecord, error) {
	route := "GET /sidecar/identity/<sidecar_id>"
	if sidecarId == (Id{}) || beforeGeneration < 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	requestUrl := self.settings.ApiUrl + "/sidecar/identity/" + sidecarId.String()
	if 0 < beforeGeneration {
		requestUrl += "?before_generation=" + strconv.FormatInt(beforeGeneration, 10)
	}
	reply := &sidecarIdentityReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "identity",
		method:    "GET",
		url:       requestUrl,
		bearer:    true,
	}, nil, reply)
	if err != nil {
		return nil, err
	}
	// an answer about another sidecar than the one asked for is not this route's
	if reply.SidecarId != nil && *reply.SidecarId != sidecarId {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return sidecarIdentityRecordOf(route, sidecarId, reply)
}

// GET /sidecar/identity?client_id=<id> (plan-CORE-client-to-sidecar-lookup): the sidecar a client
// of any generation is bound to, for a reader resolving a committer or a subject. A client with no
// binding is a *SidecarApiError with status 404.
func (self *SidecarApi) GetIdentityByClient(ctx context.Context, clientId Id) (*SidecarIdentityRecord, error) {
	route := "GET /sidecar/identity?client_id=<client_id>"
	if clientId == (Id{}) {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarIdentityReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "identity_by_client",
		method:    "GET",
		url:       self.settings.ApiUrl + "/sidecar/identity?client_id=" + clientId.String(),
		bearer:    true,
	}, nil, reply)
	if err != nil {
		return nil, err
	}
	if reply.SidecarId == nil || *reply.SidecarId == (Id{}) {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	record, err := sidecarIdentityRecordOf(route, *reply.SidecarId, reply)
	if err != nil {
		return nil, err
	}
	record.Bindings = nil
	return record, nil
}

// The record of reply about sidecarId, refusing one with no identity key or status.
func sidecarIdentityRecordOf(route string, sidecarId Id, reply *sidecarIdentityReply) (*SidecarIdentityRecord, error) {
	if len(reply.IdentityPublicKey) == 0 || reply.IdentityAlg == "" || reply.Status == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return &SidecarIdentityRecord{
		SidecarId:         sidecarId,
		IdentityPublicKey: reply.IdentityPublicKey,
		IdentityAlg:       reply.IdentityAlg,
		Status:            reply.Status,
		Binding:           reply.Binding,
		Bindings:          reply.Bindings,
	}, nil
}

// GET /auth/refresh's answer.
type sidecarRefreshReply struct {
	ByJwt string                 `json:"by_jwt"`
	Error *sidecarApiResultError `json:"error"`
}

// GET /auth/refresh (§5.6, §7.4): a new token for this client, with the jwt as bearer and a DPoP
// proof over it. It installs nothing: the token manager checks the new token, persists it, then calls
// SetByJwt (D-CORE-8). Without a signer it is not sent at all, ErrSidecarApiNoDpopSigner, which
// leaves the sidecar unenrolled and never proofless. A refusal is a *SidecarApiError: a 401, its
// code session_revoked when the session ended, or a 200 whose error object holds a code such as
// restore_required, which is not a refusal but a re-registration (§19.10).
func (self *SidecarApi) Refresh(ctx context.Context) (string, error) {
	route := "GET /auth/refresh"
	reply := &sidecarRefreshReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "refresh",
		method:    "GET",
		url:       self.settings.ApiUrl + "/auth/refresh",
		bearer:    true,
		dpop:      true,
	}, nil, reply)
	if err != nil {
		return "", err
	}
	if reply.Error != nil {
		return "", reply.Error.apiError(route)
	}
	if reply.ByJwt == "" {
		return "", fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	testHookSecret("by_client_jwt", []byte(reply.ByJwt))
	return reply.ByJwt, nil
}

// A service token from the token exchange (§7.8): one audience, 15 minutes, which never leaves the
// daemon (I-7, R-CORE-10).
type SidecarServiceToken struct {
	// The bearer for the service.
	AccessToken string
	// RFC 8693's issued_token_type, as api answered it.
	IssuedTokenType string
	// RFC 8693's token_type, as api answered it.
	TokenType string
	// Its lifetime from issue, from expires_in. Zero: the answer named none, and a caller keeps it no
	// longer than a service token lives.
	ExpiresIn time.Duration
	// The scopes granted, which may be fewer than those asked for. Empty when the answer listed none.
	Scopes []string
}

// Says what it is, never the token.
func (self *SidecarServiceToken) String() string {
	return "SidecarServiceToken{" + strings.Join(self.Scopes, " ") + "}"
}

// As String, for %#v.
func (self *SidecarServiceToken) GoString() string {
	return self.String()
}

// POST /oauth/token's exchange answer (RFC 8693 §2.2.1).
type sidecarExchangeReply struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

// Whether scope is an RFC 6749 scope-token: printable ASCII but space, " and \.
func isSidecarExchangeScope(scope string) bool {
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

// Whether resource names a service as RFC 8707 asks: an absolute http or https url with no
// credentials, query or fragment.
func isSidecarExchangeResource(resource string) bool {
	parsed, err := url.Parse(resource)
	return err == nil && isAbsoluteServiceUrl(parsed, "http", "https") &&
		!strings.ContainsAny(resource, "?# ")
}

// POST <AuthUrl>/oauth/token's token exchange (§7.8, RFC 8693): a service token for resource, a
// service's url, with scopes, form-encoded with the jwt as subject token and a DPoP proof over it.
// It never asks for the api audience, which api refuses. At most 64 repo: scopes go in one exchange,
// so a caller splits a larger set; more is refused before sending, as is a call without a signer.
// A refusal is a *SidecarApiError whose code is RFC 6749's, such as invalid_grant, or
// restore_required in re-seed mode (§19.10).
func (self *SidecarApi) ExchangeToken(ctx context.Context, resource string, scopes []string) (*SidecarServiceToken, error) {
	route := "POST /oauth/token"
	if !isSidecarExchangeResource(resource) || resource == self.settings.ApiUrl {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	repoScopeCount := 0
	for _, scope := range scopes {
		if !isSidecarExchangeScope(scope) {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
		}
		if strings.HasPrefix(scope, sidecarExchangeRepoScopePrefix) {
			repoScopeCount += 1
		}
	}
	if sidecarExchangeMaxRepoScopeCount < repoScopeCount {
		return nil, fmt.Errorf("sidecar api %s: %w: more than %d repo: scopes", route, ErrSidecarApiArgs, sidecarExchangeMaxRepoScopeCount)
	}

	responseBody, err := self.send(ctx, &sidecarApiRequest{
		route:     route,
		operation: "exchange",
		method:    "POST",
		url:       self.settings.AuthUrl + "/oauth/token",
		dpop:      true,
		buildBody: func(byJwt string) []byte {
			form := url.Values{
				"grant_type":         {sidecarExchangeGrantType},
				"subject_token":      {byJwt},
				"subject_token_type": {sidecarExchangeSubjectTokenType},
				"resource":           {resource},
			}
			if 0 < len(scopes) {
				form.Set("scope", strings.Join(scopes, " "))
			}
			return []byte(form.Encode())
		},
		contentType: "application/x-www-form-urlencoded",
	})
	if err != nil {
		return nil, err
	}
	reply := &sidecarExchangeReply{}
	err = json.Unmarshal(responseBody, reply)
	if err != nil || reply.AccessToken == "" || reply.ExpiresIn < 0 || math.MaxInt64/int64(time.Second) < reply.ExpiresIn {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	testHookSecret("service_token", []byte(reply.AccessToken))
	token := &SidecarServiceToken{
		AccessToken:     reply.AccessToken,
		IssuedTokenType: reply.IssuedTokenType,
		TokenType:       reply.TokenType,
		ExpiresIn:       time.Duration(reply.ExpiresIn) * time.Second,
	}
	if reply.Scope != "" {
		token.Scopes = strings.Fields(reply.Scope)
	}
	return token, nil
}
