// §5's and §7's routes that enroll, bind, refresh and remove a sidecar's client, on the fake api (§5.6, §5.15, §7.4,
// §7.8), beside fake_api_config.go's log and fake_api_exchange.go's exchange:
//
//	POST /network/enroll                    Public: an auth key's bearer mints a top-level client with both marks
//	POST /network/auth-client               Client, with the ClientKey's proof: a reissue of the bearer's own client,
//	                                        or a child of it, which inherits both marks
//	POST /network/remove-client             OwnClient: the bearer's own client or one of its children
//	POST /sidecar/bind                      Client: the bearer's own binding, under plan-CORE-binding-wire's rules
//	GET  /sidecar/identity/<sidecar_id>     Client: a sidecar of the caller's network, with a page of its bindings
//	GET  /sidecar/identity?client_id=<id>   Client: the sidecar a client of any generation binds
//	GET  /auth/refresh                      Client, with the ClientKey's proof: a new token, same client and device
//
// Each copies server's route step for step where server has one (server/controller/sidecar_identity_controller.go,
// model/sidecar_identity_model.go, controller/auth_controller.go's RefreshToken), and §7.8's text where it has none
// yet: POST /network/enroll is TEAM-M1-04's. A strict_exp bearer proves its ClientKey on refresh and auth-client as
// fake_api_dpop.go checks it, by the client's newest bound key, else the key its enrollment recorded
// (plan-TEAM-enroll-client-key); a bind must carry that recorded key. A refresh's refusals are server's: a client
// with no binding in its network is restore_required (model.SidecarRestoreRequired), a removed one 401.
//
// A schedule scripts what the fault queue cannot: EndSession (a 401 with session_revoked), RefuseRefresh (a refused
// credential, 401), ForgetSidecarIdentities (a Postgres restore that lost the identity tables, so refresh answers
// restore_required until the newest binding is posted again), RevokeSidecarIdentity, and SetPreviewNetworks
// (D-TRUST-3's enrollment gate). Tokens are JWT-shaped, with server's claim names, HMAC-signed by a key of this api's
// alone, so a sidecar reads their claims as it reads server's and none could be a real one (CODESTYLE's test data
// rule).

package sidecartest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The codes the core routes answer, as server's routes and SidecarApi name them.
const (
	fakeApiCodeSessionRevoked     = "session_revoked"
	fakeApiCodeRestoreRequired    = "restore_required"
	fakeApiCodeSidecarRevoked     = "sidecar_revoked"
	fakeApiCodeBindingInvalid     = "binding_invalid"
	fakeApiCodeGenerationConflict = "generation_conflict"
	fakeApiCodeClientBound        = "client_bound"
	// D-TRUST-3's preview refusal: CORE-M1-09's reading, open in questions/core-m1-08-enroll-preview-code.md
	fakeApiCodeNotPreview = "not_preview"
	// §7.8: a tagged or ephemeral enrollment before base 1
	fakeApiCodeNoGenesis = "no_genesis"
	fakeApiCodeAuthKey   = "auth_key_invalid"
	// router's StrictExpProofRefusedMessage: a strict_exp bearer's request whose proof does not verify, 403 in plain text
	// before the handler runs, so an sdk does not sign out
	fakeApiStrictExpProofRefusedText = "A sidecar token needs a proof of its client key on this route."
)

// An identity's status, as server's model holds it.
const (
	fakeApiIdentityActive  = "active"
	fakeApiIdentityRevoked = "revoked"
)

// The most bindings one page of GET /sidecar/identity/<sidecar_id> lists, a format value of the route
// (plan-CORE-client-to-sidecar-lookup).
const fakeApiIdentityBindingPageCount = 64

// An auth key's id and secret, lowercase RFC 4648 base32 with no padding (config_authkey.go).
var fakeApiAuthKeyEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// What an auth key NewAuthKey mints allows (§7.8's credential row).
type FakeApiAuthKeyArgs struct {
	NetworkId sidecar.Id
	// How many enrollments it allows. Zero is one.
	UseCount int
	// How long it lasts from its mint. Zero is an hour.
	Timeout time.Duration
	// Its clients are tagged, so before base 1 enrollment answers no_genesis (§7.9's genesis row).
	Tagged bool
	// Its clients are ephemeral, which no_genesis refuses alike before base 1.
	Ephemeral bool
}

// One auth key, by its bearer.
type fakeApiAuthKey struct {
	networkId  sidecar.Id
	usesLeft   int
	expireTime time.Time
	tagged     bool
	ephemeral  bool
}

// One sidecar's identity row and its bindings (§5.15).
type fakeApiIdentity struct {
	networkId         sidecar.Id
	identityPublicKey []byte
	status            string
	// each generation's wrapper as received
	bindings map[int64][]byte
	newest   int64
}

// One client's binding, a client binding once.
type fakeApiClientBinding struct {
	sidecarId  sidecar.Id
	generation int64
	binding    []byte
}

// The core routes' state on FakeApi, under its stateLock.
type fakeApiCoreState struct {
	// signs the tokens this api mints
	tokenKey   []byte
	authKeys   map[string]*fakeApiAuthKey
	identities map[sidecar.Id]*fakeApiIdentity
	// client_id to its binding, across sidecars
	clientBindings map[sidecar.Id]*fakeApiClientBinding
	// the key each enrollment recorded, network_client_owner.client_public_key's (plan-TEAM-enroll-client-key)
	enrollClientKeys map[sidecar.Id]ed25519.PublicKey
	// clients whose session api ended: every route 401s them with session_revoked
	endedSessionClientIds map[sidecar.Id]bool
	// clients whose refresh api refuses with a bare 401
	refusedRefreshClientIds map[sidecar.Id]bool
	// D-TRUST-3's preview_networks; nil while stage 2 is live, so every network enrolls
	previewNetworkIds map[sidecar.Id]bool
	// how many requests each route has served, by method and pattern
	routeCounts map[string]int
	// each client's newest token's iat and exp, and how many it has had
	newestTokens     map[sidecar.Id]fakeApiTokenTimes
	clientTokenCount map[sidecar.Id]int
	// enrollment answers admin_refused false whatever the request sent, as an api without the mark would
	dropEnrollMarks bool
}

// A minted token's iat and exp.
type fakeApiTokenTimes struct {
	issuedAt   time.Time
	expireTime time.Time
}

func newFakeApiCoreState() fakeApiCoreState {
	tokenKey := make([]byte, 32)
	if _, err := rand.Read(tokenKey); err != nil {
		panic(err)
	}
	return fakeApiCoreState{
		tokenKey:                tokenKey,
		authKeys:                map[string]*fakeApiAuthKey{},
		identities:              map[sidecar.Id]*fakeApiIdentity{},
		clientBindings:          map[sidecar.Id]*fakeApiClientBinding{},
		enrollClientKeys:        map[sidecar.Id]ed25519.PublicKey{},
		endedSessionClientIds:   map[sidecar.Id]bool{},
		refusedRefreshClientIds: map[sidecar.Id]bool{},
		routeCounts:             map[string]int{},
		newestTokens:            map[sidecar.Id]fakeApiTokenTimes{},
		clientTokenCount:        map[sidecar.Id]int{},
	}
}

// The routes, on the api's mux.
func (self *FakeApi) addCoreRoutes() {
	self.mux.HandleFunc("POST /network/enroll", self.counted("POST /network/enroll", self.handleEnroll))
	self.mux.HandleFunc("POST /network/auth-client", self.counted("POST /network/auth-client", self.handleAuthClient))
	self.mux.HandleFunc("POST /network/remove-client", self.counted("POST /network/remove-client", self.handleRemoveClient))
	self.mux.HandleFunc("POST /sidecar/bind", self.counted("POST /sidecar/bind", self.handleBind))
	self.mux.HandleFunc("GET /sidecar/identity/{sidecarId}", self.counted("GET /sidecar/identity/<sidecar_id>", self.handleIdentity))
	self.mux.HandleFunc("GET /sidecar/identity", self.counted("GET /sidecar/identity", self.handleIdentityByClient))
	self.mux.HandleFunc("GET /auth/refresh", self.counted("GET /auth/refresh", self.handleRefresh))
}

// handler, counting each request it serves under route.
func (self *FakeApi) counted(route string, handler http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.core.routeCounts[route] += 1
		}()
		handler(writer, request)
	}
}

// How many requests route has served, as "METHOD /path" with <sidecar_id> for the identity route's id.
func (self *FakeApi) RouteCount(route string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.core.routeCounts[route]
}

// Mints client's token, as server signs a by_jwt: client_id, device_id, session_id, network_id, create_time,
// strict_exp, iat, exp and a random jti. exp is ClientTokenTimeout from now, §7.4's 7 days. The token maps to a copy
// of client.
func (self *FakeApi) mintClientToken(client *fakeApiClient) string {
	now := self.clock.Now()
	minted := *client
	minted.expireTime = now.Add(self.settings.ClientTokenTimeout)
	claims := map[string]any{
		"network_id":  minted.networkId.String(),
		"client_id":   minted.clientId.String(),
		"device_id":   minted.deviceId.String(),
		"session_id":  minted.sessionId.String(),
		"create_time": minted.createTime.UTC().Format(time.RFC3339Nano),
		"iat":         now.Unix(),
		"exp":         minted.expireTime.Unix(),
		"jti":         sidecar.NewId().String(),
	}
	if minted.strictExp {
		claims["strict_exp"] = true
	}
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		panic(err)
	}
	claimBytes, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claimBytes)
	token := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		mac := hmac.New(sha256.New, self.core.tokenKey)
		mac.Write([]byte(signingInput))
		token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		self.bearerClients[token] = &minted
		self.core.newestTokens[minted.clientId] = fakeApiTokenTimes{issuedAt: now, expireTime: minted.expireTime}
		self.core.clientTokenCount[minted.clientId] += 1
		return token
	}()
	if self.secretSink != nil {
		self.secretSink("by_client_jwt", []byte(token))
	}
	self.mints.Update(func(count uint64) uint64 {
		return count + 1
	})
	return token
}

// Mints an auth key of args.NetworkId, ur-authkey-<id>-<secret> (§7.8), with no bundle: a key a person holds after
// creating it on another device. Synthetic, as no real api could have made it.
func (self *FakeApi) NewAuthKey(args *FakeApiAuthKeyArgs) string {
	id := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	bearer := "ur-authkey-" + fakeApiAuthKeyEncoding.EncodeToString(id) + "-" + fakeApiAuthKeyEncoding.EncodeToString(secret)
	useCount := args.UseCount
	if useCount <= 0 {
		useCount = 1
	}
	timeout := args.Timeout
	if timeout <= 0 {
		timeout = time.Hour
	}
	expireTime := self.clock.Now().Add(timeout)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.core.authKeys[bearer] = &fakeApiAuthKey{
			networkId:  args.NetworkId,
			usesLeft:   useCount,
			expireTime: expireTime,
			tagged:     args.Tagged,
			ephemeral:  args.Ephemeral,
		}
	}()
	if self.secretSink != nil {
		self.secretSink("auth_key", []byte(bearer))
	}
	return bearer
}

// Ends the client's session, as server/session's revocation does: every route, refresh included, answers its tokens
// 401 with session_revoked, which §18.5 maps to session_ended.
func (self *FakeApi) EndSession(clientId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.core.endedSessionClientIds[clientId] = true
}

// Makes the client's refresh a refused credential: 401 with no code, which ends the generation as refused.
func (self *FakeApi) RefuseRefresh(clientId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.core.refusedRefreshClientIds[clientId] = true
}

// Drops the network's identity rows and bindings, as a Postgres restore to before them does (§19.10): a strict_exp
// client's refresh then answers restore_required until its newest binding is posted again.
func (self *FakeApi) ForgetSidecarIdentities(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for sidecarId, identity := range self.core.identities {
		if identity.networkId != networkId {
			continue
		}
		delete(self.core.identities, sidecarId)
		for clientId, binding := range self.core.clientBindings {
			if binding.sidecarId == sidecarId {
				delete(self.core.clientBindings, clientId)
			}
		}
	}
}

// Marks the identity revoked, as api records a verified SidecarRevoke: its next bind answers sidecar_revoked.
func (self *FakeApi) RevokeSidecarIdentity(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if identity := self.core.identities[sidecarId]; identity != nil {
		identity.status = fakeApiIdentityRevoked
	}
}

// Sets D-TRUST-3's preview_networks: a strict_exp enrollment or mint outside them answers 403 not_preview. nil lifts
// the gate, as stage 2 does.
func (self *FakeApi) SetPreviewNetworks(networkIds []sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if networkIds == nil {
		self.core.previewNetworkIds = nil
		return
	}
	self.core.previewNetworkIds = map[sidecar.Id]bool{}
	for _, networkId := range networkIds {
		self.core.previewNetworkIds[networkId] = true
	}
}

// Whether a strict_exp client of networkId may be minted now (D-TRUST-3).
func (self *FakeApi) previewAllows(networkId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.core.previewNetworkIds == nil || self.core.previewNetworkIds[networkId]
}

// The key a client's proofs must be signed by: its newest binding's, else the key its enrollment recorded, else none
// (plan-TEAM-enroll-client-key).
func (self *FakeApi) proofKey(clientId sidecar.Id) ed25519.PublicKey {
	if key := self.clientKey(clientId); key != nil {
		return key
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.core.enrollClientKeys[clientId]
}

// The bound client a request's bearer names, or nil after answering 401, with session_revoked for an ended session.
func (self *FakeApi) requireClient(writer http.ResponseWriter, request *http.Request) (*fakeApiClient, string) {
	bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !found {
		fakeApiRefuse(writer, http.StatusUnauthorized, "unauthorized", "Unauthorized.", nil)
		return nil, ""
	}
	client, code := self.clientOfTokenRefusal(bearer)
	if client == nil {
		if code == "" {
			code = "unauthorized"
		}
		fakeApiRefuse(writer, http.StatusUnauthorized, code, "Unauthorized.", nil)
		return nil, ""
	}
	return client, bearer
}

// Checks a strict_exp bearer's proof of its ClientKey for route's uri, spending its jti, or answers false after
// router's refusal: 403 in plain text, as server's strict_exp proof gate answers before the handler runs. A bearer
// without strict_exp needs none, as §7.4's rule binds only marked clients.
func (self *FakeApi) requireProof(writer http.ResponseWriter, request *http.Request, client *fakeApiClient, bearer string, path string) bool {
	if !client.strictExp {
		return true
	}
	proofs := request.Header.Values("DPoP")
	key := self.proofKey(client.clientId)
	if len(proofs) != 1 || key == nil {
		http.Error(writer, fakeApiStrictExpProofRefusedText, http.StatusForbidden)
		return false
	}
	err := self.verifyDpop(&fakeApiDpopRequest{
		proof:    proofs[0],
		method:   request.Method,
		uri:      self.settings.Origin + path,
		token:    bearer,
		key:      key,
		replayId: client.clientId,
	})
	if err != nil {
		http.Error(writer, fakeApiStrictExpProofRefusedText, http.StatusForbidden)
		return false
	}
	return true
}

// POST /network/enroll's body (§7.8), as SidecarApi.Enroll sends it.
type fakeApiEnrollArgs struct {
	AuthKey          string `json:"auth_key"`
	ClientPublicKey  []byte `json:"client_public_key"`
	DeviceSpec       string `json:"device_spec"`
	DeclaresNoEgress bool   `json:"declares_no_egress"`
	AdminRefused     bool   `json:"admin_refused"`
	StrictExp        bool   `json:"strict_exp"`
}

// POST /network/enroll's answer.
type fakeApiEnrollResult struct {
	ByClientJwt   string     `json:"by_client_jwt"`
	ClientId      sidecar.Id `json:"client_id"`
	ApprovalState string     `json:"approval_state"`
	AdminRefused  bool       `json:"admin_refused"`
	Close         string     `json:"close,omitempty"`
}

// Whether base 1 has landed in the network's log, which a tagged or ephemeral enrollment waits for (§7.9's genesis).
func (self *FakeApi) hasBaseOne(request *http.Request, networkId sidecar.Id) bool {
	pin, err := self.Tip(request.Context(), networkId)
	return err == nil && pin != nil && 1 <= pin.GetVersion()
}

// POST /network/enroll (§7.8): Public. An auth key's bearer, never one holding # (D-TEAM-22) or a urn_ key, mints a
// top-level client of the key's network carrying the marks the request sends, records its ClientKey, and spends one
// use. A strict_exp client outside preview_networks answers 403 not_preview, and a tagged or ephemeral key before
// base 1 403 no_genesis. approval_state is pending: admission is the config repo's SidecarAdmit, not api's.
func (self *FakeApi) handleEnroll(writer http.ResponseWriter, request *http.Request) {
	args := &fakeApiEnrollArgs{}
	if !self.readJson(writer, request, args) {
		return
	}
	if strings.Contains(args.AuthKey, "#") || strings.HasPrefix(args.AuthKey, "urn_") {
		fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "The auth key is not an auth key's bearer.", nil)
		return
	}
	if len(args.ClientPublicKey) != ed25519.PublicKeySize || args.DeviceSpec == "" {
		fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "The client key or device is missing.", nil)
		return
	}
	now := self.clock.Now()
	authKey := func() *fakeApiAuthKey {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		authKey := self.core.authKeys[args.AuthKey]
		if authKey == nil || authKey.usesLeft <= 0 || !now.Before(authKey.expireTime) {
			return nil
		}
		copied := *authKey
		return &copied
	}()
	if authKey == nil {
		fakeApiRefuse(writer, http.StatusUnauthorized, fakeApiCodeAuthKey, "The auth key is not valid.", nil)
		return
	}
	if args.StrictExp && !self.previewAllows(authKey.networkId) {
		fakeApiRefuse(writer, http.StatusForbidden, fakeApiCodeNotPreview, "Sidecars are in preview for some networks only.", nil)
		return
	}
	if (authKey.tagged || authKey.ephemeral) && !self.hasBaseOne(request, authKey.networkId) {
		fakeApiRefuse(writer, http.StatusForbidden, fakeApiCodeNoGenesis, "The network has no genesis yet.", nil)
		return
	}
	spent := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		authKey := self.core.authKeys[args.AuthKey]
		if authKey == nil || authKey.usesLeft <= 0 {
			return false
		}
		authKey.usesLeft -= 1
		return true
	}()
	if !spent {
		fakeApiRefuse(writer, http.StatusUnauthorized, fakeApiCodeAuthKey, "The auth key is not valid.", nil)
		return
	}
	clientId := sidecar.NewId()
	adminRefused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.core.enrollClientKeys[clientId] = slices.Clone(ed25519.PublicKey(args.ClientPublicKey))
		return args.AdminRefused && !self.core.dropEnrollMarks
	}()
	token := self.mintClientToken(&fakeApiClient{
		networkId:    authKey.networkId,
		clientId:     clientId,
		deviceId:     sidecar.NewId(),
		sessionId:    sidecar.NewId(),
		strictExp:    args.StrictExp,
		adminRefused: adminRefused,
		createTime:   now,
	})
	fakeApiWriteJson(writer, http.StatusOK, &fakeApiEnrollResult{
		ByClientJwt:   token,
		ClientId:      clientId,
		ApprovalState: "pending",
		AdminRefused:  adminRefused,
	})
}

// POST /network/auth-client's body, as SidecarApi.AuthClient sends it.
type fakeApiAuthClientArgs struct {
	ClientId         *sidecar.Id `json:"client_id,omitempty"`
	SourceClientId   *sidecar.Id `json:"source_client_id,omitempty"`
	Description      string      `json:"description"`
	DeviceSpec       string      `json:"device_spec"`
	DeclaresNoEgress bool        `json:"declares_no_egress"`
	AdminRefused     bool        `json:"admin_refused"`
	StrictExp        bool        `json:"strict_exp"`
}

// POST /network/auth-client's answer, its refusals in a 200's error object as connect/api/bringyour.yml has them.
type fakeApiAuthClientResult struct {
	ByClientJwt  string                    `json:"by_client_jwt,omitempty"`
	ClientId     *sidecar.Id               `json:"client_id,omitempty"`
	AdminRefused bool                      `json:"admin_refused,omitempty"`
	StrictExp    bool                      `json:"strict_exp,omitempty"`
	Error        *fakeApiAuthClientRefusal `json:"error,omitempty"`
}

type fakeApiAuthClientRefusal struct {
	Message string `json:"message"`
}

// POST /network/auth-client (§7.4): with the ClientKey's proof, reissues a token for the bearer's own client, or
// mints a child of it, which inherits both marks whatever the request says. Any other client is refused in the 200's
// error object, as server's route answers one it may not touch. A strict_exp child outside preview_networks is 403
// not_preview.
func (self *FakeApi) handleAuthClient(writer http.ResponseWriter, request *http.Request) {
	client, bearer := self.requireClient(writer, request)
	if client == nil {
		return
	}
	if !self.requireProof(writer, request, client, bearer, "/network/auth-client") {
		return
	}
	args := &fakeApiAuthClientArgs{}
	if !self.readJson(writer, request, args) {
		return
	}
	refuse := func(message string) {
		fakeApiWriteJson(writer, http.StatusOK, &fakeApiAuthClientResult{Error: &fakeApiAuthClientRefusal{Message: message}})
	}
	now := self.clock.Now()
	switch {
	case args.ClientId != nil:
		if *args.ClientId != client.clientId {
			refuse("Invalid client.")
			return
		}
		reissued := *client
		reissued.createTime = now
		token := self.mintClientToken(&reissued)
		clientId := client.clientId
		fakeApiWriteJson(writer, http.StatusOK, &fakeApiAuthClientResult{ByClientJwt: token, ClientId: &clientId, AdminRefused: client.adminRefused, StrictExp: client.strictExp})
	case args.SourceClientId != nil:
		if *args.SourceClientId != client.clientId {
			refuse("Invalid source client.")
			return
		}
		strictExp := client.strictExp || args.StrictExp
		if strictExp && !self.previewAllows(client.networkId) {
			fakeApiRefuse(writer, http.StatusForbidden, fakeApiCodeNotPreview, "Sidecars are in preview for some networks only.", nil)
			return
		}
		childId := sidecar.NewId()
		token := self.mintClientToken(&fakeApiClient{
			networkId:      client.networkId,
			clientId:       childId,
			deviceId:       client.deviceId,
			sessionId:      sidecar.NewId(),
			strictExp:      strictExp,
			adminRefused:   true,
			sourceClientId: client.clientId,
			createTime:     now,
		})
		fakeApiWriteJson(writer, http.StatusOK, &fakeApiAuthClientResult{ByClientJwt: token, ClientId: &childId, AdminRefused: true, StrictExp: strictExp})
	default:
		refuse("A sidecar reissues its own client or mints a child of it.")
	}
}

// POST /network/remove-client's body.
type fakeApiRemoveClientArgs struct {
	ClientId sidecar.Id `json:"client_id"`
}

// POST /network/remove-client (§7.4's OwnClient): the bearer's own client or a child of it. Any other is refused in
// the 200's error object; a removed client's tokens authenticate nowhere after.
func (self *FakeApi) handleRemoveClient(writer http.ResponseWriter, request *http.Request) {
	client, _ := self.requireClient(writer, request)
	if client == nil {
		return
	}
	args := &fakeApiRemoveClientArgs{}
	if !self.readJson(writer, request, args) {
		return
	}
	own := args.ClientId == client.clientId || func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, other := range self.bearerClients {
			if other.clientId == args.ClientId && other.sourceClientId == client.clientId {
				return true
			}
		}
		return false
	}()
	if !own {
		fakeApiWriteJson(writer, http.StatusOK, map[string]any{"error": map[string]string{"message": "Invalid client."}})
		return
	}
	self.RemoveClient(args.ClientId)
	fakeApiWriteJson(writer, http.StatusOK, map[string]any{})
}

// POST /sidecar/bind's body and answer (plan-CORE-binding-wire #6).
type fakeApiBindArgs struct {
	Binding []byte `json:"binding"`
}

type fakeApiBindResult struct {
	Generation int64 `json:"generation"`
}

// POST /sidecar/bind (§5.5, §5.6), as server's SidecarBind and BindSidecarIdentity: both signatures verify over the
// received bytes (sidecar.VerifySidecarIdentityBinding); the bearer is the binding's client in its network, and the
// binding carries the ClientKey its enrollment recorded; a client binds once, a byte-identical retry answering its
// generation; a sidecar_id's first binding is generation 1, each later one the newest plus one under the same
// identity key, and a re-registration after a restore, its identity row gone, is admitted at any generation, as
// server's seam admits it until TEAM-M2-16. A bind maps the client's tokens to the sidecar, which the log's routes
// read as its admission's subject.
func (self *FakeApi) handleBind(writer http.ResponseWriter, request *http.Request) {
	client, _ := self.requireClient(writer, request)
	if client == nil {
		return
	}
	args := &fakeApiBindArgs{}
	if !self.readJson(writer, request, args) {
		return
	}
	invalid := func(text string) {
		fakeApiRefuse(writer, http.StatusBadRequest, fakeApiCodeBindingInvalid, text, nil)
	}
	binding, err := sidecar.VerifySidecarIdentityBinding(args.Binding)
	if err != nil {
		invalid("The binding is invalid.")
		return
	}
	if binding.ClientId != client.clientId || binding.NetworkId != client.networkId {
		invalid("The binding names another client or network than the token's.")
		return
	}
	code, generation := func() (string, int64) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if enrollKey := self.core.enrollClientKeys[binding.ClientId]; enrollKey != nil && !bytes.Equal(enrollKey, binding.ClientPublicKey) {
			return fakeApiCodeBindingInvalid, 0
		}
		if stored := self.core.clientBindings[binding.ClientId]; stored != nil {
			if bytes.Equal(stored.binding, args.Binding) {
				return "", stored.generation
			}
			return fakeApiCodeClientBound, 0
		}
		identity := self.core.identities[binding.SidecarId]
		if identity == nil {
			// a first binding, or a re-registration after a restore, which the seam admits at M1
			identity = &fakeApiIdentity{
				networkId:         binding.NetworkId,
				identityPublicKey: slices.Clone(binding.IdentityPublicKey),
				status:            fakeApiIdentityActive,
				bindings:          map[int64][]byte{},
				newest:            binding.Generation - 1,
			}
			self.core.identities[binding.SidecarId] = identity
		}
		if identity.status == fakeApiIdentityRevoked {
			return fakeApiCodeSidecarRevoked, 0
		}
		if identity.networkId != binding.NetworkId || !bytes.Equal(identity.identityPublicKey, binding.IdentityPublicKey) ||
			binding.Generation != identity.newest+1 {
			return fakeApiCodeGenerationConflict, 0
		}
		identity.bindings[binding.Generation] = slices.Clone(args.Binding)
		identity.newest = binding.Generation
		self.core.clientBindings[binding.ClientId] = &fakeApiClientBinding{
			sidecarId:  binding.SidecarId,
			generation: binding.Generation,
			binding:    slices.Clone(args.Binding),
		}
		self.exchange.clientKeys[binding.ClientId] = slices.Clone(ed25519.PublicKey(binding.ClientPublicKey))
		for bearer, other := range self.bearerClients {
			if other.clientId == binding.ClientId {
				bound := *other
				bound.sidecarId = binding.SidecarId
				self.bearerClients[bearer] = &bound
			}
		}
		return "", binding.Generation
	}()
	switch code {
	case "":
		fakeApiWriteJson(writer, http.StatusOK, &fakeApiBindResult{Generation: generation})
	case fakeApiCodeBindingInvalid:
		invalid("The binding does not carry the client's enrolled key.")
	case fakeApiCodeSidecarRevoked:
		fakeApiRefuse(writer, http.StatusForbidden, code, "The sidecar is revoked.", nil)
	case fakeApiCodeClientBound:
		fakeApiRefuse(writer, http.StatusConflict, code, "The client is bound already.", nil)
	default:
		fakeApiRefuse(writer, http.StatusConflict, code, "The binding is not the next generation of its identity.", nil)
	}
}

// GET /sidecar/identity's answer, never a user_id (§5.15).
type fakeApiIdentityResult struct {
	SidecarId         sidecar.Id `json:"sidecar_id"`
	IdentityPublicKey []byte     `json:"identity_public_key"`
	IdentityAlg       string     `json:"identity_alg"`
	Status            string     `json:"status"`
	Binding           []byte     `json:"binding"`
	Bindings          [][]byte   `json:"bindings,omitempty"`
}

// The identity's answer in the caller's network, nil for none: its current binding, the client's when clientId is
// set, and by sidecar a page of bindings below beforeGeneration, newest first.
func (self *FakeApi) identityResult(callerNetworkId sidecar.Id, sidecarId sidecar.Id, clientId *sidecar.Id, beforeGeneration int64) *fakeApiIdentityResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity := self.core.identities[sidecarId]
	if identity == nil || identity.networkId != callerNetworkId {
		return nil
	}
	result := &fakeApiIdentityResult{
		SidecarId:         sidecarId,
		IdentityPublicKey: slices.Clone(identity.identityPublicKey),
		IdentityAlg:       "ed25519",
		Status:            identity.status,
		Binding:           slices.Clone(identity.bindings[identity.newest]),
	}
	if clientId != nil {
		result.Binding = slices.Clone(self.core.clientBindings[*clientId].binding)
		return result
	}
	result.Bindings = [][]byte{}
	for generation := identity.newest; 0 < generation && len(result.Bindings) < fakeApiIdentityBindingPageCount; generation -= 1 {
		if 0 < beforeGeneration && beforeGeneration <= generation {
			continue
		}
		if binding, ok := identity.bindings[generation]; ok {
			result.Bindings = append(result.Bindings, slices.Clone(binding))
		}
	}
	return result
}

// GET /sidecar/identity/<sidecar_id>[?before_generation=<g>]: a sidecar of the caller's network, 404 otherwise.
func (self *FakeApi) handleIdentity(writer http.ResponseWriter, request *http.Request) {
	client, _ := self.requireClient(writer, request)
	if client == nil {
		return
	}
	sidecarId, err := sidecar.ParseId(request.PathValue("sidecarId"))
	if err != nil {
		fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "Invalid sidecar id.", nil)
		return
	}
	beforeGeneration := int64(0)
	if before := request.URL.Query().Get("before_generation"); before != "" {
		beforeGeneration, err = strconv.ParseInt(before, 10, 64)
		if err != nil || beforeGeneration < 1 {
			fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "Invalid generation.", nil)
			return
		}
	}
	result := self.identityResult(client.networkId, sidecarId, nil, beforeGeneration)
	if result == nil {
		fakeApiRefuse(writer, http.StatusNotFound, "not_found", "No such sidecar identity.", nil)
		return
	}
	fakeApiWriteJson(writer, http.StatusOK, result)
}

// GET /sidecar/identity?client_id=<id>: the sidecar a client of the caller's network binds, 404 for none.
func (self *FakeApi) handleIdentityByClient(writer http.ResponseWriter, request *http.Request) {
	client, _ := self.requireClient(writer, request)
	if client == nil {
		return
	}
	clientId, err := sidecar.ParseId(request.URL.Query().Get("client_id"))
	if err != nil {
		fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "Invalid client id.", nil)
		return
	}
	sidecarId, found := func() (sidecar.Id, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		binding := self.core.clientBindings[clientId]
		if binding == nil {
			return sidecar.Id{}, false
		}
		return binding.sidecarId, true
	}()
	var result *fakeApiIdentityResult
	if found {
		result = self.identityResult(client.networkId, sidecarId, &clientId, 0)
	}
	if result == nil {
		fakeApiRefuse(writer, http.StatusNotFound, "not_found", "No such sidecar identity.", nil)
		return
	}
	fakeApiWriteJson(writer, http.StatusOK, result)
}

// GET /auth/refresh's answer: a token, or a refusal in its error object, as server's RefreshTokenResult.
type fakeApiRefreshResult struct {
	ByJwt string                 `json:"by_jwt,omitempty"`
	Error *fakeApiRefreshRefusal `json:"error,omitempty"`
}

type fakeApiRefreshRefusal struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// GET /auth/refresh (§5.6, §7.4), as server's RefreshToken: the bearer, its proof if strict_exp, then a client with
// no binding in its network answers restore_required (model.SidecarRestoreRequired), which is no refusal; else a new
// token for the same client and device, its create_time kept. A refused credential is a 401.
func (self *FakeApi) handleRefresh(writer http.ResponseWriter, request *http.Request) {
	client, bearer := self.requireClient(writer, request)
	if client == nil {
		return
	}
	if !self.requireProof(writer, request, client, bearer, "/auth/refresh") {
		return
	}
	refused, bound := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		binding := self.core.clientBindings[client.clientId]
		bound := binding != nil && self.core.identities[binding.sidecarId] != nil &&
			self.core.identities[binding.sidecarId].networkId == client.networkId
		return self.core.refusedRefreshClientIds[client.clientId], bound
	}()
	if refused {
		fakeApiRefuse(writer, http.StatusUnauthorized, "unauthorized", "Unauthorized.", nil)
		return
	}
	if client.strictExp && !bound {
		fakeApiWriteJson(writer, http.StatusOK, &fakeApiRefreshResult{Error: &fakeApiRefreshRefusal{
			Message: "Re-register this sidecar, then refresh again.",
			Code:    fakeApiCodeRestoreRequired,
		}})
		return
	}
	fakeApiWriteJson(writer, http.StatusOK, &fakeApiRefreshResult{ByJwt: self.mintClientToken(client)})
}

// The client a token names, for a test: its network, client and bound sidecar. False for a token this api never
// minted.
func (self *FakeApi) TokenClient(token string) (networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	client := self.bearerClients[token]
	if client == nil {
		return sidecar.Id{}, sidecar.Id{}, sidecar.Id{}, false
	}
	return client.networkId, client.clientId, client.sidecarId, true
}

// The identity api holds for sidecarId: its status and newest generation, false for none.
func (self *FakeApi) SidecarIdentity(sidecarId sidecar.Id) (status string, newestGeneration int64, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity := self.core.identities[sidecarId]
	if identity == nil {
		return "", 0, false
	}
	return identity.status, identity.newest, true
}

// The iat and exp, on the api's clock, of the newest token this api minted for the client, false for none.
func (self *FakeApi) NewestClientToken(clientId sidecar.Id) (issuedAt time.Time, expireTime time.Time, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	times, ok := self.core.newestTokens[clientId]
	return times.issuedAt, times.expireTime, ok
}

// How many tokens this api has minted for the client.
func (self *FakeApi) ClientTokenCount(clientId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.core.clientTokenCount[clientId]
}

// How many tokens this api has minted, and a channel that closes at the next, armed before the read, so a test waits
// for one with no sleep.
func (self *FakeApi) Mints() (uint64, <-chan struct{}) {
	return self.mints.Get()
}

// Makes enrollment answer admin_refused false whatever the request sent, as an api without §7.4's mark would, so a
// schedule sees D-CORE-7's fail-closed path. false restores the mark.
func (self *FakeApi) SetEnrollDropsMarks(drop bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.core.dropEnrollMarks = drop
}

// Whether the client was removed.
func (self *FakeApi) ClientRemoved(clientId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.removedClientIds[clientId]
}
