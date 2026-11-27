//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §8.6's tokens (R-GW-1, D-GW-3, IC-11, I-7; GW-M12-02).
//
//	mint     `ur gateway token --harness <h> [--agent <label>]`, which Codex's auth command and Claude Code's
//	         apiKeyHelper run, asks the daemon's gateway.token over its control socket once it has proved the listener
//	         (gateway_proof.go), and prints ur_gw_ and GatewaySettings.TokenByteCount random bytes in base64url, valid
//	         TokenLife, an hour, so a token on disk lives at most an hour (Claude Code caches a helper's output for 5
//	         minutes). The daemon mints only while it serves the port, for the grant of that harness and agent label on
//	         the network named, or the one network holding such a grant
//	keep     the network's grant store keeps the token's SHA-256, its grant, its expiry and the run handle it is
//	         (gateway_grant.go, gateway_bind.go), fsynced before the token is answered, and never the token itself, which
//	         only its command prints
//	present  Authorization: Bearer <token> or x-api-key: <token>; the token's hash is looked up, the hashes compared in
//	         constant time, a lookup's timing depending on the presented token's hash alone. A token past its hour, of a
//	         revoked grant or of none is refused 401, which Codex and Claude Code answer by running their credential
//	         command again; while a network's grants do not read, a token none of the readable ones knows is refused 503
//	reach    the token reaches the gateway's own routes on its listener and nothing else: no other listener or socket
//	         takes it, a route acts for the token's own grant alone, whatever a request names, and none administers,
//	         reads or signs anything but that grant's calls and budget state (IC-11, I-7), as the telemetry token only
//	         adds reports. Grants are made, listed and revoked through the daemon's control socket alone
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The token's prefix, the headers that carry it, and the path the Messages front's routes start with: format values.
const (
	GatewayTokenPrefix              = "ur_gw_"
	DaemonMethodGatewayToken        = "gateway.token"
	DaemonMethodGatewayGrants       = "gateway.grants"
	gatewayHeaderAuthorization      = "Authorization"
	gatewayAuthorizationBearer      = "bearer "
	gatewayHeaderApiKey             = "X-Api-Key"
	gatewayMessagesPathPrefix       = "/v1/messages"
	gatewayAuthOpenAiType           = "invalid_request_error"
	gatewayAuthOpenAiCode           = "invalid_api_key"
	gatewayAuthOpenAiUnavailable    = "service_unavailable"
	gatewayAuthOpenAiServerType     = "server_error"
	gatewayAuthAnthropicType        = "authentication_error"
	gatewayAuthAnthropicUnavailable = "api_error"
)

// A fresh token and its SHA-256: GatewayTokenPrefix and settings.TokenByteCount random bytes from random, crypto/rand's
// reader when nil, in base64url.
func newGatewayToken(settings *GatewaySettings, random io.Reader) (string, [sha256.Size]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	if settings.TokenByteCount <= 0 {
		return "", [sha256.Size]byte{}, fmt.Errorf("%w: a token of no bytes", errInvalidSettings)
	}
	raw := make([]byte, settings.TokenByteCount)
	defer clear(raw)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	token := GatewayTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	testHookSecret("gateway_token", []byte(token))
	return token, GatewayTokenSha256(token), nil
}

// What the store keeps of a token.
func GatewayTokenSha256(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// The token a request presents, in Authorization as a bearer or in x-api-key; "" for none, or for one that is not a
// gateway token's form.
func gatewayRequestToken(request *http.Request) string {
	token := ""
	if authorization := request.Header.Get(gatewayHeaderAuthorization); authorization != "" {
		if len(authorization) <= len(gatewayAuthorizationBearer) || !strings.EqualFold(authorization[:len(gatewayAuthorizationBearer)], gatewayAuthorizationBearer) {
			return ""
		}
		token = strings.TrimSpace(authorization[len(gatewayAuthorizationBearer):])
	} else {
		token = strings.TrimSpace(request.Header.Get(gatewayHeaderApiKey))
	}
	if !strings.HasPrefix(token, GatewayTokenPrefix) {
		return ""
	}
	return token
}

// The command a harness's credential command runs, which binds its tokens to the harness (§8.6, §8.9).
func GatewayTokenCommand(harness string, agentLabel string) string {
	command := "ur gateway token --harness " + harness
	if agentLabel != "" && agentLabel != harness {
		command += " --agent " + agentLabel
	}
	return command
}

// The grant and run handle an authenticated request acts for, which a front reads. Copies: a front changes nothing
// through them.
type GatewayCaller struct {
	NetworkId Id
	Network   GatewayNetwork
	Store     *GatewayGrantStore
	Grant     *GatewayGrant
	// The token's record: its hash, never the token, and its run handle, nil for an unbound token.
	Token *GatewayTokenRecord
}

// A front's handler, reached only with a grant's token.
type GatewayHandler func(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller)

// Registers a front's route behind the guard and the token: a request without a token of a standing grant is refused
// before handler runs, and handler acts for that grant alone.
func (self *GatewayServer) Handle(pattern string, handler GatewayHandler) {
	self.mux.Handle(pattern, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		caller, status, err := self.authenticate(request)
		if err != nil {
			writeGatewayAuthRefusal(writer, request, status, err.Error())
			return
		}
		handler(writer, request, caller)
	}))
}

// The caller a request's token names: see the file header for the refusals.
func (self *GatewayServer) authenticate(request *http.Request) (*GatewayCaller, int, error) {
	token := gatewayRequestToken(request)
	if token == "" {
		return nil, http.StatusUnauthorized, errors.New("a gateway token is needed, as Authorization: Bearer ur_gw_... or x-api-key: run the harness's credential command")
	}
	hash := GatewayTokenSha256(token)
	hosts := self.gatewayHosts()
	if hosts == nil {
		return nil, http.StatusServiceUnavailable, errors.New("the daemon hosts no network yet")
	}
	unread := false
	for _, hosted := range hosts.GatewayNetworks() {
		store, err := hosted.Network.GatewayGrants()
		if err != nil {
			unread = true
			continue
		}
		grant, record, err := store.Authenticate(hash)
		switch {
		case err == nil:
			return &GatewayCaller{NetworkId: hosted.NetworkId, Network: hosted.Network, Store: store, Grant: grant, Token: record}, 0, nil
		case errors.Is(err, ErrGatewayTokenUnknown):
		case errors.Is(err, ErrGatewayTokenExpired), errors.Is(err, ErrGatewayGrantUnknown):
			return nil, http.StatusUnauthorized, fmt.Errorf("%s: run the harness's credential command for a new one", err)
		default:
			unread = true
		}
	}
	if unread {
		return nil, http.StatusServiceUnavailable, errors.New("the gateway's grants do not read now: the keychain may be locked (ur unlock)")
	}
	return nil, http.StatusUnauthorized, ErrGatewayTokenUnknown
}

// A refused token in the words of the API the request is to: Anthropic's for the Messages front, OpenAI's otherwise,
// which Codex and Claude Code show their person.
func writeGatewayAuthRefusal(writer http.ResponseWriter, request *http.Request, status int, message string) {
	var body any
	if strings.HasPrefix(request.URL.Path, gatewayMessagesPathPrefix) {
		kind := gatewayAuthAnthropicType
		if status != http.StatusUnauthorized {
			kind = gatewayAuthAnthropicUnavailable
		}
		body = map[string]any{"type": "error", "error": map[string]string{"type": kind, "message": message}}
	} else {
		kind, code := gatewayAuthOpenAiType, gatewayAuthOpenAiCode
		if status != http.StatusUnauthorized {
			kind, code = gatewayAuthOpenAiServerType, gatewayAuthOpenAiUnavailable
		}
		body = map[string]any{"error": map[string]any{"message": message, "type": kind, "param": nil, "code": code}}
	}
	encoded, _ := json.Marshal(body)
	writer.Header().Set("Content-Type", gatewayGuardContentType)
	if status == http.StatusUnauthorized {
		writer.Header().Set("WWW-Authenticate", "Bearer")
	}
	writer.WriteHeader(status)
	writer.Write(encoded)
}

// gateway.token's params.
type GatewayTokenParams struct {
	Harness string `json:"harness"`
	// The agent label, the harness's name where empty.
	Agent string `json:"agent,omitempty"`
	// The network argument; empty for the one network holding the grant.
	Network string `json:"network,omitempty"`
	// The minting command's stdout is a terminal, a person at a prompt: the token binds no process.
	Interactive bool `json:"interactive,omitempty"`
}

// gateway.token's answer: the token, which only the minting command prints.
type GatewayTokenReply struct {
	Token         string `json:"token"`
	ExpiresMillis int64  `json:"expires_millis"`
	GrantId       Id     `json:"grant_id"`
	// The token is a run handle of a harness process.
	Bound bool `json:"bound,omitempty"`
}

// Mints a token of params' grant for the caller of hello (gateway.token): only while the port is served, so a token
// never goes to a port the daemon does not hold; a run handle where the caller's ancestry, which the daemon reads from
// its socket's peer, names the grant's harness process, unbound otherwise (gateway_bind.go).
func (self *GatewayServer) MintToken(ctx context.Context, hello *DaemonHello, params *GatewayTokenParams) (*GatewayTokenReply, error) {
	if status := self.Status(); !status.Serving {
		return nil, fmt.Errorf("%w: %s", ErrGatewayNotServing, status.Reason)
	}
	if params.Harness == "" {
		return nil, fmt.Errorf("%w: a token names its harness", ErrGatewayGrantInvalid)
	}
	agentLabel := params.Agent
	if agentLabel == "" {
		agentLabel = params.Harness
	}
	network, store, grant, err := self.grantOf(hello, params.Network, params.Harness, agentLabel)
	if err != nil {
		return nil, err
	}
	var handle *GatewayRunHandle
	if !params.Interactive && hello != nil {
		handle = self.harnessHandle(ctx, network, grant.Harness, int(hello.PeerPid))
	}
	token, record, err := store.Mint(ctx, grant.GrantId, handle)
	if err != nil {
		return nil, err
	}
	return &GatewayTokenReply{Token: token, ExpiresMillis: record.ExpiresMillis, GrantId: grant.GrantId, Bound: handle != nil}, nil
}

// The standing grant of harness and agentLabel: on the network named, or on the one hosted network holding one.
func (self *GatewayServer) grantOf(hello *DaemonHello, network string, harness string, agentLabel string) (GatewayNetwork, *GatewayGrantStore, *GatewayGrant, error) {
	hosts := self.gatewayHosts()
	if hosts == nil {
		return nil, nil, nil, fmt.Errorf("%w: no network is hosted", ErrGatewayGrantUnknown)
	}
	only := Id{}
	if network != "" {
		networkId, err := hosts.ResolveNetwork(hello, network)
		if err != nil {
			return nil, nil, nil, err
		}
		only = networkId
	}
	type found struct {
		networkId Id
		network   GatewayNetwork
		store     *GatewayGrantStore
		grant     *GatewayGrant
	}
	founds := []*found{}
	unread := []string{}
	for _, hosted := range hosts.GatewayNetworks() {
		if only != (Id{}) && hosted.NetworkId != only {
			continue
		}
		store, err := hosted.Network.GatewayGrants()
		var grant *GatewayGrant
		if err == nil {
			grant, err = store.GrantOf(harness, agentLabel)
		}
		switch {
		case err == nil:
			founds = append(founds, &found{networkId: hosted.NetworkId, network: hosted.Network, store: store, grant: grant})
		case !errors.Is(err, ErrGatewayGrantUnknown):
			unread = append(unread, fmt.Sprintf("network %s: %s", hosted.NetworkId, err))
		}
	}
	switch {
	case len(founds) == 1:
		return founds[0].network, founds[0].store, founds[0].grant, nil
	case 1 < len(founds):
		networkIds := []string{}
		for _, each := range founds {
			networkIds = append(networkIds, each.networkId.String())
		}
		return nil, nil, nil, fmt.Errorf("%w: grants of %s stand on networks %s: name one with --network", ErrGatewayGrantInvalid,
			GatewayTokenCommand(harness, agentLabel), strings.Join(networkIds, ", "))
	case 0 < len(unread):
		return nil, nil, nil, fmt.Errorf("%w: the grants of %s do not read now", ErrGatewayGrantUnknown, strings.Join(unread, "; "))
	}
	return nil, nil, nil, fmt.Errorf("%w: no grant of harness %s, agent %s: ur install-harness %s --gateway makes one",
		ErrGatewayGrantUnknown, harness, agentLabel, harness)
}

// Decodes a call's params into params, refusing a field it does not know. No params is an empty object.
func decodeGatewayParams(call *DaemonCall, params any) error {
	if len(call.Params) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(call.Params))
	decoder.DisallowUnknownFields()
	return decoder.Decode(params)
}
