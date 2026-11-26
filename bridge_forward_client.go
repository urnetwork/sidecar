// The VPN component's forwarding client F as the Forwarder reaches api and gkm through it (DESIGN-DETAILS 4.2.6's
// "after" row; §18.6's Setup; owner decision 197; SDK-M8-16): a SidecarApi presenting F's token with DPoP proofs of
// F's own ClientKey, which the component generated and keeps, so the component refreshes F, follows the log and opens
// the config's generations with no sidecar role running.
//
//	projection   ReadConfigProjection, the Forwarder's ConfigProjectionReader
//	gkm          Gkm, the Forwarder's ForwarderGkm: gkm's reads under service tokens F's exchange answers, each read
//	             with the scopes it granted (QD-1230), and the config's r presented as the scope the state the
//	             Forwarder last judged gives F, so a read the exchange refuses while api's gate lags that state is
//	             ridden out (forwardingClientGkm)
//	binding      Binding, the Forwarder's binding reader: GET /sidecar/identity/<sidecar_id>'s current binding, which
//	             the Forwarder verifies under the identity key its judged state admits
//	refresh      Refresh: GET /auth/refresh with F's proof, answering the new token and installing nothing; the
//	             component keeps it in its key store first and then installs it with SetByJwt (D-CORE-8's order)
//	links        AuthWindowClient and RemoveWindowClient: the window clients of the component's links, F's children,
//	             which the sdk's BridgeHost mints and retires (SDK-M8-08)
//	poll         SyncPoll: §6.8's long-poll on F, which brings team hints where no device client receives pushes
//	heads        ConfigHeads (bridge_forward_heads.go, on every leg as this file is): the config head reader the
//	             Forwarder reads each base's head through, on F's exchange for the config repo's read scope
//
// F's token is forward_only (§7.4): api takes it only on TEAM-M8-02's allowlist and exchanges it only for the config
// repo's read scope, so what this client can reach is what forwarding needs. It holds no identity key and signs no
// statement; its ClientKey signs only proofs. Neither the token nor the seed reaches a log line (I-7).
//
// On every leg, with no connect import: an app's VPN component links this file (DESIGN-DETAILS 4.2.3). The connect
// legs' transport is bridge_forward_client_connect.go's. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What a forwarding client is built over.
type ForwardingClientArgs struct {
	// The network's service urls: ApiUrl, AuthUrl and GkmUrl, and EvsUrl for the head reader. Validated as a
	// SidecarApi's are.
	Settings *SidecarSettings
	// What every request is sent through: the component's client strategy's (NewForwardingTransport), or a test's.
	// Nil refuses every request.
	Transport http.RoundTripper
	// F's token as the component last kept it.
	ByJwt string
	// F's ClientKey seed, 32 bytes, from the component's key store (fwd.<net8>.<slot>.client). Copied: the caller may
	// erase its own.
	ClientKeySeed []byte
	// This device's clock, which proofs' iat read against api's and gkm's reads wait on; nil is real time.
	Clock Clock
}

// F's api and gkm (the file's comment).
type ForwardingClient struct {
	api *SidecarApi
	gkm *forwardingClientGkm
	// the service urls it was built with, which the head reader reads evs's from
	evsUrl string
}

// A forwarding client over args. Settings, a token and a ClientKey seed are required.
func NewForwardingClient(args *ForwardingClientArgs) (*ForwardingClient, error) {
	if args == nil || args.Settings == nil || args.ByJwt == "" || len(args.ClientKeySeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: a forwarding client needs its settings, F's token and F's ClientKey seed", errInvalidSettings)
	}
	now := clockOrReal(args.Clock).Now
	api, err := newSidecarApi(args.Settings, args.Transport, now)
	if err != nil {
		return nil, err
	}
	signer, err := newDpopSigner(args.ClientKeySeed, now, api.currentApiClockOffset, rand.Reader)
	if err != nil {
		return nil, err
	}
	api.SetByJwt(args.ByJwt)
	api.setDpopSigner(signer)
	// as Sidecar.GkmApiArgs wires a member's: the token with the scopes the exchange granted it, the settings' gkm
	// settings and the clock. Each read exchanges, so no token is kept and none is forgotten after gkm's 401.
	gkm, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:    args.Settings.GkmUrl,
		Transport: api.Transport(),
		GrantedServiceToken: func(ctx context.Context, resource string, scopes []string) (string, []string, error) {
			token, err := api.ExchangeToken(ctx, resource, scopes)
			if err != nil {
				return "", nil, err
			}
			return token.AccessToken, slices.Clone(token.Scopes), nil
		},
		Settings: args.Settings.Gkm,
		Clock:    args.Clock,
	})
	if err != nil {
		return nil, err
	}
	return &ForwardingClient{api: api, gkm: &forwardingClientGkm{api: gkm}, evsUrl: args.Settings.EvsUrl}, nil
}

// The Forwarder's ConfigProjectionReader: GET /network/config/projection?after= on F.
func (self *ForwardingClient) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	return self.api.ReadConfigProjection(ctx, after)
}

// The Forwarder's ForwarderGkm, on F's exchange, which takes the scope each state the Forwarder judges gives F
// (forwardingClientGkm).
func (self *ForwardingClient) Gkm() ForwarderGkm {
	return self.gkm
}

// What the Forwarder hands a ForwarderGkm that takes it, before each compile's reads of gkm: the state that compile
// judged. The forwarding client's takes it (forwardingClientGkm); any other ForwarderGkm reads as it always did.
type forwarderGkmJudged interface {
	// Takes the state the Forwarder judged for sidecarId, its forwarding role's sidecar, at now.
	judgedState(state *ConfigState, sidecarId Id, now time.Time)
}

// F's GkmApi as the Forwarder reads gkm through it. Its reads present the config's r as the scope the state the
// Forwarder last judged gives F, its verified state's (GkmApi.SetRepoScopes), so a read the exchange refuses
// invalid_scope while api's gate lags that state is asked again ReadRetryWait apart until ExchangeScopeWaitTimeout has
// passed since its first such answer, as a member's read is (QD-1230; §8.9's targets), and one the exchange cannot
// answer yet, no answer from api or its 429 or 5xx, goes again within ExchangeRetryCount. Before a state is judged,
// and at one that gives F nothing, a read presents that scope as one no verified state backs, and its first failure to
// get a token ends it, as every read did before QD-1230. Safe for concurrent use, as GkmApi is.
type forwardingClientGkm struct {
	api *GkmApi
}

// Sets the scope F's reads present to the one state gives sidecarId's forwarding client F at gkm, by §7.8's
// forward_only row as AclExchangeScopes grants it, which the ios_extension leg does not link: the config repo's r while
// the sidecar's forwarding Delegation is live at the state and §8's rows give the sidecar r there at now, else none.
// The row's other condition, that F is the newest active forwarding child of the sidecar's current client, only api
// knows: an F that is not is refused invalid_grant, a refusal for good that no read rides out.
func (self *forwardingClientGkm) judgedState(state *ConfigState, sidecarId Id, now time.Time) {
	scopes := []GkmRepoScope{}
	if state != nil && sidecarId != (Id{}) && state.ForwardingDelegation(sidecarId) != nil {
		configRepoId, idErr := IdFromBytes(state.Genesis().GetConfigRepoId())
		acl, aclErr := state.Acl()
		if idErr == nil && aclErr == nil && configRepoId != (Id{}) &&
			acl.EvsAccess(AclSidecarSubject(sidecarId), configRepoId, AclTokenAudienceGkm, now).Rights.Has(AclEvsRead) {
			scopes = append(scopes, GkmRepoScope{RepoId: configRepoId, Role: GkmScopeRoleRead})
		}
	}
	self.api.SetRepoScopes(scopes)
}

// GkmApi's, under F's token.
func (self *forwardingClientGkm) Generations(ctx context.Context, repoId Id, groupId Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	return self.api.Generations(ctx, repoId, groupId, since)
}

// GkmApi's, under F's token.
func (self *forwardingClientGkm) Wraps(ctx context.Context, repoId Id, groupId Id, generation uint64, query *GkmWrapsQuery) (*protocol.GkmWrapsReply, error) {
	return self.api.Wraps(ctx, repoId, groupId, generation, query)
}

// GkmApi's, under F's token.
func (self *forwardingClientGkm) Forms(ctx context.Context, repoId Id) (*protocol.GkmFormsReply, error) {
	return self.api.Forms(ctx, repoId)
}

// The Forwarder's binding reader: sidecarId's current binding as api signed it. A record with none is an error.
func (self *ForwardingClient) Binding(ctx context.Context, sidecarId Id) ([]byte, error) {
	record, err := self.api.GetIdentity(ctx, sidecarId, 0)
	if err != nil {
		return nil, err
	}
	if len(record.Binding) == 0 {
		return nil, errors.New("api holds no current binding for the sidecar")
	}
	return record.Binding, nil
}

// POST /network/auth-client on F's token with F's proof (SDK-M8-08, §17.9's sign row, D-ACL-3): a window client of one
// of the component's links, F's child, which inherits forward_only and strict_exp, so C13 seals S's client as its
// subject. args names F as the parent; the caller refuses an answer that does not confirm the marks. Never F itself.
func (self *ForwardingClient) AuthWindowClient(ctx context.Context, args *SidecarAuthClientArgs) (*SidecarAuthClientResult, error) {
	if args == nil || args.SourceClientId == nil || args.ForwardOnly || 0 < len(args.ClientPublicKey) || args.ClientId != nil {
		return nil, fmt.Errorf("%w: a window client is a new child of F, never F", ErrSidecarApiArgs)
	}
	return self.api.AuthClient(ctx, args)
}

// POST /network/remove-client on F's token: a window client F minted, which a link retired.
func (self *ForwardingClient) RemoveWindowClient(ctx context.Context, clientId Id) error {
	return self.api.RemoveClient(ctx, clientId)
}

// GET /auth/refresh with F's proof: the new token, which the caller keeps before it installs it (the file's comment).
func (self *ForwardingClient) Refresh(ctx context.Context) (string, error) {
	return self.api.Refresh(ctx)
}

// Installs F's token for every later call, once the component has kept it.
func (self *ForwardingClient) SetByJwt(byJwt string) {
	self.api.SetByJwt(byJwt)
}

// One §6.8 long-poll on F, held up to 25 s by api: its team hints name log positions for the Forwarder.
func (self *ForwardingClient) SyncPoll(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	return self.api.SyncPoll(ctx, cursor)
}

// Says what it is, never the token.
func (self *ForwardingClient) String() string {
	return "ForwardingClient{}"
}

var (
	_ ConfigProjectionReader = (*ForwardingClient)(nil)
	_ ForwarderGkm           = (*forwardingClientGkm)(nil)
	_ forwarderGkmJudged     = (*forwardingClientGkm)(nil)
)
