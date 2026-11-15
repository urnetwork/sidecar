// The VPN component's forwarding client F as the Forwarder reaches api and gkm through it (DESIGN-DETAILS 4.2.6's
// "after" row; §18.6's Setup; owner decision 197; SDK-M8-16): a SidecarApi presenting F's token with DPoP proofs of
// F's own ClientKey, which the component generated and keeps, so the component refreshes F, follows the log and opens
// the config's generations with no sidecar role running.
//
//	projection   ReadConfigProjection, the Forwarder's ConfigProjectionReader
//	gkm          Gkm, the Forwarder's ForwarderGkm: gkm's reads under service tokens F's exchange answers
//	binding      Binding, the Forwarder's binding reader: GET /sidecar/identity/<sidecar_id>'s current binding, which
//	             the Forwarder verifies under the identity key its judged state admits
//	refresh      Refresh: GET /auth/refresh with F's proof, answering the new token and installing nothing; the
//	             component keeps it in its key store first and then installs it with SetByJwt (D-CORE-8's order)
//	poll         SyncPoll: §6.8's long-poll on F, which brings team hints where no device client receives pushes
//	heads        ConfigHeads (bridge_heads_forward.go, off the ios_extension leg): the config head reader the Forwarder
//	             reads each base's head through, on F's exchange for the config repo's read scope
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
	// This device's clock, which proofs' iat read against api's; nil is real time.
	Clock Clock
}

// F's api and gkm (the file's comment).
type ForwardingClient struct {
	api *SidecarApi
	gkm *GkmApi
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
	gkm, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:    args.Settings.GkmUrl,
		Transport: api.Transport(),
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			token, err := api.ExchangeToken(ctx, resource, scopes)
			if err != nil {
				return "", err
			}
			return token.AccessToken, nil
		},
	})
	if err != nil {
		return nil, err
	}
	return &ForwardingClient{api: api, gkm: gkm, evsUrl: args.Settings.EvsUrl}, nil
}

// The Forwarder's ConfigProjectionReader: GET /network/config/projection?after= on F.
func (self *ForwardingClient) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	return self.api.ReadConfigProjection(ctx, after)
}

// The Forwarder's ForwarderGkm, on F's exchange.
func (self *ForwardingClient) Gkm() ForwarderGkm {
	return self.gkm
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

var _ ConfigProjectionReader = (*ForwardingClient)(nil)
