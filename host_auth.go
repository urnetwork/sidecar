//go:build !sidecar_http && !ios_extension

// ServiceHost.Authenticator: how an engine learns who a bearer token names, without importing
// server/session.
//
// A token that does not name its network and client refuses. It never authenticates with zero ids:
// the rev/ check reads rev/<network_id>/<kind>/<subject_id>/_, and a key under the zero network exists
// for no one, so a removed client's unexpired token would read as not revoked (§7.8, I-15). §7.8's
// claim list has no network claim yet, so until it gains one no service token authenticates.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect"
)

// A token that will not authenticate: bad signature, wrong audience, expired or revoked at the
// issuer. An engine answers 401. Any other Authenticate error says nothing about the token, and the
// engine answers unavailable, so a caller retries instead of signing out.
var ErrAuthenticationRefused = errors.New("authentication refused")

// Who a verified token names. Service tokens carry §7.8's claims. NetworkId, ClientId and Audience are
// required, and Validate refuses a value without them. A claim marked nil below may be missing, and an
// engine that needs it refuses the request.
type Principal struct {
	// The network the token belongs to, whose rev/ objects and P1 queue apply (§7.8, §11.13).
	// Required.
	NetworkId connect.Id
	// ur_client_id. Required.
	ClientId connect.Id
	// ur_subject_client_id: the §8 subject the client acts as. nil: the client itself.
	SubjectClientId *connect.Id
	// ur_sidecar_id, which evs and gkm match to §5's binding. nil: not a sidecar's token.
	SidecarId *connect.Id
	// member_id.
	MemberId *connect.Id
	// aud. Authenticate has already matched it. Required.
	Audience string
	// The token's scopes, as issued: repo:<id>:deposit|r|rw|admin, recovery:<member_id> (§7.8).
	Scopes []string
	// proj_v: the log position n the scopes came from (§7.9).
	ProjVersion uint64
	// A token issued before a rev/ object's not_before is void (§7.8), so engines read this. A zero
	// time reads as issued before every not_before, so a token with no iat fails closed.
	IssuedAt time.Time
	// When the token stops authenticating. A zero time has passed, so nothing outlives it.
	ExpiresAt time.Time
}

// What every Authenticator runs on a Principal before it answers, and what ServiceHost.Authenticate
// runs again, so a fake and the host refuse alike. A failure wraps ErrAuthenticationRefused. A pointer
// claim may be nil, but a present one names a real id, as the required ones do, since each names a rev/
// key too.
func (self *Principal) Validate() error {
	if self == nil {
		return fmt.Errorf("%w: no principal", ErrAuthenticationRefused)
	}
	if self.NetworkId == (connect.Id{}) {
		return fmt.Errorf("%w: no network", ErrAuthenticationRefused)
	}
	if self.ClientId == (connect.Id{}) {
		return fmt.Errorf("%w: no client", ErrAuthenticationRefused)
	}
	if self.Audience == "" {
		return fmt.Errorf("%w: no audience", ErrAuthenticationRefused)
	}
	for _, claimId := range []*connect.Id{self.SubjectClientId, self.SidecarId, self.MemberId} {
		if claimId != nil && *claimId == (connect.Id{}) {
			return fmt.Errorf("%w: a zero id in a claim", ErrAuthenticationRefused)
		}
	}
	return nil
}

// Verifies tokens for one process, from the keys that process mounts (§19.4). Service tokens verify
// offline; what a token's subject has lost since it was issued is the engine's to check, against
// rev/ objects and the newest projection (§7.8, §11.8).
type Authenticator interface {
	// The Principal jwt names, for audience, the one this engine serves: §7.8's "evs", "gkm", "dns",
	// "certs" or "mail". Every service audience shares one key set (§7.8), so a token good for one
	// audience verifies under another's keys: the audience is required and an empty one refuses. A
	// token that Principal.Validate would refuse refuses here. Refusal is ErrAuthenticationRefused,
	// wrapped or not. Engines reach this through ServiceHost.Authenticate.
	//
	// sockets' callers hold Client-class tokens, which have no service audience, so what its engine
	// passes here is not settled, and until it is a host answers its calls as unavailable.
	Authenticate(ctx context.Context, audience string, jwt string) (*Principal, error)
}

// The one way an engine authenticates a token, so none acts on what Principal.Validate refuses
// whatever a host's Authenticator answers, and none reads a Principal for an audience it does not
// serve. A host that left Authenticator nil says nothing about the token, so that is an error other
// than ErrAuthenticationRefused, and the engine answers unavailable.
func (self *ServiceHost) Authenticate(ctx context.Context, audience string, jwt string) (*Principal, error) {
	if audience == "" {
		return nil, fmt.Errorf("%w: no audience", ErrAuthenticationRefused)
	}
	if self.Authenticator == nil {
		return nil, errors.New("this host has no authenticator")
	}
	principal, err := self.Authenticator.Authenticate(ctx, audience, jwt)
	if err != nil {
		return nil, err
	}
	if err := principal.Validate(); err != nil {
		return nil, err
	}
	if principal.Audience != audience {
		return nil, fmt.Errorf("%w: another audience", ErrAuthenticationRefused)
	}
	return principal, nil
}
