//go:build !sidecar_http

// ServiceHost.Authenticator: how an engine learns who a bearer token names, without importing
// server/session.

package sidecar

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/connect"
)

// A token that will not authenticate: bad signature, wrong audience, expired or revoked at the
// issuer. An engine answers 401. Any other Authenticate error says nothing about the token, and the
// engine answers unavailable, so a caller retries instead of signing out.
var ErrAuthenticationRefused = errors.New("authentication refused")

// Who a verified token names. Service tokens carry §7.8's claims; a claim a token lacks stays nil or
// empty, and an engine that needs it refuses the request.
type Principal struct {
	// The network the token belongs to, whose rev/ objects and P1 queue apply (§7.8, §11.13).
	NetworkId connect.Id
	// ur_client_id.
	ClientId connect.Id
	// ur_subject_client_id: the §8 subject the client acts as. nil: the client itself.
	SubjectClientId *connect.Id
	// ur_sidecar_id, which evs and gkm match to §5's binding. nil: not a sidecar's token.
	SidecarId *connect.Id
	// member_id.
	MemberId *connect.Id
	// aud. Authenticate has already matched it.
	Audience string
	// The token's scopes, as issued: repo:<id>:deposit|r|rw|admin, recovery:<member_id> (§7.8).
	Scopes []string
	// proj_v: the log position n the scopes came from (§7.9).
	ProjVersion uint64
	// A token issued before a rev/ object's not_before is void (§7.8), so engines read this.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Verifies tokens for one process, from the keys that process mounts (§19.4). Service tokens verify
// offline; what a token's subject has lost since it was issued is the engine's to check, against
// rev/ objects and the newest projection (§7.8, §11.8).
type Authenticator interface {
	// The Principal jwt names, for audience, the one this engine serves ("evs", "gkm", "dns",
	// "certs"). Every service audience shares one key set (§7.8), so a token good for one audience
	// verifies under another's keys: the audience is required and an empty one refuses. Refusal is
	// ErrAuthenticationRefused, wrapped or not.
	Authenticate(ctx context.Context, audience string, jwt string) (*Principal, error)
}
