//go:build !sidecar_http && !ios_extension

// ServiceHost.Authenticator: how an engine learns who a bearer token names, without importing
// server/session. The error, Principal and Authenticator are operator-core's (owner decision 251).
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

	operator "github.com/urnetwork/operator-core"
)

// A token that will not authenticate: operator-core's, so errors.Is reads one sentinel on both sides.
// An engine answers 401; any other Authenticate error says nothing about the token.
var ErrAuthenticationRefused = operator.ErrAuthenticationRefused

// An Authenticate error that says nothing about the token and names how long its caller should wait.
type AuthenticationUnavailableError = operator.AuthenticationUnavailableError

// Who a verified token names, with the Validate every Authenticator runs.
type Principal = operator.Principal

// Verifies tokens for one process.
type Authenticator = operator.Authenticator

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
