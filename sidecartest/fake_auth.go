// ServiceHost.Authenticator in memory. Tokens are opaque strings this fake issued, so a test mints one
// for the Principal it wants, and only an Issue here authenticates: a guess, a token for another
// audience, a revoked one, an expired one and one Principal.Validate refuses are refused, each as
// ErrAuthenticationRefused. A dropped call is the other kind of error, the one an engine answers as
// unavailable (host_auth.go).

package sidecartest

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
)

type FakeAuthenticator struct {
	clock  Clock
	faults *FaultQueue

	stateLock  sync.Mutex
	issueCount int
	jwtTokens  map[string]*fakeToken
}

type fakeToken struct {
	principal *sidecar.Principal
	revoked   bool
}

func NewFakeAuthenticator(clock Clock, faults *FaultQueue) *FakeAuthenticator {
	return &FakeAuthenticator{clock: clock, faults: faults, jwtTokens: map[string]*fakeToken{}}
}

// A token naming principal, good for principal.Audience until principal.ExpiresAt. A zero ExpiresAt
// has passed, as host_auth.go says, and a Principal Validate refuses stays refused: a test can mint
// either to see it fail. The string is opaque and synthetic, and no real issuer could have made it.
func (self *FakeAuthenticator) Issue(principal *sidecar.Principal) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.issueCount += 1
	jwt := fmt.Sprintf("fake-service-token-%d", self.issueCount)
	principalCopy := *principal
	principalCopy.Scopes = slices.Clone(principal.Scopes)
	self.jwtTokens[jwt] = &fakeToken{principal: &principalCopy}
	return jwt
}

// Revoked at the issuer, as a token's subject being gated at the engine is not: an engine's rev/ reads
// are the engine's to test.
func (self *FakeAuthenticator) Revoke(jwt string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if token, ok := self.jwtTokens[jwt]; ok {
		token.revoked = true
	}
}

func (self *FakeAuthenticator) Authenticate(ctx context.Context, audience string, jwt string) (*sidecar.Principal, error) {
	var principal *sidecar.Principal
	err := hostCall(ctx, self.faults, "authenticator.Authenticate", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		token, ok := self.jwtTokens[jwt]
		switch {
		case audience == "":
			return fmt.Errorf("%w: no audience", sidecar.ErrAuthenticationRefused)
		case !ok:
			return fmt.Errorf("%w: no such token", sidecar.ErrAuthenticationRefused)
		case token.revoked:
			return fmt.Errorf("%w: revoked", sidecar.ErrAuthenticationRefused)
		case token.principal.Audience != audience:
			return fmt.Errorf("%w: for another audience", sidecar.ErrAuthenticationRefused)
		case !self.clock.Now().Before(token.principal.ExpiresAt):
			return fmt.Errorf("%w: expired", sidecar.ErrAuthenticationRefused)
		}
		if err := token.principal.Validate(); err != nil {
			return err
		}
		principalCopy := *token.principal
		principalCopy.Scopes = slices.Clone(token.principal.Scopes)
		principal = &principalCopy
		return nil
	})
	if err != nil {
		return nil, err
	}
	return principal, nil
}
