//go:build !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// Answers what a test sets, as a host's adapter of §7.8's claims would, and counts what it was asked.
type scriptedAuthenticator struct {
	principal *Principal
	err       error
	callCount *int
}

func (self scriptedAuthenticator) Authenticate(ctx context.Context, audience string, jwt string) (*Principal, error) {
	if self.callCount != nil {
		*self.callCount += 1
	}
	return self.principal, self.err
}

// A token naming everything Validate asks for.
func namedPrincipal() *Principal {
	return &Principal{NetworkId: connect.NewId(), ClientId: connect.NewId(), Audience: "evs"}
}

func TestAuthenticateAnswersWhatATokenNames(t *testing.T) {
	principal := namedPrincipal()
	host := &ServiceHost{Authenticator: scriptedAuthenticator{principal: principal}}
	got, err := host.Authenticate(context.Background(), "evs", "synthetic-token")
	if err != nil {
		t.Fatal(err)
	}
	if got != principal {
		t.Errorf("got %+v", got)
	}
}

// What an engine's check comes to for one token (§7.8): it passes unless its subject has a rev/ object.
// The object here is real, so a pass names exactly the failure: the token's client was removed, and
// the key read for it, under the zero network, holds nothing.
func TestARemovedClientsTokenWithNoNetworkClaimDoesNotPass(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	networkId := connect.NewId()
	clientId := connect.NewId()
	revocationKey := func(networkId connect.Id, clientId connect.Id) string {
		return fmt.Sprintf("rev/%s/client/%s/_", networkId, clientId)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, revocationKey(networkId, clientId), []byte("a signed revocation"), nil); err != nil {
		t.Fatal(err)
	}
	check := func(principal *Principal) error {
		host := &ServiceHost{Authenticator: scriptedAuthenticator{principal: principal}}
		named, err := host.Authenticate(ctx, "evs", "synthetic-token")
		if err != nil {
			return err
		}
		if _, err := cluster.Head(ctx, revocationKey(named.NetworkId, named.ClientId)); !errors.Is(err, ErrBlobNotFound) {
			return fmt.Errorf("%w: revoked", ErrAuthenticationRefused)
		}
		return nil
	}

	// §7.8's claim list as it stands: a client, and no network
	if err := check(&Principal{ClientId: clientId, Audience: "evs"}); !errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("a removed client's token with no network: %v", err)
	}
	// with the network named, the rev/ object does its work, and a client not removed still passes
	if err := check(&Principal{NetworkId: networkId, ClientId: clientId, Audience: "evs"}); !errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("a removed client's token: %v", err)
	}
	if err := check(&Principal{NetworkId: networkId, ClientId: connect.NewId(), Audience: "evs"}); err != nil {
		t.Errorf("a live client's token: %v", err)
	}
}

func TestAuthenticateRefusesWhatDoesNotNameItsSubject(t *testing.T) {
	zeroId := connect.Id{}
	for _, c := range []struct {
		name   string
		adjust func(principal *Principal)
	}{
		{name: "no network", adjust: func(principal *Principal) { principal.NetworkId = connect.Id{} }},
		{name: "no client", adjust: func(principal *Principal) { principal.ClientId = connect.Id{} }},
		{name: "no audience", adjust: func(principal *Principal) { principal.Audience = "" }},
		{name: "a zero subject", adjust: func(principal *Principal) { principal.SubjectClientId = &zeroId }},
		{name: "a zero sidecar", adjust: func(principal *Principal) { principal.SidecarId = &zeroId }},
		{name: "a zero member", adjust: func(principal *Principal) { principal.MemberId = &zeroId }},
	} {
		principal := namedPrincipal()
		c.adjust(principal)
		if err := principal.Validate(); !errors.Is(err, ErrAuthenticationRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
		host := &ServiceHost{Authenticator: scriptedAuthenticator{principal: principal}}
		got, err := host.Authenticate(context.Background(), "evs", "synthetic-token")
		if !errors.Is(err, ErrAuthenticationRefused) || got != nil {
			t.Errorf("%s: %+v, %v", c.name, got, err)
		}
	}
}

// A claim may be missing, which is what the pointers are for.
func TestAPrincipalMayLackItsOptionalClaims(t *testing.T) {
	principal := namedPrincipal()
	if err := principal.Validate(); err != nil {
		t.Error(err)
	}
	memberId := connect.NewId()
	principal.MemberId = &memberId
	if err := principal.Validate(); err != nil {
		t.Error(err)
	}
}

// An Authenticator that answers nothing at all is refused, not dereferenced.
func TestAuthenticateRefusesANilPrincipal(t *testing.T) {
	host := &ServiceHost{Authenticator: scriptedAuthenticator{}}
	if _, err := host.Authenticate(context.Background(), "evs", "synthetic-token"); !errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("err %v", err)
	}
}

// Every audience shares one key set, so a token for gkm verifies under evs's keys (§7.8).
func TestAuthenticateRefusesAnotherAudience(t *testing.T) {
	principal := namedPrincipal()
	principal.Audience = "gkm"
	host := &ServiceHost{Authenticator: scriptedAuthenticator{principal: principal}}
	if _, err := host.Authenticate(context.Background(), "evs", "synthetic-token"); !errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("err %v", err)
	}
}

func TestAuthenticateRefusesAnEmptyAudienceWithoutAsking(t *testing.T) {
	callCount := 0
	host := &ServiceHost{Authenticator: scriptedAuthenticator{principal: namedPrincipal(), callCount: &callCount}}
	if _, err := host.Authenticate(context.Background(), "", "synthetic-token"); !errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("err %v", err)
	}
	if callCount != 0 {
		t.Errorf("the authenticator was asked %d times", callCount)
	}
}

// An engine answers 401 only to a refusal, so anything else stays apart from it: a caller retries
// rather than signs out.
func TestAuthenticateKeepsUnavailableApartFromRefused(t *testing.T) {
	unavailable := errors.New("the key set is not loaded")
	host := &ServiceHost{Authenticator: scriptedAuthenticator{err: unavailable}}
	_, err := host.Authenticate(context.Background(), "evs", "synthetic-token")
	if !errors.Is(err, unavailable) || errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("err %v", err)
	}

	_, err = (&ServiceHost{}).Authenticate(context.Background(), "evs", "synthetic-token")
	if err == nil || errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("no authenticator: %v", err)
	}
}

// A host whose check cannot answer yet names its wait (QD-040's record miss): the wait reaches the
// engine unchanged, and it is never a refusal.
func TestAuthenticateCarriesAnUnavailableWait(t *testing.T) {
	cause := errors.New("the revocation record cannot answer")
	host := &ServiceHost{Authenticator: scriptedAuthenticator{err: &AuthenticationUnavailableError{RetryAfter: 5 * time.Second, Err: cause}}}
	_, err := host.Authenticate(context.Background(), "sockets", "synthetic-token")
	unavailable := &AuthenticationUnavailableError{}
	if !errors.As(err, &unavailable) || unavailable.RetryAfter != 5*time.Second || !errors.Is(err, cause) {
		t.Fatalf("err %v", err)
	}
	if errors.Is(err, ErrAuthenticationRefused) {
		t.Fatalf("an unavailable answer reads as a refusal: %v", err)
	}
}

func TestAuthenticateErrorsNeverRepeatTheToken(t *testing.T) {
	principal := namedPrincipal()
	principal.NetworkId = connect.Id{}
	host := &ServiceHost{Authenticator: scriptedAuthenticator{principal: principal}}
	if _, err := host.Authenticate(context.Background(), "evs", "synthetic-token"); strings.Contains(err.Error(), "synthetic-token") {
		t.Errorf("error %q repeats the token", err)
	}
}
