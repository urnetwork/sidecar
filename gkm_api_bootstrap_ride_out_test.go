// GkmApi asking once for a role the client's state does not give, on the fake gkm and the fake token exchange of
// gkm_api_grant_lag_test.go, so this runs on every leg, the sidecar_http page Worker's included.
// gkm_bootstrap_ride_out_test.go holds the same over the first device's bootstrap flows.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A call on a repo at a role the client's state does not give presents that one scope and goes once whatever the token
// keeper answers: api's 503 and 500, its 429 naming a wait, a keychain still locked and no api yet, each of which a call
// the state gives asks again ExchangeRetryCount times, end it after one ask and no wait, carrying errGkmNoServiceToken
// and the keeper's error, nothing sent to gkm. Two such calls: a read of a repo no batch holds, as a network's first
// device's join of the config group at the genesis, which gives it nothing, while api's gate holds no state of the
// network; and a creation needing admin of a repo the state gives rw. The code before (sidecar cf4431a9) asked each
// failure again ExchangeRetryCount times, ReadRetryWait apart, or after the 429's wait.
func TestGkmApiAsksOnceForARoleTheClientsStateDoesNotGive(t *testing.T) {
	refusals := []error{
		&SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable"},
		&SidecarApiError{Route: "POST /oauth/token", Status: http.StatusInternalServerError, Code: "server_error"},
		&SidecarApiError{Route: "POST /oauth/token", Status: http.StatusTooManyRequests, RetryAfterMs: 2000},
		ErrSidecarServiceTokenLocked,
		ErrSidecarServiceTokenNoApi,
	}
	for _, refusal := range refusals {
		world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, GkmScopeRoleWrite, GkmScopeRoleWrite, nil)
		world.guard.createRepoId = world.repoId
		unheldId := NewId()
		cases := []struct {
			name  string
			scope string
			call  func(ctx context.Context) error
		}{
			{
				name:  "a read of a repo no batch holds",
				scope: GkmRepoScope{RepoId: unheldId, Role: GkmScopeRoleRead}.scope(),
				call: func(ctx context.Context) error {
					_, err := world.api.Forms(ctx, unheldId)
					return err
				},
			},
			{
				name:  "a creation needing admin of a repo the state gives rw",
				scope: world.scope(GkmScopeRoleAdmin),
				call: func(ctx context.Context) error {
					return world.api.CreateGroup(ctx, world.repoId, nil)
				},
			},
		}
		for _, c := range cases {
			before := world.exchange.count()
			world.exchange.refuse(refusal, 10)
			err, waits := world.run(c.call)
			if !errors.Is(err, refusal) || !errors.Is(err, errGkmNoServiceToken) {
				t.Errorf("%v: %s ended with %v", refusal, c.name, err)
			}
			if len(waits) != 0 || world.exchange.count()-before != 1 || len(world.exchange.asked(c.scope)) != 1 {
				t.Errorf("%v: %s asked %d times, waiting %v, want once and no wait", refusal, c.name, world.exchange.count()-before, waits)
			}
		}
		if count := len(world.gkm.taken()); count != 0 {
			t.Errorf("%v: gkm took %d requests with no token", refusal, count)
		}
	}
}

// The rule's other side: a call whose scopes the client's state gives still asks a failure that may change again, the
// repo's read under its batch as the claim does (TestGkmApiAsksAgainAfterATokenFailureThatMayChange), and so does a
// route on no repo, which presents the state's first batch, a ReaderKey's upload: each asks api's 503 again after
// ReadRetryWait and lands on the second ask.
func TestGkmApiStillAsksAgainForWhatTheClientsStateGives(t *testing.T) {
	unloaded := &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable"}
	world := newGkmGrantLagApiWorld(t, GkmScopeRoleRead, GkmScopeRoleRead, GkmScopeRoleRead, nil)
	cases := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{
			name: "the repo's read under its batch",
			call: func(ctx context.Context) error {
				_, err := world.api.Forms(ctx, world.repoId)
				return err
			},
		},
		{
			name: "a ReaderKey's upload, on no repo",
			call: func(ctx context.Context) error {
				return world.api.UploadReaderKey(ctx, &bridge.Signed{Body: []byte("a ReaderKey")})
			},
		},
	}
	for _, c := range cases {
		before, requestsBefore := world.exchange.count(), len(world.gkm.taken())
		world.exchange.refuse(unloaded, 1)
		err, waits := world.run(c.call)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !slices.Equal(waits, []time.Duration{time.Second}) || world.exchange.count()-before != 2 {
			t.Errorf("%s: asked %d times, waiting %v, want twice and one ReadRetryWait", c.name, world.exchange.count()-before, waits)
		}
		if count := len(world.gkm.taken()) - requestsBefore; count != 1 {
			t.Errorf("%s: gkm took %d requests", c.name, count)
		}
	}
}
