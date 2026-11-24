// gkmUnreachable's reading of what GkmApi answers (QD-876): which errors are KF7's case, gkm unreachable, and which
// are gkm's refusal, a token refused for good among them (gkmTokenRefused). On a fake gkm reached through a
// RoundTripper, so it runs on every leg.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A write's error from a GkmApi whose token keeper answers refusal in place of every token, asking it again for nothing
// that may change and riding no invalid_scope out, so the error is what the keeper's answer leaves; nothing reaches
// gkm.
func gkmTestTokenError(t *testing.T, refusal error) error {
	t.Helper()
	settings := DefaultGkmSettings()
	settings.ExchangeRetryCount = 0
	settings.ExchangeScopeWaitTimeout = 0
	transport := &gkmTestTransport{}
	api, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:    "https://gkm.example",
		Transport: transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return "", refusal
		},
		Settings: settings,
		Clock:    newGkmTestClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	scopes := gkmTestScopes(1, GkmScopeRoleWrite)
	api.SetRepoScopes(scopes)
	err = api.CommitEpoch(context.Background(), scopes[0].RepoId, NewId(), 3, &protocol.GkmEpochRequest{})
	if err == nil {
		t.Fatal("a write with no token was answered a success")
	}
	if requests := transport.taken(); len(requests) != 0 {
		t.Fatalf("a write with no token reached gkm %d times", len(requests))
	}
	return err
}

// A token refused for good is gkm's refusal and no unreachability, however a caller wrapped it: each refusal
// sidecarServiceTokenRefusalOf calls final, the exchange's invalid_grant, invalid_scope and other 4xx answers,
// SidecarApi's refusal to send or read, and no enrolled client, and gkm's own 401. A token the keeper cannot have for
// now is KF7's unreachability, as gkm's transport failing is: no answer from api, its 429 or 5xx, a keychain still
// locked, no api. gkm's other answers are no token refusal, whether they refuse or not. Nothing is unreachable past
// the caller's ctx.
func TestGkmUnreachableReadsATokenRefusedForGoodAsARefusal(t *testing.T) {
	ctx := context.Background()
	ended, cancel := context.WithCancel(ctx)
	cancel()
	refusedForGood := map[string]error{
		"invalid_grant":  gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"}),
		"invalid_scope":  gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: sidecarExchangeCodeInvalidScope}),
		"invalid_target": gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_target"}),
		"api's 401":      gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusUnauthorized, Code: "invalid_dpop_proof"}),
		"api's 403":      gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusForbidden}),
		"no enrolled":    gkmTestTokenError(t, ErrSidecarServiceTokenNoClient),
		"api's args":     gkmTestTokenError(t, fmt.Errorf("%w: a scope out of form", ErrSidecarApiArgs)),
		"api's reply":    gkmTestTokenError(t, fmt.Errorf("%w: a 2xx that was not the exchange's", ErrSidecarApiReply)),
		"gkm's own 401":  gkmTestWriteError(t, func(request *gkmTestRequest) (int, http.Header, []byte) { return http.StatusUnauthorized, nil, nil }),
	}
	for name, err := range refusedForGood {
		for _, read := range []error{err, fmt.Errorf("a flow's step: %w", err)} {
			if !gkmTokenRefused(read) {
				t.Errorf("%s is not a token refused for good: %v", name, read)
			}
			if gkmUnreachable(ctx, read) {
				t.Errorf("%s reads as gkm unreachable: %v", name, read)
			}
			if gkmUnreachable(ended, read) {
				t.Errorf("%s reads as gkm unreachable past the caller's ctx", name)
			}
		}
	}
	mayChange := map[string]error{
		"no answer from api": gkmTestTokenError(t, errors.New("synthetic: api gave no answer")),
		"api's 429":          gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusTooManyRequests}),
		"api's 500":          gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusInternalServerError}),
		"api's 503":          gkmTestTokenError(t, &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable}),
		"a locked keychain":  gkmTestTokenError(t, ErrSidecarServiceTokenLocked),
		"no api yet":         gkmTestTokenError(t, ErrSidecarServiceTokenNoApi),
	}
	for name, err := range mayChange {
		for _, read := range []error{err, fmt.Errorf("a flow's step: %w", err)} {
			if gkmTokenRefused(read) {
				t.Errorf("%s reads as a token refused for good: %v", name, read)
			}
			if !gkmUnreachable(ctx, read) {
				t.Errorf("%s is not gkm unreachable: %v", name, read)
			}
			if gkmUnreachable(ended, read) {
				t.Errorf("%s reads as gkm unreachable past the caller's ctx", name)
			}
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout} {
		err := gkmTestWriteError(t, func(request *gkmTestRequest) (int, http.Header, []byte) {
			return status, nil, nil
		})
		if gkmTokenRefused(err) {
			t.Errorf("gkm's %d reads as a token refused for good: %v", status, err)
		}
	}
}

// A write's error from a gkm, or an lb before it, that answers every request with serve.
func gkmTestWriteError(t *testing.T, serve func(request *gkmTestRequest) (int, http.Header, []byte)) error {
	t.Helper()
	transport := &gkmTestTransport{serve: serve}
	api := newGkmTestApi(t, transport, newGkmTestTokens(), newGkmTestClock())
	scopes := gkmTestScopes(1, GkmScopeRoleWrite)
	api.SetRepoScopes(scopes)
	err := api.CommitEpoch(context.Background(), scopes[0].RepoId, NewId(), 3, &protocol.GkmEpochRequest{})
	if err == nil {
		t.Fatal("the write was answered a success")
	}
	return err
}

// KF7's test of an error: the lb's 502 and 504 leave gkm unreachable, as a transport error and gkm's own 429 and 503
// do, however a caller wrapped them; gkm's refusals do not, and neither does anything once the caller's ctx ended.
func TestGkmUnreachableTakesTheLbs502And504AsNoAnswer(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusBadGateway, http.StatusGatewayTimeout} {
		err := gkmTestWriteError(t, func(request *gkmTestRequest) (int, http.Header, []byte) {
			return gkmTestLbAnswer(status)
		})
		if !gkmUnreachable(ctx, err) {
			t.Errorf("the lb's %d is not unreachable: %v", status, err)
		}
		if !gkmUnreachable(ctx, fmt.Errorf("a flow's step: %w", err)) {
			t.Errorf("the lb's %d, wrapped, is not unreachable", status)
		}
		ended, cancel := context.WithCancel(ctx)
		cancel()
		if gkmUnreachable(ended, err) {
			t.Errorf("the lb's %d is unreachable past the caller's ctx", status)
		}
	}
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		err := gkmTestWriteError(t, func(request *gkmTestRequest) (int, http.Header, []byte) {
			return status, http.Header{"Retry-After": {"1"}}, nil
		})
		if !gkmUnreachable(ctx, err) {
			t.Errorf("gkm's %d is not unreachable: %v", status, err)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusPreconditionFailed, http.StatusNotImplemented} {
		err := gkmTestWriteError(t, func(request *gkmTestRequest) (int, http.Header, []byte) {
			return status, nil, []byte("what gkm holds there")
		})
		if gkmUnreachable(ctx, err) {
			t.Errorf("gkm's %d reads as unreachable: %v", status, err)
		}
	}
}
