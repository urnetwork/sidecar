// gkmUnreachable's reading of what GkmApi answers (QD-876): which errors are KF7's case, gkm unreachable, and which
// are gkm's refusal. On a fake gkm reached through a RoundTripper, so it runs on every leg.

package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

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
