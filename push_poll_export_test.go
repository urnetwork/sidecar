//go:build !sidecar_http && !js

// The bridge push_poll_test.go's external tests reach the poll client through: its constructor on the
// routes' functions, which production builds from SidecarApi. Tests only.

package sidecar

import (
	"context"

	"github.com/urnetwork/sidecar/protocol"
)

// newPushPollClient, for the external tests, on poll and versions in place of SidecarApi's routes.
func NewPushPollClientOn(
	ctx context.Context,
	poll func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error),
	versions func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error),
	store SidecarStore,
	settings *PushClientSettings,
	clock Clock,
) (*PushPollClient, error) {
	return newPushPollClient(ctx, poll, versions, store, settings, clock, NewNoopLogger(), nil)
}
