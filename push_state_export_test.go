//go:build !js

// The bridge the external tests that take a resident's frames themselves reach the client's push feed
// (push_state.go) through: the feed a PushClient hands each PushHint to, which tells its subscribers what
// a Subprotocol's are told, and counts the versions refetches its inputs ask for, a seq gap's among them.
// Its versions refetch never answers, so only the hints a test hands it tell a subscriber anything. Tests
// only.

package sidecar

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A push feed on the default settings over an empty store in memory, holding nothing, as a client's first
// does before its first refetch answers.
type PushTestFeed struct {
	feed *pushFeed
}

// Closed at t's cleanup.
func NewPushTestFeed(t testing.TB) *PushTestFeed {
	t.Helper()
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), newTestPushStore(), newTestEnvelopeClock(), NewNoopLogger(), nil, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(feed.close)
	return &PushTestFeed{feed: feed}
}

// Subprotocol.Subscribe's shape, on the feed.
func (self *PushTestFeed) Subscribe(topic string, callback PushNoticeFunction) (remove func(), err error) {
	return self.feed.subscribe(topic, callback)
}

// A resident's PushHint, as PushClient hands one to the feed: the subscribers it tells are told on this
// goroutine before it returns.
func (self *PushTestFeed) ApplyHint(hint *protocol.PushHint) {
	self.feed.applyHint(hint)
}

// The versions refetches the inputs have asked for, a seq gap's among them.
func (self *PushTestFeed) RefetchAskCount() uint64 {
	asks, _ := self.feed.asks.Get()
	return asks.askCount
}
