//go:build !sidecar_http

// §6.8's client on the connect legs: the resident's PushReset and PushHint frames from ControlId, which
// the dispatcher's source guard admits only over platform carriers (D-PROTO-8), fed to the machine in
// push_state.go. One PushClient serves one client generation's Subprotocol, keeping its versions in the
// network's store, so the next generation's starts from what this one applied.
//
// A frame that does not decode is a lost hint: the client resyncs. The resident's frames arrive on
// ControlId's one worker, in order, and a subscriber's callback runs there, so it must not block.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// Subscribe on a Subprotocol no PushClient serves.
	ErrSidecarPushUnattached = errors.New("push: no client attached")
)

// What NewPushClient takes.
type PushClientEnv struct {
	// The generation's dispatcher, whose ControlId frames carry the resident's push.
	Subprotocol *Subprotocol
	// Where applied versions are kept (§6.8): the network's store.
	Store SidecarStore
	// GET /sidecar/sync/versions for a resync.
	Api *SidecarApi
	// nil takes the defaults.
	Settings *PushClientSettings
	// nil is real time.
	Clock Clock
	Log   Logger
	// head_alarm for a durable topic a reset tried to lower. nil drops it.
	Event SidecarEventFunction
}

// The resident's push for one generation. NewPushClient makes one, running. Safe for concurrent use.
type PushClient struct {
	subprotocol *Subprotocol
	feed        *pushFeed
	removes     []func()
}

// A running client on env.Subprotocol: it takes the dispatcher's PUSH_RESET and PUSH_HINT, answers
// Subprotocol.Subscribe, and resyncs at once, at each Resync and each SyncRefetchInterval.
func NewPushClient(ctx context.Context, env *PushClientEnv) (*PushClient, error) {
	if env == nil || env.Subprotocol == nil || env.Store == nil || env.Api == nil {
		return nil, fmt.Errorf("%w: a push client needs its Subprotocol, Store and Api", errInvalidSettings)
	}
	return newPushClient(ctx, env, env.Api.SyncVersions)
}

// NewPushClient with the versions route's function.
func newPushClient(ctx context.Context, env *PushClientEnv, versions pushVersionsFunction) (*PushClient, error) {
	settings := env.Settings
	if settings == nil {
		settings = DefaultPushClientSettings()
	}
	feed, err := newPushFeed(ctx, settings, env.Store, env.Clock, env.Log, env.Event, versions)
	if err != nil {
		return nil, err
	}
	self := &PushClient{
		subprotocol: env.Subprotocol,
		feed:        feed,
	}
	for _, registration := range []struct {
		messageType protocol.MessageType
		function    subprotocolDispatchFunction
	}{
		{messageType: protocol.MessageType_PUSH_RESET, function: self.dispatchReset},
		{messageType: protocol.MessageType_PUSH_HINT, function: self.dispatchHint},
	} {
		remove, err := env.Subprotocol.setMessageTypeDispatch(registration.messageType, registration.function)
		if err != nil {
			self.Close()
			return nil, err
		}
		self.removes = append(self.removes, remove)
	}
	if !env.Subprotocol.pushClient.CompareAndSwap(nil, self) {
		self.Close()
		return nil, fmt.Errorf("%w: a second push client on one Subprotocol", errInvalidSettings)
	}
	return self, nil
}

// Takes the client off its dispatcher and stops its resync loop.
func (self *PushClient) Close() {
	for _, remove := range self.removes {
		remove()
	}
	self.removes = nil
	self.subprotocol.pushClient.CompareAndSwap(self, nil)
	self.feed.close()
}

// Whether no durable topic is held in alarm: §8's inbound state fails closed while false (I-16).
func (self *PushClient) Consistent() bool {
	return self.feed.consistent()
}

// See Subprotocol.Subscribe.
func (self *PushClient) Subscribe(topic string, callback PushNoticeFunction) (remove func(), err error) {
	return self.feed.subscribe(topic, callback)
}

// The topic's owner verified its state at version: applied, and its alarm ended.
func (self *PushClient) Reconcile(topic string, version uint64) {
	self.feed.reconcile(topic, version)
}

// Asks for a versions refetch now: what the generation calls at each reconnect.
func (self *PushClient) Resync() {
	self.feed.resync()
}

// The version applied for topic, 0 when none.
func (self *PushClient) Version(topic string) uint64 {
	return self.feed.version(topic)
}

// One PushReset part from the resident.
func (self *PushClient) dispatchReset(ctx context.Context, message *subprotocolMessage) {
	part := &protocol.PushReset{}
	if err := proto.Unmarshal(message.envelope.Body, part); err != nil {
		self.feed.resync()
		return
	}
	self.feed.applyResetPart(part)
}

// One PushHint from the resident.
func (self *PushClient) dispatchHint(ctx context.Context, message *subprotocolMessage) {
	hint := &protocol.PushHint{}
	if err := proto.Unmarshal(message.envelope.Body, hint); err != nil {
		self.feed.resync()
		return
	}
	self.feed.applyHint(hint)
}

// Calls callback with each notice for topic, an exact one of §6.8's registry or the family gkm: or
// evs:, through the PushClient serving this Subprotocol: a hint that raised it, or a resync notice that
// its state may have moved, either of which the subscriber answers by fetching over HTTPS. callback
// runs on the push's goroutine and must not block. ErrSidecarPushUnattached while no client serves it.
func (self *Subprotocol) Subscribe(topic string, callback PushNoticeFunction) (remove func(), err error) {
	client := self.pushClient.Load()
	if client == nil {
		return nil, ErrSidecarPushUnattached
	}
	return client.Subscribe(topic, callback)
}
