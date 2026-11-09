// §6.8's long-poll client and the sync routes on SidecarApi, on every leg: what a host with no connect
// client runs in place of its resident's push, an HTTP-only sandbox or the page Worker (§18.10), which
// is why this file names no connect type. It loops GET /sidecar/sync/poll?cursor= and feeds each 200
// PollResponse to the same machine the resident's frames feed (push_state.go).
//
// The cursor is opaque and the server's: the client sends back the last one it was given, which an
// empty hold leaves unchanged. Anything but a 200 is waited out, from RetryMinInterval doubling to
// RetryMaxInterval or the server's Retry-After when it asks more, since this file cannot import
// connect's Reconnect; a 401 ends the poll, since it ends the client generation it polled for.

package sidecar

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A sync route's 200 that does not decode.
	ErrSidecarSyncReply = errors.New("sidecar sync: reply malformed")
)

// A cursor as the sync routes take it in the query: base64url with no padding.
func syncCursorQuery(cursor []byte) string {
	if len(cursor) == 0 {
		return ""
	}
	return "?cursor=" + base64.RawURLEncoding.EncodeToString(cursor)
}

// A sync route's binary body, decoded.
func (self *SidecarApi) syncPollResponse(ctx context.Context, route string, operation string, requestUrl string) (*protocol.PollResponse, error) {
	body, err := self.send(ctx, &sidecarApiRequest{
		route:     route,
		operation: operation,
		method:    "GET",
		url:       requestUrl,
		bearer:    true,
	})
	if err != nil {
		return nil, err
	}
	response := &protocol.PollResponse{}
	if err := proto.Unmarshal(body, response); err != nil {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarSyncReply)
	}
	return response, nil
}

// GET /sidecar/sync/poll?cursor=: one long-poll, held up to 25 s by api (§6.8).
func (self *SidecarApi) SyncPoll(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	return self.syncPollResponse(ctx, "GET /sidecar/sync/poll", "sync_poll", self.settings.ApiUrl+"/sidecar/sync/poll"+syncCursorQuery(cursor))
}

// GET /sidecar/sync/versions?cursor=: one page of the client's versions, reset set and no hints.
func (self *SidecarApi) SyncVersions(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	return self.syncPollResponse(ctx, "GET /sidecar/sync/versions", "sync_versions", self.settings.ApiUrl+"/sidecar/sync/versions"+syncCursorQuery(cursor))
}

// GET /sidecar/sync/core's answer (plan-CORE-core-hint-body #2): candidates the client checks against
// its own signed state, never authority (§5.6).
type SidecarSyncCore struct {
	// core's version, api's clock in µs or the hinted value.
	Version uint64
	// The floor api asserts, unsigned: applied live as no more than this release's SecureVersion,
	// never kept (QD-032). 0 for none.
	MinSecureVersion uint32
	// The services sidecar.yml enables for this network.
	Gates []string
	// Whether api holds this sidecar revoked: a candidate, checked against the config.
	Revoked bool
}

// What core's JSON carries: the version as a decimal string, since it passes what a JSON number holds.
type sidecarSyncCoreReply struct {
	Version          string   `json:"version"`
	MinSecureVersion uint32   `json:"min_secure_version"`
	Gates            []string `json:"gates"`
	Revoked          bool     `json:"revoked"`
}

// GET /sidecar/sync/core.
func (self *SidecarApi) SyncCore(ctx context.Context) (*SidecarSyncCore, error) {
	route := "GET /sidecar/sync/core"
	reply := &sidecarSyncCoreReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "sync_core",
		method:    "GET",
		url:       self.settings.ApiUrl + "/sidecar/sync/core",
		bearer:    true,
	}, nil, reply)
	if err != nil {
		return nil, err
	}
	version, err := strconv.ParseUint(reply.Version, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != reply.Version {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarSyncReply)
	}
	return &SidecarSyncCore{
		Version:          version,
		MinSecureVersion: reply.MinSecureVersion,
		Gates:            reply.Gates,
		Revoked:          reply.Revoked,
	}, nil
}

// GET /sidecar/sync/poll, one hold: SidecarApi.SyncPoll, or a test's.
type pushPollFunction func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error)

// The long-poll client. NewPushPollClient makes one, running. Safe for concurrent use.
type PushPollClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	feed   *pushFeed
	poll   pushPollFunction
	clock  Clock
	log    Logger
	// closed when the poll loop has returned: at Close, or at a 401
	done chan struct{}

	stateLock sync.Mutex
	// the 401 that ended the loop, nil while it runs
	ended error
}

// A poll client over api's sync routes, keeping its versions in store, its notices for its
// subscribers and its alarms for event. Runs until Close or a 401.
func NewPushPollClient(ctx context.Context, api *SidecarApi, store SidecarStore, settings *PushClientSettings, clock Clock, log Logger, event SidecarEventFunction) (*PushPollClient, error) {
	if api == nil || store == nil {
		return nil, fmt.Errorf("%w: a poll client needs its api and store", errInvalidSettings)
	}
	return newPushPollClient(ctx, api.SyncPoll, api.SyncVersions, store, settings, clock, log, event)
}

// NewPushPollClient on the routes' functions.
func newPushPollClient(ctx context.Context, poll pushPollFunction, versions pushVersionsFunction, store SidecarStore, settings *PushClientSettings, clock Clock, log Logger, event SidecarEventFunction) (*PushPollClient, error) {
	if settings == nil {
		settings = DefaultPushClientSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	feed, err := newPushFeed(cancelCtx, settings, store, clock, log, event, versions)
	if err != nil {
		cancel()
		return nil, err
	}
	self := &PushPollClient{
		ctx:    cancelCtx,
		cancel: cancel,
		feed:   feed,
		poll:   poll,
		clock:  clockOrReal(clock),
		log:    loggerOrDefault(log),
		done:   make(chan struct{}),
	}
	go self.run()
	return self, nil
}

// Stops polling and resyncing, and waits for both.
func (self *PushPollClient) Close() {
	self.cancel()
	<-self.done
	self.feed.close()
}

// Closed once the poll has ended, at Close or at a 401; Ended then says which.
func (self *PushPollClient) Done() <-chan struct{} {
	return self.done
}

// The 401 that ended the poll, nil while it runs or after Close.
func (self *PushPollClient) Ended() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended
}

// See Subprotocol.Subscribe.
func (self *PushPollClient) Subscribe(topic string, callback PushNoticeFunction) (remove func(), err error) {
	return self.feed.subscribe(topic, callback)
}

// Whether no durable topic is held in alarm (I-16).
func (self *PushPollClient) Consistent() bool {
	return self.feed.consistent()
}

// The topic's owner verified its state at version: applied, and its alarm ended.
func (self *PushPollClient) Reconcile(topic string, version uint64) {
	self.feed.reconcile(topic, version)
}

// Asks for a versions refetch now, as at a reconnect.
func (self *PushPollClient) Resync() {
	self.feed.resync()
}

// The poll loop of the file header.
func (self *PushPollClient) run() {
	defer close(self.done)
	cursor := []byte(nil)
	retryInterval := time.Duration(0)
	for {
		response, err := self.poll(self.ctx, cursor)
		if err != nil {
			if self.ctx.Err() != nil {
				return
			}
			var apiError *SidecarApiError
			if errors.As(err, &apiError) && apiError.Status == 401 {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.ended = err
				}()
				self.feed.cancel()
				return
			}
			if retryInterval == 0 {
				retryInterval = self.feed.settings.RetryMinInterval
			} else {
				retryInterval = min(2*retryInterval, self.feed.settings.RetryMaxInterval)
			}
			wait := retryInterval
			if apiError != nil {
				wait = max(wait, time.Duration(apiError.RetryAfterMs)*time.Millisecond)
			}
			if self.log.V(1).Enabled() {
				self.log.Infof("[push]poll = %s\n", err)
			}
			select {
			case <-self.ctx.Done():
				return
			case <-self.clock.After(wait):
			}
			continue
		}
		retryInterval = 0
		self.feed.applyPoll(response)
		if 0 < len(response.Cursor) {
			cursor = response.Cursor
		}
	}
}
