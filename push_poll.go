// §6.8's long-poll client and the sync routes on SidecarApi, on every leg: what a host with no connect
// client runs in place of its resident's push, an HTTP-only sandbox or the page Worker (§18.10), which
// is why this file names no connect type. It loops GET /sidecar/sync/poll?cursor= and feeds each 200
// PollResponse to the same machine the resident's frames feed (push_state.go).
//
// The cursor is opaque and the server's: the client sends back the last one it was given, which an
// empty hold leaves unchanged. Anything but a 200 is waited out, from RetryMinInterval doubling to
// RetryMaxInterval or the server's Retry-After when it asks more, since this file cannot import
// connect's Reconnect; a 401 ends the poll, since it ends the client generation it polled for. The first
// 200 after a failure is the long-poll's reconnect: once its reply is applied the loop calls Resync,
// which ends a failed versions refetch's pending retry wait at once, as a connect leg's reconnect does
// (§6.8). The loop's own backoff paces these reconnects: at most one for each backoff a 200 ends.

package sidecar

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
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
	// Local to the authenticated request. Neither value is supplied in the core reply or persisted.
	bearerEpoch   uint64
	bearerExpires time.Time
}

// What core's JSON carries: the version as a decimal string, since it passes what a JSON number holds.
type sidecarSyncCoreReply struct {
	Version          string   `json:"version"`
	MinSecureVersion *uint32  `json:"min_secure_version"`
	Gates            []string `json:"gates"`
	Revoked          *bool    `json:"revoked"`
}

// GET /sidecar/sync/core.
func (self *SidecarApi) SyncCore(ctx context.Context) (*SidecarSyncCore, error) {
	return self.syncCore(ctx, nil)
}

// Sends the same bearer whose client and network match this generation, including when a token changes mid-request.
func (self *SidecarApi) syncCore(ctx context.Context, identity *SidecarIdentity) (*SidecarSyncCore, error) {
	route := "GET /sidecar/sync/core"
	reply := &sidecarSyncCoreReply{}
	token, epoch := self.currentBearer()
	if token == "" {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiNoToken)
	}
	request := &sidecarApiRequest{
		route:          route,
		operation:      "sync_core",
		method:         "GET",
		url:            self.settings.ApiUrl + "/sidecar/sync/core",
		bearerOverride: token,
	}
	if identity != nil {
		networkId, clientId, ok := sidecarJwtClient(token)
		if !ok || networkId != identity.NetworkId || clientId != identity.ClientId {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiNoToken)
		}
	}
	err := self.sendJson(ctx, request, nil, reply)
	if err != nil {
		return nil, err
	}
	version, err := strconv.ParseUint(reply.Version, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != reply.Version || reply.Gates == nil ||
		reply.MinSecureVersion == nil || reply.Revoked == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarSyncReply)
	}
	return &SidecarSyncCore{
		Version:          version,
		MinSecureVersion: *reply.MinSecureVersion,
		Gates:            reply.Gates,
		Revoked:          *reply.Revoked,
		bearerEpoch:      epoch,
		bearerExpires:    sidecarJwtExpiration(token),
	}, nil
}

// The core topic can fall on a reset. A local revision orders requests even across repeated remote versions.
type sidecarCoreRequest struct {
	online   bool
	revision uint64
	version  uint64
}

// A core answer lives only in the generation that authenticated it, through the next notice or hourly resync.
type sidecarCoreAnswer struct {
	revision uint64
	fetched  time.Time
	core     *SidecarSyncCore
}

type sidecarCoreSync struct {
	requests *MonitorValue[sidecarCoreRequest]
	answer   atomic.Pointer[sidecarCoreAnswer]
	// Created under Sidecar.stateLock, before the generation can be removed and joined.
	done chan struct{}
}

// A notice invalidates the previous gates immediately. Its body can separately suggest checking signed revocation.
func (self *sidecarGeneration) receiveCoreNotice(notice PushNotice) {
	self.core.requests.Update(func(request sidecarCoreRequest) sidecarCoreRequest {
		request.revision++
		request.version = notice.Version
		return request
	})
	self.sidecar.receiveCoreHint(self.generation, notice.Hint)
}

// A credential change asks again without resetting the core version. A clock fall comes from the push feed.
func (self *sidecarGeneration) refreshCore() {
	self.core.requests.Update(func(request sidecarCoreRequest) sidecarCoreRequest {
		request.revision++
		return request
	})
}

// A single reader serves all member clients in the generation. Generation removal excludes further starts.
func (self *sidecarGeneration) startCoreSyncWithLock() {
	if self.core.done == nil {
		self.core.done = make(chan struct{})
		go self.runCoreSync()
	}
}

// Reconnects, resets and hourly versions pages request the latest gates. A failed fetch leaves them unknown and
// retries on the push client's backoff. A late answer cannot undo an intervening notice or disconnect.
func (self *sidecarGeneration) runCoreSync() {
	defer close(self.core.done)
	settings := DefaultPushClientSettings()
	clock := self.sidecar.clock
	interval := self.sidecar.settings.ProtocolSettings.SyncRefetchInterval
	var backoff time.Duration
	for self.ctx.Err() == nil {
		request, changed := self.core.requests.Get()
		var retry <-chan time.Time
		if request.online {
			start := clock.Now()
			ctx, cancel := context.WithCancel(self.ctx)
			stop := clock.AfterFunc(self.sidecar.settings.ProtocolSettings.DefaultCallTimeout, cancel)
			core, err := self.sidecar.sidecarApi.syncCore(ctx, self.identity)
			stop()
			valid := err == nil && ctx.Err() == nil && core.Version >= request.version
			cancel()
			if valid {
				self.core.answer.Store(&sidecarCoreAnswer{revision: request.revision, fetched: start, core: core})
				backoff = 0
				testHookBarrier("sidecar.core_sync.accepted", self.networkId.String())
				retry = clock.After(max(0, interval-clock.Now().Sub(start)))
			} else {
				self.core.answer.Store(nil)
				if backoff == 0 {
					backoff = settings.RetryMinInterval
				} else {
					backoff = min(2*backoff, settings.RetryMaxInterval)
				}
				retry = clock.After(backoff)
			}
		}
		select {
		case <-self.ctx.Done():
			return
		case <-changed:
		case <-retry:
		}
	}
}

// A superseded answer stays inaccessible even while its replacement is still in flight.
func (self *sidecarGeneration) currentCore() *SidecarSyncCore {
	answer := self.core.answer.Load()
	request := self.core.requests.Value()
	if answer == nil || self.ctx.Err() != nil || !request.online || answer.revision != request.revision {
		return nil
	}
	age := self.sidecar.clock.Now().Sub(answer.fetched)
	if age < 0 || age >= self.sidecar.settings.ProtocolSettings.SyncRefetchInterval {
		return nil
	}
	api := self.sidecar.sidecarApi
	_, epoch := api.currentBearer()
	if epoch != answer.core.bearerEpoch || (!answer.core.bearerExpires.IsZero() && !api.apiNow().Before(answer.core.bearerExpires)) {
		return nil
	}
	return answer.core
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

// Asks for a versions refetch now, as a reconnect: it also ends a failed refetch's pending retry wait at
// once (§6.8). The poll loop calls it at its first successful poll after a failure.
func (self *PushPollClient) Resync() {
	self.feed.reconnect()
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
		// a backoff stands only after a failure, so this is the first poll answered since one
		reconnected := retryInterval != 0
		retryInterval = 0
		self.feed.applyPoll(response)
		if 0 < len(response.Cursor) {
			cursor = response.Cursor
		}
		if reconnected {
			// after the reply's inputs, so the refetch this asks for begins after them and its page
			// is judged by them
			self.Resync()
		}
	}
}
