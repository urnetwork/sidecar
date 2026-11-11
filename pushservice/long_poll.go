// §6.8's long-poll (D-PROTO-5): GET /sidecar/sync/poll?cursor= for HTTP-only hosts, which api serves
// from the same hint state the residents read. A poll answers 200 PollResponse at once when the client's
// stream holds hints past its cursor, and otherwise holds up to HoldTimeout, under the lb's 30 s
// proxy_read_timeout, answering on the next hint or, after an empty hold, with nothing and its cursor
// unchanged; never 204, which carries no body.
//
// The cursor is opaque to the client: the last stream id it was given, with that entry's seq, so a poll
// that finds the next entry's seq is not one past it knows the stream has moved on without it, by a trim
// or by the keys' hourly expiry, and puts a reset first. An empty cursor gets a reset first too. A reset
// here is one PushReset part of at most 48 versions, complete only when ver holds no more, which
// otherwise sends the client to GET /sidecar/sync/versions (D-PROTO-20).
//
// A hold is woken through the process's one shared key-event subscription on {scp_*}n, which demuxes to
// in-memory waiters: never a subscription per client. When the subscription is lost and comes back,
// every waiter rereads, since whatever was published in the gap is gone. Held polls are bounded per
// process, and a poll past the bound is refused at once.
//
// Each poll also keeps the client's poll marker {scp_<C>}hb (§18.8): SET NX EX LeaseTimeout, and when
// that sets or errs, LeaseTouch, TEAM-M1-10's narrow write of network_client_lease.seen_time, so the row
// is written at most once per LeaseTimeout while Redis answers. That is the one write a poll may make to
// Postgres; the hold itself reads only Redis (I-12).
//
// Safe for concurrent use.

package pushservice

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The process holds as many polls as its settings allow: answer 503 with Retry-After.
	ErrLongPollBusy = errors.New("long-poll: too many held polls")
	// The long-poll has closed.
	ErrLongPollClosed = errors.New("long-poll: closed")
)

// What the long-poll reads and writes: a publisher's reads, SET NX for the poll marker, and the
// process's one shared key-event subscriber. ServiceHost.Redis satisfies it, and so does server's model
// adapter. Safe for concurrent use.
type LongPollRedis interface {
	PublisherRedis
	// See sidecar.Redis.
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (set bool, err error)
	// See sidecar.Redis.
	AddKeyEventCallback(keyPattern string, callback sidecar.RedisKeyEventFunction) (remove func(), err error)
}

// Writes network_client_lease.seen_time for clientId (TEAM-M1-10, §18.8). It may reach Postgres, as the
// one write a poll makes there.
type LeaseTouchFunction func(ctx context.Context, clientId connect.Id) error

// §6.6's SidecarPublisherSettings.LongPollHoldTimeout and the long-poll's other bounds.
type LongPollSettings struct {
	// How long a poll holds with nothing to answer: SidecarPublisherSettings.LongPollHoldTimeout's 25 s,
	// under the lb's 30 s proxy_read_timeout.
	HoldTimeout time.Duration
	// Polls one process holds at once. A poll past it is refused at once, so a burst costs refusals,
	// not memory: 20,000.
	MaxHeldPollCount int
	// What a refused poll is told to wait before it polls again: 5 s.
	BusyRetryAfter time.Duration
	// The most hints one answer carries; the next poll takes the rest at once: 256, a stream's length.
	HintCount int64
	// How long the poll marker {scp_<C>}hb lives, so LeaseTouch runs at most once in it while Redis
	// answers: 300 s (§6.16, §18.8).
	LeaseTimeout time.Duration
	// §6.8's wire limits: a reset here is one part of at most ResetPartVersionCount versions.
	Format PushFormatSettings
}

// The defaults, the hold §6.6's.
func DefaultLongPollSettings() *LongPollSettings {
	return &LongPollSettings{
		HoldTimeout:      DefaultSidecarPublisherSettings().LongPollHoldTimeout,
		MaxHeldPollCount: 20000,
		BusyRetryAfter:   5 * time.Second,
		HintCount:        256,
		LeaseTimeout:     300 * time.Second,
		Format:           *DefaultPushFormatSettings(),
	}
}

func (self *LongPollSettings) validate() error {
	if self.HoldTimeout <= 0 || self.MaxHeldPollCount <= 0 || self.BusyRetryAfter <= 0 || self.HintCount <= 0 || self.LeaseTimeout < time.Second {
		return errors.New("long-poll: every setting must be positive, the lease a second or more")
	}
	if err := self.Format.validate(); err != nil {
		return err
	}
	return nil
}

// One held poll's wake.
type longPollWaiter struct {
	// buffered by one, so a wake never blocks the subscriber's goroutine and two wakes read as one
	wake chan struct{}
}

func (self *longPollWaiter) signal() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// What a LongPoll has counted.
type LongPollStats struct {
	// polls held now
	HeldCount int
	// polls refused past MaxHeldPollCount
	BusyCount uint64
	// answers that carried a reset
	ResetCount uint64
	// LeaseTouch calls, and those that failed
	LeaseTouchCount       uint64
	LeaseTouchFailedCount uint64
}

// The process's long-poll. NewLongPoll makes one.
type LongPoll struct {
	ctx        context.Context
	cancel     context.CancelFunc
	redis      LongPollRedis
	clock      sidecar.Clock
	settings   *LongPollSettings
	leaseTouch LeaseTouchFunction
	// takes the callback off the shared subscriber
	removeCallback func()

	stateLock       sync.Mutex
	clientIdWaiters map[connect.Id]map[*longPollWaiter]bool
	heldCount       int

	busyCount             atomic.Uint64
	resetCount            atomic.Uint64
	leaseTouchCount       atomic.Uint64
	leaseTouchFailedCount atomic.Uint64
}

// A long-poll on redis, its holds timed by clock (nil is real time), with settings (nil is the
// defaults). leaseTouch may be nil while no lease table exists, and then the marker alone is kept.
// Registers the one callback this process's polls need on redis's shared subscriber, which Close
// removes.
func NewLongPoll(ctx context.Context, redis LongPollRedis, clock sidecar.Clock, settings *LongPollSettings, leaseTouch LeaseTouchFunction) (*LongPoll, error) {
	if redis == nil {
		return nil, errors.New("long-poll: no Redis")
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if settings == nil {
		settings = DefaultLongPollSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &LongPoll{
		ctx:             cancelCtx,
		cancel:          cancel,
		redis:           redis,
		clock:           clock,
		settings:        settings,
		leaseTouch:      leaseTouch,
		clientIdWaiters: map[connect.Id]map[*longPollWaiter]bool{},
	}
	removeCallback, err := redis.AddKeyEventCallback(HintSeqKeyPattern, self.keyEvent)
	if err != nil {
		cancel()
		return nil, err
	}
	self.removeCallback = removeCallback
	return self, nil
}

// Ends every hold, which answers ErrLongPollClosed, and takes the callback off the subscriber. Safe to
// call more than once.
func (self *LongPoll) Close() {
	self.cancel()
	self.removeCallback()
}

// What the long-poll has counted.
func (self *LongPoll) Stats() LongPollStats {
	self.stateLock.Lock()
	heldCount := self.heldCount
	self.stateLock.Unlock()
	return LongPollStats{
		HeldCount:             heldCount,
		BusyCount:             self.busyCount.Load(),
		ResetCount:            self.resetCount.Load(),
		LeaseTouchCount:       self.leaseTouchCount.Load(),
		LeaseTouchFailedCount: self.leaseTouchFailedCount.Load(),
	}
}

// The shared subscriber's callback, on its goroutine: it wakes what it names and returns, never
// blocking. A resync wakes every waiter, since what was published in the gap is gone.
func (self *LongPoll) keyEvent(event sidecar.RedisKeyEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if event.Resync {
		for _, waiters := range self.clientIdWaiters {
			for waiter := range waiters {
				waiter.signal()
			}
		}
		return
	}
	clientId, ok := ParseHintSeqKey(event.Key)
	if !ok {
		return
	}
	for waiter := range self.clientIdWaiters[clientId] {
		waiter.signal()
	}
}

// Adds a waiter for clientId, or ErrLongPollBusy past the bound.
func (self *LongPoll) register(clientId connect.Id) (*longPollWaiter, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.MaxHeldPollCount <= self.heldCount {
		self.busyCount.Add(1)
		return nil, ErrLongPollBusy
	}
	waiter := &longPollWaiter{wake: make(chan struct{}, 1)}
	waiters := self.clientIdWaiters[clientId]
	if waiters == nil {
		waiters = map[*longPollWaiter]bool{}
		self.clientIdWaiters[clientId] = waiters
	}
	waiters[waiter] = true
	self.heldCount += 1
	return waiter, nil
}

func (self *LongPoll) unregister(clientId connect.Id, waiter *longPollWaiter) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	waiters := self.clientIdWaiters[clientId]
	if !waiters[waiter] {
		return
	}
	delete(waiters, waiter)
	if len(waiters) == 0 {
		delete(self.clientIdWaiters, clientId)
	}
	self.heldCount -= 1
}

// A poll's position: the last stream id it was given and that entry's seq. The zero value, with an
// empty stream id, is a client that has seen nothing yet.
type longPollCursor struct {
	streamId string
	seq      uint64
}

// The cursor's text form, which the client keeps and sends back unread: "1:<stream id>:<seq>".
func (self longPollCursor) encode() []byte {
	return []byte("1:" + self.streamId + ":" + strconv.FormatUint(self.seq, 10))
}

// The cursor a client sent, or false for an empty one or one this process did not make, either of
// which gets a reset first.
func decodeLongPollCursor(cursor []byte) (longPollCursor, bool) {
	rest, found := strings.CutPrefix(string(cursor), "1:")
	if !found {
		return longPollCursor{}, false
	}
	streamId, seqText, found := strings.Cut(rest, ":")
	if !found {
		return longPollCursor{}, false
	}
	if _, _, err := ParseStreamId(streamId); err != nil {
		return longPollCursor{}, false
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil {
		return longPollCursor{}, false
	}
	return longPollCursor{streamId: streamId, seq: seq}, true
}

// Answers one poll by clientId, already authenticated as that client: at once when its stream has
// something past cursor, else after holding until a hint or HoldTimeout. ErrLongPollBusy past the
// bound; ctx's error when the caller goes. The held path reads only Redis.
func (self *LongPoll) Poll(ctx context.Context, clientId connect.Id, cursor []byte) (*protocol.PollResponse, error) {
	if self.ctx.Err() != nil {
		return nil, ErrLongPollClosed
	}
	self.touchLease(ctx, clientId)

	position, hasPosition := decodeLongPollCursor(cursor)
	// the waiter first, then the read, so a hint between the two still wakes the hold
	waiter, err := self.register(clientId)
	if err != nil {
		return nil, err
	}
	defer self.unregister(clientId, waiter)
	// the hold's end, set at the first read that finds nothing, so an answer at once costs no timer
	var holdEnd <-chan time.Time
	barrierKey := clientId.String()
	for {
		response, err := self.read(ctx, clientId, position, hasPosition)
		if err != nil {
			return nil, err
		}
		if response != nil {
			return response, nil
		}
		if holdEnd == nil {
			holdEnd = self.clock.After(self.settings.HoldTimeout)
		}
		testHookBarrier("pushservice.long_poll.hold", barrierKey)
		select {
		case <-waiter.wake:
		case <-holdEnd:
			// an empty hold: the cursor as it came
			return &protocol.PollResponse{Cursor: cursor}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.ctx.Done():
			return nil, ErrLongPollClosed
		}
	}
}

// The answer the stream has for position now, or nil when it has none and the poll should hold.
func (self *LongPoll) read(ctx context.Context, clientId connect.Id, position longPollCursor, hasPosition bool) (*protocol.PollResponse, error) {
	after := ""
	if hasPosition {
		after = position.streamId
	}
	entries, err := self.redis.StreamRange(ctx, HintStreamKey(clientId), after, self.settings.HintCount)
	if err != nil {
		return nil, err
	}
	needReset := !hasPosition
	hints := make([]*protocol.PushHint, 0, len(entries))
	for _, entry := range entries {
		hint, err := ParseHintEntry(entry)
		if err != nil {
			// an entry nobody can read is a gap: the reset puts the client right
			needReset = true
			continue
		}
		hints = append(hints, hint)
	}
	if hasPosition && 0 < len(entries) {
		if first, err := ParseHintEntry(entries[0]); err != nil || first.Seq != position.seq+1 {
			// trimmed past, or n restarted after the keys' hour: the stream moved on without this cursor
			needReset = true
		}
	}
	if !needReset && len(entries) == 0 {
		return nil, nil
	}

	next := position
	if 0 < len(entries) {
		last := entries[len(entries)-1]
		next.streamId = last.Id
		next.seq = 0
		if lastHint, err := ParseHintEntry(last); err == nil {
			next.seq = lastHint.Seq
		}
	} else if !hasPosition {
		// nothing in the stream yet: the next poll reads it from the start
		next = longPollCursor{streamId: "0-0", seq: 0}
	}
	response := &protocol.PollResponse{
		Cursor: next.encode(),
		Hints:  hints,
	}
	if needReset {
		reset, err := self.reset(ctx, clientId)
		if err != nil {
			return nil, err
		}
		response.Reset_ = reset
		self.resetCount.Add(1)
	}
	return response, nil
}

// One reset part from ver: its topics in name order, at most the format's ResetPartVersionCount,
// complete only when that is all of them, under an epoch drawn for this answer alone, since a poll's
// reset is a run of one part (plan-PROTO-small-readings reading 5).
func (self *LongPoll) reset(ctx context.Context, clientId connect.Id) (*protocol.PushReset, error) {
	fieldValues, err := self.redis.HashGetAll(ctx, HintVersionsKey(clientId))
	if err != nil {
		return nil, err
	}
	topicVersions := ParseHintVersions(fieldValues)
	topics := slices.Sorted(func(yield func(string) bool) {
		for topic := range topicVersions {
			if !yield(topic) {
				return
			}
		}
	})
	partVersionCount := self.settings.Format.ResetPartVersionCount
	complete := len(topics) <= partVersionCount
	if !complete {
		topics = topics[:partVersionCount]
	}
	versions := make([]*protocol.TopicVersion, 0, len(topics))
	for _, topic := range topics {
		versions = append(versions, &protocol.TopicVersion{Topic: topic, Version: topicVersions[topic]})
	}
	epoch, err := newResetEpoch()
	if err != nil {
		return nil, err
	}
	return &protocol.PushReset{Epoch: epoch, Versions: versions, Complete: complete}, nil
}

// A reset run's epoch: random and never 0, so two runs to one client never share one.
func newResetEpoch() (uint64, error) {
	var epochBytes [8]byte
	for {
		if _, err := rand.Read(epochBytes[:]); err != nil {
			return 0, fmt.Errorf("long-poll: reset epoch: %w", err)
		}
		if epoch := binary.BigEndian.Uint64(epochBytes[:]); epoch != 0 {
			return epoch, nil
		}
	}
}

// The poll marker and, when it sets or Redis errs, LeaseTouch. Neither failing fails the poll: the
// marker is a rate limit on the lease write, and a missed lease write is the reaper's to judge.
func (self *LongPoll) touchLease(ctx context.Context, clientId connect.Id) {
	set, err := self.redis.SetIfAbsent(ctx, HintPollKey(clientId), []byte("1"), self.settings.LeaseTimeout)
	if (set || err != nil) && self.leaseTouch != nil {
		self.leaseTouchCount.Add(1)
		if err := self.leaseTouch(ctx, clientId); err != nil {
			self.leaseTouchFailedCount.Add(1)
		}
	}
}

var (
	// A versions cursor this process did not make.
	ErrVersionsCursor = errors.New("sync versions: cursor malformed")
)

// VersionsPageWithFormat on the protocol's limits.
func VersionsPage(topicVersions map[string]uint64, cursor []byte) (*protocol.PollResponse, error) {
	return VersionsPageWithFormat(DefaultPushFormatSettings(), topicVersions, cursor)
}

// One page of GET /sidecar/sync/versions?cursor= (plan-PROTO-sync-routes-durable-versions): a 200
// PollResponse with reset set and no hints, the topics after the cursor's in name order, at most
// format's ResetPartVersionCount, complete only on the last page, which alone carries no cursor. Every
// page of one run carries the run's epoch, which the first page draws. topicVersions is what api answers
// for the client: its ver hash, with what api holds of its own durable topics put over it.
func VersionsPageWithFormat(format *PushFormatSettings, topicVersions map[string]uint64, cursor []byte) (*protocol.PollResponse, error) {
	if err := format.validate(); err != nil {
		return nil, err
	}
	epoch := uint64(0)
	afterTopic := ""
	if 0 < len(cursor) {
		rest, found := strings.CutPrefix(string(cursor), "v1:")
		if !found {
			return nil, ErrVersionsCursor
		}
		epochText, topic, found := strings.Cut(rest, ":")
		if !found || topic == "" {
			return nil, ErrVersionsCursor
		}
		parsed, err := strconv.ParseUint(epochText, 10, 64)
		if err != nil || parsed == 0 {
			return nil, ErrVersionsCursor
		}
		epoch, afterTopic = parsed, topic
	} else {
		var err error
		epoch, err = newResetEpoch()
		if err != nil {
			return nil, err
		}
	}
	topics := []string{}
	for topic := range topicVersions {
		if afterTopic < topic {
			topics = append(topics, topic)
		}
	}
	slices.Sort(topics)
	complete := len(topics) <= format.ResetPartVersionCount
	if !complete {
		topics = topics[:format.ResetPartVersionCount]
	}
	versions := make([]*protocol.TopicVersion, 0, len(topics))
	for _, topic := range topics {
		versions = append(versions, &protocol.TopicVersion{Topic: topic, Version: topicVersions[topic]})
	}
	response := &protocol.PollResponse{
		Reset_: &protocol.PushReset{Epoch: epoch, Versions: versions, Complete: complete},
	}
	if !complete {
		response.Cursor = []byte("v1:" + strconv.FormatUint(epoch, 10) + ":" + topics[len(topics)-1])
	}
	return response, nil
}
