// §18.7's step 2 (D-PROTO-5, X8; WK1 to WK4): what an owning service does after a hint's script, for a
// client holding a wake token, so §19.4's push sender can wake a phone whose resident is gone. The hint
// script already returned the client's tok and live from its own slot; the enqueue is a separate XADD to
// the wake queue's stream, in that stream's own slot, never a command shared with the script, so no
// script or command spans two slots (WK1).
//
//	{wakeq_<shard>}  16 streams, each in its own slot, MAXLEN ~10000: {c, t, v, h, hint_millis, due_millis}
//	                 c the client, t the topic's wake class, v the version ver holds, h the hint's stream id,
//	                 hint_millis that id's milliseconds and due_millis when the sender checks it; the shard is
//	                 the client id's FNV-1a hash mod 16, and the sender reads every shard
//
// Only a hint of a wake class enqueues, mail, team, evs (every evs:<repo_id>) or core, and only while tok
// is present and sidecar.yml's wake switch is on. It is due now when the hint is forced (§15.6's router
// on a receiver miss, POST /sidecar/wake) or live is absent, the client's resident gone, else
// DeferTimeout (15 s) on, a deferred check by which the publisher has most likely delivered the hint and
// raised ack past it. An entry carries the topic's class, never its id, and the version: the sender's
// payload is a class and a version only (WK4), so nothing more is stored for it.
//
// An XADD that fails is tried RetryCount (3) more times within RetryWindow (1 s), and then the wake is
// counted (urnetwork_wake_enqueue_dropped_total) and dropped, the hint state as the script left it: a lost
// wake never changes hint state (WK3), and a service killed between the script and the XADD loses only
// the wake (WK2's uncounted loss). Nothing here reads or writes the client's slot.
//
// Safe for concurrent use.

package pushservice

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The stream fields of one wake-queue entry (§18.7), which the sender reads by these names.
const (
	WakeEntryFieldClient   = "c"
	WakeEntryFieldTopic    = "t"
	WakeEntryFieldVersion  = "v"
	WakeEntryFieldStreamId = "h"
	WakeEntryFieldHintMs   = "hint_millis"
	WakeEntryFieldDueMs    = "due_millis"
)

var (
	// A wake-queue setting the queue cannot run on.
	ErrWakeQueueSettings = errors.New("wake queue: settings out of range")
	// An entry that is not one this package writes.
	ErrWakeEntryMalformed = errors.New("wake queue: entry malformed")
)

// The wake queue's format and the writer's tunables. The shard count and the stream length are the
// queue's format, which every writer and the push sender (SDK-M8-10) carry alike.
type WakeQueueSettings struct {
	// The streams the queue spreads over, each in its own slot: 16 (§18.7). The sender reads every one,
	// so a writer and the sender must hold the same count. Must be positive.
	ShardCount int
	// About how many entries a stream keeps: 10,000, MAXLEN ~ trimming whole stream nodes. Must be
	// positive.
	MaxLength int64
	// How far a wake is put off while the client's resident is live: 15 s (§18.7's deferred check), so
	// the publisher delivers the hint and raises ack past it first. Must be positive.
	DeferTimeout time.Duration
	// XADD attempts after a failed first: 3 (§18.7). Zero tries once.
	RetryCount int
	// The span those retries fit in, spaced evenly: 1 s. Zero retries at once.
	RetryWindow time.Duration
}

// §18.7's values.
func DefaultWakeQueueSettings() *WakeQueueSettings {
	return &WakeQueueSettings{
		ShardCount:   16,
		MaxLength:    10000,
		DeferTimeout: 15 * time.Second,
		RetryCount:   3,
		RetryWindow:  1 * time.Second,
	}
}

func (self *WakeQueueSettings) validate() error {
	if self.ShardCount <= 0 || self.MaxLength <= 0 || self.DeferTimeout <= 0 || self.RetryCount < 0 || self.RetryWindow < 0 {
		return ErrWakeQueueSettings
	}
	return nil
}

// {wakeq_<shard>}.
func WakeQueueKey(shard int) string {
	return "{wakeq_" + strconv.Itoa(shard) + "}"
}

// The shard of the queue clientId's wakes go to, of shardCount: the FNV-1a hash of its 16 bytes, mod the
// count. Every writer computes it alike; the sender needs it never, since it reads every shard.
func WakeQueueShard(clientId connect.Id, shardCount int) int {
	hash := fnv.New32a()
	hash.Write(clientId.Bytes())
	return int(hash.Sum32() % uint32(shardCount))
}

// The wake class of topic (§18.7's mail, team, evs or core), and false for a topic that wakes no one:
// sock, tls, dns and the gkm family resync at the client's next start or hourly refetch.
func WakeTopicClass(topic string) (string, bool) {
	switch topic {
	case sidecar.PushTopicCore, sidecar.PushTopicTeam, sidecar.PushTopicMail:
		return topic, true
	}
	if strings.HasPrefix(topic, sidecar.PushTopicEvsPrefix) && sidecar.PushTopicClassOf(topic) != sidecar.PushTopicUnknown {
		return "evs", true
	}
	return "", false
}

// One wake-queue entry as the push sender reads it.
type WakeEntry struct {
	ClientId connect.Id
	// The topic's wake class: mail, team, evs or core.
	TopicClass string
	Version    uint64
	// The hint's id in the client's stream, which the sender compares with {scp_<C>}ack.
	StreamId string
	HintMs   int64
	DueMs    int64
}

// The stream fields of the entry, as Enqueue writes them.
func (self *WakeEntry) fieldValues() map[string][]byte {
	return map[string][]byte{
		WakeEntryFieldClient:   []byte(self.ClientId.String()),
		WakeEntryFieldTopic:    []byte(self.TopicClass),
		WakeEntryFieldVersion:  []byte(FormatVersion(self.Version)),
		WakeEntryFieldStreamId: []byte(self.StreamId),
		WakeEntryFieldHintMs:   []byte(strconv.FormatInt(self.HintMs, 10)),
		WakeEntryFieldDueMs:    []byte(strconv.FormatInt(self.DueMs, 10)),
	}
}

// The entry a wake-queue stream entry holds, or ErrWakeEntryMalformed for one this package did not
// write, which the sender acks and drops.
func ParseWakeEntry(entry *sidecar.RedisStreamEntry) (*WakeEntry, error) {
	field := func(name string) (string, error) {
		value, ok := entry.FieldValues[name]
		if !ok || len(value) == 0 {
			return "", fmt.Errorf("%w: %s has no %s", ErrWakeEntryMalformed, entry.Id, name)
		}
		return string(value), nil
	}
	clientText, err := field(WakeEntryFieldClient)
	if err != nil {
		return nil, err
	}
	clientId, err := connect.ParseId(clientText)
	if err != nil {
		return nil, fmt.Errorf("%w: %s's client", ErrWakeEntryMalformed, entry.Id)
	}
	topicClass, err := field(WakeEntryFieldTopic)
	if err != nil {
		return nil, err
	}
	switch topicClass {
	case sidecar.PushTopicCore, sidecar.PushTopicTeam, sidecar.PushTopicMail, "evs":
	default:
		return nil, fmt.Errorf("%w: %s's topic class", ErrWakeEntryMalformed, entry.Id)
	}
	versionText, err := field(WakeEntryFieldVersion)
	if err != nil {
		return nil, err
	}
	version, err := ParseVersion(versionText)
	if err != nil {
		return nil, fmt.Errorf("%w: %s's version", ErrWakeEntryMalformed, entry.Id)
	}
	streamId, err := field(WakeEntryFieldStreamId)
	if err != nil {
		return nil, err
	}
	if _, _, err := ParseStreamId(streamId); err != nil {
		return nil, fmt.Errorf("%w: %s's hint id", ErrWakeEntryMalformed, entry.Id)
	}
	millis := func(name string) (int64, error) {
		text, err := field(name)
		if err != nil {
			return 0, err
		}
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil || value < 0 {
			return 0, fmt.Errorf("%w: %s's %s", ErrWakeEntryMalformed, entry.Id, name)
		}
		return value, nil
	}
	hintMs, err := millis(WakeEntryFieldHintMs)
	if err != nil {
		return nil, err
	}
	dueMs, err := millis(WakeEntryFieldDueMs)
	if err != nil {
		return nil, err
	}
	return &WakeEntry{
		ClientId:   clientId,
		TopicClass: topicClass,
		Version:    version,
		StreamId:   streamId,
		HintMs:     hintMs,
		DueMs:      dueMs,
	}, nil
}

// What the queue's writer needs of Redis: ServiceHost.Redis satisfies it, and so does server's model
// adapter. Safe for concurrent use.
type WakeQueueRedis interface {
	// See sidecar.Redis.
	StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (entryId string, err error)
}

// What one Enqueue did.
type WakeEnqueueOutcome int

const (
	// Nothing to wake: no token, a topic of no wake class, or the wake switch off.
	WakeEnqueueNone WakeEnqueueOutcome = iota
	// Queued, due now: forced, or the client's resident is gone.
	WakeEnqueueDue
	// Queued, due DeferTimeout on: the resident is live.
	WakeEnqueueDeferred
	// Every attempt failed: counted and dropped, the hint state untouched.
	WakeEnqueueDropped
)

// What a WakeEnqueuer has counted.
type WakeEnqueuerStats struct {
	DueCount      uint64
	DeferredCount uint64
	DroppedCount  uint64
	// wake-class hints to a token holder the switch kept off the queue
	GatedCount uint64
	// XADDs that failed, each attempt
	FailedAttemptCount uint64
}

// Enqueues wakes. NewWakeEnqueuer makes one.
type WakeEnqueuer struct {
	redis    WakeQueueRedis
	settings *WakeQueueSettings
	clock    sidecar.Clock
	// sidecar.yml's wake switch, read at each enqueue
	enabled func() bool
	// nil when the host gave no Metrics
	droppedCounter sidecar.MetricsCounter

	dueCount           atomic.Uint64
	deferredCount      atomic.Uint64
	droppedCount       atomic.Uint64
	gatedCount         atomic.Uint64
	failedAttemptCount atomic.Uint64
}

// An enqueuer on redis with settings, nil being §18.7's, waiting on clock, nil being real time, while
// enabled answers true: the host's reading of sidecar.yml's wake switch (ServiceGates.Switch(wake)),
// asked at each enqueue; nil is always off, the closed default. metrics may be nil.
func NewWakeEnqueuer(redis WakeQueueRedis, settings *WakeQueueSettings, clock sidecar.Clock, enabled func() bool, metrics sidecar.Metrics) (*WakeEnqueuer, error) {
	if redis == nil {
		return nil, fmt.Errorf("%w: no Redis", ErrWakeQueueSettings)
	}
	if settings == nil {
		settings = DefaultWakeQueueSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if enabled == nil {
		enabled = func() bool { return false }
	}
	self := &WakeEnqueuer{
		redis:    redis,
		settings: settings,
		clock:    clock,
		enabled:  enabled,
	}
	if metrics != nil {
		self.droppedCounter = metrics.Counter("urnetwork_wake_enqueue_dropped_total", "wake-queue enqueues dropped after their retries (§18.7)", "topic")
	}
	return self, nil
}

// What the enqueuer has counted.
func (self *WakeEnqueuer) Stats() WakeEnqueuerStats {
	return WakeEnqueuerStats{
		DueCount:           self.dueCount.Load(),
		DeferredCount:      self.deferredCount.Load(),
		DroppedCount:       self.droppedCount.Load(),
		GatedCount:         self.gatedCount.Load(),
		FailedAttemptCount: self.failedAttemptCount.Load(),
	}
}

// §18.7's step 2 for one client's hint, after its script answered result: queues its wake when the hint
// is wake-class and result holds a token, due now when the hint is forced or the client has no live
// resident, else DeferTimeout on. Never touches the client's slot, and a failure is counted, never
// returned: the hint stands whatever becomes of its wake.
func (self *WakeEnqueuer) Enqueue(ctx context.Context, clientId connect.Id, hint *sidecar.ClientHint, result *PushHintResult) WakeEnqueueOutcome {
	if hint == nil || result == nil || len(result.Token) == 0 {
		return WakeEnqueueNone
	}
	topicClass, ok := WakeTopicClass(hint.Topic)
	if !ok {
		return WakeEnqueueNone
	}
	if !self.enabled() {
		self.gatedCount.Add(1)
		return WakeEnqueueNone
	}
	hintMs, _, err := ParseStreamId(result.StreamId)
	if err != nil {
		// the script's own reply, which parseHintReply checked
		self.drop(topicClass)
		return WakeEnqueueDropped
	}
	now := self.clock.Now()
	outcome := WakeEnqueueDue
	due := now
	if !hint.Forced && result.Live {
		outcome = WakeEnqueueDeferred
		due = now.Add(self.settings.DeferTimeout)
	}
	entry := &WakeEntry{
		ClientId:   clientId,
		TopicClass: topicClass,
		Version:    result.Version,
		StreamId:   result.StreamId,
		HintMs:     int64(hintMs),
		DueMs:      due.UnixMilli(),
	}
	key := WakeQueueKey(WakeQueueShard(clientId, self.settings.ShardCount))
	fieldValues := entry.fieldValues()
	spacing := time.Duration(0)
	if 0 < self.settings.RetryCount {
		spacing = self.settings.RetryWindow / time.Duration(self.settings.RetryCount)
	}
	barrierKey := clientId.String()
	for attempt := 0; attempt <= self.settings.RetryCount; attempt += 1 {
		if 0 < attempt {
			select {
			case <-ctx.Done():
				self.drop(topicClass)
				return WakeEnqueueDropped
			case <-self.clock.After(spacing):
			}
		}
		testHookBarrier("pushservice.wake.before", barrierKey)
		_, err := self.redis.StreamAdd(ctx, key, self.settings.MaxLength, fieldValues)
		testHookBarrier("pushservice.wake.after", barrierKey)
		if err == nil {
			if outcome == WakeEnqueueDue {
				self.dueCount.Add(1)
			} else {
				self.deferredCount.Add(1)
			}
			return outcome
		}
		self.failedAttemptCount.Add(1)
	}
	self.drop(topicClass)
	return WakeEnqueueDropped
}

func (self *WakeEnqueuer) drop(topicClass string) {
	self.droppedCount.Add(1)
	if self.droppedCounter != nil {
		self.droppedCounter.Add(1, topicClass)
	}
}
