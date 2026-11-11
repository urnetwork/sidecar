// ServiceHost.Push's implementation (§6.8, §18.7's step 1): one HintScript run per client, on that
// client's slot alone, so no command spans two slots and none is atomic across clients. evs, gkm and the
// other owning services get one from their host, and api writes its own topics, core and team, through
// the same writer (server's model.SidecarHint).
//
// A hint is lossy state sync, not a mailbox: a client that misses one resyncs at its next reconnect or
// hourly refetch, so a failed hint costs latency, and the writer counts it and goes on. What it carries
// is ids, kinds and versions, never content (R-PROTO-8), at most the format's 256 B of it.
//
// A writer made with a WakeEnqueuer follows each script with §18.7's step 2 (wake_enqueue.go): for a
// wake-class hint to a client the script found holding a token, a separate XADD to the wake queue, due
// now when the hint is Forced or no resident is live. The enqueue never fails the hint: a lost wake
// leaves the hint state as the script wrote it. A writer with none writes hints alone, as gkm's does,
// whose topics wake no one.
//
// Safe for concurrent use.

package pushservice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

var (
	// A hint whose topic §6.8's registry does not hold, or whose version is 0.
	ErrHintInvalid = errors.New("push hint invalid")
	// HintSidecars with no PushClientResolver: the host has no way yet to turn a sidecar_id into a client
	// (plan-KEYS-hint-addressing), so the hint is lost, counted, and the client's hourly resync covers it.
	ErrHintSidecarsUnresolved = errors.New("push hint by sidecar id has no resolver")
	// What a script answered that is not the shape the script returns.
	errHintReply = errors.New("push hint script reply malformed")
)

var _ sidecar.Push = (*HintWriter)(nil)

// The writer's tunables. The ttl and the stream's length are §2.8's published values.
type HintWriterSettings struct {
	// How long ver, hint and n live from their creation: 1 h, connect-4's ttl. EXPIRE NX sets it once a
	// key generation, so a client's n restarts at most once an hour, never at each write. Whole seconds;
	// one under a second is refused.
	KeyTimeout time.Duration
	// About how many entries the hint stream keeps: 256, MAXLEN ~ trimming in whole stream nodes.
	StreamMaxLength int64
	// How long ack lives from each raise: 1 h (§18.7). Whole seconds.
	AckTimeout time.Duration
	// §6.8's wire limits: a hint's bytes at most MaxHintByteCount.
	Format PushFormatSettings
}

// The defaults: connect-4's hour and 256 entries, and §18.7's hour for ack.
func DefaultHintWriterSettings() *HintWriterSettings {
	return &HintWriterSettings{
		KeyTimeout:      1 * time.Hour,
		StreamMaxLength: 256,
		AckTimeout:      1 * time.Hour,
		Format:          *DefaultPushFormatSettings(),
	}
}

// Whether every value can reach Redis as itself: a zero ttl would read as no expiry, and a zero length
// as no trimming.
func (self *HintWriterSettings) validate() error {
	if self.KeyTimeout < time.Second || self.AckTimeout < time.Second || self.StreamMaxLength <= 0 {
		return fmt.Errorf("%w: ttls must be whole seconds and the stream length positive", ErrHintInvalid)
	}
	if err := self.Format.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrHintInvalid, err)
	}
	return nil
}

// Resolves sidecars to their current clients for HintSidecars, which the host injects: taskworker from
// sidecar_identity_binding, a host that keeps Postgres off this path through api's internal route, each
// with its own cache (plan-KEYS-hint-addressing). Safe for concurrent use.
type PushClientResolver interface {
	// Each known, unrevoked sidecar's current client. An id it does not resolve is absent, which loses that
	// sidecar's hint; an error means the lookup itself failed.
	PushClientIds(ctx context.Context, sidecarIds []connect.Id) (map[connect.Id]connect.Id, error)
}

// What one client's script returned: §18.7's {h, tok, live}, with what the hint now carries.
type PushHintResult struct {
	// The hint's entry in {scp_<C>}hint: §18.7's h.
	StreamId string
	// The version ver holds for the topic now, which the hint carries: the caller's, a higher stored one,
	// or a raised clock.
	Version uint64
	// n's value, the hint's seq.
	Seq uint64
	// {scp_<C>}tok, §18.7's wake token projection, nil while absent.
	Token []byte
	// Whether {scp_<C>}live exists: the client's resident is up, its publisher writing it.
	Live bool
	// What §18.7's step 2 did after the script: WakeEnqueueNone for a writer with no WakeEnqueuer.
	Wake WakeEnqueueOutcome
}

// Running totals, for a host's stats.
type hintWriterStats struct {
	// scripts that answered
	hintedCount atomic.Uint64
	// scripts that failed, and hints refused before any script ran
	failedCount atomic.Uint64
	// sidecars no client was found for, whose hints are lost until their resync
	unresolvedCount atomic.Uint64
}

// What a HintWriter has counted.
type HintWriterStats struct {
	HintedCount     uint64
	FailedCount     uint64
	UnresolvedCount uint64
}

// The urnetwork_push_* family: results only, never a client, sidecar or topic id (I-13).
const (
	hintResultOk         = "ok"
	hintResultFailed     = "failed"
	hintResultUnresolved = "unresolved"
)

// Writes hints. NewHintWriter makes one, and NewWakingHintWriter one that enqueues wakes.
type HintWriter struct {
	redis    HintRedis
	settings *HintWriterSettings
	resolver PushClientResolver
	// nil: hints alone
	wake *WakeEnqueuer
	// nil when the host gave no Metrics
	hintCounter sidecar.MetricsCounter
	stats       hintWriterStats
}

// A writer on redis that enqueues no wakes. A nil settings takes the defaults. resolver may be nil until
// the host has one, and then HintSidecars refuses (ErrHintSidecarsUnresolved). metrics may be nil.
func NewHintWriter(redis HintRedis, settings *HintWriterSettings, resolver PushClientResolver, metrics sidecar.Metrics) (*HintWriter, error) {
	return NewWakingHintWriter(redis, settings, resolver, metrics, nil)
}

// NewHintWriter's writer, which follows each script with wake's §18.7 step 2: the writer of an owning
// service whose topics wake, api's (core, team), evs's and mail's. A nil wake enqueues nothing.
func NewWakingHintWriter(redis HintRedis, settings *HintWriterSettings, resolver PushClientResolver, metrics sidecar.Metrics, wake *WakeEnqueuer) (*HintWriter, error) {
	if redis == nil {
		return nil, fmt.Errorf("%w: no Redis", ErrHintInvalid)
	}
	if settings == nil {
		settings = DefaultHintWriterSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	self := &HintWriter{
		redis:    redis,
		settings: settings,
		resolver: resolver,
		wake:     wake,
	}
	if metrics != nil {
		self.hintCounter = metrics.Counter("urnetwork_push_hint_total", "push hints by result", "result")
	}
	return self, nil
}

// What the writer has counted.
func (self *HintWriter) Stats() HintWriterStats {
	return HintWriterStats{
		HintedCount:     self.stats.hintedCount.Load(),
		FailedCount:     self.stats.failedCount.Load(),
		UnresolvedCount: self.stats.unresolvedCount.Load(),
	}
}

func (self *HintWriter) count(counter *atomic.Uint64, result string, count int) {
	if count <= 0 {
		return
	}
	counter.Add(uint64(count))
	if self.hintCounter != nil {
		self.hintCounter.Add(float64(count), result)
	}
}

// Whether hint is one the script may write: a registry topic, a version above 0 and at most the format's
// MaxHintByteCount.
func (self *HintWriter) checkClientHint(hint *sidecar.ClientHint) error {
	if hint == nil || sidecar.PushTopicClassOf(hint.Topic) == sidecar.PushTopicUnknown || hint.Version == 0 {
		return ErrHintInvalid
	}
	if maxHintByteCount := self.settings.Format.MaxHintByteCount; maxHintByteCount < len(hint.Body) {
		return fmt.Errorf("%w: %d bytes past %d", ErrHintInvalid, len(hint.Body), maxHintByteCount)
	}
	return nil
}

// See sidecar.Push. Runs each client's script in turn, every one whatever the others did, and answers
// the failures joined, so one client's error says nothing of another's hint.
func (self *HintWriter) Hint(ctx context.Context, clientIds []connect.Id, hint *sidecar.ClientHint) error {
	if err := self.checkClientHint(hint); err != nil {
		self.count(&self.stats.failedCount, hintResultFailed, len(clientIds))
		return err
	}
	errs := []error{}
	for _, clientId := range clientIds {
		if _, err := self.hintClient(ctx, clientId, hint); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// See sidecar.Push. Each sidecar resolves through the host's PushClientResolver to its current client,
// whose script then runs as Hint's does. A sidecar the resolver omits loses its hint and is counted, and
// is no error: a device mid-change resyncs within the hour. With no resolver, every hint here is lost,
// counted and refused (plan-KEYS-hint-addressing's interim).
func (self *HintWriter) HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *sidecar.ClientHint) error {
	if err := self.checkClientHint(hint); err != nil {
		self.count(&self.stats.failedCount, hintResultFailed, len(sidecarIds))
		return err
	}
	if len(sidecarIds) == 0 {
		return nil
	}
	if self.resolver == nil {
		self.count(&self.stats.unresolvedCount, hintResultUnresolved, len(sidecarIds))
		return ErrHintSidecarsUnresolved
	}
	sidecarClientIds, err := self.resolver.PushClientIds(ctx, sidecarIds)
	if err != nil {
		self.count(&self.stats.unresolvedCount, hintResultUnresolved, len(sidecarIds))
		return fmt.Errorf("push hint by sidecar id: %w", err)
	}
	clientIds := make([]connect.Id, 0, len(sidecarIds))
	for _, sidecarId := range sidecarIds {
		if clientId, ok := sidecarClientIds[sidecarId]; ok {
			clientIds = append(clientIds, clientId)
		}
	}
	self.count(&self.stats.unresolvedCount, hintResultUnresolved, len(sidecarIds)-len(clientIds))
	return self.Hint(ctx, clientIds, hint)
}

// One client's script, answering §18.7's {h, tok, live} and what the wake step that follows it did.
func (self *HintWriter) HintClient(ctx context.Context, clientId connect.Id, hint *sidecar.ClientHint) (*PushHintResult, error) {
	if err := self.checkClientHint(hint); err != nil {
		self.count(&self.stats.failedCount, hintResultFailed, 1)
		return nil, err
	}
	return self.hintClient(ctx, clientId, hint)
}

// The script for one client, hint already checked, then §18.7's step 2 when the writer enqueues wakes:
// a separate command on the wake queue's own slot, after the script has answered. The script is the
// linearization point: its barrier key is the client id, opaque (I-13).
func (self *HintWriter) hintClient(ctx context.Context, clientId connect.Id, hint *sidecar.ClientHint) (*PushHintResult, error) {
	raise := "0"
	if sidecar.PushTopicRaisesClock(hint.Topic) {
		raise = "1"
	}
	keys := []string{
		HintVersionsKey(clientId),
		HintStreamKey(clientId),
		HintSeqKey(clientId),
		HintTokenKey(clientId),
		HintLiveKey(clientId),
	}
	args := []string{
		hint.Topic,
		FormatVersion(hint.Version),
		strconv.FormatUint(uint64(hint.Kind), 10),
		string(hint.Body),
		raise,
		strconv.FormatInt(int64(self.settings.KeyTimeout/time.Second), 10),
		strconv.FormatInt(self.settings.StreamMaxLength, 10),
	}
	barrierKey := clientId.String()
	testHookBarrier("pushservice.hint.before", barrierKey)
	reply, err := self.redis.RunScript(ctx, HintScript, keys, args)
	testHookBarrier("pushservice.hint.after", barrierKey)
	if err != nil {
		self.count(&self.stats.failedCount, hintResultFailed, 1)
		return nil, err
	}
	result, err := parseHintReply(reply)
	if err != nil {
		self.count(&self.stats.failedCount, hintResultFailed, 1)
		return nil, err
	}
	self.count(&self.stats.hintedCount, hintResultOk, 1)
	if self.wake != nil {
		result.Wake = self.wake.Enqueue(ctx, clientId, hint, result)
	}
	return result, nil
}

// The script's {stream id, version, seq, tok, live}.
func parseHintReply(reply *sidecar.RedisReply) (*PushHintResult, error) {
	if reply == nil || reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 5 {
		return nil, errHintReply
	}
	idReply, versionReply, seqReply, tokenReply, liveReply := reply.Replies[0], reply.Replies[1], reply.Replies[2], reply.Replies[3], reply.Replies[4]
	if idReply.Kind != sidecar.RedisReplyBulk || versionReply.Kind != sidecar.RedisReplyBulk || seqReply.Kind != sidecar.RedisReplyInteger {
		return nil, errHintReply
	}
	streamId := string(idReply.Bulk)
	if _, _, err := ParseStreamId(streamId); err != nil {
		return nil, errHintReply
	}
	version, err := ParseVersion(string(versionReply.Bulk))
	if err != nil {
		return nil, errHintReply
	}
	if seqReply.Integer <= 0 {
		return nil, errHintReply
	}
	result := &PushHintResult{
		StreamId: streamId,
		Version:  version,
		Seq:      uint64(seqReply.Integer),
	}
	switch tokenReply.Kind {
	case sidecar.RedisReplyNil:
	case sidecar.RedisReplyBulk:
		result.Token = append([]byte{}, tokenReply.Bulk...)
	default:
		return nil, errHintReply
	}
	switch liveReply.Kind {
	case sidecar.RedisReplyNil:
	case sidecar.RedisReplyBulk:
		result.Live = true
	default:
		return nil, errHintReply
	}
	return result, nil
}

// §18.7's step 3: raises clientId's ack to streamId, only while the client holds a wake token and only
// upward, for ackTimeout. Answers whether it raised. A publisher calls it on a batch's frame ack
// (PROTO-M1-08).
func RaiseHintAck(ctx context.Context, redis HintRedis, clientId connect.Id, streamId string, ackTimeout time.Duration) (bool, error) {
	if _, _, err := ParseStreamId(streamId); err != nil {
		return false, err
	}
	if ackTimeout < time.Second {
		return false, fmt.Errorf("%w: ack ttl under a second", ErrHintInvalid)
	}
	keys := []string{HintAckKey(clientId), HintTokenKey(clientId)}
	args := []string{streamId, strconv.FormatInt(int64(ackTimeout/time.Second), 10)}
	reply, err := redis.RunScript(ctx, HintAckScript, keys, args)
	if err != nil {
		return false, err
	}
	if reply == nil || reply.Kind != sidecar.RedisReplyInteger {
		return false, errHintReply
	}
	return reply.Integer == 1, nil
}
