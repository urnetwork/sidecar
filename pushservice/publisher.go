// §6.8's resident publisher (D-PROTO-5): what the resident of a sidecar's client runs to tell it, from
// ControlId, what the client's owners hinted. Server-only, as this package is (owner decision 104):
// server/connect hosts one per marked client behind EnableSidecarPush, with the resident's send and
// server's Redis in its env, and the exchange's one shared key-event subscriber kicks it.
//
// A publisher starts with a reset. It reads the hint stream's tail first and ver second, so a hint that
// lands between the two reads is in both and repeats rather than vanishes, which a client ignores. It
// sends ver's topics, filtered to Topics, as PushReset parts of at most 48 versions under one epoch,
// unique to the run, the last complete (D-PROTO-20). Then each event on the client's n, which reaches it
// as a Kick, has it wait HintCoalesceTimeout, read the stream past the last entry it sent, and send the
// entries in seq order as PushHints: every hint of a topic but the batch's last of it keeps its seq and
// loses its bytes, so the client sees no gap. A topic Topics leaves out goes as its seq alone, which a
// client counts and applies nothing from.
//
// Whatever shows the stream moved on without it sends a reset instead of the batch: a first entry whose
// seq does not follow the last one sent, which a trim or the keys' hourly restart leaves (reading 5), an
// n that moved while a read and the read after it found nothing, which a stream recreated below the
// last id leaves (one read again tells it from a hint written between the read and n's), or an entry
// that does not parse. So does a batch past QueueByteCount, so a client far behind costs a reset,
// never a queue that grows; so does a send the resident refused, after a wait; and so does Reset. A
// reset is always followed by a read, so a hint that landed before the resident's listener was there
// still goes out.
//
// Every frame is a hint, never content (R-PROTO-8). A batch goes with connect's frame ack on its last
// frame, and that ack raises {scp_<C>}ack to the batch's last stream id while tok exists (§18.7's step
// 3; a reset's last part acks the tail it read): a frame ack is the client's connect stack, not its
// application, and feeds only wake suppression (R-PROTO-10). {scp_<C>}live's refresh is PROTO-M8-01's.
//
// One goroutine runs a publisher from Start until Close or its context ends. It waits on the clock and
// never spins: one read a coalescing window, a doubling wait after a Redis error or a refused send, and
// a lost ack raise is left to the next batch's. Kick, Reset and Close are safe for concurrent use, and
// Kick and Reset never block.

package pushservice

import (
	"context"
	"errors"
	mathrand "math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The stream moved on without the publisher: a first entry whose seq does not follow the last one
	// sent, an n that moved while two reads found nothing, or an entry that does not parse.
	errPublisherGap = errors.New("sidecar publisher: the hint stream moved past the last entry sent")
	// A batch past QueueByteCount.
	errPublisherOverflow = errors.New("sidecar publisher: a batch past its bytes")
	// A frame the resident's send refused, or one that could not be built.
	errPublisherSendRefused = errors.New("sidecar publisher: send refused")
)

// §6.8's PublisherEnv: what a resident gives its publisher.
type PublisherEnv struct {
	// The client the publisher tells, whose slot {scp_<C>} it reads.
	ClientId connect.Id
	// The client's network, which the resident accounts the publisher to.
	NetworkId connect.Id
	// The resident's ControlId send with connect's frame ack (server/connect/resident.go's
	// sendPublisherFrame). Takes on success: a true return takes the frame's pool buffer, and on false the
	// publisher still owns it and returns it. It may block, as connect's sends do, until the resident's
	// client takes the frame or closes.
	Send func(frame *connectprotocol.Frame, ack connect.AckFunction) bool
	// GET, HGETALL, XRANGE and the tail and ack scripts.
	Redis PublisherRedis
	// The topics the client is told: empty for all of them, a sidecar's client; ["team"] for an
	// acl_enforcing device client (§18.6). An entry ending in ':' names a family, gkm: or evs:.
	Topics []string
}

// What a publisher has counted.
type SidecarPublisherStats struct {
	// resets sent whole, and their parts
	ResetCount     uint64
	ResetPartCount uint64
	// hints sent, and those of them sent without their bytes
	HintCount      uint64
	CoalescedCount uint64
	// reads that found the stream moved on, and batches past QueueByteCount: each sent a reset instead
	GapCount      uint64
	OverflowCount uint64
	// frames the resident's send refused
	SendRefusedCount uint64
	// Redis calls that failed
	RedisErrorCount uint64
	// ack scripts run, and those that raised ack
	AckCount       uint64
	AckRaisedCount uint64
}

// Running totals behind SidecarPublisherStats.
type sidecarPublisherStats struct {
	resetCount       atomic.Uint64
	resetPartCount   atomic.Uint64
	hintCount        atomic.Uint64
	coalescedCount   atomic.Uint64
	gapCount         atomic.Uint64
	overflowCount    atomic.Uint64
	sendRefusedCount atomic.Uint64
	redisErrorCount  atomic.Uint64
	ackCount         atomic.Uint64
	ackRaisedCount   atomic.Uint64
}

// §6.8's SidecarPublisher. NewSidecarPublisher makes one, Start runs it once, and Close ends it.
type SidecarPublisher struct {
	settings *SidecarPublisherSettings
	clock    sidecar.Clock

	// an event on n, held by one, so kicks in a window read as one
	kick chan struct{}
	// a queued reset or an acked batch, held by one
	signal chan struct{}
	// closed when the run ends, or at Start when there is nothing to run
	done chan struct{}

	stateLock sync.Mutex
	started   bool
	closed    bool
	cancel    context.CancelFunc
	// resets Reset queued, at most PendingResetCount
	pendingResetCount int
	// the highest acked batch's last stream id not yet raised, empty for none
	ackStreamId string

	stats sidecarPublisherStats
}

// A publisher on settings, nil being the defaults, waiting on clock, nil being real time. It runs once
// Start gives it its client.
func NewSidecarPublisher(settings *SidecarPublisherSettings, clock sidecar.Clock) (*SidecarPublisher, error) {
	if settings == nil {
		settings = DefaultSidecarPublisherSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &SidecarPublisher{
		settings: settings,
		clock:    clock,
		kick:     make(chan struct{}, 1),
		signal:   make(chan struct{}, 1),
		done:     make(chan struct{}),
	}, nil
}

// Runs the publisher for env's client until ctx ends or Close. A second Start, or one after Close, does
// nothing, and so does an env with no Send or Redis, which leaves the publisher ended.
func (self *SidecarPublisher) Start(ctx context.Context, env *PublisherEnv) {
	var runCtx context.Context
	start := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.started || self.closed {
			return false
		}
		self.started = true
		runCtx, self.cancel = context.WithCancel(ctx)
		return true
	}()
	if !start {
		return
	}
	if env == nil || env.Send == nil || env.Redis == nil {
		close(self.done)
		return
	}
	run := &publisherRun{
		publisher:  self,
		ctx:        runCtx,
		env:        &PublisherEnv{ClientId: env.ClientId, NetworkId: env.NetworkId, Send: env.Send, Redis: env.Redis, Topics: slices.Clone(env.Topics)},
		barrierKey: env.ClientId.String(),
	}
	go func() {
		defer close(self.done)
		run.run()
	}()
}

// An event on the client's n: the hint stream has something new. Never blocks, so the key-event
// subscriber's goroutine may call it.
func (self *SidecarPublisher) Kick() {
	select {
	case self.kick <- struct{}{}:
	default:
	}
}

// Queues a reset, at most PendingResetCount of them. Never blocks.
func (self *SidecarPublisher) Reset() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.pendingResetCount < self.settings.PendingResetCount {
			self.pendingResetCount += 1
		}
	}()
	self.wake()
}

// Ends the run and waits for it: a frame Send holds when Close comes is the resident's to release, by
// taking it or closing its client. Safe to call more than once, and before Start.
func (self *SidecarPublisher) Close() {
	var cancel context.CancelFunc
	started := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		cancel, started = self.cancel, self.started
	}()
	if cancel != nil {
		cancel()
	}
	if started {
		<-self.done
	}
}

// What the publisher has counted.
func (self *SidecarPublisher) Stats() SidecarPublisherStats {
	return SidecarPublisherStats{
		ResetCount:       self.stats.resetCount.Load(),
		ResetPartCount:   self.stats.resetPartCount.Load(),
		HintCount:        self.stats.hintCount.Load(),
		CoalescedCount:   self.stats.coalescedCount.Load(),
		GapCount:         self.stats.gapCount.Load(),
		OverflowCount:    self.stats.overflowCount.Load(),
		SendRefusedCount: self.stats.sendRefusedCount.Load(),
		RedisErrorCount:  self.stats.redisErrorCount.Load(),
		AckCount:         self.stats.ackCount.Load(),
		AckRaisedCount:   self.stats.ackRaisedCount.Load(),
	}
}

func (self *SidecarPublisher) wake() {
	select {
	case self.signal <- struct{}{}:
	default:
	}
}

// Takes one queued reset, if any.
func (self *SidecarPublisher) takeReset() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pendingResetCount == 0 {
		return false
	}
	self.pendingResetCount -= 1
	return true
}

// A batch's last frame was acked: its last stream id is raised at the run's next turn. Called on
// connect's goroutine, so it only notes the id.
func (self *SidecarPublisher) noteAck(streamId string) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.ackStreamId != "" {
			if comparison, err := CompareStreamId(streamId, self.ackStreamId); err != nil || comparison <= 0 {
				return
			}
		}
		self.ackStreamId = streamId
	}()
	self.wake()
}

// Takes the acked stream id waiting to be raised, empty for none.
func (self *SidecarPublisher) takeAck() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	streamId := self.ackStreamId
	self.ackStreamId = ""
	return streamId
}

// The last entry a run sent, or the tail its last reset read.
type publisherPosition struct {
	// "0-0" while the stream was absent at the reset
	streamId string
	seq      uint64
	// false when the entry's seq did not parse: the next entry's sets it, as a reset does a client's
	hasSeq bool
}

// One hint of a batch, with its entry's id.
type publisherHint struct {
	streamId string
	hint     *protocol.PushHint
}

// One Start's state, which only the run's goroutine touches.
type publisherRun struct {
	publisher  *SidecarPublisher
	ctx        context.Context
	env        *PublisherEnv
	barrierKey string

	position    publisherPosition
	hasPosition bool
	// the last reset's epoch, so the next is above it
	lastEpoch uint64
	// the last stream id an ack script ran for
	raisedAckStreamId string
	// the wait after the last failure, zero after a success
	retryInterval time.Duration
}

func (self *publisherRun) run() {
	settings := self.publisher.settings
	// a read is due: the window first, then the stream past the position
	readDue := false
	for {
		if self.ctx.Err() != nil {
			return
		}
		self.raiseAck()
		if self.publisher.takeReset() || !self.hasPosition {
			if err := self.sendReset(); err != nil {
				self.hasPosition = false
				if !self.backoff() {
					return
				}
				continue
			}
			self.retryInterval = 0
			readDue = true
		}
		if readDue {
			select {
			case <-self.ctx.Done():
				return
			case <-self.publisher.clock.After(settings.HintCoalesceTimeout):
			}
			// this read takes every hint whose event came in the window
			select {
			case <-self.publisher.kick:
			default:
			}
			readDue = false
			err := self.sendHints()
			switch {
			case err == nil:
				self.retryInterval = 0
			case errors.Is(err, errPublisherGap), errors.Is(err, errPublisherOverflow):
				self.hasPosition = false
			case errors.Is(err, errPublisherSendRefused):
				self.hasPosition = false
				if !self.backoff() {
					return
				}
			default:
				// Redis did not answer: read again after the wait
				readDue = true
				if !self.backoff() {
					return
				}
			}
			continue
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.publisher.kick:
			readDue = true
		case <-self.publisher.signal:
		}
	}
}

// Waits the next retry interval, doubling it up to RetryMaxInterval. False once the run has ended.
func (self *publisherRun) backoff() bool {
	settings := self.publisher.settings
	if self.retryInterval <= 0 {
		self.retryInterval = settings.RetryMinInterval
	} else {
		self.retryInterval = min(2*self.retryInterval, settings.RetryMaxInterval)
	}
	select {
	case <-self.ctx.Done():
		return false
	case <-self.publisher.clock.After(self.retryInterval):
		return true
	}
}

// Whether the client is told of topic: a registry topic Topics admits.
func (self *publisherRun) topicAdmitted(topic string) bool {
	if sidecar.PushTopicClassOf(topic) == sidecar.PushTopicUnknown {
		return false
	}
	if len(self.env.Topics) == 0 {
		return true
	}
	for _, admitted := range self.env.Topics {
		if admitted == topic || (strings.HasSuffix(admitted, ":") && strings.HasPrefix(topic, admitted)) {
			return true
		}
	}
	return false
}

// An epoch above the last, from the clock's milliseconds while they rise (plan-PROTO-small-readings
// reading 5), so no two runs of this publisher share one, and never 0.
func (self *publisherRun) nextEpoch() uint64 {
	epoch := uint64(max(self.publisher.clock.Now().UnixMilli(), 0))
	if epoch <= self.lastEpoch {
		epoch = self.lastEpoch + 1
	}
	self.lastEpoch = epoch
	return epoch
}

// Sends one push message, nil ack for none. A refused send's buffer is returned here.
func (self *publisherRun) sendFrame(messageType protocol.MessageType, message proto.Message, ack connect.AckFunction) error {
	frame, err := PushFrame(messageType, message, mathrand.Uint64())
	if err != nil {
		self.publisher.stats.sendRefusedCount.Add(1)
		return errors.Join(errPublisherSendRefused, err)
	}
	if !self.env.Send(frame, ack) {
		connect.MessagePoolReturn(frame.MessageBytes)
		self.publisher.stats.sendRefusedCount.Add(1)
		return errPublisherSendRefused
	}
	return nil
}

// The ack of a batch whose last entry is streamId.
func (self *publisherRun) ackFunction(streamId string) connect.AckFunction {
	publisher := self.publisher
	return func(err error) {
		if err == nil {
			publisher.noteAck(streamId)
		}
	}
}

// The reset of the file header: the tail, then ver, then the parts. On success the run's position is
// the tail it read.
func (self *publisherRun) sendReset() error {
	redis := self.env.Redis
	testHookBarrier("pushservice.publisher.tail.before", self.barrierKey)
	tail, found, err := ReadHintTail(self.ctx, redis, self.env.ClientId)
	testHookBarrier("pushservice.publisher.tail.after", self.barrierKey)
	if err != nil {
		self.publisher.stats.redisErrorCount.Add(1)
		return err
	}
	fieldValues, err := redis.HashGetAll(self.ctx, HintVersionsKey(self.env.ClientId))
	if err != nil {
		self.publisher.stats.redisErrorCount.Add(1)
		return err
	}
	topicVersions := ParseHintVersions(fieldValues)
	topics := make([]string, 0, len(topicVersions))
	for topic := range topicVersions {
		if self.topicAdmitted(topic) {
			topics = append(topics, topic)
		}
	}
	slices.Sort(topics)

	position := publisherPosition{streamId: "0-0", hasSeq: true}
	if found {
		position = publisherPosition{streamId: tail.Id}
		if hint, err := ParseHintEntry(tail); err == nil {
			position.seq, position.hasSeq = hint.Seq, true
		}
	}

	epoch := self.nextEpoch()
	partCount := max((len(topics)+MaxResetVersionCount-1)/MaxResetVersionCount, 1)
	for part := range partCount {
		partTopics := topics[part*MaxResetVersionCount : min((part+1)*MaxResetVersionCount, len(topics))]
		versions := make([]*protocol.TopicVersion, 0, len(partTopics))
		for _, topic := range partTopics {
			versions = append(versions, &protocol.TopicVersion{Topic: topic, Version: topicVersions[topic]})
		}
		last := part == partCount-1
		var ack connect.AckFunction
		if last && found {
			ack = self.ackFunction(tail.Id)
		}
		reset := &protocol.PushReset{Epoch: epoch, Versions: versions, Complete: last}
		if err := self.sendFrame(protocol.MessageType_PUSH_RESET, reset, ack); err != nil {
			return err
		}
		self.publisher.stats.resetPartCount.Add(1)
	}
	self.publisher.stats.resetCount.Add(1)
	self.position, self.hasPosition = position, true
	return nil
}

// Reads the stream past the position and sends what it holds as one batch, or answers why a reset must
// go instead. The position follows each frame sent.
func (self *publisherRun) sendHints() error {
	batch, err := self.readBatch()
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		// nothing past the position: n must still be where the position left it. A hint written between
		// the read and n's read moves n too, so a moved n reads again, and only a stream that still shows
		// nothing past the position was made again below the last id sent
		moved, err := self.seqMoved()
		if err != nil || !moved {
			return err
		}
		if batch, err = self.readBatch(); err != nil {
			return err
		}
		if len(batch) == 0 {
			self.publisher.stats.gapCount.Add(1)
			return errPublisherGap
		}
	}

	// every hint of a topic but the batch's last of it loses its bytes; a topic the client is not told
	// goes as its seq alone
	lastTopicIndexes := map[string]int{}
	for index, item := range batch {
		lastTopicIndexes[item.hint.Topic] = index
	}
	for index, item := range batch {
		switch {
		case !self.topicAdmitted(item.hint.Topic):
			item.hint = &protocol.PushHint{Seq: item.hint.Seq}
		case lastTopicIndexes[item.hint.Topic] != index || MaxHintByteCount < len(item.hint.Hint):
			if 0 < len(item.hint.Hint) {
				item.hint.Hint = nil
				self.publisher.stats.coalescedCount.Add(1)
			}
		}
	}

	for index, item := range batch {
		var ack connect.AckFunction
		if index == len(batch)-1 {
			ack = self.ackFunction(item.streamId)
		}
		if err := self.sendFrame(protocol.MessageType_PUSH_HINT, item.hint, ack); err != nil {
			return err
		}
		self.publisher.stats.hintCount.Add(1)
		self.position = publisherPosition{streamId: item.streamId, seq: item.hint.Seq, hasSeq: true}
	}
	return nil
}

// Every entry past the position, read page after page, or why a reset must go instead: a first entry
// whose seq does not follow the position's, an entry that does not parse, or more than QueueByteCount.
func (self *publisherRun) readBatch() ([]*publisherHint, error) {
	settings := self.publisher.settings
	streamKey := HintStreamKey(self.env.ClientId)
	batch := []*publisherHint{}
	byteCount := int64(0)
	after := self.position.streamId
	for {
		testHookBarrier("pushservice.publisher.read.before", self.barrierKey)
		entries, err := self.env.Redis.StreamRange(self.ctx, streamKey, after, settings.ReadHintCount)
		testHookBarrier("pushservice.publisher.read.after", self.barrierKey)
		if err != nil {
			self.publisher.stats.redisErrorCount.Add(1)
			return nil, err
		}
		for _, entry := range entries {
			hint, err := ParseHintEntry(entry)
			if err != nil {
				self.publisher.stats.gapCount.Add(1)
				return nil, errPublisherGap
			}
			if len(batch) == 0 && self.position.hasSeq && hint.Seq != self.position.seq+1 {
				// trimmed past the position, or n restarted with the keys' hour
				self.publisher.stats.gapCount.Add(1)
				return nil, errPublisherGap
			}
			byteCount += int64(proto.Size(hint))
			if settings.QueueByteCount < byteCount {
				self.publisher.stats.overflowCount.Add(1)
				return nil, errPublisherOverflow
			}
			batch = append(batch, &publisherHint{streamId: entry.Id, hint: hint})
		}
		if int64(len(entries)) < settings.ReadHintCount {
			return batch, nil
		}
		after = entries[len(entries)-1].Id
	}
}

// Whether n is no longer the position's seq. An absent n, the keys gone with their hour, has not moved:
// the next hint makes them again, and its first entry's seq shows the restart.
func (self *publisherRun) seqMoved() (bool, error) {
	value, found, err := self.env.Redis.Get(self.ctx, HintSeqKey(self.env.ClientId))
	if err != nil {
		self.publisher.stats.redisErrorCount.Add(1)
		return false, err
	}
	if !found || !self.position.hasSeq {
		return false, nil
	}
	seq, err := strconv.ParseUint(string(value), 10, 64)
	return err != nil || seq != self.position.seq, nil
}

// Raises ack to the highest acked batch end, once each and only upward. A script that fails is not
// retried: the next batch's ack raises past it, and until then a wake may go that a raise would have
// spared.
func (self *publisherRun) raiseAck() {
	streamId := self.publisher.takeAck()
	if streamId == "" {
		return
	}
	if self.raisedAckStreamId != "" {
		if comparison, err := CompareStreamId(streamId, self.raisedAckStreamId); err != nil || comparison <= 0 {
			return
		}
	}
	testHookBarrier("pushservice.publisher.ack.before", self.barrierKey)
	raised, err := RaiseHintAck(self.ctx, self.env.Redis, self.env.ClientId, streamId, self.publisher.settings.AckTimeout)
	testHookBarrier("pushservice.publisher.ack.after", self.barrierKey)
	self.publisher.stats.ackCount.Add(1)
	if err != nil {
		self.publisher.stats.redisErrorCount.Add(1)
		return
	}
	if raised {
		self.publisher.stats.ackRaisedCount.Add(1)
	}
	self.raisedAckStreamId = streamId
}
