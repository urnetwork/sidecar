package pushservice_test

// §6.8's publisher (PROTO-M1-08) on T2's FakeRedis, with the push scripts' Go twins, a fake clock and a
// fake resident send that decodes every frame as the client's dispatcher would and returns the pool
// buffers it takes. Every wait is on the fake clock or on a call the publisher makes; a real-time timer
// here only fails a test that would otherwise hang.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a test waits for the publisher before it fails. Real time, only ever a failure's bound.
const testPublisherTimeout = 10 * time.Second

// FakeRedis, telling the test each call the publisher makes, by its op or script name, once it has
// answered. A hook set in afterRange runs once, after the next XRANGE has answered and before the
// publisher sees the answer.
type testPublisherRedis struct {
	*sidecartest.FakeRedis
	calls      chan string
	afterRange atomic.Pointer[func()]
}

func (self *testPublisherRedis) record(call string) {
	select {
	case self.calls <- call:
	default:
		panic("the test's record of Redis calls is full")
	}
}

func (self *testPublisherRedis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	reply, err := self.FakeRedis.RunScript(ctx, script, keys, args)
	self.record(script.Name)
	return reply, err
}

func (self *testPublisherRedis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	value, found, err := self.FakeRedis.Get(ctx, key)
	self.record("get")
	return value, found, err
}

func (self *testPublisherRedis) HashGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	fieldValues, err := self.FakeRedis.HashGetAll(ctx, key)
	self.record("hgetall")
	return fieldValues, err
}

func (self *testPublisherRedis) StreamRange(ctx context.Context, key string, afterEntryId string, count int64) ([]*sidecar.RedisStreamEntry, error) {
	entries, err := self.FakeRedis.StreamRange(ctx, key, afterEntryId, count)
	if hook := self.afterRange.Swap(nil); hook != nil {
		(*hook)()
	}
	self.record("xrange")
	return entries, err
}

// One frame the resident was given, decoded.
type testPushMessage struct {
	envelope *protocol.Envelope
	reset    *protocol.PushReset
	hint     *protocol.PushHint
	ack      connect.AckFunction
}

// The frame as the client's dispatcher reads it: a SubprotocolMessage for 21842 around one unchunked
// NO_REPLY envelope of service 0x01.
func decodeTestPushFrame(frame *connectprotocol.Frame) (*testPushMessage, error) {
	if frame.MessageType != connectprotocol.MessageType_Subprotocol {
		return nil, fmt.Errorf("a frame of type %s", frame.MessageType)
	}
	wrapper := &connectprotocol.SubprotocolMessage{}
	if err := proto.Unmarshal(frame.MessageBytes, wrapper); err != nil {
		return nil, err
	}
	if wrapper.SubprotocolId != sidecar.SubprotocolId {
		return nil, fmt.Errorf("subprotocol %d", wrapper.SubprotocolId)
	}
	if sidecar.MaxEnvelopeByteCount < len(wrapper.MessageBytes) {
		return nil, fmt.Errorf("an envelope of %d B", len(wrapper.MessageBytes))
	}
	envelope := &protocol.Envelope{}
	if err := proto.Unmarshal(wrapper.MessageBytes, envelope); err != nil {
		return nil, err
	}
	if envelope.Version != sidecar.WireVersionMajor || envelope.Flags != sidecar.EnvelopeFlagNoReply || envelope.Chunk != nil {
		return nil, fmt.Errorf("an envelope of version %d, flags %d, chunk %v", envelope.Version, envelope.Flags, envelope.Chunk)
	}
	message := &testPushMessage{envelope: envelope}
	switch protocol.MessageType(envelope.Type) {
	case protocol.MessageType_PUSH_RESET:
		message.reset = &protocol.PushReset{}
		if err := proto.Unmarshal(envelope.Body, message.reset); err != nil {
			return nil, err
		}
	case protocol.MessageType_PUSH_HINT:
		message.hint = &protocol.PushHint{}
		if err := proto.Unmarshal(envelope.Body, message.hint); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("an envelope of type %#x", envelope.Type)
	}
	return message, nil
}

// The resident's send: decodes each frame, then takes it, returning its buffer to the pool, or refuses
// it and leaves the buffer with the publisher, by the fates planned for it. A held send waits until the
// test releases it.
type testPublisherSend struct {
	t        testing.TB
	messages chan *testPushMessage
	// a send waiting on its hold, with its frame decoded
	holding chan *testPushMessage

	stateLock sync.Mutex
	// the fates of the next sends, in order: true takes, false refuses; a send past them takes
	fates     []bool
	hold      chan struct{}
	sendCount int
}

func newTestPublisherSend(t testing.TB) *testPublisherSend {
	return &testPublisherSend{
		t:        t,
		messages: make(chan *testPushMessage, 4096),
		holding:  make(chan *testPushMessage, 16),
	}
}

// Plans the fates of the next sends, true taking and false refusing.
func (self *testPublisherSend) planSends(fates ...bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.fates = append(self.fates, fates...)
}

// Holds the next send until the returned release, which lets it go on, taking or refusing it.
func (self *testPublisherSend) holdNextSend() (release func(take bool)) {
	hold := make(chan struct{})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hold = hold
	return func(take bool) {
		self.planSends(take)
		close(hold)
	}
}

func (self *testPublisherSend) sends() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sendCount
}

func (self *testPublisherSend) send(frame *connectprotocol.Frame, ack connect.AckFunction) bool {
	message, err := decodeTestPushFrame(frame)
	if err != nil {
		self.t.Errorf("the resident got a frame no client reads: %v", err)
		return false
	}
	message.ack = ack
	var hold chan struct{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sendCount += 1
		hold, self.hold = self.hold, nil
	}()
	if hold != nil {
		self.holding <- message
		<-hold
	}
	take := true
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < len(self.fates) {
			take, self.fates = self.fates[0], self.fates[1:]
		}
	}()
	if !take {
		return false
	}
	connect.MessagePoolReturn(frame.MessageBytes)
	self.messages <- message
	return true
}

// A publisher for one client on a FakeRedis and its clock, not yet started.
type testPublisherEnv struct {
	t         *testing.T
	redis     *testPublisherRedis
	clock     *sidecartest.FakeClock
	faults    *sidecartest.FaultQueue
	writer    *pushservice.HintWriter
	settings  *pushservice.SidecarPublisherSettings
	clientId  connect.Id
	send      *testPublisherSend
	publisher *pushservice.SidecarPublisher
}

// settings nil takes the defaults. Every buffer the publisher took from the pool is back once the test
// has closed it, and nothing it did broke the pool's ownership rules.
func newTestPublisherEnv(t *testing.T, settings *pushservice.SidecarPublisherSettings) *testPublisherEnv {
	t.Helper()
	takenBefore, returnedBefore, _ := connect.MessagePoolCounts()
	violationsBefore := connect.MessagePoolViolationCount()
	t.Cleanup(func() {
		takenAfter, returnedAfter, _ := connect.MessagePoolCounts()
		if takenAfter-takenBefore != returnedAfter-returnedBefore {
			t.Errorf("pool: %d buffers taken and %d returned", takenAfter-takenBefore, returnedAfter-returnedBefore)
		}
		if connect.MessagePoolViolationCount() != violationsBefore {
			t.Errorf("pool: %d ownership violations", connect.MessagePoolViolationCount()-violationsBefore)
		}
	})
	if settings == nil {
		settings = pushservice.DefaultSidecarPublisherSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	fakeRedis := sidecartest.NewFakeRedis(t.Context(), clock, faults, nil, nil)
	t.Cleanup(fakeRedis.Close)
	sidecartest.RegisterPushScripts(fakeRedis)
	writer, err := pushservice.NewHintWriter(fakeRedis, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := pushservice.NewSidecarPublisher(settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)
	return &testPublisherEnv{
		t:         t,
		redis:     &testPublisherRedis{FakeRedis: fakeRedis, calls: make(chan string, 4096)},
		clock:     clock,
		faults:    faults,
		writer:    writer,
		settings:  settings,
		clientId:  connect.NewId(),
		send:      newTestPublisherSend(t),
		publisher: publisher,
	}
}

func (self *testPublisherEnv) start(topics []string) {
	self.publisher.Start(self.t.Context(), &pushservice.PublisherEnv{
		ClientId:  self.clientId,
		NetworkId: connect.NewId(),
		Send:      self.send.send,
		Redis:     self.redis,
		Topics:    topics,
	})
}

// Writes one hint as an owner would, with no event: the test kicks the publisher itself.
func (self *testPublisherEnv) hint(topic string, version uint64, body []byte) *pushservice.PushHintResult {
	self.t.Helper()
	result, err := self.writer.HintClient(self.t.Context(), self.clientId, &sidecar.ClientHint{Topic: topic, Version: version, Kind: 0x0A01, Body: body})
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// Waits for the publisher's coalescing window, a timer HintCoalesceTimeout from now, and moves the clock
// past it.
func (self *testPublisherEnv) passWindow() {
	self.t.Helper()
	self.passTimer(self.settings.HintCoalesceTimeout)
}

// Waits for a timer timeout from now and moves the clock past it.
func (self *testPublisherEnv) passTimer(timeout time.Duration) {
	self.t.Helper()
	self.awaitTimer(timeout)
	self.clock.Advance(timeout)
}

// Waits for a timer timeout from now, moving nothing.
func (self *testPublisherEnv) awaitTimer(timeout time.Duration) {
	self.t.Helper()
	at := self.clock.Now().Add(timeout)
	guard := time.After(testPublisherTimeout)
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-guard:
			self.t.Fatalf("no timer at %s: %v", at, pending)
		}
	}
}

// Waits for the publisher's next Redis call and fails unless it is want.
func (self *testPublisherEnv) awaitCall(want string) {
	self.t.Helper()
	select {
	case call := <-self.redis.calls:
		if call != want {
			self.t.Fatalf("the publisher called %s, want %s", call, want)
		}
	case <-time.After(testPublisherTimeout):
		self.t.Fatalf("the publisher never called %s", want)
	}
}

// Waits for a read that finds nothing past the position and leaves it idle: an XRANGE, then n.
func (self *testPublisherEnv) awaitIdleRead() {
	self.t.Helper()
	self.awaitCall("xrange")
	self.awaitCall("get")
}

func (self *testPublisherEnv) awaitMessage() *testPushMessage {
	self.t.Helper()
	select {
	case message := <-self.send.messages:
		return message
	case <-time.After(testPublisherTimeout):
		self.t.Fatal("the resident was sent nothing")
	}
	return nil
}

// Every part of one reset run, through its complete part: one epoch, never 0, every part but the last
// incomplete, and only the last part carrying an ack, and that only when the stream had a tail.
func (self *testPublisherEnv) awaitReset() []*protocol.PushReset {
	self.t.Helper()
	parts := []*protocol.PushReset{}
	for {
		message := self.awaitMessage()
		if message.reset == nil {
			self.t.Fatalf("a hint %v where a reset was due", message.hint)
		}
		if message.reset.Epoch == 0 || (0 < len(parts) && message.reset.Epoch != parts[0].Epoch) {
			self.t.Fatalf("part %d has epoch %d", len(parts), message.reset.Epoch)
		}
		if !message.reset.Complete && message.ack != nil {
			self.t.Errorf("an incomplete part carries an ack")
		}
		parts = append(parts, message.reset)
		if message.reset.Complete {
			return parts
		}
	}
}

// The next count hints, in order.
func (self *testPublisherEnv) awaitHints(count int) []*testPushMessage {
	self.t.Helper()
	messages := []*testPushMessage{}
	for range count {
		message := self.awaitMessage()
		if message.hint == nil {
			self.t.Fatalf("a reset %v where a hint was due", message.reset)
		}
		messages = append(messages, message)
	}
	return messages
}

// Fails on a frame the resident was sent and the test did not read.
func (self *testPublisherEnv) expectNoMessage() {
	self.t.Helper()
	select {
	case message := <-self.send.messages:
		self.t.Fatalf("an unexpected frame: reset %v, hint %v", message.reset, message.hint)
	default:
	}
}

// Starts the publisher and takes it through its first reset and the read after it, to idle.
func (self *testPublisherEnv) startIdle(topics []string) []*protocol.PushReset {
	self.t.Helper()
	self.start(topics)
	self.awaitCall(pushservice.HintTailScript.Name)
	self.awaitCall("hgetall")
	parts := self.awaitReset()
	self.passWindow()
	self.awaitIdleRead()
	return parts
}

// The union of a reset's parts, by topic.
func testResetVersions(t testing.TB, parts []*protocol.PushReset) map[string]uint64 {
	t.Helper()
	topicVersions := map[string]uint64{}
	for _, part := range parts {
		if pushservice.MaxResetVersionCount < len(part.Versions) {
			t.Errorf("a part of %d versions", len(part.Versions))
		}
		for _, topicVersion := range part.Versions {
			if _, seen := topicVersions[topicVersion.Topic]; seen {
				t.Errorf("%s twice in one reset", topicVersion.Topic)
			}
			topicVersions[topicVersion.Topic] = topicVersion.Version
		}
	}
	return topicVersions
}

// §6.8's parts: at most 48 versions each under one epoch, the last alone complete, sorted by topic, and
// one empty complete part for a client with nothing; at 0, 1, 48, 49 and 97 versions.
func TestPublisherResetPartsHoldAtMostFortyEightVersions(t *testing.T) {
	for _, versionCount := range []int{0, 1, 48, 49, 97} {
		func() {
			env := newTestPublisherEnv(t, nil)
			want := map[string]uint64{}
			for index := range versionCount {
				topic := sidecar.PushTopicEvs(sidecar.NewId())
				env.hint(topic, uint64(index+1)*1_000_000_000_000, nil)
				want[topic] = uint64(index+1) * 1_000_000_000_000
			}
			parts := env.startIdle(nil)
			if wantParts := max((versionCount+47)/48, 1); len(parts) != wantParts {
				t.Errorf("%d versions: %d parts, want %d", versionCount, len(parts), wantParts)
			}
			got := testResetVersions(t, parts)
			if len(got) != len(want) {
				t.Errorf("%d versions: the reset holds %d", versionCount, len(got))
			}
			for topic, version := range want {
				if got[topic] != version {
					t.Errorf("%d versions: %s at %d, want %d", versionCount, topic, got[topic], version)
				}
			}
			topics := []string{}
			for _, part := range parts {
				for _, topicVersion := range part.Versions {
					topics = append(topics, topicVersion.Topic)
				}
			}
			if !slices.IsSorted(topics) {
				t.Errorf("%d versions: the parts are not in topic order", versionCount)
			}
			env.expectNoMessage()
			if stats := env.publisher.Stats(); stats.ResetCount != 1 || stats.ResetPartCount != uint64(len(parts)) || stats.HintCount != 0 {
				t.Errorf("%d versions: stats %+v", versionCount, stats)
			}
			env.publisher.Close()
		}()
	}
}

// A hint that lands after the reset read the tail and before it read ver is in the reset, and goes out
// again as a hint after it: at least once, never lost.
func TestPublisherHintBetweenTailAndVersionsArrives(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.hint(sidecar.PushTopicTeam, 1, nil)
	// ver's read waits in the network until the test lets it land
	fired, err := env.faults.Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpRedis,
		KeyPrefix: pushservice.HintVersionsKey(env.clientId),
		Result:    sidecartest.Delay,
		Delay:     sidecartest.DelayInNetwork,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.start(nil)
	env.awaitCall(pushservice.HintTailScript.Name)
	select {
	case <-fired:
	case <-time.After(testPublisherTimeout):
		t.Fatal("the reset never read ver")
	}
	// parked: its caller waits out the fake's request timeout on the clock
	env.awaitTimer(sidecartest.DefaultFakeRedisSettings().RequestTimeout)
	between := env.hint(sidecar.PushTopicTeam, 2, []byte("between"))
	if env.redis.DeliverDelayed() != 1 {
		t.Fatal("no read of ver was waiting")
	}
	env.awaitCall("hgetall")
	parts := env.awaitReset()
	if versions := testResetVersions(t, parts); versions[sidecar.PushTopicTeam] != 2 {
		t.Errorf("the reset holds team at %d", versions[sidecar.PushTopicTeam])
	}
	env.passWindow()
	env.awaitCall("xrange")
	hints := env.awaitHints(1)
	if hint := hints[0].hint; hint.Seq != between.Seq || hint.Topic != sidecar.PushTopicTeam || hint.Version != 2 || string(hint.Hint) != "between" {
		t.Errorf("the hint after the reset is %v", hint)
	}
}

// Every hint of a topic but the batch's last of it keeps its seq and loses its bytes, so seqs run on
// with no gap; other topics keep theirs; only the batch's last frame carries an ack.
func TestPublisherCoalescesATopicKeepingSeq(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.startIdle(nil)
	env.hint(sidecar.PushTopicTeam, 1, []byte("a"))
	env.hint(sidecar.PushTopicDns, 5, []byte("d"))
	env.hint(sidecar.PushTopicTeam, 2, []byte("b"))
	env.hint(sidecar.PushTopicTeam, 3, []byte("c"))
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	messages := env.awaitHints(4)
	want := []*protocol.PushHint{
		{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 1, Kind: 0x0A01},
		{Seq: 2, Topic: sidecar.PushTopicDns, Version: 5, Kind: 0x0A01, Hint: []byte("d")},
		{Seq: 3, Topic: sidecar.PushTopicTeam, Version: 2, Kind: 0x0A01},
		{Seq: 4, Topic: sidecar.PushTopicTeam, Version: 3, Kind: 0x0A01, Hint: []byte("c")},
	}
	for index, message := range messages {
		if !proto.Equal(message.hint, want[index]) {
			t.Errorf("hint %d is %v, want %v", index, message.hint, want[index])
		}
		if (message.ack != nil) != (index == len(messages)-1) {
			t.Errorf("hint %d's ack is set: %t", index, message.ack != nil)
		}
	}
	if stats := env.publisher.Stats(); stats.HintCount != 4 || stats.CoalescedCount != 2 {
		t.Errorf("stats %+v", stats)
	}
	// the next read finds nothing past the last one sent
	env.publisher.Kick()
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
}

// A batch longer than one read is read page after page and sent in seq order.
func TestPublisherReadsEveryPageInOrder(t *testing.T) {
	settings := pushservice.DefaultSidecarPublisherSettings()
	settings.ReadHintCount = 2
	env := newTestPublisherEnv(t, settings)
	env.startIdle(nil)
	for version := uint64(1); version <= 5; version += 1 {
		env.hint(sidecar.PushTopicEvs(sidecar.NewId()), version, nil)
	}
	env.publisher.Kick()
	env.passWindow()
	for range 3 {
		env.awaitCall("xrange")
	}
	for index, message := range env.awaitHints(5) {
		if message.hint.Seq != uint64(index+1) {
			t.Errorf("hint %d has seq %d", index, message.hint.Seq)
		}
	}
}

// Hints the stream trimmed past the position never reach the client one by one: the first entry past
// it does not follow the last seq sent, so a reset goes instead, and the read after it starts at the
// new tail.
func TestPublisherTrimFallsBackToAReset(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.startIdle(nil)
	env.hint(sidecar.PushTopicDns, 1, nil)
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	if hint := env.awaitHints(1)[0].hint; hint.Seq != 1 {
		t.Fatalf("hint %v", hint)
	}
	const hintCount = 400
	for version := uint64(2); version <= hintCount+1; version += 1 {
		env.hint(sidecar.PushTopicDns, version, nil)
	}
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	parts := env.awaitReset()
	if versions := testResetVersions(t, parts); len(versions) != 1 || versions[sidecar.PushTopicDns] != hintCount+1 {
		t.Errorf("the reset holds %v", versions)
	}
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
	if stats := env.publisher.Stats(); stats.GapCount != 1 || stats.ResetCount != 2 || stats.HintCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// When the keys restart with an entry whose id is not past the last one sent, a read finds nothing,
// but n is no longer where the position left it: a reset, not silence.
func TestPublisherNMovedUnderAnEmptyReadResets(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	for version := uint64(1); version <= 3; version += 1 {
		env.hint(sidecar.PushTopicTeam, version, nil)
	}
	env.start(nil)
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	env.awaitReset()
	// within the same millisecond, the keys go and a new stream starts below the tail the reset read
	env.redis.LoseKeys(pushservice.HintTag(env.clientId))
	restarted := env.hint(sidecar.PushTopicDns, 9, nil)
	if restarted.Seq != 1 {
		t.Fatalf("n did not restart: seq %d", restarted.Seq)
	}
	env.passWindow()
	// the read finds nothing, n has moved, and a second read still finds nothing
	env.awaitIdleRead()
	env.awaitCall("xrange")
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	if versions := testResetVersions(t, env.awaitReset()); len(versions) != 1 || versions[sidecar.PushTopicDns] != 9 {
		t.Errorf("the second reset holds %v", versions)
	}
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
	if stats := env.publisher.Stats(); stats.GapCount != 1 || stats.ResetCount != 2 {
		t.Errorf("stats %+v", stats)
	}
}

// A hint written between a read that found nothing and n's read moves n, but its entry follows the
// position: the publisher reads again and sends it, with no reset.
func TestPublisherHintBetweenAnEmptyReadAndNIsNoGap(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.startIdle(nil)
	hook := func() {
		if _, err := env.writer.HintClient(context.Background(), env.clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 1, Body: []byte("t")}); err != nil {
			t.Errorf("the hint between the reads: %v", err)
		}
	}
	env.redis.afterRange.Store(&hook)
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	env.awaitCall("get")
	env.awaitCall("xrange")
	if hint := env.awaitHints(1)[0].hint; hint.Seq != 1 || hint.Version != 1 || string(hint.Hint) != "t" {
		t.Errorf("the hint is %v", hint)
	}
	env.publisher.Kick()
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
	if stats := env.publisher.Stats(); stats.GapCount != 0 || stats.ResetCount != 1 || stats.HintCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// Topics filters the reset and every hint, a family by its prefix: a hint of another topic goes as its
// seq alone, so the client's seqs run on with nothing applied.
func TestPublisherTopicsFilter(t *testing.T) {
	repoTopic := sidecar.PushTopicEvs(sidecar.NewId())
	cases := []struct {
		topics []string
		// the topics told of among team, dns and the repo's
		told []string
	}{
		{topics: []string{sidecar.PushTopicTeam}, told: []string{sidecar.PushTopicTeam}},
		{topics: []string{sidecar.PushTopicEvsPrefix}, told: []string{repoTopic}},
		{topics: nil, told: []string{sidecar.PushTopicDns, repoTopic, sidecar.PushTopicTeam}},
	}
	for _, c := range cases {
		func() {
			env := newTestPublisherEnv(t, nil)
			env.hint(sidecar.PushTopicTeam, 3, nil)
			env.hint(sidecar.PushTopicDns, 4, nil)
			env.hint(repoTopic, 5, nil)
			versions := testResetVersions(t, env.startIdle(c.topics))
			told := slices.Sorted(func(yield func(string) bool) {
				for topic := range versions {
					if !yield(topic) {
						return
					}
				}
			})
			if want := slices.Sorted(slices.Values(c.told)); !slices.Equal(told, want) {
				t.Errorf("%v: the reset holds %v, want %v", c.topics, told, want)
			}
			env.hint(sidecar.PushTopicDns, 6, []byte("d"))
			env.hint(sidecar.PushTopicTeam, 4, []byte("t"))
			env.hint(repoTopic, 7, []byte("r"))
			env.publisher.Kick()
			env.passWindow()
			env.awaitCall("xrange")
			for index, message := range env.awaitHints(3) {
				hint := message.hint
				if hint.Seq != uint64(4+index) {
					t.Errorf("%v: hint %d has seq %d", c.topics, index, hint.Seq)
				}
				if hint.Topic == "" {
					if slices.Contains(c.told, []string{sidecar.PushTopicDns, sidecar.PushTopicTeam, repoTopic}[index]) || hint.Version != 0 || len(hint.Hint) != 0 || hint.Kind != 0 {
						t.Errorf("%v: hint %d went as its seq alone: %v", c.topics, index, hint)
					}
				} else if !slices.Contains(c.told, hint.Topic) || len(hint.Hint) != 1 {
					t.Errorf("%v: hint %d is %v", c.topics, index, hint)
				}
			}
			env.publisher.Close()
		}()
	}
}

// A batch past QueueByteCount is dropped for a reset, which says the same in one part: what the
// publisher holds stays bounded however far behind the client is.
func TestPublisherBackpressureResetsRatherThanGrows(t *testing.T) {
	settings := pushservice.DefaultSidecarPublisherSettings()
	settings.QueueByteCount = 4096
	env := newTestPublisherEnv(t, settings)
	env.startIdle(nil)
	body := []byte(strings.Repeat("h", pushservice.MaxHintByteCount))
	for version := uint64(1); version <= 20; version += 1 {
		env.hint(sidecar.PushTopicTeam, version, body)
	}
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	if versions := testResetVersions(t, env.awaitReset()); len(versions) != 1 || versions[sidecar.PushTopicTeam] != 20 {
		t.Errorf("the reset holds %v", versions)
	}
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
	if stats := env.publisher.Stats(); stats.OverflowCount != 1 || stats.HintCount != 0 || stats.ResetCount != 2 {
		t.Errorf("stats %+v", stats)
	}
}

// A refused send leaves the buffer with the publisher, which returns it, waits RetryMinInterval and
// sends a reset; the pool balances once the test closes (the env's cleanup).
func TestPublisherRefusedSendReturnsTheBufferAndResets(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.hint(sidecar.PushTopicTeam, 1, nil)
	env.send.planSends(false)
	env.start(nil)
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	env.passTimer(env.settings.RetryMinInterval)
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	env.awaitReset()
	env.passWindow()
	env.awaitIdleRead()

	// a batch refused at its second frame: the first went, the rest go in the reset after the wait
	env.hint(sidecar.PushTopicTeam, 2, nil)
	env.hint(sidecar.PushTopicTeam, 3, nil)
	env.send.planSends(true, false)
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	if hint := env.awaitHints(1)[0].hint; hint.Seq != 2 {
		t.Errorf("the first hint is %v", hint)
	}
	env.passTimer(env.settings.RetryMinInterval)
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	if versions := testResetVersions(t, env.awaitReset()); versions[sidecar.PushTopicTeam] != 3 {
		t.Errorf("the reset holds %v", versions)
	}
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
	if stats := env.publisher.Stats(); stats.SendRefusedCount != 2 || env.send.sends() != 5 {
		t.Errorf("stats %+v, %d sends", stats, env.send.sends())
	}
}

// One ack script a batch, on the batch's last frame's ack, raising {scp_<C>}ack to the batch's last
// stream id while tok exists; an ack that failed raises nothing.
func TestPublisherAckScriptOncePerBatch(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	if err := env.redis.Set(t.Context(), pushservice.HintTokenKey(env.clientId), []byte("token"), 0); err != nil {
		t.Fatal(err)
	}
	env.startIdle(nil)
	ackCount := func() int {
		return env.redis.OpCounts()["script:"+pushservice.HintAckScript.Name]
	}
	storedAck := func() string {
		value, _, err := env.redis.Get(t.Context(), pushservice.HintAckKey(env.clientId))
		env.awaitCall("get")
		if err != nil {
			t.Fatal(err)
		}
		return string(value)
	}

	results := []*pushservice.PushHintResult{}
	for version := uint64(1); version <= 3; version += 1 {
		results = append(results, env.hint(sidecar.PushTopicTeam, version, nil))
	}
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	messages := env.awaitHints(3)
	// a failed ack raises nothing
	messages[2].ack(errors.New("ack timeout"))
	messages[2].ack(nil)
	env.awaitCall(pushservice.HintAckScript.Name)
	if ackCount() != 1 || storedAck() != results[2].StreamId {
		t.Errorf("after one batch: %d scripts, ack %q, want %s", ackCount(), storedAck(), results[2].StreamId)
	}

	results = results[:0]
	for version := uint64(4); version <= 5; version += 1 {
		results = append(results, env.hint(sidecar.PushTopicTeam, version, nil))
	}
	env.publisher.Kick()
	env.passWindow()
	env.awaitCall("xrange")
	messages = env.awaitHints(2)
	messages[1].ack(nil)
	env.awaitCall(pushservice.HintAckScript.Name)
	if ackCount() != 2 || storedAck() != results[1].StreamId {
		t.Errorf("after two batches: %d scripts, ack %q, want %s", ackCount(), storedAck(), results[1].StreamId)
	}
	if stats := env.publisher.Stats(); stats.AckCount != 2 || stats.AckRaisedCount != 2 {
		t.Errorf("stats %+v", stats)
	}
}

// Resets queue up to PendingResetCount, so three Resets in one window send one; each run's epoch is
// above the last's.
func TestPublisherQueuesAtMostPendingResetCount(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.hint(sidecar.PushTopicTeam, 1, nil)
	first := env.startIdle(nil)
	env.publisher.Kick()
	// the window is open: the run waits on it while the Resets queue
	env.awaitTimer(env.settings.HintCoalesceTimeout)
	for range 3 {
		env.publisher.Reset()
	}
	env.clock.Advance(env.settings.HintCoalesceTimeout)
	env.awaitIdleRead()
	env.awaitCall(pushservice.HintTailScript.Name)
	env.awaitCall("hgetall")
	second := env.awaitReset()
	if second[0].Epoch <= first[0].Epoch {
		t.Errorf("the second run's epoch %d is not above the first's %d", second[0].Epoch, first[0].Epoch)
	}
	env.passWindow()
	env.awaitIdleRead()
	env.expectNoMessage()
	if stats := env.publisher.Stats(); stats.ResetCount != 2 {
		t.Errorf("stats %+v", stats)
	}
}

// Close while a send holds a frame waits for the send, which the resident ends by closing its client,
// and the run sends nothing after; the refused frame's buffer is back in the pool (the env's cleanup).
func TestPublisherCloseWhileSendBlocksJoins(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.hint(sidecar.PushTopicTeam, 1, nil)
	release := env.send.holdNextSend()
	env.start(nil)
	select {
	case <-env.send.holding:
	case <-time.After(testPublisherTimeout):
		t.Fatal("no send")
	}
	closed := make(chan struct{})
	go func() {
		env.publisher.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a send held the run")
	default:
	}
	release(false)
	select {
	case <-closed:
	case <-time.After(testPublisherTimeout):
		t.Fatal("Close did not return once the send did")
	}
	if sends := env.send.sends(); sends != 1 {
		t.Errorf("%d sends", sends)
	}
	env.expectNoMessage()
}

// Settings a publisher cannot run on are refused; an env with no Send or Redis ends the publisher at
// once, and Close after it returns.
func TestPublisherRefusesWhatItCannotRunOn(t *testing.T) {
	for _, change := range []func(settings *pushservice.SidecarPublisherSettings){
		func(settings *pushservice.SidecarPublisherSettings) { settings.HintCoalesceTimeout = 0 },
		func(settings *pushservice.SidecarPublisherSettings) { settings.PendingResetCount = 0 },
		func(settings *pushservice.SidecarPublisherSettings) { settings.QueueByteCount = 1024 },
		func(settings *pushservice.SidecarPublisherSettings) { settings.ReadHintCount = 0 },
		func(settings *pushservice.SidecarPublisherSettings) { settings.AckTimeout = time.Millisecond },
		func(settings *pushservice.SidecarPublisherSettings) { settings.RetryMaxInterval = time.Millisecond },
	} {
		settings := pushservice.DefaultSidecarPublisherSettings()
		change(settings)
		if _, err := pushservice.NewSidecarPublisher(settings, nil); err == nil {
			t.Errorf("settings %+v were taken", settings)
		}
	}
	publisher, err := pushservice.NewSidecarPublisher(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	publisher.Start(t.Context(), &pushservice.PublisherEnv{ClientId: connect.NewId()})
	publisher.Close()
	// a Close before Start, and a Start after it, run nothing
	unstarted, err := pushservice.NewSidecarPublisher(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	unstarted.Close()
	unstarted.Start(t.Context(), &pushservice.PublisherEnv{ClientId: connect.NewId(), Send: func(frame *connectprotocol.Frame, ack connect.AckFunction) bool {
		t.Error("a closed publisher sent")
		return false
	}, Redis: sidecartest.NewFakeRedis(t.Context(), nil, nil, nil, nil)})
	unstarted.Close()
}
