//go:build !js

// §6.8's client machine (push_state.go) on every leg but js, whose tests cannot open files: a partial
// reset applies nothing, a run's union applies once complete, a new epoch or a hint abandons a run, seq
// gaps and restarts send the client to versions, stale versions are ignored, a reset keeps what it
// omits, a durable fall alarms until reconciled while a clock's fall is adopted, evs-sized versions stay
// exact, versions outlive a restart, and the feed resyncs at start, on demand and hourly.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A SidecarStore in memory, every leg's.
type testPushStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
}

func newTestPushStore() *testPushStore {
	return &testPushStore{files: map[string][]byte{}}
}

func (self *testPushStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.files[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(value))), nil
}

type testPushStoreWriter struct {
	store  *testPushStore
	name   string
	buffer bytes.Buffer
}

func (self *testPushStoreWriter) Write(data []byte) (int, error) {
	return self.buffer.Write(data)
}

func (self *testPushStoreWriter) Commit() error {
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	self.store.files[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *testPushStoreWriter) Close() error {
	return nil
}

func (self *testPushStore) Create(name string) (SidecarStoreWriter, error) {
	return &testPushStoreWriter{store: self, name: name}, nil
}

func (self *testPushStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

func (self *testPushStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name, value := range self.files {
		if strings.HasPrefix(name, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: int64(len(value))})
		}
	}
	return entries, nil
}

func (self *testPushStore) Directory(name string, class string) (SidecarStore, error) {
	return self, nil
}

// Waits for one value, failing after 30 s, so a broken feed fails with a message: no outcome depends on
// the wait.
func testPushAwait[T any](t testing.TB, values <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(30 * time.Second):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

func testPushMachine() *pushMachine {
	return newPushMachine(DefaultPushClientSettings(), nil)
}

func testPushPart(epoch uint64, complete bool, topicVersions ...any) *protocol.PushReset {
	part := &protocol.PushReset{Epoch: epoch, Complete: complete}
	for i := 0; i < len(topicVersions); i += 2 {
		part.Versions = append(part.Versions, &protocol.TopicVersion{Topic: topicVersions[i].(string), Version: uint64(topicVersions[i+1].(int))})
	}
	return part
}

func testPushHint(seq uint64, topic string, version uint64) *protocol.PushHint {
	return &protocol.PushHint{Seq: seq, Topic: topic, Version: version, Kind: 0x1201, Hint: []byte{1}}
}

// The topics the notices raised, in order.
func testNoticeTopics(action *pushAction) []string {
	topics := []string{}
	for _, notice := range action.notices {
		topics = append(topics, notice.Topic)
	}
	return topics
}

// D-PROTO-20: a complete=false part followed by a dropped tail applies nothing; the hint that comes
// next abandons the run and asks for versions, whose run then applies.
func TestPushPartialResetAppliesNothing(t *testing.T) {
	machine := testPushMachine()
	action := machine.resetPart(testPushPart(7, false, PushTopicTeam, 4, PushTopicDns, 9))
	if action.changed || action.refetchVersions || len(action.notices) != 0 || len(machine.topicVersions) != 0 {
		t.Fatalf("a partial part applied: %+v", action)
	}
	action = machine.hint(testPushHint(1, PushTopicSock, 3))
	if !action.refetchVersions || machine.runOpen {
		t.Fatalf("a hint during a run: %+v", action)
	}
	if machine.topicVersions[PushTopicTeam] != 0 {
		t.Errorf("the abandoned run's team applied")
	}
	action = machine.reset(map[string]uint64{PushTopicTeam: 4, PushTopicDns: 9})
	if machine.topicVersions[PushTopicTeam] != 4 || machine.topicVersions[PushTopicDns] != 9 || !action.changed {
		t.Errorf("versions did not apply: %v", machine.topicVersions)
	}
}

// A run's parts under one epoch apply as their union once a part says complete; a part under another
// epoch abandons the run and asks for versions.
func TestPushResetRunAppliesItsUnion(t *testing.T) {
	machine := testPushMachine()
	machine.resetPart(testPushPart(7, false, PushTopicTeam, 4))
	action := machine.resetPart(testPushPart(7, true, PushTopicDns, 9))
	if machine.topicVersions[PushTopicTeam] != 4 || machine.topicVersions[PushTopicDns] != 9 {
		t.Fatalf("union %v", machine.topicVersions)
	}
	if topics := testNoticeTopics(action); !slices.Equal(topics, []string{PushTopicDns, PushTopicTeam, PushTopicCore}) {
		t.Errorf("notices %v", topics)
	}

	machine.resetPart(testPushPart(8, false, PushTopicTeam, 5))
	action = machine.resetPart(testPushPart(9, true, PushTopicTeam, 6))
	if !action.refetchVersions || machine.topicVersions[PushTopicTeam] != 4 || machine.runOpen {
		t.Errorf("a new epoch: %+v, team %d", action, machine.topicVersions[PushTopicTeam])
	}
}

// seq must follow on: a gap, a restart at 1 and a duplicate each ask for versions; a reset clears the
// baseline; a version at or below the one held is ignored.
func TestPushSeqGapsAndStaleVersions(t *testing.T) {
	machine := testPushMachine()
	if action := machine.hint(testPushHint(5, PushTopicSock, 10)); action.refetchVersions || len(action.notices) != 1 {
		t.Fatalf("the first hint sets the baseline: %+v", action)
	}
	if action := machine.hint(testPushHint(6, PushTopicSock, 11)); action.refetchVersions || len(action.notices) != 1 {
		t.Errorf("the next seq: %+v", action)
	}
	if action := machine.hint(testPushHint(8, PushTopicSock, 12)); !action.refetchVersions || len(action.notices) != 1 {
		t.Errorf("a gap: %+v", action)
	}
	if action := machine.hint(testPushHint(1, PushTopicSock, 13)); !action.refetchVersions {
		t.Errorf("a restart at 1: %+v", action)
	}
	if action := machine.hint(testPushHint(1, PushTopicSock, 13)); !action.refetchVersions || len(action.notices) != 0 {
		t.Errorf("a duplicate: %+v", action)
	}
	if action := machine.hint(testPushHint(2, PushTopicSock, 7)); len(action.notices) != 0 || machine.topicVersions[PushTopicSock] != 13 {
		t.Errorf("a stale version: %+v", action)
	}
	machine.reset(map[string]uint64{})
	if action := machine.hint(testPushHint(40, PushTopicSock, 14)); action.refetchVersions {
		t.Errorf("after a reset any seq sets the baseline: %+v", action)
	}
	if action := machine.hint(testPushHint(41, "no-such-topic", 1)); action.changed || len(action.notices) != 0 {
		t.Errorf("an unknown topic: %+v", action)
	}
}

// A reset keeps what it omits; a durable topic's fall alarms and is not applied, and Consistent turns
// false until its owner reconciles; a clock's fall is adopted with a resync notice and no alarm.
func TestPushResetFallsByClass(t *testing.T) {
	store := newTestPushStore()
	events := make(chan SidecarEvent, 4)
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), store, newTestEnvelopeClock(), NewNoopLogger(), func(event SidecarEvent) {
		events <- event
	}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer feed.close()
	repo := PushTopicEvs(NewId())
	feed.applyResetPart(testPushPart(1, true, PushTopicTeam, 10, repo, 1000, PushTopicSock, 5))
	notices := make(chan PushNotice, 16)
	for _, topic := range []string{PushTopicTeam, PushTopicEvsPrefix, PushTopicSock} {
		remove, err := feed.subscribe(topic, func(notice PushNotice) {
			notices <- notice
		})
		if err != nil {
			t.Fatal(err)
		}
		defer remove()
	}

	feed.applyResetPart(testPushPart(2, true, PushTopicTeam, 6, repo, 400))
	if feed.version(PushTopicTeam) != 10 || feed.consistent() {
		t.Fatalf("a durable fall: team %d, consistent %t", feed.version(PushTopicTeam), feed.consistent())
	}
	event := testPushAwait(t, events, "head_alarm")
	held := &protocol.TopicVersion{}
	offered := &protocol.TopicVersion{}
	proto.Unmarshal(event.Evidence[0], held)
	proto.Unmarshal(event.Evidence[1], offered)
	if event.Kind != SidecarEventHeadAlarm || held.Version != 10 || offered.Version != 6 || held.Topic != PushTopicTeam {
		t.Errorf("event %+v", event)
	}
	notice := testPushAwait(t, notices, "notice")
	if notice.Topic != repo || notice.Version != 400 || !notice.Resync || feed.version(repo) != 400 {
		t.Errorf("a clock's fall: %+v", notice)
	}
	if feed.version(PushTopicSock) != 5 {
		t.Errorf("a topic the reset omitted: %d", feed.version(PushTopicSock))
	}
	select {
	case event := <-events:
		t.Errorf("a clock's fall alarmed: %+v", event)
	default:
	}

	feed.reconcile(PushTopicTeam, 6)
	if !feed.consistent() || feed.version(PushTopicTeam) != 6 {
		t.Errorf("reconciled: consistent %t, team %d", feed.consistent(), feed.version(PushTopicTeam))
	}
}

// Versions near 1.8 x 10^18, past a double's exact range, compare as integers.
func TestPushEvsSizedVersionsStayExact(t *testing.T) {
	machine := testPushMachine()
	repo := PushTopicEvs(NewId())
	if action := machine.hint(testPushHint(1, repo, 1_800_000_000_000_000_000)); len(action.notices) != 1 {
		t.Fatal("the first")
	}
	if action := machine.hint(testPushHint(2, repo, 1_800_000_000_000_000_001)); len(action.notices) != 1 || machine.topicVersions[repo] != 1_800_000_000_000_000_001 {
		t.Errorf("one above, which a double rounds to the same: %+v", action)
	}
	if action := machine.hint(testPushHint(3, repo, 1_800_000_000_000_000_001)); len(action.notices) != 0 {
		t.Errorf("the same again")
	}
}

// What a feed applied is kept, and a feed on the same store starts from it: a durable floor outlives a
// restart.
func TestPushVersionsOutliveARestart(t *testing.T) {
	store := newTestPushStore()
	blocked := func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), store, newTestEnvelopeClock(), NewNoopLogger(), nil, blocked)
	if err != nil {
		t.Fatal(err)
	}
	feed.applyResetPart(testPushPart(1, true, PushTopicTeam, 10, PushTopicDns, 3))
	feed.close()
	restarted, err := newPushFeed(t.Context(), DefaultPushClientSettings(), store, newTestEnvelopeClock(), NewNoopLogger(), nil, blocked)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if restarted.version(PushTopicTeam) != 10 || restarted.version(PushTopicDns) != 3 {
		t.Fatalf("restarted with team %d dns %d", restarted.version(PushTopicTeam), restarted.version(PushTopicDns))
	}
	restarted.applyResetPart(testPushPart(2, true, PushTopicTeam, 4))
	if restarted.version(PushTopicTeam) != 10 || restarted.consistent() {
		t.Errorf("a restart forgot the durable floor")
	}
	// a kept file that does not decode is a fault, never an empty floor
	store.files[pushVersionsFileName] = []byte{0xff, 0xff}
	if _, err := newPushFeed(t.Context(), DefaultPushClientSettings(), store, newTestEnvelopeClock(), NewNoopLogger(), nil, blocked); err == nil {
		t.Errorf("a broken file read as no versions")
	}
}

// Subscribe takes an exact topic or a family, and refuses anything else.
func TestPushSubscribe(t *testing.T) {
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), newTestPushStore(), newTestEnvelopeClock(), NewNoopLogger(), nil, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer feed.close()
	group := PushTopicGkmGroup(NewId())
	got := make(chan PushNotice, 8)
	for _, topic := range []string{PushTopicGkmGroupPrefix, PushTopicCore} {
		remove, err := feed.subscribe(topic, func(notice PushNotice) {
			got <- notice
		})
		if err != nil {
			t.Fatal(err)
		}
		defer remove()
	}
	for _, topic := range []string{"", "nothing", "gkm:x", "evs"} {
		if _, err := feed.subscribe(topic, func(notice PushNotice) {}); err == nil {
			t.Errorf("%q taken", topic)
		}
	}
	feed.applyHint(testPushHint(1, group, 5))
	feed.applyHint(testPushHint(2, PushTopicEvs(NewId()), 5))
	feed.applyHint(testPushHint(3, PushTopicCore, 9))
	if notice := testPushAwait(t, got, "group"); notice.Topic != group || notice.Kind != 0x1201 || !bytes.Equal(notice.Hint, []byte{1}) || notice.Resync {
		t.Errorf("notice %+v", notice)
	}
	if notice := testPushAwait(t, got, "core"); notice.Topic != PushTopicCore || notice.Version != 9 {
		t.Errorf("notice %+v", notice)
	}
}

// The feed refetches versions at start, at each resync asked for, and each SyncRefetchInterval, and a
// failed refetch is tried again after its wait; a run whose pages disagree applies nothing.
func TestPushFeedResyncs(t *testing.T) {
	clock := newTestEnvelopeClock()
	clock.firesWaits = true
	settings := DefaultPushClientSettings()
	fetches := make(chan []byte, 16)
	var stateLock sync.Mutex
	failNext := false
	versions := func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		stateLock.Lock()
		fail := failNext
		failNext = false
		stateLock.Unlock()
		fetches <- cursor
		if fail {
			return nil, io.ErrUnexpectedEOF
		}
		if len(cursor) == 0 {
			return &protocol.PollResponse{Cursor: []byte("next"), Reset_: testPushPart(3, false, PushTopicTeam, 2)}, nil
		}
		return &protocol.PollResponse{Reset_: testPushPart(3, true, PushTopicDns, 8)}, nil
	}
	waitCount, _ := clock.waitCount.Get()
	feed, err := newPushFeed(t.Context(), settings, newTestPushStore(), clock, NewNoopLogger(), nil, versions)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.close()
	// at start: both pages, then the hourly wait
	testPushAwait(t, fetches, "first page")
	if cursor := testPushAwait(t, fetches, "second page"); string(cursor) != "next" {
		t.Errorf("cursor %q", cursor)
	}
	clock.awaitWaitCount(waitCount + 1)
	if feed.version(PushTopicTeam) != 2 || feed.version(PushTopicDns) != 8 {
		t.Fatalf("team %d dns %d", feed.version(PushTopicTeam), feed.version(PushTopicDns))
	}
	// asked for
	feed.resync()
	testPushAwait(t, fetches, "resync first page")
	testPushAwait(t, fetches, "resync second page")
	clock.awaitWaitCount(waitCount + 2)
	// hourly, and a failure retried after its wait
	func() {
		stateLock.Lock()
		defer stateLock.Unlock()
		failNext = true
	}()
	clock.Advance(settings.SyncRefetchInterval)
	testPushAwait(t, fetches, "the failing refetch")
	clock.awaitWaitCount(waitCount + 3)
	clock.Advance(settings.RetryMinInterval)
	testPushAwait(t, fetches, "retried first page")
	testPushAwait(t, fetches, "retried second page")
}
