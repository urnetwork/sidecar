//go:build !js

// §6.8's client machine (push_state.go) on every leg but js, whose tests cannot open files: a partial
// reset applies nothing, a run's union applies once complete, a new epoch or a hint abandons a run, seq
// gaps and restarts send the client to versions, stale versions are ignored, a reset keeps what it
// omits, a clock's fall is adopted and raises nothing, evs-sized versions stay exact, versions outlive a
// restart, and the feed resyncs at start, on demand and hourly. Only a versions page judges a durable
// fall (QD-1044): a reset, a resident's or a poll's, that shows one applies its other topics, raises
// nothing and sends the client to versions once, and the page begun after it, showing the fall, raises
// head_alarm rollback (owner decision 300) and holds Consistent false until reconciled. A versions page
// begun before an input the push gave since takes only its rises (owner decision 299): it ends no run
// and raises no alarm, sending the client to versions again, one more refetch at most, and keeps the seq
// baseline, while a page begun after every input keeps the rules, its alarms included.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"maps"
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
	// the refetch the hint asked for, begun after it
	action = machine.reset(map[string]uint64{PushTopicTeam: 4, PushTopicDns: 9}, machine.inputCount)
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
	machine.reset(map[string]uint64{}, machine.inputCount)
	if action := machine.hint(testPushHint(40, PushTopicSock, 14)); action.refetchVersions {
		t.Errorf("after a reset any seq sets the baseline: %+v", action)
	}
	if action := machine.hint(testPushHint(41, "no-such-topic", 1)); action.changed || len(action.notices) != 0 {
		t.Errorf("an unknown topic: %+v", action)
	}
}

// A reset keeps what it omits; a durable topic's fall is not applied, raises nothing, leaves Consistent
// true and asks for versions once (QD-1044), and the page that answers, showing the same fall, alarms and
// turns Consistent false until the topic's owner reconciles it; a clock's fall is adopted with a resync
// notice and no alarm.
func TestPushResetFallsByClass(t *testing.T) {
	held := newTestPushHeldVersions()
	feed, events, cores := newTestPushHeldFeed(t, held)
	held.awaitStart(t, "the start's refetch")
	held.answer(t)
	testPushAwait(t, cores, "the start page's core notice")
	repo := PushTopicEvs(NewId())
	feed.applyResetPart(testPushPart(1, true, PushTopicTeam, 10, repo, 1000, PushTopicSock, 5))
	testPushAwait(t, cores, "the first reset's core notice")
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

	asks := feed.asks.Value()
	feed.applyResetPart(testPushPart(2, true, PushTopicTeam, 6, repo, 400))
	testPushAwait(t, cores, "the fall's core notice")
	if feed.version(PushTopicTeam) != 10 || !feed.consistent() || len(events) != 0 {
		t.Fatalf("a reset's durable fall: team %d, consistent %t, %d alarms", feed.version(PushTopicTeam), feed.consistent(), len(events))
	}
	if nextAsks := feed.asks.Value(); nextAsks.askCount != asks.askCount+1 {
		t.Errorf("a reset's durable fall asked for versions %d times", nextAsks.askCount-asks.askCount)
	}
	notice := testPushAwait(t, notices, "notice")
	if notice.Topic != repo || notice.Version != 400 || !notice.Resync || feed.version(repo) != 400 {
		t.Errorf("a clock's fall: %+v", notice)
	}
	if feed.version(PushTopicSock) != 5 {
		t.Errorf("a topic the reset omitted: %d", feed.version(PushTopicSock))
	}

	held.awaitStart(t, "the refetch the fall asks for")
	held.answer(t, PushTopicTeam, 6, repo, 400)
	event := testPushAwait(t, events, "head_alarm")
	evidence := [2]*protocol.TopicVersion{{}, {}}
	for i := range evidence {
		if err := proto.Unmarshal(event.Evidence[i], evidence[i]); err != nil {
			t.Fatal(err)
		}
	}
	if event.Kind != SidecarEventHeadAlarm || event.HeadAlarm != SidecarHeadAlarmRollback || evidence[0].Topic != PushTopicTeam || evidence[0].Version != 10 || evidence[1].Version != 6 {
		t.Errorf("event %+v, evidence %v", event, evidence)
	}
	// the page's last notice, after any it gave the topics subscribed to
	testPushAwait(t, cores, "the page's core notice")
	if feed.version(PushTopicTeam) != 10 || feed.consistent() || len(events) != 0 || len(notices) != 0 {
		t.Errorf("the page: team %d, consistent %t, %d more alarms, %d notices", feed.version(PushTopicTeam), feed.consistent(), len(events), len(notices))
	}

	feed.reconcile(PushTopicTeam, 6)
	if !feed.consistent() || feed.version(PushTopicTeam) != 6 {
		t.Errorf("reconciled: consistent %t, team %d", feed.consistent(), feed.version(PushTopicTeam))
	}
}

// The two ways a reset reaches the feed, each an input: a resident's complete part and a poll's reset.
var testPushResetInputs = []func(feed *pushFeed, reset *protocol.PushReset){
	func(feed *pushFeed, reset *protocol.PushReset) {
		feed.applyResetPart(reset)
	},
	func(feed *pushFeed, reset *protocol.PushReset) {
		feed.applyPoll(&protocol.PollResponse{Reset_: reset})
	},
}

// A feed whose start refetch never answers, so every input is the test's, with every event it raises in events. The
// feed raises an input's alarms before the call that gave it returns, so a test counts events as soon as it returns.
func newTestPushQuietFeed(t *testing.T) (*pushFeed, chan SidecarEvent) {
	t.Helper()
	events := make(chan SidecarEvent, 16)
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), newTestPushStore(), newTestEnvelopeClock(), NewNoopLogger(), func(event SidecarEvent) {
		events <- event
	}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(feed.close)
	return feed, events
}

// QD-928 (owner decision 300) with QD-1044: a reset below a durable version raises nothing, keeps the version held and
// Consistent true and asks for versions, and the page that answers, begun after it and showing the same fall, raises
// head_alarm of kind rollback, never fork, with no peer and as Evidence the two TopicVersions, the held one first, then
// the offered one. The version held stands and Consistent is false until the topic's owner reconciles it, the version
// reconciled then applying, while the clock topics the same reset lowers raise nothing and are adopted at the reset.
// So for each durable topic, team, dns and gkm:<group_id>, through a resident's complete part and a poll's reset alike.
func TestPushDurableFallAlarmsOneRefetchLater(t *testing.T) {
	repo := PushTopicEvs(NewId())
	for _, topic := range []string{PushTopicTeam, PushTopicDns, PushTopicGkmGroup(NewId())} {
		for i, input := range testPushResetInputs {
			held := newTestPushHeldVersions()
			feed, events, cores := newTestPushHeldFeed(t, held)
			held.awaitStart(t, "the start's refetch")
			held.answer(t)
			testPushAwait(t, cores, "the start page's core notice")
			input(feed, testPushPart(1, true, topic, 10, PushTopicSock, 50, repo, 1000))
			testPushAwait(t, cores, "the first reset's core notice")
			if len(events) != 0 || !feed.consistent() || feed.version(topic) != 10 {
				t.Fatalf("%s, input %d: the first reset raised %d events, consistent %t", topic, i, len(events), feed.consistent())
			}

			input(feed, testPushPart(2, true, topic, 6, PushTopicSock, 40, repo, 400))
			testPushAwait(t, cores, "the fall's core notice")
			if len(events) != 0 || !feed.consistent() || feed.version(topic) != 10 {
				t.Fatalf("%s, input %d: the reset's fall raised %d events, consistent %t, version %d", topic, i, len(events), feed.consistent(), feed.version(topic))
			}
			if feed.version(PushTopicSock) != 40 || feed.version(repo) != 400 {
				t.Errorf("%s, input %d: the clocks' falls: sock %d, repo %d", topic, i, feed.version(PushTopicSock), feed.version(repo))
			}

			held.awaitStart(t, "the refetch the fall asks for")
			held.answer(t, topic, 6, PushTopicSock, 40, repo, 400)
			testPushAwait(t, cores, "the page's core notice")
			if len(events) != 1 {
				t.Fatalf("%s, input %d: the page raised %d events", topic, i, len(events))
			}
			event := <-events
			if event.Kind != SidecarEventHeadAlarm || event.HeadAlarm != SidecarHeadAlarmRollback || event.SidecarId != nil {
				t.Errorf("%s, input %d: event %+v", topic, i, event)
			}
			evidence := [2]*protocol.TopicVersion{{}, {}}
			for j := range evidence {
				if err := proto.Unmarshal(event.Evidence[j], evidence[j]); err != nil {
					t.Fatalf("%s, input %d: evidence %d: %v", topic, i, j, err)
				}
			}
			if evidence[0].Topic != topic || evidence[0].Version != 10 || evidence[1].Topic != topic || evidence[1].Version != 6 {
				t.Errorf("%s, input %d: evidence %v", topic, i, evidence)
			}
			if feed.version(topic) != 10 || feed.consistent() {
				t.Errorf("%s, input %d: after the page: version %d, consistent %t", topic, i, feed.version(topic), feed.consistent())
			}

			feed.reconcile(topic, 6)
			if !feed.consistent() || feed.version(topic) != 6 || len(events) != 0 {
				t.Errorf("%s, input %d: reconciled: consistent %t, version %d, %d events", topic, i, feed.consistent(), feed.version(topic), len(events))
			}
		}
	}
}

// A reset lowering every clock topic raises nothing, leaves Consistent true and asks for no versions: each fall is a
// gap, adopted (§6.8's topic registry), a resident's part's and a poll's reset's alike, and only a durable topic's fall
// sends the client to versions (QD-1044).
func TestPushClockFallRaisesNothing(t *testing.T) {
	feed, events := newTestPushQuietFeed(t)
	clocks := []string{PushTopicCore, PushTopicSock, PushTopicMail, PushTopicTls, PushTopicGkm, PushTopicEvs(NewId())}
	at := func(version int) []any {
		topicVersions := []any{}
		for _, topic := range clocks {
			topicVersions = append(topicVersions, topic, version)
		}
		return topicVersions
	}
	asks := feed.asks.Value()
	feed.applyResetPart(testPushPart(1, true, at(10)...))
	feed.applyResetPart(testPushPart(2, true, at(5)...))
	if len(events) != 0 || !feed.consistent() {
		t.Fatalf("a part's clock falls: %d events, consistent %t", len(events), feed.consistent())
	}
	feed.applyPoll(&protocol.PollResponse{Reset_: testPushPart(3, true, at(3)...)})
	if len(events) != 0 || !feed.consistent() {
		t.Fatalf("a poll's clock falls: %d events, consistent %t", len(events), feed.consistent())
	}
	for _, topic := range clocks {
		if feed.version(topic) != 3 {
			t.Errorf("%s: %d, its falls not adopted", topic, feed.version(topic))
		}
	}
	if nextAsks := feed.asks.Value(); nextAsks != asks {
		t.Errorf("clock falls asked for versions: %+v, then %+v", asks, nextAsks)
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
// restart, a reset below it keeping it and the page that reset asks for alarming against it.
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
	held := newTestPushHeldVersions()
	restarted, err := newPushFeed(t.Context(), DefaultPushClientSettings(), store, newTestEnvelopeClock(), NewNoopLogger(), nil, held.versions)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if restarted.version(PushTopicTeam) != 10 || restarted.version(PushTopicDns) != 3 {
		t.Fatalf("restarted with team %d dns %d", restarted.version(PushTopicTeam), restarted.version(PushTopicDns))
	}
	cores := make(chan PushNotice, 4)
	remove, err := restarted.subscribe(PushTopicCore, func(notice PushNotice) {
		cores <- notice
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	held.awaitStart(t, "the restarted feed's start refetch")
	held.answer(t)
	testPushAwait(t, cores, "the start page's core notice")
	restarted.applyResetPart(testPushPart(2, true, PushTopicTeam, 4))
	if restarted.version(PushTopicTeam) != 10 || !restarted.consistent() {
		t.Errorf("a restart forgot the durable floor: team %d, consistent %t", restarted.version(PushTopicTeam), restarted.consistent())
	}
	testPushAwait(t, cores, "the reset's core notice")
	held.awaitStart(t, "the refetch the reset asks for")
	held.answer(t, PushTopicTeam, 4)
	testPushAwait(t, cores, "the page's core notice")
	if restarted.version(PushTopicTeam) != 10 || restarted.consistent() {
		t.Errorf("a page below the kept floor: team %d, consistent %t", restarted.version(PushTopicTeam), restarted.consistent())
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

// A page begun before an input the machine has since taken takes only its rises: a durable topic it shows
// lower raises no alarm and sends the client to versions again, a clock topic it shows lower is not
// adopted, a topic it raises applies with its notice and core is noticed. The same page begun after
// every input alarms and adopts the fall.
func TestPushLatePageTakesOnlyItsRises(t *testing.T) {
	repo := PushTopicEvs(NewId())
	machine := testPushMachine()
	noted := machine.inputCount
	machine.resetPart(testPushPart(1, true, PushTopicTeam, 10, PushTopicSock, 50, repo, 1000))
	page := map[string]uint64{PushTopicTeam: 9, PushTopicSock: 40, PushTopicDns: 5, repo: 1000}
	action := machine.reset(page, noted)
	if len(action.alarms) != 0 || len(machine.alarmTopics) != 0 || !action.refetchVersions {
		t.Fatalf("a late page's durable fall: %+v", action)
	}
	if machine.topicVersions[PushTopicTeam] != 10 || machine.topicVersions[PushTopicSock] != 50 || machine.topicVersions[PushTopicDns] != 5 || machine.topicVersions[repo] != 1000 {
		t.Errorf("a late page applied %v", machine.topicVersions)
	}
	if topics := testNoticeTopics(action); !slices.Equal(topics, []string{PushTopicDns, PushTopicCore}) {
		t.Errorf("notices %v", topics)
	}

	action = machine.reset(page, machine.inputCount)
	if len(action.alarms) != 1 || action.alarms[0] != (pushAlarm{topic: PushTopicTeam, held: 10, offered: 9}) || !machine.alarmTopics[PushTopicTeam] {
		t.Errorf("a timely page's durable fall: %+v", action)
	}
	if machine.topicVersions[PushTopicTeam] != 10 || machine.topicVersions[PushTopicSock] != 40 || action.refetchVersions {
		t.Errorf("a timely page: %v, %+v", machine.topicVersions, action)
	}
}

// A late page keeps the seq baseline a hint set after its refetch began, since it covers no hint after
// that one, so a gap after it still sends the client to versions; a timely page clears it.
func TestPushLatePageKeepsTheSeqBaseline(t *testing.T) {
	machine := testPushMachine()
	noted := machine.inputCount
	machine.hint(testPushHint(5, PushTopicSock, 10))
	if action := machine.reset(map[string]uint64{PushTopicSock: 9}, noted); action.refetchVersions || machine.topicVersions[PushTopicSock] != 10 {
		t.Fatalf("a late page's clock fall: %+v, sock %d", action, machine.topicVersions[PushTopicSock])
	}
	if action := machine.hint(testPushHint(7, PushTopicSock, 12)); !action.refetchVersions {
		t.Errorf("a gap after a late page: %+v", action)
	}
	machine.reset(map[string]uint64{PushTopicSock: 12}, machine.inputCount)
	if action := machine.hint(testPushHint(40, PushTopicSock, 13)); action.refetchVersions {
		t.Errorf("after a timely page any seq sets the baseline: %+v", action)
	}
}

// A late page ends no open run: it applies its rises and sends the client to versions, and the run's next
// part still joins it, so the run's union applies once complete. A timely page ends a run as before.
func TestPushLatePageLeavesARunOpen(t *testing.T) {
	machine := testPushMachine()
	noted := machine.inputCount
	machine.resetPart(testPushPart(7, false, PushTopicTeam, 9))
	action := machine.reset(map[string]uint64{PushTopicTeam: 8, PushTopicDns: 3}, noted)
	if !machine.runOpen || !action.refetchVersions || machine.topicVersions[PushTopicTeam] != 8 || machine.topicVersions[PushTopicDns] != 3 {
		t.Fatalf("a late page during a run: open %t, %+v, %v", machine.runOpen, action, machine.topicVersions)
	}
	machine.resetPart(testPushPart(7, true, PushTopicDns, 4))
	if machine.runOpen || machine.topicVersions[PushTopicTeam] != 9 || machine.topicVersions[PushTopicDns] != 4 || len(machine.alarmTopics) != 0 {
		t.Errorf("the run's union: open %t, %v", machine.runOpen, machine.topicVersions)
	}

	machine.resetPart(testPushPart(8, false, PushTopicTeam, 20))
	action = machine.reset(map[string]uint64{PushTopicTeam: 10}, machine.inputCount)
	if machine.runOpen || action.refetchVersions || machine.topicVersions[PushTopicTeam] != 10 {
		t.Errorf("a timely page during a run: open %t, %+v, team %d", machine.runOpen, action, machine.topicVersions[PushTopicTeam])
	}
}

// Late pages ask for at most MaxLateRefetchCount refetches in a row, each page answering the ask of the
// one before, so with the default a late page costs one more refetch at most: the page past the bound
// asks nothing, however late, and leaves its fall to the next page, which may ask again, and a timely
// page showing the same fall alarms.
func TestPushLatePagesAskAtMostMaxLateRefetchCountInARow(t *testing.T) {
	for _, maxLateRefetchCount := range []int{0, 1, 2} {
		settings := DefaultPushClientSettings()
		settings.MaxLateRefetchCount = maxLateRefetchCount
		machine := newPushMachine(settings, nil)
		machine.resetPart(testPushPart(1, true, PushTopicTeam, 10))
		// a page read before a sock hint the machine takes while it is in flight, showing team 9
		late := func() *pushAction {
			noted := machine.inputCount
			machine.hint(testPushHint(machine.lastSeq+1, PushTopicSock, machine.topicVersions[PushTopicSock]+1))
			return machine.reset(map[string]uint64{PushTopicTeam: 9}, noted)
		}
		for i := 0; i < maxLateRefetchCount; i += 1 {
			if action := late(); !action.refetchVersions || len(action.alarms) != 0 {
				t.Fatalf("max %d, late page %d: %+v", maxLateRefetchCount, i, action)
			}
		}
		if action := late(); action.refetchVersions || len(action.alarms) != 0 {
			t.Errorf("max %d, the page past the bound: %+v", maxLateRefetchCount, action)
		}
		if action := late(); action.refetchVersions != (0 < maxLateRefetchCount) || len(action.alarms) != 0 {
			t.Errorf("max %d, the page after it: %+v", maxLateRefetchCount, action)
		}
		if action := machine.reset(map[string]uint64{PushTopicTeam: 9}, machine.inputCount); len(action.alarms) != 1 || action.refetchVersions || machine.topicVersions[PushTopicTeam] != 10 {
			t.Errorf("max %d, a timely page showing the fall: %+v", maxLateRefetchCount, action)
		}
	}
}

// A versions route whose refetches the test answers: each says it has begun, its count noted, and waits
// for the page the test hands it, so the test gives the push inputs while a refetch is in flight and
// decides when its page lands.
type testPushHeldVersions struct {
	starts chan struct{}
	pages  chan *protocol.PollResponse
}

func newTestPushHeldVersions() *testPushHeldVersions {
	return &testPushHeldVersions{
		starts: make(chan struct{}),
		pages:  make(chan *protocol.PollResponse),
	}
}

func (self *testPushHeldVersions) versions(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	select {
	case self.starts <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case page := <-self.pages:
		return page, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Waits for the next refetch to begin.
func (self *testPushHeldVersions) awaitStart(t testing.TB, what string) {
	t.Helper()
	testPushAwait(t, self.starts, what)
}

// Answers the refetch in flight with one complete page of topicVersions, failing after 30 s.
func (self *testPushHeldVersions) answer(t testing.TB, topicVersions ...any) {
	t.Helper()
	select {
	case self.pages <- &protocol.PollResponse{Reset_: testPushPart(1, true, topicVersions...)}:
	case <-time.After(30 * time.Second):
		t.Fatalf("no refetch took the page")
	}
}

// A feed on held, with every head_alarm in events and every core notice, one per page or reset applied,
// in cores.
func newTestPushHeldFeed(t *testing.T, held *testPushHeldVersions) (*pushFeed, chan SidecarEvent, chan PushNotice) {
	t.Helper()
	events := make(chan SidecarEvent, 16)
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), newTestPushStore(), newTestEnvelopeClock(), NewNoopLogger(), func(event SidecarEvent) {
		events <- event
	}, held.versions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(feed.close)
	cores := make(chan PushNotice, 16)
	remove, err := feed.subscribe(PushTopicCore, func(notice PushNotice) {
		cores <- notice
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return feed, events, cores
}

// A resident's run opens while the start's refetch is in flight, the run's part read after the owners
// wrote team 9 and the page before: the page lands late, takes team 8, its rise, ends no run and sends
// the client to versions again, and the refetch that follows, begun after the part, brings team 9.
func TestPushLatePageDuringAnIncompleteRunRefetches(t *testing.T) {
	held := newTestPushHeldVersions()
	feed, events, _ := newTestPushHeldFeed(t, held)
	notices := make(chan PushNotice, 16)
	remove, err := feed.subscribe(PushTopicTeam, func(notice PushNotice) {
		notices <- notice
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	runOpen := func() bool {
		feed.stateLock.Lock()
		defer feed.stateLock.Unlock()
		return feed.machine.runOpen
	}

	held.awaitStart(t, "the start's refetch")
	// the run's first part, its tail never sent
	feed.applyResetPart(testPushPart(7, false, PushTopicTeam, 9))
	held.answer(t, PushTopicTeam, 8)
	// run asks for the next page only once the late one has applied
	held.awaitStart(t, "the refetch the late page asks for")
	if !runOpen() || feed.version(PushTopicTeam) != 8 {
		t.Fatalf("after the late page: run open %t, team %d", runOpen(), feed.version(PushTopicTeam))
	}
	held.answer(t, PushTopicTeam, 9)
	for {
		if notice := testPushAwait(t, notices, "team 9"); notice.Version == 9 {
			break
		}
	}
	if runOpen() || feed.version(PushTopicTeam) != 9 || !feed.consistent() || len(events) != 0 {
		t.Errorf("after the refetch: run open %t, team %d, consistent %t, %d alarms", runOpen(), feed.version(PushTopicTeam), feed.consistent(), len(events))
	}
}

// A complete reset raises team to 10 while a refetch read before it is in flight: its page, team 9, lands
// late, raises no alarm, keeps team 10 and sends the client to versions again, whose page holds team 10.
// The reset is a resident's part or a poll's, each an input.
func TestPushLatePageAfterACompleteResetRaisesNoAlarm(t *testing.T) {
	inputs := []func(feed *pushFeed){
		func(feed *pushFeed) {
			feed.applyResetPart(testPushPart(1, true, PushTopicTeam, 10))
		},
		func(feed *pushFeed) {
			feed.applyPoll(&protocol.PollResponse{Reset_: testPushPart(1, true, PushTopicTeam, 10)})
		},
	}
	for i, input := range inputs {
		held := newTestPushHeldVersions()
		feed, events, cores := newTestPushHeldFeed(t, held)
		held.awaitStart(t, "the start's refetch")
		input(feed)
		testPushAwait(t, cores, "the reset's core notice")
		held.answer(t, PushTopicTeam, 9)
		testPushAwait(t, cores, "the late page's core notice")
		if len(events) != 0 || feed.version(PushTopicTeam) != 10 || !feed.consistent() {
			t.Fatalf("input %d, the late page: %d alarms, team %d, consistent %t", i, len(events), feed.version(PushTopicTeam), feed.consistent())
		}
		held.awaitStart(t, "the refetch the late page asks for")
		held.answer(t, PushTopicTeam, 10)
		testPushAwait(t, cores, "the next page's core notice")
		if len(events) != 0 || feed.version(PushTopicTeam) != 10 || !feed.consistent() {
			t.Errorf("input %d, the next page: %d alarms, team %d, consistent %t", i, len(events), feed.version(PushTopicTeam), feed.consistent())
		}
	}
}

// A page begun after every input keeps the rules: a reset raised team to 10 before the refetch began, and
// its page, team 9, alarms with the held and offered versions as evidence, keeps team 10 and turns
// Consistent false.
func TestPushTimelyPageLoweringADurableTopicAlarms(t *testing.T) {
	held := newTestPushHeldVersions()
	feed, events, cores := newTestPushHeldFeed(t, held)
	held.awaitStart(t, "the start's refetch")
	held.answer(t)
	testPushAwait(t, cores, "the start page's core notice")
	feed.applyResetPart(testPushPart(1, true, PushTopicTeam, 10))
	feed.resync()
	held.awaitStart(t, "the refetch asked for")
	held.answer(t, PushTopicTeam, 9)
	event := testPushAwait(t, events, "head_alarm")
	evidence := [2]*protocol.TopicVersion{{}, {}}
	for i := range evidence {
		if err := proto.Unmarshal(event.Evidence[i], evidence[i]); err != nil {
			t.Fatal(err)
		}
	}
	if event.Kind != SidecarEventHeadAlarm || event.HeadAlarm != SidecarHeadAlarmRollback || evidence[0].Topic != PushTopicTeam || evidence[0].Version != 10 || evidence[1].Topic != PushTopicTeam || evidence[1].Version != 9 {
		t.Errorf("event %+v, evidence %v", event, evidence)
	}
	if feed.version(PushTopicTeam) != 10 || feed.consistent() {
		t.Errorf("team %d, consistent %t", feed.version(PushTopicTeam), feed.consistent())
	}
}

// QD-1044's first way: a resident reads {scp_<C>}ver for its reset before api reads a page that follows team's rise
// to 10, and the page lands first. The reset, showing team 9, raises no alarm and keeps team 10 and Consistent true,
// its dns rise applying, and sends the client to versions, whose page, team 10 again, raises nothing. A resident's
// part and a poll's reset alike.
func TestPushResetReadBeforeAnAppliedPageGoesToVersions(t *testing.T) {
	for i, input := range testPushResetInputs {
		held := newTestPushHeldVersions()
		feed, events, cores := newTestPushHeldFeed(t, held)
		held.awaitStart(t, "the start's refetch")
		held.answer(t, PushTopicTeam, 10, PushTopicDns, 3)
		testPushAwait(t, cores, "the page's core notice")

		input(feed, testPushPart(1, true, PushTopicTeam, 9, PushTopicDns, 4))
		testPushAwait(t, cores, "the reset's core notice")
		if len(events) != 0 || feed.version(PushTopicTeam) != 10 || feed.version(PushTopicDns) != 4 || !feed.consistent() {
			t.Fatalf("input %d, the reset: %d alarms, team %d, dns %d, consistent %t", i, len(events), feed.version(PushTopicTeam), feed.version(PushTopicDns), feed.consistent())
		}

		held.awaitStart(t, "the refetch the reset asks for")
		held.answer(t, PushTopicTeam, 10, PushTopicDns, 4)
		testPushAwait(t, cores, "the next page's core notice")
		if len(events) != 0 || feed.version(PushTopicTeam) != 10 || !feed.consistent() {
			t.Errorf("input %d, the next page: %d alarms, team %d, consistent %t", i, len(events), feed.version(PushTopicTeam), feed.consistent())
		}
	}
}

// QD-1044's first way through a run: a resident's run opens with team 9 while a page api read after team's rise is in
// flight, and the page lands late, raising team to 10 and leaving the run open (owner decision 299). The run's union,
// applied at its last part, shows team 9: no alarm, team 10 kept, its dns applied and versions asked for, and the page
// that answers, begun after the run, shows team 10 and raises nothing, asking for nothing more.
func TestPushRunSpanningALatePageGoesToVersions(t *testing.T) {
	machine := testPushMachine()
	noted := machine.inputCount
	machine.resetPart(testPushPart(7, false, PushTopicTeam, 9))
	if action := machine.reset(map[string]uint64{PushTopicTeam: 10}, noted); !machine.runOpen || !action.refetchVersions || machine.topicVersions[PushTopicTeam] != 10 {
		t.Fatalf("the late page: run open %t, %+v, team %d", machine.runOpen, action, machine.topicVersions[PushTopicTeam])
	}

	action := machine.resetPart(testPushPart(7, true, PushTopicDns, 4))
	if len(action.alarms) != 0 || len(machine.alarmTopics) != 0 || !action.refetchVersions || machine.runOpen {
		t.Fatalf("the run's union below the page: %+v, alarm topics %v, run open %t", action, machine.alarmTopics, machine.runOpen)
	}
	if machine.topicVersions[PushTopicTeam] != 10 || machine.topicVersions[PushTopicDns] != 4 {
		t.Errorf("the run's union applied %v", machine.topicVersions)
	}
	if topics := testNoticeTopics(action); !slices.Equal(topics, []string{PushTopicDns, PushTopicCore}) {
		t.Errorf("notices %v", topics)
	}

	action = machine.reset(map[string]uint64{PushTopicTeam: 10, PushTopicDns: 4}, machine.inputCount)
	if len(action.alarms) != 0 || len(machine.alarmTopics) != 0 || action.refetchVersions {
		t.Errorf("the page the run asked for: %+v", action)
	}
}

// A reset showing a durable topic below the version held applies its other topics as any reset does, a rise with its
// notice, a clock's fall adopted with its notice, a topic it omits kept, core noticed and the seq baseline cleared,
// while the durable topic keeps its version, raises nothing and asks for versions once, however many durable topics
// fell. A reset with no durable fall asks for nothing. A resident's complete part and a poll's reset alike.
func TestPushResetBelowADurableVersionAppliesItsOtherTopics(t *testing.T) {
	inputs := []func(machine *pushMachine, reset *protocol.PushReset) *pushAction{
		func(machine *pushMachine, reset *protocol.PushReset) *pushAction {
			return machine.resetPart(reset)
		},
		func(machine *pushMachine, reset *protocol.PushReset) *pushAction {
			topicVersions := map[string]uint64{}
			for _, topicVersion := range reset.Versions {
				topicVersions[topicVersion.Topic] = topicVersion.Version
			}
			return machine.pollReset(topicVersions)
		},
	}
	repo := PushTopicEvs(NewId())
	group := PushTopicGkmGroup(NewId())
	for i, input := range inputs {
		machine := testPushMachine()
		machine.reset(map[string]uint64{PushTopicTeam: 10, group: 20, PushTopicDns: 3, PushTopicSock: 50, PushTopicMail: 7, repo: 1000}, machine.inputCount)
		machine.hint(testPushHint(5, PushTopicSock, 51))

		action := input(machine, testPushPart(1, true, PushTopicTeam, 9, group, 19, PushTopicDns, 4, PushTopicSock, 40, repo, 400))
		if len(action.alarms) != 0 || len(machine.alarmTopics) != 0 || !action.refetchVersions || !action.changed {
			t.Fatalf("input %d: a reset below two durable versions: %+v, alarm topics %v", i, action, machine.alarmTopics)
		}
		want := map[string]uint64{PushTopicTeam: 10, group: 20, PushTopicDns: 4, PushTopicSock: 40, PushTopicMail: 7, repo: 400}
		if !maps.Equal(machine.topicVersions, want) {
			t.Errorf("input %d: applied %v, want %v", i, machine.topicVersions, want)
		}
		if topics := testNoticeTopics(action); !slices.Equal(topics, []string{PushTopicDns, repo, PushTopicSock, PushTopicCore}) {
			t.Errorf("input %d: notices %v", i, topics)
		}
		// the reset is the new baseline: any seq sets it
		if action := machine.hint(testPushHint(40, PushTopicSock, 41)); action.refetchVersions {
			t.Errorf("input %d: after the reset a seq asked for versions: %+v", i, action)
		}

		action = input(machine, testPushPart(2, true, PushTopicTeam, 11, PushTopicSock, 30))
		if action.refetchVersions || len(action.alarms) != 0 || machine.topicVersions[PushTopicTeam] != 11 || machine.topicVersions[PushTopicSock] != 30 {
			t.Errorf("input %d: a reset with no durable fall: %+v, %v", i, action, machine.topicVersions)
		}
	}
}
