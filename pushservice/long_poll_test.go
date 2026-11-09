package pushservice_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A long-poll on a FakeRedis and its clock, with a writer for hints and a count of LeaseTouch calls.
type testLongPollEnv struct {
	redis       *sidecartest.FakeRedis
	clock       *sidecartest.FakeClock
	faults      *sidecartest.FaultQueue
	writer      *pushservice.HintWriter
	longPoll    *pushservice.LongPoll
	leaseTouchs chan connect.Id
}

func newTestLongPollEnv(t *testing.T, settings *pushservice.LongPollSettings) *testLongPollEnv {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	redis := sidecartest.NewFakeRedis(t.Context(), clock, faults, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	writer, err := pushservice.NewHintWriter(redis, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &testLongPollEnv{redis: redis, clock: clock, faults: faults, writer: writer, leaseTouchs: make(chan connect.Id, 64)}
	longPoll, err := pushservice.NewLongPoll(t.Context(), redis, clock, settings, func(ctx context.Context, clientId connect.Id) error {
		env.leaseTouchs <- clientId
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(longPoll.Close)
	env.longPoll = longPoll
	return env
}

func (self *testLongPollEnv) hint(t *testing.T, clientId connect.Id, topic string, version uint64) {
	t.Helper()
	if _, err := self.writer.HintClient(t.Context(), clientId, &sidecar.ClientHint{Topic: topic, Version: version}); err != nil {
		t.Fatal(err)
	}
}

type testPollResult struct {
	response *protocol.PollResponse
	err      error
}

// Starts a poll and returns once it holds: its hold timer is on the clock, and its waiter was registered
// before that timer, so a hint written after this wakes it.
func (self *testLongPollEnv) startHeldPoll(t *testing.T, clientId connect.Id, cursor []byte) <-chan testPollResult {
	t.Helper()
	timerCount := len(self.clock.PendingTimers())
	results := make(chan testPollResult, 1)
	go func() {
		response, err := self.longPoll.Poll(context.Background(), clientId, cursor)
		results <- testPollResult{response: response, err: err}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := self.clock.AwaitTimers(ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	return results
}

func awaitPoll(t *testing.T, results <-chan testPollResult) *protocol.PollResponse {
	t.Helper()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.response
	case <-time.After(10 * time.Second):
		t.Fatal("the poll did not answer")
	}
	return nil
}

// An empty cursor gets a reset first, with the stream's hints and a cursor past them; then a poll with
// that cursor holds, and a hint wakes it with that hint alone, seq following on.
func TestLongPollResetsThenHolds(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	env.hint(t, clientId, sidecar.PushTopicTeam, 4)
	env.hint(t, clientId, sidecar.PushTopicDns, 9)

	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reset_ == nil || !first.Reset_.Complete || first.Reset_.Epoch == 0 || len(first.Reset_.Versions) != 2 {
		t.Fatalf("reset %v", first.Reset_)
	}
	if first.Reset_.Versions[0].Topic != sidecar.PushTopicDns || first.Reset_.Versions[0].Version != 9 || first.Reset_.Versions[1].Topic != sidecar.PushTopicTeam {
		t.Errorf("versions %v", first.Reset_.Versions)
	}
	if len(first.Hints) != 2 || first.Hints[1].Seq != 2 || len(first.Cursor) == 0 {
		t.Fatalf("hints %v cursor %q", first.Hints, first.Cursor)
	}

	results := env.startHeldPoll(t, clientId, first.Cursor)
	env.hint(t, clientId, sidecar.PushTopicTeam, 5)
	second := awaitPoll(t, results)
	if second.Reset_ != nil || len(second.Hints) != 1 || second.Hints[0].Seq != 3 || second.Hints[0].Version != 5 {
		t.Fatalf("second %v", second)
	}
	// the 200 body round-trips as PROTO-M1-06's poll client reads it
	body, err := proto.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &protocol.PollResponse{}
	if err := proto.Unmarshal(body, decoded); err != nil || !proto.Equal(decoded, second) {
		t.Errorf("round trip %v, %v", decoded, err)
	}
}

// An empty hold answers after HoldTimeout with no hints, no reset and the cursor it came with.
func TestLongPollEmptyHoldKeepsCursor(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	env.hint(t, clientId, sidecar.PushTopicTeam, 1)
	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	results := env.startHeldPoll(t, clientId, first.Cursor)
	env.clock.Advance(pushservice.DefaultLongPollSettings().HoldTimeout)
	held := awaitPoll(t, results)
	if held.Reset_ != nil || len(held.Hints) != 0 || string(held.Cursor) != string(first.Cursor) {
		t.Fatalf("held %v", held)
	}
}

// An empty stream: the first poll still answers at once with a reset of what ver holds, and the next
// poll's first hint follows on from seq 0.
func TestLongPollEmptyCursorOnEmptyStream(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reset_ == nil || !first.Reset_.Complete || len(first.Reset_.Versions) != 0 || len(first.Hints) != 0 {
		t.Fatalf("first %v", first)
	}
	results := env.startHeldPoll(t, clientId, first.Cursor)
	env.hint(t, clientId, sidecar.PushTopicTeam, 1)
	second := awaitPoll(t, results)
	if second.Reset_ != nil || len(second.Hints) != 1 || second.Hints[0].Seq != 1 {
		t.Fatalf("second %v", second)
	}
}

// A cursor past the stream's retention, here the keys' hour, which restarts n: the next entry's seq is
// not the cursor's plus one, so the answer puts a reset first. A cursor this process did not make reads
// as empty.
func TestLongPollExpiredCursorResets(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	env.hint(t, clientId, sidecar.PushTopicTeam, 1)
	env.hint(t, clientId, sidecar.PushTopicTeam, 2)
	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(pushservice.DefaultHintWriterSettings().KeyTimeout + time.Second)
	env.hint(t, clientId, sidecar.PushTopicTeam, 3)
	second, err := env.longPoll.Poll(t.Context(), clientId, first.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if second.Reset_ == nil || len(second.Hints) != 1 || second.Hints[0].Seq != 1 {
		t.Fatalf("second %v", second)
	}
	for _, cursor := range [][]byte{[]byte("garbage"), []byte("1:not-an-id:3"), []byte("1:5-0:x")} {
		response, err := env.longPoll.Poll(t.Context(), clientId, cursor)
		if err != nil || response.Reset_ == nil {
			t.Errorf("cursor %q: %v, %v", cursor, response, err)
		}
	}
}

// A reset carries at most 48 versions, complete only when that is all of ver.
func TestLongPollResetIsOnePart(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	for range pushservice.MaxResetVersionCount + 2 {
		env.hint(t, clientId, sidecar.PushTopicEvs(sidecar.NewId()), 7)
	}
	response, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Reset_.Complete || len(response.Reset_.Versions) != pushservice.MaxResetVersionCount {
		t.Fatalf("reset of %d complete %t", len(response.Reset_.Versions), response.Reset_.Complete)
	}
	body, err := proto.Marshal(&protocol.Envelope{Body: mustMarshal(t, response.Reset_)})
	if err != nil {
		t.Fatal(err)
	}
	// a part fits one envelope's body
	if len(mustMarshal(t, response.Reset_)) > 4016 || len(body) > 4080 {
		t.Errorf("a part of %d bytes", len(mustMarshal(t, response.Reset_)))
	}
}

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A lost and re-established subscription wakes every hold to reread: a hint that came with no event
// reaches the poll at the resync.
func TestLongPollSubscriptionLossWakesWaiters(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	results := env.startHeldPoll(t, clientId, first.Cursor)
	// an entry with no INCR behind it, so no event announces it
	if _, err := env.redis.StreamAdd(t.Context(), pushservice.HintStreamKey(clientId), 256, map[string][]byte{
		"seq": []byte("1"), "topic": []byte("team"), "version": []byte("6"), "kind": []byte("0"), "hint": nil,
	}); err != nil {
		t.Fatal(err)
	}
	env.redis.ResyncKeyEvents()
	response := awaitPoll(t, results)
	if len(response.Hints) != 1 || response.Hints[0].Version != 6 {
		t.Fatalf("response %v", response)
	}
}

// Past MaxHeldPollCount a poll is refused at once, and the held one goes on.
func TestLongPollRefusesPastItsBound(t *testing.T) {
	settings := pushservice.DefaultLongPollSettings()
	settings.MaxHeldPollCount = 1
	env := newTestLongPollEnv(t, settings)
	clientId := connect.NewId()
	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	results := env.startHeldPoll(t, clientId, first.Cursor)
	if _, err := env.longPoll.Poll(t.Context(), connect.NewId(), nil); !errors.Is(err, pushservice.ErrLongPollBusy) {
		t.Fatalf("err %v", err)
	}
	if stats := env.longPoll.Stats(); stats.BusyCount != 1 || stats.HeldCount != 1 {
		t.Errorf("stats %+v", stats)
	}
	env.hint(t, clientId, sidecar.PushTopicTeam, 2)
	if response := awaitPoll(t, results); len(response.Hints) != 1 {
		t.Errorf("response %v", response)
	}
	if stats := env.longPoll.Stats(); stats.HeldCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}

// LeaseTouch runs at the first poll, not again while {scp_<C>}hb lives, again once it has expired, and
// on a Redis error.
func TestLongPollLeaseTouch(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	touches := func() int {
		count := 0
		for {
			select {
			case <-env.leaseTouchs:
				count += 1
			default:
				return count
			}
		}
	}
	for range 3 {
		if _, err := env.longPoll.Poll(t.Context(), clientId, nil); err != nil {
			t.Fatal(err)
		}
	}
	if count := touches(); count != 1 {
		t.Errorf("%d touches in one lease", count)
	}
	env.clock.Advance(pushservice.DefaultLongPollSettings().LeaseTimeout)
	if _, err := env.longPoll.Poll(t.Context(), clientId, nil); err != nil {
		t.Fatal(err)
	}
	if count := touches(); count != 1 {
		t.Errorf("%d touches after the marker expired", count)
	}
	if _, err := env.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: pushservice.HintPollKey(clientId), Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.longPoll.Poll(t.Context(), clientId, nil); err != nil {
		t.Fatal(err)
	}
	if count := touches(); count != 1 {
		t.Errorf("%d touches on a Redis error", count)
	}
}

// Close ends a held poll.
func TestLongPollCloseEndsHolds(t *testing.T) {
	env := newTestLongPollEnv(t, nil)
	clientId := connect.NewId()
	first, err := env.longPoll.Poll(t.Context(), clientId, nil)
	if err != nil {
		t.Fatal(err)
	}
	results := env.startHeldPoll(t, clientId, first.Cursor)
	env.longPoll.Close()
	select {
	case result := <-results:
		if !errors.Is(result.err, pushservice.ErrLongPollClosed) {
			t.Fatalf("err %v", result.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the poll did not end")
	}
}

// versions pages at 48 under one epoch, complete and cursorless only on its last page, and refuses a
// cursor it did not make.
func TestVersionsPages(t *testing.T) {
	topicVersions := map[string]uint64{}
	for range 100 {
		topicVersions[sidecar.PushTopicEvs(sidecar.NewId())] = 1_800_000_000_000_000_001
	}
	topicVersions[sidecar.PushTopicCore] = 1_731_000_000_000_000
	seen := map[string]uint64{}
	cursor := []byte(nil)
	epoch := uint64(0)
	for page := 0; ; page += 1 {
		response, err := pushservice.VersionsPage(topicVersions, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Hints) != 0 || response.Reset_ == nil || len(response.Reset_.Versions) > pushservice.MaxResetVersionCount {
			t.Fatalf("page %d: %v", page, response)
		}
		if page == 0 {
			epoch = response.Reset_.Epoch
		} else if response.Reset_.Epoch != epoch {
			t.Errorf("page %d: epoch %d, want %d", page, response.Reset_.Epoch, epoch)
		}
		for _, version := range response.Reset_.Versions {
			seen[version.Topic] = version.Version
		}
		if response.Reset_.Complete {
			if len(response.Cursor) != 0 || page != 2 {
				t.Errorf("the last page %d carries cursor %q", page, response.Cursor)
			}
			break
		}
		cursor = response.Cursor
	}
	if len(seen) != len(topicVersions) {
		t.Errorf("%d topics of %d", len(seen), len(topicVersions))
	}
	for _, cursor := range [][]byte{[]byte("x"), []byte("v1:0:core"), []byte("v1:12"), []byte("v1:12:")} {
		if _, err := pushservice.VersionsPage(topicVersions, cursor); !errors.Is(err, pushservice.ErrVersionsCursor) {
			t.Errorf("cursor %q: %v", cursor, err)
		}
	}
}
