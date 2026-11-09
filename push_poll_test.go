//go:build !sidecar_http && !js

// §6.8's long-poll client against pushservice's long-poll on T2's FakeRedis, every answer passed through
// its 200 body's bytes as api writes them and SidecarApi reads them: a reset first, a hold a hint wakes,
// the cursor kept across an empty hold, versions pages applied whole, backoff on anything but a 200, and
// a 401 ending the poll. Fake clock throughout.

package sidecar_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

const testPushPollAwaitTimeout = 30 * time.Second

func testPushPollAwait[T any](t testing.TB, values <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(testPushPollAwaitTimeout):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

// The 200 body's bytes and back.
func testPushPollRoundTrip(response *protocol.PollResponse) (*protocol.PollResponse, error) {
	body, err := proto.Marshal(response)
	if err != nil {
		return nil, err
	}
	decoded := &protocol.PollResponse{}
	if err := proto.Unmarshal(body, decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

// A client's api side on FakeRedis: the writer, the long-poll, and the routes' functions. Each runs on
// a clock of its own, so a test counts one kind of timer at a time: FakeRedis's ttls on redisClock, the
// long-poll's holds on pollClock, and the client's resyncs and backoff on clientClock.
type testPushPollApi struct {
	redisClock  *sidecartest.FakeClock
	pollClock   *sidecartest.FakeClock
	clientClock *sidecartest.FakeClock
	redis       *sidecartest.FakeRedis
	writer      *pushservice.HintWriter
	longPoll    *pushservice.LongPoll
	clientId    connect.Id
	// each poll's cursor as it begins
	calls chan []byte

	stateLock sync.Mutex
	// polls left to fail, each with failErr
	failCount int
	failErr   error
}

func newTestPushPollApi(t *testing.T) *testPushPollApi {
	t.Helper()
	redisClock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	pollClock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	clientClock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), redisClock, nil, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	writer, err := pushservice.NewHintWriter(redis, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	longPoll, err := pushservice.NewLongPoll(t.Context(), redis, pollClock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(longPoll.Close)
	return &testPushPollApi{
		redisClock:  redisClock,
		pollClock:   pollClock,
		clientClock: clientClock,
		redis:       redis,
		writer:      writer,
		longPoll:    longPoll,
		clientId:    connect.NewId(),
		calls:       make(chan []byte, 64),
	}
}

func (self *testPushPollApi) poll(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	fail := error(nil)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < self.failCount {
			self.failCount -= 1
			fail = self.failErr
		}
	}()
	self.calls <- slices.Clone(cursor)
	if fail != nil {
		return nil, fail
	}
	response, err := self.longPoll.Poll(ctx, self.clientId, cursor)
	if err != nil {
		return nil, err
	}
	return testPushPollRoundTrip(response)
}

func (self *testPushPollApi) versions(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	fieldValues, err := self.redis.HashGetAll(ctx, pushservice.HintVersionsKey(self.clientId))
	if err != nil {
		return nil, err
	}
	response, err := pushservice.VersionsPage(pushservice.ParseHintVersions(fieldValues), cursor)
	if err != nil {
		return nil, err
	}
	return testPushPollRoundTrip(response)
}

func (self *testPushPollApi) hint(t *testing.T, topic string, version uint64) {
	t.Helper()
	if _, err := self.writer.HintClient(t.Context(), self.clientId, &sidecar.ClientHint{Topic: topic, Version: version, Kind: 0x1201, Body: []byte{7}}); err != nil {
		t.Fatal(err)
	}
}

func (self *testPushPollApi) fail(count int, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failCount = count
	self.failErr = err
}

func newTestPushPollClient(t *testing.T, api *testPushPollApi) *sidecar.PushPollClient {
	t.Helper()
	client, err := sidecar.NewPushPollClientOn(t.Context(), api.poll, api.versions, sidecartest.NewFakeStore().Root(), nil, api.clientClock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// The client's first poll gets a reset first, a later hint reaches a subscriber through a held poll,
// and the poll after an empty hold sends the cursor it sent before.
func TestPushPollClientFollowsTheLongPoll(t *testing.T) {
	api := newTestPushPollApi(t)
	api.hint(t, sidecar.PushTopicTeam, 4)
	notices := make(chan sidecar.PushNotice, 16)
	client := newTestPushPollClient(t, api)
	remove, err := client.Subscribe(sidecar.PushTopicTeam, func(notice sidecar.PushNotice) {
		notices <- notice
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	ctx, cancel := context.WithTimeout(t.Context(), testPushPollAwaitTimeout)
	defer cancel()

	if first := testPushPollAwait(t, api.calls, "the first poll"); len(first) != 0 {
		t.Fatalf("the first poll sent cursor %q", first)
	}
	second := testPushPollAwait(t, api.calls, "the second poll")
	if len(second) == 0 {
		t.Fatalf("the second poll sent no cursor")
	}
	// the second poll holds, its hold on the long-poll's clock, and the client's first versions refetch
	// is done, its hourly wait on the client's clock, so the hint below comes only through the poll
	if err := api.pollClock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := api.clientClock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	api.hint(t, sidecar.PushTopicTeam, 5)
	for {
		notice := testPushPollAwait(t, notices, "team's hint")
		if notice.Version == 5 && !notice.Resync && notice.Kind == 0x1201 {
			break
		}
	}
	third := testPushPollAwait(t, api.calls, "the third poll")
	// the third holds beside the second's spent timer, and ends empty
	if err := api.pollClock.AwaitTimers(ctx, 2); err != nil {
		t.Fatal(err)
	}
	api.pollClock.Advance(pushservice.DefaultLongPollSettings().HoldTimeout)
	fourth := testPushPollAwait(t, api.calls, "the poll after an empty hold")
	if string(fourth) != string(third) {
		t.Errorf("the cursor changed across an empty hold: %q then %q", third, fourth)
	}
	if !client.Consistent() {
		t.Errorf("inconsistent")
	}
}

// Anything but a 200 is waited out, RetryMinInterval doubling, and polling goes on; a 401 ends the
// poll, which Ended reports.
func TestPushPollClientBacksOffAndEndsAt401(t *testing.T) {
	api := newTestPushPollApi(t)
	api.fail(2, &sidecar.SidecarApiError{Route: "GET /sidecar/sync/poll", Status: 503})
	client := newTestPushPollClient(t, api)
	ctx, cancel := context.WithTimeout(t.Context(), testPushPollAwaitTimeout)
	defer cancel()
	settings := sidecar.DefaultPushClientSettings()
	for _, wait := range []time.Duration{settings.RetryMinInterval, 2 * settings.RetryMinInterval} {
		testPushPollAwait(t, api.calls, "a failing poll")
		// the backoff beside the client's hourly resync
		if err := api.clientClock.AwaitTimers(ctx, 2); err != nil {
			t.Fatal(err)
		}
		api.clientClock.Advance(wait)
	}
	// polling goes on: a reset first, then a poll that holds on the long-poll's clock
	testPushPollAwait(t, api.calls, "the poll after the backoff")
	testPushPollAwait(t, api.calls, "the poll that holds")
	if err := api.pollClock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	api.fail(1, &sidecar.SidecarApiError{Route: "GET /sidecar/sync/poll", Status: 401})
	api.pollClock.Advance(pushservice.DefaultLongPollSettings().HoldTimeout)
	testPushPollAwait(t, api.calls, "the poll that meets the 401")
	select {
	case <-client.Done():
	case <-ctx.Done():
		t.Fatal("a 401 did not end the poll")
	}
	var apiError *sidecar.SidecarApiError
	if !errors.As(client.Ended(), &apiError) || apiError.Status != 401 {
		t.Errorf("ended %v", client.Ended())
	}
}
