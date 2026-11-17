//go:build !sidecar_http && !js

// §6.8's retry waits (QD-906) through the long-poll client, on the Net's fake clock, which only the test
// moves: a failed versions refetch waits out a backoff that a reconnect ends at once, while a seq gap or a
// poll's incomplete reset made during it waits for its end; the wait after a reconnect's refetch fails
// again doubles from the one it ended; and the long-poll's first poll answered after a failure is its
// reconnect, where an answered poll with no failure before it is not. Every poll holds until the test
// answers it, so the clock's timers are the push's own. A test that shows an ask did not refetch runs in
// a synctest bubble, whose Wait returns only once every goroutine of the client is blocked again, so the
// ask has been taken in when the test looks.

package sidecar_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What one poll answers: a reply, or an error.
type testPushRetryAnswer struct {
	response *protocol.PollResponse
	err      error
}

// The routes a retry test's poll client runs on: each poll holds until the test answers it, and each
// versions refetch, noted with the clock's time as it begins, is refused while refetches are refused, and
// otherwise answers one complete page holding team 7.
type testPushRetryApi struct {
	clock *sidecartest.FakeClock
	// each poll as it begins
	polls chan struct{}
	// what the poll in flight answers
	pollAnswers chan testPushRetryAnswer
	// each versions refetch's time as it begins
	refetchTimes chan time.Time

	stateLock sync.Mutex
	refused   bool
}

// Refetches refused until refuse says otherwise.
func newTestPushRetryApi() *testPushRetryApi {
	return &testPushRetryApi{
		clock:        sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		polls:        make(chan struct{}, 64),
		pollAnswers:  make(chan testPushRetryAnswer),
		refetchTimes: make(chan time.Time, 64),
		refused:      true,
	}
}

func (self *testPushRetryApi) poll(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	self.polls <- struct{}{}
	select {
	case answer := <-self.pollAnswers:
		return answer.response, answer.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (self *testPushRetryApi) versions(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
	self.refetchTimes <- self.clock.Now()
	refused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.refused
	}()
	if refused {
		return nil, &sidecar.SidecarApiError{Route: "GET /sidecar/sync/versions", Status: 503}
	}
	return &protocol.PollResponse{Reset_: &protocol.PushReset{
		Epoch:    1,
		Complete: true,
		Versions: []*protocol.TopicVersion{{Topic: sidecar.PushTopicTeam, Version: 7}},
	}}, nil
}

// Whether versions refetches from now on are refused.
func (self *testPushRetryApi) refuse(refused bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refused = refused
}

// Answers the next poll once it has begun.
func (self *testPushRetryApi) answerPoll(t *testing.T, answer testPushRetryAnswer) {
	t.Helper()
	testPushPollAwait(t, self.polls, "a poll")
	select {
	case self.pollAnswers <- answer:
	case <-time.After(testPushPollAwaitTimeout):
		t.Fatalf("no poll took its answer")
	}
}

// Waits until a timer due at is pending on the clock.
func (self *testPushRetryApi) awaitTimerAt(t *testing.T, at time.Time, what string) {
	t.Helper()
	guard := time.After(testPushPollAwaitTimeout)
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("no timer at %s for %s: %v", at, what, pending)
		}
	}
}

// Takes the next versions refetch, which the api refuses, and waits until its retry wait of wait is set,
// on a clock standing where it stood at the refusal: answers the time the wait ends.
func (self *testPushRetryApi) awaitRefusedRefetch(t *testing.T, wait time.Duration) time.Time {
	t.Helper()
	retryTime := testPushPollAwait(t, self.refetchTimes, "a versions refetch").Add(wait)
	self.awaitTimerAt(t, retryTime, "a retry wait")
	return retryTime
}

// Takes each refused refetch from the start's on, moving the clock to the end of every wait shorter than
// last: answers the end of the wait of last, which the clock stands before.
func (self *testPushRetryApi) walkToRetryWait(t *testing.T, last time.Duration) time.Time {
	t.Helper()
	settings := sidecar.DefaultPushClientSettings()
	for wait := settings.RetryMinInterval; ; wait = min(2*wait, settings.RetryMaxInterval) {
		retryTime := self.awaitRefusedRefetch(t, wait)
		if wait == last {
			return retryTime
		}
		if wait == settings.RetryMaxInterval {
			t.Fatalf("no wait of %s on the way to the longest", last)
		}
		self.clock.AdvanceTo(retryTime)
	}
}

// Fails on a versions refetch begun and not yet taken.
func (self *testPushRetryApi) expectNoRefetch(t *testing.T, what string) {
	t.Helper()
	select {
	case refetchTime := <-self.refetchTimes:
		t.Errorf("%s refetched at %s", what, refetchTime)
	default:
	}
}

// A poll client on api's routes and clock, closed with the test, with every notice of team.
func newTestPushRetryClient(t *testing.T, api *testPushRetryApi) (*sidecar.PushPollClient, chan sidecar.PushNotice) {
	t.Helper()
	client, err := sidecar.NewPushPollClientOn(t.Context(), api.poll, api.versions, sidecartest.NewFakeStore().Root(), nil, api.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	notices := make(chan sidecar.PushNotice, 64)
	remove, err := client.Subscribe(sidecar.PushTopicTeam, func(notice sidecar.PushNotice) {
		// a subscriber must not block: a full channel is the test's failure
		select {
		case notices <- notice:
		default:
			t.Errorf("the test's notices are full")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return client, notices
}

// Takes notices of team until one at version, which a page applied.
func awaitTestPushRetryPage(t *testing.T, notices chan sidecar.PushNotice, version uint64) {
	t.Helper()
	for {
		notice := testPushPollAwait(t, notices, "the page's notice")
		if notice.Version == version && notice.Resync {
			return
		}
	}
}

// A reconnect during a failed refetch's 5 min retry wait refetches at once, the clock unmoved, and the
// page it fetches applies; the wait's own end is never reached.
func TestPushReconnectEndsAFiveMinuteRetryWait(t *testing.T) {
	api := newTestPushRetryApi()
	client, notices := newTestPushRetryClient(t, api)
	settings := sidecar.DefaultPushClientSettings()
	retryTime := api.walkToRetryWait(t, settings.RetryMaxInterval)
	waitTime := api.clock.Now()
	if wait := retryTime.Sub(waitTime); wait != 5*time.Minute {
		t.Fatalf("the longest wait is %s", wait)
	}

	api.refuse(false)
	client.Resync()
	if refetchTime := testPushPollAwait(t, api.refetchTimes, "the reconnect's refetch"); !refetchTime.Equal(waitTime) {
		t.Errorf("the reconnect's refetch began at %s, its wait at %s", refetchTime, waitTime)
	}
	awaitTestPushRetryPage(t, notices, 7)
	if !api.clock.Now().Equal(waitTime) || !slices.ContainsFunc(api.clock.PendingTimers(), retryTime.Equal) {
		t.Errorf("the clock moved to %s, timers %v", api.clock.Now(), api.clock.PendingTimers())
	}
}

// A seq gap and a poll's incomplete reset during the 5 min wait each ask for versions, and neither ends
// the wait: the asks are kept and served by the refetch at its end, after which none is left to ask
// again.
func TestPushAskDuringARetryWaitWaitsForItsEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		api := newTestPushRetryApi()
		_, notices := newTestPushRetryClient(t, api)
		settings := sidecar.DefaultPushClientSettings()
		retryTime := api.walkToRetryWait(t, settings.RetryMaxInterval)

		for _, ask := range []struct {
			what     string
			response *protocol.PollResponse
		}{
			{
				what: "a seq gap",
				response: &protocol.PollResponse{Cursor: []byte("c1"), Hints: []*protocol.PushHint{
					{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 1},
					{Seq: 3, Topic: sidecar.PushTopicTeam, Version: 2},
				}},
			},
			{
				what: "an incomplete reset",
				response: &protocol.PollResponse{Cursor: []byte("c2"), Reset_: &protocol.PushReset{
					Epoch:    2,
					Complete: false,
					Versions: []*protocol.TopicVersion{{Topic: sidecar.PushTopicTeam, Version: 9}},
				}},
			},
		} {
			api.answerPoll(t, testPushRetryAnswer{response: ask.response})
			// the poll loop holds its next poll, and the resync loop has taken the ask in
			synctest.Wait()
			api.expectNoRefetch(t, ask.what)
		}
		// the gap's two hints applied, the incomplete reset nothing
		if noticeCount := len(notices); noticeCount != 2 {
			t.Errorf("%d notices, want the gap's two hints", noticeCount)
		}

		api.refuse(false)
		api.clock.AdvanceTo(retryTime)
		if refetchTime := testPushPollAwait(t, api.refetchTimes, "the retry"); !refetchTime.Equal(retryTime) {
			t.Errorf("the retry began at %s, its wait ended at %s", refetchTime, retryTime)
		}
		awaitTestPushRetryPage(t, notices, 7)
		synctest.Wait()
		api.expectNoRefetch(t, "an ask the retry served")
	})
}

// A reconnect ends a 4 s wait, the third, and its refetch is refused again: the next wait is 8 s, doubling
// from the wait it ended, and the one after 16 s.
func TestPushRetryAfterAReconnectGoesOnDoubling(t *testing.T) {
	api := newTestPushRetryApi()
	client, _ := newTestPushRetryClient(t, api)
	settings := sidecar.DefaultPushClientSettings()
	endedTime := api.walkToRetryWait(t, 4*settings.RetryMinInterval)

	client.Resync()
	retryTime := api.awaitRefusedRefetch(t, 8*settings.RetryMinInterval)
	// the ended wait's timer, left to fire for nothing, and the next wait's: no shorter one
	if timers := api.clock.PendingTimers(); !slices.EqualFunc(timers, []time.Time{endedTime, retryTime}, time.Time.Equal) {
		t.Errorf("timers %v, want the ended wait's at %s and the next at %s", timers, endedTime, retryTime)
	}
	api.clock.AdvanceTo(retryTime)
	api.awaitRefusedRefetch(t, 16*settings.RetryMinInterval)
}

// The long-poll's first poll answered after a failure is its reconnect: an answered poll with no failure
// before it leaves the 5 min wait be, and so does the failure, while the poll answered after the failure's
// backoff ends the wait at once. With no wait pending, the next poll answered after a failure refetches
// too.
func TestPushPollFirstSuccessAfterAFailureResyncs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		api := newTestPushRetryApi()
		_, notices := newTestPushRetryClient(t, api)
		settings := sidecar.DefaultPushClientSettings()
		retryTime := api.walkToRetryWait(t, settings.RetryMaxInterval)
		unavailable := &sidecar.SidecarApiError{Route: "GET /sidecar/sync/poll", Status: 503}

		api.answerPoll(t, testPushRetryAnswer{response: &protocol.PollResponse{Cursor: []byte("c1")}})
		synctest.Wait()
		api.expectNoRefetch(t, "a poll answered with no failure before it")

		// a failure, then the poll after its backoff answered: a reconnect
		failover := func(what string) {
			t.Helper()
			api.answerPoll(t, testPushRetryAnswer{err: unavailable})
			backoffTime := api.clock.Now().Add(settings.RetryMinInterval)
			api.awaitTimerAt(t, backoffTime, "the poll's backoff")
			synctest.Wait()
			api.expectNoRefetch(t, "a failed poll")
			api.clock.AdvanceTo(backoffTime)
			api.answerPoll(t, testPushRetryAnswer{response: &protocol.PollResponse{Cursor: []byte("c2")}})
			if refetchTime := testPushPollAwait(t, api.refetchTimes, what); !refetchTime.Equal(backoffTime) {
				t.Errorf("%s began at %s, the poll answered at %s", what, refetchTime, backoffTime)
			}
		}
		api.refuse(false)
		failover("the long-poll's reconnect's refetch")
		if !api.clock.Now().Before(retryTime) {
			t.Fatalf("the clock reached the wait's end")
		}
		awaitTestPushRetryPage(t, notices, 7)

		// the hourly wait now stands, and the next reconnect refetches as well
		failover("a later reconnect's refetch")
		synctest.Wait()
		api.expectNoRefetch(t, "the reconnect's refetch, again")
	})
}
