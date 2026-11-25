// advanceUntil against the lost wakeup that hung tip-check in
// TestAdvanceUntilMovesTheClockOnlyToATimerSet. The helper read done, and only then took where the loop
// and the writer were parked and the timers set, with the channels it waited on. A loop that answered
// its held poll and parked again between the two left it acting on a read the change had outdated:
// with no timer set it waited on channels nothing would close, and with one set it moved the clock to
// it though done already held. Here the loop answers only from inside done, after its read, so that
// change lands between the read and whatever the helper does next on every run, not only on a loaded
// machine.

package dnsservice_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A loop serving serial 1 from a scripted block, its writer's first write done, parked in its second
// poll. The block holds that poll until the clock reaches holdEnd and then answers it empty, but the
// end the clock fires reaches the loop only through answered: until then the loop is woken and has
// not run, as on a loaded machine.
type advanceRace struct {
	feed     *testFeed
	scripted *scriptedFeed
	loop     *dnsservice.FeedLoop
	clock    *sidecartest.FakeClock
	start    time.Time
	holdEnd  time.Time
	// the hold's end as the clock fires it, and the channel the loop's poll waits on for it
	fired <-chan time.Time
	held  chan time.Time

	// the clock's time at done's reads, each time once
	readings []time.Time
	// whether a read has let the loop answer its held poll and park in its next
	landed bool
}

// Leaves the loop in its second poll with the held answer queued, the clock still at start.
func newAdvanceRace(t *testing.T) *advanceRace {
	t.Helper()
	feed := newTestFeed(t)
	scripted := newScriptedFeed()
	loop := feed.start(t, feed.deps(scripted, feed.edge), feed.edge)
	clock := feed.edge.clock
	scripted.queue(&dnsservice.DnsFeedAnswer{
		Format:    dnsservice.DnsFormat,
		Root:      edgeTestRoot,
		Serial:    1,
		Rows:      []dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 1, Upserts: edgeTestRows()}},
		KeyWindow: feed.edge.keys.window,
	}, nil)
	awaitServed(t, feed.edge, 1)
	// with the loop polling, the writer's interval is the one timer set; once it writes, it parks with
	// none
	if err := clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Duration(feed.edge.settings.Feed.SnapshotWriteSeconds) * time.Second)
	awaitWritten(t, loop, 1)
	// the loop is in its second poll, which takes the held answer, so the count stays put until it
	// answers
	scripted.awaitPolls(t, 2)

	start := clock.Now()
	hold := 7 * time.Second
	self := &advanceRace{
		feed:     feed,
		scripted: scripted,
		loop:     loop,
		clock:    clock,
		start:    start,
		holdEnd:  start.Add(hold),
		fired:    clock.After(hold),
		held:     make(chan time.Time, 1),
	}
	scripted.queueHeld(self.held, &dnsservice.DnsFeedAnswer{
		Format:    dnsservice.DnsFormat,
		Root:      edgeTestRoot,
		Serial:    1,
		KeyWindow: feed.edge.keys.window,
	})
	return self
}

// done for advanceUntil: the held poll answered. The first read at the hold's end finds it not, and
// before returning that, hands the loop the hold's end and waits until the loop has answered the poll
// and parked in its next, which nothing answers and which sets no timer.
func (self *advanceRace) answered(t testing.TB) bool {
	t.Helper()
	now := self.clock.Now()
	if len(self.readings) == 0 || !self.readings[len(self.readings)-1].Equal(now) {
		self.readings = append(self.readings, now)
	}
	answered := self.feed.edge.host.Metrics.Value("urnetwork_dnsedge_feed_polls_total", "empty") != 0
	if !answered && !self.landed && !now.Before(self.holdEnd) {
		self.landed = true
		// the loop is still in the held poll, so no other poll has begun
		polls := self.scripted.polls.Value()
		self.held <- <-self.fired
		self.scripted.awaitPolls(t, polls+1)
	}
	return answered
}

// The interleaving that hung tip-check: after done's read finds the held poll not yet answered, the
// loop answers it and parks in its next poll, with no timer set. The channels the helper took before
// that read have closed, so it reads done again and returns, with the clock at the hold's end. When it
// took them after the read, it waited for good; the guard fails that and sets a timer to wake it.
func TestAdvanceUntilWakesWhenTheLoopParksAgainAfterItsCheck(t *testing.T) {
	race := newAdvanceRace(t)
	returned := make(chan struct{})
	guarded := make(chan struct{})
	go func() {
		defer close(guarded)
		select {
		case <-returned:
		case <-time.After(time.Minute):
			t.Errorf("advanceUntil waits on channels nothing closes, the clock at %v", race.clock.Now())
			race.clock.After(time.Hour)
		}
	}()
	// joined however the helper ends, so the guard never outlives the test
	defer func() {
		close(returned)
		<-guarded
	}()
	advanceUntil(t, race.clock, race.loop, "the held poll answered", func() bool {
		return race.answered(t)
	})
	if !race.landed {
		t.Fatal("the loop answered before any read of done found it not")
	}
	if !slices.EqualFunc(race.readings, []time.Time{race.start, race.holdEnd}, time.Time.Equal) {
		t.Errorf("the clock read %v, want %v and then the hold's end %v", race.readings, race.start, race.holdEnd)
	}
}

// The same change with another timer set, as a wait elsewhere sets one: the helper sees that its state
// changed while done read, takes it again rather than move the clock on it, and returns with the clock
// at the hold's end and the other timer still set. Acting on the read the change had outdated, it moved
// the clock to that timer though done already held.
func TestAdvanceUntilNeverMovesTheClockOnAnOutdatedCheck(t *testing.T) {
	race := newAdvanceRace(t)
	race.clock.After(time.Hour)
	other := race.start.Add(time.Hour)
	advanceUntil(t, race.clock, race.loop, "the held poll answered", func() bool {
		return race.answered(t)
	})
	if !race.landed {
		t.Fatal("the loop answered before any read of done found it not")
	}
	if !slices.EqualFunc(race.readings, []time.Time{race.start, race.holdEnd}, time.Time.Equal) {
		t.Errorf("the clock read %v, want %v and then the hold's end %v", race.readings, race.start, race.holdEnd)
	}
	if pending := race.clock.PendingTimers(); !slices.ContainsFunc(pending, other.Equal) {
		t.Errorf("timers %v, want the other one at %v still set", pending, other)
	}
}
