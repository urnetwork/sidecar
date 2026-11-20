// FS-31's connection guard on a fake clock (fs31GuardSettings): a part at the edge waits up to PartTimeout for its
// answer and every other wait up to ConnectionTimeout, each answer starts the next wait's allowance afresh, so a case
// takes as long as its parts need, a timer left from an earlier wait ends nothing, and a hang, before any part or in
// the edge's answer, ends the connection's context with a cause naming the wait.

package smtpproof

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A guard on a fake clock with this test's allowances: a minute for a wait with no part at the edge, ten for a part's
// answer.
func testFs31Guard() (*fs31Guard, *sidecartest.FakeClock) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := &fs31GuardSettings{ConnectionTimeout: time.Minute, PartTimeout: 10 * time.Minute}
	return newFs31Guard(settings, clock), clock
}

// Fails unless the guard has ended its connection exactly when want names a wait, its context's cause the guard's
// own, naming that wait.
func testExpectGuard(t *testing.T, step string, guard *fs31Guard, want string) {
	t.Helper()
	err := guard.expired()
	cause := context.Cause(guard.context())
	switch {
	case want == "" && (err != nil || cause != nil):
		t.Errorf("%s: the guard ended the connection: %v, %v", step, err, cause)
	case want != "" && err == nil:
		t.Errorf("%s: the guard did not end the connection, its context's cause %v", step, cause)
	case want != "" && (cause != err || !strings.Contains(err.Error(), want)):
		t.Errorf("%s: the guard's cause %v and its context's %v, want one naming %q", step, err, cause, want)
	}
}

func TestFs31GuardEndsAConnectionThatHangsBeforeAnyPart(t *testing.T) {
	guard, clock := testFs31Guard()
	defer guard.end()
	clock.Advance(time.Minute - time.Second)
	testExpectGuard(t, "short of the connection's allowance", guard, "")
	clock.Advance(time.Second)
	testExpectGuard(t, "at the connection's allowance", guard, "the connection before its first part")
}

func TestFs31GuardGivesAPartAtTheEdgeItsOwnAllowance(t *testing.T) {
	guard, clock := testFs31Guard()
	defer guard.end()
	clock.Advance(30 * time.Second)
	guard.partSubmitted(1)
	// the connection's minute passes, and the part's answer is still within its ten
	clock.Advance(time.Minute)
	testExpectGuard(t, "a minute into the part", guard, "")
	clock.Advance(9*time.Minute - time.Second)
	testExpectGuard(t, "short of the part's allowance", guard, "")
	clock.Advance(time.Second)
	testExpectGuard(t, "at the part's allowance", guard, "part 1's answer from the edge")
}

func TestFs31GuardStartsEachWaitsAllowanceAfresh(t *testing.T) {
	guard, clock := testFs31Guard()
	defer guard.end()
	// six parts each slow at the edge and between, an hour in all, end nothing
	for index := uint32(1); index <= 6; index += 1 {
		clock.Advance(time.Minute - time.Second)
		guard.partSubmitted(index)
		clock.Advance(10*time.Minute - time.Second)
		guard.partAnswered()
	}
	testExpectGuard(t, "after six slow parts", guard, "")
	clock.Advance(time.Minute - time.Second)
	testExpectGuard(t, "short of the last wait's allowance", guard, "")
	clock.Advance(time.Second)
	testExpectGuard(t, "past the last part's answer", guard, "the connection after part 6's answer")
}

func TestFs31GuardEndsNothingFromAnEarlierWaitsTimer(t *testing.T) {
	guard, clock := testFs31Guard()
	defer guard.end()
	guard.partSubmitted(1)
	stale := func() uint64 {
		guard.stateLock.Lock()
		defer guard.stateLock.Unlock()
		return guard.generation
	}()
	guard.partAnswered()
	// the part's timer firing after its answer began the next wait, as a real clock's may
	guard.expire(stale, errors.New("a stale timer"))
	testExpectGuard(t, "a stale timer", guard, "")
	// and the wait after the answer keeps its own allowance
	clock.Advance(time.Minute)
	testExpectGuard(t, "the wait after the answer", guard, "the connection after part 1's answer")
}

func TestFs31GuardStopsWithItsConnection(t *testing.T) {
	guard, clock := testFs31Guard()
	guard.partSubmitted(1)
	guard.end()
	if pending := clock.PendingTimers(); len(pending) != 0 {
		t.Errorf("timers still set once the guard ended: %v", pending)
	}
	clock.Advance(time.Hour)
	if err := guard.expired(); err != nil {
		t.Errorf("an ended guard expired: %v", err)
	}
	if cause := context.Cause(guard.context()); !errors.Is(cause, context.Canceled) {
		t.Errorf("an ended guard's context: %v", cause)
	}
}

// An edge that never answers: each part waits until its context ends.
type testHungEdgeChannel struct {
	entered chan uint32
}

func (self *testHungEdgeChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	return nil
}

func (self *testHungEdgeChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	self.entered <- part.Index
	<-ctx.Done()
	return ctx.Err()
}

// Through the connection's recording channel, as fs31Run wires it: a part whose answer never comes keeps the part's
// allowance, not the connection's, and the guard ends it there with a cause naming the part.
func TestFs31GuardEndsAPartTheEdgeNeverAnswers(t *testing.T) {
	guard, clock := testFs31Guard()
	defer guard.end()
	inner := &testHungEdgeChannel{entered: make(chan uint32, 1)}
	recorder := &fs31RecordingChannel{inner: inner, guard: guard}
	answered := make(chan error, 1)
	go func() {
		answered <- recorder.SubmitPart(guard.context(), &sidecar.SmtpProofPart{Index: 1})
	}()
	if index := <-inner.entered; index != 1 {
		t.Fatalf("part %d reached the edge", index)
	}
	clock.Advance(time.Minute)
	testExpectGuard(t, "a minute at the edge", guard, "")
	clock.Advance(9 * time.Minute)
	if err := <-answered; !errors.Is(err, context.Canceled) {
		t.Errorf("the hung part returned %v", err)
	}
	testExpectGuard(t, "the part's allowance", guard, "part 1's answer from the edge")
	if refusedIndex, acceptedParts := recorder.refused(); refusedIndex != 1 || len(acceptedParts) != 0 {
		t.Errorf("the recorder kept part %d refused and %d taken", refusedIndex, len(acceptedParts))
	}
}
