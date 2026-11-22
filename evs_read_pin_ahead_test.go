// QD-1202 (question e2e-evs-verify-statement-pin-ahead-of-reader, option 1) on the stand-in evs: a reader whose config
// is a ConfigClient following the log through api's projection, which serves only what the test publishes, so the
// device's log lags a faster writer's by a base, as a follower lags a hint by a moment. A read of a head pushed under
// the base the follower does not hold yet waits for its log to reach the pin and verifies the statement at its own pin;
// a write planned over such a head lands; a pin the log does not reach within the bound is withheld, with no alarm and
// nothing counting api as withholding it; a forged statement at such a pin, or a pin off the chain there, is still
// refused once the log reaches it; and the config follower's own reads never wait.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A retained world whose log a ConfigClient follows through api's projection: the writer's log is the net's own, at
// its tip, and the follower's what the test published of it.
type evsTestPinAheadWorld struct {
	*evsTestRetainedWorld
	config *testConfigClientWorld
	client *ConfigClient
	// each position a reader of the world asked its log to reach, in order
	waits chan uint64
}

// The world, its follower caught up to the net's tip.
func newEvsTestPinAheadWorld(t *testing.T) *evsTestPinAheadWorld {
	t.Helper()
	config := newTestConfigClientWorld(t)
	self := &evsTestPinAheadWorld{
		evsTestRetainedWorld: newEvsTestRetainedWorldOn(t, config.net),
		config:               config,
		waits:                make(chan uint64, 64),
	}
	config.publish()
	self.client = config.client(nil)
	config.caughtUp(self.client)
	return self
}

// Serves what the net sequenced since, and hints the follower, as api's team push does.
func (self *evsTestPinAheadWorld) publish() {
	self.config.publish()
	self.client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: self.net.n})
}

// publish, then waits for the follower to reach the net's tip.
func (self *evsTestPinAheadWorld) catchUp() {
	self.publish()
	self.config.caughtUp(self.client)
}

// A base folding the net's tip under the next config version, as a confirmed ACL save lands one: the net's log holds it
// at once, the follower only once it is published. Its pin.
func (self *evsTestPinAheadWorld) base() *bridge.AuthPin {
	self.net.t.Helper()
	configVersion := self.net.log.State().Base().GetConfigVersion() + 1
	if verdict := self.net.fold(self.net.owner, self.net.n, configVersion); !verdict.Accepted() {
		self.net.t.Fatalf("the base at %d: %v", verdict.Pin.GetVersion(), verdict.Refusal)
	}
	return self.net.log.Pin()
}

// Has test judge at the follower's verified state, waiting through WaitForPin for a pin above it and naming each such
// pin on waits.
func (self *evsTestPinAheadWorld) follow(test *evsTestClient) {
	client := self.client
	test.client.args.Config = func() GkmAuthView {
		// never a typed nil: nothing verifies before the first state
		if state := client.State(); state != nil {
			return state
		}
		return nil
	}
	test.client.args.ConfigWait = func(ctx context.Context, n uint64) error {
		self.waits <- n
		_, err := client.WaitForPin(ctx, n)
		return err
	}
}

// A reader of the world judging at the follower's state.
func (self *evsTestPinAheadWorld) reader(t *testing.T, label string) *evsTestClient {
	t.Helper()
	reader := self.world.reader(t, evsTestId(label))
	self.follow(reader)
	return reader
}

// The next position a reader asked its log to reach.
func (self *evsTestPinAheadWorld) nextWait(t *testing.T) uint64 {
	t.Helper()
	select {
	case n := <-self.waits:
		return n
	case <-time.After(30 * time.Second):
		t.Fatal("no reader asked its log to reach a pin")
		return 0
	}
}

// A read's answer.
type evsTestPinAheadRead struct {
	content []byte
	info    *EvsFileInfo
	err     error
}

// Reads path as reader on a goroutine of its own, which a read waiting on its log needs: the answer comes on the
// channel. A read still waiting when the test ends answers once the follower closes.
func (self *evsTestPinAheadWorld) readAsync(reader *evsTestClient, path string) chan evsTestPinAheadRead {
	done := make(chan evsTestPinAheadRead, 1)
	go func() {
		out := &bytes.Buffer{}
		info, err := reader.client.Repo(self.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
		done <- evsTestPinAheadRead{content: out.Bytes(), info: info, err: err}
	}()
	return done
}

// Requires that the read on done has not answered: it waits for its log.
func evsTestRequireWaiting[T any](t *testing.T, label string, done chan T) {
	t.Helper()
	select {
	case answer := <-done:
		t.Fatalf("%s answered before its log reached the pin: %+v", label, answer)
	default:
	}
}

// The answer on done.
func evsTestAnswer[T any](t *testing.T, label string, done chan T) T {
	t.Helper()
	select {
	case answer := <-done:
		return answer
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not answer", label)
		var none T
		return none
	}
}

// A bound a reader's wait armed on its clock, and what ends the wait as the bound passing does.
type evsTestPinWaitBound struct {
	timeout time.Duration
	expire  func()
}

// The evs test clock, but each AfterFunc fires only when the test ends it: every one armed goes on bounds.
type evsTestPinWaitClock struct {
	*evsTestClock
	bounds chan evsTestPinWaitBound
}

// Arms a bound only the test ends, by calling its expire.
func (self *evsTestPinWaitClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	self.bounds <- evsTestPinWaitBound{timeout: timeout, expire: function}
	return func() bool { return true }
}

// Gives reader a clock whose bounds the test ends, and the bounds as its waits arm them.
func evsTestBoundedReader(reader *evsTestClient) chan evsTestPinWaitBound {
	bounds := make(chan evsTestPinWaitBound, 16)
	reader.client.clock = &evsTestPinWaitClock{evsTestClock: reader.clock, bounds: bounds}
	return bounds
}

// A read of a head pushed under a base one ahead of the reader's follower waits for the follower to reach it, which it
// does once api serves the base, and then verifies the statement at its own pin: the read gives the content, pins the
// head and raises no alarm. Before the change the read failed at once with ErrConfigPinAhead.
func TestEvsReadWaitsForItsLogToReachAPinOneBaseAhead(t *testing.T) {
	ahead := newEvsTestPinAheadWorld(t)
	ahead.push(&evsTestChange{path: "a.txt", content: []byte("before the base")})
	reader := ahead.reader(t, "reader whose log lags")
	ahead.requireReads(t, "before the base", reader, "a.txt", "before the base")
	behind := ahead.client.Pin().GetVersion()
	pin := ahead.base()
	version := ahead.push(&evsTestChange{path: "a.txt", content: []byte("under the new base")})

	done := ahead.readAsync(reader, "a.txt")
	if n := ahead.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("the read asked its log to reach %d, not the push's pin %d", n, pin.GetVersion())
	}
	evsTestRequireWaiting(t, "the read", done)
	if got := ahead.client.Pin().GetVersion(); got != behind {
		t.Fatalf("the follower stands at %d before api serves the base, not %d", got, behind)
	}
	ahead.publish()
	read := evsTestAnswer(t, "the read", done)
	if read.err != nil || string(read.content) != "under the new base" {
		t.Fatalf("the read gave %q: %v", read.content, read.err)
	}
	evsTestRequireNoAlarm(t, "the reader", reader)
	if got := ahead.client.Pin().GetVersion(); got != pin.GetVersion() {
		t.Errorf("the follower stands at %d, not the base's %d", got, pin.GetVersion())
	}
	if evsPin, ok, _ := reader.client.pins.Pin(ahead.repoId, ahead.world.refId); !ok || evsPin.Version != version {
		t.Errorf("the ref's pin %+v, the head %d", evsPin, version)
	}
}

// A writer whose follower lags plans over a head a faster device pushed under a base one ahead of it: the plan's read
// waits for the follower to reach the base, the push is built at the state reached, and it lands; a reader at the tip
// then reads every file, the walk's pins rising through the base.
func TestEvsWritePlannedOverAHeadPinnedOneBaseAheadLands(t *testing.T) {
	ahead := newEvsTestPinAheadWorld(t)
	faster := ahead.net.admitMemberDevice("faster writer")
	ahead.grantWriter(faster)
	ahead.catchUp()
	ahead.push(&evsTestChange{path: "docs/a.txt", content: []byte("before the base")})
	writer := ahead.writerOf(t, ahead.writer)
	ahead.follow(writer.test)
	pin := ahead.base()
	ahead.signAs(faster)
	ahead.push(&evsTestChange{path: "docs/b.txt", content: []byte("by the faster writer under the new base")})

	done := make(chan error, 1)
	content := []byte("planned over the faster writer's head")
	writer.server.know("docs/c.txt")
	go func() {
		_, err := writer.repo.Write(context.Background(), &EvsWriteArgs{Path: "docs/c.txt", Content: bytes.NewReader(content), Size: int64(len(content))})
		done <- err
	}()
	if n := ahead.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("the plan asked its log to reach %d, not the head's pin %d", n, pin.GetVersion())
	}
	evsTestRequireWaiting(t, "the write", done)
	ahead.publish()
	if err := evsTestAnswer(t, "the write", done); err != nil {
		t.Fatalf("a write planned over a head pinned one base ahead: %v", err)
	}
	evsTestRequireNoAlarm(t, "the writer", writer.test)
	reader := ahead.follower(t, "reader at the tip")
	ahead.requireReads(t, "the reader at the tip", reader, "docs/a.txt", "before the base")
	ahead.requireReads(t, "the reader at the tip", reader, "docs/b.txt", "by the faster writer under the new base")
	ahead.requireReads(t, "the reader at the tip", reader, "docs/c.txt", string(content))
}

// A pin the reader's log does not reach within the bound, a base api never serves, is withheld once the bound passes:
// the read answers ErrConfigPinAhead under ErrEvsStatementRefused as before, alarms nothing and pins nothing, and the
// follow the wait asked for counts nothing against api, which never served the pin (WaitForPin records no hint).
func TestEvsPinTheLogDoesNotReachWithinTheBoundIsWithheld(t *testing.T) {
	ahead := newEvsTestPinAheadWorld(t)
	reader := ahead.reader(t, "reader whose log stays behind")
	bounds := evsTestBoundedReader(reader)
	behind := ahead.client.Pin().GetVersion()
	pin := ahead.base()
	ahead.push(&evsTestChange{path: "a.txt", content: []byte("pinned past the reader's log")})

	done := ahead.readAsync(reader, "a.txt")
	bound := evsTestAnswer(t, "the wait's bound", bounds)
	if bound.timeout != reader.client.settings.AuthPinWaitTimeout || bound.timeout != DefaultConfigClientSettings().FollowTimeout {
		t.Fatalf("the wait's bound %s, the setting %s", bound.timeout, reader.client.settings.AuthPinWaitTimeout)
	}
	if n := ahead.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("the read asked its log to reach %d, not the push's pin %d", n, pin.GetVersion())
	}
	evsTestRequireWaiting(t, "the read", done)
	bound.expire()
	read := evsTestAnswer(t, "the read", done)
	if !errors.Is(read.err, ErrEvsStatementRefused) || !errors.Is(read.err, ErrConfigPinAhead) {
		t.Fatalf("the read past the bound: %v", read.err)
	}
	evsTestRequireNoAlarm(t, "the reader", reader)
	if _, ok, _ := reader.client.pins.Pin(ahead.repoId, ahead.world.refId); ok {
		t.Error("the reader pinned a head it withheld")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ahead.client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ahead.client.Pin().GetVersion(); got != behind {
		t.Errorf("the follower stands at %d, not %d", got, behind)
	}
	if alarms := ahead.config.headAlarms(SidecarHeadAlarmWithheld); alarms != 0 {
		t.Errorf("the follower counted api withholding a pin only evs named: %d alarms", alarms)
	}
}

// A statement pinned one base ahead that no writer validly signed at that pin is still refused, and alarmed as
// tampering, once the reader's log reaches the pin: one whose signature its signer's key does not verify, and one whose
// pin names another chain value at the base's position. The wait judges a statement at its own pin; it takes nothing.
func TestEvsForgedStatementPinnedOneBaseAheadRefusedOnceTheLogReachesIt(t *testing.T) {
	cases := []struct {
		label string
		// pushes path at pin as evs serves it, a forgery
		forge func(ahead *evsTestPinAheadWorld, pin *bridge.AuthPin, path string)
		// what the refusal also names
		reason error
	}{
		{label: "a signature by another key", forge: func(ahead *evsTestPinAheadWorld, pin *bridge.AuthPin, path string) {
			forger := newEvsTestSigner("forger")
			ahead.world.signer = &evsTestSigner{sidecarId: ahead.writer.sidecarId, privateKey: forger.privateKey}
			ahead.pushAt(pin, &evsTestChange{path: path, content: []byte("forged")})
		}},
		{label: "a pin off the chain", forge: func(ahead *evsTestPinAheadWorld, pin *bridge.AuthPin, path string) {
			offChain := &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())}
			offChain.Chain[0] ^= 0xff
			ahead.pushAt(offChain, &evsTestChange{path: path, content: []byte("off the chain")})
		}, reason: ErrGkmAuthOffChain},
	}
	for _, c := range cases {
		ahead := newEvsTestPinAheadWorld(t)
		ahead.push(&evsTestChange{path: "a.txt", content: []byte("genuine")})
		reader := ahead.reader(t, "reader whose log lags "+c.label)
		ahead.requireReads(t, c.label, reader, "a.txt", "genuine")
		pin := ahead.base()
		c.forge(ahead, pin, "b.txt")

		done := ahead.readAsync(reader, "b.txt")
		if n := ahead.nextWait(t); n != pin.GetVersion() {
			t.Fatalf("%s: the read asked its log to reach %d, not %d", c.label, n, pin.GetVersion())
		}
		ahead.publish()
		read := evsTestAnswer(t, c.label, done)
		if !errors.Is(read.err, ErrEvsStatementRefused) || errors.Is(read.err, ErrConfigPinAhead) || (c.reason != nil && !errors.Is(read.err, c.reason)) {
			t.Errorf("%s: %v", c.label, read.err)
		}
		evsTestRequireTamper(t, c.label, reader, 1)
		if got := ahead.client.Pin().GetVersion(); got != pin.GetVersion() {
			t.Errorf("%s: the follower stands at %d, not the base's %d", c.label, got, pin.GetVersion())
		}
	}
}

// The config follower reads a base's head on its own follow, so its walk withholds a statement pinned above the
// state at once and never asks its log to wait (withholdingAhead); the same walk on the reader's own verifier waits.
func TestEvsConfigFollowersOwnWalkNeverWaits(t *testing.T) {
	ahead := newEvsTestPinAheadWorld(t)
	reader := ahead.reader(t, "the follower's head reader")
	ahead.base()
	version := ahead.push(&evsTestChange{path: "a.txt", content: []byte("pinned past the follower's state")})
	ctx := context.Background()
	statements, err := reader.client.readLog(ctx, ahead.repoId, ahead.world.refId, 1, version)
	if err != nil {
		t.Fatal(err)
	}
	start := EvsChainStart(ahead.repoId, ahead.world.refId)
	_, err = reader.client.verifier.withholdingAhead().walk(ctx, ahead.repoId, ahead.world.refId, 0, start, statements, version)
	if !errors.Is(err, ErrConfigPinAhead) {
		t.Fatalf("the follower's own walk: %v", err)
	}
	select {
	case n := <-ahead.waits:
		t.Fatalf("the follower's own walk asked its log to reach %d", n)
	default:
	}
	evsTestRequireNoAlarm(t, "the follower's head reader", reader)

	// the reader's own verifier waits for the same statement, and judges it once the log is there
	done := make(chan error, 1)
	go func() {
		_, err := reader.client.verifier.walk(ctx, ahead.repoId, ahead.world.refId, 0, start, statements, version)
		done <- err
	}()
	ahead.nextWait(t)
	evsTestRequireWaiting(t, "the reader's walk", done)
	ahead.publish()
	if err := evsTestAnswer(t, "the reader's walk", done); err != nil {
		t.Errorf("the reader's walk once its log reached the pin: %v", err)
	}
}

// A subscriber whose follower lags hears a commit a faster device pushed under a base one ahead of it: the round that
// reads what the hint moved waits for its log to reach the base, then verifies the statement and raises its change.
func TestEvsSubscriberWaitsForItsLogToReachAPinOneBaseAhead(t *testing.T) {
	ahead := newEvsTestPinAheadWorld(t)
	ahead.push(&evsTestChange{path: "docs/a", content: []byte("before the base")})
	leases := newEvsTestLeases(ahead.world)
	subscriber := newEvsSubscribeTest(t, ahead.world, leases, newEvsTestStore(t))
	// the hourly resync half an hour on, out of this test's way
	subscriber.client.subscriber.random = func(limit time.Duration) time.Duration { return limit / 2 }
	ahead.follow(subscriber)
	listened := &evsTestChanges{}
	remove := subscriber.client.AddRepoChangeListener(&ahead.repoId, listened.add)
	defer remove()
	ctx := context.Background()
	if _, err := subscriber.client.Repo(ahead.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	subscriber.clock.advance(subscriber.client.settings.SubscribeRereadDelay)
	subscriber.client.subscriber.runDue(ctx)
	pin := ahead.base()
	version := ahead.push(&evsTestChange{path: "docs/b", content: []byte("by a faster device under the new base")})
	ahead.world.hint(subscriber, 100)

	done := make(chan struct{})
	go func() {
		defer close(done)
		subscriber.client.subscriber.runDue(ctx)
	}()
	if n := ahead.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("the round asked its log to reach %d, not the commit's pin %d", n, pin.GetVersion())
	}
	evsTestRequireWaiting(t, "the round", done)
	ahead.publish()
	evsTestAnswer(t, "the round", done)
	change := listened.last()
	if change == nil || change.Version != version || len(change.Paths) != 1 || change.Paths[0] != "docs" || change.Gap {
		t.Fatalf("the round raised %+v, not the commit at %d", change, version)
	}
	evsTestRequireNoAlarm(t, "the subscriber", subscriber)
}

// A mirror whose device's follower lags syncs a ref a faster device pushed to under a base one ahead of it: the sync's
// walk waits for the follower to reach the base, and the mirror then holds the head.
func TestEvsMirrorSyncWaitsForItsLogToReachAPinOneBaseAhead(t *testing.T) {
	ahead := newEvsTestPinAheadWorld(t)
	ahead.push(&evsTestChange{path: "a.txt", content: []byte("before the base")})
	reader := ahead.reader(t, "mirroring device whose log lags")
	pin := ahead.base()
	version := ahead.push(&evsTestChange{path: "b.txt", content: []byte("by a faster device under the new base")})
	mirror, err := NewEvsMirror(reader.client, ahead.repoId, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := mirror.Sync(context.Background())
		done <- err
	}()
	if n := ahead.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("the sync asked its log to reach %d, not the commit's pin %d", n, pin.GetVersion())
	}
	evsTestRequireWaiting(t, "the sync", done)
	ahead.publish()
	if err := evsTestAnswer(t, "the sync", done); err != nil {
		t.Fatalf("the sync once its log reached the pin: %v", err)
	}
	if ref, ok, err := mirror.store.Ref(ahead.world.refId); err != nil || !ok || ref.Version != version {
		t.Errorf("the mirror holds %+v %v %v, not the head %d", ref, ok, err, version)
	}
	evsTestRequireNoAlarm(t, "the mirroring device", reader)
}
