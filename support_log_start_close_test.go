//go:build sidecar_testhooks && !ios_extension && !sidecar_http

// SupportLog.Start against a Close that overtakes it (QD-1451), held at Start's barriers: support_log.start.before,
// between its read of closed and its read again under fileLock, and support_log.start.after, once that read has passed
// and Start holds fileLock for its file work. A Close that lands between the reads leaves Start refusing, with nothing
// on disk while Close runs or once it has returned; a Close that begins during Start's file work waits for it in the
// writer's last flush, so the events the ring held are on disk when Close returns.

package sidecar

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Start held at each of its barriers in turn, telling the test which one it reached, until the test releases it.
type supportLogStartBarriers struct {
	reached chan string
	proceed chan struct{}
	// frees a Start held at a barrier once the test ends
	done chan struct{}
	// the Starts begun on their own goroutines, which the test's end waits for
	group sync.WaitGroup
}

// Holds the Start of the ring in directory at its barriers until the test's end, which frees and waits for any it
// holds; another ring's Start passes, since the barriers are keyed by the ring's directory. Install it after opening
// the ring, so that cleanup runs before the ring's Close, which would wait for a held Start's fileLock, and before the
// test's directory is removed.
func holdSupportLogStart(t *testing.T, directory string) *supportLogStartBarriers {
	barriers := &supportLogStartBarriers{reached: make(chan string), proceed: make(chan struct{}), done: make(chan struct{})}
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if !strings.HasPrefix(name, "support_log.start.") || key != directory {
			return
		}
		select {
		case barriers.reached <- name:
		case <-barriers.done:
			return
		}
		select {
		case <-barriers.proceed:
		case <-barriers.done:
		}
	}})
	t.Cleanup(func() {
		SetTestHooks(nil)
		close(barriers.done)
		barriers.group.Wait()
	})
	return barriers
}

// Starts log on a goroutine of its own, answering on the channel returned.
func (self *supportLogStartBarriers) start(log *SupportLog) <-chan error {
	started := make(chan error, 1)
	self.group.Go(func() {
		started <- log.Start()
	})
	return started
}

// Waits for Start to reach want, the next barrier it must reach.
func (self *supportLogStartBarriers) await(t *testing.T, want string) {
	t.Helper()
	select {
	case name := <-self.reached:
		if name != want {
			t.Fatalf("Start reached %s, want %s", name, want)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("Start never reached %s", want)
	}
}

// Lets Start past the barrier it is held at.
func (self *supportLogStartBarriers) release(t *testing.T) {
	t.Helper()
	select {
	case self.proceed <- struct{}{}:
	case <-time.After(30 * time.Second):
		t.Fatal("no Start held to release")
	}
}

// A deferred ring in directory on clock, as an app's sidecar opens one, closed at the test's end.
func openTestDeferredSupportLog(t *testing.T, directory string, clock Clock) *SupportLog {
	t.Helper()
	log, err := OpenSupportLog(&SupportLogArgs{Directory: directory, Settings: DefaultSupportSettings(), Clock: clock, Deferred: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(log.Close)
	return log
}

// Whether the ring's directory exists, failing the test on any other answer.
func testSupportLogDirectoryExists(t *testing.T, directory string) bool {
	t.Helper()
	_, err := os.Stat(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// A Close that lands between Start's reads of closed: Start refuses at its read under fileLock, before any file work,
// so nothing reaches the ring's directory, not while Close runs and not once it has returned, and the ring never
// starts.
func TestSupportLogStartRefusesOnceACloseLandsBetweenItsReads(t *testing.T) {
	clock := newSupportLogTestClock()
	directory := filepath.Join(t.TempDir(), "support-log")
	log := openTestDeferredSupportLog(t, directory, clock)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("2026.11.27-1"))
	barriers := holdSupportLogStart(t, directory)

	started := barriers.start(log)
	barriers.await(t, "support_log.start.before")
	// the app's stop and the whole close, whose last flush keeps what a ring not started holds
	log.Event(SupportLogCodeAppStopped, SupportLogFieldUptime(time.Minute))
	log.Close()
	if testSupportLogDirectoryExists(t, directory) {
		t.Fatal("a deferred ring closed before Start made its directory")
	}
	barriers.release(t)
	select {
	case err := <-started:
		if !errors.Is(err, errSupportLogClosed) {
			t.Fatalf("a Start that Close overtook answers %v", err)
		}
	case name := <-barriers.reached:
		t.Fatalf("a Start that Close overtook reached %s", name)
	case <-time.After(30 * time.Second):
		t.Fatal("Start never returned")
	}
	if testSupportLogDirectoryExists(t, directory) {
		t.Fatal("a Start that Close overtook made the ring's directory after Close returned")
	}
	isStarted := func() bool {
		log.fileLock.Lock()
		defer log.fileLock.Unlock()
		return log.started
	}()
	if isStarted {
		t.Fatal("a Start that Close overtook started the ring")
	}
	// on a goroutine of its own, so one that passed its first read would fail here at a barrier rather than hold the test
	again := barriers.start(log)
	select {
	case err := <-again:
		if !errors.Is(err, errSupportLogClosed) {
			t.Fatalf("a Start after Close answers %v", err)
		}
	case name := <-barriers.reached:
		t.Fatalf("a Start after Close reached %s", name)
	case <-time.After(30 * time.Second):
		t.Fatal("a Start after Close never returned")
	}
}

// A Close that begins once Start's read under fileLock has passed: the writer's last flush waits for fileLock, which
// Start holds through its file work, so Close returns only once what the ring held is on disk, the app's start and
// stop with their times, as an app's ring records them around a close.
func TestSupportLogCloseWaitsForAStartWhoseFileWorkBeganFirst(t *testing.T) {
	clock := newSupportLogTestClock()
	directory := filepath.Join(t.TempDir(), "support-log")
	log := openTestDeferredSupportLog(t, directory, clock)
	held := clock.Now()
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("2026.11.27-1"))
	barriers := holdSupportLogStart(t, directory)

	started := barriers.start(log)
	barriers.await(t, "support_log.start.before")
	barriers.release(t)
	barriers.await(t, "support_log.start.after")
	// Start holds fileLock past its read, and Event never waits on it
	clock.advance(time.Minute)
	stoppedAt := clock.Now()
	log.Event(SupportLogCodeAppStopped, SupportLogFieldUptime(time.Minute))
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		log.Close()
	}()
	// Close cancels the writer once it has marked the ring closed
	select {
	case <-log.ctx.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("Close never stopped the writer")
	}
	select {
	case <-closed:
		t.Fatal("Close returned while Start held fileLock")
	default:
	}
	if testSupportLogDirectoryExists(t, directory) {
		t.Fatal("the ring's directory before Start's file work")
	}
	barriers.release(t)
	select {
	case <-closed:
	case <-time.After(30 * time.Second):
		t.Fatal("Close never returned")
	}
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("a Start whose file work began first answers %v", err)
		}
	case name := <-barriers.reached:
		t.Fatalf("Start reached %s past its file work", name)
	case <-time.After(30 * time.Second):
		t.Fatal("Start never returned")
	}

	// read back by a deferred ring over the directory, which writes nothing
	reader := openTestDeferredSupportLog(t, directory, clock)
	bundle, err := reader.Bundle(nil)
	if err != nil {
		t.Fatal(err)
	}
	startedEvents := testSupportLogEvents(bundle.Document, "app.started")
	stoppedEvents := testSupportLogEvents(bundle.Document, "app.stopped")
	if len(startedEvents) != 1 || startedEvents[0].T != held.Unix() || len(stoppedEvents) != 1 || stoppedEvents[0].T != stoppedAt.Unix() {
		t.Fatalf("once Close returned the ring holds %+v and %+v", startedEvents, stoppedEvents)
	}
}
