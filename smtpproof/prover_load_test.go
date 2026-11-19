// The loader's memory rule on a fake source and a fake clock (DESIGN-DETAILS 3.2.8): loaded shapes and
// proofs in flight never charge past MemoryMaxByteCount, a shape a proof holds is never unloaded, an idle
// shape goes after ShapeIdleTimeout and the heap returns once the last does, and a cancelled proof returns
// its charge. Whether a load would wait is read deterministically: a load under a context already ended
// fails with it exactly when it must wait, and charges nothing then.

package smtpproof

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The default budget's shape: two loaded shapes and one proof fill it.
func testLoaderSettings() *ProverSettings {
	settings := DefaultProverSettings()
	settings.MemoryMaxByteCount = 2240
	settings.ShapeMemoryByteCount = 768
	settings.PartMemoryByteCount = 704
	settings.ShapeIdleTimeout = 2 * time.Minute
	return settings
}

// A loader on a fake clock, whose loads are counted by shape and whose heap returns are counted.
type testLoader struct {
	loader *proverLoader
	clock  *sidecartest.FakeClock

	stateLock sync.Mutex
	loads     map[string]int
	frees     int
	collects  int
}

func newTestLoader(t *testing.T, settings *ProverSettings) *testLoader {
	t.Helper()
	clock := sidecartest.NewFakeClock(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	loader := &testLoader{clock: clock, loads: map[string]int{}}
	loader.loader = newProverLoader(settings, clock)
	loader.loader.freeMemory = func() {
		loader.stateLock.Lock()
		defer loader.stateLock.Unlock()
		loader.frees += 1
	}
	loader.loader.collect = func() {
		loader.stateLock.Lock()
		defer loader.stateLock.Unlock()
		loader.collects += 1
	}
	return loader
}

func (self *testLoader) load(key string) func() (*shapeKeys, error) {
	return func() (*shapeKeys, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.loads[key] += 1
		return &shapeKeys{shape: &partShape{}}, nil
	}
}

func (self *testLoader) loadCount(key string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.loads[key]
}

// The loaded shapes' keys in order, and what is charged.
func (self *testLoader) state() ([]string, int64) {
	keys, charged := self.loader.loaded()
	slices.Sort(keys)
	return keys, charged
}

// Takes a shape's charge, failing the test if it would wait.
func (self *testLoader) take(t *testing.T, key string) *loadedShape {
	t.Helper()
	shape, err := self.loader.acquire(context.Background(), key, self.load(key))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return shape
}

// Whether a shape's charge would wait now: a load under an ended context fails with it exactly then.
func (self *testLoader) wouldWait(t *testing.T, key string) bool {
	t.Helper()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	shape, err := self.loader.acquire(ended, key, self.load(key))
	switch {
	case errors.Is(err, context.Canceled):
		return true
	case err != nil:
		t.Fatalf("%s: %v", key, err)
	}
	self.loader.release(shape)
	return false
}

func (self *testLoader) expect(t *testing.T, step string, keys []string, charged int64) {
	t.Helper()
	gotKeys, gotCharged := self.state()
	if !slices.Equal(gotKeys, keys) || gotCharged != charged {
		t.Errorf("%s: loaded %v charging %d, want %v charging %d", step, gotKeys, gotCharged, keys, charged)
	}
	if max := self.loader.settings.MemoryMaxByteCount; max < gotCharged {
		t.Errorf("%s: %d charged past the budget's %d", step, gotCharged, max)
	}
}

func TestTheLoaderNeverChargesPastTheBudget(t *testing.T) {
	loader := newTestLoader(t, testLoaderSettings())
	a := loader.take(t, "a")
	loader.expect(t, "a proving", []string{"a"}, 768+704)

	// a second shape and proof beside a's would pass the budget, and a is in use, so b waits and nothing goes
	if !loader.wouldWait(t, "b") {
		t.Fatal("b loaded beside a proof of a")
	}
	loader.expect(t, "b waiting", []string{"a"}, 768+704)
	if loader.loadCount("b") != 0 {
		t.Error("a load that waits read its shape")
	}

	// once a's proof ends, a stays loaded and b loads beside it: two shapes and one proof fill the budget
	loader.loader.release(a)
	b := loader.take(t, "b")
	loader.expect(t, "b proving", []string{"a", "b"}, 2*768+704)

	// a third shape while b proves needs b's room, which b's proof holds: c waits, and a, idle, stays
	if !loader.wouldWait(t, "c") {
		t.Fatal("c loaded beside a proof of b")
	}
	loader.expect(t, "c waiting", []string{"a", "b"}, 2*768+704)

	// with b's proof done, c takes the place of the least recently used shape, a
	loader.loader.release(b)
	c := loader.take(t, "c")
	loader.expect(t, "c proving", []string{"b", "c"}, 2*768+704)
	loader.loader.release(c)

	// a proof of a shape already loaded charges only the proof
	again := loader.take(t, "b")
	loader.expect(t, "b again", []string{"b", "c"}, 2*768+704)
	loader.loader.release(again)
	if loader.loadCount("b") != 1 || loader.loadCount("a") != 1 || loader.loadCount("c") != 1 {
		t.Errorf("loads %v", loader.loads)
	}
}

func TestTheLoaderNeverUnloadsAShapeInUse(t *testing.T) {
	settings := testLoaderSettings()
	// room for three shapes and one proof, or two shapes and two proofs
	settings.MemoryMaxByteCount = 3*768 + 704
	loader := newTestLoader(t, settings)
	a := loader.take(t, "a")
	b := loader.take(t, "b")
	loader.expect(t, "a and b proving", []string{"a", "b"}, 2*768+2*704)
	// both shapes are held, so a third waits however long ago they were used
	if !loader.wouldWait(t, "c") {
		t.Fatal("c loaded over two shapes in use")
	}
	loader.loader.release(a)
	// a is idle now, and goes for c; b stays
	c := loader.take(t, "c")
	loader.expect(t, "b and c proving", []string{"b", "c"}, 2*768+2*704)
	loader.loader.release(b)
	loader.loader.release(c)
	loader.expect(t, "idle", []string{"b", "c"}, 2*768)
}

func TestTheLoaderUnloadsAnIdleShapeAndThenReturnsTheHeap(t *testing.T) {
	loader := newTestLoader(t, testLoaderSettings())
	a := loader.take(t, "a")
	loader.loader.release(a)
	loader.clock.Advance(time.Minute)
	b := loader.take(t, "b")
	loader.loader.release(b)
	loader.expect(t, "both idle", []string{"a", "b"}, 2*768)

	// a's two minutes end first, and the heap stays: b is loaded
	loader.clock.Advance(time.Minute)
	loader.expect(t, "a timed out", []string{"b"}, 768)
	if loader.frees != 0 {
		t.Errorf("%d heap returns with a shape loaded", loader.frees)
	}
	// a use restarts b's timer
	again := loader.take(t, "b")
	loader.clock.Advance(time.Hour)
	loader.expect(t, "b in use", []string{"b"}, 768+704)
	loader.loader.release(again)
	loader.clock.Advance(2*time.Minute - time.Second)
	loader.expect(t, "b not yet idle long enough", []string{"b"}, 768)
	loader.clock.Advance(time.Second)
	loader.expect(t, "b timed out", nil, 0)
	if loader.frees != 1 {
		t.Errorf("%d heap returns, want one when the last shape went", loader.frees)
	}
}

func TestTheLoaderUnloadsAtOnceWithNoIdleTimeout(t *testing.T) {
	settings := testLoaderSettings()
	settings.ShapeIdleTimeout = 0
	loader := newTestLoader(t, settings)
	a := loader.take(t, "a")
	loader.loader.release(a)
	loader.expect(t, "released", nil, 0)
	if loader.frees != 1 {
		t.Errorf("%d heap returns", loader.frees)
	}
}

func TestACancelledProofReturnsItsCharge(t *testing.T) {
	loader := newTestLoader(t, testLoaderSettings())
	started := make(chan struct{})
	unblock := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	proved := make(chan error, 1)
	go func() {
		_, err := loader.loader.prove(ctx, "a", loader.load("a"), func(keys *shapeKeys) ([]byte, error) {
			close(started)
			<-unblock
			return []byte("proof"), nil
		})
		proved <- err
	}()
	<-started
	cancel()
	if err := <-proved; !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled proof returned %v", err)
	}
	// gnark's proof cannot stop, so its charge stays until it ends
	loader.expect(t, "cancelled, still proving", []string{"a"}, 768+704)
	if !loader.wouldWait(t, "b") {
		t.Error("b loaded beside a proof that still runs")
	}
	close(unblock)
	// and returns then: b's load waits for it and takes its place
	b, err := loader.loader.acquire(context.Background(), "b", loader.load("b"))
	if err != nil {
		t.Fatal(err)
	}
	loader.expect(t, "b after the cancelled proof", []string{"a", "b"}, 2*768+704)
	loader.loader.release(b)
	if loader.collects != 1 {
		t.Errorf("%d collections, want one after the proof", loader.collects)
	}
}

func TestALoaderWithNoRoomForAProofRefusesEveryPart(t *testing.T) {
	settings := testLoaderSettings()
	settings.MemoryMaxByteCount = 768 + 704 - 1
	loader := newTestLoader(t, settings)
	if _, err := loader.loader.acquire(context.Background(), "a", loader.load("a")); err == nil {
		t.Fatal("a proof was charged past the budget")
	}
	if loader.loadCount("a") != 0 {
		t.Error("a refused load read its shape")
	}
}

func TestAFailedLoadIsNotKeptAndReturnsItsCharge(t *testing.T) {
	loader := newTestLoader(t, testLoaderSettings())
	failing := func() (*shapeKeys, error) {
		return nil, errNoKeys
	}
	if _, err := loader.loader.acquire(context.Background(), "a", failing); !errors.Is(err, errNoKeys) {
		t.Fatalf("err %v", err)
	}
	loader.expect(t, "after the failure", nil, 0)
	// the shape may be cached by now, and is loaded again
	a := loader.take(t, "a")
	loader.loader.release(a)
	if loader.loadCount("a") != 1 {
		t.Errorf("%d loads", loader.loadCount("a"))
	}
}

func TestProofsOfOneShapeShareItsLoad(t *testing.T) {
	settings := testLoaderSettings()
	settings.MemoryMaxByteCount = 768 + 2*704
	loader := newTestLoader(t, settings)
	first := loader.take(t, "a")
	second := loader.take(t, "a")
	loader.expect(t, "two proofs of a", []string{"a"}, 768+2*704)
	if !loader.wouldWait(t, "a") {
		t.Error("a third proof was charged past the budget")
	}
	loader.loader.release(first)
	loader.loader.release(second)
	if loader.loadCount("a") != 1 {
		t.Errorf("%d loads", loader.loadCount("a"))
	}
}
