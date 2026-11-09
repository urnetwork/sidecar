package sidecar

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// A queue's worker held on its first item, offers past the bound refuse at once and are counted, and the held queue
// drains in order once let go: D-CORE-3's zero-wait queue, its receive side never waiting.
func TestFullQueueDropsAndCounts(t *testing.T) {
	counters := &sidecarQueueCounters{}
	queue := newSidecarComponentQueue(context.Background(), 3, 1024, counters, NewNoopLogger())
	defer queue.closeAndWait()

	held := make(chan struct{})
	release := make(chan struct{})
	var ranLock sync.Mutex
	ran := []int{}
	note := func(i int) func(ctx context.Context) {
		return func(ctx context.Context) {
			ranLock.Lock()
			ran = append(ran, i)
			ranLock.Unlock()
		}
	}
	if !queue.offer(10, func(ctx context.Context) {
		close(held)
		<-release
	}) {
		t.Fatal("the first offer was refused")
	}
	<-held
	// the worker holds item 0, so three more fill the queue
	for i := 1; i <= 3; i += 1 {
		if !queue.offer(10, note(i)) {
			t.Fatalf("offer %d refused below the bound", i)
		}
	}
	refused := make(chan bool)
	go func() {
		refused <- queue.offer(10, note(4))
	}()
	select {
	case taken := <-refused:
		if taken {
			t.Fatal("an offer past the message bound was taken")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an offer to a full queue waited")
	}
	if counters.droppedCount.Load() != 1 || counters.droppedByteCount.Load() != 10 {
		t.Fatalf("dropped %d (%d bytes), want 1 (10)", counters.droppedCount.Load(), counters.droppedByteCount.Load())
	}

	close(release)
	queue.closeAndWait()
	ranLock.Lock()
	defer ranLock.Unlock()
	// closing drops what is still queued, so only the items the worker reached ran, in order
	if !slices.IsSorted(ran) {
		t.Errorf("ran out of order: %v", ran)
	}
	if counters.queuedCount.Load() != 4 {
		t.Errorf("queued %d, want 4", counters.queuedCount.Load())
	}
	if got := counters.ranCount.Load() + counters.droppedCount.Load(); got != 5 {
		t.Errorf("ran plus dropped %d, want 5", got)
	}
}

// The byte bound holds as the message bound does, an item past it alone included.
func TestQueueByteBoundRefuses(t *testing.T) {
	counters := &sidecarQueueCounters{}
	queue := newSidecarComponentQueue(context.Background(), 100, 100, counters, NewNoopLogger())
	defer queue.closeAndWait()

	if queue.offer(101, func(ctx context.Context) {}) {
		t.Fatal("an item past the byte bound alone was taken")
	}
	held := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	if !queue.offer(60, func(ctx context.Context) {
		close(held)
		<-release
	}) {
		t.Fatal("refused under the bound")
	}
	<-held
	if !queue.offer(60, func(ctx context.Context) {}) {
		t.Fatal("refused with the worker's item already out of the queue")
	}
	if queue.offer(41, func(ctx context.Context) {}) {
		t.Fatal("taken past the byte bound")
	}
	if counters.droppedCount.Load() != 2 || counters.droppedByteCount.Load() != 142 {
		t.Errorf("dropped %d (%d bytes), want 2 (142)", counters.droppedCount.Load(), counters.droppedByteCount.Load())
	}
}

// A panicking item stays its own: the worker counts it and runs the next.
func TestQueuedPanicStaysWithItsItem(t *testing.T) {
	counters := &sidecarQueueCounters{}
	queue := newSidecarComponentQueue(context.Background(), 4, 1024, counters, NewNoopLogger())
	defer queue.closeAndWait()

	done := make(chan struct{})
	queue.offer(1, func(ctx context.Context) {
		panic("synthetic")
	})
	queue.offer(1, func(ctx context.Context) {
		close(done)
	})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the item after a panic never ran")
	}
	if counters.panicCount.Load() != 1 {
		t.Errorf("panics %d, want 1", counters.panicCount.Load())
	}
}

// A closed queue takes nothing, and its worker has returned when closeAndWait does.
func TestClosedQueueRefuses(t *testing.T) {
	counters := &sidecarQueueCounters{}
	queue := newSidecarComponentQueue(context.Background(), 4, 1024, counters, NewNoopLogger())
	queue.closeAndWait()
	select {
	case <-queue.done:
	default:
		t.Fatal("the worker outlived closeAndWait")
	}
	if queue.offer(1, func(ctx context.Context) {}) {
		t.Fatal("a closed queue took an item")
	}
	queue.closeAndWait()
}
