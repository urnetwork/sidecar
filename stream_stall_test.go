//go:build !sidecar_http && !js

package sidecar

// D-PROTO-4's stall measure as PROTO-M5-05 exports it: each StreamData's send-to-ack time in power-of-two buckets of
// milliseconds, read by Subprotocol.StreamStallP99 as its 99th percentile's upper bound and the frames counted, the
// figure the TLS edge's 500 ms review reads.

import (
	"testing"
	"time"
)

func TestStreamStallP99ReadsTheDispatchersHistogram(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	if p99, count := fixture.subprotocol.StreamStallP99(); p99 != 0 || count != 0 {
		t.Fatalf("before any frame: %v of %d", p99, count)
	}
	stall := &fixture.subprotocol.streams.stats.stall
	// 99 frames acked within 3 ms, below the 4 ms bucket's bound
	for range 99 {
		stall.add(3 * time.Millisecond)
	}
	if p99, count := fixture.subprotocol.StreamStallP99(); p99 != 4*time.Millisecond || count != 99 {
		t.Errorf("99 quick frames: %v of %d", p99, count)
	}
	// two lost packs, each held 600 ms until resent, put the 99th percentile in the 1,024 ms bucket, past the review's
	// 500 ms
	stall.add(600 * time.Millisecond)
	stall.add(600 * time.Millisecond)
	p99, count := fixture.subprotocol.StreamStallP99()
	if p99 != 1024*time.Millisecond || count != 101 {
		t.Errorf("with two stalls: %v of %d", p99, count)
	}
	if p99 <= 500*time.Millisecond {
		t.Errorf("the measure reads %v, under the review's 500 ms", p99)
	}
	// a frame past connect's 60 s ack timeout falls in the last bucket
	stall.add(10 * time.Minute)
	if top, _ := stall.percentile(1); top != time.Millisecond<<(streamStallBucketCount-1) {
		t.Errorf("past the last bound: %v", top)
	}
	fixture.closeBalanced(t)
}
