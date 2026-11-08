//go:build !sidecar_http

// ServiceHost.ClockCheck: how far this process's clock may stand from true time (§19.6's clocks row).
// §11.8's fence margin, §11.7's collection margins and §19.6's deadline and settle rules hold only
// while every clock that writes fence_ms, a refusal record's until or a deadline is within 50 ms of
// UTC, so a process asks here before it writes one. While the answer is not sure, the work waits and
// nothing it would have done is lost:
//
//   - evs answers pushes 503 before step 4, and issues no purge DELETE;
//   - taskworker raises no evacuation or GC fence, and GC, purges and drops delete nothing;
//   - a collection or drop DELETE already issued is cancelled at once, through UnsureChannel.
//
// A storage host answers for its own clock, in the minio fork (D-OPS-20), and a Redis host only warns,
// through its exporter (§19.10).

package sidecar

import (
	"time"
)

// One process's view of its own clock. A check starts unsure and stays so until it has measured, so a
// process that cannot reach its time source fails closed. Safe for concurrent use, and no method does
// I/O, so each may be called on a request's path.
type ClockCheck interface {
	// The most this clock may be from true time, as a magnitude: the measured offset plus the time
	// source's root distance, which is RFC 5905 §4's maximum error. known is false while there is no
	// such bound, and offset is then zero. The host exports it, and monitor warns past 25 ms or while
	// it is unknown (§19.8).
	Offset() (offset time.Duration, known bool)
	// Whether Offset is known and within the bound §11.8's margins allow, 50 ms.
	Sure() bool
	// Closed the moment this clock stops being sure, and already closed while it is unsure, so a
	// DELETE started on an unsure clock cancels at once. Each sure stretch has its own channel. A
	// caller takes this before reading Sure, and takes it again for each piece of work, so a turn
	// between the two reads as unsure and never as sure.
	UnsureChannel() <-chan struct{}
}
