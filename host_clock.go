//go:build !sidecar_http && !ios_extension

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
//
// ClockCheck is operator-core's (owner decision 251).

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// One process's view of its own clock. A check starts unsure and stays so until it has measured, so a
// process that cannot reach its time source fails closed.
type ClockCheck = operator.ClockCheck
