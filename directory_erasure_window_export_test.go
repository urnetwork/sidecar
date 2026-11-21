//go:build !sidecar_http && !ios_extension

// A bridge for the directory erasure's tests of QD-1161 (directory_erasure_window_test.go), beside QD-1158's and
// QD-1160's (directory_erasure_after_cut_export_test.go, directory_erasure_dropped_export_test.go): a ref's next
// CLOSURE refused as the eraser's spent allowance refuses one at the storage limit (§11.13's wait row), so the
// rewrite that meets it waits with its pairs unsent.

package sidecar

// Refuses the next CLOSURE on the ref named name with the 429 a spent allowance answers, naming
// evs_closure_bytes_per_day, its next try at the next 00:00 UTC on the ref's clock: the rewrite that meets it reads
// waiting.
func (self *DirectoryErasureTestRefs) RefuseNextClosure(name string) {
	self.t.Helper()
	ref := self.ref(name)
	now := ref.world.at
	ref.evs.stateLock.Lock()
	defer ref.evs.stateLock.Unlock()
	ref.evs.closureRefusals = append(ref.evs.closureRefusals, &indexRefusal{
		kind: indexRefusalRetry, retryAfter: indexNextUtcMidnight(now).Sub(now),
		quota: &QuotaRefusal{LimitKey: "evs_closure_bytes_per_day", Limit: 64 * 1024 * 1024, Used: 64 * 1024 * 1024},
	})
}
