// What record_enclave_ssh_test.go reaches of the registry (CTXH-M11-08): a build from before a kind's change, for a
// test that reads as one.

package sidecar

// Makes kind unknown to this build until the answer puts it back. No test of this package runs in parallel, so the
// registry is the calling test's alone meanwhile.
func ForgetRecordKindForTest(kind RecordKind) func() {
	row, ok := recordKindRows[kind]
	delete(recordKindRows, kind)
	return func() {
		if ok {
			recordKindRows[kind] = row
		}
	}
}
