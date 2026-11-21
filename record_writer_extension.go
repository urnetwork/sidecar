//go:build ios_extension

// The forwarding role cannot sign record entries, reconcile writer streams or
// recover their journals. Shared record and receipt callers fail before any I/O.

package sidecar

import "context"

// A forwarding host opens neither the record store nor its writer.
func (self *Sidecar) Record() (*SidecarRecord, error) {
	return nil, ErrRecordStreamsUnavailable
}

// Forwarding does not publish directory announcements or recover a run writer after a config read.
func (self *DirectoryClient) reconcileRuns() error {
	return nil
}

// No direct writer stream can be prepared.
func (self *SidecarRecord) PrepareDirectWrites(ctx context.Context) error {
	return ErrRecordStreamsUnavailable
}

// A read receipt cannot prepare a writer on this host.
func (self *recordWriter) prepareLog(ctx context.Context, logId Id) error {
	return ErrRecordStreamsUnavailable
}

// No receipt destination is ready for signing.
func (self *recordWriter) readyLog(logId Id) error {
	return ErrRecordStreamsUnavailable
}

// A restored writer journal cannot be settled here.
func (self *recordWriter) settleRestoredEntries(ctx context.Context, logId Id, through uint64) error {
	return ErrRecordStreamsUnavailable
}

// No writer journal is opened for recovery.
func (self *recordWriter) finishCaptureWithLock() error {
	return ErrRecordStreamsUnavailable
}

// No draft or spool entry can be sealed by a forwarding delegation.
func (self *recordWriter) sealRoutes(draft *recordSpoolDraft, routes *recordRoutes, captureId []byte) ([]*RecordEntryRef, error) {
	return nil, ErrRecordStreamsUnavailable
}
