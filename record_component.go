//go:build !sidecar_http && !ios_extension

// The record SidecarComponent (§5.4): runs a SidecarRecord's push loop on each client generation, so entries the writer
// journaled while offline reach evs once a generation runs, and stops with the generation. Appending needs no
// generation: Sidecar.Record's writer seals, journals and spools on its own, and the loop only carries what it holds.
// The component's sealed directory is the record's own (§5.9's <component>/): Sidecar.Record opens it under the same
// name.
//
// Native member and daemon hosts attach the component with the anchored config follower. The sidecar_http leg reads
// the record through its bound streams and runs no background writer (§18.10).

package sidecar

import (
	"sync"
)

// The record's component. Close comes after its last generation is detached (SidecarComponent), so no Attach races
// it.
type recordComponent struct {
	record *SidecarRecord
	// each attached generation's loop, waited for at Close
	runs sync.WaitGroup
}

// A component running record's push loop.
func NewRecordComponent(record *SidecarRecord) SidecarComponent {
	// from here the writer keeps each deposit until its ingest, and the loop sends kept ones again after a site loss
	// (record_mirror.go)
	record.Mirrors()
	// and every sync marks archived entries, the loop running the daily expiry of each log this sidecar administers
	// (record_retention.go)
	record.Retention()
	// and every sync looks for late copies of erased entries, the loop erasing them and going on with an erasure that
	// waits (record_erase.go)
	record.hookErasures()
	// and the loop writes each approval request's a/<approval_id> notice in the vault once its entry lands, with its
	// rewrite or removal at a decision or cancel and the repair (record_approval_notice.go; CTXH-M11-07)
	record.ApprovalNotices()
	return &recordComponent{record: record}
}

// The record's own name, its keychain namespace and directory.
func (self *recordComponent) Name() string {
	return recordComponentName
}

// Starts the generation's push loop, which ends with env.Ctx, and beside it resumes any erasure a kill cut short
// (record_erase.go).
func (self *recordComponent) Attach(env *SidecarEnv) error {
	self.runs.Add(2)
	go func() {
		defer self.runs.Done()
		self.record.Run(env.Ctx)
	}()
	go func() {
		defer self.runs.Done()
		if err := self.record.Eraser().Resume(env.Ctx); err != nil {
			self.record.writer.log.Warningf("[record]an erasure did not resume: %s", err)
		}
	}()
	return nil
}

// Waits for the last generation's loop, whose context has ended by now, then writes the reach receipts still open
// (record_reach.go's exit row), which needs no generation: an append journals.
func (self *recordComponent) Close() {
	self.runs.Wait()
	if reach := self.record.reachIfMade(); reach != nil {
		reach.Close()
	}
}
