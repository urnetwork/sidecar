//go:build !sidecar_http && !ios_extension

// The record SidecarComponent (§5.4): runs a SidecarRecord's push loop on each client generation, so entries the writer
// journaled while offline reach evs once a generation runs, and stops with the generation. Appending needs no
// generation: Sidecar.Record's writer seals, journals and spools on its own, and the loop only carries what it holds.
// The component's sealed directory is the record's own (§5.9's <component>/): Sidecar.Record opens it under the same
// name.
//
// Nothing adds this component yet: the daemon's composition does, beside evs's and the others', as each lands. The
// sidecar_http leg runs no component (§18.10), and the page Worker reads the record and writes nothing.

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
	return &recordComponent{record: record}
}

// The record's own name, its keychain namespace and directory.
func (self *recordComponent) Name() string {
	return recordComponentName
}

// Starts the generation's push loop, which ends with env.Ctx.
func (self *recordComponent) Attach(env *SidecarEnv) error {
	self.runs.Add(1)
	go func() {
		defer self.runs.Done()
		self.record.Run(env.Ctx)
	}()
	return nil
}

// Waits for the last generation's loop, whose context has ended by now.
func (self *recordComponent) Close() {
	self.runs.Wait()
}
