//go:build !ios_extension

// Whether this client's network is in §19.11's format2 gate (§11.6's format row, §19.11; EVS2-M10-14): the gate api
// lists among a network's open gates in core's answer, GET /sidecar/sync/core's gates (plan-CORE-core-hint-body #2,
// SidecarConfig.GatesFor), which the client takes as a candidate, never as authority (§5.6). It decides only what this
// client writes: outside the gate every version it writes is versioning 0 and carries no format-2 value, so a format-1
// network never meets VERSIONING from 5c, and evs holds every push to the gate itself.
//
// The answer comes from the core state the composition keeps (SetFormat2Source), which reads the gates of the newest
// core answer it holds; until one is set, or while it holds none, Format2Admitted answers false, which fails closed to
// format 1.
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"slices"
)

// The gate's name in core's gates (§19.11).
const EvsFormat2GateName = "format2"

// Whether core's answer lists the format2 gate open for this client's network.
func EvsFormat2AdmittedBy(core *SidecarSyncCore) bool {
	return core != nil && slices.Contains(core.Gates, EvsFormat2GateName)
}

// Sets where Format2Admitted reads the gate: the composition's view of the newest core answer, true only while the
// network is in the format2 gate. nil removes it, which answers false.
func (self *EvsClient) SetFormat2Source(admitted func() bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.format2Source = admitted
}

// Whether the network is in §19.11's format2 gate, as the newest core answer the composition holds lists it; false
// with no source, so the client writes format 1.
func (self *EvsClient) Format2Admitted() bool {
	source := func() func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.format2Source
	}()
	return source != nil && source()
}
