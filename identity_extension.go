//go:build ios_extension

// The forwarding host owns a forwarding delegation. It never opens the sidecar's
// identity store, admits a device or releases a contingent browser statement.

package sidecar

import "context"

// An open host store gives the VPN component no sidecar client generation.
func (self *Sidecar) reconcileOpen() {
	self.stopGeneration()
	self.leaveForUnenrolled("")
}

// The forwarding delegation cannot sign another device's admission.
func sidecarDecideAdmission(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	return ErrSidecarApprovalAuthority
}

// A pending mailbox share or owner confirmation cannot be released by the forwarding role.
func (self *Sidecar) checkBrowserAdmissionDependency(ctx context.Context, dependency *browserAdmissionDependency) error {
	return ErrSidecarActRefused
}
