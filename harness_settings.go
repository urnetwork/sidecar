//go:build !ios_extension && !sidecar_http

// The Harness's settings, DESIGN-COMPUTE §7's, which HARN's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultHarnessSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultHarnessSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §7, the Harness: its sessions, events, tools, approvals and agents. Empty until HARN's tasks add their
// fields.
type HarnessSettings struct{}

// The component's defaults, the only place one is set.
func DefaultHarnessSettings() *HarnessSettings {
	return &HarnessSettings{}
}
