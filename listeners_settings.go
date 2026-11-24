//go:build !ios_extension && !sidecar_http

// Listeners' settings, DESIGN-COMPUTE §26's, which LSTN's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultListenersSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultListenersSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §26, listeners: discovery, the listeners repo, publishing and hiding, and the live ask. Empty until
// LSTN's tasks add their fields.
type ListenersSettings struct{}

// The component's defaults, the only place one is set.
func DefaultListenersSettings() *ListenersSettings {
	return &ListenersSettings{}
}
