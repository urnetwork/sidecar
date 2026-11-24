//go:build !ios_extension && !sidecar_http

// Enclaves' settings, DESIGN-COMPUTE §11's, which ENC's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultEnclaveSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultEnclaveSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §11, secure enclaves: their formats, admission, provisioning, egress and runtime. ENC's tasks add
// their fields.
type EnclaveSettings struct {
	// §11.10's agents' and edit containers and the container socket, which the enclave's daemon runs
	// (enclave_container.go; ENC-M14-13, ENC-M14-14).
	Container *EnclaveContainerSettings
}

// The component's defaults, the only place one is set.
func DefaultEnclaveSettings() *EnclaveSettings {
	return &EnclaveSettings{
		Container: DefaultEnclaveContainerSettings(),
	}
}
