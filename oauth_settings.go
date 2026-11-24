//go:build !ios_extension && !sidecar_http

// Connected services' settings, DESIGN-COMPUTE §25's, which CONN's tasks fill. Every limit, size, count, time,
// interval, threshold, retry or budget the component reads is a field here, its default set only in
// DefaultOauthSettings, protocol and format limits included; only identifiers stay constants (QD-702). The struct is
// created empty by the compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go:
// SidecarSettings holds it, and DefaultSidecarSettings sets it from DefaultOauthSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §25, connected services: definitions, sign-in, the connection store and rotation, and service calls.
// Empty until CONN's tasks add their fields.
type OauthSettings struct{}

// The component's defaults, the only place one is set.
func DefaultOauthSettings() *OauthSettings {
	return &OauthSettings{}
}
