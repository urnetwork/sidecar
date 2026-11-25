//go:build !ios_extension && !sidecar_http

// The Harness (DESIGN-COMPUTE §7.4, R-HARN-1): sidecar's own agent harness, modeled on Pi's agent core (D-HARN-1),
// one per sidecar host. Tools are built for it from their registrations (harness_tool_registry.go).

package sidecar

// One sidecar host's Harness.
type Harness struct {
	settings *HarnessSettings
	log      Logger
}

// The Harness's settings.
func (self *Harness) Settings() *HarnessSettings {
	return self.settings
}
