//go:build !ios_extension && !sidecar_http

// The models key's settings, DESIGN-COMPUTE §16.4's, with the member's harness config file the key lives in (DESIGN
// §16.7; plan-MCP-harness-config-schema #1), which CACL's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultModelsKeySettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created by the compute
// skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultModelsKeySettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

// DESIGN-COMPUTE §16.4, the person's models key: the default model, TEE-only, the models allowed and each harness's
// tiers; and the member's harness config file that holds it beside the other compute keys (CACL-M11-01).
type ModelsKeySettings struct {
	// The harness config file's cap, in bytes: 64 KiB (plan-MCP-harness-config-schema #1). A format limit every reader
	// and writer of the file shares: a version past it reads as unreadable, defaults and a config_unreadable gap, and
	// a write that would pass it is refused with nothing written. Must be positive.
	ConfigMaxByteCount int
	// The most versions of the file one read walks back past versions it takes nothing from, an enclave's or a
	// tagged sidecar's (DESIGN-COMPUTE §16.6's reading row): 32. A read that finds no version it takes within them
	// reads as unreadable, defaults and a gap, never an older copy. Must be positive.
	ConfigReadVersionMaxCount int
	// How many times one write tries, reading the file again and applying its change again each time another write
	// landed first: 4, past which ErrHarnessConfigConflict and nothing written. Must be positive.
	ConfigWriteAttemptCount int
	// The most globs `allow` holds: 64. A key with more is refused.
	AllowMaxCount int
	// The most `*` one glob holds: 4, which bounds what one match costs. A glob is also no longer than a canonical
	// name (InferSettings.NameMaxByteCount), since it lies within one.
	AllowGlobWildcardMaxCount int
	// The most entries `agents` holds: 256. A key with more is refused.
	AgentMaxCount int
	// What an agent's label under `agents` may be: the agent label format's own, which every `.ur` and hello share
	// (SidecarAgentLabelSettings).
	AgentLabel *SidecarAgentLabelSettings
}

// The component's defaults, the only place one is set.
func DefaultModelsKeySettings() *ModelsKeySettings {
	return &ModelsKeySettings{
		ConfigMaxByteCount:        64 * 1024,
		ConfigReadVersionMaxCount: 32,
		ConfigWriteAttemptCount:   4,
		AllowMaxCount:             64,
		AllowGlobWildcardMaxCount: 4,
		AgentMaxCount:             256,
		AgentLabel:                DefaultSidecarAgentLabelSettings(),
	}
}
