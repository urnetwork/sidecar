//go:build ios_extension || sidecar_http

// The compute skeleton on the legs that run no compute (CARCH-M11-01): the forwarding leg, which runs only IP and port
// forwarding (owner decision 197), and the page Worker's sidecar_http leg, which gets no compute surface
// (DESIGN-COMPUTE §15.4). settings.go, which every leg builds, holds a field for each compute component's settings, so
// each type is declared here empty, with a default that sets nothing, in place of its area's file, which these legs leave
// out by its build line. No field is ever read here: no compute code builds on these legs, so a compute surface they
// would need is refused at compile time rather than left nil. The Sidecar's lifecycle calls construct and close no
// compute component on them (compute_sidecar.go holds the real ones).

package sidecar

// DESIGN-COMPUTE §7's, which these legs do not run (harness_settings.go on the others).
type HarnessSettings struct{}

// Nothing: these legs run no such component.
func DefaultHarnessSettings() *HarnessSettings {
	return &HarnessSettings{}
}

// DESIGN-COMPUTE §24's, which these legs do not run (session_settings.go on the others).
type SessionSettings struct{}

// Nothing: these legs run no such component.
func DefaultSessionSettings() *SessionSettings {
	return &SessionSettings{}
}

// DESIGN-COMPUTE §6's, which these legs do not run (infer_settings.go on the others).
type InferSettings struct{}

// Nothing: these legs run no such component.
func DefaultInferSettings() *InferSettings {
	return &InferSettings{}
}

// DESIGN-COMPUTE §5's, which these legs do not run (attest_settings.go on the others).
type AttestSettings struct{}

// Nothing: these legs run no such component.
func DefaultAttestSettings() *AttestSettings {
	return &AttestSettings{}
}

// DESIGN-COMPUTE §2.8's, which these legs do not run (disclosure_settings.go on the others).
type ComputeDisclosureSettings struct{}

// Nothing: these legs run no such component.
func DefaultComputeDisclosureSettings() *ComputeDisclosureSettings {
	return &ComputeDisclosureSettings{}
}

// DESIGN-COMPUTE §16.4's, which these legs do not run (budget_settings.go on the others).
type BudgetSettings struct{}

// Nothing: these legs run no such component.
func DefaultBudgetSettings() *BudgetSettings {
	return &BudgetSettings{}
}

// DESIGN-COMPUTE §16.4's, which these legs do not run (models_settings.go on the others).
type ModelsKeySettings struct{}

// Nothing: these legs run no such component.
func DefaultModelsKeySettings() *ModelsKeySettings {
	return &ModelsKeySettings{}
}

// DESIGN-COMPUTE §16's, which these legs do not run (acl_compute_settings.go on the others).
type ComputePolicySettings struct{}

// Nothing: these legs run no such component.
func DefaultComputePolicySettings() *ComputePolicySettings {
	return &ComputePolicySettings{}
}

// DESIGN-COMPUTE §9's, which these legs do not run (compute_client_settings.go on the others).
type ComputeClientSettings struct{}

// Nothing: these legs run no such component.
func DefaultComputeClientSettings() *ComputeClientSettings {
	return &ComputeClientSettings{}
}

// DESIGN-COMPUTE §8's, which these legs do not run (gateway_settings.go on the others).
type GatewaySettings struct{}

// Nothing: these legs run no such component.
func DefaultGatewaySettings() *GatewaySettings {
	return &GatewaySettings{}
}

// DESIGN-COMPUTE §11's, which these legs do not run (enclave_settings.go on the others).
type EnclaveSettings struct{}

// Nothing: these legs run no such component.
func DefaultEnclaveSettings() *EnclaveSettings {
	return &EnclaveSettings{}
}

// DESIGN-COMPUTE §12's, which these legs do not run (ssh_settings.go on the others).
type SshSettings struct{}

// Nothing: these legs run no such component.
func DefaultSshSettings() *SshSettings {
	return &SshSettings{}
}

// DESIGN-COMPUTE §13's, which these legs do not run (git_settings.go on the others).
type GitSettings struct{}

// Nothing: these legs run no such component.
func DefaultGitSettings() *GitSettings {
	return &GitSettings{}
}

// DESIGN-COMPUTE §20's, which these legs do not run (skill_settings.go on the others).
type SkillSettings struct{}

// Nothing: these legs run no such component.
func DefaultSkillSettings() *SkillSettings {
	return &SkillSettings{}
}

// DESIGN-COMPUTE §21's, which these legs do not run (websearch_settings.go on the others).
type WebSearchSettings struct{}

// Nothing: these legs run no such component.
func DefaultWebSearchSettings() *WebSearchSettings {
	return &WebSearchSettings{}
}

// DESIGN-COMPUTE §22's, which these legs do not run (fetch_settings.go on the others).
type FetchSettings struct{}

// Nothing: these legs run no such component.
func DefaultFetchSettings() *FetchSettings {
	return &FetchSettings{}
}

// DESIGN-COMPUTE §23's, which these legs do not run (calendar_settings.go on the others).
type CalendarSettings struct{}

// Nothing: these legs run no such component.
func DefaultCalendarSettings() *CalendarSettings {
	return &CalendarSettings{}
}

// DESIGN-COMPUTE §25's, which these legs do not run (oauth_settings.go on the others).
type OauthSettings struct{}

// Nothing: these legs run no such component.
func DefaultOauthSettings() *OauthSettings {
	return &OauthSettings{}
}

// DESIGN-COMPUTE §26's, which these legs do not run (listeners_settings.go on the others).
type ListenersSettings struct{}

// Nothing: these legs run no such component.
func DefaultListenersSettings() *ListenersSettings {
	return &ListenersSettings{}
}

// DESIGN-COMPUTE §27's, which these legs do not run (safety_settings.go on the others).
type SafetySettings struct{}

// Nothing: these legs run no such component.
func DefaultSafetySettings() *SafetySettings {
	return &SafetySettings{}
}

// Constructs nothing: these legs register no compute component.
func (self *Sidecar) startComputeComponents() {}

// Closes nothing, since nothing was constructed.
func (self *Sidecar) closeComputeComponents() {}
