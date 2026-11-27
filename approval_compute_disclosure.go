//go:build !ios_extension && !sidecar_http

// Kind 19's card's disclosure line (DESIGN-COMPUTE §16.3, §2.8; CACL-M12-02): the provider's summary line from CTRUST's
// registry (ComputeDisclosureRegistry.Line), which opens the disclosure's whole text, read from the newest verified
// policy alone, so no agent, event or server answer puts text in it. A device whose registry holds no verified policy
// renders none, and a kind-19 card then takes no approval (approval_compute_render.go).
//
// The line is the registry's English one: the core knows no person's locale, which the apps' Disclosures() set
// (SetDisclosureLocale); a card in the app's locale is the UI phase's. On the legs that run compute; the page Worker's,
// which approves nothing yet, renders no line.

package sidecar

// This Sidecar's disclosure registry, read at each render, since components construct in no design's order.
type sidecarApprovalDisclosureLines struct {
	sidecar *Sidecar
}

// See ApprovalComputeDisclosureLines.
func (self *sidecarApprovalDisclosureLines) ApprovalDisclosureLine(id string) (string, error) {
	registry, err := self.sidecar.ComputeDisclosureRegistry()
	if err != nil {
		return "", err
	}
	return registry.Line(id, "")
}

// Gives every Sidecar's approver kind 19's disclosure lines from its registry.
func init() {
	registerApprovalComputeDisclosureLines(func(sidecar *Sidecar) ApprovalComputeDisclosureLines {
		return &sidecarApprovalDisclosureLines{sidecar: sidecar}
	})
}
