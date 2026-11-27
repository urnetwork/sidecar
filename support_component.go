//go:build !ios_extension && !sidecar_http

// The support client as a Sidecar's compute component (DESIGN-COMPUTE §28.4, compute_sidecar.go): constructed as the
// Sidecar starts, on its local store's support directory and its host's support log, and closed as it ends. Of its
// sources beyond the Sidecar (support_sources.go), the policy's support line is the attest component's store's, read
// at each use (attest_policy_support.go), and the disclosure's state CTRUST's acknowledgments (disclosure_check.go), so
// a message waits for support:urnetwork's current version; the rest start unset, so until their owners land nothing is
// posted; and the release's switch, SupportSettings.ServiceEnabled, is off until G-SUP-service passes, so every surface
// answers ErrSupportUnavailable meanwhile (§28.21).

package sidecar

// The component's name.
const supportComponentName = "support"

// The store's directory and sealing class for the support client's state.
const supportStoreName = "support"

// Registers the support client, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(supportComponentName, newSidecarSupportClient, func(client *SupportClient) { client.Close() })
}

// The client on sidecar: its local store's support directory, read at each use since a Sidecar enrolls after it starts,
// its settings and its host's support log, and its part of each client generation, which holds the support push topic
// (support_push_topic.go).
func newSidecarSupportClient(sidecar *Sidecar) (*SupportClient, error) {
	supportLog, _ := sidecar.settings.SupportLog.(*SupportLog)
	client, err := NewSupportClient(&SupportClientArgs{
		Host:     sidecar,
		Settings: sidecar.settings.Support,
		Log:      supportLog,
		Store: func() (SidecarStore, error) {
			return sidecar.LocalStore().Directory(supportStoreName, supportStoreName)
		},
		Clock:      sidecar.settings.Clock,
		BundleHost: &SupportLogBundleHost{Version: Version},
		Sources: &SupportSources{
			Policy: &computePolicySupportSource{sidecar: sidecar},
			// CTRUST's acknowledgments of support:urnetwork (disclosure_check.go)
			Disclosures: &computeDisclosureSupportSource{sidecar: sidecar},
		},
	})
	if err != nil {
		return nil, err
	}
	// listed as AddComponent lists one, without its wake, as the compute client's is: the client constructs before the
	// run loop's first pass, which attaches every listed component (compute_sidecar.go). With the release's switch off
	// the topic stays dark with the rest of the skill, holding no subscription
	leg, ok := sidecar.leg.(*sidecarConnectLeg)
	if !ok || !client.settings.ServiceEnabled {
		// no client generations, so no push, or no skill: the loop's interval reads where anything does
		return client, nil
	}
	if err := leg.addComponent(&supportHintComponent{client: client}); err != nil && sidecar.log.V(1).Enabled() {
		sidecar.log.Infof("[support]the support topic is not subscribed: %s", err)
	}
	return client, nil
}

// This Sidecar's support client, or why it has none.
func (self *Sidecar) Support() (*SupportClient, error) {
	return sidecarComputeComponent[SupportClient](self, supportComponentName)
}
