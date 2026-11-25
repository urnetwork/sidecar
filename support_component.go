//go:build !ios_extension && !sidecar_http

// The support client as a Sidecar's compute component (DESIGN-COMPUTE §28.4, compute_sidecar.go): constructed as the
// Sidecar starts, on its local store's support directory and its host's support log, and closed as it ends. Its
// sources beyond the Sidecar (support_sources.go) start unset, so until their owners land every message answers
// disclosure_required and nothing is posted; and the release's switch, SupportSettings.ServiceEnabled, is off until
// G-SUP-service passes, so every surface answers ErrSupportUnavailable meanwhile (§28.21).

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
// its settings and its host's support log.
func newSidecarSupportClient(sidecar *Sidecar) (*SupportClient, error) {
	supportLog, _ := sidecar.settings.SupportLog.(*SupportLog)
	return NewSupportClient(&SupportClientArgs{
		Host:     sidecar,
		Settings: sidecar.settings.Support,
		Log:      supportLog,
		Store: func() (SidecarStore, error) {
			return sidecar.LocalStore().Directory(supportStoreName, supportStoreName)
		},
		Clock:      sidecar.settings.Clock,
		BundleHost: &SupportLogBundleHost{Version: Version},
	})
}

// This Sidecar's support client, or why it has none.
func (self *Sidecar) Support() (*SupportClient, error) {
	return sidecarComputeComponent[SupportClient](self, supportComponentName)
}
