//go:build sidecar_http

// The sidecar_http leg's connect settings: none, since this leg links no connect package and has no
// client generations (§5.4).

package sidecar

type SidecarConnectSettings struct {
}

func defaultSidecarConnectSettings() *SidecarConnectSettings {
	return &SidecarConnectSettings{}
}
