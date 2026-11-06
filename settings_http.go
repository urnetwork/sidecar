//go:build sidecar_http

// The sidecar_http leg's connect settings: none, since this leg links no connect package and has no
// client generations (§5.4).

package sidecar

// Empty, and never nil, so a host may read the field on every leg.
type SidecarConnectSettings struct {
}

// A fresh value each call, as DefaultSidecarSettings's is.
func defaultSidecarConnectSettings() *SidecarConnectSettings {
	return &SidecarConnectSettings{}
}

// What validate adds on this leg: nothing, since PlatformUrl and the connect settings go unread here.
func (self *SidecarSettings) validateLeg() error {
	return nil
}
