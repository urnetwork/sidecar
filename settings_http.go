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

// Argon2id's cost on this leg: OWASP's 19 MiB, t=2, p=1, §5.9's wasm cost, since js/wasm runs one thread and the
// page Worker keeps within §18.4's working set.
func defaultSidecarPassCost() (memoryByteCount int64, iterationCount int, threadCount int) {
	return 19 * 1024 * 1024, 2, 1
}

// What validate adds on this leg: nothing, since PlatformUrl and the connect settings go unread here.
func (self *SidecarSettings) validateLeg() error {
	return nil
}
