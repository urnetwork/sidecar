//go:build windows

// Windows Hello as ur daemon's presence provider (MCP-M3-09; §16.6's webauthn-es256 profile): webauthn.dll's
// WebAuthNAuthenticatorMakeCredential and WebAuthNAuthenticatorGetAssertion with rp ur.io and user verification
// required, which reach Windows Hello and any FIDO key the platform sees. Not built in this draft: no struct of
// webauthn.h is laid out here yet, so a Windows host has no presence provider, every prompt refuses, ur keys
// add-presence answers that the host has none, and this sidecar's own requests wait for another device's decision.

package main

import (
	"github.com/urnetwork/sidecar"
)

// No provider until webauthn.dll's binding lands.
func urPlatformPresenceProvider(stateDirectory string, ingest *sidecar.SidecarIngestSettings, log sidecar.Logger) sidecar.PresenceProvider {
	return nil
}
