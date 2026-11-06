//go:build !sidecar_http

// The settings of a Sidecar's own connect clients, one per client generation (§5.4). settings_http.go
// is the sidecar_http leg, which links no connect package and declares this type empty.

package sidecar

import (
	"github.com/urnetwork/connect"
)

type SidecarConnectSettings struct {
	ClientStrategySettings *connect.ClientStrategySettings
	// Required, no P2P. A client provides Network, plus Service while on tls/ or smtp/ (§13.6) and
	// FriendsAndFamily while sharing (§8.11), never Public (§6).
	ClientSettings            *connect.ClientSettings
	PlatformTransportSettings *connect.PlatformTransportSettings
}

func defaultSidecarConnectSettings() *SidecarConnectSettings {
	clientSettings := connect.DefaultClientSettings()
	// I-3: never Opportunistic or Off, so a peer that cannot seal gets no application data
	clientSettings.EncryptionSettings.Mode = connect.EncryptionModeRequired
	// sidecar clients never ask for a P2P stream, so pairs stay relay-only until C3 is tested
	// (D-PROTO-10)
	clientSettings.DefaultTransferOpts.ForceStream = false
	return &SidecarConnectSettings{
		ClientStrategySettings:    connect.DefaultClientStrategySettings(),
		ClientSettings:            clientSettings,
		PlatformTransportSettings: connect.DefaultPlatformTransportSettings(),
	}
}
