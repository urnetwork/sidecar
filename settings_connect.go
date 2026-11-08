//go:build !sidecar_http

// The settings of a Sidecar's own connect clients, one per client generation (§5.4). settings_http.go
// is the sidecar_http leg, which links no connect package and declares this type empty.

package sidecar

import (
	"fmt"

	"github.com/urnetwork/connect"
)

// connect's own settings, each with connect's defaults and connect's rules for its fields. None may
// be nil.
type SidecarConnectSettings struct {
	// How a client dials: connect's default.
	ClientStrategySettings *connect.ClientStrategySettings
	// Required, no P2P. A client provides Network, plus Service while on tls/ or smtp/ (§13.6) and
	// FriendsAndFamily while sharing (§8.11), never Public (§6).
	ClientSettings *connect.ClientSettings
	// The platform connection: connect's default.
	PlatformTransportSettings *connect.PlatformTransportSettings
}

// A fresh value each call, as DefaultSidecarSettings's is. ApplySidecarClientSettings (rpc_subprotocol.go)
// is what makes the client a sidecar's, whatever connect's defaults become, and validateLeg refuses
// settings a host adjusted away from it.
func defaultSidecarConnectSettings() *SidecarConnectSettings {
	clientSettings := connect.DefaultClientSettings()
	ApplySidecarClientSettings(clientSettings)
	return &SidecarConnectSettings{
		ClientStrategySettings:    connect.DefaultClientStrategySettings(),
		ClientSettings:            clientSettings,
		PlatformTransportSettings: connect.DefaultPlatformTransportSettings(),
	}
}

// What validate adds on connect legs: the client's url, and a client that is a sidecar's. A host
// adjusts these settings, so I-3's mode is checked here and not only set above.
func (self *SidecarSettings) validateLeg() error {
	if err := checkServiceUrl("PlatformUrl", self.PlatformUrl, "ws", "wss"); err != nil {
		return err
	}
	clientSettings := self.Connect.ClientSettings
	if self.Connect.ClientStrategySettings == nil || clientSettings == nil || self.Connect.PlatformTransportSettings == nil {
		return fmt.Errorf("%w: Connect is missing its settings", errInvalidSettings)
	}
	if clientSettings.EncryptionSettings == nil || clientSettings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
		return fmt.Errorf("%w: Connect's encryption mode is not Required", errInvalidSettings)
	}
	if clientSettings.DefaultTransferOpts.ForceStream {
		return fmt.Errorf("%w: Connect asks for P2P streams", errInvalidSettings)
	}
	return nil
}
