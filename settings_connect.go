//go:build !sidecar_http

// The settings of a Sidecar's own connect clients, one per client generation (§5.4). settings_http.go
// is the sidecar_http leg, which links no connect package and declares this type empty.

package sidecar

import (
	"fmt"

	"github.com/urnetwork/connect"
)

// connect's own settings, each with connect's defaults and connect's rules for its fields, and the
// outbound mail sender's, which only connect legs run. None may be nil but SmtpProver and Platform.
type SidecarConnectSettings struct {
	// How a client dials: connect's default.
	ClientStrategySettings *connect.ClientStrategySettings
	// Required, no P2P. A client provides Network, plus Service while on tls/ or smtp/ (§13.6) and
	// FriendsAndFamily while sharing (§8.11), never Public (§6).
	ClientSettings *connect.ClientSettings
	// The platform connection: connect's default.
	PlatformTransportSettings *connect.PlatformTransportSettings
	// SmtpSender's schedule and limits (§14.4, §14.5).
	SmtpSender *SmtpSenderSettings
	// The prover a desktop build injects from the nested module smtpproof, which the root never
	// requires (D-SMTP-11). Nil, the default and every phone's: this host queues its internet mail
	// to the member's outbox for a prover host, and never sends it itself (D-SMTP-18).
	SmtpProver SmtpProver
	// How a client generation reaches the platform. Nil, the default: connect's own, an
	// ApiOutOfBandControl and a PlatformTransport (sidecar_new_connect.go). sidecartest's Net sets
	// its in-process exchange.
	Platform SidecarPlatform
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
		SmtpSender:                DefaultSmtpSenderSettings(),
	}
}

// Argon2id's cost on connect legs: RFC 9106 §4's 64 MiB, t=3, p=4 (§5.9). An sdk mobile host lowers it to OWASP's 19
// MiB, t=2, p=1 as it adjusts its other settings (§18.4).
func defaultSidecarPassCost() (memoryByteCount int64, iterationCount int, threadCount int) {
	return 64 * 1024 * 1024, 3, 4
}

// What validate adds on connect legs: the client's url, a client that is a sidecar's, and the
// sender's settings. A host adjusts these settings, so I-3's mode is checked here and not only set
// above. A nil SmtpProver is a valid host, one that only queues.
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
	return self.Connect.SmtpSender.validate()
}
