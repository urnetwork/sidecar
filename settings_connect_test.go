//go:build !sidecar_http

package sidecar

import (
	"testing"

	"github.com/urnetwork/connect"
)

// I-3: a sidecar's traffic over connect is Required, never Opportunistic or Off, so this default is
// a security property.
func TestDefaultConnectSettingsAreRequired(t *testing.T) {
	settings := DefaultSidecarSettings().Connect
	if settings.ClientSettings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
		t.Errorf("encryption mode %v", settings.ClientSettings.EncryptionSettings.Mode)
	}
}

func TestDefaultConnectSettingsAskForNoP2p(t *testing.T) {
	settings := DefaultSidecarSettings().Connect
	if settings.ClientSettings.DefaultTransferOpts.ForceStream {
		t.Error("a sidecar client asks for contract streams, which D-PROTO-10 rules out until C3")
	}
}

func TestDefaultConnectSettingsFillEveryField(t *testing.T) {
	settings := DefaultSidecarSettings().Connect
	if settings.ClientStrategySettings == nil || settings.ClientSettings == nil || settings.PlatformTransportSettings == nil {
		t.Errorf("%+v", settings)
	}
}

func TestDefaultConnectSettingsShareNothing(t *testing.T) {
	first := DefaultSidecarSettings().Connect
	second := DefaultSidecarSettings().Connect
	if first.ClientSettings == second.ClientSettings ||
		first.ClientSettings.EncryptionSettings == second.ClientSettings.EncryptionSettings ||
		first.ClientStrategySettings == second.ClientStrategySettings ||
		first.PlatformTransportSettings == second.PlatformTransportSettings {
		t.Error("connect settings are shared between calls")
	}
}
