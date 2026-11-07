//go:build !sidecar_http

package sidecar

import (
	"errors"
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

// Starts from a client that is everything a sidecar's must not be, so each line of the policy has
// something to change: connect's own defaults already leave ForceStream off.
func TestSidecarClientSettingsOverrideConnectsDefaults(t *testing.T) {
	clientSettings := connect.DefaultClientSettings()
	clientSettings.EncryptionSettings.Mode = connect.EncryptionModeOpportunistic
	clientSettings.DefaultTransferOpts.ForceStream = true

	applySidecarClientSettings(clientSettings)

	if clientSettings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
		t.Errorf("encryption mode %v", clientSettings.EncryptionSettings.Mode)
	}
	if clientSettings.DefaultTransferOpts.ForceStream {
		t.Error("ForceStream stayed on")
	}
}

// PlatformUrl is the one url only connect legs read.
func TestPlatformUrlIsRequiredAndNotHttp(t *testing.T) {
	for _, platformUrl := range []string{"", "/connect", "https://connect.example", "wss://connect.example/"} {
		settings := validSidecarSettings()
		settings.PlatformUrl = platformUrl
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%q: %v", platformUrl, err)
		}
	}
	settings := validSidecarSettings()
	settings.PlatformUrl = "ws://127.0.0.1:50080"
	if err := settings.validate(); err != nil {
		t.Error(err)
	}
}

// A host adjusts what it gets, so I-3 and D-PROTO-10 are held at the door as well as by default.
func TestAClientThatIsNotASidecarsIsRefused(t *testing.T) {
	for _, c := range []struct {
		name   string
		adjust func(settings *SidecarConnectSettings)
	}{
		{name: "off", adjust: func(settings *SidecarConnectSettings) {
			settings.ClientSettings.EncryptionSettings.Mode = connect.EncryptionModeOff
		}},
		{name: "opportunistic", adjust: func(settings *SidecarConnectSettings) {
			settings.ClientSettings.EncryptionSettings.Mode = connect.EncryptionModeOpportunistic
		}},
		{name: "no encryption settings", adjust: func(settings *SidecarConnectSettings) {
			settings.ClientSettings.EncryptionSettings = nil
		}},
		{name: "p2p", adjust: func(settings *SidecarConnectSettings) {
			settings.ClientSettings.DefaultTransferOpts.ForceStream = true
		}},
		{name: "no client settings", adjust: func(settings *SidecarConnectSettings) {
			settings.ClientSettings = nil
		}},
		{name: "no strategy settings", adjust: func(settings *SidecarConnectSettings) {
			settings.ClientStrategySettings = nil
		}},
		{name: "no transport settings", adjust: func(settings *SidecarConnectSettings) {
			settings.PlatformTransportSettings = nil
		}},
	} {
		settings := validSidecarSettings()
		c.adjust(settings.Connect)
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%s: %v", c.name, err)
		}
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
