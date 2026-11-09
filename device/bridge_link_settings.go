// What a host builds a link from (Q-BRIDGE-2, §17.5's links row, D-BRIDGE-5): one multi client per target, asking the
// platform for the target alone, with a fixed window of one Required window client, relayed until C3, carrying ICMP.
// Both hosts, the sdk's DeviceLocal and the CLI, build their links from these, so neither keeps a second copy of the
// numbers. Never DefaultMultiClientSettings' six-client quality window, which is the wrong default and six times the
// memory: CheckBridgeLinkMultiClientSettings refuses it, and a host's tests run it on what they build.

package device

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect"
)

// Multi client settings that break a link's shape.
var ErrBridgeLinkSettingsInvalid = errors.New("bridge link settings invalid")

// The window a link runs: one window client, fixed, never grown.
func bridgeLinkWindowSize() connect.WindowSizeSettings {
	return connect.WindowSizeSettings{
		WindowSizeMin:     1,
		WindowSizeMax:     1,
		WindowSizeHardMax: 1,
		FixedWindowSize:   1,
	}
}

// The provider spec a link's generator asks for: the target's client, by id, and nothing else, so discovery never
// hands the link another provider.
func BridgeLinkProviderSpecs(target connect.Id) []*connect.ProviderSpec {
	clientId := target
	return []*connect.ProviderSpec{{ClientId: &clientId}}
}

// The API generator settings a link's generator runs on, from the host's own (its credentials, control and
// transports): no identity is parked for reuse, so each window client a link builds is a fresh child of the subject,
// with its own strict_exp, which the generator wrapper signs for at its NewClient (§17.9's sign). Nil starts from the
// defaults. Returns a copy.
func BridgeLinkApiMultiClientGeneratorSettings(base *connect.ApiMultiClientGeneratorSettings) *connect.ApiMultiClientGeneratorSettings {
	if base == nil {
		base = connect.DefaultApiMultiClientGeneratorSettings()
	}
	settings := *base
	settings.ReuseFixedDestinationIdentities = false
	settings.DiscoveryIdentityParkMaxCount = 0
	return &settings
}

// The multi client settings a link runs on: connect's defaults for every timing, with a fixed window of one window
// client in every window type, post-quantum Required sessions, direct mode overridden to settings.LinkAllowDirect
// (false until C3), and ICMP echo on. Nil settings are DefaultBridgeSettings. Returns new settings each call.
func BridgeLinkMultiClientSettings(settings *BridgeSettings) *connect.MultiClientSettings {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	multiClientSettings := connect.DefaultMultiClientSettings()
	windowSize := bridgeLinkWindowSize()
	multiClientSettings.WindowSizes = map[connect.WindowType]connect.WindowSizeSettings{
		connect.WindowTypeQuality: windowSize,
		connect.WindowTypeSpeed:   windowSize,
	}
	multiClientSettings.WindowSizeLimit = 1
	multiClientSettings.DefaultPerformanceProfile = &connect.PerformanceProfile{
		WindowType:            connect.WindowTypeQuality,
		WindowSize:            windowSize,
		AllowDirect:           settings.LinkAllowDirect,
		PostQuantumEncryption: true,
	}
	allowDirect := settings.LinkAllowDirect
	multiClientSettings.OverrideAllowDirect = &allowDirect
	multiClientSettings.EnableIcmp = true
	return multiClientSettings
}

// Whether multiClientSettings give a link its shape: a fixed quality profile of one window client, post-quantum
// Required, every window type held to one, direct overridden to allowDirect, and ICMP on. A host runs it on what it
// builds; DefaultMultiClientSettings fails it.
func CheckBridgeLinkMultiClientSettings(multiClientSettings *connect.MultiClientSettings, allowDirect bool) error {
	if multiClientSettings == nil {
		return fmt.Errorf("%w: none", ErrBridgeLinkSettingsInvalid)
	}
	windowSize := bridgeLinkWindowSize()
	profile := multiClientSettings.DefaultPerformanceProfile
	if profile == nil || profile.WindowType == connect.WindowTypeAuto {
		return fmt.Errorf("%w: no fixed performance profile", ErrBridgeLinkSettingsInvalid)
	}
	if profile.WindowSize != windowSize {
		return fmt.Errorf("%w: a profile window other than one fixed window client", ErrBridgeLinkSettingsInvalid)
	}
	if !profile.PostQuantumEncryption {
		return fmt.Errorf("%w: sessions not Required", ErrBridgeLinkSettingsInvalid)
	}
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("%w: the profile does not validate", ErrBridgeLinkSettingsInvalid)
	}
	for _, windowType := range []connect.WindowType{connect.WindowTypeQuality, connect.WindowTypeSpeed} {
		size, ok := multiClientSettings.WindowSizes[windowType]
		if !ok || size.WindowSizeMax != 1 || size.WindowSizeHardMax != 1 || size.FixedWindowSize != 1 {
			return fmt.Errorf("%w: a window that may hold more than one window client", ErrBridgeLinkSettingsInvalid)
		}
	}
	if multiClientSettings.OverrideAllowDirect == nil || *multiClientSettings.OverrideAllowDirect != allowDirect ||
		profile.AllowDirect != allowDirect {
		return fmt.Errorf("%w: direct mode not overridden as the bridge sets it", ErrBridgeLinkSettingsInvalid)
	}
	if !multiClientSettings.EnableIcmp {
		return fmt.Errorf("%w: ICMP off", ErrBridgeLinkSettingsInvalid)
	}
	return nil
}
