//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// BridgeDiscoverySettings (§17.7.1; owner decision 778, owner decision 297): every limit and time §17.7.1 names, its
// default as given, and those the build adds to run it, each with its reason. The watch's format limits, which a host
// and its viewers hold alike, are protocol's DnsSdWireSettings, carried here whole.

package sidecar

import (
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The discovery component's tunables. A settings value is read, never changed, once a component holds it.
type BridgeDiscoverySettings struct {
	// The watch's limits both ends share: InstanceCount (256), AnswerByteCount (64 KiB), TxtByteCount (1,300 B),
	// NameByteCount (63) and WatchHoldTimeout (50 s). Nil is protocol's defaults.
	Wire *protocol.DnsSdWireSettings
	// The most continuous queries the gatherer's own querier sends a second on one interface: 20 (QueryRate; RFC 8766
	// §9.3). The Linux and Windows querier in cli/ reads it; mDNSResponder paces its own on macOS. Positive.
	QueryRate int
	// The most hosts a viewer watches at once, its own member's first: 64 (WatchHostCount). Positive.
	WatchHostCount int
	// How long a viewer waits to ask again a host that answered serving false: 1 h (NotServingRetryInterval).
	// Positive.
	NotServingRetryInterval time.Duration
	// How long a host's watch may keep failing before the viewer withdraws its instances: 90 s (HostLossTimeout).
	// Positive.
	HostLossTimeout time.Duration
	// How long a shared device may go unseen before its /32 route is withdrawn, its share kept: 7 days
	// (ShareRouteAbsentTimeout). Positive.
	ShareRouteAbsentTimeout time.Duration
	// The whole bound of one watch call, the host's hold and the round trip: 55 s, §6.6's call bound, past
	// WatchHoldTimeout so a held answer arrives inside it. Positive, past Wire.WatchHoldTimeout.
	WatchCallTimeout time.Duration
	// How long a viewer waits after a failed watch call before it calls again: 2 s, doubling at each further failure
	// to WatchRetryMaxInterval, 30 s, which stays under HostLossTimeout so a host is asked again before it is lost.
	// Both positive.
	WatchRetryInterval    time.Duration
	WatchRetryMaxInterval time.Duration
	// The TTL a listed entry's instance carries, renewed with each answer while it stays listed: 120 s
	// (DESIGN-COMPUTE.md §26.8). Positive.
	ListedTtl time.Duration
	// How long a watch served, or the person's own view asked, keeps the gatherer querying the LAN: 2 min, so a LAN is
	// queried on demand (RFC 8766 §1) and a viewer calling again within a hold keeps it running. Positive.
	GatherDemandTimeout time.Duration
	// How often the shares are judged for a move or an absence beside the gatherer's own reports: 1 min. Positive.
	ShareUpkeepInterval time.Duration
	// The most LAN devices a host shares at once: 64, each one /32 route. Positive.
	ShareCount int
	// The most hides the host keeps, ports and instances together: 1,024. Positive.
	HideCount int
}

// §17.7.1's values, and the build's.
func DefaultBridgeDiscoverySettings() *BridgeDiscoverySettings {
	return &BridgeDiscoverySettings{
		Wire:                    protocol.DefaultDnsSdWireSettings(),
		QueryRate:               20,
		WatchHostCount:          64,
		NotServingRetryInterval: 1 * time.Hour,
		HostLossTimeout:         90 * time.Second,
		ShareRouteAbsentTimeout: 7 * 24 * time.Hour,
		WatchCallTimeout:        55 * time.Second,
		WatchRetryInterval:      2 * time.Second,
		WatchRetryMaxInterval:   30 * time.Second,
		ListedTtl:               120 * time.Second,
		GatherDemandTimeout:     2 * time.Minute,
		ShareUpkeepInterval:     1 * time.Minute,
		ShareCount:              64,
		HideCount:               1024,
	}
}

// Whether the settings can run discovery.
func (self *BridgeDiscoverySettings) validate() error {
	wire := self.Wire
	if wire == nil {
		wire = protocol.DefaultDnsSdWireSettings()
	}
	positiveDurations := map[string]time.Duration{
		"NotServingRetryInterval": self.NotServingRetryInterval,
		"HostLossTimeout":         self.HostLossTimeout,
		"ShareRouteAbsentTimeout": self.ShareRouteAbsentTimeout,
		"WatchCallTimeout":        self.WatchCallTimeout,
		"WatchRetryInterval":      self.WatchRetryInterval,
		"WatchRetryMaxInterval":   self.WatchRetryMaxInterval,
		"ListedTtl":               self.ListedTtl,
		"GatherDemandTimeout":     self.GatherDemandTimeout,
		"ShareUpkeepInterval":     self.ShareUpkeepInterval,
		"WatchHoldTimeout":        wire.WatchHoldTimeout,
	}
	for name, value := range positiveDurations {
		if value <= 0 {
			return fmt.Errorf("%w: BridgeDiscoverySettings.%s is not positive", errInvalidSettings, name)
		}
	}
	positiveCounts := map[string]int{
		"QueryRate":       self.QueryRate,
		"WatchHostCount":  self.WatchHostCount,
		"ShareCount":      self.ShareCount,
		"HideCount":       self.HideCount,
		"InstanceCount":   wire.InstanceCount,
		"AnswerByteCount": wire.AnswerByteCount,
		"TxtByteCount":    wire.TxtByteCount,
		"NameByteCount":   wire.NameByteCount,
	}
	for name, value := range positiveCounts {
		if value <= 0 {
			return fmt.Errorf("%w: BridgeDiscoverySettings.%s is not positive", errInvalidSettings, name)
		}
	}
	if self.WatchCallTimeout <= wire.WatchHoldTimeout {
		return fmt.Errorf("%w: BridgeDiscoverySettings.WatchCallTimeout is not past the hold", errInvalidSettings)
	}
	return nil
}

// The wire's limits these settings carry.
func (self *BridgeDiscoverySettings) wire() *protocol.DnsSdWireSettings {
	if self.Wire == nil {
		return protocol.DefaultDnsSdWireSettings()
	}
	return self.Wire
}
