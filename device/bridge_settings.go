// device.Bridge's tunables (§17.5, §17.8): every timing and size a bridge reads comes from here, with §17's values as
// the defaults. DefaultBridgeSettings is the desktop's, and MobileBridgeSettings adjusts it for a phone's memory, as
// connect's applyMobile settings do, so each number has one default.

package device

import (
	"errors"
	"time"
)

// The tunables of one bridge. A settings value is read, never changed, once a bridge holds it.
type BridgeSettings struct {
	// What the bridge reads time from: drains, expiries, pins, idles and the reject bucket. Nil is real time.
	Clock Clock
	// The posture the bridge embeds. Nil is DefaultPostureSettings.
	PostureSettings *PostureSettings

	// The slots of the sender's pin table (§17.5's pins row): 8,192 on desktop, 1,024 on mobile. A pin keeps one live
	// pair on its link where an entry offers a choice. With no free slot a pair routes by the hash, unpinned, and
	// nothing is refused (owner decision 66). Rounded up to a power of two; at least 1.
	PinSlotCount int
	// How long a TCP pair or connection keeps its pin after its last packet: 600 s, a link's TCP idle (§17.5's idle
	// row). It is also how long a window holds TCP pairs after an entry first offers a choice, and the least a removed
	// link keeps its TCP pins (the removed row's max(drain_seconds, 600 s)). Positive.
	PinTcpIdleTimeout time.Duration
	// The same for UDP, ICMP and every other protocol: 5 min. Positive.
	PinIdleTimeout time.Duration
	// The least time between two writes of one pin's last-seen time, so a busy pair costs at most one atomic store a
	// second (§17.5's record row). Pins keep whole seconds, so it rounds up to one; 0 is one second. Non-negative.
	PinTouchInterval time.Duration

	// How long a refusal or a connect timeout marks a link down (§17.5's health row): 30 s. A down link takes no new
	// pairs while another advertiser of its entry is up, and keeps its pins. Positive.
	LinkDownTimeout time.Duration
	// How long a link has to form its sealed session before that counts as a refusal (§17.5's health row,
	// plan-BRIDGE-small-readings #15): 3 s. Positive.
	LinkConnectTimeout time.Duration
	// How long a link idles before it closes: 600 s, as long as a TCP pin (§17.5's links row). Positive.
	LinkIdleTimeout time.Duration
	// How old a link grows before it is rebuilt, the old one draining until its window clients' strict_exp: 6 days,
	// inside §7.4's 7-day strict_exp. Positive.
	LinkRebuildInterval time.Duration

	// The per-source token bucket a reject enters the tun through (§17.5's rejects row): 20 a second, a burst of 40,
	// since connect writes policy resets unthrottled. Both positive.
	RejectPerSecond int
	RejectBurst     int
	// How long an entry whose last advertiser was revoked answers its packets with a reset or a prohibited reply
	// before it leaves the table (§17.8's revocation row): 600 s. Positive.
	RejectEntryHoldTimeout time.Duration

	// The largest marshalled BridgeRules ParseBridgeRules reads: 8 MiB, as large as the posture keeps a state. Positive.
	RulesMaxByteCount int
	// The most messages, strings and byte fields ParseBridgeRules decodes, at every depth. Decoding allocates per
	// field, so with RulesMaxByteCount this bounds what a parse holds whatever the bytes say. Positive.
	RulesMaxFieldCount int
}

// §17's values, for a desktop: a daemon, a desktop network process or a VPS.
func DefaultBridgeSettings() *BridgeSettings {
	return &BridgeSettings{
		PinSlotCount:           8192,
		PinTcpIdleTimeout:      600 * time.Second,
		PinIdleTimeout:         5 * time.Minute,
		PinTouchInterval:       1 * time.Second,
		LinkDownTimeout:        30 * time.Second,
		LinkConnectTimeout:     3 * time.Second,
		LinkIdleTimeout:        600 * time.Second,
		LinkRebuildInterval:    6 * 24 * time.Hour,
		RejectPerSecond:        20,
		RejectBurst:            40,
		RejectEntryHoldTimeout: 600 * time.Second,
		RulesMaxByteCount:      8 * 1024 * 1024,
		RulesMaxFieldCount:     1024 * 1024,
	}
}

// The defaults adjusted for a phone (§17.5): 1,024 pin slots, which §22.9's mobile churn case runs past.
func MobileBridgeSettings() *BridgeSettings {
	settings := DefaultBridgeSettings()
	settings.PinSlotCount = 1024
	return settings
}

// Settings a bridge cannot run on.
var ErrBridgeSettingsInvalid = errors.New("bridge settings invalid")

// Whether the settings can run a bridge; ErrBridgeSettingsInvalid names the first field that cannot.
func (self *BridgeSettings) validate() error {
	positiveDurations := []struct {
		name  string
		value time.Duration
	}{
		{name: "PinTcpIdleTimeout", value: self.PinTcpIdleTimeout},
		{name: "PinIdleTimeout", value: self.PinIdleTimeout},
		{name: "LinkDownTimeout", value: self.LinkDownTimeout},
		{name: "LinkConnectTimeout", value: self.LinkConnectTimeout},
		{name: "LinkIdleTimeout", value: self.LinkIdleTimeout},
		{name: "LinkRebuildInterval", value: self.LinkRebuildInterval},
		{name: "RejectEntryHoldTimeout", value: self.RejectEntryHoldTimeout},
	}
	for _, duration := range positiveDurations {
		if duration.value <= 0 {
			return errors.Join(ErrBridgeSettingsInvalid, errors.New(duration.name+" is not positive"))
		}
	}
	positiveCounts := []struct {
		name  string
		value int
	}{
		{name: "PinSlotCount", value: self.PinSlotCount},
		{name: "RejectPerSecond", value: self.RejectPerSecond},
		{name: "RejectBurst", value: self.RejectBurst},
		{name: "RulesMaxByteCount", value: self.RulesMaxByteCount},
		{name: "RulesMaxFieldCount", value: self.RulesMaxFieldCount},
	}
	for _, count := range positiveCounts {
		if count.value <= 0 {
			return errors.Join(ErrBridgeSettingsInvalid, errors.New(count.name+" is not positive"))
		}
	}
	if self.PinTouchInterval < 0 {
		return errors.Join(ErrBridgeSettingsInvalid, errors.New("PinTouchInterval is negative"))
	}
	return nil
}

// The clock the settings name, real time when none.
func (self *BridgeSettings) clock() Clock {
	if self.Clock == nil {
		return RealClock{}
	}
	return self.Clock
}
