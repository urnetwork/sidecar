// device.Bridge's tunables (§17.5, §17.8): every timing and size a bridge reads comes from here, with §17's values as
// the defaults. DefaultBridgeSettings is the desktop's, and MobileBridgeSettings adjusts it for a phone's memory, as
// connect's applyMobile settings do, so each number has one default. The few functions here are what the device's
// host hands the bridge: the sidecar role's signer, the binding fetch, the interface subnets and the resolver upstream.

package device

import (
	"errors"
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The tunables of one bridge. A settings value is read, never changed, once a bridge holds it.
type BridgeSettings struct {
	// What the bridge reads time from: drains, expiries, pins, idles and the reject bucket. Nil is real time.
	Clock Clock
	// The posture the bridge embeds. Nil is DefaultPostureSettings.
	PostureSettings *PostureSettings
	// Which of §17.6's tables the bridge's provider hook runs: a sidecar-owned host's, the zero value, or the sdk exit
	// NAT's until C16 (BridgePolicyProfileSdkProvider).
	PolicyProfile BridgePolicyProfile
	// The revocations Bridge.Revoke holds between states, each until a state at or past its position confirms or
	// reverses it: 4,096, as many as the posture's overlay. Past it Revoke refuses, and the next state, which carries
	// the revocation, applies it. Positive.
	RevocationMaxCount int
	// The longest id Bridge.Revoke takes: 64 bytes, a grant's or a rule's 32 with room for an atom's. A longer one is
	// refused. Positive.
	RevocationIdMaxByteCount int

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
	// pairs while another advertiser of its entry is up, and keeps its pins. A build that failed is tried again only
	// after it. Positive.
	LinkDownTimeout time.Duration
	// How long a link has to form its sealed session before that counts as a refusal (§17.5's health row,
	// plan-BRIDGE-small-readings #15): 3 s from the first packet it is handed. Positive.
	LinkConnectTimeout time.Duration
	// How long a link idles before it closes: 600 s, as long as a TCP pin (§17.5's links row). Positive.
	LinkIdleTimeout time.Duration
	// How old a link grows before it is rebuilt, the old one draining until its window clients' strict_exp: 6 days,
	// inside §7.4's 7-day strict_exp. Positive.
	LinkRebuildInterval time.Duration
	// How long fetching a link target's binding may take before the build fails as a refusal would: 30 s, a window
	// client's own setup bound. The host's NewBridgeLink only constructs, and window clients set up on their own bound.
	// Positive.
	LinkBuildTimeout time.Duration
	// The largest SignedSidecarIdentityBinding a link reads of its target: 4 KiB, where a canonical binding is under
	// 250 bytes, so this only stops a decoder reading garbage whole. Positive.
	LinkBindingMaxByteCount int
	// The WindowDelegation format's limits, which this host's verifier and its links' signers share
	// (bridge.DefaultWindowDelegationSettings). Nil is the format's own.
	WindowDelegation *bridge.WindowDelegationSettings
	// Whether a link's window client may go direct, peer to peer: false until C3 (D-PROTO-10, D-BRIDGE-5), so
	// BridgeLinkMultiClientSettings overrides direct mode off and a link relays.
	LinkAllowDirect bool
	// How many links a bridge holds open before building another closes its least recently used idle one: §18.4's
	// memory budget counted in links, since a window client carries a whole client graph (§17.5's memory row). It is
	// no cap: a busy link is never closed for room and no build is refused for count (R-BRIDGE-11), so past it with no
	// idle link the build goes ahead. 64 on desktop and 8 on mobile until §22.9 measures a link. 0 builds no link at
	// all, the iOS tunnel's setting until that measurement (owner decision 100), and every link entry answers with a
	// reject. Negative holds any number open.
	LinkCountMax int
	// How long a link must have carried nothing before a bridge past LinkCountMax may close it for room: 60 s, so a
	// link carrying a live exchange is never the one closed. Positive.
	LinkRoomIdleTimeout time.Duration
	// Signs each window client's WindowDelegation as this device's sidecar role (§17.9's sign, §18.6's signer row):
	// in process, or over §18.6's channel for a keyless device role. Nil builds no link, so every link entry answers
	// with a reject.
	LinkSign BridgeSignFunction
	// Fetches a link target's identity binding, which the link verifies against the key the rules pin before any
	// contract (§17.9's target check). Nil builds no link.
	LinkTargetKey BridgeTargetKeyFunction

	// The per-source token bucket a reject enters the tun through (§17.5's rejects row): 20 a second, a burst of 40,
	// since connect writes policy resets unthrottled. Both positive, and the burst at most 16,383.
	RejectPerSecond int
	RejectBurst     int
	// The sources whose buckets a bridge keeps at once: 256, rounded up to a power of two. A source whose hash finds
	// every slot it may take held by another source short of a full bucket sends no reject, which is counted.
	// Positive.
	RejectSourceSlotCount int
	// How long an entry whose last advertiser was revoked answers its packets with a reset or a prohibited reply
	// before it leaves the table (§17.8's revocation row): 600 s. Positive.
	RejectEntryHoldTimeout time.Duration
	// The device's interface subnets, which a granted subnet route may not overlap (§17.7's sender conflicts): nil
	// reads connect.LocalIpv4Networks, which is itself nil where interfaces cannot be enumerated, and then only the
	// carve of Bridge.SetLocalAddresses applies.
	LocalIpv4Networks func() []netip.Prefix

	// How long a private name's answer may be cached (§12.9): 60 s, so a name a new state moves resolves anew within
	// a minute. Positive.
	NameTtl time.Duration
	// Where `ur tun`'s resolver sends a query for a name the zone does not own (§12.9's pass-through): the host's
	// system resolver, never this bridge's own <block>.0.53. Nil answers such a query with a server failure.
	ResolverUpstream BridgeResolverUpstream
	// The pass-through queries waiting for the upstream at once: 64. One more is dropped and counted. Positive.
	ResolverQueueCount int
	// The pass-through queries in flight at once, each on a worker of its own: 4, so one slow answer holds up few.
	// Positive.
	ResolverWorkerCount int
	// How long one pass-through query may take upstream: 5 s, a stub resolver's own retry interval. Positive.
	ResolverUpstreamTimeout time.Duration

	// The largest marshalled BridgeRules ParseBridgeRules reads: 8 MiB, as large as the posture keeps a state. Positive.
	RulesMaxByteCount int
	// The most messages, strings and byte fields ParseBridgeRules decodes, at every depth. Decoding allocates per
	// field, so with RulesMaxByteCount this bounds what a parse holds whatever the bytes say. Positive.
	RulesMaxFieldCount int
}

// §17's values, for a desktop: a daemon, a desktop network process or a VPS.
func DefaultBridgeSettings() *BridgeSettings {
	return &BridgeSettings{
		PinSlotCount:             8192,
		PinTcpIdleTimeout:        600 * time.Second,
		PinIdleTimeout:           5 * time.Minute,
		PinTouchInterval:         1 * time.Second,
		LinkDownTimeout:          30 * time.Second,
		LinkConnectTimeout:       3 * time.Second,
		LinkIdleTimeout:          600 * time.Second,
		LinkRebuildInterval:      6 * 24 * time.Hour,
		LinkBuildTimeout:         30 * time.Second,
		LinkBindingMaxByteCount:  4 * 1024,
		WindowDelegation:         bridge.DefaultWindowDelegationSettings(),
		LinkCountMax:             64,
		LinkRoomIdleTimeout:      60 * time.Second,
		RejectPerSecond:          20,
		RejectBurst:              40,
		RejectSourceSlotCount:    256,
		RejectEntryHoldTimeout:   600 * time.Second,
		NameTtl:                  60 * time.Second,
		ResolverQueueCount:       64,
		ResolverWorkerCount:      4,
		ResolverUpstreamTimeout:  5 * time.Second,
		RulesMaxByteCount:        8 * 1024 * 1024,
		RulesMaxFieldCount:       1024 * 1024,
		RevocationMaxCount:       4 * 1024,
		RevocationIdMaxByteCount: 64,
	}
}

// The defaults adjusted for a phone (§17.5): 1,024 pin slots, which §22.9's mobile churn case runs past, and 8 links
// before one idle for LinkRoomIdleTimeout closes for room. The iOS tunnel sets LinkCountMax to 0 on top of these until
// §22.9 measures a link there (owner decision 100).
func MobileBridgeSettings() *BridgeSettings {
	settings := DefaultBridgeSettings()
	settings.PinSlotCount = 1024
	settings.LinkCountMax = 8
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
		{name: "LinkBuildTimeout", value: self.LinkBuildTimeout},
		{name: "LinkRoomIdleTimeout", value: self.LinkRoomIdleTimeout},
		{name: "RejectEntryHoldTimeout", value: self.RejectEntryHoldTimeout},
		{name: "NameTtl", value: self.NameTtl},
		{name: "ResolverUpstreamTimeout", value: self.ResolverUpstreamTimeout},
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
		{name: "RejectSourceSlotCount", value: self.RejectSourceSlotCount},
		{name: "ResolverQueueCount", value: self.ResolverQueueCount},
		{name: "ResolverWorkerCount", value: self.ResolverWorkerCount},
		{name: "RulesMaxByteCount", value: self.RulesMaxByteCount},
		{name: "RulesMaxFieldCount", value: self.RulesMaxFieldCount},
		{name: "RevocationMaxCount", value: self.RevocationMaxCount},
		{name: "RevocationIdMaxByteCount", value: self.RevocationIdMaxByteCount},
		{name: "LinkBindingMaxByteCount", value: self.LinkBindingMaxByteCount},
	}
	for _, count := range positiveCounts {
		if count.value <= 0 {
			return errors.Join(ErrBridgeSettingsInvalid, errors.New(count.name+" is not positive"))
		}
	}
	if self.PinTouchInterval < 0 {
		return errors.Join(ErrBridgeSettingsInvalid, errors.New("PinTouchInterval is negative"))
	}
	if bridgeRejectTokensMax < self.RejectBurst {
		return errors.Join(ErrBridgeSettingsInvalid, errors.New("RejectBurst is past what a bucket holds"))
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
