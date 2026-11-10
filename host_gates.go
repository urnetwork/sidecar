//go:build !sidecar_http && !ios_extension

// ServiceHost.Gates: §19.11's gates (D-OPS-10), as config/<env>/sidecar.yml sets them. The host
// rereads the file every 60 s, so an engine asks on each request and keeps no answer. Engines cannot
// import server, so the host supplies the gates through this root interface (plan-OPS-small-readings
// #1), server over its reader of the file, and sidecartest.FakeServiceGates over a test's text of the
// same file. Both answer one table, testdata/gates/table.yml.
//
// Every answer fails closed. A gate the file does not open is closed, a broken file on a process's
// first read opens nothing, and a later broken read keeps the last good one. A closed service stays
// ready and answers 503 with Retry-After (§19.11), so a rollout does not revert it, and an incident
// turns writes off with `writes: false` while reads go on.
//
// A network is in a gate when the gate is enabled and the network is listed, or enabled and the
// network's bucket, ServiceGateBucket, is under its percent. One bucket serves every gate, so a
// network at 10% of evs is at 10% of gkm too, and format 2's gate and every reader agree.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/urnetwork/connect"
)

// The services §19.11 gates by name, as the file spells them.
const (
	ServiceGateEvs      = "evs"
	ServiceGateGkm      = "gkm"
	ServiceGateSockets  = "sockets"
	ServiceGateTlsedge  = "tlsedge"
	ServiceGateMxedge   = "mxedge"
	ServiceGateSmtpedge = "smtpedge"
	ServiceGateDns      = "dns"
)

// §19.11's switches, each only `enabled`.
const (
	// §6's EnableSidecarPush.
	GateSwitchPush = "push"
	// §19.4's push sender.
	GateSwitchWake = "wake"
	// §17's EnableBridge.
	GateSwitchBridge = "bridge"
	// §20.9's draw order (D-QUOTA-9), on once M6's Gn-out registers MG6's index.
	GateSwitchEscrowDrawOrder = "escrow_draw_order"
)

// The gates as the host last read them. Safe for concurrent use; no method does I/O, so each may be
// called on a request's path.
type ServiceGates interface {
	// The named service's gate. A service the file holds no gate for, or one this interface does not
	// know, answers closed.
	Service(service string) ServiceGate
	// §11.6's format 2 gate, with its purge and drop modes.
	Format2() Format2Gate
	// Whether the named switch is on. Any other name is off.
	Switch(name string) bool
	// §19.9: the metadata cluster that takes new repos. Empty means the first cluster.
	PlaceNew() string
	// §19.10: whether evs and gkm run in re-seed mode, which only site loss turns on.
	Reseed() bool
	// W1: the lb interfaces the dns edges leave out of their answers.
	Drained() []string
	// §9.10 (D-SOCK-15): the control-message rate and burst per process and calling client. ok is
	// false when the file sets none, and the engine keeps its settings' own.
	SocketsControlQps() (rate float64, burst int, ok bool)
	// §6.10.1, §9.6: the urnetwork-edge platform network. ok is false when the file names none.
	UrnetworkEdge() (networkId connect.Id, ok bool)
	// plan-EVSB-settle-gate's entry for one file cluster. An absent entry has passed nothing.
	FileCluster(clusterId string) FileClusterGate
	// How long a caller a closed gate refused waits before asking again: the interval at which the
	// host rereads the gates. A host answers 503 with this as Retry-After.
	RetryAfter() time.Duration
}

// One service's gate as one read of the file left it. The zero value is closed. A value, safe for
// concurrent use once made.
type ServiceGate struct {
	enabled    bool
	writes     bool
	networkIds map[connect.Id]bool
	percent    int
}

// A gate as the file sets it: enabled, writes (which a present gate defaults to true), the listed
// networks, and the percent admitted by bucket. A percent outside 0 to 100 reads 0, so a typo opens
// nothing.
func NewServiceGate(enabled bool, writes bool, networkIds []connect.Id, percent int) ServiceGate {
	if percent < 0 || 100 < percent {
		percent = 0
	}
	gate := ServiceGate{
		enabled:    enabled,
		writes:     writes,
		networkIds: make(map[connect.Id]bool, len(networkIds)),
		percent:    percent,
	}
	for _, networkId := range networkIds {
		gate.networkIds[networkId] = true
	}
	return gate
}

// The gate's `enabled`. Off, it admits no network, listed or not.
func (self ServiceGate) Enabled() bool {
	return self.enabled
}

// Whether the service takes writes: enabled, with `writes`, the incident switch, left on.
func (self ServiceGate) Writes() bool {
	return self.enabled && self.writes
}

// Whether the network may use the service: enabled, and listed or under the percent by bucket.
func (self ServiceGate) Admits(networkId connect.Id) bool {
	if !self.enabled {
		return false
	}
	return self.networkIds[networkId] || ServiceGateBucket(networkId) < self.percent
}

// The share of networks the gate admits by bucket, 0 to 100.
func (self ServiceGate) Percent() int {
	return self.percent
}

// format2's purge and drop modes. Anything but exactly `on` reads observe, so every failure keeps
// content.
type Format2Mode string

const (
	// Logs each candidate, or runs a drop job through verify, and deletes nothing.
	Format2Observe Format2Mode = "observe"
	// Deletes, after the mode's soak (D-TEST-12, D-TEST-18).
	Format2On Format2Mode = "on"
)

// A mode as the file spells it: `on` exactly, or observe.
func ParseFormat2Mode(mode string) Format2Mode {
	if mode == string(Format2On) {
		return Format2On
	}
	return Format2Observe
}

// §11.6's format 2 gate: networks whose pushes may carry format 2, and v1's purge and drop modes.
// The zero value admits nothing and deletes nothing.
type Format2Gate struct {
	gate  ServiceGate
	purge Format2Mode
	drop  Format2Mode
}

// The gate as the file sets it, its modes read by ParseFormat2Mode.
func NewFormat2Gate(gate ServiceGate, purge string, drop string) Format2Gate {
	return Format2Gate{gate: gate, purge: ParseFormat2Mode(purge), drop: ParseFormat2Mode(drop)}
}

// Whether the network's pushes may carry format 2.
func (self Format2Gate) Admits(networkId connect.Id) bool {
	return self.gate.Admits(networkId)
}

// The gate's networks and percent, as every other gate's.
func (self Format2Gate) Gate() ServiceGate {
	return self.gate
}

// Whether purge deletes or only logs its candidates. The zero value observes.
func (self Format2Gate) Purge() Format2Mode {
	if self.purge == Format2On {
		return Format2On
	}
	return Format2Observe
}

// Whether drop jobs delete or only verify. The zero value observes.
func (self Format2Gate) Drop() Format2Mode {
	if self.drop == Format2On {
		return Format2On
	}
	return Format2Observe
}

// plan-EVSB-settle-gate's entry for one cluster. A cluster's settle check passes only while every
// host's MinIO build equals SettlePassedBuild (EVSB-M2-18 compares it with admin info), so the zero
// value has passed nothing.
type FileClusterGate struct {
	// The build that passed filecluster-suite and FS-114 on this cluster. Empty: none has.
	SettlePassedBuild string
	// What §22.8's M3 hdd run measured, in drive operations a second. Zero: unmeasured, and evs
	// refuses no upload on HDD grounds while a drop job stays paused.
	HddCapacityOps int64
}

// §19.11's reread interval, which a host with no gates of its own asks a refused caller to wait.
const ClosedServiceGatesRetryAfter = 60 * time.Second

// Every gate closed: what an absent file, or a host that set no gates, answers. Nothing is on, no
// network is admitted, and every cluster has passed nothing.
type ClosedServiceGates struct{}

// Closed, for every service.
func (self ClosedServiceGates) Service(service string) ServiceGate {
	return ServiceGate{}
}

// Admits nothing and deletes nothing.
func (self ClosedServiceGates) Format2() Format2Gate {
	return Format2Gate{}
}

// Off, for every switch.
func (self ClosedServiceGates) Switch(name string) bool {
	return false
}

// The first cluster.
func (self ClosedServiceGates) PlaceNew() string {
	return ""
}

// Off.
func (self ClosedServiceGates) Reseed() bool {
	return false
}

// None.
func (self ClosedServiceGates) Drained() []string {
	return nil
}

// Unset, so the engine keeps its own.
func (self ClosedServiceGates) SocketsControlQps() (float64, int, bool) {
	return 0, 0, false
}

// Unset.
func (self ClosedServiceGates) UrnetworkEdge() (connect.Id, bool) {
	return connect.Id{}, false
}

// Nothing passed.
func (self ClosedServiceGates) FileCluster(clusterId string) FileClusterGate {
	return FileClusterGate{}
}

// §19.11's reread interval.
func (self ClosedServiceGates) RetryAfter() time.Duration {
	return ClosedServiceGatesRetryAfter
}

// A network's bucket, 0 to 99: the first 8 bytes of SHA-256 over the id's 16 bytes, big-endian, mod
// 100 (plan-OPS-small-readings #2). Every percent gate reads this one bucket, and server's
// SidecarGateBucket computes the same; testdata/gates/table.yml pins both, so a network's place in a
// rollout never moves between releases.
func ServiceGateBucket(networkId connect.Id) int {
	sum := sha256.Sum256(networkId[:])
	return int(binary.BigEndian.Uint64(sum[:8]) % 100)
}
