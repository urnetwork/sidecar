//go:build !sidecar_http && !ios_extension

// ServiceHost.Gates: §19.11's gates (D-OPS-10), as config/<env>/sidecar.yml sets them. The host
// rereads the file every 60 s, so an engine asks on each request and keeps no answer. Engines cannot
// import server, so the host supplies the gates through operator-core's interface, aliased here (owner
// decision 251; plan-OPS-small-readings #1), server over its reader of the file, and
// sidecartest.FakeServiceGates over a test's text of the same file. Both answer one table,
// testdata/gates/table.yml. ClosedServiceGates, the answer of a host that set none, stays here.
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
	"time"

	"github.com/urnetwork/connect"
	operator "github.com/urnetwork/operator-core"
)

// The services §19.11 gates by name, as the file spells them.
const (
	ServiceGateEvs      = operator.ServiceGateEvs
	ServiceGateGkm      = operator.ServiceGateGkm
	ServiceGateSockets  = operator.ServiceGateSockets
	ServiceGateTlsedge  = operator.ServiceGateTlsedge
	ServiceGateMxedge   = operator.ServiceGateMxedge
	ServiceGateSmtpedge = operator.ServiceGateSmtpedge
	ServiceGateDns      = operator.ServiceGateDns
	ServiceGateCompute  = operator.ServiceGateCompute
)

// §19.11's switches, each only `enabled`.
const (
	// §6's EnableSidecarPush.
	GateSwitchPush = operator.GateSwitchPush
	// §19.4's push sender.
	GateSwitchWake = operator.GateSwitchWake
	// §17's EnableBridge.
	GateSwitchBridge = operator.GateSwitchBridge
	// §20.9's draw order (D-QUOTA-9), on once M6's Gn-out registers MG6's index.
	GateSwitchEscrowDrawOrder = operator.GateSwitchEscrowDrawOrder
)

// The gates as the host last read them.
type ServiceGates = operator.ServiceGates

// One service's gate as one read of the file left it. The zero value is closed.
type ServiceGate = operator.ServiceGate

// A gate as the file sets it. A percent outside 0 to 100 reads 0, so a typo opens nothing.
func NewServiceGate(enabled bool, writes bool, networkIds []connect.Id, percent int) ServiceGate {
	return operator.NewServiceGate(enabled, writes, networkIds, percent)
}

// format2's purge and drop modes. Anything but exactly `on` reads observe.
type Format2Mode = operator.Format2Mode

const (
	// Logs each candidate, or runs a drop job through verify, and deletes nothing.
	Format2Observe = operator.Format2Observe
	// Deletes, after the mode's soak (D-TEST-12, D-TEST-18).
	Format2On = operator.Format2On
)

// A mode as the file spells it: `on` exactly, or observe.
func ParseFormat2Mode(mode string) Format2Mode {
	return operator.ParseFormat2Mode(mode)
}

// §11.6's format 2 gate. The zero value admits nothing and deletes nothing.
type Format2Gate = operator.Format2Gate

// The gate as the file sets it, its modes read by ParseFormat2Mode.
func NewFormat2Gate(gate ServiceGate, purge string, drop string) Format2Gate {
	return operator.NewFormat2Gate(gate, purge, drop)
}

// plan-EVSB-settle-gate's entry for one cluster. The zero value has passed nothing.
type FileClusterGate = operator.FileClusterGate

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
// 100 (plan-OPS-small-readings #2), operator-core's. Every percent gate reads this one bucket, and
// server's SidecarGateBucket computes the same; testdata/gates/table.yml pins both.
func ServiceGateBucket(networkId connect.Id) int {
	return operator.ServiceGateBucket(networkId)
}
