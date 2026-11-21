//go:build !ios_extension

// Whether this client's network is in §19.11's format2 gate (§11.6's format row, §19.11; EVS2-M10-14): the gate api
// lists among a network's open gates in core's answer, GET /sidecar/sync/core's gates (plan-CORE-core-hint-body #2,
// SidecarConfig.GatesFor), which the client takes as a candidate, never as authority (§5.6). It decides only what this
// client writes: outside the gate every version it writes is versioning 0 and carries no format-2 value, so a format-1
// network never meets VERSIONING from 5c, and evs holds every push to the gate itself.
//
// The answer comes from the core state the composition keeps (SetFormat2Source), which reads the gates of the newest
// core answer it holds; until one is set, or while it holds none, Format2Admitted answers false, which fails closed to
// format 1. A client whose EvsSettings.MaxFormat is 1 answers false whatever the gate says, so it writes, as it reads,
// as a format-1 client does (EVS2-M10-30).
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"slices"
)

// The gate's name in core's gates (§19.11).
const EvsFormat2GateName = "format2"

// Whether core's answer lists the format2 gate open for this client's network.
func EvsFormat2AdmittedBy(core *SidecarSyncCore) bool {
	return core != nil && slices.Contains(core.Gates, EvsFormat2GateName)
}

// Sets where Format2Admitted reads the gate: the composition's view of the newest core answer, true only while the
// network is in the format2 gate. nil removes it, which answers false.
func (self *EvsClient) SetFormat2Source(admitted func() bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if admitted == nil {
		self.format2Source = nil
		return
	}
	self.format2Source = func() (bool, bool) { return admitted(), true }
}

// The network's rollout gate. An unknown result cannot establish that a repo has no format-2 history.
// MaxFormat limits this binary's capabilities independently of the network's rollout.
func (self *EvsClient) Format2Gate() (admitted bool, known bool) {
	self.stateLock.Lock()
	source := self.format2Source
	self.stateLock.Unlock()
	if source == nil {
		return false, false
	}
	return source()
}

// Whether this client can write format 2 on its network. Format-1 and unknown-gate writers stay at format 1.
func (self *EvsClient) Format2Admitted() bool {
	if self.settings != nil && self.settings.MaxFormat < 2 {
		return false
	}
	admitted, known := self.Format2Gate()
	return known && admitted
}

// Installs the verifying reader and binds rollout to this enrolled host's current, signed membership. Reading a
// migrated repo remains possible after a rollout closes. The server independently enforces each format-2 write.
func (self *Sidecar) BindEvsFormat2(client *EvsClient) {
	client.EnableFormat2Reader()
	client.stateLock.Lock()
	client.format2Source = func() (bool, bool) {
		return self.evsFormat2Gate(client)
	}
	client.stateLock.Unlock()

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.followCoreGates = true
	if self.generation != nil {
		self.generation.startCoreSyncWithLock()
	}
}

// Membership comes from the standing config follower. Core describes only the rollout for its authenticated bearer.
func (self *Sidecar) evsFormat2Gate(client *EvsClient) (bool, bool) {
	generation := self.runningGeneration()
	if generation == nil || generation.ctx.Err() != nil || self.instance.stateError() != nil ||
		generation.networkId != client.NetworkId() || self.lifecycleState() != SidecarStateOnline {
		return false, false
	}
	identity := client.args.Identity()
	if identity == nil || identity.NetworkId != generation.networkId || identity.ClientId != generation.identity.ClientId ||
		identity.SidecarId != generation.identity.SidecarId || identity.Generation != generation.generation ||
		!bytes.Equal(identity.IdentityPublicKey, generation.identity.IdentityPublicKey) {
		return false, false
	}
	follower := self.ConfigFollower()
	if follower == nil {
		return false, false
	}
	config := follower.Client()
	if config == nil {
		return false, false
	}
	state := config.State()
	if state == nil || state.NetworkId() != identity.NetworkId || !bytes.Equal(state.IdentityKey(identity.SidecarId), identity.IdentityPublicKey) ||
		!self.admittedBy(config.Authority()) {
		return false, false
	}
	core := generation.currentCore()
	return EvsFormat2AdmittedBy(core), core != nil
}
