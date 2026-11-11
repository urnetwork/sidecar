//go:build !js && !ios && !android && !sdk_mobile_bind

// The idle rule and indexer retirement (§5.8, §7.9, D-CORE-9, D-TEAM-27, owner decision 150; CORE-M2-09). An
// auto-spawned daemon exits once idle, unless something keeps it up: a hosted Sidecar's component that serves, mail,
// sockets or bridge, which it asks through the optional SidecarActiveComponent, never a list of names, a socket forward
// or a live share the daemon holds itself, or a hosted device the network stands as an indexer (§7.9's IndexerSet). An indexer runs from its unit, which `ur indexer add`
// installs if absent, and a unit-run daemon never idles out at all.
//
// uninstall-daemon first retires the device's designations: IndexerSet{retire} for each, which the subject itself
// may sign (§7.9), confirmed by the person on /dev/tty, never through MCP (D-CORE-13). A retire that cannot land stops
// the uninstall and says why, since a designation left standing lists a dead indexer.

package sidecar

import (
	"context"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Whether something keeps this Sidecar's daemon up: a component that serves, or its device standing as an indexer.
func (self *Sidecar) Busy() bool {
	if leg, ok := self.leg.(interface{ componentsActive() bool }); ok && leg.componentsActive() {
		return true
	}
	designations, _ := self.IndexerDesignations()
	return 0 < len(designations)
}

// The designations naming this device that stand, from the verified state: none before enrollment or from an authority
// that answers none, and ErrSidecarActNoAuthority with no verified state installed, which a caller never reads as none.
func (self *Sidecar) IndexerDesignations() ([]SidecarIndexerDesignation, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return nil, nil
	}
	authority := self.authority()
	if authority == nil || authority.Pin() == nil {
		return nil, ErrSidecarActNoAuthority
	}
	indexers, ok := authority.(SidecarIndexerAuthority)
	if !ok {
		return nil, nil
	}
	return indexers.IndexerDesignations(identity.SidecarId), nil
}

// Retires every designation naming this device, one IndexerSet{retire} each in one act, as the person confirmed it
// (D-CORE-13). Answers how many it retired, zero when none stands. ErrSidecarActNoAuthority with no verified state,
// so a designation it cannot see is never taken as none; ErrSidecarNoIdentity before enrollment; the act's refusal or
// ErrSidecarActPending when they cannot land.
func (self *Sidecar) RetireIndexer(ctx context.Context) (int, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return 0, ErrSidecarNoIdentity
	}
	authority := self.authority()
	if authority == nil || authority.Pin() == nil {
		return 0, ErrSidecarActNoAuthority
	}
	designations, err := self.IndexerDesignations()
	if err != nil || len(designations) == 0 {
		return 0, err
	}
	act, err := self.newAct(SidecarActConfirmed)
	if err != nil {
		return 0, err
	}
	for _, designation := range designations {
		err := act.Add(bridge.SignedType_SIGNED_INDEXER_SET, &protocol.IndexerSet{
			SidecarId: identity.SidecarId.Bytes(),
			Scope:     designation.Scope,
			Retire:    true,
		})
		if err != nil {
			return 0, err
		}
	}
	if _, err := act.Run(ctx, nil); err != nil {
		return 0, err
	}
	return len(designations), nil
}

// Whether the daemon exits now (§5.8): it was spawned by a ur, not run from its unit; IdleExitTimeout is set; no
// session is open and none has made a request for that long; and nothing keeps it busy.
func (self *Daemon) ShouldIdleExit() bool {
	wait, idle := self.idleWait()
	return idle && wait <= 0 && !self.busy()
}

// How long until the daemon has been idle for IdleExitTimeout, and whether it may idle out at all: false for a
// unit-run daemon, with no timeout, or with a session open.
func (self *Daemon) idleWait() (time.Duration, bool) {
	timeout := self.settings.Local.IdleExitTimeout
	if !self.settings.AutoSpawned || timeout <= 0 {
		return 0, false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.sessions) {
		return 0, false
	}
	return timeout - self.clock.Now().Sub(self.lastActivity), true
}

// Whether something keeps the daemon up: a hosted Sidecar's active component or indexer designation, a socket forward
// or a live share the daemon holds (daemon_socket.go), or the host's own rule.
func (self *Daemon) busy() bool {
	for _, network := range self.Sidecars() {
		if network.Sidecar.Busy() {
			return true
		}
	}
	if self.socketsActive() {
		return true
	}
	return self.settings.Busy != nil && self.settings.Busy()
}
