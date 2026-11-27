//go:build !sidecar_http && !ios_extension

// The stock network host's socket dependencies. Network labels are allocated by
// the authenticated API. Application names and local policy come from a single
// verified config head of the enrolled network.

package sidecar

import (
	"bytes"
	"context"
	"time"
)

// Watches the verified ACL installation, including changes at the same log position
// when the local policy finishes compiling. A missing follower can start after this component.
// No refresh runs once the component has ended, a change or the retry taken as it ended
// included, so no key path is withdrawn and no live stream rechecked past the end, and an
// ended component asks the clock for nothing.
func (self *SocketComponent) followSocketConfig() {
	defer close(self.configDone)
	ctx := self.registrar.ctx
	// select takes any of its ready cases at random: a change or the retry taken as the
	// component ended reads as the end
	for ctx.Err() == nil {
		state, local, grants := self.refreshSocketConfig()
		if ctx.Err() != nil {
			// a component that ended as the refresh ran asks the clock for nothing
			return
		}
		var retry <-chan time.Time
		if state == nil {
			retry = self.clock.After(self.settings.RetryInterval)
		}
		select {
		case <-ctx.Done():
		case <-retry:
		case <-state:
		case <-local:
		case <-grants:
		}
	}
}

// Selects the ACL installation only when its local config matches the standing
// client's verified base. A new base or a refusal withdraws old key paths and
// rechecks live streams. Subscribing before the reads preserves concurrent updates.
func (self *SocketComponent) refreshSocketConfig() (stateChanged, localChanged, grantsChanged <-chan struct{}) {
	self.configLock.Lock()
	defer self.configLock.Unlock()
	var engine *AclEngine
	var install *aclEngineInstall
	if follower := self.host.ConfigFollower(); follower != nil {
		state, changed := follower.state.Get()
		stateChanged = changed
		if client := follower.Client(); state == SidecarConfigFollowerStanding && client != nil && client.NetworkId() == self.networkId {
			acl := follower.AclFollower()
			engine = follower.AclEngine()
			if acl != nil && engine != nil {
				_, grantsChanged = acl.GrantsChanged()
				local, changed := acl.Local()
				localChanged = changed
				compiled := acl.local.Load()
				current := engine.installed.Load()
				verified := client.State()
				if compiled != nil && current != nil && local != nil && compiled.local == local && current.local == local &&
					verified != nil && bytes.Equal(verified.Base().GetConfigHeadSha256(), compiled.headSha256[:]) {
					install = current
				}
			}
		}
	}
	if install != self.configInstall {
		self.configInstall = install
		var ring *SocketKeyRing
		var policy SocketPolicy
		if install != nil {
			ring = install.local.socketKeyRing
			policy = NewSocketEnginePolicy(engine)
		}
		self.SetPolicy(policy)
		self.registrar.update(func(state *socketRegistrarState) bool {
			if state.ring == ring {
				return false
			}
			state.setRing(ring)
			return true
		})
		self.PolicyChanged()
	}
	return
}

// Obtains the immutable canonical label on first use. A qualified call that
// names an alias resolves it from this network's authenticated DNS zone, and one
// that names an alias in its 90 days of retiring from the retiring aliases the
// zone and the network's label table keep (dns_label_zone_row.go), until the
// alias's tombstone time on this component's clock (§12.5).
func (self *SocketComponent) prepareSocketNetwork(ctx context.Context, networkLabel string) error {
	if self.host == nil {
		return nil
	}
	self.refreshSocketConfig()
	generation, _, labels := self.current()
	if generation == nil {
		return &SocketCodeError{Err: ErrSocketUnavailable}
	}
	if labels != nil && (networkLabel == "" || networkLabel == labels.Label) {
		return nil
	}
	if networkLabel != "" {
		if zone, row, err := self.host.networkLabelZoneRow(ctx); zone != nil {
			if err != nil {
				return &SocketCodeError{Err: ErrSocketUnavailable}
			}
			// on this component's clock, so a resolver installed before an alias's tombstone time resolves it no
			// more from then on
			resolver := &NetworkLabelTable{rows: []NetworkLabelRow{row}, clock: self.clock}
			return self.installHostLabels(row.NetworkId, &SocketNetworkLabels{Label: row.Label, Root: row.Root, Resolver: resolver})
		}
	}
	answer, err := generation.sidecarApi.GetSidecarLabel(ctx)
	if err != nil {
		return &SocketCodeError{Err: ErrSocketUnavailable}
	}
	if networkLabel != "" && networkLabel != answer.Label {
		return &SocketCodeError{Err: ErrSocketUnavailable}
	}
	return self.installHostLabels(answer.NetworkId, &SocketNetworkLabels{Label: answer.Label})
}

// The canonical label is immutable. Concurrent unqualified calls must preserve the
// resolver obtained by a qualified call. Neither source may rename this network.
func (self *SocketComponent) installHostLabels(networkId Id, labels *SocketNetworkLabels) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if networkId != self.networkId || len(labels.Label) != socketNetworkLabelByteCount || !validSocketLabel(labels.Label) {
		return &SocketCodeError{Err: ErrSocketUnavailable}
	}
	if self.labels != nil {
		if self.labels.Label != labels.Label {
			return &SocketCodeError{Err: ErrSocketUnavailable}
		}
		if labels.Resolver == nil {
			return nil
		}
	}
	self.labels = labels
	return nil
}
