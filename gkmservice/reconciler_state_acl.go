// The real GkmReconcilerState (QD-718, question keys-m2-17-gkm-auth-state-owner): what the reconciler reads of the
// authorization log is §8.9's one per-process gate cache, sidecar.AclGateCache (C-09), through the three things ACL
// gave it for a follower:
//
//	Watch            the cache's install callback: a change is told once its network's new snapshot is installed,
//	                 never when {acl_<networkId>}v only said the log moved, so the pass a change wakes reads the new
//	                 state and not the one before. The change names the newest entry's signer where the gate's log
//	                 keeps that entry
//	Networks         the networks the cache holds a loaded state of
//	State            that network's snapshot as a GkmAuthView, its ConfigState, with every repo of its acl part and
//	                 the time of each entry the gate's log keeps
//	SidecarStanding  the cache's index from a sidecar to the one loaded network whose state holds its row, and that
//	                 row's revoked_at
//
// The cache loads what its host tells it of: a host calls AclGateCache.Watch on the process's Redis, so each
// {acl_<networkId>}v INCR loads that network and a resubscription loads every held one again. A lost subscription
// therefore needs no nil change: the networks whose state moved in the gap install, and are told like any other.
// Watch tells one nil change as it starts, so the networks loaded before the reconciler are read once.
//
// What the cache does not hold, the reconciler does not see: a network whose log has not moved since this process
// started, and one the cache's byte budget evicted, answer State with an error and SidecarStanding with not known,
// which keep every object and send no hint (question gkm-auth-state-reconciler-networks).
//
// Safe for concurrent use. Nothing here does I/O or holds a lock across a call out.

package gkmservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// §8.9's gate cache as the real GkmReconcilerState reads it: sidecar.AclGateCache's methods, or a test's stand-in.
type GkmReconcilerAclGate interface {
	// The network's verified state and what the cache says of it, with no I/O.
	State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus)
	// The networks the cache holds a loaded state of, sorted.
	Networks() []sidecar.Id
	// The one loaded network whose state holds the sidecar's row, false for none or several.
	SidecarNetwork(sidecarId sidecar.Id) (networkId sidecar.Id, found bool)
	// Runs callback after each new snapshot is installed; returns what stops it.
	AddInstallCallback(callback sidecar.AclGateInstallFunction) (remove func())
}

// The real GkmReconcilerState. See the file header.
type AclGkmReconcilerState struct {
	gate GkmReconcilerAclGate
}

// The state over gate. A nil gate watches nothing: Watch refuses, so no reconciler starts on it.
func NewAclGkmReconcilerState(gate GkmReconcilerAclGate) *AclGkmReconcilerState {
	return &AclGkmReconcilerState{gate: gate}
}

var _ GkmReconcilerState = (*AclGkmReconcilerState)(nil)

// A network the cache holds no loaded state of.
var errGkmNetworkNotLoaded = errors.New("gkm: the gate cache holds no loaded state of the network")

// See GkmReconcilerState and the file header.
func (self *AclGkmReconcilerState) Watch(changed func(change *GkmStateChange)) (stop func(), err error) {
	if self.gate == nil {
		return nil, errors.New("gkm's reconciler state has no gate cache")
	}
	stop = self.gate.AddInstallCallback(func(networkId sidecar.Id, snapshot *sidecar.AclGateSnapshot) {
		change := &GkmStateChange{NetworkId: networkId}
		if entry := snapshot.Entry(snapshot.Pin.GetVersion()); entry != nil {
			change.SignerId = entry.SignerSidecarId
		}
		changed(change)
	})
	// the networks loaded before this watch
	changed(nil)
	return stop, nil
}

// See GkmReconcilerState.
func (self *AclGkmReconcilerState) Networks() []sidecar.Id {
	if self.gate == nil {
		return []sidecar.Id{}
	}
	return self.gate.Networks()
}

// See GkmReconcilerState: an error for a network with no loaded state, which the reconciler reads again later.
func (self *AclGkmReconcilerState) State(ctx context.Context, networkId sidecar.Id) (*GkmNetworkState, error) {
	if self.gate == nil {
		return nil, errGkmNetworkNotLoaded
	}
	snapshot, status := self.gate.State(networkId)
	if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Config == nil || snapshot.Acl == nil {
		return nil, fmt.Errorf("%w: %s", errGkmNetworkNotLoaded, networkId)
	}
	return &GkmNetworkState{
		View:    snapshot.Config,
		RepoIds: snapshot.Acl.RepoIds(),
		PositionTime: func(n uint64) (time.Time, bool) {
			entry := snapshot.Entry(n)
			if entry == nil {
				return time.Time{}, false
			}
			return time.UnixMilli(entry.TimeMs), true
		},
	}, nil
}

// See GkmReconcilerState: not known for a sidecar no one loaded state holds a row of, and for one two do.
func (self *AclGkmReconcilerState) SidecarStanding(ctx context.Context, sidecarId sidecar.Id) (networkId sidecar.Id, revoked bool, known bool, err error) {
	if self.gate == nil {
		return sidecar.Id{}, false, false, nil
	}
	networkId, found := self.gate.SidecarNetwork(sidecarId)
	if !found {
		return sidecar.Id{}, false, false, nil
	}
	snapshot, status := self.gate.State(networkId)
	if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Config == nil {
		return sidecar.Id{}, false, false, nil
	}
	row := snapshot.Config.SidecarRow(sidecarId)
	if row == nil {
		return sidecar.Id{}, false, false, nil
	}
	return networkId, row.GetRevokedAt() != 0, true, nil
}
