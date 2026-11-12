// The real states' closed directions, on a stand-in gate that holds no loaded state: every answer of AclGkmAuthState
// is Unknown, which gkm answers 503, a network the cache has not heard of is told to it, and AclGkmReconcilerState
// gives no state and no standing. The answers of a loaded state run on T2 over the real cache and TEAM's log
// (sidecartest/gkm_auth_state_acl_test.go).

package gkmservice

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A gate that holds no loaded state: what it says of every network, and what it was told.
type coldGkmAclGate struct {
	status sidecar.AclGateStatus

	stateLock  sync.Mutex
	changedIds []sidecar.Id
}

func (self *coldGkmAclGate) State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus) {
	return nil, self.status
}

func (self *coldGkmAclGate) Changed(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changedIds = append(self.changedIds, networkId)
}

func (self *coldGkmAclGate) HonorScope(networkId sidecar.Id, subjectId sidecar.Id, repoId sidecar.Id, scope sidecar.AclEvsRights, audience sidecar.AclTokenAudience, now time.Time) sidecar.AclScopeAnswer {
	if self.status == sidecar.AclGateUnknown {
		self.Changed(networkId)
	}
	return sidecar.AclScopeUnknown
}

func (self *coldGkmAclGate) Networks() []sidecar.Id {
	return []sidecar.Id{}
}

func (self *coldGkmAclGate) SidecarNetwork(sidecarId sidecar.Id) (sidecar.Id, bool) {
	return sidecar.Id{}, false
}

func (self *coldGkmAclGate) AddInstallCallback(callback sidecar.AclGateInstallFunction) func() {
	return func() {}
}

func (self *coldGkmAclGate) changed() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]sidecar.Id{}, self.changedIds...)
}

// Every answer the state would allow or deny from, asked of it.
func coldGkmAclAnswers(state *AclGkmAuthState, principal *sidecar.Principal) map[string]GkmAuthAnswer {
	repoId, sidecarId, now := sidecar.NewId(), sidecar.NewId(), time.UnixMilli(1790000000000)
	pin := &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}
	answers := map[string]GkmAuthAnswer{}
	_, answers["Sidecar"] = state.Sidecar(principal, sidecarId)
	answers["HonorScope"] = state.HonorScope(principal, repoId, sidecar.AclEvsRead, now)
	answers["Reads"] = state.Reads(principal, repoId, sidecarId, now)
	_, answers["PendingTargets"] = state.PendingTargets(principal, sidecarId, now)
	_, answers["RepoReaders"] = state.RepoReaders(principal, repoId, now)
	_, answers["RepoWriters"] = state.RepoWriters(principal, repoId, now)
	answers["CheckPin"] = state.CheckPin(principal, pin)
	answers["DelegationReads"] = state.DelegationReads(principal, repoId, make([]byte, 32), now)
	_, answers["DelegationKey"] = state.DelegationKey(principal, make([]byte, 32))
	_, answers["LateHolders"] = state.LateHolders(principal, repoId, "s:00", now)
	answers["HoldersDropped"] = state.HoldersDropped(principal, repoId, pin, now, now)
	return answers
}

// Cold state is no pass: with no gate, a network the cache holds nothing of, or one it holds with nothing loaded,
// every answer is Unknown, and only the network the cache had not heard of is told to it.
func TestAclGkmAuthStateAnswersUnknownWithoutALoadedState(t *testing.T) {
	networkId, sidecarId := connect.NewId(), connect.NewId()
	principal := &sidecar.Principal{NetworkId: networkId, ClientId: connect.NewId(), SidecarId: &sidecarId}
	cases := []struct {
		name   string
		gate   *coldGkmAclGate
		asking bool
	}{
		{name: "no gate"},
		{name: "a network the cache holds nothing of", gate: &coldGkmAclGate{status: sidecar.AclGateUnknown}, asking: true},
		{name: "a network with nothing loaded", gate: &coldGkmAclGate{status: sidecar.AclGateNotLoaded}},
	}
	for _, c := range cases {
		var state *AclGkmAuthState
		if c.gate == nil {
			state = NewAclGkmAuthState(nil, nil, nil)
		} else {
			state = NewAclGkmAuthState(c.gate, nil, nil)
		}
		for name, answer := range coldGkmAclAnswers(state, principal) {
			if answer != GkmAuthUnknown {
				t.Errorf("%s: %s answered %d", c.name, name, answer)
			}
		}
		for name, answer := range coldGkmAclAnswers(state, nil) {
			if answer != GkmAuthUnknown {
				t.Errorf("%s: %s with no principal answered %d", c.name, name, answer)
			}
		}
		if c.gate == nil {
			continue
		}
		changed := c.gate.changed()
		if c.asking != (0 < len(changed)) {
			t.Errorf("%s: the cache was told %d times", c.name, len(changed))
		}
		for _, changedId := range changed {
			if changedId != sidecar.Id(networkId) {
				t.Errorf("%s: the cache was told of %s", c.name, changedId)
			}
		}
	}
	// no rev/ reader: gkm cannot tell, which is no revocation and no pass
	err := NewAclGkmAuthState(&coldGkmAclGate{}, nil, nil).CheckRevocation(t.Context(), principal)
	if err == nil || errors.Is(err, ErrGkmTokenRevoked) {
		t.Errorf("a state with no rev/ reader: %v", err)
	}
}

// With no loaded state the reconciler is given none: no network, an error for a state, and no sidecar's standing,
// which keeps every object; with no gate at all it takes no watch, so no reconciler starts on it.
func TestAclGkmReconcilerStateGivesNothingWithoutALoadedState(t *testing.T) {
	for _, status := range []sidecar.AclGateStatus{sidecar.AclGateUnknown, sidecar.AclGateNotLoaded} {
		gate := &coldGkmAclGate{status: status}
		state := NewAclGkmReconcilerState(gate)
		if networkIds := state.Networks(); len(networkIds) != 0 {
			t.Errorf("status %d: networks %v", status, networkIds)
		}
		if networkState, err := state.State(t.Context(), sidecar.NewId()); err == nil || networkState != nil {
			t.Errorf("status %d: a state %+v, %v", status, networkState, err)
		}
		if _, revoked, known, err := state.SidecarStanding(t.Context(), sidecar.NewId()); err != nil || known || revoked {
			t.Errorf("status %d: a standing %t, %t, %v", status, revoked, known, err)
		}
		// the reconciler never asks the cache to load: what it reads is what the host's watch loaded
		if changed := gate.changed(); len(changed) != 0 {
			t.Errorf("status %d: the cache was told of %v", status, changed)
		}
		changes := []*GkmStateChange{}
		stop, err := state.Watch(func(change *GkmStateChange) {
			changes = append(changes, change)
		})
		if err != nil {
			t.Fatal(err)
		}
		stop()
		if len(changes) != 1 || changes[0] != nil {
			t.Errorf("status %d: the watch's first changes %v", status, changes)
		}
	}
	none := NewAclGkmReconcilerState(nil)
	if _, err := none.Watch(func(change *GkmStateChange) {}); err == nil {
		t.Error("a state with no gate took a watch")
	}
	if networkIds := none.Networks(); len(networkIds) != 0 {
		t.Errorf("no gate: networks %v", networkIds)
	}
	if _, err := none.State(t.Context(), sidecar.NewId()); err == nil {
		t.Error("no gate: a state")
	}
	if _, _, known, err := none.SidecarStanding(t.Context(), sidecar.NewId()); err != nil || known {
		t.Errorf("no gate: a standing %t, %v", known, err)
	}
}
