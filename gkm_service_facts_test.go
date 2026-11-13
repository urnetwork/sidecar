//go:build !ios_extension

// What gkm's service reads of a state, over gkm_holders_test.go's hand-made network: a sidecar's standing follows its
// row, its covering Delegation only while that Delegation is live, and a late delivery's ask is widened to the
// sidecars that may sign one, the recipient's member's devices first.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Each fact of the standing is the row's: a member device and its member, an agent and the Delegation that admitted
// it while that Delegation lives, read_only, revoked and parked, and an admission a recovery binding signed.
func TestGkmSidecarStandingFollowsTheRow(t *testing.T) {
	net := newGkmTestNet()
	recoveryKey := net.fixture.view.members[net.owner].GetRecoveryKeySha256()
	recovered := net.fixture.device(net.owner, recoveryKey)
	readOnly := net.fixture.device(net.member)
	net.fixture.admission(readOnly).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	revoked := net.fixture.device(net.member)
	net.fixture.admission(revoked).Row.RevokedAt = net.fixture.next()
	parked := net.fixture.device(net.member)
	net.fixture.admission(parked).Row.ParkedAt = net.fixture.next()
	view := net.view(t, 1)

	if standing := GkmSidecarStandingAt(view, NewId(), aclTestNow); standing != nil {
		t.Fatalf("a sidecar the state never admitted: %+v", standing)
	}
	if standing := GkmSidecarStandingAt(nil, net.ownerDevice, aclTestNow); standing != nil {
		t.Fatalf("no state: %+v", standing)
	}
	device := GkmSidecarStandingAt(view, net.ownerDevice, aclTestNow)
	if device == nil || !device.MemberDevice || device.MemberId == nil || *device.MemberId != net.owner || device.ReadOnly || device.Revoked ||
		device.Parked || device.RecoveryAdmitted || device.CoveringDelegationId != nil {
		t.Errorf("a member device: %+v", device)
	}
	if standing := GkmSidecarStandingAt(view, recovered, aclTestNow); standing == nil || !standing.RecoveryAdmitted || !standing.MemberDevice {
		t.Errorf("a device its member's recovery binding admitted: %+v", standing)
	}
	if standing := GkmSidecarStandingAt(view, readOnly, aclTestNow); standing == nil || !standing.ReadOnly || !standing.MemberDevice {
		t.Errorf("a read_only device: %+v", standing)
	}
	if standing := GkmSidecarStandingAt(view, revoked, aclTestNow); standing == nil || !standing.Revoked || standing.Parked {
		t.Errorf("a revoked device: %+v", standing)
	}
	if standing := GkmSidecarStandingAt(view, parked, aclTestNow); standing == nil || !standing.Parked || standing.Revoked {
		t.Errorf("a parked device: %+v", standing)
	}

	agent := GkmSidecarStandingAt(view, net.coveredAgent, aclTestNow)
	if agent == nil || agent.MemberDevice || agent.MemberId != nil || !slices.Equal(agent.CoveringDelegationId, net.delegation.GetDelegationId()) {
		t.Errorf("an agent under a live Delegation: %+v", agent)
	}
	// the Delegation's not_after passes with no entry, and it covers no longer
	after := time.UnixMilli(net.delegation.GetNotAfter())
	if standing := GkmSidecarStandingAt(view, net.coveredAgent, after); standing == nil || standing.CoveringDelegationId != nil {
		t.Errorf("an agent once its Delegation expired: %+v", standing)
	}
	if standing := GkmSidecarStandingAt(view, net.uncoveredAgent, aclTestNow); standing == nil || standing.MemberDevice || standing.CoveringDelegationId != nil {
		t.Errorf("an agent no Delegation admitted: %+v", standing)
	}
	// a Delegation whose key dropped covers nothing
	net.delegation.KeyDroppedAt = net.fixture.next()
	if standing := GkmSidecarStandingAt(net.view(t, 2), net.coveredAgent, aclTestNow); standing == nil || standing.CoveringDelegationId != nil {
		t.Errorf("an agent whose Delegation dropped its key: %+v", standing)
	}
}

// §10.6's late wraps row: every sidecar that may sign a LATE delivery of the repo's key, the recipient left out and a
// read_only, revoked or parked one never among them, the recipient's member's devices first, an agent's sponsor's
// and a Delegation's signer's member alike, then member devices before agents, each by id.
func TestGkmLateHoldersPutTheRecipientsMembersDevicesFirst(t *testing.T) {
	net := newGkmTestNet()
	secondDevice := net.fixture.device(net.member)
	readOnly := net.fixture.device(net.member)
	net.fixture.admission(readOnly).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	revoked := net.fixture.device(net.member)
	net.fixture.admission(revoked).Row.RevokedAt = net.fixture.next()
	parked := net.fixture.device(net.owner)
	net.fixture.admission(parked).Row.ParkedAt = net.fixture.next()
	net.fixture.view.parked[parked] = true
	view := net.view(t, 1)

	sorted := func(sidecarIds ...Id) []Id {
		slices.SortFunc(sidecarIds, Id.Cmp)
		return sidecarIds
	}
	recipientOf := func(sidecarId Id) string {
		return "s:" + hex.EncodeToString(sidecarId.Bytes())
	}
	agents := sorted(net.coveredAgent, net.ephemeralAgent, net.uncoveredAgent)

	// a member device asks: its member's other device, then the owner's, then the agents
	holderIds, err := GkmLateHolders(view, net.repoId, recipientOf(net.memberDevice), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Concat([]Id{secondDevice, net.ownerDevice}, agents); !slices.Equal(holderIds, want) {
		t.Errorf("a member device's ask: %v, want %v", holderIds, want)
	}
	for _, excluded := range []Id{net.memberDevice, readOnly, revoked, parked} {
		if slices.Contains(holderIds, excluded) {
			t.Errorf("%s may sign no LATE delivery and was listed", excluded)
		}
	}

	// an agent asks: its sponsor's devices first, the owner's, then the member's two, then the other agents
	holderIds, err = GkmLateHolders(view, net.repoId, recipientOf(net.uncoveredAgent), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Concat([]Id{net.ownerDevice}, sorted(net.memberDevice, secondDevice), sorted(net.coveredAgent, net.ephemeralAgent)); !slices.Equal(holderIds, want) {
		t.Errorf("an agent's ask: %v, want %v", holderIds, want)
	}

	// a Delegation asks: its signer's member's devices first, and no sidecar is the recipient
	holderIds, err = GkmLateHolders(view, net.repoId, "d:"+hex.EncodeToString(net.delegation.GetDelegationId()), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Concat([]Id{net.ownerDevice}, sorted(net.memberDevice, secondDevice), agents); !slices.Equal(holderIds, want) {
		t.Errorf("a Delegation's ask: %v, want %v", holderIds, want)
	}

	// a Delegation the state holds no row of names no member: member devices, then agents, each by id
	unknownDelegation := sha256.Sum256([]byte("late holders unknown delegation"))
	holderIds, err = GkmLateHolders(view, net.repoId, "d:"+hex.EncodeToString(unknownDelegation[:]), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Concat(sorted(net.ownerDevice, net.memberDevice, secondDevice), agents); !slices.Equal(holderIds, want) {
		t.Errorf("an unknown Delegation's ask: %v, want %v", holderIds, want)
	}

	// a holder that has expired by the time asked is gone from the list
	later := time.UnixMilli(net.fixture.admission(net.ephemeralAgent).Row.GetNotAfter())
	holderIds, err = GkmLateHolders(view, net.repoId, recipientOf(net.memberDevice), later)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(holderIds, net.ephemeralAgent) {
		t.Error("an agent whose admission ended was listed")
	}

	if _, err := GkmLateHolders(view, NewId(), recipientOf(net.memberDevice), aclTestNow); !errors.Is(err, ErrGkmNoRepo) {
		t.Errorf("a repo the state does not hold: %v", err)
	}
	for _, recipient := range []string{"", "s:", "x:" + hex.EncodeToString(net.memberDevice.Bytes()), "s:zz", "d:" + hex.EncodeToString(net.memberDevice.Bytes())} {
		if _, err := GkmLateHolders(view, net.repoId, recipient, aclTestNow); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("recipient %q: %v", recipient, err)
		}
	}
}
