//go:build !sidecar_http

// Seats and the leaves rule (KEYS-M2-21, §22.7's committers and seats rows): a data repo's free seat goes to the
// earliest-admitted waiting member device and the rest wait keyless and named; the config group's first 1,000 member
// devices by (live_since, sidecar_id) are leaf-entitled and the 1,001st reads by a ReaderWrap; a device that
// stops being live makes the first wrapped one entitled.

package sidecar_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Pending changes of the world's repo at view for a tree of the devices given.
func (self *gkmWorld) pendingFor(view sidecar.GkmAuthView, seatCount int, leaves ...*gkmWorldDevice) *sidecar.GkmPending {
	self.t.Helper()
	roster := []sidecar.MlsMember{}
	for index, device := range leaves {
		roster = append(roster, sidecar.MlsMember{LeafIndex: uint32(index), SidecarId: device.id, Credential: device.credential})
	}
	pending, err := sidecar.GkmPendingChanges(view, &sidecar.GkmPendingArgs{
		RepoId: self.repoId, Roster: roster, SeatCount: seatCount, ScheduleInterval: 30 * 24 * time.Hour, Now: self.now,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return pending
}

// §8.12: a data repo's free seat goes to the earliest-admitted waiting member device, by (admitted_at, sidecar_id);
// a reader past the seats waits keyless and is named; a Remove frees its seat in the same commit; and no committer
// seats past MLS's 1,000 whatever its setting says.
func TestADataReposSeatsFillEarliestAdmittedFirst(t *testing.T) {
	world := newGkmWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.admit("a")
	b := world.admit("b")
	late := world.admit("late")
	early := world.admit("early")
	middle := world.admit("middle")
	early.row.AdmittedAt, middle.row.AdmittedAt, late.row.AdmittedAt = 3, 4, 5
	agent := world.admit("agent", sidecar.NewId())
	world.grant(true, a, b)
	world.grant(false, late, early, middle, agent)
	first := world.state()

	pending := world.pendingFor(first, 3, a, b)
	if !slices.Equal(pending.Adds, []sidecar.Id{early.id}) || !slices.Equal(pending.Waiting, []sidecar.Id{middle.id, late.id}) || len(pending.Removes) != 0 {
		t.Errorf("one free seat: adds %v, waiting %v", pending.Adds, pending.Waiting)
	}
	if pending := world.pendingFor(first, 5, a, b); !slices.Equal(pending.Adds, []sidecar.Id{early.id, middle.id, late.id}) || len(pending.Waiting) != 0 {
		t.Errorf("seats for all: adds %v, waiting %v", pending.Adds, pending.Waiting)
	}
	if pending := world.pendingFor(first, 2, a, b); len(pending.Adds) != 0 || len(pending.Waiting) != 3 {
		t.Errorf("a full tree: adds %v, waiting %v", pending.Adds, pending.Waiting)
	}
	// a seated device keeps its leaf whoever waits, and an agent never takes a seat
	if pending := world.pendingFor(first, 3, a, b, late); len(pending.Adds) != 0 || len(pending.Removes) != 0 || !slices.Equal(pending.Waiting, []sidecar.Id{early.id, middle.id}) {
		t.Errorf("a seated late device: adds %v, removes %v, waiting %v", pending.Adds, pending.Removes, pending.Waiting)
	}
	// b is revoked: its Remove frees its seat for the same commit
	world.revoke(b)
	second := world.state()
	pending = world.pendingFor(second, 3, a, b, late)
	if len(pending.Removes) != 1 || pending.Removes[0].SidecarId != b.id || !slices.Equal(pending.Adds, []sidecar.Id{early.id}) || !slices.Equal(pending.Waiting, []sidecar.Id{middle.id}) {
		t.Errorf("a Remove's seat: removes %v, adds %v, waiting %v", pending.Removes, pending.Adds, pending.Waiting)
	}
	// who may commit it: the writer leaf all of it, a reader leaf none, the leaf due its Remove none
	removes, adds := sidecar.GkmMayCommit(second, world.repoId, a.id, []sidecar.MlsMember{{SidecarId: a.id}, {SidecarId: b.id}, {SidecarId: late.id}}, pending)
	if len(removes) != 1 || len(adds) != 1 {
		t.Errorf("the writer leaf may commit %d removes and %d adds", len(removes), len(adds))
	}
	for _, device := range []*gkmWorldDevice{late, b, early, agent} {
		removes, adds := sidecar.GkmMayCommit(second, world.repoId, device.id, []sidecar.MlsMember{{SidecarId: a.id}, {SidecarId: b.id}, {SidecarId: late.id}}, pending)
		if len(removes) != 0 || len(adds) != 0 {
			t.Errorf("%s may commit %d removes and %d adds", device.label, len(removes), len(adds))
		}
	}
	// the setting never passes a tree's 1,000 leaves
	if pending := world.pendingFor(second, sidecar.GkmSeatCount+500, a, late); len(pending.Adds) != 2 {
		t.Errorf("seats past the bound: adds %v", pending.Adds)
	}
}

// §7.9's leaves rule over a repo's readers (owner decisions 144, 182): the first 1,000 live member devices by
// (live_since, sidecar_id) are leaf-entitled, the 1,001st reads by wraps, and when an entitled device is revoked the
// first wrapped one becomes entitled; agents hold no rank.
func TestTheConfigGroupsLeavesRule(t *testing.T) {
	world := newGkmWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	devices := []*gkmWorldDevice{}
	for len(devices) < sidecar.GkmSeatCount+2 {
		device := world.admit("device")
		devices = append(devices, device)
	}
	agent := world.admit("agent", sidecar.NewId())
	world.grant(false, devices...)
	world.grant(false, agent)
	first := world.state()
	rank := sidecar.GkmLeafRank(first, world.repoId, world.now)
	if len(rank) != len(devices) || rank[0] != devices[0].id || rank[len(rank)-1] != devices[len(devices)-1].id {
		t.Fatalf("a rank of %d devices", len(rank))
	}
	wrapped := sidecar.GkmWrappedMembers(first, world.repoId, world.now)
	if !slices.Equal(wrapped, []sidecar.Id{devices[sidecar.GkmSeatCount].id, devices[sidecar.GkmSeatCount+1].id}) {
		t.Errorf("%d wrapped members", len(wrapped))
	}
	if !sidecar.GkmLeafEntitled(first, world.repoId, devices[sidecar.GkmSeatCount-1].id, world.now) ||
		sidecar.GkmLeafEntitled(first, world.repoId, devices[sidecar.GkmSeatCount].id, world.now) ||
		sidecar.GkmLeafEntitled(first, world.repoId, agent.id, world.now) {
		t.Errorf("entitlement at the 1,000th, the 1,001st or an agent")
	}
	// pending for a tree of the first two: every entitled device is due an Add, and the wrapped two are not
	pending := world.pendingFor(first, sidecar.GkmSeatCount, devices[0], devices[1])
	if len(pending.Adds) != sidecar.GkmSeatCount-2 || slices.Contains(pending.Adds, devices[sidecar.GkmSeatCount].id) {
		t.Errorf("%d Adds pending in the config group", len(pending.Adds))
	}
	// the move: an entitled device is revoked, and the first wrapped one becomes entitled at that state
	world.revoke(devices[5])
	second := world.state()
	if !sidecar.GkmLeafEntitled(second, world.repoId, devices[sidecar.GkmSeatCount].id, world.now) ||
		sidecar.GkmLeafEntitled(second, world.repoId, devices[sidecar.GkmSeatCount+1].id, world.now) ||
		sidecar.GkmLeafEntitled(second, world.repoId, devices[5].id, world.now) {
		t.Errorf("the move after a revocation")
	}
	// a leaf that lost entitlement while it still reads is due a Remove: it reads on by wraps
	pending = world.pendingFor(second, sidecar.GkmSeatCount, devices[0], devices[sidecar.GkmSeatCount+1])
	if len(pending.Removes) != 1 || pending.Removes[0].SidecarId != devices[sidecar.GkmSeatCount+1].id {
		t.Errorf("a leaf with no entitlement: removes %v", pending.Removes)
	}
}

// The 1,001st device reads the config by a ReaderWrap, and a wrapped signer's rotation reaches it: a rotation in the
// config group wraps to each member device among the holders that the tree lacks.
func TestAConfigRotationWrapsToMemberDevicesOutsideTheTree(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	world.holdAll()
	outside := world.admit("outside")
	world.grant(false, outside)
	second := world.stateFor()
	world.flow(outside)
	if _, err := world.flows[world.a].client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	gen2 := world.storedGeneration(second, 2)
	recipients := world.deliveryRecipients(2)
	if gen2.Rotate.GetLeafWrap() == nil || len(recipients) != 1 || recipients["s:outside"] != sidecar.GkmDeliveryStaged {
		t.Errorf("the config rotation: leaf_wrap %v, deliveries %v", gen2.Rotate.GetLeafWrap(), recipients)
	}
	// in a data repo the same device waits keyless for its seat
	data := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	data.holdAll()
	waiting := data.admit("waiting")
	data.grant(false, waiting)
	data.stateFor()
	data.flow(waiting)
	if _, err := data.flows[data.a].client.RotateRepo(data.ctx, data.repoId); err != nil {
		t.Fatal(err)
	}
	if recipients := data.deliveryRecipients(2); len(recipients) != 0 {
		t.Errorf("a data repo's rotation wrapped to a device with no seat: %v", recipients)
	}
}
