// §7.9's leaves and commit rows on the test network: §22.7's seats (the 1,001st member device reads by wrap, a revoked
// entitled device promotes the first wrapped one, nothing else shrinks), a parked device's lift ranking it last, the
// rank against a reference that applies the move rule entry by entry, and the commit rule's answers.

package sidecar

import (
	"crypto/ed25519"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §22.7's seats: with 1,000 live member devices, the 1,001st reads by wrap; revoking an entitled one promotes the first
// wrapped one at that position, and every other entitled device stays entitled.
func TestTheThousandAndFirstDeviceReadsByWrap(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("seated member")
	rows := net.log.State().Rows()
	rows.Members = append(rows.Members, &bridge.MemberRow{MemberId: member.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER})
	seated := []Id{net.owner.sidecarId}
	for i := range configLeafEntitledCount - 1 {
		device := testConfigId(fmt.Sprintf("seated device %d", i))
		rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{
			SidecarId: device.Bytes(), AdmissionSigners: [][]byte{net.owner.sidecarId.Bytes()}, AdmittedAt: 1, LiveSince: 1,
			IdentityPublicKey: testConfigDeviceKey("seated").Public().(ed25519.PublicKey), IdentityAlg: configIdentityAlgEd25519,
			MemberId: member.Bytes(),
		})
		seated = append(seated, device)
	}
	net.pushBase(net.owner, rows, net.n, 2, 0)
	state := net.log.State()
	for _, device := range seated {
		if !state.LeafEntitled(device) {
			t.Fatalf("%s is not entitled", device)
		}
	}
	extra := net.device("the 1,001st", member)
	net.admitDevice(net.owner, extra, 0)
	state = net.log.State()
	if state.LeafEntitled(extra.sidecarId) || !slices.Equal(state.WrappedMembers(), []Id{extra.sidecarId}) {
		t.Fatalf("the 1,001st: entitled %v, wrapped %v", state.LeafEntitled(extra.sidecarId), state.WrappedMembers())
	}
	if rank, live := state.LeafRank(extra.sidecarId); !live || rank != configLeafEntitledCount {
		t.Errorf("the 1,001st ranks %d", rank)
	}

	revoked := seated[5]
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: net.header(), SidecarId: revoked.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
	})
	state = net.log.State()
	if !state.LeafEntitled(extra.sidecarId) || len(state.WrappedMembers()) != 0 || state.LeafEntitled(revoked) {
		t.Errorf("the promotion: the 1,001st entitled %v, wrapped %v", state.LeafEntitled(extra.sidecarId), state.WrappedMembers())
	}
	for _, device := range seated {
		if device != revoked && !state.LeafEntitled(device) {
			t.Errorf("%s lost its entitlement", device)
		}
	}
}

// §7.9's leaves row: a device a cascade parks stops being live and ranks last once a confirmation restores it, which
// is its live_since; a revoked member's devices stop being live.
func TestALiftedDeviceRanksLast(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, tablet, watch := net.device("m phone", member), net.device("m tablet", member), net.device("m watch", member)
	net.admitDevice(laptop, phone, 0)
	sinceN := net.n + 1
	net.admitDevice(phone, tablet, 0)
	net.admitDevice(laptop, watch, 0)
	if rank, _ := net.log.State().LeafRank(tablet.sidecarId); rank != 3 {
		t.Fatalf("the tablet ranks %d", rank)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	if _, live := net.log.State().LeafRank(tablet.sidecarId); live {
		t.Fatal("a parked device is live")
	}
	lift := net.mustPost(laptop, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: tablet.sidecarId.Bytes()})
	state := net.log.State()
	rank, live := state.LeafRank(tablet.sidecarId)
	watchRank, _ := state.LeafRank(watch.sidecarId)
	if !live || state.SidecarRow(tablet.sidecarId).GetLiveSince() != lift.Pin.GetVersion() || rank <= watchRank {
		t.Errorf("the lifted tablet ranks %d after the watch's %d", rank, watchRank)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	if _, live := net.log.State().LeafRank(laptop.sidecarId); live {
		t.Error("a removed member's device is live")
	}
	net.everyReaderAgrees()
}

// Property: over generated admissions, removals, parks and lifts, the rank equals a reference that applies §7.9's move
// rule entry by entry: a device that becomes live joins the end, one that stops leaves, the rest keep their order.
func TestTheLeafRankFollowsTheMoveRule(t *testing.T) {
	for seed := uint64(1); seed <= 6; seed += 1 {
		net := newTestConfigNet(t)
		random := rand.New(rand.NewPCG(seed, 11))
		reference := []Id{net.owner.sidecarId}
		member, laptop := net.consentedMember(fmt.Sprintf("m %d", seed))
		reference = append(reference, laptop.sidecarId)
		devices := []testConfigDevice{laptop}
		for i := range 60 {
			state := net.log.State()
			standing := []testConfigDevice{}
			for _, device := range devices {
				if _, ok := state.standingSidecar(device.sidecarId, state.TimeMs()); ok {
					standing = append(standing, device)
				}
			}
			switch op := random.IntN(4); {
			case op <= 1 || len(devices) < 3:
				device := net.device(fmt.Sprintf("m %d device %d", seed, i), member)
				net.post(standing[random.IntN(len(standing))], bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(device, nil, false, 0, 0))
				devices = append(devices, device)
			case op == 2:
				target := devices[1+random.IntN(len(devices)-1)]
				net.post(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(target, 1+uint64(random.IntN(int(net.n)))))
			default:
				target := devices[1+random.IntN(len(devices)-1)]
				if state.Parked(target.sidecarId) {
					net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: target.sidecarId.Bytes()})
				}
			}
			// the reference: who stopped being live leaves, who became live joins the end in position order
			after := net.log.State()
			kept := []Id{}
			for _, sidecarId := range reference {
				if _, live := after.LeafRank(sidecarId); live {
					kept = append(kept, sidecarId)
				}
			}
			for _, sidecarId := range after.SidecarIds() {
				if _, live := after.LeafRank(sidecarId); live && !slices.Contains(kept, sidecarId) {
					kept = append(kept, sidecarId)
				}
			}
			reference = kept
			for rank, sidecarId := range reference {
				if got, _ := after.LeafRank(sidecarId); got != rank {
					t.Fatalf("seed %d, entry %d: %s ranks %d, the reference %d", seed, net.n, sidecarId, got, rank)
				}
			}
		}
	}
}

// §7.9's commit row: an admission's signer adds a leaf-entitled device from its leaf, and only one whose admission it
// signed; a revocation's signer removes from its leaf; a read_only device commits nothing for another, and an agent
// takes its first wrap.
func TestMayCommitFollowsTheCommitRow(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	if commits := net.log.State().MayCommit(laptop.sidecarId, phone.sidecarId); !commits.Add || commits.FirstWrap || commits.Remove {
		t.Errorf("the admission's signer: %+v", commits)
	}
	if commits := net.log.State().MayCommit(net.owner.sidecarId, phone.sidecarId); commits != (ConfigCommits{}) {
		t.Errorf("a device that did not sign the admission: %+v", commits)
	}
	readOnly := net.device("m read only", member)
	net.admitDevice(laptop, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	if commits := net.log.State().MayCommit(readOnly.sidecarId, phone.sidecarId); commits != (ConfigCommits{}) {
		t.Errorf("a read_only device: %+v", commits)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if commits := net.log.State().MayCommit(laptop.sidecarId, phone.sidecarId); !commits.Remove || !commits.Rotate || commits.Add {
		t.Errorf("the revocation's signer: %+v", commits)
	}
	tagId := testConfigId("tag")
	net.withTagOwner(tagId, member)
	agent := net.device("m agent", Id{})
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+testConfigHourMs, 0))
	if commits := net.log.State().MayCommit(laptop.sidecarId, agent.sidecarId); !commits.FirstWrap || commits.Add {
		t.Errorf("an agent's admission: %+v", commits)
	}
}
