package sidecar

// CORE-M2-04: the authority approvals on a device. OwnerConfirm never from MCP, a hook or an unconfirmed call; a
// parked device stays parked on deny; a read_only device signs none; a veto carries its countersignature where the log
// covers it; the safety number beside an admission alarm; and the owner-consent rows of §22.7's admission suite: a
// consented device confirms an admin's admission, an unconsented one cannot.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An admission alarm under this device's member, an admin having admitted byAdmin, and the item it opened.
func openTestAdmissionAlarm(t *testing.T, world *alarmTestWorld) (Id, *SidecarApprovalItem) {
	t.Helper()
	byAdmin := NewId()
	world.admit(byAdmin, world.memberId)
	world.authority.stateLock.Lock()
	world.authority.sidecars[byAdmin].Row.IdentityPublicKey = bytes.Repeat([]byte{7}, 32)
	world.authority.stateLock.Unlock()
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, byAdmin, world.memberId, alarmTestSigner(NewId()))}
	})
	items, err := world.sidecar.PendingApprovals()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Kind == SidecarApprovalAdmissionAlarm && item.SidecarId != nil && *item.SidecarId == byAdmin {
			return byAdmin, item
		}
	}
	t.Fatalf("no admission alarm item in %+v", items)
	return Id{}, nil
}

// This device as its member's consented device.
func (self *alarmTestWorld) consentSelf() {
	self.authority.stateLock.Lock()
	defer self.authority.stateLock.Unlock()
	self.authority.consents[[2]Id{self.sidecar.currentIdentity().SidecarId, self.memberId}] = true
}

// The statements the delta route took, decoded.
func postedStatements(t *testing.T, sidecar *Sidecar) []*bridge.Signed {
	t.Helper()
	deltaApi := sidecar.sidecarApi.Transport().(*absoluteUrlTransport).transport.(*testDeltaApi)
	signeds := []*bridge.Signed{}
	for _, post := range deltaApi.postsSoFar() {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(post, signed); err != nil {
			t.Fatal(err)
		}
		signeds = append(signeds, signed)
	}
	return signeds
}

// D-CORE-13: an OwnerConfirm, or any approval, from MCP, a hook or an unconfirmed control call is refused, nothing
// signed, the item still open; the person's confirmation signs it.
func TestOwnerConfirmNeverFromMcp(t *testing.T) {
	world := newAlarmTestWorld(t)
	world.consentSelf()
	byAdmin, item := openTestAdmissionAlarm(t, world)
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionApprove, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if posted := postedStatements(t, world.sidecar); len(posted) != 0 {
		t.Fatalf("%d statements signed", len(posted))
	}
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionApprove, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	posted := postedStatements(t, world.sidecar)
	if len(posted) != 1 || bridge.SignedType(posted[0].GetType()) != bridge.SignedType_SIGNED_OWNER_CONFIRM {
		t.Fatalf("%+v", posted)
	}
	confirm := &protocol.OwnerConfirm{}
	proto.Unmarshal(posted[0].GetBody(), confirm)
	if !bytes.Equal(confirm.GetSidecarId(), byAdmin.Bytes()) {
		t.Error("the OwnerConfirm names another device")
	}
	if items, _ := world.sidecar.PendingApprovals(); len(items) != 0 {
		t.Errorf("still pending: %+v", items)
	}
}

// §2.10: deny dismisses an admission alarm and signs nothing, so the parked device stays parked; the item closes.
func TestParkedDeviceStaysParkedOnDeny(t *testing.T) {
	world := newAlarmTestWorld(t)
	world.consentSelf()
	_, item := openTestAdmissionAlarm(t, world)
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionDeny, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if posted := postedStatements(t, world.sidecar); len(posted) != 0 {
		t.Errorf("deny signed %d statements", len(posted))
	}
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionApprove, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalUnknown) {
		t.Errorf("a decided item decided again: %v", err)
	}
	// revoke is RevokeDevice's, and refuses until it lands, the item staying open
	_, other := openTestAdmissionAlarm(t, world)
	if err := world.sidecar.DecideApproval(t.Context(), other.ApprovalId, SidecarDecisionRevoke, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalUnbuilt) {
		t.Errorf("revoke: %v", err)
	}
}

// §7.9: a read_only device signs none of these, and neither does a device its member has not consented: deny is all
// it may answer.
func TestReadOnlyDeviceSignsNoApproval(t *testing.T) {
	world := newAlarmTestWorld(t)
	world.consentSelf()
	identity := world.sidecar.currentIdentity()
	world.authority.stateLock.Lock()
	world.authority.sidecars[identity.SidecarId].Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	world.authority.stateLock.Unlock()
	_, item := openTestAdmissionAlarm(t, world)
	if len(item.Decisions) != 1 || item.Decisions[0] != SidecarDecisionDeny {
		t.Errorf("a read_only device may answer %v", item.Decisions)
	}
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionApprove, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Errorf("a read_only approve: %v", err)
	}

	unconsented := newAlarmTestWorld(t)
	_, item = openTestAdmissionAlarm(t, unconsented)
	if err := unconsented.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionApprove, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Errorf("an unconsented device's OwnerConfirm: %v", err)
	}
	if posted := postedStatements(t, unconsented.sidecar); len(posted) != 0 {
		t.Errorf("%d statements signed", len(posted))
	}
}

// A recovery window's deny signs RecoveryVeto on an AdminSet member's device, countersigned where the log covers it,
// as §7.9's presence row asks; a device outside the AdminSet may only let the window run.
func TestVetoCountersignedWhenCovered(t *testing.T) {
	world := newAlarmTestWorld(t)
	key, keyId := addTestPresenceKey(t, world.authority)
	world.authority.stateLock.Lock()
	world.authority.covered[bridge.SignedType_SIGNED_RECOVERY_VETO] = true
	world.authority.stateLock.Unlock()
	proposalId := sha256.Sum256([]byte("a recovery proposal"))
	openWindow := func(admins []Id) *SidecarApprovalItem {
		world.apply(func(entry *SidecarAuthorityEntry) {
			entry.AdminMemberIds = admins
			entry.Windows = []SidecarRecoveryWindow{{ProposalId: proposalId[:], State: SidecarRecoveryWindowPending, Start: world.n + 1, MemberId: world.memberId, RecoverySigned: true}}
		})
		items, err := world.sidecar.PendingApprovals()
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if item.Kind == SidecarApprovalRecoveryWindow {
				return item
			}
		}
		t.Fatal("no recovery window item")
		return nil
	}
	item := openWindow([]Id{NewId()})
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionDeny, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Fatalf("a veto outside the AdminSet: %v", err)
	}

	world.apply(func(entry *SidecarAuthorityEntry) { entry.AdminMemberIds = []Id{world.memberId} })
	var seen []byte
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionDeny, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarActPresence) {
		t.Fatalf("a covered veto with no check: %v", err)
	}
	if err := world.sidecar.DecideApproval(t.Context(), item.ApprovalId, SidecarDecisionDeny, SidecarActConfirmed, testPresenceCheck(t, key, keyId, &seen)); err != nil {
		t.Fatal(err)
	}
	posted := postedStatements(t, world.sidecar)
	if len(posted) != 1 || bridge.SignedType(posted[0].GetType()) != bridge.SignedType_SIGNED_RECOVERY_VETO {
		t.Fatalf("%+v", posted)
	}
	publicKey := world.authority.LiveKeys(world.sidecar.currentIdentity().SidecarId)[0].GetPublicKey()
	if err := bridge.VerifyPresenceCountersign(posted[0], bridge.SignedPurposeAuthority, bridge.SignedKeyAlgEcdsaP256, publicKey); err != nil {
		t.Errorf("the veto's countersignature: %v", err)
	}
	veto := &protocol.RecoveryVeto{}
	proto.Unmarshal(posted[0].GetBody(), veto)
	if !bytes.Equal(veto.GetProposalId(), proposalId[:]) {
		t.Error("the veto names another proposal")
	}
}

// D-CORE-13: the admission alarm's item carries the safety number over the anchored genesis and the admitted device's
// identity key, which ur approve and the apps show before an OwnerConfirm.
func TestApproveShowsSafetyNumber(t *testing.T) {
	world := newAlarmTestWorld(t)
	world.consentSelf()
	_, item := openTestAdmissionAlarm(t, world)
	if item.SafetyNumber != "" {
		t.Fatal("a safety number with no anchor")
	}
	genesis := sha256.Sum256([]byte("the network's genesis"))
	if err := world.sidecar.TrustFirstUse(genesis[:]); err != nil {
		t.Fatal(err)
	}
	items, err := world.sidecar.PendingApprovals()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := SafetyNumber(genesis[:], bytes.Repeat([]byte{7}, 32))
	if len(items) == 0 || items[0].SafetyNumber != want || len(want) != 60 {
		t.Errorf("%+v, want %s", items, want)
	}
}

// §22.7's admission suite, owner consent: a new device of the member, opened as an admission, is admitted by the
// member's consented device alone with the SidecarAdmit it signs; a device that is not consented may only deny.
func TestConsentedDeviceAdmitsItsMembersDevice(t *testing.T) {
	world := newAlarmTestWorld(t)
	newDevice := NewId()
	approvalId, err := world.sidecar.OpenAdmission(&SidecarAdmissionRequest{SidecarId: newDevice, MemberId: world.memberId, IdentityPublicKey: bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.DecideApproval(t.Context(), approvalId, SidecarDecisionApprove, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Fatalf("an unconsented device admitted: %v", err)
	}
	world.consentSelf()
	if err := world.sidecar.DecideApproval(t.Context(), approvalId, SidecarDecisionApprove, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	posted := postedStatements(t, world.sidecar)
	if len(posted) != 1 || bridge.SignedType(posted[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_ADMIT {
		t.Fatalf("%+v", posted)
	}
	admit := &protocol.SidecarAdmit{}
	proto.Unmarshal(posted[0].GetBody(), admit)
	if !bytes.Equal(admit.GetSidecarId(), newDevice.Bytes()) || !bytes.Equal(admit.GetMemberId(), world.memberId.Bytes()) || admit.GetIdentityAlg() != "ed25519" {
		t.Errorf("%+v", admit)
	}
}
