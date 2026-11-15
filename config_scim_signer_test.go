// TEAM-M6-07's scim_signer: the verifier takes a MemberRevoke of a member outside the AdminSet signed by the standing
// sidecar ServiceSettings.scim_signer names, at every reader and api alike, and refuses it for an AdminSet member, from
// a sidecar it does not name, before the setting and once the indexer is suspended (D-TEAM-25); and ConfigScimSigner
// signs the queued removals it may and leaves the rest.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Names scimSigner in the head's ServiceSettings at configVersion, which a base folding the tip carries into rows.
func (self *testConfigNet) designateScimSigner(scimSigner Id, configVersion uint64) {
	self.t.Helper()
	self.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{ScimSigner: scimSigner.Bytes()}
	if verdict := self.fold(self.owner, self.n, configVersion); !verdict.Accepted() {
		self.t.Fatalf("the base naming the scim_signer: %v", verdict.Refusal)
	}
}

// D-TEAM-25 at the verifier: the indexer scim_signer names, a device of a member with no admin role, removes a member
// outside the AdminSet, and every reader and api reach the same state; before the setting it may not, and it may never
// remove an AdminSet member; a device the setting does not name may not; and a suspended indexer signs nothing that
// counts.
func TestTheScimSignerRemovesMembersOutsideTheAdminSet(t *testing.T) {
	net := newTestConfigNet(t)
	leaver, leaverDevice := net.consentedMember("scim leaver")
	second, _ := net.consentedMember("scim second")
	_, indexer := net.consentedMember("scim indexer member")
	_, other := net.consentedMember("scim other member")
	admin := net.admitAdmin("scim admin")
	revoke := func(memberId Id) *bridge.MemberRevoke {
		return &bridge.MemberRevoke{Header: net.header(), MemberId: memberId.Bytes()}
	}

	net.mustRefuse(indexer, bridge.SignedType_SIGNED_MEMBER_REVOKE, revoke(leaver), ErrConfigAuthority)
	net.designateScimSigner(indexer.sidecarId, 2)

	revoked := net.mustPost(indexer, bridge.SignedType_SIGNED_MEMBER_REVOKE, revoke(leaver))
	for _, log := range net.everyReaderAndApi() {
		state := log.State()
		if state.Member(leaver) != nil || state.SidecarRow(leaverDevice.sidecarId).GetRevokedAt() != revoked.Pin.GetVersion() {
			t.Errorf("a reader at %d still holds the removed member", state.Pin().GetVersion())
		}
	}
	net.mustRefuse(indexer, bridge.SignedType_SIGNED_MEMBER_REVOKE, revoke(admin.memberId), ErrConfigAuthority)
	net.mustRefuse(other, bridge.SignedType_SIGNED_MEMBER_REVOKE, revoke(second), ErrConfigAuthority)

	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: indexer.sidecarId.Bytes(), SuspendId: aclTestSuspendId("scim indexer")})
	net.mustRefuse(indexer, bridge.SignedType_SIGNED_MEMBER_REVOKE, revoke(second), ErrConfigAuthority)
}

// A queue a test scripts.
type testScimChangeSource struct {
	memberIds []Id
	err       error
}

func (self *testScimChangeSource) ScimMemberRevokes(ctx context.Context) ([]Id, error) {
	return slices.Clone(self.memberIds), self.err
}

// ConfigScimSigner on the indexer scim_signer names: of the queue, a member outside the AdminSet gets its MemberRevoke,
// an AdminSet member is left to admin devices, a member already gone is passed; on a sidecar the setting does not
// name, a pass signs nothing; and where the log covers the act with a presence countersignature, the pass stops.
func TestTheScimSignerSignsTheQueueItMay(t *testing.T) {
	net := newTestConfigNet(t)
	leaver, _ := net.consentedMember("queued leaver")
	admin := net.admitAdmin("queued admin")
	sidecar, authority, deltaApi, _ := newTestMemberRemoveSidecar(t, net)
	identity := sidecar.currentIdentity()
	gone := testConfigId("already gone")
	source := &testScimChangeSource{memberIds: []Id{gone, admin.memberId, leaver}}
	signer := NewConfigScimSigner(context.Background(), sidecar, source, &ConfigScimSignerSettings{PassMaxCount: 64})
	defer signer.Close()

	pass, err := signer.Pass(context.Background())
	if err != nil || pass.Designated || len(deltaApi.postsSoFar()) != 0 {
		t.Fatalf("a pass on a sidecar the setting does not name: %+v %v", pass, err)
	}

	net.designateScimSigner(identity.SidecarId, 2)
	authority.setState(net.log.State())
	pass, err = signer.Pass(context.Background())
	if err != nil || !pass.Designated {
		t.Fatalf("the pass: %+v %v", pass, err)
	}
	if !slices.Equal(pass.Signed, []Id{leaver}) || !slices.Equal(pass.AdminSet, []Id{admin.memberId}) || !slices.Equal(pass.Gone, []Id{gone}) {
		t.Errorf("signed %v, admin set %v, gone %v", pass.Signed, pass.AdminSet, pass.Gone)
	}
	posts := deltaApi.postsSoFar()
	signed := &bridge.Signed{}
	if len(posts) != 1 || proto.Unmarshal(posts[0], signed) != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_MEMBER_REVOKE {
		t.Fatalf("posted %d statements", len(posts))
	}

	// a live presence key the log covers the MemberRevoke by: the headless indexer stops rather than sign
	addTestPresenceKey(t, authority.testActAuthority)
	authority.edit(func() {
		authority.covered[bridge.SignedType_SIGNED_MEMBER_REVOKE] = true
	})
	pass, err = signer.Pass(context.Background())
	if err != nil || !pass.PresenceNeeded || len(pass.Signed) != 0 || len(deltaApi.postsSoFar()) != 1 {
		t.Errorf("a covered pass: %+v %v, %d posts", pass, err, len(deltaApi.postsSoFar()))
	}

	source.err = errors.New("the queue is unreachable")
	if _, err := signer.Pass(context.Background()); err == nil {
		t.Error("a queue that answers no list passed")
	}
}
