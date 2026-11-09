// §8.5's consent predicate on fixed vectors, one file per clause and §22.7's cascade case, embedded so every
// leg reads the same bytes and must give the same answers; with the approval capability and the tag right.
// Pure, on every leg.

package sidecar

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/acl/consent
var testAclConsentFiles embed.FS

// A member's first device, consented by the invite an admin's device issued (§8.5's invited clause).
func (self *aclTestFixture) invitedDevice(memberId Id) Id {
	sidecarId := self.device(memberId, NewId().Bytes())
	self.admission(sidecarId).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
	return sidecarId
}

// One consent vector, names standing for ids.
type aclConsentVector struct {
	Name    string `json:"name"`
	Members []struct {
		Id       string `json:"id"`
		Role     string `json:"role"`
		Bindings []struct {
			Key string `json:"key"`
			At  uint64 `json:"at"`
		} `json:"bindings"`
	} `json:"members"`
	Genesis *struct {
		Sidecar string `json:"sidecar"`
		Member  string `json:"member"`
	} `json:"genesis"`
	Sidecars []struct {
		Id           string   `json:"id"`
		Member       string   `json:"member"`
		AdmittedAt   uint64   `json:"admitted_at"`
		Signers      []string `json:"signers"`
		ReadOnly     bool     `json:"read_only"`
		Invited      bool     `json:"invited"`
		Ephemeral    bool     `json:"ephemeral"`
		RevokedAt    uint64   `json:"revoked_at"`
		OwnerConfirm *struct {
			Signer string `json:"signer"`
			At     uint64 `json:"at"`
		} `json:"owner_confirm"`
		Confirm *struct {
			Signer string `json:"signer"`
			At     uint64 `json:"at"`
		} `json:"confirm"`
	} `json:"sidecars"`
	Parked []string `json:"parked"`
	Voids  []struct {
		Signer string `json:"signer"`
		From   uint64 `json:"from"`
	} `json:"voids"`
	Consented          []string `json:"consented"`
	NotConsented       []string `json:"not_consented"`
	ApprovalCapable    []string `json:"approval_capable"`
	NotApprovalCapable []string `json:"not_approval_capable"`
}

// A vector name's id.
func aclConsentVectorId(name string) Id {
	digest := sha256.Sum256([]byte("acl-consent-vector/" + name))
	return Id(digest[:16])
}

// A vector signer's bytes: a recovery key's hash for key:<name>, else a sidecar_id.
func aclConsentVectorSigner(name string) []byte {
	if key, isKey := strings.CutPrefix(name, "key:"); isKey {
		digest := sha256.Sum256([]byte("acl-consent-vector/key/" + key))
		return digest[:]
	}
	return aclConsentVectorId(name).Bytes()
}

// The view a vector describes.
func aclConsentVectorView(t *testing.T, vector *aclConsentVector) *aclTestView {
	roles := map[string]bridge.MemberRole{
		"owner": bridge.MemberRole_MEMBER_ROLE_OWNER, "admin": bridge.MemberRole_MEMBER_ROLE_ADMIN,
		"auditor": bridge.MemberRole_MEMBER_ROLE_AUDITOR, "member": bridge.MemberRole_MEMBER_ROLE_MEMBER,
	}
	fixture := newAclTestFixture()
	view := fixture.view
	for _, member := range vector.Members {
		role, known := roles[member.Role]
		if !known {
			t.Fatalf("%s: role %q", vector.Name, member.Role)
		}
		row := &bridge.MemberRow{MemberId: aclConsentVectorId(member.Id).Bytes(), Role: role}
		for _, binding := range member.Bindings {
			row.Bindings = append(row.Bindings, &bridge.RecoveryBindingRow{KeySha256: aclConsentVectorSigner("key:" + binding.Key), At: binding.At})
		}
		view.members[aclConsentVectorId(member.Id)] = row
	}
	if vector.Genesis != nil {
		view.genesis = &bridge.Genesis{
			OwnerSidecarId: aclConsentVectorId(vector.Genesis.Sidecar).Bytes(),
			OwnerMemberId:  aclConsentVectorId(vector.Genesis.Member).Bytes(),
		}
	}
	for _, sidecar := range vector.Sidecars {
		sidecarId := aclConsentVectorId(sidecar.Id)
		row := &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: sidecar.AdmittedAt, RevokedAt: sidecar.RevokedAt}
		for _, signer := range sidecar.Signers {
			row.AdmissionSigners = append(row.AdmissionSigners, aclConsentVectorSigner(signer))
		}
		if sidecar.ReadOnly {
			row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
		}
		if sidecar.Invited {
			row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
		}
		if sidecar.OwnerConfirm != nil {
			row.OwnerConfirmSigner = aclConsentVectorSigner(sidecar.OwnerConfirm.Signer)
			row.OwnerConfirmedAt = sidecar.OwnerConfirm.At
		}
		if sidecar.Confirm != nil {
			row.ConfirmSigner = aclConsentVectorSigner(sidecar.Confirm.Signer)
			row.ConfirmedAt = sidecar.Confirm.At
		}
		view.sidecars[sidecarId] = &AclSidecar{Row: row, MemberId: aclConsentVectorId(sidecar.Member), Ephemeral: sidecar.Ephemeral}
	}
	for _, parked := range vector.Parked {
		view.parked[aclConsentVectorId(parked)] = true
	}
	for _, void := range vector.Voids {
		view.voidFrom[string(aclConsentVectorSigner(void.Signer))] = void.From
	}
	return view
}

// Every vector's answers, the same on every leg: each named device consented or not, approval-capable or
// not, as the file says.
func TestAclConsentVectors(t *testing.T) {
	paths, err := fs.Glob(testAclConsentFiles, "testdata/acl/consent/*.json")
	if err != nil || len(paths) < 8 {
		t.Fatalf("vectors %v, %v", paths, err)
	}
	for _, path := range paths {
		data, err := testAclConsentFiles.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		vector := &aclConsentVector{}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(vector); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		state, err := NewAclState(&protocol.AclRows{}, aclConsentVectorView(t, vector))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		check := func(names []string, predicate func(Id) bool, want bool, what string) {
			for _, name := range names {
				if predicate(aclConsentVectorId(name)) != want {
					t.Errorf("%s: %s %s = %t, want %t", path, name, what, !want, want)
				}
			}
		}
		check(vector.Consented, state.Consented, true, "consented")
		check(vector.NotConsented, state.Consented, false, "consented")
		check(vector.ApprovalCapable, state.ApprovalCapable, true, "approval-capable")
		check(vector.NotApprovalCapable, state.ApprovalCapable, false, "approval-capable")
		if len(vector.Consented)+len(vector.NotConsented) != len(vector.Sidecars) {
			t.Errorf("%s: every sidecar must be named consented or not", path)
		}
	}
}

// The consent of a device for its own member, and for no other member.
func TestAclConsentedForNamesOneMember(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := fixture.invitedDevice(owner)
	state := fixture.state(t)
	if !state.ConsentedFor(laptop, owner) || state.ConsentedFor(laptop, other) || state.Consented(NewId()) {
		t.Error("ConsentedFor misread")
	}
}

// A tagged device is never consented, whatever signed it, and a suspended one is no approver.
func TestAclTaggedAndSuspendedDevices(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	laptop := fixture.invitedDevice(owner)
	agent := fixture.agent(owner, tagId)
	fixture.admission(agent).Row.AdmissionSigners = [][]byte{laptop.Bytes()}
	phone := fixture.device(owner, laptop.Bytes())
	fixture.rows.Suspensions = []*protocol.AclSuspension{{Subject: phone.Bytes()}}
	state := fixture.state(t)
	if state.Consented(agent) || state.ApprovalCapable(agent) {
		t.Error("a tagged device consented")
	}
	if !state.Consented(phone) || state.ApprovalCapable(phone) {
		t.Errorf("suspended phone: consented %t, approval-capable %t", state.Consented(phone), state.ApprovalCapable(phone))
	}
}

// CanApplyTag answers tagOwners from rows: a standing member device of an owner, not read_only, and
// nothing for a tag no row holds (plan-ACL-atom-and-rule-ids #4).
func TestAclCanApplyTag(t *testing.T) {
	fixture := newAclTestFixture()
	tagOwner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	tagId := fixture.tag(tagOwner)
	ownerDevice := fixture.device(tagOwner)
	ownerWorker := fixture.device(tagOwner)
	fixture.admission(ownerWorker).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	ownerBurner := fixture.device(tagOwner)
	fixture.admission(ownerBurner).Ephemeral = true
	ownerRevoked := fixture.device(tagOwner)
	fixture.admission(ownerRevoked).Row.RevokedAt = fixture.next()
	ownerParked := fixture.device(tagOwner)
	fixture.view.parked[ownerParked] = true
	otherDevice := fixture.device(other)
	ownerAgent := fixture.agent(tagOwner, tagId)
	state := fixture.state(t)
	cases := []struct {
		signer Id
		tagId  Id
		can    bool
	}{
		{signer: ownerDevice, tagId: tagId, can: true},
		{signer: ownerWorker, tagId: tagId, can: false},
		{signer: ownerBurner, tagId: tagId, can: false},
		{signer: ownerRevoked, tagId: tagId, can: false},
		{signer: ownerParked, tagId: tagId, can: false},
		{signer: otherDevice, tagId: tagId, can: false},
		{signer: ownerAgent, tagId: tagId, can: false},
		{signer: ownerDevice, tagId: NewId(), can: false},
		{signer: NewId(), tagId: tagId, can: false},
	}
	for i, c := range cases {
		if can := state.CanApplyTag(c.signer, c.tagId); can != c.can {
			t.Errorf("case %d: %t", i, can)
		}
	}
}

// A sidecar in an owner-bound repo's consented list reads it only while §8.5 still consents it: a
// cascade voiding the consent closes the repo to it, and the rows' list alone opens nothing.
func TestAclOwnerBoundReadsFollowConsent(t *testing.T) {
	fixture := newAclTestFixture()
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	adminDevice := fixture.invitedDevice(admin)
	a := fixture.invitedDevice(member)
	g := fixture.device(member, adminDevice.Bytes())
	fixture.admission(g).Row.OwnerConfirmSigner = a.Bytes()
	fixture.admission(g).Row.OwnerConfirmedAt = fixture.next()
	vaultId, vault := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, member)
	vault.ConsentedSidecarIds = [][]byte{a.Bytes(), g.Bytes()}
	if rights := aclTestRights(fixture.state(t), g, vaultId, AclTokenAudienceEvs); rights != AclEvsRead|AclEvsWrite {
		t.Errorf("confirmed g: %b", rights)
	}
	fixture.view.voidFrom[string(a.Bytes())] = 1
	if rights := aclTestRights(fixture.state(t), g, vaultId, AclTokenAudienceEvs); rights != AclEvsDeposit {
		t.Errorf("g after A entered P: %b, want only the owner's-subject deposit", rights)
	}
}
