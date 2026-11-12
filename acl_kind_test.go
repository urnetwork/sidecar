// §8.5's kind defaults as AclKindDefaults writes them, held to what AclState's EvsAccess gives (acl_evs.go), so the
// table and the evaluation cannot drift apart. Pure, on every leg.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Every kind's row agrees with the evaluation's own kind tests, and the table holds each kind once.
func TestAclKindDefaultsMatchTheEvaluation(t *testing.T) {
	seen := map[protocol.RepoKind]bool{}
	for _, row := range AclKindDefaults() {
		if seen[row.Kind] {
			t.Errorf("%s twice", row.Kind)
		}
		seen[row.Kind] = true
		if row.Wildcard != aclRepoKindGeneral(row.Kind) {
			t.Errorf("%s: wildcard %t", row.Kind, row.Wildcard)
		}
		if row.OwnerBound != aclRepoKindOwnerBound(row.Kind) {
			t.Errorf("%s: owner-bound %t", row.Kind, row.OwnerBound)
		}
	}
	for kind := protocol.RepoKind_REPO_KIND_GENERAL; kind <= protocol.RepoKind_REPO_KIND_SECRET; kind += 1 {
		if !seen[kind] {
			t.Errorf("%s is in no row", kind)
		}
	}
}

// What a rule naming a repo outright adds is the row's DocumentRights and nothing more: everything for general,
// record, team_record and mailcfg, deposit alone for vault and mailbox, nothing for config, directory and secret
// (D-ACL-13, D-ACL-24); and no rule narrows what the kind gives.
func TestAclKindDefaultsBoundWhatADocumentAdds(t *testing.T) {
	everything := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DEPOSIT, protocol.AclAction_ACL_ACTION_READ,
		protocol.AclAction_ACL_ACTION_WRITE, protocol.AclAction_ACL_ACTION_ADMIN}
	closure := func(rights AclEvsRights) AclEvsRights {
		if rights.Has(AclEvsAdmin) {
			rights |= AclEvsWrite
		}
		if rights.Has(AclEvsWrite) {
			rights |= AclEvsRead
		}
		return rights
	}
	for _, row := range AclKindDefaults() {
		rights := func(withRule bool) AclEvsRights {
			fixture := newAclTestFixture()
			owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
			other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
			tagId := fixture.tag(other)
			agent := fixture.agent(other, tagId)
			ownerId := Id{}
			if row.OwnerBound {
				ownerId = owner
			}
			repoId := aclTestKindRepo(fixture, row.Kind, ownerId)
			if withRule {
				fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(repoId)}, everything...)
			}
			return fixture.state(t).EvsAccess(AclSidecarSubject(agent), repoId, AclTokenAudienceEvs, aclTestNow).Rights
		}
		without, with := rights(false), rights(true)
		if with&without != without {
			t.Errorf("%s: a rule narrowed %b to %b", row.Kind, without, with)
		}
		if added := with &^ without; added&^closure(row.DocumentRights) != 0 || (row.DocumentRights != 0 && !with.Has(row.DocumentRights)) {
			t.Errorf("%s: a rule adds %b, the table %b", row.Kind, added, row.DocumentRights)
		}
	}
}

// The config and the directory are read by every admitted sidecar, an ephemeral one included (owner decision 6,
// D-ACL-24), and the config's evs writers are its config writers alone.
func TestAclKindDefaultsReadersOfTheConfigAndDirectory(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	writer := fixture.device(owner)
	fixture.view.configWriters[writer] = true
	member := fixture.device(owner)
	burner := fixture.device(owner)
	fixture.admission(burner).Ephemeral = true
	config := fixture.configRepo(Id{}, Id{})
	directory, _ := fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	state := fixture.state(t)
	for _, row := range AclKindDefaults() {
		repoId := map[protocol.RepoKind]Id{protocol.RepoKind_REPO_KIND_CONFIG: config, protocol.RepoKind_REPO_KIND_DIRECTORY: directory}[row.Kind]
		if repoId == (Id{}) {
			continue
		}
		if row.Read != AclKindAudienceAdmitted {
			t.Errorf("%s: read by %d", row.Kind, row.Read)
		}
		for _, sidecarId := range []Id{writer, member, burner} {
			if access := state.EvsAccess(AclSidecarSubject(sidecarId), repoId, AclTokenAudienceEvs, aclTestNow); !access.Rights.Has(AclEvsRead) {
				t.Errorf("%s: %s reads nothing", row.Kind, sidecarId)
			}
		}
	}
	if access := state.EvsAccess(AclSidecarSubject(writer), config, AclTokenAudienceEvs, aclTestNow); !access.Rights.Has(AclEvsWrite) {
		t.Errorf("the config writer: %b", access.Rights)
	}
	if access := state.EvsAccess(AclSidecarSubject(member), config, AclTokenAudienceEvs, aclTestNow); access.Rights.Has(AclEvsWrite) {
		t.Errorf("a member device writes config heads: %b", access.Rights)
	}
}
