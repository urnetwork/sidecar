package evsservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.12's kinds table at placement, with QD-1093's row: a mailcfg is placed with an owner, a Team scope's own, whose
// repo/ carries it, and with none, the network's; an owner-bound kind with no owner and any other kind with one stay
// projections this build keeps no repo for (400 INVALID), nothing written.
func TestPlaceTakesAnOwnerForAScopesMailcfgAlone(t *testing.T) {
	fixture := newEvsFixture(t)
	creator := testId("sidecar-a")
	owner := testId("owner-member")
	cases := []struct {
		name    string
		kind    protocol.RepoKind
		owned   bool
		refused bool
	}{
		{name: "a scope's mailcfg", kind: protocol.RepoKind_REPO_KIND_MAILCFG, owned: true},
		{name: "the network's mailcfg", kind: protocol.RepoKind_REPO_KIND_MAILCFG},
		{name: "a mailbox", kind: protocol.RepoKind_REPO_KIND_MAILBOX, owned: true},
		{name: "a mailbox with no owner", kind: protocol.RepoKind_REPO_KIND_MAILBOX, refused: true},
		{name: "a general repo with an owner", kind: protocol.RepoKind_REPO_KIND_GENERAL, owned: true, refused: true},
		{name: "a team record with an owner", kind: protocol.RepoKind_REPO_KIND_TEAM_RECORD, owned: true, refused: true},
		{name: "the directory with an owner", kind: protocol.RepoKind_REPO_KIND_DIRECTORY, owned: true, refused: true},
	}
	for _, c := range cases {
		repoId := testId("repo " + c.name)
		facts := &EvsRepoFacts{Kind: c.kind, NetworkId: sidecar.Id(fixture.networkId)}
		if c.owned {
			facts.OwnerMemberId = owner
		}
		fixture.auth.setRepo(repoId, facts)
		fixture.auth.grant(creator, repoId, sidecar.AclEvsAdmin)
		recorder := fixture.putRepoAnswer(repoId, creator)
		repoBytes := fixture.object("meta-1", RepoKey(repoId))
		if c.refused {
			requireRefusal(t, recorder, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
			if repoBytes != nil || fixture.object("meta-1", sidecar.EvsPlaceKey(repoId)) != nil {
				t.Errorf("%s: a refused create wrote place/ or repo/", c.name)
			}
			continue
		}
		if recorder.Code != http.StatusOK || repoBytes == nil {
			t.Errorf("%s: the create answered %d", c.name, recorder.Code)
			continue
		}
		object, err := sidecar.ParseEvsRepoObject(repoId, repoBytes)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if object.GetKind() != c.kind || (len(object.GetOwnerMemberId()) != 0) != c.owned || (c.owned && sidecar.Id(object.GetOwnerMemberId()) != owner) {
			t.Errorf("%s: repo/ %v", c.name, object)
		}
	}
}
