package gkmservice

// A group's resolution beside another request's read of its owner marker (DESIGN-DETAILS 6.2.2). A request whose token
// scopes the group's repo among others asks its candidates in order, and once the marker is known it asks the
// marker's repo alone. Before the fix it stopped at a marker another request had read while it asked a candidate
// before the group's repo, and refused 403 a token that scopes the group: the server e2e gkm case met it right after a
// gkm restart, whose caches start cold, as GETs of a group's gen and wraps refused with tokens scoping its repo.

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A token scoping the group's repo and another repo whose id sorts first resolves the group while a second request,
// its token scoping the group's repo alone, reads the marker between the first one's ask of the other repo and its
// next: the first request's LIST of the other repo's forms is parked until the second has answered. Both read the
// group.
func TestGkmResolvesAGroupWhoseMarkerAnotherRequestReadMeanwhile(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	world.createAndActivate()
	// another repo of the admin's, with no form, asked first: its id sorts before the group's repo's
	otherRepoId := testId("repo-a")
	if 0 <= otherRepoId.Cmp(world.repoId) {
		t.Fatalf("the other repo's id does not sort first")
	}
	fixture.placeRepo(otherRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.auth.grant(world.admin.sidecarId, otherRepoId, sidecar.AclEvsAdmin)
	bothToken := fixture.token(world.admin.sidecarId, repoScope(otherRepoId, "r"), repoScope(world.repoId, "r"))
	groupToken := fixture.token(world.admin.sidecarId, repoScope(world.repoId, "r"))
	// a restarted process: no cache of it holds the marker, a form or a placement
	fixture.start()
	parked, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpList,
		KeyPrefix: GkmFormPrefix(otherRepoId),
		Result:    sidecartest.Delay,
		Delay:     sidecartest.DelayInNetwork,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/gen?since=0"
	answered := make(chan int, 1)
	go func() {
		answered <- fixture.serve(http.MethodGet, path, bothToken, nil).Code
	}()
	select {
	case <-parked:
	case <-fixture.ctx.Done():
		t.Fatal("the first read never asked the other repo's forms")
	}
	// the second request resolves the group, reading its marker, while the first one's LIST is parked
	if code := fixture.serve(http.MethodGet, path, groupToken, nil).Code; code != http.StatusOK {
		t.Fatalf("the group's read on a token of its repo alone: %d", code)
	}
	if delivered := fixture.host.Blobs.DeliverDelayed("meta-2", GkmFormPrefix(otherRepoId)); delivered != 1 {
		t.Fatalf("%d LISTs of the other repo's forms were parked, not one", delivered)
	}
	if code := <-answered; code != http.StatusOK {
		t.Errorf("the group's read on a token scoping another repo first, the marker read meanwhile: %d", code)
	}
}
