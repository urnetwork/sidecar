package gkmservice

import (
	"bytes"
	"net/http"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// GET /gkm/welcomes under QD-975's whole set: one repo on the second cluster whose GroupForm names one group, whose
// epoch 1 has a Welcome there, and a pointer to it on the first cluster for each sidecar a test adds.
type gkmWelcomesWholeSetWorld struct {
	fixture  *gkmFixture
	repoId   sidecar.Id
	groupId  sidecar.Id
	memberId sidecar.Id
	welcome  []byte
}

func newGkmWelcomesWholeSetWorld(t *testing.T) *gkmWelcomesWholeSetWorld {
	fixture := newGkmFixture(t)
	world := &gkmWelcomesWholeSetWorld{
		fixture:  fixture,
		repoId:   testId("repo-r"),
		groupId:  testId("group-g"),
		memberId: testId("member-m"),
		welcome:  []byte("welcome of group g at epoch 1"),
	}
	fixture.placeRepo(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(world.repoId, "meta-2", 1, world.groupId)
	fixture.put("meta-2", GkmWelcomeKey(world.groupId, 1), world.welcome)
	return world
}

// A member device of the world's member, admitted with no right on any repo, with a pointer to groupId's Welcome at
// epoch 1 under a ref of its own.
func (self *gkmWelcomesWholeSetWorld) addSidecar(label string) (sidecar.Id, []byte) {
	sidecarId := testId(label)
	self.fixture.auth.admit(sidecarId, memberDeviceFacts(self.memberId))
	return sidecarId, self.point(sidecarId, self.groupId, label)
}

// Puts a pointer for sidecarId to groupId's Welcome at epoch 1, its ref made from label.
func (self *gkmWelcomesWholeSetWorld) point(sidecarId sidecar.Id, groupId sidecar.Id, label string) []byte {
	ref := bytes.Repeat([]byte(label), gkmKeyPackageRefByteCount)[:gkmKeyPackageRefByteCount]
	self.fixture.put("meta-1", GkmWelcomePointerKey(sidecarId, groupId, 1), self.fixture.marshal(&protocol.GkmWelcomePointer{
		GroupId:       groupId.Bytes(),
		Epoch:         1,
		KeyPackageRef: ref,
	}))
	return ref
}

// The right sets the state was asked of the world's repo since the asks numbered before.
func (self *gkmWelcomesWholeSetWorld) asksSince(before int) []sidecar.AclEvsRights {
	asked := []sidecar.AclEvsRights{}
	for _, ask := range self.fixture.auth.honorAsked()[before:] {
		if ask.repoId == self.repoId {
			asked = append(asked, ask.rights)
		}
	}
	return asked
}

// GET /gkm/welcomes under token: the Welcomes served by their pointer's group, and the right sets the state was asked
// of the world's repo.
func (self *gkmWelcomesWholeSetWorld) welcomes(token string) (map[sidecar.Id]*protocol.GkmWelcomeEntry, []sidecar.AclEvsRights) {
	t := self.fixture.t
	t.Helper()
	before := len(self.fixture.auth.honorAsked())
	recorder := self.fixture.serve(http.MethodGet, "/gkm/welcomes", token, nil)
	reply := &protocol.GkmWelcomesReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
		t.Fatalf("GET /gkm/welcomes: %d", recorder.Code)
	}
	groupIdEntries := map[sidecar.Id]*protocol.GkmWelcomeEntry{}
	for _, entry := range reply.GetWelcomes() {
		groupId, err := sidecar.IdFromBytes(entry.GetPointer().GetGroupId())
		if err != nil {
			t.Fatalf("a Welcome whose pointer names no group: %v", err)
		}
		groupIdEntries[groupId] = entry
	}
	return groupIdEntries, self.asksSince(before)
}

// QD-975 over QD-880's state at GET /gkm/welcomes: a sidecar the state gives admin alone on a repo, as a repo whose
// newest RepoDelete stands unrestored gives its standing admin from the moment the RepoDelete is in the gate's state,
// is served none of that repo's group's Welcomes under its admin token, the state asked admin, rw and r and honoring
// them only whole, while a live repo's group the same token scopes is still served. Once the state gives the sidecar a
// live repo's admin again, admin, rw and r, the same token is served the group's Welcome: it was the set that refused
// it. The route asked admin alone, which served it.
func TestGkmWelcomesRefuseADeletedRepoStandingAdmin(t *testing.T) {
	world := newGkmWelcomesWholeSetWorld(t)
	fixture := world.fixture
	admin, write, read := sidecar.AclEvsAdmin, sidecar.AclEvsWrite, sidecar.AclEvsRead
	liveRepoId, liveGroupId := testId("repo-live"), testId("group-live")
	fixture.placeRepo(liveRepoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(liveRepoId, "meta-1", 1, liveGroupId)
	liveWelcome := []byte("welcome of the live group at epoch 1")
	fixture.put("meta-1", GkmWelcomeKey(liveGroupId, 1), liveWelcome)

	standing, ref := world.addSidecar("sc-standing")
	liveRef := world.point(standing, liveGroupId, "sc-live")
	fixture.auth.holdExactly(standing, world.repoId, admin)
	fixture.auth.grant(standing, liveRepoId, read)
	token := fixture.token(standing, repoScope(world.repoId, "admin"), repoScope(liveRepoId, "r"))

	served, asks := world.welcomes(token)
	if entry, ok := served[world.groupId]; ok {
		t.Errorf("the deleted repo's standing admin was served its group's Welcome %q", entry.GetWelcome())
	}
	if !slices.Equal(asks, []sidecar.AclEvsRights{admin | write | read}) {
		t.Errorf("asked %04b of the deleted repo, want %04b alone", asks, admin|write|read)
	}
	if entry, ok := served[liveGroupId]; !ok || !bytes.Equal(entry.GetKeyPackageRef(), liveRef) || !bytes.Equal(entry.GetWelcome(), liveWelcome) {
		t.Errorf("the live repo's group under the same token: %v", entry)
	}
	if len(served) != 1 {
		t.Errorf("%d Welcomes served, want the live group's alone", len(served))
	}

	// the state gives the sidecar a live repo's admin: the same token is served the group's Welcome
	fixture.auth.grant(standing, world.repoId, admin)
	served, asks = world.welcomes(token)
	if entry, ok := served[world.groupId]; !ok || !bytes.Equal(entry.GetKeyPackageRef(), ref) || !bytes.Equal(entry.GetWelcome(), world.welcome) {
		t.Errorf("a live repo's admin: %v", entry)
	}
	if !slices.Equal(asks, []sidecar.AclEvsRights{admin | write | read}) {
		t.Errorf("a live repo's admin: asked %04b, want %04b", asks, admin|write|read)
	}
	if len(served) != 2 {
		t.Errorf("a live repo's admin: %d Welcomes served, want both groups'", len(served))
	}
}

// A member holding the row's rights on the group's repo is served its Welcome under each role's token, with the
// pointer's ref and the Welcome's bytes, the state asked once for that role's whole set: a reader r, a writer rw and
// r, and a live repo's admin admin, rw and r.
func TestGkmWelcomesServeAMemberHoldingTheRowsRights(t *testing.T) {
	world := newGkmWelcomesWholeSetWorld(t)
	fixture := world.fixture
	admin, write, read := sidecar.AclEvsAdmin, sidecar.AclEvsWrite, sidecar.AclEvsRead
	cases := []struct {
		label string
		role  string
		held  sidecar.AclEvsRights
		asked sidecar.AclEvsRights
	}{
		{label: "sc-reader", role: "r", held: read, asked: read},
		{label: "sc-writer", role: "rw", held: write, asked: write | read},
		{label: "sc-admin", role: "admin", held: admin, asked: admin | write | read},
	}
	for _, c := range cases {
		sidecarId, ref := world.addSidecar(c.label)
		fixture.auth.grant(sidecarId, world.repoId, c.held)
		served, asks := world.welcomes(fixture.token(sidecarId, repoScope(world.repoId, c.role)))
		entry, ok := served[world.groupId]
		switch {
		case !ok || len(served) != 1:
			t.Errorf("%s: %d Welcomes served, want the group's", c.role, len(served))
		case !bytes.Equal(entry.GetKeyPackageRef(), ref) || !bytes.Equal(entry.GetWelcome(), world.welcome):
			t.Errorf("%s: served ref %x and Welcome %q", c.role, entry.GetKeyPackageRef(), entry.GetWelcome())
		case entry.GetPointer().GetEpoch() != 1:
			t.Errorf("%s: a pointer at epoch %d", c.role, entry.GetPointer().GetEpoch())
		}
		if !slices.Equal(asks, []sidecar.AclEvsRights{c.asked}) {
			t.Errorf("%s: asked %04b, want %04b once", c.role, asks, c.asked)
		}
	}
}

// Under one token the Welcomes route asks the state what the guard asks on the group's other reads, GET of the group
// and of its repo's forms, and comes to their verdict: the group's Welcome served where they answer 200, passed over
// where they answer 403. So a deleted repo's standing admin is refused the Welcomes under whichever role its token
// presents, as it is refused the group and the forms, and a token whose role runs ahead of the state, as an admin's
// does after a demotion until its exchange catches up, is refused all three alike.
func TestGkmWelcomesRefusalMatchesTheGroupReadsForOneToken(t *testing.T) {
	world := newGkmWelcomesWholeSetWorld(t)
	fixture := world.fixture
	admin, write, read := sidecar.AclEvsAdmin, sidecar.AclEvsWrite, sidecar.AclEvsRead
	cases := []struct {
		label  string
		role   string
		held   sidecar.AclEvsRights
		served bool
	}{
		{label: "sc-reader", role: "r", held: read, served: true},
		{label: "sc-writer", role: "rw", held: write | read, served: true},
		{label: "sc-admin", role: "admin", held: admin | write | read, served: true},
		{label: "sc-standing-adm", role: "admin", held: admin, served: false},
		{label: "sc-standing-rw", role: "rw", held: admin, served: false},
		{label: "sc-standing-r", role: "r", held: admin, served: false},
		{label: "sc-demoted", role: "admin", held: write | read, served: false},
	}
	readPaths := []string{
		"/gkm/groups/" + sidecar.EvsKeyId(world.groupId),
		"/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/forms",
	}
	for _, c := range cases {
		sidecarId, _ := world.addSidecar(c.label)
		fixture.auth.holdExactly(sidecarId, world.repoId, c.held)
		token := fixture.token(sidecarId, repoScope(world.repoId, c.role))
		served, welcomesAsks := world.welcomes(token)
		if _, ok := served[world.groupId]; ok != c.served {
			t.Errorf("%s under %s: Welcome served %t, want %t", c.label, c.role, ok, c.served)
		}
		if len(welcomesAsks) != 1 {
			t.Errorf("%s under %s: the Welcomes asked %d times, want once", c.label, c.role, len(welcomesAsks))
		}
		wantCode := http.StatusForbidden
		if c.served {
			wantCode = http.StatusOK
		}
		for _, path := range readPaths {
			before := len(fixture.auth.honorAsked())
			recorder := fixture.serve(http.MethodGet, path, token, nil)
			asks := world.asksSince(before)
			if recorder.Code != wantCode {
				t.Errorf("%s under %s: GET %s %d, want %d", c.label, c.role, path, recorder.Code, wantCode)
			}
			if !slices.Equal(asks, welcomesAsks) {
				t.Errorf("%s under %s: GET %s asked %04b, the Welcomes %04b", c.label, c.role, path, asks, welcomesAsks)
			}
		}
	}
}
