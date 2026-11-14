//go:build !sidecar_http && !ios_extension

// QD-748's refusal (directory_private.go) on the test network, whose log judges each RepoCreate at its position as api
// and every reader do: an EvsClient on a stub evs files each statement through the network as one device, and its
// PrivateCreate asks directoryReadyPrivateRepo over the network's state and a tier the test sets.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device's creates over the test network, with what each step saw.
type testPrivateCreator struct {
	net    *testConfigNet
	device testConfigDevice
	client *EvsClient

	stateLock sync.Mutex
	// the tier api answers, or an error in its place
	team    bool
	tierErr error
	// evs routes in order
	routes []string
	// each RepoCreate filed, and whether it took effect
	posted   []*protocol.RepoCreate
	accepted []bool
	// each read of the tier
	tierReads int
	// each RepoCreated call, with whether the network's directory stood in the state then
	created        []*EvsRepoCreated
	directoryStood []bool
}

func newTestPrivateCreator(t *testing.T, net *testConfigNet, device testConfigDevice, team bool) *testPrivateCreator {
	t.Helper()
	creator := &testPrivateCreator{net: net, device: device, team: team}
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		func() {
			creator.stateLock.Lock()
			defer creator.stateLock.Unlock()
			creator.routes = append(creator.routes, request.Method+" "+request.URL.Path)
		}()
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	identity := &SidecarIdentity{NetworkId: net.networkId, SidecarId: device.sidecarId, ClientId: evsTestId("private creator client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	test.client.args.FileStatement = func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
		create := body.(*protocol.RepoCreate)
		create.Header = net.header()
		verdict := net.post(device, signedType, create)
		creator.stateLock.Lock()
		defer creator.stateLock.Unlock()
		creator.posted = append(creator.posted, create)
		creator.accepted = append(creator.accepted, verdict.Accepted())
		return verdict.Refusal
	}
	test.client.args.PrivateCreate = func(ctx context.Context, client *EvsClient, args *EvsCreateRepoArgs) error {
		return directoryReadyPrivateRepo(ctx, client, args.Kind, &directoryPrivateRepoArgs{
			directory: func() (Id, bool) { return NewDirectoryAuthView(net.log.State()).Directory() },
			state:     net.log.State,
			catchUp:   func(ctx context.Context) error { return nil },
			teamTier: func(ctx context.Context) (bool, error) {
				creator.stateLock.Lock()
				defer creator.stateLock.Unlock()
				creator.tierReads += 1
				return creator.team, creator.tierErr
			},
		})
	}
	test.client.args.RepoCreated = func(ctx context.Context, created *EvsRepoCreated) error {
		_, stood := NewDirectoryAuthView(net.log.State()).Directory()
		creator.stateLock.Lock()
		defer creator.stateLock.Unlock()
		creator.created = append(creator.created, created)
		creator.directoryStood = append(creator.directoryStood, stood)
		return nil
	}
	creator.client = test.client
	return creator
}

// The kinds of the RepoCreates filed, in order.
func (self *testPrivateCreator) postedKinds() []protocol.RepoKind {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kinds := []protocol.RepoKind{}
	for _, create := range self.posted {
		kinds = append(kinds, create.GetKind())
	}
	return kinds
}

// The position of a repo's RepoCreate in the network's state, false for a repo it does not hold.
func testPrivateRepoCreatedAt(t *testing.T, net *testConfigNet, repoId Id) (uint64, bool) {
	t.Helper()
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	repo := acl.Repo(repoId)
	if repo == nil {
		return 0, false
	}
	return directoryRepoCreatedAt(repo), true
}

// A member's device in a team with no directory refuses a create marked private before anything is filed, naming the
// missing directory, for a general and a record repo alike, asking nothing of api; the same create without --private
// goes on, its repo predating the directory, which §16.11's predating rule then announces.
func TestPrivateCreateWithNoDirectoryRefusedOnAMembersDevice(t *testing.T) {
	team := newTestConfigTeam(t)
	member := team.admitMemberDevice("plain")
	creator := newTestPrivateCreator(t, team.testConfigNet, member, true)
	before := team.n
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD} {
		repo, err := creator.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: kind, DisplayName: "launch plans", Private: true})
		if !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) || repo != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.Contains(err.Error(), "team directory") {
			t.Errorf("%s: the refusal names no directory: %v", kind, err)
		}
	}
	if team.n != before || len(creator.posted) != 0 || len(creator.routes) != 0 || len(creator.created) != 0 {
		t.Fatalf("filed %d, routes %v, hooks %d, log from %d to %d", len(creator.posted), creator.routes, len(creator.created), before, team.n)
	}
	if creator.tierReads != 0 {
		t.Errorf("a member's refusal asked api's tier %d times", creator.tierReads)
	}
	if len(testTeamDirectories(team.log.State())) != 0 {
		t.Error("a member's device filed the directory")
	}

	repo, err := creator.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, DisplayName: "launch plans"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(creator.postedKinds(), []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL}) || !creator.accepted[0] {
		t.Fatalf("filed %v", creator.postedKinds())
	}
	if len(creator.created) != 1 || creator.created[0].RepoId != repo.RepoId() || creator.created[0].Private || creator.directoryStood[0] {
		t.Errorf("RepoCreated %+v, directory stood %v", creator.created, creator.directoryStood)
	}
	if creator.tierReads != 0 {
		t.Error("a create not marked private asked api's tier")
	}
}

// A config writer's device in a team on the team tier with no directory files the directory first, its RepoCreate
// landing before the repo's, places and activates it through the same client, and only then files the repo, whose
// RepoCreated finds the directory standing to take its marker; a later private create, the directory standing, files
// its repo alone and asks api nothing.
func TestPrivateCreateOnAnAdminDeviceFilesTheDirectoryFirst(t *testing.T) {
	team := newTestConfigTeam(t)
	creator := newTestPrivateCreator(t, team.testConfigNet, team.adminB, true)
	repo, err := creator.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{
		Kind: protocol.RepoKind_REPO_KIND_GENERAL, DisplayName: "design notes", Private: true, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := []protocol.RepoKind{protocol.RepoKind_REPO_KIND_DIRECTORY, protocol.RepoKind_REPO_KIND_GENERAL}
	if !slices.Equal(creator.postedKinds(), wantKinds) || !creator.accepted[0] || !creator.accepted[1] {
		t.Fatalf("filed %v, accepted %v", creator.postedKinds(), creator.accepted)
	}
	directories := testTeamDirectories(team.log.State())
	if len(directories) != 1 || !teamDirectoryCreatedBy(directories[0], team.adminB.sidecarId) {
		t.Fatalf("directories %v", directories)
	}
	directoryId := Id(directories[0].GetRepoId())
	directoryAt, _ := testPrivateRepoCreatedAt(t, team.testConfigNet, directoryId)
	repoAt, ok := testPrivateRepoCreatedAt(t, team.testConfigNet, repo.RepoId())
	if !ok || repoAt <= directoryAt {
		t.Errorf("the repo created at %d, the directory at %d", repoAt, directoryAt)
	}
	wantRoutes := []string{
		"PUT /evs/v1/repos/" + evsUrlId(directoryId),
		"POST /evs/v1/repos/" + evsUrlId(directoryId) + "/activate",
		"PUT /evs/v1/repos/" + evsUrlId(repo.RepoId()),
		"POST /evs/v1/repos/" + evsUrlId(repo.RepoId()) + "/activate",
	}
	if !slices.Equal(creator.routes, wantRoutes) {
		t.Errorf("routes %v", creator.routes)
	}
	if len(creator.created) != 2 || creator.created[0].Kind != protocol.RepoKind_REPO_KIND_DIRECTORY ||
		creator.created[1].RepoId != repo.RepoId() || !creator.created[1].Private || !creator.directoryStood[1] {
		t.Fatalf("RepoCreated %+v, directory stood %v", creator.created, creator.directoryStood)
	}
	if creator.tierReads != 1 {
		t.Errorf("api's tier read %d times", creator.tierReads)
	}
	team.everyReaderAgrees()

	member := newTestPrivateCreator(t, team.testConfigNet, team.admitMemberDevice("plain"), false)
	later, err := member.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_RECORD, Private: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(member.postedKinds(), []protocol.RepoKind{protocol.RepoKind_REPO_KIND_RECORD}) || member.tierReads != 0 {
		t.Errorf("with the directory standing: filed %v, tier read %d times", member.postedKinds(), member.tierReads)
	}
	if len(member.created) != 1 || member.created[0].RepoId != later.RepoId() || !member.created[0].Private || !member.directoryStood[0] {
		t.Errorf("RepoCreated %+v", member.created)
	}
}

// A config writer's device in a network api does not put in the team tier, a personal network's owner among them,
// files no directory and refuses, naming the tier; a tier that cannot be read refuses too. Nothing is filed either way.
func TestPrivateCreateOutsideTheTeamTierRefused(t *testing.T) {
	personal := newTestConfigNet(t)
	before := personal.n
	creator := newTestPrivateCreator(t, personal, personal.owner, false)
	_, err := creator.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true})
	if !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) || !strings.Contains(err.Error(), "team tier") {
		t.Fatalf("outside the team tier: %v", err)
	}
	if creator.tierReads != 1 {
		t.Errorf("api's tier read %d times", creator.tierReads)
	}

	unread := errors.New("limits did not answer")
	creator.tierErr = unread
	_, err = creator.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_RECORD, Private: true})
	if !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) || !errors.Is(err, unread) {
		t.Fatalf("a tier that cannot be read: %v", err)
	}
	if personal.n != before || len(creator.posted) != 0 || len(creator.routes) != 0 || len(testTeamDirectories(personal.log.State())) != 0 {
		t.Fatalf("filed %d, routes %v", len(creator.posted), creator.routes)
	}
}

// The check alone, failing closed: kinds announced only explicitly ask nothing; no args, no state, a state before base
// 1 and a deleted directory refuse; and a directory the state holds but the view does not show yet is caught up to,
// refusing while the view still does not show it.
func TestPrivateCreateCheckFailsClosed(t *testing.T) {
	team := newTestConfigTeam(t)
	creator := newTestPrivateCreator(t, team.testConfigNet, team.adminB, true)
	unasked := &directoryPrivateRepoArgs{
		directory: func() (Id, bool) { t.Error("asked the directory"); return Id{}, false },
		state:     func() *ConfigState { t.Error("asked the state"); return nil },
		teamTier:  func(ctx context.Context) (bool, error) { t.Error("asked the tier"); return false, nil },
	}
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX,
		protocol.RepoKind_REPO_KIND_SECRET, protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_MAILCFG} {
		if err := directoryReadyPrivateRepo(t.Context(), creator.client, kind, unasked); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
	general := protocol.RepoKind_REPO_KIND_GENERAL
	if err := directoryReadyPrivateRepo(t.Context(), creator.client, general, nil); !errors.Is(err, ErrTeamDirectoryUnwired) {
		t.Errorf("no args: %v", err)
	}
	none := func() (Id, bool) { return Id{}, false }
	tier := func(ctx context.Context) (bool, error) { return true, nil }
	for _, state := range []*ConfigState{nil, team.statesAt[0]} {
		args := &directoryPrivateRepoArgs{directory: none, state: func() *ConfigState { return state }, teamTier: tier}
		if err := directoryReadyPrivateRepo(t.Context(), creator.client, general, args); !errors.Is(err, ErrTeamDirectoryNoState) {
			t.Errorf("no state past base 1: %v", err)
		}
	}
	if len(creator.posted) != 0 {
		t.Fatalf("filed %d", len(creator.posted))
	}

	// the directory stands in the state, and the view lags until a catch-up
	filer := &testTeamDirectoryFiler{net: team.testConfigNet, device: team.owner}
	filed, err := FileTeamDirectory(t.Context(), filer.args())
	if err != nil {
		t.Fatal(err)
	}
	shown := false
	lagging := &directoryPrivateRepoArgs{
		directory: func() (Id, bool) { return filed.RepoId, shown },
		state:     team.log.State,
		teamTier:  tier,
	}
	if err := directoryReadyPrivateRepo(t.Context(), creator.client, general, lagging); !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) {
		t.Errorf("a view that does not show the directory: %v", err)
	}
	lagging.catchUp = func(ctx context.Context) error { shown = true; return nil }
	if err := directoryReadyPrivateRepo(t.Context(), creator.client, general, lagging); err != nil {
		t.Errorf("a view caught up: %v", err)
	}
	if len(creator.posted) != 0 || len(creator.routes) != 0 {
		t.Errorf("another's directory: filed %d, routes %v", len(creator.posted), creator.routes)
	}

	// a deleted directory takes no second
	deletion := &protocol.RepoDelete{Header: team.header(), RepoId: filed.RepoId.Bytes(), DeletionId: NewId().Bytes()}
	team.mustPost(team.owner, bridge.SignedType_SIGNED_REPO_DELETE, deletion)
	deleted := &directoryPrivateRepoArgs{directory: none, state: team.log.State, teamTier: tier}
	err = directoryReadyPrivateRepo(t.Context(), creator.client, general, deleted)
	if !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) || !strings.Contains(err.Error(), "deleted") {
		t.Errorf("a deleted directory: %v", err)
	}
	if len(creator.posted) != 0 {
		t.Errorf("filed %d past a deleted directory", len(creator.posted))
	}
}

// With nothing to ask, a create marked private refuses before anything is filed or sent; a create resumed by its id
// filed its RepoCreate already and goes on unasked.
func TestEvsCreateRepoRefusesAPrivateRepoNothingChecks(t *testing.T) {
	routes := []string{}
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		routes = append(routes, request.Method+" "+request.URL.Path)
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	if _, err := test.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true}); !errors.Is(err, ErrEvsPrivateUnchecked) {
		t.Fatalf("no check: %v", err)
	}
	if len(test.poster.filed) != 0 || len(routes) != 0 {
		t.Fatalf("filed %v, routes %v", test.poster.filed, routes)
	}
	resumeId := NewEvsRepoId()
	if _, err := test.client.CreateRepo(t.Context(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true, ResumeRepoId: &resumeId}); err != nil {
		t.Fatal(err)
	}
	if len(test.poster.filed) != 0 || len(routes) != 2 {
		t.Errorf("a resumed create: filed %v, routes %v", test.poster.filed, routes)
	}
}

// A Sidecar whose directory client, config state and api are not bound yet refuses a create marked private, naming
// the missing directory, before anything is filed; once its view shows a team network's directory, it goes on.
func TestSidecarPrivateCreateRefusedUntilBound(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	sidecar.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: NewId(), IdentityPublicKey: make([]byte, 32)}
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Errorf("a refused create sent %s %s", request.Method, request.URL.Path)
	}), newEvsTestStore(t))
	test.client.args.PrivateCreate = sidecar.readyPrivateRepo
	private := &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true}
	if _, err := test.client.CreateRepo(t.Context(), private); !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) {
		t.Fatalf("unbound: %v", err)
	}
	if len(test.poster.filed) != 0 {
		t.Fatalf("filed %v", test.poster.filed)
	}
	if _, err := sidecar.teamTier(t.Context()); err == nil {
		t.Error("a tier read with no api client")
	}

	client, err := sidecar.DirectoryClient()
	if err != nil {
		t.Fatal(err)
	}
	directoryTeam := NewDirectoryAuthTestNetwork(t)
	client.Bind(nil, func() DirectoryAuthView { return directoryTeam.View() })
	if err := sidecar.readyPrivateRepo(t.Context(), test.client, private); err != nil {
		t.Errorf("with the directory standing: %v", err)
	}
	if err := sidecar.readyPrivateRepo(t.Context(), test.client, nil); !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) {
		t.Errorf("no repo: %v", err)
	}
}
