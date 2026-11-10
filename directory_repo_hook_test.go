//go:build !js

// RECORD-M6-15's seam on EvsClient.CreateRepo: RepoCreated is called once the repo is active, with what its creator
// gave, a failure answering the repo with its error and a resumed create calling it again; and a Sidecar outside a
// team network writes nothing for it.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// CreateRepo hands RepoCreated the repo once it is active: its id, kind, display name, --private, group inbox and the
// person's confirmation; a failure answers the repo made with the error, and a create resumed by its id calls the
// hook again, so a retry announces what a kill cut short.
func TestEvsCreateRepoCallsRepoCreated(t *testing.T) {
	routes := []string{}
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		routes = append(routes, request.Method+" "+request.URL.Path)
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	calls := []*EvsRepoCreated{}
	routesAtCall := []int{}
	var failure error
	test.client.args.RepoCreated = func(ctx context.Context, created *EvsRepoCreated) error {
		calls = append(calls, created)
		routesAtCall = append(routesAtCall, len(routes))
		return failure
	}
	repo, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{
		Kind: protocol.RepoKind_REPO_KIND_GENERAL, DisplayName: "design notes", Private: true, GroupInbox: true, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].RepoId != repo.RepoId() || calls[0].Kind != protocol.RepoKind_REPO_KIND_GENERAL ||
		calls[0].DisplayName != "design notes" || !calls[0].Private || !calls[0].GroupInbox || !calls[0].Confirmed {
		t.Fatalf("calls %+v", calls)
	}
	// after the activation, the last route
	if routesAtCall[0] != len(routes) || routes[len(routes)-1] != "POST /evs/v1/repos/"+evsUrlId(repo.RepoId())+"/activate" {
		t.Errorf("called after %d of %v", routesAtCall[0], routes)
	}

	failure = errors.New("no directory writer")
	failed, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_RECORD})
	if !errors.Is(err, failure) || failed == nil {
		t.Errorf("a failed hook: %v, repo %v", err, failed)
	}
	failure = nil
	resumeId := failed.RepoId()
	if _, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_RECORD, ResumeRepoId: &resumeId}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[2].RepoId != resumeId || len(test.poster.filed) != 2 {
		t.Errorf("a resumed create: %d calls, %d statements", len(calls), len(test.poster.filed))
	}
}

// A Sidecar whose network has no directory, or whose directory client is not bound, writes nothing for a new repo
// and answers no error, so CreateRepo answers the repo as it would without the hook.
func TestSidecarAnnounceCreatedRepoOutsideATeam(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	sidecar.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: NewId(), IdentityPublicKey: make([]byte, 32)}
	created := &EvsRepoCreated{RepoId: NewId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true}
	if err := sidecar.announceCreatedRepo(context.Background(), created); err != nil {
		t.Errorf("unbound: %v", err)
	}
	client, err := sidecar.DirectoryClient()
	if err != nil {
		t.Fatal(err)
	}
	personal := newTestConfigNet(t)
	client.Bind(nil, func() DirectoryAuthView { return NewDirectoryAuthView(personal.log.State()) })
	if err := sidecar.announceCreatedRepo(context.Background(), created); err != nil {
		t.Errorf("a personal network: %v", err)
	}
}
