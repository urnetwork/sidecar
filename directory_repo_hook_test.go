//go:build !js

// RECORD-M6-15's seams on EvsClient.CreateRepo: PrivateCreate is asked before a private create files anything
// (QD-748), and RepoCreated is called once the repo is active, with what its creator gave, a failure answering the
// repo with its error and a resumed create calling it again; and a Sidecar with no directory writes nothing for a new
// repo, but answers a private one's marker as waiting.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// CreateRepo asks PrivateCreate before a private create files or sends anything, and hands RepoCreated the repo once
// it is active: its id, kind, display name, --private, group inbox and the person's confirmation; a failure answers
// the repo made with the error, and a create resumed by its id calls the hook again, so a retry announces what a kill
// cut short, and is not asked again. A refusal of PrivateCreate files nothing.
func TestEvsCreateRepoCallsRepoCreated(t *testing.T) {
	routes := []string{}
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		routes = append(routes, request.Method+" "+request.URL.Path)
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	// what had been sent, routes and statements, when each ask came
	sent := func() int { return len(routes) + len(test.poster.filed) }
	asked := []*EvsCreateRepoArgs{}
	sentAtAsk := []int{}
	var refusal error
	test.client.args.PrivateCreate = func(ctx context.Context, client *EvsClient, args *EvsCreateRepoArgs) error {
		if client != test.client {
			t.Error("asked with another client")
		}
		asked = append(asked, args)
		sentAtAsk = append(sentAtAsk, sent())
		return refusal
	}
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
	if len(asked) != 1 || asked[0].Kind != protocol.RepoKind_REPO_KIND_GENERAL || !asked[0].Private || sentAtAsk[0] != 0 {
		t.Fatalf("asked %+v after %v sent", asked, sentAtAsk)
	}
	if len(calls) != 1 || calls[0].RepoId != repo.RepoId() || calls[0].Kind != protocol.RepoKind_REPO_KIND_GENERAL ||
		calls[0].DisplayName != "design notes" || !calls[0].Private || !calls[0].GroupInbox || !calls[0].Confirmed {
		t.Fatalf("calls %+v", calls)
	}
	// after the activation, the last route
	if routesAtCall[0] != len(routes) || routes[len(routes)-1] != "POST /evs/v1/repos/"+evsUrlId(repo.RepoId())+"/activate" {
		t.Errorf("called after %d of %v", routesAtCall[0], routes)
	}

	// a refusal sends and files nothing, and calls no hook
	refusal = ErrDirectoryPrivateNeedsDirectory
	sentBefore := sent()
	if _, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true}); !errors.Is(err, refusal) {
		t.Fatalf("a refused private create: %v", err)
	}
	if len(asked) != 2 || sentAtAsk[1] != sentBefore || sent() != sentBefore || len(calls) != 1 {
		t.Fatalf("a refused private create: asked %d, sent %d more, %d calls", len(asked), sent()-sentBefore, len(calls))
	}
	refusal = nil

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
	if len(asked) != 2 {
		t.Errorf("asked %d times: a create not marked private, or resumed, is not asked", len(asked))
	}
}

// A Sidecar whose network shows no directory, or whose directory client is not bound, writes nothing for a new repo
// and answers no error, so CreateRepo answers the repo as it would without the hook, and §16.11's predating rule
// announces it once a directory stands; a vault marked private asks nothing either. A general or record repo marked
// private answers ErrDirectoryPrivateNeedsDirectory instead: only its marker keeps the choice, so its create answers
// the repo made with the error, and a resume by id writes the marker once the directory shows (QD-748).
func TestSidecarAnnounceCreatedRepoOutsideATeam(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	sidecar.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: NewId(), IdentityPublicKey: make([]byte, 32)}
	memberId := NewId()
	quiet := []*EvsRepoCreated{
		{RepoId: NewId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		{RepoId: NewId(), Kind: protocol.RepoKind_REPO_KIND_RECORD, DisplayName: "build ledger"},
		{RepoId: NewId(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &memberId, Private: true},
	}
	waiting := []*EvsRepoCreated{
		{RepoId: NewId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Private: true},
		{RepoId: NewId(), Kind: protocol.RepoKind_REPO_KIND_RECORD, Private: true},
	}
	check := func(state string) {
		for _, created := range quiet {
			if err := sidecar.announceCreatedRepo(context.Background(), created); err != nil {
				t.Errorf("%s, %s: %v", state, created.Kind, err)
			}
		}
		for _, created := range waiting {
			if err := sidecar.announceCreatedRepo(context.Background(), created); !errors.Is(err, ErrDirectoryPrivateNeedsDirectory) {
				t.Errorf("%s, a private %s: %v", state, created.Kind, err)
			}
		}
	}
	check("unbound")
	client, err := sidecar.DirectoryClient()
	if err != nil {
		t.Fatal(err)
	}
	personal := newTestConfigNet(t)
	client.Bind(nil, func() DirectoryAuthView { return NewDirectoryAuthView(personal.log.State()) })
	check("no directory")
}
