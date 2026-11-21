//go:build !ios_extension && !sidecar_http && !js

package main

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A private indexer on a real Required dispatcher, with one synthetic result in the designated repo.
type testMemberSearchIndexer struct {
	ready     chan struct{}
	once      sync.Once
	calls     atomic.Int32
	requester sidecar.Id
	repo      sidecar.Id
	ref       sidecar.Id
	doc       sidecar.Id
}

func (self *testMemberSearchIndexer) Name() string { return "test-member-indexer" }
func (self *testMemberSearchIndexer) Close()       {}

func (self *testMemberSearchIndexer) Attach(env *sidecar.SidecarEnv) error {
	_, err := env.Subprotocol.Handle(protocol.MessageType_SEARCH, self.answer, nil)
	if err != nil {
		return err
	}
	if err := env.Subprotocol.SetFeatures(sidecar.SubprotocolFeatureServesSearch, nil); err != nil {
		return err
	}
	self.once.Do(func() { close(self.ready) })
	return nil
}

func (self *testMemberSearchIndexer) answer(ctx context.Context, message *sidecar.SubprotocolRequest) ([]byte, error) {
	self.calls.Add(1)
	request := &protocol.SearchRequest{}
	if message.Peer == nil || message.Peer.SidecarId != self.requester || proto.Unmarshal(message.Body, request) != nil ||
		request.GetQuery() != "orchard" || len(request.Repos) != 1 || !bytes.Equal(request.Repos[0].GetRepoId(), self.repo.Bytes()) {
		return nil, errors.New("unexpected requester or search scope")
	}
	reply := &protocol.SearchReply{
		SearchVersion: request.SearchVersion, SearchId: request.SearchId, Page: request.Page,
		Status: uint32(protocol.SearchStatus_SEARCH_OK), Complete: true, Phase: 1,
		Coverage: []*protocol.SearchCoverage{{RepoId: self.repo.Bytes(), RefId: self.ref.Bytes(), RefVersion: 1, Served: uint32(protocol.SearchServed_SERVED_INDEX)}},
		Hits: []*protocol.SearchHit{{RepoId: self.repo.Bytes(), RefId: self.ref.Bytes(), DocKey: self.doc.Bytes(), Version: 1, State: uint32(sidecar.SearchConfirmed),
			DocKind: 1, Partition: 1, TimeMs: 1000, Locator: "orchard.txt", Signer: self.requester.Bytes()}},
	}
	size := int(request.Steps) * sidecar.DefaultSearchWireSettings().StepByteCount
	reply.Pad = make([]byte, size-proto.Size(reply))
	reply.Pad = reply.Pad[:len(reply.Pad)-(proto.Size(reply)-size)]
	return proto.MarshalOptions{Deterministic: true}.Marshal(reply)
}

func TestEnrolledAppAsksOnlyItsCurrentSignedSearchIndexer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	appInstance, err := net.StartInstance("orchard-app", &sidecartest.TestInstanceArgs{Settings: func() *sidecar.SidecarSettings {
		settings := sidecar.DefaultSidecarSettings()
		settings.Search.RemoteAsk = true
		settings.Search.RemoteServe = false
		return settings
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(appInstance.Close)
	network, member := sidecar.NewId(), sidecar.NewId()
	app, err := appInstance.AddSidecarIn(network, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := urDaemonGkmClient(app)
	if err != nil {
		t.Fatal(err)
	}
	provisioned, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: app, Gkm: keys, OwnerMemberId: member}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := appInstance.Restart(); err != nil {
		t.Fatal(err)
	}
	app = appInstance.Sidecar(network)
	replica, err := app.OpenMemberReplica(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err := app.ConfigFollower().WaitStanding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	peerHost, err := net.AddSidecarIn("orchard-indexer", network, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peerHost.Close)
	peer := peerHost.Sidecar()
	id := peer.Identity()
	if _, err := engines.PostStatement(ctx, app, bridge.SignedType_SIGNED_SIDECAR_ADMIT, func(header *bridge.StatementHeader) proto.Message {
		return &protocol.SidecarAdmit{Header: header, NetworkId: network.Bytes(), SidecarId: id.SidecarId.Bytes(),
			MemberId: member.Bytes(), IdentityPublicKey: id.IdentityPublicKey, IdentityAlg: "ed25519"}
	}); err != nil {
		t.Fatal(err)
	}
	uninstall := peer.InstallAuthority(client.Authority())
	t.Cleanup(uninstall)
	repo := sidecar.NewEvsRepoId()
	if _, err := engines.PostStatement(ctx, app, bridge.SignedType_SIGNED_REPO_CREATE, func(header *bridge.StatementHeader) proto.Message {
		return &protocol.RepoCreate{Header: header, RepoId: repo.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	}); err != nil {
		t.Fatal(err)
	}
	indexer := &testMemberSearchIndexer{ready: make(chan struct{}), requester: app.Identity().SidecarId, repo: repo, ref: sidecar.NewId(), doc: sidecar.NewId()}
	if _, err := peer.AddComponent(indexer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-indexer.ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	designate := func(retire bool) {
		t.Helper()
		_, err := engines.PostStatement(ctx, app, bridge.SignedType_SIGNED_INDEXER_SET, func(header *bridge.StatementHeader) proto.Message {
			entry := &protocol.IndexerSet{Header: header, SidecarId: id.SidecarId.Bytes(), Scope: protocol.IndexerScope_INDEXER_SCOPE_NETWORK, Retire: retire}
			if !retire {
				key := app.GkmHeldKey(provisioned.ConfigRepoId, provisioned.DraftedKey.Generation())
				if key == nil {
					t.Fatal("app lost its local config key")
				}
				sealed, err := sidecar.SealConfigBody(key, sidecar.NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, header), &protocol.IndexerServices{Services: []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				entry.SealedServices = sealed
			}
			return entry
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	ask := func(scope sidecar.SearchScope, remote string) []sidecar.SearchHit {
		t.Helper()
		stream, err := app.Search(ctx, &sidecar.SearchRequest{Text: "orchard", Scope: scope, Remote: remote, Repos: []sidecar.Id{repo}})
		if err != nil {
			t.Fatal(err)
		}
		stop := context.AfterFunc(ctx, stream.Close)
		defer stop()
		defer stream.Close()
		hits, _, _, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		return hits
	}
	if len(app.GetSearchIndexers()) != 0 || len(ask(sidecar.SearchAll, "")) != 0 {
		t.Fatal("an undesignated peer answered")
	}
	designate(false)
	if listed := app.GetSearchIndexers(); len(listed) != 1 || listed[0].SidecarId != id.SidecarId || !listed[0].Own {
		t.Fatalf("current own designation: %+v", listed)
	}
	ask(sidecar.SearchCached, "")
	ask(sidecar.SearchAll, sidecar.SearchRemoteOff)
	if err := app.SetSearchRemote(sidecar.SearchRemoteOff); err != nil {
		t.Fatal(err)
	}
	ask(sidecar.SearchAll, "")
	if n := indexer.calls.Load(); n != 0 {
		t.Fatalf("received %d queries before search more was enabled", n)
	}
	if err := app.SetSearchRemote(sidecar.SearchRemoteOwn); err != nil {
		t.Fatal(err)
	}
	hits := ask(sidecar.SearchAll, "")
	if len(hits) != 1 || hits[0].Repo != repo || hits[0].DocKey != [16]byte(indexer.doc) || hits[0].By == "" || indexer.calls.Load() != 1 {
		t.Fatalf("authenticated result: %+v, calls %d", hits, indexer.calls.Load())
	}
	designate(true)
	if len(app.GetSearchIndexers()) != 0 || len(ask(sidecar.SearchAll, "")) != 0 || indexer.calls.Load() != 1 {
		t.Fatal("a retired designation received another search")
	}
	replica.Close()
	if len(app.GetSearchIndexers()) != 0 {
		t.Fatal("requester survived member close")
	}
}
