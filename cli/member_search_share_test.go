//go:build sidecar_testhooks && !ios_extension && !sidecar_http && !js

package main

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The enrolled app asks the other member's designated indexer on a signed share. The serving component
// durably records one search before replying, even when the phone has no local copy of the vault.
func TestEnrolledAppSearchesSharedVaultAtOwnersIndexer(t *testing.T) {
	world := newTestEnrolledSearchApp(t)
	ctx, app, network := world.ctx, world.app, *world.app.NetworkId()
	peerHost, err := world.net.AddSidecarIn("shared-vault-indexer", network, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peerHost.Close)
	owner := peerHost.Sidecar()
	ownerMember, ownerId, readerId := sidecar.NewId(), owner.Identity().SidecarId, app.Identity().SidecarId
	if _, err := world.engines.PostStatement(ctx, app, bridge.SignedType_SIGNED_MEMBER_ADMIT, func(h *bridge.StatementHeader) proto.Message {
		return &protocol.MemberAdmit{Header: h, MemberId: ownerMember.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.engines.PostStatement(ctx, app, bridge.SignedType_SIGNED_SIDECAR_ADMIT, func(h *bridge.StatementHeader) proto.Message {
		return &protocol.SidecarAdmit{Header: h, NetworkId: network.Bytes(), SidecarId: ownerId.Bytes(), MemberId: ownerMember.Bytes(),
			IdentityPublicKey: owner.Identity().IdentityPublicKey, IdentityAlg: "ed25519", Capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.InstallAuthority(world.client.Authority()))
	vault := sidecar.NewEvsRepoId()
	post := func(kind bridge.SignedType, makeBody func(*bridge.StatementHeader) proto.Message) {
		t.Helper()
		head := &bridge.StatementHeader{NetworkId: network.Bytes(), At: world.client.Pin(), Nonce: sidecar.NewId().Bytes(),
			NotAfterMs: world.net.Clock().Now().Add(time.Hour).UnixMilli()}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(makeBody(head))
		if err != nil {
			t.Fatal(err)
		}
		purpose, _ := sidecar.ConfigStatementPurpose(kind)
		signed, err := owner.Sign(purpose, kind, body, nil)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		api, err := world.net.Api()
		if err != nil {
			t.Fatal(err)
		}
		pin, err := api.AppendStatement(ctx, network, wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := world.client.WaitFor(ctx, pin.Version); err != nil {
			t.Fatal(err)
		}
	}
	post(bridge.SignedType_SIGNED_REPO_CREATE, func(h *bridge.StatementHeader) proto.Message {
		return &protocol.RepoCreate{Header: h, RepoId: vault.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT}
	})
	post(bridge.SignedType_SIGNED_INDEXER_SET, func(h *bridge.StatementHeader) proto.Message {
		services, err := sidecar.SealConfigBody(world.provisioned.DraftedKey, sidecar.NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, h),
			&protocol.IndexerServices{Services: []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.IndexerSet{Header: h, SidecarId: ownerId.Bytes(), Scope: protocol.IndexerScope_INDEXER_SCOPE_MEMBER, SealedServices: services}
	})
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{RepoId: vault, RefId: sidecar.NewId(), Kind: protocol.RepoKind_REPO_KIND_VAULT, Clock: world.net.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	if err := index.PushDocuments(ctx, ownerId, world.net.Clock().Now(), []*sidecar.SearchTestDocument{{Path: "orchard", Title: "orchard", Version: 1, Time: world.net.Clock().Now()}}); err != nil {
		t.Fatal(err)
	}
	remote, err := sidecartest.NewSearchRemoteWorld(&sidecartest.SearchRemoteWorldArgs{Clock: world.net.Clock(),
		Config: func(sidecar.Id) (*sidecar.ConfigState, error) { return world.client.State(), nil },
		Services: sidecar.ConfigIndexerServicesOpener(func(generation uint64) *sidecar.EvsRepoKey {
			return app.GkmHeldKey(world.provisioned.ConfigRepoId, generation)
		})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Close)
	indexer, err := remote.AddIndexer(ctx, &sidecartest.SearchRemoteIndexerArgs{SidecarId: ownerId, Refs: []*sidecar.SearchTestNetworkRef{{World: index}}})
	if err != nil {
		t.Fatal(err)
	}
	component := &testMemberSearchIndexer{ready: make(chan struct{}), handler: indexer.Server.Handle}
	if _, err := owner.AddComponent(component); err != nil {
		t.Fatal(err)
	}
	select {
	case <-component.ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ask := func() *sidecar.SearchStream {
		t.Helper()
		stream, err := app.Search(ctx, &sidecar.SearchRequest{Text: "orchard", Scope: sidecar.SearchAll, Repos: []sidecar.Id{vault}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(stream.Close)
		return stream
	}
	assertRecords := func(want int) {
		t.Helper()
		records, err := indexer.Device.State().ServedRecords()
		if err != nil || len(records) != want || want == 1 && (records[0].RequesterId != readerId || records[0].RepoId != vault || records[0].Count != 1) {
			t.Fatalf("served records %v, want %d: %v", records, want, err)
		}
	}
	if err := app.SetSearchRemote(sidecar.SearchRemoteOn); err != nil {
		t.Fatal(err)
	}
	if hits, _, _, err := ask().Next(); err != nil || len(hits) != 0 {
		t.Fatalf("before share: %v, %v", hits, err)
	}
	assertRecords(0)
	post(bridge.SignedType_SIGNED_EVS_SHARE, func(h *bridge.StatementHeader) proto.Message {
		return &protocol.EvsShare{Header: h, RepoId: vault.Bytes(), Subject: readerId.Bytes()}
	})
	acl, err := world.client.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	rights := acl.EvsAccess(sidecar.AclSidecarSubject(readerId), vault, sidecar.AclTokenAudienceEvs, world.net.Clock().Now()).Rights
	if !rights.Has(sidecar.AclEvsRead) || rights.Has(sidecar.AclEvsWrite) || !acl.ConsentedFor(ownerId, ownerMember) {
		t.Fatalf("read-only share or owner consent did not take effect: %v", rights)
	}
	if _, progress, _, err := ask().Next(); err != nil || progress.Remote != sidecar.SearchRemoteStateNotice {
		t.Fatalf("before acknowledging owner: %+v, %v", progress, err)
	}
	assertRecords(0)
	if err := app.AcknowledgeSearchIndexer(&ownerMember, true); err != nil {
		t.Fatal(err)
	}
	stream := ask()
	hits, progress, _, err := stream.Next()
	if err != nil || progress.Remote != sidecar.SearchRemoteStateAnswered || progress.RemoteBy == nil || *progress.RemoteBy != ownerId {
		t.Fatalf("owner's indexer: %+v, %v", progress, err)
	}
	if len(hits) != 0 {
		t.Fatalf("the file-shaped claim in a vault passed signed-record validation: %v", hits)
	}
	assertRecords(1)
	post(bridge.SignedType_SIGNED_REPO_REVOKE, func(h *bridge.StatementHeader) proto.Message {
		return &protocol.RepoRevoke{Header: h, RepoId: vault.Bytes(), Subject: readerId.Bytes()}
	})
	if hits, _, done, err := stream.Next(); !errors.Is(err, sidecar.ErrSearchCursorExpired) || len(hits) != 0 || !done {
		t.Fatalf("revoked cursor: %v, %t, %v", hits, done, err)
	}
	if hits, _, _, err := ask().Next(); err != nil || len(hits) != 0 {
		t.Fatalf("after revocation: %v, %v", hits, err)
	}
	assertRecords(1)
}
