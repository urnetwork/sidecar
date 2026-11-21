// A hosted member opens a signed vault note through the record binding and its verified EVS stream.

package main

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A newly bound reader has only its member's published config, EVS client and an empty record store.
func TestHostedMemberReadsSignedVaultRecord(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	engines := enginenet.NewEngines(t, world.net, nil)
	network := world.networks[0]
	engines.OpenNetwork(network.NetworkId())
	running := world.host(network, nil)
	world.standing(running, network)
	if err := engines.Sync(world.ctx, network.NetworkId()); err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	owner := network.Owner().MemberId
	vault, err := engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{
		Sidecar: running, Gkm: gkm, Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	config := running.ConfigFollower().Client()
	writer, err := running.Record()
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.BindMemberReplica(config, evs); err != nil {
		t.Fatal(err)
	}
	if err := writer.PrepareDirectWrites(world.ctx); err != nil {
		t.Fatal(err)
	}
	want := &protocol.CoordinationBody{Text: "the member's first vault note"}
	refs, err := writer.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindNote, Source: sidecar.RecordSourceAgent, NoSession: true, Body: want,
	})
	if err != nil || len(refs) != 1 || refs[0].Spooled || refs[0].LogId != vault {
		t.Fatalf("vault capture: %v, %v", refs, err)
	}
	if err := writer.Land(world.ctx, refs); err != nil {
		t.Fatal(err)
	}
	identity := running.Identity()
	reader, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId: identity.SidecarId, IdentityPublicKey: identity.IdentityPublicKey, Sign: running.Sign,
		Store: sidecartest.NewFakeStore().Root(), Clock: network.Clock(), Settings: sidecar.DefaultSidecarSettings().Record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.BindMemberReplica(config, evs); err != nil {
		t.Fatal(err)
	}
	if err := reader.Reader().Sync(world.ctx, vault); err != nil {
		t.Fatal(err)
	}
	entry, ok := reader.Reader().Entry(vault, refs[0].EntryId)
	if !ok || entry.State != sidecar.RecordEntryLive || entry.BodyInvalid || entry.Leaf != refs[0].Leaf {
		t.Fatalf("verified reader lost the signed vault entry: %v", entry)
	}
	got := &protocol.CoordinationBody{}
	if err := proto.Unmarshal(entry.Body, got); err != nil || !proto.Equal(got, want) {
		t.Fatalf("reopened vault note: %v, %v", got, err)
	}
}
