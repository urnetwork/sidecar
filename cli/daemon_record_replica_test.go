// A hosted member opens a signed vault note through the record binding and its verified EVS stream.

package main

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// Opens the normal daemon follower and writes a signed note to its member vault.
func hostedRecordNote(t *testing.T, format2 bool) (*testUrFollowWorld, *sidecar.Sidecar, *sidecar.EvsClient, *sidecar.SidecarRecord, sidecar.Id, *sidecar.RecordEntryRef) {
	t.Helper()
	world := newTestUrFollowWorld(t, 1)
	engines := enginenet.NewEngines(t, world.net, nil)
	network := world.networks[0]
	engines.OpenNetwork(network.NetworkId())
	if format2 {
		id := connect.Id(network.NetworkId()).String()
		if err := world.net.Fakes().Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  gkm: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q]}\n", id, id, id)); err != nil {
			t.Fatal(err)
		}
	}
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
	writer, err := running.Record()
	if err != nil {
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
	return world, running, evs, writer, vault, refs[0]
}

// A newly bound reader has only its member's published config, EVS client and an empty record store.
func TestHostedMemberReadsSignedVaultRecord(t *testing.T) {
	world, running, evs, _, vault, ref := hostedRecordNote(t, false)
	config := running.ConfigFollower().Client()
	want := &protocol.CoordinationBody{Text: "the member's first vault note"}
	identity := running.Identity()
	reader, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId: identity.SidecarId, IdentityPublicKey: identity.IdentityPublicKey, Sign: running.Sign,
		Store: sidecartest.NewFakeStore().Root(), Clock: world.networks[0].Clock(), Settings: sidecar.DefaultSidecarSettings().Record,
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
	entry, ok := reader.Reader().Entry(vault, ref.EntryId)
	if !ok || entry.State != sidecar.RecordEntryLive || entry.BodyInvalid || entry.Leaf != ref.Leaf {
		t.Fatalf("verified reader lost the signed vault entry: %v", entry)
	}
	got := &protocol.CoordinationBody{}
	if err := proto.Unmarshal(entry.Body, got); err != nil || !proto.Equal(got, want) {
		t.Fatalf("reopened vault note: %v, %v", got, err)
	}
}

// The native daemon's stock erase reaches the authenticated companion CUT and the writer's completion ERASE.
func TestHostedMemberErasesSignedVaultRecordWithItsIndex(t *testing.T) {
	world, _, evs, writer, vault, ref := hostedRecordNote(t, true)
	if !evs.Format2Admitted() {
		t.Fatal("the daemon did not receive the format2 gate")
	}
	result, err := writer.Eraser().Erase(world.ctx, &sidecar.RecordEraseArgs{LogId: vault, EntryIds: []sidecar.Id{ref.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true})
	if err != nil || result.Index == nil || !result.Index.Fenced || !result.Index.Completed || result.Index.DocumentCount != 1 {
		t.Fatalf("record erasure and index: %+v, %v", result, err)
	}
	erasures, err := evs.Repo(vault).ReadErasures(world.ctx, 0)
	if err != nil || len(erasures) < 2 {
		t.Fatalf("erasure statements: %+v, %v", erasures, err)
	}
	last := erasures[len(erasures)-1]
	if last.ErasureId != result.ErasureId || !last.Completion || !last.Complete {
		t.Fatalf("completion: %+v", last)
	}
	// A subsequent operation on the same initialized vault must wait if a rollout closes while its format-2 index stands.
	evs.SetFormat2Source(func() bool { return false })
	_, err = writer.Eraser().Plan(world.ctx, &sidecar.RecordEraseArgs{LogId: vault, EntryIds: []sidecar.Id{ref.EntryId}})
	if !errors.Is(err, sidecar.ErrRecordEraseIndexUnavailable) {
		t.Fatalf("closed format2 on an initialized vault: %v", err)
	}
}
