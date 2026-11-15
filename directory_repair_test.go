//go:build !sidecar_http

// RECORD-M10-02's repair row on sidecartest's fakes (FS-84's "the rightful writer's repair restores the file"): a card
// another sidecar replaced, put again by its own sidecar at a higher seq; a repo file a non-admin replaced, put again
// from folded state by another admin of the repo; and a deleted repo's file removed by its signer.

package sidecar_test

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// B puts a card at A's path: readers ignore it with path_rule and keep showing A's; A's device, at its repair after its
// next sync, puts its card again above, which readers take, alarming nothing more; with nothing breached a repair puts
// nothing.
func TestDirectoryCardBreachRepairedByItsWriter(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	aMember, bMember := sidecar.NewId(), sidecar.NewId()
	a := world.memberWriter(aMember)
	b := world.memberWriter(bMember)
	world.publish()
	aDevice := world.device(a)
	run := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())
	aDevice.writeCard(t, run)
	reader := world.reader(nil)
	reader.mustSync(t)

	path := sidecar.DirectoryCardPath(a.sidecarId)
	pin := world.directoryAuth.Tip().Pin()
	forged := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())
	world.putFile(b.sidecarId, path, world.cardContent(b, a.sidecarId, 9, pin, forged), pin)
	reader.mustSync(t)
	shown := testItemsOf(t, reader, a.sidecarId)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, b.sidecarId) != 1 || len(shown) != 1 || shown[sidecar.Id(run.GetAnnouncementId())] == nil {
		t.Fatalf("the breach: %d items shown, alarms %v", len(shown), reader.alarmReasons())
	}

	aDevice.mustSync(t)
	pass, err := aDevice.client.Repair(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Card == nil || pass.Card.Seq != 2 || len(pass.Card.Items) != 1 {
		t.Fatalf("the repair: %+v", pass)
	}
	alarms := len(reader.alarmReasons())
	reader.mustSync(t)
	shown = testItemsOf(t, reader, a.sidecarId)
	if len(shown) != 1 || shown[sidecar.Id(run.GetAnnouncementId())] == nil || shown[sidecar.Id(run.GetAnnouncementId())].Seq != 2 {
		t.Errorf("after the repair: %v", shown)
	}
	if len(reader.alarmReasons()) != alarms {
		t.Errorf("the repaired card alarmed: %v", reader.alarmReasons())
	}

	aDevice.mustSync(t)
	if again, err := aDevice.client.Repair(t.Context()); err != nil || again.Card != nil {
		t.Errorf("a repair with nothing breached: %+v, %v", again, err)
	}
}

// A non-admin replaces P's repo file: readers keep showing E's version; F, P's other admin, puts the item again from
// its folded state as its own, which readers take at the same version.
func TestDirectoryRepoFileBreachRepaired(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	eMember, fMember, xMember := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	e := world.memberWriter(eMember)
	f := world.memberWriter(fMember)
	x := world.memberWriter(xMember)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e, f)
	eDevice := world.device(e)
	eDevice.mustSync(t)
	item := testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "design notes", false)
	if _, err := eDevice.client.WriteRepoFile(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	fDevice := world.device(f)
	fDevice.mustSync(t)

	path := sidecar.DirectoryRepoPath(repoId)
	pin := world.directoryAuth.Tip().Pin()
	forged := testRepoItem(t, x.sidecarId, &xMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 2, world.clock.Now().UnixMilli(), "forged", false)
	world.putFile(x.sidecarId, path, world.repoFileContent(x, repoId, 2, pin, forged), pin)
	reader.mustSync(t)
	if shown := testRepoItemShown(t, reader, repoId); shown == nil || shown.SignerSidecarId != e.sidecarId || reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, x.sidecarId) != 1 {
		t.Fatalf("the breach: %v, alarms %v", shown, reader.alarmReasons())
	}

	fDevice.mustSync(t)
	pass, err := fDevice.client.Repair(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pass.RepoFiles, []sidecar.Id{repoId}) {
		t.Fatalf("the repair: %+v", pass)
	}
	reader.mustSync(t)
	shown := testRepoItemShown(t, reader, repoId)
	if shown == nil || shown.SignerSidecarId != f.sidecarId || shown.Announcement.GetVersion() != 1 || shown.Announcement.GetWhat().GetTitle() != "design notes" {
		t.Errorf("after the repair: %v", shown)
	}
}

// Once P is deleted, its file's signer removes it at its repair; the item already ended with its repo.
func TestDirectoryRepoFileRemovedAfterDeletion(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	eMember := sidecar.NewId()
	e := world.memberWriter(eMember)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e)
	eDevice := world.device(e)
	eDevice.mustSync(t)
	if _, err := eDevice.client.WriteRepoFile(t.Context(), testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "old", false)); err != nil {
		t.Fatal(err)
	}
	eDevice.mustSync(t)
	world.directoryFixture.Repos[repoId].Deleted = true
	world.publish()
	eDevice.mustSync(t)
	pass, err := eDevice.client.Repair(t.Context())
	if err != nil || !slices.Equal(pass.RemovedRepoFiles, []sidecar.Id{repoId}) {
		t.Fatalf("the repair: %+v, %v", pass, err)
	}
	if version := world.cardFileVersion(sidecar.DirectoryRepoPath(repoId)); version != 0 {
		t.Errorf("a deleted repo's file stands at version %d", version)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if testRepoItemShown(t, reader, repoId) != nil || len(reader.alarmReasons()) != 0 {
		t.Errorf("after the removal: alarms %v", reader.alarmReasons())
	}
}
