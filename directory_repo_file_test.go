//go:build !sidecar_http

// FS-101's r/ file cases across the retention horizon (RECORD-M10-02): admin E's repo file at n0 is taken by a fresh
// member device once api has dropped n0's entry and chain value, judging E's right by the access log's positions; a
// compromise revocation of E from a since_n at or before n0 voids it with an alarm, and the device that holds P's other
// admin row puts the item again, which readers take.

package sidecar_test

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestDirectoryRepoFileAcrossTheRetentionHorizon(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	eMember, fMember := sidecar.NewId(), sidecar.NewId()
	e := world.memberWriter(eMember)
	f := world.memberWriter(fMember)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e, f)
	eDevice := world.device(e)
	eDevice.mustSync(t)
	n0 := world.directoryAuth.Tip().Pin().GetVersion()
	item := testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "payroll exports", false)
	if _, err := eDevice.client.WriteRepoFile(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	fDevice := world.device(f)
	fDevice.mustSync(t)

	// 30 days and 10 folds past n0, with 4,096 positions of growth: n0 and its chain value are no longer held
	world.advance(sidecar.DirectoryPinPositionCount+1, time.Millisecond)
	for fold := 0; fold < 10; fold += 1 {
		world.advance(1, 3*24*time.Hour)
	}
	world.directoryAuth.RetainFrom(n0 + 1)
	world.recordAuth.RetainFrom(n0 + 1)
	fresh := world.reader(nil)
	fresh.mustSync(t)
	shown := testRepoItemShown(t, fresh, repoId)
	if shown == nil || shown.SignerSidecarId != e.sidecarId || shown.Announcement.GetWhat().GetTitle() != "payroll exports" {
		t.Fatalf("a fresh device past n0's retention: %v, alarms %v", shown, fresh.alarmReasons())
	}
	if alarms := fresh.alarmReasons(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}

	// a compromise revocation of E from a since_n at n0: E's file is void, alarming, and F's device puts it again
	admission := world.directoryFixture.Sidecars[e.sidecarId]
	admission.RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	admission.CompromisedSince = n0
	world.recordFixture.CompromisedSince = map[sidecar.Id]uint64{e.sidecarId: n0}
	world.publish()
	fresh.mustSync(t)
	if testRepoItemShown(t, fresh, repoId) != nil || fresh.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 1 {
		t.Errorf("a compromised signer's file: alarms %v", fresh.alarmReasons())
	}
	fDevice.mustSync(t)
	writes, err := fDevice.client.MaintainRepos(t.Context())
	if err != nil || len(writes) != 1 {
		t.Fatalf("the re-sign: %d writes, %v", len(writes), err)
	}
	// RECORD-M10-03 routes the re-sign to an r/ file; here F's device writes the same item there as its own
	if _, err := fDevice.client.WriteRepoFile(t.Context(), writes[0].Item); err != nil {
		t.Fatal(err)
	}
	fDevice.flush(t)
	fresh.mustSync(t)
	shown = testRepoItemShown(t, fresh, repoId)
	if shown == nil || shown.SignerSidecarId != f.sidecarId || shown.Announcement.GetVersion() != 2 {
		t.Errorf("the re-signed item: %v", shown)
	}
}
