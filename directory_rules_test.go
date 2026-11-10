//go:build !sidecar_http

// RECORD-M6-14's card rules on M6's announce entries, FS-84's entry cases on sidecartest's fakes: a run version signed
// or pushed by another sidecar, by a parked, revoked, reaped or suspended one, with a seq not above the last or a pin
// out of range, each ignored with an alarm while the honest item beside it shows; a revocation since masking an item
// with no alarm; and expiry under ±60 s of skew, stale for 24 h and never active past expires_millis (FI-25).

package sidecar_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FS-84's entry cases: each breaching version is ignored by every reader and alarms with the reason the card rule
// names, its signer named, while the honest writer's item beside it shows.
func TestDirectoryCardRulesIgnoreAndAlarmFs84Versions(t *testing.T) {
	type breach func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm
	// a standing at the pin the version is pushed at, lifted after where lift is set
	atStanding := func(set func(admission *sidecartest.FakeDirectorySidecar, next uint64), lift func(admission *sidecartest.FakeDirectorySidecar), alarm sidecar.SidecarRecordAlarm) breach {
		return func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm {
			admission := world.directoryFixture.Sidecars[bad.sidecarId]
			set(admission, world.directoryAuth.Tip().Pin().GetVersion()+1)
			world.publish()
			bad.announce(item)
			if lift != nil {
				lift(admission)
				world.publish()
			}
			return alarm
		}
	}
	cases := []struct {
		name   string
		breach breach
	}{
		{name: "signed by another sidecar", breach: func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm {
			// the item names the honest writer, the bad one signs it
			item.Who.SidecarId = honest.sidecarId.Bytes()
			item.Who.MemberId = world.directoryFixture.Sidecars[honest.sidecarId].MemberId.Bytes()
			bad.announce(item)
			return sidecar.SidecarRecordAlarmBadEntry
		}},
		{name: "pushed by another sidecar", breach: func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm {
			// signed by the bad writer, carried only in the honest writer's stream
			bad.announceIn(item, honest, nil)
			return sidecar.SidecarRecordAlarmPathRule
		}},
		{name: "parked for consent", breach: atStanding(func(admission *sidecartest.FakeDirectorySidecar, next uint64) {
			admission.Standing = sidecar.DirectoryStandingUnconsented
		}, nil, sidecar.SidecarRecordAlarmParkedWriter)},
		{name: "parked by a cascade", breach: atStanding(func(admission *sidecartest.FakeDirectorySidecar, next uint64) {
			admission.Standing = sidecar.DirectoryStandingParked
		}, nil, sidecar.SidecarRecordAlarmBadEntry)},
		{name: "revoked", breach: atStanding(func(admission *sidecartest.FakeDirectorySidecar, next uint64) {
			admission.RevokedAt = next
		}, nil, sidecar.SidecarRecordAlarmBadEntry)},
		// a reap revokes the row, which the rows do not tell from a revocation (RECORD-M6-12)
		{name: "reaped", breach: atStanding(func(admission *sidecartest.FakeDirectorySidecar, next uint64) {
			admission.RevokedAt = next
			admission.Ephemeral = true
		}, nil, sidecar.SidecarRecordAlarmBadEntry)},
		// suspended at the pin and lifted since: judged where it wrote
		{name: "suspended", breach: atStanding(func(admission *sidecartest.FakeDirectorySidecar, next uint64) {
			admission.SuspendedAt = next
		}, func(admission *sidecartest.FakeDirectorySidecar) {
			admission.SuspendedAt = 0
		}, sidecar.SidecarRecordAlarmBadEntry)},
		{name: "a pin out of range", breach: func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm {
			old := world.recordAuth.Tip().Pin()
			world.advance(sidecar.DirectoryPinPositionCount+1, time.Millisecond)
			// renewed now, and so live by its times, at a pin past the bound
			item.RenewedMillis = world.clock.Now().UnixMilli()
			item.StartedMillis = item.RenewedMillis
			item.ExpiresMillis, _ = sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, item.RenewedMillis)
			bad.announceIn(item, nil, old)
			return sidecar.SidecarRecordAlarmBadEntry
		}},
		{name: "renewed past its push by more than the skew", breach: func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm {
			item.RenewedMillis = world.clock.Now().UnixMilli() + sidecar.DirectoryClockSkew.Milliseconds() + 1
			item.ExpiresMillis, _ = sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, item.RenewedMillis)
			bad.announce(item)
			return sidecar.SidecarRecordAlarmBadEntry
		}},
		{name: "naming another member", breach: func(world *testDirectoryWorld, bad *testDirectoryWriter, honest *testDirectoryWriter, item *protocol.Announcement) sidecar.SidecarRecordAlarm {
			item.Who.MemberId = world.directoryFixture.Sidecars[honest.sidecarId].MemberId.Bytes()
			bad.announce(item)
			return sidecar.SidecarRecordAlarmBadEntry
		}},
	}
	for _, c := range cases {
		world := newTestDirectoryWorld(t, nil)
		honestMember, badMember := sidecar.NewId(), sidecar.NewId()
		honest := world.memberWriter(honestMember)
		bad := world.memberWriter(badMember)
		world.publish()
		item := testRunItem(bad.sidecarId, &badMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())
		alarm := c.breach(world, bad, honest, item)
		honest.announce(testRunItem(honest.sidecarId, &honestMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli()))

		reader := world.reader(nil)
		reader.mustSync(t)
		items := reader.items(t)
		for _, shown := range items {
			if shown.SignerSidecarId == bad.sidecarId {
				t.Errorf("%s: the breaching version shows, %s", c.name, shown.Display)
			}
			if shown.SignerSidecarId != honest.sidecarId {
				t.Errorf("%s: an item signed by %s", c.name, shown.SignerSidecarId)
			}
		}
		if len(items) == 0 {
			t.Errorf("%s: the honest item does not show", c.name)
		}
		if reader.alarmsNaming(alarm, bad.sidecarId) != 1 {
			t.Errorf("%s: alarms %v, want one %s naming the signer", c.name, reader.alarmReasons(), alarm)
		}
		if reader.alarmsNaming(alarm, honest.sidecarId) != 0 {
			t.Errorf("%s: an alarm names the honest writer", c.name)
		}
		// a later view raises nothing again
		reader.items(t)
		if reader.alarmsNaming(alarm, bad.sidecarId) != 1 {
			t.Errorf("%s: the alarm raised again", c.name)
		}
	}
}

// A version whose seq is not above its writer's last is a fork of its chain: the record reader keeps it forked and
// alarms chain_fork, and the fold never counts it, the version before standing.
func TestDirectoryCardRulesIgnoreAForkedVersion(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	runId := sidecar.NewId()
	writer.announce(testRunItem(writer.sidecarId, &memberId, runId, 1, world.clock.Now().UnixMilli()))
	// a second chain for the same writer and key seals its seq 1 again, at a higher version
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("fork", "record")
	if err != nil {
		t.Fatal(err)
	}
	forked := &testDirectoryWriter{world: world, sidecarId: writer.sidecarId, key: writer.key, counter: writer.counter}
	forked.env = &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, writer.sidecarId), Sign: forked.sign}
	world.clock.Advance(time.Minute)
	forked.announceIn(testRunItem(writer.sidecarId, &memberId, runId, 2, world.clock.Now().UnixMilli()), writer, nil)

	reader := world.reader(nil)
	reader.mustSync(t)
	item := testOnlyItemOf(t, reader.items(t), writer.sidecarId)
	if item.Announcement.GetVersion() != 1 {
		t.Errorf("the forked version 2 shows")
	}
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmChainFork, writer.sidecarId) == 0 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// A revocation after a version came in masks its item at once in every reader (§16.11's member and device rows), with
// no alarm: it broke no rule where it wrote.
func TestDirectoryCardRulesMaskARevokedWriterSilently(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	writer.announce(testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, world.clock.Now().UnixMilli()))
	writer.announce(testWorkerItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, world.clock.Now().UnixMilli()))
	reader := world.reader(nil)
	reader.mustSync(t)
	if len(reader.items(t)) != 2 {
		t.Fatal("the items before the revocation")
	}
	world.directoryFixture.Sidecars[writer.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	if items := reader.items(t); len(items) != 0 {
		t.Errorf("%d items of a revoked writer", len(items))
	}
	if len(reader.alarmReasons()) != 0 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// A tagged sidecar's run names its sponsor; once the sponsor is gone it names none and shows as autogroup:admin, and
// a version still naming the old sponsor is void (§16.11's who row).
func TestDirectoryCardRulesTaggedWho(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	sponsorId := sidecar.NewId()
	agent := world.writer()
	world.directoryFixture.Sidecars[agent.sidecarId] = &sidecartest.FakeDirectorySidecar{SponsorId: &sponsorId}
	world.publish()
	agent.announce(testRunItem(agent.sidecarId, &sponsorId, sidecar.NewId(), 1, world.clock.Now().UnixMilli()))
	reader := world.reader(nil)
	reader.mustSync(t)
	item := testOnlyItemOf(t, reader.items(t), agent.sidecarId)
	if item.MemberId == nil || *item.MemberId != sponsorId || item.MemberDevice || item.AutogroupAdmin {
		t.Errorf("a sponsored agent's who %v, member device %v", item.MemberId, item.MemberDevice)
	}

	world.directoryFixture.Sidecars[agent.sidecarId].SponsorId = nil
	world.publish()
	orphanRunId := sidecar.NewId()
	agent.announce(testRunItem(agent.sidecarId, nil, orphanRunId, 1, world.clock.Now().UnixMilli()))
	stale := testRunItem(agent.sidecarId, &sponsorId, sidecar.NewId(), 1, world.clock.Now().UnixMilli())
	agent.announce(stale)
	reader.mustSync(t)
	items := reader.items(t)
	if len(items) != 2 {
		t.Fatalf("%d items", len(items))
	}
	for _, shown := range items {
		if shown.MemberId != nil || !shown.AutogroupAdmin {
			t.Errorf("an orphan's item names %v", shown.MemberId)
		}
		if bytes.Equal(shown.Announcement.GetAnnouncementId(), stale.GetAnnouncementId()) {
			t.Error("a version naming a sponsor gone at its pin shows")
		}
	}
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, agent.sidecarId) != 1 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// Expiry under ±60 s of skew (FS-84, FI-25): a writer whose clock runs 60 s ahead or behind evs's is accepted, its item
// active until its expires_millis on the reader's clock and never after; one running further ahead is refused, so no
// clock keeps an item active past what evs's time bounds.
func TestDirectoryCardRulesExpiryUnderSkew(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	members := []sidecar.Id{sidecar.NewId(), sidecar.NewId(), sidecar.NewId()}
	ahead := world.memberWriter(members[0])
	behind := world.memberWriter(members[1])
	beyond := world.memberWriter(members[2])
	world.publish()
	pushMillis := world.clock.Now().UnixMilli()
	skew := sidecar.DirectoryClockSkew.Milliseconds()
	aheadItem := testRunItem(ahead.sidecarId, &members[0], sidecar.NewId(), 1, pushMillis+skew)
	behindItem := testRunItem(behind.sidecarId, &members[1], sidecar.NewId(), 1, pushMillis-skew)
	ahead.announce(aheadItem)
	behind.announce(behindItem)
	beyond.announce(testRunItem(beyond.sidecarId, &members[2], sidecar.NewId(), 1, pushMillis+skew+1))
	reader := world.reader(nil)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, beyond.sidecarId) != 1 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}

	displays := func() map[sidecar.Id]sidecar.DirectoryItemDisplay {
		t.Helper()
		shown := map[sidecar.Id]sidecar.DirectoryItemDisplay{}
		for _, item := range reader.items(t) {
			shown[item.SignerSidecarId] = item.Display
		}
		return shown
	}
	if shown := displays(); len(shown) != 2 || shown[ahead.sidecarId] != sidecar.DirectoryItemActive || shown[behind.sidecarId] != sidecar.DirectoryItemActive {
		t.Fatalf("shown %v", shown)
	}
	for _, item := range []*protocol.Announcement{behindItem, aheadItem} {
		writerId := sidecar.Id(item.GetWho().GetSidecarId())
		world.clock.AdvanceTo(time.UnixMilli(item.GetExpiresMillis() - 1))
		if shown := displays(); shown[writerId] != sidecar.DirectoryItemActive {
			t.Errorf("a millisecond before its expiry: %s", shown[writerId])
		}
		world.clock.AdvanceTo(time.UnixMilli(item.GetExpiresMillis()))
		if shown := displays(); shown[writerId] != sidecar.DirectoryItemStale {
			t.Errorf("at its expiry: %s", shown[writerId])
		}
	}
}

// An expired run or worker item shows stale for 24 h and never active, then not at all; an ended one shows for 24 h
// from its end (§16.11's expire and end rows).
func TestDirectoryCardRulesStaleAndEndedForADay(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	nowMillis := world.clock.Now().UnixMilli()
	run := testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, nowMillis)
	worker := testWorkerItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, nowMillis)
	ended := testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 2, nowMillis)
	ended.State = uint32(sidecar.DirectoryAnnouncementStateEnded)
	for _, item := range []*protocol.Announcement{run, worker, ended} {
		writer.announce(item)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	displayOf := func(item *protocol.Announcement) sidecar.DirectoryItemDisplay {
		t.Helper()
		for _, shown := range reader.items(t) {
			if bytes.Equal(shown.Announcement.GetAnnouncementId(), item.GetAnnouncementId()) {
				return shown.Display
			}
		}
		return ""
	}
	checks := []struct {
		at   int64
		item *protocol.Announcement
		want sidecar.DirectoryItemDisplay
	}{
		{at: run.GetExpiresMillis() - 1, item: run, want: sidecar.DirectoryItemActive},
		{at: run.GetExpiresMillis(), item: run, want: sidecar.DirectoryItemStale},
		{at: nowMillis + sidecar.DirectoryEndedKeepTime.Milliseconds() - 1, item: ended, want: sidecar.DirectoryItemEnded},
		{at: run.GetExpiresMillis() + sidecar.DirectoryStaleShowTime.Milliseconds() - 1, item: run, want: sidecar.DirectoryItemStale},
		{at: run.GetExpiresMillis() + sidecar.DirectoryStaleShowTime.Milliseconds() - 1, item: worker, want: sidecar.DirectoryItemActive},
		{at: run.GetExpiresMillis() + sidecar.DirectoryStaleShowTime.Milliseconds(), item: run, want: ""},
		{at: run.GetExpiresMillis() + sidecar.DirectoryStaleShowTime.Milliseconds(), item: ended, want: ""},
		{at: worker.GetExpiresMillis(), item: worker, want: sidecar.DirectoryItemStale},
		{at: worker.GetExpiresMillis() + sidecar.DirectoryStaleShowTime.Milliseconds(), item: worker, want: ""},
	}
	for _, check := range checks {
		world.clock.AdvanceTo(time.UnixMilli(check.at))
		if display := displayOf(check.item); display != check.want {
			t.Errorf("at %d: %q, want %q", check.at, display, check.want)
		}
	}
}
