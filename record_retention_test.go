//go:build !sidecar_http && !ios_extension

// record_retention.go on sidecartest's streams and authorization state: RECORD.md section 20's retention cases.
// Expiry across a fake-clock year, by push time, a writer's time_millis neither extending nor shortening a life, with
// class 7 surviving every pass and BASE; a policy from a non-admin ignored; two admins' policies a year apart
// resolving to the later whatever their ids; keep_days 0 accepted on the team record and 364 refused, and an entry
// below the floor ignored with one alarm; an archiving policy keeping the key and hiding the entry; searchable_days
// read by a query mask; the daily pass once a UTC day after its delay, across a restart; the weekly BASE naming only
// entries whose erasure is complete; and a set refused under a harness, or unconfirmed where it shortens a life.
// External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const testRetentionDay = 24 * time.Hour

// A device's randomness with every 8-byte draw, which only the expiry delay makes, answered as delay.
type testRetentionRandom struct {
	delay time.Duration
}

func (self *testRetentionRandom) Read(buffer []byte) (int, error) {
	if len(buffer) == 8 {
		binary.BigEndian.PutUint64(buffer, uint64(self.delay))
		return 8, nil
	}
	return rand.Read(buffer)
}

// A retention entry of the device's hand chain: a policy the device signed, sealed as its next entry of logId.
func testRetentionHandSeal(t *testing.T, device *testRecordDevice, hand *testRecordHandChain, logId sidecar.Id, policy *protocol.RetentionPolicy) *sidecar.RecordSealedEntry {
	t.Helper()
	policyBytes, err := proto.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := device.sign(sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RETENTION_POLICY, policyBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sidecar.RecordSeal(hand.env, &sidecar.RecordSealArgs{
		LogId:         logId,
		Kind:          sidecar.RecordKindRetention,
		Source:        sidecar.RecordSourceApprover,
		TimeMillis:    device.world.clock.Now().UnixMilli(),
		PolicyVersion: device.world.auth.Tip().Pin().GetVersion(),
		Body:          signed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// Pushes hand-sealed entries to the device's own stream of logId as one push.
func testRetentionPushHand(t *testing.T, device *testRecordDevice, logId sidecar.Id, counters []uint64, entries []*sidecar.RecordSealedEntry) {
	t.Helper()
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewId(),
		WriterSidecarId: device.sidecarId,
		SlotId:          sidecar.NewId(),
		AuthPin:         device.world.auth.Tip().Pin(),
	}
	for index, sealed := range entries {
		path, err := sidecar.RecordStreamPath(counters[index])
		if err != nil {
			t.Fatal(err)
		}
		push.SlotRows = append(push.SlotRows, sealed.SlotRow(uint32(index)))
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: sealed.EntryBytes(&push.SlotId, uint32(index))})
	}
	if _, err := device.world.streams.For(device.sidecarId).Append(t.Context(), logId, push); err != nil {
		t.Fatal(err)
	}
}

// The log's entries as the record's own reader holds them after a sync, by entry id.
func testRetentionEntries(t *testing.T, record *sidecar.SidecarRecord, logId sidecar.Id) map[sidecar.Id]*sidecar.RecordReadEntry {
	t.Helper()
	if err := record.Reader().Sync(t.Context(), logId); err != nil {
		t.Fatal(err)
	}
	entries := map[sidecar.Id]*sidecar.RecordReadEntry{}
	for _, entry := range record.Reader().Entries(logId) {
		entries[entry.EntryId] = entry
	}
	return entries
}

// Sets a policy, which must take, and lands it.
func testRetentionSet(t *testing.T, record *sidecar.SidecarRecord, args *sidecar.RecordRetentionSetArgs) *sidecar.RecordEntryRef {
	t.Helper()
	ref, err := record.Retention().Set(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return ref
}

// An admin's device of the team record: adminDevice with the repo admin right.
func (self *testTeamWorld) retentionAdmin() *testRecordDevice {
	self.t.Helper()
	device := self.adminDevice()
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Admins = append(repo.Admins, device.sidecarId)
	self.publish()
	return device
}

// Expiry across a fake-clock year in a vault whose owner set 30 days for coordination: a pass erases the notes past
// 30 days by their push time and leaves the younger; an entry whose writer asserted a time_millis a year ahead
// expires with its push, and one asserted a year back does not go early; the retention entry, class 7, and the
// erasure entries, a class with no policy, stand through every pass with their bodies; each pass writes one erasure
// entry of reason 2; and another reader of the vault shows the same entries expired.
func TestRecordRetentionExpiresByPushTimeAcrossAYear(t *testing.T) {
	world := newTestRecordWorld(t)
	device, _ := world.eraserDevice()
	other := world.device(true)
	record := device.open()
	retention := record.Retention()

	policyRef := testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 30, Confirmed: true,
	})
	early := []sidecar.Id{}
	for _, text := range []string{"early one", "early two"} {
		early = append(early, testRecordAppend(t, record, testRecordNote(nil, text)).EntryId)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	// another device's entries, their time_millis a year ahead and a year back of their push
	hand := other.handChain()
	asserted := []*sidecar.RecordSealedEntry{}
	for _, offset := range []time.Duration{365 * testRetentionDay, -365 * testRetentionDay} {
		sealed, err := sidecar.RecordSeal(hand.env, &sidecar.RecordSealArgs{
			LogId: world.vaultId, Kind: sidecar.RecordKindNote, Source: sidecar.RecordSourceAgent,
			TimeMillis: world.clock.Now().Add(offset).UnixMilli(), Tainted: true,
			PolicyVersion: world.auth.Tip().Pin().GetVersion(), Body: &protocol.CoordinationBody{Text: "asserted"},
		})
		if err != nil {
			t.Fatal(err)
		}
		asserted = append(asserted, sealed)
	}
	testRetentionPushHand(t, other, world.vaultId, []uint64{1, 2}, asserted)

	world.clock.Advance(20 * testRetentionDay)
	late := testRecordAppend(t, record, testRecordNote(nil, "late")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pass, err := retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId})
	if err != nil || len(pass.Expired) != 0 || len(pass.Erasures) != 0 {
		t.Fatalf("a pass at 20 days: %+v, %v", pass, err)
	}

	world.clock.Advance(11 * testRetentionDay)
	pass, err = retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId})
	if err != nil {
		t.Fatal(err)
	}
	wantExpired := append(slices.Clone(early), asserted[0].EntryId, asserted[1].EntryId)
	slices.SortFunc(wantExpired, sidecar.Id.Cmp)
	gotExpired := slices.Clone(pass.Expired)
	slices.SortFunc(gotExpired, sidecar.Id.Cmp)
	if !slices.Equal(gotExpired, wantExpired) || len(pass.Erasures) != 1 {
		t.Fatalf("the pass at 31 days expired %v in %d erasures, want %v", gotExpired, len(pass.Erasures), wantExpired)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries := testRetentionEntries(t, record, world.vaultId)
	for _, entryId := range wantExpired {
		if entry := entries[entryId]; entry.State != sidecar.RecordEntryExpired || entry.Body != nil {
			t.Errorf("entry %s reads %s", entryId, entry.State)
		}
	}
	if entry := entries[late]; entry.State != sidecar.RecordEntryLive || entry.Body == nil {
		t.Errorf("the 11-day-old note reads %s", entry.State)
	}
	if entry := entries[policyRef.EntryId]; entry.State != sidecar.RecordEntryLive || entry.Body == nil {
		t.Errorf("the retention entry reads %s", entry.State)
	}
	erasures := 0
	for _, entry := range entries {
		if entry.Kind() != sidecar.RecordKindErasure {
			continue
		}
		erasures += 1
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil || body.GetReason() != uint32(sidecar.RecordErasureReasonRetention) ||
			sidecar.RecordSource(entry.Header.Header.GetSource()) != sidecar.RecordSourceObserved || len(body.GetEntryIds()) != 4 {
			t.Errorf("the erasure entry: %v, %v", body, err)
		}
	}
	if erasures != 1 {
		t.Errorf("%d erasure entries after one batch", erasures)
	}
	// a second pass the same day finds nothing
	if pass, err := retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId}); err != nil || len(pass.Erasures) != 0 {
		t.Errorf("a second pass: %+v, %v", pass, err)
	}

	// a year on: the late note is gone too, and class 7 and the erasure entries still stand
	world.clock.Advance(365 * testRetentionDay)
	pass, err = retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId})
	if err != nil || !slices.Equal(pass.Expired, []sidecar.Id{late}) {
		t.Fatalf("the pass a year on: %+v, %v", pass, err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries = testRetentionEntries(t, record, world.vaultId)
	for _, entry := range entries {
		switch entry.Kind() {
		case sidecar.RecordKindRetention, sidecar.RecordKindErasure:
			if entry.State != sidecar.RecordEntryLive || entry.Body == nil {
				t.Errorf("a %s entry reads %s after a year", entry.Kind(), entry.State)
			}
		case sidecar.RecordKindNote:
			if entry.State != sidecar.RecordEntryExpired {
				t.Errorf("a note reads %s after a year", entry.State)
			}
		}
	}
	if reasons := device.alarmReasons(); len(reasons) != 0 {
		t.Errorf("the passes raised %v", reasons)
	}

	// another reader shows the same
	reader := world.newReader(nil, nil)
	for _, entry := range reader.sync(t, world) {
		if entry.Kind() == sidecar.RecordKindNote && (entry.State != sidecar.RecordEntryExpired || entry.Body != nil) {
			t.Errorf("another reader shows a note %s", entry.State)
		}
		if entry.Kind() == sidecar.RecordKindRetention && entry.Body == nil {
			t.Error("another reader lost the retention entry")
		}
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("another reader raised %v", reasons)
	}
}

// A retention entry from a writer that does not administer the log is ignored: the log's default stands, the entry is
// listed as not taken, and a pass expires nothing by it. A sidecar that is no admin runs no pass and sets no policy.
func TestRecordRetentionIgnoresAPolicyFromANonAdmin(t *testing.T) {
	world := newTestRecordWorld(t)
	admin, _ := world.eraserDevice()
	member := world.device(true)
	record := admin.open()
	note := testRecordAppend(t, record, testRecordNote(nil, "kept")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	hand := member.handChain()
	forged := testRetentionHandSeal(t, member, hand, world.vaultId, &protocol.RetentionPolicy{
		LogId: world.vaultId.Bytes(), Class: uint32(sidecar.RecordClassCoordination), KeepDays: 1,
	})
	testRetentionPushHand(t, member, world.vaultId, []uint64{1}, []*sidecar.RecordSealedEntry{forged})

	world.clock.Advance(10 * testRetentionDay)
	pass, err := record.Retention().Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId})
	if err != nil || len(pass.Expired) != 0 {
		t.Fatalf("a pass under a non-admin's policy: %+v, %v", pass, err)
	}
	policy := record.Retention().Policy(world.vaultId, sidecar.RecordClassCoordination)
	if policy == nil || !policy.Default || policy.KeepDays != 0 || policy.SearchableDays != 0 {
		t.Errorf("the vault's policy: %+v", policy)
	}
	entries := testRetentionEntries(t, record, world.vaultId)
	if entries[note].State != sidecar.RecordEntryLive {
		t.Errorf("the note reads %s", entries[note].State)
	}
	_, ignored := sidecar.RecordRetentionGoverning(world.auth.Tip(), world.vaultId, record.Reader().Entries(world.vaultId), nil, nil)
	if len(ignored) != 1 || ignored[0].EntryId != forged.EntryId || ignored[0].Floor {
		t.Errorf("the entries not taken: %+v", ignored)
	}

	memberRecord := member.open()
	if _, err := memberRecord.Retention().Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId}); !errors.Is(err, sidecar.ErrRecordEraseNotAdmin) {
		t.Errorf("a non-admin's pass: %v", err)
	}
	if _, err := memberRecord.Retention().Set(t.Context(), &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 0,
	}); !errors.Is(err, sidecar.ErrRecordEraseNotAdmin) {
		t.Errorf("a non-admin's set: %v", err)
	}
}

// The team record's defaults and floor: every class keeps 400 days, 90 searchable, until an admin sets one; a
// keep_days of 364 and a searchable_days of 89 are refused at the set, and 0 and 365 are taken; an entry below the
// floor that an admin wrote all the same is ignored by a reader, with one alarm however often it syncs.
func TestRecordRetentionTeamRecordFloor(t *testing.T) {
	world := newTestTeamWorld(t)
	admin := world.retentionAdmin()
	record := admin.open()
	retention := record.Retention()
	if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	policies := retention.Policies(world.teamRecordId)
	// classes 1 to 6, and 8, bulk (DESIGN-COMPUTE §24.10)
	if len(policies) != 7 {
		t.Fatalf("%d classes", len(policies))
	}
	for _, policy := range policies {
		if !policy.Default || policy.KeepDays != 400 || policy.SearchableDays != 90 || policy.Archive {
			t.Errorf("the team record's default for %s: %+v", policy.Class, policy)
		}
	}
	if retention.Policy(world.teamRecordId, sidecar.RecordClassLog) != nil {
		t.Error("class 7 has a policy")
	}
	for _, refused := range []*sidecar.RecordRetentionSetArgs{
		{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 364, Confirmed: true},
		{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 1, Confirmed: true},
		{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 400, SearchableDays: 89, Confirmed: true},
		{LogId: world.teamRecordId, Class: sidecar.RecordClassLog, KeepDays: 400, Confirmed: true},
		{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 365, SearchableDays: 366, Confirmed: true},
	} {
		if _, err := retention.Set(t.Context(), refused); !errors.Is(err, sidecar.ErrRecordRetentionInvalid) {
			t.Errorf("a set of %+v: %v", refused, err)
		}
	}
	testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 0})
	testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{
		LogId: world.teamRecordId, Class: sidecar.RecordClassCapture, KeepDays: 365, SearchableDays: 90, Confirmed: true,
	})
	if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	if policy := retention.Policy(world.teamRecordId, sidecar.RecordClassAction); policy.Default || policy.KeepDays != 0 || policy.SearchableDays != 0 {
		t.Errorf("keep_days 0 on the team record: %+v", policy)
	}
	if policy := retention.Policy(world.teamRecordId, sidecar.RecordClassCapture); policy.Default || policy.KeepDays != 365 || policy.SearchableDays != 90 {
		t.Errorf("keep_days 365 on the team record: %+v", policy)
	}

	// another admin writes 364 days by hand: every reader ignores it and alarms once
	second := world.retentionAdmin()
	hand := second.handChain()
	low := testRetentionHandSeal(t, second, hand, world.teamRecordId, &protocol.RetentionPolicy{
		LogId: world.teamRecordId.Bytes(), Class: uint32(sidecar.RecordClassRequest), KeepDays: 364,
	})
	testRetentionPushHand(t, second, world.teamRecordId, []uint64{1}, []*sidecar.RecordSealedEntry{low})
	for range 3 {
		if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
			t.Fatal(err)
		}
		if policy := retention.Policy(world.teamRecordId, sidecar.RecordClassRequest); !policy.Default || policy.KeepDays != 400 {
			t.Errorf("a class under an entry below the floor: %+v", policy)
		}
	}
	if reasons := admin.alarmReasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("an entry below the floor raised %v", reasons)
	}
	_, ignored := sidecar.RecordRetentionGoverning(world.auth.Tip(), world.teamRecordId, record.Reader().Entries(world.teamRecordId), nil, nil)
	if len(ignored) != 1 || ignored[0].EntryId != low.EntryId || !ignored[0].Floor {
		t.Errorf("the entries not taken: %+v", ignored)
	}
}

// Two admins' policies for one class a year apart resolve to the later, whichever admin's id is higher, and an
// admin's own newer entry replaces its older one.
func TestRecordRetentionLaterPolicyWinsWhateverTheIds(t *testing.T) {
	for _, laterIsHigher := range []bool{true, false} {
		world := newTestTeamWorld(t)
		admins := []*testRecordDevice{world.retentionAdmin(), world.retentionAdmin()}
		slices.SortFunc(admins, func(a *testRecordDevice, b *testRecordDevice) int { return a.sidecarId.Cmp(b.sidecarId) })
		first, later := admins[1], admins[0]
		if laterIsHigher {
			first, later = admins[0], admins[1]
		}
		firstRecord := first.open()
		testRetentionSet(t, firstRecord, &sidecar.RecordRetentionSetArgs{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 500})
		testRetentionSet(t, firstRecord, &sidecar.RecordRetentionSetArgs{LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 700})
		world.clock.Advance(365 * testRetentionDay)
		laterRecord := later.open()
		laterRef := testRetentionSet(t, laterRecord, &sidecar.RecordRetentionSetArgs{
			LogId: world.teamRecordId, Class: sidecar.RecordClassAction, KeepDays: 600, Confirmed: true,
		})
		for _, record := range []*sidecar.SidecarRecord{firstRecord, laterRecord} {
			if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
				t.Fatal(err)
			}
			policy := record.Retention().Policy(world.teamRecordId, sidecar.RecordClassAction)
			if policy.KeepDays != 600 || policy.EntryId != laterRef.EntryId || policy.WriterSidecarId != later.sidecarId {
				t.Errorf("with the later admin's id higher %t: %+v", laterIsHigher, policy)
			}
			// another class is untouched
			if policy := record.Retention().Policy(world.teamRecordId, sidecar.RecordClassCapture); !policy.Default {
				t.Errorf("another class: %+v", policy)
			}
		}
		// the first admin's 700 replaced its 500: without the later entry it would govern
		entries := []*sidecar.RecordReadEntry{}
		for _, entry := range firstRecord.Reader().Entries(world.teamRecordId) {
			if entry.EntryId != laterRef.EntryId {
				entries = append(entries, entry)
			}
		}
		policies, _ := sidecar.RecordRetentionGoverning(world.auth.Tip(), world.teamRecordId, entries, nil, nil)
		if policies[sidecar.RecordClassAction].KeepDays != 700 {
			t.Errorf("an admin's own newer entry: %+v", policies[sidecar.RecordClassAction])
		}
	}
}

// An archiving policy keeps the key: past keep_days an entry reads archived, with its body, on the admin's device
// and on every other reader's sync, a pass erases nothing, and a policy that stops archiving expires it at the next.
func TestRecordRetentionArchiveKeepsTheKey(t *testing.T) {
	world := newTestRecordWorld(t)
	device, _ := world.eraserDevice()
	record := device.open()
	retention := record.Retention()
	testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 30, Archive: true, Confirmed: true,
	})
	old := testRecordAppend(t, record, testRecordNote(nil, "old")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(31 * testRetentionDay)
	fresh := testRecordAppend(t, record, testRecordNote(nil, "fresh")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pass, err := retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId})
	if err != nil || len(pass.Expired) != 0 || !slices.Equal(pass.Archived, []sidecar.Id{old}) {
		t.Fatalf("a pass under an archiving policy: %+v, %v", pass, err)
	}
	entries := testRetentionEntries(t, record, world.vaultId)
	if entry := entries[old]; entry.State != sidecar.RecordEntryArchived || entry.Body == nil {
		t.Errorf("the old note reads %s", entry.State)
	}
	if entry := entries[fresh]; entry.State != sidecar.RecordEntryLive {
		t.Errorf("the fresh note reads %s", entry.State)
	}
	// a reader that runs no pass marks it at its sync
	other := world.device(true)
	otherRecord := other.open()
	otherRecord.Retention()
	if entry := testRetentionEntries(t, otherRecord, world.vaultId)[old]; entry.State != sidecar.RecordEntryArchived || entry.Body == nil {
		t.Errorf("another reader shows the old note %s", entry.State)
	}

	// the policy stops archiving: unconfirmed it is refused, since it would erase; confirmed, the next pass expires
	stop := &sidecar.RecordRetentionSetArgs{LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 30}
	if _, err := retention.Set(t.Context(), stop); !errors.Is(err, sidecar.ErrRecordRetentionUnconfirmed) {
		t.Fatalf("an unconfirmed end of archiving: %v", err)
	}
	stop.Confirmed = true
	testRetentionSet(t, record, stop)
	pass, err = retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId})
	if err != nil || !slices.Equal(pass.Expired, []sidecar.Id{old}) || len(pass.Archived) != 0 {
		t.Fatalf("the pass after archiving ended: %+v, %v", pass, err)
	}
	if entry := testRetentionEntries(t, record, world.vaultId)[old]; entry.State != sidecar.RecordEntryExpired || entry.Body != nil {
		t.Errorf("the old note reads %s", entry.State)
	}
}

// searchable_days as a query mask reads it: an entry past it is masked from search and stays readable by id, one
// within it is not masked, 0 masks nothing, and class 7 is never masked.
func TestRecordRetentionSearchableDaysMask(t *testing.T) {
	world := newTestRecordWorld(t)
	device, _ := world.eraserDevice()
	record := device.open()
	retention := record.Retention()
	if days := retention.SearchableDays(world.vaultId, sidecar.RecordClassCoordination); days != 0 {
		t.Fatalf("a vault's default searchable_days %d", days)
	}
	policyRef := testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 400, SearchableDays: 90, Confirmed: true,
	})
	old := testRecordAppend(t, record, testRecordNote(nil, "old")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(91 * testRetentionDay)
	fresh := testRecordAppend(t, record, testRecordNote(nil, "fresh")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries := testRetentionEntries(t, record, world.vaultId)
	if days := retention.SearchableDays(world.vaultId, sidecar.RecordClassCoordination); days != 90 {
		t.Fatalf("searchable_days %d", days)
	}
	// a fixture query mask: what search shows of the log
	shown := []sidecar.Id{}
	for _, entry := range entries {
		if entry.Kind() == sidecar.RecordKindNote && !retention.SearchMasked(entry) {
			shown = append(shown, entry.EntryId)
		}
	}
	if !slices.Equal(shown, []sidecar.Id{fresh}) {
		t.Errorf("search shows %v", shown)
	}
	if entry, ok := record.Reader().Entry(world.vaultId, old); !ok || entry.State != sidecar.RecordEntryLive || entry.Body == nil {
		t.Error("a masked entry is not readable by id")
	}
	if retention.SearchMasked(entries[policyRef.EntryId]) {
		t.Error("a class 7 entry is masked")
	}
}

// The loop's pass runs a log's expiry once a UTC day, ExpiryDelay's draw after it first syncs the day's work, and not
// again that day, on this process or the next; the following day it runs again.
func TestRecordRetentionDailyPassWaitsItsDelay(t *testing.T) {
	world := newTestRecordWorld(t)
	device, _ := world.eraserDevice()
	device.random = &testRetentionRandom{delay: 4 * time.Minute}
	record := device.open()
	retention := record.Retention()
	testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 1, Confirmed: true,
	})
	first := testRecordAppend(t, record, testRecordNote(nil, "first")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(testRetentionDay)
	state := func(entryId sidecar.Id) sidecar.RecordEntryState {
		t.Helper()
		return testRetentionEntries(t, record, world.vaultId)[entryId].State
	}
	retention.Tick(t.Context())
	if state(first) != sidecar.RecordEntryLive {
		t.Fatal("the pass ran before its delay")
	}
	world.clock.Advance(4*time.Minute - time.Second)
	retention.Tick(t.Context())
	if state(first) != sidecar.RecordEntryLive {
		t.Fatal("the pass ran a second before its delay")
	}
	world.clock.Advance(time.Second)
	retention.Tick(t.Context())
	if state(first) != sidecar.RecordEntryExpired {
		t.Fatalf("the pass did not run at its delay: %s", state(first))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	// later the same UTC day a note comes due: no second pass, on this process or after a restart
	day := world.clock.Now().UTC().Format(time.DateOnly)
	second := testRecordAppend(t, record, testRecordNote(nil, "second")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	midnight := world.clock.Now().UTC().Truncate(testRetentionDay).Add(testRetentionDay)
	world.clock.AdvanceTo(midnight.Add(-time.Minute))
	if world.clock.Now().UTC().Format(time.DateOnly) != day {
		t.Fatal("the test's clock left the day")
	}
	retention.Tick(t.Context())
	record = device.open()
	retention = record.Retention()
	retention.Tick(t.Context())
	world.clock.Advance(10 * time.Minute)
	if world.clock.Now().UTC().Format(time.DateOnly) == day {
		t.Fatal("the test's clock did not reach the next day")
	}
	if state(second) != sidecar.RecordEntryLive {
		t.Fatal("a second pass ran the same day")
	}
	// the next day's first tick draws the delay again, from where it first synced the work
	retention.Tick(t.Context())
	if state(second) != sidecar.RecordEntryLive {
		t.Fatal("the next day's pass ran before its delay")
	}
	world.clock.Advance(testRetentionDay)
	retention.Tick(t.Context())
	if state(second) != sidecar.RecordEntryExpired {
		t.Fatalf("the next day's pass did not run: %s", state(second))
	}
}

// A BASE's calls, as a test keeps them.
type testRetentionBase struct {
	stateLock sync.Mutex
	logIds    []sidecar.Id
	streamIds []sidecar.Id
	paths     [][]string
	err       error
}

func (self *testRetentionBase) base(ctx context.Context, logId sidecar.Id, streamSidecarId sidecar.Id, paths []string) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return 0, self.err
	}
	self.logIds = append(self.logIds, logId)
	self.streamIds = append(self.streamIds, streamSidecarId)
	self.paths = append(self.paths, slices.Clone(paths))
	return len(paths), nil
}

// The weekly BASE names, a stream at a time, the files of entries whose erasure is complete and nothing else: an
// expired entry's and a person's erasure's, never a live entry's and never a class 7 entry's; unbound, nothing is
// removed; and the loop runs it BaseInterval after the last.
func TestRecordRetentionBaseNamesOnlyCompleteErasures(t *testing.T) {
	world := newTestRecordWorld(t)
	device, _ := world.eraserDevice()
	device.settings.ExpiryDelay = 0
	record := device.open()
	retention := record.Retention()
	if _, err := retention.Base(t.Context(), world.vaultId); !errors.Is(err, sidecar.ErrRecordRetentionBaseUnbound) {
		t.Fatalf("an unbound BASE: %v", err)
	}
	testRetentionSet(t, record, &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCoordination, KeepDays: 30, Confirmed: true,
	})
	old := testRecordAppend(t, record, testRecordNote(nil, "old")).EntryId
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(31 * testRetentionDay)
	erased := testRecordAppend(t, record, testRecordNote(nil, "a person erases this")).EntryId
	testRecordAppend(t, record, testRecordNote(nil, "live"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Eraser().Erase(t.Context(), &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{erased}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := retention.Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.vaultId}); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries := testRetentionEntries(t, record, world.vaultId)
	wantPaths := []string{}
	for _, entryId := range []sidecar.Id{old, erased} {
		for _, entryCopy := range entries[entryId].Copies {
			wantPaths = append(wantPaths, entryCopy.Path)
		}
	}
	slices.Sort(wantPaths)

	base := &testRetentionBase{}
	retention.SetBase(base.base)
	removed, err := retention.Base(t.Context(), world.vaultId)
	if err != nil || removed != 2 {
		t.Fatalf("the BASE removed %d: %v", removed, err)
	}
	if len(base.paths) != 1 || base.logIds[0] != world.vaultId || base.streamIds[0] != device.sidecarId || !slices.Equal(base.paths[0], wantPaths) {
		t.Errorf("the BASE named %v of streams %v, want %v", base.paths, base.streamIds, wantPaths)
	}
	for _, entry := range entries {
		if entry.Kind().Class() != sidecar.RecordClassLog {
			continue
		}
		for _, entryCopy := range entry.Copies {
			if slices.Contains(base.paths[0], entryCopy.Path) {
				t.Errorf("the BASE named a class 7 entry's file %s", entryCopy.Path)
			}
		}
	}

	// the loop: the day's pass, then a BASE once BaseInterval has run since the last
	world.clock.Advance(testRetentionDay)
	retention.Tick(t.Context())
	if len(base.paths) != 2 {
		t.Fatalf("%d BASEs after the first tick", len(base.paths))
	}
	world.clock.Advance(testRetentionDay)
	retention.Tick(t.Context())
	if len(base.paths) != 2 {
		t.Fatalf("%d BASEs a day after the last", len(base.paths))
	}
	world.clock.Advance(device.settings.BaseInterval)
	retention.Tick(t.Context())
	if len(base.paths) != 3 {
		t.Fatalf("%d BASEs a week after the last", len(base.paths))
	}
	// a BASE that fails is tried again at the next tick
	base.err = io.ErrUnexpectedEOF
	world.clock.Advance(device.settings.BaseInterval)
	retention.Tick(t.Context())
	base.err = nil
	retention.Tick(t.Context())
	if len(base.paths) != 4 {
		t.Fatalf("%d BASEs after a failed one was tried again", len(base.paths))
	}
}

// A policy is a person's act: under a harness process it is refused, confirmed or not; one that shortens a class's
// life is refused unconfirmed, with nothing signed; one that lengthens it needs no confirmation.
func TestRecordRetentionSetIsAPersonsAct(t *testing.T) {
	world := newTestRecordWorld(t)
	device, _ := world.eraserDevice()
	record := device.open()
	retention := record.Retention()
	shorten := &sidecar.RecordRetentionSetArgs{LogId: world.vaultId, Class: sidecar.RecordClassCapture, KeepDays: 90}
	if !retention.Shortens(shorten) {
		t.Fatal("90 days does not shorten a class kept with no limit")
	}
	if _, err := retention.Set(t.Context(), shorten); !errors.Is(err, sidecar.ErrRecordRetentionUnconfirmed) {
		t.Fatalf("an unconfirmed shortening: %v", err)
	}
	if _, err := retention.Set(t.Context(), &sidecar.RecordRetentionSetArgs{
		LogId: world.vaultId, Class: sidecar.RecordClassCapture, KeepDays: 90, Confirmed: true, HarnessAncestor: true,
	}); !errors.Is(err, sidecar.ErrRecordRetentionUnconfirmed) {
		t.Fatalf("a set under a harness: %v", err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stored := world.storedEntries(device.sidecarId); len(stored) != 0 {
		t.Fatalf("%d entries after refused sets", len(stored))
	}
	shorten.Confirmed = true
	ref := testRetentionSet(t, record, shorten)
	// the entry: kind retention, source approver, untainted, its body the Signed policy
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 1 || sidecar.RecordKind(stored[0].header.GetKind()) != sidecar.RecordKindRetention ||
		sidecar.RecordSource(stored[0].header.GetSource()) != sidecar.RecordSourceApprover || stored[0].header.GetTainted() ||
		!bytes.Equal(stored[0].header.GetEntryId(), ref.EntryId.Bytes()) {
		t.Fatalf("the retention entry: %v", stored[0].header)
	}
	signed := &bridge.Signed{}
	policy := &protocol.RetentionPolicy{}
	if err := proto.Unmarshal(stored[0].body, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_RETENTION_POLICY) ||
		proto.Unmarshal(signed.GetBody(), policy) != nil || policy.GetKeepDays() != 90 || !bytes.Equal(policy.GetLogId(), world.vaultId.Bytes()) {
		t.Errorf("the entry's policy: %v", policy)
	}
	if err := bridge.VerifySigned(signed, sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RETENTION_POLICY, bridge.SignedKeyAlgEd25519, device.key.Public().(ed25519.PublicKey)); err != nil {
		t.Errorf("the policy's signature: %v", err)
	}
	// lengthening, and ending expiry, need no confirmation
	if err := record.Reader().Sync(t.Context(), world.vaultId); err != nil {
		t.Fatal(err)
	}
	for _, days := range []uint32{120, 0} {
		longer := &sidecar.RecordRetentionSetArgs{LogId: world.vaultId, Class: sidecar.RecordClassCapture, KeepDays: days}
		if retention.Shortens(longer) {
			t.Errorf("%d days shortens 90", days)
		}
		testRetentionSet(t, record, longer)
		if err := record.Reader().Sync(t.Context(), world.vaultId); err != nil {
			t.Fatal(err)
		}
	}
	if policy := retention.Policy(world.vaultId, sidecar.RecordClassCapture); policy.KeepDays != 0 || policy.Default {
		t.Errorf("the class's policy: %+v", policy)
	}
}
