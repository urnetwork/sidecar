//go:build !sidecar_http

// RECORD-M6-15's repo items on sidecartest's fakes: FS-101's M6 cases on the fake clock, FS-84's repo clauses, the
// private marker padded as an announcement is, and the writer's defaults, refusals and upkeep, a device writing
// through its own SidecarRecord and DirectoryClient as the daemon composes them.

package sidecar_test

import (
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A repo of kind in the next position, its admins added there, created at that position.
func (self *testDirectoryWorld) createRepo(kind protocol.RepoKind, ownerMemberId *sidecar.Id, admins ...*testDirectoryWriter) sidecar.Id {
	repoId := sidecar.NewId()
	at := self.directoryAuth.Tip().Pin().GetVersion() + 1
	repo := &sidecartest.FakeDirectoryRepo{Kind: kind, OwnerMemberId: ownerMemberId}
	for _, admin := range admins {
		repo.Admins = append(repo.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: admin.sidecarId, At: at})
	}
	self.directoryFixture.Repos[repoId] = repo
	self.publish()
	return repoId
}

// A client of the world's for sidecarId, appending through writer, nil for none: a reader's, or a device's, knowing
// repos by repoName, nil for no names.
func (self *testDirectoryWorld) clientFor(sidecarId sidecar.Id, writer sidecar.RecordWriter, readOnly bool, repoName func(repoId sidecar.Id) string) *testDirectoryReader {
	self.t.Helper()
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("directory", "search")
	if err != nil {
		self.t.Fatal(err)
	}
	reader := &testDirectoryReader{files: files, store: store, synced: make(chan struct{}, 64)}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  sidecarId,
		Store:      store,
		Cards:      self.cards.For(sidecarId),
		Streams:    func() sidecar.RecordStreams { return self.streams.For(sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			reader.stateLock.Lock()
			defer reader.stateLock.Unlock()
			reader.alarms = append(reader.alarms, alarm)
		},
		Clock:    self.clock,
		Settings: sidecar.DefaultSidecarSettings().Directory,
		Writer:   writer,
		ReadOnly: readOnly,
		RepoName: repoName,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	reader.client = client
	return reader
}

// A device of the world's: its own record, whose writer pushes to its stream, and its directory client over it.
type testDirectoryDevice struct {
	writer *testDirectoryWriter
	record *sidecar.SidecarRecord
	*testDirectoryReader
}

// writer's device, knowing repos by repoName, nil for no names. Its entries go through its record alone, so its test
// chain stays unused.
func (self *testDirectoryWorld) device(writer *testDirectoryWriter, repoName func(repoId sidecar.Id) string) *testDirectoryDevice {
	self.t.Helper()
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("record", "record")
	if err != nil {
		self.t.Fatal(err)
	}
	record, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         writer.sidecarId,
		IdentityPublicKey: writer.key.Public().(ed25519.PublicKey),
		Store:             store,
		Sign:              writer.sign,
		Streams:           self.streams.For(writer.sidecarId),
		Auth:              func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Clock:             self.clock,
		Settings:          sidecar.DefaultSidecarSettings().Record,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return &testDirectoryDevice{writer: writer, record: record, testDirectoryReader: self.clientFor(writer.sidecarId, record.Writer(), false, repoName)}
}

// Pushes what the device's record holds.
func (self *testDirectoryDevice) flush(t *testing.T) {
	t.Helper()
	if err := self.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The item shown for repoId, private markers included, nil for none.
func testRepoItemShown(t *testing.T, reader *testDirectoryReader, repoId sidecar.Id) *sidecar.DirectoryItem {
	t.Helper()
	for _, item := range reader.items(t) {
		if item.Key.Kind == sidecar.DirectoryAnnouncementKindRepo && sidecar.Id(item.Announcement.GetWhere().GetRepoId()) == repoId {
			return item
		}
	}
	return nil
}

// FS-101's M6 case across the retention horizon: repo admin E announces P at n0; with §7.9's fold (1,024 entries or
// 24 h) and retention (30 days) the log runs 30 days and 10 folds past n0, so n0 and its chain value are no longer
// held; a fresh member device then accepts P's item, judging E's right from the access log's positions; P's item
// survives 4,096 positions of log growth, while a run item's card rule refuses a stale pin; and after E's RepoAdmin
// remove the item still stands.
func TestDirectoryRepoItemAcrossTheRetentionHorizon(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	eMember := sidecar.NewId()
	e := world.memberWriter(eMember)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e)
	n0 := world.directoryAuth.Tip().Pin().GetVersion()
	e.announce(testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "payroll exports", false))
	// a run announced at the same pin, live by its own times once the positions below pass
	runId := sidecar.NewId()
	e.announce(testRunItem(e.sidecarId, &eMember, runId, 1, world.clock.Now().UnixMilli()))
	world.advance(sidecar.DirectoryPinPositionCount+1, time.Millisecond)

	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Display != sidecar.DirectoryItemActive {
		t.Fatal("P's item past 4,096 positions")
	}
	for _, item := range reader.items(t) {
		if item.Key.AnnouncementId == runId {
			t.Error("a run item at a pin past 4,096 positions shows")
		}
	}

	for fold := 0; fold < 10; fold += 1 {
		world.advance(1, 3*24*time.Hour)
	}
	world.directoryAuth.RetainFrom(n0 + 1)
	world.recordAuth.RetainFrom(n0 + 1)
	fresh := world.reader(nil)
	fresh.mustSync(t)
	item := testRepoItemShown(t, fresh, repoId)
	if item == nil || item.SignerSidecarId != e.sidecarId || item.Announcement.GetWhat().GetTitle() != "payroll exports" {
		t.Fatalf("a fresh device past n0's retention: %v", item)
	}
	if fresh.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 0 {
		t.Errorf("alarms %v", fresh.alarmReasons())
	}

	// E's RepoAdmin remove: the version it wrote while it held the right stands
	world.directoryFixture.Repos[repoId].Admins = nil
	world.publish()
	fresh.mustSync(t)
	if item := testRepoItemShown(t, fresh, repoId); item == nil || item.SignerSidecarId != e.sidecarId {
		t.Error("a RepoAdmin remove voids a version standing at a reader that accepted it")
	}
	// a device that starts after the remove, past n0's retention, cannot tell E's right there from the head: it fails
	// closed until question acl-m2-06-access-log-positions gives removed admins' rows their positions
	later := world.reader(nil)
	later.mustSync(t)
	if testRepoItemShown(t, later, repoId) != nil {
		t.Error("a removed admin's right before retention judged from a head that no longer holds it")
	}
}

// FS-101's compromise and lost-revocation cases: after a compromise revocation of E from a since_n at or before n0 its
// version is void, alarming, and another admin's device of P writes it again at a higher version, from its attested
// fields alone; after E's lost revocation its version still stands, and that admin re-signs it whole.
func TestDirectoryRepoItemOfARevokedAdminIsResigned(t *testing.T) {
	for _, compromise := range []bool{true, false} {
		world := newTestDirectoryWorld(t, nil)
		eMember, fMember := sidecar.NewId(), sidecar.NewId()
		e := world.memberWriter(eMember)
		f := world.memberWriter(fMember)
		world.publish()
		repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e, f)
		n0 := world.directoryAuth.Tip().Pin().GetVersion()
		e.announce(testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "release notes", false))
		reader := world.reader(nil)
		reader.mustSync(t)
		if testRepoItemShown(t, reader, repoId) == nil {
			t.Fatal("P's item before the revocation")
		}
		// F's device read P's item before the revocation: a device that never held a version cannot tell an
		// announcement from a private marker, so it writes nothing for it
		fDevice := world.device(f, nil)
		fDevice.mustSync(t)

		admission := world.directoryFixture.Sidecars[e.sidecarId]
		admission.RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
		if compromise {
			admission.CompromisedSince = n0
			world.recordFixture.CompromisedSince = map[sidecar.Id]uint64{e.sidecarId: n0}
		}
		world.publish()
		reader.mustSync(t)
		shown := testRepoItemShown(t, reader, repoId)
		if compromise && (shown != nil || reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 1) {
			t.Errorf("a compromised signer's version: shown %v, alarms %v", shown != nil, reader.alarmReasons())
		}
		if !compromise && (shown == nil || shown.SignerSidecarId != e.sidecarId) {
			t.Error("a lost revocation voids its signer's version")
		}

		fDevice.mustSync(t)
		writes, err := fDevice.client.MaintainRepos(t.Context())
		if err != nil || len(writes) != 1 {
			t.Fatalf("compromise %v: %d writes, %v", compromise, len(writes), err)
		}
		// a second pass before the copy reads the write back writes nothing more
		if again, err := fDevice.client.MaintainRepos(t.Context()); err != nil || len(again) != 0 {
			t.Errorf("compromise %v: a second pass wrote %d: %v", compromise, len(again), err)
		}
		fDevice.flush(t)
		reader.mustSync(t)
		shown = testRepoItemShown(t, reader, repoId)
		if shown == nil || shown.SignerSidecarId != f.sidecarId || shown.Announcement.GetVersion() != 2 {
			t.Fatalf("compromise %v: the re-signed item %v", compromise, shown)
		}
		title := shown.Announcement.GetWhat().GetTitle()
		if (compromise && title != "") || (!compromise && title != "release notes") {
			t.Errorf("compromise %v: re-signed with the display name %q", compromise, title)
		}
		if !slices.Equal(shown.Announcement.GetWhat().GetRoles(), []uint32{2, 3}) || shown.Announcement.GetWhat().GetRequests() != 1 {
			t.Errorf("re-signed roles %v, requests %d", shown.Announcement.GetWhat().GetRoles(), shown.Announcement.GetWhat().GetRequests())
		}
	}
}

// FS-101's refused versions: a removed admin's version pushed at an older pin, where it still held the right, over
// 10 min after the removal's entry (evs bounds a push's pin only by its ref's head pin); a removed admin's version at
// a pin after its removal; and a non-admin's at a fresh pin. Each is refused and alarms, while E's version from before
// the removal stands, and a push at the older pin within the 10 min stands too.
func TestDirectoryRepoItemRefusedPastItsSignersRight(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	eMember, nMember := sidecar.NewId(), sidecar.NewId()
	e := world.memberWriter(eMember)
	nonAdmin := world.memberWriter(nMember)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e)
	e.announce(testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "first", false))
	held := world.recordAuth.Tip().Pin()
	world.clock.Advance(time.Minute)
	world.directoryFixture.Repos[repoId].Admins = nil
	world.publish()

	// within 10 min of the removal, at the older pin: stands
	world.clock.Advance(5 * time.Minute)
	e.announceIn(testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 2, world.clock.Now().UnixMilli(), "second", false), nil, held)
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetWhat().GetTitle() != "second" {
		t.Fatalf("a push at an older pin within the bound: %v", item)
	}

	// over 10 min after the removal, at the older pin
	world.clock.Advance(6 * time.Minute)
	e.announceIn(testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 3, world.clock.Now().UnixMilli(), "third", false), nil, held)
	// at a pin after the removal
	e.announce(testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 4, world.clock.Now().UnixMilli(), "fourth", false))
	// a non-admin's, at a fresh pin
	nonAdmin.announce(testRepoItem(t, nonAdmin.sidecarId, &nMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 5, world.clock.Now().UnixMilli(), "fifth", false))
	reader.mustSync(t)
	item := testRepoItemShown(t, reader, repoId)
	if item == nil || item.Announcement.GetWhat().GetTitle() != "second" {
		t.Errorf("shown %v", item)
	}
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 2 || reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, nonAdmin.sidecarId) != 1 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// FS-84's repo clauses: a non-admin's item, an admin's on an owner-bound repo, an item for config, mailcfg or the
// directory, one naming another kind than its repo's and one for a repo the log never held are each ignored with an
// alarm, while the owner's consented device announces its own vault.
func TestDirectoryRepoItemFs84Refusals(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	ownerMember, adminMember := sidecar.NewId(), sidecar.NewId()
	owner := world.memberWriter(ownerMember)
	admin := world.memberWriter(adminMember)
	world.directoryFixture.Sidecars[admin.sidecarId].ConfigWriter = true
	world.publish()
	general := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, admin)
	vault := world.createRepo(protocol.RepoKind_REPO_KIND_VAULT, &ownerMember, owner)
	mailcfg := world.createRepo(protocol.RepoKind_REPO_KIND_MAILCFG, nil, admin)
	nowMillis := world.clock.Now().UnixMilli()

	refused := []struct {
		name   string
		writer *testDirectoryWriter
		member sidecar.Id
		repoId sidecar.Id
		kind   protocol.RepoKind
		alarm  sidecar.SidecarRecordAlarm
	}{
		{name: "a non-admin", writer: owner, member: ownerMember, repoId: general, kind: protocol.RepoKind_REPO_KIND_GENERAL, alarm: sidecar.SidecarRecordAlarmBadEntry},
		{name: "an admin on an owner-bound repo", writer: admin, member: adminMember, repoId: vault, kind: protocol.RepoKind_REPO_KIND_VAULT, alarm: sidecar.SidecarRecordAlarmBadEntry},
		{name: "a mailcfg repo", writer: admin, member: adminMember, repoId: mailcfg, kind: protocol.RepoKind_REPO_KIND_GENERAL, alarm: sidecar.SidecarRecordAlarmBadEntry},
		{name: "the directory, by its kind", writer: admin, member: adminMember, repoId: world.directoryId, kind: protocol.RepoKind_REPO_KIND_DIRECTORY, alarm: sidecar.SidecarRecordAlarmOverCap},
		{name: "another kind than its repo's", writer: admin, member: adminMember, repoId: general, kind: protocol.RepoKind_REPO_KIND_RECORD, alarm: sidecar.SidecarRecordAlarmBadEntry},
		{name: "a repo the log never held", writer: admin, member: adminMember, repoId: sidecar.NewId(), kind: protocol.RepoKind_REPO_KIND_GENERAL, alarm: sidecar.SidecarRecordAlarmBadEntry},
	}
	for _, c := range refused {
		member := c.member
		c.writer.announce(testRepoItem(t, c.writer.sidecarId, &member, c.repoId, c.kind, 1, nowMillis, c.name, false))
	}
	owner.announce(testRepoItem(t, owner.sidecarId, &ownerMember, vault, protocol.RepoKind_REPO_KIND_VAULT, 2, nowMillis, "my notes", false))

	reader := world.reader(nil)
	reader.mustSync(t)
	items := reader.items(t)
	if len(items) != 1 || items[0].SignerSidecarId != owner.sidecarId || sidecar.Id(items[0].Announcement.GetWhere().GetRepoId()) != vault {
		t.Fatalf("%d items", len(items))
	}
	if got := reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, admin.sidecarId); got != 4 {
		t.Errorf("%d bad_entry alarms naming the admin: %v", got, reader.alarmReasons())
	}
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, owner.sidecarId) != 1 || reader.alarmsNaming(sidecar.SidecarRecordAlarmOverCap, admin.sidecarId) != 1 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// A private marker and an announcement fill the same 2,048 B (plan-RECORD-m6-carrier #2), so their sealed entries
// are the same size and evs cannot tell which new repos are private.
func TestDirectoryRepoMarkerAndAnnouncementPadAlike(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	nowMillis := world.clock.Now().UnixMilli()
	announcement := testRepoItem(t, writer.sidecarId, &memberId, sidecar.NewId(), protocol.RepoKind_REPO_KIND_GENERAL, 1, nowMillis, "a display name of some length for the shared repo", false)
	announcement.What.Description = "what the repo holds and who looks after it"
	if _, err := sidecar.DirectoryPadRepoAnnouncement(announcement); err != nil {
		t.Fatal(err)
	}
	marker := testRepoItem(t, writer.sidecarId, &memberId, sidecar.NewId(), protocol.RepoKind_REPO_KIND_GENERAL, 1, nowMillis, "", true)
	if proto.Size(announcement) != sidecar.DirectoryRepoEntryStepByteCount || proto.Size(marker) != sidecar.DirectoryRepoEntryStepByteCount {
		t.Fatalf("an announcement of %d B and a marker of %d B", proto.Size(announcement), proto.Size(marker))
	}
	sizes := []int{}
	for _, item := range []*protocol.Announcement{announcement, marker} {
		sealed, err := sidecar.RecordSeal(writer.env, &sidecar.RecordSealArgs{
			LogId: world.directoryId, Kind: sidecar.RecordKindAnnounce, Source: sidecar.RecordSourceObserved,
			TimeMillis: nowMillis, PolicyVersion: 1, Body: item,
		})
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(sealed.SealedBody))
	}
	if sizes[0] != sizes[1] {
		t.Errorf("sealed bodies of %d and %d B", sizes[0], sizes[1])
	}
}

// §16.11's defaults at creation, through a device's own record: a general or record repo's item with its display
// name, roles {reader, writer} and requests open; a group inbox's with requests closed and no roles; a private
// marker under --private, which List leaves out and which warns a label may still name the repo; nothing for a vault.
func TestDirectoryAnnounceNewRepoDefaults(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	general := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	record := world.createRepo(protocol.RepoKind_REPO_KIND_RECORD, nil, writer)
	inbox := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	private := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	vault := world.createRepo(protocol.RepoKind_REPO_KIND_VAULT, &memberId, writer)
	device := world.device(writer, nil)
	created := []*sidecar.EvsRepoCreated{
		{RepoId: general, Kind: protocol.RepoKind_REPO_KIND_GENERAL, DisplayName: "design notes", Confirmed: true},
		{RepoId: record, Kind: protocol.RepoKind_REPO_KIND_RECORD, DisplayName: "build ledger"},
		{RepoId: inbox, Kind: protocol.RepoKind_REPO_KIND_GENERAL, DisplayName: "support inbox", GroupInbox: true},
		{RepoId: vault, Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &memberId},
	}
	for _, repo := range created {
		write, err := device.client.AnnounceNewRepo(t.Context(), repo)
		if err != nil {
			t.Fatal(err)
		}
		if (repo.Kind == protocol.RepoKind_REPO_KIND_VAULT) != (write == nil) {
			t.Errorf("%s: written %v", repo.Kind, write != nil)
		}
	}
	// a marker: no name, and the warning that a label may still name the repo, which an unbound labels seam assumes
	markerWrite, err := device.client.AnnounceNewRepo(t.Context(), &sidecar.EvsRepoCreated{RepoId: private, Kind: protocol.RepoKind_REPO_KIND_GENERAL, DisplayName: "never shown", Private: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(markerWrite.Warnings, []string{sidecar.DirectoryRepoLabelWarning}) || !markerWrite.Item.GetWhere().GetPrivate() ||
		markerWrite.Item.GetWhat().GetTitle() != "" || proto.Size(markerWrite.Item) != sidecar.DirectoryRepoEntryStepByteCount {
		t.Errorf("a marker: warnings %v, %d B", markerWrite.Warnings, proto.Size(markerWrite.Item))
	}
	device.flush(t)

	reader := world.reader(nil)
	reader.mustSync(t)
	wants := map[sidecar.Id]struct {
		title    string
		roles    []uint32
		requests sidecar.DirectoryRequests
	}{
		general: {title: "design notes", roles: []uint32{2, 3}, requests: sidecar.DirectoryRequestsOpen},
		record:  {title: "build ledger", roles: []uint32{2, 3}, requests: sidecar.DirectoryRequestsOpen},
		inbox:   {title: "support inbox", roles: nil, requests: sidecar.DirectoryRequestsClosed},
	}
	for repoId, want := range wants {
		item := testRepoItemShown(t, reader, repoId)
		if item == nil {
			t.Fatalf("no item for %s", want.title)
		}
		what := item.Announcement.GetWhat()
		if what.GetTitle() != want.title || !slices.Equal(what.GetRoles(), want.roles) || what.GetRequests() != uint32(want.requests) ||
			item.Display != sidecar.DirectoryItemActive || item.Announcement.GetVersion() != 1 {
			t.Errorf("%s: roles %v, requests %d, %s", what.GetTitle(), what.GetRoles(), what.GetRequests(), item.Display)
		}
	}
	marker := testRepoItemShown(t, reader, private)
	if marker == nil || marker.Display != sidecar.DirectoryItemPrivate || marker.Announcement.GetWhat().GetTitle() != "" {
		t.Errorf("the private marker: %v", marker)
	}
	if items, err := reader.client.List(nil); err != nil || len(items) != 3 {
		t.Errorf("List without private markers: %d, %v", len(items), err)
	}
	if testRepoItemShown(t, reader, vault) != nil {
		t.Error("a vault announced by default")
	}
	// what a run's where reads: a live, non-private item names the repo, a marker keeps it private, none says nothing
	if item, ok := reader.client.RepoItem(general); !ok || item.Display != sidecar.DirectoryItemActive {
		t.Errorf("RepoItem of an announced repo: %v", ok)
	}
	if item, ok := reader.client.RepoItem(private); !ok || item.Display != sidecar.DirectoryItemPrivate {
		t.Errorf("RepoItem of a private repo: %v", ok)
	}
	if _, ok := reader.client.RepoItem(vault); ok {
		t.Error("RepoItem of a repo with no item")
	}
	if len(reader.alarmReasons()) != 0 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}

	// the owner may later announce a private repo, a full item at a higher version
	write, err := device.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: private, DisplayName: "now public", Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if write.Item.GetVersion() != 2 {
		t.Errorf("announced over the marker at version %d", write.Item.GetVersion())
	}
	device.flush(t)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, private); item == nil || item.Display != sidecar.DirectoryItemActive || item.Announcement.GetWhat().GetTitle() != "now public" {
		t.Errorf("the announcement over the marker: %v", item)
	}
}

// The writer refuses what readers would ignore, writing nothing: a non-admin's item, an admin's on an owner-bound repo,
// an item for config, mailcfg or the directory, a read_only client's, and one with no writer; the owner's consented
// device announces its vault explicitly, reader only and requests closed; and a secret in a display name is signed
// as its marker.
func TestDirectoryAnnounceRepoRefusals(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	ownerMember, otherMember := sidecar.NewId(), sidecar.NewId()
	owner := world.memberWriter(ownerMember)
	other := world.memberWriter(otherMember)
	world.directoryFixture.Sidecars[other.sidecarId].ConfigWriter = true
	world.publish()
	general := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, owner)
	vault := world.createRepo(protocol.RepoKind_REPO_KIND_VAULT, &ownerMember, owner)
	mailcfg := world.createRepo(protocol.RepoKind_REPO_KIND_MAILCFG, nil, other)
	ownerDevice := world.device(owner, nil)
	otherDevice := world.device(other, nil)
	refusals := []struct {
		client *sidecar.DirectoryClient
		repoId sidecar.Id
		want   error
	}{
		{client: otherDevice.client, repoId: general, want: sidecar.ErrDirectoryRepoRight},
		{client: otherDevice.client, repoId: vault, want: sidecar.ErrDirectoryRepoRight},
		{client: otherDevice.client, repoId: mailcfg, want: sidecar.ErrDirectoryRepoKind},
		{client: otherDevice.client, repoId: world.directoryId, want: sidecar.ErrDirectoryRepoKind},
		{client: world.clientFor(owner.sidecarId, ownerDevice.record.Writer(), true, nil).client, repoId: general, want: sidecar.ErrDirectoryReadOnly},
		{client: world.clientFor(owner.sidecarId, nil, false, nil).client, repoId: general, want: sidecar.ErrDirectoryNoWriter},
	}
	for _, refusal := range refusals {
		if _, err := refusal.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: refusal.repoId, DisplayName: "x"}); !errors.Is(err, refusal.want) {
			t.Errorf("%v, want %v", err, refusal.want)
		}
	}
	write, err := ownerDevice.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: vault, DisplayName: "my notes", Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(write.Item.GetWhat().GetRoles(), []uint32{2}) || write.Item.GetWhat().GetRequests() != uint32(sidecar.DirectoryRequestsClosed) {
		t.Errorf("a vault offers %v, requests %d", write.Item.GetWhat().GetRoles(), write.Item.GetWhat().GetRequests())
	}
	secret, err := ownerDevice.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: general, DisplayName: "keys " + testSyntheticGithubToken(7)})
	if err != nil {
		t.Fatal(err)
	}
	if title := secret.Item.GetWhat().GetTitle(); title != "[REDACTED:github-pat]" {
		t.Errorf("a secret signed as %q", title)
	}
	ownerDevice.flush(t)
	reader := world.reader(nil)
	reader.mustSync(t)
	if items := reader.items(t); len(items) != 2 {
		t.Errorf("%d items", len(items))
	}
	if len(reader.alarmReasons()) != 0 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// A general or record repo created before the directory, with no item, is announced by the first of its admins'
// devices to sync it, with the name the device knows it by; one created after the directory is its creating device's
// to announce, or to mark private, and no other device writes it.
func TestDirectoryMaintainReposAnnouncesPredatingRepos(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	predating := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	predatingVault := world.createRepo(protocol.RepoKind_REPO_KIND_VAULT, &memberId, writer)
	// the directory is created after them
	world.directoryFixture.Repos[world.directoryId].Admins[0].At = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	later := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	names := map[sidecar.Id]string{predating: "old project"}
	device := world.device(writer, func(repoId sidecar.Id) string { return names[repoId] })
	device.mustSync(t)
	writes, err := device.client.MaintainRepos(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 || sidecar.Id(writes[0].Item.GetWhere().GetRepoId()) != predating {
		t.Fatalf("%d writes", len(writes))
	}
	device.flush(t)
	reader := world.reader(nil)
	reader.mustSync(t)
	item := testRepoItemShown(t, reader, predating)
	if item == nil || item.Announcement.GetWhat().GetTitle() != "old project" || item.SignerSidecarId != writer.sidecarId {
		t.Errorf("the predating repo's item: %v", item)
	}
	if testRepoItemShown(t, reader, later) != nil || testRepoItemShown(t, reader, predatingVault) != nil {
		t.Error("a repo created after the directory, or a vault, announced by another device")
	}
	device.mustSync(t)
	if again, err := device.client.MaintainRepos(t.Context()); err != nil || len(again) != 0 {
		t.Errorf("a second sync writes %d: %v", len(again), err)
	}
}

// A synthetic GitHub token in the redactor's github-pat form, drawn from seed: no real secret.
func testSyntheticGithubToken(seed uint64) string {
	random := rand.New(rand.NewPCG(seed, 0x5ec2e7))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 36)
	for index := range token {
		token[index] = alphabet[random.IntN(len(alphabet))]
	}
	return "ghp_" + string(token)
}

// The directory's reader judges a push pin before what the state retains at the state itself, taking its chain value as
// §11.9's first pin, so a device that starts past a repo item's push still reads it; a record reader that is not the
// directory's refuses such an entry, as before, and alarms.
func TestDirectoryReaderJudgesAPinPastRetentionAtTheState(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	n0 := world.directoryAuth.Tip().Pin().GetVersion()
	writer.announce(testRepoItem(t, writer.sidecarId, &memberId, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "kept", false))
	world.advance(2, 24*time.Hour)
	world.recordAuth.RetainFrom(n0 + 1)
	world.directoryAuth.RetainFrom(n0 + 1)

	directory := world.reader(nil)
	directory.mustSync(t)
	if len(directory.client.Entries()) != 1 || testRepoItemShown(t, directory, repoId) == nil {
		t.Error("the directory's reader refuses a pin past retention")
	}

	alarms := []*sidecar.RecordAlarm{}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("plain", "record")
	if err != nil {
		t.Fatal(err)
	}
	plain := sidecar.NewRecordReader(&sidecar.RecordReaderArgs{
		SidecarId: world.readerId,
		Store:     store,
		Streams:   func() sidecar.RecordStreams { return world.streams.For(world.readerId) },
		Auth:      func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Alarm:     func(alarm *sidecar.RecordAlarm) { alarms = append(alarms, alarm) },
		Clock:     world.clock,
	})
	if err := plain.Sync(t.Context(), world.directoryId); err != nil {
		t.Fatal(err)
	}
	if len(plain.Entries(world.directoryId)) != 0 || len(alarms) != 1 || alarms[0].Reason != sidecar.SidecarRecordAlarmBadEntry {
		t.Errorf("a plain reader: %d entries, alarms %v", len(plain.Entries(world.directoryId)), alarms)
	}
}
