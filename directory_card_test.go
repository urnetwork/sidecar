//go:build !sidecar_http

// RECORD-M10-02's cards and repo files on sidecartest's fakes, signed for real so every reader verifies them: a card
// written, folded and stored at 2 KiB steps; its caps on both sides, a 17th item and 16,193 B refused, 16,192 B taken
// (QD-834); its file read to 16 KiB and no further, which 16 items at the items' cap fit; FS-84's card cases, a card signed or pushed by another sidecar, one whose seq is not above the last or whose pin is
// out of range, one by a parked or suspended signer, and removals by another member, by a directory admin and after a
// revocation; and FS-101's r/ cases, a pin over 4,096 positions before its push's, a removed admin's and a
// non-admin's version, and a removed admin's push at an idle cards ref's older pin.

package sidecar_test

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The cards ref file at path as the fake holds it now: its version, 0 for none or a removal.
func (self *testDirectoryWorld) cardFileVersion(path string) uint64 {
	self.t.Helper()
	changes, err := self.cards.For(self.readerId).ReadCards(self.t.Context(), self.directoryId, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	version := uint64(0)
	for _, file := range changes.Files {
		if file.Path == path {
			version = file.Version
			if file.Removed {
				version = 0
			}
		}
	}
	return version
}

// Puts content at path as pusherId's push declaring pin, from the version the fake holds.
func (self *testDirectoryWorld) putFile(pusherId sidecar.Id, path string, content []byte, pin *bridge.AuthPin) {
	self.t.Helper()
	if _, err := self.cards.For(pusherId).PutCard(self.t.Context(), self.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: path, IfVersion: self.cardFileVersion(path), Content: content, AuthPin: pin,
	}); err != nil {
		self.t.Fatal(err)
	}
}

// Removes path as removerId's push, from the version the fake holds.
func (self *testDirectoryWorld) removeFile(removerId sidecar.Id, path string) {
	self.t.Helper()
	if err := self.cards.For(removerId).RemoveCard(self.t.Context(), self.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: path, IfVersion: self.cardFileVersion(path), AuthPin: self.directoryAuth.Tip().Pin(),
	}); err != nil {
		self.t.Fatal(err)
	}
}

// A card file naming sidecarId at seq and at, holding items, signed by signer: what a writer, honest or not, builds.
func (self *testDirectoryWorld) cardContent(signer *testDirectoryWriter, sidecarId sidecar.Id, seq uint64, at *bridge.AuthPin, items ...*protocol.Announcement) []byte {
	self.t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.DirectoryCard{
		NetworkId: self.networkId.Bytes(), SidecarId: sidecarId.Bytes(), Seq: seq, At: at,
		WrittenMillis: self.clock.Now().UnixMilli(), Items: items, Version: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return testSignedContent(self.t, signer, bridge.SignedType_SIGNED_DIRECTORY_CARD, body)
}

// A repo file for repoId at seq and at, holding item, signed by signer.
func (self *testDirectoryWorld) repoFileContent(signer *testDirectoryWriter, repoId sidecar.Id, seq uint64, at *bridge.AuthPin, item *protocol.Announcement) []byte {
	self.t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.RepoAnnouncement{
		NetworkId: self.networkId.Bytes(), RepoId: repoId.Bytes(), Seq: seq, At: at, Item: item,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return testSignedContent(self.t, signer, bridge.SignedType_SIGNED_DIRECTORY_REPO, body)
}

// body Signed by signer as signedType under purpose directory, marshaled.
func testSignedContent(t *testing.T, signer *testDirectoryWriter, signedType bridge.SignedType, body []byte) []byte {
	t.Helper()
	signed, err := signer.sign(sidecar.DirectorySignedPurpose, signedType, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// The device's card with items, which must take, after a sync.
func (self *testDirectoryDevice) writeCard(t *testing.T, items ...*protocol.Announcement) *sidecar.DirectoryCardWritten {
	t.Helper()
	self.mustSync(t)
	written, err := self.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: items})
	if err != nil {
		t.Fatal(err)
	}
	return written
}

// The items reader shows of writerId's, by announcement id.
func testItemsOf(t *testing.T, reader *testDirectoryReader, writerId sidecar.Id) map[sidecar.Id]*sidecar.DirectoryItem {
	t.Helper()
	items := map[sidecar.Id]*sidecar.DirectoryItem{}
	for _, item := range reader.items(t) {
		if item.SignerSidecarId == writerId {
			items[item.Key.AnnouncementId] = item
		}
	}
	return items
}

// The bytes items take as a card's items field.
func testCardItemsByteCount(items []*protocol.Announcement) int {
	byteCount := 0
	for _, item := range items {
		byteCount += protowire.SizeTag(6) + protowire.SizeBytes(proto.Size(item))
	}
	return byteCount
}

// itemCount runs of writerId's whose card items take exactly byteCount bytes: each run's claims filled with targets to
// its share of byteCount, then the last run's trimmed byte by byte, its last claim's text making up a varint's step.
func testCardRunsOfByteCount(t *testing.T, writerId sidecar.Id, memberId *sidecar.Id, renewedMillis int64, itemCount int, byteCount int) []*protocol.Announcement {
	t.Helper()
	items := []*protocol.Announcement{}
	for index := range itemCount {
		item := testRunItem(writerId, memberId, sidecar.NewId(), 1, renewedMillis)
		items = append(items, item)
		for testCardItemsByteCount(items) < byteCount*(index+1)/itemCount {
			// a run holds at most 4 claims of at most 16 targets
			if len(item.Claims) == 0 || len(item.Claims[len(item.Claims)-1].Targets) == 16 {
				if len(item.Claims) == 4 {
					t.Fatalf("%d runs hold no %d bytes", itemCount, byteCount)
				}
				item.Claims = append(item.Claims, &protocol.Claim{ClaimId: sidecar.NewId().Bytes(), Text: "c", ExpiresMillis: item.GetExpiresMillis(), State: 1})
			}
			claim := item.Claims[len(item.Claims)-1]
			claim.Targets = append(claim.Targets, "src/"+strings.Repeat("p", 252))
		}
	}
	last := items[len(items)-1]
	for byteCount < testCardItemsByteCount(items) {
		if len(last.Claims) == 0 {
			t.Fatalf("the last run has no claim left to trim to %d bytes", byteCount)
		}
		claim := last.Claims[len(last.Claims)-1]
		if len(claim.Targets) == 0 {
			last.Claims = last.Claims[:len(last.Claims)-1]
			continue
		}
		target := claim.Targets[len(claim.Targets)-1]
		if len(target) <= 1 {
			claim.Targets = claim.Targets[:len(claim.Targets)-1]
			continue
		}
		claim.Targets[len(claim.Targets)-1] = target[:len(target)-1]
	}
	if len(last.Claims) == 0 {
		t.Fatalf("the last run has no claim left to fill to %d bytes", byteCount)
	}
	claim := last.Claims[len(last.Claims)-1]
	claim.Text += strings.Repeat("c", byteCount-testCardItemsByteCount(items))
	if testCardItemsByteCount(items) != byteCount {
		t.Fatalf("items of %d bytes, not %d", testCardItemsByteCount(items), byteCount)
	}
	for _, item := range items {
		if err := sidecar.DirectoryCheckItem(item); err != nil {
			t.Fatal(err)
		}
	}
	return items
}

// A member device writes its card, a worker item and two runs; a reader folds them from the card, at the card's pin;
// one run and two store at one 2 KiB step, twelve at more.
func TestDirectoryCardWrittenFoldedAndPadded(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	worker := testWorkerItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now)
	first := testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now)
	second := testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 2, now)
	written := device.writeCard(t, first, second, worker)
	if written.Seq != 1 || len(written.Items) != 3 || written.Items[0].GetKind() != uint32(sidecar.DirectoryAnnouncementKindWorker) {
		t.Fatalf("the card written: %+v", written)
	}
	if written.Path != sidecar.DirectoryCardPath(writer.sidecarId) || written.StoredByteCount%2048 != 0 || written.StoredByteCount < written.ByteCount {
		t.Fatalf("the card stored: %+v", written)
	}

	reader := world.reader(nil)
	reader.mustSync(t)
	shown := testItemsOf(t, reader, writer.sidecarId)
	if len(shown) != 3 {
		t.Fatalf("%d of the card's items shown", len(shown))
	}
	for _, item := range shown {
		if item.Display != sidecar.DirectoryItemActive || item.Seq != 1 {
			t.Errorf("an item from the card: %+v", item)
		}
	}
	if alarms := reader.alarmReasons(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}

	// a restarted reader takes what it accepted as it stands, alarming nothing
	restarted, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: world.readerId, Store: reader.store, Cards: world.cards.For(world.readerId),
		Streams:    func() sidecar.RecordStreams { return world.streams.For(world.readerId) },
		Auth:       func() sidecar.DirectoryAuthView { return world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			t.Errorf("a restarted reader alarms %s", alarm.Reason)
		},
		Clock: world.clock, Settings: sidecar.DefaultSidecarSettings().Directory, NetworkId: world.networkId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if items, err := restarted.List(&sidecar.DirectoryFilter{IncludePrivate: true}); err != nil || len(items) != 3 {
		t.Errorf("a restarted reader shows %d items: %v", len(items), err)
	}

	// the second write rises one seq, and readers show its items in place of the first's
	again := device.writeCard(t, first)
	if again.Seq != 2 {
		t.Fatalf("the second card at seq %d", again.Seq)
	}
	reader.mustSync(t)
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != 1 {
		t.Errorf("after the second card %d items shown", len(shown))
	}

	one := device.writeCard(t, first)
	two := device.writeCard(t, first, second)
	if one.StoredByteCount != 2048 || two.StoredByteCount != 2048 {
		t.Errorf("one run stored at %d B, two at %d", one.StoredByteCount, two.StoredByteCount)
	}
	runs := []*protocol.Announcement{}
	for index := range 12 {
		runs = append(runs, testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), uint64(index+1), now))
	}
	if twelve := device.writeCard(t, runs...); twelve.StoredByteCount <= 2048 || twelve.StoredByteCount%2048 != 0 {
		t.Errorf("twelve runs stored at %d B", twelve.StoredByteCount)
	}
}

// A writer refuses a 17th item, a second worker item and items past 16,192 B, signing nothing; a reader ignores a card
// of 17 items or of 16,193 B of items with over_cap, keeps showing the card it took last, and takes 16,192 B.
func TestDirectoryCardCaps(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	device.mustSync(t)
	now := world.clock.Now().UnixMilli()
	runs := []*protocol.Announcement{}
	for index := range 17 {
		runs = append(runs, testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), uint64(index+1), now))
	}
	if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: runs}); !errors.Is(err, sidecar.ErrDirectoryCardOverCap) {
		t.Errorf("a 17th item: %v", err)
	}
	workers := []*protocol.Announcement{
		testWorkerItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now), testWorkerItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now),
	}
	if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: workers}); !errors.Is(err, sidecar.ErrDirectoryCardOverCap) {
		t.Errorf("a second worker item: %v", err)
	}
	past := testCardRunsOfByteCount(t, writer.sidecarId, &memberId, now, 1, 16193)
	if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: past}); !errors.Is(err, sidecar.ErrDirectoryCardOverCap) {
		t.Errorf("items of 16,193 B: %v", err)
	}
	if version := world.cardFileVersion(sidecar.DirectoryCardPath(writer.sidecarId)); version != 0 {
		t.Fatalf("a refused card was put at version %d", version)
	}

	path := sidecar.DirectoryCardPath(writer.sidecarId)
	pin := world.directoryAuth.Tip().Pin()
	kept := testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now)
	world.putFile(writer.sidecarId, path, world.cardContent(writer, writer.sidecarId, 1, pin, kept), pin)
	reader := world.reader(nil)
	reader.mustSync(t)
	world.putFile(writer.sidecarId, path, world.cardContent(writer, writer.sidecarId, 2, pin, runs...), pin)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmOverCap, writer.sidecarId) != 1 {
		t.Errorf("a card of 17 items: alarms %v", reader.alarmReasons())
	}
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != 1 || shown[sidecar.Id(kept.GetAnnouncementId())] == nil {
		t.Errorf("past the cap the reader shows %d items", len(shown))
	}
	world.putFile(writer.sidecarId, path, world.cardContent(writer, writer.sidecarId, 3, pin, past...), pin)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmOverCap, writer.sidecarId) != 2 {
		t.Errorf("a card of 16,193 B: alarms %v", reader.alarmReasons())
	}
	at := testCardRunsOfByteCount(t, writer.sidecarId, &memberId, now, 1, 16192)
	world.putFile(writer.sidecarId, path, world.cardContent(writer, writer.sidecarId, 4, pin, at...), pin)
	reader.mustSync(t)
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != len(at) {
		t.Errorf("a card of 16,192 B: %d of %d items shown, alarms %v", len(shown), len(at), reader.alarmReasons())
	}
}

// A card of 16 items in exactly 16,192 B, the items' cap, written and signed by the writer, fits 16 KiB, eight steps,
// and a reader shows its items; one item byte more the writer refuses, putting nothing. A card file is read to 16 KiB
// and no further: a signed card of exactly 16,384 B decodes, and one of 16,385 B is refused though its items are within
// their cap, the reader ignoring it with over_cap and showing the card it took. At the items' cap a card fits whenever
// seq and the position are below 2^56, whatever written_millis is; with seq, the position and written_millis at their
// widest varints it is 16,388 B, which the file bound refuses, so QD-834's 16 B margin falls 4 B short there.
func TestDirectoryCardFileBound(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	settings := sidecar.DefaultDirectoryCardSettings()
	if settings.ItemsByteCount != 16192 || settings.CardFileByteCount != 16*1024 {
		t.Fatalf("a card's items in %d B, its file in %d B", settings.ItemsByteCount, settings.CardFileByteCount)
	}

	items := testCardRunsOfByteCount(t, writer.sidecarId, &memberId, now, 16, 16192)
	written := device.writeCard(t, items...)
	if len(written.Items) != 16 || 16384 < written.ByteCount || written.StoredByteCount != 16384 {
		t.Fatalf("a card at the items' cap: %d items in %d B, stored at %d", len(written.Items), written.ByteCount, written.StoredByteCount)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != 16 {
		t.Fatalf("a card at the items' cap: %d of 16 items shown, alarms %v", len(shown), reader.alarmReasons())
	}

	path := sidecar.DirectoryCardPath(writer.sidecarId)
	version := world.cardFileVersion(path)
	past := testCardRunsOfByteCount(t, writer.sidecarId, &memberId, now, 16, 16193)
	if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: past}); !errors.Is(err, sidecar.ErrDirectoryCardOverCap) {
		t.Errorf("items of 16,193 B: %v", err)
	}
	if world.cardFileVersion(path) != version {
		t.Error("a refused card was put")
	}

	// the card's and the Signed's own fields take 175 B with seq and the position in one byte each and written_millis in
	// six, and 196 B at their widest, ten, ten and nine
	cardAt := func(itemsByteCount int, seq uint64, position uint64, writtenMillis int64) ([]byte, *protocol.DirectoryCard) {
		t.Helper()
		card := &protocol.DirectoryCard{
			NetworkId: world.networkId.Bytes(), SidecarId: writer.sidecarId.Bytes(), Seq: seq,
			At:            &bridge.AuthPin{Version: position, Chain: make([]byte, 32)},
			WrittenMillis: writtenMillis,
			Items:         testCardRunsOfByteCount(t, writer.sidecarId, &memberId, now, 16, itemsByteCount),
			Version:       1,
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(card)
		if err != nil {
			t.Fatal(err)
		}
		return testSignedContent(t, writer, bridge.SignedType_SIGNED_DIRECTORY_CARD, body), card
	}
	for _, bound := range []struct {
		name           string
		itemsByteCount int
		seq            uint64
		position       uint64
		writtenMillis  int64
		byteCount      int
		decodes        bool
	}{
		{name: "16,188 B of items, all at their widest", itemsByteCount: 16188, seq: math.MaxUint64, position: math.MaxUint64, writtenMillis: math.MaxInt64, byteCount: 16384, decodes: true},
		{name: "16,189 B of items, all at their widest", itemsByteCount: 16189, seq: math.MaxUint64, position: math.MaxUint64, writtenMillis: math.MaxInt64, byteCount: 16385},
		{name: "the items' cap, seq and the position below 2^56", itemsByteCount: 16192, seq: 1<<56 - 1, position: 1<<56 - 1, writtenMillis: math.MaxInt64, byteCount: 16384, decodes: true},
		{name: "the items' cap, seq and the position at their widest", itemsByteCount: 16192, seq: math.MaxUint64, position: math.MaxUint64, writtenMillis: now, byteCount: 16385},
		{name: "the items' cap, all at their widest", itemsByteCount: 16192, seq: math.MaxUint64, position: math.MaxUint64, writtenMillis: math.MaxInt64, byteCount: 16388},
	} {
		content, card := cardAt(bound.itemsByteCount, bound.seq, bound.position, bound.writtenMillis)
		if len(content) != bound.byteCount {
			t.Errorf("%s: a card file of %d B, not %d", bound.name, len(content), bound.byteCount)
		}
		if err := sidecar.DirectoryCheckCard(card, settings); err != nil {
			t.Errorf("%s: the card itself: %v", bound.name, err)
		}
		_, err := sidecar.DirectoryDecodeCard(content, settings)
		if bound.decodes != (err == nil) || err != nil && !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) {
			t.Errorf("%s: read as %v", bound.name, err)
		}
	}

	// a card file of 16,385 B at the path, its items within their cap: ignored with over_cap, the card taken still shown
	over, _ := cardAt(16189, math.MaxUint64, math.MaxUint64, math.MaxInt64)
	world.putFile(writer.sidecarId, path, over, world.directoryAuth.Tip().Pin())
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmOverCap, writer.sidecarId) != 1 {
		t.Errorf("a card file of 16,385 B: alarms %v", reader.alarmReasons())
	}
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != 16 {
		t.Errorf("past the file's bound the reader shows %d items", len(shown))
	}
}

// FS-84's card cases: a card pushed by another sidecar, whether that sidecar signed it or replays the rightful one's;
// one at a seq not above the last; one whose pin lies past 4,096 positions; one by a signer parked for consent or
// suspended. Each is ignored with its alarm while the reader keeps showing the card it took last.
func TestDirectoryCardPathRules(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	aMember, bMember := sidecar.NewId(), sidecar.NewId()
	a := world.memberWriter(aMember)
	b := world.memberWriter(bMember)
	world.publish()
	now := world.clock.Now().UnixMilli()
	path := sidecar.DirectoryCardPath(a.sidecarId)
	pin := world.directoryAuth.Tip().Pin()
	one := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, now)
	two := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, now)
	first := world.cardContent(a, a.sidecarId, 1, pin, one)
	world.putFile(a.sidecarId, path, first, pin)
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 2, pin, one, two), pin)
	reader := world.reader(nil)
	reader.mustSync(t)
	requireTwo := func(name string) {
		t.Helper()
		if shown := testItemsOf(t, reader, a.sidecarId); len(shown) != 2 {
			t.Errorf("%s: the reader shows %d of A's items", name, len(shown))
		}
	}
	requireTwo("before any breach")

	// B pushes a card it signed naming A, then A's own first card again
	world.putFile(b.sidecarId, path, world.cardContent(b, a.sidecarId, 3, pin, one), pin)
	reader.mustSync(t)
	world.putFile(b.sidecarId, path, first, pin)
	reader.mustSync(t)
	if count := reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, b.sidecarId); count != 2 {
		t.Errorf("cards B pushed at A's path: %d path_rule alarms, %v", count, reader.alarmReasons())
	}
	requireTwo("after B's pushes")

	// A replays its first card, at a seq not above the last taken
	world.putFile(a.sidecarId, path, first, pin)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, a.sidecarId) != 1 {
		t.Errorf("a seq not above the last: alarms %v", reader.alarmReasons())
	}
	requireTwo("after the replay")

	// a pin past 4,096 positions of the reader's state, while the card taken last sits at a fresh one
	world.advance(sidecar.DirectoryPinPositionCount+1, time.Millisecond)
	fresh := world.directoryAuth.Tip().Pin()
	renewed := world.clock.Now().UnixMilli()
	one = testRunItem(a.sidecarId, &aMember, sidecar.Id(one.GetAnnouncementId()), 1, renewed)
	two = testRunItem(a.sidecarId, &aMember, sidecar.Id(two.GetAnnouncementId()), 1, renewed)
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 3, fresh, one, two), fresh)
	reader.mustSync(t)
	requireTwo("at a fresh pin")
	before := reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, a.sidecarId)
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 5, pin, one), fresh)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, a.sidecarId) != before+1 {
		t.Errorf("a pin out of range: alarms %v", reader.alarmReasons())
	}
	requireTwo("after a pin out of range")

	// parked for consent, then suspended: nothing it writes counts
	world.directoryFixture.Sidecars[a.sidecarId].Standing = sidecar.DirectoryStandingUnconsented
	world.publish()
	parked := world.directoryAuth.Tip().Pin()
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 6, parked, one), parked)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmParkedWriter, a.sidecarId) != 1 {
		t.Errorf("a parked signer's card: alarms %v", reader.alarmReasons())
	}
	if shown := testItemsOf(t, reader, a.sidecarId); len(shown) != 0 {
		t.Errorf("a parked signer's items show: %d", len(shown))
	}
	world.directoryFixture.Sidecars[b.sidecarId].SuspendedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	suspended := world.directoryAuth.Tip().Pin()
	bPath := sidecar.DirectoryCardPath(b.sidecarId)
	world.putFile(b.sidecarId, bPath, world.cardContent(b, b.sidecarId, 1, suspended, testRunItem(b.sidecarId, &bMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())), suspended)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, b.sidecarId) != 1 || len(testItemsOf(t, reader, b.sidecarId)) != 0 {
		t.Errorf("a suspended signer's card: alarms %v", reader.alarmReasons())
	}
}

// Removals of a card: by another member, a breach the reader ignores, alarming and showing what it took; by a
// directory admin, a moderation that A's member's own devices hear of and others do not; by any writer once A is
// revoked.
func TestDirectoryCardRemovals(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	aMember, bMember := sidecar.NewId(), sidecar.NewId()
	a := world.memberWriter(aMember)
	aLaptop := world.memberWriter(aMember)
	b := world.memberWriter(bMember)
	world.publish()
	path := sidecar.DirectoryCardPath(a.sidecarId)
	pin := world.directoryAuth.Tip().Pin()
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 1, pin, testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())), pin)
	reader := world.reader(nil)
	laptop := world.clientFor(aLaptop.sidecarId, nil, false)
	reader.mustSync(t)
	laptop.mustSync(t)

	world.removeFile(b.sidecarId, path)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, b.sidecarId) != 1 || len(testItemsOf(t, reader, a.sidecarId)) != 1 {
		t.Errorf("another member's removal: alarms %v", reader.alarmReasons())
	}

	// the reader is the directory's creator, so a directory admin: its removal is a moderation
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 2, pin, testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())), pin)
	reader.mustSync(t)
	laptop.mustSync(t)
	world.removeFile(world.readerId, path)
	reader.mustSync(t)
	laptop.mustSync(t)
	if len(testItemsOf(t, reader, a.sidecarId)) != 0 || len(testItemsOf(t, laptop, a.sidecarId)) != 0 {
		t.Error("a moderated card's items still show")
	}
	if laptop.alarmsNaming(sidecar.SidecarRecordAlarmModeration, a.sidecarId) != 1 || reader.alarmsNaming(sidecar.SidecarRecordAlarmModeration, a.sidecarId) != 0 {
		t.Errorf("moderation alarms: A's laptop %v, the admin %v", laptop.alarmReasons(), reader.alarmReasons())
	}

	// once A is revoked any writer removes its card
	world.putFile(a.sidecarId, path, world.cardContent(a, a.sidecarId, 3, pin, testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())), pin)
	reader.mustSync(t)
	world.directoryFixture.Sidecars[a.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	world.removeFile(b.sidecarId, path)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, b.sidecarId) != 1 {
		t.Errorf("a revoked sidecar's card removed: alarms %v", reader.alarmReasons())
	}
}

// FS-101's r/ cases: admin E's repo file is taken at its push's pin; E's version whose pin lies over 4,096 positions
// before its push's, E's version once removed as admin, and a non-admin's fresh version are refused, the reader keeping
// E's; and E's push after its removal at an idle cards ref's older pin, where it still held the right, is refused by a
// reader holding the removal's entry, timed over 10 min before the push.
func TestDirectoryRepoFilePathRules(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	eMember, xMember := sidecar.NewId(), sidecar.NewId()
	e := world.memberWriter(eMember)
	x := world.memberWriter(xMember)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, e)
	eDevice := world.device(e)
	eDevice.mustSync(t)
	item := testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "release notes", false)
	written, err := eDevice.client.WriteRepoFile(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	if written.Seq != 1 || written.StoredByteCount%2048 != 0 || 4096 < written.ByteCount {
		t.Fatalf("the repo file written: %+v", written)
	}
	n0 := world.directoryAuth.Tip().Pin()
	reader := world.reader(nil)
	reader.mustSync(t)
	requireE := func(name string) {
		t.Helper()
		shown := testRepoItemShown(t, reader, repoId)
		if shown == nil || shown.SignerSidecarId != e.sidecarId || shown.Announcement.GetWhat().GetTitle() != "release notes" {
			t.Errorf("%s: P's item %v", name, shown)
		}
	}
	requireE("E's file")

	path := sidecar.DirectoryRepoPath(repoId)
	world.advance(sidecar.DirectoryPinPositionCount+1, time.Millisecond)
	stale := testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 2, world.clock.Now().UnixMilli(), "stale pin", false)
	world.putFile(e.sidecarId, path, world.repoFileContent(e, repoId, 2, n0, stale), world.directoryAuth.Tip().Pin())
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 1 {
		t.Errorf("a pin over 4,096 before its push's: alarms %v", reader.alarmReasons())
	}
	requireE("after a stale pin")

	foreign := testRepoItem(t, x.sidecarId, &xMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 3, world.clock.Now().UnixMilli(), "not an admin", false)
	tip := world.directoryAuth.Tip().Pin()
	world.putFile(x.sidecarId, path, world.repoFileContent(x, repoId, 3, tip, foreign), tip)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, x.sidecarId) != 1 {
		t.Errorf("a non-admin's version: alarms %v", reader.alarmReasons())
	}
	requireE("after a non-admin's version")

	// E holds the right at this idle pin; then it is removed as admin and, more than 10 min on, pushes there
	idle := world.directoryAuth.Tip().Pin()
	world.clock.Advance(time.Minute)
	world.directoryFixture.Repos[repoId].Admins = nil
	world.publish()
	world.clock.Advance(11 * time.Minute)
	world.publish()
	late := testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 4, world.clock.Now().UnixMilli(), "after the removal", false)
	world.putFile(e.sidecarId, path, world.repoFileContent(e, repoId, 4, idle, late), idle)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 2 {
		t.Errorf("a removed admin's push at an older pin: alarms %v", reader.alarmReasons())
	}
	requireE("after the removed admin's push")

	removed := testRepoItem(t, e.sidecarId, &eMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 5, world.clock.Now().UnixMilli(), "no right", false)
	now := world.directoryAuth.Tip().Pin()
	world.putFile(e.sidecarId, path, world.repoFileContent(e, repoId, 5, now, removed), now)
	reader.mustSync(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, e.sidecarId) != 3 {
		t.Errorf("a removed admin's version: alarms %v", reader.alarmReasons())
	}
	requireE("after the removed admin's version")
}

// A repo file and a card each hold within their file: a repo file's item is its path's repo's, and a card holds only
// its own sidecar's runs and worker; the decoders refuse every other form before anything verifies.
func TestDirectoryCardDecoders(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	pin := world.directoryAuth.Tip().Pin()
	now := world.clock.Now().UnixMilli()
	settings := sidecar.DefaultDirectoryCardSettings()
	repoId := sidecar.NewId()
	repoItem := testRepoItem(t, writer.sidecarId, &memberId, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, now, "a repo", false)
	for name, content := range map[string][]byte{
		"a repo item on a card":   world.cardContent(writer, writer.sidecarId, 1, pin, repoItem),
		"another sidecar's item":  world.cardContent(writer, writer.sidecarId, 1, pin, testRunItem(sidecar.NewId(), &memberId, sidecar.NewId(), 1, now)),
		"a worker after a run":    world.cardContent(writer, writer.sidecarId, 1, pin, testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now), testWorkerItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now)),
		"seq 0":                   world.cardContent(writer, writer.sidecarId, 0, pin),
		"no pin":                  world.cardContent(writer, writer.sidecarId, 1, nil),
		"a repo file, not a card": world.repoFileContent(writer, repoId, 1, pin, repoItem),
		"bytes that do not parse": []byte("not a card"),
		"past the file's bound":   make([]byte, settings.CardFileByteCount+1),
	} {
		if _, err := sidecar.DirectoryDecodeCard(content, settings); !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := sidecar.DirectoryDecodeCard(world.cardContent(writer, writer.sidecarId, 1, pin), settings); err != nil {
		t.Errorf("an empty card: %v", err)
	}
	for name, content := range map[string][]byte{
		"another repo's item": world.repoFileContent(writer, sidecar.NewId(), 1, pin, repoItem),
		"a run item":          world.repoFileContent(writer, repoId, 1, pin, testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, now)),
		"a card, not a file":  world.cardContent(writer, writer.sidecarId, 1, pin),
		"past 4 KiB":          make([]byte, settings.RepoFileByteCount+1),
	} {
		if _, err := sidecar.DirectoryDecodeRepoFile(content, settings); !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := sidecar.DirectoryDecodeRepoFile(world.repoFileContent(writer, repoId, 1, pin, repoItem), settings); err != nil {
		t.Errorf("a repo file: %v", err)
	}
}

// Unbound, a client writes no card, signing nothing; read_only, or for a suspended sidecar, it refuses.
func TestDirectoryCardWriterRefusals(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	unbound := world.clientWith(writer.sidecarId, nil, false, &testDirectoryClientOptions{unbound: true})
	unbound.mustSync(t)
	if _, err := unbound.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{}); !errors.Is(err, sidecar.ErrDirectoryCardUnbound) {
		t.Errorf("an unbound client's card: %v", err)
	}
	readOnly := world.clientFor(writer.sidecarId, nil, true)
	if _, err := readOnly.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{}); !errors.Is(err, sidecar.ErrDirectoryReadOnly) {
		t.Errorf("a read_only client's card: %v", err)
	}
	// a suspended sidecar's card is one readers ignore, so it writes none
	device := world.device(writer)
	device.mustSync(t)
	world.directoryFixture.Sidecars[writer.sidecarId].SuspendedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{}); !errors.Is(err, sidecar.ErrDirectoryCardStanding) {
		t.Errorf("a suspended sidecar's card: %v", err)
	}
	if version := world.cardFileVersion(sidecar.DirectoryCardPath(writer.sidecarId)); version != 0 {
		t.Errorf("a refused card at version %d", version)
	}
}
