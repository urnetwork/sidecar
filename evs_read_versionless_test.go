//go:build !ios_extension

// Reads of versionless content on the client (EVS2-M10-18; FS-64's and FS-66's reader clauses): kind-5 and staged
// content, the gone row's fresh read, ReadHead's restarts and their bound, ReadVersion, History's states and List's
// settings, against the world's stand-in for evs.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A change's format2 hook that writes its file versionless: content as one checkpoint record in a kind-5 segment
// naming the push, staged or uploaded, which the world holds. digest, when set, replaces the sealed content_sha256.
func evsTestVersionlessContent(world *evsTestWorld, content []byte, staged bool, digest []byte) func(entry *protocol.EvsEntryVersion) {
	return func(entry *protocol.EvsEntryVersion) {
		t := world.t
		keys := evsTestKeys(t, world.repoId, world.generation)
		fileId := NewEvsSlotId()
		oid, err := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if digest == nil {
			sum := sha256.Sum256(content)
			digest = sum[:]
		}
		versioning := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
		sealedFields, err := EvsSealFieldsFormat2(keys.manifest, &protocol.EvsSealedFields{
			FileId: fileId.Bytes(), Mode: 0o100644, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
			Size: uint64(len(content)), ContentSha256: digest,
		}, versioning)
		if err != nil {
			t.Fatal(err)
		}
		pushId, err := IdFromBytes(entry.GetPushId())
		if err != nil {
			t.Fatal(err)
		}
		out := &bytes.Buffer{}
		builder, err := NewEvsKind5SegmentBuilder(out, keys.manifest, keys.fek, pushId)
		if err != nil {
			t.Fatal(err)
		}
		header := &EvsRecordHeader{
			RecordId: NewEvsSlotId(), Generation: world.generation, Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT,
			KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
			BodyLength: uint64(len(content)),
		}
		copy(header.Oid[:], oid[:])
		writer, err := builder.BeginRecord(fileId, header)
		if err != nil {
			t.Fatal(err)
		}
		writer.Write(content)
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		summary, err := builder.Finish()
		if err != nil {
			t.Fatal(err)
		}
		world.stateLock.Lock()
		world.segments[string(summary.Id[:])] = out.Bytes()
		if staged {
			if world.stagedIds == nil {
				world.stagedIds = map[string]bool{}
			}
			world.stagedIds[string(summary.Id[:])] = true
		}
		world.stateLock.Unlock()
		entry.Versioning = versioning
		entry.SealedFields = sealedFields
		entry.Chain = []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: summary.Id[:],
			Offset: summary.Places[0].Offset, Length: summary.Places[0].Length, Staged: staged,
		}}
	}
}

// Writes path versionless in the world, staged or uploaded, and answers the ref version.
func evsTestWriteVersionless(world *evsTestWorld, path string, content []byte, staged bool) uint64 {
	return world.push(&evsTestChange{path: path, content: content, segment: true, format2: evsTestVersionlessContent(world, content, staged, nil)})
}

// The one kind-5 segment id the newest version of path names.
func evsTestVersionlessId(t *testing.T, world *evsTestWorld, path string) string {
	t.Helper()
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	state := world.paths[path]
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(state.versions[state.newest].entryBytes, entry); err != nil || len(entry.GetChain()) != 1 {
		t.Fatalf("the newest version of %s: %v", path, err)
	}
	return string(entry.GetChain()[0].GetId())
}

// How many alarms a reader raised, each of which must be reason.
func evsTestAlarmCount(t *testing.T, reader *evsTestClient, reason SidecarEvsAlarm) int {
	t.Helper()
	count := 0
	for _, event := range reader.eventsOf(SidecarEventEvsAlarm) {
		if event.EvsAlarm != reason {
			t.Errorf("an alarm of %s", event.EvsAlarm)
			continue
		}
		count += 1
	}
	return count
}

// A kind-5 record, uploaded or staged, reads and verifies as kind 1, then against its sealed content_sha256; a staged
// segment is served only beside the path that stages it, which the reader names with its ranges.
func TestEvsReadHeadReadsVersionlessContent(t *testing.T) {
	world := newEvsTestWorld(t)
	uploaded := bytes.Repeat([]byte("uploaded "), 4096)
	evsTestWriteVersionless(world, "big.bin", uploaded, false)
	staged := []byte("a small versionless file")
	evsTestWriteVersionless(world, "small.txt", staged, true)
	reader := evsTestFormat2Reader(t, world)
	for path, want := range map[string][]byte{"big.bin": uploaded, "small.txt": staged} {
		content, info, err := evsTestRead(t, reader, world, path)
		if err != nil || !bytes.Equal(content, want) {
			t.Fatalf("%s: %d bytes, %v", path, len(content), err)
		}
		if info.Size != uint64(len(want)) {
			t.Errorf("%s: size %d", path, info.Size)
		}
	}
	if count := evsTestAlarmCount(t, reader, ""); count != 0 {
		t.Errorf("%d alarms on clean reads", count)
	}
}

// Content that opens under its keys and matches its oid's fields but not its sealed content_sha256 is tampering.
func TestEvsReadHeadChecksContentSha256(t *testing.T) {
	world := newEvsTestWorld(t)
	content := []byte("content")
	wrong := sha256.Sum256([]byte("other content"))
	world.push(&evsTestChange{path: "a.txt", content: content, format2: evsTestVersionlessContent(world, content, true, wrong[:])})
	reader := evsTestFormat2Reader(t, world)
	out, _, err := evsTestRead(t, reader, world, "a.txt")
	if !errors.Is(err, ErrEvsSealInvalid) || len(out) != 0 {
		t.Fatalf("a wrong content_sha256: %d bytes, %v", len(out), err)
	}
	if count := evsTestAlarmCount(t, reader, SidecarEvsAlarmTamper); count != 1 {
		t.Errorf("%d tamper alarms", count)
	}
}

// FS-64's reader: R2 verifies version k of a versionless path, pauses, and k+1 commits before it fetches k's content.
// evs answers k `collected`, or its content is already purged and 404s; either way the reader reads the head fresh,
// finds k+1, reads that, and alarms on nothing.
func TestEvsReadHeadRereadsAVersionlessFileReplacedMidRead(t *testing.T) {
	for _, collected := range []bool{true, false} {
		world := newEvsTestWorld(t)
		evsTestWriteVersionless(world, "a.bin", []byte("version k"), false)
		replaced := evsTestVersionlessId(t, world, "a.bin")
		if collected {
			world.collectedPaths = map[string]bool{"a.bin": true}
		}
		reader := evsTestFormat2Reader(t, world)
		pushed := false
		world.beforeRead = func(read *protocol.EvsReadRequest) {
			if len(read.GetRanges()) == 0 || pushed {
				return
			}
			// the reader is about to fetch k's content: k+1 commits first
			pushed = true
			evsTestWriteVersionless(world, "a.bin", []byte("version k+1"), false)
			if !collected {
				world.stateLock.Lock()
				delete(world.segments, replaced)
				world.stateLock.Unlock()
			}
		}
		content, info, err := evsTestRead(t, reader, world, "a.bin")
		if err != nil || string(content) != "version k+1" || info.Version != 2 {
			t.Fatalf("collected %t: %q %v %v", collected, content, info, err)
		}
		if !pushed {
			t.Fatal("the reader fetched no ranges")
		}
		if count := evsTestAlarmCount(t, reader, ""); count != 0 {
			t.Errorf("collected %t: %d alarms for a replaced version", collected, count)
		}
	}
}

// A versionless path's newest version whose content is gone is a missing segment: alarmed once, after the fresh read
// that shows it is still the newest, and nothing is written.
func TestEvsReadHeadAlarmsWhenTheNewestVersionIsGone(t *testing.T) {
	world := newEvsTestWorld(t)
	evsTestWriteVersionless(world, "a.bin", []byte("version k"), false)
	delete(world.segments, evsTestVersionlessId(t, world, "a.bin"))
	reader := evsTestFormat2Reader(t, world)
	readsBefore := world.reads
	content, _, err := evsTestRead(t, reader, world, "a.bin")
	if !errors.Is(err, ErrEvsObjectMissing) || len(content) != 0 {
		t.Fatalf("the newest version's 404: %q %v", content, err)
	}
	if count := evsTestAlarmCount(t, reader, SidecarEvsAlarmMissingSegment); count != 1 {
		t.Errorf("%d missing_segment alarms", count)
	}
	if world.reads-readsBefore < 3 {
		t.Errorf("%d reads: the head, the ranges and the fresh head are three at least", world.reads-readsBefore)
	}
}

// A path overwritten each time its content is fetched: ReadHead rereads ReadReplacedRestartCount times, then answers
// ErrEvsReplacedMidRead with no alarm; with one overwrite fewer it reads the last version.
func TestEvsReadHeadBoundsItsRestarts(t *testing.T) {
	for _, overwrites := range []int{3, 4} {
		world := newEvsTestWorld(t)
		evsTestWriteVersionless(world, "a.bin", []byte("version 1"), false)
		world.collectedPaths = map[string]bool{"a.bin": true}
		reader := evsTestFormat2Reader(t, world)
		reader.client.settings.ReadReplacedRestartCount = 3
		done := 0
		world.beforeRead = func(read *protocol.EvsReadRequest) {
			if len(read.GetRanges()) == 0 || overwrites <= done {
				return
			}
			done += 1
			evsTestWriteVersionless(world, "a.bin", []byte("another version"), false)
		}
		content, info, err := evsTestRead(t, reader, world, "a.bin")
		if overwrites <= 3 {
			if err != nil || string(content) != "another version" || info.Version != uint64(1+overwrites) {
				t.Fatalf("%d overwrites: %q %v %v", overwrites, content, info, err)
			}
		} else if !errors.Is(err, ErrEvsReplacedMidRead) || len(content) != 0 {
			t.Fatalf("%d overwrites: %q %v", overwrites, content, err)
		}
		if count := evsTestAlarmCount(t, reader, ""); count != 0 {
			t.Errorf("%d overwrites: %d alarms", overwrites, count)
		}
	}
}

// ReadVersion reads an older version by its number: a kept one's content, ErrEvsCollected for a replaced versionless
// one with no alarm, and a `collected` answered for the version that is still its path's newest alarms as a missing
// segment.
func TestEvsReadVersionAnswersCollected(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.bin", content: []byte("kept")})
	evsTestWriteVersionless(world, "a.bin", []byte("versionless 2"), false)
	evsTestWriteVersionless(world, "a.bin", []byte("versionless 3"), false)
	world.collectedPaths = map[string]bool{"a.bin": true}
	reader := evsTestFormat2Reader(t, world)
	repo := reader.client.Repo(world.repoId)
	read := func(version uint64) (string, error) {
		out := &bytes.Buffer{}
		_, err := repo.ReadVersion(context.Background(), &EvsReadArgs{Path: "a.bin", Version: version}, out)
		return out.String(), err
	}
	if _, err := read(0); !errors.Is(err, ErrEvsTokenInvalid) {
		t.Errorf("version 0: %v", err)
	}
	if content, err := read(3); err != nil || content != "versionless 3" {
		t.Errorf("the newest by number: %q %v", content, err)
	}
	if content, err := read(2); !errors.Is(err, ErrEvsCollected) || content != "" {
		t.Errorf("a replaced versionless version: %q %v", content, err)
	}
	if count := evsTestAlarmCount(t, reader, ""); count != 0 {
		t.Fatalf("%d alarms for a collected version", count)
	}
	// evs lies: the newest version, asked for by its number, answered collected
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if reply.GetVersion().GetCommitVersion() == 3 {
			reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
		}
	}
	liar := evsTestFormat2Reader(t, world)
	out := &bytes.Buffer{}
	_, err := liar.client.Repo(world.repoId).ReadVersion(context.Background(), &EvsReadArgs{Path: "a.bin", Version: 3}, out)
	if !errors.Is(err, ErrEvsObjectMissing) || out.Len() != 0 {
		t.Errorf("collected answered for the newest version: %v", err)
	}
	if count := evsTestAlarmCount(t, liar, SidecarEvsAlarmMissingSegment); count != 1 {
		t.Errorf("%d missing_segment alarms for the lie", count)
	}
}

// History reports each version's versioning, and a replaced versionless version as collected.
func TestEvsHistoryReportsVersioningAndCollected(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.bin", content: []byte("kept")})
	evsTestWriteVersionless(world, "a.bin", []byte("versionless 2"), false)
	evsTestWriteVersionless(world, "a.bin", []byte("versionless 3"), false)
	world.collectedPaths = map[string]bool{"a.bin": true}
	reader := evsTestFormat2Reader(t, world)
	history, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.bin"})
	if err != nil || len(history.Versions) != 3 {
		t.Fatalf("history: %v %v", history, err)
	}
	want := []struct {
		versioning uint32
		state      string
	}{{versioning: 1, state: "kept"}, {versioning: 1, state: "collected"}, {versioning: 0, state: "kept"}}
	for index, version := range history.Versions {
		if version.Versioning != want[index].versioning || version.State != want[index].state {
			t.Errorf("version %d: versioning %d state %s", version.Version, version.Versioning, version.State)
		}
	}
	if count := evsTestAlarmCount(t, reader, ""); count != 0 {
		t.Errorf("%d alarms", count)
	}
}

// List hides the index files' root unless asked, and reads each file's setting when asked.
func TestEvsListReportsSettingsAndHidesIndexFiles(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(
		&evsTestChange{path: "", children: []string{"kept.txt", "loose.bin", ".ur-index"}},
		&evsTestChange{path: "kept.txt", content: []byte("kept")},
		&evsTestChange{path: "loose.bin", content: []byte("loose"), format2: evsTestVersionlessContent(world, []byte("loose"), true, nil)},
		&evsTestChange{path: ".ur-index", children: []string{}},
	)
	reader := evsTestFormat2Reader(t, world)
	repo := reader.client.Repo(world.repoId)
	listing, err := repo.List(context.Background(), &EvsReadArgs{Path: "", Settings: true})
	if err != nil || len(listing.Entries) != 2 {
		t.Fatalf("the root: %v %v", listing, err)
	}
	settings := map[string]uint32{}
	for _, entry := range listing.Entries {
		settings[string(entry.Name)] = entry.Versioning
	}
	if setting, ok := settings["kept.txt"]; !ok || setting != 0 {
		t.Errorf("kept.txt: %d %t", setting, ok)
	}
	if setting, ok := settings["loose.bin"]; !ok || setting != 1 {
		t.Errorf("loose.bin: %d %t", setting, ok)
	}
	asked, err := repo.List(context.Background(), &EvsReadArgs{Path: "", IndexFiles: true})
	if err != nil || len(asked.Entries) != 3 {
		t.Fatalf("the root with its index files: %v %v", asked, err)
	}
	for _, entry := range asked.Entries {
		if entry.Versioning != 0 {
			t.Errorf("%s: a setting nobody asked for", entry.Name)
		}
	}
}

// §11.11's mobile row, as far as the client's core goes: head mode has no local tier and syncs entries, never
// content, so a listing with its settings and a history fetch no range of a versionless file, and only an explicit
// open, ReadHead, does.
func TestEvsVersionlessContentIsFetchedOnlyOnAnOpen(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(
		&evsTestChange{path: "", children: []string{"loose.bin"}},
		&evsTestChange{path: "loose.bin", content: []byte("loose"), segment: true, format2: evsTestVersionlessContent(world, []byte("loose"), false, nil)},
	)
	rangeCount := 0
	world.beforeRead = func(read *protocol.EvsReadRequest) {
		rangeCount += len(read.GetRanges())
	}
	reader := evsTestFormat2Reader(t, world)
	repo := reader.client.Repo(world.repoId)
	if _, err := repo.List(context.Background(), &EvsReadArgs{Path: "", Settings: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.History(context.Background(), &EvsReadArgs{Path: "loose.bin"}); err != nil {
		t.Fatal(err)
	}
	if rangeCount != 0 {
		t.Fatalf("a listing and a history fetched %d ranges of versionless content", rangeCount)
	}
	if content, _, err := evsTestRead(t, reader, world, "loose.bin"); err != nil || string(content) != "loose" {
		t.Fatalf("the open: %q %v", content, err)
	}
	if rangeCount == 0 {
		t.Fatal("the open fetched no range")
	}
}
