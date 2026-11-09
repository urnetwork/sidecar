// EVS1-M2-24's tests on the stand-in evs: reconstruction across a checkpoint and a diff of another generation, a
// large file through the spill, chunk records, a missing segment's alarm, a removal reading absent, List's name checks
// and its root, History's walk, format 2's read states, and the receipt gate.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Commits a push creating path with the entry build gives, from the push's id, base version and the path's version.
func (self *evsTestWorld) pushEntry(path string, build func(pushId Id, baseVersion uint64, version uint64) []byte) uint64 {
	self.t.Helper()
	baseVersion, baseChain := self.head()
	version := baseVersion + 1
	pushId := evsTestId(fmt.Sprint("world push ", version, " ", self.generation))
	entryBytes := build(pushId, baseVersion, version)
	plan := &EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
		RefMode: protocol.EvsRefMode_EVS_REF_FILE, PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain,
		Generation: self.generation, GroupId: evsTestId("world group"), GenerationCommitment: evsTestBytes(fmt.Sprint("commitment ", self.generation), 32),
		PathEpoch: 1, Auth: self.config.Pin(), SignerSidecarId: self.signer.sidecarId, ClientId: evsTestId("world client"),
		TimeMs: 1767225600000 + int64(version), SealedMetadata: evsTestBytes(fmt.Sprint("metadata ", version), 32),
		Changes: []*EvsPlannedChange{{TokenPath: self.tokens(path), EntryVersion: entryBytes}},
	}
	built, err := NewEvsStatementBuilder(self.signer.sign).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.commits = append(self.commits, &evsTestCommit{statement: built.Statement.Bytes, parsed: built.Statement, built: built, chain: EvsChainNext(baseChain, pushId, built.Statement.Sha256)})
	self.paths[path] = &evsTestPath{versions: map[uint64]*evsTestVersion{version: {entryBytes: entryBytes, commitVersion: version, pushId: pushId.Bytes()}}, newest: version}
	return version
}

// A file entry over chain, whose sealed fields name content, sealed under the push's generation.
func (self *evsTestWorld) chainEntry(content []byte, fileId Id, chain []*protocol.EvsLocator, pushId Id, baseVersion uint64, version uint64) []byte {
	keys := evsTestKeys(self.t, self.repoId, self.generation)
	oid, _ := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
	sealedFields, err := EvsSealFields(keys.manifest, &protocol.EvsSealedFields{
		FileId: fileId.Bytes(), Mode: 0o100644, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: uint64(len(content)),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	entryBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: version, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: 1767225600000,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: EvsPadme(uint64(len(content))),
		SealedFields: sealedFields, Chain: chain,
	})
	return entryBytes
}

// A record header of kind giving content's oid.
func evsTestRecordHeader(kind protocol.EvsRecordKind, generation uint64, content []byte) *EvsRecordHeader {
	oid, _ := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
	header := &EvsRecordHeader{
		RecordId: NewEvsSlotId(), Generation: generation, Kind: kind,
		KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
	}
	copy(header.Oid[:], oid[:])
	return header
}

// Content that a delta can shorten.
func evsTestContent(label string, byteCount int) []byte {
	content := make([]byte, byteCount)
	for i := range content {
		content[i] = byte('a' + (i/7+len(label))%26)
	}
	return content
}

// A checkpoint in a segment of generation 1 and a diff on it in a segment of generation 2, the entry pushed at
// generation 2: the ladder opens each record under its own segment's generation.
func TestEvsReconstructAcrossACheckpointAndAGenerationChange(t *testing.T) {
	world := newEvsTestWorld(t)
	base := evsTestContent("base", 100*1024)
	target := append(bytes.Clone(base[:60*1024]), append([]byte("an edit in the middle"), base[60*1024:]...)...)
	fileId := NewEvsSlotId()
	checkpoint := evsTestRecordHeader(protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 1, base)
	first := world.segmentRecord(evsTestKeys(t, world.repoId, 1), fileId, checkpoint, base)
	delta := &bytes.Buffer{}
	if err := EvsGitDeltaEncode(bytes.NewReader(base), bytes.NewReader(target), delta, DefaultEvsGitDeltaSettings()); err != nil {
		t.Fatal(err)
	}
	diff := evsTestRecordHeader(protocol.EvsRecordKind_EVS_RECORD_DIFF, 2, target)
	diff.BaseRecordId = checkpoint.RecordId
	second := world.segmentRecord(evsTestKeys(t, world.repoId, 2), fileId, diff, delta.Bytes())
	world.generation = 2
	world.gkm.newest = 2
	world.pushEntry("big.bin", func(pushId Id, baseVersion uint64, version uint64) []byte {
		return world.chainEntry(target, fileId, []*protocol.EvsLocator{first, second}, pushId, baseVersion, version)
	})
	reader := world.reader(t, evsTestId("reader"))
	content, info, err := evsTestRead(t, reader, world, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, target) || info.Size != uint64(len(target)) {
		t.Errorf("reconstructed %d bytes, want %d", len(content), len(target))
	}
}

// A file larger than the memory bound reads through the sealed spill, which is gone once the read is.
func TestEvsReadSpillsPastTheMemoryBound(t *testing.T) {
	world := newEvsTestWorld(t)
	content := evsTestContent("large", 300*1024)
	world.push(&evsTestChange{path: "large.bin", content: content, segment: true})
	reader := world.reader(t, evsTestId("reader"))
	reader.client.settings.DeltaBaseMemoryByteCount = 64 * 1024
	read, _, err := evsTestRead(t, reader, world, "large.bin")
	if err != nil || !bytes.Equal(read, content) {
		t.Fatalf("read %d bytes: %v", len(read), err)
	}
	entries, err := reader.client.args.Store.List(evsSpillDirectory)
	if err != nil || len(entries) != 0 {
		t.Errorf("spill left: %d %v", len(entries), err)
	}
}

// A large file's chunk records concatenate in order.
func TestEvsChunkRecordsConcatenate(t *testing.T) {
	world := newEvsTestWorld(t)
	first, second := evsTestContent("chunk one", 70*1024), evsTestContent("chunk two", 50*1024)
	whole := append(bytes.Clone(first), second...)
	fileId := NewEvsSlotId()
	keys := evsTestKeys(t, world.repoId, 1)
	locators := []*protocol.EvsLocator{
		world.segmentRecord(keys, fileId, evsTestRecordHeader(protocol.EvsRecordKind_EVS_RECORD_CHUNK, 1, first), first),
		world.segmentRecord(keys, fileId, evsTestRecordHeader(protocol.EvsRecordKind_EVS_RECORD_CHUNK, 1, second), second),
	}
	world.pushEntry("chunked.bin", func(pushId Id, baseVersion uint64, version uint64) []byte {
		return world.chainEntry(whole, fileId, locators, pushId, baseVersion, version)
	})
	read, _, err := evsTestRead(t, world.reader(t, evsTestId("reader")), world, "chunked.bin")
	if err != nil || !bytes.Equal(read, whole) {
		t.Fatalf("read %d bytes: %v", len(read), err)
	}
}

// Content evs answers missing for a path's newest version alarms missing_segment, and nothing is shown.
func TestEvsMissingSegmentAlarms(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.bin", content: []byte("held in a segment"), segment: true})
	world.missingObjects = true
	reader := world.reader(t, evsTestId("reader"))
	read, _, err := evsTestRead(t, reader, world, "a.bin")
	if !errors.Is(err, ErrEvsObjectMissing) || len(read) != 0 {
		t.Fatalf("a missing segment: %v, %d bytes", err, len(read))
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 1 || alarms[0].EvsAlarm != SidecarEvsAlarmMissingSegment {
		t.Errorf("alarms %v", alarms)
	}
}

// A removed path reads as absent, its removal checked against the statement that made it.
func TestEvsRemovalReadsAbsent(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("here")})
	world.push(&evsTestChange{path: "a.txt"})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("a removed path: %v", err)
	}
	world.mutatePath = func(reply *protocol.EvsReadPathReply) { reply.Removal.PathVersion = 7 }
	if _, _, err := evsTestRead(t, world.reader(t, evsTestId("other reader")), world, "a.txt"); !errors.Is(err, ErrEvsVersionRule) {
		t.Errorf("a marker off its statement: %v", err)
	}
}

// List opens every row against its token, and refuses a table whose row was moved to another child.
func TestEvsListChecksEachNameAgainstItsToken(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(
		&evsTestChange{path: "d", children: []string{"b", "a"}},
		&evsTestChange{path: "d/a", content: []byte("a")},
		&evsTestChange{path: "d/b", content: []byte("b")},
	)
	reader := world.reader(t, evsTestId("reader"))
	listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range listing.Entries {
		names = append(names, string(entry.Name))
	}
	if strings.Join(names, ",") != "a,b" {
		t.Errorf("listed %v", names)
	}
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if reply.Names != nil && 1 < len(reply.Names.Names) {
			rows := reply.Names.Names
			rows[0].SealedName, rows[1].SealedName = rows[1].SealedName, rows[0].SealedName
		}
	}
	if _, err := world.reader(t, evsTestId("other reader")).client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"}); err == nil {
		t.Errorf("swapped names listed")
	}
	if _, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: ""}); err == nil ||
		!strings.Contains(err.Error(), "evs1-m2-24-root-directory-names") {
		t.Errorf("the root: %v", err)
	}
}

// History gives a path's versions newest first, each verified against its own statement.
func TestEvsHistoryWalksVersions(t *testing.T) {
	world := newEvsTestWorld(t)
	for _, content := range []string{"one", "two", "three"} {
		world.push(&evsTestChange{path: "a.txt", content: []byte(content)})
	}
	reader := world.reader(t, evsTestId("reader"))
	history, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	versions := []uint64{}
	for _, version := range history.Versions {
		versions = append(versions, version.Version)
		if version.State != "kept" || version.SignerSidecarId != world.signer.sidecarId {
			t.Errorf("version %+v", version)
		}
	}
	if fmt.Sprint(versions) != "[3 2 1]" {
		t.Errorf("versions %v", versions)
	}
}

// A format-2 read state answers FORMAT_UNSUPPORTED for that path, never a fork or tampering.
func TestEvsFormatTwoReadStateUnsupported(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
	}
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Fatalf("a format-2 state: %v", err)
	}
	if 0 < len(reader.eventsOf(SidecarEventEvsAlarm))+len(reader.eventsOf(SidecarEventHeadAlarm)) {
		t.Errorf("a format-2 state alarmed")
	}
}

// A reader of an owner-bound repo that does not write it is refused before anything is decrypted until the receipt
// gate is wired; once it is, the gate sees the objects first.
func TestEvsReceiptGateFailsClosed(t *testing.T) {
	world := newEvsTestWorld(t)
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_VAULT
	world.push(&evsTestChange{path: "a.txt", content: []byte("secret")})
	reader := world.reader(t, evsTestId("audit reader"))
	read, _, err := evsTestRead(t, reader, world, "a.txt")
	if !errors.Is(err, ErrEvsReceiptGate) || len(read) != 0 {
		t.Fatalf("an owner-bound read with no gate: %v", err)
	}
	gated := 0
	reader.client.SetPreDecrypt(func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
		gated += 1
		return nil
	})
	read, _, err = evsTestRead(t, reader, world, "a.txt")
	if err != nil || string(read) != "secret" || gated != 1 {
		t.Errorf("through the gate: %q %v %d", read, err, gated)
	}
}
