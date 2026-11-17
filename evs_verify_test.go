// EVS1-M2-23's tests on the stand-in evs (evs_world_test.go), FS-10 on T2: a forged entry refused; a rollback of a path
// changed after the pin refused; a never-read path's older version accepted, as §2.8 publishes; a reader far behind
// re-pinning with a gap mark; a fork and a rollback of the head refused and alarmed; a statement by a non-writer, a
// broken chain and a git-mode push off its tip refused; adjacent-leaf proofs for a large push; a reseed lowering a pin
// as a loss, and the ref's read records with it (QD-816); HeadCheck's ref source; a removed path read through a
// prefix's later removal, inline and under changes_root, created again by a writer pinned before both removals, and a
// write after them served as removed still refused (QD-978); and a path served plain absent once its removal paged
// out, read as absent where the walk's newest change of it, or of a prefix, is a removal, by a reader holding its
// record and by the writer that removed it, which creates it again at b + 1, and refused and alarmed where that newest
// change is a write, inline and under changes_root (QD-979).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Reads path from the world's main ref as reader, its content.
func evsTestRead(t *testing.T, reader *evsTestClient, world *evsTestWorld, path string) ([]byte, *EvsFileInfo, error) {
	t.Helper()
	out := &bytes.Buffer{}
	info, err := reader.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	return out.Bytes(), info, err
}

// A verified read pins the head, records the path, and gives the content its signer wrote.
func TestEvsVerifiedReadPinsAndRecords(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("first")})
	version := world.push(&evsTestChange{path: "a.txt", content: []byte("second")})
	reader := world.reader(t, evsTestId("reader"))
	content, info, err := evsTestRead(t, reader, world, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "second" || info.Version != 2 || info.CommitVersion != version || info.SignerSidecarId != world.signer.sidecarId {
		t.Errorf("read %q %+v", content, info)
	}
	pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId)
	_, headChain := world.head()
	if !ok || pin.Version != version || pin.Chain != headChain {
		t.Errorf("pin %+v", pin)
	}
	record, ok, _ := reader.client.pins.ReadRecord(world.repoId, world.refId, "a.txt")
	if !ok || record.EntryVersion != 2 || record.PinVersion != version {
		t.Errorf("record %+v", record)
	}
}

// An entry that does not hash to its statement's entry_sha256 is refused and alarmed as tampering.
func TestEvsForgedEntryRefused(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("honest")})
	forged := world.fileEntry([]byte("forged"), false, 1, evsTestId(fmt.Sprint("world push ", 1, " ", 1)), 0, nil)
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		reply.Version.EntryVersion = forged
	}
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("a forged entry: %v", err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) == 0 || alarms[0].EvsAlarm != SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
	if _, ok, _ := reader.client.pins.ReadRecord(world.repoId, world.refId, "a.txt"); ok {
		t.Errorf("a refused read left a record")
	}
}

// A path read once, then changed twice, is refused when evs serves its older version as current: the read record
// moves the request's pin back to the last read, so the later statements that change it are checked.
func TestEvsRollbackOfAReadPathRefused(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("v1")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "a.txt", content: []byte("v2")})
	world.push(&evsTestChange{path: "b.txt", content: []byte("other")})
	// the reader's ref pin moves past the change to a.txt by reading another path
	if _, _, err := evsTestRead(t, reader, world, "b.txt"); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "a.txt", content: []byte("v3")})
	world.serveVersion["a.txt"] = 2
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("a rollback past a later change: %v", err)
	}
	world.serveVersion = map[string]uint64{}
	content, _, err := evsTestRead(t, reader, world, "a.txt")
	if err != nil || string(content) != "v3" {
		t.Fatalf("the honest read: %q %v", content, err)
	}
	// below the record itself: refused even with no later statement to show it
	world.serveVersion["a.txt"] = 1
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {}
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err == nil {
		t.Errorf("a version below the record")
	}
}

// A path this device never read, changed at or below its first pin, may be served at an older version: §2.8's
// disclosed limit (Q-EVS-6). The reader accepts it, and claims nothing more.
func TestEvsNeverReadPathOlderVersionAccepted(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "p.txt", content: []byte("old")})
	world.push(&evsTestChange{path: "p.txt", content: []byte("new")})
	world.push(&evsTestChange{path: "q.txt", content: []byte("q")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "q.txt"); err != nil {
		t.Fatal(err)
	}
	world.serveVersion["p.txt"] = 1
	content, info, err := evsTestRead(t, reader, world, "p.txt")
	if err != nil || string(content) != "old" || info.Version != 1 {
		t.Errorf("a never-read path's older version: %q %+v %v", content, info, err)
	}
}

// A reader far behind its catch-up budget re-pins at the head, marks the gap and raises evs_gap; one within it
// pages the log and verifies every statement.
func TestEvsReaderFarBehindRepinsWithGapMark(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "a.txt", content: []byte("start")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		world.push(&evsTestChange{path: fmt.Sprint("f", i), content: []byte("x")})
	}
	// within budget: the log pages and every statement verifies
	if _, _, err := evsTestRead(t, reader, world, "f39"); err != nil {
		t.Fatal(err)
	}
	if world.logPageCount == 0 {
		t.Errorf("the log was not paged")
	}
	if !reader.client.Repo(world.repoId).VerifiedSince(world.refId).IsZero() {
		t.Errorf("a gap within the budget")
	}
	for i := range 40 {
		world.push(&evsTestChange{path: fmt.Sprint("g", i), content: []byte("x")})
	}
	reader.client.settings.CatchUpByteCount = 2 * 1024
	if _, _, err := evsTestRead(t, reader, world, "g39"); err != nil {
		t.Fatal(err)
	}
	since := reader.client.Repo(world.repoId).VerifiedSince(world.refId)
	if since.IsZero() {
		t.Errorf("no gap mark")
	}
	gaps := reader.eventsOf(SidecarEventEvsGap)
	if len(gaps) != 1 || !gaps[0].VerifiedSince.Equal(since) {
		t.Errorf("gap events %v", gaps)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if version, _ := world.head(); pin.Version != version {
		t.Errorf("not re-pinned at the head: %d", pin.Version)
	}
}

// A head below the pin, and one at the pin's version with another chain, are forks: refused, alarmed with both
// RefHeads, and the pin untouched.
func TestEvsForkAndRollbackOfTheHeadRefused(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatal(err)
	}
	firstChain := world.commits[0].chain
	world.headOverride = &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 1, Chain: firstChain[:], PathEpoch: &protocol.EvsPathEpoch{Current: 1}}
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("a head below the pin: %v", err)
	}
	other := evsTestBytes("another chain", 32)
	world.headOverride = &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 2, Chain: other, PathEpoch: &protocol.EvsPathEpoch{Current: 1}}
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("a fork at the pin: %v", err)
	}
	forks := reader.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 2 || forks[0].HeadAlarm != SidecarHeadAlarmFork || forks[0].SidecarId != nil {
		t.Fatalf("fork alarms %v", forks)
	}
	mine := &protocol.RefHead{}
	if err := proto.Unmarshal(forks[0].Evidence[0], mine); err != nil || mine.GetVersion() != 2 {
		t.Errorf("evidence %v", mine)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 2 {
		t.Errorf("the pin moved: %d", pin.Version)
	}
}

// A statement signed by a sidecar the config does not list as a writer, or whose bytes were changed after signing,
// never counts toward a head; a statement missing from the chain breaks it.
func TestEvsStatementsOfNonWritersAndBrokenChainsRefused(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	reader := world.reader(t, evsTestId("reader"))
	world.config.stateLock.Lock()
	world.config.writers = nil
	world.config.stateLock.Unlock()
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a non-writer's statement: %v", err)
	}
	world.config.stateLock.Lock()
	world.config.writers = []Id{world.signer.sidecarId}
	world.config.identityKeys[world.signer.sidecarId] = ed25519.NewKeyFromSeed(evsTestBytes("someone else", 32)).Public().(ed25519.PublicKey)
	world.config.stateLock.Unlock()
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a signature by another key: %v", err)
	}
	world.config.stateLock.Lock()
	world.config.identityKeys[world.signer.sidecarId] = world.signer.publicKey()
	world.config.stateLock.Unlock()
	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("3")})
	world.omitVersion = 2
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsChainBroken) {
		t.Fatalf("a statement left out: %v", err)
	}
	world.omitVersion = 0
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatalf("the honest chain: %v", err)
	}
}

// The walk's rules: a git-mode push off its tip, a file-mode push past the 64-version bound, a falling authorization
// pin and a path epoch moved without a PATH_EPOCH push are refused.
func TestEvsWalkRulesRefuse(t *testing.T) {
	repoId, refId := evsTestId("repo"), evsTestId("ref")
	statementOf := func(push *protocol.EvsPush) *EvsVerifiedStatement {
		return &EvsVerifiedStatement{Version: 0, Statement: &EvsStatement{Push: push}}
	}
	base := func(version uint64, mode protocol.EvsRefMode) *protocol.EvsPush {
		return &protocol.EvsPush{
			RepoId: repoId.Bytes(), RefId: refId.Bytes(), RefMode: uint32(mode), RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED),
			BaseVersion: version - 1, Auth: &bridge.AuthPin{Version: 5, Chain: evsTestBytes("a", 32)}, PathEpoch: 1, Generation: 1,
		}
	}
	walk := func(pushes ...*protocol.EvsPush) error {
		walked := []*EvsVerifiedStatement{}
		chain := EvsChainStart(repoId, refId)
		for i, push := range pushes {
			statement := statementOf(push)
			statement.Version = uint64(i + 1)
			push.BaseChain = nil
			if push.GetBaseVersion() == uint64(i) && 0 < i {
				previous := walked[i-1].Chain
				push.BaseChain = previous[:]
			}
			chain = sha256.Sum256(append(chain[:], byte(i)))
			statement.Chain = chain
			walked = append(walked, statement)
		}
		return evsCheckWalkRules(walked, 0, EvsChainStart(repoId, refId))
	}
	if err := walk(base(1, protocol.EvsRefMode_EVS_REF_GIT), base(2, protocol.EvsRefMode_EVS_REF_GIT)); err != nil {
		t.Fatalf("an honest git-mode walk: %v", err)
	}
	offTip := base(2, protocol.EvsRefMode_EVS_REF_GIT)
	offTip.BaseVersion = 0
	if err := walk(base(1, protocol.EvsRefMode_EVS_REF_GIT), offTip); !errors.Is(err, ErrEvsChainBroken) {
		t.Errorf("a git-mode push off its tip: %v", err)
	}
	pushes := []*protocol.EvsPush{}
	for version := uint64(1); version <= 70; version += 1 {
		pushes = append(pushes, base(version, protocol.EvsRefMode_EVS_REF_FILE))
	}
	pushes[69].BaseVersion = 5
	if err := walk(pushes...); !errors.Is(err, ErrEvsChainBroken) {
		t.Errorf("a push past the 64-version bound: %v", err)
	}
	fell := base(2, protocol.EvsRefMode_EVS_REF_FILE)
	fell.Auth = &bridge.AuthPin{Version: 4, Chain: evsTestBytes("b", 32)}
	if err := walk(base(1, protocol.EvsRefMode_EVS_REF_FILE), fell); !errors.Is(err, ErrEvsChainBroken) {
		t.Errorf("a falling auth pin: %v", err)
	}
	moved := base(2, protocol.EvsRefMode_EVS_REF_FILE)
	moved.PathEpoch = 2
	if err := walk(base(1, protocol.EvsRefMode_EVS_REF_FILE), moved); !errors.Is(err, ErrEvsChainBroken) {
		t.Errorf("an epoch moved without PATH_EPOCH: %v", err)
	}
	moved.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
	if err := walk(base(1, protocol.EvsRefMode_EVS_REF_FILE), moved); err != nil {
		t.Errorf("a PATH_EPOCH push: %v", err)
	}
}

// A path a 1,200-change push left alone, though the push's covering prefixes reach it, is verified by adjacent-leaf
// proofs with no change list fetched; the same read with the proofs dropped is refused. The reader read the path
// before the push, so its record's pin walks the push; a reader with no pin pins the head in its first round
// (DESIGN-DETAILS 9.2.4) and takes a never-read path's version on evs's word (Q-EVS-6).
func TestEvsAbsenceProofsForALargePush(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "d/keep.txt", content: []byte("kept")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "d/keep.txt"); err != nil {
		t.Fatal(err)
	}
	changes := []*evsTestChange{}
	for i := range 40 {
		changes = append(changes, &evsTestChange{path: fmt.Sprint("d/many", i), content: []byte("m")})
	}
	world.push(changes...)
	if world.commits[1].built.ChangeTree == nil {
		t.Fatalf("the large push's changes are inline")
	}
	world.mutatePath = func(reply *protocol.EvsReadPathReply) { reply.Absences = nil }
	if _, _, err := evsTestRead(t, reader, world, "d/keep.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("no proofs: %v", err)
	}
	world.mutatePath = nil
	content, _, err := evsTestRead(t, reader, world, "d/keep.txt")
	if err != nil || string(content) != "kept" {
		t.Fatalf("with proofs: %q %v", content, err)
	}
}

// A head below the pin is refused, unless a repo admin's verified EvsReseed names exactly that head, which lowers the
// pin, kept as a loss; a reseed by a non-admin, or of another head, is refused.
func TestEvsReseedLowersThePinAsALoss(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatal(err)
	}
	lowChain := world.commits[0].chain
	low := &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 1, Chain: lowChain[:]}
	reseed := func(signer *evsTestSigner, version uint64) []byte {
		body, _ := proto.Marshal(&protocol.EvsReseed{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), Version: version, Chain: lowChain[:], IncidentId: []byte("incident")})
		signed, _ := signer.sign(evsReseedPurpose, bridge.SignedType_SIGNED_EVS_RESEED, body, nil)
		signedBytes, _ := proto.Marshal(signed)
		return signedBytes
	}
	verifier := reader.client.verifier
	if err := verifier.AcceptReseed(reseed(world.signer, 1), world.repoId, world.refId, low); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a non-admin's reseed: %v", err)
	}
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	if err := verifier.AcceptReseed(reseed(world.signer, 2), world.repoId, world.refId, low); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a reseed of another head: %v", err)
	}
	if err := verifier.AcceptReseed(reseed(world.signer, 1), world.repoId, world.refId, low); err != nil {
		t.Fatal(err)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 1 || pin.Loss == nil || pin.Loss.FromVersion != 2 {
		t.Errorf("after the reseed: %+v", pin)
	}
}

// A verified EvsReseed takes the ref's read records with its pin (QD-816): a record whose entry was committed above
// the re-seeded head is dropped; one committed at or below it keeps its entry and commit versions, its pin lowered to
// the head, C there and the head's current epoch, and a floor the lost versions raised past that epoch lowered to it;
// one pinned at or below the head stands as it was; a record stored before the commit version was kept is dropped
// when pinned above the head and kept when not; another ref's records, and another repo's, do not change. The records
// stand so when the store opens again; a read that pinned a lost head raises no record once the pin fell; the
// listings cached at lost heads and the version this device committed at above the head go; and the same reseed
// again keeps the loss.
func TestEvsReseedDropsTheLostRecordsAndLowersTheRest(t *testing.T) {
	world := newEvsTestWorld(t)
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	store := newEvsTestStore(t)
	reader := evsTestReaderThrough(t, world, world, store, world.gkm, evsTestId("reader"))
	pins := reader.client.pins
	repoId, refId := world.repoId, world.refId
	otherRepoId, otherRefId := evsTestId("other repo"), evsTestId("other ref")
	at := time.Date(2026, time.November, 14, 0, 0, 0, 0, time.UTC)
	chainAt := func(version uint64) [sha256.Size]byte {
		return [sha256.Size]byte(evsTestBytes(fmt.Sprint("chain ", version), sha256.Size))
	}
	for _, pin := range []*EvsPin{{RepoId: repoId, RefId: refId}, {RepoId: repoId, RefId: otherRefId}, {RepoId: otherRepoId, RefId: refId}} {
		pin.Version, pin.Chain, pin.PinnedAt, pin.GroupId = 9, chainAt(9), at, evsTestId("group")
		if err := pins.Raise(pin); err != nil {
			t.Fatal(err)
		}
	}
	record := func(refId Id, path string, entryVersion uint64, commitVersion uint64, pinVersion uint64, floor uint64, pinEpoch uint64) *EvsReadRecord {
		chain := chainAt(pinVersion)
		return &EvsReadRecord{RefId: refId, Path: path, EntryVersion: entryVersion, CommitVersion: commitVersion,
			PinVersion: pinVersion, PinChain: &chain, UsedAt: at, Floor: floor, PinEpoch: pinEpoch}
	}
	if err := pins.RaiseReadRecords(repoId, []*EvsReadRecord{
		record(refId, "lost.txt", 7, 7, 9, 3, 3),
		record(refId, "kept.txt", 4, 4, 9, 3, 3),
		record(refId, "head.txt", 5, 5, 9, 1, 3),
		record(refId, "below.txt", 2, 2, 4, 1, 1),
		record(refId, "no-floor.txt", 3, 3, 9, 0, 3),
		record(refId, "old-above.txt", 3, 0, 9, 1, 3),
		record(refId, "old-at.txt", 3, 0, 5, 1, 2),
		record(otherRefId, "lost.txt", 7, 7, 9, 3, 3),
	}); err != nil {
		t.Fatal(err)
	}
	if err := pins.RaiseReadRecords(otherRepoId, []*EvsReadRecord{record(refId, "lost.txt", 7, 7, 9, 3, 3)}); err != nil {
		t.Fatal(err)
	}
	epochs := reader.client.epochs
	epochs.noteCommitted(repoId, refId, 9)
	for _, listed := range []struct {
		refId   Id
		version uint64
	}{{refId: refId, version: 4}, {refId: refId, version: 7}, {refId: otherRefId, version: 7}} {
		epochs.cacheListing(repoId, listed.refId, "d", &evsListedDirectory{headVersion: listed.version}, reader.client.settings.ListingCacheCount)
	}

	// the re-seeded head at 5, in path epoch 2, where the lost versions had cut the ref over to 3
	headChain := chainAt(5)
	head := &protocol.EvsHeadSummary{RefId: refId.Bytes(), Version: 5, Chain: headChain[:], PathEpoch: &protocol.EvsPathEpoch{Current: 2}}
	statement, err := SignEvsReseed(world.signer.sign, repoId, refId, 5, headChain, []byte("incident"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.client.verifier.AcceptReseed(statement, repoId, refId, head); err != nil {
		t.Fatal(err)
	}
	expect := func(store *EvsPinStore, repoId Id, refId Id, path string, want *EvsReadRecord) {
		t.Helper()
		got, ok, err := store.ReadRecord(repoId, refId, path)
		switch {
		case err != nil:
			t.Fatal(err)
		case want == nil && ok:
			t.Errorf("%s stands: %+v", path, got)
		case want != nil && !ok:
			t.Errorf("%s is gone", path)
		case want != nil && (got.EntryVersion != want.EntryVersion || got.CommitVersion != want.CommitVersion ||
			got.PinVersion != want.PinVersion || got.PinChain == nil || *got.PinChain != *want.PinChain ||
			got.Floor != want.Floor || got.PinEpoch != want.PinEpoch):
			t.Errorf("%s: %+v, want %+v", path, got, want)
		}
	}
	expectAll := func(store *EvsPinStore) {
		t.Helper()
		expect(store, repoId, refId, "lost.txt", nil)
		expect(store, repoId, refId, "kept.txt", record(refId, "kept.txt", 4, 4, 5, 2, 2))
		expect(store, repoId, refId, "head.txt", record(refId, "head.txt", 5, 5, 5, 1, 2))
		expect(store, repoId, refId, "below.txt", record(refId, "below.txt", 2, 2, 4, 1, 1))
		expect(store, repoId, refId, "no-floor.txt", record(refId, "no-floor.txt", 3, 3, 5, 0, 2))
		expect(store, repoId, refId, "old-above.txt", nil)
		expect(store, repoId, refId, "old-at.txt", record(refId, "old-at.txt", 3, 0, 5, 1, 2))
		expect(store, repoId, otherRefId, "lost.txt", record(otherRefId, "lost.txt", 7, 7, 9, 3, 3))
		expect(store, otherRepoId, refId, "lost.txt", record(refId, "lost.txt", 7, 7, 9, 3, 3))
		for _, pinned := range []struct {
			repoId  Id
			refId   Id
			version uint64
		}{{repoId: repoId, refId: refId, version: 5}, {repoId: repoId, refId: otherRefId, version: 9}, {repoId: otherRepoId, refId: refId, version: 9}} {
			pin, ok, err := store.Pin(pinned.repoId, pinned.refId)
			if err != nil || !ok || pin.Version != pinned.version || pin.Chain != chainAt(pinned.version) {
				t.Errorf("the pin of %s: %+v %v", pinned.refId, pin, err)
			}
		}
	}
	expectAll(pins)
	expectAll(NewEvsPinStore(store, DefaultEvsSettings()))
	pin, _, _ := pins.Pin(repoId, refId)
	if pin.Loss == nil || pin.Loss.FromVersion != 9 || pin.GroupId != evsTestId("group") {
		t.Fatalf("the lowered pin: %+v, loss %+v", pin, pin.Loss)
	}

	// a read that pinned the lost head before the reseed and raises its records after it raises none of that head's
	if err := pins.RaiseReadRecords(repoId, []*EvsReadRecord{record(refId, "late.txt", 8, 8, 9, 3, 3), record(refId, "after.txt", 2, 2, 5, 1, 2)}); err != nil {
		t.Fatal(err)
	}
	expect(pins, repoId, refId, "late.txt", nil)
	expect(pins, repoId, refId, "after.txt", record(refId, "after.txt", 2, 2, 5, 1, 2))

	if committed := epochs.committedVersion(repoId, refId); committed != 5 {
		t.Errorf("the version this device committed at after the reseed: %d", committed)
	}
	if epochs.cachedListing(repoId, refId, 4, "d") == nil || epochs.cachedListing(repoId, refId, 7, "d") != nil ||
		epochs.cachedListing(repoId, otherRefId, 7, "d") == nil {
		t.Errorf("the listings after the reseed: at the head's 4 %v, at a lost 7 %v, another ref's 7 %v",
			epochs.cachedListing(repoId, refId, 4, "d") != nil, epochs.cachedListing(repoId, refId, 7, "d") != nil,
			epochs.cachedListing(repoId, otherRefId, 7, "d") != nil)
	}

	// a second read that met the same head before the first lowered the pin keeps the loss
	if err := reader.client.verifier.AcceptReseed(statement, repoId, refId, head); err != nil {
		t.Fatal(err)
	}
	pin, _, _ = pins.Pin(repoId, refId)
	if pin.Version != 5 || pin.Loss == nil || pin.Loss.FromVersion != 9 || pin.GroupId != evsTestId("group") {
		t.Fatalf("the pin after the same reseed again: %+v, loss %+v", pin, pin.Loss)
	}
	expect(pins, repoId, refId, "kept.txt", record(refId, "kept.txt", 4, 4, 5, 2, 2))
	if pins.reseedCount(repoId, refId) != 2 || pins.reseedCount(repoId, otherRefId) != 0 {
		t.Errorf("reseeds counted: %d, another ref's %d", pins.reseedCount(repoId, refId), pins.reseedCount(repoId, otherRefId))
	}
}

// A read record stored before the commit version was kept opens with none and its other fields as stored, and a
// verified EvsReseed takes it by its pin alone (QD-816's fallback): pinned above the re-seeded head it is dropped, at
// or below it kept as it is.
func TestEvsReadRecordsStoredBeforeTheCommitVersionOpenAndFallBack(t *testing.T) {
	world := newEvsTestWorld(t)
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	store := newEvsTestStore(t)
	chain := evsTestBytes("chain 9", sha256.Size)
	// the stored form as it was before commit_version
	stored := fmt.Sprintf(`[{"ref_id":%q,"path":"above.txt","entry_version":3,"pin_version":9,"pin_chain":%q,"used_at_ms":1767225600000,"floor":1,"pin_epoch":1},`+
		`{"ref_id":%q,"path":"below.txt","entry_version":2,"pin_version":4,"used_at_ms":1767225600000}]`,
		world.refId.String(), hex.EncodeToString(chain), world.refId.String())
	writer, err := store.Create(evsReadDirectory + world.repoId.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(stored)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()

	reader := evsTestReaderThrough(t, world, world, store, world.gkm, evsTestId("reader"))
	pins := reader.client.pins
	above, ok, err := pins.ReadRecord(world.repoId, world.refId, "above.txt")
	if err != nil || !ok || above.CommitVersion != 0 || above.EntryVersion != 3 || above.PinVersion != 9 || above.PinChain == nil ||
		!bytes.Equal(above.PinChain[:], chain) || above.Floor != 1 || above.PinEpoch != 1 || !above.UsedAt.Equal(time.UnixMilli(1767225600000)) {
		t.Fatalf("a record stored before the commit version: %+v %v %v", above, ok, err)
	}
	below, ok, err := pins.ReadRecord(world.repoId, world.refId, "below.txt")
	if err != nil || !ok || below.CommitVersion != 0 || below.EntryVersion != 2 || below.PinVersion != 4 || below.PinChain != nil || below.Floor != 0 {
		t.Fatalf("a record stored before the chain and the commit version: %+v %v %v", below, ok, err)
	}
	if err := pins.Raise(&EvsPin{RepoId: world.repoId, RefId: world.refId, Version: 9, Chain: [sha256.Size]byte(chain)}); err != nil {
		t.Fatal(err)
	}
	headChain := [sha256.Size]byte(evsTestBytes("chain 5", sha256.Size))
	statement, err := SignEvsReseed(world.signer.sign, world.repoId, world.refId, 5, headChain, []byte("incident"))
	if err != nil {
		t.Fatal(err)
	}
	head := &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 5, Chain: headChain[:]}
	if err := reader.client.verifier.AcceptReseed(statement, world.repoId, world.refId, head); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := pins.ReadRecord(world.repoId, world.refId, "above.txt"); ok {
		t.Errorf("a record of no commit version read above the head stands")
	}
	if record, ok, _ := pins.ReadRecord(world.repoId, world.refId, "below.txt"); !ok || record.EntryVersion != 2 || record.PinVersion != 4 || record.PinChain != nil {
		t.Errorf("a record of no commit version read below the head: %+v %v", record, ok)
	}
}

// HeadCheck's ref source: the pins of repos the peer reads, at most 16 a call and rotating; a forward read that
// reaches the peer's head pins it, and one whose chain misses it is a fork.
func TestEvsRefSourceRotatesAndCatchesUp(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatal(err)
	}
	peerId := evsTestId("peer")
	if heads := reader.client.RefHeads(peerId); len(heads) != 0 {
		t.Errorf("a peer that reads nothing got %d", len(heads))
	}
	world.config.stateLock.Lock()
	world.config.readers = append(world.config.readers, peerId)
	world.config.stateLock.Unlock()
	for i := range 20 {
		if err := reader.client.pins.Raise(&EvsPin{RepoId: world.repoId, RefId: evsTestId(fmt.Sprint("ref ", i)), Version: 1}); err != nil {
			t.Fatal(err)
		}
	}
	first := reader.client.RefHeads(peerId)
	second := reader.client.RefHeads(peerId)
	if len(first) != HeadCheckMaxListCount || len(second) != HeadCheckMaxListCount || bytes.Equal(first[0].GetRefId(), second[0].GetRefId()) {
		t.Errorf("rotation: %d, %d", len(first), len(second))
	}
	if ref, ok := reader.client.RefHead(world.repoId, world.refId); !ok || ref.Head.GetVersion() != 1 || ref.GroupId != evsTestId("world group") {
		t.Errorf("ref head %+v", ref)
	}

	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("3")})
	version, chain := world.head()
	through := &protocol.RefHead{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), Version: version, Chain: chain[:]}
	if result, err := reader.client.CatchUpRef(context.Background(), through); result != HeadCheckCaughtUp || err != nil {
		t.Fatalf("catch up: %v %v", result, err)
	}
	if pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId); pin.Version != version {
		t.Errorf("not pinned at the peer's head")
	}
	world.push(&evsTestChange{path: "a.txt", content: []byte("4")})
	forked := &protocol.RefHead{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), Version: version + 1, Chain: evsTestBytes("elsewhere", 32)}
	if result, _ := reader.client.CatchUpRef(context.Background(), forked); result != HeadCheckCatchUpForked {
		t.Errorf("a fork: %v", result)
	}
}

// Replaying readers hold each change to §11.7's versions row: a write off its base, a creation not at max(b, m) + 1
// and a creation of a standing path are refused.
func TestEvsReplayPathsVersionRules(t *testing.T) {
	signer := newEvsTestSigner("replay")
	tokenPath := EvsTokenPath{evsTestToken("p")}
	apply := func(replay *EvsReplayPaths, baseVersion uint64, baseEntryVersion uint64, version uint64, removes bool) error {
		pushId := evsTestId(fmt.Sprint("replay push ", baseVersion, version))
		push := &protocol.EvsPush{PushId: pushId.Bytes(), BaseVersion: baseVersion, SignerSidecarId: signer.sidecarId.Bytes()}
		change := &protocol.EvsChange{TokenPath: tokenPath.Components(), BaseEntryVersion: baseEntryVersion}
		entries := map[string][]byte{}
		if !removes {
			entryBytes, _ := proto.Marshal(&protocol.EvsEntryVersion{Version: version, PushId: pushId.Bytes(), BaseVersion: baseVersion})
			digest := sha256.Sum256(entryBytes)
			change.EntrySha256 = digest[:]
			entries[tokenPath.KeyString()] = entryBytes
		}
		statement := &EvsVerifiedStatement{Statement: &EvsStatement{Push: push}}
		return replay.Apply(statement, []*EvsCheckedChange{{Change: change, TokenPath: tokenPath}}, entries)
	}
	replay := NewEvsReplayPaths(0)
	if err := apply(replay, 4, 0, 5, false); err != nil {
		t.Fatalf("a creation at b + 1: %v", err)
	}
	if err := apply(replay, 5, 0, 7, false); !errors.Is(err, ErrEvsVersionRule) {
		t.Errorf("a creation of a standing path: %v", err)
	}
	if err := apply(replay, 6, 4, 5, false); !errors.Is(err, ErrEvsVersionRule) {
		t.Errorf("a write off the newest: %v", err)
	}
	if err := apply(replay, 6, 5, 6, true); err != nil {
		t.Fatalf("a removal: %v", err)
	}
	if err := apply(replay, 3, 0, 4, false); !errors.Is(err, ErrEvsVersionRule) {
		t.Errorf("a creation below its standing removal: %v", err)
	}
	if err := apply(replay, 3, 0, 7, false); err != nil {
		t.Errorf("a creation at max(b, m) + 1: %v", err)
	}
}

// A statement pinned at a state this device's config no longer retains is refused, but proves nothing against its
// signer, so it raises no alarm.
func TestEvsUnretainedStatePinRefusesQuietly(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	world.config.stateLock.Lock()
	world.config.atErr = ErrGkmAuthNotRetained
	world.config.stateLock.Unlock()
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrGkmAuthNotRetained) {
		t.Fatalf("an unretained pin: %v", err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// The refs table on a record-class owned stream, the statement read alone: its owner creates, a repo admin's BASE of
// removals alone (plan-EVS1-v1-unspecified#6) and CLOSURE pass, the owner's own BASE only while it is a repo admin, a
// BASE that writes does not, and another sidecar's write does not. The owner's write on a base passes here, since
// without its entry version it may be a directory's add-only delta (QD-722): the reader holding the payload judges it
// (TestEvsReplayingReaderHoldsAStreamDeltaToTheCreatesOnlyRule).
func TestEvsOwnedStreamRefRules(t *testing.T) {
	repoId := evsTestId("record repo")
	owner, admin, other := evsTestId("owner"), evsTestId("admin"), evsTestId("other")
	adminOwner := evsTestId("admin owner")
	config := &evsTestConfig{
		writers: []Id{owner, admin, other, adminOwner},
		repo: &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_RECORD,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: admin.Bytes()}, {SidecarId: adminOwner.Bytes()}}},
	}
	refId := evsTestId("stream")
	statement := func(signer Id, streamOwner Id, flags protocol.EvsPushFlag, baseEntryVersion uint64, removal bool) *EvsStatement {
		push := &protocol.EvsPush{RefKind: uint32(protocol.EvsRefKind_EVS_REF_OWNED), OwnerSidecarId: streamOwner.Bytes(), Flags: uint32(flags)}
		change := &protocol.EvsChange{BaseEntryVersion: baseEntryVersion, EntrySha256: evsTestBytes("entry", 32)}
		if removal {
			change.EntrySha256 = nil
		}
		return &EvsStatement{Push: push, Changes: []*EvsCheckedChange{{Change: change}}}
	}
	cases := []struct {
		name    string
		signer  Id
		owner   Id
		flags   protocol.EvsPushFlag
		base    uint64
		removal bool
		ok      bool
	}{
		{name: "owner creates", signer: owner, owner: owner, ok: true},
		{name: "owner writes on a base, its entry not at hand", signer: owner, owner: owner, base: 3, ok: true},
		{name: "admin base", signer: admin, owner: owner, flags: protocol.EvsPushFlag_EVS_PUSH_BASE, base: 3, removal: true, ok: true},
		{name: "admin base that writes", signer: admin, owner: owner, flags: protocol.EvsPushFlag_EVS_PUSH_BASE, ok: false},
		{name: "owner's base below admin", signer: owner, owner: owner, flags: protocol.EvsPushFlag_EVS_PUSH_BASE, base: 3, removal: true, ok: false},
		{name: "admin owner's base", signer: adminOwner, owner: adminOwner, flags: protocol.EvsPushFlag_EVS_PUSH_BASE, base: 3, removal: true, ok: true},
		{name: "admin closure", signer: admin, owner: owner, flags: protocol.EvsPushFlag_EVS_PUSH_CLOSURE, base: 3, ok: true},
		{name: "other writes", signer: other, owner: owner, ok: false},
		{name: "owner forces", signer: owner, owner: owner, flags: protocol.EvsPushFlag_EVS_PUSH_FORCE, ok: false},
	}
	for _, c := range cases {
		err := evsCheckRefRules(config, statement(c.signer, c.owner, c.flags, c.base, c.removal), repoId, refId, c.signer)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a removal stays refused, entry or none
	removal := statement(owner, owner, 0, 3, true)
	if err := evsCheckRefRules(config, removal, repoId, refId, owner); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("owner removes: %v", err)
	}
}

// QD-722 at a replaying reader, which holds each change's entry version and its replay's state of the path: on a
// record-class stream a directory's add-only delta on its newest version passes, and a delta removing a token, one on
// an older version, one not at its base + 1, a file's write on a base, and a delta on a path standing as a file or not
// at all are each refused. The statement read alone, with no entry version, leaves a stream's write on a base to that
// check and refuses one on a deposit ref, which takes no delta; a statement that names no entry change is refused alike
// with its entry at hand and no path state, as a head reader holds a version it read.
func TestEvsReplayingReaderHoldsAStreamDeltaToTheCreatesOnlyRule(t *testing.T) {
	repoId := evsTestId("record repo")
	owner := evsTestId("owner")
	config := &evsTestConfig{
		writers: []Id{owner},
		repo:    &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_RECORD},
	}
	refId := evsTestId("stream")
	directory := EvsTokenPath{evsTestToken("e")}
	entryOf := func(kind protocol.EvsEntryKind, version uint64, removed [][]byte) []byte {
		entry := &protocol.EvsEntryVersion{Version: version, Kind: uint32(kind)}
		if kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			entry.Names = &protocol.EvsNameTable{
				Names:         []*protocol.EvsName{{Token: evsTestToken("1").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: evsTestBytes("sealed 1", 32)}},
				RemovedTokens: removed,
			}
		}
		entryBytes, err := proto.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		return entryBytes
	}
	changeOf := func(base uint64, entryBytes []byte) *EvsCheckedChange {
		digest := sha256.Sum256(entryBytes)
		return &EvsCheckedChange{
			Change:       &protocol.EvsChange{TokenPath: directory.Components(), BaseEntryVersion: base, EntrySha256: digest[:]},
			TokenPath:    directory,
			EntryVersion: entryBytes,
		}
	}
	standing := func(path *EvsCreatesOnlyPath) func(change *EvsCheckedChange) *EvsCreatesOnlyPath {
		return func(change *EvsCheckedChange) *EvsCreatesOnlyPath {
			return path
		}
	}
	directoryAt := &EvsCreatesOnlyPath{Exists: true, Directory: true, Version: 3}
	fileAt := &EvsCreatesOnlyPath{Exists: true, Version: 3}
	directoryEntry := protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
	stream := &EvsStatement{Push: &protocol.EvsPush{RefKind: uint32(protocol.EvsRefKind_EVS_REF_OWNED), OwnerSidecarId: owner.Bytes()}}
	cases := []struct {
		name   string
		change *EvsCheckedChange
		pathOf func(change *EvsCheckedChange) *EvsCreatesOnlyPath
		// the refusal's reason, empty for a change that passes
		reason string
	}{
		{name: "an add-only delta on the newest version", change: changeOf(3, entryOf(directoryEntry, 4, nil)), pathOf: standing(directoryAt)},
		{name: "a delta removing a token", change: changeOf(3, entryOf(directoryEntry, 4, [][]byte{evsTestToken("0").Bytes()})), pathOf: standing(directoryAt),
			reason: "a directory delta removing a name"},
		{name: "a delta on an older version", change: changeOf(2, entryOf(directoryEntry, 3, nil)), pathOf: standing(directoryAt),
			reason: "a directory delta off the directory's newest version"},
		{name: "a delta not at its base + 1", change: changeOf(3, entryOf(directoryEntry, 5, nil)), pathOf: standing(directoryAt),
			reason: "a directory delta not at its base + 1"},
		{name: "a file's write on a base", change: changeOf(3, entryOf(protocol.EvsEntryKind_EVS_ENTRY_FILE, 4, nil)), pathOf: standing(fileAt),
			reason: "a file's write on a base"},
		{name: "a delta on a path standing as a file", change: changeOf(3, entryOf(directoryEntry, 4, nil)), pathOf: standing(fileAt),
			reason: "a directory delta on a path that does not stand as a directory"},
		{name: "a delta on a path that does not stand", change: changeOf(3, entryOf(directoryEntry, 4, nil)), pathOf: standing(&EvsCreatesOnlyPath{}),
			reason: "a directory delta on a path that does not stand as a directory"},
		{name: "a file's write on a base, no path state", change: changeOf(3, entryOf(protocol.EvsEntryKind_EVS_ENTRY_FILE, 4, nil)),
			reason: "a file's write on a base"},
		{name: "a delta removing a token, no path state", change: changeOf(3, entryOf(directoryEntry, 4, [][]byte{evsTestToken("0").Bytes()})),
			reason: "a directory delta removing a name"},
		{name: "an add-only delta, no path state", change: changeOf(3, entryOf(directoryEntry, 4, nil))},
	}
	for _, c := range cases {
		err := evsCheckRefRulesOver(config, stream, []*EvsCheckedChange{c.change}, c.pathOf, repoId, refId, owner)
		if (c.reason == "") != (err == nil) || (err != nil && (!errors.Is(err, ErrEvsStatementRefused) || !strings.HasSuffix(err.Error(), ": "+c.reason))) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// the statement alone: a stream's write on a base waits on its payload, a deposit's is refused
	alone := changeOf(3, entryOf(directoryEntry, 4, nil))
	alone.EntryVersion = nil
	if err := evsCheckRefRulesOver(config, stream, []*EvsCheckedChange{alone}, nil, repoId, refId, owner); err != nil {
		t.Errorf("a stream's write on a base, the statement alone: %v", err)
	}
	depositId := EvsDepositRefId(repoId, owner)
	deposit := &EvsStatement{Push: &protocol.EvsPush{RefKind: uint32(protocol.EvsRefKind_EVS_REF_DEPOSIT), OwnerSidecarId: owner.Bytes()}}
	if err := evsCheckRefRulesOver(config, deposit, []*EvsCheckedChange{alone}, nil, repoId, depositId, owner); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a deposit's write on a base, the statement alone: %v", err)
	}
	if err := evsCheckRefRulesOver(config, deposit, []*EvsCheckedChange{changeOf(3, entryOf(directoryEntry, 4, nil))}, standing(directoryAt), repoId, depositId, owner); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a deposit's directory delta: %v", err)
	}
}

// QD-722 at a head reader of a record-class stream, which holds each version it reads with its entry: a directory's
// add-only delta lists and the file it added reads, while a file written again on a base, whose statement read alone
// passes since it cannot be told from a delta, is refused once its entry is at hand and alarmed as tampering.
func TestEvsHeadReaderHoldsAStreamVersionToTheCreatesOnlyRule(t *testing.T) {
	world := newEvsTestWorld(t)
	world.owned = true
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
	world.push(&evsTestChange{path: "e", children: []string{"1"}}, &evsTestChange{path: "e/1", content: []byte("1")})
	world.push(&evsTestChange{path: "e", children: []string{"2"}}, &evsTestChange{path: "e/2", content: []byte("2")})
	reader := world.reader(t, evsTestId("reader"))
	listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Entries) != 2 {
		t.Fatalf("e lists %d entries", len(listing.Entries))
	}
	if content, _, err := evsTestRead(t, reader, world, "e/2"); err != nil || string(content) != "2" {
		t.Fatalf("the delta's file: %q %v", content, err)
	}
	// e/1 written again, which evs's 5c refuses and a server that lies commits
	world.push(&evsTestChange{path: "e/1", content: []byte("written again")})
	if _, _, err := evsTestRead(t, reader, world, "e/1"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a stream's file written on a base: %v", err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) == 0 || alarms[len(alarms)-1].EvsAlarm != SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
}

// A directory's delta at or below the read's pin carries no statement, so it is taken as evs's word, its names still
// checked by List; a delta that is no directory's is refused.
func TestEvsDirectoryDeltaBelowThePin(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "d", children: []string{"a"}}, &evsTestChange{path: "d/a", content: []byte("a")})
	reader := world.reader(t, evsTestId("reader"))
	if _, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"}); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "d", children: []string{"b"}}, &evsTestChange{path: "d/b", content: []byte("b")})
	world.push(&evsTestChange{path: "x", content: []byte("x")})
	// a reader that never listed d, pinned past both of its versions
	reader = world.reader(t, evsTestId("later reader"))
	if _, _, err := evsTestRead(t, reader, world, "x"); err != nil {
		t.Fatal(err)
	}
	// evs now answers d with its first table and the second version as a delta, which is below the reader's pin
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if reply.Names == nil {
			return
		}
		state := world.paths["d"]
		first, second := state.versions[1], state.versions[2]
		reply.Version = &protocol.EvsIndexVersion{PushId: first.pushId, CommitVersion: first.commitVersion, EntryVersion: first.entryBytes}
		reply.Statement = world.commits[first.commitVersion-1].statement
		reply.Names = &protocol.EvsNameTable{Names: state.rows[:1]}
		reply.NamesThrough = first.commitVersion
		reply.Deltas = []*protocol.EvsIndexVersion{{PushId: second.pushId, CommitVersion: second.commitVersion, EntryVersion: second.entryBytes}}
	}
	listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Entries) != 2 {
		t.Errorf("listed %d", len(listing.Entries))
	}
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if reply.Names != nil {
			file := world.paths["x"].versions[world.paths["x"].newest]
			reply.Deltas = []*protocol.EvsIndexVersion{{PushId: file.pushId, CommitVersion: file.commitVersion, EntryVersion: file.entryBytes}}
		}
	}
	if _, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"}); err == nil {
		t.Errorf("a file's entry as a directory's delta")
	}
}

// A directory's deltas in statements whose lists are under changes_root, walked after the reader's pin, are each
// verified by their own proof (QD-681; question evs1-m2-28-rooted-delta-proofs): the reply's delta_proofs, one a
// delta in order. With none, with another delta's, or with a count that is not the deltas', the read is refused.
func TestEvsRootedDirectoryDeltasVerifyByTheirProofs(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "d", children: []string{"a"}}, &evsTestChange{path: "d/a", content: []byte("a")})
	reader := world.reader(t, evsTestId("reader"))
	if _, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"}); err != nil {
		t.Fatal(err)
	}
	// two pushes of 12 files into d, each past the inline bound, each changing d by a delta
	for _, prefix := range []string{"m", "n"} {
		directory := &evsTestChange{path: "d"}
		changes := []*evsTestChange{directory}
		for i := range 12 {
			name := fmt.Sprint(prefix, i)
			directory.children = append(directory.children, name)
			changes = append(changes, &evsTestChange{path: "d/" + name, content: []byte(name)})
		}
		world.push(changes...)
	}
	if world.commits[1].built.ChangeTree == nil || world.commits[2].built.ChangeTree == nil {
		t.Fatalf("the 12-file pushes' changes are inline")
	}
	state := world.paths["d"]
	directoryPath := world.tokensAt("d", 1)
	delta := func(pathVersion uint64) (*protocol.EvsIndexVersion, *protocol.EvsDeltaProof) {
		held := state.versions[pathVersion]
		tree := world.commits[held.commitVersion-1].built.ChangeTree
		part, index, present := evsTestTreePosition(tree, directoryPath)
		if !present {
			t.Fatalf("version %d does not change d", held.commitVersion)
		}
		proofs, err := tree.InclusionProof(part, index)
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsIndexVersion{PushId: held.pushId, CommitVersion: held.commitVersion, EntryVersion: held.entryBytes}, &protocol.EvsDeltaProof{Proof: proofs}
	}
	// evs answers d unfolded: its newest delta as the version, the table as of its first version, and both later
	// deltas after it, each with its proof
	shape := func(proofs func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof) {
		world.mutatePath = func(reply *protocol.EvsReadPathReply) {
			if reply.Names == nil {
				return
			}
			second, secondProof := delta(2)
			third, thirdProof := delta(3)
			reply.Names = &protocol.EvsNameTable{Names: state.rows[:1]}
			reply.NamesThrough = state.versions[1].commitVersion
			reply.Deltas = []*protocol.EvsIndexVersion{second, third}
			reply.DeltaProofs = proofs(secondProof, thirdProof)
		}
	}
	list := func() (int, error) {
		listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"})
		if err != nil {
			return 0, err
		}
		return len(listing.Entries), nil
	}
	refused := map[string]func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof{
		"no delta proofs": func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof {
			return nil
		},
		"an empty proof for a rooted delta": func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof {
			return []*protocol.EvsDeltaProof{{}, third}
		},
		"another delta's proof": func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof {
			return []*protocol.EvsDeltaProof{third, second}
		},
		"one proof for two deltas": func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof {
			return []*protocol.EvsDeltaProof{second}
		},
	}
	for label, proofs := range refused {
		shape(proofs)
		if _, err := list(); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("%s: %v", label, err)
		}
	}
	shape(func(second *protocol.EvsDeltaProof, third *protocol.EvsDeltaProof) []*protocol.EvsDeltaProof {
		return []*protocol.EvsDeltaProof{second, third}
	})
	count, err := list()
	if err != nil {
		t.Fatal(err)
	}
	if count != 25 {
		t.Errorf("listed %d of 25", count)
	}
}

// A push past the inline bound that adds files to a directory changes the directory by a delta, which does not end a
// file already there (§11.7's newest row): a reader pinned below it verifies the file by the adjacent-leaf proof of
// the file and the inclusion proof of the directory's delta, in the absence's present (QD-681); with present dropped
// the read is refused, as it was before the reply could carry it.
func TestEvsPrefixDeltaInARootedPushLeavesThePathStanding(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "d", children: []string{"keep.txt"}}, &evsTestChange{path: "d/keep.txt", content: []byte("kept")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "d/keep.txt"); err != nil {
		t.Fatal(err)
	}
	directory := &evsTestChange{path: "d"}
	changes := []*evsTestChange{directory}
	for i := range 12 {
		name := fmt.Sprint("many", i)
		directory.children = append(directory.children, name)
		changes = append(changes, &evsTestChange{path: "d/" + name, content: []byte("m")})
	}
	world.push(changes...)
	if world.commits[1].built.ChangeTree == nil {
		t.Fatalf("the 12-file push's changes are inline")
	}
	presents := 0
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		for _, absence := range reply.GetAbsences() {
			if len(absence.GetPresent()) != 0 {
				presents += 1
				absence.Present = nil
			}
		}
	}
	if _, _, err := evsTestRead(t, reader, world, "d/keep.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("the directory's delta with no proof: %v", err)
	}
	if presents != 1 {
		t.Fatalf("%d present proofs served, want the directory's one", presents)
	}
	world.mutatePath = nil
	content, _, err := evsTestRead(t, reader, world, "d/keep.txt")
	if err != nil || string(content) != "kept" {
		t.Fatalf("with the delta's proof: %q %v", content, err)
	}
}

// A name never written in a directory reads as absent across a rooted push that added other names there, by the
// name's adjacent leaves and the directory's delta in present (QD-681): what a writer's plan of a second push into
// the directory reads for each new name. With present dropped it is refused. The directory, a strict prefix of a name
// served holding no version, needs no proof (QD-978): with its absence left out the name still reads absent, to a
// second reader pinned below the push as the first is, and with the name's own left out it is refused.
func TestEvsAbsentNameInADirectoryARootedPushChanged(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "d", children: []string{"keep.txt"}}, &evsTestChange{path: "d/keep.txt", content: []byte("kept")})
	reader := world.reader(t, evsTestId("reader"))
	second := world.reader(t, evsTestId("second reader"))
	for _, pinned := range []*evsTestClient{reader, second} {
		if _, _, err := evsTestRead(t, pinned, world, "d/keep.txt"); err != nil {
			t.Fatal(err)
		}
	}
	directory := &evsTestChange{path: "d"}
	changes := []*evsTestChange{directory}
	for i := range 12 {
		name := fmt.Sprint("many", i)
		directory.children = append(directory.children, name)
		changes = append(changes, &evsTestChange{path: "d/" + name, content: []byte("m")})
	}
	world.push(changes...)
	if world.commits[1].built.ChangeTree == nil {
		t.Fatalf("the 12-file push's changes are inline")
	}
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		for _, absence := range reply.GetAbsences() {
			absence.Present = nil
		}
	}
	if _, _, err := evsTestRead(t, reader, world, "d/next0"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("the directory's delta with no proof: %v", err)
	}
	// the absence of one path left out: the name's own refuses, before any read moved a pin past the push
	leaveOut := func(left string) {
		leftPath := world.tokens(left)
		world.mutatePath = func(reply *protocol.EvsReadPathReply) {
			kept := []*protocol.EvsAbsenceProof{}
			for _, absence := range reply.GetAbsences() {
				if tokenPath, err := ParseEvsTokenPath(absence.GetTokenPath()); err == nil && !tokenPath.Equal(leftPath) {
					kept = append(kept, absence)
				}
			}
			if len(kept) == len(reply.GetAbsences()) {
				t.Errorf("no absence of %s served", left)
			}
			reply.Absences = kept
		}
	}
	leaveOut("d/next0")
	if _, _, err := evsTestRead(t, reader, world, "d/next0"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("the name's own absence left out: %v", err)
	}
	leaveOut("d")
	if _, _, err := evsTestRead(t, second, world, "d/next0"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("the directory's absence left out: %v", err)
	}
	world.mutatePath = nil
	if _, _, err := evsTestRead(t, reader, world, "d/next0"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a name never written: %v", err)
	}
}

// An absence's present stands only for a strict prefix whose change writes an entry (QD-681): the path's own change,
// a prefix's removal, a proof of another path, a proof to another root, and one beside adjacent leaves are refused.
// For a path served holding no version, never written or removed, a strict prefix's removal stands too (QD-978); for
// one served absent alone, so does the path's own change, a write or a removal, which the walk's order judges
// (QD-979); and every other refusal holds for each.
func TestEvsPresentIsRefusedForThePathItselfOrARemoval(t *testing.T) {
	directory := EvsTokenPath{evsTestToken("d")}
	file := EvsTokenPath{evsTestToken("d"), evsTestToken("keep")}
	sibling := EvsTokenPath{evsTestToken("d"), evsTestToken("new")}
	other := EvsTokenPath{evsTestToken("e")}
	leaf := func(tokenPath EvsTokenPath, writes bool) []byte {
		change := &protocol.EvsChange{TokenPath: tokenPath.Components(), BaseEntryVersion: 1}
		if writes {
			change.EntrySha256 = evsTestBytes("entry", 32)
		}
		leafBytes, err := proto.Marshal(change)
		if err != nil {
			t.Fatal(err)
		}
		return leafBytes
	}
	// a list in token path order, with what each of the named paths' changes does
	build := func(writes map[string]bool, tokenPaths ...EvsTokenPath) (*protocol.EvsPush, func(tokenPath EvsTokenPath) *protocol.EvsAbsenceProof) {
		slices.SortFunc(tokenPaths, func(a EvsTokenPath, b EvsTokenPath) int { return a.Compare(b) })
		leaves := [][]byte{}
		for _, tokenPath := range tokenPaths {
			leaves = append(leaves, leaf(tokenPath, writes[string(tokenPath.Bytes())]))
		}
		tree, err := NewEvsChangeTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		root := tree.Root()
		push := &protocol.EvsPush{ChangesRoot: root[:], ChangeCount: uint32(len(leaves))}
		present := func(tokenPath EvsTokenPath) *protocol.EvsAbsenceProof {
			part, index, found := evsTestTreePosition(tree, tokenPath)
			if !found {
				t.Fatalf("no change of the path in the list")
			}
			proofs, err := tree.InclusionProof(part, index)
			if err != nil {
				t.Fatal(err)
			}
			return &protocol.EvsAbsenceProof{Version: 2, TokenPath: tokenPath.Components(), Present: proofs}
		}
		return push, present
	}
	written := func(tokenPaths ...EvsTokenPath) map[string]bool {
		writes := map[string]bool{}
		for _, tokenPath := range tokenPaths {
			writes[string(tokenPath.Bytes())] = true
		}
		return writes
	}

	// the path served standing, served removed, then served absent
	for _, served := range []evsServedAs{evsServedStanding, evsServedRemoved, evsServedAbsent} {
		push, present := build(written(directory, sibling, other), directory, sibling, other)
		if change, err := evsVerifyPresent(push, file, directory, present(directory), served); err != nil || len(change.GetEntrySha256()) == 0 {
			t.Fatalf("served %d: a strict prefix's delta: %v %v", served, change, err)
		}
		// a proof of another path's change where the prefix's is asked
		if _, err := evsVerifyPresent(push, file, directory, present(other), served); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: another path's change: %v", served, err)
		}
		// beside adjacent leaves
		both := present(directory)
		both.Above = both.GetPresent()
		if _, err := evsVerifyPresent(push, file, directory, both, served); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: present beside a leaf above: %v", served, err)
		}
		// to another statement's root
		elsewhere, _ := build(written(directory), directory, other)
		if _, err := evsVerifyPresent(elsewhere, file, directory, present(directory), served); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: a proof to another root: %v", served, err)
		}
		// the path itself, written again by the statement: refused beside a version or removal served, and taken
		// beside absent, where the walk's order judges it (QD-979)
		push, present = build(written(directory, file), directory, file)
		change, err := evsVerifyPresent(push, file, file, present(file), served)
		if served != evsServedAbsent && !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: the path's own change: %v", served, err)
		}
		if served == evsServedAbsent && (err != nil || len(change.GetEntrySha256()) == 0) {
			t.Errorf("the path's own write beside absent: %v %v", change, err)
		}
		// a path that is no prefix of the one read
		if _, err := evsVerifyPresent(push, other, directory, present(directory), served); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: a change of a path that holds nothing of the one read: %v", served, err)
		}
		// the proof of a prefix's change where the path's own is asked
		if _, err := evsVerifyPresent(push, file, file, present(directory), served); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: the prefix's change where the path's is asked: %v", served, err)
		}
		// the path's own removal: the same
		push, present = build(written(directory), directory, file)
		change, err = evsVerifyPresent(push, file, file, present(file), served)
		if served != evsServedAbsent && !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("served %d: the path's own removal: %v", served, err)
		}
		if served == evsServedAbsent && (err != nil || len(change.GetEntrySha256()) != 0) {
			t.Errorf("the path's own removal beside absent: %v %v", change, err)
		}
		// the prefix's removal, which ends every path below it that stands, and leaves one served holding no version
		// as it was served
		push, present = build(written(other), directory, other)
		change, err = evsVerifyPresent(push, file, directory, present(directory), served)
		if served == evsServedStanding && !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("a prefix's removal of a path served standing: %v", err)
		}
		if served != evsServedStanding && (err != nil || len(change.GetEntrySha256()) != 0) {
			t.Errorf("served %d: a prefix's removal of a path served holding no version: %v %v", served, change, err)
		}
	}
}

// Beside changes, twelve file creations under prefix, which put a statement's list under changes_root.
func evsTestRootedChanges(prefix string, changes ...*evsTestChange) []*evsTestChange {
	for i := range 12 {
		changes = append(changes, &evsTestChange{path: fmt.Sprint(prefix, i), content: []byte("m")})
	}
	return changes
}

// The world's d holding d/a.txt, which reader reads at version 1, then d/a.txt removed and d removed, each by a
// statement of its own whose list goes under changes_root when rooted: the version d/a.txt's removal committed at.
func evsTestRemoveFileThenDirectory(t *testing.T, world *evsTestWorld, reader *evsTestClient, rooted bool) uint64 {
	t.Helper()
	world.push(&evsTestChange{path: "d", children: []string{"a.txt"}}, &evsTestChange{path: "d/a.txt", content: []byte("a")})
	if content, _, err := evsTestRead(t, reader, world, "d/a.txt"); err != nil || string(content) != "a" {
		t.Fatalf("d/a.txt before its removal: %q %v", content, err)
	}
	removeFile := []*evsTestChange{{path: "d/a.txt"}}
	removeDirectory := []*evsTestChange{{path: "d"}}
	if rooted {
		removeFile = evsTestRootedChanges("e/many", removeFile...)
		removeDirectory = evsTestRootedChanges("f/many", removeDirectory...)
	}
	removed := world.push(removeFile...)
	world.push(removeDirectory...)
	for _, version := range []uint64{removed, removed + 1} {
		if (world.commits[version-1].built.ChangeTree != nil) != rooted {
			t.Fatalf("version %d's list under changes_root: %t, want %t", version, !rooted, rooted)
		}
	}
	return removed
}

// QD-978 (question evs-removal-from-window-prefix-removal-after-removal, option 1): d/a.txt removed and then d removed
// is served d/a.txt's own removal, as evs's newest rule answers a path already absent when a prefix holding it is
// removed (§11.7's removal row), and a reader pinned below both removals, whose walk holds d's removal, verifies it: a
// removed path stays removed through a prefix's removal, which contradicts only a reply serving the path standing. No
// fold or collection runs; evs's side is evsservice's read_walked_test.go.
func TestEvsRemovalStandsThroughAPrefixsLaterRemoval(t *testing.T) {
	world := newEvsTestWorld(t)
	reader := world.reader(t, evsTestId("reader"))
	removed := evsTestRemoveFileThenDirectory(t, world, reader, false)
	requestPins := []uint64{}
	world.beforeRead = func(read *protocol.EvsReadRequest) {
		requestPins = append(requestPins, read.GetPinVersion())
	}
	var served *protocol.EvsReadPathReply
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		served = proto.Clone(reply).(*protocol.EvsReadPathReply)
	}
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("d/a.txt after d's removal: %v", err)
	}
	if removal := served.GetRemoval(); removal == nil || removal.GetRemovalVersion() != removed || removal.GetPathVersion() != 2 {
		t.Fatalf("served %v, not d/a.txt's own removal at %d", served, removed)
	}
	if len(requestPins) != 1 || removed <= requestPins[0] {
		t.Fatalf("read from pins %v, which walk neither removal", requestPins)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	if pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId); !ok || pin.Version != removed+1 {
		t.Errorf("pin %+v, not d's removal", pin)
	}
}

// The same with both removals in statements whose lists go under changes_root. evs shows d/a.txt left alone by d's
// removal with its adjacent leaves and sends nothing for d, a removal being shown by no proof (§11.9's reply row); the
// reader takes a strict prefix of a path served holding no version with no proof, since nothing a statement does to
// such a prefix makes the path stand. The path's own absence is still needed: with it dropped the read is refused.
func TestEvsRemovalStandsThroughARootedPrefixRemoval(t *testing.T) {
	world := newEvsTestWorld(t)
	reader := world.reader(t, evsTestId("reader"))
	removed := evsTestRemoveFileThenDirectory(t, world, reader, true)
	file, directory := world.tokens("d/a.txt"), world.tokens("d")
	var served *protocol.EvsReadPathReply
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		served = proto.Clone(reply).(*protocol.EvsReadPathReply)
		kept := []*protocol.EvsAbsenceProof{}
		for _, absence := range reply.GetAbsences() {
			if tokenPath, err := ParseEvsTokenPath(absence.GetTokenPath()); err == nil && !tokenPath.Equal(file) {
				kept = append(kept, absence)
			}
		}
		reply.Absences = kept
	}
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("the path's own absence dropped: %v", err)
	}
	fileAbsences, directoryAbsences := 0, 0
	for _, absence := range served.GetAbsences() {
		tokenPath, err := ParseEvsTokenPath(absence.GetTokenPath())
		switch {
		case err != nil || absence.GetVersion() != removed+1:
			t.Fatalf("an absence %v", absence)
		case tokenPath.Equal(file) && len(absence.GetPresent()) == 0 && (len(absence.GetBelow()) != 0 || len(absence.GetAbove()) != 0):
			fileAbsences += 1
		case tokenPath.Equal(directory):
			directoryAbsences += 1
		}
	}
	if fileAbsences != 1 || directoryAbsences != 0 || served.GetRemoval().GetRemovalVersion() != removed || len(served.GetProof()) == 0 {
		t.Fatalf("served %d absences of d/a.txt and %d of d beside %v", fileAbsences, directoryAbsences, served.GetRemoval())
	}
	world.mutatePath = nil
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("d/a.txt after d's rooted removal: %v", err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A second device of the world's signer on writer's stand-in: a client and store of its own, so its pins and read
// records are its own.
func (self *evsTestWriter) otherDevice(t *testing.T, label string) *evsTestWriter {
	t.Helper()
	test := newEvsTestClient(t, self.server, newEvsTestStore(t))
	test.client.args.Gkm = self.gkm
	test.client.args.Config = func() GkmAuthView { return self.world.config }
	test.client.args.Sign = self.world.signer.sign
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: self.world.signer.sidecarId, ClientId: evsTestId(label)}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	return &evsTestWriter{world: self.world, server: self.server, gkm: self.gkm, test: test, repo: test.client.Repo(self.world.repoId)}
}

// QD-978: a writer pinned before both removals, its read record of d/a.txt at version 1, creates d/a.txt again once
// another device removed it and then d: its plan reads d/a.txt as its own removal through d's, and the creation takes
// max(b, m) + 1 (§11.7's versions row), d created again beside it.
func TestEvsWriterPinnedBeforeBothRemovalsCreatesThePathAgain(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "d/a.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	pinned := writer.otherDevice(t, "pinned client")
	out := &bytes.Buffer{}
	if _, err := pinned.repo.ReadHead(context.Background(), &EvsReadArgs{Path: "d/a.txt"}, out); err != nil || out.String() != "first" {
		t.Fatalf("the pinned device's read: %q %v", out.String(), err)
	}
	pin, _, _ := pinned.test.client.pins.Pin(writer.world.repoId, writer.world.refId)
	removed, err := writer.write(t, "d/a.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	directoryRemoved, err := writer.write(t, "d", nil)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Version <= pin.Version || directoryRemoved.Version != removed.Version+1 {
		t.Fatalf("pinned at %d, d/a.txt removed at %d and d at %d", pin.Version, removed.Version, directoryRemoved.Version)
	}
	created, err := pinned.write(t, "d/a.txt", []byte("again"))
	if err != nil {
		t.Fatalf("the pinned device's creation: %v", err)
	}
	if want := max(directoryRemoved.Version, removed.PathVersion) + 1; created.Version != directoryRemoved.Version+1 || created.PathVersion != want {
		t.Errorf("created at %d with version %d, want version %d", created.Version, created.PathVersion, want)
	}
	if d := writer.entry(t, "d"); d.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) || len(d.GetNames().GetNames()) != 1 {
		t.Errorf("d created again: %v", d)
	}
	if content, _, err := writer.read(t, "d/a.txt"); err != nil || string(content) != "again" {
		t.Errorf("read back: %q %v", content, err)
	}
	if alarms := pinned.test.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("the pinned device's alarms %v", alarms)
	}
}

// QD-978's limit: a removal served after the path was written again still contradicts that walked write, which is
// refused and alarmed as tampering, whether the write's list is inline or under changes_root and evs passes the
// path's own change off as a prefix's present (QD-681).
func TestEvsWriteAfterThePrefixsRemovalServedAsRemovedIsRefused(t *testing.T) {
	for _, rooted := range []bool{false, true} {
		world := newEvsTestWorld(t)
		reader := world.reader(t, evsTestId("reader"))
		removed := evsTestRemoveFileThenDirectory(t, world, reader, false)
		world.stateLock.Lock()
		marker := proto.Clone(world.paths["d/a.txt"].removals[2]).(*protocol.EvsRemovalMarker)
		world.stateLock.Unlock()
		create := []*evsTestChange{{path: "d", children: []string{"a.txt"}}, {path: "d/a.txt", content: []byte("again")}}
		if rooted {
			create = evsTestRootedChanges("e/many", create...)
		}
		created := world.push(create...)
		if (world.commits[created-1].built.ChangeTree != nil) != rooted {
			t.Fatalf("rooted %t: the creation's list under changes_root: %t", rooted, !rooted)
		}
		file := world.tokens("d/a.txt")
		world.mutatePath = func(reply *protocol.EvsReadPathReply) {
			// the removal in place of the version created since
			reply.Version, reply.Removal, reply.Proof, reply.Statement = nil, marker, nil, nil
			reply.Names, reply.NamesThrough, reply.Absences = nil, 0, nil
			if rooted {
				tree := world.commits[created-1].built.ChangeTree
				part, index, present := evsTestTreePosition(tree, file)
				if !present {
					t.Fatalf("d/a.txt is not in its creation's list")
				}
				proofs, err := tree.InclusionProof(part, index)
				if err != nil {
					t.Fatal(err)
				}
				reply.Absences = []*protocol.EvsAbsenceProof{{Version: created, TokenPath: file.Components(), Present: proofs}}
			}
		}
		if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
			t.Fatalf("rooted %t: the removal at %d served over the write at %d: %v", rooted, removed, created, err)
		}
		if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) == 0 || alarms[0].EvsAlarm != SidecarEvsAlarmTamper {
			t.Errorf("rooted %t: alarms %v", rooted, alarms)
		}
		world.mutatePath = nil
		if content, _, err := evsTestRead(t, reader, world, "d/a.txt"); err != nil || string(content) != "again" {
			t.Errorf("rooted %t: the honest read: %q %v", rooted, content, err)
		}
	}
}

// Has world serve path plain absent, as evs serves it once a collection took its removal's marker and the window paged
// the removal out (QD-879's window case passed; QD-979): no version, removal, statement or proof, and for each
// statement whose list is under changes_root the absences evs sends a path it holds nothing of, nothing for the
// path's own change or a prefix's removal. With presents, beside them the present of the path's own change and of a
// strict prefix's removal in each such statement that made one, which evs as built does not send (question
// evs-absent-walked-removal-own-present).
func evsTestServeAbsent(world *evsTestWorld, path string, presents bool) {
	tokenPath := world.tokens(path)
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		replyPath, err := ParseEvsChangedTokenPath(reply.GetTokenPath())
		if err != nil || !replyPath.Equal(tokenPath) {
			return
		}
		reply.Version, reply.Removal, reply.Base, reply.Statement, reply.Proof = nil, nil, nil, nil, nil
		reply.Names, reply.NamesThrough, reply.Deltas, reply.DeltaProofs, reply.Absences = nil, 0, nil, nil, nil
		// called under the world's lock, as pathReplyWithLock runs
		for i, commit := range world.commits {
			tree := commit.built.ChangeTree
			if tree == nil {
				continue
			}
			version := uint64(i + 1)
			reply.Absences = append(reply.Absences, evsTestAbsences(tree, commit.parsed.ChangedPrefixes, version, tokenPath)...)
			if !presents {
				continue
			}
			for _, absentPath := range EvsAbsencePaths(commit.parsed.ChangedPrefixes, tokenPath) {
				part, index, present := evsTestTreePosition(tree, absentPath)
				if !present {
					continue
				}
				change, _, err := parseEvsChangeLeaf(tree.runs[part].leaves[index])
				if err != nil {
					world.t.Error(err)
					return
				}
				if len(absentPath) < len(tokenPath) && len(change.GetEntrySha256()) != 0 {
					// a strict prefix's delta, whose present evsTestAbsences sends
					continue
				}
				proofs, err := tree.InclusionProof(part, index)
				if err != nil {
					world.t.Error(err)
					return
				}
				reply.Absences = append(reply.Absences, &protocol.EvsAbsenceProof{Version: version, TokenPath: absentPath.Components(), Present: proofs})
			}
		}
	}
}

// Pushes count creations of files named prefix and their number, each a statement of its own.
func evsTestPushOthers(world *evsTestWorld, prefix string, count int) {
	for i := range count {
		world.push(&evsTestChange{path: fmt.Sprint(prefix, i), content: []byte(prefix)})
	}
}

// Requires reader to have raised no alarm.
func evsTestRequireNoAlarm(t *testing.T, label string, reader *evsTestClient) {
	t.Helper()
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("%s: alarms %v", label, alarms)
	}
}

// Requires reader's newest alarm to be the tamper alarm, count of them in all.
func evsTestRequireTamper(t *testing.T, label string, reader *evsTestClient, count int) {
	t.Helper()
	alarms := reader.eventsOf(SidecarEventEvsAlarm)
	if len(alarms) != count || alarms[len(alarms)-1].EvsAlarm != SidecarEvsAlarmTamper {
		t.Errorf("%s: alarms %v, want %d ending in tamper", label, alarms, count)
	}
}

// QD-979 (question evs-removal-from-window-removal-paged-out, option 2) on the stand-in: x.txt written at 1 and 2 and
// removed at 3, then 70 versions and 60 more, the window holding the last 70 (from 64 at head 133), and evs serving
// x.txt plain absent, as it does once a collection took the removal's marker and the window paged the removal out. A
// reader holding a record of x.txt pinned at 1 walks the second write and then the removal from the log pages, one
// pinned at 2 the removal alone, and each reads x.txt absent, its record no refusal, with no alarm; once x.txt is
// created again, the same absent reply contradicts the walked creation, which the reader refuses and alarms as
// tampering.
func TestEvsAbsentAgreesWithTheWalksRemoval(t *testing.T) {
	world := newEvsTestWorld(t)
	readers := []*evsTestClient{}
	for i, content := range []string{"first", "second"} {
		world.push(&evsTestChange{path: "x.txt", content: []byte(content)})
		reader := world.reader(t, evsTestId(fmt.Sprint("reader ", i)))
		if read, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil || string(read) != content {
			t.Fatalf("x.txt at %d: %q %v", i+1, read, err)
		}
		readers = append(readers, reader)
	}
	removed := world.push(&evsTestChange{path: "x.txt"})
	evsTestPushOthers(world, "n", 70)
	evsTestPushOthers(world, "m", 60)
	head, _ := world.head()
	if removed != 3 || head != 133 {
		t.Fatalf("removed at %d, head %d", removed, head)
	}
	world.stateLock.Lock()
	world.window = 70
	world.stateLock.Unlock()
	evsTestServeAbsent(world, "x.txt", false)
	for i, reader := range readers {
		requestPins := []uint64{}
		world.beforeRead = func(read *protocol.EvsReadRequest) {
			requestPins = append(requestPins, read.GetPinVersion())
		}
		pages := world.logPageCount
		if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
			t.Fatalf("pinned at %d: x.txt served absent past its removal: %v", i+1, err)
		}
		if len(requestPins) != 1 || requestPins[0] != uint64(i+1) || world.logPageCount == pages {
			t.Fatalf("pinned at %d: read from pins %v with %d log pages, which walk no removal from the log", i+1, requestPins, world.logPageCount-pages)
		}
		evsTestRequireNoAlarm(t, fmt.Sprint("pinned at ", i+1), reader)
		if pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId); !ok || pin.Version != head {
			t.Errorf("pinned at %d: pin %+v, not the head %d", i+1, pin, head)
		}
	}
	world.beforeRead = nil

	reader := readers[0]
	created := world.push(&evsTestChange{path: "x.txt", content: []byte("again")})
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("absent served over the creation at %d: %v", created, err)
	}
	evsTestRequireTamper(t, "absent over the creation", reader, 1)
	world.stateLock.Lock()
	world.mutatePath = nil
	world.stateLock.Unlock()
	if content, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil || string(content) != "again" {
		t.Errorf("the honest read: %q %v", content, err)
	}
}

// A path written and never removed, served plain absent, is refused with the tamper alarm as before QD-979: the walk's
// newest change of it is a write. So is a reply whose walk shows the path removed, then created again: a removal the
// walk holds counts only where nothing written after it.
func TestEvsAbsentRefusedWhereTheWalksNewestChangeIsAWrite(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "g", content: []byte("g")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "g"); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "x.txt", content: []byte("first")})
	evsTestServeAbsent(world, "x.txt", false)
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("a written path served absent: %v", err)
	}
	evsTestRequireTamper(t, "a written path", reader, 1)

	second := world.reader(t, evsTestId("second reader"))
	if _, _, err := evsTestRead(t, second, world, "g"); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "x.txt"})
	world.push(&evsTestChange{path: "x.txt", content: []byte("again")})
	evsTestPushOthers(world, "n", 3)
	if _, _, err := evsTestRead(t, second, world, "x.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("written again after its removal, served absent: %v", err)
	}
	evsTestRequireTamper(t, "written again after its removal", second, 1)
}

// The same through a prefix's removal: d holding d/a.txt, which a reader reads, and d removed. Served plain absent,
// d/a.txt agrees with the walk's newest change, d's removal, and the reader, holding a record of d/a.txt, reads it
// absent with no alarm. Once d and d/a.txt are created again, the reply is refused and alarmed.
func TestEvsAbsentAgreesWithAPrefixsWalkedRemoval(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "d", children: []string{"a.txt"}}, &evsTestChange{path: "d/a.txt", content: []byte("a")})
	reader := world.reader(t, evsTestId("reader"))
	if content, _, err := evsTestRead(t, reader, world, "d/a.txt"); err != nil || string(content) != "a" {
		t.Fatalf("d/a.txt at 1: %q %v", content, err)
	}
	world.push(&evsTestChange{path: "d"})
	evsTestPushOthers(world, "n", 5)
	evsTestServeAbsent(world, "d/a.txt", false)
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("d/a.txt after d's removal: %v", err)
	}
	evsTestRequireNoAlarm(t, "after d's removal", reader)
	world.push(&evsTestChange{path: "d", children: []string{"a.txt"}}, &evsTestChange{path: "d/a.txt", content: []byte("again")})
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("absent served over d/a.txt's creation: %v", err)
	}
	evsTestRequireTamper(t, "over the creation", reader, 1)
}

// A write of d/a.txt walked before d's removal, d/a.txt served plain absent. Inline, the walk shows the removal after
// the write and the reply agrees with it. Under changes_root evs as built shows d's removal by nothing, so the reader
// can neither count it nor rule it out: it refuses the reply with no alarm, and takes it once the removal's present is
// beside it (question evs-absent-walked-removal-own-present).
func TestEvsAbsentAfterAWriteAndAPrefixsRemoval(t *testing.T) {
	for _, rooted := range []bool{false, true} {
		world := newEvsTestWorld(t)
		world.push(&evsTestChange{path: "d", children: []string{"a.txt"}}, &evsTestChange{path: "d/a.txt", content: []byte("a")})
		reader := world.reader(t, evsTestId("reader"))
		if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); err != nil {
			t.Fatal(err)
		}
		world.push(&evsTestChange{path: "d/a.txt", content: []byte("b")})
		removeDirectory := []*evsTestChange{{path: "d"}}
		if rooted {
			removeDirectory = evsTestRootedChanges("e/many", removeDirectory...)
		}
		removed := world.push(removeDirectory...)
		if (world.commits[removed-1].built.ChangeTree != nil) != rooted {
			t.Fatalf("rooted %t: d's removal's list under changes_root: %t", rooted, !rooted)
		}
		evsTestPushOthers(world, "n", 3)
		evsTestServeAbsent(world, "d/a.txt", false)
		_, _, err := evsTestRead(t, reader, world, "d/a.txt")
		if !rooted && !errors.Is(err, ErrEvsPathAbsent) {
			t.Fatalf("an inline removal of d after the write: %v", err)
		}
		if rooted && (!errors.Is(err, ErrEvsEntryRefused) || errors.Is(err, ErrEvsPathAbsent)) {
			t.Fatalf("a rooted removal of d, shown by nothing, after the write: %v", err)
		}
		evsTestRequireNoAlarm(t, fmt.Sprint("rooted ", rooted), reader)
		if !rooted {
			continue
		}
		evsTestServeAbsent(world, "d/a.txt", true)
		if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
			t.Fatalf("the rooted removal of d with its present: %v", err)
		}
		evsTestRequireNoAlarm(t, "the rooted removal's present", reader)
	}
}

// The rooted form: x.txt removed by a statement whose list is under changes_root. evs as built sends nothing for the
// path's own change, so a reader of x.txt served plain absent holds no proof of what that statement did to it and
// refuses the reply, raising no alarm (fail closed). With the present of x.txt's own removal beside the reply the
// reader takes it, the walk's newest change of x.txt being that removal; and once x.txt is created again by another
// rooted statement, the creation's own present shows a write after the removal, refused and alarmed as tampering.
func TestEvsAbsentAgreesWithARootedWalkedRemoval(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "x.txt", content: []byte("first")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil {
		t.Fatal(err)
	}
	removed := world.push(evsTestRootedChanges("e/many", &evsTestChange{path: "x.txt"})...)
	evsTestPushOthers(world, "n", 5)
	if world.commits[removed-1].built.ChangeTree == nil {
		t.Fatalf("the removal's list is inline")
	}
	evsTestServeAbsent(world, "x.txt", false)
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsEntryRefused) || errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("no proof of the rooted removal: %v", err)
	}
	evsTestRequireNoAlarm(t, "no proof of the rooted removal", reader)
	evsTestServeAbsent(world, "x.txt", true)
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("the rooted removal's own present: %v", err)
	}
	evsTestRequireNoAlarm(t, "the rooted removal's own present", reader)

	created := world.push(evsTestRootedChanges("f/many", &evsTestChange{path: "x.txt", content: []byte("again")})...)
	if world.commits[created-1].built.ChangeTree == nil {
		t.Fatalf("the creation's list is inline")
	}
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("absent served over the rooted creation at %d: %v", created, err)
	}
	evsTestRequireTamper(t, "over the rooted creation", reader, 1)
	world.stateLock.Lock()
	world.mutatePath = nil
	world.stateLock.Unlock()
	if content, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil || string(content) != "again" {
		t.Errorf("the honest read: %q %v", content, err)
	}
}

// QD-979's writer on the stand-in: writerA writes x.txt, a device of its signer reads it, writerA writes it again and
// removes it, and 130 versions pass with the window holding the last 70. evs serves x.txt plain absent: the device,
// its record pinned below the second write, and writerA, whose record is its removal's plan read, each read it absent
// with no alarm; and writerA's creation of x.txt commits at b + 1, the planner's max(b, m) + 1 with no m.
func TestEvsWriterCreatesAPathAgainPastItsPagedOutRemoval(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "x.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	pinned := writer.otherDevice(t, "pinned client")
	out := &bytes.Buffer{}
	if _, err := pinned.repo.ReadHead(context.Background(), &EvsReadArgs{Path: "x.txt"}, out); err != nil || out.String() != "first" {
		t.Fatalf("the pinned device's read: %q %v", out.String(), err)
	}
	if _, err := writer.write(t, "x.txt", []byte("second")); err != nil {
		t.Fatal(err)
	}
	removed, err := writer.write(t, "x.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	evsTestPushOthers(writer.world, "n", 130)
	head, _ := writer.world.head()
	if head != removed.Version+130 {
		t.Fatalf("head %d, removed at %d", head, removed.Version)
	}
	writer.world.stateLock.Lock()
	writer.world.window = 70
	writer.world.stateLock.Unlock()
	evsTestServeAbsent(writer.world, "x.txt", false)
	if _, err := pinned.repo.ReadHead(context.Background(), &EvsReadArgs{Path: "x.txt"}, &bytes.Buffer{}); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("the pinned device's read past the removal: %v", err)
	}
	if _, err := writer.repo.ReadHead(context.Background(), &EvsReadArgs{Path: "x.txt"}, &bytes.Buffer{}); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("writerA's read past its removal: %v", err)
	}
	created, err := writer.write(t, "x.txt", []byte("again"))
	if err != nil {
		t.Fatalf("writerA's creation: %v", err)
	}
	if created.Version != head+1 || created.PathVersion != head+1 {
		t.Errorf("created at %d with version %d, want b + 1 = %d", created.Version, created.PathVersion, head+1)
	}
	evsTestRequireNoAlarm(t, "the pinned device", pinned.test)
	evsTestRequireNoAlarm(t, "writerA", writer.test)
	writer.world.stateLock.Lock()
	writer.world.mutatePath = nil
	writer.world.stateLock.Unlock()
	if content, _, err := writer.read(t, "x.txt"); err != nil || string(content) != "again" {
		t.Errorf("read back: %q %v", content, err)
	}
}

// The exported walk reads the log from a version and chains every statement, as a stream's or the config's replay
// does: it reaches the head's C from C_0, and refuses a log that skips a version.
func TestEvsWalkFromTheLog(t *testing.T) {
	world := newEvsTestWorld(t)
	for i := range 20 {
		world.push(&evsTestChange{path: fmt.Sprint("f", i), content: []byte("x")})
	}
	reader := world.reader(t, evsTestId("replayer"))
	version, chain := world.head()
	walked, err := reader.client.Verifier().Walk(context.Background(), world.repoId, world.refId, 0, EvsChainStart(world.repoId, world.refId), version)
	if err != nil {
		t.Fatal(err)
	}
	if len(walked) != int(version) || walked[len(walked)-1].Chain != chain {
		t.Errorf("walked %d to another chain", len(walked))
	}
	world.omitVersion = 7
	if _, err := reader.client.Verifier().Walk(context.Background(), world.repoId, world.refId, 0, EvsChainStart(world.repoId, world.refId), version); !errors.Is(err, ErrEvsChainBroken) {
		t.Errorf("a log that skips a version: %v", err)
	}
}
