// EVS1-M2-23's tests on the stand-in evs (evs_world_test.go), FS-10 on T2: a forged entry refused; a rollback of a path
// changed after the pin refused; a never-read path's older version accepted, as §2.8 publishes; a reader far behind
// re-pinning with a gap mark; a fork and a rollback of the head refused and alarmed; a statement by a non-writer, a
// broken chain and a git-mode push off its tip refused; adjacent-leaf proofs for a large push; a reseed lowering a pin
// as a loss; and HeadCheck's ref source.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

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

// The refs table on a record-class owned stream: its owner creates only, a repo admin's BASE and CLOSURE pass, and
// another sidecar's write does not.
func TestEvsOwnedStreamRefRules(t *testing.T) {
	repoId := evsTestId("record repo")
	owner, admin, other := evsTestId("owner"), evsTestId("admin"), evsTestId("other")
	config := &evsTestConfig{
		writers: []Id{owner, admin, other},
		repo: &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_RECORD,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: admin.Bytes()}}},
	}
	refId := evsTestId("stream")
	statement := func(signer Id, flags protocol.EvsPushFlag, baseEntryVersion uint64) *EvsStatement {
		push := &protocol.EvsPush{RefKind: uint32(protocol.EvsRefKind_EVS_REF_OWNED), OwnerSidecarId: owner.Bytes(), Flags: uint32(flags)}
		change := &protocol.EvsChange{BaseEntryVersion: baseEntryVersion, EntrySha256: evsTestBytes("entry", 32)}
		return &EvsStatement{Push: push, Changes: []*EvsCheckedChange{{Change: change}}}
	}
	cases := []struct {
		name   string
		signer Id
		flags  protocol.EvsPushFlag
		base   uint64
		ok     bool
	}{
		{name: "owner creates", signer: owner, ok: true},
		{name: "owner rewrites", signer: owner, base: 3, ok: false},
		{name: "admin base", signer: admin, flags: protocol.EvsPushFlag_EVS_PUSH_BASE, ok: true},
		{name: "admin closure", signer: admin, flags: protocol.EvsPushFlag_EVS_PUSH_CLOSURE, base: 3, ok: true},
		{name: "other writes", signer: other, ok: false},
		{name: "owner forces", signer: owner, flags: protocol.EvsPushFlag_EVS_PUSH_FORCE, ok: false},
	}
	for _, c := range cases {
		err := evsCheckRefRules(config, statement(c.signer, c.flags, c.base), repoId, refId, c.signer)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
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
// the directory reads for each new name. With present dropped it is refused.
func TestEvsAbsentNameInADirectoryARootedPushChanged(t *testing.T) {
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
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		for _, absence := range reply.GetAbsences() {
			absence.Present = nil
		}
	}
	if _, _, err := evsTestRead(t, reader, world, "d/next0"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("the directory's delta with no proof: %v", err)
	}
	world.mutatePath = nil
	if _, _, err := evsTestRead(t, reader, world, "d/next0"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a name never written: %v", err)
	}
}

// An absence's present stands only for a strict prefix whose change writes an entry (QD-681): the path's own change,
// a prefix's removal, a proof of another path, a proof to another root, and one beside adjacent leaves are refused.
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

	push, present := build(written(directory, sibling, other), directory, sibling, other)
	if err := evsVerifyPrefixDelta(push, file, directory, present(directory)); err != nil {
		t.Fatalf("a strict prefix's delta: %v", err)
	}
	// a proof of another path's change where the prefix's is asked
	if err := evsVerifyPrefixDelta(push, file, directory, present(other)); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("another path's change: %v", err)
	}
	// beside adjacent leaves
	both := present(directory)
	both.Above = both.GetPresent()
	if err := evsVerifyPrefixDelta(push, file, directory, both); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("present beside a leaf above: %v", err)
	}
	// to another statement's root
	elsewhere, _ := build(written(directory), directory, other)
	if err := evsVerifyPrefixDelta(elsewhere, file, directory, present(directory)); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("a proof to another root: %v", err)
	}
	// the path itself, written again by the statement
	push, present = build(written(directory, file), directory, file)
	if err := evsVerifyPrefixDelta(push, file, file, present(file)); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("the path's own change: %v", err)
	}
	// a path that is no prefix of the one read
	if err := evsVerifyPrefixDelta(push, other, directory, present(directory)); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("a change of a path that holds nothing of the one read: %v", err)
	}
	// the prefix's removal, which ends every path below it
	push, present = build(written(other), directory, other)
	if err := evsVerifyPrefixDelta(push, file, directory, present(directory)); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("a prefix's removal: %v", err)
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
