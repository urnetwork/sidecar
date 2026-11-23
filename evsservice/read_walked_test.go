// Reads a walk decides, on T2's fakes through the engine: a removal whose marker a collection took, served from the
// window to a reader pinned below it (QD-879); with no fold and no collection, a removal served through a prefix's
// later removal, held to the client's own reader (QD-978); and once the window paged a collected removal out, the path
// served plain absent, which the client's reader verifies by the removal its own walk holds (QD-979).

package evsservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Deletes the entry of labels' path, as a marker's collection does.
func (self *pushFixture) deleteEntry(labels ...string) {
	self.t.Helper()
	if err := self.cluster.Delete(self.paidContext(), IndexEntryKey(self.check.repoId, self.check.refId, 1, checkTestPath(labels...))); err != nil {
		self.t.Fatal(err)
	}
}

// Checks a removal as §11.9's reader does: its statement, among those after the pin or beside the reply, removes the
// path, inline or by its proof, one past the version the removal names.
func requireRemovalProven(t *testing.T, reply *readTestReply, pathReply *protocol.EvsReadPathReply, path sidecar.EvsTokenPath) {
	t.Helper()
	removal := pathReply.GetRemoval()
	if removal == nil || pathReply.GetVersion() != nil {
		t.Fatalf("path %v: no removal alone", pathReply)
	}
	statement := readTestStatement(t, reply, pathReply, removal.GetRemovalVersion())
	push := statement.Push
	if !bytes.Equal(push.GetPushId(), removal.GetPushId()) {
		t.Fatal("a removal naming another push than its statement's")
	}
	var change *protocol.EvsChange
	if len(push.GetChangesRoot()) == 0 {
		if len(pathReply.GetProof()) != 0 {
			t.Fatal("a proof beside an inline list")
		}
		for _, listed := range statement.Changes {
			if listed.TokenPath.Equal(path) {
				change = listed.Change
			}
		}
	} else {
		proven, provenPath, err := sidecar.EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), pathReply.GetProof())
		if err != nil || !provenPath.Equal(path) {
			t.Fatalf("proof: %v %v", err, provenPath)
		}
		change = proven
	}
	if change == nil || len(change.GetEntrySha256()) != 0 || change.GetBaseEntryVersion()+1 != removal.GetPathVersion() {
		t.Fatalf("the statement's change %v is not the removal %v", change, removal)
	}
}

// Whether a path reply names a path evs holds nothing of.
func readReplyPlainAbsent(pathReply *protocol.EvsReadPathReply) bool {
	return pathReply.GetRemoval() == nil && pathReply.GetVersion() == nil && pathReply.GetBase() == nil &&
		len(pathReply.GetStatement()) == 0 && len(pathReply.GetProof()) == 0
}

// QD-879 (question test-m2-04-recreate-after-collection): once a removal's marker is collected, a reader pinned below
// the removal, whose walk holds its statement, is served the removal from the window, as its marker served it; a
// reader pinned at or past it reads the path absent; and the path is created again at max(b, m) + 1.
func TestReadServesARemovalFromTheWindowOnceItsMarkerIsCollected(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	write := fixture.plan()
	write.Changes = append(write.Changes, fixture.check.change(write, path, 1, 2))
	fixture.requireCommitted(fixture.push(write), 2)
	fixture.awaitStepEights()
	remove := fixture.plan()
	remove.Changes = append(remove.Changes, fixture.check.change(remove, path, 2, 0))
	fixture.requireCommitted(fixture.push(remove), 3)
	fixture.awaitStepEights()
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "b")
	fixture.foldRef()
	if head := fixture.head(); head.Head.GetFoldedThrough() != 4 {
		t.Fatalf("folded through %d", head.Head.GetFoldedThrough())
	}
	marked := fixture.readPath(token, 0, true, path).paths[0].GetRemoval()
	if marked == nil || marked.GetRemovalVersion() != 3 || marked.GetPathVersion() != 3 || !bytes.Equal(marked.GetPushId(), remove.PushId.Bytes()) {
		t.Fatalf("the marker's removal %v", marked)
	}
	fixture.deleteEntry("a")
	for _, pin := range []uint64{0, 1, 2} {
		reply := fixture.readPath(token, pin, true, path)
		pathReply := reply.paths[0]
		removal := pathReply.GetRemoval()
		if removal == nil || removal.GetRemovalVersion() != 3 || removal.GetPathVersion() != 3 || !bytes.Equal(removal.GetPushId(), remove.PushId.Bytes()) ||
			removal.GetLeafPart() != 0 || removal.GetLeafIndex() != 0 {
			t.Fatalf("pinned at %d: removal %v, the marker's %v", pin, removal, marked)
		}
		// the statement is among those the walk returns, not beside the reply
		if len(pathReply.GetStatement()) != 0 || len(reply.statements) != int(4-pin) {
			t.Fatalf("pinned at %d: %d statements, %d bytes beside the reply", pin, len(reply.statements), len(pathReply.GetStatement()))
		}
		requireRemovalProven(t, reply, pathReply, path)
	}
	for _, pin := range []uint64{3, 4} {
		reply := fixture.readPath(token, pin, true, path)
		if !readReplyPlainAbsent(reply.paths[0]) {
			t.Fatalf("pinned at %d, past the removal: %v", pin, reply.paths[0])
		}
	}
	// a path never written reads absent to a reader of any pin
	if reply := fixture.readPath(token, 0, true, checkTestPath("never")); !readReplyPlainAbsent(reply.paths[0]) {
		t.Fatalf("a path never written: %v", reply.paths[0])
	}
	// created again by the versions rule: b is past the removal, so the marker's going moves nothing
	create := fixture.plan()
	create.Changes = append(create.Changes, fixture.check.change(create, path, 0, max(create.BaseVersion, marked.GetPathVersion())+1))
	fixture.requireCommitted(fixture.push(create), 5)
	fixture.awaitStepEights()
	reply := fixture.readPath(token, 0, true, path)
	if reply.paths[0].GetRemoval() != nil || reply.paths[0].GetVersion().GetCommitVersion() != 5 {
		t.Fatalf("re-created: %v", reply.paths[0])
	}
	requireVersionProven(t, reply, reply.paths[0], path)
}

// The same under changes_root: the removal a collection took the marker of comes with its inclusion proof from the
// window's record, located by the path's current token path, the marker's leaf place being gone with it.
func TestReadProvesACollectedRemovalUnderChangesRoot(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	remove := fixture.plan()
	remove.Changes = append(remove.Changes, fixture.check.change(remove, path, 1, 0))
	for _, label := range readTestLabels("n") {
		fixture.create(remove, label)
	}
	if built := fixture.built(remove); len(built.Statement.Push.GetChangesRoot()) == 0 || len(built.Parts) != 0 {
		t.Fatal("a push whose list is inline or in parts")
	}
	fixture.requireCommitted(fixture.push(remove), 2)
	fixture.awaitStepEights()
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "b")
	fixture.foldRef()
	marked := fixture.readPath(token, 0, true, path)
	requireRemovalProven(t, marked, marked.paths[0], path)
	if marked.paths[0].GetRemoval().GetLeafIndex() == 0 {
		t.Fatalf("the marker's removal %v names no leaf place", marked.paths[0].GetRemoval())
	}
	fixture.deleteEntry("a")
	reply := fixture.readPath(token, 0, true, path)
	removal := reply.paths[0].GetRemoval()
	if removal == nil || removal.GetRemovalVersion() != 2 || removal.GetPathVersion() != 2 || removal.GetLeafIndex() != 0 || len(reply.paths[0].GetProof()) == 0 {
		t.Fatalf("removal %v with %d proofs", removal, len(reply.paths[0].GetProof()))
	}
	requireRemovalProven(t, reply, reply.paths[0], path)
	if reply := fixture.readPath(token, 2, true, path); !readReplyPlainAbsent(reply.paths[0]) {
		t.Fatalf("pinned at the removal: %v", reply.paths[0])
	}
}

// A device's verifying reader over the fixture's engine: an EvsClient of the fixture's other sidecar whose config is
// the fixture's state, so what evs serves is held to the client's own checks of a head and a path (evs_verify.go,
// evs_proof.go), its alarms kept.
type walkedTestReader struct {
	fixture *pushFixture
	client  *sidecar.EvsClient

	stateLock sync.Mutex
	alarms    []sidecar.SidecarEvsAlarm
}

func newWalkedTestReader(fixture *pushFixture) *walkedTestReader {
	t := fixture.t
	t.Helper()
	check := fixture.check
	sign := checkTestSign(check.otherKey, check.otherId)
	identity := &sidecar.SidecarIdentity{
		NetworkId: check.networkId, SidecarId: check.otherId, ClientId: check.clientId, Generation: 1,
		IdentityPublicKey: check.otherKey.Public().(ed25519.PublicKey),
	}
	reader := &walkedTestReader{fixture: fixture}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: check.networkId,
		EvsUrl:    "https://evs.example",
		Transport: reader,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(check.otherId)
			return fixture.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(check.networkId), ClientId: connect.Id(check.clientId), SidecarId: &connectSidecarId,
				Audience: EvsAudience, Scopes: scopes, IssuedAt: fixture.clock.Now(), ExpiresAt: fixture.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sign,
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      sidecartest.NewFakeGkm(fixture.clock, fixture.host.Blobs, nil).Client(check.otherId, sidecar.GkmSignFunction(sign)),
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return check.auth },
		Emit: func(event sidecar.SidecarEvent) {
			if event.Kind != sidecar.SidecarEventEvsAlarm {
				return
			}
			reader.stateLock.Lock()
			defer reader.stateLock.Unlock()
			reader.alarms = append(reader.alarms, event.EvsAlarm)
		},
		Clock:    &reseedDeviceClock{clock: fixture.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	reader.client = client
	return reader
}

// The engine serves what the client asks: the log's pages, should its walk page them.
func (self *walkedTestReader) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.fixture.engine.Handler().ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

// The alarms the client raised, in order.
func (self *walkedTestReader) raised() []sidecar.SidecarEvsAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.alarms)
}

// reply, a read from pin whose C there is chain (C_0 for nil), held to the client's check of its head and then of its
// one path, path in epoch 1, as the client's read runs them (evs_epoch_read.go), the path's own pin at since: the
// path as verified, or the error the read ends in.
func (self *walkedTestReader) verify(reply *readTestReply, pin uint64, chain []byte, since uint64, path sidecar.EvsTokenPath) (*sidecar.EvsVerifiedPath, error) {
	check := self.fixture.check
	fromChain := sidecar.EvsChainStart(check.repoId, check.refId)
	if chain != nil {
		fromChain = [sha256.Size]byte(chain)
	}
	head, err := self.client.Verifier().VerifyHead(self.fixture.ctx, &sidecar.EvsHeadRead{
		RepoId: check.repoId, RefId: check.refId, Head: reply.head, FromVersion: pin, FromChain: fromChain,
		Statements: reply.statements, Behind: reply.behind,
	})
	if err != nil {
		return nil, err
	}
	epochs := &sidecar.EvsPathEpochs{
		TokenPathIn: func(epoch uint64) (sidecar.EvsTokenPath, error) { return path, nil },
		Named:       map[uint64]bool{1: true},
		Since:       since,
	}
	verified, more, err := self.client.Verifier().VerifyPath(self.fixture.ctx, head, epochs, reply.paths[0])
	if err == nil && len(more) != 0 {
		return nil, fmt.Errorf("epochs %v asked again", more)
	}
	return verified, err
}

// d and d/a.txt.
func walkedTestPaths() (sidecar.EvsTokenPath, sidecar.EvsTokenPath) {
	return checkTestPath("d"), checkTestPath("d", "a.txt")
}

// A push on the head creating d, its table naming a.txt, and d/a.txt beside it, each at max(b, m) + 1 with m its
// standing removal's path version, 0 for none (§11.7's versions row); with directoryOnly, d alone with an empty
// table. The version it committed at.
func (self *pushFixture) walkedCreate(directoryRemoval uint64, fileRemoval uint64, directoryOnly bool) uint64 {
	self.t.Helper()
	directory, file := walkedTestPaths()
	plan := self.plan()
	rows := []*protocol.EvsName{}
	if !directoryOnly {
		rows = append(rows, &protocol.EvsName{Token: file.Last().Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed a.txt")})
		plan.Changes = append(plan.Changes, self.check.change(plan, file, 0, max(plan.BaseVersion, fileRemoval)+1))
	}
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: directory, EntryVersion: self.check.directoryEntry(plan, max(plan.BaseVersion, directoryRemoval)+1, rows, nil),
	})
	version := self.requireCommitted(self.push(plan), plan.BaseVersion+1).GetVersion()
	self.awaitStepEights()
	return version
}

// A push on the head removing path, whose newest version is base, with 30 creations of labels from rooted beside it
// when rooted is not empty, which put the push's list under changes_root. The version it committed at.
func (self *pushFixture) walkedRemove(path sidecar.EvsTokenPath, base uint64, rooted string) uint64 {
	self.t.Helper()
	plan := self.plan()
	plan.Changes = append(plan.Changes, self.check.change(plan, path, base, 0))
	if rooted != "" {
		for _, label := range readTestLabels(rooted) {
			self.create(plan, label)
		}
	}
	if built := self.built(plan); (len(built.Statement.Push.GetChangesRoot()) != 0) != (rooted != "") || len(built.Parts) != 0 {
		self.t.Fatalf("a removal whose list is not as asked (rooted %q)", rooted)
	}
	version := self.requireCommitted(self.push(plan), plan.BaseVersion+1).GetVersion()
	self.awaitStepEights()
	return version
}

// QD-978 (question evs-removal-from-window-prefix-removal-after-removal, option 1) on evs, with no fold and no
// collection: d holding d/a.txt at 1, d/a.txt removed at 2 and d at 3. A reader pinned at 1, whose walk holds both
// removals, is served d/a.txt's own removal at 2, d's removal adding none of its own (§11.7's removal row; newest.go's
// below), and the client's reader verifies it, raising no alarm.
func TestReadServesARemovalThroughItsPrefixsLaterRemoval(t *testing.T) {
	walkedTestRemovalThroughPrefix(t, false)
}

// The same with both removals under changes_root: the removal comes with its inclusion proof, and d's removal with
// d/a.txt's adjacent leaves and nothing for d itself (§11.9's reply row), which the reader takes for a path served
// removed.
func TestReadServesARemovalThroughARootedPrefixRemoval(t *testing.T) {
	walkedTestRemovalThroughPrefix(t, true)
}

func walkedTestRemovalThroughPrefix(t *testing.T, rooted bool) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	reader := newWalkedTestReader(fixture)
	directory, file := walkedTestPaths()
	fileLabel, directoryLabel, fileAbsenceCount := "", "", 0
	if rooted {
		fileLabel, directoryLabel, fileAbsenceCount = "n", "m", 1
	}
	fixture.walkedCreate(0, 0, false)
	chainAtOne := fixture.head().Head.GetChain()
	if verified, err := reader.verify(fixture.readPath(token, 0, true, file), 0, nil, 0, file); err != nil || verified.Entry == nil {
		t.Fatalf("d/a.txt at 1: %v", err)
	}
	removed := fixture.walkedRemove(file, 1, fileLabel)
	directoryRemoved := fixture.walkedRemove(directory, 1, directoryLabel)
	if head := fixture.head(); head.Version() != directoryRemoved || head.Head.GetFoldedThrough() != 0 {
		t.Fatalf("head at %d, folded through %d", head.Version(), head.Head.GetFoldedThrough())
	}
	reply := fixture.readPath(token, 1, true, file)
	pathReply := reply.paths[0]
	if removal := pathReply.GetRemoval(); removal == nil || removal.GetRemovalVersion() != removed || removal.GetPathVersion() != 2 {
		t.Fatalf("served %v, not d/a.txt's own removal at %d", pathReply, removed)
	}
	if len(reply.statements) != 2 {
		t.Fatalf("%d statements after the pin, not both removals", len(reply.statements))
	}
	requireRemovalProven(t, reply, pathReply, file)
	fileAbsences, directoryAbsences := 0, 0
	for _, absence := range pathReply.GetAbsences() {
		absencePath, err := sidecar.ParseEvsTokenPath(absence.GetTokenPath())
		switch {
		case err != nil || absence.GetVersion() != directoryRemoved:
			t.Fatalf("an absence %v", absence)
		case absencePath.Equal(file) && len(absence.GetPresent()) == 0:
			fileAbsences += 1
		case absencePath.Equal(directory):
			directoryAbsences += 1
		}
	}
	if fileAbsences != fileAbsenceCount || directoryAbsences != 0 {
		t.Fatalf("%d absences of d/a.txt and %d of d", fileAbsences, directoryAbsences)
	}
	verified, err := reader.verify(reply, 1, chainAtOne, 1, file)
	if err != nil || verified.Removal == nil || verified.CommitVersion != removed || !verified.ChangePath.Equal(file) {
		t.Fatalf("the reader's check: %+v %v", verified, err)
	}
	if alarms := reader.raised(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// The same when the removal evs serves is a prefix's: d holding d/a.txt at 1, d removed at 2 and d/a.txt with it, d
// created again empty at 3 and removed again at 4. A reader pinned at 1 is served d's removal at 2, d/a.txt's version
// one past its last, and the walk's later creation and removal of d leave d/a.txt removed as served.
func TestReadServesAPrefixsRemovalThroughThePrefixsLaterRemoval(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	reader := newWalkedTestReader(fixture)
	directory, file := walkedTestPaths()
	fixture.walkedCreate(0, 0, false)
	chainAtOne := fixture.head().Head.GetChain()
	if verified, err := reader.verify(fixture.readPath(token, 0, true, file), 0, nil, 0, file); err != nil || verified.Entry == nil {
		t.Fatalf("d/a.txt at 1: %v", err)
	}
	removed := fixture.walkedRemove(directory, 1, "")
	fixture.walkedCreate(2, 0, true)
	fixture.walkedRemove(directory, 3, "")
	reply := fixture.readPath(token, 1, true, file)
	if removal := reply.paths[0].GetRemoval(); removal == nil || removal.GetRemovalVersion() != removed || removal.GetPathVersion() != 2 {
		t.Fatalf("served %v, not d's removal at %d", reply.paths[0], removed)
	}
	verified, err := reader.verify(reply, 1, chainAtOne, 1, file)
	if err != nil || verified.Removal == nil || !verified.ChangePath.Equal(directory) {
		t.Fatalf("the reader's check: %+v %v", verified, err)
	}
	if alarms := reader.raised(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// QD-978's limit on evs: d/a.txt created again after both removals, at max(b, m) + 1, reads as that version, and a
// reply serving its removal at 2 in its place contradicts the walked creation, which the reader refuses and alarms as
// tampering.
func TestReadOfARemovalServedOverALaterCreationIsRefused(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	reader := newWalkedTestReader(fixture)
	directory, file := walkedTestPaths()
	fixture.walkedCreate(0, 0, false)
	chainAtOne := fixture.head().Head.GetChain()
	fixture.walkedRemove(file, 1, "")
	fixture.walkedRemove(directory, 1, "")
	removal := fixture.readPath(token, 1, true, file).paths[0]
	if removal.GetRemoval() == nil {
		t.Fatalf("served %v, not a removal", removal)
	}
	created := fixture.walkedCreate(2, 2, false)
	reply := fixture.readPath(token, 1, true, file)
	requireVersionProven(t, reply, reply.paths[0], file)
	verified, err := reader.verify(reply, 1, chainAtOne, 1, file)
	if err != nil || verified.CommitVersion != created || verified.Entry.GetVersion() != max(created-1, 2)+1 {
		t.Fatalf("the creation at %d: %+v %v", created, verified, err)
	}
	reply.paths[0] = removal
	if _, err := reader.verify(reply, 1, chainAtOne, 1, file); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
		t.Fatalf("the removal served over the creation: %v", err)
	}
	if alarms := reader.raised(); len(alarms) != 1 || alarms[0] != sidecar.SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
}

// QD-979 (question evs-removal-from-window-removal-paged-out, option 2) on evs: x.txt written at 1 and 2 and removed at
// 3, 70 versions, a fold, the collection of x.txt's marker, and 60 more versions, the head at 133 and the window from
// 64. NewestWalked finds the removal nowhere, so evs serves x.txt plain absent, with behind, to a reader pinned below
// it (QD-879's window case passed); the client's reader, paging the log, verifies it absent by its walk's newest change
// of x.txt, the removal at 3, whether its walk holds both writes before it, the second, or neither, with no alarm. A
// reader pinned past the removal walks no change of x.txt. x.txt's creation commits at b + 1, and the absent reply in
// place of the version it reads contradicts the walked creation, which the reader refuses and alarms as tampering.
// evs's own answer here is TestNewestWalkedReadsNoRemovalTheWindowPagedOut's.
func TestReadAbsentPastAPagedOutRemovalVerifiesByTheWalk(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	reader := newWalkedTestReader(fixture)
	path := checkTestPath("x.txt")
	chains := [][]byte{nil}
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "x.txt")
	chains = append(chains, fixture.head().Head.GetChain())
	fixture.commitChange(path, 1, 2, 0)
	chains = append(chains, fixture.head().Head.GetChain())
	removalId, removed := fixture.commitChange(path, 2, 0, 0)
	chains = append(chains, fixture.head().Head.GetChain())
	fixture.commitOthers("n", 70)
	fixture.foldRef()
	if marked := fixture.readPath(token, 0, true, path).paths[0].GetRemoval(); marked == nil || marked.GetRemovalVersion() != removed {
		t.Fatalf("the marker's removal %v", marked)
	}
	fixture.deleteEntry("x.txt")
	fixture.commitOthers("m", 60)
	head := fixture.head().Head
	if removed != 3 || head.GetVersion() != 133 || head.GetFoldedThrough() != 73 || EvsHeadWindowFirstVersion(head) != 64 {
		t.Fatalf("removed at %d, head %d folded through %d, the window from %d", removed, head.GetVersion(), head.GetFoldedThrough(), EvsHeadWindowFirstVersion(head))
	}
	for pin := uint64(0); pin <= 3; pin += 1 {
		reply := fixture.readPath(token, pin, true, path)
		if !readReplyPlainAbsent(reply.paths[0]) || reply.behind != pin+1 {
			t.Fatalf("pinned at %d: %v, behind %d", pin, reply.paths[0], reply.behind)
		}
		verified, err := reader.verify(reply, pin, chains[pin], pin, path)
		if err != nil || !verified.Absent {
			t.Fatalf("pinned at %d: the reader's check: %+v %v", pin, verified, err)
		}
		walked := verified.WalkedRemoval
		if pin == removed {
			if walked != nil || verified.Floor != 0 {
				t.Fatalf("pinned at the removal: a walked removal %+v, floor %d", walked, verified.Floor)
			}
			continue
		}
		if walked == nil || walked.CommitVersion != removed || !walked.ChangePath.Equal(path) || len(walked.Change.GetEntrySha256()) != 0 ||
			!bytes.Equal(walked.Statement.Push.GetPushId(), removalId.Bytes()) {
			t.Fatalf("pinned at %d: the walked removal %+v, not x.txt's at %d", pin, walked, removed)
		}
		// E1: the removal's statement, verified, names x.txt's token path in epoch 1
		if verified.Floor != 1 {
			t.Fatalf("pinned at %d: floor %d after the walked removal", pin, verified.Floor)
		}
	}
	if alarms := reader.raised(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	// created again at max(b, m) + 1 with no m: b + 1
	absent := fixture.readPath(token, 2, true, path).paths[0]
	_, created := fixture.commitChange(path, 0, 0, 0)
	reply := fixture.readPath(token, 2, true, path)
	requireVersionProven(t, reply, reply.paths[0], path)
	verified, err := reader.verify(reply, 2, chains[2], 2, path)
	if err != nil || created != head.GetVersion()+1 || verified.CommitVersion != created || verified.Entry.GetVersion() != head.GetVersion()+1 {
		t.Fatalf("the creation at %d: %+v %v", created, verified, err)
	}
	reply.paths[0] = absent
	if _, err := reader.verify(reply, 2, chains[2], 2, path); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
		t.Fatalf("absent served over the creation: %v", err)
	}
	if alarms := reader.raised(); len(alarms) != 1 || alarms[0] != sidecar.SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
}
