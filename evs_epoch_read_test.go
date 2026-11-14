// EVS1-M2-28's reads and writes across path epochs (DESIGN-DETAILS 9.6's floors, capture, reads and writes rows, the
// client half) over the stand-in evs of evs_world_test.go, whose entries keep a home epoch as evs's idx/ copies do:
// a file last written before a cut-over by a rooted push reads and verifies, looked up through its directory, moved
// or not; a reader pinned before a cut-over refuses a rollback across it; a read naming no current-epoch token path is
// answered stale_epoch and asked again on the new head; a rooted statement of an epoch the request did not name takes
// one second round; History crosses two cut-overs by E4; a creation across a cut-over answers 409 (9.1 C); a removal
// while its row is carried drops the row (G); a creation under immediate pressure sends nothing (F); the capture
// over three epochs holds P1; and a creation whose push names a generation ahead of its path epoch reads through its
// source after a cut-over, each sealed value under what its own statement names (QD-666).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Moves one path's entry to the current epoch as the copy does, before its directory's rows are translated.
func (self *evsTestWorld) moveEntry(path string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.paths[path].home = self.currentWithLock()
}

// Raises the world's generation and its readers' newest key to epoch, and cuts the ref over to it.
func (self *evsTestWorld) cutOverTo(epoch uint64) {
	self.generation = epoch
	self.gkm.newest = epoch
	self.cutOver(epoch)
}

// The epochs a captured token path of path was named in, in order, by the world's tokens for it.
func (self *evsTestWorld) epochsNamed(path string) []uint64 {
	epochs := []uint64{}
	for _, captured := range self.capturedTokenPaths() {
		if captured.row {
			continue
		}
		for epoch := uint64(1); epoch <= 4; epoch += 1 {
			if captured.epoch == epoch && captured.tokenPath.Equal(self.tokensAt(path, epoch)) {
				epochs = append(epochs, epoch)
			}
		}
	}
	return epochs
}

// 9.1 B's first and third cases, and A: after a cut-over, a file last written in epoch 1 by a rooted push, never read
// by this reader, is looked up through its directory, whose table is served from the source with entry_epoch, read
// from the source by its epoch-1 token path and verified under it by its proof; after the copy it reads from the
// current epoch. A name created after the cut-over is named in the current epoch only.
func TestEvsReadAcrossACutOverByItsRow(t *testing.T) {
	world := newEvsTestWorld(t)
	children := []string{}
	changes := []*evsTestChange{{path: "", children: []string{"d"}}}
	for i := range 40 {
		children = append(children, fmt.Sprintf("f%02d", i))
		changes = append(changes, &evsTestChange{path: fmt.Sprintf("d/f%02d", i), content: []byte(fmt.Sprint("file ", i))})
	}
	changes = append(changes, &evsTestChange{path: "d", children: children})
	world.push(changes...)
	if world.commits[0].built.ChangeTree == nil {
		t.Fatal("the push's changes are inline")
	}
	world.cutOverTo(2)
	reader := world.reader(t, evsTestId("reader"))
	content, _, err := evsTestRead(t, reader, world, "d/f07")
	if err != nil || string(content) != "file 7" {
		t.Fatalf("a file of the source: %q %v", content, err)
	}
	// the push's change in epoch 1, then the read in the current epoch and in its row's
	if epochs := world.epochsNamed("d/f07"); !slicesEqual(epochs, []uint64{1, 2, 1}) {
		t.Errorf("the file was named in %v", epochs)
	}
	listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"})
	if err != nil || len(listing.Entries) != 40 {
		t.Fatalf("the unmoved directory: %v %v", listing, err)
	}
	// a name created after the cut-over: its row is epoch 2's, so nothing of it is named in epoch 1
	world.push(&evsTestChange{path: "d/new", content: []byte("new")}, &evsTestChange{path: "d", children: []string{"new"}})
	other := world.reader(t, evsTestId("other reader"))
	if content, _, err := evsTestRead(t, other, world, "d/new"); err != nil || string(content) != "new" {
		t.Fatalf("a new name: %q %v", content, err)
	}
	if epochs := world.epochsNamed("d/new"); slicesContains(epochs, 1) {
		t.Errorf("a name created in epoch 2 was named in epoch 1: %v", epochs)
	}
	// the copy moves every entry: a fresh reader reads from the current epoch
	world.copyAll()
	moved := world.reader(t, evsTestId("moved reader"))
	if content, _, err := evsTestRead(t, moved, world, "d/f07"); err != nil || string(content) != "file 7" {
		t.Fatalf("a moved file: %q %v", content, err)
	}
}

// QD-666 (question evs1-m2-41-tail-creation-read): a file created in epoch 2 by a push of generation 4, a writer
// holding a key newer than the ref's epoch while a batched due stands, then carried across a PATH_EPOCH to epoch 3
// by its tail. Before the copy it reads through source 2, and after it from epoch 3: its row opens under the epoch
// its statement names, 2, and its sealed fields and record under the generation its statement names, 4, which is
// neither the epoch's key nor p_new's; so a reader pinned before the creation, one first reading after the cut-over
// and one whose pin is already at the head all read it and list it, and a file the same push changed reads too.
func TestEvsGenerationAheadCreationReadsThroughItsSource(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(
		&evsTestChange{path: "", children: []string{"d"}},
		&evsTestChange{path: "d", children: []string{"keep"}},
		&evsTestChange{path: "d/keep", content: []byte("keep 1")},
	)
	world.cutOverTo(2)
	world.copyAll()
	pinned := world.reader(t, evsTestId("pinned reader"))
	if content, _, err := evsTestRead(t, pinned, world, "d/keep"); err != nil || string(content) != "keep 1" {
		t.Fatalf("d/keep before the creation: %q %v", content, err)
	}
	// a writer holding generation 4 creates in epoch 2, the ref's current one
	world.generation = 4
	world.gkm.newest = 4
	created := world.push(
		&evsTestChange{path: "d", children: []string{"n3"}},
		&evsTestChange{path: "d/n3", content: []byte("created ahead")},
		&evsTestChange{path: "d/keep", content: []byte("keep 2")},
	)
	if push := world.commits[created-1].parsed.Push; push.GetPathEpoch() != 2 || push.GetGeneration() != 4 {
		t.Fatalf("the creation names epoch %d and generation %d", push.GetPathEpoch(), push.GetGeneration())
	}
	// the mapper's PATH_EPOCH to epoch 3, the creation carried by its tail: its entry stays in source 2 until the copy
	world.cutOver(3)
	atHead := world.reader(t, evsTestId("reader at the head"))
	if content, _, err := evsTestRead(t, atHead, world, "d/keep"); err != nil || string(content) != "keep 2" {
		t.Fatalf("d/keep, written by the generation-ahead push: %q %v", content, err)
	}
	readAll := func(when string) {
		t.Helper()
		for label, reader := range map[string]*evsTestClient{
			"pinned before the creation": pinned, "pinned at the head": atHead, "fresh": world.reader(t, evsTestId("fresh reader "+when)),
		} {
			if content, _, err := evsTestRead(t, reader, world, "d/n3"); err != nil || string(content) != "created ahead" {
				t.Fatalf("%s, a reader %s: d/n3: %q %v", when, label, content, err)
			}
			if content, _, err := evsTestRead(t, reader, world, "d/keep"); err != nil || string(content) != "keep 2" {
				t.Fatalf("%s, a reader %s: d/keep: %q %v", when, label, content, err)
			}
			listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "d"})
			if err != nil || len(listing.Entries) != 2 {
				t.Fatalf("%s, a reader %s: d's listing: %v %v", when, label, listing, err)
			}
		}
	}
	readAll("before the copy")
	// the creation was named in its own epoch and, after the cut-over, in the current one and its row's source
	if epochs := world.epochsNamed("d/n3"); !slicesContains(epochs, 2) || slicesContains(epochs, 1) || slicesContains(epochs, 4) {
		t.Errorf("d/n3 was named in %v", epochs)
	}
	world.copyAll()
	readAll("after the copy")
}

// 9.1 B's second case: a reader pinned before the cut-over refuses a rollback across it, the change made in epoch 1
// at an inline statement and at a rooted one, each found under the path's token path in that statement's epoch.
func TestEvsRollbackAcrossACutOverRefused(t *testing.T) {
	for _, rooted := range []bool{false, true} {
		world := newEvsTestWorld(t)
		world.push(&evsTestChange{path: "", children: []string{"x"}}, &evsTestChange{path: "x", content: []byte("v1")})
		reader := world.reader(t, evsTestId("reader"))
		if _, _, err := evsTestRead(t, reader, world, "x"); err != nil {
			t.Fatal(err)
		}
		changes := []*evsTestChange{{path: "x", content: []byte("v2")}}
		if rooted {
			for i := range 40 {
				changes = append(changes, &evsTestChange{path: fmt.Sprint("many", i), content: []byte("m")})
			}
		}
		world.push(changes...)
		if (world.commits[1].built.ChangeTree != nil) != rooted {
			t.Fatalf("rooted %t: the change list's place", rooted)
		}
		world.cutOverTo(2)
		world.push(&evsTestChange{path: "other", content: []byte("o")})
		world.serveVersion["x"] = 1
		if _, _, err := evsTestRead(t, reader, world, "x"); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("rooted %t: a rollback across the cut-over: %v", rooted, err)
		}
	}
}

// A read naming no token path in the head's current epoch is answered stale_epoch with the new head, which the reader
// pins and asks again on, naming the path in the new epoch and its floor's source.
func TestEvsStaleEpochAsksAgain(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "", children: []string{"x"}}, &evsTestChange{path: "x", content: []byte("v1")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "x"); err != nil {
		t.Fatal(err)
	}
	world.cutOverTo(2)
	reads := world.reads
	if content, _, err := evsTestRead(t, reader, world, "x"); err != nil || string(content) != "v1" {
		t.Fatalf("after a stale epoch: %q %v", content, err)
	}
	if world.reads-reads != 2 {
		t.Errorf("%d rounds", world.reads-reads)
	}
	if epochs := world.epochsNamed("x"); !slicesEqual(epochs[len(epochs)-3:], []uint64{1, 2, 1}) {
		t.Errorf("named in %v", epochs)
	}
}

// A rooted statement of an epoch the request named no token path in, whose covering prefixes reach the path, takes
// one second round naming that epoch; evs silent there too is refused. Under the path's token path in another epoch the
// statement's prefixes would not reach it at all, the hole 9.1 B names.
func TestEvsSecondRoundForAnUnnamedEpoch(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "", children: []string{"d"}}, &evsTestChange{path: "d", children: []string{"keep"}},
		&evsTestChange{path: "d/keep", content: []byte("kept")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "d/keep"); err != nil {
		t.Fatal(err)
	}
	world.cutOverTo(2)
	world.copyAll()
	changes := []*evsTestChange{}
	for i := range 40 {
		changes = append(changes, &evsTestChange{path: fmt.Sprint("d/many", i), content: []byte("m")})
	}
	world.push(changes...)
	if world.commits[len(world.commits)-1].built.ChangeTree == nil {
		t.Fatal("the epoch-2 push's changes are inline")
	}
	world.cutOverTo(3)
	world.copyAll()
	world.mutatePath = func(reply *protocol.EvsReadPathReply) { reply.Absences = nil }
	if _, _, err := evsTestRead(t, reader, world, "d/keep"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("evs silent in the second round: %v", err)
	}
	world.mutatePath = nil
	reads := world.reads
	if content, _, err := evsTestRead(t, reader, world, "d/keep"); err != nil || string(content) != "kept" {
		t.Fatalf("with the second round: %q %v", content, err)
	}
	if world.reads-reads != 2 || !slicesContains(world.epochsNamed("d/keep"), 2) {
		t.Errorf("%d rounds, named in %v", world.reads-reads, world.epochsNamed("d/keep"))
	}
}

// History across two cut-overs: each older version of an epoch the request names no token path in is answered with
// its statement alone, which the reader takes as E4 by the newer version's prev_push_id and asks again naming its
// epoch; a statement of another push is refused.
func TestEvsHistoryAcrossTwoCutOvers(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "", children: []string{"x"}}, &evsTestChange{path: "x", content: []byte("v1")})
	world.cutOverTo(2)
	world.push(&evsTestChange{path: "x", content: []byte("v2")})
	world.copyAll()
	world.cutOverTo(3)
	world.push(&evsTestChange{path: "x", content: []byte("v3")})
	world.copyAll()
	world.statementAloneUnnamed = true
	reader := world.reader(t, evsTestId("reader"))
	history, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "x"})
	if err != nil || len(history.Versions) != 3 || history.Versions[2].CommitVersion != 1 {
		t.Fatalf("history: %v %v", history, err)
	}
	if epochs := world.epochsNamed("x"); !slicesContains(epochs, 2) || !slicesContains(epochs, 1) {
		t.Errorf("named in %v", epochs)
	}
	// a statement alone of another push is no evidence for the path
	// commits: x v1, the PATH_EPOCH to 2, x v2, the PATH_EPOCH to 3, x v3
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if len(reply.GetStatement()) != 0 && reply.GetVersion() == nil {
			reply.Statement = world.commits[3].statement
		}
	}
	other := world.reader(t, evsTestId("other reader"))
	if _, err := other.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "x"}); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("another push's statement: %v", err)
	}
}

// 9.1 C: w reads no report.md and creates it; v creates it in epoch 1 first; the ref cuts over; w's push, refused 412
// PATH_EPOCH, is re-tokenized naming report.md in epoch 1, its floor, as a source, so evs reads v's file there and the
// creation answers 409, v's file standing. Under a hook that forgets the floors the same retoken commits over it.
func TestEvsCreationAcrossACutOverAnswers409(t *testing.T) {
	for _, forget := range []bool{false, true} {
		writer := newEvsTestWriter(t)
		// the root stands, so w's delta is on a standing directory and only report.md's own check decides
		if _, err := writer.write(t, "seed", []byte("seed")); err != nil {
			t.Fatal(err)
		}
		writer.gkm.newest = 2
		writer.world.generation = 2
		writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
		cutOver := true
		writer.server.onPush = func(statement *EvsStatement) {
			if !cutOver {
				return
			}
			cutOver = false
			writer.world.push(&evsTestChange{path: "", children: []string{"report.md"}}, &evsTestChange{path: "report.md", content: []byte("v's")})
			writer.world.cutOver(2)
		}
		if forget {
			evsRetokenFloorsHook = func(plan *EvsWritePlan) { clear(plan.floors) }
		}
		_, err := writer.write(t, "report.md", []byte("w's"))
		evsRetokenFloorsHook = nil
		content, _, readErr := writer.read(t, "report.md")
		switch {
		case !forget && (!IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT) || readErr != nil || string(content) != "v's"):
			t.Errorf("the retoken naming the floor: %v, report.md %q %v", err, content, readErr)
		case forget && (err != nil || string(content) != "w's"):
			t.Errorf("the floors forgotten: %v, report.md %q %v", err, content, readErr)
		}
	}
}

// G: a removal while the file's row is still carried in epoch 1, its entry already moved, names the child's token in
// the current epoch and in its row's, so the carried row goes; the name created again has one row.
func TestEvsRemovalWhileItsRowIsCarried(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "x", []byte("x1")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write(t, "y", []byte("y1")); err != nil {
		t.Fatal(err)
	}
	writer.gkm.newest = 2
	writer.world.cutOverTo(2)
	writer.world.moveEntry("x")
	if _, err := writer.write(t, "x", nil); err != nil {
		t.Fatalf("the removal: %v", err)
	}
	rowsOf := func(name string) int {
		listing, err := writer.world.reader(t, evsTestId(fmt.Sprint("lister ", name, len(writer.world.commits)))).client.Repo(writer.world.repoId).List(context.Background(), &EvsReadArgs{Path: ""})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, entry := range listing.Entries {
			if string(entry.Name) == name {
				count += 1
			}
		}
		return count
	}
	if rowsOf("x") != 0 || rowsOf("y") != 1 {
		t.Fatalf("after the removal: %d rows of x, %d of y", rowsOf("x"), rowsOf("y"))
	}
	if _, err := writer.write(t, "x", []byte("x2")); err != nil {
		t.Fatal(err)
	}
	if rowsOf("x") != 1 {
		t.Fatalf("%d rows of x created again", rowsOf("x"))
	}
}

// F: a device holding a REMOVE generation the ref has not cut over to, the crossing immediate, plans a creation on a
// blocking ref: nothing of the new name is sent, and past its waits the write answers EVS_PATH_EPOCH_DUE; a
// modification of a standing path still writes.
func TestEvsCreationUnderImmediatePressureWaits(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "a", []byte("a1")); err != nil {
		t.Fatal(err)
	}
	writer.gkm.newest = 2
	writer.gkm.causes[2] = GkmCauseRemove
	writer.gkm.auths[1] = 3
	writer.world.config.repo.HoldersShrunkAt = 5
	posted := len(writer.server.postedStatements)
	if _, err := writer.write(t, "new.txt", []byte("new")); !errors.Is(err, ErrEvsPathEpochDue) {
		t.Fatalf("a creation under immediate pressure: %v", err)
	}
	if len(writer.server.postedStatements) != posted || 0 < len(writer.world.epochsNamed("new.txt")) {
		t.Fatalf("%d pushes posted, the new name named in %v", len(writer.server.postedStatements)-posted, writer.world.epochsNamed("new.txt"))
	}
	if _, err := writer.write(t, "a", []byte("a2")); err != nil {
		t.Fatalf("a modification under the same pressure: %v", err)
	}
}

// The push sender's retoken of a push in parts, DESIGN-DETAILS 9.6's 2,000 entries: every part posted again under the
// new push id, committed in the new epoch, sealed once.
func TestEvsRetokenOfAPushInParts(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.gkm.newest = 2
	writer.world.generation = 2
	const fileCount = 2000
	writes := []*EvsPathWrite{}
	for i := 0; i < fileCount; i += 1 {
		path := fmt.Sprintf("file-%04d.txt", i)
		writer.server.know(path)
		writes = append(writes, &EvsPathWrite{Path: path, Content: bytes.NewReader([]byte(path))})
	}
	writer.seed(t)
	writer.cutOverAtPushes(2)
	result, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: writes})
	if err != nil {
		t.Fatal(err)
	}
	statement := writer.world.commits[result.Version-1].parsed
	partCount := int(statement.Push.GetPartCount())
	if statement.Push.GetPathEpoch() != 2 || partCount < 2 || len(writer.server.postedParts) != 2*partCount || writer.gkm.ensured != 1 {
		t.Fatalf("epoch %d, %d parts, %d parts posted, %d seals", statement.Push.GetPathEpoch(), statement.Push.GetPartCount(),
			len(writer.server.postedParts), writer.gkm.ensured)
	}
	if read, _, err := writer.read(t, "file-1999.txt"); err != nil || string(read) != "file-1999.txt" {
		t.Errorf("read back: %v", err)
	}
}

// A retoken whose new head's generation is past the sealed one goes to the rebuild, sealing again under the newer
// generation and planning on the new head.
func TestEvsRetokenPastTheSealedGenerationRebuilds(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	writer.server.onPush = func(statement *EvsStatement) {
		if statement.Push.GetGeneration() == 1 {
			writer.gkm.newest = 2
			writer.world.generation = 2
			writer.world.cutOver(2)
		}
	}
	result, err := writer.write(t, "big.txt", evsTestContent("generation", 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	statement, _ := writer.committedPayload(t, result.Version)
	if statement.Push.GetGeneration() != 2 || statement.Push.GetPathEpoch() != 2 || writer.gkm.ensured != 2 || len(writer.server.uploads) != 2 {
		t.Fatalf("generation %d, epoch %d, %d EnsureWritable, %d uploads", statement.Push.GetGeneration(), statement.Push.GetPathEpoch(),
			writer.gkm.ensured, len(writer.server.uploads))
	}
}

// The capture (FS-4's no late token; DESIGN-DETAILS 9.3's P1): over three epochs, names created before, between and
// after each cut-over, read, listed, changed, removed and created again, a push across each cut-over, every token path
// a request names under an epoch below the current one has an earlier one of the same path at or below that epoch.
func TestEvsCaptureNoLateToken(t *testing.T) {
	if late := evsCaptureLateTokens(t); 0 < len(late) {
		t.Fatalf("late tokens: %s", strings.Join(late, ", "))
	}
}

// The capture's twin (DESIGN-DETAILS 9.6): the same run with every read naming every listed source, as the landed
// tokenize did, sends a late token, which the capture catches: d, created after the second cut-over while epoch 2
// stands as a source, named under that source, where no request had shown it.
func TestEvsCaptureCatchesTheTokenizeTwin(t *testing.T) {
	evsTokenizeEverySourceHook = true
	defer func() { evsTokenizeEverySourceHook = false }()
	late := evsCaptureLateTokens(t)
	if !slices.Contains(late, "d in epoch 2 at 3") {
		t.Fatalf("the twin's late tokens: %v", late)
	}
}

// The capture's run, and every late token it records: a token path under an epoch below the current one with no
// earlier token of the same path at or below that epoch.
func evsCaptureLateTokens(t *testing.T) []string {
	t.Helper()
	writer := newEvsTestWriter(t)
	world := writer.world
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	reader := world.reader(t, evsTestId("reader"))
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	readAll := func(paths ...string) {
		t.Helper()
		for _, path := range paths {
			out := &bytes.Buffer{}
			_, err := reader.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
			if err != nil && !errors.Is(err, ErrEvsPathAbsent) {
				t.Fatalf("read %s: %v", path, err)
			}
		}
		if _, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: ""}); err != nil {
			t.Fatalf("list: %v", err)
		}
	}
	write := func(path string, content []byte) {
		t.Helper()
		if _, err := writer.write(t, path, content); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write("a", []byte("a1"))
	write("b", []byte("b1"))
	readAll("a", "b", "c")
	// a push across the first cut-over, then a name created between
	writer.gkm.newest = 3
	world.generation = 3
	writer.cutOverAtPushes(2)
	write("c", []byte("c1"))
	writer.server.onPush = nil
	readAll("a", "b", "c")
	write("a", []byte("a2"))
	write("b", nil)
	readAll("a", "b", "c")
	world.copyAll()
	world.cutOver(3)
	write("b", []byte("b2"))
	write("d", []byte("d1"))
	readAll("a", "b", "c", "d")
	for _, path := range []string{"a", "b", "c", "d"} {
		if _, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: path}); err != nil && !errors.Is(err, ErrEvsPathAbsent) {
			t.Fatalf("history %s: %v", path, err)
		}
	}
	captured := world.capturedTokenPaths()
	pathOf := func(captured *evsTestCaptured) string {
		for _, path := range []string{"a", "b", "c", "d"} {
			tokenPath := world.tokensAt(path, captured.epoch)
			if (captured.row && captured.tokenPath[0] == tokenPath.Last()) || (!captured.row && captured.tokenPath.Equal(tokenPath)) {
				return path
			}
		}
		return ""
	}
	late := []string{}
	for i, token := range captured {
		path := pathOf(token)
		if path == "" || token.current <= token.epoch {
			continue
		}
		shown := false
		for _, earlier := range captured[:i] {
			if earlier.epoch <= token.epoch && pathOf(earlier) == path {
				shown = true
				break
			}
		}
		if !shown {
			late = append(late, fmt.Sprintf("%s in epoch %d at %d", path, token.epoch, token.current))
		}
	}
	if len(captured) == 0 {
		t.Fatal("nothing captured")
	}
	_ = http.StatusOK
	return late
}

func slicesEqual(a []uint64, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func slicesContains(values []uint64, value uint64) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// DESIGN-DETAILS 9.2.3's first push (QD-632): a device holding a REMOVE generation creates a ref in that generation's
// epoch. Its read of the ref with no head names no token, its push names epoch 2 and every token it shows evs is of
// epoch 2, none a holder the removal dropped could test, and the head starts in epoch 2.
func TestEvsFirstPushNamesTheNewestRemovalItHolds(t *testing.T) {
	writer, below := evsFirstPushCapture(t)
	if 0 < len(below) {
		t.Fatalf("tokens below the removal's epoch: %v", below)
	}
	writer.world.stateLock.Lock()
	defer writer.world.stateLock.Unlock()
	if head := writer.world.headSummaryWithLock(); head.GetVersion() != 1 || head.GetPathEpoch().GetCurrent() != 2 {
		t.Fatalf("the head after the first push: %v", head)
	}
}

// PathEpochTwin-NewRefAtOne (DESIGN-DETAILS 9.6): a creator that names epoch 1 whatever it holds shows evs its new names
// under the epoch a dropped holder can test, which the same capture catches.
func TestEvsFirstPushCaptureCatchesTheNewRefAtOneTwin(t *testing.T) {
	evsFirstEpochHook = func(generation uint64) uint64 { return 1 }
	defer func() { evsFirstEpochHook = nil }()
	if _, below := evsFirstPushCapture(t); len(below) == 0 {
		t.Fatal("the twin's first push named no token below the removal's epoch")
	}
}

// One device holding generation 2, a REMOVE, writes docs/a.md to a ref with no head; every token path the run showed
// evs under an epoch below 2.
func evsFirstPushCapture(t *testing.T) (*evsTestWriter, []string) {
	t.Helper()
	writer := newEvsTestWriter(t)
	writer.gkm.newest = 2
	writer.gkm.causes[2] = GkmCauseRemove
	if _, err := writer.write(t, "docs/a.md", []byte("a")); err != nil {
		t.Fatal(err)
	}
	world := writer.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	below := []string{}
	for _, captured := range world.captured {
		if 0 < len(captured.tokenPath) && max(1, captured.epoch) < 2 {
			below = append(below, fmt.Sprintf("a token path of %d tokens in epoch %d", len(captured.tokenPath), max(1, captured.epoch)))
		}
	}
	return writer, below
}
