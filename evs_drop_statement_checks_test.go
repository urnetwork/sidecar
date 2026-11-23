//go:build !ios_extension

// The drop listing's and the cancel's checks of a drop's own statement (§11.7's action and states rows, §11.9's trusts
// row, §11.13's start and table rows; DESIGN-DETAILS 10.2.3's H1; FS-89's cancel clause), against the stand-in evs at
// format 2: Drops names a drop's paths from the body of the statement at the drop's version, and CancelDrop sends a
// cancel only where that statement is the table's DROP and its body names the drop cancelled. Each runs where the walk
// of the device's head read holds the statement, as on a device that has not read the ref since it, and where it lies
// at or below the device's pin, read again from evs's log and verified on its own, where a DROP the log serves at its
// own base's version is refused too. Before the fix both checks looked for the statement in a head that never
// carries statements: the listing named nothing on a device keeping no body of the drop, as its signer keeps none,
// and every cancel was sent unchecked.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A world where "other.txt" was written once and "notes/plan.md" five times, then notes/plan.md's history dropped by
// the writer, a repo admin, with the drop as evs's table lists it, pending. Right after the drop the writer's pin
// stands below the drop's version, its last read having been the one its DROP was planned on.
type evsTestDropTarget struct {
	writer  *evsTestWriter
	server  *evsTestDropServer
	capture *evsTestDropCapture
	pushed  *EvsDropPushResult
	status  *protocol.EvsDropStatus
}

func newEvsTestDropTarget(t *testing.T) *evsTestDropTarget {
	t.Helper()
	ctx := context.Background()
	writer, server, capture := newEvsTestDropPusher(t)
	if _, err := writer.write(t, "other.txt", []byte("other")); err != nil {
		t.Fatal(err)
	}
	evsTestDropHistory(t, writer, server, "notes/plan.md", 3000, 5)
	preview, err := writer.repo.DropHistoryPreview(ctx, &EvsDropPreviewArgs{Paths: []string{"notes/plan.md"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.repo.DropHistory(ctx, &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "notes/plan.md"})
	if err != nil {
		t.Fatal(err)
	}
	pushed := result.Pushes[0]
	target := &evsTestDropTarget{writer: writer, server: server, capture: capture, pushed: pushed}
	target.status = target.entry(pushed.DropId, pushed.PushId, pushed.Version)
	target.list(target.status)
	return target
}

// The table's entry of a pending drop: its id, push and version as given, its window the drop's.
func (self *evsTestDropTarget) entry(dropId Id, pushId Id, version uint64) *protocol.EvsDropStatus {
	return &protocol.EvsDropStatus{
		DropId: dropId.Bytes(), RefId: self.writer.world.refId.Bytes(), PushId: pushId.Bytes(), Version: version,
		NotBeforeMs: self.pushed.NotBefore.UnixMilli(), State: protocol.EvsDropState_EVS_DROP_PENDING,
	}
}

// Lists status in the drop table, alone.
func (self *evsTestDropTarget) list(status *protocol.EvsDropStatus) {
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	self.server.drops = []*protocol.EvsDropStatus{status}
}

// Raises the writer's pin to the ref's head by a read of another path, so a statement at or below the head lies below
// the walk of the writer's next head read.
func (self *evsTestDropTarget) readPast(t *testing.T) {
	t.Helper()
	if _, err := self.writer.repo.ReadHead(context.Background(), &EvsReadArgs{Path: "other.txt"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

// Holds the case to its place: the writer's pin at or past version (below the walk), or below it (in the walk).
func (self *evsTestDropTarget) placed(t *testing.T, what string, version uint64, belowWalk bool) {
	t.Helper()
	pin, pinned, err := self.writer.test.client.pins.Pin(self.writer.world.repoId, self.writer.world.refId)
	if err != nil {
		t.Fatal(err)
	}
	if past := pinned && version <= pin.Version; past != belowWalk {
		t.Fatalf("%s: the pin is not where the case needs it for version %d: %+v", what, version, pin)
	}
}

// Counts each read that asks evs for the record of pushId at version, from now on.
func (self *evsTestDropTarget) countRecordReads(pushId Id, version uint64) func() int {
	world := self.writer.world
	// the count, which the world's reads raise with no lock of its held
	stateLock := &sync.Mutex{}
	count := 0
	world.stateLock.Lock()
	world.beforeRead = func(read *protocol.EvsReadRequest) {
		for _, push := range read.GetPushes() {
			if bytes.Equal(push.GetPushId(), pushId.Bytes()) && push.GetVersion() == version {
				stateLock.Lock()
				count += 1
				stateLock.Unlock()
			}
		}
	}
	world.stateLock.Unlock()
	return func() int {
		stateLock.Lock()
		defer stateLock.Unlock()
		return count
	}
}

// The push id of the statement the world committed at version.
func (self *evsTestDropTarget) pushIdAt(t *testing.T, version uint64) Id {
	t.Helper()
	world := self.writer.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	pushId, err := IdFromBytes(world.commits[version-1].parsed.Push.GetPushId())
	if err != nil {
		t.Fatal(err)
	}
	return pushId
}

// Drops names a drop's paths from the body of its own statement, where the walk of its head read holds the statement
// and where it lies below the pin, and names no path the body does not cover. The signer keeps no body of its own
// drop, so before the fix it listed its drop with no names. A table entry the statement at its version does not bear
// out, a write's version or the DROP under another drop id, names nothing from it.
func TestEvsDropsNameTheDropsPathsFromItsOwnStatement(t *testing.T) {
	ctx := context.Background()
	target := newEvsTestDropTarget(t)
	writer := target.writer
	known := []string{"other.txt", "notes/plan.md"}
	if held := writer.test.client.dropBodies().list(writer.world.repoId, writer.world.refId); len(held) != 0 {
		t.Fatalf("the signer keeps %d bodies, which a listing could name its drop from", len(held))
	}
	named := func(what string, want []string) {
		t.Helper()
		drops, err := writer.repo.Drops(ctx, &EvsDropsArgs{KnownPaths: known})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(drops) != 1 || !slices.Equal(drops[0].Paths, want) {
			t.Fatalf("%s: %d drops, the first naming %v", what, len(drops), drops[0].Paths)
		}
	}
	target.placed(t, "in the walk", target.pushed.Version, false)
	named("in the walk", []string{"notes/plan.md"})
	target.readPast(t)
	target.placed(t, "below the walk", target.pushed.Version, true)
	named("below the walk", []string{"notes/plan.md"})

	// entries the statement at their version does not bear out
	write := target.pushed.Version - 1
	target.list(target.entry(target.pushed.DropId, target.pushIdAt(t, write), write))
	named("a write's version", nil)
	target.list(target.entry(evsTestId("another drop"), target.pushed.PushId, target.pushed.Version))
	named("the DROP under another drop id", nil)
}

// CancelDrop refuses with ErrEvsDropNotPending, and sends nothing, a drop whose table entry the statement at its
// version does not bear out: a write there, under the DROP's push id or its own; the DROP under another drop id; a
// version past the head; and a cancel listed as a drop. Each case runs where the walk of the cancel's head read holds
// the statement and where it lies below the pin. Before the fix each cancel was sent.
func TestEvsCancelDropRefusesADropItsStatementDoesNotBearOut(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		// the table's entry the cancel names, after any push the case makes first
		entry func(t *testing.T, target *evsTestDropTarget) *protocol.EvsDropStatus
	}{
		{name: "a write under the DROP's push id", entry: func(t *testing.T, target *evsTestDropTarget) *protocol.EvsDropStatus {
			later, err := target.writer.write(t, "later.txt", []byte("later"))
			if err != nil {
				t.Fatal(err)
			}
			return target.entry(target.pushed.DropId, target.pushed.PushId, later.Version)
		}},
		{name: "a write under its own push id", entry: func(t *testing.T, target *evsTestDropTarget) *protocol.EvsDropStatus {
			later, err := target.writer.write(t, "later.txt", []byte("later"))
			if err != nil {
				t.Fatal(err)
			}
			return target.entry(target.pushed.DropId, later.PushId, later.Version)
		}},
		{name: "the DROP under another drop id", entry: func(t *testing.T, target *evsTestDropTarget) *protocol.EvsDropStatus {
			return target.entry(evsTestId("another drop"), target.pushed.PushId, target.pushed.Version)
		}},
		{name: "a version past the head", entry: func(t *testing.T, target *evsTestDropTarget) *protocol.EvsDropStatus {
			return target.entry(target.pushed.DropId, target.pushed.PushId, target.pushed.Version+1)
		}},
		{name: "a cancel listed as a drop", entry: func(t *testing.T, target *evsTestDropTarget) *protocol.EvsDropStatus {
			cancelled, err := target.writer.repo.CancelDrop(ctx, &EvsCancelDropArgs{DropId: target.pushed.DropId})
			if err != nil {
				t.Fatal(err)
			}
			drops := target.capture.drops(t)
			cancelId, err := IdFromBytes(drops[len(drops)-1].Drop.History.GetDropId())
			if err != nil {
				t.Fatal(err)
			}
			return target.entry(cancelId, cancelled.PushId, cancelled.Version)
		}},
	}
	for _, belowWalk := range []bool{false, true} {
		for _, c := range cases {
			what := c.name
			if belowWalk {
				what += ", below the walk"
			}
			target := newEvsTestDropTarget(t)
			entry := c.entry(t, target)
			if belowWalk {
				target.readPast(t)
			}
			if head, _ := target.writer.world.head(); entry.GetVersion() <= head {
				target.placed(t, what, entry.GetVersion(), belowWalk)
			}
			target.list(entry)
			dropId, err := IdFromBytes(entry.GetDropId())
			if err != nil {
				t.Fatal(err)
			}
			sent := len(target.capture.drops(t))
			if _, err := target.writer.repo.CancelDrop(ctx, &EvsCancelDropArgs{DropId: dropId}); !errors.Is(err, ErrEvsDropNotPending) {
				t.Fatalf("%s: %v", what, err)
			}
			if len(target.capture.drops(t)) != sent {
				t.Fatalf("%s: a cancel was sent", what)
			}
		}
	}
}

// CancelDrop refuses with ErrEvsDropNotPending, and sends nothing, a drop whose statement evs's log serves below the
// walk at a version no push on that statement's base stands at: the real DROP, signed and of the table's push, moved
// by evs to the version of its own base. Its record evs would not serve there either, but the refusal is the
// statement's, before any record is read. Before the fix the cancel was sent.
func TestEvsCancelDropRefusesADropStatementServedAtItsBase(t *testing.T) {
	ctx := context.Background()
	target := newEvsTestDropTarget(t)
	statement, err := ParseEvsStatementFormat2(func() []byte {
		world := target.writer.world
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		return world.commits[target.pushed.Version-1].statement
	}())
	if err != nil {
		t.Fatal(err)
	}
	base := statement.Push.GetBaseVersion()
	if base == 0 || target.pushed.Version <= base {
		t.Fatalf("a DROP at version %d on base %d", target.pushed.Version, base)
	}
	target.readPast(t)
	target.placed(t, "below the walk", base, true)
	// evs's log serves the DROP's own statement at its base's version
	honest := target.capture.handler
	target.capture.handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/log") ||
			request.URL.Query().Get("since") != strconv.FormatUint(base, 10) {
			honest.ServeHTTP(writer, request)
			return
		}
		body, _ := proto.Marshal(&protocol.EvsLogReply{Statements: []*protocol.EvsReadStatement{{Version: base, Statement: statement.Bytes}}})
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	})
	target.list(target.entry(target.pushed.DropId, target.pushed.PushId, base))
	recordReads := target.countRecordReads(target.pushed.PushId, base)
	sent := len(target.capture.drops(t))
	if _, err := target.writer.repo.CancelDrop(ctx, &EvsCancelDropArgs{DropId: target.pushed.DropId}); !errors.Is(err, ErrEvsDropNotPending) {
		t.Fatalf("a DROP served at its base: %v", err)
	}
	if len(target.capture.drops(t)) != sent || recordReads() != 0 {
		t.Fatalf("%d cancels sent, %d records read", len(target.capture.drops(t))-sent, recordReads())
	}
}

// CancelDrop sends the cancel of a drop whose statement at its version is the table's DROP naming it, where the walk of
// its head read holds the statement and where it lies below the pin: action 2 naming the drop at that version. Its
// check reads the DROP's own body by that statement's push; before the fix nothing was read and the cancel was sent
// unchecked, so the read is what tells this case from the old code's.
func TestEvsCancelDropSendsTheCancelOfTheDropItsStatementBearsOut(t *testing.T) {
	ctx := context.Background()
	for _, belowWalk := range []bool{false, true} {
		what := "in the walk"
		target := newEvsTestDropTarget(t)
		if belowWalk {
			what = "below the walk"
			target.readPast(t)
		}
		target.placed(t, what, target.pushed.Version, belowWalk)
		recordReads := target.countRecordReads(target.pushed.PushId, target.pushed.Version)
		cancelled, err := target.writer.repo.CancelDrop(ctx, &EvsCancelDropArgs{DropId: target.pushed.DropId})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		drops := target.capture.drops(t)
		cancel := drops[len(drops)-1].Drop.History
		if cancel.GetAction() != 2 || !bytes.Equal(cancel.GetCancelsDropId(), target.pushed.DropId.Bytes()) ||
			cancel.GetCancelsVersion() != target.pushed.Version || cancelled.DropId != target.pushed.DropId ||
			cancelled.DropVersion != target.pushed.Version {
			t.Fatalf("%s: the cancel's body %v, its result %+v", what, cancel, cancelled)
		}
		if recordReads() == 0 {
			t.Fatalf("%s: the cancel read no body of the drop's own push", what)
		}
	}
}
