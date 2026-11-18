//go:build !ios_extension

// Drops on a head reader (EVS2-M10-22; FS-89's reader clauses, FS-95's invalid DROP, DESIGN-DETAILS 10.6's
// evs_drop_verify_test.go rows, against the stand-in evs answering a real committed DROP's states): a dropped version
// reads EVS_DROPPED with no fetch and no alarm, History lists it dropped and the head kept, and history_drop is raised
// done naming the signer; a pending one reads its content and lists drop_pending; a drop state on the newest version,
// a DROP by a non-admin, a body off its hash and one past its bound are refused with a tamper alarm; another path's DROP
// leaves evs's state ignored; a withheld entry version reads dropped and History walks below it; the lineage's names
// (H5), the version's bound (H6) and a held cancel (H7) on their own; and the replaying reader's exactness check, a
// list missing a version and one adding one found with no list byte fetched.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A world whose path's history a real DROP committed, and a format-2 reader of it; the world answers each older
// version of the path in the drop's state, as evs's read route does.
type evsTestDropReadWorld struct {
	writer    *evsTestWriter
	server    *evsTestDropServer
	statement []byte
	body      []byte
	version   uint64
	dropId    Id
	reader    *evsTestClient

	stateLock sync.Mutex
	// what the world serves, settable by a test: the state, and the DROP's statement and body it names
	state          protocol.EvsReadPathState
	serveStatement []byte
	serveBody      []byte
	withhold       bool
	// the held_drops of each read request
	held [][]uint64
}

// The world: "notes/plan.md" written five times and dropped, with now when now is set.
func newEvsTestDropReadWorld(t *testing.T, now bool) *evsTestDropReadWorld {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "notes/plan.md", 3000, 5)
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"notes/plan.md"}})
	if err != nil {
		t.Fatal(err)
	}
	args := &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "notes/plan.md"}
	if now {
		args.Now, args.ConfirmNow = true, EvsDropConfirmNow
	}
	result, err := writer.repo.DropHistory(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	drops := capture.drops(t)
	posted := drops[len(drops)-1]
	world := &evsTestDropReadWorld{
		writer: writer, server: server, statement: posted.Statement.Bytes, body: posted.Drop.Body,
		version: result.Pushes[0].Version, dropId: result.Pushes[0].DropId, state: protocol.EvsReadPathState_EVS_READ_PATH_DROPPED,
	}
	if !now {
		world.state = protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING
	}
	world.serveStatement, world.serveBody = world.statement, world.body
	reader := writer.world.reader(t, evsTestId("drop reader"))
	reader.client.args.Gkm = writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	reader.client.EnableFormat2Reader()
	world.reader = reader
	tokens := writer.world.tokens("notes/plan.md")
	writer.world.stateLock.Lock()
	writer.world.beforeRead = func(read *protocol.EvsReadRequest) {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.held = append(world.held, slices.Clone(read.GetHeldDrops()))
	}
	writer.world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		replyPath, err := ParseEvsChangedTokenPath(reply.GetTokenPath())
		if err != nil || !replyPath.Equal(tokens) || reply.GetVersion() == nil {
			return
		}
		entry := &protocol.EvsEntryVersion{}
		if proto.Unmarshal(reply.GetVersion().GetEntryVersion(), entry) != nil || 6 <= entry.GetVersion() {
			return
		}
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		reply.State, reply.DropId = world.state, world.dropId.Bytes()
		if world.state == protocol.EvsReadPathState_EVS_READ_PATH_DROPPED {
			reply.DropVersion = world.version
			if world.withhold {
				reply.Version.EntryVersion = nil
			}
		} else {
			history := &protocol.EvsDropHistory{}
			proto.Unmarshal(world.body, history)
			reply.NotBeforeMs = history.GetNotBeforeMs()
		}
		reply.DropStatement = world.serveStatement
		held := len(world.held) != 0 && slices.Contains(world.held[len(world.held)-1], world.version)
		if !held {
			reply.DropBody = world.serveBody
		}
	}
	writer.world.stateLock.Unlock()
	return world
}

// Reads version of the path through the reader.
func (self *evsTestDropReadWorld) readVersion(version uint64) ([]byte, error) {
	out := &bytes.Buffer{}
	_, err := self.reader.client.Repo(self.writer.world.repoId).ReadVersion(context.Background(), &EvsReadArgs{Path: "notes/plan.md", Version: version}, out)
	return out.Bytes(), err
}

// The path's history through the reader.
func (self *evsTestDropReadWorld) history(t *testing.T) *EvsHistory {
	t.Helper()
	history, err := self.reader.client.Repo(self.writer.world.repoId).History(context.Background(), &EvsReadArgs{Path: "notes/plan.md"})
	if err != nil {
		t.Fatal(err)
	}
	return history
}

// A dropped version reads EVS_DROPPED, fetching nothing and alarming nothing; History lists the head kept and every
// older version dropped; history_drop is raised done, naming the signer; and a later read names the kept body in
// held_drops and is sent none.
func TestEvsDropReaderDroppedVersionReadsDropped(t *testing.T) {
	world := newEvsTestDropReadWorld(t, true)
	if _, err := world.readVersion(3); !errors.Is(err, ErrEvsDropped) {
		t.Fatalf("a dropped version read: %v", err)
	}
	history := world.history(t)
	if len(history.Versions) != 6 || history.Versions[0].State != "kept" {
		t.Fatalf("%d versions, the head %q", len(history.Versions), history.Versions[0].State)
	}
	for _, version := range history.Versions[1:] {
		if version.State != EvsVersionStateDropped {
			t.Fatalf("version %d reads %q", version.Version, version.State)
		}
	}
	if alarms := world.reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Fatalf("a dropped version alarmed: %v", alarms[0].EvsAlarm)
	}
	raised := world.reader.eventsOf(SidecarEventHistoryDrop)
	if len(raised) != 1 || raised[0].DropState != SidecarDropDone || *raised[0].SidecarId != world.writer.world.signer.sidecarId ||
		*raised[0].DropId != world.dropId {
		t.Fatalf("history_drop raised %v", raised)
	}
	world.stateLock.Lock()
	lastHeld := world.held[len(world.held)-1]
	world.stateLock.Unlock()
	if !slices.Contains(lastHeld, world.version) {
		t.Fatalf("a later read held %v, not the DROP at %d", lastHeld, world.version)
	}
}

// A pending drop's version is readable, listed drop_pending, and raises history_drop pending.
func TestEvsDropReaderPendingVersionReads(t *testing.T) {
	world := newEvsTestDropReadWorld(t, false)
	content, err := world.readVersion(3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, evsTestEdited("notes/plan.md", 3000, 2)) {
		t.Fatalf("a pending version's content differs")
	}
	history := world.history(t)
	if history.Versions[2].State != EvsVersionStateDropPending {
		t.Fatalf("a pending version lists %q", history.Versions[2].State)
	}
	raised := world.reader.eventsOf(SidecarEventHistoryDrop)
	if len(raised) != 1 || raised[0].DropState != SidecarDropPending || raised[0].NotBefore.IsZero() {
		t.Fatalf("history_drop raised %v", raised)
	}
}

// Refused with a tamper alarm, nothing shown as dropped: a drop state on the newest version (H0), a DROP signed by a
// device that was no repo admin (H1), a body off its hash and one past its bound (H2).
func TestEvsDropReaderRefusesABadDrop(t *testing.T) {
	refused := func(t *testing.T, world *evsTestDropReadWorld, read func() error) {
		t.Helper()
		if err := read(); err == nil || errors.Is(err, ErrEvsDropped) {
			t.Fatalf("a bad drop read: %v", err)
		}
		alarmed := false
		for _, alarm := range world.reader.eventsOf(SidecarEventEvsAlarm) {
			alarmed = alarmed || alarm.EvsAlarm == SidecarEvsAlarmTamper
		}
		if !alarmed {
			t.Fatalf("no tamper alarm")
		}
	}
	world := newEvsTestDropReadWorld(t, true)
	world.writer.world.stateLock.Lock()
	mutate := world.writer.world.mutatePath
	world.writer.world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		mutate(reply)
		if reply.GetState() == 0 && reply.GetVersion() != nil {
			// the newest version, in a drop's state
			reply.State, reply.DropId, reply.DropVersion = protocol.EvsReadPathState_EVS_READ_PATH_DROPPED, world.dropId.Bytes(), world.version
			reply.DropStatement, reply.DropBody = world.statement, world.body
		}
	}
	world.writer.world.stateLock.Unlock()
	refused(t, world, func() error {
		_, err := world.reader.client.Repo(world.writer.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "notes/plan.md"}, &bytes.Buffer{})
		return err
	})

	world = newEvsTestDropReadWorld(t, true)
	world.writer.world.config.repo.Admins = nil
	refused(t, world, func() error { _, err := world.readVersion(3); return err })

	world = newEvsTestDropReadWorld(t, true)
	altered := bytes.Clone(world.body)
	altered[len(altered)-1] ^= 1
	world.serveBody = altered
	refused(t, world, func() error { _, err := world.readVersion(3); return err })

	world = newEvsTestDropReadWorld(t, true)
	world.serveBody = make([]byte, DefaultEvsFormatSettings().DropMaxBodyByteCount+1)
	refused(t, world, func() error { _, err := world.readVersion(3); return err })
}

// A DROP whose body covers another path only (H4): evs's state is ignored and the version reads as any version.
func TestEvsDropReaderIgnoresAnotherPathsDrop(t *testing.T) {
	world := newEvsTestDropReadWorld(t, true)
	evsTestDropHistory(t, world.writer, world.server, "b.txt", 500, 2)
	preview, err := world.writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"b.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	capture := world.writer.test.client.args.Transport.(*evsTestTransport).handler.(*evsTestDropCapture)
	if _, err := world.writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "b.txt", Now: true, ConfirmNow: EvsDropConfirmNow}); err != nil {
		t.Fatal(err)
	}
	drops := capture.drops(t)
	other := drops[len(drops)-1]
	otherId, _ := IdFromBytes(other.Drop.History.GetDropId())
	world.stateLock.Lock()
	world.serveStatement, world.serveBody, world.dropId, world.version = other.Statement.Bytes, other.Drop.Body, otherId, 0
	world.stateLock.Unlock()
	content, err := world.readVersion(3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, evsTestEdited("notes/plan.md", 3000, 2)) {
		t.Fatalf("an ignored drop state changed the content read")
	}
}

// A dropped version whose entry version evs withheld reads EVS_DROPPED, and History lists it and walks below it.
func TestEvsDropReaderWithheldEntryVersion(t *testing.T) {
	world := newEvsTestDropReadWorld(t, true)
	world.withhold = true
	if _, err := world.readVersion(3); !errors.Is(err, ErrEvsDropped) {
		t.Fatalf("a withheld version read: %v", err)
	}
	history := world.history(t)
	if len(history.Versions) != 6 || history.Versions[5].Version != 1 || history.Versions[5].State != EvsVersionStateDropped {
		t.Fatalf("history over withheld versions: %d versions", len(history.Versions))
	}
}

// H5, H6 and H7 on their own: a lineage entry another name's, or in an epoch with no key; a version at
// through_version, or a statement based at or past the DROP; a cancel this device holds of the drop at its version.
func TestEvsDropReaderLineageVersionAndCancelRules(t *testing.T) {
	own := EvsTokenPath{EvsToken(evsTestBytes("own", 16))}
	other := EvsTokenPath{EvsToken(evsTestBytes("other", 16))}
	tokenPathIn := func(epoch uint64) (EvsTokenPath, error) {
		if epoch == 3 {
			return nil, errors.New("no key for the epoch")
		}
		return own, nil
	}
	listing := func(entries ...EvsTokenPath) *protocol.EvsDropPath {
		path := &protocol.EvsDropPath{ThroughVersion: 6}
		for i, entry := range entries {
			path.Lineage = append(path.Lineage, &protocol.EvsSourcePath{Epoch: uint64(len(entries) - i), TokenPath: entry.Components()})
		}
		return path
	}
	if !evsDropLineageNamed(listing(own, own), tokenPathIn) || evsDropLineageNamed(listing(other, own), tokenPathIn) ||
		evsDropLineageNamed(listing(own, own, own), tokenPathIn) {
		t.Fatalf("H5's names")
	}
	if !evsDropListsVersion(listing(own), 5, 10, 9) || evsDropListsVersion(listing(own), 6, 10, 9) || evsDropListsVersion(listing(own), 5, 10, 10) ||
		!evsDropListsVersion(listing(own), 5, 0, 99) {
		t.Fatalf("H6's bounds")
	}
	// H7: a cancel held in the body store, naming the drop at its version
	world := newEvsTestDropReadWorld(t, false)
	writer := world.writer
	server := world.server
	server.stateLock.Lock()
	server.drops = []*protocol.EvsDropStatus{{
		DropId: world.dropId.Bytes(), RefId: writer.world.refId.Bytes(), Version: world.version, State: protocol.EvsDropState_EVS_DROP_PENDING,
		NotBeforeMs: writer.test.client.clock.Now().Add(DefaultEvsFormatSettings().DropWindow).UnixMilli(),
	}}
	server.stateLock.Unlock()
	capture := writer.test.client.args.Transport.(*evsTestTransport).handler.(*evsTestDropCapture)
	cancelled, err := writer.repo.CancelDrop(context.Background(), &EvsCancelDropArgs{DropId: world.dropId})
	if err != nil {
		t.Fatal(err)
	}
	drops := capture.drops(t)
	cancel := drops[len(drops)-1]
	cancelId, _ := IdFromBytes(cancel.Drop.History.GetDropId())
	if err := world.reader.client.dropBodies().put(writer.world.repoId, writer.world.refId, cancelId, cancelled.Version, cancel.Statement.Bytes, cancel.Drop.Body); err != nil {
		t.Fatal(err)
	}
	history := world.history(t)
	if history.Versions[2].State != "kept" {
		t.Fatalf("a cancelled drop's version lists %q", history.Versions[2].State)
	}
}

// The replaying reader's exactness check, from its own history: an exact list passes; a list missing a version, and
// one adding one, are invalid.
func TestEvsDropReaderReplayExactness(t *testing.T) {
	tokenPath := EvsTokenPath{EvsToken(evsTestBytes("path", 16))}
	versions := []*EvsDropReplayVersion{}
	for version := uint64(1); version <= 6; version += 1 {
		sum := sha256.Sum256([]byte{byte(version)})
		versions = append(versions, &EvsDropReplayVersion{Epoch: 1, TokenPath: tokenPath, Version: version, EntrySha256: sum[:]})
	}
	// a removal has no entry and is never listed
	versions = append(versions, &EvsDropReplayVersion{Epoch: 1, TokenPath: tokenPath, Version: 7})
	body := func(listed [][]byte) *protocol.EvsDropHistory {
		path := &protocol.EvsDropPath{Lineage: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: tokenPath.Components()}}, ThroughVersion: 6}
		if _, err := EvsBuildDropLists([]*protocol.EvsDropPath{path}, [][][]byte{listed}); err != nil {
			t.Fatal(err)
		}
		return &protocol.EvsDropHistory{Action: 1, Paths: []*protocol.EvsDropPath{path}}
	}
	exact := [][]byte{}
	for _, version := range versions[:5] {
		exact = append(exact, version.EntrySha256)
	}
	if err := EvsCheckDropExact(body(exact), versions); err != nil {
		t.Fatal(err)
	}
	if err := EvsCheckDropExact(body(exact[1:]), versions); !errors.Is(err, ErrEvsDropInvalid) {
		t.Fatalf("a list missing a version: %v", err)
	}
	if err := EvsCheckDropExact(body(append(slices.Clone(exact), versions[5].EntrySha256)), versions); !errors.Is(err, ErrEvsDropInvalid) {
		t.Fatalf("a list adding a version: %v", err)
	}
}

// An executed drop takes what only its listed versions name: the head it keeps, which re-cites a listed version's
// segment, and a copy on another ref keep theirs, a kind-5 segment stays the purge's, and an applier is handed the
// drop, or with none nothing is deleted.
func TestEvsDropExecutedTakesWhatOnlyListedVersionsName(t *testing.T) {
	world := newEvsTestDropReadWorld(t, true)
	statement, err := ParseEvsStatementFormat2(world.statement)
	if err != nil {
		t.Fatal(err)
	}
	refId := world.writer.world.refId
	tokens := world.writer.world.tokens("notes/plan.md")
	segment := func(name string) []byte { return evsTestBytes(name, 32) }
	held := []*EvsDropHeldVersion{}
	for version := uint64(1); version <= 5; version += 1 {
		held = append(held, &EvsDropHeldVersion{
			Path: "notes/plan.md", RefId: refId, Epoch: 1, TokenPath: tokens, Version: version,
			Entry:         &protocol.EvsEntryVersion{Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: segment(string(rune('0' + version)))}}},
			ContentSha256: sha256.Sum256([]byte{byte(version)}),
		})
	}
	// version 5 also names a kind-5 segment, which the purge alone deletes
	held[4].Entry.Chain = append(held[4].Entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: segment("kind 5")})
	// the kept head re-cites version 5's segment, and a copy on another ref names version 3's and its content
	held = append(held,
		&EvsDropHeldVersion{Path: "notes/plan.md", RefId: refId, Epoch: 1, TokenPath: tokens, Version: 6,
			Entry: &protocol.EvsEntryVersion{Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: segment("5")}}}},
		&EvsDropHeldVersion{Path: "copy.md", RefId: evsTestId("another ref"), Epoch: 1, TokenPath: tokens, Version: 2,
			Entry:         &protocol.EvsEntryVersion{Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: segment("3")}}},
			ContentSha256: sha256.Sum256([]byte{3})},
	)
	drop, err := EvsExecutedDropOf(world.writer.world.repoId, refId, statement, world.body, held, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(drop.Versions) != 5 || drop.DropId != world.dropId {
		t.Fatalf("%d listed versions", len(drop.Versions))
	}
	for _, version := range drop.Versions {
		for _, segmentId := range version.SegmentIds {
			if bytes.Equal(segmentId, segment("kind 5")) {
				t.Fatalf("a kind-5 segment among a drop's")
			}
		}
	}
	live := func(kind SidecarDropObjectKind, id []byte) bool {
		answer, err := drop.Live(context.Background(), SidecarDropObject{Kind: kind, Id: id})
		if err != nil {
			t.Fatal(err)
		}
		return answer
	}
	content3 := sha256.Sum256([]byte{3})
	content1 := sha256.Sum256([]byte{1})
	if !live(SidecarDropSegment, segment("5")) || !live(SidecarDropSegment, segment("3")) || live(SidecarDropSegment, segment("1")) ||
		!live(SidecarDropContent, content3[:]) || live(SidecarDropContent, content1[:]) {
		t.Fatalf("what stays live")
	}
	if err := world.reader.client.ApplyExecutedDrop(context.Background(), drop); !errors.Is(err, ErrEvsDropApplierMissing) {
		t.Fatalf("an apply with no applier: %v", err)
	}
	handed := 0
	world.reader.client.SetDropApplier(func(ctx context.Context, applied *SidecarExecutedDrop) error {
		handed += 1
		return nil
	})
	if err := world.reader.client.ApplyExecutedDrop(context.Background(), drop); err != nil || handed != 1 {
		t.Fatalf("the applier handed %d: %v", handed, err)
	}
}
