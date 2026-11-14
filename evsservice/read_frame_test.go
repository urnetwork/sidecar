// The read reply's frames as evs writes them (QD-662; question evs1-m2-40-unfolded-listing-frame): a directory's path
// frame with its folded table, then each delta in a frame of its own; a reply that cannot be finished ending with an
// error frame, logged; and the listing those deltas come from, which takes only a directory's newest life.

package evsservice

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A read reply's frames as evs wrote them, none folded.
func readRawFrames(t *testing.T, body []byte) []*protocol.EvsReadFrame {
	t.Helper()
	frames := []*protocol.EvsReadFrame{}
	for at := 0; at < len(body); {
		if len(body)-at < 4 {
			t.Fatalf("a frame's length cut short at %d", at)
		}
		length := int(binary.BigEndian.Uint32(body[at : at+4]))
		at += 4
		frame := &protocol.EvsReadFrame{}
		if err := proto.Unmarshal(body[at:at+length], frame); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
		at += length
	}
	return frames
}

// A directory's deltas go one a frame after its path frame (QD-662): the path frame carries no delta, each delta frame
// its token path, that one delta and continues; the reader folds them back. With no folded table the path carries no
// table; once folded it carries the table as its entry holds it, and only the deltas after it follow.
func TestReadSendsADirectorysDeltasOneAFrame(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	directory := checkTestPath("d")
	row := func(label string) *protocol.EvsName {
		return &protocol.EvsName{Token: checkTestPath("d", label).Last().Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed " + label)}
	}
	addRow := func(base uint64, version uint64, label string) {
		plan := fixture.plan()
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: directory, BaseEntryVersion: base, EntryVersion: fixture.check.directoryEntry(plan, version, []*protocol.EvsName{row(label)}, nil)})
		fixture.requireCommitted(fixture.push(plan), version)
		fixture.awaitStepEights()
	}
	addRow(0, 1, "x")
	addRow(1, 2, "y")
	request := &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(),
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: directory.Components()}}}},
	}
	rawPath := func() (*protocol.EvsReadPathReply, []*protocol.EvsReadPathReply) {
		recorder := fixture.call(token, http.MethodPost, "/read", request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("read: status %d", recorder.Code)
		}
		var path *protocol.EvsReadPathReply
		deltas := []*protocol.EvsReadPathReply{}
		for _, frame := range readRawFrames(t, recorder.Body.Bytes()) {
			switch {
			case frame.GetPath() != nil && frame.GetPath().GetContinues():
				deltas = append(deltas, frame.GetPath())
			case frame.GetPath() != nil:
				if path != nil || 0 < len(deltas) {
					t.Fatal("a second path frame")
				}
				path = frame.GetPath()
			}
		}
		return path, deltas
	}
	path, deltas := rawPath()
	if len(path.GetDeltas()) != 0 || path.GetNames() != nil || path.GetNamesThrough() != 0 || path.GetVersion().GetCommitVersion() != 2 {
		t.Fatalf("the path frame %v", path)
	}
	if len(deltas) != 2 {
		t.Fatalf("%d delta frames", len(deltas))
	}
	for i, delta := range deltas {
		if len(delta.GetDeltas()) != 1 || delta.GetDeltas()[0].GetCommitVersion() != uint64(i+1) || !bytes.Equal(bytes.Join(delta.GetTokenPath(), nil), directory.Bytes()) ||
			delta.GetVersion() != nil || len(delta.GetProof()) != 0 || delta.GetNames() != nil {
			t.Fatalf("delta frame %d: %v", i, delta)
		}
	}
	reply := fixture.read(token, request)
	if folded := reply.paths[0]; len(folded.GetDeltas()) != 2 || folded.GetDeltas()[1].GetCommitVersion() != 2 {
		t.Fatalf("folded back: %v", folded)
	}
	requireVersionProven(t, reply, reply.paths[0], directory)

	// folded: the table as its entry holds it, and a later delta alone after it
	fixture.foldRef()
	addRow(2, 3, "z")
	path, deltas = rawPath()
	entry := fixture.entryAt(1, "d")
	if path.GetNamesThrough() != 2 || !proto.Equal(path.GetNames(), entry.Entry.GetNames()) || len(path.GetNames().GetNames()) != 2 {
		t.Fatalf("the folded path frame: names through %d, %v", path.GetNamesThrough(), path.GetNames())
	}
	if len(deltas) != 1 || deltas[0].GetDeltas()[0].GetCommitVersion() != 3 {
		t.Fatalf("delta frames after the table: %v", deltas)
	}
}

// A frame past the bound after the 200, or a store read that fails, ends the stream with an error frame in the end
// frame's place, UNAVAILABLE with its retry delay, noted and logged with the request's opaque ids, never a cut stream
// (QD-662); an unencodable frame also counts an alarm. The client answers it as that refusal.
func TestReadStreamEndsAFailedReplyWithAnErrorFrame(t *testing.T) {
	lines := []string{}
	metrics := sidecartest.NewFakeMetrics(sidecartest.DefaultFakeMetricsSettings())
	engine := &EvsEngine{log: &capturingLogger{lines: &lines}, metrics: newEvsMetrics(metrics), settings: DefaultEvsSettings()}
	repoId, refId := testId("frame repo"), testId("frame ref")
	newStream := func() (*readStream, *httptest.ResponseRecorder) {
		recorder := httptest.NewRecorder()
		request := &EvsRequest{engine: engine, Writer: recorder, RepoId: repoId, refIds: []sidecar.Id{refId}}
		return &readStream{request: request}, recorder
	}
	requireErrorFrame := func(label string, recorder *httptest.ResponseRecorder) {
		frames := sidecar.NewEvsReadFrames(bytes.NewReader(recorder.Body.Bytes()))
		if frame, err := frames.Next(); err != nil || frame.GetHead() == nil {
			t.Fatalf("%s: the head: %v", label, err)
		}
		_, err := frames.Next()
		evsError, ok := sidecar.EvsErrorOf(err)
		if !ok || evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE || !evsError.RefusesNothing() || evsError.RetryAfter < time.Second {
			t.Fatalf("%s: %v", label, err)
		}
		if _, err := frames.Next(); err != io.EOF {
			t.Fatalf("%s: past the error frame: %v", label, err)
		}
	}

	stream, recorder := newStream()
	if !stream.frame(&protocol.EvsReadFrame{Head: &protocol.EvsHeadSummary{Version: 3}}) {
		t.Fatal("the head frame")
	}
	tooLarge := &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{Body: make([]byte, sidecar.DefaultEvsFormatSettings().ReadFrameMaxByteCount)}}
	if stream.frame(tooLarge) || stream.frame(&protocol.EvsReadFrame{End: true}) {
		t.Fatal("a frame written past the bound, or after it")
	}
	requireErrorFrame("past the bound", recorder)
	if !slices.Contains(stream.request.notes, "frame_unencodable") || stream.request.code != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
		t.Errorf("notes %v code %s", stream.request.notes, stream.request.code)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "alarm read frame_unencodable") || !strings.Contains(lines[0], sidecar.EvsKeyId(repoId)) ||
		!strings.Contains(lines[0], sidecar.EvsKeyId(refId)) {
		t.Errorf("log %v", lines)
	}
	if alarms := metrics.Value("urnetwork_evs_alarms_total", "read_frame"); alarms != 1 {
		t.Errorf("%v alarms", alarms)
	}

	stream, recorder = newStream()
	stream.frame(&protocol.EvsReadFrame{Head: &protocol.EvsHeadSummary{Version: 3}})
	if stream.object(engine.settings, protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT, make([]byte, 32), 0, 0, &readTestFailingReader{}) {
		t.Fatal("a failed object read answered")
	}
	requireErrorFrame("a failed store read", recorder)
	if !slices.Contains(stream.request.notes, "object_read_failed") || len(lines) != 2 || strings.Contains(lines[1], "alarm") {
		t.Errorf("notes %v log %v", stream.request.notes, lines)
	}
	if alarms := metrics.Value("urnetwork_evs_alarms_total", "read_frame"); alarms != 1 {
		t.Errorf("%v alarms after a store read", alarms)
	}
}

// A reader whose every read fails, as a store's ranged GET cut off mid-body.
type readTestFailingReader struct{}

func (self *readTestFailingReader) Read(buffer []byte) (int, error) {
	return 0, errors.New("the store's body failed")
}

// A directory removed and created again in the window lists only its new life: no table stands, and its deltas are
// the creation and those after it, never one before the removal, so a reader that applies a reply's deltas after its
// table lists no row the removal took (QD-662's listing, read.go's reply).
func TestListingAfterARemovalAndCreationInTheWindowTakesOnlyTheNewLife(t *testing.T) {
	world := newEvsWorld(t)
	directory := worldPath("d")
	world.push(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x")}})
	world.fold(1)
	world.push(&worldChange{path: directory, directory: true, base: 1, version: 2, names: []sidecar.EvsToken{worldToken("q")}})
	world.push(&worldChange{path: directory, base: 2})
	world.push(&worldChange{path: directory, directory: true, version: 4, names: []sidecar.EvsToken{worldToken("z")}})
	world.push(&worldChange{path: directory, directory: true, base: 4, version: 5, names: []sidecar.EvsToken{worldToken("w")}})
	head, _ := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	read, _ := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, directory, head.Head.GetFoldedThrough())
	if read.Entry.GetNames() == nil || read.Entry.GetNamesThrough() != 1 {
		t.Fatalf("the folded table %v", read.Entry)
	}
	listing, err := Listing(world.ctx, read, head.Head, NewRecordPushSource(NewRecordCache(world.settings), nil, world.cluster, world.repoId, world.refId))
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[sidecar.EvsToken]bool{}
	for _, name := range listing.Names {
		tokens[sidecar.EvsToken(name.GetToken())] = true
	}
	if !listing.Exists || listing.TableThrough != 0 || len(tokens) != 2 || !tokens[worldToken("z")] || !tokens[worldToken("w")] {
		t.Fatalf("listing %+v", listing)
	}
	if fmt.Sprint(listing.DeltaVersions) != "[4 5]" {
		t.Fatalf("deltas %v", listing.DeltaVersions)
	}
}
