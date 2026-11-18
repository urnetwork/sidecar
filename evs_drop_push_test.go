//go:build !ios_extension

// The DROP push, its kept head and the cancel (EVS2-M10-21; FS-89's client part, FS-95's client rows, against the
// stand-in evs at format 2): a drop of a path's history written as one DROP push whose body and lists hold §11.6's
// checks, its written boundary the head's content again as one fresh inline checkpoint, not_before_ms a week on or, with
// now, time_ms; a chunked head's chunk set cited as it stands, uploading nothing; a removed boundary pushed with no
// change; a dry run that never ran, a wrong typed path, and now without its word refused before anything is sent; a
// versionless head and a head moved since the dry run refused; a retried statement keeping its drop_id and a rebuilt
// one drawing a new one; the cancel naming the drop and its version, refused within 60 s of the window's end; the index
// hook's rewrites rebuilt once after 409 INDEX_EPOCH and then dropped; and the cut into batches at lineage boundaries.
// That no MCP code reaches DropHistory or CancelDrop is evs_drop_mcp_test.go's, which reads the source tree.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Records every one-part push and seal posted, then hands it on.
type evsTestDropCapture struct {
	handler http.Handler

	stateLock sync.Mutex
	pushes    []*protocol.EvsPushRequest
}

func (self *evsTestDropCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
		body, _ := io.ReadAll(request.Body)
		pushRequest := &protocol.EvsPushRequest{}
		if proto.Unmarshal(body, pushRequest) == nil {
			self.stateLock.Lock()
			self.pushes = append(self.pushes, pushRequest)
			self.stateLock.Unlock()
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	self.handler.ServeHTTP(writer, request)
}

// One DROP push posted: its statement and its payload as checked.
type evsTestPostedDrop struct {
	*EvsCheckedPayload
	Statement *EvsStatement
}

// The DROP pushes posted so far: each statement with flag 256, checked as format 2, and its checked payload.
func (self *evsTestDropCapture) drops(t *testing.T) []*evsTestPostedDrop {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	checked := []*evsTestPostedDrop{}
	for _, pushRequest := range self.pushes {
		statement, err := ParseEvsStatementFormat2(pushRequest.GetStatement())
		if err != nil || statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
			continue
		}
		payload, err := EvsCheckPayloadFormat2(statement, pushRequest.GetPayload(), pushRequest.GetStaged())
		if err != nil {
			t.Fatalf("a DROP whose payload does not check: %v", err)
		}
		checked = append(checked, &evsTestPostedDrop{EvsCheckedPayload: payload, Statement: statement})
	}
	return checked
}

// Reads path back through a fresh verifying reader of format 2, which takes the DROP's statement in its walk.
func evsTestReadFormat2(t *testing.T, writer *evsTestWriter, path string) ([]byte, *EvsFileInfo, error) {
	t.Helper()
	reader := writer.world.reader(t, evsTestId("format-2 reader"))
	reader.client.args.Gkm = writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	reader.client.EnableFormat2Reader()
	out := &bytes.Buffer{}
	info, err := reader.client.Repo(writer.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	return out.Bytes(), info, err
}

// A writer at format 2, a repo admin, whose client reaches the drop routes, its pushes captured.
func newEvsTestDropPusher(t *testing.T) (*evsTestWriter, *evsTestDropServer, *evsTestDropCapture) {
	writer, server := newEvsTestDropWriter(t)
	writer.server.format2 = true
	writer.test.client.SetFormat2Source(func() bool { return true })
	writer.test.client.EnableFormat2Reader()
	writer.world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: writer.world.signer.sidecarId.Bytes()}}
	capture := &evsTestDropCapture{handler: server}
	writer.test.client.args.Transport = &evsTestTransport{handler: capture}
	writer.test.client.http.transport = wrapSidecarApiTransport(writer.test.client.args.Transport)
	return writer, server, capture
}

// Writes path count times, each version a little different, and asks the stand-in to expect its list.
func evsTestDropHistory(t *testing.T, writer *evsTestWriter, server *evsTestDropServer, path string, size int, count int) []byte {
	t.Helper()
	var last []byte
	for i := 0; i < count; i += 1 {
		last = evsTestEdited(path, size, i)
		if _, err := writer.write(t, path, last); err != nil {
			t.Fatal(err)
		}
	}
	server.expectPath(t, path)
	return last
}

// A drop of a five-version path: one DROP push whose body names the lineage and a week's window, whose lists hold its
// five versions, and whose written boundary is the head's content again as one fresh inline checkpoint at version 6.
func TestEvsDropHistoryWritesTheKeptHeadAndTheBody(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	head := evsTestDropHistory(t, writer, server, "notes/plan.md", 3000, 5)
	_, before, err := evsTestReadFormat2(t, writer, "notes/plan.md")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"notes/plan.md"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "notes/plan.md"})
	if err != nil {
		t.Fatal(err)
	}
	drops := capture.drops(t)
	if len(result.Pushes) != 1 || len(drops) != 1 {
		t.Fatalf("%d results, %d DROP pushes", len(result.Pushes), len(drops))
	}
	pushed, checked := result.Pushes[0], drops[0]
	history := checked.Drop.History
	if history.GetAction() != 1 || !bytes.Equal(history.GetDropId(), pushed.DropId.Bytes()) || !bytes.Equal(history.GetPreviewId(), preview.PreviewId) {
		t.Fatalf("the body %v", history)
	}
	week := DefaultEvsFormatSettings().DropWindowMs()
	if history.GetNotBeforeMs() != checked.Statement.Push.GetTimeMs()+week || !pushed.NotBefore.Equal(evsTime(history.GetNotBeforeMs())) {
		t.Fatalf("not_before_ms %d for a statement of %d", history.GetNotBeforeMs(), checked.Statement.Push.GetTimeMs())
	}
	if len(history.GetPaths()) != 1 || history.GetPaths()[0].GetThroughVersion() != 6 || history.GetPaths()[0].GetCount() != 5 {
		t.Fatalf("the body's paths %v", history.GetPaths())
	}
	if len(checked.Changes) != 1 || checked.Changes[0].Change.GetBaseEntryVersion() != 5 {
		t.Fatalf("the DROP's changes %v", checked.Changes)
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(checked.Changes[0].EntryVersion, entry); err != nil {
		t.Fatal(err)
	}
	if entry.GetVersion() != 6 || entry.GetVersioning() != 0 || len(entry.GetChain()) != 1 ||
		entry.GetChain()[0].GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE) {
		t.Fatalf("the kept head's entry: version %d, versioning %d, chain %v", entry.GetVersion(), entry.GetVersioning(), entry.GetChain())
	}
	content, after, err := evsTestReadFormat2(t, writer, "notes/plan.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, head) || after.Version != 6 || after.GitOid != before.GitOid || after.Mode != before.Mode {
		t.Fatalf("the kept head reads version %d, oid %x, mode %o", after.Version, after.GitOid, after.Mode)
	}
	if writer.test.client.dropPreview(writer.repo.repoId, preview.PreviewId) != nil {
		t.Fatalf("a dry run kept after its drop committed")
	}
}

// --now: not_before_ms is the statement's own time_ms.
func TestEvsDropHistoryNowTakesNoWindow(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{
		PreviewId: preview.PreviewId, ConfirmPath: "a.txt", Now: true, ConfirmNow: EvsDropConfirmNow,
	}); err != nil {
		t.Fatal(err)
	}
	drops := capture.drops(t)
	if len(drops) != 1 || drops[0].Drop.History.GetNotBeforeMs() != drops[0].Statement.Push.GetTimeMs() {
		t.Fatalf("a now drop's window")
	}
}

// A drop with no dry run, a typed path that is not the previewed one, now without its word, and the word without now
// are refused before anything is sent.
func TestEvsDropHistoryRefusesWhatThePersonDidNotConfirm(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args *EvsDropHistoryArgs
		want error
	}{
		{args: &EvsDropHistoryArgs{PreviewId: evsTestBytes("never run", 16), ConfirmPath: "a.txt"}, want: ErrEvsDropPreviewMissing},
		{args: &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "b.txt"}, want: ErrEvsDropConfirm},
		{args: &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt", Now: true}, want: ErrEvsDropConfirm},
		{args: &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt", ConfirmNow: EvsDropConfirmNow}, want: ErrEvsDropConfirm},
	}
	for i, c := range cases {
		if _, err := writer.repo.DropHistory(context.Background(), c.args); !errors.Is(err, c.want) {
			t.Fatalf("case %d: %v, want %v", i, err, c.want)
		}
	}
	if drops := capture.drops(t); len(drops) != 0 {
		t.Fatalf("%d DROP pushes sent for refused drops", len(drops))
	}
	// a device that is not a repo admin signs none either
	writer.world.config.repo.Admins = nil
	if _, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"}); !errors.Is(err, ErrEvsDropRefused) {
		t.Fatalf("a non-admin's drop: %v", err)
	}
}

// A head written again since the dry run fails the drop with ErrEvsDropStale and sends no DROP; a versionless head is
// refused.
func TestEvsDropHistoryRefusesAStaleOrVersionlessHead(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write(t, "a.txt", []byte("written after the dry run")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"}); !errors.Is(err, ErrEvsDropStale) {
		t.Fatalf("a drop over a moved head: %v", err)
	}
	if drops := capture.drops(t); len(drops) != 0 {
		t.Fatalf("a stale drop sent")
	}
	versionless := &EvsDropLineage{
		Path: "a.txt", DropPath: &protocol.EvsDropPath{Boundary: EvsDropBoundaryWritten, ThroughVersion: 4},
		Versions: []*EvsHistoryVersion{{Version: 3, Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)}},
	}
	if _, _, err := writer.repo.dropKeptWrites(context.Background(), nil, []*EvsDropLineage{versionless}); !errors.Is(err, ErrEvsDropVersionless) {
		t.Fatalf("a versionless head: %v", err)
	}
}

// A retried statement keeps its bytes and drop_id; a rebuild under a new push id draws a new drop_id.
func TestEvsDropHistoryRetryKeepsTheDropIdAndARebuildDrawsANewOne(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	writer.server.stateLock.Lock()
	writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE}}}
	writer.server.dropAnswers = 1
	writer.server.stateLock.Unlock()
	result, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	capture.stateLock.Lock()
	statements := [][]byte{}
	for _, pushRequest := range capture.pushes {
		statement, err := ParseEvsStatementFormat2(pushRequest.GetStatement())
		if err == nil && statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0 {
			statements = append(statements, pushRequest.GetStatement())
		}
	}
	capture.stateLock.Unlock()
	// the refused statement, the rebuilt one whose answer was lost, and its retry
	if len(statements) != 3 || bytes.Equal(statements[0], statements[1]) || !bytes.Equal(statements[1], statements[2]) {
		t.Fatalf("%d DROP statements posted", len(statements))
	}
	drops := capture.drops(t)
	if bytes.Equal(drops[0].Drop.History.GetDropId(), drops[1].Drop.History.GetDropId()) ||
		!bytes.Equal(drops[2].Drop.History.GetDropId(), result.Pushes[0].DropId.Bytes()) {
		t.Fatalf("a rebuild kept its drop_id, or the result names another")
	}
}

// A removed boundary alone is a DROP of no change; its cancel names the drop and its version, and a cancel within 60 s
// of the window's end is refused here.
func TestEvsDropHistoryRemovedBoundaryAndItsCancel(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "old.txt", 500, 3)
	if _, err := writer.write(t, "old.txt", nil); err != nil {
		t.Fatal(err)
	}
	server.expectPath(t, "old.txt")
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"old.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "old.txt"})
	if err != nil {
		t.Fatal(err)
	}
	drops := capture.drops(t)
	if len(drops) != 1 || len(drops[0].Changes) != 0 || drops[0].Drop.History.GetPaths()[0].GetBoundary() != EvsDropBoundaryRemoved {
		t.Fatalf("a removed boundary's DROP")
	}
	pushed := result.Pushes[0]
	server.stateLock.Lock()
	server.drops = []*protocol.EvsDropStatus{{
		DropId: pushed.DropId.Bytes(), RefId: writer.world.refId.Bytes(), PushId: pushed.PushId.Bytes(), Version: pushed.Version,
		NotBeforeMs: pushed.NotBefore.UnixMilli(), State: protocol.EvsDropState_EVS_DROP_PENDING,
	}}
	server.stateLock.Unlock()
	cancelled, err := writer.repo.CancelDrop(context.Background(), &EvsCancelDropArgs{DropId: pushed.DropId})
	if err != nil {
		t.Fatal(err)
	}
	drops = capture.drops(t)
	cancel := drops[len(drops)-1].Drop.History
	if cancel.GetAction() != 2 || !bytes.Equal(cancel.GetCancelsDropId(), pushed.DropId.Bytes()) || cancel.GetCancelsVersion() != pushed.Version ||
		cancel.GetNotBeforeMs() != 0 || cancelled.DropVersion != pushed.Version || len(drops[len(drops)-1].Changes) != 0 {
		t.Fatalf("the cancel's body %v", cancel)
	}
	// within the margin of the window's end: refused here, nothing sent
	server.stateLock.Lock()
	server.drops[0].NotBeforeMs = writer.test.client.clock.Now().Add(30 * time.Second).UnixMilli()
	server.stateLock.Unlock()
	sent := len(capture.drops(t))
	if _, err := writer.repo.CancelDrop(context.Background(), &EvsCancelDropArgs{DropId: pushed.DropId}); !errors.Is(err, ErrEvsDropState) {
		t.Fatalf("a late cancel: %v", err)
	}
	if len(capture.drops(t)) != sent {
		t.Fatalf("a late cancel sent")
	}
}

// The index hook's rewrites ride the DROP; a 409 INDEX_EPOCH rebuilds once with the hook asked again, and a second
// sends the DROP without them.
func TestEvsDropHistoryIndexRewritesRebuildOnceThenGoWithout(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	writer.server.know(".ur-index/x")
	calls := []bool{}
	writer.test.client.SetDropIndexHook(func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
		calls = append(calls, args.Rebuild)
		return &EvsDropIndexRewrites{Writes: []*EvsPathWrite{{
			Path: ".ur-index/x", Content: bytes.NewReader([]byte("rewritten")), Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
		}}}, nil
	})
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	epoch := &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH}}
	writer.server.stateLock.Lock()
	writer.server.pushRefusals = []*evsTestRefusal{epoch, {status: epoch.status, reply: proto.Clone(epoch.reply).(*protocol.EvsRefusalReply)}}
	writer.server.stateLock.Unlock()
	result, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] || !calls[1] || result.Pushes[0].IndexRewritten {
		t.Fatalf("hook calls %v, rewritten %v", calls, result.Pushes[0].IndexRewritten)
	}
	drops := capture.drops(t)
	if len(drops) != 3 || len(drops[0].Changes) < 2 || len(drops[1].Changes) != len(drops[0].Changes) || len(drops[2].Changes) != 1 {
		t.Fatalf("%d DROP pushes", len(drops))
	}
}

// A chunked head's chunk set is cited as it stands: the kept head names the head's own chunk locators and uploads
// nothing.
func TestEvsDropHistoryCitesAChunkedHead(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	size := 9*1024*1024 + 100
	evsTestDropHistory(t, writer, server, "big.bin", size, 2)
	writer.server.stateLock.Lock()
	uploads := len(writer.server.uploads)
	writer.server.stateLock.Unlock()
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"big.bin"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "big.bin"}); err != nil {
		t.Fatal(err)
	}
	writer.server.stateLock.Lock()
	uploaded := len(writer.server.uploads) - uploads
	writer.server.stateLock.Unlock()
	drops := capture.drops(t)
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(drops[0].Changes[0].EntryVersion, entry); err != nil {
		t.Fatal(err)
	}
	if uploaded != 0 || len(entry.GetChain()) != 3 {
		t.Fatalf("%d uploads, a chain of %d", uploaded, len(entry.GetChain()))
	}
	for _, locator := range entry.GetChain() {
		if locator.GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT) {
			t.Fatalf("a kept chunk of kind %d", locator.GetKind())
		}
	}
}

// Lineages are cut into batches at lineage boundaries within one DROP's bounds: the path count, the listed count and
// the body's bytes.
func TestEvsDropBatchesCutAtTheBounds(t *testing.T) {
	lineage := func(name string, count uint32) *EvsDropLineage {
		sum := sha256.Sum256([]byte(name))
		return &EvsDropLineage{Path: name, DropPath: &protocol.EvsDropPath{
			Lineage:        []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: [][]byte{sum[:16]}}},
			ThroughVersion: uint64(count) + 1, Boundary: EvsDropBoundaryWritten, Count: count, ListedSha256: sum[:],
		}}
	}
	format := DefaultEvsFormatSettings()
	format.DropMaxPathCount = 2
	batches := evsDropBatches(format, []*EvsDropLineage{lineage("a", 1), lineage("b", 1), lineage("c", 1)})
	if len(batches) != 2 || len(batches[0]) != 2 || len(batches[1]) != 1 {
		t.Fatalf("by path count: %d batches", len(batches))
	}
	format = DefaultEvsFormatSettings()
	format.DropMaxListedCount = 10
	batches = evsDropBatches(format, []*EvsDropLineage{lineage("a", 6), lineage("b", 4), lineage("c", 1)})
	if len(batches) != 2 || len(batches[0]) != 2 || batches[1][0].Path != "c" {
		t.Fatalf("by listed count: %d batches", len(batches))
	}
	format = DefaultEvsFormatSettings()
	one := proto.Size(lineage("a", 1).DropPath)
	format.DropMaxBodyByteCount = 64 + 2*one
	batches = evsDropBatches(format, []*EvsDropLineage{lineage("a", 1), lineage("b", 1), lineage("c", 1)})
	if len(batches) < 2 {
		t.Fatalf("by body size: %d batches", len(batches))
	}
}
