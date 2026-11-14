// The format-2 push sender end to end on T2 (FS-64's writer clauses, FS-68; EVS2-M10-16): sidecar.EvsClient devices
// in §19.11's format2 gate against an evsservice.EvsEngine over FakeHost's stores, on the path-epoch world
// (evs_epoch_world_test.go).
//
//	off, on    a versioned file turned versionless with its content unchanged uploads nothing; a versionless write
//	           past 16 KiB uploads one kind-5 segment under its push, and one within it stages in the push's body
//	           with no upload; turned on again it starts history, and every step reads back verified
//	retry      a push whose first POST got no answer posts the same bytes again, its staged bytes among them
//	409        a write to a versionless path based on a version another write replaced gets 409 PATH_CONFLICT, which
//	           is ErrEvsVersionlessConflict, and the winner's content stands
//	parts      a push whose staged bytes pass one part goes in parts, each carrying its own staged segments
//	retoken    a versionless write refused 412 PATH_EPOCH across a cut-over is sent again under a new push id, its
//	           kind-5 segment uploaded again under that push
//	removal    a removal of a directory lists the versionless file below it as a removal of its own
//	gate       outside the gate "off" is FORMAT_UNSUPPORTED and nothing is sent
//	command    ur evs versioning's engine on a glob, off then on, and the settings ls -l lists

package sidecartest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The epoch world with its network in the format2 gate.
func newVersionlessWorld(t *testing.T) *epochWorld {
	t.Helper()
	world := newEpochWorld(t)
	network := connect.Id(world.networkId).String()
	gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q]}\n", network, network)
	if err := world.host.Gates.Set(gates); err != nil {
		t.Fatal(err)
	}
	return world
}

// A device that writes and reads format 2.
func (self *epochWorld) format2Device(label string) *epochDevice {
	device := self.device(label, nil)
	device.client.SetFormat2Source(func() bool { return true })
	device.client.EnableFormat2Reader()
	return device
}

// Writes path with a versioning setting.
func (self *epochDevice) writeSetting(path string, content []byte, versioning string) (*sidecar.EvsWriteResult, error) {
	return self.repo.Write(self.world.ctx, &sidecar.EvsWriteArgs{
		Path: path, Content: bytes.NewReader(content), Size: int64(len(content)), Versioning: versioning,
	})
}

// What the devices sent since it was set: segment uploads, and each push's and part's request.
type versionlessSent struct {
	stateLock sync.Mutex
	uploads   []string
	pushes    []*protocol.EvsPushRequest
	pushBytes [][]byte
	parts     []*protocol.EvsPartRequest
}

// Logs every request from now on; then, when given, runs before each.
func (self *epochWorld) logSent(then func(device *epochDevice, request *http.Request) error) *versionlessSent {
	sent := &versionlessSent{}
	self.setIntercept(func(device *epochDevice, request *http.Request) error {
		var body []byte
		if request.Body != nil {
			var err error
			if body, err = io.ReadAll(request.Body); err != nil {
				return err
			}
			request.Body.Close()
			request.Body = io.NopCloser(bytes.NewReader(body))
		}
		func() {
			sent.stateLock.Lock()
			defer sent.stateLock.Unlock()
			switch {
			case request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/segments/"):
				sent.uploads = append(sent.uploads, request.URL.RequestURI())
			case epochIsPush(request):
				push := &protocol.EvsPushRequest{}
				if err := proto.Unmarshal(body, push); err == nil {
					sent.pushes = append(sent.pushes, push)
					sent.pushBytes = append(sent.pushBytes, body)
				}
			case request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/push/") && !strings.HasSuffix(request.URL.Path, "/lease"):
				part := &protocol.EvsPartRequest{}
				if err := proto.Unmarshal(body, part); err == nil {
					sent.parts = append(sent.parts, part)
				}
			}
		}()
		if then != nil {
			return then(device, request)
		}
		return nil
	})
	return sent
}

// How many uploads and pushes it holds, and the last push's staged bytes; then it forgets them.
func (self *versionlessSent) take() (uploads []string, pushes []*protocol.EvsPushRequest) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	uploads, pushes = self.uploads, self.pushes
	self.uploads, self.pushes, self.pushBytes = nil, nil, nil
	return uploads, pushes
}

// The versioning of path's newest version.
func (self *epochDevice) newestVersioning(path string) uint32 {
	self.world.t.Helper()
	history, err := self.repo.History(self.world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) == 0 {
		self.world.t.Fatalf("the history of %s: %v", path, err)
	}
	return history.Versions[0].Versioning
}

// path reads back content on a fresh reader.
func (self *epochWorld) requireReads(when string, path string, content []byte) {
	self.t.Helper()
	reader := self.format2Device("r")
	out := &bytes.Buffer{}
	if _, err := reader.repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, out); err != nil || !bytes.Equal(out.Bytes(), content) {
		self.t.Fatalf("%s: %s reads %d bytes, %v", when, path, out.Len(), err)
	}
}

// Content of size bytes that no other label's content equals.
func versionlessContent(label string, size int) []byte {
	content := bytes.Repeat([]byte(label+"\n"), size/(len(label)+1)+1)
	return content[:size]
}

func TestEvsWriteVersioningOffAndOnEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	path := "build/out.bin"
	large := versionlessContent("large one", 40*1024)

	// a versioned file past the inline bound, its record in a segment
	if _, err := w.writeSetting(path, large, ""); err != nil {
		t.Fatal(err)
	}
	if versioning := w.newestVersioning(path); versioning != 0 {
		t.Fatalf("a new path with no rule: versioning %d", versioning)
	}
	sent := world.logSent(nil)

	// off, its content unchanged: k's records cited as kind 1, nothing uploaded and nothing staged
	if _, err := w.writeSetting(path, large, sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("turning versioning off: %v", err)
	}
	uploads, pushes := sent.take()
	if len(uploads) != 0 || len(pushes) != 1 || len(pushes[0].GetStaged()) != 0 {
		t.Fatalf("off with the content unchanged: %d uploads, %d pushes", len(uploads), len(pushes))
	}
	if versioning := w.newestVersioning(path); versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) {
		t.Fatalf("after off: versioning %d", versioning)
	}
	world.requireReads("after off", path, large)
	sent.take()

	// a versionless write past 16 KiB keeps the setting and uploads one kind-5 segment under its push
	larger := versionlessContent("large two", 48*1024)
	result, err := w.writeSetting(path, larger, "")
	if err != nil {
		t.Fatalf("a versionless write: %v", err)
	}
	uploads, pushes = sent.take()
	if len(uploads) != 1 || !strings.Contains(uploads[0], "push=") || len(pushes) != 1 || len(pushes[0].GetStaged()) != 0 {
		t.Fatalf("a versionless write past 16 KiB: uploads %v, %d pushes", uploads, len(pushes))
	}
	if receipts := pushes[0].GetReceipts(); len(receipts) != 1 || !receipts[0].GetVersionless() {
		t.Fatalf("its receipt: %v", receipts)
	}
	if versioning := w.newestVersioning(path); versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) {
		t.Fatalf("a path keeps its setting: versioning %d", versioning)
	}
	world.requireReads("a kind-5 upload", path, larger)
	sent.take()

	// one within 16 KiB stages in the push's body, with no upload and no receipt
	small := versionlessContent("small", 1024)
	if _, err := w.writeSetting(path, small, ""); err != nil {
		t.Fatalf("a staged write: %v", err)
	}
	uploads, pushes = sent.take()
	if len(uploads) != 0 || len(pushes) != 1 || len(pushes[0].GetStaged()) == 0 || len(pushes[0].GetReceipts()) != 0 {
		t.Fatalf("a staged write: uploads %v, %d pushes", uploads, len(pushes))
	}
	staged, err := sidecar.EvsDecodeStaged(pushes[0].GetStaged())
	if err != nil || len(staged) != 1 {
		t.Fatalf("its staged bytes: %d segments, %v", len(staged), err)
	}
	world.requireReads("a staged write", path, small)
	sent.take()

	// on, its content unchanged: history starts there, the staged content inline again
	if _, err := w.writeSetting(path, small, sidecar.EvsVersioningOn); err != nil {
		t.Fatalf("turning versioning on: %v", err)
	}
	uploads, pushes = sent.take()
	if len(uploads) != 0 || len(pushes) != 1 || len(pushes[0].GetStaged()) != 0 {
		t.Fatalf("on over staged content: uploads %v, %d pushes", uploads, len(pushes))
	}
	if versioning := w.newestVersioning(path); versioning != 0 {
		t.Fatalf("after on: versioning %d", versioning)
	}
	world.requireReads("after on", path, small)
	if result.PathVersion == 0 {
		t.Fatal("a write with no path version")
	}

	// off and a kind-5 upload again, then on with its content unchanged adopts the upload as kind 1
	if _, err := w.writeSetting(path, larger, sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("off with new content: %v", err)
	}
	sent.take()
	if _, err := w.writeSetting(path, larger, sidecar.EvsVersioningOn); err != nil {
		t.Fatalf("on adopting an upload: %v", err)
	}
	uploads, pushes = sent.take()
	if len(uploads) != 0 || len(pushes) != 1 {
		t.Fatalf("on adopting an upload: uploads %v, %d pushes", uploads, len(pushes))
	}
	world.requireReads("after adopting", path, larger)
}

func TestEvsWriteStagedBytesKeptAcrossARetryEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	var dropped sync.Once
	sent := world.logSent(func(device *epochDevice, request *http.Request) error {
		var err error
		if epochIsPush(request) {
			// the first POST gets no answer
			dropped.Do(func() { err = errors.New("the connection dropped") })
		}
		return err
	})
	content := versionlessContent("retried", 2048)
	if _, err := w.writeSetting("notes/a.txt", content, sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	sent.stateLock.Lock()
	pushBytes := sent.pushBytes
	sent.stateLock.Unlock()
	if len(pushBytes) != 2 || !bytes.Equal(pushBytes[0], pushBytes[1]) {
		t.Fatalf("%d POSTs of the push, the same bytes: %t", len(pushBytes), len(pushBytes) == 2 && bytes.Equal(pushBytes[0], pushBytes[1]))
	}
	if _, pushes := sent.take(); len(pushes[0].GetStaged()) == 0 {
		t.Fatal("the push staged nothing")
	}
	world.requireReads("after the retry", "notes/a.txt", content)
}

func TestEvsWriteVersionlessConflictIsSurfacedEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	v := world.format2Device("v")
	path := "cache/state.bin"
	if _, err := w.writeSetting(path, versionlessContent("k", 4096), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	winner := versionlessContent("the winner", 4096)
	var once sync.Once
	var interceptErr error
	pushCount := 0
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if device != w || !epochIsPush(request) {
			return nil
		}
		pushCount += 1
		once.Do(func() {
			// v replaces k after w planned on it and before w's push lands
			if _, err := v.writeSetting(path, winner, ""); err != nil {
				interceptErr = fmt.Errorf("v's write: %w", err)
			}
		})
		return nil
	})
	_, err := w.writeSetting(path, versionlessContent("the loser", 4096), "")
	if interceptErr != nil {
		t.Fatal(interceptErr)
	}
	var conflict *sidecar.EvsPathConflictError
	if !errors.As(err, &conflict) || !sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT) {
		t.Fatalf("a push based on k: %v, want 409 PATH_CONFLICT", err)
	}
	if !errors.Is(err, sidecar.ErrEvsVersionlessConflict) || len(conflict.Paths) != 1 || conflict.Paths[0] != path {
		t.Fatalf("the conflict: versionless %t, paths %v", errors.Is(err, sidecar.ErrEvsVersionlessConflict), conflict.Paths)
	}
	if pushCount != 1 {
		t.Fatalf("w posted %d pushes: a versionless conflict is never rebased", pushCount)
	}
	world.setIntercept(nil)
	world.requireReads("after the conflict", path, winner)
}

func TestEvsWriteStagedBytesPastOnePartGoInPartsEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	sent := world.logSent(nil)
	// 100 files of 12 KiB each stage 16 KiB apiece: 1.6 MiB of staged bytes over a payload of a few KiB
	writes := []*sidecar.EvsPathWrite{}
	contents := map[string][]byte{}
	for i := range 100 {
		path := fmt.Sprintf("tiles/%03d.bin", i)
		contents[path] = versionlessContent(path, 12*1024)
		writes = append(writes, &sidecar.EvsPathWrite{
			Path: path, Content: bytes.NewReader(contents[path]), Options: &sidecar.EvsWriteOptions{Versioning: sidecar.EvsVersioningOff},
		})
	}
	if _, err := w.repo.WritePaths(world.ctx, &sidecar.EvsWritePathsArgs{Writes: writes}); err != nil {
		t.Fatal(err)
	}
	sent.stateLock.Lock()
	parts, uploads := sent.parts, sent.uploads
	sent.stateLock.Unlock()
	if len(parts) < 2 || len(uploads) != 0 {
		t.Fatalf("%d parts and %d uploads", len(parts), len(uploads))
	}
	stagedCount := 0
	for i, part := range parts {
		segments, err := sidecar.EvsDecodeStaged(part.GetStaged())
		if err != nil {
			t.Fatalf("part %d's staged bytes: %v", i+1, err)
		}
		if 1024*1024 < len(part.GetPart())+len(part.GetStaged()) {
			t.Fatalf("part %d: %d bytes with its staged bytes", i+1, len(part.GetPart())+len(part.GetStaged()))
		}
		stagedCount += len(segments)
	}
	if stagedCount != len(writes) {
		t.Fatalf("%d staged segments over the parts, want %d", stagedCount, len(writes))
	}
	world.setIntercept(nil)
	for _, path := range []string{"tiles/000.bin", "tiles/057.bin", "tiles/099.bin"} {
		world.requireReads("after the parts", path, contents[path])
	}
}

func TestEvsWriteVersionlessRetokenUploadsAgainUnderTheNewPushEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	world.advance([]string{"w", "v", "m", "r", "d"}, 0, map[string]time.Time{"d": world.clock.Now().Add(time.Hour)})
	w := world.format2Device("w")
	v := world.device("v", func(settings *sidecar.EvsSettings) {
		settings.MapperBatchedLead = 48 * time.Hour
		settings.MapperSpread = time.Nanosecond
	})
	v.client.SetFormat2Source(func() bool { return true })
	v.client.EnableFormat2Reader()
	path := "media/clip.bin"
	if _, err := w.writeSetting(path, versionlessContent("clip one", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(w)
	world.clock.Advance(2 * time.Hour)

	var once sync.Once
	var interceptErr error
	sent := world.logSent(func(device *epochDevice, request *http.Request) error {
		if device != w || !epochIsPush(request) {
			return nil
		}
		once.Do(func() {
			// the cut-over lands between w's plan and its push
			if err := v.repo.TickMapper(world.ctx, refId); err != nil {
				interceptErr = fmt.Errorf("v's mapper: %w", err)
			}
		})
		return nil
	})
	second := versionlessContent("clip two", 44*1024)
	if _, err := w.writeSetting(path, second, ""); err != nil {
		t.Fatalf("w's write across the cut-over: %v", err)
	}
	if interceptErr != nil {
		t.Fatal(interceptErr)
	}
	if head := world.head(refId); head.GetPathEpoch().GetCurrent() != 2 {
		t.Fatalf("the cut-over: %v", head.GetPathEpoch())
	}
	sent.stateLock.Lock()
	var uploads []string
	pushCount := 0
	for _, upload := range sent.uploads {
		// w's kind-5 uploads; the mapper's map parts are no segments
		uploads = append(uploads, upload)
	}
	for _, push := range sent.pushes {
		statement, err := sidecar.ParseEvsStatementFormat2(push.GetStatement())
		if err == nil && statement.Push.GetFlags() == 0 {
			pushCount += 1
		}
	}
	sent.stateLock.Unlock()
	if pushCount != 2 || len(uploads) != 2 || uploads[0] == uploads[1] {
		t.Fatalf("%d pushes and uploads %v: the retoken's push uploads its kind-5 segment again under its own id", pushCount, uploads)
	}
	world.setIntercept(nil)
	world.requireReads("after the retoken", path, second)
}

func TestEvsWriteRemovalListsVersionlessFilesBelowEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	if _, err := w.writeSetting("out/kept.txt", versionlessContent("kept", 2048), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := w.writeSetting("out/deep/artifact.bin", versionlessContent("artifact", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	if _, err := w.writeSetting("out/deep/log.txt", versionlessContent("log", 1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	sent := world.logSent(nil)
	if _, err := w.repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: "out/deep", Remove: true}); err != nil {
		t.Fatalf("removing the directory: %v", err)
	}
	_, pushes := sent.take()
	if len(pushes) != 1 {
		t.Fatalf("%d pushes", len(pushes))
	}
	statement, err := sidecar.ParseEvsStatementFormat2(pushes[0].GetStatement())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sidecar.EvsCheckPayloadFormat2(statement, pushes[0].GetPayload(), pushes[0].GetStaged())
	if err != nil {
		t.Fatal(err)
	}
	removals := 0
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			removals += 1
		}
	}
	// the directory and the two versionless files below it
	if removals != 3 {
		t.Fatalf("%d removals in the push, want the directory's and each versionless file's", removals)
	}
	world.setIntercept(nil)
	reader := world.format2Device("r")
	if _, _, err := reader.read("out/deep/artifact.bin"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("a removed versionless file reads: %v", err)
	}
	world.requireReads("beside the removal", "out/kept.txt", versionlessContent("kept", 2048))
}

func TestEvsWriteVersioningOffOutsideTheGateIsRefused(t *testing.T) {
	world := newEpochWorld(t)
	w := world.device("w", nil)
	sent := world.logSent(nil)
	_, err := w.writeSetting("a.bin", versionlessContent("a", 1024), sidecar.EvsVersioningOff)
	if !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		t.Fatalf("off outside the gate: %v", err)
	}
	if uploads, pushes := sent.take(); len(uploads) != 0 || len(pushes) != 0 {
		t.Fatalf("off outside the gate sent %d uploads and %d pushes", len(uploads), len(pushes))
	}
	if _, err := w.writeSetting("a.bin", versionlessContent("a", 1024), "sometimes"); !errors.Is(err, sidecar.ErrEvsWriteInvalid) {
		t.Fatalf("a setting that is none: %v", err)
	}
	// "" and "on" write versioning 0, format 1's
	if _, err := w.writeSetting("a.bin", versionlessContent("a", 1024), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := w.writeSetting("a.bin", versionlessContent("b", 1024), sidecar.EvsVersioningOn); err != nil {
		t.Fatal(err)
	}
	if _, pushes := sent.take(); len(pushes) != 2 || len(pushes[0].GetStaged()) != 0 || len(pushes[1].GetStaged()) != 0 {
		t.Fatalf("%d pushes outside the gate", len(pushes))
	}
	world.setIntercept(nil)
	if content, _, err := world.device("r", nil).read("a.bin"); err != nil || !bytes.Equal(content, versionlessContent("b", 1024)) {
		t.Fatalf("a format-1 reader: %v", err)
	}
}

// ur evs versioning's engine on a glob: every file the glob names takes a new version with the setting and its
// content unchanged, in one push; the files beside them keep theirs; ls -l's listing shows each one's setting.
func TestEvsSetVersioningOnAGlobEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	contents := map[string][]byte{
		"build/a.bin":      versionlessContent("a", 40*1024),
		"build/deep/b.bin": versionlessContent("b", 2048),
		"build/notes.txt":  versionlessContent("notes", 2048),
		"src/main.go":      versionlessContent("main", 2048),
	}
	if _, err := w.writePaths(contents); err != nil {
		t.Fatal(err)
	}
	sent := world.logSent(nil)
	result, err := w.repo.SetVersioning(world.ctx, &sidecar.EvsSetVersioningArgs{Patterns: []string{"build/**/*.bin"}, Versioning: sidecar.EvsVersioningOff})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(result.Changed) != "[build/a.bin build/deep/b.bin]" || len(result.Unchanged) != 0 || result.Version == 0 {
		t.Fatalf("the glob's result: %+v", result)
	}
	if _, pushes := sent.take(); len(pushes) != 1 {
		t.Fatalf("%d pushes, want the one", len(pushes))
	}
	settings := func(directory string) map[string]uint32 {
		t.Helper()
		listing, err := w.repo.List(world.ctx, &sidecar.EvsReadArgs{Path: directory, Fresh: true, Settings: true})
		if err != nil {
			t.Fatal(err)
		}
		named := map[string]uint32{}
		for _, entry := range listing.Entries {
			if entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE {
				named[string(entry.Name)] = entry.Versioning
			}
		}
		return named
	}
	if build := settings("build"); build["a.bin"] != 1 || build["notes.txt"] != 0 {
		t.Fatalf("build's settings: %v", build)
	}
	if deep := settings("build/deep"); deep["b.bin"] != 1 {
		t.Fatalf("build/deep's settings: %v", deep)
	}
	if src := settings("src"); src["main.go"] != 0 {
		t.Fatalf("src's settings: %v", src)
	}
	world.setIntercept(nil)
	for path, content := range contents {
		world.requireReads("after the glob", path, content)
	}
	sent = world.logSent(nil)

	// again: every match already has the setting, and nothing is sent; a directory names every file below it
	again, err := w.repo.SetVersioning(world.ctx, &sidecar.EvsSetVersioningArgs{Patterns: []string{"build/**/*.bin"}, Versioning: sidecar.EvsVersioningOff})
	if err != nil || len(again.Changed) != 0 || len(again.Unchanged) != 2 || again.Version != 0 {
		t.Fatalf("the glob again: %+v, %v", again, err)
	}
	if _, pushes := sent.take(); len(pushes) != 0 {
		t.Fatalf("%d pushes for no change", len(pushes))
	}
	on, err := w.repo.SetVersioning(world.ctx, &sidecar.EvsSetVersioningArgs{Patterns: []string{"build"}, Versioning: sidecar.EvsVersioningOn})
	if err != nil || fmt.Sprint(on.Changed) != "[build/a.bin build/deep/b.bin]" || fmt.Sprint(on.Unchanged) != "[build/notes.txt]" {
		t.Fatalf("on over the directory: %+v, %v", on, err)
	}
	if build := settings("build"); build["a.bin"] != 0 {
		t.Fatalf("build's settings after on: %v", build)
	}
	if _, err := w.repo.SetVersioning(world.ctx, &sidecar.EvsSetVersioningArgs{Patterns: []string{"nothing/*"}, Versioning: sidecar.EvsVersioningOn}); !errors.Is(err, sidecar.ErrEvsVersioningNoMatch) {
		t.Fatalf("a glob naming no file: %v", err)
	}
	if _, err := w.repo.SetVersioning(world.ctx, &sidecar.EvsSetVersioningArgs{Patterns: []string{"build"}, Versioning: ""}); !errors.Is(err, sidecar.ErrEvsVersioningSetting) {
		t.Fatalf("no setting: %v", err)
	}
	world.setIntercept(nil)
	for path, content := range contents {
		world.requireReads("after on", path, content)
	}
}
