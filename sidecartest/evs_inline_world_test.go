// QD-735 end to end on T2 (question evs1-m2-01-inline-record-home): sidecar.EvsClient devices against an
// evsservice.EvsEngine over FakeHost's stores, in the epoch world (evs_epoch_world_test.go). A small file's push
// carries its record once, in its entry version's kind-2 locators, with no payload section 3 and no segment, and evs's
// batch record stores it once; a reader reads it back byte for byte. After two more versions and a fold, idx/ holds
// the newest version whole and the two older ones with their inline records elided, and a fresh reader reads every
// version by number byte for byte, evs restoring each elided entry version from its push record before serving it,
// which the reader holds to its statement's entry_sha256.

package sidecartest

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

func TestEvsSmallFileRidesOnceInItsLocatorEndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	w := world.device("w", nil)
	var pushLock sync.Mutex
	pushBodies := [][]byte{}
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if !epochIsPush(request) || request.Body == nil {
			return nil
		}
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		pushLock.Lock()
		defer pushLock.Unlock()
		pushBodies = append(pushBodies, body)
		return nil
	})
	const path = "notes/small.txt"
	contents := [][]byte{
		[]byte("a small file, short enough to ride inline\n"),
		[]byte("a small file, short enough to ride inline, edited once\n"),
		[]byte("other bytes altogether, written over the small file\n"),
	}
	if _, err := w.write(path, contents[0]); err != nil {
		t.Fatal(err)
	}
	pushLock.Lock()
	first := pushBodies
	pushLock.Unlock()
	if len(first) != 1 {
		t.Fatalf("%d pushes for one small file", len(first))
	}
	request := &protocol.EvsPushRequest{}
	if err := proto.Unmarshal(first[0], request); err != nil {
		t.Fatal(err)
	}
	statement, err := sidecar.ParseEvsStatement(request.GetStatement())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sidecar.ParseEvsPayload(request.GetPayload())
	if err != nil {
		t.Fatal(err)
	}
	if payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_INLINE_RECORDS) != nil {
		t.Fatal("the push carries payload section 3")
	}
	checked, err := sidecar.EvsCheckPayload(statement, request.GetPayload())
	if err != nil {
		t.Fatal(err)
	}
	records := [][]byte{}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			t.Fatal(err)
		}
		if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			continue
		}
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				t.Fatalf("the small file's chain names a locator of kind %d", locator.GetKind())
			}
			records = append(records, locator.GetInline())
		}
	}
	if len(records) == 0 {
		t.Fatal("the small file rode in no inline locator")
	}
	dump := world.host.Blobs.Dump()
	for key := range dump {
		if strings.Contains(key, "/seg/") {
			t.Fatalf("a small file uploaded a segment: %s", key)
		}
	}
	for i, record := range records {
		if count := bytes.Count(first[0], record); count != 1 {
			t.Fatalf("record %d is in its push %d times", i, count)
		}
		stored := 0
		for key, object := range dump {
			if strings.HasPrefix(key, "meta-1/pb/") {
				stored += bytes.Count(object, record)
			}
		}
		if stored != 1 {
			t.Fatalf("record %d is in the batches %d times", i, stored)
		}
	}
	r := world.device("r", nil)
	if content, _, err := r.read(path); err != nil || !bytes.Equal(content, contents[0]) {
		t.Fatalf("the small file read back: %q %v", content, err)
	}

	for _, content := range contents[1:] {
		if _, err := w.write(path, content); err != nil {
			t.Fatal(err)
		}
	}
	refId := world.mainRefId(w)
	head, err := world.engine.Heads().ReadCluster(world.ctx, world.cluster, world.repoId, refId)
	if err != nil {
		t.Fatal(err)
	}
	now := world.clock.Now()
	if _, err := world.engine.Folder().FoldAll(world.ctx, world.cluster, world.repoId, refId, head, now, now.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	read, err := evsservice.ReadEntry(world.ctx, world.cluster, world.repoId, refId, 1, w.tokenPath(path, 1), 0)
	if err != nil {
		t.Fatal(err)
	}
	versions := read.Entry.GetVersions()
	if len(versions) != 3 {
		t.Fatalf("the entry holds %d versions", len(versions))
	}
	for i, version := range versions {
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(version.GetEntryVersion(), entry); err != nil {
			t.Fatal(err)
		}
		if version.GetElided() != (0 < i) {
			t.Fatalf("folded version %d elided %v", i, version.GetElided())
		}
		inlineCount := 0
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				t.Fatalf("folded version %d names a locator of kind %d", i, locator.GetKind())
			}
			inlineCount += 1
			if (len(locator.GetInline()) == 0) != (0 < i) {
				t.Fatalf("folded version %d holds %d inline bytes in a locator", i, len(locator.GetInline()))
			}
		}
		if inlineCount == 0 {
			t.Fatalf("folded version %d names no inline record", i)
		}
	}

	fresh := world.device("v", nil)
	for version := uint64(1); version <= 3; version += 1 {
		out := &bytes.Buffer{}
		info, err := fresh.repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: path, Version: version}, out)
		if err != nil || info.Version != version || !bytes.Equal(out.Bytes(), contents[version-1]) {
			t.Fatalf("version %d read back: %q %v", version, out.Bytes(), err)
		}
	}
	history, err := fresh.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: path})
	if err != nil || len(history.Versions) != 3 {
		t.Fatalf("the small file's history: %v %v", history, err)
	}
}
