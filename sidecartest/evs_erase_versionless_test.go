// Erasure over versionless paths end to end on T2 (§11.12's versionless row, §22.5's "erasure leaves no prior
// version"; FS-69's ERASE clause; EVS2-M10-12): sidecar.EvsClient devices in the format2 gate against an
// evsservice.EvsEngine and its purge over FakeHost's stores, on the path-epoch world (evs_epoch_world_test.go).
//
//	erase     a slot-keyed repo's versionless path keeps one key across its overwrites; an ERASE of the keys
//	          SlotKeysOf names destroys it at once and no version of the path opens
//	closure   a CLOSURE rewrites a slot-keyed versionless file in place, staged, under a fresh key in a new slot;
//	          the ERASE of the old slot's key leaves the rewrite reading, and a minute after the CLOSURE the purge
//	          deletes the old slot
//	general   in a general repo the key rides the segment: a CLOSURE's rewrite replaces it, the old ciphertext
//	          stands for the readers' minute and then the purge takes it, and no prior version opens
//	remove    after three overwrites under one key a REMOVE generation's next write draws a fresh key in a new
//	          slot, and the purge deletes the old slot and ciphertext
//	whole     SlotKeysOf of a path removed and created again does not reach its first life, and gives no list
//	rekey     ur evs rekey's pass after a REMOVE generation seals a versionless file again under a fresh key and
//	          leaves its setting as it was, a versioned file beside it staying versioned

package sidecartest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The world's engine's purge sink: nothing until startPurger gives it a purge, then that purge's.
type epochPurgeSink struct {
	stateLock sync.Mutex
	purger    *evsservice.Purger
}

func (self *epochPurgeSink) Certain(commit *evsservice.PurgeCommit) {
	self.stateLock.Lock()
	purger := self.purger
	self.stateLock.Unlock()
	if purger != nil {
		purger.Certain(commit)
	}
}

func (self *epochPurgeSink) set(purger *evsservice.Purger) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.purger = purger
}

// Turns the gate's purge mode on and starts the engine's purge, which takes every commit from now on. Its DELETEs
// are not paced, since the world's clock moves only when a test moves it.
func (self *epochWorld) startPurger() *evsservice.Purger {
	self.t.Helper()
	network := connect.Id(self.networkId).String()
	gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q], purge: on}\n", network, network)
	if err := self.host.Gates.Set(gates); err != nil {
		self.t.Fatal(err)
	}
	settings := evsservice.DefaultPurgerSettings()
	settings.DeleteRate = 2 * int(time.Second)
	purger, err := evsservice.NewPurger(self.ctx, self.host.ServiceHost(), &evsservice.PurgerDeps{
		Format2:  evsservice.NewFormat2Gate(self.host.ServiceHost()),
		Newest:   self.engine.PurgeNewest(),
		Settings: settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(purger.Close)
	self.purge.set(purger)
	return purger
}

// The readers' minute passes and the purge deletes what is due, then ends: what it did.
func (self *epochWorld) purgeDue(purger *evsservice.Purger) evsservice.PurgeStats {
	self.t.Helper()
	self.purge.set(nil)
	self.clock.Advance(61 * time.Second)
	purger.Drain()
	return purger.Stats()
}

// The repo's segment object keys.
func (self *epochWorld) segmentKeys() []string {
	keys := []string{}
	prefix := strings.TrimSuffix(evsservice.SegmentKey(self.repoId, [32]byte{}), hex.EncodeToString(make([]byte, 32)))
	for key := range self.host.Blobs.Dump() {
		_, objectKey, _ := strings.Cut(key, "/")
		if strings.HasPrefix(objectKey, prefix) {
			keys = append(keys, objectKey)
		}
	}
	slices.Sort(keys)
	return keys
}

// How many keys the slot's stored object holds, -1 when it is gone.
func (self *epochWorld) slotKeyCount(slotId sidecar.Id) int {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, evsservice.SlotKey(self.repoId, slotId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return -1
	}
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	slot, err := sidecar.EvsDecodeSlotObject(body)
	if err != nil {
		self.t.Fatal(err)
	}
	return len(slot.GetKeys())
}

// No version of path opens on a fresh device: the newest, and each one its history shows.
func (self *epochWorld) requireNoVersionOpens(when string, path string, versionCount int) {
	self.t.Helper()
	fresh := self.format2Device("r")
	out := &bytes.Buffer{}
	if _, err := fresh.repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, out); err == nil {
		self.t.Fatalf("%s: %s opened, %d bytes", when, path, out.Len())
	}
	history, err := fresh.repo.History(self.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != versionCount {
		self.t.Fatalf("%s: the history of %s: %v %v", when, path, history, err)
	}
	for _, version := range history.Versions {
		out := &bytes.Buffer{}
		if _, err := fresh.repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: path, Version: version.Version}, out); err == nil {
			self.t.Fatalf("%s: version %d of %s opened", when, version.Version, path)
		}
	}
}

// No version of path but its newest opens on a fresh device.
func (self *epochWorld) requireNoPriorVersionOpens(when string, path string, versionCount int) {
	self.t.Helper()
	fresh := self.format2Device("r")
	history, err := fresh.repo.History(self.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != versionCount {
		self.t.Fatalf("%s: the history of %s: %v %v", when, path, history, err)
	}
	for _, version := range history.Versions[1:] {
		out := &bytes.Buffer{}
		if _, err := fresh.repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: path, Version: version.Version}, out); err == nil {
			self.t.Fatalf("%s: version %d of %s opened", when, version.Version, path)
		}
	}
}

func TestEvsEraseOfASlotKeyedVersionlessPathLeavesNoVersionEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.format2Device("w")
	path := "notes/draft.bin"
	if _, err := w.writeSetting(path, versionlessContent("draft 0", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	slots := world.slotKeys()
	if len(slots) != 1 {
		t.Fatalf("%d slots after the first write", len(slots))
	}
	// three overwrites, one staged: the path's one key, no new slot
	last := []byte{}
	for round, size := range []int{44 * 1024, 2 * 1024, 48 * 1024} {
		last = versionlessContent(fmt.Sprintf("draft %d", round+1), size)
		if _, err := w.writeSetting(path, last, ""); err != nil {
			t.Fatalf("overwrite %d: %v", round+1, err)
		}
		if after := world.slotKeys(); !slices.Equal(after, slots) {
			t.Fatalf("overwrite %d changed the slots: %v, were %v", round+1, after, slots)
		}
	}
	world.requireReads("before the ERASE", path, last)
	slotId := epochNewSlots(nil, slots)[0]
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if err != nil || len(keys) != 1 || keys[0].SlotId != slotId || keys[0].KeyIndex != 0 {
		t.Fatalf("the path's slot keys: %v %v", keys, err)
	}
	segments := world.segmentKeys()
	erasureId := sidecar.NewId()
	erased, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: true, Note: []byte("the draft")})
	if err != nil || erased.Version != 1 {
		t.Fatalf("the ERASE: %v %v", erased, err)
	}
	// at once: the key is gone when the ERASE answers, the ciphertext where it was
	if count := world.slotKeyCount(slotId); count != 0 {
		t.Fatalf("the slot holds %d keys after the ERASE", count)
	}
	if after := world.segmentKeys(); !slices.Equal(after, segments) {
		t.Fatalf("the ERASE changed the segments: %v, were %v", after, segments)
	}
	world.requireNoVersionOpens("after the ERASE", path, 4)
	erasures, err := world.format2Device("v").repo.Erasures(world.ctx)
	if err != nil || len(erasures) != 1 {
		t.Fatalf("the erasures read back: %v %v", erasures, err)
	}
}

func TestEvsClosureRewritesAVersionlessFileInANewSlotEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	purger := world.startPurger()
	w := world.format2Device("w")
	path := "index/shard.bin"
	if _, err := w.writeSetting(path, versionlessContent("shard one", 2*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	if _, err := w.writeSetting(path, versionlessContent("shard two", 3*1024), ""); err != nil {
		t.Fatalf("the overwrite: %v", err)
	}
	before := world.slotKeys()
	if len(before) != 1 {
		t.Fatalf("%d slots before the CLOSURE", len(before))
	}
	oldSlot := epochNewSlots(nil, before)[0]
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if err != nil || len(keys) != 1 || keys[0].SlotId != oldSlot {
		t.Fatalf("the file's slot keys: %v %v", keys, err)
	}

	sent := world.logSent(nil)
	closed := versionlessContent("shard without the entry", 1500)
	erasureId := sidecar.NewId()
	if _, err := w.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: erasureId, Writes: []*sidecar.EvsPathWrite{{Path: path, Content: bytes.NewReader(closed)}}, Erased: keys,
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	uploads, pushes := sent.take()
	world.setIntercept(nil)
	if len(uploads) != 0 || len(pushes) != 1 || len(pushes[0].GetStaged()) == 0 {
		t.Fatalf("the CLOSURE sent %d uploads and %d pushes", len(uploads), len(pushes))
	}
	statement, err := sidecar.ParseEvsStatementFormat2(pushes[0].GetStatement())
	if err != nil || statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) == 0 {
		t.Fatalf("the CLOSURE's statement: %v", err)
	}
	added := epochNewSlots(before, world.slotKeys())
	if len(added) != 1 {
		t.Fatalf("the CLOSURE added %d slots", len(added))
	}
	if versioning := w.newestVersioning(path); versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) {
		t.Fatalf("the rewrite's versioning: %d", versioning)
	}
	world.requireReads("after the CLOSURE", path, closed)

	// the ERASE waits for no purge
	if _, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: true, Note: []byte("the shard's entry")}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	if count := world.slotKeyCount(oldSlot); count != 0 {
		t.Fatalf("the old slot holds %d keys after the ERASE", count)
	}
	if count := world.slotKeyCount(added[0]); count != 1 {
		t.Fatalf("the rewrite's slot holds %d keys after the ERASE", count)
	}
	world.requireReads("after the ERASE", path, closed)
	world.requireNoPriorVersionOpens("after the ERASE", path, 3)

	// a minute after the CLOSURE the purge deletes the old slot
	stats := world.purgeDue(purger)
	if count := world.slotKeyCount(oldSlot); count != -1 {
		t.Fatalf("the old slot stands after the purge, %d keys: %+v", count, stats)
	}
	if count := world.slotKeyCount(added[0]); count != 1 {
		t.Fatalf("the rewrite's slot after the purge: %d keys", count)
	}
	world.requireReads("after the purge", path, closed)
}

func TestEvsClosureOfAVersionlessFileInAGeneralRepoLeavesNoPriorVersionEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	purger := world.startPurger()
	w := world.format2Device("w")
	path := "index/all.bin"
	if _, err := w.writeSetting(path, versionlessContent("all with the entry", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	first := world.segmentKeys()
	if len(first) != 1 || len(world.slotKeys()) != 0 {
		t.Fatalf("%d segments and %d slots after the first write", len(first), len(world.slotKeys()))
	}
	// a general repo's versions name no slot: the key rides the segment, and goes with it
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if err != nil || len(keys) != 0 {
		t.Fatalf("a general repo's slot keys: %v %v", keys, err)
	}
	closed := versionlessContent("all without it", 36*1024)
	if _, err := w.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: sidecar.NewId(), Writes: []*sidecar.EvsPathWrite{{Path: path, Content: bytes.NewReader(closed)}},
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	if segments := world.segmentKeys(); len(segments) != 2 {
		t.Fatalf("%d segments inside the readers' minute", len(segments))
	}
	stats := world.purgeDue(purger)
	segments := world.segmentKeys()
	if len(segments) != 1 || segments[0] == first[0] || stats.DeletedCount != 1 {
		t.Fatalf("the segments after the purge: %v, were %v: %+v", segments, first, stats)
	}
	world.requireReads("after the purge", path, closed)
	world.requireNoPriorVersionOpens("after the purge", path, 2)
}

func TestEvsVersionlessKeyIsDrawnAgainAfterARemoveGenerationEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	purger := world.startPurger()
	w := world.format2Device("w")
	path := "cache/blob.bin"
	if _, err := w.writeSetting(path, versionlessContent("blob 0", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	slots := world.slotKeys()
	if len(slots) != 1 {
		t.Fatalf("%d slots after the first write", len(slots))
	}
	for round := 1; round <= 3; round += 1 {
		if _, err := w.writeSetting(path, versionlessContent(fmt.Sprintf("blob %d", round), 40*1024+round*1024), ""); err != nil {
			t.Fatalf("overwrite %d: %v", round, err)
		}
		if after := world.slotKeys(); !slices.Equal(after, slots) {
			t.Fatalf("overwrite %d changed the slots: %v, were %v", round, after, slots)
		}
	}
	// the overwrites' purges, so the last one below is the REMOVE write's alone
	world.purgeDue(purger)
	if segments := world.segmentKeys(); len(segments) != 1 {
		t.Fatalf("%d segments after the overwrites' purge", len(segments))
	}
	oldSlot := epochNewSlots(nil, slots)[0]
	oldSegments := world.segmentKeys()

	// d leaves: w's next write rotates to the REMOVE generation, newer than the path's key (checkpoint rule (4))
	world.advance([]string{"w", "v", "m", "r"}, 2, nil)
	purger = world.startPurger()
	rekeyed := versionlessContent("blob after the removal", 42*1024)
	if _, err := w.writeSetting(path, rekeyed, ""); err != nil {
		t.Fatalf("the write after the removal: %v", err)
	}
	added := epochNewSlots(slots, world.slotKeys())
	if len(added) != 1 {
		t.Fatalf("the write after the removal added %d slots", len(added))
	}
	stats := world.purgeDue(purger)
	if count := world.slotKeyCount(oldSlot); count != -1 {
		t.Fatalf("the old slot stands after the purge, %d keys: %+v", count, stats)
	}
	if segments := world.segmentKeys(); len(segments) != 1 || segments[0] == oldSegments[0] {
		t.Fatalf("the segments after the purge: %v, were %v: %+v", segments, oldSegments, stats)
	}
	if count := world.slotKeyCount(added[0]); count != 1 {
		t.Fatalf("the new slot holds %d keys", count)
	}
	world.requireReads("after the removal's purge", path, rekeyed)

	// an ERASE of the path names the key of every slot a version of it names, the one from before the REMOVE
	// generation included; that slot the purge deleted holds no key, so its rewrite is done, and the new slot's goes
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if err != nil || len(keys) != 2 || keys[0].SlotId != added[0] || keys[1].SlotId != oldSlot {
		t.Fatalf("the path's slot keys across the re-key: %v %v", keys, err)
	}
	if _, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true, Note: []byte("the blob")}); err != nil {
		t.Fatalf("the ERASE across the re-key: %v", err)
	}
	if count := world.slotKeyCount(added[0]); count != 0 {
		t.Fatalf("the new slot holds %d keys after the ERASE", count)
	}
	if count := world.slotKeyCount(oldSlot); count != -1 {
		t.Fatalf("the ERASE put the purged slot back, %d keys", count)
	}
	world.requireNoVersionOpens("after the ERASE", path, 5)
}

func TestEvsRekeyKeepsAVersionlessPathsSettingEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	clip := versionlessContent("clip", 40*1024)
	note := versionlessContent("note", 1024)
	doc := versionlessContent("doc", 2048)
	if _, err := w.writeSetting("media/clip.bin", clip, sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	if _, err := w.writeSetting("media/note.txt", note, sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	if _, err := w.writeSetting("docs/kept.md", doc, ""); err != nil {
		t.Fatal(err)
	}
	before := world.segmentKeys()
	if len(before) != 1 {
		t.Fatalf("%d segments before the rekey", len(before))
	}
	// d leaves: the job's generation is the REMOVE one, newer than every file's key
	world.advance([]string{"w", "v", "m", "r"}, 2, nil)
	rekey, err := sidecar.NewGkmRekey(&sidecar.GkmRekeyArgs{Evs: w.client, Store: NewFakeStore().Root()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rekey.Close)
	progress, err := rekey.Run(world.ctx, &sidecar.GkmRekeyRequest{RepoId: world.repoId, Paths: []string{"docs", "media"}})
	if err != nil || progress.State != sidecar.GkmRekeyStateDone || progress.RewrittenCount != 3 {
		t.Fatalf("the rekey: %+v %v", progress, err)
	}
	for path, want := range map[string]uint32{
		"media/clip.bin": uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
		"media/note.txt": uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
		"docs/kept.md":   uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT),
	} {
		if versioning := w.newestVersioning(path); versioning != want {
			t.Fatalf("%s after the rekey: versioning %d, want %d", path, versioning, want)
		}
	}
	// the clip's every chunk sealed again: a new kind-5 segment, its key in its header
	added := 0
	for _, key := range world.segmentKeys() {
		if !slices.Contains(before, key) {
			added += 1
		}
	}
	if added != 1 {
		t.Fatalf("the rekey uploaded %d segments", added)
	}
	world.requireReads("after the rekey", "media/clip.bin", clip)
	world.requireReads("after the rekey", "media/note.txt", note)
	world.requireReads("after the rekey", "docs/kept.md", doc)
	// a second run finds every file current
	again, err := rekey.Run(world.ctx, &sidecar.GkmRekeyRequest{RepoId: world.repoId, Paths: []string{"docs", "media"}})
	if err != nil || again.State != sidecar.GkmRekeyStateDone {
		t.Fatalf("the second rekey: %+v %v", again, err)
	}
	if after := world.segmentKeys(); len(after) != len(before)+added {
		t.Fatalf("the second rekey uploaded: %d segments", len(after))
	}
}

func TestEvsSlotKeysOfAPathCreatedAgainFailsClosedEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.format2Device("w")
	path := "notes/again.bin"
	if _, err := w.writeSetting(path, versionlessContent("first life", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	if keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path}); err != nil || len(keys) != 1 {
		t.Fatalf("the first life's slot keys: %v %v", keys, err)
	}
	if _, err := w.repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: path, Remove: true}); err != nil {
		t.Fatalf("the removal: %v", err)
	}
	if _, err := w.writeSetting(path, versionlessContent("second life", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the second creation: %v", err)
	}
	// the walk ends at the second creation: the first life's slot is not reached, so no list is given
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if !errors.Is(err, sidecar.ErrEvsSlotKeysIncomplete) || keys != nil {
		t.Fatalf("a path created again: %v %v", keys, err)
	}
}
