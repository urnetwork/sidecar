//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-35's tests (DESIGN-DETAILS 8.6's evs-to-git row): a push on device A, the publisher, applied on device B by
// its sync engine with equal oids and a clean git fsck; a branch and an annotated tag replayed with their source first;
// each broken line of the check refused with its alarm and the ref left; a committed FORCE and a git-mode PATH_EPOCH
// raising no alarm; a source the ref waits on; a stopped ref resuming at a DELETE, its re-creating push held to the
// tainted token paths; the tips log and tip index; and the replayed name index of a branch and of an overlay. And the
// fix track evs1-m2-34-tainted-recreate's (8.5; 8.2.4's chain row): a design device's re-creation writing and removing
// each tainted path, applied by a stopped device and by one mounted afterwards in one replay. And QD-826's (track
// tainted-removed-clear): a path the stopped versions last removed, which a re-creation whose tree lacks it leaves
// alone in one push that every reader takes, whether it stood before the stop or the stop planted it; a tainted path
// left standing, or last removed and held by the new tree, that a re-creation leaves alone, refused; a record from a
// writer that reads every taint as standing refused before any evs write; and a taint record stored before the field.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A second device of the publisher's world: a reader with a mount registry on its own state, the world's repo mounted,
// whose sync engine replays what the publisher committed.
type evsTestDevice struct {
	t         *testing.T
	publisher *evsTestPublisher
	test      *evsTestClient
	mounts    *EvsMounts
	mount     *EvsLocalRepo
	engine    *EvsGitSyncEngine
}

func newEvsTestDevice(t *testing.T, publisher *evsTestPublisher, name string) *evsTestDevice {
	t.Helper()
	test := publisher.writer.world.reader(t, evsTestId(name))
	mounts, err := NewEvsMounts(test.client, t.TempDir(), evsTestGitRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	mount, err := mounts.Add(context.Background(), publisher.writer.world.repoId, &EvsMountArgs{AgentLabel: name})
	if err != nil {
		t.Fatal(err)
	}
	return &evsTestDevice{t: t, publisher: publisher, test: test, mounts: mounts, mount: mount, engine: mount.Sync()}
}

// Replays the ref of name to its head.
func (self *evsTestDevice) replay(name string) {
	self.t.Helper()
	if err := self.engine.Replay(context.Background(), self.publisher.ref(name).refId); err != nil {
		self.t.Fatal(err)
	}
}

// The record of the ref of name.
func (self *evsTestDevice) ref(name string) *EvsGitRef {
	self.t.Helper()
	ref, err := self.engine.GitRef(context.Background(), self.publisher.ref(name).refId)
	if err != nil {
		self.t.Fatal(err)
	}
	return ref
}

// The local ref gitRef in the device's bare repository, nil for none.
func (self *evsTestDevice) local(gitRef string) *EvsGitOid {
	self.t.Helper()
	oid, err := self.mount.localRef(context.Background(), gitRef)
	if err != nil {
		self.t.Fatal(err)
	}
	return oid
}

// The alarms the device raised.
func (self *evsTestDevice) alarms() []SidecarEvent {
	return self.test.eventsOf(SidecarEventEvsAlarm)
}

// The taint the record of the ref of name holds at path in epoch 1, nil for none.
func (self *evsTestDevice) taintAt(name string, path string) *EvsTaintedPath {
	self.t.Helper()
	key := self.publisher.writer.world.tokensAt(path, 1).KeyString()
	for _, tainted := range self.ref(name).Tainted {
		if tainted.Epoch == 1 && tainted.Key == key {
			return &tainted
		}
	}
	return nil
}

// 8.1's A on a second device: two commits in one push whose middle blob only a history blob carries, then a push that
// adds a directory and removes a file. Device B's sync engine applies both: its main and refs/ur/evs/ at the tip, every
// oid equal, git fsck clean, the middle blob readable, the tips log and the tip index holding each version's tip.
func TestEvsLocalSyncAppliesAPushOnASecondDevice(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"README": "hello\n", "plan.md": "plan one\n"})
	c2 := publisher.commit(map[string]string{"README": "hello\n", "plan.md": "plan two\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	c3 := publisher.commit(map[string]string{"plan.md": "plan two\n", "docs/a.md": "a\n", "docs/deep/b.md": "b\n"}, c2)
	if _, err := publisher.publish("main", &c3); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c3 {
		t.Fatalf("main is %v", local)
	}
	mainId := publisher.ref("main").refId
	if evsTip := device.local(evsLocalEvsRefPrefix + evsUrlId(mainId)); evsTip == nil || *evsTip != c3 {
		t.Fatalf("refs/ur/evs/ is %v", evsTip)
	}
	ref := device.ref("main")
	if ref.Version != 2 || !evsOidEqual(ref.Tip, &c3) || !evsOidEqual(ref.AppliedTip, &c3) || !bytes.Equal(ref.Name, EvsMainRefName) ||
		ref.StuckAt != 0 {
		t.Fatalf("the record %+v", ref)
	}
	if fsck := evsTestFsck(t, device.mount.BareDir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
	if content := evsTestGit(t, device.mount.BareDir, "cat-file", "-p", hex.EncodeToString(c1[:])+":plan.md"); content != "plan one\n" {
		t.Fatalf("the history blob %q", content)
	}
	for version, want := range map[uint64]EvsGitOid{1: c2, 2: c3} {
		if tip, ok, err := device.engine.TipAt(context.Background(), mainId, version); err != nil || !ok || tip != want {
			t.Fatalf("the tip at %d: %x %v %v", version, tip, ok, err)
		}
	}
	tips, err := device.engine.TipsOf(context.Background(), c3)
	if err != nil || len(tips) != 1 || tips[0].RefId != mainId || tips[0].Version != 2 {
		t.Fatalf("the tip index %+v %v", tips, err)
	}
	if alarms := device.alarms(); len(alarms) != 0 {
		t.Fatalf("alarms %v", alarms)
	}
	// a replay with nothing new changes nothing
	device.replay("main")
	if again := device.ref("main"); again.Version != 2 || !evsOidEqual(again.AppliedTip, &c3) {
		t.Fatalf("a second replay %+v", again)
	}
}

// A branch at a held commit and an annotated tag naming main as their source, then a branch commit: device B replays
// the branch and the tag alone, main first as their source, each at its tip; the tag's object stored.
func TestEvsLocalSyncReplaysSourcesFirst(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.publish("feature", &c1); err != nil {
		t.Fatal(err)
	}
	tagObject := evsTestTag(c2, evsGitCommitKind, "v2")
	tagOid, _ := publisher.mount.history.store.WriteGitObject(evsGitTagKind, tagObject)
	if _, err := publisher.publish("refs/tags/v2", &tagOid); err != nil {
		t.Fatal(err)
	}
	f2 := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b\n"}, c1)
	if _, err := publisher.publish("feature", &f2); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("feature")
	device.replay("refs/tags/v2")
	if local := device.local("refs/heads/main"); local == nil || *local != c2 {
		t.Fatalf("main, the source, is %v", local)
	}
	if local := device.local("refs/heads/feature"); local == nil || *local != f2 {
		t.Fatalf("feature is %v", local)
	}
	if local := device.local("refs/tags/v2"); local == nil || *local != tagOid {
		t.Fatalf("the tag is %v", local)
	}
	if kind := strings.TrimSpace(evsTestGit(t, device.mount.BareDir, "cat-file", "-t", tagOid.String())); kind != "tag" {
		t.Fatalf("the tag object is a %s", kind)
	}
	if fsck := evsTestFsck(t, device.mount.BareDir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
	if alarms := device.alarms(); len(alarms) != 0 {
		t.Fatalf("alarms %v", alarms)
	}
}

// Each broken line of the check, by a push its writer built against the rule, refused with evs_alarm version_rule on
// device B: the ref stopped at the version before, its local ref left there: a commit of another client carried as
// new; a push missing a path of the tree's change; an UPDATE that does not descend, without FORCE.
func TestEvsLocalSyncRefusesEachLineOfTheCheck(t *testing.T) {
	cases := []struct {
		name  string
		build func(publisher *evsTestPublisher, c1 EvsGitOid) (*EvsGitOid, func(args *EvsLocalPublishArgs))
	}{
		{name: "a forged committer", build: func(publisher *evsTestPublisher, c1 EvsGitOid) (*EvsGitOid, func(args *EvsLocalPublishArgs)) {
			foreign, _ := publisher.mount.history.commit(publisher.tree(map[string]string{"a.txt": "forged\n"}), evsTestId("another client").String()+evsCommitterDomain, c1)
			return &foreign, func(args *EvsLocalPublishArgs) { args.OwnClient = func(clientId Id) bool { return true } }
		}},
		{name: "a missing change", build: func(publisher *evsTestPublisher, c1 EvsGitOid) (*EvsGitOid, func(args *EvsLocalPublishArgs)) {
			c2 := publisher.commit(map[string]string{"a.txt": "a two\n", "b.txt": "b two\n"}, c1)
			evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) {
				update.changes = slices.DeleteFunc(update.changes, func(change *EvsGitPathChange) bool { return change.Path == "b.txt" })
			}
			return &c2, nil
		}},
		{name: "a rewind without FORCE", build: func(publisher *evsTestPublisher, c1 EvsGitOid) (*EvsGitOid, func(args *EvsLocalPublishArgs)) {
			other := publisher.commit(map[string]string{"a.txt": "elsewhere\n", "b.txt": "b\n"})
			evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) {
				update.flags &^= uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
			}
			return &other, nil
		}},
	}
	for _, c := range cases {
		publisher := newEvsTestPublisher(t)
		c1 := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b\n"})
		if _, err := publisher.publish("main", &c1); err != nil {
			t.Fatal(err)
		}
		bad, configure := c.build(publisher, c1)
		configures := []func(args *EvsLocalPublishArgs){}
		if configure != nil {
			configures = append(configures, configure)
		}
		_, err := publisher.publish("main", bad, configures...)
		evsLocalPublishUpdateHook = nil
		if err != nil {
			t.Fatalf("%s: the writer's push: %v", c.name, err)
		}
		device := newEvsTestDevice(t, publisher, "device b")
		device.replay("main")
		ref := device.ref("main")
		if ref.StuckAt != 2 || ref.Version != 2 || !evsOidEqual(ref.Tip, &c1) || len(ref.Tainted) == 0 {
			t.Fatalf("%s: the record %+v", c.name, ref)
		}
		if local := device.local("refs/heads/main"); local == nil || *local != c1 {
			t.Fatalf("%s: main moved to %v", c.name, local)
		}
		alarms := device.alarms()
		if len(alarms) != 1 || alarms[0].EvsAlarm != SidecarEvsAlarmVersionRule {
			t.Fatalf("%s: alarms %v", c.name, alarms)
		}
	}
}

// A committed FORCE by a repo admin and a git-mode PATH_EPOCH between two pushes raise no alarm on device B (FS-1's
// case): the PATH_EPOCH moves no tip, and the rewind applies.
func TestEvsLocalSyncForceAndPathEpochRaiseNoAlarm(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	publisher.writer.world.pushPathEpoch(1)
	rewound, err := publisher.publish("main", &c1)
	if err != nil {
		t.Fatal(err)
	}
	if rewound.Flags != uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) || rewound.Version != 4 {
		t.Fatalf("the rewind %+v", rewound)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main is %v", local)
	}
	if ref := device.ref("main"); ref.Version != 4 || ref.StuckAt != 0 {
		t.Fatalf("the record %+v", ref)
	}
	if tip, ok, _ := device.engine.TipAt(context.Background(), publisher.ref("main").refId, 3); !ok || tip != c2 {
		t.Fatalf("the PATH_EPOCH's version keeps the tip before: %x %v", tip, ok)
	}
	if alarms := device.alarms(); len(alarms) != 0 {
		t.Fatalf("alarms %v", alarms)
	}
}

// A push naming a source at a version its ref never reached leaves the ref waiting at the version before, with no
// alarm, and a later replay waits again.
func TestEvsLocalSyncWaitsOnASourceItCannotReplay(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	f1 := publisher.commit(map[string]string{"a.txt": "a\n", "f.txt": "f\n"}, c1)
	if _, err := publisher.publish("feature", &f1); err != nil {
		t.Fatal(err)
	}
	mainId := publisher.ref("main").refId
	f2 := publisher.commit(map[string]string{"a.txt": "a\n", "f.txt": "f two\n"}, f1)
	evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) {
		update.git.Sources = []*protocol.EvsOverlay{{RefId: mainId.Bytes(), Version: 9}}
	}
	_, err := publisher.publish("feature", &f2)
	evsLocalPublishUpdateHook = nil
	if err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	for range 2 {
		device.replay("feature")
		ref := device.ref("feature")
		if ref.Version != 1 || ref.WaitingSource == nil || *ref.WaitingSource != mainId || ref.WaitingVersion != 9 || ref.StuckAt != 0 {
			t.Fatalf("the waiting record %+v", ref)
		}
	}
	if local := device.local("refs/heads/feature"); local == nil || *local != f1 {
		t.Fatalf("feature is %v", local)
	}
	if alarms := device.alarms(); len(alarms) != 0 {
		t.Fatalf("alarms %v", alarms)
	}
}

// 8.5's stop and resume: a refused version stops main with its token paths tainted; a DELETE resumes it, the local
// ref deleted; a re-creating push that neither writes nor removes a tainted path is refused, and one that writes each
// applies, the taints cleared. The writer here is given no taint, so its first re-creation leaves a.txt alone as a
// hand-built push would; a design device's, given them, is TestEvsLocalSyncReCreationWritesAndRemovesTaintedPaths.
func TestEvsLocalSyncResumesAtADeleteHeldToTaintedPaths(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	// a forged commit changing a.txt, which every honest reader refuses
	forged, _ := publisher.mount.history.commit(publisher.tree(map[string]string{"a.txt": "forged\n", "b.txt": "b\n"}), evsTestId("another client").String()+evsCommitterDomain, c1)
	if _, err := publisher.publish("main", &forged, func(args *EvsLocalPublishArgs) { args.OwnClient = func(Id) bool { return true } }); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 2 || len(ref.Tainted) != 1 {
		t.Fatalf("stopped %+v", ref)
	}
	// the writer, stopped as every honest reader is, holds c1 and deletes on the head
	stopped := func() {
		ref := publisher.ref("main")
		ref.tip = &c1
		publisher.mount.evsTip(ref.refId, c1)
	}
	stopped()
	if _, err := publisher.publish("main", nil); err != nil {
		t.Fatal(err)
	}
	device.replay("main")
	ref := device.ref("main")
	if ref.StuckAt != 0 || !ref.Deleted || ref.Tip != nil || !evsOidEqual(ref.LastTip, &c1) || len(ref.Stopped) != 1 || ref.Stopped[0] != [2]uint64{2, 3} {
		t.Fatalf("after the DELETE %+v", ref)
	}
	if local := device.local("refs/heads/main"); local != nil {
		t.Fatalf("main stands at %v after the DELETE", local)
	}
	// a re-creation that leaves a.txt alone does not clear its taint
	untouched := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b two\n"}, c1)
	if _, err := publisher.publish("main", &untouched); err != nil {
		t.Fatal(err)
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 4 || ref.Tip != nil {
		t.Fatalf("a re-creation that leaves a taint: %+v", ref)
	}
	// stopped again, deleted again, and re-created writing every tainted path
	stopped()
	publisher.ref("main").deleted, publisher.ref("main").lastTip = false, nil
	if _, err := publisher.publish("main", nil); err != nil {
		t.Fatal(err)
	}
	cleared := publisher.commit(map[string]string{"a.txt": "a three\n", "b.txt": "b three\n"}, c1)
	if _, err := publisher.publish("main", &cleared); err != nil {
		t.Fatal(err)
	}
	device.replay("main")
	ref = device.ref("main")
	if ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &cleared) || len(ref.Tainted) != 0 {
		t.Fatalf("a re-creation writing every taint: %+v", ref)
	}
	if local := device.local("refs/heads/main"); local == nil || *local != cleared {
		t.Fatalf("main is %v", local)
	}
	if alarms := device.alarms(); len(alarms) != 2 {
		t.Fatalf("alarms %v", alarms)
	}
}

// The replayed name index (8.2.10): a branch with no base walks its whole tree, the root first and a directory before
// what it holds, at the record's head; an overlay walks only the paths it holds; CreatedAfter names what a version's
// tip added. Each branch's index is registered with the client's mapper.
func TestEvsLocalSyncNameIndex(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	m1 := publisher.commit(map[string]string{"src/a.go": "a\n", "docs/readme": "r\n"})
	if _, err := publisher.publish("main", &m1); err != nil {
		t.Fatal(err)
	}
	f1 := publisher.commit(map[string]string{"src/a.go": "a changed\n", "docs/readme": "r\n"}, m1)
	if _, err := publisher.publish("feature", &f1); err != nil {
		t.Fatal(err)
	}
	m2 := publisher.commit(map[string]string{"src/a.go": "a\n", "docs/readme": "r\n", "docs/new.md": "n\n"}, m1)
	if _, err := publisher.publish("main", &m2); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	device.replay("feature")
	walk := func(name string) []string {
		t.Helper()
		index := &evsLocalNameIndex{engine: device.engine, refId: publisher.ref(name).refId}
		paths := []string{}
		if err := index.Walk(context.Background(), func(path *EvsIndexedPath) error {
			paths = append(paths, path.Path()+":"+path.Kind.String())
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return paths
	}
	want := []string{":EVS_ENTRY_DIRECTORY", "docs:EVS_ENTRY_DIRECTORY", "docs/new.md:EVS_ENTRY_FILE", "docs/readme:EVS_ENTRY_FILE",
		"src:EVS_ENTRY_DIRECTORY", "src/a.go:EVS_ENTRY_FILE"}
	if got := walk("main"); !slices.Equal(got, want) {
		t.Fatalf("main's walk %v", got)
	}
	if got := walk("feature"); !slices.Equal(got, []string{":EVS_ENTRY_DIRECTORY", "src/a.go:EVS_ENTRY_FILE"}) {
		t.Fatalf("the overlay's walk %v", got)
	}
	index := &evsLocalNameIndex{engine: device.engine, refId: publisher.ref("main").refId}
	head, err := index.Head(context.Background())
	if err != nil || head.Version != 2 {
		t.Fatalf("the head %+v %v", head, err)
	}
	created, err := index.CreatedAfter(context.Background(), 1)
	if err != nil || len(created) != 1 || created[0].Path() != "docs/new.md" {
		t.Fatalf("created after 1: %v %v", created, err)
	}
	mapper := device.test.client.mapper()
	mapper.stateLock.Lock()
	registered := mapper.indexes[evsRefKey{repoId: publisher.writer.world.repoId, refId: publisher.ref("main").refId}] != nil &&
		mapper.indexes[evsRefKey{repoId: publisher.writer.world.repoId, refId: publisher.ref("feature").refId}] != nil
	mapper.stateLock.Unlock()
	if !registered {
		t.Fatal("the branches' indexes are not registered")
	}
}

// Stops the ref of name at a forged version on before, of files and committed by another client, which every honest
// reader refuses: device b replays it and holds its token paths tainted. Then beforeDelete runs, if any, and the
// writer, stopped as b is and so holding before as the tip, deletes the ref on the head, which b applies. Answers b,
// whose record holds the taints the re-creating push takes.
func (self *evsTestPublisher) stopAndDelete(name string, before EvsGitOid, files map[string]string, beforeDelete func()) *evsTestDevice {
	self.t.Helper()
	forged, _ := self.mount.history.commit(self.tree(files), evsTestId("another client").String()+evsCommitterDomain, before)
	if _, err := self.publish(name, &forged, func(args *EvsLocalPublishArgs) { args.OwnClient = func(Id) bool { return true } }); err != nil {
		self.t.Fatal(err)
	}
	device := newEvsTestDevice(self.t, self, "device b")
	device.replay(name)
	if ref := device.ref(name); ref.StuckAt == 0 || len(ref.Tainted) == 0 {
		self.t.Fatalf("not stopped: %+v", ref)
	}
	if beforeDelete != nil {
		beforeDelete()
	}
	ref := self.ref(name)
	ref.tip = &before
	self.mount.evsTip(ref.refId, before)
	if _, err := self.publish(name, nil); err != nil {
		self.t.Fatal(err)
	}
	device.replay(name)
	if ref := device.ref(name); !ref.Deleted || ref.StuckAt != 0 || len(ref.Tainted) == 0 {
		self.t.Fatalf("after the DELETE %+v", ref)
	}
	return device
}

// 8.6's re-creating push at M2 (DESIGN-DETAILS 8.5; 8.2.4's chain row, amendment 16-D): main is stopped at a forged
// version that changes a.txt, plants x.txt at the top and docs/y.md below, and is deleted. A design device re-creates
// it with a change to b.txt alone, so its net change leaves every tainted path alone: it writes a.txt again where its
// file stands, one checkpoint of the tree's blob; removes x.txt and docs/y.md where they do not; and gives the root and
// docs the tables the tree gives them. Device b, which stopped, applies the push and its taints clear, and a device
// mounted afterwards, whose one replay runs from the first version through the stop, the DELETE and the re-creation,
// reaches the same tip.
func TestEvsLocalSyncReCreationWritesAndRemovesTaintedPaths(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	text := strings.Repeat("a line of a.txt that a diff would rest on\n", 64)
	c1 := publisher.commit(map[string]string{"a.txt": text, "b.txt": "b\n", "docs/keep.md": "k\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := publisher.stopAndDelete("main", c1, map[string]string{
		"a.txt": text + "forged\n", "b.txt": "b\n", "x.txt": "planted\n", "docs/keep.md": "k\n", "docs/y.md": "planted\n",
	}, nil)
	// a.txt, x.txt, docs/y.md, and the root's and docs's deltas that added the two planted names
	tainted := device.ref("main").Tainted
	if len(tainted) != 5 {
		t.Fatalf("taints %v", tainted)
	}
	next := publisher.commit(map[string]string{"a.txt": text, "b.txt": "b two\n", "docs/keep.md": "k\n"}, c1)
	result, err := publisher.publish("main", &next, func(args *EvsLocalPublishArgs) { args.Tainted = tainted })
	if err != nil {
		t.Fatal(err)
	}
	if changes := publisher.payload("main", result.Version).Changes; len(changes) != 6 {
		t.Fatalf("the re-creation states %d changes", len(changes))
	}
	if chain := publisher.writer.entry(t, "a.txt").GetChain(); len(chain) != 1 {
		t.Fatalf("a.txt written again as a chain of %d", len(chain))
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	removed := world.paths["x.txt"].removal != nil && world.paths["docs/y.md"].removal != nil
	rootRows, docsRows := len(world.paths[""].rows), len(world.paths["docs"].rows)
	world.stateLock.Unlock()
	if !removed || rootRows != 3 || docsRows != 1 {
		t.Fatalf("the planted paths removed %v; the root's rows %d, docs's %d", removed, rootRows, docsRows)
	}
	device.replay("main")
	ref := device.ref("main")
	if ref.StuckAt != 0 || ref.Deleted || !evsOidEqual(ref.Tip, &next) || len(ref.Tainted) != 0 {
		t.Fatalf("device b after the re-creation %+v", ref)
	}
	if local := device.local("refs/heads/main"); local == nil || *local != next {
		t.Fatalf("device b's main is %v", local)
	}
	late := newEvsTestDevice(t, publisher, "device c")
	late.replay("main")
	if ref := late.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &next) || len(ref.Tainted) != 0 || len(ref.Stopped) != 1 {
		t.Fatalf("a later mount %+v", ref)
	}
	if content := evsTestGit(t, late.mount.BareDir, "cat-file", "-p", hex.EncodeToString(next[:])+":a.txt"); content != text {
		t.Fatalf("a.txt on a later mount %q", content)
	}
	if fsck := evsTestFsck(t, late.mount.BareDir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
	if len(device.alarms()) != 1 || len(late.alarms()) != 1 {
		t.Fatalf("alarms %v and %v", device.alarms(), late.alarms())
	}
}

// The writer, stopped as every honest reader is and so holding before as the tip, deletes the ref of name on the head
// again after a re-creation the readers refused.
func (self *evsTestPublisher) deleteStopped(name string, before EvsGitOid) {
	self.t.Helper()
	ref := self.ref(name)
	ref.tip, ref.deleted, ref.lastTip = &before, false, nil
	self.mount.evsTip(ref.refId, before)
	if _, err := self.publish(name, nil); err != nil {
		self.t.Fatal(err)
	}
}

// Whether a committed version of the ref of name states a change at path.
func (self *evsTestPublisher) changesPath(name string, version uint64, path string) bool {
	self.t.Helper()
	key := self.writer.world.tokensAt(path, 1).KeyString()
	return slices.ContainsFunc(self.payload(name, version).Changes, func(change *EvsCheckedChange) bool {
		return change.TokenPath.KeyString() == key
	})
}

// A stopped version removed secret.txt (QD-826; question evs1-m2-34-tainted-recreate-removed-taint, option 1): device
// b records that taint as removed, and the root's, whose table the version changed, as standing. A writer given the
// taints as a record stored before the field reads them, all standing, plans a removal evs would refuse, and is
// refused before any evs write. Given device b's record, a re-creation whose tree lacks secret.txt too lands in one
// push that states nothing there, the stopped removal standing for the net change's own; device b and a device
// mounted afterwards both apply it, their taints cleared, and the tree they hold has no secret.txt.
func TestEvsLocalSyncReCreationLeavesAPathTheStopRemoved(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n", "secret.txt": "s\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := publisher.stopAndDelete("main", c1, map[string]string{"a.txt": "a\n"}, nil)
	tainted := device.ref("main").Tainted
	if secret, root := device.taintAt("main", "secret.txt"), device.taintAt("main", ""); len(tainted) != 2 || secret == nil ||
		!secret.Removed || root == nil || root.Removed {
		t.Fatalf("taints %+v", tainted)
	}
	lacking := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	standing := slices.Clone(tainted)
	for i := range standing {
		standing[i].Removed = false
	}
	posted, uploads := publisher.posted(), len(publisher.writer.server.uploads)
	if _, err := publisher.publish("main", &lacking, func(args *EvsLocalPublishArgs) { args.Tainted = standing }); !errors.Is(err, ErrEvsGitTaintedPath) ||
		publisher.posted() != posted || len(publisher.writer.server.uploads) != uploads {
		t.Fatalf("a re-creation from taints all standing: %v", err)
	}
	result, err := publisher.publish("main", &lacking, func(args *EvsLocalPublishArgs) { args.Tainted = tainted })
	if err != nil {
		t.Fatal(err)
	}
	if changes := publisher.payload("main", result.Version).Changes; len(changes) != 2 || publisher.changesPath("main", result.Version, "secret.txt") {
		t.Fatalf("the re-creation states %d changes", len(changes))
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	stillRemoved, rootRows := world.paths["secret.txt"].removal != nil, len(world.paths[""].rows)
	world.stateLock.Unlock()
	if !stillRemoved || rootRows != 1 {
		t.Fatalf("secret.txt removed %v; the root's rows %d", stillRemoved, rootRows)
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 0 || ref.Deleted || !evsOidEqual(ref.Tip, &lacking) || len(ref.Tainted) != 0 {
		t.Fatalf("device b after the re-creation %+v", ref)
	}
	if local := device.local("refs/heads/main"); local == nil || *local != lacking {
		t.Fatalf("device b's main is %v", local)
	}
	late := newEvsTestDevice(t, publisher, "device c")
	late.replay("main")
	if ref := late.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &lacking) || len(ref.Tainted) != 0 || len(ref.Stopped) != 1 {
		t.Fatalf("a later mount %+v", ref)
	}
	if names := evsTestGit(t, late.mount.BareDir, "ls-tree", "--name-only", hex.EncodeToString(lacking[:])); names != "a.txt\n" {
		t.Fatalf("the re-created tree holds %q", names)
	}
	if len(device.alarms()) != 1 || len(late.alarms()) != 1 {
		t.Fatalf("alarms %v and %v", device.alarms(), late.alarms())
	}
}

// A stopped span whose refused version plants new.txt and whose later version removes it (QD-826): device b reads the
// later version for its token paths alone and records new.txt's taint as removed, the last change there. A
// re-creation whose tree never held new.txt states nothing there, writes the root the stopped versions changed as the
// tree gives it, and lands in one push that device b and a device mounted afterwards both apply.
func TestEvsLocalSyncReCreationLeavesAPathTheStopCreatedAndRemoved(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := publisher.stopAndDelete("main", c1, map[string]string{"a.txt": "a\n", "new.txt": "planted\n"}, func() {
		// on the forged tip, a version of the stopped span that removes what the refused one planted
		removing := publisher.commit(map[string]string{"a.txt": "a\n"}, *publisher.ref("main").tip)
		if _, err := publisher.publish("main", &removing); err != nil {
			t.Fatal(err)
		}
	})
	ref := device.ref("main")
	if len(ref.Stopped) != 1 || ref.Stopped[0] != [2]uint64{2, 4} {
		t.Fatalf("stopped %+v", ref)
	}
	if planted, root := device.taintAt("main", "new.txt"), device.taintAt("main", ""); len(ref.Tainted) != 2 || planted == nil ||
		!planted.Removed || root == nil || root.Removed {
		t.Fatalf("taints %+v", ref.Tainted)
	}
	next := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	result, err := publisher.publish("main", &next, func(args *EvsLocalPublishArgs) { args.Tainted = ref.Tainted })
	if err != nil {
		t.Fatal(err)
	}
	if changes := publisher.payload("main", result.Version).Changes; len(changes) != 2 || publisher.changesPath("main", result.Version, "new.txt") ||
		!publisher.changesPath("main", result.Version, "") {
		t.Fatalf("the re-creation states %d changes", len(changes))
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &next) || len(ref.Tainted) != 0 {
		t.Fatalf("device b after the re-creation %+v", ref)
	}
	late := newEvsTestDevice(t, publisher, "device c")
	late.replay("main")
	if ref := late.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &next) || len(ref.Tainted) != 0 || len(ref.Stopped) != 1 {
		t.Fatalf("a later mount %+v", ref)
	}
	if names := evsTestGit(t, late.mount.BareDir, "ls-tree", "--name-only", hex.EncodeToString(next[:])); names != "a.txt\n" {
		t.Fatalf("the re-created tree holds %q", names)
	}
}

// A tainted path the stopped version left standing still has to be written or removed (QD-826): main's stopped
// version changes a.txt and removes secret.txt. A re-creation from a writer given every taint but a.txt's, whose tree
// holds a.txt as it stood, writes the root and states nothing at a.txt or secret.txt, and device b refuses it,
// stopping main again. Deleted again and re-created from device b's record, which holds a.txt standing and
// secret.txt removed, the push writes a.txt again, states nothing at secret.txt and applies.
func TestEvsLocalSyncReCreationLeavingAStandingTaintIsRefused(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n", "secret.txt": "s\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := publisher.stopAndDelete("main", c1, map[string]string{"a.txt": "forged\n"}, nil)
	tainted := device.ref("main").Tainted
	if text := device.taintAt("main", "a.txt"); len(tainted) != 3 || text == nil || text.Removed {
		t.Fatalf("taints %+v", tainted)
	}
	textKey := publisher.writer.world.tokensAt("a.txt", 1).KeyString()
	partial := slices.DeleteFunc(slices.Clone(tainted), func(path EvsTaintedPath) bool { return path.Key == textKey })
	next := publisher.commit(map[string]string{"a.txt": "a\n"}, c1)
	result, err := publisher.publish("main", &next, func(args *EvsLocalPublishArgs) { args.Tainted = partial })
	if err != nil {
		t.Fatal(err)
	}
	if publisher.changesPath("main", result.Version, "a.txt") || publisher.changesPath("main", result.Version, "secret.txt") {
		t.Fatal("the partial re-creation changes a.txt or secret.txt")
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != result.Version || ref.Tip != nil || len(device.alarms()) != 2 {
		t.Fatalf("a re-creation leaving a standing taint alone: %+v", ref)
	}
	publisher.deleteStopped("main", c1)
	device.replay("main")
	tainted = device.ref("main").Tainted
	if secret, text := device.taintAt("main", "secret.txt"), device.taintAt("main", "a.txt"); secret == nil || !secret.Removed ||
		text == nil || text.Removed {
		t.Fatalf("taints after the second DELETE %+v", tainted)
	}
	again := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b\n"}, c1)
	result, err = publisher.publish("main", &again, func(args *EvsLocalPublishArgs) { args.Tainted = tainted })
	if err != nil {
		t.Fatal(err)
	}
	if !publisher.changesPath("main", result.Version, "a.txt") || publisher.changesPath("main", result.Version, "secret.txt") {
		t.Fatal("the re-creation from the record does not write a.txt alone of the two")
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &again) || len(ref.Tainted) != 0 {
		t.Fatalf("device b after the re-creation from its record %+v", ref)
	}
	if content := evsTestGit(t, device.mount.BareDir, "cat-file", "-p", hex.EncodeToString(again[:])+":a.txt"); content != "a\n" {
		t.Fatalf("a.txt %q", content)
	}
}

// A stopped version removed secret.txt, and a re-creation's tree keeps it as it stood (QD-826): the push must write
// it. One from a writer given every taint but secret.txt's writes the root, whose table lists secret.txt again, and
// leaves secret.txt alone, where evs holds the removal and the tree a file, and device b refuses it. Deleted again and
// re-created from device b's record, the push writes secret.txt again, a creation over the removal, and device b
// applies it.
func TestEvsLocalSyncReCreationWritesAgainAPathTheStopRemoved(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n", "secret.txt": "s\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := publisher.stopAndDelete("main", c1, map[string]string{"a.txt": "a\n"}, nil)
	tainted := device.ref("main").Tainted
	secretKey := publisher.writer.world.tokensAt("secret.txt", 1).KeyString()
	partial := slices.DeleteFunc(slices.Clone(tainted), func(path EvsTaintedPath) bool { return path.Key == secretKey })
	if len(tainted) != 2 || len(partial) != 1 {
		t.Fatalf("taints %+v", tainted)
	}
	kept := publisher.commit(map[string]string{"a.txt": "a two\n", "secret.txt": "s\n"}, c1)
	result, err := publisher.publish("main", &kept, func(args *EvsLocalPublishArgs) { args.Tainted = partial })
	if err != nil {
		t.Fatal(err)
	}
	if publisher.changesPath("main", result.Version, "secret.txt") || !publisher.changesPath("main", result.Version, "") {
		t.Fatal("the partial re-creation writes secret.txt, or not the root")
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != result.Version || ref.Tip != nil {
		t.Fatalf("a re-creation leaving a removed path the tree holds alone: %+v", ref)
	}
	publisher.deleteStopped("main", c1)
	device.replay("main")
	tainted = device.ref("main").Tainted
	if secret := device.taintAt("main", "secret.txt"); secret == nil || !secret.Removed {
		t.Fatalf("taints after the second DELETE %+v", tainted)
	}
	again := publisher.commit(map[string]string{"a.txt": "a three\n", "secret.txt": "s\n"}, c1)
	result, err = publisher.publish("main", &again, func(args *EvsLocalPublishArgs) { args.Tainted = tainted })
	if err != nil {
		t.Fatal(err)
	}
	if !publisher.changesPath("main", result.Version, "secret.txt") {
		t.Fatal("the re-creation from the record leaves secret.txt alone")
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	restored := world.paths["secret.txt"].removal == nil && len(world.paths[""].rows) == 2
	world.stateLock.Unlock()
	if !restored {
		t.Fatal("secret.txt is not written again with its row")
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &again) || len(ref.Tainted) != 0 {
		t.Fatalf("device b after the re-creation from its record %+v", ref)
	}
	if content := evsTestGit(t, device.mount.BareDir, "cat-file", "-p", hex.EncodeToString(again[:])+":secret.txt"); content != "s\n" {
		t.Fatalf("secret.txt %q", content)
	}
}

// A ref record whose taints were stored before EvsTaintedPath.Removed (QD-826) opens, each taint read as one the
// stopped versions left standing, which a re-creating push must still write or remove; a taint stored removed reads
// back removed, and one standing stores no field, so the record a reader without the field reads is the one it wrote.
func TestEvsLocalGitRefRecordOfTaintsBeforeRemovedOpens(t *testing.T) {
	state := &evsLocalState{store: newEvsTestStore(t), repoId: evsTestId("repo")}
	refId := evsTestId("ref")
	chain := EvsChainStart(state.repoId, refId)
	key := EvsLocalKey{Family: EvsLocalRefs, RefId: refId}
	stored := `{"ref_id":"` + hex.EncodeToString(refId[:]) + `","version":3,"chain":"` + hex.EncodeToString(chain[:]) +
		`","deleted":true,"stopped":[[2,3]],"tainted":[{"epoch":1,"key":"t"},{"epoch":1,"key":""}]}`
	if err := state.writeJson(key, json.RawMessage(stored)); err != nil {
		t.Fatal(err)
	}
	read, err := state.gitRef(refId)
	if err != nil {
		t.Fatal(err)
	}
	if !read.Deleted || read.Version != 3 || len(read.Tainted) != 2 || read.Tainted[0] != (EvsTaintedPath{Epoch: 1, Key: "t"}) ||
		read.Tainted[1] != (EvsTaintedPath{Epoch: 1, Key: ""}) {
		t.Fatalf("read %+v", read)
	}
	read.Tainted[0].Removed = true
	if err := state.writeGitRef(read); err != nil {
		t.Fatal(err)
	}
	again, err := state.gitRef(refId)
	if err != nil || len(again.Tainted) != 2 || !again.Tainted[0].Removed || again.Tainted[1].Removed {
		t.Fatalf("read back %+v: %v", again, err)
	}
	encoded, err := json.Marshal(again.record().Tainted)
	if err != nil || string(encoded) != `[{"epoch":1,"key":"t","removed":true},{"epoch":1,"key":""}]` {
		t.Fatalf("stored as %s: %v", encoded, err)
	}
}
