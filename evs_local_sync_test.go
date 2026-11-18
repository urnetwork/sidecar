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
//
// And EVS1-M6-06's readers (DESIGN-DETAILS 8.6's evs-to-git row as amended for section 16 and QD-801), under a rule
// set that holds a signer to agents/build: hand-built pushes refused with prefix_rule, each with its passing twin by
// a signer the set names for every path, on overlay branches of main (a file written outside, refused before a commit
// is read; an inherited file removed outside; a directory created over a file outside), the last file under the
// prefix removed with the directories above it passing; a set pending at the pin leaving the ref waiting with no alarm
// and no stuck_at, the replay going on once the set opens; new shared branches measured from main's tree or from
// nothing; tags with a proof at a current and a past tip, and each way a named source is no proof; a first push
// refused, deleted and pushed again; a re-creation writing a tainted token path outside; a push failing both the
// tree's hash and the prefix line raising the tree's reason on two devices; and two mounts' one verdict on a tag,
// which a hook that looks the tagged commit up in a device's own tip index breaks.

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
	"github.com/urnetwork/sidecar/protocol/bridge"
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
	// a second stop after the re-creation: a mount whose one replay runs through both holds the second's taints alone
	planted, _ := publisher.mount.history.commit(publisher.tree(map[string]string{"a.txt": "a two\n", "x.txt": "planted\n"}), evsTestId("another client").String()+evsCommitterDomain, lacking)
	if _, err := publisher.publish("main", &planted, func(args *EvsLocalPublishArgs) { args.OwnClient = func(Id) bool { return true } }); err != nil {
		t.Fatal(err)
	}
	fresh := newEvsTestDevice(t, publisher, "device d")
	fresh.replay("main")
	if ref := fresh.ref("main"); ref.StuckAt != result.Version+1 || !evsOidEqual(ref.Tip, &lacking) || len(ref.Tainted) != 2 ||
		fresh.taintAt("main", "x.txt") == nil || fresh.taintAt("main", "secret.txt") != nil {
		t.Fatalf("a mount whose one replay runs through both stops %+v", ref)
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

// The mirror of the last (QD-826): a stopped span whose refused version removes secret.txt and whose later version
// writes it again leaves it standing on evs, and device b records its taint as standing, the last change there. A
// re-creation whose tree lacks secret.txt must remove it, and does, a removal of the later version's entry, which
// device b and a device mounted afterwards apply.
func TestEvsLocalSyncReCreationRemovesAPathTheStopRemovedAndWroteAgain(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n", "secret.txt": "s\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := publisher.stopAndDelete("main", c1, map[string]string{"a.txt": "a\n"}, func() {
		// on the forged tip, a version of the stopped span that writes what the refused one removed
		rewriting := publisher.commit(map[string]string{"a.txt": "a\n", "secret.txt": "written again\n"}, *publisher.ref("main").tip)
		if _, err := publisher.publish("main", &rewriting); err != nil {
			t.Fatal(err)
		}
	})
	tainted := device.ref("main").Tainted
	if secret := device.taintAt("main", "secret.txt"); secret == nil || secret.Removed {
		t.Fatalf("taints %+v", tainted)
	}
	lacking := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	result, err := publisher.publish("main", &lacking, func(args *EvsLocalPublishArgs) { args.Tainted = tainted })
	if err != nil {
		t.Fatal(err)
	}
	if !publisher.changesPath("main", result.Version, "secret.txt") {
		t.Fatal("the re-creation leaves alone secret.txt, which the stop wrote again")
	}
	world := publisher.writer.world
	world.stateLock.Lock()
	removed := world.paths["secret.txt"].removal != nil
	world.stateLock.Unlock()
	if !removed {
		t.Fatal("secret.txt stands after the re-creation")
	}
	device.replay("main")
	if ref := device.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &lacking) || len(ref.Tainted) != 0 {
		t.Fatalf("device b after the re-creation %+v", ref)
	}
	late := newEvsTestDevice(t, publisher, "device c")
	late.replay("main")
	if ref := late.ref("main"); ref.StuckAt != 0 || !evsOidEqual(ref.Tip, &lacking) || len(ref.Tainted) != 0 {
		t.Fatalf("a later mount %+v", ref)
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

// A re-creating push whose tainted paths outside the net change are not as the new tree holds them is refused
// (QD-826; 8.2.7's changes row). Its writer is handed another tree to name the taints in, so it removes a.txt, which
// the new tree holds as it stood, writes a.txt with a blob the new tree does not hold there, or writes x.txt, which
// the stop planted and the new tree lacks; or it is not told of x.txt's taint, and leaves alone the file the stop
// planted there, standing on evs where the new tree holds nothing. Device b refuses each, stopping main at the
// re-creation, where the design writer's push of such a tree applies
// (TestEvsLocalSyncReCreationWritesAndRemovesTaintedPaths).
func TestEvsLocalSyncRefusesTaintedPathsNotAsTheTreeHoldsThem(t *testing.T) {
	cases := []struct {
		name string
		// the tree the writer names its taints in, nil for the new one
		files map[string]string
		// leaves x.txt's taint out of what the writer is told
		forget bool
	}{
		{name: "a removal of a path the tree holds", files: map[string]string{"b.txt": "b two\n"}},
		{name: "a file of another blob", files: map[string]string{"a.txt": "another blob\n", "b.txt": "b two\n"}},
		{name: "a write of a path the tree lacks", files: map[string]string{"a.txt": "a\n", "b.txt": "b two\n", "x.txt": "planted\n"}},
		{name: "a planted path left standing", forget: true},
	}
	for _, c := range cases {
		publisher := newEvsTestPublisher(t)
		c1 := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b\n"})
		if _, err := publisher.publish("main", &c1); err != nil {
			t.Fatal(err)
		}
		device := publisher.stopAndDelete("main", c1, map[string]string{"a.txt": "forged\n", "b.txt": "b\n", "x.txt": "planted\n"}, nil)
		if text, planted := device.taintAt("main", "a.txt"), device.taintAt("main", "x.txt"); text == nil || text.Removed || planted == nil || planted.Removed {
			t.Fatalf("%s: taints %+v", c.name, device.ref("main").Tainted)
		}
		next := publisher.commit(map[string]string{"a.txt": "a\n", "b.txt": "b two\n"}, c1)
		var named *EvsGitOid
		if c.files != nil {
			tree := publisher.tree(c.files)
			named = &tree
		}
		plantedKey := publisher.writer.world.tokensAt("x.txt", 1).KeyString()
		evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) {
			if named != nil {
				update.nextTree = *named
			}
			if c.forget {
				update.tainted = slices.DeleteFunc(slices.Clone(update.tainted), func(path EvsTaintedPath) bool { return path.Key == plantedKey })
			}
		}
		result, err := publisher.publish("main", &next, func(args *EvsLocalPublishArgs) { args.Tainted = device.ref("main").Tainted })
		evsLocalPublishUpdateHook = nil
		if err != nil {
			t.Fatalf("%s: the writer's push: %v", c.name, err)
		}
		device.replay("main")
		if ref := device.ref("main"); ref.StuckAt != result.Version || ref.Tip != nil || len(device.alarms()) != 2 {
			t.Fatalf("%s: device b %+v", c.name, ref)
		}
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

// A git-mode world under a rule set at 5 that names the world's writer, a repo admin, for every path and holds a
// second writer, held, to agents/build and docs/inner; a third writer, unnamed, the set names in no rule. The
// writer's client publishes as any of them, its local refusal the engine's over the world's state, or, for a breach,
// skipped as a device that does not run this code; devices replay under the same sets.
type evsTestGitRules struct {
	*evsPrefixTest
	publisher *evsTestPublisher
	unnamed   *evsTestSigner
	// the paths the writer's local refusal drew, and whether the publish now is a breach
	drawn  []string
	breach bool
}

func newEvsTestGitRules(t *testing.T) *evsTestGitRules {
	t.Helper()
	publisher := newEvsTestPublisher(t)
	world := publisher.writer.world
	test := &evsTestGitRules{evsPrefixTest: newEvsPrefixTestOn(t, world), publisher: publisher, unnamed: newEvsTestSigner("unnamed writer")}
	world.config.identityKeys[test.unnamed.sidecarId] = test.unnamed.publicKey()
	world.config.writers = append(world.config.writers, test.unnamed.sidecarId)
	world.config.rows[test.unnamed.sidecarId] = &bridge.SidecarRow{SidecarId: test.unnamed.sidecarId.Bytes()}
	test.file(5, AclPrefixSetOpened, "agents/build", "docs/inner")
	world.config.setPin(5)
	publisher.writer.test.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets:       func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return slices.Clone(test.sets), nil },
		AllowWrite: test.allowWrite,
		Settings:   testAclPrefixSettingsOn(),
	})
	evsLocalPublishSkipPrefixHook = func(update *evsGitPublishUpdate) bool { return test.breach }
	t.Cleanup(func() { evsLocalPublishSkipPrefixHook = nil })
	return test
}

// AclEngine.AllowPrefixWrite's lines over the world's state, for the sidecar the writer's client signs as now, each
// path drawn noted; a breach allows everything.
func (self *evsTestGitRules) allowWrite(write *AclPrefixWrite) AclPrefixWriteDecision {
	allowed := func(at uint64) AclPrefixWriteDecision {
		return AclPrefixWriteDecision{AclDecision: AclDecision{Allowed: true, Reason: AclReasonPrefixRule, At: at}}
	}
	refused := func(detail AclPrefixDetail, at uint64, path string) AclPrefixWriteDecision {
		return AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule, At: at}, Detail: detail, Path: path}
	}
	if self.breach {
		return allowed(0)
	}
	config := self.world.config
	repo := config.Repo(write.RepoId)
	if aclPrefixOutside(repo.GetKind(), write.RefKind, write.RefName, write.Flags) {
		return allowed(0)
	}
	set, verdict, decided := aclPrefixSetInForce(repo.GetPrefixRules(), write.Sets, config.Pin().GetVersion())
	if decided {
		switch verdict.Outcome {
		case AclPrefixAllowed:
			return allowed(0)
		case AclPrefixUpdate:
			return refused(AclPrefixDetailUpdate, verdict.SetAt, "")
		}
		return refused(AclPrefixDetailPending, verdict.SetAt, "")
	}
	named := aclPrefixNamedRules(set, config.SidecarRow(self.publisher.writer.test.client.args.Identity().SidecarId))
	for _, rule := range named {
		if len(rule.GetPath()) == 0 {
			return allowed(set.At)
		}
	}
	if write.Paths != nil {
		for path := range write.Paths {
			self.drawn = append(self.drawn, path)
			if path == "" {
				return refused(AclPrefixDetailRefused, set.At, "")
			}
			if !aclPrefixRulesCoverNames(named, strings.Split(path, "/")) {
				return refused(AclPrefixDetailRefused, set.At, path)
			}
		}
	}
	return allowed(set.At)
}

// The client a signer's pushes and commits name: the world's for the admin.
func (self *evsTestGitRules) clientOf(signer *evsTestSigner) Id {
	if signer == self.admin {
		return evsTestId("world client")
	}
	return evsTestId("client of " + signer.sidecarId.String())
}

// A commit by signer's client of files on parents.
func (self *evsTestGitRules) commitAs(signer *evsTestSigner, files map[string]string, parents ...EvsGitOid) EvsGitOid {
	oid, _ := self.publisher.mount.history.commit(self.publisher.tree(files), self.clientOf(signer).String()+evsCommitterDomain, parents...)
	return oid
}

// Publishes the ref of name to new as signer, a breach skipping the writer's own check.
func (self *evsTestGitRules) publishAs(signer *evsTestSigner, breach bool, name string, new *EvsGitOid, configure ...func(args *EvsLocalPublishArgs)) (*EvsLocalPublishResult, error) {
	self.t.Helper()
	client := self.publisher.writer.test.client
	identity, sign := client.args.Identity, client.args.Sign
	as := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: signer.sidecarId, ClientId: self.clientOf(signer)}
	client.args.Identity = func() *SidecarIdentity { return as }
	client.args.Sign = signer.sign
	self.breach = breach
	defer func() { client.args.Identity, client.args.Sign, self.breach = identity, sign, false }()
	return self.publisher.publish(name, new, configure...)
}

// publishAs that must commit.
func (self *evsTestGitRules) mustPublish(signer *evsTestSigner, breach bool, name string, new *EvsGitOid, configure ...func(args *EvsLocalPublishArgs)) *EvsLocalPublishResult {
	self.t.Helper()
	result, err := self.publishAs(signer, breach, name, new, configure...)
	if err != nil {
		self.t.Fatalf("%s: %v", name, err)
	}
	return result
}

// A device of the world under its rules.
func (self *evsTestGitRules) device(name string) *evsTestDevice {
	self.t.Helper()
	device := newEvsTestDevice(self.t, self.publisher, name)
	self.enable(device.test)
	return device
}

// The name of signer's owned ref, which the stand-in serves as owned by signer, as evs's head holds an owned ref's kind
// and owner from its first push.
func (self *evsTestGitRules) ownedRef(signer *evsTestSigner, rest string) string {
	name := evsOwnedRefPrefix + signer.sidecarId.String() + "/" + rest
	world := self.publisher.writer.world.otherRef([]byte(name))
	world.stateLock.Lock()
	world.owned, world.signer = true, signer
	world.stateLock.Unlock()
	return name
}

// The ref's record held to a refusal at version by the prefix line, its local ref at tip (nil: none), and the device's
// prefix_rule alarm for it naming signer and path, and no version_rule alarm.
func (self *evsTestGitRules) refused(device *evsTestDevice, name string, version uint64, tip *EvsGitOid, signer *evsTestSigner, path string) {
	self.t.Helper()
	self.stopped(device, name, version, tip, signer)
	self.alarmed(device, name, version, signer, path)
}

// The ref's record held to a refusal at version by the prefix line, its local ref at tip (nil: none).
func (self *evsTestGitRules) stopped(device *evsTestDevice, name string, version uint64, tip *EvsGitOid, signer *evsTestSigner) {
	self.t.Helper()
	ref := device.ref(name)
	if ref.StuckAt != version || ref.StuckReason != SidecarEvsAlarmPrefixRule || ref.StuckSigner == nil || *ref.StuckSigner != signer.sidecarId {
		self.t.Fatalf("%s: the record %+v", name, ref)
	}
	if local := device.local(EvsGitRefOfName([]byte(name))); !evsOidEqual(local, tip) {
		self.t.Fatalf("%s: the local ref is %v", name, local)
	}
}

// The device's prefix_rule alarm with detail refused for the ref's version, naming signer and path, and no
// version_rule alarm for the ref.
func (self *evsTestGitRules) alarmed(device *evsTestDevice, name string, version uint64, signer *evsTestSigner, path string) {
	self.t.Helper()
	for _, alarm := range device.alarms() {
		if alarm.EvsAlarm == SidecarEvsAlarmVersionRule && alarm.RefId != nil && *alarm.RefId == self.publisher.ref(name).refId {
			self.t.Fatalf("%s: a version_rule alarm %+v", name, alarm)
		}
	}
	for _, alarm := range device.alarms() {
		if alarm.EvsAlarm == SidecarEvsAlarmPrefixRule && alarm.RefId != nil && *alarm.RefId == self.publisher.ref(name).refId && alarm.Version == version {
			if alarm.EvsAlarmDetail != SidecarEvsAlarmDetailRefused || alarm.SidecarId == nil || *alarm.SidecarId != signer.sidecarId ||
				alarm.Version != version || alarm.Path != path {
				self.t.Fatalf("%s: the alarm %+v", name, alarm)
			}
			return
		}
	}
	self.t.Fatalf("%s: no prefix_rule alarm in %+v", name, device.alarms())
}

// The ref's record applied through version at tip, with no stop and no wait.
func (self *evsTestGitRules) applied(device *evsTestDevice, name string, version uint64, tip EvsGitOid) {
	self.t.Helper()
	ref := device.ref(name)
	if ref.Version != version || ref.StuckAt != 0 || ref.WaitingRules != "" || ref.WaitingSource != nil || !evsOidEqual(ref.Tip, &tip) {
		self.t.Fatalf("%s: the record %+v", name, ref)
	}
	if local := device.local(EvsGitRefOfName([]byte(name))); local == nil || *local != tip {
		self.t.Fatalf("%s: the local ref is %v", name, local)
	}
}

// Hand-built pushes by the held signer on overlay branches of main, each refused with prefix_rule and its twin by the
// admin applied: a file written outside, refused early with no path; an inherited file removed outside and a
// directory created over a file outside (its own files under docs/inner, a prefix), refused late naming the file,
// though neither has a change at its own token path; and, passing for the held signer, a file written under the
// prefix, and the last file under the prefix removed with the directories above it.
func TestEvsLocalSyncPrefixRefusesFileChangesOutside(t *testing.T) {
	rules := newEvsTestGitRules(t)
	base := map[string]string{"README": "readme\n", "src/main.go": "main\n", "agents/build/out": "built\n", "docs": "docs\n"}
	c1 := rules.commitAs(rules.admin, base)
	rules.mustPublish(rules.admin, false, "main", &c1)
	with := func(changes map[string]string, removed ...string) map[string]string {
		files := map[string]string{}
		for path, content := range base {
			files[path] = content
		}
		for path, content := range changes {
			files[path] = content
		}
		for _, path := range removed {
			delete(files, path)
		}
		return files
	}
	cases := []struct {
		name  string
		files map[string]string
		// "" applies
		path    string
		refused bool
	}{
		{name: "written", files: with(map[string]string{"src/main.go": "breach\n"}), refused: true},
		{name: "removed", files: with(nil, "README"), refused: true, path: "README"},
		{name: "overfile", files: with(map[string]string{"docs/inner/x": "x\n"}, "docs"), refused: true, path: "docs"},
		{name: "under", files: with(map[string]string{"agents/build/new": "new\n"})},
		{name: "lastunder", files: with(nil, "agents/build/out")},
	}
	tips := map[string]EvsGitOid{}
	for _, c := range cases {
		rules.mustPublish(rules.admin, false, c.name, &c1)
		tips[c.name] = rules.commitAs(rules.held, c.files, c1)
		tip := tips[c.name]
		rules.mustPublish(rules.held, c.refused, c.name, &tip)
		// the admin's twin, named for every path
		twin := "admin-" + c.name
		rules.mustPublish(rules.admin, false, twin, &c1)
		tips[twin] = rules.commitAs(rules.admin, c.files, c1)
		twinTip := tips[twin]
		rules.mustPublish(rules.admin, false, twin, &twinTip)
	}
	device := rules.device("device b")
	for _, c := range cases {
		device.replay(c.name)
		device.replay("admin-" + c.name)
		if c.refused {
			rules.refused(device, c.name, 2, &c1, rules.held, c.path)
		} else {
			rules.applied(device, c.name, 2, tips[c.name])
		}
		rules.applied(device, "admin-"+c.name, 2, tips["admin-"+c.name])
	}
	if fsck := evsTestFsck(t, device.mount.BareDir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
}

// A set pending at u's pin leaves the ref waiting before u, with no alarm and no stuck_at, as held; once the set
// opens the replay goes on and applies u.
func TestEvsLocalSyncPrefixWaitsOnAPendingSet(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	rules.file(7, AclPrefixSetPending, "agents/build")
	rules.world.config.setPin(7)
	c2 := rules.commitAs(rules.held, map[string]string{"README": "readme\n", "agents/build/out": "built again\n"}, c1)
	// the held writer could not send this under a set it cannot read; a device running other code does
	rules.mustPublish(rules.held, true, "main", &c2)
	device := rules.device("device b")
	for range 2 {
		device.replay("main")
		ref := device.ref("main")
		if ref.Version != 1 || ref.WaitingRules != EvsGitRuleWaitHeld || ref.StuckAt != 0 || ref.WaitingSource != nil {
			t.Fatalf("the waiting record %+v", ref)
		}
	}
	if alarms := device.alarms(); len(alarms) != 0 {
		t.Fatalf("alarms %+v", alarms)
	}
	// the set opens
	opened := *rules.sets[0]
	opened.At, opened.State = 7, AclPrefixSetOpened
	rules.sets[1] = &opened
	device.replay("main")
	rules.applied(device, "main", 2, c2)
}

// New shared branches (QD-801): measured from main's tree where main is their base, from nothing over the signer's
// own branch or no base. The held signer's branch over its own branch with no change is refused naming the first
// file of its tree outside the prefix; its branch over main with a change under the prefix applies, as does one at
// main's tip with no change, and that one by a signer the set names in no rule; an orphan branch writing a file
// outside is refused.
func TestEvsLocalSyncPrefixNewSharedBranches(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	own := rules.ownedRef(rules.held, "work")
	c2 := rules.commitAs(rules.held, map[string]string{"README": "readme\n", "agents/build/out": "built\n", "agents/build/x": "x\n"}, c1)
	rules.mustPublish(rules.held, false, own, &c2)
	// a breaching writer creates release over its own branch, the nearest base
	release := rules.mustPublish(rules.held, true, "release", &c2)
	ownId := rules.publisher.ref(own).refId
	if release.Base == nil || Id(release.Base.GetRefId()) != ownId {
		t.Fatalf("release's base %v", release.Base)
	}
	// the design device takes main, the shared branch, for a branch whose tip descends from main's
	f1 := rules.commitAs(rules.held, map[string]string{"README": "readme\n", "agents/build/out": "built\n", "agents/build/f": "f\n"}, c1)
	feature := rules.mustPublish(rules.held, false, "feature", &f1)
	if feature.Base == nil || Id(feature.Base.GetRefId()) != rules.publisher.ref("main").refId {
		t.Fatalf("feature's base %v", feature.Base)
	}
	rules.mustPublish(rules.held, false, "atmain", &c1)
	rules.mustPublish(rules.unnamed, false, "unnamed", &c1)
	orphan := rules.commitAs(rules.held, map[string]string{"agents/build/y": "y\n", "src/x": "x\n"})
	rules.mustPublish(rules.held, true, "orphan", &orphan)
	device := rules.device("device b")
	for _, name := range []string{"release", "feature", "atmain", "unnamed", "orphan"} {
		device.replay(name)
	}
	rules.refused(device, "release", 1, nil, rules.held, "README")
	rules.applied(device, "feature", 1, f1)
	rules.applied(device, "atmain", 1, c1)
	rules.applied(device, "unnamed", 1, c1)
	// the orphan writes src/x outside: the early test refuses it before a commit is read, holding no name for it
	rules.refused(device, "orphan", 1, nil, rules.held, "")
	// a ref refused at its first version has no tip and no local ref, and ur status lists it with its signer
	if ref := device.ref("release"); ref.Tip != nil || ref.LastTip != nil || ref.Base == nil {
		t.Fatalf("release's record %+v", ref)
	}
}

// Tags (QD-801): with a proof naming main's current version or a past one, each passing for the held signer; with a
// source that is an owned ref, a shared branch at another tip, or a tag of a commit its own push carries, each judged
// from nothing and refused.
func TestEvsLocalSyncPrefixTagProofs(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	c2 := rules.commitAs(rules.admin, map[string]string{"README": "readme two\n", "agents/build/out": "built\n"}, c1)
	rules.mustPublish(rules.admin, false, "main", &c2)
	mainId := rules.publisher.ref("main").refId
	current := rules.mustPublish(rules.held, false, "refs/tags/current", &c2)
	past := rules.mustPublish(rules.held, false, "refs/tags/past", &c1)
	for name, result := range map[string]*EvsLocalPublishResult{"current": current, "past": past} {
		if len(result.Sources) == 0 || Id(result.Sources[0].GetRefId()) != mainId || len(result.Commits) != 0 {
			t.Fatalf("%s: sources %v, carried %d", name, result.Sources, len(result.Commits))
		}
	}
	if current.Sources[0].GetVersion() != 2 || past.Sources[0].GetVersion() != 1 {
		t.Fatalf("the proofs %v %v", current.Sources, past.Sources)
	}
	c3 := rules.commitAs(rules.held, map[string]string{"README": "readme three\n", "agents/build/out": "built\n"}, c2)
	carried := rules.mustPublish(rules.held, true, "refs/tags/carried", &c3)
	if len(carried.Commits) != 1 {
		t.Fatalf("the carried tag carries %d", len(carried.Commits))
	}
	own := rules.ownedRef(rules.held, "work")
	rules.mustPublish(rules.held, false, own, &c2)
	ownId := rules.publisher.ref(own).refId
	sources := func(sources ...*protocol.EvsOverlay) func(args *EvsLocalPublishArgs) {
		return func(args *EvsLocalPublishArgs) {
			evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) { update.git.Sources = sources }
		}
	}
	defer func() { evsLocalPublishUpdateHook = nil }()
	rules.mustPublish(rules.held, true, "refs/tags/owned", &c2, sources(&protocol.EvsOverlay{RefId: ownId.Bytes(), Version: 1}))
	rules.mustPublish(rules.held, true, "refs/tags/other", &c1, sources(&protocol.EvsOverlay{RefId: mainId.Bytes(), Version: 2}))
	evsLocalPublishUpdateHook = nil
	device := rules.device("device b")
	for _, name := range []string{"refs/tags/current", "refs/tags/past", "refs/tags/owned", "refs/tags/other", "refs/tags/carried"} {
		device.replay(name)
	}
	rules.applied(device, "refs/tags/current", 1, c2)
	rules.applied(device, "refs/tags/past", 1, c1)
	rules.refused(device, "refs/tags/owned", 1, nil, rules.held, "README")
	rules.refused(device, "refs/tags/other", 1, nil, rules.held, "README")
	rules.refused(device, "refs/tags/carried", 1, nil, rules.held, "README")
}

// One verdict on a tag whatever the mount: the held signer tags its own commit c2, which was main's tip at version 2,
// naming main at version 1 as its one source and carrying c2, so naming no proof. A long-running mount that follows
// main and one made after the last push that replays only the tag, and main to version 1 for it, both refuse it with
// prefix_rule; under a hook that looks the tagged commit up in a device's own tip index in place of the version the
// push names, the mount that follows main passes it and the other refuses, which is why the proof is the named
// version.
func TestEvsLocalSyncPrefixOneVerdictOnATagWhateverTheMount(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"agents/build/out": "built\n", "README": "readme\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	c2 := rules.commitAs(rules.held, map[string]string{"agents/build/out": "built\n", "agents/build/x": "x\n", "README": "readme\n"}, c1)
	rules.mustPublish(rules.held, false, "main", &c2)
	c3 := rules.commitAs(rules.admin, map[string]string{"agents/build/out": "built\n", "agents/build/x": "x\n", "README": "readme three\n"}, c2)
	rules.mustPublish(rules.admin, false, "main", &c3)
	mainId := rules.publisher.ref("main").refId
	blob := rules.publisher.mount.history.blob("x\n")
	evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) {
		sealed, _, err := evsGitSealCommit(context.Background(), update.objects, c2)
		if err != nil {
			t.Fatal(err)
		}
		update.git.Sources = []*protocol.EvsOverlay{{RefId: mainId.Bytes(), Version: 1}}
		update.commits, update.commitOids = []*protocol.EvsSealedCommit{sealed}, []EvsGitOid{c2}
		update.carried.blobs[blob] = true
	}
	rules.mustPublish(rules.held, true, "refs/tags/v2", &c2)
	evsLocalPublishUpdateHook = nil
	verdicts := func(label string) (bool, bool) {
		follower := rules.device("follows main " + label)
		follower.replay("main")
		follower.replay("refs/tags/v2")
		later := rules.device("tag only " + label)
		later.replay("refs/tags/v2")
		for _, device := range []*evsTestDevice{follower, later} {
			if ref := device.ref("refs/tags/v2"); ref.StuckAt != 0 && ref.StuckReason != SidecarEvsAlarmPrefixRule {
				t.Fatalf("%s: refused for another reason %+v", label, ref)
			}
		}
		return follower.ref("refs/tags/v2").StuckAt == 0, later.ref("refs/tags/v2").StuckAt == 0
	}
	if followerPassed, laterPassed := verdicts("named"); followerPassed || laterPassed {
		t.Fatalf("by the named versions: %v %v", followerPassed, laterPassed)
	}
	evsLocalSyncProofHook = func(engine *EvsGitSyncEngine) func(ctx context.Context, peeled EvsGitOid) (bool, error) {
		return func(ctx context.Context, peeled EvsGitOid) (bool, error) {
			rows, err := engine.TipsOf(ctx, peeled)
			for _, row := range rows {
				if evsGitSourceSharedBranch(row) {
					return true, err
				}
			}
			return false, err
		}
	}
	defer func() { evsLocalSyncProofHook = nil }()
	if followerPassed, laterPassed := verdicts("own index"); !followerPassed || laterPassed {
		t.Fatalf("by each device's own tip index: %v %v", followerPassed, laterPassed)
	}
}

// A push that fails both the tree's hash and the prefix line late raises the tree's reason, on two devices alike: the
// trees row comes before the late test.
func TestEvsLocalSyncPrefixTheTreesReasonComesFirst(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	c2 := rules.commitAs(rules.held, map[string]string{"agents/build/out": "built\n"}, c1)
	evsLocalPublishUpdateHook = func(update *evsGitPublishUpdate) {
		// the sealed commit's changes no longer rebuild its tree
		update.commits[0].Changes = nil
	}
	rules.mustPublish(rules.held, true, "main", &c2)
	evsLocalPublishUpdateHook = nil
	for _, name := range []string{"device b", "device c"} {
		device := rules.device(name)
		device.replay("main")
		ref := device.ref("main")
		if ref.StuckAt != 2 || ref.StuckReason != SidecarEvsAlarmVersionRule {
			t.Fatalf("%s: %+v", name, ref)
		}
	}
}

// A branch whose first push was refused is still new after its DELETE (QD-801): pushed again by the held signer over
// its own branch with no change it is refused again, and by the admin it applies.
func TestEvsLocalSyncPrefixFirstPushRefusedDeletedAndPushedAgain(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	own := rules.ownedRef(rules.held, "work")
	c2 := rules.commitAs(rules.held, map[string]string{"README": "readme\n", "agents/build/out": "built two\n"}, c1)
	rules.mustPublish(rules.held, false, own, &c2)
	rules.mustPublish(rules.held, true, "release", &c2)
	device := rules.device("device b")
	device.replay("release")
	rules.refused(device, "release", 1, nil, rules.held, "README")
	// the admin deletes it: the stopped ref takes the DELETE and nothing else; the push that re-creates it repeats the
	// head's base, which this device kept from the refused creation (the tests' publisher drops it at a DELETE)
	record := device.ref("release")
	rules.mustPublish(rules.admin, false, "release", nil)
	rules.publisher.ref("release").base = record.Base
	device.replay("release")
	if ref := device.ref("release"); ref.StuckAt != 0 || !ref.Deleted || ref.LastTip != nil || ref.Base == nil {
		t.Fatalf("after the DELETE %+v", ref)
	}
	rules.mustPublish(rules.held, true, "release", &c2)
	device.replay("release")
	// its alarm is counted into the window's next event for the same ref and signer
	rules.stopped(device, "release", 3, nil, rules.held)
	rules.mustPublish(rules.admin, false, "release", nil)
	rules.publisher.ref("release").base = record.Base
	rules.mustPublish(rules.admin, false, "release", &c2)
	device.replay("release")
	rules.applied(device, "release", 5, c2)
}

// Export judges with the sync engine's function and arguments (DESIGN-DETAILS 8.6's export bullet): the export of a
// git-mode ref a held signer breached stops at the breach, reports it with reason prefix_rule and alarms prefix_rule,
// its tip the version before; a set export cannot read ends it with EVS_PREFIX_RULE. Beside the git harness, which
// evs_export_test.go's legs do not build.
func TestEvsExportPrefixStopsAtABreach(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	c2 := rules.commitAs(rules.held, map[string]string{"README": "breach\n", "agents/build/out": "built\n"}, c1)
	rules.mustPublish(rules.held, true, "main", &c2)
	c3 := rules.commitAs(rules.admin, map[string]string{"README": "breach\n", "agents/build/out": "built three\n"}, c2)
	rules.mustPublish(rules.admin, false, "main", &c3)
	exporter := rules.world.reader(t, evsTestId("exporter"))
	rules.enable(exporter)
	result, err := exporter.client.Repo(rules.world.repoId).Export(context.Background(), &EvsExportArgs{Dir: t.TempDir() + "/export.git"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Refs) != 1 || result.Refs[0].Tip != c1 || len(result.Refs[0].Refused) != 1 || result.Refs[0].Refused[0].Version != 2 ||
		!strings.Contains(result.Refs[0].Refused[0].Reason, "prefix_rule") {
		t.Fatalf("the export %+v", result.Refs)
	}
	alarms := evsPrefixTestAlarms(exporter)
	if len(alarms) != 1 || alarms[0].EvsAlarmDetail != SidecarEvsAlarmDetailRefused || *alarms[0].SidecarId != rules.held.sidecarId {
		t.Fatalf("the export's alarms %+v", alarms)
	}
	// a set the exporter holds pending at a push's pin ends the export: it cannot wait
	pending := rules.world.reader(t, evsTestId("pending exporter"))
	pendingSets := []*AclPrefixRuleSet{{At: 5, Signer: rules.admin.sidecarId, State: AclPrefixSetPending}}
	pending.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets:     func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return pendingSets, nil },
		Settings: testAclPrefixSettingsOn(),
	})
	_, err = pending.client.Repo(rules.world.repoId).Export(context.Background(), &EvsExportArgs{Dir: t.TempDir() + "/pending.git"})
	if detail, _ := evsTestPrefixRefusal(err); detail != EvsPrefixDetailPending {
		t.Fatalf("an export under a pending set: %v", err)
	}
}

// A re-creating push that writes a tainted token path outside its signer's prefixes is refused with prefix_rule (8.5,
// 8.2.7's tainted row): a breach stops main at version 2 with README tainted; the admin deletes it; the held signer's
// re-creation writes README back as the tree holds it, which every reader refuses on the token path alone, and the
// admin's same re-creation applies.
func TestEvsLocalSyncPrefixRefusesATaintedPathOutside(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	c2 := rules.commitAs(rules.held, map[string]string{"README": "breach\n", "agents/build/out": "built\n"}, c1)
	rules.mustPublish(rules.held, true, "main", &c2)
	device := rules.device("device b")
	device.replay("main")
	rules.refused(device, "main", 2, &c1, rules.held, "")
	rules.mustPublish(rules.admin, false, "main", nil)
	device.replay("main")
	stopped := device.ref("main")
	if len(stopped.Tainted) == 0 || !stopped.Deleted {
		t.Fatalf("after the DELETE %+v", stopped)
	}
	recreate := func(signer *evsTestSigner) {
		rules.publisher.ref("main").lastTip = stopped.LastTip
		rules.mustPublish(signer, true, "main", &c1, func(args *EvsLocalPublishArgs) { args.Tainted = stopped.Tainted })
	}
	recreate(rules.held)
	device.replay("main")
	rules.stopped(device, "main", 4, nil, rules.held)
	rules.mustPublish(rules.admin, false, "main", nil)
	device.replay("main")
	stopped = device.ref("main")
	recreate(rules.admin)
	device.replay("main")
	rules.applied(device, "main", 6, c1)
}
