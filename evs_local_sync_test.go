//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-35's tests (DESIGN-DETAILS 8.6's evs-to-git row): a push on device A, the publisher, applied on device B by
// its sync engine with equal oids and a clean git fsck; a branch and an annotated tag replayed with their source first;
// each broken line of the check refused with its alarm and the ref left; a committed FORCE and a git-mode PATH_EPOCH
// raising no alarm; a source the ref waits on; a stopped ref resuming at a DELETE, its re-creating push held to the
// tainted token paths; the tips log and tip index; and the replayed name index of a branch and of an overlay.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
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
// applies, the taints cleared.
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
