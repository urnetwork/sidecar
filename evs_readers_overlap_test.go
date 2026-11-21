//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Overlapping calls on one EvsClient for the readers that walk a ref's statements themselves (evs_pin_walk.go), on the
// stand-in evs: the pin store's judgment of their walks, from a reader's own state and in pages; and for pinnedHead's
// readers (storage status, export, the desktop sync engine) and mirrors, a read whose head another call of the same
// client raised the pin past while it was in flight stands as read, with no alarm, where that raise's walk places it,
// and is a fork, alarmed, where its walk meets that raise's chain with another. Each overlapping case fails on the
// code before this change, which held the head to the live pin. A hold at the stand-in fixes each order.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The walks a reader makes itself, judged by the pin store against their asks: a page short of the head below the
// pin it asked at is no regression and raises nothing, one past the pin raises it to its end, and one on another
// chain than a kept one is a fork; a walk from a reader's own state above the pin that nothing places raises as Raise
// raises one, keeping its own chains and dropping those of the history below, so a head another read had there is
// read again, while one whose start the store holds stays placed; and a trail kept from the asked pin's version judges
// a walk read a page at a time as its statements would.
func TestEvsPinStoreJudgesTheWalksReadersMakeThemselves(t *testing.T) {
	world := newEvsTestWorld(t)
	reader := world.reader(t, evsTestId("reader"))
	pins := reader.client.pins
	repoId, refId := world.repoId, world.refId
	chains := [][sha256.Size]byte{EvsChainStart(repoId, refId)}
	for version := 1; version <= 9; version += 1 {
		chains = append(chains, EvsChainNext(chains[version-1], evsTestId(fmt.Sprint("push ", version)), sha256.Sum256([]byte(fmt.Sprint("statement ", version)))))
	}
	other := EvsChainNext(chains[2], evsTestId("the other push 3"), sha256.Sum256([]byte("the other statement 3")))
	// a walk verified from ask, from fromVersion to version, its chain at each version chains' but where swapped
	walk := func(ask *evsPinAsk, fromVersion uint64, version uint64, swapped map[uint64][sha256.Size]byte) *EvsVerifiedHead {
		chainAt := func(at uint64) [sha256.Size]byte {
			if chain, ok := swapped[at]; ok {
				return chain
			}
			return chains[at]
		}
		verified := &EvsVerifiedHead{
			RepoId: repoId, RefId: refId, Head: &protocol.EvsHeadSummary{}, Version: version, Chain: chainAt(version),
			FromVersion: fromVersion, ask: ask, fromChain: chainAt(fromVersion), ownStart: true,
		}
		for at := fromVersion + 1; at <= version; at += 1 {
			verified.Statements = append(verified.Statements, &EvsVerifiedStatement{Version: at, Chain: chainAt(at)})
		}
		return verified
	}
	page := func(ask *evsPinAsk, fromVersion uint64, version uint64, swapped map[uint64][sha256.Size]byte) *EvsVerifiedHead {
		verified := walk(ask, fromVersion, version, swapped)
		verified.page = true
		return verified
	}
	raise := func(verified *EvsVerifiedHead) (evsPinStanding, *EvsPin, error) {
		return pins.raiseRead(&EvsPin{RepoId: repoId, RefId: refId, Version: verified.Version, Chain: verified.Chain}, verified)
	}
	ask := func() *evsPinAsk {
		asked, err := pins.ask(repoId, refId)
		if err != nil {
			t.Fatal(err)
		}
		return asked
	}
	pinned := func(version uint64) {
		t.Helper()
		pin, ok, _ := pins.Pin(repoId, refId)
		if !ok || pin.Version != version || pin.Chain != chains[version] {
			t.Fatalf("the pin %+v, want %d", pin, version)
		}
	}

	done := pins.beginRead(repoId, refId)
	defer done()
	if standing, _, err := raise(walk(ask(), 0, 2, nil)); err != nil || standing != evsPinAbove {
		t.Fatalf("the first raise: %d %v", standing, err)
	}
	pinned(2)
	asked := ask()
	if standing, _, err := raise(page(asked, 0, 1, nil)); err != nil || standing != evsPinPassed {
		t.Errorf("a page below the pin it asked at: %d %v", standing, err)
	}
	pinned(2)
	if standing, _, err := raise(page(asked, 2, 4, nil)); err != nil || standing != evsPinAbove {
		t.Errorf("a page past the pin: %d %v", standing, err)
	}
	pinned(4)
	if _, mine, err := raise(page(asked, 2, 3, map[uint64][sha256.Size]byte{3: other})); !errors.Is(err, ErrEvsPinFork) || mine.Version != 3 || mine.Chain != chains[3] {
		t.Errorf("a page on another chain than a kept one: %+v %v", mine, err)
	}
	if standing, _, err := raise(walk(asked, 2, 3, nil)); err != nil || standing != evsPinPassed {
		t.Errorf("a head the page walked over: %d %v", standing, err)
	}
	pinned(4)
	// from the reader's own state at 6, which nothing the store holds places: raised as Raise raises
	if standing, _, err := raise(walk(ask(), 6, 7, nil)); err != nil || standing != evsPinAbove {
		t.Fatalf("an own start above the pin: %d %v", standing, err)
	}
	pinned(7)
	if standing, _, err := raise(walk(asked, 2, 3, nil)); err != nil || standing != evsPinStale {
		t.Errorf("a head below the history an own start moved the pin off: %d %v", standing, err)
	}
	// an own start the store holds is placed, its chains kept beside those it walked
	if standing, _, err := raise(walk(ask(), 7, 8, nil)); err != nil || standing != evsPinAbove {
		t.Fatalf("an own start at the pin: %d %v", standing, err)
	}
	if standing, _, err := raise(walk(asked, 6, 7, nil)); err != nil || standing != evsPinPassed {
		t.Errorf("a head an own start's walk kept: %d %v", standing, err)
	}
	pinned(8)

	// a paged walk's trail from the pin its read asked at: below it the trail keeps nothing, then C at each version
	trailAsk := ask()
	trail := newEvsWalkTrail(trailAsk)
	trail.start(0, chains[0])
	statementsTo := func(from uint64, through uint64, swapped map[uint64][sha256.Size]byte) []*EvsVerifiedStatement {
		statements := []*EvsVerifiedStatement{}
		for at := from; at <= through; at += 1 {
			chain := chains[at]
			if swappedChain, ok := swapped[at]; ok {
				chain = swappedChain
			}
			statements = append(statements, &EvsVerifiedStatement{Version: at, Chain: chain})
		}
		return statements
	}
	trail.add(statementsTo(1, 5, nil))
	trail.add(statementsTo(6, 9, nil))
	trailed := trail.head(&EvsVerifiedHead{RepoId: repoId, RefId: refId, Head: &protocol.EvsHeadSummary{}, Version: 9, Chain: chains[9], ask: trailAsk})
	if trailed.FromVersion != 8 || trailed.fromChain != chains[8] || len(trailed.walkChains) != 1 || trailed.walkChains[0] != chains[9] {
		t.Fatalf("the trail from 8: %d %d", trailed.FromVersion, len(trailed.walkChains))
	}
	if standing, _, err := raise(trailed); err != nil || standing != evsPinAbove {
		t.Fatalf("a trail's raise: %d %v", standing, err)
	}
	pinned(9)
	// a trail that crosses the pin on another chain is a fork, though its walk kept no statement
	forkedAsk := &evsPinAsk{pin: &EvsPin{RepoId: repoId, RefId: refId, Version: 2, Chain: chains[2]}, reseeds: trailAsk.reseeds}
	forked := newEvsWalkTrail(forkedAsk)
	forked.start(0, chains[0])
	forked.add(statementsTo(1, 9, map[uint64][sha256.Size]byte{8: other}))
	forkedHead := forked.head(&EvsVerifiedHead{RepoId: repoId, RefId: refId, Head: &protocol.EvsHeadSummary{}, Version: 9, Chain: chains[9], ask: forkedAsk})
	if _, mine, err := raise(forkedHead); !errors.Is(err, ErrEvsPinFork) || mine.Version != 8 {
		t.Errorf("a trail on another chain: %+v %v", mine, err)
	}
}

// The storage status of the world's main ref, off the test's goroutine: pinnedHead's read, a walk of the whole history
// from C_0, and the pin raised with it (verifiedHistory).
func evsTestStorageStatusOf(reader *evsTestClient, world *evsTestWorld) chan error {
	statuses := make(chan error, 1)
	go func() {
		_, err := reader.client.Repo(world.repoId).StorageStatus(context.Background(), nil)
		statuses <- err
	}()
	return statuses
}

// Pins the world's main ref's head as reader reads it alone, as another call of the client does.
func evsTestReadHeadAlone(t *testing.T, reader *evsTestClient, world *evsTestWorld) {
	t.Helper()
	if _, err := reader.client.Repo(world.repoId).readHeadAlone(context.Background(), world.refId, true); err != nil {
		t.Fatal(err)
	}
}

// GET .../log, a walk's page of statements.
func evsTestIsLog(request *http.Request) bool {
	return request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/log")
}

// pinnedHead's head stands once its whole history is walked, with no alarm, though another read of the same client
// pinned a newer head while the walk was in flight: that read's raise walked over it. Before the change the walk's
// raise was held to the live pin and refused as a regression with head_alarm (ErrEvsPinLower).
func TestEvsPinnedHeadAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	evsTestReadHeadAlone(t, reader, world)
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	held := hold.arm(evsTestIsLog, false)
	t.Cleanup(held.let)
	statuses := evsTestStorageStatusOf(reader, world)
	<-held.held
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	evsTestReadHeadAlone(t, reader, world)
	held.let()
	if err := <-statuses; err != nil {
		t.Fatalf("the held status: %v", err)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if _, chain := world.head(); pin.Version != 3 || pin.Chain != chain {
		t.Errorf("the pin %d", pin.Version)
	}
}

// pinnedHead's head on one side of a fork, walked whole, while another read of the same client pinned the other side
// past it: its walk holds another chain at a version that raise walked, so it is refused as a fork with head_alarm,
// both RefHeads as evidence, and the pin stays on the side it was raised on.
func TestEvsPinnedHeadOnAnotherChainThanARaiseWalkedIsAFork(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	route := &evsTestWorldRoute{world: world}
	hold := &evsTestHold{handler: route}
	reader := evsTestOverlapReader(t, world, hold)
	evsTestReadHeadAlone(t, reader, world)
	fork := evsTestForkWorld(t, world)
	world.push(&evsTestChange{path: "b.txt", content: []byte("one side")})
	fork.push(&evsTestChange{path: "b.txt", content: []byte("the other side")})
	fork.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	held := hold.arm(evsTestIsLog, false)
	t.Cleanup(held.let)
	statuses := evsTestStorageStatusOf(reader, world)
	<-held.held
	route.to(fork)
	evsTestReadHeadAlone(t, reader, fork)
	// the held read walks the side it was answered on
	route.to(world)
	held.let()
	if err := <-statuses; !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("the held status: %v", err)
	}
	forks := reader.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 1 || forks[0].HeadAlarm != SidecarHeadAlarmFork {
		t.Fatalf("fork alarms %v", forks)
	}
	mine, served := &protocol.RefHead{}, &protocol.RefHead{}
	if proto.Unmarshal(forks[0].Evidence[0], mine) != nil || proto.Unmarshal(forks[0].Evidence[1], served) != nil {
		t.Fatal("the evidence does not parse")
	}
	if mine.GetVersion() != 2 || !bytes.Equal(mine.GetChain(), fork.commits[1].chain[:]) ||
		served.GetVersion() != 2 || !bytes.Equal(served.GetChain(), world.commits[1].chain[:]) {
		t.Errorf("evidence %v %v", mine, served)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 3 || pin.Chain != fork.commits[2].chain {
		t.Errorf("the pin moved: %d", pin.Version)
	}
}

// pinnedHead's head below the pin its read asked at is a regression, alarmed as a fork with the pin asked at as its
// evidence, whatever the walk holds.
func TestEvsPinnedHeadBelowThePinItAskedAtIsARegression(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("two")})
	reader := world.reader(t, evsTestId("reader"))
	evsTestReadHeadAlone(t, reader, world)
	first := world.commits[0].chain
	world.stateLock.Lock()
	world.headOverride = &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 1, Chain: first[:], PathEpoch: &protocol.EvsPathEpoch{Current: 1}}
	world.stateLock.Unlock()
	if err := <-evsTestStorageStatusOf(reader, world); !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("the regressed status: %v", err)
	}
	forks := reader.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 1 || forks[0].HeadAlarm != SidecarHeadAlarmFork {
		t.Fatalf("fork alarms %v", forks)
	}
	mine := &protocol.RefHead{}
	if err := proto.Unmarshal(forks[0].Evidence[0], mine); err != nil || mine.GetVersion() != 2 {
		t.Errorf("evidence %v", mine)
	}
}

// A git-mode export exports the head it read, its tip and versions, with no alarm, though another read of the same
// client pinned a newer head while the export walked: the walk, read a page at a time, is judged by its trail from the
// pin its read asked at, which the other read's raise walked over. Before the change the export's raise was held to
// the live pin and refused as a regression with head_alarm.
func TestEvsExportGitModeAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newEvsTestWorld(t)
	first := world.pushGit(nil, &evsTestGitCommit{files: map[string][]byte{"README": []byte("hello\n")}})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	evsTestReadHeadAlone(t, reader, world)
	second := world.pushGit(&first, &evsTestGitCommit{files: map[string][]byte{"src/main.go": []byte("package main\n")}})
	held := hold.arm(evsTestIsLog, false)
	t.Cleanup(held.let)
	type exported struct {
		result *EvsExportResult
		err    error
	}
	exports := make(chan exported, 1)
	dir := filepath.Join(t.TempDir(), "export.git")
	go func() {
		result, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir})
		exports <- exported{result: result, err: err}
	}()
	<-held.held
	world.pushGit(&second, &evsTestGitCommit{files: map[string][]byte{"docs/a.md": []byte("# a\n")}})
	evsTestReadHeadAlone(t, reader, world)
	held.let()
	export := <-exports
	if export.err != nil {
		t.Fatalf("the held export: %v", export.err)
	}
	if len(export.result.Refs) != 1 || export.result.Refs[0].Tip != second || export.result.Refs[0].Versions != 2 {
		t.Fatalf("exported %+v, want tip %s at 2", export.result.Refs, second)
	}
	evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 3 {
		t.Errorf("the pin %d", pin.Version)
	}
}

// A device of the publisher's world whose requests go to handler, as newEvsTestDevice's go to the world.
func newEvsTestDeviceThrough(t *testing.T, publisher *evsTestPublisher, name string, handler http.Handler) *evsTestDevice {
	t.Helper()
	world := publisher.writer.world
	test := evsTestReaderThrough(t, world, handler, newEvsTestStore(t), world.gkm, evsTestId(name))
	mounts, err := NewEvsMounts(test.client, t.TempDir(), evsTestGitRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	mount, err := mounts.Add(context.Background(), world.repoId, &EvsMountArgs{AgentLabel: name})
	if err != nil {
		t.Fatal(err)
	}
	return &evsTestDevice{t: t, publisher: publisher, test: test, mounts: mounts, mount: mount, engine: mount.Sync()}
}

// The sync engine's replay applies the head it read, with no alarm, though another read of the same client pinned a
// newer one while the replay walked, and leaves the pin where the other read raised it; a later replay takes the newer
// head.
func TestEvsLocalSyncReplayAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"README": "hello\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	world := publisher.writer.world
	hold := &evsTestHold{handler: world}
	device := newEvsTestDeviceThrough(t, publisher, "device b", hold)
	device.replay("main")
	c2 := publisher.commit(map[string]string{"README": "hello\n", "plan.md": "plan\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	mainId := publisher.ref("main").refId
	held := hold.arm(evsTestIsLog, false)
	t.Cleanup(held.let)
	replays := make(chan error, 1)
	go func() { replays <- device.engine.Replay(context.Background(), mainId) }()
	<-held.held
	c3 := publisher.commit(map[string]string{"plan.md": "plan two\n"}, c2)
	if _, err := publisher.publish("main", &c3); err != nil {
		t.Fatal(err)
	}
	evsTestReadHeadAlone(t, device.test, world)
	held.let()
	if err := <-replays; err != nil {
		t.Fatalf("the held replay: %v", err)
	}
	if ref := device.ref("main"); ref.Version != 2 || !evsOidEqual(ref.Tip, &c2) {
		t.Fatalf("the record %+v", ref)
	}
	if alarms := append(device.alarms(), device.test.eventsOf(SidecarEventHeadAlarm)...); len(alarms) != 0 {
		t.Fatalf("alarms %v", alarms)
	}
	if pin, _, _ := device.test.client.pins.Pin(world.repoId, mainId); pin.Version != 3 {
		t.Errorf("the pin %d", pin.Version)
	}
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c3 {
		t.Fatalf("main is %v", local)
	}
}

// The sync engine's replay whose walk meets, at a version another read of the same client raised the pin over while
// the replay walked, another chain than that raise walked is a fork, alarmed with head_alarm and both RefHeads, and
// applies nothing of it. Before the change the replay skipped its raise once the pin stood past its head, and took
// the other side's history unjudged.
func TestEvsLocalSyncReplayOnAnotherChainThanARaiseWalkedIsAFork(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"README": "hello\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	world := publisher.writer.world
	hold := &evsTestHold{handler: world}
	device := newEvsTestDeviceThrough(t, publisher, "device b", hold)
	device.replay("main")
	c2 := publisher.commit(map[string]string{"README": "hello\n", "plan.md": "plan\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	mainId := publisher.ref("main").refId
	held := hold.arm(evsTestIsLog, false)
	t.Cleanup(held.let)
	replays := make(chan error, 1)
	go func() { replays <- device.engine.Replay(context.Background(), mainId) }()
	<-held.held
	// another read of the client raises the pin over the other side of a fork, its walk from the pin the replay asked at
	pins := device.test.client.pins
	asked, err := pins.ask(world.repoId, mainId)
	if err != nil {
		t.Fatal(err)
	}
	otherTwo := EvsChainNext(asked.pin.Chain, evsTestId("the other push 2"), sha256.Sum256([]byte("the other statement 2")))
	otherThree := EvsChainNext(otherTwo, evsTestId("the other push 3"), sha256.Sum256([]byte("the other statement 3")))
	raised := &EvsVerifiedHead{
		RepoId: world.repoId, RefId: mainId, Head: &protocol.EvsHeadSummary{}, Version: 3, Chain: otherThree, FromVersion: 1,
		Statements: []*EvsVerifiedStatement{{Version: 2, Chain: otherTwo}, {Version: 3, Chain: otherThree}}, ask: asked, fromChain: asked.pin.Chain,
	}
	if standing, _, err := pins.raiseRead(&EvsPin{RepoId: world.repoId, RefId: mainId, Version: 3, Chain: otherThree}, raised); err != nil || standing != evsPinAbove {
		t.Fatalf("the other side's raise: %d %v", standing, err)
	}
	held.let()
	if err := <-replays; !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("the held replay: %v", err)
	}
	forks := device.test.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 1 || forks[0].HeadAlarm != SidecarHeadAlarmFork {
		t.Fatalf("fork alarms %v", forks)
	}
	mine := &protocol.RefHead{}
	if err := proto.Unmarshal(forks[0].Evidence[0], mine); err != nil || mine.GetVersion() != 2 || !bytes.Equal(mine.GetChain(), otherTwo[:]) {
		t.Errorf("evidence %v", mine)
	}
	if ref := device.ref("main"); ref.Version != 1 {
		t.Errorf("the record %+v", ref)
	}
}

// The sync engine's replay of a head below the pin its read asked at is a regression, alarmed as a fork, and applies
// nothing.
func TestEvsLocalSyncReplayBelowThePinItAskedAtIsARegression(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"README": "hello\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	c2 := publisher.commit(map[string]string{"README": "hello two\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	world := publisher.writer.world
	device := newEvsTestDeviceThrough(t, publisher, "device b", world)
	mainId := publisher.ref("main").refId
	evsTestReadHeadAlone(t, device.test, world)
	first := world.commits[0].chain
	world.stateLock.Lock()
	world.headOverride = proto.Clone(world.headSummaryWithLock()).(*protocol.EvsHeadSummary)
	world.headOverride.Version, world.headOverride.Chain = 1, first[:]
	world.stateLock.Unlock()
	if err := device.engine.Replay(context.Background(), mainId); !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("the regressed replay: %v", err)
	}
	forks := device.test.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 1 || forks[0].HeadAlarm != SidecarHeadAlarmFork {
		t.Fatalf("fork alarms %v", forks)
	}
	if ref := device.ref("main"); ref.Version != 0 {
		t.Errorf("the record %+v", ref)
	}
}

// GET .../refs, the listing a mirror's sync reads every head from.
func evsTestIsRefs(request *http.Request) bool {
	return request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/refs")
}

// A mirror's sync whose listing evs answered before another read of the same client pinned a newer head raises no
// alarm: the head the listing gave, which nothing the pin store held then placed, is synced again from a fresh
// listing, and the mirror and the pin stand at the newer head.
func TestEvsMirrorSyncAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	evsTestReadHeadAlone(t, reader, world)
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	mirror, err := NewEvsMirror(reader.client, world.repoId, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := hold.arm(evsTestIsRefs, false)
	t.Cleanup(held.let)
	syncs := make(chan error, 1)
	go func() {
		_, err := mirror.Sync(context.Background())
		syncs <- err
	}()
	<-held.held
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	evsTestReadHeadAlone(t, reader, world)
	held.let()
	if err := <-syncs; err != nil {
		t.Fatalf("the held sync: %v", err)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	version, chain := world.head()
	if ref, ok, err := mirror.store.Ref(world.refId); err != nil || !ok || ref.Version != version || ref.Chain != chain {
		t.Errorf("the mirror holds %+v %v %v", ref, ok, err)
	}
	if pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId); pin.Version != version {
		t.Errorf("the pin %d", pin.Version)
	}
}

// A mirror's sync whose listing gave one side of a fork while another read of the same client pinned the other side
// past it is refused as a fork with head_alarm, the listing read again giving a head below the pin it asked at, and
// the pin stays on the side it was raised on.
func TestEvsMirrorSyncOnAnotherChainThanARaiseIsAFork(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	route := &evsTestWorldRoute{world: world}
	hold := &evsTestHold{handler: route}
	reader := evsTestOverlapReader(t, world, hold)
	evsTestReadHeadAlone(t, reader, world)
	fork := evsTestForkWorld(t, world)
	world.push(&evsTestChange{path: "b.txt", content: []byte("one side")})
	fork.push(&evsTestChange{path: "b.txt", content: []byte("the other side")})
	fork.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	mirror, err := NewEvsMirror(reader.client, world.repoId, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := hold.arm(evsTestIsRefs, false)
	t.Cleanup(held.let)
	syncs := make(chan error, 1)
	go func() {
		_, err := mirror.Sync(context.Background())
		syncs <- err
	}()
	<-held.held
	route.to(fork)
	evsTestReadHeadAlone(t, reader, fork)
	route.to(world)
	held.let()
	if err := <-syncs; !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("the held sync: %v", err)
	}
	forks := reader.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 1 || forks[0].HeadAlarm != SidecarHeadAlarmFork {
		t.Fatalf("fork alarms %v", forks)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 3 || pin.Chain != fork.commits[2].chain {
		t.Errorf("the pin moved: %d", pin.Version)
	}
}
