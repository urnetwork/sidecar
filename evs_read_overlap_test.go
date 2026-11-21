// Overlapping calls on one EvsClient (the e2e-client-origins bug; evs_pin_store.go's header), on the stand-in evs: a
// read whose answer another call of the same client raised the pin past while it was in flight stands as read, with
// no alarm, where the client's own raise walked over its head, and is read again where nothing places it; a read on
// another chain than that raise walked is still a fork, one below the pin it asked at still a regression, and one
// served below the record it loaded still tampering. A hold at the stand-in fixes each order.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Holds evs's answer to the one request a test arms it for, as a slow link holds a reply that has left evs: the
// handler answers it in full, then the answer waits for the test's release. Armed before, it holds the request ahead
// of the handler, as one on its way to evs. Every other request passes.
type evsTestHold struct {
	handler http.Handler

	stateLock sync.Mutex
	armed     *evsTestHeld
}

// One armed hold: which request it takes, whether ahead of the handler, closed once that request is held, and let go
// by the test.
type evsTestHeld struct {
	takes   func(request *http.Request) bool
	before  bool
	held    chan struct{}
	release chan struct{}
	once    sync.Once
}

// Holds the next request takes names.
func (self *evsTestHold) arm(takes func(request *http.Request) bool, before bool) *evsTestHeld {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.armed = &evsTestHeld{takes: takes, before: before, held: make(chan struct{}), release: make(chan struct{})}
	return self.armed
}

// Lets the held request go on; safe to call more than once.
func (self *evsTestHeld) let() {
	self.once.Do(func() { close(self.release) })
}

func (self *evsTestHold) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	held := func() *evsTestHeld {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.armed == nil || !self.armed.takes(request) {
			return nil
		}
		held := self.armed
		self.armed = nil
		return held
	}()
	if held == nil {
		self.handler.ServeHTTP(writer, request)
		return
	}
	if held.before {
		close(held.held)
		<-held.release
		self.handler.ServeHTTP(writer, request)
		return
	}
	answer := httptest.NewRecorder()
	self.handler.ServeHTTP(answer, request)
	close(held.held)
	<-held.release
	for key, values := range answer.Header() {
		writer.Header()[key] = values
	}
	writer.WriteHeader(answer.Code)
	writer.Write(answer.Body.Bytes())
}

// A head read, POST .../read.
func evsTestIsRead(request *http.Request) bool {
	return request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/read")
}

// A push, POST .../push.
func evsTestIsPush(request *http.Request) bool {
	return request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push")
}

// Serves each request from whichever world the test routes to at the time: the two sides of a fork evs could show
// one reader.
type evsTestWorldRoute struct {
	stateLock sync.Mutex
	world     *evsTestWorld
}

func (self *evsTestWorldRoute) to(world *evsTestWorld) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.world = world
}

func (self *evsTestWorldRoute) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	world := func() *evsTestWorld {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.world
	}()
	world.ServeHTTP(writer, request)
}

// A second world holding world's history so far, under the same repo, ref, keys, signer and config, whose later pushes
// are its own: the other side of a fork.
func evsTestForkWorld(t testing.TB, world *evsTestWorld) *evsTestWorld {
	fork := newEvsTestWorld(t)
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	fork.repoId, fork.refId = world.repoId, world.refId
	fork.signer, fork.config, fork.gkm, fork.generation = world.signer, world.config, world.gkm, world.generation
	fork.commits = slices.Clone(world.commits)
	for path, state := range world.paths {
		copied := *state
		copied.versions = maps.Clone(state.versions)
		copied.removals = maps.Clone(state.removals)
		copied.rows = slices.Clone(state.rows)
		fork.paths[path] = &copied
	}
	maps.Copy(fork.segments, world.segments)
	return fork
}

// A reader of world whose requests go to handler, as world.reader's go to the world.
func evsTestOverlapReader(t *testing.T, world *evsTestWorld, handler http.Handler) *evsTestClient {
	t.Helper()
	return evsTestReaderThrough(t, world, handler, newEvsTestStore(t), world.gkm, evsTestId("reader"))
}

// What one ReadHead gave.
type evsTestReadResult struct {
	content []byte
	info    *EvsFileInfo
	err     error
}

// Reads path's newest version from the world's main ref as reader, off the test's goroutine.
func evsTestReadOf(reader *evsTestClient, world *evsTestWorld, path string) evsTestReadResult {
	out := &bytes.Buffer{}
	info, err := reader.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	return evsTestReadResult{content: out.Bytes(), info: info, err: err}
}

// The alarms a test client raised: head_alarm's and evs_alarm's.
func (self *evsTestClient) alarms() []SidecarEvent {
	return append(self.eventsOf(SidecarEventHeadAlarm), self.eventsOf(SidecarEventEvsAlarm)...)
}

// A read evs answered before another read of the same client pinned a newer head reaches the client after: judged
// against the pin it asked at and placed on the pinned history by the chain the other read's raise walked over its
// head, it stands as read, with no alarm, and the pin stays where the other read raised it. Before the fix it was
// refused as a fork with head_alarm: the e2e's TestT3WorldEvsReadAnsweredBeforeItsOwnWrite in one process.
func TestEvsReadAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	held := hold.arm(evsTestIsRead, false)
	t.Cleanup(held.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held.held
	// the same client reads past the held answer and pins the newer head, walking over the held answer's
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	if result := evsTestReadOf(reader, world, "c.txt"); result.err != nil || string(result.content) != "c" {
		t.Fatalf("the read beside it: %q %v", result.content, result.err)
	}
	held.let()
	result := <-reads
	if result.err != nil || string(result.content) != "asked" || result.info.HeadVersion != 2 {
		t.Fatalf("the held read: %q %+v %v", result.content, result.info, result.err)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if _, chain := world.head(); pin.Version != 3 || pin.Chain != chain {
		t.Errorf("the pin %d", pin.Version)
	}
	record, ok, _ := reader.client.pins.ReadRecord(world.repoId, world.refId, "a.txt")
	if !ok || record.EntryVersion != 1 || record.PinVersion != 2 {
		t.Errorf("the record %+v", record)
	}
}

// A read answered on one side of a fork while another read of the same client pinned the other side past it: the
// chain its walk holds at its head is not the one the other read's raise walked there, so it is refused as a fork with
// head_alarm, both RefHeads as evidence, and the pin stays on the side it was raised on.
func TestEvsOverlappingReadOnAnotherChainThanARaiseWalkedIsAFork(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	route := &evsTestWorldRoute{world: world}
	hold := &evsTestHold{handler: route}
	reader := evsTestOverlapReader(t, world, hold)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	fork := evsTestForkWorld(t, world)
	world.push(&evsTestChange{path: "b.txt", content: []byte("one side")})
	fork.push(&evsTestChange{path: "b.txt", content: []byte("the other side")})
	fork.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	held := hold.arm(evsTestIsRead, false)
	t.Cleanup(held.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held.held
	route.to(fork)
	if result := evsTestReadOf(reader, fork, "c.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	held.let()
	if result := <-reads; !errors.Is(result.err, ErrEvsHeadForked) || 0 < len(result.content) {
		t.Fatalf("the held read: %q %v", result.content, result.err)
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

// A head below the pin a read asked at is a regression whatever another read of the client raised meanwhile: refused
// as a fork with head_alarm, its evidence the pin it was asked at.
func TestEvsOverlappingReadBelowThePinItAskedAtIsARegression(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("two")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil || string(result.content) != "two" {
		t.Fatalf("%q %v", result.content, result.err)
	}
	first := world.commits[0].chain
	world.stateLock.Lock()
	world.headOverride = &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 1, Chain: first[:], PathEpoch: &protocol.EvsPathEpoch{Current: 1}}
	world.stateLock.Unlock()
	held := hold.arm(evsTestIsRead, false)
	t.Cleanup(held.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held.held
	world.stateLock.Lock()
	world.headOverride = nil
	world.stateLock.Unlock()
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	if result := evsTestReadOf(reader, world, "c.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	held.let()
	if result := <-reads; !errors.Is(result.err, ErrEvsHeadForked) {
		t.Fatalf("the regressed read: %v", result.err)
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

// A read whose head a raise that walked nothing passed while it was in flight, as a HeadCheck catch-up raises the pin
// (EvsClient.CatchUpRef), cannot be placed on the pinned history: a stale read, read again fresh from the pin then,
// with no alarm, which answers the path at the newer head.
func TestEvsOverlappingReadARaiseCannotPlaceIsReadAgain(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	held := hold.arm(evsTestIsRead, false)
	t.Cleanup(held.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held.held
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	version, chain := world.head()
	if err := reader.client.pins.Raise(&EvsPin{RepoId: world.repoId, RefId: world.refId, Version: version, Chain: chain}); err != nil {
		t.Fatal(err)
	}
	world.stateLock.Lock()
	readCount := world.reads
	world.stateLock.Unlock()
	held.let()
	result := <-reads
	if result.err != nil || string(result.content) != "asked" || result.info.HeadVersion != 3 {
		t.Fatalf("the read again: %q %+v %v", result.content, result.info, result.err)
	}
	world.stateLock.Lock()
	again := world.reads - readCount
	world.stateLock.Unlock()
	if again != 1 {
		t.Errorf("read again %d times", again)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A read served a version below the record it loaded is refused as tampering, with the tamper alarm, though another
// read of the client raised the pin past its head while it was in flight: the head stands on the pinned history, and
// the path is held to the record the read asked with.
func TestEvsOverlappingReadServedBelowItsRecordIsTampering(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("two")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil || string(result.content) != "two" {
		t.Fatalf("%q %v", result.content, result.err)
	}
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	world.stateLock.Lock()
	world.serveVersion["a.txt"] = 1
	world.stateLock.Unlock()
	held := hold.arm(evsTestIsRead, false)
	t.Cleanup(held.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held.held
	world.stateLock.Lock()
	world.serveVersion = map[string]uint64{}
	world.stateLock.Unlock()
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	if result := evsTestReadOf(reader, world, "c.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	held.let()
	if result := <-reads; !errors.Is(result.err, ErrEvsEntryRefused) || 0 < len(result.content) {
		t.Fatalf("the rolled-back read: %q %v", result.content, result.err)
	}
	if forks := reader.eventsOf(SidecarEventHeadAlarm); len(forks) != 0 {
		t.Errorf("head alarms %v", forks)
	}
	tampers := reader.eventsOf(SidecarEventEvsAlarm)
	if len(tampers) != 1 || tampers[0].EvsAlarm != SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", tampers)
	}
	record, _, _ := reader.client.pins.ReadRecord(world.repoId, world.refId, "a.txt")
	if record.EntryVersion != 2 {
		t.Errorf("the record %+v", record)
	}
}
