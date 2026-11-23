// What a device's reads of a ref are held to after its own push (evs_read.go's own pushes row) moves only on a head
// that verified. A fresh read that finds evs's cluster behind the push, as a site loss leaves it until its reseed,
// holds the device's reads to what the cluster holds, and before this change the head its reply carried was noted
// before anything judged it: a reply evs forged below the push lowered the floor though the read refused it, and
// later reads took heads below the device's own pushes with no fresh request. Now a fresh head is noted only once
// its walk and VerifyHead pass, never one past the catch-up budget, whose version is evs's word, and the floor falls
// once, to the first such head, never below what a verified head showed; freshEpochState holds a state at that floor
// rather than read it again at every call; and another device's reads are as they were.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The frames a forged reply carries before its end, made from the head the stand-in serves now.
type evsTestForge func(head *protocol.EvsHeadSummary) []*protocol.EvsReadFrame

// evs as a misbehaving one answers fresh reads, in front of the stand-in: armed, a fresh POST .../read is answered
// with the frames its forge makes, and never reaches the stand-in; every other request goes on to it. It keeps every
// read it saw: whether fresh, and whether it forged the answer.
type evsTestFreshForger struct {
	server http.Handler
	world  *evsTestWorld

	stateLock sync.Mutex
	forge     evsTestForge
	reads     []evsTestForgedRead
}

// One read the forger saw.
type evsTestForgedRead struct {
	fresh  bool
	forged bool
}

// Answers every fresh read from now on with forge's frames; nil lets them through again.
func (self *evsTestFreshForger) arm(forge evsTestForge) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forge = forge
}

// How many reads the forger has seen.
func (self *evsTestFreshForger) readCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.reads)
}

// The reads the forger saw from the start'th on, in order.
func (self *evsTestFreshForger) readsSince(start int) []evsTestForgedRead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.reads[start:])
}

func (self *evsTestFreshForger) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/read") {
		self.server.ServeHTTP(writer, request)
		return
	}
	body, err := io.ReadAll(request.Body)
	read := &protocol.EvsReadRequest{}
	if err != nil || proto.Unmarshal(body, read) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	forge := func() evsTestForge {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		var forge evsTestForge
		if read.GetFresh() {
			forge = self.forge
		}
		self.reads = append(self.reads, evsTestForgedRead{fresh: read.GetFresh(), forged: forge != nil})
		return forge
	}()
	if forge == nil {
		self.server.ServeHTTP(writer, request)
		return
	}
	frames := append(forge(self.world.headSummaryNow()), &protocol.EvsReadFrame{End: true})
	writer.WriteHeader(http.StatusOK)
	for _, frame := range frames {
		encoded, err := EncodeEvsReadFrame(frame)
		if err != nil {
			panic(err)
		}
		writer.Write(encoded)
	}
}

// How many of reads were fresh.
func evsTestForgedReadFreshCount(reads []evsTestForgedRead) int {
	fresh := 0
	for _, read := range reads {
		if read.fresh {
			fresh += 1
		}
	}
	return fresh
}

// The head summary the stand-in serves now, a copy the caller may change.
func (self *evsTestWorld) headSummaryNow() *protocol.EvsHeadSummary {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return proto.Clone(self.headSummaryWithLock()).(*protocol.EvsHeadSummary)
}

// A writer whose client reaches the stand-in through a forger of fresh reads, and the forger.
func newEvsTestWriterForged(t *testing.T) (*evsTestWriter, *evsTestFreshForger) {
	var forger *evsTestFreshForger
	writer := newEvsTestWriterThrough(t, func(server http.Handler) http.Handler {
		forger = &evsTestFreshForger{server: server, world: server.(*evsTestPushServer).world}
		return forger
	})
	return writer, forger
}

// Another sidecar of the world, as otherWriter makes, whose requests go through handler.
func (self *evsTestWriter) otherWriterOver(t *testing.T, label string, handler http.Handler) *evsTestWriter {
	t.Helper()
	other := self.otherWriter(t, label)
	other.test.client.args.Transport = &evsTestTransport{handler: handler}
	other.test.client.http.transport = wrapSidecarApiTransport(other.test.client.args.Transport)
	return other
}

// A writer whose push committed above what evs's cluster holds, as a site loss leaves it before its reseed: the ref
// seeded, its head read and pinned, and a push of the writer's noted at that head + 8. The head the cluster holds.
func newEvsTestWriterPastTheCluster(t *testing.T) (*evsTestWriter, *evsTestFreshForger, uint64) {
	writer, forger := newEvsTestWriterForged(t)
	writer.seed(t)
	if _, err := writer.repo.ReadHead(context.Background(), &EvsReadArgs{Path: "seed.txt"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	head, _ := writer.world.head()
	writer.test.client.epochs.noteCommitted(writer.world.repoId, writer.world.refId, head+8)
	return writer, forger, head
}

// head, as the stand-in serves it, moved to version under a chain no writer's statements make.
func evsTestForgedHead(head *protocol.EvsHeadSummary, version uint64) *protocol.EvsHeadSummary {
	chain := sha256.Sum256([]byte(fmt.Sprintf("a chain evs forged at %d", version)))
	head.Version, head.Chain, head.PushId = version, chain[:], evsTestId("a push evs forged").Bytes()
	return head
}

// A writer's statement with its signature changed.
func evsTestForgedSignature(t *testing.T, statement []byte) []byte {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(statement, signed); err != nil {
		t.Fatal(err)
	}
	signed.Signature = slices.Clone(signed.GetSignature())
	signed.Signature[0] ^= 1
	forged, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return forged
}

// A request the hold takes: a fresh read.
func evsTestIsFreshRead(request *http.Request) bool {
	if !evsTestIsRead(request) {
		return false
	}
	body, err := io.ReadAll(request.Body)
	request.Body = io.NopCloser(bytes.NewReader(body))
	read := &protocol.EvsReadRequest{}
	return err == nil && proto.Unmarshal(body, read) == nil && read.GetFresh()
}

// A fresh reply evs forged below the version the device's own push committed at is refused, and the floor under the
// device's reads stays at its push: a head at the pin's version on another chain, one past what evs holds that no
// statement chains to, and one whose statement's signature does not verify. The device's next read still goes fresh,
// and when evs answers it truly, the head that verifies lowers the floor to what the cluster holds. Before the fix the
// forged head was noted before it was judged, and the floor fell to the version it named.
func TestEvsOwnFloorStaysAtItsPushOnAForgedFreshReply(t *testing.T) {
	cases := []struct {
		name  string
		forge func(t *testing.T, writer *evsTestWriter, head uint64) evsTestForge
		err   error
		alarm SidecarEventKind
	}{
		{
			name: "a head at the pin's version on another chain",
			forge: func(t *testing.T, writer *evsTestWriter, head uint64) evsTestForge {
				return func(summary *protocol.EvsHeadSummary) []*protocol.EvsReadFrame {
					return []*protocol.EvsReadFrame{{Head: evsTestForgedHead(summary, head)}}
				}
			},
			err:   ErrEvsHeadForked,
			alarm: SidecarEventHeadAlarm,
		},
		{
			name: "a head past what evs holds that no statement chains to",
			forge: func(t *testing.T, writer *evsTestWriter, head uint64) evsTestForge {
				return func(summary *protocol.EvsHeadSummary) []*protocol.EvsReadFrame {
					return []*protocol.EvsReadFrame{{Head: evsTestForgedHead(summary, head+4)}}
				}
			},
			err: ErrEvsChainBroken,
		},
		{
			name: "a statement whose signature does not verify",
			forge: func(t *testing.T, writer *evsTestWriter, head uint64) evsTestForge {
				statement := func() []byte {
					writer.world.stateLock.Lock()
					defer writer.world.stateLock.Unlock()
					return writer.world.commits[head-1].statement
				}()
				forged := evsTestForgedSignature(t, statement)
				return func(summary *protocol.EvsHeadSummary) []*protocol.EvsReadFrame {
					return []*protocol.EvsReadFrame{
						{Head: evsTestForgedHead(summary, head+1)},
						{Statement: &protocol.EvsReadStatement{Version: head + 1, Statement: forged}},
					}
				}
			},
			err:   ErrEvsStatementRefused,
			alarm: SidecarEventEvsAlarm,
		},
	}
	for _, c := range cases {
		writer, forger, head := newEvsTestWriterPastTheCluster(t)
		ctx := context.Background()
		repoId, refId := writer.world.repoId, writer.world.refId
		epochs := writer.test.client.epochs
		forger.arm(c.forge(t, writer, head))
		reads := forger.readCount()
		out := &bytes.Buffer{}
		if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out); !errors.Is(err, c.err) || out.Len() != 0 {
			t.Fatalf("%s: the read: %q %v, not %v", c.name, out.String(), err, c.err)
		}
		if served := forger.readsSince(reads); len(served) != 2 || served[0].fresh || !served[1].forged {
			t.Errorf("%s: requests %+v, not one through the cache and then one fresh, forged", c.name, served)
		}
		if floor := epochs.ownFloor(repoId, refId); floor != head+8 {
			t.Errorf("%s: held to %d after the forged reply, not the push's %d", c.name, floor, head+8)
		}
		if alarms := writer.test.alarms(); (c.alarm == "" && len(alarms) != 0) || (c.alarm != "" && (len(alarms) != 1 || alarms[0].Kind != c.alarm)) {
			t.Errorf("%s: alarms %v", c.name, alarms)
		}
		// evs answers truly: the next read is still asked again fresh, and the head that verifies lowers the floor
		forger.arm(nil)
		reads = forger.readCount()
		out.Reset()
		if info, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out); err != nil || out.String() != "seed" || info.HeadVersion != head {
			t.Fatalf("%s: the true read: %q %+v %v", c.name, out.String(), info, err)
		}
		if served := forger.readsSince(reads); len(served) != 2 || served[0].fresh || !served[1].fresh || served[1].forged {
			t.Errorf("%s: the true read's requests %+v", c.name, served)
		}
		if floor := epochs.ownFloor(repoId, refId); floor != head {
			t.Errorf("%s: held to %d after the verified head, not %d", c.name, floor, head)
		}
	}
}

// A fresh reply whose statements pass the catch-up budget gives a head the read takes as evs's word, re-pinned with
// evs_gap (§11.9's budget row): its version was never walked to, so it lowers no floor, though the read stands. Before
// the fix it was noted before it was judged, and the floor fell to the version evs named.
func TestEvsOwnFloorStaysAtItsPushOnAFreshGapHead(t *testing.T) {
	writer, forger, head := newEvsTestWriterPastTheCluster(t)
	ctx := context.Background()
	repoId, refId := writer.world.repoId, writer.world.refId
	// a budget the forged reply's statement passes
	writer.test.client.settings.CatchUpByteCount = 4
	forger.arm(func(summary *protocol.EvsHeadSummary) []*protocol.EvsReadFrame {
		return []*protocol.EvsReadFrame{
			{Head: evsTestForgedHead(summary, head+4)},
			{Statement: &protocol.EvsReadStatement{Version: head + 1, Statement: bytes.Repeat([]byte{7}, 16)}},
		}
	})
	verified, err := writer.repo.readHeadAlone(ctx, refId, false)
	if err != nil || !verified.Gap || verified.Version != head+4 {
		t.Fatalf("the head past the budget: %+v %v", verified, err)
	}
	if gaps := writer.test.eventsOf(SidecarEventEvsGap); len(gaps) != 1 {
		t.Errorf("evs_gap %v", gaps)
	}
	if floor := writer.test.client.epochs.ownFloor(repoId, refId); floor != head+8 {
		t.Errorf("held to %d after a gap head, not the push's %d", floor, head+8)
	}
}

// A device whose push evs's cluster no longer holds: its first read goes fresh, and the head that verifies lowers the
// floor to what the cluster holds, once. Later reads, ReadHead, List and History, take that head as evs serves it,
// none of them fresh, and a fresh read the caller asks for finds it again and lowers nothing further.
func TestEvsOwnFloorFallsOnceToAVerifiedSiteLossHead(t *testing.T) {
	writer, forger, head := newEvsTestWriterPastTheCluster(t)
	ctx := context.Background()
	repoId, refId := writer.world.repoId, writer.world.refId
	epochs := writer.test.client.epochs
	reads := forger.readCount()
	out := &bytes.Buffer{}
	if info, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out); err != nil || out.String() != "seed" || info.HeadVersion != head {
		t.Fatalf("the read: %q %+v %v", out.String(), info, err)
	}
	if served := forger.readsSince(reads); len(served) != 2 || served[0].fresh || !served[1].fresh {
		t.Errorf("the read's requests %+v, not one and then one fresh", served)
	}
	if floor := epochs.ownFloor(repoId, refId); floor != head {
		t.Fatalf("held to %d after the verified site loss, not %d", floor, head)
	}
	reads = forger.readCount()
	out.Reset()
	if info, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out); err != nil || out.String() != "seed" || info.HeadVersion != head {
		t.Fatalf("a later read: %q %+v %v", out.String(), info, err)
	}
	if listing, err := writer.repo.List(ctx, &EvsReadArgs{Path: ""}); err != nil || evsTestListedNames(listing) != "seed.txt" || listing.HeadVersion != head {
		t.Fatalf("the root's listing: %+v %v", listing, err)
	}
	if history, err := writer.repo.History(ctx, &EvsReadArgs{Path: "seed.txt"}); err != nil || len(history.Versions) != 1 {
		t.Fatalf("the history: %+v %v", history, err)
	}
	if served := forger.readsSince(reads); len(served) == 0 || evsTestForgedReadFreshCount(served) != 0 {
		t.Errorf("the later reads' requests %+v", served)
	}
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt", Fresh: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if floor := epochs.ownFloor(repoId, refId); floor != head {
		t.Errorf("held to %d after a fresh read found the head again, not %d", floor, head)
	}
	if committed := epochs.committedVersion(repoId, refId); committed != head+8 {
		t.Errorf("committed %d", committed)
	}
	if alarms := writer.test.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A fresh read answered below this device's push, verified only after another read of the device pinned a head at
// the push, stands as read below the pin, and the floor stays at the push: no verified head lowers it below what
// another showed, the ref's pin among them. Before the fix the late answer was noted as found and the floor fell to
// it, below the head the device had verified.
func TestEvsOwnFloorNeverFallsBelowAHeadAnotherReadPinned(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	head, _ := world.head()
	epochs := reader.client.epochs
	// a push of this device committed at the next version, which evs's cluster has not shown it yet
	epochs.noteCommitted(world.repoId, world.refId, head+1)
	held := hold.arm(evsTestIsFreshRead, false)
	t.Cleanup(held.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	// the read is answered fresh at head, below the push, and held before the device sees the answer
	<-held.held
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil || result.info.HeadVersion != head+1 {
		t.Fatalf("the read beside it: %+v %v", result.info, result.err)
	}
	held.let()
	result := <-reads
	if result.err != nil || string(result.content) != "asked" || result.info.HeadVersion != head {
		t.Fatalf("the held read: %q %+v %v", result.content, result.info, result.err)
	}
	if floor := epochs.ownFloor(world.repoId, world.refId); floor != head+1 {
		t.Errorf("held to %d below the head another read pinned, not %d", floor, head+1)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// Another device's reads are as they were while this device's floor moves: during this device's site loss and evs's
// forged fresh replies the other device's ReadHead and List go through the cache, none of them fresh or forged, and it
// holds no floor; this device's verified site-loss head lowers only its own floor; the other device's own push holds
// its reads alone, and this device's next read takes that push as evs serves it, not fresh.
func TestEvsOwnFloorLeavesAnotherDevicesReadsAsTheyWere(t *testing.T) {
	writer, forger, head := newEvsTestWriterPastTheCluster(t)
	ctx := context.Background()
	repoId, refId := writer.world.repoId, writer.world.refId
	other := writer.otherWriterOver(t, "other device", forger)
	if _, err := other.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	forger.arm(func(summary *protocol.EvsHeadSummary) []*protocol.EvsReadFrame {
		return []*protocol.EvsReadFrame{{Head: evsTestForgedHead(summary, head+4)}}
	})
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, &bytes.Buffer{}); !errors.Is(err, ErrEvsChainBroken) {
		t.Fatalf("the writer's read of a forged reply: %v", err)
	}
	reads := forger.readCount()
	out := &bytes.Buffer{}
	if _, err := other.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out); err != nil || out.String() != "seed" {
		t.Fatalf("the other device's read: %q %v", out.String(), err)
	}
	if listing, err := other.repo.List(ctx, &EvsReadArgs{Path: ""}); err != nil || evsTestListedNames(listing) != "seed.txt" {
		t.Fatalf("the other device's listing: %+v %v", listing, err)
	}
	served := forger.readsSince(reads)
	if len(served) == 0 || evsTestForgedReadFreshCount(served) != 0 || slices.ContainsFunc(served, func(read evsTestForgedRead) bool { return read.forged }) {
		t.Errorf("the other device's requests %+v", served)
	}
	if floor := other.test.client.epochs.ownFloor(repoId, refId); floor != 0 {
		t.Errorf("the other device held to %d", floor)
	}
	forger.arm(nil)
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if floor := writer.test.client.epochs.ownFloor(repoId, refId); floor != head {
		t.Fatalf("the writer held to %d after its verified site loss, not %d", floor, head)
	}
	if floor := other.test.client.epochs.ownFloor(repoId, refId); floor != 0 {
		t.Errorf("the other device held to %d after the writer's site loss", floor)
	}
	written, err := other.write(t, "other.txt", []byte("other"))
	if err != nil || written.Version != head+1 {
		t.Fatalf("the other device's push: %+v %v", written, err)
	}
	if floor := other.test.client.epochs.ownFloor(repoId, refId); floor != head+1 {
		t.Errorf("the other device held to %d after its push, not %d", floor, head+1)
	}
	if floor := writer.test.client.epochs.ownFloor(repoId, refId); floor != head {
		t.Errorf("the writer held to %d after the other device's push, not %d", floor, head)
	}
	reads = forger.readCount()
	out.Reset()
	if info, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "other.txt"}, out); err != nil || out.String() != "other" || info.HeadVersion != head+1 {
		t.Fatalf("the writer's read of the other device's push: %q %+v %v", out.String(), info, err)
	}
	if served := forger.readsSince(reads); len(served) == 0 || evsTestForgedReadFreshCount(served) != 0 {
		t.Errorf("the writer's requests %+v", served)
	}
	if alarms := other.test.alarms(); len(alarms) != 0 {
		t.Errorf("the other device's alarms %v", alarms)
	}
}

// freshEpochState below the push reads the head again, fresh, once, and the head that verifies below it lowers the
// floor; at that floor a state verified within EpochFreshFor stands, read again only once it is older. Before the fix
// it compared the state with the version the push committed at, which the cluster stays behind, and every call read
// the head again, fresh.
func TestEvsFreshEpochStateStandsAtAVerifiedSiteLossFloor(t *testing.T) {
	writer, forger, head := newEvsTestWriterPastTheCluster(t)
	ctx := context.Background()
	repoId, refId := writer.world.repoId, writer.world.refId
	reads := forger.readCount()
	if state, err := writer.repo.freshEpochState(ctx, refId); err != nil || state.version != head {
		t.Fatalf("the state below the push: %+v %v", state, err)
	}
	if served := forger.readsSince(reads); len(served) != 1 || !served[0].fresh {
		t.Errorf("the state below the push read %+v, not once fresh", served)
	}
	if floor := writer.test.client.epochs.ownFloor(repoId, refId); floor != head {
		t.Fatalf("held to %d, not %d", floor, head)
	}
	reads = forger.readCount()
	for range 3 {
		if state, err := writer.repo.freshEpochState(ctx, refId); err != nil || state.version != head {
			t.Fatalf("the state at the floor: %+v %v", state, err)
		}
	}
	if served := forger.readsSince(reads); len(served) != 0 {
		t.Errorf("the state at the floor read %+v", served)
	}
	writer.test.clock.advance(writer.test.client.settings.EpochFreshFor + time.Second)
	reads = forger.readCount()
	if state, err := writer.repo.freshEpochState(ctx, refId); err != nil || state.version != head {
		t.Fatalf("the state past EpochFreshFor: %+v %v", state, err)
	}
	if served := forger.readsSince(reads); len(served) != 1 || !served[0].fresh {
		t.Errorf("the state past EpochFreshFor read %+v, not once fresh", served)
	}
}
