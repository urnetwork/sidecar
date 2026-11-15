//go:build !ios_extension && !sidecar_http

// Reach receipts for forwards and routes (bridge_reach.go): a device role's reach event reaches RecordReach.Note with
// its grant and its peer, a share's with its source network beside the peer; the grant's owner, approver and action
// and a forward's model manifest ride where the composer gives them; events of one (grant, peer) coalesce into one
// receipt holding ids and counts alone; an event that is no note and a note the record refuses are counted and hold
// nothing; and with no record the component takes no events, so they wait in the device role.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A device role that reports reach: the component test's sink, with the callbacks a bridge keeps. report calls them
// on the test's goroutine, where a bridge calls them on its reach goroutine.
type testBridgeReachSink struct {
	*testBridgeSink

	reachLock      sync.Mutex
	reachCallbacks map[int]BridgeReachFunction
	nextCallbackId int
}

var _ BridgeReachSource = (*testBridgeReachSink)(nil)

func newTestBridgeReachSink(world *testBridgeComponentWorld) *testBridgeReachSink {
	return &testBridgeReachSink{testBridgeSink: world.sink, reachCallbacks: map[int]BridgeReachFunction{}}
}

func (self *testBridgeReachSink) AddReachCallback(callback BridgeReachFunction) func() {
	self.reachLock.Lock()
	defer self.reachLock.Unlock()
	callbackId := self.nextCallbackId
	self.nextCallbackId += 1
	self.reachCallbacks[callbackId] = callback
	return func() {
		self.reachLock.Lock()
		defer self.reachLock.Unlock()
		delete(self.reachCallbacks, callbackId)
	}
}

func (self *testBridgeReachSink) callbackCount() int {
	self.reachLock.Lock()
	defer self.reachLock.Unlock()
	return len(self.reachCallbacks)
}

// Hands event to each callback, and answers how many took it.
func (self *testBridgeReachSink) report(event *BridgeReachEvent) int {
	callbacks := func() []BridgeReachFunction {
		self.reachLock.Lock()
		defer self.reachLock.Unlock()
		callbacks := []BridgeReachFunction{}
		for _, callback := range self.reachCallbacks {
			callbacks = append(callbacks, callback)
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback(event)
	}
	return len(callbacks)
}

// The notes a test's Reach took, and the error it answers each with.
type testBridgeReachNotes struct {
	stateLock sync.Mutex
	notes     []*RecordReachNote
	err       error
}

func (self *testBridgeReachNotes) note(note *RecordReachNote) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	self.notes = append(self.notes, note)
	return nil
}

func (self *testBridgeReachNotes) list() []*RecordReachNote {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*RecordReachNote(nil), self.notes...)
}

// A component over the world's client as world.component builds one, its args changed by edit, with a device role
// that reports reach set on it.
func (self *testBridgeComponentWorld) reachComponent(edit func(args *BridgeComponentArgs)) (*BridgeComponent, *testBridgeReachSink) {
	self.t.Helper()
	args := &BridgeComponentArgs{
		NetworkId: self.net.networkId,
		Identity: func() *SidecarIdentity {
			return &SidecarIdentity{NetworkId: self.net.networkId, SidecarId: self.host.sidecarId, IdentityPublicKey: self.host.publicKey()}
		},
		Config:   self.client,
		Heads:    self.heads,
		Rows:     self.net.source,
		Clock:    self.clock,
		Log:      NewNoopLogger(),
		Settings: self.settings,
		parts: &bridgeProviderParts{
			newNat: func(ctx context.Context, settings *connect.LocalUserNatSettings) *connect.LocalUserNat {
				return nil
			},
			newProvider: func(client *connect.Client, nat *connect.LocalUserNat) (func(), error) {
				return func() {}, nil
			},
		},
	}
	if edit != nil {
		edit(args)
	}
	component, err := NewBridgeComponent(context.Background(), args)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(component.Close)
	sink := newTestBridgeReachSink(self)
	if err := component.SetDeviceRole(sink); err != nil {
		self.t.Fatal(err)
	}
	return component, sink
}

// A grant id of 32 bytes.
func testBridgeReachGrantId(seed byte) []byte {
	sum := sha256.Sum256([]byte{0x6A, seed})
	return sum[:]
}

// A forward's event: three flows of one peer under one grant, to port 11434.
func testBridgeReachEvent(grantSeed byte, peer Id) *BridgeReachEvent {
	return &BridgeReachEvent{
		Kind:           RecordReachKindForward,
		GrantId:        testBridgeReachGrantId(grantSeed),
		Peer:           peer,
		TargetPort:     11434,
		PolicyVersion:  7,
		GrantEndMillis: testConfigStartMs + 3_600_000,
		StreamCount:    3,
	}
}

// A decided flow reaches RecordReach.Note with its grant and its peer: the forward's event is one note of that grant,
// naming the peer alone, with the flows it counts, the position it was judged at and the grant's end; a route's is a
// route.
func TestBridgeReachEventReachesTheRecordWithItsGrantAndPeer(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	notes := &testBridgeReachNotes{}
	component, sink := world.reachComponent(func(args *BridgeComponentArgs) {
		args.Reach = notes.note
	})
	peer := NewId()
	event := testBridgeReachEvent(1, peer)
	if took := sink.report(event); took != 1 {
		t.Fatalf("%d callbacks on the device role, want the component's one", took)
	}
	route := testBridgeReachEvent(2, peer)
	route.Kind = RecordReachKindRoute
	route.TargetPort = 0
	route.StreamCount = 1
	sink.report(route)

	list := notes.list()
	if len(list) != 2 {
		t.Fatalf("%d notes, want 2", len(list))
	}
	forward := list[0]
	if forward.Kind != RecordReachKindForward || !bytes.Equal(forward.GrantId, event.GrantId) ||
		len(forward.Peers) != 1 || !bytes.Equal(forward.Peers[0], peer.Bytes()) {
		t.Fatalf("the forward's note %+v", forward)
	}
	if forward.StreamCount != 3 || forward.ByteCount != 0 || forward.PolicyVersion != 7 || forward.GrantEndMillis != event.GrantEndMillis {
		t.Fatalf("the forward's counts %+v", forward)
	}
	if forward.Visitor.IsValid() || 0 < len(forward.Relays) || 0 < len(forward.Owner) || 0 < len(forward.Approver) ||
		0 < len(forward.ActionId) || forward.Manifest != nil {
		t.Fatalf("the forward's note names more than its grant and peer: %+v", forward)
	}
	if list[1].Kind != RecordReachKindRoute || !bytes.Equal(list[1].GrantId, route.GrantId) || list[1].StreamCount != 1 {
		t.Fatalf("the route's note %+v", list[1])
	}
	if status := component.Status(); status.ReachNotedCount != 4 || status.ReachRefusedCount != 0 {
		t.Fatalf("noted %d, refused %d", status.ReachNotedCount, status.ReachRefusedCount)
	}
	// the note holds its own copy of the grant id
	event.GrantId[0] ^= 0xFF
	if bytes.Equal(forward.GrantId, event.GrantId) {
		t.Fatal("the note shares the event's grant id")
	}
}

// A share's reach event names the source network (§17.9): its note's peer is the source sidecar with its network
// beside it, so it coalesces apart from the same id in this network.
func TestBridgeReachShareNamesTheSourceNetwork(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	notes := &testBridgeReachNotes{}
	_, sink := world.reachComponent(func(args *BridgeComponentArgs) {
		args.Reach = notes.note
	})
	peer := NewId()
	sourceNetworkId := NewId()
	share := testBridgeReachEvent(1, peer)
	share.SourceNetworkId = sourceNetworkId
	sink.report(share)
	sink.report(testBridgeReachEvent(1, peer))
	list := notes.list()
	if len(list) != 2 {
		t.Fatalf("%d notes, want 2", len(list))
	}
	if len(list[0].Peers) != 2 || !bytes.Equal(list[0].Peers[0], peer.Bytes()) || !bytes.Equal(list[0].Peers[1], sourceNetworkId.Bytes()) {
		t.Fatalf("the share's peers %x", list[0].Peers)
	}
	if len(list[1].Peers) != 1 || !bytes.Equal(list[1].Peers[0], peer.Bytes()) {
		t.Fatalf("this network's own peers %x", list[1].Peers)
	}
}

// The grant's owner, approver and action ride its receipts where the composer resolves the grant, and a forward to a
// port a model manifest is declared on names the manifest in force; a route names none, whatever its port field.
func TestBridgeReachNoteCarriesTheGrantAndTheManifest(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	notes := &testBridgeReachNotes{}
	owner := NewId()
	approver := NewId()
	actionId := testBridgeReachGrantId(0xA1)
	manifest := &RecordContentRef{LogId: NewId(), EntryId: NewId(), Commitment: sha256.Sum256([]byte("manifest"))}
	_, sink := world.reachComponent(func(args *BridgeComponentArgs) {
		args.Reach = notes.note
		args.ReachGrant = func(grantId []byte) *BridgeReachGrant {
			if !bytes.Equal(grantId, testBridgeReachGrantId(1)) {
				return nil
			}
			return &BridgeReachGrant{Owner: owner.Bytes(), Approver: approver.Bytes(), ActionId: actionId}
		}
		args.ReachManifest = func(port uint32) *RecordContentRef {
			if port != 11434 {
				return nil
			}
			return manifest
		}
	})
	peer := NewId()
	sink.report(testBridgeReachEvent(1, peer))
	unknown := testBridgeReachEvent(2, peer)
	unknown.TargetPort = 8080
	sink.report(unknown)
	route := testBridgeReachEvent(1, peer)
	route.Kind = RecordReachKindRoute
	sink.report(route)

	list := notes.list()
	if len(list) != 3 {
		t.Fatalf("%d notes, want 3", len(list))
	}
	if !bytes.Equal(list[0].Owner, owner.Bytes()) || !bytes.Equal(list[0].Approver, approver.Bytes()) ||
		!bytes.Equal(list[0].ActionId, actionId) || list[0].Manifest == nil || *list[0].Manifest != *manifest {
		t.Fatalf("the resolved grant's note %+v", list[0])
	}
	if 0 < len(list[1].Owner) || 0 < len(list[1].ActionId) || list[1].Manifest != nil {
		t.Fatalf("an unresolved grant's note %+v", list[1])
	}
	if list[2].Manifest != nil || !bytes.Equal(list[2].Owner, owner.Bytes()) {
		t.Fatalf("a route's note %+v", list[2])
	}
}

// A fake record writer: each draft appended.
type testBridgeReachWriter struct {
	stateLock sync.Mutex
	drafts    []*RecordDraft
}

func (self *testBridgeReachWriter) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	return []*RecordEntryRef{{EntryId: NewId()}}, nil
}

// Through the record's own RecordReach: the events of one (grant, peer) coalesce into one reach entry, another
// peer's and a share's into their own, and each receipt is exactly its grant, the judged position, the kind, the
// window, its peer ids and its counts, so no address, port or name is in a stored byte (I-13).
func TestBridgeReachCoalescesIntoReceiptsOfIdsAlone(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	writer := &testBridgeReachWriter{}
	reach := NewRecordReach(&RecordReachArgs{Writer: writer, Clock: newTestConfigClock()})
	defer reach.Close()
	component, sink := world.reachComponent(func(args *BridgeComponentArgs) {
		args.Reach = reach.Note
	})
	peer := NewId()
	otherPeer := NewId()
	sourceNetworkId := NewId()
	share := testBridgeReachEvent(1, peer)
	share.SourceNetworkId = sourceNetworkId
	share.StreamCount = 1
	for _, event := range []*BridgeReachEvent{
		testBridgeReachEvent(1, peer), testBridgeReachEvent(1, otherPeer), testBridgeReachEvent(1, peer), share,
	} {
		sink.report(event)
	}
	if stats := reach.Stats(); stats.OpenCount != 3 || stats.WrittenCount != 0 {
		t.Fatalf("%d receipts open and %d written before the window ends", stats.OpenCount, stats.WrittenCount)
	}
	reach.Flush()

	writer.stateLock.Lock()
	drafts := append([]*RecordDraft(nil), writer.drafts...)
	writer.stateLock.Unlock()
	if len(drafts) != 3 {
		t.Fatalf("%d reach entries, want 3", len(drafts))
	}
	grantId := testBridgeReachGrantId(1)
	wants := []*protocol.ReachReceipt{
		{GrantId: grantId, PolicyVersion: 7, Kind: uint32(RecordReachKindForward), Peers: [][]byte{peer.Bytes()}, StreamCount: 6},
		{GrantId: grantId, PolicyVersion: 7, Kind: uint32(RecordReachKindForward), Peers: [][]byte{otherPeer.Bytes()}, StreamCount: 3},
		{GrantId: grantId, PolicyVersion: 7, Kind: uint32(RecordReachKindForward), Peers: [][]byte{peer.Bytes(), sourceNetworkId.Bytes()}, StreamCount: 1},
	}
	for i, draft := range drafts {
		if draft.Kind != RecordKindReach || draft.Source != RecordSourceObserved || !bytes.Equal(draft.GrantId, grantId) {
			t.Fatalf("entry %d: kind %s, source %d, grant %x", i, draft.Kind, draft.Source, draft.GrantId)
		}
		receipt, ok := draft.Body.(*protocol.ReachReceipt)
		if !ok {
			t.Fatalf("entry %d: a body of %T", i, draft.Body)
		}
		// the window is the record's to set; everything else is the event's ids and counts
		wants[i].WindowStartMillis = receipt.GetWindowStartMillis()
		if !proto.Equal(receipt, wants[i]) {
			t.Errorf("entry %d: receipt %v, want %v", i, receipt, wants[i])
		}
	}
	if status := component.Status(); status.ReachNotedCount != 10 || status.ReachRefusedCount != 0 {
		t.Fatalf("noted %d, refused %d", status.ReachNotedCount, status.ReachRefusedCount)
	}
}

// An event that is no note is refused before the record sees it, and a note the record refuses is counted: neither
// is noted, and the next event still is.
func TestBridgeReachRefusalsAreCountedAndHoldNothing(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	notes := &testBridgeReachNotes{}
	component, sink := world.reachComponent(func(args *BridgeComponentArgs) {
		args.Reach = notes.note
	})
	peer := NewId()
	edits := []func(event *BridgeReachEvent){
		func(event *BridgeReachEvent) { event.Kind = RecordReachKindListen },
		func(event *BridgeReachEvent) { event.Kind = RecordReachKindUnspecified },
		func(event *BridgeReachEvent) { event.Kind = 9 },
		func(event *BridgeReachEvent) { event.GrantId = event.GrantId[:16] },
		func(event *BridgeReachEvent) { event.GrantId = nil },
		func(event *BridgeReachEvent) { event.Peer = Id{} },
		func(event *BridgeReachEvent) { event.GrantEndMillis = -1 },
	}
	for i, edit := range edits {
		event := testBridgeReachEvent(1, peer)
		edit(event)
		if note, err := BridgeReachNote(event); !errors.Is(err, ErrBridgeReachEventInvalid) || note != nil {
			t.Errorf("event %d: %v", i, err)
		}
		sink.report(event)
	}
	if note, err := BridgeReachNote(nil); !errors.Is(err, ErrBridgeReachEventInvalid) || note != nil {
		t.Errorf("no event: %v", err)
	}
	empty := testBridgeReachEvent(1, peer)
	empty.StreamCount = 0
	sink.report(empty)
	if list := notes.list(); len(list) != 0 {
		t.Fatalf("%d notes of refused events", len(list))
	}
	// seven events of three flows each, and the empty one counted once
	if status := component.Status(); status.ReachNotedCount != 0 || status.ReachRefusedCount != 22 {
		t.Fatalf("noted %d, refused %d", status.ReachNotedCount, status.ReachRefusedCount)
	}

	// the record refuses: counted, nothing noted
	func() {
		notes.stateLock.Lock()
		defer notes.stateLock.Unlock()
		notes.err = ErrRecordReachNoteInvalid
	}()
	sink.report(testBridgeReachEvent(1, peer))
	if status := component.Status(); status.ReachNotedCount != 0 || status.ReachRefusedCount != 25 {
		t.Fatalf("noted %d, refused %d", status.ReachNotedCount, status.ReachRefusedCount)
	}
	// and the next one it takes is noted
	func() {
		notes.stateLock.Lock()
		defer notes.stateLock.Unlock()
		notes.err = nil
	}()
	sink.report(testBridgeReachEvent(1, peer))
	if list := notes.list(); len(list) != 1 {
		t.Fatalf("%d notes, want 1", len(list))
	}
	if status := component.Status(); status.ReachNotedCount != 3 || status.ReachRefusedCount != 25 {
		t.Fatalf("noted %d, refused %d", status.ReachNotedCount, status.ReachRefusedCount)
	}
}

// With no record to note to, the component takes no reach events, so they wait in the device role; with one, its
// callback stands until the component closes; and a device role that reports no reach is still a device role.
func TestBridgeReachWaitsInTheDeviceRoleWithoutARecord(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	_, sink := world.reachComponent(nil)
	if count := sink.callbackCount(); count != 0 {
		t.Fatalf("%d reach callbacks with no record", count)
	}
	if took := sink.report(testBridgeReachEvent(1, NewId())); took != 0 {
		t.Fatalf("%d callbacks took an event with no record", took)
	}

	withRecord := newTestBridgeComponentWorld(t)
	notes := &testBridgeReachNotes{}
	component, recordSink := withRecord.reachComponent(func(args *BridgeComponentArgs) {
		args.Reach = notes.note
	})
	if count := recordSink.callbackCount(); count != 1 {
		t.Fatalf("%d reach callbacks, want 1", count)
	}
	component.Close()
	if count := recordSink.callbackCount(); count != 0 {
		t.Fatalf("%d reach callbacks after the close", count)
	}

	// the component test's plain sink reports no reach
	plain := newTestBridgeComponentWorld(t)
	plainComponent := plain.component()
	if err := plainComponent.SetDeviceRole(plain.sink); err != nil {
		t.Fatal(err)
	}
	if status := plainComponent.Status(); !status.DeviceRole || status.ReachNotedCount != 0 {
		t.Fatalf("status %+v", status)
	}
}
