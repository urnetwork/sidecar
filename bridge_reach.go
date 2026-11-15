//go:build !ios_extension && !sidecar_http

// Reach receipts for forwards and routes (§16.8's reach row, §17.9; R-BRIDGE-6, R-BRIDGE-13, I-13; BRIDGE-M6-07): §16.8
// has the endpoint that enforces a grant write its reach receipt, and for a forward or a route that is the provider.
// The device role's hook reports each flow a granted row admitted (device/bridge_reach.go), off the packet path, and
// the sidecar role writes the receipts: the bridge component takes the device role's reach events and notes each
// with RecordReach.Note, which coalesces them into one receipt per (grant, peer) per ReachReceiptCoalesce. The root
// never imports device/, so the device role is a BridgeReachSource here, which cli/ adapts device.Bridge to as it does
// BridgeStateSink.
//
//	kinds       RECORD.md section 6.2's 3, a forward, and 4, a route; no other kind is noted from here
//	peer        the sealed source subject as the device role resolved it, an opaque id; on a share, the source
//	            network beside it (§17.9's isolation row), so a reader sees which network reached the target
//	counts      streams are the flows the hook decided; bytes are 0, since the hook decides a flow before its first
//	            byte and nothing here follows it after
//	relays      none: a provider knows no relay of the path that reached it
//	grant       the event carries the grant's id and its row's end; its owner, approver and action come from
//	            ReachGrant where the composer gives one, and stay empty where it gives none
//	manifest    a forward to a port a model manifest is declared on names the manifest in force (RECORD.md section
//	            12), through ReachManifest
//	waiting     with no Reach in its args the component takes no events, so they wait in the device role, in its
//	            bounded table, counted past it: a keyless role's notes wait for a sidecar role that writes a record
//
// An event that is no forward or route, names no grant or no peer, or counts nothing is refused and counted, and a note
// the record refuses is counted and logged, at the first and at each doubling of their count; neither holds a flow
// back, since the flow was decided before the event left the hook. A note names ids and counts alone, never an address, a prefix or a name (I-13).
//
// Not on the ios_extension leg: a VPN component forwards and writes no record (owner decision 197; DESIGN-DETAILS
// 4.7), and its events wait for its app's sidecar role.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

// A reach event that is no note: no forward or route, no grant, no peer, or no flow.
var ErrBridgeReachEventInvalid = errors.New("bridge reach event invalid")

// The flows one grant admitted from one peer, as the device role reports them: device.BridgeReachEvent's fields in
// the root's types.
type BridgeReachEvent struct {
	// RecordReachKindForward or RecordReachKindRoute.
	Kind RecordReachKind
	// The requested grant whose row admitted the flows: 32 bytes.
	GrantId []byte
	// The sealed source subject: the subject's sidecar, or at an sdk provider the client no subject binds.
	Peer Id
	// A share's source network; the zero id for a flow of this network's own.
	SourceNetworkId Id
	// A forward's port on this host, past its map; 0 for a route.
	TargetPort uint32
	// The log position of the state the hook judged the flows at.
	PolicyVersion uint64
	// When the grant's row stops admitting, Unix milliseconds, 0 for no end the rules name.
	GrantEndMillis int64
	// The flows decided.
	StreamCount uint64
}

// Takes a device role's reach events.
type BridgeReachFunction func(event *BridgeReachEvent)

// What a device role is beside BridgeStateSink where it reports reach: device.Bridge through cli/'s adapter. A sink
// that is none reports nothing, and no receipt is written for its flows.
type BridgeReachSource interface {
	// Calls callback with each event, on a goroutine of the device role's that no packet waits on, the events that
	// waited for a callback first; the returned function removes it.
	AddReachCallback(callback BridgeReachFunction) func()
}

// What a receipt names of a grant beside its id: RecordReachNote's fields for it.
type BridgeReachGrant struct {
	// The grant's owner and its approver, as ids; each empty where none.
	Owner    []byte
	Approver []byte
	// The O action that made the grant, 32 bytes, or empty.
	ActionId []byte
}

// The note an event is: its kind, grant and peer, a share's source network beside the peer, and its counts. A refused
// event answers ErrBridgeReachEventInvalid.
func BridgeReachNote(event *BridgeReachEvent) (*RecordReachNote, error) {
	switch {
	case event == nil:
		return nil, fmt.Errorf("%w: no event", ErrBridgeReachEventInvalid)
	case event.Kind != RecordReachKindForward && event.Kind != RecordReachKindRoute:
		return nil, fmt.Errorf("%w: kind %d is no forward or route", ErrBridgeReachEventInvalid, uint32(event.Kind))
	case len(event.GrantId) != sha256.Size:
		return nil, fmt.Errorf("%w: a grant id of %d bytes", ErrBridgeReachEventInvalid, len(event.GrantId))
	case event.Peer == (Id{}):
		return nil, fmt.Errorf("%w: no peer", ErrBridgeReachEventInvalid)
	case event.StreamCount == 0:
		return nil, fmt.Errorf("%w: no flow", ErrBridgeReachEventInvalid)
	case event.GrantEndMillis < 0:
		return nil, fmt.Errorf("%w: a grant ending before 1970", ErrBridgeReachEventInvalid)
	}
	peers := [][]byte{event.Peer.Bytes()}
	if event.SourceNetworkId != (Id{}) {
		peers = append(peers, event.SourceNetworkId.Bytes())
	}
	return &RecordReachNote{
		Kind:           event.Kind,
		GrantId:        append([]byte(nil), event.GrantId...),
		PolicyVersion:  event.PolicyVersion,
		Peers:          peers,
		StreamCount:    event.StreamCount,
		GrantEndMillis: event.GrantEndMillis,
	}, nil
}

// The component's reach state: its registration on the device role and what it noted.
type bridgeComponentReach struct {
	stateLock sync.Mutex
	// removes the component's callback from the device role; nil while none is set
	remove func()
	// flows noted to the record, and flows whose event or note was refused
	notedCount   uint64
	refusedCount uint64
	// refusals, an event each, which paces their log line
	refusalCount uint64
}

// Starts taking sink's reach events, once, where the component has a record to note them to and the sink reports
// any. With no Reach the events stay in the device role (the file's comment).
func (self *BridgeComponent) followReach(sink BridgeStateSink) {
	source, ok := sink.(BridgeReachSource)
	if !ok || self.args.Reach == nil {
		return
	}
	remove := source.AddReachCallback(self.noteReach)
	closed := func() bool {
		self.reach.stateLock.Lock()
		defer self.reach.stateLock.Unlock()
		if self.ctx.Err() != nil {
			return true
		}
		self.reach.remove = remove
		return false
	}()
	if closed {
		remove()
	}
}

// Stops taking the device role's reach events: the component's close.
func (self *BridgeComponent) stopReach() {
	remove := func() func() {
		self.reach.stateLock.Lock()
		defer self.reach.stateLock.Unlock()
		remove := self.reach.remove
		self.reach.remove = nil
		return remove
	}()
	if remove != nil {
		remove()
	}
}

// Notes one reach event to the record (the file's comment). On the device role's reach goroutine.
func (self *BridgeComponent) noteReach(event *BridgeReachEvent) {
	note, err := BridgeReachNote(event)
	if err == nil {
		if self.args.ReachGrant != nil {
			if grant := self.args.ReachGrant(note.GrantId); grant != nil {
				note.Owner = grant.Owner
				note.Approver = grant.Approver
				note.ActionId = grant.ActionId
			}
		}
		if self.args.ReachManifest != nil && event.Kind == RecordReachKindForward && event.TargetPort != 0 {
			note.Manifest = self.args.ReachManifest(event.TargetPort)
		}
		err = self.args.Reach(note)
	}
	streamCount := uint64(0)
	if event != nil {
		streamCount = event.StreamCount
	}
	refusalCount := func() uint64 {
		self.reach.stateLock.Lock()
		defer self.reach.stateLock.Unlock()
		if err == nil {
			self.reach.notedCount = recordReachSum(self.reach.notedCount, streamCount)
			return 0
		}
		// an event that counts no flow is still one refusal
		self.reach.refusedCount = recordReachSum(self.reach.refusedCount, max(streamCount, 1))
		self.reach.refusalCount = recordReachSum(self.reach.refusalCount, 1)
		return self.reach.refusalCount
	}()
	// the first refusal and then each doubling of their count, so a record that stays unavailable is said, not
	// repeated a line an event
	if err != nil && refusalCount&(refusalCount-1) == 0 {
		self.log.Warningf("[bridge]%s a reach receipt was refused, %d so far: %v", self.args.NetworkId, refusalCount, err)
	}
}

// The flows noted to the record and the flows whose event or note was refused, since the component started.
func (self *BridgeComponent) reachCounts() (notedCount uint64, refusedCount uint64) {
	self.reach.stateLock.Lock()
	defer self.reach.stateLock.Unlock()
	return self.reach.notedCount, self.reach.refusedCount
}
