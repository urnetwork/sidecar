//go:build !ios_extension

// RECORD-M6-02's reach receipts (§16.8's reach row, owner decision 25; R-MCP-7, I-13, X20), on every leg but
// ios_extension, whose VPN component forwards and writes no record (owner decision 197; DESIGN-DETAILS 4's note that the
// sidecar role writes BRIDGE-M6-07's receipts from what the component's status mirror counted): the endpoint
// enforcing a grant notes each act it lets through, and RecordReach coalesces those notes into one ReachReceipt per
// (grant, peer) per window, held in memory and written as a reach entry through RecordWriter.Append, whose routing
// (record_team.go) puts it in a personal network's author's vault and in a team network's team record.
//
//	who notes   the endpoint enforcing the grant: the listener for listens and publishes (§9's tickets, §13.7's front),
//	            the provider for forwards and routes (§17.9), §14.9's SmtpSender for sends and §15.7's ingest for
//	            received mail; Note names none of their types, so each calls it as it lands
//	window      ReachReceiptCoalesce long and aligned to the Unix epoch, so one time falls in the same window on every
//	            endpoint and a reader joins receipts by window (RECORD.md section 12's join row); window_start_millis
//	            is its start, and a note in a later window closes the receipt of an earlier one
//	flush       at the window's end, at the grant's end (the note's GrantEndMillis, or GrantEnded), and at Close, the
//	            process's exit; a timer on the record's clock runs the timed ones, and nothing waits on evs, since
//	            Append returns once the entry is journaled or spooled
//	bound       at most ReceiptCount receipts open; past it the one opened first flushes early and is never dropped;
//	            a note that changes a receipt's policy version, owner, approver or action, or whose relays would pass
//	            RelayCount, flushes that receipt early too and opens the next
//	peers       opaque ids alone (I-13): a sidecar's id, or a share's source sidecar with its network beside it; a
//	            public visitor's address comes in as Visitor and is keyed at once into VisitorPeer's hash under a key
//	            that lives only in memory and is drawn anew each VisitorKeyInterval, so no stored byte holds a
//	            visitor's address, and once an interval's key is gone no one can compute that interval's hashes again
//	relays      one string a relay or edge in the path, "<host> <ip> <operator>", each part a token with no space or
//	            control character and "-" where it is not known; a receipt names each relay once
//
// Safe for concurrent use. Note holds stateLock only over the map, so an endpoint's send path never waits on an append:
// appends run on the flush timer's goroutine, under appendLock and never stateLock, and in Note's own goroutine only
// once the receipts waiting for their append pass ReceiptCount, which bounds memory without dropping any. Locks:
// appendLock, then stateLock.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/urnetwork/sidecar/protocol"
)

// A relay part a receipt does not know, which the relay string carries in its place.
const recordReachRelayUnknown = "-"

// The family bytes a visitor's hash takes before its address, as tlsedge's record hash does.
const (
	recordReachVisitorFamilyIpv4 = 4
	recordReachVisitorFamilyIpv6 = 6
)

var (
	// A note the receipts cannot take: no grant, a kind §16.8 does not name, no peer or both forms of one, or a peer id
	// or relay outside its bounds. Nothing of it is kept.
	ErrRecordReachNoteInvalid = errors.New("record reach note invalid")
)

// The receipts' own bounds. RECORD.md section 18 names SidecarRecordSettings' fields, whose ReachReceiptCoalesce sets
// the window, so a bound that is these receipts' alone sits here.
type RecordReachSettings struct {
	// Receipts held open at once, one per (grant, peer) in its window: 4,096, a reading, since §16.8 names no bound.
	// Past it the receipt opened first flushes early; none is dropped. Non-positive holds none, so each note is
	// written alone.
	ReceiptCount int
	// Relays one receipt names: 16, a reading. A note whose relays would pass it flushes its receipt early and opens
	// the next; a note naming more on its own is refused. Non-positive refuses every note naming a relay.
	RelayCount int
	// Ids that together name one peer: 4, a reading (a sidecar, and a share's source network beside it). A note with
	// more is refused.
	PeerIdCount int
	// One peer id's bytes at most, and an owner's or an approver's: 64, past a sidecar's 16 and a hash's 32.
	PeerIdByteCount int
	// One relay part's bytes at most: 253, a DNS name's.
	RelayPartByteCount int
	// A public visitor's peer id: this many bytes of HMAC-SHA256, 16, as tlsedge's record hash (tls-3). At most 32.
	VisitorHashByteCount int
	// How long one visitor key serves, in steps from the Unix epoch, before the next is drawn and the old one is
	// forgotten: 24 h, a reading after tlsedge's daily key. Non-positive keeps one key for the process's life.
	VisitorKeyInterval time.Duration
}

// The defaults, a fresh value each call.
func DefaultRecordReachSettings() *RecordReachSettings {
	return &RecordReachSettings{
		ReceiptCount:         4096,
		RelayCount:           16,
		PeerIdCount:          4,
		PeerIdByteCount:      64,
		RelayPartByteCount:   253,
		VisitorHashByteCount: 16,
		VisitorKeyInterval:   24 * time.Hour,
	}
}

// One relay or edge of a path, as a receipt names it (§16.8's relays: host, IP and operator). The platform's own,
// never a visitor's.
type RecordReachRelay struct {
	// Its DNS name; "" for none known.
	Host string
	// Its address; the zero Addr for none known.
	Ip netip.Addr
	// Who runs it, a token; "" for none known.
	Operator string
}

// One act the endpoint enforcing a grant let through.
type RecordReachNote struct {
	Kind RecordReachKind
	// The grant the endpoint enforced: 32 bytes, ACL's AclGrantId.
	GrantId []byte
	// The policy version the endpoint judged the grant at.
	PolicyVersion uint64
	// The grant's owner and its approver, as ids; each empty where none.
	Owner    []byte
	Approver []byte
	// The O action that made the grant, §16.6's action_id of 32 bytes, which joins the entry to its approval (RECORD.md
	// section 4.4); empty for none.
	ActionId []byte
	// The peer, as opaque ids that together name it: a sidecar's id, or a share's source sidecar and its network
	// (§17.9). Never an address. Exactly one of Peers and Visitor.
	Peers [][]byte
	// A public visitor's address (§13.7), keyed at once into its peer id (VisitorPeer) and never kept (I-13).
	Visitor netip.Addr
	// What this note adds since the endpoint's last for this grant and peer.
	StreamCount uint64
	ByteCount   uint64
	// Each relay or edge the path crossed.
	Relays []RecordReachRelay
	// When the grant ends, Unix milliseconds, 0 for no end the endpoint knows: its receipt flushes then.
	GrantEndMillis int64
}

// What a RecordReach writes through.
type RecordReachArgs struct {
	// The record's writer: reach entries go through Append.
	Writer RecordWriter
	Clock  Clock
	// ReachReceiptCoalesce, the window.
	RecordSettings *SidecarRecordSettings
	// Nil takes DefaultRecordReachSettings.
	Settings *RecordReachSettings
	// crypto/rand's reader when nil: the visitor keys.
	Random io.Reader
	Log    Logger
}

// What the receipts did since they were made.
type RecordReachStats struct {
	// Receipts open now.
	OpenCount int
	// Receipts written.
	WrittenCount int
	// Receipts flushed before their window's or grant's end: past ReceiptCount, a changed attribute, or full relays.
	EarlyCount int
	// Receipts the writer refused, each logged: an append that fails is not retried.
	FailedCount int
}

// The coalescing key: one receipt per kind, grant and peer.
type recordReachKey struct {
	kind    RecordReachKind
	grantId [sha256.Size]byte
	// each peer id, length-prefixed, in the note's order
	peers string
}

// One receipt being coalesced.
type recordReachReceipt struct {
	key     recordReachKey
	receipt *protocol.ReachReceipt
	// the grant's id and the action's, as the entry's header carries them
	grantId  []byte
	actionId []byte
	// when the window ends, and the grant, Unix milliseconds; grant 0 for none
	windowEndMillis int64
	grantEndMillis  int64
	// the order receipts opened in, the oldest flushing first past ReceiptCount
	openedSeq uint64
}

// When the receipt flushes, Unix milliseconds: its window's end or its grant's, whichever comes first.
func (self *recordReachReceipt) dueMillis() int64 {
	if 0 < self.grantEndMillis && self.grantEndMillis < self.windowEndMillis {
		return self.grantEndMillis
	}
	return self.windowEndMillis
}

// The reach receipts of one record.
type RecordReach struct {
	writer         RecordWriter
	clock          Clock
	recordSettings *SidecarRecordSettings
	settings       *RecordReachSettings
	random         io.Reader
	log            Logger

	// one append pass at a time, so receipts reach the writer in the order they were flushed: never stateLock
	appendLock sync.Mutex

	stateLock   sync.Mutex
	keyReceipts map[recordReachKey]*recordReachReceipt
	// flushed and waiting for their append
	waitingReceipts []*recordReachReceipt
	openedSeq       uint64
	// the timer set for timerDueMillis, and its stop
	timerStop      func() bool
	timerDueMillis int64
	// the visitor key and the interval it serves, -1 before the first
	visitorKey      []byte
	visitorInterval int64
	closed          bool
	stats           RecordReachStats
}

// Receipts over args. Nothing runs until the first note.
func NewRecordReach(args *RecordReachArgs) *RecordReach {
	settings := args.Settings
	if settings == nil {
		settings = DefaultRecordReachSettings()
	}
	recordSettings := args.RecordSettings
	if recordSettings == nil {
		recordSettings = defaultSidecarRecordSettings()
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &RecordReach{
		writer:          args.Writer,
		clock:           clockOrReal(args.Clock),
		recordSettings:  recordSettings,
		settings:        settings,
		random:          random,
		log:             log,
		keyReceipts:     map[recordReachKey]*recordReachReceipt{},
		visitorInterval: -1,
	}
}

// The record's reach receipts, made at the first call on the record's writer, clock and settings, with
// DefaultRecordReachSettings.
func (self *SidecarRecord) Reach() *RecordReach {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reach, _ := self.reach.(*RecordReach)
	if reach == nil {
		reach = NewRecordReach(&RecordReachArgs{
			Writer:         self.writer,
			Clock:          self.writer.clock,
			RecordSettings: self.writer.settings,
			Random:         self.writer.random,
			Log:            self.writer.log,
		})
		self.reach = reach
	}
	return reach
}

// The record's reach receipts if a call has made them, else nil: what the component's close flushes.
func (self *SidecarRecord) reachIfMade() *RecordReach {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reach, _ := self.reach.(*RecordReach)
	return reach
}

// A public visitor's peer id (§13.7's keyed client_ip hash): HMAC-SHA256 of the address's family byte and bytes,
// under the visitor key of the interval now falls in, cut to VisitorHashByteCount; an IPv4-mapped IPv6 address is its
// IPv4 address. The key lives only in memory (see the file header).
func (self *RecordReach) VisitorPeer(addr netip.Addr) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.visitorPeerWithLock(addr, self.clock.Now())
}

// VisitorPeer's hash, with stateLock held.
func (self *RecordReach) visitorPeerWithLock(addr netip.Addr, now time.Time) ([]byte, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("%w: no visitor address", ErrRecordReachNoteInvalid)
	}
	byteCount := self.settings.VisitorHashByteCount
	if byteCount <= 0 || sha256.Size < byteCount {
		return nil, fmt.Errorf("%w: a visitor hash of %d bytes", ErrRecordReachNoteInvalid, byteCount)
	}
	interval := int64(0)
	if 0 < self.settings.VisitorKeyInterval {
		interval = now.UnixMilli() / self.settings.VisitorKeyInterval.Milliseconds()
	}
	if self.visitorKey == nil || interval != self.visitorInterval {
		key := make([]byte, sha256.Size)
		if _, err := io.ReadFull(self.random, key); err != nil {
			return nil, fmt.Errorf("record reach: a visitor key: %w", err)
		}
		testHookSecret("record_reach_visitor_key", key)
		clear(self.visitorKey)
		self.visitorKey = key
		self.visitorInterval = interval
	}
	addr = addr.Unmap()
	family := byte(recordReachVisitorFamilyIpv6)
	if addr.Is4() {
		family = recordReachVisitorFamilyIpv4
	}
	mac := hmac.New(sha256.New, self.visitorKey)
	mac.Write([]byte{family})
	mac.Write(addr.AsSlice())
	return mac.Sum(nil)[:byteCount], nil
}

// A relay part as the relay string carries it, "-" when not known, or false when it holds what a token may not.
func (self *RecordReach) relayPart(part string) (string, bool) {
	if part == "" {
		return recordReachRelayUnknown, true
	}
	if part == recordReachRelayUnknown || self.settings.RelayPartByteCount < len(part) {
		return "", false
	}
	for _, character := range part {
		if unicode.IsSpace(character) || unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return "", false
		}
	}
	return part, true
}

// A relay as one string, "<host> <ip> <operator>".
func (self *RecordReach) relayText(relay RecordReachRelay) (string, error) {
	ip := ""
	if relay.Ip.IsValid() {
		ip = relay.Ip.Unmap().String()
	}
	parts := []string{}
	for _, part := range []string{relay.Host, ip, relay.Operator} {
		text, ok := self.relayPart(part)
		if !ok {
			return "", fmt.Errorf("%w: a relay part that is no token", ErrRecordReachNoteInvalid)
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, " "), nil
}

// The note's key and relay strings, its peer ids resolved, or why it is refused. With stateLock held, for the
// visitor key.
func (self *RecordReach) checkWithLock(note *RecordReachNote, now time.Time) (recordReachKey, [][]byte, []string, error) {
	key := recordReachKey{}
	if note == nil {
		return key, nil, nil, fmt.Errorf("%w: no note", ErrRecordReachNoteInvalid)
	}
	key.kind = note.Kind
	switch {
	case !note.Kind.Known():
		return key, nil, nil, fmt.Errorf("%w: kind %d", ErrRecordReachNoteInvalid, uint32(note.Kind))
	case len(note.GrantId) != sha256.Size:
		return key, nil, nil, fmt.Errorf("%w: a grant id of %d bytes", ErrRecordReachNoteInvalid, len(note.GrantId))
	case len(note.ActionId) != 0 && len(note.ActionId) != sha256.Size:
		return key, nil, nil, fmt.Errorf("%w: an action id of %d bytes", ErrRecordReachNoteInvalid, len(note.ActionId))
	case (len(note.Peers) == 0) == !note.Visitor.IsValid():
		return key, nil, nil, fmt.Errorf("%w: a note names its peer by ids or by a visitor's address, exactly one", ErrRecordReachNoteInvalid)
	case self.settings.PeerIdCount < len(note.Peers):
		return key, nil, nil, fmt.Errorf("%w: %d peer ids", ErrRecordReachNoteInvalid, len(note.Peers))
	case self.settings.RelayCount < len(note.Relays) && 0 < len(note.Relays):
		return key, nil, nil, fmt.Errorf("%w: %d relays", ErrRecordReachNoteInvalid, len(note.Relays))
	case note.GrantEndMillis < 0:
		return key, nil, nil, fmt.Errorf("%w: a grant ending before 1970", ErrRecordReachNoteInvalid)
	}
	for _, id := range [][]byte{note.Owner, note.Approver} {
		if self.settings.PeerIdByteCount < len(id) {
			return key, nil, nil, fmt.Errorf("%w: an owner or approver of %d bytes", ErrRecordReachNoteInvalid, len(id))
		}
	}
	copy(key.grantId[:], note.GrantId)
	peers := [][]byte{}
	if note.Visitor.IsValid() {
		peer, err := self.visitorPeerWithLock(note.Visitor, now)
		if err != nil {
			return key, nil, nil, err
		}
		peers = append(peers, peer)
	} else {
		for _, peer := range note.Peers {
			if len(peer) == 0 || self.settings.PeerIdByteCount < len(peer) {
				return key, nil, nil, fmt.Errorf("%w: a peer id of %d bytes", ErrRecordReachNoteInvalid, len(peer))
			}
			peers = append(peers, bytes.Clone(peer))
		}
	}
	keyPeers := &strings.Builder{}
	for _, peer := range peers {
		fmt.Fprintf(keyPeers, "%d:", len(peer))
		keyPeers.Write(peer)
	}
	key.peers = keyPeers.String()
	relays := []string{}
	for _, relay := range note.Relays {
		text, err := self.relayText(relay)
		if err != nil {
			return key, nil, nil, err
		}
		if !slices.Contains(relays, text) {
			relays = append(relays, text)
		}
	}
	return key, peers, relays, nil
}

// Adds one act to its (grant, peer)'s receipt in the window now falls in, opening the receipt when none is open. A
// refused note keeps nothing; ErrRecordReachNoteInvalid says why. Never waits on evs, and on an append only past the
// bound the file header names.
func (self *RecordReach) Note(note *RecordReachNote) error {
	now := self.clock.Now()
	nowMillis := now.UnixMilli()
	appendNow := false
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		key, peers, relays, err := self.checkWithLock(note, now)
		if err != nil {
			return err
		}
		windowStartMillis, windowEndMillis := self.windowOf(nowMillis)
		receipt := self.keyReceipts[key]
		if receipt != nil {
			switch {
			case receipt.receipt.GetWindowStartMillis() != windowStartMillis:
				// the window it was opened in has ended, and its timer has not run yet
				self.flushWithLock(receipt, false)
				receipt = nil
			case !self.sameAttributes(receipt, note), self.relaysOverflow(receipt, relays):
				self.flushWithLock(receipt, true)
				receipt = nil
			}
		}
		if receipt == nil {
			if 0 < self.settings.ReceiptCount && self.settings.ReceiptCount <= len(self.keyReceipts) {
				self.flushOldestWithLock()
			}
			self.openedSeq += 1
			receipt = &recordReachReceipt{
				key: key,
				receipt: &protocol.ReachReceipt{
					GrantId:           bytes.Clone(note.GrantId),
					PolicyVersion:     note.PolicyVersion,
					Kind:              uint32(note.Kind),
					Owner:             bytes.Clone(note.Owner),
					Approver:          bytes.Clone(note.Approver),
					WindowStartMillis: windowStartMillis,
					Peers:             peers,
				},
				grantId:         bytes.Clone(note.GrantId),
				actionId:        bytes.Clone(note.ActionId),
				windowEndMillis: windowEndMillis,
				grantEndMillis:  note.GrantEndMillis,
				openedSeq:       self.openedSeq,
			}
			self.keyReceipts[key] = receipt
		}
		receipt.receipt.StreamCount = recordReachSum(receipt.receipt.GetStreamCount(), note.StreamCount)
		receipt.receipt.ByteCount = recordReachSum(receipt.receipt.GetByteCount(), note.ByteCount)
		for _, relay := range relays {
			if !slices.Contains(receipt.receipt.Relays, relay) {
				receipt.receipt.Relays = append(receipt.receipt.Relays, relay)
			}
		}
		if 0 < note.GrantEndMillis && (receipt.grantEndMillis == 0 || note.GrantEndMillis < receipt.grantEndMillis) {
			receipt.grantEndMillis = note.GrantEndMillis
		}
		if self.closed || self.settings.ReceiptCount <= 0 || receipt.dueMillis() <= nowMillis {
			// past Close, with no receipt held open, or for a grant already ended: written at once
			self.flushWithLock(receipt, false)
		}
		appendNow = self.closed || self.settings.ReceiptCount <= 0 || max(self.settings.ReceiptCount, 1) < len(self.waitingReceipts)
		return nil
	}()
	if err != nil {
		return err
	}
	if appendNow {
		self.appendWaiting()
	} else {
		self.schedule()
	}
	return nil
}

// a + b, held at the largest count rather than wrapping.
func recordReachSum(a uint64, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

// The window nowMillis falls in, its start and end, Unix milliseconds: ReachReceiptCoalesce long from the epoch, or
// the instant alone when it is not positive.
func (self *RecordReach) windowOf(nowMillis int64) (int64, int64) {
	windowMillis := self.recordSettings.ReachReceiptCoalesce.Milliseconds()
	if windowMillis <= 0 {
		return nowMillis, nowMillis
	}
	start := nowMillis / windowMillis * windowMillis
	if nowMillis < start {
		start -= windowMillis
	}
	return start, start + windowMillis
}

// Whether the note keeps the receipt's attributes: the grant's policy version, owner, approver and action.
func (self *RecordReach) sameAttributes(receipt *recordReachReceipt, note *RecordReachNote) bool {
	return receipt.receipt.GetPolicyVersion() == note.PolicyVersion && bytes.Equal(receipt.receipt.GetOwner(), note.Owner) &&
		bytes.Equal(receipt.receipt.GetApprover(), note.Approver) && bytes.Equal(receipt.actionId, note.ActionId)
}

// Whether relays would take the receipt past RelayCount.
func (self *RecordReach) relaysOverflow(receipt *recordReachReceipt, relays []string) bool {
	count := len(receipt.receipt.GetRelays())
	for _, relay := range relays {
		if !slices.Contains(receipt.receipt.GetRelays(), relay) {
			count += 1
		}
	}
	return self.settings.RelayCount < count && 0 < count
}

// Moves a receipt from the open map to the append queue, counting an early one.
func (self *RecordReach) flushWithLock(receipt *recordReachReceipt, early bool) {
	if held, ok := self.keyReceipts[receipt.key]; ok && held == receipt {
		delete(self.keyReceipts, receipt.key)
	}
	if early {
		self.stats.EarlyCount += 1
	}
	self.waitingReceipts = append(self.waitingReceipts, receipt)
}

// Flushes each open receipt flushed answers true for, in the order they opened, none early.
func (self *RecordReach) flushEachWithLock(flushed func(receipt *recordReachReceipt) bool) {
	receipts := []*recordReachReceipt{}
	for _, receipt := range self.keyReceipts {
		if flushed(receipt) {
			receipts = append(receipts, receipt)
		}
	}
	slices.SortFunc(receipts, func(a *recordReachReceipt, b *recordReachReceipt) int { return cmp.Compare(a.openedSeq, b.openedSeq) })
	for _, receipt := range receipts {
		self.flushWithLock(receipt, false)
	}
}

// Flushes the receipt opened first, early: the bound's overflow.
func (self *RecordReach) flushOldestWithLock() {
	var oldest *recordReachReceipt
	for _, receipt := range self.keyReceipts {
		if oldest == nil || receipt.openedSeq < oldest.openedSeq {
			oldest = receipt
		}
	}
	if oldest != nil {
		self.flushWithLock(oldest, true)
	}
}

// Sets the flush timer for the earliest receipt due, unless one is set for that time already, and starts an append
// pass at once when receipts wait for theirs. Called with no lock held: a fake clock runs a due callback inline.
func (self *RecordReach) schedule() {
	dueMillis, stop, waiting := func() (int64, func() bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		dueMillis := int64(0)
		for _, receipt := range self.keyReceipts {
			if due := receipt.dueMillis(); dueMillis == 0 || due < dueMillis {
				dueMillis = due
			}
		}
		if dueMillis == self.timerDueMillis {
			return 0, nil, 0 < len(self.waitingReceipts)
		}
		stop := self.timerStop
		self.timerStop = nil
		self.timerDueMillis = dueMillis
		return dueMillis, stop, 0 < len(self.waitingReceipts)
	}()
	if stop != nil {
		stop()
	}
	if 0 < dueMillis {
		timeout := time.Duration(dueMillis-self.clock.Now().UnixMilli()) * time.Millisecond
		armed := self.clock.AfterFunc(timeout, func() { self.flushDue(dueMillis) })
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.timerDueMillis == dueMillis && self.timerStop == nil {
				self.timerStop = armed
			}
		}()
	}
	if waiting {
		self.clock.AfterFunc(0, self.appendWaiting)
	}
}

// The timer's work: every receipt due by now flushed and appended, then the next timer set.
func (self *RecordReach) flushDue(dueMillis int64) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.timerDueMillis == dueMillis {
			self.timerDueMillis = 0
			self.timerStop = nil
		}
		nowMillis := self.clock.Now().UnixMilli()
		self.flushEachWithLock(func(receipt *recordReachReceipt) bool { return receipt.dueMillis() <= nowMillis })
	}()
	self.appendWaiting()
	self.schedule()
}

// Appends every receipt waiting for its append, in the order they were flushed.
func (self *RecordReach) appendWaiting() {
	self.appendLock.Lock()
	defer self.appendLock.Unlock()
	for {
		receipt := func() *recordReachReceipt {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if len(self.waitingReceipts) == 0 {
				return nil
			}
			receipt := self.waitingReceipts[0]
			self.waitingReceipts = self.waitingReceipts[1:]
			return receipt
		}()
		if receipt == nil {
			return
		}
		err := fmt.Errorf("%w: the receipts have no writer", ErrRecordDraftInvalid)
		if self.writer != nil {
			_, err = self.writer.Append(&RecordDraft{
				Kind:      RecordKindReach,
				Source:    RecordSourceObserved,
				NoSession: true,
				ActionId:  receipt.actionId,
				GrantId:   receipt.grantId,
				Body:      receipt.receipt,
			})
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if err != nil {
				self.stats.FailedCount += 1
			} else {
				self.stats.WrittenCount += 1
			}
		}()
		if err != nil {
			self.log.Warningf("[record]a reach receipt was not written: %s", err)
		}
	}
}

// Flushes, and writes, every receipt of a grant now: what a revocation or a grant's early end calls.
func (self *RecordReach) GrantEnded(grantId []byte) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.flushEachWithLock(func(receipt *recordReachReceipt) bool { return bytes.Equal(receipt.grantId, grantId) })
	}()
	self.appendWaiting()
	self.schedule()
}

// Writes every open receipt now and keeps coalescing after: what sleep calls.
func (self *RecordReach) Flush() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.flushEachWithLock(func(receipt *recordReachReceipt) bool { return true })
	}()
	self.appendWaiting()
	self.schedule()
}

// Writes every open receipt and stops the timer: the process's exit. A note after Close is written at once, alone.
func (self *RecordReach) Close() {
	stop := func() func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		self.flushEachWithLock(func(receipt *recordReachReceipt) bool { return true })
		stop := self.timerStop
		self.timerStop = nil
		self.timerDueMillis = 0
		return stop
	}()
	if stop != nil {
		stop()
	}
	self.appendWaiting()
}

// What the receipts did since they were made.
func (self *RecordReach) Stats() RecordReachStats {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stats := self.stats
	stats.OpenCount = len(self.keyReceipts)
	return stats
}
