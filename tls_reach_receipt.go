//go:build !sidecar_http && !ios_extension

// §13.7's reach receipts (owner decision 25, R-MCP-7, §16.8, I-13): the front, the endpoint enforcing a publish grant,
// writes one ReachReceipt of kind publish per grant, visitor and window of SidecarRecordSettings.ReachReceiptCoalesce
// (5 min), through the record's writer, which journals it and never waits on evs (RecordWriter.Append). A visitor is
// its address's /32 or /64, as the front's share counts it (tls_front_limits.go), and a receipt names it only by a
// hash this device keys:
//
//	peers           one: HMAC-SHA256(k, family || the prefix's address bytes)[:16], family 4 or 6; k is HKDF-SHA256 of
//	                the front's session root in keychain.ur (tls_session.go), salt the network_id, info
//	                urnetwork-sidecar-v1/tls-front-reach, so no server holds it and the raw address never leaves the
//	                front
//	grant_id        the lowest of the grant's rule_ids, bytewise, and the header's grant_id too when it is 32 bytes, an
//	                activated grant's (§8.8)
//	policy_version  the newest config version a counted connection's grant was read at
//	owner           this sidecar, which holds the publish grant
//	stream_count    connections whose pass opened the target, each counted once, in the window its first target
//	                connection opened in
//	byte_count      what those streams carried either way, TLS records included, in the window each ended in
//
// Receipts are held in memory by grant, peer and window, and written when their window ends, when their grant's
// expiry passes, and at the front's close; when one more would pass ReachReceiptMaxCount, all held are written at
// once, off the visitor's path, so an overflow writes early and never drops. A connection that ends after the close
// writes its own receipt at once.
//
// Not written yet: approver; relays, the edge's host, IP and operator, which the front does not learn (RECORD-M6-02's
// relays row); and the visitor's SNI, which ReachReceipt has no field for (tls-m6-06-reach-receipt-server-name).
//
// The key reaches testHookSecret where it is derived. Nothing here logs an address, a hash or a name (I-13). Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The visitor key's derivation, its length, the peer hash's length and the address families it writes: format
// values and cryptographic constants.
const (
	tlsReachVisitorKeyInfo      = "urnetwork-sidecar-v1/tls-front-reach"
	tlsReachVisitorKeyByteCount = 32
	tlsReachPeerByteCount       = 16
	tlsReachFamilyIpv4          = 4
	tlsReachFamilyIpv6          = 6
)

// What newTlsReachReceipts takes.
type tlsReachReceiptsArgs struct {
	// Nil writes no receipts, and newTlsReachReceipts answers nil.
	Writer RecordWriter
	// Nil takes the defaults.
	RecordSettings *SidecarRecordSettings
	Settings       *TlsFrontSettings
	// The front's tls namespace of keychain.ur, which holds the session root the visitor key derives from.
	Secrets   SidecarSecrets
	NetworkId Id
	SidecarId Id
	Clock     Clock
	Log       Logger
}

// One receipt's key: its grant, its visitor's hash and its window's start.
type tlsReachKey struct {
	grantId           string
	peer              [tlsReachPeerByteCount]byte
	windowStartMillis int64
}

// What one receipt has counted.
type tlsReachCount struct {
	// the grant's expiry as last read; zero for none
	grantExpireTime time.Time
	policyVersion   uint64
	streamCount     uint64
	byteCount       uint64
}

// One receipt taken out of memory to write.
type tlsReachDrained struct {
	key   tlsReachKey
	count *tlsReachCount
}

// One front's reach receipts. A nil one notes nothing and writes nothing.
type tlsReachReceipts struct {
	writer     RecordWriter
	sidecarId  Id
	coalesce   time.Duration
	maxCount   int
	clock      Clock
	log        Logger
	visitors   *tlsFrontVisitors
	visitorKey []byte
	ctx        context.Context
	cancel     context.CancelFunc
	// a receipt with an earlier deadline than the loop waits for arrived
	wake chan struct{}
	// closed once the loop has returned
	done chan struct{}
	// overflow writes in flight, which close waits for
	writes sync.WaitGroup

	stateLock sync.Mutex
	counts    map[tlsReachKey]*tlsReachCount
	// the deadline the loop waits for; zero while it waits for none
	armedTime time.Time
	closed    bool
}

// The front's receipts, their loop running until ctx ends or close, or nil when args name no writer.
func newTlsReachReceipts(ctx context.Context, args *tlsReachReceiptsArgs) (*tlsReachReceipts, error) {
	if args.Writer == nil {
		return nil, nil
	}
	recordSettings := args.RecordSettings
	if recordSettings == nil {
		recordSettings = defaultSidecarRecordSettings()
	}
	if recordSettings.ReachReceiptCoalesce.Milliseconds() < 1 {
		return nil, fmt.Errorf("%w: a reach receipt's window is at least 1 ms", errInvalidSettings)
	}
	root, err := loadOrCreateTlsFrontSessionRoot(args.Secrets)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	visitorKey, err := hkdf.Key(sha256.New, root, args.NetworkId.Bytes(), tlsReachVisitorKeyInfo, tlsReachVisitorKeyByteCount)
	if err != nil {
		return nil, err
	}
	testHookSecret("tls_front_reach_key", visitorKey)
	receiptsCtx, cancel := context.WithCancel(ctx)
	self := &tlsReachReceipts{
		writer:    args.Writer,
		sidecarId: args.SidecarId,
		coalesce:  recordSettings.ReachReceiptCoalesce,
		maxCount:  args.Settings.ReachReceiptMaxCount,
		clock:     clockOrReal(args.Clock),
		log:       loggerOrDefault(args.Log),
		visitors: &tlsFrontVisitors{
			ipv4PrefixBitCount: args.Settings.VisitorIpv4PrefixBitCount,
			ipv6PrefixBitCount: args.Settings.VisitorIpv6PrefixBitCount,
		},
		visitorKey: visitorKey,
		ctx:        receiptsCtx,
		cancel:     cancel,
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		counts:     map[tlsReachKey]*tlsReachCount{},
	}
	go self.run()
	return self, nil
}

// The keyed hash naming clientIp's visitor, false for bytes that are no address.
func (self *tlsReachReceipts) peer(clientIp []byte) ([tlsReachPeerByteCount]byte, bool) {
	peer := [tlsReachPeerByteCount]byte{}
	prefix, ok := self.visitors.prefixOf(clientIp)
	if !ok {
		return peer, false
	}
	family := byte(tlsReachFamilyIpv6)
	if prefix.Addr().Is4() {
		family = tlsReachFamilyIpv4
	}
	mac := hmac.New(sha256.New, self.visitorKey)
	mac.Write([]byte{family})
	mac.Write(prefix.Masked().Addr().AsSlice())
	copy(peer[:], mac.Sum(nil))
	return peer, true
}

// When key's receipt is due: its window's end, or its grant's expiry when that is sooner.
func (self *tlsReachReceipts) deadline(key tlsReachKey, count *tlsReachCount) time.Time {
	deadline := time.UnixMilli(key.windowStartMillis).Add(self.coalesce)
	if !count.grantExpireTime.IsZero() && count.grantExpireTime.Before(deadline) {
		return count.grantExpireTime
	}
	return deadline
}

// Counts streamCount connections and byteCount bytes of clientIp's visitor under grant, in the window now is in.
func (self *tlsReachReceipts) note(grant *TlsPublishGrant, clientIp []byte, streamCount uint64, byteCount uint64) {
	if self == nil || grant == nil || len(grant.GrantIds) == 0 {
		return
	}
	peer, ok := self.peer(clientIp)
	if !ok {
		return
	}
	nowMillis := self.clock.Now().UnixMilli()
	key := tlsReachKey{
		grantId:           string(slices.MinFunc(grant.GrantIds, bytes.Compare)),
		peer:              peer,
		windowStartMillis: nowMillis - nowMillis%self.coalesce.Milliseconds(),
	}
	closed, wake := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true, false
		}
		count, found := self.counts[key]
		if !found {
			if self.maxCount <= len(self.counts) {
				// write what is held, off this visitor's path, and start again
				drained := self.drainWithLock(func(tlsReachKey, *tlsReachCount) bool { return true })
				self.writes.Add(1)
				go func() {
					defer self.writes.Done()
					self.write(drained)
				}()
			}
			count = &tlsReachCount{}
			self.counts[key] = count
		}
		count.grantExpireTime = grant.Expires
		count.policyVersion = max(count.policyVersion, grant.PolicyVersion)
		count.streamCount += streamCount
		count.byteCount += byteCount
		deadline := self.deadline(key, count)
		return false, self.armedTime.IsZero() || deadline.Before(self.armedTime)
	}()
	if closed {
		self.write([]*tlsReachDrained{{key: key, count: &tlsReachCount{
			policyVersion: grant.PolicyVersion,
			streamCount:   streamCount,
			byteCount:     byteCount,
		}}})
		return
	}
	if wake {
		select {
		case self.wake <- struct{}{}:
		default:
		}
	}
}

// Takes the receipts due says are due out of memory, in window, grant and peer order.
func (self *tlsReachReceipts) drainWithLock(due func(key tlsReachKey, count *tlsReachCount) bool) []*tlsReachDrained {
	drained := []*tlsReachDrained{}
	for key, count := range self.counts {
		if due(key, count) {
			drained = append(drained, &tlsReachDrained{key: key, count: count})
			delete(self.counts, key)
		}
	}
	slices.SortFunc(drained, func(a *tlsReachDrained, b *tlsReachDrained) int {
		return cmp.Or(
			cmp.Compare(a.key.windowStartMillis, b.key.windowStartMillis),
			cmp.Compare(a.key.grantId, b.key.grantId),
			bytes.Compare(a.key.peer[:], b.key.peer[:]),
		)
	})
	return drained
}

// Writes each receipt through the record's writer, which journals it or spools it and never waits on evs.
func (self *tlsReachReceipts) write(drained []*tlsReachDrained) {
	for _, receipt := range drained {
		draft := &RecordDraft{
			Kind:      RecordKindReach,
			Source:    RecordSourceObserved,
			NoSession: true,
			Body: &protocol.ReachReceipt{
				GrantId:           []byte(receipt.key.grantId),
				PolicyVersion:     receipt.count.policyVersion,
				Kind:              uint32(RecordReachKindPublish),
				Owner:             self.sidecarId.Bytes(),
				WindowStartMillis: receipt.key.windowStartMillis,
				Peers:             [][]byte{bytes.Clone(receipt.key.peer[:])},
				StreamCount:       receipt.count.streamCount,
				ByteCount:         receipt.count.byteCount,
			},
		}
		if len(receipt.key.grantId) == recordHashByteCount {
			draft.GrantId = []byte(receipt.key.grantId)
		}
		if _, err := self.writer.Append(draft); err != nil {
			self.log.Warningf("[tls]a reach receipt was not written: %s", err)
		}
	}
}

// Writes each receipt as it comes due, until the front's context ends or close.
func (self *tlsReachReceipts) run() {
	defer close(self.done)
	for {
		armedTime := func() time.Time {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.armedTime = time.Time{}
			for key, count := range self.counts {
				if deadline := self.deadline(key, count); self.armedTime.IsZero() || deadline.Before(self.armedTime) {
					self.armedTime = deadline
				}
			}
			return self.armedTime
		}()
		var timeout <-chan time.Time
		if !armedTime.IsZero() {
			timeout = self.clock.After(armedTime.Sub(self.clock.Now()))
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-timeout:
			now := self.clock.Now()
			drained := func() []*tlsReachDrained {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return self.drainWithLock(func(key tlsReachKey, count *tlsReachCount) bool {
					return !now.Before(self.deadline(key, count))
				})
			}()
			self.write(drained)
		}
	}
}

// Stops the loop and writes every receipt held, once the overflow writes in flight are done. A second close does
// nothing.
func (self *tlsReachReceipts) close() {
	if self == nil {
		return
	}
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		return true
	}()
	if !first {
		return
	}
	self.cancel()
	<-self.done
	self.writes.Wait()
	drained := func() []*tlsReachDrained {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.drainWithLock(func(tlsReachKey, *tlsReachCount) bool { return true })
	}()
	self.write(drained)
}
