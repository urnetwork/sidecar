//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Retries and joins (DESIGN-COMPUTE §8.5's retries table; D-GW-5, IC-19, Q-GW-7; GW-M12-05): whether a request repeats
// an earlier call is decided only by what its caller supplies, and never across run handles, so no run takes another's
// call, answer or tool-call ids. One table per network holds its calls, in flight and kept:
//
//	key        a run handle and an Idempotency-Key (draft-ietf-httpapi-idempotency-key-header-09): the earlier call's
//	           operation where handle and key match a call in flight or ended within GatewaySettings.KeptResponseLife,
//	           its body's SHA-256 the same; the key reused with another body is refused 422 idempotency_key_reused
//	           before any call (the draft's section 2.7)
//	handle     a run handle alone, as Codex and Claude Code send today: the earlier call's operation where handle and
//	           body's SHA-256 match a call in flight or ended within KeptResponseLife whose answer never reached its
//	           caller whole, the caller having left before its end (Q-GW-7's answer (b)); a crash's cut call is never
//	           one (gateway_kept.go)
//	none       no run handle: never; every request is a new call
//	join       the same operation follows the call's answer, replaying what streamed and then live, the call running on
//	           after its first caller left, or, once it ended, its kept answer: neither makes a provider call or charge
//	           nor records anything, and each goes ahead only after the router checked the call's model against the
//	           caller's marks as they stand then (gateway_responses.go's check), service_model where they no longer
//	           admit it
//
// A call whose answer is an error before its stream began (tee_unverified, insufficient_quota at the broker, a
// refusal) is no operation to join: its retry is a new call, which may pass. An answer past KeptResponseByteCount stops
// being kept, so its retry is a new call. What the record shows is what was assumed (Q-GW-7): a join records nothing
// new, so a new request that repeats an abandoned call's bytes shows as that one call; a retry of an answer that
// arrived whole is a second call on the same context node (§24.8).
//
// Safe for concurrent use: a table's stateLock guards its entries, and each entry's stateLock its own fields; an entry's
// writeLock orders its writes to the store and is held across them, never under either stateLock.

package sidecar

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The header a caller names one operation in (draft-ietf-httpapi-idempotency-key-header-09).
const gatewayHeaderIdempotencyKey = "Idempotency-Key"

// One network's calls (see the file header).
type gatewayCallTable struct {
	fronts    *GatewayFronts
	networkId Id
	// the network's store for kept answers; nil keeps them in memory alone
	store func() (SidecarStore, error)

	stateLock sync.Mutex
	// in the order they began
	entries []*gatewayCallEntry
	// whether the store's kept answers were read, after a restart
	loaded bool
	// the files of calls a crash cut whose Cut is not written yet
	cutNames []string
}

// One call the table holds: what matches its retries, its answer, and what a crash's Cut records of it.
type gatewayCallEntry struct {
	table *gatewayCallTable
	// its file in the store, kept/<hex>
	name           string
	handle         string
	idempotencyKey string
	bodySha256     [32]byte
	answer         *gatewayAnswer
	// what Cut records after a crash, set when the call is recorded
	cut *GatewayRecordCut

	writeLock sync.Mutex

	stateLock sync.Mutex
	nodeIds   []Id
	began     time.Time
	ended     time.Time
	// the answer reached a caller whole
	delivered bool
	// a caller left before the end, and none has had it whole
	abandoned bool
	// not to be joined: its answer is past the bound, or an error before its stream began
	unjoinable bool
	// the items journaled when the store was last written, -1 before the first write
	writtenItems int
	// the drop at the end of its life, nil before it ended
	stopDrop func() bool
}

// The request's Idempotency-Key, empty for none; one past IdempotencyKeyByteCount, or repeated, is refused 400.
func gatewayIdempotencyKey(request *http.Request, settings *GatewaySettings) (string, *gatewayError) {
	values := request.Header.Values(gatewayHeaderIdempotencyKey)
	switch {
	case len(values) == 0:
		return "", nil
	case 1 < len(values):
		return "", gatewayInvalidRequest(GatewayErrorCodeInvalidValue, gatewayHeaderIdempotencyKey, "one Idempotency-Key names one operation")
	}
	key := strings.TrimSpace(values[0])
	if key == "" || settings.IdempotencyKeyByteCount < len(key) {
		return "", gatewayInvalidRequest(GatewayErrorCodeInvalidValue, gatewayHeaderIdempotencyKey,
			"an Idempotency-Key is 1 to %d bytes", settings.IdempotencyKeyByteCount)
	}
	return key, nil
}

// The tables, by network, made at a network's first call. Guarded by the fronts' tablesLock.
type gatewayCallTables struct {
	tablesLock      sync.Mutex
	networkIdTables map[Id]*gatewayCallTable
	// a crash's stand-in in tests: once set, nothing more reaches the store, as nothing does from a process that died
	stopped atomic.Bool
	// each drop of an entry, for a test to wait on; nil in a daemon
	dropped func()
}

// The table of caller's network, its kept answers read from the store at its first use.
func (self *GatewayFronts) tableOf(ctx context.Context, caller *GatewayCaller) *gatewayCallTable {
	table := func() *gatewayCallTable {
		self.tables.tablesLock.Lock()
		defer self.tables.tablesLock.Unlock()
		if self.tables.networkIdTables == nil {
			self.tables.networkIdTables = map[Id]*gatewayCallTable{}
		}
		table, ok := self.tables.networkIdTables[caller.NetworkId]
		if !ok {
			table = &gatewayCallTable{fronts: self, networkId: caller.NetworkId}
			if kept, ok := caller.Network.(GatewayKeptNetwork); ok {
				table.store = kept.GatewayKeptStore
			}
			self.tables.networkIdTables[caller.NetworkId] = table
		}
		return table
	}()
	table.load(ctx)
	return table
}

// The call a prepared request repeats, and whether it joins it (see the file header); else the entry the new call is
// kept as, nil where the table is full of calls in flight.
func (self *GatewayFronts) lookup(ctx context.Context, prepared *gatewayPreparedCall) (*gatewayCallEntry, bool, *gatewayError) {
	table := self.tableOf(ctx, prepared.caller)
	return table.lookup(prepared.binding.Handle, prepared.idempotencyKey, prepared.bodySha256, self.clock.Now())
}

// The entry a request of handle, idempotencyKey and bodySha256 joins, or a new one: in one critical section, so two
// requests of one operation at once make one call.
func (self *gatewayCallTable) lookup(handle string, idempotencyKey string, bodySha256 [32]byte, now time.Time) (*gatewayCallEntry, bool, *gatewayError) {
	settings := self.fronts.settings
	raw := make([]byte, max(settings.IdRandomByteCount, 1))
	if _, err := io.ReadFull(self.fronts.random, raw); err != nil {
		return nil, false, nil
	}
	testHookBarrier("gateway.call_table.lookup.before", handle)
	defer testHookBarrier("gateway.call_table.lookup.after", handle)
	entry, joined, refusal, dropped := func() (*gatewayCallEntry, bool, *gatewayError, []*gatewayCallEntry) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if handle != "" && 0 < settings.KeptResponseLife {
			entry, refusal := self.findWithLock(handle, idempotencyKey, bodySha256, now)
			if refusal != nil || entry != nil {
				return entry, entry != nil, refusal, nil
			}
		}
		entry, dropped := self.addWithLock(gatewayKeptPrefix+hex.EncodeToString(raw), handle, idempotencyKey, bodySha256, now)
		return entry, false, nil, dropped
	}()
	for _, each := range dropped {
		each.remove()
	}
	return entry, joined, refusal
}

// Whether entry is in flight or ended within life at now.
func (self *gatewayCallEntry) liveAt(now time.Time, life time.Duration) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended.IsZero() || now.Before(self.ended.Add(life))
}

// The call request's handle, key and body name, or the refusal of a key reused with another body; nil for none. Under
// the table's stateLock, which is taken before an entry's.
func (self *gatewayCallTable) findWithLock(handle string, idempotencyKey string, bodySha256 [32]byte, now time.Time) (*gatewayCallEntry, *gatewayError) {
	life := self.fronts.settings.KeptResponseLife
	// the newest first, so a key reused after its life finds its newest call
	for _, entry := range slices.Backward(self.entries) {
		if entry.handle != handle || !entry.liveAt(now, life) {
			continue
		}
		sameBody := subtle.ConstantTimeCompare(entry.bodySha256[:], bodySha256[:]) == 1
		if idempotencyKey != "" {
			if entry.idempotencyKey != idempotencyKey {
				continue
			}
			if !sameBody {
				return nil, &gatewayError{
					Status:       http.StatusUnprocessableEntity,
					Type:         gatewayErrorTypeInvalidRequest,
					Code:         GatewayErrorCodeIdempotencyKeyReused,
					Param:        gatewayHeaderIdempotencyKey,
					MessagesType: gatewayErrorTypeInvalidRequest,
					Message:      "this Idempotency-Key named another request within the last minutes: send a new key for a new request",
				}
			}
			if entry.joinable() {
				return entry, nil
			}
			return nil, nil
		}
		if sameBody && entry.joinable() && entry.wasAbandoned() {
			return entry, nil
		}
	}
	return nil, nil
}

// Whether a retry may follow the entry's answer.
func (self *gatewayCallEntry) joinable() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.unjoinable
}

// Whether a caller left before the end and none has had the answer whole.
func (self *gatewayCallEntry) wasAbandoned() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.abandoned && !self.delivered
}

// A new call's entry named name, the oldest ended ones dropped to fit KeptCallCount, answered for their removal outside
// the lock; nil where every one is in flight. Under the table's stateLock.
func (self *gatewayCallTable) addWithLock(name string, handle string, idempotencyKey string, bodySha256 [32]byte, now time.Time) (*gatewayCallEntry, []*gatewayCallEntry) {
	entry := &gatewayCallEntry{
		table:          self,
		name:           name,
		handle:         handle,
		idempotencyKey: idempotencyKey,
		bodySha256:     bodySha256,
		answer:         newGatewayAnswer(),
		began:          now,
		writtenItems:   -1,
	}
	dropped := []*gatewayCallEntry{}
	for max(self.fronts.settings.KeptCallCount, 1) <= len(self.entries) {
		index := slices.IndexFunc(self.entries, func(each *gatewayCallEntry) bool { return each.isEnded() })
		if index < 0 {
			return nil, dropped
		}
		dropped = append(dropped, self.entries[index])
		self.entries = slices.Delete(self.entries, index, index+1)
	}
	self.entries = append(self.entries, entry)
	return entry, dropped
}

// Whether the call ended.
func (self *gatewayCallEntry) isEnded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.ended.IsZero()
}

// Drops an entry whose call was never sent.
func (self *GatewayFronts) forget(entry *gatewayCallEntry) {
	if entry == nil {
		return
	}
	entry.table.drop(entry)
}

// Takes entry out of the table and its kept answer out of the store.
func (self *gatewayCallTable) drop(entry *gatewayCallEntry) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.entries = slices.DeleteFunc(self.entries, func(each *gatewayCallEntry) bool { return each == entry })
	}()
	entry.remove()
	if dropped := self.fronts.tables.dropped; dropped != nil {
		dropped()
	}
}

// The calls every table holds, for ur status.
func (self *GatewayFronts) keptCount() int {
	tables := func() []*gatewayCallTable {
		self.tables.tablesLock.Lock()
		defer self.tables.tablesLock.Unlock()
		tables := []*gatewayCallTable{}
		for _, table := range self.tables.networkIdTables {
			tables = append(tables, table)
		}
		return tables
	}()
	count := 0
	for _, table := range tables {
		table.stateLock.Lock()
		count += len(table.entries)
		table.stateLock.Unlock()
	}
	return count
}

// Notes how a caller fared: the answer reached it whole, or it left before the end.
func (self *gatewayCallEntry) followed(delivered bool) {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch {
		case delivered && !self.delivered:
			self.delivered = true
			return true
		case !delivered && !self.delivered && !self.abandoned:
			self.abandoned = true
			return true
		}
		return false
	}()
	if changed {
		self.write(nil)
	}
}

// Notes that a call was recorded and sent: what a Cut records of it after a crash, and its first write to the store,
// before any of its answer.
func (self *gatewayCallEntry) dispatched(cut *GatewayRecordCut) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.cut = cut
	}()
	self.write(nil)
}

// Notes that pending, frames about to reach the callers, follow the answer, the items journaled now nodeIds: the store
// is written, with them, where an item was journaled since its last write (IC-19's points), before they are sent; an
// answer past KeptResponseByteCount stops being kept.
func (self *gatewayCallEntry) grew(nodeIds []Id, pending [][]byte) {
	settings := self.table.fronts.settings
	write := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.nodeIds = slices.Clone(nodeIds)
		if !self.unjoinable && settings.KeptResponseByteCount < self.answer.size()+gatewayFramesSize(pending) {
			self.unjoinable = true
		}
		return self.writtenItems != len(nodeIds)
	}()
	if write {
		self.write(pending)
	}
}

// Notes the call's end at now, pending its last frames, terminal among them: the store written whole with them before
// they are sent, kept for KeptResponseLife, then dropped. An answer that is an error before its stream began, status
// not 200, is no operation to join.
func (self *gatewayCallEntry) finish(nodeIds []Id, pending [][]byte, status int, now time.Time) {
	settings := self.table.fronts.settings
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.nodeIds = slices.Clone(nodeIds)
		self.ended = now
		if status != http.StatusOK || settings.KeptResponseByteCount < self.answer.size()+gatewayFramesSize(pending) {
			self.unjoinable = true
		}
	}()
	self.write(pending)
	stop := self.table.fronts.clock.AfterFunc(settings.KeptResponseLife, func() {
		self.table.drop(self)
	})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stopDrop = stop
	}()
}

// The bytes frames hold.
func gatewayFramesSize(frames [][]byte) int {
	size := 0
	for _, frame := range frames {
		size += len(frame)
	}
	return size
}
