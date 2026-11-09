// §13.9's kill switch as tlsedge holds it: per network, a host or * to its reason and until, refusing
// new connections to what it names (unrecognized_name, reading 5) and, once the connection path keeps
// its streams, resetting open ones within 5 s.
//
// A kill lives in two places, network_tls_suspension's row and the {tes_<network_id>} hash, and arrives
// from both: the rows at every 60 s reload, the hash at each key event (KillChanged) and at the reload.
// The set merges the two and drops a kill only once neither holds it (§13.9). So a Postgres restore,
// which can lose a row the case never lifted, lifts nothing while the key holds, and a lost Redis lifts
// nothing while the row holds. A read that fails changes nothing: the last answer from that place
// stands. A kill whose until has passed refuses nothing, whichever place still holds it, until the
// sweep removes it.
//
// Reads take no lock: Kills reads one immutable view through an atomic pointer. Writers take stateLock
// and publish a new view, which is cheap because kills are few. Safe for concurrent use.

package tlsedgeservice

import (
	"encoding/json"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/sidecar"
)

// Where a kill came from, so each source replaces only its own.
type tlsKillSource int

const (
	tlsKillSourceRow tlsKillSource = iota
	tlsKillSourceKey
)

// One network's kills in a view: the union of its rows' and its key's.
type tlsKillView struct {
	networkIdEntries map[sidecar.Id][]*sidecar.TlsKillEntry
}

// The kill set. See the file header.
type TlsKillSet struct {
	clock sidecar.Clock
	view  atomic.Pointer[tlsKillView]

	stateLock sync.Mutex
	// the last reload's rows, by network
	rowNetworkIdEntries map[sidecar.Id][]*sidecar.TlsKillEntry
	// each network's hash as last read, by network: only networks with a kill in it
	keyNetworkIdEntries map[sidecar.Id][]*sidecar.TlsKillEntry
	rowsLoaded          bool
}

// An empty set, refusing nothing and not loaded. clock decides whether an until has passed; nil is real
// time.
func NewTlsKillSet(clock sidecar.Clock) *TlsKillSet {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	self := &TlsKillSet{
		clock:               clock,
		rowNetworkIdEntries: map[sidecar.Id][]*sidecar.TlsKillEntry{},
		keyNetworkIdEntries: map[sidecar.Id][]*sidecar.TlsKillEntry{},
	}
	self.view.Store(&tlsKillView{networkIdEntries: map[sidecar.Id][]*sidecar.TlsKillEntry{}})
	return self
}

// Whether a kill refuses a connection to host of networkId now. Takes no lock and does no I/O.
func (self *TlsKillSet) Kills(networkId sidecar.Id, host string) bool {
	entries := self.view.Load().networkIdEntries[networkId]
	if len(entries) == 0 {
		return false
	}
	now := self.clock.Now()
	for _, entry := range entries {
		if entry.Kills(host, now) {
			return true
		}
	}
	return false
}

// Whether the rows have been read once: the set is not ready before then, since a kill could be
// missing.
func (self *TlsKillSet) Loaded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.rowsLoaded
}

// The networks whose key a reload reads again: every network a row or the last key read names. A key
// that has gone empty and has no row drops out after one read shows it empty.
func (self *TlsKillSet) NetworkIds() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []sidecar.Id{}
	for networkId := range self.rowNetworkIdEntries {
		networkIds = append(networkIds, networkId)
	}
	for networkId := range self.keyNetworkIdEntries {
		if _, ok := self.rowNetworkIdEntries[networkId]; !ok {
			networkIds = append(networkIds, networkId)
		}
	}
	slices.SortFunc(networkIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	return networkIds
}

// Replaces every row with a reload's: network_tls_suspension as Suspensions read it. Returns the
// networks whose kills changed.
func (self *TlsKillSet) SetRows(rows []*sidecar.TlsSuspendArgs) []sidecar.Id {
	rowNetworkIdEntries := map[sidecar.Id][]*sidecar.TlsKillEntry{}
	for _, row := range rows {
		if row == nil {
			continue
		}
		rowNetworkIdEntries[row.NetworkId] = append(rowNetworkIdEntries[row.NetworkId], &sidecar.TlsKillEntry{
			Host:   row.Host,
			Reason: row.Reason,
			Until:  row.Until,
		})
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	changed := []sidecar.Id{}
	for networkId := range self.rowNetworkIdEntries {
		if _, ok := rowNetworkIdEntries[networkId]; !ok {
			changed = append(changed, networkId)
		}
	}
	for networkId, entries := range rowNetworkIdEntries {
		if !tlsKillEntriesEqual(self.rowNetworkIdEntries[networkId], entries) {
			changed = append(changed, networkId)
		}
	}
	self.rowNetworkIdEntries = rowNetworkIdEntries
	self.rowsLoaded = true
	self.publishWithLock()
	return changed
}

// Replaces a network's key entries with a read of its {tes_} hash, field to value. Returns whether its
// kills changed.
func (self *TlsKillSet) SetKey(networkId sidecar.Id, fieldValues map[string][]byte) bool {
	entries := ParseTlsKillHash(fieldValues)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if tlsKillEntriesEqual(self.keyNetworkIdEntries[networkId], entries) {
		return false
	}
	if len(entries) == 0 {
		delete(self.keyNetworkIdEntries, networkId)
	} else {
		self.keyNetworkIdEntries[networkId] = entries
	}
	self.publishWithLock()
	return true
}

// Publishes the union of rows and keys as a new view.
func (self *TlsKillSet) publishWithLock() {
	networkIdEntries := map[sidecar.Id][]*sidecar.TlsKillEntry{}
	for networkId, entries := range self.rowNetworkIdEntries {
		networkIdEntries[networkId] = append(networkIdEntries[networkId], entries...)
	}
	for networkId, entries := range self.keyNetworkIdEntries {
		networkIdEntries[networkId] = append(networkIdEntries[networkId], entries...)
	}
	testHookBarrier("tlsedge.kill_publish.before", "")
	self.view.Store(&tlsKillView{networkIdEntries: networkIdEntries})
	testHookBarrier("tlsedge.kill_publish.after", "")
}

// The kills a {tes_<network_id>} hash holds: field the host or *, value the entry's JSON (tls_api.go).
// What cannot be read fails closed. A value that does not parse kills its field's host with no until;
// a value naming another host than its field kills both, with its until; and an empty field kills every
// host, as an entry with no host does. Entries come back sorted by host, so two reads compare.
func ParseTlsKillHash(fieldValues map[string][]byte) []*sidecar.TlsKillEntry {
	entries := []*sidecar.TlsKillEntry{}
	for field, value := range fieldValues {
		entry := &sidecar.TlsKillEntry{}
		if err := json.Unmarshal(value, entry); err != nil {
			entries = append(entries, &sidecar.TlsKillEntry{Host: field})
			continue
		}
		if entry.Host != field {
			entries = append(entries, &sidecar.TlsKillEntry{Host: field, Reason: entry.Reason, Until: entry.Until})
		}
		entries = append(entries, entry)
	}
	tlsKillEntriesSort(entries)
	return entries
}

func tlsKillEntriesSort(entries []*sidecar.TlsKillEntry) {
	slices.SortFunc(entries, func(a *sidecar.TlsKillEntry, b *sidecar.TlsKillEntry) int {
		switch {
		case a.Host != b.Host:
			if a.Host < b.Host {
				return -1
			}
			return 1
		case a.Reason != b.Reason:
			if a.Reason < b.Reason {
				return -1
			}
			return 1
		}
		return a.Until.Compare(b.Until)
	})
}

// Whether two lists hold the same kills, in any order.
func tlsKillEntriesEqual(a []*sidecar.TlsKillEntry, b []*sidecar.TlsKillEntry) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := slices.Clone(a)
	sortedB := slices.Clone(b)
	tlsKillEntriesSort(sortedA)
	tlsKillEntriesSort(sortedB)
	for index := range sortedA {
		if sortedA[index].Host != sortedB[index].Host || sortedA[index].Reason != sortedB[index].Reason ||
			!sortedA[index].Until.Equal(sortedB[index].Until) {
			return false
		}
	}
	return true
}
