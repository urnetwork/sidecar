// The name map, §13.5's step 2: a visitor's normalized SNI and the port it came in on, to the network
// and the socket name its listener registered, from §12's label map held in memory. A lookup reads one
// immutable view through an atomic pointer, so it takes no lock and never waits on the store (I-12): a
// name the view does not hold is unrecognized_name, with no fallback lookup.
//
// What maps (§13.5, Q-TLS-6): <host>.<x>.<root> and <x>.<root>, the latter as host @, where <x> is a
// live label or a live alias and <host> one LDH label. The target always names the network's
// 10-character label, which SOCK's target needs, so an alias resolves to its network's label. Deeper
// names, the scope hosts <label>.<scope>, and custom hosts map nothing until TLS-M6-02. A retiring or
// tombstoned name, an ownerless one, a reserved label (§12.5), a suspended zone and a withheld host
// (§12.9) map nothing either, and all of these read on the wire exactly as an unknown name does.
//
// The view is split into shards by a keyed hash, so a change copies only the shards it touches rather
// than the whole map: a change every 5 s on a map of every labelled network stays cheap. One writer
// applies snapshots and changes at a time; any number of readers resolve alongside it.

package tlsedgeservice

import (
	"hash/maphash"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar"
)

// The ports tlsedge serves (owner decisions 68 and 121; §13.15), the same list the lb renders and
// ValidateListen allows. Facts, not tunables.
var tlsEdgePorts = []int{443, 8443, 8883, 5671}

// Whether port is one tlsedge serves.
func tlsEdgePortServed(port int) bool {
	for _, servedPort := range tlsEdgePorts {
		if port == servedPort {
			return true
		}
	}
	return false
}

// How many shards a view splits into. A structural size, as a hash table's buckets are, not a policy:
// any power of two works, and this one keeps a change's copy to a few hundredths of the map.
const tlsEdgeNameShardCount = 256

// §12.5's network label: ten characters (owner decision 14).
const tlsEdgeLabelByteCount = 10

// The host a zone's apex takes in a socket name (§9.4).
const tlsEdgeApexHost = "@"

// What a name maps to: the listening network and the socket name a tls/ listener registered (§9.4).
type TlsEdgeTarget struct {
	NetworkId sidecar.Id
	// The network's 10-character label, even when the visitor named an alias.
	Label string
	// @ or one label.
	Host string
	// The port the visitor came in on: 443, 8443, 8883 or 5671.
	Port int
	// tls/<port>/<host>.
	Name string
}

// One routable name in a view.
type tlsEdgeNameRow struct {
	networkId sidecar.Id
	kind      TlsEdgeNameKind
	// the 10-character label of a label row; an alias finds its network's in the view's labels
	label            string
	zoneSuspended    bool
	zoneSuspendUntil time.Time
	withheldHosts    []string
}

// A host withheld here or below one withheld here (§12.9).
func (self *tlsEdgeNameRow) withholds(host string) bool {
	for _, withheldHost := range self.withheldHosts {
		if host == withheldHost || strings.HasSuffix(host, "."+withheldHost) {
			return true
		}
	}
	return false
}

// One immutable state of the map. Nothing in a published view changes; a change publishes a new one.
type tlsEdgeNameView struct {
	serial        uint64
	restoreSerial uint64
	// name to row, by shard
	nameShards [tlsEdgeNameShardCount]map[string]*tlsEdgeNameRow
	// network to its label, by shard
	labelShards [tlsEdgeNameShardCount]map[sidecar.Id]string
}

// The map, as the engine and its loader share it. Resolve is safe for concurrent use with everything;
// Apply is safe for concurrent use, one apply at a time.
type TlsEdgeNames struct {
	root       string
	rootSuffix string
	clock      sidecar.Clock
	seed       maphash.Seed
	view       atomic.Pointer[tlsEdgeNameView]

	// serializes writers; readers never take it
	applyLock sync.Mutex
}

// An empty map for root, which resolves nothing until its first snapshot. clock decides whether a
// zone suspension's until has passed; nil is real time.
func NewTlsEdgeNames(root string, clock sidecar.Clock) *TlsEdgeNames {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &TlsEdgeNames{
		root:       root,
		rootSuffix: "." + root,
		clock:      clock,
		seed:       maphash.MakeSeed(),
	}
}

func (self *TlsEdgeNames) nameShard(name string) int {
	return int(maphash.String(self.seed, name) % tlsEdgeNameShardCount)
}

func (self *TlsEdgeNames) labelShard(networkId sidecar.Id) int {
	return int(maphash.Bytes(self.seed, networkId[:]) % tlsEdgeNameShardCount)
}

// Whether a snapshot has been applied.
func (self *TlsEdgeNames) Loaded() bool {
	return self.view.Load() != nil
}

// The serial the next NamesSince follows from and the restore serial the view was read under, zeros
// before the first snapshot.
func (self *TlsEdgeNames) Serials() (serial uint64, restoreSerial uint64) {
	if view := self.view.Load(); view != nil {
		return view.serial, view.restoreSerial
	}
	return 0, 0
}

// Whether an entry routes at all: live, owned, and a name §12.5 could have issued.
func tlsEdgeEntryRoutable(entry *TlsEdgeNameEntry) bool {
	if entry.State != TlsEdgeNameStateLive || entry.NetworkId == (sidecar.Id{}) {
		return false
	}
	if normalized, ok := NormalizeSni(entry.Name); !ok || normalized != entry.Name || strings.Contains(entry.Name, ".") {
		return false
	}
	if sidecar.IsReservedDnsLabel(entry.Name) {
		return false
	}
	switch entry.Kind {
	case TlsEdgeNameKindLabel:
		return len(entry.Name) == tlsEdgeLabelByteCount
	case TlsEdgeNameKindAlias:
		return true
	}
	return false
}

// Applies a label map: a snapshot replaces the view, and anything else is the changes since the view's
// serial, each entry replacing its name's. A change applied with no view yet is dropped, since a map
// must start from a snapshot.
func (self *TlsEdgeNames) Apply(nameMap *TlsEdgeNameMap, snapshot bool) {
	self.applyLock.Lock()
	defer self.applyLock.Unlock()

	old := self.view.Load()
	if !snapshot && old == nil {
		return
	}
	view := &tlsEdgeNameView{serial: nameMap.Serial, restoreSerial: nameMap.RestoreSerial}
	// a shard is copied before its first change and written in place after, so each is copied once
	copied := [tlsEdgeNameShardCount]bool{}
	labelCopied := [tlsEdgeNameShardCount]bool{}
	if snapshot {
		for index := range view.nameShards {
			view.nameShards[index] = map[string]*tlsEdgeNameRow{}
			view.labelShards[index] = map[sidecar.Id]string{}
			copied[index] = true
			labelCopied[index] = true
		}
	} else {
		view.nameShards = old.nameShards
		view.labelShards = old.labelShards
		view.serial = max(old.serial, nameMap.Serial)
	}
	nameShardForWrite := func(name string) map[string]*tlsEdgeNameRow {
		index := self.nameShard(name)
		if !copied[index] {
			shard := make(map[string]*tlsEdgeNameRow, len(view.nameShards[index])+1)
			for key, row := range view.nameShards[index] {
				shard[key] = row
			}
			view.nameShards[index] = shard
			copied[index] = true
		}
		return view.nameShards[index]
	}
	labelShardForWrite := func(networkId sidecar.Id) map[sidecar.Id]string {
		index := self.labelShard(networkId)
		if !labelCopied[index] {
			shard := make(map[sidecar.Id]string, len(view.labelShards[index])+1)
			for key, label := range view.labelShards[index] {
				shard[key] = label
			}
			view.labelShards[index] = shard
			labelCopied[index] = true
		}
		return view.labelShards[index]
	}

	for _, entry := range nameMap.Entries {
		if entry == nil {
			continue
		}
		routable := tlsEdgeEntryRoutable(entry)
		nameShard := nameShardForWrite(entry.Name)
		if previous, ok := nameShard[entry.Name]; ok && previous.kind == TlsEdgeNameKindLabel {
			// a label that stops routing takes its network's label with it, unless another row holds it
			labelShard := labelShardForWrite(previous.networkId)
			if labelShard[previous.networkId] == entry.Name {
				delete(labelShard, previous.networkId)
			}
		}
		if !routable {
			delete(nameShard, entry.Name)
			continue
		}
		row := &tlsEdgeNameRow{
			networkId:        entry.NetworkId,
			kind:             entry.Kind,
			zoneSuspended:    entry.ZoneSuspended,
			zoneSuspendUntil: entry.ZoneSuspendUntil,
			withheldHosts:    append([]string{}, entry.WithheldHosts...),
		}
		if entry.Kind == TlsEdgeNameKindLabel {
			row.label = entry.Name
			labelShardForWrite(entry.NetworkId)[entry.NetworkId] = entry.Name
		}
		nameShard[entry.Name] = row
	}
	testHookBarrier("tlsedge.names_publish.before", "")
	self.view.Store(view)
	testHookBarrier("tlsedge.names_publish.after", "")
}

// The target a visitor's server name maps to on port, §13.5's step 2, or false. The name may be as the
// visitor sent it: it is normalized here (lowercase, one trailing dot off, LDH). Takes no lock and does
// no I/O.
func (self *TlsEdgeNames) Resolve(serverName string, port int) (*TlsEdgeTarget, bool) {
	if !tlsEdgePortServed(port) {
		return nil, false
	}
	name, ok := NormalizeSni(serverName)
	if !ok {
		return nil, false
	}
	rest, found := strings.CutSuffix(name, self.rootSuffix)
	if !found || rest == "" {
		return nil, false
	}
	host, x, deeper := strings.Cut(rest, ".")
	if !deeper {
		host, x = tlsEdgeApexHost, rest
	} else if strings.Contains(x, ".") {
		// a scope host or deeper: TLS-M6-02's
		return nil, false
	}
	view := self.view.Load()
	if view == nil {
		return nil, false
	}
	row, ok := view.nameShards[self.nameShard(x)][x]
	if !ok {
		return nil, false
	}
	if row.zoneSuspended && (row.zoneSuspendUntil.IsZero() || self.clock.Now().Before(row.zoneSuspendUntil)) {
		return nil, false
	}
	if host != tlsEdgeApexHost && row.withholds(host) {
		return nil, false
	}
	label := row.label
	if row.kind == TlsEdgeNameKindAlias {
		label, ok = view.labelShards[self.labelShard(row.networkId)][row.networkId]
		if !ok {
			return nil, false
		}
	}
	return &TlsEdgeTarget{
		NetworkId: row.networkId,
		Label:     label,
		Host:      host,
		Port:      port,
		Name:      "tls/" + strconv.Itoa(port) + "/" + host,
	}, true
}
