// The name map, §13.5's step 2: a visitor's normalized SNI and the port it came in on, to the network
// and the socket name its listener registered, from §12's label map held in memory. A lookup reads one
// immutable view through an atomic pointer, so it takes no lock and never waits on the store (I-12): a
// name the view does not hold is unrecognized_name, with no fallback lookup.
//
// What maps (§13.5, Q-TLS-6, Q-TLS-3): <host>.<x>.<root> and <x>.<root>, the latter as host @, where <x>
// is a live label or a live alias and <host> one LDH label; v1's scope hosts <label>.<scope>.<x>.<root>,
// as host <label>.<scope> within one 63-byte segment of §9.4's grammar, deeper names mapping nothing; and
// §12.8's active custom hosts, <host>.<domain> or an apex <domain>, each to the host owner of its
// network's zone it maps to (TLS-M6-02). The target always names the network's 10-character label, which
// SOCK's target needs, so an alias and a custom host resolve to their network's label. tlsedge holds no
// scope table: Find denies a scope that does not exist, and the negative cache holds the denial. A
// retiring or tombstoned name, an ownerless one, a reserved label (§12.5), a suspended zone and a
// withheld host (§12.9), a custom host's owner among them, map nothing either, and all of these read on
// the wire exactly as an unknown name does.
//
// A name that resolved through an alias or the custom-host map carries the visitor's name as Find's
// server_name (DESIGN-DETAILS 17.2.10), so Find matches only listeners certified for it; a name under
// the network's own zone carries none, since the network's wildcard covers it.
//
// The label view is split into shards by a keyed hash, so a change copies only the shards it touches
// rather than the whole map: a change every 5 s on a map of every labelled network stays cheap. The
// custom-host view is Team's alone and small, read whole at each reload and replaced whole. One writer
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
	// The visitor's normalized name when it resolved through an alias or the custom-host map, which Find
	// takes as server_name (DESIGN-DETAILS 17.2.10); empty for a name under the network's own zone.
	ServerName string
}

// One active custom host in a view.
type tlsEdgeCustomHostRow struct {
	networkId  sidecar.Id
	ownerHost  string
	ownerLabel string
}

// One immutable state of the custom-host map, replaced whole at each read.
type tlsEdgeCustomHostView struct {
	hosts map[string]*tlsEdgeCustomHostRow
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

// Whether the zone's suspension holds at now (§12.9): until its until passes, or until a lift when it
// has none.
func (self *tlsEdgeNameRow) suspendedAt(now time.Time) bool {
	return self.zoneSuspended && (self.zoneSuspendUntil.IsZero() || now.Before(self.zoneSuspendUntil))
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
	customView atomic.Pointer[tlsEdgeCustomHostView]

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

// Whether a read of the custom hosts has been applied, which the engine is ready only after: until
// then a ready custom host's visitor would read as an unknown name.
func (self *TlsEdgeNames) CustomHostsLoaded() bool {
	return self.customView.Load() != nil
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
	// the barriers sit outside the lock, so a schedule holding one stalls no other writer
	testHookBarrier("tlsedge.names_publish.before", "")
	defer testHookBarrier("tlsedge.names_publish.after", "")
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
	self.view.Store(view)
}

// Whether entry is a custom host the map may hold: a canonical name under no root of this map and not
// the root itself, an owner host of one LDH label, a 10-character owner label, and a network.
func (self *TlsEdgeNames) customHostRoutable(entry *TlsEdgeCustomHostEntry) bool {
	if entry.NetworkId == (sidecar.Id{}) {
		return false
	}
	if host, ok := NormalizeSni(entry.Host); !ok || host != entry.Host || host == self.root || strings.HasSuffix(host, self.rootSuffix) {
		return false
	}
	if ownerHost, ok := NormalizeSni(entry.OwnerHost); !ok || ownerHost != entry.OwnerHost || strings.Contains(ownerHost, ".") {
		return false
	}
	ownerLabel, ok := NormalizeSni(entry.OwnerLabel)
	return ok && ownerLabel == entry.OwnerLabel && len(ownerLabel) == tlsEdgeLabelByteCount
}

// Replaces the custom-host map with one read of the active rows (§13.4), dropping any entry that could
// not route, and returns how many it holds. A host the read lacks maps nothing from here on.
func (self *TlsEdgeNames) ApplyCustomHosts(entries []*TlsEdgeCustomHostEntry) int {
	testHookBarrier("tlsedge.custom_hosts_publish.before", "")
	defer testHookBarrier("tlsedge.custom_hosts_publish.after", "")
	self.applyLock.Lock()
	defer self.applyLock.Unlock()

	view := &tlsEdgeCustomHostView{hosts: make(map[string]*tlsEdgeCustomHostRow, len(entries))}
	for _, entry := range entries {
		if entry == nil || !self.customHostRoutable(entry) {
			continue
		}
		view.hosts[entry.Host] = &tlsEdgeCustomHostRow{
			networkId:  entry.NetworkId,
			ownerHost:  entry.OwnerHost,
			ownerLabel: entry.OwnerLabel,
		}
	}
	self.customView.Store(view)
	return len(view.hosts)
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
	view := self.view.Load()
	if view == nil {
		return nil, false
	}
	rest, underRoot := strings.CutSuffix(name, self.rootSuffix)
	if !underRoot {
		if name == self.root {
			return nil, false
		}
		return self.resolveCustomHost(view, name, port)
	}
	// <x>, <host>.<x> or <label>.<scope>.<x>, <x> the label or alias just below the root
	host, x := tlsEdgeApexHost, rest
	if cut := strings.LastIndexByte(rest, '.'); 0 <= cut {
		host, x = rest[:cut], rest[cut+1:]
		if scopeCut := strings.IndexByte(host, '.'); 0 <= scopeCut {
			// a scope host: one label under one scope label, the whole within one segment of §9.4's
			// grammar, and nothing deeper
			if strings.Contains(host[scopeCut+1:], ".") {
				return nil, false
			}
			if _, _, err := sidecar.ParseSocketName("tls/" + strconv.Itoa(port) + "/" + host); err != nil {
				return nil, false
			}
		}
	}
	row, ok := view.nameShards[self.nameShard(x)][x]
	if !ok {
		return nil, false
	}
	if row.suspendedAt(self.clock.Now()) {
		return nil, false
	}
	if host != tlsEdgeApexHost && row.withholds(host) {
		return nil, false
	}
	target := &TlsEdgeTarget{
		NetworkId: row.networkId,
		Label:     row.label,
		Host:      host,
		Port:      port,
		Name:      "tls/" + strconv.Itoa(port) + "/" + host,
	}
	if row.kind == TlsEdgeNameKindAlias {
		target.Label, ok = view.labelShards[self.labelShard(row.networkId)][row.networkId]
		if !ok {
			return nil, false
		}
		// an alias is a name the network's wildcard does not cover, so Find matches only listeners
		// certified for it (TLS-M6-03 certifies aliases; until a certificate names one, none is)
		target.ServerName = name
	}
	return target, true
}

// A custom host's target: the host owner it maps to in its network's zone, while that network's live
// label is the owner's and neither the zone's suspension nor the owner's withholding holds.
func (self *TlsEdgeNames) resolveCustomHost(view *tlsEdgeNameView, name string, port int) (*TlsEdgeTarget, bool) {
	customView := self.customView.Load()
	if customView == nil {
		return nil, false
	}
	customRow, ok := customView.hosts[name]
	if !ok {
		return nil, false
	}
	label, ok := view.labelShards[self.labelShard(customRow.networkId)][customRow.networkId]
	if !ok || label != customRow.ownerLabel {
		return nil, false
	}
	labelRow, ok := view.nameShards[self.nameShard(label)][label]
	if !ok || labelRow.suspendedAt(self.clock.Now()) || labelRow.withholds(customRow.ownerHost) {
		return nil, false
	}
	return &TlsEdgeTarget{
		NetworkId:  customRow.networkId,
		Label:      label,
		Host:       customRow.ownerHost,
		Port:       port,
		Name:       "tls/" + strconv.Itoa(port) + "/" + customRow.ownerHost,
		ServerName: name,
	}, true
}
