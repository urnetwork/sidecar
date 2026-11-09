package tlsedgeservice

import (
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

const testRoot = "root.example"

// A clock a test sets by hand, for the parts of this package that only read the time. Tests that wait on
// timers use sidecartest's FakeClock from tlsedgeservice_test instead.
type testManualClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func newTestManualClock() *testManualClock {
	return &testManualClock{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
}

func (self *testManualClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testManualClock) Advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
}

func (self *testManualClock) After(timeout time.Duration) <-chan time.Time {
	panic("a manual clock has no timers")
}

func (self *testManualClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	panic("a manual clock has no timers")
}

var _ sidecar.Clock = (*testManualClock)(nil)

// Two networks: one with a label and an alias, one with a label alone.
type testNamesWorld struct {
	clock      *testManualClock
	names      *TlsEdgeNames
	aliasedId  sidecar.Id
	plainId    sidecar.Id
	aliasLabel string
	plainLabel string
	alias      string
}

func newTestNamesWorld() *testNamesWorld {
	world := &testNamesWorld{
		clock:      newTestManualClock(),
		aliasedId:  sidecar.NewId(),
		plainId:    sidecar.NewId(),
		aliasLabel: "k3x9qwerty",
		plainLabel: "b7plainlbl",
		alias:      "my-shop",
	}
	world.names = NewTlsEdgeNames(testRoot, world.clock)
	world.names.Apply(&TlsEdgeNameMap{
		Serial: 3,
		Entries: []*TlsEdgeNameEntry{
			{Name: world.aliasLabel, NetworkId: world.aliasedId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
			{Name: world.plainLabel, NetworkId: world.plainId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
			{Name: world.alias, NetworkId: world.aliasedId, Kind: TlsEdgeNameKindAlias, State: TlsEdgeNameStateLive},
		},
	}, true)
	return world
}

// §13.5's step 2 on labels, aliases, @ and every listed port: the target names the network's label and
// the socket name tls/<port>/<host>.
func TestTlsEdgeNamesResolveTable(t *testing.T) {
	world := newTestNamesWorld()
	cases := []struct {
		serverName string
		port       int
		networkId  sidecar.Id
		label      string
		host       string
		name       string
	}{
		{serverName: "blog." + world.plainLabel + "." + testRoot, port: 443, networkId: world.plainId, label: world.plainLabel, host: "blog", name: "tls/443/blog"},
		{serverName: world.plainLabel + "." + testRoot, port: 443, networkId: world.plainId, label: world.plainLabel, host: "@", name: "tls/443/@"},
		{serverName: "api." + world.aliasLabel + "." + testRoot, port: 8443, networkId: world.aliasedId, label: world.aliasLabel, host: "api", name: "tls/8443/api"},
		{serverName: "mqtt." + world.alias + "." + testRoot, port: 8883, networkId: world.aliasedId, label: world.aliasLabel, host: "mqtt", name: "tls/8883/mqtt"},
		{serverName: world.alias + "." + testRoot, port: 5671, networkId: world.aliasedId, label: world.aliasLabel, host: "@", name: "tls/5671/@"},
		{serverName: "mx." + world.plainLabel + "." + testRoot, port: 443, networkId: world.plainId, label: world.plainLabel, host: "mx", name: "tls/443/mx"},
		// case and one trailing dot, which NormalizeSni takes off
		{serverName: "Blog." + "B7PLAINLBL." + "Root.Example.", port: 443, networkId: world.plainId, label: world.plainLabel, host: "blog", name: "tls/443/blog"},
	}
	for _, c := range cases {
		target, ok := world.names.Resolve(c.serverName, c.port)
		if !ok {
			t.Errorf("%s:%d did not map", c.serverName, c.port)
			continue
		}
		if target.NetworkId != c.networkId || target.Label != c.label || target.Host != c.host || target.Port != c.port || target.Name != c.name {
			t.Errorf("%s:%d mapped to %+v", c.serverName, c.port, target)
		}
	}
}

// What maps nothing: unknown and reserved names, the root and names beside it, deeper names, ports
// tlsedge does not serve, and names no SNI could carry.
func TestTlsEdgeNamesUnmappedTable(t *testing.T) {
	world := newTestNamesWorld()
	cases := []struct {
		serverName string
		port       int
	}{
		{serverName: "probe.edge." + testRoot, port: 443},
		{serverName: "canary." + testRoot, port: 443},
		{serverName: "ns1." + testRoot, port: 443},
		{serverName: "blog.unknownlbl." + testRoot, port: 443},
		{serverName: testRoot, port: 443},
		{serverName: "", port: 443},
		{serverName: "blog." + world.plainLabel + ".other.example", port: 443},
		{serverName: world.plainLabel + "x." + testRoot, port: 443},
		{serverName: "a.team." + world.plainLabel + "." + testRoot, port: 443},
		{serverName: "blog." + world.plainLabel + "." + testRoot, port: 80},
		{serverName: "blog." + world.plainLabel + "." + testRoot, port: 8080},
		{serverName: "blog." + world.plainLabel + "." + testRoot + "..", port: 443},
		{serverName: "bl_og." + world.plainLabel + "." + testRoot, port: 443},
		{serverName: "-blog." + world.plainLabel + "." + testRoot, port: 443},
	}
	for _, c := range cases {
		if target, ok := world.names.Resolve(c.serverName, c.port); ok {
			t.Errorf("%q:%d mapped to %+v", c.serverName, c.port, target)
		}
	}
}

// A map with no snapshot resolves nothing, and a change applied before one is dropped.
func TestTlsEdgeNamesEmptyUntilSnapshot(t *testing.T) {
	names := NewTlsEdgeNames(testRoot, newTestManualClock())
	label := "c4snapshot"
	names.Apply(&TlsEdgeNameMap{Serial: 1, Entries: []*TlsEdgeNameEntry{
		{Name: label, NetworkId: sidecar.NewId(), Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
	}}, false)
	if names.Loaded() {
		t.Fatal("a change made the map loaded")
	}
	if _, ok := names.Resolve(label+"."+testRoot, 443); ok {
		t.Fatal("a map with no snapshot mapped a name")
	}
}

// Only a live, owned name §12.5 could issue maps: a retiring alias, a tombstoned label, an ownerless
// name, a reserved label, a label of the wrong length and an uppercase one map nothing.
func TestTlsEdgeNamesOnlyLiveRoutableNames(t *testing.T) {
	names := NewTlsEdgeNames(testRoot, newTestManualClock())
	networkId := sidecar.NewId()
	names.Apply(&TlsEdgeNameMap{Serial: 9, Entries: []*TlsEdgeNameEntry{
		{Name: "d5livelabl", NetworkId: networkId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
		{Name: "retiring-alias", NetworkId: networkId, Kind: TlsEdgeNameKindAlias, State: TlsEdgeNameStateRetiring},
		{Name: "e6tombston", NetworkId: sidecar.NewId(), Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateTombstoned},
		{Name: "f7ownerles", Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
		{Name: "canary", NetworkId: sidecar.NewId(), Kind: TlsEdgeNameKindAlias, State: TlsEdgeNameStateLive},
		{Name: "short", NetworkId: sidecar.NewId(), Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
		{Name: "G8UPPERCAS", NetworkId: sidecar.NewId(), Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
		{Name: "h9kindless", NetworkId: sidecar.NewId(), Kind: "other", State: TlsEdgeNameStateLive},
	}}, true)
	if _, ok := names.Resolve("d5livelabl."+testRoot, 443); !ok {
		t.Fatal("the live label did not map")
	}
	for _, name := range []string{"retiring-alias", "e6tombston", "f7ownerles", "canary", "short", "g8uppercas", "h9kindless"} {
		if target, ok := names.Resolve("www."+name+"."+testRoot, 443); ok {
			t.Errorf("%s mapped to %+v", name, target)
		}
	}
}

// A change replaces its name's entry and leaves every other: a label tombstoned stops mapping, and so
// does its network's alias, while another network's names keep mapping.
func TestTlsEdgeNamesChangesApply(t *testing.T) {
	world := newTestNamesWorld()
	world.names.Apply(&TlsEdgeNameMap{Serial: 4, Entries: []*TlsEdgeNameEntry{
		{Name: world.aliasLabel, NetworkId: world.aliasedId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateTombstoned},
	}}, false)
	if serial, _ := world.names.Serials(); serial != 4 {
		t.Fatalf("serial %d", serial)
	}
	if _, ok := world.names.Resolve("api."+world.aliasLabel+"."+testRoot, 443); ok {
		t.Fatal("a tombstoned label mapped")
	}
	if _, ok := world.names.Resolve("api."+world.alias+"."+testRoot, 443); ok {
		t.Fatal("an alias of a network with no live label mapped")
	}
	if _, ok := world.names.Resolve("blog."+world.plainLabel+"."+testRoot, 443); !ok {
		t.Fatal("another network's label stopped mapping")
	}

	// a new label lands with its change
	newId := sidecar.NewId()
	world.names.Apply(&TlsEdgeNameMap{Serial: 5, Entries: []*TlsEdgeNameEntry{
		{Name: "j1newlabel", NetworkId: newId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
	}}, false)
	target, ok := world.names.Resolve("j1newlabel."+testRoot, 443)
	if !ok || target.NetworkId != newId {
		t.Fatalf("the new label mapped to %+v, %v", target, ok)
	}

	// a snapshot replaces everything
	world.names.Apply(&TlsEdgeNameMap{Serial: 7, RestoreSerial: 6, Entries: []*TlsEdgeNameEntry{
		{Name: "j1newlabel", NetworkId: newId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive},
	}}, true)
	if _, ok := world.names.Resolve("blog."+world.plainLabel+"."+testRoot, 443); ok {
		t.Fatal("a name the snapshot lacks still mapped")
	}
	if serial, restoreSerial := world.names.Serials(); serial != 7 || restoreSerial != 6 {
		t.Fatalf("serials %d, %d", serial, restoreSerial)
	}
}

// §12.9: a suspended zone maps none of its names until its until passes, and a withheld host and the
// hosts below it map nothing while the zone's other hosts map.
func TestTlsEdgeNamesSuspensions(t *testing.T) {
	clock := newTestManualClock()
	names := NewTlsEdgeNames(testRoot, clock)
	suspendedId := sidecar.NewId()
	withheldId := sidecar.NewId()
	names.Apply(&TlsEdgeNameMap{Serial: 2, Entries: []*TlsEdgeNameEntry{
		{
			Name: "k2suspendd", NetworkId: suspendedId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive,
			ZoneSuspended: true, ZoneSuspendUntil: clock.Now().Add(time.Hour),
		},
		{
			Name: "l3withheld", NetworkId: withheldId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive,
			WithheldHosts: []string{"shop", "a.blog"},
		},
	}}, true)
	for _, serverName := range []string{"k2suspendd." + testRoot, "www.k2suspendd." + testRoot, "shop.l3withheld." + testRoot} {
		if _, ok := names.Resolve(serverName, 443); ok {
			t.Errorf("%s mapped while suspended", serverName)
		}
	}
	for _, serverName := range []string{"l3withheld." + testRoot, "blog.l3withheld." + testRoot, "shopping.l3withheld." + testRoot} {
		if _, ok := names.Resolve(serverName, 443); !ok {
			t.Errorf("%s did not map", serverName)
		}
	}
	clock.Advance(time.Hour)
	if _, ok := names.Resolve("www.k2suspendd."+testRoot, 443); !ok {
		t.Fatal("a zone suspension past its until still held")
	}

	// a suspension with no until holds until a change lifts it
	names.Apply(&TlsEdgeNameMap{Serial: 3, Entries: []*TlsEdgeNameEntry{
		{Name: "k2suspendd", NetworkId: suspendedId, Kind: TlsEdgeNameKindLabel, State: TlsEdgeNameStateLive, ZoneSuspended: true},
	}}, false)
	clock.Advance(365 * 24 * time.Hour)
	if _, ok := names.Resolve("www.k2suspendd."+testRoot, 443); ok {
		t.Fatal("a suspension with no until lapsed")
	}
}

// Readers resolve while a writer applies changes, with no lock between them; the race detector holds
// the claim.
func TestTlsEdgeNamesConcurrentReadersAndWriter(t *testing.T) {
	world := newTestNamesWorld()
	done := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if _, ok := world.names.Resolve("blog."+world.plainLabel+"."+testRoot, 443); !ok {
					t.Error("a stable name stopped mapping during changes")
					return
				}
			}
		}()
	}
	for serial := uint64(4); serial < 200; serial += 1 {
		world.names.Apply(&TlsEdgeNameMap{Serial: serial, Entries: []*TlsEdgeNameEntry{
			{Name: world.alias, NetworkId: world.aliasedId, Kind: TlsEdgeNameKindAlias, State: TlsEdgeNameStateLive, ZoneSuspended: serial%2 == 0},
		}}, false)
	}
	close(done)
	readers.Wait()
}
