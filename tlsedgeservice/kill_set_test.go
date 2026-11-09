package tlsedgeservice

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A {tes_} hash value for entry.
func testKillValue(t *testing.T, entry *sidecar.TlsKillEntry) []byte {
	t.Helper()
	value, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// §13.9's merge: a kill holds while its row or its key holds it, and only once neither does is it
// dropped; a kill whose until has passed refuses nothing, whichever still holds it.
func TestTlsKillSetMerge(t *testing.T) {
	clock := newTestManualClock()
	until := clock.Now().Add(time.Hour)
	cases := []struct {
		name  string
		row   bool
		key   bool
		until time.Time
		kills bool
	}{
		{name: "row only", row: true, kills: true},
		{name: "key only", key: true, kills: true},
		{name: "both", row: true, key: true, kills: true},
		{name: "neither"},
		{name: "row only, until ahead", row: true, until: until, kills: true},
		{name: "key only, until ahead", key: true, until: until, kills: true},
	}
	for _, c := range cases {
		kills := NewTlsKillSet(clock)
		networkId := sidecar.NewId()
		rows := []*sidecar.TlsSuspendArgs{}
		if c.row {
			rows = append(rows, &sidecar.TlsSuspendArgs{NetworkId: networkId, Host: "blog", Reason: "case", Until: c.until})
		}
		kills.SetRows(rows)
		fieldValues := map[string][]byte{}
		if c.key {
			fieldValues["blog"] = testKillValue(t, &sidecar.TlsKillEntry{Host: "blog", Reason: "case", Until: c.until})
		}
		kills.SetKey(networkId, fieldValues)
		if got := kills.Kills(networkId, "blog"); got != c.kills {
			t.Errorf("%s: kills %v", c.name, got)
		}
		if kills.Kills(networkId, "shop") || kills.Kills(sidecar.NewId(), "blog") {
			t.Errorf("%s: the kill reached another host or network", c.name)
		}
	}

	// until passed: neither place's entry refuses, though both still hold it
	kills := NewTlsKillSet(clock)
	networkId := sidecar.NewId()
	kills.SetRows([]*sidecar.TlsSuspendArgs{{NetworkId: networkId, Host: sidecar.TlsKillAllHosts, Reason: "case", Until: until}})
	kills.SetKey(networkId, map[string][]byte{
		sidecar.TlsKillAllHosts: testKillValue(t, &sidecar.TlsKillEntry{Host: sidecar.TlsKillAllHosts, Reason: "case", Until: until}),
	})
	if !kills.Kills(networkId, "anything") {
		t.Fatal("* did not kill every host")
	}
	clock.Advance(time.Hour)
	if kills.Kills(networkId, "anything") {
		t.Fatal("a kill past its until refused")
	}
}

// A Postgres restore lifts nothing: the rows going missing leave the key's kill standing, a lost key
// leaves the row's, and only both gone drops it.
func TestTlsKillSetRestoreLiftsNothing(t *testing.T) {
	kills := NewTlsKillSet(newTestManualClock())
	networkId := sidecar.NewId()
	kills.SetRows([]*sidecar.TlsSuspendArgs{{NetworkId: networkId, Host: "blog", Reason: "case"}})
	kills.SetKey(networkId, map[string][]byte{"blog": testKillValue(t, &sidecar.TlsKillEntry{Host: "blog", Reason: "case"})})

	if changed := kills.SetRows(nil); !slices.Equal(changed, []sidecar.Id{networkId}) {
		t.Fatalf("changed %v", changed)
	}
	if !kills.Kills(networkId, "blog") {
		t.Fatal("a restore's missing row lifted a kill its key holds")
	}
	if !slices.Contains(kills.NetworkIds(), networkId) {
		t.Fatal("a network held only by its key is not reread")
	}

	kills.SetRows([]*sidecar.TlsSuspendArgs{{NetworkId: networkId, Host: "blog", Reason: "case"}})
	kills.SetKey(networkId, map[string][]byte{})
	if !kills.Kills(networkId, "blog") {
		t.Fatal("a lost key lifted a kill its row holds")
	}

	kills.SetRows(nil)
	if kills.Kills(networkId, "blog") {
		t.Fatal("a kill neither place holds still refused")
	}
	if slices.Contains(kills.NetworkIds(), networkId) {
		t.Fatal("a network with no kill left is still reread")
	}
}

// What a {tes_} hash cannot say clearly fails closed: a value that does not parse kills its field's
// host, a value naming another host kills both, and an empty field or host kills every host.
func TestParseTlsKillHashFailsClosed(t *testing.T) {
	clock := newTestManualClock()
	kills := NewTlsKillSet(clock)
	networkId := sidecar.NewId()
	kills.SetKey(networkId, map[string][]byte{
		"blog": []byte("not json"),
		"shop": testKillValue(t, &sidecar.TlsKillEntry{Host: "api", Reason: "case"}),
	})
	for _, host := range []string{"blog", "shop", "api"} {
		if !kills.Kills(networkId, host) {
			t.Errorf("%s was not killed", host)
		}
	}
	if kills.Kills(networkId, "www") {
		t.Fatal("a host no field names was killed")
	}

	otherId := sidecar.NewId()
	kills.SetKey(otherId, map[string][]byte{"": testKillValue(t, &sidecar.TlsKillEntry{Reason: "case"})})
	if !kills.Kills(otherId, "www") {
		t.Fatal("an entry with no host spared a host")
	}
}

// A set is loaded only once its rows have been read, and a key read that changes nothing says so.
func TestTlsKillSetLoadedAndChanges(t *testing.T) {
	kills := NewTlsKillSet(newTestManualClock())
	networkId := sidecar.NewId()
	if kills.Loaded() {
		t.Fatal("a set with no rows read is loaded")
	}
	value := map[string][]byte{"blog": testKillValue(t, &sidecar.TlsKillEntry{Host: "blog", Reason: "case"})}
	if !kills.SetKey(networkId, value) {
		t.Fatal("a new key read reported no change")
	}
	if kills.SetKey(networkId, value) {
		t.Fatal("the same key read reported a change")
	}
	if kills.Loaded() {
		t.Fatal("a key read alone loaded the set")
	}
	kills.SetRows(nil)
	if !kills.Loaded() {
		t.Fatal("a rows read did not load the set")
	}
}
