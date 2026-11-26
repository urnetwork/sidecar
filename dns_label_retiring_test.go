//go:build !ios_extension

// The label table's retiring aliases (§12.5's alias and retirement rows, D-DNS-10, D-DNS-2), on every leg the table
// is on: an alias a zone answer or api's GET /sidecar/label changes or releases stays readable as retiring for its 90
// days and is gone after, across a reopen; api's tombstone times bound the aliases an answer names, a table that
// never saw them live included; an alias live again retires no more; an alias handed over with no time is bounded
// from when the table took it, once, and a file an older release wrote is bounded at its open and written at the next
// change, still in a shape that release reads. All on a clock the test moves.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// A clock the test sets, which never fires: the table reads it and waits on nothing.
type testLabelClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func newTestLabelClock() *testLabelClock {
	return &testLabelClock{now: time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)}
}

func (self *testLabelClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testLabelClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *testLabelClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// Sets the clock to at.
func (self *testLabelClock) set(at time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = at
}

// A table on clock in a fresh store, with the default settings.
func testRetiringLabelTable(t *testing.T, clock Clock) (*NetworkLabelTable, *mlsTestStore) {
	t.Helper()
	store := newMlsTestStore()
	table, err := OpenNetworkLabelTableWithSettings(store, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	return table, store
}

// The table in store again, on clock.
func reopenTestRetiringLabelTable(t *testing.T, store *mlsTestStore, clock Clock) *NetworkLabelTable {
	t.Helper()
	table, err := OpenNetworkLabelTableWithSettings(store, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// The one row table holds.
func onlyNetworkLabelRow(t *testing.T, table *NetworkLabelTable) NetworkLabelRow {
	t.Helper()
	rows := table.Networks()
	if len(rows) != 1 {
		t.Fatalf("the table holds %+v", rows)
	}
	return rows[0]
}

// What the table's file holds.
func testNetworkLabelTableFileBytes(t *testing.T, store *mlsTestStore) []byte {
	t.Helper()
	reader, err := store.Open(networkLabelTableName)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A zone answer moves the alias and then releases it: each alias it held stays a retiring alias from that answer
// on, bounded by the table's window from when it saw the alias leave, read alike after a reopen, and gone from its
// tombstone time on.
func TestNetworkLabelTableKeepsAChangedAliasForItsWindow(t *testing.T) {
	clock := newTestLabelClock()
	changed := clock.Now()
	window := DefaultNetworkLabelTableSettings().RetiringWindow
	networkId := NewId()
	table, store := testRetiringLabelTable(t, clock)
	zone := &DnsZone{NetworkId: networkId, Root: testLabelRoot + ".", Label: "a7q2m9x4k1", Alias: "team-old", Version: 1}
	if err := table.SetZoneLabel(zone); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindAlias)

	moved := *zone
	moved.Alias = "team-new"
	moved.Version = 2
	if err := table.SetZoneLabel(&moved); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, "team-new", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindRetiringAlias)
	row := onlyNetworkLabelRow(t, table)
	if want := changed.Add(window); len(row.RetiringAliases) != 1 || !row.RetiringAliasTombstoneTimes["team-old"].Equal(want) {
		t.Fatalf("the changed alias retires as %v %v, want until %s", row.RetiringAliases, row.RetiringAliasTombstoneTimes, want)
	}

	// a day on, the network releases its alias: the second retires from then, the first keeps its own end
	released := changed.Add(24 * time.Hour)
	clock.set(released)
	unaliased := moved
	unaliased.Alias = ""
	unaliased.Version = 3
	if err := table.SetZoneLabel(&unaliased); err != nil {
		t.Fatal(err)
	}
	row = onlyNetworkLabelRow(t, table)
	if !row.RetiringAliasTombstoneTimes["team-old"].Equal(changed.Add(window)) || !row.RetiringAliasTombstoneTimes["team-new"].Equal(released.Add(window)) {
		t.Fatalf("after the release the table holds %+v", row)
	}
	// an answer the same again moves no end
	clock.set(released.Add(time.Hour))
	if err := table.SetZoneLabel(&unaliased); err != nil {
		t.Fatal(err)
	}
	if again := onlyNetworkLabelRow(t, table); !equalNetworkLabelRow(again, row) {
		t.Fatalf("the same answer again moved the row to %+v from %+v", again, row)
	}

	for _, reader := range []*NetworkLabelTable{table, reopenTestRetiringLabelTable(t, store, clock)} {
		clock.set(changed.Add(window - time.Second))
		requireNetworkLabel(t, reader, "team-old", false, networkId, NetworkLabelKindRetiringAlias)
		requireNetworkLabel(t, reader, "team-new", false, networkId, NetworkLabelKindRetiringAlias)
		clock.set(changed.Add(window))
		requireNetworkLabelUnknown(t, reader, "team-old", false)
		requireNetworkLabel(t, reader, "team-new", false, networkId, NetworkLabelKindRetiringAlias)
		if row := onlyNetworkLabelRow(t, reader); len(row.RetiringAliases) != 1 || row.RetiringAliases[0] != "team-new" {
			t.Fatalf("past the first end a read holds %+v", row)
		}
		clock.set(released.Add(window))
		requireNetworkLabelUnknown(t, reader, "team-new", false)
		requireNetworkLabel(t, reader, "a7q2m9x4k1", false, networkId, NetworkLabelKindLabel)
	}

	// a write past both ends drops them from the file: read on a clock before their ends, it holds neither
	third := unaliased
	third.Alias = "team-third"
	third.Version = 4
	if err := table.SetZoneLabel(&third); err != nil {
		t.Fatal(err)
	}
	clock.set(changed)
	if row := onlyNetworkLabelRow(t, reopenTestRetiringLabelTable(t, store, clock)); len(row.RetiringAliases) != 0 || row.Alias != "team-third" {
		t.Fatalf("a write past both ends kept %+v", row)
	}
}

// GET /sidecar/label's answer names the network's retiring aliases with their tombstone times, which bound them in
// place of the table's own window: the alias the table saw leave takes api's earlier end, one it never saw live
// resolves until its end, one already past its end never resolves, and an answer naming no retiring alias, as an
// older api's, keeps what the table holds. An answer whose retiring alias is not a label changes nothing.
func TestNetworkLabelTableTakesApisTombstoneTimes(t *testing.T) {
	clock := newTestLabelClock()
	now := clock.Now()
	networkId := NewId()
	table, _ := testRetiringLabelTable(t, clock)
	if err := table.SetZoneLabel(&DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "k7q2m9x4a1", Alias: "team-old", Version: 1}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	answer := func(body string) *SidecarApi {
		return newTestSidecarApi(t, answerWith(http.StatusOK, body))
	}
	stamp := func(at time.Time) string {
		return at.Format(time.RFC3339Nano)
	}
	oldEnd := now.Add(30 * 24 * time.Hour)
	olderEnd := now.Add(10 * 24 * time.Hour)
	body := `{"network_id":"` + networkId.String() + `","label":"k7q2m9x4a1","alias":"team-new","retiring_aliases":[` +
		`{"alias":"Team-Old","tombstone_time":"` + stamp(oldEnd) + `"},` +
		`{"alias":"team-older","tombstone_time":"` + stamp(olderEnd) + `"},` +
		`{"alias":"team-gone","tombstone_time":"` + stamp(now.Add(-time.Hour)) + `"}]}`
	if err := table.Refresh(ctx, answer(body), testLabelRoot, networkId, "team-name"); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, "team-new", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindRetiringAlias)
	requireNetworkLabel(t, table, "team-older", false, networkId, NetworkLabelKindRetiringAlias)
	requireNetworkLabelUnknown(t, table, "team-gone", false)
	row := onlyNetworkLabelRow(t, table)
	if !row.RetiringAliasTombstoneTimes["team-old"].Equal(oldEnd) || !row.RetiringAliasTombstoneTimes["team-older"].Equal(olderEnd) {
		t.Fatalf("the answer's ends were not taken: %+v", row)
	}

	// an older api names none, and the table keeps what it holds
	clock.set(now.Add(time.Hour))
	if err := table.Refresh(ctx, answer(`{"network_id":"`+networkId.String()+`","label":"k7q2m9x4a1","alias":"team-new"}`), testLabelRoot, networkId, "team-name"); err != nil {
		t.Fatal(err)
	}
	if again := onlyNetworkLabelRow(t, table); !equalNetworkLabelRow(again, row) {
		t.Fatalf("an answer naming none moved the row to %+v from %+v", again, row)
	}

	notLabel := `{"network_id":"` + networkId.String() + `","label":"k7q2m9x4a1","alias":"team-new","retiring_aliases":[{"alias":"not a label","tombstone_time":"` + stamp(oldEnd) + `"}]}`
	if err := table.Refresh(ctx, answer(notLabel), testLabelRoot, networkId, "team-name"); !errors.Is(err, ErrSidecarApiReply) {
		t.Fatalf("a retiring alias that is no label answered %v", err)
	}
	if again := onlyNetworkLabelRow(t, table); !equalNetworkLabelRow(again, row) {
		t.Fatalf("a refused answer moved the row to %+v", again)
	}

	clock.set(olderEnd)
	requireNetworkLabelUnknown(t, table, "team-older", false)
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindRetiringAlias)
	clock.set(oldEnd)
	requireNetworkLabelUnknown(t, table, "team-old", false)
	requireNetworkLabel(t, table, "team-name", true, networkId, NetworkLabelKindLegacyName)
}

// A zone answer names the retiring aliases too, so a table that never saw an alias live, as a device enrolled after
// the change, holds it until its end; and an alias that is live again, as a reclaim makes one, retires no more while
// the one it replaced retires.
func TestNetworkLabelTableZoneNamesRetiringAliases(t *testing.T) {
	clock := newTestLabelClock()
	now := clock.Now()
	networkId := NewId()
	table, _ := testRetiringLabelTable(t, clock)
	end := now.Add(5 * 24 * time.Hour)
	zone := &DnsZone{
		NetworkId:       networkId,
		Root:            testLabelRoot,
		Label:           "a7q2m9x4k1",
		Alias:           "team-new",
		RetiringAliases: []NetworkLabelRetiringAlias{{Alias: "team-old", TombstoneTime: end}},
		Version:         4,
	}
	if err := table.SetZoneLabel(zone); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindRetiringAlias)
	if row := onlyNetworkLabelRow(t, table); !row.RetiringAliasTombstoneTimes["team-old"].Equal(end) {
		t.Fatalf("the zone's end was not taken: %+v", row)
	}

	back := *zone
	back.Alias = "team-old"
	back.RetiringAliases = nil
	back.Version = 5
	if err := table.SetZoneLabel(&back); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, table, "team-new", false, networkId, NetworkLabelKindRetiringAlias)
	if row := onlyNetworkLabelRow(t, table); len(row.RetiringAliases) != 1 || row.RetiringAliases[0] != "team-new" {
		t.Fatalf("the alias live again still retires: %+v", row)
	}
	clock.set(end.Add(time.Hour))
	requireNetworkLabel(t, table, "team-old", false, networkId, NetworkLabelKindAlias)
}

// An alias handed over with no time, as SetNetwork takes one, is bounded by the window from when the table took it,
// and handing it over again keeps that end. A file an older release wrote, whose retiring aliases have no time, is
// bounded at its open and written at the next change, which an unchanged answer is then, and the file keeps
// format 1 with its retiring aliases a list of names, so that release still reads it.
func TestNetworkLabelTableBoundsAnAliasWithNoTime(t *testing.T) {
	clock := newTestLabelClock()
	taken := clock.Now()
	window := DefaultNetworkLabelTableSettings().RetiringWindow
	networkId := NewId()
	table, _ := testRetiringLabelTable(t, clock)
	row := NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "a7q2m9x4k1", Alias: "team-live", RetiringAliases: []string{"team-old"}}
	if err := table.SetNetwork(row); err != nil {
		t.Fatal(err)
	}
	clock.set(taken.Add(time.Hour))
	if err := table.SetNetwork(row); err != nil {
		t.Fatal(err)
	}
	if held := onlyNetworkLabelRow(t, table); !held.RetiringAliasTombstoneTimes["team-old"].Equal(taken.Add(window)) {
		t.Fatalf("handed over again the alias retires until %v", held.RetiringAliasTombstoneTimes)
	}

	// an older release's file: format 1, its retiring aliases names with no time
	older := newMlsTestStore()
	writer, err := older.Create(networkLabelTableName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`{"format":1,"rows":[{"root":"` + testLabelRoot + `","network_id":"` + networkId.String() +
		`","label":"a7q2m9x4k1","alias":"team-live","retiring_aliases":["team-old"]}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	opened := taken.Add(2 * time.Hour)
	clock.set(opened)
	reopened := reopenTestRetiringLabelTable(t, older, clock)
	requireNetworkLabel(t, reopened, "team-old", false, networkId, NetworkLabelKindRetiringAlias)
	if held := onlyNetworkLabelRow(t, reopened); !held.RetiringAliasTombstoneTimes["team-old"].Equal(opened.Add(window)) {
		t.Fatalf("the open bounded the older file's alias until %v", held.RetiringAliasTombstoneTimes)
	}
	if err := reopened.SetZoneLabel(&DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "team-live", Version: 1}); err != nil {
		t.Fatal(err)
	}
	type olderRow struct {
		Root            string   `json:"root"`
		Label           string   `json:"label"`
		Alias           string   `json:"alias"`
		RetiringAliases []string `json:"retiring_aliases"`
	}
	olderFile := &struct {
		Format int        `json:"format"`
		Rows   []olderRow `json:"rows"`
	}{}
	data := testNetworkLabelTableFileBytes(t, older)
	if err := json.Unmarshal(data, olderFile); err != nil || olderFile.Format != 1 || len(olderFile.Rows) != 1 ||
		len(olderFile.Rows[0].RetiringAliases) != 1 || olderFile.Rows[0].RetiringAliases[0] != "team-old" {
		t.Fatalf("an older release reads the written file as %+v (%v): %s", olderFile, err, data)
	}
	clock.set(taken)
	if held := onlyNetworkLabelRow(t, reopenTestRetiringLabelTable(t, older, clock)); !held.RetiringAliasTombstoneTimes["team-old"].Equal(opened.Add(window)) {
		t.Fatalf("the open's bound was not written: %s", data)
	}
	clock.set(opened.Add(window))
	requireNetworkLabelUnknown(t, reopenTestRetiringLabelTable(t, older, clock), "team-old", false)
}

// With no window a table keeps no alias it saw leave, while the ends api gives still stand.
func TestNetworkLabelTableWithNoWindowKeepsOnlyApisEnds(t *testing.T) {
	clock := newTestLabelClock()
	networkId := NewId()
	table, err := OpenNetworkLabelTableWithSettings(newMlsTestStore(), &NetworkLabelTableSettings{RetiringWindow: 0}, clock)
	if err != nil {
		t.Fatal(err)
	}
	zone := &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "team-old", Version: 1}
	if err := table.SetZoneLabel(zone); err != nil {
		t.Fatal(err)
	}
	moved := *zone
	moved.Alias = "team-new"
	moved.RetiringAliases = []NetworkLabelRetiringAlias{{Alias: "team-older", TombstoneTime: clock.Now().Add(time.Hour)}}
	moved.Version = 2
	if err := table.SetZoneLabel(&moved); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabelUnknown(t, table, "team-old", false)
	requireNetworkLabel(t, table, "team-older", false, networkId, NetworkLabelKindRetiringAlias)
}
