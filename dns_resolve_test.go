// ResolveNetworkLabel on the client (DNS-M2-01), T1 on every leg, sidecar_http included: D-DNS-2's
// order of label, alias and legacy name, the legacy name refused unless interactive, a retiring alias
// with its kind, another network's name refused, the empty text with one network and with two, the
// table kept across a reopen and unchanged by a failed write, and its refresh from api.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
)

const testLabelRoot = "zone.example"

// A table in a fresh store, with rows.
func testNetworkLabelTable(t *testing.T, rows ...NetworkLabelRow) (*NetworkLabelTable, *mlsTestStore) {
	t.Helper()
	store := newMlsTestStore()
	table, err := OpenNetworkLabelTable(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := table.SetNetwork(row); err != nil {
			t.Fatal(err)
		}
	}
	return table, store
}

func requireNetworkLabel(t *testing.T, resolver NetworkLabelResolver, text string, interactive bool, networkId Id, kind NetworkLabelKind) {
	t.Helper()
	gotId, gotKind, err := resolver.ResolveNetworkLabel(testLabelRoot, text, interactive)
	if err != nil || gotId != networkId || gotKind != kind {
		t.Fatalf("%q (interactive %t) resolved to %s %q (%v), want %s %q", text, interactive, gotId, gotKind, err, networkId, kind)
	}
}

func requireNetworkLabelUnknown(t *testing.T, resolver NetworkLabelResolver, text string, interactive bool) {
	t.Helper()
	if networkId, kind, err := resolver.ResolveNetworkLabel(testLabelRoot, text, interactive); !errors.Is(err, ErrNetworkLabelUnknown) {
		t.Fatalf("%q (interactive %t) resolved to %s %q (%v), want unknown", text, interactive, networkId, kind, err)
	}
}

// A label wins over an alias and a legacy name that read the same, and an alias over a legacy name:
// network B now holds the name network A was once called, and only a person's typed input ever
// reaches a legacy name.
func TestResolveNetworkLabelOrder(t *testing.T) {
	networkA := NewId()
	networkB := NewId()
	networkC := NewId()
	table, _ := testNetworkLabelTable(t,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkA, Label: "a7q2m9x4k1", LegacyName: "old-team-name"},
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkB, Label: "b3k8p2r6t0", Alias: "old-team-name", LegacyName: "old-team-name-2"},
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkC, Label: "c5n1w7d3y9", LegacyName: "b3k8p2r6t0"},
	)
	requireNetworkLabel(t, table, "a7q2m9x4k1", false, networkA, NetworkLabelKindLabel)
	requireNetworkLabel(t, table, "old-team-name", true, networkB, NetworkLabelKindAlias)
	requireNetworkLabel(t, table, "b3k8p2r6t0", true, networkB, NetworkLabelKindLabel)
	requireNetworkLabel(t, table, "old-team-name-2", true, networkB, NetworkLabelKindLegacyName)
	// ASCII case and the root's suffix change nothing
	requireNetworkLabel(t, table, " A7Q2M9X4K1.zone.example. ", false, networkA, NetworkLabelKindLabel)
}

// `.ur` and git remotes pass interactive false, and a legacy name never answers them.
func TestResolveNetworkLabelRefusesALegacyNameNotTyped(t *testing.T) {
	networkId := NewId()
	table, _ := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9x4a1", LegacyName: "billing-team"})
	requireNetworkLabelUnknown(t, table, "billing-team", false)
	requireNetworkLabel(t, table, "billing-team", true, networkId, NetworkLabelKindLegacyName)
}

// An alias in its 90 days of retiring still names its network, and says so.
func TestResolveNetworkLabelRetiringAlias(t *testing.T) {
	networkId := NewId()
	table, _ := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9x4a1", Alias: "new-name", RetiringAliases: []string{"Old-Name"}})
	requireNetworkLabel(t, table, "old-name", false, networkId, NetworkLabelKindRetiringAlias)
	requireNetworkLabel(t, table, "new-name", false, networkId, NetworkLabelKindAlias)
}

// Another network's label, a name under another root and a name no network has are unknown: the
// table holds only networks this client belongs to.
func TestResolveNetworkLabelRefusesAForeignName(t *testing.T) {
	networkId := NewId()
	table, _ := testNetworkLabelTable(t,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9x4a1"},
		NetworkLabelRow{Root: "other.example", NetworkId: NewId(), Label: "z9z9z9z9z9"},
	)
	requireNetworkLabelUnknown(t, table, "f0r31gnlab", true)
	requireNetworkLabelUnknown(t, table, "z9z9z9z9z9", true)
	requireNetworkLabelUnknown(t, table, "k7q2m9x4a1.other.example", false)
}

// The empty text is the only network, labelled or not; with two it is ambiguous and names both.
func TestResolveNetworkLabelEmptyText(t *testing.T) {
	first := NewId()
	table, _ := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: first, LegacyName: "first-network"})
	requireNetworkLabel(t, table, "", false, first, NetworkLabelKindOnly)
	// until labels exist only the empty text answers
	requireNetworkLabelUnknown(t, table, "first-network", false)

	second := NewId()
	if err := table.SetNetwork(NetworkLabelRow{Root: testLabelRoot, NetworkId: second, Label: "s3c0nd0n3x"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := table.ResolveNetworkLabel(testLabelRoot, "", false)
	ambiguous := &NetworkLabelAmbiguousError{}
	if !errors.As(err, &ambiguous) {
		t.Fatalf("the empty text with two networks answered %v", err)
	}
	if !slices.Contains(ambiguous.NetworkIds, first) || !slices.Contains(ambiguous.NetworkIds, second) || !slices.Contains(ambiguous.Names, "s3c0nd0n3x") || !slices.Contains(ambiguous.Names, first.String()) {
		t.Fatalf("named %v %v", ambiguous.NetworkIds, ambiguous.Names)
	}
	if err := table.RemoveNetwork(second); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, "", false, first, NetworkLabelKindOnly)

	empty, _ := testNetworkLabelTable(t)
	requireNetworkLabelUnknown(t, empty, "", false)
}

// A row no network can have is refused: a name two networks would share, a bad label or root.
func TestNetworkLabelTableRefusesConflictingRows(t *testing.T) {
	networkId := NewId()
	table, _ := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9x4a1", Alias: "team-alias"})
	refused := []NetworkLabelRow{
		{Root: testLabelRoot, NetworkId: NewId(), Label: "k7q2m9x4a1"},
		{Root: testLabelRoot, NetworkId: NewId(), Label: "x1x1x1x1x1", Alias: "team-alias"},
		{Root: testLabelRoot, NetworkId: NewId(), Label: "y2y2y2y2y2", RetiringAliases: []string{"k7q2m9x4a1"}},
		{Root: testLabelRoot, NetworkId: NewId(), Label: "not a label"},
		{Root: "nodot", NetworkId: NewId()},
		{Root: testLabelRoot},
	}
	for _, row := range refused {
		if err := table.SetNetwork(row); err == nil {
			t.Errorf("took %+v", row)
		}
	}
	if rows := table.Networks(); len(rows) != 1 || rows[0].NetworkId != networkId {
		t.Fatalf("rows %+v", rows)
	}
}

// What a table writes it reads back after a reopen; a write that fails changes nothing, on disk or in
// the table.
func TestNetworkLabelTableSurvivesAReopenAndAFailedWrite(t *testing.T) {
	networkId := NewId()
	table, store := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: "k7q2m9x4a1", Alias: "team-alias", LegacyName: "team-name"})
	reopened, err := OpenNetworkLabelTable(store)
	if err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, reopened, "team-alias", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, reopened, "team-name", true, networkId, NetworkLabelKindLegacyName)

	store.failWritesAfter(0)
	if err := table.SetNetwork(NetworkLabelRow{Root: testLabelRoot, NetworkId: NewId(), Label: "n3wn3wn3w0"}); err == nil {
		t.Fatal("a failed write reported success")
	}
	requireNetworkLabelUnknown(t, table, "n3wn3wn3w0", false)
	requireNetworkLabel(t, table, "", false, networkId, NetworkLabelKindOnly)
	store.failWritesAfter(-1)
	again, err := OpenNetworkLabelTable(store)
	if err != nil {
		t.Fatal(err)
	}
	if rows := again.Networks(); len(rows) != 1 {
		t.Fatalf("the store holds %d rows after a failed write", len(rows))
	}
}

// A file this release cannot read is refused rather than taken for an empty table.
func TestNetworkLabelTableRefusesAnUnreadableFile(t *testing.T) {
	for _, content := range []string{`{"format":2,"rows":[]}`, `not json`, `{"format":1,"rows":[{"root":"zone.example"}]}`} {
		store := newMlsTestStore()
		writer, err := store.Create(networkLabelTableName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Commit(); err != nil {
			t.Fatal(err)
		}
		writer.Close()
		if _, err := OpenNetworkLabelTable(store); err == nil {
			t.Errorf("opened %q", content)
		}
	}
}

// A refresh takes the label and alias api gives the network and keeps its retiring aliases; a
// refusal or an answer about another network changes nothing.
func TestNetworkLabelTableRefreshesFromApi(t *testing.T) {
	networkId := NewId()
	table, _ := testNetworkLabelTable(t, NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, RetiringAliases: []string{"older-alias"}})
	ctx := context.Background()

	refused := newTestSidecarApi(t, answerWith(http.StatusNotFound, `{"code":"not_found"}`))
	if err := table.Refresh(ctx, refused, testLabelRoot, networkId, "team-name"); err == nil {
		t.Fatal("a refusal refreshed the table")
	}
	requireNetworkLabelUnknown(t, table, "team-name", true)

	other := newTestSidecarApi(t, answerWith(http.StatusOK, `{"network_id":"`+NewId().String()+`","label":"k7q2m9x4a1"}`))
	if err := table.Refresh(ctx, other, testLabelRoot, networkId, "team-name"); !errors.Is(err, ErrSidecarApiReply) {
		t.Fatalf("an answer about another network answered %v", err)
	}
	requireNetworkLabelUnknown(t, table, "k7q2m9x4a1", false)

	transport := answerWith(http.StatusOK, `{"network_id":"`+networkId.String()+`","label":"k7q2m9x4a1","alias":"team-alias"}`)
	if err := table.Refresh(ctx, newTestSidecarApi(t, transport), testLabelRoot, networkId, "Team-Name"); err != nil {
		t.Fatal(err)
	}
	request, _ := transport.onlyRequest(t)
	if request.Method != http.MethodGet || request.URL.Path != "/sidecar/label" || request.Header.Get("Authorization") != "Bearer "+testByJwt {
		t.Fatalf("sent %s %s", request.Method, request.URL)
	}
	requireNetworkLabel(t, table, "k7q2m9x4a1", false, networkId, NetworkLabelKindLabel)
	requireNetworkLabel(t, table, "team-alias", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, table, "older-alias", false, networkId, NetworkLabelKindRetiringAlias)
	requireNetworkLabel(t, table, "team-name", true, networkId, NetworkLabelKindLegacyName)

	for _, body := range []string{`{"network_id":"` + networkId.String() + `"}`, `{"label":"k7q2m9x4a1"}`, `[]`} {
		if _, err := newTestSidecarApi(t, answerWith(http.StatusOK, body)).GetSidecarLabel(ctx); !errors.Is(err, ErrSidecarApiReply) {
			t.Errorf("%s answered %v", body, err)
		}
	}
}
