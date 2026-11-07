package sidecartest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A list with one live and one withdrawn row, which each planted test breaks in one way.
const testMetadataListBody = `# metadata_list.yml v1; a comment the reader keeps out of every row
evs-1:
  service: evs
  store: repo/<repo> (metadata cluster); Redis {evsq_<repo_id>}
  sees: repo_id
  why: "a value: quoted as v7 made every row"
  ttl: the repo's life
  owner: §11.8
evs-2:
  withdrawn: no such value now
`

// The test's list with one piece of text replaced.
func plantedMetadataList(t *testing.T, old string, new string) []byte {
	t.Helper()
	if !strings.Contains(testMetadataListBody, old) {
		t.Fatalf("the test list holds no %q", old)
	}
	return []byte(strings.Replace(testMetadataListBody, old, new, 1))
}

// Parses and wants an error that says want.
func wantMetadataListError(t *testing.T, data []byte, want string) {
	t.Helper()
	list, err := ParseMetadataList(data)
	if err == nil {
		t.Errorf("parsed %d rows, and want an error naming %q", len(list.Rows), want)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %q", err, want)
	}
}

// The families a list names, of one kind, whichever row names them.
func testFamilyNames(list *MetadataList, kind MetadataFamilyKind) []string {
	names := []string{}
	for _, row := range list.LiveRows() {
		for _, family := range row.Families() {
			if family.Kind == kind && !slices.Contains(names, family.Name) {
				names = append(names, family.Name)
			}
		}
	}
	return names
}

// Counts are printed and not pinned, so a later version of the list passes here. Withdrawn ids stay,
// because citations resolve through them.
func TestMetadataListParses(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("metadata_list.yml %s: %d rows, %d live, %d withdrawn", list.Version, len(list.Rows), len(list.LiveRows()), len(list.WithdrawnRows()))
	if list.Version == "" {
		t.Errorf("the list names no version on its first line")
	}
	if len(list.Rows) != len(list.LiveRows())+len(list.WithdrawnRows()) {
		t.Errorf("%d rows are neither live nor withdrawn", len(list.Rows)-len(list.LiveRows())-len(list.WithdrawnRows()))
	}
	for _, rowId := range []string{"api-12", "evs-20", "gkm-3", "ext-2", "ext-9"} {
		row := list.Row(rowId)
		if row == nil {
			t.Errorf("%s has gone, and a withdrawn row keeps its id", rowId)
		} else if row.Live() {
			t.Errorf("%s came back live, which §2.8 would have to say", rowId)
		}
	}
	for _, row := range list.LiveRows() {
		if list.Row(row.Id) != row {
			t.Errorf("%s does not find itself", row.Id)
		}
	}
}

// §22.7 names these, and a guard reading prose finds them all or it guards nothing.
func TestMetadataListNamesSection22sFamilies(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	kindNames := map[MetadataFamilyKind][]string{
		MetadataFamilyRedis: {
			"{evsq_}", "{evsl_}", "{evsh_}", "{gka_}", "{evsd_}", "{nvb_}", "{dpop_}", "{tcb_}", "{acl_}e",
		},
		MetadataFamilyObject: {
			"place/", "repo/", "head/", "log/", "pb/", "hp/", "idx/", "slot/", "pmap/", "pidx/", "spidx/",
			"hold/", "seg/", "pack/", "proj/", "projrows/", "rev/", "gkm/", "drops/", "dropscan/",
		},
		MetadataFamilyTable:  {"network_client_lease", "mail_connection_record"},
		MetadataFamilyColumn: {"helo_name"},
	}
	for kind, names := range kindNames {
		for _, name := range names {
			if rows := list.RowsNaming(MetadataFamily{Kind: kind, Name: name}); len(rows) == 0 {
				t.Errorf("no live row names the %s %s", kind, name)
			}
		}
	}
}

// The rest of §19.7's Redis tags, in the forms their sections write keys, each suffix a family of its
// own: what §22.7 calls matching a family by its prefix.
func TestMetadataListKeepsRedisSuffixesApart(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	names := testFamilyNames(list, MetadataFamilyRedis)
	for _, name := range []string{
		"{acl_}v", "{acl_}e", "{acl_}q",
		"{scp_}ver", "{scp_}hint", "{scp_}n", "{scp_}tok", "{scp_}tokrev", "{scp_}ack", "{scp_}live", "{scp_}hb",
		"{wake_}", "{wakeq_}", "{tokgen_}", "{sg_}", "{sg_}ix", "{svc_}", "{sn_}names", "{sc_}set",
		"{evsl_}v", "{tes_}", "{tes_}n", "{sq_}", "{smq_}", "{mxr_}", "{mxc_}", "{dns}serial:",
	} {
		if !slices.Contains(names, name) {
			t.Errorf("no row names %s, among %q", name, names)
		}
	}
	for _, name := range []string{"{acl_}", "{scp_}"} {
		if slices.Contains(names, name) {
			t.Errorf("%s reads as a family, which would cover every suffix under it", name)
		}
	}
}

// gkm-7's commentary writes gen/<256k+1>, which is a key under gkm/, so reading it as a family would
// pass a top-level gen/ object no row names.
func TestMetadataListReadsNoFamilyFromCommentary(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	names := testFamilyNames(list, MetadataFamilyObject)
	if slices.Contains(names, "gen/") {
		t.Errorf("gen/ reads as an object family, among %q", names)
	}
	for _, kind := range []MetadataFamilyKind{MetadataFamilyRedis, MetadataFamilyObject, MetadataFamilyTable, MetadataFamilyColumn} {
		for _, name := range testFamilyNames(list, kind) {
			if strings.ContainsAny(name, "<>() ") {
				t.Errorf("the %s %q holds a placeholder or prose", kind, name)
			}
		}
	}
	for _, name := range []string{"repo_id", "ref_id", "network_id", "client_id"} {
		if slices.Contains(testFamilyNames(list, MetadataFamilyTable), name) {
			t.Errorf("%s reads as a table", name)
		}
	}
}

// A table a store qualifies with its column gives both.
func TestMetadataRowReadsAQualifiedColumn(t *testing.T) {
	row := &MetadataRow{
		Service: "api", Store: "network_client (existing), network_client.acl_subject_client_id",
		Sees: "a value", Why: "a reason", Ttl: "a time", Owner: "§7.7",
	}
	families := row.Families()
	for _, want := range []MetadataFamily{
		{Kind: MetadataFamilyTable, Name: "network_client"},
		{Kind: MetadataFamilyColumn, Name: "acl_subject_client_id"},
	} {
		if !slices.Contains(families, want) {
			t.Errorf("no %v in %v", want, families)
		}
	}
	if slices.Contains(families, MetadataFamily{Kind: MetadataFamilyTable, Name: "acl_subject_client_id"}) {
		t.Errorf("a column reads as a table in %v", families)
	}
}

func TestMetadataRowWithdrawnNamesNothing(t *testing.T) {
	row := &MetadataRow{Withdrawn: "no upload markers; head/ and {evsq_} once"}
	if families := row.Families(); len(families) != 0 {
		t.Errorf("a withdrawn row names %v", families)
	}
}

func TestParseMetadataListReadsTheShape(t *testing.T) {
	list, err := ParseMetadataList([]byte(testMetadataListBody))
	if err != nil {
		t.Fatal(err)
	}
	if list.Version != "v1" || len(list.Rows) != 2 || list.Rows[0].Id != "evs-1" || list.Rows[1].Id != "evs-2" {
		t.Fatalf("read %q and %v", list.Version, list.Rows)
	}
	row := list.Rows[0]
	if row.Line != 2 || !row.Live() || row.Why != "a value: quoted as v7 made every row" {
		t.Errorf("read %+v", row)
	}
	if list.Rows[1].Live() || list.Rows[1].Withdrawn != "no such value now" {
		t.Errorf("read %+v", list.Rows[1])
	}
	if list.Row("evs-9") != nil {
		t.Errorf("found a row the list does not hold")
	}
}

func TestParseMetadataListRefusesADuplicateRow(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "evs-2:\n", "evs-1:\n"), "already defined")
}

func TestParseMetadataListRefusesADuplicateField(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n", "  ttl: the repo's life\n  ttl: longer\n"), "ttl")
}

func TestParseMetadataListRefusesAnUnquotedColon(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, `"a value: quoted as v7 made every row"`, "a value: unquoted"), "mapping values are not allowed")
}

func TestParseMetadataListRefusesATabIndent(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  sees: repo_id\n", "\tsees: repo_id\n"), "line 5 holds a tab")
}

func TestParseMetadataListRefusesATabInsideAValue(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "repo_id\n", "repo_id\tand more\n"), "line 5 holds a tab")
}

func TestParseMetadataListRefusesALiveRowWithoutItsFields(t *testing.T) {
	for _, line := range []string{
		"  service: evs\n",
		"  store: repo/<repo> (metadata cluster); Redis {evsq_<repo_id>}\n",
		"  sees: repo_id\n",
		"  why: \"a value: quoted as v7 made every row\"\n",
		"  ttl: the repo's life\n",
		"  owner: §11.8\n",
	} {
		name, _, _ := strings.Cut(strings.TrimSpace(line), ":")
		wantMetadataListError(t, plantedMetadataList(t, line, ""), "live row evs-1 has no "+name)
	}
}

func TestParseMetadataListRefusesAnEmptyValue(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n", "  ttl: \"\"\n"), "live row evs-1 has no ttl")
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n", "  ttl:\n"), "no plain string")
}

func TestParseMetadataListRefusesAnUnknownField(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n", "  ttl: the repo's life\n  purpose: a reason\n"), "purpose")
}

func TestParseMetadataListRefusesAValueOfAnotherType(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n", "  ttl: 7\n"), "evs-1's ttl is no plain string")
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n", "  ttl: true\n"), "evs-1's ttl is no plain string")
}

func TestParseMetadataListRefusesAWithdrawnRowWithMore(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  withdrawn: no such value now\n", "  withdrawn: no such value now\n  ttl: a day\n"), "withdrawn row evs-2 still has ttl")
}

func TestParseMetadataListRefusesALiveRowMarkedWithdrawn(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  owner: §11.8\n", "  owner: §11.8\n  withdrawn: gone\n"), "withdrawn row evs-1 still has service")
}

func TestParseMetadataListRefusesAnAlias(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "  owner: §11.8\n", "  owner: &section §11.8\n  ttl2: *section\n"), "ttl2")
	wantMetadataListError(t, plantedMetadataList(t, "  ttl: the repo's life\n  owner: §11.8\n", "  ttl: &section the repo's life\n  owner: *section\n"), "holds an alias")
}

func TestParseMetadataListRefusesAMergeKey(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "evs-2:\n  withdrawn: no such value now\n", "evs-2:\n  <<: {withdrawn: no such value now}\n"), "a merge key")
}

func TestParseMetadataListRefusesASecondDocument(t *testing.T) {
	data := append(plantedMetadataList(t, "evs-2:\n", "evs-2:\n"), []byte("---\nevs-3:\n  withdrawn: later\n")...)
	wantMetadataListError(t, data, "second document")
}

func TestParseMetadataListRefusesARowIdOfAnotherShape(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "evs-2:\n", "Evs_2:\n"), "is no row id")
}

func TestParseMetadataListRefusesARowThatIsNoMapping(t *testing.T) {
	wantMetadataListError(t, plantedMetadataList(t, "evs-2:\n  withdrawn: no such value now\n", "evs-2: withdrawn\n"), "cannot unmarshal")
}

func TestParseMetadataListRefusesAnEmptyList(t *testing.T) {
	wantMetadataListError(t, []byte("# only a comment\n"), "no document")
	wantMetadataListError(t, []byte(""), "no document")
	wantMetadataListError(t, []byte("[]\n"), "cannot unmarshal")
}

// A consumer's test runs in its own package: a replace's ../sidecar is what LoadMetadataList reads,
// and from nowhere near one it fails.
func TestLoadMetadataListFindsTheSibling(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sidecar"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sidecar", metadataListFileName), []byte(testMetadataListBody), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "server", "model")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(deep)
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	if list.Version != "v1" {
		t.Errorf("read %q", list.Version)
	}
}

func TestLoadMetadataListFailsWithNoList(t *testing.T) {
	t.Chdir(t.TempDir())
	if list, err := LoadMetadataList(); err == nil {
		t.Errorf("read %d rows from nowhere", len(list.Rows))
	}
}

func TestLoadMetadataListNamesAFileThatDoesNotParse(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, metadataListFileName), []byte("evs-1:\n  surprise: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	_, err := LoadMetadataList()
	if err == nil || !strings.Contains(err.Error(), metadataListFileName) {
		t.Errorf("error %v names no file", err)
	}
}
