package sidecartest

// §2.8's rows for the search index (SEARCH-M10-41; I-18, I-19): evs-26, what evs sees of the index, and connect-5, what
// relays and api see of remote search, are live rows §11.14 owns; and every index value a server sees is held to the
// row that names it, in the list's own words and in the schema guard's map: the head's and a push's index_epoch to evs-3
// and evs-12, the CUT flag to evs-12, and versioning 2 to evs-11. A row rewritten so it no longer says one, or a map
// entry moved off its row, fails here as well as in §22.7's guard.

import (
	"path/filepath"
	"strings"
	"testing"
)

// Each index value, the row that must name it, and the words the row says it in.
var searchMetadataValues = []struct {
	value string
	row   string
	words []string
}{
	{value: "EvsHead.index_epoch", row: "evs-3", words: []string{"index_epoch, the version of its newest CUT"}},
	{value: "EvsPush.index_epoch", row: "evs-12", words: []string{"an index push's or CUT's index_epoch"}},
	{value: "EvsPushFlag.EVS_PUSH_CUT", row: "evs-12", words: []string{"CLOSURE, DROP or CUT"}},
	{value: "EvsEntryVersion.versioning", row: "evs-11", words: []string{"versioning setting (0 kept, 1 versionless, 2 the search index's"}},
	{value: "EvsVersioning.EVS_VERSIONING_INDEX", row: "evs-11", words: []string{"2 the search index's"}},
}

// The rows' own words for what they add, which a rewrite must keep saying.
var searchMetadataRowWords = map[string][]string{
	"evs-26":    {"versioning value 2", "nothing else of a query, term, candidate, result or result count"},
	"connect-5": {"every search request a 4,016 B body", "steps times 16,384 B", "never a query, term, filter, repo named, hit, snippet or result count"},
}

func TestSearchMetadataRowsNameTheIndex(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	for rowId, words := range searchMetadataRowWords {
		row := list.Row(rowId)
		if row == nil || !row.Live() {
			t.Errorf("§2.8 holds no live %s", rowId)
			continue
		}
		if row.Owner != "§11.14" {
			t.Errorf("%s's owner is %q, not §11.14", rowId, row.Owner)
		}
		for _, word := range words {
			if !strings.Contains(row.Store+"\n"+row.Sees+"\n"+row.Why, word) {
				t.Errorf("%s no longer says %q", rowId, word)
			}
		}
	}
	listPath, err := findMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	fieldMap, areaFields, err := readSchemaGuardMap(filepath.Dir(listPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range searchMetadataValues {
		row := list.Row(value.row)
		if row == nil || !row.Live() {
			t.Errorf("%s: §2.8 holds no live %s", value.value, value.row)
			continue
		}
		for _, word := range value.words {
			if !strings.Contains(row.Sees, word) {
				t.Errorf("%s: %s no longer says %q", value.value, value.row, word)
			}
		}
		mapped := fieldMap.Fields[value.value]
		if mapped == "" {
			mapped = fieldMap.EnumValues[value.value]
		}
		if area := areaFields[value.value]; mapped == "" && area != nil {
			mapped = area.Row
		}
		if mapped != value.row {
			t.Errorf("the schema guard maps %s to %q, not %s", value.value, mapped, value.row)
		}
	}
}
