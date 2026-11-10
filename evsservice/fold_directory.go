// A directory's fold (§11.7's fold, directory and epochs rows): its entry's name table {child token, kind, sealed
// name}, as of the newest delta applied, names_through. A push's directory change is a delta {names added, child
// tokens removed} that merges without a path-level CAS, since each child's own path is checked, so a fold applies
// every delta past what the table holds, in version order: a newer delta never replaces an older one. A creation,
// base_entry_version 0, starts the table again, carrying nothing, and so does a delta over a marker, which 5g
// never commits.
//
// Rows stay sorted by token, so two folds of one range write equal bytes. A removed token drops the row whatever
// epoch it is tagged with, since a delta removing a child lists its token in each epoch that may hold it (§11.6's
// read row). While sources stand, a table carried from a source epoch tags each of its untagged rows with that
// epoch, rows already carried keeping theirs until the copy translates them, and the bound counts a carried row at
// its untagged size (sidecar.EvsNameTableBoundByteCount).
//
// evs reads no name: rows are opaque bytes here, and readers check each one against its token (§11.7).

package evsservice

import (
	"bytes"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A directory's delta merged into its entry: past a creation, a marker or anything but a table it starts from an
// empty table; removed tokens drop their rows, added names replace theirs, and names_through becomes the delta's
// commit version. The entry's drop mark stays, and a replaced marker's carried ids alarm (format1_guard.go).
func applyFoldDelta(entry *protocol.EvsIndexEntry, event *foldEvent, log sidecar.Logger) *protocol.EvsIndexEntry {
	delta := event.entryVersion.GetNames()
	if event.change.BaseEntryVersion == 0 || entry.GetMarker() != nil || entry.GetNames() == nil {
		alarmCarriedIdsDropped(log, entry.GetMarker(), "a directory's delta")
		entry = &protocol.EvsIndexEntry{Names: &protocol.EvsNameTable{}, DropMark: entry.GetDropMark()}
	}
	tokenRows := map[sidecar.EvsToken]*protocol.EvsName{}
	for _, row := range entry.GetNames().GetNames() {
		if token, err := sidecar.EvsTokenFromBytes(row.GetToken()); err == nil {
			tokenRows[token] = row
		}
	}
	for _, removed := range delta.GetRemovedTokens() {
		if token, err := sidecar.EvsTokenFromBytes(removed); err == nil {
			delete(tokenRows, token)
		}
	}
	for _, row := range delta.GetNames() {
		if token, err := sidecar.EvsTokenFromBytes(row.GetToken()); err == nil {
			tokenRows[token] = proto.Clone(row).(*protocol.EvsName)
		}
	}
	entry.Names = &protocol.EvsNameTable{Names: sortedEvsNameRows(tokenRows)}
	entry.NamesThrough = event.commitVersion
	entry.Versions = nil
	entry.Marker = nil
	return entry
}

// A table's rows, by token.
func sortedEvsNameRows(tokenRows map[sidecar.EvsToken]*protocol.EvsName) []*protocol.EvsName {
	rows := make([]*protocol.EvsName, 0, len(tokenRows))
	for _, row := range tokenRows {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i int, j int) bool { return bytes.Compare(rows[i].GetToken(), rows[j].GetToken()) < 0 })
	return rows
}

// A source epoch's entry as the current epoch carries it (§11.7's epochs row): its folded versions, drop mark and
// table, each untagged row tagged with the source's epoch, a row already carried keeping its own.
func carryEvsIndexEntry(source *protocol.EvsIndexEntry, sourceEpoch uint64) *protocol.EvsIndexEntry {
	carried := proto.Clone(source).(*protocol.EvsIndexEntry)
	for _, row := range carried.GetNames().GetNames() {
		if row.GetEpoch() == 0 {
			row.Epoch = sourceEpoch
		}
	}
	return carried
}

// Alarms when a folded table passes §11.7's directory bound, 4,096 children or 448 KiB of rows, a carried row counted
// untagged: 5g checks the bound before any delta commits, so this is a fault. The fold still writes what committed.
func checkFoldedTableBound(table *protocol.EvsNameTable, log sidecar.Logger) {
	childCount := len(table.GetNames())
	boundByteCount := sidecar.EvsNameTableBoundByteCount(table)
	if sidecar.EvsDirectoryMaxChildCount < childCount || sidecar.EvsNameTableMaxBoundByteCount < boundByteCount {
		log.Errorf("[evs] alarm directory_bound: a folded table of %d children and %d bytes", childCount, boundByteCount)
	}
}
