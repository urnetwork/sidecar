// EVS2-M10-05's classifier: each value EVS-FORMAT.md's format 2 chapter lists makes a push need format 2, and the
// tainted bit, which format 1 ignores, does not.

package sidecar

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

func evsFormatTestEntry(t *testing.T, entry *protocol.EvsEntryVersion) []byte {
	t.Helper()
	entryBytes, err := proto.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return entryBytes
}

func TestEvsPushNeedsFormat2ByEachValue(t *testing.T) {
	inline := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("record")}
	format1Entry := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Chain: []*protocol.EvsLocator{inline}}
	cases := []struct {
		name      string
		statement *EvsStatement
		payload   *EvsCheckedPayload
		needs     bool
	}{
		{name: "nothing", statement: &EvsStatement{Push: &protocol.EvsPush{}}, payload: &EvsCheckedPayload{}},
		{name: "a format-1 entry", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{EntryVersion: evsFormatTestEntry(t, format1Entry)}}}},
		{name: "a removal", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{}}}},
		{name: "flag 256", statement: &EvsStatement{Push: &protocol.EvsPush{Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)}}, needs: true},
		{name: "flag 512", statement: &EvsStatement{Push: &protocol.EvsPush{Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)}}, needs: true},
		{name: "field 33", statement: &EvsStatement{Push: &protocol.EvsPush{DropSha256: make([]byte, 32)}}, needs: true},
		{name: "field 34", statement: &EvsStatement{Push: &protocol.EvsPush{IndexEpoch: 1}}, needs: true},
		{name: "format-1 flags", statement: &EvsStatement{Push: &protocol.EvsPush{Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE | protocol.EvsPushFlag_EVS_PUSH_CLOSURE)}}},
		{name: "versioning 1", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{EntryVersion: evsFormatTestEntry(t, &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{inline}})}}}, needs: true},
		{name: "versioning 2", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{EntryVersion: evsFormatTestEntry(t, &protocol.EvsEntryVersion{Versioning: 2, Chain: []*protocol.EvsLocator{inline}})}}}, needs: true},
		{name: "a kind-5 locator", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{EntryVersion: evsFormatTestEntry(t, &protocol.EvsEntryVersion{Chain: []*protocol.EvsLocator{{Kind: 5, Id: make([]byte, 32)}}})}}}, needs: true},
		{name: "a staged mark", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{EntryVersion: evsFormatTestEntry(t, &protocol.EvsEntryVersion{Chain: []*protocol.EvsLocator{{Kind: 1, Id: make([]byte, 32), Staged: true}}})}}}, needs: true},
		{name: "a staged new-objects item", payload: &EvsCheckedPayload{NewObjects: []*EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: make([]byte, 32)}}}, needs: true},
		{name: "a segment new-objects item", payload: &EvsCheckedPayload{NewObjects: []*EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: make([]byte, 32)}}}},
		{name: "staged bytes", payload: &EvsCheckedPayload{Staged: []*EvsStagedSegment{{}}}, needs: true},
		{name: "a drop body", payload: &EvsCheckedPayload{Drop: &EvsCheckedDrop{}}, needs: true},
		{name: "an entry that does not parse", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{{EntryVersion: []byte{0xff, 0xff}}}}},
		{name: "a second change carrying it", payload: &EvsCheckedPayload{Changes: []*EvsCheckedChange{
			{EntryVersion: evsFormatTestEntry(t, format1Entry)},
			{EntryVersion: evsFormatTestEntry(t, &protocol.EvsEntryVersion{Versioning: 1})},
		}}, needs: true},
	}
	for _, c := range cases {
		if got := EvsPushNeedsFormat2(c.statement, c.payload); got != c.needs {
			t.Errorf("%s: needs format 2 %t, want %t", c.name, got, c.needs)
		}
	}
}

// The provenance's tainted bit rides inside the sealed commit, which format 1 ignores, so a classifier reading the
// statement and payload never sees it: a push whose only format-2 value is the bit is a format-1 push.
func TestEvsPushNeedsFormat2IgnoresTheTaintedBit(t *testing.T) {
	provenance, err := proto.Marshal(&protocol.EvsProvenance{Tainted: true})
	if err != nil {
		t.Fatal(err)
	}
	payload := &EvsCheckedPayload{SealedMetadata: provenance, Changes: []*EvsCheckedChange{{EntryVersion: evsFormatTestEntry(t, &protocol.EvsEntryVersion{
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Chain: []*protocol.EvsLocator{{Kind: 2, Inline: []byte("record")}},
	})}}}
	if EvsPushNeedsFormat2(&EvsStatement{Push: &protocol.EvsPush{}}, payload) {
		t.Fatal("the tainted bit counted as format 2")
	}
	if EvsStatementNeedsFormat2(nil) || EvsEntryVersionNeedsFormat2(nil) || EvsLocatorNeedsFormat2(nil) || EvsPushNeedsFormat2(nil, nil) {
		t.Fatal("nothing counted as format 2")
	}
}
