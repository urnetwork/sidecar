// EVS1-M6-01's server tests on T2's fakes, through the engine's guard: a streams read refuses any other field beside
// its refs, more refs than its bound, a ref named twice, and a repo that is not record-class, each 400 INVALID before
// anything is read past the repo; and the moved listing's filter answers only the refs past the value, or every ref
// with all set for a value past the sequence, an unreadable sequence or hash, or a ref the hash lacks. The streams
// read end to end, its versions, more and the budget, runs through the client on record_evs_test.go's world
// (evs_streams_test.go at the root).

package evsservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestReadStreamsRefusesItsShape(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	refs := []*protocol.EvsReadRef{{RefId: sidecar.NewId().Bytes()}}
	tooMany := []*protocol.EvsReadRef{}
	for range fixture.settings.ReadStreamRefMaxCount + 1 {
		tooMany = append(tooMany, &protocol.EvsReadRef{RefId: sidecar.NewId().Bytes()})
	}
	twice := []*protocol.EvsReadRef{refs[0], refs[0]}
	for name, request := range map[string]*protocol.EvsReadRequest{
		"a ref_id beside refs": {RefId: sidecar.NewId().Bytes(), Refs: refs},
		"a path beside refs":   {Refs: refs, Paths: []*protocol.EvsReadPath{{}}},
		"a slot beside refs":   {Refs: refs, SlotIds: [][]byte{make([]byte, 16)}},
		"past the bound":       {Refs: tooMany},
		"a ref named twice":    {Refs: twice},
		"a ref of 3 bytes":     {Refs: []*protocol.EvsReadRef{{RefId: []byte{1, 2, 3}}}},
		// the fixture's repo is general, whose refs are no streams
		"a general repo": {Refs: refs},
	} {
		recorder := fixture.call(token, http.MethodPost, "/read", request)
		if recorder.Code != http.StatusBadRequest || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID {
			t.Errorf("%s: status %d (%s)", name, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
}

func TestMovedRefsFilter(t *testing.T) {
	a, b, c := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	summaries := []*protocol.EvsHeadSummary{
		{RefId: a.Bytes(), PushSequence: 10}, {RefId: b.Bytes(), PushSequence: 20}, {RefId: c.Bytes(), PushSequence: 30},
	}
	sequences := map[sidecar.Id]uint64{a: 10, b: 20, c: 30}
	cases := []struct {
		name         string
		query        string
		sequence     uint64
		sequenceRead bool
		sequences    map[sidecar.Id]uint64
		hashRead     bool
		want         int
		all          bool
		ok           bool
	}{
		{name: "past 15", query: "15", sequence: 30, sequenceRead: true, sequences: sequences, hashRead: true, want: 2, ok: true},
		{name: "past the newest", query: "30", sequence: 30, sequenceRead: true, sequences: sequences, hashRead: true, want: 0, ok: true},
		{name: "past the sequence, a restart's", query: "31", sequence: 30, sequenceRead: true, sequences: sequences, hashRead: true, want: 3, all: true, ok: true},
		{name: "no sequence read", query: "15", sequenceRead: false, sequences: sequences, hashRead: true, want: 3, all: true, ok: true},
		{name: "no hash read", query: "15", sequence: 30, sequenceRead: true, hashRead: false, want: 3, all: true, ok: true},
		{name: "a ref the hash lacks", query: "15", sequence: 30, sequenceRead: true, sequences: map[sidecar.Id]uint64{a: 10, b: 20}, hashRead: true, want: 3, all: true, ok: true},
		{name: "a value that does not parse", query: "fifteen", ok: false},
	}
	for _, c := range cases {
		refs, all, ok := movedRefs(c.query, c.sequence, c.sequenceRead, c.sequences, c.hashRead, summaries)
		if ok != c.ok || (ok && (len(refs) != c.want || all != c.all)) {
			t.Errorf("%s: %d refs, all %t, ok %t", c.name, len(refs), all, ok)
		}
	}
}
