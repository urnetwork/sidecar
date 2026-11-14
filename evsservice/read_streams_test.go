// EVS1-M6-01's server tests on T2's fakes, through the engine's guard: a streams read refuses any other field beside
// its refs, more refs than its bound, a ref named twice, and a repo that is not record-class, each 400 INVALID before
// anything is read past the repo; and the moved listing reads only the refs past the value and those the hash lacks,
// or every ref with all set for a value past the sequence or an unreadable sequence or hash. The streams
// read end to end, its versions, more and the budget, runs through the client on record_evs_test.go's world
// (evs_streams_test.go at the root).

package evsservice

import (
	"net/http"
	"slices"
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

// The moved form's choice of heads: the refs past the value and those the hash lacks, or every ref with all set for a
// value past the sequence, an unreadable sequence or an unreadable hash; and its value's parse.
func TestMovedRefsCandidates(t *testing.T) {
	a, b, c := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	refIds := []sidecar.Id{a, b, c}
	sequences := map[sidecar.Id]uint64{a: 10, b: 20, c: 30}
	cases := []struct {
		name         string
		movedAfter   uint64
		sequence     uint64
		sequenceRead bool
		sequences    map[sidecar.Id]uint64
		hashRead     bool
		want         []sidecar.Id
		all          bool
	}{
		{name: "past 15", movedAfter: 15, sequence: 30, sequenceRead: true, sequences: sequences, hashRead: true, want: []sidecar.Id{b, c}},
		{name: "past the newest", movedAfter: 30, sequence: 30, sequenceRead: true, sequences: sequences, hashRead: true, want: []sidecar.Id{}},
		{name: "past the sequence, a restart's", movedAfter: 31, sequence: 30, sequenceRead: true, sequences: sequences, hashRead: true, want: refIds, all: true},
		{name: "no sequence read", movedAfter: 15, sequences: sequences, hashRead: true, want: refIds, all: true},
		{name: "no hash read", movedAfter: 15, sequence: 30, sequenceRead: true, hashRead: false, want: refIds, all: true},
		// read to tell whether it stands: serveRefs answers every ref when it does
		{name: "a ref the hash lacks", movedAfter: 15, sequence: 30, sequenceRead: true, sequences: map[sidecar.Id]uint64{a: 10, b: 20}, hashRead: true, want: []sidecar.Id{b, c}},
	}
	for _, c := range cases {
		candidates, all := movedRefCandidates(c.movedAfter, c.sequence, c.sequenceRead, c.sequences, c.hashRead, refIds)
		if all != c.all || !slices.Equal(candidates, c.want) {
			t.Errorf("%s: %v, all %t", c.name, candidates, all)
		}
	}
	if value, ok := parseMovedAfter("15"); !ok || value != 15 {
		t.Errorf("15 parses as %d, %t", value, ok)
	}
	for _, bad := range []string{"fifteen", "", "-1", "18446744073709551616"} {
		if _, ok := parseMovedAfter(bad); ok {
			t.Errorf("%q parses", bad)
		}
	}
}
