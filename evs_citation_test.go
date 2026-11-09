// §11.7's citation rule as a pure function with fixed vectors (§22.5's §11 row; EVS2-M10-04): testdata/evs/citation/,
// one file per case with its verdict written by hand in evsCitationCases, which another implementation reads as is;
// FS-64's and FS-68's clauses as pure cases; and plan-EVS2-slot-rename's slot-keyed rename and two-target refusal.
// evsservice/purge_candidates_test.go runs the property test over random push histories, which holds this rule and
// the purge together.

package sidecar

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/evs/citation
var evsCitationVectorFiles embed.FS

// A locator of a test version, by label: kind 1, 2 or 5, staged or not.
type evsCitationLocatorVector struct {
	Kind   uint32   `json:"kind"`
	Id     hexBytes `json:"id,omitempty"`
	Staged bool     `json:"staged,omitempty"`
}

// A test version: its versioning, chain and slots.
type evsCitationVersionVector struct {
	Versioning uint32                      `json:"versioning"`
	Chain      []*evsCitationLocatorVector `json:"chain"`
	SlotIds    []hexBytes                  `json:"slot_ids,omitempty"`
}

type evsCitationCitationVector struct {
	TokenPath hexBytes                  `json:"token_path"`
	Version   *evsCitationVersionVector `json:"version"`
	Base      *evsCitationVersionVector `json:"base"`
}

type evsCitationSourceVector struct {
	RefId     hexBytes                  `json:"ref_id,omitempty"`
	TokenPath hexBytes                  `json:"token_path"`
	Version   *evsCitationVersionVector `json:"version"`
}

type evsCitationSourcesVector struct {
	RefId              hexBytes                   `json:"ref_id"`
	Staged             []hexBytes                 `json:"staged"`
	VersionlessUploads []hexBytes                 `json:"versionless_uploads"`
	Removed            []*evsCitationSourceVector `json:"removed"`
	Reuse              []*evsCitationSourceVector `json:"reuse"`
}

// One case file of testdata/evs/citation/ (schema.yml's vectors section).
type evsCitationCaseVector struct {
	Name      string                       `json:"name"`
	Citations []*evsCitationCitationVector `json:"citations"`
	Sources   *evsCitationSourcesVector    `json:"sources"`
	Want      string                       `json:"want"`
}

// A test id by label.
func evsCitationId(label string) hexBytes {
	return evsTestBytes("citation "+label, sha256.Size)
}

// A test slot id by label.
func evsCitationSlot(label string) hexBytes {
	return evsTestBytes("citation slot "+label, 16)
}

// A test token path by label.
func evsCitationTokenPath(label string) hexBytes {
	return EvsTokenPath{evsTestToken("citation " + label)}.Bytes()
}

// Locators by short spelling: "k5:a" an unstaged kind-5 segment a, "s5:a" a staged one, "k1:a" a kind-1 one, "in" an
// inline record.
func evsCitationVersion(versioning uint32, locators []string, slots ...string) *evsCitationVersionVector {
	version := &evsCitationVersionVector{Versioning: versioning, Chain: []*evsCitationLocatorVector{}}
	for _, spelled := range locators {
		kind, label, _ := strings.Cut(spelled, ":")
		switch kind {
		case "k5":
			version.Chain = append(version.Chain, &evsCitationLocatorVector{Kind: 5, Id: evsCitationId(label)})
		case "s5":
			version.Chain = append(version.Chain, &evsCitationLocatorVector{Kind: 5, Id: evsCitationId(label), Staged: true})
		case "k1":
			version.Chain = append(version.Chain, &evsCitationLocatorVector{Kind: 1, Id: evsCitationId(label)})
		case "in":
			version.Chain = append(version.Chain, &evsCitationLocatorVector{Kind: 2})
		}
	}
	for _, slot := range slots {
		version.SlotIds = append(version.SlotIds, evsCitationSlot(slot))
	}
	return version
}

// The entry version a vector's version stands for.
func (self *evsCitationVersionVector) entry() *protocol.EvsEntryVersion {
	if self == nil {
		return nil
	}
	entry := &protocol.EvsEntryVersion{Versioning: self.Versioning, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)}
	for _, locator := range self.Chain {
		message := &protocol.EvsLocator{Kind: locator.Kind, Id: locator.Id, Staged: locator.Staged}
		if locator.Kind == 2 {
			message.Inline = evsTestBytes("inline", 32)
		}
		entry.Chain = append(entry.Chain, message)
	}
	for _, slotId := range self.SlotIds {
		entry.SlotIds = append(entry.SlotIds, slotId)
	}
	return entry
}

// The cases, each verdict written by hand. X is a 20 MiB versionless file at version k, five 4 MiB kind-5 chunks c1
// to c5 (FS-64); Y and Z are other paths.
func evsCitationCases() []*evsCitationCaseVector {
	refId := hexBytes(evsTestId("ref main").Bytes())
	k := evsCitationVersion(1, []string{"k5:c1", "k5:c2", "k5:c3", "k5:c4", "k5:c5"})
	k1 := evsCitationVersion(1, []string{"k5:c1", "k5:n2", "k5:c3", "k5:n4", "k5:c5"})
	at := func(name string, version *evsCitationVersionVector, base *evsCitationVersionVector) *evsCitationCitationVector {
		return &evsCitationCitationVector{TokenPath: evsCitationTokenPath(name), Version: version, Base: base}
	}
	sources := func(mutate func(*evsCitationSourcesVector)) *evsCitationSourcesVector {
		value := &evsCitationSourcesVector{RefId: refId, Staged: []hexBytes{}, VersionlessUploads: []hexBytes{}, Removed: []*evsCitationSourceVector{}, Reuse: []*evsCitationSourceVector{}}
		if mutate != nil {
			mutate(value)
		}
		return value
	}
	uploads := func(labels ...string) func(*evsCitationSourcesVector) {
		return func(value *evsCitationSourcesVector) {
			for _, label := range labels {
				value.VersionlessUploads = append(value.VersionlessUploads, evsCitationId(label))
			}
		}
	}
	staged := func(labels ...string) func(*evsCitationSourcesVector) {
		return func(value *evsCitationSourcesVector) {
			for _, label := range labels {
				value.Staged = append(value.Staged, evsCitationId(label))
			}
		}
	}
	removed := func(name string, version *evsCitationVersionVector) func(*evsCitationSourcesVector) {
		return func(value *evsCitationSourcesVector) {
			value.Removed = append(value.Removed, &evsCitationSourceVector{TokenPath: evsCitationTokenPath(name), Version: version})
		}
	}
	reuse := func(name string, version *evsCitationVersionVector) func(*evsCitationSourcesVector) {
		return func(value *evsCitationSourcesVector) {
			value.Reuse = append(value.Reuse, &evsCitationSourceVector{RefId: refId, TokenPath: evsCitationTokenPath(name), Version: version})
		}
	}
	both := func(mutations ...func(*evsCitationSourcesVector)) func(*evsCitationSourcesVector) {
		return func(value *evsCitationSourcesVector) {
			for _, mutate := range mutations {
				mutate(value)
			}
		}
	}
	type citations = []*evsCitationCitationVector
	return []*evsCitationCaseVector{
		{Name: "fs64 k+1 replaces chunks 2 and 4 by uploads", Want: "ok",
			Citations: citations{at("x", k1, k)}, Sources: sources(uploads("n2", "n4"))},
		{Name: "fs64 a copy citing k's chunks from another path", Want: "VERSIONING",
			Citations: citations{at("y", evsCitationVersion(1, []string{"k5:c1"}), nil)}, Sources: sources(reuse("x", k))},
		{Name: "fs64 the copy citing them as kind 1", Want: "VERSIONING",
			Citations: citations{at("y", evsCitationVersion(0, []string{"k1:c1"}), nil)}, Sources: sources(reuse("x", k))},
		{Name: "fs64 a kind-5 locator on an unmarked receipt's segment", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k5:c1", "k5:n9", "k5:c3", "k5:c4", "k5:c5"}), k)}, Sources: sources(nil)},
		{Name: "fs64 one push removing x and creating x2 from k+1's chunks", Want: "ok",
			Citations: citations{at("x2", k1, nil)}, Sources: sources(removed("x", k1))},
		{Name: "a rename to two targets", Want: "VERSIONING",
			Citations: citations{at("x2", evsCitationVersion(1, []string{"k5:c1"}), nil), at("x3", evsCitationVersion(1, []string{"k5:c1"}), nil)},
			Sources:   sources(removed("x", k1))},
		{Name: "a kind-5 locator in a versioned version", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(0, []string{"k5:c1"}), k)}, Sources: sources(nil)},
		{Name: "a staged segment of this push", Want: "ok",
			Citations: citations{at("y", evsCitationVersion(1, []string{"s5:s1"}), nil)}, Sources: sources(staged("s1"))},
		{Name: "a staged locator naming no staged segment", Want: "VERSIONING",
			Citations: citations{at("y", evsCitationVersion(1, []string{"s5:s1"}), nil)}, Sources: sources(nil)},
		{Name: "a staged segment named by two versions", Want: "VERSIONING",
			Citations: citations{at("y", evsCitationVersion(1, []string{"s5:s1"}), nil), at("z", evsCitationVersion(1, []string{"s5:s1"}), nil)},
			Sources:   sources(staged("s1"))},
		{Name: "the base's staged segment cited again as staged", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(1, []string{"s5:s0"}), evsCitationVersion(1, []string{"s5:s0"}))}, Sources: sources(nil)},
		{Name: "the base's staged segment cited again as unstaged", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k5:s0"}), evsCitationVersion(1, []string{"s5:s0"}))}, Sources: sources(nil)},
		{Name: "fs68 on: the base's staged segment adopted as kind 1", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(0, []string{"k1:s0"}), evsCitationVersion(1, []string{"s5:s0"}))}, Sources: sources(nil)},
		{Name: "an inline record in a versionless version", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(1, []string{"in"}), k)}, Sources: sources(nil)},
		{Name: "fs68 off: k+1 versionless citing k's kind-1 chunks", Want: "ok",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k1:a1", "k1:a2"}), evsCitationVersion(0, []string{"k1:a1", "k1:a2"}))},
			Sources:   sources(nil)},
		{Name: "fs68 off citing kind-1 chunks from a reuse source", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k1:b9"}), evsCitationVersion(0, []string{"k1:a1"}))},
			Sources:   sources(reuse("z", evsCitationVersion(0, []string{"k1:b9"})))},
		{Name: "fs68 on: k+1 adopting k's kind-5 chunks as kind 1", Want: "ok",
			Citations: citations{at("x", evsCitationVersion(0, []string{"k1:c1", "k1:c2", "k1:c3", "k1:c4", "k1:c5"}), k)}, Sources: sources(nil)},
		{Name: "a versionless upload named by two versions", Want: "VERSIONING",
			Citations: citations{at("y", evsCitationVersion(1, []string{"k5:n7"}), nil), at("z", evsCitationVersion(1, []string{"k5:n7"}), nil)},
			Sources:   sources(uploads("n7"))},
		{Name: "a slot-keyed versionless path keeping its slot", Want: "ok",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k5:n2"}, "sx"), evsCitationVersion(1, []string{"k5:c1"}, "sx"))},
			Sources:   sources(uploads("n2"))},
		{Name: "another path naming a versionless path's slot", Want: "VERSIONING",
			Citations: citations{at("y", evsCitationVersion(0, []string{"k1:b1"}, "sx"), nil)},
			Sources:   sources(reuse("x", evsCitationVersion(1, []string{"k5:c1"}, "sx")))},
		{Name: "a versionless version naming another path's slot", Want: "VERSIONING",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k5:n2"}, "sz"), nil)},
			Sources:   sources(both(uploads("n2"), reuse("z", evsCitationVersion(0, []string{"k1:b2"}, "sz"))))},
		{Name: "slot rename: a slot-keyed rename keeping its slot and chunks", Want: "ok",
			Citations: citations{at("x2", evsCitationVersion(1, []string{"k5:c1"}, "sx"), nil)},
			Sources:   sources(removed("x", evsCitationVersion(1, []string{"k5:c1"}, "sx")))},
		{Name: "slot rename: two targets of one slot", Want: "VERSIONING",
			Citations: citations{at("x2", evsCitationVersion(0, []string{"k1:b1"}, "sx"), nil), at("x3", evsCitationVersion(0, []string{"k1:b2"}, "sx"), nil)},
			Sources:   sources(removed("x", evsCitationVersion(1, []string{"k5:c1"}, "sx")))},
		{Name: "slot rename: kind-1 chunks from the removed path", Want: "ok",
			Citations: citations{at("x2", evsCitationVersion(1, []string{"k1:a1"}, "sx"), nil)},
			Sources:   sources(removed("x", evsCitationVersion(1, []string{"k1:a1"}, "sx")))},
		{Name: "a kind-5 segment a reuse source also names, cited from the base", Want: "ok",
			Citations: citations{at("x", evsCitationVersion(1, []string{"k5:c1"}), k)}, Sources: sources(reuse("y", k))},
		{Name: "a versioned copy of a versioned file sharing its slot", Want: "ok",
			Citations: citations{at("y", evsCitationVersion(0, []string{"k1:b1"}, "sv"), nil)},
			Sources:   sources(reuse("z", evsCitationVersion(0, []string{"k1:b1"}, "sv")))},
	}
}

// The citation and sources a vector stands for.
func evsCitationInputs(t testing.TB, vector *evsCitationCaseVector) ([]*EvsCitation, *EvsCitationSources) {
	path := func(tokenPathBytes hexBytes) EvsTokenPath {
		components := [][]byte{}
		for at := 0; at < len(tokenPathBytes); at += EvsTokenByteCount {
			components = append(components, tokenPathBytes[at:at+EvsTokenByteCount])
		}
		tokenPath, err := ParseEvsChangedTokenPath(components)
		if err != nil {
			t.Fatal(err)
		}
		return tokenPath
	}
	citations := []*EvsCitation{}
	for _, citation := range vector.Citations {
		citations = append(citations, &EvsCitation{TokenPath: path(citation.TokenPath), Version: citation.Version.entry(), Base: citation.Base.entry()})
	}
	sources := &EvsCitationSources{
		RefId: Id(vector.Sources.RefId), Staged: map[[sha256.Size]byte]bool{}, VersionlessUploads: map[[sha256.Size]byte]bool{},
	}
	for _, id := range vector.Sources.Staged {
		sources.Staged[[sha256.Size]byte(id)] = true
	}
	for _, id := range vector.Sources.VersionlessUploads {
		sources.VersionlessUploads[[sha256.Size]byte(id)] = true
	}
	for _, removed := range vector.Sources.Removed {
		sources.Removed = append(sources.Removed, &EvsCitedVersion{RefId: Id(vector.Sources.RefId), TokenPath: path(removed.TokenPath), Entry: removed.Version.entry()})
	}
	for _, reuse := range vector.Sources.Reuse {
		sources.Reuse = append(sources.Reuse, &EvsCitedVersion{RefId: Id(reuse.RefId), TokenPath: path(reuse.TokenPath), Entry: reuse.Version.entry()})
	}
	return citations, sources
}

// A case's file name: its name in lowercase words joined by hyphens.
func evsCitationFileName(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.NewReplacer("'", "", "+", " plus ", ":", "").Replace(name))), "-") + ".json"
}

// Each stored case answers its hand-written verdict on this build, and the stored files are the cases this build
// writes, one each, under -update-evs-vectors.
func TestEvsCitationVectors(t *testing.T) {
	cases := evsCitationCases()
	if *updateEvsVectors {
		for _, vector := range cases {
			writeEvsVectors(t, path.Join("testdata/evs/citation", evsCitationFileName(vector.Name)), vector)
		}
		return
	}
	entries, err := evsCitationVectorFiles.ReadDir("testdata/evs/citation")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(cases) {
		t.Errorf("%d stored cases, and this build writes %d", len(entries), len(cases))
	}
	byName := map[string]*evsCitationCaseVector{}
	for _, vector := range cases {
		byName[evsCitationFileName(vector.Name)] = vector
	}
	for _, entry := range entries {
		data, err := evsCitationVectorFiles.ReadFile("testdata/evs/citation/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		stored := &evsCitationCaseVector{}
		if err := json.Unmarshal(data, stored); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		if built, ok := byName[entry.Name()]; !ok {
			t.Errorf("%s is no case this build writes", entry.Name())
		} else if want, _ := json.Marshal(built); string(want) != string(evsCitationRemarshal(t, stored)) {
			t.Errorf("%s differs from this build's case", entry.Name())
		}
		citations, sources := evsCitationInputs(t, stored)
		err = EvsCheckCitation(citations, sources)
		got := "ok"
		if err != nil {
			if !errors.Is(err, ErrEvsVersioning) {
				t.Errorf("%s: %v is no VERSIONING", stored.Name, err)
			}
			got = "VERSIONING"
		}
		if got != stored.Want {
			t.Errorf("%s: %s (%v), want %s", stored.Name, got, err, stored.Want)
		}
	}
}

// A stored case marshaled again, so it compares with a built one field for field.
func evsCitationRemarshal(t *testing.T, vector *evsCitationCaseVector) []byte {
	data, err := json.Marshal(vector)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A locator the rule cannot read is refused as INVALID, as the payload checks refuse it first, never passed.
func TestEvsCitationRefusesWhatItCannotRead(t *testing.T) {
	version := &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{{Kind: 5, Id: evsTestBytes("short", 8)}}}
	citations := []*EvsCitation{{TokenPath: EvsTokenPath{evsTestToken("x")}, Version: version}}
	if err := EvsCheckCitation(citations, &EvsCitationSources{}); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a locator out of shape: %v", err)
	}
}
