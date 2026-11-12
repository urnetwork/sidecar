// The purge's candidates as a pure function with fixed vectors (§22.5's §11 row; EVS2-M10-04): testdata/evs/purge/, one
// file per case with its list written by hand in purgeCases, which another implementation reads as is; FS-64's clauses
// as pure cases (the two replaced chunks, a rename keeping its chunks, the 2,048 cap falling to marked); and the
// property test over random push histories, which runs the citation rule and the purge together against a brute-force
// reading of the whole state after every commit: every path's newest version keeps all its content, no version written
// with versioning on loses any, and no kind-5 segment is ever any two paths' at once (I-EVS-1, I-EVS-9, I-EVS-10,
// FI-16, FI-17).

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Where the vectors are, from this package's directory: beside the root's, which an embed cannot reach.
const purgeVectorDirectory = "../testdata/evs/purge"

var updatePurgeVectors = flag.Bool("update-evs-vectors", false, "rewrite testdata/evs/purge's vectors")

// Bytes no other test value shares.
func purgeTestBytes(label string, length int) []byte {
	digest := sha256.Sum256([]byte("purge " + label))
	return bytes.Clone(digest[:length])
}

// A hex value in a vector.
type purgeHex []byte

func (self purgeHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(self))
}

func (self *purgeHex) UnmarshalJSON(src []byte) error {
	var text string
	if err := json.Unmarshal(src, &text); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(text)
	*self = decoded
	return err
}

type purgeLocatorVector struct {
	Kind   uint32   `json:"kind"`
	Id     purgeHex `json:"id,omitempty"`
	Staged bool     `json:"staged,omitempty"`
}

type purgeVersionVector struct {
	Version    uint64                `json:"version"`
	Versioning uint32                `json:"versioning"`
	Chain      []*purgeLocatorVector `json:"chain"`
	SlotIds    []purgeHex            `json:"slot_ids,omitempty"`
}

type purgeReplacedVector struct {
	TokenPath purgeHex            `json:"token_path"`
	Version   *purgeVersionVector `json:"version"`
}

// One case file of testdata/evs/purge/ (schema.yml's vectors section).
type purgeCaseVector struct {
	Name          string                 `json:"name"`
	Replaced      []*purgeReplacedVector `json:"replaced"`
	PushVersions  []*purgeVersionVector  `json:"push_versions"`
	RoomByteCount int                    `json:"room_byte_count"`
	Want          purgeHex               `json:"want"`
}

func purgeSegment(label string) []byte {
	return purgeTestBytes("segment "+label, 32)
}

func purgeSlot(label string) []byte {
	return purgeTestBytes("slot "+label, 16)
}

func purgeTokenPath(label string) sidecar.EvsTokenPath {
	return sidecar.EvsTokenPath{sidecar.EvsToken(purgeTestBytes("token "+label, sidecar.EvsTokenByteCount))}
}

// Locators by short spelling, as the citation vectors spell them: "k5:a", "s5:a", "k1:a".
func purgeVersion(version uint64, versioning uint32, locators []string, slots ...string) *purgeVersionVector {
	vector := &purgeVersionVector{Version: version, Versioning: versioning, Chain: []*purgeLocatorVector{}}
	for _, spelled := range locators {
		kind, label, _ := strings.Cut(spelled, ":")
		switch kind {
		case "k5":
			vector.Chain = append(vector.Chain, &purgeLocatorVector{Kind: 5, Id: purgeSegment(label)})
		case "s5":
			vector.Chain = append(vector.Chain, &purgeLocatorVector{Kind: 5, Id: purgeSegment(label), Staged: true})
		case "k1":
			vector.Chain = append(vector.Chain, &purgeLocatorVector{Kind: 1, Id: purgeSegment(label)})
		}
	}
	for _, slot := range slots {
		vector.SlotIds = append(vector.SlotIds, purgeSlot(slot))
	}
	return vector
}

func (self *purgeVersionVector) entry() *protocol.EvsEntryVersion {
	entry := &protocol.EvsEntryVersion{Version: self.Version, Versioning: self.Versioning, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)}
	for _, locator := range self.Chain {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: locator.Kind, Id: locator.Id, Staged: locator.Staged})
	}
	for _, slotId := range self.SlotIds {
		entry.SlotIds = append(entry.SlotIds, slotId)
	}
	return entry
}

// A hand-written candidate.
func purgeCandidate(path string, version uint64, segments []string, staged []string, slots []string) *protocol.EvsPurgeCandidate {
	candidate := &protocol.EvsPurgeCandidate{TokenPath: purgeTokenPath(path).Components(), ReplacedVersion: version}
	for _, label := range segments {
		candidate.SegmentIds = append(candidate.SegmentIds, purgeSegment(label))
	}
	for _, label := range staged {
		candidate.StagedSegmentIds = append(candidate.StagedSegmentIds, purgeSegment(label))
	}
	for _, label := range slots {
		candidate.SlotIds = append(candidate.SlotIds, purgeSlot(label))
	}
	return candidate
}

// The cases, each list written by hand. X at version 4 is FS-64's: five kind-5 chunks.
func purgeCases(t testing.TB) []*purgeCaseVector {
	encode := func(list *protocol.EvsPurgeList) purgeHex {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	replaced := func(path string, version *purgeVersionVector) *purgeReplacedVector {
		return &purgeReplacedVector{TokenPath: purgeTokenPath(path).Bytes(), Version: version}
	}
	k := purgeVersion(4, 1, []string{"k5:c1", "k5:c2", "k5:c3", "k5:c4", "k5:c5"})
	k1 := purgeVersion(5, 1, []string{"k5:c1", "k5:n2", "k5:c3", "k5:n4", "k5:c5"})
	manyChunks := []string{}
	for i := range sidecar.DefaultEvsFormatSettings().PurgeListMaxIdCount + 1 {
		manyChunks = append(manyChunks, fmt.Sprint("k5:many ", i))
	}
	tenChunks := []string{}
	for i := range 10 {
		tenChunks = append(tenChunks, fmt.Sprint("k5:ten ", i))
	}
	const room = 1024 * 1024
	return []*purgeCaseVector{
		{Name: "fs64 the two replaced chunks", RoomByteCount: room,
			Replaced: []*purgeReplacedVector{replaced("x", k)}, PushVersions: []*purgeVersionVector{k1},
			Want: encode(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{purgeCandidate("x", 4, []string{"c2", "c4"}, nil, nil)}})},
		{Name: "fs64 a removal and a rename keeping its chunks", RoomByteCount: room,
			Replaced: []*purgeReplacedVector{replaced("x", k1)}, PushVersions: []*purgeVersionVector{purgeVersion(1, 1, []string{"k5:c1", "k5:n2", "k5:c3", "k5:n4", "k5:c5"})},
			Want: encode(&protocol.EvsPurgeList{})},
		{Name: "a removal", RoomByteCount: room,
			Replaced: []*purgeReplacedVector{replaced("x", k)}, PushVersions: []*purgeVersionVector{},
			Want: encode(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{purgeCandidate("x", 4, []string{"c1", "c2", "c3", "c4", "c5"}, nil, nil)}})},
		{Name: "a staged chunk and a kept slot", RoomByteCount: room,
			Replaced:     []*purgeReplacedVector{replaced("y", purgeVersion(2, 1, []string{"s5:s0", "k5:d1"}, "sy"))},
			PushVersions: []*purgeVersionVector{purgeVersion(3, 1, []string{"k5:d9"}, "sy")},
			Want:         encode(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{purgeCandidate("y", 2, []string{"d1"}, []string{"s0"}, nil)}})},
		{Name: "a slot no longer named", RoomByteCount: room,
			Replaced:     []*purgeReplacedVector{replaced("y", purgeVersion(2, 1, []string{"k5:d1"}, "sy"))},
			PushVersions: []*purgeVersionVector{purgeVersion(3, 1, []string{"k5:d1"}, "sz")},
			Want:         encode(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{purgeCandidate("y", 2, nil, nil, []string{"sy"})}})},
		{Name: "a versioned version replaced", RoomByteCount: room,
			Replaced: []*purgeReplacedVector{replaced("z", purgeVersion(7, 0, []string{"k1:e1"}))}, PushVersions: []*purgeVersionVector{},
			Want: encode(&protocol.EvsPurgeList{})},
		{Name: "fs68 on adopting the chunks as kind 1", RoomByteCount: room,
			Replaced:     []*purgeReplacedVector{replaced("x", k)},
			PushVersions: []*purgeVersionVector{purgeVersion(5, 0, []string{"k1:c1", "k1:c2", "k1:c3", "k1:c4", "k1:c5"})},
			Want:         encode(&protocol.EvsPurgeList{})},
		{Name: "fs64 the 2,048 cap falling to marked", RoomByteCount: room,
			Replaced: []*purgeReplacedVector{replaced("x", purgeVersion(9, 1, manyChunks))}, PushVersions: []*purgeVersionVector{},
			Want: encode(&protocol.EvsPurgeList{Marked: true})},
		{Name: "the record's room falling to marked", RoomByteCount: 100,
			Replaced: []*purgeReplacedVector{replaced("x", purgeVersion(9, 1, tenChunks))}, PushVersions: []*purgeVersionVector{},
			Want: encode(&protocol.EvsPurgeList{Marked: true})},
		{Name: "two replaced paths in change order", RoomByteCount: room,
			Replaced:     []*purgeReplacedVector{replaced("a", purgeVersion(1, 1, []string{"k5:a1"})), replaced("b", purgeVersion(2, 2, []string{"k5:b1"}))},
			PushVersions: []*purgeVersionVector{purgeVersion(2, 1, []string{"k5:a2"})},
			Want: encode(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{
				purgeCandidate("a", 1, []string{"a1"}, nil, nil), purgeCandidate("b", 2, []string{"b1"}, nil, nil),
			}})},
	}
}

// A case's file name.
func purgeFileName(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.NewReplacer(",", "", "'", "").Replace(name))), "-") + ".json"
}

// The inputs a vector stands for.
func purgeInputs(t testing.TB, vector *purgeCaseVector) ([]*PurgeReplaced, []*protocol.EvsEntryVersion) {
	replaced := []*PurgeReplaced{}
	for _, entry := range vector.Replaced {
		components := [][]byte{}
		for at := 0; at < len(entry.TokenPath); at += sidecar.EvsTokenByteCount {
			components = append(components, entry.TokenPath[at:at+sidecar.EvsTokenByteCount])
		}
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(components)
		if err != nil {
			t.Fatal(err)
		}
		replaced = append(replaced, &PurgeReplaced{TokenPath: tokenPath, Version: entry.Version.entry()})
	}
	versions := []*protocol.EvsEntryVersion{}
	for _, version := range vector.PushVersions {
		versions = append(versions, version.entry())
	}
	return replaced, versions
}

// Each stored case's list is what PurgeCandidates answers on this build, byte for byte, and the stored files are the
// cases this build writes, one each, under -update-evs-vectors. The lists are written by hand above, so a code change
// that moves one fails here.
func TestPurgeCandidateVectors(t *testing.T) {
	cases := purgeCases(t)
	if *updatePurgeVectors {
		for _, vector := range cases {
			encoded, err := json.MarshalIndent(vector, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path.Join(purgeVectorDirectory, purgeFileName(vector.Name)), append(encoded, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	entries, err := os.ReadDir(purgeVectorDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(cases) {
		t.Errorf("%d stored cases, and this build writes %d", len(entries), len(cases))
	}
	for _, entry := range entries {
		data, err := os.ReadFile(path.Join(purgeVectorDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		stored := &purgeCaseVector{}
		if err := json.Unmarshal(data, stored); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		replaced, versions := purgeInputs(t, stored)
		list := PurgeCandidates(replaced, versions, stored.RoomByteCount)
		got, err := proto.MarshalOptions{Deterministic: true}.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, stored.Want) {
			t.Errorf("%s: %x, want %x", stored.Name, got, []byte(stored.Want))
		}
		if 0 < len(list.GetCandidates()) || list.GetMarked() {
			if _, err := sidecar.EncodeEvsPurgeList(list); err != nil {
				t.Errorf("%s: a list the record codec refuses: %v", stored.Name, err)
			}
		}
	}
}

// One ref's simulated state for the property test: each path's newest committed version, what the purge deleted,
// and what versions written with versioning on named, which nothing may delete (FI-17).
type purgeSimulation struct {
	random       *mathrand.Rand
	refId        sidecar.Id
	newest       map[string]*protocol.EvsEntryVersion
	deleted      map[string]bool
	keptForGood  map[string]bool
	nextId       int
	stagedPushes int
}

// A fresh id of the simulation, segment or slot.
func (self *purgeSimulation) fresh(length int) []byte {
	self.nextId += 1
	return purgeTestBytes(fmt.Sprint("simulated ", self.nextId), length)
}

func (self *purgeSimulation) tokenPath(label string) sidecar.EvsTokenPath {
	return purgeTokenPath("simulated " + label)
}

// One generated push: its citations and sources, the versions it replaces, and whether it keeps §11.7's citation
// rule by construction.
type purgeSimulatedPush struct {
	citations []*sidecar.EvsCitation
	sources   *sidecar.EvsCitationSources
	replaced  []*PurgeReplaced
	removed   []string
	written   map[string]*protocol.EvsEntryVersion
	valid     bool
	op        string
}

// A versionless version's unstaged kind-5 ids, kind-1 ids and staged ids.
func purgeLocatorIds(entry *protocol.EvsEntryVersion) (kind5 [][]byte, kind1 [][]byte, staged [][]byte) {
	for _, locator := range entry.GetChain() {
		switch {
		case locator.GetKind() == 5 && locator.GetStaged():
			staged = append(staged, locator.GetId())
		case locator.GetKind() == 5:
			kind5 = append(kind5, locator.GetId())
		case locator.GetKind() == 1:
			kind1 = append(kind1, locator.GetId())
		}
	}
	return
}

// Generates one push of the simulated ref: an honest write, removal or rename, or one of §11.7's breaches.
func (self *purgeSimulation) push() *purgeSimulatedPush {
	push := &purgeSimulatedPush{
		sources: &sidecar.EvsCitationSources{
			RefId: self.refId, Staged: map[[sha256.Size]byte]bool{}, VersionlessUploads: map[[sha256.Size]byte]bool{},
		},
		written: map[string]*protocol.EvsEntryVersion{},
		valid:   true,
	}
	labels := []string{"p0", "p1", "p2", "p3", "p4"}
	existing := []string{}
	versionless := []string{}
	for _, label := range labels {
		if entry := self.newest[label]; entry != nil {
			existing = append(existing, label)
			if entry.GetVersioning() != 0 {
				versionless = append(versionless, label)
			}
		}
	}
	pick := func(from []string) string {
		return from[self.random.IntN(len(from))]
	}
	upload := func() *protocol.EvsLocator {
		id := self.fresh(32)
		push.sources.VersionlessUploads[[sha256.Size]byte(id)] = true
		return &protocol.EvsLocator{Kind: 5, Id: id}
	}
	write := func(label string, entry *protocol.EvsEntryVersion) {
		base := self.newest[label]
		entry.Version = 1
		if base != nil {
			entry.Version = base.GetVersion() + 1
			push.replaced = append(push.replaced, &PurgeReplaced{TokenPath: self.tokenPath(label), Version: base})
		}
		entry.Kind = uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)
		push.citations = append(push.citations, &sidecar.EvsCitation{TokenPath: self.tokenPath(label), Version: entry, Base: base})
		push.written[label] = entry
	}
	remove := func(label string) {
		base := self.newest[label]
		push.sources.Removed = append(push.sources.Removed, &sidecar.EvsCitedVersion{RefId: self.refId, TokenPath: self.tokenPath(label), Entry: base})
		push.replaced = append(push.replaced, &PurgeReplaced{TokenPath: self.tokenPath(label), Version: base})
		push.removed = append(push.removed, label)
	}
	versionlessWrite := func(label string) {
		base := self.newest[label]
		entry := &protocol.EvsEntryVersion{Versioning: 1}
		slotId := self.fresh(16)
		if base != nil && base.GetVersioning() != 0 {
			kind5, kind1, _ := purgeLocatorIds(base)
			for _, id := range kind5 {
				if self.random.IntN(2) == 0 {
					entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 5, Id: id})
				} else {
					entry.Chain = append(entry.Chain, upload())
				}
			}
			for _, id := range kind1 {
				entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 1, Id: id})
			}
			if 0 < len(base.GetSlotIds()) {
				slotId = base.GetSlotIds()[0]
			}
		} else if base != nil && self.random.IntN(2) == 0 {
			// the off row: cite a versioned base's chunks as kind 1
			_, kind1, _ := purgeLocatorIds(base)
			for _, id := range kind1 {
				entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 1, Id: id})
			}
		}
		if len(entry.Chain) == 0 || self.random.IntN(3) == 0 {
			if self.random.IntN(2) == 0 {
				id := self.fresh(32)
				push.sources.Staged[[sha256.Size]byte(id)] = true
				entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 5, Id: id, Staged: true})
			} else {
				entry.Chain = append(entry.Chain, upload())
			}
		}
		entry.SlotIds = [][]byte{slotId}
		write(label, entry)
	}
	versionedWrite := func(label string) {
		base := self.newest[label]
		entry := &protocol.EvsEntryVersion{Versioning: 0, SlotIds: [][]byte{self.fresh(16)}}
		if base != nil && base.GetVersioning() != 0 && self.random.IntN(2) == 0 {
			// the on row: adopt the base's unstaged kind-5 chunks as kind 1
			kind5, kind1, _ := purgeLocatorIds(base)
			for _, id := range append(kind5, kind1...) {
				entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 1, Id: id})
			}
		}
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 1, Id: self.fresh(32)})
		write(label, entry)
	}
	absent := []string{}
	for _, label := range labels {
		if self.newest[label] == nil {
			absent = append(absent, label)
		}
	}
	switch choice := self.random.IntN(12); {
	case choice < 4:
		push.op = "versionless write"
		versionlessWrite(pick(labels))
		if self.random.IntN(2) == 0 {
			other := pick(labels)
			if _, taken := push.written[other]; !taken {
				versionedWrite(other)
			}
		}
	case choice < 6:
		push.op = "versioned write"
		versionedWrite(pick(labels))
	case choice < 7 && 0 < len(existing):
		push.op = "removal"
		remove(pick(existing))
	case choice < 8 && 0 < len(versionless) && 0 < len(absent):
		push.op = "rename"
		source, target := pick(versionless), pick(absent)
		base := self.newest[source]
		remove(source)
		kind5, kind1, _ := purgeLocatorIds(base)
		entry := &protocol.EvsEntryVersion{Versioning: 1, SlotIds: base.GetSlotIds()}
		for _, id := range kind5 {
			entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 5, Id: id})
		}
		for _, id := range kind1 {
			entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: 1, Id: id})
		}
		if len(entry.Chain) == 0 {
			entry.Chain = append(entry.Chain, upload())
		}
		write(target, entry)
	case 0 < len(versionless):
		push.valid = false
		source := pick(versionless)
		base := self.newest[source]
		kind5, _, staged := purgeLocatorIds(base)
		breaches := []string{"inline in versionless", "kind 5 in versioned", "slot taken"}
		if 0 < len(kind5) {
			breaches = append(breaches, "copy of kind 5", "two rename targets")
		}
		if 0 < len(staged) {
			breaches = append(breaches, "restaged")
		}
		push.op = pick(breaches)
		others := []string{}
		for _, label := range labels {
			if label != source {
				others = append(others, label)
			}
		}
		switch push.op {
		case "inline in versionless":
			write(source, &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{{Kind: 2, Inline: []byte("inline")}}})
		case "kind 5 in versioned":
			chain := []*protocol.EvsLocator{upload()}
			chain[0].Kind = 5
			if 0 < len(kind5) {
				chain[0].Id = kind5[0]
			}
			write(source, &protocol.EvsEntryVersion{Versioning: 0, Chain: chain})
		case "slot taken":
			target := pick(others)
			push.sources.Reuse = append(push.sources.Reuse, &sidecar.EvsCitedVersion{RefId: self.refId, TokenPath: self.tokenPath(source), Entry: base})
			write(target, &protocol.EvsEntryVersion{Versioning: 0, Chain: []*protocol.EvsLocator{{Kind: 1, Id: self.fresh(32)}}, SlotIds: base.GetSlotIds()})
		case "copy of kind 5":
			push.sources.Reuse = append(push.sources.Reuse, &sidecar.EvsCitedVersion{RefId: self.refId, TokenPath: self.tokenPath(source), Entry: base})
			write(pick(others), &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{{Kind: 5, Id: kind5[0]}}})
		case "two rename targets":
			remove(source)
			first := pick(others)
			second := pick(others)
			for second == first {
				second = pick(others)
			}
			write(first, &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{{Kind: 5, Id: kind5[0]}}})
			write(second, &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{{Kind: 5, Id: kind5[0]}}})
		case "restaged":
			write(source, &protocol.EvsEntryVersion{Versioning: 1, Chain: []*protocol.EvsLocator{{Kind: 5, Id: staged[0], Staged: true}}})
		}
	default:
		push.op = "versioned write"
		versionedWrite(pick(labels))
	}
	return push
}

// Commits a push: its versions become their paths' newest, removed paths go, and the purge deletes its candidates
// (the 60 s allowance and the reread of the newest versions are the Purger's and pass here, since no later push names
// a candidate within this step).
func (self *purgeSimulation) commit(t *testing.T, push *purgeSimulatedPush) {
	versions := []*protocol.EvsEntryVersion{}
	for _, citation := range push.citations {
		versions = append(versions, citation.Version)
	}
	list := PurgeCandidates(push.replaced, versions, 1024*1024)
	if list.GetMarked() {
		t.Fatal("a small push's list was marked")
	}
	for _, label := range push.removed {
		delete(self.newest, label)
	}
	for label, entry := range push.written {
		self.newest[label] = entry
		if entry.GetVersioning() == 0 {
			for _, locator := range entry.GetChain() {
				self.keptForGood[string(locator.GetId())] = true
			}
		}
	}
	for _, candidate := range list.GetCandidates() {
		for _, group := range [][][]byte{candidate.GetSegmentIds(), candidate.GetStagedSegmentIds(), candidate.GetSlotIds()} {
			for _, id := range group {
				self.deleted[string(id)] = true
			}
		}
	}
}

// The brute-force reading of the whole state: every path's newest version keeps all its content and slots
// (I-EVS-1, I-EVS-9), nothing a versioned version named is deleted (FI-17), and no segment named as kind 5 by one
// path's newest version is named by another's (I-EVS-10).
func (self *purgeSimulation) check(t *testing.T, step int, op string) {
	namers := map[string]map[string]bool{}
	kind5 := map[string]bool{}
	for label, entry := range self.newest {
		for _, locator := range entry.GetChain() {
			id := string(locator.GetId())
			if locator.GetKind() == 2 {
				continue
			}
			if self.deleted[id] {
				t.Fatalf("step %d (%s): %s's newest version names a purged segment", step, op, label)
			}
			if namers[id] == nil {
				namers[id] = map[string]bool{}
			}
			namers[id][label] = true
			if locator.GetKind() == 5 {
				kind5[id] = true
			}
		}
		for _, slotId := range entry.GetSlotIds() {
			if self.deleted[string(slotId)] {
				t.Fatalf("step %d (%s): %s's newest version names a purged slot", step, op, label)
			}
		}
	}
	for id := range self.keptForGood {
		if self.deleted[id] {
			t.Fatalf("step %d (%s): content written with versioning on was purged", step, op)
		}
	}
	for id := range kind5 {
		if 1 < len(namers[id]) {
			t.Fatalf("step %d (%s): a kind-5 segment named by %d paths' newest versions", step, op, len(namers[id]))
		}
	}
}

// The property test: random push histories on one ref, each push an honest write, removal or rename or one of
// §11.7's breaches; the citation rule takes exactly the honest ones, and after each commit and purge the brute-force
// reading holds. Deterministic: the seeds are fixed.
func TestPurgeAndCitationHoldOverRandomHistories(t *testing.T) {
	const histories = 300
	const pushes = 40
	ops := map[string]int{}
	for history := range histories {
		simulation := &purgeSimulation{
			random: mathrand.New(mathrand.NewPCG(uint64(history), 7)),
			refId:  sidecar.Id(purgeTestBytes("ref", 16)),
			newest: map[string]*protocol.EvsEntryVersion{}, deleted: map[string]bool{}, keptForGood: map[string]bool{},
		}
		for step := range pushes {
			push := simulation.push()
			ops[push.op] += 1
			err := sidecar.EvsCheckCitation(push.citations, push.sources)
			if push.valid != (err == nil) {
				t.Fatalf("history %d step %d (%s): valid %t, and the rule says %v", history, step, push.op, push.valid, err)
			}
			if err != nil {
				continue
			}
			simulation.commit(t, push)
			simulation.check(t, step, push.op)
		}
	}
	for _, op := range []string{"versionless write", "versioned write", "removal", "rename", "inline in versionless", "kind 5 in versioned", "slot taken", "copy of kind 5", "two rename targets", "restaged"} {
		if ops[op] == 0 {
			t.Errorf("no history generated a %s", op)
		}
	}
}
