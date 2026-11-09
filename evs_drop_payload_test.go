// The DROP payload's pure rules (EVS2-M10-03): testdata/evs/format2/drop_vectors.json on every leg, each case's
// verdict and EvsDropLists' membership answers; §22.6's EvsDropHistory and list target, where tampering fails before
// adoption; every DROP_LIST shape (a count off by one either way, an order swap, a repeat, past 2^20, a hash off); a
// cancel with paths and a drop with none refused; not_before_ms's two values; a list spread over parts, split anywhere,
// checking equal to one list, through the seal of a real push in parts too; and format 2's DROP statement shape.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	mathrand "math/rand/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/evs/format2/drop_vectors.json
var evsDropVectorsJson []byte

// The DROP target's seeds: tamperings, as evsFuzzTamper reads them, of the test drop's body (an even first byte) or
// lists (an odd one).
//
//go:embed testdata/fuzz/evs_drop
var evsDropFuzzSeeds embed.FS

// Each seed file of a directory of the DROP target's.
func evsDropFuzzSeedFiles(t testing.TB, directory string) [][]byte {
	t.Helper()
	entries, err := evsDropFuzzSeeds.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	seeds := [][]byte{}
	for _, entry := range entries {
		seed, err := evsDropFuzzSeeds.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, seed)
	}
	if len(seeds) == 0 {
		t.Fatalf("no seeds in %s", directory)
	}
	return seeds
}

// The test DROP's time and path epoch.
const (
	evsTestDropTimeMs    = int64(1767225600000)
	evsTestDropPathEpoch = 3
)

// A lineage of a path renamed across epochs: newest first, in epochs 3 and 2.
func evsTestDropPath(label string, throughVersion uint64, boundary uint32) *protocol.EvsDropPath {
	return &protocol.EvsDropPath{
		Lineage: []*protocol.EvsSourcePath{
			{Epoch: evsTestDropPathEpoch, TokenPath: EvsTokenPath{evsTestToken(label + " dir"), evsTestToken(label)}.Components()},
			{Epoch: 2, TokenPath: EvsTokenPath{evsTestToken(label + " old")}.Components()},
		},
		MapParts:       []uint32{1},
		ThroughVersion: throughVersion,
		Boundary:       boundary,
	}
}

// count entry hashes of a path's listed versions.
func evsTestDropListed(label string, count int) [][]byte {
	listed := [][]byte{}
	for i := range count {
		listed = append(listed, evsTestBytes(fmt.Sprint("entry ", label, " ", i), 32))
	}
	return listed
}

// A drop of paths with their lists, put in the body's order, its body and lists' bytes, and the statement's push
// naming them.
func evsTestDrop(t testing.TB, paths []*protocol.EvsDropPath, listed [][][]byte, mutate func(*protocol.EvsDropHistory)) (*protocol.EvsPush, []byte, []byte) {
	t.Helper()
	order := make([]int, len(paths))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a int, b int) int {
		return evsCompareDropLineageEntries(paths[a].GetLineage()[0], paths[b].GetLineage()[0])
	})
	sortedPaths := make([]*protocol.EvsDropPath, len(paths))
	sortedListed := make([][][]byte, len(listed))
	for i, j := range order {
		sortedPaths[i] = paths[j]
		sortedListed[i] = listed[j]
	}
	paths, listed = sortedPaths, sortedListed
	lists, err := EvsBuildDropLists(paths, listed)
	if err != nil {
		t.Fatal(err)
	}
	history := &protocol.EvsDropHistory{
		DropId: evsTestId("drop").Bytes(), Action: evsDropActionDrop, NotBeforeMs: evsTestDropTimeMs + EvsDropWindowMs, Paths: paths,
	}
	if mutate != nil {
		mutate(history)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	return evsTestDropPush(body), body, lists
}

// The push of a DROP whose body is body.
func evsTestDropPush(body []byte) *protocol.EvsPush {
	digest := sha256.Sum256(body)
	return &protocol.EvsPush{
		PushId: evsTestId("push drop").Bytes(), PathEpoch: evsTestDropPathEpoch, TimeMs: evsTestDropTimeMs,
		Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), DropSha256: digest[:],
	}
}

// The usual test drop: two paths, of 5 and 3 listed versions.
func evsTestTwoPathDrop(t testing.TB) (*protocol.EvsPush, []byte, []byte) {
	paths := []*protocol.EvsDropPath{evsTestDropPath("a", 9, evsDropBoundaryWritten), evsTestDropPath("b", 4, evsDropBoundaryRemoved)}
	return evsTestDrop(t, paths, [][][]byte{evsTestDropListed("a", 5), evsTestDropListed("b", 3)}, nil)
}

// What testdata/evs/format2/drop_vectors.json holds (schema.yml's vectors section).
type evsDropVectors struct {
	Cases      []*evsDropVectorCase       `json:"cases"`
	Membership []*evsDropMembershipVector `json:"membership"`
}

type evsDropVectorCase struct {
	Name   string     `json:"name"`
	Push   hexBytes   `json:"push"`
	Body   hexBytes   `json:"body"`
	Lists  hexBytes   `json:"lists"`
	Slices []hexBytes `json:"slices,omitempty"`
	Want   string     `json:"want"`
}

type evsDropMembershipVector struct {
	Epoch     uint64   `json:"epoch"`
	TokenPath hexBytes `json:"token_path"`
	Version   uint64   `json:"version"`
	Removal   bool     `json:"removal"`
	Path      int      `json:"path"`
}

// The verdict's name: ok, or the refusal code's.
func evsDropVerdict(err error) string {
	if err == nil {
		return "ok"
	}
	name := protocol.EvsRefusalCode_name[int32(EvsRefusalCodeOf(err))]
	return name[len("EVS_REFUSAL_"):]
}

// The cases: each built with its own expected verdict, which the vector stores and this build must reproduce.
func evsDropVectorCases(t testing.TB) []*evsDropVectorCase {
	cases := []*evsDropVectorCase{}
	add := func(name string, push *protocol.EvsPush, body []byte, lists []byte, slices [][]byte, want string) {
		pushBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(push)
		if err != nil {
			t.Fatal(err)
		}
		vector := &evsDropVectorCase{Name: name, Push: pushBytes, Body: body, Lists: lists, Want: want}
		for _, slice := range slices {
			vector.Slices = append(vector.Slices, slice)
		}
		cases = append(cases, vector)
	}
	push, body, lists := evsTestTwoPathDrop(t)
	add("a drop of two paths", push, body, lists, nil, "ok")
	add("the same lists split over three parts", push, body, lists, [][]byte{lists[:40], lists[40:200], lists[200:]}, "ok")
	add("a count one short", push, body, lists[:len(lists)-32], nil, "DROP_LIST")
	add("a value past the last count", push, body, append(bytes.Clone(lists), evsTestBytes("extra", 32)...), nil, "DROP_LIST")
	swapped := bytes.Clone(lists)
	copy(swapped[0:32], lists[32:64])
	copy(swapped[32:64], lists[0:32])
	add("an order swap", push, body, swapped, nil, "DROP_LIST")
	repeated := bytes.Clone(lists)
	copy(repeated[32:64], lists[0:32])
	add("a repeat", push, body, repeated, nil, "DROP_LIST")
	add("a list cut inside a value", push, body, lists[:len(lists)-1], nil, "DROP_LIST")

	tooMany := evsTestDropPath("c", EvsDropMaxListedCount+5, evsDropBoundaryWritten)
	pushMany, bodyMany, _ := evsTestDrop(t, []*protocol.EvsDropPath{tooMany}, [][][]byte{evsTestDropListed("c", 1)}, func(history *protocol.EvsDropHistory) {
		history.Paths[0].Count = EvsDropMaxListedCount + 1
	})
	add("a count past 2^20", pushMany, bodyMany, evsTestDropListed("c", 1)[0], nil, "DROP_LIST")

	pushNow, bodyNow, listsNow := evsTestDrop(t, []*protocol.EvsDropPath{evsTestDropPath("d", 3, evsDropBoundaryWritten)}, [][][]byte{evsTestDropListed("d", 2)}, func(history *protocol.EvsDropHistory) {
		history.NotBeforeMs = evsTestDropTimeMs
	})
	add("now", pushNow, bodyNow, listsNow, nil, "ok")
	pushLate, bodyLate, listsLate := evsTestDrop(t, []*protocol.EvsDropPath{evsTestDropPath("d", 3, evsDropBoundaryWritten)}, [][][]byte{evsTestDropListed("d", 2)}, func(history *protocol.EvsDropHistory) {
		history.NotBeforeMs = evsTestDropTimeMs + EvsDropWindowMs + 1
	})
	add("a not_before_ms off its values", pushLate, bodyLate, listsLate, nil, "DROP_STATE")

	cancel := &protocol.EvsDropHistory{
		DropId: evsTestId("cancel").Bytes(), Action: evsDropActionCancel, CancelsDropId: evsTestId("drop").Bytes(), CancelsVersion: 12,
	}
	cancelBody, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cancel)
	add("a cancel", evsTestDropPush(cancelBody), cancelBody, nil, nil, "ok")
	add("a cancel carrying lists", evsTestDropPush(cancelBody), cancelBody, lists[:32], nil, "INVALID")
	cancel.Paths = []*protocol.EvsDropPath{evsTestDropPath("e", 3, evsDropBoundaryWritten)}
	cancelWithPaths, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cancel)
	add("a cancel with paths", evsTestDropPush(cancelWithPaths), cancelWithPaths, nil, nil, "INVALID")

	noPaths := &protocol.EvsDropHistory{DropId: evsTestId("drop").Bytes(), Action: evsDropActionDrop, NotBeforeMs: evsTestDropTimeMs}
	noPathsBody, _ := proto.MarshalOptions{Deterministic: true}.Marshal(noPaths)
	add("a drop with no path", evsTestDropPush(noPathsBody), noPathsBody, nil, nil, "INVALID")

	wrongHash := evsTestDropPush(body)
	wrongHash.DropSha256 = evsTestBytes("another body", 32)
	add("a body off drop_sha256", wrongHash, body, lists, nil, "INVALID")
	return cases
}

func computeEvsDropVectors(t *testing.T) *evsDropVectors {
	cases := evsDropVectorCases(t)
	vectors := &evsDropVectors{Cases: cases}
	first := cases[0]
	push := &protocol.EvsPush{}
	if err := proto.Unmarshal(first.Push, push); err != nil {
		t.Fatal(err)
	}
	lists, err := NewEvsDropLists(push, first.Body)
	if err != nil {
		t.Fatal(err)
	}
	pathA := evsTestDropPath("a", 9, evsDropBoundaryWritten)
	pathB := evsTestDropPath("b", 4, evsDropBoundaryRemoved)
	questions := []struct {
		entry   *protocol.EvsSourcePath
		version uint64
		removal bool
	}{
		{entry: pathA.Lineage[0], version: 8},
		{entry: pathA.Lineage[0], version: 9},
		{entry: pathA.Lineage[1], version: 2},
		{entry: pathA.Lineage[1], version: 3, removal: true},
		{entry: pathB.Lineage[0], version: 3},
		{entry: pathB.Lineage[0], version: 4},
		{entry: &protocol.EvsSourcePath{Epoch: 2, TokenPath: pathA.Lineage[0].TokenPath}, version: 1},
		{entry: &protocol.EvsSourcePath{Epoch: 3, TokenPath: EvsTokenPath{evsTestToken("unlisted")}.Components()}, version: 1},
	}
	for _, question := range questions {
		tokenPath, _ := ParseEvsChangedTokenPath(question.entry.TokenPath)
		path, _ := lists.Lists(question.entry.Epoch, tokenPath, question.version, question.removal)
		vectors.Membership = append(vectors.Membership, &evsDropMembershipVector{
			Epoch: question.entry.Epoch, TokenPath: tokenPath.Bytes(), Version: question.version, Removal: question.removal, Path: path,
		})
	}
	return vectors
}

// Each stored case answers its stored verdict on this build, its slices checking as its whole list does; each stored
// membership question answers its stored lineage. The verdicts are written by hand in evsDropVectorCases, so a code
// change that moves one fails here.
func TestEvsDropVectors(t *testing.T) {
	stored := &evsDropVectors{}
	if !compareEvsVectors(t, "testdata/evs/format2/drop_vectors.json", evsDropVectorsJson, computeEvsDropVectors(t), stored) {
		return
	}
	for _, vector := range stored.Cases {
		push := &protocol.EvsPush{}
		if err := proto.Unmarshal(vector.Push, push); err != nil {
			t.Fatal(err)
		}
		slices := [][]byte{vector.Lists}
		if len(vector.Slices) != 0 {
			slices = nil
			for _, slice := range vector.Slices {
				slices = append(slices, slice)
			}
			if !bytes.Equal(bytes.Join(slices, nil), vector.Lists) {
				t.Errorf("%s: its slices are not its lists", vector.Name)
			}
		}
		_, err := EvsCheckDropPayload(push, vector.Body, slices)
		if got := evsDropVerdict(err); got != vector.Want {
			t.Errorf("%s: %s (%v), want %s", vector.Name, got, err, vector.Want)
		}
	}
	firstPush := &protocol.EvsPush{}
	if err := proto.Unmarshal(stored.Cases[0].Push, firstPush); err != nil {
		t.Fatal(err)
	}
	lists, err := NewEvsDropLists(firstPush, stored.Cases[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	wantListed := map[bool]int{}
	for _, question := range stored.Membership {
		components := [][]byte{}
		for at := 0; at < len(question.TokenPath); at += EvsTokenByteCount {
			components = append(components, question.TokenPath[at:at+EvsTokenByteCount])
		}
		tokenPath, err := ParseEvsChangedTokenPath(components)
		if err != nil {
			t.Fatal(err)
		}
		path, listed := lists.Lists(question.Epoch, tokenPath, question.Version, question.Removal)
		if path != question.Path || listed != (0 <= question.Path) {
			t.Errorf("version %d of %x in epoch %d: path %d, want %d", question.Version, question.TokenPath, question.Epoch, path, question.Path)
		}
		wantListed[listed] += 1
	}
	if wantListed[true] == 0 || wantListed[false] == 0 {
		t.Error("the membership vectors hold no listed or no unlisted version")
	}
}

// plan-EVS2-drop-list-proof's membership by hand: below through_version in any lineage epoch is listed, at it is not,
// a removal never is, the same token path in another epoch is not, and a cancel lists nothing.
func TestEvsDropListsMembership(t *testing.T) {
	push, body, _ := evsTestTwoPathDrop(t)
	lists, err := NewEvsDropLists(push, body)
	if err != nil {
		t.Fatal(err)
	}
	pathA := evsTestDropPath("a", 9, evsDropBoundaryWritten)
	newest, _ := ParseEvsChangedTokenPath(pathA.Lineage[0].TokenPath)
	older, _ := ParseEvsChangedTokenPath(pathA.Lineage[1].TokenPath)
	indexA := slices.IndexFunc(lists.History().GetPaths(), func(path *protocol.EvsDropPath) bool {
		return path.GetThroughVersion() == 9
	})
	cases := []struct {
		name     string
		epoch    uint64
		path     EvsTokenPath
		version  uint64
		removal  bool
		wantPath int
	}{
		{name: "below through_version", epoch: 3, path: newest, version: 8, wantPath: indexA},
		{name: "through_version itself", epoch: 3, path: newest, version: 9, wantPath: -1},
		{name: "in its older epoch", epoch: 2, path: older, version: 1, wantPath: indexA},
		{name: "a removal", epoch: 3, path: newest, version: 5, removal: true, wantPath: -1},
		{name: "its token path in another epoch", epoch: 2, path: newest, version: 1, wantPath: -1},
		{name: "version 0", epoch: 3, path: newest, version: 0, wantPath: -1},
	}
	for _, c := range cases {
		if path, _ := lists.Lists(c.epoch, c.path, c.version, c.removal); path != c.wantPath {
			t.Errorf("%s: path %d, want %d", c.name, path, c.wantPath)
		}
	}
	cancel := &protocol.EvsDropHistory{DropId: evsTestId("cancel").Bytes(), Action: evsDropActionCancel, CancelsDropId: evsTestId("drop").Bytes(), CancelsVersion: 3}
	cancelBody, _ := proto.Marshal(cancel)
	cancelLists, err := NewEvsDropLists(evsTestDropPush(cancelBody), cancelBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, listed := cancelLists.Lists(3, newest, 1, false); listed {
		t.Error("a cancel lists a version")
	}
	if _, err := NewEvsDropLists(evsTestDropPush(body), evsTestBytes("another body", 32)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a body off drop_sha256: %v", err)
	}
}

// Each DROP_LIST shape and each shape refusal, with the codes they answer: DROP_LIST for the lists and counts, INVALID
// for the body's shape, DROP_STATE for not_before_ms.
func TestEvsDropPayloadRefusals(t *testing.T) {
	paths := func() []*protocol.EvsDropPath {
		return []*protocol.EvsDropPath{evsTestDropPath("a", 9, evsDropBoundaryWritten), evsTestDropPath("b", 4, evsDropBoundaryRemoved)}
	}
	listed := [][][]byte{evsTestDropListed("a", 5), evsTestDropListed("b", 3)}
	cases := []struct {
		name   string
		mutate func(*protocol.EvsDropHistory)
		want   error
	}{
		{name: "a count one over", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].Count += 1 }, want: ErrEvsDropList},
		{name: "a count one under", mutate: func(history *protocol.EvsDropHistory) { history.Paths[1].Count -= 1 }, want: ErrEvsDropList},
		{name: "a count of 0", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].Count = 0 }, want: ErrEvsDropList},
		{name: "a count at through_version", mutate: func(history *protocol.EvsDropHistory) { history.Paths[1].ThroughVersion = 3 }, want: ErrEvsDropList},
		{name: "a hash off", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].ListedSha256 = evsTestBytes("off", 32) }, want: ErrEvsDropList},
		{name: "paths out of order", mutate: func(history *protocol.EvsDropHistory) {
			history.Paths[0], history.Paths[1] = history.Paths[1], history.Paths[0]
		}, want: ErrEvsPushInvalid},
		{name: "a path twice", mutate: func(history *protocol.EvsDropHistory) { history.Paths[1] = history.Paths[0] }, want: ErrEvsPushInvalid},
		{name: "past 1,024 paths", mutate: func(history *protocol.EvsDropHistory) {
			for len(history.Paths) <= EvsDropMaxPathCount {
				history.Paths = append(history.Paths, history.Paths[0])
			}
		}, want: ErrEvsPushInvalid},
		{name: "a lineage of epochs not descending", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].Lineage[1].Epoch = 3 }, want: ErrEvsPushInvalid},
		{name: "a lineage newer than the push", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].Lineage[0].Epoch = 4 }, want: ErrEvsPushInvalid},
		{name: "a map part missing", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].MapParts = nil }, want: ErrEvsPushInvalid},
		{name: "boundary 3", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].Boundary = 3 }, want: ErrEvsPushInvalid},
		{name: "through_version 1", mutate: func(history *protocol.EvsDropHistory) { history.Paths[0].ThroughVersion = 1 }, want: ErrEvsPushInvalid},
		{name: "a drop naming a cancel", mutate: func(history *protocol.EvsDropHistory) { history.CancelsVersion = 3 }, want: ErrEvsPushInvalid},
		{name: "action 3", mutate: func(history *protocol.EvsDropHistory) { history.Action = 3 }, want: ErrEvsPushInvalid},
		{name: "a drop_id of 8 bytes", mutate: func(history *protocol.EvsDropHistory) { history.DropId = history.DropId[:8] }, want: ErrEvsPushInvalid},
		{name: "a preview_id of 8 bytes", mutate: func(history *protocol.EvsDropHistory) { history.PreviewId = evsTestBytes("preview", 8) }, want: ErrEvsPushInvalid},
		{name: "not_before_ms a day out", mutate: func(history *protocol.EvsDropHistory) { history.NotBeforeMs = evsTestDropTimeMs + 86400000 }, want: ErrEvsDropState},
	}
	for _, c := range cases {
		push, body, lists := evsTestDrop(t, paths(), listed, c.mutate)
		_, err := EvsCheckDropPayload(push, body, [][]byte{lists})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	push, body, lists := evsTestTwoPathDrop(t)
	if _, err := EvsCheckDropPayload(push, body, [][]byte{lists}); err != nil {
		t.Fatalf("the passing twin: %v", err)
	}
	for _, code := range []struct {
		err  error
		want protocol.EvsRefusalCode
	}{
		{err: ErrEvsDropList, want: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST},
		{err: ErrEvsDropState, want: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE},
		{err: ErrEvsVersioning, want: protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING},
	} {
		if EvsRefusalCodeOf(fmt.Errorf("wrapped: %w", code.err)) != code.want {
			t.Errorf("%v answers %v", code.err, EvsRefusalCodeOf(code.err))
		}
	}
	if _, err := EvsBuildDropLists(paths()[:1], [][][]byte{{evsTestBytes("x", 32), evsTestBytes("x", 32)}}); !errors.Is(err, ErrEvsDropList) {
		t.Errorf("a version listed twice: %v", err)
	}
}

// A list spread over parts, split anywhere, inside a value too, checks as the one list does; the same split of a
// list with a repeat still refuses.
func TestEvsDropListsSplitAnywhere(t *testing.T) {
	push, body, lists := evsTestTwoPathDrop(t)
	random := mathrand.New(mathrand.NewPCG(1, 2))
	split := func(lists []byte) [][]byte {
		slices := [][]byte{}
		for rest := lists; 0 < len(rest); {
			take := min(len(rest), random.IntN(50))
			slices = append(slices, rest[:take])
			rest = rest[take:]
		}
		return slices
	}
	for range 50 {
		if _, err := EvsCheckDropPayload(push, body, split(lists)); err != nil {
			t.Fatalf("a split list: %v", err)
		}
	}
	repeated := bytes.Clone(lists)
	copy(repeated[64:96], lists[32:64])
	for range 20 {
		if _, err := EvsCheckDropPayload(push, body, split(repeated)); !errors.Is(err, ErrEvsDropList) {
			t.Fatalf("a split list with a repeat: %v", err)
		}
	}
}

// Format 2's DROP statement and payload through the push checks: a one-part DROP checks with its body and lists; a push
// in parts carries them in its parts' slices, which the seal streams; a DROP with other flags, an index_epoch, or no
// drop_sha256, and DROP sections under a push without flag 256, are refused; format 1 refuses the statement.
func TestEvsDropThroughThePushChecks(t *testing.T) {
	signer := newEvsTestSigner("drop writer")
	_, body, lists := evsTestTwoPathDrop(t)

	plan := evsTestPlan(t, signer, "drop one part", 2)
	plan.PathEpoch = evsTestDropPathEpoch
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	plan.DropBody = body
	plan.DropLists = lists
	if _, err := NewEvsStatementBuilder(signer.sign).Build(plan); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1's builder built a DROP: %v", err)
	}
	built, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEvsStatement(built.Statement.Bytes); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1 parsed a DROP: %v", err)
	}
	statement, err := ParseEvsStatementFormat2(built.Statement.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := EvsCheckPayloadFormat2(statement, built.Payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if checked.Drop == nil || checked.Drop.Cancel() || len(checked.Drop.History.GetPaths()) != 2 || !bytes.Equal(checked.Drop.Body, body) {
		t.Error("the DROP was not adopted as written")
	}

	many := evsTestPlan(t, signer, "drop parts", 1100)
	many.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	bigPaths := []*protocol.EvsDropPath{evsTestDropPath("big", 20001, evsDropBoundaryWritten)}
	bigLists, err := EvsBuildDropLists(bigPaths, [][][]byte{evsTestDropListed("big", 20000)})
	if err != nil {
		t.Fatal(err)
	}
	bigBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsDropHistory{
		DropId: evsTestId("big drop").Bytes(), Action: evsDropActionDrop, NotBeforeMs: many.TimeMs, Paths: bigPaths,
	})
	if err != nil {
		t.Fatal(err)
	}
	many.PathEpoch = evsTestDropPathEpoch
	many.DropBody = bigBody
	many.DropLists = bigLists
	builtMany, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(many)
	if err != nil {
		t.Fatal(err)
	}
	carrying := 0
	for _, partBytes := range builtMany.Parts {
		part, _, err := parseEvsPushPart(partBytes)
		if err != nil {
			t.Fatal(err)
		}
		sections, err := parseEvsPayload(part.GetSections(), true)
		if err != nil {
			t.Fatal(err)
		}
		if len(sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS)) != 0 {
			carrying += 1
		}
	}
	if carrying < 2 {
		t.Errorf("640 KB of lists rode in %d parts", carrying)
	}
	checkedMany, _, err := EvsCheckSealFormat2(builtMany.Statement, builtMany.Parts, make([][]byte, len(builtMany.Parts)))
	if err != nil {
		t.Fatal(err)
	}
	if checkedMany.Drop == nil || checkedMany.Drop.History.GetPaths()[0].GetCount() != 20000 {
		t.Error("the seal did not adopt the DROP")
	}
	if _, _, err := EvsCheckSeal(builtMany.Statement, builtMany.Parts); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1's seal took a DROP's sections: %v", err)
	}

	// statement shapes
	shapes := []struct {
		name   string
		mutate func(*protocol.EvsPush)
	}{
		{name: "DROP with FORCE", mutate: func(push *protocol.EvsPush) { push.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) }},
		{name: "DROP with an index_epoch", mutate: func(push *protocol.EvsPush) { push.IndexEpoch = 3 }},
		{name: "DROP without drop_sha256", mutate: func(push *protocol.EvsPush) { push.DropSha256 = nil }},
		{name: "drop_sha256 without DROP", mutate: func(push *protocol.EvsPush) { push.Flags = 0 }},
		{name: "a drop_sha256 of 16 bytes", mutate: func(push *protocol.EvsPush) { push.DropSha256 = push.DropSha256[:16] }},
	}
	for _, shape := range shapes {
		push := proto.Clone(statement.Push).(*protocol.EvsPush)
		shape.mutate(push)
		if _, err := NewEvsStatementBuilder(signer.sign).signStatementOf(push, false); err == nil {
			t.Errorf("%s: format 1 took it", shape.name)
		}
		if _, err := NewEvsStatementBuilder(signer.sign).signStatementOf(push, true); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", shape.name, err)
		}
	}
	cut := proto.Clone(statement.Push).(*protocol.EvsPush)
	cut.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	cut.DropSha256 = nil
	cut.IndexEpoch = 7
	if _, err := NewEvsStatementBuilder(signer.sign).signStatementOf(cut, true); err != nil {
		t.Errorf("a CUT's shape: %v", err)
	}

	// DROP sections under a push without flag 256
	plain := evsTestPlan(t, signer, "plain with drop sections", 2)
	builtPlain, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(plain)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parseEvsPayload(builtPlain.Payload, true)
	if err != nil {
		t.Fatal(err)
	}
	payload.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, body)
	if _, err := EvsCheckPayloadFormat2(builtPlain.Statement, payload.Encode(), nil); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a DROP body without flag 256: %v", err)
	}
}

// §22.6's DROP target: whatever is done to a DROP's body or lists, one that still checks against its statement adopts
// exactly the original's body, and so its paths, counts and list hashes.
func checkEvsDropTampering(t *testing.T, push *protocol.EvsPush, body []byte, lists []byte, input []byte) {
	tamperedBody, tamperedLists := body, lists
	if 0 < len(input) {
		if input[0]%2 == 0 {
			tamperedBody = evsFuzzTamper(body, input[1:], func([]byte) {})
		} else {
			tamperedLists = evsFuzzTamper(lists, input[1:], func([]byte) {})
		}
	}
	checked, err := EvsCheckDropPayload(push, tamperedBody, [][]byte{tamperedLists})
	if err != nil {
		return
	}
	if !bytes.Equal(checked.Body, body) || !bytes.Equal(tamperedLists, lists) {
		t.Fatal("a tampered DROP was adopted")
	}
}

func TestEvsDropFuzzSeeds(t *testing.T) {
	push, body, lists := evsTestTwoPathDrop(t)
	checkEvsDropTampering(t, push, body, lists, nil)
	for _, seed := range evsDropFuzzSeedFiles(t, "testdata/fuzz/evs_drop") {
		checkEvsDropTampering(t, push, body, lists, seed)
	}
}

// schema.yml's vectors section names each format-2 vector file's top-level keys, which the files hold exactly, so a
// reviewer reading the schema reads the files' shape.
func TestEvsFormat2VectorFilesMatchTheSchema(t *testing.T) {
	schema := &struct {
		Vectors map[string]map[string]string `yaml:"vectors"`
	}{}
	if err := yaml.Unmarshal(evsFormat2SchemaYaml, schema); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"testdata/evs/format2/segment_vectors.json": evsFormat2SegmentVectorsJson,
		"testdata/evs/format2/batch_vectors.json":   evsFormat2BatchVectorsJson,
		"testdata/evs/format2/drop_vectors.json":    evsDropVectorsJson,
	}
	for path, data := range files {
		keys, ok := schema.Vectors[path]
		if !ok {
			t.Errorf("the schema names no %s", path)
			continue
		}
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if !maps.EqualFunc(fields, keys, func(json.RawMessage, string) bool { return true }) {
			t.Errorf("%s holds %v, and the schema names %v", path, slices.Sorted(maps.Keys(fields)), slices.Sorted(maps.Keys(keys)))
		}
	}
}
