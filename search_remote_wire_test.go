//go:build !sidecar_http && !ios_extension

// Remote search's exact sizes (DESIGN-DETAILS 11.2.9 and 11.6's unit tests for sizes; FS-83's size cases at this
// layer; D-EVS-59): Z2 against the marshaler for every pad length, Z3 at every content of every size, the caps'
// bounds, every request shape, seeded replies, the replies that sit on the 16,387 B gap, Z8's refusals in its
// order, and sizes.json. testSearchWalk is a reading of Z9's rule of bytes that calls no marshaler, held to
// every body the builders make.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The five sizes a body may have: a request, and a reply of 1 to 4 steps.
func testSearchBodySizes(settings *SearchWireSettings) []int {
	sizes := []int{settings.RequestByteCount}
	for steps := 1; steps <= settings.MaxStepCount; steps += 1 {
		sizes = append(sizes, steps*settings.StepByteCount)
	}
	return sizes
}

// A 16 B id whose first byte is b.
func testSearchId(b byte) []byte {
	id := bytes.Repeat([]byte{0x11}, 16)
	id[0] = b
	return id
}

// content followed by Z1's pad sized to bodyByteCount by Z2, the way a builder writes it.
func testSearchPadded(t *testing.T, content []byte, bodyByteCount int) []byte {
	t.Helper()
	settings := DefaultSearchWireSettings()
	padByteCount, ok := searchRemotePadByteCount(bodyByteCount, len(content), settings)
	if !ok {
		t.Fatalf("no pad sizes %d B to %d B", len(content), bodyByteCount)
	}
	body := protowire.AppendTag(append([]byte{}, content...), searchPadFieldNumber, protowire.BytesType)
	body = protowire.AppendVarint(body, uint64(padByteCount))
	return append(body, make([]byte, padByteCount)...)
}

// message's fields other than pad, deterministically encoded, with no cap checked.
func testSearchContent(t *testing.T, message proto.Message) []byte {
	t.Helper()
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// A page-0 request within the caps.
func testSearchRequest() *protocol.SearchRequest {
	return &protocol.SearchRequest{
		SearchVersion: 1,
		SearchId:      0x0102030405060708,
		Steps:         1,
		Scope:         2,
		Query:         "needle haystack",
		Repos:         []*protocol.SearchRepo{{RepoId: testSearchId(1)}, {RepoId: testSearchId(2), RefId: testSearchId(3)}},
	}
}

// A hit within the caps with locator and snippet of these lengths.
func testSearchHit(n int, locatorByteCount int, snippetByteCount int, fieldCount int) *protocol.SearchHit {
	fields := []*protocol.SearchField{}
	for i := range fieldCount {
		fields = append(fields, &protocol.SearchField{Field: uint32(1 + i), Text: strings.Repeat("f", 256)})
	}
	return &protocol.SearchHit{
		RepoId:    testSearchId(1),
		RefId:     testSearchId(2),
		DocKey:    testSearchId(byte(n)),
		Version:   uint64(1000 + n),
		TimeMs:    1_790_000_000_000 - int64(n),
		DocKind:   2,
		Locator:   strings.Repeat("l", locatorByteCount),
		State:     1,
		Partition: 1,
		Trust:     1,
		Signer:    testSearchId(9),
		Fields:    fields,
		Snippet:   strings.Repeat("s", snippetByteCount),
		Line:      uint32(n),
	}
}

// A page-0 head of rows coverage rows whose checked_through_ms follows the hits returned, as SEARCH-M10-32's
// does: pure in k.
func testSearchHead(rows int, hits []*protocol.SearchHit, status protocol.SearchStatus) func(hitCount int) *protocol.SearchReply {
	return func(hitCount int) *protocol.SearchReply {
		coverage := []*protocol.SearchCoverage{}
		for i := range rows {
			coverage = append(coverage, &protocol.SearchCoverage{
				RepoId: testSearchId(byte(i)), RefId: testSearchId(byte(i + 1)), Served: uint32(protocol.SearchServed_SERVED_TEXT),
				RefVersion: 77, Chain: bytes.Repeat([]byte{0xc4}, 32), RefTimeMs: 1_790_000_000_000, LatestFromMs: 1_789_000_000_000,
			})
		}
		checkedThroughMs := int64(0)
		if hitCount < len(hits) {
			checkedThroughMs = hits[hitCount].GetTimeMs()
		}
		return &protocol.SearchReply{
			SearchVersion:    1,
			MinVersion:       1,
			MaxVersion:       1,
			SearchId:         0x0102030405060708,
			Status:           uint32(status),
			Phase:            1,
			Complete:         hitCount == len(hits),
			CheckedThroughMs: checkedThroughMs,
			Coverage:         coverage,
			Counts:           &protocol.SearchCounts{Checked: uint32(hitCount), Verified: uint32(hitCount)},
		}
	}
}

// Z9's rule of bytes, read without the marshaler: each message's fields by number, with how each is written.
type testSearchWalkKind int

const (
	testSearchWalkUint32 testSearchWalkKind = iota + 1
	testSearchWalkUint64
	testSearchWalkBool
	testSearchWalkFixed64
	testSearchWalkString
	testSearchWalkBytes
	testSearchWalkMessage
	testSearchWalkPackedUint32
)

type testSearchWalkField struct {
	kind     testSearchWalkKind
	repeated bool
	message  string
}

// search.proto's messages as Z9 reads them, written from the proto file by hand.
var testSearchWalkSchemas = map[string]map[protowire.Number]testSearchWalkField{
	"SearchRequest": {
		1: {kind: testSearchWalkUint32}, 2: {kind: testSearchWalkFixed64}, 3: {kind: testSearchWalkUint32},
		4: {kind: testSearchWalkFixed64}, 5: {kind: testSearchWalkUint32}, 6: {kind: testSearchWalkUint32},
		7: {kind: testSearchWalkString}, 8: {kind: testSearchWalkMessage, repeated: true, message: "SearchRepo"},
		9: {kind: testSearchWalkUint64}, 10: {kind: testSearchWalkUint64},
		11: {kind: testSearchWalkMessage, message: "SearchFilters"}, 12: {kind: testSearchWalkBool},
		15: {kind: testSearchWalkBytes},
	},
	"SearchRepo": {1: {kind: testSearchWalkBytes}, 2: {kind: testSearchWalkBytes}},
	"SearchFilters": {
		1: {kind: testSearchWalkString, repeated: true}, 2: {kind: testSearchWalkBytes, repeated: true},
		3: {kind: testSearchWalkBytes, repeated: true}, 4: {kind: testSearchWalkBytes, repeated: true},
		5: {kind: testSearchWalkString, repeated: true}, 6: {kind: testSearchWalkPackedUint32},
		7: {kind: testSearchWalkString}, 8: {kind: testSearchWalkMessage, repeated: true, message: "SearchField"},
	},
	"SearchField": {1: {kind: testSearchWalkUint32}, 2: {kind: testSearchWalkString}},
	"SearchReply": {
		1: {kind: testSearchWalkUint32}, 2: {kind: testSearchWalkUint32}, 3: {kind: testSearchWalkUint32},
		4: {kind: testSearchWalkFixed64}, 5: {kind: testSearchWalkUint32}, 6: {kind: testSearchWalkUint32},
		7: {kind: testSearchWalkUint32}, 8: {kind: testSearchWalkBool}, 9: {kind: testSearchWalkUint64},
		10: {kind: testSearchWalkMessage, repeated: true, message: "SearchCoverage"},
		11: {kind: testSearchWalkMessage, repeated: true, message: "SearchHit"},
		12: {kind: testSearchWalkMessage, message: "SearchCounts"}, 15: {kind: testSearchWalkBytes},
	},
	"SearchCoverage": {
		1: {kind: testSearchWalkBytes}, 2: {kind: testSearchWalkBytes}, 3: {kind: testSearchWalkUint32},
		4: {kind: testSearchWalkUint64}, 5: {kind: testSearchWalkBytes}, 6: {kind: testSearchWalkUint64},
		7: {kind: testSearchWalkUint64}, 8: {kind: testSearchWalkUint32},
	},
	"SearchHit": {
		1: {kind: testSearchWalkBytes}, 2: {kind: testSearchWalkBytes}, 3: {kind: testSearchWalkBytes},
		4: {kind: testSearchWalkUint64}, 5: {kind: testSearchWalkUint64}, 6: {kind: testSearchWalkUint32},
		7: {kind: testSearchWalkString}, 8: {kind: testSearchWalkUint32}, 9: {kind: testSearchWalkString},
		10: {kind: testSearchWalkUint32}, 11: {kind: testSearchWalkUint32}, 12: {kind: testSearchWalkBytes},
		13: {kind: testSearchWalkMessage, repeated: true, message: "SearchField"},
		14: {kind: testSearchWalkString}, 15: {kind: testSearchWalkUint32},
	},
	"SearchCounts": {
		1: {kind: testSearchWalkUint32}, 2: {kind: testSearchWalkUint32}, 3: {kind: testSearchWalkUint32},
		4: {kind: testSearchWalkUint32}, 5: {kind: testSearchWalkUint32},
	},
}

// A varint at the front of b at its shortest, else n < 0.
func testSearchWalkVarint(b []byte) (uint64, int) {
	v, n := protowire.ConsumeVarint(b)
	if n < 0 || n != protowire.SizeVarint(v) {
		return 0, -1
	}
	return v, n
}

// Whether b is the one encoding of a message named name by Z9's words: fields ascending by number, each once
// unless repeated, a repeated field's elements together; a zero number or bool and an empty string or bytes left
// out unless an element of a repeated field; a message field written when present, though empty; every varint
// at its shortest; kinds one packed record left out when empty; a message field's bytes its own one encoding.
func testSearchWalk(b []byte, name string) bool {
	schema := testSearchWalkSchemas[name]
	last := protowire.Number(0)
	for 0 < len(b) {
		tag, n := testSearchWalkVarint(b)
		if n < 0 {
			return false
		}
		b = b[n:]
		number, wireType := protowire.Number(tag>>3), protowire.Type(tag&7)
		field, ok := schema[number]
		if !ok || number < last {
			return false
		}
		if number == last && (!field.repeated || field.kind == testSearchWalkPackedUint32) {
			return false
		}
		last = number
		switch field.kind {
		case testSearchWalkUint32, testSearchWalkUint64, testSearchWalkBool:
			if wireType != protowire.VarintType {
				return false
			}
			v, n := testSearchWalkVarint(b)
			if n < 0 || (field.kind == testSearchWalkUint32 && 0xFFFFFFFF < v) || (field.kind == testSearchWalkBool && 1 < v) {
				return false
			}
			if !field.repeated && v == 0 {
				return false
			}
			b = b[n:]
		case testSearchWalkFixed64:
			if wireType != protowire.Fixed64Type {
				return false
			}
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 || v == 0 {
				return false
			}
			b = b[n:]
		default:
			if wireType != protowire.BytesType {
				return false
			}
			length, n := testSearchWalkVarint(b)
			if n < 0 || uint64(len(b)-n) < length {
				return false
			}
			value := b[n : n+int(length)]
			b = b[n+int(length):]
			switch field.kind {
			case testSearchWalkString:
				if !utf8.Valid(value) || (!field.repeated && len(value) == 0) {
					return false
				}
			case testSearchWalkBytes:
				if !field.repeated && len(value) == 0 {
					return false
				}
			case testSearchWalkMessage:
				if !testSearchWalk(value, field.message) {
					return false
				}
			case testSearchWalkPackedUint32:
				if len(value) == 0 {
					return false
				}
				for 0 < len(value) {
					v, n := testSearchWalkVarint(value)
					if n < 0 || 0xFFFFFFFF < v {
						return false
					}
					value = value[n:]
				}
			}
		}
	}
	return true
}

// Every pad length 1 to 70,000 through the marshaler: the gaps it cannot fill, 0 to 65,536, are 1, 2, 130 and
// 16,387, and Z2 gives the marshaler's length for every gap it accepts, every gap from 131 but 16,387 among them.
func TestSearchPadFillsEveryGapButFour(t *testing.T) {
	settings := DefaultSearchWireSettings()
	maxGap := settings.MaxStepCount * settings.StepByteCount
	zeros := make([]byte, 70_000)
	gapPads := map[int]int{}
	for padByteCount := 1; padByteCount <= len(zeros); padByteCount += 1 {
		gap := proto.Size(&protocol.SearchReply{Pad: zeros[:padByteCount]})
		if _, ok := gapPads[gap]; !ok {
			gapPads[gap] = padByteCount
		}
	}
	unfilled := []int{}
	for gap := 1; gap <= maxGap; gap += 1 {
		if _, ok := gapPads[gap]; !ok {
			unfilled = append(unfilled, gap)
		}
	}
	if len(unfilled) != 4 || unfilled[0] != 1 || unfilled[1] != 2 || unfilled[2] != 130 || unfilled[3] != 16387 {
		t.Errorf("the marshaler leaves gaps %v", unfilled)
	}
	for gap := 0; gap <= maxGap; gap += 1 {
		padByteCount, ok := searchRemotePadByteCount(maxGap, maxGap-gap, settings)
		if ok != (131 <= gap && gap != 16387) {
			t.Fatalf("gap %d: Z2 answers %v", gap, ok)
		}
		// from 131 B a gap has one pad length, so Z2's is the marshaler's
		if ok && (proto.Size(&protocol.SearchReply{Pad: zeros[:padByteCount]}) != gap || padByteCount != gapPads[gap]) {
			t.Fatalf("gap %d: Z2's pad of %d B encodes otherwise", gap, padByteCount)
		}
	}
}

// Every content at the five sizes: admissible exactly when 0 <= content <= size - 131 and size - content is not
// 16,387, and then sizable to the byte.
func TestSearchAdmissibleIsSound(t *testing.T) {
	settings := DefaultSearchWireSettings()
	for _, size := range testSearchBodySizes(settings) {
		for content := -1; content <= size; content += 1 {
			admissible := searchRemoteAdmissible(size, content, settings)
			if admissible != (0 <= content && content <= size-131 && size-content != 16387) {
				t.Fatalf("size %d, content %d: admissible %v", size, content, admissible)
			}
			if !admissible {
				continue
			}
			padByteCount, ok := searchRemotePadByteCount(size, content, settings)
			if !ok || content+1+protowire.SizeVarint(uint64(padByteCount))+padByteCount != size {
				t.Fatalf("size %d, content %d: pad %d", size, content, padByteCount)
			}
		}
	}
}

// The marshaler's sizes at the caps, every integer at its widest: a page-0 request 3,778 B, a later page 36 B, a
// reply of 64 coverage rows and no hit 7,578 B, one hit 3,248 B more, a reply's head without rows 90 B, which
// bounds every failure's reply.
func TestSearchCapBounds(t *testing.T) {
	settings := DefaultSearchWireSettings()
	widest32 := uint32(0xFFFFFFFF)
	widest64 := ^uint64(0)
	repos := []*protocol.SearchRepo{}
	for range settings.RepoMaxCount {
		repos = append(repos, &protocol.SearchRepo{RepoId: testSearchId(0xff), RefId: testSearchId(0xff)})
	}
	filters := &protocol.SearchFilters{PathPrefix: strings.Repeat("p", settings.FiltersMaxByteCount-3)}
	if proto.Size(filters) != settings.FiltersMaxByteCount {
		t.Fatalf("filters of %d B", proto.Size(filters))
	}
	pageZero := &protocol.SearchRequest{
		SearchVersion: widest32, SearchId: widest64, Supersedes: widest64, Steps: widest32, Scope: widest32,
		Query: strings.Repeat("q", settings.QueryMaxByteCount), Repos: repos, SinceMs: -1, UntilMs: -1,
		Filters: filters, Fuzzy: true,
	}
	laterPage := &protocol.SearchRequest{SearchVersion: widest32, SearchId: widest64, Page: widest32, Supersedes: widest64, Steps: widest32}
	coverage := []*protocol.SearchCoverage{}
	for range settings.CoverageMaxCount {
		coverage = append(coverage, &protocol.SearchCoverage{
			RepoId: testSearchId(0xff), RefId: testSearchId(0xff), Served: widest32, RefVersion: widest64,
			Chain: make([]byte, settings.ChainMaxByteCount), RefTimeMs: -1, LatestFromMs: -1, Uncovered: widest32,
		})
	}
	head := &protocol.SearchReply{
		SearchVersion: widest32, MinVersion: widest32, MaxVersion: widest32, SearchId: widest64, Page: widest32,
		Status: widest32, Phase: widest32, Complete: true, CheckedThroughMs: -1,
		Counts: &protocol.SearchCounts{Checked: widest32, Verified: widest32, Possible: widest32, Near: widest32, Masked: widest32},
	}
	withCoverage := proto.Clone(head).(*protocol.SearchReply)
	withCoverage.Coverage = coverage
	fields := []*protocol.SearchField{}
	for range settings.HitFieldMaxCount {
		fields = append(fields, &protocol.SearchField{Field: widest32, Text: strings.Repeat("f", settings.HitFieldTextMaxByteCount)})
	}
	hit := &protocol.SearchHit{
		RepoId: testSearchId(0xff), RefId: testSearchId(0xff), DocKey: testSearchId(0xff), Version: widest64, TimeMs: -1,
		DocKind: widest32, Locator: strings.Repeat("l", settings.LocatorMaxByteCount), State: widest32,
		Correction: strings.Repeat("c", settings.CorrectionMaxByteCount), Partition: widest32, Trust: widest32,
		Signer: testSearchId(0xff), Fields: fields, Snippet: strings.Repeat("s", settings.SnippetMaxByteCount), Line: widest32,
	}
	withHit := proto.Clone(withCoverage).(*protocol.SearchReply)
	withHit.Hits = []*protocol.SearchHit{hit}
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{name: "page 0", got: proto.Size(pageZero), want: 3778},
		{name: "a later page", got: proto.Size(laterPage), want: 36},
		{name: "64 rows, no hit", got: proto.Size(withCoverage), want: 7578},
		{name: "one hit", got: proto.Size(withHit) - proto.Size(withCoverage), want: 3248},
		{name: "a head without rows", got: proto.Size(head), want: 90},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d B, want %d", c.name, c.got, c.want)
		}
	}
	// each is admissible at the tightest size it meets (Z-B, Z-C)
	if !searchRemoteAdmissible(settings.RequestByteCount, proto.Size(pageZero), settings) ||
		!searchRemoteAdmissible(settings.StepByteCount, proto.Size(withHit), settings) {
		t.Errorf("a content at its caps is not admissible")
	}
	for steps := 1; steps <= settings.MaxStepCount; steps += 1 {
		if !searchRemoteAdmissible(steps*settings.StepByteCount, proto.Size(head), settings) {
			t.Errorf("a failure's head is not admissible at %d steps", steps)
		}
	}
}

// Every query length 0 to 512 with every repo count 0 to 64, with no filters and with filters of 3, 127, 128 and
// 768 B: each built exactly 4,016 B, parsed back equal, accepted by Z8 and walked as Z9's one encoding.
func TestSearchRequestSizes(t *testing.T) {
	settings := DefaultSearchWireSettings()
	repos := []*protocol.SearchRepo{}
	for i := range settings.RepoMaxCount {
		repo := &protocol.SearchRepo{RepoId: testSearchId(byte(i))}
		if i%2 == 1 {
			repo.RefId = testSearchId(byte(i + 64))
		}
		repos = append(repos, repo)
	}
	filterSets := []*protocol.SearchFilters{nil}
	for _, byteCount := range []int{3, 127, 128, 768} {
		filters := &protocol.SearchFilters{PathPrefix: strings.Repeat("p", byteCount-1-protowire.SizeVarint(uint64(byteCount)))}
		if byteCount == 128 {
			filters = &protocol.SearchFilters{PathPrefix: strings.Repeat("p", 126)}
		}
		if proto.Size(filters) != byteCount {
			t.Fatalf("filters of %d B, want %d", proto.Size(filters), byteCount)
		}
		filterSets = append(filterSets, filters)
	}
	query := strings.Repeat("q", settings.QueryMaxByteCount)
	built := 0
	for queryByteCount := 0; queryByteCount <= settings.QueryMaxByteCount; queryByteCount += 1 {
		for repoCount := 0; repoCount <= settings.RepoMaxCount; repoCount += 1 {
			for _, filters := range filterSets {
				request := &protocol.SearchRequest{
					SearchVersion: 1, SearchId: uint64(queryByteCount)<<8 | uint64(repoCount) + 1, Steps: 1, Scope: 2,
					Query: query[:queryByteCount], Repos: repos[:repoCount], Filters: filters,
				}
				body, err := searchRemoteBuildRequest(request, settings)
				if err != nil {
					t.Fatalf("query %d B, %d repos: %v", queryByteCount, repoCount, err)
				}
				if len(body) != settings.RequestByteCount {
					t.Fatalf("query %d B, %d repos: %d B", queryByteCount, repoCount, len(body))
				}
				parsed, status := searchRemoteParseRequest(body, settings)
				if status != protocol.SearchStatus_SEARCH_OK {
					t.Fatalf("query %d B, %d repos: %v", queryByteCount, repoCount, status)
				}
				parsed.Pad = nil
				if !proto.Equal(parsed, request) {
					t.Fatalf("query %d B, %d repos: parsed back otherwise", queryByteCount, repoCount)
				}
				// the walker on a sample, since it adds nothing per body the marshaler check does not
				if built%97 == 0 && !testSearchWalk(body, "SearchRequest") {
					t.Fatalf("query %d B, %d repos: not walked as one encoding", queryByteCount, repoCount)
				}
				built += 1
			}
		}
	}
	if built != 166_725 {
		t.Errorf("%d bodies", built)
	}
	if request := testSearchRequest(); request.Pad != nil {
		t.Errorf("the builder set its caller's pad")
	}
}

// Seeded random replies at each step count with 0 to 25 hits to give: each exactly its size, accepted by Z8 and
// walked as its one encoding, its hits a prefix of those given, at least one whenever there was one.
func TestSearchReplySizes(t *testing.T) {
	settings := DefaultSearchWireSettings()
	random := rand.New(rand.NewPCG(11, 2))
	heldBack := 0
	for steps := 1; steps <= settings.MaxStepCount; steps += 1 {
		for range 1500 {
			hits := []*protocol.SearchHit{}
			for i := range random.IntN(26) {
				hit := testSearchHit(i, random.IntN(settings.LocatorMaxByteCount+1), random.IntN(settings.SnippetMaxByteCount+1), random.IntN(settings.HitFieldMaxCount+1))
				if random.IntN(4) == 0 {
					hit.Correction = strings.Repeat("c", random.IntN(settings.CorrectionMaxByteCount+1))
				}
				hits = append(hits, hit)
			}
			head := testSearchHead(random.IntN(settings.CoverageMaxCount+1), hits, protocol.SearchStatus_SEARCH_OK)
			body, accounted := searchRemoteBuildReply(steps, hits, head, settings)
			if len(body) != steps*settings.StepByteCount {
				t.Fatalf("steps %d: %d B", steps, len(body))
			}
			reply, ok := searchRemoteAcceptReply(body, steps, settings)
			if !ok || !testSearchWalk(body, "SearchReply") {
				t.Fatalf("steps %d: refused its own body", steps)
			}
			if len(reply.Hits) != accounted || (0 < len(hits) && accounted == 0) {
				t.Fatalf("steps %d: %d hits for %d accounted of %d", steps, len(reply.Hits), accounted, len(hits))
			}
			for i, hit := range reply.Hits {
				if !proto.Equal(hit, hits[i]) {
					t.Fatalf("steps %d: hit %d is not the %dth given", steps, i, i)
				}
			}
			if accounted < min(len(hits), settings.HitMaxCount) {
				heldBack += 1
			}
		}
	}
	if heldBack == 0 {
		t.Errorf("no reply held a hit back for size")
	}
}

// Sets *rows, the head's coverage rows, and the locator of hits[count-1] so that head with the first count of hits
// encodes to exactly content B: a row moves it about 117 B and a locator of 128 to 512 B a byte at a time, so some
// row count reaches every content in range.
func testSearchTuneOnto(t *testing.T, rows *int, head func(int) *protocol.SearchReply, hits []*protocol.SearchHit, count int, content int) {
	t.Helper()
	sizeOf := func() int {
		reply := head(count)
		reply.Hits = hits[:count]
		return proto.Size(reply)
	}
	for *rows = 0; *rows <= DefaultSearchWireSettings().CoverageMaxCount; *rows += 1 {
		hits[count-1].Locator = strings.Repeat("l", 128)
		if delta := content - sizeOf(); 0 <= delta && delta <= DefaultSearchWireSettings().LocatorMaxByteCount-128 {
			hits[count-1].Locator = strings.Repeat("l", 128+delta)
			if sizeOf() == content {
				return
			}
		}
	}
	t.Fatalf("no tuning of %d hits reaches %d B", count, content)
}

// The replies that sit on the gap: 6 hits of 16,381 B at two steps, 11 of 32,765 B at three, 17 of 49,149 B at
// four. Each is built with one hit fewer, and with one more when one more is waiting and fits.
func TestSearchReplyOnTheGap(t *testing.T) {
	settings := DefaultSearchWireSettings()
	for _, c := range []struct {
		steps      int
		hitCount   int
		content    int
		fieldCount int
	}{
		{steps: 2, hitCount: 6, content: 16381, fieldCount: 7},
		{steps: 3, hitCount: 11, content: 32765, fieldCount: 8},
		{steps: 4, hitCount: 17, content: 49149, fieldCount: 8},
	} {
		hits := []*protocol.SearchHit{}
		for i := range c.hitCount + 1 {
			hits = append(hits, testSearchHit(i, 300, 200, c.fieldCount))
		}
		rows := 0
		head := func(hitCount int) *protocol.SearchReply {
			return testSearchHead(rows, hits, protocol.SearchStatus_SEARCH_OK)(hitCount)
		}
		testSearchTuneOnto(t, &rows, head, hits, c.hitCount, c.content)
		if c.steps*settings.StepByteCount-c.content != 16387 || searchRemoteAdmissible(c.steps*settings.StepByteCount, c.content, settings) {
			t.Fatalf("%d steps: %d B is not on the gap", c.steps, c.content)
		}
		body, accounted := searchRemoteBuildReply(c.steps, hits[:c.hitCount], head, settings)
		reply, ok := searchRemoteAcceptReply(body, c.steps, settings)
		if !ok || len(reply.Hits) != c.hitCount-1 || accounted != c.hitCount-1 {
			t.Errorf("%d steps, %d hits on the gap: %d returned", c.steps, c.hitCount, accounted)
		}
		body, accounted = searchRemoteBuildReply(c.steps, hits, head, settings)
		reply, ok = searchRemoteAcceptReply(body, c.steps, settings)
		if !ok || len(reply.Hits) != c.hitCount+1 || accounted != c.hitCount+1 {
			t.Errorf("%d steps, one more waiting: %d returned", c.steps, accounted)
		}
	}
}

// FS-83's size cases at this layer: replies of 0, 1 and 20 hits, TOO_BROAD, and the failures INVALID,
// CURSOR_EXPIRED and UNSUPPORTED_VERSION, each exactly steps × 16,384 B at every step count and each accepted.
func TestSearchRemoteRepliesKeepTheirSize(t *testing.T) {
	settings := DefaultSearchWireSettings()
	twenty := []*protocol.SearchHit{}
	for i := range settings.HitMaxCount {
		twenty = append(twenty, testSearchHit(i, 40, 60, 2))
	}
	request := testSearchRequest()
	for steps := 1; steps <= settings.MaxStepCount; steps += 1 {
		request.Steps = uint32(steps)
		bodies := map[string][]byte{}
		for _, hitCount := range []int{0, 1, 20} {
			body, accounted := searchRemoteBuildReply(steps, twenty[:hitCount], testSearchHead(2, twenty[:hitCount], protocol.SearchStatus_SEARCH_OK), settings)
			if accounted != hitCount {
				t.Errorf("%d steps: %d of %d hits", steps, accounted, hitCount)
			}
			bodies[fmt.Sprintf("%d hits", hitCount)] = body
		}
		tooBroad, _ := searchRemoteBuildReply(steps, twenty[:3], testSearchHead(2, twenty[:3], protocol.SearchStatus_SEARCH_TOO_BROAD), settings)
		bodies["too broad"] = tooBroad
		for _, status := range []protocol.SearchStatus{protocol.SearchStatus_SEARCH_INVALID, protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION} {
			body, err := searchRemoteFailureReply(status, request, settings)
			if err != nil {
				t.Fatal(err)
			}
			bodies[status.String()] = body
		}
		for name, body := range bodies {
			if len(body) != steps*settings.StepByteCount {
				t.Errorf("%d steps, %s: %d B", steps, name, len(body))
			}
			if _, ok := searchRemoteParseReply(body, steps, request.GetSearchId(), request.GetPage(), settings); !ok {
				t.Errorf("%d steps, %s: refused", steps, name)
			}
		}
	}
}

// Z7 at the request's steps where it parsed and asks 1 to 4, and at one step otherwise; the version fields, and
// the request's search_id and page where it parsed.
func TestSearchFailureReplyTakesTheRequestsSteps(t *testing.T) {
	settings := DefaultSearchWireSettings()
	for _, c := range []struct {
		request *protocol.SearchRequest
		steps   int
	}{
		{request: nil, steps: 1},
		{request: &protocol.SearchRequest{SearchId: 5, Page: 3, Steps: 0}, steps: 1},
		{request: &protocol.SearchRequest{SearchId: 5, Page: 3, Steps: 3}, steps: 3},
		{request: &protocol.SearchRequest{SearchId: 5, Page: 3, Steps: 4}, steps: 4},
		{request: &protocol.SearchRequest{SearchId: 5, Page: 3, Steps: 5}, steps: 1},
	} {
		body, err := searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, c.request, settings)
		if err != nil || len(body) != c.steps*settings.StepByteCount {
			t.Fatalf("%v: %d B, %v", c.request, len(body), err)
		}
		reply := &protocol.SearchReply{}
		if err := proto.Unmarshal(body, reply); err != nil {
			t.Fatal(err)
		}
		if reply.SearchVersion != 1 || reply.MinVersion != 1 || reply.MaxVersion != 1 || reply.Status != uint32(protocol.SearchStatus_SEARCH_INVALID) ||
			reply.SearchId != c.request.GetSearchId() || reply.Page != c.request.GetPage() || len(reply.Hits) != 0 || reply.Coverage != nil {
			t.Errorf("%v: %v", c.request, reply)
		}
		reply.Pad = nil
		if 90 < proto.Size(reply) {
			t.Errorf("a failure's content of %d B", proto.Size(reply))
		}
	}
}

// The caps on a request: a builder refuses each past them, and Z8 (f) answers each INVALID at its size; a later
// page carrying page 0's fields is not built.
func TestSearchRequestPastACap(t *testing.T) {
	settings := DefaultSearchWireSettings()
	pastCaps := []func(request *protocol.SearchRequest){
		func(request *protocol.SearchRequest) { request.Query = strings.Repeat("q", 513) },
		func(request *protocol.SearchRequest) {
			for len(request.Repos) <= 64 {
				request.Repos = append(request.Repos, &protocol.SearchRepo{RepoId: testSearchId(7)})
			}
		},
		func(request *protocol.SearchRequest) { request.Repos[0].RepoId = request.Repos[0].RepoId[:15] },
		func(request *protocol.SearchRequest) { request.Repos[1].RefId = append(request.Repos[1].RefId, 0) },
		func(request *protocol.SearchRequest) {
			request.Filters = &protocol.SearchFilters{PathPrefix: strings.Repeat("p", 766)}
		},
		func(request *protocol.SearchRequest) { request.Steps = 0 },
		func(request *protocol.SearchRequest) { request.Steps = 5 },
	}
	for i, pastCap := range pastCaps {
		request := testSearchRequest()
		pastCap(request)
		if _, err := searchRemoteBuildRequest(request, settings); err != errSearchRequestCaps {
			t.Errorf("cap %d: built, %v", i, err)
		}
		body := testSearchPadded(t, testSearchContent(t, request), settings.RequestByteCount)
		if _, status := searchRemoteParseRequest(body, settings); status != protocol.SearchStatus_SEARCH_INVALID {
			t.Errorf("cap %d: %v", i, status)
		}
	}
	laterPage := &protocol.SearchRequest{SearchVersion: 1, SearchId: 9, Page: 2, Steps: 1, Query: "a"}
	if _, err := searchRemoteBuildRequest(laterPage, settings); err != errSearchRequestPageFields {
		t.Errorf("a later page with a query: %v", err)
	}
	laterPage.Query = ""
	if _, err := searchRemoteBuildRequest(laterPage, settings); err != nil {
		t.Errorf("a later page alone: %v", err)
	}
}

// Z8 at an indexer judges the version before the encoding: a request of a later version carrying a field this
// build does not know is UNSUPPORTED_VERSION, and the same field at version 1 is INVALID; an unparsed body is
// INVALID with no request.
func TestSearchParseRequestJudgesTheVersionFirst(t *testing.T) {
	settings := DefaultSearchWireSettings()
	for _, c := range []struct {
		version uint32
		want    protocol.SearchStatus
	}{
		{version: 2, want: protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION},
		{version: 1, want: protocol.SearchStatus_SEARCH_INVALID},
	} {
		request := testSearchRequest()
		request.SearchVersion = c.version
		// field 13, which SearchRequest reserves for later requesters
		content := protowire.AppendVarint(protowire.AppendTag(testSearchContent(t, request), 13, protowire.VarintType), 1)
		parsed, status := searchRemoteParseRequest(testSearchPadded(t, content, settings.RequestByteCount), settings)
		if status != c.want || parsed == nil || parsed.GetSearchId() != request.GetSearchId() {
			t.Errorf("version %d: %v", c.version, status)
		}
	}
	unparsed := make([]byte, settings.RequestByteCount)
	unparsed[0] = 0xff
	if parsed, status := searchRemoteParseRequest(unparsed, settings); parsed != nil || status != protocol.SearchStatus_SEARCH_INVALID {
		t.Errorf("an unparsed body: %v %v", parsed, status)
	}
}

// Z8's refusals at an indexer and a requester, each body of the right size but the last: a non-zero pad, an
// unknown field before and after pad, pad twice, a varint one byte too long, a zero written out, two fields out
// of order, and a wrong size. The walker refuses each that is not its one encoding, as Z8 (d) does, and accepts
// the rest.
func TestSearchBodyIsItsOneEncoding(t *testing.T) {
	settings := DefaultSearchWireSettings()
	tag := func(b []byte, number protowire.Number, wireType protowire.Type) []byte {
		return protowire.AppendTag(b, number, wireType)
	}
	request := testSearchRequest()
	content := testSearchContent(t, request)
	// version, then search_id: the request's first two fields, 2 and 9 bytes
	version, searchId, rest := content[:2], content[2:11], content[11:]
	if !bytes.Equal(version, []byte{0x08, 0x01}) || searchId[0] != 0x11 {
		t.Fatalf("the request opens % x", content[:11])
	}
	join := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}
	canonical := testSearchPadded(t, content, settings.RequestByteCount)
	nonZeroPad := append([]byte{}, canonical...)
	nonZeroPad[len(nonZeroPad)-1] = 1
	padTwice := func() []byte {
		first := join(content, tag(nil, searchPadFieldNumber, protowire.BytesType), []byte{0x05}, make([]byte, 5))
		return testSearchPadded(t, first, settings.RequestByteCount)
	}()
	unknownAfterPad := func() []byte {
		unknown := protowire.AppendVarint(tag(nil, 16, protowire.VarintType), 1)
		body := testSearchPadded(t, content, settings.RequestByteCount-len(unknown))
		return append(body, unknown...)
	}()
	cases := []struct {
		name     string
		body     []byte
		status   protocol.SearchStatus
		oneOfZ9  bool
		sizeOnly bool
	}{
		{name: "canonical", body: canonical, status: protocol.SearchStatus_SEARCH_OK, oneOfZ9: true},
		{name: "a non-zero pad", body: nonZeroPad, status: protocol.SearchStatus_SEARCH_INVALID, oneOfZ9: true},
		{name: "an unknown field", body: testSearchPadded(t, join(content, protowire.AppendVarint(tag(nil, 13, protowire.VarintType), 1)), settings.RequestByteCount), status: protocol.SearchStatus_SEARCH_INVALID},
		{name: "an unknown field after pad", body: unknownAfterPad, status: protocol.SearchStatus_SEARCH_INVALID},
		{name: "pad twice", body: padTwice, status: protocol.SearchStatus_SEARCH_INVALID},
		{name: "a long varint", body: testSearchPadded(t, join([]byte{0x08, 0x81, 0x00}, searchId, rest), settings.RequestByteCount), status: protocol.SearchStatus_SEARCH_INVALID},
		{name: "a zero written out", body: testSearchPadded(t, join(version, searchId, []byte{0x18, 0x00}, rest), settings.RequestByteCount), status: protocol.SearchStatus_SEARCH_INVALID},
		{name: "fields out of order", body: testSearchPadded(t, join(searchId, version, rest), settings.RequestByteCount), status: protocol.SearchStatus_SEARCH_INVALID},
		{name: "a wrong size", body: testSearchPadded(t, content, settings.RequestByteCount+1), status: protocol.SearchStatus_SEARCH_INVALID, oneOfZ9: true, sizeOnly: true},
	}
	for _, c := range cases {
		if !c.sizeOnly && len(c.body) != settings.RequestByteCount {
			t.Fatalf("%s: %d B", c.name, len(c.body))
		}
		parsed, status := searchRemoteParseRequest(c.body, settings)
		if status != c.status || parsed == nil {
			t.Errorf("%s: %v", c.name, status)
		}
		if testSearchWalk(c.body, "SearchRequest") != c.oneOfZ9 {
			t.Errorf("%s: the walker reads it otherwise", c.name)
		}
	}

	// the same refusals of a reply, which a requester reads as no reply
	hits := []*protocol.SearchHit{testSearchHit(1, 30, 40, 1)}
	replyBody, _ := searchRemoteBuildReply(1, hits, testSearchHead(1, hits, protocol.SearchStatus_SEARCH_OK), settings)
	reply, ok := searchRemoteAcceptReply(replyBody, 1, settings)
	if !ok || !testSearchWalk(replyBody, "SearchReply") {
		t.Fatalf("a built reply refused")
	}
	reply.Pad = nil
	replyContent := testSearchContent(t, reply)
	replyVersion, replyRest := replyContent[:2], replyContent[2:]
	replyNonZeroPad := append([]byte{}, replyBody...)
	replyNonZeroPad[len(replyNonZeroPad)-2] = 7
	for _, c := range []struct {
		name    string
		body    []byte
		oneOfZ9 bool
	}{
		{name: "a non-zero pad", body: replyNonZeroPad, oneOfZ9: true},
		{name: "an unknown field", body: testSearchPadded(t, join(replyContent, protowire.AppendVarint(tag(nil, 13, protowire.VarintType), 1)), settings.StepByteCount)},
		{name: "a long varint", body: testSearchPadded(t, join([]byte{0x08, 0x81, 0x00}, replyRest), settings.StepByteCount)},
		{name: "fields out of order", body: testSearchPadded(t, join(replyRest[:4], replyVersion, replyRest[4:]), settings.StepByteCount)},
		{name: "a wrong size", body: replyBody[:len(replyBody)-1], oneOfZ9: false},
	} {
		if _, ok := searchRemoteAcceptReply(c.body, 1, settings); ok {
			t.Errorf("reply, %s: accepted", c.name)
		}
		if c.name != "a wrong size" && testSearchWalk(c.body, "SearchReply") != c.oneOfZ9 {
			t.Errorf("reply, %s: the walker reads it otherwise", c.name)
		}
	}
}

// A requester's reading of a reply: one that names another search or page is no reply; (f) drops what is past a
// cap and keeps the rest; a status or served code this build does not know, or a status other than
// UNSUPPORTED_VERSION at a version it does not speak, reads as unspecified.
func TestSearchParseReplyKeepsWithinTheCaps(t *testing.T) {
	settings := DefaultSearchWireSettings()
	coverage := []*protocol.SearchCoverage{}
	for i := range 66 {
		coverage = append(coverage, &protocol.SearchCoverage{RepoId: testSearchId(byte(i)), RefId: testSearchId(byte(i)), Served: 1})
	}
	coverage[0].RepoId = coverage[0].RepoId[:15]
	coverage[1].Chain = make([]byte, 33)
	coverage[2].Served = 12
	hits := []*protocol.SearchHit{}
	for i := range 23 {
		hits = append(hits, testSearchHit(i, 10, 10, 1))
	}
	hits[0].Signer = nil
	hits[1].Locator = strings.Repeat("l", 513)
	hits[2].Fields = append(hits[2].Fields, &protocol.SearchField{Field: 2, Text: strings.Repeat("t", 257)})
	for len(hits[3].Fields) < 10 {
		hits[3].Fields = append(hits[3].Fields, &protocol.SearchField{Field: 3, Text: "x"})
	}
	hits[4].Snippet = strings.Repeat("s", 201)
	hits[5].Correction = strings.Repeat("c", 257)
	raw := &protocol.SearchReply{SearchVersion: 1, SearchId: 44, Page: 1, Status: 1, Coverage: coverage, Hits: hits}
	body := testSearchPadded(t, testSearchContent(t, raw), 4*settings.StepByteCount)
	if _, ok := searchRemoteParseReply(body, 4, 45, 1, settings); ok {
		t.Errorf("another search_id read as a reply")
	}
	if _, ok := searchRemoteParseReply(body, 4, 44, 2, settings); ok {
		t.Errorf("another page read as a reply")
	}
	reply, ok := searchRemoteParseReply(body, 4, 44, 1, settings)
	if !ok {
		t.Fatalf("refused")
	}
	if len(reply.Coverage) != 64 || bytes.Equal(reply.Coverage[0].RepoId, coverage[0].RepoId) || reply.Coverage[0].RepoId[0] != 2 ||
		reply.Coverage[0].Served != uint32(protocol.SearchServed_SEARCH_SERVED_UNSPECIFIED) {
		t.Errorf("coverage: %d rows, first %v", len(reply.Coverage), reply.Coverage[0])
	}
	if len(reply.Hits) != 20 || !bytes.Equal(reply.Hits[0].DocKey, hits[2].DocKey) {
		t.Fatalf("hits: %d", len(reply.Hits))
	}
	if len(reply.Hits[0].Fields) != 1 || len(reply.Hits[1].Fields) != 8 || reply.Hits[2].Snippet != "" || reply.Hits[3].Correction != "" {
		t.Errorf("hits not kept within their caps")
	}
	if kept, ok := searchRemoteKeepHit(hits[3], settings); !ok || len(kept.Fields) != 8 || len(hits[3].Fields) != 10 {
		t.Errorf("keeping a hit within its caps changed the caller's")
	}
	for _, c := range []struct {
		version uint32
		status  uint32
		want    protocol.SearchStatus
	}{
		{version: 1, status: 9, want: protocol.SearchStatus_SEARCH_STATUS_UNSPECIFIED},
		{version: 2, status: 1, want: protocol.SearchStatus_SEARCH_STATUS_UNSPECIFIED},
		{version: 2, status: 6, want: protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION},
		{version: 1, status: 2, want: protocol.SearchStatus_SEARCH_PARTIAL},
	} {
		raw := &protocol.SearchReply{SearchVersion: c.version, MinVersion: 2, MaxVersion: 3, SearchId: 44, Status: c.status}
		reply, ok := searchRemoteParseReply(testSearchPadded(t, testSearchContent(t, raw), settings.StepByteCount), 1, 44, 0, settings)
		if !ok || protocol.SearchStatus(reply.Status) != c.want {
			t.Errorf("version %d, status %d: read as %d", c.version, c.status, reply.GetStatus())
		}
	}
}

// sizes.json, row by row and body by body: Z3 and Z2 for each (size, content), and each whole body's content,
// pad and SHA-256, its head the one encoding of its fields, and each request within the caps built again to the
// same bytes.
func TestSearchSizeVectors(t *testing.T) {
	settings := DefaultSearchWireSettings()
	data, err := os.ReadFile(filepath.Join("testdata", "index", "conformance", "sizes.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := struct {
		Pads []struct {
			Size        int  `json:"size"`
			Content     int  `json:"content"`
			Sized       bool `json:"sized"`
			Pad         int  `json:"pad"`
			LengthBytes int  `json:"length_bytes"`
		} `json:"pads"`
		Bodies []struct {
			Name    string `json:"name"`
			Message string `json:"message"`
			Size    int    `json:"size"`
			Content int    `json:"content"`
			Pad     int    `json:"pad"`
			HeadHex string `json:"head_hex"`
			Sha256  string `json:"sha256"`
		} `json:"bodies"`
	}{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Pads) != 85 || len(vectors.Bodies) != 7 {
		t.Fatalf("%d pads, %d bodies", len(vectors.Pads), len(vectors.Bodies))
	}
	for _, row := range vectors.Pads {
		padByteCount, ok := searchRemotePadByteCount(row.Size, row.Content, settings)
		if searchRemoteAdmissible(row.Size, row.Content, settings) != row.Sized || ok != row.Sized {
			t.Errorf("(%d, %d): sized %v", row.Size, row.Content, ok)
			continue
		}
		if ok && (padByteCount != row.Pad || protowire.SizeVarint(uint64(padByteCount)) != row.LengthBytes) {
			t.Errorf("(%d, %d): pad %d", row.Size, row.Content, padByteCount)
		}
	}
	for _, vector := range vectors.Bodies {
		head, err := hex.DecodeString(vector.HeadHex)
		if err != nil || len(head) != vector.Content {
			t.Fatalf("%s: head of %d B, %v", vector.Name, len(head), err)
		}
		padByteCount, ok := searchRemotePadByteCount(vector.Size, vector.Content, settings)
		if !ok || padByteCount != vector.Pad {
			t.Errorf("%s: pad %d", vector.Name, padByteCount)
		}
		body := testSearchPadded(t, head, vector.Size)
		sum := sha256.Sum256(body)
		if len(body) != vector.Size || hex.EncodeToString(sum[:]) != vector.Sha256 {
			t.Errorf("%s: %d B, sha256 %x", vector.Name, len(body), sum)
		}
		var message proto.Message
		switch vector.Message {
		case "SearchRequest":
			message = &protocol.SearchRequest{}
		case "SearchReply":
			message = &protocol.SearchReply{}
		default:
			t.Fatalf("%s: a %s", vector.Name, vector.Message)
		}
		if err := proto.Unmarshal(body, message); err != nil || !searchRemoteOneEncoding(body, message) || !testSearchWalk(body, vector.Message) {
			t.Errorf("%s: not its one encoding (%v)", vector.Name, err)
		}
		if request, ok := message.(*protocol.SearchRequest); ok && searchRemoteRequestWithinCaps(request, settings) {
			built, err := searchRemoteBuildRequest(request, settings)
			if err != nil || !bytes.Equal(built, body) {
				t.Errorf("%s: built again otherwise (%v)", vector.Name, err)
			}
			if _, status := searchRemoteParseRequest(body, settings); status != protocol.SearchStatus_SEARCH_OK {
				t.Errorf("%s: %v", vector.Name, status)
			}
		}
		if reply, ok := message.(*protocol.SearchReply); ok {
			if _, ok := searchRemoteAcceptReply(body, vector.Size/settings.StepByteCount, settings); !ok {
				t.Errorf("%s: refused", vector.Name)
			}
			hits := reply.Hits
			head := func(hitCount int) *protocol.SearchReply {
				fields := proto.Clone(reply).(*protocol.SearchReply)
				fields.Hits = nil
				return fields
			}
			built, accounted := searchRemoteBuildReply(vector.Size/settings.StepByteCount, hits, head, settings)
			if !bytes.Equal(built, body) || accounted != len(hits) {
				t.Errorf("%s: built again otherwise", vector.Name)
			}
		}
	}
}
