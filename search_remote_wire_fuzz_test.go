//go:build !sidecar_http && !ios_extension

// §22.6's `SearchRequest` and `SearchReply` target (DESIGN-DETAILS 11.6): parsing any bytes is total, and a body
// is accepted only when Z8 holds, which testSearchWalk, Z9's rule of bytes read without the marshaler, and the
// checks below restate; an accepted body marshals back to itself. Seeds: every body the builders make for the
// shapes the unit tests use, and their sizes' neighbours.

package sidecar

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Bodies the builders make: requests on page 0 and later, and replies of 0 to 20 hits at each step count, and
// failures.
func testSearchWireSeeds(t testing.TB) [][]byte {
	settings := DefaultSearchWireSettings()
	seeds := [][]byte{}
	request := testSearchRequest()
	if body, err := searchRemoteBuildRequest(request, settings); err == nil {
		seeds = append(seeds, body)
	}
	laterPage := &protocol.SearchRequest{SearchVersion: 1, SearchId: 3, Page: 4, Steps: 2}
	if body, err := searchRemoteBuildRequest(laterPage, settings); err == nil {
		seeds = append(seeds, body)
	}
	hits := []*protocol.SearchHit{}
	for i := range settings.HitMaxCount {
		hits = append(hits, testSearchHit(i, 20+i, 30+i, i%3))
	}
	for steps := 1; steps <= settings.MaxStepCount; steps += 1 {
		for _, hitCount := range []int{0, 1, 7, 20} {
			body, _ := searchRemoteBuildReply(steps, hits[:hitCount], testSearchHead(steps, hits[:hitCount], protocol.SearchStatus_SEARCH_OK), settings)
			seeds = append(seeds, body)
		}
		request.Steps = uint32(steps)
		if body, err := searchRemoteFailureReply(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, request, settings); err == nil {
			seeds = append(seeds, body)
		}
	}
	return seeds
}

// Z8 at an indexer on any bytes: total; a body answered OK is RequestByteCount, its one encoding by the walker,
// pad all zeros, within the caps and its marshal is the body; one parsed is answered a failure reply of its size.
func FuzzSearchRequestBody(f *testing.F) {
	for _, seed := range testSearchWireSeeds(f) {
		if len(seed) == DefaultSearchWireSettings().RequestByteCount {
			f.Add(seed)
			f.Add(seed[:len(seed)-1])
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		settings := DefaultSearchWireSettings()
		request, status := searchRemoteParseRequest(body, settings)
		if status != protocol.SearchStatus_SEARCH_OK {
			if status != protocol.SearchStatus_SEARCH_INVALID && status != protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION {
				t.Fatalf("answered %v", status)
			}
			reply, err := searchRemoteFailureReply(status, request, settings)
			if err != nil || len(reply) != searchRemoteFailureSteps(request, settings)*settings.StepByteCount {
				t.Fatalf("a failure's reply of %d B: %v", len(reply), err)
			}
			return
		}
		if len(body) != settings.RequestByteCount || !testSearchWalk(body, "SearchRequest") || !searchRemotePadZeros(request.GetPad()) ||
			!searchRemoteRequestWithinCaps(request, settings) || request.GetSearchVersion() != searchVersion {
			t.Fatalf("accepted a body Z8 refuses")
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
		if err != nil || !bytes.Equal(encoded, body) {
			t.Fatalf("an accepted body does not marshal back to itself")
		}
	})
}

// Z8 at a requester on any bytes, at each step count its length allows: total; a body accepted is that size, its
// one encoding by the walker, pad all zeros, and its marshal is the body; its reading keeps every hit, row and
// field within the caps.
func FuzzSearchReplyBody(f *testing.F) {
	for _, seed := range testSearchWireSeeds(f) {
		if len(seed) != DefaultSearchWireSettings().RequestByteCount {
			f.Add(seed)
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		settings := DefaultSearchWireSettings()
		for steps := 0; steps <= settings.MaxStepCount+1; steps += 1 {
			reply, ok := searchRemoteAcceptReply(body, steps, settings)
			if !ok {
				continue
			}
			if len(body) != steps*settings.StepByteCount || !testSearchWalk(body, "SearchReply") || !searchRemotePadZeros(reply.GetPad()) {
				t.Fatalf("accepted a body Z8 refuses")
			}
			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(reply)
			if err != nil || !bytes.Equal(encoded, body) {
				t.Fatalf("an accepted body does not marshal back to itself")
			}
			read, ok := searchRemoteParseReply(body, steps, reply.GetSearchId(), reply.GetPage(), settings)
			if !ok || settings.CoverageMaxCount < len(read.GetCoverage()) || settings.HitMaxCount < len(read.GetHits()) {
				t.Fatalf("a reading past the caps")
			}
			for _, hit := range read.GetHits() {
				if _, ok := searchRemoteKeepHit(hit, settings); !ok || settings.HitFieldMaxCount < len(hit.GetFields()) ||
					settings.SnippetMaxByteCount < len(hit.GetSnippet()) || settings.CorrectionMaxByteCount < len(hit.GetCorrection()) {
					t.Fatalf("a hit past its caps")
				}
			}
		}
	})
}
