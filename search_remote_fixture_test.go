//go:build !sidecar_http && !ios_extension

package sidecar

// Remote search's test fixtures (SEARCH-M10-32 to 34): a fake corpus an indexer serves from, requests and replies built
// and parsed by the wire's own functions, and servers over TEAM-M10-02's test Team, whose config is real.

import (
	"cmp"
	"context"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A doc_key from a label.
func testSearchRemoteKey(label string) [16]byte {
	sum := sha256.Sum256([]byte("remote search test doc " + label))
	return [16]byte(sum[:16])
}

// One document of the fake corpus.
type testSearchRemoteDoc struct {
	label   string
	timeMs  int64
	version uint64
	// it holds the query: verified where the text is held, else a phone's judgment, possible
	matches  bool
	textHeld bool
	// its display fields confirm the query (what a too-broad page gives)
	headerConfirmed bool
	// in the all partition, else a bucket
	all bool
	// a large hit: every display field at its cap, so few fit a step
	large bool
}

// One ref of the fake corpus: its row 4 to 8, its documents, and a too-broad verdict.
type testSearchRemoteRef struct {
	row      searchRemoteRefRow
	docs     []*testSearchRemoteDoc
	tail     []*protocol.SearchHit
	tooBroad bool
}

// A corpus serving what refs holds, by repo. It counts its opens, passes and the all shards its passes read.
type testSearchRemoteCorpus struct {
	refs      map[Id]*testSearchRemoteRef
	opens     int
	passes    int
	allReads  int
	openViews int
}

func newTestSearchRemoteCorpus() *testSearchRemoteCorpus {
	return &testSearchRemoteCorpus{refs: map[Id]*testSearchRemoteRef{}}
}

// A text-served ref of repoId holding docs.
func (self *testSearchRemoteCorpus) serveText(repoId Id, version uint64, docs ...*testSearchRemoteDoc) *testSearchRemoteRef {
	ref := &testSearchRemoteRef{row: searchRemoteRefRow{
		served: protocol.SearchServed_SERVED_TEXT, refId: repoId, refVersion: version, chain: make([]byte, 32), refTimeMs: 1_000_000,
	}, docs: docs}
	self.refs[repoId] = ref
	return ref
}

func (self *testSearchRemoteCorpus) Open(ctx context.Context, query *searchRemoteQuery, asks []searchRemoteRefAsk) (searchRemoteView, []searchRemoteRefRow, error) {
	self.opens += 1
	view := &testSearchRemoteView{corpus: self, query: query}
	rows := []searchRemoteRefRow{}
	for _, ask := range asks {
		ref := self.refs[ask.repoId]
		if ref == nil {
			rows = append(rows, searchRemoteRefRow{served: protocol.SearchServed_REFUSED_ALL_ABSENT})
			continue
		}
		rows = append(rows, ref.row)
		view.refs = append(view.refs, testSearchRemoteViewRef{repoId: ask.repoId, place: ask.place, ref: ref})
	}
	self.openViews += 1
	return view, rows, nil
}

type testSearchRemoteViewRef struct {
	repoId Id
	place  uint16
	ref    *testSearchRemoteRef
}

type testSearchRemoteView struct {
	corpus    *testSearchRemoteCorpus
	query     *searchRemoteQuery
	refs      []testSearchRemoteViewRef
	ended     bool
	closed    bool
	tailTaken int
	firstPass bool
}

// One candidate's handle.
type testSearchRemoteHandle struct {
	repoId Id
	doc    *testSearchRemoteDoc
}

func (self *testSearchRemoteView) candidates(all bool) []*searchRemoteCandidate {
	candidates := []*searchRemoteCandidate{}
	for _, viewRef := range self.refs {
		if viewRef.ref.row.served != protocol.SearchServed_SERVED_TEXT {
			continue
		}
		for _, doc := range viewRef.ref.docs {
			if doc.all != all {
				continue
			}
			if self.query.sinceMs != 0 && doc.timeMs < self.query.sinceMs || self.query.untilMs != 0 && self.query.untilMs < doc.timeMs {
				continue
			}
			candidate := &searchRemoteCandidate{
				place:  searchWatermark{timeMs: doc.timeMs, repoIndex: viewRef.place, docKey: testSearchRemoteKey(doc.label)},
				handle: &testSearchRemoteHandle{repoId: viewRef.repoId, doc: doc},
			}
			if doc.headerConfirmed {
				candidate.header = testSearchRemoteHitOf(viewRef.repoId, doc, SearchConfirmed)
				candidate.headerConfirmed = true
			}
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

// The order's first k after watermark and the one after, reading the all partition only once the buckets leave room, as
// the engine's corpus reads its shards by their times.
func (self *testSearchRemoteView) CandidatesAfter(ctx context.Context, watermark searchWatermark, k int) ([]*searchRemoteCandidate, *searchRemoteCandidate, bool, error) {
	self.corpus.passes += 1
	first := !self.firstPass
	self.firstPass = true
	for _, viewRef := range self.refs {
		if viewRef.ref.tooBroad && first {
			candidates := self.candidates(false)
			slices.SortFunc(candidates, testSearchRemoteOrder)
			return candidates, nil, true, nil
		}
	}
	after := func(candidates []*searchRemoteCandidate) []*searchRemoteCandidate {
		kept := []*searchRemoteCandidate{}
		for _, candidate := range candidates {
			if searchWatermarkBefore(watermark, candidate.place) {
				kept = append(kept, candidate)
			}
		}
		slices.SortFunc(kept, testSearchRemoteOrder)
		return kept
	}
	ordered := after(self.candidates(false))
	allCandidates := after(self.candidates(true))
	allNewest := int64(0)
	for _, candidate := range allCandidates {
		allNewest = max(allNewest, candidate.place.timeMs)
	}
	if 0 < len(allCandidates) && (len(ordered) <= k || allNewest >= ordered[k].place.timeMs) {
		self.corpus.allReads += 1
		ordered = append(ordered, allCandidates...)
		slices.SortFunc(ordered, testSearchRemoteOrder)
	}
	if k < len(ordered) {
		return ordered[:k], ordered[k], false, nil
	}
	return ordered, nil, false, nil
}

// 7.2.5's order as a comparison.
func testSearchRemoteOrder(a *searchRemoteCandidate, b *searchRemoteCandidate) int {
	switch {
	case searchWatermarkBefore(a.place, b.place):
		return -1
	case searchWatermarkBefore(b.place, a.place):
		return 1
	}
	return 0
}

// A document's hit in state.
func testSearchRemoteHitOf(repoId Id, doc *testSearchRemoteDoc, state SearchHitState) *protocol.SearchHit {
	key := testSearchRemoteKey(doc.label)
	hit := &protocol.SearchHit{
		RepoId: repoId.Bytes(), RefId: repoId.Bytes(), DocKey: key[:], Version: doc.version, TimeMs: doc.timeMs, DocKind: 1,
		Locator: "notes/" + doc.label + ".md", State: uint32(state), Partition: 1, Signer: make([]byte, 16),
		Fields: []*protocol.SearchField{{Field: 4, Text: doc.label}},
	}
	if doc.all {
		hit.Partition = 4
	}
	if doc.large {
		hit.Fields = nil
		for field := uint32(1); field <= 8; field += 1 {
			text := make([]byte, 256)
			for i := range text {
				text[i] = 'a' + byte(field)
			}
			hit.Fields = append(hit.Fields, &protocol.SearchField{Field: field, Text: string(text)})
		}
		locator := make([]byte, 512)
		for i := range locator {
			locator[i] = 'l'
		}
		hit.Locator = string(locator)
	}
	return hit
}

func (self *testSearchRemoteView) Verify(ctx context.Context, candidate *searchRemoteCandidate) (*protocol.SearchHit, bool, error) {
	handle := candidate.handle.(*testSearchRemoteHandle)
	doc := handle.doc
	switch {
	case !doc.textHeld:
		return testSearchRemoteHitOf(handle.repoId, doc, SearchPossible), true, nil
	case doc.matches:
		hit := testSearchRemoteHitOf(handle.repoId, doc, SearchVerified)
		hit.Snippet = "around the match"
		return hit, true, nil
	}
	return nil, false, nil
}

func (self *testSearchRemoteView) Tail(ctx context.Context, k int) ([]*protocol.SearchHit, bool, error) {
	tail := []*protocol.SearchHit{}
	for _, viewRef := range self.refs {
		if viewRef.ref.row.served == protocol.SearchServed_SERVED_INDEX {
			tail = append(tail, viewRef.ref.tail...)
		}
	}
	taken := tail[min(self.tailTaken, len(tail)):]
	taken = taken[:min(k, len(taken))]
	self.tailTaken += len(taken)
	return taken, len(tail) <= self.tailTaken, nil
}

func (self *testSearchRemoteView) AllNewestMs() int64 {
	newest := int64(0)
	for _, viewRef := range self.refs {
		for _, doc := range viewRef.ref.docs {
			if doc.all {
				newest = max(newest, doc.timeMs)
			}
		}
	}
	return newest
}

func (self *testSearchRemoteView) Ended() bool {
	return self.ended
}

func (self *testSearchRemoteView) Close() {
	if !self.closed {
		self.closed = true
		self.corpus.openViews -= 1
	}
}

// A server on the Team's network as indexer self, its corpus fake, on a clock the test moves.
type testSearchRemoteServer struct {
	team     *testConfigSearchTeam
	settings *SidecarSearchSettings
	wire     *SearchWireSettings
	clock    *searchTestClock
	corpus   *testSearchRemoteCorpus
	budget   *SidecarRemoteBudget
	server   *SearchRemoteServer
	self     testConfigDevice
	state    *SidecarSearchState
	world    *searchStateTestWorld
}

func newTestSearchRemoteServer(t *testing.T, team *testConfigSearchTeam, self testConfigDevice) *testSearchRemoteServer {
	t.Helper()
	world := newSearchStateTestWorld(t)
	fixture := &testSearchRemoteServer{
		team: team, settings: world.settings, wire: DefaultSearchWireSettings(), clock: world.clock, corpus: newTestSearchRemoteCorpus(),
		self: self, state: world.state, world: world,
	}
	budget, err := NewSidecarRemoteBudget(fixture.settings, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	fixture.budget = budget
	server, err := newSearchRemoteServer(&SearchRemoteServerArgs{
		Settings: fixture.settings,
		Wire:     fixture.wire,
		Config:   func() (*ConfigState, error) { return team.net.log.State(), nil },
		Services: testConfigSearchServices,
		SelfId:   func() (Id, bool) { return self.sidecarId, true },
		Budget:   budget,
		State:    world.state,
		Clock:    fixture.clock,
	}, fixture.corpus)
	if err != nil {
		t.Fatal(err)
	}
	fixture.server = server
	t.Cleanup(server.Close)
	return fixture
}

// A page 0 request of requester's search over repos, as the wire builds it.
func testSearchRemoteRequest(t *testing.T, wire *SearchWireSettings, searchId uint64, page uint32, query string, repoIds ...Id) []byte {
	t.Helper()
	request := &protocol.SearchRequest{SearchVersion: searchVersion, SearchId: searchId, Page: page, Steps: 1}
	if page == 0 {
		request.Scope = 2
		request.Query = query
		for _, repoId := range repoIds {
			request.Repos = append(request.Repos, &protocol.SearchRepo{RepoId: repoId.Bytes()})
		}
	}
	body, err := searchRemoteBuildRequest(request, wire)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// What the server answers requester's body.
func (self *testSearchRemoteServer) ask(t *testing.T, requester testConfigDevice, body []byte) ([]byte, error) {
	t.Helper()
	return self.server.Handle(t.Context(), &SubprotocolRequest{
		SourceId: NewId(), Peer: &SubprotocolPeerIdentity{SidecarId: requester.sidecarId}, MessageType: protocol.MessageType_SEARCH, Body: body,
	})
}

// The reply to requester's page of searchId, parsed as the requester parses it; fails on an Error.
func (self *testSearchRemoteServer) page(t *testing.T, requester testConfigDevice, body []byte, searchId uint64, page uint32) *protocol.SearchReply {
	t.Helper()
	answer, err := self.ask(t, requester, body)
	if err != nil {
		t.Fatalf("page %d: %v", page, err)
	}
	reply, ok := searchRemoteParseReply(answer, 1, searchId, page, self.wire)
	if !ok {
		t.Fatalf("page %d: no reply", page)
	}
	return reply
}

// The hits' labels, by their doc keys among docs.
func testSearchRemoteLabels(hits []*protocol.SearchHit, docs ...*testSearchRemoteDoc) []string {
	labels := []string{}
	for _, hit := range hits {
		for _, doc := range docs {
			key := testSearchRemoteKey(doc.label)
			if string(hit.GetDocKey()) == string(key[:]) {
				labels = append(labels, doc.label)
			}
		}
	}
	return labels
}

// Docs at the given times, each matching.
func testSearchRemoteDocs(prefix string, times ...int64) []*testSearchRemoteDoc {
	docs := []*testSearchRemoteDoc{}
	for i, timeMs := range times {
		docs = append(docs, &testSearchRemoteDoc{label: prefix + string(rune('a'+i)), timeMs: timeMs, version: 1, matches: true, textHeld: true})
	}
	slices.SortFunc(docs, func(a *testSearchRemoteDoc, b *testSearchRemoteDoc) int { return cmp.Compare(a.label, b.label) })
	return docs
}
