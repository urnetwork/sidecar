//go:build !ios_extension

// The drop engine's lineages, lists and dry run (EVS2-M10-20; FS-89's and FS-93's lineage clauses as far as one path
// epoch goes): a path's every version listed by entry hash at a written boundary, a removed path's at a removed one;
// the reserved refs, the index's root and a directory refused by name with nothing sent; the dry run's map_parts
// copied, list_match false and linked false each stopping the command; a pending prefix rule set stopping it before
// the dry run; and Drops listing the table's drops.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The stand-in's drop routes: the dry run answered from what the test expects of each lineage, keyed by its newest
// token path, and the drop table's listing; every other route the push server's.
type evsTestDropServer struct {
	writer *evsTestWriter

	stateLock sync.Mutex
	// each lineage's resolved count and listed_sha256, by its newest token path's bytes
	expect map[string]*protocol.EvsDropPath
	// answered for every path in place of the comparison, when set
	listMatch *bool
	linked    *bool
	requests  []*protocol.EvsDropPreviewRequest
	drops     []*protocol.EvsDropStatus
}

func (self *evsTestDropServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	answer := func(status int, message proto.Message) {
		body, _ := proto.Marshal(message)
		writer.WriteHeader(status)
		writer.Write(body)
	}
	switch {
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/drops/preview"):
		body, _ := io.ReadAll(request.Body)
		preview := &protocol.EvsDropPreviewRequest{}
		if err := proto.Unmarshal(body, preview); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		self.stateLock.Lock()
		self.requests = append(self.requests, preview)
		self.stateLock.Unlock()
		answer(http.StatusAccepted, &protocol.EvsDropPreviewReply{PreviewId: evsTestBytes("preview", 16), State: protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED})
	case request.Method == http.MethodGet && strings.Contains(path, "/drops/preview/"):
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		last := self.requests[len(self.requests)-1]
		reply := &protocol.EvsDropPreviewReply{PreviewId: evsTestBytes("preview", 16), State: protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE, FreedBytes: 4096}
		for _, asked := range last.GetPaths() {
			key := string(bytes.Join(asked.GetLineage()[0].GetTokenPath(), nil))
			expected := self.expect[key]
			match := expected != nil && expected.GetCount() == asked.GetCount() && bytes.Equal(expected.GetListedSha256(), asked.GetListedSha256())
			if self.listMatch != nil {
				match = *self.listMatch
			}
			linked := true
			if self.linked != nil {
				linked = *self.linked
			}
			result := &protocol.EvsDropPreviewPath{ListMatch: match, Linked: linked, MapParts: make([]uint32, len(asked.GetLineage())-1)}
			if expected != nil {
				result.Count = expected.GetCount()
			}
			reply.Paths = append(reply.Paths, result)
		}
		answer(http.StatusOK, reply)
	case request.Method == http.MethodGet && strings.HasSuffix(path, "/drops"):
		self.stateLock.Lock()
		reply := &protocol.EvsDropsReply{Drops: self.drops}
		self.stateLock.Unlock()
		answer(http.StatusOK, reply)
	default:
		self.writer.server.ServeHTTP(writer, request)
	}
}

// A writer whose client reaches the drop routes too.
func newEvsTestDropWriter(t *testing.T) (*evsTestWriter, *evsTestDropServer) {
	writer := newEvsTestWriter(t)
	server := &evsTestDropServer{writer: writer, expect: map[string]*protocol.EvsDropPath{}}
	writer.test.client.args.Transport = &evsTestTransport{handler: server}
	writer.test.client.http.transport = wrapSidecarApiTransport(writer.test.client.args.Transport)
	return writer, server
}

// What the world's history makes of path's drop: its versions with entries below through, hashed.
func (self *evsTestDropServer) expectPath(t *testing.T, path string) [][]byte {
	t.Helper()
	world := self.writer.world
	world.stateLock.Lock()
	state := world.paths[path]
	listed := [][]byte{}
	for _, version := range state.versions {
		if version.entryBytes != nil {
			sum := sha256.Sum256(version.entryBytes)
			listed = append(listed, sum[:])
		}
	}
	world.stateLock.Unlock()
	dropPath := &protocol.EvsDropPath{}
	if _, err := EvsBuildDropLists([]*protocol.EvsDropPath{dropPath}, [][][]byte{listed}); err != nil {
		t.Fatal(err)
	}
	self.stateLock.Lock()
	self.expect[string(world.tokens(path).Bytes())] = dropPath
	self.stateLock.Unlock()
	slices.SortFunc(listed, bytes.Compare)
	return listed
}

// A path written five times lists its five versions at a written boundary, and its dry run copies map_parts.
func TestEvsDropLineageListsEveryVersion(t *testing.T) {
	writer, server := newEvsTestDropWriter(t)
	for i := 0; i < 5; i += 1 {
		if _, err := writer.write(t, "notes/plan.md", evsTestEdited("plan", 3000, i)); err != nil {
			t.Fatal(err)
		}
	}
	want := server.expectPath(t, "notes/plan.md")
	lineage, err := writer.repo.DropLineage(context.Background(), nil, "notes/plan.md")
	if err != nil {
		t.Fatal(err)
	}
	if lineage.DropPath.GetBoundary() != EvsDropBoundaryWritten || lineage.DropPath.GetThroughVersion() != 6 || lineage.DropPath.GetCount() != 5 {
		t.Fatalf("the lineage %v", lineage.DropPath)
	}
	if len(lineage.DropPath.GetLineage()) != 1 || !bytes.Equal(bytes.Join(lineage.DropPath.GetLineage()[0].GetTokenPath(), nil), writer.world.tokens("notes/plan.md").Bytes()) {
		t.Fatalf("the lineage's entries %v", lineage.DropPath.GetLineage())
	}
	if len(lineage.Listed) != len(want) {
		t.Fatalf("listed %d, want %d", len(lineage.Listed), len(want))
	}
	for i := range want {
		if !bytes.Equal(lineage.Listed[i], want[i]) {
			t.Fatalf("listed value %d differs", i)
		}
	}
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"notes/plan.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Lineages) != 1 || preview.VersionCount != 5 || preview.FreedBytes != 4096 || len(preview.PreviewId) != 16 {
		t.Fatalf("the preview %+v", preview)
	}
}

// A removed path lists the versions of its removed life at a removed boundary, through_version its removal.
func TestEvsDropLineageRemovedPath(t *testing.T) {
	writer, server := newEvsTestDropWriter(t)
	for i := 0; i < 3; i += 1 {
		if _, err := writer.write(t, "old.txt", evsTestEdited("old", 2000, i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.write(t, "old.txt", nil); err != nil {
		t.Fatal(err)
	}
	server.expectPath(t, "old.txt")
	lineage, err := writer.repo.DropLineage(context.Background(), nil, "old.txt")
	if err != nil {
		t.Fatal(err)
	}
	if lineage.DropPath.GetBoundary() != EvsDropBoundaryRemoved || lineage.DropPath.GetThroughVersion() != 4 || lineage.DropPath.GetCount() != 3 {
		t.Fatalf("the removed path's lineage %v", lineage.DropPath)
	}
}

// The reserved refs, the index's root and a directory are refused by name, and nothing reaches evs's drop routes.
func TestEvsDropLineageRefusesReservedPaths(t *testing.T) {
	writer, server := newEvsTestDropWriter(t)
	if _, err := writer.write(t, "docs/a.md", []byte("a")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		refName []byte
		path    string
	}{
		{refName: EvsIndexRefName, path: "x"},
		{refName: EvsLfsRefName, path: "ab/cd/x"},
		{refName: nil, path: ".ur-index/settings"},
		{refName: nil, path: "docs"},
	}
	for _, c := range cases {
		if _, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{RefName: c.refName, Paths: []string{c.path}}); !errors.Is(err, ErrEvsDropPath) {
			t.Errorf("%s on %s: %v", c.path, c.refName, err)
		}
	}
	if _, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"docs/a.md"}, Follow: true}); !errors.Is(err, ErrEvsDropPath) {
		t.Errorf("--follow: %v", err)
	}
	if len(server.requests) != 0 {
		t.Fatal("a refused drop reached evs")
	}
}

// A dry run whose list does not match, or whose lineage evs cannot follow, stops the command.
func TestEvsDropPreviewStopsOnMismatchOrUnlinked(t *testing.T) {
	writer, server := newEvsTestDropWriter(t)
	for i := 0; i < 2; i += 1 {
		if _, err := writer.write(t, "a.txt", evsTestEdited("a", 1000, i)); err != nil {
			t.Fatal(err)
		}
	}
	server.expectPath(t, "a.txt")
	no := false
	server.listMatch = &no
	if _, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}}); !errors.Is(err, ErrEvsDropListMismatch) {
		t.Fatalf("list_match false: %v", err)
	}
	server.listMatch = nil
	server.linked = &no
	if _, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}}); !errors.Is(err, ErrEvsDropUnlinked) {
		t.Fatalf("linked false: %v", err)
	}
}

// In a repo whose rows hold a prefix rule set this client cannot judge, the command stops with EVS_PREFIX_RULE
// pending before the dry run.
func TestEvsDropPreviewPendingPrefixSetStops(t *testing.T) {
	writer, server := newEvsTestDropWriter(t)
	if _, err := writer.write(t, "a.txt", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write(t, "a.txt", []byte("two")); err != nil {
		t.Fatal(err)
	}
	writer.world.config.stateLock.Lock()
	repo := proto.Clone(writer.world.config.repo).(*protocol.AclRepo)
	repo.PrefixRules = []*protocol.AclRepoPrefixRulesRow{{}}
	writer.world.config.repo = repo
	writer.world.config.stateLock.Unlock()
	var ruleErr *EvsPrefixRuleError
	if _, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}}); !errors.As(err, &ruleErr) || ruleErr.Detail != EvsPrefixDetailPending {
		t.Fatalf("a pending set: %v", err)
	}
	if len(server.requests) != 0 {
		t.Fatal("the dry run was sent")
	}
}

// Drops lists the table's drops; a drop whose body this device cannot read names no path.
func TestEvsDropsListsTheTable(t *testing.T) {
	writer, server := newEvsTestDropWriter(t)
	server.drops = []*protocol.EvsDropStatus{{DropId: evsTestBytes("drop", 16), RefId: writer.world.refId.Bytes(), Version: 7, State: protocol.EvsDropState_EVS_DROP_PENDING}}
	drops, err := writer.repo.Drops(context.Background(), &EvsDropsArgs{KnownPaths: []string{"a.txt"}})
	if err != nil || len(drops) != 1 || drops[0].Status.GetVersion() != 7 || len(drops[0].Paths) != 0 {
		t.Fatalf("drops %+v %v", drops, err)
	}
}
