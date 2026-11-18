//go:build !ios_extension && !sidecar_http

// The directory client's index surface over its own copy (directory_index.go, directory_admin.go; RECORD-M10-04): the
// cards source giving the announcements a synced copy holds, a renewal changing no version; the content the copy
// accepted at a version, for the in-ref writer; the folded view reading a hit at its item's renewed expiry; and
// ur admin directory --window's refusals, each with nothing signed, and its write from format 2.

package sidecar_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A cards binding that also writes index settings, recording what it was asked.
type testIndexWindowCards struct {
	sidecar.DirectoryCards
	repoIds    []sidecar.Id
	windowDays []uint32
	err        error
}

func (self *testIndexWindowCards) SetIndexWindow(ctx context.Context, repoId sidecar.Id, windowDays uint32) (*sidecar.EvsIndexSettingsResult, error) {
	self.repoIds = append(self.repoIds, repoId)
	self.windowDays = append(self.windowDays, windowDays)
	return &sidecar.EvsIndexSettingsResult{Roots: []*sidecar.EvsIndexRootSettings{{}}}, self.err
}

// Every document a source gives at refVersion, by name.
func testDirectoryIndexDocuments(t *testing.T, source sidecar.IndexDocumentSource, refVersion uint64) map[string]*sidecar.IndexDocument {
	t.Helper()
	documents := map[string]*sidecar.IndexDocument{}
	if err := source.IndexDocuments(t.Context(), refVersion, func(document *sidecar.IndexDocument) error {
		documents[string(document.Name)] = document
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return documents
}

// A synced copy's cards source gives its writer's announcement at the Announcement's version, a renewal moving its
// expiry and no version; the copy gives the content it accepted at a card's version and at no other; and the fold
// behind search_agents reads a hit at the item's renewed expiry, a copy that finished no sync folding nothing.
func TestDirectoryClientIndexOverItsCopy(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	announcementId := sidecar.NewId()
	run := testRunItem(writer.sidecarId, &memberId, announcementId, 1, now)
	device.writeCard(t, run)
	path := sidecar.DirectoryCardPath(writer.sidecarId)
	name := "a/" + hex.EncodeToString(writer.sidecarId.Bytes()) + hex.EncodeToString(announcementId.Bytes())

	reader := world.reader(nil)
	reader.mustSync(t)
	source, err := reader.client.IndexCardsSource()
	if err != nil {
		t.Fatal(err)
	}
	documents := testDirectoryIndexDocuments(t, source, reader.client.RefVersions().CardsVersion)
	document := documents[name]
	if len(documents) != 1 || document == nil || document.Kind != sidecar.IndexDocDerived || document.Version != 1 ||
		document.ExpiresSeconds != uint64(run.GetExpiresMillis()/1000) {
		t.Fatalf("the copy's documents: %+v", documents)
	}
	// the content the copy accepted at the card's version, and none at another
	fileVersion := world.cardFileVersion(path)
	if content, ok := reader.client.IndexReplaced(world.directoryId, path, fileVersion); !ok || len(content) == 0 {
		t.Fatal("the copy does not give the card version it accepted")
	}
	if _, ok := reader.client.IndexReplaced(world.directoryId, path, fileVersion+1); ok {
		t.Fatal("the copy gave a version it never accepted")
	}
	if _, ok := reader.client.IndexReplaced(sidecar.NewId(), path, fileVersion); ok {
		t.Fatal("the copy answered for another repo")
	}
	if _, ok := reader.client.IndexReplaced(world.directoryId, "notes/a.txt", fileVersion); ok {
		t.Fatal("the copy answered for a path that is no card")
	}

	// an hour on the run renews: the same version, a later expiry
	world.clock.Advance(time.Hour)
	renewedMillis := world.clock.Now().UnixMilli()
	renewed := testRunItem(writer.sidecarId, &memberId, announcementId, 1, renewedMillis)
	renewed.StartedMillis, renewed.Who.AgentId, renewed.What.RunId = run.GetStartedMillis(), run.GetWho().GetAgentId(), run.GetWhat().GetRunId()
	device.writeCard(t, renewed)
	reader.mustSync(t)
	documents = testDirectoryIndexDocuments(t, source, reader.client.RefVersions().CardsVersion)
	if document := documents[name]; len(documents) != 1 || document == nil || document.Version != 1 {
		t.Fatalf("the copy's documents after a renewal: %+v", documents)
	}

	// search_agents' fold: a hit whose row holds the first expiry reads the renewed one, and the item's state
	stale := sidecar.SearchHit{
		Repo: world.directoryId, Path: name, Version: 1, DocKind: int(sidecar.IndexDocDerived), Expires: time.UnixMilli(run.GetExpiresMillis()),
		Fields: []sidecar.SearchField{{Field: 6, Text: "run"}, {Field: 15, Text: "active"}},
	}
	other := sidecar.SearchHit{Repo: sidecar.NewId(), Path: name, Version: 1, DocKind: int(sidecar.IndexDocDerived), Expires: time.UnixMilli(run.GetExpiresMillis())}
	folded := reader.client.SearchAgentsFold([]sidecar.SearchHit{stale, other})
	if len(folded) != 2 || !folded[0].Expires.Equal(time.UnixMilli(renewed.GetExpiresMillis())) || !folded[1].Expires.Equal(other.Expires) {
		t.Fatalf("the folded hits: %+v", folded)
	}
	state := ""
	for _, field := range folded[0].Fields {
		if field.Field == 15 {
			state = field.Text
		}
	}
	if state != "active" {
		t.Fatalf("the folded hit's state is %q", state)
	}
	// a copy that has finished no sync leaves hits as they are
	unsynced := world.reader(nil)
	if kept := unsynced.client.SearchAgentsFold([]sidecar.SearchHit{stale}); len(kept) != 1 || !kept[0].Expires.Equal(stale.Expires) {
		t.Fatalf("an unsynced copy folded: %+v", kept)
	}
}

// ur admin directory --window: a window outside 7 to 90 days, a device that is no directory admin, a directory before
// format 2 (needs_format 2) and a binding that writes no index settings each refuse with nothing asked of evs; from
// format 2 a directory admin's write names the directory and the days.
func TestDirectoryIndexWindow(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	member := world.device(world.memberWriter(sidecar.NewId()))
	admin := world.adminDevice()
	member.mustSync(t)
	admin.mustSync(t)
	binding := &testIndexWindowCards{DirectoryCards: world.cardsFor(admin.writer.sidecarId)}
	admin.client.Bind(binding, nil)
	ctx := t.Context()

	for _, days := range []uint32{0, 6, 91} {
		if _, err := admin.client.SetIndexWindow(ctx, days); !errors.Is(err, sidecar.ErrDirectoryIndexWindow) {
			t.Fatalf("a window of %d days: %v", days, err)
		}
	}
	if _, err := member.client.SetIndexWindow(ctx, 14); !errors.Is(err, sidecar.ErrDirectoryEraseNotAdmin) {
		t.Fatalf("a member's window: %v", err)
	}
	// before format 2
	if _, err := admin.client.SetIndexWindow(ctx, 14); !errors.Is(err, sidecar.ErrDirectoryWindowFormat) || !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		t.Fatalf("a window before format 2: %v", err)
	}
	if len(binding.windowDays) != 0 {
		t.Fatalf("a refused window reached evs: %v", binding.windowDays)
	}

	world.cards.RaiseFormat(world.directoryId)
	admin.mustSync(t)
	if !admin.client.Format2() {
		t.Fatal("the admin does not read the directory at format 2")
	}
	window, err := admin.client.SetIndexWindow(ctx, 14)
	if err != nil {
		t.Fatal(err)
	}
	if window.WindowDays != 14 || window.RootCount != 1 || window.Waiting || len(binding.windowDays) != 1 || binding.windowDays[0] != 14 || binding.repoIds[0] != world.directoryId {
		t.Fatalf("the window written: %+v, asked %v of %v", window, binding.windowDays, binding.repoIds)
	}
	binding.err = sidecar.ErrEvsIndexWaits
	if window, err := admin.client.SetIndexWindow(ctx, 30); err != nil || !window.Waiting || window.WindowDays != 30 {
		t.Fatalf("a window that waits: %+v %v", window, err)
	}
	binding.err = errors.New("evs refused the push")
	if _, err := admin.client.SetIndexWindow(ctx, 30); err == nil {
		t.Fatal("a refused write answered a window")
	}
	// a binding that reaches no index writes nothing
	unbound := world.adminDevice()
	unbound.mustSync(t)
	if _, err := unbound.client.SetIndexWindow(ctx, 14); !errors.Is(err, sidecar.ErrDirectoryIndexUnbound) {
		t.Fatalf("a window with no index binding: %v", err)
	}
}
