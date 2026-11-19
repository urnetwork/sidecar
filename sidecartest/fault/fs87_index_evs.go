//go:build sidecar_testhooks

// FS-87's index case (§22.8; §16.11's revoke, retention and roll-up rows and Erasure and removal block, §11.12's cut
// and closure rows, §11.14's erase row, owner decision 181, FI-19; RECORD-M10-06), format 2's, at the later of M6-out
// and M10-out, on real engines: the directory world on evs (fs_directory_evs.go), on T2's fakes and, through server's
// evshost, on T3's stores (server's sidecar_directory_format2_t3_test.go). It extends RECORD-M6-26's schedule: the
// M6 case's masking, cleanup and retention legs stay in the directory world on the fakes (fs87_test.go).
//
//	world     directory admin D, repo owner R (P's admin), writers A and B and a fresh member device F. R announces
//	          P; A's card holds a run in P; B's card holds two runs, one of which changes once, so two stored
//	          versions of the card held it under the path's one key
//	erase     D, a directory admin, erases B's announcement (moderation): the CUT lists its document first, the card
//	          that still held it is removed whole and every key its stored versions were kept under is destroyed, each
//	          ERASE's note naming moderation and no request; the same id again finds nothing; B's next card brings
//	          its other run back under a key no ERASE named; B's device hears of the moderation as a notice, and no
//	          other device raises anything
//	revoke    R revokes P, seeded with A's card and its index document. A's daemon renews its run before it reads
//	          the marker, so a copy naming P is written after the request. D's pass rewrites P's file and the index
//	          files under fresh keys and leaves A's card waiting; a pass with nothing new sends nothing; once A read
//	          the marker and wrote its run private, the runner's later sync rewrites the card, and no key that a
//	          stored card, repo file or index file naming P was kept under remains
//	fresh     F, with an empty cache, syncs with no alarm, holds no copy naming P or the erased run, and shows B's
//	          other run
//	roll-up   past searchable_days the cards ref's expired bucket is rolled up: the roll-up drops no document, A's
//	          run, private by then, still standing in the index, since searchable_days is a mask a search applies
//	          (question record-m10-06-rollups-drop-past-searchable-days, QD-1104), and no document the erasures
//	          listed comes back
//
// Not here: whether B's other run is searchable again once its card is back: the removal's push left its document a
// tombstone one version above the item's, which the card written again at the item's own version does not pass
// (question record-m10-06-moderated-card-index-tombstone), so the case holds that run to the fold alone; the mask itself, which a search applies and the search rows hold (FS-76; search_mask.go's tests); FI-19
// through the search oracle, whose ledger this world does not feed: the case holds the same rule on the slot objects
// and the index's own files; a runner killed mid-erasure, which FS-99's cards case runs (fs99_cards_evs.go).

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs87Index = Register("FS-87", "index", []Tier{TierT2, TierT3}, Fs87IndexOnEvs)

const (
	fs87IndexAdmin   = "daemonD"
	fs87IndexOwner   = "ownerR"
	fs87IndexWriterA = "writerA"
	fs87IndexWriterB = "writerB"
	fs87IndexFresh   = "daemonF"
	fs87IndexRepo    = "P"
	// what no readable copy may hold once the erasures ran: P's name, the project A's run names in it, and the
	// erased run's title
	fs87IndexRepoTitle   = "pricing notes"
	fs87IndexProject     = "example.org/team/pricing-notes"
	fs87IndexErasedTitle = "ship the pricing change"
)

// FS-87's index case's sizes.
type Fs87IndexSettings struct {
	// The time between a card's writes, past a card's write interval.
	WriteSpacing time.Duration
	// How far past the last write the roll-up runs: past the directory's searchable_days, 90.
	RollUpAge time.Duration
}

func DefaultFs87IndexSettings() *Fs87IndexSettings {
	return &Fs87IndexSettings{
		WriteSpacing: time.Minute,
		RollUpAge:    100 * 24 * time.Hour,
	}
}

// The case's world and what its steps keep.
type fs87Index struct {
	world    *DirEvsWorld
	settings *Fs87IndexSettings
	runInP   *DirEvsRun
	erased   *DirEvsRun
	kept     *DirEvsRun

	noted      *DirEvsNoted
	revocation *sidecar.DirectoryRevocation
	// the ERASEs the moderation erasure sent, before the revocation's
	moderationEraseCount int
}

func (self *fs87Index) repoPath() string {
	return sidecar.DirectoryRepoPath(self.world.Repo(fs87IndexRepo))
}

func (self *fs87Index) cardPath(device string) string {
	return sidecar.DirectoryCardPath(self.world.Device(device).SidecarId)
}

// The name of a run's document on the cards ref's index.
func (self *fs87Index) runDocument(device string, run *DirEvsRun) []byte {
	writerId := self.world.Device(device).SidecarId
	return DirEvsDocumentName(&writerId, run.AnnouncementId)
}

// The version the cards ref's index holds a document live at, as device reads the index; 0 for none.
func (self *fs87Index) liveVersion(ctx context.Context, device string, name []byte) (uint64, error) {
	erasure, err := self.world.Erasure(device)
	if err != nil {
		return 0, err
	}
	index, err := erasure.CardsIndex(ctx, self.world.DirectoryId)
	if err != nil {
		return 0, err
	}
	key, err := index.DocKey(name)
	if err != nil {
		return 0, err
	}
	held, err := self.world.CardsIndex(ctx, device)
	if err != nil {
		return 0, err
	}
	return held.Live[key], nil
}

// No document naming P stands live in the cards ref's index at the version that named it, nor the erased run's at
// any.
func (self *fs87Index) noErasedDocumentLive(ctx context.Context, device string, revoked bool) error {
	if version, err := self.liveVersion(ctx, device, self.runDocument(fs87IndexWriterB, self.erased)); err != nil || version != 0 {
		return fmt.Errorf("the erased run's document stands live at version %d: %v", version, err)
	}
	if !revoked {
		return nil
	}
	for _, name := range [][]byte{
		DirEvsDocumentName(nil, sidecar.DirectoryRepoAnnouncementId(self.world.Repo(fs87IndexRepo))),
		self.runDocument(fs87IndexWriterA, self.runInP),
	} {
		// version 1 of each named P; the marker and the private run are their version 2
		if version, err := self.liveVersion(ctx, device, name); err != nil || version == 1 {
			return fmt.Errorf("a document naming P stands live at version %d: %v", version, err)
		}
	}
	return nil
}

// Each ERASE in erasures carrying a body names reason, and requestId where one is given.
func fs87IndexNotes(erasures []*sidecar.EvsErasure, eraserId sidecar.Id, reason sidecar.RecordErasureReason, requestId *sidecar.Id) error {
	for _, erasure := range erasures {
		if erasure.EraserSidecarId != eraserId {
			return fmt.Errorf("an ERASE by %s, not the directory admin", erasure.EraserSidecarId)
		}
		if len(erasure.Note) == 0 {
			// an index pair's ERASE short of the completing one carries no caller bytes
			continue
		}
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(erasure.Note, body); err != nil {
			return fmt.Errorf("an ERASE's note: %w", err)
		}
		if sidecar.RecordErasureReason(body.GetReason()) != reason {
			return fmt.Errorf("an ERASE's note names reason %d", body.GetReason())
		}
		if requestId == nil && len(body.GetRequestId()) != 0 || requestId != nil && !bytes.Equal(body.GetRequestId(), requestId[:]) {
			return errors.New("an ERASE's note names another request")
		}
	}
	return nil
}

// FS-87's index case: see the file header.
func Fs87IndexOnEvs(net *Net) *Schedule {
	return Fs87IndexOnEvsOf(net, nil)
}

// FS-87's index case under settings, nil for the defaults.
func Fs87IndexOnEvsOf(net *Net, settings *Fs87IndexSettings) *Schedule {
	if settings == nil {
		settings = DefaultFs87IndexSettings()
	}
	devices := []string{fs87IndexAdmin, fs87IndexOwner, fs87IndexWriterA, fs87IndexWriterB, fs87IndexFresh}
	world := NewDirEvsWorld(net, &DirEvsWorldSettings{
		Devices: []*DirEvsDeviceSettings{
			{Name: fs87IndexAdmin, Admin: true}, {Name: fs87IndexOwner}, {Name: fs87IndexWriterA}, {Name: fs87IndexWriterB}, {Name: fs87IndexFresh},
		},
		RepoAdmins: map[string][]string{fs87IndexRepo: {fs87IndexOwner}},
	})
	state := &fs87Index{
		world: world, settings: settings,
		runInP: NewDirEvsRun("pricer", "model the new tiers"), erased: NewDirEvsRun("shipper", fs87IndexErasedTitle),
		kept: NewDirEvsRun("tidier", "tidy the changelog"),
	}
	runOfA := func(net *Net, private bool) *protocol.Announcement {
		repoId := world.Repo(fs87IndexRepo)
		if private {
			return world.RunItem(net, fs87IndexWriterA, state.runInP, 2, &DirEvsWhere{RepoId: &repoId, Private: true})
		}
		return world.RunItem(net, fs87IndexWriterA, state.runInP, 1, &DirEvsWhere{RepoId: &repoId, Project: fs87IndexProject, Branch: "main"})
	}
	keptItem := func(net *Net) *protocol.Announcement {
		return world.RunItem(net, fs87IndexWriterB, state.kept, 1, &DirEvsWhere{Project: "example.org/team/app", Branch: "main"})
	}
	steps := []*Step{
		{Actor: fs87IndexAdmin, Action: world.Setup},
		{Actor: fs87IndexAdmin, Action: world.InstallIndexWriters(devices...)},
		{Actor: fs87IndexOwner, Action: func(ctx context.Context, net *Net) error {
			owner := world.Device(fs87IndexOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			if _, err := owner.Client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.Repo(fs87IndexRepo), DisplayName: fs87IndexRepoTitle, Confirmed: true}); err != nil {
				return fmt.Errorf("R's announcement of P: %w", err)
			}
			return nil
		}},
		{Actor: fs87IndexWriterA, Action: func(ctx context.Context, net *Net) error {
			_, err := world.WriteCard(ctx, fs87IndexWriterA, runOfA(net, false))
			return err
		}},
		{Actor: fs87IndexWriterB, Action: func(ctx context.Context, net *Net) error {
			_, err := world.WriteCard(ctx, fs87IndexWriterB,
				world.RunItem(net, fs87IndexWriterB, state.erased, 1, &DirEvsWhere{Project: "example.org/team/app", Branch: "main"}), keptItem(net))
			return err
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87IndexWriterB, Action: func(ctx context.Context, net *Net) error {
			// a content change, so two stored versions of the card held the item
			_, err := world.WriteCard(ctx, fs87IndexWriterB,
				world.RunItem(net, fs87IndexWriterB, state.erased, 2, &DirEvsWhere{Project: "example.org/team/app", Branch: "pricing"}), keptItem(net))
			return err
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			noted, err := world.Note(ctx, net, fs87IndexAdmin, []string{state.repoPath(), state.cardPath(fs87IndexWriterA), state.cardPath(fs87IndexWriterB)})
			if err != nil {
				return err
			}
			state.noted = noted
			if version, err := state.liveVersion(ctx, fs87IndexAdmin, state.runDocument(fs87IndexWriterB, state.erased)); err != nil || version != 2 {
				return fmt.Errorf("the run's document before its erasure, live at version %d: %v", version, err)
			}
			return nil
		}},

		// a directory admin's erasure of an announcement
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			admin := world.Device(fs87IndexAdmin)
			if err := admin.Client.Sync(ctx); err != nil {
				return err
			}
			result, err := admin.Client.Erase(ctx, &sidecar.DirectoryEraseArgs{Id: state.erased.AnnouncementId, Confirmed: true})
			if err != nil {
				return fmt.Errorf("D's erasure of B's announcement: %w", err)
			}
			cardPath := state.cardPath(fs87IndexWriterB)
			if result.Reason != sidecar.RecordErasureReasonModeration || result.Files == nil || result.Files.CutCount == 0 ||
				!slices.Equal(result.Files.RemovedPaths, []string{cardPath}) || len(result.Files.ClosedPaths) != 0 {
				return fmt.Errorf("D's erasure: %+v, files %+v", result, result.Files)
			}
			// no stored card version that held it has a readable key, and no index version holds it live
			if held, err := world.KeysHeld(ctx, net, state.noted, cardPath); err != nil || held != 0 {
				return fmt.Errorf("%d keys of the card's stored versions remain: %v", held, err)
			}
			if err := state.noErasedDocumentLive(ctx, fs87IndexAdmin, false); err != nil {
				return err
			}
			erasures, err := world.Erasures(ctx, fs87IndexAdmin)
			if err != nil || len(erasures) == state.noted.EraseCount {
				return fmt.Errorf("no ERASE for the admin's erasure: %v", err)
			}
			for _, erasure := range erasures[state.noted.EraseCount:] {
				if erasure.ErasureId != result.ErasureId {
					return fmt.Errorf("an ERASE of %s, not the admin's erasure", erasure.ErasureId)
				}
			}
			if err := fs87IndexNotes(erasures[state.noted.EraseCount:], admin.SidecarId, sidecar.RecordErasureReasonModeration, nil); err != nil {
				return err
			}
			state.moderationEraseCount = len(erasures)
			// the others' files keep their keys
			for _, path := range []string{state.repoPath(), state.cardPath(fs87IndexWriterA)} {
				if held, err := world.KeysHeld(ctx, net, state.noted, path); err != nil || held != len(state.noted.Keys[path]) {
					return fmt.Errorf("the erasure of B's announcement took a key of another file: %v", err)
				}
			}
			// the same id again finds nothing left
			if err := admin.Client.Sync(ctx); err != nil {
				return err
			}
			if _, err := admin.Client.Erase(ctx, &sidecar.DirectoryEraseArgs{Id: state.erased.AnnouncementId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryItemNone) {
				return fmt.Errorf("a second erasure of the announcement: %v", err)
			}
			return nil
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87IndexWriterB, Action: func(ctx context.Context, net *Net) error {
			// B's next card brings its other run back, under a key no ERASE named
			if _, err := world.WriteCard(ctx, fs87IndexWriterB, keptItem(net)); err != nil {
				return err
			}
			erasure, err := world.Erasure(fs87IndexWriterB)
			if err != nil {
				return err
			}
			keys, err := erasure.CardKeys(ctx, world.DirectoryId, []string{state.cardPath(fs87IndexWriterB)})
			if err != nil {
				return err
			}
			standing := 0
			for _, key := range keys {
				held, err := world.KeyHeld(ctx, net, key)
				if err != nil {
					return err
				}
				if held {
					standing += 1
				}
			}
			if standing != 1 {
				return fmt.Errorf("B's card, written again, stands under %d keys", standing)
			}
			// the moderated sidecar's member's device hears of it, as a notice naming its sidecar, and of nothing else
			writer := world.Device(fs87IndexWriterB)
			if alarms := writer.Alarms(); len(alarms) != 1 || writer.AlarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.SidecarId) != 1 {
				return fmt.Errorf("B's notices of its card's removal: %v", alarms)
			}
			if err := world.Device(fs87IndexWriterA).Client.Sync(ctx); err != nil {
				return err
			}
			if alarms := world.Device(fs87IndexWriterA).Alarms(); len(alarms) != 0 {
				return fmt.Errorf("another member's device alarmed at B's card's removal: %v", alarms)
			}
			return nil
		}},

		// a revoke seeded with cards and index documents, and a daemon renewing before it reads the marker
		{Actor: fs87IndexOwner, Action: func(ctx context.Context, net *Net) error {
			owner := world.Device(fs87IndexOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			revocation, err := owner.Client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.Repo(fs87IndexRepo), Confirmed: true})
			if err != nil {
				return fmt.Errorf("R's revocation: %w", err)
			}
			state.revocation = revocation
			return owner.Record.Flush(ctx)
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87IndexWriterA, Action: func(ctx context.Context, net *Net) error {
			// A's renewal, from a copy that has not read the marker: the card names P again, after the request
			writer := world.Device(fs87IndexWriterA)
			if item, ok := writer.Client.RepoItem(world.Repo(fs87IndexRepo)); !ok || item.Announcement.GetWhere().GetPrivate() {
				return errors.New("A's copy already holds the marker")
			}
			if _, err := writer.Client.WriteCard(ctx, &sidecar.DirectoryCardWriteArgs{Items: []*protocol.Announcement{runOfA(net, false)}}); err != nil {
				return fmt.Errorf("A's renewal before it reads the marker: %w", err)
			}
			return nil
		}},
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			pass, err := world.Pass(ctx, fs87IndexAdmin)
			if err != nil {
				return fmt.Errorf("D's pass: %w", err)
			}
			files := pass.Files[state.revocation.RequestId]
			if files == nil || files.CutCount == 0 || !slices.Equal(files.ClosedPaths, []string{state.repoPath()}) ||
				!slices.Equal(files.WaitingPaths, []string{state.cardPath(fs87IndexWriterA)}) {
				return fmt.Errorf("D's pass: %+v, files %+v", pass, files)
			}
			if held, err := world.KeysHeld(ctx, net, state.noted, state.repoPath()); err != nil || held != 0 {
				return fmt.Errorf("%d keys of P's file's old versions remain: %v", held, err)
			}
			if err := state.noErasedDocumentLive(ctx, fs87IndexAdmin, true); err != nil {
				return err
			}
			// a pass with nothing new sends nothing
			erasures, err := world.Erasures(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			closures, err := world.CardClosures(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			if pass, err = world.Pass(ctx, fs87IndexAdmin); err != nil {
				return fmt.Errorf("D's idle pass: %w", err)
			}
			erasuresAfter, err := world.Erasures(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			closuresAfter, err := world.CardClosures(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			if len(erasuresAfter) != len(erasures) || len(closuresAfter) != len(closures) {
				return fmt.Errorf("an idle pass sent %d ERASEs and %d CLOSUREs", len(erasuresAfter)-len(erasures), len(closuresAfter)-len(closures))
			}
			return nil
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87IndexWriterA, Action: func(ctx context.Context, net *Net) error {
			// A reads the marker and writes its run private
			_, err := world.WriteCard(ctx, fs87IndexWriterA, runOfA(net, true))
			return err
		}},
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			// the runner's later sync
			pass, err := world.Pass(ctx, fs87IndexAdmin)
			if err != nil {
				return fmt.Errorf("D's later pass: %w", err)
			}
			cardPath := state.cardPath(fs87IndexWriterA)
			files := pass.Files[state.revocation.RequestId]
			if files == nil || !slices.Equal(files.ClosedPaths, []string{cardPath}) || len(files.WaitingPaths) != 0 {
				return fmt.Errorf("D's later pass: %+v, files %+v", pass, files)
			}
			// no stored card, repo file or index file holding the name has a readable key
			for _, path := range []string{state.repoPath(), cardPath} {
				if held, err := world.KeysHeld(ctx, net, state.noted, path); err != nil || held != 0 {
					return fmt.Errorf("%d keys of versions naming P remain: %v", held, err)
				}
			}
			if err := state.noErasedDocumentLive(ctx, fs87IndexAdmin, true); err != nil {
				return err
			}
			erasures, err := world.Erasures(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			for _, erasure := range erasures[state.moderationEraseCount:] {
				if erasure.ErasureId != state.revocation.RequestId {
					return fmt.Errorf("an ERASE of %s, not the request", erasure.ErasureId)
				}
			}
			return fs87IndexNotes(erasures[state.moderationEraseCount:], world.Device(fs87IndexAdmin).SidecarId, sidecar.RecordErasureReasonRevocation, &state.revocation.RequestId)
		}},
		{Actor: fs87IndexFresh, Action: func(ctx context.Context, net *Net) error {
			fresh := world.Device(fs87IndexFresh)
			if err := fresh.Client.Sync(ctx); err != nil {
				return fmt.Errorf("the fresh device's sync: %w", err)
			}
			if alarms := fresh.Alarms(); len(alarms) != 0 {
				return fmt.Errorf("the fresh device alarmed: %v", alarms)
			}
			if alarms := world.EvsAlarms(fs87IndexFresh); len(alarms) != 0 {
				return fmt.Errorf("the fresh device's evs alarmed: %v", alarms)
			}
			for _, file := range fresh.Client.Cards() {
				for _, name := range []string{fs87IndexRepoTitle, fs87IndexProject, fs87IndexErasedTitle} {
					if bytes.Contains(file.Content, []byte(name)) {
						return fmt.Errorf("the fresh device's copy holds %q at %s version %d", name, file.Path, file.Version)
					}
				}
			}
			items, err := fresh.Client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun, IncludePrivate: true})
			if err != nil {
				return err
			}
			shown := map[sidecar.Id]*protocol.Announcement{}
			for _, item := range items {
				shown[item.Key.AnnouncementId] = item.Announcement
			}
			if shown[state.erased.AnnouncementId] != nil {
				return errors.New("the fresh device shows the erased run")
			}
			if item := shown[state.kept.AnnouncementId]; item == nil || item.GetWhat().GetTitle() != state.kept.Title {
				return errors.New("the fresh device does not show B's other run")
			}
			if item := shown[state.runInP.AnnouncementId]; item == nil || !item.GetWhere().GetPrivate() || item.GetWhere().GetProject() != "" {
				return fmt.Errorf("A's run in P at the fresh device: %v", item)
			}
			return nil
		}},

		// past searchable_days a roll-up drops nothing: the days are a search's mask
		{Advance: settings.RollUpAge},
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			admin := world.Device(fs87IndexAdmin)
			// A's run, private since it read the marker, is the document that stands
			standingName := state.runDocument(fs87IndexWriterA, state.runInP)
			if version, err := state.liveVersion(ctx, fs87IndexAdmin, standingName); err != nil || version != 2 {
				return fmt.Errorf("A's run's document before the roll-up, live at version %d: %v", version, err)
			}
			rolled, err := sidecar.RollUpSearchTestEvs(ctx, admin.device.Repo, sidecar.DirectoryCardsRefName(), admin.SidecarId, world.IsAdmin)
			if err != nil {
				return fmt.Errorf("the roll-up: %w", err)
			}
			if rolled.Version == 0 {
				return fmt.Errorf("the roll-up committed nothing: %q", rolled.Skipped)
			}
			index, err := world.CardsIndex(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			if index.RolledThroughDay == 0 || index.AllShardCount == 0 {
				return fmt.Errorf("the index after the roll-up: rolled through day %d, %d shards in all", index.RolledThroughDay, index.AllShardCount)
			}
			if version, err := state.liveVersion(ctx, fs87IndexAdmin, standingName); err != nil || version != 2 {
				return fmt.Errorf("the roll-up dropped a document past searchable_days: live at version %d, %v", version, err)
			}
			return state.noErasedDocumentLive(ctx, fs87IndexAdmin, true)
		}},
	}
	return &Schedule{Id: "FS-87", Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
