//go:build sidecar_testhooks

// FS-87's index case in the dropped-listing order (QD-1148, question moderated-run-left-out-dropped-erasure, option 2;
// §16.11's moderation and erasure rows, §11.14's cut row; FI-19, FI-25), on the real engines of the directory world on
// evs (fs_directory_evs.go), T2's fakes: the order fs87_index_evs.go's schedule does not reach, where other erasures'
// CUTs drop a complete moderation from the cards ref's index erasure set before the moderated writer's card returns.
//
//	world     directory admin D, writers B and C and a fresh member device F; B's card holds two runs, the one D
//	          moderates and the one it keeps, and C's two runs D erases after
//	moderate  D erases B's moderated run: the CUT lists its document, the card goes by moderation's removal and its
//	          keys by the ERASE after it, each note of the erasure naming the run in announcement_ids
//	complete  the index's eraser cannot prove its list whole on evs yet (indexEvsStore.Retained answers incomplete, the
//	          not-built row of evs_index_erase.go's header), so the moderation's rewrite stays unproven and the erasure
//	          listed, which no CUT drops: D ends it as a proven rewrite would, by a completion ERASE naming the keys its
//	          ERASEs destroyed, its note the moderation's (QD-1132, QD-1137), and the step does nothing once the
//	          moderation reads complete without it
//	drop      D then erases each of C's runs, each a moderation whose CUT drops every complete erasure before it from
//	          the set, C's card coming back with its other run between: B's evs binding reads the moderated run's
//	          document listed at the version erased after the moderation, and unlisted after the first of C's; B's
//	          daemon, off since its card's write, syncs none of it
//	return    B's daemon still runs the moderated run and hands it to its next card with the other: its sync reads
//	          every ERASE since it stopped and journals the run from the moderation's note, so the return, which
//	          reads the set listing nothing of it, leaves it out and carries the other two above; B hears of the
//	          moderation as a notice once; F lists the kept run at that version and not the moderated one, and the
//	          index holds the kept run's document live at it and the moderated run's nowhere
//	restart   B's daemon starts again from its stores, reading no ERASE again, and a card it rewrites, the moderated run
//	          handed again, keeps the version and leaves the run out
//	checks    after every step: no key a step found an erasure took is readable again (FI-19's keys clause); from the
//	          moderation on, no document an erasure listed stands live in the cards ref's index, read each time the
//	          ref's head moves (FI-19's index clause); every ERASE the repo holds is a directory admin's (FI-25)
//
// Not here: B's run writer and format 2's carrier, which hand the cards as B's daemon would, their stop at the journal
// being the root's directory_cards_erasure_note_test.go's; T3, where only registered cases run, and no catalog case
// names this order.

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

const fs87DroppedWriterC = "writerC"

// The dropped-listing order's sizes.
type Fs87IndexDroppedSettings struct {
	// The time between steps that write, past a card's write interval.
	WriteSpacing time.Duration
}

func DefaultFs87IndexDroppedSettings() *Fs87IndexDroppedSettings {
	return &Fs87IndexDroppedSettings{
		WriteSpacing: time.Minute,
	}
}

// The order's world and what its steps keep.
type fs87IndexDropped struct {
	// the index case's reads of the world (fs87_index_evs.go), over this one
	index    *fs87Index
	world    *DirEvsWorld
	settings *Fs87IndexDroppedSettings
	erased   *DirEvsRun
	kept     *DirEvsRun
	// C's runs, which the erasures after the moderation take
	later []*DirEvsRun

	noted *DirEvsNoted
	// the moderation's erasure, whose notes name the erased run
	moderationId sidecar.Id
	// What the checks hold from the step that found it on: the paths whose noted keys an erasure took, the documents
	// an erasure listed, and the cards ref's head the index clause last read the index at.
	erasedPaths     []string
	erasedDocuments [][]byte
	checkedHead     uint64
	checkedCount    int
}

// The checks after every step: see the file header's checks row.
func (self *fs87IndexDropped) checks() []Invariant {
	return []Invariant{
		NewInvariant("FI-19/keys", func(ctx context.Context, oracle *Oracle) error {
			for _, path := range self.erasedPaths {
				if held, err := self.world.KeysHeld(ctx, oracle.Net, self.noted, path); err != nil || held != 0 {
					return fmt.Errorf("%d keys an erasure took of %s's stored versions are readable: %v", held, path, err)
				}
			}
			return nil
		}),
		NewInvariant("FI-19/index", func(ctx context.Context, oracle *Oracle) error {
			if len(self.erasedDocuments) == 0 {
				return nil
			}
			head, err := self.world.CardsHead(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			if head == self.checkedHead && len(self.erasedDocuments) == self.checkedCount {
				return nil
			}
			versions, err := self.index.liveVersions(ctx, fs87IndexAdmin, self.erasedDocuments...)
			if err != nil {
				return fmt.Errorf("the cards ref's index: %w", err)
			}
			for at, version := range versions {
				if version != 0 {
					return fmt.Errorf("at the cards ref's head %d, document %s an erasure listed stands live at version %d", head, self.erasedDocuments[at], version)
				}
			}
			self.checkedHead, self.checkedCount = head, len(self.erasedDocuments)
			return nil
		}),
		NewInvariant("FI-25/erasers", func(ctx context.Context, oracle *Oracle) error {
			if self.noted == nil {
				return nil
			}
			erasures, err := self.world.Erasures(ctx, fs87IndexAdmin)
			if err != nil {
				return err
			}
			for _, erasure := range erasures {
				if !self.world.IsAdmin(erasure.EraserSidecarId) {
					return fmt.Errorf("an ERASE by %s, which is no directory admin", erasure.EraserSidecarId)
				}
			}
			return nil
		}),
	}
}

// D's erasure of writer's run, a moderation: its card removed whole, the erasure complete, and every ERASE it sent
// carrying a note that names the run alone. Answers the erasure's id.
func (self *fs87IndexDropped) moderate(ctx context.Context, net *Net, writer string, run *DirEvsRun) (sidecar.Id, error) {
	admin := self.world.Device(fs87IndexAdmin)
	if err := admin.Client.Sync(ctx); err != nil {
		return sidecar.Id{}, err
	}
	before, err := self.world.Erasures(ctx, fs87IndexAdmin)
	if err != nil {
		return sidecar.Id{}, err
	}
	result, err := admin.Client.Erase(ctx, &sidecar.DirectoryEraseArgs{Id: run.AnnouncementId, Confirmed: true})
	if err != nil {
		return sidecar.Id{}, fmt.Errorf("D's erasure of %s's run: %w", writer, err)
	}
	cardPath := self.index.cardPath(writer)
	if result.Reason != sidecar.RecordErasureReasonModeration || result.Files == nil || result.Files.CutCount == 0 ||
		!slices.Equal(result.Files.RemovedPaths, []string{cardPath}) {
		return sidecar.Id{}, fmt.Errorf("D's erasure of %s's run: %+v, files %+v", writer, result, result.Files)
	}
	self.erasedPaths = append(self.erasedPaths, cardPath)
	self.erasedDocuments = append(self.erasedDocuments, self.index.runDocument(writer, run))
	if held, err := self.world.KeysHeld(ctx, net, self.noted, cardPath); err != nil || held != 0 {
		return sidecar.Id{}, fmt.Errorf("%d keys of %s's card's stored versions remain: %v", held, writer, err)
	}
	erasures, err := self.world.Erasures(ctx, fs87IndexAdmin)
	if err != nil {
		return sidecar.Id{}, err
	}
	noted := 0
	for _, erasure := range erasures[len(before):] {
		if erasure.EraserSidecarId != admin.SidecarId {
			return sidecar.Id{}, fmt.Errorf("an ERASE of %s by %s, not D", erasure.ErasureId, erasure.EraserSidecarId)
		}
		if erasure.ErasureId != result.ErasureId {
			// an earlier erasure of D's, which this erase resumed first
			continue
		}
		if len(erasure.Note) == 0 {
			// an index pair's ERASE short of the completing one carries no caller bytes
			continue
		}
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(erasure.Note, body); err != nil {
			return sidecar.Id{}, fmt.Errorf("an ERASE's note: %w", err)
		}
		if sidecar.RecordErasureReason(body.GetReason()) != sidecar.RecordErasureReasonModeration || len(body.GetRequestId()) != 0 ||
			len(body.GetAnnouncementIds()) != 1 || !bytes.Equal(body.GetAnnouncementIds()[0], run.AnnouncementId[:]) {
			return sidecar.Id{}, fmt.Errorf("a moderation's note: reason %d, request %x, announcements %x", body.GetReason(), body.GetRequestId(), body.GetAnnouncementIds())
		}
		noted += 1
	}
	if noted == 0 {
		return sidecar.Id{}, errors.New("no ERASE of the moderation names the run it took")
	}
	return result.ErasureId, nil
}

// Ends the moderation at evs where it has not ended: see the file header's complete row.
func (self *fs87IndexDropped) complete(ctx context.Context) error {
	erasures, err := self.world.Erasures(ctx, fs87IndexAdmin)
	if err != nil {
		return err
	}
	keys := []*sidecar.EvsErasedKey{}
	var note []byte
	for _, erasure := range erasures {
		if erasure.ErasureId != self.moderationId {
			continue
		}
		if erasure.Complete {
			return nil
		}
		keys = append(keys, erasure.Keys...)
		if len(erasure.Note) != 0 {
			note = erasure.Note
		}
	}
	if len(keys) == 0 || note == nil {
		return errors.New("the moderation destroyed no key under a note")
	}
	if _, err := self.world.devices[fs87IndexAdmin].device.Repo.Erase(ctx, &sidecar.EvsEraseArgs{
		ErasureId: self.moderationId, Keys: keys, Complete: true, Note: note, Completion: true,
	}); err != nil {
		return fmt.Errorf("D's completion of the moderation: %w", err)
	}
	if erasures, err = self.world.Erasures(ctx, fs87IndexAdmin); err != nil {
		return err
	}
	if !slices.ContainsFunc(erasures, func(erasure *sidecar.EvsErasure) bool {
		return erasure.ErasureId == self.moderationId && erasure.Complete
	}) {
		return errors.New("the moderation reads incomplete after its completion")
	}
	return nil
}

// The version B's evs binding reads the cards ref's index erasure set listing the moderated run's document at.
func (self *fs87IndexDropped) listedVersion(ctx context.Context) (uint64, error) {
	versions, err := self.index.erasedVersions(ctx, fs87IndexWriterB, self.world.IsAdmin, self.index.runDocument(fs87IndexWriterB, self.erased))
	if err != nil {
		return 0, err
	}
	return versions[0], nil
}

// A card of B's handed both its runs, which leaves the moderated one out and carries the kept one at version 3.
func (self *fs87IndexDropped) leavesTheRunOut(written *sidecar.DirectoryCardWritten) error {
	if version := fs87IndexCarried(written, self.kept); version != 3 || len(written.Items) != 1 {
		return fmt.Errorf("B's card carries its kept run at version %d, %d items", version, len(written.Items))
	}
	if !slices.Equal(written.Moderated, []sidecar.Id{self.erased.AnnouncementId}) {
		return fmt.Errorf("B's card left out %v", written.Moderated)
	}
	return nil
}

// FS-87's index case in the dropped-listing order: see the file header.
func Fs87IndexDroppedOnEvs(net *Net) *Schedule {
	return Fs87IndexDroppedOnEvsOf(net, nil)
}

// The order under settings, nil for the defaults.
func Fs87IndexDroppedOnEvsOf(net *Net, settings *Fs87IndexDroppedSettings) *Schedule {
	if settings == nil {
		settings = DefaultFs87IndexDroppedSettings()
	}
	devices := []string{fs87IndexAdmin, fs87IndexWriterB, fs87DroppedWriterC, fs87IndexFresh}
	world := NewDirEvsWorld(net, &DirEvsWorldSettings{
		Devices: []*DirEvsDeviceSettings{
			{Name: fs87IndexAdmin, Admin: true}, {Name: fs87IndexWriterB}, {Name: fs87DroppedWriterC}, {Name: fs87IndexFresh},
		},
	})
	state := &fs87IndexDropped{
		index: &fs87Index{world: world}, world: world, settings: settings,
		erased: NewDirEvsRun("shipper", fs87IndexErasedTitle), kept: NewDirEvsRun("tidier", "tidy the changelog"),
		later: []*DirEvsRun{NewDirEvsRun("pricer", "model the new tiers"), NewDirEvsRun("porter", "port the importer")},
	}
	where := &DirEvsWhere{Project: "example.org/team/app", Branch: "main"}
	// B's runs as its daemon, still running both, hands them: renewed now
	bItems := func(net *Net) []*protocol.Announcement {
		return []*protocol.Announcement{
			world.RunItem(net, fs87IndexWriterB, state.erased, 1, where), world.RunItem(net, fs87IndexWriterB, state.kept, 1, where),
		}
	}
	steps := []*Step{
		{Actor: fs87IndexAdmin, Action: world.Setup},
		{Actor: fs87IndexAdmin, Action: world.InstallIndexWriters(devices...)},
		{Actor: fs87IndexWriterB, Action: func(ctx context.Context, net *Net) error {
			_, err := world.WriteCard(ctx, fs87IndexWriterB, bItems(net)...)
			return err
		}},
		{Actor: fs87DroppedWriterC, Action: func(ctx context.Context, net *Net) error {
			_, err := world.WriteCard(ctx, fs87DroppedWriterC,
				world.RunItem(net, fs87DroppedWriterC, state.later[0], 1, where), world.RunItem(net, fs87DroppedWriterC, state.later[1], 1, where))
			return err
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			noted, err := world.Note(ctx, net, fs87IndexAdmin, []string{state.index.cardPath(fs87IndexWriterB), state.index.cardPath(fs87DroppedWriterC)})
			if err != nil {
				return err
			}
			state.noted = noted
			names := [][]byte{
				state.index.runDocument(fs87IndexWriterB, state.erased), state.index.runDocument(fs87IndexWriterB, state.kept),
				state.index.runDocument(fs87DroppedWriterC, state.later[0]), state.index.runDocument(fs87DroppedWriterC, state.later[1]),
			}
			if versions, err := state.index.liveVersions(ctx, fs87IndexAdmin, names...); err != nil || !slices.Equal(versions, []uint64{1, 1, 1, 1}) {
				return fmt.Errorf("the runs' documents before the erasures, live at versions %v: %v", versions, err)
			}
			return nil
		}},
		{Advance: settings.WriteSpacing},

		// the moderation, then two erasures whose CUTs drop it from the set
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			erasureId, err := state.moderate(ctx, net, fs87IndexWriterB, state.erased)
			if err != nil {
				return err
			}
			state.moderationId = erasureId
			if version, err := state.listedVersion(ctx); err != nil || version != 1 {
				return fmt.Errorf("B's read of the set after the moderation lists the run at %d: %v", version, err)
			}
			return nil
		}},
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			return state.complete(ctx)
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			if _, err := state.moderate(ctx, net, fs87DroppedWriterC, state.later[0]); err != nil {
				return err
			}
			// the dropped-listing order: the set lists nothing of the moderated run any more
			if version, err := state.listedVersion(ctx); err != nil || version != 0 {
				return fmt.Errorf("B's read of the set after a later erasure lists the run at %d: %v", version, err)
			}
			return nil
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87DroppedWriterC, Action: func(ctx context.Context, net *Net) error {
			// C's card back with the run it still holds, which D erases next
			written, err := world.WriteCard(ctx, fs87DroppedWriterC, world.RunItem(net, fs87DroppedWriterC, state.later[1], 1, where))
			if err != nil {
				return err
			}
			if version := fs87IndexCarried(written, state.later[1]); version != 3 {
				return fmt.Errorf("C's card back carries its run at version %d", version)
			}
			return nil
		}},
		{Advance: settings.WriteSpacing},
		{Actor: fs87IndexAdmin, Action: func(ctx context.Context, net *Net) error {
			_, err := state.moderate(ctx, net, fs87DroppedWriterC, state.later[1])
			return err
		}},
		{Advance: settings.WriteSpacing},

		// B's daemon, off through every erasure, comes back still running both runs
		{Actor: fs87IndexWriterB, Action: func(ctx context.Context, net *Net) error {
			if version, err := state.listedVersion(ctx); err != nil || version != 0 {
				return fmt.Errorf("B's read of the set before its return lists the run at %d: %v", version, err)
			}
			written, err := world.WriteCard(ctx, fs87IndexWriterB, bItems(net)...)
			if err != nil {
				return err
			}
			if err := state.leavesTheRunOut(written); err != nil {
				return fmt.Errorf("B's return: %w", err)
			}
			writer := world.Device(fs87IndexWriterB)
			if alarms := writer.Alarms(); len(alarms) != 1 || writer.AlarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.SidecarId) != 1 {
				return fmt.Errorf("B's notices of the moderation: %v", alarms)
			}
			return nil
		}},
		{Actor: fs87IndexFresh, Action: func(ctx context.Context, net *Net) error {
			fresh := world.Device(fs87IndexFresh)
			if err := fresh.Client.Sync(ctx); err != nil {
				return fmt.Errorf("the fresh device's sync: %w", err)
			}
			items, err := fresh.Client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun})
			if err != nil {
				return err
			}
			shown := map[sidecar.Id]*protocol.Announcement{}
			for _, item := range items {
				shown[item.Key.AnnouncementId] = item.Announcement
			}
			if item := shown[state.kept.AnnouncementId]; item == nil || item.GetVersion() != 3 || len(shown) != 1 {
				return fmt.Errorf("the fresh device's directory_list after B's return: %v", shown)
			}
			names := [][]byte{state.index.runDocument(fs87IndexWriterB, state.kept), state.index.runDocument(fs87IndexWriterB, state.erased)}
			if versions, err := state.index.liveVersions(ctx, fs87IndexAdmin, names...); err != nil || !slices.Equal(versions, []uint64{3, 0}) {
				return fmt.Errorf("B's runs' documents after its return, live at versions %v: %v", versions, err)
			}
			return nil
		}},
		{Advance: settings.WriteSpacing},
		// B's daemon starts again from its stores
		{Actor: fs87IndexWriterB, Action: world.Reopen(fs87IndexWriterB)},
		{Actor: fs87IndexWriterB, Action: func(ctx context.Context, net *Net) error {
			written, err := world.WriteCard(ctx, fs87IndexWriterB, bItems(net)...)
			if err != nil {
				return err
			}
			if err := state.leavesTheRunOut(written); err != nil {
				return fmt.Errorf("B's card after its restart: %w", err)
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-87 index, dropped listing", Steps: steps, Check: state.checks(), Tiers: []Tier{TierT2}}
}
