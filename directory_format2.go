//go:build !ios_extension

// The directory's move to format 2 (RECORD-M10-03; §16.11's M6 carrier row, its last clause; D-MCP-28, D-PHASE-11,
// D-EVS-39, FS-84, FS-100): until the directory reaches format 2 items ride announce entries in each writer's stream;
// at the directory's first format-2 push daemons write cards and repo files instead, readers reading both until the
// last entry expires, so one announcement folds to one state from either carrier.
//
//	format    the directory repo's format as GET .../refs lists it (§11.6's format row), which the copy keeps and
//	          never lowers (Format2)
//	start     §19.11's format2 gate governs it: a daemon whose network the gate admits (EvsClient.Format2Admitted,
//	          bound by BindFormat2Gate) writes its directory items as format 2's, its first card or repo file the
//	          push that raises the repo; every other daemon follows once its copy reads the repo at format 2, so one
//	          outside the gate in a format-1 directory keeps writing entries, which M6 clients still read
//	carrier   the carrier writer the run, worker and repo writers append through hands an announce draft at format 2
//	          to the card or the repo file in place of an entry: run and worker items join this sidecar's card, whose
//	          items the carrier keeps (seeded from the last card this device wrote), one card write carrying every
//	          live item and a withdrawal leaving its item out; a repo item, or a private marker, is its repo's r/ file.
//	          Every other draft, and every announce draft before format 2, goes to the record's writer as before
//	readers   the fold reads entries and files alike, keyed by (kind, writer, announcement_id) for runs and workers and
//	          by (repo, announcement_id) for repos, so a reader mid-migration counts an item that has both an entry and
//	          a card once, the higher (version, renewed_millis) standing (directory_fold.go); reading both ends only as
//	          the last entry expires (directory_retention.go's hold)
//	repos     at format 2 a repo admin's device moves each repo item an entry still carries onto its r/ file, the same
//	          announcement at a higher version (MaintainRepos), so a live repo item's last M6 entry expires 30 days
//	          after the r/ file supersedes it
//	notices   q/ notices turn versionless with the cards ref's other files: the binding writes d/, r/ and q/ as the
//	          directory's reserved writer (EvsReservedDirectory, versionless once the gate admits the network), and a
//	          rewrite's replaced content is purged about a minute later, so "from the version it read" rides path CAS
//	          on the path's current version, which the notices already use (directory_notice.go); repair stays the
//	          safety net
//
// Safe for concurrent use. Locks: the carrier's writeLock across a card's write, then the card writer's (WriteCard's),
// then the carrier's stateLock, held across no call out.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const directoryCarrierPart = "format 2 carrier"

// What the move to format 2 runs by.
type DirectoryFormat2Settings struct {
	// The longest an item's card or repo file write takes inside the writer's append, which carries no context: 30 s.
	CarrierTimeout time.Duration
}

// The defaults.
func DefaultDirectoryFormat2Settings() *DirectoryFormat2Settings {
	return &DirectoryFormat2Settings{
		CarrierTimeout: 30 * time.Second,
	}
}

// The client's carrier: the gate, and the items this sidecar's card carries.
type directoryCarrier struct {
	// one card's items computed and written at a time, so a write never drops another's item
	writeLock sync.Mutex

	stateLock sync.Mutex
	// §19.11's format2 gate for the network (EvsClient.Format2Admitted); nil admits nothing
	admitted func() bool
	settings *DirectoryFormat2Settings
	// this sidecar's card's items by announcement_id, seeded once from the last card this device wrote
	items  map[Id]*protocol.Announcement
	seeded bool
}

// The client's carrier part.
func (self *DirectoryClient) carrier() *directoryCarrier {
	return self.part(directoryCarrierPart, func() any {
		return &directoryCarrier{settings: DefaultDirectoryFormat2Settings(), items: map[Id]*protocol.Announcement{}}
	}).(*directoryCarrier)
}

// Binds §19.11's format2 gate for the network, EvsClient.Format2Admitted; nil unbinds it, admitting nothing.
func (self *DirectoryClient) BindFormat2Gate(admitted func() bool) {
	carrier := self.carrier()
	carrier.stateLock.Lock()
	defer carrier.stateLock.Unlock()
	carrier.admitted = admitted
}

// Sets the move's settings; nil keeps them.
func (self *DirectoryClient) SetFormat2Settings(settings *DirectoryFormat2Settings) {
	if settings == nil {
		return
	}
	carrier := self.carrier()
	carrier.stateLock.Lock()
	defer carrier.stateLock.Unlock()
	carrier.settings = settings
}

// Whether the directory's repo is at format 2 as the copy's last listing gave it.
func (self *DirectoryClient) Format2() bool {
	return EvsRepoFormat2 <= self.store.State().Format
}

// Whether this daemon writes its items as format 2's: the copy reads the repo at format 2, or the gate admits the
// network, whose first such write raises it.
func (self *DirectoryClient) carriesFiles() bool {
	if self.Format2() {
		return true
	}
	carrier := self.carrier()
	admitted := func() func() bool {
		carrier.stateLock.Lock()
		defer carrier.stateLock.Unlock()
		return carrier.admitted
	}()
	return admitted != nil && admitted()
}

// The record writer every directory writer appends through: announce drafts go to the card or the repo file once this
// daemon carries files, everything else to next.
type directoryCarrierWriter struct {
	client *DirectoryClient
	next   RecordWriter
}

// The writer the client's parts append through; nil when the client has none.
func (self *DirectoryClient) carrierWriter() RecordWriter {
	if self.writer == nil {
		return nil
	}
	return &directoryCarrierWriter{client: self, next: self.writer}
}

// See the type's comment. A carried draft answers no entry ref.
func (self *directoryCarrierWriter) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	if draft == nil || draft.Kind != RecordKindAnnounce || !self.client.carriesFiles() {
		return self.next.Append(draft)
	}
	item, ok := draft.Body.(*protocol.Announcement)
	if !ok {
		return self.next.Append(draft)
	}
	carrier := self.client.carrier()
	timeout := func() time.Duration {
		carrier.stateLock.Lock()
		defer carrier.stateLock.Unlock()
		return carrier.settings.CarrierTimeout
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := self.client.carryItem(ctx, item); err != nil {
		return nil, err
	}
	return []*RecordEntryRef{}, nil
}

// Hands one item to format 2's carrier: see the file's header's carrier row.
func (self *DirectoryClient) carryItem(ctx context.Context, item *protocol.Announcement) error {
	switch DirectoryAnnouncementKind(item.GetKind()) {
	case DirectoryAnnouncementKindRepo:
		_, err := self.WriteRepoFile(ctx, item)
		return err
	case DirectoryAnnouncementKindRun, DirectoryAnnouncementKindWorker:
	default:
		return fmt.Errorf("%w: an announcement of kind %d", ErrDirectoryFormatInvalid, item.GetKind())
	}
	carrier := self.carrier()
	carrier.writeLock.Lock()
	defer carrier.writeLock.Unlock()
	if err := self.seedCarrier(carrier); err != nil {
		return err
	}
	announcementId := recordIdOf(item.GetAnnouncementId())
	items := func() []*protocol.Announcement {
		carrier.stateLock.Lock()
		defer carrier.stateLock.Unlock()
		if DirectoryAnnouncementState(item.GetState()) == DirectoryAnnouncementStateWithdrawn {
			// a card says a withdrawal by leaving the item out
			delete(carrier.items, announcementId)
		} else {
			carrier.items[announcementId] = proto.Clone(item).(*protocol.Announcement)
		}
		items := make([]*protocol.Announcement, 0, len(carrier.items))
		for _, held := range carrier.items {
			items = append(items, proto.Clone(held).(*protocol.Announcement))
		}
		return items
	}()
	written, err := self.WriteCard(ctx, &DirectoryCardWriteArgs{Items: items})
	if err != nil {
		return err
	}
	// what the card no longer holds, ended or stale past its window, the carrier forgets
	carrier.stateLock.Lock()
	defer carrier.stateLock.Unlock()
	kept := map[Id]bool{}
	for _, held := range written.Items {
		kept[recordIdOf(held.GetAnnouncementId())] = true
	}
	for heldId := range carrier.items {
		if !kept[heldId] {
			delete(carrier.items, heldId)
		}
	}
	return nil
}

// Seeds the carrier's items once from the last card this device wrote, so a restart's first card keeps the items the
// last one carried.
func (self *DirectoryClient) seedCarrier(carrier *directoryCarrier) error {
	carrier.stateLock.Lock()
	seeded := carrier.seeded
	carrier.stateLock.Unlock()
	if seeded {
		return nil
	}
	written, err := self.readCardWritten()
	if err != nil {
		return err
	}
	items := []*protocol.Announcement{}
	if 0 < len(written.Content) {
		signed := &bridge.Signed{}
		card := &protocol.DirectoryCard{}
		if proto.Unmarshal(written.Content, signed) == nil && proto.Unmarshal(signed.GetBody(), card) == nil &&
			bytes.Equal(card.GetSidecarId(), self.sidecarId[:]) {
			items = card.GetItems()
		}
	}
	carrier.stateLock.Lock()
	defer carrier.stateLock.Unlock()
	if !carrier.seeded {
		for _, item := range items {
			announcementId := recordIdOf(item.GetAnnouncementId())
			if _, ok := carrier.items[announcementId]; !ok {
				carrier.items[announcementId] = item
			}
		}
		carrier.seeded = true
	}
	return nil
}

// Whether a repo item that stands rides an entry still: what MaintainRepos moves onto the r/ file once this daemon
// carries files.
func directoryRepoItemOnEntry(winner *directoryVersion) bool {
	return winner != nil && winner.entryId != (Id{})
}
