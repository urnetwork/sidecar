//go:build !ios_extension

// What a card's return reads of the cards ref's index erasure set (QD-1144, question
// card-version-rise-after-removal-moderated-run-carried-again, option 1; §16.11's erasure, closure, moderation and
// versions rows, owner decisions 636 and 645; FI-19, FS-87): a directory admin's erase of an announcement removes the
// card still holding it, and nothing tells the writer's daemon which item was taken, so its run and worker writers and
// format 2's carrier would hand the item to its next card, which owner decision 645 raises above the erasure's listing,
// and the index would enter it live again.
//
//	read       at a return, the first card a writer puts since another signer removed its path (directory_card.go's
//	           version row), the card writer reads the set once, through the directory's evs binding: the optional
//	           DirectoryCardsErasureSet beside DirectoryCards, which DirectoryEvsCards answers by reading the set's
//	           file at the cards ref's head through evs's verifying reader, held to the index format and to a directory
//	           admin's signature as every index reader holds it (§11.14's cut row), and keying each item's document,
//	           a/ || writer || announcement_id, under K_ref (§11.14's key row)
//	moderated  every item of the card this device put last whose document the set lists at or above the version that
//	           card held it at is one an erasure took: the return leaves it out, and so does every card after, which the
//	           card written document journals with the seq and the raise before the put (Moderated), so a kill, a
//	           failed put or a restart leaves it out alike; format 2's carrier forgets it with the card, and a restart
//	           seeds it no more (cardWrittenItems)
//	writers    the run and worker writers ask the journal before each write (cardItemModerated) and stop announcing an
//	           item it names, keeping that in their own state (directory_run.go, directory_worker.go); a carried
//	           draft the card left out answers ErrDirectoryItemModerated, so the writer appending it learns at once
//	nothing    a return whose last card holds nothing the set lists reads it once and changes nothing: every item comes
//	           back raised, as owner decision 645 says
//	closed     a return whose check cannot be made, no binding reading the set, a set that does not read, one no
//	           directory admin signed, refuses with ErrDirectoryCardReturnUnchecked before anything is signed or put:
//	           the next write checks again, and nothing that may be listed comes back unread
//	note       the backstop (QD-1148, question moderated-run-left-out-dropped-erasure, option 2): what the set no longer
//	           lists the read cannot find, since another erasure's CUT drops a complete one from it (indexCutSet's
//	           listed_since), and a directory admin's moderation of an announcement says complete with the ERASE of the
//	           removed card's keys once its index rewrites are proven (directory_erasure.go; on evs, once the index's
//	           eraser walks a removed path's history, evs_index_erase.go). So that ERASE's sealed note names the
//	           moderation took (ErasureBody.announcement_ids), and every sync of this device reads the erasure ref's
//	           ERASEs (the judge of directory_revoke.go): each announcement a directory admin's moderation note names
//	           that the card this device put last holds is journaled at once, as a return's finds are, whatever the set
//	           lists by then and however long this device was off, so its return, every card after, the format 2
//	           carrier's seed and the run and worker writers leave it out. A sync journals under the card writer's
//	           stateLock, never its writeLock, which a card write holds across its conflict's sync; a write takes into
//	           its journal what a sync journaled since it read it (takeJournal), and one the store did not keep is held
//	           for the next keep. The return's read stays for what no note names: a moderation whose ERASE has not
//	           committed yet is still listed, being incomplete
//
// The read costs one index file read at a return, which is rare, and changes no format; the note's ids are sealed, so
// no server sees more. Nothing of a view or a search reaches evs (I-19): the read names the ref and its erasure set's
// path, and the doc_keys stay on the device. Neither finds an item only a card put just before a kill held, a card
// the card written document never recorded: it comes back. On every leg but the ios_extension legs. Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A return, the first card since another signer removed this sidecar's path, whose check against the cards ref's
	// erasure set could not be made: no binding reads the set, or it does not read, or no directory admin signed it.
	// Nothing was signed or put; the next write checks again.
	ErrDirectoryCardReturnUnchecked = errors.New("directory card: a return not checked against the erasure set")
	// The card a carried item was handed to left it out: an erasure took its announcement (the file's header's
	// moderated row), and its writer announces it no more.
	ErrDirectoryItemModerated = errors.New("directory item left out: an erasure took it")
)

// What a card's return reads beyond DirectoryCards: the cards ref's index erasure set, which DirectoryEvsCards answers.
// See the file's header.
type DirectoryCardsErasureSet interface {
	// The version the cards ref's index erasure set lists each of args.Names' documents at, by its doc_key under the
	// directory's K_ref, in the order asked; 0 for a document it lists nowhere, and every 0 where no set is written. A
	// set that does not read, or whose version no signer args.IsAdmin takes, is an error: no document reads as unlisted
	// that may be listed.
	CardsErasedVersions(ctx context.Context, repoId Id, args *DirectoryCardsErasedArgs) ([]uint64, error)
}

// What CardsErasedVersions reads by.
type DirectoryCardsErasedArgs struct {
	// The documents' names, a/ || writer || announcement_id (directoryIndexAnnouncementName).
	Names [][]byte
	// Whether a sidecar may erase in the directory: the set's version counts only as one such sidecar signed.
	IsAdmin func(signerSidecarId Id) bool
	// The index format the set's file is read under; nil for its defaults.
	IndexFormat *IndexFormatSettings
}

var _ DirectoryCardsErasureSet = (*DirectoryEvsCards)(nil)

// The set's file at the cards ref's head, read and verified by evs's reader, held to the index format and to its
// signer's standing, and each name's doc_key under K_ref looked up in it: see DirectoryCardsErasureSet.
func (self *DirectoryEvsCards) CardsErasedVersions(ctx context.Context, repoId Id, args *DirectoryCardsErasedArgs) ([]uint64, error) {
	if args == nil || args.IsAdmin == nil {
		return nil, directoryEvsInvalid()
	}
	format := args.IndexFormat
	if format == nil {
		format = DefaultIndexFormatSettings()
	}
	versions := make([]uint64, len(args.Names))
	if len(args.Names) == 0 {
		return versions, nil
	}
	repo := self.client.Repo(repoId)
	store := newIndexEvsStore(repo, DirectoryCardsRefName(), false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	path := indexErasureSetPath(false)
	files, _, err := store.fileVersions(ctx, refId, []string{path})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	if len(files) == 0 {
		// no CUT wrote one: nothing is listed
		return versions, nil
	}
	file := files[0]
	if !args.IsAdmin(file.signerSidecarId) {
		// a version from a signer who may not erase: every index reader ignores it, so nothing reads as listed or not
		return nil, fmt.Errorf("%w: a set version no directory admin signed", ErrDirectoryCardReturnUnchecked)
	}
	plaintext, err := store.Read(ctx, file)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	parsed, ok := indexParsePath(path, false)
	if !ok {
		return nil, fmt.Errorf("%w: the set's path", ErrDirectoryCardReturnUnchecked)
	}
	validated, err := indexValidateFile(parsed, indexBytesFrames(plaintext), file.contentSha256[:], format)
	switch {
	case errors.Is(err, errIndexMalformed), errors.Is(err, errIndexNewerFormat):
		return nil, fmt.Errorf("%w: %w", ErrDirectoryCardReturnUnchecked, err)
	case err != nil:
		return nil, err
	}
	erasureSet, ok := validated.message.(*protocol.IndexErasureSet)
	if !ok {
		return nil, fmt.Errorf("%w: the set's file", ErrDirectoryCardReturnUnchecked)
	}
	repoKey, err := self.client.args.Gkm.CurrentRepoKey(ctx, repoId)
	if err != nil {
		return nil, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	for index, name := range args.Names {
		key, err := indexDocKey(refKey, refId, name, 0)
		if err != nil {
			return nil, err
		}
		for _, erasure := range erasureSet.GetErasures() {
			for _, erased := range erasure.GetDocs() {
				if bytes.Equal(erased.GetDocKey(), key[:]) {
					versions[index] = max(versions[index], erased.GetVersion())
				}
			}
		}
	}
	return versions, nil
}

// One item an erasure took, as the card written document journals it: one a return left out, or one a moderation's
// note named.
type directoryCardModerated struct {
	AnnouncementId Id `json:"announcement_id"`
	// The version the erasure set listed its document at, at or above the one the card put last held it at; for one a
	// note named, the version that card held it at, which the moderation's CUT listed.
	ListedVersion uint64 `json:"listed_version"`
	// The push version of the removal whose return read it; 0 for one a note named.
	Removal uint64 `json:"removal"`
	// The erasure whose moderation's note named it (the file's header's note row); nil for one a return found.
	NotedBy *Id `json:"noted_by,omitempty"`
}

// One announcement a directory admin's moderation took off a card, as its ERASE's sealed note names it
// (ErasureBody.announcement_ids).
type directoryModerationNote struct {
	erasureId      Id
	announcementId Id
}

// Whether the journal leaves announcementId out.
func (self *directoryCardWrittenDocument) moderated(announcementId Id) bool {
	return slices.ContainsFunc(self.Moderated, func(moderated *directoryCardModerated) bool {
		return moderated.AnnouncementId == announcementId
	})
}

// items less those the journal leaves out.
func (self *directoryCardWrittenDocument) withoutModerated(items []*protocol.Announcement) []*protocol.Announcement {
	kept := make([]*protocol.Announcement, 0, len(items))
	for _, item := range items {
		if !self.moderated(recordIdOf(item.GetAnnouncementId())) {
			kept = append(kept, item)
		}
	}
	return kept
}

// The ids of items the journal leaves out, in items' order.
func (self *directoryCardWrittenDocument) moderatedOf(items []*protocol.Announcement) []Id {
	ids := []Id{}
	for _, item := range items {
		if announcementId := recordIdOf(item.GetAnnouncementId()); self.moderated(announcementId) && !slices.Contains(ids, announcementId) {
			ids = append(ids, announcementId)
		}
	}
	return ids
}

// Journals what removal's return found moderated, by announcement id with the version listed, each once, keeping
// the newest itemCount; non-positive keeps every one.
func (self *directoryCardWrittenDocument) noteModerated(found map[Id]uint64, removal uint64, itemCount int) {
	for _, announcementId := range slices.SortedFunc(func(yield func(Id) bool) {
		for announcementId := range found {
			if !yield(announcementId) {
				return
			}
		}
	}, func(a Id, b Id) int { return a.Cmp(b) }) {
		if self.moderated(announcementId) {
			continue
		}
		self.Moderated = append(self.Moderated, &directoryCardModerated{
			AnnouncementId: announcementId, ListedVersion: found[announcementId], Removal: removal,
		})
	}
	self.keepNewestModerated(itemCount)
}

// Keeps the journal's newest itemCount; non-positive keeps every one.
func (self *directoryCardWrittenDocument) keepNewestModerated(itemCount int) {
	if 0 < itemCount && itemCount < len(self.Moderated) {
		self.Moderated = slices.Clone(self.Moderated[len(self.Moderated)-itemCount:])
	}
}

// Takes into the journal what kept, the document as the store holds it now, journals that this one does not: what a
// sync journaled since this one was read. kept's entries keep their order and this one's own follow, the newest
// itemCount kept; non-positive keeps every one.
func (self *directoryCardWrittenDocument) takeJournal(kept []*directoryCardModerated, itemCount int) {
	merged := slices.Clone(kept)
	for _, moderated := range self.Moderated {
		if !slices.ContainsFunc(merged, func(held *directoryCardModerated) bool { return held.AnnouncementId == moderated.AnnouncementId }) {
			merged = append(merged, moderated)
		}
	}
	self.Moderated = merged
	self.keepNewestModerated(itemCount)
}

// Journals at once each announcement notes name that the card this device put last holds (the file's header's note
// row), as a return's finds are, so every card after leaves it out whatever the erasure set lists by then. Called by
// a sync's judge of the erasure ref, which holds syncLock, so it takes the card writer's stateLock and never its
// writeLock. A journal the store does not keep is held for the document's next keep, and every read of the document
// meanwhile holds it too.
func (self *DirectoryClient) journalModerationNotes(notes []*directoryModerationNote) error {
	if len(notes) == 0 {
		return nil
	}
	settings := self.cardSettings()
	writer := self.cardWriter()
	err := func() error {
		writer.stateLock.Lock()
		defer writer.stateLock.Unlock()
		written, err := self.readCardWrittenWithLock(writer)
		if err != nil {
			return err
		}
		held := map[Id]uint64{}
		for _, item := range written.card(self.sidecarId).GetItems() {
			held[recordIdOf(item.GetAnnouncementId())] = item.GetVersion()
		}
		noted := []*directoryCardModerated{}
		for _, note := range notes {
			version, ok := held[note.announcementId]
			if !ok || written.moderated(note.announcementId) {
				// another sidecar's, or one this card never held, or journaled already
				continue
			}
			erasureId := note.erasureId
			moderated := &directoryCardModerated{AnnouncementId: note.announcementId, ListedVersion: version, NotedBy: &erasureId}
			written.Moderated = append(written.Moderated, moderated)
			noted = append(noted, moderated)
		}
		if len(noted) == 0 && len(writer.unkept) == 0 {
			return nil
		}
		written.keepNewestModerated(settings.ModeratedItemCount)
		if err := self.store.writeDocument(directoryCardWrittenName, written); err != nil {
			writer.unkept = append(writer.unkept, noted...)
			return err
		}
		writer.unkept = nil
		return nil
	}()
	if err != nil {
		self.log.Warningf("[directory]what a moderation's note names was not journaled: %s", err)
	}
	return err
}

// The items of the card this device put last that the cards ref's erasure set lists at or above the version that
// card held each at, with the version listed: what an erasure took (the file's header's read and moderated rows).
// Every item of that card is asked, handed again or not. ErrDirectoryCardReturnUnchecked where the check cannot be
// made.
func (self *DirectoryClient) cardModeratedAtReturn(ctx context.Context, written *directoryCardWrittenDocument) (map[Id]uint64, error) {
	found := map[Id]uint64{}
	held := written.card(self.sidecarId).GetItems()
	if len(held) == 0 {
		// this device's last card held nothing an erasure could have taken from it
		return found, nil
	}
	reader, ok := self.boundCards().(DirectoryCardsErasureSet)
	if !ok {
		return nil, fmt.Errorf("%w: no binding reads the erasure set", ErrDirectoryCardReturnUnchecked)
	}
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return nil, ErrDirectoryNone
	}
	admins, err := auth.DirectoryAdmins(auth.Pin())
	if err != nil {
		return nil, fmt.Errorf("%w: the directory's admins: %w", ErrDirectoryCardReturnUnchecked, err)
	}
	names := make([][]byte, 0, len(held))
	for _, item := range held {
		names = append(names, directoryIndexAnnouncementName(DirectoryAnnouncementKind(item.GetKind()), self.sidecarId, recordIdOf(item.GetAnnouncementId())))
	}
	versions, err := reader.CardsErasedVersions(ctx, directoryId, &DirectoryCardsErasedArgs{
		Names: names, IsAdmin: func(signerSidecarId Id) bool { return slices.Contains(admins, signerSidecarId) },
	})
	if err != nil {
		if errors.Is(err, ErrDirectoryCardReturnUnchecked) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrDirectoryCardReturnUnchecked, err)
	}
	if len(versions) != len(names) {
		return nil, fmt.Errorf("%w: %d versions for %d documents", ErrDirectoryCardReturnUnchecked, len(versions), len(names))
	}
	for index, item := range held {
		if item.GetVersion() <= versions[index] {
			found[recordIdOf(item.GetAnnouncementId())] = versions[index]
		}
	}
	return found, nil
}

// Whether this sidecar's card leaves announcementId out, an erasure having taken it (the file's header's writers
// row): what the run and worker writers ask before each write.
func (self *DirectoryClient) cardItemModerated(announcementId Id) (bool, error) {
	written, err := self.readCardWritten()
	if err != nil {
		return false, err
	}
	return written.moderated(announcementId), nil
}
