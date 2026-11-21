//go:build !ios_extension

// §15.7's erasure in a format-2 mailbox (D-MAIL-5, FI-5, FI-19, FS-78, FS-111, FS-112; §11.12's cut, closure and
// reconcile rows; §11.14's cut, epoch and erase rows; DESIGN-DETAILS 15.7's note; MAIL-M10-02): what the search index
// adds to mail_erase.go's order, through the index's eraser on the mailbox's ref (IndexEraser).
//
//	cut       before its first ERASE an erasure commits one CUT on the mailbox's ref listing its messages' documents:
//	          the doc_key of each chunk of each m/ path at the path's version (a message never changes, so it owes no
//	          re-entry). From there no index push built before it publishes them and every search masks them, with the
//	          index on or off. A batch, such as a month's trash shred, is one CUT. A set too full for it makes the CUT
//	          wait while pending erasures finish, and the first ERASE does not wait: the bodies go at once
//	documents a message's documents are one a 1 MiB chunk of its extracted text (§11.14's D4). A message whose bytes
//	          cannot outgrow one chunk under TextGrowthFactor is one document; a larger one is extracted as the index's
//	          writer extracted it, which counts them; one that cannot be read, and a deposit not yet consumed, is listed
//	          to the bound its size gives, at the version an ingest writes. Listing a doc_key the index holds nothing
//	          under costs only the set's room
//	note      the first ERASE's note carries each message's version and chunk count (mail_erase_note.go), so any
//	          admin's device rebuilds the documents once the bodies are gone, and commits a CUT that waited
//	journal   a device killed between its CUT and its first ERASE committed nothing a resume can read as mail's, so
//	          the eraser journals the erasure's id and messages on the device before the CUT and drops the entry at
//	          the first ERASE; its next erasure step runs a journaled erasure again under the same id (§11.12's
//	          reconcile row: only its own device's journal retries it). With no journal store that crash leaves a CUT
//	          no device finishes
//	parts     after the first ERASE the index's files go first: IndexEraser.Resume commits the CUT where it is missing,
//	          then rewrites each index file holding a listed document in CLOSURE and ERASE pairs, whose wait and finish
//	          are its own arithmetic (§11.13). Then mail's parts re-key each i/ segment (mail_erase_closure.go), the
//	          last one's ERASE completing the erasure where the index's rewrite left nothing unproven. An erasure with
//	          no i/ segment and no orphaned CLOSURE left ends with the index's rewrite: its last ERASE completes it,
//	          or, where it finds no index file to rewrite, its completion ERASE (IndexRewriteArgs.Completion; QD-1132).
//	          While the index's side waits, on a full set, an allowance or another device's 25 h, the i/ parts wait
//	          with it
//	resume    by role: the device whose first ERASE began the erasure at once, another admin's device ResumeAfter
//	          (25 h) after its CUT or last ERASE, any admin's once the eraser no longer administers the repo
//
// An ERASE that names only keys already gone is refused and commits nothing (evs's NOTHING_TO_ERASE), so complete
// rides an ERASE that destroys a key, or a completion ERASE (evs_erase_completion.go; QD-1137), flagged COMPLETION, which
// evs takes once a key of the erasure's ERASEs no completion named since. An erasure whose index rewrite is unproven
// (a history the store could not walk whole) ends with every key it could find destroyed and no complete, sending no
// completion: it stays rewriting, fail closed. A format-1 mailbox, which has neither this index nor a completion ERASE
// (COMPLETION is format 2's flag, QD-1137), reads an erasure with nothing left done on this device instead
// (mail_erase.go's settleFormat1), so only a format-2 one waits on evs's state to say so.
//
// On every leg but the extension's. The types here are used under MailEraser's lock.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
)

var (
	// An erasure whose CUT would list more documents than one erasure set entry is given (CutDocumentMaxCount): the
	// caller erases the messages in smaller batches. Nothing was destroyed.
	ErrMailEraseBatchTooLarge = errors.New("mail erasure of more documents than one CUT lists")
	// A format-2 mailbox's eraser could not reach the search index's eraser. Nothing was destroyed.
	ErrMailEraseIndexUnavailable = errors.New("mail erasure without the search index's eraser")
)

// What a format-2 mailbox's erasure asks of the search index's eraser on the mailbox's ref: *IndexEraser is one.
type mailIndexEraser interface {
	// The erasure's CUT; called again with nothing new it pushes nothing. ErrIndexErasureSetFull where the set cannot
	// hold it yet.
	Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error)
	// The CUT where it is missing, then the erasure's index files' rewrite, from evs's state.
	Resume(ctx context.Context, args *IndexResumeArgs) (*IndexResumeResult, error)
}

// The search index's side of one mail repo's erasures.
type mailEraseIndex struct {
	eraser mailIndexEraser
	// The doc_key of one chunk of an m/ path under the ref's K_ref, as every reader derives it.
	docKey func(path string, chunk uint32) ([indexIdByteCount]byte, error)
	// Extractor 1's bounds, which the chunk count follows.
	format *IndexFormatSettings
}

// The documents a CUT lists for messages: each chunk of each m/ path at its version. A message whose note named no
// document, a format-1 erasure's, lists none.
func (self *mailEraseIndex) documents(messages []mailErasedMessage) ([]*IndexCutDocument, error) {
	documents := []*IndexCutDocument{}
	for _, message := range messages {
		path := MailMessagePath(message.Month, message.MessageId)
		for chunk := uint32(0); chunk < message.ChunkCount; chunk += 1 {
			key, err := self.docKey(path, chunk)
			if err != nil {
				return nil, err
			}
			documents = append(documents, &IndexCutDocument{Key: key, Version: message.Version})
		}
	}
	return documents, nil
}

// Whether any of messages names a document: a format-2 erasure's.
func mailErasureDocumented(messages []mailErasedMessage) bool {
	return slices.ContainsFunc(messages, func(message mailErasedMessage) bool { return 0 < message.ChunkCount })
}

// The index's side of repo's erasures: the index's eraser over the mailbox's main ref, whose .ur-index/ holds its
// index, signing as this device, a set or settings version counting where authority says its signer administers the
// repo, and which erasures are complete read from the repo's erasure ref. It reads the repo's current key for K_ref.
func mailNewEraseIndex(ctx context.Context, repo *EvsRepo, args *MailEraserArgs, settings *MailEraseSettings) (*mailEraseIndex, error) {
	store := newIndexEvsStore(repo, nil, false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	kind, err := repo.repoKind()
	if err != nil {
		return nil, err
	}
	repoKey, err := repo.client.args.Gkm.CurrentRepoKey(ctx, repo.repoId)
	if err != nil {
		return nil, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	format := settings.IndexFormat
	if format == nil {
		format = DefaultIndexFormatSettings()
	}
	repoId := repo.repoId
	authority := args.Authority
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: store, eraseStore: store, repoId: repoId, refId: refId, repoKind: kind,
		isAdmin: func(file *indexFileVersion) bool {
			return authority != nil && authority.Erases(repoId, file.signerSidecarId)
		},
		format: format, settings: settings.Index, eraser: repo.client.args.Identity().SidecarId,
		complete: func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
			erasures, err := repo.ReadErasures(ctx, 0)
			if err != nil {
				return nil, err
			}
			complete := map[Id]bool{}
			for _, erasure := range erasures {
				if id, ended, applies := erasure.completionState(); applies {
					complete[id] = ended
				}
			}
			return complete, nil
		},
		events: args.Progress, clock: repo.client.clock, log: repo.client.log,
	})
	if err != nil {
		return nil, err
	}
	return &mailEraseIndex{
		eraser: eraser,
		docKey: func(path string, chunk uint32) ([indexIdByteCount]byte, error) {
			return indexDocKey(refKey, refId, []byte(path), chunk)
		},
		format: format,
	}, nil
}

// How many chunk documents extractor 1 makes of the message at path, as the index's in-ref writer counts them: one
// past the highest chunk it emits, a chunk D6 skips included.
func mailIndexChunkCount(path string, content []byte, format *IndexFormatSettings) (uint32, error) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return 0, err
	}
	count := uint32(0)
	stream := indexExtractMailStream(&indexStreamArgs{
		template:   &IndexDocument{Kind: IndexDocMail, Name: []byte(path), Version: 1},
		byteCount:  uint64(len(content)),
		normalizer: normalizer,
		settings:   format,
		emit: func(document *indexStreamDocument) error {
			count = max(count, document.chunk+1)
			return nil
		},
	})
	blockByteCount := max(format.ExtractReadByteCount, 1)
	for offset := 0; offset < len(content); offset += blockByteCount {
		if _, err := stream.Write(content[offset:min(len(content), offset+blockByteCount)]); err != nil {
			return 0, err
		}
	}
	if err := stream.Close(); err != nil {
		return 0, err
	}
	return max(count, 1), nil
}

// The most chunk documents a message of byteCount bytes gives: its extracted text is at most growthFactor times its
// bytes, one document a ChunkByteCount of it, and one for an empty text.
func mailIndexChunkBound(byteCount uint64, growthFactor int, format *IndexFormatSettings) uint32 {
	chunkByteCount := uint64(max(format.ChunkByteCount, 1))
	growth := uint64(max(growthFactor, 1))
	// A deposit's padded size comes from its signer. An oversized claim must exceed the CUT budget.
	if math.MaxUint64/growth < byteCount {
		return math.MaxUint32
	}
	textByteCount := byteCount * growth
	if textByteCount == 0 {
		return 1
	}
	return uint32(min((textByteCount-1)/chunkByteCount+1, math.MaxUint32))
}

// The index's side of this repo's erasures, opened at its first use: nil in a format-1 mailbox, which has none.
func (self *MailEraser) indexOf(ctx context.Context) (*mailEraseIndex, error) {
	if self.index != nil {
		return self.index, nil
	}
	if self.indexOpen == nil {
		return nil, nil
	}
	index, err := self.indexOpen(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailEraseIndexUnavailable, err)
	}
	self.index = index
	return index, nil
}

// The version and chunk count a message's documents are listed at: see the file header's documents row. version is
// the m/ path's newest standing version, 0 where none stands, and depositByteCount its unconsumed deposit's size.
func (self *MailEraser) documentOf(ctx context.Context, index *mailEraseIndex, path string, version uint64, depositByteCount uint64) (uint64, uint32, error) {
	growthFactor := self.settings.TextGrowthFactor
	if version == 0 {
		// no m/ file yet: the version an ingest's create writes, to the bound the deposit's size gives
		return 1, mailIndexChunkBound(depositByteCount, growthFactor, index.format), nil
	}
	content, _, err := self.store.Read(ctx, path, self.settings.MessageMaxByteCount)
	switch {
	case errors.Is(err, ErrMailStoreTooLarge), errors.Is(err, ErrEvsObjectMissing), errors.Is(err, ErrEvsSealInvalid),
		errors.Is(err, ErrEvsErased), errors.Is(err, ErrEvsEntryRefused), errors.Is(err, ErrEvsPathAbsent):
		// not readable here, its key erased among the rest: every chunk a message at the read's bound could have
		return version, mailIndexChunkBound(uint64(max(self.settings.MessageMaxByteCount, 0)), growthFactor, index.format), nil
	case err != nil:
		return 0, 0, err
	}
	bound := mailIndexChunkBound(uint64(len(content)), growthFactor, index.format)
	if bound <= 1 {
		return version, 1, nil
	}
	count, err := mailIndexChunkCount(path, content, index.format)
	if err != nil {
		return version, bound, nil
	}
	return version, min(count, bound), nil
}

// Commits the erasure's CUT, before its first ERASE: true once the set lists it, false where a full set makes it
// wait, which holds back no ERASE.
func (self *MailEraser) cut(ctx context.Context, index *mailEraseIndex, erasureId Id, messages []mailErasedMessage) (bool, error) {
	documents, err := index.documents(messages)
	if err != nil {
		return false, err
	}
	testHookBarrier("mail.erase.cut.before", "")
	_, err = index.eraser.Cut(ctx, &IndexCutArgs{ErasureId: erasureId, Documents: documents})
	testHookBarrier("mail.erase.cut.after", "")
	if errors.Is(err, ErrIndexErasureSetFull) {
		return false, nil
	}
	return err == nil, err
}

// Whether a CUT's error says evs committed nothing of it: every build refused, or a refusal other than an unknown
// outcome. Any other error may have left the CUT committed.
func mailEraseCutRefused(err error) bool {
	if errors.Is(err, errIndexCutAttempts) || errors.Is(err, errIndexCutArgs) {
		return true
	}
	if _, refused := indexRefusalOf(err); refused {
		return !isIndexRefusal(err, indexRefusalOutcomeUnknown)
	}
	return false
}

// The index's part of an erasure after its first ERASE: the CUT where it is missing, then its index files' rewrite,
// whose last ERASE says complete where last says no i/ segment and no orphaned CLOSURE is left to carry it. True where
// the erasure's call ends here: done, waiting, or not this device's yet; erasure says which.
func (self *MailEraser) indexParts(ctx context.Context, index *mailEraseIndex, erasure *MailErasure, messages []mailErasedMessage, segments []*mailEraseSegment, role IndexResumeRole, last bool) (bool, error) {
	documents, err := index.documents(messages)
	if err != nil {
		erasure.State = MailErasureRewriting
		return true, err
	}
	segmentsLeft := func() {
		erasure.SegmentsLeft, erasure.BytesLeft = len(segments), 0
		for _, segment := range segments {
			erasure.BytesLeft += segment.byteCount
		}
	}
	testHookBarrier("mail.erase.index.before", "")
	// with nothing left after it, a rewrite that finds no file to rewrite ends the erasure by a completion ERASE
	resumed, err := index.eraser.Resume(ctx, &IndexResumeArgs{
		ErasureId: erasure.ErasureId, Role: role, Documents: documents, Complete: last, Completion: last,
	})
	testHookBarrier("mail.erase.index.after", "")
	switch {
	case errors.Is(err, ErrIndexErasureSetFull):
		// the CUT waits while pending erasures finish; the bodies are gone already
		segmentsLeft()
		erasure.State = MailErasureWaiting
		erasure.NextTry = self.clock.Now().Add(self.settings.CutRetryInterval)
		return true, nil
	case err != nil:
		erasure.State = MailErasureRewriting
		return true, err
	case resumed == nil:
		erasure.State = MailErasureRewriting
		return true, ErrMailEraseIndexUnavailable
	case !resumed.NotBefore.IsZero():
		// another device's erasure, which this one takes over only from then
		segmentsLeft()
		erasure.State = MailErasureRewriting
		erasure.NextTry = resumed.NotBefore
		return true, nil
	}
	erasure.Fenced = true
	if resumed.Rewrite == nil || resumed.Rewrite.Erasure == nil {
		erasure.State = MailErasureRewriting
		return true, ErrMailEraseIndexUnavailable
	}
	erasure.Unproven = resumed.Rewrite.Unproven
	switch standing := resumed.Rewrite.Erasure; standing.State {
	case SidecarErasureDone:
		*erasure = MailErasure{ErasureId: erasure.ErasureId, MessageIds: erasure.MessageIds, State: MailErasureDone, Fenced: true}
		return true, nil
	case SidecarErasureWaiting:
		// the wait's arithmetic is the index's (§11.13); the i/ segments follow its last pair
		segmentsLeft()
		erasure.State = MailErasureWaiting
		erasure.IndexObjectsLeft, erasure.IndexBytesLeft = standing.ObjectsLeft, standing.BytesLeft
		erasure.NextTry, erasure.Finish = standing.NextTry, standing.Finish
		if !erasure.Finish.IsZero() && 0 < erasure.BytesLeft {
			if finish := mailEraseFinish(erasure.Finish, erasure.BytesLeft, self.settings.ClosureFloorByteCountPerDay); !finish.IsZero() {
				erasure.Finish = finish
			}
		}
		return true, nil
	}
	return false, nil
}

// Who this device is to an erasure its eraser began (§11.12's reconcile row): the eraser itself, another admin's
// device while the eraser still administers the repo, which waits ResumeAfter, or any admin's once it does not.
func (self *MailEraser) resumeRole(eraserId Id) IndexResumeRole {
	switch {
	case eraserId == self.sidecarId:
		return IndexResumeEraser
	case self.authority != nil && eraserId != (Id{}) && !self.authority.Erases(self.repoId, eraserId):
		return IndexResumeAny
	}
	return IndexResumeMember
}

// A journaled erasure's file name under the journal's directory.
const mailEraseJournalPrefix = "erase-"

// One erasure the journal holds: begun on this device, its first ERASE not yet known to have committed.
type mailEraseJournaled struct {
	ErasureId  Id
	Month      MailYearMonth
	MessageIds []Id
}

// A journaled erasure as its file holds it.
type mailEraseJournalFile struct {
	Month      string   `json:"month"`
	MessageIds []string `json:"message_ids"`
}

// The device's journal of erasures between their CUT and their first ERASE: see the file header's journal row. A nil
// store journals nothing.
type mailEraseJournal struct {
	store        SidecarStore
	maxByteCount int64
}

// Records the erasure before its CUT, durably.
func (self *mailEraseJournal) begin(erasureId Id, month MailYearMonth, messageIds []Id) error {
	if self == nil || self.store == nil {
		return nil
	}
	file := &mailEraseJournalFile{Month: month.String()}
	for _, messageId := range messageIds {
		file.MessageIds = append(file.MessageIds, messageId.String())
	}
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if self.maxByteCount < int64(len(data)) {
		return ErrMailEraseBatchTooLarge
	}
	writer, err := self.store.Create(mailEraseJournalPrefix + erasureId.String())
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Drops the erasure: its first ERASE committed, or it never began.
func (self *mailEraseJournal) done(erasureId Id) error {
	if self == nil || self.store == nil {
		return nil
	}
	return self.store.Remove(mailEraseJournalPrefix + erasureId.String())
}

// The erasures the journal holds, by file name. A file that does not read back as one is dropped: it names nothing a
// resume could erase.
func (self *mailEraseJournal) pending() ([]*mailEraseJournaled, error) {
	if self == nil || self.store == nil {
		return nil, nil
	}
	entries, err := self.store.List(mailEraseJournalPrefix)
	if err != nil {
		return nil, err
	}
	pending := []*mailEraseJournaled{}
	for _, entry := range entries {
		journaled, ok := self.read(entry.Name)
		if !ok {
			if err := self.store.Remove(entry.Name); err != nil {
				return nil, err
			}
			continue
		}
		pending = append(pending, journaled)
	}
	return pending, nil
}

// One journaled erasure read back, false for a file of another shape.
func (self *mailEraseJournal) read(name string) (*mailEraseJournaled, bool) {
	erasureId, err := ParseId(strings.TrimPrefix(name, mailEraseJournalPrefix))
	if err != nil || erasureId == (Id{}) {
		return nil, false
	}
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, false
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, self.maxByteCount+1))
	if err != nil || self.maxByteCount < int64(len(data)) {
		return nil, false
	}
	file := &mailEraseJournalFile{}
	if json.Unmarshal(data, file) != nil {
		return nil, false
	}
	month, ok := ParseMailYearMonth(file.Month)
	if !ok || len(file.MessageIds) == 0 {
		return nil, false
	}
	journaled := &mailEraseJournaled{ErasureId: erasureId, Month: month}
	for _, text := range file.MessageIds {
		messageId, err := ParseId(text)
		if err != nil {
			return nil, false
		}
		journaled.MessageIds = append(journaled.MessageIds, messageId)
	}
	return journaled, true
}

// Runs each journaled erasure again under its id: one whose first ERASE committed is dropped from the journal, and
// one whose messages are gone began nothing. The first that fails, or does not end done, ends the pass.
func (self *MailEraser) resumeJournaled(ctx context.Context, index *mailEraseIndex) ([]*MailErasure, error) {
	pending, err := self.journal.pending()
	if err != nil || len(pending) == 0 {
		return nil, err
	}
	committed, err := self.store.Erasures(ctx, 0)
	if err != nil {
		return nil, err
	}
	resumed := []*MailErasure{}
	for _, journaled := range pending {
		began := slices.ContainsFunc(committed, func(erasure *EvsErasure) bool { return erasure.ErasureId == journaled.ErasureId })
		fresh := []Id{}
		for _, messageId := range journaled.MessageIds {
			if _, erased := self.erased.erased(messageId); !erased && !slices.Contains(fresh, messageId) {
				fresh = append(fresh, messageId)
			}
		}
		if began || len(fresh) == 0 {
			// its first ERASE is in evs's state, which Resume reads, or another erasure took its messages
			if err := self.journal.done(journaled.ErasureId); err != nil {
				return resumed, err
			}
			continue
		}
		erasure, err := self.begin(ctx, journaled.ErasureId, journaled.Month, fresh, index)
		if errors.Is(err, ErrMailMessageAbsent) {
			if err := self.journal.done(journaled.ErasureId); err != nil {
				return resumed, err
			}
			continue
		}
		if erasure != nil {
			resumed = append(resumed, erasure)
		}
		if err != nil || erasure == nil || erasure.State != MailErasureDone {
			return resumed, err
		}
	}
	return resumed, nil
}
