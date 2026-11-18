//go:build !ios_extension

// The team directory's index (§16.11's Index and search block; §11.14's directory, version and reproduce rows;
// RECORD.md 7.1 and 7.2's D rows; R-MCP-13, R-MCP-16, D-MCP-31, D-EVS-61, I-19, I-20, FS-86, FS-88; RECORD-M10-04):
// what the directory gives its repo's index through IndexDocumentSource, what a card's push carries of it, how a
// reader derives a card writer's head, and the folded view behind search_agents.
//
//	documents  one per announcement, derived, named a/ || writer_sidecar_id || announcement_id for a run or worker
//	           item and a/ || announcement_id for a repo item, each id as 32 lowercase hex characters, its version the
//	           Announcement's, from the card or repo file holding it, on the cards ref's own index; M6's announce
//	           entries fold into the document of the same name on their stream's ref; one per other stream entry
//	           (ask, answer, check, note, request, decision, erasure_request), doc kind record, named by its path
//	fields     4 a run's title or a repo's display name; 5 prose (description, service descriptions, claim texts, the
//	           handoff's note), then the identifier values: the member label, which directory.proto carries for the
//	           index, harness or harnesses, host label, service names, topics and claim targets, one a line; 6 run,
//	           worker or repo, or the entry's kind; 7 sidecar_id, 8 agent_id, 10 run_id, 11 member_id and 14 repo_id in lowercase hex; 9
//	           the agent label, a worker's labels joined by one space; 12 project; 13 branch; 15 state: active, ended
//	           or handed_off, a request's pending, a decision's approved, denied or cancelled. Tainted and private
//	           are the row's flag bits, started and expires its times in seconds
//	entries    an entry's 4 and 5 are RECORD.md 7.2's; 9 and 11 to 14 come from its run's announcement at writing: the
//	           newest announce entry of the run below it in its own stream, else the item its writer's card holds
//	           now, else empty
//	versions   a card version's entries are a function of that version and the one it replaces (card change): an item
//	           whose Announcement.version rose, or that is new, is a full entry; a renewal, which keeps the version,
//	           is none; an item left out is a tombstone at its version + 1, a withdrawal, unless it was ended or
//	           handed off, or was active and past its expiry by the stale 24 h at the card's written_millis, when it
//	           is none; a removed card tombstones its active items. A repo file's item is a full entry while it is no
//	           private marker; a marker over an announcement, or the file's removal, is a tombstone, a revocation
//	writes     a card's and a repo file's entries ride the push that writes the file: the in-ref writer
//	           (evs_index_writer.go) asks enterDirectory for every d/ and r/ write of a directory repo, and a notice
//	           is no document. Stream entries ride ur/index, by companion pushes, at the cadence the index sets
//	reproduce  a reader keeps, for each file version it accepts, the entries that version's push carries
//	           (indexAccepted), and derives the writer's head from them and the writer's files at the push's base
//	           (indexDeriveHead, on IndexReproducer.DeriveHead): equal, nothing is fetched; unequal, the head is
//	           fetched and index_mismatch names the push's signer; lacking the derivation or a base file, the head is
//	           fetched and nothing raised
//	rebuild    a build, a rebuild or a backfill takes each announcement from its file as it stands, renewed expiry and
//	           all (DirectoryIndexCardsSource), so a check by rebuild of the cards ref's index compares an announcement's
//	           row less its expires, its other bytes, its keys and its version matching (QD-1067); no such check of
//	           derived documents is built yet (evs_index_check_text.go leaves them unjudged)
//	settings   on by kind: the index refuses off for this repo and a window outside 7 to 90 days, 7 where none is
//	           set (evs_index_bucket.go's rule for the kind); ur admin directory --window writes it, a directory
//	           admin's confirmed act, from format 2 (directory_admin.go's SetDirectoryIndexWindow); searchable_days
//	           is retention's, 90 by default, 7 to 400 where an admin sets it
//	roll-up    the index's own schedule (indexer_search.go) over the kind's 7-day window: weekly, by the directory's
//	           network-scope search indexer, else the first writer after expiry
//	agents     search_agents reads run announcements from the index, whose rows hold an item's state and expiry as
//	           its last content change wrote them, since a renewal writes no entry; SearchAgentsFold reads each such
//	           hit at its item's state and expiry in this copy's fold, one hit an announcement, so active means an
//	           unexpired item in state active now
//
// A document is a function of its announcement, or of its entry and its run's announcement, so every device writes the
// same bytes for one (§11.14's determinism); nothing here reads a clock or a device's own state into a document.
// directory_list stays a filter over the folded state (directory_view.go). Nothing of a search reaches evs (I-19): this
// file makes no request, and the window write names only settings. Titles, labels and prose are this device's plaintext
// and go into no log or error (I-13). No key is created, derived or unwrapped here.
//
// Safe for concurrent use: the functions read only their arguments, and the client's index part locks its own state.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The registered prefix of an announcement document's name (§11.14's key row), and the client's part.
const (
	directoryIndexAnnouncementPrefix = "a/"
	directoryIndexPartName           = "index"
)

// Field 6's and field 15's values (§16.11's fields row; RECORD.md 7.2's D rows). Identifiers.
const (
	directoryIndexKindRun    = "run"
	directoryIndexKindWorker = "worker"
	directoryIndexKindRepo   = "repo"

	directoryIndexStateActive    = "active"
	directoryIndexStateEnded     = "ended"
	directoryIndexStateHandedOff = "handed_off"
	directoryIndexStatePending   = "pending"
	directoryIndexStateApproved  = "approved"
	directoryIndexStateDenied    = "denied"
	directoryIndexStateCancelled = "cancelled"
)

var (
	// A window the team directory's index does not take: outside its days.
	ErrDirectoryIndexWindow = errors.New("directory index window outside its days")
	// A searchable_days the team directory does not take: outside its days.
	ErrDirectoryIndexSearchable = errors.New("directory searchable_days outside its days")
	// Nothing bound writes the directory's index settings on this device: nothing was signed.
	ErrDirectoryIndexUnbound = errors.New("directory index settings unbound")
	// A source or a derivation asked without what it reads.
	errDirectoryIndexArgs = errors.New("directory index source without its copy, stream or settings")
)

// What the directory's index holds to. The window's days and the documents' bounds are the format's, which every
// device shares, so a deployment changes none on one side alone.
type DirectoryIndexSettings struct {
	// The index window where no settings name one: 7 days, the index's own default for the kind.
	WindowDays uint32
	// The fewest and the most days a window takes: 7 and 90.
	WindowMinDays uint32
	WindowMaxDays uint32
	// The searchable_days an admin's retention policy takes at the fewest and the most: 7 and 400. The default, 90,
	// is retention's (RecordRetentionSettings.DirectorySearchableDays).
	SearchableMinDays uint32
	SearchableMaxDays uint32
	// The accepted file versions whose index entries a reader keeps for deriving their writers' heads: 4,096, a
	// Team's cards between two index syncs with room. Past it the oldest go, and their heads are fetched, raising
	// nothing. Non-positive keeps none.
	DerivationCount int
	// Record extractor 1's bounds, for stream entries' titles.
	Record *IndexRecordSettings
	// The cards' and repo files' caps and times, by which a file decodes and an item reads lapsed.
	Cards *DirectoryCardSettings
}

// §16.11's values, the index's own for the window. A fresh value each call.
func DefaultDirectoryIndexSettings() *DirectoryIndexSettings {
	return &DirectoryIndexSettings{
		WindowDays:        indexDirectoryDefaultWindowDays,
		WindowMinDays:     indexMinWindowDays,
		WindowMaxDays:     indexDirectoryMaxWindowDays,
		SearchableMinDays: 7,
		SearchableMaxDays: 400,
		DerivationCount:   4096,
		Record:            DefaultIndexRecordSettings(),
		Cards:             DefaultDirectoryCardSettings(),
	}
}

// Refuses settings no index can run on.
func (self *DirectoryIndexSettings) check() error {
	if self.WindowMinDays == 0 || self.WindowMaxDays < self.WindowMinDays || self.WindowDays < self.WindowMinDays ||
		self.WindowMaxDays < self.WindowDays || self.SearchableMinDays == 0 || self.SearchableMaxDays < self.SearchableMinDays ||
		self.Record == nil || self.Cards == nil {
		return fmt.Errorf("%w: the directory index's days and bounds", errInvalidSettings)
	}
	return self.Record.check()
}

// Refuses a window outside the directory's days. 0 is no window: the command names one.
func (self *DirectoryIndexSettings) CheckWindowDays(windowDays uint32) error {
	if windowDays < self.WindowMinDays || self.WindowMaxDays < windowDays {
		return fmt.Errorf("%w: %d, of %d to %d", ErrDirectoryIndexWindow, windowDays, self.WindowMinDays, self.WindowMaxDays)
	}
	return nil
}

// Refuses a searchable_days outside the directory's days.
func (self *DirectoryIndexSettings) CheckSearchableDays(searchableDays uint32) error {
	if searchableDays < self.SearchableMinDays || self.SearchableMaxDays < searchableDays {
		return fmt.Errorf("%w: %d, of %d to %d", ErrDirectoryIndexSearchable, searchableDays, self.SearchableMinDays, self.SearchableMaxDays)
	}
	return nil
}

// Whether path is a file of the cards ref whose items are documents: a card, d/<h>/<sid>, or a repo file,
// r/<h>/<repo>. A notice and anything else is none.
func directoryIndexPath(path string) bool {
	if _, ok := directoryCardPathSidecar(path); ok {
		return true
	}
	_, ok := directoryRepoPathRepo(path)
	return ok
}

// An announcement document's name: a/ || writer || announcement_id for a run or worker item, a/ || announcement_id
// for a repo item, which folds across its admins.
func directoryIndexAnnouncementName(kind DirectoryAnnouncementKind, writerSidecarId Id, announcementId Id) []byte {
	if kind == DirectoryAnnouncementKindRepo {
		return []byte(directoryIndexAnnouncementPrefix + directoryIdText(announcementId))
	}
	return []byte(directoryIndexAnnouncementPrefix + directoryIdText(writerSidecarId) + directoryIdText(announcementId))
}

// Field 6 of an announcement, "" for a kind §16.11 does not name.
func directoryIndexKindName(kind DirectoryAnnouncementKind) string {
	switch kind {
	case DirectoryAnnouncementKindRun:
		return directoryIndexKindRun
	case DirectoryAnnouncementKindWorker:
		return directoryIndexKindWorker
	case DirectoryAnnouncementKindRepo:
		return directoryIndexKindRepo
	}
	return ""
}

// Field 15 of an announcement, "" for a state that is no document's: withdrawn, and one §16.11 does not name.
func directoryIndexStateName(state DirectoryAnnouncementState) string {
	switch state {
	case DirectoryAnnouncementStateActive:
		return directoryIndexStateActive
	case DirectoryAnnouncementStateEnded:
		return directoryIndexStateEnded
	case DirectoryAnnouncementStateHandedOff:
		return directoryIndexStateHandedOff
	}
	return ""
}

// A time of an announcement in the row's seconds, 0 for none.
func directoryIndexSeconds(millis int64) uint64 {
	if millis <= 0 {
		return 0
	}
	return uint64(millis / 1000)
}

// An id field in lowercase hex, empty for none or for bytes that are no id.
func directoryIndexHex(id []byte) string {
	if len(id) != len(Id{}) {
		return ""
	}
	return indexRecordHex(id)
}

// Whether item indexes as a document: a run, worker or repo item in a state that shows, and no private marker of a
// repo, which holds only who, repo_id, repo_kind and requests.
func directoryIndexShows(item *protocol.Announcement) bool {
	kind := DirectoryAnnouncementKind(item.GetKind())
	if directoryIndexKindName(kind) == "" || directoryIndexStateName(DirectoryAnnouncementState(item.GetState())) == "" {
		return false
	}
	return kind != DirectoryAnnouncementKindRepo || !item.GetWhere().GetPrivate()
}

// The document of item as writerSidecarId's card, repo file or announce entry holds it: see the file header's fields
// row. A function of the item alone but for its name, which a run's or worker's writer joins.
func directoryIndexAnnouncementDocument(item *protocol.Announcement, writerSidecarId Id) (*IndexDocument, error) {
	kind := DirectoryAnnouncementKind(item.GetKind())
	if !directoryIndexShows(item) || len(item.GetAnnouncementId()) != len(Id{}) {
		return nil, indexMalformed("an announcement that is no document")
	}
	who := item.GetWho()
	what := item.GetWhat()
	where := item.GetWhere()
	// the item's bytes less the times a renewal moves and the pad its carrier sets, so neither changes the document
	sized := proto.Clone(item).(*protocol.Announcement)
	sized.RenewedMillis, sized.ExpiresMillis, sized.Pad = 0, 0, nil
	document := &IndexDocument{
		Kind:           IndexDocDerived,
		Name:           directoryIndexAnnouncementName(kind, writerSidecarId, recordIdOf(item.GetAnnouncementId())),
		Version:        item.GetVersion(),
		ByteCount:      uint64(proto.Size(sized)),
		Tainted:        item.GetTainted(),
		Private:        where.GetPrivate(),
		StartedSeconds: directoryIndexSeconds(item.GetStartedMillis()),
		ExpiresSeconds: directoryIndexSeconds(item.GetExpiresMillis()),
	}
	// prose first, then the identifier values, each in its message's order
	lines := []string{what.GetDescription()}
	for _, service := range what.GetServices() {
		lines = append(lines, service.GetDescription())
	}
	for _, claim := range item.GetClaims() {
		lines = append(lines, claim.GetText())
	}
	lines = append(lines, item.GetHandoff().GetNote(), who.GetMemberLabel(), who.GetHarness())
	lines = append(lines, what.GetHarnesses()...)
	lines = append(lines, where.GetHostLabel())
	for _, service := range what.GetServices() {
		lines = append(lines, service.GetName())
	}
	lines = append(lines, what.GetTopics()...)
	for _, claim := range item.GetClaims() {
		lines = append(lines, claim.GetTargets()...)
	}
	agentLabel := who.GetAgentLabel()
	if kind == DirectoryAnnouncementKindWorker {
		agentLabel = strings.Join(what.GetAgentLabels(), " ")
	}
	set := func(number int, value string) {
		document.Fields[number] = []byte(indexRowText(value))
	}
	if kind != DirectoryAnnouncementKindWorker {
		set(indexFieldTitle, what.GetTitle())
	}
	set(indexFieldBody, indexRecordLines(lines...))
	set(searchFieldKind, directoryIndexKindName(kind))
	set(searchFieldWriter, directoryIndexHex(who.GetSidecarId()))
	set(searchFieldAgentId, directoryIndexHex(who.GetAgentId()))
	set(searchFieldAgentLabel, agentLabel)
	set(searchFieldRunId, directoryIndexHex(what.GetRunId()))
	set(searchFieldMemberId, directoryIndexHex(who.GetMemberId()))
	set(searchFieldProject, where.GetProject())
	set(searchFieldBranch, where.GetBranch())
	set(searchFieldRepoId, directoryIndexHex(where.GetRepoId()))
	set(searchFieldState, directoryIndexStateName(DirectoryAnnouncementState(item.GetState())))
	if err := indexDirectoryFieldRegistry().check(document); err != nil {
		return nil, err
	}
	return document, nil
}

// A tombstone of the announcement document at version.
func directoryIndexTombstone(kind DirectoryAnnouncementKind, writerSidecarId Id, item *protocol.Announcement, version uint64) *indexDeriveDocument {
	return &indexDeriveDocument{
		document: &IndexDocument{
			Kind:    IndexDocDerived,
			Name:    directoryIndexAnnouncementName(kind, writerSidecarId, recordIdOf(item.GetAnnouncementId())),
			Version: version,
		},
		tombstone: true,
	}
}

// The index entries the card version next carries over previous, the version of the same path it replaces, each nil
// for none (a first version, a removal): see the file header's versions row. The order is the card's, then the
// replaced card's for what next leaves out, so every device enters them alike.
func directoryIndexCardChange(sidecarId Id, previous *protocol.DirectoryCard, next *protocol.DirectoryCard, settings *DirectoryIndexSettings) ([]*indexDeriveDocument, error) {
	held := map[Id]*protocol.Announcement{}
	for _, item := range previous.GetItems() {
		if directoryIndexShows(item) {
			held[recordIdOf(item.GetAnnouncementId())] = item
		}
	}
	derived := []*indexDeriveDocument{}
	carried := map[Id]bool{}
	for _, item := range next.GetItems() {
		announcementId := recordIdOf(item.GetAnnouncementId())
		carried[announcementId] = true
		replaced := held[announcementId]
		kind := DirectoryAnnouncementKind(item.GetKind())
		if !directoryIndexShows(item) {
			// a card says a withdrawal by leaving the item out; one that carries it withdrawn says the same
			if replaced != nil {
				derived = append(derived, directoryIndexTombstone(kind, sidecarId, item, max(item.GetVersion(), replaced.GetVersion()+1)))
			}
			continue
		}
		if replaced != nil && item.GetVersion() <= replaced.GetVersion() {
			// a renewal keeps the version and writes no index entry
			continue
		}
		document, err := directoryIndexAnnouncementDocument(item, sidecarId)
		if err != nil {
			return nil, err
		}
		derived = append(derived, &indexDeriveDocument{document: document})
	}
	for _, item := range previous.GetItems() {
		announcementId := recordIdOf(item.GetAnnouncementId())
		if carried[announcementId] || held[announcementId] != item {
			continue
		}
		if DirectoryAnnouncementState(item.GetState()) != DirectoryAnnouncementStateActive {
			// an ended or handed-off item dropped from its card writes no tombstone
			continue
		}
		if next != nil && item.GetExpiresMillis()+settings.Cards.StaleShowTime.Milliseconds() <= next.GetWrittenMillis() {
			// an active item past its expiry and its stale time lapsed: its row already reads expired
			continue
		}
		derived = append(derived, directoryIndexTombstone(DirectoryAnnouncementKind(item.GetKind()), sidecarId, item, item.GetVersion()+1))
	}
	return derived, nil
}

// The index entries the repo file's item next carries over previous, each nil for none: a full entry for an
// announcement above what it replaces, a tombstone for a private marker over an announcement or for the file's
// removal, and nothing for a marker where no document stood.
func directoryIndexRepoFileChange(previous *protocol.Announcement, next *protocol.Announcement) ([]*indexDeriveDocument, error) {
	stood := previous != nil && directoryIndexShows(previous)
	if next != nil && directoryIndexShows(next) {
		if stood && next.GetVersion() <= previous.GetVersion() {
			return nil, nil
		}
		document, err := directoryIndexAnnouncementDocument(next, Id{})
		if err != nil {
			return nil, err
		}
		return []*indexDeriveDocument{{document: document}}, nil
	}
	if !stood {
		return nil, nil
	}
	// a revocation's marker, at its own version, or the repo's deletion
	version := previous.GetVersion() + 1
	if next != nil {
		version = max(version, next.GetVersion())
	}
	return []*indexDeriveDocument{directoryIndexTombstone(DirectoryAnnouncementKindRepo, Id{}, previous, version)}, nil
}

// The index entries a write of path carries, from the content it replaces and the content it writes, each nil for
// none: a card's or a repo file's, and nothing for any other path. A replaced content that does not decode under the
// file's own rules is no version a reader accepted, and reads as none.
func directoryIndexFileChange(path string, previousContent []byte, nextContent []byte, settings *DirectoryIndexSettings) ([]*indexDeriveDocument, error) {
	if sidecarId, ok := directoryCardPathSidecar(path); ok {
		var previous, next *protocol.DirectoryCard
		if previousContent != nil {
			if stored, err := DirectoryDecodeCard(previousContent, settings.Cards); err == nil {
				previous = stored.Card
			}
		}
		if nextContent != nil {
			stored, err := DirectoryDecodeCard(nextContent, settings.Cards)
			if err != nil {
				return nil, err
			}
			next = stored.Card
		}
		return directoryIndexCardChange(sidecarId, previous, next, settings)
	}
	if _, ok := directoryRepoPathRepo(path); ok {
		var previous, next *protocol.Announcement
		if previousContent != nil {
			if stored, err := DirectoryDecodeRepoFile(previousContent, settings.Cards); err == nil {
				previous = stored.File.GetItem()
			}
		}
		if nextContent != nil {
			stored, err := DirectoryDecodeRepoFile(nextContent, settings.Cards)
			if err != nil {
				return nil, err
			}
			next = stored.File.GetItem()
		}
		return directoryIndexRepoFileChange(previous, next)
	}
	return nil, nil
}

// Enters the documents a card's or repo file's write carries (§16.11's writes row): the entries directoryIndexFileChange
// gives for the content the plan writes over the content it replaces. False where the replaced version reads from
// neither the directory's copy nor evs, so the push writes no entry and a backfill covers it. A write whose content
// its own rules refuse carries no entry: no reader accepts the version, so none derives a head from it.
func (self *indexWriterDocuments) enterDirectory(ctx context.Context, change *indexWriterChange) (bool, error) {
	planned := change.planned
	settings := DefaultDirectoryIndexSettings()
	var nextContent []byte
	if !planned.Remove {
		content := change.write.Content
		if content == nil || int64(settings.Cards.CardFileByteCount) < content.Size() {
			return true, nil
		}
		nextContent = make([]byte, content.Size())
		if _, err := content.ReadAt(nextContent, 0); err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
	}
	var previousContent []byte
	if planned.BaseEntryVersion != 0 {
		held := false
		if replaced := self.writer.args.directoryReplaced; replaced != nil {
			previousContent, held = replaced(self.plan.RepoId, planned.Path, planned.BaseEntryVersion)
		}
		if !held {
			previous, err := self.readReplaced(ctx, planned)
			if err != nil {
				self.writer.args.log.Infof("[index]a replaced directory file did not read: the push goes unindexed")
				return false, nil
			}
			defer previous.close()
			previousContent = make([]byte, previous.Size())
			if _, err := previous.ReadAt(previousContent, 0); err != nil && !errors.Is(err, io.EOF) {
				return false, err
			}
		}
	}
	derived, err := directoryIndexFileChange(planned.Path, previousContent, nextContent, settings)
	if err != nil {
		return true, nil
	}
	pending, err := indexDerivePending(derived, self.normalizer, self.refKey, self.plan.RefId, false, self.writer.args.settings)
	if err != nil {
		return false, err
	}
	self.pending = append(self.pending, pending...)
	return true, nil
}

// One accepted file version's index entries: what its push carries, as this copy derives it.
type directoryIndexDerivation struct {
	path string
	// the cards ref version the file's push committed at, and its signer
	pushVersion     uint64
	signerSidecarId Id
	documents       []*indexDeriveDocument
}

// The client's index part: its settings and the derivations it keeps.
type directoryIndexPart struct {
	stateLock sync.Mutex
	settings  *DirectoryIndexSettings
	// oldest first, at most settings.DerivationCount
	derivations []*directoryIndexDerivation
}

// The client's index part.
func (self *DirectoryClient) indexPart() *directoryIndexPart {
	return self.part(directoryIndexPartName, func() any {
		return &directoryIndexPart{settings: DefaultDirectoryIndexSettings()}
	}).(*directoryIndexPart)
}

// Sets what the directory's index holds to; nil, and settings no index runs on, keep the current ones.
func (self *DirectoryClient) SetIndexSettings(settings *DirectoryIndexSettings) {
	if settings == nil || settings.check() != nil {
		return
	}
	part := self.indexPart()
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	part.settings = settings
}

// What the directory's index holds to now.
func (self *DirectoryClient) indexSettings() *DirectoryIndexSettings {
	part := self.indexPart()
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	return part.settings
}

// Keeps the index entries the push of an accepted file version carries, for deriving its writer's head: called as
// the copy accepts taken over previous, the version it accepted at the path before, nil for none.
func (self *DirectoryClient) indexAccepted(previous *directoryAcceptedFile, taken *directoryAcceptedFile) {
	settings := self.indexSettings()
	if settings.DerivationCount <= 0 {
		return
	}
	var previousContent, nextContent []byte
	if previous != nil && !previous.file.Removed {
		previousContent = previous.file.Content
	}
	if !taken.file.Removed {
		nextContent = taken.file.Content
	}
	documents, err := directoryIndexFileChange(taken.file.Path, previousContent, nextContent, settings)
	if err != nil || len(documents) == 0 {
		// a renewal's push carries no entry, so no head of its writer's changes with it
		return
	}
	part := self.indexPart()
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	part.derivations = append(part.derivations, &directoryIndexDerivation{
		path: taken.file.Path, pushVersion: taken.file.PushVersion, signerSidecarId: taken.file.SignerSidecarId, documents: documents,
	})
	if over := len(part.derivations) - settings.DerivationCount; 0 < over {
		part.derivations = slices.Clone(part.derivations[over:])
	}
}

// The index entries the cards ref's push at pushVersion carries as this copy derived them, in path order; false where
// it holds none, a push whose files it did not accept or whose derivation aged out.
func (self *DirectoryClient) indexDerived(pushVersion uint64) ([]*indexDeriveDocument, bool) {
	part := self.indexPart()
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	held := []*directoryIndexDerivation{}
	for _, derivation := range part.derivations {
		if derivation.pushVersion == pushVersion {
			held = append(held, derivation)
		}
	}
	if len(held) == 0 {
		return nil, false
	}
	slices.SortStableFunc(held, func(a *directoryIndexDerivation, b *directoryIndexDerivation) int { return cmp.Compare(a.path, b.path) })
	documents := []*indexDeriveDocument{}
	for _, derivation := range held {
		documents = append(documents, derivation.documents...)
	}
	return documents, true
}

// Derives the head a card writer's push wrote on the cards ref's index (§16.11's reproduce row; D-MCP-31): from the
// writer's files at the push's base, which base gives, and the entries this copy derived from the file versions the
// push carried. Equal, nothing is fetched; unequal, the head is fetched and index_mismatch names the push's signer;
// where this copy holds no derivation of the push, or lacks a base file, the head is fetched and nothing is raised.
func (self *DirectoryClient) indexDeriveHead(ctx context.Context, reproducer *IndexReproducer, push *indexReproducePush, base *indexReproduceBase, refId Id, refKey []byte) (*indexReproduceOutcome, error) {
	if reproducer == nil || push == nil || base == nil {
		return nil, errDirectoryIndexArgs
	}
	documents, ok := self.indexDerived(push.version)
	if !ok {
		return reproducer.fetchAll(push, indexReproduceHead, true), nil
	}
	return reproducer.DeriveHead(ctx, &indexDeriveHeadArgs{push: push, base: base, documents: documents, refId: refId, refKey: refKey})
}

// The content this copy accepted at path's version: what a write that replaces the version reads of it, since a
// versionless file's replaced content is purged about a minute on (the in-ref writer's directoryReplaced). False for
// another directory, and where the copy accepted another version or none.
func (self *DirectoryClient) IndexReplaced(repoId Id, path string, version uint64) ([]byte, bool) {
	if directoryId, ok := self.DirectoryId(); !ok || directoryId != repoId || !directoryIndexPath(path) {
		return nil, false
	}
	accepted := self.files().acceptedAt(path)
	if accepted == nil || accepted.file.Removed || accepted.file.Version != version {
		return nil, false
	}
	return bytes.Clone(accepted.file.Content), true
}

// Every card and repo file this copy accepted that stands, in path order.
func (self *directoryFiles) standing() []*directoryAcceptedFile {
	settings := self.client.cardSettings()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.loadWithLock(settings); err != nil {
		return nil
	}
	standing := []*directoryAcceptedFile{}
	for _, taken := range self.accepted {
		if !taken.file.Removed {
			standing = append(standing, taken)
		}
	}
	slices.SortFunc(standing, func(a *directoryAcceptedFile, b *directoryAcceptedFile) int {
		return cmp.Compare(a.file.Path, b.file.Path)
	})
	return standing
}

// One file of the cards ref as a source reads it: its path, the cards ref version its push committed at, and its
// content.
type directoryIndexFile struct {
	path        string
	pushVersion uint64
	content     []byte
}

// The cards ref's documents (§16.11's documents row): the directory class's IndexDocumentSource over the cards and
// repo files a copy accepted, for a build, a rebuild, a backfill and a check by rebuild.
type DirectoryIndexCardsSource struct {
	// the files that stand, in path order, and the cards ref version the copy read them to
	files    func() ([]*directoryIndexFile, uint64)
	settings *DirectoryIndexSettings
}

var _ IndexDocumentSource = (*DirectoryIndexCardsSource)(nil)

// A source over files, which answers the standing d/ and r/ files in path order and the cards ref version they were
// read to.
func newDirectoryIndexCardsSource(files func() ([]*directoryIndexFile, uint64), settings *DirectoryIndexSettings) (*DirectoryIndexCardsSource, error) {
	if files == nil || settings == nil {
		return nil, errDirectoryIndexArgs
	}
	if err := settings.check(); err != nil {
		return nil, err
	}
	return &DirectoryIndexCardsSource{files: files, settings: settings}, nil
}

// §16.11's registry.
func (self *DirectoryIndexCardsSource) IndexRegistry() *IndexFieldRegistry {
	return indexDirectoryFieldRegistry()
}

// Visits every announcement the cards ref holds at refVersion, each at its newest version: a card's items in the
// card's order, cards in path order, then repo files' items in path order. An item that is no document (a private
// marker) is not visited. errIndexRecordBehind where the copy has not read the ref to refVersion; a file written past
// refVersion is left out, since its path's older version is the copy's no more and a later build takes it.
func (self *DirectoryIndexCardsSource) IndexDocuments(ctx context.Context, refVersion uint64, visit func(document *IndexDocument) error) error {
	files, readVersion := self.files()
	if readVersion < refVersion {
		return fmt.Errorf("%w: read to %d of %d", errIndexRecordBehind, readVersion, refVersion)
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if refVersion < file.pushVersion {
			continue
		}
		derived, err := directoryIndexFileChange(file.path, nil, file.content, self.settings)
		if err != nil {
			return err
		}
		for _, one := range derived {
			if one.tombstone {
				continue
			}
			if err := visit(one.document); err != nil {
				return err
			}
		}
	}
	return nil
}

// The cards ref's documents as this copy holds them: the directory class's source for the directory's own index.
func (self *DirectoryClient) IndexCardsSource() (*DirectoryIndexCardsSource, error) {
	return newDirectoryIndexCardsSource(func() ([]*directoryIndexFile, uint64) {
		files := []*directoryIndexFile{}
		for _, taken := range self.files().standing() {
			files = append(files, &directoryIndexFile{path: taken.file.Path, pushVersion: taken.file.PushVersion, content: taken.file.Content})
		}
		return files, self.store.State().CardsVersion
	}, self.indexSettings())
}

// The stream entry kinds the directory indexes as documents of their own (RECORD.md 7.2's D rows); an announce entry
// folds into its announcement's document, and every other kind is none.
var directoryIndexEntryKinds = []RecordKind{
	RecordKindAsk, RecordKindAnswer, RecordKindCheck, RecordKindNote, RecordKindRequest, RecordKindDecision, RecordKindErasureRequest,
}

// A decision's outcome as field 15 names it.
var directoryIndexOutcomes = map[uint32]string{1: directoryIndexStateApproved, 2: directoryIndexStateDenied, 3: directoryIndexStateCancelled}

// One stream entry's document (RECORD.md 7.1's D row and 7.2): named by its path at its entry version, 4 and 5 by its
// kind, 6 the kind's name, 7 the writer, 8 agent_id and 10 run_id from its header, 9 and 11 to 14 from announcement,
// its run's announcement at writing, nil for none, and 15 a request's or a decision's state.
func directoryIndexEntryDocument(entry *indexRecordEntry, announcement *protocol.Announcement, settings *DirectoryIndexSettings) (*IndexDocument, error) {
	document := &IndexDocument{
		Kind:      IndexDocRecord,
		Name:      []byte(entry.path),
		Version:   entry.version,
		ByteCount: uint64(len(entry.body)),
		Tainted:   entry.header.GetTainted(),
	}
	set := func(number int, value string) {
		document.Fields[number] = []byte(indexRowText(value))
	}
	set(searchFieldKind, indexRecordKindName(entry.kind()))
	set(searchFieldWriter, indexRecordHex(entry.header.GetWriterSidecarId()))
	set(searchFieldAgentId, indexRecordHex(entry.header.GetAgentId()))
	set(searchFieldRunId, indexRecordHex(entry.header.GetRunId()))
	if announcement != nil {
		set(searchFieldAgentLabel, announcement.GetWho().GetAgentLabel())
		set(searchFieldMemberId, directoryIndexHex(announcement.GetWho().GetMemberId()))
		set(searchFieldProject, announcement.GetWhere().GetProject())
		set(searchFieldBranch, announcement.GetWhere().GetBranch())
		set(searchFieldRepoId, directoryIndexHex(announcement.GetWhere().GetRepoId()))
	}
	if entry.body != nil && !entry.unreadable {
		switch entry.kind() {
		case RecordKindRequest:
			body := &protocol.DirectoryRequest{}
			if proto.Unmarshal(entry.body, body) == nil {
				target := body.GetTarget()
				set(indexFieldBody, indexRecordLines(body.GetReason(), indexRecordHex(target.GetRepoId()), indexRecordHex(target.GetSidecarId()), indexRecordHex(target.GetSocketToken())))
				set(searchFieldState, directoryIndexStatePending)
				if repoId := directoryIndexHex(target.GetRepoId()); repoId != "" {
					set(searchFieldRepoId, repoId)
				}
			}
		case RecordKindDecision:
			body := &protocol.DirectoryDecision{}
			if proto.Unmarshal(entry.body, body) == nil {
				set(indexFieldBody, body.GetNote())
				set(searchFieldState, directoryIndexOutcomes[body.GetOutcome()])
			}
		case RecordKindErasureRequest:
			body := &protocol.DirectoryErasureRequest{}
			if proto.Unmarshal(entry.body, body) == nil {
				set(searchFieldRepoId, directoryIndexHex(body.GetRepoId()))
			}
		default:
			title, text, _, _ := indexRecordTitleAndText(entry, settings.Record)
			set(indexFieldTitle, title)
			set(indexFieldBody, text)
		}
	}
	if err := indexDirectoryFieldRegistry().check(document); err != nil {
		return nil, err
	}
	return document, nil
}

// What a stream source reads one build with.
type directoryIndexStreamSourceArgs struct {
	// One writer's stream of the directory, as the record class reads a stream.
	stream indexRecordStream
	// The item writerSidecarId's card holds for runId now, nil for none: an entry's run's announcement where its own
	// stream holds no announce entry of the run below it. Nil knows none.
	runItem  func(writerSidecarId Id, runId Id) *protocol.Announcement
	settings *DirectoryIndexSettings
}

// One writer's stream's documents (§16.11's documents row): the directory class's IndexDocumentSource for the
// directory's ur/index. Construct with newDirectoryIndexStreamSource at each build.
type DirectoryIndexStreamSource struct {
	args directoryIndexStreamSourceArgs
}

var _ IndexDocumentSource = (*DirectoryIndexStreamSource)(nil)

// A source over args.
func newDirectoryIndexStreamSource(args *directoryIndexStreamSourceArgs) (*DirectoryIndexStreamSource, error) {
	if args == nil || args.stream == nil || args.settings == nil {
		return nil, errDirectoryIndexArgs
	}
	if args.stream.LogKind() != protocol.RepoKind_REPO_KIND_DIRECTORY {
		return nil, errIndexRecordLogKind
	}
	if err := args.settings.check(); err != nil {
		return nil, err
	}
	return &DirectoryIndexStreamSource{args: *args}, nil
}

// §16.11's registry.
func (self *DirectoryIndexStreamSource) IndexRegistry() *IndexFieldRegistry {
	return indexDirectoryFieldRegistry()
}

// The announce entries of a stream, by the order a fold takes them: the highest (version, renewed_millis), then seq.
func directoryIndexAnnounceCompare(a *directoryIndexAnnounce, b *directoryIndexAnnounce) int {
	return cmp.Or(
		cmp.Compare(a.item.GetVersion(), b.item.GetVersion()),
		cmp.Compare(a.item.GetRenewedMillis(), b.item.GetRenewedMillis()),
		indexRecordFoldCompare(a.entry, b.entry),
	)
}

// One announce entry of a stream, parsed.
type directoryIndexAnnounce struct {
	entry *indexRecordEntry
	item  *protocol.Announcement
}

// Visits every document the stream holds at refVersion: each entry document in path order, then each announcement
// its announce entries fold to, in name order, at its newest version. An entry this device cannot open is left out,
// as an unopenable path is; a withdrawn announcement, and a repo's private marker, is no document.
func (self *DirectoryIndexStreamSource) IndexDocuments(ctx context.Context, refVersion uint64, visit func(document *IndexDocument) error) error {
	entries, err := self.args.stream.Entries(ctx, refVersion)
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(a *indexRecordEntry, b *indexRecordEntry) int { return strings.Compare(a.path, b.path) })
	announces := []*directoryIndexAnnounce{}
	for _, entry := range entries {
		if entry.kind() != RecordKindAnnounce || entry.keyGone || entry.unreadable || entry.body == nil {
			continue
		}
		item := &protocol.Announcement{}
		if proto.Unmarshal(entry.body, item) != nil || len(item.GetAnnouncementId()) != len(Id{}) {
			continue
		}
		announces = append(announces, &directoryIndexAnnounce{entry: entry, item: item})
	}
	// an entry's run's announcement at writing: the newest announce entry of the run below it in the stream
	announcementOf := func(entry *indexRecordEntry) *protocol.Announcement {
		runId, ok := entry.runId()
		if !ok {
			return nil
		}
		var newest *directoryIndexAnnounce
		for _, announce := range announces {
			if !bytes.Equal(announce.item.GetWhat().GetRunId(), runId[:]) || entry.header.GetSeq() <= announce.entry.header.GetSeq() {
				continue
			}
			if newest == nil || 0 < directoryIndexAnnounceCompare(announce, newest) {
				newest = announce
			}
		}
		if newest != nil {
			return newest.item
		}
		if self.args.runItem != nil {
			return self.args.runItem(recordIdOf(entry.header.GetWriterSidecarId()), runId)
		}
		return nil
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !slices.Contains(directoryIndexEntryKinds, entry.kind()) || entry.keyGone {
			continue
		}
		document, err := directoryIndexEntryDocument(entry, announcementOf(entry), self.args.settings)
		if err != nil {
			return err
		}
		if err := visit(document); err != nil {
			return err
		}
	}
	// M6's announce entries fold into their announcement's document
	newest := map[string]*directoryIndexAnnounce{}
	names := []string{}
	for _, announce := range announces {
		kind := DirectoryAnnouncementKind(announce.item.GetKind())
		if directoryIndexKindName(kind) == "" {
			continue
		}
		name := string(directoryIndexAnnouncementName(kind, recordIdOf(announce.entry.header.GetWriterSidecarId()), recordIdOf(announce.item.GetAnnouncementId())))
		held, ok := newest[name]
		if !ok {
			names = append(names, name)
		}
		if !ok || 0 < directoryIndexAnnounceCompare(announce, held) {
			newest[name] = announce
		}
	}
	slices.Sort(names)
	for _, name := range names {
		announce := newest[name]
		if !directoryIndexShows(announce.item) {
			continue
		}
		document, err := directoryIndexAnnouncementDocument(announce.item, recordIdOf(announce.entry.header.GetWriterSidecarId()))
		if err != nil {
			return err
		}
		document.Tainted = document.Tainted || announce.entry.header.GetTainted()
		if err := visit(document); err != nil {
			return err
		}
	}
	return nil
}

// writerSidecarId's stream's documents as this copy holds them: the directory class's source for the directory's
// ur/index. errIndexRecordBehind where the copy holds no such stream.
func (self *DirectoryClient) IndexStreamSource(writerSidecarId Id) (*DirectoryIndexStreamSource, error) {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	reader := func() *RecordReader {
		self.syncLock.Lock()
		defer self.syncLock.Unlock()
		return self.reader
	}()
	streams, _ := reader.Streams(directoryId)
	for _, stream := range streams {
		if stream.StreamSidecarId != writerSidecarId {
			continue
		}
		return newDirectoryIndexStreamSource(&directoryIndexStreamSourceArgs{
			stream: newIndexRecordReaderStream(reader, directoryId, protocol.RepoKind_REPO_KIND_DIRECTORY, writerSidecarId, stream.RefId),
			runItem: func(writerSidecarId Id, runId Id) *protocol.Announcement {
				accepted := self.files().acceptedAt(DirectoryCardPath(writerSidecarId))
				if accepted == nil || accepted.card == nil || accepted.file.Removed {
					return nil
				}
				for _, item := range accepted.card.Card.GetItems() {
					if bytes.Equal(item.GetWhat().GetRunId(), runId[:]) {
						return item
					}
				}
				return nil
			},
			settings: self.indexSettings(),
		})
	}
	return nil, fmt.Errorf("%w: no stream of that writer", errIndexRecordBehind)
}

// The folded view behind search_agents (§16.11's tools row; SearchAgentsRequest.Fold): reads each run, worker or repo
// announcement hit of this directory at its item's state and expiry in this copy's fold now, and keeps one hit an
// announcement. A renewal moves an item's expiry and writes no index entry, so a row's own expiry is its last content
// change's: without this an hour-old run would read expired. Hits of other repos and of entries pass as they are, and
// so does every hit while the copy has finished no sync. Asks for a sync for the view, coalesced, and answers from
// what the copy holds.
func (self *DirectoryClient) SearchAgentsFold(hits []SearchHit) []SearchHit {
	directoryId, ok := self.DirectoryId()
	if !ok || !self.store.State().SequenceKnown {
		return hits
	}
	items, err := self.List(&DirectoryFilter{IncludePrivate: true})
	if err != nil {
		return hits
	}
	return directorySearchAgentsFold(directoryId, items, hits)
}

// SearchAgentsFold over items, the directory's current items: see there. Of two hits naming one announcement, as its
// card's index and an announce entry's stream give it through the move to format 2, the higher version stays, the
// first on a tie. An item that shows no more reads ended.
func directorySearchAgentsFold(directoryId Id, items []*DirectoryItem, hits []SearchHit) []SearchHit {
	current := map[string]*DirectoryItem{}
	for _, item := range items {
		current[string(directoryIndexAnnouncementName(item.Key.Kind, item.Key.WriterSidecarId, item.Key.AnnouncementId))] = item
	}
	announcement := func(hit *SearchHit) bool {
		return hit.Repo == directoryId && indexDocKind(hit.DocKind) == indexDocDerived && strings.HasPrefix(hit.Path, directoryIndexAnnouncementPrefix)
	}
	newest := map[string]int{}
	for index := range hits {
		if !announcement(&hits[index]) {
			continue
		}
		if held, ok := newest[hits[index].Path]; !ok || hits[held].Version < hits[index].Version {
			newest[hits[index].Path] = index
		}
	}
	folded := make([]SearchHit, 0, len(hits))
	for index := range hits {
		hit := hits[index]
		if !announcement(&hit) {
			folded = append(folded, hit)
			continue
		}
		if newest[hit.Path] != index {
			continue
		}
		state := directoryIndexStateEnded
		if item := current[hit.Path]; item != nil {
			hit.Started = directoryIndexTime(item.Announcement.GetStartedMillis())
			hit.Expires = directoryIndexTime(item.Announcement.GetExpiresMillis())
			switch item.Display {
			case DirectoryItemActive, DirectoryItemStale:
				// a stale item's expiry is past, so it reads active and expired
				state = directoryIndexStateActive
			case DirectoryItemHandedOff:
				state = directoryIndexStateHandedOff
			}
		} else if held := searchHitField(&hit, searchFieldState); held != directoryIndexStateActive && held != "" {
			state = held
		}
		fields := make([]SearchField, 0, len(hit.Fields)+1)
		for _, field := range hit.Fields {
			if field.Field != searchFieldState {
				fields = append(fields, field)
			}
		}
		hit.Fields = append(fields, SearchField{Field: searchFieldState, Text: state})
		folded = append(folded, hit)
	}
	return folded
}

// An announcement's time as a hit carries it, zero for none.
func directoryIndexTime(millis int64) time.Time {
	if millis <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis)
}

// What writes the directory's index settings: a DirectoryCards binding that also reaches the index, as
// DirectoryEvsCards does through EvsRepo.IndexSettings.
type DirectoryCardsIndexSettings interface {
	// Writes the next settings version, naming windowDays, on the cards ref's index root and on ur/index's where the
	// repo holds that ref, as a directory admin.
	SetIndexWindow(ctx context.Context, repoId Id, windowDays uint32) (*EvsIndexSettingsResult, error)
}

var _ DirectoryCardsIndexSettings = (*DirectoryEvsCards)(nil)

// Writes the directory's index window through the repo's own settings write (EvsRepo.IndexSettings), which checks
// the kind's days and this device's admin right again and never turns the index off.
func (self *DirectoryEvsCards) SetIndexWindow(ctx context.Context, repoId Id, windowDays uint32) (*EvsIndexSettingsResult, error) {
	return self.client.Repo(repoId).IndexSettings(ctx, &EvsIndexSettingsArgs{
		Action: EvsIndexWindow, WindowDays: windowDays, RefNames: [][]byte{DirectoryCardsRefName()},
	})
}
