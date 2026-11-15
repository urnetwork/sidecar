//go:build !ios_extension

// §16.11's revoke row at M6 (RECORD-M6-20; R-MCP-16, D-MCP-27, D-MCP-33, FS-99): a repo owner's revocation of its
// repo's item, and what every reader does with a directory ERASE.
//
//	revoke    a device holding D-MCP-35's right on the repo now (a repo admin; owner-bound, a consented device of its
//	          owner), for a person's confirmed act only (§5.8): it journals the revocation first, its request id, the
//	          marker's version and the marker's fields, then appends the private marker over the repo's item and the
//	          erasure_request entry, DirectoryErasureRequest, back to back with the record writer's pump held, so the
//	          two leave in one push. A restart that finds the journal unfiled appends the same marker and the same
//	          request again: one request id whatever the kill. A second revoke of a repo whose marker still stands
//	          files nothing and answers the first
//	pending   until a directory admin's ERASE or erasure entry names the request, the revocation reads pending with
//	          its age (Revocations, RevocationStatusLines); an ordinary writer never destroys another writer's key
//	          (I-EVS-16), so the revoker waits for the directory's erasure runner (directory_erasure.go) and is never
//	          dropped. A full item at a higher version lapses it
//	readers   a directory ERASE counts only from a sidecar the state names a directory admin: the reader takes no
//	          other, and alarms bad_erasure naming its signer, which only a server breaching the scope rule can
//	          commit. One whose note names an erasure_request is shown as that repo owner's revocation (ErasureOf)
//
// The journal is one file a repo, revoke/<repo id>, in the directory's own store, beside the requests an ERASE named,
// erased, which outlive the reader's memory. Barriers: directory.revoke.journaled after the journal and before the
// first append, and directory.revoke.filed after both, keyed by the repo's id.
//
// Not here: format 2's r/ overwrite and its purge (RECORD-M10-02), and the runner. Safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A revocation is a person's act: its command was not confirmed on /dev/tty or in an app's UI, or its caller has a
// harness process among its ancestors (§5.8). Nothing was journaled or signed.
var ErrDirectoryRevokeUnconfirmed = errors.New("directory revoke is a person's act")

// The revoke journal's format values.
const (
	directoryRevokeJournalDirectory = "revoke/"
	directoryRevokeJournalVersion   = 1
	directoryErasedStoreName        = "erased"
	directoryErasedStoreVersion     = 1
	directoryRevocationsPart        = "revocations"
)

// A revocation's state on the device that filed it.
type DirectoryRevocationState string

const (
	// No directory admin's ERASE names its request yet.
	DirectoryRevocationPending DirectoryRevocationState = "pending"
	// An ERASE names its request.
	DirectoryRevocationDone DirectoryRevocationState = "done"
	// A full item at a higher version replaced its marker: the request erases nothing.
	DirectoryRevocationLapsed DirectoryRevocationState = "lapsed"
)

// One revocation asked of the client.
type DirectoryRevokeArgs struct {
	RepoId Id
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
	// The caller has a harness process among its ancestors: the revocation is refused.
	HarnessAncestor bool
}

// One revocation as the device that filed it holds it.
type DirectoryRevocation struct {
	RepoId    Id
	RequestId Id
	// The private marker's Announcement.version.
	MarkerVersion uint64
	// When this device journaled it.
	TimeMillis int64
	// The marker's and the request's entries; nil while they wait unsealed in the spool.
	MarkerEntryId  *Id
	RequestEntryId *Id
	State          DirectoryRevocationState
	// Pending: how long it has waited.
	Age time.Duration
	// Done: evs's time of the first ERASE naming it, and its eraser.
	ErasedMillis    int64
	EraserSidecarId *Id
	// What the person should hear, as DirectoryRepoLabelWarning.
	Warnings []string
}

// One erasure_request entry as this copy holds it.
type DirectoryErasureRequestView struct {
	RequestId     Id
	RepoId        Id
	MarkerVersion uint64
	// Its signer, whose own stream carried it, and where.
	SignerSidecarId Id
	EntryId         Id
	PushPin         *bridge.AuthPin
	PushTimeMillis  int64
	// A directory admin's ERASE or erasure entry names it, and when.
	Erased          bool
	ErasedMillis    int64
	EraserSidecarId *Id
}

// What erased an entry of the directory, as a reader shows it.
type DirectoryErasure struct {
	EraserSidecarId Id
	// The erasure's id, as its ERASE and its erasure entry name it.
	ErasureId Id
	Reason    RecordErasureReason
	// A repo owner's revocation: the erasure_request its note names, and the repo where this copy holds the request.
	RequestId *Id
	RepoId    *Id
}

// One revocation in the journal.
type directoryRevokeDocument struct {
	Version       int    `json:"version"`
	RepoId        Id     `json:"repo_id"`
	RequestId     Id     `json:"request_id"`
	MarkerVersion uint64 `json:"marker_version"`
	// the marker's started time and its requests value, so a restart builds the same marker
	StartedMillis int64  `json:"started_millis"`
	Requests      uint32 `json:"requests"`
	TimeMillis    int64  `json:"time_millis"`
	// both entries are with the record writer, journaled or spooled
	Filed          bool `json:"filed"`
	MarkerEntryId  *Id  `json:"marker_entry_id,omitempty"`
	RequestEntryId *Id  `json:"request_entry_id,omitempty"`
}

// One request an ERASE named.
type directoryErasedRow struct {
	TimeMillis      int64 `json:"time_millis"`
	EraserSidecarId Id    `json:"eraser_sidecar_id"`
}

// The requests ERASEs named, kept: the reader's memory of an ERASE ends with its process.
type directoryErasedDocument struct {
	Version  int                            `json:"version"`
	Requests map[string]*directoryErasedRow `json:"requests"`
}

// The client's revocations and what its reader learned from the directory's ERASEs.
type directoryRevocations struct {
	// one revocation at a time
	revokeLock sync.Mutex

	stateLock sync.Mutex
	// each request an accepted ERASE named, loaded from the store at first use
	erased map[Id]*directoryErasedRow
	loaded bool
	// each entry an accepted ERASE's note named, this process's reads only
	entryErasures map[Id]*DirectoryErasure
	// the refused ERASEs already alarmed, by their version of the erasure ref
	refusedVersions map[uint64]bool
}

// Sets the readers' rule for the directory's ERASEs on every leg that links this file.
func init() {
	directoryErasureJudge = func(client *DirectoryClient, repoId Id, erasures []*RecordStreamErasure) ([]*RecordStreamErasure, error) {
		return client.judgeErasures(repoId, erasures)
	}
}

// The client's revocations part.
func (self *DirectoryClient) revocations() *directoryRevocations {
	return self.part(directoryRevocationsPart, func() any {
		return &directoryRevocations{erased: map[Id]*directoryErasedRow{}, entryErasures: map[Id]*DirectoryErasure{}, refusedVersions: map[uint64]bool{}}
	}).(*directoryRevocations)
}

// Appends drafts back to back with the pump held, so no push leaves between them and one push carries them all.
func (self *recordWriter) appendTogether(drafts ...*RecordDraft) ([][]*RecordEntryRef, error) {
	self.pumpLock.Lock()
	defer self.pumpLock.Unlock()
	refs := [][]*RecordEntryRef{}
	for _, draft := range drafts {
		appended, err := self.Append(draft)
		if err != nil {
			return refs, err
		}
		refs = append(refs, appended)
	}
	return refs, nil
}

// The journal's file of repoId.
func directoryRevokeJournalName(repoId Id) string {
	return directoryRevokeJournalDirectory + hex.EncodeToString(repoId[:])
}

// The journaled revocation of repoId, nil for none.
func (self *DirectoryClient) readRevoke(repoId Id) (*directoryRevokeDocument, error) {
	content, err := self.store.readFile(directoryRevokeJournalName(repoId))
	if err != nil || content == nil {
		return nil, err
	}
	document := &directoryRevokeDocument{}
	if err := json.Unmarshal(content, document); err != nil || document.Version != directoryRevokeJournalVersion || document.RepoId != repoId {
		return nil, fmt.Errorf("%w: revocation journal of repo %s", ErrDirectoryStoreCorrupt, repoId)
	}
	return document, nil
}

// Every journaled revocation, in repo id order.
func (self *DirectoryClient) readRevokes() ([]*directoryRevokeDocument, error) {
	entries, err := self.store.store.List(directoryRevokeJournalDirectory)
	if err != nil {
		return nil, err
	}
	documents := []*directoryRevokeDocument{}
	for _, entry := range entries {
		content, err := self.store.readFile(entry.Name)
		if err != nil {
			return nil, err
		}
		if content == nil {
			continue
		}
		document := &directoryRevokeDocument{}
		if err := json.Unmarshal(content, document); err != nil || document.Version != directoryRevokeJournalVersion || directoryRevokeJournalName(document.RepoId) != entry.Name {
			return nil, fmt.Errorf("%w: revocation journal %s", ErrDirectoryStoreCorrupt, entry.Name)
		}
		documents = append(documents, document)
	}
	slices.SortFunc(documents, func(a *directoryRevokeDocument, b *directoryRevokeDocument) int { return a.RepoId.Cmp(b.RepoId) })
	return documents, nil
}

// The item that stands for repoId in this copy at auth, its private marker included, with no sync asked; nil for
// none.
func (self *DirectoryClient) standingRepoItem(auth DirectoryAuthView, repoId Id, nowMillis int64) *DirectoryItem {
	item, err := directoryGetItem(self.currentFold().View(auth, nowMillis), DirectoryRepoAnnouncementId(repoId), nil)
	if err != nil {
		return nil
	}
	return item
}

// The private marker a journaled revocation writes, built from the journal alone, so a restart builds it again the
// same.
func (self *DirectoryClient) revokeMarker(auth DirectoryAuthView, repo *DirectoryRepo, journal *directoryRevokeDocument) (*protocol.Announcement, error) {
	who := &protocol.AnnounceWho{SidecarId: self.sidecarId.Bytes()}
	if memberId, ok := DirectoryWhoMember(auth, self.sidecarId); ok {
		who.MemberId = memberId.Bytes()
	}
	item := &protocol.Announcement{
		AnnouncementId: DirectoryRepoAnnouncementId(repo.RepoId).Bytes(),
		Kind:           uint32(DirectoryAnnouncementKindRepo),
		Version:        journal.MarkerVersion,
		StartedMillis:  journal.StartedMillis,
		RenewedMillis:  journal.TimeMillis,
		State:          uint32(DirectoryAnnouncementStateActive),
		Who:            who,
		What:           &protocol.AnnounceWhat{RepoKind: uint32(repo.Kind), Requests: journal.Requests},
		Where:          &protocol.AnnounceWhere{RepoId: repo.RepoId.Bytes(), Private: true},
	}
	if err := DirectoryCheckItem(item); err != nil {
		return nil, err
	}
	if _, err := DirectoryPadRepoAnnouncement(item); err != nil {
		return nil, err
	}
	return item, nil
}

// Revokes a repo's item: see the file's header's revoke row. Answers the revocation as it stands, pending until the
// directory's erasure runner erases the copies that name the repo.
func (self *DirectoryClient) RevokeRepo(ctx context.Context, args *DirectoryRevokeArgs) (*DirectoryRevocation, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no repo", ErrDirectoryFormatInvalid)
	}
	if !args.Confirmed || args.HarnessAncestor {
		return nil, ErrDirectoryRevokeUnconfirmed
	}
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	if self.writer == nil {
		return nil, ErrDirectoryNoWriter
	}
	auth := self.auth()
	if _, ok := auth.Directory(); !ok {
		return nil, ErrDirectoryNone
	}
	repo, ok := auth.Repo(args.RepoId)
	if !ok || !repo.Live {
		return nil, fmt.Errorf("%w: a repo this state does not hold live", ErrDirectoryRepoRight)
	}
	if directoryRepoFileIgnored(repo.Kind) {
		return nil, ErrDirectoryRepoKind
	}
	if err := self.holdsRepoRight(auth, args.RepoId); err != nil {
		return nil, err
	}
	part := self.revocations()
	part.revokeLock.Lock()
	defer part.revokeLock.Unlock()
	nowMillis := self.clock.Now().UnixMilli()
	journal, err := self.readRevoke(args.RepoId)
	if err != nil {
		return nil, err
	}
	standing := self.standingRepoItem(auth, args.RepoId, nowMillis)
	if journal != nil && journal.Filed && !directoryRevokeLapsed(journal, standing) {
		// filed once: the marker stands, or the copy has not read it back yet
		return self.revocationOf(journal, standing, nowMillis), nil
	}
	if journal == nil || journal.Filed {
		version, startedMillis := self.repoVersionAbove(auth, args.RepoId, nowMillis)
		requests := DirectoryRequestsOpen
		if aclRepoKindOwnerBound(repo.Kind) {
			requests = DirectoryRequestsClosed
		}
		if standing != nil && standing.Announcement.GetWhat().GetRequests() != 0 {
			// the marker keeps what the item it replaces said of requests
			requests = DirectoryRequests(standing.Announcement.GetWhat().GetRequests())
		}
		journal = &directoryRevokeDocument{
			Version: directoryRevokeJournalVersion, RepoId: args.RepoId, RequestId: NewId(), MarkerVersion: version,
			StartedMillis: startedMillis, Requests: uint32(requests), TimeMillis: nowMillis,
		}
		if err := self.store.writeDocument(directoryRevokeJournalName(args.RepoId), journal); err != nil {
			return nil, err
		}
	}
	hookKey := recordChainIdText(args.RepoId)
	testHookBarrier("directory.revoke.journaled", hookKey)
	marker, err := self.revokeMarker(auth, repo, journal)
	if err != nil {
		return nil, err
	}
	request := &protocol.DirectoryErasureRequest{RequestId: journal.RequestId.Bytes(), RepoId: args.RepoId.Bytes(), MarkerVersion: journal.MarkerVersion}
	if err := DirectoryCheckErasureRequest(request); err != nil {
		return nil, err
	}
	drafts := []*RecordDraft{
		{Kind: RecordKindAnnounce, Source: RecordSourceApprover, NoSession: true, Body: marker},
		{Kind: RecordKindErasureRequest, Source: RecordSourceApprover, NoSession: true, Body: request},
	}
	var refs [][]*RecordEntryRef
	if together, ok := self.writer.(interface {
		appendTogether(drafts ...*RecordDraft) ([][]*RecordEntryRef, error)
	}); ok {
		refs, err = together.appendTogether(drafts...)
	} else {
		for _, draft := range drafts {
			var appended []*RecordEntryRef
			appended, err = self.writer.Append(draft)
			if err != nil {
				break
			}
			refs = append(refs, appended)
		}
	}
	if err != nil {
		// the journal stands unfiled: the next revoke of this repo appends the same marker and request
		return nil, err
	}
	directoryId, _ := self.DirectoryId()
	entryIdOf := func(appended []*RecordEntryRef) *Id {
		for _, ref := range appended {
			if !ref.Spooled && ref.LogId == directoryId {
				entryId := ref.EntryId
				return &entryId
			}
		}
		return nil
	}
	journal.Filed = true
	journal.MarkerEntryId = entryIdOf(refs[0])
	journal.RequestEntryId = entryIdOf(refs[1])
	if err := self.store.writeDocument(directoryRevokeJournalName(args.RepoId), journal); err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.repoWrittenVersions[args.RepoId] = max(self.repoWrittenVersions[args.RepoId], journal.MarkerVersion)
	}()
	testHookBarrier("directory.revoke.filed", hookKey)
	revocation := self.revocationOf(journal, standing, nowMillis)
	if self.repoLabeled == nil || self.repoLabeled(args.RepoId) {
		// unknown counts as labeled: the warning costs nothing, a missed one the name
		revocation.Warnings = append(revocation.Warnings, DirectoryRepoLabelWarning)
	}
	return revocation, nil
}

// Whether a full item above the journaled marker stands: the revocation erases nothing any more.
func directoryRevokeLapsed(journal *directoryRevokeDocument, standing *DirectoryItem) bool {
	return standing != nil && standing.Display != DirectoryItemPrivate && journal.MarkerVersion < standing.Announcement.GetVersion()
}

// A journaled revocation as it stands now.
func (self *DirectoryClient) revocationOf(journal *directoryRevokeDocument, standing *DirectoryItem, nowMillis int64) *DirectoryRevocation {
	revocation := &DirectoryRevocation{
		RepoId: journal.RepoId, RequestId: journal.RequestId, MarkerVersion: journal.MarkerVersion, TimeMillis: journal.TimeMillis,
		MarkerEntryId: journal.MarkerEntryId, RequestEntryId: journal.RequestEntryId, State: DirectoryRevocationPending,
	}
	if row, ok := self.requestErased(journal.RequestId); ok {
		revocation.State = DirectoryRevocationDone
		revocation.ErasedMillis = row.TimeMillis
		eraserId := row.EraserSidecarId
		revocation.EraserSidecarId = &eraserId
		return revocation
	}
	if directoryRevokeLapsed(journal, standing) {
		revocation.State = DirectoryRevocationLapsed
		return revocation
	}
	revocation.Age = max(0, time.Duration(nowMillis-journal.TimeMillis)*time.Millisecond)
	return revocation
}

// This device's revocations as they stand, in repo id order: each pending until an ERASE names its request.
func (self *DirectoryClient) Revocations() ([]*DirectoryRevocation, error) {
	journals, err := self.readRevokes()
	if err != nil {
		return nil, err
	}
	auth := self.auth()
	nowMillis := self.clock.Now().UnixMilli()
	revocations := []*DirectoryRevocation{}
	for _, journal := range journals {
		revocations = append(revocations, self.revocationOf(journal, self.standingRepoItem(auth, journal.RepoId, nowMillis), nowMillis))
	}
	return revocations, nil
}

// `ur status`'s lines for this device's revocations still waiting for the directory's erasure runner, each with its
// age (§16.11's revoke row).
func (self *DirectoryClient) RevocationStatusLines() []string {
	revocations, err := self.Revocations()
	if err != nil {
		return []string{fmt.Sprintf("directory: this device's revocations do not read: %s", err)}
	}
	lines := []string{}
	for _, revocation := range revocations {
		if revocation.State == DirectoryRevocationPending {
			lines = append(lines, fmt.Sprintf("directory: the erasure for repo %s is pending for %s (request %s): it waits for a directory admin's daemon",
				revocation.RepoId, directoryAgeText(revocation.Age), revocation.RequestId))
		}
	}
	return lines
}

// An age as a status line says it: whole minutes below an hour, whole hours above.
func directoryAgeText(age time.Duration) string {
	if age < time.Hour {
		return age.Truncate(time.Minute).String()
	}
	return fmt.Sprintf("%dh", int64(age/time.Hour))
}

// Loads the kept erased requests once. The caller holds part.stateLock.
func (self *DirectoryClient) loadErasedWithLock(part *directoryRevocations) {
	if part.loaded {
		return
	}
	part.loaded = true
	if self.store == nil || self.store.store == nil {
		return
	}
	content, err := self.store.readFile(directoryErasedStoreName)
	if err != nil || content == nil {
		return
	}
	document := &directoryErasedDocument{}
	if err := json.Unmarshal(content, document); err != nil || document.Version != directoryErasedStoreVersion {
		// unreadable: the erasure entries in the copy still name what was erased
		self.log.Warningf("[directory]the kept erased requests do not read")
		return
	}
	for text, row := range document.Requests {
		if requestId, err := directoryParseIdText(text); err == nil && row != nil {
			if _, ok := part.erased[requestId]; !ok {
				part.erased[requestId] = row
			}
		}
	}
}

// Keeps the erased requests. The caller holds part.stateLock.
func (self *DirectoryClient) keepErasedWithLock(part *directoryRevocations) error {
	if self.store == nil || self.store.store == nil {
		return nil
	}
	document := &directoryErasedDocument{Version: directoryErasedStoreVersion, Requests: map[string]*directoryErasedRow{}}
	for requestId, row := range part.erased {
		document.Requests[recordChainIdText(requestId)] = row
	}
	return self.store.writeDocument(directoryErasedStoreName, document)
}

// §16.11's readers row for the directory's ERASEs, before the reader takes them: one from a sidecar the state names a
// directory admin counts, its note's request and entries remembered; any other is left out and alarms bad_erasure,
// naming its signer, once.
func (self *DirectoryClient) judgeErasures(repoId Id, erasures []*RecordStreamErasure) ([]*RecordStreamErasure, error) {
	if len(erasures) == 0 {
		return erasures, nil
	}
	auth := self.auth()
	admins, err := auth.DirectoryAdmins(auth.Pin())
	if err != nil {
		return nil, err
	}
	recordAuth := self.recordAuth()
	part := self.revocations()
	accepted := []*RecordStreamErasure{}
	refused := []Id{}
	err = func() error {
		part.stateLock.Lock()
		defer part.stateLock.Unlock()
		self.loadErasedWithLock(part)
		changed := false
		for _, erasure := range erasures {
			if !slices.Contains(admins, erasure.EraserSidecarId) && !recordAuth.Admins(repoId, erasure.EraserSidecarId) {
				if !part.refusedVersions[erasure.Version] {
					part.refusedVersions[erasure.Version] = true
					refused = append(refused, erasure.EraserSidecarId)
				}
				continue
			}
			accepted = append(accepted, erasure)
			body, ok := recordErasureNoteBody(erasure)
			if !ok {
				continue
			}
			seen := &DirectoryErasure{EraserSidecarId: erasure.EraserSidecarId, ErasureId: erasure.ErasureId, Reason: RecordErasureReason(body.GetReason())}
			if seen.Reason == RecordErasureReasonRevocation && len(body.GetRequestId()) == len(Id{}) {
				requestId := recordIdOf(body.GetRequestId())
				seen.RequestId = &requestId
				if _, ok := part.erased[requestId]; !ok {
					part.erased[requestId] = &directoryErasedRow{TimeMillis: erasure.TimeMillis, EraserSidecarId: erasure.EraserSidecarId}
					changed = true
				}
			}
			for _, entryId := range body.GetEntryIds() {
				if len(entryId) == len(Id{}) {
					part.entryErasures[recordIdOf(entryId)] = seen
				}
			}
		}
		if changed {
			return self.keepErasedWithLock(part)
		}
		return nil
	}()
	for _, signerId := range refused {
		self.raise(SidecarRecordAlarmBadErasure, repoId, &signerId)
	}
	if err != nil {
		return nil, err
	}
	return accepted, nil
}

// Every entry this copy's reader verified, in read order.
func (self *DirectoryClient) allEntries() []*RecordReadEntry {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil
	}
	self.syncLock.Lock()
	reader := self.reader
	self.syncLock.Unlock()
	return reader.Entries(directoryId)
}

// The erasure entries of the directory's admins this copy holds, each with its writer and its push's time.
func (self *DirectoryClient) erasureEntries() []*directoryErasureEntry {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil
	}
	recordAuth := self.recordAuth()
	found := []*directoryErasureEntry{}
	for _, entry := range self.entriesOfKinds(RecordKindErasure) {
		writerId, _, timeMillis, ok := directoryEntryPush(entry)
		if !ok || !recordAuth.Admins(directoryId, writerId) {
			continue
		}
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			continue
		}
		found = append(found, &directoryErasureEntry{writerId: writerId, timeMillis: timeMillis, body: body})
	}
	return found
}

// One erasure entry of a directory admin.
type directoryErasureEntry struct {
	writerId   Id
	timeMillis int64
	body       *protocol.ErasureBody
}

// Every request an accepted ERASE's note or a directory admin's erasure entry names, with the earliest such time.
func (self *DirectoryClient) erasedRequests() map[Id]*directoryErasedRow {
	part := self.revocations()
	erased := func() map[Id]*directoryErasedRow {
		part.stateLock.Lock()
		defer part.stateLock.Unlock()
		self.loadErasedWithLock(part)
		copied := map[Id]*directoryErasedRow{}
		for requestId, row := range part.erased {
			copied[requestId] = row
		}
		return copied
	}()
	for _, entry := range self.erasureEntries() {
		if RecordErasureReason(entry.body.GetReason()) != RecordErasureReasonRevocation || len(entry.body.GetRequestId()) != len(Id{}) {
			continue
		}
		requestId := recordIdOf(entry.body.GetRequestId())
		if row, ok := erased[requestId]; !ok || entry.timeMillis < row.TimeMillis {
			erased[requestId] = &directoryErasedRow{TimeMillis: entry.timeMillis, EraserSidecarId: entry.writerId}
		}
	}
	return erased
}

// Whether a directory admin's ERASE or erasure entry names requestId, and when.
func (self *DirectoryClient) requestErased(requestId Id) (*directoryErasedRow, bool) {
	row, ok := self.erasedRequests()[requestId]
	return row, ok
}

// The erasure_request entries this copy holds, oldest push first: each live one with a copy in its signer's own
// stream, the first of a request id standing and a later one under that id left out.
func (self *DirectoryClient) ErasureRequests() []*DirectoryErasureRequestView {
	erased := self.erasedRequests()
	views := []*DirectoryErasureRequestView{}
	for _, entry := range self.entriesOfKinds(RecordKindErasureRequest) {
		writerId, pin, timeMillis, ok := directoryEntryPush(entry)
		if !ok {
			continue
		}
		request, err := DirectoryDecodeErasureRequest(entry.Body)
		if err != nil {
			continue
		}
		view := &DirectoryErasureRequestView{
			RequestId: recordIdOf(request.GetRequestId()), RepoId: recordIdOf(request.GetRepoId()), MarkerVersion: request.GetMarkerVersion(),
			SignerSidecarId: writerId, EntryId: entry.EntryId, PushPin: pin, PushTimeMillis: timeMillis,
		}
		if row, ok := erased[view.RequestId]; ok {
			view.Erased = true
			view.ErasedMillis = row.TimeMillis
			eraserId := row.EraserSidecarId
			view.EraserSidecarId = &eraserId
		}
		views = append(views, view)
	}
	slices.SortStableFunc(views, func(a *DirectoryErasureRequestView, b *DirectoryErasureRequestView) int {
		if order := cmp.Compare(a.PushTimeMillis, b.PushTimeMillis); order != 0 {
			return order
		}
		return a.EntryId.Cmp(b.EntryId)
	})
	seen := map[Id]bool{}
	return slices.DeleteFunc(views, func(view *DirectoryErasureRequestView) bool {
		if seen[view.RequestId] {
			return true
		}
		seen[view.RequestId] = true
		return false
	})
}

// What erased entryId, for a reader's line beside an erased entry: a directory admin's erasure, and a repo owner's
// revocation when its note names an erasure_request (§16.11's readers row); false for an entry no ERASE or erasure
// entry this copy holds names.
func (self *DirectoryClient) ErasureOf(entryId Id) (*DirectoryErasure, bool) {
	part := self.revocations()
	seen := func() *DirectoryErasure {
		part.stateLock.Lock()
		defer part.stateLock.Unlock()
		if erasure, ok := part.entryErasures[entryId]; ok {
			copied := *erasure
			return &copied
		}
		return nil
	}()
	if seen == nil {
		for _, entry := range self.erasureEntries() {
			if !slices.ContainsFunc(entry.body.GetEntryIds(), func(named []byte) bool { return len(named) == len(Id{}) && recordIdOf(named) == entryId }) {
				continue
			}
			seen = &DirectoryErasure{EraserSidecarId: entry.writerId, ErasureId: recordIdOf(entry.body.GetErasureId()), Reason: RecordErasureReason(entry.body.GetReason())}
			if seen.Reason == RecordErasureReasonRevocation && len(entry.body.GetRequestId()) == len(Id{}) {
				requestId := recordIdOf(entry.body.GetRequestId())
				seen.RequestId = &requestId
			}
			break
		}
	}
	if seen == nil {
		return nil, false
	}
	if seen.RequestId != nil {
		for _, request := range self.ErasureRequests() {
			if request.RequestId == *seen.RequestId {
				repoId := request.RepoId
				seen.RepoId = &repoId
			}
		}
	}
	return seen, true
}

// DaemonDirectoryBackends.Revoke: the call's Sidecar's revocation of repoId, the daemon having run the method only
// for a confirmed call.
func DirectoryRevokeBackend(ctx context.Context, sidecar *Sidecar, repoId Id) (any, error) {
	client := sidecar.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
	}
	return client.RevokeRepo(ctx, &DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
}
