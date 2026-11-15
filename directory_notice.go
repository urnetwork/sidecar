//go:build !ios_extension

// §16.11's notices (RECORD-M6-18; the repo table's q/ rows, its path rules and repair row, D-MCP-30): one file
// q/<h>/<tgt>/<rid> on the cards ref for each request, at most 256 B, written by path CAS. A notice names the request,
// its requester and the request entry's seq, never an approver: readers compute the target's approvers from their own
// state.
//
//	accept    a reader takes a notice version only by its push's signer and auth pin (I-EVS-14): pending with no
//	          decision, written by the requester whose stream holds the request; pending with the first approval of a
//	          rule that asks two, or decided, written by a decider the notice names who is eligible for the target at
//	          that pin; a version that names another request, requester, seq or expiry than the request entry's is
//	          none. A breach is ignored with a path_rule alarm, once a version, and the reader shows the version it
//	          last accepted meanwhile
//	repair    every file here is current state its rightful writer reproduces: the requester's daemon re-creates a
//	          pending notice from its request entry when the path holds none or a version no rule takes, which is also
//	          how a crash between the entry and the notice is repaired
//	leases    an approver's device leases q/<h>/<tgt>/ for every target it approves, and a requester's each pending
//	          notice's own path (§11.10), never the cards ref
//
// The copy keeps the newest file of a path and nothing of a removal, so a removal is taken as it comes: who removed a
// notice is not judged here, and the request's entries then say its state (directory_request.go).
//
// A phone keeps no copy and runs no sync (§16.11's phones row, D-MCP-31), so from M8 it holds its leases from what it
// keeps itself (RECORD-M8-01; D-SDK-28, D-MCP-34, §18.7, FS-85, FS-100), through DirectoryPhoneNotices:
//
//	leases    q/<h>/<tgt>/ for each target its member approves, by the state now (a repo whose requests this device
//	          decides; a worker of its member's as far as the client's items name one), and each of its own requests'
//	          notice paths from its filing until the request closes or not_after + NoticeGrace passes; never the
//	          cards ref, d/ or r/ (D-MCP-31)
//	hints     a lease's hint is evs's for the directory's repo, evs:<repo_id> (§11.10's hint row), a wake class, so
//	          §18.7 wakes the phone with topic class evs and a version, naming no directory, target or request (WK4)
//	renew     Resync, which the app host runs at each of its resyncs (its open, each wake, hourly while open), renews
//	          a lease once PhoneLeaseRenewAge old, at once rather than within the next hour, since a phone may not run
//	          an hour: a phone that slept a week renews at its next resync. A lease held PhoneLeaseExpiry had lapsed,
//	          and so had any this process did not hold, so their paths are read again once held, as §11.10's loss row
//	          reads every subscribed head. Nothing renews for a reconnect
//	epochs    a lease names plaintext: the DirectoryCards binding tokenizes it in the cards ref's current path epoch
//	          and re-creates it at a PATH_EPOCH, as EvsRepo.Subscribe does (§11.10's epochs row)
//	receipt   RECORD-M6-19's (directory_receipt.go) from head reads in place of a copy: at a hint on its own notice's
//	          path the phone reads that notice and, at decided, each entry its DecisionRefs name by a head read of its
//	          decider's stream, and nothing else; its own request entry it read once, when it filed (D-MCP-34)
//	approver  at a hint on a prefix the phone lists it and reads each new pending notice's request entry by a head
//	          read, raising access_request once for each it decides now, which Incoming answers for
//	          SidecarApprovals.GetPending
//	close     Close ends this process's part and releases nothing: evs keeps each lease until it lapses, so a closed
//	          app is still woken, and the next process takes them again
//
// A phone decides through the same journal as a desktop (RECORD-M6-19's DirectoryDecideJournal over its approval
// ledger), but Decide and Cancel still read the copy's fold, which a phone does not keep, so on a phone they answer
// ErrDirectoryRequestUnknown.
//
// Barriers: directory.notice.before and .after around each write and removal, keyed by the request's id.

package sidecar

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A notice version this reader accepted.
type directoryNoticeAccepted struct {
	version uint64
	notice  *protocol.DirectoryNotice
	// the push's signer and pin
	signerSidecarId Id
	authPin         *bridge.AuthPin
}

// The pending notice of a request, as its requester writes it at creation and in repair.
func directoryPendingNotice(view *DirectoryRequestView) *protocol.DirectoryNotice {
	return &protocol.DirectoryNotice{
		RequestId:          view.RequestId.Bytes(),
		RequesterSidecarId: view.RequesterSidecarId.Bytes(),
		EntrySeq:           view.EntrySeq,
		NotAfterMillis:     view.Request.GetNotAfterMillis(),
		State:              uint32(DirectoryNoticeStatePending),
	}
}

// Whether a notice names a decider.
func directoryNoticeNames(notice *protocol.DirectoryNotice, deciderSidecarId Id) bool {
	return slices.ContainsFunc(notice.GetDecisions(), func(ref *protocol.DecisionRef) bool {
		return Id(ref.GetDeciderSidecarId()) == deciderSidecarId
	})
}

// Whether file is a version of view's notice the path rules take, and the notice it holds. unknown is true when the
// state at the file's pin could not be asked, which neither takes the version nor calls it a breach.
func (self *DirectoryAccessRequests) judgeNotice(auth DirectoryAuthView, view *DirectoryRequestView, file *DirectoryCardFile) (notice *protocol.DirectoryNotice, taken bool, unknown bool) {
	notice, err := DirectoryDecodeNotice(file.Content)
	if err != nil {
		return nil, false, false
	}
	if Id(notice.GetRequestId()) != view.RequestId || Id(notice.GetRequesterSidecarId()) != view.RequesterSidecarId ||
		notice.GetEntrySeq() != view.EntrySeq || notice.GetNotAfterMillis() != view.Request.GetNotAfterMillis() {
		return nil, false, false
	}
	pending := DirectoryNoticeState(notice.GetState()) == DirectoryNoticeStatePending
	if pending && len(notice.GetDecisions()) == 0 {
		return notice, file.SignerSidecarId == view.RequesterSidecarId, false
	}
	// a rewrite: by a decider it names, eligible for the target at the push's pin
	if !directoryNoticeNames(notice, file.SignerSidecarId) {
		return nil, false, false
	}
	decides, err := auth.Decides(view.Request, view.RequesterSidecarId, file.SignerSidecarId, file.AuthPin)
	if err != nil {
		return nil, false, true
	}
	if !decides {
		return nil, false, false
	}
	approvers, err := auth.EligibleApprovers(view.Request, view.RequesterSidecarId, file.AuthPin)
	if err != nil {
		return nil, false, true
	}
	approved := DirectoryOutcome(notice.GetOutcome()) == DirectoryOutcomeApproved
	switch {
	case pending && approvers.Count < 2:
		// the first approval of a rule that asks one decides it
		return nil, false, false
	case !pending && approved && len(notice.GetDecisions()) < approvers.Count:
		return nil, false, false
	}
	return notice, true, false
}

// The version of view's notice this reader shows: file's when the path rules take it, else the one it last accepted,
// nil for none. A breach alarms once a version.
func (self *DirectoryAccessRequests) acceptNotice(auth DirectoryAuthView, view *DirectoryRequestView, file *DirectoryCardFile) *directoryNoticeAccepted {
	path := view.NoticePath
	if file == nil {
		// removed, or never written
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.accepted, path)
		}()
		return nil
	}
	held := func() *directoryNoticeAccepted {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.accepted[path]
	}()
	if held != nil && held.version == file.Version {
		return held
	}
	notice, taken, unknown := self.judgeNotice(auth, view, file)
	if taken {
		accepted := &directoryNoticeAccepted{version: file.Version, notice: notice, signerSidecarId: file.SignerSidecarId, authPin: file.AuthPin}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.accepted[path] = accepted
		return accepted
	}
	if !unknown {
		alarm := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.breached[path] == file.Version {
				return false
			}
			self.breached[path] = file.Version
			return true
		}()
		if alarm {
			signerSidecarId := file.SignerSidecarId
			directoryId, _ := self.client.DirectoryId()
			self.client.raise(SidecarRecordAlarmPathRule, directoryId, &signerSidecarId)
		}
	}
	return held
}

// Writes a notice at path from the version read, by path CAS, under pushId: the path's new version.
func (self *DirectoryAccessRequests) putNotice(ctx context.Context, path string, ifVersion uint64, notice *protocol.DirectoryNotice, pushId Id) (uint64, error) {
	if err := DirectoryCheckNotice(notice); err != nil {
		return 0, err
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(notice)
	if err != nil {
		return 0, err
	}
	hookKey := recordChainIdText(Id(notice.GetRequestId()))
	testHookBarrier("directory.notice.before", hookKey)
	version, err := self.client.PutCard(ctx, &DirectoryCardWrite{
		PushId: pushId, Path: path, IfVersion: ifVersion, Content: content, AuthPin: self.client.auth().Pin(),
	})
	testHookBarrier("directory.notice.after", hookKey)
	return version, err
}

// Removes the notice at path from the version read, by path CAS, under pushId.
func (self *DirectoryAccessRequests) removeNotice(ctx context.Context, requestId Id, path string, ifVersion uint64, pushId Id) error {
	hookKey := recordChainIdText(requestId)
	testHookBarrier("directory.notice.before", hookKey)
	err := self.client.RemoveCard(ctx, &DirectoryCardWrite{PushId: pushId, Path: path, IfVersion: ifVersion, AuthPin: self.client.auth().Pin()})
	testHookBarrier("directory.notice.after", hookKey)
	return err
}

// Whether err is a path CAS's conflict: another write, or a removal, landed since the version read.
func directoryPathConflict(err error) bool {
	code, ok := RecordStreamRefusalCode(err)
	return ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT
}

// The requester's repair (the path rules' repair row): each of this sidecar's own requests still pending by its
// entries and before not_after, whose path holds no notice or a version no rule takes, gets its pending notice again,
// from the version the path holds. Answers how many were written. A conflict means another write landed, which the
// next sync reads.
func (self *DirectoryAccessRequests) repairNotices(ctx context.Context, fold *directoryRequestFold) (int, error) {
	written := 0
	var firstErr error
	for _, view := range fold.views {
		if !view.Mine || view.State != DirectoryRequestPending || view.Notice != nil || view.cancelEntry != nil {
			continue
		}
		ifVersion := uint64(0)
		if view.noticeFile != nil {
			ifVersion = view.noticeFile.Version
		}
		pushId, err := self.newId()
		if err != nil {
			return written, err
		}
		if _, err := self.putNotice(ctx, view.NoticePath, ifVersion, directoryPendingNotice(view), pushId); err != nil {
			if !directoryPathConflict(err) && firstErr == nil {
				firstErr = fmt.Errorf("directory notice: repair: %w", err)
			}
			continue
		}
		written += 1
	}
	return written, firstErr
}

// Holds the leases the fold calls for and releases the rest: q/<h>/<tgt>/ for every target this device decides, and
// the path of each of its own pending requests' notices. A phone's are its phone part's, which needs no fold.
func (self *DirectoryAccessRequests) maintainLeases(fold *directoryRequestFold) {
	if self.client.PhoneNotices() != nil {
		return
	}
	wanted := map[string]bool{}
	for _, prefix := range self.approverPrefixes() {
		wanted[prefix] = true
	}
	for _, view := range fold.views {
		if view.Mine && (view.State == DirectoryRequestPending || view.State == DirectoryRequestDenied) {
			// a denied one is still leased until it is closed, so a repo approval that a denial beat still arrives
			wanted[view.NoticePath] = true
		}
	}
	releases := []func(){}
	missing := []string{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for prefix, release := range self.leases {
			if !wanted[prefix] {
				releases = append(releases, release)
				delete(self.leases, prefix)
			}
		}
		for prefix := range wanted {
			if _, ok := self.leases[prefix]; !ok {
				missing = append(missing, prefix)
			}
		}
	}()
	for _, release := range releases {
		release()
	}
	slices.Sort(missing)
	for _, prefix := range missing {
		release, err := self.client.Lease(prefix)
		if err != nil {
			continue
		}
		kept := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if _, ok := self.leases[prefix]; ok || self.closed {
				return false
			}
			self.leases[prefix] = release
			return true
		}()
		if !kept {
			release()
		}
	}
}

// The notice prefixes of the targets this device decides now (§16.11's notify row): each live repo whose requests it
// decides, an admin's for its repos and an owner's consented device for an owner-bound one, and each worker of its own
// member's or sponsored by it, itself among them. Sockets' prefixes wait on §9's listeners, which name a socket's
// owner.
func (self *DirectoryAccessRequests) approverPrefixes() []string {
	auth := self.client.auth()
	sidecarId := self.client.sidecarId
	prefixes := []string{}
	for _, repo := range auth.Repos() {
		if repo == nil || !repo.Live {
			continue
		}
		target := &protocol.RequestTarget{RepoId: repo.RepoId.Bytes()}
		probe := &protocol.DirectoryRequest{Target: target}
		if decides, err := auth.Decides(probe, sidecarId, sidecarId, auth.Pin()); err != nil || !decides {
			continue
		}
		if prefix, err := DirectoryNoticePrefix(target); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	memberId, isMember := auth.MemberOf(sidecarId)
	if !isMember {
		return prefixes
	}
	workerIds := []Id{sidecarId}
	if items, err := self.client.List(&DirectoryFilter{Kind: DirectoryAnnouncementKindWorker, MemberId: &memberId}); err == nil {
		for _, item := range items {
			workerIds = append(workerIds, item.SignerSidecarId)
		}
	}
	slices.SortFunc(workerIds, Id.Cmp)
	for _, workerId := range slices.Compact(workerIds) {
		if prefix, err := DirectoryNoticePrefix(&protocol.RequestTarget{SidecarId: workerId.Bytes()}); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

// The client's phone part (RECORD-M8-01), and the store's name for what it keeps and its format.
const (
	directoryPhoneNoticesPartName = "phone_notices"
	directoryPhoneStoreName       = "phone_notices"
	directoryPhoneStoreVersion    = 1
)

var (
	// Nothing serves §11.9's head reads here: a phone reads no notice or entry at a hint, and takes no outcome.
	ErrDirectoryHeadReadUnavailable = errors.New("directory head reads unavailable")
	// An entry a head read brought does not verify, or is not the one asked for: nothing is taken from it.
	ErrDirectoryHeadEntryRefused = errors.New("directory head-read entry refused")
	// The phone part closed: nothing more is read, written or leased in this process.
	ErrDirectoryPhoneClosed = errors.New("directory phone notices closed")
)

// §11.9's head reads (R-EVS-8), which a phone takes in place of a sync (D-MCP-34: the requester reaches the outcome by
// one notice read and a head read per entry the notice names). A DirectoryCards binding that serves an app host
// implements it, or DirectoryPhoneNoticesArgs names another. Calls carry this sidecar's token, so evs says what it may
// read. Safe for concurrent use.
type DirectoryHeadReader interface {
	// The newest version of path on the directory's cards ref, with its push's signer, auth pin and time; nil with no
	// error while the path holds none, or its newest statement removed it.
	ReadCard(ctx context.Context, repoId Id, path string) (*DirectoryCardFile, error)
	// The newest version of each file under prefix on the cards ref, in path order, removed ones left out: a listing
	// of a notice prefix q/<h>/<tgt>/.
	ListCards(ctx context.Context, repoId Id, prefix string) ([]*DirectoryCardFile, error)
	// The committed push of writerSidecarId's stream that created the entry at RecordStreamPath(seq), with its slot's
	// live rows; nil with no error while the stream holds no entry there.
	ReadStreamEntry(ctx context.Context, repoId Id, writerSidecarId Id, seq uint64) (*DirectoryStreamVersion, error)
}

// What a phone's notices read with.
type DirectoryPhoneNoticesArgs struct {
	// §11.9's head reads; nil takes the bound DirectoryCards when it serves them. With neither, the phone reads nothing
	// at a hint and takes no outcome.
	Heads DirectoryHeadReader
	// Called after each hint on a lease this process holds, with no lock held: the app host's cue to schedule a
	// Resync, which it must not run from within the call, since a hint can come during one. nil for none.
	Hinted func()
}

// What one Resync did, for the app host's log and a test's counts.
type DirectoryPhoneResynced struct {
	// Leases taken where this process held none, renewed once PhoneLeaseRenewAge old, and released.
	LeasesTaken    int
	LeasesRenewed  int
	LeasesReleased int
	// Head reads: notices, prefix listings and entries.
	NoticeReads  int
	ListingReads int
	EntryReads   int
	// Pending notices written again from their entries (the repair row).
	Repaired int
	// access_decided raised, and access_request raised.
	Decided   int
	Requested int
}

// One lease a phone holds in this process.
type directoryPhoneLease struct {
	release        func()
	leasedAtMillis int64
}

// One of this phone's own requests, kept in place of a copy.
type directoryPhoneRequestRow struct {
	NoticePath     string `json:"notice_path"`
	NotAfterMillis int64  `json:"not_after_millis"`
	// The request entry's seq in this sidecar's stream, 0 while it waits in the spool.
	EntrySeq uint64 `json:"entry_seq"`
	// The entry as a head read verified it: SHA-256 of its Signed header as stored, and its body as stored; empty
	// until that read.
	EntrySha256 []byte `json:"entry_sha256,omitempty"`
	Body        []byte `json:"body,omitempty"`
	// Its pending notice landed, as far as this phone knows.
	NoticeWritten bool `json:"notice_written,omitempty"`
	// access_decided's outcome once raised, "" before; whether the member's vault recorded it; whether its notice was
	// removed (the close row).
	Outcome  string `json:"outcome,omitempty"`
	Recorded bool   `json:"recorded,omitempty"`
	Closed   bool   `json:"closed,omitempty"`
}

// What a phone keeps, in the client's store.
type directoryPhoneDocument struct {
	Version int `json:"version"`
	// This phone's own requests, by the request's id in hex.
	Requests map[string]*directoryPhoneRequestRow `json:"requests"`
	// The requests access_request was raised for, by id in hex, with their not_after, so a restart raises none again.
	Raised map[string]int64 `json:"raised"`
}

// A phone's notice leases and what it reads at a wake: see the file's header.
type DirectoryPhoneNotices struct {
	requests *DirectoryAccessRequests
	client   *DirectoryClient

	// one Resync, or one filing's note, at a time; taken after the requests' writeLock
	writeLock sync.Mutex

	stateLock  sync.Mutex
	heads      DirectoryHeadReader
	hintedFunc func()
	// path or prefix -> its lease in this process
	leases map[string]*directoryPhoneLease
	// paths and prefixes to read at the next Resync: hinted, taken fresh, or lapsed
	due map[string]bool
	// the pending requests this phone decides, as its last resync read them, by request id
	incoming map[Id]*DirectoryRequestView
	closed   bool
}

// Binds this client's phone part, which an app host on a phone calls once in place of running the client's sync
// (§16.11's phones row): from then on its leases are the part's, never the fold's. ErrDirectoryReadOnly on a
// read_only client. Binding again replaces the args.
func (self *DirectoryClient) BindPhoneNotices(args *DirectoryPhoneNoticesArgs) (*DirectoryPhoneNotices, error) {
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	requests := self.Requests()
	phone := self.part(directoryPhoneNoticesPartName, func() any {
		return &DirectoryPhoneNotices{
			requests: requests,
			client:   self,
			leases:   map[string]*directoryPhoneLease{},
			due:      map[string]bool{},
			incoming: map[Id]*DirectoryRequestView{},
		}
	}).(*DirectoryPhoneNotices)
	if args == nil {
		args = &DirectoryPhoneNoticesArgs{}
	}
	phone.stateLock.Lock()
	defer phone.stateLock.Unlock()
	phone.heads = args.Heads
	phone.hintedFunc = args.Hinted
	return phone, nil
}

// This client's phone part, nil until BindPhoneNotices: a desktop's client has none.
func (self *DirectoryClient) PhoneNotices() *DirectoryPhoneNotices {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	phone, _ := self.parts[directoryPhoneNoticesPartName].(*DirectoryPhoneNotices)
	return phone
}

// What File runs once a request is filed: on a phone, its phone part keeps it and leases its notice's path at once;
// nothing on a client with no phone part. The caller holds writeLock.
func (self *DirectoryAccessRequests) notePhoneFiled(ctx context.Context, filed *DirectoryRequestFiled) {
	if filed == nil {
		return
	}
	if phone := self.client.PhoneNotices(); phone != nil {
		phone.noteFiled(ctx, filed)
	}
}

// The head reads bound now: the args', else the bound DirectoryCards when it serves them.
func (self *DirectoryPhoneNotices) headReader() (DirectoryHeadReader, bool) {
	heads := func() DirectoryHeadReader {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.heads
	}()
	if heads != nil {
		return heads, true
	}
	heads, ok := self.client.boundCards().(DirectoryHeadReader)
	return heads, ok
}

func (self *DirectoryPhoneNotices) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// What this phone keeps, an empty document for none. One that does not read is an error, never empty, which would
// drop its requests' leases.
func (self *DirectoryPhoneNotices) load() (*directoryPhoneDocument, error) {
	document := &directoryPhoneDocument{
		Version:  directoryPhoneStoreVersion,
		Requests: map[string]*directoryPhoneRequestRow{},
		Raised:   map[string]int64{},
	}
	content, err := self.client.store.readFile(directoryPhoneStoreName)
	if err != nil || content == nil {
		return document, err
	}
	kept := &directoryPhoneDocument{}
	if err := json.Unmarshal(content, kept); err != nil || kept.Version != directoryPhoneStoreVersion {
		return nil, fmt.Errorf("%w: the phone's notices do not read", ErrDirectoryStoreCorrupt)
	}
	if kept.Requests == nil {
		kept.Requests = map[string]*directoryPhoneRequestRow{}
	}
	if kept.Raised == nil {
		kept.Raised = map[string]int64{}
	}
	return kept, nil
}

func (self *DirectoryPhoneNotices) keep(document *directoryPhoneDocument) error {
	return self.client.store.writeDocument(directoryPhoneStoreName, document)
}

// Keeps a request this phone filed, reads its entry once, and leases its notice's path at once, so the decision's
// rewrite wakes the phone. Best effort: what fails here the next Resync does. The caller holds the requests'
// writeLock.
func (self *DirectoryPhoneNotices) noteFiled(ctx context.Context, filed *DirectoryRequestFiled) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.isClosed() {
		return
	}
	directoryId, ok := self.client.DirectoryId()
	if !ok {
		return
	}
	document, err := self.load()
	if err != nil {
		self.client.log.Infof("[directory]a phone's request is not kept: %s", err)
		return
	}
	row := &directoryPhoneRequestRow{
		NoticePath:     filed.NoticePath,
		NotAfterMillis: filed.NotAfterMillis,
		EntrySeq:       filed.EntrySeq,
		NoticeWritten:  filed.NoticeWritten,
	}
	document.Requests[recordChainIdText(filed.RequestId)] = row
	if heads, ok := self.headReader(); ok && 0 < row.EntrySeq {
		if err := self.readOwnEntry(ctx, heads, directoryId, filed.RequestId, row); err != nil {
			self.client.log.Infof("[directory]a phone's request entry is not read yet: %s", err)
		}
	}
	if err := self.keep(document); err != nil {
		self.client.log.Infof("[directory]a phone's request is not kept: %s", err)
		return
	}
	self.holdLeases(directoryId, self.wantedLeases(document), &DirectoryPhoneResynced{})
	// its notice was written before the lease: nothing to read for it yet
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.due, row.NoticePath)
}

// The paths and prefixes this phone leases now: q/<h>/<tgt>/ for each target it decides, and each own request's
// notice path until it closes or not_after + NoticeGrace passes. A phone announces no worker item (§16.11's worker
// row), so its own id is no target.
func (self *DirectoryPhoneNotices) wantedLeases(document *directoryPhoneDocument) map[string]bool {
	wanted := map[string]bool{}
	ownPrefix, err := DirectoryNoticePrefix(&protocol.RequestTarget{SidecarId: self.client.sidecarId.Bytes()})
	if err != nil {
		ownPrefix = ""
	}
	for _, prefix := range self.requests.approverPrefixes() {
		if prefix != ownPrefix {
			wanted[prefix] = true
		}
	}
	nowMillis := self.client.clock.Now().UnixMilli()
	grace := self.requests.settings().NoticeGrace.Milliseconds()
	for _, row := range document.Requests {
		if !row.Closed && nowMillis <= row.NotAfterMillis+grace {
			wanted[row.NoticePath] = true
		}
	}
	return wanted
}

// The callback of the lease on path: marks it due and cues the app host.
func (self *DirectoryPhoneNotices) hintFunc(path string) func(repoId Id) {
	return func(repoId Id) {
		hinted := func() func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil
			}
			self.due[path] = true
			return self.hintedFunc
		}()
		if hinted != nil {
			hinted()
		}
	}
}

// Holds wanted and releases the rest (the file's header's leases, renew and epochs rows). A lease is taken again
// before the one it renews goes, so evs holds it throughout. One this process did not hold, or held PhoneLeaseExpiry,
// is due to be read once it is held, since what changed while none stood is unknown.
func (self *DirectoryPhoneNotices) holdLeases(directoryId Id, wanted map[string]bool, resynced *DirectoryPhoneResynced) {
	settings := self.client.settings
	nowMillis := self.client.clock.Now().UnixMilli()
	renewAge := settings.PhoneLeaseRenewAge.Milliseconds()
	expiry := settings.PhoneLeaseExpiry.Milliseconds()
	releases := []func(){}
	takes := []string{}
	lapsed := map[string]bool{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for path, lease := range self.leases {
			if !wanted[path] {
				releases = append(releases, lease.release)
				delete(self.leases, path)
			}
		}
		for path := range wanted {
			lease, held := self.leases[path]
			switch {
			case !held:
				takes = append(takes, path)
				lapsed[path] = true
			case lease.leasedAtMillis+renewAge <= nowMillis:
				takes = append(takes, path)
				lapsed[path] = lease.leasedAtMillis+expiry <= nowMillis
			}
		}
	}()
	for _, release := range releases {
		release()
		resynced.LeasesReleased += 1
	}
	slices.Sort(takes)
	cards := self.client.boundCards()
	for _, path := range takes {
		if !DirectoryLeasePathAllowed(path) {
			continue
		}
		release, err := cards.Lease(directoryId, path, self.hintFunc(path))
		if err != nil {
			// taken at the next resync
			continue
		}
		old, kept := func() (*directoryPhoneLease, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil, false
			}
			old := self.leases[path]
			self.leases[path] = &directoryPhoneLease{release: release, leasedAtMillis: nowMillis}
			if lapsed[path] {
				self.due[path] = true
			}
			return old, true
		}()
		if !kept {
			release()
			continue
		}
		if old != nil {
			old.release()
			resynced.LeasesRenewed += 1
		} else {
			resynced.LeasesTaken += 1
		}
	}
}

// One entry read by a head read and verified alone: RECORD.md section 5.5's steps 2, 3 and 5, its header's Signed
// under its writer's identity key, its writer's right in its own stream at its push's pin, and its body opened with its
// slot row and held to its commitment and its kind's caps. Step 4, its place in its writer's chain, is not judged: a
// head reader holds no chain (D-MCP-34, R-EVS-8). Version 1 alone, a device's own entry, as requests and decisions
// are.
type directoryHeadEntry struct {
	writerSidecarId Id
	seq             uint64
	header          *StoredRecordHeader
	signedBytes     []byte
	body            []byte
	pushPin         *bridge.AuthPin
	pushTimeMillis  int64
}

// The entry at seq in writerId's stream, read and verified: nil with no error while it is not there, or the state has
// not reached its push's pin; ErrDirectoryHeadEntryRefused, with a bad_entry alarm once an entry, when it does not
// verify.
func (self *DirectoryPhoneNotices) readEntry(ctx context.Context, heads DirectoryHeadReader, directoryId Id, writerId Id, seq uint64) (*directoryHeadEntry, error) {
	version, err := heads.ReadStreamEntry(ctx, directoryId, writerId, seq)
	if err != nil || version == nil || version.Version == nil {
		return nil, err
	}
	refuse := func(why string) (*directoryHeadEntry, error) {
		if self.requests.raiseOnce(fmt.Sprintf("head_entry/%s/%d", recordChainIdText(writerId), seq)) {
			self.client.raise(SidecarRecordAlarmBadEntry, directoryId, &writerId)
		}
		return nil, fmt.Errorf("%w: %s", ErrDirectoryHeadEntryRefused, why)
	}
	path, err := RecordStreamPath(seq)
	if err != nil {
		return nil, err
	}
	var streamEntry *RecordStreamEntry
	for _, entry := range version.Version.Entries {
		if entry != nil && entry.Path == path {
			streamEntry = entry
		}
	}
	if streamEntry == nil {
		return refuse("a push that holds no entry at the seq's path")
	}
	fields := &recordEntryFields{}
	if err := fields.parse(streamEntry.Entry); err != nil {
		return refuse("an entry that does not parse")
	}
	arrival := &RecordEntryArrival{StreamSidecarId: writerId, PushPin: version.Version.AuthPin, UnretainedAtHead: true}
	verified, err := VerifyRecordEntry(self.client.recordAuth(), directoryId, fields.signed, arrival)
	if errors.Is(err, ErrRecordAuthAhead) {
		return nil, nil
	}
	if err != nil {
		return refuse(err.Error())
	}
	header := verified.Header
	if recordIdOf(header.Header.GetWriterSidecarId()) != writerId || header.Header.GetSeq() != seq {
		return refuse("an entry of another writer or seq")
	}
	if max(fields.version, recordEntryVersion) != recordEntryVersion {
		return refuse("an entry of another version than a device's own")
	}
	if len(fields.keySlotId) != len(Id{}) || Id(fields.keySlotId) != version.Version.SlotId || version.Slot == nil {
		// its key is gone: an erased entry, which nothing is taken from
		return nil, fmt.Errorf("%w: its key is gone", ErrDirectoryHeadEntryRefused)
	}
	var row []byte
	for _, slotRow := range version.Slot.Rows {
		if slotRow != nil && slotRow.KeyIndex == fields.keyIndex {
			row = slotRow.Row
		}
	}
	if row == nil {
		return nil, fmt.Errorf("%w: its key is gone", ErrDirectoryHeadEntryRefused)
	}
	key, salt, err := RecordSlotRowSplit(row)
	if err != nil {
		return refuse("a slot row that does not split")
	}
	body, err := RecordOpen(header, fields.sealedBody, key, salt)
	clear(key)
	clear(salt)
	if err != nil {
		return refuse("a body that does not open or commit")
	}
	if err := RecordBodyValidateStored(header.Kind(), body); err != nil {
		return refuse("a body past its kind's caps")
	}
	return &directoryHeadEntry{
		writerSidecarId: writerId,
		seq:             seq,
		header:          header,
		signedBytes:     verified.SignedBytes,
		body:            body,
		pushPin:         proto.Clone(version.Version.AuthPin).(*bridge.AuthPin),
		pushTimeMillis:  version.Version.TimeMillis,
	}, nil
}

// Reads this phone's own request entry once, by a head read, and keeps its header's hash and its body, so a receipt
// reads nothing of this sidecar's stream at a wake.
func (self *DirectoryPhoneNotices) readOwnEntry(ctx context.Context, heads DirectoryHeadReader, directoryId Id, requestId Id, row *directoryPhoneRequestRow) error {
	entry, err := self.readEntry(ctx, heads, directoryId, self.client.sidecarId, row.EntrySeq)
	if err != nil || entry == nil {
		return err
	}
	if entry.header.Kind() != RecordKindRequest {
		return fmt.Errorf("%w: its own entry at seq %d is no request", ErrDirectoryHeadEntryRefused, row.EntrySeq)
	}
	stored, err := DirectoryDecodeRequest(entry.body)
	if err != nil {
		return err
	}
	if Id(stored.Request.GetRequestId()) != requestId {
		return fmt.Errorf("%w: its own entry at seq %d is another request", ErrDirectoryHeadEntryRefused, row.EntrySeq)
	}
	sum := DirectoryEntryHeaderSha256(entry.signedBytes)
	row.EntrySha256 = sum[:]
	row.Body = entry.body
	return nil
}

// This phone's own request as a view, from what it keeps: nil until its entry was read.
func (self *DirectoryPhoneNotices) rowView(requestId Id, row *directoryPhoneRequestRow) *DirectoryRequestView {
	if len(row.EntrySha256) != len(DirectoryEntryHeaderSha256(nil)) || len(row.Body) == 0 {
		return nil
	}
	stored, err := DirectoryDecodeRequest(row.Body)
	if err != nil {
		return nil
	}
	targetKind, err := DirectoryRequestTargetKind(stored.Request.GetTarget())
	if err != nil {
		return nil
	}
	view := &DirectoryRequestView{
		RequestId:          requestId,
		RequesterSidecarId: self.client.sidecarId,
		Request:            stored.Request,
		Stored:             stored,
		TargetKind:         targetKind,
		EntrySeq:           row.EntrySeq,
		NoticePath:         row.NoticePath,
		State:              DirectoryRequestPending,
		Mine:               true,
	}
	copy(view.EntrySha256[:], row.EntrySha256)
	return view
}

// Where a phone's receipt reads a decision entry: its decider's stream at the path its seq names, by a head read.
type directoryPhoneReceiptSource struct {
	phone       *DirectoryPhoneNotices
	heads       DirectoryHeadReader
	directoryId Id
	resynced    *DirectoryPhoneResynced
}

// The entry, read and verified alone. An entry that is no decision binds no request, so the receipt refuses it with
// its alarm.
func (self *directoryPhoneReceiptSource) DecisionEntry(ctx context.Context, deciderSidecarId Id, seq uint64) (*DirectoryDecisionView, error) {
	self.resynced.EntryReads += 1
	entry, err := self.phone.readEntry(ctx, self.heads, self.directoryId, deciderSidecarId, seq)
	if err != nil || entry == nil {
		return nil, err
	}
	view := &DirectoryDecisionView{
		DeciderSidecarId: entry.writerSidecarId,
		EntryId:          recordIdOf(entry.header.Header.GetEntryId()),
		Seq:              seq,
		HeaderSha256:     DirectoryEntryHeaderSha256(entry.signedBytes),
		Decision:         &protocol.DirectoryDecision{},
		PushPin:          entry.pushPin,
		PushTimeMillis:   entry.pushTimeMillis,
	}
	if entry.header.Kind() == RecordKindDecision {
		if stored, err := DirectoryDecodeDecision(entry.body); err == nil {
			view.Decision, view.Stored = stored.Decision, stored
		}
	}
	return view, nil
}

// Raises access_decided with outcome once for the row, keeping it.
func (self *DirectoryPhoneNotices) decided(requestId Id, row *directoryPhoneRequestRow, outcome string, resynced *DirectoryPhoneResynced) error {
	if row.Outcome == outcome {
		return nil
	}
	row.Outcome = outcome
	resynced.Decided += 1
	if events := self.requests.bound().Events; events != nil {
		return events.RaiseAccessDecided(requestId, outcome)
	}
	return nil
}

// Reads one of this phone's own notices by a head read and takes what it says: a decided one by RECORD-M6-19's
// receipt, its entries by head reads, then the close row; a pending one past not_after, or none, is expired. Answers
// false while it must be read again: its decision's entries or statement not there yet.
func (self *DirectoryPhoneNotices) receiveRow(ctx context.Context, heads DirectoryHeadReader, directoryId Id, requestId Id, row *directoryPhoneRequestRow, resynced *DirectoryPhoneResynced) (bool, error) {
	nowMillis := self.client.clock.Now().UnixMilli()
	grace := self.requests.settings().NoticeGrace.Milliseconds()
	expired := row.Outcome == "" && row.NotAfterMillis < nowMillis
	view := self.rowView(requestId, row)
	if view == nil {
		// its entry was never read, so nothing can be judged: an entry that never landed had no notice to decide, so
		// past not_after + NoticeGrace the request is expired
		if row.Outcome == "" && row.NotAfterMillis+grace < nowMillis {
			return true, self.decided(requestId, row, SidecarAccessDecidedExpired, resynced)
		}
		return false, nil
	}
	resynced.NoticeReads += 1
	file, err := heads.ReadCard(ctx, directoryId, row.NoticePath)
	if err != nil {
		return false, err
	}
	if file == nil {
		if expired {
			return true, self.decided(requestId, row, SidecarAccessDecidedExpired, resynced)
		}
		if row.Outcome == "" {
			// gone before a decision: its repair writes it again
			row.NoticeWritten = false
		}
		return true, nil
	}
	auth := self.client.auth()
	if _, _, unknown := self.requests.judgeNotice(auth, view, file); unknown {
		// the state cannot judge its version yet
		return false, nil
	}
	accepted := self.requests.acceptNotice(auth, view, file)
	current := accepted != nil && accepted.version == file.Version
	if !current && row.Outcome == "" {
		// a version no rule takes, alarmed: the repair writes this request's pending notice over it
		row.NoticeWritten = false
	}
	if accepted == nil || DirectoryNoticeState(accepted.notice.GetState()) != DirectoryNoticeStateDecided {
		if expired {
			return true, self.decided(requestId, row, SidecarAccessDecidedExpired, resynced)
		}
		if current && accepted.signerSidecarId == self.client.sidecarId {
			row.NoticeWritten = true
		}
		return true, nil
	}
	view.Notice, view.NoticeVersion, view.noticeFile = accepted.notice, accepted.version, file
	outcome := SidecarAccessDecidedDenied
	if DirectoryOutcome(accepted.notice.GetOutcome()) == DirectoryOutcomeApproved {
		outcome = SidecarAccessDecidedApproved
	}
	if row.Outcome != outcome || !row.Recorded {
		source := &directoryPhoneReceiptSource{phone: self, heads: heads, directoryId: directoryId, resynced: resynced}
		receipt, err := self.requests.Receive(ctx, view, source)
		if err != nil {
			return false, err
		}
		if receipt == nil {
			return false, nil
		}
		if row.Outcome != outcome {
			// a denial that an approval's rewrite beat is received again as the approval
			row.Recorded = false
		}
		if err := self.decided(requestId, row, outcome, resynced); err != nil {
			return true, err
		}
		row.Recorded = row.Recorded || receipt.Recorded
	}
	// close: an approved notice once the vault recorded it, a denied one past not_after + NoticeGrace, each from the
	// version the path holds
	closes := (outcome == SidecarAccessDecidedApproved && row.Recorded) ||
		(outcome == SidecarAccessDecidedDenied && row.NotAfterMillis+grace < nowMillis)
	if !closes || row.Closed || !current {
		return true, nil
	}
	pushId, err := self.requests.newId()
	if err != nil {
		return true, err
	}
	if err := self.requests.removeNotice(ctx, requestId, row.NoticePath, accepted.version, pushId); err != nil {
		if directoryPathConflict(err) {
			// another write landed: read again
			return false, nil
		}
		return true, err
	}
	row.Closed = true
	return true, nil
}

// Writes again the pending notice of an own request that did not land (the path rules' repair row): the path read
// first, so a notice of this request that a rule takes stands, and one that no rule takes is written over.
func (self *DirectoryPhoneNotices) repairRow(ctx context.Context, heads DirectoryHeadReader, directoryId Id, requestId Id, row *directoryPhoneRequestRow, resynced *DirectoryPhoneResynced) error {
	view := self.rowView(requestId, row)
	if view == nil {
		return nil
	}
	resynced.NoticeReads += 1
	file, err := heads.ReadCard(ctx, directoryId, row.NoticePath)
	if err != nil {
		return err
	}
	ifVersion := uint64(0)
	if file != nil {
		notice, taken, unknown := self.requests.judgeNotice(self.client.auth(), view, file)
		if taken || unknown {
			// it landed, or it stands until the state can judge it
			row.NoticeWritten = notice != nil || unknown
			return nil
		}
		ifVersion = file.Version
	}
	pushId, err := self.requests.newId()
	if err != nil {
		return err
	}
	if _, err := self.requests.putNotice(ctx, row.NoticePath, ifVersion, directoryPendingNotice(view), pushId); err != nil {
		if directoryPathConflict(err) {
			return nil
		}
		return err
	}
	row.NoticeWritten = true
	resynced.Repaired += 1
	return nil
}

// Lists a prefix this phone leases, by a head read, and reads each new pending notice's request entry, raising
// access_request once for each this device decides now. What it reads it keeps for Incoming.
func (self *DirectoryPhoneNotices) readPrefix(ctx context.Context, heads DirectoryHeadReader, directoryId Id, prefix string, document *directoryPhoneDocument, resynced *DirectoryPhoneResynced) error {
	resynced.ListingReads += 1
	files, err := heads.ListCards(ctx, directoryId, prefix)
	if err != nil {
		return err
	}
	auth := self.client.auth()
	sidecarId := self.client.sidecarId
	nowMillis := self.client.clock.Now().UnixMilli()
	seen := map[Id]bool{}
	var firstErr error
	for _, file := range files {
		if file == nil || !strings.HasPrefix(file.Path, prefix) {
			continue
		}
		notice, err := DirectoryDecodeNotice(file.Content)
		if err != nil {
			continue
		}
		requestId := Id(notice.GetRequestId())
		requesterId := Id(notice.GetRequesterSidecarId())
		if file.Path != prefix+directoryIdText(requestId) || requesterId == sidecarId ||
			DirectoryNoticeState(notice.GetState()) != DirectoryNoticeStatePending || notice.GetNotAfterMillis() < nowMillis {
			continue
		}
		seen[requestId] = true
		held := func() *DirectoryRequestView {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.incoming[requestId]
		}()
		if held != nil && held.NoticeVersion == file.Version {
			continue
		}
		resynced.EntryReads += 1
		entry, err := self.readEntry(ctx, heads, directoryId, requesterId, notice.GetEntrySeq())
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if entry == nil || entry.header.Kind() != RecordKindRequest || auth.Masked(requesterId) {
			continue
		}
		stored, err := DirectoryDecodeRequest(entry.body)
		if err != nil || Id(stored.Request.GetRequestId()) != requestId {
			continue
		}
		request := stored.Request
		// the subject is the requester's own: itself, or its member
		subject := Id(request.GetSubject())
		memberId, isMember := auth.MemberOf(requesterId)
		if (request.GetSubjectIsMember() && (!isMember || subject != memberId)) || (!request.GetSubjectIsMember() && subject != requesterId) {
			continue
		}
		targetKind, err := DirectoryRequestTargetKind(request.GetTarget())
		if err != nil {
			continue
		}
		if path, err := DirectoryNoticePath(request.GetTarget(), requestId); err != nil || path != file.Path {
			continue
		}
		view := &DirectoryRequestView{
			RequestId:          requestId,
			RequesterSidecarId: requesterId,
			Request:            request,
			Stored:             stored,
			TargetKind:         targetKind,
			EntryId:            recordIdOf(entry.header.Header.GetEntryId()),
			EntrySeq:           entry.seq,
			EntrySha256:        DirectoryEntryHeaderSha256(entry.signedBytes),
			PushPin:            entry.pushPin,
			PushTimeMillis:     entry.pushTimeMillis,
			NoticePath:         file.Path,
			State:              DirectoryRequestPending,
		}
		accepted := self.requests.acceptNotice(auth, view, file)
		if accepted == nil {
			continue
		}
		view.Notice, view.NoticeVersion, view.noticeFile = accepted.notice, accepted.version, file
		if decides, err := auth.Decides(request, requesterId, sidecarId, auth.Pin()); err != nil || !decides {
			continue
		}
		view.Decidable = true
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.incoming[requestId] = view
		}()
		key := recordChainIdText(requestId)
		if _, raised := document.Raised[key]; raised {
			continue
		}
		document.Raised[key] = request.GetNotAfterMillis()
		resynced.Requested += 1
		if events := self.requests.bound().Events; events != nil {
			if err := events.RaiseAccessRequest(requestId); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	// what left the prefix's pending notices leaves Incoming
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for requestId, view := range self.incoming {
		if strings.HasPrefix(view.NoticePath, prefix) && !seen[requestId] {
			delete(self.incoming, requestId)
		}
	}
	return firstErr
}

// One resync of a phone's notices, which the app host runs at its open, at each wake and hourly while it stays open
// (§18.7's resync), in place of a sync. In order: its own requests kept, each entry not read yet read once, and each
// pending notice that did not land written again (the repair row); the leases held, renewed and released; then each
// path or prefix a hint, a fresh lease or a lapse made due, read by head reads: an own notice that turned decided
// received by RECORD-M6-19's receipt, one past not_after reported expired, and each new pending notice under a prefix
// read with its request entry and raised once as access_request. ErrDirectoryHeadReadUnavailable when something is due
// and nothing serves head reads; what did not settle stays due.
func (self *DirectoryPhoneNotices) Resync(ctx context.Context) (*DirectoryPhoneResynced, error) {
	self.requests.writeLock.Lock()
	defer self.requests.writeLock.Unlock()
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.isClosed() {
		return nil, ErrDirectoryPhoneClosed
	}
	directoryId, ok := self.client.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	resynced := &DirectoryPhoneResynced{}
	document, err := self.load()
	if err != nil {
		return resynced, err
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	nowMillis := self.client.clock.Now().UnixMilli()
	grace := self.requests.settings().NoticeGrace.Milliseconds()
	heads, headsBound := self.headReader()

	// own requests: what is done goes, what was not read is read, what did not land is written again
	keys := slices.Sorted(maps.Keys(document.Requests))
	for _, key := range keys {
		row := document.Requests[key]
		requestId, err := ParseId(key)
		if err != nil {
			delete(document.Requests, key)
			continue
		}
		if row.NotAfterMillis+grace < nowMillis && row.Outcome != "" {
			delete(document.Requests, key)
			continue
		}
		if !headsBound || row.EntrySeq == 0 {
			continue
		}
		if len(row.EntrySha256) == 0 {
			resynced.EntryReads += 1
			if err := self.readOwnEntry(ctx, heads, directoryId, requestId, row); err != nil {
				note(err)
				continue
			}
		}
		if !row.NoticeWritten && row.Outcome == "" && nowMillis <= row.NotAfterMillis {
			note(self.repairRow(ctx, heads, directoryId, requestId, row, resynced))
		}
	}
	for key, notAfterMillis := range document.Raised {
		if notAfterMillis+grace < nowMillis {
			delete(document.Raised, key)
		}
	}

	// leases
	wanted := self.wantedLeases(document)
	self.holdLeases(directoryId, wanted, resynced)

	// reads: what is due, and an own request past not_after with no outcome yet
	due := func() map[string]bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		due := self.due
		self.due = map[string]bool{}
		return due
	}()
	stillDue := map[string]bool{}
	for _, key := range keys {
		row, ok := document.Requests[key]
		if !ok || !(due[row.NoticePath] || (row.Outcome == "" && row.NotAfterMillis < nowMillis)) {
			continue
		}
		delete(due, row.NoticePath)
		if !headsBound {
			stillDue[row.NoticePath] = true
			continue
		}
		requestId, _ := ParseId(key)
		settled, err := self.receiveRow(ctx, heads, directoryId, requestId, row, resynced)
		note(err)
		if !settled {
			stillDue[row.NoticePath] = true
		}
	}
	for _, prefix := range slices.Sorted(maps.Keys(due)) {
		if !wanted[prefix] || !strings.HasSuffix(prefix, "/") {
			continue
		}
		if !headsBound {
			stillDue[prefix] = true
			continue
		}
		if err := self.readPrefix(ctx, heads, directoryId, prefix, document, resynced); err != nil {
			note(err)
			stillDue[prefix] = true
		}
	}
	if !headsBound && 0 < len(stillDue) {
		note(ErrDirectoryHeadReadUnavailable)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for path := range stillDue {
			self.due[path] = true
		}
	}()
	note(self.keep(document))
	return resynced, firstErr
}

// The pending requests this phone decides, as its last resync read them, older first: what SidecarApprovals.GetPending
// shows as access_request. Nothing is read here.
func (self *DirectoryPhoneNotices) Incoming() []*DirectoryRequestView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	views := []*DirectoryRequestView{}
	for _, view := range self.incoming {
		copied := *view
		views = append(views, &copied)
	}
	slices.SortFunc(views, func(a *DirectoryRequestView, b *DirectoryRequestView) int {
		return cmp.Or(cmp.Compare(a.PushTimeMillis, b.PushTimeMillis), a.RequestId.Cmp(b.RequestId))
	})
	return views
}

// The paths and prefixes this process holds leases on, sorted.
func (self *DirectoryPhoneNotices) Leased() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.leases))
}

// Ends this process's part: nothing more is read, written or leased, and no lease is released, so evs keeps each
// until it lapses and a closed app is still woken; the next process takes them again.
func (self *DirectoryPhoneNotices) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.leases = map[string]*directoryPhoneLease{}
	self.due = map[string]bool{}
}
