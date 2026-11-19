//go:build !ios_extension && !sidecar_http

// §16.11's Erasure and removal block, M6's half (RECORD-M6-20; R-MCP-16, D-MCP-27, D-MCP-33, I-EVS-16, FS-99,
// FS-87): a directory admin's erasure, and the directory's erasure runner. A daemon's alone: the sidecar_http leg,
// the console's page Worker, links none of it, and no app host builds a runner.
//
//	authority  every key destruction in the directory takes admin, which evs checks before any commit (I-EVS-16): the
//	           ERASEs here go through the record's RecordEraser over the directory log (BindEraser), which refuses a
//	           device that is no admin of it, and through nothing else
//	erase      a directory admin's `ur directory erase <id>`, a person's confirmed act: for an entry, 16.8's per-entry
//	           ERASE; for an announcement, the ERASE of every announce entry of its item, M6's form of the card's
//	           erasure. Its reason is moderation when another sidecar wrote any of them, a person's otherwise
//	runner     a network-scope indexer that is itself a directory admin, else each directory admin's daemon. It runs
//	           after each sync of its client: every erasure_request entry is checked, its signer holding D-MCP-35's
//	           right on the repo at the entry's push's pin, the repo's private marker still its newest item, and no
//	           full item of the repo accepted above the request's marker, now or since: a request a full item replaced
//	           lapsed for good, so a later revocation's marker, a higher version, revives none (owner decision 472;
//	           DirectoryErasureRequestView.LapsedVersion). Then each earlier announce entry for the repo, and each
//	           run's that names it, is erased, every ERASE's note naming the request, whose id is the erasure's
//	           (plan-RECORD-small-readings #12). The work waits 0-10 min from the sync that first showed it, so the
//	           first commit wins and a later runner, which has synced that ERASE, finds nothing left; two that race
//	           both send, and evs answers the second NOTHING_TO_ERASE. While the marker stands, for 30 days from the
//	           request, each later sync erases any copy a daemon wrote since. A request whose check fails erases
//	           nothing and alarms bad_erasure, naming its signer, once
//	superseded a request whose signer held the right, whose own marker this copy no longer opens, while a later marker
//	           of its repo stands (QD-1061; DirectoryClient.requestSuperseded): a later request's ERASEs took the
//	           marker, with the item that lapsed the request on a copy that never opened it, or before the request was
//	           worked. It is not worked, not pending and raises nothing, and no bad_erasure: later copies go under the
//	           newer request, whose marker stands
//	expiry     the runner also runs the directory's retention expiry (RECORD-M6-03) through Expire: an announce entry
//	           is held until 30 days after a newer entry or file for its item, or its item's expiry, so a live repo
//	           item keeps its newest copy (directory_retention.go's hold), and then the weekly admin BASE (Base). A
//	           request whose work waits for its delay keeps its own marker from expiry, which under a later marker
//	           would read it superseded with its copies unerased
//	waiting    a request no ERASE names is pending, and is never dropped: past 24 h every directory admin's device
//	           raises directory_erasure, pending, and done once it is erased; StatusLines names each one past 24 h and
//	           the oldest waiting
//
// Format 2's half (RECORD-M10-05; §11.12's cut, rekey, versionless, reconcile and directory rows, §11.14's cut and
// erase rows, DESIGN-DETAILS 15.2.10's directory note; FI-19, FS-87, FS-99), from the directory's first format-2 push,
// when announcements ride cards and repo files and the index holds a document an announcement:
//
//	copies     an announcement's copies beside its M6 announce entries: its document a/ || writer || announcement_id (a
//	           repo's a/ || announcement_id) on the cards ref's own index, from the card or repo file holding it, and on
//	           the streams' ur/index, where its announce entries folded into it; and the stored versions of the file
//	           itself, every version of a versionless d/ or r/ path sealed under the one key its slot holds until a
//	           CLOSURE draws another
//	order      the announce entries' ERASEs first, as at M6, so a body never waits on index work (§11.12's closure
//	           row); then a CUT on the cards ref and on ur/index listing the documents at the newest version erased,
//	           through each ref's eraser (DirectoryErasureIndex, the index's IndexEraser), which folds nothing again:
//	           an announcement's document goes whole (15.2.10); then each ref's CLOSURE and ERASE pairs over its index
//	           files (IndexEraser.Rewrite); then a CLOSURE a file, rewriting in place under a fresh key each card and
//	           repo file whose earlier versions held a document, and its ERASE of every key a stored version of the
//	           file names. The files go last so that the ERASE that says the erasure complete names keys that stand:
//	           a ref whose index holds none of the documents sends no ERASE. Every ERASE of a file's keys, and the
//	           index's completing one, carries as its sealed note an ErasureBody naming the erasure, its reason and,
//	           for a revocation, the request, whose id is the erasure's
//	files      a CLOSURE rewrites the file's standing bytes, which are still its rightful writer's Signed: the eraser
//	           signs no card and no repo file. So it rewrites a file only once its standing version no longer holds
//	           the document: the repo file once the marker stands over it, a card once its writer wrote the run private
//	           or left it out. A card whose standing version still holds one waits for its writer, which rewrites it
//	           at its next write after reading the marker, and is caught at a later sync, for 30 days; a directory
//	           admin's own erase takes such a card by moderation's removal (§16.11's path rules) and the ERASE of its
//	           keys, and refuses an announcement that stands on a repo file, which only its owner's revocation takes
//	           (question record-m10-05-card-closure-content)
//	revoke     the runner works a request's files as its entries: the repo file's versions below the marker, each
//	           card holding a run that names the repo, and their documents; a later-signed card naming the repo is
//	           cut at the sync that shows it and rewritten once its writer has, while the marker stands, for 30 days
//	ledger     what this device cut, rewrote and still owes of each erasure is kept in the copy (erasure files), so a
//	           later sync repeats nothing; a file whose standing version another admin's CLOSURE left reads as
//	           rewritten there. Two runners that race meet at the path's CAS and at evs: one CLOSURE commits, the
//	           other's is a conflict it reads past, and a second ERASE of keys already gone is done
//	resume     from evs's state (§11.12's reconcile row): once a process an erasure, and whenever the ledger shows a
//	           CLOSURE of this device that may stand alone, which it journals before sending one, an ERASE for each
//	           CLOSURE of the cards ref no ERASE followed; and each index ref's rewrite again, which erases its own
//	           orphans first. A person's erasure this device began is resumed at its next erase or pass
//	authority  CUT, CLOSURE, their uploads and ERASE take admin, which evs checks before any commit or slot rewrite
//	           (I-EVS-16): the calls go through DirectoryErasureFiles alone, and with none bound nothing of this half
//	           is cut, rewritten or erased (ErrDirectoryErasureFilesUnbound)
//
// Barriers: directory.erasure.erase.before, before a request's first ERASE, keyed by the request's id;
// directory.erasure.cut.before, before an erasure's CUT on a ref, and directory.erasure.closure.before and .after
// around a file's CLOSURE, the ERASE of its old keys following .after, each keyed by the erasure's id.
//
// Safe for concurrent use: one pass at a time, and one erasure's files at a time a client.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// Only a directory admin erases in the directory (D-MCP-33): nothing was erased.
	ErrDirectoryEraseNotAdmin = errors.New("directory erase: not a directory admin")
	// A directory admin's erasure is a person's act (§5.8): nothing was erased.
	ErrDirectoryEraseUnconfirmed = errors.New("directory erase is a person's act")
	// No eraser is bound to the client, so nothing is erased.
	ErrDirectoryEraserUnbound = errors.New("directory eraser unbound")
	// Format 2's erasure of cards, repo files and index files has no binding to the directory's evs
	// (DirectoryErasureFiles): nothing of that half is cut, rewritten or erased.
	ErrDirectoryErasureFilesUnbound = errors.New("directory erasure: no binding for the cards ref and the index")
	// The announcement stands on its repo's file, which only a repo admin signs and removes (§16.11's path rules): its
	// owner's revocation takes it, and the runner then erases what named it. Nothing was erased.
	ErrDirectoryEraseStanding = errors.New("directory erase: the announcement stands on its repo file, which its owner revokes")
)

const (
	directoryEraserPart        = "eraser"
	directoryErasureRunnerPart = "erasure runner"
	directoryErasureFilesPart  = "erasure files"
	// the copy's name for what this device cut, rewrote and owes of each erasure, and its document's version
	directoryErasureFilesStoreName    = "erasure_files"
	directoryErasureFilesStoreVersion = 1
)

// The directory log's eraser: RecordEraser.Erase of the record whose writer the client appends through.
type DirectoryEraseFunction func(ctx context.Context, args *RecordEraseArgs) (*RecordEraseResult, error)

// What the runner runs by.
type DirectoryErasureSettings struct {
	// The most a runner waits after the sync that first showed it work: 10 min, the wait drawn in 0 to this (§16.11's
	// runner row).
	Delay time.Duration
	// How long after a request later copies naming its repo are still erased, while the marker stands: 30 days.
	SweepWindow time.Duration
	// A request waiting past this raises directory_erasure on every directory admin's device: 24 h.
	PendingAlarm time.Duration
	// How long an announce entry is held after a newer entry for its item, or its item's expiry: 30 days (§16.11's
	// retention row).
	AnnounceHold time.Duration
	// The entries one erasure names, RecordEraserSettings.EntryCount's: 512. A request with more takes several.
	EntryCount int
	// How long a device keeps what it cut and rewrote of an erasure with nothing owed, from when it first worked it:
	// 60 days, twice the sweep window, so no sync inside the window repeats a rewrite.
	LedgerHold time.Duration
}

// §16.11's values.
func DefaultDirectoryErasureSettings() *DirectoryErasureSettings {
	return &DirectoryErasureSettings{
		Delay:        10 * time.Minute,
		SweepWindow:  30 * 24 * time.Hour,
		PendingAlarm: 24 * time.Hour,
		AnnounceHold: 30 * 24 * time.Hour,
		EntryCount:   512,
		LedgerHold:   60 * 24 * time.Hour,
	}
}

// One erasure a directory admin asks.
type DirectoryEraseArgs struct {
	// An entry's id, or an announcement's.
	Id Id
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
	// The caller has a harness process among its ancestors: the erasure is refused.
	HarnessAncestor bool
}

// What a directory admin's erasure did.
type DirectoryEraseResult struct {
	ErasureId Id
	// The entries whose keys are gone.
	EntryIds []Id
	Reason   RecordErasureReason
	// Format 2's half: what was cut, rewritten and removed of the cards ref and the index; nil where the
	// announcement had no copy there.
	Files *DirectoryErasureFilesResult
}

// The client's bound eraser.
type directoryEraser struct {
	stateLock sync.Mutex
	erase     DirectoryEraseFunction
}

// Binds the directory log's eraser, nil for none: until one is bound nothing here erases.
func (self *DirectoryClient) BindEraser(erase DirectoryEraseFunction) {
	part := self.part(directoryEraserPart, func() any { return &directoryEraser{} }).(*directoryEraser)
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	part.erase = erase
}

// The bound eraser, nil for none.
func (self *DirectoryClient) boundEraser() DirectoryEraseFunction {
	part := self.part(directoryEraserPart, func() any { return &directoryEraser{} }).(*directoryEraser)
	part.stateLock.Lock()
	defer part.stateLock.Unlock()
	return part.erase
}

// Whether this sidecar is a directory admin at the state now.
func (self *DirectoryClient) directoryAdmin(auth DirectoryAuthView) (bool, []Id, error) {
	admins, err := auth.DirectoryAdmins(auth.Pin())
	if err != nil {
		return false, nil, err
	}
	return slices.Contains(admins, self.sidecarId), admins, nil
}

// A directory admin's erasure of an entry or of an announcement's entries: see the file's header's erase row.
func (self *DirectoryClient) Erase(ctx context.Context, args *DirectoryEraseArgs) (*DirectoryEraseResult, error) {
	if args == nil || args.Id == (Id{}) {
		return nil, fmt.Errorf("%w: an erasure names an announcement or an entry", ErrDirectoryFormatInvalid)
	}
	if !args.Confirmed || args.HarnessAncestor {
		return nil, ErrDirectoryEraseUnconfirmed
	}
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return nil, ErrDirectoryNone
	}
	admin, _, err := self.directoryAdmin(auth)
	if err != nil {
		return nil, err
	}
	if !admin {
		return nil, ErrDirectoryEraseNotAdmin
	}
	erase := self.boundEraser()
	if erase == nil {
		return nil, ErrDirectoryEraserUnbound
	}
	format2 := self.Format2()
	if format2 {
		// a person's erasure of files a kill left unfinished goes first, under its own id
		if err := self.resumeErasureFiles(ctx); err != nil && !errors.Is(err, ErrDirectoryErasureFilesUnbound) {
			return nil, err
		}
	}
	entryIds := []Id{}
	reason := RecordErasureReasonPerson
	take := func(entry *RecordReadEntry) {
		entryIds = append(entryIds, entry.EntryId)
		if recordIdOf(entry.Header.Header.GetWriterSidecarId()) != self.sidecarId {
			reason = RecordErasureReasonModeration
		}
	}
	// format 2's copies of an announcement: a holding card goes by moderation's removal
	work := newDirectoryErasureWork()
	work.own = true
	work.remove = true
	for _, entry := range self.allEntries() {
		if entry.Header == nil || entry.Header.Header == nil || entry.State.KeyGone() {
			continue
		}
		if entry.EntryId == args.Id {
			take(entry)
			continue
		}
		if entry.Header.Kind() != RecordKindAnnounce || entry.Body == nil {
			continue
		}
		if item, err := DirectoryDecodeAnnouncement(entry.Body); err == nil && recordIdOf(item.GetAnnouncementId()) == args.Id {
			take(entry)
			if format2 {
				work.addStreamDocument(entry, item)
			}
		}
	}
	standingRepoFile := false
	if format2 {
		standingRepoFile = self.announcementFiles(args.Id, work)
		for _, holding := range work.holding {
			if holding.rightfulId != self.sidecarId {
				reason = RecordErasureReasonModeration
			}
		}
	}
	if len(entryIds) == 0 && !work.found() && !standingRepoFile {
		return nil, fmt.Errorf("%w: no entry or announcement %s with a key left to erase", ErrDirectoryItemNone, args.Id)
	}
	if standingRepoFile {
		// before anything is erased: the file would go on showing what the entries and the index no longer hold
		return nil, ErrDirectoryEraseStanding
	}
	if work.found() && self.erasureFiles() == nil {
		return nil, ErrDirectoryErasureFilesUnbound
	}
	result := &DirectoryEraseResult{ErasureId: NewId(), Reason: reason}
	if 0 < len(entryIds) {
		erased, err := erase(ctx, &RecordEraseArgs{LogId: directoryId, EntryIds: entryIds, Reason: reason, Confirmed: true})
		if err != nil {
			return nil, err
		}
		result.ErasureId = erased.ErasureId
		result.EntryIds = erased.Erased
	}
	if work.found() {
		work.erasureId = result.ErasureId
		work.reason = reason
		files, err := self.eraseFiles(ctx, work)
		result.Files = files
		if err != nil {
			// what committed stands, and the ledger resumes the rest under this id
			self.ViewSync()
			return result, err
		}
	}
	self.ViewSync()
	return result, nil
}

// DaemonDirectoryBackends.Erase: the call's Sidecar's erasure of id through its record's eraser, the daemon having
// run the method only for a confirmed call.
func DirectoryEraseBackend(ctx context.Context, sidecar *Sidecar, id Id) (any, error) {
	client := sidecar.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
	}
	record, err := sidecar.Record()
	if err != nil {
		return nil, err
	}
	client.BindEraser(record.Eraser().Erase)
	return client.Erase(ctx, &DirectoryEraseArgs{Id: id, Confirmed: true})
}

// What a runner is made over.
type DirectoryErasureRunnerArgs struct {
	Client *DirectoryClient
	// The directory log's eraser; nil takes the client's bound one at each pass.
	Erase DirectoryEraseFunction
	// The directory's retention expiry, RecordRetention.Expire with hold as its Hold; nil runs none.
	Expire func(ctx context.Context, directoryId Id, hold func(entry *RecordReadEntry) bool) error
	// The directory's admin BASE once due, RecordRetention.DirectoryBase; nil runs none.
	Base func(ctx context.Context, directoryId Id) (int, bool, error)
	// The network-scope indexers at the state now (ConfigState.Indexers); nil for none known, when every directory
	// admin's daemon runs.
	Indexers func() []Id
	// Sidecar.RaiseDirectoryErasure; nil raises nothing.
	Raise func(repoId Id, requestId Id, outcome string) error
	// The delay's randomness; nil for the system's.
	Random   io.Reader
	Settings *DirectoryErasureSettings
}

// One request still waiting, as a directory admin's device names it.
type DirectoryErasurePending struct {
	Request *DirectoryErasureRequestView
	Age     time.Duration
}

// What one pass of the runner did.
type DirectoryErasurePass struct {
	// This daemon is the runner now.
	Runs bool
	// Each request it erased copies for, with the entries.
	Erased map[Id][]Id
	// The requests whose check failed at this pass.
	Refused []Id
	// The requests it read as superseded at this pass: neither worked, pending nor raised.
	Superseded []Id
	// The requests whose work waits for its delay.
	Delayed []Id
	// The requests still pending after it.
	Pending []*DirectoryErasurePending
	// Format 2's half: what the pass cut, rewrote and erased of the cards ref and the index for each request.
	Files map[Id]*DirectoryErasureFilesResult
	// The requests a card still names the repo for at its standing version: its writer rewrites it, and a later
	// pass rewrites it under a fresh key.
	Waiting []Id
	// The directory is at format 2 and no binding reaches its cards ref and index: the requests' files wait.
	FilesUnbound bool
}

// The directory's erasure runner on one daemon: see the file's header.
type DirectoryErasureRunner struct {
	client   *DirectoryClient
	erase    DirectoryEraseFunction
	expire   func(ctx context.Context, directoryId Id, hold func(entry *RecordReadEntry) bool) error
	base     func(ctx context.Context, directoryId Id) (int, bool, error)
	indexers func() []Id
	raise    func(repoId Id, requestId Id, outcome string) error
	random   io.Reader
	settings *DirectoryErasureSettings

	// one pass at a time
	passLock sync.Mutex

	stateLock sync.Mutex
	// when each request's waiting work may run, set at the sync that first showed it
	dueMillis map[Id]int64
	// the requests whose failed check alarmed
	refused map[Id]bool
	// the outcome last raised for each request
	raised map[Id]string
}

// A runner over args, which runs a pass after each sync of its client. It erases nothing on a device that is not the
// runner at the state of the pass.
func NewDirectoryErasureRunner(args *DirectoryErasureRunnerArgs) (*DirectoryErasureRunner, error) {
	if args == nil || args.Client == nil {
		return nil, fmt.Errorf("%w: an erasure runner needs a directory client", ErrDirectoryCardsUnavailable)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDirectoryErasureSettings()
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	self := &DirectoryErasureRunner{
		client: args.Client, erase: args.Erase, expire: args.Expire, base: args.Base, indexers: args.Indexers, raise: args.Raise, random: random,
		settings: settings, dueMillis: map[Id]int64{}, refused: map[Id]bool{}, raised: map[Id]string{},
	}
	if 0 < settings.LedgerHold {
		state := args.Client.erasureFilesState()
		func() {
			state.stateLock.Lock()
			defer state.stateLock.Unlock()
			state.ledgerHold = settings.LedgerHold
		}()
	}
	args.Client.addSyncHook(func(ctx context.Context) {
		if _, err := self.Pass(ctx); err != nil {
			self.client.log.Infof("[directory]the erasure runner stopped: %s", err)
		}
	})
	return self, nil
}

// The Sidecar's erasure runner, made once over its directory client, its record's eraser and retention and the
// config's indexers: what the daemon's composition calls beside the directory's component.
func (self *Sidecar) DirectoryErasureRunner() (*DirectoryErasureRunner, error) {
	client, err := self.DirectoryClient()
	if err != nil {
		return nil, err
	}
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	var made error
	runner, _ := client.part(directoryErasureRunnerPart, func() any {
		client.BindEraser(record.Eraser().Erase)
		if cards, ok := client.boundCards().(*DirectoryEvsCards); ok {
			// format 2's half over the directory's own evs binding; any other binding leaves it unbound, and it waits
			files, err := NewDirectoryEvsErasure(&DirectoryEvsErasureArgs{Cards: cards, IsAdmin: client.erasureAdmin})
			if err != nil {
				made = err
				return nil
			}
			client.BindErasureFiles(files)
		}
		runner, err := NewDirectoryErasureRunner(&DirectoryErasureRunnerArgs{
			Client: client,
			Expire: func(ctx context.Context, directoryId Id, hold func(entry *RecordReadEntry) bool) error {
				_, err := record.Retention().Expire(ctx, &RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
				return err
			},
			Base: record.Retention().DirectoryBase,
			Indexers: func() []Id {
				state, err := self.configState()
				if err != nil {
					return nil
				}
				ids := []Id{}
				for _, indexer := range state.Indexers() {
					if indexer.Scope == protocol.IndexerScope_INDEXER_SCOPE_NETWORK {
						ids = append(ids, indexer.SidecarId)
					}
				}
				return ids
			},
			Raise: self.RaiseDirectoryErasure,
		})
		if err != nil {
			made = err
			return nil
		}
		return runner
	}).(*DirectoryErasureRunner)
	if runner == nil {
		return nil, made
	}
	return runner, nil
}

// Whether this daemon is the runner at admins: a network-scope indexer that is itself a directory admin, else every
// directory admin's daemon.
func (self *DirectoryErasureRunner) runs(admin bool, admins []Id) bool {
	if !admin || self.client.readOnly {
		return false
	}
	if self.indexers == nil {
		return true
	}
	indexerAdmin := false
	for _, indexerId := range self.indexers() {
		if indexerId == self.client.sidecarId {
			return true
		}
		indexerAdmin = indexerAdmin || slices.Contains(admins, indexerId)
	}
	return !indexerAdmin
}

// The runner's reading of one request's check.
type directoryErasureCheck int

const (
	// Its signer held the right at its pin and its marker stands.
	directoryErasureCheckPassed directoryErasureCheck = iota + 1
	// Not judged yet: its pin is ahead of this state, or its marker has not been read.
	directoryErasureCheckWaits
	// Its signer held no right on the repo at its pin.
	directoryErasureCheckNoRight
	// A full item above its marker stands, or replaced it since: the repo was announced again, and the request lapsed
	// for good.
	directoryErasureCheckLapsed
	// This copy no longer opens its own marker, and a later marker of the repo stands: the newer request's ERASEs
	// cover every copy it could name (QD-1061).
	directoryErasureCheckSuperseded
)

// §16.11's revoke row's step 3 for one request.
func (self *DirectoryErasureRunner) check(auth DirectoryAuthView, request *DirectoryErasureRequestView, nowMillis int64) directoryErasureCheck {
	if request.LapsedVersion != 0 {
		// a full item replaced its marker: whatever marker stands now, a later revocation's among them, the request
		// erases nothing (owner decision 472)
		return directoryErasureCheckLapsed
	}
	if request.PushPin == nil {
		return directoryErasureCheckNoRight
	}
	position := request.PushPin.GetVersion()
	right, err := auth.RepoAdminRight(request.RepoId, request.SignerSidecarId, position)
	switch {
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryErasureCheckWaits
	case err != nil, !right, auth.SignatureVoided(request.SignerSidecarId, position):
		return directoryErasureCheckNoRight
	}
	repo, ok := auth.Repo(request.RepoId)
	if !ok {
		return directoryErasureCheckNoRight
	}
	standing := self.client.standingRepoItem(auth, request.RepoId, nowMillis)
	switch {
	case standing == nil && !repo.Live:
		// the item ended with its repo; the copies that name it are still the request's
		return directoryErasureCheckPassed
	case standing == nil:
		return directoryErasureCheckWaits
	case self.client.requestSuperseded(standing, request.RepoId, request.MarkerVersion):
		// after the signer's right, so a request with none still alarms; before the standing marker passes it
		return directoryErasureCheckSuperseded
	case standing.Display == DirectoryItemPrivate && request.MarkerVersion <= standing.Announcement.GetVersion():
		return directoryErasureCheckPassed
	case standing.Display != DirectoryItemPrivate && request.MarkerVersion < standing.Announcement.GetVersion():
		return directoryErasureCheckLapsed
	}
	// the marker has not been read or judged yet
	return directoryErasureCheckWaits
}

// The entries with a key left that a request erases: each announce entry for the repo's item below the marker's
// version, and each run's announce entry that names the repo. An archived copy still names the repo, so it is among
// them.
func (self *DirectoryErasureRunner) copiesNaming(request *DirectoryErasureRequestView) []Id {
	entryIds := []Id{}
	for _, entry := range self.client.entriesOfKinds(RecordKindAnnounce) {
		if (entry.State != RecordEntryLive && entry.State != RecordEntryArchived) || entry.Body == nil || entry.BodyInvalid {
			continue
		}
		item, err := DirectoryDecodeAnnouncement(entry.Body)
		if err != nil || recordIdOf(item.GetWhere().GetRepoId()) != request.RepoId {
			continue
		}
		switch DirectoryAnnouncementKind(item.GetKind()) {
		case DirectoryAnnouncementKindRepo:
			if item.GetVersion() < request.MarkerVersion {
				entryIds = append(entryIds, entry.EntryId)
			}
		case DirectoryAnnouncementKindRun:
			if !item.GetWhere().GetPrivate() {
				entryIds = append(entryIds, entry.EntryId)
			}
		}
	}
	return entryIds
}

// A wait drawn in 0 to Delay, the whole of it when no draw comes.
func (self *DirectoryErasureRunner) delay() time.Duration {
	most := self.settings.Delay
	if most <= 0 {
		return 0
	}
	draw := make([]byte, 8)
	if _, err := io.ReadFull(self.random, draw); err != nil {
		return most
	}
	return time.Duration(binary.BigEndian.Uint64(draw) % uint64(most+1))
}

// Raises directory_erasure for request once an outcome.
func (self *DirectoryErasureRunner) raiseOnce(request *DirectoryErasureRequestView, outcome string) {
	if self.raise == nil {
		return
	}
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.raised[request.RequestId] == outcome || (outcome == SidecarDirectoryErasureDone && self.raised[request.RequestId] == "") {
			// done is raised only for a request this device raised pending
			return false
		}
		self.raised[request.RequestId] = outcome
		return true
	}()
	if changed {
		if err := self.raise(request.RepoId, request.RequestId, outcome); err != nil {
			self.client.log.Infof("[directory]directory_erasure was not raised: %s", err)
		}
	}
}

// One pass: see the file's header's runner, expiry and waiting rows. On a device that is no directory admin it does
// nothing; on an admin's that is not the runner it only raises what waits past 24 h.
func (self *DirectoryErasureRunner) Pass(ctx context.Context) (*DirectoryErasurePass, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	pass := &DirectoryErasurePass{Erased: map[Id][]Id{}, Files: map[Id]*DirectoryErasureFilesResult{}}
	auth := self.client.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return pass, nil
	}
	admin, admins, err := self.client.directoryAdmin(auth)
	if err != nil {
		return nil, err
	}
	if !admin {
		return pass, nil
	}
	pass.Runs = self.runs(admin, admins)
	nowMillis := self.client.clock.Now().UnixMilli()
	erase := self.erase
	if erase == nil {
		erase = self.client.boundEraser()
	}
	var firstErr error
	format2 := self.client.Format2()
	if format2 && pass.Runs {
		// a person's erasure of files this device began and a kill left unfinished
		if err := self.client.resumeErasureFiles(ctx); err != nil && !errors.Is(err, ErrDirectoryErasureFilesUnbound) {
			firstErr = err
		}
	}
	// the requests whose work waits for its delay at this pass
	delayedRequests := []*DirectoryErasureRequestView{}
	for _, request := range self.client.ErasureRequests() {
		age := max(0, time.Duration(nowMillis-request.PushTimeMillis)*time.Millisecond)
		verdict := self.check(auth, request, nowMillis)
		if request.Erased {
			self.raiseOnce(request, SidecarDirectoryErasureDone)
		}
		switch verdict {
		case directoryErasureCheckNoRight, directoryErasureCheckLapsed:
			if request.Erased {
				// its erasure ran while its check held: nothing more is erased for it
				continue
			}
			alarm := func() bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if self.refused[request.RequestId] {
					return false
				}
				self.refused[request.RequestId] = true
				return true
			}()
			if alarm {
				signerId := request.SignerSidecarId
				self.client.raise(SidecarRecordAlarmBadErasure, directoryId, &signerId)
				pass.Refused = append(pass.Refused, request.RequestId)
			}
			continue
		case directoryErasureCheckSuperseded:
			pass.Superseded = append(pass.Superseded, request.RequestId)
			continue
		case directoryErasureCheckWaits:
			if !request.Erased {
				pass.Pending = append(pass.Pending, &DirectoryErasurePending{Request: request, Age: age})
				if self.settings.PendingAlarm < age {
					self.raiseOnce(request, SidecarDirectoryErasurePending)
				}
			}
			continue
		}
		pending := func() {
			pass.Pending = append(pass.Pending, &DirectoryErasurePending{Request: request, Age: age})
			if self.settings.PendingAlarm < age {
				self.raiseOnce(request, SidecarDirectoryErasurePending)
			}
		}
		if request.Erased && self.settings.SweepWindow < age {
			continue
		}
		if !pass.Runs || erase == nil || firstErr != nil {
			if !request.Erased {
				pending()
			}
			continue
		}
		entryIds := self.copiesNaming(request)
		// format 2's copies: the repo file's versions below the marker, the cards naming the repo and their documents
		var work *directoryErasureWork
		owed := false
		if format2 {
			work = self.fileCopies(request)
			var waits bool
			owed, waits = self.client.erasureFilesOwed(work)
			if waits {
				pass.Waiting = append(pass.Waiting, request.RequestId)
			}
		}
		if len(entryIds) == 0 && !owed {
			if !request.Erased {
				// nothing this copy reads names the repo, or what names it waits for its writer: no ERASE names the
				// request yet, so it stays pending
				pending()
			}
			continue
		}
		if owed && self.client.erasureFiles() == nil {
			// fail closed: nothing of the files is cut or erased, and the request waits
			pass.FilesUnbound = true
			owed = false
			if len(entryIds) == 0 {
				if !request.Erased {
					pending()
				}
				continue
			}
		}
		due := func() int64 {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			due, ok := self.dueMillis[request.RequestId]
			if !ok {
				due = nowMillis + self.delay().Milliseconds()
				self.dueMillis[request.RequestId] = due
			}
			return due
		}()
		if nowMillis < due {
			pass.Delayed = append(pass.Delayed, request.RequestId)
			delayedRequests = append(delayedRequests, request)
			if !request.Erased {
				pending()
			}
			continue
		}
		testHookBarrier("directory.erasure.erase.before", recordChainIdText(request.RequestId))
		for chunk := range slices.Chunk(entryIds, max(1, self.settings.EntryCount)) {
			result, err := erase(ctx, &RecordEraseArgs{
				LogId: directoryId, EntryIds: chunk, Reason: RecordErasureReasonRevocation, RequestId: request.RequestId.Bytes(),
			})
			if err != nil {
				firstErr = err
				break
			}
			pass.Erased[request.RequestId] = append(pass.Erased[request.RequestId], result.Erased...)
		}
		erasedFiles := false
		if owed && firstErr == nil {
			files, err := self.client.eraseFiles(ctx, work)
			if files != nil {
				pass.Files[request.RequestId] = files
				erasedFiles = files.erased()
			}
			if err != nil {
				firstErr = err
			}
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.dueMillis, request.RequestId)
		}()
		if !request.Erased && (firstErr != nil || (len(pass.Erased[request.RequestId]) == 0 && !erasedFiles)) {
			// no ERASE of this pass names it: a CUT alone, or a card that waits for its writer
			pending()
		}
	}
	if pass.Runs && self.expire != nil && firstErr == nil {
		entries := self.client.allEntries()
		hold := directoryAnnounceHold(entries, self.client.foldFileVersions(), nowMillis, self.settings.AnnounceHold)
		// a request whose work waits for its delay keeps its own marker: expired under a later marker, it would read
		// the request superseded with the copies it found still unerased
		delayedMarkerEntryIds := map[Id]bool{}
		for _, request := range delayedRequests {
			for _, entryId := range self.client.repoMarkerEntryIds(request.RepoId, request.MarkerVersion) {
				delayedMarkerEntryIds[entryId] = true
			}
		}
		held := func(entry *RecordReadEntry) bool {
			return delayedMarkerEntryIds[entry.EntryId] || hold(entry)
		}
		if err := self.expire(ctx, directoryId, held); err != nil {
			firstErr = err
		}
	}
	if pass.Runs && firstErr == nil {
		// the weekly admin BASE re-lists the live set (directory_retention.go)
		firstErr = self.rebase(ctx, directoryId)
	}
	if 0 < len(pass.Erased) || 0 < len(pass.Files) {
		// the copy reads its own ERASEs and rewrites at the next sync
		self.client.ViewSync()
	}
	return pass, firstErr
}

// The requests no ERASE names yet, oldest first, as this copy holds them now, with nothing erased or raised: what a
// directory admin's device names.
func (self *DirectoryErasureRunner) Pending() []*DirectoryErasurePending {
	auth := self.client.auth()
	nowMillis := self.client.clock.Now().UnixMilli()
	pending := []*DirectoryErasurePending{}
	for _, request := range self.client.ErasureRequests() {
		if request.Erased {
			continue
		}
		switch self.check(auth, request, nowMillis) {
		case directoryErasureCheckNoRight, directoryErasureCheckLapsed, directoryErasureCheckSuperseded:
			continue
		}
		pending = append(pending, &DirectoryErasurePending{Request: request, Age: max(0, time.Duration(nowMillis-request.PushTimeMillis)*time.Millisecond)})
	}
	return pending
}

// `ur status`'s directory lines on this device, with no runner made and nothing erased or raised: its own revocations
// still waiting (RevocationStatusLines), then on a directory admin's device the runner's lines (StatusLines). settings
// nil reads the defaults.
func (self *DirectoryClient) ErasureStatusLines(settings *DirectoryErasureSettings) []string {
	if settings == nil {
		settings = DefaultDirectoryErasureSettings()
	}
	lines := self.RevocationStatusLines()
	// a runner value for its reading alone: it holds no hook, eraser or timer, so it runs nothing
	reading := &DirectoryErasureRunner{client: self, settings: settings}
	lines = append(lines, reading.StatusLines()...)
	// and on a directory admin's device the oldest entry that waits for retention expiry (RECORD-M6-21)
	return append(lines, self.RetentionStatusLines(settings)...)
}

// `ur status`'s lines on a directory admin's device: each request still pending past 24 h, and the oldest waiting one
// with how many wait (§16.11's revoke and readers rows). None on a device that is no directory admin.
func (self *DirectoryErasureRunner) StatusLines() []string {
	auth := self.client.auth()
	admin, _, err := self.client.directoryAdmin(auth)
	if err != nil || !admin {
		return nil
	}
	pending := self.Pending()
	lines := []string{}
	if 0 < len(pending) {
		oldest := pending[0]
		lines = append(lines, fmt.Sprintf("directory: %d erasure request(s) wait for the erasure runner, the oldest for repo %s, %s old (request %s)",
			len(pending), oldest.Request.RepoId, directoryAgeText(oldest.Age), oldest.Request.RequestId))
	}
	for _, waiting := range pending {
		if self.settings.PendingAlarm < waiting.Age {
			lines = append(lines, fmt.Sprintf("directory: the erasure for repo %s is pending for %s, past %s (request %s, by %s)",
				waiting.Request.RepoId, directoryAgeText(waiting.Age), directoryAgeText(self.settings.PendingAlarm), waiting.Request.RequestId, waiting.Request.SignerSidecarId))
		}
	}
	return lines
}

// One index ref of the directory as its erasure reaches it: the cards ref's own index, or the streams' ur/index. The
// index's eraser of that ref (IndexEraser) with the ref's doc keys. Every push it makes takes admin.
type DirectoryErasureIndex interface {
	// The doc_key of the document registered under name on this ref (§11.14's key row).
	DocKey(name []byte) ([indexIdByteCount]byte, error)
	// The erasure's CUT on the ref: IndexEraser.Cut.
	Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error)
	// The erasure's CLOSURE and ERASE pairs over the ref's index files, resumed from evs's state: IndexEraser.Rewrite.
	Rewrite(ctx context.Context, args *IndexRewriteArgs) (*IndexRewriteResult, error)
}

// What format 2's erasure asks of the directory's evs beyond DirectoryCards (§11.12's cut, rekey, versionless,
// reconcile and directory rows). Every call that changes anything takes admin, which evs checks before any commit or
// slot rewrite (I-EVS-16); a refusal is a RecordStreamRefusal by §11.8's code. Safe for concurrent use.
type DirectoryErasureFiles interface {
	// The cards ref's own index, .ur-index/ under it.
	CardsIndex(ctx context.Context, repoId Id) (DirectoryErasureIndex, error)
	// The streams' companion index, ur/index, which a CUT creates where it is absent.
	StreamsIndex(ctx context.Context, repoId Id) (DirectoryErasureIndex, error)
	// The key of every slot a stored version of each cards ref path names, a version a hold kept included: what a
	// CLOSURE of the paths lists and the ERASE after it destroys. It fails where a path's history cannot be walked
	// whole, so no list reads complete that is not.
	CardKeys(ctx context.Context, repoId Id, paths []string) ([]*EvsErasedKey, error)
	// A CLOSURE on the cards ref for erasureId, which its note names: write's file written again in place, by its path
	// CAS, under a fresh key in a new slot, the push listing keys for the ERASE that follows. Answers the path's new
	// version. Another push at the path is PATH_CONFLICT, with nothing rewritten.
	CloseCard(ctx context.Context, repoId Id, erasureId Id, write *DirectoryCardWrite, keys []*EvsErasedKey) (uint64, error)
	// An ERASE of args.Keys, its sealed note args.Note. Keys already gone are done.
	EraseCardKeys(ctx context.Context, repoId Id, args *EvsEraseArgs) error
	// The keys erasureId's CLOSUREs on the cards ref listed that none of its ERASEs names, by evs's state: what a
	// resume erases first (§11.12's reconcile row).
	OrphanCardKeys(ctx context.Context, repoId Id, erasureId Id) ([]*EvsErasedKey, error)
}

// What an erasure's format 2 half did at one call.
type DirectoryErasureFilesResult struct {
	ErasureId Id
	// CUTs pushed, one a ref whose set gained a document.
	CutCount int
	// The cards ref's paths rewritten under a fresh key by CLOSURE, and the cards removed as moderation.
	ClosedPaths  []string
	RemovedPaths []string
	// The paths whose standing version still holds a document: each waits for its writer.
	WaitingPaths []string
	// The paths another push changed under this call: judged again at the next sync.
	ConflictPaths []string
	// Keys the cards ref's ERASEs named, and the index refs' pairs.
	ErasedKeyCount int
	IndexPairCount int
	// An index ref's erasure set is full, a rewrite waits for its allowance, or one could not prove its list whole:
	// the rest runs at a later call.
	IndexWaiting bool
	// An ERASE of this call said the erasure complete.
	Complete bool
}

// Whether an ERASE of the call named a key.
func (self *DirectoryErasureFilesResult) erased() bool {
	return 0 < self.ErasedKeyCount || 0 < self.IndexPairCount || self.Complete
}

// One cards ref path in an erasure's ledger.
type directoryErasurePathRow struct {
	// The highest path version this device read holding one of the erasure's documents, or took to hold one.
	Held uint64 `json:"held"`
	// The path version the last CLOSURE or removal of it left: no stored version at or below Held has a key once it
	// is above Held.
	Closed uint64 `json:"closed"`
	// The path version this device first met it at, with an earlier version taken to have held a document.
	Met uint64 `json:"met"`
}

// One erasure's format 2 half as this device left it.
type directoryErasureLedgerRow struct {
	// When this device first worked it, by which the ledger forgets it.
	TimeMillis int64  `json:"time_millis"`
	Reason     uint32 `json:"reason"`
	RequestId  []byte `json:"request_id,omitempty"`
	// A person's erasure this device began, which only it resumes; a request's is every runner's.
	Own   bool                                `json:"own,omitempty"`
	Paths map[string]*directoryErasurePathRow `json:"paths,omitempty"`
	// The documents its CUTs listed on each ref, by name, at their versions.
	CardsDocuments  map[string]uint64 `json:"cards_documents,omitempty"`
	StreamDocuments map[string]uint64 `json:"stream_documents,omitempty"`
	// A ref's index files are owed their rewrite since its last CUT.
	CardsRewriteOwed   bool `json:"cards_rewrite_owed,omitempty"`
	StreamsRewriteOwed bool `json:"streams_rewrite_owed,omitempty"`
	// A CLOSURE of the cards ref this device sent may stand with no ERASE after it: evs's state is read before
	// anything else.
	Unerased bool `json:"unerased,omitempty"`
	// Its last work ended with an ERASE that said complete.
	Complete bool `json:"complete,omitempty"`
}

// The document the ledger is kept in.
type directoryErasureLedgerDocument struct {
	Version  int                                   `json:"version"`
	Erasures map[string]*directoryErasureLedgerRow `json:"erasures"`
}

// The client's format 2 erasure state.
type directoryErasureFilesState struct {
	// one erasure's files at a time
	workLock sync.Mutex

	stateLock sync.Mutex
	files     DirectoryErasureFiles
	rows      map[Id]*directoryErasureLedgerRow
	loaded    bool
	// the erasures whose state at evs this process has read
	resumed map[Id]bool
	// DirectoryErasureSettings.LedgerHold, the runner's where one is built
	ledgerHold time.Duration
}

// The client's erasure files part.
func (self *DirectoryClient) erasureFilesState() *directoryErasureFilesState {
	return self.part(directoryErasureFilesPart, func() any {
		return &directoryErasureFilesState{
			rows: map[Id]*directoryErasureLedgerRow{}, resumed: map[Id]bool{}, ledgerHold: DefaultDirectoryErasureSettings().LedgerHold,
		}
	}).(*directoryErasureFilesState)
}

// Binds format 2's erasure to the directory's evs, nil for none: until one is bound nothing of the cards ref or the
// index is cut, rewritten or erased.
func (self *DirectoryClient) BindErasureFiles(files DirectoryErasureFiles) {
	state := self.erasureFilesState()
	state.stateLock.Lock()
	defer state.stateLock.Unlock()
	state.files = files
}

// The bound binding, else the client's cards binding where it is one, else nil.
func (self *DirectoryClient) erasureFiles() DirectoryErasureFiles {
	state := self.erasureFilesState()
	bound := func() DirectoryErasureFiles {
		state.stateLock.Lock()
		defer state.stateLock.Unlock()
		return state.files
	}()
	if bound != nil {
		return bound
	}
	if files, ok := self.boundCards().(DirectoryErasureFiles); ok {
		return files
	}
	return nil
}

// Whether signer is a directory admin at the state now: which erasure set and settings versions the index's eraser
// counts.
func (self *DirectoryClient) erasureAdmin(signerSidecarId Id) bool {
	auth := self.auth()
	admins, err := auth.DirectoryAdmins(auth.Pin())
	return err == nil && slices.Contains(admins, signerSidecarId)
}

// Loads the ledger once. The caller holds state.stateLock.
func (self *DirectoryClient) loadErasureLedgerWithLock(state *directoryErasureFilesState) {
	if state.loaded {
		return
	}
	state.loaded = true
	if self.store == nil || self.store.store == nil {
		return
	}
	content, err := self.store.readFile(directoryErasureFilesStoreName)
	if err != nil || content == nil {
		return
	}
	document := &directoryErasureLedgerDocument{}
	if err := json.Unmarshal(content, document); err != nil || document.Version != directoryErasureFilesStoreVersion {
		// unreadable: each erasure is read again from the copy and from evs's state, and repeats at most one rewrite
		self.log.Warningf("[directory]the kept erasure files do not read")
		return
	}
	for text, row := range document.Erasures {
		if erasureId, err := directoryParseIdText(text); err == nil && row != nil {
			state.rows[erasureId] = row
		}
	}
}

// Keeps the ledger, less the erasures with nothing owed first worked past the ledger's hold ago. The caller holds
// state.stateLock.
func (self *DirectoryClient) keepErasureLedgerWithLock(state *directoryErasureFilesState) error {
	forgetMillis := self.clock.Now().UnixMilli() - state.ledgerHold.Milliseconds()
	document := &directoryErasureLedgerDocument{Version: directoryErasureFilesStoreVersion, Erasures: map[string]*directoryErasureLedgerRow{}}
	for erasureId, row := range state.rows {
		if row.TimeMillis < forgetMillis && !row.CardsRewriteOwed && !row.StreamsRewriteOwed && !row.Unerased {
			delete(state.rows, erasureId)
			continue
		}
		document.Erasures[recordChainIdText(erasureId)] = row
	}
	if self.store == nil || self.store.store == nil {
		return nil
	}
	return self.store.writeDocument(directoryErasureFilesStoreName, document)
}

// One cards ref file an erasure reads: the version the copy accepted, and the sidecar whose Signed it is.
type directoryErasureFile struct {
	file       *DirectoryCardFile
	rightfulId Id
}

// What one erasure finds of its announcement, or of the copies naming its repo, on format 2's carriers at one sync.
type directoryErasureWork struct {
	erasureId Id
	reason    RecordErasureReason
	// a revocation's request, whose id the erasure's is
	requestId []byte
	// a person's erasure this device began
	own bool
	// some device's ERASE names the erasure already: its state at evs is read before anything else
	began bool
	// each document's name and the newest version erased, on the cards ref's index and on ur/index
	cardsDocuments  map[string]uint64
	streamDocuments map[string]uint64
	// the files whose standing version holds a document, and those an earlier version of which did
	holding []*directoryErasureFile
	held    []*directoryErasureFile
	// a holding card goes by moderation's removal; false waits for its writer
	remove bool
}

func newDirectoryErasureWork() *directoryErasureWork {
	return &directoryErasureWork{cardsDocuments: map[string]uint64{}, streamDocuments: map[string]uint64{}}
}

// Whether the sync showed any copy on format 2's carriers.
func (self *directoryErasureWork) found() bool {
	return 0 < len(self.cardsDocuments) || 0 < len(self.streamDocuments) || 0 < len(self.holding) || 0 < len(self.held)
}

// Lists the announcement document an announce entry folded into on ur/index, at the entry's item's version.
func (self *directoryErasureWork) addStreamDocument(entry *RecordReadEntry, item *protocol.Announcement) {
	writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
	name := string(directoryIndexAnnouncementName(DirectoryAnnouncementKind(item.GetKind()), writerId, recordIdOf(item.GetAnnouncementId())))
	self.streamDocuments[name] = max(self.streamDocuments[name], item.GetVersion())
}

// The sealed note of the erasure's ERASEs: its ErasureBody, naming its reason and any request.
func (self *directoryErasureWork) note() ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ErasureBody{
		ErasureId: self.erasureId.Bytes(), Reason: uint32(self.reason), RequestId: self.requestId,
	})
}

// The sidecar whose Signed a standing card or repo file is.
func directoryErasureRightful(taken *directoryAcceptedFile) Id {
	if taken.repo != nil {
		return recordIdOf(taken.repo.Signed.GetSignerId())
	}
	sidecarId, _ := directoryCardPathSidecar(taken.file.Path)
	return sidecarId
}

// Adds to work what the cards ref holds of announcement id: each card holding an item of that id, taken whole, and
// the repo file whose marker stands over it. True where the announcement itself stands on a repo file, which an
// eraser neither rewrites nor removes.
func (self *DirectoryClient) announcementFiles(id Id, work *directoryErasureWork) bool {
	standingRepoFile := false
	for _, taken := range self.files().standing() {
		erasureFile := &directoryErasureFile{file: taken.file, rightfulId: directoryErasureRightful(taken)}
		switch {
		case taken.card != nil:
			holds := false
			for _, item := range taken.card.Card.GetItems() {
				if recordIdOf(item.GetAnnouncementId()) != id {
					continue
				}
				name := string(directoryIndexAnnouncementName(DirectoryAnnouncementKind(item.GetKind()), erasureFile.rightfulId, id))
				work.cardsDocuments[name] = max(work.cardsDocuments[name], item.GetVersion())
				holds = true
			}
			if holds {
				work.holding = append(work.holding, erasureFile)
			}
		case taken.repo != nil:
			item := taken.repo.File.GetItem()
			if recordIdOf(item.GetAnnouncementId()) != id {
				continue
			}
			if !item.GetWhere().GetPrivate() {
				standingRepoFile = true
				continue
			}
			if 1 < item.GetVersion() {
				// the versions below the marker held the announcement
				name := string(directoryIndexAnnouncementName(DirectoryAnnouncementKindRepo, erasureFile.rightfulId, id))
				work.cardsDocuments[name] = max(work.cardsDocuments[name], item.GetVersion()-1)
				work.held = append(work.held, erasureFile)
			}
		}
	}
	return standingRepoFile
}

// What a request finds on format 2's carriers at this sync: the repo's file once its marker stands, the versions
// below the marker its document's; each card holding a run that names the repo, holding it still where the run is
// not private, held by an earlier version where its writer wrote it private at a raised version; and the documents
// the request's announce entries folded into on ur/index.
func (self *DirectoryErasureRunner) fileCopies(request *DirectoryErasureRequestView) *directoryErasureWork {
	work := newDirectoryErasureWork()
	work.erasureId = request.RequestId
	work.reason = RecordErasureReasonRevocation
	work.requestId = request.RequestId.Bytes()
	work.began = request.Erased
	repoPath := DirectoryRepoPath(request.RepoId)
	for _, taken := range self.client.files().standing() {
		erasureFile := &directoryErasureFile{file: taken.file, rightfulId: directoryErasureRightful(taken)}
		switch {
		case taken.card != nil:
			holds, held := false, false
			for _, item := range taken.card.Card.GetItems() {
				if DirectoryAnnouncementKind(item.GetKind()) != DirectoryAnnouncementKindRun || recordIdOf(item.GetWhere().GetRepoId()) != request.RepoId {
					continue
				}
				name := string(directoryIndexAnnouncementName(DirectoryAnnouncementKindRun, erasureFile.rightfulId, recordIdOf(item.GetAnnouncementId())))
				switch {
				case !item.GetWhere().GetPrivate():
					work.cardsDocuments[name] = max(work.cardsDocuments[name], item.GetVersion())
					holds = true
				case 1 < item.GetVersion():
					// written private at a raised version: the versions below it named the repo
					work.cardsDocuments[name] = max(work.cardsDocuments[name], item.GetVersion()-1)
					held = true
				}
			}
			switch {
			case holds:
				work.holding = append(work.holding, erasureFile)
			case held:
				work.held = append(work.held, erasureFile)
			}
		case taken.repo != nil && taken.file.Path == repoPath:
			item := taken.repo.File.GetItem()
			if !item.GetWhere().GetPrivate() || item.GetVersion() < request.MarkerVersion {
				continue
			}
			if 1 < request.MarkerVersion {
				name := string(directoryIndexAnnouncementName(DirectoryAnnouncementKindRepo, erasureFile.rightfulId, DirectoryRepoAnnouncementId(request.RepoId)))
				work.cardsDocuments[name] = max(work.cardsDocuments[name], request.MarkerVersion-1)
			}
			work.held = append(work.held, erasureFile)
		}
	}
	for _, entry := range self.client.entriesOfKinds(RecordKindAnnounce) {
		if (entry.State != RecordEntryLive && entry.State != RecordEntryArchived) || entry.Body == nil || entry.BodyInvalid {
			continue
		}
		item, err := DirectoryDecodeAnnouncement(entry.Body)
		if err != nil || recordIdOf(item.GetWhere().GetRepoId()) != request.RepoId {
			continue
		}
		switch DirectoryAnnouncementKind(item.GetKind()) {
		case DirectoryAnnouncementKindRepo:
			if item.GetVersion() < request.MarkerVersion {
				work.addStreamDocument(entry, item)
			}
		case DirectoryAnnouncementKindRun:
			if !item.GetWhere().GetPrivate() {
				work.addStreamDocument(entry, item)
			}
		}
	}
	return work
}

// The ledger's row of an erasure's path, made where absent.
func (self *directoryErasureLedgerRow) path(path string) *directoryErasurePathRow {
	if self.Paths == nil {
		self.Paths = map[string]*directoryErasurePathRow{}
	}
	row, ok := self.Paths[path]
	if !ok {
		row = &directoryErasurePathRow{}
		self.Paths[path] = row
	}
	return row
}

// Notes a file the sync showed, and answers whether its path is owed a CLOSURE: a stored version at or below Held
// still has its key. A standing version another sidecar than its rightful writer pushed is an admin's CLOSURE, so
// the path reads rewritten there; a file first met with nothing rewritten is taken to have held the document at the
// version below its standing one, none where it has only one.
func (self *directoryErasureLedgerRow) noteHeld(erasureFile *directoryErasureFile) bool {
	row := self.path(erasureFile.file.Path)
	if erasureFile.file.SignerSidecarId != erasureFile.rightfulId {
		row.Closed = max(row.Closed, erasureFile.file.Version)
	}
	if row.Met == 0 {
		row.Met = erasureFile.file.Version
		if row.Closed == 0 {
			row.Held = max(row.Held, erasureFile.file.Version-1)
		}
	}
	return 0 < row.Held && row.Closed <= row.Held
}

// Notes a file whose standing version holds a document.
func (self *directoryErasureLedgerRow) noteHolding(erasureFile *directoryErasureFile) {
	row := self.path(erasureFile.file.Path)
	row.Held = max(row.Held, erasureFile.file.Version)
}

// The documents of found the row's CUT has not listed at their version, in name order.
func directoryErasureUncut(found map[string]uint64, cut map[string]uint64) []string {
	names := []string{}
	for name, version := range found {
		if cut[name] < version {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// The erasure's row, made where absent with work's reason and request. The caller holds state.stateLock.
func (self *DirectoryClient) erasureLedgerRowWithLock(state *directoryErasureFilesState, work *directoryErasureWork) *directoryErasureLedgerRow {
	self.loadErasureLedgerWithLock(state)
	row, ok := state.rows[work.erasureId]
	if !ok {
		row = &directoryErasureLedgerRow{
			TimeMillis: self.clock.Now().UnixMilli(), Reason: uint32(work.reason), RequestId: bytes.Clone(work.requestId), Own: work.own,
			CardsDocuments: map[string]uint64{}, StreamDocuments: map[string]uint64{},
		}
		if work.began {
			// another device began it: its CUTs may stand with rewrites owed, which each ref's rewrite reads from evs
			row.CardsRewriteOwed = true
			row.StreamsRewriteOwed = true
		}
		state.rows[work.erasureId] = row
	}
	if row.CardsDocuments == nil {
		row.CardsDocuments = map[string]uint64{}
	}
	if row.StreamDocuments == nil {
		row.StreamDocuments = map[string]uint64{}
	}
	return row
}

// Whether work leaves this device anything to send, and whether a file waits for its writer: read against the
// ledger, which takes note of what the sync showed. Nothing is sent.
func (self *DirectoryClient) erasureFilesOwed(work *directoryErasureWork) (bool, bool) {
	state := self.erasureFilesState()
	state.stateLock.Lock()
	defer state.stateLock.Unlock()
	self.loadErasureLedgerWithLock(state)
	if _, ok := state.rows[work.erasureId]; !ok && !work.found() && !work.began {
		// nothing on format 2's carriers, and nothing begun: no row is made
		return false, false
	}
	row := self.erasureLedgerRowWithLock(state, work)
	owed := row.CardsRewriteOwed || row.StreamsRewriteOwed || row.Unerased || (work.began && !state.resumed[work.erasureId])
	owed = owed || 0 < len(directoryErasureUncut(work.cardsDocuments, row.CardsDocuments)) || 0 < len(directoryErasureUncut(work.streamDocuments, row.StreamDocuments))
	for _, held := range work.held {
		owed = row.noteHeld(held) || owed
	}
	waits := false
	for _, holding := range work.holding {
		row.noteHolding(holding)
		if work.remove {
			owed = true
		} else {
			waits = true
		}
	}
	if err := self.keepErasureLedgerWithLock(state); err != nil {
		self.log.Warningf("[directory]the erasure files were not kept: %s", err)
	}
	return owed, waits
}

// Runs fn on the erasure's row and keeps the ledger.
func (self *DirectoryClient) updateErasureLedger(work *directoryErasureWork, fn func(row *directoryErasureLedgerRow)) error {
	state := self.erasureFilesState()
	state.stateLock.Lock()
	defer state.stateLock.Unlock()
	fn(self.erasureLedgerRowWithLock(state, work))
	return self.keepErasureLedgerWithLock(state)
}

// Format 2's half of one erasure: see the file's header's order, files, ledger and resume rows. It sends what the
// ledger shows owed of work and no more, so a call that follows a finished one sends nothing. On an error what
// committed stands and the next call carries on from the ledger and evs's state.
func (self *DirectoryClient) eraseFiles(ctx context.Context, work *directoryErasureWork) (*DirectoryErasureFilesResult, error) {
	state := self.erasureFilesState()
	state.workLock.Lock()
	defer state.workLock.Unlock()
	result := &DirectoryErasureFilesResult{ErasureId: work.erasureId}
	if self.readOnly {
		return result, ErrDirectoryReadOnly
	}
	files := self.erasureFiles()
	if files == nil {
		return result, ErrDirectoryErasureFilesUnbound
	}
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return result, ErrDirectoryNone
	}
	note, err := work.note()
	if err != nil {
		return result, err
	}
	barrierKey := recordChainIdText(work.erasureId)

	// what the ledger shows owed, read once: the documents no CUT of this device lists, and the files owed a CLOSURE
	var uncutCards, uncutStreams []string
	closes := []*directoryErasureFile{}
	removes := []*directoryErasureFile{}
	resume := false
	err = func() error {
		state.stateLock.Lock()
		defer state.stateLock.Unlock()
		row := self.erasureLedgerRowWithLock(state, work)
		uncutCards = directoryErasureUncut(work.cardsDocuments, row.CardsDocuments)
		uncutStreams = directoryErasureUncut(work.streamDocuments, row.StreamDocuments)
		for _, held := range work.held {
			if row.noteHeld(held) {
				closes = append(closes, held)
			}
		}
		for _, holding := range work.holding {
			row.noteHolding(holding)
			if work.remove {
				removes = append(removes, holding)
			} else {
				result.WaitingPaths = append(result.WaitingPaths, holding.file.Path)
			}
		}
		resume = row.Unerased || !state.resumed[work.erasureId]
		return self.keepErasureLedgerWithLock(state)
	}()
	if err != nil {
		return result, err
	}
	eraseKeys := func(keys []*EvsErasedKey, complete bool) error {
		if len(keys) == 0 {
			return nil
		}
		if err := files.EraseCardKeys(ctx, directoryId, &EvsEraseArgs{ErasureId: work.erasureId, Keys: keys, Complete: complete, Note: note}); err != nil {
			return err
		}
		result.ErasedKeyCount += len(keys)
		result.Complete = result.Complete || complete
		return nil
	}

	// the reconcile row: an ERASE first for each CLOSURE of the cards ref no ERASE followed, by evs's state, once a
	// process an erasure and whenever a CLOSURE of this device may stand alone
	if resume {
		orphans, err := files.OrphanCardKeys(ctx, directoryId, work.erasureId)
		if err != nil {
			return result, err
		}
		if err := eraseKeys(orphans, false); err != nil {
			return result, err
		}
		if err := self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) { row.Unerased = false }); err != nil {
			return result, err
		}
		func() {
			state.stateLock.Lock()
			defer state.stateLock.Unlock()
			state.resumed[work.erasureId] = true
		}()
	}

	// the fence: a CUT a ref listing the documents, before any CLOSURE and any list of index files
	cut := func(names []string, found map[string]uint64, index func(ctx context.Context, repoId Id) (DirectoryErasureIndex, error), cards bool) error {
		if len(names) == 0 {
			return nil
		}
		eraser, err := index(ctx, directoryId)
		if err != nil {
			return err
		}
		documents := make([]*IndexCutDocument, 0, len(names))
		for _, name := range names {
			key, err := eraser.DocKey([]byte(name))
			if err != nil {
				return err
			}
			documents = append(documents, &IndexCutDocument{Key: key, Version: found[name]})
		}
		testHookBarrier("directory.erasure.cut.before", barrierKey)
		cutResult, err := eraser.Cut(ctx, &IndexCutArgs{ErasureId: work.erasureId, Documents: documents})
		if err != nil {
			return err
		}
		if cutResult != nil && cutResult.Pushed {
			result.CutCount += 1
		}
		return self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) {
			listed := row.StreamDocuments
			if cards {
				listed = row.CardsDocuments
				row.CardsRewriteOwed = true
			} else {
				row.StreamsRewriteOwed = true
			}
			for _, name := range names {
				listed[name] = found[name]
			}
			row.Complete = false
		})
	}
	for _, each := range []struct {
		names []string
		found map[string]uint64
		index func(ctx context.Context, repoId Id) (DirectoryErasureIndex, error)
		cards bool
	}{{uncutCards, work.cardsDocuments, files.CardsIndex, true}, {uncutStreams, work.streamDocuments, files.StreamsIndex, false}} {
		if err := cut(each.names, each.found, each.index, each.cards); err != nil {
			if errors.Is(err, ErrIndexErasureSetFull) {
				// the CUT waits while pending erasures finish, and with it everything it fences (§11.12's cut row)
				result.IndexWaiting = true
				return result, nil
			}
			return result, err
		}
	}

	var cardsOwed, streamsOwed bool
	func() {
		state.stateLock.Lock()
		defer state.stateLock.Unlock()
		row := self.erasureLedgerRowWithLock(state, work)
		cardsOwed, streamsOwed = row.CardsRewriteOwed, row.StreamsRewriteOwed
	}()
	// whether an ERASE may yet say the erasure complete: no file waits for its writer, and none met a conflict
	settled := func() bool {
		return len(result.WaitingPaths) == 0 && len(result.ConflictPaths) == 0
	}

	// each ref's index files: the eraser's CLOSURE and ERASE pairs, which read their own progress from evs's state
	rewrite := func(index func(ctx context.Context, repoId Id) (DirectoryErasureIndex, error), cards bool, complete bool) error {
		eraser, err := index(ctx, directoryId)
		if err != nil {
			return err
		}
		rewritten, err := eraser.Rewrite(ctx, &IndexRewriteArgs{ErasureId: work.erasureId, Complete: complete, Note: note})
		waits := false
		switch {
		case errors.Is(err, ErrIndexEraseNotCut):
			// no CUT of the erasure stands on this ref: nothing of it is listed there
		case err != nil:
			return err
		default:
			result.IndexPairCount += rewritten.PairCount
			result.Complete = result.Complete || rewritten.Completed
			waits = rewritten.Unproven || (rewritten.Erasure != nil && rewritten.Erasure.State == SidecarErasureWaiting)
		}
		if waits {
			result.IndexWaiting = true
			return nil
		}
		return self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) {
			if cards {
				row.CardsRewriteOwed = false
			} else {
				row.StreamsRewriteOwed = false
			}
		})
	}
	// the erasure's last ERASE says it complete: a file's, whose keys always stand, where a file is rewritten or
	// removed at this call, else the last ref's
	fileCount := len(closes) + len(removes)
	if cardsOwed {
		if err := rewrite(files.CardsIndex, true, fileCount == 0 && !streamsOwed && settled()); err != nil {
			return result, err
		}
	}
	if streamsOwed {
		if err := rewrite(files.StreamsIndex, false, fileCount == 0 && !result.IndexWaiting && settled()); err != nil {
			return result, err
		}
	}
	// the cards ref's files, last: a CLOSURE each, then the ERASE of every key its stored versions name
	pin := auth.Pin()
	for index, erasureFile := range closes {
		path := erasureFile.file.Path
		keys, err := files.CardKeys(ctx, directoryId, []string{path})
		if err != nil {
			return result, err
		}
		// journaled first: a kill after the CLOSURE leaves it with no ERASE, which the next call reads from evs's state
		if err := self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) { row.Unerased = true }); err != nil {
			return result, err
		}
		testHookBarrier("directory.erasure.closure.before", barrierKey)
		version, err := files.CloseCard(ctx, directoryId, work.erasureId, &DirectoryCardWrite{
			PushId: NewId(), Path: path, IfVersion: erasureFile.file.Version, Content: bytes.Clone(erasureFile.file.Content), AuthPin: pin,
		}, keys)
		if directoryPathConflict(err) {
			// its writer, or another runner, changed it first: the next sync judges the path again
			result.ConflictPaths = append(result.ConflictPaths, path)
			continue
		}
		if err != nil {
			return result, err
		}
		testHookBarrier("directory.erasure.closure.after", barrierKey)
		last := index == len(closes)-1 && len(removes) == 0 && !result.IndexWaiting && settled()
		if err := eraseKeys(keys, last); err != nil {
			return result, err
		}
		result.ClosedPaths = append(result.ClosedPaths, path)
		if err := self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) {
			pathRow := row.path(path)
			pathRow.Closed = max(pathRow.Closed, version)
			row.Unerased = false
		}); err != nil {
			return result, err
		}
	}
	// a person's erasure of a card that still holds the item: moderation's removal, then its keys
	cards := self.boundCards()
	for index, erasureFile := range removes {
		path := erasureFile.file.Path
		if _, ok := directoryCardPathSidecar(path); !ok {
			continue
		}
		keys, err := files.CardKeys(ctx, directoryId, []string{path})
		if err != nil {
			return result, err
		}
		err = cards.RemoveCard(ctx, directoryId, &DirectoryCardWrite{PushId: NewId(), Path: path, IfVersion: erasureFile.file.Version, AuthPin: pin})
		if directoryPathConflict(err) {
			result.ConflictPaths = append(result.ConflictPaths, path)
			continue
		}
		if err != nil {
			return result, err
		}
		last := index == len(removes)-1 && !result.IndexWaiting && settled()
		if err := eraseKeys(keys, last); err != nil {
			return result, err
		}
		result.RemovedPaths = append(result.RemovedPaths, path)
		if err := self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) {
			pathRow := row.path(path)
			pathRow.Closed = max(pathRow.Closed, erasureFile.file.Version+1)
		}); err != nil {
			return result, err
		}
	}

	slices.Sort(result.WaitingPaths)
	if err := self.updateErasureLedger(work, func(row *directoryErasureLedgerRow) {
		row.Complete = result.Complete || (row.Complete && !result.erased())
	}); err != nil {
		return result, err
	}
	return result, nil
}

// Carries on each person's erasure this device began whose files the ledger shows owed: a kill between its pushes left
// a CLOSURE without its ERASE, or a ref's index files unrewritten. A card it had yet to remove is not journaled: the
// command, run again, finds it standing. Requests are the runner's, at each pass.
func (self *DirectoryClient) resumeErasureFiles(ctx context.Context) error {
	state := self.erasureFilesState()
	owed := func() []*directoryErasureWork {
		state.stateLock.Lock()
		defer state.stateLock.Unlock()
		self.loadErasureLedgerWithLock(state)
		owed := []*directoryErasureWork{}
		for _, erasureId := range slices.SortedFunc(maps.Keys(state.rows), func(a Id, b Id) int { return a.Cmp(b) }) {
			row := state.rows[erasureId]
			if !row.Own || (!row.Unerased && !row.CardsRewriteOwed && !row.StreamsRewriteOwed) {
				continue
			}
			work := newDirectoryErasureWork()
			work.erasureId = erasureId
			work.reason = RecordErasureReason(row.Reason)
			work.requestId = bytes.Clone(row.RequestId)
			work.own = true
			owed = append(owed, work)
		}
		return owed
	}()
	for _, work := range owed {
		if _, err := self.eraseFiles(ctx, work); err != nil {
			return err
		}
	}
	return nil
}

// What a DirectoryEvsErasure runs on.
type DirectoryEvsErasureArgs struct {
	// The directory's evs binding, whose client's repo every call goes through.
	Cards *DirectoryEvsCards
	// Whether a sidecar may erase in the directory at the state now: the erasure set and index settings versions an
	// eraser counts are those such a sidecar signed.
	IsAdmin func(signerSidecarId Id) bool
	// The index's format and its erasers' settings; nil for the defaults.
	IndexFormat *IndexFormatSettings
	IndexErase  *IndexEraseSettings
}

// DirectoryErasureFiles over the directory repo's EvsRepo: the cards ref's CLOSUREs and the ERASEs through
// EvsRepo.Closure, EvsRepo.Erase and EvsRepo.SlotKeysOf, and each index ref's eraser over EvsRepo's index store, as
// the index's own erasers are built (evs_index_store_evs.go). evs holds each call to admin.
type DirectoryEvsErasure struct {
	cards       *DirectoryEvsCards
	isAdmin     func(signerSidecarId Id) bool
	indexFormat *IndexFormatSettings
	indexErase  *IndexEraseSettings
}

var _ DirectoryErasureFiles = (*DirectoryEvsErasure)(nil)

// A binding on args.
func NewDirectoryEvsErasure(args *DirectoryEvsErasureArgs) (*DirectoryEvsErasure, error) {
	if args == nil || args.Cards == nil || args.IsAdmin == nil {
		return nil, fmt.Errorf("%w: the directory's erasure binding needs its evs binding and its admins", ErrDirectoryCardsUnavailable)
	}
	indexFormat := args.IndexFormat
	if indexFormat == nil {
		indexFormat = DefaultIndexFormatSettings()
	}
	indexErase := args.IndexErase
	if indexErase == nil {
		indexErase = DefaultIndexEraseSettings()
	}
	return &DirectoryEvsErasure{cards: args.Cards, isAdmin: args.IsAdmin, indexFormat: indexFormat, indexErase: indexErase}, nil
}

// One index ref's eraser with the ref's K_ref and id, which its documents' keys are drawn under.
type directoryEvsErasureIndex struct {
	*IndexEraser
	refKey []byte
	refId  Id
}

// An announcement's document is one row, chunk 0.
func (self *directoryEvsErasureIndex) DocKey(name []byte) ([indexIdByteCount]byte, error) {
	return indexDocKey(self.refKey, self.refId, name, 0)
}

// The eraser of one index ref of the directory: the file-mode ref refName's own index, or ur/index.
func (self *DirectoryEvsErasure) index(ctx context.Context, repoId Id, refName []byte, companion bool) (DirectoryErasureIndex, error) {
	client := self.cards.client
	repo := client.Repo(repoId)
	store := newIndexEvsStore(repo, refName, companion)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	kind, err := repo.repoKind()
	if err != nil {
		return nil, err
	}
	repoKey, err := client.args.Gkm.CurrentRepoKey(ctx, repoId)
	if err != nil {
		return nil, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	padKey, err := indexNewPadKey(repoKey)
	if err != nil {
		return nil, err
	}
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: store, eraseStore: store, repoId: repoId, refId: refId, repoKind: kind, companion: companion,
		isAdmin:  func(file *indexFileVersion) bool { return self.isAdmin(file.signerSidecarId) },
		format:   self.indexFormat,
		settings: self.indexErase,
		eraser:   client.args.Identity().SidecarId,
		complete: func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
			erasures, err := repo.ReadErasures(ctx, 0)
			if err != nil {
				return nil, err
			}
			complete := map[Id]bool{}
			for _, erasure := range erasures {
				if erasure.Complete {
					complete[erasure.ErasureId] = true
				}
			}
			return complete, nil
		},
		refKey: refKey, tables: indexLinkedTables(), mayMerge: func() bool { return true },
		padKey: func(ctx context.Context) (*indexPadKey, error) { return padKey, nil },
		clock:  client.clock, log: client.log,
	})
	if err != nil {
		return nil, err
	}
	return &directoryEvsErasureIndex{IndexEraser: eraser, refKey: refKey, refId: refId}, nil
}

// The cards ref's own index.
func (self *DirectoryEvsErasure) CardsIndex(ctx context.Context, repoId Id) (DirectoryErasureIndex, error) {
	return self.index(ctx, repoId, DirectoryCardsRefName(), false)
}

// The streams' ur/index.
func (self *DirectoryEvsErasure) StreamsIndex(ctx context.Context, repoId Id) (DirectoryErasureIndex, error) {
	return self.index(ctx, repoId, nil, true)
}

// EvsRepo.SlotKeysOf over the cards ref, which fails where a path's history is not walked to its first version.
func (self *DirectoryEvsErasure) CardKeys(ctx context.Context, repoId Id, paths []string) ([]*EvsErasedKey, error) {
	for _, path := range paths {
		if !directoryCardPathKept(path) {
			return nil, directoryEvsInvalid()
		}
	}
	keys, err := self.cards.client.Repo(repoId).SlotKeysOf(ctx, DirectoryCardsRefName(), paths)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	return keys, nil
}

// One CLOSURE of one file of the cards ref: see DirectoryErasureFiles. The rewrite keeps the path's setting, so a
// versionless card stays versionless, and declares the client's verified pin, which must stand at or above the
// write's and on its chain.
func (self *DirectoryEvsErasure) CloseCard(ctx context.Context, repoId Id, erasureId Id, write *DirectoryCardWrite, keys []*EvsErasedKey) (uint64, error) {
	if write == nil || write.Content == nil || write.IfVersion == 0 || write.AuthPin == nil || !directoryCardPathKept(write.Path) {
		return 0, directoryEvsInvalid()
	}
	client := self.cards.client
	state, err := client.verifier.config()
	if err != nil {
		return 0, err
	}
	if state.Pin().GetVersion() < write.AuthPin.GetVersion() || !state.OnChain(write.AuthPin) {
		return 0, ErrEvsStreamPinBehind
	}
	ifVersion := write.IfVersion
	closed, err := client.Repo(repoId).Closure(ctx, &EvsClosureArgs{
		ErasureId: erasureId, RefName: DirectoryCardsRefName(), Erased: keys,
		Writes: []*EvsPathWrite{{
			Path: write.Path, Content: bytes.NewReader(bytes.Clone(write.Content)), IfVersion: &ifVersion,
			Options: &EvsWriteOptions{Versioning: EvsVersioningKeepSetting, Reserved: EvsReservedDirectory},
		}},
	})
	if err != nil {
		return 0, recordEvsRefusal(err)
	}
	if len(closed.PathVersions) != 1 {
		return 0, directoryEvsInvalid()
	}
	return closed.PathVersions[0], nil
}

// EvsRepo.Erase, which counts keys already gone as done.
func (self *DirectoryEvsErasure) EraseCardKeys(ctx context.Context, repoId Id, args *EvsEraseArgs) error {
	if _, err := self.cards.client.Repo(repoId).Erase(ctx, args); err != nil {
		return recordEvsRefusal(err)
	}
	return nil
}

// The cards ref's CLOSUREs of erasureId against the erasure ref's ERASEs of it, both read from their first statement.
func (self *DirectoryEvsErasure) OrphanCardKeys(ctx context.Context, repoId Id, erasureId Id) ([]*EvsErasedKey, error) {
	repo := self.cards.client.Repo(repoId)
	closures, err := repo.ReadClosures(ctx, DirectoryCardsRefName(), 0)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	erasures, err := repo.ReadErasures(ctx, 0)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	erased := map[EvsErasedKey]bool{}
	for _, erasure := range erasures {
		if erasure.ErasureId != erasureId {
			continue
		}
		for _, key := range erasure.Keys {
			erased[*key] = true
		}
	}
	orphans := []*EvsErasedKey{}
	for _, closure := range closures {
		if closure.ErasureId != erasureId {
			continue
		}
		for _, key := range closure.Keys {
			if !erased[*key] {
				erased[*key] = true
				orphans = append(orphans, &EvsErasedKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
			}
		}
	}
	return orphans, nil
}
