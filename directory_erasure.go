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
//	           right on the repo at the entry's push's pin and the repo's private marker still its newest item, and
//	           then each earlier announce entry for the repo, and each run's that names it, is erased, every ERASE's
//	           note naming the request, whose id is the erasure's (plan-RECORD-small-readings #12). The work waits
//	           0-10 min from the sync that first showed it, so the first commit wins and a later runner, which has
//	           synced that ERASE, finds nothing left; two that race both send, and evs answers the second
//	           NOTHING_TO_ERASE. While the marker stands, for 30 days from the request, each later sync erases any copy
//	           a daemon wrote since. A request whose check fails erases nothing and alarms bad_erasure, naming its
//	           signer, once
//	expiry     the runner also runs the directory's retention expiry (RECORD-M6-03) through Expire: an announce entry
//	           is held until 30 days after a newer entry for its item, or its item's expiry, so a live repo item keeps
//	           its newest copy
//	waiting    a request no ERASE names is pending, and is never dropped: past 24 h every directory admin's device
//	           raises directory_erasure, pending, and done once it is erased; StatusLines names each one past 24 h and
//	           the oldest waiting
//
// Barriers: directory.erasure.erase.before, before a request's first ERASE, keyed by the request's id.
//
// Not here: format 2's CUT and CLOSURE on the cards ref and ur/index (RECORD-M10-05). Safe for concurrent use: one
// pass at a time.

package sidecar

import (
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// Only a directory admin erases in the directory (D-MCP-33): nothing was erased.
	ErrDirectoryEraseNotAdmin = errors.New("directory erase: not a directory admin")
	// A directory admin's erasure is a person's act (§5.8): nothing was erased.
	ErrDirectoryEraseUnconfirmed = errors.New("directory erase is a person's act")
	// No eraser is bound to the client, so nothing is erased.
	ErrDirectoryEraserUnbound = errors.New("directory eraser unbound")
)

const (
	directoryEraserPart        = "eraser"
	directoryErasureRunnerPart = "erasure runner"
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
}

// §16.11's values.
func DefaultDirectoryErasureSettings() *DirectoryErasureSettings {
	return &DirectoryErasureSettings{
		Delay:        10 * time.Minute,
		SweepWindow:  30 * 24 * time.Hour,
		PendingAlarm: 24 * time.Hour,
		AnnounceHold: 30 * 24 * time.Hour,
		EntryCount:   512,
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
	entryIds := []Id{}
	reason := RecordErasureReasonPerson
	take := func(entry *RecordReadEntry) {
		entryIds = append(entryIds, entry.EntryId)
		if recordIdOf(entry.Header.Header.GetWriterSidecarId()) != self.sidecarId {
			reason = RecordErasureReasonModeration
		}
	}
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
		}
	}
	if len(entryIds) == 0 {
		return nil, fmt.Errorf("%w: no entry or announcement %s with a key left to erase", ErrDirectoryItemNone, args.Id)
	}
	result, err := erase(ctx, &RecordEraseArgs{LogId: directoryId, EntryIds: entryIds, Reason: reason, Confirmed: true})
	if err != nil {
		return nil, err
	}
	self.ViewSync()
	return &DirectoryEraseResult{ErasureId: result.ErasureId, EntryIds: result.Erased, Reason: reason}, nil
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
	// The requests whose work waits for its delay.
	Delayed []Id
	// The requests still pending after it.
	Pending []*DirectoryErasurePending
}

// The directory's erasure runner on one daemon: see the file's header.
type DirectoryErasureRunner struct {
	client   *DirectoryClient
	erase    DirectoryEraseFunction
	expire   func(ctx context.Context, directoryId Id, hold func(entry *RecordReadEntry) bool) error
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
		client: args.Client, erase: args.Erase, expire: args.Expire, indexers: args.Indexers, raise: args.Raise, random: random,
		settings: settings, dueMillis: map[Id]int64{}, refused: map[Id]bool{}, raised: map[Id]string{},
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
		runner, err := NewDirectoryErasureRunner(&DirectoryErasureRunnerArgs{
			Client: client,
			Expire: func(ctx context.Context, directoryId Id, hold func(entry *RecordReadEntry) bool) error {
				_, err := record.Retention().Expire(ctx, &RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
				return err
			},
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
	// A full item above its marker stands: the repo was announced again.
	directoryErasureCheckLapsed
)

// §16.11's revoke row's step 3 for one request.
func (self *DirectoryErasureRunner) check(auth DirectoryAuthView, request *DirectoryErasureRequestView, nowMillis int64) directoryErasureCheck {
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
	case standing.Display == DirectoryItemPrivate && request.MarkerVersion <= standing.Announcement.GetVersion():
		return directoryErasureCheckPassed
	case standing.Display != DirectoryItemPrivate && request.MarkerVersion < standing.Announcement.GetVersion():
		return directoryErasureCheckLapsed
	}
	// the marker has not been read or judged yet
	return directoryErasureCheckWaits
}

// The live entries a request erases: each announce entry for the repo's item below the marker's version, and each
// run's announce entry that names the repo.
func (self *DirectoryErasureRunner) copiesNaming(request *DirectoryErasureRequestView) []Id {
	entryIds := []Id{}
	for _, entry := range self.client.entriesOfKinds(RecordKindAnnounce) {
		if entry.State != RecordEntryLive || entry.Body == nil || entry.BodyInvalid {
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

// Whether expiry holds entry: an announce entry until AnnounceHold after a newer entry for its item, or its item's
// expiry; a repo item's newest copy, which has neither, for as long as it is the newest.
func (self *DirectoryErasureRunner) announceHold(entries []*RecordReadEntry, nowMillis int64) func(entry *RecordReadEntry) bool {
	type copyOf struct {
		entryId       Id
		version       uint64
		pushMillis    int64
		expiresMillis int64
	}
	byItem := map[DirectoryItemKey][]*copyOf{}
	for _, entry := range entries {
		if entry.Header == nil || entry.Header.Kind() != RecordKindAnnounce || entry.Body == nil || entry.BodyInvalid {
			continue
		}
		version, ok := directoryVersionOf(entry)
		if !ok {
			continue
		}
		byItem[version.key] = append(byItem[version.key], &copyOf{
			entryId: entry.EntryId, version: version.item.GetVersion(), pushMillis: entry.PushTimeMillis, expiresMillis: version.item.GetExpiresMillis(),
		})
	}
	endedMillis := map[Id]int64{}
	held := map[Id]bool{}
	for _, copies := range byItem {
		slices.SortStableFunc(copies, func(a *copyOf, b *copyOf) int {
			if order := cmp.Compare(a.version, b.version); order != 0 {
				return order
			}
			if order := cmp.Compare(a.pushMillis, b.pushMillis); order != 0 {
				return order
			}
			return a.entryId.Cmp(b.entryId)
		})
		for i, copied := range copies {
			held[copied.entryId] = true
			switch {
			case i+1 < len(copies):
				endedMillis[copied.entryId] = copies[i+1].pushMillis
			case copied.expiresMillis != 0:
				endedMillis[copied.entryId] = copied.expiresMillis
			}
		}
	}
	window := self.settings.AnnounceHold.Milliseconds()
	return func(entry *RecordReadEntry) bool {
		if !held[entry.EntryId] {
			// no announce entry this copy reads: the policy's own rule
			return false
		}
		ended, ok := endedMillis[entry.EntryId]
		return !ok || nowMillis < ended+window
	}
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
	pass := &DirectoryErasurePass{Erased: map[Id][]Id{}}
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
		if len(entryIds) == 0 {
			if !request.Erased {
				// nothing this copy reads names the repo: no ERASE will name the request, so it stays pending
				pending()
			}
			continue
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
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.dueMillis, request.RequestId)
		}()
		if firstErr != nil && !request.Erased {
			pending()
		}
	}
	if pass.Runs && self.expire != nil && firstErr == nil {
		entries := self.client.allEntries()
		if err := self.expire(ctx, directoryId, self.announceHold(entries, nowMillis)); err != nil {
			firstErr = err
		}
	}
	if 0 < len(pass.Erased) {
		// the copy reads its own ERASEs at the next sync
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
		case directoryErasureCheckNoRight, directoryErasureCheckLapsed:
			continue
		}
		pending = append(pending, &DirectoryErasurePending{Request: request, Age: max(0, time.Duration(nowMillis-request.PushTimeMillis)*time.Millisecond)})
	}
	return pending
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
