// The team directory's client on one sidecar (RECORD-M6-13): its copy (directory_store.go), its sync
// (directory_sync.go), the cadence §16.11's desktops row sets, and the bindings every later directory task builds on.
// Sidecar.Directory answers it in a team network whose directory exists, and nil otherwise, where the tools answer
// FAILED_PRECONDITION naming a personal network or a directory not made yet (plan-RECORD-small-readings #8).
//
//	cadence   a sync at once, then every SessionSyncInterval while the daemon serves a harness session in the
//	          network, else every IdleSyncInterval, and at each view or search, coalesced over ViewCoalesce
//	verify    a reader of its own (RECORD-M3-03's) over the copy, judging the directory as any log: no entry shows
//	          before its header, right and chain verify, and an unknown kind shows generically
//	lost read once DirectoryAuthView says this sidecar is no longer admitted, or evs refuses its read, the copy is
//	          deleted with the reader's state (§5.9), and every call answers ErrDirectoryReadLost until it reads again
//	read_only the console's page Worker reads and refuses every write: on the sidecar_http leg the client is built
//	          apart from any component, by NewDirectoryClient, and its writes refuse whatever the args say
//	leases    only notice prefixes and paths, never the cards ref (D-MCP-31)
//
// What a sync fetches is folded by DirectoryFold after each sync (RECORD-M6-14), which List and Get read, and a phone's
// view fetches apart from the sync (directory_phone.go). The writes go through the record writer for entries (repo
// items here, RECORD-M6-15; runs, workers, requests and decisions RECORD-M6-16 to -19) and through PutCard and
// RemoveCard for notices. An admin device that finds a team with no directory files its RepoCreate through
// TEAM-M6-10's FileTeamDirectory: a create marked private does so first (directory_private.go, QD-748), and nothing
// here files one at a sync yet.
//
// Safe for concurrent use. Locks: syncLock, then stateLock, then a fold's own; none is held across a call out but
// syncLock across a sync's own I/O.

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"sync"
	"time"
)

// What a DirectoryClient reads and writes with.
type DirectoryClientArgs struct {
	SidecarId Id
	// §5.9's directory/ under file class search; a memory store on phones, which keep the copy only while the view is
	// open.
	Store SidecarStore
	// The directory's evs: DirectoryCardsUnavailable when nil, until RECORD-M3-12 and EVS1-M6-01 bind one.
	Cards DirectoryCards
	// The record's streams, for the directory's erasure ref; nil is RecordStreamsUnavailable.
	Streams func() RecordStreams
	// §7.9's and §8's state now as the directory asks it; nil, and a nil answer, read as DirectoryAuthUnavailable.
	Auth func() DirectoryAuthView
	// The same state as the record's reader asks it, for verifying entries; nil reads as RecordAuthUnavailable.
	RecordAuth func() RecordAuthView
	// Whether the daemon serves a harness session in the network now; nil reads no.
	SessionActive func() bool
	// Called after each sync the loop runs, with its outcome, with no lock held; nil for none.
	AfterSync func(err error)
	// record_alarm's sink for what the reader finds; nil drops alarms.
	Alarm          func(alarm *RecordAlarm)
	Clock          Clock
	Settings       *SidecarDirectorySettings
	RecordSettings *SidecarRecordSettings
	// The page Worker's client: reads, refusing every write. The sidecar_http leg forces it.
	ReadOnly bool
	Log      Logger
	// The record's writer, through which every directory entry this client files is appended; nil refuses each write
	// with ErrDirectoryNoWriter.
	Writer RecordWriter
	// §16.7's redactor, which every identifier and prose field passes before it is signed (§16.11's redaction row);
	// nil makes one of the client's own, which hashes PII.
	Redactor *Redactor
	// Whether a config label names the repo (§8.8), for the warning a repo marked private takes; nil reads every repo
	// as possibly labeled, so the warning is never missed.
	RepoLabeled func(repoId Id) bool
	// The display name this device knows for a repo (prose), which a repo predating the directory is announced under
	// (§16.11's default row): "" for none, and nil knows none, so the item names the repo by its kind and id until an
	// admin announces it at a higher version.
	RepoDisplayName func(repoId Id) string
	// Each run's taint, which a run's item carries as written (directory_run.go, RECORD-M6-16); nil reads every run
	// tainted.
	Runs RecordRunView
}

// One network's team directory on this sidecar.
type DirectoryClient struct {
	sidecarId     Id
	store         *DirectoryStore
	adapter       *directoryStreams
	recordAuth    func() RecordAuthView
	alarm         func(alarm *RecordAlarm)
	clock         Clock
	settings      *SidecarDirectorySettings
	recordSet     *SidecarRecordSettings
	sessionActive func() bool
	afterSync     func(err error)
	readOnly      bool
	log           Logger
	wake          chan struct{}
	writer        RecordWriter
	redactor      *Redactor
	repoLabeled   func(repoId Id) bool
	// what a repo predating the directory is announced under (DirectoryClientArgs.RepoDisplayName), nil for none
	repoDisplayName func(repoId Id) string
	// each run's taint, for a run's item (DirectoryClientArgs.Runs)
	runView RecordRunView

	syncLock sync.Mutex
	// the record reader over the copy, replaced at a lost read
	reader *RecordReader

	stateLock sync.Mutex
	cards     DirectoryCards
	authFunc  func() DirectoryAuthView
	// a view or search asked for a sync since the last one
	viewPending bool
	// when the last sync started, Unix milliseconds; 0 before any
	lastSyncMillis int64
	// the fold of the directory read now, nil until one is asked for and after a lost read
	fold *DirectoryFold
	// the highest version of each repo's item this client wrote, until the copy reads it back
	repoWrittenVersions map[Id]uint64
	// this sidecar's run announcements (directory_run.go, which no ios_extension leg links), made at the first Runs:
	// held as any, so this file, which the forwarding leg links, names none of their types
	runs any
}

// A client over args. Nothing is read until its first Sync.
func NewDirectoryClient(args *DirectoryClientArgs) (*DirectoryClient, error) {
	if args == nil || args.Store == nil || args.Settings == nil {
		return nil, fmt.Errorf("%w: a directory client needs a store and settings", ErrDirectoryCardsUnavailable)
	}
	streams := args.Streams
	if streams == nil {
		streams = func() RecordStreams { return RecordStreamsUnavailable{} }
	}
	recordAuth := args.RecordAuth
	if recordAuth == nil {
		recordAuth = func() RecordAuthView { return RecordAuthUnavailable{} }
	}
	cards := args.Cards
	if cards == nil {
		cards = DirectoryCardsUnavailable{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	recordSettings := args.RecordSettings
	if recordSettings == nil {
		recordSettings = defaultSidecarRecordSettings()
	}
	redactor := args.Redactor
	if redactor == nil {
		var err error
		if redactor, err = NewRedactor(cryptorand.Reader); err != nil {
			return nil, err
		}
	}
	runView := args.Runs
	if runView == nil {
		runView = RecordRunViewMissing{}
	}
	store := NewDirectoryStore(args.Store)
	self := &DirectoryClient{
		sidecarId:     args.SidecarId,
		store:         store,
		adapter:       &directoryStreams{store: store, streams: streams},
		recordAuth:    recordAuth,
		alarm:         args.Alarm,
		clock:         clockOrReal(args.Clock),
		settings:      args.Settings,
		recordSet:     recordSettings,
		sessionActive: args.SessionActive,
		afterSync:     args.AfterSync,
		readOnly:      args.ReadOnly || directoryLegReadOnly,
		log:           log,
		wake:          make(chan struct{}, 1),
		writer:        args.Writer,
		redactor:      redactor,
		repoLabeled:   args.RepoLabeled,
		cards:         cards,
		authFunc:      args.Auth,

		repoDisplayName: args.RepoDisplayName,
		runView:         runView,

		repoWrittenVersions: map[Id]uint64{},
	}
	self.reader = self.newReader()
	return self, nil
}

// A reader over the copy, its pins in the copy's own store. A push pin before what the state retains is judged at the
// state, since a repo item's announce entry stands with no age bound and a device that starts after it still reads it
// (§16.11's repo file row, FS-101); the fold holds each kind to its own rule after.
func (self *DirectoryClient) newReader() *RecordReader {
	return NewRecordReader(&RecordReaderArgs{
		SidecarId:        self.sidecarId,
		Store:            self.store.store,
		Streams:          func() RecordStreams { return self.adapter },
		Auth:             self.recordAuth,
		Alarm:            self.alarm,
		Clock:            self.clock,
		Settings:         self.recordSet,
		Log:              self.log,
		UnretainedAtHead: true,
	})
}

// The fold of the directory this client reads now: a new one for another directory, and after a lost read.
func (self *DirectoryClient) currentFold() *DirectoryFold {
	directoryId, _ := self.DirectoryId()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.fold == nil || self.fold.DirectoryId() != directoryId {
		self.fold = NewDirectoryFold(directoryId, self.alarm)
	}
	return self.fold
}

// The redactor every write passes.
func (self *DirectoryClient) redactorNow() *Redactor {
	return self.redactor
}

// Binds the directory's evs and its view of the authorization state as they land. A nil argument keeps the current
// binding.
func (self *DirectoryClient) Bind(cards DirectoryCards, auth func() DirectoryAuthView) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if cards != nil {
			self.cards = cards
		}
		if auth != nil {
			self.authFunc = auth
		}
	}()
	self.signal()
}

// The authorization state now, failing closed.
func (self *DirectoryClient) auth() DirectoryAuthView {
	authFunc := func() func() DirectoryAuthView {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.authFunc
	}()
	if authFunc != nil {
		if auth := authFunc(); auth != nil {
			return auth
		}
	}
	return DirectoryAuthUnavailable{}
}

// The directory's evs bound now.
func (self *DirectoryClient) boundCards() DirectoryCards {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.cards
}

// The network's directory now, false in a personal network or before the directory exists.
func (self *DirectoryClient) DirectoryId() (Id, bool) {
	return self.auth().Directory()
}

// The directory this sidecar reads now: ErrDirectoryNone without one, and ErrDirectoryReadLost, the copy deleted,
// once the state no longer admits this sidecar.
func (self *DirectoryClient) readableDirectory() (Id, error) {
	auth := self.auth()
	directoryId, ok := auth.Directory()
	if !ok {
		return Id{}, ErrDirectoryNone
	}
	standing, err := auth.SignerStanding(self.sidecarId, auth.Pin())
	if err != nil {
		return Id{}, err
	}
	switch standing {
	case DirectoryStandingUnadmitted, DirectoryStandingRevoked, DirectoryStandingExpired:
		return Id{}, self.loseRead(directoryId, fmt.Errorf("this sidecar is %s", standing))
	}
	return directoryId, nil
}

// Deletes the copy and the reader's state: this sidecar no longer reads the directory (§5.9). The caller holds
// syncLock.
func (self *DirectoryClient) loseRead(directoryId Id, cause error) error {
	if err := self.store.Reset(); err != nil {
		return err
	}
	self.reader = self.newReader()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.fold = nil
		clear(self.repoWrittenVersions)
	}()
	self.log.Infof("[directory]%s: the read is lost, its copy deleted", recordChainIdText(directoryId))
	return fmt.Errorf("%w: %w", ErrDirectoryReadLost, cause)
}

// The directory's entries this copy verified, in read order (RecordReader.Entries), for RECORD-M6-14's fold.
func (self *DirectoryClient) Entries() []*RecordReadEntry {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil
	}
	self.syncLock.Lock()
	reader := self.reader
	self.syncLock.Unlock()
	return reader.Entries(directoryId)
}

// The cards ref's files this copy holds, in path order: the notices at M6.
func (self *DirectoryClient) Cards() []*DirectoryCardFile {
	return self.store.Cards()
}

// Writes a file of the cards ref by path CAS: ErrDirectoryReadOnly on a read_only client.
func (self *DirectoryClient) PutCard(ctx context.Context, write *DirectoryCardWrite) (uint64, error) {
	if self.readOnly {
		return 0, ErrDirectoryReadOnly
	}
	directoryId, ok := self.DirectoryId()
	if !ok {
		return 0, ErrDirectoryNone
	}
	return self.boundCards().PutCard(ctx, directoryId, write)
}

// Removes a file of the cards ref by path CAS: ErrDirectoryReadOnly on a read_only client.
func (self *DirectoryClient) RemoveCard(ctx context.Context, write *DirectoryCardWrite) error {
	if self.readOnly {
		return ErrDirectoryReadOnly
	}
	directoryId, ok := self.DirectoryId()
	if !ok {
		return ErrDirectoryNone
	}
	return self.boundCards().RemoveCard(ctx, directoryId, write)
}

// Leases a notice prefix or a notice's path, never the cards ref (D-MCP-31); each hint wakes the loop to sync.
func (self *DirectoryClient) Lease(prefix string) (func(), error) {
	if !DirectoryLeasePathAllowed(prefix) {
		return nil, fmt.Errorf("%w: %q", ErrDirectoryLeaseRefused, prefix)
	}
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	return self.boundCards().Lease(directoryId, prefix, func(repoId Id) { self.ViewSync() })
}

// Asks for a sync for a view or a search, which the loop coalesces over ViewCoalesce. Nothing of the view reaches evs
// (I-19).
func (self *DirectoryClient) ViewSync() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.viewPending = true
	}()
	self.signal()
}

// One alarm through the record's sink.
func (self *DirectoryClient) raise(reason SidecarRecordAlarm, logId Id, sidecarId *Id) {
	if self.alarm != nil {
		self.alarm(&RecordAlarm{Reason: reason, LogId: logId, SidecarId: sidecarId})
	}
}

// Wakes the loop without waiting.
func (self *DirectoryClient) signal() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The interval to the next scheduled sync: SessionSyncInterval while a harness session is served, else
// IdleSyncInterval.
func (self *DirectoryClient) interval() time.Duration {
	if self.sessionActive != nil && self.sessionActive() {
		return self.settings.SessionSyncInterval
	}
	return self.settings.IdleSyncInterval
}

// When the next sync is due, Unix milliseconds: the schedule's, or a view's once ViewCoalesce has passed since the
// last sync.
func (self *DirectoryClient) dueMillis() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lastSyncMillis == 0 {
		return 0
	}
	due := self.lastSyncMillis + self.interval().Milliseconds()
	if self.viewPending {
		due = min(due, self.lastSyncMillis+self.settings.ViewCoalesce.Milliseconds())
	}
	return due
}

// Syncs on §16.11's cadence until ctx ends: see the file's header. A second Run waits for the first to return.
func (self *DirectoryClient) Run(ctx context.Context) {
	for {
		nowMillis := self.clock.Now().UnixMilli()
		if due := self.dueMillis(); due <= nowMillis {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.lastSyncMillis = nowMillis
				self.viewPending = false
			}()
			err := self.Sync(ctx)
			if err != nil && self.log.V(1).Enabled() {
				self.log.Infof("[directory]a sync stopped: %s", err)
			}
			if err == nil {
				// what this device's repo rights call for once it has read the directory (RECORD-M6-15)
				if _, maintainErr := self.MaintainRepos(ctx); maintainErr != nil {
					self.log.Infof("[directory]repo items: %s", maintainErr)
				}
			}
			if self.afterSync != nil {
				self.afterSync(err)
			}
			continue
		}
		wait := time.Duration(self.dueMillis()-nowMillis) * time.Millisecond
		stop := self.clock.AfterFunc(wait, self.signal)
		select {
		case <-ctx.Done():
			stop()
			return
		case <-self.wake:
		}
		stop()
	}
}

// The network's team directory: nil in a personal network, before its directory exists, before the record does, and
// while nothing binds the authorization state (plan-RECORD-small-readings #8). DirectoryClient answers the client
// whatever the network, for binding it and running its component.
func (self *Sidecar) Directory() *DirectoryClient {
	client, err := self.DirectoryClient()
	if err != nil {
		return nil
	}
	if _, ok := client.DirectoryId(); !ok {
		return nil
	}
	return client
}

// The network's directory client, built once with the record (Sidecar.Record), whose writer it appends through, and
// §5.9's directory/ under file class search; its evs and authorization state stay unbound until DirectoryClient.Bind.
func (self *Sidecar) DirectoryClient() (*DirectoryClient, error) {
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	store, err := self.LocalStore().Directory(directoryComponentName, directoryFileClass)
	if err != nil {
		return nil, err
	}
	networkId := self.knownNetworkId()
	if networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	// the spool's redactor, whose PII setting is the harness config's; the client makes its own without one
	var redactor *Redactor
	if spool, err := self.Spool(); err == nil {
		redactor = spool.Redactor()
	}
	self.records.stateLock.Lock()
	defer self.records.stateLock.Unlock()
	self.records.forNetworkWithLock(*networkId)
	if self.records.directory != nil {
		return self.records.directory, nil
	}
	client, err := NewDirectoryClient(&DirectoryClientArgs{
		SidecarId:      record.writer.sidecarId,
		Store:          store,
		Streams:        record.writer.boundStreams,
		RecordAuth:     record.writer.auth,
		Alarm:          record.writer.alarm,
		Clock:          self.settings.ClockOrReal(),
		Settings:       self.settings.Directory,
		RecordSettings: self.settings.Record,
		Log:            self.log,
		Writer:         record.Writer(),
		Redactor:       redactor,
		Runs:           self,
	})
	if err != nil {
		return nil, err
	}
	self.records.directory = client
	return client, nil
}
