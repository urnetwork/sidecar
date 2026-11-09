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
// What a sync fetches is folded by RECORD-M6-14; the writes are RECORD-M6-16 to -19's, through the record writer for
// entries and through PutCard and RemoveCard for notices. An admin device that finds a team with no directory files
// its RepoCreate through TEAM-M6-10's FileTeamDirectory, which is not built: until it is, nothing here files one.
//
// Safe for concurrent use. Locks: syncLock, then stateLock; neither is held across a call out but syncLock across a
// sync's own I/O.

package sidecar

import (
	"context"
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
		cards:         cards,
		authFunc:      args.Auth,
	}
	self.reader = self.newReader()
	return self, nil
}

// A reader over the copy, its pins in the copy's own store.
func (self *DirectoryClient) newReader() *RecordReader {
	return NewRecordReader(&RecordReaderArgs{
		SidecarId: self.sidecarId,
		Store:     self.store.store,
		Streams:   func() RecordStreams { return self.adapter },
		Auth:      self.recordAuth,
		Alarm:     self.alarm,
		Clock:     self.clock,
		Settings:  self.recordSet,
		Log:       self.log,
	})
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
	return self.boundCards().Lease(directoryId, prefix, func(repoId Id) { self.View() })
}

// Asks for a sync for a view or a search, which the loop coalesces over ViewCoalesce. Nothing of the view reaches evs
// (I-19).
func (self *DirectoryClient) View() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.viewPending = true
	}()
	self.signal()
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

// The network's directory client, built once with the record (Sidecar.Record) and §5.9's directory/ under file class
// search; its evs and authorization state stay unbound until DirectoryClient.Bind.
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
	})
	if err != nil {
		return nil, err
	}
	self.records.directory = client
	return client, nil
}
