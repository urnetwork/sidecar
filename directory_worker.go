//go:build !ios_extension

// RECORD-M6-17's worker item (§16.11's Announcements table, its worker row, and its renew, expire and withdraw rows;
// R-MCP-16, D-MCP-27, Q-MCP-8; FI-26): one item a sidecar, saying what it serves, so members and their agents can ask
// to reach it. Before format 2 it rides announce entries in this sidecar's own stream, through the record writer, as a
// run's item does (§16.11's M6 carrier row).
//
//	on         by ServiceSettings.directory.workers (the team's, §7.9), and off per device: the device's own setting,
//	           `ur directory worker on|off` on the sidecar's own host, kept in this sidecar's local state, never a
//	           record, which is how a tagged sidecar's is set too (plan-RECORD-worker-setting). The team's off governs
//	           every device, and a device's on under it announces nothing and says so
//	never      on phones, page Workers or the quick burner: the host's class is the daemon's to state, and any class
//	           but a daemon's, the zero value included, announces nothing and refuses SetWorker's on
//	what       harnesses, agent labels and services (application sockets, published TLS hosts, bridge ports, each with
//	           a description), requests open or closed, and a description; who's tags; where's host label, platform
//	           and ephemeral. Services are what a reach grant may name (FI-26), so they come only from what this sidecar
//	           really serves, read from its components' own state through DirectoryWorkerServices, never from a
//	           setting: with no services bound the item lists none
//	version    raised only on a content change; a renewal is a new entry at the same version, renewed and expires
//	           raised (§16.11's renew row)
//	renew      daily (RenewInterval), expiring renewed + 26 h, so an offline sidecar's item lapses
//	withdraw   off, the team's or the device's, withdraws the item: a newer entry at version + 1 holding a withdrawal's
//	           fields alone, terminal (plan-RECORD-m6-carrier#1), so turning it on again takes a new announcement_id
//	refused    an item past §16.11's caps, 32 services among them, is refused whole before anything is kept or written
//	persist    the item's state is kept in the directory's store, worker, before its entry is appended, so a restart
//	           never writes a version again
//	platform   this build's, DirectoryPlatformOfGoos of its GOOS (owner decision 468); a GOOS §16.11 names no platform
//	           for leaves the field out, which readers show as unknown. A build that wrote none before sees its
//	           content change, so its next upkeep raises the version once
//	moderated  an item an erasure took, which this sidecar's card leaves out from its return on
//	           (directory_cards_erasure.go; QD-1144), is announced no more: each upkeep first asks the card writer's
//	           journal (DirectoryWorkerArgs.Moderated), and a carried draft the card left out answers so too. The kept
//	           state then holds no item and is marked so, which the team's setting does not clear: only the device's
//	           own on, a person's act, announces again, under a new announcement_id
//
// Barriers: directory.worker.before and .after around each append, keyed by the announcement's id. Safe for concurrent
// use. Locks: writeLock, then stateLock; stateLock is never held across a call out, an append or a store write.

package sidecar

import (
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The store's names for the worker item, a format value of this device's own state, and the client's part.
const (
	directoryWorkerStoreName    = "worker"
	directoryWorkerStoreVersion = 1
	directoryWorkerPartName     = "worker"
)

var (
	// This host announces no worker item: a phone, a page Worker, the quick burner, or a host whose class nothing
	// stated (§16.11's worker row).
	ErrDirectoryWorkerHost = errors.New("this host announces no worker item")
	// The team's ServiceSettings.directory.workers is off, or not known yet: the device's setting is kept, and
	// nothing is announced.
	ErrDirectoryWorkersOff = errors.New("the team's directory workers setting is off")
	// The worker item closed: nothing more is written in this process.
	ErrDirectoryWorkerClosed = errors.New("directory worker closed")
)

// What kind of host a sidecar runs on, as its daemon states it.
type DirectoryWorkerHost int

const (
	// A desktop's or a server's daemon: the only class that announces a worker item.
	DirectoryWorkerHostDaemon DirectoryWorkerHost = iota + 1
	// A phone's app.
	DirectoryWorkerHostPhone
	// The console's page Worker.
	DirectoryWorkerHostPageWorker
	// The quick burner (§15).
	DirectoryWorkerHostQuickBurner
)

// The worker item's own timing.
type DirectoryWorkerSettings struct {
	// The item renews this often: daily (§16.11's renew row). Non-positive renews nothing.
	RenewInterval time.Duration
}

// The defaults, a fresh value each call.
func DefaultDirectoryWorkerSettings() *DirectoryWorkerSettings {
	return &DirectoryWorkerSettings{
		RenewInterval: 24 * time.Hour,
	}
}

// One service this sidecar serves.
type DirectoryWorkerService struct {
	Kind DirectoryServiceKind
	// The socket's name (§9.4), the published host, or tcp:<port>.
	Name string
	// Prose, at most 256 B.
	Description string
}

// What this sidecar serves now.
type DirectoryWorkerServing struct {
	// The harnesses installed here, identifiers, at most 8.
	Harnesses []string
	// The agent labels it runs, identifiers, at most 16.
	AgentLabels []string
	// At most 32.
	Services []*DirectoryWorkerService
}

// What this sidecar really serves, read from its components' own state (FI-26): §9's listening sockets, §13's active
// publishes and §17's forwarded ports, each as its own component holds it now, and the harnesses and agent labels the
// daemon runs. A seam, so the worker item builds before those components bind theirs.
type DirectoryWorkerServices interface {
	WorkerServing(ctx context.Context) (*DirectoryWorkerServing, error)
}

// This sidecar as §7.9's config names it, for the item's who and where.
type DirectoryWorkerIdentity struct {
	// Its keyed tag ids, none for a member's device.
	TagIds []Id
	// Its config name (§7.7), a DNS label, or "".
	HostLabel string
	Ephemeral bool
}

// What the worker item is written through.
type DirectoryWorkerArgs struct {
	SidecarId Id
	// The record's writer: announce entries go to this sidecar's own stream in the directory.
	Writer RecordWriter
	// §7.9's and §8's state now as the directory asks it; nil reads DirectoryAuthUnavailable.
	Auth func() DirectoryAuthView
	// ServiceSettings.directory.workers now (ConfigState.DirectorySettings): on, and whether it is known. Nil reads not
	// known, which announces nothing and withdraws nothing.
	TeamWorkers func() (on bool, known bool)
	// The host's class; the zero value announces nothing.
	Host DirectoryWorkerHost
	// What this sidecar serves; nil lists no harness, label or service.
	Services DirectoryWorkerServices
	// This sidecar's tags, config name and ephemeral bit; nil for none.
	Identity func() *DirectoryWorkerIdentity
	// §16.7's redactor; nil makes one of the worker's own.
	Redactor *Redactor
	// Where the item's state is kept: the directory's store; nil keeps nothing, so a restart starts afresh.
	Store SidecarStore
	// Whether this sidecar's card leaves an announcement out, an erasure having taken it: the card writer's journal
	// (the directory client's), which each upkeep asks first. Nil reads none, and only a carried draft the card left
	// out tells the item so.
	Moderated func(announcementId Id) (bool, error)
	Clock     Clock
	Settings  *DirectoryWorkerSettings
	// crypto/rand's reader when nil: the announcement's id.
	Random io.Reader
	Log    Logger
}

// What SetWorker changes: `ur directory worker [on|off] [--description t] [--requests open|closed]` and the SDK's
// SetWorker. A nil field, and a zero Requests, keeps the value held.
type DirectoryWorkerSetting struct {
	On          *bool
	Description *string
	Requests    DirectoryRequests
}

// The worker item's state as kept.
type directoryWorkerState struct {
	// The device's setting: off per device. A worker is on until its device turns it off.
	Off bool `json:"off"`
	// Prose, as the person wrote it.
	Description string `json:"description"`
	// open or closed; 0 reads open.
	Requests uint32 `json:"requests"`
	// The item last written, zero before any and after a withdrawal.
	AnnouncementId Id     `json:"announcement_id"`
	Version        uint64 `json:"version"`
	StartedMillis  int64  `json:"started_millis"`
	RenewedMillis  int64  `json:"renewed_millis"`
	// SHA-256 over the content last written: its who, what and where with every time and its version left out.
	ContentSha256 []byte `json:"content_sha256,omitempty"`
	// An erasure took the item last written, which this sidecar's card leaves out: none is announced until the
	// device's own on (the file's header's moderated row).
	Moderated bool `json:"moderated,omitempty"`
	// The terminal item still owed, including its previous announcement id.
	PendingWithdrawal *protocol.Announcement `json:"pending_withdrawal,omitempty"`
}

// The store's document of the worker item.
type directoryWorkerDocument struct {
	Version int                   `json:"version"`
	Worker  *directoryWorkerState `json:"worker"`
}

// Whether an item stands written: announced and not withdrawn.
func (self *directoryWorkerState) announced() bool {
	return 0 < self.Version && self.AnnouncementId != (Id{})
}

// The item an erasure took, held no more: none stands, and none is announced until the device's own on.
func (self *directoryWorkerState) leftOut() {
	self.Moderated = true
	self.AnnouncementId = Id{}
	self.Version = 0
	self.StartedMillis = 0
	self.RenewedMillis = 0
	self.ContentSha256 = nil
}

// What one upkeep did.
type DirectoryWorkerWrite string

const (
	// Nothing was written: the item stands as it is, or none is due.
	DirectoryWorkerUnchanged DirectoryWorkerWrite = "unchanged"
	// A first version, or a version raised by a content change.
	DirectoryWorkerAnnounced DirectoryWorkerWrite = "announced"
	// A new entry at the same version.
	DirectoryWorkerRenewed DirectoryWorkerWrite = "renewed"
	// A withdrawal.
	DirectoryWorkerWithdrawn DirectoryWorkerWrite = "withdrawn"
	// Nothing was written: an erasure took the item, which this sidecar's card leaves out, and none is announced
	// until the device's own on.
	DirectoryWorkerModerated DirectoryWorkerWrite = "moderated"
)

// This sidecar's worker item in one network's team directory.
type DirectoryWorker struct {
	sidecarId   Id
	writer      RecordWriter
	auth        func() DirectoryAuthView
	teamWorkers func() (bool, bool)
	host        DirectoryWorkerHost
	services    DirectoryWorkerServices
	identity    func() *DirectoryWorkerIdentity
	redactor    *Redactor
	store       SidecarStore
	moderated   func(announcementId Id) (bool, error)
	clock       Clock
	settings    *DirectoryWorkerSettings
	random      io.Reader
	log         Logger

	// one item write at a time: its build, its document and its append, in that order
	writeLock sync.Mutex

	stateLock sync.Mutex
	loaded    bool
	state     *directoryWorkerState
	// the renewal's timer, set while an item stands
	renewStop func() bool
	closed    bool
}

// A worker item over args. Nothing is read until the first call.
func NewDirectoryWorker(args *DirectoryWorkerArgs) (*DirectoryWorker, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no worker args", ErrDirectoryFormatInvalid)
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	redactor := args.Redactor
	if redactor == nil {
		var err error
		if redactor, err = NewRedactor(random); err != nil {
			return nil, err
		}
	}
	auth := args.Auth
	if auth == nil {
		auth = func() DirectoryAuthView { return DirectoryAuthUnavailable{} }
	}
	teamWorkers := args.TeamWorkers
	if teamWorkers == nil {
		teamWorkers = func() (bool, bool) { return false, false }
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDirectoryWorkerSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &DirectoryWorker{
		sidecarId:   args.SidecarId,
		writer:      args.Writer,
		auth:        auth,
		teamWorkers: teamWorkers,
		host:        args.Host,
		services:    args.Services,
		identity:    args.Identity,
		redactor:    redactor,
		store:       args.Store,
		moderated:   args.Moderated,
		clock:       clockOrReal(args.Clock),
		settings:    settings,
		random:      random,
		log:         log,
		state:       &directoryWorkerState{},
	}, nil
}

// What a daemon binds a client's worker item to: its host's class, what it serves, its config row and the team's
// setting. Nil fields read as DirectoryWorkerArgs' do.
type DirectoryWorkerBinding struct {
	Host        DirectoryWorkerHost
	Services    DirectoryWorkerServices
	Identity    func() *DirectoryWorkerIdentity
	TeamWorkers func() (on bool, known bool)
	Settings    *DirectoryWorkerSettings
	Random      io.Reader
}

// Binds this client's worker item, once: its upkeep then runs after each sync. A second bind keeps the first, and a
// read_only client binds none.
func (self *DirectoryClient) BindWorker(binding *DirectoryWorkerBinding) *DirectoryWorker {
	if binding == nil || self.readOnly {
		return self.Worker()
	}
	made := false
	worker, _ := self.part(directoryWorkerPartName, func() any {
		var store SidecarStore
		if self.store != nil {
			store = self.store.store
		}
		worker, err := NewDirectoryWorker(&DirectoryWorkerArgs{
			SidecarId: self.sidecarId,
			// an announce entry at format 1, this sidecar's card from format 2 (directory_format2.go)
			Writer:      self.carrierWriter(),
			Auth:        self.auth,
			TeamWorkers: binding.TeamWorkers,
			Host:        binding.Host,
			Services:    binding.Services,
			Identity:    binding.Identity,
			Redactor:    self.redactor,
			Store:       store,
			// what this sidecar's card leaves out, an erasure having taken it (directory_cards_erasure.go)
			Moderated: self.cardItemModerated,
			Clock:     self.clock,
			Settings:  binding.Settings,
			Random:    binding.Random,
			Log:       self.log,
		})
		if err != nil {
			// a redactor is passed, so nothing above can fail; a nil answer leaves the worker unbound
			return nil
		}
		made = true
		return worker
	}).(*DirectoryWorker)
	if made {
		self.addSyncHook(func(ctx context.Context) {
			if _, err := worker.Maintain(ctx); err != nil && !errors.Is(err, ErrDirectoryWorkerHost) {
				self.log.Infof("[directory]the worker item: %s", err)
			}
		})
	}
	return worker
}

// This client's worker item, nil until BindWorker binds it.
func (self *DirectoryClient) Worker() *DirectoryWorker {
	worker, _ := self.part(directoryWorkerPartName, func() any { return nil }).(*DirectoryWorker)
	return worker
}

// The device's worker setting (§16.11's worker row; `ur directory worker`, the SDK's SetWorker): a person's act on
// /dev/tty or in an app, never through MCP, kept in this sidecar's local state (plan-RECORD-worker-setting). The item
// is then written, renewed or withdrawn as the setting and the team's call for. ErrDirectoryWorkerHost on a host that
// announces none, and ErrDirectoryWorkersOff, the setting kept, when on is asked under the team's off.
func (self *DirectoryClient) SetWorker(ctx context.Context, setting *DirectoryWorkerSetting) error {
	if self.readOnly {
		return ErrDirectoryReadOnly
	}
	if _, ok := self.DirectoryId(); !ok {
		return ErrDirectoryNone
	}
	worker := self.Worker()
	if worker == nil {
		// nothing stated this host's class
		return ErrDirectoryWorkerHost
	}
	_, err := worker.Set(ctx, setting)
	return err
}

// Reads the kept state once.
func (self *DirectoryWorker) load() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	state := &directoryWorkerState{}
	if self.store != nil {
		reader, err := self.store.Open(directoryWorkerStoreName)
		switch {
		case errors.Is(err, ErrSidecarStoreAbsent):
		case err != nil:
			return err
		default:
			content, readErr := io.ReadAll(reader)
			reader.Close()
			if readErr != nil {
				return readErr
			}
			document := &directoryWorkerDocument{}
			if err := json.Unmarshal(content, document); err != nil || document.Version != directoryWorkerStoreVersion || document.Worker == nil {
				// kept state that does not read is never taken as no state: a version might be written twice
				return fmt.Errorf("%w: the kept worker item does not read", ErrDirectoryStoreCorrupt)
			}
			state = document.Worker
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		self.state = state
		self.loaded = true
	}
	return nil
}

// The state as kept, a copy.
func (self *DirectoryWorker) stateNow() *directoryWorkerState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *self.state
	copied.ContentSha256 = slices.Clone(self.state.ContentSha256)
	return &copied
}

// The device's worker setting as kept, and the item it last wrote, for `ur directory worker` to show.
type DirectoryWorkerShown struct {
	On          bool
	Description string
	Requests    DirectoryRequests
	// The item last written; zero before any and after a withdrawal.
	AnnouncementId Id
	Version        uint64
	// An erasure took the item last written: none is announced until the device's own on.
	Moderated bool
}

// What `ur directory worker` shows: the kept setting and item.
func (self *DirectoryWorker) Shown() (*DirectoryWorkerShown, error) {
	if err := self.load(); err != nil {
		return nil, err
	}
	state := self.stateNow()
	shown := &DirectoryWorkerShown{
		On: !state.Off, Description: state.Description, Requests: DirectoryRequestsOpen, AnnouncementId: state.AnnouncementId, Version: state.Version,
		Moderated: state.Moderated,
	}
	if DirectoryRequests(state.Requests) == DirectoryRequestsClosed {
		shown.Requests = DirectoryRequestsClosed
	}
	return shown, nil
}

// Writes the state, before an entry is appended.
func (self *DirectoryWorker) persist(state *directoryWorkerState) error {
	if self.store != nil {
		content, err := json.Marshal(&directoryWorkerDocument{Version: directoryWorkerStoreVersion, Worker: state})
		if err != nil {
			return err
		}
		writer, err := self.store.Create(directoryWorkerStoreName)
		if err != nil {
			return err
		}
		defer writer.Close()
		if _, err := writer.Write(content); err != nil {
			return err
		}
		if err := writer.Commit(); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
	return nil
}

// Whether the host's class announces a worker item.
func (self *DirectoryWorker) hostAnnounces() bool {
	return self.host == DirectoryWorkerHostDaemon
}

// Changes the device's setting and writes what it calls for: see DirectoryClient.SetWorker.
func (self *DirectoryWorker) Set(ctx context.Context, setting *DirectoryWorkerSetting) (DirectoryWorkerWrite, error) {
	if setting == nil {
		return DirectoryWorkerUnchanged, fmt.Errorf("%w: no worker setting", ErrDirectoryFormatInvalid)
	}
	if !self.hostAnnounces() {
		return DirectoryWorkerUnchanged, ErrDirectoryWorkerHost
	}
	if setting.Requests != 0 && !directoryRequestsValid(uint32(setting.Requests)) {
		return DirectoryWorkerUnchanged, fmt.Errorf("%w: requests is open or closed", ErrDirectoryFormatInvalid)
	}
	if err := self.load(); err != nil {
		return DirectoryWorkerUnchanged, err
	}
	asksOn := setting.On != nil && *setting.On
	write, err := self.maintain(ctx, func(state *directoryWorkerState) {
		if setting.On != nil {
			state.Off = !*setting.On
			if *setting.On {
				// the person's on announces again, under a new id, once an erasure took the item
				state.Moderated = false
			}
		}
		if setting.Description != nil {
			state.Description = *setting.Description
		}
		if setting.Requests != 0 {
			state.Requests = uint32(setting.Requests)
		}
	})
	if err != nil {
		return write, err
	}
	if on, known := self.teamWorkers(); asksOn && (!known || !on) {
		return write, ErrDirectoryWorkersOff
	}
	return write, nil
}

// The item's upkeep, which a sync and the renewal's timer call: announced when it is due and none stands, rewritten at
// a raised version when its content changed, renewed at its version once RenewInterval has passed, and withdrawn when
// the team's or the device's setting turned off. On a host that announces none it writes nothing, and withdraws an
// item a kept state says stands. An item an erasure took is announced no more (DirectoryWorkerModerated; the file's
// header's moderated row).
func (self *DirectoryWorker) Maintain(ctx context.Context) (DirectoryWorkerWrite, error) {
	if err := self.load(); err != nil {
		return DirectoryWorkerUnchanged, err
	}
	return self.maintain(ctx, nil)
}

// Maintain, after change, nil for none, is applied to the kept state.
func (self *DirectoryWorker) maintain(ctx context.Context, change func(state *directoryWorkerState)) (DirectoryWorkerWrite, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.isClosed() {
		return DirectoryWorkerUnchanged, ErrDirectoryWorkerClosed
	}
	state := self.stateNow()
	retriedWithdrawal := state.PendingWithdrawal != nil
	if retriedWithdrawal {
		if err := self.publishWithdrawal(state); err != nil {
			return DirectoryWorkerUnchanged, err
		}
		state = self.stateNow()
	}
	// before any change, so the device's own on in the same call announces again
	moderatedNow, err := self.moderatedItem(state)
	if err != nil {
		return DirectoryWorkerUnchanged, err
	}
	if change != nil {
		change(state)
	}
	teamOn, teamKnown := self.teamWorkers()
	hostAnnounces := self.hostAnnounces()
	wanted := hostAnnounces && teamKnown && teamOn && !state.Off && !state.Moderated
	// a setting not known yet withdraws nothing: only a known off, the device's off or a host that announces none does
	unwanted := !hostAnnounces || state.Off || (teamKnown && !teamOn)
	nowMillis := self.clock.Now().UnixMilli()

	switch {
	case wanted:
		content, contentSha256, err := self.contentOf(ctx, state)
		if err != nil {
			return DirectoryWorkerUnchanged, err
		}
		write := DirectoryWorkerUnchanged
		switch {
		case !state.announced():
			announcementId, err := self.newId()
			if err != nil {
				return DirectoryWorkerUnchanged, err
			}
			state.AnnouncementId = announcementId
			state.Version = 1
			state.StartedMillis = nowMillis
			write = DirectoryWorkerAnnounced
		case !slices.Equal(state.ContentSha256, contentSha256):
			state.Version += 1
			write = DirectoryWorkerAnnounced
		case 0 < self.settings.RenewInterval && self.settings.RenewInterval.Milliseconds() <= nowMillis-state.RenewedMillis:
			write = DirectoryWorkerRenewed
		}
		if write == DirectoryWorkerUnchanged {
			if change != nil || moderatedNow {
				if err := self.persist(state); err != nil {
					return DirectoryWorkerUnchanged, err
				}
			}
			self.scheduleRenew()
			return DirectoryWorkerUnchanged, nil
		}
		state.ContentSha256 = contentSha256
		state.RenewedMillis = nowMillis
		expiresMillis, _ := DirectoryAnnouncementExpiresMillis(DirectoryAnnouncementKindWorker, nowMillis)
		content.AnnouncementId = state.AnnouncementId.Bytes()
		content.Version = state.Version
		content.StartedMillis = min(state.StartedMillis, nowMillis)
		content.RenewedMillis = nowMillis
		content.ExpiresMillis = expiresMillis
		if err := DirectoryCheckItem(content); err != nil {
			return DirectoryWorkerUnchanged, err
		}
		if err := self.persist(state); err != nil {
			return DirectoryWorkerUnchanged, err
		}
		if err := self.append(state.AnnouncementId, content); err != nil {
			if !errors.Is(err, ErrDirectoryItemModerated) {
				return DirectoryWorkerUnchanged, err
			}
			// the card this append wrote left the item out, an erasure having taken it
			state.leftOut()
			if err := self.persist(state); err != nil {
				return DirectoryWorkerUnchanged, err
			}
			return DirectoryWorkerModerated, nil
		}
		self.scheduleRenew()
		return write, nil
	case unwanted && state.announced():
		withdrawal := &protocol.Announcement{
			AnnouncementId: state.AnnouncementId.Bytes(),
			Kind:           uint32(DirectoryAnnouncementKindWorker),
			Version:        state.Version + 1,
			RenewedMillis:  nowMillis,
			State:          uint32(DirectoryAnnouncementStateWithdrawn),
			Who:            self.who(),
		}
		withdrawal.ExpiresMillis, _ = DirectoryAnnouncementExpiresMillis(DirectoryAnnouncementKindWorker, nowMillis)
		// a withdrawal's who holds its member and sidecar alone
		withdrawal.Who.TagIds = nil
		if err := DirectoryCheckItem(withdrawal); err != nil {
			return DirectoryWorkerUnchanged, err
		}
		state.PendingWithdrawal = withdrawal
		// terminal: the next announcement takes a new id
		state.AnnouncementId = Id{}
		state.Version = 0
		state.StartedMillis = 0
		state.RenewedMillis = 0
		state.ContentSha256 = nil
		if err := self.persist(state); err != nil {
			return DirectoryWorkerUnchanged, err
		}
		if err := self.publishWithdrawal(state); err != nil {
			return DirectoryWorkerUnchanged, err
		}
		return DirectoryWorkerWithdrawn, nil
	}
	if change != nil || moderatedNow {
		if err := self.persist(state); err != nil {
			return DirectoryWorkerUnchanged, err
		}
	}
	if moderatedNow {
		return DirectoryWorkerModerated, nil
	}
	if retriedWithdrawal {
		return DirectoryWorkerWithdrawn, nil
	}
	return DirectoryWorkerUnchanged, nil
}

// Replays the saved item without minting a new version or changing its times.
func (self *DirectoryWorker) publishWithdrawal(state *directoryWorkerState) error {
	item := state.PendingWithdrawal
	if err := self.append(recordIdOf(item.GetAnnouncementId()), item); err != nil && !errors.Is(err, ErrDirectoryItemModerated) {
		return err
	}
	written := *state
	written.PendingWithdrawal = nil
	return self.persist(&written)
}

// Whether an erasure took the item state holds, which this sidecar's card writer's journal says: state then holds none
// and is marked so (leftOut), for the caller to keep. The caller holds writeLock.
func (self *DirectoryWorker) moderatedItem(state *directoryWorkerState) (bool, error) {
	if self.moderated == nil || !state.announced() {
		return false, nil
	}
	moderated, err := self.moderated(state.AnnouncementId)
	if err != nil || !moderated {
		return false, err
	}
	state.leftOut()
	return true, nil
}

// The item's who by the state now: this sidecar, its member or its sponsor, and its tags.
func (self *DirectoryWorker) who() *protocol.AnnounceWho {
	who := &protocol.AnnounceWho{SidecarId: self.sidecarId.Bytes()}
	if memberId, ok := DirectoryWhoMember(self.auth(), self.sidecarId); ok {
		who.MemberId = memberId.Bytes()
	}
	if self.identity != nil {
		if identity := self.identity(); identity != nil {
			tagIds := slices.Clone(identity.TagIds)
			slices.SortFunc(tagIds, Id.Cmp)
			for _, tagId := range slices.Compact(tagIds) {
				who.TagIds = append(who.TagIds, tagId.Bytes())
			}
		}
	}
	return who
}

// The item's content now, with no id, version or time, normalized, redacted and held to §16.11's caps, and its hash:
// what a content change is told by. Services come from the components' own state alone, each once, in kind and name
// order, so the order a component lists them in raises no version.
func (self *DirectoryWorker) contentOf(ctx context.Context, state *directoryWorkerState) (*protocol.Announcement, []byte, error) {
	serving := &DirectoryWorkerServing{}
	if self.services != nil {
		served, err := self.services.WorkerServing(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("directory worker: what this sidecar serves: %w", err)
		}
		if served != nil {
			serving = served
		}
	}
	requests := state.Requests
	if requests == 0 {
		requests = uint32(DirectoryRequestsOpen)
	}
	what := &protocol.AnnounceWhat{
		Description: state.Description,
		Harnesses:   directoryWorkerNames(serving.Harnesses),
		AgentLabels: directoryWorkerNames(serving.AgentLabels),
		Requests:    requests,
	}
	services := []*DirectoryWorkerService{}
	for _, service := range serving.Services {
		if service != nil {
			services = append(services, service)
		}
	}
	slices.SortFunc(services, func(a *DirectoryWorkerService, b *DirectoryWorkerService) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})
	for index, service := range services {
		if 0 < index && services[index-1].Kind == service.Kind && services[index-1].Name == service.Name {
			continue
		}
		what.Services = append(what.Services, &protocol.Service{Kind: uint32(service.Kind), Name: service.Name, Description: service.Description})
	}
	where := &protocol.AnnounceWhere{Platform: uint32(DirectoryPlatformOfGoos(runtime.GOOS))}
	if self.identity != nil {
		if identity := self.identity(); identity != nil {
			where.HostLabel = identity.HostLabel
			where.Ephemeral = identity.Ephemeral
		}
	}
	item := &protocol.Announcement{
		Kind:  uint32(DirectoryAnnouncementKindWorker),
		State: uint32(DirectoryAnnouncementStateActive),
		Who:   self.who(),
		What:  what,
		Where: where,
	}
	if _, err := DirectoryRedact(self.redactor, item); err != nil {
		return nil, nil, err
	}
	// the caps, before any id or time is drawn: an item past them is refused whole (§16.11's caps row)
	probe := proto.Clone(item).(*protocol.Announcement)
	probe.AnnouncementId = self.sidecarId.Bytes()
	probe.Version = 1
	probe.RenewedMillis = 1
	probe.ExpiresMillis, _ = DirectoryAnnouncementExpiresMillis(DirectoryAnnouncementKindWorker, 1)
	if err := DirectoryCheckItem(probe); err != nil {
		return nil, nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(item)
	if err != nil {
		return nil, nil, err
	}
	contentSha256 := sha256.Sum256(encoded)
	return item, contentSha256[:], nil
}

// names, each once, in order.
func directoryWorkerNames(names []string) []string {
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// 16 random bytes as an id.
func (self *DirectoryWorker) newId() (Id, error) {
	var id Id
	if _, err := io.ReadFull(self.random, id[:]); err != nil {
		return Id{}, fmt.Errorf("directory worker: an id: %w", err)
	}
	return id, nil
}

// Appends the item as an announce entry in this sidecar's stream, the daemon's own, bound to no run or session.
func (self *DirectoryWorker) append(announcementId Id, item *protocol.Announcement) error {
	if self.writer == nil {
		return ErrDirectoryNoWriter
	}
	hookKey := recordChainIdText(announcementId)
	testHookBarrier("directory.worker.before", hookKey)
	_, err := self.writer.Append(&RecordDraft{Kind: RecordKindAnnounce, Source: RecordSourceHook, NoSession: true, Body: item})
	testHookBarrier("directory.worker.after", hookKey)
	return err
}

// Whether Close has run.
func (self *DirectoryWorker) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// Stops the renewal timer, and every write after: the component's close. The item expires unless a later process
// renews it.
func (self *DirectoryWorker) Close() {
	stop := func() func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		stop := self.renewStop
		self.renewStop = nil
		return stop
	}()
	if stop != nil {
		stop()
	}
}

// Sets the renewal timer when none is set and an item stands: RenewInterval after its last renewal, always a positive
// timeout, so a fake clock never fires it inline under writeLock.
func (self *DirectoryWorker) scheduleRenew() {
	if self.settings.RenewInterval <= 0 {
		return
	}
	nowMillis := self.clock.Now().UnixMilli()
	timeout, set := func() (time.Duration, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.renewStop != nil || self.closed || !self.state.announced() {
			return 0, false
		}
		due := self.state.RenewedMillis + self.settings.RenewInterval.Milliseconds()
		return time.Duration(max(due-nowMillis, 1)) * time.Millisecond, true
	}()
	if !set {
		return
	}
	stop := self.clock.AfterFunc(timeout, self.renew)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.renewStop == nil && !self.closed {
		self.renewStop = stop
	} else {
		stop()
	}
}

// The renewal: the item's upkeep, then the next renewal's timer.
func (self *DirectoryWorker) renew() {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.renewStop = nil
		return self.closed
	}()
	if closed {
		return
	}
	if _, err := self.Maintain(context.Background()); err != nil && !errors.Is(err, ErrDirectoryWorkerClosed) {
		self.log.Warningf("[directory]the worker item's renewal was not written: %s", err)
	}
	self.scheduleRenew()
}

// Binds this Sidecar's worker item for a host of class host, serving what services says: the team's setting is
// ServiceSettings.directory.workers at the newest verified state (ConfigState.DirectorySettings), not known while no
// state is installed, and its tags and ephemeral bit are its own admission's there. Its config name is sealed in §7.9's
// rows, so the item names no host label until the composition that unseals one passes it. What the daemon's
// composition calls beside the directory's component; nil in a network whose client cannot be made yet.
func (self *Sidecar) BindDirectoryWorker(host DirectoryWorkerHost, services DirectoryWorkerServices) *DirectoryWorker {
	client, err := self.DirectoryClient()
	if err != nil {
		return nil
	}
	sidecarId := client.sidecarId
	return client.BindWorker(&DirectoryWorkerBinding{
		Host:     host,
		Services: services,
		Identity: func() *DirectoryWorkerIdentity {
			state, err := self.configState()
			if err != nil {
				return nil
			}
			admission := state.Sidecar(sidecarId)
			if admission == nil {
				return nil
			}
			return &DirectoryWorkerIdentity{TagIds: slices.Clone(admission.TagIds), Ephemeral: admission.Ephemeral}
		},
		TeamWorkers: func() (bool, bool) {
			state, err := self.configState()
			if err != nil {
				return false, false
			}
			settings, known := state.DirectorySettings()
			if !known {
				return false, false
			}
			return settings.Workers == protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_ON, true
		},
	})
}
