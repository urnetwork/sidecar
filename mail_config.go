//go:build !ios_extension

// §15.7's mailcfg repo and §15.8's address directory (R-MAIL-3, R-MAIL-5, R-MAIL-11, D-MAIL-6, D-ACL-12, I-4, I-8,
// I-14, R-CTX-25; MAIL-M7-04): one MailConfig follows one mailcfg repo, the network's or a Team scope's, keeps its
// records in an in-memory table, answers which mailbox a recipient's mail goes to, and writes the records this
// device may.
//
//	records   addr/<h>/<address> holds one MailAddress and burner/<h>/<blabel> one MailBurner (MAIL-FORMAT.md). An
//	          address is spelled under the network's label, <name>@<label>.<root>, a scope's under <scope>.<label>,
//	          a bounce's under b.<label>, so an alias zone resolves to the label's record; admin@ holds the record
//	          postmaster@ and abuse@ reach
//	authority a record's authority is its evs push, judged per version (I-4), so a reader replays every version of
//	          a path, oldest first (mail_config_read.go): the first version counts only when its creator field is
//	          its push's signer, a later one only from a device that may change the record, and a version that
//	          counts for nothing is passed over with an alarm, never an error
//	grant     a record routes only while §8's policy grants its creator mail:<alias>#listen (D-ACL-12), asked at
//	          every Resolve on the installed state, so a record outlives no grant; <alias> is an address's local
//	          part and a burner's label
//	writes    creating an alias or a burner is an outward action (I-8): the record is the action's SidecarEffect,
//	          which Authorize runs once its use is reserved, created only if absent (EvsPathWrite.IfVersion 0,
//	          QD-721) and carrying the use's effect_key, so a retry or a restart's Lookup finds its own record
//	          (D-MCP-11; mail_config_write.go). A burn or a pause is local, a later version of the same path
//	never     an address, a label or a path reaches a log, an error or a server (I-13): policy and mailcfg are
//	          sealed, and the alarms here carry ids and versions only. Every version is written with versioning on,
//	          since evs refuses 1 and 2 in a mailcfg repo (409 VERSIONING) and a reader passes such a version over
//
// The table is this device's working copy of a repo it mirrors in full (§18.4), a few hundred bytes a record. Sync
// reads each record's head and replays only the paths whose version moved; a Resolve that misses asks for one more
// Sync, at most once each MissRefreshInterval, so a sender guessing addresses costs one read of the repo an
// interval. Before the first Sync nothing is known or unknown: Resolve answers ErrMailConfigNotSynced, which a
// receiver answers as a temporary failure rather than 550.
//
// On every leg but the extension's. MailConfig is safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// What no mailcfg holds or takes: arguments out of shape, or a stored action that is not a mailcfg effect's.
	// The error names no address.
	ErrMailConfigInvalid = errors.New("mail config: invalid")
	// No Sync has finished yet, so nothing is known or unknown.
	ErrMailConfigNotSynced = errors.New("mail config: not synced")
	// The network has no label under its root yet, so no address has a spelling.
	ErrMailConfigNoZone = errors.New("mail config: the network has no label")
	// This device holds no key of the mailcfg repo: it waits keyless and creates no address (§8.12).
	ErrMailConfigUnseated = errors.New("mail config: this device holds no key of the repo")
	// Policy grants this device no mail:<alias>#listen, so no receiver would honor the record (D-ACL-12).
	ErrMailConfigNoGrant = errors.New("mail config: no listen grant for the alias")
	// A record stands at the address, another's: created only if absent (§15.8).
	ErrMailConfigAddressTaken = errors.New("mail config: the address is taken")
	// No record a reader honors stands there.
	ErrMailConfigAddressAbsent = errors.New("mail config: no such address")
	// This device may not change the record: it is no consented device of the member who owns its mailbox, and no
	// admin of its group repo.
	ErrMailConfigNotOwner = errors.New("mail config: not a device that may change the record")
	// A burned label, which never changes again and is never reissued (§15.9).
	ErrMailConfigBurned = errors.New("mail config: the label is burned")
	// A group past its member bound (§20.4's mail_group_members).
	ErrMailConfigGroupFull = errors.New("mail config: the group is full")
	// No gate to authorize an outward action through, or no label drawer for a burner: nothing is created.
	ErrMailConfigNoGate = errors.New("mail config: no gate")
	// An outward action whose effect may or may not have happened: the same call again completes it.
	ErrMailConfigUncertain = errors.New("mail config: the effect's outcome is uncertain")
	// A path with more versions than a reader replays: its record is unknown.
	ErrMailConfigReplayBound = errors.New("mail config: a record past the replay bound")
)

// What MailConfig is tuned by (MAIL-M7-04).
type MailConfigSettings struct {
	// The most one record's bytes take, encoded: a version past it counts for nothing. A group of 100 members is
	// under 2 KiB; 16 KiB leaves room for a tier that raises mail_group_members. Non-positive takes 1.
	RecordMaxByteCount int
	// The most versions of one path a reader replays, past which the record is unknown: a burner paused and
	// resumed daily for ten years is under 8,192. Non-positive takes 1.
	ReplayVersionMaxCount int
	// A group's members, §20.4's mail_group_members, whose default is 100: a writer refuses past it. The mail
	// component sets it from GET /sidecar/limits. Non-positive takes none.
	GroupMemberMaxCount int
	// The labels one burner creation tries, in its drawer's order, before it gives up: a label is passed over when
	// its path ever stood, and 16 in a row is past any chance with four digits a word. Non-positive tries 1.
	BurnerCandidateMaxCount int
	// How many times a writer reads again after a conflict on its path before it gives the conflict back: 8, past
	// the few devices one member has. Non-positive tries once.
	WriteRetryCount int
	// How many times a creation waits out evs's 412 PATH_EPOCH_DUE, which holds new names while an immediate path
	// epoch is due and passes once it commits (DESIGN-DETAILS 9.2.5), and how long each wait is: evs's writer has
	// waited its own tries by then, so 3 waits of 5 s cover a mapper's turn. Non-positive counts try once.
	EpochDueRetryCount    int
	EpochDueRetryInterval time.Duration
	// A Resolve that finds no record asks for a Sync when the last one is older than this: a record another device
	// made is found within it, and a run of mail to addresses no record holds reads the repo once an interval.
	// Non-positive syncs at every miss.
	MissRefreshInterval time.Duration
	// How long the follower waits after a failed Sync, or a failed subscription, before it tries again.
	// Non-positive takes 1 s, so a failing store is never spun on.
	FollowRetryInterval time.Duration
	// How often the follower syncs with no change raised: hints are lossy, and evs's own hourly fresh read raises
	// a change only for a ref that moved. Non-positive never syncs on its own.
	ResyncInterval time.Duration
}

// The one default.
func DefaultMailConfigSettings() *MailConfigSettings {
	return &MailConfigSettings{
		RecordMaxByteCount:      16 * 1024,
		ReplayVersionMaxCount:   8192,
		GroupMemberMaxCount:     100,
		BurnerCandidateMaxCount: 16,
		WriteRetryCount:         8,
		EpochDueRetryCount:      3,
		EpochDueRetryInterval:   5 * time.Second,
		MissRefreshInterval:     10 * time.Second,
		FollowRetryInterval:     30 * time.Second,
		ResyncInterval:          time.Hour,
	}
}

// What MailConfig asks of §8's policy and the access log. Implementations are safe for concurrent use.
type MailConfigAuthority interface {
	// Whether policy grants the creator mail:<alias>#listen now (D-ACL-12): for the creator's subject, an untagged
	// sidecar's member or a tagged one's tags, which outlives the device (reading 15).
	HonorsRecord(creatorSidecarId Id, alias string, now time.Time) bool
	// Whether a version signerSidecarId signed may change a record whose mailbox is mailboxRepoId: a consented
	// device (§8.5) of the member who owns that mailbox, or for a group one of the group repo's admins (reading 15).
	MayChangeRecord(signerSidecarId Id, mailboxRepoId Id) bool
}

// MailConfigAuthority over the installed AclEngine.
//
// A later version is judged at the installed state, not at its push's own pin: EvsHistoryVersion carries no pin
// yet, so a version a device signed while consented and since revoked counts for nothing here, and the record reads
// as it stood before it. That errs toward the record's earlier state, never toward another mailbox; judging each
// version at its pin is the review phase's (it needs the pin from History).
type MailConfigAclAuthority struct {
	Engine *AclEngine
}

// AclEngine.AllowAlias for the creator's listen.
func (self *MailConfigAclAuthority) HonorsRecord(creatorSidecarId Id, alias string, now time.Time) bool {
	if self == nil || self.Engine == nil {
		return false
	}
	return self.Engine.AllowAlias(AclSidecarSubject(creatorSidecarId), protocol.AclAction_ACL_ACTION_LISTEN, alias, now).Allowed
}

// The owner's consented devices for a mailbox, the repo's admins for a group's general repo, nobody for any other
// kind or a repo the state does not hold.
func (self *MailConfigAclAuthority) MayChangeRecord(signerSidecarId Id, mailboxRepoId Id) bool {
	if self == nil || self.Engine == nil {
		return false
	}
	state := self.Engine.State()
	if state == nil {
		return false
	}
	repo := state.Repo(mailboxRepoId)
	if repo == nil {
		return false
	}
	switch repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_MAILBOX:
		ownerMemberId, err := IdFromBytes(repo.GetOwnerMemberId())
		return err == nil && state.ConsentedFor(signerSidecarId, ownerMemberId)
	case protocol.RepoKind_REPO_KIND_GENERAL:
		for _, admin := range repo.GetAdmins() {
			if adminId, err := IdFromBytes(admin.GetSidecarId()); err == nil && adminId == signerSidecarId {
				return true
			}
		}
	}
	return false
}

// §5.4's gate as MailConfig uses it, which *Sidecar is: Authorize runs an outward action's effect once its use is
// reserved, and a kind's Lookup reconciles a reserved use at restart.
type MailConfigGate interface {
	Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
	RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func()
}

// Why a reader passed a version over.
type MailConfigAlarmReason string

const (
	// A first version whose creator field is not its push's signer.
	MailConfigAlarmCreator MailConfigAlarmReason = "creator"
	// A later version, or a removal, from a signer that may not change the record.
	MailConfigAlarmSigner MailConfigAlarmReason = "signer"
	// A later version that changes what no version may: the kind, the mailbox, the creator, the effect key, or a
	// burned label's state.
	MailConfigAlarmChange MailConfigAlarmReason = "change"
	// A second first version over a record that stands, or over a label kept forever.
	MailConfigAlarmRecreated MailConfigAlarmReason = "recreated"
	// A version that is not its path's record, or sits at a name that is no address or label of this zone.
	MailConfigAlarmInvalid MailConfigAlarmReason = "invalid"
	// A versionless version, which a mailcfg repo never holds (§11.7).
	MailConfigAlarmVersioning MailConfigAlarmReason = "versioning"
)

// One version a reader passed over (reading 15's mail_receiver_alarm, which MAIL-M7-25 raises from this). It names
// no address or label (I-13).
type MailConfigAlarm struct {
	Reason MailConfigAlarmReason
	// The mailcfg repo.
	RepoId Id
	// The version's signer, and the path version it signed.
	SidecarId Id
	Version   uint64
	// A burner/ record's, else an addr/ record's.
	Burner bool
}

// Candidate burner labels for one use, in the order to try, from its effect key: MAIL-M8-01's DRBG (§15.9), so a
// retry or a restart's Lookup draws the same labels. The key is empty under a standing grant.
type MailBurnerLabelsFunction func(effectKey []byte) []string

// What NewMailConfig builds on.
type MailConfigArgs struct {
	// The mailcfg repo: the network's, or a Team scope's.
	Repo *EvsRepo
	// The network's row under its root, read at each use: its label spells the records, and its alias and
	// retiring aliases name the same zone. Nil, or a row with no label, resolves and creates nothing.
	Network func() NetworkLabelRow
	// A Team scope's label for a scope's mailcfg, else empty.
	Scope string
	// This sidecar.
	SidecarId Id
	// Nil honors no record and changes none.
	Authority MailConfigAuthority
	// Nil refuses every outward action; else its alias_create and alias_delete Lookups are this MailConfig's until
	// Close. One gate holds one Lookup a kind, so a second MailConfig on it replaces the first's.
	Gate MailConfigGate
	// A burner creation's label drawer; nil refuses burner creations (SetBurnerLabels installs one later).
	BurnerLabels MailBurnerLabelsFunction
	// Called with each version a reader passes over, on the syncing goroutine; it must not block. Nil counts them
	// in the log.
	Alarm func(alarm *MailConfigAlarm)
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailConfigSettings.
	Settings *MailConfigSettings
}

// What Resolve answers for a recipient, and what Addresses lists.
type MailAddressLookup struct {
	// Whether mail for the recipient is taken: a record a reader honors, its creator still granted, and for a
	// burner a live label. Unknown, burned and paused read alike (§15.9), and every other field is then zero.
	Known bool
	Kind  protocol.MailAddressKind
	// The record's address as mailcfg spells it; a burner's is its label under BurnerLabel.
	Address     string
	BurnerLabel string
	// The repo the mail goes to.
	MailboxRepoId Id
	// A group's members.
	MemberIds []Id
	// The sidecar whose push created the record.
	CreatorSidecarId Id
	// A burner with its own selector and records (§15.9).
	Replying bool
}

// One burner label as mailcfg holds it, burned and paused ones included.
type MailBurnerInfo struct {
	Label            string
	State            protocol.MailBurnerState
	MailboxRepoId    Id
	Replying         bool
	CreatedMillis    uint64
	CreatorSidecarId Id
	// Whether policy still grants its creator the label's listen.
	Granted bool
}

// One path as the table holds it: evs's newest version of it, and the record a reader honors there, if any.
type mailConfigEntry struct {
	path string
	// The path's newest version the replay covered, a removal's included, and whether a file stands there.
	headVersion uint64
	standing    bool
	// The honored record, nil for none: a path that never held one, or holds only what counts for nothing.
	record *mailConfigRecord
	// A replay that failed for good, such as one past ReplayVersionMaxCount: the record is unknown until the path
	// moves.
	unreadable bool
}

// A record a reader honors.
type mailConfigRecord struct {
	// One of the two.
	address *protocol.MailAddress
	burner  *protocol.MailBurner
	// The signer of the version that created it, and that version.
	creatorSidecarId Id
	createdVersion   uint64
	mailboxRepoId    Id
	// What mail:<alias> names: an address's local part, a burner's label.
	alias string
	// Whether the life that stands in evs is this record's, so a later version of it can be written.
	lifeHonored bool
	// A burner an owner's removal ended: burned for good, with no file to change.
	removedForever bool
}

// One mailcfg repo, followed. See the file header. Safe for concurrent use.
type MailConfig struct {
	store        mailConfigStore
	network      func() NetworkLabelRow
	scope        string
	sidecarId    Id
	authority    MailConfigAuthority
	gate         MailConfigGate
	alarmHandler func(alarm *MailConfigAlarm)
	clock        Clock
	log          Logger
	settings     *MailConfigSettings

	// held for one Sync at a time, across its reads; never taken with stateLock held
	syncToken chan struct{}
	// what a change raised by the store wakes
	wake chan struct{}
	// closed when the follower ends
	finished chan struct{}

	stateLock sync.Mutex
	// each table by its key, an address or a label
	addressEntries map[string]*mailConfigEntry
	burnerEntries  map[string]*mailConfigEntry
	// the zone the tables were read under, and when the last Sync finished; zero before the first
	syncedZone MailZone
	syncedTime time.Time
	synced     bool
	// when a Resolve's miss last asked for a Sync, and that Sync's error while none has passed since
	missTime time.Time
	missErr  error
	// alarms raised already, by path, version and reason, so a path replayed again raises none twice
	alarmed      map[string]bool
	burnerLabels MailBurnerLabelsFunction
	unregisters  []func()
	// ends the follower, once it started
	cancel    func()
	following bool
	closed    bool
	// called on the follower's goroutine after each of its Syncs, with that Sync's error; nil outside tests
	afterFollowerSync func(err error)
}

// The followed mailcfg of args.Repo: its first Sync and its subscription run on its own goroutine until Close, so
// the answer is ready for writes at once and for Resolve once that Sync lands.
func NewMailConfig(args *MailConfigArgs) (*MailConfig, error) {
	if args == nil || args.Repo == nil {
		return nil, fmt.Errorf("%w: no repo", ErrMailConfigInvalid)
	}
	store := &mailConfigEvsStore{mailEvsStore: newMailEvsStore(args.Repo, nil, nil)}
	config := newMailConfig(store, args)
	config.startFollower()
	return config, nil
}

// A MailConfig over store, its follower not yet started.
func newMailConfig(store mailConfigStore, args *MailConfigArgs) *MailConfig {
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailConfigSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	config := &MailConfig{
		store:          store,
		network:        args.Network,
		scope:          args.Scope,
		sidecarId:      args.SidecarId,
		authority:      args.Authority,
		gate:           args.Gate,
		alarmHandler:   args.Alarm,
		clock:          clockOrReal(args.Clock),
		log:            log,
		settings:       settings,
		syncToken:      make(chan struct{}, 1),
		wake:           make(chan struct{}, 1),
		finished:       make(chan struct{}),
		addressEntries: map[string]*mailConfigEntry{},
		burnerEntries:  map[string]*mailConfigEntry{},
		alarmed:        map[string]bool{},
		burnerLabels:   args.BurnerLabels,
	}
	if args.Gate != nil {
		config.unregisters = append(config.unregisters,
			args.Gate.RegisterEffectLookup(SidecarActionAliasCreate, config.Lookup),
			args.Gate.RegisterEffectLookup(SidecarActionAliasDelete, config.Lookup),
		)
	}
	config.cancel = func() {}
	return config
}

// Starts the follower, once: see run.
func (self *MailConfig) startFollower() {
	ctx, cancel := context.WithCancel(context.Background())
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.following || self.closed {
			return false
		}
		self.following = true
		self.cancel = cancel
		return true
	}()
	if !started {
		cancel()
		return
	}
	go self.run(ctx)
}

// Installs the burner label drawer, replacing any before; nil refuses burner creations again.
func (self *MailConfig) SetBurnerLabels(burnerLabels MailBurnerLabelsFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.burnerLabels = burnerLabels
}

// Ends the follower and removes this MailConfig's Lookups from its gate; the table stays as it was last read.
func (self *MailConfig) Close() {
	unregisters := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil
		}
		self.closed = true
		return self.unregisters
	}()
	cancel, following := func() (func(), bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.cancel, self.following
	}()
	cancel()
	if following {
		<-self.finished
	}
	for _, unregister := range unregisters {
		unregister()
	}
}

// The follower: a first Sync, the store's subscription, then a Sync at each change it raises and each
// ResyncInterval, a failure tried again after FollowRetryInterval. It ends with ctx.
func (self *MailConfig) run(ctx context.Context) {
	defer close(self.finished)
	retryInterval := max(self.settings.FollowRetryInterval, time.Second)
	var stopFollowing func()
	defer func() {
		if stopFollowing != nil {
			stopFollowing()
		}
	}()
	for {
		syncErr := self.Sync(ctx)
		if ctx.Err() != nil {
			return
		}
		if syncErr != nil && self.log.V(1).Enabled() {
			// the error names evs's refusal or the zone, never a path
			self.log.Infof("[mail] mailcfg sync failed: %v", syncErr)
		}
		if self.afterFollowerSync != nil {
			self.afterFollowerSync(syncErr)
		}
		var followErr error
		if stopFollowing == nil {
			stop, err := self.store.Follow(ctx, self.wakeFollower)
			if err == nil {
				stopFollowing = stop
				// a change between the Sync above and the subscription is read by one more
				self.wakeFollower()
			}
			followErr = err
		}
		var resync <-chan time.Time
		switch {
		case syncErr != nil || followErr != nil:
			resync = self.clock.After(retryInterval)
		case 0 < self.settings.ResyncInterval:
			resync = self.clock.After(self.settings.ResyncInterval)
		}
		select {
		case <-ctx.Done():
			return
		case <-self.wake:
		case <-resync:
		}
	}
}

// Wakes the follower for one more Sync; never blocks.
func (self *MailConfig) wakeFollower() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The zone the records are spelled under: the network's label under its root, with this mailcfg's scope.
// ErrMailConfigNoZone while the network has no label.
func (self *MailConfig) zone() (MailZone, NetworkLabelRow, error) {
	if self.network == nil {
		return MailZone{}, NetworkLabelRow{}, ErrMailConfigNoZone
	}
	row := self.network()
	if row.Label == "" || row.Root == "" {
		return MailZone{}, NetworkLabelRow{}, ErrMailConfigNoZone
	}
	return MailZone{Root: row.Root, Net: row.Label, Scope: self.scope}, row, nil
}

// Raises alarm once for its path, version and reason: to the handler, else to the log as a count of one, with ids
// only.
func (self *MailConfig) alarm(path string, alarm *MailConfigAlarm) {
	key := fmt.Sprintf("%s\x00%d\x00%s", path, alarm.Version, alarm.Reason)
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.alarmed[key] {
			return false
		}
		self.alarmed[key] = true
		return true
	}()
	if !first {
		return
	}
	alarm.RepoId = self.store.RepoId()
	if self.alarmHandler != nil {
		self.alarmHandler(alarm)
		return
	}
	self.log.Infof("[mail] mailcfg version %d from %s passed over: %s", alarm.Version, alarm.SidecarId, alarm.Reason)
}
